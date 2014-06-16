/*
     This file is part of GNUnet.
     (C) 2013 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file dv/gnunet-service-dv.c
 * @brief the distance vector service, primarily handles gossip of nearby
 * peers and sending/receiving DV messages from core and decapsulating
 * them
 *
 * @author Christian Grothoff
 * @author Nathan Evans
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_core_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet_set_service.h"
#include "gnunet_ats_service.h"
#include "dv.h"
#include <gcrypt.h>


/**
 * How often do we establish the consensu?
 */
#define GNUNET_DV_CONSENSUS_FREQUENCY GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 5)

/**
 * Maximum number of messages we queue per peer.
 */
#define MAX_QUEUE_SIZE 16

/**
 * Maximum number of messages we queue towards the clients/plugin.
 */
#define MAX_QUEUE_SIZE_PLUGIN 1024

/**
 * The default fisheye depth, from how many hops away will
 * we keep peers?
 */
#define DEFAULT_FISHEYE_DEPTH 3

/**
 * How many hops is a direct neighbor away?
 */
#define DIRECT_NEIGHBOR_COST 1


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Information about a peer DV can route to.  These entries are what
 * we use as the binary format to establish consensus to create our
 * routing table and as the address format in the HELLOs.
 */
struct Target
{

  /**
   * Identity of the peer we can reach.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * How many hops (1-3) is this peer away? in network byte order
   */
  uint32_t distance GNUNET_PACKED;

};


/**
 * Message exchanged between DV services (via core), requesting a
 * message to be routed.
 */
struct RouteMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DV_ROUTE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Expected (remaining) distance.  Must be always smaller than
   * #DEFAULT_FISHEYE_DEPTH, should be zero at the target.  Must
   * be decremented by one at each hop.  Peers must not forward
   * these messages further once the counter has reached zero.
   */
  uint32_t distance GNUNET_PACKED;

  /**
   * The (actual) target of the message (this peer, if distance is zero).
   */
  struct GNUNET_PeerIdentity target;

  /**
   * The (actual) sender of the message.
   */
  struct GNUNET_PeerIdentity sender;

};

GNUNET_NETWORK_STRUCT_END


/**
 * Linked list of messages to send to clients.
 */
struct PendingMessage
{
  /**
   * Pointer to next item in the list
   */
  struct PendingMessage *next;

  /**
   * Pointer to previous item in the list
   */
  struct PendingMessage *prev;

  /**
   * Actual message to be sent, allocated after this struct.
   */
  const struct GNUNET_MessageHeader *msg;

  /**
   * Next target for the message (a neighbour of ours).
   */
  struct GNUNET_PeerIdentity next_target;

  /**
   * Unique ID of the message.
   */
  uint32_t uid;

};


/**
 * Information about a direct neighbor (core-level, excluding
 * DV-links, only DV-enabled peers).
 */
struct DirectNeighbor
{

  /**
   * Identity of the peer.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Session ID we use whenever we create a set union with
   * this neighbor; constructed from the XOR of our peer
   * IDs and then salted with "DV-SALT" to avoid conflicts
   * with other applications.
   */
  struct GNUNET_HashCode real_session_id;

  /**
   * Head of linked list of messages to send to this peer.
   */
  struct PendingMessage *pm_head;

  /**
   * Tail of linked list of messages to send to this peer.
   */
  struct PendingMessage *pm_tail;

  /**
   * Transmit handle to core service.
   */
  struct GNUNET_CORE_TransmitHandle *cth;

  /**
   * Routing table of the neighbor, NULL if not yet established.
   * Keys are peer identities, values are 'struct Target' entries.
   * Note that the distances in the targets are from the point-of-view
   * of the peer, not from us!
   */
  struct GNUNET_CONTAINER_MultiPeerMap *neighbor_table;

  /**
   * Updated routing table of the neighbor, under construction,
   * NULL if we are not currently building it.
   * Keys are peer identities, values are 'struct Target' entries.
   * Note that the distances in the targets are from the point-of-view
   * of the other peer, not from us!
   */
  struct GNUNET_CONTAINER_MultiPeerMap *neighbor_table_consensus;

  /**
   * Our current (exposed) routing table as a set.
   */
  struct GNUNET_SET_Handle *my_set;

  /**
   * Handle for our current active set union operation.
   */
  struct GNUNET_SET_OperationHandle *set_op;

  /**
   * Handle used if we are listening for this peer, waiting for the
   * other peer to initiate construction of the set union.  NULL if
   * we ar the initiating peer.
   */
  struct GNUNET_SET_ListenHandle *listen_handle;

  /**
   * ID of the task we use to (periodically) update our consensus
   * with this peer.  Used if we are the initiating peer.
   */
  GNUNET_SCHEDULER_TaskIdentifier initiate_task;

  /**
   * At what offset are we, with respect to inserting our own routes
   * into the consensus?
   */
  unsigned int consensus_insertion_offset;

  /**
   * At what distance are we, with respect to inserting our own routes
   * into the consensus?
   */
  unsigned int consensus_insertion_distance;

  /**
   * Number of messages currently in the 'pm_XXXX'-DLL.
   */
  unsigned int pm_queue_size;

  /**
   * Elements in consensus
   */
  unsigned int consensus_elements;

  /**
   * Direct one hop route
   */
  struct Route *direct_route;

  /**
   * Flag set within 'check_target_removed' to trigger full global route refresh.
   */
  int target_removed;

  /**
   * Our distance to this peer, 0 for unknown.
   */
  uint32_t distance;

  /**
   * The network this peer is in
   */
  enum GNUNET_ATS_Network_Type network;

  /**
   * Is this neighbor connected at the core level?
   */
  int connected;

};


/**
 * A route includes information about the next hop,
 * the target, and the ultimate distance to the
 * target.
 */
struct Route
{

  /**
   * Which peer do we need to forward the message to?
   */
  struct DirectNeighbor *next_hop;

  /**
   * What would be the target, and how far is it away?
   */
  struct Target target;

  /**
   * Offset of this target in the respective consensus set.
   */
  unsigned int set_offset;

};


/**
 * Set of targets we bring to a consensus; all targets in a set have a
 * distance equal to the sets distance (which is implied by the array
 * index of the set).
 */
struct ConsensusSet
{

  /**
   * Array of targets in the set, may include NULL entries if a
   * neighbor has disconnected; the targets are allocated with the
   * respective container (all_routes), not here.
   */
  struct Route **targets;

  /**
   * Size of the @e targets array.
   */
  unsigned int array_length;

};


/**
 * Peermap of all of our neighbors; processing these usually requires
 * first checking to see if the peer is core-connected and if the
 * distance is 1, in which case they are direct neighbors.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *direct_neighbors;

/**
 * Hashmap with all routes that we currently support; contains
 * routing information for all peers from distance 2
 * up to distance #DEFAULT_FISHEYE_DEPTH.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *all_routes;

/**
 * Array of consensus sets we expose to the outside world.  Sets
 * are structured by the distance to the target.
 */
static struct ConsensusSet consensi[DEFAULT_FISHEYE_DEPTH];

/**
 * Handle to the core service api.
 */
static struct GNUNET_CORE_Handle *core_api;

/**
 * The identity of our peer.
 */
static struct GNUNET_PeerIdentity my_identity;

/**
 * The configuration for this service.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * The client, the DV plugin connected to us (or an event monitor).
 * Hopefully this client will never change, although if the plugin
 * dies and returns for some reason it may happen.
 */
static struct GNUNET_SERVER_NotificationContext *nc;

/**
 * Handle for the statistics service.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Handle to ATS service.
 */
static struct GNUNET_ATS_PerformanceHandle *ats;

/**
 * Task scheduled to refresh routes based on direct neighbours.
 */
static GNUNET_SCHEDULER_TaskIdentifier rr_task;

/**
 * #GNUNET_YES if we are shutting down.
 */
static int in_shutdown;

/**
 * Start creating a new DV set union by initiating the connection.
 *
 * @param cls the 'struct DirectNeighbor' of the peer we're building
 *        a routing consensus with
 * @param tc scheduler context
 */
static void
initiate_set_union (void *cls,
		    const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Start creating a new DV set union construction, our neighbour has
 * asked for it (callback for listening peer).
 *
 * @param cls the 'struct DirectNeighbor' of the peer we're building
 *        a routing consensus with
 * @param other_peer the other peer
 * @param context_msg message with application specific information from
 *        the other peer
 * @param request request from the other peer, use GNUNET_SET_accept
 *        to accept it, otherwise the request will be refused
 *        Note that we don't use a return value here, as it is also
 *        necessary to specify the set we want to do the operation with,
 *        whith sometimes can be derived from the context message.
 *        Also necessary to specify the timeout.
 */
static void
listen_set_union (void *cls,
		  const struct GNUNET_PeerIdentity *other_peer,
		  const struct GNUNET_MessageHeader *context_msg,
		  struct GNUNET_SET_Request *request);


/**
 * Forward a message from another peer to the plugin.
 *
 * @param message the message to send to the plugin
 * @param origin the original sender of the message
 * @param distance distance to the original sender of the message
 */
static void
send_data_to_plugin (const struct GNUNET_MessageHeader *message,
		     const struct GNUNET_PeerIdentity *origin,
		     uint32_t distance)
{
  struct GNUNET_DV_ReceivedMessage *received_msg;
  size_t size;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Delivering message from peer `%s' at distance %u\n",
              GNUNET_i2s (origin),
              (unsigned int) distance);
  size = sizeof (struct GNUNET_DV_ReceivedMessage) +
    ntohs (message->size);
  if (size >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0); /* too big */
    return;
  }
  received_msg = GNUNET_malloc (size);
  received_msg->header.size = htons (size);
  received_msg->header.type = htons (GNUNET_MESSAGE_TYPE_DV_RECV);
  received_msg->distance = htonl (distance);
  received_msg->sender = *origin;
  memcpy (&received_msg[1], message, ntohs (message->size));
  GNUNET_SERVER_notification_context_broadcast (nc,
						&received_msg->header,
						GNUNET_YES);
  GNUNET_free (received_msg);
}


/**
 * Forward a control message to the plugin.
 *
 * @param message the message to send to the plugin
 */
static void
send_control_to_plugin (const struct GNUNET_MessageHeader *message)
{
  GNUNET_SERVER_notification_context_broadcast (nc,
						message,
						GNUNET_NO);
}


/**
 * Give an (N)ACK message to the plugin, we transmitted a message for it.
 *
 * @param target peer that received the message
 * @param uid plugin-chosen UID for the message
 * @param nack #GNUNET_NO to send ACK, #GNUNET_YES to send NACK
 */
static void
send_ack_to_plugin (const struct GNUNET_PeerIdentity *target,
		    uint32_t uid,
		    int nack)
{
  struct GNUNET_DV_AckMessage ack_msg;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Delivering ACK for message to peer `%s'\n",
              GNUNET_i2s (target));
  ack_msg.header.size = htons (sizeof (ack_msg));
  ack_msg.header.type = htons ((GNUNET_YES == nack)
			       ? GNUNET_MESSAGE_TYPE_DV_SEND_NACK
			       : GNUNET_MESSAGE_TYPE_DV_SEND_ACK);
  ack_msg.uid = htonl (uid);
  ack_msg.target = *target;
  send_control_to_plugin (&ack_msg.header);
}


/**
 * Send a DISTANCE_CHANGED message to the plugin.
 *
 * @param peer peer with a changed distance
 * @param distance new distance to the peer
 * @param network network used by the neighbor
 */
static void
send_distance_change_to_plugin (const struct GNUNET_PeerIdentity *peer,
				uint32_t distance,
                                enum GNUNET_ATS_Network_Type network)
{
  struct GNUNET_DV_DistanceUpdateMessage du_msg;

  GNUNET_break (GNUNET_ATS_NET_UNSPECIFIED != network);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Delivering DISTANCE_CHANGED for message about peer `%s'\n",
              GNUNET_i2s (peer));
  du_msg.header.size = htons (sizeof (du_msg));
  du_msg.header.type = htons (GNUNET_MESSAGE_TYPE_DV_DISTANCE_CHANGED);
  du_msg.distance = htonl (distance);
  du_msg.peer = *peer;
  du_msg.network = htonl ((uint32_t) network);
  send_control_to_plugin (&du_msg.header);
}


/**
 * Give a CONNECT message to the plugin.
 *
 * @param target peer that connected
 * @param distance distance to the target
 * @param network the network the next hop is located in
 */
static void
send_connect_to_plugin (const struct GNUNET_PeerIdentity *target,
			uint32_t distance,
                        enum GNUNET_ATS_Network_Type network)
{
  struct GNUNET_DV_ConnectMessage cm;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Delivering CONNECT about peer %s with distance %u\n",
              GNUNET_i2s (target), distance);
  cm.header.size = htons (sizeof (cm));
  cm.header.type = htons (GNUNET_MESSAGE_TYPE_DV_CONNECT);
  cm.distance = htonl (distance);
  cm.network = htonl ((uint32_t) network);
  cm.peer = *target;
  send_control_to_plugin (&cm.header);
}


/**
 * Give a DISCONNECT message to the plugin.
 *
 * @param target peer that disconnected
 */
static void
send_disconnect_to_plugin (const struct GNUNET_PeerIdentity *target)
{
  struct GNUNET_DV_DisconnectMessage dm;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Delivering DISCONNECT about peer `%s'\n",
              GNUNET_i2s (target));
  dm.header.size = htons (sizeof (dm));
  dm.header.type = htons (GNUNET_MESSAGE_TYPE_DV_DISCONNECT);
  dm.reserved = htonl (0);
  dm.peer = *target;
  send_control_to_plugin (&dm.header);
}


/**
 * Function called to transfer a message to another peer
 * via core.
 *
 * @param cls closure with the direct neighbor
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
core_transmit_notify (void *cls, size_t size, void *buf)
{
  struct DirectNeighbor *dn = cls;
  char *cbuf = buf;
  struct PendingMessage *pending;
  size_t off;
  size_t msize;

  dn->cth = NULL;
  if (NULL == buf)
  {
    /* client disconnected */
    return 0;
  }
  off = 0;
  while ( (NULL != (pending = dn->pm_head)) &&
	  (size >= off + (msize = ntohs (pending->msg->size))))
  {
    dn->pm_queue_size--;
    GNUNET_CONTAINER_DLL_remove (dn->pm_head,
				 dn->pm_tail,
                                 pending);
    memcpy (&cbuf[off], pending->msg, msize);
    if (0 != pending->uid)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Acking transmission of %u bytes to %s with plugin\n",
                  msize,
                  GNUNET_i2s (&pending->next_target));
      send_ack_to_plugin (&pending->next_target,
			  pending->uid,
			  GNUNET_NO);
    }
    GNUNET_free (pending);
    off += msize;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Transmitting total of %u bytes to %s\n",
	      off,
	      GNUNET_i2s (&dn->peer));
  GNUNET_assert (NULL != core_api);
  if (NULL != dn->pm_head)
    dn->cth =
      GNUNET_CORE_notify_transmit_ready (core_api,
					 GNUNET_YES /* cork */,
					 GNUNET_CORE_PRIO_BEST_EFFORT,
					 GNUNET_TIME_UNIT_FOREVER_REL,
					 &dn->peer,
					 msize,
					 &core_transmit_notify, dn);
  return off;
}


/**
 * Forward the given payload to the given target.
 *
 * @param target where to send the message
 * @param distance distance to the @a sender
 * @param uid unique ID for the message
 * @param sender original sender of the message
 * @param actual_target ultimate recipient for the message
 * @param payload payload of the message
 */
static void
forward_payload (struct DirectNeighbor *target,
		 uint32_t distance,
		 uint32_t uid,
		 const struct GNUNET_PeerIdentity *sender,
		 const struct GNUNET_PeerIdentity *actual_target,
		 const struct GNUNET_MessageHeader *payload)
{
  struct PendingMessage *pm;
  struct RouteMessage *rm;
  size_t msize;

  if ( (target->pm_queue_size >= MAX_QUEUE_SIZE) &&
       (0 == uid) &&
       (0 != memcmp (sender,
		     &my_identity,
		     sizeof (struct GNUNET_PeerIdentity))) )
  {
    /* not _our_ client and queue is full, drop */
    GNUNET_STATISTICS_update (stats,
                              "# messages dropped",
                              1, GNUNET_NO);
    return;
  }
  msize = sizeof (struct RouteMessage) + ntohs (payload->size);
  if (msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }
  pm = GNUNET_malloc (sizeof (struct PendingMessage) + msize);
  pm->next_target = target->peer;
  pm->uid = uid;
  pm->msg = (const struct GNUNET_MessageHeader *) &pm[1];
  rm = (struct RouteMessage *) &pm[1];
  rm->header.size = htons ((uint16_t) msize);
  rm->header.type = htons (GNUNET_MESSAGE_TYPE_DV_ROUTE);
  rm->distance = htonl (distance);
  rm->target = *actual_target;
  rm->sender = *sender;
  memcpy (&rm[1], payload, ntohs (payload->size));
  GNUNET_CONTAINER_DLL_insert_tail (target->pm_head,
				    target->pm_tail,
				    pm);
  target->pm_queue_size++;
  GNUNET_assert (NULL != core_api);
  if (NULL == target->cth)
    target->cth = GNUNET_CORE_notify_transmit_ready (core_api,
						     GNUNET_YES /* cork */,
						     GNUNET_CORE_PRIO_BEST_EFFORT,
						     GNUNET_TIME_UNIT_FOREVER_REL,
						     &target->peer,
						     msize,
						     &core_transmit_notify, target);
}


/**
 * Find a free slot for storing a 'route' in the 'consensi'
 * set at the given distance.
 *
 * @param distance distance to use for the set slot
 */
static unsigned int
get_consensus_slot (uint32_t distance)
{
  struct ConsensusSet *cs;
  unsigned int i;

  GNUNET_assert (distance < DEFAULT_FISHEYE_DEPTH);
  cs = &consensi[distance];
  i = 0;
  while ( (i < cs->array_length) &&
	  (NULL != cs->targets[i]) ) i++;
  if (i == cs->array_length)
  {
    GNUNET_array_grow (cs->targets,
		       cs->array_length,
		       cs->array_length * 2 + 2);
  }
  return i;
}


/**
 * Allocate a slot in the consensus set for a route.
 *
 * @param route route to initialize
 * @param distance which consensus set to use
 */
static void
allocate_route (struct Route *route,
		uint32_t distance)
{
  unsigned int i;

  if (distance >= DEFAULT_FISHEYE_DEPTH)
  {
    route->target.distance = htonl (distance);
    route->set_offset = UINT_MAX; /* invalid slot */
    return;
  }
  i = get_consensus_slot (distance);
  route->set_offset = i;
  consensi[distance].targets[i] = route;
  route->target.distance = htonl (distance);
}


/**
 * Release a slot in the consensus set for a route.
 *
 * @param route route to release the slot from
 */
static void
release_route (struct Route *route)
{
  if (UINT_MAX == route->set_offset)
    return;
  GNUNET_assert (ntohl (route->target.distance) < DEFAULT_FISHEYE_DEPTH);
  consensi[ntohl (route->target.distance)].targets[route->set_offset] = NULL;
  route->set_offset = UINT_MAX; /* indicate invalid slot */
}


/**
 * Move a route from one consensus set to another.
 *
 * @param route route to move
 * @param new_distance new distance for the route (destination set)
 */
static void
move_route (struct Route *route,
	    uint32_t new_distance)
{
  release_route (route);
  allocate_route (route, new_distance);
}


/**
 * Initialize this neighbors 'my_set' and when done give
 * it to the pending set operation for execution.
 *
 * Add a single element to the set per call:
 *
 * If we reached the last element of a consensus element: increase distance
 *
 *
 * @param cls the neighbor for which we are building the set
 */
static void
build_set (void *cls)
{
  struct DirectNeighbor *neighbor = cls;
  struct GNUNET_SET_Element element;
  struct Target *target;
  struct Route *route;

  target = NULL;
  /* skip over NULL entries */
  while ( (DEFAULT_FISHEYE_DEPTH > neighbor->consensus_insertion_distance) &&
	  (consensi[neighbor->consensus_insertion_distance].array_length > neighbor->consensus_insertion_offset) &&
	  (NULL == consensi[neighbor->consensus_insertion_distance].targets[neighbor->consensus_insertion_offset]) )
    neighbor->consensus_insertion_offset++;
  while ( (DEFAULT_FISHEYE_DEPTH > neighbor->consensus_insertion_distance) &&
	  (consensi[neighbor->consensus_insertion_distance].array_length == neighbor->consensus_insertion_offset) )
  {
    /* If we reached the last element of a consensus array element: increase distance and start with next array */
    neighbor->consensus_insertion_offset = 0;
    neighbor->consensus_insertion_distance++;
    /* skip over NULL entries */
    while ( (DEFAULT_FISHEYE_DEPTH > neighbor->consensus_insertion_distance) &&
	    (consensi[neighbor->consensus_insertion_distance].array_length  > neighbor->consensus_insertion_offset) &&
	    (NULL == consensi[neighbor->consensus_insertion_distance].targets[neighbor->consensus_insertion_offset]) )
      neighbor->consensus_insertion_offset++;
  }
  if (DEFAULT_FISHEYE_DEPTH == neighbor->consensus_insertion_distance)
  {
    /* we have added all elements to the set, run the operation */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Finished building my SET for peer `%s' with %u elements, committing\n",
		GNUNET_i2s (&neighbor->peer),
		neighbor->consensus_elements);
    GNUNET_SET_commit (neighbor->set_op,
		       neighbor->my_set);
    GNUNET_SET_destroy (neighbor->my_set);
    neighbor->my_set = NULL;
    return;
  }

  route = consensi[neighbor->consensus_insertion_distance].targets[neighbor->consensus_insertion_offset];
  GNUNET_assert (NULL != route);
  target = &route->target;
  GNUNET_assert (ntohl (target->distance) < DEFAULT_FISHEYE_DEPTH);
  element.size = sizeof (struct Target);
  element.type = htons (0); /* do we need this? */
  element.data = target;

  /* Find next non-NULL entry */
  neighbor->consensus_insertion_offset++;
  if ( (0 != memcmp (&target->peer, &my_identity, sizeof (my_identity))) &&
       (0 != memcmp (&target->peer, &neighbor->peer, sizeof (neighbor->peer))) )
  {
    /* Add target if it is not the neighbor or this peer */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Adding peer `%s' with distance %u to SET\n",
                GNUNET_i2s (&target->peer),
                ntohl (target->distance) + 1);
    GNUNET_SET_add_element (neighbor->my_set,
                            &element,
                            &build_set, neighbor);
    neighbor->consensus_elements++;
  }
  else
    build_set (neighbor);
}


/**
 * A peer is now connected to us at distance 1.  Initiate DV exchange.
 *
 * @param neighbor entry for the neighbor at distance 1
 */
static void
handle_direct_connect (struct DirectNeighbor *neighbor)
{
  struct Route *route;
  struct GNUNET_HashCode h1;
  struct GNUNET_HashCode h2;
  struct GNUNET_HashCode session_id;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Direct connection to %s established, routing table exchange begins.\n",
	      GNUNET_i2s (&neighbor->peer));
  GNUNET_STATISTICS_update (stats,
			    "# peers connected (1-hop)",
			    1, GNUNET_NO);
  route = GNUNET_CONTAINER_multipeermap_get (all_routes,
					     &neighbor->peer);
  if (NULL != route)
  {
    GNUNET_assert (GNUNET_YES ==
		   GNUNET_CONTAINER_multipeermap_remove (all_routes,
                                                         &neighbor->peer,
                                                         route));
    send_disconnect_to_plugin (&neighbor->peer);
    release_route (route);
    GNUNET_free (route);
  }

  neighbor->direct_route = GNUNET_new (struct Route);
  neighbor->direct_route->next_hop = neighbor;
  neighbor->direct_route->target.peer = neighbor->peer;
  allocate_route (neighbor->direct_route, DIRECT_NEIGHBOR_COST);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Adding direct route to %s\n",
              GNUNET_i2s (&neighbor->direct_route->target.peer));


  /* construct session ID seed as XOR of both peer's identities */
  GNUNET_CRYPTO_hash (&my_identity, sizeof (my_identity), &h1);
  GNUNET_CRYPTO_hash (&neighbor->peer, sizeof (struct GNUNET_PeerIdentity), &h2);
  GNUNET_CRYPTO_hash_xor (&h1,
			  &h2,
			  &session_id);
  /* make sure session ID is unique across applications by salting it with 'DV' */
  GNUNET_CRYPTO_hkdf (&neighbor->real_session_id, sizeof (struct GNUNET_HashCode),
		      GCRY_MD_SHA512, GCRY_MD_SHA256,
		      "DV-SALT", 2,
		      &session_id, sizeof (session_id),
		      NULL, 0);
  if (0 < memcmp (&neighbor->peer,
		  &my_identity,
		  sizeof (struct GNUNET_PeerIdentity)))
  {
    if (NULL != neighbor->listen_handle)
    {
      GNUNET_break (0);
    }
    else
      neighbor->initiate_task = GNUNET_SCHEDULER_add_now (&initiate_set_union,
                                                          neighbor);
  }
  else
  {
    if (NULL != neighbor->listen_handle)
    {
      GNUNET_break (0);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Starting SET listen operation with peer `%s'\n",
                  GNUNET_i2s(&neighbor->peer));
      neighbor->listen_handle = GNUNET_SET_listen (cfg,
                                                   GNUNET_SET_OPERATION_UNION,
                                                   &neighbor->real_session_id,
                                                   &listen_set_union,
                                                   neighbor);
    }
  }
}


/**
 * Method called whenever a peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
handle_core_connect (void *cls,
		     const struct GNUNET_PeerIdentity *peer)
{
  struct DirectNeighbor *neighbor;

  /* Check for connect to self message */
  if (0 == memcmp (&my_identity, peer, sizeof (struct GNUNET_PeerIdentity)))
    return;
  /* check if entry exists */
  neighbor = GNUNET_CONTAINER_multipeermap_get (direct_neighbors,
						peer);
  if (NULL != neighbor)
  {
    GNUNET_break (GNUNET_ATS_NET_UNSPECIFIED != neighbor->network);
    GNUNET_break (GNUNET_YES != neighbor->connected);
    neighbor->connected = GNUNET_YES;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Core connected to %s (distance %u)\n",
		GNUNET_i2s (peer),
		(unsigned int) neighbor->distance);
    if (DIRECT_NEIGHBOR_COST != neighbor->distance)
      return;
    handle_direct_connect (neighbor);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Core connected to %s (distance unknown)\n",
	      GNUNET_i2s (peer));
  neighbor = GNUNET_new (struct DirectNeighbor);
  neighbor->peer = *peer;
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multipeermap_put (direct_neighbors,
						    peer,
						    neighbor,
						    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  neighbor->connected = GNUNET_YES;
  neighbor->distance = 0; /* unknown */
  neighbor->network = GNUNET_ATS_NET_UNSPECIFIED;
}


/**
 * Called for each 'target' in a neighbor table to free the associated memory.
 *
 * @param cls NULL
 * @param key key of the value
 * @param value value to free
 * @return #GNUNET_OK to continue to iterate
 */
static int
free_targets (void *cls,
	      const struct GNUNET_PeerIdentity *key,
	      void *value)
{
  GNUNET_free (value);
  return GNUNET_OK;
}


/**
 * Add a new route to the given @a target via the given @a neighbor.
 *
 * @param target the target of the route
 * @param neighbor the next hop for communicating with the @a target
 */
static void
add_new_route (struct Target *target,
               struct DirectNeighbor *neighbor)
{
  struct Route *route;

  route = GNUNET_new (struct Route);
  route->next_hop = neighbor;
  route->target.peer = target->peer;
  allocate_route (route, ntohl (target->distance) + 1);
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multipeermap_put (all_routes,
						    &route->target.peer,
						    route,
						    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  send_connect_to_plugin (&route->target.peer,
                          ntohl (route->target.distance),
                          neighbor->network);
}


/**
 * Multipeerhmap iterator for checking if a given route is
 * (now) useful to this peer.
 *
 * @param cls the direct neighbor for the given route
 * @param key key value stored under
 * @param value a 'struct Target' that may or may not be useful; not that
 *        the distance in 'target' does not include the first hop yet
 * @return #GNUNET_YES to continue iteration, #GNUNET_NO to stop
 */
static int
check_possible_route (void *cls,
		      const struct GNUNET_PeerIdentity *key,
		      void *value)
{
  struct DirectNeighbor *neighbor = cls;
  struct Target *target = value;
  struct Route *route;

  if (GNUNET_YES ==
      GNUNET_CONTAINER_multipeermap_contains (direct_neighbors,
                                              key))
    return GNUNET_YES; /* direct route, do not care about alternatives */
  route = GNUNET_CONTAINER_multipeermap_get (all_routes,
					     key);
  if (NULL != route)
  {
    /* we have an existing route, check how it compares with going via 'target' */
    if (ntohl (route->target.distance) > ntohl (target->distance) + 1)
    {
      /* via 'target' is cheaper than the existing route; switch to alternative route! */
      move_route (route, ntohl (target->distance) + 1);
      route->next_hop = neighbor;
      send_distance_change_to_plugin (&target->peer,
                                      ntohl (target->distance) + 1,
                                      neighbor->network);
    }
    return GNUNET_YES; /* got a route to this target already */
  }
  if (ntohl (target->distance) >= DEFAULT_FISHEYE_DEPTH)
    return GNUNET_YES; /* distance is too large to be interesting */
  add_new_route (target, neighbor);
  return GNUNET_YES;
}


/**
 * Multipeermap iterator for finding routes that were previously
 * "hidden" due to a better route (called after a disconnect event).
 *
 * @param cls NULL
 * @param key peer identity of the given direct neighbor
 * @param value a `struct DirectNeighbor` to check for additional routes
 * @return #GNUNET_YES to continue iteration
 */
static int
refresh_routes (void *cls,
		const struct GNUNET_PeerIdentity *key,
		void *value)
{
  struct DirectNeighbor *neighbor = value;

  if ( (GNUNET_YES != neighbor->connected) ||
       (DIRECT_NEIGHBOR_COST != neighbor->distance) )
    return GNUNET_YES;
  if (NULL != neighbor->neighbor_table)
    GNUNET_CONTAINER_multipeermap_iterate (neighbor->neighbor_table,
					   &check_possible_route,
					   neighbor);
  return GNUNET_YES;
}


/**
 * Task to run #refresh_routes() on all direct neighbours.
 *
 * @param cls NULL
 * @param tc unused
 */
static void
refresh_routes_task (void *cls,
                     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  rr_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_CONTAINER_multipeermap_iterate (direct_neighbors,
					 &refresh_routes,
                                         NULL);
}


/**
 * Asynchronously run #refresh_routes() at the next opportunity
 * on all direct neighbours.
 */
static void
schedule_refresh_routes ()
{
  if (GNUNET_SCHEDULER_NO_TASK == rr_task)
    rr_task = GNUNET_SCHEDULER_add_now (&refresh_routes_task,
                                        NULL);
}


/**
 * Get distance information from 'atsi'.
 *
 * @param atsi performance data
 * @param atsi_count number of entries in atsi
 * @return connected transport distance
 */
static uint32_t
get_atsi_distance (const struct GNUNET_ATS_Information *atsi,
                   uint32_t atsi_count)
{
  uint32_t i;

  for (i = 0; i < atsi_count; i++)
    if (ntohl (atsi[i].type) == GNUNET_ATS_QUALITY_NET_DISTANCE)
      return (0 == ntohl (atsi[i].value)) ? DIRECT_NEIGHBOR_COST : ntohl (atsi[i].value); // FIXME: 0 check should not be required once ATS is fixed!
  /* If we do not have explicit distance data, assume direct neighbor. */
  return DIRECT_NEIGHBOR_COST;
}


/**
 * Get network information from 'atsi'.
 *
 * @param atsi performance data
 * @param atsi_count number of entries in atsi
 * @return connected transport network
 */
static enum GNUNET_ATS_Network_Type
get_atsi_network (const struct GNUNET_ATS_Information *atsi,
                   uint32_t atsi_count)
{
  uint32_t i;

  for (i = 0; i < atsi_count; i++)
    if (ntohl (atsi[i].type) == GNUNET_ATS_NETWORK_TYPE)
      return (enum GNUNET_ATS_Network_Type) ntohl (atsi[i].value);
  return GNUNET_ATS_NET_UNSPECIFIED;
}

/**
 * Multipeermap iterator for freeing routes that go via a particular
 * neighbor that disconnected and is thus no longer available.
 *
 * @param cls the direct neighbor that is now unavailable
 * @param key key value stored under
 * @param value a `struct Route` that may or may not go via neighbor
 *
 * @return #GNUNET_YES to continue iteration, #GNUNET_NO to stop
 */
static int
cull_routes (void *cls,
	     const struct GNUNET_PeerIdentity *key,
	     void *value)
{
  struct DirectNeighbor *neighbor = cls;
  struct Route *route = value;

  if (route->next_hop != neighbor)
    return GNUNET_YES; /* not affected */
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multipeermap_remove (all_routes, key, value));
  release_route (route);
  send_disconnect_to_plugin (&route->target.peer);
  GNUNET_free (route);
  return GNUNET_YES;
}


/**
 * Handle the case that a direct connection to a peer is
 * disrupted.  Remove all routes via that peer and
 * stop the consensus with it.
 *
 * @param neighbor peer that was disconnected (or at least is no
 *    longer at distance 1)
 */
static void
handle_direct_disconnect (struct DirectNeighbor *neighbor)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Culling routes via %s due to direct disconnect\n",
	      GNUNET_i2s (&neighbor->peer));
  GNUNET_CONTAINER_multipeermap_iterate (all_routes,
					 &cull_routes,
                                         neighbor);
  if (NULL != neighbor->cth)
  {
    GNUNET_CORE_notify_transmit_ready_cancel (neighbor->cth);
    neighbor->cth = NULL;
  }

  if (NULL != neighbor->direct_route)
  {
    release_route (neighbor->direct_route);
    GNUNET_free (neighbor->direct_route);
    neighbor->direct_route = NULL;
  }

  if (NULL != neighbor->neighbor_table_consensus)
  {
    GNUNET_CONTAINER_multipeermap_iterate (neighbor->neighbor_table_consensus,
					   &free_targets,
					   NULL);
    GNUNET_CONTAINER_multipeermap_destroy (neighbor->neighbor_table_consensus);
    neighbor->neighbor_table_consensus = NULL;
  }
  if (NULL != neighbor->neighbor_table)
  {
    GNUNET_CONTAINER_multipeermap_iterate (neighbor->neighbor_table,
					   &free_targets,
					   NULL);
    GNUNET_CONTAINER_multipeermap_destroy (neighbor->neighbor_table);
    neighbor->neighbor_table = NULL;
  }
  if (NULL != neighbor->set_op)
  {
    GNUNET_SET_operation_cancel (neighbor->set_op);
    neighbor->set_op = NULL;
  }
  if (NULL != neighbor->my_set)
  {
    GNUNET_SET_destroy (neighbor->my_set);
    neighbor->my_set = NULL;
  }
  if (NULL != neighbor->listen_handle)
  {
    GNUNET_SET_listen_cancel (neighbor->listen_handle);
    neighbor->listen_handle = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != neighbor->initiate_task)
  {
    GNUNET_SCHEDULER_cancel (neighbor->initiate_task);
    neighbor->initiate_task = GNUNET_SCHEDULER_NO_TASK;
  }
}


/**
 * Function that is called with QoS information about an address; used
 * to update our current distance to another peer.
 *
 * @param cls closure
 * @param address the address
 * @param active #GNUNET_YES if this address is actively used
 *        to maintain a connection to a peer;
 *        #GNUNET_NO if the address is not actively used;
 *        #GNUNET_SYSERR if this address is no longer available for ATS
 * @param bandwidth_out assigned outbound bandwidth for the connection
 * @param bandwidth_in assigned inbound bandwidth for the connection
 * @param ats performance data for the address (as far as known)
 * @param ats_count number of performance records in @a ats
 */
static void
handle_ats_update (void *cls,
		   const struct GNUNET_HELLO_Address *address,
		   int active,
		   struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
		   struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
		   const struct GNUNET_ATS_Information *ats,
		   uint32_t ats_count)
{
  struct DirectNeighbor *neighbor;
  uint32_t distance;
  enum GNUNET_ATS_Network_Type network = GNUNET_ATS_NET_UNSPECIFIED;

  if (NULL == address)
  {
    /* ATS service temporarily disconnected */
    return;
  }

  if (GNUNET_YES != active)
  {
    // FIXME: handle disconnect/inactive case too!
    return;
  }
  distance = get_atsi_distance (ats, ats_count);
  network = get_atsi_network (ats, ats_count);
  GNUNET_break (GNUNET_ATS_NET_UNSPECIFIED != network);
  /* check if entry exists */
  neighbor = GNUNET_CONTAINER_multipeermap_get (direct_neighbors,
						&address->peer);
  if (NULL != neighbor)
  {
    neighbor->network = network;
    if (neighbor->distance == distance)
      return; /* nothing new to see here, move along */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "ATS says distance to %s is now %u\n",
                GNUNET_i2s (&address->peer),
                (unsigned int) distance);
    if ( (DIRECT_NEIGHBOR_COST == neighbor->distance) &&
	 (DIRECT_NEIGHBOR_COST == distance) )
      return; /* no change */
    if (DIRECT_NEIGHBOR_COST == neighbor->distance)
    {
      neighbor->distance = distance;
      GNUNET_STATISTICS_update (stats,
				"# peers connected (1-hop)",
				-1, GNUNET_NO);
      handle_direct_disconnect (neighbor);
      schedule_refresh_routes ();
      return;
    }
    neighbor->distance = distance;
    if (DIRECT_NEIGHBOR_COST != neighbor->distance)
      return;
    if (GNUNET_YES != neighbor->connected)
      return;
    handle_direct_connect (neighbor);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "ATS says distance to %s is now %u\n",
	      GNUNET_i2s (&address->peer),
	      (unsigned int) distance);
  neighbor = GNUNET_new (struct DirectNeighbor);
  neighbor->peer = address->peer;
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multipeermap_put (direct_neighbors,
						    &address->peer,
						    neighbor,
						    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  neighbor->connected = GNUNET_NO; /* not yet */
  neighbor->distance = distance;
  neighbor->network = network;
}


/**
 * Check if a target was removed from the set of the other peer; if so,
 * if we also used it for our route, we need to remove it from our
 * 'all_routes' set (and later check if an alternative path now exists).
 *
 * @param cls the `struct DirectNeighbor`
 * @param key peer identity for the target
 * @param value a `struct Target` previously reachable via the given neighbor
 */
static int
check_target_removed (void *cls,
		      const struct GNUNET_PeerIdentity *key,
		      void *value)
{
  struct DirectNeighbor *neighbor = cls;
  struct Target *new_target;
  struct Route *current_route;

  new_target = GNUNET_CONTAINER_multipeermap_get (neighbor->neighbor_table_consensus,
						  key);
  current_route = GNUNET_CONTAINER_multipeermap_get (all_routes,
                                                     key);
  if (NULL != new_target)
  {
    /* target was in old set, is in new set */
    if ( (NULL != current_route) &&
         (current_route->next_hop == neighbor) &&
         (current_route->target.distance != new_target->distance) )
    {
      /* need to recalculate routes due to distance change */
      neighbor->target_removed = GNUNET_YES;
    }
    return GNUNET_OK;
  }
  /* target was revoked, check if it was used */
  if ( (NULL == current_route) ||
       (current_route->next_hop != neighbor) )
  {
    /* didn't matter, wasn't used */
    return GNUNET_OK;
  }
  /* remove existing route */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Lost route to %s\n",
              GNUNET_i2s (&current_route->target.peer));
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (all_routes, key, current_route));
  send_disconnect_to_plugin (&current_route->target.peer);
  release_route (current_route);
  GNUNET_free (current_route);
  neighbor->target_removed = GNUNET_YES;
  return GNUNET_OK;
}


/**
 * Check if a target was added to the set of the other peer; if it
 * was added or impoves the existing route, do the needed updates.
 *
 * @param cls the `struct DirectNeighbor`
 * @param key peer identity for the target
 * @param value a `struct Target` now reachable via the given neighbor
 */
static int
check_target_added (void *cls,
		    const struct GNUNET_PeerIdentity *key,
		    void *value)
{
  struct DirectNeighbor *neighbor = cls;
  struct Target *target = value;
  struct Route *current_route;

  /* target was revoked, check if it was used */
  current_route = GNUNET_CONTAINER_multipeermap_get (all_routes,
						     key);
  if (NULL != current_route)
  {
    /* route exists */
    if (current_route->next_hop == neighbor)
    {
      /* we had the same route before, no change in target */
      if (ntohl (target->distance) + 1 != ntohl (current_route->target.distance))
      {
        /* but distance changed! */
        if (ntohl (target->distance) + 1 > DEFAULT_FISHEYE_DEPTH)
        {
          /* distance increased beyond what is allowed, kill route */
          GNUNET_assert (GNUNET_YES ==
                         GNUNET_CONTAINER_multipeermap_remove (all_routes,
                                                               key,
                                                               current_route));
          send_disconnect_to_plugin (key);
          release_route (current_route);
          GNUNET_free (current_route);
        }
        else
        {
          /* distance decreased, update route */
          move_route (current_route,
                      ntohl (target->distance) + 1);
          send_distance_change_to_plugin (&target->peer,
                                          ntohl (target->distance) + 1,
                                          neighbor->network);
        }
      }
      return GNUNET_OK;
    }
    if (ntohl (current_route->target.distance) <= ntohl (target->distance) + 1)
    {
      /* alternative, shorter route exists, ignore */
      return GNUNET_OK;
    }
    /* new route is better than the existing one, take over! */
    /* NOTE: minor security issue: malicious peers may advertise
       very short routes to take over longer paths; as we don't
       check that the shorter routes actually work, a malicious
       direct neighbor can use this to DoS our long routes */

    move_route (current_route, ntohl (target->distance) + 1);
    current_route->next_hop = neighbor;
    send_distance_change_to_plugin (&target->peer,
                                    ntohl (target->distance) + 1,
                                    neighbor->network);
    return GNUNET_OK;
  }
  /* new route */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Discovered new route to %s using %u hops\n",
	      GNUNET_i2s (&target->peer),
	      (unsigned int) (ntohl (target->distance) + 1));
  current_route = GNUNET_new (struct Route);
  current_route->next_hop = neighbor;
  current_route->target.peer = target->peer;
  allocate_route (current_route, ntohl (target->distance) + 1);
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multipeermap_put (all_routes,
						    &current_route->target.peer,
						    current_route,
						    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));

  send_connect_to_plugin (&current_route->target.peer,
			  ntohl (current_route->target.distance),
			  neighbor->network);
  return GNUNET_OK;
}


/**
 * Callback for set operation results. Called for each element
 * in the result set.
 * We have learned a new route from the other peer.  Add it to the
 * route set we're building.
 *
 * @param cls the `struct DirectNeighbor` we're building the consensus with
 * @param element a result element, only valid if status is #GNUNET_SET_STATUS_OK
 * @param status see `enum GNUNET_SET_Status`
 */
static void
handle_set_union_result (void *cls,
			 const struct GNUNET_SET_Element *element,
			 enum GNUNET_SET_Status status)
{
  struct DirectNeighbor *neighbor = cls;
  struct DirectNeighbor *dn;
  struct Target *target;
  char *status_str;

  switch (status)
  {
  case GNUNET_SET_STATUS_OK:
    status_str = "GNUNET_SET_STATUS_OK";
    break;
  case GNUNET_SET_STATUS_TIMEOUT:
    status_str = "GNUNET_SET_STATUS_TIMEOUT";
    break;
  case GNUNET_SET_STATUS_FAILURE:
    status_str = "GNUNET_SET_STATUS_FAILURE";
    break;
  case GNUNET_SET_STATUS_HALF_DONE:
    status_str = "GNUNET_SET_STATUS_HALF_DONE";
    break;
  case GNUNET_SET_STATUS_DONE:
    status_str = "GNUNET_SET_STATUS_DONE";
    break;
  default:
    status_str = "UNDEFINED";
    break;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Got SET union result: %s\n",
	      status_str);
  switch (status)
  {
  case GNUNET_SET_STATUS_OK:
    if (sizeof (struct Target) != element->size)
    {
      GNUNET_break_op (0);
      return;
    }
    if ( (NULL != (dn = GNUNET_CONTAINER_multipeermap_get (direct_neighbors, &((struct Target *) element->data)->peer))) && (DIRECT_NEIGHBOR_COST == dn->distance) )
    {
      /* this is a direct neighbor of ours, we do not care about routes
         to this peer */
      return;
    }
    target = GNUNET_new (struct Target);
    memcpy (target, element->data, sizeof (struct Target));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received information about peer `%s' with distance %u from SET\n",
                GNUNET_i2s (&target->peer),
                ntohl (target->distance) + 1);

    if (NULL == neighbor->neighbor_table_consensus)
      neighbor->neighbor_table_consensus
        = GNUNET_CONTAINER_multipeermap_create (10, GNUNET_NO);
    if (GNUNET_YES !=
	GNUNET_CONTAINER_multipeermap_put (neighbor->neighbor_table_consensus,
					   &target->peer,
					   target,
					   GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
    {
      GNUNET_break_op (0);
      GNUNET_free (target);
    }
    break;
  case GNUNET_SET_STATUS_TIMEOUT:
  case GNUNET_SET_STATUS_FAILURE:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Failed to establish DV union, will try again later\n");
    neighbor->set_op = NULL;
    if (NULL != neighbor->neighbor_table_consensus)
    {
      GNUNET_CONTAINER_multipeermap_iterate (neighbor->neighbor_table_consensus,
					     &free_targets,
					     NULL);
      GNUNET_CONTAINER_multipeermap_destroy (neighbor->neighbor_table_consensus);
      neighbor->neighbor_table_consensus = NULL;
    }
    if (0 < memcmp (&neighbor->peer,
		    &my_identity,
		    sizeof (struct GNUNET_PeerIdentity)))
      neighbor->initiate_task = GNUNET_SCHEDULER_add_delayed (GNUNET_DV_CONSENSUS_FREQUENCY,
							      &initiate_set_union,
							      neighbor);
    break;
  case GNUNET_SET_STATUS_HALF_DONE:
    break;
  case GNUNET_SET_STATUS_DONE:
    /* we got all of our updates; integrate routing table! */
    neighbor->target_removed = GNUNET_NO;
    if (NULL == neighbor->neighbor_table_consensus)
      neighbor->neighbor_table_consensus = GNUNET_CONTAINER_multipeermap_create (10, GNUNET_NO);
    if (NULL != neighbor->neighbor_table)
      GNUNET_CONTAINER_multipeermap_iterate (neighbor->neighbor_table,
                                             &check_target_removed,
                                             neighbor);
    if (GNUNET_YES == neighbor->target_removed)
    {
      /* check if we got an alternative for the removed routes */
      schedule_refresh_routes ();
    }
    /* add targets that appeared (and check for improved routes) */
    GNUNET_CONTAINER_multipeermap_iterate (neighbor->neighbor_table_consensus,
                                           &check_target_added,
                                           neighbor);
    if (NULL != neighbor->neighbor_table)
    {
      GNUNET_CONTAINER_multipeermap_iterate (neighbor->neighbor_table,
                                             &free_targets,
                                             NULL);
      GNUNET_CONTAINER_multipeermap_destroy (neighbor->neighbor_table);
      neighbor->neighbor_table = NULL;
    }
    neighbor->neighbor_table = neighbor->neighbor_table_consensus;
    neighbor->neighbor_table_consensus = NULL;

    /* operation done, schedule next run! */
    neighbor->set_op = NULL;
    if (0 < memcmp (&neighbor->peer,
		    &my_identity,
		    sizeof (struct GNUNET_PeerIdentity)))
      neighbor->initiate_task = GNUNET_SCHEDULER_add_delayed (GNUNET_DV_CONSENSUS_FREQUENCY,
							      &initiate_set_union,
							      neighbor);
    break;
  default:
    GNUNET_break (0);
    return;
  }
}


/**
 * Start creating a new DV set union construction, our neighbour has
 * asked for it (callback for listening peer).
 *
 * @param cls the 'struct DirectNeighbor' of the peer we're building
 *        a routing consensus with
 * @param other_peer the other peer
 * @param context_msg message with application specific information from
 *        the other peer
 * @param request request from the other peer, use GNUNET_SET_accept
 *        to accept it, otherwise the request will be refused
 *        Note that we don't use a return value here, as it is also
 *        necessary to specify the set we want to do the operation with,
 *        whith sometimes can be derived from the context message.
 *        Also necessary to specify the timeout.
 */
static void
listen_set_union (void *cls,
		  const struct GNUNET_PeerIdentity *other_peer,
		  const struct GNUNET_MessageHeader *context_msg,
		  struct GNUNET_SET_Request *request)
{
  struct DirectNeighbor *neighbor = cls;

  if (NULL == request)
    return; /* why??? */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Starting to create consensus with %s\n",
	      GNUNET_i2s (&neighbor->peer));
  if (NULL != neighbor->set_op)
  {
    GNUNET_SET_operation_cancel (neighbor->set_op);
    neighbor->set_op = NULL;
  }
  if (NULL != neighbor->my_set)
  {
    GNUNET_SET_destroy (neighbor->my_set);
    neighbor->my_set = NULL;
  }
  neighbor->my_set = GNUNET_SET_create (cfg,
					GNUNET_SET_OPERATION_UNION);
  neighbor->set_op = GNUNET_SET_accept (request,
					GNUNET_SET_RESULT_ADDED,
					&handle_set_union_result,
					neighbor);
  neighbor->consensus_insertion_offset = 0;
  neighbor->consensus_insertion_distance = 0;
  neighbor->consensus_elements = 0;
  build_set (neighbor);
}


/**
 * Start creating a new DV set union by initiating the connection.
 *
 * @param cls the `struct DirectNeighbor *` of the peer we're building
 *        a routing consensus with
 * @param tc scheduler context
 */
static void
initiate_set_union (void *cls,
		    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static uint16_t salt;
  struct DirectNeighbor *neighbor = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Initiating SET union with peer `%s'\n",
	      GNUNET_i2s (&neighbor->peer));
  neighbor->initiate_task = GNUNET_SCHEDULER_NO_TASK;
  neighbor->my_set = GNUNET_SET_create (cfg,
					GNUNET_SET_OPERATION_UNION);
  neighbor->set_op = GNUNET_SET_prepare (&neighbor->peer,
                                         &neighbor->real_session_id,
                                         NULL,
                                         salt++,
                                         GNUNET_SET_RESULT_ADDED,
                                         &handle_set_union_result,
                                         neighbor);
  neighbor->consensus_insertion_offset = 0;
  neighbor->consensus_insertion_distance = 0;
  neighbor->consensus_elements = 0;
  build_set (neighbor);
}


/**
 * Core handler for DV data messages.  Whatever this message
 * contains all we really have to do is rip it out of its
 * DV layering and give it to our pal the DV plugin to report
 * in with.
 *
 * @param cls closure
 * @param peer peer which sent the message (immediate sender)
 * @param message the message
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the other peer violated the protocol
 */
static int
handle_dv_route_message (void *cls, const struct GNUNET_PeerIdentity *peer,
			 const struct GNUNET_MessageHeader *message)
{
  const struct RouteMessage *rm;
  const struct GNUNET_MessageHeader *payload;
  struct Route *route;
  struct DirectNeighbor *neighbor;
  struct DirectNeighbor *dn;
  struct Target *target;
  uint32_t distance;
  char me[5];
  char src[5];
  char prev[5];
  char dst[5];

  if (ntohs (message->size) < sizeof (struct RouteMessage) + sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  rm = (const struct RouteMessage *) message;
  distance = ntohl (rm->distance);
  payload = (const struct GNUNET_MessageHeader *) &rm[1];
  if (ntohs (message->size) != sizeof (struct RouteMessage) + ntohs (payload->size))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  strncpy (prev, GNUNET_i2s (peer), 4);
  strncpy (me, GNUNET_i2s (&my_identity), 4);
  strncpy (src, GNUNET_i2s (&rm->sender), 4);
  strncpy (dst, GNUNET_i2s (&rm->target), 4);
  prev[4] = me[4] = src[4] = dst[4] = '\0';
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Handling DV message with %u bytes payload of type %u from %s to %s routed by %s to me (%s @ hop %u)\n",
              ntohs (message->size) - sizeof (struct RouteMessage),
              ntohs (payload->type),
              src, dst,
              prev, me,
              (unsigned int) distance + 1);

  if (0 == memcmp (&rm->target,
		   &my_identity,
		   sizeof (struct GNUNET_PeerIdentity)))
  {
    if ((NULL
        != (dn = GNUNET_CONTAINER_multipeermap_get (direct_neighbors,
            &rm->sender))) && (DIRECT_NEIGHBOR_COST == dn->distance))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Discarding DV message, as %s is a direct neighbor\n",
                  GNUNET_i2s (&rm->sender));
      GNUNET_STATISTICS_update (stats,
                                "# messages discarded (direct neighbor)",
                                1, GNUNET_NO);
      return GNUNET_OK;
    }
    /* message is for me, check reverse route! */
    route = GNUNET_CONTAINER_multipeermap_get (all_routes,
					       &rm->sender);
    if ( (NULL == route) &&
         (distance < DEFAULT_FISHEYE_DEPTH) )
    {
      /* don't have reverse route yet, learn it! */
      neighbor = GNUNET_CONTAINER_multipeermap_get (direct_neighbors,
                                                    peer);
      if (NULL == neighbor)
      {
        GNUNET_break (0);
        return GNUNET_SYSERR;
      }
      target = GNUNET_new (struct Target);
      target->peer = rm->sender;
      target->distance = htonl (distance);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Learning sender %s at distance %u from delivery!\n",
                  GNUNET_i2s (&rm->sender),
                  (unsigned int) distance + 1);
      if (NULL == neighbor->neighbor_table)
        neighbor->neighbor_table = GNUNET_CONTAINER_multipeermap_create (10, GNUNET_NO);
      if (GNUNET_YES !=
          GNUNET_CONTAINER_multipeermap_put (neighbor->neighbor_table,
                                             &target->peer,
                                             target,
                                             GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
      {
        GNUNET_break_op (0);
        GNUNET_free (target);
        return GNUNET_SYSERR;
      }
      add_new_route (target, neighbor);
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Delivering %u bytes from %s to myself!\n",
		ntohs (payload->size),
                GNUNET_i2s (&rm->sender));
    send_data_to_plugin (payload,
			 &rm->sender,
			 1 + distance);
    return GNUNET_OK;
  }
  if ( (NULL == GNUNET_CONTAINER_multipeermap_get (direct_neighbors,
                                                   &rm->sender)) &&
       (NULL == GNUNET_CONTAINER_multipeermap_get (all_routes,
                                                   &rm->sender)) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Learning sender %s at distance %u from forwarding!\n",
                GNUNET_i2s (&rm->sender),
                1 + distance);
    neighbor = GNUNET_CONTAINER_multipeermap_get (direct_neighbors,
                                                  peer);
    if (NULL == neighbor)
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    target = GNUNET_new (struct Target);
    target->peer = rm->sender;
    target->distance = htonl (distance);
    if (NULL == neighbor->neighbor_table)
      neighbor->neighbor_table = GNUNET_CONTAINER_multipeermap_create (10, GNUNET_NO);
    if (GNUNET_YES !=
        GNUNET_CONTAINER_multipeermap_put (neighbor->neighbor_table,
                                           &target->peer,
                                           target,
                                           GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
    {
      GNUNET_break_op (0);
      GNUNET_free (target);
    }
    add_new_route (target, neighbor);
  }

  route = GNUNET_CONTAINER_multipeermap_get (all_routes,
					     &rm->target);
  if (NULL == route)
  {
    neighbor = GNUNET_CONTAINER_multipeermap_get (direct_neighbors,
                                                  &rm->target);
    if (NULL == neighbor)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "No route to %s, not routing %u bytes!\n",
                  GNUNET_i2s (&rm->target),
                  ntohs (payload->size));
      GNUNET_STATISTICS_update (stats,
                                "# messages discarded (no route)",
                                1, GNUNET_NO);
      return GNUNET_OK;
    }
  }
  else
  {
    neighbor = route->next_hop;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Forwarding message to %s\n",
	      GNUNET_i2s (&neighbor->peer));
  forward_payload (neighbor,
		   distance + 1,
		   0,
		   &rm->sender,
		   &rm->target,
		   payload);
  return GNUNET_OK;
}


/**
 * Service server's handler for message send requests (which come
 * bubbling up to us through the DV plugin).
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_dv_send_message (void *cls, struct GNUNET_SERVER_Client *client,
                        const struct GNUNET_MessageHeader *message)
{
  struct Route *route;
  const struct GNUNET_DV_SendMessage *msg;
  const struct GNUNET_MessageHeader *payload;

  if (ntohs (message->size) < sizeof (struct GNUNET_DV_SendMessage) + sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  msg = (const struct GNUNET_DV_SendMessage *) message;
  GNUNET_break (0 != ntohl (msg->uid));
  payload = (const struct GNUNET_MessageHeader *) &msg[1];
  if (ntohs (message->size) != sizeof (struct GNUNET_DV_SendMessage) + ntohs (payload->size))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  route = GNUNET_CONTAINER_multipeermap_get (all_routes,
					     &msg->target);
  if (NULL == route)
  {
    /* got disconnected */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No route to %s, dropping local message of type %u\n",
                GNUNET_i2s (&msg->target),
                ntohs (payload->type));
    GNUNET_STATISTICS_update (stats,
			      "# local messages discarded (no route)",
			      1, GNUNET_NO);
    send_ack_to_plugin (&msg->target, ntohl (msg->uid), GNUNET_YES);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Forwarding %u bytes of type %u to %s\n",
	      ntohs (payload->size),
              ntohs (payload->type),
	      GNUNET_i2s (&msg->target));

  forward_payload (route->next_hop,
		   0 /* first hop, distance is zero */,
		   htonl (msg->uid),
		   &my_identity,
		   &msg->target,
		   payload);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Cleanup all of the data structures associated with a given neighbor.
 *
 * @param neighbor neighbor to clean up
 */
static void
cleanup_neighbor (struct DirectNeighbor *neighbor)
{
  struct PendingMessage *pending;

  while (NULL != (pending = neighbor->pm_head))
  {
    neighbor->pm_queue_size--;
    GNUNET_CONTAINER_DLL_remove (neighbor->pm_head,
				 neighbor->pm_tail,
				 pending);
    GNUNET_free (pending);
  }
  handle_direct_disconnect (neighbor);
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multipeermap_remove (direct_neighbors,
						       &neighbor->peer,
						       neighbor));
  GNUNET_free (neighbor);
}


/**
 * Method called whenever a given peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
handle_core_disconnect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct DirectNeighbor *neighbor;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received core peer disconnect message for peer `%s'!\n",
	      GNUNET_i2s (peer));
  /* Check for disconnect from self message */
  if (0 == memcmp (&my_identity, peer, sizeof (struct GNUNET_PeerIdentity)))
    return;
  neighbor =
      GNUNET_CONTAINER_multipeermap_get (direct_neighbors, peer);
  if (NULL == neighbor)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_break (GNUNET_YES == neighbor->connected);
  neighbor->connected = GNUNET_NO;
  if (DIRECT_NEIGHBOR_COST == neighbor->distance)
  {

    GNUNET_STATISTICS_update (stats,
			      "# peers connected (1-hop)",
			      -1, GNUNET_NO);
  }
  cleanup_neighbor (neighbor);

  if (GNUNET_YES == in_shutdown)
    return;
  schedule_refresh_routes ();
}


/**
 * Multipeermap iterator for freeing routes.  Should never be called.
 *
 * @param cls NULL
 * @param key key value stored under
 * @param value the route to be freed
 * @return #GNUNET_YES to continue iteration, #GNUNET_NO to stop
 */
static int
free_route (void *cls,
            const struct GNUNET_PeerIdentity *key,
            void *value)
{
  struct Route *route = value;

  GNUNET_break (0);
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multipeermap_remove (all_routes, key, value));
  release_route (route);
  send_disconnect_to_plugin (&route->target.peer);
  GNUNET_free (route);
  return GNUNET_YES;
}


/**
 * Multipeermap iterator for freeing direct neighbors. Should never be called.
 *
 * @param cls NULL
 * @param key key value stored under
 * @param value the direct neighbor to be freed
 * @return #GNUNET_YES to continue iteration, #GNUNET_NO to stop
 */
static int
free_direct_neighbors (void *cls,
                       const struct GNUNET_PeerIdentity *key,
                       void *value)
{
  struct DirectNeighbor *neighbor = value;

  cleanup_neighbor (neighbor);
  return GNUNET_YES;
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  unsigned int i;

  in_shutdown = GNUNET_YES;
  GNUNET_assert (NULL != core_api);
  GNUNET_CORE_disconnect (core_api);
  core_api = NULL;
  GNUNET_ATS_performance_done (ats);
  ats = NULL;
  GNUNET_CONTAINER_multipeermap_iterate (direct_neighbors,
                                         &free_direct_neighbors, NULL);
  GNUNET_CONTAINER_multipeermap_iterate (all_routes,
                                         &free_route, NULL);
  GNUNET_CONTAINER_multipeermap_destroy (direct_neighbors);
  GNUNET_CONTAINER_multipeermap_destroy (all_routes);
  GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
  stats = NULL;
  GNUNET_SERVER_notification_context_destroy (nc);
  nc = NULL;
  for (i=0;i<DEFAULT_FISHEYE_DEPTH;i++)
  {
    GNUNET_array_grow (consensi[i].targets,
		       consensi[i].array_length,
		       0);
  }
  if (GNUNET_SCHEDULER_NO_TASK != rr_task)
  {
    GNUNET_SCHEDULER_cancel (rr_task);
    rr_task = GNUNET_SCHEDULER_NO_TASK;
  }
}


/**
 * Notify newly connected client about an existing route.
 *
 * @param cls the `struct GNUNET_SERVER_Client *`
 * @param key peer identity
 * @param value the `struct Route *`
 * @return #GNUNET_OK (continue to iterate)
 */
static int
notify_client_about_route (void *cls,
                           const struct GNUNET_PeerIdentity *key,
                           void *value)
{
  struct GNUNET_SERVER_Client *client = cls;
  struct Route *route = value;
  struct GNUNET_DV_ConnectMessage cm;

  memset (&cm, 0, sizeof (cm));
  cm.header.size = htons (sizeof (cm));
  cm.header.type = htons (GNUNET_MESSAGE_TYPE_DV_CONNECT);
  cm.distance = htonl (route->target.distance);
  cm.peer = route->target.peer;

  GNUNET_SERVER_notification_context_unicast (nc,
					      client,
					      &cm.header,
					      GNUNET_NO);
  return GNUNET_OK;
}


/**
 * Handle START-message.  This is the first message sent to us
 * by the client (can only be one!).
 *
 * @param cls closure (always NULL)
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_start (void *cls, struct GNUNET_SERVER_Client *client,
              const struct GNUNET_MessageHeader *message)
{
  GNUNET_SERVER_notification_context_add (nc, client);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  GNUNET_CONTAINER_multipeermap_iterate (all_routes,
					 &notify_client_about_route,
					 client);
}


/**
 * Called on core init.
 *
 * @param cls unused
 * @param identity this peer's identity
 */
static void
core_init (void *cls,
           const struct GNUNET_PeerIdentity *identity)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "I am peer: %s\n",
              GNUNET_i2s (identity));
  my_identity = *identity;
}


/**
 * Process dv requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  static struct GNUNET_CORE_MessageHandler core_handlers[] = {
    {&handle_dv_route_message, GNUNET_MESSAGE_TYPE_DV_ROUTE, 0},
    {NULL, 0, 0}
  };
  static struct GNUNET_SERVER_MessageHandler plugin_handlers[] = {
    {&handle_start, NULL,
     GNUNET_MESSAGE_TYPE_DV_START,
     sizeof (struct GNUNET_MessageHeader) },
    { &handle_dv_send_message, NULL,
      GNUNET_MESSAGE_TYPE_DV_SEND,
      0},
    {NULL, NULL, 0, 0}
  };
  in_shutdown = GNUNET_NO;
  cfg = c;
  direct_neighbors = GNUNET_CONTAINER_multipeermap_create (128, GNUNET_NO);
  all_routes = GNUNET_CONTAINER_multipeermap_create (65536, GNUNET_NO);
  core_api = GNUNET_CORE_connect (cfg, NULL,
				  &core_init,
				  &handle_core_connect,
				  &handle_core_disconnect,
				  NULL, GNUNET_NO,
				  NULL, GNUNET_NO,
				  core_handlers);

  if (NULL == core_api)
    return;
  ats = GNUNET_ATS_performance_init (cfg, &handle_ats_update, NULL);
  if (NULL == ats)
  {
    GNUNET_CORE_disconnect (core_api);
    core_api = NULL;
    return;
  }
  nc = GNUNET_SERVER_notification_context_create (server,
						  MAX_QUEUE_SIZE_PLUGIN);
  stats = GNUNET_STATISTICS_create ("dv", cfg);
  GNUNET_SERVER_add_handlers (server, plugin_handlers);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
				&shutdown_task, NULL);
}


/**
 * The main function for the dv service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "dv", GNUNET_SERVICE_OPTION_NONE,
                              &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-dv.c */
