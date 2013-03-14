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
 *
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_core_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet_consensus_service.h"
#include "dv.h"

/**
 * How often do we establish the consensu?
 */
#define GNUNET_DV_CONSENSUS_FREQUENCY GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 5))

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
   * How many hops (1-3) is this peer away?
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
   * Type: GNUNET_MESSAGE_TYPE_DV_ROUTE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Expected (remaining) distance.  Must be always smaller than
   * DEFAULT_FISHEYE_DEPTH, should be zero at the target.  Must
   * be decremented by one at each hop.  Peers must not forward
   * these messages further once the counter has reached zero.
   */
  uint32_t distance GNUNET_PACKED;

  /**
   * The (actual) target of the message (this peer, if distance is zero).
   */
  struct GNUNET_PeerIdentity target;

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
   * Ultimate target for the message.
   */
  struct GNUNET_PeerIdentity ultimate_target;

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
   */ 
  struct GNUNET_CONTAINER_MultiHashMap *neighbor_table;

  /**
   * Updated routing table of the neighbor, under construction,
   * NULL if we are not currently building it.
   * Keys are peer identities, values are 'struct Target' entries.
   */ 
  struct GNUNET_CONTAINER_MultiHashMap *neighbor_table_consensus;

  /**
   * Active consensus, if we are currently synchronizing the
   * routing tables.
   */
  struct GNUNET_CONSENSUS_Handle *consensus;

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
   * Size of the 'targets' array.
   */
  unsigned int array_length;

};


/**
 * Hashmap of all of our direct neighbors (no DV routing).
 */
static struct GNUNET_CONTAINER_MultiHashMap *direct_neighbors;

/**
 * Hashmap with all routes that we currently support; contains 
 * routing information for all peers up to distance DEFAULT_FISHEYE_DEPTH.
 */
static struct GNUNET_CONTAINER_MultiHashMap *all_routes;

/**
 * Array of consensus sets we expose to the outside world.  Sets
 * are structured by the distance to the target.
 */
static struct ConsensusSet consensi[DEFAULT_FISHEYE_DEPTH - 1];

/**
 * ID of the task we use to (periodically) update our consensus
 * with other peers.
 */
static GNUNET_SCHEDULER_Task consensus_task;

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
 * The client, the DV plugin connected to us.  Hopefully
 * this client will never change, although if the plugin dies
 * and returns for some reason it may happen.
 */
static struct GNUNET_SERVER_Client *client_handle;

/**
 * Transmit handle to the plugin.
 */
static struct GNUNET_SERVER_TransmitHandle *plugin_transmit_handle;

/**
 * Head of DLL for client messages
 */
static struct PendingMessage *plugin_pending_head;

/**
 * Tail of DLL for client messages
 */
static struct PendingMessage *plugin_pending_tail;

/**
 * Handle for the statistics service.
 */
struct GNUNET_STATISTICS_Handle *stats;

/**
 * How far out to keep peers we learn about.
 */
static unsigned long long fisheye_depth;


/**
 * Get distance information from 'atsi'.
 *
 * @param atsi performance data
 * @param atsi_count number of entries in atsi
 * @return connected transport distance
 */
static uint32_t
get_atsi_distance (const struct GNUNET_ATS_Information *atsi,
                   unsigned int atsi_count)
{
  unsigned int i;

  for (i = 0; i < atsi_count; i++)
    if (ntohl (atsi[i].type) == GNUNET_ATS_QUALITY_NET_DISTANCE)
      return ntohl (atsi->value);
  /* FIXME: we do not have distance data? Assume direct neighbor. */
  return DIRECT_NEIGHBOR_COST;
}


/**
 * Function called to notify a client about the socket
 * begin ready to queue more data.  "buf" will be
 * NULL and "size" zero if the socket was closed for
 * writing in the meantime.
 *
 * @param cls closure
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_to_plugin (void *cls, size_t size, void *buf)
{
  char *cbuf = buf;
  struct PendingMessage *reply;
  size_t off;
  size_t msize;

  plugin_transmit_handle = NULL;
  if (NULL == buf)
  {
    /* client disconnected */    
    return 0;
  }
  off = 0;
  while ( (NULL != (reply = plugin_pending_head)) &&
	  (size >= off + (msize = ntohs (reply->msg->size))))
  {
    GNUNET_CONTAINER_DLL_remove (plugin_pending_head, plugin_pending_tail,
                                 reply);
    memcpy (&cbuf[off], reply->msg, msize);
    GNUNET_free (reply);
    off += msize;
  }
  if (NULL != plugin_pending_head)
    plugin_transmit_handle =
      GNUNET_SERVER_notify_transmit_ready (client_handle,
					   msize,
					   GNUNET_TIME_UNIT_FOREVER_REL,
					   &transmit_to_plugin, NULL);
  return off;
}


/**
 * Forward a message from another peer to the plugin.
 *
 * @param message the message to send to the plugin
 * @param distant_neighbor the original sender of the message
 * @param distnace distance to the original sender of the message
 */
static void
send_data_to_plugin (const struct GNUNET_MessageHeader *message, 
		     struct GNUNET_PeerIdentity *distant_neighbor, 
		     uint32_t distance)
{
  struct GNUNET_DV_ReceivedMessage *received_msg;
  struct PendingMessage *pending_message;
  size_t size;

  if (NULL == client_handle)
  {
    GNUNET_STATISTICS_update (stats,
			      "# messages discarded (no plugin)",
			      1, GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("Refusing to queue messages, DV plugin not active.\n"));
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Delivering message from peer `%s'\n",
              GNUNET_i2s (distant_neighbor));
  size = sizeof (struct GNUNET_DV_ReceivedMessage) + 
    ntohs (message->size);
  if (size >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {    
    GNUNET_break (0); /* too big */
    return;
  }
  pending_message = GNUNET_malloc (sizeof (struct PendingMessage) + size);
  received_msg = (struct GNUNET_DV_ReceivedMessage *) &pending_message[1];
  received_msg->header.size = htons (size);
  received_msg->header.type = htons (GNUNET_MESSAGE_TYPE_DV_RECV);
  received_msg->distance = htonl (distance);
  received_msg->sender = *distant_neighbor;
  memcpy (&received_msg[1], message, ntohs (message->size));
  GNUNET_CONTAINER_DLL_insert_tail (plugin_pending_head, 
				    plugin_pending_tail,
				    pending_message);  
  if (NULL == plugin_transmit_handle)
    plugin_transmit_handle =
      GNUNET_SERVER_notify_transmit_ready (client_handle, size,
					   GNUNET_TIME_UNIT_FOREVER_REL,
					   &transmit_to_plugin, NULL);
}


/**
 * Forward a control message to the plugin.
 *
 * @param message the message to send to the plugin
 * @param distant_neighbor the original sender of the message
 * @param distnace distance to the original sender of the message
 */
static void
send_control_to_plugin (const struct GNUNET_MessageHeader *message)
{
  struct PendingMessage *pending_message;
  size_t size;

  if (NULL == client_handle)
  {
    GNUNET_STATISTICS_update (stats,
			      "# control messages discarded (no plugin)",
			      1, GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("Refusing to queue messages, DV plugin not active.\n"));
    return;
  }
  size = ntohs (message->size);
  pending_message = GNUNET_malloc (sizeof (struct PendingMessage) + size);
  memcpy (&pending_message[1], message, size);
  GNUNET_CONTAINER_DLL_insert_tail (plugin_pending_head, 
				    plugin_pending_tail,
				    pending_message);  
  if (NULL == plugin_transmit_handle)
    plugin_transmit_handle =
      GNUNET_SERVER_notify_transmit_ready (client_handle, size,
					   GNUNET_TIME_UNIT_FOREVER_REL,
					   &transmit_to_plugin, NULL);
}


/**
 * Give an ACK message to the plugin, we transmitted a message for it.
 *
 * @param target peer that received the message
 * @param uid plugin-chosen UID for the message
 */
static void
send_ack_to_plugin (struct GNUNET_PeerIdentity *target, 
		    uint32_t uid)
{
  struct GNUNET_DV_AckMessage ack_msg;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Delivering ACK for message to peer `%s'\n",
              GNUNET_i2s (target));
  ack_msg.header.size = htons (sizeof (ack_msg));
  ack_msg.header.type = htons (GNUNET_MESSAGE_TYPE_DV_SEND_ACK);
  ack_msg.uid = htonl (uid);
  ack_msg.target = *target;
  send_control_to_plugin (&ack_msg.header);
}


/**
 * Give a CONNECT message to the plugin.
 *
 * @param target peer that connected
 * @param distance distance to the target
 */
static void
send_connect_to_plugin (const struct GNUNET_PeerIdentity *target, 
			uint32_t distance)
{
  struct GNUNET_DV_ConnectMessage cm;

  if (NULL == client_handle)
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Delivering CONNECT about peer `%s'\n",
              GNUNET_i2s (target));
  cm.header.size = htons (sizeof (cm));
  cm.header.type = htons (GNUNET_MESSAGE_TYPE_DV_CONNECT);
  cm.distance = htonl (distance);
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

  if (NULL == client_handle)
    return;
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
    /* peer disconnected */
    return 0;
  }
  off = 0;
  pending = dn->pm_head;
  off = 0;
  while ( (NULL != (pending = dn->pm_head)) &&
	  (size >= off + (msize = ntohs (pending->msg->size))))
  {
    GNUNET_CONTAINER_DLL_remove (dn->pm_head,
				 dn->pm_tail,
                                 pending);
    memcpy (&cbuf[off], pending->msg, msize);
    send_ack_to_plugin (&pending->ultimate_target,
			pending->uid);
    GNUNET_free (pending);
    off += msize;
  }
  if (NULL != dn->pm_head)
    dn->cth =
      GNUNET_CORE_notify_transmit_ready (core_api,
					 GNUNET_YES /* cork */,
					 0 /* priority */,
					 GNUNET_TIME_UNIT_FOREVER_REL,
					 &dn->peer,
					 msize,					 
					 &core_transmit_notify, dn);
  return off;
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

  cs = &consensi[distance];
  i = 0;
  while ( (i < cs->array_length) &&
	  (NULL != cs->targets[i]) ) i++;
  if (i == cs->array_length)
    GNUNET_array_grow (cs->targets,
		       cs->array_length,
		       cs->array_length * 2 + 2);
  return i;
}


/**
 * Method called whenever a peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param atsi performance data
 * @param atsi_count number of entries in atsi
 */
static void
handle_core_connect (void *cls, const struct GNUNET_PeerIdentity *peer,
                     const struct GNUNET_ATS_Information *atsi,
                     unsigned int atsi_count)
{
  struct DirectNeighbor *neighbor;
  struct Route *route;
  uint32_t distance;
  unsigned int i;

  /* Check for connect to self message */
  if (0 == memcmp (&my_identity, peer, sizeof (struct GNUNET_PeerIdentity)))
    return;
  distance = get_atsi_distance (atsi, atsi_count);
  neighbor = GNUNET_CONTAINER_multihashmap_get (direct_neighbors, 
						&peer->hashPubKey);
  if (NULL != neighbor)
  {
    GNUNET_break (0);
    return;
  }
  if (DIRECT_NEIGHBOR_COST != distance) 
    return; /* is a DV-neighbor */
  neighbor = GNUNET_malloc (sizeof (struct DirectNeighbor));
  neighbor->peer = *peer;
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multihashmap_put (direct_neighbors,
						    &peer->hashPubKey,
						    neighbor,
						    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));

  route = GNUNET_CONTAINER_multihashmap_get (all_routes, 
					     &peer->hashPubKey);
  if (NULL == route)  
  {
    route->target.peer = *peer;
    i = get_consensus_slot (DIRECT_NEIGHBOR_COST);
    route->set_offset = i;
    consensi[DIRECT_NEIGHBOR_COST].targets[i] = route;
    GNUNET_assert (GNUNET_YES ==
		   GNUNET_CONTAINER_multihashmap_put (all_routes,
						      &route->target.peer.hashPubKey,
						      route,
						      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }
  else
  {
    /* move to new consensi slot */
    send_disconnect_to_plugin (peer);
    consensi[route->target.distance].targets[route->set_offset] = NULL;
    i = get_consensus_slot (DIRECT_NEIGHBOR_COST);
    route->set_offset = i;
    consensi[DIRECT_NEIGHBOR_COST].targets[i] = route;      
  }
  route->next_hop = neighbor;
  route->target.distance = DIRECT_NEIGHBOR_COST;
  // FIXME: begin exchange_routing_information!
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
 * @param atsi transport ATS information (latency, distance, etc.)
 * @param atsi_count number of entries in atsi
 */
static int
handle_dv_route_message (void *cls, const struct GNUNET_PeerIdentity *peer,
			 const struct GNUNET_MessageHeader *message,
			 const struct GNUNET_ATS_Information *atsi,
			 unsigned int atsi_count)
{
  GNUNET_break (0); // FIXME
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
  GNUNET_break (0); // FIXME
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Multihashmap iterator for freeing routes that go via a particular
 * neighbor that disconnected and is thus no longer available.
 *
 * @param cls the direct neighbor that is now unavailable
 * @param key key value stored under
 * @param value a 'struct Route' that may or may not go via neighbor
 *
 * @return GNUNET_YES to continue iteration, GNUNET_NO to stop
 */
static int
cull_routes (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  struct DirectNeighbor *neighbor = cls;
  struct Route *route = value;

  if (route->next_hop != neighbor)
    return GNUNET_YES; /* not affected */

  /* FIXME: destroy route! */
  GNUNET_break (0);

  return GNUNET_YES;
}


/**
 * Multihashmap iterator for checking if a given route is
 * (now) useful to this peer.
 *
 * @param cls the direct neighbor for the given route
 * @param key key value stored under
 * @param value a 'struct Target' that may or may not be useful
 *
 * @return GNUNET_YES to continue iteration, GNUNET_NO to stop
 */
static int
cull_routes (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  struct DirectNeighbor *neighbor = cls;
  struct Target *target = value;
  struct Route *cur;
  
  cur = GNUNET_CONTAINER_multihashmap_get (all_routes,
					   key);
  if (NULL != cur)
  {
    if (cur->target.distance > target->distance)
    {
      /* FIXME: this 'target' is cheaper than the existing route;
	 switch route! */
    }
    return GNUNET_YES; /* got a route to this target already */
  }
  cur = GNUNET_malloc (sizeof (struct Route));
  cur->next_hop = neighbor;
  cur->target = *target;
  cur->set_offset = get_consensus_slot (target->distance);
  GNUNET_CONTAINER_multihashmap_put (all_routes,
				     key,
				     cur);
  return GNUNET_YES;
}


/**
 * Multihashmap iterator for finding routes that were previously
 * "hidden" due to a better route (called after a disconnect event).
 *
 * @param cls NULL
 * @param key peer identity of the given direct neighbor
 * @param value a 'struct DirectNeighbor' to check for additional routes
 * @return GNUNET_YES to continue iteration
 */
static int
refresh_routes (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  struct DirectNeighbor *neighbor = value;

  if (NULL != neighbor->neighbor_table)
    GNUNET_CONTAINER_multihashmap_iterate (neighbor->neighbor_table,
					   &check_possible_route,
					   neighbor);
  return GNUNET_YES;
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
  struct PendingMessage *pending;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received core peer disconnect message for peer `%s'!\n",
	      GNUNET_i2s (peer));
  /* Check for disconnect from self message */
  if (0 == memcmp (&my_identity, peer, sizeof (struct GNUNET_PeerIdentity)))
    return;
  neighbor =
      GNUNET_CONTAINER_multihashmap_get (direct_neighbors, &peer->hashPubKey);
  if (NULL == neighbor)
  {
    /* must have been a DV-neighbor, ignore */
    return;
  }
  while (NULL != (pending = neighbor->pm_head))
  {
    GNUNET_CONTAINER_DLL_remove (neighbor->pm_head,
				 neighbor->pm_tail,
				 pending);    
    GNUNET_free (pending);
  }
  GNUNET_CONTAINER_multihashmap_iterate (all_routes,
					 &cull_routes,
                                         neighbor);
  if (NULL != neighbor->cth)
  {
    GNUNET_CORE_notify_transmit_ready_cancel (neighbor->cth);
    neighbor->cth = NULL;
  }
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multihashmap_remove (direct_neighbors, 
						       &peer->hashPubKey,
						       neighbor));
  GNUNET_free (neighbor);
  GNUNET_CONTAINER_multihashmap_iterate (direct_neighbors,
					 &refresh_routes,
                                         NULL);
}



/**
 * Multihashmap iterator for freeing routes.  Should never be called.
 *
 * @param cls NULL
 * @param key key value stored under
 * @param value the route to be freed
 *
 * @return GNUNET_YES to continue iteration, GNUNET_NO to stop
 */
static int
free_route (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  GNUNET_break (0);
  // FIXME: notify client about disconnect
  return GNUNET_YES;
}


/**
 * Multihashmap iterator for freeing direct neighbors. Should never be called.
 *
 * @param cls NULL
 * @param key key value stored under
 * @param value the direct neighbor to be freed
 *
 * @return GNUNET_YES to continue iteration, GNUNET_NO to stop
 */
static int
free_direct_neighbors (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  struct DirectNeighbor *dn = value;

  GNUNET_break (0);
  // FIXME: release resources, ...
  return GNUNET_YES;
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PendingMessage *pending;
  unsigned int i;

  GNUNET_CONTAINER_multihashmap_iterate (direct_neighbors,
                                         &free_direct_neighbors, NULL);
  GNUNET_CONTAINER_multihashmap_destroy (direct_neighbors);
  GNUNET_CONTAINER_multihashmap_iterate (all_routes,
                                         &free_route, NULL);
  GNUNET_CONTAINER_multihashmap_destroy (all_routes);
  GNUNET_CORE_disconnect (core_api);
  core_api = NULL;
  GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
  stats = NULL;
  while (NULL != (pending = plugin_pending_head))
  {
    GNUNET_CONTAINER_DLL_remove (plugin_pending_head,
				 plugin_pending_tail,
				 pending);
    GNUNET_free (pending);
  }
  for (i=0;i<DEFAULT_FISHEYE_DEPTH - 1;i++)
    GNUNET_array_grow (consensi[i].targets,
		       consensi[i].array_length,
		       0);
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
  if (NULL != client_handle)
  {
    /* forcefully drop old client */
    GNUNET_SERVER_client_disconnect (client_handle);
    GNUNET_SERVER_client_drop (client_handle);
  }
  client_handle = client;
  GNUNET_SERVER_client_keep (client_handle);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Called on core init.
 *
 * @param cls unused
 * @param server legacy
 * @param identity this peer's identity
 */
static void
core_init (void *cls, struct GNUNET_CORE_Handle *server,
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

  cfg = c;
  direct_neighbors = GNUNET_CONTAINER_multihashmap_create (128, GNUNET_NO);
  all_routes = GNUNET_CONTAINER_multihashmap_create (65536, GNUNET_NO);
  core_api = GNUNET_CORE_connect (cfg, NULL,
				  &core_init, 
				  &handle_core_connect,
				  &handle_core_disconnect,
				  NULL, GNUNET_NO, 
				  NULL, GNUNET_NO, 
				  core_handlers);

  if (NULL == core_api)
    return;
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
