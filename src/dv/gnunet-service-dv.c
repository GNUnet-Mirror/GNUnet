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
 * Routing neighbors are neighbors that we exchange
 * routing information with; that is, their distance
 * must be strictly less than the DEFAULT_FISHEYE_DEPTH;
 * they can also be direct neighbors.
 */
struct RoutingNeighbor
{

  /**
   * Which peer is this, and how do we talk to it?
   */
  struct Route route;

  /**
   * Routing table of the neighbor, NULL if not yet established.
   */ 
  struct GNUNET_CONTAINER_MultiHashMap *neighbor_table;

  /**
   * Updated routing table of the neighbor, under construction,
   * NULL if we are not currently building it.
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
 * Set of targets we bring to a consensus; all targets in a set have a
 * distance equal to the sets distance (which is implied by the array
 * index of the set).
 */
struct ConsensusSet
{

  /**
   * Array of targets in the set, may include NULL 
   * entries if a neighbor has disconnected; the
   * targets are allocated with the respective
   * 'struct Route', not here.
   */
  struct Target **targets;

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
 * Hashmap of all of the neighbors we exchange routing information
 * with (peers up to DEFAULT_FISHEYE_DEPTH - 1 distance from us).
 */
static struct GNUNET_CONTAINER_MultiHashMap *routing_neighbors;

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
  received_msg->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_DV_RECV);
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
 * Give an ACK message to the plugin, we transmitted a message for it.
 *
 * @param target peer that received the message
 * @param uid plugin-chosen UID for the message
 */
static void
send_ack_to_plugin (struct GNUNET_PeerIdentity *target, 
		    uint32_t uid)
{
  struct GNUNET_DV_AckMessage *ack_msg;
  struct PendingMessage *pending_message;
  size_t size;

  if (NULL == client_handle)
  {
    GNUNET_STATISTICS_update (stats,
			      "# acks discarded (no plugin)",
			      1, GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("Refusing to queue messages, DV plugin not active.\n"));
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Delivering ACK for message to peer `%s'\n",
              GNUNET_i2s (target));
  size = sizeof (struct GNUNET_DV_AckMessage);
  pending_message = GNUNET_malloc (sizeof (struct PendingMessage) + size);
  ack_msg = (struct GNUNET_DV_AckMessage *) &pending_message[1];
  ack_msg->header.size = htons (size);
  ack_msg->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_DV_SEND_ACK);
  ack_msg->uid = htonl (uid);
  ack_msg->target = *target;
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


#if 0
// ////////////////////////////////////////////////////////////////////////


/**
 * Send a DV data message via DV.
 *
 * @param sender the original sender of the message
 * @param recipient the next hop recipient, may be our direct peer, maybe not
 * @param send_context the send context
 */
static int
send_message_via (const struct GNUNET_PeerIdentity *sender,
                  const struct GNUNET_PeerIdentity *recipient,
                  struct DV_SendContext *send_context)
{
  p2p_dv_MESSAGE_Data *toSend;
  unsigned int msg_size;
  unsigned int recipient_id;
  unsigned int sender_id;
  struct DistantNeighbor *source;
  struct PendingMessage *pending_message;
  struct FindIDContext find_context;

  msg_size = send_context->message_size + sizeof (p2p_dv_MESSAGE_Data);

  find_context.dest = send_context->distant_peer;
  find_context.via = recipient;
  find_context.tid = 0;
  GNUNET_CONTAINER_multihashmap_get_multiple (extended_neighbors,
                                              &send_context->
                                              distant_peer->hashPubKey,
                                              &find_specific_id, &find_context);

  if (find_context.tid == 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "%s: find_specific_id failed to find peer!\n", my_short_id);
    /* target unknown to us, drop! */
    return GNUNET_SYSERR;
  }
  recipient_id = find_context.tid;

  if (0 == (memcmp (&my_identity, sender, sizeof (struct GNUNET_PeerIdentity))))
  {
    sender_id = 0;
    source =
        GNUNET_CONTAINER_multihashmap_get (extended_neighbors,
                                           &sender->hashPubKey);
    if (source != NULL)
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "%s: send_message_via found %s, myself in extended peer list???\n",
                  my_short_id, GNUNET_i2s (&source->identity));
  }
  else
  {
    source =
        GNUNET_CONTAINER_multihashmap_get (extended_neighbors,
                                           &sender->hashPubKey);
    if (source == NULL)
    {
      /* sender unknown to us, drop! */
      return GNUNET_SYSERR;
    }
    sender_id = source->our_id;
  }

  pending_message = GNUNET_malloc (sizeof (struct PendingMessage) + msg_size);
  pending_message->msg = (struct GNUNET_MessageHeader *) &pending_message[1];
  pending_message->send_result = send_context->send_result;
  memcpy (&pending_message->recipient, recipient,
          sizeof (struct GNUNET_PeerIdentity));
  pending_message->msg_size = msg_size;
  pending_message->importance = send_context->importance;
  pending_message->timeout = send_context->timeout;
  toSend = (p2p_dv_MESSAGE_Data *) pending_message->msg;
  toSend->header.size = htons (msg_size);
  toSend->header.type = htons (GNUNET_MESSAGE_TYPE_DV_DATA);
  toSend->sender = htonl (sender_id);
  toSend->recipient = htonl (recipient_id);
#if DEBUG_DV_MESSAGES
  toSend->uid = send_context->uid;      /* Still sent around in network byte order */
#else
  toSend->uid = htonl (0);
#endif

  memcpy (&toSend[1], send_context->message, send_context->message_size);

#if DEBUG_DV
  memcpy (&shortname, GNUNET_i2s (send_context->distant_peer), 4);
  shortname[4] = '\0';
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Notifying core of send to destination `%s' via `%s' size %u\n",
              "DV", &shortname, GNUNET_i2s (recipient), msg_size);
#endif

  GNUNET_CONTAINER_DLL_insert_after (core_pending_head, core_pending_tail,
                                     core_pending_tail, pending_message);

  GNUNET_SCHEDULER_add_now (try_core_send, NULL);

  return GNUNET_YES;
}

/**
 * Given a FindLeastCostContext, and a set
 * of peers that match the target, return the cheapest.
 *
 * @param cls closure, a struct FindLeastCostContext
 * @param key the key identifying the target peer
 * @param value the target peer
 *
 * @return GNUNET_YES to continue iteration, GNUNET_NO to stop
 */
static int
find_least_cost_peer (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  struct FindLeastCostContext *find_context = cls;
  struct DistantNeighbor *dn = value;

  if (dn->cost < find_context->least_cost)
  {
    find_context->target = dn;
  }
  if (dn->cost == DIRECT_NEIGHBOR_COST)
    return GNUNET_NO;
  return GNUNET_YES;
}

/**
 * Send a DV data message via DV.
 *
 * @param recipient the ultimate recipient of this message
 * @param sender the original sender of the message
 * @param specific_neighbor the specific neighbor to send this message via
 * @param message the packed message
 * @param message_size size of the message
 * @param importance what priority to send this message with
 * @param uid the unique identifier of this message (or 0 for none)
 * @param timeout how long to possibly delay sending this message
 */
static int
send_message (const struct GNUNET_PeerIdentity *recipient,
              const struct GNUNET_PeerIdentity *sender,
              const struct DistantNeighbor *specific_neighbor,
              const struct GNUNET_MessageHeader *message, size_t message_size,
              unsigned int importance, unsigned int uid,
              struct GNUNET_TIME_Relative timeout)
{
  p2p_dv_MESSAGE_Data *toSend;
  unsigned int msg_size;
  unsigned int cost;
  unsigned int recipient_id;
  unsigned int sender_id;
  struct DistantNeighbor *target;
  struct DistantNeighbor *source;
  struct PendingMessage *pending_message;
  struct FindLeastCostContext find_least_ctx;

#if DEBUG_DV_PEER_NUMBERS
  struct GNUNET_CRYPTO_HashAsciiEncoded encPeerFrom;
  struct GNUNET_CRYPTO_HashAsciiEncoded encPeerTo;
  struct GNUNET_CRYPTO_HashAsciiEncoded encPeerVia;
#endif
  msg_size = message_size + sizeof (p2p_dv_MESSAGE_Data);

  find_least_ctx.least_cost = -1;
  find_least_ctx.target = NULL;
  /*
   * Need to find the least cost peer, lest the transport selection keep
   * picking the same DV route for the same destination which results
   * in messages looping forever.  Relatively cheap, we don't iterate
   * over all known peers, just those that apply.
   */
  GNUNET_CONTAINER_multihashmap_get_multiple (extended_neighbors,
                                              &recipient->hashPubKey,
                                              &find_least_cost_peer,
                                              &find_least_ctx);
  target = find_least_ctx.target;

  if (target == NULL)
  {
    /* target unknown to us, drop! */
    return GNUNET_SYSERR;
  }
  recipient_id = target->referrer_id;

  source =
      GNUNET_CONTAINER_multihashmap_get (extended_neighbors,
                                         &sender->hashPubKey);
  if (source == NULL)
  {
    if (0 !=
        (memcmp (&my_identity, sender, sizeof (struct GNUNET_PeerIdentity))))
    {
      /* sender unknown to us, drop! */
      return GNUNET_SYSERR;
    }
    sender_id = 0;              /* 0 == us */
  }
  else
  {
    /* find out the number that we use when we gossip about
     * the sender */
    sender_id = source->our_id;
  }

#if DEBUG_DV_PEER_NUMBERS
  GNUNET_CRYPTO_hash_to_enc (&source->identity.hashPubKey, &encPeerFrom);
  GNUNET_CRYPTO_hash_to_enc (&target->referrer->identity.hashPubKey,
                             &encPeerVia);
  encPeerFrom.encoding[4] = '\0';
  encPeerVia.encoding[4] = '\0';
#endif
  if ((sender_id != 0) &&
      (0 ==
       memcmp (&source->identity, &target->referrer->identity,
               sizeof (struct GNUNET_PeerIdentity))))
  {
    return 0;
  }

  cost = target->cost;
  pending_message = GNUNET_malloc (sizeof (struct PendingMessage) + msg_size);
  pending_message->msg = (struct GNUNET_MessageHeader *) &pending_message[1];
  pending_message->send_result = NULL;
  pending_message->importance = importance;
  pending_message->timeout = timeout;
  memcpy (&pending_message->recipient, &target->referrer->identity,
          sizeof (struct GNUNET_PeerIdentity));
  pending_message->msg_size = msg_size;
  toSend = (p2p_dv_MESSAGE_Data *) pending_message->msg;
  toSend->header.size = htons (msg_size);
  toSend->header.type = htons (GNUNET_MESSAGE_TYPE_DV_DATA);
  toSend->sender = htonl (sender_id);
  toSend->recipient = htonl (recipient_id);
#if DEBUG_DV_MESSAGES
  toSend->uid = htonl (uid);
#else
  toSend->uid = htonl (0);
#endif

#if DEBUG_DV_PEER_NUMBERS
  GNUNET_CRYPTO_hash_to_enc (&target->identity.hashPubKey, &encPeerTo);
  encPeerTo.encoding[4] = '\0';
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Sending DATA message. Sender id %u, source %s, destination %s, via %s\n",
              GNUNET_i2s (&my_identity), sender_id, &encPeerFrom, &encPeerTo,
              &encPeerVia);
#endif
  memcpy (&toSend[1], message, message_size);
  if ((source != NULL) && (source->pkey == NULL))       /* Test our hypothesis about message failures! */
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "%s: Sending message, but anticipate recipient will not know sender!!!\n\n\n",
                my_short_id);
  }
  GNUNET_CONTAINER_DLL_insert_after (core_pending_head, core_pending_tail,
                                     core_pending_tail, pending_message);
#if DEBUG_DV
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Notifying core of send size %d to destination `%s'\n",
              "DV SEND MESSAGE", msg_size, GNUNET_i2s (recipient));
#endif

  GNUNET_SCHEDULER_add_now (try_core_send, NULL);
  return (int) cost;
}

#if USE_PEER_ID
struct CheckPeerContext
{
  /**
   * Peer we found
   */
  struct DistantNeighbor *peer;

  /**
   * Sender id to search for
   */
  unsigned int sender_id;
};

/**
 * Iterator over hash map entries.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
int
checkPeerID (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  struct CheckPeerContext *ctx = cls;
  struct DistantNeighbor *distant = value;

  if (memcmp (key, &ctx->sender_id, sizeof (unsigned int)) == 0)
  {
    ctx->peer = distant;
    return GNUNET_NO;
  }
  return GNUNET_YES;

}
#endif


/**
 * Handler for messages parsed out by the tokenizer from
 * DV DATA received for this peer.
 *
 * @param cls NULL
 * @param client the TokenizedMessageContext which contains message information
 * @param message the actual message
 */
int
tokenized_message_handler (void *cls, void *client,
                           const struct GNUNET_MessageHeader *message)
{
  struct TokenizedMessageContext *ctx = client;

  GNUNET_break_op (ntohs (message->type) != GNUNET_MESSAGE_TYPE_DV_GOSSIP);
  GNUNET_break_op (ntohs (message->type) != GNUNET_MESSAGE_TYPE_DV_DATA);
  if ((ntohs (message->type) != GNUNET_MESSAGE_TYPE_DV_GOSSIP) &&
      (ntohs (message->type) != GNUNET_MESSAGE_TYPE_DV_DATA))
  {
#if DEBUG_DV_MESSAGES
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s: Receives %s message for me, uid %u, size %d, type %d cost %u from %s!\n",
                my_short_id, "DV DATA", ctx->uid, ntohs (message->size),
                ntohs (message->type), ctx->distant->cost,
                GNUNET_i2s (&ctx->distant->identity));
#endif
    GNUNET_assert (memcmp
                   (ctx->peer, &ctx->distant->identity,
                    sizeof (struct GNUNET_PeerIdentity)) != 0);
    send_to_plugin (ctx->peer, message, ntohs (message->size),
                    &ctx->distant->identity, ctx->distant->cost);
  }
  return GNUNET_OK;
}

#if DELAY_FORWARDS
struct DelayedMessageContext
{
  struct GNUNET_PeerIdentity dest;
  struct GNUNET_PeerIdentity sender;
  struct GNUNET_MessageHeader *message;
  size_t message_size;
  uint32_t uid;
};

void
send_message_delayed (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct DelayedMessageContext *msg_ctx = cls;

  if (msg_ctx != NULL)
  {
    send_message (&msg_ctx->dest, &msg_ctx->sender, NULL, msg_ctx->message,
                  msg_ctx->message_size, default_dv_priority, msg_ctx->uid,
                  GNUNET_TIME_UNIT_FOREVER_REL);
    GNUNET_free (msg_ctx->message);
    GNUNET_free (msg_ctx);
  }
}
#endif

/**
 * Find latency information in 'atsi'.
 *
 * @param atsi performance data
 * @param atsi_count number of entries in atsi
 * @return connection latency
 */
static struct GNUNET_TIME_Relative
get_atsi_latency (const struct GNUNET_ATS_Information *atsi,
                  unsigned int atsi_count)
{
  unsigned int i;

  for (i = 0; i < atsi_count; i++)
    if (ntohl (atsi[i].type) == GNUNET_ATS_QUALITY_NET_DELAY)
      return GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS,
                                            ntohl (atsi->value));
  GNUNET_break (0);
  /* how can we not have latency data? */
  return GNUNET_TIME_UNIT_SECONDS;
}


#if DEBUG_DV
/**
 * Iterator over hash map entries.
 *
 * @param cls closure (NULL)
 * @param key current key code
 * @param value value in the hash map (DistantNeighbor)
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
int
print_neighbors (void *cls, const struct GNUNET_HashCode * key, void *abs_value)
{
  struct DistantNeighbor *distant_neighbor = abs_value;
  char my_shortname[5];
  char referrer_shortname[5];

  memcpy (&my_shortname, GNUNET_i2s (&my_identity), 4);
  my_shortname[4] = '\0';
  memcpy (&referrer_shortname,
          GNUNET_i2s (&distant_neighbor->referrer->identity), 4);
  referrer_shortname[4] = '\0';

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "`%s' %s: Peer `%s', distance %d, referrer `%s' pkey: %s\n",
              &my_shortname, "DV", GNUNET_i2s (&distant_neighbor->identity),
              distant_neighbor->cost, &referrer_shortname,
              distant_neighbor->pkey == NULL ? "no" : "yes");
  return GNUNET_YES;
}
#endif

/**
 *  Scheduled task which gossips about known direct peers to other connected
 *  peers.  Will run until called with reason shutdown.
 */
static void
neighbor_send_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct NeighborSendContext *send_context = cls;

#if DEBUG_DV_GOSSIP_SEND
  char *encPeerAbout;
  char *encPeerTo;
#endif
  struct DistantNeighbor *about;
  struct DirectNeighbor *to;
  struct FastGossipNeighborList *about_list;

  p2p_dv_MESSAGE_NeighborInfo *message;
  struct PendingMessage *pending_message;

  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
  {
#if DEBUG_DV_GOSSIP
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s: Called with reason shutdown, shutting down!\n",
                GNUNET_i2s (&my_identity));
#endif
    return;
  }

  if (send_context->fast_gossip_list_head != NULL)
  {
    about_list = send_context->fast_gossip_list_head;
    about = about_list->about;
    GNUNET_CONTAINER_DLL_remove (send_context->fast_gossip_list_head,
                                 send_context->fast_gossip_list_tail,
                                 about_list);
    GNUNET_free (about_list);
  }
  else
  {
    /* FIXME: this may become a problem, because the heap walk has only one internal "walker".  This means
     * that if two neighbor_send_tasks are operating in lockstep (which is quite possible, given default
     * values for all connected peers) there may be a serious bias as to which peers get gossiped about!
     * Probably the *best* way to fix would be to have an opaque pointer to the walk position passed as
     * part of the walk_get_next call.  Then the heap would have to keep a list of walks, or reset the walk
     * whenever a modification has been detected.  Yuck either way.  Perhaps we could iterate over the heap
     * once to get a list of peers to gossip about and gossip them over time... But then if one goes away
     * in the mean time that becomes nasty.  For now we'll just assume that the walking is done
     * asynchronously enough to avoid major problems (-;
     *
     * NOTE: probably fixed once we decided send rate based on allowed bandwidth.
     */
    about = GNUNET_CONTAINER_heap_walk_get_next (neighbor_min_heap);
  }
  to = send_context->toNeighbor;

  if ((about != NULL) && (to != about->referrer /* split horizon */ ) &&
#if SUPPORT_HIDING
      (about->hidden == GNUNET_NO) &&
#endif
      (to != NULL) &&
      (0 !=
       memcmp (&about->identity, &to->identity,
               sizeof (struct GNUNET_PeerIdentity))) && (about->pkey != NULL))
  {
#if DEBUG_DV_GOSSIP_SEND
    encPeerAbout = GNUNET_strdup (GNUNET_i2s (&about->identity));
    encPeerTo = GNUNET_strdup (GNUNET_i2s (&to->identity));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s: Sending info about peer %s id %u to directly connected peer %s\n",
                GNUNET_i2s (&my_identity), encPeerAbout, about->our_id,
                encPeerTo);
    GNUNET_free (encPeerAbout);
    GNUNET_free (encPeerTo);
#endif
    about->last_gossip = GNUNET_TIME_absolute_get ();
    pending_message =
        GNUNET_malloc (sizeof (struct PendingMessage) +
                       sizeof (p2p_dv_MESSAGE_NeighborInfo));
    pending_message->msg = (struct GNUNET_MessageHeader *) &pending_message[1];
    pending_message->importance = default_dv_priority;
    pending_message->timeout = GNUNET_TIME_UNIT_FOREVER_REL;
    memcpy (&pending_message->recipient, &to->identity,
            sizeof (struct GNUNET_PeerIdentity));
    pending_message->msg_size = sizeof (p2p_dv_MESSAGE_NeighborInfo);
    message = (p2p_dv_MESSAGE_NeighborInfo *) pending_message->msg;
    message->header.size = htons (sizeof (p2p_dv_MESSAGE_NeighborInfo));
    message->header.type = htons (GNUNET_MESSAGE_TYPE_DV_GOSSIP);
    message->cost = htonl (about->cost);
    message->neighbor_id = htonl (about->our_id);

    memcpy (&message->pkey, about->pkey,
            sizeof (struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded));
    memcpy (&message->neighbor, &about->identity,
            sizeof (struct GNUNET_PeerIdentity));

    GNUNET_CONTAINER_DLL_insert_after (core_pending_head, core_pending_tail,
                                       core_pending_tail, pending_message);

    GNUNET_SCHEDULER_add_now (try_core_send, NULL);
    /*if (core_transmit_handle == NULL)
     * core_transmit_handle = GNUNET_CORE_notify_transmit_ready(coreAPI, GNUNET_YES,  default_dv_priority, GNUNET_TIME_UNIT_FOREVER_REL, &to->identity, sizeof(p2p_dv_MESSAGE_NeighborInfo), &core_transmit_notify, NULL); */

  }

  if (send_context->fast_gossip_list_head != NULL)      /* If there are other peers in the fast list, schedule right away */
  {
#if DEBUG_DV_PEER_NUMBERS
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "DV SERVICE: still in fast send mode\n");
#endif
    send_context->task =
        GNUNET_SCHEDULER_add_now (&neighbor_send_task, send_context);
  }
  else
  {
#if DEBUG_DV_PEER_NUMBERS
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "DV SERVICE: entering slow send mode\n");
#endif
    send_context->task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_DV_DEFAULT_SEND_INTERVAL,
                                      &neighbor_send_task, send_context);
  }

  return;
}



#if UNSIMPLER
/**
 * Iterate over hash map entries for a distant neighbor,
 * if direct neighbor matches context call send message
 *
 * @param cls closure, a DV_SendContext
 * @param key current key code
 * @param value value in the hash map
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
int
send_iterator (void *cls, const struct GNUNET_HashCode * key, void *abs_value)
{
  struct DV_SendContext *send_context = cls;
  struct DistantNeighbor *distant_neighbor = abs_value;

  if (memcmp (distant_neighbor->referrer, send_context->direct_peer, sizeof (struct GNUNET_PeerIdentity)) == 0) /* They match, send and free */
  {
    send_message_via (&my_identity, distant_neighbor, send_context);
    return GNUNET_NO;
  }
  return GNUNET_YES;
}
#endif


/** Forward declarations **/
static int
handle_dv_gossip_message (void *cls, const struct GNUNET_PeerIdentity *peer,
                          const struct GNUNET_MessageHeader *message,
                          const struct GNUNET_ATS_Information *atsi,
                          unsigned int atsi_count);

static int
handle_dv_disconnect_message (void *cls, const struct GNUNET_PeerIdentity *peer,
                              const struct GNUNET_MessageHeader *message,
                              const struct GNUNET_ATS_Information *atsi,
                              unsigned int atsi_count);
/** End forward declarations **/


/**
 * Free a DistantNeighbor node, including removing it
 * from the referer's list.
 */
static void
distant_neighbor_free (struct DistantNeighbor *referee)
{
  struct DirectNeighbor *referrer;

  referrer = referee->referrer;
  if (referrer != NULL)
  {
    GNUNET_CONTAINER_DLL_remove (referrer->referee_head, referrer->referee_tail,
                                 referee);
  }
  GNUNET_CONTAINER_heap_remove_node (referee->max_loc);
  GNUNET_CONTAINER_heap_remove_node (referee->min_loc);
  GNUNET_CONTAINER_multihashmap_remove_all (extended_neighbors,
                                            &referee->identity.hashPubKey);
  GNUNET_free_non_null (referee->pkey);
  GNUNET_free (referee);
}

/**
 * Free a DirectNeighbor node, including removing it
 * from the referer's list.
 */
static void
direct_neighbor_free (struct DirectNeighbor *direct)
{
  struct NeighborSendContext *send_context;
  struct FastGossipNeighborList *about_list;
  struct FastGossipNeighborList *prev_about;

  send_context = direct->send_context;

  if (send_context->task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (send_context->task);

  about_list = send_context->fast_gossip_list_head;
  while (about_list != NULL)
  {
    GNUNET_CONTAINER_DLL_remove (send_context->fast_gossip_list_head,
                                 send_context->fast_gossip_list_tail,
                                 about_list);
    prev_about = about_list;
    about_list = about_list->next;
    GNUNET_free (prev_about);
  }
  GNUNET_free (send_context);
  GNUNET_free (direct);
}

/**
 * Multihashmap iterator for sending out disconnect messages
 * for a peer.
 *
 * @param cls the peer that was disconnected
 * @param key key value stored under
 * @param value the direct neighbor to send disconnect to
 *
 * @return GNUNET_YES to continue iteration, GNUNET_NO to stop
 */
static int
schedule_disconnect_messages (void *cls, const struct GNUNET_HashCode * key,
                              void *value)
{
  struct DisconnectContext *disconnect_context = cls;
  struct DirectNeighbor *disconnected = disconnect_context->direct;
  struct DirectNeighbor *notify = value;
  struct PendingMessage *pending_message;
  p2p_dv_MESSAGE_Disconnect *disconnect_message;

  if (memcmp
      (&notify->identity, &disconnected->identity,
       sizeof (struct GNUNET_PeerIdentity)) == 0)
    return GNUNET_YES;          /* Don't send disconnect message to peer that disconnected! */

  pending_message =
      GNUNET_malloc (sizeof (struct PendingMessage) +
                     sizeof (p2p_dv_MESSAGE_Disconnect));
  pending_message->msg = (struct GNUNET_MessageHeader *) &pending_message[1];
  pending_message->importance = default_dv_priority;
  pending_message->timeout = GNUNET_TIME_UNIT_FOREVER_REL;
  memcpy (&pending_message->recipient, &notify->identity,
          sizeof (struct GNUNET_PeerIdentity));
  pending_message->msg_size = sizeof (p2p_dv_MESSAGE_Disconnect);
  disconnect_message = (p2p_dv_MESSAGE_Disconnect *) pending_message->msg;
  disconnect_message->header.size = htons (sizeof (p2p_dv_MESSAGE_Disconnect));
  disconnect_message->header.type = htons (GNUNET_MESSAGE_TYPE_DV_DISCONNECT);
  disconnect_message->peer_id = htonl (disconnect_context->distant->our_id);

  GNUNET_CONTAINER_DLL_insert_after (core_pending_head, core_pending_tail,
                                     core_pending_tail, pending_message);

  GNUNET_SCHEDULER_add_now (try_core_send, NULL);
  /*if (core_transmit_handle == NULL)
   * core_transmit_handle = GNUNET_CORE_notify_transmit_ready(coreAPI, GNUNET_YES, default_dv_priority, GNUNET_TIME_UNIT_FOREVER_REL, &notify->identity, sizeof(p2p_dv_MESSAGE_Disconnect), &core_transmit_notify, NULL); */

  return GNUNET_YES;
}


#if PKEY_NO_NEIGHBOR_ON_ADD
/**
 * Iterator over hash map entries.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
static int
add_pkey_to_extended (void *cls, const struct GNUNET_HashCode * key, void *abs_value)
{
  struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded *pkey = cls;
  struct DistantNeighbor *distant_neighbor = abs_value;

  if (distant_neighbor->pkey == NULL)
  {
    distant_neighbor->pkey =
        GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded));
    memcpy (distant_neighbor->pkey, pkey,
            sizeof (struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded));
  }

  return GNUNET_YES;
}
#endif

/**
 * Iterator over hash map entries.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
static int
update_matching_neighbors (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  struct NeighborUpdateInfo *update_info = cls;
  struct DistantNeighbor *distant_neighbor = value;

  if (update_info->referrer == distant_neighbor->referrer)      /* Direct neighbor matches, update it's info and return GNUNET_NO */
  {
    /* same referrer, cost change! */
    GNUNET_CONTAINER_heap_update_cost (neighbor_max_heap,
                                       update_info->neighbor->max_loc,
                                       update_info->cost);
    GNUNET_CONTAINER_heap_update_cost (neighbor_min_heap,
                                       update_info->neighbor->min_loc,
                                       update_info->cost);
    update_info->neighbor->last_activity = update_info->now;
    update_info->neighbor->cost = update_info->cost;
    update_info->neighbor->referrer_id = update_info->referrer_peer_id;
    return GNUNET_NO;
  }

  return GNUNET_YES;
}


/**
 * Iterate over all current direct peers, add DISTANT newly connected
 * peer to the fast gossip list for that peer so we get DV routing
 * information out as fast as possible!
 *
 * @param cls the newly connected neighbor we will gossip about
 * @param key the hashcode of the peer
 * @param value the direct neighbor we should gossip to
 *
 * @return GNUNET_YES to continue iteration, GNUNET_NO otherwise
 */
static int
add_distant_all_direct_neighbors (void *cls, const struct GNUNET_HashCode * key,
                                  void *value)
{
  struct DirectNeighbor *direct = (struct DirectNeighbor *) value;
  struct DistantNeighbor *distant = (struct DistantNeighbor *) cls;
  struct NeighborSendContext *send_context = direct->send_context;
  struct FastGossipNeighborList *gossip_entry;

#if DEBUG_DV
  char *encPeerAbout;
  char *encPeerTo;
#endif

  if (distant == NULL)
  {
    return GNUNET_YES;
  }

  if (memcmp
      (&direct->identity, &distant->identity,
       sizeof (struct GNUNET_PeerIdentity)) == 0)
  {
    return GNUNET_YES;          /* Don't gossip to a peer about itself! */
  }

#if SUPPORT_HIDING
  if (distant->hidden == GNUNET_YES)
    return GNUNET_YES;          /* This peer should not be gossipped about (hidden) */
#endif
  gossip_entry = GNUNET_malloc (sizeof (struct FastGossipNeighborList));
  gossip_entry->about = distant;

  GNUNET_CONTAINER_DLL_insert_after (send_context->fast_gossip_list_head,
                                     send_context->fast_gossip_list_tail,
                                     send_context->fast_gossip_list_tail,
                                     gossip_entry);
#if DEBUG_DV
  encPeerAbout = GNUNET_strdup (GNUNET_i2s (&distant->identity));
  encPeerTo = GNUNET_strdup (GNUNET_i2s (&direct->identity));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Fast send info about peer %s id %u for directly connected peer %s\n",
              GNUNET_i2s (&my_identity), encPeerAbout, distant->our_id,
              encPeerTo);
  GNUNET_free (encPeerAbout);
  GNUNET_free (encPeerTo);
#endif
  /*if (send_context->task != GNUNET_SCHEDULER_NO_TASK)
   * GNUNET_SCHEDULER_cancel(send_context->task); */

  send_context->task =
      GNUNET_SCHEDULER_add_now (&neighbor_send_task, send_context);
  return GNUNET_YES;
}

/**
 * Callback for hello address creation.
 *
 * @param cls closure, a struct HelloContext
 * @param max maximum number of bytes that can be written to buf
 * @param buf where to write the address information
 *
 * @return number of bytes written, 0 to signal the
 *         end of the iteration.
 */
static size_t
generate_hello_address (void *cls, size_t max, void *buf)
{
  struct HelloContext *hello_context = cls;
  struct GNUNET_HELLO_Address hello_address;
  char *addr_buffer;
  size_t offset;
  size_t size;
  size_t ret;

  if (hello_context->addresses_to_add == 0)
    return 0;

  /* Hello "address" will be concatenation of distant peer and direct peer identities */
  size = 2 * sizeof (struct GNUNET_PeerIdentity);
  GNUNET_assert (max >= size);

  addr_buffer = GNUNET_malloc (size);
  offset = 0;
  /* Copy the distant peer identity to buffer */
  memcpy (addr_buffer, &hello_context->distant_peer,
          sizeof (struct GNUNET_PeerIdentity));
  offset += sizeof (struct GNUNET_PeerIdentity);
  /* Copy the direct peer identity to buffer */
  memcpy (&addr_buffer[offset], hello_context->direct_peer,
          sizeof (struct GNUNET_PeerIdentity));
  memset (&hello_address.peer, 0, sizeof (struct GNUNET_PeerIdentity));
  hello_address.address = addr_buffer;
  hello_address.transport_name = "dv";
  hello_address.address_length = size;
  ret =
      GNUNET_HELLO_add_address (&hello_address,
                                GNUNET_TIME_relative_to_absolute
                                (GNUNET_TIME_UNIT_HOURS), buf, max);

  hello_context->addresses_to_add--;

  GNUNET_free (addr_buffer);
  return ret;
}


/**
 * Handles when a peer is either added due to being newly connected
 * or having been gossiped about, also called when the cost for a neighbor
 * needs to be updated.
 *
 * @param peer identity of the peer whose info is being added/updated
 * @param pkey public key of the peer whose info is being added/updated
 * @param referrer_peer_id id to use when sending to 'peer'
 * @param referrer if this is a gossiped peer, who did we hear it from?
 * @param cost the cost of communicating with this peer via 'referrer'
 *
 * @return the added neighbor, the updated neighbor or NULL (neighbor
 *         not added)
 */
static struct DistantNeighbor *
addUpdateNeighbor (const struct GNUNET_PeerIdentity *peer,
                   struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded *pkey,
                   unsigned int referrer_peer_id,
                   struct DirectNeighbor *referrer, unsigned int cost)
{
  struct DistantNeighbor *neighbor;
  struct DistantNeighbor *max;
  struct GNUNET_TIME_Absolute now;
  struct NeighborUpdateInfo *neighbor_update;
  struct HelloContext *hello_context;
  struct GNUNET_HELLO_Message *hello_msg;
  unsigned int our_id;
  char *addr1;
  char *addr2;
  int i;

#if DEBUG_DV_PEER_NUMBERS
  char *encAbout;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%s Received sender id (%u)!\n",
              "DV SERVICE", referrer_peer_id);
#endif

  now = GNUNET_TIME_absolute_get ();
  neighbor =
      GNUNET_CONTAINER_multihashmap_get (extended_neighbors, &peer->hashPubKey);
  neighbor_update = GNUNET_malloc (sizeof (struct NeighborUpdateInfo));
  neighbor_update->neighbor = neighbor;
  neighbor_update->cost = cost;
  neighbor_update->now = now;
  neighbor_update->referrer = referrer;
  neighbor_update->referrer_peer_id = referrer_peer_id;

  if (neighbor != NULL)
  {
#if USE_PEER_ID
    memcpy (&our_id, &neighbor->identity, sizeof (unsigned int));
#else
    our_id = neighbor->our_id;
#endif
  }
  else
  {
#if USE_PEER_ID
    memcpy (&our_id, peer, sizeof (unsigned int));
#else
    our_id =
        GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_STRONG,
                                  RAND_MAX - 1) + 1;
#endif
  }

  /* Either we do not know this peer, or we already do but via a different immediate peer */
  if ((neighbor == NULL) ||
      (GNUNET_CONTAINER_multihashmap_get_multiple
       (extended_neighbors, &peer->hashPubKey, &update_matching_neighbors,
        neighbor_update) != GNUNET_SYSERR))
  {
#if AT_MOST_ONE
    if ((neighbor != NULL) && (cost < neighbor->cost))  /* New cost is less than old, remove old */
    {
      distant_neighbor_free (neighbor);
    }
    else if (neighbor != NULL)  /* Only allow one DV connection to each peer */
    {
      return NULL;
    }
#endif
    /* new neighbor! */
    if (cost > fisheye_depth)
    {
      /* too costly */
      GNUNET_free (neighbor_update);
      return NULL;
    }

#if DEBUG_DV_PEER_NUMBERS
    encAbout = GNUNET_strdup (GNUNET_i2s (peer));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s: %s Chose NEW id (%u) for peer %s!\n",
                GNUNET_i2s (&my_identity), "DV SERVICE", our_id, encAbout);
    GNUNET_free (encAbout);
#endif

    if (max_table_size <=
        GNUNET_CONTAINER_multihashmap_size (extended_neighbors))
    {
      /* remove most expensive entry */
      max = GNUNET_CONTAINER_heap_peek (neighbor_max_heap);
      GNUNET_assert (max != NULL);
      if (cost > max->cost)
      {
        /* new entry most expensive, don't create */
        GNUNET_free (neighbor_update);
        return NULL;
      }
      if (max->cost > 1)
      {
        /* only free if this is not a direct connection;
         * we could theoretically have more direct
         * connections than DV entries allowed total! */
        distant_neighbor_free (max);
      }
    }

    neighbor = GNUNET_malloc (sizeof (struct DistantNeighbor));
    GNUNET_CONTAINER_DLL_insert (referrer->referee_head, referrer->referee_tail,
                                 neighbor);
    neighbor->max_loc =
        GNUNET_CONTAINER_heap_insert (neighbor_max_heap, neighbor, cost);
    neighbor->min_loc =
        GNUNET_CONTAINER_heap_insert (neighbor_min_heap, neighbor, cost);
    neighbor->referrer = referrer;
    memcpy (&neighbor->identity, peer, sizeof (struct GNUNET_PeerIdentity));
    if (pkey != NULL)           /* pkey will be null on direct neighbor addition */
    {
      neighbor->pkey =
          GNUNET_malloc (sizeof
                         (struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded));
      memcpy (neighbor->pkey, pkey,
              sizeof (struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded));
    }
    else
      neighbor->pkey = pkey;

    neighbor->last_activity = now;
    neighbor->cost = cost;
    neighbor->referrer_id = referrer_peer_id;
    neighbor->our_id = our_id;
    neighbor->hidden =
        (cost ==
         DIRECT_NEIGHBOR_COST)
        ? (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 4) ==
           0) : GNUNET_NO;

    GNUNET_CONTAINER_multihashmap_put (extended_neighbors, &peer->hashPubKey,
                                       neighbor,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
    if (referrer_peer_id != 0)
    {
      for (i = 0; i < MAX_OUTSTANDING_MESSAGES; i++)
      {
        if (referrer->pending_messages[i].sender_id == referrer_peer_id)        /* We have a queued message from just learned about peer! */
        {
#if DEBUG_DV_MESSAGES
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "%s: learned about peer %llu from which we have a previous unknown message, processing!\n",
                      my_short_id, referrer_peer_id);
#endif
          struct GNUNET_ATS_Information atsi[2];

          atsi[0].type = htonl (GNUNET_ATS_QUALITY_NET_DISTANCE);
          atsi[0].value = htonl (referrer->pending_messages[i].distance);
          atsi[1].type = htonl (GNUNET_ATS_QUALITY_NET_DELAY);
          atsi[1].value =
              htonl ((uint32_t) referrer->pending_messages[i].
                     latency.rel_value);
          handle_dv_data_message (NULL, &referrer->pending_messages[i].sender,
                                  referrer->pending_messages[i].message, atsi,
                                  2);
          GNUNET_free (referrer->pending_messages[i].message);
          referrer->pending_messages[i].sender_id = 0;
        }
      }
    }
    if ((cost != DIRECT_NEIGHBOR_COST) && (neighbor->pkey != NULL))
    {
      /* Added neighbor, now send HELLO to transport */
      hello_context = GNUNET_malloc (sizeof (struct HelloContext));
      hello_context->direct_peer = &referrer->identity;
      memcpy (&hello_context->distant_peer, peer,
              sizeof (struct GNUNET_PeerIdentity));
      hello_context->addresses_to_add = 1;
      hello_msg =
          GNUNET_HELLO_create (pkey, &generate_hello_address, hello_context);
      GNUNET_assert (memcmp
                     (hello_context->direct_peer, &hello_context->distant_peer,
                      sizeof (struct GNUNET_PeerIdentity)) != 0);
      addr1 = GNUNET_strdup (GNUNET_i2s (hello_context->direct_peer));
      addr2 = GNUNET_strdup (GNUNET_i2s (&hello_context->distant_peer));
#if DEBUG_DV
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "%s: GIVING HELLO size %d for %s via %s to TRANSPORT\n",
                  my_short_id, GNUNET_HELLO_size (hello_msg), addr2, addr1);
#endif
      GNUNET_free (addr1);
      GNUNET_free (addr2);
      send_to_plugin (hello_context->direct_peer,
                      GNUNET_HELLO_get_header (hello_msg),
                      GNUNET_HELLO_size (hello_msg),
                      &hello_context->distant_peer, cost);
      GNUNET_free (hello_context);
      GNUNET_free (hello_msg);
    }

  }
  else
  {
#if DEBUG_DV_GOSSIP
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s: Already know peer %s distance %d, referrer id %d!\n", "dv",
                GNUNET_i2s (peer), cost, referrer_peer_id);
#endif
  }
#if DEBUG_DV
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%s: Size of extended_neighbors is %d\n",
              "dv", GNUNET_CONTAINER_multihashmap_size (extended_neighbors));
#endif

  GNUNET_free (neighbor_update);
  return neighbor;
}


/**
 * Core handler for dv disconnect messages.  These will be used
 * by us to tell transport via the dv plugin that a peer can
 * no longer be contacted by us via a certain address.  We should
 * then propagate these messages on, given that the distance to
 * the peer indicates we would have gossiped about it to others.
 *
 * @param cls closure
 * @param peer peer which sent the message (immediate sender)
 * @param message the message
 * @param atsi performance data
 * @param atsi_count number of entries in atsi
 */
static int
handle_dv_disconnect_message (void *cls, const struct GNUNET_PeerIdentity *peer,
                              const struct GNUNET_MessageHeader *message,
                              const struct GNUNET_ATS_Information *atsi,
                              unsigned int atsi_count)
{
  struct DirectNeighbor *referrer;
  struct DistantNeighbor *distant;
  p2p_dv_MESSAGE_Disconnect *enc_message =
      (p2p_dv_MESSAGE_Disconnect *) message;

  if (ntohs (message->size) < sizeof (p2p_dv_MESSAGE_Disconnect))
  {
    return GNUNET_SYSERR;       /* invalid message */
  }

  referrer =
      GNUNET_CONTAINER_multihashmap_get (direct_neighbors, &peer->hashPubKey);
  if (referrer == NULL)
    return GNUNET_OK;

  distant = referrer->referee_head;
  while (distant != NULL)
  {
    if (distant->referrer_id == ntohl (enc_message->peer_id))
    {
      distant_neighbor_free (distant);
      distant = referrer->referee_head;
    }
    else
      distant = distant->next;
  }

  return GNUNET_OK;
}


/**
 * Iterate over all currently known peers, add them to the
 * fast gossip list for this peer so we get DV routing information
 * out as fast as possible!
 *
 * @param cls the direct neighbor we will gossip to
 * @param key the hashcode of the peer
 * @param value the distant neighbor we should add to the list
 *
 * @return GNUNET_YES to continue iteration, GNUNET_NO otherwise
 */
static int
add_all_extended_peers (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  struct NeighborSendContext *send_context = (struct NeighborSendContext *) cls;
  struct DistantNeighbor *distant = (struct DistantNeighbor *) value;
  struct FastGossipNeighborList *gossip_entry;

  if (memcmp
      (&send_context->toNeighbor->identity, &distant->identity,
       sizeof (struct GNUNET_PeerIdentity)) == 0)
    return GNUNET_YES;          /* Don't gossip to a peer about itself! */

#if SUPPORT_HIDING
  if (distant->hidden == GNUNET_YES)
    return GNUNET_YES;          /* This peer should not be gossipped about (hidden) */
#endif
  gossip_entry = GNUNET_malloc (sizeof (struct FastGossipNeighborList));
  gossip_entry->about = distant;

  GNUNET_CONTAINER_DLL_insert_after (send_context->fast_gossip_list_head,
                                     send_context->fast_gossip_list_tail,
                                     send_context->fast_gossip_list_tail,
                                     gossip_entry);

  return GNUNET_YES;
}


/**
 * Iterate over all current direct peers, add newly connected peer
 * to the fast gossip list for that peer so we get DV routing
 * information out as fast as possible!
 *
 * @param cls the newly connected neighbor we will gossip about
 * @param key the hashcode of the peer
 * @param value the direct neighbor we should gossip to
 *
 * @return GNUNET_YES to continue iteration, GNUNET_NO otherwise
 */
static int
add_all_direct_neighbors (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  struct DirectNeighbor *direct = (struct DirectNeighbor *) value;
  struct DirectNeighbor *to = (struct DirectNeighbor *) cls;
  struct DistantNeighbor *distant;
  struct NeighborSendContext *send_context = direct->send_context;
  struct FastGossipNeighborList *gossip_entry;
  char *direct_id;


  distant =
      GNUNET_CONTAINER_multihashmap_get (extended_neighbors,
                                         &to->identity.hashPubKey);
  if (distant == NULL)
  {
    return GNUNET_YES;
  }

  if (memcmp
      (&direct->identity, &to->identity,
       sizeof (struct GNUNET_PeerIdentity)) == 0)
  {
    return GNUNET_YES;          /* Don't gossip to a peer about itself! */
  }

#if SUPPORT_HIDING
  if (distant->hidden == GNUNET_YES)
    return GNUNET_YES;          /* This peer should not be gossipped about (hidden) */
#endif
  direct_id = GNUNET_strdup (GNUNET_i2s (&direct->identity));
#if DEBUG_DV_GOSSIP
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "%s: adding peer %s to fast send list for %s\n", my_short_id,
              GNUNET_i2s (&distant->identity), direct_id);
#endif
  GNUNET_free (direct_id);
  gossip_entry = GNUNET_malloc (sizeof (struct FastGossipNeighborList));
  gossip_entry->about = distant;

  GNUNET_CONTAINER_DLL_insert_after (send_context->fast_gossip_list_head,
                                     send_context->fast_gossip_list_tail,
                                     send_context->fast_gossip_list_tail,
                                     gossip_entry);
  if (send_context->task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (send_context->task);

  send_context->task =
      GNUNET_SCHEDULER_add_now (&neighbor_send_task, send_context);
  //tc.reason = GNUNET_SCHEDULER_REASON_TIMEOUT;
  //neighbor_send_task(send_context, &tc);
  return GNUNET_YES;
}


////////////////////////////////////////////////////////////////////////
#endif



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
  uint32_t distance;

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

  GNUNET_break (0); // FIXME...
}



/**
 * Core handler for dv data messages.  Whatever this message
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
cull_routing_neighbors (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  struct DirectNeighbor *neighbor = cls;
  struct RoutingNeighbor *rn = value;

  if (rn->route.next_hop != neighbor)
    return GNUNET_YES; /* not affected */

  /* FIXME: destroy routing neighbor! */
  GNUNET_break (0);  

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
  GNUNET_CONTAINER_multihashmap_iterate (routing_neighbors,
					 &cull_routing_neighbors,
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
 * Multihashmap iterator for freeing routing neighbors. Should never be called.
 *
 * @param cls NULL
 * @param key key value stored under
 * @param value the distant neighbor to be freed
 *
 * @return GNUNET_YES to continue iteration, GNUNET_NO to stop
 */
static int
free_routing_neighbors (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  struct RoutingNeighbor *router = value;

  GNUNET_break (0); 
  // FIXME: release resources
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
  GNUNET_CONTAINER_multihashmap_iterate (routing_neighbors,
                                         &free_routing_neighbors, NULL);
  GNUNET_CONTAINER_multihashmap_destroy (routing_neighbors);
  GNUNET_CONTAINER_multihashmap_iterate (all_routes,
                                         &free_route, NULL);
  GNUNET_CONTAINER_multihashmap_destroy (all_routes);
  GNUNET_CORE_disconnect (core_api);
  core_api = NULL;
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
      GNUNET_MESSAGE_TYPE_TRANSPORT_DV_SEND, 
      0},
    {NULL, NULL, 0, 0}
  };

  cfg = c;
  direct_neighbors = GNUNET_CONTAINER_multihashmap_create (128, GNUNET_NO);
  routing_neighbors = GNUNET_CONTAINER_multihashmap_create (128 * 128, GNUNET_NO);
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
  // FIXME: stats
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
