/*
     This file is part of GNUnet.
     (C) 2010,2011 Christian Grothoff (and other contributing authors)

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
 * @file transport/gnunet-service-transport_neighbours.c
 * @brief neighbour management
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-transport_neighbours.h"
#include "gnunet-service-transport.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_constants.h"


/**
 * Size of the neighbour hash map.
 */
#define NEIGHBOUR_TABLE_SIZE 256


// TODO:
// - have a way to access the currently 'connected' session
//   (for sending and to notice disconnect of it!)
// - have a way to access/update bandwidth/quota information per peer
//   (for CostReport/TrafficReport callbacks)


struct NeighbourMapEntry;

/**
 * For each neighbour we keep a list of messages
 * that we still want to transmit to the neighbour.
 */
struct MessageQueue
{

  /**
   * This is a doubly linked list.
   */
  struct MessageQueue *next;

  /**
   * This is a doubly linked list.
   */
  struct MessageQueue *prev;

  /**
   * The message(s) we want to transmit, GNUNET_MessageHeader(s)
   * stuck together in memory.  Allocated at the end of this struct.
   */
  const char *message_buf;

  /**
   * Size of the message buf
   */
  size_t message_buf_size;

  /**
   * Client responsible for queueing the message; used to check that a
   * client has no two messages pending for the same target and to
   * notify the client of a successful transmission; NULL if this is
   * an internal message.
   */
  struct TransportClient *client;

  /**
   * At what time should we fail?
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Internal message of the transport system that should not be
   * included in the usual SEND-SEND_OK transmission confirmation
   * traffic management scheme.  Typically, "internal_msg" will
   * be set whenever "client" is NULL (but it is not strictly
   * required).
   */
  int internal_msg;

  /**
   * How important is the message?
   */
  unsigned int priority;

};


/**
 * Entry in neighbours. 
 */
struct NeighbourMapEntry
{

  /**
   * Head of list of messages we would like to send to this peer;
   * must contain at most one message per client.
   */
  struct MessageQueue *messages_head;

  /**
   * Tail of list of messages we would like to send to this peer; must
   * contain at most one message per client.
   */
  struct MessageQueue *messages_tail;

  /**
   * Context for peerinfo iteration.
   * NULL after we are done processing peerinfo's information.
   */
  struct GNUNET_PEERINFO_IteratorContext *piter;

  /**
   * Performance data for the peer.
   */
  struct GNUNET_TRANSPORT_ATS_Information *ats;

  /**
   * Public key for this peer.  Valid only if the respective flag is set below.
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded publicKey;

  /**
   * Identity of this neighbour.
   */
  struct GNUNET_PeerIdentity id;

  /**
   * ID of task scheduled to run when this peer is about to
   * time out (will free resources associated with the peer).
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * ID of task scheduled to run when we should retry transmitting
   * the head of the message queue.  Actually triggered when the
   * transmission is timing out (we trigger instantly when we have
   * a chance of success).
   */
  GNUNET_SCHEDULER_TaskIdentifier retry_task;

  /**
   * How long until we should consider this peer dead (if we don't
   * receive another message in the meantime)?
   */
  struct GNUNET_TIME_Absolute peer_timeout;

  /**
   * Tracker for inbound bandwidth.
   */
  struct GNUNET_BANDWIDTH_Tracker in_tracker;

  /**
   * The latency we have seen for this particular address for
   * this particular peer.  This latency may have been calculated
   * over multiple transports.  This value reflects how long it took
   * us to receive a response when SENDING via this particular
   * transport/neighbour/address combination!
   *
   * FIXME: we need to periodically send PINGs to update this
   * latency (at least more often than the current "huge" (11h?)
   * update interval).
   */
  struct GNUNET_TIME_Relative latency;

  /**
   * How often has the other peer (recently) violated the inbound
   * traffic limit?  Incremented by 10 per violation, decremented by 1
   * per non-violation (for each time interval).
   */
  unsigned int quota_violation_count;

  /**
   * DV distance to this peer (1 if no DV is used).
   */
  uint32_t distance;
  
  /**
   * Number of values in 'ats' array.
   */
  unsigned int ats_count;

  /**
   * Have we seen an PONG from this neighbour in the past (and
   * not had a disconnect since)?
   */
  int received_pong;

  /**
   * Do we have a valid public key for this neighbour?
   */
  int public_key_valid;

  /**
   * Are we already in the process of disconnecting this neighbour?
   */
  int in_disconnect;

};


/**
 * All known neighbours and their HELLOs.
 */
static struct GNUNET_CONTAINER_MultiHashMap *neighbours;

/**
 * Closure for connect_notify_cb and disconnect_notify_cb
 */
static void *callback_cls;

/**
 * Function to call when we connected to a neighbour.
 */
static GNUNET_TRANSPORT_NotifyConnect connect_notify_cb;

/**
 * Function to call when we disconnected from a neighbour.
 */
static GNUNET_TRANSPORT_NotifyDisconnect disconnect_notify_cb;


/**
 * Lookup a neighbour entry in the neighbours hash map.
 *
 * @param pid identity of the peer to look up
 * @return the entry, NULL if there is no existing record
 */
static struct NeighbourMapEntry *
lookup_neighbour (const struct GNUNET_PeerIdentity *pid)
{
  return GNUNET_CONTAINER_multihashmap_get (neighbours,
					    &pid->hashPubKey);
}


#if 0
/**
 * Check the ready list for the given neighbour and if a plugin is
 * ready for transmission (and if we have a message), do so!
 *
 * @param neighbour target peer for which to transmit
 */
static void
try_transmission_to_peer (struct NeighbourMapEntry *n)
{
  struct ReadyList *rl;
  struct MessageQueue *mq;
  struct GNUNET_TIME_Relative timeout;
  ssize_t ret;
  int force_address;

  if (n->messages_head == NULL)
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Transmission queue for `%4s' is empty\n",
		  GNUNET_i2s (&n->id));
#endif
      return;                     /* nothing to do */
    }
  rl = NULL;
  mq = n->messages_head;
  force_address = GNUNET_YES;
  if (mq->specific_address == NULL)
    {
      /* TODO: ADD ATS */
      mq->specific_address = get_preferred_ats_address(n);
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# transport selected peer address freely"),
				1,
				GNUNET_NO);
      force_address = GNUNET_NO;
    }
  if (mq->specific_address == NULL)
    {
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# transport failed to selected peer address"),
				1,
				GNUNET_NO);
      timeout = GNUNET_TIME_absolute_get_remaining (mq->timeout);
      if (timeout.rel_value == 0)
	{
#if DEBUG_TRANSPORT
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "No destination address available to transmit message of size %u to peer `%4s'\n",
		      mq->message_buf_size,
		      GNUNET_i2s (&mq->neighbour_id));
#endif
	  GNUNET_STATISTICS_update (stats,
				    gettext_noop ("# bytes in message queue for other peers"),
				    - (int64_t) mq->message_buf_size,
				    GNUNET_NO);
	  GNUNET_STATISTICS_update (stats,
				    gettext_noop ("# bytes discarded (no destination address available)"),
				    mq->message_buf_size,
				    GNUNET_NO);
	  if (mq->client != NULL)
	    transmit_send_ok (mq->client, n, &n->id, GNUNET_NO);
	  GNUNET_CONTAINER_DLL_remove (n->messages_head,
				       n->messages_tail,
				       mq);
	  GNUNET_free (mq);
	  return;               /* nobody ready */
	}
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# message delivery deferred (no address)"),
				1,
				GNUNET_NO);
      if (n->retry_task != GNUNET_SCHEDULER_NO_TASK)
	GNUNET_SCHEDULER_cancel (n->retry_task);
      n->retry_task = GNUNET_SCHEDULER_add_delayed (timeout,
						    &retry_transmission_task,
						    n);
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "No validated destination address available to transmit message of size %u to peer `%4s', will wait %llums to find an address.\n",
		  mq->message_buf_size,
		  GNUNET_i2s (&mq->neighbour_id),
		  timeout.rel_value);
#endif
      /* FIXME: might want to trigger peerinfo lookup here
	 (unless that's already pending...) */
      return;
    }
  GNUNET_CONTAINER_DLL_remove (n->messages_head,
			       n->messages_tail,
			       mq);
  if (mq->specific_address->connected == GNUNET_NO)
    mq->specific_address->connect_attempts++;
  rl = mq->specific_address->ready_list;
  mq->plugin = rl->plugin;
  if (!mq->internal_msg)
    mq->specific_address->in_transmit = GNUNET_YES;
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending message of size %u for `%4s' to `%s' via plugin `%s'\n",
              mq->message_buf_size,
              GNUNET_i2s (&n->id),
	      (mq->specific_address->addr != NULL)
	      ? a2s (mq->plugin->short_name,
		     mq->specific_address->addr,
		     mq->specific_address->addrlen)
	      : "<inbound>",
	      rl->plugin->short_name);
#endif
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# bytes in message queue for other peers"),
			    - (int64_t) mq->message_buf_size,
			    GNUNET_NO);
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# bytes pending with plugins"),
			    mq->message_buf_size,
			    GNUNET_NO);

  GNUNET_CONTAINER_DLL_insert (n->cont_head,
                               n->cont_tail,
                               mq);

  ret = rl->plugin->api->send (rl->plugin->api->cls,
			       &mq->neighbour_id,
			       mq->message_buf,
			       mq->message_buf_size,
			       mq->priority,
			       GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
			       mq->specific_address->session,
			       mq->specific_address->addr,
			       mq->specific_address->addrlen,
			       force_address,
			       &transmit_send_continuation, mq);
  if (ret == -1)
    {
      /* failure, but 'send' would not call continuation in this case,
	 so we need to do it here! */
      transmit_send_continuation (mq,
				  &mq->neighbour_id,
				  GNUNET_SYSERR);
    }
}


/**
 * Create a fresh entry in our neighbour list for the given peer.
 * Will try to transmit our current HELLO to the new neighbour.
 * Do not call this function directly, use 'setup_peer_check_blacklist.
 *
 * @param peer the peer for which we create the entry
 * @param do_hello should we schedule transmitting a HELLO
 * @return the new neighbour list entry
 */
static struct NeighbourMapEntry *
setup_new_neighbour (const struct GNUNET_PeerIdentity *peer,
		     int do_hello)
{
  struct NeighbourMapEntry *n;
  struct TransportPlugin *tp;
  struct ReadyList *rl;

  GNUNET_assert (0 != memcmp (peer,
			      &my_identity,
			      sizeof (struct GNUNET_PeerIdentity)));
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Setting up state for neighbour `%4s'\n",
	      GNUNET_i2s (peer));
#endif
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# active neighbours"),
			    1,
			    GNUNET_NO);
  n = GNUNET_malloc (sizeof (struct NeighbourMapEntry));
  n->id = *peer;
  n->peer_timeout =
    GNUNET_TIME_relative_to_absolute
    (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
  GNUNET_BANDWIDTH_tracker_init (&n->in_tracker,
				 GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT,
				 MAX_BANDWIDTH_CARRY_S);
  tp = plugins;
  while (tp != NULL)
    {
      if ((tp->api->send != NULL) && (!is_blacklisted(peer, tp)))
        {
          rl = GNUNET_malloc (sizeof (struct ReadyList));
	  rl->neighbour = n;
          rl->next = n->plugins;
          n->plugins = rl;
          rl->plugin = tp;
          rl->addresses = NULL;
        }
      tp = tp->next;
    }
  n->latency = GNUNET_TIME_UNIT_FOREVER_REL;
  n->distance = -1;
  n->timeout_task = GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                                                  &neighbour_timeout_task, n);
  GNUNET_CONTAINER_multihashmap_put (neighbours,
				     &n->id.hashPubKey,
				     n,
				     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  if (do_hello)
    {
      GNUNET_STATISTICS_update (stats,
                                gettext_noop ("# peerinfo new neighbor iterate requests"),
                                1,
                                GNUNET_NO);
      GNUNET_STATISTICS_update (stats,
                                gettext_noop ("# outstanding peerinfo iterate requests"),
                                1,
                                GNUNET_NO);
      n->piter = GNUNET_PEERINFO_iterate (peerinfo, peer,
					  GNUNET_TIME_UNIT_FOREVER_REL,
					  &add_hello_for_peer, n);

      GNUNET_STATISTICS_update (stats,
                                gettext_noop ("# HELLO's sent to new neighbors"),
                                1,
                                GNUNET_NO);
      if (NULL != our_hello)
	transmit_to_peer (NULL, NULL, 0,
			  HELLO_ADDRESS_EXPIRATION,
			  (const char *) our_hello, GNUNET_HELLO_size(our_hello),
			  GNUNET_NO, n);
    }
  return n;
}
#endif


/**
 * Initialize the neighbours subsystem.
 *
 * @param cls closure for callbacks
 * @param connect_cb function to call if we connect to a peer
 * @param disconnect_cb function to call if we disconnect from a peer
 */
void 
GST_neighbours_start (void *cls,
		      GNUNET_TRANSPORT_NotifyConnect connect_cb,
		      GNUNET_TRANSPORT_NotifyDisconnect disconnect_cb)
{
  callback_cls = cls;
  connect_notify_cb = connect_cb;
  disconnect_notify_cb = disconnect_cb;
  neighbours = GNUNET_CONTAINER_multihashmap_create (NEIGHBOUR_TABLE_SIZE);
}


/**
 * Disconnect from the given neighbour, clean up the record.
 *
 * @param n neighbour to disconnect from
 */
static void
disconnect_neighbour (struct NeighbourMapEntry *n)
{
  struct MessageQueue *mq;

  disconnect_notify_cb (callback_cls,
			&n->id);
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multihashmap_remove (neighbours,
						       &n->id.hashPubKey,
						       n));
  while (NULL != (mq = n->messages_head))
    {
      GNUNET_CONTAINER_DLL_remove (n->messages_head,
				   n->messages_tail,
				   mq);
      GNUNET_free (mq);
    }
  if (NULL != n->piter)
    {
      GNUNET_PEERINFO_iterate_cancel (n->piter);
      n->piter = NULL;
    }
  GNUNET_array_grow (n->ats,
		     n->ats_count,
		     0);
  GNUNET_free (n);
}


/**
 * Disconnect from the given neighbour.
 *
 * @param cls unused
 * @param key hash of neighbour's public key (not used)
 * @param value the 'struct NeighbourMapEntry' of the neighbour
 */
static int
disconnect_all_neighbours (void *cls,
			   const GNUNET_HashCode *key,
			   void *value)
{
  struct NeighbourMapEntry *n = value;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Disconnecting peer `%4s', %s\n",
	      GNUNET_i2s(&n->id),
	      "SHUTDOWN_TASK");
#endif
  disconnect_neighbour (n);
  return GNUNET_OK;
}


/**
 * Cleanup the neighbours subsystem.
 */
void
GST_neighbours_stop ()
{
  GNUNET_CONTAINER_multihashmap_iterate (neighbours,
					 &disconnect_all_neighbours,
					 NULL);
  GNUNET_CONTAINER_multihashmap_destroy (neighbours);
  neighbours = NULL;
  callback_cls = NULL;
  connect_notify_cb = NULL;
  disconnect_notify_cb = NULL;
}


/**
 * Try to create a connection to the given target (eventually).
 *
 * @param target peer to try to connect to
 */
void
GST_neighbours_try_connect (const struct GNUNET_PeerIdentity *target)
{
}


/**
 * Test if we're connected to the given peer.
 * 
 * @param target peer to test
 * @return GNUNET_YES if we are connected, GNUNET_NO if not
 */
int
GST_neighbours_test_connected (const struct GNUNET_PeerIdentity *target)
{
  struct NeighbourMapEntry *n;

  n = lookup_neighbour (target);
  if ( (NULL == n) ||
       (GNUNET_TIME_absolute_get_remaining (n->peer_timeout).rel_value == 0) )
       return GNUNET_NO; /* not connected */
  return GNUNET_YES;
}


/**
 * Transmit a message to the given target using the active connection.
 *
 * @param target destination
 * @param msg message to send
 * @param timeout when to fail with timeout
 * @param cont function to call when done
 * @param cont_cls closure for 'cont'
 */
void
GST_neighbours_send (const struct GNUNET_PeerIdentity *target,
		     const struct GNUNET_MessageHeader *msg,
		     struct GNUNET_TIME_Relative timeout,
		     GST_NeighbourSendContinuation cont,
		     void *cont_cls)
{
  struct NeighbourMapEntry *n;
  struct MessageQueue *mq;
  uint16_t message_buf_size;

  n = lookup_neighbour (target);
  if ( (n == NULL) ||
       (GNUNET_TIME_absolute_get_remaining (n->peer_timeout).rel_value == 0) ) 
    {
      GNUNET_STATISTICS_update (GST_stats,
				gettext_noop ("# SET QUOTA messages ignored (no such peer)"),
				1,
				GNUNET_NO);
      if (NULL != cont)
	cont (cont_cls,
	      GNUNET_SYSERR);
      return;
    }
  message_buf_size = ntohs (msg->size);
  GNUNET_assert (message_buf_size >= sizeof (struct GNUNET_MessageHeader));
  GNUNET_STATISTICS_update (GST_stats,
			    gettext_noop ("# bytes in message queue for other peers"),
			    message_buf_size,
			    GNUNET_NO);
  mq = GNUNET_malloc (sizeof (struct MessageQueue) + message_buf_size);
  /* FIXME: this memcpy can be up to 7% of our total runtime! */
  memcpy (&mq[1], msg, message_buf_size);
  mq->message_buf = (const char*) &mq[1];
  mq->message_buf_size = message_buf_size;
  mq->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  GNUNET_CONTAINER_DLL_insert_tail (n->messages_head,
				    n->messages_tail,
				    mq);
  // try_transmission_to_peer (n);
}


/**
 * Change the incoming quota for the given peer.
 *
 * @param neighbour identity of peer to change qutoa for
 * @param quota new quota 
 */
void
GST_neighbours_set_incoming_quota (const struct GNUNET_PeerIdentity *neighbour,
				   struct GNUNET_BANDWIDTH_Value32NBO quota)
{
  struct NeighbourMapEntry *n;

  n = lookup_neighbour (neighbour);
  if (n == NULL)
    {
      GNUNET_STATISTICS_update (GST_stats,
				gettext_noop ("# SET QUOTA messages ignored (no such peer)"),
				1,
				GNUNET_NO);
      return;
    }
  GNUNET_BANDWIDTH_tracker_update_quota (&n->in_tracker,
					 quota);
  if (0 != ntohl (quota.value__))
    return;
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Disconnecting peer `%4s' due to `%s'\n",
	      GNUNET_i2s(&n->id),
	      "SET_QUOTA");
#endif
  GNUNET_STATISTICS_update (GST_stats,
			    gettext_noop ("# disconnects due to quota of 0"),
			    1,
			    GNUNET_NO);
  disconnect_neighbour (n);
}


/**
 * If we have an active connection to the given target, it must be shutdown.
 *
 * @param target peer to disconnect from
 */
void
GST_neighbours_force_disconnect (const struct GNUNET_PeerIdentity *target)
{
  struct NeighbourMapEntry *n;

  n = lookup_neighbour (target);
  disconnect_neighbour (n);
}


/**
 * Closure for the neighbours_iterate function.
 */
struct IteratorContext
{
  /**
   * Function to call on each connected neighbour.
   */
  GST_NeighbourIterator cb;

  /**
   * Closure for 'cb'.
   */
  void *cb_cls;
};


/**
 * Call the callback from the closure for each connected neighbour.
 *
 * @param cls the 'struct IteratorContext'
 * @param key the hash of the public key of the neighbour
 * @param value the 'struct NeighbourMapEntry'
 * @return GNUNET_OK (continue to iterate)
 */
static int
neighbours_iterate (void *cls,
		    const GNUNET_HashCode *key,
		    void *value)
{
  struct IteratorContext *ic = cls;
  struct NeighbourMapEntry *n = value;

  if (GNUNET_TIME_absolute_get_remaining (n->peer_timeout).rel_value == 0)
    return GNUNET_OK; /* not connected */
  GNUNET_assert (n->ats_count > 0);
  ic->cb (ic->cb_cls,
	  &n->id,
	  n->ats,
	  n->ats_count - 1);
  return GNUNET_OK;
}


/**
 * Iterate over all connected neighbours.
 *
 * @param cb function to call 
 * @param cb_cls closure for cb
 */
void
GST_neighbours_iterate (GST_NeighbourIterator cb,
			void *cb_cls)
{
  struct IteratorContext ic;

  ic.cb = cb;
  ic.cb_cls = cb_cls;
  GNUNET_CONTAINER_multihashmap_iterate (neighbours,
					 &neighbours_iterate,
					 &ic);
}


/**
 * We have received a PONG.  Update lifeness of the neighbour.
 *
 * @param sender peer sending the PONG
 * @param hdr the PONG message (presumably)
 * @param plugin_name name of transport that delivered the PONG
 * @param sender_address address of the other peer, NULL if other peer
 *                       connected to us
 * @param sender_address_len number of bytes in sender_address
 * @param ats performance data
 * @param ats_count number of entries in ats (excluding 0-termination)
 * @return GNUNET_OK if the message was well-formed, GNUNET_SYSERR if not
 */
int
GST_neighbours_handle_pong (const struct GNUNET_PeerIdentity *sender,
			    const struct GNUNET_MessageHeader *hdr,
			    const char *plugin_name,
			    const void *sender_address,
			    size_t sender_address_len,
			    const struct GNUNET_TRANSPORT_ATS_Information *ats,
			    uint32_t ats_count)
{
  return GNUNET_SYSERR;
}


/**
 * We have received a CONNECT.  Set the peer to connected.
 *
 * @param sender peer sending the PONG
 * @param hdr the PONG message (presumably)
 * @param plugin_name name of transport that delivered the PONG
 * @param sender_address address of the other peer, NULL if other peer
 *                       connected to us
 * @param sender_address_len number of bytes in sender_address
 * @param ats performance data
 * @param ats_count number of entries in ats (excluding 0-termination)
 * @return GNUNET_OK if the message was well-formed, GNUNET_SYSERR if not
 */
int
GST_neighbours_handle_connect (const struct GNUNET_PeerIdentity *sender,
			       const struct GNUNET_MessageHeader *hdr,
			       const char *plugin_name,
			       const void *sender_address,
			       size_t sender_address_len,
			       const struct GNUNET_TRANSPORT_ATS_Information *ats,
			       uint32_t ats_count)
{
  return GNUNET_SYSERR;
}


/**
 * We have received a DISCONNECT.  Set the peer to disconnected.
 *
 * @param sender peer sending the PONG
 * @param hdr the PONG message (presumably)
 * @param plugin_name name of transport that delivered the PONG
 * @param sender_address address of the other peer, NULL if other peer
 *                       connected to us
 * @param sender_address_len number of bytes in sender_address
 * @return GNUNET_OK if the message was well-formed, GNUNET_SYSERR if not
 */
int
GST_neighbours_handle_disconnect (const struct GNUNET_PeerIdentity *sender,
				  const struct GNUNET_MessageHeader *hdr,
				  const char *plugin_name,
				  const void *sender_address,
				  size_t sender_address_len)
{
  return GNUNET_SYSERR;
}


/* end of file gnunet-service-transport_neighbours.c */
