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
#include "gnunet-service-transport_ats-new.h"
#include "gnunet-service-transport_neighbours.h"
#include "gnunet-service-transport_validation.h"
#include "gnunet-service-transport.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_constants.h"
#include "transport.h"


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
   * Context for address suggestion.
   * NULL after we are connected.
   */
  struct GST_AtsSuggestionContext *asc;

  /**
   * Performance data for the peer.
   */
  struct GNUNET_TRANSPORT_ATS_Information *ats;

  /**
   * Public key for this peer.  Valid only if the respective flag is set below.
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded public_key;

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
   * How often has the other peer (recently) violated the inbound
   * traffic limit?  Incremented by 10 per violation, decremented by 1
   * per non-violation (for each time interval).
   */
  unsigned int quota_violation_count;

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

  /**
   * Do we currently consider this neighbour connected? (as far as
   * the connect/disconnect callbacks are concerned)?
   */
  int is_connected;

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
  struct MessageQueue *mq;
  struct GNUNET_TIME_Relative timeout;
  ssize_t ret;

  if (n->messages_head == NULL)
    {
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Transmission queue for `%4s' is empty\n",
		  GNUNET_i2s (&n->id));
#endif
      return;                     /* nothing to do */
    }
  mq = n->messages_head;
  GNUNET_CONTAINER_DLL_remove (n->messages_head,
			       n->messages_tail,
			       mq);
  ret = papi->send (papi->cls,
		    &n->pid,
		    mq->message_buf,
		    mq->message_buf_size,
		    mq->priority,
		    GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
		    n->session,
		    n->addr,
		    n->addrlen,
		    GNUNET_YES /*?*/,
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

  if (n->is_connected)
    {
      disconnect_notify_cb (callback_cls,
			    &n->id);
      n->is_connected = GNUNET_NO;
    }
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
  if (NULL != n->asc)
    {
      GST_ats_suggest_address_cancel (n->asc);
      n->asc = NULL;
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
 * Try to connect to the target peer using the given address
 * (if is valid).
 *
 * @param cls the 'struct NeighbourMapEntry' of the target
 * @param public_key public key for the peer, never NULL
 * @param target identity of the target peer
 * @param plugin_name name of the plugin
 * @param plugin_address binary address
 * @param plugin_address_len length of address
 * @param ats performance data for the address (as far as known)
 * @param ats_count number of performance records in 'ats'
 */
static void
try_connect_using_address (void *cls,
			   const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *public_key,
			   const struct GNUNET_PeerIdentity *target,
			   const char *plugin_name,
			   const void *plugin_address,
			   size_t plugin_address_len,
			   const struct GNUNET_TRANSPORT_ATS_Information *ats,
			   uint32_t ats_count)
{
  struct NeighbourMapEntry *n = cls;

  n->asc = NULL;
  if (n->public_key_valid == GNUNET_NO)
    {
      n->public_key = *public_key;
      n->public_key_valid = GNUNET_YES;
    }
  /* FIXME: do connect! */

}


/**
 * We've tried to connect but waited long enough and failed.  Clean up.
 *
 * @param cls the 'struct NeighbourMapEntry' of the neighbour that failed to connect
 * @param tc scheduler context
 */
static void
neighbour_connect_timeout_task (void *cls,
				const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct NeighbourMapEntry *n = cls;

  n->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multihashmap_remove (neighbours,
						       &n->id.hashPubKey,
						       n));
  GNUNET_assert (NULL == n->messages_head);
  GNUNET_assert (NULL == n->ats);
  GNUNET_free (n);
}


/**
 * Try to create a connection to the given target (eventually).
 *
 * @param target peer to try to connect to
 */
void
GST_neighbours_try_connect (const struct GNUNET_PeerIdentity *target)
{
  struct NeighbourMapEntry *n;

  GNUNET_assert (0 != memcmp (target,
			      &GST_my_identity,
			      sizeof (struct GNUNET_PeerIdentity)));
  n = lookup_neighbour (target);
  if ( (NULL != n) ||
       (GNUNET_TIME_absolute_get_remaining (n->peer_timeout).rel_value > 0) )
    return; /* already connected */
  if (n == NULL)
    {
      n = GNUNET_malloc (sizeof (struct NeighbourMapEntry));
      n->id = *target;
      GNUNET_BANDWIDTH_tracker_init (&n->in_tracker,
				     GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT,
				     MAX_BANDWIDTH_CARRY_S);
      n->timeout_task = GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
						      &neighbour_connect_timeout_task, n);
      GNUNET_assert (GNUNET_OK ==
		     GNUNET_CONTAINER_multihashmap_put (neighbours,
							&n->id.hashPubKey,
							n,
							GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
    }
  if (n->asc != NULL)
    return; /* already trying */
  n->asc = GST_ats_suggest_address (GST_ats,
				    target,
				    &try_connect_using_address,
				    n); 
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
 * @param msg_size number of bytes in msg
 * @param timeout when to fail with timeout
 * @param cont function to call when done
 * @param cont_cls closure for 'cont'
 */
void
GST_neighbours_send (const struct GNUNET_PeerIdentity *target,
		     const void *msg,
		     size_t msg_size,
		     struct GNUNET_TIME_Relative timeout,
		     GST_NeighbourSendContinuation cont,
		     void *cont_cls)
{
  struct NeighbourMapEntry *n;
  struct MessageQueue *mq;

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
  GNUNET_assert (msg_size >= sizeof (struct GNUNET_MessageHeader));
  GNUNET_STATISTICS_update (GST_stats,
			    gettext_noop ("# bytes in message queue for other peers"),
			    msg_size,
			    GNUNET_NO);
  mq = GNUNET_malloc (sizeof (struct MessageQueue) + msg_size);
  /* FIXME: this memcpy can be up to 7% of our total runtime! */
  memcpy (&mq[1], msg, msg_size);
  mq->message_buf = (const char*) &mq[1];
  mq->message_buf_size = msg_size;
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
 * Peer has been idle for too long. Disconnect.
 *
 * @param cls the 'struct NeighbourMapEntry' of the neighbour that went idle
 * @param tc scheduler context
 */
static void
neighbour_idle_timeout_task (void *cls,
			     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct NeighbourMapEntry *n = cls;

  n->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  disconnect_neighbour (n);
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
			       struct Session *session,
			       const struct GNUNET_TRANSPORT_ATS_Information *ats,
			       uint32_t ats_count)
{  
  struct NeighbourMapEntry *n;

  if (0 == memcmp (sender,
		   &GST_my_identity,
		   sizeof (struct GNUNET_PeerIdentity)))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    } 
  n = lookup_neighbour (sender);
  if ( (NULL != n) ||
       (n->is_connected == GNUNET_YES) )
    {
      /* already connected */
      if (session != NULL)
	{
	  // FIXME: ATS: switch session!?
	  // FIXME: merge/update ats?
	}
      return GNUNET_OK; 
    }
  if (n == NULL)
    {
      n = GNUNET_malloc (sizeof (struct NeighbourMapEntry));
      n->id = *sender;
      GNUNET_BANDWIDTH_tracker_init (&n->in_tracker,
				     GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT,
				     MAX_BANDWIDTH_CARRY_S);
      n->timeout_task = GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
						      &neighbour_connect_timeout_task, n);
      GNUNET_assert (GNUNET_OK ==
		     GNUNET_CONTAINER_multihashmap_put (neighbours,
							&n->id.hashPubKey,
							n,
							GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
      if (NULL == ats)
	{
	  GNUNET_array_grow (n->ats,
			     n->ats_count,
			     1);
	}
      else
	{
	  GNUNET_array_grow (n->ats,
			     n->ats_count,
			     ats_count);
	  memcpy (n->ats,
		  ats, 
		  sizeof (struct GNUNET_TRANSPORT_ATS_Information) * ats_count);
	}
    }
  if (session != NULL)
    {
      // FIXME: ATS: switch session!?
      // n->session = session;
    }
  n->peer_timeout = GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
  if (GNUNET_SCHEDULER_NO_TASK != n->timeout_task)
    GNUNET_SCHEDULER_cancel (n->timeout_task);
  n->timeout_task = GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
						  &neighbour_idle_timeout_task,
						  n);
  n->is_connected = GNUNET_YES;  
  connect_notify_cb (callback_cls,
		     sender,
		     n->ats,
		     n->ats_count);
  return GNUNET_OK;
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
  /* FIXME: send disconnect message to target... */
  disconnect_neighbour (n);
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
  struct NeighbourMapEntry *n;

  n = lookup_neighbour (sender);
  /* FIXME: should disconnects have a signature that we should check here? */
  disconnect_neighbour (n);
  return GNUNET_OK;
}


/* end of file gnunet-service-transport_neighbours.c */
