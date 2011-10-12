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
#include "gnunet_ats_service.h"
#include "gnunet-service-transport_neighbours.h"
#include "gnunet-service-transport_plugins.h"
#include "gnunet-service-transport_validation.h"
#include "gnunet-service-transport_clients.h"
#include "gnunet-service-transport.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_constants.h"
#include "transport.h"


/**
 * Size of the neighbour hash map.
 */
#define NEIGHBOUR_TABLE_SIZE 256

/**
 * How often must a peer violate bandwidth quotas before we start
 * to simply drop its messages?
 */
#define QUOTA_VIOLATION_DROP_THRESHOLD 10

/**
 * How often do we send KEEPALIVE messages to each of our neighbours?
 * (idle timeout is 5 minutes or 300 seconds, so with 90s interval we
 * send 3 keepalives in each interval, so 3 messages would need to be
 * lost in a row for a disconnect).
 */
#define KEEPALIVE_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 90)


/**
 * Entry in neighbours.
 */
struct NeighbourMapEntry;

/**
 * Message a peer sends to another to indicate its
 * preference for communicating via a particular
 * session (and the desire to establish a real
 * connection).
 */
struct SessionConnectMessage
{
  /**
   * Header of type 'GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_CONNECT'
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Absolute time at the sender.  Only the most recent connect
   * message implies which session is preferred by the sender.
   */
  struct GNUNET_TIME_AbsoluteNBO timestamp;

};


struct SessionDisconnectMessage
{
  /**
   * Header of type 'GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_DISCONNECT'
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Purpose of the signature.  Extends over the timestamp.
   * Purpose should be GNUNET_SIGNATURE_PURPOSE_TRANSPORT_DISCONNECT.
   */
  struct GNUNET_CRYPTO_RsaSignaturePurpose purpose;

  /**
   * Absolute time at the sender.  Only the most recent connect
   * message implies which session is preferred by the sender.
   */
  struct GNUNET_TIME_AbsoluteNBO timestamp;

  /**
   * Signature of the peer that sends us the disconnect.  Only
   * valid if the timestamp is AFTER the timestamp from the
   * corresponding 'CONNECT' message.
   */
  struct GNUNET_CRYPTO_RsaSignature signature;
};


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
   * Once this message is actively being transmitted, which
   * neighbour is it associated with?
   */
  struct NeighbourMapEntry *n;

  /**
   * Function to call once we're done.
   */
  GST_NeighbourSendContinuation cont;

  /**
   * Closure for 'cont'
   */
  void *cont_cls;

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
   * At what time should we fail?
   */
  struct GNUNET_TIME_Absolute timeout;

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
  struct GNUNET_ATS_SuggestionContext *asc;

  /**
   * Performance data for the peer.
   */
  struct GNUNET_TRANSPORT_ATS_Information *ats;

  /**
   * Are we currently trying to send a message? If so, which one?
   */
  struct MessageQueue *is_active;

  /**
   * Active session for communicating with the peer.
   */
  struct Session *session;

  /**
   * Name of the plugin we currently use.
   */
  char *plugin_name;

  /**
   * Address used for communicating with the peer, NULL for inbound connections.
   */
  void *addr;

  /**
   * Number of bytes in 'addr'.
   */
  size_t addrlen;

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
   * ID of task scheduled to send keepalives.
   */
  GNUNET_SCHEDULER_TaskIdentifier keepalive_task;

  /**
   * ID of task scheduled to run when we should try transmitting
   * the head of the message queue.
   */
  GNUNET_SCHEDULER_TaskIdentifier transmission_task;

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
 * counter for connected neighbours
 */
static int neighbours_connected;

/**
 * Lookup a neighbour entry in the neighbours hash map.
 *
 * @param pid identity of the peer to look up
 * @return the entry, NULL if there is no existing record
 */
static struct NeighbourMapEntry *
lookup_neighbour (const struct GNUNET_PeerIdentity *pid)
{
  return GNUNET_CONTAINER_multihashmap_get (neighbours, &pid->hashPubKey);
}


/**
 * Task invoked to start a transmission to another peer.
 *
 * @param cls the 'struct NeighbourMapEntry'
 * @param tc scheduler context
 */
static void
transmission_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * We're done with our transmission attempt, continue processing.
 *
 * @param cls the 'struct MessageQueue' of the message
 * @param receiver intended receiver
 * @param success whether it worked or not
 */
static void
transmit_send_continuation (void *cls,
                            const struct GNUNET_PeerIdentity *receiver,
                            int success)
{
  struct MessageQueue *mq;
  struct NeighbourMapEntry *n;

  mq = cls;
  n = mq->n;
  if (NULL != n)
  {
    GNUNET_assert (n->is_active == mq);
    n->is_active = NULL;
    GNUNET_assert (n->transmission_task == GNUNET_SCHEDULER_NO_TASK);
    n->transmission_task = GNUNET_SCHEDULER_add_now (&transmission_task, n);
  }
  if (NULL != mq->cont)
    mq->cont (mq->cont_cls, success);
  GNUNET_free (mq);
}


/**
 * Check the ready list for the given neighbour and if a plugin is
 * ready for transmission (and if we have a message), do so!
 *
 * @param n target peer for which to transmit
 */
static void
try_transmission_to_peer (struct NeighbourMapEntry *n)
{
  struct MessageQueue *mq;
  struct GNUNET_TIME_Relative timeout;
  ssize_t ret;
  struct GNUNET_TRANSPORT_PluginFunctions *papi;

  if (n->is_active != NULL)
    return;                     /* transmission already pending */
  if (n->transmission_task != GNUNET_SCHEDULER_NO_TASK)
    return;                     /* currently waiting for bandwidth */
  while (NULL != (mq = n->messages_head))
  {
    timeout = GNUNET_TIME_absolute_get_remaining (mq->timeout);
    if (timeout.rel_value > 0)
      break;
    GNUNET_CONTAINER_DLL_remove (n->messages_head, n->messages_tail, mq);
    n->is_active = mq;
    transmit_send_continuation (mq, &n->id, GNUNET_SYSERR);     /* timeout */
  }
  if (NULL == mq)
    return;                     /* no more messages */

  papi = GST_plugins_find (n->plugin_name);
  if (papi == NULL)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_CONTAINER_DLL_remove (n->messages_head, n->messages_tail, mq);
  n->is_active = mq;
  mq->n = n;

  if  (((n->session == NULL) && (n->addr == NULL) && (n->addrlen == 0)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No address peer for peer `%s'\n",
                GNUNET_i2s (&n->id));
    transmit_send_continuation (mq, &n->id, GNUNET_SYSERR);
    n->transmission_task = GNUNET_SCHEDULER_add_now (&transmission_task, n);
    return;
  }

  ret =
      papi->send (papi->cls, &n->id, mq->message_buf, mq->message_buf_size,
                  0 /* priority -- remove from plugin API? */ ,
                  timeout, n->session, n->addr, n->addrlen, GNUNET_YES,
                  &transmit_send_continuation, mq);
  if (ret == -1)
  {
    /* failure, but 'send' would not call continuation in this case,
     * so we need to do it here! */
    transmit_send_continuation (mq, &n->id, GNUNET_SYSERR);
    n->transmission_task = GNUNET_SCHEDULER_add_now (&transmission_task, n);
  }
}


/**
 * Task invoked to start a transmission to another peer.
 *
 * @param cls the 'struct NeighbourMapEntry'
 * @param tc scheduler context
 */
static void
transmission_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct NeighbourMapEntry *n = cls;

  n->transmission_task = GNUNET_SCHEDULER_NO_TASK;
  try_transmission_to_peer (n);
}


/**
 * Initialize the neighbours subsystem.
 *
 * @param cls closure for callbacks
 * @param connect_cb function to call if we connect to a peer
 * @param disconnect_cb function to call if we disconnect from a peer
 */
void
GST_neighbours_start (void *cls, GNUNET_TRANSPORT_NotifyConnect connect_cb,
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

  if (GNUNET_YES == n->in_disconnect)
    return;
  n->in_disconnect = GNUNET_YES;
  while (NULL != (mq = n->messages_head))
  {
    GNUNET_CONTAINER_DLL_remove (n->messages_head, n->messages_tail, mq);
    if (NULL != mq->cont)
      mq->cont (mq->cont_cls, GNUNET_SYSERR);
    GNUNET_free (mq);
  }
  if (NULL != n->is_active)
  {
    n->is_active->n = NULL;
    n->is_active = NULL;
  }
  if (GNUNET_YES == n->is_connected)
  {
    n->is_connected = GNUNET_NO;
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK != n->keepalive_task);
    GNUNET_SCHEDULER_cancel (n->keepalive_task);
    n->keepalive_task = GNUNET_SCHEDULER_NO_TASK;  
    GNUNET_assert (neighbours_connected > 0);
    neighbours_connected--;
    GNUNET_STATISTICS_update (GST_stats, gettext_noop ("# peers connected"), -1,
                              GNUNET_NO);
    disconnect_notify_cb (callback_cls, &n->id);
  }
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (neighbours,
                                                       &n->id.hashPubKey, n));
  if (GNUNET_SCHEDULER_NO_TASK != n->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (n->timeout_task);
    n->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (GNUNET_SCHEDULER_NO_TASK != n->transmission_task)
  {
    GNUNET_SCHEDULER_cancel (n->transmission_task);
    n->transmission_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != n->asc)
  {
    GNUNET_ATS_suggest_address_cancel (n->asc);
    n->asc = NULL;
  }
  GNUNET_array_grow (n->ats, n->ats_count, 0);
  if (NULL != n->plugin_name)
  {
    GNUNET_free (n->plugin_name);
    n->plugin_name = NULL;
  }
  if (NULL != n->addr)
  {
    GNUNET_free (n->addr);
    n->addr = NULL;
    n->addrlen = 0;
  }
  n->session = NULL;
  GNUNET_free (n);
}


/**
 * Peer has been idle for too long. Disconnect.
 *
 * @param cls the 'struct NeighbourMapEntry' of the neighbour that went idle
 * @param tc scheduler context
 */
static void
neighbour_timeout_task (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct NeighbourMapEntry *n = cls;

  n->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  if (GNUNET_YES == n->is_connected)
    GNUNET_STATISTICS_update (GST_stats,
			      gettext_noop ("# peers disconnected due to timeout"), 1,
			      GNUNET_NO);
  disconnect_neighbour (n);
}


/**
 * Send another keepalive message.
 *
 * @param cls the 'struct NeighbourMapEntry' of the neighbour that went idle
 * @param tc scheduler context
 */
static void
neighbour_keepalive_task (void *cls,
			  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct NeighbourMapEntry *n = cls;
  struct GNUNET_MessageHeader m;
  struct GNUNET_TRANSPORT_PluginFunctions *papi;

  n->keepalive_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_assert (GNUNET_YES == n->is_connected);
  GNUNET_STATISTICS_update (GST_stats,
			    gettext_noop ("# keepalives sent"), 1,
			    GNUNET_NO);
  m.size = htons (sizeof (struct GNUNET_MessageHeader));
  m.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_KEEPALIVE);
  papi = GST_plugins_find (n->plugin_name);
  if (papi != NULL)
    papi->send (papi->cls, 
		&n->id, (const void *) &m,
		sizeof (m),
		UINT32_MAX /* priority */ ,
		GNUNET_TIME_UNIT_FOREVER_REL, n->session, n->addr, n->addrlen,
		GNUNET_YES, NULL, NULL);
  n->keepalive_task = GNUNET_SCHEDULER_add_delayed (KEEPALIVE_FREQUENCY,
						    &neighbour_keepalive_task,
						    n);
}


/**
 * Disconnect from the given neighbour.
 *
 * @param cls unused
 * @param key hash of neighbour's public key (not used)
 * @param value the 'struct NeighbourMapEntry' of the neighbour
 */
static int
disconnect_all_neighbours (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct NeighbourMapEntry *n = value;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Disconnecting peer `%4s', %s\n",
              GNUNET_i2s (&n->id), "SHUTDOWN_TASK");
#endif
  if (GNUNET_YES == n->is_connected)
    GNUNET_STATISTICS_update (GST_stats,
			      gettext_noop ("# peers disconnected due to global disconnect"), 1,
			      GNUNET_NO);
  disconnect_neighbour (n);
  return GNUNET_OK;
}


/**
 * Cleanup the neighbours subsystem.
 */
void
GST_neighbours_stop ()
{
  GNUNET_assert (neighbours != NULL);

  GNUNET_CONTAINER_multihashmap_iterate (neighbours, &disconnect_all_neighbours,
                                         NULL);
  GNUNET_CONTAINER_multihashmap_destroy (neighbours);
  GNUNET_assert (neighbours_connected == 0);
  neighbours = NULL;
  callback_cls = NULL;
  connect_notify_cb = NULL;
  disconnect_notify_cb = NULL;
}


/**
 * For an existing neighbour record, set the active connection to
 * the given address.
 *
 * @param peer identity of the peer to switch the address for
 * @param plugin_name name of transport that delivered the PONG
 * @param address address of the other peer, NULL if other peer
 *                       connected to us
 * @param address_len number of bytes in address
 * @param session session to use (or NULL)
 * @param ats performance data
 * @param ats_count number of entries in ats (excluding 0-termination)
 */
void
GST_neighbours_switch_to_address (const struct GNUNET_PeerIdentity *peer,
                                  const char *plugin_name, const void *address,
                                  size_t address_len, struct Session *session,
                                  const struct GNUNET_TRANSPORT_ATS_Information
                                  *ats, uint32_t ats_count)
{
  struct NeighbourMapEntry *n;
  struct SessionConnectMessage connect_msg;

  GNUNET_assert (neighbours != NULL);

  n = lookup_neighbour (peer);
  if (NULL == n)
  {
    /* FIXME: ATS not fully implemented, once ATS only generates
       these events for 'connected' addresses, things should be better... */
    // GNUNET_break (0);
    return;
  }

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "SWITCH! Peer `%4s' switches to plugin `%s' address '%s' session %X\n",
              GNUNET_i2s (peer), plugin_name,
              (address_len == 0) ? "<inbound>" : GST_plugins_a2s (plugin_name,
                                                                  address,
                                                                  address_len),
              session);
#endif

  GNUNET_free_non_null (n->addr);
  n->addr = GNUNET_malloc (address_len);
  memcpy (n->addr, address, address_len);
  n->addrlen = address_len;
  n->session = session;
  GNUNET_array_grow (n->ats, n->ats_count, ats_count);
  memcpy (n->ats, ats,
          ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information));
  GNUNET_free_non_null (n->plugin_name);
  n->plugin_name = GNUNET_strdup (plugin_name);
  GNUNET_SCHEDULER_cancel (n->timeout_task);
  n->timeout_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                                    &neighbour_timeout_task, n);
  connect_msg.header.size = htons (sizeof (struct SessionConnectMessage));
  connect_msg.header.type =
      htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_CONNECT);
  connect_msg.reserved = htonl (0);
  connect_msg.timestamp =
      GNUNET_TIME_absolute_hton (GNUNET_TIME_absolute_get ());
  GST_neighbours_send (peer, &connect_msg, sizeof (connect_msg),
                       GNUNET_TIME_UNIT_FOREVER_REL, NULL, NULL);
}


/**
 * Try to connect to the target peer using the given address
 *
 * @param cls the 'struct NeighbourMapEntry' of the target
 * @param target identity of the target peer
 * @param plugin_name name of the plugin
 * @param plugin_address binary address
 * @param plugin_address_len length of address
 * @param session session to use
 * @param bandwidth_out available outbound bandwidth
 * @param bandwidth_in available inbound bandwidth
 * @param ats performance data for the address (as far as known)
 * @param ats_count number of performance records in 'ats'
 */
static void
try_connect_using_address (void *cls, const struct GNUNET_PeerIdentity *target,
                           const char *plugin_name, const void *plugin_address,
                           size_t plugin_address_len, struct Session *session,
                           struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
                           struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
                           const struct GNUNET_TRANSPORT_ATS_Information *ats,
                           uint32_t ats_count)
{
  struct NeighbourMapEntry *n = cls;
  int was_connected;

  n->asc = NULL;
  was_connected = n->is_connected;
  n->is_connected = GNUNET_YES;

  GST_neighbours_switch_to_address (target, plugin_name, plugin_address,
                                    plugin_address_len, session, ats,
                                    ats_count);
  if (GNUNET_YES == was_connected)
    return;
  n->keepalive_task = GNUNET_SCHEDULER_add_now (&neighbour_keepalive_task,
						n);

  /* ATS told us inbound quota for this peer */
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Setting inbound quota of %u for peer `%s' to \n",
              ntohl (bandwidth_in.value__), GNUNET_i2s (target));
#endif
  GST_neighbours_set_incoming_quota (&n->id, bandwidth_in);

  /* First tell clients about connected neighbours...*/
  neighbours_connected++;
  GNUNET_STATISTICS_update (GST_stats, gettext_noop ("# peers connected"), 1,
                            GNUNET_NO);
  connect_notify_cb (callback_cls, target, n->ats, n->ats_count);

  /* ... then send outbound quota for this peer to all clients */
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending outbound quota of %u Bps for peer `%s' to all clients\n",
              ntohl (bandwidth_out.value__), GNUNET_i2s (target));
#endif

  struct QuotaSetMessage msg;
  msg.header.size = htons (sizeof (struct QuotaSetMessage));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SET_QUOTA);
  msg.quota = bandwidth_out;
  msg.peer = (*target);
  GST_clients_broadcast ((struct GNUNET_MessageHeader *) &msg, GNUNET_NO);

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

  GNUNET_assert (neighbours != NULL);

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Trying to connect to peer `%s'\n",
              GNUNET_i2s (target));
#endif

  GNUNET_assert (0 !=
                 memcmp (target, &GST_my_identity,
                         sizeof (struct GNUNET_PeerIdentity)));
  n = lookup_neighbour (target);
  if ((NULL != n) && (GNUNET_YES == n->is_connected))
    return;                     /* already connected */
  if (n == NULL)
  {
#if DEBUG_TRANSPORT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Unknown peer `%s', creating new neighbour\n",
                GNUNET_i2s (target));
#endif
    n = GNUNET_malloc (sizeof (struct NeighbourMapEntry));
    n->id = *target;
    GNUNET_array_grow (n->ats, n->ats_count, 1);
    n->ats[0].type = htonl (GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR);;
    n->ats[0].value = htonl (0);
    GNUNET_BANDWIDTH_tracker_init (&n->in_tracker,
                                   GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT,
                                   MAX_BANDWIDTH_CARRY_S);
    n->timeout_task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                                      &neighbour_timeout_task, n);
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multihashmap_put (neighbours,
                                                      &n->id.hashPubKey, n,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }
  if (n->asc != NULL)
    return;                     /* already trying */
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Asking ATS for suggested address to connect to peer `%s'\n",
              GNUNET_i2s (target));
#endif
  n->asc =
      GNUNET_ATS_suggest_address (GST_ats, target, &try_connect_using_address,
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

  GNUNET_assert (neighbours != NULL);

  n = lookup_neighbour (target);
  if ((NULL == n) || (n->is_connected != GNUNET_YES))
    return GNUNET_NO;           /* not connected */
  return GNUNET_YES;
}


/**
 * A session was terminated. Take note.
 *
 * @param peer identity of the peer where the session died
 * @param session session that is gone
 */
void
GST_neighbours_session_terminated (const struct GNUNET_PeerIdentity *peer,
                                   struct Session *session)
{
  struct NeighbourMapEntry *n;

  GNUNET_assert (neighbours != NULL);

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Session %X to peer `%s' ended \n",
              session, GNUNET_i2s (peer));
#endif

  n = lookup_neighbour (peer);
  if (NULL == n)
    return;
  if (session != n->session)
    return;                     /* doesn't affect us */

  n->session = NULL;
  GNUNET_free (n->addr);
  n->addr = NULL;
  n->addrlen = 0;


  if (GNUNET_YES != n->is_connected)
    return;                     /* not connected anymore anyway, shouldn't matter */

  //n->is_connected = GNUNET_NO;

  /* fast disconnect unless ATS suggests a new address */
  GNUNET_SCHEDULER_cancel (n->timeout_task);
  n->timeout_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_DISCONNECT_SESSION_TIMEOUT,
                                    &neighbour_timeout_task, n);
  /* try QUICKLY to re-establish a connection, reduce timeout! */
  if (NULL != n->ats)
  {
    /* how can this be!? */
    //GNUNET_break (0);
    return;
  }
  n->asc =
      GNUNET_ATS_suggest_address (GST_ats, peer, &try_connect_using_address, n);
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
GST_neighbours_send (const struct GNUNET_PeerIdentity *target, const void *msg,
                     size_t msg_size, struct GNUNET_TIME_Relative timeout,
                     GST_NeighbourSendContinuation cont, void *cont_cls)
{
  struct NeighbourMapEntry *n;
  struct MessageQueue *mq;

  GNUNET_assert (neighbours != NULL);

  n = lookup_neighbour (target);
  if ((n == NULL) || (GNUNET_YES != n->is_connected))
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# messages not sent (no such peer or not connected)"),
                              1, GNUNET_NO);
#if DEBUG_TRANSPORT
    if (n == NULL)
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Could not send message to peer `%s': unknown neighbor",
                  GNUNET_i2s (target));
    else if (GNUNET_YES != n->is_connected)
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Could not send message to peer `%s': not connected\n",
                  GNUNET_i2s (target));
#endif
    if (NULL != cont)
      cont (cont_cls, GNUNET_SYSERR);
    return;
  }

  if ((n->session == NULL) && (n->addr == NULL) && (n->addrlen ==0))
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# messages not sent (no such peer or not connected)"),
                              1, GNUNET_NO);
#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Could not send message to peer `%s': no address available\n",
                  GNUNET_i2s (target));
#endif

    if (NULL != cont)
      cont (cont_cls, GNUNET_SYSERR);
    return;
  }


  GNUNET_assert (msg_size >= sizeof (struct GNUNET_MessageHeader));
  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop
                            ("# bytes in message queue for other peers"),
                            msg_size, GNUNET_NO);
  mq = GNUNET_malloc (sizeof (struct MessageQueue) + msg_size);
  mq->cont = cont;
  mq->cont_cls = cont_cls;
  /* FIXME: this memcpy can be up to 7% of our total runtime! */
  memcpy (&mq[1], msg, msg_size);
  mq->message_buf = (const char *) &mq[1];
  mq->message_buf_size = msg_size;
  mq->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  GNUNET_CONTAINER_DLL_insert_tail (n->messages_head, n->messages_tail, mq);
  if ((GNUNET_SCHEDULER_NO_TASK == n->transmission_task) &&
      (NULL == n->is_active))
    n->transmission_task = GNUNET_SCHEDULER_add_now (&transmission_task, n);
}


/**
 * We have received a message from the given sender.  How long should
 * we delay before receiving more?  (Also used to keep the peer marked
 * as live).
 *
 * @param sender sender of the message
 * @param size size of the message
 * @param do_forward set to GNUNET_YES if the message should be forwarded to clients
 *                   GNUNET_NO if the neighbour is not connected or violates the quota
 * @return how long to wait before reading more from this sender
 */
struct GNUNET_TIME_Relative
GST_neighbours_calculate_receive_delay (const struct GNUNET_PeerIdentity
                                        *sender, ssize_t size, int *do_forward)
{
  struct NeighbourMapEntry *n;
  struct GNUNET_TIME_Relative ret;

  GNUNET_assert (neighbours != NULL);

  n = lookup_neighbour (sender);
  if (n == NULL)
  {
    *do_forward = GNUNET_NO;
    return GNUNET_TIME_UNIT_ZERO;
  }
  if (GNUNET_YES == GNUNET_BANDWIDTH_tracker_consume (&n->in_tracker, size))
  {
    n->quota_violation_count++;
#if DEBUG_TRANSPORT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Bandwidth quota (%u b/s) violation detected (total of %u).\n",
                n->in_tracker.available_bytes_per_s__,
                n->quota_violation_count);
#endif
    /* Discount 32k per violation */
    GNUNET_BANDWIDTH_tracker_consume (&n->in_tracker, -32 * 1024);
  }
  else
  {
    if (n->quota_violation_count > 0)
    {
      /* try to add 32k back */
      GNUNET_BANDWIDTH_tracker_consume (&n->in_tracker, 32 * 1024);
      n->quota_violation_count--;
    }
  }
  if (n->quota_violation_count > QUOTA_VIOLATION_DROP_THRESHOLD)
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# bandwidth quota violations by other peers"),
                              1, GNUNET_NO);
    *do_forward = GNUNET_NO;
    return GNUNET_CONSTANTS_QUOTA_VIOLATION_TIMEOUT;
  }
  *do_forward = GNUNET_YES;
  ret = GNUNET_BANDWIDTH_tracker_get_delay (&n->in_tracker, 0);
  if (ret.rel_value > 0)
  {
#if DEBUG_TRANSPORT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Throttling read (%llu bytes excess at %u b/s), waiting %llu ms before reading more.\n",
                (unsigned long long) n->in_tracker.
                consumption_since_last_update__,
                (unsigned int) n->in_tracker.available_bytes_per_s__,
                (unsigned long long) ret.rel_value);
#endif
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop ("# ms throttling suggested"),
                              (int64_t) ret.rel_value, GNUNET_NO);
  }
  return ret;
}


/**
 * Keep the connection to the given neighbour alive longer,
 * we received a KEEPALIVE (or equivalent).
 *
 * @param neighbour neighbour to keep alive
 */
void
GST_neighbours_keepalive (const struct GNUNET_PeerIdentity *neighbour)
{
  struct NeighbourMapEntry *n;

  GNUNET_assert (neighbours != NULL);

  n = lookup_neighbour (neighbour);
  if (NULL == n)
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# KEEPALIVE messages discarded (not connected)"),
                              1, GNUNET_NO);
    return;
  }
  GNUNET_SCHEDULER_cancel (n->timeout_task);
  n->timeout_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                                    &neighbour_timeout_task, n);
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

  GNUNET_assert (neighbours != NULL);

  n = lookup_neighbour (neighbour);
  if (n == NULL)
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# SET QUOTA messages ignored (no such peer)"),
                              1, GNUNET_NO);
    return;
  }
  GNUNET_BANDWIDTH_tracker_update_quota (&n->in_tracker, quota);
  if (0 != ntohl (quota.value__))
    return;
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Disconnecting peer `%4s' due to `%s'\n",
              GNUNET_i2s (&n->id), "SET_QUOTA");
#endif
  if (GNUNET_YES == n->is_connected)
    GNUNET_STATISTICS_update (GST_stats,
			      gettext_noop ("# disconnects due to quota of 0"), 1,
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
neighbours_iterate (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct IteratorContext *ic = cls;
  struct NeighbourMapEntry *n = value;

  if (GNUNET_YES != n->is_connected)
    return GNUNET_OK;

  GNUNET_assert (n->ats_count > 0);
  ic->cb (ic->cb_cls, &n->id, n->ats, n->ats_count, n->plugin_name, n->addr, n->addrlen);
  return GNUNET_OK;
}


/**
 * Iterate over all connected neighbours.
 *
 * @param cb function to call
 * @param cb_cls closure for cb
 */
void
GST_neighbours_iterate (GST_NeighbourIterator cb, void *cb_cls)
{
  struct IteratorContext ic;

  GNUNET_assert (neighbours != NULL);

  ic.cb = cb;
  ic.cb_cls = cb_cls;
  GNUNET_CONTAINER_multihashmap_iterate (neighbours, &neighbours_iterate, &ic);
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
  struct GNUNET_TRANSPORT_PluginFunctions *papi;
  struct SessionDisconnectMessage disconnect_msg;

  GNUNET_assert (neighbours != NULL);

  n = lookup_neighbour (target);
  if (NULL == n)
    return;                     /* not active */
  if (GNUNET_YES == n->is_connected)
  {
    /* we're actually connected, send DISCONNECT message */
    disconnect_msg.header.size = htons (sizeof (struct SessionDisconnectMessage));
    disconnect_msg.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_DISCONNECT);
    disconnect_msg.reserved = htonl (0);
    disconnect_msg.purpose.size = htonl (sizeof (struct GNUNET_CRYPTO_RsaSignaturePurpose) +
					 sizeof (struct GNUNET_TIME_AbsoluteNBO));
    disconnect_msg.purpose.purpose = htonl (GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_DISCONNECT);
    disconnect_msg.timestamp = GNUNET_TIME_absolute_hton (GNUNET_TIME_absolute_get ());
    GNUNET_assert (GNUNET_OK ==
		   GNUNET_CRYPTO_rsa_sign (GST_my_private_key,
					   &disconnect_msg.purpose,
					   &disconnect_msg.signature));
    papi = GST_plugins_find (n->plugin_name);
    if (papi != NULL)
      papi->send (papi->cls, target, (const void *) &disconnect_msg,
                  sizeof (disconnect_msg),
                  UINT32_MAX /* priority */ ,
                  GNUNET_TIME_UNIT_FOREVER_REL, n->session, n->addr, n->addrlen,
                  GNUNET_YES, NULL, NULL);
    GNUNET_STATISTICS_update (GST_stats,
			      gettext_noop ("# peers disconnected due to external request"), 1,
			      GNUNET_NO);
  }
  disconnect_neighbour (n);
}


/* end of file gnunet-service-transport_neighbours.c */
