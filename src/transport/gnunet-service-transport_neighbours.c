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
#include "gnunet-service-transport_blacklist.h"
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
 * How often do we send KEEPALIVE messages to each of our neighbours and measure
 * the latency with this neighbour?
 * (idle timeout is 5 minutes or 300 seconds, so with 30s interval we
 * send 10 keepalives in each interval, so 10 messages would need to be
 * lost in a row for a disconnect).
 */
#define KEEPALIVE_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)


#define ATS_RESPONSE_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

#define FAST_RECONNECT_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)

#define SETUP_CONNECTION_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15)

#define  TEST_NEW_CODE GNUNET_NO

/**
 * Entry in neighbours.
 */
struct NeighbourMapEntry;

GNUNET_NETWORK_STRUCT_BEGIN

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
   * Public key of the sender.
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded public_key;

  /**
   * Signature of the peer that sends us the disconnect.  Only
   * valid if the timestamp is AFTER the timestamp from the
   * corresponding 'CONNECT' message.
   */
  struct GNUNET_CRYPTO_RsaSignature signature;

};
GNUNET_NETWORK_STRUCT_END

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


enum State
{
  /**
   * fresh peer or completely disconnected
   */
  S_NOT_CONNECTED,

  /**
   * sent CONNECT message to other peer, waiting for CONNECT_ACK
   */
  S_CONNECT_SENT,

  /**
   * received CONNECT message to other peer, sending CONNECT_ACK
   */
  S_CONNECT_RECV,

  /**
   * received ACK or payload
   */
  S_CONNECTED,

  /**
   * connection ended, fast reconnect
   */
  S_FAST_RECONNECT,

  /**
   * Disconnect in progress
   */
  S_DISCONNECT
};

enum Address_State
{
  USED,
  UNUSED,
  FRESH,
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
   * Are we currently trying to send a message? If so, which one?
   */
  struct MessageQueue *is_active;

  /**
   * Active session for communicating with the peer.
   */
  struct Session *session;

  /**
   * Address we currently use.
   */
  struct GNUNET_HELLO_Address *address;

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
   * Inbound bandwidth from ATS, activated when connection is up
   */
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in;

  /**
   * Inbound bandwidth from ATS, activated when connection is up
   */
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out;

  /**
   * Timestamp of the 'SESSION_CONNECT' message we got from the other peer
   */
  struct GNUNET_TIME_Absolute connect_ts;

  /**
   * When did we sent the last keep-alive message?
   */
  struct GNUNET_TIME_Absolute keep_alive_sent;

  /**
   * Latest calculated latency value
   */
  struct GNUNET_TIME_Relative latency;

  /**
   * Timeout for ATS
   * We asked ATS for a new address for this peer
   */
  GNUNET_SCHEDULER_TaskIdentifier ats_suggest;

  /**
   * Task the resets the peer state after due to an pending
   * unsuccessful connection setup
   */
  GNUNET_SCHEDULER_TaskIdentifier state_reset;


  /**
   * How often has the other peer (recently) violated the inbound
   * traffic limit?  Incremented by 10 per violation, decremented by 1
   * per non-violation (for each time interval).
   */
  unsigned int quota_violation_count;


  /**
   * The current state of the peer
   * Element of enum State
   */
  int state;

  /**
   * Did we sent an KEEP_ALIVE message and are we expecting a response?
   */
  int expect_latency_response;
  int address_state;
};


/**
 * All known neighbours and their HELLOs.
 */
static struct GNUNET_CONTAINER_MultiHashMap *neighbours;

/**
 * Closure for connect_notify_cb, disconnect_notify_cb and address_change_cb
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
 * Function to call when we changed an active address of a neighbour.
 */
static GNUNET_TRANSPORT_PeerIterateCallback address_change_cb;

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
 * Disconnect from the given neighbour, clean up the record.
 *
 * @param n neighbour to disconnect from
 */
static void
disconnect_neighbour (struct NeighbourMapEntry *n);

#define change_state(n, state, ...) change (n, state, __LINE__)

static int
is_connecting (struct NeighbourMapEntry *n)
{
  if ((n->state > S_NOT_CONNECTED) && (n->state < S_CONNECTED))
    return GNUNET_YES;
  return GNUNET_NO;
}

static int
is_connected (struct NeighbourMapEntry *n)
{
  if (n->state == S_CONNECTED)
    return GNUNET_YES;
  return GNUNET_NO;
}

static int
is_disconnecting (struct NeighbourMapEntry *n)
{
  if (n->state == S_DISCONNECT)
    return GNUNET_YES;
  return GNUNET_NO;
}

static const char *
print_state (int state)
{
  switch (state)
  {
  case S_CONNECTED:
    return "S_CONNECTED";
    break;
  case S_CONNECT_RECV:
    return "S_CONNECT_RECV";
    break;
  case S_CONNECT_SENT:
    return "S_CONNECT_SENT";
    break;
  case S_DISCONNECT:
    return "S_DISCONNECT";
    break;
  case S_NOT_CONNECTED:
    return "S_NOT_CONNECTED";
    break;
  case S_FAST_RECONNECT:
    return "S_FAST_RECONNECT";
    break;
  default:
    GNUNET_break (0);
    break;
  }
  return NULL;
}

static int
change (struct NeighbourMapEntry *n, int state, int line);

static void
ats_suggest_cancel (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


static void
reset_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct NeighbourMapEntry *n = cls;

  if (n == NULL)
    return;

  n->state_reset = GNUNET_SCHEDULER_NO_TASK;
  if (n->state == S_CONNECTED)
    return;

#if DEBUG_TRANSPORT
  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop
                            ("# failed connection attempts due to timeout"), 1,
                            GNUNET_NO);
#endif

  /* resetting state */

  if (n->state == S_FAST_RECONNECT)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Fast reconnect time out, disconnecting peer `%s'\n",
                GNUNET_i2s (&n->id));
    disconnect_neighbour(n);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "State for neighbour `%s' %X changed from `%s' to `%s' in line %u\n",
              GNUNET_i2s (&n->id), n, print_state(n->state), "S_NOT_CONNECTED", __LINE__);

  n->state = S_NOT_CONNECTED;

  /* destroying address */
  if (n->address != NULL)
  {
    GNUNET_assert (strlen (n->address->transport_name) > 0);
    GNUNET_ATS_address_destroyed (GST_ats, n->address, n->session);
  }

  /* request new address */
  if (n->ats_suggest != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (n->ats_suggest);
  n->ats_suggest =
      GNUNET_SCHEDULER_add_delayed (ATS_RESPONSE_TIMEOUT, ats_suggest_cancel,
                                    n);
  GNUNET_ATS_suggest_address (GST_ats, &n->id);
}

static int
change (struct NeighbourMapEntry *n, int state, int line)
{
  int previous_state;
  /* allowed transitions */
  int allowed = GNUNET_NO;

  previous_state = n->state;

  switch (n->state)
  {
  case S_NOT_CONNECTED:
    if ((state == S_CONNECT_RECV) || (state == S_CONNECT_SENT) ||
        (state == S_DISCONNECT))
      allowed = GNUNET_YES;
    break;
  case S_CONNECT_RECV:
    allowed = GNUNET_YES;
    break;
  case S_CONNECT_SENT:
    allowed = GNUNET_YES;
    break;
  case S_CONNECTED:
    if ((state == S_DISCONNECT) || (state == S_FAST_RECONNECT))
      allowed = GNUNET_YES;
    break;
  case S_DISCONNECT:
    break;
  case S_FAST_RECONNECT:
    if ((state == S_CONNECTED) || (state == S_DISCONNECT))
      allowed = GNUNET_YES;
    break;
  default:
    GNUNET_break (0);
    break;
  }
  if (allowed == GNUNET_NO)
  {
    char *old = GNUNET_strdup (print_state (n->state));
    char *new = GNUNET_strdup (print_state (state));

    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Illegal state transition from `%s' to `%s' in line %u \n", old,
                new, line);
    GNUNET_break (0);
    GNUNET_free (old);
    GNUNET_free (new);
    return GNUNET_SYSERR;
  }
  {
    char *old = GNUNET_strdup (print_state (n->state));
    char *new = GNUNET_strdup (print_state (state));

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "State for neighbour `%s' %X changed from `%s' to `%s' in line %u\n",
                GNUNET_i2s (&n->id), n, old, new, line);
    GNUNET_free (old);
    GNUNET_free (new);
  }
  n->state = state;

  switch (n->state)
  {
  case S_FAST_RECONNECT:
  case S_CONNECT_RECV:
  case S_CONNECT_SENT:
    if (n->state_reset != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (n->state_reset);
    n->state_reset =
        GNUNET_SCHEDULER_add_delayed (SETUP_CONNECTION_TIMEOUT, &reset_task, n);
    break;
  case S_CONNECTED:
  case S_NOT_CONNECTED:
  case S_DISCONNECT:
    if (GNUNET_SCHEDULER_NO_TASK != n->state_reset)
    {
#if DEBUG_TRANSPORT
      char *old = GNUNET_strdup (print_state (n->state));
      char *new = GNUNET_strdup (print_state (state));

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Removed reset task for peer `%s' %s failed in state transition `%s' -> `%s' \n",
                  GNUNET_i2s (&n->id), GST_plugins_a2s (n->address), old, new);
      GNUNET_free (old);
      GNUNET_free (new);
#endif
      GNUNET_assert (n->state_reset != GNUNET_SCHEDULER_NO_TASK);
      GNUNET_SCHEDULER_cancel (n->state_reset);
      n->state_reset = GNUNET_SCHEDULER_NO_TASK;
    }
    break;

  default:
    GNUNET_assert (0);
  }

  if (NULL != address_change_cb)
  {
    if (n->state == S_CONNECTED)
      address_change_cb (callback_cls, &n->id, n->address);
    else if (previous_state == S_CONNECTED)
      address_change_cb (callback_cls, &n->id, NULL);
  }

  return GNUNET_OK;
}

static ssize_t
send_with_session (struct NeighbourMapEntry *n,
                   const char *msgbuf, size_t msgbuf_size,
                   uint32_t priority,
                   struct GNUNET_TIME_Relative timeout,
                   GNUNET_TRANSPORT_TransmitContinuation cont, void *cont_cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *papi;
  size_t ret = GNUNET_SYSERR;

  GNUNET_assert (n != NULL);
  GNUNET_assert (n->session != NULL);

  papi = GST_plugins_find (n->address->transport_name);
  if (papi == NULL)
  {
    if (cont != NULL)
      cont (cont_cls, &n->id, GNUNET_SYSERR);
    return GNUNET_SYSERR;
  }

  ret = papi->send (papi->cls,
                   n->session,
                   msgbuf, msgbuf_size,
                   0,
                   timeout,
                   cont, cont_cls);

  if ((ret == -1) && (cont != NULL))
      cont (cont_cls, &n->id, GNUNET_SYSERR);
  return ret;
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
  struct MessageQueue *mq = cls;
  struct NeighbourMapEntry *n;
  struct NeighbourMapEntry *tmp;

  tmp = lookup_neighbour (receiver);
  n = mq->n;
  if ((NULL != n) && (tmp != NULL) && (tmp == n))
  {
    GNUNET_assert (n->is_active == mq);
    n->is_active = NULL;
    if (success == GNUNET_YES)
    {
      GNUNET_assert (n->transmission_task == GNUNET_SCHEDULER_NO_TASK);
      n->transmission_task = GNUNET_SCHEDULER_add_now (&transmission_task, n);
    }
  }
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending message of type %u was %s\n",
              ntohs (((struct GNUNET_MessageHeader *) mq->message_buf)->type),
              (success == GNUNET_OK) ? "successful" : "FAILED");
#endif
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

  if (n->is_active != NULL)
  {
    GNUNET_break (0);
    return;                     /* transmission already pending */
  }
  if (n->transmission_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_break (0);
    return;                     /* currently waiting for bandwidth */
  }
  while (NULL != (mq = n->messages_head))
  {
    timeout = GNUNET_TIME_absolute_get_remaining (mq->timeout);
    if (timeout.rel_value > 0)
      break;
    GNUNET_CONTAINER_DLL_remove (n->messages_head, n->messages_tail, mq);
    n->is_active = mq;
    mq->n = n;
    transmit_send_continuation (mq, &n->id, GNUNET_SYSERR);     /* timeout */
  }
  if (NULL == mq)
    return;                     /* no more messages */

  if (n->address == NULL)
  {
#if DEBUG_TRANSPORT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "No address for peer `%s'\n",
                GNUNET_i2s (&n->id));
#endif
    GNUNET_CONTAINER_DLL_remove (n->messages_head, n->messages_tail, mq);
    transmit_send_continuation (mq, &n->id, GNUNET_SYSERR);
    GNUNET_assert (n->transmission_task == GNUNET_SCHEDULER_NO_TASK);
    n->transmission_task = GNUNET_SCHEDULER_add_now (&transmission_task, n);
    return;
  }

  if (GST_plugins_find (n->address->transport_name) == NULL)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_CONTAINER_DLL_remove (n->messages_head, n->messages_tail, mq);
  n->is_active = mq;
  mq->n = n;

  if ((n->address->address_length == 0) && (n->session == NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "No address for peer `%s'\n",
                GNUNET_i2s (&n->id));
    transmit_send_continuation (mq, &n->id, GNUNET_SYSERR);
    GNUNET_assert (n->transmission_task == GNUNET_SCHEDULER_NO_TASK);
    n->transmission_task = GNUNET_SCHEDULER_add_now (&transmission_task, n);
    return;
  }

  ret = send_with_session(n,
              mq->message_buf, mq->message_buf_size,
              0, timeout,
              &transmit_send_continuation, mq);

  if (ret == -1)
  {
    /* failure, but 'send' would not call continuation in this case,
     * so we need to do it here! */
    transmit_send_continuation (mq, &n->id, GNUNET_SYSERR);
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

  GNUNET_assert (NULL != lookup_neighbour (&n->id));
  n->transmission_task = GNUNET_SCHEDULER_NO_TASK;
  try_transmission_to_peer (n);
}


/**
 * Initialize the neighbours subsystem.
 *
 * @param cls closure for callbacks
 * @param connect_cb function to call if we connect to a peer
 * @param disconnect_cb function to call if we disconnect from a peer
 * @param peer_address_cb function to call if we change an active address
 *                   of a neighbour
 */
void
GST_neighbours_start (void *cls,
                      GNUNET_TRANSPORT_NotifyConnect connect_cb,
                      GNUNET_TRANSPORT_NotifyDisconnect disconnect_cb,
                      GNUNET_TRANSPORT_PeerIterateCallback peer_address_cb)
{
  callback_cls = cls;
  connect_notify_cb = connect_cb;
  disconnect_notify_cb = disconnect_cb;
  address_change_cb = peer_address_cb;
  neighbours = GNUNET_CONTAINER_multihashmap_create (NEIGHBOUR_TABLE_SIZE);
}


static void
send_disconnect_cont (void *cls, const struct GNUNET_PeerIdentity *target,
                      int result)
{
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending DISCONNECT message to peer `%4s': %i\n",
              GNUNET_i2s (target), result);
#endif
}


static int
send_disconnect (struct NeighbourMapEntry * n)
{
  size_t ret;
  struct SessionDisconnectMessage disconnect_msg;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending DISCONNECT message to peer `%4s'\n",
              GNUNET_i2s (&n->id));
#endif

  disconnect_msg.header.size = htons (sizeof (struct SessionDisconnectMessage));
  disconnect_msg.header.type =
      htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_DISCONNECT);
  disconnect_msg.reserved = htonl (0);
  disconnect_msg.purpose.size =
      htonl (sizeof (struct GNUNET_CRYPTO_RsaSignaturePurpose) +
             sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded) +
             sizeof (struct GNUNET_TIME_AbsoluteNBO));
  disconnect_msg.purpose.purpose =
      htonl (GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_DISCONNECT);
  disconnect_msg.timestamp =
      GNUNET_TIME_absolute_hton (GNUNET_TIME_absolute_get ());
  disconnect_msg.public_key = GST_my_public_key;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_rsa_sign (GST_my_private_key,
                                         &disconnect_msg.purpose,
                                         &disconnect_msg.signature));

  ret = send_with_session (n,
            (const char *) &disconnect_msg, sizeof (disconnect_msg),
            UINT32_MAX, GNUNET_TIME_UNIT_FOREVER_REL,
            &send_disconnect_cont, NULL);

  if (ret == GNUNET_SYSERR)
    return GNUNET_SYSERR;

  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop
                            ("# peers disconnected due to external request"), 1,
                            GNUNET_NO);
  return GNUNET_OK;
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
  int previous_state;

  previous_state = n->state;

  if (is_disconnecting (n))
    return;

  /* send DISCONNECT MESSAGE */
  if (previous_state == S_CONNECTED)
  {
    if (GNUNET_OK == send_disconnect (n))
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sent DISCONNECT_MSG to `%s'\n",
                  GNUNET_i2s (&n->id));
    else
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Could not send DISCONNECT_MSG to `%s'\n",
                  GNUNET_i2s (&n->id));
  }

  change_state (n, S_DISCONNECT);

  if (previous_state == S_CONNECTED)
  {
    GNUNET_assert (NULL != n->address);
    if (n->address_state == USED)
    {
      GST_validation_set_address_use (n->address, n->session, GNUNET_NO);
      GNUNET_ATS_address_in_use (GST_ats, n->address, n->session, GNUNET_NO);
      n->address_state = UNUSED;
    }
  }

  if (n->address != NULL)
  {
    struct GNUNET_TRANSPORT_PluginFunctions *papi;

    papi = GST_plugins_find (n->address->transport_name);
    if (papi != NULL)
      papi->disconnect (papi->cls, &n->id);
  }
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

  switch (previous_state)
  {
  case S_CONNECTED:
    GNUNET_assert (neighbours_connected > 0);
    neighbours_connected--;
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK != n->keepalive_task);
    GNUNET_SCHEDULER_cancel (n->keepalive_task);
    n->keepalive_task = GNUNET_SCHEDULER_NO_TASK;
    n->expect_latency_response = GNUNET_NO;
    GNUNET_STATISTICS_update (GST_stats, gettext_noop ("# peers connected"), -1,
                              GNUNET_NO);
    disconnect_notify_cb (callback_cls, &n->id);
    break;
  case S_FAST_RECONNECT:
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop ("# fast reconnects failed"), 1,
                              GNUNET_NO);
    disconnect_notify_cb (callback_cls, &n->id);
    break;
  default:
    break;
  }

  GNUNET_ATS_suggest_address_cancel (GST_ats, &n->id);

  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (neighbours,
                                                       &n->id.hashPubKey, n));
  if (GNUNET_SCHEDULER_NO_TASK != n->ats_suggest)
  {
    GNUNET_SCHEDULER_cancel (n->ats_suggest);
    n->ats_suggest = GNUNET_SCHEDULER_NO_TASK;
  }
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
  if (NULL != n->address)
  {
    GNUNET_HELLO_address_free (n->address);
    n->address = NULL;
  }
  n->session = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Deleting peer `%4s', %X\n",
              GNUNET_i2s (&n->id), n);
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

  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop
                            ("# peers disconnected due to timeout"), 1,
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
  int ret;

  GNUNET_assert (S_CONNECTED == n->state);
  n->keepalive_task =
      GNUNET_SCHEDULER_add_delayed (KEEPALIVE_FREQUENCY,
                                    &neighbour_keepalive_task, n);

  GNUNET_STATISTICS_update (GST_stats, gettext_noop ("# keepalives sent"), 1,
                            GNUNET_NO);
  m.size = htons (sizeof (struct GNUNET_MessageHeader));
  m.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_KEEPALIVE);

  ret = send_with_session (n,
            (const void *) &m, sizeof (m),
            UINT32_MAX /* priority */ ,
            GNUNET_TIME_UNIT_FOREVER_REL,
            NULL, NULL);

  n->expect_latency_response = GNUNET_NO;
  n->keep_alive_sent = GNUNET_TIME_absolute_get_zero ();
  if (ret != GNUNET_SYSERR)
  {
    n->expect_latency_response = GNUNET_YES;
    n->keep_alive_sent = GNUNET_TIME_absolute_get ();
  }

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
  if (S_CONNECTED == n->state)
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# peers disconnected due to global disconnect"),
                              1, GNUNET_NO);
  disconnect_neighbour (n);
  return GNUNET_OK;
}


static void
ats_suggest_cancel (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct NeighbourMapEntry *n = cls;

  n->ats_suggest = GNUNET_SCHEDULER_NO_TASK;

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "ATS did not suggested address to connect to peer `%s'\n",
              GNUNET_i2s (&n->id));

  disconnect_neighbour (n);
}

/**
 * Cleanup the neighbours subsystem.
 */
void
GST_neighbours_stop ()
{
  // This can happen during shutdown
  if (neighbours == NULL)
  {
    return;
  }

  GNUNET_CONTAINER_multihashmap_iterate (neighbours, &disconnect_all_neighbours,
                                         NULL);
  GNUNET_CONTAINER_multihashmap_destroy (neighbours);
//  GNUNET_assert (neighbours_connected == 0);
  neighbours = NULL;
  callback_cls = NULL;
  connect_notify_cb = NULL;
  disconnect_notify_cb = NULL;
  address_change_cb = NULL;
}

struct ContinutionContext
{
  struct GNUNET_HELLO_Address *address;

  struct Session *session;
};

static void
send_outbound_quota (const struct GNUNET_PeerIdentity *target,
                     struct GNUNET_BANDWIDTH_Value32NBO quota)
{
  struct QuotaSetMessage q_msg;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending outbound quota of %u Bps for peer `%s' to all clients\n",
              ntohl (quota.value__), GNUNET_i2s (target));
#endif
  q_msg.header.size = htons (sizeof (struct QuotaSetMessage));
  q_msg.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SET_QUOTA);
  q_msg.quota = quota;
  q_msg.peer = (*target);
  GST_clients_broadcast (&q_msg.header, GNUNET_NO);
}

/**
 * We tried to send a SESSION_CONNECT message to another peer.  If this
 * succeeded, we change the state.  If it failed, we should tell
 * ATS to not use this address anymore (until it is re-validated).
 *
 * @param cls the 'struct GNUNET_HELLO_Address' of the address that was tried
 * @param target peer to send the message to
 * @param success GNUNET_OK on success
 */
static void
send_connect_continuation (void *cls, const struct GNUNET_PeerIdentity *target,
                           int success)
{
  struct ContinutionContext *cc = cls;
  struct NeighbourMapEntry *n = lookup_neighbour (&cc->address->peer);

  if (GNUNET_YES != success)
  {
    GNUNET_assert (strlen (cc->address->transport_name) > 0);
    GNUNET_ATS_address_destroyed (GST_ats, cc->address, cc->session);
  }
  if ((NULL == neighbours) || (NULL == n) || (n->state == S_DISCONNECT))
  {
    GNUNET_HELLO_address_free (cc->address);
    GNUNET_free (cc);
    return;
  }

  if ((GNUNET_YES == success) &&
      ((n->state == S_NOT_CONNECTED) || (n->state == S_CONNECT_SENT)))
  {
    change_state (n, S_CONNECT_SENT);
    GNUNET_HELLO_address_free (cc->address);
    GNUNET_free (cc);
    return;
  }

  if ((GNUNET_NO == success) &&
      ((n->state == S_NOT_CONNECTED) || (n->state == S_CONNECT_SENT)))
  {
#if DEBUG_TRANSPORT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Failed to send CONNECT_MSG to peer `%4s' with address '%s' session %p, asking ATS for new address \n",
                GNUNET_i2s (&n->id), GST_plugins_a2s (n->address), n->session);
#endif
    change_state (n, S_NOT_CONNECTED);
    if (n->ats_suggest != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (n->ats_suggest);
    n->ats_suggest =
        GNUNET_SCHEDULER_add_delayed (ATS_RESPONSE_TIMEOUT, &ats_suggest_cancel,
                                      n);
    GNUNET_ATS_suggest_address (GST_ats, &n->id);
  }
  GNUNET_HELLO_address_free (cc->address);
  GNUNET_free (cc);
}


/**
 * We tried to switch addresses with an peer already connected. If it failed,
 * we should tell ATS to not use this address anymore (until it is re-validated).
 *
 * @param cls the 'struct NeighbourMapEntry'
 * @param target peer to send the message to
 * @param success GNUNET_OK on success
 */
static void
send_switch_address_continuation (void *cls,
                                  const struct GNUNET_PeerIdentity *target,
                                  int success)
{
  struct ContinutionContext *cc = cls;
  struct NeighbourMapEntry *n;

  if (neighbours == NULL)
  {
    GNUNET_HELLO_address_free (cc->address);
    GNUNET_free (cc);
    return;                     /* neighbour is going away */
  }

  n = lookup_neighbour (&cc->address->peer);
  if ((n == NULL) || (is_disconnecting (n)))
  {
    GNUNET_HELLO_address_free (cc->address);
    GNUNET_free (cc);
    return;                     /* neighbour is going away */
  }

  GNUNET_assert ((n->state == S_CONNECTED) || (n->state == S_FAST_RECONNECT));
  if (GNUNET_YES != success)
  {
#if DEBUG_TRANSPORT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Failed to switch connected peer `%s' to address '%s' session %X, asking ATS for new address \n",
                GNUNET_i2s (&n->id), GST_plugins_a2s (cc->address), cc->session);
#endif
    GNUNET_assert (strlen (cc->address->transport_name) > 0);
    GNUNET_ATS_address_destroyed (GST_ats, cc->address, cc->session);

    if (n->ats_suggest != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (n->ats_suggest);
    n->ats_suggest =
        GNUNET_SCHEDULER_add_delayed (ATS_RESPONSE_TIMEOUT, ats_suggest_cancel,
                                      n);
    GNUNET_ATS_suggest_address (GST_ats, &n->id);
    GNUNET_HELLO_address_free (cc->address);
    GNUNET_free (cc);
    return;
  }
  /* Tell ATS that switching addresses was successful */
  switch (n->state)
  {
  case S_CONNECTED:
    if (n->address_state == FRESH)
    {
      GST_validation_set_address_use (cc->address, cc->session, GNUNET_YES);
      GNUNET_ATS_address_update (GST_ats, cc->address, cc->session, NULL, 0);
      if (cc->session != n->session)
        GNUNET_break (0);
      GNUNET_ATS_address_in_use (GST_ats, cc->address, cc->session, GNUNET_YES);
      n->address_state = USED;
    }
    break;
  case S_FAST_RECONNECT:
#if DEBUG_TRANSPORT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Successful fast reconnect to peer `%s'\n",
                GNUNET_i2s (&n->id));
#endif
    change_state (n, S_CONNECTED);
    neighbours_connected++;
    GNUNET_STATISTICS_update (GST_stats, gettext_noop ("# peers connected"), 1,
                              GNUNET_NO);

    if (n->address_state == FRESH)
    {
      GST_validation_set_address_use (cc->address, cc->session, GNUNET_YES);
      GNUNET_ATS_address_update (GST_ats, cc->address, cc->session, NULL, 0);
      GNUNET_ATS_address_in_use (GST_ats, cc->address, cc->session, GNUNET_YES);
      n->address_state = USED;
    }

    if (n->keepalive_task == GNUNET_SCHEDULER_NO_TASK)
      n->keepalive_task =
          GNUNET_SCHEDULER_add_now (&neighbour_keepalive_task, n);

    /* Updating quotas */
    GST_neighbours_set_incoming_quota (&n->id, n->bandwidth_in);
    send_outbound_quota (target, n->bandwidth_out);

  default:
    break;
  }
  GNUNET_HELLO_address_free (cc->address);
  GNUNET_free (cc);
}


/**
 * We tried to send a SESSION_CONNECT message to another peer.  If this
 * succeeded, we change the state.  If it failed, we should tell
 * ATS to not use this address anymore (until it is re-validated).
 *
 * @param cls the 'struct NeighbourMapEntry'
 * @param target peer to send the message to
 * @param success GNUNET_OK on success
 */
static void
send_connect_ack_continuation (void *cls,
                               const struct GNUNET_PeerIdentity *target,
                               int success)
{
  struct ContinutionContext *cc = cls;
  struct NeighbourMapEntry *n;

  if (neighbours == NULL)
  {
    GNUNET_HELLO_address_free (cc->address);
    GNUNET_free (cc);
    return;                     /* neighbour is going away */
  }

  n = lookup_neighbour (&cc->address->peer);
  if ((n == NULL) || (is_disconnecting (n)))
  {
    GNUNET_HELLO_address_free (cc->address);
    GNUNET_free (cc);
    return;                     /* neighbour is going away */
  }

  if (GNUNET_YES == success)
  {
    GNUNET_HELLO_address_free (cc->address);
    GNUNET_free (cc);
    return;                     /* sending successful */
  }

  /* sending failed, ask for next address  */
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Failed to send CONNECT_MSG to peer `%4s' with address '%s' session %X, asking ATS for new address \n",
              GNUNET_i2s (&n->id), GST_plugins_a2s (n->address), n->session);
#endif
  change_state (n, S_NOT_CONNECTED);
  GNUNET_assert (strlen (cc->address->transport_name) > 0);
  GNUNET_ATS_address_destroyed (GST_ats, cc->address, cc->session);

  if (n->ats_suggest != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (n->ats_suggest);
  n->ats_suggest =
      GNUNET_SCHEDULER_add_delayed (ATS_RESPONSE_TIMEOUT, ats_suggest_cancel,
                                    n);
  GNUNET_ATS_suggest_address (GST_ats, &n->id);
  GNUNET_HELLO_address_free (cc->address);
  GNUNET_free (cc);
}


/**
 * For an existing neighbour record, set the active connection to
 * use the given address.
 *
 * @param peer identity of the peer to switch the address for
 * @param address address of the other peer, NULL if other peer
 *                       connected to us
 * @param session session to use (or NULL)
 * @param ats performance data
 * @param ats_count number of entries in ats
 * @param bandwidth_in inbound quota to be used when connection is up
 * @param bandwidth_out outbound quota to be used when connection is up
 * @return GNUNET_YES if we are currently connected, GNUNET_NO if the
 *         connection is not up (yet)
 */
int
GST_neighbours_switch_to_address (const struct GNUNET_PeerIdentity *peer,
                                       const struct GNUNET_HELLO_Address
                                       *address,
                                       struct Session *session,
                                       const struct GNUNET_ATS_Information *ats,
                                       uint32_t ats_count,
                                       struct GNUNET_BANDWIDTH_Value32NBO
                                       bandwidth_in,
                                       struct GNUNET_BANDWIDTH_Value32NBO
                                       bandwidth_out)
{
  struct NeighbourMapEntry *n;
  struct SessionConnectMessage connect_msg;
  struct ContinutionContext *cc;
  size_t msg_len;
  size_t ret;

  if (neighbours == NULL)
  {
    /* This can happen during shutdown */
    return GNUNET_NO;
  }
  n = lookup_neighbour (peer);
  if (NULL == n)
    return GNUNET_NO;
  if (n->state == S_DISCONNECT)
  {
    /* We are disconnecting, nothing to do here */
    return GNUNET_NO;
  }
  GNUNET_assert (address->transport_name != NULL);
  if ((session == NULL) && (0 == address->address_length))
  {
    GNUNET_break_op (0);
    /* FIXME: is this actually possible? When does this happen? */
    if (strlen (address->transport_name) > 0)
      GNUNET_ATS_address_destroyed (GST_ats, address, session);
    GNUNET_ATS_suggest_address (GST_ats, peer);
    return GNUNET_NO;
  }

  /* checks successful and neighbour != NULL */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "ATS tells us to switch to address '%s' session %p for peer `%s' in state `%s'\n",
              (address->address_length != 0) ? GST_plugins_a2s (address): "<inbound>",
              session,
              GNUNET_i2s (peer),
              print_state (n->state));

  if (n->ats_suggest != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (n->ats_suggest);
    n->ats_suggest = GNUNET_SCHEDULER_NO_TASK;
  }
  /* do not switch addresses just update quotas */
/*
  if (n->state == S_FAST_RECONNECT)
  {
    if (0 == GNUNET_HELLO_address_cmp(address, n->address))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "FAST RECONNECT to peer `%s' and  address '%s' with identical ADDRESS\n",
                  GNUNET_i2s (&n->id), GST_plugins_a2s (n->address));
    }
  }
*/
  if ((n->state == S_CONNECTED) && (NULL != n->address) &&
      (0 == GNUNET_HELLO_address_cmp (address, n->address)) &&
      (n->session == session))
  {
    n->bandwidth_in = bandwidth_in;
    n->bandwidth_out = bandwidth_out;
    GST_neighbours_set_incoming_quota (&n->id, n->bandwidth_in);
    send_outbound_quota (peer, n->bandwidth_out);
    return GNUNET_NO;
  }
  if (n->state == S_CONNECTED)
  {
    /* mark old address as no longer used */
    GNUNET_assert (NULL != n->address);
    if (n->address_state == USED)
    {
      GST_validation_set_address_use (n->address, n->session, GNUNET_NO);
      GNUNET_ATS_address_in_use (GST_ats, n->address, n->session, GNUNET_NO);
      n->address_state = UNUSED;
    }
  }

  /* set new address */
  if (NULL != n->address)
    GNUNET_HELLO_address_free (n->address);
  n->address = GNUNET_HELLO_address_copy (address);
  n->address_state = FRESH;
  n->bandwidth_in = bandwidth_in;
  n->bandwidth_out = bandwidth_out;
  GNUNET_SCHEDULER_cancel (n->timeout_task);
  n->timeout_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                                    &neighbour_timeout_task, n);

  if (NULL != address_change_cb && n->state == S_CONNECTED)
    address_change_cb (callback_cls, &n->id, n->address); 

  /* Obtain an session for this address from plugin */
  struct GNUNET_TRANSPORT_PluginFunctions *papi;
  papi = GST_plugins_find (address->transport_name);

  if (papi == NULL)
  {
    /* we don't have the plugin for this address */
    GNUNET_ATS_address_destroyed (GST_ats, n->address, NULL);

    if (n->ats_suggest != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (n->ats_suggest);
    n->ats_suggest =  GNUNET_SCHEDULER_add_delayed (ATS_RESPONSE_TIMEOUT,
                                      ats_suggest_cancel,
                                      n);
    GNUNET_ATS_suggest_address (GST_ats, &n->id);
    GNUNET_HELLO_address_free (n->address);
    n->address = NULL;
    n->session = NULL;
    return GNUNET_NO;
  }

  if (session == NULL)
  {
    n->session = papi->get_session (papi->cls, address);
    /* Session could not be initiated */
    if (n->session == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Failed to obtain new session %p for peer `%s' and  address '%s'\n",
                  n->session, GNUNET_i2s (&n->id), GST_plugins_a2s (n->address));

      GNUNET_ATS_address_destroyed (GST_ats, n->address, NULL);

      if (n->ats_suggest != GNUNET_SCHEDULER_NO_TASK)
        GNUNET_SCHEDULER_cancel (n->ats_suggest);
      n->ats_suggest =  GNUNET_SCHEDULER_add_delayed (ATS_RESPONSE_TIMEOUT,
                                        ats_suggest_cancel,
                                        n);
      GNUNET_ATS_suggest_address (GST_ats, &n->id);
      GNUNET_HELLO_address_free (n->address);
      n->address = NULL;
      n->session = NULL;
      return GNUNET_NO;
    }

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Obtained new session %p for peer `%s' and  address '%s'\n",
                 n->session, GNUNET_i2s (&n->id), GST_plugins_a2s (n->address));
    /* Telling ATS about new session */
    GNUNET_ATS_address_update (GST_ats, n->address, n->session, NULL, 0);
  }
  else
  {
    n->session = session;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Using existing session %p for peer `%s' and  address '%s'\n",
                n->session,
                GNUNET_i2s (&n->id),
                (address->address_length != 0) ? GST_plugins_a2s (address): "<inbound>");
  }

  switch (n->state)
  {
  case S_NOT_CONNECTED:
  case S_CONNECT_SENT:
    msg_len = sizeof (struct SessionConnectMessage);
    connect_msg.header.size = htons (msg_len);
    connect_msg.header.type =
        htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_CONNECT);
    connect_msg.reserved = htonl (0);
    connect_msg.timestamp =
        GNUNET_TIME_absolute_hton (GNUNET_TIME_absolute_get ());

    cc = GNUNET_malloc (sizeof (struct ContinutionContext));
    cc->session = n->session;
    cc->address = GNUNET_HELLO_address_copy (address);

    ret = send_with_session (n,
      (const char *) &connect_msg, msg_len,
      UINT32_MAX, GNUNET_TIME_UNIT_FOREVER_REL,
      &send_connect_continuation, cc);

    return GNUNET_NO;
  case S_CONNECT_RECV:
    /* We received a CONNECT message and asked ATS for an address */
    msg_len = sizeof (struct SessionConnectMessage);
    connect_msg.header.size = htons (msg_len);
    connect_msg.header.type =
        htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_CONNECT_ACK);
    connect_msg.reserved = htonl (0);
    connect_msg.timestamp =
        GNUNET_TIME_absolute_hton (GNUNET_TIME_absolute_get ());
    cc = GNUNET_malloc (sizeof (struct ContinutionContext));
    cc->session = n->session;
    cc->address = GNUNET_HELLO_address_copy (address);

    ret = send_with_session(n,
                            (const void *) &connect_msg, msg_len,
                            UINT32_MAX, GNUNET_TIME_UNIT_FOREVER_REL,
                            &send_connect_ack_continuation,
                            cc);
    return GNUNET_NO;
  case S_CONNECTED:
  case S_FAST_RECONNECT:
    /* connected peer is switching addresses or tries fast reconnect */
    msg_len = sizeof (struct SessionConnectMessage);
    connect_msg.header.size = htons (msg_len);
    connect_msg.header.type =
        htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_CONNECT);
    connect_msg.reserved = htonl (0);
    connect_msg.timestamp =
        GNUNET_TIME_absolute_hton (GNUNET_TIME_absolute_get ());
    cc = GNUNET_malloc (sizeof (struct ContinutionContext));
    cc->session = n->session;
    cc->address = GNUNET_HELLO_address_copy (address);
    ret = send_with_session(n,
                            (const void *) &connect_msg, msg_len,
                            UINT32_MAX, GNUNET_TIME_UNIT_FOREVER_REL,
                            &send_switch_address_continuation, cc);
    if (ret == GNUNET_SYSERR)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Failed to send CONNECT_MESSAGE to `%4s' using address '%s' session %X\n",
                  GNUNET_i2s (peer), GST_plugins_a2s (address), session);
    }
    return GNUNET_NO;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Invalid connection state to switch addresses %u \n", n->state);
    GNUNET_break_op (0);
    return GNUNET_NO;
  }
}


/**
 * Obtain current latency information for the given neighbour.
 *
 * @param peer
 * @return observed latency of the address, FOREVER if the address was
 *         never successfully validated
 */
struct GNUNET_TIME_Relative
GST_neighbour_get_latency (const struct GNUNET_PeerIdentity *peer)
{
  struct NeighbourMapEntry *n;

  n = lookup_neighbour (peer);
  if ((NULL == n) || ((n->address == NULL) && (n->session == NULL)))
    return GNUNET_TIME_UNIT_FOREVER_REL;

  return n->latency;
}

/**
 * Obtain current address information for the given neighbour.
 *
 * @param peer
 * @return address currently used
 */
struct GNUNET_HELLO_Address *
GST_neighbour_get_current_address (const struct GNUNET_PeerIdentity *peer)
{
  struct NeighbourMapEntry *n;

  n = lookup_neighbour (peer);
  if ((NULL == n) || ((n->address == NULL) && (n->session == NULL)))
    return NULL;

  return n->address;
}



/**
 * Create an entry in the neighbour map for the given peer
 *
 * @param peer peer to create an entry for
 * @return new neighbour map entry
 */
static struct NeighbourMapEntry *
setup_neighbour (const struct GNUNET_PeerIdentity *peer)
{
  struct NeighbourMapEntry *n;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Unknown peer `%s', creating new neighbour\n", GNUNET_i2s (peer));
#endif
  n = GNUNET_malloc (sizeof (struct NeighbourMapEntry));
  n->id = *peer;
  n->state = S_NOT_CONNECTED;
  n->latency = GNUNET_TIME_relative_get_forever ();
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
  return n;
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

  // This can happen during shutdown
  if (neighbours == NULL)
  {
    return;
  }
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Trying to connect to peer `%s'\n",
              GNUNET_i2s (target));
#endif
  if (0 ==
      memcmp (target, &GST_my_identity, sizeof (struct GNUNET_PeerIdentity)))
  {
    /* my own hello */
    return;
  }
  n = lookup_neighbour (target);

  if (NULL != n)
  {
    if ((S_CONNECTED == n->state) || (is_connecting (n)))
      return;                   /* already connecting or connected */
    if (is_disconnecting (n))
      change_state (n, S_NOT_CONNECTED);
  }


  if (n == NULL)
    n = setup_neighbour (target);
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Asking ATS for suggested address to connect to peer `%s'\n",
              GNUNET_i2s (&n->id));
#endif

  GNUNET_ATS_suggest_address (GST_ats, &n->id);
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

  // This can happen during shutdown
  if (neighbours == NULL)
  {
    return GNUNET_NO;
  }

  n = lookup_neighbour (target);

  if ((NULL == n) || (S_CONNECTED != n->state))
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

  if (neighbours == NULL)
  {
    /* This can happen during shutdown */
    return;
  }

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Session %X to peer `%s' ended \n",
              session, GNUNET_i2s (peer));
#endif

  n = lookup_neighbour (peer);
  if (NULL == n)
    return;
  if (session != n->session)
    return;                     /* doesn't affect us */
  if (n->state == S_CONNECTED)
  {
    if (n->address_state == USED)
    {
      GST_validation_set_address_use (n->address, n->session, GNUNET_NO);
      GNUNET_ATS_address_in_use (GST_ats, n->address, n->session, GNUNET_NO);
      n->address_state = UNUSED;
    }
  }

  if (NULL != n->address)
  {
    GNUNET_HELLO_address_free (n->address);
    n->address = NULL;
  }
  n->session = NULL;

  /* not connected anymore anyway, shouldn't matter */
  if (S_CONNECTED != n->state)
    return;

  if (n->keepalive_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (n->keepalive_task);
    n->keepalive_task = GNUNET_SCHEDULER_NO_TASK;
    n->expect_latency_response = GNUNET_NO;
  }

  /* connected, try fast reconnect */
  /* statistics "transport" : "# peers connected" -= 1
   * neighbours_connected -= 1
   * BUT: no disconnect_cb to notify clients about disconnect
   */

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Trying fast reconnect to peer `%s'\n",
              GNUNET_i2s (peer));

  GNUNET_assert (neighbours_connected > 0);
  change_state (n, S_FAST_RECONNECT);
  neighbours_connected--;
  GNUNET_STATISTICS_update (GST_stats, gettext_noop ("# peers connected"), -1,
                            GNUNET_NO);


  /* We are connected, so ask ATS to switch addresses */
  GNUNET_SCHEDULER_cancel (n->timeout_task);
  n->timeout_task = GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_DISCONNECT_SESSION_TIMEOUT,
                                    &neighbour_timeout_task, n);
  /* try QUICKLY to re-establish a connection, reduce timeout! */
  if (n->ats_suggest != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (n->ats_suggest);
  n->ats_suggest = GNUNET_SCHEDULER_add_delayed (ATS_RESPONSE_TIMEOUT,
                                    &ats_suggest_cancel,
                                    n);
  GNUNET_ATS_suggest_address (GST_ats, peer);
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

  // This can happen during shutdown
  if (neighbours == NULL)
  {
    return;
  }

  n = lookup_neighbour (target);
  if ((n == NULL) || (!is_connected (n)))
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# messages not sent (no such peer or not connected)"),
                              1, GNUNET_NO);
#if DEBUG_TRANSPORT
    if (n == NULL)
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Could not send message to peer `%s': unknown neighbour",
                  GNUNET_i2s (target));
    else if (!is_connected (n))
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Could not send message to peer `%s': not connected\n",
                  GNUNET_i2s (target));
#endif
    if (NULL != cont)
      cont (cont_cls, GNUNET_SYSERR);
    return;
  }

  if ((n->session == NULL) && (n->address == NULL))
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
 *                   GNUNET_NO if the neighbour is not connected or violates the quota,
 *                   GNUNET_SYSERR if the connection is not fully up yet
 * @return how long to wait before reading more from this sender
 */
struct GNUNET_TIME_Relative
GST_neighbours_calculate_receive_delay (const struct GNUNET_PeerIdentity
                                        *sender, ssize_t size, int *do_forward)
{
  struct NeighbourMapEntry *n;
  struct GNUNET_TIME_Relative ret;

  // This can happen during shutdown
  if (neighbours == NULL)
  {
    return GNUNET_TIME_UNIT_FOREVER_REL;
  }

  n = lookup_neighbour (sender);
  if (n == NULL)
  {
    GST_neighbours_try_connect (sender);
    n = lookup_neighbour (sender);
    if (NULL == n)
    {
      GNUNET_STATISTICS_update (GST_stats,
                                gettext_noop
                                ("# messages discarded due to lack of neighbour record"),
                                1, GNUNET_NO);
      *do_forward = GNUNET_NO;
      return GNUNET_TIME_UNIT_ZERO;
    }
  }
  if (!is_connected (n))
  {
    *do_forward = GNUNET_SYSERR;
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
  ret = GNUNET_BANDWIDTH_tracker_get_delay (&n->in_tracker, 32 * 1024);
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

  // This can happen during shutdown
  if (neighbours == NULL)
  {
    return;
  }

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

  /* send reply to measure latency */
  if (S_CONNECTED != n->state)
    return;

  struct GNUNET_MessageHeader m;

  m.size = htons (sizeof (struct GNUNET_MessageHeader));
  m.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_KEEPALIVE_RESPONSE);

  send_with_session(n,
      (const void *) &m, sizeof (m),
      UINT32_MAX,
      GNUNET_TIME_UNIT_FOREVER_REL,
      NULL, NULL);
}

/**
 * We received a KEEP_ALIVE_RESPONSE message and use this to calculate latency
 * to this peer
 *
 * @param neighbour neighbour to keep alive
 * @param ats performance data
 * @param ats_count number of entries in ats
 */
void
GST_neighbours_keepalive_response (const struct GNUNET_PeerIdentity *neighbour,
                                   const struct GNUNET_ATS_Information *ats,
                                   uint32_t ats_count)
{
  struct NeighbourMapEntry *n;
  struct GNUNET_ATS_Information *ats_new;
  uint32_t latency;

  if (neighbours == NULL)
  {
    // This can happen during shutdown
    return;
  }

  n = lookup_neighbour (neighbour);
  if ((NULL == n) || (n->state != S_CONNECTED))
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# KEEPALIVE_RESPONSE messages discarded (not connected)"),
                              1, GNUNET_NO);
    return;
  }
  if (n->expect_latency_response != GNUNET_YES)
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# KEEPALIVE_RESPONSE messages discarded (not expected)"),
                              1, GNUNET_NO);
    return;
  }
  n->expect_latency_response = GNUNET_NO;

  GNUNET_assert (n->keep_alive_sent.abs_value !=
                 GNUNET_TIME_absolute_get_zero ().abs_value);
  n->latency =
      GNUNET_TIME_absolute_get_difference (n->keep_alive_sent,
                                           GNUNET_TIME_absolute_get ());
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Latency for peer `%s' is %llu ms\n",
              GNUNET_i2s (&n->id), n->latency.rel_value);
#endif


  if (n->latency.rel_value == GNUNET_TIME_relative_get_forever ().rel_value)
  {
    GNUNET_ATS_address_update (GST_ats, n->address, n->session, ats, ats_count);
  }
  else
  {
    ats_new =
        GNUNET_malloc (sizeof (struct GNUNET_ATS_Information) *
                       (ats_count + 1));
    memcpy (ats_new, ats, sizeof (struct GNUNET_ATS_Information) * ats_count);

    /* add latency */
    ats_new[ats_count].type = htonl (GNUNET_ATS_QUALITY_NET_DELAY);
    if (n->latency.rel_value > UINT32_MAX)
      latency = UINT32_MAX;
    else
      latency = n->latency.rel_value;
    ats_new[ats_count].value = htonl (latency);

    GNUNET_ATS_address_update (GST_ats, n->address, n->session, ats_new,
                               ats_count + 1);
    GNUNET_free (ats_new);
  }
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

  // This can happen during shutdown
  if (neighbours == NULL)
  {
    return;
  }

  n = lookup_neighbour (neighbour);
  if (n == NULL)
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# SET QUOTA messages ignored (no such peer)"),
                              1, GNUNET_NO);
    return;
  }
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Setting inbound quota of %u Bps for peer `%s' to all clients\n",
              ntohl (quota.value__), GNUNET_i2s (&n->id));
#endif
  GNUNET_BANDWIDTH_tracker_update_quota (&n->in_tracker, quota);
  if (0 != ntohl (quota.value__))
    return;
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Disconnecting peer `%4s' due to `%s'\n",
              GNUNET_i2s (&n->id), "SET_QUOTA");
#endif
  if (is_connected (n))
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop ("# disconnects due to quota of 0"),
                              1, GNUNET_NO);
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

  if (!is_connected (n))
    return GNUNET_OK;

  ic->cb (ic->cb_cls, &n->id, NULL, 0, n->address);
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

  // This can happen during shutdown
  if (neighbours == NULL)
  {
    return;
  }

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

  // This can happen during shutdown
  if (neighbours == NULL)
  {
    return;
  }

  n = lookup_neighbour (target);
  if (NULL == n)
    return;                     /* not active */
  disconnect_neighbour (n);
}


/**
 * We received a disconnect message from the given peer,
 * validate and process.
 *
 * @param peer sender of the message
 * @param msg the disconnect message
 */
void
GST_neighbours_handle_disconnect_message (const struct GNUNET_PeerIdentity
                                          *peer,
                                          const struct GNUNET_MessageHeader
                                          *msg)
{
  struct NeighbourMapEntry *n;
  const struct SessionDisconnectMessage *sdm;
  GNUNET_HashCode hc;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received DISCONNECT message from peer `%s'\n",
              GNUNET_i2s (peer));
#endif

  if (ntohs (msg->size) != sizeof (struct SessionDisconnectMessage))
  {
    // GNUNET_break_op (0);
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# disconnect messages ignored (old format)"), 1,
                              GNUNET_NO);
    return;
  }
  sdm = (const struct SessionDisconnectMessage *) msg;
  n = lookup_neighbour (peer);
  if (NULL == n)
    return;                     /* gone already */
  if (GNUNET_TIME_absolute_ntoh (sdm->timestamp).abs_value <=
      n->connect_ts.abs_value)
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# disconnect messages ignored (timestamp)"), 1,
                              GNUNET_NO);
    return;
  }
  GNUNET_CRYPTO_hash (&sdm->public_key,
                      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                      &hc);
  if (0 != memcmp (peer, &hc, sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break_op (0);
    return;
  }
  if (ntohl (sdm->purpose.size) !=
      sizeof (struct GNUNET_CRYPTO_RsaSignaturePurpose) +
      sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded) +
      sizeof (struct GNUNET_TIME_AbsoluteNBO))
  {
    GNUNET_break_op (0);
    return;
  }
  if (GNUNET_OK !=
      GNUNET_CRYPTO_rsa_verify
      (GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_DISCONNECT, &sdm->purpose,
       &sdm->signature, &sdm->public_key))
  {
    GNUNET_break_op (0);
    return;
  }
  GST_neighbours_force_disconnect (peer);
}


/**
 * We received a 'SESSION_CONNECT_ACK' message from the other peer.
 * Consider switching to it.
 *
 * @param message possibly a 'struct SessionConnectMessage' (check format)
 * @param peer identity of the peer to switch the address for
 * @param address address of the other peer, NULL if other peer
 *                       connected to us
 * @param session session to use (or NULL)
 * @param ats performance data
 * @param ats_count number of entries in ats
 */
void
GST_neighbours_handle_connect_ack (const struct GNUNET_MessageHeader *message,
                                   const struct GNUNET_PeerIdentity *peer,
                                   const struct GNUNET_HELLO_Address *address,
                                   struct Session *session,
                                   const struct GNUNET_ATS_Information *ats,
                                   uint32_t ats_count)
{
  const struct SessionConnectMessage *scm;
  struct GNUNET_MessageHeader msg;
  struct NeighbourMapEntry *n;
  size_t msg_len;
  size_t ret;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received CONNECT_ACK message from peer `%s'\n",
              GNUNET_i2s (peer));

  if (ntohs (message->size) != sizeof (struct SessionConnectMessage))
  {
    GNUNET_break_op (0);
    return;
  }
  scm = (const struct SessionConnectMessage *) message;
  GNUNET_break_op (ntohl (scm->reserved) == 0);
  n = lookup_neighbour (peer);
  if (NULL == n)
  {
    /* we did not send 'CONNECT' -- at least not recently */
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# unexpected CONNECT_ACK messages (no peer)"),
                              1, GNUNET_NO);
    return;
  }

  /* Additional check
   *
   * ((n->state != S_CONNECT_RECV) && (n->address != NULL)):
   *
   * We also received an CONNECT message, switched from SENDT to RECV and
   * ATS already suggested us an address after a successful blacklist check
   */

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received CONNECT_ACK message from peer `%s' in state `%s'\n",
              GNUNET_i2s (peer),
              print_state(n->state));

  if ((n->address != NULL) && (n->state == S_CONNECTED))
  {
    /* After fast reconnect: send ACK (ACK) even when we are connected */
    msg_len = sizeof (msg);
    msg.size = htons (msg_len);
    msg.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_ACK);

    ret = send_with_session(n,
              (const char *) &msg, msg_len,
              UINT32_MAX, GNUNET_TIME_UNIT_FOREVER_REL,
              NULL, NULL);

    if (ret == GNUNET_SYSERR)
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Failed to send SESSION_ACK to `%4s' using address '%s' session %X\n",
                  GNUNET_i2s (&n->id), GST_plugins_a2s (n->address), n->session);
    return;
  }

  if ((n->state != S_CONNECT_SENT) &&
      ((n->state != S_CONNECT_RECV) && (n->address != NULL)))
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# unexpected CONNECT_ACK messages"), 1,
                              GNUNET_NO);
    return;
  }
  if (n->state != S_CONNECTED)
    change_state (n, S_CONNECTED);

  if (NULL != session)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
                     "transport-ats",
                     "Giving ATS session %p of plugin %s for peer %s\n",
                     session, address->transport_name, GNUNET_i2s (peer));
  }
  GNUNET_ATS_address_update (GST_ats, address, session, ats, ats_count);
  GNUNET_assert (NULL != n->address);

  if ((n->address_state == FRESH) && (0 == GNUNET_HELLO_address_cmp(address, n->address)))
  {
    GST_validation_set_address_use (n->address, n->session, GNUNET_YES);
    GNUNET_ATS_address_in_use (GST_ats, n->address, n->session, GNUNET_YES);
    n->address_state = USED;
  }

  GST_neighbours_set_incoming_quota (&n->id, n->bandwidth_in);

  /* send ACK (ACK) */
  msg_len = sizeof (msg);
  msg.size = htons (msg_len);
  msg.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_ACK);

  ret = send_with_session(n,
            (const char *) &msg, msg_len,
            UINT32_MAX, GNUNET_TIME_UNIT_FOREVER_REL,
            NULL, NULL);

  if (ret == GNUNET_SYSERR)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Failed to send SESSION_ACK to `%4s' using address '%s' session %X\n",
                GNUNET_i2s (&n->id), GST_plugins_a2s (n->address), n->session);


  if (n->keepalive_task == GNUNET_SCHEDULER_NO_TASK)
    n->keepalive_task = GNUNET_SCHEDULER_add_now (&neighbour_keepalive_task, n);

  neighbours_connected++;
  GNUNET_STATISTICS_update (GST_stats, gettext_noop ("# peers connected"), 1,
                            GNUNET_NO);
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Notify about connect of `%4s' using address '%s' session %X LINE %u\n",
              GNUNET_i2s (&n->id), GST_plugins_a2s (n->address), n->session,
              __LINE__);
#endif
  connect_notify_cb (callback_cls, &n->id, ats, ats_count);
  send_outbound_quota (peer, n->bandwidth_out);

}


void
GST_neighbours_handle_ack (const struct GNUNET_MessageHeader *message,
                           const struct GNUNET_PeerIdentity *peer,
                           const struct GNUNET_HELLO_Address *address,
                           struct Session *session,
                           const struct GNUNET_ATS_Information *ats,
                           uint32_t ats_count)
{
  struct NeighbourMapEntry *n;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received ACK message from peer `%s'\n",
              GNUNET_i2s (peer));
#endif

  if (ntohs (message->size) != sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break_op (0);
    return;
  }
  n = lookup_neighbour (peer);
  if (NULL == n)
  {
    GNUNET_break (0);
    return;
  }
  if (S_CONNECTED == n->state)
    return;
  if (!is_connecting (n))
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop ("# unexpected ACK messages"), 1,
                              GNUNET_NO);
    return;
  }
  change_state (n, S_CONNECTED);
  if (NULL != session)
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
                     "transport-ats",
                     "Giving ATS session %p of plugin %s for peer %s\n",
                     session, address->transport_name, GNUNET_i2s (peer));
  GNUNET_ATS_address_update (GST_ats, address, session, ats, ats_count);
  GNUNET_assert (n->address != NULL);

  if ((n->address_state == FRESH) && (0 == GNUNET_HELLO_address_cmp(address, n->address)))
  {
    GST_validation_set_address_use (n->address, n->session, GNUNET_YES);
    GNUNET_ATS_address_in_use (GST_ats, n->address, n->session, GNUNET_YES);
    n->address_state = USED;
  }


  neighbours_connected++;
  GNUNET_STATISTICS_update (GST_stats, gettext_noop ("# peers connected"), 1,
                            GNUNET_NO);

  GST_neighbours_set_incoming_quota (&n->id, n->bandwidth_in);
  if (n->keepalive_task == GNUNET_SCHEDULER_NO_TASK)
    n->keepalive_task = GNUNET_SCHEDULER_add_now (&neighbour_keepalive_task, n);
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Notify about connect of `%4s' using address '%s' session %X LINE %u\n",
              GNUNET_i2s (&n->id), GST_plugins_a2s (n->address), n->session,
              __LINE__);
#endif
  connect_notify_cb (callback_cls, &n->id, ats, ats_count);
  send_outbound_quota (peer, n->bandwidth_out);
}

struct BlackListCheckContext
{
  struct GNUNET_ATS_Information *ats;

  uint32_t ats_count;

  struct Session *session;

  struct GNUNET_HELLO_Address *address;

  struct GNUNET_TIME_Absolute ts;
};


static void
handle_connect_blacklist_cont (void *cls,
                               const struct GNUNET_PeerIdentity *peer,
                               int result)
{
  struct NeighbourMapEntry *n;
  struct BlackListCheckContext *bcc = cls;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Blacklist check due to CONNECT message: `%s'\n",
              GNUNET_i2s (peer),
              (result == GNUNET_OK) ? "ALLOWED" : "FORBIDDEN");
#endif

  /* not allowed */
  if (GNUNET_OK != result)
  {
    GNUNET_HELLO_address_free (bcc->address);
    GNUNET_free (bcc);
    return;
  }

  n = lookup_neighbour (peer);
  if (NULL == n)
    n = setup_neighbour (peer);

  if (bcc->ts.abs_value > n->connect_ts.abs_value)
  {
    if (NULL != bcc->session)
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
                       "transport-ats",
                       "Giving ATS session %p of address `%s' for peer %s\n",
                       bcc->session, GST_plugins_a2s (bcc->address),
                       GNUNET_i2s (peer));
    /* Tell ATS about the session, so ATS can suggest it if it likes it. */

    GNUNET_ATS_address_update (GST_ats, bcc->address, bcc->session, bcc->ats,
                               bcc->ats_count);
    n->connect_ts = bcc->ts;
  }

  GNUNET_HELLO_address_free (bcc->address);
  GNUNET_free (bcc);

  if (n->state != S_CONNECT_RECV)
    change_state (n, S_CONNECT_RECV);


  /* Ask ATS for an address to connect via that address */
  if (n->ats_suggest != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (n->ats_suggest);
  n->ats_suggest =
      GNUNET_SCHEDULER_add_delayed (ATS_RESPONSE_TIMEOUT, ats_suggest_cancel,
                                    n);
  GNUNET_ATS_suggest_address (GST_ats, peer);
}

/**
 * We received a 'SESSION_CONNECT' message from the other peer.
 * Consider switching to it.
 *
 * @param message possibly a 'struct SessionConnectMessage' (check format)
 * @param peer identity of the peer to switch the address for
 * @param address address of the other peer, NULL if other peer
 *                       connected to us
 * @param session session to use (or NULL)
 * @param ats performance data
 * @param ats_count number of entries in ats (excluding 0-termination)
 */
void
GST_neighbours_handle_connect (const struct GNUNET_MessageHeader *message,
                               const struct GNUNET_PeerIdentity *peer,
                               const struct GNUNET_HELLO_Address *address,
                               struct Session *session,
                               const struct GNUNET_ATS_Information *ats,
                               uint32_t ats_count)
{
  const struct SessionConnectMessage *scm;
  struct BlackListCheckContext *bcc = NULL;
  struct NeighbourMapEntry *n;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received CONNECT message from peer `%s'\n", GNUNET_i2s (peer));
#endif

  if (ntohs (message->size) != sizeof (struct SessionConnectMessage))
  {
    GNUNET_break_op (0);
    return;
  }

  scm = (const struct SessionConnectMessage *) message;
  GNUNET_break_op (ntohl (scm->reserved) == 0);

  GNUNET_ATS_address_update (GST_ats, address, session, ats, ats_count);

  n = lookup_neighbour (peer);
  if ((n != NULL) && ((S_CONNECTED == n->state) || (S_FAST_RECONNECT == n->state)))
  {
    /* connected peer switches addresses or is trying to do a fast reconnect*/
    return;
  }


  /* we are not connected to this peer */
  /* do blacklist check */
  bcc =
      GNUNET_malloc (sizeof (struct BlackListCheckContext) +
                     sizeof (struct GNUNET_ATS_Information) * (ats_count + 1));
  bcc->ts = GNUNET_TIME_absolute_ntoh (scm->timestamp);
  bcc->ats_count = ats_count + 1;
  bcc->address = GNUNET_HELLO_address_copy (address);
  bcc->session = session;
  bcc->ats = (struct GNUNET_ATS_Information *) &bcc[1];
  memcpy (bcc->ats, ats, sizeof (struct GNUNET_ATS_Information) * ats_count);
  bcc->ats[ats_count].type = htonl (GNUNET_ATS_QUALITY_NET_DELAY);
  bcc->ats[ats_count].value =
      htonl ((uint32_t) GST_neighbour_get_latency (peer).rel_value);
  GST_blacklist_test_allowed (peer, address->transport_name,
                              &handle_connect_blacklist_cont, bcc);
}


/* end of file gnunet-service-transport_neighbours.c */
