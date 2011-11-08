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
 * How often do we send KEEPALIVE messages to each of our neighbours?
 * (idle timeout is 5 minutes or 300 seconds, so with 90s interval we
 * send 3 keepalives in each interval, so 3 messages would need to be
 * lost in a row for a disconnect).
 */
#define KEEPALIVE_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 90)


#define ATS_RESPONSE_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 3)


#define SETUP_CONNECTION_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15)


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
  /* fresh peer or completely disconnected */
  S_NOT_CONNECTED = 0,
  /* sent CONNECT message to other peer, waiting for CONNECT_ACK */
  S_CONNECT_SENT = 1,
  /* received CONNECT message to other peer, sending CONNECT_ACK */
  S_CONNECT_RECV = 4,
  /* sent CONNECT_ACK message to other peer, wait for ACK or payload */
  S_CONNECT_RECV_ACK_SENT = 8,
  /* received ACK or payload */
  S_CONNECTED = 16,
  /* Disconnect in progress */
  S_DISCONNECT = 32
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
   * Performance data for the peer.
   */
  //struct GNUNET_ATS_Information *ats;

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
  case S_CONNECT_RECV_ACK_SENT:
    return "S_CONNECT_RECV_ACK_SENT";
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

  n->state_reset = GNUNET_SCHEDULER_NO_TASK;

#if DEBUG_TRANSPORT
#endif
  /* This jut a temporary debug message to check if a the value
   * SETUP_CONNECTION_TIMEOUT was choosen to small for slow machines
   */
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Information for developers: Connection to peer `%s' %s failed in state `%s', resetting connection attempt \n",
              GNUNET_i2s (&n->id), GST_plugins_a2s (n->plugin_name, n->addr,
                                                    n->addrlen),
              print_state (n->state));

  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop
                            ("# failed connection attempts due to timeout"), 1,
                            GNUNET_NO);

  /* resetting state */
  n->state = S_NOT_CONNECTED;

  /* destroying address */
  GNUNET_ATS_address_destroyed (GST_ats, &n->id, n->plugin_name, n->addr,
                                n->addrlen, NULL);

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
  char *old = strdup (print_state (n->state));
  char *new = strdup (print_state (state));

  /* allowed transitions */
  int allowed = GNUNET_NO;

  switch (n->state)
  {
  case S_NOT_CONNECTED:
    if ((state == S_CONNECT_RECV) || (state == S_CONNECT_SENT) ||
        (state == S_DISCONNECT))
    {
      allowed = GNUNET_YES;

      /* Schedule reset task */
      if ((state == S_CONNECT_RECV) || (state == S_CONNECT_SENT))
      {
        GNUNET_assert (n->state_reset == GNUNET_SCHEDULER_NO_TASK);
        n->state_reset =
            GNUNET_SCHEDULER_add_delayed (SETUP_CONNECTION_TIMEOUT, &reset_task,
                                          n);
      }
      break;
    }
    break;
  case S_CONNECT_RECV:
    if ((state == S_NOT_CONNECTED) || (state == S_DISCONNECT) ||
        (state == S_CONNECTED) ||
        /* FIXME SENT -> RECV ISSUE! */ (state == S_CONNECT_SENT))
    {
      if ((state == S_CONNECTED) || (state == S_DISCONNECT) ||
          (state == S_NOT_CONNECTED))
      {
#if DEBUG_TRANSPORT
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Removed reset task for peer `%s' %s failed in state transition `%s' -> `%s' \n",
                    GNUNET_i2s (&n->id), GST_plugins_a2s (n->plugin_name,
                                                          n->addr, n->addrlen),
                    print_state (n->state), print_state (state));
#endif
        GNUNET_assert (n->state_reset != GNUNET_SCHEDULER_NO_TASK);
        GNUNET_SCHEDULER_cancel (n->state_reset);
        n->state_reset = GNUNET_SCHEDULER_NO_TASK;
      }

      allowed = GNUNET_YES;
      break;
    }
    break;
  case S_CONNECT_SENT:
    if ((state == S_NOT_CONNECTED) || (state == S_CONNECTED) ||
        (state == S_DISCONNECT) ||
        /* FIXME SENT -> RECV ISSUE! */ (state == S_CONNECT_RECV))
    {
      if ((state == S_CONNECTED) || (state == S_DISCONNECT) ||
          (state == S_NOT_CONNECTED))
      {
#if DEBUG_TRANSPORT
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Removed reset task for peer `%s' %s failed in state transition `%s' -> `%s' \n",
                    GNUNET_i2s (&n->id), GST_plugins_a2s (n->plugin_name,
                                                          n->addr, n->addrlen),
                    print_state (n->state), print_state (state));
#endif
        GNUNET_assert (n->state_reset != GNUNET_SCHEDULER_NO_TASK);
        GNUNET_SCHEDULER_cancel (n->state_reset);
        n->state_reset = GNUNET_SCHEDULER_NO_TASK;
      }

      allowed = GNUNET_YES;
      break;
    }
    break;
  case S_CONNECTED:
    if (state == S_DISCONNECT)
    {
      allowed = GNUNET_YES;
      break;
    }
    break;
  case S_DISCONNECT:
    /*
     * if (state == S_NOT_CONNECTED)
     * {
     * allowed = GNUNET_YES;
     * break;
     * } */
    break;
  default:
    GNUNET_break (0);
    break;

  }

  if (allowed == GNUNET_NO)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Illegal state transition from `%s' to `%s' in line %u \n", old,
                new, line);
    GNUNET_break (0);
    GNUNET_free (old);
    GNUNET_free (new);
    return GNUNET_SYSERR;
  }

  n->state = state;
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "State for neighbour `%s' %X changed from `%s' to `%s' in line %u\n",
              GNUNET_i2s (&n->id), n, old, new, line);
#endif
  GNUNET_free (old);
  GNUNET_free (new);
  return GNUNET_OK;
}

static ssize_t
send_with_plugin (const struct GNUNET_PeerIdentity *target, const char *msgbuf,
                  size_t msgbuf_size, uint32_t priority,
                  struct GNUNET_TIME_Relative timeout, struct Session *session,
                  const char *plugin_name, const void *addr, size_t addrlen,
                  int force_address, GNUNET_TRANSPORT_TransmitContinuation cont,
                  void *cont_cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *papi;
  size_t ret = GNUNET_SYSERR;

  /* FIXME : ats returns an address with all values 0 */
  if (plugin_name == NULL)
  {
    if (cont != NULL)
      cont (cont_cls, target, GNUNET_SYSERR);
    return GNUNET_SYSERR;
  }

  if ((session == NULL) && (addr == NULL) && (addrlen == 0))
  {
    if (cont != NULL)
      cont (cont_cls, target, GNUNET_SYSERR);
    return GNUNET_SYSERR;
  }

  papi = GST_plugins_find (plugin_name);
  if (papi == NULL)
  {
    if (cont != NULL)
      cont (cont_cls, target, GNUNET_SYSERR);
    return GNUNET_SYSERR;
  }

  ret =
      papi->send (papi->cls, target, msgbuf, msgbuf_size, 0, timeout, session,
                  addr, addrlen, GNUNET_YES, cont, cont_cls);

  if (ret == -1)
  {
    if (cont != NULL)
      cont (cont_cls, target, GNUNET_SYSERR);
  }
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
  struct MessageQueue *mq;
  struct NeighbourMapEntry *n;

  mq = cls;
  n = mq->n;
  if (NULL != n)
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

  if (GST_plugins_find (n->plugin_name) == NULL)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_CONTAINER_DLL_remove (n->messages_head, n->messages_tail, mq);
  n->is_active = mq;
  mq->n = n;

  if ((n->session == NULL) && (n->addr == NULL) && (n->addrlen == 0))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "No address for peer `%s'\n",
                GNUNET_i2s (&n->id));
    transmit_send_continuation (mq, &n->id, GNUNET_SYSERR);
    GNUNET_assert (n->transmission_task == GNUNET_SCHEDULER_NO_TASK);
    n->transmission_task = GNUNET_SCHEDULER_add_now (&transmission_task, n);
    return;
  }

  ret =
      send_with_plugin (&n->id, mq->message_buf, mq->message_buf_size, 0,
                        timeout, n->session, n->plugin_name, n->addr,
                        n->addrlen, GNUNET_YES, &transmit_send_continuation,
                        mq);
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
send_disconnect (const struct GNUNET_PeerIdentity *target,
                 const char *plugin_name, const char *sender_address,
                 uint16_t sender_address_len, struct Session *session)
{
  size_t ret;
  struct SessionDisconnectMessage disconnect_msg;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending DISCONNECT message to peer `%4s'\n",
              GNUNET_i2s (target));
#endif

  disconnect_msg.header.size = htons (sizeof (struct SessionDisconnectMessage));
  disconnect_msg.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_DISCONNECT);
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

  ret =
      send_with_plugin (target, (const char *) &disconnect_msg,
                        sizeof (disconnect_msg), UINT32_MAX,
                        GNUNET_TIME_UNIT_FOREVER_REL, session, plugin_name,
                        sender_address, sender_address_len, GNUNET_YES,
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
  int was_connected = is_connected (n);

  /* send DISCONNECT MESSAGE */
  if (is_connected (n) || is_connecting (n))
  {
    if (GNUNET_OK ==
        send_disconnect (&n->id, n->plugin_name, n->addr, n->addrlen,
                         n->session))
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sent DISCONNECT_MSG to `%s'\n",
                  GNUNET_i2s (&n->id));
    else
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Could not send DISCONNECT_MSG to `%s'\n",
                  GNUNET_i2s (&n->id));
  }

  if (is_connected(n))
  {
     GNUNET_ATS_address_in_use (GST_ats, &n->id, n->plugin_name,
         n->addr, n->addrlen, n->session, GNUNET_NO);
  }


  if (is_disconnecting (n))
    return;
  change_state (n, S_DISCONNECT);
  GST_validation_set_address_use (&n->id,
				  n->plugin_name,
				  n->session,
				  n->addr,
				  n->addrlen,
				  GNUNET_NO);

  if (n->plugin_name != NULL)
  {
    struct GNUNET_TRANSPORT_PluginFunctions *papi;
    papi = GST_plugins_find (n->plugin_name);
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
  if (was_connected)
  {
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

  n->keepalive_task =
      GNUNET_SCHEDULER_add_delayed (KEEPALIVE_FREQUENCY,
                                    &neighbour_keepalive_task, n);
  GNUNET_assert (is_connected (n));
  GNUNET_STATISTICS_update (GST_stats, gettext_noop ("# keepalives sent"), 1,
                            GNUNET_NO);
  m.size = htons (sizeof (struct GNUNET_MessageHeader));
  m.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_KEEPALIVE);

  send_with_plugin (&n->id, (const void *) &m, sizeof (m),
                    UINT32_MAX /* priority */ ,
                    GNUNET_TIME_UNIT_FOREVER_REL, n->session, n->plugin_name,
                    n->addr, n->addrlen, GNUNET_YES, NULL, NULL);
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
  if (is_connected (n))
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              " ATS did not suggested address to connect to peer `%s'\n",
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
  GNUNET_assert (neighbours_connected == 0);
  neighbours = NULL;
  callback_cls = NULL;
  connect_notify_cb = NULL;
  disconnect_notify_cb = NULL;
}


/**
 * We tried to send a SESSION_CONNECT message to another peer.  If this
 * succeeded, we change the state.  If it failed, we should tell
 * ATS to not use this address anymore (until it is re-validated).
 *
 * @param cls the 'struct NeighbourMapEntry'
 * @param success GNUNET_OK on success
 */
static void
send_connect_continuation (void *cls, const struct GNUNET_PeerIdentity *target,
                           int success)
{
  struct NeighbourMapEntry *n = cls;

  GNUNET_assert (n != NULL);
  GNUNET_assert (!is_connected (n));

  if (is_disconnecting (n))
    return;                     /* neighbour is going away */

  if (GNUNET_YES != success)
  {
#if DEBUG_TRANSPORT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Failed to send CONNECT_MSG to peer `%4s' with plugin `%s' address '%s' session %X, asking ATS for new address \n",
                GNUNET_i2s (&n->id), n->plugin_name,
                (n->addrlen ==
                 0) ? "<inbound>" : GST_plugins_a2s (n->plugin_name, n->addr,
                                                     n->addrlen), n->session);
#endif

    GNUNET_ATS_address_destroyed (GST_ats, &n->id, n->plugin_name, n->addr,
                                  n->addrlen, NULL);

    change_state (n, S_NOT_CONNECTED);

    if (n->ats_suggest != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (n->ats_suggest);
    n->ats_suggest =
        GNUNET_SCHEDULER_add_delayed (ATS_RESPONSE_TIMEOUT, ats_suggest_cancel,
                                      n);
    GNUNET_ATS_suggest_address (GST_ats, &n->id);
    return;
  }


}


/**
 * We tried to switch addresses with an peer already connected. If it failed,
 * we should tell ATS to not use this address anymore (until it is re-validated).
 *
 * @param cls the 'struct NeighbourMapEntry'
 * @param success GNUNET_OK on success
 */
static void
send_switch_address_continuation (void *cls,
                                  const struct GNUNET_PeerIdentity *target,
                                  int success)
{
  struct NeighbourMapEntry *n = cls;

  GNUNET_assert (n != NULL);
  if (is_disconnecting (n))
    return;                     /* neighbour is going away */

  GNUNET_assert (n->state == S_CONNECTED);
  if (GNUNET_YES != success)
  {
#if DEBUG_TRANSPORT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Failed to switch connected peer `%s' to plugin `%s' address '%s' session %X, asking ATS for new address \n",
                GNUNET_i2s (&n->id), n->plugin_name,
                (n->addrlen ==
                 0) ? "<inbound>" : GST_plugins_a2s (n->plugin_name, n->addr,
                                                     n->addrlen), n->session);
#endif

    GNUNET_ATS_address_destroyed (GST_ats, &n->id, n->plugin_name, n->addr,
                                  n->addrlen, NULL);

    if (n->ats_suggest != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (n->ats_suggest);
    n->ats_suggest =
        GNUNET_SCHEDULER_add_delayed (ATS_RESPONSE_TIMEOUT, ats_suggest_cancel,
                                      n);
    GNUNET_ATS_suggest_address (GST_ats, &n->id);
    return;
  }
  /* Tell ATS that switching addresses was successful */
  GNUNET_ATS_address_in_use (GST_ats, &n->id, n->plugin_name, n->addr,
                             n->addrlen, n->addr, GNUNET_YES);
}

/**
 * We tried to send a SESSION_CONNECT message to another peer.  If this
 * succeeded, we change the state.  If it failed, we should tell
 * ATS to not use this address anymore (until it is re-validated).
 *
 * @param cls the 'struct NeighbourMapEntry'
 * @param success GNUNET_OK on success
 */
static void
send_connect_ack_continuation (void *cls,
                               const struct GNUNET_PeerIdentity *target,
                               int success)
{
  struct NeighbourMapEntry *n = cls;

  GNUNET_assert (n != NULL);

  if (GNUNET_YES == success)
    return;                     /* sending successful */

  /* sending failed, ask for next address  */
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Failed to send CONNECT_MSG to peer `%4s' with plugin `%s' address '%s' session %X, asking ATS for new address \n",
              GNUNET_i2s (&n->id), n->plugin_name,
              (n->addrlen == 0) ? "<inbound>" : GST_plugins_a2s (n->plugin_name,
                                                                 n->addr,
                                                                 n->addrlen),
              n->session);
#endif
  change_state (n, S_NOT_CONNECTED);

  GNUNET_ATS_address_destroyed (GST_ats, &n->id, n->plugin_name, n->addr,
                                n->addrlen, NULL);

  if (n->ats_suggest != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (n->ats_suggest);
  n->ats_suggest =
      GNUNET_SCHEDULER_add_delayed (ATS_RESPONSE_TIMEOUT, ats_suggest_cancel,
                                    n);
  GNUNET_ATS_suggest_address (GST_ats, &n->id);
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
 * @param ats_count number of entries in ats
 * @return GNUNET_YES if we are currently connected, GNUNET_NO if the
 *         connection is not up (yet)
 */
int
GST_neighbours_switch_to_address_3way (const struct GNUNET_PeerIdentity *peer,
                                       const char *plugin_name,
                                       const void *address, size_t address_len,
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
  size_t msg_len;
  size_t ret;
  int checks_failed;

  // This can happen during shutdown
  if (neighbours == NULL)
  {
    return GNUNET_NO;
  }

  checks_failed = GNUNET_NO;

  if (plugin_name == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "ATS offered suggested us empty address: plugin NULL");
    GNUNET_break_op (0);
    checks_failed = GNUNET_YES;
  }
  if ((address == NULL) && (address_len == 0) && (session == NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "ATS offered suggested us empty address: address NULL & session NULL");
    GNUNET_break_op (0);
    checks_failed = GNUNET_YES;
  }

  n = lookup_neighbour (peer);
  if (NULL == n)
    checks_failed = GNUNET_YES;

  if (checks_failed == GNUNET_YES)
  {
    GNUNET_ATS_address_destroyed (GST_ats, peer, plugin_name, address,
                                  address_len, session);
    if (n != NULL)
      GNUNET_ATS_suggest_address (GST_ats, peer);
    return GNUNET_NO;
  }

  /* checks successful and neighbour != NULL */
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "ATS tells us to switch to plugin `%s' address '%s' session %X for %s peer `%s'\n",
              plugin_name,
              (address_len == 0) ? "<inbound>" : GST_plugins_a2s (plugin_name,
                                                                  address,
                                                                  address_len),
              session, (is_connected (n) ? "CONNECTED" : "NOT CONNECTED"),
              GNUNET_i2s (peer));
#endif

  if (n->ats_suggest != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (n->ats_suggest);
    n->ats_suggest = GNUNET_SCHEDULER_NO_TASK;
  }

  // do not switch addresses just update quotas
  if ((is_connected (n)) && (address_len == n->addrlen))
  {
    if ((0 == memcmp (address, n->addr, address_len)) &&
        (n->session == session))
    {
      struct QuotaSetMessage q_msg;

#if DEBUG_TRANSPORT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Sending outbound quota of %u Bps and inbound quota of %u Bps for peer `%s' to all clients\n",
                  ntohl (n->bandwidth_out.value__),
                  ntohl (n->bandwidth_in.value__), GNUNET_i2s (peer));
#endif

      n->bandwidth_in = bandwidth_in;
      n->bandwidth_out = bandwidth_out;
      GST_neighbours_set_incoming_quota (&n->id, n->bandwidth_in);

      q_msg.header.size = htons (sizeof (struct QuotaSetMessage));
      q_msg.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SET_QUOTA);
      q_msg.quota = n->bandwidth_out;
      q_msg.peer = (*peer);
      GST_clients_broadcast (&q_msg.header, GNUNET_NO);
      return GNUNET_NO;
    }
  }
  if (n->state == S_CONNECTED) 
    GST_validation_set_address_use (&n->id,
				    n->plugin_name,
				    n->session,
				    n->addr,
				    n->addrlen,
				    GNUNET_NO);
  /* This will be a connection switch, tell ATS about it */
  if (n->state == S_CONNECTED)
  {
    GNUNET_ATS_address_in_use (GST_ats, &n->id, n->plugin_name, n->addr,
                               n->addrlen, n->addr, GNUNET_NO);
  }

  /* set new address */
  GNUNET_free_non_null (n->addr);
  n->addr = GNUNET_malloc (address_len);
  memcpy (n->addr, address, address_len);
  n->bandwidth_in = bandwidth_in;
  n->bandwidth_out = bandwidth_out;
  n->addrlen = address_len;
  n->session = session;
  GNUNET_free_non_null (n->plugin_name);
  n->plugin_name = GNUNET_strdup (plugin_name);
  GNUNET_SCHEDULER_cancel (n->timeout_task);
  n->timeout_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                                    &neighbour_timeout_task, n);
  if (n->state == S_CONNECTED)
    GST_validation_set_address_use (&n->id,
				    n->plugin_name,
				    n->session,
				    n->addr,
				    n->addrlen,
				    GNUNET_YES);


  if (n->state == S_DISCONNECT)
  {
    /* We are disconnecting, nothing to do here */
    return GNUNET_NO;
  }
  /* We are not connected/connecting and initiate a fresh connect */
  if (n->state == S_NOT_CONNECTED)
  {
    msg_len = sizeof (struct SessionConnectMessage);
    connect_msg.header.size = htons (msg_len);
    connect_msg.header.type =
        htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_CONNECT);
    connect_msg.reserved = htonl (0);
    connect_msg.timestamp =
        GNUNET_TIME_absolute_hton (GNUNET_TIME_absolute_get ());

    change_state (n, S_CONNECT_SENT);

    ret =
        send_with_plugin (peer, (const char *) &connect_msg, msg_len,
                          UINT32_MAX, GNUNET_TIME_UNIT_FOREVER_REL, session,
                          plugin_name, address, address_len, GNUNET_YES,
                          &send_connect_continuation, n);


    return GNUNET_NO;
  }
  /* We received a CONNECT message and asked ATS for an address */
  else if (n->state == S_CONNECT_RECV)
  {
    msg_len = sizeof (struct SessionConnectMessage);
    connect_msg.header.size = htons (msg_len);
    connect_msg.header.type =
        htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_CONNECT_ACK);
    connect_msg.reserved = htonl (0);
    connect_msg.timestamp =
        GNUNET_TIME_absolute_hton (GNUNET_TIME_absolute_get ());

    ret =
        send_with_plugin (&n->id, (const void *) &connect_msg, msg_len,
                          UINT32_MAX, GNUNET_TIME_UNIT_FOREVER_REL, session,
                          plugin_name, address, address_len, GNUNET_YES,
                          &send_connect_ack_continuation, n);
    return GNUNET_NO;
  }
  /* connected peer is switching addresses */
  else if (n->state == S_CONNECTED)
  {
    msg_len = sizeof (struct SessionConnectMessage);
    connect_msg.header.size = htons (msg_len);
    connect_msg.header.type =
        htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_CONNECT);
    connect_msg.reserved = htonl (0);
    connect_msg.timestamp =
        GNUNET_TIME_absolute_hton (GNUNET_TIME_absolute_get ());

    ret =
        send_with_plugin (peer, (const char *) &connect_msg, msg_len,
                          UINT32_MAX, GNUNET_TIME_UNIT_FOREVER_REL, session,
                          plugin_name, address, address_len, GNUNET_YES,
                          &send_switch_address_continuation, n);
    if (ret == GNUNET_SYSERR)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Failed to send CONNECT_MESSAGE to `%4s' using plugin `%s' address '%s' session %X\n",
                  GNUNET_i2s (peer), plugin_name,
                  (address_len ==
                   0) ? "<inbound>" : GST_plugins_a2s (plugin_name, address,
                                                       address_len), session);
    }
    return GNUNET_NO;
  }
  else if (n->state == S_CONNECT_SENT)
  {
    return GNUNET_NO;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Invalid connection state to switch addresses %u \n", n->state);
  GNUNET_break_op (0);
  return GNUNET_NO;
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
  if (NULL == n)
    return GNUNET_TIME_UNIT_FOREVER_REL;
  return GST_validation_get_address_latency (peer,
					     n->plugin_name,
					     n->session,
					     n->addr,
					     n->addrlen);
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
    if ((is_connected (n)) || (is_connecting (n)))
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

  if ((NULL == n) || (!is_connected (n)))
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

  // This can happen during shutdown
  if (neighbours == NULL)
  {
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

  n->session = NULL;
  GNUNET_free (n->addr);
  n->addr = NULL;
  n->addrlen = 0;

  /* not connected anymore anyway, shouldn't matter */
  if ((!is_connected (n)) && (!is_connecting (n)))
    return;

  /* We are connected, so ask ATS to switch addresses */
  GNUNET_SCHEDULER_cancel (n->timeout_task);
  n->timeout_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_DISCONNECT_SESSION_TIMEOUT,
                                    &neighbour_timeout_task, n);
  /* try QUICKLY to re-establish a connection, reduce timeout! */
  if (n->ats_suggest != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (n->ats_suggest);
  n->ats_suggest =
      GNUNET_SCHEDULER_add_delayed (ATS_RESPONSE_TIMEOUT, ats_suggest_cancel,
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

  if ((n->session == NULL) && (n->addr == NULL) && (n->addrlen == 0))
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

  ic->cb (ic->cb_cls, &n->id, NULL, 0, n->plugin_name, n->addr, n->addrlen);
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
  if (is_connected (n))
  {
    send_disconnect (&n->id, n->plugin_name, n->addr, n->addrlen, n->session);

    n = lookup_neighbour (target);
    if (NULL == n)
      return;                   /* gone already */
  }
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
 * @param plugin_name name of transport that delivered the PONG
 * @param address address of the other peer, NULL if other peer
 *                       connected to us
 * @param address_len number of bytes in address
 * @param session session to use (or NULL)
 * @param ats performance data
 * @param ats_count number of entries in ats
  */
void
GST_neighbours_handle_connect_ack (const struct GNUNET_MessageHeader *message,
                                   const struct GNUNET_PeerIdentity *peer,
                                   const char *plugin_name,
                                   const char *sender_address,
                                   uint16_t sender_address_len,
                                   struct Session *session,
                                   const struct GNUNET_ATS_Information *ats,
                                   uint32_t ats_count)
{
  const struct SessionConnectMessage *scm;
  struct QuotaSetMessage q_msg;
  struct GNUNET_MessageHeader msg;
  struct NeighbourMapEntry *n;
  size_t msg_len;
  size_t ret;
  int was_connected;

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received CONNECT_ACK message from peer `%s'\n",
              GNUNET_i2s (peer));
#endif

  if (ntohs (message->size) != sizeof (struct SessionConnectMessage))
  {
    GNUNET_break_op (0);
    return;
  }

  scm = (const struct SessionConnectMessage *) message;
  GNUNET_break_op (ntohl (scm->reserved) == 0);
  n = lookup_neighbour (peer);
  if (NULL == n)
    n = setup_neighbour (peer);

  if (!is_connecting(n))
  {
    GNUNET_STATISTICS_update (GST_stats,
        gettext_noop ("# unexpected CONNECT_ACK messages"), 1,
        GNUNET_NO);
    return;
  }

  if (NULL != session)
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
                     "transport-ats",
                     "Giving ATS session %p of plugin %s for peer %s\n",
                     session, plugin_name, GNUNET_i2s (peer));
  GNUNET_ATS_address_update (GST_ats, peer, plugin_name, sender_address,
                             sender_address_len, session, ats, ats_count);

  was_connected = is_connected (n);
  if (!is_connected (n))
  {
    change_state (n, S_CONNECTED);
    GST_validation_set_address_use (&n->id,
				    n->plugin_name,
				    n->session,
				    n->addr,
				    n->addrlen,
				    GNUNET_YES);
  }

  GNUNET_ATS_address_in_use (GST_ats, &n->id, n->plugin_name, n->addr,
                             n->addrlen, n->addr, GNUNET_YES);

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Setting inbound quota of %u for peer `%s' to \n",
              ntohl (n->bandwidth_in.value__), GNUNET_i2s (&n->id));
#endif
  GST_neighbours_set_incoming_quota (&n->id, n->bandwidth_in);

  /* send ACK (ACK) */
  msg_len = sizeof (msg);
  msg.size = htons (msg_len);
  msg.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_ACK);

  ret =
      send_with_plugin (&n->id, (const char *) &msg, msg_len, UINT32_MAX,
                        GNUNET_TIME_UNIT_FOREVER_REL, n->session,
                        n->plugin_name, n->addr, n->addrlen, GNUNET_YES, NULL,
                        NULL);

  if (ret == GNUNET_SYSERR)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Failed to send SESSION_ACK to `%4s' using plugin `%s' address '%s' session %X\n",
                GNUNET_i2s (&n->id), n->plugin_name,
                (n->addrlen ==
                 0) ? "<inbound>" : GST_plugins_a2s (n->plugin_name, n->addr,
                                                     n->addrlen), n->session);


  if (!was_connected)
  {
    if (n->keepalive_task == GNUNET_SCHEDULER_NO_TASK)
      n->keepalive_task =
          GNUNET_SCHEDULER_add_delayed (KEEPALIVE_FREQUENCY,
                                        &neighbour_keepalive_task, n);

    neighbours_connected++;
    GNUNET_STATISTICS_update (GST_stats, gettext_noop ("# peers connected"), 1,
                              GNUNET_NO);
#if DEBUG_TRANSPORT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Notify about connect of `%4s' using plugin `%s' address '%s' session %X LINE %u\n",
                GNUNET_i2s (&n->id), n->plugin_name,
                (n->addrlen ==
                 0) ? "<inbound>" : GST_plugins_a2s (n->plugin_name, n->addr,
                                                     n->addrlen), n->session,
                __LINE__);
#endif
    connect_notify_cb (callback_cls, &n->id, ats, ats_count);
  }

#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending outbound quota of %u Bps for peer `%s' to all clients\n",
              ntohl (n->bandwidth_out.value__), GNUNET_i2s (peer));
#endif
  q_msg.header.size = htons (sizeof (struct QuotaSetMessage));
  q_msg.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SET_QUOTA);
  q_msg.quota = n->bandwidth_out;
  q_msg.peer = (*peer);
  GST_clients_broadcast (&q_msg.header, GNUNET_NO);

}

void
GST_neighbours_handle_ack (const struct GNUNET_MessageHeader *message,
                           const struct GNUNET_PeerIdentity *peer,
                           const char *plugin_name, const char *sender_address,
                           uint16_t sender_address_len, struct Session *session,
                           const struct GNUNET_ATS_Information *ats,
                           uint32_t ats_count)
{
  struct NeighbourMapEntry *n;
  struct QuotaSetMessage q_msg;
  int was_connected;

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
    send_disconnect (peer, plugin_name, sender_address, sender_address_len,
                     session);
    GNUNET_break (0);
    return;
  }

  if (is_connected (n))
    return;

  if (!is_connecting(n))
  {
    GNUNET_STATISTICS_update (GST_stats, gettext_noop ("# unexpected ACK messages"), 1,
                              GNUNET_NO);
    return;
  }

  if (NULL != session)
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
                     "transport-ats",
                     "Giving ATS session %p of plugin %s for peer %s\n",
                     session, plugin_name, GNUNET_i2s (peer));
  GNUNET_ATS_address_update (GST_ats, peer, plugin_name, sender_address,
                             sender_address_len, session, ats, ats_count);

  was_connected = is_connected (n);
  change_state (n, S_CONNECTED);

  GNUNET_ATS_address_in_use (GST_ats, &n->id, n->plugin_name, n->addr,
                             n->addrlen, n->addr, GNUNET_YES);

  GST_neighbours_set_incoming_quota (&n->id, n->bandwidth_in);

  if (n->keepalive_task == GNUNET_SCHEDULER_NO_TASK)
    n->keepalive_task =
        GNUNET_SCHEDULER_add_delayed (KEEPALIVE_FREQUENCY,
                                      &neighbour_keepalive_task, n);

  if (!was_connected)
  {
    GST_validation_set_address_use (&n->id,
				    n->plugin_name,
				    n->session,
				    n->addr,
				    n->addrlen,
				    GNUNET_YES);
    neighbours_connected++;
    GNUNET_STATISTICS_update (GST_stats, gettext_noop ("# peers connected"), 1,
                              GNUNET_NO);

#if DEBUG_TRANSPORT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Notify about connect of `%4s' using plugin `%s' address '%s' session %X LINE %u\n",
                GNUNET_i2s (&n->id), n->plugin_name,
                (n->addrlen ==
                 0) ? "<inbound>" : GST_plugins_a2s (n->plugin_name, n->addr,
                                                     n->addrlen), n->session,
                __LINE__);
#endif
    connect_notify_cb (callback_cls, &n->id, ats, ats_count);
  }
#if DEBUG_TRANSPORT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending outbound quota of %u Bps for peer `%s' to all clients\n",
              ntohl (n->bandwidth_out.value__), GNUNET_i2s (peer));
#endif
  q_msg.header.size = htons (sizeof (struct QuotaSetMessage));
  q_msg.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SET_QUOTA);
  q_msg.quota = n->bandwidth_out;
  q_msg.peer = (*peer);
  GST_clients_broadcast (&q_msg.header, GNUNET_NO);
}

struct BlackListCheckContext
{
  struct GNUNET_ATS_Information *ats;

  uint32_t ats_count;

  struct Session *session;

  char *sender_address;

  uint16_t sender_address_len;

  char *plugin_name;

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
                       "Giving ATS session %p of plugin %s address `%s' for peer %s\n",
                       bcc->session, bcc->plugin_name,
                       GST_plugins_a2s (bcc->plugin_name, bcc->sender_address,
                                        bcc->sender_address_len),
                       GNUNET_i2s (peer));
    GNUNET_ATS_address_update (GST_ats, peer, bcc->plugin_name,
                               bcc->sender_address, bcc->sender_address_len,
                               bcc->session, bcc->ats, bcc->ats_count);
    n->connect_ts = bcc->ts;
  }

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
 * @param plugin_name name of transport that delivered the PONG
 * @param address address of the other peer, NULL if other peer
 *                       connected to us
 * @param address_len number of bytes in address
 * @param session session to use (or NULL)
 * @param ats performance data
 * @param ats_count number of entries in ats (excluding 0-termination)
  */
void
GST_neighbours_handle_connect (const struct GNUNET_MessageHeader *message,
                               const struct GNUNET_PeerIdentity *peer,
                               const char *plugin_name,
                               const char *sender_address,
                               uint16_t sender_address_len,
                               struct Session *session,
                               const struct GNUNET_ATS_Information *ats,
                               uint32_t ats_count)
{
  const struct SessionConnectMessage *scm;
  struct NeighbourMapEntry *n;
  struct BlackListCheckContext *bcc = NULL;

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

  n = lookup_neighbour (peer);
  if (n != NULL)
  {
    /* connected peer switches addresses */
    if (is_connected (n))
    {
      GNUNET_ATS_address_update (GST_ats, peer, plugin_name, sender_address,
                                 sender_address_len, session, ats, ats_count);
      return;
    }
  }

  /* we are not connected to this peer */
  /* do blacklist check */
  bcc =
      GNUNET_malloc (sizeof (struct BlackListCheckContext) +
                     sizeof (struct GNUNET_ATS_Information) * (ats_count + 1) +
                     sender_address_len + strlen (plugin_name) + 1);

  bcc->ts = GNUNET_TIME_absolute_ntoh (scm->timestamp);

  bcc->ats_count = ats_count + 1;
  bcc->sender_address_len = sender_address_len;
  bcc->session = session;

  bcc->ats = (struct GNUNET_ATS_Information *) &bcc[1];
  memcpy (bcc->ats, ats, sizeof (struct GNUNET_ATS_Information) * ats_count);
  bcc->ats[ats_count].type = htonl (GNUNET_ATS_QUALITY_NET_DELAY);
  bcc->ats[ats_count].value = htonl ((uint32_t) GST_neighbour_get_latency (peer).rel_value);
  bcc->sender_address = (char *) &bcc->ats[ats_count + 1];
  memcpy (bcc->sender_address, sender_address, sender_address_len);

  bcc->plugin_name = &bcc->sender_address[sender_address_len];
  strcpy (bcc->plugin_name, plugin_name);

  GST_blacklist_test_allowed (peer, plugin_name, handle_connect_blacklist_cont,
                              bcc);
}


/* end of file gnunet-service-transport_neighbours.c */
