/*
     This file is part of GNUnet.
     Copyright (C) 2010-2015 Christian Grothoff (and other contributing authors)

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
#include "gnunet-service-transport_ats.h"
#include "gnunet-service-transport_blacklist.h"
#include "gnunet-service-transport_clients.h"
#include "gnunet-service-transport_neighbours.h"
#include "gnunet-service-transport_manipulation.h"
#include "gnunet-service-transport_plugins.h"
#include "gnunet-service-transport_validation.h"
#include "gnunet-service-transport.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_constants.h"
#include "transport.h"


/**
 * Size of the neighbour hash map.
 */
#define NEIGHBOUR_TABLE_SIZE 256

/**
 * Time we give plugin to transmit DISCONNECT message before the
 * neighbour entry self-destructs.
 */
#define DISCONNECT_SENT_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 500)

/**
 * How often must a peer violate bandwidth quotas before we start
 * to simply drop its messages?
 */
#define QUOTA_VIOLATION_DROP_THRESHOLD 10

/**
 * How long are we willing to wait for a response from ATS before timing out?
 */
#define ATS_RESPONSE_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * How long are we willing to wait for an ACK from the other peer before
 * giving up on our connect operation?
 */
#define SETUP_CONNECTION_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15)

/**
 * How long are we willing to wait for a successful reconnect if
 * an existing connection went down?  Much shorter than the
 * usual SETUP_CONNECTION_TIMEOUT as we do not inform the
 * higher layers about the disconnect during this period.
 */
#define FAST_RECONNECT_TIMEOUT GNUNET_TIME_UNIT_SECONDS

/**
 * Interval to send utilization data
 */
#define UTIL_TRANSMISSION_INTERVAL GNUNET_TIME_UNIT_SECONDS

/**
 * State describing which kind a reply this neighbour should send
 */
enum GST_ACK_State
{
  /**
   * We did not receive a SYN message for this neighbour
   */
  ACK_UNDEFINED = 0,

  /**
   * The neighbour received a SYN message and has to send a SYN_ACK
   * as reply
   */
  ACK_SEND_SYN_ACK = 1,

  /**
   * The neighbour sent a SYN_ACK message and has to send a ACK
   * as reply
   */
  ACK_SEND_ACK = 2
};


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Message a peer sends to another to indicate that it intends to
 * setup a connection/session for data exchange.  A 'SESSION_SYN'
 * should be answered with a 'SESSION_SYN_ACK' with the same body
 * to confirm.  A 'SESSION_SYN_ACK' should then be followed with
 * a 'ACK'.  Once the 'ACK' is received, both peers
 * should be connected.
 */
struct TransportSynMessage
{
  /**
   * Header of type #GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_SYN
   * or #GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_SYN_ACK
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


/**
 * Message a peer sends to another when connected to indicate that a
 * session is in use and the peer is still alive or to respond to a keep alive.
 * A peer sends a message with type #GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_KEEPALIVE
 * to request a message with #GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_KEEPALIVE_RESPONSE.
 * When the keep alive response with type is received, transport service
 * will call the respective plugin to update the session timeout
 */
struct SessionKeepAliveMessage
{
  /**
   * Header of type #GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_KEEPALIVE or
   * #GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_KEEPALIVE_RESPONSE.
   */
  struct GNUNET_MessageHeader header;

  /**
   * A nonce to identify the session the keep alive is used for
   */
  uint32_t nonce GNUNET_PACKED;
};


/**
 * Message a peer sends to another when connected to indicate that
 * the other peer should limit transmissions to the indicated
 * quota.
 */
struct SessionQuotaMessage
{
  /**
   * Header of type #GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_QUOTA.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Quota to use (for sending), in bytes per second.
   */
  uint32_t quota GNUNET_PACKED;
};


/**
 * Message we send to the other peer to notify him that we intentionally
 * are disconnecting (to reduce timeouts).  This is just a friendly
 * notification, peers must not rely on always receiving disconnect
 * messages.
 */
struct SessionDisconnectMessage
{
  /**
   * Header of type #GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_DISCONNECT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Purpose of the signature.  Extends over the timestamp.
   * Purpose should be #GNUNET_SIGNATURE_PURPOSE_TRANSPORT_DISCONNECT.
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * Absolute time at the sender.  Only the most recent connect
   * message implies which session is preferred by the sender.
   */
  struct GNUNET_TIME_AbsoluteNBO timestamp;

  /**
   * Public key of the sender.
   */
  struct GNUNET_CRYPTO_EddsaPublicKey public_key;

  /**
   * Signature of the peer that sends us the disconnect.  Only
   * valid if the timestamp is AFTER the timestamp from the
   * corresponding 'SYN' message.
   */
  struct GNUNET_CRYPTO_EddsaSignature signature;

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
   * Function to call once we're done.
   */
  GST_NeighbourSendContinuation cont;

  /**
   * Closure for @e cont
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
 * A possible address we could use to communicate with a neighbour.
 */
struct NeighbourAddress
{

  /**
   * Active session for this address.
   */
  struct Session *session;

  /**
   * Network-level address information.
   */
  struct GNUNET_HELLO_Address *address;

  /**
   * Timestamp of the 'SESSION_CONNECT' message we sent to the other
   * peer for this address.  Use to check that the ACK is in response
   * to our most recent 'SYN'.
   */
  struct GNUNET_TIME_Absolute connect_timestamp;

  /**
   * Inbound bandwidth from ATS for this address.
   */
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in;

  /**
   * Outbound bandwidth from ATS for this address.
   */
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out;

  /**
   * Did we tell ATS that this is our 'active' address?
   */
  int ats_active;

  /**
   * The current nonce sent in the last keep alive messages
   */
  uint32_t keep_alive_nonce;
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
   * Primary address we currently use to communicate with the neighbour.
   */
  struct NeighbourAddress primary_address;

  /**
   * Alternative address currently under consideration for communicating
   * with the neighbour.
   */
  struct NeighbourAddress alternative_address;

  /**
   * Identity of this neighbour.
   */
  struct GNUNET_PeerIdentity id;

  /**
   * Main task that drives this peer (timeouts, keepalives, etc.).
   * Always runs the #master_task().
   */
  struct GNUNET_SCHEDULER_Task *task;

  /**
   * Task to disconnect neighbour after we received a DISCONNECT message
   */
  struct GNUNET_SCHEDULER_Task *delayed_disconnect_task;

  /**
   * At what time should we sent the next keep-alive message?
   */
  struct GNUNET_TIME_Absolute keep_alive_time;

  /**
   * At what time did we sent the last keep-alive message?  Used
   * to calculate round-trip time ("latency").
   */
  struct GNUNET_TIME_Absolute last_keep_alive_time;

  /**
   * Timestamp we should include in our next SYN_ACK message.
   * (only valid if 'send_connect_ack' is #GNUNET_YES).  Used to build
   * our SYN_ACK message.
   */
  struct GNUNET_TIME_Absolute connect_ack_timestamp;

  /**
   * ATS address suggest handle
   */
  struct GNUNET_ATS_ConnectivitySuggestHandle *suggest_handle;

  /**
   * Time where we should cut the connection (timeout) if we don't
   * make progress in the state machine (or get a KEEPALIVE_RESPONSE
   * if we are in #GNUNET_TRANSPORT_PS_CONNECTED).
   */
  struct GNUNET_TIME_Absolute timeout;

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
   * Latest quota the other peer send us in bytes per second.
   * We should not send more, least the other peer throttle
   * receiving our traffic.
   */
  struct GNUNET_BANDWIDTH_Value32NBO neighbour_receive_quota;

  /**
   * The current state of the peer.
   */
  enum GNUNET_TRANSPORT_PeerState state;

  /**
   * Did we sent an KEEP_ALIVE message and are we expecting a response?
   */
  int expect_latency_response;

  /**
   * When a peer wants to connect we have to reply to the 1st SYN message
   * with a SYN_ACK message. But sometime we cannot send this message
   * immediately since we do not have an address and then we have to remember
   * to send this message as soon as we have an address.
   *
   * Flag to set if we still need to send a SYN_ACK message to the other peer
   * (once we have an address to use and the peer has been allowed by our
   * blacklist).  Initially set to #ACK_UNDEFINED. Set to #ACK_SEND_SYN_ACK
   * if we need to send a SYN_ACK.  Set to #ACK_SEND_ACK if we did
   * send a SYN_ACK and should go to #S_CONNECTED upon receiving a
   * 'ACK' (regardless of what our own state machine might say).
   */
  enum GST_ACK_State ack_state;

  /**
   * Tracking utilization of outbound bandwidth
   */
  uint32_t util_total_bytes_sent;

  /**
   * Tracking utilization of inbound bandwidth
   */
  uint32_t util_total_bytes_recv;

  /**
   * Date of last utilization transmission
   */
  struct GNUNET_TIME_Absolute last_util_transmission;
};


/**
 * Context for blacklist checks and the #try_connect_bl_check_cont()
 * function.  Stores information about ongoing blacklist checks.
 */
struct BlackListCheckContext
{

  /**
   * We keep blacklist checks in a DLL.
   */
  struct BlackListCheckContext *next;

  /**
   * We keep blacklist checks in a DLL.
   */
  struct BlackListCheckContext *prev;

  /**
   * Address that is being checked.
   */
  struct NeighbourAddress na;

  /**
   * Handle to the ongoing blacklist check.
   */
  struct GST_BlacklistCheck *bc;
};


/**
 * Hash map from peer identities to the respective `struct NeighbourMapEntry`.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *neighbours;

/**
 * We keep blacklist checks in a DLL so that we can find
 * the 'sessions' in their 'struct NeighbourAddress' if
 * a session goes down.
 */
static struct BlackListCheckContext *bc_head;

/**
 * We keep blacklist checks in a DLL.
 */
static struct BlackListCheckContext *bc_tail;

/**
 * List of pending blacklist checks: head
 */
static struct BlacklistCheckSwitchContext *pending_bc_head;

/**
 * List of pending blacklist checks: tail
 */
static struct BlacklistCheckSwitchContext *pending_bc_tail;

/**
 * counter for connected neighbours
 */
static unsigned int neighbours_connected;

/**
 * Number of bytes we have currently queued for transmission.
 */
static unsigned long long bytes_in_send_queue;

/**
 * Task transmitting utilization data
 */
static struct GNUNET_SCHEDULER_Task *util_transmission_tk;


/**
 * Convert the given ACK state to a string.
 *
 * @param s state
 * @return corresponding human-readable string
 */
static char *
print_ack_state (enum GST_ACK_State s)
{
  switch (s) {
    case ACK_UNDEFINED:
      return "UNDEFINED";
    case ACK_SEND_SYN_ACK:
      return "SEND_SYN_ACK";
    case ACK_SEND_ACK:
      return "SEND_ACK";
    default:
      GNUNET_break (0);
      return "N/A";
  }
}


/**
 * Notify our clients that another peer connected to us.
 *
 * @param peer the peer that connected
 * @param bandwidth_in inbound bandwidth in NBO
 * @param bandwidth_out outbound bandwidth in NBO
 */
static void
neighbours_connect_notification (const struct GNUNET_PeerIdentity *peer,
                                 struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
                                 struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out)
{
  size_t len = sizeof(struct ConnectInfoMessage);
  char buf[len] GNUNET_ALIGN;
  struct ConnectInfoMessage *connect_msg = (struct ConnectInfoMessage *) buf;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "We are now connected to peer `%s'\n",
              GNUNET_i2s (peer));
  connect_msg->header.size = htons (sizeof(buf));
  connect_msg->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_CONNECT);
  connect_msg->id = *peer;
  connect_msg->quota_in = bandwidth_in;
  connect_msg->quota_out = bandwidth_out;
  GST_clients_broadcast (&connect_msg->header, GNUNET_NO);
}


/**
 * Notify our clients (and manipulation) that a peer disconnected from
 * us.
 *
 * @param peer the peer that disconnected
 */
static void
neighbours_disconnect_notification (const struct GNUNET_PeerIdentity *peer)
{
  struct DisconnectInfoMessage disconnect_msg;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Peer `%s' disconnected\n",
              GNUNET_i2s (peer));
  GST_manipulation_peer_disconnect (peer);
  disconnect_msg.header.size = htons (sizeof(struct DisconnectInfoMessage));
  disconnect_msg.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_DISCONNECT);
  disconnect_msg.reserved = htonl (0);
  disconnect_msg.peer = *peer;
  GST_clients_broadcast (&disconnect_msg.header,
                         GNUNET_NO);
}


/**
 * Notify transport clients that a neighbour peer changed its active
 * address.
 *
 * @param peer identity of the peer
 * @param address address possibly NULL if peer is not connected
 * @param state current state this peer is in
 * @param state_timeout timeout for the current state of the peer
 * @param bandwidth_in bandwidth assigned inbound, 0 on disconnect
 * @param bandwidth_out bandwidth assigned outbound, 0 on disconnect
 */
static void
neighbours_changed_notification (const struct GNUNET_PeerIdentity *peer,
                                 const struct GNUNET_HELLO_Address *address,
                                 enum GNUNET_TRANSPORT_PeerState state,
                                 struct GNUNET_TIME_Absolute state_timeout,
                                 struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
                                 struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Notifying about change for peer `%s' with address `%s' in state `%s' timing out at %s\n",
              GNUNET_i2s (peer),
              GST_plugins_a2s (address),
              GNUNET_TRANSPORT_ps2s (state),
              GNUNET_STRINGS_absolute_time_to_string (state_timeout));
  /* FIXME: include bandwidth in notification! */
  GST_clients_broadcast_peer_notification (peer,
                                           address,
                                           state,
                                           state_timeout);
}


/**
 * Lookup a neighbour entry in the neighbours hash map.
 *
 * @param pid identity of the peer to look up
 * @return the entry, NULL if there is no existing record
 */
static struct NeighbourMapEntry *
lookup_neighbour (const struct GNUNET_PeerIdentity *pid)
{
  if (NULL == neighbours)
    return NULL;
  return GNUNET_CONTAINER_multipeermap_get (neighbours, pid);
}


/**
 * Test if we're connected to the given peer.
 *
 * @param n neighbour entry of peer to test
 * @return #GNUNET_YES if we are connected, #GNUNET_NO if not
 */
static int
test_connected (struct NeighbourMapEntry *n)
{
  if (NULL == n)
    return GNUNET_NO;
  return GNUNET_TRANSPORT_is_connected (n->state);
}


/**
 * Send information about a new outbound quota to our clients.
 * Note that the outbound quota is enforced client-side (i.e.
 * in libgnunettransport).
 *
 * @param target affected peer
 * @param quota new quota
 */
static void
send_outbound_quota_to_clients (const struct GNUNET_PeerIdentity *target,
                                struct GNUNET_BANDWIDTH_Value32NBO quota)
{
  struct QuotaSetMessage q_msg;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending outbound quota of %u Bps for peer `%s' to all clients\n",
              ntohl (quota.value__),
              GNUNET_i2s (target));
  q_msg.header.size = htons (sizeof (struct QuotaSetMessage));
  q_msg.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SET_QUOTA);
  q_msg.quota = quota;
  q_msg.peer = (*target);
  GST_clients_broadcast (&q_msg.header, GNUNET_NO);
}


/**
 * We don't need a given neighbour address any more.
 * Release its resources and give appropriate notifications
 * to ATS and other subsystems.
 *
 * @param na address we are done with; @a na itself must NOT be 'free'd, only the contents!
 */
static void
free_address (struct NeighbourAddress *na)
{
  if (GNUNET_YES == na->ats_active)
    GST_validation_set_address_use (na->address,
                                    GNUNET_NO);
  if (NULL != na->address)
  {
    GST_ats_block_address (na->address,
                           na->session);
    GNUNET_HELLO_address_free (na->address);
    na->address = NULL;
  }
  na->bandwidth_in = GNUNET_BANDWIDTH_value_init (0);
  na->bandwidth_out = GNUNET_BANDWIDTH_value_init (0);
  na->ats_active = GNUNET_NO;
  na->keep_alive_nonce = 0;
  na->session = NULL;
}


/**
 * Master task run for every neighbour.  Performs all of the time-related
 * activities (keep alive, send next message, disconnect if idle, finish
 * clean up after disconnect).
 *
 * @param cls the `struct NeighbourMapEntry` for which we are running
 * @param tc scheduler context (unused)
 */
static void
master_task (void *cls,
	     const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Set net state and state timeout for this neighbour and notify monitoring
 *
 * @param n the respective neighbour
 * @param s the new state
 * @param timeout the new timeout
 */
static void
set_state_and_timeout (struct NeighbourMapEntry *n,
		       enum GNUNET_TRANSPORT_PeerState s,
		       struct GNUNET_TIME_Absolute timeout)
{
  if (GNUNET_TRANSPORT_is_connected (s) &&
      ! GNUNET_TRANSPORT_is_connected (n->state) )
  {
    neighbours_connect_notification (&n->id,
                                     n->primary_address.bandwidth_in,
                                     n->primary_address.bandwidth_out);
    GNUNET_STATISTICS_set (GST_stats,
			   gettext_noop ("# peers connected"),
			   ++neighbours_connected,
			   GNUNET_NO);
  }
  if (! GNUNET_TRANSPORT_is_connected (s) &&
        GNUNET_TRANSPORT_is_connected (n->state) )
  {
    GNUNET_STATISTICS_set (GST_stats,
			   gettext_noop ("# peers connected"),
			   --neighbours_connected,
			   GNUNET_NO);
    neighbours_disconnect_notification (&n->id);
  }
  n->state = s;
  if ( (timeout.abs_value_us < n->timeout.abs_value_us) &&
       (NULL != n->task ) )
  {
    /* new timeout is earlier, reschedule master task */
    GNUNET_SCHEDULER_cancel (n->task);
    n->task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_absolute_get_remaining (timeout),
                                            &master_task,
                                            n);
  }
  n->timeout = timeout;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      "Neighbour `%s' changed state to %s with timeout %s\n",
	      GNUNET_i2s (&n->id),
	      GNUNET_TRANSPORT_ps2s(s),
	      GNUNET_STRINGS_absolute_time_to_string (timeout));
  neighbours_changed_notification (&n->id,
                                   n->primary_address.address,
                                   n->state,
                                   n->timeout,
                                   n->primary_address.bandwidth_in,
                                   n->primary_address.bandwidth_out);
}


/**
 * Initialize the alternative address of a neighbour
 *
 * @param n the neighbour
 * @param address address of the other peer, NULL if other peer
 *                       connected to us
 * @param session session to use (or NULL, in which case an
 *        address must be setup)
 * @param bandwidth_in inbound quota to be used when connection is up
 * @param bandwidth_out outbound quota to be used when connection is up
 */
static void
set_alternative_address (struct NeighbourMapEntry *n,
                         const struct GNUNET_HELLO_Address *address,
                         struct Session *session,
                         struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
                         struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out)
{
  struct GNUNET_TRANSPORT_PluginFunctions *papi;

  if (NULL == (papi = GST_plugins_find (address->transport_name)))
  {
    GNUNET_break (0);
    return;
  }
  if (session == n->alternative_address.session)
  {
    n->alternative_address.bandwidth_in = bandwidth_in;
    n->alternative_address.bandwidth_out = bandwidth_out;
    return;
  }
  if (NULL != n->alternative_address.address)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Replacing existing alternative address with another one\n");
    free_address (&n->alternative_address);
  }
  if (NULL == session)
    session = papi->get_session (papi->cls,
                                 address);
  if (NULL == session)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Failed to obtain new session for peer `%s' and  address '%s'\n",
                GNUNET_i2s (&address->peer),
                GST_plugins_a2s (address));
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop ("# session creation failed"),
                              1,
                              GNUNET_NO);
    return;
  }
  GST_ats_new_session (address,
                       session);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Neighbour `%s' configured alternative address %s\n",
              GNUNET_i2s (&n->id),
              GST_plugins_a2s(address));

  n->alternative_address.address = GNUNET_HELLO_address_copy (address);
  n->alternative_address.bandwidth_in = bandwidth_in;
  n->alternative_address.bandwidth_out = bandwidth_out;
  n->alternative_address.session = session;
  n->alternative_address.ats_active = GNUNET_NO;
  n->alternative_address.keep_alive_nonce = 0;
  GNUNET_assert (GNUNET_YES ==
                 GST_ats_is_known (n->alternative_address.address,
                                   n->alternative_address.session));
}


/**
 * Initialize the primary address of a neighbour
 *
 * @param n the neighbour
 * @param address address of the other peer, NULL if other peer
 *                       connected to us
 * @param session session to use (or NULL, in which case an
 *        address must be setup)
 * @param bandwidth_in inbound quota to be used when connection is up
 * @param bandwidth_out outbound quota to be used when connection is up
 */
static void
set_primary_address (struct NeighbourMapEntry *n,
                     const struct GNUNET_HELLO_Address *address,
                     struct Session *session,
                     struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
                     struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out)
{
  if (session == n->primary_address.session)
  {
    GST_validation_set_address_use (n->primary_address.address,
                                    GNUNET_YES);
    if (n->primary_address.bandwidth_in.value__ != bandwidth_in.value__)
    {
      n->primary_address.bandwidth_in = bandwidth_in;
      GST_neighbours_set_incoming_quota (&address->peer,
                                         bandwidth_in);
    }
    if (n->primary_address.bandwidth_out.value__ != bandwidth_out.value__)
    {
      n->primary_address.bandwidth_out = bandwidth_out;
      send_outbound_quota_to_clients (&address->peer,
                                      bandwidth_out);
    }
    return;
  }
  if ( (NULL != n->primary_address.address) &&
       (0 == GNUNET_HELLO_address_cmp (address,
                                       n->primary_address.address)) )
  {
    GNUNET_break (0);
    return;
  }
  if (NULL == session)
  {
    GNUNET_break (0);
    GST_ats_block_address (address,
                           session);
    return;
  }
  if (NULL != n->primary_address.address)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Replacing existing primary address with another one\n");
    free_address (&n->primary_address);
  }
  n->primary_address.address = GNUNET_HELLO_address_copy (address);
  n->primary_address.bandwidth_in = bandwidth_in;
  n->primary_address.bandwidth_out = bandwidth_out;
  n->primary_address.session = session;
  n->primary_address.keep_alive_nonce = 0;
  GNUNET_assert (GNUNET_YES ==
                 GST_ats_is_known (n->primary_address.address,
                                   n->primary_address.session));
  /* subsystems about address use */
  GST_validation_set_address_use (n->primary_address.address,
                                  GNUNET_YES);
  GST_neighbours_set_incoming_quota (&address->peer,
                                     bandwidth_in);
  send_outbound_quota_to_clients (&address->peer,
                                  bandwidth_out);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Neighbour `%s' switched to address `%s'\n",
              GNUNET_i2s (&n->id),
              GST_plugins_a2s(address));

  neighbours_changed_notification (&n->id,
                                   n->primary_address.address,
                                   n->state,
                                   n->timeout,
                                   n->primary_address.bandwidth_in,
                                   n->primary_address.bandwidth_out);
}


/**
 * Clear the primary address of a neighbour since this address is not
 * valid anymore and notify monitoring about it
 *
 * @param n the neighbour
 */
static void
unset_primary_address (struct NeighbourMapEntry *n)
{
  /* Notify monitoring about change */
  if (NULL == n->primary_address.address)
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Disabling primary address\n");
  neighbours_changed_notification (&n->id,
                                   n->primary_address.address,
                                   n->state,
                                   n->timeout,
                                   GNUNET_BANDWIDTH_value_init (0),
                                   GNUNET_BANDWIDTH_value_init (0));
  free_address (&n->primary_address);
}


/**
 * Free a neighbour map entry.
 *
 * @param n entry to free
 */
static void
free_neighbour (struct NeighbourMapEntry *n)
{
  struct MessageQueue *mq;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Freeing neighbour state of peer `%s'\n",
              GNUNET_i2s (&n->id));
  n->is_active = NULL; /* always free'd by its own continuation! */

  /* fail messages currently in the queue */
  while (NULL != (mq = n->messages_head))
  {
    GNUNET_CONTAINER_DLL_remove (n->messages_head,
                                 n->messages_tail,
                                 mq);
    if (NULL != mq->cont)
      mq->cont (mq->cont_cls,
                GNUNET_SYSERR,
                mq->message_buf_size,
                0);
    GNUNET_free (mq);
  }
  /* Mark peer as disconnected */
  set_state_and_timeout (n,
                         GNUNET_TRANSPORT_PS_DISCONNECT_FINISHED,
                         GNUNET_TIME_UNIT_FOREVER_ABS);
  /* free addresses and mark as unused */
  unset_primary_address (n);

  if (NULL != n->alternative_address.address)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Cleaning up alternative address\n");
    free_address (&n->alternative_address);
  }
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (neighbours,
                                                       &n->id, n));

  /* Cancel address requests for this peer */
  if (NULL != n->suggest_handle)
  {
    GNUNET_ATS_connectivity_suggest_cancel (n->suggest_handle);
    n->suggest_handle = NULL;
  }

  /* Cancel the disconnect task */
  if (NULL != n->delayed_disconnect_task)
  {
    GNUNET_SCHEDULER_cancel (n->delayed_disconnect_task);
    n->delayed_disconnect_task = NULL;
  }

  /* Cancel the master task */
  if (NULL != n->task)
  {
    GNUNET_SCHEDULER_cancel (n->task);
    n->task = NULL;
  }
  /* free rest of memory */
  GNUNET_free (n);
}


/**
 * Transmit a message using the current session of the given
 * neighbour.
 *
 * @param n entry for the recipient
 * @param msgbuf buffer to transmit
 * @param msgbuf_size number of bytes in @a msgbuf buffer
 * @param priority transmission priority
 * @param timeout transmission timeout
 * @param use_keepalive_timeout #GNUNET_YES to use plugin-specific keep-alive
 *        timeout (@a timeout is ignored in that case), #GNUNET_NO otherwise
 * @param cont continuation to call when finished (can be NULL)
 * @param cont_cls closure for @a cont
 * @return timeout (copy of @a timeout or a calculated one if
 *         @a use_keepalive_timeout is #GNUNET_YES.
 */
static struct GNUNET_TIME_Relative
send_with_session (struct NeighbourMapEntry *n,
                   const void *msgbuf,
                   size_t msgbuf_size,
                   uint32_t priority,
                   struct GNUNET_TIME_Relative timeout,
		   unsigned int use_keepalive_timeout,
                   GNUNET_TRANSPORT_TransmitContinuation cont,
		   void *cont_cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *papi;
  struct GNUNET_TIME_Relative result = GNUNET_TIME_UNIT_FOREVER_REL;

  GNUNET_assert (NULL != n->primary_address.session);
  if ( ((NULL == (papi = GST_plugins_find (n->primary_address.address->transport_name)) ||
	 (-1 == papi->send (papi->cls,
			    n->primary_address.session,
			    msgbuf,
                            msgbuf_size,
			    priority,
			    (result = (GNUNET_NO == use_keepalive_timeout) ? timeout :
                             GNUNET_TIME_relative_divide (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                                                          papi->query_keepalive_factor (papi->cls))),
			    cont,
                            cont_cls)))) &&
       (NULL != cont))
    cont (cont_cls,
          &n->id,
          GNUNET_SYSERR,
          msgbuf_size,
          0);
  GST_neighbours_notify_data_sent (n->primary_address.address,
				   n->primary_address.session,
				   msgbuf_size);
  GNUNET_break (NULL != papi);
  return result;
}


/**
 * Function called when the 'DISCONNECT' message has been sent by the
 * plugin.  Frees the neighbour --- if the entry still exists.
 *
 * @param cls NULL
 * @param target identity of the neighbour that was disconnected
 * @param result #GNUNET_OK if the disconnect got out successfully
 * @param payload bytes payload
 * @param physical bytes on wire
 */
static void
send_disconnect_cont (void *cls,
                      const struct GNUNET_PeerIdentity *target,
                      int result,
                      size_t payload,
                      size_t physical)
{
  struct NeighbourMapEntry *n;

  n = lookup_neighbour (target);
  if (NULL == n)
    return; /* already gone */
  if (GNUNET_TRANSPORT_PS_DISCONNECT != n->state)
    return; /* have created a fresh entry since */
  if (NULL != n->task)
    GNUNET_SCHEDULER_cancel (n->task);
  n->task = GNUNET_SCHEDULER_add_now (&master_task, n);
}


/**
 * Transmit a DISCONNECT message to the other peer.
 *
 * @param n neighbour to send DISCONNECT message.
 */
static void
send_disconnect (struct NeighbourMapEntry *n)
{
  struct SessionDisconnectMessage disconnect_msg;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Sending DISCONNECT message to peer `%4s'\n",
              GNUNET_i2s (&n->id));
  disconnect_msg.header.size = htons (sizeof (struct SessionDisconnectMessage));
  disconnect_msg.header.type =
      htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_DISCONNECT);
  disconnect_msg.reserved = htonl (0);
  disconnect_msg.purpose.size =
      htonl (sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) +
             sizeof (struct GNUNET_CRYPTO_EddsaPublicKey) +
             sizeof (struct GNUNET_TIME_AbsoluteNBO));
  disconnect_msg.purpose.purpose =
      htonl (GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_DISCONNECT);
  disconnect_msg.timestamp =
      GNUNET_TIME_absolute_hton (GNUNET_TIME_absolute_get ());
  disconnect_msg.public_key = GST_my_identity.public_key;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_eddsa_sign (GST_my_private_key,
                                         &disconnect_msg.purpose,
                                         &disconnect_msg.signature));

  (void) send_with_session (n,
                            &disconnect_msg,
                            sizeof (disconnect_msg),
                            UINT32_MAX,
                            GNUNET_TIME_UNIT_FOREVER_REL,
                            GNUNET_NO,
                            &send_disconnect_cont,
                            NULL);
  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop ("# DISCONNECT messages sent"),
                            1,
                            GNUNET_NO);
}


/**
 * Disconnect from the given neighbour, clean up the record.
 *
 * @param n neighbour to disconnect from
 */
static void
disconnect_neighbour (struct NeighbourMapEntry *n)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Disconnecting from peer %s in state %s\n",
              GNUNET_i2s (&n->id),
              GNUNET_TRANSPORT_ps2s (n->state));
  /* depending on state, notify neighbour and/or upper layers of this peer
     about disconnect */
  switch (n->state)
  {
  case GNUNET_TRANSPORT_PS_NOT_CONNECTED:
  case GNUNET_TRANSPORT_PS_INIT_ATS:
    /* other peer is completely unaware of us, no need to send DISCONNECT */
    free_neighbour (n);
    return;
  case GNUNET_TRANSPORT_PS_SYN_SENT:
    send_disconnect (n);
    set_state_and_timeout (n,
                           GNUNET_TRANSPORT_PS_DISCONNECT,
                           GNUNET_TIME_UNIT_FOREVER_ABS);
    break;
  case GNUNET_TRANSPORT_PS_SYN_RECV_ATS:
    /* we never ACK'ed the other peer's request, no need to send DISCONNECT */
    free_neighbour (n);
    return;
  case GNUNET_TRANSPORT_PS_SYN_RECV_ACK:
    /* we DID ACK the other peer's request, must send DISCONNECT */
    send_disconnect (n);
    set_state_and_timeout (n,
                           GNUNET_TRANSPORT_PS_DISCONNECT,
                           GNUNET_TIME_UNIT_FOREVER_ABS);
    break;
  case GNUNET_TRANSPORT_PS_SWITCH_SYN_SENT:
  case GNUNET_TRANSPORT_PS_CONNECTED:
  case GNUNET_TRANSPORT_PS_RECONNECT_SENT:
    /* we are currently connected, need to send disconnect and do
       internal notifications and update statistics */
    send_disconnect (n);
    set_state_and_timeout (n,
                           GNUNET_TRANSPORT_PS_DISCONNECT,
                           GNUNET_TIME_UNIT_FOREVER_ABS);
    break;
  case GNUNET_TRANSPORT_PS_RECONNECT_ATS:
    /* Disconnecting while waiting for an ATS address to reconnect,
     * cannot send DISCONNECT */
    free_neighbour (n);
    return;
  case GNUNET_TRANSPORT_PS_DISCONNECT:
    /* already disconnected, ignore */
    break;
  case GNUNET_TRANSPORT_PS_DISCONNECT_FINISHED:
    /* already cleaned up, how did we get here!? */
    GNUNET_assert (0);
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unhandled state `%s'\n",
                GNUNET_TRANSPORT_ps2s (n->state));
    GNUNET_break (0);
    break;
  }
  /* schedule timeout to clean up */
  if (NULL != n->task)
    GNUNET_SCHEDULER_cancel (n->task);
  n->task = GNUNET_SCHEDULER_add_delayed (DISCONNECT_SENT_TIMEOUT,
					  &master_task,
                                          n);
}


/**
 * We're done with our transmission attempt, continue processing.
 *
 * @param cls the `struct MessageQueue` of the message
 * @param receiver intended receiver
 * @param success whether it worked or not
 * @param size_payload bytes payload sent
 * @param physical bytes sent on wire
 */
static void
transmit_send_continuation (void *cls,
                            const struct GNUNET_PeerIdentity *receiver,
                            int success,
                            size_t size_payload,
                            size_t physical)
{
  struct MessageQueue *mq = cls;
  struct NeighbourMapEntry *n;

  if (NULL == (n = lookup_neighbour (receiver)))
  {
    if (NULL != mq->cont)
      mq->cont (mq->cont_cls,
                GNUNET_SYSERR /* not connected */,
                size_payload,
                0);
    GNUNET_free (mq);
    return; /* disconnect or other error while transmitting, can happen */
  }
  if (n->is_active == mq)
  {
    /* this is still "our" neighbour, remove us from its queue
       and allow it to send the next message now */
    n->is_active = NULL;
    if (NULL != n->task)
      GNUNET_SCHEDULER_cancel (n->task);
    n->task = GNUNET_SCHEDULER_add_now (&master_task,
                                        n);
  }
  if (bytes_in_send_queue < mq->message_buf_size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Bytes_in_send_queue `%u', Message_size %u, result: %s, payload %u, on wire %u\n",
                bytes_in_send_queue,
                mq->message_buf_size,
                (GNUNET_OK == success) ? "OK" : "FAIL",
                size_payload,
                physical);
    GNUNET_break (0);
  }

  GNUNET_break (size_payload == mq->message_buf_size);
  bytes_in_send_queue -= mq->message_buf_size;
  GNUNET_STATISTICS_set (GST_stats,
                         gettext_noop ("# bytes in message queue for other peers"),
			 bytes_in_send_queue,
                         GNUNET_NO);
  if (GNUNET_OK == success)
    GNUNET_STATISTICS_update (GST_stats,
			      gettext_noop ("# messages transmitted to other peers"),
			      1,
                              GNUNET_NO);
  else
    GNUNET_STATISTICS_update (GST_stats,
			      gettext_noop
			      ("# transmission failures for messages to other peers"),
			      1, GNUNET_NO);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Sending message to `%s' of type %u with %u bytes was a %s\n",
	      GNUNET_i2s (receiver),
              ntohs (((struct GNUNET_MessageHeader *) mq->message_buf)->type),
              mq->message_buf_size,
              (success == GNUNET_OK) ? "success" : "FAILURE");
  if (NULL != mq->cont)
    mq->cont (mq->cont_cls,
              success,
              size_payload,
              physical);
  GNUNET_free (mq);
}


/**
 * Check the message list for the given neighbour and if we can
 * send a message, do so.  This function should only be called
 * if the connection is at least generally ready for transmission.
 * While we will only send one message at a time, no bandwidth
 * quota management is performed here.  If a message was given to
 * the plugin, the continuation will automatically re-schedule
 * the 'master' task once the next message might be transmitted.
 *
 * @param n target peer for which to transmit
 */
static void
try_transmission_to_peer (struct NeighbourMapEntry *n)
{
  struct MessageQueue *mq;
  struct GNUNET_TIME_Relative timeout;

  if (NULL == n->primary_address.address)
  {
    /* no address, why are we here? */
    GNUNET_break (0);
    return;
  }
  if ((0 == n->primary_address.address->address_length) &&
      (NULL == n->primary_address.session))
  {
    /* no address, why are we here? */
    GNUNET_break (0);
    return;
  }
  if (NULL != n->is_active)
  {
    /* transmission already pending */
    return;
  }

  /* timeout messages from the queue that are past their due date */
  while (NULL != (mq = n->messages_head))
  {
    timeout = GNUNET_TIME_absolute_get_remaining (mq->timeout);
    if (timeout.rel_value_us > 0)
      break;
    GNUNET_STATISTICS_update (GST_stats,
			      gettext_noop ("# messages timed out while in transport queue"),
			      1,
                              GNUNET_NO);
    GNUNET_CONTAINER_DLL_remove (n->messages_head,
                                 n->messages_tail,
                                 mq);
    n->is_active = mq;
    transmit_send_continuation (mq,
                                &n->id,
                                GNUNET_SYSERR,
                                mq->message_buf_size,
                                0);     /* timeout */
  }
  if (NULL == mq)
    return;                     /* no more messages */
  GNUNET_CONTAINER_DLL_remove (n->messages_head,
                               n->messages_tail,
                               mq);
  n->is_active = mq;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Giving message with %u bytes to plugin session %p\n",
              mq->message_buf_size,
              n->primary_address.session);
  (void) send_with_session (n,
			    mq->message_buf,
                            mq->message_buf_size,
			    0 /* priority */,
                            timeout,
                            GNUNET_NO,
			    &transmit_send_continuation,
                            mq);
}


/**
 * Send keepalive message to the neighbour.  Must only be called
 * if we are on 'connected' state or while trying to switch addresses.
 * Will internally determine if a keepalive is truly needed (so can
 * always be called).
 *
 * @param n neighbour that went idle and needs a keepalive
 */
static void
send_keepalive (struct NeighbourMapEntry *n)
{
  struct SessionKeepAliveMessage m;
  struct GNUNET_TIME_Relative timeout;
  uint32_t nonce;

  GNUNET_assert ((GNUNET_TRANSPORT_PS_CONNECTED == n->state) ||
                 (GNUNET_TRANSPORT_PS_SWITCH_SYN_SENT == n->state));
  if (GNUNET_TIME_absolute_get_remaining (n->keep_alive_time).rel_value_us > 0)
    return; /* no keepalive needed at this time */

  nonce = 0; /* 0 indicates 'not set' */
  while (0 == nonce)
    nonce = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
                                      UINT32_MAX);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending KEEPALIVE to peer `%s' with nonce %u\n",
              GNUNET_i2s (&n->id),
              nonce);
  m.header.size = htons (sizeof (struct SessionKeepAliveMessage));
  m.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_KEEPALIVE);
  m.nonce = htonl (nonce);

  timeout = send_with_session (n,
			       &m,
                               sizeof (m),
			       UINT32_MAX /* priority */,
			       GNUNET_TIME_UNIT_FOREVER_REL,
                               GNUNET_YES,
			       NULL, NULL);
  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop ("# KEEPALIVES sent"),
                            1,
			    GNUNET_NO);
  n->primary_address.keep_alive_nonce = nonce;
  n->expect_latency_response = GNUNET_YES;
  n->last_keep_alive_time = GNUNET_TIME_absolute_get ();
  n->keep_alive_time = GNUNET_TIME_relative_to_absolute (timeout);
}


/**
 * Keep the connection to the given neighbour alive longer,
 * we received a KEEPALIVE (or equivalent); send a response.
 *
 * @param neighbour neighbour to keep alive (by sending keep alive response)
 * @param m the keep alive message containing the nonce to respond to
 */
void
GST_neighbours_keepalive (const struct GNUNET_PeerIdentity *neighbour,
                          const struct GNUNET_MessageHeader *m)
{
  struct NeighbourMapEntry *n;
  const struct SessionKeepAliveMessage *msg_in;
  struct SessionKeepAliveMessage msg;

  if (sizeof (struct SessionKeepAliveMessage) != ntohs (m->size))
  {
    GNUNET_break_op (0);
    return;
  }

  msg_in = (const struct SessionKeepAliveMessage *) m;
  if (NULL == (n = lookup_neighbour (neighbour)))
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# KEEPALIVE messages discarded (peer unknown)"),
                              1, GNUNET_NO);
    return;
  }
  if (NULL == n->primary_address.session)
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# KEEPALIVE messages discarded (no session)"),
                              1, GNUNET_NO);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received KEEPALIVE request from peer `%s' with nonce %u\n",
              GNUNET_i2s (&n->id),
              ntohl (msg_in->nonce));
  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop ("# KEEPALIVES received in good order"),
                            1,
			    GNUNET_NO);

  /* send reply to allow neighbour to measure latency */
  msg.header.size = htons (sizeof (struct SessionKeepAliveMessage));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_KEEPALIVE_RESPONSE);
  msg.nonce = msg_in->nonce;
  (void) send_with_session (n,
                            &msg,
                            sizeof (struct SessionKeepAliveMessage),
                            UINT32_MAX /* priority */,
                            GNUNET_TIME_UNIT_FOREVER_REL,
                            GNUNET_YES,
                            NULL, NULL);
}


/**
 * We received a KEEP_ALIVE_RESPONSE message and use this to calculate
 * latency to this peer.  Pass the updated information (existing ats
 * plus calculated latency) to ATS.
 *
 * @param neighbour neighbour to keep alive
 * @param m the message containing the keep alive response
 */
void
GST_neighbours_keepalive_response (const struct GNUNET_PeerIdentity *neighbour,
                                   const struct GNUNET_MessageHeader *m)
{
  struct NeighbourMapEntry *n;
  const struct SessionKeepAliveMessage *msg;
  struct GNUNET_TRANSPORT_PluginFunctions *papi;
  struct GNUNET_TIME_Relative latency;

  if (sizeof (struct SessionKeepAliveMessage) != ntohs (m->size))
  {
    GNUNET_break_op (0);
    return;
  }

  msg = (const struct SessionKeepAliveMessage *) m;
  if (NULL == (n = lookup_neighbour (neighbour)))
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop ("# KEEPALIVE_RESPONSEs discarded (not connected)"),
                              1,
                              GNUNET_NO);
    return;
  }
  if ( (GNUNET_TRANSPORT_PS_CONNECTED != n->state) ||
       (GNUNET_YES != n->expect_latency_response) )
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop ("# KEEPALIVE_RESPONSEs discarded (not expected)"),
                              1,
                              GNUNET_NO);
    return;
  }
  if (NULL == n->primary_address.address)
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop ("# KEEPALIVE_RESPONSEs discarded (address changed)"),
                              1,
                              GNUNET_NO);
    return;
  }
  if (n->primary_address.keep_alive_nonce != ntohl (msg->nonce))
  {
    if (0 == n->primary_address.keep_alive_nonce)
      GNUNET_STATISTICS_update (GST_stats,
                                gettext_noop ("# KEEPALIVE_RESPONSEs discarded (no nonce)"),
                                1,
                                GNUNET_NO);
    else
      GNUNET_STATISTICS_update (GST_stats,
                                gettext_noop ("# KEEPALIVE_RESPONSEs discarded (bad nonce)"),
                                1,
                                GNUNET_NO);
    return;
  }
  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop ("# KEEPALIVE_RESPONSEs received (OK)"),
                            1,
                            GNUNET_NO);


  /* Update session timeout here */
  if (NULL != (papi = GST_plugins_find (n->primary_address.address->transport_name)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Updating session for peer `%s' for session %p\n",
                GNUNET_i2s (&n->id),
                n->primary_address.session);
    papi->update_session_timeout (papi->cls,
                                  &n->id,
                                  n->primary_address.session);
  }
  else
  {
    GNUNET_break (0);
  }

  n->primary_address.keep_alive_nonce = 0;
  n->expect_latency_response = GNUNET_NO;
  set_state_and_timeout (n,
                         n->state,
                         GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT));

  latency = GNUNET_TIME_absolute_get_duration (n->last_keep_alive_time);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received KEEPALIVE_RESPONSE from peer `%s', latency is %s\n",
              GNUNET_i2s (&n->id),
	      GNUNET_STRINGS_relative_time_to_string (latency,
						      GNUNET_YES));
  GST_ats_update_delay (n->primary_address.address,
                        GNUNET_TIME_relative_divide (latency,
                                                     2));
}


/**
 * We have received a message from the given sender.  How long should
 * we delay before receiving more?  (Also used to keep the peer marked
 * as live).
 *
 * @param sender sender of the message
 * @param size size of the message
 * @param do_forward set to #GNUNET_YES if the message should be forwarded to clients
 *                   #GNUNET_NO if the neighbour is not connected or violates the quota,
 *                   #GNUNET_SYSERR if the connection is not fully up yet
 * @return how long to wait before reading more from this sender
 */
struct GNUNET_TIME_Relative
GST_neighbours_calculate_receive_delay (const struct GNUNET_PeerIdentity *sender,
                                        ssize_t size,
                                        int *do_forward)
{
  struct NeighbourMapEntry *n;
  struct GNUNET_TIME_Relative ret;

  if (NULL == neighbours)
  {
    *do_forward = GNUNET_NO;
    return GNUNET_TIME_UNIT_FOREVER_REL; /* This can happen during shutdown */
  }
  if (NULL == (n = lookup_neighbour (sender)))
  {
    GST_neighbours_try_connect (sender);
    if (NULL == (n = lookup_neighbour (sender)))
    {
      GNUNET_STATISTICS_update (GST_stats,
                                gettext_noop
                                ("# messages discarded due to lack of neighbour record"),
                                1, GNUNET_NO);
      *do_forward = GNUNET_NO;
      return GNUNET_TIME_UNIT_ZERO;
    }
  }
  if (! test_connected (n))
  {
    *do_forward = GNUNET_SYSERR;
    return GNUNET_TIME_UNIT_ZERO;
  }
  if (GNUNET_YES == GNUNET_BANDWIDTH_tracker_consume (&n->in_tracker, size))
  {
    n->quota_violation_count++;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Bandwidth quota (%u b/s) violation detected (total of %u).\n",
                n->in_tracker.available_bytes_per_s__,
                n->quota_violation_count);
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
  if (ret.rel_value_us > 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Throttling read (%lld bytes excess at %u b/s), waiting %s before reading more.\n",
                (long long) n->in_tracker.consumption_since_last_update__,
                (unsigned int) n->in_tracker.available_bytes_per_s__,
                GNUNET_STRINGS_relative_time_to_string (ret, GNUNET_YES));
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop ("# ms throttling suggested"),
                              (int64_t) ret.rel_value_us / 1000LL,
			      GNUNET_NO);
  }
  return ret;
}


/**
 * Transmit a message to the given target using the active connection.
 *
 * @param target destination
 * @param msg message to send
 * @param msg_size number of bytes in msg
 * @param timeout when to fail with timeout
 * @param cont function to call when done
 * @param cont_cls closure for @a cont
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

  /* All ove these cases should never happen; they are all API violations.
     But we check anyway, just to be sure. */
  if (NULL == (n = lookup_neighbour (target)))
  {
    GNUNET_break (0);
    if (NULL != cont)
      cont (cont_cls,
            GNUNET_SYSERR,
            msg_size,
            0);
    return;
  }
  if (GNUNET_YES != test_connected (n))
  {
    GNUNET_break (0);
    if (NULL != cont)
      cont (cont_cls,
            GNUNET_SYSERR,
            msg_size,
            0);
    return;
  }
  bytes_in_send_queue += msg_size;
  GNUNET_STATISTICS_set (GST_stats,
			 gettext_noop
			 ("# bytes in message queue for other peers"),
			 bytes_in_send_queue, GNUNET_NO);
  mq = GNUNET_malloc (sizeof (struct MessageQueue) + msg_size);
  mq->cont = cont;
  mq->cont_cls = cont_cls;
  memcpy (&mq[1], msg, msg_size);
  mq->message_buf = (const char *) &mq[1];
  mq->message_buf_size = msg_size;
  mq->timeout = GNUNET_TIME_relative_to_absolute (timeout);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Enqueueing %u bytes to send to peer %s\n",
              msg_size,
              GNUNET_i2s (target));
  GNUNET_CONTAINER_DLL_insert_tail (n->messages_head,
                                    n->messages_tail,
                                    mq);
  if (NULL != n->task)
    GNUNET_SCHEDULER_cancel (n->task);
  n->task = GNUNET_SCHEDULER_add_now (&master_task, n);
}


/**
 * Continuation called from our attempt to transmitted our
 * #GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_SYN to the specified @a
 * target.  Continue processing based on the @a result.  Specifically,
 * if we failed to transmit, discard the address we used.
 *
 * @param cls NULL
 * @param target which peer received the transmission
 * @param result #GNUNET_OK if sending worked
 * @param size_payload how many bytes of payload were sent (ignored)
 * @param size_on_wire how much bandwidth was consumed on the wire (ignored)
 */
static void
send_session_syn_cont (void *cls,
                       const struct GNUNET_PeerIdentity *target,
                       int result,
                       size_t size_payload,
                       size_t size_on_wire)
{
  struct NeighbourMapEntry *n;

  n = lookup_neighbour (target);
  if (NULL == n)
  {
    /* SYN continuation was called after neighbor was freed,
     * for example due to a time out for the state or the session
     * used was already terminated: nothing to do here... */
    return;
  }

  if ( (GNUNET_TRANSPORT_PS_SYN_SENT != n->state) &&
       (GNUNET_TRANSPORT_PS_RECONNECT_SENT != n->state) &&
       (GNUNET_TRANSPORT_PS_SWITCH_SYN_SENT != n->state))
  {
    /* SYN continuation was called after neighbor changed state,
     * for example due to a time out for the state or the session
     * used was already terminated: nothing to do here... */
    return;
  }
  if (GNUNET_OK == result)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Failed to send SYN message to peer `%s'\n"),
              GNUNET_i2s (target));
  switch (n->state) {
  case GNUNET_TRANSPORT_PS_SYN_SENT:
    /* Remove address and request an additional one */
    unset_primary_address (n);
    set_state_and_timeout (n,
                           GNUNET_TRANSPORT_PS_INIT_ATS,
                           GNUNET_TIME_relative_to_absolute (FAST_RECONNECT_TIMEOUT));
    break;
  case GNUNET_TRANSPORT_PS_RECONNECT_SENT:
    /* Remove address and request an additional one */
    unset_primary_address (n);
    set_state_and_timeout (n,
                           GNUNET_TRANSPORT_PS_RECONNECT_ATS,
                           GNUNET_TIME_relative_to_absolute (ATS_RESPONSE_TIMEOUT));
    break;
  case GNUNET_TRANSPORT_PS_SWITCH_SYN_SENT:
    /* Remove address and request and go back to primary address */
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop ("# Failed attempts to switch addresses (failed to send SYN CONT)"),
                              1,
                              GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Switch failed, cleaning up alternative address\n");
    free_address (&n->alternative_address);
    set_state_and_timeout (n,
                           GNUNET_TRANSPORT_PS_CONNECTED,
                           GNUNET_TIME_relative_to_absolute (ATS_RESPONSE_TIMEOUT));
    break;
  default:
    disconnect_neighbour (n);
    break;
  }
}


/**
 * Send a SYN message via the given address.
 *
 * @param na address to use
 */
static void
send_syn (struct NeighbourAddress *na)
{
  struct GNUNET_TRANSPORT_PluginFunctions *papi;
  struct TransportSynMessage connect_msg;
  struct NeighbourMapEntry *n;

  GNUNET_assert (NULL != na->session);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Sending SYN message to peer `%s' at %s\n",
              GNUNET_i2s (&na->address->peer),
              GST_plugins_a2s (na->address));

  papi = GST_plugins_find (na->address->transport_name);
  GNUNET_assert (NULL != papi);
  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop
                            ("# SYN messages sent"),
                            1, GNUNET_NO);
  na->connect_timestamp = GNUNET_TIME_absolute_get ();
  connect_msg.header.size = htons (sizeof (struct TransportSynMessage));
  connect_msg.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_SYN);
  connect_msg.reserved = htonl (0);
  connect_msg.timestamp = GNUNET_TIME_absolute_hton (na->connect_timestamp);
  if (-1 ==
      papi->send (papi->cls,
                  na->session,
                  (const char *) &connect_msg,
                  sizeof (struct TransportSynMessage),
                  UINT_MAX,
                  SETUP_CONNECTION_TIMEOUT,
                  &send_session_syn_cont, NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failed to transmit SYN message to %s\n"),
                GST_plugins_a2s (na->address));
    n = lookup_neighbour (&na->address->peer);
    if (NULL == n)
    {
      GNUNET_break (0);
      return;
    }
    switch (n->state) {
      case GNUNET_TRANSPORT_PS_SYN_SENT:
        /* Remove address and request and additional one */
        GNUNET_assert (na == &n->primary_address);
        unset_primary_address (n);
        set_state_and_timeout (n,
                               GNUNET_TRANSPORT_PS_INIT_ATS,
                               GNUNET_TIME_relative_to_absolute (FAST_RECONNECT_TIMEOUT));
        /* Hard failure to send the SYN message with this address:
           Destroy address and session */
        break;
      case GNUNET_TRANSPORT_PS_RECONNECT_SENT:
        /* Remove address and request an additional one */
        GNUNET_assert (na == &n->primary_address);
        unset_primary_address (n);
        set_state_and_timeout (n,
                               GNUNET_TRANSPORT_PS_RECONNECT_ATS,
                               GNUNET_TIME_relative_to_absolute (ATS_RESPONSE_TIMEOUT));
        break;
      case GNUNET_TRANSPORT_PS_SWITCH_SYN_SENT:
        GNUNET_assert (na == &n->alternative_address);
        GNUNET_STATISTICS_update (GST_stats,
                                  gettext_noop ("# Failed attempts to switch addresses (failed to send SYN)"),
                                  1,
                                  GNUNET_NO);
        /* Remove address and request an additional one */
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Switch failed, cleaning up alternative address\n");
        free_address (&n->alternative_address);
        set_state_and_timeout (n,
                               GNUNET_TRANSPORT_PS_CONNECTED,
                               GNUNET_TIME_relative_to_absolute (ATS_RESPONSE_TIMEOUT));
        break;
      default:
        GNUNET_break (0);
        disconnect_neighbour (n);
        break;
    }
    return;
  }
  GST_neighbours_notify_data_sent (na->address,
                                   na->session,
                                   sizeof (struct TransportSynMessage));
}


/**
 * Continuation called from our attempt to transmitted our
 * #GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_SYN_ACK to the specified @a
 * target.  Continue processing based on the @a result.  Specifically,
 * if we failed to transmit, discard the address we used.
 *
 * @param cls NULL
 * @param target which peer received the transmission
 * @param result #GNUNET_OK if sending worked
 * @param size_payload how many bytes of payload were sent (ignored)
 * @param size_on_wire how much bandwidth was consumed on the wire (ignored)
 */
static void
send_session_syn_ack_cont (void *cls,
                           const struct GNUNET_PeerIdentity *target,
                           int result,
                           size_t size_payload,
                           size_t size_on_wire)
{
  struct NeighbourMapEntry *n;

  n = lookup_neighbour (target);
  if (NULL == n)
  {
    /* SYN_ACK continuation was called after neighbor was freed,
     * for example due to a time out for the state or the session
     * used was already terminated: nothing to do here... */
    return;
  }

  if (GNUNET_TRANSPORT_PS_SYN_RECV_ACK != n->state)
  {
    /* SYN_ACK continuation was called after neighbor changed state,
     * for example due to a time out for the state or the session
     * used was already terminated: nothing to do here... */
    return;
  }
  if (GNUNET_OK == result)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
            _("Failed to send SYN_ACK message to peer `%s' using address `%s'\n"),
            GNUNET_i2s (target),
            GST_plugins_a2s (n->primary_address.address));

  /* Remove address and request and additional one */
  /* FIXME: what if the neighbour's primary address
     changed in the meantime? Might want to instead
     pass "something" around in closure to be sure. */
  unset_primary_address (n);
  n->ack_state = ACK_SEND_SYN_ACK;
  set_state_and_timeout (n,
                         GNUNET_TRANSPORT_PS_SYN_RECV_ATS,
                         GNUNET_TIME_relative_to_absolute (ATS_RESPONSE_TIMEOUT));
}


/**
 * Send a SYN_ACK message via the given address.
 *
 * @param na address and session to use
 * @param timestamp timestamp to use for the ACK message
 * @return #GNUNET_SYSERR if sending immediately failed, #GNUNET_OK otherwise
 */
static void
send_syn_ack_message (struct NeighbourAddress *na,
                      struct GNUNET_TIME_Absolute timestamp)
{
  const struct GNUNET_HELLO_Address *address = na->address;
  struct Session *session = na->session;
  struct GNUNET_TRANSPORT_PluginFunctions *papi;
  struct TransportSynMessage connect_msg;
  struct NeighbourMapEntry *n;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Sending SYN_ACK to peer `%s'\n",
              GNUNET_i2s (&address->peer));

  if (NULL == (papi = GST_plugins_find (address->transport_name)))
  {
    GNUNET_break (0);
    return;
  }
  if (NULL == session)
    session = papi->get_session (papi->cls,
                                 address);
  if (NULL == session)
  {
    GNUNET_break (0);
    return;
  }
  GST_ats_new_session (address,
                       session);
  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop
                            ("# SYN_ACK messages sent"),
                            1, GNUNET_NO);
  connect_msg.header.size = htons (sizeof (struct TransportSynMessage));
  connect_msg.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_SYN_ACK);
  connect_msg.reserved = htonl (0);
  connect_msg.timestamp = GNUNET_TIME_absolute_hton (timestamp);

  if (GNUNET_SYSERR ==
      papi->send (papi->cls,
                  session,
                  (const char *) &connect_msg,
                  sizeof (struct TransportSynMessage),
                  UINT_MAX,
                  GNUNET_TIME_UNIT_FOREVER_REL,
                  &send_session_syn_ack_cont, NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failed to transmit SYN_ACK message to %s\n"),
                GST_plugins_a2s (address));

    n = lookup_neighbour (&address->peer);
    if (NULL == n)
    {
      GNUNET_break (0);
      return;
    }
    /* Remove address and request and additional one */
    unset_primary_address (n);
    n->ack_state = ACK_SEND_SYN_ACK;
    set_state_and_timeout (n,
                           GNUNET_TRANSPORT_PS_SYN_RECV_ATS,
                           GNUNET_TIME_relative_to_absolute (ATS_RESPONSE_TIMEOUT));
    return;
  }
}


/**
 * Function called by the bandwidth tracker for a peer whenever
 * the tracker's state changed such that we need to recalculate
 * the delay for flow control.  We calculate the latest delay
 * and inform the plugin (if applicable).
 *
 * @param cls the `struct NeighbourMapEntry` to update calculations for
 */
static void
inbound_bw_tracker_update (void *cls)
{
  struct NeighbourMapEntry *n = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *papi;
  struct GNUNET_TIME_Relative delay;
  int do_forward;

  if (NULL == n->primary_address.address)
    return; /* not active, ignore */
  papi = GST_plugins_find (n->primary_address.address->transport_name);
  GNUNET_assert (NULL != papi);
  if (NULL == papi->update_inbound_delay)
    return;
  delay = GST_neighbours_calculate_receive_delay (&n->id,
                                                  0,
                                                  &do_forward);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "New inbound delay for peer `%s' is %llu ms\n",
              GNUNET_i2s (&n->id),
              delay.rel_value_us / 1000);
  papi->update_inbound_delay (papi->cls,
                              &n->id,
                              n->primary_address.session,
                              delay);
}


/**
 * Create a fresh entry in the neighbour map for the given peer
 *
 * @param peer peer to create an entry for
 * @return new neighbour map entry
 */
static struct NeighbourMapEntry *
setup_neighbour (const struct GNUNET_PeerIdentity *peer)
{
  struct NeighbourMapEntry *n;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Creating new neighbour entry for `%s'\n",
	      GNUNET_i2s (peer));
  n = GNUNET_new (struct NeighbourMapEntry);
  n->id = *peer;
  n->ack_state = ACK_UNDEFINED;
  n->last_util_transmission = GNUNET_TIME_absolute_get();
  n->neighbour_receive_quota = GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT;
  GNUNET_BANDWIDTH_tracker_init (&n->in_tracker,
                                 &inbound_bw_tracker_update,
                                 n,
                                 GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT,
                                 MAX_BANDWIDTH_CARRY_S);
  n->task = GNUNET_SCHEDULER_add_now (&master_task, n);
  set_state_and_timeout (n,
                         GNUNET_TRANSPORT_PS_NOT_CONNECTED,
                         GNUNET_TIME_UNIT_FOREVER_ABS);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multipeermap_put (neighbours,
                                                    &n->id, n,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  n->suggest_handle = GNUNET_ATS_connectivity_suggest (GST_ats_connect,
                                                       peer);

  return n;
}


/**
 * Entry in a DLL we use to keep track of pending blacklist checks.
 */
struct BlacklistCheckSwitchContext
{
  /**
   * DLL prev pointer.
   */
  struct BlacklistCheckSwitchContext *prev;

  /**
   * DLL next pointer.
   */
  struct BlacklistCheckSwitchContext *next;

  /**
   * Handle to the blacklist check we are performing.
   */
  struct GST_BlacklistCheck *blc;

  /**
   * Inbound bandwidth that was assigned to @e address.
   */
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in;

  /**
   * Outbound bandwidth that was assigned to @e address.
   */
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out;
};


/**
 * Black list check result for try_connect call
 * If connection to the peer is allowed request adddress and
 *
 * @param cls blc_ctx bl context
 * @param peer the peer
 * @param address address associated with the request
 * @param session session associated with the request
 * @param result #GNUNET_OK if the connection is allowed,
 *               #GNUNET_NO if not,
 *               #GNUNET_SYSERR if operation was aborted
 */
static void
try_connect_bl_check_cont (void *cls,
                           const struct GNUNET_PeerIdentity *peer,
			   const struct GNUNET_HELLO_Address *address,
			   struct Session *session,
                           int result)
{
  struct BlacklistCheckSwitchContext *blc_ctx = cls;
  struct NeighbourMapEntry *n;

  GNUNET_CONTAINER_DLL_remove (pending_bc_head,
                               pending_bc_tail,
                               blc_ctx);
  GNUNET_free (blc_ctx);
  if (GNUNET_OK != result)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("Blacklisting disapproved to connect to peer `%s'\n"),
                GNUNET_i2s (peer));
    return;
  }

  /* Setup a new neighbour */
  if (NULL != lookup_neighbour(peer))
    return; /* The neighbor was created in the meantime while waited for BL clients */

  n = setup_neighbour (peer);

  /* Request address suggestions for this peer */
  set_state_and_timeout (n,
                         GNUNET_TRANSPORT_PS_INIT_ATS,
                         GNUNET_TIME_relative_to_absolute (ATS_RESPONSE_TIMEOUT));
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
  struct GST_BlacklistCheck *blc;
  struct BlacklistCheckSwitchContext *blc_ctx;

  if (NULL == neighbours)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Asked to connect to peer `%s' during shutdown\n",
                GNUNET_i2s (target));
    return; /* during shutdown, do nothing */
  }
  n = lookup_neighbour (target);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      "Asked to connect to peer `%s' (state: %s)\n",
              GNUNET_i2s (target),
              (NULL != n) ? GNUNET_TRANSPORT_ps2s(n->state) : "NEW PEER");
  if (NULL != n)
  {
    switch (n->state)
    {
    case GNUNET_TRANSPORT_PS_NOT_CONNECTED:
      /* this should not be possible */
      GNUNET_break (0);
      free_neighbour (n);
      break;
    case GNUNET_TRANSPORT_PS_INIT_ATS:
    case GNUNET_TRANSPORT_PS_SYN_SENT:
    case GNUNET_TRANSPORT_PS_SYN_RECV_ATS:
    case GNUNET_TRANSPORT_PS_SYN_RECV_ACK:
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Ignoring request to try to connect to `%s', already trying!\n",
		  GNUNET_i2s (target));
      return; /* already trying */
    case GNUNET_TRANSPORT_PS_CONNECTED:
    case GNUNET_TRANSPORT_PS_RECONNECT_ATS:
    case GNUNET_TRANSPORT_PS_RECONNECT_SENT:
    case GNUNET_TRANSPORT_PS_SWITCH_SYN_SENT:
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Ignoring request to try to connect, already connected to `%s'!\n",
		  GNUNET_i2s (target));
      return; /* already connected */
    case GNUNET_TRANSPORT_PS_DISCONNECT:
      /* get rid of remains, ready to re-try immediately */
      free_neighbour (n);
      break;
    case GNUNET_TRANSPORT_PS_DISCONNECT_FINISHED:
      /* should not be possible */
      GNUNET_assert (0);
      return;
    default:
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Unhandled state `%s'\n",
                  GNUNET_TRANSPORT_ps2s (n->state));
      GNUNET_break (0);
      free_neighbour (n);
      break;
    }
  }

  /* Do blacklist check if connecting to this peer is allowed */
  blc_ctx = GNUNET_new (struct BlacklistCheckSwitchContext);
  GNUNET_CONTAINER_DLL_insert (pending_bc_head,
                               pending_bc_tail,
                               blc_ctx);

  if (NULL !=
      (blc = GST_blacklist_test_allowed (target,
                                         NULL,
                                         &try_connect_bl_check_cont,
                                         blc_ctx,
					 NULL,
					 NULL)))
  {
    blc_ctx->blc = blc;
  }
}


/**
 * We received a 'SYN' message from the other peer.
 * Consider switching to it.
 *
 * @param message possibly a `struct TransportSynMessage` (check format)
 * @param peer identity of the peer to switch the address for
 * @return #GNUNET_OK if the message was fine, #GNUNET_SYSERR on serious error
 */
int
GST_neighbours_handle_session_syn (const struct GNUNET_MessageHeader *message,
                                   const struct GNUNET_PeerIdentity *peer)
{
  const struct TransportSynMessage *scm;
  struct NeighbourMapEntry *n;
  struct GNUNET_TIME_Absolute ts;

  if (ntohs (message->size) != sizeof (struct TransportSynMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop
                            ("# SYN messages received"),
                            1, GNUNET_NO);
  if (NULL == neighbours)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("SYN request from peer `%s' ignored due impending shutdown\n"),
                GNUNET_i2s (peer));
    return GNUNET_OK; /* we're shutting down */
  }
  scm = (const struct TransportSynMessage *) message;
  GNUNET_break_op (0 == ntohl (scm->reserved));
  ts = GNUNET_TIME_absolute_ntoh (scm->timestamp);
  n = lookup_neighbour (peer);
  if (NULL == n)
  {
    /* This is a new neighbour and set to not connected */
    n = setup_neighbour (peer);
  }

  /* Remember this SYN message in neighbour */
  n->ack_state = ACK_SEND_SYN_ACK;
  n->connect_ack_timestamp = ts;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Received SYN for peer `%s' in state %s/%s\n",
              GNUNET_i2s (peer),
              GNUNET_TRANSPORT_ps2s (n->state),
              print_ack_state (n->ack_state));

  switch (n->state)
  {
  case GNUNET_TRANSPORT_PS_NOT_CONNECTED:
    /* Request an address from ATS to send SYN_ACK to this peer */
    set_state_and_timeout (n,
                           GNUNET_TRANSPORT_PS_SYN_RECV_ATS,
                           GNUNET_TIME_relative_to_absolute (ATS_RESPONSE_TIMEOUT));
    break;
  case GNUNET_TRANSPORT_PS_INIT_ATS:
    /* SYN message takes priority over us asking ATS for address:
     * Wait for ATS to suggest an address and send SYN_ACK */
    set_state_and_timeout (n,
                           GNUNET_TRANSPORT_PS_SYN_RECV_ATS,
                           GNUNET_TIME_relative_to_absolute (ATS_RESPONSE_TIMEOUT));
    break;
  case GNUNET_TRANSPORT_PS_SYN_RECV_ATS:
    /* We already wait for an address to send an SYN_ACK */
    break;
  case GNUNET_TRANSPORT_PS_SYN_SENT:
  case GNUNET_TRANSPORT_PS_SYN_RECV_ACK:
    /* Send ACK immediately */
    n->ack_state = ACK_SEND_ACK;
    send_syn_ack_message (&n->primary_address,
                          ts);
    break;
  case GNUNET_TRANSPORT_PS_CONNECTED:
    /* we are already connected and can thus send the ACK immediately */
    GNUNET_assert (NULL != n->primary_address.address);
    GNUNET_assert (NULL != n->primary_address.session);
    n->ack_state = ACK_SEND_ACK;
    send_syn_ack_message (&n->primary_address,
                          ts);
    break;
  case GNUNET_TRANSPORT_PS_RECONNECT_ATS:
    /* We wait for ATS address suggestion */
    break;
  case GNUNET_TRANSPORT_PS_RECONNECT_SENT:
    /* We received a SYN message while waiting for a SYN_ACK in fast
     * reconnect. Send SYN_ACK immediately */
    n->ack_state = ACK_SEND_ACK;
    send_syn_ack_message (&n->primary_address,
                          n->connect_ack_timestamp);
    break;
  case GNUNET_TRANSPORT_PS_SWITCH_SYN_SENT:
    /* We are already connected and can thus send the ACK immediately;
       still, it can never hurt to have an alternative address, so also
       tell ATS  about it */
    GNUNET_assert (NULL != n->primary_address.address);
    GNUNET_assert (NULL != n->primary_address.session);
    n->ack_state = ACK_SEND_ACK;
    send_syn_ack_message (&n->primary_address,
                          ts);
    break;
  case GNUNET_TRANSPORT_PS_DISCONNECT:
    /* Get rid of remains and re-try */
    free_neighbour (n);
    n = setup_neighbour (peer);
    /* Remember the SYN time stamp for ACK message */
    n->ack_state = ACK_SEND_SYN_ACK;
    n->connect_ack_timestamp = ts;
    /* Request an address for the peer */
    set_state_and_timeout (n,
                           GNUNET_TRANSPORT_PS_SYN_RECV_ATS,
                           GNUNET_TIME_relative_to_absolute (ATS_RESPONSE_TIMEOUT));
    break;
  case GNUNET_TRANSPORT_PS_DISCONNECT_FINISHED:
    /* should not be possible */
    GNUNET_assert (0);
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unhandled state `%s'\n",
                GNUNET_TRANSPORT_ps2s (n->state));
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Check if the given @a address is the same that we are already
 * using for the respective neighbour. If so, update the bandwidth
 * assignment and possibly the session and return #GNUNET_OK.
 * If the new address is different from what the neighbour is
 * using right now, return #GNUNET_NO.
 *
 * @param address address of the other peer,
 * @param session session to use or NULL if transport should initiate a session
 * @param bandwidth_in inbound quota to be used when connection is up,
 * 	0 to disconnect from peer
 * @param bandwidth_out outbound quota to be used when connection is up,
 * 	0 to disconnect from peer
 * @return #GNUNET_OK if we were able to just update the bandwidth and session,
 *         #GNUNET_NO if more extensive changes are required (address changed)
 */
static int
try_run_fast_ats_update (const struct GNUNET_HELLO_Address *address,
                         struct Session *session,
                         struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
                         struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out)
{
  struct NeighbourMapEntry *n;
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_min;

  n = lookup_neighbour (&address->peer);
  if ( (NULL == n) ||
       (NULL == n->primary_address.address) ||
       (0 != GNUNET_HELLO_address_cmp (address,
                                       n->primary_address.address)) )
    return GNUNET_NO;
  /* We are not really switching addresses, but merely adjusting
     session and/or bandwidth, can do fast ATS update! */
  if (session != n->primary_address.session)
  {
    /* switch to a different session, but keeping same address; could
       happen if there is a 2nd inbound connection */
    n->primary_address.session = session;
    GNUNET_assert (GNUNET_YES ==
                   GST_ats_is_known (n->primary_address.address,
                                     n->primary_address.session));
  }
  if (n->primary_address.bandwidth_in.value__ != bandwidth_in.value__)
  {
    n->primary_address.bandwidth_in = bandwidth_in;
    GST_neighbours_set_incoming_quota (&address->peer,
                                       bandwidth_in);
  }
  if (n->primary_address.bandwidth_out.value__ != bandwidth_out.value__)
  {
    n->primary_address.bandwidth_out = bandwidth_out;
    bandwidth_min = GNUNET_BANDWIDTH_value_min (bandwidth_out,
                                                n->neighbour_receive_quota);
    send_outbound_quota_to_clients (&address->peer,
                                    bandwidth_min);
  }
  return GNUNET_OK;
}


/**
 * We've been asked to switch addresses, and just now got the result
 * from the blacklist check to see if this is allowed.
 *
 * @param cls the `struct BlacklistCheckSwitchContext` with
 *        the information about the future address
 * @param peer the peer we may switch addresses on
 * @param address address associated with the request
 * @param session session associated with the request
 * @param result #GNUNET_OK if the connection is allowed,
 *               #GNUNET_NO if not,
 *               #GNUNET_SYSERR if operation was aborted
 */
static void
switch_address_bl_check_cont (void *cls,
                              const struct GNUNET_PeerIdentity *peer,
			      const struct GNUNET_HELLO_Address *address,
			      struct Session *session,
                              int result)
{
  struct BlacklistCheckSwitchContext *blc_ctx = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *papi;
  struct NeighbourMapEntry *n;

  if (GNUNET_SYSERR == result)
    goto cleanup;

  papi = GST_plugins_find (address->transport_name);
  GNUNET_assert (NULL != papi);

  if (GNUNET_NO == result)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Blacklist denied to switch to suggested address `%s' session %p for peer `%s'\n",
                GST_plugins_a2s (address),
		session,
                GNUNET_i2s (peer));
    GNUNET_STATISTICS_update (GST_stats,
                              "# ATS suggestions ignored (blacklist denied)",
                              1,
                              GNUNET_NO);
    papi->disconnect_session (papi->cls,
			      session);
    if (GNUNET_YES !=
	GNUNET_HELLO_address_check_option (address,
					   GNUNET_HELLO_ADDRESS_INFO_INBOUND))
      GST_ats_block_address (address,
			     NULL);
    goto cleanup;
  }


  if (NULL == session)
  {
    /* need to create a session, ATS only gave us an address */
    session = papi->get_session (papi->cls,
				 address);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Obtained new session for peer `%s' and  address '%s': %p\n",
                GNUNET_i2s (&address->peer),
                GST_plugins_a2s (address),
                session);
    if (NULL != session)
      GST_ats_new_session (address,
                           session);
  }
  if (NULL == session)
  {
    /* session creation failed, bad!, fail! */
    GNUNET_STATISTICS_update (GST_stats,
                              "# ATS suggestions ignored (failed to create session)",
                              1,
                              GNUNET_NO);
    /* No session could be obtained, remove blacklist check and clean up */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Failed to obtain new session for peer `%s' and address '%s'\n",
                GNUNET_i2s (&address->peer),
                GST_plugins_a2s (address));
    GST_ats_block_address (address,
                           session);
    goto cleanup;
  }

  /* We did this check already before going into blacklist, but
     it is theoretically possible that the situation changed in
     the meantime, hence we check again here */
  if (GNUNET_OK ==
      try_run_fast_ats_update (address,
                               session,
                               blc_ctx->bandwidth_in,
                               blc_ctx->bandwidth_out))
    goto cleanup; /* was just a minor update, we're done */

  /* check if we also need to setup the neighbour entry */
  if (NULL == (n = lookup_neighbour (peer)))
  {
    n = setup_neighbour (peer);
    n->state = GNUNET_TRANSPORT_PS_INIT_ATS;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Peer `%s' switches to address `%s'\n",
              GNUNET_i2s (&address->peer),
              GST_plugins_a2s (address));

  switch (n->state)
  {
  case GNUNET_TRANSPORT_PS_NOT_CONNECTED:
    GNUNET_break (0);
    GST_ats_block_address (address,
                           session);
    free_neighbour (n);
    return;
  case GNUNET_TRANSPORT_PS_INIT_ATS:
    /* We requested an address and ATS suggests one:
     * set primary address and send SYN message*/
    set_primary_address (n,
                         address,
                         session,
                         blc_ctx->bandwidth_in,
                         blc_ctx->bandwidth_out);
    if (ACK_SEND_SYN_ACK == n->ack_state)
    {
      /* Send pending SYN_ACK message */
      n->ack_state = ACK_SEND_ACK;
      send_syn_ack_message (&n->primary_address,
                            n->connect_ack_timestamp);
    }
    set_state_and_timeout (n,
                           GNUNET_TRANSPORT_PS_SYN_SENT,
                           GNUNET_TIME_relative_to_absolute (SETUP_CONNECTION_TIMEOUT));
    send_syn (&n->primary_address);
    break;
  case GNUNET_TRANSPORT_PS_SYN_SENT:
    /* ATS suggested a new address while waiting for an SYN_ACK:
     * Switch and send new SYN */
    /* ATS suggests a different address, switch again */
    set_primary_address (n,
                         address,
                         session,
                         blc_ctx->bandwidth_in,
                         blc_ctx->bandwidth_out);
    if (ACK_SEND_SYN_ACK == n->ack_state)
    {
      /* Send pending SYN_ACK message */
      n->ack_state = ACK_SEND_ACK;
      send_syn_ack_message (&n->primary_address,
                            n->connect_ack_timestamp);
    }
    set_state_and_timeout (n,
                           GNUNET_TRANSPORT_PS_SYN_SENT,
                           GNUNET_TIME_relative_to_absolute (SETUP_CONNECTION_TIMEOUT));
    send_syn (&n->primary_address);
    break;
  case GNUNET_TRANSPORT_PS_SYN_RECV_ATS:
    /* We requested an address and ATS suggests one:
     * set primary address and send SYN_ACK message*/
    set_primary_address (n,
                         address,
                         session,
                         blc_ctx->bandwidth_in,
                         blc_ctx->bandwidth_out);
    /* Send an ACK message as a response to the SYN msg */
    set_state_and_timeout (n,
                           GNUNET_TRANSPORT_PS_SYN_RECV_ACK,
                           GNUNET_TIME_relative_to_absolute (SETUP_CONNECTION_TIMEOUT));
    send_syn_ack_message (&n->primary_address,
                          n->connect_ack_timestamp);
    if ( (ACK_SEND_SYN_ACK == n->ack_state) ||
         (ACK_UNDEFINED == n->ack_state) )
      n->ack_state = ACK_SEND_ACK;
    break;
  case GNUNET_TRANSPORT_PS_SYN_RECV_ACK:
    /* ATS asks us to switch while we were trying to connect; switch to new
       address and check blacklist again */
    if ( (ACK_SEND_SYN_ACK == n->ack_state) )
    {
      n->ack_state = ACK_SEND_ACK;
      send_syn_ack_message (&n->primary_address,
                            n->connect_ack_timestamp);
    }
    set_primary_address (n,
			 address,
                         session,
                         blc_ctx->bandwidth_in,
                         blc_ctx->bandwidth_out);
    set_state_and_timeout (n,
                           GNUNET_TRANSPORT_PS_SYN_RECV_ACK,
                           GNUNET_TIME_relative_to_absolute (SETUP_CONNECTION_TIMEOUT));
    break;
  case GNUNET_TRANSPORT_PS_CONNECTED:
    GNUNET_assert (NULL != n->primary_address.address);
    GNUNET_assert (NULL != n->primary_address.session);
    GNUNET_break (n->primary_address.session != session);
    /* ATS asks us to switch a life connection; see if we can get
       a SYN_ACK on it before we actually do this! */
    set_alternative_address (n,
                             address,
                             session,
                             blc_ctx->bandwidth_in,
                             blc_ctx->bandwidth_out);
    set_state_and_timeout (n,
                           GNUNET_TRANSPORT_PS_SWITCH_SYN_SENT,
                           GNUNET_TIME_relative_to_absolute (SETUP_CONNECTION_TIMEOUT));
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop ("# Attempts to switch addresses"),
                              1,
                              GNUNET_NO);
    send_syn (&n->alternative_address);
    break;
  case GNUNET_TRANSPORT_PS_RECONNECT_ATS:
    set_primary_address (n,
                         address,
                         session,
                         blc_ctx->bandwidth_in,
                         blc_ctx->bandwidth_out);
    if (ACK_SEND_SYN_ACK == n->ack_state)
    {
      /* Send pending SYN_ACK message */
      n->ack_state = ACK_SEND_ACK;
      send_syn_ack_message (&n->primary_address,
                            n->connect_ack_timestamp);
    }
    set_state_and_timeout (n,
                           GNUNET_TRANSPORT_PS_RECONNECT_SENT,
                           GNUNET_TIME_relative_to_absolute (FAST_RECONNECT_TIMEOUT));
    send_syn (&n->primary_address);
    break;
  case GNUNET_TRANSPORT_PS_RECONNECT_SENT:
    /* ATS asks us to switch while we were trying to reconnect; switch to new
       address and send SYN again */
    set_primary_address (n,
                         address,
                         session,
                         blc_ctx->bandwidth_in,
                         blc_ctx->bandwidth_out);
    set_state_and_timeout (n,
                           GNUNET_TRANSPORT_PS_RECONNECT_SENT,
                           GNUNET_TIME_relative_to_absolute (FAST_RECONNECT_TIMEOUT));
    send_syn (&n->primary_address);
    break;
  case GNUNET_TRANSPORT_PS_SWITCH_SYN_SENT:
    if ( (0 == GNUNET_HELLO_address_cmp (n->primary_address.address,
                                         address)) &&
         (n->primary_address.session == session) )
    {
      /* ATS switches back to still-active session */
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "ATS double-switched, cleaning up alternative address\n");
      free_address (&n->alternative_address);
      set_state_and_timeout (n,
                             GNUNET_TRANSPORT_PS_CONNECTED,
                             n->timeout);
      break;
    }
    /* ATS asks us to switch a life connection, send */
    set_alternative_address (n,
			     address,
                             session,
                             blc_ctx->bandwidth_in,
                             blc_ctx->bandwidth_out);
    set_state_and_timeout (n,
                           GNUNET_TRANSPORT_PS_SWITCH_SYN_SENT,
                           GNUNET_TIME_relative_to_absolute (SETUP_CONNECTION_TIMEOUT));
    send_syn (&n->alternative_address);
    break;
  case GNUNET_TRANSPORT_PS_DISCONNECT:
    /* not going to switch addresses while disconnecting */
    GNUNET_STATISTICS_update (GST_stats,
                              "# ATS suggestion ignored (disconnecting)",
                              1,
                              GNUNET_NO);
    return;
  case GNUNET_TRANSPORT_PS_DISCONNECT_FINISHED:
    GNUNET_assert (0);
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unhandled state `%s'\n",
                GNUNET_TRANSPORT_ps2s (n->state));
    GNUNET_break (0);
    break;
  }
 cleanup:
  GNUNET_CONTAINER_DLL_remove (pending_bc_head,
                               pending_bc_tail,
                               blc_ctx);
  GNUNET_free (blc_ctx);
}


/**
 * For the given peer, switch to this address.
 *
 * Before accepting this addresses and actively using it, a blacklist check
 * is performed.
 *
 * If any check fails or the suggestion can somehow not be followed, we
 * MUST call #GST_ats_block_address() to tell ATS that the suggestion
 * could not be satisfied and force ATS to do something else.
 *
 * @param address address of the other peer,
 * @param session session to use or NULL if transport should initiate a session
 * @param bandwidth_in inbound quota to be used when connection is up,
 * 	0 to disconnect from peer
 * @param bandwidth_out outbound quota to be used when connection is up,
 * 	0 to disconnect from peer
 */
void
GST_neighbours_switch_to_address (const struct GNUNET_HELLO_Address *address,
				  struct Session *session,
				  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
				  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out)
{
  struct GST_BlacklistCheck *blc;
  struct BlacklistCheckSwitchContext *blc_ctx;

  GNUNET_assert (NULL != address->transport_name);
  if (GNUNET_OK ==
      try_run_fast_ats_update (address,
                               session,
                               bandwidth_in,
                               bandwidth_out))
    return;

  /* Check if plugin is available */
  if (NULL == (GST_plugins_find (address->transport_name)))
  {
    /* we don't have the plugin for this address */
    GNUNET_break (0);
    GST_ats_block_address (address,
                           session);
    return;
  }
  if ((NULL == session) &&
      (GNUNET_HELLO_address_check_option (address,
                                          GNUNET_HELLO_ADDRESS_INFO_INBOUND)))
  {
    /* This is a inbound address and we do not have a session to use! */
    GNUNET_break (0);
    GST_ats_block_address (address,
                           session);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "ATS suggests address '%s' for peer `%s' at %u/%u speed\n",
	      GST_plugins_a2s (address),
	      GNUNET_i2s (&address->peer),
              (unsigned int) ntohl (bandwidth_in.value__),
              (unsigned int) ntohl (bandwidth_out.value__));

  /* Perform blacklist check */
  blc_ctx = GNUNET_new (struct BlacklistCheckSwitchContext);
  blc_ctx->bandwidth_in = bandwidth_in;
  blc_ctx->bandwidth_out = bandwidth_out;
  GNUNET_CONTAINER_DLL_insert (pending_bc_head,
                               pending_bc_tail,
                               blc_ctx);
  if (NULL != (blc = GST_blacklist_test_allowed (&address->peer,
                                                 address->transport_name,
                                                 &switch_address_bl_check_cont,
                                                 blc_ctx,
						 address,
						 session)))
  {
    blc_ctx->blc = blc;
  }
}


/**
 * Function called to send network utilization data to ATS for
 * each active connection.
 *
 * @param cls NULL
 * @param key peer we send utilization data for
 * @param value the `struct NeighbourMapEntry *` with data to send
 * @return #GNUNET_OK (continue to iterate)
 */
static int
send_utilization_data (void *cls,
                       const struct GNUNET_PeerIdentity *key,
                       void *value)
{
  struct NeighbourMapEntry *n = value;
  uint32_t bps_in;
  uint32_t bps_out;
  struct GNUNET_TIME_Relative delta;

  if ( (GNUNET_YES != test_connected (n)) ||
       (NULL == n->primary_address.address) )
    return GNUNET_OK;
  delta = GNUNET_TIME_absolute_get_difference (n->last_util_transmission,
                                               GNUNET_TIME_absolute_get ());
  bps_in = 0;
  if ((0 != n->util_total_bytes_recv) && (0 != delta.rel_value_us))
    bps_in =  (1000LL * 1000LL *  n->util_total_bytes_recv) / (delta.rel_value_us);
  bps_out = 0;
  if ((0 != n->util_total_bytes_sent) && (0 != delta.rel_value_us))
    bps_out = (1000LL * 1000LL * n->util_total_bytes_sent) / delta.rel_value_us;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s' total: received %u Bytes/s, sent %u Bytes/s\n",
              GNUNET_i2s (key),
              bps_in,
              bps_out);
  GST_ats_update_utilization (n->primary_address.address,
                              bps_in,
                              bps_out);
  n->util_total_bytes_recv = 0;
  n->util_total_bytes_sent = 0;
  n->last_util_transmission = GNUNET_TIME_absolute_get ();
  return GNUNET_OK;
}


/**
 * Task transmitting utilization in a regular interval
 *
 * @param cls the 'struct NeighbourMapEntry' for which we are running
 * @param tc scheduler context (unused)
 */
static void
utilization_transmission (void *cls,
                          const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  util_transmission_tk = NULL;
  GNUNET_CONTAINER_multipeermap_iterate (neighbours,
                                         &send_utilization_data,
                                         NULL);
  util_transmission_tk
    = GNUNET_SCHEDULER_add_delayed (UTIL_TRANSMISSION_INTERVAL,
                                    &utilization_transmission,
                                    NULL);
}


/**
 * Track information about data we received from the
 * given address (used to notify ATS about our utilization
 * of allocated resources).
 *
 * @param address the address we got data from
 * @param message the message we received (really only the size is used)
 */
void
GST_neighbours_notify_data_recv (const struct GNUNET_HELLO_Address *address,
                                 const struct GNUNET_MessageHeader *message)
{
  struct NeighbourMapEntry *n;

  n = lookup_neighbour (&address->peer);
  if (NULL == n)
    return;
  n->util_total_bytes_recv += ntohs (message->size);
}


/**
 * Track information about data we transmitted using the given @a
 * address and @a session (used to notify ATS about our utilization of
 * allocated resources).
 *
 * @param address the address we transmitted data to
 * @param session session we used to transmit data
 * @param message the message we sent (really only the size is used)
 */
void
GST_neighbours_notify_data_sent (const struct GNUNET_HELLO_Address *address,
                                 struct Session *session,
                                 size_t size)
{
  struct NeighbourMapEntry *n;

  n = lookup_neighbour (&address->peer);
  if (NULL == n)
      return;
  if (n->primary_address.session != session)
    return;
  n->util_total_bytes_sent += size;
}


/**
 * Master task run for every neighbour.  Performs all of the time-related
 * activities (keep alive, send next message, disconnect if idle, finish
 * clean up after disconnect).
 *
 * @param cls the 'struct NeighbourMapEntry' for which we are running
 * @param tc scheduler context (unused)
 */
static void
master_task (void *cls,
	     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct NeighbourMapEntry *n = cls;
  struct GNUNET_TIME_Relative delay;

  n->task = NULL;
  delay = GNUNET_TIME_absolute_get_remaining (n->timeout);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Master task runs for neighbour `%s' in state %s with timeout in %s\n",
	      GNUNET_i2s (&n->id),
	      GNUNET_TRANSPORT_ps2s(n->state),
	      GNUNET_STRINGS_relative_time_to_string (delay,
						      GNUNET_YES));
  switch (n->state)
  {
  case GNUNET_TRANSPORT_PS_NOT_CONNECTED:
    /* invalid state for master task, clean up */
    GNUNET_break (0);
    free_neighbour (n);
    return;
  case GNUNET_TRANSPORT_PS_INIT_ATS:
    if (0 == delay.rel_value_us)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  "Connection to `%s' timed out waiting for ATS to provide address\n",
		  GNUNET_i2s (&n->id));
      free_neighbour (n);
      return;
    }
    break;
  case GNUNET_TRANSPORT_PS_SYN_SENT:
    if (0 == delay.rel_value_us)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  "Connection to `%s' timed out waiting for other peer to send SYN_ACK\n",
		  GNUNET_i2s (&n->id));
      /* Remove address and request and additional one */
      unset_primary_address (n);
      set_state_and_timeout (n,
                             GNUNET_TRANSPORT_PS_INIT_ATS,
                             GNUNET_TIME_relative_to_absolute (ATS_RESPONSE_TIMEOUT));
      return;
    }
    break;
  case GNUNET_TRANSPORT_PS_SYN_RECV_ATS:
    if (0 == delay.rel_value_us)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  "Connection to `%s' timed out waiting ATS to provide address to use for SYN_ACK\n",
		  GNUNET_i2s (&n->id));
      free_neighbour (n);
      return;
    }
    break;
  case GNUNET_TRANSPORT_PS_SYN_RECV_ACK:
    if (0 == delay.rel_value_us)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  "Connection to `%s' timed out waiting for other peer to send ACK\n",
		  GNUNET_i2s (&n->id));
      disconnect_neighbour (n);
      return;
    }
    break;
  case GNUNET_TRANSPORT_PS_CONNECTED:
    if (0 == delay.rel_value_us)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  "Connection to `%s' timed out, missing KEEPALIVE_RESPONSEs\n",
		  GNUNET_i2s (&n->id));
      disconnect_neighbour (n);
      return;
    }
    try_transmission_to_peer (n);
    send_keepalive (n);
    break;
  case GNUNET_TRANSPORT_PS_RECONNECT_ATS:
    if (0 == delay.rel_value_us)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  "Connection to `%s' timed out, waiting for ATS replacement address\n",
		  GNUNET_i2s (&n->id));
      disconnect_neighbour (n);
      return;
    }
    break;
  case GNUNET_TRANSPORT_PS_RECONNECT_SENT:
    if (0 == delay.rel_value_us)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  "Connection to `%s' timed out, waiting for other peer to SYN_ACK replacement address\n",
		  GNUNET_i2s (&n->id));
      disconnect_neighbour (n);
      return;
    }
    break;
  case GNUNET_TRANSPORT_PS_SWITCH_SYN_SENT:
    if (0 == delay.rel_value_us)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Switch failed, cleaning up alternative address\n");
      free_address (&n->alternative_address);
      set_state_and_timeout (n,
                             GNUNET_TRANSPORT_PS_CONNECTED,
                             GNUNET_TIME_relative_to_absolute (SETUP_CONNECTION_TIMEOUT));
    }
    try_transmission_to_peer (n);
    send_keepalive (n);
    break;
  case GNUNET_TRANSPORT_PS_DISCONNECT:
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		"Cleaning up connection to `%s' after sending DISCONNECT\n",
		GNUNET_i2s (&n->id));
    free_neighbour (n);
    return;
  case GNUNET_TRANSPORT_PS_DISCONNECT_FINISHED:
    /* how did we get here!? */
    GNUNET_assert (0);
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unhandled state `%s'\n",
                GNUNET_TRANSPORT_ps2s (n->state));
    GNUNET_break (0);
    break;
  }
  delay = GNUNET_TIME_absolute_get_remaining (n->timeout);
  if ( (GNUNET_TRANSPORT_PS_SWITCH_SYN_SENT == n->state) ||
       (GNUNET_TRANSPORT_PS_CONNECTED == n->state) )
  {
    /* if we are *now* in one of the two states, we're sending
       keep alive messages, so we need to consider the keepalive
       delay, not just the connection timeout */
    delay = GNUNET_TIME_relative_min (GNUNET_TIME_absolute_get_remaining (n->keep_alive_time),
				      delay);
  }
  if (NULL == n->task)
    n->task = GNUNET_SCHEDULER_add_delayed (delay,
					    &master_task,
					    n);
}


/**
 * Send a ACK message to the neighbour to confirm that we
 * got his SYN_ACK.
 *
 * @param n neighbour to send the ACK to
 */
static void
send_session_ack_message (struct NeighbourMapEntry *n)
{
  struct GNUNET_MessageHeader msg;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Sending ACK message to peer `%s'\n",
              GNUNET_i2s (&n->id));

  msg.size = htons (sizeof (struct GNUNET_MessageHeader));
  msg.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_ACK);
  (void) send_with_session (n,
                            &msg,
                            sizeof (struct GNUNET_MessageHeader),
                            UINT32_MAX,
                            GNUNET_TIME_UNIT_FOREVER_REL,
                            GNUNET_NO,
                            NULL, NULL);
}


/**
 * We received a 'SESSION_SYN_ACK' message from the other peer.
 * Consider switching to it.
 *
 * @param message possibly a `struct SessionConnectMessage` (check format)
 * @param peer identity of the peer to switch the address for
 * @param address address of the other peer, NULL if other peer
 *                       connected to us
 * @param session session to use (or NULL)
 * @return #GNUNET_OK if the message was fine, #GNUNET_SYSERR on serious error
 */
int
GST_neighbours_handle_session_syn_ack (const struct GNUNET_MessageHeader *message,
				       const struct GNUNET_HELLO_Address *address,
				       struct Session *session)
{
  const struct TransportSynMessage *scm;
  struct GNUNET_TIME_Absolute ts;
  struct NeighbourMapEntry *n;

  if (ntohs (message->size) != sizeof (struct TransportSynMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop
                            ("# SYN_ACK messages received"),
                            1, GNUNET_NO);
  scm = (const struct TransportSynMessage *) message;
  GNUNET_break_op (ntohl (scm->reserved) == 0);
  if (NULL == (n = lookup_neighbour (&address->peer)))
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# unexpected SYN_ACK messages (no peer)"),
                              1, GNUNET_NO);
    return GNUNET_SYSERR;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received SYN_ACK message from peer `%s' in state %s/%s\n",
              GNUNET_i2s (&address->peer),
              GNUNET_TRANSPORT_ps2s (n->state),
              print_ack_state (n->ack_state));
  ts = GNUNET_TIME_absolute_ntoh (scm->timestamp);
  switch (n->state)
  {
  case GNUNET_TRANSPORT_PS_NOT_CONNECTED:
    GNUNET_break (0);
    free_neighbour (n);
    return GNUNET_SYSERR;
  case GNUNET_TRANSPORT_PS_INIT_ATS:
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop ("# unexpected SYN_ACK messages (not ready)"),
                              1,
                              GNUNET_NO);
    break;
  case GNUNET_TRANSPORT_PS_SYN_SENT:
    if (ts.abs_value_us != n->primary_address.connect_timestamp.abs_value_us)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "SYN_ACK ignored as the timestamp does not match our SYN request\n");
      return GNUNET_OK;
    }
    set_state_and_timeout (n,
                           GNUNET_TRANSPORT_PS_CONNECTED,
                           GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT));
    set_primary_address (n,
                         n->primary_address.address,
                         n->primary_address.session,
                         n->primary_address.bandwidth_in,
                         n->primary_address.bandwidth_out);
    send_session_ack_message (n);
    break;
  case GNUNET_TRANSPORT_PS_SYN_RECV_ATS:
  case GNUNET_TRANSPORT_PS_SYN_RECV_ACK:
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop ("# unexpected SYN_ACK messages (not ready)"),
                              1,
                              GNUNET_NO);
    break;
  case GNUNET_TRANSPORT_PS_CONNECTED:
    /* duplicate SYN_ACK, let's answer by duplicate ACK just in case */
    send_session_ack_message (n);
    break;
  case GNUNET_TRANSPORT_PS_RECONNECT_ATS:
    /* we didn't expect any SYN_ACK, as we are waiting for ATS
       to give us a new address... */
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop ("# unexpected SYN_ACK messages (waiting on ATS)"),
                              1,
                              GNUNET_NO);
    break;
  case GNUNET_TRANSPORT_PS_RECONNECT_SENT:
    /* Reconnecting with new address address worked; go back to connected! */
    set_state_and_timeout (n,
                           GNUNET_TRANSPORT_PS_CONNECTED,
                           GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT));
    send_session_ack_message (n);
    break;
  case GNUNET_TRANSPORT_PS_SWITCH_SYN_SENT:
    /* new address worked; adopt it and go back to connected! */
    set_state_and_timeout (n,
                           GNUNET_TRANSPORT_PS_CONNECTED,
                           GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT));
    GNUNET_break (GNUNET_NO == n->alternative_address.ats_active);

    /* Set primary addresses */
    set_primary_address (n,
                         n->alternative_address.address,
                         n->alternative_address.session,
                         n->alternative_address.bandwidth_in,
                         n->alternative_address.bandwidth_out);
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop ("# Successful attempts to switch addresses"),
                              1,
                              GNUNET_NO);

    GNUNET_HELLO_address_free (n->alternative_address.address);
    memset (&n->alternative_address,
            0,
            sizeof (n->alternative_address));
    send_session_ack_message (n);
    break;
  case GNUNET_TRANSPORT_PS_DISCONNECT:
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# unexpected SYN_ACK messages (disconnecting)"),
                              1, GNUNET_NO);
    return GNUNET_SYSERR;
  case GNUNET_TRANSPORT_PS_DISCONNECT_FINISHED:
    GNUNET_assert (0);
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unhandled state `%s'\n",
                GNUNET_TRANSPORT_ps2s (n->state));
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * A session was terminated. Take note; if needed, try to get
 * an alternative address from ATS.
 *
 * @param peer identity of the peer where the session died
 * @param session session that is gone
 * @return #GNUNET_YES if this was a session used, #GNUNET_NO if
 *        this session was not in use
 */
int
GST_neighbours_session_terminated (const struct GNUNET_PeerIdentity *peer,
                                   struct Session *session)
{
  struct NeighbourMapEntry *n;
  struct BlackListCheckContext *bcc;
  struct BlackListCheckContext *bcc_next;

  /* make sure to cancel all ongoing blacklist checks involving 'session' */
  bcc_next = bc_head;
  while (NULL != (bcc = bcc_next))
  {
    bcc_next = bcc->next;
    if (bcc->na.session == session)
    {
      if (NULL != bcc->bc)
        GST_blacklist_test_cancel (bcc->bc);
      GNUNET_HELLO_address_free (bcc->na.address);
      GNUNET_CONTAINER_DLL_remove (bc_head,
				   bc_tail,
				   bcc);
      GNUNET_free (bcc);
    }
  }
  if (NULL == (n = lookup_neighbour (peer)))
    return GNUNET_NO; /* can't affect us */
  if (session != n->primary_address.session)
  {
    /* Free alternative address */
    if (session == n->alternative_address.session)
    {
      if (GNUNET_TRANSPORT_PS_SWITCH_SYN_SENT == n->state)
        set_state_and_timeout (n,
                               GNUNET_TRANSPORT_PS_CONNECTED,
                               n->timeout);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Session died, cleaning up alternative address\n");
      free_address (&n->alternative_address);
    }
    return GNUNET_NO; /* doesn't affect us further */
  }

  n->expect_latency_response = GNUNET_NO;
  /* The session for neighbour's primary address died */
  switch (n->state)
  {
  case GNUNET_TRANSPORT_PS_NOT_CONNECTED:
    GNUNET_break (0);
    free_neighbour (n);
    return GNUNET_YES;
  case GNUNET_TRANSPORT_PS_INIT_ATS:
    GNUNET_break (0);
    free_neighbour (n);
    return GNUNET_YES;
  case GNUNET_TRANSPORT_PS_SYN_SENT:
    /* The session used to send the SYN terminated:
     * this implies a connect error*/
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Failed to send SYN in %s with `%s' %p: session terminated\n",
                "CONNECT_SENT",
                GST_plugins_a2s (n->primary_address.address),
                n->primary_address.session,
                GNUNET_i2s (peer));

    /* Destroy the address since it cannot be used */
    unset_primary_address (n);
    set_state_and_timeout (n,
                           GNUNET_TRANSPORT_PS_INIT_ATS,
                           GNUNET_TIME_relative_to_absolute (ATS_RESPONSE_TIMEOUT));
    break;
  case GNUNET_TRANSPORT_PS_SYN_RECV_ATS:
  case GNUNET_TRANSPORT_PS_SYN_RECV_ACK:
    /* error on inbound session; free neighbour entirely */
    free_neighbour (n);
    return GNUNET_YES;
  case GNUNET_TRANSPORT_PS_CONNECTED:
    /* Our primary connection died, try a fast reconnect */
    unset_primary_address (n);
    set_state_and_timeout (n,
                           GNUNET_TRANSPORT_PS_RECONNECT_ATS,
                           GNUNET_TIME_relative_to_absolute (ATS_RESPONSE_TIMEOUT));
    break;
  case GNUNET_TRANSPORT_PS_RECONNECT_ATS:
    /* we don't have an address, how can it go down? */
    GNUNET_break (0);
    break;
  case GNUNET_TRANSPORT_PS_RECONNECT_SENT:
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Failed to send SYN in %s with `%s' %p: session terminated\n",
                "RECONNECT_SENT",
                GST_plugins_a2s (n->primary_address.address),
                n->primary_address.session,
                GNUNET_i2s (peer));
    /* Destroy the address since it cannot be used */
    unset_primary_address (n);
    set_state_and_timeout (n,
                           GNUNET_TRANSPORT_PS_RECONNECT_ATS,
                           GNUNET_TIME_relative_to_absolute (ATS_RESPONSE_TIMEOUT));
    break;
  case GNUNET_TRANSPORT_PS_SWITCH_SYN_SENT:
    /* primary went down while we were waiting for SYN_ACK on secondary;
       secondary as primary */

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Connection `%s' %p to peer `%s' was terminated while switching, "
                "switching to alternative address `%s' %p\n",
                GST_plugins_a2s (n->primary_address.address),
                n->primary_address.session,
                GNUNET_i2s (peer),
                GST_plugins_a2s (n->alternative_address.address),
                n->alternative_address.session);

    /* Destroy the inbound address since it cannot be used */
    free_address (&n->primary_address);
    n->primary_address = n->alternative_address;
    GNUNET_assert (GNUNET_YES ==
                   GST_ats_is_known (n->primary_address.address,
                                     n->primary_address.session));
    memset (&n->alternative_address,
            0,
            sizeof (struct NeighbourAddress));
    set_state_and_timeout (n,
                           GNUNET_TRANSPORT_PS_RECONNECT_SENT,
                           GNUNET_TIME_relative_to_absolute (FAST_RECONNECT_TIMEOUT));
    break;
  case GNUNET_TRANSPORT_PS_DISCONNECT:
    unset_primary_address (n);
    break;
  case GNUNET_TRANSPORT_PS_DISCONNECT_FINISHED:
    /* neighbour was freed and plugins told to terminate session */
    return GNUNET_NO;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unhandled state `%s'\n",
                GNUNET_TRANSPORT_ps2s (n->state));
    GNUNET_break (0);
    break;
  }
  if (NULL != n->task)
    GNUNET_SCHEDULER_cancel (n->task);
  n->task = GNUNET_SCHEDULER_add_now (&master_task, n);
  return GNUNET_YES;
}


/**
 * We received a 'ACK' message from the other peer.
 * If we sent a 'SYN_ACK' last, this means we are now
 * connected.  Otherwise, do nothing.
 *
 * @param message possibly a 'struct SessionConnectMessage' (check format)
 * @param address address of the other peer
 * @param session session to use (or NULL)
 * @return #GNUNET_OK if the message was fine, #GNUNET_SYSERR on serious error
 */
int
GST_neighbours_handle_session_ack (const struct GNUNET_MessageHeader *message,
				   const struct GNUNET_HELLO_Address *address,
				   struct Session *session)
{
  struct NeighbourMapEntry *n;

  if (ntohs (message->size) != sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop ("# ACK messages received"),
                            1,
                            GNUNET_NO);
  if (NULL == (n = lookup_neighbour (&address->peer)))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received ACK for peer `%s' in state %s/%s\n",
              GNUNET_i2s (&address->peer),
              GNUNET_TRANSPORT_ps2s (n->state),
              print_ack_state (n->ack_state));

  /* Check if we are in a plausible state for having sent
     a SYN_ACK.  If not, return, otherwise break.

     The remote peers sends a ACK as a response for a SYN_ACK
     message.

     We expect a ACK:
     - If a remote peer has sent a SYN, we responded with a SYN_ACK and
     now wait for the ACK to finally be connected
     - If we sent a SYN_ACK to this peer before */

  if ( ( (GNUNET_TRANSPORT_PS_SYN_RECV_ACK != n->state) &&
	 (ACK_SEND_ACK != n->ack_state) ) ||
       (NULL == n->primary_address.address) ) 
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Received unexpected ACK message from peer `%s' in state %s/%s\n",
                GNUNET_i2s (&address->peer),
                GNUNET_TRANSPORT_ps2s (n->state),
                print_ack_state (n->ack_state));

    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop ("# unexpected ACK messages"),
                              1,
                              GNUNET_NO);
    return GNUNET_OK;
  }
  if (GNUNET_TRANSPORT_PS_SWITCH_SYN_SENT == n->state)
  {
    /* We tried to switch addresses while being connect. We explicitly wait
     * for a SYN_ACK before going to GNUNET_TRANSPORT_PS_CONNECTED,
     * so we do not want to set the address as in use! */
    return GNUNET_OK;
  }
  set_state_and_timeout (n,
                         GNUNET_TRANSPORT_PS_CONNECTED,
                         GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT));

  if (NULL == n->primary_address.address) {
    /* See issue #3693.
     * We are in state = PSY_SYN_RECV_ACK or ack_state = ACK_SEND_ACK, which
     * really means we did try (and succeed) to send a SYN and are waiting for
     * an ACK.
     * That suggests that the primary_address used to be non-NULL, but maybe it
     * got reset to NULL without the state being changed appropriately?
     */
    GNUNET_break (0);
    return GNUNET_OK;
  }

  /* Reset backoff for primary address */
  GST_ats_block_reset (n->primary_address.address,
                       n->primary_address.session);
  return GNUNET_OK;
}


/**
 * Test if we're connected to the given peer.
 *
 * @param target peer to test
 * @return #GNUNET_YES if we are connected, #GNUNET_NO if not
 */
int
GST_neighbours_test_connected (const struct GNUNET_PeerIdentity *target)
{
  return test_connected (lookup_neighbour (target));
}


/**
 * Change the incoming quota for the given peer.  Updates
 * our own receive rate and informs the neighbour about
 * the new quota.
 *
 * @param neighbour identity of peer to change qutoa for
 * @param quota new quota
 */
void
GST_neighbours_set_incoming_quota (const struct GNUNET_PeerIdentity *neighbour,
                                   struct GNUNET_BANDWIDTH_Value32NBO quota)
{
  struct NeighbourMapEntry *n;

  if (NULL == (n = lookup_neighbour (neighbour)))
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# SET QUOTA messages ignored (no such peer)"),
                              1, GNUNET_NO);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Setting inbound quota of %u Bps for peer `%s' to all clients\n",
              ntohl (quota.value__), GNUNET_i2s (&n->id));
  GNUNET_BANDWIDTH_tracker_update_quota (&n->in_tracker, quota);
  if (0 != ntohl (quota.value__))
  {
    struct SessionQuotaMessage sqm;

    sqm.header.size = htons (sizeof (struct SessionQuotaMessage));
    sqm.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_QUOTA);
    sqm.quota = quota.value__;
    (void) send_with_session (n,
                              &sqm,
                              sizeof (sqm),
                              UINT32_MAX - 1,
                              GNUNET_TIME_UNIT_FOREVER_REL,
                              GNUNET_NO,
                              NULL, NULL);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Disconnecting peer `%4s' due to SET_QUOTA\n",
              GNUNET_i2s (&n->id));
  if (GNUNET_YES == test_connected (n))
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop ("# disconnects due to quota of 0"),
                              1, GNUNET_NO);
  disconnect_neighbour (n);
}


/**
 * Task to asynchronously run #free_neighbour().
 *
 * @param cls the `struct NeighbourMapEntry` to free
 * @param tc unused
 */
static void
delayed_disconnect (void *cls,
                    const struct GNUNET_SCHEDULER_TaskContext* tc)
{
  struct NeighbourMapEntry *n = cls;

  n->delayed_disconnect_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Disconnecting by request from peer %s\n",
              GNUNET_i2s (&n->id));
  free_neighbour (n);
}


/**
 * We received a quoat message from the given peer,
 * validate and process.
 *
 * @param peer sender of the message
 * @param msg the quota message
 */
void
GST_neighbours_handle_quota_message (const struct GNUNET_PeerIdentity *peer,
                                     const struct GNUNET_MessageHeader *msg)
{
  struct NeighbourMapEntry *n;
  const struct SessionQuotaMessage *sqm;
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_min;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received QUOTA message from peer `%s'\n",
              GNUNET_i2s (peer));
  if (ntohs (msg->size) != sizeof (struct SessionQuotaMessage))
  {
    GNUNET_break_op (0);
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop ("# quota messages ignored (malformed)"),
                              1,
                              GNUNET_NO);
    return;
  }
  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop
                            ("# QUOTA messages received"),
                            1, GNUNET_NO);
  sqm = (const struct SessionQuotaMessage *) msg;
  if (NULL == (n = lookup_neighbour (peer)))
  {
    /* gone already */
    return;
  }
  n->neighbour_receive_quota
    = GNUNET_BANDWIDTH_value_max (GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT,
                                  GNUNET_BANDWIDTH_value_init (ntohl (sqm->quota)));

  bandwidth_min = GNUNET_BANDWIDTH_value_min (n->primary_address.bandwidth_out,
                                              n->neighbour_receive_quota);
  send_outbound_quota_to_clients (peer,
                                  bandwidth_min);
}


/**
 * We received a disconnect message from the given peer,
 * validate and process.
 *
 * @param peer sender of the message
 * @param msg the disconnect message
 */
void
GST_neighbours_handle_disconnect_message (const struct GNUNET_PeerIdentity *peer,
                                          const struct GNUNET_MessageHeader *msg)
{
  struct NeighbourMapEntry *n;
  const struct SessionDisconnectMessage *sdm;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received DISCONNECT message from peer `%s'\n",
              GNUNET_i2s (peer));
  if (ntohs (msg->size) != sizeof (struct SessionDisconnectMessage))
  {
    GNUNET_break_op (0);
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# disconnect messages ignored (malformed)"),
                              1,
                              GNUNET_NO);
    return;
  }
  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop
                            ("# DISCONNECT messages received"),
                            1, GNUNET_NO);
  sdm = (const struct SessionDisconnectMessage *) msg;
  if (NULL == (n = lookup_neighbour (peer)))
  {
    /* gone already */
    return;
  }
  if (GNUNET_TIME_absolute_ntoh (sdm->timestamp).abs_value_us <= n->connect_ack_timestamp.abs_value_us)
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop ("# disconnect messages ignored (timestamp)"),
                              1,
                              GNUNET_NO);
    return;
  }
  if (0 != memcmp (peer,
                   &sdm->public_key,
                   sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break_op (0);
    return;
  }
  if (ntohl (sdm->purpose.size) !=
      sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) +
      sizeof (struct GNUNET_CRYPTO_EddsaPublicKey) +
      sizeof (struct GNUNET_TIME_AbsoluteNBO))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "DISCONNECT message from peer `%s' has invalid size\n",
                GNUNET_i2s (peer));
    GNUNET_break_op (0);
    return;
  }
  if (GNUNET_OK !=
      GNUNET_CRYPTO_eddsa_verify (GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_DISCONNECT,
                                  &sdm->purpose,
                                  &sdm->signature,
                                  &sdm->public_key))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "DISCONNECT message from peer `%s' cannot be verified \n",
                GNUNET_i2s (peer));
    GNUNET_break_op (0);
    return;
  }
  if (NULL == n->delayed_disconnect_task)
  {
    n->delayed_disconnect_task = GNUNET_SCHEDULER_add_now (&delayed_disconnect,
                                                           n);
  }
}


/**
 * Closure for the #neighbours_iterate() function.
 */
struct IteratorContext
{
  /**
   * Function to call on each connected neighbour.
   */
  GST_NeighbourIterator cb;

  /**
   * Closure for @e cb.
   */
  void *cb_cls;
};


/**
 * Call the callback from the closure for each neighbour.
 *
 * @param cls the `struct IteratorContext`
 * @param key the hash of the public key of the neighbour
 * @param value the `struct NeighbourMapEntry`
 * @return #GNUNET_OK (continue to iterate)
 */
static int
neighbours_iterate (void *cls,
                    const struct GNUNET_PeerIdentity *key,
                    void *value)
{
  struct IteratorContext *ic = cls;
  struct NeighbourMapEntry *n = value;
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in;
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out;

  if (NULL != n->primary_address.address)
  {
    bandwidth_in = n->primary_address.bandwidth_in;
    bandwidth_out = n->primary_address.bandwidth_out;
  }
  else
  {
    bandwidth_in = GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT;
    bandwidth_out = GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT;
  }
  ic->cb (ic->cb_cls,
          &n->id,
          n->primary_address.address,
          n->state,
          n->timeout,
          bandwidth_in, bandwidth_out);
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

  if (NULL == neighbours)
    return; /* can happen during shutdown */
  ic.cb = cb;
  ic.cb_cls = cb_cls;
  GNUNET_CONTAINER_multipeermap_iterate (neighbours,
                                         &neighbours_iterate,
                                         &ic);
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

  if (NULL == (n = lookup_neighbour (target)))
    return;  /* not active */
  if (GNUNET_YES == test_connected (n))
    GNUNET_STATISTICS_update (GST_stats,
			      gettext_noop ("# disconnected from peer upon explicit request"),
                              1,
			      GNUNET_NO);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Forced disconnect from peer %s\n",
              GNUNET_i2s (target));
  disconnect_neighbour (n);
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
  if (NULL == n)
    return NULL;
  return n->primary_address.address;
}


/**
 * Initialize the neighbours subsystem.
 *
 * @param max_fds maximum number of fds to use
 */
void
GST_neighbours_start (unsigned int max_fds)
{
  neighbours = GNUNET_CONTAINER_multipeermap_create (NEIGHBOUR_TABLE_SIZE,
                                                     GNUNET_NO);
  util_transmission_tk = GNUNET_SCHEDULER_add_delayed (UTIL_TRANSMISSION_INTERVAL,
                                                       &utilization_transmission,
                                                       NULL);
}


/**
 * Disconnect from the given neighbour.
 *
 * @param cls unused
 * @param key hash of neighbour's public key (not used)
 * @param value the 'struct NeighbourMapEntry' of the neighbour
 * @return #GNUNET_OK (continue to iterate)
 */
static int
disconnect_all_neighbours (void *cls,
			   const struct GNUNET_PeerIdentity *key,
			   void *value)
{
  struct NeighbourMapEntry *n = value;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Disconnecting peer `%4s' during shutdown\n",
              GNUNET_i2s (&n->id));
  free_neighbour (n);
  return GNUNET_OK;
}


/**
 * Cleanup the neighbours subsystem.
 */
void
GST_neighbours_stop ()
{
  struct BlacklistCheckSwitchContext *cur;
  struct BlacklistCheckSwitchContext *next;

  if (NULL == neighbours)
    return;
  if (NULL != util_transmission_tk)
  {
    GNUNET_SCHEDULER_cancel (util_transmission_tk);
    util_transmission_tk = NULL;
  }
  GNUNET_CONTAINER_multipeermap_iterate (neighbours,
                                         &disconnect_all_neighbours,
                                         NULL);
  GNUNET_CONTAINER_multipeermap_destroy (neighbours);
  neighbours = NULL;
  next = pending_bc_head;
  for (cur = next; NULL != cur; cur = next)
  {
    next = cur->next;
    GNUNET_CONTAINER_DLL_remove (pending_bc_head,
                                 pending_bc_tail,
                                 cur);

    if (NULL != cur->blc)
    {
      GST_blacklist_test_cancel (cur->blc);
      cur->blc = NULL;
    }
    GNUNET_free (cur);
  }
}


/* end of file gnunet-service-transport_neighbours.c */
