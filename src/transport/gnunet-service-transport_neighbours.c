/*
     This file is part of GNUnet.
     (C) 2010,2011,2012 Christian Grothoff (and other contributing authors)

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
 *
 * TODO:
 * - "address_change_cb" is NEVER invoked; when should we call this one exactly?
 * - TEST, TEST, TEST...
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
 * Time we give plugin to transmit DISCONNECT message before the
 * neighbour entry self-destructs.
 */
#define DISCONNECT_SENT_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 100)

/**
 * How often must a peer violate bandwidth quotas before we start
 * to simply drop its messages?
 */
#define QUOTA_VIOLATION_DROP_THRESHOLD 10

/**
 * How often do we send KEEPALIVE messages to each of our neighbours and measure
 * the latency with this neighbour?
 * (idle timeout is 5 minutes or 300 seconds, so with 100s interval we
 * send 3 keepalives in each interval, so 3 messages would need to be
 * lost in a row for a disconnect).
 */
#define KEEPALIVE_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 100)

/**
 * How long are we willing to wait for a response from ATS before timing out?
 */
#define ATS_RESPONSE_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 500)

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
#define FAST_RECONNECT_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)

/**
 * How long are we willing to wait for a response from the blacklist
 * subsystem before timing out?
 */
#define BLACKLIST_RESPONSE_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 500)


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Message a peer sends to another to indicate that it intends to
 * setup a connection/session for data exchange.  A 'SESSION_CONNECT'
 * should be answered with a 'SESSION_CONNECT_ACK' with the same body
 * to confirm.  A 'SESSION_CONNECT_ACK' should then be followed with
 * a 'SESSION_ACK'.  Once the 'SESSION_ACK' is received, both peers 
 * should be connected.
 */
struct SessionConnectMessage
{
  /**
   * Header of type 'GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_CONNECT'
   * or 'GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_CONNECT_ACK'
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
 * Message we send to the other peer to notify him that we intentionally
 * are disconnecting (to reduce timeouts).  This is just a friendly 
 * notification, peers must not rely on always receiving disconnect
 * messages.
 */
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
 * Possible state of a neighbour.  Initially, we are S_NOT_CONNECTED.
 *
 * Then, there are two main paths. If we receive a CONNECT message, we
 * first run a check against the blacklist and ask ATS for a
 * suggestion.  (S_CONNECT_RECV_ATS).  If the blacklist comes back
 * positive, we give the address to ATS.  If ATS makes a suggestion,
 * we ALSO give that suggestion to the blacklist
 * (S_CONNECT_RECV_BLACKLIST).  Once the blacklist approves the
 * address we got from ATS, we send our CONNECT_ACK and go to
 * S_CONNECT_RECV_ACK.  If we receive a SESSION_ACK, we go to
 * S_CONNECTED (and notify everyone about the new connection).  If the
 * operation times out, we go to S_DISCONNECT.
 *
 * The other case is where we transmit a CONNECT message first.  We
 * start with S_INIT_ATS.  If we get an address, we enter
 * S_INIT_BLACKLIST and check the blacklist.  If the blacklist is OK
 * with the connection, we actually send the CONNECT message and go to
 * state S_CONNECT_SENT.  Once we receive a CONNECT_ACK, we go to
 * S_CONNECTED (and notify everyone about the new connection and send
 * back a SESSION_ACK).  If the operation times out, we go to
 * S_DISCONNECT.
 *
 * If the session is in trouble (i.e. transport-level disconnect or
 * timeout), we go to S_RECONNECT_ATS where we ask ATS for a new
 * address (we don't notify anyone about the disconnect yet).  Once we
 * have a new address, we go to S_RECONNECT_BLACKLIST to check the new
 * address against the blacklist.  If the blacklist approves, we enter
 * S_RECONNECT_SENT and send a CONNECT message.  If we receive a
 * CONNECT_ACK, we go to S_CONNECTED and nobody noticed that we had
 * trouble; we also send a SESSION_ACK at this time just in case.  If
 * the operation times out, we go to S_DISCONNECT (and notify everyone
 * about the lost connection).
 *
 * If ATS decides to switch addresses while we have a normal
 * connection, we go to S_CONNECTED_SWITCHING_BLACKLIST to check the
 * new address against the blacklist.  If the blacklist approves, we
 * go to S_CONNECTED_SWITCHING_CONNECT_SENT and send a
 * SESSION_CONNECT.  If we get a SESSION_ACK back, we switch the
 * primary connection to the suggested alternative from ATS, go back
 * to S_CONNECTED and send a SESSION_ACK to the other peer just to be
 * sure.  If the operation times out (or the blacklist disapproves),
 * we go to S_CONNECTED (and notify ATS that the given alternative
 * address is "invalid").
 *
 * Once a session is in S_DISCONNECT, it is cleaned up and then goes
 * to (S_DISCONNECT_FINISHED).  If we receive an explicit disconnect
 * request, we can go from any state to S_DISCONNECT, possibly after
 * generating disconnect notifications.
 *
 * Note that it is quite possible that while we are in any of these
 * states, we could receive a 'CONNECT' request from the other peer.
 * We then enter a 'weird' state where we pursue our own primary state
 * machine (as described above), but with the 'send_connect_ack' flag
 * set to 1.  If our state machine allows us to send a 'CONNECT_ACK'
 * (because we have an acceptable address), we send the 'CONNECT_ACK'
 * and set the 'send_connect_ack' to 2.  If we then receive a
 * 'SESSION_ACK', we go to 'S_CONNECTED' (and reset 'send_connect_ack'
 * to 0).
 * 
 */ 
enum State
{
  /**
   * fresh peer or completely disconnected
   */
  S_NOT_CONNECTED = 0,

  /**
   * Asked to initiate connection, trying to get address from ATS
   */
  S_INIT_ATS,

  /**
   * Asked to initiate connection, trying to get address approved
   * by blacklist.
   */
  S_INIT_BLACKLIST,

  /**
   * Sent CONNECT message to other peer, waiting for CONNECT_ACK
   */
  S_CONNECT_SENT,

  /**
   * Received a CONNECT, asking ATS about address suggestions.
   */
  S_CONNECT_RECV_ATS,

  /**
   * Received CONNECT from other peer, got an address, checking with blacklist.
   */
  S_CONNECT_RECV_BLACKLIST,

  /**
   * CONNECT request from other peer was SESSION_ACK'ed, waiting for
   * SESSION_ACK.
   */
  S_CONNECT_RECV_ACK,

  /**
   * Got our CONNECT_ACK/SESSION_ACK, connection is up.
   */
  S_CONNECTED,

  /**
   * Connection got into trouble, rest of the system still believes
   * it to be up, but we're getting a new address from ATS.
   */
  S_RECONNECT_ATS,

  /**
   * Connection got into trouble, rest of the system still believes
   * it to be up; we are checking the new address against the blacklist.
   */
  S_RECONNECT_BLACKLIST,

  /**
   * Sent CONNECT over new address (either by ATS telling us to switch
   * addresses or from RECONNECT_ATS); if this fails, we need to tell
   * the rest of the system about a disconnect.
   */
  S_RECONNECT_SENT,

  /**
   * We have some primary connection, but ATS suggested we switch
   * to some alternative; we're now checking the alternative against
   * the blacklist.
   */
  S_CONNECTED_SWITCHING_BLACKLIST,

  /** 
   * We have some primary connection, but ATS suggested we switch
   * to some alternative; we now sent a CONNECT message for the
   * alternative session to the other peer and waiting for a
   * CONNECT_ACK to make this our primary connection.
   */
  S_CONNECTED_SWITCHING_CONNECT_SENT,

  /**
   * Disconnect in progress (we're sending the DISCONNECT message to the
   * other peer; after that is finished, the state will be cleaned up).
   */
  S_DISCONNECT,

  /**
   * We're finished with the disconnect; clean up state now!
   */
  S_DISCONNECT_FINISHED
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
   * to our most recent 'CONNECT'.
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
   * Always runs the 'master_task'.
   */
  GNUNET_SCHEDULER_TaskIdentifier task;

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
   * Timestamp we should include in our next CONNECT_ACK message.
   * (only valid if 'send_connect_ack' is GNUNET_YES).  Used to build
   * our CONNECT_ACK message.
   */
  struct GNUNET_TIME_Absolute connect_ack_timestamp;

  /**
   * Time where we should cut the connection (timeout) if we don't
   * make progress in the state machine (or get a KEEPALIVE_RESPONSE
   * if we are in S_CONNECTED).
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Latest calculated latency value
   */
  struct GNUNET_TIME_Relative latency;

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
   * The current state of the peer.
   */
  enum State state;

  /**
   * Did we sent an KEEP_ALIVE message and are we expecting a response?
   */
  int expect_latency_response;

  /**
   * Flag to set if we still need to send a CONNECT_ACK message to the other peer
   * (once we have an address to use and the peer has been allowed by our
   * blacklist).  Set to 1 if we need to send a CONNECT_ACK.  Set to 2 if we
   * did send a CONNECT_ACK and should go to 'S_CONNECTED' upon receiving
   * a 'SESSION_ACK' (regardless of what our own state machine might say).
   */
  int send_connect_ack;

};


/**
 * Context for blacklist checks and the 'handle_test_blacklist_cont'
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
   * ATS information about the address.
   */
  struct GNUNET_ATS_Information *ats;

  /**
   * Handle to the ongoing blacklist check.
   */
  struct GST_BlacklistCheck *bc;

  /**
   * Size of the 'ats' array.
   */
  uint32_t ats_count;

};


/**
 * Hash map from peer identities to the respective 'struct NeighbourMapEntry'.
 */
static struct GNUNET_CONTAINER_MultiHashMap *neighbours;

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
static unsigned int neighbours_connected;

/**
 * Number of bytes we have currently queued for transmission.
 */
static unsigned long long bytes_in_send_queue;


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
  return GNUNET_CONTAINER_multihashmap_get (neighbours, &pid->hashPubKey);
}

static const char *
print_state (int state)
{

  switch (state)
  {
  case S_NOT_CONNECTED:
    return "S_NOT_CONNECTED";
    break;
  case S_INIT_ATS:
    return "S_INIT_ATS";
    break;
  case S_INIT_BLACKLIST:
    return "S_INIT_BLACKLIST";
    break;
  case S_CONNECT_SENT:
    return "S_CONNECT_SENT";
    break;
  case S_CONNECT_RECV_ATS:
    return "S_CONNECT_RECV_ATS";
    break;
  case S_CONNECT_RECV_BLACKLIST:
    return "S_CONNECT_RECV_BLACKLIST";
    break;
  case S_CONNECT_RECV_ACK:
    return "S_CONNECT_RECV_ACK";
    break;
  case S_CONNECTED:
    return "S_CONNECTED";
    break;
  case S_RECONNECT_ATS:
    return "S_RECONNECT_ATS";
    break;
  case S_RECONNECT_BLACKLIST:
    return "S_RECONNECT_BLACKLIST";
    break;
  case S_RECONNECT_SENT:
    return "S_RECONNECT_SENT";
    break;
  case S_CONNECTED_SWITCHING_BLACKLIST:
    return "S_CONNECTED_SWITCHING_BLACKLIST";
    break;
  case S_CONNECTED_SWITCHING_CONNECT_SENT:
    return "S_CONNECTED_SWITCHING_CONNECT_SENT";
    break;
  case S_DISCONNECT:
    return "S_DISCONNECT";
    break;
  case S_DISCONNECT_FINISHED:
    return "S_DISCONNECT_FINISHED";
    break;
  default:
    return "UNDEFINED";
    GNUNET_break (0);
    break;
  }
  GNUNET_break (0);
  return "UNDEFINED";
}

/**
 * Test if we're connected to the given peer.
 *
 * @param n neighbour entry of peer to test
 * @return GNUNET_YES if we are connected, GNUNET_NO if not
 */
static int
test_connected (struct NeighbourMapEntry *n)
{
  if (NULL == n)
    return GNUNET_NO;
  switch (n->state)
  {
  case S_NOT_CONNECTED:
  case S_INIT_ATS:
  case S_INIT_BLACKLIST:
  case S_CONNECT_SENT:
  case S_CONNECT_RECV_ATS:
  case S_CONNECT_RECV_BLACKLIST:
  case S_CONNECT_RECV_ACK:
    return GNUNET_NO;
  case S_CONNECTED:
  case S_RECONNECT_ATS:
  case S_RECONNECT_BLACKLIST:
  case S_RECONNECT_SENT:
  case S_CONNECTED_SWITCHING_BLACKLIST:
  case S_CONNECTED_SWITCHING_CONNECT_SENT:
    return GNUNET_YES;
  case S_DISCONNECT:
  case S_DISCONNECT_FINISHED:
    return GNUNET_NO;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Unhandled state `%s' \n",print_state (n->state));
    GNUNET_break (0);
    break;
  }
  return GNUNET_SYSERR;
}

/**
 * Send information about a new outbound quota to our clients.
 *
 * @param target affected peer
 * @param quota new quota
 */
static void
send_outbound_quota (const struct GNUNET_PeerIdentity *target,
                     struct GNUNET_BANDWIDTH_Value32NBO quota)
{
  struct QuotaSetMessage q_msg;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending outbound quota of %u Bps for peer `%s' to all clients\n",
              ntohl (quota.value__), GNUNET_i2s (target));
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
 * @param na address we are done with; 'na' itself must NOT be 'free'd, only the contents!
 */
static void
free_address (struct NeighbourAddress *na)
{
  if (GNUNET_YES == na->ats_active)
  {
    GST_validation_set_address_use (na->address, na->session, GNUNET_NO, __LINE__);
    GNUNET_ATS_address_in_use (GST_ats, na->address, na->session, GNUNET_NO);
  }
  na->ats_active = GNUNET_NO;
  if (NULL != na->address)
  {
    GNUNET_HELLO_address_free (na->address);
    na->address = NULL;
  }
  na->session = NULL;
}


/**
 * Initialize the 'struct NeighbourAddress'.
 *
 * @param na neighbour address to initialize
 * @param address address of the other peer, NULL if other peer
 *                       connected to us
 * @param session session to use (or NULL, in which case an
 *        address must be setup)
 * @param bandwidth_in inbound quota to be used when connection is up
 * @param bandwidth_out outbound quota to be used when connection is up
 * @param is_active GNUNET_YES to mark this as the active address with ATS
 */
static void
set_address (struct NeighbourAddress *na,
	     const struct GNUNET_HELLO_Address *address,
	     struct Session *session,
	     struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
	     struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
	     int is_active)
{
  struct GNUNET_TRANSPORT_PluginFunctions *papi;

  if (NULL == (papi = GST_plugins_find (address->transport_name)))  
  {
    GNUNET_break (0);
    return;
  }
  if (session == na->session)
  {
    na->bandwidth_in = bandwidth_in;
    na->bandwidth_out = bandwidth_out;
    if (is_active != na->ats_active)
    {
      na->ats_active = is_active;
      GNUNET_ATS_address_in_use (GST_ats, na->address, na->session, is_active);
      GST_validation_set_address_use (na->address, na->session, is_active,  __LINE__);
    }
    if (GNUNET_YES == is_active)
    {
      /* FIXME: is this the right place to set quotas? */
      GST_neighbours_set_incoming_quota (&address->peer, bandwidth_in);
      send_outbound_quota (&address->peer, bandwidth_out);
    }    
    return;
  }
  free_address (na);
  if (NULL == session)
    session = papi->get_session (papi->cls, address);    
  if (NULL == session)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Failed to obtain new session for peer `%s' and  address '%s'\n",
		GNUNET_i2s (&address->peer), GST_plugins_a2s (address));    
    GNUNET_ATS_address_destroyed (GST_ats, address, NULL);
    return;
  }
  na->address = GNUNET_HELLO_address_copy (address);
  na->bandwidth_in = bandwidth_in;
  na->bandwidth_out = bandwidth_out;
  na->session = session;
  na->ats_active = is_active;
  if (GNUNET_YES == is_active)
  {
    /* Telling ATS about new session */
    GNUNET_ATS_address_update (GST_ats, na->address, na->session, NULL, 0);
    GNUNET_ATS_address_in_use (GST_ats, na->address, na->session, GNUNET_YES);
    GST_validation_set_address_use (na->address, na->session, GNUNET_YES,  __LINE__);

    /* FIXME: is this the right place to set quotas? */
    GST_neighbours_set_incoming_quota (&address->peer, bandwidth_in);
    send_outbound_quota (&address->peer, bandwidth_out);
  }
}


/**
 * Free a neighbour map entry.
 *
 * @param n entry to free
 * @param keep_sessions GNUNET_NO to tell plugin to terminate sessions,
 *                      GNUNET_YES to keep all sessions
 */
static void
free_neighbour (struct NeighbourMapEntry *n, int keep_sessions)
{
  struct MessageQueue *mq;
  struct GNUNET_TRANSPORT_PluginFunctions *papi;

  n->is_active = NULL; /* always free'd by its own continuation! */

  /* fail messages currently in the queue */
  while (NULL != (mq = n->messages_head))
  {
    GNUNET_CONTAINER_DLL_remove (n->messages_head, n->messages_tail, mq);
    if (NULL != mq->cont)
      mq->cont (mq->cont_cls, GNUNET_SYSERR);
    GNUNET_free (mq);
  }
  /* It is too late to send other peer disconnect notifications, but at
     least internally we need to get clean... */
  if (GNUNET_YES == test_connected (n))
  {
    GNUNET_STATISTICS_set (GST_stats, 
			   gettext_noop ("# peers connected"), 
			   --neighbours_connected,
			   GNUNET_NO);
    disconnect_notify_cb (callback_cls, &n->id);
  }

  /* FIXME-PLUGIN-API: This does not seem to guarantee that all
     transport sessions eventually get killed due to inactivity; they
     MUST have their own timeout logic (but at least TCP doesn't have
     one yet).  Are we sure that EVERY 'session' of a plugin is
     actually cleaned up this way!?  Note that if we are switching
     between two TCP sessions to the same peer, the existing plugin
     API gives us not even the means to selectively kill only one of
     them! Killing all sessions like this seems to be very, very
     wrong. */
  if ((GNUNET_NO == keep_sessions) &&
      (NULL != n->primary_address.address) &&
      (NULL != (papi = GST_plugins_find (n->primary_address.address->transport_name))))
    papi->disconnect (papi->cls, &n->id);

  n->state = S_DISCONNECT_FINISHED;

  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (neighbours,
                                                       &n->id.hashPubKey, n));

  /* cut transport-level connection */
  free_address (&n->primary_address);
  free_address (&n->alternative_address);

  // FIXME-ATS-API: we might want to be more specific about
  // which states we do this from in the future (ATS should
  // have given us a 'suggest_address' handle, and if we have
  // such a handle, we should cancel the operation here!
  GNUNET_ATS_suggest_address_cancel (GST_ats, &n->id);

  if (GNUNET_SCHEDULER_NO_TASK != n->task)
  {
    GNUNET_SCHEDULER_cancel (n->task);
    n->task = GNUNET_SCHEDULER_NO_TASK;
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
 * @param msgbuf_size number of bytes in buffer
 * @param priority transmission priority
 * @param timeout transmission timeout
 * @param cont continuation to call when finished (can be NULL)
 * @param cont_cls closure for cont
 */
static void
send_with_session (struct NeighbourMapEntry *n,
                   const char *msgbuf, size_t msgbuf_size,
                   uint32_t priority,
                   struct GNUNET_TIME_Relative timeout,
                   GNUNET_TRANSPORT_TransmitContinuation cont,
		   void *cont_cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *papi;

  GNUNET_assert (n->primary_address.session != NULL);
  if ( ( (NULL == (papi = GST_plugins_find (n->primary_address.address->transport_name))) ||
	 (-1 == papi->send (papi->cls,
			    n->primary_address.session,
			    msgbuf, msgbuf_size,
			    priority,
			    timeout,
			    cont, cont_cls))) &&
       (NULL != cont) )
    cont (cont_cls, &n->id, GNUNET_SYSERR);
  GNUNET_break (NULL != papi);
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
	     const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Function called when the 'DISCONNECT' message has been sent by the
 * plugin.  Frees the neighbour --- if the entry still exists.
 *
 * @param cls NULL
 * @param target identity of the neighbour that was disconnected
 * @param result GNUNET_OK if the disconnect got out successfully
 */
static void
send_disconnect_cont (void *cls, const struct GNUNET_PeerIdentity *target,
                      int result)
{
  struct NeighbourMapEntry *n;

  n = lookup_neighbour (target);
  if (NULL == n)
    return; /* already gone */
  if (S_DISCONNECT != n->state)
    return; /* have created a fresh entry since */
  n->state = S_DISCONNECT;
  if (GNUNET_SCHEDULER_NO_TASK != n->task)
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending DISCONNECT message to peer `%4s'\n",
              GNUNET_i2s (&n->id));
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

  send_with_session (n,
		     (const char *) &disconnect_msg, sizeof (disconnect_msg),
		     UINT32_MAX, GNUNET_TIME_UNIT_FOREVER_REL,
		     &send_disconnect_cont, NULL);
  GNUNET_STATISTICS_update (GST_stats,
                            gettext_noop
                            ("# DISCONNECT messages sent"), 1,
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
  /* depending on state, notify neighbour and/or upper layers of this peer 
     about disconnect */
  switch (n->state)
  {
  case S_NOT_CONNECTED:
  case S_INIT_ATS:
  case S_INIT_BLACKLIST:
    /* other peer is completely unaware of us, no need to send DISCONNECT */
    n->state = S_DISCONNECT_FINISHED;
    free_neighbour (n, GNUNET_NO);
    return;
  case S_CONNECT_SENT:
    send_disconnect (n); 
    n->state = S_DISCONNECT;
    break;   
  case S_CONNECT_RECV_ATS:
  case S_CONNECT_RECV_BLACKLIST:
    /* we never ACK'ed the other peer's request, no need to send DISCONNECT */
    n->state = S_DISCONNECT_FINISHED;
    free_neighbour (n, GNUNET_NO);
    return;
  case S_CONNECT_RECV_ACK:
    /* we DID ACK the other peer's request, must send DISCONNECT */
    send_disconnect (n); 
    n->state = S_DISCONNECT;
    break;   
  case S_CONNECTED:
  case S_RECONNECT_BLACKLIST:
  case S_RECONNECT_SENT:
  case S_CONNECTED_SWITCHING_BLACKLIST:
  case S_CONNECTED_SWITCHING_CONNECT_SENT:
    /* we are currently connected, need to send disconnect and do
       internal notifications and update statistics */
    send_disconnect (n);
    GNUNET_STATISTICS_set (GST_stats, 
			   gettext_noop ("# peers connected"), 
			   --neighbours_connected,
			   GNUNET_NO);
    disconnect_notify_cb (callback_cls, &n->id);
    n->state = S_DISCONNECT;
    break;
  case S_RECONNECT_ATS:
    /* ATS address request timeout, disconnect without sending disconnect message */
    GNUNET_STATISTICS_set (GST_stats,
                           gettext_noop ("# peers connected"),
                           --neighbours_connected,
                           GNUNET_NO);
    disconnect_notify_cb (callback_cls, &n->id);
    n->state = S_DISCONNECT;
    break;
  case S_DISCONNECT:
    /* already disconnected, ignore */
    break;
  case S_DISCONNECT_FINISHED:
    /* already cleaned up, how did we get here!? */
    GNUNET_assert (0);
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Unhandled state `%s' \n",print_state (n->state));
    GNUNET_break (0);
    break;
  }
  /* schedule timeout to clean up */
  if (GNUNET_SCHEDULER_NO_TASK != n->task)
    GNUNET_SCHEDULER_cancel (n->task);
  n->task = GNUNET_SCHEDULER_add_delayed (DISCONNECT_SENT_TIMEOUT,
					  &master_task, n);
}


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

  if (NULL == (n = lookup_neighbour (receiver)))
  {
    GNUNET_free (mq);
    return; /* disconnect or other error while transmitting, can happen */
  }
  if (n->is_active == mq)
  {
    /* this is still "our" neighbour, remove us from its queue
       and allow it to send the next message now */
    n->is_active = NULL;
    if (GNUNET_SCHEDULER_NO_TASK != n->task)
      GNUNET_SCHEDULER_cancel (n->task);
    n->task = GNUNET_SCHEDULER_add_now (&master_task, n);    
  }
  GNUNET_assert (bytes_in_send_queue >= mq->message_buf_size);
  bytes_in_send_queue -= mq->message_buf_size;
  GNUNET_STATISTICS_set (GST_stats,
                        gettext_noop
			 ("# bytes in message queue for other peers"),
			 bytes_in_send_queue, GNUNET_NO);
  if (GNUNET_OK == success)
    GNUNET_STATISTICS_update (GST_stats,
			      gettext_noop
			      ("# messages transmitted to other peers"),
			      1, GNUNET_NO);
  else
    GNUNET_STATISTICS_update (GST_stats,
			      gettext_noop
			      ("# transmission failures for messages to other peers"),
			      1, GNUNET_NO);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Sending message to `%s' of type %u was a %s\n",
	      GNUNET_i2s (receiver),
              ntohs (((struct GNUNET_MessageHeader *) mq->message_buf)->type),
              (success == GNUNET_OK) ? "success" : "FAILURE");
  if (NULL != mq->cont)
    mq->cont (mq->cont_cls, success);
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
    if (timeout.rel_value > 0)
      break;
    GNUNET_STATISTICS_update (GST_stats,
			      gettext_noop
			      ("# messages timed out while in transport queue"),
			      1, GNUNET_NO);
    GNUNET_CONTAINER_DLL_remove (n->messages_head, n->messages_tail, mq);
    n->is_active = mq;
    transmit_send_continuation (mq, &n->id, GNUNET_SYSERR);     /* timeout */
  }
  if (NULL == mq)
    return;                     /* no more messages */
  GNUNET_CONTAINER_DLL_remove (n->messages_head, n->messages_tail, mq);
  n->is_active = mq;
  send_with_session (n,
		     mq->message_buf, mq->message_buf_size,
		     0 /* priority */, timeout,
		     &transmit_send_continuation, mq);
}


/**
 * Send keepalive message to the neighbour.  Must only be called
 * if we are on 'connected' state.  Will internally determine
 * if a keepalive is truly needed (so can always be called).
 *
 * @param n neighbour that went idle and needs a keepalive
 */
static void
send_keepalive (struct NeighbourMapEntry *n)
{
  struct GNUNET_MessageHeader m;

  GNUNET_assert (S_CONNECTED == n->state);
  if (GNUNET_TIME_absolute_get_remaining (n->keep_alive_time).rel_value > 0)
    return; /* no keepalive needed at this time */
  m.size = htons (sizeof (struct GNUNET_MessageHeader));
  m.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_KEEPALIVE);
  send_with_session (n,
		     (const void *) &m, sizeof (m),
		     UINT32_MAX /* priority */,
		     KEEPALIVE_FREQUENCY,
		     NULL, NULL);
  GNUNET_STATISTICS_update (GST_stats, gettext_noop ("# keepalives sent"), 1,
			    GNUNET_NO);
  n->expect_latency_response = GNUNET_YES;
  n->last_keep_alive_time = GNUNET_TIME_absolute_get ();
  n->keep_alive_time = GNUNET_TIME_relative_to_absolute (KEEPALIVE_FREQUENCY);
}


/**
 * Keep the connection to the given neighbour alive longer,
 * we received a KEEPALIVE (or equivalent); send a response.
 *
 * @param neighbour neighbour to keep alive (by sending keep alive response)
 */
void
GST_neighbours_keepalive (const struct GNUNET_PeerIdentity *neighbour)
{
  struct NeighbourMapEntry *n;
  struct GNUNET_MessageHeader m;

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
  /* send reply to allow neighbour to measure latency */
  m.size = htons (sizeof (struct GNUNET_MessageHeader));
  m.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_KEEPALIVE_RESPONSE);
  send_with_session(n,
		    (const void *) &m, sizeof (m),
		    UINT32_MAX /* priority */,
		    KEEPALIVE_FREQUENCY,
		    NULL, NULL);
}


/**
 * We received a KEEP_ALIVE_RESPONSE message and use this to calculate
 * latency to this peer.  Pass the updated information (existing ats
 * plus calculated latency) to ATS.
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
  uint32_t latency;
  struct GNUNET_ATS_Information ats_new[ats_count + 1];

  if (NULL == (n = lookup_neighbour (neighbour)))
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# KEEPALIVE_RESPONSE messages discarded (not connected)"),
                              1, GNUNET_NO);
    return;
  }
  if ( (S_CONNECTED != n->state) ||
       (GNUNET_YES != n->expect_latency_response) )
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# KEEPALIVE_RESPONSE messages discarded (not expected)"),
                              1, GNUNET_NO);
    return;
  }
  n->expect_latency_response = GNUNET_NO;
  n->latency = GNUNET_TIME_absolute_get_duration (n->last_keep_alive_time);
  n->timeout = GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Latency for peer `%s' is %llu ms\n",
              GNUNET_i2s (&n->id), n->latency.rel_value);
  memcpy (ats_new, ats, sizeof (struct GNUNET_ATS_Information) * ats_count);
  /* append latency */
  ats_new[ats_count].type = htonl (GNUNET_ATS_QUALITY_NET_DELAY);
  if (n->latency.rel_value > UINT32_MAX)
    latency = UINT32_MAX;
  else
    latency = n->latency.rel_value;
  ats_new[ats_count].value = htonl (latency);
  GNUNET_ATS_address_update (GST_ats, 
			     n->primary_address.address, 
			     n->primary_address.session, ats_new,
			     ats_count + 1);
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
  if (ret.rel_value > 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Throttling read (%llu bytes excess at %u b/s), waiting %llu ms before reading more.\n",
                (unsigned long long) n->in_tracker.
                consumption_since_last_update__,
                (unsigned int) n->in_tracker.available_bytes_per_s__,
                (unsigned long long) ret.rel_value);
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop ("# ms throttling suggested"),
                              (int64_t) ret.rel_value, GNUNET_NO);
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
 * @param cont_cls closure for 'cont'
 */
void
GST_neighbours_send (const struct GNUNET_PeerIdentity *target, const void *msg,
                     size_t msg_size, struct GNUNET_TIME_Relative timeout,
                     GST_NeighbourSendContinuation cont, void *cont_cls)
{
  struct NeighbourMapEntry *n;
  struct MessageQueue *mq;

  /* All ove these cases should never happen; they are all API violations.
     But we check anyway, just to be sure. */
  if (NULL == (n = lookup_neighbour (target)))
  {
    GNUNET_break (0);
    if (NULL != cont)
      cont (cont_cls, GNUNET_SYSERR);
    return;
  }
  if (GNUNET_YES != test_connected (n))
  {
    GNUNET_break (0);
    if (NULL != cont)
      cont (cont_cls, GNUNET_SYSERR);
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
  GNUNET_CONTAINER_DLL_insert_tail (n->messages_head, n->messages_tail, mq);
  if ( (NULL != n->is_active) ||
       ( (NULL == n->primary_address.session) && (NULL == n->primary_address.address)) )
    return;
  if (GNUNET_SCHEDULER_NO_TASK != n->task)
    GNUNET_SCHEDULER_cancel (n->task);
  n->task = GNUNET_SCHEDULER_add_now (&master_task, n);
}


/**
 * Send a SESSION_CONNECT message via the given address.
 *
 * @param na address to use
 */
static void
send_session_connect (struct NeighbourAddress *na)
{
  struct GNUNET_TRANSPORT_PluginFunctions *papi;
  struct SessionConnectMessage connect_msg;
  
  if (NULL == (papi = GST_plugins_find (na->address->transport_name)))  
  {
    GNUNET_break (0);
    return;
  }
  if (NULL == na->session)
    na->session = papi->get_session (papi->cls, na->address);    
  if (NULL == na->session)
  {
    GNUNET_break (0);
    return;
  }
  na->connect_timestamp = GNUNET_TIME_absolute_get ();
  connect_msg.header.size = htons (sizeof (struct SessionConnectMessage));
  connect_msg.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_CONNECT);
  connect_msg.reserved = htonl (0);
  connect_msg.timestamp = GNUNET_TIME_absolute_hton (na->connect_timestamp);
  (void) papi->send (papi->cls,
		     na->session,
		     (const char *) &connect_msg, sizeof (struct SessionConnectMessage),
		     UINT_MAX,
		     GNUNET_TIME_UNIT_FOREVER_REL,
		     NULL, NULL);
}


/**
 * Send a SESSION_CONNECT_ACK message via the given address.
 *
 * @param address address to use
 * @param session session to use
 * @param timestamp timestamp to use for the ACK message
 */
static void
send_session_connect_ack_message (const struct GNUNET_HELLO_Address *address,
				  struct Session *session,
				  struct GNUNET_TIME_Absolute timestamp)
{
  struct GNUNET_TRANSPORT_PluginFunctions *papi;
  struct SessionConnectMessage connect_msg;
  
  if (NULL == (papi = GST_plugins_find (address->transport_name)))  
  {
    GNUNET_break (0);
    return;
  }
  if (NULL == session)
    session = papi->get_session (papi->cls, address);    
  if (NULL == session)
  {
    GNUNET_break (0);
    return;
  }
  connect_msg.header.size = htons (sizeof (struct SessionConnectMessage));
  connect_msg.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_CONNECT_ACK);
  connect_msg.reserved = htonl (0);
  connect_msg.timestamp = GNUNET_TIME_absolute_hton (timestamp);
  (void) papi->send (papi->cls,
		     session,
		     (const char *) &connect_msg, sizeof (struct SessionConnectMessage),
		     UINT_MAX,
		     GNUNET_TIME_UNIT_FOREVER_REL,
		     NULL, NULL);
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
  n = GNUNET_malloc (sizeof (struct NeighbourMapEntry));
  n->id = *peer;
  n->state = S_NOT_CONNECTED;
  n->latency = GNUNET_TIME_UNIT_FOREVER_REL;
  GNUNET_BANDWIDTH_tracker_init (&n->in_tracker,
                                 GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT,
                                 MAX_BANDWIDTH_CARRY_S);
  n->task = GNUNET_SCHEDULER_add_now (&master_task, n);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap_put (neighbours,
                                                    &n->id.hashPubKey, n,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  return n;
}


/**
 * Check if the two given addresses are the same.
 * Actually only checks if the sessions are non-NULL
 * (which they should be) and then if they are identical;
 * the actual addresses don't matter if the session
 * pointers match anyway, and we must have session pointers
 * at this time.
 *
 * @param a1 first address to compare
 * @param a2 other address to compare
 * @return GNUNET_NO if the addresses do not match, GNUNET_YES if they do match
 */
static int
address_matches (const struct NeighbourAddress *a1,
		 const struct NeighbourAddress *a2)
{
  if ( (NULL == a1->session) ||
       (NULL == a2->session) )
  {
    GNUNET_break (0);
    return 0;
  }
  return (a1->session == a2->session) ? GNUNET_YES : GNUNET_NO;
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

  if (NULL == neighbours)  
    return; /* during shutdown, do nothing */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Asked to connect to peer `%s'\n",
              GNUNET_i2s (target));
  if (0 ==
      memcmp (target, &GST_my_identity, sizeof (struct GNUNET_PeerIdentity)))
  {
    /* refuse to connect to myself */
    /* FIXME: can this happen? Is this not an API violation? */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Refusing to try to connect to myself.\n");
    return;
  }
  n = lookup_neighbour (target);
  if (NULL != n)
  {
    switch (n->state)
    {
    case S_NOT_CONNECTED:
      /* this should not be possible */
      GNUNET_break (0);
      free_neighbour (n, GNUNET_NO);
      break;
    case S_INIT_ATS:
    case S_INIT_BLACKLIST:
    case S_CONNECT_SENT:
    case S_CONNECT_RECV_ATS:
    case S_CONNECT_RECV_BLACKLIST:
    case S_CONNECT_RECV_ACK:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Ignoring request to try to connect to `%s', already trying!\n",
		  GNUNET_i2s (target));
      return; /* already trying */
    case S_CONNECTED:      
    case S_RECONNECT_ATS:
    case S_RECONNECT_BLACKLIST:
    case S_RECONNECT_SENT:
    case S_CONNECTED_SWITCHING_BLACKLIST:
    case S_CONNECTED_SWITCHING_CONNECT_SENT:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Ignoring request to try to connect, already connected to `%s'!\n",
		  GNUNET_i2s (target));
      return; /* already connected */
    case S_DISCONNECT:
      /* get rid of remains, ready to re-try immediately */
      free_neighbour (n, GNUNET_NO);
      break;
    case S_DISCONNECT_FINISHED:
      /* should not be possible */      
      GNUNET_assert (0); 
    default:
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Unhandled state `%s' \n",print_state (n->state));
      GNUNET_break (0);
      free_neighbour (n, GNUNET_NO);
      break;
    }
  }
  n = setup_neighbour (target);  
  n->state = S_INIT_ATS; 
  n->timeout = GNUNET_TIME_relative_to_absolute (ATS_RESPONSE_TIMEOUT);

  GNUNET_ATS_reset_backoff (GST_ats, target);
  GNUNET_ATS_suggest_address (GST_ats, target);
}


/**
 * Function called with the result of a blacklist check.
 *
 * @param cls closure with the 'struct BlackListCheckContext'
 * @param peer peer this check affects
 * @param result GNUNET_OK if the address is allowed
 */
static void
handle_test_blacklist_cont (void *cls,
			    const struct GNUNET_PeerIdentity *peer,
			    int result)
{
  struct BlackListCheckContext *bcc = cls;
  struct NeighbourMapEntry *n;

  bcc->bc = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connection to new address of peer `%s' based on blacklist is `%s'\n",
              GNUNET_i2s (peer),
              (GNUNET_OK == result) ? "allowed" : "FORBIDDEN");
  if (GNUNET_OK == result)
  {
    /* valid new address, let ATS know! */
    GNUNET_ATS_address_update (GST_ats, 
			       bcc->na.address, 
			       bcc->na.session, 
			       bcc->ats, bcc->ats_count);
  }
  if (NULL == (n = lookup_neighbour (peer)))
    goto cleanup; /* nobody left to care about new address */
  switch (n->state)
  {
  case S_NOT_CONNECTED:
    /* this should not be possible */
    GNUNET_break (0);
    free_neighbour (n, GNUNET_NO);
    break;
  case S_INIT_ATS:
    /* still waiting on ATS suggestion */
    break;
  case S_INIT_BLACKLIST:
    /* check if the address the blacklist was fine with matches
       ATS suggestion, if so, we can move on! */
    if ( (GNUNET_OK == result) &&
	 (1 == n->send_connect_ack) )
    {
      n->send_connect_ack = 2;
      send_session_connect_ack_message (bcc->na.address,
					bcc->na.session,
					n->connect_ack_timestamp);
    }
    if (GNUNET_YES != address_matches (&bcc->na, &n->primary_address))
      break; /* result for an address we currently don't care about */
    if (GNUNET_OK == result)
    {
      n->timeout = GNUNET_TIME_relative_to_absolute (SETUP_CONNECTION_TIMEOUT);
      n->state = S_CONNECT_SENT;
      send_session_connect (&n->primary_address);
    }
    else
    {
      // FIXME: should also possibly destroy session with plugin!?
      GNUNET_ATS_address_destroyed (GST_ats,
				    bcc->na.address,
				    NULL);
      free_address (&n->primary_address);
      n->state = S_INIT_ATS;
      n->timeout = GNUNET_TIME_relative_to_absolute (ATS_RESPONSE_TIMEOUT);
      // FIXME: do we need to ask ATS again for suggestions?
      GNUNET_ATS_suggest_address (GST_ats, &n->id);
    }
    break;
  case S_CONNECT_SENT:
    /* waiting on CONNECT_ACK, send ACK if one is pending */
    if ( (GNUNET_OK == result) &&
	 (1 == n->send_connect_ack) )
    {
      n->send_connect_ack = 2;
      send_session_connect_ack_message (n->primary_address.address,
					n->primary_address.session,
					n->connect_ack_timestamp);
    }
    break; 
  case S_CONNECT_RECV_ATS:
    /* still waiting on ATS suggestion, don't care about blacklist */
    break; 
  case S_CONNECT_RECV_BLACKLIST:
    if (GNUNET_YES != address_matches (&bcc->na, &n->primary_address))
      break; /* result for an address we currently don't care about */
    if (GNUNET_OK == result)
    {
      n->timeout = GNUNET_TIME_relative_to_absolute (SETUP_CONNECTION_TIMEOUT);
      n->state = S_CONNECT_RECV_ACK;
      send_session_connect_ack_message (bcc->na.address,
					bcc->na.session,
					n->connect_ack_timestamp);
      if (1 == n->send_connect_ack) 
	n->send_connect_ack = 2;
    }
    else
    {
      // FIXME: should also possibly destroy session with plugin!?
      GNUNET_ATS_address_destroyed (GST_ats,
				    bcc->na.address,
				    NULL);
      free_address (&n->primary_address);
      n->state = S_INIT_ATS;
      n->timeout = GNUNET_TIME_relative_to_absolute (ATS_RESPONSE_TIMEOUT);
      // FIXME: do we need to ask ATS again for suggestions?
      GNUNET_ATS_reset_backoff (GST_ats, peer);
      GNUNET_ATS_suggest_address (GST_ats, &n->id);
    }
    break;
  case S_CONNECT_RECV_ACK:
    /* waiting on SESSION_ACK, send ACK if one is pending */
    if ( (GNUNET_OK == result) &&
	 (1 == n->send_connect_ack) )
    {
      n->send_connect_ack = 2;
      send_session_connect_ack_message (n->primary_address.address,
					n->primary_address.session,
					n->connect_ack_timestamp);
    }
    break; 
  case S_CONNECTED:
    /* already connected, don't care about blacklist */
    break;
  case S_RECONNECT_ATS:
    /* still waiting on ATS suggestion, don't care about blacklist */
    break;     
  case S_RECONNECT_BLACKLIST:
    if ( (GNUNET_OK == result) &&
	 (1 == n->send_connect_ack) )
    {
      n->send_connect_ack = 2;
      send_session_connect_ack_message (bcc->na.address,
					bcc->na.session,
					n->connect_ack_timestamp);
    }
    if (GNUNET_YES != address_matches (&bcc->na, &n->primary_address))
      break; /* result for an address we currently don't care about */
    if (GNUNET_OK == result)
    {
      send_session_connect (&n->primary_address);
      n->timeout = GNUNET_TIME_relative_to_absolute (FAST_RECONNECT_TIMEOUT);
      n->state = S_RECONNECT_SENT;
    }
    else
    {
      GNUNET_ATS_address_destroyed (GST_ats,
				    bcc->na.address,
				    NULL);
      n->state = S_RECONNECT_ATS;
      n->timeout = GNUNET_TIME_relative_to_absolute (ATS_RESPONSE_TIMEOUT);
      // FIXME: do we need to ask ATS again for suggestions?
      GNUNET_ATS_suggest_address (GST_ats, &n->id);
    }
    break;
  case S_RECONNECT_SENT:
    /* waiting on CONNECT_ACK, don't care about blacklist */
    if ( (GNUNET_OK == result) &&
	 (1 == n->send_connect_ack) )
    {
      n->send_connect_ack = 2;
      send_session_connect_ack_message (n->primary_address.address,
					n->primary_address.session,
					n->connect_ack_timestamp);
    }
    break;     
  case S_CONNECTED_SWITCHING_BLACKLIST:
    if (GNUNET_YES != address_matches (&bcc->na, &n->alternative_address))
      break; /* result for an address we currently don't care about */
    if (GNUNET_OK == result)
    {
      send_session_connect (&n->alternative_address);
      n->state = S_CONNECTED_SWITCHING_CONNECT_SENT;
    }
    else
    {
      GNUNET_ATS_address_destroyed (GST_ats,
				    bcc->na.address,
				    NULL);
      free_address (&n->alternative_address);
      n->state = S_CONNECTED;
    }
    break;
  case S_CONNECTED_SWITCHING_CONNECT_SENT:
    /* waiting on CONNECT_ACK, don't care about blacklist */
    if ( (GNUNET_OK == result) &&
	 (1 == n->send_connect_ack) )
    {
      n->send_connect_ack = 2;
      send_session_connect_ack_message (n->primary_address.address,
					n->primary_address.session,
					n->connect_ack_timestamp);
    }
    break;     
  case S_DISCONNECT:
    /* Nothing to do here, ATS will already do what can be done */
    break;
  case S_DISCONNECT_FINISHED:
    /* should not be possible */
    GNUNET_assert (0);
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Unhandled state `%s' \n",print_state (n->state));
    GNUNET_break (0);
    free_neighbour (n, GNUNET_NO);
    break;
  }
 cleanup:
  GNUNET_HELLO_address_free (bcc->na.address);
  GNUNET_CONTAINER_DLL_remove (bc_head,
			       bc_tail,
			       bcc);
  GNUNET_free (bcc);
}


/**
 * We want to know if connecting to a particular peer via
 * a particular address is allowed.  Check it!
 *
 * @param peer identity of the peer to switch the address for
 * @param ts time at which the check was initiated
 * @param address address of the other peer, NULL if other peer
 *                       connected to us
 * @param session session to use (or NULL)
 * @param ats performance data
 * @param ats_count number of entries in ats (excluding 0-termination)
 */
static void
check_blacklist (const struct GNUNET_PeerIdentity *peer,
		 struct GNUNET_TIME_Absolute ts,
		 const struct GNUNET_HELLO_Address *address,
		 struct Session *session,
		 const struct GNUNET_ATS_Information *ats,
		 uint32_t ats_count)
{
  struct BlackListCheckContext *bcc;
  struct GST_BlacklistCheck *bc;

  bcc =
      GNUNET_malloc (sizeof (struct BlackListCheckContext) +
                     sizeof (struct GNUNET_ATS_Information) * ats_count);
  bcc->ats_count = ats_count;
  bcc->na.address = GNUNET_HELLO_address_copy (address);
  bcc->na.session = session;
  bcc->na.connect_timestamp = ts;
  bcc->ats = (struct GNUNET_ATS_Information *) &bcc[1];
  memcpy (bcc->ats, ats, sizeof (struct GNUNET_ATS_Information) * ats_count);
  GNUNET_CONTAINER_DLL_insert (bc_head,
			       bc_tail,
			       bcc);
  if (NULL != (bc = GST_blacklist_test_allowed (peer, 
						address->transport_name,
						&handle_test_blacklist_cont, bcc)))
    bcc->bc = bc; 
  /* if NULL == bc, 'cont' was already called and 'bcc' already free'd, so
     we must only store 'bc' if 'bc' is non-NULL... */
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
  struct NeighbourMapEntry *n;
  struct GNUNET_TIME_Absolute ts;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received CONNECT message from peer `%s'\n", 
	      GNUNET_i2s (peer));
  if (ntohs (message->size) != sizeof (struct SessionConnectMessage))
  {
    GNUNET_break_op (0);
    return;
  }
  if (NULL == neighbours)
    return; /* we're shutting down */
  scm = (const struct SessionConnectMessage *) message;
  GNUNET_break_op (0 == ntohl (scm->reserved));
  ts = GNUNET_TIME_absolute_ntoh (scm->timestamp);
  n = lookup_neighbour (peer);
  if (NULL == n)
    n = setup_neighbour (peer);
  n->send_connect_ack = 1;
  n->connect_ack_timestamp = ts;
  switch (n->state)
  {  
  case S_NOT_CONNECTED:
    n->state = S_CONNECT_RECV_ATS;
    n->timeout = GNUNET_TIME_relative_to_absolute (ATS_RESPONSE_TIMEOUT);
    GNUNET_ATS_reset_backoff (GST_ats, peer);
    GNUNET_ATS_suggest_address (GST_ats, peer);
    check_blacklist (peer, ts, address, session, ats, ats_count);
    break;
  case S_INIT_ATS:
  case S_INIT_BLACKLIST:
  case S_CONNECT_SENT:
  case S_CONNECT_RECV_ATS:
  case S_CONNECT_RECV_BLACKLIST:
  case S_CONNECT_RECV_ACK:
    /* It can never hurt to have an alternative address in the above cases, 
       see if it is allowed */
    check_blacklist (peer, ts, address, session, ats, ats_count);
    break;
  case S_CONNECTED:
    /* we are already connected and can thus send the ACK immediately;
       still, it can never hurt to have an alternative address, so also
       tell ATS  about it */
    GNUNET_assert (NULL != n->primary_address.address);
    GNUNET_assert (NULL != n->primary_address.session);
    n->send_connect_ack = 0;
    send_session_connect_ack_message (n->primary_address.address,
				      n->primary_address.session, ts);
    check_blacklist (peer, ts, address, session, ats, ats_count);
    break;
  case S_RECONNECT_ATS:
  case S_RECONNECT_BLACKLIST:
  case S_RECONNECT_SENT:
    /* It can never hurt to have an alternative address in the above cases, 
       see if it is allowed */
    check_blacklist (peer, ts, address, session, ats, ats_count);
    break;
  case S_CONNECTED_SWITCHING_BLACKLIST:
  case S_CONNECTED_SWITCHING_CONNECT_SENT:
    /* we are already connected and can thus send the ACK immediately;
       still, it can never hurt to have an alternative address, so also
       tell ATS  about it */
    GNUNET_assert (NULL != n->primary_address.address);
    GNUNET_assert (NULL != n->primary_address.session);
    n->send_connect_ack = 0;
    send_session_connect_ack_message (n->primary_address.address,
				      n->primary_address.session, ts);
    check_blacklist (peer, ts, address, session, ats, ats_count);
    break;
  case S_DISCONNECT:
    /* get rid of remains without terminating sessions, ready to re-try */
    free_neighbour (n, GNUNET_YES);
    n = setup_neighbour (peer);
    n->state = S_CONNECT_RECV_ATS;
    GNUNET_ATS_reset_backoff (GST_ats, peer);
    GNUNET_ATS_suggest_address (GST_ats, peer);
    break;
  case S_DISCONNECT_FINISHED:
    /* should not be possible */
    GNUNET_assert (0);
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Unhandled state `%s' \n",print_state (n->state));
    GNUNET_break (0);
    free_neighbour (n, GNUNET_NO);
    break;
  }
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
 */
void
GST_neighbours_switch_to_address (const struct GNUNET_PeerIdentity *peer,
				  const struct GNUNET_HELLO_Address *address,
				  struct Session *session,
				  const struct GNUNET_ATS_Information *ats,
				  uint32_t ats_count,
				  struct GNUNET_BANDWIDTH_Value32NBO
				  bandwidth_in,
				  struct GNUNET_BANDWIDTH_Value32NBO
				  bandwidth_out)
{
  struct NeighbourMapEntry *n;
  struct GNUNET_TRANSPORT_PluginFunctions *papi;

  GNUNET_assert (address->transport_name != NULL);
  if (NULL == (n = lookup_neighbour (peer)))
    return;

  /* Obtain an session for this address from plugin */
  if (NULL == (papi = GST_plugins_find (address->transport_name)))
  {
    /* we don't have the plugin for this address */
    GNUNET_ATS_address_destroyed (GST_ats, address, NULL);
    return;
  }
  if ((NULL == session) && (0 == address->address_length))
  {
    GNUNET_break (0);
    if (strlen (address->transport_name) > 0)
      GNUNET_ATS_address_destroyed (GST_ats, address, session);
    return;
  }
  if (NULL == session)
    session = papi->get_session (papi->cls, address);
  if (NULL == session)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Failed to obtain new session for peer `%s' and  address '%s'\n",
		GNUNET_i2s (&address->peer), GST_plugins_a2s (address));    
    GNUNET_ATS_address_destroyed (GST_ats, address, NULL);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "ATS tells us to switch to address '%s' for peer `%s'\n",
              (address->address_length != 0) ? GST_plugins_a2s (address): "<inbound>",
              GNUNET_i2s (peer));
  switch (n->state)
  {
  case S_NOT_CONNECTED:
    GNUNET_break (0);
    free_neighbour (n, GNUNET_NO);
    return;
  case S_INIT_ATS:
    set_address (&n->primary_address,
		 address, session, bandwidth_in, bandwidth_out, GNUNET_NO);
    n->state = S_INIT_BLACKLIST;
    n->timeout = GNUNET_TIME_relative_to_absolute (BLACKLIST_RESPONSE_TIMEOUT);
    check_blacklist (&n->id,
		     n->connect_ack_timestamp,
		     address, session, ats, ats_count);    
    break;
  case S_INIT_BLACKLIST:
    /* ATS suggests a different address, switch again */
    set_address (&n->primary_address,
		 address, session, bandwidth_in, bandwidth_out, GNUNET_NO);
    n->timeout = GNUNET_TIME_relative_to_absolute (BLACKLIST_RESPONSE_TIMEOUT);
    check_blacklist (&n->id,
		     n->connect_ack_timestamp,
		     address, session, ats, ats_count);    
    break;
  case S_CONNECT_SENT:
    /* ATS suggests a different address, switch again */
    set_address (&n->primary_address,
		 address, session, bandwidth_in, bandwidth_out, GNUNET_NO);
    n->state = S_INIT_BLACKLIST;
    n->timeout = GNUNET_TIME_relative_to_absolute (BLACKLIST_RESPONSE_TIMEOUT);
    check_blacklist (&n->id,
		     n->connect_ack_timestamp,
		     address, session, ats, ats_count);    
    break;
  case S_CONNECT_RECV_ATS:
    set_address (&n->primary_address,
		 address, session, bandwidth_in, bandwidth_out, GNUNET_NO);
    n->state = S_CONNECT_RECV_BLACKLIST;
    n->timeout = GNUNET_TIME_relative_to_absolute (BLACKLIST_RESPONSE_TIMEOUT);
    check_blacklist (&n->id,
		     n->connect_ack_timestamp,
		     address, session, ats, ats_count);    
    break;
  case S_CONNECT_RECV_BLACKLIST:
  case S_CONNECT_RECV_ACK:
    /* ATS asks us to switch while we were trying to connect; switch to new
       address and check blacklist again */
    set_address (&n->primary_address,
		 address, session, bandwidth_in, bandwidth_out, GNUNET_NO);
    n->timeout = GNUNET_TIME_relative_to_absolute (BLACKLIST_RESPONSE_TIMEOUT);
    check_blacklist (&n->id,
		     n->connect_ack_timestamp,
		     address, session, ats, ats_count);    
    break;
  case S_CONNECTED:
    GNUNET_assert (NULL != n->primary_address.address);
    GNUNET_assert (NULL != n->primary_address.session);
    if (n->primary_address.session == session)
    {
      /* not an address change, just a quota change */
      set_address (&n->primary_address,
		   address, session, bandwidth_in, bandwidth_out, GNUNET_YES);
      break;
    }
    /* ATS asks us to switch a life connection; see if we can get
       a CONNECT_ACK on it before we actually do this! */
    set_address (&n->alternative_address,
		 address, session, bandwidth_in, bandwidth_out, GNUNET_NO);
    n->state = S_CONNECTED_SWITCHING_BLACKLIST;
    check_blacklist (&n->id,
		     GNUNET_TIME_absolute_get (),
		     address, session, ats, ats_count);
    break;
  case S_RECONNECT_ATS:
    set_address (&n->primary_address,
		 address, session, bandwidth_in, bandwidth_out, GNUNET_NO);
    n->state = S_RECONNECT_BLACKLIST;
    n->timeout = GNUNET_TIME_relative_to_absolute (BLACKLIST_RESPONSE_TIMEOUT);
    check_blacklist (&n->id,
		     n->connect_ack_timestamp,
		     address, session, ats, ats_count);    
    break;
  case S_RECONNECT_BLACKLIST:
    /* ATS asks us to switch while we were trying to reconnect; switch to new
       address and check blacklist again */
    set_address (&n->primary_address,
		 address, session, bandwidth_in, bandwidth_out, GNUNET_NO);
    n->timeout = GNUNET_TIME_relative_to_absolute (BLACKLIST_RESPONSE_TIMEOUT);
    check_blacklist (&n->id,
		     n->connect_ack_timestamp,
		     address, session, ats, ats_count);    
    break;
  case S_RECONNECT_SENT:
    /* ATS asks us to switch while we were trying to reconnect; switch to new
       address and check blacklist again */
    set_address (&n->primary_address,
		 address, session, bandwidth_in, bandwidth_out, GNUNET_NO);
    n->state = S_RECONNECT_BLACKLIST;
    n->timeout = GNUNET_TIME_relative_to_absolute (BLACKLIST_RESPONSE_TIMEOUT);
    check_blacklist (&n->id,
		     n->connect_ack_timestamp,
		     address, session, ats, ats_count); 
    break;
  case S_CONNECTED_SWITCHING_BLACKLIST:
    if (n->primary_address.session == session)
    {
      /* ATS switches back to still-active session */
      free_address (&n->alternative_address);
      n->state = S_CONNECTED;
      break;
    }
    /* ATS asks us to switch a life connection, update blacklist check */
    set_address (&n->alternative_address,
		 address, session, bandwidth_in, bandwidth_out, GNUNET_NO);
    check_blacklist (&n->id,
		     GNUNET_TIME_absolute_get (),
		     address, session, ats, ats_count);
    break;
  case S_CONNECTED_SWITCHING_CONNECT_SENT:
    if (n->primary_address.session == session)
    {
      /* ATS switches back to still-active session */
      free_address (&n->alternative_address);
      n->state = S_CONNECTED;
      break;
    }
    /* ATS asks us to switch a life connection, update blacklist check */
    set_address (&n->alternative_address,
		 address, session, bandwidth_in, bandwidth_out, GNUNET_NO);
    n->state = S_CONNECTED_SWITCHING_BLACKLIST;
    check_blacklist (&n->id,
		     GNUNET_TIME_absolute_get (),
		     address, session, ats, ats_count);
    break;
  case S_DISCONNECT:
    /* not going to switch addresses while disconnecting */
    return;
  case S_DISCONNECT_FINISHED:
    GNUNET_assert (0);
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Unhandled state `%s' \n",print_state (n->state));
    GNUNET_break (0);
    break;
  }
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

  n->task = GNUNET_SCHEDULER_NO_TASK;
  delay = GNUNET_TIME_absolute_get_remaining (n->timeout);  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "master task runs for neighbour `%s' in state %d with timeout in %llu ms\n",
	      GNUNET_i2s (&n->id),
	      n->state,
	      (unsigned long long) delay.rel_value);
  switch (n->state)
  {
  case S_NOT_CONNECTED:
    /* invalid state for master task, clean up */
    GNUNET_break (0);
    n->state = S_DISCONNECT_FINISHED;
    free_neighbour (n, GNUNET_NO);
    return;
  case S_INIT_ATS:
    if (0 == delay.rel_value)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Connection to `%s' timed out waiting for ATS to provide address\n",
		  GNUNET_i2s (&n->id));
      n->state = S_DISCONNECT_FINISHED;
      free_neighbour (n, GNUNET_NO);
      return;
    }
    break;
  case S_INIT_BLACKLIST:
    if (0 == delay.rel_value)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Connection to `%s' timed out waiting for BLACKLIST to approve address\n",
		  GNUNET_i2s (&n->id));
      n->state = S_DISCONNECT_FINISHED;
      free_neighbour (n, GNUNET_NO);
      return;
    }
    break;
  case S_CONNECT_SENT:
    if (0 == delay.rel_value)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Connection to `%s' timed out waiting for other peer to send CONNECT_ACK\n",
		  GNUNET_i2s (&n->id));
      disconnect_neighbour (n);
      return;
    }
    break;
  case S_CONNECT_RECV_ATS:
    if (0 == delay.rel_value)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Connection to `%s' timed out waiting ATS to provide address to use for CONNECT_ACK\n",
		  GNUNET_i2s (&n->id));
      n->state = S_DISCONNECT_FINISHED;
      free_neighbour (n, GNUNET_NO);
      return;
    }
    break;
  case S_CONNECT_RECV_BLACKLIST:
    if (0 == delay.rel_value)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Connection to `%s' timed out waiting BLACKLIST to approve address to use for CONNECT_ACK\n",
		  GNUNET_i2s (&n->id));
      n->state = S_DISCONNECT_FINISHED;
      free_neighbour (n, GNUNET_NO);
      return;
    }
    break;
  case S_CONNECT_RECV_ACK:
    if (0 == delay.rel_value)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Connection to `%s' timed out waiting for other peer to send SESSION_ACK\n",
		  GNUNET_i2s (&n->id));
      disconnect_neighbour (n);
      return;
    }
    break;
  case S_CONNECTED:
    if (0 == delay.rel_value)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Connection to `%s' timed out, missing KEEPALIVE_RESPONSEs\n",
		  GNUNET_i2s (&n->id));
      disconnect_neighbour (n);
      return;
    }
    try_transmission_to_peer (n);
    send_keepalive (n);
    break;
  case S_RECONNECT_ATS:
    if (0 == delay.rel_value)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Connection to `%s' timed out, waiting for ATS replacement address\n",
		  GNUNET_i2s (&n->id));
      disconnect_neighbour (n);
      return;
    }
    break;
  case S_RECONNECT_BLACKLIST:
    if (0 == delay.rel_value)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Connection to `%s' timed out, waiting for BLACKLIST to approve replacement address\n",
		  GNUNET_i2s (&n->id));
      disconnect_neighbour (n);
      return;
    }
    break;
  case S_RECONNECT_SENT:
    if (0 == delay.rel_value)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Connection to `%s' timed out, waiting for other peer to CONNECT_ACK replacement address\n",
		  GNUNET_i2s (&n->id));
      disconnect_neighbour (n);
      return;
    }
    break;
  case S_CONNECTED_SWITCHING_BLACKLIST:
    if (0 == delay.rel_value)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Connection to `%s' timed out, missing KEEPALIVE_RESPONSEs\n",
		  GNUNET_i2s (&n->id));
      disconnect_neighbour (n);
      return;
    }
    try_transmission_to_peer (n);
    send_keepalive (n);
    break;
  case S_CONNECTED_SWITCHING_CONNECT_SENT:
    if (0 == delay.rel_value)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Connection to `%s' timed out, missing KEEPALIVE_RESPONSEs (after trying to CONNECT on alternative address)\n",
		  GNUNET_i2s (&n->id));
      disconnect_neighbour (n);
      return;
    }
    try_transmission_to_peer (n);
    send_keepalive (n);
    break;
  case S_DISCONNECT:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Cleaning up connection to `%s' after sending DISCONNECT\n",
		GNUNET_i2s (&n->id));
    n->state = S_DISCONNECT_FINISHED;
    free_neighbour (n, GNUNET_NO);
    return;
  case S_DISCONNECT_FINISHED:
    /* how did we get here!? */
    GNUNET_assert (0);
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Unhandled state `%s' \n",print_state (n->state));
    GNUNET_break (0);
    break;  
  }
  if ( (S_CONNECTED_SWITCHING_CONNECT_SENT == n->state) ||
       (S_CONNECTED_SWITCHING_BLACKLIST == n->state) ||
       (S_CONNECTED == n->state) )    
  {
    /* if we are *now* in one of these three states, we're sending
       keep alive messages, so we need to consider the keepalive
       delay, not just the connection timeout */
    delay = GNUNET_TIME_relative_min (GNUNET_TIME_absolute_get_remaining (n->keep_alive_time),
				      delay);
  }
  if (GNUNET_SCHEDULER_NO_TASK == n->task)
    n->task = GNUNET_SCHEDULER_add_delayed (delay,
					    &master_task,
					    n);
}


/**
 * Send a SESSION_ACK message to the neighbour to confirm that we
 * got his CONNECT_ACK.
 *
 * @param n neighbour to send the SESSION_ACK to
 */
static void
send_session_ack_message (struct NeighbourMapEntry *n)
{
  struct GNUNET_MessageHeader msg;

  msg.size = htons (sizeof (struct GNUNET_MessageHeader));
  msg.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_ACK);
  (void) send_with_session(n,
			   (const char *) &msg, sizeof (struct GNUNET_MessageHeader),
			   UINT32_MAX, GNUNET_TIME_UNIT_FOREVER_REL,
			   NULL, NULL);
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
  struct GNUNET_TIME_Absolute ts;
  struct NeighbourMapEntry *n;

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
  if (NULL == (n = lookup_neighbour (peer)))
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# unexpected CONNECT_ACK messages (no peer)"),
                              1, GNUNET_NO);
    return;
  }
  ts = GNUNET_TIME_absolute_ntoh (scm->timestamp);
  switch (n->state)
  {
  case S_NOT_CONNECTED:
    GNUNET_break (0);
    free_neighbour (n, GNUNET_NO);
    return;
  case S_INIT_ATS:
  case S_INIT_BLACKLIST:
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# unexpected CONNECT_ACK messages (not ready)"),
                              1, GNUNET_NO);
    break;    
  case S_CONNECT_SENT:
    if (ts.abs_value != n->primary_address.connect_timestamp.abs_value)
      break; /* ACK does not match our original CONNECT message */
    n->state = S_CONNECTED;
    n->timeout = GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
    GNUNET_STATISTICS_set (GST_stats, 
			   gettext_noop ("# peers connected"), 
			   ++neighbours_connected,
			   GNUNET_NO);
    connect_notify_cb (callback_cls, &n->id, ats, ats_count);
    set_address (&n->primary_address,
		 n->primary_address.address,
		 n->primary_address.session,
		 n->primary_address.bandwidth_in,
		 n->primary_address.bandwidth_out,
		 GNUNET_YES);
    send_session_ack_message (n);
    break;
  case S_CONNECT_RECV_ATS:
  case S_CONNECT_RECV_BLACKLIST:
  case S_CONNECT_RECV_ACK:
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# unexpected CONNECT_ACK messages (not ready)"),
                              1, GNUNET_NO);
    break;
  case S_CONNECTED:
    /* duplicate CONNECT_ACK, let's answer by duplciate SESSION_ACK just in case */
    send_session_ack_message (n);
    break;
  case S_RECONNECT_ATS:
  case S_RECONNECT_BLACKLIST:
    /* we didn't expect any CONNECT_ACK, as we are waiting for ATS
       to give us a new address... */
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# unexpected CONNECT_ACK messages (waiting on ATS)"),
                              1, GNUNET_NO);
    break;
  case S_RECONNECT_SENT:
    /* new address worked; go back to connected! */
    n->state = S_CONNECTED;
    send_session_ack_message (n);
    break;
  case S_CONNECTED_SWITCHING_BLACKLIST:
    /* duplicate CONNECT_ACK, let's answer by duplciate SESSION_ACK just in case */
    send_session_ack_message (n);
    break;
  case S_CONNECTED_SWITCHING_CONNECT_SENT:
    /* new address worked; adopt it and go back to connected! */
    n->state = S_CONNECTED;
    n->timeout = GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
    GNUNET_break (GNUNET_NO == n->alternative_address.ats_active);
    set_address (&n->primary_address,
		 n->alternative_address.address,
		 n->alternative_address.session,
		 n->alternative_address.bandwidth_in,
		 n->alternative_address.bandwidth_out,
		 GNUNET_YES);
    free_address (&n->alternative_address);
    send_session_ack_message (n);
    break;    
  case S_DISCONNECT:
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop
                              ("# unexpected CONNECT_ACK messages (disconnecting)"),
                              1, GNUNET_NO);
    break;
  case S_DISCONNECT_FINISHED:
    GNUNET_assert (0);
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Unhandled state `%s' \n",print_state (n->state));
    GNUNET_break (0);
    break;   
  }
}


/**
 * A session was terminated. Take note; if needed, try to get
 * an alternative address from ATS.
 *
 * @param peer identity of the peer where the session died
 * @param session session that is gone
 */
void
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
      GST_blacklist_test_cancel (bcc->bc);
      GNUNET_HELLO_address_free (bcc->na.address);
      GNUNET_CONTAINER_DLL_remove (bc_head,
				   bc_tail,
				   bcc);
      GNUNET_free (bcc);
    }
  }
  if (NULL == (n = lookup_neighbour (peer)))
    return; /* can't affect us */
  if (session != n->primary_address.session)
  {
    if (session == n->alternative_address.session)
    {
      free_address (&n->alternative_address);
      if ( (S_CONNECTED_SWITCHING_BLACKLIST == n->state) ||
	   (S_CONNECTED_SWITCHING_CONNECT_SENT == n->state) )
	n->state = S_CONNECTED;
      else
	GNUNET_break (0);
    }
    return; /* doesn't affect us further */
  }

  n->expect_latency_response = GNUNET_NO;

  switch (n->state)
  {
  case S_NOT_CONNECTED:
    GNUNET_break (0);
    free_neighbour (n, GNUNET_NO);
    return;
  case S_INIT_ATS:
    GNUNET_break (0);
    free_neighbour (n, GNUNET_NO);
    return;
  case S_INIT_BLACKLIST:
  case S_CONNECT_SENT:
    free_address (&n->primary_address);
    n->state = S_INIT_ATS;
    n->timeout = GNUNET_TIME_relative_to_absolute (ATS_RESPONSE_TIMEOUT);
    // FIXME: need to ask ATS for suggestions again?
    GNUNET_ATS_suggest_address (GST_ats, &n->id);
    break;
  case S_CONNECT_RECV_ATS:    
  case S_CONNECT_RECV_BLACKLIST:
  case S_CONNECT_RECV_ACK:
    /* error on inbound session; free neighbour entirely */
    free_address (&n->primary_address);
    free_neighbour (n, GNUNET_NO);
    return;
  case S_CONNECTED:
    free_address (&n->primary_address);
    n->state = S_RECONNECT_ATS;
    n->timeout = GNUNET_TIME_relative_to_absolute (ATS_RESPONSE_TIMEOUT);
    /* FIXME: is this ATS call needed? */
    GNUNET_ATS_suggest_address (GST_ats, &n->id);
    break;
  case S_RECONNECT_ATS:
    /* we don't have an address, how can it go down? */
    GNUNET_break (0);
    break;
  case S_RECONNECT_BLACKLIST:
  case S_RECONNECT_SENT:
    n->state = S_RECONNECT_ATS;
    n->timeout = GNUNET_TIME_relative_to_absolute (ATS_RESPONSE_TIMEOUT);
    // FIXME: need to ask ATS for suggestions again?
    GNUNET_ATS_suggest_address (GST_ats, &n->id);
    break;
  case S_CONNECTED_SWITCHING_BLACKLIST:
    /* primary went down while we were checking secondary against
       blacklist, adopt secondary as primary */       
    free_address (&n->primary_address);
    n->primary_address = n->alternative_address;
    memset (&n->alternative_address, 0, sizeof (struct NeighbourAddress));
    n->timeout = GNUNET_TIME_relative_to_absolute (FAST_RECONNECT_TIMEOUT);
    n->state = S_RECONNECT_BLACKLIST;
    break;
  case S_CONNECTED_SWITCHING_CONNECT_SENT:
    /* primary went down while we were waiting for CONNECT_ACK on secondary;
       secondary as primary */       
    free_address (&n->primary_address);
    n->primary_address = n->alternative_address;
    memset (&n->alternative_address, 0, sizeof (struct NeighbourAddress));
    n->timeout = GNUNET_TIME_relative_to_absolute (FAST_RECONNECT_TIMEOUT);
    n->state = S_RECONNECT_SENT;
    break;
  case S_DISCONNECT:
    free_address (&n->primary_address);
    break;
  case S_DISCONNECT_FINISHED:
    /* neighbour was freed and plugins told to terminate session */
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Unhandled state `%s' \n",print_state (n->state));
    GNUNET_break (0);
    break;
  }
  if (GNUNET_SCHEDULER_NO_TASK != n->task)
    GNUNET_SCHEDULER_cancel (n->task);
  n->task = GNUNET_SCHEDULER_add_now (&master_task, n);
}


/**
 * We received a 'SESSION_ACK' message from the other peer.
 * If we sent a 'CONNECT_ACK' last, this means we are now
 * connected.  Otherwise, do nothing.
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
GST_neighbours_handle_session_ack (const struct GNUNET_MessageHeader *message,
				   const struct GNUNET_PeerIdentity *peer,
				   const struct GNUNET_HELLO_Address *address,
				   struct Session *session,
				   const struct GNUNET_ATS_Information *ats,
				   uint32_t ats_count)
{
  struct NeighbourMapEntry *n;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Received SESSION_ACK message from peer `%s'\n",
              GNUNET_i2s (peer));
  if (ntohs (message->size) != sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break_op (0);
    return;
  }
  if (NULL == (n = lookup_neighbour (peer)))
    return;
  /* check if we are in a plausible state for having sent
     a CONNECT_ACK.  If not, return, otherwise break */
  if ( ( (S_CONNECT_RECV_ACK != n->state) &&
	 (S_CONNECT_SENT != n->state) ) ||
       (2 != n->send_connect_ack) )
  {
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop ("# unexpected SESSION ACK messages"), 1,
                              GNUNET_NO);
    return;
  }
  n->state = S_CONNECTED;
  n->timeout = GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
  GNUNET_STATISTICS_set (GST_stats, 
			 gettext_noop ("# peers connected"), 
			 ++neighbours_connected,
			 GNUNET_NO);
  connect_notify_cb (callback_cls, &n->id, ats, ats_count);
  set_address (&n->primary_address,
	       n->primary_address.address,
	       n->primary_address.session,
	       n->primary_address.bandwidth_in,
	       n->primary_address.bandwidth_out,
	       GNUNET_YES);
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
  return test_connected (lookup_neighbour (target));
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
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Disconnecting peer `%4s' due to `%s'\n",
              GNUNET_i2s (&n->id), "SET_QUOTA");
  if (GNUNET_YES == test_connected (n))
    GNUNET_STATISTICS_update (GST_stats,
                              gettext_noop ("# disconnects due to quota of 0"),
                              1, GNUNET_NO);
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received DISCONNECT message from peer `%s'\n",
              GNUNET_i2s (peer));
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
  if (NULL == (n = lookup_neighbour (peer)))
    return;                     /* gone already */
  if (GNUNET_TIME_absolute_ntoh (sdm->timestamp).abs_value <= n->connect_ack_timestamp.abs_value)
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
  if (GNUNET_YES == test_connected (n))
    GNUNET_STATISTICS_update (GST_stats,
			      gettext_noop
			      ("# other peer asked to disconnect from us"), 1,
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

  if (GNUNET_YES == test_connected (n))
    ic->cb (ic->cb_cls, &n->id, NULL, 0, n->primary_address.address);
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

  if (NULL == (n = lookup_neighbour (target)))
    return;  /* not active */
  if (GNUNET_YES == test_connected (n))
    GNUNET_STATISTICS_update (GST_stats,
			      gettext_noop
			      ("# disconnected from peer upon explicit request"), 1,
			      GNUNET_NO);
  disconnect_neighbour (n);
}


/**
 * Obtain current latency information for the given neighbour.
 *
 * @param peer to get the latency for
 * @return observed latency of the address, FOREVER if the 
 *         the connection is not up
 */
struct GNUNET_TIME_Relative
GST_neighbour_get_latency (const struct GNUNET_PeerIdentity *peer)
{
  struct NeighbourMapEntry *n;

  n = lookup_neighbour (peer);
  if (NULL == n) 
    return GNUNET_TIME_UNIT_FOREVER_REL;
  switch (n->state)
  {
  case S_CONNECTED:
  case S_RECONNECT_SENT:
  case S_RECONNECT_ATS:
    return n->latency;
  case S_NOT_CONNECTED:
  case S_INIT_BLACKLIST:
  case S_INIT_ATS:
  case S_CONNECT_SENT:
  case S_CONNECT_RECV_BLACKLIST:
  case S_DISCONNECT:
  case S_DISCONNECT_FINISHED:
    return GNUNET_TIME_UNIT_FOREVER_REL;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Unhandled state `%s' \n",print_state (n->state));
    GNUNET_break (0);
    break;
  }
  return GNUNET_TIME_UNIT_FOREVER_REL;   
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


/**
 * Disconnect from the given neighbour.
 *
 * @param cls unused
 * @param key hash of neighbour's public key (not used)
 * @param value the 'struct NeighbourMapEntry' of the neighbour
 * @return GNUNET_OK (continue to iterate)
 */
static int
disconnect_all_neighbours (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct NeighbourMapEntry *n = value;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Disconnecting peer `%4s', %s\n",
              GNUNET_i2s (&n->id), "SHUTDOWN_TASK");
  n->state = S_DISCONNECT_FINISHED;
  free_neighbour (n, GNUNET_NO);
  return GNUNET_OK;
}


/**
 * Cleanup the neighbours subsystem.
 */
void
GST_neighbours_stop ()
{
  if (NULL == neighbours)
    return;
  GNUNET_CONTAINER_multihashmap_iterate (neighbours, 
					 &disconnect_all_neighbours,
                                         NULL);
  GNUNET_CONTAINER_multihashmap_destroy (neighbours);
  neighbours = NULL;
  callback_cls = NULL;
  connect_notify_cb = NULL;
  disconnect_notify_cb = NULL;
  address_change_cb = NULL;
}


/* end of file gnunet-service-transport_neighbours.c */
