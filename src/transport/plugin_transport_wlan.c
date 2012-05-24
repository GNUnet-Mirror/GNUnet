/*
  This file is part of GNUnet
  (C) 2010, 2011, 2012 Christian Grothoff (and other contributing authors)

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
 * @file transport/plugin_transport_wlan.c
 * @brief transport plugin for wlan
 * @author David Brodski
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_transport_plugin.h"
#include "plugin_transport_wlan.h"
#include "gnunet_common.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_fragmentation_lib.h"
#include "gnunet_constants.h"

#define LOG(kind,...) GNUNET_log_from (kind, "transport-wlan",__VA_ARGS__)

/**
 * Max size of packet (that we give to the WLAN driver for transmission)
 */
#define WLAN_MTU 1430

/**
 * time out of a mac endpoint
 */
#define MACENDPOINT_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT, 2)

/**
 * We reduce the frequence of HELLO beacons in relation to
 * the number of MAC addresses currently visible to us.
 * This is the multiplication factor.
 */
#define HELLO_BEACON_SCALING_FACTOR GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 2)

/**
 * Maximum number of messages in defragmentation queue per MAC
 */
#define MESSAGES_IN_DEFRAG_QUEUE_PER_MAC 2

/**
 * Link layer control fields for better compatibility
 * (i.e. GNUnet over WLAN is not IP-over-WLAN).
 */
#define WLAN_LLC_DSAP_FIELD 0x1f
#define WLAN_LLC_SSAP_FIELD 0x1f


GNUNET_NETWORK_STRUCT_BEGIN
/**
 * Header for messages which need fragmentation.  This is the format of
 * a message we obtain AFTER defragmentation.  We then need to check
 * the CRC and then tokenize the payload and pass it to the 
 * 'receive' callback.
 */
struct WlanHeader
{

  /**
   * Message type is GNUNET_MESSAGE_TYPE_WLAN_DATA.
   */
  struct GNUNET_MessageHeader header;

  /**
   * CRC32 checksum (only over the payload), in NBO.
   */
  uint32_t crc GNUNET_PACKED;

  /**
   * Sender of the message.
   */
  struct GNUNET_PeerIdentity sender;

  /**
   * Target of the message.
   */
  struct GNUNET_PeerIdentity target;

  /* followed by payload, possibly including
     multiple messages! */

};
GNUNET_NETWORK_STRUCT_END


/**
 * Information kept for each message that is yet to be fragmented and
 * transmitted.
 */
struct PendingMessage
{
  /**
   * next entry in the DLL
   */
  struct PendingMessage *next;

  /**
   * previous entry in the DLL
   */
  struct PendingMessage *prev;

  /**
   * The pending message
   */
  struct WlanHeader *msg;

  /**
   * Continuation function to call once the message
   * has been sent.  Can be NULL if there is no
   * continuation to call.
   */
  GNUNET_TRANSPORT_TransmitContinuation transmit_cont;

  /**
   * Cls for transmit_cont
   */
  void *transmit_cont_cls;

  /**
   * Timeout task (for this message).
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

};


/**
 * Session handle for connections with other peers.
 */
struct Session
{

  /**
   * API requirement (must be first).
   */
  struct SessionHeader header;

  /**
   * We keep all sessions in a DLL at their respective
   * 'struct MACEndpoint'.
   */
  struct Session *next;

  /**
   * We keep all sessions in a DLL at their respective
   * 'struct MACEndpoint'.
   */
  struct Session *prev;

  /**
   * MAC endpoint with the address of this peer.
   */
  struct MacEndpoint *mac;

  /**
   * Head of messages currently pending for transmission to this peer.
   */
  struct PendingMessage *pending_message_head;

  /**
   * Tail of messages currently pending for transmission to this peer.
   */
  struct PendingMessage *pending_message_tail;

  /**
   * To whom are we talking to (set to our identity
   * if we are still waiting for the welcome message)
   */
  struct GNUNET_PeerIdentity target;

  /**
   * When should this session time out?
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Timeout task (for the session).
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

};


/**
 * Struct for messages that are being fragmented in a MAC's transmission queue.
 */
struct FragmentMessage
{

  /**
   * This is a doubly-linked list.
   */
  struct FragmentMessage *next;

  /**
   * This is a doubly-linked list.
   */
  struct FragmentMessage *prev;

  /**
   * MAC endpoint this message belongs to
   */
  struct MacEndpoint *macendpoint;

  /**
   * Fragmentation context
   */
  struct GNUNET_FRAGMENT_Context *fragcontext;

  /**
   * Transmission handle to helper (to cancel if the frag context
   * is destroyed early for some reason).
   */
  struct GNUNET_HELPER_SendHandle *sh;

  /**
   * Intended recipient.
   */
  struct GNUNET_PeerIdentity target;

  /**
   * Timeout value for the message.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Timeout task.
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * Continuation to call when we're done with this message.
   */
  GNUNET_TRANSPORT_TransmitContinuation cont;

  /**
   * Closure for 'cont'
   */
  void *cont_cls;

};


/**
 * Struct to represent one network card connection
 */
struct MacEndpoint
{

  /**
   * We keep all MACs in a DLL in the plugin.
   */
  struct MacEndpoint *next;

  /**
   * We keep all MACs in a DLL in the plugin.
   */
  struct MacEndpoint *prev;

  /**
   * Pointer to the global plugin struct.
   */
  struct Plugin *plugin;

  /**
   * Head of sessions that use this MAC.
   */
  struct Session *sessions_head;

  /**
   * Tail of sessions that use this MAC.
   */
  struct Session *sessions_tail;

  /**
   * Head of messages we are currently sending to this MAC.
   */
  struct FragmentMessage *sending_messages_head;

  /**
   * Tail of messages we are currently sending to this MAC.
   */
  struct FragmentMessage *sending_messages_tail;

  /**
   * Defrag context for this MAC
   */
  struct GNUNET_DEFRAGMENT_Context *defrag;

  /**
   * When should this endpoint time out?
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Timeout task.
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * count of messages in the fragment out queue for this mac endpoint
   */
  unsigned int fragment_messages_out_count;

  /**
   * peer mac address
   */
  struct GNUNET_TRANSPORT_WLAN_MacAddress addr;

  /**
   * Desired transmission power for this MAC
   */
  uint16_t tx_power;

  /**
   * Desired transmission rate for this MAC
   */
  uint8_t rate;

  /**
   * Antenna we should use for this MAC
   */
  uint8_t antenna;

};


/**
 * Encapsulation of all of the state of the plugin.
 */
struct Plugin
{
  /**
   * Our environment.
   */
  struct GNUNET_TRANSPORT_PluginEnvironment *env;

  /**
   * Handle to helper process for priviledged operations.
   */ 
  struct GNUNET_HELPER_Handle *suid_helper;

  /**
   * ARGV-vector for the helper (all helpers take only the binary
   * name, one actual argument, plus the NULL terminator for 'argv').
   */
  char * helper_argv[3];

  /**
   * The interface of the wlan card given to us by the user.
   */
  char *interface;

  /**
   * Tokenizer for demultiplexing of data packets resulting from defragmentation.
   */
  struct GNUNET_SERVER_MessageStreamTokenizer *fragment_data_tokenizer;

  /**
   * Tokenizer for demultiplexing of data packets received from the suid helper
   */
  struct GNUNET_SERVER_MessageStreamTokenizer *helper_payload_tokenizer;

  /**
   * Tokenizer for demultiplexing of data packets that follow the WLAN Header
   */
  struct GNUNET_SERVER_MessageStreamTokenizer *wlan_header_payload_tokenizer;

  /**
   * Head of list of open connections.
   */
  struct MacEndpoint *mac_head;

  /**
   * Tail of list of open connections.
   */
  struct MacEndpoint *mac_tail;

  /**
   * Number of connections
   */
  unsigned int mac_count;

  /**
   * Task that periodically sends a HELLO beacon via the helper.
   */
  GNUNET_SCHEDULER_TaskIdentifier beacon_task;

  /**
   * Tracker for bandwidth limit
   */
  struct GNUNET_BANDWIDTH_Tracker tracker;

  /**
   * The mac_address of the wlan card given to us by the helper.
   */
  struct GNUNET_TRANSPORT_WLAN_MacAddress mac_address;

  /**
   * Have we received a control message with our MAC address yet?
   */
  int have_mac;


};


/**
 * Information associated with a message.  Can contain
 * the session or the MAC endpoint associated with the
 * message (or both).
 */
struct MacAndSession
{
  /**
   * NULL if the identity of the other peer is not known.
   */
  struct Session *session;

  /**
   * MAC address of the other peer, NULL if not known.
   */
  struct MacEndpoint *endpoint;
};


/**
 * Print MAC addresses nicely.
 *
 * @param mac the mac address
 * @return string to a static buffer with the human-readable mac, will be overwritten during the next call to this function
 */
static const char *
mac_to_string (const struct GNUNET_TRANSPORT_WLAN_MacAddress * mac)
{
  static char macstr[20];

  GNUNET_snprintf (macstr, sizeof (macstr), "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", mac->mac[0], mac->mac[1],
                   mac->mac[2], mac->mac[3], mac->mac[4], mac->mac[5]);
  return macstr;
}


/**
 * Fill the radiotap header
 *
 * @param endpoint pointer to the endpoint, can be NULL
 * @param header pointer to the radiotap header
 * @param size total message size
 */
static void
get_radiotap_header (struct MacEndpoint *endpoint,
		     struct GNUNET_TRANSPORT_WLAN_RadiotapSendMessage *header,
		     uint16_t size)
{
  header->header.type = ntohs (GNUNET_MESSAGE_TYPE_WLAN_DATA_TO_HELPER);
  header->header.size = ntohs (size);
  if (NULL != endpoint)
  {
    header->rate = endpoint->rate;
    header->tx_power = endpoint->tx_power;
    header->antenna = endpoint->antenna;
  }
  else
  {
    header->rate = 255;
    header->tx_power = 0;
    header->antenna = 0;
  }
}


/**
 * Generate the WLAN hardware header for one packet
 *
 * @param plugin the plugin handle
 * @param header address to write the header to
 * @param to_mac_addr address of the recipient
 * @param size size of the whole packet, needed to calculate the time to send the packet
 */
static void
get_wlan_header (struct Plugin *plugin,
		 struct GNUNET_TRANSPORT_WLAN_Ieee80211Frame *header,
		 const struct GNUNET_TRANSPORT_WLAN_MacAddress *to_mac_addr, 
		 unsigned int size)
{
  const int rate = 11000000;

  header->frame_control = htons (IEEE80211_FC0_TYPE_DATA);
  header->addr1 = *to_mac_addr;
  header->addr2 = plugin->mac_address;
  header->addr3 = mac_bssid_gnunet;
  header->duration = GNUNET_htole16 ((size * 1000000) / rate + 290);
  header->sequence_control = 0; // FIXME?
  header->llc[0] = WLAN_LLC_DSAP_FIELD;
  header->llc[1] = WLAN_LLC_SSAP_FIELD;
  header->llc[2] = 0;  // FIXME?
  header->llc[3] = 0;  // FIXME?
}


/**
 * Send an ACK for a fragment we received.
 *
 * @param cls the 'struct MacEndpoint' the ACK must be sent to
 * @param msg_id id of the message
 * @param hdr pointer to the hdr where the ack is stored
 */
static void
send_ack (void *cls, uint32_t msg_id,
	  const struct GNUNET_MessageHeader *hdr)
{
  struct MacEndpoint *endpoint = cls;
  struct GNUNET_TRANSPORT_WLAN_RadiotapSendMessage* radio_header;
  uint16_t msize = ntohs (hdr->size);
  size_t size = sizeof (struct GNUNET_TRANSPORT_WLAN_RadiotapSendMessage) + msize;
  char buf[size];

  if (size >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, 
       "Sending ACK to helper\n");
  radio_header = (struct GNUNET_TRANSPORT_WLAN_RadiotapSendMessage *) buf;
  get_radiotap_header (endpoint, radio_header, size);
  get_wlan_header (endpoint->plugin,
		   &radio_header->frame, 
		   &endpoint->addr, 
		   size);
  memcpy (&radio_header[1], hdr, msize);
  if (NULL !=
      GNUNET_HELPER_send (endpoint->plugin->suid_helper,
			  &radio_header->header,
			  GNUNET_NO /* dropping ACKs is bad */,
			  NULL, NULL))    
    GNUNET_STATISTICS_update (endpoint->plugin->env->stats, _("# WLAN ACKs sent"),
			      1, GNUNET_NO);
}


/**
 * Handles the data after all fragments are put together
 *
 * @param cls macendpoint this messages belongs to
 * @param hdr pointer to the data
 */
static void
wlan_data_message_handler (void *cls, const struct GNUNET_MessageHeader *hdr)
{
  struct MacEndpoint *endpoint = cls;
  struct Plugin *plugin = endpoint->plugin;
  struct MacAndSession mas;

  GNUNET_STATISTICS_update (plugin->env->stats,
			    _("# WLAN messages defragmented"), 1,
			    GNUNET_NO);
  mas.session = NULL;
  mas.endpoint = endpoint;
  (void) GNUNET_SERVER_mst_receive (plugin->fragment_data_tokenizer, 
				    &mas,
				    (const char *) hdr,
				    ntohs (hdr->size),
				    GNUNET_YES, GNUNET_NO);
}


/**
 * Free a session
 *
 * @param session the session free
 */
static void
free_session (struct Session *session)
{
  struct MacEndpoint *endpoint = session->mac;
  struct PendingMessage *pm;
  
  endpoint->plugin->env->session_end (endpoint->plugin->env->cls,
				      &session->target,
				      session);
  while (NULL != (pm = session->pending_message_head))
  {
    GNUNET_CONTAINER_DLL_remove (session->pending_message_head,
                                 session->pending_message_tail, pm);
    if (GNUNET_SCHEDULER_NO_TASK != pm->timeout_task)
    {
      GNUNET_SCHEDULER_cancel (pm->timeout_task);
      pm->timeout_task = GNUNET_SCHEDULER_NO_TASK;
    }
    GNUNET_free (pm->msg);
    GNUNET_free (pm);
  }
  GNUNET_CONTAINER_DLL_remove (endpoint->sessions_head, 
			       endpoint->sessions_tail,
                               session);
  if (session->timeout_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (session->timeout_task);
    session->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_STATISTICS_update (endpoint->plugin->env->stats, _("# WLAN sessions allocated"), -1,
                            GNUNET_NO);
  GNUNET_free (session);
}


/**
 * A session is timing out.  Clean up.
 *
 * @param cls pointer to the Session
 * @param tc pointer to the GNUNET_SCHEDULER_TaskContext
 */
static void
session_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Session * session = cls;
  struct GNUNET_TIME_Relative timeout;

  session->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  timeout = GNUNET_TIME_absolute_get_remaining (session->timeout);
  if (0 == timeout.rel_value) 
  {
    free_session (session);
    return;
  }
  session->timeout_task =
    GNUNET_SCHEDULER_add_delayed (timeout, &session_timeout, session);
}


/**
 * Create a new session
 *
 * @param endpoint pointer to the mac endpoint of the peer
 * @param peer peer identity to use for this session
 * @return returns the session
 */
static struct Session *
create_session (struct MacEndpoint *endpoint,
                const struct GNUNET_PeerIdentity *peer)
{
  struct Session *session;

  for (session = endpoint->sessions_head; NULL != session; session = session->next)
    if (0 == memcmp (peer, &session->target,
		     sizeof (struct GNUNET_PeerIdentity)))
    {
      session->timeout = GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
      return session;
    }
  GNUNET_STATISTICS_update (endpoint->plugin->env->stats, _("# WLAN sessions allocated"), 1,
                            GNUNET_NO);
  session = GNUNET_malloc (sizeof (struct Session));
  GNUNET_CONTAINER_DLL_insert_tail (endpoint->sessions_head,
                                    endpoint->sessions_tail,
				    session);
  session->mac = endpoint;
  session->target = *peer;
  session->timeout = GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
  session->timeout_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT, &session_timeout, session);
  LOG (GNUNET_ERROR_TYPE_DEBUG, 
       "Created new session for peer `%s' with endpoint %s\n",
       GNUNET_i2s (peer),
       mac_to_string (&endpoint->addr));
  return session;
}


/**
 * Function called once we have successfully given the fragment
 * message to the SUID helper process and we are thus ready for
 * the next fragment.
 *
 * @param cls the 'struct FragmentMessage' 
 * @param result result of the operation (GNUNET_OK on success, GNUNET_NO if the helper died, GNUNET_SYSERR
 *        if the helper was stopped)
 */
static void
fragment_transmission_done (void *cls,
			    int result)
{
  struct FragmentMessage *fm = cls;

  fm->sh = NULL;
  GNUNET_FRAGMENT_context_transmission_done (fm->fragcontext);
}


/**
 * Transmit a fragment of a message.
 *
 * @param cls 'struct FragmentMessage' this fragment message belongs to
 * @param hdr pointer to the start of the fragment message 
 */
static void
transmit_fragment (void *cls,
		   const struct GNUNET_MessageHeader *hdr)
{
  struct FragmentMessage *fm = cls;
  struct MacEndpoint *endpoint = fm->macendpoint;
  size_t size;
  uint16_t msize;

  msize = ntohs (hdr->size);
  size = sizeof (struct GNUNET_TRANSPORT_WLAN_RadiotapSendMessage) + msize;
  {
    char buf[size];
    struct GNUNET_TRANSPORT_WLAN_RadiotapSendMessage *radio_header;

    radio_header = (struct GNUNET_TRANSPORT_WLAN_RadiotapSendMessage *) buf;
    get_radiotap_header (endpoint, radio_header, size);
    get_wlan_header (endpoint->plugin,
		     &radio_header->frame, 
		     &endpoint->addr,
		     size);
    memcpy (&radio_header[1], hdr, msize);
    GNUNET_assert (NULL == fm->sh);
    fm->sh = GNUNET_HELPER_send (endpoint->plugin->suid_helper,
				 &radio_header->header,
				 GNUNET_NO,
				 &fragment_transmission_done, fm);
    if (NULL != fm->sh)
      GNUNET_STATISTICS_update (endpoint->plugin->env->stats, _("# WLAN message fragments sent"),
				1, GNUNET_NO);
    else
      GNUNET_FRAGMENT_context_transmission_done (fm->fragcontext);
  }
}


/**
 * Frees the space of a message in the fragment queue (send queue)
 *
 * @param fm message to free
 */
static void
free_fragment_message (struct FragmentMessage *fm)
{
  struct MacEndpoint *endpoint = fm->macendpoint;

  GNUNET_STATISTICS_update (endpoint->plugin->env->stats, _("# WLAN messages pending (with fragmentation)"), 
			    -1, GNUNET_NO);
  GNUNET_CONTAINER_DLL_remove (endpoint->sending_messages_head,
                               endpoint->sending_messages_tail, fm);
  if (NULL != fm->sh)
  {
    GNUNET_HELPER_send_cancel (fm->sh);
    fm->sh = NULL;
  }
  GNUNET_FRAGMENT_context_destroy (fm->fragcontext);
  if (fm->timeout_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (fm->timeout_task);
    fm->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_free (fm);
}


/**
 * A FragmentMessage has timed out.  Remove it.
 *
 * @param cls pointer to the 'struct FragmentMessage'
 * @param tc pointer to the GNUNET_SCHEDULER_TaskContext
 */
static void
fragmentmessage_timeout (void *cls,
                         const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct FragmentMessage *fm = cls;

  fm->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  if (NULL != fm->cont)
  {
    fm->cont (fm->cont_cls, &fm->target, GNUNET_SYSERR);
    fm->cont = NULL;
  }
  free_fragment_message (fm);
}


/**
 * Transmit a message to the given destination with fragmentation.
 *
 * @param endpoint desired destination
 * @param timeout how long can the message wait?
 * @param target peer that should receive the message
 * @param msg message to transmit
 * @param cont continuation to call once the message has
 *        been transmitted (or if the transport is ready
 *        for the next transmission call; or if the
 *        peer disconnected...); can be NULL
 * @param cont_cls closure for cont
 */
static void
send_with_fragmentation (struct MacEndpoint *endpoint,
			 struct GNUNET_TIME_Relative timeout,
			 const struct GNUNET_PeerIdentity *target,			 
			 const struct GNUNET_MessageHeader *msg,
			 GNUNET_TRANSPORT_TransmitContinuation cont, void *cont_cls)

{
  struct FragmentMessage *fm;
  struct Plugin *plugin;

  plugin = endpoint->plugin;
  fm = GNUNET_malloc (sizeof (struct FragmentMessage));
  fm->macendpoint = endpoint;
  fm->target = *target;
  fm->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  fm->cont = cont;
  fm->cont_cls = cont_cls;
  fm->fragcontext =
    GNUNET_FRAGMENT_context_create (plugin->env->stats, WLAN_MTU,
				    &plugin->tracker,
				    GNUNET_TIME_UNIT_SECONDS,
				    msg,
				    &transmit_fragment, fm);
  fm->timeout_task =
    GNUNET_SCHEDULER_add_delayed (timeout, 
				  &fragmentmessage_timeout, fm);
  GNUNET_CONTAINER_DLL_insert_tail (endpoint->sending_messages_head,
				    endpoint->sending_messages_tail,
				    fm);
}


/**
 * Free a MAC endpoint.
 * 
 * @param endpoint pointer to the MacEndpoint to free
 */
static void
free_macendpoint (struct MacEndpoint *endpoint)
{
  struct Plugin *plugin = endpoint->plugin;
  struct FragmentMessage *fm;
  struct Session *session;

  GNUNET_STATISTICS_update (plugin->env->stats,
			    _("# WLAN MAC endpoints allocated"), -1, GNUNET_NO);
  while (NULL != (session = endpoint->sessions_head))
    free_session (session);
  while (NULL != (fm = endpoint->sending_messages_head))
    free_fragment_message (fm);
  GNUNET_CONTAINER_DLL_remove (plugin->mac_head, 
			       plugin->mac_tail, 
			       endpoint);

  if (NULL != endpoint->defrag)
  {
    GNUNET_DEFRAGMENT_context_destroy(endpoint->defrag);
    endpoint->defrag = NULL;
  }

  plugin->mac_count--;
  if (GNUNET_SCHEDULER_NO_TASK != endpoint->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (endpoint->timeout_task);
    endpoint->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_free (endpoint);
}


/**
 * A MAC endpoint is timing out.  Clean up.
 *
 * @param cls pointer to the MacEndpoint
 * @param tc pointer to the GNUNET_SCHEDULER_TaskContext
 */
static void
macendpoint_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MacEndpoint *endpoint = cls;
  struct GNUNET_TIME_Relative timeout;

  endpoint->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  timeout = GNUNET_TIME_absolute_get_remaining (endpoint->timeout);
  if (0 == timeout.rel_value) 
  {
    free_macendpoint (endpoint);
    return;
  }
  endpoint->timeout_task =
    GNUNET_SCHEDULER_add_delayed (timeout, &macendpoint_timeout,
				  endpoint);
}


/**
 * Find (or create) a MacEndpoint with a specific MAC address
 *
 * @param plugin pointer to the plugin struct
 * @param addr the MAC address of the endpoint
 * @return handle to our data structure for this MAC
 */
static struct MacEndpoint *
create_macendpoint (struct Plugin *plugin,
		    const struct GNUNET_TRANSPORT_WLAN_MacAddress *addr)
{
  struct MacEndpoint *pos;

  for (pos = plugin->mac_head; NULL != pos; pos = pos->next)
    if (0 == memcmp (addr, &pos->addr, sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress)))
      return pos; 
  pos = GNUNET_malloc (sizeof (struct MacEndpoint));
  pos->addr = *addr;
  pos->plugin = plugin;
  pos->defrag =
    GNUNET_DEFRAGMENT_context_create (plugin->env->stats, WLAN_MTU,
				      MESSAGES_IN_DEFRAG_QUEUE_PER_MAC,
				      pos, 
				      &wlan_data_message_handler,
				      &send_ack);
  pos->timeout = GNUNET_TIME_relative_to_absolute (MACENDPOINT_TIMEOUT);
  pos->timeout_task =
      GNUNET_SCHEDULER_add_delayed (MACENDPOINT_TIMEOUT, &macendpoint_timeout,
                                    pos);
  GNUNET_CONTAINER_DLL_insert (plugin->mac_head, plugin->mac_tail, pos);
  plugin->mac_count++;
  GNUNET_STATISTICS_update (plugin->env->stats, _("# WLAN MAC endpoints allocated"),
			    1, GNUNET_NO);
  LOG (GNUNET_ERROR_TYPE_DEBUG, 
       "New MAC endpoint `%s'\n",
       mac_to_string (addr));
  return pos;
}


/**
 * Creates a new outbound session the transport service will use to send data to the
 * peer
 *
 * @param cls the plugin
 * @param address the address
 * @return the session or NULL of max connections exceeded
 */
static struct Session *
wlan_plugin_get_session (void *cls,
			 const struct GNUNET_HELLO_Address *address)
{
  struct Plugin *plugin = cls;
  struct MacEndpoint *endpoint;

  if (NULL == address)
    return NULL;
  if (sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress) != address->address_length)
  {
    GNUNET_break (0);
    return NULL;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Service asked to create session for peer `%s' with MAC `%s'\n",
       GNUNET_i2s (&address->peer),
       mac_to_string (address->address));
  endpoint = create_macendpoint (plugin, address->address);
  return create_session (endpoint, &address->peer);
}


/**
 * Function that can be used to force the plugin to disconnect
 * from the given peer and cancel all previous transmissions
 * (and their continuation).
 *
 * @param cls closure
 * @param target peer from which to disconnect
 */
static void
wlan_plugin_disconnect (void *cls, const struct GNUNET_PeerIdentity *target)
{
  struct Plugin *plugin = cls;
  struct Session *session;
  struct MacEndpoint *endpoint;

  for (endpoint = plugin->mac_head; NULL != endpoint; endpoint = endpoint->next)
    for (session = endpoint->sessions_head; NULL != session; session = session->next)
      if (0 == memcmp (target, &session->target,
		       sizeof (struct GNUNET_PeerIdentity)))
      {
        free_session (session);
	break; /* inner-loop only (in case peer has another MAC as well!) */
      }
}


/**
 * Function that can be used by the transport service to transmit
 * a message using the plugin.   Note that in the case of a
 * peer disconnecting, the continuation MUST be called
 * prior to the disconnect notification itself.  This function
 * will be called with this peer's HELLO message to initiate
 * a fresh connection to another peer.
 *
 * @param cls closure
 * @param session which session must be used
 * @param msgbuf the message to transmit
 * @param msgbuf_size number of bytes in 'msgbuf'
 * @param priority how important is the message (most plugins will
 *                 ignore message priority and just FIFO)
 * @param to how long to wait at most for the transmission (does not
 *                require plugins to discard the message after the timeout,
 *                just advisory for the desired delay; most plugins will ignore
 *                this as well)
 * @param cont continuation to call once the message has
 *        been transmitted (or if the transport is ready
 *        for the next transmission call; or if the
 *        peer disconnected...); can be NULL
 * @param cont_cls closure for cont
 * @return number of bytes used (on the physical network, with overheads);
 *         -1 on hard errors (i.e. address invalid); 0 is a legal value
 *         and does NOT mean that the message was not transmitted (DV)
 */
static ssize_t
wlan_plugin_send (void *cls,
                  struct Session *session,
                  const char *msgbuf, size_t msgbuf_size,
                  unsigned int priority,
                  struct GNUNET_TIME_Relative to,
                  GNUNET_TRANSPORT_TransmitContinuation cont, void *cont_cls)
{
  struct Plugin *plugin = cls;
  struct WlanHeader *wlanheader;
  size_t size = msgbuf_size + sizeof (struct WlanHeader);
  char buf[size] GNUNET_ALIGN;

  LOG (GNUNET_ERROR_TYPE_DEBUG, 
       "Transmitting %u bytes of payload to peer `%s' (starting with %u byte message of type %u)\n",
       msgbuf_size,
       GNUNET_i2s (&session->target),
       (unsigned int) ntohs (((struct GNUNET_MessageHeader*)msgbuf)->size),
       (unsigned int) ntohs (((struct GNUNET_MessageHeader*)msgbuf)->type));
  wlanheader = (struct WlanHeader *) buf;
  wlanheader->header.size = htons (msgbuf_size + sizeof (struct WlanHeader));
  wlanheader->header.type = htons (GNUNET_MESSAGE_TYPE_WLAN_DATA);
  wlanheader->sender = *plugin->env->my_identity;
  wlanheader->target = session->target;
  wlanheader->crc = htonl (GNUNET_CRYPTO_crc32_n (msgbuf, msgbuf_size));
  memcpy (&wlanheader[1], msgbuf, msgbuf_size);
  send_with_fragmentation (session->mac,
			   to,
			   &session->target,
			   &wlanheader->header,
			   cont, cont_cls);
  return size;
}


/**
 * We have received data from the WLAN via some session.  Process depending
 * on the message type (HELLO, DATA, FRAGMENTATION or FRAGMENTATION-ACK).
 *
 * @param cls pointer to the plugin
 * @param client pointer to the session this message belongs to
 * @param hdr start of the message
 */
static int
process_data (void *cls, void *client, const struct GNUNET_MessageHeader *hdr)
{
  struct Plugin *plugin = cls;
  struct MacAndSession *mas = client;
  struct MacAndSession xmas;
#define NUM_ATS 2
  struct GNUNET_ATS_Information ats[NUM_ATS]; /* FIXME: do better here */
  struct FragmentMessage *fm;
  struct GNUNET_PeerIdentity tmpsource;
  const struct WlanHeader *wlanheader;
  int ret;
  uint16_t msize;

  ats[0].type = htonl (GNUNET_ATS_QUALITY_NET_DISTANCE);
  ats[0].value = htonl (1);
  ats[1].type = htonl (GNUNET_ATS_NETWORK_TYPE);
  ats[1].value = htonl (GNUNET_ATS_NET_WLAN);
  msize = ntohs (hdr->size);
  switch (ntohs (hdr->type))
  {
  case GNUNET_MESSAGE_TYPE_HELLO:
    if (GNUNET_OK != 
	GNUNET_HELLO_get_id ((const struct GNUNET_HELLO_Message *) hdr, &tmpsource))
    {
      GNUNET_break_op (0);
      break;
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG, 
	 "Processing %u bytes of HELLO from peer `%s' at MAC %s\n",
	 (unsigned int) msize,
	 GNUNET_i2s (&tmpsource),
	 mac_to_string (&mas->endpoint->addr));

    GNUNET_STATISTICS_update (plugin->env->stats,
			      _("# HELLO messages received via WLAN"), 1,
			      GNUNET_NO);
    plugin->env->receive (plugin->env->cls, 
			  &tmpsource,
			  hdr, 
			  ats, NUM_ATS,
			  mas->session,
			  (mas->endpoint == NULL) ? NULL : (const char *) &mas->endpoint->addr,
			  (mas->endpoint == NULL) ? 0 : sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress));
    break;
  case GNUNET_MESSAGE_TYPE_FRAGMENT:
    if (NULL == mas->endpoint)
    {
      GNUNET_break (0);
      break;
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG, 
	 "Processing %u bytes of FRAGMENT from MAC %s\n",
	 (unsigned int) msize,
	 mac_to_string (&mas->endpoint->addr));
    GNUNET_STATISTICS_update (plugin->env->stats,
                              _("# fragments received via WLAN"), 1, GNUNET_NO);
    (void) GNUNET_DEFRAGMENT_process_fragment (mas->endpoint->defrag,
					      hdr);
    break;
  case GNUNET_MESSAGE_TYPE_FRAGMENT_ACK:
    if (NULL == mas->endpoint)
    {
      GNUNET_break (0);
      break;
    }
    GNUNET_STATISTICS_update (plugin->env->stats, _("# ACKs received via WLAN"),
			      1, GNUNET_NO);
    for (fm = mas->endpoint->sending_messages_head; NULL != fm; fm = fm->next)
    {
      ret = GNUNET_FRAGMENT_process_ack (fm->fragcontext, hdr);
      if (GNUNET_OK == ret)
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG, 
	     "Got last ACK, finished message transmission to `%s' (%p)\n",
	     mac_to_string (&mas->endpoint->addr),
	     fm);
	mas->endpoint->timeout = GNUNET_TIME_relative_to_absolute (MACENDPOINT_TIMEOUT);
	if (NULL != fm->cont)
	{
	  fm->cont (fm->cont_cls, &fm->target, GNUNET_OK);
	  fm->cont = NULL;
	}
        free_fragment_message (fm);
        break;
      }
      if (GNUNET_NO == ret)
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG, 
	     "Got an ACK, message transmission to `%s' not yet finished\n",
	     mac_to_string (&mas->endpoint->addr));
        break;
      }
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG, 
	 "ACK not matched against any active fragmentation with MAC `%s'\n",
	 mac_to_string (&mas->endpoint->addr));
    break;
  case GNUNET_MESSAGE_TYPE_WLAN_DATA:
    if (NULL == mas->endpoint)
    {
      GNUNET_break (0);
      break;
    }
    if (msize < sizeof (struct WlanHeader))
    {
      GNUNET_break (0);
      break;
    }    
    wlanheader = (const struct WlanHeader *) hdr;
    if (0 != memcmp (&wlanheader->target,
		     plugin->env->my_identity,
		     sizeof (struct GNUNET_PeerIdentity)))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, 
	   "WLAN data for `%s', not for me, ignoring\n",
	   GNUNET_i2s (&wlanheader->target));
      break;
    }
    if (ntohl (wlanheader->crc) !=
	GNUNET_CRYPTO_crc32_n (&wlanheader[1], msize - sizeof (struct WlanHeader)))
    {
      GNUNET_STATISTICS_update (plugin->env->stats,
				_("# WLAN DATA messages discarded due to CRC32 error"), 1,
				GNUNET_NO);
      break;
    }
    xmas.endpoint = mas->endpoint;
    xmas.session = create_session (mas->endpoint, &wlanheader->sender);
    LOG (GNUNET_ERROR_TYPE_DEBUG, 
	 "Processing %u bytes of WLAN DATA from peer `%s'\n",
	 (unsigned int) msize,
	 GNUNET_i2s (&wlanheader->sender));
    (void) GNUNET_SERVER_mst_receive (plugin->wlan_header_payload_tokenizer, 
				      &xmas,
				      (const char *) &wlanheader[1],
				      msize - sizeof (struct WlanHeader),
				      GNUNET_YES, GNUNET_NO); 
    break;
  default:
    if (NULL == mas->endpoint)
    {
      GNUNET_break (0);
      break;
    }
    if (NULL == mas->session)
    {
      GNUNET_break (0);
      break;
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Received packet with %u bytes of type %u from peer %s\n",
	 (unsigned int) msize,
	 (unsigned int) ntohs (hdr->type),
	 GNUNET_i2s (&mas->session->target));
    plugin->env->receive (plugin->env->cls, 
			  &mas->session->target,
			  hdr, 
			  ats, NUM_ATS,
			  mas->session,
			  (mas->endpoint == NULL) ? NULL : (const char *) &mas->endpoint->addr,
			  (mas->endpoint == NULL) ? 0 : sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress));
    break;
  }
  return GNUNET_OK;
}
#undef NUM_ATS


/**
 * Function used for to process the data from the suid process
 *
 * @param cls the plugin handle
 * @param client client that send the data (not used)
 * @param hdr header of the GNUNET_MessageHeader
 */
static int
handle_helper_message (void *cls, void *client,
		       const struct GNUNET_MessageHeader *hdr)
{
  struct Plugin *plugin = cls;
  const struct GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage *rxinfo;
  const struct GNUNET_TRANSPORT_WLAN_HelperControlMessage *cm;
  struct MacAndSession mas;
  uint16_t msize;

  msize = ntohs (hdr->size);
  switch (ntohs (hdr->type))
  {
  case GNUNET_MESSAGE_TYPE_WLAN_HELPER_CONTROL:
    if (msize != sizeof (struct GNUNET_TRANSPORT_WLAN_HelperControlMessage))
    {
      GNUNET_break (0);
      break;
    }
    cm = (const struct GNUNET_TRANSPORT_WLAN_HelperControlMessage *) hdr;
    if (GNUNET_YES == plugin->have_mac)
    {
      if (0 == memcmp (&plugin->mac_address,
		       &cm->mac,
		       sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress)))
	break; /* no change */
      /* remove old address */
      plugin->env->notify_address (plugin->env->cls, GNUNET_NO,
				   &plugin->mac_address,
				   sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress));      
    }
    plugin->mac_address = cm->mac;
    plugin->have_mac = GNUNET_YES;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Received WLAN_HELPER_CONTROL message with MAC address `%s' for peer `%s'\n",
	 mac_to_string (&cm->mac),
	 GNUNET_i2s (plugin->env->my_identity));
    plugin->env->notify_address (plugin->env->cls, GNUNET_YES,
                                 &plugin->mac_address,
                                 sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress));
    break;
  case GNUNET_MESSAGE_TYPE_WLAN_DATA_FROM_HELPER:
    LOG (GNUNET_ERROR_TYPE_DEBUG, 
	 "Got data message from helper with %u bytes\n",
	 msize);
    GNUNET_STATISTICS_update (plugin->env->stats,
                              _("# DATA messages received via WLAN"), 1,
                              GNUNET_NO);
    if (msize < sizeof (struct GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage))
    {
      GNUNET_break (0);
      LOG (GNUNET_ERROR_TYPE_DEBUG,
	   "Size of packet is too small (%u bytes)\n",
	   msize);
      break;
    }
    rxinfo = (const struct GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage *) hdr;

    /* check if message is actually for us */
    if (0 != memcmp (&rxinfo->frame.addr3, &mac_bssid_gnunet,
		     sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress)))
    {
      /* Not the GNUnet BSSID */
      break;
    }
    if ( (0 != memcmp (&rxinfo->frame.addr1, &bc_all_mac,
		       sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress))) &&
	 (0 != memcmp (&rxinfo->frame.addr1, &plugin->mac_address,
		       sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress))) )
    {
      /* Neither broadcast nor specifically for us */
      break;
    }
    if (0 == memcmp (&rxinfo->frame.addr2, &plugin->mac_address,
		     sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress)))
    {
      /* packet is FROM us, thus not FOR us */
      break;
    }
    
    GNUNET_STATISTICS_update (plugin->env->stats,
			      _("# WLAN DATA messages processed"),
			      1, GNUNET_NO);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Receiving %u bytes of data from MAC `%s'\n",
	 (unsigned int) (msize - sizeof (struct GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage)),
	 mac_to_string (&rxinfo->frame.addr2));
    mas.endpoint = create_macendpoint (plugin, &rxinfo->frame.addr2);
    mas.session = NULL;
    (void) GNUNET_SERVER_mst_receive (plugin->helper_payload_tokenizer, 
				      &mas,
				      (const char*) &rxinfo[1],
				      msize - sizeof (struct GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage),
				      GNUNET_YES, GNUNET_NO);
    break;
  default:
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_DEBUG, 
	 "Unexpected message of type %u (%u bytes)",
	 ntohs (hdr->type), ntohs (hdr->size));
    break;
  }
  return GNUNET_OK;
}



/**
 * Task to (periodically) send a HELLO beacon
 *
 * @param cls pointer to the plugin struct
 * @param tc scheduler context
 */
static void
send_hello_beacon (void *cls,
		   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;
  uint16_t size;
  uint16_t hello_size;
  struct GNUNET_TRANSPORT_WLAN_RadiotapSendMessage *radioHeader;
  const struct GNUNET_MessageHeader *hello;

  hello = plugin->env->get_our_hello ();
  hello_size = GNUNET_HELLO_size ((struct GNUNET_HELLO_Message *) hello);
  GNUNET_assert (sizeof (struct WlanHeader) + hello_size <= WLAN_MTU);
  size = sizeof (struct GNUNET_TRANSPORT_WLAN_RadiotapSendMessage) + hello_size;
  {
    char buf[size] GNUNET_ALIGN;

    LOG (GNUNET_ERROR_TYPE_DEBUG, 
	 "Sending %u byte HELLO beacon\n",
	 (unsigned int) size);
    radioHeader = (struct GNUNET_TRANSPORT_WLAN_RadiotapSendMessage*) buf;
    get_radiotap_header (NULL, radioHeader, size);
    get_wlan_header (plugin, &radioHeader->frame, &bc_all_mac, size);
    memcpy (&radioHeader[1], hello, hello_size);
    if (NULL !=
	GNUNET_HELPER_send (plugin->suid_helper,
			    &radioHeader->header,
			    GNUNET_YES /* can drop */,
			    NULL, NULL))
      GNUNET_STATISTICS_update (plugin->env->stats, _("# HELLO beacons sent via WLAN"),
				1, GNUNET_NO);
  }
  plugin->beacon_task =
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
				  (HELLO_BEACON_SCALING_FACTOR,
				   plugin->mac_count + 1),
				  &send_hello_beacon,
				  plugin);

}


/**
 * Another peer has suggested an address for this
 * peer and transport plugin.  Check that this could be a valid
 * address.  If so, consider adding it to the list
 * of addresses.
 *
 * @param cls closure
 * @param addr pointer to the address
 * @param addrlen length of addr
 * @return GNUNET_OK if this is a plausible address for this peer
 *         and transport
 */
static int
wlan_plugin_address_suggested (void *cls, const void *addr, size_t addrlen)
{
  struct Plugin *plugin = cls;

  if (addrlen != sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress))
  {    
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (GNUNET_YES != plugin->have_mac)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, 
	 "Rejecting MAC `%s': I don't know my MAC!\n",
	 mac_to_string (addr));
    return GNUNET_NO; /* don't know my MAC */
  }
  if (0 != memcmp (addr,
		   &plugin->mac_address,
		   addrlen))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, 
	 "Rejecting MAC `%s': not my MAC!\n",
	 mac_to_string (addr));
    return GNUNET_NO; /* not my MAC */
  }
  return GNUNET_OK;
}


/**
 * Function called for a quick conversion of the binary address to
 * a numeric address.  Note that the caller must not free the
 * address and that the next call to this function is allowed
 * to override the address again.
 *
 * @param cls closure
 * @param addr binary address
 * @param addrlen length of the address
 * @return string representing the same address
 */
static const char *
wlan_plugin_address_to_string (void *cls, const void *addr, size_t addrlen)
{
  const struct GNUNET_TRANSPORT_WLAN_MacAddress *mac;

  if (sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress) != addrlen)
  {
    GNUNET_break (0);
    return NULL;
  }
  mac = addr;
  return GNUNET_strdup (mac_to_string (mac));
}


/**
 * Convert the transports address to a nice, human-readable format.
 *
 * @param cls closure
 * @param type name of the transport that generated the address
 * @param addr one of the addresses of the host, NULL for the last address
 *        the specific address format depends on the transport
 * @param addrlen length of the address
 * @param numeric should (IP) addresses be displayed in numeric form?
 * @param timeout after how long should we give up?
 * @param asc function to call on each string
 * @param asc_cls closure for asc
 */
static void
wlan_plugin_address_pretty_printer (void *cls, const char *type,
                                    const void *addr, size_t addrlen,
                                    int numeric,
                                    struct GNUNET_TIME_Relative timeout,
                                    GNUNET_TRANSPORT_AddressStringCallback asc,
                                    void *asc_cls)
{
  const struct GNUNET_TRANSPORT_WLAN_MacAddress *mac;
  char *ret;

  if (sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress) != addrlen)
  {
    /* invalid address  */
    LOG (GNUNET_ERROR_TYPE_WARNING,
	 _("WLAN address with invalid size encountered\n"));
    asc (asc_cls, NULL);
    return;
  }
  mac = addr;
  ret = GNUNET_strdup (mac_to_string (mac));
  asc (asc_cls, ret);
  GNUNET_free (ret);
  asc (asc_cls, NULL);
}


/**
 * Exit point from the plugin. 
 *
 * @param cls pointer to the api struct
 */
void *
libgnunet_plugin_transport_wlan_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;
  struct MacEndpoint *endpoint;
  struct MacEndpoint *endpoint_next;

  if (NULL == plugin)
  {
    GNUNET_free (api);
    return NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != plugin->beacon_task)
  {
    GNUNET_SCHEDULER_cancel (plugin->beacon_task);
    plugin->beacon_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != plugin->suid_helper)
  {
    GNUNET_HELPER_stop (plugin->suid_helper);
    plugin->suid_helper = NULL;
  }
  endpoint_next = plugin->mac_head;
  while (NULL != (endpoint = endpoint_next))
  {
    endpoint_next = endpoint->next;
    free_macendpoint (endpoint);
  }
  if (NULL != plugin->fragment_data_tokenizer)
  {
    GNUNET_SERVER_mst_destroy (plugin->fragment_data_tokenizer);
    plugin->fragment_data_tokenizer = NULL;
  }
  if (NULL != plugin->wlan_header_payload_tokenizer)
  {
    GNUNET_SERVER_mst_destroy (plugin->wlan_header_payload_tokenizer);
    plugin->wlan_header_payload_tokenizer = NULL;
  }
  if (NULL != plugin->helper_payload_tokenizer)
  {
    GNUNET_SERVER_mst_destroy (plugin->helper_payload_tokenizer);
    plugin->helper_payload_tokenizer = NULL;
  }
  GNUNET_free_non_null (plugin->interface);
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}


/**
 * Function called to convert a string address to
 * a binary address.
 *
 * @param cls closure ('struct Plugin*')
 * @param addr string address
 * @param addrlen length of the address
 * @param buf location to store the buffer
 * @param added location to store the number of bytes in the buffer.
 *        If the function returns GNUNET_SYSERR, its contents are undefined.
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
static int
wlan_string_to_address (void *cls, const char *addr, uint16_t addrlen,
			void **buf, size_t *added)
{
  struct GNUNET_TRANSPORT_WLAN_MacAddress *mac;
  unsigned int a[6];
  unsigned int i;

  if ((NULL == addr) || (addrlen == 0))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if ('\0' != addr[addrlen - 1])
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (strlen (addr) != addrlen - 1)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (6 != SSCANF (addr,
		   "%X:%X:%X:%X:%X:%X", 
		   &a[0], &a[1], &a[2], &a[3], &a[4], &a[5]))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  mac = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress));
  for (i=0;i<6;i++)
    mac->mac[i] = a[i];
  *buf = mac;
  *added = sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress);
  return GNUNET_OK;
}


/**
 * Entry point for the plugin.
 *
 * @param cls closure, the 'struct GNUNET_TRANSPORT_PluginEnvironment*'
 * @return the 'struct GNUNET_TRANSPORT_PluginFunctions*' or NULL on error
 */
void *
libgnunet_plugin_transport_wlan_init (void *cls)
{
  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  struct Plugin *plugin;
  char *interface;
  unsigned long long testmode;

  /* check for 'special' mode */
  if (NULL == env->receive)
  {
    /* run in 'stub' mode (i.e. as part of gnunet-peerinfo), don't fully
       initialze the plugin or the API */
    api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
    api->cls = NULL;
    api->address_pretty_printer = &wlan_plugin_address_pretty_printer;
    api->address_to_string = &wlan_plugin_address_to_string;
    api->string_to_address = &wlan_string_to_address;
    return api;
  }

  testmode = 0;
  /* check configuration */
  if ( (GNUNET_YES == 
	GNUNET_CONFIGURATION_have_value (env->cfg, "transport-wlan", "TESTMODE")) &&
       ( (GNUNET_SYSERR ==
	  GNUNET_CONFIGURATION_get_value_number (env->cfg, "transport-wlan",
						 "TESTMODE", &testmode)) ||
	 (testmode > 2) ) )
    {
    LOG (GNUNET_ERROR_TYPE_ERROR,
	 _("Invalid configuration option `%s' in section `%s'\n"),
	 "TESTMODE",
	 "transport-wlan");
    return NULL;
  }
  if ( (0 == testmode) &&
       (GNUNET_YES != GNUNET_OS_check_helper_binary ("gnunet-helper-transport-wlan")) )
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
	 _("Helper binary `%s' not SUID, cannot run WLAN transport\n"),
	 "gnunet-helper-transport-wlan");
    return NULL;
  }
  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_get_value_string
      (env->cfg, "transport-wlan", "INTERFACE",
       &interface))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
	 _("Missing configuration option `%s' in section `%s'\n"),
	 "INTERFACE",
	 "transport-wlan");
    return NULL;    
  }

  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->interface = interface;
  plugin->env = env;
  GNUNET_STATISTICS_set (plugin->env->stats, _("# WLAN sessions allocated"),
                         0, GNUNET_NO);
  GNUNET_STATISTICS_set (plugin->env->stats, _("# WLAN MAC endpoints allocated"),
                         0, 0);
  GNUNET_BANDWIDTH_tracker_init (&plugin->tracker,
                                 GNUNET_BANDWIDTH_value_init (100 * 1024 *
                                                              1024 / 8), 100);
  plugin->fragment_data_tokenizer = GNUNET_SERVER_mst_create (&process_data, plugin);
  plugin->wlan_header_payload_tokenizer = GNUNET_SERVER_mst_create (&process_data, plugin);
  plugin->helper_payload_tokenizer = GNUNET_SERVER_mst_create (&process_data, plugin);
  plugin->beacon_task = GNUNET_SCHEDULER_add_now (&send_hello_beacon, 
						  plugin);
  switch (testmode)
  {
  case 0: /* normal */ 
    plugin->helper_argv[0] = (char *) "gnunet-helper-transport-wlan";
    plugin->helper_argv[1] = interface;
    plugin->helper_argv[2] = NULL;
    plugin->suid_helper = GNUNET_HELPER_start ("gnunet-helper-transport-wlan",
					       plugin->helper_argv,
					       &handle_helper_message,
					       plugin);
    break;
  case 1: /* testmode, peer 1 */
    plugin->helper_argv[0] = (char *) "gnunet-helper-transport-wlan-dummy";
    plugin->helper_argv[1] = (char *) "1";
    plugin->helper_argv[2] = NULL;
    plugin->suid_helper = GNUNET_HELPER_start ("gnunet-helper-transport-wlan-dummy",
					       plugin->helper_argv,
					       &handle_helper_message,
					       plugin);
    break;
  case 2: /* testmode, peer 2 */
    plugin->helper_argv[0] = (char *) "gnunet-helper-transport-wlan-dummy";
    plugin->helper_argv[1] = (char *) "2";
    plugin->helper_argv[2] = NULL;
    plugin->suid_helper = GNUNET_HELPER_start ("gnunet-helper-transport-wlan-dummy",
					       plugin->helper_argv,
					       &handle_helper_message,
					       plugin);
    break;
  default:
    GNUNET_assert (0);
  }

  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
  api->cls = plugin;
  api->send = &wlan_plugin_send;
  api->get_session = &wlan_plugin_get_session;
  api->disconnect = &wlan_plugin_disconnect;
  api->address_pretty_printer = &wlan_plugin_address_pretty_printer;
  api->check_address = &wlan_plugin_address_suggested;
  api->address_to_string = &wlan_plugin_address_to_string;
  api->string_to_address = &wlan_string_to_address;
  return api;
}


/* end of plugin_transport_wlan.c */
