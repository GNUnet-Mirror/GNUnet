/*
  This file is part of GNUnet
  Copyright (C) 2010-2014 GNUnet e.V.

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
  Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
  Boston, MA 02110-1301, USA.
*/

/**
 * @file transport/plugin_transport_wlan.c
 * @brief transport plugin for wlan and/or bluetooth
 * @author David Brodski
 * @author Christian Grothoff
 *
 * BUILD_WLAN or BUILD_BLUETOOTH must be defined such that the respective
 * variant of this code is compiled.
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_transport_plugin.h"
#include "plugin_transport_wlan.h"
#include "gnunet_fragmentation_lib.h"
#include "gnunet_constants.h"

#if BUILD_WLAN
/* begin case wlan */
#define PLUGIN_NAME "wlan"
#define CONFIG_NAME "transport-wlan"
#define HELPER_NAME "gnunet-helper-transport-wlan"
#define DUMMY_HELPER_NAME "gnunet-helper-transport-wlan-dummy"
#define LIBGNUNET_PLUGIN_TRANSPORT_INIT libgnunet_plugin_transport_wlan_init
#define LIBGNUNET_PLUGIN_TRANSPORT_DONE libgnunet_plugin_transport_wlan_done
#define LOG(kind,...) GNUNET_log_from (kind, "transport-wlan",__VA_ARGS__)

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


/* end case wlan */
#elif BUILD_BLUETOOTH
/* begin case bluetooth */

#define PLUGIN_NAME "bluetooth"
#define CONFIG_NAME "transport-bluetooth"
#define HELPER_NAME "gnunet-helper-transport-bluetooth"
/* yes, this is correct, we use the same dummy driver as 'wlan' */
#define DUMMY_HELPER_NAME "gnunet-helper-transport-wlan-dummy"
#define LIBGNUNET_PLUGIN_TRANSPORT_INIT libgnunet_plugin_transport_bluetooth_init
#define LIBGNUNET_PLUGIN_TRANSPORT_DONE libgnunet_plugin_transport_bluetooth_done
#define LOG(kind,...) GNUNET_log_from (kind, "transport-bluetooth",__VA_ARGS__)

/**
 * time out of a mac endpoint
 */
#define MACENDPOINT_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT, 60)


/**
 * We reduce the frequence of HELLO beacons in relation to
 * the number of MAC addresses currently visible to us.
 * This is the multiplication factor.
 */
#define HELLO_BEACON_SCALING_FACTOR GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)

/* end case bluetooth */
#else
#error need to build wlan or bluetooth
#endif

/**
 * Max size of packet (that we give to the WLAN driver for transmission)
 */
#define WLAN_MTU 1430


/**
 * Which network scope do we belong to?
 */
#if BUILD_WLAN
static const enum GNUNET_ATS_Network_Type scope = GNUNET_ATS_NET_WLAN;
#else
static const enum GNUNET_ATS_Network_Type scope = GNUNET_ATS_NET_BT;
#endif


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
   * Message type is #GNUNET_MESSAGE_TYPE_WLAN_DATA.
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


/**
 * Address format for WLAN.
 */
struct WlanAddress
{
  /**
   * Options set for the WLAN, in NBO.
   */
  uint32_t options GNUNET_PACKED;

  /**
   * WLAN addresses using MACs.
   */
  struct GNUNET_TRANSPORT_WLAN_MacAddress mac;
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
   * Cls for @e transmit_cont
   */
  void *transmit_cont_cls;

  /**
   * Timeout task (for this message).
   */
  struct GNUNET_SCHEDULER_Task * timeout_task;

};


/**
 * Session handle for connections with other peers.
 */
struct GNUNET_ATS_Session
{
  /**
   * To whom are we talking to (set to our identity
   * if we are still waiting for the welcome message)
   */
  struct GNUNET_PeerIdentity target;

  /**
   * We keep all sessions in a DLL at their respective
   * `struct MACEndpoint *`.
   */
  struct GNUNET_ATS_Session *next;

  /**
   * We keep all sessions in a DLL at their respective
   * `struct MACEndpoint *`.
   */
  struct GNUNET_ATS_Session *prev;

  /**
   * MAC endpoint with the address of this peer.
   */
  struct MacEndpoint *mac;

  /**
   * Address associated with this session and MAC endpoint
   */
  struct GNUNET_HELLO_Address *address;

  /**
   * When should this session time out?
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Timeout task (for the session).
   */
  struct GNUNET_SCHEDULER_Task * timeout_task;

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
  struct GNUNET_SCHEDULER_Task * timeout_task;

  /**
   * Continuation to call when we're done with this message.
   */
  GNUNET_TRANSPORT_TransmitContinuation cont;

  /**
   * Message we need to fragment and transmit, NULL after the
   * @e fragmentcontext has been created.
   */
  struct GNUNET_MessageHeader *msg;

  /**
   * Closure for @e cont
   */
  void *cont_cls;

  /**
   * Size of original message
   */
  size_t size_payload;

  /**
   * Number of bytes used to transmit message
   */
  size_t size_on_wire;

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
  struct GNUNET_ATS_Session *sessions_head;

  /**
   * Tail of sessions that use this MAC.
   */
  struct GNUNET_ATS_Session *sessions_tail;

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
  struct GNUNET_SCHEDULER_Task * timeout_task;

  /**
   * count of messages in the fragment out queue for this mac endpoint
   */
  unsigned int fragment_messages_out_count;

  /**
   * peer MAC address
   */
  struct WlanAddress wlan_addr;

  /**
   * Message delay for fragmentation context
   */
  struct GNUNET_TIME_Relative msg_delay;

  /**
   * ACK delay for fragmentation context
   */
  struct GNUNET_TIME_Relative ack_delay;

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
   * Function to call about session status changes.
   */
  GNUNET_TRANSPORT_SessionInfoCallback sic;

  /**
   * Closure for @e sic.
   */
  void *sic_cls;

  /**
   * ARGV-vector for the helper (all helpers take only the binary
   * name, one actual argument, plus the NULL terminator for 'argv').
   */
  char *helper_argv[3];

  /**
   * The interface of the wlan card given to us by the user.
   */
  char *wlan_interface;

  /**
   * Tokenizer for demultiplexing of data packets resulting from
   * defragmentation.
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
   * Task that periodically sends a HELLO beacon via the helper.
   */
  struct GNUNET_SCHEDULER_Task *beacon_task;

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

  /**
   * Number of connections
   */
  unsigned int mac_count;

  /**
   * Options for addresses
   */
  uint32_t options;

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
  struct GNUNET_ATS_Session *session;

  /**
   * MAC address of the other peer, NULL if not known.
   */
  struct MacEndpoint *endpoint;
};


/**
 * Print MAC addresses nicely.
 *
 * @param mac the mac address
 * @return string to a static buffer with
 * the human-readable mac, will be overwritten during the next call to
 * this function
 */
static const char *
mac_to_string (const struct GNUNET_TRANSPORT_WLAN_MacAddress * mac)
{
  static char macstr[20];

  GNUNET_snprintf (macstr,
                   sizeof (macstr),
                   "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
                   mac->mac[0], mac->mac[1],
                   mac->mac[2], mac->mac[3],
                   mac->mac[4], mac->mac[5]);
  return macstr;
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
wlan_plugin_address_to_string (void *cls,
                               const void *addr,
                               size_t addrlen)
{
  const struct GNUNET_TRANSPORT_WLAN_MacAddress *mac;
  static char macstr[36];

  if (sizeof (struct WlanAddress) != addrlen)
  {
    GNUNET_break (0);
    return NULL;
  }
  mac = &((struct WlanAddress *) addr)->mac;
  GNUNET_snprintf (macstr,
                   sizeof (macstr),
                   "%s.%u.%s",
                   PLUGIN_NAME,
                   ntohl (((struct WlanAddress *) addr)->options),
                   mac_to_string (mac));
  return macstr;
}


/**
 * If a session monitor is attached, notify it about the new
 * session state.
 *
 * @param plugin our plugin
 * @param session session that changed state
 * @param state new state of the session
 */
static void
notify_session_monitor (struct Plugin *plugin,
                        struct GNUNET_ATS_Session *session,
                        enum GNUNET_TRANSPORT_SessionState state)
{
  struct GNUNET_TRANSPORT_SessionInfo info;

  if (NULL == plugin->sic)
    return;
  memset (&info, 0, sizeof (info));
  info.state = state;
  info.is_inbound = GNUNET_SYSERR; /* hard to say */
  info.num_msg_pending = 0; /* we queue per MAC, not per peer */
  info.num_bytes_pending = 0; /* we queue per MAC, not per peer */
  info.receive_delay = GNUNET_TIME_UNIT_ZERO_ABS; /* not supported by WLAN */
  info.session_timeout = session->timeout;
  info.address = session->address;
  plugin->sic (plugin->sic_cls,
               session,
               &info);
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
 * @param cls the `struct MacEndpoint *` the ACK must be sent to
 * @param msg_id id of the message
 * @param hdr pointer to the hdr where the ack is stored
 */
static void
send_ack (void *cls,
          uint32_t msg_id,
	  const struct GNUNET_MessageHeader *hdr)
{
  struct MacEndpoint *endpoint = cls;
  struct GNUNET_TRANSPORT_WLAN_RadiotapSendMessage* radio_header;
  uint16_t msize = ntohs (hdr->size);
  size_t size = sizeof (struct GNUNET_TRANSPORT_WLAN_RadiotapSendMessage) + msize;
  char buf[size];

  if (NULL == endpoint)
  {
    GNUNET_break (0);
    return;
  }
  if (size >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending ACK to %s\n",
       mac_to_string (&endpoint->wlan_addr.mac));
  radio_header = (struct GNUNET_TRANSPORT_WLAN_RadiotapSendMessage *) buf;
  get_radiotap_header (endpoint, radio_header, size);
  get_wlan_header (endpoint->plugin,
		   &radio_header->frame,
		   &endpoint->wlan_addr.mac,
		   sizeof (endpoint->wlan_addr.mac));
  memcpy (&radio_header[1], hdr, msize);
  if (NULL !=
      GNUNET_HELPER_send (endpoint->plugin->suid_helper,
			  &radio_header->header,
			  GNUNET_NO /* dropping ACKs is bad */,
			  NULL, NULL))
    GNUNET_STATISTICS_update (endpoint->plugin->env->stats,
                              _("# ACKs sent"),
			      1, GNUNET_NO);
}


/**
 * Handles the data after all fragments are put together
 *
 * @param cls macendpoint this messages belongs to
 * @param hdr pointer to the data
 */
static void
wlan_data_message_handler (void *cls,
                           const struct GNUNET_MessageHeader *hdr)
{
  struct MacEndpoint *endpoint = cls;
  struct Plugin *plugin = endpoint->plugin;
  struct MacAndSession mas;

  GNUNET_STATISTICS_update (plugin->env->stats,
			    _("# Messages defragmented"),
                            1,
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
 * @param cls our `struct Plugin`.
 * @param session the session free
 */
static int
wlan_plugin_disconnect_session (void *cls,
                                struct GNUNET_ATS_Session *session)
{
  struct MacEndpoint *endpoint = session->mac;
  struct Plugin *plugin = endpoint->plugin;

  plugin->env->session_end (plugin->env->cls,
                            session->address,
                            session);
  notify_session_monitor (plugin,
                          session,
                          GNUNET_TRANSPORT_SS_DONE);
  GNUNET_CONTAINER_DLL_remove (endpoint->sessions_head,
			       endpoint->sessions_tail,
                               session);
  if (session->timeout_task != NULL)
  {
    GNUNET_SCHEDULER_cancel (session->timeout_task);
    session->timeout_task = NULL;
  }
  GNUNET_STATISTICS_update (plugin->env->stats,
                            _("# Sessions allocated"),
                            -1,
                            GNUNET_NO);
  GNUNET_HELLO_address_free (session->address);
  GNUNET_free (session);
  return GNUNET_OK;
}


/**
 * Function that is called to get the keepalive factor.
 * #GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT is divided by this number to
 * calculate the interval between keepalive packets.
 *
 * @param cls closure with the `struct Plugin`
 * @return keepalive factor
 */
static unsigned int
wlan_plugin_query_keepalive_factor (void *cls)
{
  return 3;
}


/**
 * A session is timing out.  Clean up.
 *
 * @param cls pointer to the Session
 * @param tc unused
 */
static void
session_timeout (void *cls,
                 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_ATS_Session *session = cls;
  struct GNUNET_TIME_Relative left;

  session->timeout_task = NULL;
  left = GNUNET_TIME_absolute_get_remaining (session->timeout);
  if (0 != left.rel_value_us)
  {
    session->timeout_task =
      GNUNET_SCHEDULER_add_delayed (left,
                                    &session_timeout,
                                    session);
    return;
  }
  wlan_plugin_disconnect_session (session->mac->plugin,
                                  session);
}



/**
 * Lookup a new session
 *
 * @param endpoint pointer to the mac endpoint of the peer
 * @param peer peer identity to use for this session
 * @return returns the session or NULL
 */
static struct GNUNET_ATS_Session *
lookup_session (struct MacEndpoint *endpoint,
                const struct GNUNET_PeerIdentity *peer)
{
  struct GNUNET_ATS_Session *session;

  for (session = endpoint->sessions_head; NULL != session; session = session->next)
    if (0 == memcmp (peer, &session->target, sizeof (struct GNUNET_PeerIdentity)))
      return session;
  return NULL;
}


/**
 * Create a new session
 *
 * @param endpoint pointer to the mac endpoint of the peer
 * @param peer peer identity to use for this session
 * @return returns the session or NULL
 */
static struct GNUNET_ATS_Session *
create_session (struct MacEndpoint *endpoint,
                const struct GNUNET_PeerIdentity *peer)
{
  struct GNUNET_ATS_Session *session;

  GNUNET_STATISTICS_update (endpoint->plugin->env->stats,
                            _("# Sessions allocated"),
                            1,
                            GNUNET_NO);
  session = GNUNET_new (struct GNUNET_ATS_Session);
  GNUNET_CONTAINER_DLL_insert_tail (endpoint->sessions_head,
                                    endpoint->sessions_tail,
				    session);
  session->address = GNUNET_HELLO_address_allocate (peer,
                                                    PLUGIN_NAME,
                                                    &endpoint->wlan_addr,
                                                    sizeof (endpoint->wlan_addr),
                                                    GNUNET_HELLO_ADDRESS_INFO_NONE);
  session->mac = endpoint;
  session->target = *peer;
  session->timeout = GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
  session->timeout_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT, &session_timeout,
                                    session);
  notify_session_monitor (endpoint->plugin,
                          session,
                          GNUNET_TRANSPORT_SS_INIT);
  notify_session_monitor (endpoint->plugin,
                          session,
                          GNUNET_TRANSPORT_SS_UP);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Created new session %p for peer `%s' with endpoint %s\n",
       session,
       GNUNET_i2s (peer),
       mac_to_string (&endpoint->wlan_addr.mac));

  return session;
}


/**
 * Look up a session for a peer and create a new session if none is found
 *
 * @param endpoint pointer to the mac endpoint of the peer
 * @param peer peer identity to use for this session
 * @return returns the session
 */
static struct GNUNET_ATS_Session *
get_session (struct MacEndpoint *endpoint,
             const struct GNUNET_PeerIdentity *peer)
{
  struct GNUNET_ATS_Session *session;

  if (NULL != (session = lookup_session (endpoint, peer)))
    return session;
  return create_session (endpoint, peer);
}


/**
 * Function called once we have successfully given the fragment
 * message to the SUID helper process and we are thus ready for
 * the next fragment.
 *
 * @param cls the `struct FragmentMessage *`
 * @param result result of the operation (#GNUNET_OK on success,
 *        #GNUNET_NO if the helper died, #GNUNET_SYSERR
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
 * @param cls `struct FragmentMessage *` this fragment message belongs to
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

  if (NULL == endpoint)
  {
    GNUNET_break (0);
    return;
  }
  msize = ntohs (hdr->size);
  size = sizeof (struct GNUNET_TRANSPORT_WLAN_RadiotapSendMessage) + msize;
  {
    char buf[size];
    struct GNUNET_TRANSPORT_WLAN_RadiotapSendMessage *radio_header;

    radio_header = (struct GNUNET_TRANSPORT_WLAN_RadiotapSendMessage *) buf;
    get_radiotap_header (endpoint, radio_header, size);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Sending %u bytes of data to MAC `%s'\n",
	 (unsigned int) msize,
	 mac_to_string (&endpoint->wlan_addr.mac));

    get_wlan_header (endpoint->plugin,
		     &radio_header->frame,
		     &endpoint->wlan_addr.mac,
		     sizeof (endpoint->wlan_addr.mac));
    memcpy (&radio_header[1], hdr, msize);
    GNUNET_assert (NULL == fm->sh);
    fm->sh = GNUNET_HELPER_send (endpoint->plugin->suid_helper,
				 &radio_header->header,
				 GNUNET_NO,
				 &fragment_transmission_done, fm);
    fm->size_on_wire += size;
    if (NULL != fm->sh)
    {
      GNUNET_STATISTICS_update (endpoint->plugin->env->stats,
                                _("# message fragments sent"),
				1,
                                GNUNET_NO);
    }
    else
    {
      GNUNET_FRAGMENT_context_transmission_done (fm->fragcontext);
    }
    GNUNET_STATISTICS_update (endpoint->plugin->env->stats,
                              "# bytes currently in buffers",
                              -msize, GNUNET_NO);
    GNUNET_STATISTICS_update (endpoint->plugin->env->stats,
                              "# bytes transmitted",
                              msize, GNUNET_NO);
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

  GNUNET_STATISTICS_update (endpoint->plugin->env->stats,
                            _("# messages pending (with fragmentation)"),
			    -1, GNUNET_NO);
  GNUNET_CONTAINER_DLL_remove (endpoint->sending_messages_head,
                               endpoint->sending_messages_tail,
                               fm);
  if (NULL != fm->sh)
  {
    GNUNET_HELPER_send_cancel (fm->sh);
    fm->sh = NULL;
  }
  if (NULL != fm->msg)
  {
    GNUNET_free (fm->msg);
    fm->msg = NULL;
  }
  if (NULL != fm->fragcontext)
  {
    GNUNET_FRAGMENT_context_destroy (fm->fragcontext,
                                     &endpoint->msg_delay,
                                     &endpoint->ack_delay);
    fm->fragcontext = NULL;
  }
  if (NULL != fm->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (fm->timeout_task);
    fm->timeout_task = NULL;
  }
  GNUNET_free (fm);
}


/**
 * A FragmentMessage has timed out.  Remove it.
 *
 * @param cls pointer to the 'struct FragmentMessage'
 * @param tc unused
 */
static void
fragmentmessage_timeout (void *cls,
                         const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct FragmentMessage *fm = cls;

  fm->timeout_task = NULL;
  if (NULL != fm->cont)
  {
    fm->cont (fm->cont_cls,
              &fm->target,
              GNUNET_SYSERR,
              fm->size_payload,
              fm->size_on_wire);
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
 * @param payload_size bytes of payload
 * @param cont continuation to call once the message has
 *        been transmitted (or if the transport is ready
 *        for the next transmission call; or if the
 *        peer disconnected...); can be NULL
 * @param cont_cls closure for @a cont
 */
static void
send_with_fragmentation (struct MacEndpoint *endpoint,
			 struct GNUNET_TIME_Relative timeout,
			 const struct GNUNET_PeerIdentity *target,
			 const struct GNUNET_MessageHeader *msg,
			 size_t payload_size,
			 GNUNET_TRANSPORT_TransmitContinuation cont,
                         void *cont_cls)

{
  struct FragmentMessage *fm;
  struct Plugin *plugin;

  plugin = endpoint->plugin;
  fm = GNUNET_new (struct FragmentMessage);
  fm->macendpoint = endpoint;
  fm->target = *target;
  fm->size_payload = payload_size;
  fm->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  fm->cont = cont;
  fm->cont_cls = cont_cls;
  /* 1 MBit/s typical data rate, 1430 byte fragments => ~100 ms per message */
  fm->timeout_task =
    GNUNET_SCHEDULER_add_delayed (timeout,
                                  &fragmentmessage_timeout,
                                  fm);
  if (GNUNET_YES == plugin->have_mac)
  {
    fm->fragcontext =
      GNUNET_FRAGMENT_context_create (plugin->env->stats,
                                      WLAN_MTU,
                                      &plugin->tracker,
                                      fm->macendpoint->msg_delay,
                                      fm->macendpoint->ack_delay,
                                      msg,
                                      &transmit_fragment, fm);
  }
  else
  {
    fm->msg = GNUNET_copy_message (msg);
  }
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
  struct GNUNET_ATS_Session *session;

  GNUNET_STATISTICS_update (plugin->env->stats,
			    _("# MAC endpoints allocated"),
                            -1,
                            GNUNET_NO);
  while (NULL != (session = endpoint->sessions_head))
    wlan_plugin_disconnect_session (plugin,
                                    session);
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
  if (NULL != endpoint->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (endpoint->timeout_task);
    endpoint->timeout_task = NULL;
  }
  GNUNET_free (endpoint);
}


/**
 * A MAC endpoint is timing out.  Clean up.
 *
 * @param cls pointer to the `struct MacEndpoint *`
 * @param tc pointer to the GNUNET_SCHEDULER_TaskContext
 */
static void
macendpoint_timeout (void *cls,
                     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MacEndpoint *endpoint = cls;
  struct GNUNET_TIME_Relative timeout;

  endpoint->timeout_task = NULL;
  timeout = GNUNET_TIME_absolute_get_remaining (endpoint->timeout);
  if (0 == timeout.rel_value_us)
  {
    free_macendpoint (endpoint);
    return;
  }
  endpoint->timeout_task =
    GNUNET_SCHEDULER_add_delayed (timeout,
                                  &macendpoint_timeout,
				  endpoint);
}


/**
 * Find (or create) a MacEndpoint with a specific MAC address
 *
 * @param plugin pointer to the plugin struct
 * @param mac the MAC address of the endpoint
 * @return handle to our data structure for this MAC
 */
static struct MacEndpoint *
create_macendpoint (struct Plugin *plugin,
                    struct WlanAddress *mac)
{
  struct MacEndpoint *pos;

  for (pos = plugin->mac_head; NULL != pos; pos = pos->next)
    if (0 == memcmp (mac, &pos->wlan_addr, sizeof (pos->wlan_addr)))
      return pos;
  pos = GNUNET_new (struct MacEndpoint);
  pos->wlan_addr = (*mac);
  pos->plugin = plugin;
  pos->defrag =
    GNUNET_DEFRAGMENT_context_create (plugin->env->stats,
                                      WLAN_MTU,
				      MESSAGES_IN_DEFRAG_QUEUE_PER_MAC,
				      pos,
				      &wlan_data_message_handler,
				      &send_ack);

  pos->msg_delay = GNUNET_TIME_UNIT_MILLISECONDS;
  pos->ack_delay = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 100);
  pos->timeout = GNUNET_TIME_relative_to_absolute (MACENDPOINT_TIMEOUT);
  pos->timeout_task =
      GNUNET_SCHEDULER_add_delayed (MACENDPOINT_TIMEOUT, &macendpoint_timeout,
                                    pos);
  GNUNET_CONTAINER_DLL_insert (plugin->mac_head,
                               plugin->mac_tail,
                               pos);
  plugin->mac_count++;
  GNUNET_STATISTICS_update (plugin->env->stats,
                            _("# MAC endpoints allocated"),
			    1, GNUNET_NO);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "New MAC endpoint `%s'\n",
       wlan_plugin_address_to_string (NULL,
                                      &pos->wlan_addr,
                                      sizeof (struct WlanAddress)));
  return pos;
}


/**
 * Function obtain the network type for a session
 *
 * @param cls closure (`struct Plugin*`)
 * @param session the session
 * @return the network type in HBO or #GNUNET_SYSERR
 */
static enum GNUNET_ATS_Network_Type
wlan_plugin_get_network (void *cls,
                         struct GNUNET_ATS_Session *session)
{
#if BUILD_WLAN
  return GNUNET_ATS_NET_WLAN;
#else
  return GNUNET_ATS_NET_BT;
#endif
}


/**
 * Function obtain the network type for an address.
 *
 * @param cls closure (`struct Plugin *`)
 * @param address the address
 * @return the network type
 */
static enum GNUNET_ATS_Network_Type
wlan_plugin_get_network_for_address (void *cls,
                                    const struct GNUNET_HELLO_Address *address)
{
#if BUILD_WLAN
  return GNUNET_ATS_NET_WLAN;
#else
  return GNUNET_ATS_NET_BT;
#endif
}


/**
 * Creates a new outbound session the transport service will use to
 * send data to the peer
 *
 * @param cls the `struct Plugin *`
 * @param address the address
 * @return the session or NULL of max connections exceeded
 */
static struct GNUNET_ATS_Session *
wlan_plugin_get_session (void *cls,
			 const struct GNUNET_HELLO_Address *address)
{
  struct Plugin *plugin = cls;
  struct MacEndpoint *endpoint;

  if (NULL == address)
    return NULL;
  if (sizeof (struct WlanAddress) != address->address_length)
  {
    GNUNET_break (0);
    return NULL;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Service asked to create session for peer `%s' with MAC `%s'\n",
       GNUNET_i2s (&address->peer),
       wlan_plugin_address_to_string (NULL,
                                      address->address,
                                      address->address_length));
  endpoint = create_macendpoint (plugin,
                                 (struct WlanAddress *) address->address);
  return get_session (endpoint, &address->peer);
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
wlan_plugin_disconnect_peer (void *cls,
                             const struct GNUNET_PeerIdentity *target)
{
  struct Plugin *plugin = cls;
  struct GNUNET_ATS_Session *session;
  struct MacEndpoint *endpoint;

  for (endpoint = plugin->mac_head; NULL != endpoint; endpoint = endpoint->next)
    for (session = endpoint->sessions_head; NULL != session; session = session->next)
      if (0 == memcmp (target, &session->target,
		       sizeof (struct GNUNET_PeerIdentity)))
      {
        wlan_plugin_disconnect_session (plugin, session);
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
 * @param msgbuf_size number of bytes in @a msgbuf
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
 * @param cont_cls closure for @a cont
 * @return number of bytes used (on the physical network, with overheads);
 *         -1 on hard errors (i.e. address invalid); 0 is a legal value
 *         and does NOT mean that the message was not transmitted (DV)
 */
static ssize_t
wlan_plugin_send (void *cls,
                  struct GNUNET_ATS_Session *session,
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
  memcpy (&wlanheader[1],
          msgbuf,
          msgbuf_size);
  GNUNET_STATISTICS_update (plugin->env->stats,
                            "# bytes currently in buffers",
                            msgbuf_size,
                            GNUNET_NO);
  send_with_fragmentation (session->mac,
			   to,
			   &session->target,
			   &wlanheader->header,
			   msgbuf_size,
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
process_data (void *cls,
              void *client,
              const struct GNUNET_MessageHeader *hdr)
{
  struct Plugin *plugin = cls;
  struct GNUNET_HELLO_Address *address;
  struct MacAndSession *mas = client;
  struct FragmentMessage *fm;
  struct GNUNET_PeerIdentity tmpsource;
  const struct WlanHeader *wlanheader;
  int ret;
  uint16_t msize;

  msize = ntohs (hdr->size);

  GNUNET_STATISTICS_update (plugin->env->stats,
                            "# bytes received",
                            msize, GNUNET_NO);

  switch (ntohs (hdr->type))
  {
  case GNUNET_MESSAGE_TYPE_HELLO:

    if (GNUNET_OK !=
	GNUNET_HELLO_get_id ((const struct GNUNET_HELLO_Message *) hdr,
                             &tmpsource))
    {
      GNUNET_break_op (0);
      break;
    }
    if (NULL == mas->endpoint)
    {
      GNUNET_break (0);
      break;
    }

    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Processing %u bytes of HELLO from peer `%s' at MAC %s\n",
	 (unsigned int) msize,
	 GNUNET_i2s (&tmpsource),
	 wlan_plugin_address_to_string (NULL,
                                        &mas->endpoint->wlan_addr,
                                        sizeof (mas->endpoint->wlan_addr)));

    GNUNET_STATISTICS_update (plugin->env->stats,
			      _("# HELLO messages received"), 1,
			      GNUNET_NO);
    address = GNUNET_HELLO_address_allocate (&tmpsource,
                                             PLUGIN_NAME,
                                             &mas->endpoint->wlan_addr,
                                             sizeof (mas->endpoint->wlan_addr),
                                             GNUNET_HELLO_ADDRESS_INFO_NONE);
    mas->session = lookup_session (mas->endpoint,
                                   &tmpsource);
    if (NULL == mas->session)
    {
      mas->session = create_session (mas->endpoint,
                                     &tmpsource);
      plugin->env->session_start (plugin->env->cls,
                                  address,
                                  mas->session,
                                  scope);
    }
    plugin->env->receive (plugin->env->cls,
                          address,
                          mas->session,
                          hdr);
    GNUNET_HELLO_address_free (address);
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
	 wlan_plugin_address_to_string (NULL,
                                        &mas->endpoint->wlan_addr,
                                        sizeof (mas->endpoint->wlan_addr)));
    GNUNET_STATISTICS_update (plugin->env->stats,
                              _("# fragments received"),
                              1,
                              GNUNET_NO);
    (void) GNUNET_DEFRAGMENT_process_fragment (mas->endpoint->defrag,
					      hdr);
    break;
  case GNUNET_MESSAGE_TYPE_FRAGMENT_ACK:
    if (NULL == mas->endpoint)
    {
      GNUNET_break (0);
      break;
    }
    GNUNET_STATISTICS_update (plugin->env->stats,
                              _("# ACKs received"),
			      1, GNUNET_NO);
    for (fm = mas->endpoint->sending_messages_head; NULL != fm; fm = fm->next)
    {
      ret = GNUNET_FRAGMENT_process_ack (fm->fragcontext, hdr);
      if (GNUNET_OK == ret)
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG,
	     "Got last ACK, finished message transmission to `%s' (%p)\n",
             wlan_plugin_address_to_string (NULL,
                                            &mas->endpoint->wlan_addr,
                                            sizeof (mas->endpoint->wlan_addr)),
	     fm);
	mas->endpoint->timeout = GNUNET_TIME_relative_to_absolute (MACENDPOINT_TIMEOUT);
	if (NULL != fm->cont)
	{
	  fm->cont (fm->cont_cls,
                    &fm->target,
                    GNUNET_OK,
                    fm->size_payload,
                    fm->size_on_wire);
	  fm->cont = NULL;
	}
        free_fragment_message (fm);
        break;
      }
      if (GNUNET_NO == ret)
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG,
	     "Got an ACK, message transmission to `%s' not yet finished\n",
             wlan_plugin_address_to_string (NULL,
                                            &mas->endpoint->wlan_addr,
                                            sizeof (mas->endpoint->wlan_addr)));
        break;
      }
    }
    if (NULL == fm)
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "ACK not matched against any active fragmentation with MAC `%s'\n",
           wlan_plugin_address_to_string (NULL,
                                          &mas->endpoint->wlan_addr,
                                          sizeof (mas->endpoint->wlan_addr)));
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
	   "Data for `%s', not for me, ignoring\n",
	   GNUNET_i2s (&wlanheader->target));
      break;
    }
    if (ntohl (wlanheader->crc) !=
	GNUNET_CRYPTO_crc32_n (&wlanheader[1],
                               msize - sizeof (struct WlanHeader)))
    {
      GNUNET_STATISTICS_update (plugin->env->stats,
				_("# DATA messages discarded due to CRC32 error"),
                                1,
				GNUNET_NO);
      break;
    }
    mas->session = lookup_session (mas->endpoint,
                                   &wlanheader->sender);
    if (NULL == mas->session)
    {
      mas->session = create_session (mas->endpoint,
                                     &wlanheader->sender);
      address = GNUNET_HELLO_address_allocate (&wlanheader->sender,
                                               PLUGIN_NAME,
                                               &mas->endpoint->wlan_addr,
                                               sizeof (struct WlanAddress),
                                               GNUNET_HELLO_ADDRESS_INFO_NONE);
      plugin->env->session_start (plugin->env->cls,
                                  address,
                                  mas->session,
                                  scope);
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Notifying transport about peer `%s''s new session %p \n",
           GNUNET_i2s (&wlanheader->sender),
           mas->session);
      GNUNET_HELLO_address_free (address);
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Processing %u bytes of DATA from peer `%s'\n",
	 (unsigned int) msize,
	 GNUNET_i2s (&wlanheader->sender));
    mas->session->timeout = GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
    (void) GNUNET_SERVER_mst_receive (plugin->wlan_header_payload_tokenizer,
				      mas,
				      (const char *) &wlanheader[1],
				      msize - sizeof (struct WlanHeader),
				      GNUNET_YES,
                                      GNUNET_NO);
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
                          mas->session->address,
                          mas->session,
                          hdr);
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
  if (NULL != hello)
  {
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
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Broadcasting %u bytes of data to MAC `%s'\n",
	 (unsigned int) size,
	 mac_to_string (&bc_all_mac));
    get_wlan_header (plugin, &radioHeader->frame, &bc_all_mac, size);
    memcpy (&radioHeader[1], hello, hello_size);
    if (NULL !=
	GNUNET_HELPER_send (plugin->suid_helper,
			    &radioHeader->header,
			    GNUNET_YES /* can drop */,
			    NULL, NULL))
      GNUNET_STATISTICS_update (plugin->env->stats,
                                _("# HELLO beacons sent"),
				1, GNUNET_NO);
  } }
  plugin->beacon_task =
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
				  (HELLO_BEACON_SCALING_FACTOR,
				   plugin->mac_count + 1),
				  &send_hello_beacon,
				  plugin);

}


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
  struct GNUNET_HELLO_Address *my_address;
  const struct GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage *rxinfo;
  const struct GNUNET_TRANSPORT_WLAN_HelperControlMessage *cm;
  struct WlanAddress wa;
  struct MacAndSession mas;
  uint16_t msize;
  struct FragmentMessage *fm;
  struct MacEndpoint *endpoint;

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
      memset (&wa, 0, sizeof (struct WlanAddress));
      wa.mac = plugin->mac_address;
      wa.options = htonl(plugin->options);
      my_address = GNUNET_HELLO_address_allocate (plugin->env->my_identity,
                                                  PLUGIN_NAME,
                                                  &wa, sizeof (wa),
                                                  GNUNET_HELLO_ADDRESS_INFO_NONE);
      plugin->env->notify_address (plugin->env->cls,
                                   GNUNET_NO,
                                   my_address);
      GNUNET_HELLO_address_free (my_address);
      plugin->mac_address = cm->mac;
    }
    else
    {
      plugin->mac_address = cm->mac;
      plugin->have_mac = GNUNET_YES;
      for (endpoint = plugin->mac_head; NULL != endpoint; endpoint = endpoint->next)
      {
        for (fm = endpoint->sending_messages_head; NULL != fm; fm = fm->next)
        {
          if (NULL != fm->fragcontext)
          {
            GNUNET_break (0); /* should not happen */
            continue;
          }
          fm->fragcontext =
            GNUNET_FRAGMENT_context_create (plugin->env->stats,
                                            WLAN_MTU,
                                            &plugin->tracker,
                                            fm->macendpoint->msg_delay,
                                            fm->macendpoint->ack_delay,
                                            fm->msg,
                                            &transmit_fragment, fm);
          GNUNET_free (fm->msg);
          fm->msg = NULL;
        }
      }
      GNUNET_break (NULL == plugin->beacon_task);
      plugin->beacon_task = GNUNET_SCHEDULER_add_now (&send_hello_beacon,
                                                      plugin);

    }

    memset (&wa, 0, sizeof (struct WlanAddress));
    wa.mac = plugin->mac_address;
    wa.options = htonl(plugin->options);
    my_address = GNUNET_HELLO_address_allocate (plugin->env->my_identity,
                                                PLUGIN_NAME,
                                                &wa, sizeof (wa),
                                                GNUNET_HELLO_ADDRESS_INFO_NONE);

    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Received WLAN_HELPER_CONTROL message with MAC address `%s' for peer `%s'\n",
	 mac_to_string (&cm->mac),
	 GNUNET_i2s (plugin->env->my_identity));
    plugin->env->notify_address (plugin->env->cls,
                                 GNUNET_YES,
                                 my_address);
    GNUNET_HELLO_address_free (my_address);
    break;
  case GNUNET_MESSAGE_TYPE_WLAN_DATA_FROM_HELPER:
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Got data message from helper with %u bytes\n",
	 msize);
    GNUNET_STATISTICS_update (plugin->env->stats,
                              _("# DATA messages received"), 1,
                              GNUNET_NO);
    if (msize < sizeof (struct GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
	   "Size of packet is too small (%u bytes < %u)\n",
	   msize,  sizeof (struct GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage));
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
			      _("# DATA messages processed"),
			      1, GNUNET_NO);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Receiving %u bytes of data from MAC `%s'\n",
	 (unsigned int) (msize - sizeof (struct GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage)),
	 mac_to_string (&rxinfo->frame.addr2));
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Receiving %u bytes of data to MAC `%s'\n",
	 (unsigned int) (msize - sizeof (struct GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage)),
	 mac_to_string (&rxinfo->frame.addr1));
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Receiving %u bytes of data with BSSID MAC `%s'\n",
	 (unsigned int) (msize - sizeof (struct GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage)),
	 mac_to_string (&rxinfo->frame.addr3));
    wa.mac = rxinfo->frame.addr2;
    wa.options = htonl (0);
    mas.endpoint = create_macendpoint (plugin, &wa);
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
 * Another peer has suggested an address for this
 * peer and transport plugin.  Check that this could be a valid
 * address.  If so, consider adding it to the list
 * of addresses.
 *
 * @param cls closure
 * @param addr pointer to the address
 * @param addrlen length of @a addr
 * @return #GNUNET_OK if this is a plausible address for this peer
 *         and transport
 */
static int
wlan_plugin_address_suggested (void *cls,
                               const void *addr,
                               size_t addrlen)
{
  struct Plugin *plugin = cls;
  struct WlanAddress *wa = (struct WlanAddress *) addr;

  if (addrlen != sizeof (struct WlanAddress))
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
  if (0 != memcmp (&wa->mac,
		   &plugin->mac_address,
		   sizeof (wa->mac)))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Rejecting MAC `%s': not my MAC!\n",
	 mac_to_string (addr));
    return GNUNET_NO; /* not my MAC */
  }
  return GNUNET_OK;
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
 * @param asc_cls closure for @a asc
 */
static void
wlan_plugin_address_pretty_printer (void *cls,
                                    const char *type,
                                    const void *addr,
                                    size_t addrlen,
                                    int numeric,
                                    struct GNUNET_TIME_Relative timeout,
                                    GNUNET_TRANSPORT_AddressStringCallback asc,
                                    void *asc_cls)
{
  const char *ret;

  if (sizeof (struct WlanAddress) == addrlen)
    ret = wlan_plugin_address_to_string (NULL,
                                         addr,
                                         addrlen);
  else
    ret = NULL;
  asc (asc_cls,
       ret,
       (NULL == ret) ? GNUNET_SYSERR : GNUNET_OK);
  asc (asc_cls, NULL, GNUNET_OK);
}


/**
 * Exit point from the plugin.
 *
 * @param cls pointer to the api struct
 */
void *
LIBGNUNET_PLUGIN_TRANSPORT_DONE (void *cls)
{
  struct WlanAddress wa;
  struct GNUNET_HELLO_Address *address;
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;
  struct MacEndpoint *endpoint;
  struct MacEndpoint *endpoint_next;

  if (NULL == plugin)
  {
    GNUNET_free (api);
    return NULL;
  }
  if (GNUNET_YES == plugin->have_mac)
  {
    memset (&wa, 0, sizeof(wa));
    wa.options = htonl (plugin->options);
    wa.mac = plugin->mac_address;
    address = GNUNET_HELLO_address_allocate (plugin->env->my_identity,
                                             PLUGIN_NAME,
                                             &wa, sizeof (struct WlanAddress),
                                             GNUNET_HELLO_ADDRESS_INFO_NONE);

    plugin->env->notify_address (plugin->env->cls,
                                 GNUNET_NO,
                                 address);
    plugin->have_mac = GNUNET_NO;
    GNUNET_HELLO_address_free (address);
  }

  if (NULL != plugin->beacon_task)
  {
    GNUNET_SCHEDULER_cancel (plugin->beacon_task);
    plugin->beacon_task = NULL;
  }
  if (NULL != plugin->suid_helper)
  {
    GNUNET_HELPER_stop (plugin->suid_helper,
                        GNUNET_NO);
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
  GNUNET_free_non_null (plugin->wlan_interface);
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}


/**
 * Function called to convert a string address to
 * a binary address.
 *
 * @param cls closure (`struct Plugin *`)
 * @param addr string address
 * @param addrlen length of the address
 * @param buf location to store the buffer
 * @param added location to store the number of bytes in the buffer.
 *        If the function returns #GNUNET_SYSERR, its contents are undefined.
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
static int
wlan_plugin_string_to_address (void *cls,
                               const char *addr,
                               uint16_t addrlen,
                               void **buf,
                               size_t *added)
{
  struct WlanAddress *wa;
  unsigned int a[6];
  unsigned int i;
  char plugin[5];
  uint32_t options;

  if ((NULL == addr) || (0 == addrlen))
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

  if (8 != SSCANF (addr,
		   "%4s.%u.%X:%X:%X:%X:%X:%X",
		   plugin, &options,
		   &a[0], &a[1], &a[2],
                   &a[3], &a[4], &a[5]))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  wa = GNUNET_new (struct WlanAddress);
  for (i=0;i<6;i++)
    wa->mac.mac[i] = a[i];
  wa->options = htonl (0);
  *buf = wa;
  *added = sizeof (struct WlanAddress);
  return GNUNET_OK;
}


/**
 * Begin monitoring sessions of a plugin.  There can only
 * be one active monitor per plugin (i.e. if there are
 * multiple monitors, the transport service needs to
 * multiplex the generated events over all of them).
 *
 * @param cls closure of the plugin
 * @param sic callback to invoke, NULL to disable monitor;
 *            plugin will being by iterating over all active
 *            sessions immediately and then enter monitor mode
 * @param sic_cls closure for @a sic
 */
static void
wlan_plugin_setup_monitor (void *cls,
                           GNUNET_TRANSPORT_SessionInfoCallback sic,
                           void *sic_cls)
{
  struct Plugin *plugin = cls;
  struct MacEndpoint *mac;
  struct GNUNET_ATS_Session *session;

  plugin->sic = sic;
  plugin->sic_cls = sic_cls;
  if (NULL != sic)
  {
    for (mac = plugin->mac_head; NULL != mac; mac = mac->next)
      for (session = mac->sessions_head; NULL != session; session = session->next)
      {
        notify_session_monitor (plugin,
                                session,
                                GNUNET_TRANSPORT_SS_INIT);
        notify_session_monitor (plugin,
                                session,
                                GNUNET_TRANSPORT_SS_UP);
      }
    sic (sic_cls, NULL, NULL);
  }
}



/**
 * Function that will be called whenever the transport service wants to
 * notify the plugin that a session is still active and in use and
 * therefore the session timeout for this session has to be updated
 *
 * @param cls closure
 * @param peer which peer was the session for
 * @param session which session is being updated
 */
static void
wlan_plugin_update_session_timeout (void *cls,
                                    const struct GNUNET_PeerIdentity *peer,
                                    struct GNUNET_ATS_Session *session)
{
  GNUNET_assert (NULL != session->timeout_task);
  session->timeout = GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
}


/**
 * Function that will be called whenever the transport service wants to
 * notify the plugin that the inbound quota changed and that the plugin
 * should update it's delay for the next receive value
 *
 * @param cls closure
 * @param peer which peer was the session for
 * @param session which session is being updated
 * @param delay new delay to use for receiving
 */
static void
wlan_plugin_update_inbound_delay (void *cls,
                                  const struct GNUNET_PeerIdentity *peer,
                                  struct GNUNET_ATS_Session *session,
                                  struct GNUNET_TIME_Relative delay)
{
  /* does nothing, as inbound delay is not supported by WLAN */
}


/**
 * Entry point for the plugin.
 *
 * @param cls closure, the `struct GNUNET_TRANSPORT_PluginEnvironment *`
 * @return the `struct GNUNET_TRANSPORT_PluginFunctions *` or NULL on error
 */
void *
LIBGNUNET_PLUGIN_TRANSPORT_INIT (void *cls)
{
  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  struct Plugin *plugin;
  char *wlan_interface;
  unsigned long long testmode;
  char *binary;

  /* check for 'special' mode */
  if (NULL == env->receive)
  {
    /* run in 'stub' mode (i.e. as part of gnunet-peerinfo), don't fully
       initialze the plugin or the API */
    api = GNUNET_new (struct GNUNET_TRANSPORT_PluginFunctions);
    api->cls = NULL;
    api->address_pretty_printer = &wlan_plugin_address_pretty_printer;
    api->address_to_string = &wlan_plugin_address_to_string;
    api->string_to_address = &wlan_plugin_string_to_address;
    return api;
  }

  testmode = 0;
  /* check configuration */
  if ( (GNUNET_YES ==
	GNUNET_CONFIGURATION_have_value (env->cfg,
                                         CONFIG_NAME,
                                         "TESTMODE")) &&
       ( (GNUNET_SYSERR ==
	  GNUNET_CONFIGURATION_get_value_number (env->cfg,
                                                 CONFIG_NAME,
						 "TESTMODE",
                                                 &testmode)) ||
	 (testmode > 2) ) )
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
			       CONFIG_NAME,
                               "TESTMODE");
    return NULL;
  }
  binary = GNUNET_OS_get_libexec_binary_path (HELPER_NAME);
  if ( (0 == testmode) &&
       (GNUNET_YES !=
        GNUNET_OS_check_helper_binary (binary,
                                       GNUNET_YES,
                                       NULL)) )
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
	 _("Helper binary `%s' not SUID, cannot run WLAN transport\n"),
	 HELPER_NAME);
    GNUNET_free (binary);
    return NULL;
  }
    GNUNET_free (binary);
  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_get_value_string (env->cfg,
                                             CONFIG_NAME,
                                             "INTERFACE",
                                             &wlan_interface))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
			       CONFIG_NAME,
                               "INTERFACE");
    return NULL;
  }

  plugin = GNUNET_new (struct Plugin);
  plugin->wlan_interface = wlan_interface;
  plugin->env = env;
  GNUNET_STATISTICS_set (plugin->env->stats,
                         _("# sessions allocated"),
                         0, GNUNET_NO);
  GNUNET_STATISTICS_set (plugin->env->stats,
                         _("# MAC endpoints allocated"),
                         0, 0);
  GNUNET_BANDWIDTH_tracker_init (&plugin->tracker, NULL, NULL,
                                 GNUNET_BANDWIDTH_value_init (100 * 1024 *
                                                              1024 / 8),
                                 100);
  plugin->fragment_data_tokenizer = GNUNET_SERVER_mst_create (&process_data,
                                                              plugin);
  plugin->wlan_header_payload_tokenizer = GNUNET_SERVER_mst_create (&process_data,
                                                                    plugin);
  plugin->helper_payload_tokenizer = GNUNET_SERVER_mst_create (&process_data,
                                                               plugin);

  plugin->options = 0;

  /* some compilers do not like switch on 'long long'... */
  switch ((unsigned int) testmode)
  {
  case 0: /* normal */
    plugin->helper_argv[0] = (char *) HELPER_NAME;
    plugin->helper_argv[1] = wlan_interface;
    plugin->helper_argv[2] = NULL;
    plugin->suid_helper = GNUNET_HELPER_start (GNUNET_NO,
					       HELPER_NAME,
					       plugin->helper_argv,
					       &handle_helper_message,
					       NULL,
					       plugin);
    break;
  case 1: /* testmode, peer 1 */
    plugin->helper_argv[0] = (char *) DUMMY_HELPER_NAME;
    plugin->helper_argv[1] = (char *) "1";
    plugin->helper_argv[2] = NULL;
    plugin->suid_helper = GNUNET_HELPER_start (GNUNET_NO,
					       DUMMY_HELPER_NAME,
					       plugin->helper_argv,
					       &handle_helper_message,
					       NULL,
					       plugin);
    break;
  case 2: /* testmode, peer 2 */
    plugin->helper_argv[0] = (char *) DUMMY_HELPER_NAME;
    plugin->helper_argv[1] = (char *) "2";
    plugin->helper_argv[2] = NULL;
    plugin->suid_helper = GNUNET_HELPER_start (GNUNET_NO,
					       DUMMY_HELPER_NAME,
					       plugin->helper_argv,
					       &handle_helper_message,
					       NULL,
					       plugin);
    break;
  default:
    GNUNET_assert (0);
  }

  api = GNUNET_new (struct GNUNET_TRANSPORT_PluginFunctions);
  api->cls = plugin;
  api->send = &wlan_plugin_send;
  api->get_session = &wlan_plugin_get_session;
  api->disconnect_peer = &wlan_plugin_disconnect_peer;
  api->disconnect_session = &wlan_plugin_disconnect_session;
  api->query_keepalive_factor = &wlan_plugin_query_keepalive_factor;
  api->address_pretty_printer = &wlan_plugin_address_pretty_printer;
  api->check_address = &wlan_plugin_address_suggested;
  api->address_to_string = &wlan_plugin_address_to_string;
  api->string_to_address = &wlan_plugin_string_to_address;
  api->get_network = &wlan_plugin_get_network;
  api->get_network_for_address = &wlan_plugin_get_network_for_address;
  api->update_session_timeout = &wlan_plugin_update_session_timeout;
  api->update_inbound_delay = &wlan_plugin_update_inbound_delay;
  api->setup_monitor = &wlan_plugin_setup_monitor;
  return api;
}


/* end of plugin_transport_wlan.c */
