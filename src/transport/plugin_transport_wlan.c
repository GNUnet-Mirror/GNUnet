/*
 This file is part of GNUnet
 (C) 2010 2011 Christian Grothoff (and other contributing authors)

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
 */

//TODO split rx and tx structures for better handling

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

/**
 * DEBUG switch
 */
#define DEBUG_WLAN GNUNET_EXTRA_LOGGING


#define PROTOCOL_PREFIX "wlan"

#define PLUGIN_LOG_NAME "wlan-plugin"

/**
 * Max size of packet
 */
#define WLAN_MTU 1430

/**
 * time out of a session
 */
#define SESSION_TIMEOUT GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT

/**
 * time out of a mac endpoint
 */
#define MACENDPOINT_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT, 2)

/**
 * scaling factor for hello beacon
 */
#define HELLO_BEACON_SCALING_FACTOR 30

/**
 * scaling factor for restarting the helper
 */
#define HELPER_RESTART_SCALING_FACTOR 2

/**
 * max size of fragment queue
 */
#define FRAGMENT_QUEUE_SIZE 10
/**
 * max messages in fragment queue per session/client
 */
#define FRAGMENT_QUEUE_MESSAGES_OUT_PER_SESSION 1

/**
 * max messages in fragment queue per MAC
 */
#define FRAGMENT_QUEUE_MESSAGES_OUT_PER_MACENDPOINT 1

/**
 * max messages in in queue
 */
#define MESSAGES_IN_QUEUE_SIZE 10
/**
 * max messages in in queue per session/client
 */
#define MESSAGES_IN_DEFRAG_QUEUE_PER_MAC 1

/**
 * LLC fields for better compatibility
 */
#define WLAN_LLC_DSAP_FIELD 0x1f
#define WLAN_LLC_SSAP_FIELD 0x1f


#define IEEE80211_ADDR_LEN      6       /* size of 802.11 address */

#define IEEE80211_FC0_VERSION_MASK              0x03
#define IEEE80211_FC0_VERSION_SHIFT             0
#define IEEE80211_FC0_VERSION_0                 0x00
#define IEEE80211_FC0_TYPE_MASK                 0x0c
#define IEEE80211_FC0_TYPE_SHIFT                2
#define IEEE80211_FC0_TYPE_MGT                  0x00
#define IEEE80211_FC0_TYPE_CTL                  0x04
#define IEEE80211_FC0_TYPE_DATA                 0x08

GNUNET_NETWORK_STRUCT_BEGIN

/*
 * generic definitions for IEEE 802.11 frames
 */
struct ieee80211_frame
{
  u_int8_t i_fc[2];
  u_int8_t i_dur[2];
  u_int8_t i_addr1[IEEE80211_ADDR_LEN];
  u_int8_t i_addr2[IEEE80211_ADDR_LEN];
  u_int8_t i_addr3[IEEE80211_ADDR_LEN];
  u_int8_t i_seq[2];
  u_int8_t llc[4];
} GNUNET_PACKED;
GNUNET_NETWORK_STRUCT_END

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
   * List of open connections. head
   */
  struct MacEndpoint *mac_head;

  /**
   * List of open connections. tail
   */
  struct MacEndpoint *mac_tail;

  /**
   * Number of connections
   */
  unsigned int mac_count;

  /**
   * encapsulation of data from the local wlan helper program
   */
  struct GNUNET_SERVER_MessageStreamTokenizer *suid_tokenizer;

  /**
   * encapsulation of packets received from the wlan helper
   */
  struct GNUNET_SERVER_MessageStreamTokenizer *data_tokenizer;

  /**
   * stdout pipe handle for the gnunet-helper-transport-wlan process
   */
  struct GNUNET_DISK_PipeHandle *server_stdout;

  /**
   * stdout file handle for the gnunet-helper-transport-wlan process
   */
  const struct GNUNET_DISK_FileHandle *server_stdout_handle;

  /**
   * stdin pipe handle for the gnunet-helper-transport-wlan process
   */
  struct GNUNET_DISK_PipeHandle *server_stdin;

  /**
   * stdin file handle for the gnunet-helper-transport-wlan process
   */
  const struct GNUNET_DISK_FileHandle *server_stdin_handle;

  /**
   * ID of the gnunet-wlan-server std read task
   */
  GNUNET_SCHEDULER_TaskIdentifier server_read_task;

  /**
   * ID of the gnunet-wlan-server std read task
   */
  GNUNET_SCHEDULER_TaskIdentifier server_write_task;

  /**
   * ID of the delay task for writing
   */
  GNUNET_SCHEDULER_TaskIdentifier server_write_delay_task;

  /**
   * The process id of the wlan process
   */
  struct GNUNET_OS_Process *server_proc;

  /**
   * The interface of the wlan card given to us by the user.
   */
  char *interface;

  /**
   * Mode of operation for the helper, 0 = normal, 1 = first loopback, 2 = second loopback
   */
  long long unsigned int testmode;

  /**
   * The mac_address of the wlan card given to us by the helper.
   */
  struct GNUNET_TRANSPORT_WLAN_MacAddress mac_address;

  /**
   * Sessions currently pending for transmission
   * to a peer, if any.
   */
  struct Sessionqueue *pending_Sessions_head;

  /**
   * Sessions currently pending for transmission
   * to a peer (tail), if any.
   */
  struct Sessionqueue *pending_Sessions_tail;

  /**
   * number of pending sessions
   */
  unsigned int pendingsessions;

  /**
   * Messages in the sending queues
   */
  int pending_Fragment_Messages;

  /**
   * messages ready for send, head
   */
  struct FragmentMessage_queue *sending_messages_head;
  /**
   * messages ready for send, tail
   */
  struct FragmentMessage_queue *sending_messages_tail;
  /**
   * time of the next "hello-beacon"
   */
  struct GNUNET_TIME_Absolute beacon_time;

  /**
   * queue to send acks for received fragments (head)
   */
  struct AckSendQueue *ack_send_queue_head;

  /**
   * queue to send acks for received fragments (tail)
   */
  struct AckSendQueue *ack_send_queue_tail;

  /**
   * Tracker for bandwidth limit
   */
  struct GNUNET_BANDWIDTH_Tracker tracker;

  /**
   * saves the current state of the helper process
   */
  int helper_is_running;
};

/**
 * Struct to store data if file write did not accept the whole packet
 */
struct Finish_send
{
  /**
   * pointer to the global plugin struct
   */
  struct Plugin *plugin;

  /**
   * head of the next part to send to the helper
   */
  char *head_of_next_write;

  /**
   * Start of the message to send, needed for free
   */
  struct GNUNET_MessageHeader *msgstart;

  /**
   * rest size to send
   */
  ssize_t size;
};

/**
 * Queue of sessions, for the general session queue and the pending session queue
 */
//TODO DOXIGEN
struct Sessionqueue
{
  struct Sessionqueue *next;
  struct Sessionqueue *prev;
  struct Session *content;
#if !HAVE_UNALIGNED_64_ACCESS
  void *dummy;                  /* for alignment, see #1909 */
#endif
};

/**
 * Queue of fragmented messages, for the sending queue of the plugin
 */
//TODO DOXIGEN
struct FragmentMessage_queue
{
  struct FragmentMessage_queue *next;
  struct FragmentMessage_queue *prev;
  struct FragmentMessage *content;
};

/**
 * Queue for the fragments received
 */
//TODO DOXIGEN
struct Receive_Fragment_Queue
{
  struct Receive_Fragment_Queue *next;
  struct Receive_Fragment_Queue *prev;
  uint16_t num;
  const char *msg;
  uint16_t size;
  struct Radiotap_rx rxinfo;
};

//TODO DOXIGEN
struct MacEndpoint_id_fragment_triple
{
  struct MacEndpoint *endpoint;
  uint32_t message_id;
  struct FragmentMessage *fm;
};

//TODO DOXIGEN
struct Plugin_Session_pair
{
  struct Plugin *plugin;
  struct Session *session;
};


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Header for messages which need fragmentation
 */
struct WlanHeader
{

  struct GNUNET_MessageHeader header;

  /**
   * checksum/error correction
   */
  uint32_t crc GNUNET_PACKED;

  /**
   * To whom are we talking to (set to our identity
   * if we are still waiting for the welcome message)
   */
  struct GNUNET_PeerIdentity target;

  /**
   *  Where the packet came from
   */
  struct GNUNET_PeerIdentity source;

// followed by payload

};
GNUNET_NETWORK_STRUCT_END

/**
 * Information kept for each message that is yet to
 * be transmitted.
 */
struct PendingMessage
{
  /**
   * dll next
   */
  struct PendingMessage *next;
  /**
   * dll prev
   */
  struct PendingMessage *prev;

  /**
   * The pending message
   */
  struct WlanHeader *msg;

  /**
   * Size of the message
   */
  size_t message_size;

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
   * Timeout value for the pending message.
   */
  struct GNUNET_TIME_Absolute timeout;

};

/**
 * Queue for acks to send for fragments recived
 */
struct AckSendQueue
{

  /**
   * next ack in the ack send queue
   */
  struct AckSendQueue *next;
  /**
   * previous ack in the ack send queue
   */
  struct AckSendQueue *prev;
  /**
   * pointer to the session this ack belongs to
   */
  struct MacEndpoint *endpoint;
  /**
   * ID of message, to distinguish between the messages, picked randomly.
   */
  uint32_t message_id;

  /**
   * msg to send
   */
  struct GNUNET_MessageHeader *hdr;
  /**
   * pointer to the ieee wlan header
   */
  struct ieee80211_frame *ieeewlanheader;
  /**
   * pointer to the radiotap header
   */
  struct Radiotap_Send *radioHeader;
};

/**
 * Session infos gathered from a messages
 */
struct Session_light
{
  /**
   * the session this message belongs to
   */
  struct Session *session;
  /**
   * peer mac address
   */
  struct GNUNET_TRANSPORT_WLAN_MacAddress addr;

  /**
   * mac endpoint
   */
  struct MacEndpoint *macendpoint;
};

/**
 * Session handle for connections.
 */
struct Session
{

  /**
   * API requirement.
   */
  struct SessionHeader header;

  /**
   * Message currently pending for transmission
   * to this peer, if any. head
   */
  struct PendingMessage *pending_message_head;

  /**
   * Message currently pending for transmission
   * to this peer, if any. tail
   */
  struct PendingMessage *pending_message_tail;

  /**
   * To whom are we talking to (set to our identity
   * if we are still waiting for the welcome message)
   */
  struct GNUNET_PeerIdentity target;

  /**
   * Address of the other peer (either based on our 'connect'
   * call or on our 'accept' call).
   */
  void *connect_addr;

  /**
   * Last activity on this connection.  Used to select preferred
   * connection and timeout
   */
  struct GNUNET_TIME_Absolute last_activity;

  /**
   * Timeout task.
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * peer connection
   */
  struct MacEndpoint *mac;

  /**
   * count of messages in the fragment out queue for this session
   */

  int fragment_messages_out_count;

};

/**
 * Struct to represent one network card connection
 */
struct MacEndpoint
{
  /**
   * Pointer to the global plugin struct.
   */
  struct Plugin *plugin;
  /**
   * Struct to hold the session reachable over this mac; head
   */
  struct Sessionqueue *sessions_head;
  /**
   * Struct to hold the session reachable over this mac; tail
   */
  struct Sessionqueue *sessions_tail;
  /**
   * Messages currently sending
   * to a peer, if any.
   */
  struct FragmentMessage *sending_messages_head;

  /**
   * Messages currently sending
   * to a peer (tail), if any.
   */
  struct FragmentMessage *sending_messages_tail;
  /**
   * dll next
   */
  struct MacEndpoint *next;
  /**
   * dll prev
   */
  struct MacEndpoint *prev;

  /**
   * peer mac address
   */
  struct GNUNET_TRANSPORT_WLAN_MacAddress addr;

  /**
   * Defrag context for this mac endpoint
   */
  struct GNUNET_DEFRAGMENT_Context *defrag;

  /**
   * count of messages in the fragment out queue for this mac endpoint
   */

  int fragment_messages_out_count;

  //TODO DOXIGEN
  uint8_t rate;
  uint16_t tx_power;
  uint8_t antenna;

  /**
   * Duplicates received
   */
  int dups;

  /**
   * Fragments received
   */
  int fragc;

  /**
   * Acks received
   */
  int acks;

  /**
   * Last activity on this endpoint.  Used to select preferred
   * connection.
   */
  struct GNUNET_TIME_Absolute last_activity;

  /**
   * Timeout task.
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;
};

/**
 * Struct for Messages in the fragment queue
 */
struct FragmentMessage
{

  /**
   * Session this message belongs to
   */
  struct Session *session;

  /**
   * This is a doubly-linked list.
   */
  struct FragmentMessage *next;

  /**
   * This is a doubly-linked list.
   */
  struct FragmentMessage *prev;

  /**
   * Fragmentation context
   */
  struct GNUNET_FRAGMENT_Context *fragcontext;

  /**
   * Timeout value for the message.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Timeout task.
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * Fragment to send
   */
  char *frag;

  /**
   * size of message
   */
  size_t size;

  /**
   * pointer to the ieee wlan header
   */
  struct ieee80211_frame *ieeewlanheader;
  /**
   * pointer to the radiotap header
   */
  struct Radiotap_Send *radioHeader;
};

static void
do_transmit (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

static void
free_session (struct Plugin *plugin, struct Sessionqueue *queue,
              int do_free_macendpoint);

static struct MacEndpoint *
create_macendpoint (struct Plugin *plugin, const struct GNUNET_TRANSPORT_WLAN_MacAddress *addr);

static void
finish_sending (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

/**
 * Generates a nice hexdump of a memory area.
 *
 * \param  mem     pointer to memory to dump
 * \param  length  how many bytes to dump
 */
static void
hexdump (const void *mem, unsigned length)
{
  char line[80];
  char *src = (char *) mem;

  printf ("dumping %u bytes from %p\r\n"
          "       0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F    0123456789ABCDEF\r\n",
          length, src);
  unsigned i;
  int j;

  for (i = 0; i < length; i += 16, src += 16)
  {
    char *t = line;

    t += sprintf (t, "%04x:  ", i);
    for (j = 0; j < 16; j++)
    {
      if (i + j < length)
        t += sprintf (t, "%02X", src[j] & 0xff);
      else
        t += sprintf (t, "  ");

      t += sprintf (t, (j % 2) ? " " : "-");
    }

    t += sprintf (t, "  ");
    for (j = 0; j < 16; j++)
    {
      if (i + j < length)
      {
        if (isprint ((unsigned char) src[j]))
          t += sprintf (t, "%c", src[j]);
        else
          t += sprintf (t, ".");
      }
      else
      {
        t += sprintf (t, " ");
      }
    }

    t += sprintf (t, "\r\n");
    printf ("%s", line);
  }
}

/**
 * Function to find a MacEndpoint with a specific mac addr
 * @param plugin pointer to the plugin struct
 * @param addr pointer to the mac address
 * @param create_new GNUNET_YES if a new end point should be created
 * @return
 */
static struct MacEndpoint *
get_macendpoint (struct Plugin *plugin, const struct GNUNET_TRANSPORT_WLAN_MacAddress *addr,
                 int create_new)
{
  struct MacEndpoint *queue = plugin->mac_head;

  while (queue != NULL)
  {
    //GNUNET_assert (queue->sessions_head != NULL);
    if (memcmp (addr, &queue->addr, sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress)) == 0)
      return queue;             /* session found */
    queue = queue->next;
  }

  if (create_new == GNUNET_YES)
  {
    return create_macendpoint (plugin, addr);
  }
  else
  {
    return NULL;
  }

}

/**
 * search for a session with the macendpoint and peer id
 *
 * @param plugin pointer to the plugin struct
 * @param endpoint pointer to the mac endpoint of the peer
 * @param peer pointer to the peerid
 * @return returns the session
 */
static struct Session *
search_session (struct Plugin *plugin, const struct MacEndpoint *endpoint,
                const struct GNUNET_PeerIdentity *peer)
{
  GNUNET_assert (endpoint != NULL);
  struct Sessionqueue *queue = endpoint->sessions_head;

  while (queue != NULL)
  {
    GNUNET_assert (queue->content != NULL);
    if (memcmp
        (peer, &queue->content->target,
         sizeof (struct GNUNET_PeerIdentity)) == 0)
      return queue->content;    /* session found */
    queue = queue->next;
  }
  return NULL;
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
  static char ret[40];
  const struct GNUNET_TRANSPORT_WLAN_MacAddress *mac;

  if (addrlen != sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress))
  {
    GNUNET_break (0);
    return NULL;
  }
  mac = addr;
  GNUNET_snprintf (ret, sizeof (ret), "%s Mac-Address %X:%X:%X:%X:%X:%X",
                   PROTOCOL_PREFIX, mac->mac[0], mac->mac[1], mac->mac[2],
                   mac->mac[3], mac->mac[4], mac->mac[5]);

  return ret;
}

/**
 * Function for the scheduler if a session times out
 * @param cls pointer to the Sessionqueue
 * @param tc pointer to the GNUNET_SCHEDULER_TaskContext
 */
static void
session_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Sessionqueue *queue = cls;

  GNUNET_assert (queue != NULL);
  GNUNET_assert (queue->content != NULL);
  queue->content->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  if (tc->reason == GNUNET_SCHEDULER_REASON_SHUTDOWN)
  {
    return;
  }
  if (GNUNET_TIME_absolute_get_remaining
      (GNUNET_TIME_absolute_add
       (queue->content->last_activity, SESSION_TIMEOUT)).rel_value == 0)
  {

    GNUNET_assert (queue->content->mac != NULL);
    GNUNET_assert (queue->content->mac->plugin != NULL);
    GNUNET_STATISTICS_update (queue->content->mac->plugin->env->stats,
                              _("# wlan session timeouts"), 1, GNUNET_NO);
    free_session (queue->content->mac->plugin, queue, GNUNET_YES);
  }
  else
  {
    queue->content->timeout_task =
        GNUNET_SCHEDULER_add_delayed (SESSION_TIMEOUT, &session_timeout, queue);
  }
}

/**
 * create a new session
 *
 * @param plugin pointer to the plugin struct
 * @param endpoint pointer to the mac endpoint of the peer
 * @param peer peer identity to use for this session
 * @return returns the session
 */
static struct Session *
create_session (struct Plugin *plugin, struct MacEndpoint *endpoint,
                const struct GNUNET_PeerIdentity *peer)
{
  GNUNET_assert (endpoint != NULL);
  GNUNET_assert (plugin != NULL);
  GNUNET_STATISTICS_update (plugin->env->stats, _("# wlan session created"), 1,
                            GNUNET_NO);
  struct Sessionqueue *queue =
      GNUNET_malloc (sizeof (struct Sessionqueue) + sizeof (struct Session));

  GNUNET_CONTAINER_DLL_insert_tail (endpoint->sessions_head,
                                    endpoint->sessions_tail, queue);

  queue->content = (struct Session *) &queue[1];
  queue->content->mac = endpoint;
  queue->content->target = *peer;
  queue->content->last_activity = GNUNET_TIME_absolute_get ();
  queue->content->timeout_task =
      GNUNET_SCHEDULER_add_delayed (SESSION_TIMEOUT, &session_timeout, queue);

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                   "New session %p with endpoint %p: %s\n", queue->content,
                   endpoint, wlan_plugin_address_to_string (NULL,
                                                            endpoint->addr.mac,
                                                            6));
  return queue->content;
}

/**
 * Get session from address, create if no session exists
 *
 * @param plugin pointer to the plugin struct
 * @param addr pointer to the mac address of the peer
 * @param peer pointer to the peerid
 * @return returns the session
 */
static struct Session *
get_session (struct Plugin *plugin, const struct GNUNET_TRANSPORT_WLAN_MacAddress *addr,
             const struct GNUNET_PeerIdentity *peer)
{
  struct MacEndpoint *mac;

  mac = get_macendpoint (plugin, addr, GNUNET_YES);
  struct Session *session = search_session (plugin, mac, peer);

  if (session != NULL)
    return session;
  return create_session (plugin, mac, peer);
}

/**
 * Queue the session to send data
 * checks if there is a message pending
 * checks if this session is not allready in the queue
 * @param plugin pointer to the plugin
 * @param session pointer to the session to add
 */
static void
queue_session (struct Plugin *plugin, struct Session *session)
{
  struct Sessionqueue *queue = plugin->pending_Sessions_head;

  if (session->pending_message_head != NULL)
  {
    while (queue != NULL)
    {
      // content is never NULL
      GNUNET_assert (queue->content != NULL);
      // is session already in queue?
      if (session == queue->content)
      {
        return;
      }
      // try next
      queue = queue->next;
    }

    // Session is not in the queue

    queue = GNUNET_malloc (sizeof (struct Sessionqueue));
    queue->content = session;

    //insert at the tail
    GNUNET_CONTAINER_DLL_insert_tail (plugin->pending_Sessions_head,
                                      plugin->pending_Sessions_tail, queue);
    plugin->pendingsessions++;
    GNUNET_STATISTICS_set (plugin->env->stats, _("# wlan pending sessions"),
                           plugin->pendingsessions, GNUNET_NO);
  }

}

/**
 * Function to schedule the write task, executed after a delay
 * @param cls pointer to the plugin struct
 * @param tc GNUNET_SCHEDULER_TaskContext pointer
 */
static void
delay_fragment_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;

  plugin->server_write_delay_task = GNUNET_SCHEDULER_NO_TASK;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  // GNUNET_TIME_UNIT_FOREVER_REL is needed to clean up old msg
  if (plugin->server_write_task == GNUNET_SCHEDULER_NO_TASK)
  {
    plugin->server_write_task =
        GNUNET_SCHEDULER_add_write_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                         plugin->server_stdin_handle,
                                         &do_transmit, plugin);
  }
}

/**
 * Function to calculate the time of the next periodic "hello-beacon"
 * @param plugin pointer to the plugin struct
 */
static void
set_next_beacon_time (struct Plugin *const plugin)
{
  //under 10 known peers: once a second
  if (plugin->mac_count < 10)
  {
    plugin->beacon_time =
        GNUNET_TIME_absolute_add (GNUNET_TIME_absolute_get (),
                                  GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_SECONDS,
                                   HELLO_BEACON_SCALING_FACTOR));
  }
  //under 30 known peers: every 10 seconds
  else if (plugin->mac_count < 30)
  {
    plugin->beacon_time =
        GNUNET_TIME_absolute_add (GNUNET_TIME_absolute_get (),
                                  GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_SECONDS,
                                   10 * HELLO_BEACON_SCALING_FACTOR));
  }
  //over 30 known peers: once a minute
  else
  {
    plugin->beacon_time =
        GNUNET_TIME_absolute_add (GNUNET_TIME_absolute_get (),
                                  GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_MINUTES,
                                   HELLO_BEACON_SCALING_FACTOR));
  }
}

/**
 * Function to set the timer for the next timeout of the fragment queue
 * @param plugin the handle to the plugin struct
 */
static void
set_next_send (struct Plugin *const plugin)
{
  struct GNUNET_TIME_Relative next_send;

  //abort if helper is not running
  if (plugin->helper_is_running == GNUNET_NO)
  {
    return;
  }

  //cancel old task
  if (plugin->server_write_delay_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (plugin->server_write_delay_task);
    plugin->server_write_delay_task = GNUNET_SCHEDULER_NO_TASK;
  }

  //check if some acks are in the queue
  if (plugin->ack_send_queue_head != NULL)
  {
    next_send = GNUNET_TIME_UNIT_ZERO;
  }

  //check if there are some fragments in the queue
  else if (plugin->sending_messages_head != NULL)
  {
    next_send = GNUNET_TIME_UNIT_ZERO;
  }
  else
  {
    next_send = GNUNET_TIME_absolute_get_remaining (plugin->beacon_time);
  }

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                   "Next packet is send in: %u\n", next_send.rel_value);
  if (next_send.rel_value == GNUNET_TIME_UNIT_ZERO.rel_value)
  {
    if (plugin->server_write_task == GNUNET_SCHEDULER_NO_TASK)
    {
      plugin->server_write_task =
          GNUNET_SCHEDULER_add_write_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                           plugin->server_stdin_handle,
                                           &do_transmit, plugin);
    }
  }
  else
  {
    if (plugin->server_write_delay_task == GNUNET_SCHEDULER_NO_TASK)
    {
      plugin->server_write_delay_task =
          GNUNET_SCHEDULER_add_delayed (next_send, &delay_fragment_task,
                                        plugin);
    }
  }
}

/**
 * Function to get the next queued Session, removes the session from the queue
 * @param plugin pointer to the plugin struct
 * @return pointer to the session found, returns NULL if there is now session in the queue
 */
static struct Session *
get_next_queue_session (struct Plugin *plugin)
{
  struct Session *session;
  struct Sessionqueue *sessionqueue;
  struct Sessionqueue *sessionqueue_alt;
  struct PendingMessage *pm;

  sessionqueue = plugin->pending_Sessions_head;

  while (sessionqueue != NULL)
  {
    session = sessionqueue->content;

    GNUNET_assert (session != NULL);
    pm = session->pending_message_head;

    if (pm == NULL)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, PLUGIN_LOG_NAME,
                       "pending message is empty, should not happen. session %p\n",
                       session);
      sessionqueue_alt = sessionqueue;
      sessionqueue = sessionqueue->next;
      plugin->pendingsessions--;
      GNUNET_STATISTICS_set (plugin->env->stats, _("# wlan pending sessions"),
                             plugin->pendingsessions, GNUNET_NO);
      GNUNET_CONTAINER_DLL_remove (plugin->pending_Sessions_head,
                                   plugin->pending_Sessions_tail,
                                   sessionqueue_alt);

      GNUNET_free (sessionqueue_alt);
      continue;

    }

    //check for message timeout
    if (GNUNET_TIME_absolute_get_remaining (pm->timeout).rel_value > 0)
    {
      //check if session has no message in the fragment queue
      if ((session->mac->fragment_messages_out_count <
           FRAGMENT_QUEUE_MESSAGES_OUT_PER_MACENDPOINT) &&
          (session->fragment_messages_out_count <
           FRAGMENT_QUEUE_MESSAGES_OUT_PER_SESSION))
      {
        plugin->pendingsessions--;
        GNUNET_STATISTICS_set (plugin->env->stats, _("# wlan pending sessions"),
                               plugin->pendingsessions, GNUNET_NO);
        GNUNET_CONTAINER_DLL_remove (plugin->pending_Sessions_head,
                                     plugin->pending_Sessions_tail,
                                     sessionqueue);
        GNUNET_free (sessionqueue);

        return session;
      }
      else
      {
        sessionqueue = sessionqueue->next;
      }
    }
    else
    {
      GNUNET_CONTAINER_DLL_remove (session->pending_message_head,
                                   session->pending_message_tail, pm);

      //call the cont func that it did not work
      if (pm->transmit_cont != NULL)
        pm->transmit_cont (pm->transmit_cont_cls, &(session->target),
                           GNUNET_SYSERR);
      GNUNET_free (pm->msg);
      GNUNET_free (pm);

      if (session->pending_message_head == NULL)
      {
        sessionqueue_alt = sessionqueue;
        sessionqueue = sessionqueue->next;
        plugin->pendingsessions--;
        GNUNET_STATISTICS_set (plugin->env->stats, _("# wlan pending sessions"),
                               plugin->pendingsessions, GNUNET_NO);
        GNUNET_CONTAINER_DLL_remove (plugin->pending_Sessions_head,
                                     plugin->pending_Sessions_tail,
                                     sessionqueue_alt);

        GNUNET_free (sessionqueue_alt);
      }
    }

  }
  return NULL;
}

/**
 * frees the space of a message in the fragment queue (send queue)
 * @param plugin the plugin struct
 * @param fm message to free
 */
static void
free_fragment_message (struct Plugin *plugin, struct FragmentMessage *fm)
{
  struct Session *session = fm->session;
  struct MacEndpoint *endpoint = session->mac;
  struct FragmentMessage_queue *fmq;
  struct FragmentMessage_queue *fmq_next;

  fmq = plugin->sending_messages_head;
  while (fmq != NULL)
  {
    fmq_next = fmq->next;
    if (fmq->content == fm)
    {
      GNUNET_CONTAINER_DLL_remove (plugin->sending_messages_head,
                                   plugin->sending_messages_tail, fmq);
      GNUNET_free (fmq);
    }
    fmq = fmq_next;
  }

  (session->mac->fragment_messages_out_count)--;
  session->fragment_messages_out_count--;
  plugin->pending_Fragment_Messages--;
  GNUNET_STATISTICS_set (plugin->env->stats, _("# wlan pending fragments"),
                         plugin->pending_Fragment_Messages, GNUNET_NO);
  GNUNET_CONTAINER_DLL_remove (endpoint->sending_messages_head,
                               endpoint->sending_messages_tail, fm);
  GNUNET_FRAGMENT_context_destroy (fm->fragcontext);
  if (fm->timeout_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (fm->timeout_task);
    fm->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }

  GNUNET_free (fm);

  queue_session (plugin, session);
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                   "Free pending fragment messages %p, session %p\n", fm,
                   session);
}

/**
 * function to fill the radiotap header
 * @param plugin pointer to the plugin struct
 * @param endpoint pointer to the endpoint
 * @param header pointer to the radiotap header
 * @return GNUNET_YES at success
 */
static int
getRadiotapHeader (struct Plugin *plugin, struct MacEndpoint *endpoint,
                   struct Radiotap_Send *header)
{

  if (endpoint != NULL)
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

  return GNUNET_YES;
}

/**
 * function to generate the wlan hardware header for one packet
 * @param Header address to write the header to
 * @param to_mac_addr address of the recipient
 * @param plugin pointer to the plugin struct
 * @param size size of the whole packet, needed to calculate the time to send the packet
 * @return GNUNET_YES if there was no error
 */
static int
getWlanHeader (struct ieee80211_frame *Header,
               const struct GNUNET_TRANSPORT_WLAN_MacAddress *to_mac_addr, struct Plugin *plugin,
               unsigned int size)
{
  uint16_t *tmp16;
  const int rate = 11000000;

  Header->i_fc[0] = IEEE80211_FC0_TYPE_DATA;
  Header->i_fc[1] = 0x00;
  memcpy (&Header->i_addr3, &mac_bssid_gnunet, sizeof (mac_bssid_gnunet));
  memcpy (&Header->i_addr2, plugin->mac_address.mac,
          sizeof (plugin->mac_address));
  memcpy (&Header->i_addr1, to_mac_addr, sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress));

  tmp16 = (uint16_t *) Header->i_dur;
  *tmp16 = (uint16_t) GNUNET_htole16 ((size * 1000000) / rate + 290);
  Header->llc[0] = WLAN_LLC_DSAP_FIELD;
  Header->llc[1] = WLAN_LLC_SSAP_FIELD;

  return GNUNET_YES;
}


/**
 * function to add a fragment of a message to send
 * @param cls FragmentMessage this message belongs to
 * @param hdr pointer to the start of the message
 */
static void
add_message_for_send (void *cls, const struct GNUNET_MessageHeader *hdr)
{

  struct FragmentMessage *fm = cls;
  struct FragmentMessage_queue *fmqueue;

  GNUNET_assert (cls != NULL);
  GNUNET_assert (fm->frag == NULL);
  struct MacEndpoint *endpoint = fm->session->mac;
  struct Plugin *plugin = endpoint->plugin;
  struct GNUNET_MessageHeader *msgheader;
  struct GNUNET_MessageHeader *msgheader2;
  uint16_t size;

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                   "Adding fragment of message %p to send, session %p, endpoint %p, type %u\n",
                   fm, fm->session, endpoint, hdr->type);
  size =
      sizeof (struct GNUNET_MessageHeader) + sizeof (struct Radiotap_Send) +
      sizeof (struct ieee80211_frame) + ntohs (hdr->size);
  fm->frag = GNUNET_malloc (size);
  fm->size = size;

  msgheader = (struct GNUNET_MessageHeader *) fm->frag;
  msgheader->size = htons (size);
  msgheader->type = htons (GNUNET_MESSAGE_TYPE_WLAN_HELPER_DATA);

  fm->radioHeader = (struct Radiotap_Send *) &msgheader[1];
  fm->ieeewlanheader = (struct ieee80211_frame *) &fm->radioHeader[1];
  msgheader2 = (struct GNUNET_MessageHeader *) &fm->ieeewlanheader[1];
  memcpy (msgheader2, hdr, ntohs (hdr->size));

  fmqueue = GNUNET_malloc (sizeof (struct FragmentMessage_queue));
  fmqueue->content = fm;

  GNUNET_CONTAINER_DLL_insert_tail (plugin->sending_messages_head,
                                    plugin->sending_messages_tail, fmqueue);
  set_next_send (plugin);
}


/**
 * We have been notified that gnunet-helper-transport-wlan has written something to stdout.
 * Handle the output, then reschedule this function to be called again once
 * more is available.
 *
 * @param cls the plugin handle
 * @param tc the scheduling context
 */
static void
wlan_plugin_helper_read (void *cls,
                         const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;

  plugin->server_read_task = GNUNET_SCHEDULER_NO_TASK;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  char mybuf[WLAN_MTU + sizeof (struct GNUNET_MessageHeader)];
  ssize_t bytes;

  bytes =
      GNUNET_DISK_file_read (plugin->server_stdout_handle, mybuf,
                             sizeof (mybuf));
  if (bytes <= 0)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                     _
                     ("Finished reading from gnunet-helper-transport-wlan stdout with code: %d\n"),
                     bytes);
    return;
  }
  GNUNET_SERVER_mst_receive (plugin->suid_tokenizer, NULL, mybuf, bytes,
                             GNUNET_NO, GNUNET_NO);

  GNUNET_assert (plugin->server_read_task == GNUNET_SCHEDULER_NO_TASK);
  plugin->server_read_task =
      GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                      plugin->server_stdout_handle,
                                      &wlan_plugin_helper_read, plugin);
}

/**
 * Start the gnunet-helper-transport-wlan process.
 *
 * @param plugin the transport plugin
 * @return GNUNET_YES if process was started, GNUNET_SYSERR on error
 */
static int
wlan_transport_start_wlan_helper (struct Plugin *plugin)
{
  const char *filenamehw = "gnunet-helper-transport-wlan";
  const char *filenameloopback = "gnunet-helper-transport-wlan-dummy";
  char *absolute_filename = NULL;

  if (plugin->helper_is_running == GNUNET_YES)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                     "wlan_transport_start_wlan_helper not needed, helper already running!");
    return GNUNET_YES;
  }

  plugin->server_stdout = GNUNET_DISK_pipe (GNUNET_YES, GNUNET_YES, GNUNET_NO, GNUNET_YES);
  if (plugin->server_stdout == NULL)
    return GNUNET_SYSERR;

  plugin->server_stdin = GNUNET_DISK_pipe (GNUNET_YES, GNUNET_YES, GNUNET_YES, GNUNET_NO);
  if (plugin->server_stdin == NULL)
    return GNUNET_SYSERR;

  if ((plugin->testmode == 1) || (plugin->testmode == 2))
  {
    if (GNUNET_OS_check_helper_binary (filenameloopback) == GNUNET_YES)
    {
      absolute_filename = GNUNET_strdup (filenameloopback);
    }
    else
    {
      char cwd[FILENAME_MAX];

      GNUNET_assert (getcwd (cwd, sizeof (cwd)) != NULL);

      GNUNET_asprintf (&absolute_filename, "%s%s%s", cwd, DIR_SEPARATOR_STR,
                       filenameloopback);

      if (GNUNET_DISK_file_test (filenameloopback) != GNUNET_YES)
      {
        GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, PLUGIN_LOG_NAME,
                         "Helper `%s' not found! %i\n", absolute_filename);
        GNUNET_break (0);
      }
    }
  }

  /* Start the server process */

  if (plugin->testmode == 0)
  {

    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                     "Starting gnunet-helper-transport-wlan process cmd: %s %s %i\n",
                     filenamehw, plugin->interface, plugin->testmode);
    if (GNUNET_OS_check_helper_binary (filenamehw) == GNUNET_YES)
    {
      plugin->server_proc =
	  GNUNET_OS_start_process (GNUNET_NO, plugin->server_stdin, plugin->server_stdout,
                                   filenamehw, filenamehw, plugin->interface,
                                   NULL);
    }
    else if (GNUNET_OS_check_helper_binary (filenamehw) == GNUNET_NO)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, PLUGIN_LOG_NAME,
                       "gnunet-helper-transport-wlan is not suid, please change it or look at the doku\n");
      GNUNET_break (0);
    }
    else
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, PLUGIN_LOG_NAME,
                       "gnunet-helper-transport-wlan not found, please look if it exists and is the $PATH variable!\n");
      GNUNET_break (0);
    }

  }
  else if (plugin->testmode == 1)
  {

    GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, PLUGIN_LOG_NAME,
                     "Starting gnunet-helper-transport-wlan-dummy loopback 1 process cmd: %s %s %i\n",
                     absolute_filename, plugin->interface, plugin->testmode);
    plugin->server_proc =
        GNUNET_OS_start_process (GNUNET_NO, plugin->server_stdin, plugin->server_stdout,
                                 absolute_filename, absolute_filename, "1",
                                 NULL);
    if (plugin->server_proc == NULL)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, PLUGIN_LOG_NAME,
                       "`%s' not found, please look if it exists and is in the $PATH variable!\n",
                       absolute_filename);
      GNUNET_break (0);
    }
  }
  else if (plugin->testmode == 2)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, PLUGIN_LOG_NAME,
                     "Starting gnunet-helper-transport-wlan-dummy loopback 2 process cmd: %s %s %i\n",
                     absolute_filename, plugin->interface, plugin->testmode);
    plugin->server_proc =
        GNUNET_OS_start_process (GNUNET_NO, plugin->server_stdin, plugin->server_stdout,
                                 absolute_filename, absolute_filename, "2",
                                 NULL);
    if (plugin->server_proc == NULL)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, PLUGIN_LOG_NAME,
                       "`%s' not found, please look if it exists and is in the $PATH variable!\n",
                       absolute_filename);
      GNUNET_break (0);
    }
  }
  if (absolute_filename != NULL)
    GNUNET_free (absolute_filename);
  if (plugin->server_proc == NULL)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                     "Failed to start gnunet-helper-transport-wlan process\n");
    return GNUNET_SYSERR;
  }



  /* Close the write end of the read pipe */
  GNUNET_DISK_pipe_close_end (plugin->server_stdout,
                              GNUNET_DISK_PIPE_END_WRITE);

  /* Close the read end of the write pipe */
  GNUNET_DISK_pipe_close_end (plugin->server_stdin, GNUNET_DISK_PIPE_END_READ);

  plugin->server_stdout_handle =
      GNUNET_DISK_pipe_handle (plugin->server_stdout,
                               GNUNET_DISK_PIPE_END_READ);
  plugin->server_stdin_handle =
      GNUNET_DISK_pipe_handle (plugin->server_stdin,
                               GNUNET_DISK_PIPE_END_WRITE);

  GNUNET_assert (plugin->server_read_task == GNUNET_SCHEDULER_NO_TASK);

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                   "Adding server_read_task for the gnunet-helper-transport-wlan\n");
  plugin->server_read_task =
      GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                      plugin->server_stdout_handle,
                                      &wlan_plugin_helper_read, plugin);

  plugin->helper_is_running = GNUNET_YES;
  return GNUNET_YES;
}

/**
 * Stops the gnunet-helper-transport-wlan process.
 *
 * @param plugin the transport plugin
 * @return GNUNET_YES if process was started, GNUNET_SYSERR on error
 */
static int
wlan_transport_stop_wlan_helper (struct Plugin *plugin)
{
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                   "Stoping WLAN helper process\n");

  if (plugin->helper_is_running == GNUNET_NO)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                     "wlan_transport_stop_wlan_helper not needed, helper already stopped!");
    return GNUNET_YES;
  }

  if (plugin->server_write_delay_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (plugin->server_write_delay_task);
    plugin->server_write_delay_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (plugin->server_write_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (plugin->server_write_task);
    plugin->server_write_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (plugin->server_read_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (plugin->server_read_task);
    plugin->server_read_task = GNUNET_SCHEDULER_NO_TASK;
  }

  GNUNET_DISK_pipe_close (plugin->server_stdout);
  GNUNET_DISK_pipe_close (plugin->server_stdin);
  GNUNET_OS_process_kill (plugin->server_proc, SIGKILL);
  GNUNET_OS_process_wait (plugin->server_proc);
  GNUNET_OS_process_close (plugin->server_proc);

  plugin->helper_is_running = GNUNET_NO;

  return GNUNET_YES;
}

/**
 * function for delayed restart of the helper process
 * @param cls Finish_send struct if message should be finished
 * @param tc TaskContext
 */
static void
delay_restart_helper (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Finish_send *finish = cls;
  struct Plugin *plugin;

  plugin = finish->plugin;

  plugin->server_write_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
  {
    GNUNET_free_non_null (finish->msgstart);
    GNUNET_free (finish);
    return;
  }

  wlan_transport_start_wlan_helper (plugin);

  if (finish->size != 0)
  {
    plugin->server_write_task =
        GNUNET_SCHEDULER_add_write_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                         plugin->server_stdin_handle,
                                         &finish_sending, finish);
  }
  else
  {
    set_next_send (plugin);
    GNUNET_free_non_null (finish->msgstart);
    GNUNET_free (finish);
  }

}

/**
 * Function to restart the helper
 * @param plugin pointer to the global plugin struct
 * @param finish pointer to the Finish_send struct to finish
 */
static void
restart_helper (struct Plugin *plugin, struct Finish_send *finish)
{
  static struct GNUNET_TIME_Relative next_try = { 1000 };
  GNUNET_assert (finish != NULL);

  wlan_transport_stop_wlan_helper (plugin);
  plugin->server_write_task =
      GNUNET_SCHEDULER_add_delayed (next_try, &delay_restart_helper, finish);
  GNUNET_TIME_relative_multiply (next_try, HELPER_RESTART_SCALING_FACTOR);

}

/**
 * function to finish a sending if not all could have been writen befor
 * @param cls pointer to the Finish_send struct
 * @param tc TaskContext
 */
static void
finish_sending (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Finish_send *finish = cls;
  struct Plugin *plugin;
  ssize_t bytes;

  plugin = finish->plugin;
  plugin->server_write_task = GNUNET_SCHEDULER_NO_TASK;

  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
  {
    GNUNET_free (finish->msgstart);
    GNUNET_free (finish);
    return;
  }
  bytes =
      GNUNET_DISK_file_write (plugin->server_stdin_handle,
                              finish->head_of_next_write, finish->size);

  if (bytes != finish->size)
  {
    if (bytes != GNUNET_SYSERR)
    {
      finish->head_of_next_write += bytes;
      finish->size -= bytes;
      plugin->server_write_task =
          GNUNET_SCHEDULER_add_write_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                           plugin->server_stdin_handle,
                                           &finish_sending, finish);
    }
    else
    {
      restart_helper (plugin, finish);
    }
  }
  else
  {
    GNUNET_free (finish->msgstart);
    GNUNET_free (finish);
    set_next_send (plugin);
  }
}

/**
 * function to send a hello beacon
 * @param plugin pointer to the plugin struct
 */
static void
send_hello_beacon (struct Plugin *plugin)
{
  uint16_t size;
  ssize_t bytes;
  uint16_t hello_size;
  struct GNUNET_MessageHeader *msgheader;
  struct ieee80211_frame *ieeewlanheader;
  struct Radiotap_Send *radioHeader;
  struct GNUNET_MessageHeader *msgheader2;
  const struct GNUNET_MessageHeader *hello;
  struct Finish_send *finish;

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                   "Sending hello beacon\n");

  GNUNET_assert (plugin != NULL);

  GNUNET_STATISTICS_update (plugin->env->stats, _("# wlan hello beacons send"),
                            1, GNUNET_NO);

  hello = plugin->env->get_our_hello ();
  hello_size = GNUNET_HELLO_size ((struct GNUNET_HELLO_Message *) hello);
  GNUNET_assert (sizeof (struct WlanHeader) + hello_size <= WLAN_MTU);
  size =
      sizeof (struct GNUNET_MessageHeader) + sizeof (struct Radiotap_Send) +
      sizeof (struct ieee80211_frame) + hello_size;

  msgheader = GNUNET_malloc (size);
  msgheader->size = htons (size);
  msgheader->type = htons (GNUNET_MESSAGE_TYPE_WLAN_HELPER_DATA);

  radioHeader = (struct Radiotap_Send *) &msgheader[1];
  getRadiotapHeader (plugin, NULL, radioHeader);
  ieeewlanheader = (struct ieee80211_frame *) &radioHeader[1];
  getWlanHeader (ieeewlanheader, &bc_all_mac, plugin, size);

  msgheader2 = (struct GNUNET_MessageHeader *) &ieeewlanheader[1];
  /*msgheader2->size =
   * htons (GNUNET_HELLO_size ((struct GNUNET_HELLO_Message *) hello) +
   * sizeof (struct GNUNET_MessageHeader));
   *
   * msgheader2->type = htons (GNUNET_MESSAGE_TYPE_WLAN_ADVERTISEMENT); */
  memcpy (msgheader2, hello, hello_size);

  bytes = GNUNET_DISK_file_write (plugin->server_stdin_handle, msgheader, size);

  if (bytes == GNUNET_SYSERR)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, PLUGIN_LOG_NAME,
                     _
                     ("Error writing to wlan helper. errno == %d, ERROR: %s\n"),
                     errno, strerror (errno));
    finish = GNUNET_malloc (sizeof (struct Finish_send));
    finish->plugin = plugin;
    finish->head_of_next_write = NULL;
    finish->size = 0;
    finish->msgstart = NULL;
    restart_helper (plugin, finish);

    set_next_beacon_time (plugin);

  }
  else
  {
    GNUNET_assert (bytes == size);
    set_next_beacon_time (plugin);
    set_next_send (plugin);
  }
  GNUNET_free (msgheader);


}

/**
 * function to add an ack to send it for a received fragment
 * @param cls MacEndpoint this ack belongs to
 * @param msg_id id of the message
 * @param hdr pointer to the hdr where the ack is stored
 *
 */
static void
add_ack_for_send (void *cls, uint32_t msg_id,
                  const struct GNUNET_MessageHeader *hdr)
{

  struct AckSendQueue *ack;

  GNUNET_assert (cls != NULL);
  struct MacEndpoint *endpoint = cls;
  struct Plugin *plugin = endpoint->plugin;
  struct GNUNET_MessageHeader *msgheader;
  struct GNUNET_MessageHeader *msgheader2;
  uint16_t size;

  size =
      sizeof (struct GNUNET_MessageHeader) + sizeof (struct Radiotap_Send) +
      sizeof (struct ieee80211_frame) + ntohs (hdr->size) +
      sizeof (struct AckSendQueue);

  ack = GNUNET_malloc (size);
  ack->message_id = msg_id;
  ack->endpoint = endpoint;

  size =
      sizeof (struct GNUNET_MessageHeader) + sizeof (struct Radiotap_Send) +
      sizeof (struct ieee80211_frame) + ntohs (hdr->size);

  msgheader = (struct GNUNET_MessageHeader *) &ack[1];
  ack->hdr = (struct GNUNET_MessageHeader *) &ack[1];
  msgheader->size = htons (size);
  msgheader->type = htons (GNUNET_MESSAGE_TYPE_WLAN_HELPER_DATA);

  ack->radioHeader = (struct Radiotap_Send *) &msgheader[1];
  ack->ieeewlanheader = (struct ieee80211_frame *) &(ack->radioHeader)[1];
  msgheader2 = (struct GNUNET_MessageHeader *) &(ack->ieeewlanheader)[1];
  memcpy (msgheader2, hdr, ntohs (hdr->size));

  GNUNET_CONTAINER_DLL_insert_tail (plugin->ack_send_queue_head,
                                    plugin->ack_send_queue_tail, ack);

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                   "Adding ack with message id %u to send, AckSendQueue %p, endpoint %p\n",
                   msg_id, ack, endpoint);
  set_next_send (plugin);
}

/**
 * Function for the scheduler if a FragmentMessage times out
 * @param cls pointer to the FragmentMessage
 * @param tc pointer to the GNUNET_SCHEDULER_TaskContext
 */
static void
fragmentmessage_timeout (void *cls,
                         const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct FragmentMessage *fm = cls;

  GNUNET_assert (fm != NULL);
  fm->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  if (tc->reason == GNUNET_SCHEDULER_REASON_SHUTDOWN)
  {
    return;
  }
  free_fragment_message (fm->session->mac->plugin, fm);
}

/**
 * Function to check if there is some space in the fragment queue
 * inserts a message if space is available
 * @param plugin the plugin struct
 */

static void
check_fragment_queue (struct Plugin *plugin)
{
  struct Session *session;
  struct FragmentMessage *fm;
  struct GNUNET_PeerIdentity pid;

  struct PendingMessage *pm;

  if (plugin->pending_Fragment_Messages < FRAGMENT_QUEUE_SIZE)
  {
    session = get_next_queue_session (plugin);
    if (session != NULL)
    {
      pm = session->pending_message_head;
      GNUNET_assert (pm != NULL);
      GNUNET_CONTAINER_DLL_remove (session->pending_message_head,
                                   session->pending_message_tail, pm);
      session->mac->fragment_messages_out_count++;
      session->fragment_messages_out_count++;
      plugin->pending_Fragment_Messages++;
      GNUNET_STATISTICS_set (plugin->env->stats, _("# wlan pending fragments"),
                             plugin->pending_Fragment_Messages, GNUNET_NO);

      fm = GNUNET_malloc (sizeof (struct FragmentMessage));
      fm->session = session;
      fm->timeout.abs_value = pm->timeout.abs_value;
      fm->frag = NULL;
      fm->fragcontext =
          GNUNET_FRAGMENT_context_create (plugin->env->stats, WLAN_MTU,
                                          &plugin->tracker,
                                          GNUNET_TIME_UNIT_SECONDS,
                                          &(pm->msg->header),
                                          &add_message_for_send, fm);
      fm->timeout_task =
          GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_absolute_get_remaining
                                        (fm->timeout), fragmentmessage_timeout,
                                        fm);
      GNUNET_CONTAINER_DLL_insert_tail (session->mac->sending_messages_head,
                                        session->mac->sending_messages_tail,
                                        fm);

      if (pm->transmit_cont != NULL)
      {
        pid = session->target;
        pm->transmit_cont (pm->transmit_cont_cls, &pid, GNUNET_OK);
        GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                         "called pm->transmit_cont for %p\n", session);
      }
      else
      {
        GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                         "no pm->transmit_cont for %p\n", session);
      }
      GNUNET_free (pm);

      if (session->pending_message_head != NULL)
      {
        //requeue session
        queue_session (plugin, session);
      }

    }
  }

  //check if timeout changed
  set_next_send (plugin);
}

/**
 * Function to send an ack, does not free the ack
 * @param plugin pointer to the plugin
 */
static void
send_ack (struct Plugin *plugin)
{

  ssize_t bytes;
  struct AckSendQueue *ack;
  struct Finish_send *finish;

  ack = plugin->ack_send_queue_head;
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                   "Sending ack for message_id %u for mac endpoint %p, size %u\n",
                   ack->message_id, ack->endpoint,
                   ntohs (ack->hdr->size) - sizeof (struct Radiotap_Send));
  GNUNET_assert (plugin != NULL);
  GNUNET_STATISTICS_update (plugin->env->stats, _("# wlan acks send"), 1,
                            GNUNET_NO);

  getRadiotapHeader (plugin, ack->endpoint, ack->radioHeader);
  getWlanHeader (ack->ieeewlanheader, &ack->endpoint->addr, plugin,
                 ntohs (ack->hdr->size));

  bytes =
      GNUNET_DISK_file_write (plugin->server_stdin_handle, ack->hdr,
                              ntohs (ack->hdr->size));
  if (bytes == GNUNET_SYSERR)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, PLUGIN_LOG_NAME,
                     _
                     ("Error writing to wlan helper. errno == %d, ERROR: %s\n"),
                     errno, strerror (errno));
    finish = GNUNET_malloc (sizeof (struct Finish_send));
    finish->plugin = plugin;
    finish->head_of_next_write = NULL;
    finish->size = 0;
    finish->msgstart = NULL;
    restart_helper (plugin, finish);
  }
  else
  {
    GNUNET_assert (bytes == ntohs (ack->hdr->size));
    GNUNET_CONTAINER_DLL_remove (plugin->ack_send_queue_head,
                                 plugin->ack_send_queue_tail, ack);
    GNUNET_free (ack);
    set_next_send (plugin);
  }
}

/**
 * Function called when wlan helper is ready to get some data
 *
 * @param cls closure
 * @param tc GNUNET_SCHEDULER_TaskContext
 */
static void
do_transmit (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;

  GNUNET_assert (plugin != NULL);

  plugin->server_write_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  struct Session *session;
  struct FragmentMessage *fm;
  struct Finish_send *finish;
  struct FragmentMessage_queue *fmq;
  ssize_t bytes;

  if (plugin->ack_send_queue_head != NULL)
  {
    send_ack (plugin);
    return;
  }

  //test if a "hello-beacon" has to be send
  if (GNUNET_TIME_absolute_get_remaining (plugin->beacon_time).rel_value == 0)
  {
    send_hello_beacon (plugin);
    return;
  }

  if (plugin->sending_messages_head != NULL)
  {
    GNUNET_STATISTICS_update (plugin->env->stats, _("# wlan fragments send"), 1,
                              GNUNET_NO);

    fmq = plugin->sending_messages_head;
    fm = fmq->content;
    GNUNET_CONTAINER_DLL_remove (plugin->sending_messages_head,
                                 plugin->sending_messages_tail, fmq);
    GNUNET_free (fmq);

    session = fm->session;
    GNUNET_assert (session != NULL);
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                     "Sending GNUNET_MESSAGE_TYPE_WLAN_FRAGMENT for fragment message %p, size: %u\n",
                     fm, fm->size);
    getRadiotapHeader (plugin, session->mac, fm->radioHeader);
    getWlanHeader (fm->ieeewlanheader, &(fm->session->mac->addr), plugin,
                   fm->size);

    bytes =
        GNUNET_DISK_file_write (plugin->server_stdin_handle, fm->frag,
                                fm->size);


    if (bytes != fm->size)
    {
      finish = GNUNET_malloc (sizeof (struct Finish_send));
      finish->plugin = plugin;
      finish->msgstart = (struct GNUNET_MessageHeader *) fm->frag;
      GNUNET_assert (plugin->server_write_task == GNUNET_SCHEDULER_NO_TASK);

      if (bytes == GNUNET_SYSERR)
      {
        GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, PLUGIN_LOG_NAME,
                         _
                         ("Error writing to wlan helper. errno == %d, ERROR: %s\n"),
                         errno, strerror (errno));

        finish->head_of_next_write = fm->frag;
        finish->size = fm->size;
        restart_helper (plugin, finish);
      }
      else
      {
        finish->head_of_next_write = fm->frag + bytes;
        finish->size = fm->size - bytes;
        plugin->server_write_task =
            GNUNET_SCHEDULER_add_write_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                             plugin->server_stdin_handle,
                                             &finish_sending, finish);
      }

      fm->frag = NULL;
    }
    else
    {
      GNUNET_free (fm->frag);
      fm->frag = NULL;
      set_next_send (plugin);
    }
    GNUNET_FRAGMENT_context_transmission_done (fm->fragcontext);
    return;
  }

#if 1
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                   "do_transmit did nothing, should not happen!\n");
#endif
  set_next_send (plugin);
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
  //struct Plugin *plugin = cls;

  /* check if the address is plausible; if so,
   * add it to our list! */

  GNUNET_assert (cls != NULL);
  //FIXME mitm is not checked
  //Mac Address has 6 bytes
  if (addrlen == 6)
  {
    /* TODO check for bad addresses like multicast, broadcast, etc */
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                     "wlan_plugin_address_suggested got good address, size %u!\n",
                     addrlen);
    return GNUNET_OK;
  }
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                   "wlan_plugin_address_suggested got bad address, size %u!\n",
                   addrlen);
  return GNUNET_SYSERR;
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
  struct Session * s = NULL;

  GNUNET_assert (plugin != NULL);
  GNUNET_assert (address != NULL);

  if (GNUNET_OK == wlan_plugin_address_suggested (plugin,
            address->address,
            address->address_length))
  {
    s = get_session (plugin, address->address, &address->peer);
  }
  else
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, PLUGIN_LOG_NAME,
                     _("Wlan Address len %d is wrong\n"), address->address_length);
    return s;
  }

  return s;
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
  struct PendingMessage *newmsg;
  struct WlanHeader *wlanheader;

  GNUNET_assert (plugin != NULL);
  GNUNET_assert (session != NULL);
  GNUNET_assert (msgbuf_size > 0);

  //queue message:

  //queue message in session
  //test if there is no other message in the "queue"
  //FIXME: to many send requests
  if (session->pending_message_head != NULL)
  {
    newmsg = session->pending_message_head;
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                     "wlan_plugin_send: a pending message is already in the queue for this client\n remaining time to send this message is %u, queued fragment messages for this mac connection %u\n",
                     GNUNET_TIME_absolute_get_remaining (newmsg->
                                                         timeout).rel_value,
                     session->mac->fragment_messages_out_count);
  }

  newmsg = GNUNET_malloc (sizeof (struct PendingMessage));
  newmsg->msg = GNUNET_malloc (msgbuf_size + sizeof (struct WlanHeader));
  wlanheader = newmsg->msg;
  //copy msg to buffer, not fragmented / segmented yet, but with message header
  wlanheader->header.size = htons (msgbuf_size + sizeof (struct WlanHeader));
  wlanheader->header.type = htons (GNUNET_MESSAGE_TYPE_WLAN_DATA);
  memcpy (&(wlanheader->target), &session->target, sizeof (struct GNUNET_PeerIdentity));
  memcpy (&(wlanheader->source), plugin->env->my_identity,
          sizeof (struct GNUNET_PeerIdentity));
  wlanheader->crc = 0;
  memcpy (&wlanheader[1], msgbuf, msgbuf_size);
  wlanheader->crc =
      htonl (GNUNET_CRYPTO_crc32_n
             ((char *) wlanheader, msgbuf_size + sizeof (struct WlanHeader)));

  newmsg->transmit_cont = cont;
  newmsg->transmit_cont_cls = cont_cls;
  newmsg->timeout = GNUNET_TIME_relative_to_absolute (to);

  newmsg->timeout.abs_value = newmsg->timeout.abs_value - 500;

  newmsg->message_size = msgbuf_size + sizeof (struct WlanHeader);

  GNUNET_CONTAINER_DLL_insert_tail (session->pending_message_head,
                                    session->pending_message_tail, newmsg);

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                   "New message for %p with size (incl wlan header) %u added\n",
                   session, newmsg->message_size);
#if DEBUG_WLAN > 1
  hexdump (msgbuf, GNUNET_MIN (msgbuf_size, 256));
#endif
  //queue session
  queue_session (plugin, session);

  check_fragment_queue (plugin);
  //FIXME not the correct size
  return msgbuf_size;
}


/**
 * function to free a mac endpoint
 * @param plugin pointer to the plugin struct
 * @param endpoint pointer to the MacEndpoint to free
 */
static void
free_macendpoint (struct Plugin *plugin, struct MacEndpoint *endpoint)
{
  struct Sessionqueue *sessions;
  struct Sessionqueue *sessions_next;

  GNUNET_assert (endpoint != NULL);

  sessions = endpoint->sessions_head;
  while (sessions != NULL)
  {
    sessions_next = sessions->next;
    free_session (plugin, sessions, GNUNET_NO);
    sessions = sessions_next;
  }

  GNUNET_CONTAINER_DLL_remove (plugin->mac_head, plugin->mac_tail, endpoint);
  if (endpoint->timeout_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (endpoint->timeout_task);
    endpoint->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  plugin->mac_count--;
  GNUNET_STATISTICS_set (plugin->env->stats, _("# wlan mac endpoints"),
                         plugin->mac_count, GNUNET_NO);
  GNUNET_free (endpoint);

}

/**
 * function to free a session
 * @param plugin pointer to the plugin
 * @param queue pointer to the sessionqueue element to free
 * @param do_free_macendpoint if GNUNET_YES and mac endpoint would be empty, free mac endpoint
 */
static void
free_session (struct Plugin *plugin, struct Sessionqueue *queue,
              int do_free_macendpoint)
{
  struct Sessionqueue *pendingsession;
  struct Sessionqueue *pendingsession_tmp;
  struct PendingMessage *pm;
  struct MacEndpoint *endpoint;
  struct FragmentMessage *fm;
  struct FragmentMessage *fmnext;
  int check = 0;

  GNUNET_assert (plugin != NULL);
  GNUNET_assert (queue != NULL);
  GNUNET_assert (queue->content != NULL);

  //session found
  //is this session pending for send
  pendingsession = plugin->pending_Sessions_head;
  while (pendingsession != NULL)
  {
    pendingsession_tmp = pendingsession;
    pendingsession = pendingsession->next;
    GNUNET_assert (pendingsession_tmp->content != NULL);
    if (pendingsession_tmp->content == queue->content)
    {
      plugin->pendingsessions--;
      GNUNET_STATISTICS_set (plugin->env->stats, _("# wlan pending sessions"),
                             plugin->pendingsessions, GNUNET_NO);
      GNUNET_CONTAINER_DLL_remove (plugin->pending_Sessions_head,
                                   plugin->pending_Sessions_tail,
                                   pendingsession_tmp);
      GNUNET_free (pendingsession_tmp);

      GNUNET_assert (check == 0);
      check = 1;
    }
  }

  endpoint = queue->content->mac;
  fm = endpoint->sending_messages_head;
  while (fm != NULL)
  {
    fmnext = fm->next;
    if (fm->session == queue->content)
    {
      free_fragment_message (plugin, fm);
    }
    fm = fmnext;
  }

  // remove PendingMessage
  pm = queue->content->pending_message_head;
  while (pm != NULL)
  {
    GNUNET_CONTAINER_DLL_remove (queue->content->pending_message_head,
                                 queue->content->pending_message_tail, pm);
    GNUNET_free (pm->msg);
    GNUNET_free (pm);
    pm = queue->content->pending_message_head;
  }

  GNUNET_CONTAINER_DLL_remove (endpoint->sessions_head, endpoint->sessions_tail,
                               queue);
  //Check that no ohter session on this endpoint for this session exits
  GNUNET_assert (search_session (plugin, endpoint, &queue->content->target) ==
                 NULL);
  if (endpoint->sessions_head == NULL && do_free_macendpoint == GNUNET_YES)
  {
    free_macendpoint (plugin, endpoint);
    //check if no endpoint with the same address exists
    GNUNET_assert (get_macendpoint (plugin, &endpoint->addr, GNUNET_NO) ==
                   NULL);
  }

  if (queue->content->timeout_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (queue->content->timeout_task);
    queue->content->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_free (queue);

  check_fragment_queue (plugin);
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
  struct Sessionqueue *queue;
  struct Sessionqueue *queue_next;
  struct MacEndpoint *endpoint = plugin->mac_head;
  struct MacEndpoint *endpoint_next;

  // just look at all the session for the needed one
  while (endpoint != NULL)
  {
    queue = endpoint->sessions_head;
    endpoint_next = endpoint->next;
    while (queue != NULL)
    {
      // content is never NULL
      GNUNET_assert (queue->content != NULL);
      queue_next = queue->next;
      if (memcmp
          (target, &(queue->content->target),
           sizeof (struct GNUNET_PeerIdentity)) == 0)
      {
        free_session (plugin, queue, GNUNET_YES);
      }
      // try next
      queue = queue_next;
    }
    endpoint = endpoint_next;
  }
}

/**
 * Convert the transports address to a nice, human-readable
 * format.
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
  char *ret;
  const unsigned char *input;

  //GNUNET_assert(cls !=NULL);
  if (addrlen != sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress))
  {
    /* invalid address (MAC addresses have 6 bytes) */
    //GNUNET_break (0);
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                     "Func wlan_plugin_address_pretty_printer got size: %u, worng size!\n",
                     addrlen);
    asc (asc_cls, NULL);
    return;
  }
  input = (const unsigned char *) addr;
  GNUNET_asprintf (&ret,
                   "Transport %s: %s Mac-Address %.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
                   type, PROTOCOL_PREFIX, input[0], input[1], input[2],
                   input[3], input[4], input[5]);
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                   "Func wlan_plugin_address_pretty_printer got size: %u, nummeric %u, type %s; made string: %s\n",
                   addrlen, numeric, type, ret);
  asc (asc_cls, ret);
  //only one mac address per plugin
  asc (asc_cls, NULL);
}



/**
 * handels the data after all fragments are put together
 * @param cls macendpoint this messages belongs to
 * @param hdr pointer to the data
 */
static void
wlan_data_message_handler (void *cls, const struct GNUNET_MessageHeader *hdr)
{
  struct MacEndpoint *endpoint = (struct MacEndpoint *) cls;
  struct Plugin *plugin = endpoint->plugin;
  struct WlanHeader *wlanheader;
  struct Session *session;

  const struct GNUNET_MessageHeader *temp_hdr;
  struct GNUNET_PeerIdentity tmpsource;
  int crc;

  GNUNET_assert (plugin != NULL);

  if (ntohs (hdr->type) == GNUNET_MESSAGE_TYPE_WLAN_DATA)
  {

    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                     "Func wlan_data_message_handler got GNUNET_MESSAGE_TYPE_WLAN_DATA size: %u\n",
                     ntohs (hdr->size));

    if (ntohs (hdr->size) <
        sizeof (struct WlanHeader) + sizeof (struct GNUNET_MessageHeader))
    {
      //packet not big enought
      return;
    }

    GNUNET_STATISTICS_update (plugin->env->stats,
                              _("# wlan whole messages received"), 1,
                              GNUNET_NO);
    wlanheader = (struct WlanHeader *) hdr;

    session = search_session (plugin, endpoint, &wlanheader->source);

    temp_hdr = (const struct GNUNET_MessageHeader *) &wlanheader[1];
    crc = ntohl (wlanheader->crc);
    wlanheader->crc = 0;
    if (GNUNET_CRYPTO_crc32_n
        ((char *) wlanheader, ntohs (wlanheader->header.size)) != crc)
    {
      //wrong crc, dispose message
      GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, PLUGIN_LOG_NAME,
                       "Wlan message header crc was wrong: %u != %u\n",
                       GNUNET_CRYPTO_crc32_n ((char *) wlanheader,
                                              ntohs (wlanheader->header.size)),
                       crc);
      hexdump ((void *) hdr, ntohs (hdr->size));
      return;
    }

    //if not in session list
    if (session == NULL)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                       "WLAN client not in session list: packet size = %u, inner size = %u, header size = %u\n",
                       ntohs (wlanheader->header.size), ntohs (temp_hdr->size),
                       sizeof (struct WlanHeader));
      //try if it is a hello message
      if (ntohs (wlanheader->header.size) >=
          ntohs (temp_hdr->size) + sizeof (struct WlanHeader))
      {
        if (ntohs (temp_hdr->type) == GNUNET_MESSAGE_TYPE_HELLO)
        {
          if (GNUNET_HELLO_get_id
              ((const struct GNUNET_HELLO_Message *) temp_hdr,
               &tmpsource) == GNUNET_OK)
          {
            session = create_session (plugin, endpoint, &tmpsource);
          }
          else
          {
            GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, PLUGIN_LOG_NAME,
                             "WLAN client not in session list and hello message is not okay\n");
            return;
          }

        }
        else
        {
          GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, PLUGIN_LOG_NAME,
                           "WLAN client not in session list and not a hello message\n");
          return;
        }
      }
      else
      {
        GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, PLUGIN_LOG_NAME,
                         "WLAN client not in session list and message size in does not fit\npacket size = %u, inner size = %u, header size = %u\n",
                         ntohs (wlanheader->header.size),
                         ntohs (temp_hdr->size), sizeof (struct WlanHeader));
        return;
      }
    }

    //"receive" the message

    if (memcmp
        (&wlanheader->source, &session->target,
         sizeof (struct GNUNET_PeerIdentity)) != 0)
    {
      //wrong peer id
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                       "WLAN peer source id doesn't match packet peer source id: session %p\n",
                       session);
      return;
    }

    if (memcmp
        (&wlanheader->target, plugin->env->my_identity,
         sizeof (struct GNUNET_PeerIdentity)) != 0)
    {
      //wrong peer id
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                       "WLAN peer target id doesn't match our peer id: session %p\n",
                       session);
      return;
    }

    GNUNET_SERVER_mst_receive (plugin->data_tokenizer, session,
                               (const char *) temp_hdr,
                               ntohs (hdr->size) - sizeof (struct WlanHeader),
                               GNUNET_YES, GNUNET_NO);

    return;
  }
  else
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, PLUGIN_LOG_NAME,
                     "wlan_data_message_handler got wrong message type: %u\n",
                     ntohs (hdr->size));
    return;
  }
}

/**
 * function to process the a message, give it to the higher layer
 * @param cls pointer to the plugin
 * @param client pointer to the session this message belongs to
 * @param hdr start of the message
 */
//TODO ATS informations
static void
process_data (void *cls, void *client, const struct GNUNET_MessageHeader *hdr)
{

  GNUNET_assert (client != NULL);
  GNUNET_assert (cls != NULL);
  struct Session *session = (struct Session *) client;
  struct Plugin *plugin = (struct Plugin *) cls;
  struct GNUNET_ATS_Information ats[2];

  ats[0].type = htonl (GNUNET_ATS_QUALITY_NET_DISTANCE);
  ats[0].value = htonl (1);
  ats[1].type = htonl (GNUNET_ATS_NETWORK_TYPE);
  ats[1].value = htonl (GNUNET_ATS_NET_WLAN);

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                   "Calling plugin->env->receive for session %p; %s; size: %u\n",
                   session, wlan_plugin_address_to_string (NULL,
                                                           session->mac->
                                                           addr.mac, 6),
                   htons (hdr->size));
  plugin->env->receive (plugin->env->cls, &(session->target), hdr,
                        (const struct GNUNET_ATS_Information *) &ats, 2,
                        session, (const char *) &session->mac->addr,
                        sizeof (session->mac->addr));
}

/**
 * Function used for to process the data received from the wlan interface
 *
 * @param cls the plugin handle
 * @param session_light pointer to the struct holding known informations
 * @param hdr hdr of the GNUNET_MessageHeader
 * @param rxinfo pointer to the radiotap informations got with this packet FIXME: give ATS for info
 */
static void
wlan_data_helper (void *cls, struct Session_light *session_light,
                  const struct GNUNET_MessageHeader *hdr,
                  const struct Radiotap_rx *rxinfo)
{
  struct Plugin *plugin = cls;
  struct FragmentMessage *fm;
  struct FragmentMessage *fm2;
  struct GNUNET_PeerIdentity tmpsource;

  GNUNET_assert (plugin != NULL);

  //ADVERTISEMENT
  if (ntohs (hdr->type) == GNUNET_MESSAGE_TYPE_HELLO)
  {

    //TODO better DOS protection, error handling
    //TODO test first than create session
    GNUNET_assert (session_light != NULL);

    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                     "Func wlan_data_helper got GNUNET_MESSAGE_TYPE_HELLO size: %u; %s\n",
                     ntohs (hdr->size), wlan_plugin_address_to_string (NULL,
                                                                       session_light->addr.
                                                                       mac, 6));
    if (session_light->macendpoint == NULL)
    {
      session_light->macendpoint =
          get_macendpoint (plugin, &session_light->addr, GNUNET_YES);
    }


    if (GNUNET_HELLO_get_id
        ((const struct GNUNET_HELLO_Message *) hdr, &tmpsource) == GNUNET_OK)
    {
      session_light->session =
          search_session (plugin, session_light->macendpoint, &tmpsource);
      if (session_light->session == NULL)
      {
        session_light->session =
            create_session (plugin, session_light->macendpoint, &tmpsource);
      }
      GNUNET_STATISTICS_update (plugin->env->stats,
                                _("# wlan hello messages received"), 1,
                                GNUNET_NO);
      plugin->env->receive (plugin->env->cls, &session_light->session->target,
                            hdr, NULL, 0, session_light->session,
                            (const char *) &session_light->session->mac->addr,
                            sizeof (session_light->session->mac->addr));
    }
    else
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, PLUGIN_LOG_NAME,
                       "WLAN client not in session list and hello message is not okay\n");
      return;
    }
  }

  //FRAGMENT

  else if (ntohs (hdr->type) == GNUNET_MESSAGE_TYPE_FRAGMENT)
  {

    GNUNET_assert (session_light != NULL);
    if (session_light->macendpoint == NULL)
    {
      session_light->macendpoint =
          get_macendpoint (plugin, &session_light->addr, GNUNET_YES);
    }

    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                     "Func wlan_data_helper got GNUNET_MESSAGE_TYPE_FRAGMENT with size: %u; mac endpoint %p: %s\n",
                     ntohs (hdr->size), session_light->macendpoint,
                     wlan_plugin_address_to_string (NULL,
                                                    session_light->addr.mac,
                                                    6));
    GNUNET_STATISTICS_update (plugin->env->stats,
                              _("# wlan fragments received"), 1, GNUNET_NO);
    int ret =
        GNUNET_DEFRAGMENT_process_fragment (session_light->macendpoint->defrag,
                                            hdr);

    if (ret == GNUNET_NO)
    {
      session_light->macendpoint->dups++;
    }
    else if (ret == GNUNET_OK)
    {
      session_light->macendpoint->fragc++;
    }
    set_next_send (plugin);

  }

  //ACK

  else if (ntohs (hdr->type) == GNUNET_MESSAGE_TYPE_FRAGMENT_ACK)
  {
    GNUNET_assert (session_light != NULL);
    if (session_light->macendpoint == NULL)
    {
      session_light->macendpoint =
          get_macendpoint (plugin, &session_light->addr, GNUNET_NO);
    }

    if (session_light->macendpoint == NULL)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                       "Macendpoint does not exist for this GNUNET_MESSAGE_TYPE_FRAGMENT_ACK size: %u; %s\n",
                       ntohs (hdr->size), wlan_plugin_address_to_string (NULL,
                                                                         session_light->addr.mac,
                                                                         6));
      return;
    }

    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                     "Func wlan_data_helper got GNUNET_MESSAGE_TYPE_FRAGMENT_ACK size: %u; mac endpoint: %p; %s\n",
                     ntohs (hdr->size), session_light->macendpoint,
                     wlan_plugin_address_to_string (NULL,
                                                    session_light->addr.mac,
                                                    6));
    fm = session_light->macendpoint->sending_messages_head;
    while (fm != NULL)
    {
      fm2 = fm->next;
      GNUNET_STATISTICS_update (plugin->env->stats, _("# wlan acks received"),
                                1, GNUNET_NO);
      int ret = GNUNET_FRAGMENT_process_ack (fm->fragcontext, hdr);

      if (ret == GNUNET_OK)
      {
        GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                         "Got last ack, finished fragment message %p\n", fm);
        session_light->macendpoint->acks++;
        fm->session->last_activity = GNUNET_TIME_absolute_get ();
        session_light->macendpoint->last_activity = fm->session->last_activity;
        free_fragment_message (plugin, fm);
        check_fragment_queue (plugin);
        return;
      }
      if (ret == GNUNET_NO)
      {
        GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                         "Got ack for: %p\n", fm);
        session_light->macendpoint->acks++;
        return;
      }
      if (ret == GNUNET_SYSERR)
      {

      }

      fm = fm2;
    }

    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                     "WLAN fragment not in fragment list\n");
    return;

  }
  else
  {
    // TODO Wrong data?
    GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, PLUGIN_LOG_NAME,
                     "WLAN packet inside the WLAN helper packet has not the right type: %u size: %u\n",
                     ntohs (hdr->type), ntohs (hdr->size));
    GNUNET_break (0);
    return;
  }

#if 0
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                   "Helper finished\n");
#endif

}

/**
 * Function to print mac addresses nice *
 * @param pointer to 6 byte with the mac address
 * @return pointer to the chars which hold the print out
 */
static const char *
macprinter (const u_int8_t * mac)
{
  static char macstr[20];

  GNUNET_snprintf (macstr, sizeof (macstr), "%X:%X:%X:%X:%X:%X", mac[0], mac[1],
                   mac[2], mac[3], mac[4], mac[5]);
  return macstr;
}

/**
 * Function for the scheduler if a mac endpoint times out
 * @param cls pointer to the MacEndpoint
 * @param tc pointer to the GNUNET_SCHEDULER_TaskContext
 */
static void
macendpoint_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MacEndpoint *endpoint = cls;

  GNUNET_assert (endpoint != NULL);
  endpoint->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  if (tc->reason == GNUNET_SCHEDULER_REASON_SHUTDOWN)
  {
    return;
  }
  if (GNUNET_TIME_absolute_get_remaining
      (GNUNET_TIME_absolute_add
       (endpoint->last_activity, MACENDPOINT_TIMEOUT)).rel_value == 0)
  {
    GNUNET_assert (endpoint->plugin != NULL);
    GNUNET_STATISTICS_update (endpoint->plugin->env->stats,
                              _("# wlan mac endpoints timeouts"), 1, GNUNET_NO);
    free_macendpoint (endpoint->plugin, endpoint);
  }
  else
  {
    endpoint->timeout_task =
        GNUNET_SCHEDULER_add_delayed (MACENDPOINT_TIMEOUT, &macendpoint_timeout,
                                      endpoint);
  }
}

/**
 * function to create an macendpoint
 * @param plugin pointer to the plugin struct
 * @param addr pointer to the macaddress
 * @return returns a macendpoint
 */
static struct MacEndpoint *
create_macendpoint (struct Plugin *plugin, const struct GNUNET_TRANSPORT_WLAN_MacAddress *addr)
{
  struct MacEndpoint *newend = GNUNET_malloc (sizeof (struct MacEndpoint));

  GNUNET_assert (plugin != NULL);
  GNUNET_STATISTICS_update (plugin->env->stats,
                            _("# wlan mac endpoints created"), 1, GNUNET_NO);
  newend->addr = *addr;
  newend->plugin = plugin;
  newend->addr = *addr;
  newend->fragment_messages_out_count = 0;
  newend->defrag =
      GNUNET_DEFRAGMENT_context_create (plugin->env->stats, WLAN_MTU,
                                        MESSAGES_IN_DEFRAG_QUEUE_PER_MAC,
                                        newend, &wlan_data_message_handler,
                                        &add_ack_for_send);
  newend->last_activity = GNUNET_TIME_absolute_get ();
  newend->timeout_task =
      GNUNET_SCHEDULER_add_delayed (MACENDPOINT_TIMEOUT, &macendpoint_timeout,
                                    newend);

  plugin->mac_count++;
  GNUNET_STATISTICS_set (plugin->env->stats, _("# wlan mac endpoints"),
                         plugin->mac_count, GNUNET_NO);
  GNUNET_CONTAINER_DLL_insert_tail (plugin->mac_head, plugin->mac_tail, newend);
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                   "New Mac Endpoint %p: %s\n", newend,
                   wlan_plugin_address_to_string (NULL, newend->addr.mac, 6));
  return newend;
}

/**
 * Function used for to process the data from the suid process
 *
 * @param cls the plugin handle
 * @param client client that send the data (not used)
 * @param hdr header of the GNUNET_MessageHeader
 */
static void
wlan_process_helper (void *cls, void *client,
                     const struct GNUNET_MessageHeader *hdr)
{
  struct Plugin *plugin = cls;
  struct ieee80211_frame *wlanIeeeHeader = NULL;
  struct Session_light *session_light = NULL;
  struct Radiotap_rx *rxinfo;
  const struct GNUNET_MessageHeader *temp_hdr = NULL;

  int datasize = 0;
  int pos;

  GNUNET_assert (plugin != NULL);
  switch (ntohs (hdr->type))
  {
  case GNUNET_MESSAGE_TYPE_WLAN_HELPER_DATA:
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                     "Func wlan_process_helper got GNUNET_MESSAGE_TYPE_WLAN_HELPER_DATA size: %u\n",
                     ntohs (hdr->size));
    GNUNET_STATISTICS_update (plugin->env->stats,
                              _("# wlan WLAN_HELPER_DATA received"), 1,
                              GNUNET_NO);
    //call wlan_process_helper with the message inside, later with wlan: analyze signal
    if (ntohs (hdr->size) <
        sizeof (struct ieee80211_frame) +
        2 * sizeof (struct GNUNET_MessageHeader) + sizeof (struct Radiotap_rx))
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                       "Size of packet is too small; size: %u min size: %u\n",
                       ntohs (hdr->size),
                       sizeof (struct ieee80211_frame) +
                       sizeof (struct GNUNET_MessageHeader));
      //GNUNET_break (0);
      /* FIXME: restart SUID process */
      return;
    }

    rxinfo = (struct Radiotap_rx *) &hdr[1];
    wlanIeeeHeader = (struct ieee80211_frame *) &rxinfo[1];

    //process only if it is an broadcast or for this computer both with the gnunet bssid

    //check for bssid
    if (memcmp
        (&(wlanIeeeHeader->i_addr3), &mac_bssid_gnunet,
         sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress)) == 0)
    {
      //check for broadcast or mac
      if ((memcmp
           (&(wlanIeeeHeader->i_addr1), &bc_all_mac,
            sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress)) == 0) ||
          (memcmp
           (&(wlanIeeeHeader->i_addr1), &(plugin->mac_address),
            sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress)) == 0))
      {
        //if packet is from us return
        if ((memcmp
             (&(wlanIeeeHeader->i_addr2), &(plugin->mac_address),
              sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress)) == 0))
        {
          return;
        }
        // process the inner data


        datasize =
            ntohs (hdr->size) - sizeof (struct ieee80211_frame) -
            sizeof (struct GNUNET_MessageHeader) - sizeof (struct Radiotap_rx);

        session_light = GNUNET_malloc (sizeof (struct Session_light));
        memcpy (&session_light->addr, &(wlanIeeeHeader->i_addr2),
                sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress));
        //session_light->session = search_session(plugin,session_light->addr);
        GNUNET_STATISTICS_update (plugin->env->stats,
                                  _("# wlan messages for this client received"),
                                  1, GNUNET_NO);

        pos = 0;
        while (pos < datasize)
        {
          temp_hdr = (struct GNUNET_MessageHeader *) &wlanIeeeHeader[1] + pos;
          if (ntohs (temp_hdr->size) <= datasize + pos)
          {
            GNUNET_STATISTICS_update (plugin->env->stats,
                                      _
                                      ("# wlan messages inside WLAN_HELPER_DATA received"),
                                      1, GNUNET_NO);
            wlan_data_helper (plugin, session_light, temp_hdr, rxinfo);
          }
          else
          {
            GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                             "Size of packet is too small; size: %u > size of packet: %u\n",
                             ntohs (temp_hdr->size), datasize + pos);
          }
          pos += ntohs (temp_hdr->size);

        }

        //clean up
        GNUNET_free (session_light);
      }
      else
      {
        GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                         "Func wlan_process_helper got wrong MAC: %s\n",
                         macprinter (wlanIeeeHeader->i_addr1));
      }
    }
    else
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                       "Func wlan_process_helper got wrong BSSID: %s\n",
                       macprinter (wlanIeeeHeader->i_addr2));
    }
    break;
  case GNUNET_MESSAGE_TYPE_WLAN_HELPER_CONTROL:
    //TODO more control messages
    if (ntohs (hdr->size) != sizeof (struct GNUNET_TRANSPORT_WLAN_HelperControlMessage))
    {
      GNUNET_break (0);
      /* FIXME: restart SUID process */
      return;
    }
    memcpy (&plugin->mac_address, &hdr[1], sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress));
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                     "Received WLAN_HELPER_CONTROL message with transport of address %s\n",
                     wlan_plugin_address_to_string (cls, &plugin->mac_address,
                                                    sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress)));
    plugin->env->notify_address (plugin->env->cls, GNUNET_YES,
                                 &plugin->mac_address,
                                 sizeof (struct GNUNET_TRANSPORT_WLAN_MacAddress));
    break;
  default:
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                     "Func wlan_process_helper got unknown message with number %u, size %u\n",
                     ntohs (hdr->type), ntohs (hdr->size));

#if DEBUG_WLAN > 1
    hexdump (hdr, GNUNET_MIN (ntohs (hdr->size), 256));
#endif
    GNUNET_break (0);
    return;
  }
}

/**
 * Exit point from the plugin.
 * @param cls pointer to the api struct
 */

//FIXME cleanup
void *
libgnunet_plugin_transport_wlan_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;
  struct MacEndpoint *endpoint = plugin->mac_head;
  struct MacEndpoint *endpoint_next;

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                   "libgnunet_plugin_transport_wlan_done started\n");
  wlan_transport_stop_wlan_helper (plugin);

  GNUNET_assert (cls != NULL);
  //free sessions
  while (endpoint != NULL)
  {
    endpoint_next = endpoint->next;
    free_macendpoint (plugin, endpoint);
    endpoint = endpoint_next;

  }


  if (plugin->suid_tokenizer != NULL)
    GNUNET_SERVER_mst_destroy (plugin->suid_tokenizer);

  if (plugin->data_tokenizer != NULL)
    GNUNET_SERVER_mst_destroy (plugin->data_tokenizer);

  GNUNET_free_non_null (plugin->interface);
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
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
  //struct GNUNET_SERVICE_Context *service;
  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  struct Plugin *plugin;

  GNUNET_assert (cls != NULL);

  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->env = env;
  plugin->pendingsessions = 0;
  GNUNET_STATISTICS_set (plugin->env->stats, _("# wlan pending sessions"),
                         plugin->pendingsessions, GNUNET_NO);
  plugin->mac_count = 0;
  GNUNET_STATISTICS_set (plugin->env->stats, _("# wlan mac endpoints"),
                         plugin->mac_count, GNUNET_NO);
  plugin->server_write_task = GNUNET_SCHEDULER_NO_TASK;
  plugin->server_read_task = GNUNET_SCHEDULER_NO_TASK;
  plugin->server_write_delay_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_BANDWIDTH_tracker_init (&plugin->tracker,
                                 GNUNET_BANDWIDTH_value_init (100 * 1024 *
                                                              1024 / 8), 100);

  plugin->suid_tokenizer =
      GNUNET_SERVER_mst_create (&wlan_process_helper, plugin);

  plugin->data_tokenizer = GNUNET_SERVER_mst_create (&process_data, plugin);

  //plugin->sessions = GNUNET_malloc (sizeof (struct Sessionqueue));
  //plugin->pending_Sessions_head = GNUNET_malloc (sizeof (struct Sessionqueue));

  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
  api->cls = plugin;
  api->send = &wlan_plugin_send;
  api->get_session = &wlan_plugin_get_session;
  api->disconnect = &wlan_plugin_disconnect;
  api->address_pretty_printer = &wlan_plugin_address_pretty_printer;
  api->check_address = &wlan_plugin_address_suggested;
  api->address_to_string = &wlan_plugin_address_to_string;

  //read config

  if (GNUNET_CONFIGURATION_have_value (env->cfg, "transport-wlan", "TESTMODE"))
  {
    if (GNUNET_SYSERR ==
        GNUNET_CONFIGURATION_get_value_number (env->cfg, "transport-wlan",
                                               "TESTMODE", &(plugin->testmode)))
      plugin->testmode = 0;     //default value
  }

  if (GNUNET_CONFIGURATION_have_value (env->cfg, "transport-wlan", "INTERFACE"))
  {
    if (GNUNET_CONFIGURATION_get_value_string
        (env->cfg, "transport-wlan", "INTERFACE",
         &(plugin->interface)) != GNUNET_YES)
    {
      libgnunet_plugin_transport_wlan_done (api);
      return NULL;
    }
  }

  //start the plugin
  wlan_transport_start_wlan_helper (plugin);
  set_next_beacon_time (plugin);
  set_next_send (plugin);
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, PLUGIN_LOG_NAME,
                   "wlan init finished\n");
  return api;
}

/* end of plugin_transport_wlan.c */
