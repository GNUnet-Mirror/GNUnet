/*
 This file is part of GNUnet
 (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009 Christian Grothoff (and other contributing authors)

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
#include "wlan/ieee80211.h"

#include <string.h>

#define PROTOCOL_PREFIX "wlan"

/**
 * Max size of packet from helper
 */
#define WLAN_MTU 3000

/**
 * Time until retransmission of a fragment in ms
 */
#define FRAGMENT_TIMEOUT GNUNET_TIME_UNIT_SECONDS

#define FRAGMENT_QUEUE_SIZE 10
#define FRAGMENT_QUEUE_MESSAGES_OUT_PER_SESSION 1

#define MESSAGE_IN_TIMEOUT GNUNET_TIME_UNIT_SECONDS

#define MESSAGES_IN_QUEUE_SIZE 10
#define MESSAGES_IN_QUEUE_PER_SESSION 1

#define HALLO_BEACON_SCALING_FACTOR 900

#define DEBUG_wlan GNUNET_YES
#define DEBUG_wlan_retransmission GNUNET_NO

#define MESSAGE_LENGHT_UNKNOWN -1
//#define NO_MESSAGE_OR_MESSAGE_FINISHED -2

/**
 * After how long do we expire an address that we
 * learned from another peer if it is not reconfirmed
 * by anyone?
 */
#define LEARNED_ADDRESS_EXPIRATION GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 6)

/**
 * Initial handshake message for a session.
 */
struct WelcomeMessage
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_WELCOME.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Identit*mac_y of the node connecting (TCP client)
   */
  struct GNUNET_PeerIdentity clientIdentity;

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
   * List of open sessions. head
   */
  struct Sessionqueue *sessions;

  /**
   * List of open sessions. tail
   */
  struct Sessionqueue *sessions_tail;

  /**
   * Number of sessions
   */
  unsigned int session_count;

  /**
   * encapsulation of data from the local wlan helper program
   */
  struct GNUNET_SERVER_MessageStreamTokenizer * suid_tokenizer;

  /**
   * encapsulation of packets received from the wlan helper
   */
  struct GNUNET_SERVER_MessageStreamTokenizer * data_tokenizer;
  /**
   * encapsulation of packets received
   */
  struct GNUNET_SERVER_MessageStreamTokenizer * fragment_tokenizer;

  /**
   * stdout pipe handle for the gnunet-wlan-helper process
   */
  struct GNUNET_DISK_PipeHandle *server_stdout;

  /**
   * stdout file handle for the gnunet-wlan-helper process
   */
  const struct GNUNET_DISK_FileHandle *server_stdout_handle;

  /**
   * stdin pipe handle for the gnunet-wlan-helper process
   */
  struct GNUNET_DISK_PipeHandle *server_stdin;

  /**
   * stdin file handle for the gnunet-wlan-helper process
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
   * The mac_address of the wlan card given to us by the helper.
   */
  struct MacAddress mac_address;

  /**
   * Sessions currently pending for transmission
   * to this peer, if any.
   */
  struct Sessionqueue * pending_Sessions_head;

  /**
   * Sessions currently pending for transmission
   * to this peer (tail), if any.
   */
  struct Sessionqueue * pending_Sessions_tail;

  /**
   * number of pending sessions
   */
  unsigned int pendingsessions;

  /**
   * Messages in the fragmentation queue, head
   */
  struct GNUNET_CONTAINER_Heap * pending_Fragment_Messages;

  /**
   * Messages in the in Queue, head
   */
  struct Receive_Message_Queue * receive_messages_head;

  /**
   * Messages in the in Queue, tail
   */
  struct Receive_Message_Queue * receive_messages_teil;

  /**
   * number of messages in the in queue
   */
  unsigned int pending_receive_messages;

  /**
   * time of the next "hello-beacon"
   */
  struct GNUNET_TIME_Absolute beacon_time;

  /**
   * queue to send acks for received fragments (head)
   */
  struct AckSendQueue * ack_send_queue_head;

  /**
   * queue to send acks for received fragments (tail)
   */
  struct AckSendQueue * ack_send_queue_tail;

};

/**
 * Struct to store data if file write did not accept the whole packet
 */
struct Finish_send
{
  struct Plugin * plugin;
  char * msgheader;
  struct GNUNET_MessageHeader * msgstart;
  ssize_t size;
};

/**
 * Queue of sessions, for the general session queue and the pending session queue
 */
//TODO DOXIGEN
struct Sessionqueue
{
  struct Sessionqueue * next;
  struct Sessionqueue * prev;
  struct Session * content;
};

/**
 * Queue for the fragments received
 */
//TODO DOXIGEN
struct Receive_Fragment_Queue
{
  struct Receive_Fragment_Queue * next;
  struct Receive_Fragment_Queue * prev;
  uint16_t num;
  const char * msg;
  uint16_t size;
  struct Radiotap_rx rxinfo;
};

//TODO DOXIGEN
struct Session_id_fragment_triple
{
  struct Session * session;
  uint32_t message_id;
  struct FragmentMessage * fm;
};

//TODO DOXIGEN
struct Plugin_Session_pair
{
  struct Plugin * plugin;
  struct Session * session;
};

/**
 * Queue for the fragments received
 */
struct Receive_Message_Queue
{
  struct Receive_Message_Queue * next;

  struct Receive_Message_Queue * prev;

  /**
   * current number for message incoming, to distinguish between the messages
   */
  uint32_t message_id_in;

  /**
   * size of the message received,
   * MESSAGE_LENGHT_UNKNOWN means that the size is not known,
   * NO_MESSAGE_OR_MESSAGE_FINISHED means no message received
   */
  int rec_size;

  /**
   * Sorted queue with the fragments received; head
   */

  struct Receive_Fragment_Queue * frag_head;

  /**
   * Sorted queue with the fragments received; tail
   */

  struct Receive_Fragment_Queue * frag_tail;

  /**
   * Session this fragment belongs to
   */

  struct Session * session;

  /**
   * Timeout value for the pending message.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Bitfield of received fragments
   */

  uint64_t received_fragments;
};

/**
 * Information kept for each message that is yet to
 * be transmitted.
 */
struct PendingMessage
{

  /**
   * The pending message
   */
  char *msg;

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
  void * transmit_cont_cls;

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
  struct AckSendQueue * next;
  /**
   * previous ack in the ack send queue
   */
  struct AckSendQueue * prev;
  /**
   * pointer to the session this ack belongs to
   */
  struct Session * session;
  /**
   * ID of message, to distinguish between the messages, picked randomly.
   */
  uint32_t message_id;

  /**
   * Bit field for received fragments
   */
  uint64_t fragments_field;

};

/**
 * Session infos gathered from a messages
 */

struct Session_light
{
  /**
   * the session this message belongs to
   */
  struct Session * session;
  /**
   * peer mac address
   */
  struct MacAddress addr;
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
   * Pointer to the global plugin struct.
   */
  struct Plugin *plugin;

  /**
   * Message currently pending for transmission
   * to this peer, if any.
   */
  struct PendingMessage *pending_message;

  /**
   * Message currently pending for transmission
   * to this peer, if any.
   */
  struct PendingMessage *pending_message2;

  /**
   * To whom are we talking to (set to our identity
   * if we are still waiting for the welcome message)
   */
  struct GNUNET_PeerIdentity target;

  /**
   * peer mac address
   */
  struct MacAddress addr;

  /**
   * Address of the other peer (either based on our 'connect'
   * call or on our 'accept' call).
   */
  void *connect_addr;

  /**
   * Last activity on this connection.  Used to select preferred
   * connection.
   */
  struct GNUNET_TIME_Absolute last_activity;

  /**
   * count of messages in the fragment out queue for this session
   */

  int fragment_messages_out_count;

  /**
   * count of messages in the fragment in queue for this session
   */

  int fragment_messages_in_count;

  //TODO DOXIGEN
  uint8_t rate;
  uint16_t tx_power;
  uint8_t antenna;

};

/**
 * Struct for Messages in the fragment queue
 */

struct FragmentMessage
{
  /**
   * heap pointer of this message
   */
  struct GNUNET_CONTAINER_HeapNode * node;

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
   * The pending message
   */
  char *msg;

  /**
   * 0 if not in ack queue
   * 1 if in ack queue
   */

  char in_ack_queue;

  /**
   * Timeout value for the pending message.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Timeout value for the pending fragments.
   * Stores the time when the next msg fragment ack has to be received
   */
  struct GNUNET_TIME_Absolute next_ack;

  /**
   * bitfield with all acks received for this message
   */
  uint64_t ack_bitfield;

  /**
   * Size of the message
   */
  size_t message_size;

  /**
   * pos / next fragment number in the message, for fragmentation/segmentation,
   * some acks can be missing but there is still time
   */
  uint32_t message_pos;

  /**
   * current number for message outgoing, to distinguish between the messages
   */
  uint32_t message_id_out;
};

/**
 * Header for messages which need fragmentation
 */
struct FragmentationAckHeader
{

  struct GNUNET_MessageHeader header;

  /**
   * ID of message, to distinguish between the messages, picked randomly.
   */
  uint32_t message_id GNUNET_PACKED;

  /**
   * Offset or number of this fragment, for fragmentation/segmentation (design choice, TBD)
   */
  uint64_t fragment_field GNUNET_PACKED;

};

static void
do_transmit(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

/**
 * Sets a bit active in the bitArray. Increment bit-specific
 * usage counter on disk only if below 4bit max (==15).
 *
 * @param bitArray memory area to set the bit in
 * @param bitIdx which bit to set
 */
static void
setBit(char *bitArray, unsigned int bitIdx)
{
  size_t arraySlot;
  unsigned int targetBit;

  arraySlot = bitIdx / 8;
  targetBit = (1L << (bitIdx % 8));
  bitArray[arraySlot] |= targetBit;
}

/**
 * Checks if a bit is active in the bitArray
 *
 * @param bitArray memory area to set the bit in
 * @param bitIdx which bit to test
 * @return GNUNET_YES if the bit is set, GNUNET_NO if not.
 */
static int
testBit(char *bitArray, unsigned int bitIdx)
{
  size_t slot;
  unsigned int targetBit;

  slot = bitIdx / 8;
  targetBit = (1L << (bitIdx % 8));
  if (bitArray[slot] & targetBit)
    return GNUNET_YES;
  return GNUNET_NO;
}

/**
 * get the next message number, at the moment just a random one
 * @return returns the next valid message-number for sending packets
 */
static uint32_t
get_next_message_id()
{
  return GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_NONCE, UINT32_MAX);
}

/**
 * search for a session with the addr
 *
 * @param plugin pointer to the plugin struct
 * @param addr pointer to the mac address of the peer
 * @return returns the session
 */
static struct Session *
search_session(struct Plugin *plugin, const struct MacAddress *addr)
{
  struct Sessionqueue * queue = plugin->sessions;

  while (queue != NULL)
    {
      GNUNET_assert (queue->content != NULL);
      if (memcmp(addr, &queue->content->addr, sizeof(struct MacAddress)) == 0)
        return queue->content; /* session found */
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
static const char*
wlan_plugin_address_to_string(void *cls, const void *addr, size_t addrlen)
{
  static char ret[40];
  const struct MacAddress *mac;

  if (addrlen != sizeof(struct MacAddress))
    {
      GNUNET_break (0);
      return NULL;
    }
  mac = addr;
  GNUNET_snprintf(ret, sizeof(ret), "%s Mac-Address %X:%X:%X:%X:%X:%X",
      PROTOCOL_PREFIX, mac->mac[0], mac->mac[1], mac->mac[2], mac->mac[3],
      mac->mac[4], mac->mac[5]);
  return ret;
}

/**
 * create a new session
 *
 * @param plugin pointer to the plugin struct
 * @param addr pointer to the mac address of the peer
 * @return returns the session
 */

static struct Session *
create_session(struct Plugin *plugin, const struct MacAddress * addr)
{
  struct Sessionqueue * queue = GNUNET_malloc (sizeof (struct Sessionqueue));

  GNUNET_CONTAINER_DLL_insert_tail(plugin->sessions, plugin->sessions_tail, queue);

  queue->content = GNUNET_malloc (sizeof (struct Session));
  queue->content->plugin = plugin;
  queue->content->addr = *addr;
  queue->content->fragment_messages_out_count = 0;
  queue->content->fragment_messages_in_count = 0;

  plugin->session_count++;

#if DEBUG_wlan
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "New session %p with %s\n",
      queue->content, wlan_plugin_address_to_string(NULL, addr, 6));
#endif

  return queue->content;
}

/**
 * Get session from address, create if no session exists
 *
 * @param plugin pointer to the plugin struct
 * @param addr pointer to the mac address of the peer
 * @return returns the session
 */
static struct Session *
get_session(struct Plugin *plugin, const struct MacAddress *addr)
{
  struct Session * session = search_session(plugin, addr);
  if (session != NULL)
    return session;
  return create_session(plugin, addr);
}

/**
 * Queue the session to send data
 * checks if there is a message pending
 * checks if this session is not allready in the queue
 * @param plugin pointer to the plugin
 * @param session pointer to the session to add
 */
static void
queue_session(struct Plugin *plugin, struct Session * session)
{
  struct Sessionqueue * queue = plugin->pending_Sessions_head;

  if (session->pending_message != NULL)
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
      GNUNET_CONTAINER_DLL_insert_tail(plugin->pending_Sessions_head,
          plugin->pending_Sessions_tail, queue);
      plugin->pendingsessions++;
    }

}

/**
 * Function to schedule the write task, executed after a delay
 * @param cls pointer to the plugin struct
 * @param tc GNUNET_SCHEDULER_TaskContext pointer
 */
static void
delay_fragment_task(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin * plugin = cls;
  plugin->server_write_delay_task = GNUNET_SCHEDULER_NO_TASK;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  // GNUNET_TIME_UNIT_FOREVER_REL is needed to clean up old msg
  if (plugin->server_write_task == GNUNET_SCHEDULER_NO_TASK)
    {
      plugin->server_write_task = GNUNET_SCHEDULER_add_write_file(
          GNUNET_TIME_UNIT_FOREVER_REL, plugin->server_stdin_handle,
          &do_transmit, plugin);
    }
}

/**
 * Function to calculate the time of the next periodic "hello-beacon"
 * @param plugin pointer to the plugin struct
 */

static void
set_next_beacon_time(struct Plugin * const plugin)
{
  //under 10 known peers: once a second
  if (plugin->session_count < 10)
    {
      plugin->beacon_time = GNUNET_TIME_absolute_add(
          GNUNET_TIME_absolute_get(), GNUNET_TIME_relative_multiply(
              GNUNET_TIME_UNIT_SECONDS, HALLO_BEACON_SCALING_FACTOR));
    }
  //under 30 known peers: every 10 seconds
  else if (plugin->session_count < 30)
    {
      plugin->beacon_time = GNUNET_TIME_absolute_add(
          GNUNET_TIME_absolute_get(), GNUNET_TIME_relative_multiply(
              GNUNET_TIME_UNIT_SECONDS, 10 * HALLO_BEACON_SCALING_FACTOR));
    }
  //over 30 known peers: once a minute
  else
    {
      plugin->beacon_time = GNUNET_TIME_absolute_add(
          GNUNET_TIME_absolute_get(), GNUNET_TIME_relative_multiply(
              GNUNET_TIME_UNIT_MINUTES, HALLO_BEACON_SCALING_FACTOR));
    }
}

/**
 * Function to get the timeout value for acks for this session
 * @param fm pointer to the FragmentMessage to get the next timeout
 * @return time until the next ack should be received, in GNUNET_TIME_Relative
 */
static struct GNUNET_TIME_Relative
get_ack_timeout(struct FragmentMessage * fm)
{
  return FRAGMENT_TIMEOUT;
}

/**
 * Function to set the timer for the next timeout of the fragment queue
 * @param plugin the handle to the plugin struct
 */

static void
set_next_send(struct Plugin * const plugin)
{
  struct FragmentMessage * fm;
  struct GNUNET_TIME_Relative next_send;
  struct GNUNET_TIME_Absolute next_send_tmp;

  //cancel old task
  if (plugin->server_write_delay_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel(plugin->server_write_delay_task);
      plugin->server_write_delay_task = GNUNET_SCHEDULER_NO_TASK;
    }

  fm = GNUNET_CONTAINER_heap_peek(plugin->pending_Fragment_Messages);

  //check if some acks are in the queue
  if (plugin->ack_send_queue_head != NULL)
    {
      next_send = GNUNET_TIME_UNIT_ZERO;
    }

  //check if there are some fragments in the queue
  else
    {
      next_send = GNUNET_TIME_absolute_get_remaining(plugin->beacon_time);
      if (fm != NULL)
        {
          next_send_tmp.abs_value = GNUNET_CONTAINER_heap_node_get_cost(
              fm->node);
          next_send = GNUNET_TIME_relative_min(next_send,
              GNUNET_TIME_absolute_get_remaining(next_send_tmp));

        }
    }

#if DEBUG_wlan

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Next packet is send in: %u\n",
      next_send.rel_value);

#endif

  if (next_send.rel_value == GNUNET_TIME_UNIT_ZERO.rel_value)
    {
      if (plugin->server_write_task == GNUNET_SCHEDULER_NO_TASK)
        {
          plugin->server_write_task = GNUNET_SCHEDULER_add_write_file(
              GNUNET_TIME_UNIT_FOREVER_REL, plugin->server_stdin_handle,
              &do_transmit, plugin);
        }
    }
  else
    {
      plugin->server_write_delay_task 
	= GNUNET_SCHEDULER_add_delayed(next_send,
				       &delay_fragment_task, plugin);
    }
}

/**
 * Function to get the next queued Session, removes the session from the queue
 * @param plugin pointer to the plugin struct
 * @return pointer to the session found, returns NULL if there is now session in the queue
 */
static struct Session *
get_next_queue_session(struct Plugin * plugin)
{
  struct Session * session;
  struct Sessionqueue * sessionqueue;
  struct Sessionqueue * sessionqueue_alt;
  struct PendingMessage * pm;
  sessionqueue = plugin->pending_Sessions_head;

  while (sessionqueue != NULL)
    {
      session = sessionqueue->content;

      GNUNET_assert(session != NULL);
      pm = session->pending_message;


#if DEBUG_wlan
      if (pm == NULL)
        {
          GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
              "pending message is empty, should not happen. session %p\n",
              session);
        }
#endif

      GNUNET_assert(pm != NULL);

      //check for message timeout
      if (GNUNET_TIME_absolute_get_remaining(pm->timeout).rel_value > 0)
        {
          //check if session has no message in the fragment queue
          if (session->fragment_messages_out_count
              < FRAGMENT_QUEUE_MESSAGES_OUT_PER_SESSION)
            {
              plugin->pendingsessions--;
              GNUNET_CONTAINER_DLL_remove (plugin->pending_Sessions_head,
                  plugin->pending_Sessions_tail, sessionqueue);
              GNUNET_free(sessionqueue);

              return session;
            }
          else
            {
              sessionqueue = sessionqueue->next;
            }
        }
      else
        {

          session->pending_message = session->pending_message2;
          session->pending_message2 = NULL;

          //call the cont func that it did not work
          if (pm->transmit_cont != NULL)
            pm->transmit_cont(pm->transmit_cont_cls, &(session->target),
                GNUNET_SYSERR);
          GNUNET_free(pm->msg);
          GNUNET_free(pm);

          if (session->pending_message == NULL)
            {
              sessionqueue_alt = sessionqueue;
              sessionqueue = sessionqueue->next;
              plugin->pendingsessions--;
              GNUNET_CONTAINER_DLL_remove (plugin->pending_Sessions_head,
                  plugin->pending_Sessions_tail, sessionqueue_alt);

              GNUNET_free(sessionqueue_alt);
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
free_fragment_message(struct Plugin * plugin, struct FragmentMessage * fm)
{
  struct Session * session = fm->session;

  if (fm != NULL)
    {
      (session->fragment_messages_out_count)--;
      GNUNET_free_non_null(fm->msg);
      GNUNET_CONTAINER_heap_remove_node(fm->node);
      GNUNET_free(fm);

      queue_session(plugin, session);
#if DEBUG_wlan
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "free pending fragment messages, pending messages remaining %u\n",
          GNUNET_CONTAINER_heap_get_size(plugin->pending_Fragment_Messages));
#endif
    }
}

/**
 * Function to check if there is some space in the fragment queue
 * inserts a message if space is available
 * @param plugin the plugin struct
 */

static void
check_fragment_queue(struct Plugin * plugin)
{
  struct Session * session;
  struct FragmentMessage * fm;
  struct GNUNET_PeerIdentity pid;

  struct PendingMessage * pm;

  if (GNUNET_CONTAINER_heap_get_size(plugin->pending_Fragment_Messages)
      < FRAGMENT_QUEUE_SIZE)
    {
      session = get_next_queue_session(plugin);
      if (session != NULL)
        {
          pm = session->pending_message;
          session->pending_message = NULL;
          session->fragment_messages_out_count++;
          GNUNET_assert(pm != NULL);

          fm = GNUNET_malloc(sizeof(struct FragmentMessage));
          fm->message_size = pm->message_size;
          fm->msg = pm->msg;
          fm->session = session;
          fm->timeout.abs_value = pm->timeout.abs_value;
          fm->message_pos = 0;
          fm->next_ack = GNUNET_TIME_absolute_get();
          fm->message_id_out = get_next_message_id();
          fm->ack_bitfield = 0;
          fm->node = GNUNET_CONTAINER_heap_insert(
              plugin->pending_Fragment_Messages, fm,
              GNUNET_TIME_absolute_get().abs_value);

          GNUNET_assert(session !=NULL);

          if (pm->transmit_cont != NULL)
            {
              pid = session->target;
              pm->transmit_cont(pm->transmit_cont_cls, &pid, GNUNET_OK);
#if DEBUG_wlan
              GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                  "called pm->transmit_cont for %p\n", session);
#endif
            }
          else
            {
#if DEBUG_wlan
              GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                  "no pm->transmit_cont for %p\n", session);
#endif
            }
          GNUNET_free(pm);

          if (session->pending_message2 != NULL)
            {
              session->pending_message = session->pending_message2;
              session->pending_message2 = NULL;
              //requeue session
              queue_session(plugin, session);
            }

        }
    }

  //check if timeout changed
  set_next_send(plugin);
}

/**
 * Funktion to check if all fragments where send and the acks received
 * frees the space if finished
 * @param plugin the plugin struct
 * @param fm the message to check
 */
static void
check_finished_fragment(struct Plugin * plugin, struct FragmentMessage * fm)
{
  //maxack = size of message / max packet size, eg 12 / 5 = 2 start at 0 so ack numbers are 0,1,2
  unsigned int maxack = 63 - ((fm->message_size - 1) / (WLAN_MTU
      - sizeof(struct FragmentationHeader)));
  uint64_t tmpfield = UINT64_MAX;
  tmpfield = tmpfield >> maxack;

#if DEBUG_wlan
  if (maxack != 63)
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
      "Test bitfields %X and %X, maxack is %u, fm size %u\n",
      fm->ack_bitfield, tmpfield, maxack, fm->message_size);
#endif

  if (fm->ack_bitfield == tmpfield)
    {

#if DEBUG_wlan_retransmission
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Finished sending and got all acks; message_id %u\n",
          fm->message_id_out);
#endif

      free_fragment_message(plugin, fm);

      check_fragment_queue(plugin);

    }
}

/**
 * Function to set the next fragment number
 * @param fm use this FragmentMessage
 */

static void
set_next_message_fragment_pos(struct Plugin * plugin,
    struct FragmentMessage * fm)
{

  fm->message_pos++;

  //check if retransmit is needed
  if (GNUNET_TIME_absolute_get_remaining(fm->next_ack).rel_value == 0)
    {

      // be positive and try again later :-D
      fm->next_ack = GNUNET_TIME_relative_to_absolute(get_ack_timeout(fm));
      // find first missing fragment

      fm->message_pos = 0;

      GNUNET_CONTAINER_heap_update_cost(plugin->pending_Fragment_Messages,
          fm->node, 0);

#if DEBUG_wlan_retransmission
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Retransmit; message_id %u; fragment number %i, size: %u\n",
          fm->message_id_out, fm->message_pos, fm->message_size);
#endif
    }

  //test if ack 0 (or X) was already received
  while (testBit((char*) &fm->ack_bitfield, fm->message_pos) == GNUNET_YES)
    {
      fm->message_pos++;
    }

}

//TODO DOXIGEN
static int
getRadiotapHeader(struct Plugin * plugin, struct Session * session,
    struct Radiotap_Send * header)
{

  if (session != NULL)
    {
      header->rate = session->rate;
      header->tx_power = session->tx_power;
      header->antenna = session->antenna;
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
 * @return GNUNET_YES if there was no error
 */
static int
getWlanHeader(struct ieee80211_frame * Header,
    const struct MacAddress * to_mac_addr, struct Plugin * plugin,
    unsigned int size)
{
  uint16_t * tmp16;
  const int rate = 11000000;

  Header->i_fc[0] = 0x08;
  Header->i_fc[1] = 0x00;
  memcpy(&Header->i_addr3, &mac_bssid, sizeof(mac_bssid));
  memcpy(&Header->i_addr2, plugin->mac_address.mac, sizeof(plugin->mac_address));
  memcpy(&Header->i_addr1, to_mac_addr, sizeof(struct MacAddress));

  tmp16 = (uint16_t*) Header->i_dur;
  *tmp16 = (uint16_t) htole16((size * 1000000) / rate + 290);

  return GNUNET_YES;
}

/**
 * 32bit CRC
 *
 * @param msgbuf pointer tor the data
 * @param msgbuf_size size of the data
 *
 * @return 32bit crc value
 */

uint32_t
getcrc32(const char *msgbuf, size_t msgbuf_size)
{
  //TODO calc some crc
  return 0;
}

/**
 * 16bit CRC
 *
 * @param msgbuf pointer tor the data
 * @param msgbuf_size size of the data
 *
 * @return 16bit crc value
 */

uint16_t
getcrc16(const char *msgbuf, size_t msgbuf_size)
{
  //TODO calc some crc
  return 0;
}

//TODO DOXIGEN
static void
send_hello_beacon(struct Plugin * plugin)
{

#if DEBUG_wlan
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Sending hello beacon\n");
#endif

  uint16_t size;
  ssize_t bytes;
  uint16_t hallo_size;
  struct GNUNET_MessageHeader * msgheader;
  struct ieee80211_frame * ieeewlanheader;
  struct Radiotap_Send * radioHeader;
  struct GNUNET_MessageHeader * msgheader2;

  hallo_size = GNUNET_HELLO_size(*(plugin->env->our_hello));
  GNUNET_assert(sizeof(struct WlanHeader) + hallo_size <= WLAN_MTU);
  size = sizeof(struct GNUNET_MessageHeader) + sizeof(struct Radiotap_Send)
      + sizeof(struct ieee80211_frame) + sizeof(struct GNUNET_MessageHeader)
      + hallo_size;

  msgheader = GNUNET_malloc(size);
  msgheader->size = htons(size);
  msgheader->type = htons(GNUNET_MESSAGE_TYPE_WLAN_HELPER_DATA);

  radioHeader = (struct Radiotap_Send*) &msgheader[1];
  getRadiotapHeader(plugin, NULL, radioHeader);
  ieeewlanheader = (struct ieee80211_frame*) &radioHeader[1];
  getWlanHeader(ieeewlanheader, &bc_all_mac, plugin, size);

  msgheader2 = (struct GNUNET_MessageHeader*) &ieeewlanheader[1];
  msgheader2->size = htons(GNUNET_HELLO_size(*(plugin->env->our_hello))
      + sizeof(struct GNUNET_MessageHeader));

  msgheader2->type = htons(GNUNET_MESSAGE_TYPE_WLAN_ADVERTISEMENT);
  memcpy(&msgheader2[1], *plugin->env->our_hello, hallo_size);

  bytes = GNUNET_DISK_file_write(plugin->server_stdin_handle, msgheader, size);

  if (bytes == GNUNET_SYSERR)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
          _("Error writing to wlan healper. errno == %d, ERROR: %s\n"),
          errno, strerror(errno));

    }
  GNUNET_assert(bytes != GNUNET_SYSERR);
  GNUNET_assert(bytes == size);
  GNUNET_free(msgheader);

  set_next_beacon_time(plugin);
  set_next_send(plugin);
}

//TODO DOXIGEN
static void
send_ack(struct Plugin * plugin, struct AckSendQueue * ack)
{

  uint16_t size;
  ssize_t bytes;
  struct GNUNET_MessageHeader * msgheader;
  struct ieee80211_frame * ieeewlanheader;
  struct Radiotap_Send * radioHeader;
  struct FragmentationAckHeader * msgheader2;

  GNUNET_assert(sizeof(struct FragmentationAckHeader) <= WLAN_MTU);

  size = sizeof(struct GNUNET_MessageHeader) + sizeof(struct Radiotap_Send)
      + sizeof(struct ieee80211_frame) + sizeof(struct FragmentationAckHeader);

#if DEBUG_wlan
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
      "Sending ack for message_id %u with fragment field %u, size %u\n",
      ack->message_id, ack->fragments_field, size
      - sizeof(struct Radiotap_Send));
#endif

  msgheader = GNUNET_malloc(size);
  msgheader->size = htons(size);
  msgheader->type = htons(GNUNET_MESSAGE_TYPE_WLAN_HELPER_DATA);

  radioHeader = (struct Radiotap_Send*) &msgheader[1];
  getRadiotapHeader(plugin, ack->session, radioHeader);
  ieeewlanheader = (struct ieee80211_frame*) &radioHeader[1];
  getWlanHeader(ieeewlanheader, &ack->session->addr, plugin, size);

  msgheader2 = (struct FragmentationAckHeader*) &ieeewlanheader[1];
  msgheader2->header.size = htons(sizeof(struct FragmentationAckHeader));
  msgheader2->header.type = htons(GNUNET_MESSAGE_TYPE_WLAN_FRAGMENT_ACK);
  msgheader2->message_id = htonl(ack->message_id);
  msgheader2->fragment_field = GNUNET_htonll(ack->fragments_field);

  bytes = GNUNET_DISK_file_write(plugin->server_stdin_handle, msgheader, size);
  if (bytes == GNUNET_SYSERR)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
          _("Error writing to wlan healper. errno == %d, ERROR: %s\n"),
          errno, strerror(errno));

    }
  GNUNET_assert(bytes != GNUNET_SYSERR);
  GNUNET_assert(bytes == size);
  GNUNET_free(msgheader);
  set_next_send(plugin);
}

//TODO DOXIGEN
static void
finish_sending(void *cls, 
	       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Finish_send * finish = cls;
  struct Plugin * plugin;
  ssize_t bytes;

  plugin = finish->plugin;
  plugin->server_write_task = GNUNET_SCHEDULER_NO_TASK;

  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    {
      GNUNET_free (finish->msgstart);
      GNUNET_free (finish);
      return;
    }
  bytes = GNUNET_DISK_file_write (plugin->server_stdin_handle,
				  finish->msgheader, 
				  finish->size);
  GNUNET_assert (bytes != GNUNET_SYSERR);

  if (bytes != finish->size)
    {
      finish->msgheader = finish->msgheader + bytes;
      finish->size = finish->size - bytes;
      plugin->server_write_task 
	= GNUNET_SCHEDULER_add_write_file(GNUNET_TIME_UNIT_FOREVER_REL,
					  plugin->server_stdin_handle,
					  &finish_sending, finish);
    }
  else
    {
      GNUNET_free(finish->msgstart);
      GNUNET_free(finish);
      set_next_send(plugin);
    }
}

/**
 * Function called when wlan helper is ready to get some data
 *
 * @param cls closure
 * @param tc GNUNET_SCHEDULER_TaskContext
 */
static void
do_transmit(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin * plugin = cls;

  plugin->server_write_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  struct Session * session;
  struct FragmentMessage * fm;
  struct ieee80211_frame * ieeewlanheader;
  struct Radiotap_Send * radioHeader;
  struct GNUNET_MessageHeader * msgheader;
  struct FragmentationHeader fragheader;
  struct FragmentationHeader * fragheaderptr;
  struct Finish_send * finish;
  struct AckSendQueue * ack;
  uint16_t size;
  ssize_t bytes;
  const char * copystart;
  uint16_t copysize;
  uint copyoffset;

  if (plugin->ack_send_queue_head != NULL)
    {
      ack = plugin->ack_send_queue_head;
      GNUNET_CONTAINER_DLL_remove(plugin->ack_send_queue_head,
          plugin->ack_send_queue_tail, ack);
      send_ack(plugin, ack);
      GNUNET_free(ack);
      return;
    }

  //test if a "hello-beacon" has to be send
  if (GNUNET_TIME_absolute_get_remaining(plugin->beacon_time).rel_value == 0)
    {
      send_hello_beacon(plugin);
      return;
    }

  fm = GNUNET_CONTAINER_heap_peek(plugin->pending_Fragment_Messages);

  if (fm != NULL)
    {
      session = fm->session;
      GNUNET_assert(session != NULL);

      // test if message timed out
      if (GNUNET_TIME_absolute_get_remaining(fm->timeout).rel_value == 0)
        {
#if DEBUG_wlan
          GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "message timeout\n");
#endif

          free_fragment_message(plugin, fm);
          check_fragment_queue(plugin);

        }
      else
        {

          //if (fm->message_size > WLAN_MTU)
          // {
          size = sizeof(struct FragmentationHeader);

          set_next_message_fragment_pos(plugin, fm);

          copyoffset = (WLAN_MTU - sizeof(struct FragmentationHeader))
              * fm->message_pos;

          fragheader.fragment_off_or_num = htons(fm->message_pos);
          fragheader.message_id = htonl(fm->message_id_out);
          copystart = fm->msg + copyoffset;
          copysize = GNUNET_MIN(fm->message_size - copyoffset,
              WLAN_MTU - sizeof(struct FragmentationHeader));

#if DEBUG_wlan
          GNUNET_log(
              GNUNET_ERROR_TYPE_DEBUG,
              "Sending GNUNET_MESSAGE_TYPE_WLAN_FRAGMENT with message_id %u with fragment number %i, size: %u, offset %u, time until timeout %u\n",
              fm->message_id_out, fm->message_pos, copysize
              + sizeof(struct FragmentationHeader), copyoffset,
              GNUNET_TIME_absolute_get_remaining(fm->timeout));
#endif

          if (copyoffset >= fm->message_size)
            {
              GNUNET_log(
                  GNUNET_ERROR_TYPE_ERROR,
                  "offset in message for fragment too large, offset %u, size %u, max size %u, copysize %u, message_pos %u,\n",
                  copyoffset, fm->message_size, WLAN_MTU
                      - sizeof(struct FragmentationHeader), copysize,
                  fm->message_pos);
            }
          GNUNET_assert(copyoffset < fm->message_size);

          fragheader.header.size = htons(copysize
              + sizeof(struct FragmentationHeader));
          fragheader.header.type = htons(GNUNET_MESSAGE_TYPE_WLAN_FRAGMENT);

          size += copysize;
          size += sizeof(struct Radiotap_Send) + sizeof(struct ieee80211_frame)
              + sizeof(struct GNUNET_MessageHeader);
          msgheader = GNUNET_malloc(size);
          msgheader->size = htons(size);
          msgheader->type = htons(GNUNET_MESSAGE_TYPE_WLAN_HELPER_DATA);

          radioHeader = (struct Radiotap_Send*) &msgheader[1];
          getRadiotapHeader(plugin, session, radioHeader);

          ieeewlanheader = (struct ieee80211_frame *) &radioHeader[1];
          getWlanHeader(ieeewlanheader, &(fm->session->addr), plugin, size);

          //could be faster if content is just send and not copyed before
          //fragmentheader is needed
          fragheader.message_crc = htons(getcrc16(copystart, copysize));
          memcpy(&ieeewlanheader[1], &fragheader,
              sizeof(struct FragmentationHeader));
          fragheaderptr = (struct FragmentationHeader *) &ieeewlanheader[1];
          memcpy(&fragheaderptr[1], copystart, copysize);

          bytes = GNUNET_DISK_file_write(plugin->server_stdin_handle,
              msgheader, size);
          if (bytes == GNUNET_SYSERR)
            {
              GNUNET_log(
                  GNUNET_ERROR_TYPE_ERROR,
                  _("Error writing to wlan healper. errno == %d, ERROR: %s\n"),
                  errno, strerror(errno));

            }
          GNUNET_assert(bytes != GNUNET_SYSERR);

          //check if this was the last fragment of this message, if true then queue at the end of the list
          if (copysize + copyoffset >= fm->message_size)
            {
              GNUNET_assert(copysize + copyoffset == fm->message_size);

              GNUNET_CONTAINER_heap_update_cost(
                  plugin->pending_Fragment_Messages, fm->node, MIN(
                      fm->timeout.abs_value, fm->next_ack.abs_value));
              // if fragments have opimized timeouts
              //sort_fragment_into_queue(plugin,fm);


#if DEBUG_wlan_retransmission
              GNUNET_log(
                  GNUNET_ERROR_TYPE_DEBUG,
                  "Finished sending all fragments waiting for acks; message_id %u; message_id %u; fragment number %i, size: %u, time until timeout %u\n",
                  fm->message_id_out, fm->message_id_out, fm->message_pos,
                  fm->message_size, GNUNET_TIME_absolute_get_remaining(
                      fm->timeout));
#endif
            }
          else
            {
              GNUNET_CONTAINER_heap_update_cost(
                  plugin->pending_Fragment_Messages, fm->node,
                  GNUNET_TIME_absolute_get().abs_value);
            }

          if (bytes != size)
            {
              finish = GNUNET_malloc(sizeof( struct Finish_send));
              finish->plugin = plugin;
              finish->msgheader = (char *) msgheader + bytes;
              finish->size = size - bytes;
              finish->msgstart = msgheader;

              GNUNET_assert(plugin->server_write_task == GNUNET_SCHEDULER_NO_TASK);

              plugin->server_write_task = GNUNET_SCHEDULER_add_write_file(
                  GNUNET_TIME_UNIT_FOREVER_REL, plugin->server_stdin_handle,
                  &finish_sending, finish);

            }
          else
            {
              GNUNET_free(msgheader);
              set_next_send(plugin);
            }

        }
      return;
    }

  GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
      "do_transmit did nothing, should not happen!\n");
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
wlan_plugin_address_suggested(void *cls, const void *addr, size_t addrlen)
{
  //struct Plugin *plugin = cls;

  /* check if the address is plausible; if so,
   add it to our list! */

  GNUNET_assert(cls !=NULL);
  //FIXME mitm is not checked
  //Mac Address has 6 bytes
  if (addrlen == 6)
    {
      /* TODO check for bad addresses like multicast, broadcast, etc */
      return GNUNET_OK;
    }

  return GNUNET_SYSERR;
}

/**
 * Function that can be used by the transport service to transmit
 * a message using the plugin.
 *
 * @param cls closure
 * @param target who should receive this message
 * @param priority how important is the message
 * @param msgbuf the message to transmit
 * @param msgbuf_size number of bytes in 'msgbuf'
 * @param timeout when should we time out
 * @param session which session must be used (or NULL for "any")
 * @param addr the address to use (can be NULL if the plugin
 *                is "on its own" (i.e. re-use existing TCP connection))
 * @param addrlen length of the address in bytes
 * @param force_address GNUNET_YES if the plugin MUST use the given address,
 *                otherwise the plugin may use other addresses or
 *                existing connections (if available)
 * @param cont continuation to call once the message has
 *        been transmitted (or if the transport is ready
 *        for the next transmission call; or if the
 *        peer disconnected...)
 * @param cont_cls closure for cont
 * @return number of bytes used (on the physical network, with overheads);
 *         -1 on hard errors (i.e. address invalid); 0 is a legal value
 *         and does NOT mean that the message was not transmitted (DV)
 */
static ssize_t
wlan_plugin_send(void *cls, const struct GNUNET_PeerIdentity * target,
    const char *msgbuf, size_t msgbuf_size, unsigned int priority,
    struct GNUNET_TIME_Relative timeout, struct Session *session,
    const void *addr, size_t addrlen, int force_address,
    GNUNET_TRANSPORT_TransmitContinuation cont, void *cont_cls)
{
  struct Plugin * plugin = cls;
  struct PendingMessage * newmsg;
  struct WlanHeader * wlanheader;

  //check if msglen > 0
  GNUNET_assert(msgbuf_size > 0);

  //get session if needed
  if (session == NULL)
    {
      if (wlan_plugin_address_suggested(plugin, addr, addrlen) == GNUNET_OK)
        {
          session = get_session(plugin, addr);
        }
      else
        {
          GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
              _("Wlan Address len %d is wrong\n"), addrlen);
          return -1;
        }
    }

  //TODO target "problem" not solved
  //if (session->target != NULL){
  //  GNUNET_assert(session->target == *target);
  //} else {
  session->target = *target;
  //}


  //queue message:

  //queue message in session
  //test if there is no other message in the "queue"
  //FIXME: to many send requests
  //GNUNET_assert (session->pending_message == NULL);
  if (session->pending_message != NULL)
    {
      newmsg = session->pending_message;
      GNUNET_log(
          GNUNET_ERROR_TYPE_ERROR,
          "wlan_plugin_send: a pending message is already in the queue for this client\n remaining time to send this message is %u, queued fragment messages %u\n",
          GNUNET_TIME_absolute_get_remaining(newmsg->timeout).rel_value,
          session->fragment_messages_out_count);
      if (session->pending_message2 != NULL)
        {
          GNUNET_log(
              GNUNET_ERROR_TYPE_ERROR,
              "wlan_plugin_send: two pending messages are already in the queue for this client\n");
          return -1;
        }
    }

  newmsg = GNUNET_malloc(sizeof(struct PendingMessage));
  (newmsg->msg) = GNUNET_malloc(msgbuf_size + sizeof(struct WlanHeader));
  wlanheader = (struct WlanHeader *) newmsg->msg;
  //copy msg to buffer, not fragmented / segmented yet, but with message header
  wlanheader->header.size = htons(msgbuf_size + sizeof(struct WlanHeader));
  wlanheader->header.type = htons(GNUNET_MESSAGE_TYPE_WLAN_DATA);
  memcpy(&(wlanheader->target), target, sizeof(struct GNUNET_PeerIdentity));
  wlanheader->crc = htonl(getcrc32(msgbuf, msgbuf_size));
  memcpy(&wlanheader[1], msgbuf, msgbuf_size);
  newmsg->transmit_cont = cont;
  newmsg->transmit_cont_cls = cont_cls;
  newmsg->timeout = GNUNET_TIME_relative_to_absolute(timeout);

  newmsg->timeout.abs_value = newmsg->timeout.abs_value - 500;

  newmsg->message_size = msgbuf_size + sizeof(struct WlanHeader);

  if (session->pending_message == NULL)
    {
      session->pending_message = newmsg;
    }
  else
    {
      session->pending_message2 = newmsg;
    }

#if DEBUG_wlan
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
      "New message for %p with size (incl wlan header) %u added\n", session,
      newmsg->message_size);
#endif

  //queue session
  queue_session(plugin, session);

  check_fragment_queue(plugin);
  //FIXME not the correct size
  return msgbuf_size;

}

/**
 * Iterate over the fragment messages of the given session.
 *
 * @param cls argument to give to iterator
 * @param node node to iterate over
 * @param element value stored at the node
 * @param cost cost associated with the node
 * @return GNUNET_YES if we should continue to iterate,
 *         GNUNET_NO if not.
 */
static int
free_fragment_message_from_session(void *cls,
    struct GNUNET_CONTAINER_HeapNode *node, void *element,
    GNUNET_CONTAINER_HeapCostType cost)
{
  struct Plugin_Session_pair * pair = (struct Plugin_Session_pair *) cls;
  struct FragmentMessage * fm = (struct FragmentMessage*) element;

  if (fm->session == pair->session)
    {

      free_fragment_message(pair->plugin, fm);
    }
  return GNUNET_YES;

}

/**
 * Search for fragment message with given id and session
 *
 * @param cls argument to give to iterator
 * @param node node to iterate over
 * @param element value stored at the node
 * @param cost cost associated with the node
 * @return GNUNET_YES if we should continue to iterate,
 *         GNUNET_NO if not.
 */
static int
search_fragment_message_from_session_and_id(void *cls,
    struct GNUNET_CONTAINER_HeapNode *node, void *element,
    GNUNET_CONTAINER_HeapCostType cost)
{
  struct Session_id_fragment_triple * triple =
      (struct Session_id_fragment_triple *) cls;
  struct FragmentMessage * fm = (struct FragmentMessage*) element;

  if ((fm->session == triple->session) && (fm->message_id_out
      == triple->message_id))
    {
      triple->fm = fm;
      return GNUNET_NO;
    }
  return GNUNET_YES;

}

/**
 * function to get the message in the fragement queue (out) of a session with a specific id
 * @param session pointer to the session
 * @param message_id id of the message
 * @return pointer to the struct FragmentMessage
 */
static struct FragmentMessage *
get_fragment_message_from_session_and_id(struct Plugin * plugin,
    struct Session * session, uint32_t message_id)
{
  struct Session_id_fragment_triple triple;
  triple.session = session;
  triple.message_id = message_id;
  GNUNET_CONTAINER_heap_iterate(plugin->pending_Fragment_Messages,
      &search_fragment_message_from_session_and_id, &triple);
  return triple.fm;
}

/**
 * function to get the receive message of a session
 * @param plugin pointer to the plugin struct
 * @param session session this fragment belongs to
 */
static struct Receive_Message_Queue *
get_receive_message_from_session(struct Plugin * plugin,
    struct Session * session)
{
  struct Receive_Message_Queue * rec_message = plugin->receive_messages_head;
  while (rec_message != NULL)
    {
      if (rec_message->session == session)
        {
          return rec_message;
        }
      rec_message = rec_message->next;
    }
  return NULL;
}

/**
 * Function to dispose the fragments received for a message and the message
 * @param plugin pointer to the plugin struct
 * @param rec_message pointer to the struct holding the message which should be freed
 */
static void
free_receive_message(struct Plugin* plugin,
    struct Receive_Message_Queue * rx_message)
{
  GNUNET_assert(rx_message !=NULL);
  struct Receive_Fragment_Queue * rec_queue = rx_message->frag_head;
  struct Receive_Fragment_Queue * rec_queue2;

  while (rec_queue != NULL)
    {
      rec_queue2 = rec_queue;
      rec_queue = rec_queue->next;
      GNUNET_free(rec_queue2);
    }

  GNUNET_CONTAINER_DLL_remove(plugin->receive_messages_head,plugin->receive_messages_teil, rx_message);

  GNUNET_assert(plugin->pending_receive_messages > 0);
  GNUNET_assert(rx_message->session->fragment_messages_in_count > 0);

  plugin->pending_receive_messages--;
  rx_message->session->fragment_messages_in_count--;
  GNUNET_free(rx_message);
}

/**
 * function to get the receive message of a session
 * @param plugin pointer to the plugin struct
 * @param session session this fragment belongs to
 */
static void
check_receive_message_timeouts(struct Plugin * plugin, struct Session * session)
{
  struct Receive_Message_Queue * rec_message = plugin->receive_messages_head;
  while (rec_message != NULL)
    {
      if (GNUNET_TIME_absolute_get_remaining(rec_message->timeout).rel_value
          == 0)
        {
          free_receive_message(plugin, rec_message);
        }
      rec_message = rec_message->next;
    }

}

//TODO DOXIGEN
static void
free_session(struct Plugin * plugin, struct Sessionqueue * queue)
{
  struct Sessionqueue * pendingsession;
  struct Sessionqueue * pendingsession_tmp;
  struct PendingMessage * pm;
  struct Receive_Message_Queue * receive_queue;
  struct Plugin_Session_pair pair;
  int check = 0;

  GNUNET_assert(queue != NULL);
  GNUNET_assert(queue->content != NULL);

  //session found
  //is this session pending for send
  pendingsession = plugin->pending_Sessions_head;
  while (pendingsession != NULL)
    {
      pendingsession_tmp = pendingsession->next;
      if (pendingsession->content == queue->content)
        {
          plugin->pendingsessions--;
          GNUNET_CONTAINER_DLL_remove (plugin->pending_Sessions_head,
				       plugin->pending_Sessions_tail, 
				       pendingsession);
          GNUNET_free(pendingsession);

          GNUNET_assert (check == 0);
          check = 1;
        }
      pendingsession = pendingsession_tmp;
    }

  //is something of this session in the fragment queue?
  pair.plugin = plugin;
  pair.session = queue->content;
  GNUNET_CONTAINER_heap_iterate(plugin->pending_Fragment_Messages,
      &free_fragment_message_from_session, &pair);

  //dispose all received fragments
  receive_queue = get_receive_message_from_session(plugin, queue->content);
  while (receive_queue != NULL)
    {
      free_receive_message(plugin, receive_queue);
      receive_queue = get_receive_message_from_session(plugin, queue->content);
    }

  // remove PendingMessage
  pm = queue->content->pending_message;
  if (pm != NULL)
    {
      GNUNET_free_non_null(pm->msg);
      GNUNET_free(pm);
    }

  // remove PendingMessage
  pm = queue->content->pending_message2;
  if (pm != NULL)
    {
      GNUNET_free_non_null(pm->msg);
      GNUNET_free(pm);
    }

  GNUNET_CONTAINER_DLL_remove(plugin->sessions, 
			      plugin->sessions_tail, 
			      queue);
  GNUNET_free(queue->content);
  GNUNET_free(queue);
  plugin->session_count--;
  check_fragment_queue(plugin);
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
wlan_plugin_disconnect(void *cls, const struct GNUNET_PeerIdentity *target)
{
  struct Plugin *plugin = cls;
  struct Sessionqueue * queue = plugin->sessions;

  // just look at all the session for the needed one
  while (queue != NULL)
    {
      // content is never NULL
      GNUNET_assert (queue->content != NULL);
      if (memcmp(target, &(queue->content->target),
          sizeof(struct GNUNET_PeerIdentity)) == 0)
        {
          free_session(plugin, queue);
          return;
        }
      // try next
      queue = queue->next;
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
wlan_plugin_address_pretty_printer(void *cls, const char *type,
    const void *addr, size_t addrlen, int numeric,
    struct GNUNET_TIME_Relative timeout,
    GNUNET_TRANSPORT_AddressStringCallback asc, void *asc_cls)
{
  char ret[92];
  const unsigned char * input;

  //GNUNET_assert(cls !=NULL);
  if (addrlen != 6)
    {
      /* invalid address (MAC addresses have 6 bytes) */
      GNUNET_break (0);
      asc(asc_cls, NULL);
      return;
    }
  input = (const unsigned char*) addr;
  GNUNET_snprintf(ret, sizeof(ret),
      "%s Mac-Address %.2X:%.2X:%.2X:%.2X:%.2X:%.2X", PROTOCOL_PREFIX,
      input[0], input[1], input[2], input[3], input[4], input[5]);
  asc(asc_cls, ret);
}


/**
 * Function to test if fragment number already exists in the fragments received
 *
 * @param rec_message message this fragment belongs to
 * @param fh Fragmentheader of the fragment
 * @return GNUNET_YES if fragment exists already, GNUNET_NO if it does not exists in the queue of the session
 */
static int
is_double_msg(struct Receive_Message_Queue * rx_msg,
    struct FragmentationHeader * fh)
{


  return testBit((char *) &rx_msg->received_fragments, ntohs(
      fh->fragment_off_or_num));

}

/**
 * Function to insert a fragment in a queue of a message
 * @param session session the fragment belongs to
 * @param rec_queue fragment to add
 */
static void
insert_fragment_in_queue(struct Receive_Message_Queue * rx_message,
    struct Receive_Fragment_Queue * rx_frag)
{
  GNUNET_assert(rx_message != NULL);
  GNUNET_assert(rx_frag != NULL);

  struct Receive_Fragment_Queue * rx_frag2 = rx_message->frag_head;
  struct WlanHeader * wlanheader;

  //this is the first fragment of the message (fragment id 0)
  if (rx_frag->num == 0)
    {
      wlanheader = (struct WlanHeader *) rx_frag->msg;
      rx_message->rec_size = ntohs(wlanheader->header.size);
    }

  //sort into list
  while (rx_frag2 != NULL)
    {
      if (rx_frag2->num > rx_frag->num)
        {
          //next element number is grater than the current num
          GNUNET_CONTAINER_DLL_insert_before(rx_message->frag_head, rx_message->frag_tail, rx_frag2, rx_frag);
          setBit((char *) &rx_message->received_fragments, rx_frag->num);
          return;
        }
      rx_frag2 = rx_frag2->next;
    }

  //no element has a grater number
  GNUNET_CONTAINER_DLL_insert_tail(rx_message->frag_head, rx_message->frag_tail, rx_frag);

  setBit((char *) &rx_message->received_fragments, rx_frag->num);
}

/**
 * handels the data after all fragments are put together
 * @param plugin
 * @param session_light
 * @param hdr pointer to the data
 */
static void
wlan_data_message_handler(void *cls, void *client,
    const struct GNUNET_MessageHeader *hdr)
{
  struct Plugin * plugin = (struct Plugin*) cls;
  struct Session_light * session_light = (struct Session_light *) client;
  struct WlanHeader * wlanheader;
  struct Session * session;
  const char * tempmsg;
  const struct GNUNET_MessageHeader * temp_hdr;
  struct GNUNET_PeerIdentity tmptarget;

  if (ntohs(hdr->type) == GNUNET_MESSAGE_TYPE_WLAN_DATA)
    {

#if DEBUG_wlan
      GNUNET_log(
          GNUNET_ERROR_TYPE_DEBUG,
          "Func wlan_data_message_handler got GNUNET_MESSAGE_TYPE_WLAN_DATA size: %u\n",
          ntohs(hdr->size));
#endif

      if (ntohs(hdr->size) < sizeof(struct WlanHeader)
          + sizeof(struct GNUNET_MessageHeader))
        {
          //packet not big enought
          return;
        }

      GNUNET_assert(session_light != NULL);
      if (session_light->session == NULL)
        {
          session_light->session = search_session(plugin, &session_light->addr);
        }
      session = session_light->session;
      wlanheader = (struct WlanHeader *) hdr;

      tempmsg = (char*) &wlanheader[1];
      temp_hdr = (const struct GNUNET_MessageHeader *) &wlanheader[1];

      if (getcrc32(tempmsg, ntohs(wlanheader->header.size)) != ntohl(
          wlanheader->crc))
        {
          //wrong crc, dispose message
          GNUNET_log(GNUNET_ERROR_TYPE_INFO,
              "Wlan message Header crc was wrong\n");
          return;
        }

      //if not in session list
      if (session == NULL)
        {
#if DEBUG_wlan
          GNUNET_log(
              GNUNET_ERROR_TYPE_DEBUG,
              "WLAN client not in session list: packet size = %u, inner size = %u, header size = %u\n",
              ntohs(wlanheader->header.size), ntohs(temp_hdr->size),
              sizeof(struct WlanHeader));
#endif
          //try if it is a hello message
          if (ntohs(wlanheader->header.size) >= ntohs(temp_hdr->size)
              + sizeof(struct WlanHeader))
            {
              if (ntohs(temp_hdr->type) == GNUNET_MESSAGE_TYPE_HELLO)
                {
                  if (GNUNET_HELLO_get_id(
                      (const struct GNUNET_HELLO_Message *) temp_hdr,
                      &tmptarget) == GNUNET_OK)
                    {
                      session = create_session(plugin, &session_light->addr);
                      session_light->session = session;
                      memcpy(&session->target, &tmptarget,
                          sizeof(struct GNUNET_PeerIdentity));
                    }
                  else
                    {
                      GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
                          "WLAN client not in session list and hello message not okay\n");
                      return;
                    }

                }
              else
                {
                  GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
                      "WLAN client not in session list and not a hello message\n");
                  return;
                }
            }
          else
            {
              GNUNET_log(
                  GNUNET_ERROR_TYPE_WARNING,
                  "WLAN client not in session list and message size in does not fit\npacket size = %u, inner size = %u, header size = %u\n",
                  ntohs(wlanheader->header.size), ntohs(temp_hdr->size),
                  sizeof(struct WlanHeader));
              return;
            }
        }

      //"receive" the message


      GNUNET_SERVER_mst_receive(plugin->data_tokenizer, session,
          (const char *) temp_hdr,
          ntohs(hdr->size) - sizeof(struct WlanHeader), GNUNET_YES, GNUNET_NO);

      return;
    }
  else
    {
      GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
          "wlan_data_message_handler got wrong message type\n");
      return;
    }
}

/**
 * Function to check if all fragments of a message have been received
 * @param plugin the plugin handle
 * @param session_light information of the message sender
 * @param session session the message belongs to
 * @param rec_message pointer to the message that should be checked
 */

static void
check_rx_finished_msg(struct Plugin* plugin,
    struct Session_light * session_light, struct Session * session,
    struct Receive_Message_Queue * rx_message)
{
  GNUNET_assert(rx_message !=NULL);

  struct Receive_Fragment_Queue * rx_frag = rx_message->frag_head;
  int packetsize = rx_message->rec_size;
  int sum;
  //TODO CLEANUP
  //int aktnum;
  uint64_t bitfield = 0;
  //char * msg;

  //check if first fragment is present
  if (packetsize == MESSAGE_LENGHT_UNKNOWN)
    {
      return;
    }
  // test if message has at least the size of the WlanHeader and a GNUNET_MessageHeader

  else if (packetsize < sizeof(struct WlanHeader)
      + sizeof(struct GNUNET_MessageHeader))
    {
#if DEBUG_wlan
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Message not big enough\n");
#endif
      free_receive_message(plugin, rx_message);
      return;
    }

  //  if (rx_message->frag_tail->num == ffsl(rx_message->received_fragments))
  //    {
  bitfield = ~bitfield;
  bitfield = bitfield >> (63 - rx_message->frag_tail->num);
  if (rx_message->received_fragments == bitfield)
    {
      sum = 0;
      while (rx_frag != NULL)
        {
          sum += rx_frag->size;
          rx_frag = rx_frag->next;
        }
      //sum should always be smaller or equal of
      GNUNET_assert(sum <= packetsize);
      if (sum == packetsize)
        {

#if DEBUG_wlan
          GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
              "check_rec_finished_msg: A message for %p is complete\n", session);
#endif

          //TODO cleanup

          //copy fragments together
          //msg = GNUNET_malloc(packetsize);
          rx_frag = rx_message->frag_head;
          //aktnum = 0;
          /*while (rx_frag != NULL)
           {
           //TODO SAVE SOME COPY OPS AND CHECK CRC WITHOUT COPY
           memcpy(msg + aktnum, rx_frag->msg, rx_frag->size);
           aktnum += rx_frag->size;
           rx_frag = rx_frag->next;
           }*/

          while (rx_frag != NULL)
            {
              if (rx_frag->next != NULL)
                {
                  GNUNET_SERVER_mst_receive(plugin->fragment_tokenizer,
                      session_light, rx_frag->msg, rx_frag->size, GNUNET_NO,
                      GNUNET_NO);
                }
              else
                {
                  //if it is the last fragment just kill all leftover
                  GNUNET_SERVER_mst_receive(plugin->fragment_tokenizer,
                      session_light, rx_frag->msg, rx_frag->size, GNUNET_YES,
                      GNUNET_NO);
                }
              rx_frag = rx_frag->next;
            }
          free_receive_message(plugin, rx_message);
          //call wlan_process_helper to process the message
          //wlan_data_message_handler(plugin, session_light,
          //   (struct GNUNET_MessageHeader*) msg);
          //wlan_data_helper (plugin, session_light, (struct GNUNET_MessageHeader*) msg);

          //GNUNET_free(msg);
        }
    }
  //    }
}

//TODO DOXIGEN
static void
process_data(void *cls, void *client, const struct GNUNET_MessageHeader *hdr)
{

  GNUNET_assert(client != NULL);
  GNUNET_assert(cls != NULL);
  struct Session * session = (struct Session *) client;
  struct Plugin * plugin = (struct Plugin *) cls;

  struct GNUNET_TRANSPORT_ATS_Information distance[2];
  distance[0].type = htonl(GNUNET_TRANSPORT_ATS_QUALITY_NET_DISTANCE);
  distance[0].value = htonl(1);
  distance[1].type = htonl(GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR);
  distance[1].value = htonl(0);

#if DEBUG_wlan
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
      "Calling plugin->env->receive for session %p; %s; size: %u\n", session,
      wlan_plugin_address_to_string(NULL, session->addr.mac, 6), htons(
          hdr->size));
#endif

  plugin->env->receive(plugin->env->cls, &(session->target), hdr,
      (const struct GNUNET_TRANSPORT_ATS_Information *) &distance, 2, session,
      (const char*) &session->addr, sizeof(session->addr));
}

/**
 * function to add an ack to send it for a received fragment
 * @param plugin pointer to the global plugin structure
 * @param session pointer to the session this ack belongs to
 * @param bitfield bitfield to send
 * @param fh pointer to the fragmentation header which we would like to acknolage
 */

void
add_ack_for_send(struct Plugin * plugin, struct Session * session,
    uint64_t bitfield, struct FragmentationHeader * fh)
{
  struct AckSendQueue * ack;

  GNUNET_assert(plugin != NULL);
  GNUNET_assert(session != NULL);
  GNUNET_assert(fh != NULL);

  ack = GNUNET_malloc(sizeof(struct AckSendQueue));
  ack->fragments_field = bitfield;
  ack->message_id = ntohl(fh->message_id);
  ack->session = session;

  GNUNET_CONTAINER_DLL_insert_tail(plugin->ack_send_queue_head,
      plugin->ack_send_queue_tail, ack);

}

/**
 * function to get the receive message from the message id and the session
 * @param plugin pointer to the plugin struct
 * @param session session this fragment belongs to
 * @param message_id id of the message
 */

struct Receive_Message_Queue *
get_receive_message(struct Plugin * plugin, struct Session * session,
    uint32_t message_id)
{
  struct Receive_Message_Queue * rec_message = plugin->receive_messages_head;
  while (rec_message != NULL)
    {
      if ((rec_message->message_id_in == message_id) && (rec_message->session
          == session))
        {
          return rec_message;
        }
      rec_message = rec_message->next;
    }
  return NULL;
}

/**
 * function to insert a received fragment into the right fragment queue of the right message
 * @param plugin pointer to the plugin struct
 * @param session_light pointer to the session_light struct of this message
 * @param session session this fragment belongs to
 * @param fh pointer to the header of the fragment
 * @return new fragment bitfield for the message
 */

uint64_t
insert_fragment_in_in_message_queue(struct Plugin * plugin,
    struct Session_light * session_light, struct Session * session,
    struct FragmentationHeader * fh, const struct Radiotap_rx * rxinfo)
{
  struct Receive_Fragment_Queue * rx_frag = NULL;
  struct Receive_Message_Queue * rx_message;
  const char * tempmsg = (char*) &fh[1];
  uint64_t retval = 0;

  //TODO fragments do not timeout
  //check if message_id is right or it is a new msg
  GNUNET_assert(fh != NULL);

  rx_message = get_receive_message(plugin, session, ntohl(fh->message_id));

  if (rx_message == NULL)
    {
      if (session->fragment_messages_in_count < MESSAGES_IN_QUEUE_PER_SESSION)
        {
          check_receive_message_timeouts(plugin, session);
        }

      if (session->fragment_messages_in_count < MESSAGES_IN_QUEUE_PER_SESSION)
        {

          //new message incoming
          rx_message = GNUNET_malloc(sizeof (struct Receive_Message_Queue));
          rx_message->message_id_in = ntohl(fh->message_id);
          rx_message->rec_size = MESSAGE_LENGHT_UNKNOWN;
          rx_message->session = session;
          rx_message->received_fragments = 0;

          GNUNET_CONTAINER_DLL_insert(plugin->receive_messages_head, plugin->receive_messages_teil, rx_message);

          session->fragment_messages_in_count++;
          plugin->pending_receive_messages++;

#if DEBUG_wlan
          GNUNET_log(
              GNUNET_ERROR_TYPE_DEBUG,
              "New fragmented message started: message id %u, messages in for this session %u, messages in %u\n",
              rx_message->message_id_in, session->fragment_messages_in_count,
              plugin->pending_receive_messages);
#endif
        }
      else
        {

          GNUNET_log(
              GNUNET_ERROR_TYPE_INFO,
              "WLAN fragment message_id and session message_id do not exist, max MESSAGES_IN_QUEUE_PER_SESSION reached, akt in message_id %u\n",
              get_receive_message_from_session(plugin, session)->message_id_in);
          setBit((char *) &retval, ntohs(fh->fragment_off_or_num));
          return retval;
        }
    }

  //reset timeout
  rx_message->timeout = GNUNET_TIME_absolute_add(
  GNUNET_TIME_absolute_get(),
      MESSAGE_IN_TIMEOUT);

  if (is_double_msg(rx_message, fh) != GNUNET_YES)
    {

      //report size
      rx_frag = GNUNET_malloc(sizeof (struct Receive_Fragment_Queue) +
          ntohs(fh->header.size) - sizeof(struct FragmentationHeader));
      rx_frag->size = ntohs(fh->header.size)
          - sizeof(struct FragmentationHeader);
      rx_frag->num = ntohs(fh->fragment_off_or_num);
      rx_frag->msg = (char*) &(rx_frag[1]);
      //copy msg to buffer
      memcpy((char *) rx_frag->msg, tempmsg, rx_frag->size);
      memcpy((char *) &(rx_frag->rxinfo), rxinfo, sizeof(rxinfo));
      insert_fragment_in_queue(rx_message, rx_frag);
      //save bitfield
      retval = rx_message->received_fragments;

#if DEBUG_wlan
      GNUNET_log(
          GNUNET_ERROR_TYPE_DEBUG,
          "New fragment:  size %u, fragsize %u, message id %u, bitfield %X, session %u\n",
          rx_message->rec_size, rx_frag->size, rx_message->message_id_in,
          rx_message->received_fragments, session);
#endif

      check_rx_finished_msg(plugin, session_light, session, rx_message);
    }
  else
    {
      GNUNET_log(GNUNET_ERROR_TYPE_INFO, "WLAN fragment is a clone\n");
      retval = rx_message->received_fragments;

    }
  return retval;

}

/**
 * Function used for to process the data received from the wlan interface
 *
 * @param cls the plugin handle
 * @param session_light FIXME: document
 * @param hdr hdr of the GNUNET_MessageHeader
 */
static void
wlan_data_helper(void *cls, struct Session_light * session_light,
    const struct GNUNET_MessageHeader * hdr, const struct Radiotap_rx * rxinfo)
{
  struct Plugin *plugin = cls;
  struct Session * session;

  struct FragmentationHeader * fh;
  struct FragmentationAckHeader * fah;
  struct FragmentMessage * fm;

  const char * tempmsg;

  uint64_t fragment_bitfield = 0;

  //ADVERTISEMENT
  if (ntohs(hdr->type) == GNUNET_MESSAGE_TYPE_WLAN_ADVERTISEMENT)
    {

      //TODO better DOS protection, error handling
      //TODO test first than create session
      GNUNET_assert(session_light != NULL);

#if DEBUG_wlan
      GNUNET_log(
          GNUNET_ERROR_TYPE_DEBUG,
          "Func wlan_data_helper got GNUNET_MESSAGE_TYPE_WLAN_ADVERTISEMENT size: %u; %s\n",
          ntohs(hdr->size), wlan_plugin_address_to_string(NULL,
              session_light->addr.mac, 6));
#endif

      if (session_light->session == NULL)
        {
          session_light->session = get_session(plugin, &session_light->addr);
        }
      GNUNET_assert(GNUNET_HELLO_get_id(
              (const struct GNUNET_HELLO_Message *) &hdr[1],
              &(session_light->session->target) ) != GNUNET_SYSERR);

    }

  //FRAGMENT

  else if (ntohs(hdr->type) == GNUNET_MESSAGE_TYPE_WLAN_FRAGMENT)
    {

      GNUNET_assert(session_light != NULL);
      if (session_light->session == NULL)
        {
          session_light->session = search_session(plugin, &session_light->addr);
        }
      session = session_light->session;

      fh = (struct FragmentationHeader *) hdr;
      tempmsg = (char*) &fh[1];

#if DEBUG_wlan
      GNUNET_log(
          GNUNET_ERROR_TYPE_DEBUG,
          "Func wlan_data_helper got GNUNET_MESSAGE_TYPE_WLAN_FRAGMENT with message_id %u with fragment number %i, size: %u; %s\n",
          ntohl(fh->message_id), ntohs(fh->fragment_off_or_num), ntohs(
              hdr->size), wlan_plugin_address_to_string(NULL,
              session_light->addr.mac, 6));
#endif

      if (getcrc16(tempmsg, ntohs(fh->header.size)) != ntohs(fh->message_crc))
        {
          //wrong crc, dispose message
          GNUNET_log(GNUNET_ERROR_TYPE_INFO, "WLAN fragment crc was wrong\n");
          return;
        }

      //if in the session list
      if (session != NULL)
        {
          fragment_bitfield = insert_fragment_in_in_message_queue(plugin,
              session_light, session, fh, rxinfo);
        }
      else
        {
          // new session
          GNUNET_log(
              GNUNET_ERROR_TYPE_INFO,
              "WLAN client not in session list, fragment num %u, message id %u\n",
              ntohs(fh->fragment_off_or_num), ntohl(fh->message_id));

          GNUNET_SERVER_mst_receive(plugin->fragment_tokenizer, session_light,
              tempmsg, ntohs(hdr->size) - sizeof(struct FragmentationHeader),
              GNUNET_YES, GNUNET_NO);
          //wlan_data_message_handler(plugin, session_light,
          //    (struct GNUNET_MessageHeader *) tempmsg);
          session = session_light->session;
          //test if a session was created
          if (session == NULL)
            {
              return;
            }
          setBit((char *) &fragment_bitfield, ntohs(fh->fragment_off_or_num));
        }

      add_ack_for_send(plugin, session, fragment_bitfield, fh);
      set_next_send(plugin);

    }

  //ACK

  else if (ntohs(hdr->type) == GNUNET_MESSAGE_TYPE_WLAN_FRAGMENT_ACK)
    {

#if DEBUG_wlan
      GNUNET_log(
          GNUNET_ERROR_TYPE_DEBUG,
          "Func wlan_data_helper got GNUNET_MESSAGE_TYPE_WLAN_FRAGMENT_ACK size: %u; %s\n",
          ntohs(hdr->size), wlan_plugin_address_to_string(NULL,
              session_light->addr.mac, 6));
#endif

      GNUNET_assert(session_light != NULL);
      if (session_light->session == NULL)
        {
          session_light->session = search_session(plugin, &session_light->addr);
          GNUNET_assert(session_light->session != NULL);
        }
      session = session_light->session;
      fah = (struct FragmentationAckHeader *) hdr;
      fm = get_fragment_message_from_session_and_id(plugin, session, ntohl(
          fah->message_id));

      if (fm != NULL)
        {

          fm->ack_bitfield = fm->ack_bitfield | GNUNET_ntohll(
              fah->fragment_field);
          fm->next_ack = GNUNET_TIME_relative_to_absolute(get_ack_timeout(fm));

#if DEBUG_wlan_retransmission
          GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Got ack for: %u; %u\n",
              fm->message_id_out, fm->ack_bitfield);
#endif
          check_finished_fragment(plugin, fm);
          set_next_send(plugin);

        }
      else
        {
          GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
              "WLAN fragment not in fragment list with id %u of ack\n", ntohl(
                  fah->message_id));
          return;
        }

    }
  else
    {
      // TODO Wrong data?
      GNUNET_log(
          GNUNET_ERROR_TYPE_INFO,
          "WLAN packet inside the WLAN helper packet has not the right type: %u size: %u\n",
          ntohs(hdr->type), ntohs(hdr->size));
      GNUNET_break(0);
      return;
    }

#if 0
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
      "Helper finished\n");
#endif

}

//TODO DOXIGEN
const char *
macprinter(const u_int8_t * mac)
{
  static char macstr[20];

  GNUNET_snprintf(macstr, sizeof(macstr), "%X:%X:%X:%X:%X:%X", mac[0], mac[1],
      mac[2], mac[3], mac[4], mac[5]);
  return macstr;
}

/**
 * Function used for to process the data from the suid process
 *
 * @param cls the plugin handle
 * @param client client that send the data (not used)
 * @param hdr header of the GNUNET_MessageHeader
 */
static void
wlan_process_helper(void *cls, void *client,
    const struct GNUNET_MessageHeader *hdr)
{
  struct Plugin *plugin = cls;
  struct ieee80211_frame * wlanIeeeHeader = NULL;
  struct Session_light * session_light = NULL;
  struct Radiotap_rx * rxinfo;
  const struct GNUNET_MessageHeader * temp_hdr = NULL;

  int datasize = 0;
  int pos;

  switch (ntohs(hdr->type))
    {
  case GNUNET_MESSAGE_TYPE_WLAN_HELPER_DATA:
#if DEBUG_wlan
    GNUNET_log(
        GNUNET_ERROR_TYPE_DEBUG,
        "Func wlan_process_helper got  GNUNET_MESSAGE_TYPE_WLAN_HELPER_DATA size: %u\n",
        ntohs(hdr->size));
#endif

    //call wlan_process_helper with the message inside, later with wlan: analyze signal
    if (ntohs(hdr->size) < sizeof(struct ieee80211_frame)
        + sizeof(struct GNUNET_MessageHeader) + sizeof(struct Radiotap_rx))
      {
#if DEBUG_wlan
        GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
            "Size of packet is too small; size: %u min size: %u\n", ntohs(
                hdr->size), sizeof(struct ieee80211_frame)
            + sizeof(struct GNUNET_MessageHeader));
#endif
        //GNUNET_break (0);
        /* FIXME: restart SUID process */
        return;
      }
    rxinfo = (struct Radiotap_rx *) &hdr[1];
    wlanIeeeHeader = (struct ieee80211_frame *) &rxinfo[1];

    //process only if it is an broadcast or for this computer both with the gnunet bssid

    //check for bssid
    if (memcmp(&(wlanIeeeHeader->i_addr3), &mac_bssid,
        sizeof(struct MacAddress)) == 0)
      {
        //check for broadcast or mac
        if (memcmp(&(wlanIeeeHeader->i_addr1), &bc_all_mac,
            sizeof(struct MacAddress) == 0) || memcmp(
            &(wlanIeeeHeader->i_addr1), &(plugin->mac_address),
            sizeof(struct MacAddress)) == 0)
          {

            // process the inner data


            datasize = ntohs(hdr->size) - sizeof(struct ieee80211_frame)
                - sizeof(struct GNUNET_MessageHeader)
                - sizeof(struct Radiotap_rx);

            session_light = GNUNET_malloc(sizeof(struct Session_light));
            memcpy(&session_light->addr, &(wlanIeeeHeader->i_addr2),
                sizeof(struct MacAddress));
            //session_light->session = search_session(plugin,session_light->addr);

            pos = 0;
            while (pos < datasize)
              {
                temp_hdr = (struct GNUNET_MessageHeader *) &wlanIeeeHeader[1]
                    + pos;

                wlan_data_helper(plugin, session_light, temp_hdr, rxinfo);
                pos += ntohs(temp_hdr->size);

              }

            //clean up
            GNUNET_free(session_light);
          }
        else
          {
#if DEBUG_wlan
            GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                "Func wlan_process_helper got wrong MAC: %s\n", macprinter(
                    wlanIeeeHeader->i_addr1));
#endif
          }
      }
    else
      {
#if DEBUG_wlan
        GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
            "Func wlan_process_helper got wrong BSSID: %s\n", macprinter(
                wlanIeeeHeader->i_addr2));
#endif
      }
    break;
  case GNUNET_MESSAGE_TYPE_WLAN_HELPER_CONTROL:
    //TODO more control messages
    //TODO use struct wlan_helper_control
    if (ntohs(hdr->size) != sizeof(struct Wlan_Helper_Control_Message))
      {
        GNUNET_break (0);
        /* FIXME: restart SUID process */
        return;
      }
    memcpy(&plugin->mac_address, &hdr[1], sizeof(struct MacAddress));
#if DEBUG_wlan
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
        "Received WLAN_HELPER_CONTROL message with transport of address %s\n",
        wlan_plugin_address_to_string(cls, &plugin->mac_address,
            sizeof(struct MacAddress)));
#endif
    plugin->env->notify_address(plugin->env->cls, "wlan", &plugin->mac_address,
        sizeof(struct MacAddress), GNUNET_TIME_UNIT_FOREVER_REL);
    break;
  default:
    GNUNET_break (0);
    return;
    }
}

/**
 * We have been notified that wlan-helper has written something to stdout.
 * Handle the output, then reschedule this function to be called again once
 * more is available.
 *
 * @param cls the plugin handle
 * @param tc the scheduling context
 */
static void
wlan_plugin_helper_read(void *cls,
    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;
  plugin->server_read_task = GNUNET_SCHEDULER_NO_TASK;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  char mybuf[WLAN_MTU + sizeof(struct GNUNET_MessageHeader)];
  ssize_t bytes;

  bytes = GNUNET_DISK_file_read(plugin->server_stdout_handle, mybuf,
      sizeof(mybuf));
  if (bytes <= 0)
    {
#if DEBUG_wlan
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          _("Finished reading from wlan-helper stdout with code: %d\n"),
          bytes);
#endif
      return;
    }
  GNUNET_SERVER_mst_receive(plugin->suid_tokenizer, NULL, mybuf, bytes,
      GNUNET_NO, GNUNET_NO);

  GNUNET_assert(plugin->server_read_task == GNUNET_SCHEDULER_NO_TASK);
  plugin->server_read_task = GNUNET_SCHEDULER_add_read_file(
      GNUNET_TIME_UNIT_FOREVER_REL, plugin->server_stdout_handle,
      &wlan_plugin_helper_read, plugin);
}

/**
 * Start the gnunet-wlan-helper process.
 *
 * @param plugin the transport plugin
 * @param testmode should we use the dummy driver for testing?
 * @return GNUNET_YES if process was started, GNUNET_SYSERR on error
 */
static int
wlan_transport_start_wlan_helper(struct Plugin *plugin, int testmode)
{
  const char * filename = "gnunet-transport-wlan-helper";
  plugin->server_stdout = GNUNET_DISK_pipe(GNUNET_YES, GNUNET_NO, GNUNET_YES);
  if (plugin->server_stdout == NULL)
    return GNUNET_SYSERR;

  plugin->server_stdin = GNUNET_DISK_pipe(GNUNET_YES, GNUNET_YES, GNUNET_NO);
  if (plugin->server_stdin == NULL)
    return GNUNET_SYSERR;

#if DEBUG_wlan
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
      "Starting gnunet-wlan-helper process cmd: %s %s %i\n", filename,
      plugin->interface, testmode);
#endif
  /* Start the server process */

  plugin->server_proc = GNUNET_OS_start_process(plugin->server_stdin,
      plugin->server_stdout, filename, filename, plugin->interface, ((testmode
          == 1) ? "1" : (testmode == 2) ? "2" : "0"), NULL);
  if (plugin->server_proc == NULL)
    {
#if DEBUG_wlan
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Failed to start gnunet-wlan-helper process\n");
#endif
      return GNUNET_SYSERR;
    }

  /* Close the write end of the read pipe */
  GNUNET_DISK_pipe_close_end(plugin->server_stdout, GNUNET_DISK_PIPE_END_WRITE);

  /* Close the read end of the write pipe */
  GNUNET_DISK_pipe_close_end(plugin->server_stdin, GNUNET_DISK_PIPE_END_READ);

  plugin->server_stdout_handle = GNUNET_DISK_pipe_handle(plugin->server_stdout,
      GNUNET_DISK_PIPE_END_READ);
  plugin->server_stdin_handle = GNUNET_DISK_pipe_handle(plugin->server_stdin,
      GNUNET_DISK_PIPE_END_WRITE);

  GNUNET_assert(plugin->server_read_task == GNUNET_SCHEDULER_NO_TASK);

#if DEBUG_wlan
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
      "Adding server_read_task for the wlan-helper\n");
#endif

  plugin->server_read_task = GNUNET_SCHEDULER_add_read_file(
      GNUNET_TIME_UNIT_FOREVER_REL, plugin->server_stdout_handle,
      &wlan_plugin_helper_read, plugin);

  return GNUNET_YES;
}

/**
 * Exit point from the plugin.
 * @param cls pointer to the api struct
 */

//FIXME cleanup
void *
libgnunet_plugin_transport_wlan_done(void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;
  struct Sessionqueue * queue = plugin->sessions;
  struct Sessionqueue * queue_next;
  struct FragmentMessage * fm;

#if DEBUG_wlan
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
      "libgnunet_plugin_transport_wlan_done started\n");
#endif


  GNUNET_OS_process_close(plugin->server_proc);
  GNUNET_DISK_pipe_close(plugin->server_stdout);
  GNUNET_DISK_pipe_close(plugin->server_stdin);

  GNUNET_assert (cls !=NULL);
  //free sessions
  while (queue != NULL)
    {
      queue_next = queue->next;
      free_session(plugin, queue);
      queue = queue_next;

    }
  if (plugin->server_write_delay_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel(plugin->server_write_delay_task);
      plugin->server_write_delay_task = GNUNET_SCHEDULER_NO_TASK;
    }
  if (plugin->server_write_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel(plugin->server_write_task);
      plugin->server_write_task = GNUNET_SCHEDULER_NO_TASK;
    }
  if (plugin->server_read_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel(plugin->server_read_task);
      plugin->server_read_task = GNUNET_SCHEDULER_NO_TASK;
    }


  if (plugin->suid_tokenizer != NULL)
    GNUNET_SERVER_mst_destroy(plugin->suid_tokenizer);

  if (plugin->data_tokenizer != NULL)
    GNUNET_SERVER_mst_destroy(plugin->data_tokenizer);

  if (plugin->fragment_tokenizer != NULL)
    GNUNET_SERVER_mst_destroy(plugin->fragment_tokenizer);

  fm = (struct FragmentMessage *) GNUNET_CONTAINER_heap_peek(
      plugin->pending_Fragment_Messages);

  while (fm != NULL)
    {
      free_fragment_message(plugin, fm);
      fm = (struct FragmentMessage *) GNUNET_CONTAINER_heap_peek(
          plugin->pending_Fragment_Messages);
    }

  GNUNET_free_non_null(plugin->interface);
  GNUNET_CONTAINER_heap_destroy(plugin->pending_Fragment_Messages);
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
libgnunet_plugin_transport_wlan_init(void *cls)
{
  //struct GNUNET_SERVICE_Context *service;
  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  struct Plugin *plugin;
  static unsigned long long testmode = 0;

  GNUNET_assert(cls !=NULL);

  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->env = env;
  plugin->pendingsessions = 0;
  plugin->session_count = 0;
  plugin->server_write_task = GNUNET_SCHEDULER_NO_TASK;
  plugin->server_read_task = GNUNET_SCHEDULER_NO_TASK;
  plugin->server_write_delay_task = GNUNET_SCHEDULER_NO_TASK;
  plugin->pending_Fragment_Messages = GNUNET_CONTAINER_heap_create(
      GNUNET_CONTAINER_HEAP_ORDER_MIN);

  plugin->suid_tokenizer = GNUNET_SERVER_mst_create(&wlan_process_helper,
      plugin);

  plugin->data_tokenizer = GNUNET_SERVER_mst_create(&process_data, plugin);
  plugin->fragment_tokenizer = GNUNET_SERVER_mst_create(
      &wlan_data_message_handler, plugin);

  //plugin->sessions = GNUNET_malloc (sizeof (struct Sessionqueue));
  //plugin->pending_Sessions_head = GNUNET_malloc (sizeof (struct Sessionqueue));

  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
  api->cls = plugin;
  api->send = &wlan_plugin_send;
  api->disconnect = &wlan_plugin_disconnect;
  api->address_pretty_printer = &wlan_plugin_address_pretty_printer;
  api->check_address = &wlan_plugin_address_suggested;
  api->address_to_string = &wlan_plugin_address_to_string;

  //read config

  if (GNUNET_CONFIGURATION_have_value(env->cfg, "transport-wlan", "TESTMODE"))
    {
      if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number(env->cfg,
          "transport-wlan", "TESTMODE", &testmode))
        testmode = 0; //default value
    }

  if (GNUNET_CONFIGURATION_have_value(env->cfg, "transport-wlan", "INTERFACE"))
    {
      if (GNUNET_CONFIGURATION_get_value_string(env->cfg, "transport-wlan",
          "INTERFACE", &(plugin->interface)) != GNUNET_YES)
        {
          libgnunet_plugin_transport_wlan_done(api);
          return NULL;
        }
    }

  //start the plugin
  set_next_beacon_time(plugin);

  wlan_transport_start_wlan_helper(plugin, testmode);

#if DEBUG_wlan
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "wlan init finished\n");
#endif

  return api;
}

/* end of plugin_transport_wlan.c */
