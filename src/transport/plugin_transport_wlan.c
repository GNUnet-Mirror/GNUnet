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

#define DEBUG_wlan GNUNET_YES

#define MESSAGE_LENGHT_UNKNOWN -1
#define NO_MESSAGE_OR_MESSAGE_FINISHED -2


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

  int session_count;

  /**
   * encapsulation to the local wlan server prog
   */

  struct GNUNET_SERVER_MessageStreamTokenizer * consoltoken;


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
  struct Sessionqueue * pending_Sessions;

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

  struct FragmentMessage * pending_Fragment_Messages_head;

  /**
   * Messages in the fragmentation queue, tail
   */

  struct FragmentMessage * pending_Fragment_Messages_tail;

  /**
     * number of pending fragment message
     */

  unsigned int pending_fragment_messages;

  /**
   * time of the next "hello-beacon"
   */

  struct GNUNET_TIME_Absolute beacon_time;

};

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

struct Sessionqueue
{
	struct Sessionqueue * next;
	struct Sessionqueue * prev;
	struct Session * content;
};

/**
 * Queue of ack received for messages send
 */

struct AckQueue
{
	struct AckQueue * next;
	struct AckQueue * prev;
	int fragment_num; //TODO change it to offset if better
};



/**
 * Queue for the fragments received
 */

struct RecQueue
{
        struct RecQueue * next;
        struct RecQueue * prev;
        uint16_t num;
        const char * msg;
        uint16_t size;
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

  /**
   * Size of the message
   */
  size_t message_size;

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
  uint8_t addr[6];
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
   * To whom are we talking to (set to our identity
   * if we are still waiting for the welcome message)
   */
  struct GNUNET_PeerIdentity target;

  /**
   * encapsulation of the receive data
   */
  //struct GNUNET_SERVER_MessageStreamTokenizer * receive_token;

  /**
   * offset of the next fragment for the receive_token, -1 means last message finished
   */

  //int rec_offset;

  /**
   * size of the message received,
   * MESSAGE_LENGHT_UNKNOWN means that the size is not known,
   * NO_MESSAGE_OR_MESSAGE_FINISHED means no message received
   */

  int rec_size;

  /**
   * Sorted queue with the fragments received; head
   */

  struct RecQueue * frag_head;

  /**
   * Sorted queue with the fragments received; tail
   */

  struct RecQueue * frag_tail;

  /**
   * peer mac address
   */
  char addr[6];

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
   * current number for message incoming, to distinguish between the messages
   */
  uint32_t message_id_in;

  /**
   * current number for message outgoing, to distinguish between the messages
   */
  uint32_t message_id_out;

  /**
   * does this session have a message in the fragment queue
   */

  int has_fragment;

};




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
	* The pending message
	*/
	char *msg;

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
	* Sorted queue with the acks received for fragments; head
	*/

	struct AckQueue * head;

	/**
	* Sorted queue with the acks received for fragments; tail
	*/

	struct AckQueue * tail;

	/**
	* Size of the message
	*/
	size_t message_size;

	/**
	* pos / next fragment number in the message, for fragmentation/segmentation,
	* some acks can be missing but there is still time
	*/
	uint32_t message_pos;

};

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

  // followed by payload

};

/**
 * Header for messages which need fragmentation
 */
struct FragmentationHeader
{

  struct GNUNET_MessageHeader header;

  /**
   * To whom are we talking to (set to our identity
   * if we are still waiting for the welcome message)
   */
  // struct GNUNET_PeerIdentity target GNUNET_PACKED;

  /**
   * ID of message, to distinguish between the messages, picked randomly.
   */
  uint32_t message_id GNUNET_PACKED;

  /**
   * Offset or number of this fragment, for fragmentation/segmentation (design choice, TBD)
   */
  uint16_t fragment_off_or_num GNUNET_PACKED;

  /**
   * CRC of fragment (for error checking)
   */
  uint16_t message_crc GNUNET_PACKED;

  /**
   * Flags
   * // 0x1 ack => Use two different message types in header.type! (FRAG_MESSAGE; FRAG_ACK)
   * // 0x2 has data (not only ack)
   * // 0x4 last fragment of message
   * // 0x8 new message
   */
  //  uint32_t flags GNUNET_PACKED;

  /**
   * checksum/error correction
   */
  // uint32_t crc GNUNET_PACKED;

  // followed by payload unless ACK

};

//enum { ACK_FRAGMENT = 1, DATA_FRAGMENT = 2, LAST_FRAGMENT = 4, NEW_MESSAGE = 8 };

int
getRadiotapHeader(struct RadiotapHeader * Header);

int
getWlanHeader(struct IeeeHeader * Header);

static int
wlan_plugin_address_suggested(void *cls, const void *addr, size_t addrlen);

uint16_t
getcrc16(const char *msgbuf, size_t msgbuf_size);

static void
do_transmit(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

static void
check_fragment_queue(struct Plugin * plugin);

uint32_t
getcrc32(const char *msgbuf, size_t msgbuf_size);

static void
free_rec_frag_queue(struct Session * session);

static void
wlan_data_helper(void *cls, void * client, const struct GNUNET_MessageHeader * hdr);

static void
wlan_process_helper (void *cls,
                      void *client,
                      const struct GNUNET_MessageHeader *hdr);

static void
finish_sending(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

/**
 * get the next message number, at the moment just a random one
 * @return returns the next valid message-number for sending packets
 */
uint32_t
get_next_message_id()
{
  return GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_NONCE, UINT32_MAX);
}

/**
 * start next message number generator
 * (not necessary at the moment)
 */
void
start_next_message_id()
{
  //GNUNET_CRYPTO_random_init;
}

/**
 * search for a session with the addr
 *
 * @param plugin pointer to the plugin struct
 * @param addr pointer to the mac address of the peer
 * @return returns the session
 */

static struct Session *
search_session(struct Plugin *plugin, const uint8_t * addr)
{
  struct Sessionqueue * queue = plugin->sessions;
  struct Sessionqueue * lastitem = NULL;

  //just look at all the session for the needed one
  while (queue != NULL)
    {
      // content is never NULL
      GNUNET_assert (queue->content != NULL);
      char * addr2 = queue->content->addr;
      if (memcmp(addr, addr2, 6) == 0)
        {
          //sesion found
          return queue->content;
        }
      // try next
      lastitem = queue;
      queue = queue->next;
    }
  return NULL;
}

/**
 * create a new session
 *
 * @param plugin pointer to the plugin struct
 * @param addr pointer to the mac address of the peer
 * @return returns the session
 */

static struct Session *
create_session(struct Plugin *plugin,const uint8_t * addr)
{
  struct Sessionqueue * queue = GNUNET_malloc (sizeof (struct Sessionqueue));

  GNUNET_CONTAINER_DLL_insert_tail(plugin->sessions, plugin->sessions_tail, queue);

  queue->content = GNUNET_malloc (sizeof (struct Session));
  queue->content->plugin = plugin;
  memcpy(queue->content->addr, addr, 6);
  queue->content->message_id_out = get_next_message_id();
  queue->content->has_fragment = 0;
  queue->content->rec_size = NO_MESSAGE_OR_MESSAGE_FINISHED;

  plugin->session_count++;
  return queue->content;
}

/**
 * get Session from address, create if no session exists
 *
 * @param plugin pointer to the plugin struct
 * @param addr pointer to the mac address of the peer
 * @return returns the session
 */
//TODO add other possibilities to find the right session (are there other?)
static struct Session *
get_Session(struct Plugin *plugin, const uint8_t * addr)
{
  struct Session * session = search_session(plugin, addr);
  if (session != NULL)
    {
      return session;
    }
  // new session
  return create_session(plugin, addr);

  /* -- not needed, layer above already has it--
   //queue welcome message for new sessions, not realy needed
   //struct WelcomeMessage welcome;
   struct PendingMessage *pm;
   pm = GNUNET_malloc (sizeof (struct PendingMessage));
   pm->msg = GNUNET_malloc(GNUNET_HELLO_size(* (plugin->env->our_hello)));
   pm->message_size = GNUNET_HELLO_size(* (plugin->env->our_hello));
   //welcome.header.size = htons (GNUNET_HELLO_size(* (plugin->env->our_hello)));
   //welcome.header.type = htons (GNUNET_MESSAGE_TYPE_WLAN_ADVERTISEMENT);
   //welcome.clientIdentity = *plugin->env->my_identity;
   memcpy ( (pm->msg), * plugin->env->our_hello, GNUNET_HELLO_size(* (plugin->env->our_hello)));
   pm->timeout = GNUNET_TIME_UNIT_FOREVER_ABS;
   queue->content->pending_message = pm;
   plugin->pendingsessions ++;
   GNUNET_CONTAINER_DLL_insert_tail(plugin->pending_Sessions, plugin->pending_Sessions_tail, queue);

   check_fragment_queue(plugin);
   */
}

/**
 * Queue the session to send data
 */
//TODO doxigen
static void
queue_Session (struct Plugin *plugin,
		struct Session * session)
{
	struct Sessionqueue * queue = plugin->pending_Sessions;
	struct Sessionqueue * lastitem = NULL;

	while (queue != NULL){
		// content is never NULL
		GNUNET_assert (queue->content == NULL);
		// is session already in queue?
		if (session == queue->content){
			return;
		}
		// try next
		lastitem = queue;
		queue = queue->next;
	}

	// Session is not in the queue

	queue = GNUNET_malloc (sizeof (struct Sessionqueue));
	queue->content = session;

	//insert at the tail
	GNUNET_CONTAINER_DLL_insert_after (plugin->pending_Sessions,
			plugin->pending_Sessions_tail,
			plugin->pending_Sessions_tail, queue);
	plugin->pendingsessions ++;

}

//TODO doxigen
static void
free_acks (struct FragmentMessage * fm){
	struct AckQueue * fq;
	while (fm->head != NULL){
		fq = fm->head;
		GNUNET_CONTAINER_DLL_remove(fm->head, fm->tail, fq);
		GNUNET_free(fq);
	}
	//needed?
	fm->head = NULL;
	fm->tail = NULL;
}

//TODO doxigen
/**
 * Function to schedule the write task, executed after a delay
 */
static void
delay_fragment_task(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin * plugin = cls;
  plugin->server_write_delay_task = GNUNET_SCHEDULER_NO_TASK;

  if (tc->reason == GNUNET_SCHEDULER_REASON_SHUTDOWN)
    return;

  // GNUNET_TIME_UNIT_FOREVER_REL is needed to clean up old msg
  if (plugin->server_write_task == GNUNET_SCHEDULER_NO_TASK)
    {
      plugin->server_write_task = GNUNET_SCHEDULER_add_write_file(
          GNUNET_TIME_UNIT_FOREVER_REL, plugin->server_stdin_handle,
          &do_transmit, plugin);
    }
}

//TODO doxigen
/**
 * Function to calculate the time of the next periodic "hello-beacon"
 */
static void
set_next_beacon_time(struct Plugin * const plugin)
{
  //under 10 known peers: once a second
  if (plugin->session_count < 10)
    {
      plugin->beacon_time = GNUNET_TIME_absolute_add(
          GNUNET_TIME_absolute_get(), GNUNET_TIME_UNIT_SECONDS);
    }
  //under 30 known peers: every 10 seconds
  else if (plugin->session_count < 30)
    {
      plugin->beacon_time = GNUNET_TIME_absolute_add(
          GNUNET_TIME_absolute_get(), GNUNET_TIME_relative_multiply(
              GNUNET_TIME_UNIT_SECONDS, 10));
    }
  //over 30 known peers: once a minute
  else
    {
      plugin->beacon_time = GNUNET_TIME_absolute_add(
          GNUNET_TIME_absolute_get(), GNUNET_TIME_UNIT_MINUTES);
    }
}


//TODO doxigen
struct GNUNET_TIME_Relative
get_next_frag_timeout(struct FragmentMessage * fm)
{
  return GNUNET_TIME_relative_min(GNUNET_TIME_absolute_get_remaining(
      fm->next_ack), GNUNET_TIME_absolute_get_remaining(fm->timeout));
}

//TODO doxigen
/**
 * Function to get the timeout value for acks for this session
 */

struct GNUNET_TIME_Relative
get_ack_timeout (struct FragmentMessage * fm){
	return FRAGMENT_TIMEOUT;
}


/**
 * Function to set the timer for the next timeout of the fragment queue
 * @param plugin the handle to the plugin struct
 */
static void
check_next_fragment_timeout(struct Plugin * const plugin)
{
  struct FragmentMessage * fm;
  struct GNUNET_TIME_Relative next_send;

  next_send = GNUNET_TIME_absolute_get_remaining(plugin->beacon_time);

  //cancel old task
  if (plugin->server_write_delay_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel(plugin->server_write_delay_task);
    }
  fm = plugin->pending_Fragment_Messages_head;

  GNUNET_assert(plugin->server_write_delay_task == GNUNET_SCHEDULER_NO_TASK);

  //check if there are some fragments in the queue
  if (fm != NULL)
    {
      next_send
          = GNUNET_TIME_relative_min(next_send, get_next_frag_timeout(fm));
    }
  plugin->server_write_delay_task = GNUNET_SCHEDULER_add_delayed(next_send,
      &delay_fragment_task, plugin);
}



//TODO doxigen
/**
 * Function to get the next queued Session, removes the session from the queue
 */

static struct Session *
get_next_queue_Session (struct Plugin * plugin){
	struct Session * session;
	struct Sessionqueue * sessionqueue;
	struct Sessionqueue * sessionqueue_alt;
	struct PendingMessage * pm;
	sessionqueue = plugin->pending_Sessions;
	while (sessionqueue != NULL){
		session = sessionqueue->content;
		pm = session->pending_message;

		//check for message timeout
		if (GNUNET_TIME_absolute_get_remaining(pm->timeout).rel_value > 0){
			//check if session has no message in the fragment queue
			if (! session->has_fragment){
				plugin->pendingsessions --;
				GNUNET_CONTAINER_DLL_remove (plugin->pending_Sessions,
						plugin->pending_Sessions_tail, sessionqueue);
				GNUNET_free(sessionqueue);

				return session;
			} else {
				sessionqueue = sessionqueue->next;
			}
		} else {

			session->pending_message = NULL;
			//call the cont func that it did not work
			if (pm->transmit_cont != NULL)
			  pm->transmit_cont (pm->transmit_cont_cls,
						&(session->target), GNUNET_SYSERR);
			GNUNET_free(pm->msg);
			GNUNET_free(pm);

			sessionqueue_alt = sessionqueue;
			sessionqueue = sessionqueue->next;
			plugin->pendingsessions --;
			GNUNET_CONTAINER_DLL_remove (plugin->pending_Sessions,
					plugin->pending_Sessions_tail, sessionqueue_alt);

			GNUNET_free(sessionqueue_alt);

		}


	}
	return NULL;
}


/**
 * Function to sort the message into the message fragment queue
 * @param plugin the plugin struct
 * @param fm message to sort into the queue
 */
static void
sort_fragment_into_queue (struct Plugin * plugin, struct FragmentMessage * fm){
	struct FragmentMessage * fm2;
	//sort into the list at the right position

	fm2 = plugin->pending_Fragment_Messages_head;

	while (fm2 != NULL){
		if (GNUNET_TIME_absolute_get_difference(fm2->next_ack, fm->next_ack).rel_value == 0){
			break;
		} else {
			fm2 = fm2->next;
		}
	}

	GNUNET_CONTAINER_DLL_insert_after(plugin->pending_Fragment_Messages_head,
			plugin->pending_Fragment_Messages_tail,fm2,fm);
}

/**
 * frees the space of a message in the fragment queue (send queue)
 * @param plugin the plugin struct
 * @param fm message to free
 */
static void
free_fragment_message(struct Plugin * plugin,struct FragmentMessage * fm)
{
  if (fm != NULL)
    {
      free_acks(fm);
      GNUNET_free_non_null(fm->msg);
      GNUNET_CONTAINER_DLL_remove (plugin->pending_Fragment_Messages_head,
          plugin->pending_Fragment_Messages_tail, fm);
      GNUNET_free(fm);
      plugin->pending_fragment_messages --;
      check_fragment_queue(plugin);
    }
}

/**
 * Function to check if there is some space in the fragment queue
 * inserts a message if space is available
 * @param plugin the plugin struct
 */

static void
check_fragment_queue (struct Plugin * plugin){
	struct Session * session;
	struct FragmentMessage * fm;

	struct PendingMessage * pm;

	if (plugin->pending_fragment_messages < FRAGMENT_QUEUE_SIZE){
		session = get_next_queue_Session(plugin);
		if (session != NULL){
			pm = session->pending_message;
			session->pending_message = NULL;
			session->has_fragment = 1;
			GNUNET_assert(pm != NULL);

			fm = GNUNET_malloc(sizeof(struct FragmentMessage));
			fm->message_size = pm->message_size;
			fm->msg = pm->msg;
			fm->session = session;
			fm->timeout.abs_value = pm->timeout.abs_value;
			fm->message_pos = 0;
			fm->next_ack = GNUNET_TIME_absolute_get();

			if (pm->transmit_cont != NULL)
				  pm->transmit_cont (pm->transmit_cont_cls,
							&(session->target), GNUNET_OK);
			GNUNET_free(pm);

			sort_fragment_into_queue(plugin,fm);
			plugin->pending_fragment_messages ++;

			//generate new message id
			session->message_id_out = get_next_message_id();

			//check if timeout changed
			check_next_fragment_timeout(plugin);
		}
	}
}

/**
 * Funktion to check if all fragments where send and the acks received
 * frees the space if finished
 * @param plugin the plugin struct
 * @param fm the message to check
 */
static void
check_finished_fragment(struct Plugin * plugin, struct FragmentMessage * fm){
  struct AckQueue * ack;
  int counter = 0;

  if (fm->message_size >= (WLAN_MTU - sizeof(struct FragmentationHeader))
      * fm->tail->fragment_num)
    {
      ack = fm->head;
      counter = 0;
      //check if all acks are present
      while (ack != NULL)
        {
          if (counter == ack->fragment_num)
            {
              counter ++;
              ack = ack->next;
            } else {
              //ack is missing
              return;
            }
        }
      fm->session->has_fragment = 0;
      free_fragment_message(plugin, fm);


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

  ssize_t bytes;

  if (tc->reason == GNUNET_SCHEDULER_REASON_SHUTDOWN)
    return;

  struct Session * session = NULL;
  struct FragmentMessage * fm = NULL;
  struct IeeeHeader * ieeewlanheader = NULL;
  struct RadiotapHeader * radioHeader = NULL;
  struct GNUNET_MessageHeader * msgheader = NULL;

  struct FragmentationHeader fragheader;
  struct FragmentationHeader * fragheaderptr = NULL;
  struct Finish_send * finish = NULL;
  uint16_t size = 0;
  const char * copystart = NULL;
  uint16_t copysize = 0;
  uint copyoffset = 0;
  struct AckQueue * akt = NULL;

#if 0
  struct GNUNET_MessageHeader * msgheader2 = NULL;

  //test if a "hello-beacon" has to be send
  if (GNUNET_TIME_absolute_get_remaining(plugin->beacon_time).rel_value == 0)
    {
      //check if the message is not to big
      GNUNET_assert(sizeof(struct WlanHeader) + GNUNET_HELLO_size(
              *(plugin->env->our_hello)) <= WLAN_MTU);
      size = sizeof(struct GNUNET_MessageHeader)
          + sizeof(struct RadiotapHeader) + sizeof(struct IeeeHeader)
          + sizeof(struct GNUNET_MessageHeader) + GNUNET_HELLO_size(
          *(plugin->env->our_hello));

      msgheader = GNUNET_malloc(size);
      msgheader->size = htons(size);
      msgheader->type = htons(GNUNET_MESSAGE_TYPE_WLAN_HELPER_DATA);

      radioHeader = (struct RadiotapHeader *) &msgheader[1];
      getRadiotapHeader(radioHeader);

      ieeewlanheader = (struct IeeeHeader *) &radioHeader[1];
      getWlanHeader(ieeewlanheader);

      msgheader2 = (struct GNUNET_MessageHeader *) &ieeewlanheader[1];
      msgheader2->size = htons(GNUNET_HELLO_size(*(plugin->env->our_hello))
          + sizeof(struct GNUNET_MessageHeader));
      msgheader2->type = htons(GNUNET_MESSAGE_TYPE_WLAN_ADVERTISEMENT);

      memcpy(&msgheader2[1], *plugin->env->our_hello, GNUNET_HELLO_size(
          *(plugin->env->our_hello)));

      bytes = GNUNET_DISK_file_write(plugin->server_stdin_handle, msgheader,
          size);
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
      check_next_fragment_timeout(plugin);

      return;

    }

#endif

  fm = plugin->pending_Fragment_Messages_head;
  GNUNET_assert(fm != NULL);
  session = fm->session;
  GNUNET_assert(session != NULL);

  // test if message timed out
  if (GNUNET_TIME_absolute_get_remaining(fm->timeout).rel_value == 0)
    {
      free_acks(fm);
      GNUNET_assert(plugin->pending_fragment_messages > 0);
      plugin->pending_fragment_messages--;
      GNUNET_CONTAINER_DLL_remove(plugin->pending_Fragment_Messages_head,
          plugin->pending_Fragment_Messages_tail, fm);

      GNUNET_free(fm->msg);

      GNUNET_free(fm);
      check_fragment_queue(plugin);
    }
  else
    {

      if (fm->message_size > WLAN_MTU)
        {
          size += sizeof(struct FragmentationHeader);
          // check/set for retransmission
          if (GNUNET_TIME_absolute_get_duration(fm->next_ack).rel_value == 0)
            {

              // be positive and try again later :-D
              fm->next_ack = GNUNET_TIME_relative_to_absolute(get_ack_timeout(
                  fm));
              // find first missing fragment
              akt = fm->head;
              fm->message_pos = 0;

              //test if ack 0 was already received
              while (akt != NULL)
                {
                  //if fragment is present, take next
                  if (akt->fragment_num == fm->message_pos)
                    {
                      fm->message_pos++;
                    }
                  //next ack is bigger then the fragment number
                  //in case there is something like this: (acks) 1, 2, 5, 6, ...
                  //and we send 3 again, the next number should be 4
                  else if (akt->fragment_num > fm->message_pos)
                    {
                      break;
                    }

                  akt = akt->next;

                }

            }

          copyoffset = (WLAN_MTU - sizeof(struct FragmentationHeader))
              * fm->message_pos;
          fragheader.fragment_off_or_num = htons(fm->message_pos);
          fragheader.message_id = htonl(session->message_id_out);

          // start should be smaller then the packet size
          GNUNET_assert(copyoffset < fm->message_size);
          copystart = fm->msg + copyoffset;

          //size of the fragment is either the MTU - overhead
          //or the missing part of the message in case this is the last fragment
          copysize = GNUNET_MIN(fm->message_size - copyoffset,
              WLAN_MTU - sizeof(struct FragmentationHeader));
          fragheader.header.size = htons(copysize
              + sizeof(struct FragmentationHeader));
          fragheader.header.type = htons(GNUNET_MESSAGE_TYPE_WLAN_FRAGMENT);

          //get the next missing fragment
          akt = fm->head;
          fm->message_pos++;

          //test if ack was already received
          while (akt != NULL)
            {
              //if fragment is present, take next
              if (akt->fragment_num == fm->message_pos)
                {
                  fm->message_pos++;
                }
              //next ack is bigger then the fragment number
              //in case there is something like this: (acks) 1, 2, 5, 6, ...
              //and we send 3 again, the next number should be 4
              else if (akt->fragment_num > fm->message_pos)
                {
                  break;
                }

              akt = akt->next;
            }
        }
      else
        {
          // there is no need to split
          copystart = fm->msg;
          copysize = fm->message_size;
        }

      size += copysize;
      size += sizeof(struct RadiotapHeader) + sizeof(struct IeeeHeader)
          + sizeof(struct GNUNET_MessageHeader);
      msgheader = GNUNET_malloc(size);
      msgheader->size = htons(size);
      msgheader->type = htons(GNUNET_MESSAGE_TYPE_WLAN_HELPER_DATA);

      radioHeader = (struct RadiotapHeader*) &msgheader[1];
      getRadiotapHeader(radioHeader);

      ieeewlanheader = (struct IeeeHeader *) &radioHeader[1];
      getWlanHeader(ieeewlanheader);

      //could be faster if content is just send and not copyed before
      //fragmentheader is needed
      if (fm->message_size > WLAN_MTU)
        {
          fragheader.message_crc = htons(getcrc16(copystart, copysize));
          memcpy(&ieeewlanheader[1], &fragheader,
              sizeof(struct FragmentationHeader));
          fragheaderptr = (struct FragmentationHeader *) &ieeewlanheader[1];
          memcpy(&fragheaderptr[1], copystart, copysize);
        }
      else
        {
          memcpy(&ieeewlanheader[1], copystart, copysize);
        }

      bytes = GNUNET_DISK_file_write(plugin->server_stdin_handle, msgheader, size);
      if (bytes == GNUNET_SYSERR){
        GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
            _("Error writing to wlan healper. errno == %d, ERROR: %s\n"), errno, strerror(errno) );

      }
      GNUNET_assert(bytes != GNUNET_SYSERR);

      if (bytes != size)
        {
          finish = GNUNET_malloc(sizeof( struct Finish_send));
          finish->plugin = plugin;
          finish->msgheader = (char * ) msgheader + bytes;
          finish->size = size - bytes;
          finish->msgstart = msgheader;

          GNUNET_assert(plugin->server_write_task == GNUNET_SCHEDULER_NO_TASK);

          plugin->server_write_task = GNUNET_SCHEDULER_add_write_file(
              GNUNET_TIME_UNIT_FOREVER_REL, plugin->server_stdin_handle,
              &finish_sending, finish);

        }
      else
        {
          GNUNET_assert(bytes == size);

          GNUNET_free(msgheader);
          check_next_fragment_timeout(plugin);
        }

      //check if this was the last fragment of this message, if true then queue at the end of the list
      if (copysize + copyoffset >= fm->message_size)
        {
          GNUNET_assert(copysize + copyoffset == fm->message_size);

          GNUNET_CONTAINER_DLL_remove (plugin->pending_Fragment_Messages_head,
              plugin->pending_Fragment_Messages_tail, fm);

          GNUNET_CONTAINER_DLL_insert_tail(plugin->pending_Fragment_Messages_head,
              plugin->pending_Fragment_Messages_tail, fm);
          // if fragments have opimized timeouts
          //sort_fragment_into_queue(plugin,fm);

        }

    }
}


static void
finish_sending(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Finish_send * finish;
  struct Plugin * plugin;
  ssize_t bytes;

  finish = cls;
  plugin = finish->plugin;

  plugin->server_write_task = GNUNET_SCHEDULER_NO_TASK;

  bytes = GNUNET_DISK_file_write(plugin->server_stdin_handle, finish->msgheader, finish->size);
  GNUNET_assert(bytes != GNUNET_SYSERR);

  GNUNET_assert(plugin->server_write_task == GNUNET_SCHEDULER_NO_TASK);
  if (bytes != finish->size)
    {

      finish->plugin = plugin;
      finish->msgheader = finish->msgheader + bytes;
      finish->size = finish->size - bytes;
      plugin->server_write_task = GNUNET_SCHEDULER_add_write_file(
          GNUNET_TIME_UNIT_FOREVER_REL, plugin->server_stdin_handle,
          &finish_sending, finish);
    }
  else
    {
      GNUNET_free(finish->msgstart);
      GNUNET_free(finish);
      check_next_fragment_timeout(plugin);
    }

}

int
getRadiotapHeader(struct RadiotapHeader * Header){
  return GNUNET_YES;
};

int
getWlanHeader(struct IeeeHeader * Header){

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
getcrc32 (const char *msgbuf,
		  size_t msgbuf_size){
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
getcrc16 (const char *msgbuf,
		  size_t msgbuf_size){
	//TODO calc some crc
	return 0;
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
wlan_plugin_send (void *cls,
		  const struct GNUNET_PeerIdentity * target,
		  const char *msgbuf,
		  size_t msgbuf_size,
		  unsigned int priority,
		  struct GNUNET_TIME_Relative timeout,
		  struct Session *session,
		  const void *addr,
		  size_t addrlen,
		  int force_address,
		  GNUNET_TRANSPORT_TransmitContinuation cont,
		  void *cont_cls)
{
  struct Plugin * plugin = cls;
  struct PendingMessage * newmsg = NULL;
  struct WlanHeader * wlanheader = NULL;
  //check if msglen > 0
  GNUNET_assert(msgbuf_size > 0);

  //get session if needed
  if (session == NULL)
    {
      if (wlan_plugin_address_suggested(plugin, addr, addrlen) == GNUNET_OK)
        {
          session = get_Session(plugin, addr);
        }
      else
        {
          GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
              _("Wlan Address len %d is wrong\n"), addrlen);
          return -1;
        }
    }

  //TODO target "problem" not solved
  session->target = *target;

  //queue message:
  //first queue session
  queue_Session(plugin, session);

  //queue message in session
  //test if there is no other message in the "queue"
  GNUNET_assert (session->pending_message == NULL);

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
  newmsg->message_size = msgbuf_size + sizeof(struct WlanHeader);

  session->pending_message = newmsg;

  check_fragment_queue(plugin);
  //FIXME not the correct size
  return msgbuf_size;

}

//TODO doxigen
static struct FragmentMessage *
get_fragment_message_from_session(struct Session * session)
{
  struct FragmentMessage * fm = session->plugin->pending_Fragment_Messages_head;
  while (fm != NULL)
    {
      if (fm->session == session)
        {
          return fm;
        }
      fm = fm->next;
    }
  return NULL;
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
  struct Sessionqueue * pendingsession = plugin->pending_Sessions;
  struct PendingMessage * pm = NULL;
  struct FragmentMessage * fm;

  // just look at all the session for the needed one
  while (queue != NULL)
    {
      // content is never NULL
      GNUNET_assert (queue->content != NULL);
      if (memcmp(target, &(queue->content->target),
          sizeof(struct GNUNET_PeerIdentity)) == 0)
        {
          //session found
          //is this session pending for send
          while (pendingsession != NULL)
            {
              if (pendingsession->content == queue->content)
                {
                  plugin->pendingsessions --;
                  GNUNET_CONTAINER_DLL_remove (plugin->pending_Sessions,
                      plugin->pending_Sessions_tail, pendingsession);
                  GNUNET_free(pendingsession);
                  break;
                }
              pendingsession = pendingsession->next;
            }

          //is something of this session in the fragment queue?
          fm = get_fragment_message_from_session(queue->content);
          free_fragment_message(plugin,fm);

          //dispose all received fragments
          free_rec_frag_queue(queue->content);

          // remove PendingMessage
          pm = queue->content->pending_message;
          GNUNET_free(pm->msg);
          GNUNET_free(pm);

          GNUNET_free(queue->content);
          GNUNET_CONTAINER_DLL_remove(plugin->sessions, plugin->sessions_tail, queue);
          GNUNET_free(queue);
          plugin->session_count --;

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
wlan_plugin_address_pretty_printer (void *cls,
				    const char *type,
				    const void *addr,
				    size_t addrlen,
				    int numeric,
				    struct GNUNET_TIME_Relative timeout,
				    GNUNET_TRANSPORT_AddressStringCallback
				    asc, void *asc_cls)
{
  char ret[92];
  const unsigned char * input;
  
  GNUNET_assert(cls !=NULL);
  if (addrlen != 6)
    {
      /* invalid address (MAC addresses have 6 bytes) */
      GNUNET_break (0);
      asc (asc_cls, NULL);
      return;
    }
  input = (const unsigned char*) addr;
  GNUNET_snprintf (ret, 
		   sizeof (ret),
		   "%s Mac-Adress %X:%X:%X:%X:%X:%X",
		   PROTOCOL_PREFIX, 
		   input[0], input[1], input[2], input[3], input[4], input[5]);  
  asc (asc_cls, ret);
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
wlan_plugin_address_suggested (void *cls,
				   const void *addr,
				   size_t addrlen)
{
  //struct Plugin *plugin = cls;

  /* check if the address is plausible; if so,
     add it to our list! */

  GNUNET_assert(cls !=NULL);
  //FIXME mitm is not checked
  //Mac Adress has 6 bytes
  if (addrlen == 6){
    /* TODO check for bad addresses like milticast, broadcast, etc */
    return GNUNET_OK;
  } else {
    return GNUNET_SYSERR;
  }

  return GNUNET_SYSERR;
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
wlan_plugin_address_to_string (void *cls,
			       const void *addr,
			       size_t addrlen)
{
  char ret[92];
  const unsigned char * input;
  
  GNUNET_assert(cls !=NULL);
  if (addrlen != 6)
    {
      /* invalid address (MAC addresses have 6 bytes) */
      GNUNET_break (0);
      return NULL;
    }
  input = (const unsigned char*) addr;
  GNUNET_snprintf (ret, 
		   sizeof (ret),
		   "%s Mac-Adress %X:%X:%X:%X:%X:%X",
		   PROTOCOL_PREFIX, 
		   input[0], input[1], input[2], input[3], input[4], input[5]);  
  return GNUNET_strdup (ret);
}

/**
 * Function to test if fragment number already exists in the fragments received
 *
 * @param session session the fragment belongs to
 * @param fh Fragmentheader of the fragment
 * @return GNUNET_YES if fragment exists already, GNUNET_NO if it does not exists in the queue of the session
 */

static const int
is_double_msg(struct Session * session, struct FragmentationHeader * fh)
{
  struct RecQueue * rec_queue = session->frag_head;
  while (rec_queue != NULL)
    {
      if (rec_queue->num == fh->fragment_off_or_num)
        {
          return GNUNET_YES;
        }
      rec_queue = rec_queue->next;

    }
  return GNUNET_NO;
}

/**
 * Function to insert a fragment in a queue of a session
 * @param session session the fragment belongs to
 * @param rec_queue fragment to add
 */

static void
insert_fragment_in_queue(struct Session * session, struct RecQueue * rec_queue)
{
  struct RecQueue * rec_queue2 = session->frag_head;
  struct WlanHeader * wlanheader = NULL;
  //first received fragment of message
  if (session->rec_size == NO_MESSAGE_OR_MESSAGE_FINISHED)
    {
      session->rec_size = MESSAGE_LENGHT_UNKNOWN;
    }
  //this is the first fragment of the message (fragment id 0)
  if (rec_queue->num == 0)
    {
      wlanheader = (struct WlanHeader *) rec_queue->msg;
      session->rec_size = wlanheader->header.size;
    }

  //sort into list
  while (rec_queue2 != NULL)
    {
      if (rec_queue2->num > rec_queue->num)
        {
          //next element number is grater than the current num
          GNUNET_CONTAINER_DLL_insert_before(session->frag_head, session->frag_tail, rec_queue2, rec_queue);
          return;
        }
      rec_queue = rec_queue->next;
    }
  //no element has a grater number
  GNUNET_CONTAINER_DLL_insert_tail(session->frag_head, session->frag_tail, rec_queue);
}

/**
 * Function to dispose the fragments received for a message
 * @param session session to free the fragments from
 */

static void
free_rec_frag_queue(struct Session * session)
{
  struct RecQueue * rec_queue = session->frag_head;
  struct RecQueue * rec_queue2;
  while (rec_queue != NULL)
    {
      rec_queue2 = rec_queue;
      rec_queue = rec_queue->next;
      GNUNET_free(rec_queue2);
    }
  session->frag_head = NULL;
  session->frag_tail = NULL;
  session->rec_size = NO_MESSAGE_OR_MESSAGE_FINISHED;
}

/**
 * Function to check if all fragments of a message have been received
 * @param plugin the plugin handle
 * @param session_light information of the message sender
 * @param session session the message belongs to
 */

static void
check_rec_finished_msg (struct Plugin* plugin, struct Session_light * session_light, struct Session * session){
  struct RecQueue * rec_queue = session->frag_head;
  int packetsize = session->rec_size;
  int sum = 0;
  int aktnum = 0;
  char * msg;
  //some fragment should be received
  GNUNET_assert(session->rec_size != NO_MESSAGE_OR_MESSAGE_FINISHED);
  //check if first fragment is present
  if (session->rec_size == MESSAGE_LENGHT_UNKNOWN){
    return;
  }
  while (rec_queue != NULL){
    sum += rec_queue->size;
    //check if all fragment numbers are present
    if (rec_queue->num != aktnum){
      return;
    }
    aktnum ++;
    rec_queue = rec_queue->next;
  }
  //sum should always be smaller or equal of
  GNUNET_assert(sum <= packetsize);
  if(sum == packetsize){

#if DEBUG_wlan
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "check_rec_finished_msg: A message with fragments is complete\n");
#endif

    //copy fragments together
    msg = GNUNET_malloc(packetsize);
    rec_queue = session->frag_head;
    aktnum = 0;
    while (rec_queue != NULL){
      memcpy(msg + aktnum, rec_queue->msg, rec_queue->size);
      aktnum += rec_queue->size;
      rec_queue = rec_queue->next;
    }
    free_rec_frag_queue(session);
    //call wlan_process_helper to process the message
    wlan_data_helper (plugin, session_light, (struct GNUNET_MessageHeader*) msg);

    GNUNET_free(msg);
  }
}

/**
 * Function used for to process the data received from the wlan interface
 *
 * @param cls the plugin handle
 * @param client client which send the data (not used)
 * @param hdr hdr of the GNUNET_MessageHeader
 */
static void
wlan_data_helper(void *cls, void * client, const struct GNUNET_MessageHeader * hdr)
{
  struct Plugin *plugin = cls;
  struct Session * session = NULL;
  struct Session_light * session_light = NULL;

  struct WlanHeader * wlanheader = NULL;
  struct FragmentationHeader * fh = NULL;
  struct FragmentMessage * fm = NULL;

  const char * tempmsg = NULL;

  struct AckQueue * ack = NULL;
  struct AckQueue * ack2 = NULL;

  struct RecQueue * rec_queue = NULL;
  const struct GNUNET_MessageHeader * temp_hdr = NULL;

  if (ntohs(hdr->type) == GNUNET_MESSAGE_TYPE_WLAN_ADVERTISEMENT)
    {

#if DEBUG_wlan
      GNUNET_log(
          GNUNET_ERROR_TYPE_DEBUG,
          "Func wlan_data_helper got GNUNET_MESSAGE_TYPE_WLAN_ADVERTISEMENT size: %i\n",
          ntohs(hdr->size));
#endif

      //TODO better DOS protection, error handling
      GNUNET_assert(client != NULL);
      session_light = (struct Session_light *) client;
      if (session_light->session == NULL)
        {
          session_light->session = get_Session(plugin, session_light->addr);
        }
      GNUNET_assert(GNUNET_HELLO_get_id(
              (const struct GNUNET_HELLO_Message *) &hdr[1],
              &(session_light->session->target) ) != GNUNET_SYSERR);

    }


    else if (ntohs(hdr->type) == GNUNET_MESSAGE_TYPE_WLAN_DATA)
    {

#if DEBUG_wlan
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Func wlan_data_helper got GNUNET_MESSAGE_TYPE_WLAN_DATA size: %i\n",
          ntohs(hdr->size));
#endif

      GNUNET_assert(client != NULL);
      session_light = (struct Session_light *) client;
      if (session_light->session == NULL)
        {
          session_light->session = search_session(plugin, session_light->addr);
        }
      session = session_light->session;
      wlanheader = (struct WlanHeader *) hdr;
      tempmsg = (char*) &wlanheader[1];
      temp_hdr = (const struct GNUNET_MessageHeader *) &wlanheader[1];

      if (getcrc32(tempmsg, wlanheader->header.size) != wlanheader->crc)
        {
          //wrong crc, dispose message
          GNUNET_log(GNUNET_ERROR_TYPE_INFO, "WLAN message crc was wrong\n");
          return;
        }

#if DEBUG_wlan
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "After crc\n");
#endif

      //if not in session list
      if (session == NULL)
        {

          //try if it is a hello message
          if (ntohs(temp_hdr->type) == GNUNET_MESSAGE_TYPE_HELLO)
            {
#if DEBUG_wlan
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "New WLAN Client\n");
#endif
              session = create_session(plugin, session_light->addr);
              session_light->session = session;
              GNUNET_assert(GNUNET_HELLO_get_id(
                      (const struct GNUNET_HELLO_Message *) temp_hdr,
                      &session->target ) != GNUNET_SYSERR);

            }
          else
            {
              GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
                  "WLAN client not in session list and not a hello message\n");
              return;
            }
        }

#if DEBUG_wlan
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "After session\n");
#endif

      //"receive" the message
      struct GNUNET_TRANSPORT_ATS_Information distance[2];
      distance[0].type = htonl(GNUNET_TRANSPORT_ATS_QUALITY_NET_DISTANCE);
      distance[0].value = htonl(1);
      distance[1].type = htonl(GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR);
      distance[1].value = htonl(0);
#if DEBUG_wlan
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "After Information\n");
#endif
      plugin->env->receive(plugin, &(session->target), temp_hdr,
          (const struct GNUNET_TRANSPORT_ATS_Information *) &distance, 2,
          session, session->addr, sizeof(session->addr));
#if DEBUG_wlan
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "After receive\n");
#endif

    }

  else if (ntohs(hdr->type) == GNUNET_MESSAGE_TYPE_WLAN_FRAGMENT)
    {

#if DEBUG_wlan
      GNUNET_log(
          GNUNET_ERROR_TYPE_DEBUG,
          "Func wlan_data_helper got GNUNET_MESSAGE_TYPE_WLAN_FRAGMENT size: %i\n",
          ntohs(hdr->size));
#endif

      GNUNET_assert(client != NULL);
      session_light = (struct Session_light *) client;
      if (session_light->session == NULL)
        {
          session_light->session = search_session(plugin, session_light->addr);
        }
      session = session_light->session;

      fh = (struct FragmentationHeader *) hdr;
      tempmsg = (char*) &fh[1];

      //if not in session list
      if (session != NULL)
        {
          if (getcrc16(tempmsg, fh->header.size) != fh->message_crc)
            {
              //wrong crc, dispose message
              GNUNET_log(GNUNET_ERROR_TYPE_INFO,
                  "WLAN fragment crc was wrong\n");
              return;
            }
          else
            {
              //todo fragments do not timeout
              //check if message_id is rigth or it is a new msg
              if ((session->message_id_in == ntohs(fh->message_id))
                  || (session->rec_size == NO_MESSAGE_OR_MESSAGE_FINISHED))
                {
                  session->message_id_in = ntohs(fh->message_id);
                  if (is_double_msg(session, fh) != GNUNET_YES)
                    {
                      rec_queue
                          = GNUNET_malloc(sizeof (struct RecQueue) +
                              ntohs(fh->header.size) - sizeof(struct FragmentationHeader));
                      rec_queue->size = ntohs(fh->header.size
                          - sizeof(struct FragmentationHeader));
                      rec_queue->num = ntohs(fh->fragment_off_or_num);
                      rec_queue->msg = (char*) &rec_queue[1];
                      //copy msg to buffer
                      memcpy((char*) rec_queue->msg, tempmsg, rec_queue->size);
                      insert_fragment_in_queue(session, rec_queue);
                      check_rec_finished_msg(plugin, session_light, session);
                    }
                  else
                    {
                      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
                          "WLAN fragment is a clone\n");
                      return;
                    }
                }
              else
                {
                  GNUNET_log(
                      GNUNET_ERROR_TYPE_INFO,
                      "WLAN fragment message_id and session message_id are not the same and a message is already (partly) received\n");
                  return;
                }
            }
        }
      else
        {
          GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
              "WLAN client not in session list and it is a fragment message\n");
          return;
        }

    }

  else if (ntohs(hdr->type) == GNUNET_MESSAGE_TYPE_WLAN_FRAGMENT_ACK)
    {

#if DEBUG_wlan
      GNUNET_log(
          GNUNET_ERROR_TYPE_DEBUG,
          "Func wlan_data_helper got GNUNET_MESSAGE_TYPE_WLAN_FRAGMENT_ACK size: %i\n",
          ntohs(hdr->size));
#endif

      GNUNET_assert(client != NULL);
      session_light = (struct Session_light *) client;
      if (session_light->session == NULL)
        {
          session_light->session = search_session(plugin, session_light->addr);
          GNUNET_assert(session_light->session != NULL);
        }
      session = session_light->session;
      fh = (struct FragmentationHeader *) &hdr[1];
      if (fh->message_id == session->message_id_out)
        {
          fm = get_fragment_message_from_session(session);
          if (fm != NULL)
            {

              ack2 = fm->head;
              while (ack2 != NULL)
                {
                  // check for double
                  if (ack2->fragment_num != fh->fragment_off_or_num)
                    {
                      // check if next ack has bigger number
                      if (ack2->fragment_num > fh->fragment_off_or_num)
                        {
                          ack = GNUNET_malloc(sizeof(struct AckQueue));
                          ack->fragment_num = fh->fragment_off_or_num;
                          GNUNET_CONTAINER_DLL_insert_before(fm->head,fm->tail,ack2,ack);
                          //check if finished
                          check_finished_fragment(plugin, fm);
                          return;
                        }
                    }
                  else
                    {
                      //double ack
                      return;
                    }
                  ack2 = ack2->next;
                }
              //GNUNET_CONTAINER_DLL_insert_tail(fm->head,fm->tail,ack);
              //should never happen but...
              //check_finished_fragment(plugin, fm);
            }
          else
            {
              GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
                  "WLAN fragment not in fragment list but id is right\n");
              return;
            }

        }

    }
  else
    {
      // TODO Wrong data?
      GNUNET_log(GNUNET_ERROR_TYPE_INFO,
          "WLAN packet inside the WLAN helper packet has not the right type\n");
      return;
    }

#if DEBUG_wlan
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Helper finished\n");
#endif

}

/**
 * Function used for to process the data from the suid process
 *
 * @param cls the plugin handle
 * @param client which send the data (not used)
 * @param hdr of the GNUNET_MessageHeader
 */

static void
wlan_process_helper (void *cls,
                      void *client,
                      const struct GNUNET_MessageHeader *hdr)
{
  struct Plugin *plugin = cls;
  struct IeeeHeader * wlanIeeeHeader = NULL;
  struct Session_light * session_light = NULL;
  const struct GNUNET_MessageHeader * temp_hdr = NULL;

  int pos = 0;


  if (ntohs(hdr->type) == GNUNET_MESSAGE_TYPE_WLAN_HELPER_DATA)
    {
#if DEBUG_wlan
      GNUNET_log(
          GNUNET_ERROR_TYPE_DEBUG,
          "Func wlan_process_helper got  GNUNET_MESSAGE_TYPE_WLAN_HELPER_DATA size: %i\n",
          ntohs(hdr->size));
#endif

      //call wlan_process_helper with the message inside, later with wlan: analyze signal
      GNUNET_assert(ntohs(hdr->size) >= sizeof(struct IeeeHeader));
      wlanIeeeHeader = (struct IeeeHeader *) &hdr[1];

      session_light = GNUNET_malloc(sizeof(struct Session_light));
      memcpy(session_light->addr, &(wlanIeeeHeader->mac3), sizeof(struct MacAddress));
      session_light->session = search_session(plugin, session_light->addr);

      //process only if it is an broadcast or for this computer both with the gnunet bssid
      //check for bssid
      if (memcmp(&(wlanIeeeHeader->mac2), macbc, sizeof(struct MacAddress)))
        {
          //check for broadcast or mac
          if (memcmp(&(wlanIeeeHeader->mac1), bc_all_mac, sizeof(struct MacAddress))
              || memcmp(&(wlanIeeeHeader->mac1), &(plugin->mac_address),
                  sizeof(struct MacAddress)))
            {
              // process the inner data
            pos = 0;
            temp_hdr = (struct GNUNET_MessageHeader *) &wlanIeeeHeader[1];
              while (pos < hdr->size)
                {
                  wlan_data_helper(plugin, &session_light, temp_hdr);
                  pos += temp_hdr->size + sizeof(struct GNUNET_MessageHeader);
                }
            }
        }

      //clean up
      GNUNET_free(session_light);

    }



  else if (ntohs(hdr->type) == GNUNET_MESSAGE_TYPE_WLAN_HELPER_CONTROL)
    {


#if DEBUG_wlan
      GNUNET_log(
          GNUNET_ERROR_TYPE_DEBUG,
          "Func wlan_process_helper got  GNUNET_MESSAGE_TYPE_WLAN_HELPER_CONTROL size: %i\n",
          ntohs(hdr->size));
#endif

      //TODO more control
      //TODO use struct wlan_helper_control
      if (ntohs(hdr->size) == sizeof(struct Wlan_Helper_Control_Message))
        {
          //plugin->mac_address = GNUNET_malloc(sizeof(struct MacAddress));
          memcpy(&(plugin->mac_address), &hdr[1], sizeof(struct MacAddress));
          GNUNET_log(
              GNUNET_ERROR_TYPE_DEBUG,
              "Notifying transport of address %s\n",
              wlan_plugin_address_to_string(cls, &(plugin->mac_address), ntohs(hdr->size) - sizeof(struct GNUNET_MessageHeader)));
          plugin->env->notify_address(plugin->env->cls, "wlan",
              &plugin->mac_address, sizeof(struct MacAddress),
              GNUNET_TIME_UNIT_FOREVER_REL);
        }
      else
        {
          GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Wrong wlan mac address %s\n",
              plugin->mac_address);
        }

    }


  else
    {
      // TODO Wrong data?
      GNUNET_log(GNUNET_ERROR_TYPE_INFO, "WLAN helper packet has not the right type\n");
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
wlan_plugin_helper_read (void *cls,
			 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;
  plugin->server_read_task = GNUNET_SCHEDULER_NO_TASK;

#if DEBUG_wlan
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Start reading from STDIN\n");
#endif

  if (tc->reason == GNUNET_SCHEDULER_REASON_SHUTDOWN)
    return;

  char mybuf[WLAN_MTU + sizeof(struct GNUNET_MessageHeader)];
  ssize_t bytes;

  bytes = GNUNET_DISK_file_read (plugin->server_stdout_handle, 
				 mybuf, sizeof(mybuf));
  if (bytes <= 0)
    {
#if DEBUG_wlan
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Finished reading from wlan-helper stdout with code: %d\n"), bytes);
#endif
      return;
    }
  GNUNET_SERVER_mst_receive(plugin->consoltoken, NULL,
			    mybuf, bytes, GNUNET_NO, GNUNET_NO);

  GNUNET_assert(plugin->server_read_task == GNUNET_SCHEDULER_NO_TASK);
  plugin->server_read_task =
  GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                  plugin->server_stdout_handle, &wlan_plugin_helper_read, plugin);
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
      "Starting gnunet-wlan-helper process cmd: %s %s %i\n", filename, plugin->interface, testmode);
#endif
  /* Start the server process */


  plugin->server_proc = GNUNET_OS_start_process(plugin->server_stdin,
		  plugin->server_stdout, filename,filename, plugin->interface, ((testmode==1)?"1":(testmode==2)?"2":"0"), NULL);
  if (plugin->server_proc == NULL)
    {
#if DEBUG_wlan
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
      "Adding server_read_task for the wlan-helper\n");
#endif

  sleep(2);

  plugin->server_read_task = GNUNET_SCHEDULER_add_read_file(
      GNUNET_TIME_UNIT_FOREVER_REL, plugin->server_stdout_handle,
      &wlan_plugin_helper_read, plugin);

  return GNUNET_YES;
}


/**
 * Exit point from the plugin.
 */
//TODO doxigen
//FIXME cleanup
void *
libgnunet_plugin_transport_wlan_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

#if DEBUG_wlan
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
      "libgnunet_plugin_transport_wlan_done started\n");
#endif

  GNUNET_assert(cls !=NULL);

  if (plugin->consoltoken != NULL)
  GNUNET_SERVER_mst_destroy(plugin->consoltoken);

  GNUNET_free_non_null(plugin->interface);
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
  static unsigned long long testmode =0;

  GNUNET_assert(cls !=NULL);

  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->env = env;
  plugin->pendingsessions = 0;
  plugin->session_count = 0;
  plugin->server_write_task = GNUNET_SCHEDULER_NO_TASK;
  plugin->server_read_task = GNUNET_SCHEDULER_NO_TASK;
  plugin->server_write_delay_task = GNUNET_SCHEDULER_NO_TASK;


  if (GNUNET_CONFIGURATION_have_value(env->cfg, "transport-wlan", "TESTMODE"))
    {
      if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_number(env->cfg, "transport-wlan",
          "TESTMODE", &testmode))
        return NULL;
    }

  if (GNUNET_CONFIGURATION_have_value(env->cfg,
		  "transport-wlan", "INTERFACE"))
	{
	   if (GNUNET_CONFIGURATION_get_value_string (env->cfg,
			  "transport-wlan","INTERFACE", &(plugin->interface)) != GNUNET_YES){
		   libgnunet_plugin_transport_wlan_done(plugin);
		   return NULL;
	   }
	}

  wlan_transport_start_wlan_helper(plugin, testmode);
  plugin->consoltoken = GNUNET_SERVER_mst_create(&wlan_process_helper,plugin);

  //plugin->sessions = GNUNET_malloc (sizeof (struct Sessionqueue));
  //plugin->pending_Sessions = GNUNET_malloc (sizeof (struct Sessionqueue));

  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
  api->cls = plugin;
  api->send = &wlan_plugin_send;
  api->disconnect = &wlan_plugin_disconnect;
  api->address_pretty_printer = &wlan_plugin_address_pretty_printer;
  api->check_address = &wlan_plugin_address_suggested;
  api->address_to_string = &wlan_plugin_address_to_string;


  start_next_message_id();

#if DEBUG_wlan
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
      "wlan init finished\n");
#endif

  return api;
}

/* end of plugin_transport_wlan.c */
