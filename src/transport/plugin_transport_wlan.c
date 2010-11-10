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

#define FRAGMENT_TIMEOUT 1000

#define FRAGMENT_QUEUE_SIZE 10

#define DEBUG_wlan GNUNET_NO

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
   * Identity of the node connecting (TCP client)
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
   * ID of select gnunet-nat-server std read task
   */
  GNUNET_SCHEDULER_TaskIdentifier server_read_task;

  /**
     * ID of select gnunet-nat-server std read task
     */
  GNUNET_SCHEDULER_TaskIdentifier server_write_task;

  /**
   * The process id of the server process (if behind NAT)
   */
  struct GNUNET_OS_Process *server_proc;

  /**
   * The interface of the wlan card given to us by the user.
   */
  char *interface;

  /**
   * The mac_address of the wlan card given to us by the helper.
   */
  char *mac_address;

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

};

//TODO doxigen

struct Sessionqueue
{
	struct Sessionqueue * next;
	struct Sessionqueue * prev;
	struct Session * content;
};

//TODO doxigen

struct AckQueue
{
	struct AckQueue * next;
	struct AckQueue * prev;
	int fragment_num;
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
   * encapsulation of the data
   */
  //struct GNUNET_SERVER_MessageStreamTokenizer * datatoken;

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

int getRadiotapHeader (struct RadiotapHeader * Header);
int getWlanHeader (struct IeeeHeader * Header);
static int wlan_plugin_address_suggested (void *cls,
				   const void *addr,
				   size_t addrlen);
uint16_t getcrc16 (const char *msgbuf, size_t msgbuf_size);
static void do_transmit (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);
static void check_fragment_queue (struct Plugin * plugin);

/**
 * get the next message number, at the moment just a random one
 *
 */
//TODO doxigen
uint32_t
get_next_message_id()
{
	return GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, UINT32_MAX);
}

/**
 * start next message number generator
 */
//TODO doxigen
void
start_next_message_id()
{
	//GNUNET_CRYPTO_random_init;
}


/**
 * get Session from address
 *
 */
//TODO doxigen
//TODO add other possibilities to find the right session (are there other?)
static struct Session *
get_Session (struct Plugin *plugin,
	     const char * addr)
{
	struct Sessionqueue * queue = plugin->sessions;
	struct Sessionqueue * lastitem = NULL;


	//just look at all the session for the needed one
	while (queue != NULL){
		// content is never NULL
		GNUNET_assert (queue->content == NULL);
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
	// new session
	queue = GNUNET_malloc (sizeof (struct Sessionqueue));

	GNUNET_CONTAINER_DLL_insert(plugin->sessions, plugin->sessions_tail, queue);

	queue->content = GNUNET_malloc (sizeof (struct Session));
	queue->content->plugin = plugin;
	memcpy(queue->content->addr, addr, 6);
	queue->content->message_id_out = get_next_message_id();
	queue->content->has_fragment = 0;

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

	return queue->content;

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
free_acks (struct FragmentMessage * pm){
	struct AckQueue * fq;
	while (pm->head != NULL){
		fq = pm->head;
		GNUNET_CONTAINER_DLL_remove(pm->head, pm->tail, fq);
		GNUNET_free(fq);
	}
}

//TODO doxigen
static void
delay_fragment_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc){
	struct Plugin * plugin = cls;
	plugin->server_write_task = GNUNET_SCHEDULER_NO_TASK;

	if (tc->reason == GNUNET_SCHEDULER_REASON_SHUTDOWN)
	    return;

	// GNUNET_TIME_UNIT_FOREVER_REL is needed to clean up old msg
	plugin->server_write_task
		= GNUNET_SCHEDULER_add_write_file(GNUNET_TIME_UNIT_FOREVER_REL,
											plugin->server_stdin_handle,
										   &do_transmit,
										   plugin);
}


//TODO doxigen
struct GNUNET_TIME_Relative
get_next_frag_timeout (struct FragmentMessage * fm)
{
	return GNUNET_TIME_relative_min(GNUNET_TIME_absolute_get_remaining(fm->next_ack), GNUNET_TIME_absolute_get_remaining(fm->timeout));
}

//TODO doxigen
/**
 * Function to get the timeout value for acks for this session
 */

struct GNUNET_TIME_Relative
get_ack_timeout (struct FragmentMessage * fm){
	struct GNUNET_TIME_Relative timeout;
	timeout.rel_value = FRAGMENT_TIMEOUT;
	return timeout;
}

//TODO doxigen
/**
 * Function to set the timer for the next timeout of the fragment queue
 */
static void
check_next_fragment_timeout (struct Plugin * plugin){
	struct FragmentMessage * fm;
	if (plugin->server_write_task != GNUNET_SCHEDULER_NO_TASK){
		GNUNET_SCHEDULER_cancel(plugin->server_write_task);
	}
	fm = plugin->pending_Fragment_Messages_head;
	if (fm != NULL){
		plugin->server_write_task = GNUNET_SCHEDULER_add_delayed(get_next_frag_timeout(fm), &delay_fragment_task, plugin);
	}
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

//TODO doxigen
/**
 * Function to sort the message into the message fragment queue
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

//TODO doxigen
/**
 * Function to check if there is some space in the fragment queue
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
 * Function called to when wlan helper is ready to get some data
 *
 * @param cls closure
 * @param GNUNET_SCHEDULER_TaskContext
 */

static void
do_transmit (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{

  struct Plugin * plugin = cls;
  plugin->server_write_task = GNUNET_SCHEDULER_NO_TASK;

  ssize_t bytes;

  if (tc->reason == GNUNET_SCHEDULER_REASON_SHUTDOWN)
    return;

  struct Session * session;
  struct FragmentMessage * fm;
  struct IeeeHeader * wlanheader;
  struct RadiotapHeader * radioHeader;
  struct GNUNET_MessageHeader * msgheader;
  struct FragmentationHeader fragheader;
  uint16_t size = 0;
  const char * copystart = NULL;
  uint16_t copysize = 0;
  uint copyoffset = 0;
  struct AckQueue * akt = NULL;
  //int exit = 0;

  fm = plugin->pending_Fragment_Messages_head;
  GNUNET_assert(fm != NULL);
  session = fm->session;
  GNUNET_assert(session != NULL);

  // test if message timed out
  if (GNUNET_TIME_absolute_get_remaining(fm->timeout).rel_value == 0){
	  free_acks(fm);
	  GNUNET_assert(plugin->pending_fragment_messages > 0);
	  plugin->pending_fragment_messages --;
	  GNUNET_CONTAINER_DLL_remove(plugin->pending_Fragment_Messages_head,
			  plugin->pending_Fragment_Messages_tail, fm);

	  GNUNET_free(fm->msg);

	  GNUNET_free(fm);
	  check_fragment_queue(plugin);
  } else {

	  if (fm->message_size > WLAN_MTU) {
		size += sizeof(struct FragmentationHeader);
		// check/set for retransmission
		if (GNUNET_TIME_absolute_get_duration(fm->next_ack).rel_value == 0) {

			// be positive and try again later :-D
			fm->next_ack = GNUNET_TIME_relative_to_absolute(get_ack_timeout(fm));
			// find first missing fragment
			akt = fm->head;
			fm->message_pos = 0;

			//test if ack 0 was already received
			while (akt != NULL){
				//if fragment is present, take next
				if (akt->fragment_num == fm->message_pos) {
					fm->message_pos ++;
				}
				//next ack is bigger then the fragment number
				//in case there is something like this: (acks) 1, 2, 5, 6, ...
				//and we send 3 again, the next number should be 4
				else if (akt->fragment_num > fm->message_pos) {
					break;
				}

				akt = akt->next;

			}


	 	}

		copyoffset = (WLAN_MTU - sizeof(struct FragmentationHeader)) * fm->message_pos;
		fragheader.fragment_off_or_num = htons(fm->message_pos);
		fragheader.message_id = htonl(session->message_id_out);

		// start should be smaller then the packet size
		GNUNET_assert(copyoffset < fm->message_size);
		copystart = fm->msg + copyoffset;

		//size of the fragment is either the MTU - overhead
		//or the missing part of the message in case this is the last fragment
		copysize = GNUNET_MIN(fm->message_size - copyoffset,
				WLAN_MTU - sizeof(struct FragmentationHeader));
		fragheader.header.size = htons(copysize);
		fragheader.header.type = GNUNET_MESSAGE_TYPE_WLAN_FRAGMENT;


		//get the next missing fragment
		akt = fm->head;
		fm->message_pos ++;

		//test if ack was already received
		while (akt != NULL){
			//if fragment is present, take next
			if (akt->fragment_num == fm->message_pos) {
				fm->message_pos ++;
			}
			//next ack is bigger then the fragment number
			//in case there is something like this: (acks) 1, 2, 5, 6, ...
			//and we send 3 again, the next number should be 4
			else if (akt->fragment_num > fm->message_pos) {
				break;
			}

			akt = akt->next;
		}
	  } else {
	  	// there is no need to split
	  	copystart = fm->msg;
	  	copysize = fm->message_size;
	  }

	size += copysize;
	size += sizeof(struct RadiotapHeader) + sizeof(struct IeeeHeader)
		+ sizeof(struct GNUNET_MessageHeader);
	msgheader = GNUNET_malloc(size);
	msgheader->size = htons(size - sizeof(struct GNUNET_MessageHeader));
	msgheader->type = GNUNET_MESSAGE_TYPE_WLAN_HELPER_DATA;

	radioHeader = (struct RadiotapHeader*) &msgheader[1];
	getRadiotapHeader(radioHeader);

	wlanheader = (struct IeeeHeader *) &radioHeader[1];
	getWlanHeader(wlanheader);


	//could be faster if content is just send and not copyed before
	//fragmentheader is needed
	if (fm->message_size > WLAN_MTU){
		fragheader.message_crc = htons(getcrc16(copystart, copysize));
		memcpy(&wlanheader[1],&fragheader, sizeof(struct FragmentationHeader));
		memcpy(&wlanheader[1] + sizeof(struct FragmentationHeader),copystart,copysize);
	} else {
		memcpy(&wlanheader[1],copystart,copysize);
	}

	bytes = GNUNET_DISK_file_write(plugin->server_stdin_handle, msgheader, size);
	GNUNET_assert(bytes == size);

	//check if this was the last fragment of this message, if true then queue at the end of the list
	if (copysize + copyoffset >= fm->message_size){
		GNUNET_assert(copysize + copyoffset == fm->message_size);

		GNUNET_CONTAINER_DLL_remove (plugin->pending_Fragment_Messages_head,
				plugin->pending_Fragment_Messages_tail, fm);

		GNUNET_CONTAINER_DLL_insert_tail(plugin->pending_Fragment_Messages_head,
				plugin->pending_Fragment_Messages_tail, fm);
		// if fragments have opimized timeouts
		//sort_fragment_into_queue(plugin,fm);

	}
	check_next_fragment_timeout(plugin);

  }
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
  if (session == NULL) {
	  if ( wlan_plugin_address_suggested(plugin , addr, addrlen) == GNUNET_OK){
		  session = get_Session(plugin, addr);
	  } else {
		  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		                        _("Wlan Address len %d is wrong\n"),
		                         addrlen);
		  return -1;
	  }
  }

  //TODO target "problem" not solved
  session->target = *target;

  //queue message:
  //first queue session
  queue_Session(plugin, session);

  //queue message in session
  if (session->pending_message == NULL){
	newmsg = GNUNET_malloc(sizeof(struct PendingMessage));
	(newmsg->msg) = GNUNET_malloc(msgbuf_size + sizeof(struct WlanHeader));
	wlanheader = (struct WlanHeader *) newmsg->msg;
	//copy msg to buffer, not fragmented / segmented yet, but with message header
	wlanheader->header.size = htons(msgbuf_size);
	wlanheader->header.type = GNUNET_MESSAGE_TYPE_WLAN_DATA;
	wlanheader->target = *target;
	wlanheader->crc = getcrc32(msgbuf, msgbuf_size);
	memcpy(&wlanheader[1], msgbuf, msgbuf_size);
	newmsg->transmit_cont = cont;
	newmsg->transmit_cont_cls = cont_cls;
	newmsg->timeout = GNUNET_TIME_relative_to_absolute(timeout);
	newmsg->message_size = msgbuf_size + sizeof(struct WlanHeader);
  } else {
	  //TODO if message is send while hello is still pending, other cases should not occur
  }
  check_fragment_queue(plugin);
  //FIXME not the correct size
  return msgbuf_size;

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
wlan_plugin_disconnect (void *cls,
                            const struct GNUNET_PeerIdentity *target)
{
	struct Plugin *plugin = cls;
	struct Sessionqueue * queue = plugin->sessions;
	struct Sessionqueue * lastitem = NULL;
	struct PendingMessage * pm;

	// just look at all the session for the needed one
	while (queue != NULL){
		// content is never NULL
		GNUNET_assert (queue->content == NULL);
		if (memcmp(target, &(queue->content->target), sizeof(struct GNUNET_PeerIdentity)) == 0)
		  {
			// session found
			// remove PendingMessage
			pm = queue->content->pending_message;
			GNUNET_free(pm->msg);
			GNUNET_free(pm);

			GNUNET_free(queue->content);
			GNUNET_CONTAINER_DLL_remove(plugin->sessions, plugin->sessions_tail, queue);
			GNUNET_free(queue);

			return;
		  }
		// try next
		lastitem = queue;
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
 * Function used for to process the data from the suid process
 */
//TODO doxigen

static void
wlan_process_helper (void *cls,
                      void *client,
                      const struct GNUNET_MessageHeader *hdr)
{
  struct Plugin *plugin = cls;
  if (hdr->type == GNUNET_MESSAGE_TYPE_WLAN_HELPER_DATA){
    //TODO DATA
  } else if (hdr->type == GNUNET_MESSAGE_TYPE_WLAN_ADVERTISEMENT){
    //TODO ADV
  } else if (hdr->type == GNUNET_MESSAGE_TYPE_WLAN_HELPER_CONTROL){
    //TODO Control
    if (hdr->size == 6){
      plugin->mac_address = GNUNET_malloc(6);
      memcpy(plugin->mac_address, &hdr[1],6);
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Notifying transport of address %s\n", wlan_plugin_address_to_string(cls, plugin->mac_address, hdr->size));
      plugin->env->notify_address (plugin->env->cls,
                                      "wlan",
                                      &plugin->mac_address, sizeof(plugin->mac_address),
                                      GNUNET_TIME_UNIT_FOREVER_REL);
    } else {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Wrong wlan mac address %s\n", plugin->mac_address);
    }


  } else {
    // TODO Wrong data?
  }
}


static void
wlan_plugin_helper_read (void *cls,
			 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;
  char mybuf[WLAN_MTU]; 
  ssize_t bytes;

  if (tc->reason == GNUNET_SCHEDULER_REASON_SHUTDOWN)
    return;
  bytes = GNUNET_DISK_file_read (plugin->server_stdout_handle, 
				 mybuf, sizeof(mybuf));
  if (bytes <= 0)
    {
#if DEBUG_TCP_NAT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Finished reading from wlan-helper stdout with code: %d\n"), bytes);
#endif
      return;
    }
  GNUNET_SERVER_mst_receive(plugin->consoltoken, NULL,
			    mybuf, bytes, 0, GNUNET_NO);

}


/**
 * Start the gnunet-wlan-helper process.
 *
 * @param plugin the transport plugin
 *
 * @return GNUNET_YES if process was started, GNUNET_SYSERR on error
 */
static int
wlan_transport_start_wlan_helper (struct Plugin *plugin)
{

  plugin->server_stdout = GNUNET_DISK_pipe (GNUNET_YES, GNUNET_NO, GNUNET_YES);
  if (plugin->server_stdout == NULL)
    return GNUNET_SYSERR;

  plugin->server_stdin = GNUNET_DISK_pipe (GNUNET_YES, GNUNET_YES, GNUNET_NO);
    if (plugin->server_stdin == NULL)
      return GNUNET_SYSERR;

#if DEBUG_TCP_NAT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                   "Starting gnunet-wlan-helper process cmd: %s %s\n", "gnunet-wlan-helper", plugin->interface);
#endif
  /* Start the server process */
  plugin->server_proc = GNUNET_OS_start_process(plugin->server_stdin, plugin->server_stdout, "gnunet-transport-wlan-helper", "gnunet-transport-wlan-helper", plugin->interface, NULL);
  if (plugin->server_proc == NULL)
    {
#if DEBUG_TCP_NAT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                     "Failed to start gnunet-wlan-helper process\n");
#endif
      return GNUNET_SYSERR;
    }
  /* Close the write end of the read pipe */
  GNUNET_DISK_pipe_close_end(plugin->server_stdout, GNUNET_DISK_PIPE_END_WRITE);

  /* Close the read end of the write pipe */
  GNUNET_DISK_pipe_close_end(plugin->server_stdin, GNUNET_DISK_PIPE_END_READ);

  plugin->server_stdout_handle = GNUNET_DISK_pipe_handle(plugin->server_stdout, GNUNET_DISK_PIPE_END_READ);
  plugin->server_stdin_handle = GNUNET_DISK_pipe_handle(plugin->server_stdin, GNUNET_DISK_PIPE_END_WRITE);

  plugin->server_read_task =
  GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                  plugin->server_stdout_handle, &wlan_plugin_helper_read, plugin);
  return GNUNET_YES;
}



/**
 * Entry point for the plugin.
 *
 * @param cls closure, the 'struct GNUNET_TRANSPORT_PluginEnvironment*'
 * @return the 'struct GNUNET_TRANSPORT_PluginFunctions*' or NULL on error
 */
void *
gnunet_plugin_transport_wlan_init (void *cls)
{
  struct GNUNET_SERVICE_Context *service;
  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  struct Plugin *plugin;

  GNUNET_assert(cls !=NULL);

  service = GNUNET_SERVICE_start ("transport-wlan", env->cfg);
	if (service == NULL){
		GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
			   _("Failed to start service for `%s' transport plugin.\n"),
			   "wlan");
		return NULL;
	}

  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->env = env;
  plugin->pendingsessions = 0;
  plugin->server_write_task = GNUNET_SCHEDULER_NO_TASK;
  plugin->server_read_task = GNUNET_SCHEDULER_NO_TASK;

  wlan_transport_start_wlan_helper(plugin);
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

  return api;
}


/**
 * Exit point from the plugin.
 */
//TODO doxigen
void *
gnunet_plugin_transport_wlan_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  GNUNET_assert(cls !=NULL);

  GNUNET_free_non_null(plugin->mac_address);
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}

/* end of plugin_transport_wlan.c */
