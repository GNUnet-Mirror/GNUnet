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
#include "gnunet_protocols.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "plugin_transport.h"
#include "plugin_transport_wlan.h"
#include "gnunet_common.h"

#define PROTOCOL_PREFIX "wlan"

/**
 * Max size of packet from helper
 */
#define WLAN_MTU 3000

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
   * List of open sessions.
   */
  struct Session *sessions;

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
  pid_t server_pid;

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
   * to this peer, if any.
   */
  struct Sessionqueue * all_Sessions;

};


struct Sessionqueue
{
	struct Sessionqueue * next;
	struct Sessionqueue * prev;
	struct Session * content;
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
   * Messages currently pending for transmission
   * to this peer, if any.
   */
  struct PendingMessage *pending_messages_head;

  /**
   * Messages currently pending for transmission
   * to this peer, if any.
   */
  struct PendingMessage *pending_messages_tail;

  /**
   * To whom are we talking to (set to our identity
   * if we are still waiting for the welcome message)
   */
  struct GNUNET_PeerIdentity target;

  /**
   * encapsulation of the data
   */

  struct GNUNET_SERVER_MessageStreamTokenizer * datatoken;

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
   * number of message, to distinguish between the messages
   */

  uint16_t message_num_in;

  /**
   * number of message, to distinguish between the messages
   */

  uint16_t message_num_out;


};

/**
 * Information kept for each message that is yet to
 * be transmitted.
 */
struct PendingMessage
{

  /**
   * This is a doubly-linked list.
   */
  struct PendingMessage *next;

  /**
   * This is a doubly-linked list.
   */
  struct PendingMessage *prev;

  /**
   * The pending message
   */
  const char *msg;

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

  /**
   * pos in the message, for fragmentation/segmentation
   */
  size_t message_pos;
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
   * number of this fragment, for fragmentation/segmentation
   */
  uint16_t fragment_num GNUNET_PACKED;

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

enum { ACK_FRAGMENT = 1, DATA_FRAGMENT = 2, LAST_FRAGMENT = 4, NEW_MESSAGE = 8 };

int getRadiotapHeader (struct RadiotapHeader * Header);
int getWlanHeader (struct IeeeHeader * Header);
static int wlan_plugin_address_suggested (void *cls,
				   const void *addr,
				   size_t addrlen);
/**
 * get Session from address
 *
 */

//TODO add other possibilities to find the right session (are there other?)
static struct Session *
get_Session (struct Plugin *plugin,
	     const char * addr)
{
	struct Sessionqueue * queue = plugin->all_Sessions;
	struct Sessionqueue * lastitem = NULL;

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

	if (plugin->all_Sessions == NULL){
		//is first session
		plugin->all_Sessions = queue;
	} else {
		lastitem->next = queue;
		queue->prev = lastitem;
	}

	queue->content = GNUNET_malloc (sizeof (struct Session));
	queue->content->plugin = plugin;
	memcpy(queue->content->addr, addr, 6);

	//queue welcome
	struct WelcomeMessage welcome;
	struct PendingMessage *pm;
	pm = GNUNET_malloc (sizeof (struct PendingMessage) + sizeof (struct WelcomeMessage));
	pm->msg = (const char*) &pm[1];
	pm->message_size = sizeof (struct WelcomeMessage);
	welcome.header.size = htons (sizeof (struct WelcomeMessage));
	welcome.header.type = htons (GNUNET_MESSAGE_TYPE_WLAN_ADVERTISEMENT);
	welcome.clientIdentity = *plugin->env->my_identity;
	memcpy (&pm[1], &welcome, sizeof (welcome));
	pm->timeout = GNUNET_TIME_UNIT_FOREVER_ABS;
	GNUNET_CONTAINER_DLL_insert ((queue->content)->pending_messages_head,
					   (queue->content)->pending_messages_tail,
				       pm);

	return queue->content;

}

/**
 * Queue the session to send data
 */

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
	if (plugin->pending_Sessions == NULL){
			//is first session
			plugin->pending_Sessions = queue;
		} else {
			lastitem->next = queue;
			queue->prev = lastitem;
		}

	queue->content = session;

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
  ssize_t bytes;

  if (tc->reason == GNUNET_SCHEDULER_REASON_SHUTDOWN)
    return;

  struct Session * session;
  struct Sessionqueue * queue;
  struct PendingMessage * pm;
  struct IeeeHeader * wlanheader;
  struct RadiotapHeader * radioHeader;
  struct GNUNET_MessageHeader * msgheader;
  uint16_t size = 0;

  queue = plugin->pending_Sessions;

  //check if the are some pending sessions/messages ...
  GNUNET_assert(queue != NULL);

  session = queue->content;
  GNUNET_assert(session != NULL);

  pm = session->pending_messages_head;
  GNUNET_assert(pm != NULL);

  //check if msg is valid to send
  if (GNUNET_TIME_absolute_get_remaining(pm->timeout).value > 0){
	// fixme split msg if to large

	//increment one, this is a new message
	session->message_num_out ++;
	// fixme peer id is needed in each packet
	size = pm->message_size + sizeof(struct RadiotapHeader)
					+ sizeof(struct IeeeHeader) + sizeof(struct GNUNET_MessageHeader)
					+ sizeof(struct FragmentationHeader);
	msgheader = GNUNET_malloc(size);
	msgheader->size = pm->message_size + sizeof(struct RadiotapHeader) + sizeof(struct IeeeHeader);
	msgheader->type = GNUNET_MESSAGE_TYPE_WLAN_HELPER_DATA;

	radioHeader = (struct RadiotapHeader*) &msgheader[1];
	getRadiotapHeader(radioHeader);

	wlanheader = (struct IeeeHeader *) &radioHeader[1];
	getWlanHeader(wlanheader);

	bytes = GNUNET_DISK_file_write(plugin->server_stdin_handle, msgheader, size);
  } else {
	  //remove message
	  GNUNET_CONTAINER_DLL_remove (session->pending_messages_head,
								  session->pending_messages_tail,
								  pm);
	  GNUNET_free(pm);

  }





  if (bytes < 1)
    {
      return;
    }

  //plugin->server_read_task =
  //GNUNET_SCHEDULER_add_read_file (plugin->env->sched,
  //                                GNUNET_TIME_UNIT_FOREVER_REL,
  //                                plugin->server_stdout_handle, &wlan_plugin_helper_read, plugin);

}

/**
 * If we have pending messages, ask the server to
 * transmit them (schedule the respective tasks, etc.)
 *
 * @param Plugin env to get everything needed
 */
static void
process_pending_messages (struct Plugin * plugin)
{
  struct Sessionqueue * queue;
  struct Session * session;

  if (plugin->pending_Sessions == NULL)
    return;

  queue = plugin->pending_Sessions;
  //contet should not be empty
  GNUNET_assert(queue->content != NULL);

  session = queue->content;
  //pending sessions should have some msg
  GNUNET_assert(session->pending_messages_head != NULL);

  // GNUNET_TIME_UNIT_FOREVER_REL is needed to clean up old msg
  plugin->server_write_task
    = GNUNET_SCHEDULER_add_write_file(plugin->env->sched,
											GNUNET_TIME_UNIT_FOREVER_REL,
											plugin->server_stdin_handle,
                                           &do_transmit,
                                           plugin);
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
  newmsg = GNUNET_malloc(sizeof(struct PendingMessage) + msgbuf_size);
  newmsg->msg = (const char*) &newmsg[1];
  //copy msg to buffer, not fragmented / segmented yet
  memcpy(&newmsg[1], msgbuf, msgbuf_size);
  newmsg->transmit_cont = cont;
  newmsg->transmit_cont_cls = cont_cls;
  newmsg->timeout = GNUNET_TIME_relative_to_absolute(timeout);
  newmsg->message_pos = 0;
  newmsg->message_size = msgbuf_size;
  newmsg->next = NULL;

  //check if queue is empty
  struct PendingMessage * tailmsg;
  tailmsg = session->pending_messages_tail;

  //new tail is the new msg
  session->pending_messages_tail = newmsg;
  newmsg->prev = tailmsg;

  //test if tail was not NULL (queue is empty)
  if (tailmsg == NULL){
	  // head should be NULL too
	  GNUNET_assert(session->pending_messages_head == NULL);

	  session->pending_messages_head = newmsg;

  } else {
	  //next at the tail should be NULL
	  GNUNET_assert(tailmsg->next == NULL);

	  //queue the msg
	  tailmsg->next = newmsg;
  }

  process_pending_messages(plugin);


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
  // struct Plugin *plugin = cls;
  // FIXME
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
  /* struct Plugin *plugin = cls; */

  /* check if the address is plausible; if so,
     add it to our list! */

  GNUNET_assert(cls !=NULL);

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


#if 1
/**
 * Function used for to process the data from the suid process
 */
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
wlan_transport_start_wlan_helper(struct Plugin *plugin)
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
  plugin->server_pid = GNUNET_OS_start_process(plugin->server_stdin, plugin->server_stdout, "gnunet-transport-wlan-helper", "gnunet-transport-wlan-helper", plugin->interface, NULL);
  if (plugin->server_pid == GNUNET_SYSERR)
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
  GNUNET_SCHEDULER_add_read_file (plugin->env->sched,
                                  GNUNET_TIME_UNIT_FOREVER_REL,
                                  plugin->server_stdout_handle, &wlan_plugin_helper_read, plugin);
  return GNUNET_YES;
}



#endif


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

  service = GNUNET_SERVICE_start ("transport-wlan", env->sched, env->cfg);
	if (service == NULL){
		GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
			   _("Failed to start service for `%s' transport plugin.\n"),
			   "wlan");
		return NULL;
	}

  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->env = env;

  wlan_transport_start_wlan_helper(plugin);
  plugin->consoltoken = GNUNET_SERVER_mst_create(&wlan_process_helper,plugin);

  //plugin->all_Sessions = GNUNET_malloc (sizeof (struct Sessionqueue));
  //plugin->pending_Sessions = GNUNET_malloc (sizeof (struct Sessionqueue));

  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
  api->cls = plugin;
  api->send = &wlan_plugin_send;
  api->disconnect = &wlan_plugin_disconnect;
  api->address_pretty_printer = &wlan_plugin_address_pretty_printer;
  api->check_address = &wlan_plugin_address_suggested;
  api->address_to_string = &wlan_plugin_address_to_string;

  return api;
}


/**
 * Exit point from the plugin.
 */
void *
gnunet_plugin_transport_wlan_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  GNUNET_assert(cls !=NULL);

  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}

/* end of plugin_transport_wlan.c */
