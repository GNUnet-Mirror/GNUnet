/*
     This file is part of GNUnet
     (C) 2010, 2013 Christian Grothoff (and other contributing authors)

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
 * @file transport/plugin_transport_unix.c
 * @brief Transport plugin using unix domain sockets (!)
 *        Clearly, can only be used locally on Unix/Linux hosts...
 *        ONLY INTENDED FOR TESTING!!!
 * @author Christian Grothoff
 * @author Nathan Evans
 */
#include "platform.h"
#include "gnunet_hello_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_transport_plugin.h"
#include "transport.h"


/**
 * Return code we give on 'send' if we failed to send right now
 * but it makes sense to retry later. (Note: we might want to
 * move this to the plugin API!?).
 */
#define RETRY 0

#define PLUGIN_NAME "unix"

/**
 * How long until we give up on transmitting the welcome message?
 */
#define HOSTNAME_RESOLVE_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * Default "port" to use, if configuration does not specify.
 * Essentially just a number appended to the UNIX path.
 */
#define UNIX_NAT_DEFAULT_PORT 22086


#define LOG(kind,...) GNUNET_log_from (kind, "transport-unix",__VA_ARGS__)


GNUNET_NETWORK_STRUCT_BEGIN

struct UnixAddress
{
	uint32_t options GNUNET_PACKED;

	uint32_t addrlen GNUNET_PACKED;
};


/**
 * UNIX Message-Packet header.
 */
struct UNIXMessage
{
  /**
   * Message header.
   */
  struct GNUNET_MessageHeader header;

  /**
   * What is the identity of the sender (GNUNET_hash of public key)
   */
  struct GNUNET_PeerIdentity sender;

};

GNUNET_NETWORK_STRUCT_END

/**
 * Address options
 */
static uint32_t myoptions;

/**
 * Handle for a session.
 */
struct Session
{
  struct GNUNET_PeerIdentity target;

  struct Plugin * plugin;

  struct UnixAddress *addr;

  size_t addrlen;

  /**
   * Session timeout task
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;
};


struct UNIXMessageWrapper
{
  /**
   * We keep messages in a doubly linked list.
   */
  struct UNIXMessageWrapper *next;

  /**
   * We keep messages in a doubly linked list.
   */
  struct UNIXMessageWrapper *prev;

  /**
   * The actual payload (allocated separately right now).
   */
  struct UNIXMessage * msg;

  /**
   * Session this message belongs to.
   */
  struct Session *session;

  /**
   * Function to call upon transmission.
   */
  GNUNET_TRANSPORT_TransmitContinuation cont;

  /**
   * Closure for 'cont'.
   */
  void *cont_cls;

  /**
   * Timeout for this message.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Number of bytes in 'msg'.
   */
  size_t msgsize;

  /**
   * Number of bytes of payload encapsulated in 'msg'.
   */
  size_t payload;

  /**
   * Priority of the message (ignored, just dragged along in UNIX).
   */
  unsigned int priority;
};


/**
 * Encapsulation of all of the state of the plugin.
 */
struct Plugin;


/**
 * UNIX "Session"
 */
struct PeerSession
{

  /**
   * Stored in a linked list.
   */
  struct PeerSession *next;

  /**
   * Pointer to the global plugin struct.
   */
  struct Plugin *plugin;

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
   * Length of connect_addr.
   */
  size_t connect_alen;

  /**
   * Are we still expecting the welcome message? (GNUNET_YES/GNUNET_NO)
   */
  int expecting_welcome;

  /**
   * From which socket do we need to send to this peer?
   */
  struct GNUNET_NETWORK_Handle *sock;

  /*
   * Queue of messages for this peer, in the case that
   * we have to await a connection...
   */
  struct MessageQueue *messages;

};


/**
 * Information we keep for each of our listen sockets.
 */
struct UNIX_Sock_Info
{
  /**
   * The network handle
   */
  struct GNUNET_NETWORK_Handle *desc;

  /**
   * The port we bound to (not an actual PORT, as UNIX domain sockets
   * don't have ports, but rather a number in the path name to make this
   * one unique).
   */
  uint16_t port;
};


/**
 * Encapsulation of all of the state of the plugin.
 */
struct Plugin
{

  /**
   * ID of task used to update our addresses when one expires.
   */
  GNUNET_SCHEDULER_TaskIdentifier address_update_task;

  /**
   * ID of select task
   */
  GNUNET_SCHEDULER_TaskIdentifier select_task;

  /**
   * Number of bytes we currently have in our write queue.
   */
  unsigned long long bytes_in_queue;

  /**
   * Our environment.
   */
  struct GNUNET_TRANSPORT_PluginEnvironment *env;

  /**
   * Sessions
   */
  struct GNUNET_CONTAINER_MultiHashMap *session_map;

  /**
   * FD Read set
   */
  struct GNUNET_NETWORK_FDSet *rs;

  /**
   * FD Write set
   */
  struct GNUNET_NETWORK_FDSet *ws;

  /**
   * Path of our unix domain socket (/tmp/unix-plugin-PORT)
   */
  char *unix_socket_path;

  /**
   * Head of queue of messages to transmit.
   */
  struct UNIXMessageWrapper *msg_head;

  /**
   * Tail of queue of messages to transmit.
   */
  struct UNIXMessageWrapper *msg_tail;

  /**
   * socket that we transmit all data with
   */
  struct UNIX_Sock_Info unix_sock;

  /**
   * ATS network
   */
  struct GNUNET_ATS_Information ats_network;

  /**
   * Is the write set in the current 'select' task?  GNUNET_NO if the
   * write queue was empty when the main task was scheduled,
   * GNUNET_YES if we're already waiting for being allowed to write.
   */
  int with_ws;

  /**
   * Integer to append to unix domain socket.
   */
  uint16_t port;

};


/**
 * Increment session timeout due to activity
 *
 * @param s session for which the timeout should be moved
 */
static void
reschedule_session_timeout (struct Session *s);


/**
 * We have been notified that our writeset has something to read.  We don't
 * know which socket needs to be read, so we have to check each one
 * Then reschedule this function to be called again once more is available.
 *
 * @param cls the plugin handle
 * @param tc the scheduling context (for rescheduling this function again)
 */
static void
unix_plugin_select (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

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
unix_address_to_string (void *cls, const void *addr, size_t addrlen);

/**
 * Re-schedule the main 'select' callback (unix_plugin_select)
 * for this plugin.
 *
 * @param plugin the plugin context
 */
static void
reschedule_select (struct Plugin * plugin)
{
  if (plugin->select_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (plugin->select_task);
    plugin->select_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != plugin->msg_head)
  {
    plugin->select_task =
      GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                   GNUNET_TIME_UNIT_FOREVER_REL,
                                   plugin->rs,
                                   plugin->ws,
                                   &unix_plugin_select, plugin);
    plugin->with_ws = GNUNET_YES;
  }
  else
  {
    plugin->select_task =
      GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                   GNUNET_TIME_UNIT_FOREVER_REL,
                                   plugin->rs,
                                   NULL,
                                   &unix_plugin_select, plugin);
    plugin->with_ws = GNUNET_NO;
  }
}


/**
 * Closure to 'lookup_session_it'.
 */
struct LookupCtx
{
  /**
   * Location to store the session, if found.
   */
  struct Session *s;

  /**
   * Address we are looking for.
   */
  const struct UnixAddress *ua;

  size_t ua_len;
};


/**
 * Function called to find a session by address.
 *
 * @param cls the 'struct LookupCtx'
 * @param key peer we are looking for (unused)
 * @param value a session
 * @return GNUNET_YES if not found (continue looking), GNUNET_NO on success
 */
static int 
lookup_session_it (void *cls,
		   const struct GNUNET_HashCode * key,
		   void *value)
{
  struct LookupCtx *lctx = cls;
  struct Session *t = value;

  if (t->addrlen != lctx->ua_len)
    return GNUNET_YES;

  if (0 == memcmp (&t->addr, lctx->ua, lctx->ua_len))
  {
    lctx->s = t;
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Find an existing session by address.
 *
 * @param plugin the plugin
 * @param sender for which peer should the session be?
 * @param ua address to look for
 * @param ua_len length of the address
 * @return NULL if session was not found
 */
static struct Session *
lookup_session (struct Plugin *plugin, 
		const struct GNUNET_PeerIdentity *sender, 
		const struct UnixAddress *ua, size_t ua_len)
{
  struct LookupCtx lctx;

  GNUNET_assert (NULL != plugin);
  GNUNET_assert (NULL != sender);
  GNUNET_assert (NULL != ua);
  lctx.s = NULL;
  lctx.ua = ua;
  lctx.ua_len = ua_len;
  GNUNET_CONTAINER_multihashmap_get_multiple (plugin->session_map, 
					      &sender->hashPubKey,
					      &lookup_session_it, &lctx);
  return lctx.s;
}


/**
 * Functions with this signature are called whenever we need
 * to close a session due to a disconnect or failure to
 * establish a connection.
 *
 * @param s session to close down
 */
static void
disconnect_session (struct Session *s)
{
  struct Plugin *plugin = s->plugin;
  struct UNIXMessageWrapper *msgw;
  struct UNIXMessageWrapper *next;
  int removed;

  LOG (GNUNET_ERROR_TYPE_DEBUG, 
       "Disconnecting session for peer `%s' `%s'\n",
       GNUNET_i2s (&s->target), 
       s->addr);
  plugin->env->session_end (plugin->env->cls, &s->target, s);
  removed = GNUNET_NO;
  next = plugin->msg_head;
  while (NULL != next)
  {
    msgw = next;
    next = msgw->next;
    if (msgw->session != s)
      continue;
    GNUNET_CONTAINER_DLL_remove (plugin->msg_head, plugin->msg_tail, msgw);
    if (NULL != msgw->cont)
      msgw->cont (msgw->cont_cls,  &msgw->session->target, GNUNET_SYSERR,
                  msgw->payload, 0);
    GNUNET_free (msgw->msg);
    GNUNET_free (msgw);
    removed = GNUNET_YES;    
  }
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (plugin->session_map, 
						       &s->target.hashPubKey, 
						       s));
  GNUNET_STATISTICS_set (plugin->env->stats,
			 "# UNIX sessions active",
			 GNUNET_CONTAINER_multihashmap_size (plugin->session_map),
			 GNUNET_NO);
  if ((GNUNET_YES == removed) && (NULL == plugin->msg_head))
    reschedule_select (plugin);
  if (GNUNET_SCHEDULER_NO_TASK != s->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (s->timeout_task);
    s->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_free (s);
}


/**
 * Actually send out the message, assume we've got the address and
 * send_handle squared away!
 *
 * @param cls closure
 * @param send_handle which handle to send message on
 * @param target who should receive this message (ignored by UNIX)
 * @param msgbuf one or more GNUNET_MessageHeader(s) strung together
 * @param msgbuf_size the size of the msgbuf to send
 * @param priority how important is the message (ignored by UNIX)
 * @param timeout when should we time out (give up) if we can not transmit?
 * @param addr the addr to send the message to, needs to be a sockaddr for us
 * @param addrlen the len of addr
 * @param payload bytes payload to send
 * @param cont continuation to call once the message has
 *        been transmitted (or if the transport is ready
 *        for the next transmission call; or if the
 *        peer disconnected...)
 * @param cont_cls closure for cont
 * @return on success the number of bytes written, RETRY for retry, -1 on errors
 */
static ssize_t
unix_real_send (void *cls,
                struct GNUNET_NETWORK_Handle *send_handle,
                const struct GNUNET_PeerIdentity *target, const char *msgbuf,
                size_t msgbuf_size, unsigned int priority,
                struct GNUNET_TIME_Absolute timeout,
                const struct UnixAddress *addr,
                size_t addrlen,
                size_t payload,
                GNUNET_TRANSPORT_TransmitContinuation cont,
                void *cont_cls)
{
  struct Plugin *plugin = cls;
  ssize_t sent;
  const void *sb;
  size_t sbs;
  struct sockaddr_un un;
  size_t slen;
  const char *unix_path;


  GNUNET_assert (NULL != plugin);
  if (NULL == send_handle)
  {
    GNUNET_break (0); /* We do not have a send handle */
    return GNUNET_SYSERR;
  }
  if ((NULL == addr) || (0 == addrlen))
  {
    GNUNET_break (0); /* Can never send if we don't have an address */
    return GNUNET_SYSERR;
  }

  /* Prepare address */
  unix_path = (const char *)  &addr[1];
  memset (&un, 0, sizeof (un));
  un.sun_family = AF_UNIX;
  slen =  strlen (unix_path);
  if (slen >= sizeof (un.sun_path))
    slen = sizeof (un.sun_path) - 1;
  GNUNET_assert (slen < sizeof (un.sun_path));
  memcpy (un.sun_path, unix_path, slen);
  un.sun_path[slen] = '\0';
  slen = sizeof (struct sockaddr_un);
#if LINUX
  un.sun_path[0] = '\0';
#endif
#if HAVE_SOCKADDR_IN_SIN_LEN
  un.sun_len = (u_char) slen;
#endif
  sb = (struct sockaddr *) &un;
  sbs = slen;

resend:
  /* Send the data */
  sent = 0;
  sent = GNUNET_NETWORK_socket_sendto (send_handle, msgbuf, msgbuf_size, sb, sbs);

  if (GNUNET_SYSERR == sent)
  {
    if ( (EAGAIN == errno) ||
	 (ENOBUFS == errno) )
      return RETRY; /* We have to retry later  */
    if (EMSGSIZE == errno)
    {
      socklen_t size = 0;
      socklen_t len = sizeof (size);

      GNUNET_NETWORK_socket_getsockopt ((struct GNUNET_NETWORK_Handle *)
                                        send_handle, SOL_SOCKET, SO_SNDBUF, &size,
                                        &len);
      if (size < msgbuf_size)
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG,
                    "Trying to increase socket buffer size from %i to %i for message size %i\n",
                    size, ((msgbuf_size / 1000) + 2) * 1000, msgbuf_size);
        size = ((msgbuf_size / 1000) + 2) * 1000;
        if (GNUNET_OK == GNUNET_NETWORK_socket_setsockopt
            ((struct GNUNET_NETWORK_Handle *) send_handle, SOL_SOCKET, SO_SNDBUF,
             &size, sizeof (size)))
          goto resend; /* Increased buffer size, retry sending */
        else
        {
          /* Could not increase buffer size: error, no retry */
          GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "setsockopt");
          return GNUNET_SYSERR;
        }
      }
      else
      {
        /* Buffer is bigger than message:  error, no retry
         * This should never happen!*/
        GNUNET_break (0);
        return GNUNET_SYSERR;
      }
    }
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "UNIX transmit %u-byte message to %s (%d: %s)\n",
       (unsigned int) msgbuf_size, 
       GNUNET_a2s (sb, sbs), 
       (int) sent,
       (sent < 0) ? STRERROR (errno) : "ok");
  return sent;
}


/**
 * Closure for 'get_session_it'.
 */
struct GetSessionIteratorContext
{ 
  /**
   * Location to store the session, if found.
   */
  struct Session *res;

  /**
   * Address information.
   */
  const char *address;

  /**
   * Number of bytes in 'address'
   */
  size_t addrlen;
};


/**
 * Function called to find a session by address.
 *
 * @param cls the 'struct LookupCtx'
 * @param key peer we are looking for (unused)
 * @param value a session
 * @return GNUNET_YES if not found (continue looking), GNUNET_NO on success
 */
static int
get_session_it (void *cls, 
		const struct GNUNET_HashCode *key, 
		void *value)
{
  struct GetSessionIteratorContext *gsi = cls;
  struct Session *s = value;

  if ( (gsi->addrlen == s->addrlen) &&
       (0 == memcmp (gsi->address, s->addr, s->addrlen)) )
  {
    gsi->res = s;
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Session was idle for too long, so disconnect it
 *
 * @param cls the 'struct Session' to disconnect
 * @param tc scheduler context
 */
static void
session_timeout (void *cls, 
		 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Session *s = cls;
  
  s->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Session %p was idle for %s, disconnecting\n",
       s,
       GNUNET_STRINGS_relative_time_to_string (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
					       GNUNET_YES));
  disconnect_session (s);
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
unix_plugin_get_session (void *cls,
			 const struct GNUNET_HELLO_Address *address)
{
  struct Plugin *plugin = cls;
  struct Session *s;
  struct GetSessionIteratorContext gsi;
  struct UnixAddress *ua;
  char * addrstr;
  uint32_t addr_str_len;

  GNUNET_assert (NULL != plugin);
  GNUNET_assert (NULL != address);

  ua = (struct UnixAddress *) address->address;
  if ((NULL == address->address) || (0 == address->address_length) ||
  		(sizeof (struct UnixAddress) > address->address_length))
  {
    GNUNET_break (0);
    return NULL;
  }
	addrstr = (char *) &ua[1];
	addr_str_len = ntohl (ua->addrlen);
	if (addr_str_len != address->address_length - sizeof (struct UnixAddress *))
  {
		/* This can be a legacy address */
    return NULL;
  }

  if ('\0' != addrstr[addr_str_len - 1])
  {
    GNUNET_break (0);
    return NULL;
  }
  if (strlen (addrstr) + 1 != addr_str_len)
  {
    GNUNET_break (0);
    return NULL;
  }

  /* Check if already existing */
  gsi.address = (const char *) address->address;
  gsi.addrlen = address->address_length;
  gsi.res = NULL;
  GNUNET_CONTAINER_multihashmap_get_multiple (plugin->session_map, 
					      &address->peer.hashPubKey, 
					      &get_session_it, &gsi);
  if (NULL != gsi.res)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, 
	 "Found existing session\n");
    return gsi.res;
  }

  /* create a new session */
  s = GNUNET_malloc (sizeof (struct Session) + address->address_length);
  s->addr = (struct UnixAddress *) &s[1];
  s->addrlen = address->address_length;
  s->plugin = plugin;
  memcpy (s->addr, address->address, address->address_length);
  memcpy (&s->target, &address->peer, sizeof (struct GNUNET_PeerIdentity));
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == s->timeout_task);
  s->timeout_task = GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
						  &session_timeout,
						  s);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Creating a new session %p for address `%s'\n",
       s,  unix_address_to_string (NULL, address->address, address->address_length));
  (void) GNUNET_CONTAINER_multihashmap_put (plugin->session_map,
					    &address->peer.hashPubKey, s,
					    GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  GNUNET_STATISTICS_set (plugin->env->stats,
			 "# UNIX sessions active",
			 GNUNET_CONTAINER_multihashmap_size (plugin->session_map),
			 GNUNET_NO);
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
unix_plugin_send (void *cls,
                  struct Session *session,
                  const char *msgbuf, size_t msgbuf_size,
                  unsigned int priority,
                  struct GNUNET_TIME_Relative to,
                  GNUNET_TRANSPORT_TransmitContinuation cont, void *cont_cls)
{
  struct Plugin *plugin = cls;
  struct UNIXMessageWrapper *wrapper;
  struct UNIXMessage *message;
  int ssize;
  
  GNUNET_assert (NULL != plugin);
  GNUNET_assert (NULL != session);

  if (GNUNET_OK != 
      GNUNET_CONTAINER_multihashmap_contains_value (plugin->session_map,
						    &session->target.hashPubKey,
						    session))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, 
	 "Invalid session for peer `%s' `%s'\n",
	 GNUNET_i2s (&session->target),
	 (const char *) session->addr);
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, 
       "Sending %u bytes with session for peer `%s' `%s'\n",
       msgbuf_size,
       GNUNET_i2s (&session->target),
       (const char *) session->addr);
  ssize = sizeof (struct UNIXMessage) + msgbuf_size;
  message = GNUNET_malloc (sizeof (struct UNIXMessage) + msgbuf_size);
  message->header.size = htons (ssize);
  message->header.type = htons (0);
  memcpy (&message->sender, plugin->env->my_identity,
          sizeof (struct GNUNET_PeerIdentity));
  memcpy (&message[1], msgbuf, msgbuf_size);
  reschedule_session_timeout (session);
  wrapper = GNUNET_malloc (sizeof (struct UNIXMessageWrapper));
  wrapper->msg = message;
  wrapper->msgsize = ssize;
  wrapper->payload = msgbuf_size;
  wrapper->priority = priority;
  wrapper->timeout = GNUNET_TIME_absolute_add (GNUNET_TIME_absolute_get(), to);
  wrapper->cont = cont;
  wrapper->cont_cls = cont_cls;
  wrapper->session = session;
  GNUNET_CONTAINER_DLL_insert (plugin->msg_head, 
			       plugin->msg_tail,
			       wrapper);
  plugin->bytes_in_queue += ssize;
  GNUNET_STATISTICS_set (plugin->env->stats,
			 "# bytes currently in UNIX buffers",
			 plugin->bytes_in_queue, 
			 GNUNET_NO);
  if (GNUNET_NO == plugin->with_ws)
    reschedule_select (plugin);
  return ssize;
}


/**
 * Demultiplexer for UNIX messages
 *
 * @param plugin the main plugin for this transport
 * @param sender from which peer the message was received
 * @param currhdr pointer to the header of the message
 * @param ua address to look for
 * @param ua_len length of the address
 */
static void
unix_demultiplexer (struct Plugin *plugin, struct GNUNET_PeerIdentity *sender,
                    const struct GNUNET_MessageHeader *currhdr,
                    const struct UnixAddress *ua, size_t ua_len)
{
  struct Session *s = NULL;
  struct GNUNET_HELLO_Address * addr;

  GNUNET_break (ntohl(plugin->ats_network.value) != GNUNET_ATS_NET_UNSPECIFIED);

  GNUNET_assert (ua_len >= sizeof (struct UnixAddress));

  LOG (GNUNET_ERROR_TYPE_DEBUG, 
       "Received message from %s\n",
       unix_address_to_string(NULL, ua, ua_len));
  GNUNET_STATISTICS_update (plugin->env->stats,
			    "# bytes received via UNIX",
			    ntohs (currhdr->size),
			    GNUNET_NO);

  addr = GNUNET_HELLO_address_allocate (sender,
					"unix",
					ua,
					ua_len);
  s = lookup_session (plugin, sender, ua, ua_len);
  if (NULL == s)
    s = unix_plugin_get_session (plugin, addr);
  reschedule_session_timeout (s);

  plugin->env->receive (plugin->env->cls, sender, currhdr,
                        s, (const char *) ua, ua_len);

  plugin->env->update_address_metrics (plugin->env->cls,
				       sender,
				       (const char *) ua, ua_len,
				       s,
				       &plugin->ats_network, 1);

  GNUNET_free (addr);
}


/**
 * Read from UNIX domain socket (it is ready).
 *
 * @param plugin the plugin
 */
static void
unix_plugin_select_read (struct Plugin *plugin)
{
  char buf[65536] GNUNET_ALIGN;
  struct UnixAddress *ua;
  struct UNIXMessage *msg;
  struct GNUNET_PeerIdentity sender;
  struct sockaddr_un un;
  socklen_t addrlen;
  ssize_t ret;
  int offset;
  int tsize;
  char *msgbuf;
  const struct GNUNET_MessageHeader *currhdr;
  uint16_t csize;
  size_t ua_len;

  addrlen = sizeof (un);
  memset (&un, 0, sizeof (un));

  ret =
      GNUNET_NETWORK_socket_recvfrom (plugin->unix_sock.desc, buf, sizeof (buf),
                                      (struct sockaddr *) &un, &addrlen);

  if ((GNUNET_SYSERR == ret) && ((errno == EAGAIN) || (errno == ENOBUFS)))
    return;

  if (ret == GNUNET_SYSERR)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "recvfrom");
    return;
  }
  else
  {
#if LINUX
    un.sun_path[0] = '/';
#endif
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Read %d bytes from socket %s\n", ret,
                &un.sun_path[0]);
  }

  GNUNET_assert (AF_UNIX == (un.sun_family));
  ua_len = sizeof (struct UnixAddress) + strlen (&un.sun_path[0]) +1;
  ua = GNUNET_malloc (ua_len);
  ua->addrlen = htonl (strlen (&un.sun_path[0]) +1);
  ua->options = htonl (0);
  memcpy (&ua[1], &un.sun_path[0], strlen (&un.sun_path[0]) +1);

  msg = (struct UNIXMessage *) buf;
  csize = ntohs (msg->header.size);
  if ((csize < sizeof (struct UNIXMessage)) || (csize > ret))
  {
    GNUNET_break_op (0);
    return;
  }
  msgbuf = (char *) &msg[1];
  memcpy (&sender, &msg->sender, sizeof (struct GNUNET_PeerIdentity));
  offset = 0;
  tsize = csize - sizeof (struct UNIXMessage);
  while (offset + sizeof (struct GNUNET_MessageHeader) <= tsize)
  {
    currhdr = (struct GNUNET_MessageHeader *) &msgbuf[offset];
    csize = ntohs (currhdr->size);
    if ((csize < sizeof (struct GNUNET_MessageHeader)) ||
        (csize > tsize - offset))
    {
      GNUNET_break_op (0);
      break;
    }
    unix_demultiplexer (plugin, &sender, currhdr, ua, ua_len);
    offset += csize;
  }
  GNUNET_free (ua);
}


/**
 * Write to UNIX domain socket (it is ready).
 *
 * @param plugin the plugin
 */
static void
unix_plugin_select_write (struct Plugin *plugin)
{
  int sent = 0;
  struct UNIXMessageWrapper * msgw;

  while (NULL != (msgw = plugin->msg_tail))
  {
    if (GNUNET_TIME_absolute_get_remaining (msgw->timeout).rel_value > 0)
      break; /* Message is ready for sending */
    /* Message has a timeout */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Timeout for message with %u bytes \n", 
	 (unsigned int) msgw->msgsize);
    GNUNET_CONTAINER_DLL_remove (plugin->msg_head, plugin->msg_tail, msgw);
    plugin->bytes_in_queue -= msgw->msgsize;
    GNUNET_STATISTICS_set (plugin->env->stats, 
			   "# bytes currently in UNIX buffers",
			   plugin->bytes_in_queue, GNUNET_NO);    
    GNUNET_STATISTICS_update (plugin->env->stats,
			      "# UNIX bytes discarded",
			      msgw->msgsize,
			      GNUNET_NO);
    if (NULL != msgw->cont)
      msgw->cont (msgw->cont_cls,
		  &msgw->session->target, 
		  GNUNET_SYSERR, 
		  msgw->payload, 
		  0);    
    GNUNET_free (msgw->msg);
    GNUNET_free (msgw);  
  }
  if (NULL == msgw)
    return; /* Nothing to send at the moment */

  sent = unix_real_send (plugin,
                         plugin->unix_sock.desc,
                         &msgw->session->target,
                         (const char *) msgw->msg,
                         msgw->msgsize,
                         msgw->priority,
                         msgw->timeout,
                         msgw->session->addr,
                         msgw->session->addrlen,
                         msgw->payload,
                         msgw->cont, msgw->cont_cls);

  if (RETRY == sent)
  {
    GNUNET_STATISTICS_update (plugin->env->stats,
			      "# UNIX retry attempts",
			      1, GNUNET_NO);
    return;
  }
  if (GNUNET_SYSERR == sent)
  {
    /* failed and no retry */
    if (NULL != msgw->cont)
      msgw->cont (msgw->cont_cls, &msgw->session->target, GNUNET_SYSERR, msgw->payload, 0);

    GNUNET_CONTAINER_DLL_remove(plugin->msg_head, plugin->msg_tail, msgw);

    GNUNET_assert (plugin->bytes_in_queue >= msgw->msgsize);
    plugin->bytes_in_queue -= msgw->msgsize;
    GNUNET_STATISTICS_set (plugin->env->stats, 
			   "# bytes currently in UNIX buffers",
			   plugin->bytes_in_queue, GNUNET_NO);
    GNUNET_STATISTICS_update (plugin->env->stats,
			      "# UNIX bytes discarded",
			      msgw->msgsize,
			      GNUNET_NO);

    GNUNET_free (msgw->msg);
    GNUNET_free (msgw);
    return;
  }
  /* successfully sent bytes */
  GNUNET_break (sent > 0);
  GNUNET_CONTAINER_DLL_remove (plugin->msg_head, 
			       plugin->msg_tail, 
			       msgw); 
  GNUNET_assert (plugin->bytes_in_queue >= msgw->msgsize);
  plugin->bytes_in_queue -= msgw->msgsize;
  GNUNET_STATISTICS_set (plugin->env->stats,
			 "# bytes currently in UNIX buffers",
			 plugin->bytes_in_queue,
			 GNUNET_NO);
  GNUNET_STATISTICS_update (plugin->env->stats,
			    "# bytes transmitted via UNIX",
			    msgw->msgsize,
			    GNUNET_NO);  
  if (NULL != msgw->cont)
    msgw->cont (msgw->cont_cls, &msgw->session->target, 
		GNUNET_OK,
		msgw->payload, 
		msgw->msgsize);  
  GNUNET_free (msgw->msg);
  GNUNET_free (msgw);
}


/**
 * We have been notified that our writeset has something to read.  We don't
 * know which socket needs to be read, so we have to check each one
 * Then reschedule this function to be called again once more is available.
 *
 * @param cls the plugin handle
 * @param tc the scheduling context (for rescheduling this function again)
 */
static void
unix_plugin_select (void *cls,
		    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;

  plugin->select_task = GNUNET_SCHEDULER_NO_TASK;
  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;

  if ((tc->reason & GNUNET_SCHEDULER_REASON_WRITE_READY) != 0)
  {
    /* Ready to send data */
    GNUNET_assert (GNUNET_NETWORK_fdset_isset
                   (tc->write_ready, plugin->unix_sock.desc));
    if (NULL != plugin->msg_head)
      unix_plugin_select_write (plugin);
  }

  if ((tc->reason & GNUNET_SCHEDULER_REASON_READ_READY) != 0)
  {
    /* Ready to receive data */
    GNUNET_assert (GNUNET_NETWORK_fdset_isset
                   (tc->read_ready, plugin->unix_sock.desc));
    unix_plugin_select_read (plugin);
  }
  reschedule_select (plugin);
}


/**
 * Create a slew of UNIX sockets.  If possible, use IPv6 and IPv4.
 *
 * @param cls closure for server start, should be a struct Plugin *
 * @return number of sockets created or GNUNET_SYSERR on error
 */
static int
unix_transport_server_start (void *cls)
{
  struct Plugin *plugin = cls;
  struct sockaddr *serverAddr;
  socklen_t addrlen;
  struct sockaddr_un un;
  size_t slen;

  memset (&un, 0, sizeof (un));
  un.sun_family = AF_UNIX;
  slen = strlen (plugin->unix_socket_path) + 1;
  if (slen >= sizeof (un.sun_path))
    slen = sizeof (un.sun_path) - 1;

  memcpy (un.sun_path, plugin->unix_socket_path, slen);
  un.sun_path[slen] = '\0';
  slen = sizeof (struct sockaddr_un);
#if HAVE_SOCKADDR_IN_SIN_LEN
  un.sun_len = (u_char) slen;
#endif

  serverAddr = (struct sockaddr *) &un;
  addrlen = slen;
#if LINUX
  un.sun_path[0] = '\0';
#endif
  plugin->ats_network = plugin->env->get_address_type (plugin->env->cls, serverAddr, addrlen);
  plugin->unix_sock.desc =
      GNUNET_NETWORK_socket_create (AF_UNIX, SOCK_DGRAM, 0);
  if (NULL == plugin->unix_sock.desc)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "socket");
    return GNUNET_SYSERR;
  }
  if (GNUNET_NETWORK_socket_bind (plugin->unix_sock.desc, serverAddr, addrlen, 0)
      != GNUNET_OK)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "bind");
    GNUNET_NETWORK_socket_close (plugin->unix_sock.desc);
    plugin->unix_sock.desc = NULL;
    return GNUNET_SYSERR;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Bound to `%s'\n", plugin->unix_socket_path);
  plugin->rs = GNUNET_NETWORK_fdset_create ();
  plugin->ws = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_zero (plugin->rs);
  GNUNET_NETWORK_fdset_zero (plugin->ws);
  GNUNET_NETWORK_fdset_set (plugin->rs, plugin->unix_sock.desc);
  GNUNET_NETWORK_fdset_set (plugin->ws, plugin->unix_sock.desc);

  reschedule_select (plugin);

  return 1;
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
unix_address_to_string (void *cls, const void *addr, size_t addrlen)
{
  static char rbuf[1024];
	struct UnixAddress *ua = (struct UnixAddress *) addr;
	char *addrstr;
	char *tmp;
	size_t addr_str_len;

  if ((NULL == addr) || (0 == addrlen) || (sizeof (struct UnixAddress) > addrlen))
  {
    GNUNET_break (0);
    return NULL;
  }
	addrstr = (char *) &ua[1];
	addr_str_len = ntohl (ua->addrlen);

	if (addr_str_len != addrlen - sizeof (struct UnixAddress))
  {
    GNUNET_break (0);
    return NULL;
  }

  if ('\0' != addrstr[addr_str_len - 1])
  {
    GNUNET_break (0);
    return NULL;
  }
  if (strlen (addrstr) + 1 != addr_str_len)
  {
    GNUNET_break (0);
    return NULL;
  }

  GNUNET_asprintf(&tmp, "%s.%u.%s", PLUGIN_NAME, ntohl (ua->options), addrstr);
  memcpy (rbuf, tmp, strlen (tmp) + 1);
  GNUNET_free (tmp);
  return rbuf;
}

/**
 * Function that will be called to check if a binary address for this
 * plugin is well-formed and corresponds to an address for THIS peer
 * (as per our configuration).  Naturally, if absolutely necessary,
 * plugins can be a bit conservative in their answer, but in general
 * plugins should make sure that the address does not redirect
 * traffic to a 3rd party that might try to man-in-the-middle our
 * traffic.
 *
 * @param cls closure, should be our handle to the Plugin
 * @param addr pointer to the address
 * @param addrlen length of addr
 * @return GNUNET_OK if this is a plausible address for this peer
 *         and transport, GNUNET_SYSERR if not
 *
 */
static int
unix_check_address (void *cls, const void *addr, size_t addrlen)
{
	struct Plugin* plugin = cls;
	struct UnixAddress *ua = (struct UnixAddress *) addr;
	char *addrstr;
	size_t addr_str_len;

  if ((NULL == addr) || (0 == addrlen) || (sizeof (struct UnixAddress) > addrlen))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
	addrstr = (char *) &ua[1];
	addr_str_len = ntohl (ua->addrlen);
  if ('\0' != addrstr[addr_str_len - 1])
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (strlen (addrstr) + 1 != addr_str_len)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  if (0 == strcmp (plugin->unix_socket_path, addrstr))
  	return GNUNET_OK;
  return GNUNET_SYSERR;
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
unix_plugin_address_pretty_printer (void *cls, const char *type,
                                    const void *addr, size_t addrlen,
                                    int numeric,
                                    struct GNUNET_TIME_Relative timeout,
                                    GNUNET_TRANSPORT_AddressStringCallback asc,
                                    void *asc_cls)
{
  if ((NULL != addr) && (addrlen > 0))
  {
    asc (asc_cls, unix_address_to_string (NULL, addr, addrlen));
  }
  else
  {
    GNUNET_break (0);
    asc (asc_cls, "<invalid UNIX address>");
  }
  asc (asc_cls, NULL);
}


/**
 * Function called to convert a string address to
 * a binary address.
 *
 * @param cls closure ('struct Plugin*')
 * @param addr string address
 * @param addrlen length of the address (strlen(addr) + '\0')
 * @param buf location to store the buffer
 *        If the function returns GNUNET_SYSERR, its contents are undefined.
 * @param added length of created address
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
static int
unix_string_to_address (void *cls, const char *addr, uint16_t addrlen,
    void **buf, size_t *added)
{
	struct UnixAddress *ua;
  char *address;
  char *plugin;
  char *optionstr;
  uint32_t options;
  size_t ua_size;

  /* Format unix.options.address */
  address = NULL;
  plugin = NULL;
  optionstr = NULL;
  options = 0;
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
  plugin = GNUNET_strdup (addr);
  optionstr = strchr (plugin, '.');
  if (NULL == optionstr)
  {
    GNUNET_break (0);
    GNUNET_free (plugin);
    return GNUNET_SYSERR;
  }
  optionstr[0] = '\0';
  optionstr ++;
  options = atol (optionstr);
  address = strchr (optionstr, '.');
  if (NULL == address)
  {
    GNUNET_break (0);
    GNUNET_free (plugin);
    return GNUNET_SYSERR;
  }
  address[0] = '\0';
  address ++;
  if (0 != strcmp(plugin, PLUGIN_NAME))
  {
    GNUNET_break (0);
    GNUNET_free (plugin);
    return GNUNET_SYSERR;
  }

  ua_size = sizeof (struct UnixAddress) + strlen (address) + 1;
  ua = GNUNET_malloc (ua_size);
  ua->options = htonl (options);
  ua->addrlen = htonl (strlen (address) + 1);
  memcpy (&ua[1], address, strlen (address) + 1);
  GNUNET_free (plugin);

  (*buf) = ua;
  (*added) = ua_size;
  return GNUNET_OK;
}


/**
 * Notify transport service about address
 *
 * @param cls the plugin
 * @param tc unused
 */
static void
address_notification (void *cls,
		      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;
  size_t len;
  struct UnixAddress *ua;

  len = sizeof (struct UnixAddress) + strlen (plugin->unix_socket_path) + 1;
  ua = GNUNET_malloc (len);
  ua->options = htonl (myoptions);
  ua->addrlen = htonl(strlen (plugin->unix_socket_path) + 1);
  memcpy (&ua[1], plugin->unix_socket_path, strlen (plugin->unix_socket_path) + 1);

  plugin->address_update_task = GNUNET_SCHEDULER_NO_TASK;
  plugin->env->notify_address (plugin->env->cls, GNUNET_YES,
                               ua, len, "unix");
  GNUNET_free (ua);
}


/**
 * Increment session timeout due to activity
 *
 * @param s session for which the timeout should be moved
 */
static void
reschedule_session_timeout (struct Session *s)
{
  GNUNET_assert (NULL != s);
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK != s->timeout_task);
  GNUNET_SCHEDULER_cancel (s->timeout_task);
  s->timeout_task =  GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                                                   &session_timeout,
                                                   s);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Timeout rescheduled for session %p set to %s\n",
       s,
       GNUNET_STRINGS_relative_time_to_string (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
					       GNUNET_YES));
}


/**
 * Function called on sessions to disconnect
 *
 * @param cls the plugin (unused)
 * @param key peer identity (unused)
 * @param value the 'struct Session' to disconnect
 * @return GNUNET_YES (always, continue to iterate)
 */
static int
get_session_delete_it (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  struct Session *s = value;

  disconnect_session (s);
  return GNUNET_YES;
}


/**
 * Disconnect from a remote node.  Clean up session if we have one for this peer
 *
 * @param cls closure for this call (should be handle to Plugin)
 * @param target the peeridentity of the peer to disconnect
 * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
 */
static void
unix_disconnect (void *cls, 
		 const struct GNUNET_PeerIdentity *target)
{
  struct Plugin *plugin = cls;

  GNUNET_assert (plugin != NULL);
  GNUNET_CONTAINER_multihashmap_get_multiple (plugin->session_map,
					      &target->hashPubKey, 
					      &get_session_delete_it, plugin);
}


/**
 * The exported method.  Initializes the plugin and returns a
 * struct with the callbacks.
 *
 * @param cls the plugin's execution environment
 * @return NULL on error, plugin functions otherwise
 */
void *
libgnunet_plugin_transport_unix_init (void *cls)
{
  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  unsigned long long port;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  struct Plugin *plugin;
  int sockets_created;

  if (NULL == env->receive)
  {
    /* run in 'stub' mode (i.e. as part of gnunet-peerinfo), don't fully
       initialze the plugin or the API */
    api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
    api->cls = NULL;
    api->address_pretty_printer = &unix_plugin_address_pretty_printer;
    api->address_to_string = &unix_address_to_string;
    api->string_to_address = &unix_string_to_address;
    return api;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (env->cfg, "transport-unix", "PORT",
                                             &port))
    port = UNIX_NAT_DEFAULT_PORT;
  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->port = port;
  plugin->env = env;
  GNUNET_asprintf (&plugin->unix_socket_path, 
		   "/tmp/unix-plugin-sock.%d",
                   plugin->port);

  /* Initialize my flags */
  myoptions = 0;

  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
  api->cls = plugin;

  api->get_session = &unix_plugin_get_session;
  api->send = &unix_plugin_send;
  api->disconnect = &unix_disconnect;
  api->address_pretty_printer = &unix_plugin_address_pretty_printer;
  api->address_to_string = &unix_address_to_string;
  api->check_address = &unix_check_address;
  api->string_to_address = &unix_string_to_address;
  sockets_created = unix_transport_server_start (plugin);
  if (0 == sockets_created)
    LOG (GNUNET_ERROR_TYPE_WARNING,
	 _("Failed to open UNIX listen socket\n"));
  plugin->session_map = GNUNET_CONTAINER_multihashmap_create (10, GNUNET_NO);
  plugin->address_update_task = GNUNET_SCHEDULER_add_now (&address_notification, plugin);
  return api;
}


/**
 * Shutdown the plugin.
 *
 * @param cls the plugin API returned from the initialization function
 * @return NULL (always)
 */
void *
libgnunet_plugin_transport_unix_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;
  struct UNIXMessageWrapper * msgw;
  struct UnixAddress *ua;
  size_t len;

  if (NULL == plugin)
  {
    GNUNET_free (api);
    return NULL;
  }

  len = sizeof (struct UnixAddress) + strlen (plugin->unix_socket_path) + 1;
  ua = GNUNET_malloc (len);
  ua->options = htonl (myoptions);
  ua->addrlen = htonl(strlen (plugin->unix_socket_path) + 1);
  memcpy (&ua[1], plugin->unix_socket_path, strlen (plugin->unix_socket_path) + 1);

  plugin->env->notify_address (plugin->env->cls, GNUNET_NO,
  														 ua, len, "unix");
  GNUNET_free (ua);
  while (NULL != (msgw = plugin->msg_head))
  {
    GNUNET_CONTAINER_DLL_remove (plugin->msg_head, plugin->msg_tail, msgw);
    if (msgw->cont != NULL)
      msgw->cont (msgw->cont_cls,  &msgw->session->target, GNUNET_SYSERR,
                  msgw->payload, 0);
    GNUNET_free (msgw->msg);
    GNUNET_free (msgw);
  }

  if (GNUNET_SCHEDULER_NO_TASK != plugin->select_task)
  {
    GNUNET_SCHEDULER_cancel (plugin->select_task);
    plugin->select_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (GNUNET_SCHEDULER_NO_TASK != plugin->address_update_task)
  {
    GNUNET_SCHEDULER_cancel (plugin->address_update_task);
    plugin->address_update_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != plugin->unix_sock.desc)
  {
    GNUNET_break (GNUNET_OK ==
                  GNUNET_NETWORK_socket_close (plugin->unix_sock.desc));
    plugin->unix_sock.desc = NULL;
    plugin->with_ws = GNUNET_NO;
  }
  GNUNET_CONTAINER_multihashmap_iterate (plugin->session_map,
					 &get_session_delete_it, plugin);
  GNUNET_CONTAINER_multihashmap_destroy (plugin->session_map);
  if (NULL != plugin->rs)
    GNUNET_NETWORK_fdset_destroy (plugin->rs);
  if (NULL != plugin->ws)
    GNUNET_NETWORK_fdset_destroy (plugin->ws);
  GNUNET_free (plugin->unix_socket_path);
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}

/* end of plugin_transport_unix.c */
