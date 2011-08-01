/*
     This file is part of GNUnet
     (C) 2010 Christian Grothoff (and other contributing authors)

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
#include "gnunet_connection_lib.h"
#include "gnunet_container_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_protocols.h"
#include "gnunet_resolver_service.h"
#include "gnunet_server_lib.h"
#include "gnunet_signatures.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_transport_plugin.h"
#include "transport.h"

#define DEBUG_UNIX GNUNET_NO
#define DETAILS GNUNET_NO

#define MAX_PROBES 20

/*
 * Transport cost to peer, always 1 for UNIX (direct connection)
 */
#define UNIX_DIRECT_DISTANCE 1

#define DEFAULT_NAT_PORT 0

/**
 * How long until we give up on transmitting the welcome message?
 */
#define HOSTNAME_RESOLVE_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * Starting port for listening and sending, eventually a config value
 */
#define UNIX_NAT_DEFAULT_PORT 22086

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

struct RetryList
{
  /**
   * Pointer to next element.
   */
  struct RetryList *next;

  /**
   * Pointer to previous element.
   */
  struct RetryList *prev;

  /**
   * The actual retry context.
   */
  struct RetrySendContext *retry_ctx;
};

/**
 * Network format for IPv4 addresses.
 */
struct IPv4UdpAddress
{
  /**
   * IPv4 address, in network byte order.
   */
  uint32_t ipv4_addr GNUNET_PACKED;

  /**
   * Port number, in network byte order.
   */
  uint16_t u_port GNUNET_PACKED;
};


/**
 * Network format for IPv6 addresses.
 */
struct IPv6UdpAddress
{
  /**
   * IPv6 address.
   */
  struct in6_addr ipv6_addr GNUNET_PACKED;

  /**
   * Port number, in network byte order.
   */
  uint16_t u6_port GNUNET_PACKED;
};

/* Forward definition */
struct Plugin;

struct PrettyPrinterContext
{
  GNUNET_TRANSPORT_AddressStringCallback asc;
  void *asc_cls;
  uint16_t port;
};

struct RetrySendContext
{

  /**
   * Main plugin handle.
   */
  struct Plugin *plugin;

  /**
   * Address of recipient.
   */
  char *addr;

  /**
   * Length of address.
   */
  ssize_t addrlen;

  /**
   * Message to send.
   */
  char *msg;

  /**
   * Size of the message.
   */
  int msg_size;

  /**
   * Handle to send message out on.
   */
  struct GNUNET_NETWORK_Handle *send_handle;

  /**
   * Continuation to call on success or
   * timeout.
   */
  GNUNET_TRANSPORT_TransmitContinuation cont;

  /**
   * Closure for continuation.
   */
  void *cont_cls;

  /**
   * The peer the message is destined for.
   */
  struct GNUNET_PeerIdentity target;

  /**
   * How long before not retrying any longer.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * How long the last message was delayed.
   */
  struct GNUNET_TIME_Relative delay;

  /**
   * The actual retry task.
   */
  GNUNET_SCHEDULER_TaskIdentifier retry_task;

  /**
   * The priority of the message.
   */
  unsigned int priority;

  /**
   * Entry in the DLL of retry items.
   */
  struct RetryList *retry_list_entry;
};


/**
 * UNIX NAT "Session"
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
   * The port we bound to
   */
  uint16_t port;
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

  /*
   * Session of peers with whom we are currently connected
   */
  struct PeerSession *sessions;

  /**
   * ID of task used to update our addresses when one expires.
   */
  GNUNET_SCHEDULER_TaskIdentifier address_update_task;

  /**
   * ID of select task
   */
  GNUNET_SCHEDULER_TaskIdentifier select_task;

  /**
   * Integer to append to unix domain socket.
   */
  uint16_t port;

  /**
   * FD Read set
   */
  struct GNUNET_NETWORK_FDSet *rs;

  /**
   * socket that we transmit all data with
   */
  struct UNIX_Sock_Info unix_sock;

  /**
   * Path of our unix domain socket (/tmp/unix-plugin-PORT)
   */
  char *unix_socket_path;

};

/**
 * Head of retry DLL.
 */
static struct RetryList *retry_list_head;

/**
 * Tail of retry DLL.
 */
static struct RetryList *retry_list_tail;


/**
 * Disconnect from a remote node.  Clean up session if we have one for this peer
 *
 * @param cls closure for this call (should be handle to Plugin)
 * @param target the peeridentity of the peer to disconnect
 * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
 */
void
unix_disconnect (void *cls, const struct GNUNET_PeerIdentity *target)
{
  /** TODO: Implement! */
  return;
}

/**
 * Shutdown the server process (stop receiving inbound traffic). Maybe
 * restarted later!
 *
 * @param cls Handle to the plugin for this transport
 *
 * @return returns the number of sockets successfully closed,
 *         should equal the number of sockets successfully opened
 */
static int
unix_transport_server_stop (void *cls)
{
  struct Plugin *plugin = cls;
  struct RetryList *pos;

  pos = retry_list_head;

  while(NULL != (pos = retry_list_head))
    {
      GNUNET_CONTAINER_DLL_remove(retry_list_head, retry_list_tail, pos);
      if (GNUNET_SCHEDULER_NO_TASK != pos->retry_ctx->retry_task)
        {
          GNUNET_SCHEDULER_cancel(pos->retry_ctx->retry_task);
        }
      GNUNET_free(pos->retry_ctx->msg);
      GNUNET_free(pos->retry_ctx->addr);
      GNUNET_free(pos->retry_ctx);
      GNUNET_free(pos);
    }

  if (plugin->select_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (plugin->select_task);
      plugin->select_task = GNUNET_SCHEDULER_NO_TASK;
    }

  GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (plugin->unix_sock.desc));
  plugin->unix_sock.desc = NULL;

  return GNUNET_OK;
}


struct PeerSession *
find_session (struct Plugin *plugin,
	      const struct GNUNET_PeerIdentity *peer)
{
  struct PeerSession *pos;

  pos = plugin->sessions;
  while (pos != NULL)
    {
      if (memcmp(&pos->target, peer, sizeof(struct GNUNET_PeerIdentity)) == 0)
        return pos;
      pos = pos->next;
    }

  return pos;
}

/* Forward Declaration */
static ssize_t
unix_real_send (void *cls,
                struct RetrySendContext *incoming_retry_context,
                struct GNUNET_NETWORK_Handle *send_handle,
                const struct GNUNET_PeerIdentity *target,
                const char *msgbuf,
                size_t msgbuf_size,
                unsigned int priority,
                struct GNUNET_TIME_Relative timeout,
                const void *addr,
                size_t addrlen,
                GNUNET_TRANSPORT_TransmitContinuation cont,
                void *cont_cls);

/**
 * Retry sending a message.
 *
 * @param cls closure a struct RetrySendContext
 * @param tc context information
 */
void retry_send_message (void *cls,
                         const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  struct RetrySendContext *retry_ctx = cls;

  if ( (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    {
      GNUNET_free(retry_ctx->msg);
      GNUNET_free(retry_ctx->addr);
      GNUNET_free(retry_ctx);
      return;
    }

  unix_real_send (retry_ctx->plugin,
                  retry_ctx,
                  retry_ctx->send_handle,
                  &retry_ctx->target,
                  retry_ctx->msg,
                  retry_ctx->msg_size,
                  retry_ctx->priority,
                  GNUNET_TIME_absolute_get_remaining (retry_ctx->timeout),
                  retry_ctx->addr,
                  retry_ctx->addrlen,
                  retry_ctx->cont,
                  retry_ctx->cont_cls);
  return;
}

/**
 * Actually send out the message, assume we've got the address and
 * send_handle squared away!
 *
 * @param cls closure
 * @param incoming_retry_context the retry context to use
 * @param send_handle which handle to send message on
 * @param target who should receive this message (ignored by UNIX)
 * @param msgbuf one or more GNUNET_MessageHeader(s) strung together
 * @param msgbuf_size the size of the msgbuf to send
 * @param priority how important is the message (ignored by UNIX)
 * @param timeout when should we time out (give up) if we can not transmit?
 * @param addr the addr to send the message to, needs to be a sockaddr for us
 * @param addrlen the len of addr
 * @param cont continuation to call once the message has
 *        been transmitted (or if the transport is ready
 *        for the next transmission call; or if the
 *        peer disconnected...)
 * @param cont_cls closure for cont
 *
 * @return the number of bytes written, -1 on errors
 */
static ssize_t
unix_real_send (void *cls,
                struct RetrySendContext *incoming_retry_context,
                struct GNUNET_NETWORK_Handle *send_handle,
	        const struct GNUNET_PeerIdentity *target,
	        const char *msgbuf,
	        size_t msgbuf_size,
	        unsigned int priority,
	        struct GNUNET_TIME_Relative timeout,
	        const void *addr,
	        size_t addrlen,
	        GNUNET_TRANSPORT_TransmitContinuation cont,
	        void *cont_cls)
{
  struct Plugin *plugin = cls;
  struct UNIXMessage *message;
  struct RetrySendContext *retry_ctx;
  int ssize;
  ssize_t sent;
  const void *sb;
  size_t sbs;
  struct sockaddr_un un;
  size_t slen;
  struct RetryList *retry_list_entry;
  int retry;

  if (send_handle == NULL)
    {
#if DEBUG_UNIX
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                       "unix_real_send with send_handle NULL!\n");
#endif
      /* failed to open send socket for AF */
      if (cont != NULL)
        cont (cont_cls, target, GNUNET_SYSERR);
      return 0;
    }
  if ((addr == NULL) || (addrlen == 0))
    {
#if DEBUG_UNIX
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		       "unix_real_send called without address, returning!\n");
#endif
      if (cont != NULL)
        cont (cont_cls, target, GNUNET_SYSERR);
      return 0; /* Can never send if we don't have an address!! */
    }

  /* Build the message to be sent */
  message = GNUNET_malloc (sizeof (struct UNIXMessage) + msgbuf_size);
  ssize = sizeof (struct UNIXMessage) + msgbuf_size;

  message->header.size = htons (ssize);
  message->header.type = htons (0);
  memcpy (&message->sender, plugin->env->my_identity,
          sizeof (struct GNUNET_PeerIdentity));
  memcpy (&message[1], msgbuf, msgbuf_size);

  memset(&un, 0, sizeof(un));
  un.sun_family = AF_UNIX;
  slen = strlen (addr) + 1;
  if (slen >= sizeof (un.sun_path))
    slen = sizeof (un.sun_path) - 1;
  sent = 0;
  GNUNET_assert(slen < sizeof(un.sun_path));
  memcpy (un.sun_path, addr, slen);
  un.sun_path[slen] = '\0';
  slen = sizeof (struct sockaddr_un);
#if LINUX
  un.sun_path[0] = '\0';
#endif
#if HAVE_SOCKADDR_IN_SIN_LEN
  un.sun_len = (u_char) slen;
#endif
  sb = (struct sockaddr*) &un;
  sbs = slen;
  retry = GNUNET_NO;

  sent = GNUNET_NETWORK_socket_sendto(send_handle, message, ssize, sb, sbs);

  if ((GNUNET_SYSERR == sent) && (errno == EAGAIN))
	  retry = GNUNET_YES;

  if ((GNUNET_SYSERR == sent) && (errno == EMSGSIZE))
  {
	  socklen_t size = 0;
	  socklen_t len = sizeof (size);
	  GNUNET_NETWORK_socket_getsockopt ((struct GNUNET_NETWORK_Handle * ) send_handle,
			  SOL_SOCKET,
			  SO_SNDBUF,
			  &size, &len);

	  if (size < ssize)
	  {
#if DEBUG_UNIX
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Trying to increase socket buffer size from %i to %i for message size %i\n",
	      size,
              ((ssize / 1000) + 2) * 1000, ssize);
#endif
		  size = ((ssize / 1000) + 2) * 1000;
		  if (GNUNET_NETWORK_socket_setsockopt ((struct GNUNET_NETWORK_Handle * ) send_handle,
				  SOL_SOCKET,
				  SO_SNDBUF,
				  &size, sizeof(size)) == GNUNET_OK)
			 retry = GNUNET_YES;
		  else
			 GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "setsockopt");
	  }
  }

  if (retry == GNUNET_YES)
    {
      if (incoming_retry_context == NULL)
        {
          retry_list_entry = GNUNET_malloc(sizeof(struct RetryList));
          retry_ctx = GNUNET_malloc(sizeof(struct RetrySendContext));
          retry_ctx->addr = GNUNET_malloc(addrlen);
          retry_ctx->msg = GNUNET_malloc(msgbuf_size);
          retry_ctx->plugin = plugin;
          memcpy(retry_ctx->addr, addr, addrlen);
          memcpy(retry_ctx->msg, msgbuf, msgbuf_size);
          retry_ctx->msg_size = msgbuf_size;
          retry_ctx->addrlen = addrlen;
          retry_ctx->send_handle = send_handle;
          retry_ctx->cont = cont;
          retry_ctx->cont_cls = cont_cls;
          retry_ctx->priority = priority;
          retry_ctx->timeout = GNUNET_TIME_relative_to_absolute(timeout);
          memcpy(&retry_ctx->target, target, sizeof(struct GNUNET_PeerIdentity));
          retry_ctx->delay = GNUNET_TIME_UNIT_MILLISECONDS;
          retry_ctx->retry_list_entry = retry_list_entry;
          retry_list_entry->retry_ctx = retry_ctx;
          GNUNET_CONTAINER_DLL_insert(retry_list_head, retry_list_tail, retry_list_entry);
        }
      else
        {
          retry_ctx = incoming_retry_context;
          retry_ctx->delay = GNUNET_TIME_relative_multiply(retry_ctx->delay, 2);
        }
      retry_ctx->retry_task = GNUNET_SCHEDULER_add_delayed(retry_ctx->delay, &retry_send_message, retry_ctx);

      //GNUNET_log_strerror (GNUNET_ERROR_TYPE_DEBUG, "send");
      GNUNET_free(message);
      return ssize;
    }
#if DEBUG_UNIX
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "UNIX transmit %u-byte message to %s (%d: %s)\n",
	      (unsigned int) ssize,
	      GNUNET_a2s (sb, sbs),
	      (int) sent,
	      (sent < 0) ? STRERROR (errno) : "ok");
#endif
  if (cont != NULL)
    {
      if (sent == GNUNET_SYSERR)
        cont (cont_cls, target, GNUNET_SYSERR);
      else
        {
          cont (cont_cls, target, GNUNET_OK);
        }
    }

  if (incoming_retry_context != NULL)
    {
      GNUNET_CONTAINER_DLL_remove(retry_list_head, retry_list_tail, incoming_retry_context->retry_list_entry);
      GNUNET_free(incoming_retry_context->retry_list_entry);
      GNUNET_free(incoming_retry_context->msg);
      GNUNET_free(incoming_retry_context->addr);
      GNUNET_free(incoming_retry_context);
    }

  GNUNET_free (message);
  return sent;
}


/**
 * Function that can be used by the transport service to transmit
 * a message using the plugin.
 *
 * @param cls closure
 * @param target who should receive this message (ignored by UNIX)
 * @param msgbuf one or more GNUNET_MessageHeader(s) strung together
 * @param msgbuf_size the size of the msgbuf to send
 * @param priority how important is the message (ignored by UNIX)
 * @param timeout when should we time out (give up) if we can not transmit?
 * @param session identifier used for this session (can be NULL)
 * @param addr the addr to send the message to, needs to be a sockaddr for us
 * @param addrlen the len of addr
 * @param force_address not used, we had better have an address to send to
 *        because we are stateless!!
 * @param cont continuation to call once the message has
 *        been transmitted (or if the transport is ready
 *        for the next transmission call; or if the
 *        peer disconnected...)
 * @param cont_cls closure for cont
 *
 * @return the number of bytes written (may return 0 and the message can
 *         still be transmitted later!)
 */
static ssize_t
unix_plugin_send (void *cls,
		     const struct GNUNET_PeerIdentity *target,
		     const char *msgbuf,
		     size_t msgbuf_size,
		     unsigned int priority,
		     struct GNUNET_TIME_Relative timeout,
		     struct Session *session,
		     const void *addr,
		     size_t addrlen,
		     int force_address,
		     GNUNET_TRANSPORT_TransmitContinuation cont, void *cont_cls)
{
  struct Plugin *plugin = cls;
  ssize_t sent;

  if (force_address == GNUNET_SYSERR)
    return GNUNET_SYSERR;
  GNUNET_assert (NULL == session);

#if DEBUG_UNIX
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Asked to send message to `%s'\n", (char *)addr);
#endif
  sent = unix_real_send(cls,
                        NULL,
                        plugin->unix_sock.desc,
                        target,
                        msgbuf, msgbuf_size,
                        priority, timeout, addr, addrlen,
                        cont, cont_cls);
#if DEBUG_UNIX
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Sent %d bytes to `%s'\n", sent, (char *)addr);
#endif
  if (sent == GNUNET_SYSERR)
    return 0;
  return sent;
}


/**
 * Demultiplexer for UNIX messages
 *
 * @param plugin the main plugin for this transport
 * @param sender from which peer the message was received
 * @param currhdr pointer to the header of the message
 * @param un the address from which the message was received
 * @param fromlen the length of the address
 */
static void
unix_demultiplexer(struct Plugin *plugin,
		   struct GNUNET_PeerIdentity *sender,
                   const struct GNUNET_MessageHeader *currhdr,
                   const struct sockaddr_un *un,
                   size_t fromlen)
{
  struct GNUNET_TRANSPORT_ATS_Information distance[2];

  distance[0].type = htonl (GNUNET_TRANSPORT_ATS_QUALITY_NET_DISTANCE);
  distance[0].value = htonl (UNIX_DIRECT_DISTANCE);
  distance[1].type = htonl (GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR);
  distance[1].value = htonl (0);

  GNUNET_assert(fromlen >= sizeof(struct sockaddr_un));

#if DEBUG_UNIX
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Received message from %s\n", un->sun_path);
#endif
  plugin->env->receive (plugin->env->cls, sender, currhdr,
                       (const struct GNUNET_TRANSPORT_ATS_Information *) &distance, 2,
                              NULL, un->sun_path, strlen(un->sun_path) + 1);
}


/*
 * @param cls the plugin handle
 * @param tc the scheduling context (for rescheduling this function again)
 *
 * We have been notified that our writeset has something to read.  We don't
 * know which socket needs to be read, so we have to check each one
 * Then reschedule this function to be called again once more is available.
 *
 */
static void
unix_plugin_select (void *cls,
		    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;
  char buf[65536];
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

  plugin->select_task = GNUNET_SCHEDULER_NO_TASK;
  if ( (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;

  addrlen = sizeof(un);
  memset(&un, 0, sizeof(un));
  GNUNET_assert (GNUNET_NETWORK_fdset_isset (tc->read_ready, plugin->unix_sock.desc));
  ret =
    GNUNET_NETWORK_socket_recvfrom (plugin->unix_sock.desc, buf, sizeof (buf),
                                    (struct sockaddr *)&un, &addrlen);

  if (ret == GNUNET_SYSERR)
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "recvfrom");
      plugin->select_task =
        GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                     GNUNET_SCHEDULER_NO_TASK,
                                     GNUNET_TIME_UNIT_FOREVER_REL, plugin->rs,
                                     NULL, &unix_plugin_select, plugin);
      return;
    }
  else
  {
#if LINUX
    un.sun_path[0] = '/';
#endif
#if DEBUG_UNIX
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Read %d bytes from socket %s\n", ret, &un.sun_path[0]);
#endif
  }

  GNUNET_assert (AF_UNIX == (un.sun_family));

  msg = (struct UNIXMessage *) buf;
  csize = ntohs (msg->header.size);
  if ( (csize < sizeof (struct UNIXMessage)) ||
       (csize > ret) )
    {
      GNUNET_break_op (0);
      plugin->select_task =
	GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
				     GNUNET_SCHEDULER_NO_TASK,
				     GNUNET_TIME_UNIT_FOREVER_REL, plugin->rs,
				     NULL, &unix_plugin_select, plugin);
      return;
    }
  msgbuf = (char *)&msg[1];
  memcpy (&sender, &msg->sender, sizeof (struct GNUNET_PeerIdentity));
  offset = 0;
  tsize = csize - sizeof (struct UNIXMessage);
  while (offset + sizeof (struct GNUNET_MessageHeader) <= tsize)
    {
      currhdr = (struct GNUNET_MessageHeader *)&msgbuf[offset];
      csize = ntohs (currhdr->size);
      if ( (csize < sizeof (struct GNUNET_MessageHeader)) ||
	   (csize > tsize - offset) )
	{
	  GNUNET_break_op (0);
	  break;
	}
      unix_demultiplexer(plugin, &sender, currhdr,
			 &un, sizeof(un));
      offset += csize;
    }
  plugin->select_task =
    GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                 GNUNET_SCHEDULER_NO_TASK,
                                 GNUNET_TIME_UNIT_FOREVER_REL, plugin->rs,
                                 NULL, &unix_plugin_select, plugin);
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

  memset(&un, 0, sizeof(un));
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

  serverAddr = (struct sockaddr*) &un;
  addrlen = slen;
#if LINUX
  un.sun_path[0] = '\0';
#endif

  plugin->unix_sock.desc = GNUNET_NETWORK_socket_create (AF_UNIX, SOCK_DGRAM, 0);
  if (NULL == plugin->unix_sock.desc)
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "socket");
      return GNUNET_SYSERR;
    }
  if (GNUNET_NETWORK_socket_bind (plugin->unix_sock.desc, serverAddr, addrlen) !=
      GNUNET_OK)
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "bind");
      GNUNET_NETWORK_socket_close (plugin->unix_sock.desc);
      plugin->unix_sock.desc = NULL;
      return GNUNET_SYSERR;
    }
#if DEBUG_UNIX
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, 
		   "unix",
		   "Bound to `%s'\n",
		   &un.sun_path[0]);
#endif
  plugin->rs = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_zero (plugin->rs);
  GNUNET_NETWORK_fdset_set (plugin->rs,
                            plugin->unix_sock.desc);

  plugin->select_task =
    GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                 GNUNET_SCHEDULER_NO_TASK,
                                 GNUNET_TIME_UNIT_FOREVER_REL, plugin->rs,
                                 NULL, &unix_plugin_select, plugin);
  return 1;
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
unix_check_address (void *cls,
		   const void *addr,
		   size_t addrlen)
{

#if DEBUG_UNIX
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                   "Informing transport service about my address `%s'\n",
                   (char *)addr);
#endif
  return GNUNET_OK;
}


/**
 * Append our port and forward the result.
 */
static void
append_port (void *cls, const char *hostname)
{
  struct PrettyPrinterContext *ppc = cls;
  char *ret;

  if (hostname == NULL)
    {
      ppc->asc (ppc->asc_cls, NULL);
      GNUNET_free (ppc);
      return;
    }
  GNUNET_asprintf (&ret, "%s:%d", hostname, ppc->port);
  ppc->asc (ppc->asc_cls, ret);
  GNUNET_free (ret);
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
unix_plugin_address_pretty_printer (void *cls,
                                   const char *type,
                                   const void *addr,
                                   size_t addrlen,
                                   int numeric,
                                   struct GNUNET_TIME_Relative timeout,
                                   GNUNET_TRANSPORT_AddressStringCallback asc,
                                   void *asc_cls)
{
  struct PrettyPrinterContext *ppc;
  const void *sb;
  size_t sbs;
  struct sockaddr_in a4;
  struct sockaddr_in6 a6;
  const struct IPv4UdpAddress *u4;
  const struct IPv6UdpAddress *u6;
  uint16_t port;

  if (addrlen == sizeof (struct IPv6UdpAddress))
    {
      u6 = addr;
      memset (&a6, 0, sizeof (a6));
      a6.sin6_family = AF_INET6;
      a6.sin6_port = u6->u6_port;
      memcpy (&a6.sin6_addr,
              &u6->ipv6_addr,
              sizeof (struct in6_addr));
      port = ntohs (u6->u6_port);
      sb = &a6;
      sbs = sizeof (a6);
    }
  else if (addrlen == sizeof (struct IPv4UdpAddress))
    {
      u4 = addr;
      memset (&a4, 0, sizeof (a4));
      a4.sin_family = AF_INET;
      a4.sin_port = u4->u_port;
      a4.sin_addr.s_addr = u4->ipv4_addr;
      port = ntohs (u4->u_port);
      sb = &a4;
      sbs = sizeof (a4);
    }
  else
    {
      /* invalid address */
      GNUNET_break_op (0);
      asc (asc_cls, NULL);
      return;
    }
  ppc = GNUNET_malloc (sizeof (struct PrettyPrinterContext));
  ppc->asc = asc;
  ppc->asc_cls = asc_cls;
  ppc->port = port;
  GNUNET_RESOLVER_hostname_get (sb,
                                sbs,
                                !numeric, timeout, &append_port, ppc);
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
unix_address_to_string (void *cls,
                       const void *addr,
                       size_t addrlen)
{
  if ((addr != NULL) && (addrlen > 0))
    return (const char *) addr;
  else
    return NULL;
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
  plugin->env->notify_address(plugin->env->cls,
                              GNUNET_YES,
                              plugin->unix_socket_path,
                              strlen(plugin->unix_socket_path) + 1);
}

/**
 * The exported method. Makes the core api available via a global and
 * returns the unix transport API.
 */
void *
libgnunet_plugin_transport_unix_init (void *cls)
{
  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  unsigned long long port;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  struct Plugin *plugin;
  int sockets_created;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (env->cfg,
					     "transport-unix",
					     "PORT",
					     &port))
    port = UNIX_NAT_DEFAULT_PORT;
  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->port = port;
  plugin->env = env;
  GNUNET_asprintf (&plugin->unix_socket_path, 
		   "/tmp/unix-plugin-sock.%d", 
		   plugin->port);
  
  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
  api->cls = plugin;

  api->send = &unix_plugin_send;
  api->disconnect = &unix_disconnect;
  api->address_pretty_printer = &unix_plugin_address_pretty_printer;
  api->address_to_string = &unix_address_to_string;
  api->check_address = &unix_check_address;
  sockets_created = unix_transport_server_start (plugin);
  if (sockets_created == 0)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Failed to open UNIX sockets\n"));

  GNUNET_SCHEDULER_add_now(address_notification, plugin);
  return api;
}

void *
libgnunet_plugin_transport_unix_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  unix_transport_server_stop (plugin);

  GNUNET_NETWORK_fdset_destroy (plugin->rs);
  GNUNET_free (plugin->unix_socket_path);
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}

/* end of plugin_transport_unix.c */
