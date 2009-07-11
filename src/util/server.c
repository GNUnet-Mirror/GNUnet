/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file util/server.c
 * @brief library for building GNUnet network servers
 * @author Christian Grothoff
 *
 * TODO:
 * - fix inefficient memmove in message processing
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_network_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_server_lib.h"
#include "gnunet_time_lib.h"

#define DEBUG_SERVER GNUNET_NO

/**
 * List of arrays of message handlers.
 */
struct HandlerList
{
  /**
   * This is a linked list.
   */
  struct HandlerList *next;

  /**
   * NULL-terminated array of handlers.
   */
  const struct GNUNET_SERVER_MessageHandler *handlers;
};


/**
 * List of arrays of message handlers.
 */
struct NotifyList
{
  /**
   * This is a linked list.
   */
  struct NotifyList *next;

  /**
   * Function to call.
   */
  GNUNET_SERVER_DisconnectCallback callback;

  /**
   * Closure for callback.
   */
  void *callback_cls;
};


/**
 * @brief handle for a server
 */
struct GNUNET_SERVER_Handle
{
  /**
   * My scheduler.
   */
  struct GNUNET_SCHEDULER_Handle *sched;

  /**
   * List of handlers for incoming messages.
   */
  struct HandlerList *handlers;

  /**
   * List of our current clients.
   */
  struct GNUNET_SERVER_Client *clients;

  /**
   * Linked list of functions to call on disconnects by clients.
   */
  struct NotifyList *disconnect_notify_list;

  /**
   * Function to call for access control.
   */
  GNUNET_NETWORK_AccessCheck access;

  /**
   * Closure for access.
   */
  void *access_cls;

  /**
   * After how long should an idle connection time
   * out (on write).
   */
  struct GNUNET_TIME_Relative idle_timeout;

  /**
   * maximum write buffer size for accepted sockets
   */
  size_t maxbuf;

  /**
   * Pipe used to signal shutdown of the server.
   */
  int shutpipe[2];

  /**
   * Socket used to listen for new connections.  Set to
   * "-1" by GNUNET_SERVER_destroy to initiate shutdown.
   */
  int listen_socket;

  /**
   * Set to GNUNET_YES if we are shutting down.
   */
  int do_shutdown;

  /**
   * Do we ignore messages of types that we do not
   * understand or do we require that a handler
   * is found (and if not kill the connection)?
   */
  int require_found;

};


/**
 * @brief handle for a client of the server
 */
struct GNUNET_SERVER_Client
{

  /**
   * Size of the buffer for incoming data.  Should be
   * first so we get nice alignment.
   */
  char incoming_buffer[GNUNET_SERVER_MAX_MESSAGE_SIZE];

  /**
   * This is a linked list.
   */
  struct GNUNET_SERVER_Client *next;

  /**
   * Server that this client belongs to.
   */
  struct GNUNET_SERVER_Handle *server;

  /**
   * Client closure for callbacks.
   */
  void *client_closure;

  /**
   * Callback to receive from client.
   */
  GNUNET_SERVER_ReceiveCallback receive;

  /**
   * Callback to cancel receive from client.
   */
  GNUNET_SERVER_ReceiveCancelCallback receive_cancel;

  /**
   * Callback to ask about transmit-ready notification.
   */
  GNUNET_SERVER_TransmitReadyCallback notify_transmit_ready;

   /**
   * Callback to ask about transmit-ready notification.
   */
  GNUNET_SERVER_TransmitReadyCancelCallback notify_transmit_ready_cancel;

  /**
   * Callback to check if client is still valid.
   */
  GNUNET_SERVER_CheckCallback check;

  /**
   * Callback to destroy client.
   */
  GNUNET_SERVER_DestroyCallback destroy;

  /**
   * Side-buffer for incoming data used when processing
   * is suspended.
   */
  char *side_buf;

  /**
   * Number of bytes in the side buffer.
   */
  size_t side_buf_size;

  /**
   * Last activity on this socket (used to time it out
   * if reference_count == 0).
   */
  struct GNUNET_TIME_Absolute last_activity;

  /**
   * Current task identifier for the receive call
   * (or GNUNET_SCHEDULER_NO_PREREQUISITE_TASK for none).
   */
  GNUNET_SCHEDULER_TaskIdentifier my_receive;

  /**
   * How many bytes in the "incoming_buffer" are currently
   * valid? (starting at offset 0).
   */
  size_t receive_pos;

  /**
   * Number of external entities with a reference to
   * this client object.
   */
  unsigned int reference_count;

  /**
   * Was processing if incoming messages suspended while
   * we were still processing data already received?
   * This is a counter saying how often processing was
   * suspended (once per handler invoked).
   */
  unsigned int suspended;

  /**
   * Are we currently in the "process_client_buffer" function (and
   * will hence restart the receive job on exit if suspended == 0 once
   * we are done?).  If this is set, then "receive_done" will
   * essentially only decrement suspended; if this is not set, then
   * "receive_done" may need to restart the receive process (either
   * from the side-buffer or via select/recv).
   */
  int in_process_client_buffer;

  /**
   * We're about to close down this client due to some serious
   * error.
   */
  int shutdown_now;

};


/**
 * Server has been asked to shutdown, free resources.
 */
static void
destroy_server (struct GNUNET_SERVER_Handle *server)
{
  struct GNUNET_SERVER_Client *pos;
  struct HandlerList *hpos;
  struct NotifyList *npos;

#if DEBUG_SERVER
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Server shutting down.\n");
#endif
  GNUNET_assert (server->listen_socket == -1);
  GNUNET_break (0 == CLOSE (server->shutpipe[0]));
  GNUNET_break (0 == CLOSE (server->shutpipe[1]));
  while (server->clients != NULL)
    {
      pos = server->clients;
      server->clients = pos->next;
      pos->server = NULL;
    }
  while (NULL != (hpos = server->handlers))
    {
      server->handlers = hpos->next;
      GNUNET_free (hpos);
    }
  while (NULL != (npos = server->disconnect_notify_list))
    {
      server->disconnect_notify_list = npos->next;
      GNUNET_free (npos);
    }
  GNUNET_free (server);
}


/**
 * Scheduler says our listen socket is ready.
 * Process it!
 */
static void
process_listen_socket (void *cls,
                       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_SERVER_Handle *server = cls;
  struct GNUNET_NETWORK_SocketHandle *sock;
  struct GNUNET_SERVER_Client *client;
  fd_set r;

  if ((server->do_shutdown) ||
      ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0))
    {
      /* shutdown was initiated */
      GNUNET_assert (server->listen_socket != -1);
      GNUNET_break (0 == CLOSE (server->listen_socket));
      server->listen_socket = -1;
      if (server->do_shutdown)
        destroy_server (server);
      return;
    }
  GNUNET_assert (FD_ISSET (server->listen_socket, tc->read_ready));
  GNUNET_assert (!FD_ISSET (server->shutpipe[0], tc->read_ready));
  sock = GNUNET_NETWORK_socket_create_from_accept (tc->sched,
                                                   server->access,
                                                   server->access_cls,
                                                   server->listen_socket,
                                                   server->maxbuf);
  if (sock != NULL)
    {
#if DEBUG_SERVER
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Server accepted incoming connection.\n");
#endif
      client = GNUNET_SERVER_connect_socket (server, sock);
      /* decrement reference count, we don't keep "client" alive */
      GNUNET_SERVER_client_drop (client);
    }
  /* listen for more! */
  FD_ZERO (&r);
  FD_SET (server->listen_socket, &r);
  FD_SET (server->shutpipe[0], &r);
  GNUNET_SCHEDULER_add_select (server->sched,
                               GNUNET_YES,
                               GNUNET_SCHEDULER_PRIORITY_HIGH,
                               GNUNET_SCHEDULER_NO_PREREQUISITE_TASK,
                               GNUNET_TIME_UNIT_FOREVER_REL,
                               GNUNET_MAX (server->listen_socket,
                                           server->shutpipe[0]) + 1, &r, NULL,
                               &process_listen_socket, server);
}


/**
 * Create and initialize a listen socket for the server.
 *
 * @return -1 on error, otherwise the listen socket
 */
static int
open_listen_socket (const struct sockaddr *serverAddr, socklen_t socklen)
{
  const static int on = 1;
  int fd;
  uint16_t port;

  switch (serverAddr->sa_family)
    {
    case AF_INET:
      port = ntohs (((const struct sockaddr_in *) serverAddr)->sin_port);
      break;
    case AF_INET6:
      port = ntohs (((const struct sockaddr_in6 *) serverAddr)->sin6_port);
      break;
    default:
      GNUNET_break (0);
      return -1;
    }
  fd = SOCKET (serverAddr->sa_family, SOCK_STREAM, 0);
  if (fd < 0)
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "socket");
      return -1;
    }
#ifndef MINGW
  // FIXME NILS
  if (0 != fcntl (fd, F_SETFD, fcntl (fd, F_GETFD) | FD_CLOEXEC))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                         "fcntl");
#endif
  if (SETSOCKOPT (fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on)) < 0)
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                         "setsockopt");
  /* bind the socket */
  if (BIND (fd, serverAddr, socklen) < 0)
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "bind");
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _
                  ("`%s' failed for port %d. Is the service already running?\n"),
                  "bind", port);
      GNUNET_break (0 == CLOSE (fd));
      return -1;
    }
  if (0 != LISTEN (fd, 5))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "listen");
      GNUNET_break (0 == CLOSE (fd));
      return -1;
    }
#if DEBUG_SERVER
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Server starts to listen on port %u.\n",
		  port);
#endif
  return fd;
}


/**
 * Create a new server.
 *
 * @param sched scheduler to use
 * @param access function for access control
 * @param access_cls closure for access
 * @param serverAddr address to listen on (including port), use NULL
 *        for internal server (no listening)
 * @param socklen length of serverAddr
 * @param maxbuf maximum write buffer size for accepted sockets
 * @param idle_timeout after how long should we timeout idle connections?
 * @param require_found if YES, connections sending messages of unknown type
 *        will be closed
 * @return handle for the new server, NULL on error
 *         (typically, "port" already in use)
 */
struct GNUNET_SERVER_Handle *
GNUNET_SERVER_create (struct GNUNET_SCHEDULER_Handle *sched,
                      GNUNET_NETWORK_AccessCheck access,
                      void *access_cls,
                      const struct sockaddr *serverAddr,
                      socklen_t socklen,
                      size_t maxbuf,
                      struct GNUNET_TIME_Relative
                      idle_timeout, int require_found)
{
  struct GNUNET_SERVER_Handle *ret;
  int lsock;
  fd_set r;

  lsock = -2;
  if (serverAddr != NULL)
    {
      lsock = open_listen_socket (serverAddr, socklen);
      if (lsock == -1)
        return NULL;
    }
  ret = GNUNET_malloc (sizeof (struct GNUNET_SERVER_Handle));
  if (0 != PIPE (ret->shutpipe))
    {
      GNUNET_break (0 == CLOSE (lsock));
      GNUNET_free (ret);
      return NULL;
    }
  ret->sched = sched;
  ret->maxbuf = maxbuf;
  ret->idle_timeout = idle_timeout;
  ret->listen_socket = lsock;
  ret->access = access;
  ret->access_cls = access_cls;
  ret->require_found = require_found;
  if (lsock >= 0)
    {
      FD_ZERO (&r);
      FD_SET (ret->listen_socket, &r);
      FD_SET (ret->shutpipe[0], &r);
      GNUNET_SCHEDULER_add_select (sched,
                                   GNUNET_YES,
                                   GNUNET_SCHEDULER_PRIORITY_HIGH,
                                   GNUNET_SCHEDULER_NO_PREREQUISITE_TASK,
                                   GNUNET_TIME_UNIT_FOREVER_REL,
                                   GNUNET_MAX (ret->listen_socket,
                                               ret->shutpipe[0]) + 1, &r,
                                   NULL, &process_listen_socket, ret);
    }
  return ret;
}


/**
 * Free resources held by this server.
 */
void
GNUNET_SERVER_destroy (struct GNUNET_SERVER_Handle *s)
{
  static char c;

  GNUNET_assert (s->do_shutdown == GNUNET_NO);
  s->do_shutdown = GNUNET_YES;
  if (s->listen_socket == -1)
    destroy_server (s);
  else
    GNUNET_break (1 == WRITE (s->shutpipe[1], &c, 1));
}


/**
 * Add additional handlers to an existing server.
 *
 * @param server the server to add handlers to
 * @param handlers array of message handlers for
 *        incoming messages; the last entry must
 *        have "NULL" for the "callback"; multiple
 *        entries for the same type are allowed,
 *        they will be called in order of occurence.
 *        These handlers can be removed later;
 *        the handlers array must exist until removed
 *        (or server is destroyed).
 */
void
GNUNET_SERVER_add_handlers (struct GNUNET_SERVER_Handle *server,
                            const struct GNUNET_SERVER_MessageHandler
                            *handlers)
{
  struct HandlerList *p;

  p = GNUNET_malloc (sizeof (struct HandlerList));
  p->handlers = handlers;
  p->next = server->handlers;
  server->handlers = p;
}


/**
 * Inject a message into the server, pretend it came
 * from the specified client.  Delivery of the message
 * will happen instantly (if a handler is installed;
 * otherwise the call does nothing).
 *
 * @param server the server receiving the message
 * @param sender the "pretended" sender of the message
 *        can be NULL!
 * @param message message to transmit
 * @return GNUNET_OK if the message was OK and the
 *                   connection can stay open
 *         GNUNET_SYSERR if the connection to the
 *         client should be shut down
 */
int
GNUNET_SERVER_inject (struct GNUNET_SERVER_Handle *server,
                      struct GNUNET_SERVER_Client *sender,
                      const struct GNUNET_MessageHeader *message)
{
  struct HandlerList *pos;
  const struct GNUNET_SERVER_MessageHandler *mh;
  unsigned int i;
  uint16_t type;
  uint16_t size;
  int found;

  type = ntohs (message->type);
  size = ntohs (message->size);
#if DEBUG_SERVER
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Server schedules transmission of %u-byte message of type %u to client.\n",
	      size,
	      type);
#endif
  pos = server->handlers;
  found = GNUNET_NO;
  while (pos != NULL)
    {
      i = 0;
      while (pos->handlers[i].callback != NULL)
        {
          mh = &pos->handlers[i];
          if (mh->type == type)
            {
              if ((mh->expected_size != 0) && (mh->expected_size != size))
                {
                  GNUNET_break_op (0);
                  return GNUNET_SYSERR;
                }
              if (sender != NULL)
                sender->suspended++;
              mh->callback (mh->callback_cls, sender, message);
              found = GNUNET_YES;
            }
          i++;
        }
      pos = pos->next;
    }
  if (found == GNUNET_NO)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
                  _("Received message of unknown type %d\n"), type);
      if (server->require_found == GNUNET_YES)
        return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}


/**
 * We're finished with this client and especially its input
 * processing.  If the RC is zero, free all resources otherwise wait
 * until RC hits zero to do so.
 */
static void
shutdown_incoming_processing (struct GNUNET_SERVER_Client *client)
{
  struct GNUNET_SERVER_Client *prev;
  struct GNUNET_SERVER_Client *pos;
  struct GNUNET_SERVER_Handle *server;
  struct NotifyList *n;
  unsigned int rc;

  GNUNET_assert (client->my_receive == GNUNET_SCHEDULER_NO_PREREQUISITE_TASK);
  rc = client->reference_count;
  if (client->server != NULL)
    {
      server = client->server;
      client->server = NULL;
      prev = NULL;
      pos = server->clients;
      while ((pos != NULL) && (pos != client))
        {
          prev = pos;
          pos = pos->next;
        }
      GNUNET_assert (pos != NULL);
      if (prev == NULL)
        server->clients = pos->next;
      else
        prev->next = pos->next;
      n = server->disconnect_notify_list;
      while (n != NULL)
        {
          n->callback (n->callback_cls, client);
          n = n->next;
        }
    }
  /* wait for RC to hit zero, then free */
  if (rc > 0)
    return;
  client->destroy (client->client_closure);
  GNUNET_free (client);
}


/**
 * Go over the contents of the client buffer; as long as full messages
 * are available, pass them on for processing.  Update the buffer
 * accordingly.  Handles fatal errors by shutting down the connection.
 *
 * @param client identifies which client receive buffer to process
 */
static void
process_client_buffer (struct GNUNET_SERVER_Client *client)
{
  struct GNUNET_SERVER_Handle *server;
  const struct GNUNET_MessageHeader *hdr;
  size_t msize;

  client->in_process_client_buffer = GNUNET_YES;
  server = client->server;
#if DEBUG_SERVER
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Private buffer contains %u bytes; client is %s and we are %s\n",
	      client->receive_pos,
	      client->suspended ? "suspended" : "up",
	      client->shutdown_now ? "in shutdown" : "running");
#endif
  while ((client->receive_pos >= sizeof (struct GNUNET_MessageHeader)) &&
         (0 == client->suspended) && (GNUNET_YES != client->shutdown_now))
    {
      hdr = (const struct GNUNET_MessageHeader *) &client->incoming_buffer;
      msize = ntohs (hdr->size);
      if (msize > client->receive_pos)
	{
#if DEBUG_SERVER
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Total message size is %u, we only have %u bytes; need more data\n",
		      msize,
		      client->receive_pos);
#endif
	  break;
	}
#if DEBUG_SERVER
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Passing %u bytes to callback for processing\n",
		  msize);
#endif
      if ((msize < sizeof (struct GNUNET_MessageHeader)) ||
          (GNUNET_OK != GNUNET_SERVER_inject (server, client, hdr)))
        {
          client->in_process_client_buffer = GNUNET_NO;
          shutdown_incoming_processing (client);
          return;
        }
      /* FIXME: this is highly inefficient; we should
         try to avoid this if the new base address is
         already nicely aligned.  See old handler code... */
      memmove (client->incoming_buffer,
               &client->incoming_buffer[msize], client->receive_pos - msize);
      client->receive_pos -= msize;
    }
  client->in_process_client_buffer = GNUNET_NO;
  if (GNUNET_YES == client->shutdown_now)
    shutdown_incoming_processing (client);
}


/**
 * We are receiving an incoming message.  Process it.
 *
 * @param cls our closure (handle for the client)
 * @param buf buffer with data received from network
 * @param available number of bytes available in buf
 * @param addr address of the sender
 * @param addrlen length of addr
 * @param errCode code indicating errors receiving, 0 for success
 */
static void
process_incoming (void *cls,
                  const void *buf,
                  size_t available,
                  const struct sockaddr *addr, 
		  socklen_t addrlen,
		  int errCode)
{
  struct GNUNET_SERVER_Client *client = cls;
  struct GNUNET_SERVER_Handle *server = client->server;
  const char *cbuf = buf;
  size_t maxcpy;

  client->my_receive = GNUNET_SCHEDULER_NO_PREREQUISITE_TASK;
  if ((buf == NULL) ||
      (available == 0) ||
      (errCode != 0) ||
      (server == NULL) ||
      (client->shutdown_now == GNUNET_YES) ||
      (GNUNET_YES != client->check (client->client_closure)))
    {
      /* other side closed connection, error connecting, etc. */
      shutdown_incoming_processing (client);
      return;
    }
#if DEBUG_SERVER
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Server receives %u bytes from `%s'.\n",
	      available,
	      GNUNET_a2s(addr, addrlen));
#endif
  GNUNET_SERVER_client_keep (client);
  client->last_activity = GNUNET_TIME_absolute_get ();
  /* process data (if available) */
  while (available > 0)
    {
      maxcpy = available;
      if (maxcpy > sizeof (client->incoming_buffer) - client->receive_pos)
        maxcpy = sizeof (client->incoming_buffer) - client->receive_pos;
#if DEBUG_SERVER
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Can copy %u bytes to private buffer\n",
		  maxcpy);
#endif
      memcpy (&client->incoming_buffer[client->receive_pos], cbuf, maxcpy);
      client->receive_pos += maxcpy;
      cbuf += maxcpy;
      available -= maxcpy;
      if (0 < client->suspended)
        {
          if (available > 0)
            {
#if DEBUG_SERVER
	      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			  "Client has suspended processing; copying %u bytes to side buffer to be used later.\n",
			  available);
#endif
	      GNUNET_assert (client->side_buf_size == 0);
	      GNUNET_assert (client->side_buf == NULL);
              client->side_buf_size = available;
              client->side_buf = GNUNET_malloc (available);
              memcpy (client->side_buf, cbuf, available);
              available = 0;
            }
          break;                /* do not run next client iteration! */
        }
#if DEBUG_SERVER
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Now processing messages in private buffer\n");
#endif
      process_client_buffer (client);
    }
  GNUNET_assert (available == 0);
  if ((client->suspended == 0) &&
      (GNUNET_YES != client->shutdown_now) && (client->server != NULL))
    {
      /* Finally, keep receiving! */
      client->my_receive = client->receive (client->client_closure,
                                            GNUNET_SERVER_MAX_MESSAGE_SIZE,
                                            server->idle_timeout,
                                            &process_incoming, client);
    }
  if (GNUNET_YES == client->shutdown_now)
    shutdown_incoming_processing (client);
  GNUNET_SERVER_client_drop (client);
}


/**
 * FIXME: document.
 */
static void
restart_processing (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_SERVER_Client *client = cls;

  process_client_buffer (client);
  if (0 == client->suspended)
    client->my_receive = client->receive (client->client_closure,
                                          GNUNET_SERVER_MAX_MESSAGE_SIZE,
                                          client->server->idle_timeout,
                                          &process_incoming, client);
}


/**
 * Add a client to the set of our clients and
 * start receiving.
 */
static void
add_client (struct GNUNET_SERVER_Handle *server,
            struct GNUNET_SERVER_Client *client)
{
  client->server = server;
  client->last_activity = GNUNET_TIME_absolute_get ();
  client->next = server->clients;
  server->clients = client;
  client->my_receive = client->receive (client->client_closure,
                                        GNUNET_SERVER_MAX_MESSAGE_SIZE,
                                        server->idle_timeout,
                                        &process_incoming, client);
}


/**
 * Create a request for receiving data from a socket.
 *
 * @param cls identifies the socket to receive from
 * @param max how much data to read at most
 * @param timeout when should this operation time out
 * @param receiver function to call for processing
 * @param receiver_cls closure for receiver
 * @return task identifier that can be used to cancel the operation
 */
static GNUNET_SCHEDULER_TaskIdentifier
sock_receive (void *cls,
              size_t max,
              struct GNUNET_TIME_Relative timeout,
              GNUNET_NETWORK_Receiver receiver, void *receiver_cls)
{
  return GNUNET_NETWORK_receive (cls, max, timeout, receiver, receiver_cls);
}


/**
 * Wrapper to cancel receiving from a socket.
 * 
 * @param cls handle to the GNUNET_NETWORK_SocketHandle to cancel
 * @param tc task ID that was returned by GNUNET_NETWORK_receive
 */
static void
sock_receive_cancel (void *cls, GNUNET_SCHEDULER_TaskIdentifier ti)
{
  GNUNET_NETWORK_receive_cancel (cls, ti);
}


/**
 * FIXME: document.
 */
static void *
sock_notify_transmit_ready (void *cls,
                            size_t size,
                            struct GNUNET_TIME_Relative timeout,
                            GNUNET_NETWORK_TransmitReadyNotify notify,
                            void *notify_cls)
{
  return GNUNET_NETWORK_notify_transmit_ready (cls, size, timeout, notify,
                                               notify_cls);
}


/**
 * FIXME: document.
 */
static void
sock_notify_transmit_ready_cancel (void *cls, void *h)
{
  GNUNET_NETWORK_notify_transmit_ready_cancel (h);
}


/**
 * Check if socket is still valid (no fatal errors have happened so far).
 *
 * @param cls the socket
 * @return GNUNET_YES if valid, GNUNET_NO otherwise
 */
static int
sock_check (void *cls)
{
  return GNUNET_NETWORK_socket_check (cls);
}


/**
 * Destroy this socket (free resources).
 *
 * @param cls the socket
 */
static void
sock_destroy (void *cls)
{
  GNUNET_NETWORK_socket_destroy (cls);
}


/**
 * Add a TCP socket-based connection to the set of handles managed by
 * this server.  Use this function for outgoing (P2P) connections that
 * we initiated (and where this server should process incoming
 * messages).
 *
 * @param server the server to use
 * @param connection the connection to manage (client must
 *        stop using this connection from now on)
 * @return the client handle (client should call
 *         "client_drop" on the return value eventually)
 */
struct GNUNET_SERVER_Client *
GNUNET_SERVER_connect_socket (struct
                              GNUNET_SERVER_Handle
                              *server,
                              struct GNUNET_NETWORK_SocketHandle *connection)
{
  struct GNUNET_SERVER_Client *client;

  client = GNUNET_malloc (sizeof (struct GNUNET_SERVER_Client));
  client->client_closure = connection;
  client->receive = &sock_receive;
  client->receive_cancel = &sock_receive_cancel;
  client->notify_transmit_ready = &sock_notify_transmit_ready;
  client->notify_transmit_ready_cancel = &sock_notify_transmit_ready_cancel;
  client->check = &sock_check;
  client->destroy = &sock_destroy;
  client->reference_count = 1;
  add_client (server, client);
  return client;
}


/**
 * Add an arbitrary connection to the set of handles managed by this
 * server.  This can be used if a sending and receiving does not
 * really go over the network (internal transmission) or for servers
 * using UDP.
 *
 * @param server the server to use
 * @param chandle opaque handle for the connection
 * @param creceive receive function for the connection
 * @param ccancel cancel receive function for the connection
 * @param cnotify transmit notification function for the connection
 * @param cnotify_cancel transmit notification cancellation function for the connection
 * @param ccheck function to test if the connection is still up
 * @param cdestroy function to close and free the connection
 * @return the client handle (client should call
 *         "client_drop" on the return value eventually)
 */
struct GNUNET_SERVER_Client *
GNUNET_SERVER_connect_callback (struct
                                GNUNET_SERVER_Handle
                                *server,
                                void *chandle,
                                GNUNET_SERVER_ReceiveCallback
                                creceive,
                                GNUNET_SERVER_ReceiveCancelCallback
                                ccancel,
                                GNUNET_SERVER_TransmitReadyCallback
                                cnotify,
                                GNUNET_SERVER_TransmitReadyCancelCallback
                                cnotify_cancel,
                                GNUNET_SERVER_CheckCallback
                                ccheck,
                                GNUNET_SERVER_DestroyCallback cdestroy)
{
  struct GNUNET_SERVER_Client *client;

  client = GNUNET_malloc (sizeof (struct GNUNET_SERVER_Client));
  client->client_closure = chandle;
  client->receive = creceive;
  client->receive_cancel = ccancel;
  client->notify_transmit_ready = cnotify;
  client->notify_transmit_ready_cancel = cnotify_cancel;
  client->check = ccheck;
  client->destroy = cdestroy;
  client->reference_count = 1;
  add_client (server, client);
  return client;
}


/**
 * Notify the server that the given client handle should
 * be kept (keeps the connection up if possible, increments
 * the internal reference counter).
 *
 * @param client the client to keep
 */
void
GNUNET_SERVER_client_keep (struct GNUNET_SERVER_Client *client)
{
  client->reference_count++;
}


/**
 * Notify the server that the given client handle is no
 * longer required.  Decrements the reference counter.  If
 * that counter reaches zero an inactive connection maybe
 * closed.
 *
 * @param client the client to drop
 */
void
GNUNET_SERVER_client_drop (struct GNUNET_SERVER_Client *client)
{
  GNUNET_assert (client->reference_count > 0);
  client->reference_count--;
  if ((client->server == NULL) && (client->reference_count == 0))
    shutdown_incoming_processing (client);
}


/**
 * Obtain the network address of the other party.
 *
 * @param client the client to get the address for
 * @param addr where to store the address
 * @param addrlen where to store the length of the address
 * @return GNUNET_OK on success
 */
int
GNUNET_SERVER_client_get_address (struct GNUNET_SERVER_Client *client,
                                  void **addr, size_t * addrlen)
{
  if (client->receive != &sock_receive)
    return GNUNET_SYSERR;       /* not a network client */
  return GNUNET_NETWORK_socket_get_address (client->client_closure,
                                            addr, addrlen);
}


/**
 * Ask the server to notify us whenever a client disconnects.
 * This function is called whenever the actual network connection
 * is closed; the reference count may be zero or larger than zero
 * at this point.
 *
 * @param server the server manageing the clients
 * @param callback function to call on disconnect
 * @param callback_cls closure for callback
 */
void
GNUNET_SERVER_disconnect_notify (struct GNUNET_SERVER_Handle *server,
                                 GNUNET_SERVER_DisconnectCallback callback,
                                 void *callback_cls)
{
  struct NotifyList *n;

  n = GNUNET_malloc (sizeof (struct NotifyList));
  n->callback = callback;
  n->callback_cls = callback_cls;
  n->next = server->disconnect_notify_list;
  server->disconnect_notify_list = n;
}


/**
 * Ask the server to disconnect from the given client.
 * This is the same as returning GNUNET_SYSERR from a message
 * handler, except that it allows dropping of a client even
 * when not handling a message from that client.
 *
 * @param client the client to disconnect from
 */
void
GNUNET_SERVER_client_disconnect (struct GNUNET_SERVER_Client *client)
{
  if (client->server == NULL)
    return;                     /* already disconnected */
  GNUNET_assert (client->my_receive != GNUNET_SCHEDULER_NO_PREREQUISITE_TASK);
  client->receive_cancel (client->client_closure, client->my_receive);
  client->my_receive = GNUNET_SCHEDULER_NO_PREREQUISITE_TASK;
  shutdown_incoming_processing (client);
}


/**
 * Notify us when the server has enough space to transmit
 * a message of the given size to the given client.
 *
 * @param server the server to use
 * @param client client to transmit message to
 * @param size requested amount of buffer space
 * @param timeout after how long should we give up (and call
 *        notify with buf NULL and size 0)?
 * @param callback function to call when space is available
 * @param callback_cls closure for callback
 * @return non-NULL if the notify callback was queued; can be used
 *           to cancel the request using
 *           GNUNET_NETWORK_notify_transmit_ready_cancel.
 *         NULL if we are already going to notify someone else (busy)
 */
struct GNUNET_NETWORK_TransmitHandle *
GNUNET_SERVER_notify_transmit_ready (struct GNUNET_SERVER_Client *client,
                                     size_t size,
                                     struct GNUNET_TIME_Relative timeout,
                                     GNUNET_NETWORK_TransmitReadyNotify
                                     callback, void *callback_cls)
{
  return client->notify_transmit_ready (client->client_closure,
                                        size,
                                        timeout, callback, callback_cls);
}


/**
 * Resume receiving from this client, we are done processing the
 * current request.  This function must be called from within each
 * GNUNET_SERVER_MessageCallback (or its respective continuations).
 *
 * @param client client we were processing a message of
 * @param success GNUNET_OK to keep the connection open and
 *                          continue to receive
 *                GNUNET_SYSERR to close the connection (signal
 *                          serious error)
 */
void
GNUNET_SERVER_receive_done (struct GNUNET_SERVER_Client *client, int success)
{
  char *sb;

  if (client == NULL)
    return;
  GNUNET_assert (client->suspended > 0);
  client->suspended--;
  if (success != GNUNET_OK)
    client->shutdown_now = GNUNET_YES;
  if (client->suspended > 0)
    return;
  if (client->in_process_client_buffer == GNUNET_YES)
    return;
  if (client->side_buf_size > 0)
    {
      /* resume processing from side-buf */
      sb = client->side_buf;
      client->side_buf = NULL;
      /* this will also resume the receive job */
      if (GNUNET_YES != client->shutdown_now)
        process_incoming (client, sb, client->side_buf_size, NULL, 0, 0);
      else
        shutdown_incoming_processing (client);
      /* finally, free the side-buf */
      GNUNET_free (sb);
      return;
    }
  /* resume receive job */
  if (GNUNET_YES != client->shutdown_now)
    {
      GNUNET_SCHEDULER_add_continuation (client->server->sched,
                                         GNUNET_NO,
                                         &restart_processing,
                                         client,
                                         GNUNET_SCHEDULER_REASON_PREREQ_DONE);
      return;
    }
  shutdown_incoming_processing (client);
}


/* end of server.c */
