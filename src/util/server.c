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
#include "gnunet_connection_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_server_lib.h"
#include "gnunet_time_lib.h"
#include "gnunet_disk_lib.h"
#include "gnunet_protocols.h"

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
  GNUNET_CONNECTION_AccessCheck access;

  /**
   * Closure for access.
   */
  void *access_cls;

  /**
   * NULL-terminated array of sockets used to listen for new
   * connections.
   */
  struct GNUNET_NETWORK_Handle **listen_sockets;

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
   * Task scheduled to do the listening.
   */
  GNUNET_SCHEDULER_TaskIdentifier listen_task;

  /**
   * Do we ignore messages of types that we do not understand or do we
   * require that a handler is found (and if not kill the connection)?
   */
  int require_found;

  /**
   * Should all of the clients of this server continue to process
   * connections as usual even if we get a shutdown request? (the
   * listen socket always ignores shutdown).
   */
  int clients_ignore_shutdown;

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
   * ID of task used to restart processing.
   */
  GNUNET_SCHEDULER_TaskIdentifier restart_task;

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

  /**
   * Are we currently trying to receive?
   */
  int receive_pending;
};


/**
 * Scheduler says our listen socket is ready.  Process it!
 *
 * @param cls handle to our server for which we are processing the listen
 *        socket
 * @param tc reason why we are running right now
 */
static void
process_listen_socket (void *cls,
                       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_SERVER_Handle *server = cls;
  struct GNUNET_CONNECTION_Handle *sock;
  struct GNUNET_SERVER_Client *client;
  struct GNUNET_NETWORK_FDSet *r;
  unsigned int i;

  server->listen_task = GNUNET_SCHEDULER_NO_TASK;
  r = GNUNET_NETWORK_fdset_create ();
  i = 0;
  while (NULL != server->listen_sockets[i])
    GNUNET_NETWORK_fdset_set (r, server->listen_sockets[i++]);
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    {
      /* ignore shutdown, someone else will take care of it! */
      server->listen_task = GNUNET_SCHEDULER_add_select (server->sched,
                                                         GNUNET_SCHEDULER_PRIORITY_HIGH,
                                                         GNUNET_SCHEDULER_NO_TASK,
                                                         GNUNET_TIME_UNIT_FOREVER_REL,
                                                         r, NULL,
                                                         &process_listen_socket,
                                                         server);
      GNUNET_NETWORK_fdset_destroy (r);
      return;
    }
  i = 0;
  while (NULL != server->listen_sockets[i])
    {
      if (GNUNET_NETWORK_fdset_isset
          (tc->read_ready, server->listen_sockets[i]))
        {
          sock =
            GNUNET_CONNECTION_create_from_accept (tc->sched, server->access,
                                                  server->access_cls,
                                                  server->listen_sockets[i],
                                                  server->maxbuf);
          if (sock != NULL)
            {
#if DEBUG_SERVER
              GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                          "Server accepted incoming connection.\n");
#endif
              client = GNUNET_SERVER_connect_socket (server, sock);
              GNUNET_CONNECTION_ignore_shutdown (sock,
                                                 server->clients_ignore_shutdown);
              /* decrement reference count, we don't keep "client" alive */
              GNUNET_SERVER_client_drop (client);
            }
        }
      i++;
    }
  /* listen for more! */
  server->listen_task = GNUNET_SCHEDULER_add_select (server->sched,
                                                     GNUNET_SCHEDULER_PRIORITY_HIGH,
                                                     GNUNET_SCHEDULER_NO_TASK,
                                                     GNUNET_TIME_UNIT_FOREVER_REL,
                                                     r, NULL,
                                                     &process_listen_socket,
                                                     server);
  GNUNET_NETWORK_fdset_destroy (r);
}


/**
 * Create and initialize a listen socket for the server.
 *
 * @param serverAddr address to listen on
 * @param socklen length of address
 * @return NULL on error, otherwise the listen socket
 */
static struct GNUNET_NETWORK_Handle *
open_listen_socket (const struct sockaddr *serverAddr, socklen_t socklen)
{
  const static int on = 1;
  struct GNUNET_NETWORK_Handle *sock;
  uint16_t port;
  int eno;

  switch (serverAddr->sa_family)
    {
    case AF_INET:
      port = ntohs (((const struct sockaddr_in *) serverAddr)->sin_port);
      break;
    case AF_INET6:
      port = ntohs (((const struct sockaddr_in6 *) serverAddr)->sin6_port);
      break;
    default:
      port = 0;
      break;
    }
  sock = GNUNET_NETWORK_socket_create (serverAddr->sa_family, SOCK_STREAM, 0);
  if (NULL == sock)
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "socket");
      errno = 0;
      return NULL;
    }
  if ((port != 0) &&
      (GNUNET_NETWORK_socket_setsockopt
       (sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on)) != GNUNET_OK))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                         "setsockopt");
  /* bind the socket */
  if (GNUNET_NETWORK_socket_bind (sock, serverAddr, socklen) != GNUNET_OK)
    {
      eno = errno;
      if (errno != EADDRINUSE)
        {
          /* we don't log 'EADDRINUSE' here since an IPv4 bind may
             fail if we already took the port on IPv6; if both IPv4 and
             IPv6 binds fail, then our caller will log using the
             errno preserved in 'eno' */
          GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "bind");
          if (port != 0)
            GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                        _
                        ("`%s' failed for port %d (%s).\n"),
                        "bind", port,
                        (serverAddr->sa_family == AF_INET) ? "IPv4" : "IPv6");
          eno = 0;
        }
      GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (sock));
      errno = eno;
      return NULL;
    }
  if (GNUNET_OK != GNUNET_NETWORK_socket_listen (sock, 5))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "listen");
      GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (sock));
      errno = 0;
      return NULL;
    }
#if DEBUG_SERVER
  if (port != 0)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Server starts to listen on port %u.\n", port);
#endif
  return sock;
}


/**
 * Create a new server.
 *
 * @param sched scheduler to use
 * @param access function for access control
 * @param access_cls closure for access
 * @param serverAddr address to listen on (including port), NULL terminated array
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
                      GNUNET_CONNECTION_AccessCheck access,
                      void *access_cls,
                      struct sockaddr *const *serverAddr,
                      const socklen_t * socklen,
                      size_t maxbuf,
                      struct GNUNET_TIME_Relative
                      idle_timeout, int require_found)
{
  struct GNUNET_SERVER_Handle *ret;
  struct GNUNET_NETWORK_Handle **lsocks;
  struct GNUNET_NETWORK_FDSet *r;
  unsigned int i;
  unsigned int j;

  i = 0;
  while (serverAddr[i] != NULL)
    i++;
  if (i > 0)
    {
      lsocks =
        GNUNET_malloc (sizeof (struct GNUNET_NETWORK_Handle *) * (i + 1));
      i = 0;
      j = 0;
      while (serverAddr[i] != NULL)
        {
          lsocks[j] = open_listen_socket (serverAddr[i], socklen[i]);
          if (lsocks[j] != NULL)
            j++;
          i++;
        }
      if (j == 0)
        {
          if (errno != 0)
            GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "bind");
          GNUNET_free (lsocks);
          lsocks = NULL;
        }
    }
  else
    {
      lsocks = NULL;
    }
  ret = GNUNET_malloc (sizeof (struct GNUNET_SERVER_Handle));
  ret->sched = sched;
  ret->maxbuf = maxbuf;
  ret->idle_timeout = idle_timeout;
  ret->listen_sockets = lsocks;
  ret->access = access;
  ret->access_cls = access_cls;
  ret->require_found = require_found;
  if (lsocks != NULL)
    {
      r = GNUNET_NETWORK_fdset_create ();
      i = 0;
      while (NULL != ret->listen_sockets[i])
        GNUNET_NETWORK_fdset_set (r, ret->listen_sockets[i++]);
      ret->listen_task = GNUNET_SCHEDULER_add_select (sched,
                                                      GNUNET_SCHEDULER_PRIORITY_HIGH,
                                                      GNUNET_SCHEDULER_NO_TASK,
                                                      GNUNET_TIME_UNIT_FOREVER_REL,
                                                      r, NULL,
                                                      &process_listen_socket,
                                                      ret);
      GNUNET_NETWORK_fdset_destroy (r);
    }
  return ret;
}


/**
 * Free resources held by this server.
 *
 * @param s server to destroy
 */
void
GNUNET_SERVER_destroy (struct GNUNET_SERVER_Handle *s)
{
  struct HandlerList *hpos;
  struct NotifyList *npos;
  unsigned int i;

#if DEBUG_SERVER
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Server shutting down.\n");
#endif
  if (GNUNET_SCHEDULER_NO_TASK != s->listen_task)
    {
      GNUNET_SCHEDULER_cancel (s->sched, s->listen_task);
      s->listen_task = GNUNET_SCHEDULER_NO_TASK;
    }
  if (s->listen_sockets != NULL)
    {
      i = 0;
      while (s->listen_sockets[i] != NULL)
        GNUNET_break (GNUNET_OK ==
                      GNUNET_NETWORK_socket_close (s->listen_sockets[i++]));
      GNUNET_free (s->listen_sockets);
      s->listen_sockets = NULL;
    }
  while (s->clients != NULL)
    GNUNET_SERVER_client_disconnect (s->clients);
  while (NULL != (hpos = s->handlers))
    {
      s->handlers = hpos->next;
      GNUNET_free (hpos);
    }
  while (NULL != (npos = s->disconnect_notify_list))
    {
      npos->callback (npos->callback_cls, NULL);
      s->disconnect_notify_list = npos->next;
      GNUNET_free (npos);
    }
  GNUNET_free (s);
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
              size, type);
#endif
  pos = server->handlers;
  found = GNUNET_NO;
  while (pos != NULL)
    {
      i = 0;
      while (pos->handlers[i].callback != NULL)
        {
          mh = &pos->handlers[i];
          if ( (mh->type == type) ||
               (mh->type == GNUNET_MESSAGE_TYPE_ALL) )
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
  while ( (client->receive_pos >= sizeof (struct GNUNET_MessageHeader)) &&
	  (0 == client->suspended) && 
	  (GNUNET_YES != client->shutdown_now) )
    {
      hdr = (const struct GNUNET_MessageHeader *) &client->incoming_buffer;
      msize = ntohs (hdr->size);
      if (msize > client->receive_pos)
        {
#if DEBUG_SERVER
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Total message size is %u, we only have %u bytes; need more data\n",
                      msize, client->receive_pos);
#endif
          break;
        }
#if DEBUG_SERVER
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Passing %u bytes to callback for processing\n", msize);
#endif
      if ( (msize < sizeof (struct GNUNET_MessageHeader)) ||
	   (GNUNET_OK != GNUNET_SERVER_inject (server, client, hdr)) )
        {
          client->in_process_client_buffer = GNUNET_NO;
          GNUNET_SERVER_client_disconnect (client);
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
    GNUNET_SERVER_client_disconnect (client);
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
                  const struct sockaddr *addr, socklen_t addrlen, int errCode)
{
  struct GNUNET_SERVER_Client *client = cls;
  struct GNUNET_SERVER_Handle *server = client->server;
  const char *cbuf = buf;
  size_t maxcpy;

  client->receive_pending = GNUNET_NO;
  if ((buf == NULL) ||
      (available == 0) ||
      (errCode != 0) ||
      (server == NULL) ||
      (client->shutdown_now == GNUNET_YES) ||
      (GNUNET_YES != client->check (client->client_closure)))
    {
      /* other side closed connection, error connecting, etc. */      
      GNUNET_SERVER_client_disconnect (client);
      return;
    }
#if DEBUG_SERVER
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Server receives %u bytes from `%s'.\n",
              available, GNUNET_a2s (addr, addrlen));
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
                  "Can copy %u bytes to private buffer\n", maxcpy);
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
      client->receive_pending = GNUNET_YES;
      client->receive (client->client_closure,
                       GNUNET_SERVER_MAX_MESSAGE_SIZE,
                       server->idle_timeout, &process_incoming, client);
    }
  if (GNUNET_YES == client->shutdown_now)
    GNUNET_SERVER_client_disconnect (client);
  GNUNET_SERVER_client_drop (client);
}


/**
 * Task run to start again receiving from the network
 * and process requests.
 *
 * @param cls our 'struct GNUNET_SERVER_Client*' to process more requests from
 * @param tc scheduler context (unused)
 */
static void
restart_processing (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_SERVER_Client *client = cls;
  struct GNUNET_SERVER_Handle *server = client->server;

  client->restart_task = GNUNET_SCHEDULER_NO_TASK;
  if ( (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN)) &&
       (GNUNET_NO == server->clients_ignore_shutdown) )
    {
      GNUNET_SERVER_client_disconnect (client);
      return;
    }
  GNUNET_SERVER_client_keep (client);
  process_client_buffer (client);
  if (0 == client->suspended)
    {
      client->receive_pending = GNUNET_YES;
      client->receive (client->client_closure,
		       GNUNET_SERVER_MAX_MESSAGE_SIZE,
		       client->server->idle_timeout, &process_incoming, client);
    }
  GNUNET_SERVER_client_drop (client);
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
  client->receive_pending = GNUNET_YES;
  client->receive (client->client_closure,
                   GNUNET_SERVER_MAX_MESSAGE_SIZE,
                   server->idle_timeout, &process_incoming, client);
}


/**
 * Create a request for receiving data from a socket.
 *
 * @param cls identifies the socket to receive from
 * @param max how much data to read at most
 * @param timeout when should this operation time out
 * @param receiver function to call for processing
 * @param receiver_cls closure for receiver
 */
static void
sock_receive (void *cls,
              size_t max,
              struct GNUNET_TIME_Relative timeout,
              GNUNET_CONNECTION_Receiver receiver, void *receiver_cls)
{
  GNUNET_CONNECTION_receive (cls, max, timeout, receiver, receiver_cls);
}


/**
 * Wrapper to cancel receiving from a socket.
 * 
 * @param cls handle to the GNUNET_CONNECTION_Handle to cancel
 */
static void
sock_receive_cancel (void *cls)
{
  GNUNET_CONNECTION_receive_cancel (cls);
}


/**
 * FIXME: document.
 */
static void *
sock_notify_transmit_ready (void *cls,
                            size_t size,
                            struct GNUNET_TIME_Relative timeout,
                            GNUNET_CONNECTION_TransmitReadyNotify notify,
                            void *notify_cls)
{
  return GNUNET_CONNECTION_notify_transmit_ready (cls, size, timeout, notify,
                                                  notify_cls);
}


/**
 * FIXME: document.
 */
static void
sock_notify_transmit_ready_cancel (void *cls, void *h)
{
  GNUNET_CONNECTION_notify_transmit_ready_cancel (h);
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
  return GNUNET_CONNECTION_check (cls);
}


/**
 * Destroy this socket (free resources).
 *
 * @param cls the socket
 */
static void
sock_destroy (void *cls)
{
  GNUNET_CONNECTION_destroy (cls);
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
                              struct GNUNET_CONNECTION_Handle *connection)
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
  if ( (client->shutdown_now == GNUNET_YES) && 
       (client->reference_count == 0) )
    GNUNET_SERVER_client_disconnect (client);
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
  return GNUNET_CONNECTION_get_address (client->client_closure,
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
 * Ask the server to stop notifying us whenever a client disconnects.
 *
 * @param server the server manageing the clients
 * @param callback function to call on disconnect
 * @param callback_cls closure for callback
 */
void
GNUNET_SERVER_disconnect_notify_cancel (struct GNUNET_SERVER_Handle *server,
					GNUNET_SERVER_DisconnectCallback callback,
					void *callback_cls)
{
  struct NotifyList *pos;
  struct NotifyList *prev;

  prev = NULL;
  pos = server->disconnect_notify_list;
  while (pos != NULL)
    {
      if ( (pos->callback == callback) &&
	   (pos->callback_cls == callback_cls ) )
	break;
      prev = pos;
      pos = pos->next;
    }
  if (pos == NULL)
    {
      GNUNET_break (0);
      return;
    }
  if (prev == NULL)
    server->disconnect_notify_list = pos->next;
  else
    prev->next = pos->next;
  GNUNET_free (pos);
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
  struct GNUNET_SERVER_Client *prev;
  struct GNUNET_SERVER_Client *pos;
  struct GNUNET_SERVER_Handle *server;
  struct NotifyList *n;
  unsigned int rc;

  if (client->restart_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (client->server->sched,
			       client->restart_task);
      client->restart_task = GNUNET_SCHEDULER_NO_TASK;
    }
  if (GNUNET_YES == client->receive_pending)
    {
      client->receive_cancel (client->client_closure);
      client->receive_pending = GNUNET_NO;
    }
  rc = client->reference_count;  
  if (client->server != NULL)
    {
      server = client->server;
      client->server = NULL;
      client->shutdown_now = GNUNET_YES;
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
      if (client->restart_task != GNUNET_SCHEDULER_NO_TASK)
	GNUNET_SCHEDULER_cancel (client->server->sched,
				 client->restart_task);
    }
  if (rc > 0)
    return;
  if (client->in_process_client_buffer)
    return;
  client->destroy (client->client_closure);
  GNUNET_free (client);

  
}


/**
 * Notify us when the server has enough space to transmit
 * a message of the given size to the given client.
 *
 * @param client client to transmit message to
 * @param size requested amount of buffer space
 * @param timeout after how long should we give up (and call
 *        notify with buf NULL and size 0)?
 * @param callback function to call when space is available
 * @param callback_cls closure for callback
 * @return non-NULL if the notify callback was queued; can be used
 *           to cancel the request using
 *           GNUNET_CONNECTION_notify_transmit_ready_cancel.
 *         NULL if we are already going to notify someone else (busy)
 */
struct GNUNET_CONNECTION_TransmitHandle *
GNUNET_SERVER_notify_transmit_ready (struct GNUNET_SERVER_Client *client,
                                     size_t size,
                                     struct GNUNET_TIME_Relative timeout,
                                     GNUNET_CONNECTION_TransmitReadyNotify
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
 *                GNUNET_NO to close the connection (normal behavior)
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
    {
      GNUNET_SERVER_client_disconnect (client);
      return;
    }
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
      process_incoming (client, sb, client->side_buf_size, NULL, 0, 0);
      /* finally, free the side-buf */
      GNUNET_free (sb);
      return;
    }
  client->restart_task = GNUNET_SCHEDULER_add_now (client->server->sched,
						   &restart_processing,
						   client);
}


/**
 * Configure this server's connections to continue handling client
 * requests as usual even after we get a shutdown signal.  The change
 * only applies to clients that connect to the server from the outside
 * using TCP after this call.  Clients managed previously or those
 * added using GNUNET_SERVER_connect_socket and
 * GNUNET_SERVER_connect_callback are not affected by this option.
 *
 * @param h server handle
 * @param do_ignore GNUNET_YES to ignore, GNUNET_NO to restore default
 */
void
GNUNET_SERVER_ignore_shutdown (struct GNUNET_SERVER_Handle *h, int do_ignore)
{
  h->clients_ignore_shutdown = do_ignore;
}

/* end of server.c */
