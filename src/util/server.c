/*
     This file is part of GNUnet.
     (C) 2009, 2012 Christian Grothoff (and other contributing authors)

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
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

#define LOG_STRERROR(kind,syscall) GNUNET_log_from_strerror (kind, "util", syscall)

#define LOG_STRERROR_FILE(kind,syscall,filename) GNUNET_log_from_strerror_file (kind, "util", syscall, filename)


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
   * This is a doubly linked list.
   */
  struct NotifyList *next;

  /**
   * This is a doubly linked list.
   */
  struct NotifyList *prev;

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
   * List of handlers for incoming messages.
   */
  struct HandlerList *handlers;

  /**
   * Head of list of our current clients.
   */
  struct GNUNET_SERVER_Client *clients_head;

  /**
   * Head of list of our current clients.
   */
  struct GNUNET_SERVER_Client *clients_tail;

  /**
   * Head of linked list of functions to call on disconnects by clients.
   */
  struct NotifyList *disconnect_notify_list_head;

  /**
   * Tail of linked list of functions to call on disconnects by clients.
   */
  struct NotifyList *disconnect_notify_list_tail;

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
   * Task scheduled to do the listening.
   */
  GNUNET_SCHEDULER_TaskIdentifier listen_task;

  /**
   * Alternative function to create a MST instance.
   */
  GNUNET_SERVER_MstCreateCallback mst_create;

  /**
   * Alternative function to destroy a MST instance.
   */
  GNUNET_SERVER_MstDestroyCallback mst_destroy;

  /**
   * Alternative function to give data to a MST instance.
   */
  GNUNET_SERVER_MstReceiveCallback mst_receive;

  /**
   * Closure for 'mst_'-callbacks.
   */
  void *mst_cls;

  /**
   * Do we ignore messages of types that we do not understand or do we
   * require that a handler is found (and if not kill the connection)?
   */
  int require_found;

  /**
   * Set to GNUNET_YES once we are in 'soft' shutdown where we wait for
   * all non-monitor clients to disconnect before we call
   * GNUNET_SERVER_destroy.  See 'test_monitor_clients'.  Set to
   * GNUNET_SYSERR once the final destroy task has been scheduled
   * (we cannot run it in the same task).
   */
  int in_soft_shutdown;
};


/**
 * Handle server returns for aborting transmission to a client.
 */
struct GNUNET_SERVER_TransmitHandle
{
  /**
   * Function to call to get the message.
   */
  GNUNET_CONNECTION_TransmitReadyNotify callback;

  /**
   * Closure for 'callback'
   */
  void *callback_cls;

  /**
   * Active connection transmission handle.
   */
  struct GNUNET_CONNECTION_TransmitHandle *cth;

};


/**
 * @brief handle for a client of the server
 */
struct GNUNET_SERVER_Client
{

  /**
   * This is a doubly linked list.
   */
  struct GNUNET_SERVER_Client *next;

  /**
   * This is a doubly linked list.
   */
  struct GNUNET_SERVER_Client *prev;

  /**
   * Processing of incoming data.
   */
  void *mst;

  /**
   * Server that this client belongs to.
   */
  struct GNUNET_SERVER_Handle *server;

  /**
   * Client closure for callbacks.
   */
  struct GNUNET_CONNECTION_Handle *connection;

  /**
   * ID of task used to restart processing.
   */
  GNUNET_SCHEDULER_TaskIdentifier restart_task;

  /**
   * Task that warns about missing calls to 'GNUNET_SERVER_receive_done'.
   */
  GNUNET_SCHEDULER_TaskIdentifier warn_task;

  /**
   * Time when the warn task was started.
   */
  struct GNUNET_TIME_Absolute warn_start;

  /**
   * Last activity on this socket (used to time it out
   * if reference_count == 0).
   */
  struct GNUNET_TIME_Absolute last_activity;

  /**
   * Transmission handle we return for this client from
   * GNUNET_SERVER_notify_transmit_ready.
   */
  struct GNUNET_SERVER_TransmitHandle th;

  /**
   * After how long should an idle connection time
   * out (on write).
   */
  struct GNUNET_TIME_Relative idle_timeout;

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
   * We're about to close down this client.
   */
  int shutdown_now;

  /**
   * Are we currently trying to receive? (YES if we are, NO if we are not,
   * SYSERR if data is already available in MST).
   */
  int receive_pending;

  /**
   * Finish pending write when disconnecting?
   */
  int finish_pending_write;

  /**
   * Persist the file handle for this client no matter what happens,
   * force the OS to close once the process actually dies.  Should only
   * be used in special cases!
   */
  int persist;

  /**
   * Is this client a 'monitor' client that should not be counted
   * when deciding on destroying the server during soft shutdown?
   * (see also GNUNET_SERVICE_start)
   */
  int is_monitor;

  /**
   * Type of last message processed (for warn_no_receive_done).
   */
  uint16_t warn_type;
};


/**
 * Scheduler says our listen socket is ready.  Process it!
 *
 * @param cls handle to our server for which we are processing the listen
 *        socket
 * @param tc reason why we are running right now
 */
static void
process_listen_socket (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Add a listen task with the scheduler for this server.
 *
 * @param server handle to our server for which we are adding the listen
 *        socket
 */
static void
schedule_listen_task (struct GNUNET_SERVER_Handle *server)
{
  struct GNUNET_NETWORK_FDSet *r;
  unsigned int i;

  if (NULL == server->listen_sockets[0])
    return; /* nothing to do, no listen sockets! */
  if (NULL == server->listen_sockets[1])
  {
    /* simplified method: no fd set needed; this is then much simpler and
       much more efficient */
    server->listen_task =
      GNUNET_SCHEDULER_add_read_net_with_priority (GNUNET_TIME_UNIT_FOREVER_REL,
						   GNUNET_SCHEDULER_PRIORITY_HIGH,
						   server->listen_sockets[0],
						   &process_listen_socket, server);
    return;
  }
  r = GNUNET_NETWORK_fdset_create ();
  i = 0;
  while (NULL != server->listen_sockets[i])
    GNUNET_NETWORK_fdset_set (r, server->listen_sockets[i++]);
  server->listen_task =
    GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_HIGH,
				 GNUNET_TIME_UNIT_FOREVER_REL, r, NULL,
				 &process_listen_socket, server);
  GNUNET_NETWORK_fdset_destroy (r);
}


/**
 * Scheduler says our listen socket is ready.  Process it!
 *
 * @param cls handle to our server for which we are processing the listen
 *        socket
 * @param tc reason why we are running right now
 */
static void
process_listen_socket (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_SERVER_Handle *server = cls;
  struct GNUNET_CONNECTION_Handle *sock;
  struct GNUNET_SERVER_Client *client;
  unsigned int i;

  server->listen_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    /* ignore shutdown, someone else will take care of it! */
    schedule_listen_task (server);
    return;
  }
  i = 0;
  while (NULL != server->listen_sockets[i])
  {
    if (GNUNET_NETWORK_fdset_isset (tc->read_ready, server->listen_sockets[i]))
    {
      sock =
          GNUNET_CONNECTION_create_from_accept (server->access,
                                                server->access_cls,
                                                server->listen_sockets[i]);
      if (NULL != sock)
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG, "Server accepted incoming connection.\n");
        client = GNUNET_SERVER_connect_socket (server, sock);
        /* decrement reference count, we don't keep "client" alive */
        GNUNET_SERVER_client_drop (client);
      }
    }
    i++;
  }
  /* listen for more! */
  schedule_listen_task (server);
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
  static int on = 1;
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
  case AF_UNIX:
    port = 0;
    break;
  default:
    GNUNET_break (0);
    port = 0;
    break;
  }
  sock = GNUNET_NETWORK_socket_create (serverAddr->sa_family, SOCK_STREAM, 0);
  if (NULL == sock)
  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "socket");
    errno = 0;
    return NULL;
  }
  if (0 != port)
  {
    if (GNUNET_NETWORK_socket_setsockopt
        (sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on)) != GNUNET_OK)
      LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                    "setsockopt");
#ifdef IPV6_V6ONLY
    if ((AF_INET6 == serverAddr->sa_family) &&
        (GNUNET_NETWORK_socket_setsockopt
         (sock, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof (on)) != GNUNET_OK))
      LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                    "setsockopt");
#endif
  }
  /* bind the socket */
  if (GNUNET_OK != GNUNET_NETWORK_socket_bind (sock, serverAddr, socklen))
  {
    eno = errno;
    if (EADDRINUSE != errno)
    {
      /* we don't log 'EADDRINUSE' here since an IPv4 bind may
       * fail if we already took the port on IPv6; if both IPv4 and
       * IPv6 binds fail, then our caller will log using the
       * errno preserved in 'eno' */
      LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "bind");
      if (0 != port)
        LOG (GNUNET_ERROR_TYPE_ERROR, _("`%s' failed for port %d (%s).\n"),
             "bind", port,
             (AF_INET == serverAddr->sa_family) ? "IPv4" : "IPv6");
      eno = 0;
    }
    else
    {
      if (0 != port)
        LOG (GNUNET_ERROR_TYPE_WARNING,
             _("`%s' failed for port %d (%s): address already in use\n"),
             "bind", port,
             (AF_INET == serverAddr->sa_family) ? "IPv4" : "IPv6");
      else if (AF_UNIX == serverAddr->sa_family)
        LOG (GNUNET_ERROR_TYPE_WARNING,
             _("`%s' failed for `%s': address already in use\n"), "bind",
             ((const struct sockaddr_un *) serverAddr)->sun_path);

    }
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (sock));
    errno = eno;
    return NULL;
  }
  if (GNUNET_OK != GNUNET_NETWORK_socket_listen (sock, 5))
  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "listen");
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (sock));
    errno = 0;
    return NULL;
  }
  if (0 != port)
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Server starts to listen on port %u.\n",
         port);
  return sock;
}


/**
 * Create a new server.
 *
 * @param access function for access control
 * @param access_cls closure for access
 * @param lsocks NULL-terminated array of listen sockets
 * @param idle_timeout after how long should we timeout idle connections?
 * @param require_found if YES, connections sending messages of unknown type
 *        will be closed
 * @return handle for the new server, NULL on error
 *         (typically, "port" already in use)
 */
struct GNUNET_SERVER_Handle *
GNUNET_SERVER_create_with_sockets (GNUNET_CONNECTION_AccessCheck access,
                                   void *access_cls,
                                   struct GNUNET_NETWORK_Handle **lsocks,
                                   struct GNUNET_TIME_Relative idle_timeout,
                                   int require_found)
{
  struct GNUNET_SERVER_Handle *server;

  server = GNUNET_malloc (sizeof (struct GNUNET_SERVER_Handle));
  server->idle_timeout = idle_timeout;
  server->listen_sockets = lsocks;
  server->access = access;
  server->access_cls = access_cls;
  server->require_found = require_found;
  if (NULL != lsocks)
    schedule_listen_task (server);
  return server;
}


/**
 * Create a new server.
 *
 * @param access function for access control
 * @param access_cls closure for access
 * @param serverAddr address to listen on (including port), NULL terminated array
 * @param socklen length of serverAddr
 * @param idle_timeout after how long should we timeout idle connections?
 * @param require_found if YES, connections sending messages of unknown type
 *        will be closed
 * @return handle for the new server, NULL on error
 *         (typically, "port" already in use)
 */
struct GNUNET_SERVER_Handle *
GNUNET_SERVER_create (GNUNET_CONNECTION_AccessCheck access, void *access_cls,
                      struct sockaddr *const *serverAddr,
                      const socklen_t * socklen,
                      struct GNUNET_TIME_Relative idle_timeout,
                      int require_found)
{
  struct GNUNET_NETWORK_Handle **lsocks;
  unsigned int i;
  unsigned int j;
  unsigned int k;
  int seen;

  i = 0;
  while (NULL != serverAddr[i])
    i++;
  if (i > 0)
  {
    lsocks = GNUNET_malloc (sizeof (struct GNUNET_NETWORK_Handle *) * (i + 1));
    i = 0;
    j = 0;
    while (NULL != serverAddr[i])
    {
      seen = 0;
      for (k=0;k<i;k++)
	if ( (socklen[k] == socklen[i]) &&
	     (0 == memcmp (serverAddr[k], serverAddr[i], socklen[i])) )
	{
	  seen = 1;
	  break;
	}
      if (0 != seen)
      {
	/* duplicate address, skip */
	i++;
	continue;
      }
      lsocks[j] = open_listen_socket (serverAddr[i], socklen[i]);
      if (NULL != lsocks[j])
        j++;
      i++;
    }
    if (0 == j)
    {
      if (0 != errno)
        LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "bind");
      GNUNET_free (lsocks);
      lsocks = NULL;
    }
  }
  else
  {
    lsocks = NULL;
  }
  return GNUNET_SERVER_create_with_sockets (access, access_cls, lsocks,
                                            idle_timeout, require_found);
}


/**
 * Set the 'monitor' flag on this client.  Clients which have been
 * marked as 'monitors' won't prevent the server from shutting down
 * once 'GNUNET_SERVER_stop_listening' has been invoked.  The idea is
 * that for "normal" clients we likely want to allow them to process
 * their requests; however, monitor-clients are likely to 'never'
 * disconnect during shutdown and thus will not be considered when
 * determining if the server should continue to exist after
 * 'GNUNET_SERVER_destroy' has been called.
 *
 * @param client the client to set the 'monitor' flag on
 */
void
GNUNET_SERVER_client_mark_monitor (struct GNUNET_SERVER_Client *client)
{
  client->is_monitor = GNUNET_YES;
}


/**
 * Helper function for 'test_monitor_clients' to trigger
 * 'GNUNET_SERVER_destroy' after the stack has unwound.
 *
 * @param cls the 'struct GNUNET_SERVER_Handle' to destroy
 * @param tc unused
 */
static void
do_destroy (void *cls,
	    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_SERVER_Handle *server = cls;
  GNUNET_SERVER_destroy (server);
}


/**
 * Check if only 'monitor' clients are left.  If so, destroy the
 * server completely.
 *
 * @param server server to test for full shutdown
 */
static void
test_monitor_clients (struct GNUNET_SERVER_Handle *server)
{
  struct GNUNET_SERVER_Client *client;

  if (GNUNET_YES != server->in_soft_shutdown)
    return;
  for (client = server->clients_head; NULL != client; client = client->next)
    if (GNUNET_NO == client->is_monitor)
      return; /* not done yet */
  server->in_soft_shutdown = GNUNET_SYSERR;
  GNUNET_SCHEDULER_add_continuation (&do_destroy, server,
				     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
}


/**
 * Stop the listen socket and get ready to shutdown the server
 * once only 'monitor' clients are left.
 *
 * @param server server to stop listening on
 */
void
GNUNET_SERVER_stop_listening (struct GNUNET_SERVER_Handle *server)
{
  unsigned int i;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Server in soft shutdown\n");
  if (GNUNET_SCHEDULER_NO_TASK != server->listen_task)
  {
    GNUNET_SCHEDULER_cancel (server->listen_task);
    server->listen_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != server->listen_sockets)
  {
    i = 0;
    while (NULL != server->listen_sockets[i])
      GNUNET_break (GNUNET_OK ==
                    GNUNET_NETWORK_socket_close (server->listen_sockets[i++]));
    GNUNET_free (server->listen_sockets);
    server->listen_sockets = NULL;
  }
  if (GNUNET_NO == server->in_soft_shutdown)
    server->in_soft_shutdown = GNUNET_YES;
  test_monitor_clients (server);
}


/**
 * Free resources held by this server.
 *
 * @param server server to destroy
 */
void
GNUNET_SERVER_destroy (struct GNUNET_SERVER_Handle *server)
{
  struct HandlerList *hpos;
  struct NotifyList *npos;
  unsigned int i;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Server shutting down.\n");
  if (GNUNET_SCHEDULER_NO_TASK != server->listen_task)
  {
    GNUNET_SCHEDULER_cancel (server->listen_task);
    server->listen_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != server->listen_sockets)
  {
    i = 0;
    while (NULL != server->listen_sockets[i])
      GNUNET_break (GNUNET_OK ==
                    GNUNET_NETWORK_socket_close (server->listen_sockets[i++]));
    GNUNET_free (server->listen_sockets);
    server->listen_sockets = NULL;
  }
  while (NULL != server->clients_head)
    GNUNET_SERVER_client_disconnect (server->clients_head);
  while (NULL != (hpos = server->handlers))
  {
    server->handlers = hpos->next;
    GNUNET_free (hpos);
  }
  while (NULL != (npos = server->disconnect_notify_list_head))
  {
    npos->callback (npos->callback_cls, NULL);
    GNUNET_CONTAINER_DLL_remove (server->disconnect_notify_list_head,
				 server->disconnect_notify_list_tail,
				 npos);
    GNUNET_free (npos);
  }
  GNUNET_free (server);
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
                            const struct GNUNET_SERVER_MessageHandler *handlers)
{
  struct HandlerList *p;

  p = GNUNET_malloc (sizeof (struct HandlerList));
  p->handlers = handlers;
  p->next = server->handlers;
  server->handlers = p;
}


/**
 * Change functions used by the server to tokenize the message stream.
 * (very rarely used).
 *
 * @param server server to modify
 * @param create new tokenizer initialization function
 * @param destroy new tokenizer destruction function
 * @param receive new tokenizer receive function
 * @param cls closure for 'create', 'receive', 'destroy' 
 */
void
GNUNET_SERVER_set_callbacks (struct GNUNET_SERVER_Handle *server,
                             GNUNET_SERVER_MstCreateCallback create,
                             GNUNET_SERVER_MstDestroyCallback destroy,
                             GNUNET_SERVER_MstReceiveCallback receive,
                             void *cls)
{
  server->mst_create = create;
  server->mst_destroy = destroy;
  server->mst_receive = receive;
  server->mst_cls = cls;
}


/**
 * Task run to warn about missing calls to 'GNUNET_SERVER_receive_done'.
 *
 * @param cls our 'struct GNUNET_SERVER_Client*' to process more requests from
 * @param tc scheduler context (unused)
 */
static void
warn_no_receive_done (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_SERVER_Client *client = cls;

  GNUNET_break (0 != client->warn_type); /* type should never be 0 here, as we don't use 0 */
  client->warn_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MINUTES,
                                    &warn_no_receive_done, client);
  if (0 == (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _
         ("Processing code for message of type %u did not call GNUNET_SERVER_receive_done after %llums\n"),
         (unsigned int) client->warn_type,
         (unsigned long long)
         GNUNET_TIME_absolute_get_duration (client->warn_start).rel_value);
}


/**
 * Disable the warning the server issues if a message is not acknowledged
 * in a timely fashion.  Use this call if a client is intentionally delayed
 * for a while.  Only applies to the current message.
 *
 * @param client client for which to disable the warning
 */
void
GNUNET_SERVER_disable_receive_done_warning (struct GNUNET_SERVER_Client *client)
{
  if (GNUNET_SCHEDULER_NO_TASK != client->warn_task)
  {
    GNUNET_SCHEDULER_cancel (client->warn_task);
    client->warn_task = GNUNET_SCHEDULER_NO_TASK;
  }
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
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Server schedules transmission of %u-byte message of type %u to client.\n",
       size, type);
  found = GNUNET_NO;
  for (pos = server->handlers; NULL != pos; pos = pos->next)
  {
    i = 0;
    while (pos->handlers[i].callback != NULL)
    {
      mh = &pos->handlers[i];
      if ((mh->type == type) || (mh->type == GNUNET_MESSAGE_TYPE_ALL))
      {
        if ((0 != mh->expected_size) && (mh->expected_size != size))
        {
#if GNUNET8_NETWORK_IS_DEAD
          LOG (GNUNET_ERROR_TYPE_WARNING,
               "Expected %u bytes for message of type %u, got %u\n",
               mh->expected_size, mh->type, size);
          GNUNET_break_op (0);
#endif
          return GNUNET_SYSERR;
        }
        if (NULL != sender)
        {
          if ( (0 == sender->suspended) &&
	       (GNUNET_SCHEDULER_NO_TASK == sender->warn_task) )
          {
	    GNUNET_break (0 != type); /* type should never be 0 here, as we don't use 0 */
            sender->warn_start = GNUNET_TIME_absolute_get ();	    
            sender->warn_task =
                GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MINUTES,
                                              &warn_no_receive_done, sender);
            sender->warn_type = type;
          }
          sender->suspended++;
        }
        mh->callback (mh->callback_cls, sender, message);
        found = GNUNET_YES;
      }
      i++;
    }
  }
  if (GNUNET_NO == found)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
         "Received message of unknown type %d\n", type);
    if (GNUNET_YES == server->require_found)
      return GNUNET_SYSERR;
  }
  return GNUNET_OK;
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
process_incoming (void *cls, const void *buf, size_t available,
                  const struct sockaddr *addr, socklen_t addrlen, int errCode);


/**
 * Process messages from the client's message tokenizer until either
 * the tokenizer is empty (and then schedule receiving more), or
 * until some handler is not immediately done (then wait for restart_processing)
 * or shutdown.
 *
 * @param client the client to process, RC must have already been increased
 *        using GNUNET_SERVER_client_keep and will be decreased by one in this
 *        function
 * @param ret GNUNET_NO to start processing from the buffer,
 *            GNUNET_OK if the mst buffer is drained and we should instantly go back to receiving
 *            GNUNET_SYSERR if we should instantly abort due to error in a previous step
 */
static void
process_mst (struct GNUNET_SERVER_Client *client, int ret)
{
  while ((GNUNET_SYSERR != ret) && (NULL != client->server) &&
         (GNUNET_YES != client->shutdown_now) && (0 == client->suspended))
  {
    if (GNUNET_OK == ret)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Server re-enters receive loop, timeout: %llu.\n",
           client->idle_timeout.rel_value);
      client->receive_pending = GNUNET_YES;
      GNUNET_CONNECTION_receive (client->connection,
                                 GNUNET_SERVER_MAX_MESSAGE_SIZE - 1,
                                 client->idle_timeout, &process_incoming,
                                 client);
      break;
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Server processes additional messages instantly.\n");
    if (NULL != client->server->mst_receive)
      ret =
          client->server->mst_receive (client->server->mst_cls, client->mst,
                                       client, NULL, 0, GNUNET_NO, GNUNET_YES);
    else
      ret =
          GNUNET_SERVER_mst_receive (client->mst, client, NULL, 0, GNUNET_NO,
                                     GNUNET_YES);
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Server leaves instant processing loop: ret = %d, server = %p, shutdown = %d, suspended = %u\n",
       ret, client->server, client->shutdown_now, client->suspended);
  if (GNUNET_NO == ret)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Server has more data pending but is suspended.\n");
    client->receive_pending = GNUNET_SYSERR;    /* data pending */
  }
  if ((GNUNET_SYSERR == ret) || (GNUNET_YES == client->shutdown_now))
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
process_incoming (void *cls, const void *buf, size_t available,
                  const struct sockaddr *addr, socklen_t addrlen, int errCode)
{
  struct GNUNET_SERVER_Client *client = cls;
  struct GNUNET_SERVER_Handle *server = client->server;
  struct GNUNET_TIME_Absolute end;
  struct GNUNET_TIME_Absolute now;
  int ret;

  GNUNET_assert (GNUNET_YES == client->receive_pending);
  client->receive_pending = GNUNET_NO;
  now = GNUNET_TIME_absolute_get ();
  end = GNUNET_TIME_absolute_add (client->last_activity, client->idle_timeout);

  if ((NULL == buf) && (0 == available) && (NULL == addr) && (0 == errCode) &&
      (GNUNET_YES != client->shutdown_now) && (NULL != server) &&
      (GNUNET_YES == GNUNET_CONNECTION_check (client->connection)) &&
      (end.abs_value > now.abs_value))
  {
    /* wait longer, timeout changed (i.e. due to us sending) */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Receive time out, but no disconnect due to sending (%p)\n",
         GNUNET_a2s (addr, addrlen));
    client->receive_pending = GNUNET_YES;
    GNUNET_CONNECTION_receive (client->connection,
                               GNUNET_SERVER_MAX_MESSAGE_SIZE - 1,
                               GNUNET_TIME_absolute_get_remaining (end),
                               &process_incoming, client);
    return;
  }
  if ((NULL == buf) || (0 == available) || (0 != errCode) || (NULL == server) ||
      (GNUNET_YES == client->shutdown_now) ||
      (GNUNET_YES != GNUNET_CONNECTION_check (client->connection)))
  {
    /* other side closed connection, error connecting, etc. */
    GNUNET_SERVER_client_disconnect (client);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Server receives %u bytes from `%s'.\n",
       (unsigned int) available, GNUNET_a2s (addr, addrlen));
  GNUNET_SERVER_client_keep (client);
  client->last_activity = now;

  if (NULL != server->mst_receive)
    ret =
        client->server->mst_receive (client->server->mst_cls, client->mst,
                                     client, buf, available, GNUNET_NO, GNUNET_YES);
  else if (NULL != client->mst)
  {
    ret =
        GNUNET_SERVER_mst_receive (client->mst, client, buf, available, GNUNET_NO,
                                   GNUNET_YES);
  }
  else
  {
    GNUNET_break (0);
    return;
  }

  process_mst (client, ret);
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

  GNUNET_assert (GNUNET_YES != client->shutdown_now);
  client->restart_task = GNUNET_SCHEDULER_NO_TASK;
  if (GNUNET_NO == client->receive_pending)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Server begins to read again from client.\n");
    client->receive_pending = GNUNET_YES;
    GNUNET_CONNECTION_receive (client->connection,
                               GNUNET_SERVER_MAX_MESSAGE_SIZE - 1,
                               client->idle_timeout, &process_incoming, client);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Server continues processing messages still in the buffer.\n");
  GNUNET_SERVER_client_keep (client);
  client->receive_pending = GNUNET_NO;
  process_mst (client, GNUNET_NO);
  GNUNET_SERVER_client_drop (client);
}


/**
 * This function is called whenever our inbound message tokenizer has
 * received a complete message.
 *
 * @param cls closure (struct GNUNET_SERVER_Handle)
 * @param client identification of the client (struct GNUNET_SERVER_Client*)
 * @param message the actual message
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR to stop further processing
 */
static int
client_message_tokenizer_callback (void *cls, void *client,
                                   const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_SERVER_Handle *server = cls;
  struct GNUNET_SERVER_Client *sender = client;
  int ret;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Tokenizer gives server message of type %u from client\n",
       ntohs (message->type));
  sender->in_process_client_buffer = GNUNET_YES;
  ret = GNUNET_SERVER_inject (server, sender, message);
  sender->in_process_client_buffer = GNUNET_NO;
  if ( (GNUNET_OK != ret) || (GNUNET_YES == sender->shutdown_now) )
  {
    GNUNET_SERVER_client_disconnect (sender);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
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
GNUNET_SERVER_connect_socket (struct GNUNET_SERVER_Handle *server,
                              struct GNUNET_CONNECTION_Handle *connection)
{
  struct GNUNET_SERVER_Client *client;

  client = GNUNET_malloc (sizeof (struct GNUNET_SERVER_Client));
  client->connection = connection;
  client->reference_count = 1;
  client->server = server;
  client->last_activity = GNUNET_TIME_absolute_get ();
  client->idle_timeout = server->idle_timeout;
  GNUNET_CONTAINER_DLL_insert (server->clients_head,
			       server->clients_tail,
			       client);
  if (NULL != server->mst_create)
    client->mst =
        server->mst_create (server->mst_cls, client);
  else
    client->mst =
        GNUNET_SERVER_mst_create (&client_message_tokenizer_callback, server);
  GNUNET_assert (NULL != client->mst);
  client->receive_pending = GNUNET_YES;
  GNUNET_CONNECTION_receive (client->connection,
                             GNUNET_SERVER_MAX_MESSAGE_SIZE - 1,
                             client->idle_timeout, &process_incoming, client);
  return client;
}


/**
 * Change the timeout for a particular client.  Decreasing the timeout
 * may not go into effect immediately (only after the previous timeout
 * times out or activity happens on the socket).
 *
 * @param client the client to update
 * @param timeout new timeout for activities on the socket
 */
void
GNUNET_SERVER_client_set_timeout (struct GNUNET_SERVER_Client *client,
                                  struct GNUNET_TIME_Relative timeout)
{
  client->idle_timeout = timeout;
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
  if ((GNUNET_YES == client->shutdown_now) && (0 == client->reference_count))
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
  return GNUNET_CONNECTION_get_address (client->connection, addr, addrlen);
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
  GNUNET_CONTAINER_DLL_insert (server->disconnect_notify_list_head,
			       server->disconnect_notify_list_tail,
			       n);
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
                                        GNUNET_SERVER_DisconnectCallback
                                        callback, void *callback_cls)
{
  struct NotifyList *pos;

  for (pos = server->disconnect_notify_list_head; NULL != pos; pos = pos->next)
    if ((pos->callback == callback) && (pos->callback_cls == callback_cls))
      break;
  if (NULL == pos)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_CONTAINER_DLL_remove (server->disconnect_notify_list_head,
			       server->disconnect_notify_list_tail,
			       pos);
  GNUNET_free (pos);
}


/**
 * Destroy the connection that is passed in via 'cls'.  Used
 * as calling 'GNUNET_CONNECTION_destroy' from within a function
 * that was itself called from within 'process_notify' of
 * 'connection.c' is not allowed (see #2329).
 *
 * @param cls connection to destroy
 * @param tc scheduler context (unused)
 */
static void
destroy_connection (void *cls,
		    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CONNECTION_Handle *connection = cls;
  
  GNUNET_CONNECTION_destroy (connection);
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
  struct GNUNET_SERVER_Handle *server = client->server;
  struct NotifyList *n;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Client is being disconnected from the server.\n");
  if (GNUNET_SCHEDULER_NO_TASK != client->restart_task)
  {
    GNUNET_SCHEDULER_cancel (client->restart_task);
    client->restart_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (GNUNET_SCHEDULER_NO_TASK != client->warn_task)
  {
    GNUNET_SCHEDULER_cancel (client->warn_task);
    client->warn_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (GNUNET_YES == client->receive_pending)
  {
    GNUNET_CONNECTION_receive_cancel (client->connection);
    client->receive_pending = GNUNET_NO;
  }
  client->shutdown_now = GNUNET_YES;    
  client->reference_count++; /* make sure nobody else clean up client... */
  if ( (NULL != client->mst) &&
       (NULL != server) )
  {
    GNUNET_CONTAINER_DLL_remove (server->clients_head,
				 server->clients_tail,
				 client);
    if (NULL != server->mst_destroy)
      server->mst_destroy (server->mst_cls, client->mst);
    else
      GNUNET_SERVER_mst_destroy (client->mst);
    client->mst = NULL;
    for (n = server->disconnect_notify_list_head; NULL != n; n = n->next)
      n->callback (n->callback_cls, client);
  }
  client->reference_count--;
  if (client->reference_count > 0)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "RC still positive, not destroying everything.\n");
    client->server = NULL;
    return;
  }
  if (GNUNET_YES == client->in_process_client_buffer)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Still processing inputs, not destroying everything.\n");
    return;
  }
  if (GNUNET_YES == client->persist)
    GNUNET_CONNECTION_persist_ (client->connection);
  if (NULL != client->th.cth)
    GNUNET_SERVER_notify_transmit_ready_cancel (&client->th);
  (void) GNUNET_SCHEDULER_add_now (&destroy_connection,
				   client->connection);
  /* need to cancel again, as it might have been re-added
     in the meantime (i.e. during callbacks) */
  if (GNUNET_SCHEDULER_NO_TASK != client->warn_task)
  {
    GNUNET_SCHEDULER_cancel (client->warn_task);
    client->warn_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (GNUNET_YES == client->receive_pending)
  {
    GNUNET_CONNECTION_receive_cancel (client->connection);
    client->receive_pending = GNUNET_NO;
  }
  GNUNET_free (client);
  /* we might be in soft-shutdown, test if we're done */
  if (NULL != server)
    test_monitor_clients (server);
}


/**
 * Disable the "CORK" feature for communication with the given client,
 * forcing the OS to immediately flush the buffer on transmission
 * instead of potentially buffering multiple messages.
 *
 * @param client handle to the client
 * @return GNUNET_OK on success
 */
int
GNUNET_SERVER_client_disable_corking (struct GNUNET_SERVER_Client *client)
{
  return GNUNET_CONNECTION_disable_corking (client->connection);
}


/**
 * Wrapper for transmission notification that calls the original
 * callback and update the last activity time for our connection.
 *
 * @param cls the 'struct GNUNET_SERVER_Client'
 * @param size number of bytes we can transmit
 * @param buf where to copy the message
 * @return number of bytes actually transmitted
 */
static size_t
transmit_ready_callback_wrapper (void *cls, size_t size, void *buf)
{
  struct GNUNET_SERVER_Client *client = cls;
  GNUNET_CONNECTION_TransmitReadyNotify callback;

  client->th.cth = NULL;
  callback = client->th.callback;
  client->th.callback = NULL;
  client->last_activity = GNUNET_TIME_absolute_get ();
  return callback (client->th.callback_cls, size, buf);
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
 *           GNUNET_SERVER_notify_transmit_ready_cancel.
 *         NULL if we are already going to notify someone else (busy)
 */
struct GNUNET_SERVER_TransmitHandle *
GNUNET_SERVER_notify_transmit_ready (struct GNUNET_SERVER_Client *client,
                                     size_t size,
                                     struct GNUNET_TIME_Relative timeout,
                                     GNUNET_CONNECTION_TransmitReadyNotify
                                     callback, void *callback_cls)
{
  if (NULL != client->th.callback)
    return NULL;
  client->th.callback_cls = callback_cls;
  client->th.callback = callback;
  client->th.cth = GNUNET_CONNECTION_notify_transmit_ready (client->connection, size,
							    timeout,
							    &transmit_ready_callback_wrapper,
							    client);
  return &client->th;
}


/**
 * Abort transmission request.
 *
 * @param th request to abort
 */
void
GNUNET_SERVER_notify_transmit_ready_cancel (struct GNUNET_SERVER_TransmitHandle *th)
{
  GNUNET_CONNECTION_notify_transmit_ready_cancel (th->cth);
  th->cth = NULL;
  th->callback = NULL;
}


/**
 * Set the persistent flag on this client, used to setup client connection
 * to only be killed when the service it's connected to is actually dead.
 *
 * @param client the client to set the persistent flag on
 */
void
GNUNET_SERVER_client_persist_ (struct GNUNET_SERVER_Client *client)
{
  client->persist = GNUNET_YES;
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
  if (NULL == client)
    return;
  GNUNET_assert (client->suspended > 0);
  client->suspended--;
  if (GNUNET_OK != success)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "GNUNET_SERVER_receive_done called with failure indication\n");
    if ( (client->reference_count > 0) || (client->suspended > 0) )
      client->shutdown_now = GNUNET_YES;
    else
      GNUNET_SERVER_client_disconnect (client);
    return;
  }
  if (client->suspended > 0)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "GNUNET_SERVER_receive_done called, but more clients pending\n");
    return;
  }
  if (GNUNET_SCHEDULER_NO_TASK != client->warn_task)
  {
    GNUNET_SCHEDULER_cancel (client->warn_task);
    client->warn_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (GNUNET_YES == client->in_process_client_buffer)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "GNUNET_SERVER_receive_done called while still in processing loop\n");
    return;
  }
  if ((NULL == client->server) || (GNUNET_YES == client->shutdown_now))
  {
    GNUNET_SERVER_client_disconnect (client);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "GNUNET_SERVER_receive_done causes restart in reading from the socket\n");
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == client->restart_task);
  client->restart_task = GNUNET_SCHEDULER_add_now (&restart_processing, client);
}


/* end of server.c */
