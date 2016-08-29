/*
     This file is part of GNUnet.
     Copyright (C) 2016 GNUnet e.V.

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file util/service_new.c
 * @brief functions related to starting services (redesign)
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_constants.h"
#include "gnunet_resolver_service.h"


/**
 * Information the service tracks per listen operation.
 */
struct ServiceListenContext
{

  /**
   * Kept in a DLL.
   */
  struct ServiceListenContext *next;

  /**
   * Kept in a DLL.
   */
  struct ServiceListenContext *prev;

  /**
   * Service this listen context belongs to.
   */
  struct GNUNET_SERVICE_Handle *sh;

  /**
   * Socket we are listening on.
   */
  struct GNUNET_NETWORK_Handle *listen_socket;

  /**
   * Task scheduled to do the listening.
   */
  struct GNUNET_SCHEDULER_Task *listen_task;

};


/**
 * Handle to a service.
 */
struct GNUNET_SERVICE_Handle
{
  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Name of our service.
   */
  const char *service_name;

  /**
   * Main service-specific task to run.
   */
  GNUNET_SERVICE_InitCallback service_init_cb;

  /**
   * Function to call when clients connect.
   */
  GNUNET_SERVICE_ConnectHandler connect_cb;

  /**
   * Function to call when clients disconnect / are disconnected.
   */
  GNUNET_SERVICE_DisconnectHandler disconnect_cb;

  /**
   * Closure for @e service_init_cb, @e connect_cb, @e disconnect_cb.
   */
  void *cb_cls;

  /**
   * DLL of listen sockets used to accept new connections.
   */
  struct ServiceListenContext *slc_head;

  /**
   * DLL of listen sockets used to accept new connections.
   */
  struct ServiceListenContext *slc_tail;

  /**
   * Our clients, kept in a DLL.
   */
  struct GNUNET_SERVICE_Client *clients_head;

  /**
   * Our clients, kept in a DLL.
   */
  struct GNUNET_SERVICE_Client *clients_tail;

  /**
   * Message handlers to use for all clients.
   */
  const struct GNUNET_MQ_MessageHandler *handlers;

  /**
   * Closure for @e task.
   */
  void *task_cls;

  /**
   * IPv4 addresses that are not allowed to connect.
   */
  struct GNUNET_STRINGS_IPv4NetworkPolicy *v4_denied;

  /**
   * IPv6 addresses that are not allowed to connect.
   */
  struct GNUNET_STRINGS_IPv6NetworkPolicy *v6_denied;

  /**
   * IPv4 addresses that are allowed to connect (if not
   * set, all are allowed).
   */
  struct GNUNET_STRINGS_IPv4NetworkPolicy *v4_allowed;

  /**
   * IPv6 addresses that are allowed to connect (if not
   * set, all are allowed).
   */
  struct GNUNET_STRINGS_IPv6NetworkPolicy *v6_allowed;

  /**
   * Do we require a matching UID for UNIX domain socket connections?
   * #GNUNET_NO means that the UID does not have to match (however,
   * @e match_gid may still impose other access control checks).
   */
  int match_uid;

  /**
   * Do we require a matching GID for UNIX domain socket connections?
   * Ignored if @e match_uid is #GNUNET_YES.  Note that this is about
   * checking that the client's UID is in our group OR that the
   * client's GID is our GID.  If both "match_gid" and @e match_uid are
   * #GNUNET_NO, all users on the local system have access.
   */
  int match_gid;

  /**
   * Set to #GNUNET_YES if we got a shutdown signal and terminate
   * the service if #have_non_monitor_clients() returns #GNUNET_YES.
   */
  int got_shutdown;

  /**
   * Our options.
   */
  enum GNUNET_SERVICE_Options options;

};


/**
 * Handle to a client that is connected to a service.
 */
struct GNUNET_SERVICE_Client
{

  /**
   * Kept in a DLL.
   */
  struct GNUNET_SERVICE_Client *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_SERVICE_Client *prev;

  /**
   * Server that this client belongs to.
   */
  struct GNUNET_SERVER_Handle *sh;

  /**
   * Socket of this client.
   */
  struct GNUNET_NETWORK_Handle *sock;

  /**
   * Message queue for the client.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Tokenizer we use for processing incoming data.
   */
  struct GNUNET_SERVER_MessageStreamTokenizer *mst;

  /**
   * Task that warns about missing calls to
   * #GNUNET_SERVICE_client_continue().
   */
  struct GNUNET_SCHEDULER_Task *warn_task;

  /**
   * Task that receives data from the client to
   * pass it to the handlers.
   */
  struct GNUNET_SCHEDULER_Task *recv_task;

  /**
   * Task that transmit data to the client.
   */
  struct GNUNET_SCHEDULER_Task *send_task;

  /**
   * User context value, value returned from
   * the connect callback.
   */
  void *user_context;

  /**
   * Persist the file handle for this client no matter what happens,
   * force the OS to close once the process actually dies.  Should only
   * be used in special cases!
   */
  int persist;

  /**
   * Is this client a 'monitor' client that should not be counted
   * when deciding on destroying the server during soft shutdown?
   * (see also #GNUNET_SERVICE_start)
   */
  int is_monitor;

  /**
   * Type of last message processed (for warn_no_receive_done).
   */
  uint16_t warn_type;
};


/**
 * Check if any of the clients we have left are unrelated to
 * monitoring.
 *
 * @param sh service to check clients for
 * @return #GNUNET_YES if we have non-monitoring clients left
 */
static int
have_non_monitor_clients (struct GNUNET_SERVICE_Handle *sh)
{
  struct GNUNET_SERVICE_Client *client;

  for (client = sh->clients_head;NULL != client; client = client->next)
  {
    if (client->is_monitor)
      continue;
    return GNUNET_YES;
  }
  return GNUNET_NO;
}


/**
 * Shutdown task triggered when a service should be terminated.
 * This considers active clients and the service options to see
 * how this specific service is to be terminated, and depending
 * on this proceeds with the shutdown logic.
 *
 * @param cls our `struct GNUNET_SERVICE_Handle`
 */
static void
service_main (void *cls)
{
  struct GNUNET_SERVICE_Handle *sh = cls;
  struct GNUNET_SERVICE_Client *client;
  int alive;

  switch (sh->options)
  {
  case GNUNET_SERVICE_OPTION_NONE:
    GNUNET_SERVICE_shutdown (sh);
    break;
  case GNUNET_SERVICE_OPTION_MANUAL_SHUTDOWN:
    /* This task should never be run if we are using
       the manual shutdown. */
    GNUNET_assert (0);
    break;
  case GNUNET_SERVICE_OPTION_SOFT_SHUTDOWN:
    sh->got_shutdown = GNUNET_YES;
    GNUNET_SERVICE_suspend (sh);
    if (GNUNET_NO == have_non_monitor_clients (sh))
      GNUNET_SERVICE_shutdown (sh);
    break;
  }
}


/**
 * First task run by any service.  Initializes our shutdown task,
 * starts the listening operation on our listen sockets and launches
 * the custom logic of the application service.
 *
 * @param cls our `struct GNUNET_SERVICE_Handle`
 */
static void
service_main (void *cls)
{
  struct GNUNET_SERVICE_Handle *sh = cls;

  if (GNUNET_SERVICE_OPTION_MANUAL_SHUTDOWN != sh->options)
    GNUNET_SCHEDULER_add_shutdown (&service_shutdown,
                                   sh);
  GNUNET_SERVICE_resume (sh);
  sh->service_init_cb (sh->cb_cls,
                       sh->cfg,
                       sh);
}


/**
 * Creates the "main" function for a GNUnet service.  You
 * should almost always use the #GNUNET_SERVICE_MAIN macro
 * instead of calling this function directly (except
 * for ARM, which should call this function directly).
 *
 * The function will launch the service with the name @a service_name
 * using the @a service_options to configure its shutdown
 * behavior. Once the service is ready, the @a init_cb will be called
 * for service-specific initialization.  @a init_cb will be given the
 * service handler which can be used to control the service's
 * availability.  When clients connect or disconnect, the respective
 * @a connect_cb or @a disconnect_cb functions will be called. For
 * messages received from the clients, the respective @a handlers will
 * be invoked; for the closure of the handlers we use the return value
 * from the @a connect_cb invocation of the respective client.
 *
 * Each handler MUST call #GNUNET_SERVICE_client_continue() after each
 * message to receive further messages from this client.  If
 * #GNUNET_SERVICE_client_continue() is not called within a short
 * time, a warning will be logged. If delays are expected, services
 * should call #GNUNET_SERVICE_client_disable_continue_warning() to
 * disable the warning.
 *
 * Clients sending invalid messages (based on @a handlers) will be
 * dropped. Additionally, clients can be dropped at any time using
 * #GNUNET_SERVICE_client_drop().
 *
 * @param argc number of command-line arguments in @a argv
 * @param argv array of command-line arguments
 * @param service_name name of the service to run
 * @param options options controlling shutdown of the service
 * @param service_init_cb function to call once the service is ready
 * @param connect_cb function to call whenever a client connects
 * @param disconnect_cb function to call whenever a client disconnects
 * @param cls closure argument for @a service_init_cb, @a connect_cb and @a disconnect_cb
 * @param handlers NULL-terminated array of message handlers for the service,
 *                 the closure will be set to the value returned by
 *                 the @a connect_cb for the respective connection
 * @return 0 on success, non-zero on error
 */
int
GNUNET_SERVICE_ruN_ (int argc,
                     char *const *argv,
                     const char *service_name,
                     enum GNUNET_SERVICE_Options options,
                     GNUNET_SERVICE_InitCallback service_init_cb,
                     GNUNET_SERVICE_ConnectHandler connect_cb,
                     GNUNET_SERVICE_DisconnectHandler disconnect_cb,
                     void *cls,
                     const struct GNUNET_MQ_MessageHandler *handlers)
{
  struct GNUNET_SERVICE_Handle sh;

  // FIXME: setup (parse command line, configuration, init sh)
  GNUNET_SCHEDULER_run (&service_main,
                        &sh);
  // FIXME: cleanup
  return 1;
}


/**
 * Suspend accepting connections from the listen socket temporarily.
 * Resume activity using #GNUNET_SERVICE_resume.
 *
 * @param sh service to stop accepting connections.
 */
void
GNUNET_SERVICE_suspend (struct GNUNET_SERVICE_Handle *sh)
{
  struct ServiceListenContext *slc;

  for (slc = slc_head; NULL != slc; slc = slc->next)
  {
    if (NULL != slc->listen_task)
      {
        GNUNET_SCHEDULER_cancel (slc->listen_task);
        slc->listen_task = NULL;
      }
  }
}


/**
 * Signature of functions implementing the sending functionality of a
 * message queue.
 *
 * @param mq the message queue
 * @param msg the message to send
 * @param impl_state state of the implementation
 */
static void
service_mq_send (struct GNUNET_MQ_Handle *mq,
                 const struct GNUNET_MessageHeader *msg,
                 void *impl_state)
{
  struct GNUNET_SERVICE_Client *client = cls;

  // FIXME 1: setup "client->send_task" for transmission.
  // FIXME 2: I seriously hope we do not need to make a copy of `msg`!
  // OPTIMIZATION: ideally, we'd like the ability to peak at the rest of
  //               the queue and transmit more than one message if possible.
}


/**
 * Implements the destruction of a message queue.  Implementations
 * must not free @a mq, but should take care of @a impl_state.
 * Not sure there is anything to do here! (FIXME!)
 *
 * @param mq the message queue to destroy
 * @param impl_state state of the implementation
 */
static void
service_mq_destroy (struct GNUNET_MQ_Handle *mq,
                    void *impl_state)
{
  struct GNUNET_SERVICE_Client *client = cls;

  // FIXME
}


/**
 * Implementation function that cancels the currently sent message.
 *
 * @param mq message queue
 * @param impl_state state specific to the implementation
 */
static void
service_mq_cancel (struct GNUNET_MQ_Handle *mq,
                   void *impl_state)
{
  struct GNUNET_SERVICE_Client *client = cls;

  // FIXME: semantics? What to do!?
}


/**
 * Generic error handler, called with the appropriate
 * error code and the same closure specified at the creation of
 * the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure
 * @param error error code
 */
static void
service_mq_error_handler (void *cls,
                          enum GNUNET_MQ_Error error)
{
  struct GNUNET_SERVICE_Client *client = cls;

  // FIXME!
}


/**
 * Functions with this signature are called whenever a
 * complete message is received by the tokenizer for a client.
 *
 * Do not call #GNUNET_SERVER_mst_destroy() from within
 * the scope of this callback.
 *
 * @param cls closure with the `struct GNUNET_SERVICE_Client *`
 * @param client closure with the `struct GNUNET_SERVICE_Client *`
 * @param message the actual message
 * @return #GNUNET_OK on success (always)
 */
static int
service_client_mst_cb (void *cls,
                       void *client,
                       const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_SERVICE_Client *client = cls;

  GNUNET_MQ_inject_message (client->mq,
                            message);
  return GNUNET_OK;
}


/**
 * A client sent us data. Receive and process it.  If we are done,
 * reschedule this task.
 *
 * @param cls the `struct GNUNET_SERVICE_Client` that sent us data.
 */
static void
service_client_recv (void *cls)
{
  struct GNUNET_SERVICE_Client *client = cls;

  // FIXME: read into buffer, pass to MST, then client->mq inject!
  // FIXME: revise MST API to avoid the memcpy!
  // i.e.: GNUNET_MST_read (client->sock);
}


/**
 * We have successfully accepted a connection from a client.  Now
 * setup the client (with the scheduler) and tell the application.
 *
 * @param sh service that accepted the client
 * @param sock socket associated with the client
 */
static void
start_client (struct GNUNET_SERVICE_Handle *sh,
              struct GNUNET_NETWORK_Handle *csock)
{
  struct GNUNET_SERVICE_Client *client;

  client = GNUNET_new (struct GNUNET_SERVICE_Client);
  GNUNET_CONTAINER_DLL_insert (sh->clients_head,
                               sh->clients_tail,
                               client);
  client->sh = sh;
  client->sock = csock;
  client->mq = GNUNET_MQ_queue_for_callbacks (&service_mq_send,
                                              &service_mq_destroy,
                                              &service_mq_cancel,
                                              client,
                                              sh->handlers,
                                              &service_mq_error_handler,
                                              client);
  client->mst = GNUNET_SERVER_mst_create (&service_client_mst_cb,
                                          client);
  client->user_context = sh->connect_cb (sh->cb_cls,
                                         client,
                                         client->mq);
  GNUNET_MQ_set_handlers_closure (client->mq,
                                  client->user_context);
  client->recv_task = GNUNET_SCHEDULER_add_read (client->sock,
                                                 &service_client_recv,
                                                 client);
}


/**
 * We have a client. Accept the incoming socket(s) (and reschedule
 * the listen task).
 *
 * @param cls the `struct ServiceListenContext` of the ready listen socket
 */
static void
accept_client (void *cls)
{
  struct ServiceListenContext *slc = cls;

  slc->listen_task = NULL;
  while (1)
    {
      struct GNUNET_NETWORK_Handle *sock;
      struct sockaddr_in *v4;
      struct sockaddr_in6 *v6;
      struct sockaddr_storage sa;
      socklen_t addrlen;
      int ok;

      addrlen = sizeof (sa);
      sock = GNUNET_NETWORK_socket_accept (slc->listen_socket,
                                           (struct sockaddr *) &sa,
                                           &addrlen);
      if (NULL == sock)
        break;
      switch (sa.sa_family)
      {
      case AF_INET:
        GNUNET_assert (addrlen == sizeof (struct sockaddr_in));
        v4 = (const struct sockaddr_in *) addr;
        ok = ( ( (NULL == sh->v4_allowed) ||
                 (check_ipv4_listed (sh->v4_allowed,
                                     &i4->sin_addr))) &&
               ( (NULL == sh->v4_denied) ||
                 (! check_ipv4_listed (sh->v4_denied,
                                       &i4->sin_addr)) ) );
        break;
      case AF_INET6:
        GNUNET_assert (addrlen == sizeof (struct sockaddr_in6));
        v6 = (const struct sockaddr_in6 *) addr;
        ok = ( ( (NULL == sh->v6_allowed) ||
                 (check_ipv6_listed (sh->v6_allowed,
                                     &i6->sin6_addr))) &&
               ( (NULL == sh->v6_denied) ||
                 (! check_ipv6_listed (sh->v6_denied,
                                       &i6->sin6_addr)) ) );
        break;
#ifndef WINDOWS
      case AF_UNIX:
        ok = GNUNET_OK;            /* controlled using file-system ACL now */
        break;
#endif
      default:
        LOG (GNUNET_ERROR_TYPE_WARNING,
             _("Unknown address family %d\n"),
             addr->sa_family);
        return GNUNET_SYSERR;
      }
      if (! ok)
        {
          LOG (GNUNET_ERROR_TYPE_DEBUG,
               "Service rejected incoming connection from %s due to policy.\n",
               GNUNET_a2s ((const struct sockaddr *) &sa,
                           addrlen));
          GNUNET_NETWORK_socket_close (sock);
          continue;
        }
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Service accepted incoming connection from %s.\n",
           GNUNET_a2s ((const struct sockaddr *) &sa,
                       addrlen));
      start_client (slc->sh,
                    sock);
    }
  slc->listen_task = GNUNET_SCHEDULER_add_read (slc->listen_socket,
                                                &accept_client,
                                                slc);
}


/**
 * Resume accepting connections from the listen socket.
 *
 * @param sh service to resume accepting connections.
 */
void
GNUNET_SERVICE_resume (struct GNUNET_SERVICE_Handle *sh)
{
  struct ServiceListenContext *slc;

  for (slc = slc_head; NULL != slc; slc = slc->next)
  {
    GNUNET_assert (NULL == slc->listen_task);
    slc->listen_task = GNUNET_SCHEDULER_add_read (slc->listen_socket,
                                                  &accept_client,
                                                  slc);
  }
}


/**
 * Continue receiving further messages from the given client.
 * Must be called after each message received.
 *
 * @param c the client to continue receiving from
 */
void
GNUNET_SERVICE_client_continue (struct GNUNET_SERVICE_Client *c)
{
  GNUNET_break (0); // not implemented
}


/**
 * Disable the warning the server issues if a message is not
 * acknowledged in a timely fashion.  Use this call if a client is
 * intentionally delayed for a while.  Only applies to the current
 * message.
 *
 * @param c client for which to disable the warning
 */
void
GNUNET_SERVICE_client_disable_continue_warning (struct GNUNET_SERVICE_Client *c)
{
  GNUNET_break (NULL != c->warn_task);
  if (NULL != c->warn_task)
  {
    GNUNET_SCHEDULER_cancel (c->warn_task);
    c->warn_task = NULL;
  }
}


/**
 * Ask the server to disconnect from the given client.  This is the
 * same as returning #GNUNET_SYSERR within the check procedure when
 * handling a message, wexcept that it allows dropping of a client even
 * when not handling a message from that client.  The `disconnect_cb`
 * will be called on @a c even if the application closes the connection
 * using this function.
 *
 * @param c client to disconnect now
 */
void
GNUNET_SERVICE_client_drop (struct GNUNET_SERVICE_Client *c)
{
  struct GNUNET_SERVICE_Handle *sh = c->sh;

  GNUNET_CONTAINER_DLL_remove (sh->clients_head,
                               sh->clients_tail,
                               c);
  sh->disconnect_cb (sh->cb_cls,
                     c,
                     c->user_context);
  if (NULL != c->warn_task)
  {
    GNUNET_SCHEDULER_cancel (c->warn_task);
    c->warn_task = NULL;
  }
  if (NULL != c->recv_task)
  {
    GNUNET_SCHEDULER_cancel (c->recv_task);
    c->recv_task = NULL;
  }
  if (NULL != c->send_task)
  {
    GNUNET_SCHEDULER_cancel (c->send_task);
    c->send_task = NULL;
  }
  GNUNET_SERVER_mst_destroy (c->mst);
  GNUNET_MQ_destroy (c->mq);
  if (GNUNET_NO == c->persist)
  {
    GNUNET_NETWORK_socket_close (c->sock);
  }
  else
  {
    GNUNET_NETWORK_socket_free_memory_only_ (c->sock);
  }
  GNUNET_free (c);
  if ( (GNUNET_YES == sh->got_shutdown) &&
       (GNUNET_NO == have_non_monitor_clients (sh)) )
    GNUNET_SERVICE_shutdown (sh);
}


/**
 * Explicitly stops the service.
 *
 * @param sh server to shutdown
 */
void
GNUNET_SERVICE_shutdown (struct GNUNET_SERVICE_Handle *sh)
{
  struct GNUNET_SERVICE_Client *client;

  GNUNET_SERVICE_suspend (sh);
  sh->got_shutdown = GNUNET_NO;
  while (NULL != (client = sh->clients_head))
    GNUNET_SERVICE_client_drop (client);
}


/**
 * Set the 'monitor' flag on this client.  Clients which have been
 * marked as 'monitors' won't prevent the server from shutting down
 * once #GNUNET_SERVICE_stop_listening() has been invoked.  The idea is
 * that for "normal" clients we likely want to allow them to process
 * their requests; however, monitor-clients are likely to 'never'
 * disconnect during shutdown and thus will not be considered when
 * determining if the server should continue to exist after
 * shutdown has been triggered.
 *
 * @param c client to mark as a monitor
 */
void
GNUNET_SERVICE_client_mark_monitor (struct GNUNET_SERVICE_Client *c)
{
  c->is_monitor = GNUNET_YES;
  if ( (GNUNET_YES == sh->got_shutdown) &&
       (GNUNET_NO == have_non_monitor_clients (sh)) )
    GNUNET_SERVICE_shutdown (sh);
}


/**
 * Set the persist option on this client.  Indicates that the
 * underlying socket or fd should never really be closed.  Used for
 * indicating process death.
 *
 * @param c client to persist the socket (never to be closed)
 */
void
GNUNET_SERVICE_client_persist (struct GNUNET_SERVICE_Client *c)
{
  c->persist = GNUNET_YES;
}


/* end of service_new.c */
