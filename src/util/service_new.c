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
  GNUNET_SERVICE_Main task;

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
   * Server that this client belongs to.
   */
  struct GNUNET_SERVER_Handle *server;

  /**
   * Task that warns about missing calls to
   * #GNUNET_SERVICE_client_continue().
   */
  struct GNUNET_SCHEDULER_Task *warn_task;

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
  GNUNET_break (0); // not implemented
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
  GNUNET_break (0); // not implemented
}


/**
 * Resume accepting connections from the listen socket.
 *
 * @param sh service to resume accepting connections.
 */
void
GNUNET_SERVICE_resume (struct GNUNET_SERVICE_Handle *sh)
{
  GNUNET_break (0); // not implemented
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
  GNUNET_break (0); // not implemented
}


/**
 * Stop the listen socket and get ready to shutdown the server once
 * only clients marked using #GNUNET_SERVER_client_mark_monitor are
 * left.
 *
 * @param sh server to stop listening on
 */
void
GNUNET_SERVICE_stop_listening (struct GNUNET_SERVICE_Handle *sh)
{
  GNUNET_break (0); // not implemented
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
  GNUNET_break (0); // not implemented
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
  GNUNET_break (0); // not implemented
}



/* end of service_new.c */
