/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013, 2016 GNUnet e.V.

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
 * @author Christian Grothoff
 *
 * @file
 * Functions related to starting services
 *
 * @defgroup service  Service library
 * Start service processes.
 *
 * @see [Documentation](https://gnunet.org/developer-handbook-util-services)
 *
 * @{
 */

#ifndef GNUNET_SERVICE_LIB_H
#define GNUNET_SERVICE_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_configuration_lib.h"
#include "gnunet_mq_lib.h"

/**
 * Largest supported message (to be precise, one byte more
 * than the largest possible message, so tests involving
 * this value should check for messages being smaller than
 * this value). NOTE: legacy name.
 */
#define GNUNET_SERVER_MAX_MESSAGE_SIZE 65536

/**
 * Smallest supported message. NOTE: legacy name.
 */
#define GNUNET_SERVER_MIN_BUFFER_SIZE sizeof (struct GNUNET_MessageHeader)

/**
 * Timeout we use on TCP connect before trying another
 * result from the DNS resolver.  Actual value used
 * is this value divided by the number of address families.
 * Default is 5s.  NOTE: legacy name.
 */
#define GNUNET_CONNECTION_CONNECT_RETRY_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)


/**
 * Options for the service (bitmask).
 */
enum GNUNET_SERVICE_Options
{
  /**
   * Use defaults.  Terminates all client connections and the listen
   * sockets immediately upon receiving the shutdown signal.
   */
  GNUNET_SERVICE_OPTION_NONE = 0,

  /**
   * Do not trigger server shutdown on signal at all; instead, allow
   * for the user to terminate the server explicitly when needed
   * by calling #GNUNET_SERVICE_shutdown().
   */
  GNUNET_SERVICE_OPTION_MANUAL_SHUTDOWN = 1,

  /**
   * Trigger a SOFT server shutdown on signals, allowing active
   * non-monitor clients to complete their transactions.
   */
  GNUNET_SERVICE_OPTION_SOFT_SHUTDOWN = 2
};




/**
 * Opaque handle for a service.
 */
struct GNUNET_SERVICE_Context;


/**
 * Run a service startup sequence within an existing
 * initialized system.
 *
 * @param service_name our service name
 * @param cfg configuration to use
 * @param options service options
 * @return NULL on error, service handle
 * @deprecated
 */
struct GNUNET_SERVICE_Context *
GNUNET_SERVICE_start (const char *service_name,
                      const struct GNUNET_CONFIGURATION_Handle *cfg,
		      enum GNUNET_SERVICE_Options options);


/**
 * Get the NULL-terminated array of listen sockets for this service.
 *
 * @param ctx service context to query
 * @return NULL if there are no listen sockets, otherwise NULL-terminated
 *              array of listen sockets.
 * @deprecated
 */
struct GNUNET_NETWORK_Handle *const *
GNUNET_SERVICE_get_listen_sockets (struct GNUNET_SERVICE_Context *ctx);


/**
 * Stop a service that was started with #GNUNET_SERVICE_start.
 *
 * @param sctx the service context returned from the start function
 * @deprecated
 */
void
GNUNET_SERVICE_stop (struct GNUNET_SERVICE_Context *sctx);


/* **************** NEW SERVICE API ********************** */

/**
 * Handle to a service.
 */
struct GNUNET_SERVICE_Handle;


/**
 * Handle to a client that is connected to a service.
 */
struct GNUNET_SERVICE_Client;


/**
 * Callback to initialize a service, called exactly once when the service is run.
 *
 * @param cls closure passed to #GNUNET_SERVICE_MAIN
 * @param cfg configuration to use for this service
 * @param sh handle to the newly create service
 */
typedef void
(*GNUNET_SERVICE_InitCallback)(void *cls,
                               const struct GNUNET_CONFIGURATION_Handle *cfg,
                               struct GNUNET_SERVICE_Handle *sh);


/**
 * Callback to be called when a client connects to the service.
 *
 * @param cls closure for the service
 * @param c the new client that connected to the service
 * @param mq the message queue used to send messages to the client
 * @return the client-specific (`internal') closure
 */
typedef void *
(*GNUNET_SERVICE_ConnectHandler)(void *cls,
                                 struct GNUNET_SERVICE_Client *c,
                                 struct GNUNET_MQ_Handle *mq);


/**
 * Callback to be called when a client disconnected from the service
 *
 * @param cls closure for the service
 * @param c the client that disconnected
 * @param internal_cls the client-specific (`internal') closure
 */
typedef void
(*GNUNET_SERVICE_DisconnectHandler)(void *cls,
                                    struct GNUNET_SERVICE_Client *c,
                                    void *internal_cls);


/**
 * Low-level function to start a service if the scheduler
 * is already running.  Should only be used directly in
 * special cases.
 *
 * The function will launch the service with the name @a service_name
 * using the @a service_options to configure its shutdown
 * behavior. When clients connect or disconnect, the respective
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
 * The service must be stopped using #GNUNET_SERVICE_stoP().
 *
 * @param service_name name of the service to run
 * @param cfg configuration to use
 * @param connect_cb function to call whenever a client connects
 * @param disconnect_cb function to call whenever a client disconnects
 * @param cls closure argument for @a connect_cb and @a disconnect_cb
 * @param handlers NULL-terminated array of message handlers for the service,
 *                 the closure will be set to the value returned by
 *                 the @a connect_cb for the respective connection
 * @return NULL on error
 */
struct GNUNET_SERVICE_Handle *
GNUNET_SERVICE_starT (const char *service_name,
                      const struct GNUNET_CONFIGURATION_Handle *cfg,
                      GNUNET_SERVICE_ConnectHandler connect_cb,
                      GNUNET_SERVICE_DisconnectHandler disconnect_cb,
                      void *cls,
                      const struct GNUNET_MQ_MessageHandler *handlers);


/**
 * Stops a service that was started with #GNUNET_SERVICE_starT().
 *
 * @param srv service to stop
 */
void
GNUNET_SERVICE_stoP (struct GNUNET_SERVICE_Handle *srv);


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
                     const struct GNUNET_MQ_MessageHandler *handlers);


/**
 * Creates the "main" function for a GNUnet service.  You
 * MUST use this macro to define GNUnet services (except
 * for ARM, which MUST NOT use the macro).  The reason is
 * the GNUnet-as-a-library project, where we will not define
 * a main function anywhere but in ARM.
 *
 * The macro will launch the service with the name @a service_name
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
 * @param service_name name of the service to run
 * @param options options controlling shutdown of the service
 * @param service_init_cb function to call once the service is ready
 * @param connect_cb function to call whenever a client connects
 * @param disconnect_cb function to call whenever a client disconnects
 * @param cls closure argument for @a service_init_cb, @a connect_cb and @a disconnect_cb
 * @param ... array of message handlers for the service, terminated
 *            by #GNUNET_MQ_handler_end();
 *                 the closure will be set to the value returned by
 *                 the @a connect_cb for the respective connection
 * @return 0 on success, non-zero on error
 *
 * Sample invocation:
 * <code>
 * GNUNET_SERVICE_MAIN
 * ("resolver",
 *  GNUNET_SERVICE_OPTION_NONE,
 *  &init_cb,
 *  &connect_cb,
 *  &disconnect_cb,
 *  closure_for_cb,
 *  GNUNET_MQ_hd_var_size (get,
 *	 		   GNUNET_MESSAGE_TYPE_RESOLVER_REQUEST,
 * 			   struct GNUNET_RESOLVER_GetMessage,
 *			   NULL),
 *  GNUNET_MQ_handler_end ());
 * </code>
 */
#define GNUNET_SERVICE_MAIN(service_name,service_options,init_cb,connect_cb,disconnect_cb,cls,...) \
  int \
  main (int argc,\
        char *const *argv)\
  { \
    struct GNUNET_MQ_MessageHandler mh[] = { \
      __VA_ARGS__ \
    };			      \
    return GNUNET_SERVICE_ruN_ (argc, \
                                argv, \
                                service_name, \
                                service_options, \
                                init_cb, \
                                connect_cb, \
                                disconnect_cb, \
                                cls, \
                                mh); \
  }


/**
 * Suspend accepting connections from the listen socket temporarily.
 * Resume activity using #GNUNET_SERVICE_resume.
 *
 * @param sh service to stop accepting connections.
 */
void
GNUNET_SERVICE_suspend (struct GNUNET_SERVICE_Handle *sh);


/**
 * Resume accepting connections from the listen socket.
 *
 * @param sh service to resume accepting connections.
 */
void
GNUNET_SERVICE_resume (struct GNUNET_SERVICE_Handle *sh);


/**
 * Continue receiving further messages from the given client.
 * Must be called after each message received.
 *
 * @param c the client to continue receiving from
 */
void
GNUNET_SERVICE_client_continue (struct GNUNET_SERVICE_Client *c);


/**
 * Obtain the message queue of @a c.  Convenience function.
 *
 * @param c the client to continue receiving from
 * @return the message queue of @a c
 */
struct GNUNET_MQ_Handle *
GNUNET_SERVICE_client_get_mq (struct GNUNET_SERVICE_Client *c);


/**
 * Disable the warning the server issues if a message is not
 * acknowledged in a timely fashion.  Use this call if a client is
 * intentionally delayed for a while.  Only applies to the current
 * message.
 *
 * @param c client for which to disable the warning
 */
void
GNUNET_SERVICE_client_disable_continue_warning (struct GNUNET_SERVICE_Client *c);


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
GNUNET_SERVICE_client_drop (struct GNUNET_SERVICE_Client *c);


/**
 * Explicitly stops the service.
 *
 * @param sh server to shutdown
 */
void
GNUNET_SERVICE_shutdown (struct GNUNET_SERVICE_Handle *sh);


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
GNUNET_SERVICE_client_mark_monitor (struct GNUNET_SERVICE_Client *c);


/**
 * Set the persist option on this client.  Indicates that the
 * underlying socket or fd should never really be closed.  Used for
 * indicating process death.
 *
 * @param c client to persist the socket (never to be closed)
 */
void
GNUNET_SERVICE_client_persist (struct GNUNET_SERVICE_Client *c);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_SERVICE_LIB_H */
#endif

/** @} */  /* end of group service */

/* end of gnunet_service_lib.h */
