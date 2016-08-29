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
#include "gnunet_server_lib.h"
#include "gnunet_mq_lib.h"


/**
 * Get the list of addresses that a server for the given service
 * should bind to.
 *
 * @param service_name name of the service
 * @param cfg configuration (which specifies the addresses)
 * @param addrs set (call by reference) to an array of pointers to the
 *              addresses the server should bind to and listen on; the
 *              array will be NULL-terminated (on success)
 * @param addr_lens set (call by reference) to an array of the lengths
 *              of the respective `struct sockaddr` struct in the @a addrs
 *              array (on success)
 * @return number of addresses found on success,
 *              #GNUNET_SYSERR if the configuration
 *              did not specify reasonable finding information or
 *              if it specified a hostname that could not be resolved;
 *              #GNUNET_NO if the number of addresses configured is
 *              zero (in this case, '* @a addrs' and '* @a addr_lens' will be
 *              set to NULL).
 */
int
GNUNET_SERVICE_get_server_addresses (const char *service_name,
                                     const struct GNUNET_CONFIGURATION_Handle *cfg,
                                     struct sockaddr ***addrs,
                                     socklen_t **addr_lens);


/**
 * Function called by the service's run
 * method to run service-specific setup code.
 *
 * @param cls closure
 * @param server the initialized server
 * @param cfg configuration to use
 */
typedef void
(*GNUNET_SERVICE_Main) (void *cls,
                        struct GNUNET_SERVER_Handle *server,
                        const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Options for the service (bitmask).
 */
enum GNUNET_SERVICE_Options
{
  /**
   * Use defaults.
   */
  GNUNET_SERVICE_OPTION_NONE = 0,

  /**
   * Do not trigger server shutdown on signals, allow for the user
   * to terminate the server explicitly when needed.
   */
  GNUNET_SERVICE_OPTION_MANUAL_SHUTDOWN = 1,

  /**
   * Trigger a SOFT server shutdown on signals, allowing active
   * non-monitor clients to complete their transactions.
   */
  GNUNET_SERVICE_OPTION_SOFT_SHUTDOWN = 2
};


/**
 * Run a standard GNUnet service startup sequence (initialize loggers
 * and configuration, parse options).
 *
 * @param argc number of command line arguments in @a argv
 * @param argv command line arguments
 * @param service_name our service name
 * @param options service options
 * @param task main task of the service
 * @param task_cls closure for @a task
 * @return #GNUNET_SYSERR on error, #GNUNET_OK
 *         if we shutdown nicely
 * @deprecated
 */
int
GNUNET_SERVICE_run (int argc,
                    char *const *argv,
		    const char *service_name,
                    enum GNUNET_SERVICE_Options options,
		    GNUNET_SERVICE_Main task,
		    void *task_cls);


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
 * Obtain the server used by a service.  Note that the server must NOT
 * be destroyed by the caller.
 *
 * @param ctx the service context returned from the start function
 * @return handle to the server for this service, NULL if there is none
 * @deprecated
 */
struct GNUNET_SERVER_Handle *
GNUNET_SERVICE_get_server (struct GNUNET_SERVICE_Context *ctx);


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
 *
 */
struct GNUNET_SERVICE_Handle;


/**
 *
 */
struct GNUNET_SERVICE_Client;


/**
 *
 *
 * @param cls
 * @param cfg
 * @param sh
 */
typedef void
(*GNUNET_SERVICE_InitCallback)(void *cls,
                               const struct GNUNET_CONFIGURATION_Handle *cfg,
                               struct GNUNET_SERVICE_Handle *sh);


/**
 *
 *
 * @param cls
 * @param c
 * @param mq
 * @return
 */
typedef void *
(*GNUNET_SERVICE_ConnectHandler)(void *cls,
                                 struct GNUNET_SERVICE_Client *c,
                                 struct GNUNET_MQ_Handle *mq);


/**
 *
 *
 * @param cls
 * @param c
 * @param internal_cls
 */
typedef void
(*GNUNET_SERVICE_DisconnectHandler)(void *cls,
                                    struct GNUNET_SERVICE_Client *c,
                                    void *internal_cls);


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
 * @param handlers NULL-terminated array of message handlers for the service,
 *                 the closure will be set to the value returned by
 *                 the @a connect_cb for the respective connection
 * @return 0 on success, non-zero on error
 */
#define GNUNET_SERVICE_MAIN(service_name,service_options,init_cb,connect_cb,disconnect_cb,cls,handlers) \
  int \
  main (int argc,\
        char *const *argv)\
  { \
    return GNUNET_SERVICE_ruN_ (argc, \
                                argv, \
                                service_name, \
                                service_options, \
                                init_cb, \
                                connect_cb, \
                                disconnect_cb, \
                                cls, \
                                handlers); \
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
 * Stop the listen socket and get ready to shutdown the server once
 * only clients marked using #GNUNET_SERVER_client_mark_monitor are
 * left.
 *
 * @param sh server to stop listening on
 */
void
GNUNET_SERVICE_stop_listening (struct GNUNET_SERVICE_Handle *sh);


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
