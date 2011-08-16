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
 * @file include/gnunet_service_lib.h
 * @brief functions related to starting services
 * @author Christian Grothoff
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


/**
 * Get the list of addresses that a server for the given service
 * should bind to.
 *
 * @param serviceName name of the service
 * @param cfg configuration (which specifies the addresses)
 * @param addrs set (call by reference) to an array of pointers to the
 *              addresses the server should bind to and listen on; the
 *              array will be NULL-terminated (on success)
 * @param addr_lens set (call by reference) to an array of the lengths
 *              of the respective 'struct sockaddr' struct in the 'addrs'
 *              array (on success)
 * @return number of addresses found on success,
 *              GNUNET_SYSERR if the configuration
 *              did not specify reasonable finding information or
 *              if it specified a hostname that could not be resolved;
 *              GNUNET_NO if the number of addresses configured is
 *              zero (in this case, '*addrs' and '*addr_lens' will be
 *              set to NULL).
 */
int
GNUNET_SERVICE_get_server_addresses (const char *serviceName,
                                     const struct GNUNET_CONFIGURATION_Handle
                                     *cfg, struct sockaddr ***addrs,
                                     socklen_t ** addr_lens);


/**
 * Function called by the service's run
 * method to run service-specific setup code.
 *
 * @param cls closure
 * @param server the initialized server
 * @param cfg configuration to use
 */
typedef void (*GNUNET_SERVICE_Main) (void *cls,
                                     struct GNUNET_SERVER_Handle * server,
                                     const struct GNUNET_CONFIGURATION_Handle *
                                     cfg);


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
  GNUNET_SERVICE_OPTION_MANUAL_SHUTDOWN = 1
};


/**
 * Run a standard GNUnet service startup sequence (initialize loggers
 * and configuration, parse options).
 *
 * @param argc number of command line arguments
 * @param argv command line arguments
 * @param serviceName our service name
 * @param opt service options
 * @param task main task of the service
 * @param task_cls closure for task
 * @return GNUNET_SYSERR on error, GNUNET_OK
 *         if we shutdown nicely
 */
int
GNUNET_SERVICE_run (int argc, char *const *argv, const char *serviceName,
                    enum GNUNET_SERVICE_Options opt, GNUNET_SERVICE_Main task,
                    void *task_cls);


struct GNUNET_SERVICE_Context;

/**
 * Run a service startup sequence within an existing
 * initialized system.
 *
 * @param serviceName our service name
 * @param cfg configuration to use
 * @return NULL on error, service handle
 */
struct GNUNET_SERVICE_Context *
GNUNET_SERVICE_start (const char *serviceName,
                      const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Obtain the server used by a service.  Note that the server must NOT
 * be destroyed by the caller.
 *
 * @param ctx the service context returned from the start function
 * @return handle to the server for this service, NULL if there is none
 */
struct GNUNET_SERVER_Handle *
GNUNET_SERVICE_get_server (struct GNUNET_SERVICE_Context *ctx);


/**
 * Stop a service that was started with "GNUNET_SERVICE_start".
 *
 * @param sctx the service context returned from the start function
 */
void
GNUNET_SERVICE_stop (struct GNUNET_SERVICE_Context *sctx);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_SERVICE_LIB_H */
#endif
/* end of gnunet_service_lib.h */
