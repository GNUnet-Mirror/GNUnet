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
 * Function called by the service's run
 * method to run service-specific setup code.
 *
 * @param cls closure
 * @param sched scheduler to use
 * @param server the initialized server
 * @param cfg configuration to use
 */
typedef void (*GNUNET_SERVICE_Main) (void *cls,
                                     struct GNUNET_SCHEDULER_Handle * sched,
                                     struct GNUNET_SERVER_Handle * server,
                                     struct GNUNET_CONFIGURATION_Handle *
                                     cfg);


/**
 * Function called when the service shuts
 * down to run service-specific teardown code.
 *
 * @param cls closure
 * @param cfg configuration to use
 */
typedef void (*GNUNET_SERVICE_Term) (void *cls,
                                     struct GNUNET_CONFIGURATION_Handle *
                                     cfg);


/**
 * Run a standard GNUnet service startup sequence (initialize loggers
 * and configuration, parse options).
 *
 * @param argc number of command line arguments
 * @param argv command line arguments
 * @param serviceName our service name
 * @param task main task of the service
 * @param task_cls closure for task
 * @param term termination task of the service
 * @param term_cls closure for term
 * @return GNUNET_SYSERR on error, GNUNET_OK
 *         if we shutdown nicely
 */
int GNUNET_SERVICE_run (int argc,
                        char *const *argv,
                        const char *serviceName,
                        GNUNET_SERVICE_Main task,
                        void *task_cls,
                        GNUNET_SERVICE_Term term, void *term_cls);


struct GNUNET_SERVICE_Context;

/**
 * Run a service startup sequence within an existing
 * initialized system.
 *
 * @param serviceName our service name
 * @param sched scheduler to use
 * @param cfg configuration to use
 * @return NULL on error, service handle
 */
struct GNUNET_SERVICE_Context *GNUNET_SERVICE_start (const char *serviceName,
                                                     struct
                                                     GNUNET_SCHEDULER_Handle
                                                     *sched,
                                                     struct
                                                     GNUNET_CONFIGURATION_Handle
                                                     *cfg);


/**
 * Obtain the server used by a service.  Note that the server must NOT
 * be destroyed by the caller.
 *
 * @param ctx the service context returned from the start function
 * @return handle to the server for this service, NULL if there is none
 */
struct GNUNET_SERVER_Handle *GNUNET_SERVICE_get_server (struct
                                                        GNUNET_SERVICE_Context
                                                        *ctx);


/**
 * Stop a service that was started with "GNUNET_SERVICE_start".
 *
 * @param ctx the service context returned from the start function
 */
void GNUNET_SERVICE_stop (struct GNUNET_SERVICE_Context *ctx);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_SERVICE_LIB_H */
#endif
/* end of gnunet_service_lib.h */
