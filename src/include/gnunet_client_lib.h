/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2009 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_client_lib.h
 * @brief functions related to accessing services
 * @author Christian Grothoff
 */

#ifndef GNUNET_CLIENT_LIB_H
#define GNUNET_CLIENT_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_common.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_connection_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_time_lib.h"

/**
 * Opaque handle for a connection to a service.
 */
struct GNUNET_CLIENT_Connection;

/**
 * Get a connection with a service.
 *
 * @param sched scheduler to use
 * @param service_name name of the service
 * @param cfg configuration to use
 * @return NULL on error (service unknown to configuration)
 */
struct GNUNET_CLIENT_Connection *GNUNET_CLIENT_connect (struct
                                                        GNUNET_SCHEDULER_Handle
                                                        *sched,
                                                        const char
                                                        *service_name,
                                                        const struct
                                                        GNUNET_CONFIGURATION_Handle
                                                        *cfg);

/**
 * Destroy connection with the service.  This will
 * automatically cancel any pending "receive" request
 * (however, the handler will *NOT* be called, not
 * even with a NULL message).
 */
void GNUNET_CLIENT_disconnect (struct GNUNET_CLIENT_Connection *sock);

/**
 * Type of a function to call when we receive a message
 * from the service.
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
typedef void (*GNUNET_CLIENT_MessageHandler) (void *cls,
                                              const struct
                                              GNUNET_MessageHeader * msg);

/**
 * Read from the service.
 *
 * @param sched scheduler to use
 * @param sock the service
 * @param handler function to call with the message
 * @param cls closure for handler
 * @param timeout how long to wait until timing out
 */
void GNUNET_CLIENT_receive (struct GNUNET_CLIENT_Connection *sock,
                            GNUNET_CLIENT_MessageHandler handler,
                            void *cls, struct GNUNET_TIME_Relative timeout);


/**
 * Ask the client to call us once the specified number of bytes
 * are free in the transmission buffer.  May call the notify
 * method immediately if enough space is available.
 *
 * @param client connection to the service
 * @param size number of bytes to send
 * @param timeout after how long should we give up (and call
 *        notify with buf NULL and size 0)?
 * @param notify function to call
 * @param notify_cls closure for notify
 * @return NULL if someone else is already waiting to be notified
 *         non-NULL if the notify callback was queued (can be used to cancel
 *         using GNUNET_CONNECTION_notify_transmit_ready_cancel)
 */
struct GNUNET_NETWORK_TransmitHandle
  *GNUNET_CLIENT_notify_transmit_ready (struct GNUNET_CLIENT_Connection *sock,
                                        size_t size,
                                        struct GNUNET_TIME_Relative timeout,
                                        GNUNET_NETWORK_TransmitReadyNotify
                                        notify, void *notify_cls);


/**
 * Request that the service should shutdown.
 * Afterwards, the connection should be disconnected.
 *
 * @param sched scheduler to use
 * @param sock the socket connected to the service
 */
void GNUNET_CLIENT_service_shutdown (struct GNUNET_CLIENT_Connection *sock);


/**
 * Wait until the service is running.
 *
 * @param sched scheduler to use
 * @param service name of the service to wait for
 * @param cfg configuration to use
 * @param timeout how long to wait at most in ms
 * @param task task to run if service is running
 *        (reason will be "PREREQ_DONE" (service running)
 *         or "TIMEOUT" (service not known to be running))
 * @param task_cls closure for task
 */
void GNUNET_CLIENT_service_test (struct GNUNET_SCHEDULER_Handle *sched,
                                 const char *service,
                                 const struct GNUNET_CONFIGURATION_Handle *cfg,
                                 struct GNUNET_TIME_Relative timeout,
                                 GNUNET_SCHEDULER_Task task, void *task_cls);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_CLIENT_LIB_H */
#endif
/* end of gnunet_client_lib.h */
