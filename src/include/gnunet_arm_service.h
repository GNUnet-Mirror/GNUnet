/*
      This file is part of GNUnet
      (C) 2009 Christian Grothoff (and other contributing authors)

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
      Free Software Foundation, Inc., 59 Temple Place - Suite 330,
      Boston, MA 02111-1307, USA.
 */

/**
 * @file include/gnunet_arm_service.h
 * @brief API to access gnunet-arm
 * @author Christian Grothoff
 */

#ifndef GNUNET_ARM_SERVICE_H
#define GNUNET_ARM_SERVICE_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_configuration_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_time_lib.h"

/**
 * Version of the arm API.
 */
#define GNUNET_ARM_VERSION 0x00000001


/**
 * Values characterizing GNUnet process states.
 */
enum GNUNET_ARM_ProcessStatus
{
  /**
   * Service name is unknown to ARM.
   */
  GNUNET_ARM_PROCESS_UNKNOWN = -1,

  /**
   * Service is now down (due to client request).
   */
  GNUNET_ARM_PROCESS_DOWN = 0,

  /**
   * Service is already running.
   */
  GNUNET_ARM_PROCESS_ALREADY_RUNNING = 1,

  /**
   * Service is currently being started (due to client request).
   */
  GNUNET_ARM_PROCESS_STARTING = 2,
  
  /**
   * Service is already being stopped by some other client.
   */
  GNUNET_ARM_PROCESS_ALREADY_STOPPING = 3,

  /**
   * Service is already down (no action taken)
   */
  GNUNET_ARM_PROCESS_ALREADY_DOWN = 4,

  /**
   * ARM is currently being shut down (no more process starts)
   */
  GNUNET_ARM_PROCESS_SHUTDOWN = 5,

  /**
   * Error in communication with ARM
   */
  GNUNET_ARM_PROCESS_COMMUNICATION_ERROR = 6,

  /**
   * Timeout in communication with ARM
   */
  GNUNET_ARM_PROCESS_COMMUNICATION_TIMEOUT = 7,

  /**
   * Failure to perform operation
   */
  GNUNET_ARM_PROCESS_FAILURE = 8
};


/**
 * Callback function invoked when operation is complete.
 *
 * @param cls closure
 * @param result outcome of the operation
 */
typedef void (*GNUNET_ARM_Callback) (void *cls, 
				     enum GNUNET_ARM_ProcessStatus result);


/**
 * Handle for interacting with ARM.
 */
struct GNUNET_ARM_Handle;


/**
 * Setup a context for communicating with ARM.  Note that this
 * can be done even if the ARM service is not yet running.
 *
 * @param cfg configuration to use (needed to contact ARM;
 *        the ARM service may internally use a different
 *        configuration to determine how to start the service).
 * @param service service that *this* process is implementing/providing, can be NULL
 * @return context to use for further ARM operations, NULL on error
 */
struct GNUNET_ARM_Handle *
GNUNET_ARM_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                    const char *service);


/**
 * Disconnect from the ARM service.
 *
 * @param h the handle that was being used
 */
void
GNUNET_ARM_disconnect (struct GNUNET_ARM_Handle *h);


/**
 * Start a service.  Note that this function merely asks ARM to start
 * the service and that ARM merely confirms that it forked the
 * respective process.  The specified callback may thus return before
 * the service has started to listen on the server socket and it may
 * also be that the service has crashed in the meantime.  Clients
 * should repeatedly try to connect to the service at the respective
 * port (with some delays in between) before assuming that the service
 * actually failed to start.  Note that if an error is returned to the
 * callback, clients obviously should not bother with trying to
 * contact the service.
 *
 * @param h handle to ARM
 * @param service_name name of the service
 * @param timeout how long to wait before failing for good
 * @param cb callback to invoke when service is ready
 * @param cb_cls closure for callback
 */
void
GNUNET_ARM_start_service (struct GNUNET_ARM_Handle *h, const char *service_name,
                          struct GNUNET_TIME_Relative timeout,
                          GNUNET_ARM_Callback cb, void *cb_cls);


/**
 * Stop a service.  Note that the callback is invoked as soon
 * as ARM confirms that it will ask the service to terminate.
 * The actual termination may still take some time.
 *
 * @param h handle to ARM
 * @param service_name name of the service
 * @param timeout how long to wait before failing for good
 * @param cb callback to invoke when service is ready
 * @param cb_cls closure for callback
 */
void
GNUNET_ARM_stop_service (struct GNUNET_ARM_Handle *h, const char *service_name,
                         struct GNUNET_TIME_Relative timeout,
                         GNUNET_ARM_Callback cb, void *cb_cls);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
