/*
      This file is part of GNUnet
      Copyright (C) 2009, 2016 GNUnet e.V.

      GNUnet is free software: you can redistribute it and/or modify it
      under the terms of the GNU Affero General Public License as published
      by the Free Software Foundation, either version 3 of the License,
      or (at your option) any later version.

      GNUnet is distributed in the hope that it will be useful, but
      WITHOUT ANY WARRANTY; without even the implied warranty of
      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
      Affero General Public License for more details.

      You should have received a copy of the GNU Affero General Public License
      along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @author Christian Grothoff
 *
 * @file
 * API to access gnunet-arm
 *
 * @defgroup arm  ARM service
 * Automatic Restart Manager
 *
 * @see [Documentation](https://gnunet.org/arm)
 *
 * @{
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

#include "gnunet_util_lib.h"

/**
 * Version of the arm API.
 */
#define GNUNET_ARM_VERSION 0x00000003


/**
 * Statuses of the requests that client can send to ARM.
 */
enum GNUNET_ARM_RequestStatus {
  /**
   * Message was sent successfully.
   */
  GNUNET_ARM_REQUEST_SENT_OK = 0,

  /**
   * We disconnected from ARM, and request was not sent.
   */
  GNUNET_ARM_REQUEST_DISCONNECTED = 2
};


/**
 * Statuses of services.
 */
enum GNUNET_ARM_ServiceMonitorStatus {
  /**
   * Dummy message.
   */
  GNUNET_ARM_SERVICE_MONITORING_STARTED = 0,

  /**
   * Service was stopped.
   */
  GNUNET_ARM_SERVICE_STOPPED = 1,

  /**
   * Service starting was initiated
   */
  GNUNET_ARM_SERVICE_STARTING = 2,

  /**
   * Service stopping was initiated
   */
  GNUNET_ARM_SERVICE_STOPPING = 3
};


/**
 * Replies to ARM requests
 */
enum GNUNET_ARM_Result {
  /**
   * Service was stopped (never sent for ARM itself).
   */
  GNUNET_ARM_RESULT_STOPPED = 0,

  /**
   * ARM stopping was initiated (there's no "stopped" for ARM itself).
   */
  GNUNET_ARM_RESULT_STOPPING = 1,

  /**
   * Service starting was initiated
   */
  GNUNET_ARM_RESULT_STARTING = 2,

  /**
   * Asked to start it, but it's already starting.
   */
  GNUNET_ARM_RESULT_IS_STARTING_ALREADY = 3,

  /**
   * Asked to stop it, but it's already stopping.
   */
  GNUNET_ARM_RESULT_IS_STOPPING_ALREADY = 4,

  /**
   * Asked to start it, but it's already started.
   */
  GNUNET_ARM_RESULT_IS_STARTED_ALREADY = 5,

  /**
   * Asked to stop it, but it's already stopped.
   */
  GNUNET_ARM_RESULT_IS_STOPPED_ALREADY = 6,

  /**
   * Asked to start or stop a service, but it's not known.
   */
  GNUNET_ARM_RESULT_IS_NOT_KNOWN = 7,

  /**
   * Tried to start a service, but that failed for some reason.
   */
  GNUNET_ARM_RESULT_START_FAILED = 8,

  /**
   * Asked to start something, but ARM is shutting down and can't comply.
   */
  GNUNET_ARM_RESULT_IN_SHUTDOWN = 9
};


/**
 * Status of a service managed by ARM.
 */
enum GNUNET_ARM_ServiceStatus
{
  /**
   * Service is stopped.
   */
  GNUNET_ARM_SERVICE_STATUS_STOPPED = 0,

  /**
   * Service has been started and is currently running.
   */
  GNUNET_ARM_SERVICE_STATUS_STARTED = 1,

  /**
   * The service has previously failed, and
   * will be restarted.
   */
  GNUNET_ARM_SERVICE_STATUS_FAILED = 2,

  /**
   * The service was started, but then exited normally.
   */
  GNUNET_ARM_SERVICE_STATUS_FINISHED = 3,
};


/**
 * Information about a service managed by ARM.
 */
struct GNUNET_ARM_ServiceInfo
{
  /**
   * The current status of the service.
   */
  enum GNUNET_ARM_ServiceStatus status;

  /**
   * The name of the service.
   */
  const char *name;

  /**
   * The binary used to execute the service.
   */
  const char *binary;

  /**
   * Time when the sevice will be restarted, if applicable
   * to the current status.
   */
  struct GNUNET_TIME_Absolute restart_at;

  /**
   * Time when the sevice was first started, if applicable.
   */
  struct GNUNET_TIME_Absolute last_started_at;

  /**
   * Last process exit status.
   */
  int last_exit_status;
};


/**
 * Handle for interacting with ARM.
 */
struct GNUNET_ARM_Handle;

/**
 * Handle for an ARM operation.
 */
struct GNUNET_ARM_Operation;


/**
 * Function called whenever we connect to or disconnect from ARM.
 *
 * @param cls closure
 * @param connected #GNUNET_YES if connected, #GNUNET_NO if disconnected,
 *                  #GNUNET_SYSERR if there was an error.
 */
typedef void
(*GNUNET_ARM_ConnectionStatusCallback) (void *cls,
                                        int connected);


/**
 * Function called in response to a start/stop request.
 * Will be called when request was not sent successfully,
 * or when a reply comes. If the request was not sent successfully,
 * @a rs will indicate that, and @a result will be undefined.
 *
 * @param cls closure
 * @param rs status of the request
 * @param result result of the operation
 */
typedef void
(*GNUNET_ARM_ResultCallback) (void *cls,
                              enum GNUNET_ARM_RequestStatus rs,
                              enum GNUNET_ARM_Result result);


/**
 * Callback function invoked when list operation is complete.
 * Will be called when request was not sent successfully,
 * or when a reply comes. If the request was not sent successfully,
 * @a rs will indicate that, and @a count and @a list will be undefined.
 *
 * @param cls closure
 * @param rs status of the request
 * @param count number of strings in the list
 * @param list list of services managed by arm
 */
typedef void
(*GNUNET_ARM_ServiceListCallback) (void *cls,
                                   enum GNUNET_ARM_RequestStatus rs,
                                   unsigned int count,
                                   const struct GNUNET_ARM_ServiceInfo *list);


/**
 * Set up a context for communicating with ARM, then
 * start connecting to the ARM service using that context.
 *
 * @param cfg configuration to use (needed to contact ARM;
 *        the ARM service may internally use a different
 *        configuration to determine how to start the service).
 * @param conn_status will be called when connecting/disconnecting
 * @param conn_status_cls closure for @a conn_status
 * @return context to use for further ARM operations, NULL on error.
 */
struct GNUNET_ARM_Handle *
GNUNET_ARM_connect(const struct GNUNET_CONFIGURATION_Handle *cfg,
                   GNUNET_ARM_ConnectionStatusCallback conn_status,
                   void *conn_status_cls);


/**
 * Disconnect from the ARM service and destroy the handle.
 *
 * @param h the handle that was being used
 */
void
GNUNET_ARM_disconnect(struct GNUNET_ARM_Handle *h);


/**
 * Abort an operation.  Only prevents the callback from being
 * called, the operation may still complete.
 *
 * @param op operation to cancel
 */
void
GNUNET_ARM_operation_cancel(struct GNUNET_ARM_Operation *op);


/**
 * Request a list of running services.
 *
 * @param h handle to ARM
 * @param cont callback to invoke after request is sent or is not sent
 * @param cont_cls closure for @a cont
 * @return handle for the operation, NULL on error
 */
struct GNUNET_ARM_Operation *
GNUNET_ARM_request_service_list(struct GNUNET_ARM_Handle *h,
                                GNUNET_ARM_ServiceListCallback cont,
                                void *cont_cls);


/**
 * Request a service to be stopped.
 * Stopping arm itself will not invalidate its handle, and
 * ARM API will try to restore connection to the ARM service,
 * even if ARM connection was lost because you asked for ARM to be stopped.
 * Call #GNUNET_ARM_disconnect() to free the handle and prevent
 * further connection attempts.
 *
 * @param h handle to ARM
 * @param service_name name of the service
 * @param cont callback to invoke after request is sent or is not sent
 * @param cont_cls closure for @a cont
 * @return handle for the operation, NULL on error
 */
struct GNUNET_ARM_Operation *
GNUNET_ARM_request_service_stop(struct GNUNET_ARM_Handle *h,
                                const char *service_name,
                                GNUNET_ARM_ResultCallback cont,
                                void *cont_cls);


/**
 * Request for a service to be started.
 *
 * @param h handle to ARM
 * @param service_name name of the service
 * @param std_inheritance inheritance of std streams
 * @param cont callback to invoke after request is sent or not sent
 * @param cont_cls closure for @a cont
 * @return handle for the operation, NULL on error
 */
struct GNUNET_ARM_Operation *
GNUNET_ARM_request_service_start(struct GNUNET_ARM_Handle *h,
                                 const char *service_name,
                                 enum GNUNET_OS_InheritStdioFlags std_inheritance,
                                 GNUNET_ARM_ResultCallback cont,
                                 void *cont_cls);


/**
 * Handle for monitoring ARM.
 */
struct GNUNET_ARM_MonitorHandle;


/**
 * Function called in when a status update arrives.
 *
 * @param cls closure
 * @param service service name
 * @param status status of the service
 */
typedef void
(*GNUNET_ARM_ServiceMonitorCallback) (void *cls,
                                     const char *service,
                                     enum GNUNET_ARM_ServiceMonitorStatus status);


/**
 * Setup a context for monitoring ARM, then
 * start connecting to the ARM service for monitoring using that context.
 *
 * @param cfg configuration to use (needed to contact ARM;
 *        the ARM service may internally use a different
 *        configuration to determine how to start the service).
 * @param cont callback to invoke on status updates
 * @param cont_cls closure for @a cont
 * @return context to use for further ARM monitor operations, NULL on error.
 */
struct GNUNET_ARM_MonitorHandle *
GNUNET_ARM_monitor_start(const struct GNUNET_CONFIGURATION_Handle *cfg,
                         GNUNET_ARM_ServiceMonitorCallback cont,
                         void *cont_cls);


/**
 * Disconnect from the ARM service and destroy the handle.
 *
 * @param h the handle that was being used
 */
void
GNUNET_ARM_monitor_stop(struct GNUNET_ARM_MonitorHandle *h);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/** @} */  /* end of group */
