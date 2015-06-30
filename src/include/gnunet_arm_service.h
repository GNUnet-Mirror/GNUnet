/*
      This file is part of GNUnet
      Copyright (C) 2009 Christian Grothoff (and other contributing authors)

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

#include "gnunet_util_lib.h"

/**
 * Version of the arm API.
 */
#define GNUNET_ARM_VERSION 0x00000002


/**
 * Statuses of the requests that client can send to ARM.
 */
enum GNUNET_ARM_RequestStatus
{
  /**
   * Message was sent successfully.
   */
  GNUNET_ARM_REQUEST_SENT_OK = 0,

  /**
   * Misconfiguration (can't connect to the ARM service).
   */
  GNUNET_ARM_REQUEST_CONFIGURATION_ERROR = 1,

  /**
   * We disconnected from ARM, and request was not sent.
   */
  GNUNET_ARM_REQUEST_DISCONNECTED = 2,

  /**
   * ARM API is busy (probably trying to connect to ARM),
   * and request was not sent. Try again later.
   */
  GNUNET_ARM_REQUEST_BUSY = 3,

  /**
   * It was discovered that the request would be too long to fit in a message,
   * and thus it was not sent.
   */
  GNUNET_ARM_REQUEST_TOO_LONG = 4,

  /**
   * Request time ran out before we had a chance to send it.
   */
  GNUNET_ARM_REQUEST_TIMEOUT = 5

};


/**
 * Statuses of services.
 */
enum GNUNET_ARM_ServiceStatus
{
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
enum GNUNET_ARM_Result
{
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
 * Handle for interacting with ARM.
 */
struct GNUNET_ARM_Handle;


/**
 * Function called whenever we connect to or disconnect from ARM.
 *
 * @param cls closure
 * @param connected GNUNET_YES if connected, GNUNET_NO if disconnected,
 *                  GNUNET_SYSERR if there was an error.
 */
typedef void (*GNUNET_ARM_ConnectionStatusCallback) (void *cls,
						     int connected);


/**
 * Function called in response to a start/stop request.
 * Will be called when request was not sent successfully,
 * or when a reply comes. If the request was not sent successfully,
 * 'rs' will indicate that, and 'service' and 'result' will be undefined.
 *
 * @param cls closure
 * @param rs status of the request
 * @param service service name
 * @param result result of the operation
 */
typedef void (*GNUNET_ARM_ResultCallback) (void *cls,
					   enum GNUNET_ARM_RequestStatus rs,
					   const char *service,
					   enum GNUNET_ARM_Result result);


/**
 * Callback function invoked when list operation is complete.
 * Will be called when request was not sent successfully,
 * or when a reply comes. If the request was not sent successfully,
 * 'rs' will indicate that, and 'count' and 'list' will be undefined.
 *
 * @param cls closure
 * @param rs status of the request
 * @param count number of strings in the list
 * @param list list of running services
 */
typedef void (*GNUNET_ARM_ServiceListCallback) (void *cls,
						enum GNUNET_ARM_RequestStatus rs,
						unsigned int count,
						const char *const*list);


/**
 * Set up a context for communicating with ARM, then
 * start connecting to the ARM service using that context.
 *
 * @param cfg configuration to use (needed to contact ARM;
 *        the ARM service may internally use a different
 *        configuration to determine how to start the service).
 * @param conn_status will be called when connecting/disconnecting
 * @param cls closure for conn_status
 * @return context to use for further ARM operations, NULL on error.
 */
struct GNUNET_ARM_Handle *
GNUNET_ARM_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
		    GNUNET_ARM_ConnectionStatusCallback conn_status,
		    void *cls);


/**
 * Disconnect from the ARM service and destroy the handle.
 *
 * @param h the handle that was being used
 */
void
GNUNET_ARM_disconnect_and_free (struct GNUNET_ARM_Handle *h);


/**
 * Request a list of running services.
 *
 * @param h handle to ARM
 * @param timeout how long to wait before failing for good
 * @param cont callback to invoke after request is sent or is not sent
 * @param cont_cls closure for callback
 */
void
GNUNET_ARM_request_service_list (struct GNUNET_ARM_Handle *h,
				 struct GNUNET_TIME_Relative timeout,
				 GNUNET_ARM_ServiceListCallback cont, void *cont_cls);


/**
 * Request a service to be stopped.
 * Stopping arm itself will not invalidate its handle, and
 * ARM API will try to restore connection to the ARM service,
 * even if ARM connection was lost because you asked for ARM to be stopped.
 * Call GNUNET_ARM_disconnect_and_free () to free the handle and prevent
 * further connection attempts.
 *
 * @param h handle to ARM
 * @param service_name name of the service
 * @param timeout how long to wait before failing for good
 * @param cont callback to invoke after request is sent or is not sent
 * @param cont_cls closure for callback
 */
void
GNUNET_ARM_request_service_stop (struct GNUNET_ARM_Handle *h,
				 const char *service_name,
				 struct GNUNET_TIME_Relative timeout,
				 GNUNET_ARM_ResultCallback cont, void *cont_cls);


/**
 * Request for a service to be started.
 *
 * @param h handle to ARM
 * @param service_name name of the service
 * @param std_inheritance inheritance of std streams
 * @param timeout how long to wait before failing for good
 * @param cont callback to invoke after request is sent or not sent
 * @param cont_cls closure for callback
 */
void
GNUNET_ARM_request_service_start (struct GNUNET_ARM_Handle *h,
				  const char *service_name,
				  enum GNUNET_OS_InheritStdioFlags std_inheritance,
				  struct GNUNET_TIME_Relative timeout,
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
 * @param arm handle to the arm connection
 * @param service service name
 * @param status status of the service
 */
typedef void (*GNUNET_ARM_ServiceStatusCallback) (void *cls,
						  const char *service,
						  enum GNUNET_ARM_ServiceStatus status);


/**
 * Setup a context for monitoring ARM, then
 * start connecting to the ARM service for monitoring using that context.
 *
 * @param cfg configuration to use (needed to contact ARM;
 *        the ARM service may internally use a different
 *        configuration to determine how to start the service).
 * @param cont callback to invoke on status updates
 * @param cont_cls closure
 * @return context to use for further ARM monitor operations, NULL on error.
 */
struct GNUNET_ARM_MonitorHandle *
GNUNET_ARM_monitor (const struct GNUNET_CONFIGURATION_Handle *cfg,
		    GNUNET_ARM_ServiceStatusCallback cont,
		    void *cont_cls);


/**
 * Disconnect from the ARM service and destroy the handle.
 *
 * @param h the handle that was being used
 */
void
GNUNET_ARM_monitor_disconnect_and_free (struct GNUNET_ARM_MonitorHandle *h);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
