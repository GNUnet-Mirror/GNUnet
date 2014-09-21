/*
     This file is part of GNUnet.
     (C) 2001-2013 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_client_lib.h
 * @brief functions related to accessing services
 * @author Christian Grothoff
 * @defgroup client Generic client-side communication with services
 * @{
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


/**
 * Opaque handle for a connection to a service.
 */
struct GNUNET_CLIENT_Connection;

/**
 * Get a connection with a service.
 *
 * @param service_name name of the service
 * @param cfg configuration to use
 * @return NULL on error (service unknown to configuration)
 */
struct GNUNET_CLIENT_Connection *
GNUNET_CLIENT_connect (const char *service_name,
                       const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Destroy connection with the service.  This will automatically
 * cancel any pending "receive" request (however, the handler will
 * *NOT* be called, not even with a NULL message).  Any pending
 * transmission request will also be cancelled UNLESS the callback for
 * the transmission request has already been called, in which case the
 * transmission 'finish_pending_write' argument determines whether or
 * not the write is guaranteed to complete before the socket is fully
 * destroyed (unless, of course, there is an error with the server in
 * which case the message may still be lost).
 *
 * @param client handle to the service connection
 */
void
GNUNET_CLIENT_disconnect (struct GNUNET_CLIENT_Connection *client);


/**
 * Type of a function to call when we receive a message
 * from the service.
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
typedef void (*GNUNET_CLIENT_MessageHandler) (void *cls,
                                              const struct GNUNET_MessageHeader *msg);


/**
 * Read from the service.
 *
 * @param client connection to the service
 * @param handler function to call with the message
 * @param handler_cls closure for @a handler
 * @param timeout how long to wait until timing out
 */
void
GNUNET_CLIENT_receive (struct GNUNET_CLIENT_Connection *client,
                       GNUNET_CLIENT_MessageHandler handler, void *handler_cls,
                       struct GNUNET_TIME_Relative timeout);


/**
 * Transmit handle for client connections.
 */
struct GNUNET_CLIENT_TransmitHandle;


/**
 * Ask the client to call us once the specified number of bytes
 * are free in the transmission buffer.  Will never call the @a notify
 * callback in this task, but always first go into the scheduler.
 *
 * @param client connection to the service
 * @param size number of bytes to send
 * @param timeout after how long should we give up (and call
 *        @a notify with buf NULL and size 0)?
 * @param auto_retry if the connection to the service dies, should we
 *        automatically re-connect and retry (within the timeout period)
 *        or should we immediately fail in this case?  Pass #GNUNET_YES
 *        if the caller does not care about temporary connection errors,
 *        for example because the protocol is stateless
 * @param notify function to call
 * @param notify_cls closure for @a notify
 * @return NULL if someone else is already waiting to be notified
 *         non-NULL if the notify callback was queued (can be used to cancel
 *         using #GNUNET_CONNECTION_notify_transmit_ready_cancel)
 */
struct GNUNET_CLIENT_TransmitHandle *
GNUNET_CLIENT_notify_transmit_ready (struct GNUNET_CLIENT_Connection *client,
                                     size_t size,
                                     struct GNUNET_TIME_Relative timeout,
                                     int auto_retry,
                                     GNUNET_CONNECTION_TransmitReadyNotify notify,
                                     void *notify_cls);


/**
 * Cancel a request for notification.
 *
 * @param th handle from the original request.
 */
void
GNUNET_CLIENT_notify_transmit_ready_cancel (struct GNUNET_CLIENT_TransmitHandle
                                            *th);


/**
 * Convenience API that combines sending a request
 * to the service and waiting for a response.
 * If either operation times out, the callback
 * will be called with a "NULL" response (in which
 * case the connection should probably be destroyed).
 *
 * @param client connection to use
 * @param hdr message to transmit
 * @param timeout when to give up (for both transmission
 *         and for waiting for a response)
 * @param auto_retry if the connection to the service dies, should we
 *        automatically re-connect and retry (within the timeout period)
 *        or should we immediately fail in this case?  Pass #GNUNET_YES
 *        if the caller does not care about temporary connection errors,
 *        for example because the protocol is stateless
 * @param rn function to call with the response
 * @param rn_cls closure for @a rn
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if a request
 *         is already pending
 */
int
GNUNET_CLIENT_transmit_and_get_response (struct GNUNET_CLIENT_Connection *client,
                                         const struct GNUNET_MessageHeader *hdr,
                                         struct GNUNET_TIME_Relative timeout,
                                         int auto_retry,
                                         GNUNET_CLIENT_MessageHandler rn,
                                         void *rn_cls);


/**
 * Handle for a test to check if a service is running.
 */
struct GNUNET_CLIENT_TestHandle;

/**
 * Function called with the result on the service test.
 *
 * @param cls closure
 * @param result #GNUNET_YES if the service is running,
 *               #GNUNET_NO if the service is not running
 *               #GNUNET_SYSERR if the configuration is invalid
 */
typedef void (*GNUNET_CLIENT_TestResultCallback)(void *cls,
						 int result);


/**
 * Test if the service is running.  If we are given a UNIXPATH or a
 * local address, we do this NOT by trying to connect to the service,
 * but by trying to BIND to the same port.  If the BIND fails, we know
 * the service is running.
 *
 * @param service name of the service to wait for
 * @param cfg configuration to use
 * @param timeout how long to wait at most
 * @param cb function to call with the result
 * @param cb_cls closure for @a cb
 * @return handle to cancel the test
 */
struct GNUNET_CLIENT_TestHandle *
GNUNET_CLIENT_service_test (const char *service,
                            const struct GNUNET_CONFIGURATION_Handle *cfg,
                            struct GNUNET_TIME_Relative timeout,
                            GNUNET_CLIENT_TestResultCallback cb, void *cb_cls);


/**
 * Abort testing for service.
 *
 * @param th test handle
 */
void
GNUNET_CLIENT_service_test_cancel (struct GNUNET_CLIENT_TestHandle *th);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/** @} */ /* end of group client */

/* ifndef GNUNET_CLIENT_LIB_H */
#endif
/* end of gnunet_client_lib.h */
