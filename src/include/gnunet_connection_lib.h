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
 * @file include/gnunet_connection_lib.h
 * @brief basic, low-level TCP networking interface
 * @author Christian Grothoff
 */
#ifndef GNUNET_CONNECTION_LIB_H
#define GNUNET_CONNECTION_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_network_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_time_lib.h"

/**
 * Timeout we use on TCP connect before trying another
 * result from the DNS resolver.  Actual value used
 * is this value divided by the number of address families.
 * Default is 5s.
 */
#define GNUNET_CONNECTION_CONNECT_RETRY_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * @brief handle for a network connection
 */
struct GNUNET_CONNECTION_Handle;


/**
 * Credentials for UNIX domain sockets.
 */
struct GNUNET_CONNECTION_Credentials
{
  /**
   * UID of the other end of the connection.
   */
  uid_t uid;

  /**
   * GID of the other end of the connection.
   */
  gid_t gid;
};


/**
 * Function to call for access control checks.
 *
 * @param cls closure
 * @param ucred credentials, if available, otherwise NULL
 * @param addr address
 * @param addrlen length of address
 * @return GNUNET_YES to allow, GNUNET_NO to deny, GNUNET_SYSERR
 *   for unknown address family (will be denied).
 */
typedef int (*GNUNET_CONNECTION_AccessCheck) (void *cls,
                                              const struct
                                              GNUNET_CONNECTION_Credentials *
                                              ucred,
                                              const struct sockaddr * addr,
                                              socklen_t addrlen);


/**
 * Callback function for data received from the network.  Note that
 * both "available" and "err" would be 0 if the read simply timed out.
 *
 * @param cls closure
 * @param buf pointer to received data
 * @param available number of bytes availabe in "buf",
 *        possibly 0 (on errors)
 * @param addr address of the sender
 * @param addrlen size of addr
 * @param errCode value of errno (on errors receiving)
 */
typedef void (*GNUNET_CONNECTION_Receiver) (void *cls, const void *buf,
                                            size_t available,
                                            const struct sockaddr * addr,
                                            socklen_t addrlen, int errCode);

/**
 * Set the persist option on this connection handle.  Indicates
 * that the underlying socket or fd should never really be closed.
 * Used for indicating process death.
 *
 * @param connection the connection to set persistent
 */
void
GNUNET_CONNECTION_persist_ (struct GNUNET_CONNECTION_Handle *connection);

/**
 * Disable the "CORK" feature for communication with the given socket,
 * forcing the OS to immediately flush the buffer on transmission
 * instead of potentially buffering multiple messages.  Essentially
 * reduces the OS send buffers to zero.
 * Used to make sure that the last messages sent through the connection
 * reach the other side before the process is terminated.
 *
 * @param connection the connection to make flushing and blocking
 * @return GNUNET_OK on success
 */
int
GNUNET_CONNECTION_disable_corking (struct GNUNET_CONNECTION_Handle *connection);


/**
 * Create a connection handle by boxing an existing OS socket.  The OS
 * socket should henceforth be no longer used directly.
 * GNUNET_CONNECTION_destroy will close it.
 *
 * @param osSocket existing socket to box
 * @return the boxed socket handle
 */
struct GNUNET_CONNECTION_Handle *
GNUNET_CONNECTION_create_from_existing (struct GNUNET_NETWORK_Handle *osSocket);


/**
 * Create a connection handle by accepting on a listen socket.  This
 * function may block if the listen socket has no connection ready.
 *
 * @param access function to use to check if access is allowed
 * @param access_cls closure for access
 * @param lsock listen socket
 * @return the connection handle, NULL on error (for example, access refused)
 */
struct GNUNET_CONNECTION_Handle *
GNUNET_CONNECTION_create_from_accept (GNUNET_CONNECTION_AccessCheck access,
                                      void *access_cls,
                                      struct GNUNET_NETWORK_Handle *lsock);


/**
 * Create a connection handle by (asynchronously) connecting to a host.
 * This function returns immediately, even if the connection has not
 * yet been established.  This function only creates TCP connections.
 *
 * @param cfg configuration to use
 * @param hostname name of the host to connect to
 * @param port port to connect to
 * @return the connection handle
 */
struct GNUNET_CONNECTION_Handle *
GNUNET_CONNECTION_create_from_connect (const struct GNUNET_CONFIGURATION_Handle
                                       *cfg, const char *hostname,
                                       uint16_t port);


/**
 * Create a connection handle by connecting to a UNIX domain service.
 * This function returns immediately, even if the connection has not
 * yet been established.  This function only creates UNIX connections.
 *
 * @param cfg configuration to use
 * @param unixpath path to connect to)
 * @return the connection handle, NULL on systems without UNIX support
 */
struct GNUNET_CONNECTION_Handle *
GNUNET_CONNECTION_create_from_connect_to_unixpath (const struct
                                                   GNUNET_CONFIGURATION_Handle
                                                   *cfg, const char *unixpath);




/**
 * Create a connection handle by (asynchronously) connecting to a host.
 * This function returns immediately, even if the connection has not
 * yet been established.  This function only creates TCP connections.
 *
 * @param af_family address family to use
 * @param serv_addr server address
 * @param addrlen length of server address
 * @return the connection handle
 */
struct GNUNET_CONNECTION_Handle *
GNUNET_CONNECTION_create_from_sockaddr (int af_family,
                                        const struct sockaddr *serv_addr,
                                        socklen_t addrlen);

/**
 * Check if connection is valid (no fatal errors have happened so far).
 * Note that a connection that is still trying to connect is considered
 * valid.
 *
 * @param connection handle to check
 * @return GNUNET_YES if valid, GNUNET_NO otherwise
 */
int
GNUNET_CONNECTION_check (struct GNUNET_CONNECTION_Handle *connection);


/**
 * Obtain the network address of the other party.
 *
 * @param connection the client to get the address for
 * @param addr where to store the address
 * @param addrlen where to store the length of the address
 * @return GNUNET_OK on success
 */
int
GNUNET_CONNECTION_get_address (struct GNUNET_CONNECTION_Handle *connection,
                               void **addr, size_t * addrlen);


/**
 * Close the connection and free associated resources.  There must
 * not be any pending requests for reading or writing to the
 * connection at this time.
 *
 * @param connection connection to destroy
 */
void
GNUNET_CONNECTION_destroy (struct GNUNET_CONNECTION_Handle *connection);


/**
 * Receive data from the given connection.  Note that this function will
 * call "receiver" asynchronously using the scheduler.  It will
 * "immediately" return.  Note that there MUST only be one active
 * receive call per connection at any given point in time (so do not
 * call receive again until the receiver callback has been invoked).
 *
 * @param connection connection handle
 * @param max maximum number of bytes to read
 * @param timeout maximum amount of time to wait
 * @param receiver function to call with received data
 * @param receiver_cls closure for receiver
 */
void
GNUNET_CONNECTION_receive (struct GNUNET_CONNECTION_Handle *connection, size_t max,
                           struct GNUNET_TIME_Relative timeout,
                           GNUNET_CONNECTION_Receiver receiver,
                           void *receiver_cls);


/**
 * Cancel receive job on the given connection.  Note that the
 * receiver callback must not have been called yet in order
 * for the cancellation to be valid.
 *
 * @param connection connection handle
 * @return closure of the original receiver callback closure
 */
void *
GNUNET_CONNECTION_receive_cancel (struct GNUNET_CONNECTION_Handle *connection);


/**
 * Function called to notify a client about the connection
 * begin ready to queue more data.  "buf" will be
 * NULL and "size" zero if the connection was closed for
 * writing in the meantime.
 *
 * @param cls closure
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
typedef size_t (*GNUNET_CONNECTION_TransmitReadyNotify) (void *cls, size_t size,
                                                         void *buf);


/**
 * Opaque handle that can be used to cancel
 * a transmit-ready notification.
 */
struct GNUNET_CONNECTION_TransmitHandle;

/**
 * Ask the connection to call us once the specified number of bytes
 * are free in the transmission buffer.  May call the notify
 * method immediately if enough space is available.  Note that
 * this function will abort if "size" is greater than
 * GNUNET_SERVER_MAX_MESSAGE_SIZE.
 *
 * Note that "notify" will be called either when enough
 * buffer space is available OR when the connection is destroyed.
 * The size parameter given to notify is guaranteed to be
 * larger or equal to size if the buffer is ready, or zero
 * if the connection was destroyed (or at least closed for
 * writing).  Finally, any time before 'notify' is called, a
 * client may call "notify_transmit_ready_cancel" to cancel
 * the transmission request.
 *
 * Only one transmission request can be scheduled at the same
 * time.  Notify will be run with the same scheduler priority
 * as that of the caller.
 *
 * @param connection connection
 * @param size number of bytes to send
 * @param timeout after how long should we give up (and call
 *        notify with buf NULL and size 0)?
 * @param notify function to call when buffer space is available
 * @param notify_cls closure for notify
 * @return non-NULL if the notify callback was queued,
 *         NULL if we are already going to notify someone else (busy)
 */
struct GNUNET_CONNECTION_TransmitHandle *
GNUNET_CONNECTION_notify_transmit_ready (struct GNUNET_CONNECTION_Handle *connection,
                                         size_t size,
                                         struct GNUNET_TIME_Relative timeout,
                                         GNUNET_CONNECTION_TransmitReadyNotify
                                         notify, void *notify_cls);


/**
 * Cancel the specified transmission-ready
 * notification.
 *
 * @param th handle for notification to cancel
 */
void
GNUNET_CONNECTION_notify_transmit_ready_cancel (struct
                                                GNUNET_CONNECTION_TransmitHandle
                                                *th);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_CONNECTION_LIB_H */
#endif
/* end of gnunet_connection_lib.h */
