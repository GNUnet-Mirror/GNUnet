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
 * Function to call for access control checks.
 *
 * @param cls closure
 * @param addr address
 * @param addrlen length of address
 * @return GNUNET_YES to allow, GNUNET_NO to deny, GNUNET_SYSERR
 *   for unknown address family (will be denied).
 */
typedef int (*GNUNET_CONNECTION_AccessCheck) (void *cls,
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
typedef void (*GNUNET_CONNECTION_Receiver) (void *cls,
                                         const void *buf,
                                         size_t available,
                                         const struct sockaddr * addr,
                                         socklen_t addrlen, int errCode);


/**
 * Create a socket handle by boxing an existing OS socket.  The OS
 * socket should henceforth be no longer used directly.
 * GNUNET_socket_destroy will close it.
 *
 * @param sched scheduler to use
 * @param osSocket existing socket to box
 * @param maxbuf maximum write buffer size for the socket (use
 *        0 for sockets that need no write buffers, such as listen sockets)
 * @return the boxed socket handle
 */
struct GNUNET_CONNECTION_Handle
  *GNUNET_CONNECTION_create_from_existing (struct
                                                   GNUNET_SCHEDULER_Handle
                                                   *sched,
                                                   struct
                                                   GNUNET_NETWORK_Handle
                                                   *osSocket, size_t maxbuf);


/**
 * Create a socket handle by accepting on a listen socket.  This
 * function may block if the listen socket has no connection ready.
 *
 * @param sched scheduler to use
 * @param access function to use to check if access is allowed
 * @param access_cls closure for access
 * @param lsock listen socket
 * @param maxbuf maximum write buffer size for the socket (use
 *        0 for sockets that need no write buffers, such as listen sockets)
 * @return the socket handle, NULL on error (for example, access refused)
 */
struct GNUNET_CONNECTION_Handle
  *GNUNET_CONNECTION_create_from_accept (struct
                                                 GNUNET_SCHEDULER_Handle
                                                 *sched,
                                                 GNUNET_CONNECTION_AccessCheck
                                                 access, void *access_cls,
                                                 struct
                                                 GNUNET_NETWORK_Handle
                                                 *lsock, size_t maxbuf);


/**
 * Create a socket handle by (asynchronously) connecting to a host.
 * This function returns immediately, even if the connection has not
 * yet been established.  This function only creates TCP connections.
 *
 * @param sched scheduler to use
 * @param cfg configuration to use
 * @param hostname name of the host to connect to
 * @param port port to connect to
 * @param maxbuf maximum write buffer size for the socket (use
 *        0 for sockets that need no write buffers, such as listen sockets)
 * @return the socket handle
 */
struct GNUNET_CONNECTION_Handle
  *GNUNET_CONNECTION_create_from_connect (struct GNUNET_SCHEDULER_Handle *sched,
					  const struct GNUNET_CONFIGURATION_Handle *cfg,
					  const char *hostname,
					  uint16_t port,
					  size_t maxbuf);



/**
 * Create a socket handle by (asynchronously) connecting to a host.
 * This function returns immediately, even if the connection has not
 * yet been established.  This function only creates TCP connections.
 *
 * @param sched scheduler to use
 * @param af_family address family to use
 * @param serv_addr server address
 * @param addrlen length of server address
 * @param maxbuf maximum write buffer size for the socket (use
 *        0 for sockets that need no write buffers, such as listen sockets)
 * @return the socket handle
 */
struct GNUNET_CONNECTION_Handle
  *GNUNET_CONNECTION_create_from_sockaddr (struct
                                                   GNUNET_SCHEDULER_Handle
                                                   *sched, int af_family,
                                                   const struct sockaddr
                                                   *serv_addr,
                                                   socklen_t addrlen,
                                                   size_t maxbuf);

/**
 * Check if socket is valid (no fatal errors have happened so far).
 * Note that a socket that is still trying to connect is considered
 * valid.
 *
 * @param sock socket to check
 * @return GNUNET_YES if valid, GNUNET_NO otherwise
 */
int GNUNET_CONNECTION_check (struct GNUNET_CONNECTION_Handle
                                     *sock);


/**
 * Obtain the network address of the other party.
 *
 * @param sock the client to get the address for
 * @param addr where to store the address
 * @param addrlen where to store the length of the address
 * @return GNUNET_OK on success
 */
int GNUNET_CONNECTION_get_address (struct
                                           GNUNET_CONNECTION_Handle
                                           *sock, void **addr,
                                           size_t * addrlen);

/**
 * Close the socket and free associated resources.  Pending
 * transmissions are simply dropped.  A pending receive call will be
 * called with an error code of "EPIPE".
 *
 * @param sock socket to destroy
 */
void GNUNET_CONNECTION_destroy (struct GNUNET_CONNECTION_Handle
                                        *sock);


/**
 * Receive data from the given socket.  Note that this function will
 * call "receiver" asynchronously using the scheduler.  It will
 * "immediately" return.  Note that there MUST only be one active
 * receive call per socket at any given point in time (so do not
 * call receive again until the receiver callback has been invoked).
 *
 * @param sock socket handle
 * @param max maximum number of bytes to read
 * @param timeout maximum amount of time to wait
 * @param receiver function to call with received data
 * @param receiver_cls closure for receiver
 */
void
GNUNET_CONNECTION_receive (struct GNUNET_CONNECTION_Handle
                                   *sock, size_t max,
                                   struct GNUNET_TIME_Relative timeout,
                                   GNUNET_CONNECTION_Receiver receiver,
                                   void *receiver_cls);


/**
 * Cancel receive job on the given socket.  Note that the
 * receiver callback must not have been called yet in order
 * for the cancellation to be valid.
 *
 * @param sock socket handle
 * @return closure of the original receiver callback closure
 */
void *GNUNET_CONNECTION_receive_cancel (struct
					GNUNET_CONNECTION_Handle
					*sock);


/**
 * Function called to notify a client about the socket
 * begin ready to queue more data.  "buf" will be
 * NULL and "size" zero if the socket was closed for
 * writing in the meantime.
 *
 * @param cls closure
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
typedef size_t (*GNUNET_CONNECTION_TransmitReadyNotify) (void *cls,
                                                      size_t size, void *buf);


/**
 * Opaque handle that can be used to cancel
 * a transmit-ready notification.
 */
struct GNUNET_CONNECTION_TransmitHandle;

/**
 * Ask the socket to call us once the specified number of bytes
 * are free in the transmission buffer.  May call the notify
 * method immediately if enough space is available.  Note that
 * this function will abort if "size" is greater than
 * "maxbuf" (as specified when the socket handle was created).
 *
 * Note that "notify" will be called either when enough
 * buffer space is available OR when the socket is destroyed.
 * The size parameter given to notify is guaranteed to be
 * larger or equal to size if the buffer is ready, or zero
 * if the socket was destroyed (or at least closed for
 * writing).  Finally, any time before 'notify' is called, a
 * client may call "notify_transmit_ready_cancel" to cancel
 * the transmission request.
 *
 * Only one transmission request can be scheduled at the same
 * time.  Notify will be run with the same scheduler priority
 * as that of the caller.
 *
 * @param sock socket
 * @param size number of bytes to send
 * @param timeout after how long should we give up (and call
 *        notify with buf NULL and size 0)?
 * @param notify function to call when buffer space is available
 * @param notify_cls closure for notify
 * @return non-NULL if the notify callback was queued,
 *         NULL if we are already going to notify someone else (busy)
 */
struct GNUNET_CONNECTION_TransmitHandle
  *GNUNET_CONNECTION_notify_transmit_ready (struct
                                                    GNUNET_CONNECTION_Handle
                                                    *sock, size_t size,
                                                    struct
                                                    GNUNET_TIME_Relative
                                                    timeout,
                                                    GNUNET_CONNECTION_TransmitReadyNotify
                                                    notify, void *notify_cls);


/**
 * Cancel the specified transmission-ready
 * notification.
 *
 * @param h handle for notification to cancel
 */
void
GNUNET_CONNECTION_notify_transmit_ready_cancel (struct
                                                        GNUNET_CONNECTION_TransmitHandle
                                                        *h);


/**
 * Configure this connection to ignore shutdown signals.
 *
 * @param sock socket handle
 * @param do_ignore GNUNET_YES to ignore, GNUNET_NO to restore default
 */
void
GNUNET_CONNECTION_ignore_shutdown (struct GNUNET_CONNECTION_Handle *sock,
				   int do_ignore);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_CONNECTION_LIB_H */
#endif
/* end of gnunet_connection_lib.h */
