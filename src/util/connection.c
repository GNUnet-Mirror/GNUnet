/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013 GNUnet e.V.

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
 * @file util/connection.c
 * @brief  TCP connection management
 * @author Christian Grothoff
 *
 * This code is rather complex.  Only modify it if you
 * 1) Have a NEW testcase showing that the new code
 *    is needed and correct
 * 2) All EXISTING testcases pass with the new code
 * These rules should apply in general, but for this
 * module they are VERY, VERY important.
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_resolver_service.h"


#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

#define LOG_STRERROR(kind,syscall) GNUNET_log_from_strerror (kind, "util", syscall)


/**
 * Transmission handle.  There can only be one for each connection.
 */
struct GNUNET_CONNECTION_TransmitHandle
{

  /**
   * Function to call if the send buffer has notify_size
   * bytes available.
   */
  GNUNET_CONNECTION_TransmitReadyNotify notify_ready;

  /**
   * Closure for notify_ready.
   */
  void *notify_ready_cls;

  /**
   * Our connection handle.
   */
  struct GNUNET_CONNECTION_Handle *connection;

  /**
   * Timeout for receiving (in absolute time).
   */
  struct GNUNET_TIME_Absolute transmit_timeout;

  /**
   * Task called on timeout.
   */
  struct GNUNET_SCHEDULER_Task * timeout_task;

  /**
   * At what number of bytes available in the
   * write buffer should the notify method be called?
   */
  size_t notify_size;

};


/**
 * During connect, we try multiple possible IP addresses
 * to find out which one might work.
 */
struct AddressProbe
{

  /**
   * This is a linked list.
   */
  struct AddressProbe *next;

  /**
   * This is a doubly-linked list.
   */
  struct AddressProbe *prev;

  /**
   * The address; do not free (allocated at the end of this struct).
   */
  const struct sockaddr *addr;

  /**
   * Underlying OS's socket.
   */
  struct GNUNET_NETWORK_Handle *sock;

  /**
   * Connection for which we are probing.
   */
  struct GNUNET_CONNECTION_Handle *connection;

  /**
   * Lenth of addr.
   */
  socklen_t addrlen;

  /**
   * Task waiting for the connection to finish connecting.
   */
  struct GNUNET_SCHEDULER_Task * task;
};


/**
 * @brief handle for a network connection
 */
struct GNUNET_CONNECTION_Handle
{

  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Linked list of sockets we are currently trying out
   * (during connect).
   */
  struct AddressProbe *ap_head;

  /**
   * Linked list of sockets we are currently trying out
   * (during connect).
   */
  struct AddressProbe *ap_tail;

  /**
   * Network address of the other end-point, may be NULL.
   */
  struct sockaddr *addr;

  /**
   * Pointer to the hostname if connection was
   * created using DNS lookup, otherwise NULL.
   */
  char *hostname;

  /**
   * Underlying OS's socket, set to NULL after fatal errors.
   */
  struct GNUNET_NETWORK_Handle *sock;

  /**
   * Function to call on data received, NULL if no receive is pending.
   */
  GNUNET_CONNECTION_Receiver receiver;

  /**
   * Closure for @e receiver.
   */
  void *receiver_cls;

  /**
   * Pointer to our write buffer.
   */
  char *write_buffer;

  /**
   * Current size of our @e write_buffer.
   */
  size_t write_buffer_size;

  /**
   * Current write-offset in @e write_buffer (where
   * would we write next).
   */
  size_t write_buffer_off;

  /**
   * Current read-offset in @e write_buffer (how many
   * bytes have already been sent).
   */
  size_t write_buffer_pos;

  /**
   * Length of @e addr.
   */
  socklen_t addrlen;

  /**
   * Read task that we may need to wait for.
   */
  struct GNUNET_SCHEDULER_Task *read_task;

  /**
   * Write task that we may need to wait for.
   */
  struct GNUNET_SCHEDULER_Task *write_task;

  /**
   * Handle to a pending DNS lookup request.
   */
  struct GNUNET_RESOLVER_RequestHandle *dns_active;

  /**
   * The handle we return for GNUNET_CONNECTION_notify_transmit_ready.
   */
  struct GNUNET_CONNECTION_TransmitHandle nth;

  /**
   * Timeout for receiving (in absolute time).
   */
  struct GNUNET_TIME_Absolute receive_timeout;

  /**
   * Maximum number of bytes to read (for receiving).
   */
  size_t max;

  /**
   * Port to connect to.
   */
  uint16_t port;

  /**
   * When shutdown, do not ever actually close the socket, but
   * free resources.  Only should ever be set if using program
   * termination as a signal (because only then will the leaked
   * socket be freed!)
   */
  int8_t persist;

  /**
   * Usually 0.  Set to 1 if this handle is in use, and should
   * #GNUNET_CONNECTION_destroy() be called right now, the action needs
   * to be deferred by setting it to -1.
   */
  int8_t destroy_later;

  /**
   * Handle to subsequent connection after proxy handshake completes,
   */
  struct GNUNET_CONNECTION_Handle *proxy_handshake;

};


/**
 * Set the persist option on this connection handle.  Indicates
 * that the underlying socket or fd should never really be closed.
 * Used for indicating process death.
 *
 * @param connection the connection to set persistent
 */
void
GNUNET_CONNECTION_persist_ (struct GNUNET_CONNECTION_Handle *connection)
{
  connection->persist = GNUNET_YES;
}


/**
 * Disable the "CORK" feature for communication with the given connection,
 * forcing the OS to immediately flush the buffer on transmission
 * instead of potentially buffering multiple messages.  Essentially
 * reduces the OS send buffers to zero.
 * Used to make sure that the last messages sent through the connection
 * reach the other side before the process is terminated.
 *
 * @param connection the connection to make flushing and blocking
 * @return #GNUNET_OK on success
 */
int
GNUNET_CONNECTION_disable_corking (struct GNUNET_CONNECTION_Handle *connection)
{
  return GNUNET_NETWORK_socket_disable_corking (connection->sock);
}


/**
 * Create a connection handle by boxing an existing OS socket.  The OS
 * socket should henceforth be no longer used directly.
 * #GNUNET_connection_destroy() will close it.
 *
 * @param osSocket existing socket to box
 * @return the boxed connection handle
 */
struct GNUNET_CONNECTION_Handle *
GNUNET_CONNECTION_create_from_existing (struct GNUNET_NETWORK_Handle *osSocket)
{
  struct GNUNET_CONNECTION_Handle *connection;

  connection = GNUNET_new (struct GNUNET_CONNECTION_Handle);
  connection->write_buffer_size = GNUNET_SERVER_MIN_BUFFER_SIZE;
  connection->write_buffer = GNUNET_malloc (connection->write_buffer_size);
  connection->sock = osSocket;
  return connection;
}


/**
 * Create a connection handle by accepting on a listen socket.  This
 * function may block if the listen socket has no connection ready.
 *
 * @param access_cb function to use to check if access is allowed
 * @param access_cb_cls closure for @a access_cb
 * @param lsock listen socket
 * @return the connection handle, NULL on error
 */
struct GNUNET_CONNECTION_Handle *
GNUNET_CONNECTION_create_from_accept (GNUNET_CONNECTION_AccessCheck access_cb,
                                      void *access_cb_cls,
                                      struct GNUNET_NETWORK_Handle *lsock)
{
  struct GNUNET_CONNECTION_Handle *connection;
  char addr[128];
  socklen_t addrlen;
  struct GNUNET_NETWORK_Handle *sock;
  int aret;
  struct sockaddr_in *v4;
  struct sockaddr_in6 *v6;
  struct sockaddr *sa;
  void *uaddr;
  struct GNUNET_CONNECTION_Credentials *gcp;
  struct GNUNET_CONNECTION_Credentials gc;
#ifdef SO_PEERCRED
  struct ucred uc;
  socklen_t olen;
#endif

  addrlen = sizeof (addr);
  sock =
      GNUNET_NETWORK_socket_accept (lsock, (struct sockaddr *) &addr, &addrlen);
  if (NULL == sock)
  {
    if (EAGAIN != errno)
      LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "accept");
    return NULL;
  }
  if ((addrlen > sizeof (addr)) || (addrlen < sizeof (sa_family_t)))
  {
    GNUNET_break (0);
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (sock));
    return NULL;
  }

  sa = (struct sockaddr *) addr;
  v6 = (struct sockaddr_in6 *) addr;
  if ((AF_INET6 == sa->sa_family) && (IN6_IS_ADDR_V4MAPPED (&v6->sin6_addr)))
  {
    /* convert to V4 address */
    v4 = GNUNET_new (struct sockaddr_in);
    memset (v4, 0, sizeof (struct sockaddr_in));
    v4->sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
    v4->sin_len = (u_char) sizeof (struct sockaddr_in);
#endif
    memcpy (&v4->sin_addr,
            &((char *) &v6->sin6_addr)[sizeof (struct in6_addr) -
                                       sizeof (struct in_addr)],
            sizeof (struct in_addr));
    v4->sin_port = v6->sin6_port;
    uaddr = v4;
    addrlen = sizeof (struct sockaddr_in);
  }
  else
  {
    uaddr = GNUNET_malloc (addrlen);
    memcpy (uaddr, addr, addrlen);
  }
  gcp = NULL;
  gc.uid = 0;
  gc.gid = 0;
  if (AF_UNIX == sa->sa_family)
  {
#if HAVE_GETPEEREID
    /* most BSDs */
    if (0 == getpeereid (GNUNET_NETWORK_get_fd (sock), &gc.uid, &gc.gid))
      gcp = &gc;
#else
#ifdef SO_PEERCRED
    /* largely traditional GNU/Linux */
    olen = sizeof (uc);
    if ((0 ==
         getsockopt (GNUNET_NETWORK_get_fd (sock), SOL_SOCKET, SO_PEERCRED, &uc,
                     &olen)) && (olen == sizeof (uc)))
    {
      gc.uid = uc.uid;
      gc.gid = uc.gid;
      gcp = &gc;
    }
#else
#if HAVE_GETPEERUCRED
    /* this is for Solaris 10 */
    ucred_t *uc;

    uc = NULL;
    if (0 == getpeerucred (GNUNET_NETWORK_get_fd (sock), &uc))
    {
      gc.uid = ucred_geteuid (uc);
      gc.gid = ucred_getegid (uc);
      gcp = &gc;
    }
    ucred_free (uc);
#endif
#endif
#endif
  }

  if ((NULL != access_cb) &&
      (GNUNET_YES != (aret = access_cb (access_cb_cls, gcp, uaddr, addrlen))))
  {
    if (GNUNET_NO == aret)
      LOG (GNUNET_ERROR_TYPE_INFO,
           _("Access denied to `%s'\n"),
           GNUNET_a2s (uaddr,
                       addrlen));
    GNUNET_break (GNUNET_OK ==
                  GNUNET_NETWORK_socket_shutdown (sock,
                                                  SHUT_RDWR));
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (sock));
    GNUNET_free (uaddr);
    return NULL;
  }
  connection = GNUNET_new (struct GNUNET_CONNECTION_Handle);
  connection->write_buffer_size = GNUNET_SERVER_MIN_BUFFER_SIZE;
  connection->write_buffer = GNUNET_malloc (connection->write_buffer_size);
  connection->addr = uaddr;
  connection->addrlen = addrlen;
  connection->sock = sock;
  LOG (GNUNET_ERROR_TYPE_INFO,
       _("Accepting connection from `%s': %p\n"),
       GNUNET_a2s (uaddr, addrlen), connection);
  return connection;
}


/**
 * Obtain the network address of the other party.
 *
 * @param connection the client to get the address for
 * @param addr where to store the address
 * @param addrlen where to store the length of the @a addr
 * @return #GNUNET_OK on success
 */
int
GNUNET_CONNECTION_get_address (struct GNUNET_CONNECTION_Handle *connection,
                               void **addr,
                               size_t *addrlen)
{
  if ((NULL == connection->addr) || (0 == connection->addrlen))
    return GNUNET_NO;
  *addr = GNUNET_malloc (connection->addrlen);
  memcpy (*addr, connection->addr, connection->addrlen);
  *addrlen = connection->addrlen;
  return GNUNET_OK;
}


/**
 * Tell the receiver callback that we had an IO error.
 *
 * @param connection connection to signal error
 * @param errcode error code to send
 */
static void
signal_receive_error (struct GNUNET_CONNECTION_Handle *connection,
                      int errcode)
{
  GNUNET_CONNECTION_Receiver receiver;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Receive encounters error (%s), connection closed (%p)\n",
       STRERROR (errcode),
       connection);
  GNUNET_assert (NULL != (receiver = connection->receiver));
  connection->receiver = NULL;
  receiver (connection->receiver_cls,
            NULL,
            0,
            connection->addr,
            connection->addrlen,
            errcode);
}


/**
 * Tell the receiver callback that a timeout was reached.
 *
 * @param connection connection to signal for
 */
static void
signal_receive_timeout (struct GNUNET_CONNECTION_Handle *connection)
{
  GNUNET_CONNECTION_Receiver receiver;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connection signals timeout to receiver (%p)!\n",
       connection);
  GNUNET_assert (NULL != (receiver = connection->receiver));
  connection->receiver = NULL;
  receiver (connection->receiver_cls, NULL, 0, NULL, 0, 0);
}


/**
 * We failed to transmit data to the service, signal the error.
 *
 * @param connection handle that had trouble
 * @param ecode error code (errno)
 */
static void
signal_transmit_error (struct GNUNET_CONNECTION_Handle *connection,
		       int ecode)
{
  GNUNET_CONNECTION_TransmitReadyNotify notify;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Transmission encounterd error (%s), connection closed (%p)\n",
       STRERROR (ecode),
       connection);
  if (NULL != connection->sock)
  {
    (void) GNUNET_NETWORK_socket_shutdown (connection->sock,
                                           SHUT_RDWR);
    GNUNET_break (GNUNET_OK ==
                  GNUNET_NETWORK_socket_close (connection->sock));
    connection->sock = NULL;
    GNUNET_assert (NULL == connection->write_task);
  }
  if (NULL != connection->read_task)
  {
    /* send errors trigger read errors... */
    GNUNET_SCHEDULER_cancel (connection->read_task);
    connection->read_task = NULL;
    signal_receive_timeout (connection);
    return;
  }
  if (NULL == connection->nth.notify_ready)
    return;                     /* nobody to tell about it */
  notify = connection->nth.notify_ready;
  connection->nth.notify_ready = NULL;
  notify (connection->nth.notify_ready_cls, 0, NULL);
}


/**
 * We've failed for good to establish a connection (timeout or
 * no more addresses to try).
 *
 * @param connection the connection we tried to establish
 */
static void
connect_fail_continuation (struct GNUNET_CONNECTION_Handle *connection)
{
  LOG (GNUNET_ERROR_TYPE_INFO,
       "Failed to establish TCP connection to `%s:%u', no further addresses to try.\n",
       connection->hostname,
    connection->port);
  GNUNET_break (NULL == connection->ap_head);
  GNUNET_break (NULL == connection->ap_tail);
  GNUNET_break (GNUNET_NO == connection->dns_active);
  GNUNET_break (NULL == connection->sock);
  GNUNET_assert (NULL == connection->write_task);
  GNUNET_assert (NULL == connection->proxy_handshake);

  /* signal errors for jobs that used to wait on the connection */
  connection->destroy_later = 1;
  if (NULL != connection->receiver)
    signal_receive_error (connection,
                          ECONNREFUSED);
  if (NULL != connection->nth.notify_ready)
  {
    GNUNET_assert (NULL != connection->nth.timeout_task);
    GNUNET_SCHEDULER_cancel (connection->nth.timeout_task);
    connection->nth.timeout_task = NULL;
    signal_transmit_error (connection,
                           ECONNREFUSED);
  }
  if (-1 == connection->destroy_later)
  {
    /* do it now */
    connection->destroy_later = 0;
    GNUNET_CONNECTION_destroy (connection);
    return;
  }
  connection->destroy_later = 0;
}


/**
 * We are ready to transmit (or got a timeout).
 *
 * @param cls our connection handle
 * @param tc task context describing why we are here
 */
static void
transmit_ready (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * This function is called once we either timeout or have data ready
 * to read.
 *
 * @param cls connection to read from
 * @param tc scheduler context
 */
static void
receive_ready (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * We've succeeded in establishing a connection.
 *
 * @param connection the connection we tried to establish
 */
static void
connect_success_continuation (struct GNUNET_CONNECTION_Handle *connection)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connection to `%s' succeeded! (%p)\n",
       GNUNET_a2s (connection->addr, connection->addrlen),
       connection);
  /* trigger jobs that waited for the connection */
  if (NULL != connection->receiver)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Connection succeeded, starting with receiving data (%p)\n",
	 connection);
    GNUNET_assert (NULL == connection->read_task);
    connection->read_task =
      GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_absolute_get_remaining
                                     (connection->receive_timeout), connection->sock,
                                     &receive_ready, connection);
  }
  if (NULL != connection->nth.notify_ready)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Connection succeeded, starting with sending data (%p)\n",
         connection);
    GNUNET_assert (connection->nth.timeout_task != NULL);
    GNUNET_SCHEDULER_cancel (connection->nth.timeout_task);
    connection->nth.timeout_task = NULL;
    GNUNET_assert (connection->write_task == NULL);
    connection->write_task =
        GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_absolute_get_remaining
                                        (connection->nth.transmit_timeout), connection->sock,
                                        &transmit_ready, connection);
  }
}


/**
 * Scheduler let us know that we're either ready to write on the
 * socket OR connect timed out.  Do the right thing.
 *
 * @param cls the "struct AddressProbe*" with the address that we are probing
 * @param tc success or failure info about the connect attempt.
 */
static void
connect_probe_continuation (void *cls,
                            const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct AddressProbe *ap = cls;
  struct GNUNET_CONNECTION_Handle *connection = ap->connection;
  struct AddressProbe *pos;
  int error;
  socklen_t len;

  GNUNET_assert (NULL != ap->sock);
  GNUNET_CONTAINER_DLL_remove (connection->ap_head, connection->ap_tail, ap);
  len = sizeof (error);
  errno = 0;
  error = 0;
  if ((0 == (tc->reason & GNUNET_SCHEDULER_REASON_WRITE_READY)) ||
      (GNUNET_OK !=
       GNUNET_NETWORK_socket_getsockopt (ap->sock, SOL_SOCKET, SO_ERROR, &error,
                                         &len)) || (0 != error))
  {
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (ap->sock));
    GNUNET_free (ap);
    if ((NULL == connection->ap_head) &&
        (GNUNET_NO == connection->dns_active) &&
        (NULL == connection->proxy_handshake))
      connect_fail_continuation (connection);
    return;
  }
  GNUNET_assert (NULL == connection->sock);
  connection->sock = ap->sock;
  GNUNET_assert (NULL == connection->addr);
  connection->addr = GNUNET_malloc (ap->addrlen);
  memcpy (connection->addr, ap->addr, ap->addrlen);
  connection->addrlen = ap->addrlen;
  GNUNET_free (ap);
  /* cancel all other attempts */
  while (NULL != (pos = connection->ap_head))
  {
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (pos->sock));
    GNUNET_SCHEDULER_cancel (pos->task);
    GNUNET_CONTAINER_DLL_remove (connection->ap_head, connection->ap_tail, pos);
    GNUNET_free (pos);
  }
  connect_success_continuation (connection);
}


/**
 * Try to establish a connection given the specified address.
 * This function is called by the resolver once we have a DNS reply.
 *
 * @param cls our `struct GNUNET_CONNECTION_Handle *`
 * @param addr address to try, NULL for "last call"
 * @param addrlen length of @a addr
 */
static void
try_connect_using_address (void *cls,
                           const struct sockaddr *addr,
                           socklen_t addrlen)
{
  struct GNUNET_CONNECTION_Handle *connection = cls;
  struct AddressProbe *ap;
  struct GNUNET_TIME_Relative delay;

  if (NULL == addr)
  {
    connection->dns_active = NULL;
    if ((NULL == connection->ap_head) &&
        (NULL == connection->sock) &&
        (NULL == connection->proxy_handshake))
      connect_fail_continuation (connection);
    return;
  }
  if (NULL != connection->sock)
    return;                     /* already connected */
  GNUNET_assert (NULL == connection->addr);
  /* try to connect */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Trying to connect using address `%s:%u/%s:%u'\n",
       connection->hostname,
       connection->port,
       GNUNET_a2s (addr, addrlen),
       connection->port);
  ap = GNUNET_malloc (sizeof (struct AddressProbe) + addrlen);
  ap->addr = (const struct sockaddr *) &ap[1];
  memcpy (&ap[1], addr, addrlen);
  ap->addrlen = addrlen;
  ap->connection = connection;

  switch (ap->addr->sa_family)
  {
  case AF_INET:
    ((struct sockaddr_in *) ap->addr)->sin_port = htons (connection->port);
    break;
  case AF_INET6:
    ((struct sockaddr_in6 *) ap->addr)->sin6_port = htons (connection->port);
    break;
  default:
    GNUNET_break (0);
    GNUNET_free (ap);
    return;                     /* not supported by us */
  }
  ap->sock = GNUNET_NETWORK_socket_create (ap->addr->sa_family, SOCK_STREAM, 0);
  if (NULL == ap->sock)
  {
    GNUNET_free (ap);
    return;                     /* not supported by OS */
  }
  LOG (GNUNET_ERROR_TYPE_INFO,
       "Trying to connect to `%s' (%p)\n",
       GNUNET_a2s (ap->addr, ap->addrlen),
       connection);
  if ((GNUNET_OK !=
       GNUNET_NETWORK_socket_connect (ap->sock, ap->addr, ap->addrlen)) &&
      (EINPROGRESS != errno))
  {
    /* maybe refused / unsupported address, try next */
    LOG_STRERROR (GNUNET_ERROR_TYPE_INFO, "connect");
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (ap->sock));
    GNUNET_free (ap);
    return;
  }
  GNUNET_CONTAINER_DLL_insert (connection->ap_head, connection->ap_tail, ap);
  delay = GNUNET_CONNECTION_CONNECT_RETRY_TIMEOUT;
  if (NULL != connection->nth.notify_ready)
    delay =
        GNUNET_TIME_relative_min (delay,
                                  GNUNET_TIME_absolute_get_remaining (connection->nth.transmit_timeout));
  if (NULL != connection->receiver)
    delay =
        GNUNET_TIME_relative_min (delay,
                                  GNUNET_TIME_absolute_get_remaining
                                  (connection->receive_timeout));
  ap->task =
      GNUNET_SCHEDULER_add_write_net (delay, ap->sock,
                                      &connect_probe_continuation, ap);
}


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
GNUNET_CONNECTION_create_from_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                       const char *hostname,
                                       uint16_t port)
{
  struct GNUNET_CONNECTION_Handle *connection;

  GNUNET_assert (0 < strlen (hostname));        /* sanity check */
  connection = GNUNET_new (struct GNUNET_CONNECTION_Handle);
  connection->cfg = cfg;
  connection->write_buffer_size = GNUNET_SERVER_MIN_BUFFER_SIZE;
  connection->write_buffer = GNUNET_malloc (connection->write_buffer_size);
  connection->port = port;
  connection->hostname = GNUNET_strdup (hostname);
  connection->dns_active =
      GNUNET_RESOLVER_ip_get (connection->hostname, AF_UNSPEC,
                              GNUNET_CONNECTION_CONNECT_RETRY_TIMEOUT,
                              &try_connect_using_address, connection);
  return connection;
}


/**
 * Create a connection handle by connecting to a UNIX domain service.
 * This function returns immediately, even if the connection has not
 * yet been established.  This function only creates UNIX connections.
 *
 * @param cfg configuration to use
 * @param unixpath path to connect to
 * @return the connection handle, NULL on systems without UNIX support
 */
struct GNUNET_CONNECTION_Handle *
GNUNET_CONNECTION_create_from_connect_to_unixpath (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                                   const char *unixpath)
{
#ifdef AF_UNIX
  struct GNUNET_CONNECTION_Handle *connection;
  struct sockaddr_un *un;

  GNUNET_assert (0 < strlen (unixpath));        /* sanity check */
  un = GNUNET_new (struct sockaddr_un);
  un->sun_family = AF_UNIX;
  strncpy (un->sun_path, unixpath, sizeof (un->sun_path) - 1);
#ifdef LINUX
  {
    int abstract;

    abstract = GNUNET_CONFIGURATION_get_value_yesno (cfg, "TESTING",
                                                     "USE_ABSTRACT_SOCKETS");
    if (GNUNET_YES == abstract)
      un->sun_path[0] = '\0';
  }
#endif
#if HAVE_SOCKADDR_IN_SIN_LEN
  un->sun_len = (u_char) sizeof (struct sockaddr_un);
#endif
  connection = GNUNET_new (struct GNUNET_CONNECTION_Handle);
  connection->cfg = cfg;
  connection->write_buffer_size = GNUNET_SERVER_MIN_BUFFER_SIZE;
  connection->write_buffer = GNUNET_malloc (connection->write_buffer_size);
  connection->port = 0;
  connection->hostname = NULL;
  connection->addr = (struct sockaddr *) un;
  connection->addrlen = sizeof (struct sockaddr_un);
  connection->sock = GNUNET_NETWORK_socket_create (AF_UNIX, SOCK_STREAM, 0);
  if (NULL == connection->sock)
  {
    GNUNET_free (connection->addr);
    GNUNET_free (connection->write_buffer);
    GNUNET_free (connection);
    return NULL;
  }
  if ( (GNUNET_OK !=
	GNUNET_NETWORK_socket_connect (connection->sock, connection->addr, connection->addrlen)) &&
       (EINPROGRESS != errno) )
  {
    /* Just return; we expect everything to work eventually so don't fail HARD */
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (connection->sock));
    connection->sock = NULL;
    return connection;
  }
  connect_success_continuation (connection);
  return connection;
#else
  return NULL;
#endif
}


/**
 * Create a connection handle by (asynchronously) connecting to a host.
 * This function returns immediately, even if the connection has not
 * yet been established.  This function only creates TCP connections.
 *
 * @param s socket to connect
 * @param serv_addr server address
 * @param addrlen length of @a serv_addr
 * @return the connection handle
 */
struct GNUNET_CONNECTION_Handle *
GNUNET_CONNECTION_connect_socket (struct GNUNET_NETWORK_Handle *s,
                                  const struct sockaddr *serv_addr,
                                  socklen_t addrlen)
{
  struct GNUNET_CONNECTION_Handle *connection;

  if ( (GNUNET_OK !=
        GNUNET_NETWORK_socket_connect (s, serv_addr, addrlen)) &&
       (EINPROGRESS != errno) )
  {
    /* maybe refused / unsupported address, try next */
    LOG_STRERROR (GNUNET_ERROR_TYPE_DEBUG,
                  "connect");
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Attempt to connect to `%s' failed\n",
         GNUNET_a2s (serv_addr,
                     addrlen));
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (s));
    return NULL;
  }
  connection = GNUNET_CONNECTION_create_from_existing (s);
  connection->addr = GNUNET_malloc (addrlen);
  memcpy (connection->addr, serv_addr, addrlen);
  connection->addrlen = addrlen;
  LOG (GNUNET_ERROR_TYPE_INFO,
       "Trying to connect to `%s' (%p)\n",
       GNUNET_a2s (serv_addr, addrlen),
       connection);
  return connection;
}


/**
 * Create a connection handle by creating a socket and
 * (asynchronously) connecting to a host.  This function returns
 * immediately, even if the connection has not yet been established.
 * This function only creates TCP connections.
 *
 * @param af_family address family to use
 * @param serv_addr server address
 * @param addrlen length of @a serv_addr
 * @return the connection handle
 */
struct GNUNET_CONNECTION_Handle *
GNUNET_CONNECTION_create_from_sockaddr (int af_family,
                                        const struct sockaddr *serv_addr,
                                        socklen_t addrlen)
{
  struct GNUNET_NETWORK_Handle *s;

  s = GNUNET_NETWORK_socket_create (af_family, SOCK_STREAM, 0);
  if (NULL == s)
  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING | GNUNET_ERROR_TYPE_BULK, "socket");
    return NULL;
  }
  return GNUNET_CONNECTION_connect_socket (s, serv_addr, addrlen);
}


/**
 * Check if connection is valid (no fatal errors have happened so far).
 * Note that a connection that is still trying to connect is considered
 * valid.
 *
 * @param connection connection to check
 * @return #GNUNET_YES if valid, #GNUNET_NO otherwise
 */
int
GNUNET_CONNECTION_check (struct GNUNET_CONNECTION_Handle *connection)
{
  if ((NULL != connection->ap_head) ||
      (NULL != connection->dns_active) ||
      (NULL != connection->proxy_handshake))
    return GNUNET_YES;          /* still trying to connect */
  if ( (0 != connection->destroy_later) ||
       (NULL == connection->sock) )
    return GNUNET_NO;
  return GNUNET_YES;
}


/**
 * Close the connection and free associated resources.  There must
 * not be any pending requests for reading or writing to the
 * connection at this time.
 *
 * @param connection connection to destroy
 */
void
GNUNET_CONNECTION_destroy (struct GNUNET_CONNECTION_Handle *connection)
{
  struct AddressProbe *pos;

  if (0 != connection->destroy_later)
  {
    connection->destroy_later = -1;
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Shutting down connection (%p)\n",
       connection);
  GNUNET_assert (NULL == connection->nth.notify_ready);
  GNUNET_assert (NULL == connection->receiver);
  if (NULL != connection->write_task)
  {
    GNUNET_SCHEDULER_cancel (connection->write_task);
    connection->write_task = NULL;
    connection->write_buffer_off = 0;
  }
  if (NULL != connection->read_task)
  {
    GNUNET_SCHEDULER_cancel (connection->read_task);
    connection->read_task = NULL;
  }
  if (NULL != connection->nth.timeout_task)
  {
    GNUNET_SCHEDULER_cancel (connection->nth.timeout_task);
    connection->nth.timeout_task = NULL;
  }
  connection->nth.notify_ready = NULL;
  if (NULL != connection->dns_active)
  {
    GNUNET_RESOLVER_request_cancel (connection->dns_active);
    connection->dns_active = NULL;
  }
  if (NULL != connection->proxy_handshake)
  {
    /* GNUNET_CONNECTION_destroy (connection->proxy_handshake); */
    connection->proxy_handshake->destroy_later = -1;
    connection->proxy_handshake = NULL;  /* Not leaked ??? */
  }
  while (NULL != (pos = connection->ap_head))
  {
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (pos->sock));
    GNUNET_SCHEDULER_cancel (pos->task);
    GNUNET_CONTAINER_DLL_remove (connection->ap_head, connection->ap_tail, pos);
    GNUNET_free (pos);
  }
  if ( (NULL != connection->sock) &&
       (GNUNET_YES != connection->persist) )
  {
    if ((GNUNET_OK !=
         GNUNET_NETWORK_socket_shutdown (connection->sock,
                                         SHUT_RDWR)) &&
	(ENOTCONN != errno) &&
	(ECONNRESET != errno) )
      LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING,
                    "shutdown");
  }
  if (NULL != connection->sock)
  {
    if (GNUNET_YES != connection->persist)
    {
      GNUNET_break (GNUNET_OK ==
                    GNUNET_NETWORK_socket_close (connection->sock));
    }
    else
    {
      GNUNET_NETWORK_socket_free_memory_only_ (connection->sock); /* at least no memory leak (we deliberately
								   * leak the socket in this special case) ... */
    }
  }
  GNUNET_free_non_null (connection->addr);
  GNUNET_free_non_null (connection->hostname);
  GNUNET_free (connection->write_buffer);
  GNUNET_free (connection);
}


/**
 * This function is called once we either timeout
 * or have data ready to read.
 *
 * @param cls connection to read from
 * @param tc scheduler context
 */
static void
receive_ready (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CONNECTION_Handle *connection = cls;
  char buffer[connection->max];
  ssize_t ret;
  GNUNET_CONNECTION_Receiver receiver;

  connection->read_task = NULL;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    /* ignore shutdown request, go again immediately */
    connection->read_task =
        GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_absolute_get_remaining
                                       (connection->receive_timeout), connection->sock,
                                       &receive_ready, connection);
    return;
  }
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_TIMEOUT))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Receive from `%s' encounters error: timeout (%s, %p)\n",
	 GNUNET_a2s (connection->addr, connection->addrlen),
	 GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_duration (connection->receive_timeout), GNUNET_YES),
	 connection);
    signal_receive_timeout (connection);
    return;
  }
  if (NULL == connection->sock)
  {
    /* connect failed for good */
    signal_receive_error (connection, ECONNREFUSED);
    return;
  }
  GNUNET_assert (GNUNET_NETWORK_fdset_isset (tc->read_ready, connection->sock));
RETRY:
  ret = GNUNET_NETWORK_socket_recv (connection->sock,
                                    buffer,
                                    connection->max);
  if (-1 == ret)
  {
    if (EINTR == errno)
      goto RETRY;
    signal_receive_error (connection, errno);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "receive_ready read %u/%u bytes from `%s' (%p)!\n",
       (unsigned int) ret,
       connection->max,
       GNUNET_a2s (connection->addr,
                   connection->addrlen),
       connection);
  GNUNET_assert (NULL != (receiver = connection->receiver));
  connection->receiver = NULL;
  receiver (connection->receiver_cls,
            buffer,
            ret,
            connection->addr,
            connection->addrlen,
            0);
}


/**
 * Receive data from the given connection.  Note that this function will
 * call @a receiver asynchronously using the scheduler.  It will
 * "immediately" return.  Note that there MUST only be one active
 * receive call per connection at any given point in time (so do not
 * call receive again until the receiver callback has been invoked).
 *
 * @param connection connection handle
 * @param max maximum number of bytes to read
 * @param timeout maximum amount of time to wait
 * @param receiver function to call with received data
 * @param receiver_cls closure for @a receiver
 */
void
GNUNET_CONNECTION_receive (struct GNUNET_CONNECTION_Handle *connection,
                           size_t max,
                           struct GNUNET_TIME_Relative timeout,
                           GNUNET_CONNECTION_Receiver receiver,
                           void *receiver_cls)
{
  GNUNET_assert ((NULL == connection->read_task) &&
                 (NULL == connection->receiver));
  GNUNET_assert (NULL != receiver);
  connection->receiver = receiver;
  connection->receiver_cls = receiver_cls;
  connection->receive_timeout = GNUNET_TIME_relative_to_absolute (timeout);
  connection->max = max;
  if (NULL != connection->sock)
  {
    connection->read_task =
      GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_absolute_get_remaining
                                     (connection->receive_timeout),
                                     connection->sock,
                                     &receive_ready,
                                     connection);
    return;
  }
  if ((NULL == connection->dns_active) &&
      (NULL == connection->ap_head) &&
      (NULL == connection->proxy_handshake))
  {
    connection->receiver = NULL;
    receiver (receiver_cls, NULL, 0, NULL, 0, ETIMEDOUT);
    return;
  }
}


/**
 * Cancel receive job on the given connection.  Note that the
 * receiver callback must not have been called yet in order
 * for the cancellation to be valid.
 *
 * @param connection connection handle
 * @return closure of the original receiver callback closure
 */
void *
GNUNET_CONNECTION_receive_cancel (struct GNUNET_CONNECTION_Handle *connection)
{
  if (NULL != connection->read_task)
  {
    GNUNET_assert (connection ==
                   GNUNET_SCHEDULER_cancel (connection->read_task));
    connection->read_task = NULL;
  }
  connection->receiver = NULL;
  return connection->receiver_cls;
}


/**
 * Try to call the transmit notify method (check if we do
 * have enough space available first)!
 *
 * @param connection connection for which we should do this processing
 * @return #GNUNET_YES if we were able to call notify
 */
static int
process_notify (struct GNUNET_CONNECTION_Handle *connection)
{
  size_t used;
  size_t avail;
  size_t size;
  GNUNET_CONNECTION_TransmitReadyNotify notify;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "process_notify is running\n");
  GNUNET_assert (NULL == connection->write_task);
  if (NULL == (notify = connection->nth.notify_ready))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "No one to notify\n");
    return GNUNET_NO;
  }
  used = connection->write_buffer_off - connection->write_buffer_pos;
  avail = connection->write_buffer_size - used;
  size = connection->nth.notify_size;
  if (size > avail)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Not enough buffer\n");
    return GNUNET_NO;
  }
  connection->nth.notify_ready = NULL;
  if (connection->write_buffer_size - connection->write_buffer_off < size)
  {
    /* need to compact */
    memmove (connection->write_buffer,
             &connection->write_buffer[connection->write_buffer_pos],
             used);
    connection->write_buffer_off -= connection->write_buffer_pos;
    connection->write_buffer_pos = 0;
  }
  avail = connection->write_buffer_size - connection->write_buffer_off;
  GNUNET_assert (avail >= size);
  size =
      notify (connection->nth.notify_ready_cls, avail,
              &connection->write_buffer[connection->write_buffer_off]);
  GNUNET_assert (size <= avail);
  if (0 != size)
    connection->write_buffer_off += size;
  return GNUNET_YES;
}


/**
 * Task invoked by the scheduler when a call to transmit
 * is timing out (we never got enough buffer space to call
 * the callback function before the specified timeout
 * expired).
 *
 * This task notifies the client about the timeout.
 *
 * @param cls the `struct GNUNET_CONNECTION_Handle`
 * @param tc scheduler context
 */
static void
transmit_timeout (void *cls,
                  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CONNECTION_Handle *connection = cls;
  GNUNET_CONNECTION_TransmitReadyNotify notify;

  connection->nth.timeout_task = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Transmit to `%s:%u/%s' fails, time out reached (%p).\n",
       connection->hostname,
       connection->port,
       GNUNET_a2s (connection->addr,
                   connection->addrlen),
       connection);
  notify = connection->nth.notify_ready;
  GNUNET_assert (NULL != notify);
  connection->nth.notify_ready = NULL;
  notify (connection->nth.notify_ready_cls, 0, NULL);
}


/**
 * Task invoked by the scheduler when we failed to connect
 * at the time of being asked to transmit.
 *
 * This task notifies the client about the error.
 *
 * @param cls the `struct GNUNET_CONNECTION_Handle`
 * @param tc scheduler context
 */
static void
connect_error (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CONNECTION_Handle *connection = cls;
  GNUNET_CONNECTION_TransmitReadyNotify notify;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Transmission request of size %u fails (%s/%u), connection failed (%p).\n",
       connection->nth.notify_size,
       connection->hostname,
       connection->port,
       connection);
  connection->write_task = NULL;
  notify = connection->nth.notify_ready;
  connection->nth.notify_ready = NULL;
  notify (connection->nth.notify_ready_cls, 0, NULL);
}


/**
 * We are ready to transmit (or got a timeout).
 *
 * @param cls our connection handle
 * @param tc task context describing why we are here
 */
static void
transmit_ready (void *cls,
                const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CONNECTION_Handle *connection = cls;
  GNUNET_CONNECTION_TransmitReadyNotify notify;
  ssize_t ret;
  size_t have;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "transmit_ready running (%p).\n",
       connection);
  GNUNET_assert (NULL != connection->write_task);
  connection->write_task = NULL;
  GNUNET_assert (NULL == connection->nth.timeout_task);
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    if (NULL != connection->sock)
      goto SCHEDULE_WRITE;      /* ignore shutdown, go again immediately */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Transmit to `%s' fails, shutdown happened (%p).\n",
         GNUNET_a2s (connection->addr, connection->addrlen), connection);
    notify = connection->nth.notify_ready;
    if (NULL != notify)
    {
      connection->nth.notify_ready = NULL;
      notify (connection->nth.notify_ready_cls, 0, NULL);
    }
    return;
  }
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_TIMEOUT))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Transmit to `%s' fails, time out reached (%p).\n",
         GNUNET_a2s (connection->addr,
                     connection->addrlen),
         connection);
    notify = connection->nth.notify_ready;
    GNUNET_assert (NULL != notify);
    connection->nth.notify_ready = NULL;
    notify (connection->nth.notify_ready_cls, 0, NULL);
    return;
  }
  GNUNET_assert (NULL != connection->sock);
  if (NULL == tc->write_ready)
  {
    /* special circumstances (in particular, PREREQ_DONE after
     * connect): not yet ready to write, but no "fatal" error either.
     * Hence retry.  */
    goto SCHEDULE_WRITE;
  }
  if (!GNUNET_NETWORK_fdset_isset (tc->write_ready, connection->sock))
  {
    GNUNET_assert (NULL == connection->write_task);
    /* special circumstances (in particular, shutdown): not yet ready
     * to write, but no "fatal" error either.  Hence retry.  */
    goto SCHEDULE_WRITE;
  }
  GNUNET_assert (connection->write_buffer_off >= connection->write_buffer_pos);
  if ((NULL != connection->nth.notify_ready) &&
      (connection->write_buffer_size < connection->nth.notify_size))
  {
    connection->write_buffer =
        GNUNET_realloc (connection->write_buffer, connection->nth.notify_size);
    connection->write_buffer_size = connection->nth.notify_size;
  }
  process_notify (connection);
  have = connection->write_buffer_off - connection->write_buffer_pos;
  if (0 == have)
  {
    /* no data ready for writing, terminate write loop */
    return;
  }
  GNUNET_assert (have <= connection->write_buffer_size);
  GNUNET_assert (have + connection->write_buffer_pos <= connection->write_buffer_size);
  GNUNET_assert (connection->write_buffer_pos <= connection->write_buffer_size);
RETRY:
  ret =
      GNUNET_NETWORK_socket_send (connection->sock,
				  &connection->write_buffer[connection->write_buffer_pos],
				  have);
  if (-1 == ret)
  {
    if (EINTR == errno)
      goto RETRY;
    if (NULL != connection->write_task)
    {
      GNUNET_SCHEDULER_cancel (connection->write_task);
      connection->write_task = NULL;
    }
    signal_transmit_error (connection, errno);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connection transmitted %u/%u bytes to `%s' (%p)\n",
       (unsigned int) ret, have, GNUNET_a2s (connection->addr, connection->addrlen), connection);
  connection->write_buffer_pos += ret;
  if (connection->write_buffer_pos == connection->write_buffer_off)
  {
    /* transmitted all pending data */
    connection->write_buffer_pos = 0;
    connection->write_buffer_off = 0;
  }
  if ((0 == connection->write_buffer_off) && (NULL == connection->nth.notify_ready))
    return;                     /* all data sent! */
  /* not done writing, schedule more */
SCHEDULE_WRITE:
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Re-scheduling transmit_ready (more to do) (%p).\n", connection);
  have = connection->write_buffer_off - connection->write_buffer_pos;
  GNUNET_assert ((NULL != connection->nth.notify_ready) || (have > 0));
  if (NULL == connection->write_task)
    connection->write_task =
        GNUNET_SCHEDULER_add_write_net ((connection->nth.notify_ready ==
                                         NULL) ? GNUNET_TIME_UNIT_FOREVER_REL :
                                        GNUNET_TIME_absolute_get_remaining
                                        (connection->nth.transmit_timeout),
                                        connection->sock, &transmit_ready, connection);
}


/**
 * Ask the connection to call us once the specified number of bytes
 * are free in the transmission buffer.  Will never call the @a notify
 * callback in this task, but always first go into the scheduler.
 *
 * @param connection connection
 * @param size number of bytes to send
 * @param timeout after how long should we give up (and call
 *        @a notify with buf NULL and size 0)?
 * @param notify function to call
 * @param notify_cls closure for @a notify
 * @return non-NULL if the notify callback was queued,
 *         NULL if we are already going to notify someone else (busy)
 */
struct GNUNET_CONNECTION_TransmitHandle *
GNUNET_CONNECTION_notify_transmit_ready (struct GNUNET_CONNECTION_Handle *connection,
                                         size_t size,
                                         struct GNUNET_TIME_Relative timeout,
                                         GNUNET_CONNECTION_TransmitReadyNotify
                                         notify, void *notify_cls)
{
  if (NULL != connection->nth.notify_ready)
  {
    GNUNET_assert (0);
    return NULL;
  }
  GNUNET_assert (NULL != notify);
  GNUNET_assert (size < GNUNET_SERVER_MAX_MESSAGE_SIZE);
  GNUNET_assert (connection->write_buffer_off <= connection->write_buffer_size);
  GNUNET_assert (connection->write_buffer_pos <= connection->write_buffer_size);
  GNUNET_assert (connection->write_buffer_pos <= connection->write_buffer_off);
  connection->nth.notify_ready = notify;
  connection->nth.notify_ready_cls = notify_cls;
  connection->nth.connection = connection;
  connection->nth.notify_size = size;
  connection->nth.transmit_timeout = GNUNET_TIME_relative_to_absolute (timeout);
  GNUNET_assert (NULL == connection->nth.timeout_task);
  if ((NULL == connection->sock) &&
      (NULL == connection->ap_head) &&
      (NULL == connection->dns_active) &&
      (NULL == connection->proxy_handshake))
  {
    if (NULL != connection->write_task)
      GNUNET_SCHEDULER_cancel (connection->write_task);
    connection->write_task = GNUNET_SCHEDULER_add_now (&connect_error,
                                                       connection);
    return &connection->nth;
  }
  if (NULL != connection->write_task)
    return &connection->nth; /* previous transmission still in progress */
  if (NULL != connection->sock)
  {
    /* connected, try to transmit now */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Scheduling transmission (%p).\n",
         connection);
    connection->write_task =
        GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_absolute_get_remaining
                                        (connection->nth.transmit_timeout),
                                        connection->sock, &transmit_ready, connection);
    return &connection->nth;
  }
  /* not yet connected, wait for connection */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Need to wait to schedule transmission for connection, adding timeout task (%p).\n",
       connection);
  connection->nth.timeout_task =
    GNUNET_SCHEDULER_add_delayed (timeout,
                                  &transmit_timeout, connection);
  return &connection->nth;
}


/**
 * Cancel the specified transmission-ready notification.
 *
 * @param th notification to cancel
 */
void
GNUNET_CONNECTION_notify_transmit_ready_cancel (struct GNUNET_CONNECTION_TransmitHandle *th)
{
  GNUNET_assert (NULL != th->notify_ready);
  th->notify_ready = NULL;
  if (NULL != th->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (th->timeout_task);
    th->timeout_task = NULL;
  }
  if (NULL != th->connection->write_task)
  {
    GNUNET_SCHEDULER_cancel (th->connection->write_task);
    th->connection->write_task = NULL;
  }
}


/**
 * Create a connection to be proxied using a given connection.
 *
 * @param cph connection to proxy server
 * @return connection to be proxied
 */
struct GNUNET_CONNECTION_Handle *
GNUNET_CONNECTION_create_proxied_from_handshake (struct GNUNET_CONNECTION_Handle *cph)
{
  struct GNUNET_CONNECTION_Handle * proxied = GNUNET_CONNECTION_create_from_existing(NULL);
  proxied->proxy_handshake = cph;
  return proxied;
}


/**
 * Activate proxied connection and destroy initial proxy handshake connection.
 * There must not be any pending requests for reading or writing to the
 * proxy hadshake connection at this time.
 *
 * @param proxied connection connection to proxy server
 */
void
GNUNET_CONNECTION_acivate_proxied (struct GNUNET_CONNECTION_Handle *proxied)
{
  struct GNUNET_CONNECTION_Handle *cph = proxied->proxy_handshake;
  GNUNET_assert (NULL != cph);
  GNUNET_assert (NULL == proxied->sock);
  GNUNET_assert (NULL != cph->sock);
  proxied->sock=cph->sock;
  cph->sock=NULL;
  GNUNET_CONNECTION_destroy (cph);
  connect_success_continuation (proxied);
}


/* end of connection.c */
