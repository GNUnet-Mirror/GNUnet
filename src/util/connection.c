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
#include "gnunet_common.h"
#include "gnunet_connection_lib.h"
#include "gnunet_container_lib.h"
#include "gnunet_resolver_service.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_server_lib.h"


#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

#define LOG_STRERROR(kind,syscall) GNUNET_log_from_strerror (kind, "util", syscall)

/**
 * Possible functions to call after connect failed or succeeded.
 */
enum ConnectContinuations
{
    /**
     * Call nothing.
     */
  COCO_NONE = 0,

    /**
     * Call "receive_again".
     */
  COCO_RECEIVE_AGAIN = 1,

    /**
     * Call "transmit_ready".
     */
  COCO_TRANSMIT_READY = 2

};


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
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

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
  GNUNET_SCHEDULER_TaskIdentifier task;
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
   * Closure for receiver.
   */
  void *receiver_cls;

  /**
   * Pointer to our write buffer.
   */
  char *write_buffer;

  /**
   * Current size of our write buffer.
   */
  size_t write_buffer_size;

  /**
   * Current write-offset in write buffer (where
   * would we write next).
   */
  size_t write_buffer_off;

  /**
   * Current read-offset in write buffer (how many
   * bytes have already been sent).
   */
  size_t write_buffer_pos;

  /**
   * Length of addr.
   */
  socklen_t addrlen;

  /**
   * Read task that we may need to wait for.
   */
  GNUNET_SCHEDULER_TaskIdentifier read_task;

  /**
   * Write task that we may need to wait for.
   */
  GNUNET_SCHEDULER_TaskIdentifier write_task;

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
   * Functions to call after connect failed or succeeded.
   */
  enum ConnectContinuations ccs;

  /**
   * Maximum number of bytes to read (for receiving).
   */
  size_t max;

  /**
   * Ignore GNUNET_SCHEDULER_REASON_SHUTDOWN for this connection.
   */
  int ignore_shutdown;

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
  int16_t persist;

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
 * @return GNUNET_OK on success
 */
int
GNUNET_CONNECTION_disable_corking (struct GNUNET_CONNECTION_Handle *connection)
{
  return GNUNET_NETWORK_socket_disable_corking (connection->sock);
}


/**
 * Create a connection handle by boxing an existing OS socket.  The OS
 * socket should henceforth be no longer used directly.
 * GNUNET_connection_destroy will close it.
 *
 * @param osSocket existing socket to box
 * @return the boxed connection handle
 */
struct GNUNET_CONNECTION_Handle *
GNUNET_CONNECTION_create_from_existing (struct GNUNET_NETWORK_Handle *osSocket)
{
  struct GNUNET_CONNECTION_Handle *connection;

  connection = GNUNET_malloc (sizeof (struct GNUNET_CONNECTION_Handle));
  connection->write_buffer_size = GNUNET_SERVER_MIN_BUFFER_SIZE;
  connection->write_buffer = GNUNET_malloc (connection->write_buffer_size);
  connection->sock = osSocket;
  return connection;
}


/**
 * Create a connection handle by accepting on a listen socket.  This
 * function may block if the listen socket has no connection ready.
 *
 * @param access function to use to check if access is allowed
 * @param access_cls closure for access
 * @param lsock listen socket
 * @return the connection handle, NULL on error
 */
struct GNUNET_CONNECTION_Handle *
GNUNET_CONNECTION_create_from_accept (GNUNET_CONNECTION_AccessCheck access,
                                      void *access_cls,
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
  if ((sa->sa_family == AF_INET6) && (IN6_IS_ADDR_V4MAPPED (&v6->sin6_addr)))
  {
    /* convert to V4 address */
    v4 = GNUNET_malloc (sizeof (struct sockaddr_in));
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
  if (sa->sa_family == AF_UNIX)
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

  if ((access != NULL) &&
      (GNUNET_YES != (aret = access (access_cls, gcp, uaddr, addrlen))))
  {
    if (aret == GNUNET_NO)
      LOG (GNUNET_ERROR_TYPE_INFO, _("Access denied to `%s'\n"),
           GNUNET_a2s (uaddr, addrlen));
    GNUNET_break (GNUNET_OK ==
                  GNUNET_NETWORK_socket_shutdown (sock, SHUT_RDWR));
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (sock));
    GNUNET_free (uaddr);
    return NULL;
  }
  connection = GNUNET_malloc (sizeof (struct GNUNET_CONNECTION_Handle));
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
 * @param addrlen where to store the length of the address
 * @return GNUNET_OK on success
 */
int
GNUNET_CONNECTION_get_address (struct GNUNET_CONNECTION_Handle *connection,
                               void **addr, size_t * addrlen)
{
  if ((connection->addr == NULL) || (connection->addrlen == 0))
    return GNUNET_NO;
  *addr = GNUNET_malloc (connection->addrlen);
  memcpy (*addr, connection->addr, connection->addrlen);
  *addrlen = connection->addrlen;
  return GNUNET_OK;
}


/**
 * This function is called after establishing a connection either has
 * succeeded or timed out.  Note that it is possible that the attempt
 * timed out and that we're immediately retrying.  If we are retrying,
 * we need to wait again (or timeout); if we succeeded, we need to
 * wait for data (or timeout).
 *
 * @param cls our connection handle
 * @param tc task context describing why we are here
 */
static void
receive_again (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * See if we are now connected.  If not, wait longer for
 * connect to succeed.  If connected, we should be able
 * to write now as well, unless we timed out.
 *
 * @param cls our connection handle
 * @param tc task context describing why we are here
 */
static void
transmit_ready (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * We've failed for good to establish a connection.
 *
 * @param h the connection we tried to establish
 */
static void
connect_fail_continuation (struct GNUNET_CONNECTION_Handle *h)
{
  LOG (GNUNET_ERROR_TYPE_INFO,
       _("Failed to establish TCP connection to `%s:%u', no further addresses to try.\n"),
       h->hostname, h->port);
  /* connect failed / timed out */
  GNUNET_break (h->ap_head == NULL);
  GNUNET_break (h->ap_tail == NULL);
  GNUNET_break (h->dns_active == GNUNET_NO);
  GNUNET_break (h->sock == NULL);

  /* trigger jobs that used to wait on "connect_task" */
  if (0 != (h->ccs & COCO_RECEIVE_AGAIN))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "connect_fail_continuation triggers receive_again (%p)\n", h);
    h->ccs -= COCO_RECEIVE_AGAIN;
    h->read_task = GNUNET_SCHEDULER_add_now (&receive_again, h);
  }
  if (0 != (h->ccs & COCO_TRANSMIT_READY))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "connect_fail_continuation cancels timeout_task, triggers transmit_ready (%p)\n",
         h);
    GNUNET_assert (h->nth.timeout_task != GNUNET_SCHEDULER_NO_TASK);
    GNUNET_SCHEDULER_cancel (h->nth.timeout_task);
    h->nth.timeout_task = GNUNET_SCHEDULER_NO_TASK;
    h->ccs -= COCO_TRANSMIT_READY;
    GNUNET_assert (h->nth.notify_ready != NULL);
    GNUNET_assert (h->write_task == GNUNET_SCHEDULER_NO_TASK);
    h->write_task = GNUNET_SCHEDULER_add_now (&transmit_ready, h);
  }
}


/**
 * We've succeeded in establishing a connection.
 *
 * @param connection the connection we tried to establish
 */
static void
connect_success_continuation (struct GNUNET_CONNECTION_Handle *connection)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Connection to `%s' succeeded! (%p)\n",
       GNUNET_a2s (connection->addr, connection->addrlen), connection);
  /* trigger jobs that waited for the connection */
  if (0 != (connection->ccs & COCO_RECEIVE_AGAIN))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "connect_success_continuation runs receive_again (%p)\n", connection);
    connection->ccs -= COCO_RECEIVE_AGAIN;
    connection->read_task = GNUNET_SCHEDULER_add_now (&receive_again, connection);
  }
  if (0 != (connection->ccs & COCO_TRANSMIT_READY))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "connect_success_continuation runs transmit_ready, cancels timeout_task (%p)\n",
         connection);
    GNUNET_assert (connection->nth.timeout_task != GNUNET_SCHEDULER_NO_TASK);
    GNUNET_SCHEDULER_cancel (connection->nth.timeout_task);
    connection->nth.timeout_task = GNUNET_SCHEDULER_NO_TASK;
    connection->ccs -= COCO_TRANSMIT_READY;
    GNUNET_assert (connection->write_task == GNUNET_SCHEDULER_NO_TASK);
    GNUNET_assert (connection->nth.notify_ready != NULL);
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

  GNUNET_assert (ap->sock != NULL);
  GNUNET_CONTAINER_DLL_remove (connection->ap_head, connection->ap_tail, ap);
  len = sizeof (error);
  errno = 0;
  error = 0;
  if ((0 == (tc->reason & GNUNET_SCHEDULER_REASON_WRITE_READY)) ||
      (GNUNET_OK !=
       GNUNET_NETWORK_socket_getsockopt (ap->sock, SOL_SOCKET, SO_ERROR, &error,
                                         &len)) || (error != 0))
  {
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (ap->sock));
    GNUNET_free (ap);
    if ((NULL == connection->ap_head) && (connection->dns_active == GNUNET_NO))
      connect_fail_continuation (connection);
    return;
  }
  GNUNET_assert (connection->sock == NULL);
  connection->sock = ap->sock;
  GNUNET_assert (connection->addr == NULL);
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
 * @param cls our "struct GNUNET_CONNECTION_Handle *"
 * @param addr address to try, NULL for "last call"
 * @param addrlen length of addr
 */
static void
try_connect_using_address (void *cls, const struct sockaddr *addr,
                           socklen_t addrlen)
{
  struct GNUNET_CONNECTION_Handle *connection = cls;
  struct AddressProbe *ap;
  struct GNUNET_TIME_Relative delay;

  if (addr == NULL)
  {
    connection->dns_active = NULL;
    if ((NULL == connection->ap_head) && (NULL == connection->sock))
      connect_fail_continuation (connection);
    return;
  }
  if (connection->sock != NULL)
    return;                     /* already connected */
  GNUNET_assert (connection->addr == NULL);
  /* try to connect */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Trying to connect using address `%s:%u/%s:%u'\n", connection->hostname, connection->port,
       GNUNET_a2s (addr, addrlen), connection->port);
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
  if (ap->sock == NULL)
  {
    GNUNET_free (ap);
    return;                     /* not supported by OS */
  }
  LOG (GNUNET_ERROR_TYPE_INFO, _("Trying to connect to `%s' (%p)\n"),
       GNUNET_a2s (ap->addr, ap->addrlen), connection);
  if ((GNUNET_OK !=
       GNUNET_NETWORK_socket_connect (ap->sock, ap->addr, ap->addrlen)) &&
      (errno != EINPROGRESS))
  {
    /* maybe refused / unsupported address, try next */
    LOG_STRERROR (GNUNET_ERROR_TYPE_INFO, "connect");
#if 0
    LOG (GNUNET_ERROR_TYPE_INFO, _("Failed to connect to `%s' (%p)\n"),
         GNUNET_a2s (ap->addr, ap->addrlen), connection);
#endif
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (ap->sock));
    GNUNET_free (ap);
    return;
  }
  GNUNET_CONTAINER_DLL_insert (connection->ap_head, connection->ap_tail, ap);
  delay = GNUNET_CONNECTION_CONNECT_RETRY_TIMEOUT;
  if (connection->nth.notify_ready != NULL)
    delay =
        GNUNET_TIME_relative_min (delay,
                                  GNUNET_TIME_absolute_get_remaining (connection->
                                                                      nth.transmit_timeout));
  if (connection->receiver != NULL)
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
GNUNET_CONNECTION_create_from_connect (const struct GNUNET_CONFIGURATION_Handle
                                       *cfg, const char *hostname,
                                       uint16_t port)
{
  struct GNUNET_CONNECTION_Handle *connection;

  GNUNET_assert (0 < strlen (hostname));        /* sanity check */
  connection = GNUNET_malloc (sizeof (struct GNUNET_CONNECTION_Handle));
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
GNUNET_CONNECTION_create_from_connect_to_unixpath (const struct
                                                   GNUNET_CONFIGURATION_Handle
                                                   *cfg, const char *unixpath)
{
#ifdef AF_UNIX
  struct GNUNET_CONNECTION_Handle *connection;
  struct sockaddr_un *un;
  size_t slen;

  GNUNET_assert (0 < strlen (unixpath));        /* sanity check */
  un = GNUNET_malloc (sizeof (struct sockaddr_un));
  un->sun_family = AF_UNIX;
  slen = strlen (unixpath);
  if (slen >= sizeof (un->sun_path))
    slen = sizeof (un->sun_path) - 1;
  memcpy (un->sun_path, unixpath, slen);
  un->sun_path[slen] = '\0';
  slen = sizeof (struct sockaddr_un);
#if HAVE_SOCKADDR_IN_SIN_LEN
  un->sun_len = (u_char) slen;
#endif
#if LINUX
  un->sun_path[0] = '\0';
#endif
  connection = GNUNET_malloc (sizeof (struct GNUNET_CONNECTION_Handle));
  connection->cfg = cfg;
  connection->write_buffer_size = GNUNET_SERVER_MIN_BUFFER_SIZE;
  connection->write_buffer = GNUNET_malloc (connection->write_buffer_size);
  connection->port = 0;
  connection->hostname = NULL;
  connection->addr = (struct sockaddr *) un;
  connection->addrlen = slen;
  connection->sock = GNUNET_NETWORK_socket_create (AF_UNIX, SOCK_STREAM, 0);
  if (NULL == connection->sock)
  {
    GNUNET_free (connection->addr);
    GNUNET_free (connection->write_buffer);
    GNUNET_free (connection);
    return NULL;
  }
  if (GNUNET_OK !=
      GNUNET_NETWORK_socket_connect (connection->sock, connection->addr, connection->addrlen))
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
 * @param af_family address family to use
 * @param serv_addr server address
 * @param addrlen length of server address
 * @return the connection handle
 */
struct GNUNET_CONNECTION_Handle *
GNUNET_CONNECTION_create_from_sockaddr (int af_family,
                                        const struct sockaddr *serv_addr,
                                        socklen_t addrlen)
{
  struct GNUNET_NETWORK_Handle *s;
  struct GNUNET_CONNECTION_Handle *connection;


  s = GNUNET_NETWORK_socket_create (af_family, SOCK_STREAM, 0);
  if (s == NULL)
  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING | GNUNET_ERROR_TYPE_BULK, "socket");
    return NULL;
  }
  if ((GNUNET_OK != GNUNET_NETWORK_socket_connect (s, serv_addr, addrlen)) &&
      (errno != EINPROGRESS))
  {
    /* maybe refused / unsupported address, try next */
    LOG_STRERROR (GNUNET_ERROR_TYPE_INFO, "connect");
    LOG (GNUNET_ERROR_TYPE_INFO, _("Attempt to connect to `%s' failed\n"),
         GNUNET_a2s (serv_addr, addrlen));
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (s));
    return NULL;
  }
  connection = GNUNET_CONNECTION_create_from_existing (s);
  connection->addr = GNUNET_malloc (addrlen);
  memcpy (connection->addr, serv_addr, addrlen);
  connection->addrlen = addrlen;
  LOG (GNUNET_ERROR_TYPE_INFO, _("Trying to connect to `%s' (%p)\n"),
       GNUNET_a2s (serv_addr, addrlen), connection);
  return connection;
}


/**
 * Check if connection is valid (no fatal errors have happened so far).
 * Note that a connection that is still trying to connect is considered
 * valid.
 *
 * @param connection connection to check
 * @return GNUNET_YES if valid, GNUNET_NO otherwise
 */
int
GNUNET_CONNECTION_check (struct GNUNET_CONNECTION_Handle *connection)
{
  if ((connection->ap_head != NULL) || (connection->dns_active != NULL))
    return GNUNET_YES;          /* still trying to connect */
  return (connection->sock == NULL) ? GNUNET_NO : GNUNET_YES;
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

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Shutting down connection (%p)\n", connection);
  GNUNET_assert (NULL == connection->nth.notify_ready);
  GNUNET_assert (NULL == connection->receiver);
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == connection->read_task);
  if (connection->write_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (connection->write_task);
    connection->write_task = GNUNET_SCHEDULER_NO_TASK;
    connection->write_buffer_off = 0;
  }
  if (connection->read_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (connection->read_task);
    connection->read_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (connection->nth.timeout_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (connection->nth.timeout_task);
    connection->nth.timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  connection->nth.notify_ready = NULL;
  if (NULL != connection->dns_active)
  {
    GNUNET_RESOLVER_request_cancel (connection->dns_active);
    connection->dns_active = NULL;
  }
  while (NULL != (pos = connection->ap_head))
  {
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (pos->sock));
    GNUNET_SCHEDULER_cancel (pos->task);
    GNUNET_CONTAINER_DLL_remove (connection->ap_head, connection->ap_tail, pos);
    GNUNET_free (pos);
  }
  if ( (NULL != connection->sock) &&
       (connection->persist != GNUNET_YES) )
  {
    if ((GNUNET_YES != GNUNET_NETWORK_socket_shutdown (connection->sock, SHUT_RDWR)) && 
	(errno != ENOTCONN) && 
	(errno != ECONNRESET) )
      LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "shutdown");    
  }
  if (connection->sock != NULL)
  {
    if (connection->persist != GNUNET_YES)
      GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (connection->sock));
    else
      GNUNET_free (connection->sock); /* at least no memory leak (we deliberately
				       * leak the socket in this special case) ... */
  }
  GNUNET_free_non_null (connection->addr);
  GNUNET_free_non_null (connection->hostname);
  GNUNET_free (connection->write_buffer);
  GNUNET_free (connection);
}


/**
 * Tell the receiver callback that a timeout was reached.
 */
static void
signal_timeout (struct GNUNET_CONNECTION_Handle *connection)
{
  GNUNET_CONNECTION_Receiver receiver;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Network signals time out to receiver (%p)!\n",
       connection);
  GNUNET_assert (NULL != (receiver = connection->receiver));
  connection->receiver = NULL;
  receiver (connection->receiver_cls, NULL, 0, NULL, 0, 0);
}


/**
 * Tell the receiver callback that we had an IO error.
 */
static void
signal_error (struct GNUNET_CONNECTION_Handle *connection, int errcode)
{
  GNUNET_CONNECTION_Receiver receiver;

  GNUNET_assert (NULL != (receiver = connection->receiver));
  connection->receiver = NULL;
  receiver (connection->receiver_cls, NULL, 0, connection->addr, connection->addrlen, errcode);
}


/**
 * This function is called once we either timeout
 * or have data ready to read.
 */
static void
receive_ready (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CONNECTION_Handle *connection = cls;
  struct GNUNET_TIME_Absolute now;
  char buffer[connection->max];
  ssize_t ret;
  GNUNET_CONNECTION_Receiver receiver;

  connection->read_task = GNUNET_SCHEDULER_NO_TASK;
  if ((GNUNET_YES == connection->ignore_shutdown) &&
      (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN)))
  {
    /* ignore shutdown request, go again immediately */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Ignoring shutdown signal per configuration\n");
    connection->read_task =
        GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_absolute_get_remaining
                                       (connection->receive_timeout), connection->sock,
                                       &receive_ready, connection);
    return;
  }
  now = GNUNET_TIME_absolute_get ();
  if ((now.abs_value > connection->receive_timeout.abs_value) ||
      (0 != (tc->reason & GNUNET_SCHEDULER_REASON_TIMEOUT)) ||
      (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN)))
  {
    if (0 == (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Receive from `%s' encounters error: time out by %llums... (%p)\n",
           GNUNET_a2s (connection->addr, connection->addrlen),
           GNUNET_TIME_absolute_get_duration (connection->receive_timeout).rel_value,
           connection);
    signal_timeout (connection);
    return;
  }
  if (connection->sock == NULL)
  {
    /* connect failed for good */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Receive encounters error, connection closed... (%p)\n", connection);
    signal_error (connection, ECONNREFUSED);
    return;
  }
  GNUNET_assert (GNUNET_NETWORK_fdset_isset (tc->read_ready, connection->sock));
RETRY:
  ret = GNUNET_NETWORK_socket_recv (connection->sock, buffer, connection->max);
  if (ret == -1)
  {
    if (errno == EINTR)
      goto RETRY;
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Error receiving: %s\n", STRERROR (errno));
    signal_error (connection, errno);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "receive_ready read %u/%u bytes from `%s' (%p)!\n", (unsigned int) ret,
       connection->max, GNUNET_a2s (connection->addr, connection->addrlen), connection);
  GNUNET_assert (NULL != (receiver = connection->receiver));
  connection->receiver = NULL;
  receiver (connection->receiver_cls, buffer, ret, connection->addr, connection->addrlen, 0);
}


/**
 * This function is called after establishing a connection either has
 * succeeded or timed out.  Note that it is possible that the attempt
 * timed out and that we're immediately retrying.  If we are retrying,
 * we need to wait again (or timeout); if we succeeded, we need to
 * wait for data (or timeout).
 *
 * @param cls our connection handle
 * @param tc task context describing why we are here
 */
static void
receive_again (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CONNECTION_Handle *connection = cls;
  struct GNUNET_TIME_Absolute now;

  connection->read_task = GNUNET_SCHEDULER_NO_TASK;
  if (connection->sock == NULL)
  {
    /* not connected and no longer trying */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Receive encounters error, connection closed (%p)...\n", connection);
    signal_error (connection, ECONNREFUSED);
    return;
  }
  now = GNUNET_TIME_absolute_get ();
  if ((now.abs_value > connection->receive_timeout.abs_value) ||
      (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN)))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Receive encounters error: time out (%p)...\n", connection);
    signal_timeout (connection);
    return;
  }
  GNUNET_assert (connection->sock != NULL);
  /* connect succeeded, wait for data! */
  connection->read_task =
      GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_absolute_get_remaining
                                     (connection->receive_timeout), connection->sock,
                                     &receive_ready, connection);
}


/**
 * Receive data from the given connection.  Note that this function will
 * call "receiver" asynchronously using the scheduler.  It will
 * "immediately" return.  Note that there MUST only be one active
 * receive call per connection at any given point in time (so do not
 * call receive again until the receiver callback has been invoked).
 *
 * @param connection connection handle
 * @param max maximum number of bytes to read
 * @param timeout maximum amount of time to wait (use -1 for "forever")
 * @param receiver function to call with received data
 * @param receiver_cls closure for receiver
 */
void
GNUNET_CONNECTION_receive (struct GNUNET_CONNECTION_Handle *connection, size_t max,
                           struct GNUNET_TIME_Relative timeout,
                           GNUNET_CONNECTION_Receiver receiver,
                           void *receiver_cls)
{
  struct GNUNET_SCHEDULER_TaskContext tc;

  GNUNET_assert ((connection->read_task == GNUNET_SCHEDULER_NO_TASK) &&
                 (0 == (connection->ccs & COCO_RECEIVE_AGAIN)) &&
                 (connection->receiver == NULL));
  connection->receiver = receiver;
  connection->receiver_cls = receiver_cls;
  connection->receive_timeout = GNUNET_TIME_relative_to_absolute (timeout);
  connection->max = max;
  if (connection->sock != NULL)
  {
    memset (&tc, 0, sizeof (tc));
    tc.reason = GNUNET_SCHEDULER_REASON_PREREQ_DONE;
    receive_again (connection, &tc);
    return;
  }
  if ((connection->dns_active == NULL) && (connection->ap_head == NULL))
  {
    receiver (receiver_cls, NULL, 0, NULL, 0, ETIMEDOUT);
    return;
  }
  connection->ccs += COCO_RECEIVE_AGAIN;
}


/**
 * Configure this connection to ignore shutdown signals.
 *
 * @param connection connection handle
 * @param do_ignore GNUNET_YES to ignore, GNUNET_NO to restore default
 */
void
GNUNET_CONNECTION_ignore_shutdown (struct GNUNET_CONNECTION_Handle *connection,
                                   int do_ignore)
{
  connection->ignore_shutdown = do_ignore;
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
  if (connection->read_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_assert (connection == GNUNET_SCHEDULER_cancel (connection->read_task));
    connection->read_task = GNUNET_SCHEDULER_NO_TASK;
  }
  else
  {
    GNUNET_assert (0 != (connection->ccs & COCO_RECEIVE_AGAIN));
    connection->ccs -= COCO_RECEIVE_AGAIN;
  }
  connection->receiver = NULL;
  return connection->receiver_cls;
}


/**
 * Try to call the transmit notify method (check if we do
 * have enough space available first)!
 *
 * @param connection connection for which we should do this processing
 * @return GNUNET_YES if we were able to call notify
 */
static int
process_notify (struct GNUNET_CONNECTION_Handle *connection)
{
  size_t used;
  size_t avail;
  size_t size;
  GNUNET_CONNECTION_TransmitReadyNotify notify;

  GNUNET_assert (connection->write_task == GNUNET_SCHEDULER_NO_TASK);
  if (NULL == (notify = connection->nth.notify_ready))
    return GNUNET_NO;
  used = connection->write_buffer_off - connection->write_buffer_pos;
  avail = connection->write_buffer_size - used;
  size = connection->nth.notify_size;
  if (size > avail)
    return GNUNET_NO;
  connection->nth.notify_ready = NULL;
  if (connection->write_buffer_size - connection->write_buffer_off < size)
  {
    /* need to compact */
    memmove (connection->write_buffer, &connection->write_buffer[connection->write_buffer_pos],
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
 * @param cls the 'struct GNUNET_CONNECTION_Handle'
 * @param tc scheduler context
 */
static void
transmit_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CONNECTION_Handle *connection = cls;
  GNUNET_CONNECTION_TransmitReadyNotify notify;

  connection->nth.timeout_task = GNUNET_SCHEDULER_NO_TASK;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Transmit to `%s:%u/%s' fails, time out reached (%p).\n",
       connection->hostname,
       connection->port, GNUNET_a2s (connection->addr, connection->addrlen), connection);
  GNUNET_assert (0 != (connection->ccs & COCO_TRANSMIT_READY));
  connection->ccs -= COCO_TRANSMIT_READY;     /* remove request */
  notify = connection->nth.notify_ready;
  connection->nth.notify_ready = NULL;
  notify (connection->nth.notify_ready_cls, 0, NULL);
}


/**
 * Task invoked by the scheduler when we failed to connect
 * at the time of being asked to transmit.
 *
 * This task notifies the client about the error.
 *
 * @param cls the 'struct GNUNET_CONNECTION_Handle'
 * @param tc scheduler context
 */
static void
connect_error (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CONNECTION_Handle *connection = cls;
  GNUNET_CONNECTION_TransmitReadyNotify notify;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Transmission request of size %u fails (%s/%u), connection failed (%p).\n",
       connection->nth.notify_size, connection->hostname, connection->port, connection);
  connection->write_task = GNUNET_SCHEDULER_NO_TASK;
  notify = connection->nth.notify_ready;
  connection->nth.notify_ready = NULL;
  notify (connection->nth.notify_ready_cls, 0, NULL);
}


/**
 * FIXME
 *
 * @param connection FIXME
 */
static void
transmit_error (struct GNUNET_CONNECTION_Handle *connection)
{
  GNUNET_CONNECTION_TransmitReadyNotify notify;

  if (NULL != connection->sock)
  {
    GNUNET_NETWORK_socket_shutdown (connection->sock, SHUT_RDWR);
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (connection->sock));
    connection->sock = NULL;
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == connection->write_task);
  }
  if (connection->read_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (connection->read_task);
    connection->read_task = GNUNET_SCHEDULER_NO_TASK;
    signal_timeout (connection);
    return;
  }
  if (connection->nth.notify_ready == NULL)
    return;                     /* nobody to tell about it */
  notify = connection->nth.notify_ready;
  connection->nth.notify_ready = NULL;
  notify (connection->nth.notify_ready_cls, 0, NULL);
}


/**
 * See if we are now connected.  If not, wait longer for
 * connect to succeed.  If connected, we should be able
 * to write now as well, unless we timed out.
 *
 * @param cls our connection handle
 * @param tc task context describing why we are here
 */
static void
transmit_ready (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CONNECTION_Handle *connection = cls;
  GNUNET_CONNECTION_TransmitReadyNotify notify;
  ssize_t ret;
  size_t have;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "transmit_ready running (%p).\n", connection);
  GNUNET_assert (connection->write_task != GNUNET_SCHEDULER_NO_TASK);
  connection->write_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_assert (connection->nth.timeout_task == GNUNET_SCHEDULER_NO_TASK);
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    if ((connection->ignore_shutdown == GNUNET_YES) && (NULL != connection->sock))
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
         GNUNET_a2s (connection->addr, connection->addrlen), connection);
    notify = connection->nth.notify_ready;
    GNUNET_assert (NULL != notify);
    connection->nth.notify_ready = NULL;
    notify (connection->nth.notify_ready_cls, 0, NULL);
    return;
  }
  GNUNET_assert (NULL != connection->sock);
  if (tc->write_ready == NULL)
  {
    /* special circumstances (in particular,
     * PREREQ_DONE after connect): not yet ready to write,
     * but no "fatal" error either.  Hence retry.  */
    goto SCHEDULE_WRITE;
  }
  if (!GNUNET_NETWORK_fdset_isset (tc->write_ready, connection->sock))
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         _
         ("Could not satisfy pending transmission request, socket closed or connect failed (%p).\n"),
         connection);
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == connection->write_task);
    transmit_error (connection);
    return;                     /* connect failed for good, we're finished */
  }
  GNUNET_assert (connection->write_buffer_off >= connection->write_buffer_pos);
  if ((connection->nth.notify_ready != NULL) &&
      (connection->write_buffer_size < connection->nth.notify_size))
  {
    connection->write_buffer =
        GNUNET_realloc (connection->write_buffer, connection->nth.notify_size);
    connection->write_buffer_size = connection->nth.notify_size;
  }
  process_notify (connection);
  have = connection->write_buffer_off - connection->write_buffer_pos;
  if (have == 0)
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
  if (ret == -1)
  {
    if (errno == EINTR)
      goto RETRY;
    LOG_STRERROR (GNUNET_ERROR_TYPE_DEBUG, "send");
    if (GNUNET_SCHEDULER_NO_TASK != connection->write_task)
    {
      GNUNET_SCHEDULER_cancel (connection->write_task);
      connection->write_task = GNUNET_SCHEDULER_NO_TASK;
    }
    transmit_error (connection);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "transmit_ready transmitted %u/%u bytes to `%s' (%p)\n",
       (unsigned int) ret, have, GNUNET_a2s (connection->addr, connection->addrlen), connection);
  connection->write_buffer_pos += ret;
  if (connection->write_buffer_pos == connection->write_buffer_off)
  {
    /* transmitted all pending data */
    connection->write_buffer_pos = 0;
    connection->write_buffer_off = 0;
  }
  if ((connection->write_buffer_off == 0) && (NULL == connection->nth.notify_ready))
    return;                     /* all data sent! */
  /* not done writing, schedule more */
SCHEDULE_WRITE:
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Re-scheduling transmit_ready (more to do) (%p).\n", connection);
  have = connection->write_buffer_off - connection->write_buffer_pos;
  GNUNET_assert ((connection->nth.notify_ready != NULL) || (have > 0));
  if (connection->write_task == GNUNET_SCHEDULER_NO_TASK)
    connection->write_task =
        GNUNET_SCHEDULER_add_write_net ((connection->nth.notify_ready ==
                                         NULL) ? GNUNET_TIME_UNIT_FOREVER_REL :
                                        GNUNET_TIME_absolute_get_remaining
                                        (connection->nth.transmit_timeout),
                                        connection->sock, &transmit_ready, connection);
}


/**
 * Ask the connection to call us once the specified number of bytes
 * are free in the transmission buffer.  May call the notify
 * method immediately if enough space is available.
 *
 * @param connection connection
 * @param size number of bytes to send
 * @param timeout after how long should we give up (and call
 *        notify with buf NULL and size 0)?
 * @param notify function to call
 * @param notify_cls closure for notify
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
  if (connection->nth.notify_ready != NULL)
  {
    GNUNET_assert (0);
    return NULL;
  }
  GNUNET_assert (notify != NULL);
  GNUNET_assert (size < GNUNET_SERVER_MAX_MESSAGE_SIZE);
  GNUNET_assert (connection->write_buffer_off <= connection->write_buffer_size);
  GNUNET_assert (connection->write_buffer_pos <= connection->write_buffer_size);
  GNUNET_assert (connection->write_buffer_pos <= connection->write_buffer_off);
  connection->nth.notify_ready = notify;
  connection->nth.notify_ready_cls = notify_cls;
  connection->nth.connection = connection;
  connection->nth.notify_size = size;
  connection->nth.transmit_timeout = GNUNET_TIME_relative_to_absolute (timeout);
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == connection->nth.timeout_task);
  if ((connection->sock == NULL) && (connection->ap_head == NULL) &&
      (connection->dns_active == NULL))
  {
    if (connection->write_task != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (connection->write_task);
    connection->write_task = GNUNET_SCHEDULER_add_now (&connect_error, connection);
    return &connection->nth;
  }
  if (GNUNET_SCHEDULER_NO_TASK != connection->write_task)
    return &connection->nth;
  if (connection->sock != NULL)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Scheduling transmit_ready (%p).\n", connection);
    connection->write_task =
        GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_absolute_get_remaining
                                        (connection->nth.transmit_timeout),
                                        connection->sock, &transmit_ready, connection);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "CCS-Scheduling transmit_ready, adding timeout task (%p).\n", connection);
    connection->ccs |= COCO_TRANSMIT_READY;
    connection->nth.timeout_task =
        GNUNET_SCHEDULER_add_delayed (timeout, &transmit_timeout, connection);
  }
  return &connection->nth;
}


/**
 * Cancel the specified transmission-ready notification.
 *
 * @param th notification to cancel
 */
void
GNUNET_CONNECTION_notify_transmit_ready_cancel (struct
                                                GNUNET_CONNECTION_TransmitHandle
                                                *th)
{
  GNUNET_assert (th->notify_ready != NULL);
  if (0 != (th->connection->ccs & COCO_TRANSMIT_READY))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "notify_transmit_ready_cancel cancels timeout_task (%p)\n", th);
    GNUNET_SCHEDULER_cancel (th->timeout_task);
    th->timeout_task = GNUNET_SCHEDULER_NO_TASK;
    th->connection->ccs -= COCO_TRANSMIT_READY;
  }
  else
  {
    if (th->connection->write_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (th->connection->write_task);
      th->connection->write_task = GNUNET_SCHEDULER_NO_TASK;
    }
  }
  th->notify_ready = NULL;
}

/* end of connection.c */
