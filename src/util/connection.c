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

#define DEBUG_CONNECTION GNUNET_NO


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
  COCO_TRANSMIT_READY = 2,

    /**
     * Call "destroy_continuation".
     */
  COCO_DESTROY_CONTINUATION = 4
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
   * Our socket handle.
   */
  struct GNUNET_CONNECTION_Handle *sh;

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
  struct GNUNET_CONNECTION_Handle *h;

  /**
   * Lenth of addr.
   */
  socklen_t addrlen;

  /**
   * Task waiting for the socket to finish connecting.
   */
  GNUNET_SCHEDULER_TaskIdentifier task;
};


/**
 * @brief handle for a network socket
 */
struct GNUNET_CONNECTION_Handle
{

  /**
   * Scheduler that was used for the connect task.
   */
  struct GNUNET_SCHEDULER_Handle *sched;

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
   * Pointer to the hostname if socket was
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
   * Size of our write buffer.
   */
  size_t write_buffer_size;

  /**
   * Current write-offset in write buffer (where
   * would we write next).
   */
  size_t write_buffer_off;

  /**
   * Current read-offset in write buffer (how many
   * bytes have already been send).
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
   * Port to connect to.
   */
  uint16_t port;

};


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
struct GNUNET_CONNECTION_Handle *
GNUNET_CONNECTION_create_from_existing (struct GNUNET_SCHEDULER_Handle
                                        *sched,
                                        struct GNUNET_NETWORK_Handle
                                        *osSocket, size_t maxbuf)
{
  struct GNUNET_CONNECTION_Handle *ret;
  ret = GNUNET_malloc (sizeof (struct GNUNET_CONNECTION_Handle) + maxbuf);
  ret->write_buffer = (char *) &ret[1];
  ret->write_buffer_size = maxbuf;
  ret->sock = osSocket;
  ret->sched = sched;
  return ret;
}


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
 * @return the socket handle, NULL on error
 */
struct GNUNET_CONNECTION_Handle *
GNUNET_CONNECTION_create_from_accept (struct GNUNET_SCHEDULER_Handle
                                      *sched,
                                      GNUNET_CONNECTION_AccessCheck access,
                                      void *access_cls,
                                      struct GNUNET_NETWORK_Handle *lsock,
                                      size_t maxbuf)
{
  struct GNUNET_CONNECTION_Handle *ret;
  char addr[32];
  socklen_t addrlen;
  struct GNUNET_NETWORK_Handle *sock;
  int aret;
  struct sockaddr_in *v4;
  struct sockaddr_in6 *v6;
  struct sockaddr *sa;
  void *uaddr;

  addrlen = sizeof (addr);
  sock =
    GNUNET_NETWORK_socket_accept (lsock, (struct sockaddr *) &addr, &addrlen);
  if (NULL == sock)
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "accept");
      return NULL;
    }
  if (addrlen > sizeof (addr))
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

  if ((access != NULL) &&
      (GNUNET_YES != (aret = access (access_cls, uaddr, addrlen))))
    {
      if (aret == GNUNET_NO)
        GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                    _("Access denied to `%s'\n"),
                    GNUNET_a2s (uaddr, addrlen));
      GNUNET_break (GNUNET_OK ==
                    GNUNET_NETWORK_socket_shutdown (sock, SHUT_RDWR));
      GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (sock));
      GNUNET_free (uaddr);
      return NULL;
    }
  ret = GNUNET_malloc (sizeof (struct GNUNET_CONNECTION_Handle) + maxbuf);
  ret->write_buffer = (char *) &ret[1];
  ret->write_buffer_size = maxbuf;
  ret->addr = uaddr;
  ret->addrlen = addrlen;
  ret->sock = sock;
  ret->sched = sched;
#if DEBUG_CONNECTION
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Accepting connection from `%s': %p\n"),
              GNUNET_a2s (uaddr, addrlen), ret);
#endif
  return ret;
}

/**
 * Obtain the network address of the other party.
 *
 * @param sock the client to get the address for
 * @param addr where to store the address
 * @param addrlen where to store the length of the address
 * @return GNUNET_OK on success
 */
int
GNUNET_CONNECTION_get_address (struct GNUNET_CONNECTION_Handle *sock,
                               void **addr, size_t * addrlen)
{
  if ((sock->addr == NULL) || (sock->addrlen == 0))
    return GNUNET_NO;
  *addr = GNUNET_malloc (sock->addrlen);
  memcpy (*addr, sock->addr, sock->addrlen);
  *addrlen = sock->addrlen;
  return GNUNET_OK;
}


/**
 * It is time to re-try connecting.
 * 
 * @param cls the handle for the connection that should be re-tried
 * @param tc unused scheduler taks context
 */
static void
retry_connect_continuation (void *cls,
                            const struct GNUNET_SCHEDULER_TaskContext *tc);


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
 * Scheduler let us know that the connect task is finished (or was
 * cancelled due to shutdown).  Now really clean up.
 *
 * @param cls our "struct GNUNET_CONNECTION_Handle *"
 * @param tc unused
 */
static void
destroy_continuation (void *cls,
                      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CONNECTION_Handle *sock = cls;
  GNUNET_CONNECTION_TransmitReadyNotify notify;

  GNUNET_assert (sock->dns_active == NULL);
  if (0 != (sock->ccs & COCO_TRANSMIT_READY))
    {
#if DEBUG_CONNECTION
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Destroy waits for CCS-TR to be done (%p)\n", sock);
#endif
      sock->ccs |= COCO_DESTROY_CONTINUATION;
      return;
    }
  if (sock->write_task != GNUNET_SCHEDULER_NO_TASK)
    {
#if DEBUG_CONNECTION
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Destroy waits for write_task to be done (%p)\n", sock);
#endif
      GNUNET_SCHEDULER_add_after (sock->sched,
                                  sock->write_task,
                                  &destroy_continuation, sock);
      return;
    }
  if (0 != (sock->ccs & COCO_RECEIVE_AGAIN))
    {
      sock->ccs |= COCO_DESTROY_CONTINUATION;
      return;
    }
  if (sock->sock != NULL)
    {
#if DEBUG_CONNECTION
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Shutting down socket (%p)\n", sock);
#endif
      GNUNET_NETWORK_socket_shutdown (sock->sock, SHUT_RDWR);
    }
  if (sock->read_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_add_after (sock->sched,
                                  sock->read_task,
                                  &destroy_continuation, sock);
      return;
    }
#if DEBUG_CONNECTION
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Destroy actually runs (%p)!\n", sock);
#endif
  GNUNET_assert (sock->nth.timeout_task == GNUNET_SCHEDULER_NO_TASK);
  GNUNET_assert (sock->ccs == COCO_NONE);
  if (NULL != (notify = sock->nth.notify_ready))
    {
      sock->nth.notify_ready = NULL;
      notify (sock->nth.notify_ready_cls, 0, NULL);
    }
  if (sock->sock != NULL)
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (sock->sock));
  GNUNET_free_non_null (sock->addr);
  GNUNET_free_non_null (sock->hostname);
#if DEBUG_CONNECTION
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Freeing memory of connection %p.\n", sock);
#endif
  GNUNET_free (sock);
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
transmit_ready (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * We've failed for good to establish a connection.
 *
 * @param h the connection we tried to establish
 */
static void
connect_fail_continuation (struct GNUNET_CONNECTION_Handle *h)
{
#if DEBUG_CONNECTION
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Failed to establish TCP connection to `%s:%u', no further addresses to try (%p).\n",
              h->hostname, h->port, h);
#endif
  /* connect failed / timed out */
  GNUNET_break (h->ap_head == NULL);
  GNUNET_break (h->ap_tail == NULL);
  GNUNET_break (h->dns_active == GNUNET_NO);
  GNUNET_break (h->sock == NULL);

  /* FIXME: trigger delayed reconnect attempt... */
  /* trigger jobs that used to wait on "connect_task" */
  if (0 != (h->ccs & COCO_RECEIVE_AGAIN))
    {
#if DEBUG_CONNECTION
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "connect_timeout_continuation triggers receive_again (%p)\n",
                  h);
#endif
      h->ccs -= COCO_RECEIVE_AGAIN;
      h->read_task = GNUNET_SCHEDULER_add_after (h->sched,
                                                 GNUNET_SCHEDULER_NO_TASK,
                                                 &receive_again, h);
    }
  if (0 != (h->ccs & COCO_TRANSMIT_READY))
    {
#if DEBUG_CONNECTION
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "connect_timeout_continuation cancels timeout_task, triggers transmit_ready (%p)\n",
                  h);
#endif
      GNUNET_assert (h->nth.timeout_task != GNUNET_SCHEDULER_NO_TASK);
      GNUNET_SCHEDULER_cancel (h->sched, h->nth.timeout_task);
      h->nth.timeout_task = GNUNET_SCHEDULER_NO_TASK;
      h->ccs -= COCO_TRANSMIT_READY;
      h->write_task = GNUNET_SCHEDULER_add_after (h->sched,
                                                  GNUNET_SCHEDULER_NO_TASK,
                                                  &transmit_ready, h);
    }
  if (0 != (h->ccs & COCO_DESTROY_CONTINUATION))
    {
#if DEBUG_CONNECTION
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "connect_timeout_continuation runs destroy_continuation (%p)\n",
                  h);
#endif
      h->ccs -= COCO_DESTROY_CONTINUATION;
      GNUNET_SCHEDULER_add_continuation (h->sched,
                                         &destroy_continuation,
                                         h, GNUNET_SCHEDULER_REASON_TIMEOUT);
    }
}


/**
 * We've succeeded in establishing a connection.
 *
 * @param h the connection we tried to establish
 */
static void
connect_success_continuation (struct GNUNET_CONNECTION_Handle *h)
{
#if DEBUG_CONNECTION
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connection to `%s' succeeded! (%p)\n",
              GNUNET_a2s (h->addr, h->addrlen), h);
#endif
  /* trigger jobs that waited for the connection */
  if (0 != (h->ccs & COCO_RECEIVE_AGAIN))
    {
#if DEBUG_CONNECTION
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "connect_success_continuation runs receive_again (%p)\n",
                  h);
#endif
      h->ccs -= COCO_RECEIVE_AGAIN;
      h->read_task = GNUNET_SCHEDULER_add_after (h->sched,
                                                 GNUNET_SCHEDULER_NO_TASK,
                                                 &receive_again, h);
    }
  if (0 != (h->ccs & COCO_TRANSMIT_READY))
    {
#if DEBUG_CONNECTION
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "connect_success_continuation runs transmit_ready, cancels timeout_task (%p)\n",
                  h);
#endif
      GNUNET_assert (h->nth.timeout_task != GNUNET_SCHEDULER_NO_TASK);
      GNUNET_SCHEDULER_cancel (h->sched, h->nth.timeout_task);
      h->nth.timeout_task = GNUNET_SCHEDULER_NO_TASK;
      h->ccs -= COCO_TRANSMIT_READY;
      h->write_task =
        GNUNET_SCHEDULER_add_write_net (h->sched,
                                        GNUNET_TIME_absolute_get_remaining
                                        (h->nth.transmit_timeout), h->sock,
                                        &transmit_ready, h);
    }
  if (0 != (h->ccs & COCO_DESTROY_CONTINUATION))
    {
#if DEBUG_CONNECTION
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "connect_success_continuation runs destroy_continuation (%p)\n",
                  h);
#endif
      h->ccs -= COCO_DESTROY_CONTINUATION;
      GNUNET_SCHEDULER_add_continuation (h->sched,
                                         &destroy_continuation,
                                         h,
                                         GNUNET_SCHEDULER_REASON_PREREQ_DONE);
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
  struct GNUNET_CONNECTION_Handle *h = ap->h;
  struct AddressProbe *pos;
  int error;
  unsigned int len;

  GNUNET_CONTAINER_DLL_remove (h->ap_head, h->ap_tail, ap);
  len = sizeof (error);
  errno = 0;
  error = 0;
  if ((0 == (tc->reason & GNUNET_SCHEDULER_REASON_WRITE_READY)) ||
      (GNUNET_OK !=
       GNUNET_NETWORK_socket_getsockopt (ap->sock, SOL_SOCKET, SO_ERROR,
                                         &error, &len)) || (error != 0)
      || (errno != 0))
    {
      GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (ap->sock));
      GNUNET_free (ap);
      if ((NULL == h->ap_head) && (h->dns_active == GNUNET_NO))
        connect_fail_continuation (h);
      return;
    }
  h->sock = ap->sock;
  GNUNET_assert (h->addr == NULL);
  h->addr = GNUNET_malloc (ap->addrlen);
  memcpy (h->addr, ap->addr, ap->addrlen);
  h->addrlen = ap->addrlen;
  GNUNET_free (ap);
  /* cancel all other attempts */
  while (NULL != (pos = h->ap_head))
    {
      GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (pos->sock));
      GNUNET_SCHEDULER_cancel (h->sched, pos->task);
      GNUNET_CONTAINER_DLL_remove (h->ap_head, h->ap_tail, pos);
      GNUNET_free (pos);
    }
  connect_success_continuation (h);
}


/**
 * Try to establish a socket connection given the specified address.
 * This function is called by the resolver once we have a DNS reply.
 *
 * @param cls our "struct GNUNET_CONNECTION_Handle *"
 * @param addr address to try, NULL for "last call"
 * @param addrlen length of addr
 */
static void
try_connect_using_address (void *cls,
                           const struct sockaddr *addr, socklen_t addrlen)
{
  struct GNUNET_CONNECTION_Handle *h = cls;
  struct AddressProbe *ap;
  struct GNUNET_TIME_Relative delay;

  if (addr == NULL)
    {
      h->dns_active = NULL;
      if (NULL == h->ap_head)
        connect_fail_continuation (h);
      return;
    }
  if (h->sock != NULL)
    return;                     /* already connected */
  /* try to connect */
#if DEBUG_CONNECTION
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Trying to connect using address `%s:%u/%s:%u'\n",
              h->hostname, h->port, GNUNET_a2s (addr, addrlen), h->port);
#endif
  ap = GNUNET_malloc (sizeof (struct AddressProbe) + addrlen);
  ap->addr = (const struct sockaddr *) &ap[1];
  memcpy (&ap[1], addr, addrlen);
  ap->addrlen = addrlen;
  ap->h = h;

  switch (ap->addr->sa_family)
    {
    case AF_INET:
      ((struct sockaddr_in *) ap->addr)->sin_port = htons (h->port);
      break;
    case AF_INET6:
      ((struct sockaddr_in6 *) ap->addr)->sin6_port = htons (h->port);
      break;
    default:
      GNUNET_break (0);
      GNUNET_free (ap);
      return;                   /* not supported by us */
    }
  ap->sock =
    GNUNET_NETWORK_socket_create (ap->addr->sa_family, SOCK_STREAM, 0);
  if (ap->sock == NULL)
    {
      GNUNET_free (ap);
      return;                   /* not supported by OS */
    }
#if DEBUG_CONNECTION
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Trying to connect to `%s' (%p)\n"),
              GNUNET_a2s (ap->addr, ap->addrlen), h);
#endif
  if ((GNUNET_OK != GNUNET_NETWORK_socket_connect (ap->sock,
                                                   ap->addr,
                                                   ap->addrlen)) &&
      (errno != EINPROGRESS))
    {
      /* maybe refused / unsupported address, try next */
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_INFO, "connect");
      GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (ap->sock));
      GNUNET_free (ap);
      return;
    }
  GNUNET_CONTAINER_DLL_insert (h->ap_head, h->ap_tail, ap);
  delay = GNUNET_CONNECTION_CONNECT_RETRY_TIMEOUT;
  if (h->nth.notify_ready != NULL)
    delay = GNUNET_TIME_relative_min (delay,
                                      GNUNET_TIME_absolute_get_remaining (h->
                                                                          nth.
                                                                          transmit_timeout));
  if (h->receiver != NULL)
    delay = GNUNET_TIME_relative_min (delay,
                                      GNUNET_TIME_absolute_get_remaining (h->
                                                                          receive_timeout));
  ap->task =
    GNUNET_SCHEDULER_add_write_net (h->sched, 
                                    delay, ap->sock,
                                    &connect_probe_continuation, ap);
}


/**
 * It is time to re-try connecting.
 * 
 * @param cls the handle for the connection that should be re-tried
 * @param tc unused scheduler taks context
 */
static void
retry_connect_continuation (void *cls,
                            const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CONNECTION_Handle *sock = cls;

  GNUNET_assert (sock->dns_active == NULL);
  sock->dns_active = GNUNET_RESOLVER_ip_get (sock->sched,
					     sock->cfg,
					     sock->hostname,
					     AF_UNSPEC,
					     GNUNET_CONNECTION_CONNECT_RETRY_TIMEOUT,
					     &try_connect_using_address, sock);
}


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
struct GNUNET_CONNECTION_Handle *
GNUNET_CONNECTION_create_from_connect (struct GNUNET_SCHEDULER_Handle *sched,
                                       const struct
                                       GNUNET_CONFIGURATION_Handle *cfg,
                                       const char *hostname, uint16_t port,
                                       size_t maxbuf)
{
  struct GNUNET_CONNECTION_Handle *ret;

  GNUNET_assert (0 < strlen (hostname));        /* sanity check */
  ret = GNUNET_malloc (sizeof (struct GNUNET_CONNECTION_Handle) + maxbuf);
  ret->cfg = cfg;
  ret->sched = sched;
  ret->write_buffer = (char *) &ret[1];
  ret->write_buffer_size = maxbuf;
  ret->port = port;
  ret->hostname = GNUNET_strdup (hostname);
  retry_connect_continuation (ret, NULL);
  return ret;
}


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
struct GNUNET_CONNECTION_Handle *
GNUNET_CONNECTION_create_from_sockaddr (struct GNUNET_SCHEDULER_Handle
                                        *sched, int af_family,
                                        const struct sockaddr *serv_addr,
                                        socklen_t addrlen, size_t maxbuf)
{
  struct GNUNET_NETWORK_Handle *s;
  struct GNUNET_CONNECTION_Handle *ret;

  s = GNUNET_NETWORK_socket_create (af_family, SOCK_STREAM, 0);
  if (s == NULL)
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING |
                           GNUNET_ERROR_TYPE_BULK, "socket");
      return NULL;
    }
  if ((GNUNET_OK != GNUNET_NETWORK_socket_connect (s, serv_addr, addrlen))
      && (errno != EINPROGRESS))
    {
      /* maybe refused / unsupported address, try next */
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_INFO, "connect");
      GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (s));
      return NULL;
    }
  ret = GNUNET_CONNECTION_create_from_existing (sched, s, maxbuf);
  ret->addr = GNUNET_malloc (addrlen);
  memcpy (ret->addr, serv_addr, addrlen);
  ret->addrlen = addrlen;
#if DEBUG_CONNECTION
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Trying to connect to `%s' (%p)\n"),
              GNUNET_a2s (serv_addr, addrlen), ret);
#endif
  return ret;
}


/**
 * Check if socket is valid (no fatal errors have happened so far).
 * Note that a socket that is still trying to connect is considered
 * valid.
 *
 * @param sock socket to check
 * @return GNUNET_YES if valid, GNUNET_NO otherwise
 */
int
GNUNET_CONNECTION_check (struct GNUNET_CONNECTION_Handle *sock)
{
  if ((sock->ap_head != NULL) || (sock->dns_active != NULL))
    return GNUNET_YES;          /* still trying to connect */
  return (sock->sock == NULL) ? GNUNET_NO : GNUNET_YES;
}


/**
 * Close the socket and free associated resources. Pending
 * transmissions are simply dropped.  A pending receive call will be
 * called with an error code of "EPIPE".
 *
 * @param sock socket to destroy
 */
void
GNUNET_CONNECTION_destroy (struct GNUNET_CONNECTION_Handle *sock)
{
  if ((sock->write_buffer_off == 0) && (sock->dns_active != NULL))
    {
      GNUNET_RESOLVER_request_cancel (sock->dns_active);
      sock->dns_active = NULL;
    }
  GNUNET_assert (sock->sched != NULL);
  GNUNET_SCHEDULER_add_after (sock->sched,
                              GNUNET_SCHEDULER_NO_TASK,
                              &destroy_continuation, sock);
}


/**
 * Tell the receiver callback that a timeout was reached.
 */
static void
signal_timeout (struct GNUNET_CONNECTION_Handle *sh)
{
  GNUNET_CONNECTION_Receiver receiver;

#if DEBUG_CONNECTION
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Network signals time out to receiver (%p)!\n", sh);
#endif
  GNUNET_assert (NULL != (receiver = sh->receiver));
  sh->receiver = NULL;
  receiver (sh->receiver_cls, NULL, 0, NULL, 0, 0);
}


/**
 * Tell the receiver callback that we had an IO error.
 */
static void
signal_error (struct GNUNET_CONNECTION_Handle *sh, int errcode)
{
  GNUNET_CONNECTION_Receiver receiver;
  GNUNET_assert (NULL != (receiver = sh->receiver));
  sh->receiver = NULL;
  receiver (sh->receiver_cls, NULL, 0, sh->addr, sh->addrlen, errcode);
}


/**
 * This function is called once we either timeout
 * or have data ready to read.
 */
static void
receive_ready (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CONNECTION_Handle *sh = cls;
  struct GNUNET_TIME_Absolute now;
  char buffer[sh->max];
  ssize_t ret;
  GNUNET_CONNECTION_Receiver receiver;

  sh->read_task = GNUNET_SCHEDULER_NO_TASK;
  now = GNUNET_TIME_absolute_get ();
  if ((now.value > sh->receive_timeout.value) ||
      (0 != (tc->reason & GNUNET_SCHEDULER_REASON_TIMEOUT)) ||
      (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN)))
    {
#if DEBUG_CONNECTION
      if (0 == (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Receive from `%s' encounters error: time out by %llums... (%p)\n",
                    GNUNET_a2s (sh->addr, sh->addrlen),
                    GNUNET_TIME_absolute_get_duration (sh->receive_timeout).
                    value, sh);
#endif
      signal_timeout (sh);
      return;
    }
  if (sh->sock == NULL)
    {
      /* connect failed for good */
#if DEBUG_CONNECTION
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Receive encounters error, socket closed... (%p)\n", sh);
#endif
      signal_error (sh, ECONNREFUSED);
      return;
    }
  GNUNET_assert (GNUNET_NETWORK_fdset_isset (tc->read_ready, sh->sock));
RETRY:
  ret = GNUNET_NETWORK_socket_recv (sh->sock, buffer, sh->max);
  if (ret == -1)
    {
      if (errno == EINTR)
        goto RETRY;
#if DEBUG_CONNECTION
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Error receiving: %s\n", STRERROR (errno));
#endif
      signal_error (sh, errno);
      return;
    }
#if DEBUG_CONNECTION
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "receive_ready read %u/%u bytes from `%s' (%p)!\n",
              (unsigned int) ret,
              sh->max, GNUNET_a2s (sh->addr, sh->addrlen), sh);
#endif
  GNUNET_assert (NULL != (receiver = sh->receiver));
  sh->receiver = NULL;
  receiver (sh->receiver_cls, buffer, ret, sh->addr, sh->addrlen, 0);
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
  struct GNUNET_CONNECTION_Handle *sh = cls;
  struct GNUNET_TIME_Absolute now;

  sh->read_task = GNUNET_SCHEDULER_NO_TASK;
  if (sh->sock == NULL)
    {
      /* not connected and no longer trying */
#if DEBUG_CONNECTION
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Receive encounters error, socket closed (%p)...\n", sh);
#endif
      signal_error (sh, ECONNREFUSED);
      return;
    }
  now = GNUNET_TIME_absolute_get ();
  if ((now.value > sh->receive_timeout.value) ||
      (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN)))
    {
#if DEBUG_CONNECTION
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Receive encounters error: time out (%p)...\n", sh);
#endif
      signal_timeout (sh);
      return;
    }
  GNUNET_assert (sh->sock != NULL);
  /* connect succeeded, wait for data! */
  sh->read_task = GNUNET_SCHEDULER_add_read_net (tc->sched,
                                                 GNUNET_TIME_absolute_get_remaining
                                                 (sh->receive_timeout),
                                                 sh->sock,
                                                 &receive_ready, sh);
}


/**
 * Receive data from the given socket.  Note that this function will
 * call "receiver" asynchronously using the scheduler.  It will
 * "immediately" return.  Note that there MUST only be one active
 * receive call per socket at any given point in time (so do not
 * call receive again until the receiver callback has been invoked).
 *
 * @param sock socket handle
 * @param max maximum number of bytes to read
 * @param timeout maximum amount of time to wait (use -1 for "forever")
 * @param receiver function to call with received data
 * @param receiver_cls closure for receiver
 */
void
GNUNET_CONNECTION_receive (struct GNUNET_CONNECTION_Handle *sock,
                           size_t max,
                           struct GNUNET_TIME_Relative timeout,
                           GNUNET_CONNECTION_Receiver receiver,
                           void *receiver_cls)
{
  struct GNUNET_SCHEDULER_TaskContext tc;

  GNUNET_assert ((sock->read_task == GNUNET_SCHEDULER_NO_TASK) &&
                 (0 == (sock->ccs & COCO_RECEIVE_AGAIN)) &&
                 (sock->receiver == NULL));
  sock->receiver = receiver;
  sock->receiver_cls = receiver_cls;
  sock->receive_timeout = GNUNET_TIME_relative_to_absolute (timeout);
  sock->max = max;
  if (sock->sock != NULL)
    {
      memset (&tc, 0, sizeof (tc));
      tc.sched = sock->sched;
      tc.reason = GNUNET_SCHEDULER_REASON_PREREQ_DONE;
      receive_again (sock, &tc);
      return;
    }
  if ((sock->dns_active == NULL) && (sock->ap_head == NULL))
    {
      receiver (receiver_cls, NULL, 0, NULL, 0, ETIMEDOUT);
      return;
    }
  sock->ccs += COCO_RECEIVE_AGAIN;
}


/**
 * Cancel receive job on the given socket.  Note that the
 * receiver callback must not have been called yet in order
 * for the cancellation to be valid.
 *
 * @param sock socket handle
 * @return closure of the original receiver callback closure
 */
void *
GNUNET_CONNECTION_receive_cancel (struct GNUNET_CONNECTION_Handle *sock)
{
  if (sock->read_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_assert (sock == GNUNET_SCHEDULER_cancel (sock->sched,
                                                      sock->read_task));
      sock->read_task = GNUNET_SCHEDULER_NO_TASK;
    }
  else
    {
      GNUNET_assert (0 != (sock->ccs & COCO_RECEIVE_AGAIN));
      sock->ccs -= COCO_RECEIVE_AGAIN;
    }
  sock->receiver = NULL;
  return sock->receiver_cls;
}


/**
 * Try to call the transmit notify method (check if we do
 * have enough space available first)!
 *
 * @param sock socket for which we should do this processing
 * @return GNUNET_YES if we were able to call notify
 */
static int
process_notify (struct GNUNET_CONNECTION_Handle *sock)
{
  size_t used;
  size_t avail;
  size_t size;
  GNUNET_CONNECTION_TransmitReadyNotify notify;

  GNUNET_assert (sock->write_task == GNUNET_SCHEDULER_NO_TASK);
  if (NULL == (notify = sock->nth.notify_ready))
    return GNUNET_NO;
  used = sock->write_buffer_off - sock->write_buffer_pos;
  avail = sock->write_buffer_size - used;
  size = sock->nth.notify_size;
  if (sock->nth.notify_size > avail)
    return GNUNET_NO;
  sock->nth.notify_ready = NULL;
  if (sock->write_buffer_size - sock->write_buffer_off < size)
    {
      /* need to compact */
      memmove (sock->write_buffer,
               &sock->write_buffer[sock->write_buffer_pos], used);
      sock->write_buffer_off -= sock->write_buffer_pos;
      sock->write_buffer_pos = 0;
    }
  GNUNET_assert (sock->write_buffer_size - sock->write_buffer_off >= size);
  size = notify (sock->nth.notify_ready_cls,
                 sock->write_buffer_size - sock->write_buffer_off,
                 &sock->write_buffer[sock->write_buffer_off]);
  sock->write_buffer_off += size;
  return GNUNET_YES;
}


/**
 * Task invoked by the scheduler when a call to transmit
 * is timing out (we never got enough buffer space to call
 * the callback function before the specified timeout
 * expired).
 *
 * This task notifies the client about the timeout.
 */
static void
transmit_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CONNECTION_Handle *sock = cls;
  GNUNET_CONNECTION_TransmitReadyNotify notify;

#if DEBUG_CONNECTION
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "transmit_timeout running (%p)\n", sock);
#endif
  sock->nth.timeout_task = GNUNET_SCHEDULER_NO_TASK;
#if DEBUG_CONNECTION
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmit to `%s:%u/%s' fails, time out reached (%p).\n",
              sock->hostname,
              sock->port, GNUNET_a2s (sock->addr, sock->addrlen), sock);
#endif
  GNUNET_assert (0 != (sock->ccs & COCO_TRANSMIT_READY));
  sock->ccs -= COCO_TRANSMIT_READY;     /* remove request */
  notify = sock->nth.notify_ready;
  sock->nth.notify_ready = NULL;
  notify (sock->nth.notify_ready_cls, 0, NULL);
}


/**
 * Task invoked by the scheduler when we failed to connect
 * at the time of being asked to transmit.
 *
 * This task notifies the client about the error.
 */
static void
connect_error (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CONNECTION_Handle *sock = cls;
  GNUNET_CONNECTION_TransmitReadyNotify notify;

#if DEBUG_CONNECTION
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmission request of size %u fails, connection failed (%p).\n",
              sock->nth.notify_size, sock);
#endif
  sock->write_task = GNUNET_SCHEDULER_NO_TASK;
  notify = sock->nth.notify_ready;
  sock->nth.notify_ready = NULL;
  notify (sock->nth.notify_ready_cls, 0, NULL);
}


static void
transmit_error (struct GNUNET_CONNECTION_Handle *sock)
{
  GNUNET_CONNECTION_TransmitReadyNotify notify;

  if (sock->nth.notify_ready == NULL)
    return;                     /* nobody to tell about it */
  notify = sock->nth.notify_ready;
  sock->nth.notify_ready = NULL;
  notify (sock->nth.notify_ready_cls, 0, NULL);
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
  struct GNUNET_CONNECTION_Handle *sock = cls;
  GNUNET_CONNECTION_TransmitReadyNotify notify;
  ssize_t ret;
  size_t have;

#if DEBUG_CONNECTION
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "transmit_ready running (%p).\n", sock);
#endif
  GNUNET_assert (sock->write_task != GNUNET_SCHEDULER_NO_TASK);
  sock->write_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_assert (sock->nth.timeout_task == GNUNET_SCHEDULER_NO_TASK);
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_TIMEOUT))
    {
#if DEBUG_CONNECTION
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Transmit to `%s' fails, time out reached (%p).\n",
                  GNUNET_a2s (sock->addr, sock->addrlen), sock);
#endif
      notify = sock->nth.notify_ready;
      sock->nth.notify_ready = NULL;
      notify (sock->nth.notify_ready_cls, 0, NULL);
      return;
    }
  GNUNET_assert (NULL != sock->sock);
  if (tc->write_ready == NULL)
    {
      /* special circumstances (in particular,
         PREREQ_DONE after connect): not yet ready to write,
         but no "fatal" error either.  Hence retry.  */
      goto SCHEDULE_WRITE;
    }
  if (!GNUNET_NETWORK_fdset_isset (tc->write_ready, sock->sock))
    {
#if DEBUG_CONNECTION
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _
                  ("Could not satisfy pending transmission request, socket closed or connect failed (%p).\n"),
                  sock);
#endif
      if (NULL != sock->sock)
        {
          GNUNET_NETWORK_socket_shutdown (sock->sock, SHUT_RDWR);
          GNUNET_break (GNUNET_OK ==
                        GNUNET_NETWORK_socket_close (sock->sock));
          sock->sock = NULL;
        }
      transmit_error (sock);
      return;                   /* connect failed for good, we're finished */
    }
  GNUNET_assert (sock->write_buffer_off >= sock->write_buffer_pos);
  process_notify (sock);
  have = sock->write_buffer_off - sock->write_buffer_pos;
  if (have == 0)
    {
      /* no data ready for writing, terminate write loop */
      return;
    }
  GNUNET_assert (have <= sock->write_buffer_size);
  GNUNET_assert (have + sock->write_buffer_pos <= sock->write_buffer_size);
  GNUNET_assert (sock->write_buffer_pos <= sock->write_buffer_size);
RETRY:
  ret = GNUNET_NETWORK_socket_send (sock->sock,
                                    &sock->write_buffer[sock->
                                                        write_buffer_pos],
                                    have);
  if (ret == -1)
    {
      if (errno == EINTR)
        goto RETRY;
#if DEBUG_CONNECTION
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_DEBUG, "send");
#endif
      GNUNET_NETWORK_socket_shutdown (sock->sock, SHUT_RDWR);
      GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (sock->sock));
      sock->sock = NULL;
      transmit_error (sock);
      return;
    }
#if DEBUG_CONNECTION
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "transmit_ready transmitted %u/%u bytes to `%s' (%p)\n",
              (unsigned int) ret,
              have, GNUNET_a2s (sock->addr, sock->addrlen), sock);
#endif
  sock->write_buffer_pos += ret;
  if (sock->write_buffer_pos == sock->write_buffer_off)
    {
      /* transmitted all pending data */
      sock->write_buffer_pos = 0;
      sock->write_buffer_off = 0;
    }
  if ((sock->write_buffer_off == 0) && (NULL == sock->nth.notify_ready))
    return;                     /* all data sent! */
  /* not done writing, schedule more */
SCHEDULE_WRITE:
#if DEBUG_CONNECTION
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Re-scheduling transmit_ready (more to do) (%p).\n", sock);
#endif
  if (sock->write_task == GNUNET_SCHEDULER_NO_TASK)
    sock->write_task =
      GNUNET_SCHEDULER_add_write_net (tc->sched,
                                      GNUNET_TIME_absolute_get_remaining
                                      (sock->nth.transmit_timeout),
                                      sock->sock, &transmit_ready, sock);
}


/**
 * Ask the socket to call us once the specified number of bytes
 * are free in the transmission buffer.  May call the notify
 * method immediately if enough space is available.
 *
 * @param sock socket
 * @param size number of bytes to send
 * @param timeout after how long should we give up (and call
 *        notify with buf NULL and size 0)?
 * @param notify function to call
 * @param notify_cls closure for notify
 * @return non-NULL if the notify callback was queued,
 *         NULL if we are already going to notify someone else (busy)
 */
struct GNUNET_CONNECTION_TransmitHandle *
GNUNET_CONNECTION_notify_transmit_ready (struct GNUNET_CONNECTION_Handle
                                         *sock, size_t size,
                                         struct GNUNET_TIME_Relative timeout,
                                         GNUNET_CONNECTION_TransmitReadyNotify
                                         notify, void *notify_cls)
{
  if (sock->nth.notify_ready != NULL)
    return NULL;
  GNUNET_assert (notify != NULL);
  GNUNET_assert (sock->write_buffer_size >= size);
  GNUNET_assert (sock->write_buffer_off <= sock->write_buffer_size);
  GNUNET_assert (sock->write_buffer_pos <= sock->write_buffer_size);
  GNUNET_assert (sock->write_buffer_pos <= sock->write_buffer_off);
  sock->nth.notify_ready = notify;
  sock->nth.notify_ready_cls = notify_cls;
  sock->nth.sh = sock;
  sock->nth.notify_size = size;
  sock->nth.transmit_timeout = GNUNET_TIME_relative_to_absolute (timeout);
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == sock->nth.timeout_task);
  if ((sock->sock == NULL) &&
      (sock->ap_head == NULL) && (sock->dns_active == NULL))
    {
      sock->write_task = GNUNET_SCHEDULER_add_delayed (sock->sched,
                                                       GNUNET_TIME_UNIT_ZERO,
                                                       &connect_error, sock);
      return &sock->nth;
    }
  if (GNUNET_SCHEDULER_NO_TASK != sock->write_task)
    return &sock->nth;
  if (sock->sock != NULL)
    {
#if DEBUG_CONNECTION
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Scheduling transmit_ready (%p).\n", sock);
#endif
      sock->write_task = GNUNET_SCHEDULER_add_write_net (sock->sched,
                                                         GNUNET_TIME_absolute_get_remaining
                                                         (sock->nth.
                                                          transmit_timeout),
                                                         sock->sock,
                                                         &transmit_ready,
                                                         sock);
    }
  else
    {
#if DEBUG_CONNECTION
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "CCS-Scheduling transmit_ready, adding timeout task (%p).\n",
                  sock);
#endif
      sock->ccs |= COCO_TRANSMIT_READY;
      sock->nth.timeout_task = GNUNET_SCHEDULER_add_delayed (sock->sched,
                                                             timeout,
                                                             &transmit_timeout,
                                                             sock);
    }
  return &sock->nth;
}


/**
 * Cancel the specified transmission-ready
 * notification.
 */
void
GNUNET_CONNECTION_notify_transmit_ready_cancel (struct
                                                GNUNET_CONNECTION_TransmitHandle
                                                *h)
{
  GNUNET_assert (h->notify_ready != NULL);
  if (0 != (h->sh->ccs & COCO_TRANSMIT_READY))
    {
#if DEBUG_CONNECTION
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "notify_transmit_ready_cancel cancels timeout_task (%p)\n",
                  h);
#endif
      GNUNET_SCHEDULER_cancel (h->sh->sched, h->timeout_task);
      h->timeout_task = GNUNET_SCHEDULER_NO_TASK;
      h->sh->ccs -= COCO_TRANSMIT_READY;
    }
  else
    {
      GNUNET_SCHEDULER_cancel (h->sh->sched, h->sh->write_task);
      h->sh->write_task = GNUNET_SCHEDULER_NO_TASK;
    }
  h->notify_ready = NULL;
}

/* end of connection.c */
