/*
     This file is part of GNUnet.
     (C) 2009, 2012 Christian Grothoff (and other contributing authors)

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
 * @file util/network.c
 * @brief basic, low-level networking interface
 * @author Nils Durner
 */

#include "platform.h"
#include "gnunet_disk_lib.h"
#include "disk.h"
#include "gnunet_container_lib.h"

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)
#define LOG_STRERROR_FILE(kind,syscall,filename) GNUNET_log_from_strerror_file (kind, "util", syscall, filename)
#define LOG_STRERROR(kind,syscall) GNUNET_log_from_strerror (kind, "util", syscall)

#define DEBUG_NETWORK GNUNET_EXTRA_LOGGING


#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif


struct GNUNET_NETWORK_Handle
{
#ifndef MINGW
  int fd;
#else
  SOCKET fd;
#endif

  /**
   * Address family / domain.
   */
  int af;

  /**
   * Number of bytes in addr.
   */
  socklen_t addrlen;

  /**
   * Address we were bound to, or NULL.
   */
  struct sockaddr *addr;

};


#ifndef FD_COPY
#define FD_COPY(s, d) (memcpy ((d), (s), sizeof (fd_set)))
#endif


/**
 * Set if a socket should use blocking or non-blocking IO.
 * @param fd socket
 * @param doBlock blocking mode
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
socket_set_blocking (struct GNUNET_NETWORK_Handle *fd, int doBlock)
{

#if MINGW
  u_long mode;

  mode = !doBlock;
  if (ioctlsocket (fd->fd, FIONBIO, &mode) == SOCKET_ERROR)

  {
    SetErrnoFromWinsockError (WSAGetLastError ());
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "ioctlsocket");
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;

#else
  /* not MINGW */
  int flags = fcntl (fd->fd, F_GETFL);

  if (flags == -1)

  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "fcntl");
    return GNUNET_SYSERR;
  }
  if (doBlock)
    flags &= ~O_NONBLOCK;

  else
    flags |= O_NONBLOCK;
  if (0 != fcntl (fd->fd, F_SETFL, flags))

  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "fcntl");
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
#endif
}


#ifndef MINGW
/**
 * Make a socket non-inheritable to child processes
 *
 * @param h the socket to make non-inheritable
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 * @warning Not implemented on Windows
 */
static int
socket_set_inheritable (const struct GNUNET_NETWORK_Handle *h)
{
  int i;

  i = fcntl (h->fd, F_GETFD);
  if (i < 0)
    return GNUNET_SYSERR;
  if (i == (i | FD_CLOEXEC))
    return GNUNET_OK;
  i |= FD_CLOEXEC;
  if (fcntl (h->fd, F_SETFD, i) < 0)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}
#endif


#ifdef DARWIN
/**
 * The MSG_NOSIGNAL equivalent on Mac OS X
 *
 * @param h the socket to make non-delaying
 */
static void
socket_set_nosigpipe (const struct GNUNET_NETWORK_Handle *h)
{
  int abs_value = 1;

  if (0 !=
      setsockopt (h->fd, SOL_SOCKET, SO_NOSIGPIPE, &abs_value,
                  sizeof (abs_value)))
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "setsockopt");
}
#endif


/**
 * Disable delays when sending data via the socket.
 * (GNUnet makes sure that messages are as big as
 * possible already).
 *
 * @param h the socket to make non-delaying
 */
static void
socket_set_nodelay (const struct GNUNET_NETWORK_Handle *h)
{
#ifndef WINDOWS
  int value = 1;

  if (0 != setsockopt (h->fd, IPPROTO_TCP, TCP_NODELAY, &value, sizeof (value)))
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "setsockopt");
#else
  const char *abs_value = "1";

  if (0 !=
      setsockopt (h->fd, IPPROTO_TCP, TCP_NODELAY, abs_value,
                  sizeof (abs_value)))
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "setsockopt");
#endif
}


/**
 * Perform proper canonical initialization for a network handle.
 * Set it to non-blocking, make it non-inheritable to child
 * processes, disable SIGPIPE, enable "nodelay" (if non-UNIX
 * stream socket) and check that it is smaller than FS_SETSIZE.
 *
 * @param h socket to initialize
 * @param af address family of the socket
 * @param type socket type
 * @return GNUNET_OK on success, GNUNET_SYSERR if initialization
 *         failed and the handle was destroyed
 */
static int
initialize_network_handle (struct GNUNET_NETWORK_Handle *h,
			   int af, int type)
{
  h->af = af;
  if (h->fd == INVALID_SOCKET)
  {
#ifdef MINGW
    SetErrnoFromWinsockError (WSAGetLastError ());
#endif
    GNUNET_free (h);
    return GNUNET_SYSERR;
  }
#ifndef MINGW
  if (h->fd >= FD_SETSIZE)
  {
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (h));
    errno = EMFILE;
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK != socket_set_inheritable (h))
    LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "socket_set_inheritable");
#endif
  if (GNUNET_SYSERR == socket_set_blocking (h, GNUNET_NO))
  {
    GNUNET_break (0);
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (h));
    return GNUNET_SYSERR;
  }
#ifdef DARWIN
  socket_set_nosigpipe (h);
#endif
  if ( (type == SOCK_STREAM) 
#ifdef AF_UNIX
       && (af != AF_UNIX)
#endif
       )
    socket_set_nodelay (h);
  return GNUNET_OK;
}


/**
 * accept a new connection on a socket
 *
 * @param desc bound socket
 * @param address address of the connecting peer, may be NULL
 * @param address_len length of address
 * @return client socket
 */
struct GNUNET_NETWORK_Handle *
GNUNET_NETWORK_socket_accept (const struct GNUNET_NETWORK_Handle *desc,
                              struct sockaddr *address, socklen_t * address_len)
{
  struct GNUNET_NETWORK_Handle *ret;

  ret = GNUNET_malloc (sizeof (struct GNUNET_NETWORK_Handle));
#if DEBUG_NETWORK
  {
    struct sockaddr name;
    socklen_t namelen = sizeof (name);
    int gsn = getsockname (desc->fd, &name, &namelen);

    if (gsn == 0)
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Accepting connection on `%s'\n",
           GNUNET_a2s (&name, namelen));
  }
#endif
  ret->fd = accept (desc->fd, address, address_len);
  if (GNUNET_OK != initialize_network_handle (ret,
					      (NULL != address) ? address->sa_family : desc->af,
					      SOCK_STREAM))
    return NULL;
  return ret;
}


/**
 * Bind to a connected socket
 * @param desc socket
 * @param address address to be bound
 * @param address_len length of address
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
int
GNUNET_NETWORK_socket_bind (struct GNUNET_NETWORK_Handle *desc,
                            const struct sockaddr *address,
                            socklen_t address_len)
{
  int ret;

#ifdef IPV6_V6ONLY
#ifdef IPPROTO_IPV6
  const int on = 1;

  if (desc->af == AF_INET6)
    if (0 != setsockopt (desc->fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof (on)))
      LOG_STRERROR (GNUNET_ERROR_TYPE_DEBUG, "setsockopt");
#endif
#endif
#ifndef WINDOWS
  /* This is required, and required here, but only on UNIX */
  if (0 != setsockopt (desc->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on)))
    LOG_STRERROR (GNUNET_ERROR_TYPE_DEBUG, "setsockopt");
#endif
#ifndef LINUX
#ifndef MINGW
  if (address->sa_family == AF_UNIX)
  {
    const struct sockaddr_un *un = (const struct sockaddr_un *) address;

    (void) unlink (un->sun_path);
  }
#endif
#endif
  ret = bind (desc->fd, address, address_len);
#ifdef MINGW
  if (SOCKET_ERROR == ret)
    SetErrnoFromWinsockError (WSAGetLastError ());
#endif
  if (ret != 0)
    return GNUNET_SYSERR;
#ifndef MINGW
#ifndef LINUX
  desc->addr = GNUNET_malloc (address_len);
  memcpy (desc->addr, address, address_len);
  desc->addrlen = address_len;
#endif
#endif
  return GNUNET_OK;
}


/**
 * Close a socket
 * @param desc socket
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
int
GNUNET_NETWORK_socket_close (struct GNUNET_NETWORK_Handle *desc)
{
  int ret;

#ifdef MINGW
  DWORD error = 0;

  SetLastError (0);
  ret = closesocket (desc->fd);
  error = WSAGetLastError ();
  SetErrnoFromWinsockError (error);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Closed 0x%x, closesocket() returned %d, GLE is %u\n", desc->fd, ret,
       error);
#else
  ret = close (desc->fd);
#endif
#ifndef LINUX
#ifndef MINGW
  if ((desc->af == AF_UNIX) && (NULL != desc->addr))
  {
    const struct sockaddr_un *un = (const struct sockaddr_un *) desc->addr;

    if (0 != unlink (un->sun_path))
      LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "unlink", un->sun_path);
  }
#endif
#endif
  GNUNET_free_non_null (desc->addr);
  GNUNET_free (desc);
  return (ret == 0) ? GNUNET_OK : GNUNET_SYSERR;
}


/**
 * Box a native socket (and check that it is a socket).
 *
 * @param fd socket to box
 * @return NULL on error (including not supported on target platform)
 */
struct GNUNET_NETWORK_Handle *
GNUNET_NETWORK_socket_box_native (SOCKTYPE fd)
{
  struct GNUNET_NETWORK_Handle *ret;
#if MINGW
  unsigned long i;
  DWORD d;
  /* FIXME: Find a better call to check that FD is valid */
  if (WSAIoctl (fd, FIONBIO, (void *) &i, sizeof (i), NULL, 0, &d, NULL, NULL) != 0)
    return NULL;                /* invalid FD */
  ret = GNUNET_malloc (sizeof (struct GNUNET_NETWORK_Handle));
  ret->fd = fd;
  ret->af = AF_UNSPEC;
  return ret;
#else
  if (fcntl (fd, F_GETFD) < 0)
    return NULL;                /* invalid FD */
  ret = GNUNET_malloc (sizeof (struct GNUNET_NETWORK_Handle));
  ret->fd = fd;
  ret->af = AF_UNSPEC;
  return ret;
#endif
}


/**
 * Connect a socket
 * @param desc socket
 * @param address peer address
 * @param address_len length of address
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
int
GNUNET_NETWORK_socket_connect (const struct GNUNET_NETWORK_Handle *desc,
                               const struct sockaddr *address,
                               socklen_t address_len)
{
  int ret;

  ret = connect (desc->fd, address, address_len);

#ifdef MINGW
  if (SOCKET_ERROR == ret)
  {
    SetErrnoFromWinsockError (WSAGetLastError ());
    if (errno == EWOULDBLOCK)
      errno = EINPROGRESS;
  }
#endif
  return ret == 0 ? GNUNET_OK : GNUNET_SYSERR;
}


/**
 * Get socket options
 *
 * @param desc socket
 * @param level protocol level of the option
 * @param optname identifier of the option
 * @param optval options
 * @param optlen length of optval
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
int
GNUNET_NETWORK_socket_getsockopt (const struct GNUNET_NETWORK_Handle *desc,
                                  int level, int optname, void *optval,
                                  socklen_t * optlen)
{
  int ret;

  ret = getsockopt (desc->fd, level, optname, optval, optlen);

#ifdef MINGW
  if (ret == 0 && level == SOL_SOCKET && optname == SO_ERROR)
    *((int *) optval) = GetErrnoFromWinsockError (*((int *) optval));

  else if (SOCKET_ERROR == ret)
    SetErrnoFromWinsockError (WSAGetLastError ());
#endif
  return ret == 0 ? GNUNET_OK : GNUNET_SYSERR;
}


/**
 * Listen on a socket
 * @param desc socket
 * @param backlog length of the listen queue
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
int
GNUNET_NETWORK_socket_listen (const struct GNUNET_NETWORK_Handle *desc,
                              int backlog)
{
  int ret;

  ret = listen (desc->fd, backlog);

#ifdef MINGW
  if (SOCKET_ERROR == ret)
    SetErrnoFromWinsockError (WSAGetLastError ());

#endif
  return ret == 0 ? GNUNET_OK : GNUNET_SYSERR;
}


/**
 * How much data is available to be read on this descriptor?
 *
 * Returns GNUNET_NO if no data is available, or on error!
 * @param desc socket
 */
ssize_t
GNUNET_NETWORK_socket_recvfrom_amount (const struct GNUNET_NETWORK_Handle *
                                       desc)
{
  int error;

  /* How much is there to be read? */
#ifndef WINDOWS
  int pending;

  error = ioctl (desc->fd, FIONREAD, &pending);
  if (error == 0)
    return (ssize_t) pending;
  return GNUNET_NO;
#else
  u_long pending;

  error = ioctlsocket (desc->fd, FIONREAD, &pending);
  if (error != SOCKET_ERROR)
    return (ssize_t) pending;
  return GNUNET_NO;
#endif
}


/**
 * Read data from a connected socket (always non-blocking).
 * @param desc socket
 * @param buffer buffer
 * @param length length of buffer
 * @param src_addr either the source to recv from, or all zeroes
 *        to be filled in by recvfrom
 * @param addrlen length of the addr
 */
ssize_t
GNUNET_NETWORK_socket_recvfrom (const struct GNUNET_NETWORK_Handle * desc,
                                void *buffer, size_t length,
                                struct sockaddr * src_addr, socklen_t * addrlen)
{
  int ret;
  int flags;

  flags = 0;

#ifdef MSG_DONTWAIT
  flags |= MSG_DONTWAIT;

#endif
  ret = recvfrom (desc->fd, buffer, length, flags, src_addr, addrlen);
#ifdef MINGW
  if (SOCKET_ERROR == ret)
    SetErrnoFromWinsockError (WSAGetLastError ());
#endif
  return ret;
}


/**
 * Read data from a connected socket (always non-blocking).
 * @param desc socket
 * @param buffer buffer
 * @param length length of buffer
 */
ssize_t
GNUNET_NETWORK_socket_recv (const struct GNUNET_NETWORK_Handle * desc,
                            void *buffer, size_t length)
{
  int ret;
  int flags;

  flags = 0;

#ifdef MSG_DONTWAIT
  flags |= MSG_DONTWAIT;
#endif
  ret = recv (desc->fd, buffer, length, flags);
#ifdef MINGW
  if (SOCKET_ERROR == ret)
    SetErrnoFromWinsockError (WSAGetLastError ());
#endif
  return ret;
}


/**
 * Send data (always non-blocking).
 *
 * @param desc socket
 * @param buffer data to send
 * @param length size of the buffer
 * @return number of bytes sent, GNUNET_SYSERR on error
 */
ssize_t
GNUNET_NETWORK_socket_send (const struct GNUNET_NETWORK_Handle * desc,
                            const void *buffer, size_t length)
{
  int ret;
  int flags;

  flags = 0;

#ifdef MSG_DONTWAIT
  flags |= MSG_DONTWAIT;

#endif
#ifdef MSG_NOSIGNAL
  flags |= MSG_NOSIGNAL;

#endif
  ret = send (desc->fd, buffer, length, flags);

#ifdef MINGW
  if (SOCKET_ERROR == ret)
    SetErrnoFromWinsockError (WSAGetLastError ());

#endif
  return ret;
}


/**
 * Send data to a particular destination (always non-blocking).
 * This function only works for UDP sockets.
 *
 * @param desc socket
 * @param message data to send
 * @param length size of the data
 * @param dest_addr destination address
 * @param dest_len length of address
 * @return number of bytes sent, GNUNET_SYSERR on error
 */
ssize_t
GNUNET_NETWORK_socket_sendto (const struct GNUNET_NETWORK_Handle * desc,
                              const void *message, size_t length,
                              const struct sockaddr * dest_addr,
                              socklen_t dest_len)
{
  int ret;
  int flags;

  flags = 0;

#ifdef MSG_DONTWAIT
  flags |= MSG_DONTWAIT;
#endif
#ifdef MSG_NOSIGNAL
  flags |= MSG_NOSIGNAL;
#endif
  ret = sendto (desc->fd, message, length, flags, dest_addr, dest_len);
#ifdef MINGW
  if (SOCKET_ERROR == ret)
    SetErrnoFromWinsockError (WSAGetLastError ());
#endif
  return ret;
}


/**
 * Set socket option
 * @param fd socket
 * @param level protocol level of the option
 * @param option_name option identifier
 * @param option_value value to set
 * @param option_len size of option_value
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
int
GNUNET_NETWORK_socket_setsockopt (struct GNUNET_NETWORK_Handle *fd, int level,
                                  int option_name, const void *option_value,
                                  socklen_t option_len)
{
  int ret;

  ret = setsockopt (fd->fd, level, option_name, option_value, option_len);
#ifdef MINGW
  if (SOCKET_ERROR == ret)
    SetErrnoFromWinsockError (WSAGetLastError ());
#endif
  return ret == 0 ? GNUNET_OK : GNUNET_SYSERR;
}


/**
 * Create a new socket.  Configure it for non-blocking IO and
 * mark it as non-inheritable to child processes (set the
 * close-on-exec flag).
 *
 * @param domain domain of the socket
 * @param type socket type
 * @param protocol network protocol
 * @return new socket, NULL on error
 */
struct GNUNET_NETWORK_Handle *
GNUNET_NETWORK_socket_create (int domain, int type, int protocol)
{
  struct GNUNET_NETWORK_Handle *ret;

  ret = GNUNET_malloc (sizeof (struct GNUNET_NETWORK_Handle));
  ret->fd = socket (domain, type, protocol);
  if (GNUNET_OK !=
      initialize_network_handle (ret, domain, type))
    return NULL;
  return ret;
}


/**
 * Shut down socket operations
 * @param desc socket
 * @param how type of shutdown
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
int
GNUNET_NETWORK_socket_shutdown (struct GNUNET_NETWORK_Handle *desc, int how)
{
  int ret;

  ret = shutdown (desc->fd, how);
#ifdef MINGW
  if (ret != 0)
    SetErrnoFromWinsockError (WSAGetLastError ());
#endif
  return ret == 0 ? GNUNET_OK : GNUNET_SYSERR;
}


/**
 * Disable the "CORK" feature for communication with the given socket,
 * forcing the OS to immediately flush the buffer on transmission
 * instead of potentially buffering multiple messages.  Essentially
 * reduces the OS send buffers to zero.
 *
 * @param desc socket
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
int
GNUNET_NETWORK_socket_disable_corking (struct GNUNET_NETWORK_Handle *desc)
{
  int ret = 0;

#if WINDOWS
  int value = 0;

  if (0 !=
      (ret =
       setsockopt (desc->fd, SOL_SOCKET, SO_SNDBUF, (char *) &value,
                   sizeof (value))))
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "setsockopt");
  if (0 !=
      (ret =
       setsockopt (desc->fd, SOL_SOCKET, SO_RCVBUF, (char *) &value,
                   sizeof (value))))
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "setsockopt");
#elif LINUX
  int value = 0;

  if (0 !=
      (ret =
       setsockopt (desc->fd, SOL_SOCKET, SO_SNDBUF, &value, sizeof (value))))
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "setsockopt");
  if (0 !=
      (ret =
       setsockopt (desc->fd, SOL_SOCKET, SO_RCVBUF, &value, sizeof (value))))
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "setsockopt");
#endif
  return ret == 0 ? GNUNET_OK : GNUNET_SYSERR;
}


/**
 * Reset FD set
 * @param fds fd set
 */
void
GNUNET_NETWORK_fdset_zero (struct GNUNET_NETWORK_FDSet *fds)
{
  FD_ZERO (&fds->sds);
  fds->nsds = 0;
#ifdef MINGW
  GNUNET_CONTAINER_slist_clear (fds->handles);
#endif
}

/**
 * Add a socket to the FD set
 * @param fds fd set
 * @param desc socket to add
 */
void
GNUNET_NETWORK_fdset_set (struct GNUNET_NETWORK_FDSet *fds,
                          const struct GNUNET_NETWORK_Handle *desc)
{
  FD_SET (desc->fd, &fds->sds);
  if (desc->fd + 1 > fds->nsds)
    fds->nsds = desc->fd + 1;
}


/**
 * Check whether a socket is part of the fd set
 * @param fds fd set
 * @param desc socket
 * @return 0 if the FD is not set
 */
int
GNUNET_NETWORK_fdset_isset (const struct GNUNET_NETWORK_FDSet *fds,
                            const struct GNUNET_NETWORK_Handle *desc)
{
  return FD_ISSET (desc->fd, &fds->sds);
}


/**
 * Add one fd set to another
 * @param dst the fd set to add to
 * @param src the fd set to add from
 */
void
GNUNET_NETWORK_fdset_add (struct GNUNET_NETWORK_FDSet *dst,
                          const struct GNUNET_NETWORK_FDSet *src)
{
  int nfds;

  for (nfds = src->nsds; nfds > 0; nfds--)
    if (FD_ISSET (nfds, &src->sds))

    {
      FD_SET (nfds, &dst->sds);
      if (nfds + 1 > dst->nsds)
        dst->nsds = nfds + 1;
    }
#ifdef MINGW
  GNUNET_CONTAINER_slist_append (dst->handles, src->handles);
#endif
}


/**
 * Copy one fd set to another
 *
 * @param to destination
 * @param from source
 */
void
GNUNET_NETWORK_fdset_copy (struct GNUNET_NETWORK_FDSet *to,
                           const struct GNUNET_NETWORK_FDSet *from)
{
  FD_COPY (&from->sds, &to->sds);
  to->nsds = from->nsds;

#ifdef MINGW
  GNUNET_CONTAINER_slist_clear (to->handles);
  GNUNET_CONTAINER_slist_append (to->handles, from->handles);
#endif
}


/**
 * Return file descriptor for this network handle
 *
 * @param desc wrapper to process
 * @return POSIX file descriptor
 */
int
GNUNET_NETWORK_get_fd (struct GNUNET_NETWORK_Handle *desc)
{
  return desc->fd;
}

/**
 * Return sockaddr for this network handle
 *
 * @param desc wrapper to process
 * @return sockaddr
 */
struct sockaddr*
GNUNET_NETWORK_get_addr (struct GNUNET_NETWORK_Handle *desc)
{
  return desc->addr;
}

/**
 * Return sockaddr length for this network handle
 *
 * @param desc wrapper to process
 * @return socklen_t for sockaddr
 */
socklen_t
GNUNET_NETWORK_get_addrlen (struct GNUNET_NETWORK_Handle *desc)
{
  return desc->addrlen;
}
/**
 * Copy a native fd set
 *
 * @param to destination
 * @param from native source set
 * @param nfds the biggest socket number in from + 1
 */
void
GNUNET_NETWORK_fdset_copy_native (struct GNUNET_NETWORK_FDSet *to,
                                  const fd_set * from, int nfds)
{
  FD_COPY (from, &to->sds);
  to->nsds = nfds;
}


/**
 * Set a native fd in a set
 *
 * @param to destination
 * @param nfd native FD to set
 */
void
GNUNET_NETWORK_fdset_set_native (struct GNUNET_NETWORK_FDSet *to, int nfd)
{
  GNUNET_assert ((nfd >= 0) && (nfd < FD_SETSIZE));
  FD_SET (nfd, &to->sds);
  to->nsds = GNUNET_MAX (nfd + 1, to->nsds);
}


/**
 * Test native fd in a set
 *
 * @param to set to test, NULL for empty set
 * @param nfd native FD to test, or -1 for none
 * @return GNUNET_YES if FD is set in the set
 */
int
GNUNET_NETWORK_fdset_test_native (const struct GNUNET_NETWORK_FDSet *to,
                                  int nfd)
{
  if ((nfd == -1) || (to == NULL))
    return GNUNET_NO;
  return FD_ISSET (nfd, &to->sds) ? GNUNET_YES : GNUNET_NO;
}


/**
 * Add a file handle to the fd set
 * @param fds fd set
 * @param h the file handle to add
 */
void
GNUNET_NETWORK_fdset_handle_set (struct GNUNET_NETWORK_FDSet *fds,
                                 const struct GNUNET_DISK_FileHandle *h)
{
#ifdef MINGW
  GNUNET_CONTAINER_slist_add (fds->handles,
                              GNUNET_CONTAINER_SLIST_DISPOSITION_TRANSIENT, h,
                              sizeof (struct GNUNET_DISK_FileHandle));

#else
  int fd;

  GNUNET_DISK_internal_file_handle_ (h, &fd, sizeof (int));
  FD_SET (fd, &fds->sds);
  if (fd + 1 > fds->nsds)
    fds->nsds = fd + 1;

#endif
}


/**
 * Check if a file handle is part of an fd set
 * @param fds fd set
 * @param h file handle
 * @return GNUNET_YES if the file handle is part of the set
 */
int
GNUNET_NETWORK_fdset_handle_isset (const struct GNUNET_NETWORK_FDSet *fds,
                                   const struct GNUNET_DISK_FileHandle *h)
{

#ifdef MINGW
  return GNUNET_CONTAINER_slist_contains (fds->handles, h,
                                          sizeof (struct
                                                  GNUNET_DISK_FileHandle));
#else
  return FD_ISSET (h->fd, &fds->sds);
#endif
}


/**
 * Checks if two fd sets overlap
 * @param fds1 first fd set
 * @param fds2 second fd set
 * @return GNUNET_YES if they do overlap, GNUNET_NO otherwise
 */
int
GNUNET_NETWORK_fdset_overlap (const struct GNUNET_NETWORK_FDSet *fds1,
                              const struct GNUNET_NETWORK_FDSet *fds2)
{
#ifndef MINGW
  int nfds;

  nfds = fds1->nsds;
  if (nfds > fds2->nsds)
    nfds = fds2->nsds;
  while (nfds > 0)
  {
    nfds--;
    if (FD_ISSET (nfds, &fds1->sds) && FD_ISSET (nfds, &fds2->sds))
      return GNUNET_YES;
  }
#else
  struct GNUNET_CONTAINER_SList_Iterator it;
  struct GNUNET_DISK_FileHandle *h;
  int i;
  int j;

  /*This code is somewhat hacky, we are not supposed to know what's
   * inside of fd_set; also the O(n^2) is really bad... */

  for (i = 0; i < fds1->sds.fd_count; i++)
  {
    for (j = 0; j < fds2->sds.fd_count; j++)
    {
      if (fds1->sds.fd_array[i] == fds2->sds.fd_array[j])
        return GNUNET_YES;
    }
  }
  it = GNUNET_CONTAINER_slist_begin (fds1->handles);
  while (GNUNET_CONTAINER_slist_end (&it) != GNUNET_YES)
  {
#if DEBUG_NETWORK
    struct GNUNET_CONTAINER_SList_Iterator t;
#endif
    h = (struct GNUNET_DISK_FileHandle *) GNUNET_CONTAINER_slist_get (&it,
                                                                      NULL);
#if DEBUG_NETWORK
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Checking that FD 0x%x is in another set:\n",
         h->h);
    for (t = GNUNET_CONTAINER_slist_begin (fds2->handles);
         GNUNET_CONTAINER_slist_end (&t) != GNUNET_YES;
         GNUNET_CONTAINER_slist_next (&t))
    {
      struct GNUNET_DISK_FileHandle *fh;

      fh = (struct GNUNET_DISK_FileHandle *) GNUNET_CONTAINER_slist_get (&t,
                                                                         NULL);
      LOG (GNUNET_ERROR_TYPE_DEBUG, "0x%x\n", fh->h);
    }
#endif
    if (GNUNET_CONTAINER_slist_contains
        (fds2->handles, h, sizeof (struct GNUNET_DISK_FileHandle)))
    {
      return GNUNET_YES;
    }
    GNUNET_CONTAINER_slist_next (&it);
  }
#endif
  return GNUNET_NO;
}


/**
 * Creates an fd set
 * @return a new fd set
 */
struct GNUNET_NETWORK_FDSet *
GNUNET_NETWORK_fdset_create ()
{
  struct GNUNET_NETWORK_FDSet *fds;

  fds = GNUNET_malloc (sizeof (struct GNUNET_NETWORK_FDSet));
#ifdef MINGW
  fds->handles = GNUNET_CONTAINER_slist_create ();
#endif
  GNUNET_NETWORK_fdset_zero (fds);
  return fds;
}


/**
 * Releases the associated memory of an fd set
 * @param fds fd set
 */
void
GNUNET_NETWORK_fdset_destroy (struct GNUNET_NETWORK_FDSet *fds)
{
#ifdef MINGW
  GNUNET_CONTAINER_slist_destroy (fds->handles);
#endif
  GNUNET_free (fds);
}

/**
 * Check if sockets meet certain conditions
 * @param rfds set of sockets to be checked for readability
 * @param wfds set of sockets to be checked for writability
 * @param efds set of sockets to be checked for exceptions
 * @param timeout relative value when to return
 * @return number of selected sockets, GNUNET_SYSERR on error
 */
int
GNUNET_NETWORK_socket_select (struct GNUNET_NETWORK_FDSet *rfds,
                              struct GNUNET_NETWORK_FDSet *wfds,
                              struct GNUNET_NETWORK_FDSet *efds,
                              const struct GNUNET_TIME_Relative timeout)
{
  int nfds = 0;
#ifdef MINGW
  int handles = 0;
  int ex_handles = 0;
  int read_handles = 0;
  int write_handles = 0;

  int i = 0;
  int retcode = 0;
  DWORD ms_total = 0;

  int nsock = 0;
  int nhandles = 0;
  int nSockEvents = 0;

  static HANDLE hEventRead = 0;
  static HANDLE hEventWrite = 0;
  static HANDLE hEventException = 0;
  static HANDLE hEventPipeWrite = 0;
  static HANDLE hEventReadReady = 0;

  int readPipes = 0;
  int writePipePos = 0;

  HANDLE handle_array[FD_SETSIZE + 2];
  int returncode = -1;
  DWORD newretcode = 0;
  int returnedpos = 0;

  struct GNUNET_CONTAINER_SList *handles_read;
  struct GNUNET_CONTAINER_SList *handles_write;
  struct GNUNET_CONTAINER_SList *handles_except;

  fd_set aread;
  fd_set awrite;
  fd_set aexcept;

#if DEBUG_NETWORK
  fd_set bread;
  fd_set bwrite;
  fd_set bexcept;
#endif

  /* TODO: Make this growable */
  struct GNUNET_DISK_FileHandle *readArray[50];
#else
  struct timeval tv;
#endif
  if (NULL != rfds)
  {
    nfds = rfds->nsds;
#ifdef MINGW
    handles += read_handles = GNUNET_CONTAINER_slist_count (rfds->handles);
#if DEBUG_NETWORK
    {
      struct GNUNET_CONTAINER_SList_Iterator t;

      for (t = GNUNET_CONTAINER_slist_begin (rfds->handles);
           GNUNET_CONTAINER_slist_end (&t) != GNUNET_YES;
           GNUNET_CONTAINER_slist_next (&t))
      {
        struct GNUNET_DISK_FileHandle *fh;

        fh = (struct GNUNET_DISK_FileHandle *) GNUNET_CONTAINER_slist_get (&t,
                                                                           NULL);
        LOG (GNUNET_ERROR_TYPE_DEBUG, "FD 0x%x (0x%x) is SET in rfds\n", fh->h,
             fh);
      }
    }
#endif
#endif
  }
  if (NULL != wfds)
  {
    nfds = GNUNET_MAX (nfds, wfds->nsds);
#ifdef MINGW
    handles += write_handles = GNUNET_CONTAINER_slist_count (wfds->handles);
#endif
  }
  if (NULL != efds)
  {
    nfds = GNUNET_MAX (nfds, efds->nsds);
#ifdef MINGW
    handles += ex_handles = GNUNET_CONTAINER_slist_count (efds->handles);
#endif
  }

  if ((nfds == 0) &&
      (timeout.rel_value == GNUNET_TIME_UNIT_FOREVER_REL.rel_value)
#ifdef MINGW
      && handles == 0
#endif
      )
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _
         ("Fatal internal logic error, process hangs in `%s' (abort with CTRL-C)!\n"),
         "select");
    GNUNET_break (0);
  }
#ifndef MINGW
  tv.tv_sec = timeout.rel_value / GNUNET_TIME_UNIT_SECONDS.rel_value;
  tv.tv_usec =
      1000 * (timeout.rel_value -
              (tv.tv_sec * GNUNET_TIME_UNIT_SECONDS.rel_value));
  return select (nfds, (rfds != NULL) ? &rfds->sds : NULL,
                 (wfds != NULL) ? &wfds->sds : NULL,
                 (efds != NULL) ? &efds->sds : NULL,
                 (timeout.rel_value ==
                  GNUNET_TIME_UNIT_FOREVER_REL.rel_value) ? NULL : &tv);

#else
#define SAFE_FD_ISSET(fd, set)  (set != NULL && FD_ISSET(fd, set))
  /* calculate how long we need to wait in milliseconds */
  if (timeout.rel_value == GNUNET_TIME_UNIT_FOREVER_REL.rel_value)
    ms_total = INFINITE;
  else
    ms_total = timeout.rel_value / GNUNET_TIME_UNIT_MILLISECONDS.rel_value;
  /* select() may be used as a portable way to sleep */
  if (!(rfds || wfds || efds))
  {
    Sleep (ms_total);
    return 0;
  }

  /* Events for sockets */
  if (!hEventRead)
    hEventRead = CreateEvent (NULL, TRUE, FALSE, NULL);
  else
    ResetEvent (hEventRead);
  if (!hEventReadReady)
    hEventReadReady = CreateEvent (NULL, TRUE, TRUE, NULL);
  if (!hEventWrite)
    hEventWrite = CreateEvent (NULL, TRUE, FALSE, NULL);
  else
    ResetEvent (hEventWrite);
  if (!hEventException)
    hEventException = CreateEvent (NULL, TRUE, FALSE, NULL);
  else
    ResetEvent (hEventException);

  /* Event for pipes */
  if (!hEventPipeWrite)
    hEventPipeWrite = CreateEvent (NULL, TRUE, TRUE, NULL);
  readPipes = 0;
  writePipePos = -1;

  handles_read = GNUNET_CONTAINER_slist_create ();
  handles_write = GNUNET_CONTAINER_slist_create ();
  handles_except = GNUNET_CONTAINER_slist_create ();
  FD_ZERO (&aread);
  FD_ZERO (&awrite);
  FD_ZERO (&aexcept);
#if DEBUG_NETWORK
  FD_ZERO (&bread);
  FD_ZERO (&bwrite);
  FD_ZERO (&bexcept);
#endif
  if (rfds)
  {
    FD_COPY (&rfds->sds, &aread);
#if DEBUG_NETWORK
    FD_COPY (&rfds->sds, &bread);
#endif
  }
  if (wfds)
  {
    FD_COPY (&wfds->sds, &awrite);
#if DEBUG_NETWORK
    FD_COPY (&wfds->sds, &bwrite);
#endif
  }
  if (efds)
  {
    FD_COPY (&efds->sds, &aexcept);
#if DEBUG_NETWORK
    FD_COPY (&efds->sds, &bexcept);
#endif
  }
  /* We will first Add the PIPES to the events */
  /* Read Pipes */
  if (rfds && read_handles)
  {
    struct GNUNET_CONTAINER_SList_Iterator i;

    for (i = GNUNET_CONTAINER_slist_begin (rfds->handles);
         GNUNET_CONTAINER_slist_end (&i) != GNUNET_YES;
         GNUNET_CONTAINER_slist_next (&i))
    {
      struct GNUNET_DISK_FileHandle *fh;

      fh = (struct GNUNET_DISK_FileHandle *) GNUNET_CONTAINER_slist_get (&i,
                                                                         NULL);
      if (fh->type == GNUNET_PIPE)
      {
        /* Read zero bytes to check the status of the pipe */
        LOG (GNUNET_ERROR_TYPE_DEBUG, "Reading 0 bytes from the pipe 0x%x\n",
             fh->h);
        if (!ReadFile (fh->h, NULL, 0, NULL, fh->oOverlapRead))
        {
          DWORD error_code = GetLastError ();

          if (error_code == ERROR_IO_PENDING)
          {
            LOG (GNUNET_ERROR_TYPE_DEBUG,
                 "Adding the pipe's 0x%x overlapped event to the array as %d\n",
                 fh->h, nhandles);
            handle_array[nhandles++] = fh->oOverlapRead->hEvent;
            readArray[readPipes++] = fh;
          }
          else
          {
            LOG (GNUNET_ERROR_TYPE_DEBUG,
                 "Read failed, adding the read ready event to the array as %d\n", nhandles);
            handle_array[nhandles++] = hEventReadReady;
            readArray[readPipes++] = fh;
          }
        }
        else
        {
          LOG (GNUNET_ERROR_TYPE_DEBUG,
               "Adding the read ready event to the array as %d\n", nhandles);
          handle_array[nhandles++] = hEventReadReady;
          readArray[readPipes++] = fh;
        }
      }
      else
      {
        GNUNET_CONTAINER_slist_add (handles_read,
                                    GNUNET_CONTAINER_SLIST_DISPOSITION_TRANSIENT,
                                    fh, sizeof (struct GNUNET_DISK_FileHandle));
      }
    }
  }
  if (wfds && write_handles)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Adding the write ready event to the array as %d\n", nhandles);
    handle_array[nhandles++] = hEventPipeWrite;
    writePipePos = nhandles;
  }
  if (efds && ex_handles)
  {
    struct GNUNET_CONTAINER_SList_Iterator i;

    for (i = GNUNET_CONTAINER_slist_begin (efds->handles);
         GNUNET_CONTAINER_slist_end (&i) != GNUNET_YES;
         GNUNET_CONTAINER_slist_next (&i))
    {
      struct GNUNET_DISK_FileHandle *fh;
      DWORD dwBytes;

      fh = (struct GNUNET_DISK_FileHandle *) GNUNET_CONTAINER_slist_get (&i,
                                                                         NULL);
      if (fh->type == GNUNET_PIPE)
      {
        if (!PeekNamedPipe (fh->h, NULL, 0, NULL, &dwBytes, NULL))
        {
          GNUNET_CONTAINER_slist_add (handles_except,
                                      GNUNET_CONTAINER_SLIST_DISPOSITION_TRANSIENT,
                                      fh,
                                      sizeof (struct GNUNET_DISK_FileHandle));
          newretcode++;
        }
      }
    }
  }
  if (nfds > 0)
  {
    if (rfds)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Adding the socket read event to the array as %d\n", nhandles);
      handle_array[nhandles++] = hEventRead;
      nSockEvents++;
      for (i = 0; i < rfds->sds.fd_count; i++)
      {
        WSAEventSelect (rfds->sds.fd_array[i], hEventRead,
                        FD_ACCEPT | FD_READ | FD_CLOSE);
        nsock++;
      }
    }
    if (wfds)
    {
      int wakeup = 0;

      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Adding the socket write event to the array as %d\n", nhandles);
      handle_array[nhandles++] = hEventWrite;
      nSockEvents++;
      for (i = 0; i < wfds->sds.fd_count; i++)
      {
        DWORD error;
        int status;

        status = send (wfds->sds.fd_array[i], NULL, 0, 0);
        error = GetLastError ();
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "pre-send to the socket %d returned %d (%u)\n", i, status, error);
        if (status == 0 || (error != WSAEWOULDBLOCK && error != WSAENOTCONN))
          wakeup = 1;
        WSAEventSelect (wfds->sds.fd_array[i], hEventWrite,
                        FD_WRITE | FD_CONNECT | FD_CLOSE);
        nsock++;
      }
      if (wakeup)
        SetEvent (hEventWrite);
    }
    if (efds)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Adding the socket error event to the array as %d\n", nhandles);
      handle_array[nhandles++] = hEventException;
      nSockEvents++;
      for (i = 0; i < efds->sds.fd_count; i++)
      {
        WSAEventSelect (efds->sds.fd_array[i], hEventException,
                        FD_OOB | FD_CLOSE);
        nsock++;
      }
    }
  }

  handle_array[nhandles] = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG, 
       "Number nfds: %d, handles: %d, return code: %u will wait: %d ms\n", 
       nfds, nhandles, newretcode, ms_total);
  if (nhandles)
    returncode =
        WaitForMultipleObjects (nhandles, handle_array, FALSE, ms_total);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "WaitForMultipleObjects Returned : %d\n",
       returncode);

  returnedpos = returncode - WAIT_OBJECT_0;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "return pos is : %d\n", returnedpos);

  /* FIXME: THIS LINE IS WRONG !! We should add to handles only handles that fired the events, not all ! */
  /*
   * if(rfds)
   * GNUNET_CONTAINER_slist_append (handles_read, rfds->handles);
   */
  if (nhandles && (returnedpos < nhandles))
  {
    DWORD waitstatus;

    /* Do the select */
    if (nfds)
    {
      struct timeval tvslice;

      tvslice.tv_sec = 0;
      tvslice.tv_usec = 0;
      retcode = select (nfds, &aread, &awrite, &aexcept, &tvslice);
      if (retcode == -1)
        retcode = 0;
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Select retcode : %d\n", retcode);
    }
    /* FIXME: <= writePipePos? Really? */
    if ((writePipePos != -1) && (returnedpos <= writePipePos))
    {
      GNUNET_CONTAINER_slist_append (handles_write, wfds->handles);
      retcode += write_handles;
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Added write pipe\n");
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG, "ReadPipes is : %d\n", readPipes);
    /* We have some pipes ready for read. */
    /* FIXME: it is supposed to work !! Only choose the Pipes who fired the event, but it is not working */

    if (returnedpos < readPipes)
    {
      /*
       * for (i = 0; i < readPipes; i++)
       * {
       * waitstatus = WaitForSingleObject (handle_array[i], 0);
       * LOG (GNUNET_ERROR_TYPE_DEBUG, "Read pipe %d wait status is : %d\n", i, waitstatus);
       * if (waitstatus != WAIT_OBJECT_0)
       * continue;
       * GNUNET_CONTAINER_slist_add (handles_read,
       * GNUNET_CONTAINER_SLIST_DISPOSITION_TRANSIENT,
       * readArray[i], sizeof (struct GNUNET_DISK_FileHandle));
       * retcode++;
       * LOG (GNUNET_ERROR_TYPE_DEBUG, "Added read Pipe\n");
       * }
       */
      for (i = 0; i < readPipes; i++)
      {
        DWORD error;
        BOOL bret;

        SetLastError (0);
        waitstatus = 0;
        bret =
            PeekNamedPipe (readArray[i]->h, NULL, 0, NULL, &waitstatus, NULL);
        error = GetLastError ();
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "Peek at read pipe %d (0x%x) returned %d (%d bytes available) GLE %u\n",
             i, readArray[i]->h, bret, waitstatus, error);
        if (bret == 0)
        {
          if (error != ERROR_BROKEN_PIPE)
            continue;
        }
        else if (waitstatus <= 0)
          continue;
        GNUNET_CONTAINER_slist_add (handles_read,
                                    GNUNET_CONTAINER_SLIST_DISPOSITION_TRANSIENT,
                                    readArray[i],
                                    sizeof (struct GNUNET_DISK_FileHandle));
        retcode++;
        LOG (GNUNET_ERROR_TYPE_DEBUG, "Added read Pipe 0x%x (0x%x)\n",
             readArray[i], readArray[i]->h);
      }
    }
    waitstatus = WaitForSingleObject (hEventWrite, 0);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Wait for the write event returned %d\n",
         waitstatus);
    if (waitstatus == WAIT_OBJECT_0)
    {
      for (i = 0; i < wfds->sds.fd_count; i++)
      {
        DWORD error;
        int status;
        int so_error = 0;
        int sizeof_so_error = sizeof (so_error);
        int gso_result =
            getsockopt (wfds->sds.fd_array[i], SOL_SOCKET, SO_ERROR,
                        (char *) &so_error, &sizeof_so_error);

        status = send (wfds->sds.fd_array[i], NULL, 0, 0);
        error = GetLastError ();
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "send to the socket %d returned %d (%u)\n", i, status, error);
        if (status == 0 || (error != WSAEWOULDBLOCK && error != WSAENOTCONN) ||
            (status == -1 && gso_result == 0 && error == WSAENOTCONN &&
             so_error == WSAECONNREFUSED))
        {
          FD_SET (wfds->sds.fd_array[i], &awrite);
          retcode += 1;
        }
      }
    }
  }
  if (!nhandles || (returnedpos >= nhandles))
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Returning from _select() with nothing!\n");
  if (rfds)
  {
    struct GNUNET_CONTAINER_SList_Iterator t;

    for (i = 0; i < rfds->sds.fd_count; i++)
    {
      WSAEventSelect (rfds->sds.fd_array[i], hEventRead, 0);
      nsock++;
    }
    for (t = GNUNET_CONTAINER_slist_begin (rfds->handles);
         GNUNET_CONTAINER_slist_end (&t) != GNUNET_YES;
         GNUNET_CONTAINER_slist_next (&t))
    {
      struct GNUNET_DISK_FileHandle *fh;

      fh = (struct GNUNET_DISK_FileHandle *) GNUNET_CONTAINER_slist_get (&t,
                                                                         NULL);
      if (fh->type == GNUNET_PIPE)
      {
        CancelIo (fh->h);
      }
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Zeroing rfds\n");
    GNUNET_NETWORK_fdset_zero (rfds);
    if (retcode != -1 && nhandles && (returnedpos < nhandles))
      GNUNET_NETWORK_fdset_copy_native (rfds, &aread, retcode);
    GNUNET_CONTAINER_slist_append (rfds->handles, handles_read);
  }
  if (wfds)
  {
    for (i = 0; i < wfds->sds.fd_count; i++)
    {
      WSAEventSelect (wfds->sds.fd_array[i], hEventWrite, 0);
      nsock++;
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Zeroing wfds\n");
    GNUNET_NETWORK_fdset_zero (wfds);
    if (retcode != -1 && nhandles && (returnedpos < nhandles))
      GNUNET_NETWORK_fdset_copy_native (wfds, &awrite, retcode);
    GNUNET_CONTAINER_slist_append (wfds->handles, handles_write);
  }
  if (efds)
  {
    for (i = 0; i < efds->sds.fd_count; i++)
    {
      WSAEventSelect (efds->sds.fd_array[i], hEventException, 0);
      nsock++;
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Zeroing efds\n");
    GNUNET_NETWORK_fdset_zero (efds);
    if (retcode != -1 && nhandles && (returnedpos < nhandles))
      GNUNET_NETWORK_fdset_copy_native (efds, &aexcept, retcode);
    GNUNET_CONTAINER_slist_append (efds->handles, handles_except);
  }
  GNUNET_CONTAINER_slist_destroy (handles_read);
  GNUNET_CONTAINER_slist_destroy (handles_write);
  GNUNET_CONTAINER_slist_destroy (handles_except);
#if DEBUG_NETWORK
  if (rfds)
  {
    struct GNUNET_CONTAINER_SList_Iterator t;

    for (i = 0; i < bread.fd_count; i++)
    {
      if (bread.fd_array[i] != 0)
        LOG (GNUNET_ERROR_TYPE_DEBUG, "FD 0x%x is %s in rfds\n",
             bread.fd_array[i],
             (SAFE_FD_ISSET (bread.fd_array[i], rfds)) ? "SET" : "NOT SET");
    }
    for (t = GNUNET_CONTAINER_slist_begin (rfds->handles);
         GNUNET_CONTAINER_slist_end (&t) != GNUNET_YES;
         GNUNET_CONTAINER_slist_next (&t))
    {
      struct GNUNET_DISK_FileHandle *fh;

      fh = (struct GNUNET_DISK_FileHandle *) GNUNET_CONTAINER_slist_get (&t,
                                                                         NULL);
      LOG (GNUNET_ERROR_TYPE_DEBUG, "FD 0x%x is SET in rfds\n", fh->h);
    }
  }
  if (wfds)
  {
    for (i = 0; i < bwrite.fd_count; i++)
    {
      if (bwrite.fd_array[i] != 0)
        LOG (GNUNET_ERROR_TYPE_DEBUG, "FD 0x%x is %s in wfds\n",
             bwrite.fd_array[i],
             (SAFE_FD_ISSET (bwrite.fd_array[i], rfds)) ? "SET" : "NOT SET");
    }
  }
  if (efds)
  {
    for (i = 0; i < bexcept.fd_count; i++)
    {
      if (bexcept.fd_array[i] != 0)
        LOG (GNUNET_ERROR_TYPE_DEBUG, "FD 0x%x is %s in efds\n",
             bexcept.fd_array[i],
             (SAFE_FD_ISSET (bexcept.fd_array[i], rfds)) ? "SET" : "NOT SET");
    }
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Returning %d or 0\n", retcode);
#endif
  if (nhandles && (returnedpos < nhandles))
    return retcode;
  else
#endif
    return 0;
}

/* end of network.c */
