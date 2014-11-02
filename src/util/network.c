/*
     This file is part of GNUnet.
     (C) 2009-2013 Christian Grothoff (and other contributing authors)

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
 * @file util/network.c
 * @brief basic, low-level networking interface
 * @author Nils Durner
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "disk.h"

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
   * Type of the socket
   */
  int type;

  /**
   * Number of bytes in addr.
   */
  socklen_t addrlen;

  /**
   * Address we were bound to, or NULL.
   */
  struct sockaddr *addr;

};


/**
 * Test if the given protocol family is supported by this system.
 *
 * @param pf protocol family to test (PF_INET, PF_INET6, PF_UNIX)
 * @return #GNUNET_OK if the PF is supported
 */
int
GNUNET_NETWORK_test_pf (int pf)
{
  int s;

  s = socket (pf, SOCK_STREAM, 0);
  if (-1 == s)
  {
    if (EAFNOSUPPORT == errno)
      return GNUNET_NO;
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		"Failed to create test socket: %s\n",
		STRERROR (errno));
    return GNUNET_SYSERR;
  }
#if WINDOWS
  closesocket (s);
#else
  close (s);
#endif
  return GNUNET_OK;
}


/**
 * Given a unixpath that is too long (larger than UNIX_PATH_MAX),
 * shorten it to an acceptable length while keeping it unique
 * and making sure it remains a valid filename (if possible).
 *
 * @param unixpath long path, will be freed (or same pointer returned
 *        with moved 0-termination).
 * @return shortened unixpath, NULL on error
 */
char *
GNUNET_NETWORK_shorten_unixpath (char *unixpath)
{
  struct sockaddr_un dummy;
  size_t slen;
  char *end;
  struct GNUNET_HashCode sh;
  struct GNUNET_CRYPTO_HashAsciiEncoded ae;
  size_t upm;

  upm = sizeof (dummy.sun_path);
  slen = strlen (unixpath);
  if (slen < upm)
    return unixpath; /* no shortening required */
  GNUNET_CRYPTO_hash (unixpath, slen, &sh);
  while (16 +
	 strlen (unixpath) >= upm)
  {
    if (NULL == (end = strrchr (unixpath, '/')))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Unable to shorten unix path `%s' while keeping name unique\n"),
		  unixpath);
      GNUNET_free (unixpath);
      return NULL;
    }
    *end = '\0';
  }
  GNUNET_CRYPTO_hash_to_enc (&sh, &ae);
  strncat (unixpath, (char*) ae.encoding, 16);
  return unixpath;
}


#ifndef FD_COPY
#define FD_COPY(s, d) (memcpy ((d), (s), sizeof (fd_set)))
#endif


/**
 * Set if a socket should use blocking or non-blocking IO.
 *
 * @param fd socket
 * @param doBlock blocking mode
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_NETWORK_socket_set_blocking (struct GNUNET_NETWORK_Handle *fd,
                                    int doBlock)
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


/**
 * Make a socket non-inheritable to child processes
 *
 * @param h the socket to make non-inheritable
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 * @warning Not implemented on Windows
 */
static int
socket_set_inheritable (const struct GNUNET_NETWORK_Handle *h)
{
#ifndef MINGW
  int i;
  i = fcntl (h->fd, F_GETFD);
  if (i < 0)
    return GNUNET_SYSERR;
  if (i == (i | FD_CLOEXEC))
    return GNUNET_OK;
  i |= FD_CLOEXEC;
  if (fcntl (h->fd, F_SETFD, i) < 0)
    return GNUNET_SYSERR;
#else
  BOOL b;
  SetLastError (0);
  b = SetHandleInformation ((HANDLE) h->fd, HANDLE_FLAG_INHERIT, 0);
  if (!b)
  {
    SetErrnoFromWinsockError (WSAGetLastError ());
    return GNUNET_SYSERR;
  }
#endif
  return GNUNET_OK;
}


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
      setsockopt (h->fd, SOL_SOCKET, SO_NOSIGPIPE,
		  (const void *) &abs_value,
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
      setsockopt (h->fd, IPPROTO_TCP, TCP_NODELAY,
		  (const void *) abs_value,
                  sizeof (abs_value)))
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "setsockopt");
#endif
}


/**
 * Perform proper canonical initialization for a network handle.
 * Set it to non-blocking, make it non-inheritable to child
 * processes, disable SIGPIPE, enable "nodelay" (if non-UNIX
 * stream socket) and check that it is smaller than FD_SETSIZE.
 *
 * @param h socket to initialize
 * @param af address family of the socket
 * @param type socket type
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if initialization
 *         failed and the handle was destroyed
 */
static int
initialize_network_handle (struct GNUNET_NETWORK_Handle *h,
			   int af, int type)
{
  h->af = af;
  h->type = type;
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
#endif
  if (GNUNET_OK != socket_set_inheritable (h))
    LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                  "socket_set_inheritable");

  if (GNUNET_SYSERR == GNUNET_NETWORK_socket_set_blocking (h, GNUNET_NO))
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
 * @param address_len length of @a address
 * @return client socket
 */
struct GNUNET_NETWORK_Handle *
GNUNET_NETWORK_socket_accept (const struct GNUNET_NETWORK_Handle *desc,
                              struct sockaddr *address,
			      socklen_t *address_len)
{
  struct GNUNET_NETWORK_Handle *ret;

  ret = GNUNET_new (struct GNUNET_NETWORK_Handle);
#if DEBUG_NETWORK
  {
    struct sockaddr name;
    socklen_t namelen = sizeof (name);
    int gsn = getsockname (desc->fd, &name, &namelen);

    if (gsn == 0)
      LOG (GNUNET_ERROR_TYPE_DEBUG,
	   "Accepting connection on `%s'\n",
           GNUNET_a2s (&name, namelen));
  }
#endif
  ret->fd = accept (desc->fd, address, address_len);
  if (-1 == ret->fd)
  {
    GNUNET_free (ret);
    return NULL;
  }
  if (GNUNET_OK != initialize_network_handle (ret,
					      (NULL != address) ? address->sa_family : desc->af,
					      SOCK_STREAM))
    return NULL;
  return ret;
}


/**
 * Bind a socket to a particular address.
 *
 * @param desc socket to bind
 * @param address address to be bound
 * @param address_len length of @a address
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
int
GNUNET_NETWORK_socket_bind (struct GNUNET_NETWORK_Handle *desc,
                            const struct sockaddr *address,
                            socklen_t address_len)
{
  int ret;

#ifdef IPV6_V6ONLY
#ifdef IPPROTO_IPV6
  {
    const int on = 1;

    if (AF_INET6 == desc->af)
      if (setsockopt (desc->fd, IPPROTO_IPV6, IPV6_V6ONLY,
		      (const void *) &on,
		      sizeof (on)))
        LOG_STRERROR (GNUNET_ERROR_TYPE_DEBUG, "setsockopt");
  }
#endif
#endif
#ifndef WINDOWS
  {
    const int on = 1;

    /* This is required here for TCP sockets, but only on UNIX */
    if ((SOCK_STREAM == desc->type)
        && (0 != setsockopt (desc->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on))))
      LOG_STRERROR (GNUNET_ERROR_TYPE_DEBUG, "setsockopt");
  }
#endif
#ifndef WINDOWS
  {
    /* set permissions of newly created non-abstract UNIX domain socket to
       "user-only"; applications can choose to relax this later */
    mode_t old_mask = 0; /* assigned to make compiler happy */
    const struct sockaddr_un *un;
    int not_abstract = 0;

    if ((AF_UNIX == address->sa_family)
        && (NULL != (un = (const struct sockaddr_un *) address)->sun_path)
        && ('\0' != un->sun_path[0]) ) /* Not an abstract socket */
      not_abstract = 1;
    if (not_abstract)
      old_mask = umask (S_IWGRP | S_IRGRP | S_IXGRP | S_IWOTH | S_IROTH | S_IXOTH);
#endif

    ret = bind (desc->fd, address, address_len);
#ifndef WINDOWS
    if (not_abstract)
      (void) umask (old_mask);
  }
#endif
#ifdef MINGW
  if (SOCKET_ERROR == ret)
    SetErrnoFromWinsockError (WSAGetLastError ());
#endif
  if (ret != 0)
    return GNUNET_SYSERR;
#ifndef MINGW
  desc->addr = GNUNET_malloc (address_len);
  memcpy (desc->addr, address, address_len);
  desc->addrlen = address_len;
#endif
  return GNUNET_OK;
}


/**
 * Close a socket
 *
 * @param desc socket
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
int
GNUNET_NETWORK_socket_close (struct GNUNET_NETWORK_Handle *desc)
{
  int ret;

#ifdef WINDOWS
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
#ifndef WINDOWS
  const struct sockaddr_un *un;

  /* Cleanup the UNIX domain socket and its parent directories in case of non
     abstract sockets */
  if ((AF_UNIX == desc->af) && (NULL != desc->addr)
      && (NULL != (un = (const struct sockaddr_un *) desc->addr)->sun_path)
      && ('\0' != un->sun_path[0]))
  {
    char *dirname = GNUNET_strndup (un->sun_path,
                                    sizeof (un->sun_path));

    if (0 != unlink (dirname))
    {
      LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING,
			 "unlink",
			 dirname);
    }
    else
    {
      size_t len;

      len = strlen (dirname);
      while ((len > 0) && (dirname[len] != DIR_SEPARATOR))
        len--;
      dirname[len] = '\0';
      if ((0 != len) && (0 != rmdir (dirname)))
      {
        switch (errno)
        {
        case EACCES:
        case ENOTEMPTY:
        case EPERM:
          /* these are normal and can just be ignored */
          break;
        default:
          GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
                                    "rmdir",
                                    dirname);
          break;
        }
      }
    }
    GNUNET_free (dirname);
  }
#endif
  GNUNET_NETWORK_socket_free_memory_only_ (desc);
  return (ret == 0) ? GNUNET_OK : GNUNET_SYSERR;
}


/**
 * Only free memory of a socket, keep the file descriptor untouched.
 *
 * @param desc socket
 */
void
GNUNET_NETWORK_socket_free_memory_only_ (struct GNUNET_NETWORK_Handle *desc)
{
  GNUNET_free_non_null (desc->addr);
  GNUNET_free (desc);
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
  ret = GNUNET_new (struct GNUNET_NETWORK_Handle);
  ret->fd = fd;
  ret->af = AF_UNSPEC;
  return ret;
#else
  if (fcntl (fd, F_GETFD) < 0)
    return NULL;                /* invalid FD */
  ret = GNUNET_new (struct GNUNET_NETWORK_Handle);
  ret->fd = fd;
  ret->af = AF_UNSPEC;
  return ret;
#endif
}


/**
 * Connect a socket to some remote address.
 *
 * @param desc socket
 * @param address peer address
 * @param address_len length of @a address
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
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
 * @param optlen length of @a optval
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
int
GNUNET_NETWORK_socket_getsockopt (const struct GNUNET_NETWORK_Handle *desc,
                                  int level, int optname, void *optval,
                                  socklen_t *optlen)
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
 *
 * @param desc socket
 * @param backlog length of the listen queue
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
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
 * @param desc socket
 * @returns #GNUNET_NO if no data is available, or on error!
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
 * Read data from a socket (always non-blocking).
 *
 * @param desc socket
 * @param buffer buffer
 * @param length length of @a buffer
 * @param src_addr either the source to recv from, or all zeroes
 *        to be filled in by recvfrom
 * @param addrlen length of the @a src_addr
 */
ssize_t
GNUNET_NETWORK_socket_recvfrom (const struct GNUNET_NETWORK_Handle *desc,
                                void *buffer, size_t length,
                                struct sockaddr *src_addr, socklen_t *addrlen)
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
 *
 * @param desc socket
 * @param buffer buffer
 * @param length length of @a buffer
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
 * @param length size of the @a buffer
 * @return number of bytes sent, #GNUNET_SYSERR on error
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
 * @param dest_len length of @a address
 * @return number of bytes sent, #GNUNET_SYSERR on error
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
 *
 * @param fd socket
 * @param level protocol level of the option
 * @param option_name option identifier
 * @param option_value value to set
 * @param option_len size of @a option_value
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
int
GNUNET_NETWORK_socket_setsockopt (struct GNUNET_NETWORK_Handle *fd,
                                  int level,
                                  int option_name,
                                  const void *option_value,
                                  socklen_t option_len)
{
  int ret;

  ret = setsockopt (fd->fd,
                    level,
                    option_name,
                    option_value,
                    option_len);
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

  ret = GNUNET_new (struct GNUNET_NETWORK_Handle);
  ret->fd = socket (domain, type, protocol);
  if (-1 == ret->fd)
  {
    GNUNET_free (ret);
    return NULL;
  }
  if (GNUNET_OK !=
      initialize_network_handle (ret, domain, type))
    return NULL;
  return ret;
}


/**
 * Shut down socket operations
 * @param desc socket
 * @param how type of shutdown
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
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
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
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
 *
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
 *
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
 *
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
 *
 * @param dst the fd set to add to
 * @param src the fd set to add from
 */
void
GNUNET_NETWORK_fdset_add (struct GNUNET_NETWORK_FDSet *dst,
                          const struct GNUNET_NETWORK_FDSet *src)
{
#ifndef MINGW
  int nfds;

  for (nfds = src->nsds; nfds >= 0; nfds--)
    if (FD_ISSET (nfds, &src->sds))

    {
      FD_SET (nfds, &dst->sds);
      if (nfds + 1 > dst->nsds)
        dst->nsds = nfds + 1;
    }
#else
  /* This is MinGW32-specific implementation that relies on the code that
   * winsock2.h defines for FD_SET. Namely, it relies on FD_SET checking
   * that fd being added is not already in the set.
   * Also relies on us knowing what's inside fd_set (fd_count and fd_array).
   */
  int i;
  for (i = 0; i < src->sds.fd_count; i++)
    FD_SET (src->sds.fd_array[i], &dst->sds);
  if (src->nsds > dst->nsds)
    dst->nsds = src->nsds;

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
 * @return #GNUNET_YES if FD is set in the set
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
 * @return #GNUNET_YES if the file handle is part of the set
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
 * @return #GNUNET_YES if they do overlap, #GNUNET_NO otherwise
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
 *
 * @return a new fd set
 */
struct GNUNET_NETWORK_FDSet *
GNUNET_NETWORK_fdset_create ()
{
  struct GNUNET_NETWORK_FDSet *fds;

  fds = GNUNET_new (struct GNUNET_NETWORK_FDSet);
#ifdef MINGW
  fds->handles = GNUNET_CONTAINER_slist_create ();
#endif
  GNUNET_NETWORK_fdset_zero (fds);
  return fds;
}


/**
 * Releases the associated memory of an fd set
 *
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

#if MINGW
struct _select_params
{
  fd_set *r;
  fd_set *w;
  fd_set *e;
  struct timeval *tv;
  HANDLE wakeup;
  HANDLE standby;
  SOCKET wakeup_socket;
  int status;
};

static DWORD WINAPI
_selector (LPVOID p)
{
  struct _select_params *sp = p;

  while (1)
  {
    WaitForSingleObject (sp->standby, INFINITE);
    ResetEvent (sp->standby);
    sp->status = select (1, sp->r, sp->w, sp->e, sp->tv);
    if (FD_ISSET (sp->wakeup_socket, sp->r))
    {
      FD_CLR (sp->wakeup_socket, sp->r);
      sp->status -= 1;
    }
    SetEvent (sp->wakeup);
  }
  return 0;
}
#endif


#ifndef MINGW
/**
 * Check if sockets or pipes meet certain conditions
 *
 * @param rfds set of sockets or pipes to be checked for readability
 * @param wfds set of sockets or pipes to be checked for writability
 * @param efds set of sockets or pipes to be checked for exceptions
 * @param timeout relative value when to return
 * @return number of selected sockets or pipes, #GNUNET_SYSERR on error
 */
int
GNUNET_NETWORK_socket_select (struct GNUNET_NETWORK_FDSet *rfds,
                              struct GNUNET_NETWORK_FDSet *wfds,
                              struct GNUNET_NETWORK_FDSet *efds,
                              const struct GNUNET_TIME_Relative timeout)
{
  int nfds;
  struct timeval tv;

  if (NULL != rfds)
    nfds = rfds->nsds;
  else
    nfds = 0;
  if (NULL != wfds)
    nfds = GNUNET_MAX (nfds, wfds->nsds);
  if (NULL != efds)
    nfds = GNUNET_MAX (nfds, efds->nsds);
  if ((nfds == 0) &&
      (timeout.rel_value_us == GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us))
  {
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Fatal internal logic error, process hangs in `%s' (abort with CTRL-C)!\n"),
         "select");
  }
  tv.tv_sec = timeout.rel_value_us / GNUNET_TIME_UNIT_SECONDS.rel_value_us;
  tv.tv_usec =
    (timeout.rel_value_us -
     (tv.tv_sec * GNUNET_TIME_UNIT_SECONDS.rel_value_us));
  return select (nfds,
		 (NULL != rfds) ? &rfds->sds : NULL,
                 (NULL != wfds) ? &wfds->sds : NULL,
                 (NULL != efds) ? &efds->sds : NULL,
                 (timeout.rel_value_us ==
                  GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us) ? NULL : &tv);
}


#else
/* MINGW */


/**
 * Check if sockets or pipes meet certain conditions, version for W32.
 *
 * @param rfds set of sockets or pipes to be checked for readability
 * @param wfds set of sockets or pipes to be checked for writability
 * @param efds set of sockets or pipes to be checked for exceptions
 * @param timeout relative value when to return
 * @return number of selected sockets or pipes, #GNUNET_SYSERR on error
 */
int
GNUNET_NETWORK_socket_select (struct GNUNET_NETWORK_FDSet *rfds,
                              struct GNUNET_NETWORK_FDSet *wfds,
                              struct GNUNET_NETWORK_FDSet *efds,
                              const struct GNUNET_TIME_Relative timeout)
{
  int nfds = 0;
  int handles = 0;
  int ex_handles = 0;
  int read_handles = 0;
  int write_handles = 0;

  int i = 0;
  int retcode = 0;
  uint64_t mcs_total = 0;
  DWORD ms_rounded = 0;

  int nhandles = 0;

  static HANDLE hEventPipeWrite = 0;
  static HANDLE hEventReadReady = 0;

  static struct _select_params sp;
  static HANDLE select_thread = NULL;
  static HANDLE select_finished_event = NULL;
  static HANDLE select_standby_event = NULL;
  static SOCKET select_wakeup_socket = -1;
  static SOCKET select_send_socket = -1;
  static struct timeval select_timeout;

  int readPipes = 0;
  int writePipePos = 0;

  HANDLE handle_array[FD_SETSIZE + 2];
  int returncode = -1;
  int returnedpos = 0;

  struct GNUNET_CONTAINER_SList *handles_read;
  struct GNUNET_CONTAINER_SList *handles_write;
  struct GNUNET_CONTAINER_SList *handles_except;

  int selectret = 0;

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
  struct timeval tv;

  if (NULL != rfds)
  {
    nfds = rfds->nsds;
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
  }
  if (NULL != wfds)
  {
    nfds = GNUNET_MAX (nfds, wfds->nsds);
    handles += write_handles = GNUNET_CONTAINER_slist_count (wfds->handles);
  }
  if (NULL != efds)
  {
    nfds = GNUNET_MAX (nfds, efds->nsds);
    handles += ex_handles = GNUNET_CONTAINER_slist_count (efds->handles);
  }

  if ((nfds == 0) &&
      (timeout.rel_value_us == GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us)
      && (handles == 0) )
  {
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Fatal internal logic error, process hangs in `%s' (abort with CTRL-C)!\n"),
         "select");
  }
#define SAFE_FD_ISSET(fd, set)  (set != NULL && FD_ISSET(fd, set))
  /* calculate how long we need to wait in microseconds */
  if (timeout.rel_value_us == GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us)
  {
    mcs_total = INFINITE;
    ms_rounded = INFINITE;
  }
  else
  {
    mcs_total = timeout.rel_value_us / GNUNET_TIME_UNIT_MICROSECONDS.rel_value_us;
    ms_rounded = (DWORD) (mcs_total / GNUNET_TIME_UNIT_MILLISECONDS.rel_value_us);
    if (mcs_total > 0 && ms_rounded == 0)
      ms_rounded = 1;
  }
  /* select() may be used as a portable way to sleep */
  if (!(rfds || wfds || efds))
  {
    Sleep (ms_rounded);
    return 0;
  }

  if (NULL == select_thread)
  {
    SOCKET select_listening_socket = -1;
    struct sockaddr_in s_in;
    int alen;
    int res;
    unsigned long p;

    select_standby_event = CreateEvent (NULL, TRUE, FALSE, NULL);
    select_finished_event = CreateEvent (NULL, TRUE, FALSE, NULL);

    select_wakeup_socket = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);

    select_listening_socket = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);

    p = 1;
    res = ioctlsocket (select_wakeup_socket, FIONBIO, &p);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Select thread initialization: ioctlsocket() returns %d\n", res);

    alen = sizeof (s_in);
    s_in.sin_family = AF_INET;
    s_in.sin_port = 0;
    s_in.sin_addr.S_un.S_un_b.s_b1 = 127;
    s_in.sin_addr.S_un.S_un_b.s_b2 = 0;
    s_in.sin_addr.S_un.S_un_b.s_b3 = 0;
    s_in.sin_addr.S_un.S_un_b.s_b4 = 1;
    res = bind (select_listening_socket, (const struct sockaddr *) &s_in, sizeof (s_in));
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Select thread initialization: bind() returns %d\n", res);

    res = getsockname (select_listening_socket, (struct sockaddr *) &s_in, &alen);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Select thread initialization: getsockname() returns %d\n", res);

    res = listen (select_listening_socket, SOMAXCONN);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Select thread initialization: listen() returns %d\n", res);

    res = connect (select_wakeup_socket, (const struct sockaddr *) &s_in, sizeof (s_in));
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Select thread initialization: connect() returns %d\n", res);

    select_send_socket = accept (select_listening_socket, (struct sockaddr *) &s_in, &alen);

    closesocket (select_listening_socket);

    sp.wakeup = select_finished_event;
    sp.standby = select_standby_event;
    sp.wakeup_socket = select_wakeup_socket;

    select_thread = CreateThread (NULL, 0, _selector, &sp, 0, NULL);
  }


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

  /* Start by doing a fast check on sockets and pipes (without waiting). It is cheap, and is sufficient most of the time.
     By profiling we detected that to be true in 90% of the cases.
  */

  /* Do the select now */
  select_timeout.tv_sec = 0;
  select_timeout.tv_usec = 0;

  /* Copy all the writes to the except, so we can detect connect() errors */
  for (i = 0; i < awrite.fd_count; i++)
    FD_SET (awrite.fd_array[i], &aexcept);
  if (aread.fd_count > 0 || awrite.fd_count > 0 || aexcept.fd_count > 0)
    selectret = select (1, (rfds != NULL) ? &aread : NULL,
        (wfds != NULL) ? &awrite : NULL, &aexcept, &select_timeout);
  else
    selectret = 0;
  if (selectret == -1)
  {
    /* Throw an error early on, while we still have the context. */
    LOG (GNUNET_ERROR_TYPE_ERROR, "W32 select(%d, %d, %d) failed: %lu\n",
        rfds ? aread.fd_count : 0, wfds ? awrite.fd_count : 0, aexcept.fd_count, GetLastError ());
    GNUNET_abort ();
  }

  /* Check aexcept, add its contents to awrite
     This is technically wrong (aexcept might have its own descriptors), we should
     have checked that descriptors were in awrite originally before re-adding them from
     aexcept. Luckily, GNUnet never uses aexcept for anything, so this does not become a problem (yet). */
  for (i = 0; i < aexcept.fd_count; i++)
    FD_SET (aexcept.fd_array[i], &awrite);

  /* If our select returned something or is a 0-timed request, then also check the pipes and get out of here! */
  /* Sadly, it means code duplication :( */
  if ((selectret > 0) || (mcs_total == 0))
  {
    /* Read Pipes */
    if (rfds && read_handles)
    {
      struct GNUNET_CONTAINER_SList_Iterator i;
      int c;

      for (c = 0, i = GNUNET_CONTAINER_slist_begin (rfds->handles);
          GNUNET_CONTAINER_slist_end (&i) != GNUNET_YES;
          GNUNET_CONTAINER_slist_next (&i), c++)
      {
        struct GNUNET_DISK_FileHandle *fh;

        fh = (struct GNUNET_DISK_FileHandle *) GNUNET_CONTAINER_slist_get (&i,NULL);
        if (fh->type == GNUNET_DISK_HANLDE_TYPE_PIPE)
        {
          DWORD error;
          BOOL bret;

          SetLastError (0);
          DWORD waitstatus = 0;
          bret = PeekNamedPipe (fh->h, NULL, 0, NULL, &waitstatus, NULL);
          error = GetLastError ();
          LOG (GNUNET_ERROR_TYPE_DEBUG, "Peek at read pipe %d (0x%x) returned %d (%d bytes available) GLE %u\n",
              c, fh->h, bret, waitstatus, error);
          if (bret == 0)
          {
            /* TODO: either add more errors to this condition, or eliminate it
             * entirely (failed to peek -> pipe is in serious trouble, should
             * be selected as readable).
             */
            if (error != ERROR_BROKEN_PIPE && error != ERROR_INVALID_HANDLE)
              continue;
          }
          else if (waitstatus <= 0)
            continue;
          GNUNET_CONTAINER_slist_add (handles_read, GNUNET_CONTAINER_SLIST_DISPOSITION_TRANSIENT,
              fh, sizeof (struct GNUNET_DISK_FileHandle));
          retcode++;
          LOG (GNUNET_ERROR_TYPE_DEBUG, "Added read Pipe 0x%x (0x%x)\n",
              fh, fh->h);
        }
        else
        {
          GNUNET_CONTAINER_slist_add (handles_read, GNUNET_CONTAINER_SLIST_DISPOSITION_TRANSIENT,
              fh, sizeof (struct GNUNET_DISK_FileHandle));
          retcode++;
        }
      }
    }
    if (wfds && write_handles)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
          "Adding the write ready event to the array as %d\n", nhandles);
      GNUNET_CONTAINER_slist_append (handles_write, wfds->handles);
      retcode += write_handles;
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

        fh = (struct GNUNET_DISK_FileHandle *) GNUNET_CONTAINER_slist_get (&i, NULL);
        if (fh->type == GNUNET_DISK_HANLDE_TYPE_PIPE)
        {
          if (PeekNamedPipe (fh->h, NULL, 0, NULL, &dwBytes, NULL))
            continue;
          GNUNET_CONTAINER_slist_add (handles_except, GNUNET_CONTAINER_SLIST_DISPOSITION_TRANSIENT,
              fh, sizeof (struct GNUNET_DISK_FileHandle));
          retcode++;
        }
      }
    }

    /* Add our select() result.*/
    if (selectret >= 0)
      retcode += selectret;

    if (rfds)
    {
      GNUNET_NETWORK_fdset_zero (rfds);
      if (selectret != -1)
        GNUNET_NETWORK_fdset_copy_native (rfds, &aread, selectret);
      GNUNET_CONTAINER_slist_append (rfds->handles, handles_read);
    }
    if (wfds)
    {
      GNUNET_NETWORK_fdset_zero (wfds);
      if (selectret != -1)
        GNUNET_NETWORK_fdset_copy_native (wfds, &awrite, selectret);
      GNUNET_CONTAINER_slist_append (wfds->handles, handles_write);
    }
    if (efds)
    {
      GNUNET_NETWORK_fdset_zero (efds);
      if (selectret != -1)
        GNUNET_NETWORK_fdset_copy_native (efds, &aexcept, selectret);
      GNUNET_CONTAINER_slist_append (efds->handles, handles_except);
    }
    GNUNET_CONTAINER_slist_destroy (handles_read);
    GNUNET_CONTAINER_slist_destroy (handles_write);
    GNUNET_CONTAINER_slist_destroy (handles_except);

    if (selectret == -1)
      return -1;
    return retcode;
  }

  /* If we got this far, use slower implementation that is able to do a waiting select
     on both sockets and pipes simultaneously */

  /* Events for pipes */
  if (!hEventReadReady)
    hEventReadReady = CreateEvent (NULL, TRUE, TRUE, NULL);
  if (!hEventPipeWrite)
    hEventPipeWrite = CreateEvent (NULL, TRUE, TRUE, NULL);
  readPipes = 0;
  writePipePos = -1;

  retcode = 0;

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
      if (fh->type == GNUNET_DISK_HANLDE_TYPE_PIPE)
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
      if (fh->type == GNUNET_DISK_HANLDE_TYPE_PIPE)
      {
        if (!PeekNamedPipe (fh->h, NULL, 0, NULL, &dwBytes, NULL))
        {
          GNUNET_CONTAINER_slist_add (handles_except,
                                      GNUNET_CONTAINER_SLIST_DISPOSITION_TRANSIENT,
                                      fh,
                                      sizeof (struct GNUNET_DISK_FileHandle));
        }
      }
    }
  }

  sp.status = 0;

  if (nfds > 0)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Adding the socket event to the array as %d\n",
	 nhandles);
    handle_array[nhandles++] = select_finished_event;
    if (timeout.rel_value_us == GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us)
      sp.tv = NULL;
    else
    {
      select_timeout.tv_sec = timeout.rel_value_us / GNUNET_TIME_UNIT_SECONDS.rel_value_us;
      select_timeout.tv_usec =(timeout.rel_value_us -
          (select_timeout.tv_sec * GNUNET_TIME_UNIT_SECONDS.rel_value_us));
      sp.tv = &select_timeout;
    }
    FD_SET (select_wakeup_socket, &aread);
    do
    {
      i = recv (select_wakeup_socket, (char *) &returnedpos, 1, 0);
    } while (i == 1);
    sp.r = &aread;
    sp.w = &awrite;
    sp.e = &aexcept;
    /* Failed connections cause sockets to be set in errorfds on W32,
     * but on POSIX it should set them in writefds.
     * First copy all awrite sockets to aexcept, later we'll
     * check aexcept and set its contents in awrite as well
     * Sockets are also set in errorfds when OOB data is available,
     * but we don't use OOB data.
     */
    for (i = 0; i < awrite.fd_count; i++)
      FD_SET (awrite.fd_array[i], &aexcept);
    ResetEvent (select_finished_event);
    SetEvent (select_standby_event);
  }

  handle_array[nhandles] = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "nfds: %d, handles: %d, will wait: %llu mcs\n",
       nfds, nhandles, mcs_total);
  if (nhandles)
  {
    returncode =
        WaitForMultipleObjects (nhandles, handle_array, FALSE, ms_rounded);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "WaitForMultipleObjects Returned : %d\n", returncode);
  }
  else if (nfds > 0)
  {
    GNUNET_break (0); /* This branch shouldn't actually be executed...*/
    i = (int) WaitForSingleObject (select_finished_event, INFINITE);
    returncode = WAIT_TIMEOUT;
  }
  else
  {
    /* Shouldn't come this far. If it does - investigate. */
    GNUNET_assert (0);
  }

  if (nfds > 0)
  {
    /* Don't wake up select-thread when delay is 0, it should return immediately
     * and wake up by itself.
     */
    if (mcs_total != 0)
      i = send (select_send_socket, (const char *) &returnedpos, 1, 0);
    i = (int) WaitForSingleObject (select_finished_event, INFINITE);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Finished waiting for the select thread: %d %d\n", i, sp.status);
    if (mcs_total != 0)
    {
      do
      {
        i = recv (select_wakeup_socket, (char *) &returnedpos, 1, 0);
      } while (i == 1);
    }
    /* Check aexcept, add its contents to awrite */
    for (i = 0; i < aexcept.fd_count; i++)
      FD_SET (aexcept.fd_array[i], &awrite);
  }

  returnedpos = returncode - WAIT_OBJECT_0;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "return pos is : %d\n", returnedpos);

  if (nhandles && (returnedpos < nhandles))
  {
    DWORD waitstatus;

    if (sp.status > 0)
      retcode += sp.status;

    if ((writePipePos != -1) && (returnedpos < writePipePos))
    {
      GNUNET_CONTAINER_slist_append (handles_write, wfds->handles);
      retcode += write_handles;
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Added write pipe\n");
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG, "ReadPipes is : %d\n", readPipes);
    /* We have some pipes ready for read. */
    if (returnedpos < readPipes)
    {
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
          /* TODO: either add more errors to this condition, or eliminate it
           * entirely (failed to peek -> pipe is in serious trouble, should
           * be selected as readable).
           */
          if (error != ERROR_BROKEN_PIPE && error != ERROR_INVALID_HANDLE)
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
  }
  if (!nhandles || (returnedpos >= nhandles))
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Returning from _select() with nothing!\n");
  if (rfds)
  {
    struct GNUNET_CONTAINER_SList_Iterator t;

    for (t = GNUNET_CONTAINER_slist_begin (rfds->handles);
         GNUNET_CONTAINER_slist_end (&t) != GNUNET_YES;
         GNUNET_CONTAINER_slist_next (&t))
    {
      struct GNUNET_DISK_FileHandle *fh;

      fh = (struct GNUNET_DISK_FileHandle *) GNUNET_CONTAINER_slist_get (&t,
                                                                         NULL);
      if (fh->type == GNUNET_DISK_HANLDE_TYPE_PIPE)
      {
        CancelIo (fh->h);
      }
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Zeroing rfds%s\n", (retcode != -1 && nhandles && (returnedpos < nhandles)) ? ", copying fdset" : "");
    GNUNET_NETWORK_fdset_zero (rfds);
    if (retcode != -1 && nhandles && (returnedpos < nhandles))
      GNUNET_NETWORK_fdset_copy_native (rfds, &aread, retcode);
    GNUNET_CONTAINER_slist_append (rfds->handles, handles_read);
  }
  if (wfds)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Zeroing wfds%s\n", (retcode != -1 && nhandles && (returnedpos < nhandles)) ? ", copying fdset" : "");
    GNUNET_NETWORK_fdset_zero (wfds);
    if (retcode != -1 && nhandles && (returnedpos < nhandles))
      GNUNET_NETWORK_fdset_copy_native (wfds, &awrite, retcode);
    GNUNET_CONTAINER_slist_append (wfds->handles, handles_write);
  }
  if (efds)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Zeroing efds%s\n", (retcode != -1 && nhandles && (returnedpos < nhandles)) ? ", copying fdset" : "");
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

    LOG (GNUNET_ERROR_TYPE_DEBUG, "rfds:\n");
    for (i = 0; i < rfds->sds.fd_count; i++)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "%d\n", rfds->sds.fd_array[i]);
    }
    for (t = GNUNET_CONTAINER_slist_begin (rfds->handles);
         GNUNET_CONTAINER_slist_end (&t) != GNUNET_YES;
         GNUNET_CONTAINER_slist_next (&t))
    {
      struct GNUNET_DISK_FileHandle *fh;

      fh = (struct GNUNET_DISK_FileHandle *) GNUNET_CONTAINER_slist_get (&t,
                                                                         NULL);
      LOG (GNUNET_ERROR_TYPE_DEBUG, "%d\n", fh->h);
    }
  }
  if (wfds)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "wfds:\n");
    for (i = 0; i < wfds->sds.fd_count; i++)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "%d\n", wfds->sds.fd_array[i]);
    }
  }
  if (efds)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "efds:\n");
    for (i = 0; i < efds->sds.fd_count; i++)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "%d\n", efds->sds.fd_array[i]);
    }
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Returning %d or 0\n", retcode);
#endif
  if (nhandles && (returnedpos < nhandles))
    return retcode;
  else
    return 0;
}

/* MINGW */
#endif

/* end of network.c */
