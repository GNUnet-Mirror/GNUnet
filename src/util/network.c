/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013 Christian Grothoff (and other contributing authors)

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


/**
 * @brief handle to a socket
 */
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
  if (SOCKET_ERROR ==
      ioctlsocket (fd->fd,
                   FIONBIO,
                   &mode))

  {
    SetErrnoFromWinsockError (WSAGetLastError ());
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING,
                  "ioctlsocket");
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;

#else
  /* not MINGW */
  int flags = fcntl (fd->fd, F_GETFL);

  if (flags == -1)

  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING,
                  "fcntl");
    return GNUNET_SYSERR;
  }
  if (doBlock)
    flags &= ~O_NONBLOCK;

  else
    flags |= O_NONBLOCK;
  if (0 != fcntl (fd->fd,
                  F_SETFL,
                  flags))

  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING,
                  "fcntl");
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

  if (0 !=
      setsockopt (h->fd,
                  IPPROTO_TCP,
                  TCP_NODELAY,
                  &value, sizeof (value)))
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING,
                  "setsockopt");
#else
  const char *abs_value = "1";

  if (0 !=
      setsockopt (h->fd, IPPROTO_TCP, TCP_NODELAY,
		  (const void *) abs_value,
                  sizeof (abs_value)))
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING,
                  "setsockopt");
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
			   int af,
                           int type)
{
  int eno;

  h->af = af;
  h->type = type;
  if (h->fd == INVALID_SOCKET)
  {
#ifdef MINGW
    SetErrnoFromWinsockError (WSAGetLastError ());
#endif
    eno = errno;
    GNUNET_free (h);
    errno = eno;
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
    eno = errno;
    GNUNET_break (0);
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (h));
    errno = eno;
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
  int eno;

  ret = GNUNET_new (struct GNUNET_NETWORK_Handle);
#if DEBUG_NETWORK
  {
    struct sockaddr_storage name;
    socklen_t namelen = sizeof (name);

    int gsn = getsockname (desc->fd,
                           (struct sockaddr *) &name,
                           &namelen);

    if (0 == gsn)
      LOG (GNUNET_ERROR_TYPE_DEBUG,
	   "Accepting connection on `%s'\n",
           GNUNET_a2s ((const struct sockaddr *) &name,
                       namelen));
  }
#endif
  ret->fd = accept (desc->fd,
                    address,
                    address_len);
  if (-1 == ret->fd)
  {
    eno = errno;
    GNUNET_free (ret);
    errno = eno;
    return NULL;
  }
  if (GNUNET_OK !=
      initialize_network_handle (ret,
                                 (NULL != address) ? address->sa_family : desc->af,
                                 SOCK_STREAM))
  {

    return NULL;
  }
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
        LOG_STRERROR (GNUNET_ERROR_TYPE_DEBUG,
                      "setsockopt");
  }
#endif
#endif
#ifndef WINDOWS
  {
    const int on = 1;

    /* This is required here for TCP sockets, but only on UNIX */
    if ( (SOCK_STREAM == desc->type) &&
         (0 != setsockopt (desc->fd,
                           SOL_SOCKET,
                           SO_REUSEADDR,
                           &on, sizeof (on))))
      LOG_STRERROR (GNUNET_ERROR_TYPE_DEBUG,
                    "setsockopt");
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
       "Closed 0x%x, closesocket() returned %d, GLE is %u\n",
       desc->fd,
       ret,
       error);
#else
  ret = close (desc->fd);
#endif
#ifndef WINDOWS
  const struct sockaddr_un *un;

  /* Cleanup the UNIX domain socket and its parent directories in case of non
     abstract sockets */
  if ( (AF_UNIX == desc->af) &&
       (NULL != desc->addr) &&
       (NULL != (un = (const struct sockaddr_un *) desc->addr)->sun_path) &&
       ('\0' != un->sun_path[0]) )
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
  if (0 !=
      WSAIoctl (fd, FIONBIO,
                (void *) &i, sizeof (i),
                NULL, 0, &d,
                NULL, NULL))
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

  ret = connect (desc->fd,
                 address,
                 address_len);
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
                                  int level,
                                  int optname,
                                  void *optval,
                                  socklen_t *optlen)
{
  int ret;

  ret = getsockopt (desc->fd,
                    level,
                    optname,
                    optval, optlen);

#ifdef MINGW
  if ( (0 == ret) &&
       (SOL_SOCKET == level) &&
       (SO_ERROR == optname) )
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

  ret = listen (desc->fd,
                backlog);
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
GNUNET_NETWORK_socket_recvfrom_amount (const struct GNUNET_NETWORK_Handle *desc)
{
  int error;

  /* How much is there to be read? */
#ifndef WINDOWS
  int pending;

  error = ioctl (desc->fd,
                 FIONREAD,
                 &pending);
  if (error == 0)
    return (ssize_t) pending;
  return GNUNET_NO;
#else
  u_long pending;

  error = ioctlsocket (desc->fd,
                       FIONREAD,
                       &pending);
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
                                void *buffer,
                                size_t length,
                                struct sockaddr *src_addr,
                                socklen_t *addrlen)
{
  int ret;
  int flags;

  flags = 0;

#ifdef MSG_DONTWAIT
  flags |= MSG_DONTWAIT;

#endif
  ret = recvfrom (desc->fd,
                  buffer,
                  length,
                  flags,
                  src_addr,
                  addrlen);
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
 * @return number of bytes received, -1 on error
 */
ssize_t
GNUNET_NETWORK_socket_recv (const struct GNUNET_NETWORK_Handle *desc,
                            void *buffer,
                            size_t length)
{
  int ret;
  int flags;

  flags = 0;

#ifdef MSG_DONTWAIT
  flags |= MSG_DONTWAIT;
#endif
  ret = recv (desc->fd,
              buffer,
              length,
              flags);
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
GNUNET_NETWORK_socket_send (const struct GNUNET_NETWORK_Handle *desc,
                            const void *buffer,
                            size_t length)
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
  ret = send (desc->fd,
              buffer,
              length,
              flags);
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
 * @param length size of the @a message
 * @param dest_addr destination address
 * @param dest_len length of @a address
 * @return number of bytes sent, #GNUNET_SYSERR on error
 */
ssize_t
GNUNET_NETWORK_socket_sendto (const struct GNUNET_NETWORK_Handle *desc,
                              const void *message,
                              size_t length,
                              const struct sockaddr *dest_addr,
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
GNUNET_NETWORK_socket_create (int domain,
                              int type,
                              int protocol)
{
  struct GNUNET_NETWORK_Handle *ret;
  int fd;

  fd = socket (domain, type, protocol);
  if (-1 == fd)
    return NULL;
  ret = GNUNET_new (struct GNUNET_NETWORK_Handle);
  ret->fd = fd;
  if (GNUNET_OK !=
      initialize_network_handle (ret,
                                 domain,
                                 type))
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
GNUNET_NETWORK_socket_shutdown (struct GNUNET_NETWORK_Handle *desc,
                                int how)
{
  int ret;

  ret = shutdown (desc->fd, how);
#ifdef MINGW
  if (0 != ret)
    SetErrnoFromWinsockError (WSAGetLastError ());
#endif
  return (0 == ret) ? GNUNET_OK : GNUNET_SYSERR;
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
       setsockopt (desc->fd,
                   SOL_SOCKET,
                   SO_SNDBUF,
                   (char *) &value,
                   sizeof (value))))
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING,
                  "setsockopt");
  if (0 !=
      (ret =
       setsockopt (desc->fd,
                   SOL_SOCKET,
                   SO_RCVBUF,
                   (char *) &value,
                   sizeof (value))))
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING,
                  "setsockopt");
#elif LINUX
  int value = 0;

  if (0 !=
      (ret =
       setsockopt (desc->fd,
                   SOL_SOCKET,
                   SO_SNDBUF,
                   &value,
                   sizeof (value))))
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING,
                  "setsockopt");
  if (0 !=
      (ret =
       setsockopt (desc->fd,
                   SOL_SOCKET,
                   SO_RCVBUF,
                   &value,
                   sizeof (value))))
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING,
                  "setsockopt");
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
  fds->handles_pos = 0;
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
  FD_SET (desc->fd,
          &fds->sds);
  fds->nsds = GNUNET_MAX (fds->nsds,
                          desc->fd + 1);
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
  return FD_ISSET (desc->fd,
                   &fds->sds);
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
      FD_SET (nfds, &dst->sds);
  dst->nsds = GNUNET_MAX (dst->nsds,
                          src->nsds);
#else
  /* This is MinGW32-specific implementation that relies on the code that
   * winsock2.h defines for FD_SET. Namely, it relies on FD_SET checking
   * that fd being added is not already in the set.
   * Also relies on us knowing what's inside fd_set (fd_count and fd_array).
   *
   * NOTE: I don't understand why the UNIX-logic wouldn't work
   * for the first part here as well. -CG
   */
  unsigned int i;

  for (i = 0; i < src->sds.fd_count; i++)
    FD_SET (src->sds.fd_array[i],
            &dst->sds);
  dst->nsds = GNUNET_MAX (src->nsds,
                          dst->nsds);

  /* also copy over `struct GNUNET_DISK_FileHandle` array */
  if (dst->handles_pos + src->handles_pos > dst->handles_size)
    GNUNET_array_grow (dst->handles,
                       dst->handles_size,
                       ((dst->handles_pos + src->handles_pos) << 1));
  for (i = 0; i < src->handles_pos; i++)
    dst->handles[dst->handles_pos++] = src->handles[i];
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
  FD_COPY (&from->sds,
           &to->sds);
  to->nsds = from->nsds;
#ifdef MINGW
  if (from->handles_pos > to->handles_size)
    GNUNET_array_grow (to->handles,
                       to->handles_size,
                       from->handles_pos * 2);
  memcpy (to->handles,
          from->handles,
          from->handles_pos * sizeof (struct GNUNET_NETWORK_Handle *));
  to->handles_pos = from->handles_pos;
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
                                  const fd_set *from,
                                  int nfds)
{
  FD_COPY (from,
           &to->sds);
  to->nsds = nfds;
}


/**
 * Set a native fd in a set
 *
 * @param to destination
 * @param nfd native FD to set
 */
void
GNUNET_NETWORK_fdset_set_native (struct GNUNET_NETWORK_FDSet *to,
                                 int nfd)
{
  GNUNET_assert ((nfd >= 0) && (nfd < FD_SETSIZE));
  FD_SET (nfd, &to->sds);
  to->nsds = GNUNET_MAX (nfd + 1,
                         to->nsds);
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
  if ( (-1 == nfd) ||
       (NULL == to) )
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
  if (fds->handles_pos == fds->handles_size)
    GNUNET_array_grow (fds->handles,
                       fds->handles_size,
                       fds->handles_size * 2 + 2);
  fds->handles[fds->handles_pos++] = h;
#else
  int fd;

  GNUNET_DISK_internal_file_handle_ (h,
                                     &fd,
                                     sizeof (int));
  FD_SET (fd,
          &fds->sds);
  fds->nsds = GNUNET_MAX (fd + 1,
                          fds->nsds);
#endif
}


/**
 * Add a file handle to the fd set
 * @param fds fd set
 * @param h the file handle to add
 */
void
GNUNET_NETWORK_fdset_handle_set_first (struct GNUNET_NETWORK_FDSet *fds,
                                       const struct GNUNET_DISK_FileHandle *h)
{
#ifdef MINGW
  if (fds->handles_pos == fds->handles_size)
    GNUNET_array_grow (fds->handles,
                       fds->handles_size,
                       fds->handles_size * 2 + 2);
  fds->handles[fds->handles_pos] = h;
  if (fds->handles[0] != h)
  {
    const struct GNUNET_DISK_FileHandle *bak = fds->handles[0];
    fds->handles[0] = h;
    fds->handles[fds->handles_pos] = bak;
  }
  fds->handles_pos++;
#else
  GNUNET_NETWORK_fdset_handle_set (fds, h);
#endif
}


/**
 * Check if a file handle is part of an fd set
 *
 * @param fds fd set
 * @param h file handle
 * @return #GNUNET_YES if the file handle is part of the set
 */
int
GNUNET_NETWORK_fdset_handle_isset (const struct GNUNET_NETWORK_FDSet *fds,
                                   const struct GNUNET_DISK_FileHandle *h)
{
#ifdef MINGW
  unsigned int i;

  for (i=0;i<fds->handles_pos;i++)
    if (fds->handles[i] == h)
      return GNUNET_YES;
  return GNUNET_NO;
#else
  return FD_ISSET (h->fd,
                   &fds->sds);
#endif
}


#ifdef MINGW
/**
 * Numerically compare pointers to sort them.
 * Used to test for overlap in the arrays.
 *
 * @param p1 a pointer
 * @param p2 a pointer
 * @return -1, 0 or 1, if the p1 < p2, p1==p2 or p1 > p2.
 */
static int
ptr_cmp (const void *p1,
         const void *p2)
{
  if (p1 == p2)
    return 0;
  if ((intptr_t) p1 < (intptr_t) p2)
    return -1;
  return 1;
}
#endif


/**
 * Checks if two fd sets overlap
 *
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

  nfds = GNUNET_MIN (fds1->nsds,
                     fds2->nsds);
  while (nfds > 0)
  {
    nfds--;
    if ( (FD_ISSET (nfds,
                    &fds1->sds)) &&
         (FD_ISSET (nfds,
                    &fds2->sds)) )
      return GNUNET_YES;
  }
  return GNUNET_NO;
#else
  unsigned int i;
  unsigned int j;

  /* This code is somewhat hacky, we are not supposed to know what's
   * inside of fd_set; also the O(n^2) is really bad... */
  for (i = 0; i < fds1->sds.fd_count; i++)
    for (j = 0; j < fds2->sds.fd_count; j++)
      if (fds1->sds.fd_array[i] == fds2->sds.fd_array[j])
        return GNUNET_YES;

  /* take a short cut if possible */
  if ( (0 == fds1->handles_pos) ||
       (0 == fds2->handles_pos) )
    return GNUNET_NO;

  /* Sort file handles array to avoid quadratic complexity when
     checking for overlap */
  qsort (fds1->handles,
         fds1->handles_pos,
         sizeof (void *),
         &ptr_cmp);
  qsort (fds2->handles,
         fds2->handles_pos,
         sizeof (void *),
         &ptr_cmp);
  i = 0;
  j = 0;
  while ( (i < fds1->handles_pos) &&
          (j < fds2->handles_pos) )
  {
    switch (ptr_cmp (fds1->handles[i],
                     fds2->handles[j]))
    {
    case -1:
      i++;
      break;
    case 0:
      return GNUNET_YES;
    case 1:
      j++;
    }
  }
  return GNUNET_NO;
#endif
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
  GNUNET_array_grow (fds->handles,
                     fds->handles_size,
                     0);
#endif
  GNUNET_free (fds);
}


#if MINGW
/**
 * FIXME.
 */
struct _select_params
{
  /**
   * Read set.
   */
  fd_set *r;

  /**
   * Write set.
   */
  fd_set *w;

  /**
   * Except set.
   */
  fd_set *e;

  /**
   * Timeout for select().
   */
  struct timeval *tv;

  /**
   * FIXME.
   */
  HANDLE wakeup;

  /**
   * FIXME.
   */
  HANDLE standby;

  /**
   * FIXME.
   */
  SOCKET wakeup_socket;

  /**
   * Set to return value from select.
   */
  int status;
};


/**
 * FIXME.
 */
static DWORD WINAPI
_selector (LPVOID p)
{
  struct _select_params *sp = p;

  while (1)
  {
    WaitForSingleObject (sp->standby,
                         INFINITE);
    ResetEvent (sp->standby);
    sp->status = select (1,
                         sp->r,
                         sp->w,
                         sp->e,
                         sp->tv);
    if (FD_ISSET (sp->wakeup_socket,
                  sp->r))
    {
      FD_CLR (sp->wakeup_socket,
              sp->r);
      sp->status -= 1;
    }
    SetEvent (sp->wakeup);
  }
  return 0;
}


static HANDLE hEventPipeWrite;

static HANDLE hEventReadReady;

static struct _select_params sp;

static HANDLE select_thread;

static HANDLE select_finished_event;

static HANDLE select_standby_event;

static SOCKET select_wakeup_socket = -1;

static SOCKET select_send_socket = -1;

static struct timeval select_timeout;


/**
 * On W32, we actually use a thread to help with the
 * event loop due to W32-API limitations.  This function
 * initializes that thread.
 */
static void
initialize_select_thread ()
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
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Select thread initialization: ioctlsocket() returns %d\n",
       res);

  alen = sizeof (s_in);
  s_in.sin_family = AF_INET;
  s_in.sin_port = 0;
  s_in.sin_addr.S_un.S_un_b.s_b1 = 127;
  s_in.sin_addr.S_un.S_un_b.s_b2 = 0;
  s_in.sin_addr.S_un.S_un_b.s_b3 = 0;
  s_in.sin_addr.S_un.S_un_b.s_b4 = 1;
  res = bind (select_listening_socket,
              (const struct sockaddr *) &s_in,
              sizeof (s_in));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Select thread initialization: bind() returns %d\n",
       res);

  res = getsockname (select_listening_socket,
                     (struct sockaddr *) &s_in,
                     &alen);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Select thread initialization: getsockname() returns %d\n",
       res);

  res = listen (select_listening_socket,
                SOMAXCONN);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Select thread initialization: listen() returns %d\n",
       res);
  res = connect (select_wakeup_socket,
                 (const struct sockaddr *) &s_in,
                 sizeof (s_in));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Select thread initialization: connect() returns %d\n",
       res);

  select_send_socket = accept (select_listening_socket,
                               (struct sockaddr *) &s_in,
                               &alen);

  closesocket (select_listening_socket);

  sp.wakeup = select_finished_event;
  sp.standby = select_standby_event;
  sp.wakeup_socket = select_wakeup_socket;

  select_thread = CreateThread (NULL,
                                0,
                                _selector,
                                &sp,
                                0, NULL);
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
    nfds = GNUNET_MAX (nfds,
                       wfds->nsds);
  if (NULL != efds)
    nfds = GNUNET_MAX (nfds,
                       efds->nsds);
  if ((0 == nfds) &&
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
 * Non-blocking test if a pipe is ready for reading.
 *
 * @param fh pipe handle
 * @return #GNUNET_YES if the pipe is ready for reading
 */
static int
pipe_read_ready (const struct GNUNET_DISK_FileHandle *fh)
{
  DWORD error;
  BOOL bret;
  DWORD waitstatus = 0;

  SetLastError (0);
  bret = PeekNamedPipe (fh->h, NULL, 0, NULL, &waitstatus, NULL);
  error = GetLastError ();
  if (0 == bret)
  {
    /* TODO: either add more errors to this condition, or eliminate it
     * entirely (failed to peek -> pipe is in serious trouble, should
     * be selected as readable).
     */
    if ( (error != ERROR_BROKEN_PIPE) &&
         (error != ERROR_INVALID_HANDLE) )
      return GNUNET_NO;
  }
  else if (waitstatus <= 0)
    return GNUNET_NO;
  return GNUNET_YES;
}


/**
 * Non-blocking test if a pipe is having an IO exception.
 *
 * @param fh pipe handle
 * @return #GNUNET_YES if the pipe is having an IO exception.
 */
static int
pipe_except_ready (const struct GNUNET_DISK_FileHandle *fh)
{
  DWORD dwBytes;

  if (PeekNamedPipe (fh->h, NULL, 0, NULL, &dwBytes, NULL))
    return GNUNET_NO;
  return GNUNET_YES;
}


/**
 * Iterate over handles in fds, destructively rewrite the
 * handles array contents of fds so that it starts with the
 * handles that are ready, and update handles_pos accordingly.
 *
 * @param fds set of handles (usually pipes) to be checked for readiness
 * @param except GNUNET_NO if fds should be checked for readiness to read,
 * GNUNET_YES if fds should be checked for exceptions
 * (there is no way to check for write-readiness - pipes are always write-ready)
 * @param set_for_sure a HANDLE that is known to be set already,
 * because WaitForMultipleObjects() returned its index.
 * @return number of ready handles
 */
static int
check_handles_status (struct GNUNET_NETWORK_FDSet *fds,
                      int except,
                      HANDLE set_for_sure)
{
  const struct GNUNET_DISK_FileHandle *fh;
  unsigned int roff;
  unsigned int woff;

  for (woff = 0, roff = 0; roff < fds->handles_pos; roff++)
  {
    fh = fds->handles[roff];
    if (fh == set_for_sure)
    {
      fds->handles[woff++] = fh;
    }
    else if (fh->type == GNUNET_DISK_HANLDE_TYPE_PIPE)
    {
      if ((except && pipe_except_ready (fh)) ||
          (!except && pipe_read_ready (fh)))
        fds->handles[woff++] = fh;
    }
    else if (fh->type == GNUNET_DISK_HANLDE_TYPE_FILE)
    {
      if (!except)
        fds->handles[woff++] = fh;
    }
    else
    {
      if (WAIT_OBJECT_0 == WaitForSingleObject (fh->h, 0))
        fds->handles[woff++] = fh;
    }
  }
  fds->handles_pos = woff;
  return woff;
}


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
  const struct GNUNET_DISK_FileHandle *fh;
  int nfds;
  int handles;
  unsigned int i;
  int retcode;
  uint64_t mcs_total;
  DWORD ms_rounded;
  int nhandles = 0;
  int read_pipes_off;
  HANDLE handle_array[FD_SETSIZE + 2];
  int returncode;
  int returnedpos = 0;
  int selectret;
  fd_set aread;
  fd_set awrite;
  fd_set aexcept;

  nfds = 0;
  handles = 0;
  if (NULL != rfds)
  {
    nfds = GNUNET_MAX (nfds, rfds->nsds);
    handles += rfds->handles_pos;
  }
  if (NULL != wfds)
  {
    nfds = GNUNET_MAX (nfds, wfds->nsds);
    handles += wfds->handles_pos;
  }
  if (NULL != efds)
  {
    nfds = GNUNET_MAX (nfds, efds->nsds);
    handles += efds->handles_pos;
  }

  if ((0 == nfds) &&
      (GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us == timeout.rel_value_us) &&
      (0 == handles) )
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
  if (! (rfds || wfds || efds))
  {
    Sleep (ms_rounded);
    return 0;
  }

  if (NULL == select_thread)
    initialize_select_thread ();

  FD_ZERO (&aread);
  FD_ZERO (&awrite);
  FD_ZERO (&aexcept);
  if (rfds)
    FD_COPY (&rfds->sds, &aread);
  if (wfds)
    FD_COPY (&wfds->sds, &awrite);
  if (efds)
    FD_COPY (&efds->sds, &aexcept);

  /* Start by doing a fast check on sockets and pipes (without
     waiting). It is cheap, and is sufficient most of the time.  By
     profiling we detected that to be true in 90% of the cases.
  */

  /* Do the select now */
  select_timeout.tv_sec = 0;
  select_timeout.tv_usec = 0;

  /* Copy all the writes to the except, so we can detect connect() errors */
  for (i = 0; i < awrite.fd_count; i++)
    FD_SET (awrite.fd_array[i],
            &aexcept);
  if ( (aread.fd_count > 0) ||
       (awrite.fd_count > 0) ||
       (aexcept.fd_count > 0) )
    selectret = select (1,
                        (NULL != rfds) ? &aread : NULL,
                        (NULL != wfds) ? &awrite : NULL,
                        &aexcept,
                        &select_timeout);
  else
    selectret = 0;
  if (-1 == selectret)
  {
    /* Throw an error early on, while we still have the context. */
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "W32 select(%d, %d, %d) failed: %lu\n",
         rfds ? aread.fd_count : 0,
         wfds ? awrite.fd_count : 0,
         aexcept.fd_count,
         GetLastError ());
    GNUNET_assert (0);
  }

  /* Check aexcept, if something is in there and we copied that
     FD before to detect connect() errors, add it back to the
     write set to report errors. */
  if (NULL != wfds)
    for (i = 0; i < aexcept.fd_count; i++)
      if (FD_ISSET (aexcept.fd_array[i],
                    &wfds->sds))
        FD_SET (aexcept.fd_array[i],
                &awrite);


  /* If our select returned something or is a 0-timed request, then
     also check the pipes and get out of here! */
  /* Sadly, it means code duplication :( */
  if ( (selectret > 0) || (0 == mcs_total) )
  {
    retcode = 0;

    /* Read Pipes */
    if (rfds && (rfds->handles_pos > 0))
      retcode += check_handles_status (rfds, GNUNET_NO, NULL);

    /* wfds handles remain untouched, on W32
       we pretend our pipes are "always" write-ready */

    /* except pipes */
    if (efds && (efds->handles_pos > 0))
      retcode += check_handles_status (efds, GNUNET_YES, NULL);

    if (rfds)
    {
      GNUNET_NETWORK_fdset_zero (rfds);
      if (selectret != -1)
        GNUNET_NETWORK_fdset_copy_native (rfds, &aread, selectret);
    }
    if (wfds)
    {
      GNUNET_NETWORK_fdset_zero (wfds);
      if (selectret != -1)
        GNUNET_NETWORK_fdset_copy_native (wfds, &awrite, selectret);
    }
    if (efds)
    {
      GNUNET_NETWORK_fdset_zero (efds);
      if (selectret != -1)
        GNUNET_NETWORK_fdset_copy_native (efds, &aexcept, selectret);
    }
    if (-1 == selectret)
      return -1;
    /* Add our select() FDs to the total return value */
    retcode += selectret;
    return retcode;
  }

  /* If we got this far, use slower implementation that is able to do a waiting select
     on both sockets and pipes simultaneously */

  /* Events for pipes */
  if (! hEventReadReady)
    hEventReadReady = CreateEvent (NULL, TRUE, TRUE, NULL);
  if (! hEventPipeWrite)
    hEventPipeWrite = CreateEvent (NULL, TRUE, TRUE, NULL);
  retcode = 0;

  FD_ZERO (&aread);
  FD_ZERO (&awrite);
  FD_ZERO (&aexcept);
  if (rfds)
    FD_COPY (&rfds->sds, &aread);
  if (wfds)
    FD_COPY (&wfds->sds, &awrite);
  if (efds)
    FD_COPY (&efds->sds, &aexcept);
  /* We will first Add the PIPES to the events */
  /* Track how far in `handle_array` the read pipes go,
     so we may by-pass them quickly if none of them
     are selected. */
  read_pipes_off = 0;
  if (rfds && (rfds->handles_pos > 0))
  {
    for (i = 0; i <rfds->handles_pos; i++)
    {
      fh = rfds->handles[i];
      if (fh->type == GNUNET_DISK_HANLDE_TYPE_EVENT)
      {
        handle_array[nhandles++] = fh->h;
        continue;
      }
      if (fh->type != GNUNET_DISK_HANLDE_TYPE_PIPE)
        continue;
      /* Read zero bytes to check the status of the pipe */
      if (! ReadFile (fh->h, NULL, 0, NULL, fh->oOverlapRead))
      {
        DWORD error_code = GetLastError ();

        if (error_code == ERROR_IO_PENDING)
        {
          /* add as unready */
          handle_array[nhandles++] = fh->oOverlapRead->hEvent;
          read_pipes_off++;
        }
        else
        {
          /* add as ready */
          handle_array[nhandles++] = hEventReadReady;
          read_pipes_off++;
        }
      }
      else
      {
        /* error also counts as ready */
        handle_array[nhandles++] = hEventReadReady;
        read_pipes_off++;
      }
    }
  }

  if (wfds && (wfds->handles_pos > 0))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Adding the write ready event to the array as %d\n",
         nhandles);
    handle_array[nhandles++] = hEventPipeWrite;
  }

  sp.status = 0;
  if (nfds > 0)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Adding the socket event to the array as %d\n",
	 nhandles);
    handle_array[nhandles++] = select_finished_event;
    if (timeout.rel_value_us == GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us)
    {
      sp.tv = NULL;
    }
    else
    {
      select_timeout.tv_sec = timeout.rel_value_us / GNUNET_TIME_UNIT_SECONDS.rel_value_us;
      select_timeout.tv_usec = (timeout.rel_value_us -
                                (select_timeout.tv_sec *
                                 GNUNET_TIME_UNIT_SECONDS.rel_value_us));
      sp.tv = &select_timeout;
    }
    FD_SET (select_wakeup_socket, &aread);
    do
    {
      i = recv (select_wakeup_socket,
                (char *) &returnedpos,
                1,
                0);
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
      FD_SET (awrite.fd_array[i],
              &aexcept);
    ResetEvent (select_finished_event);
    SetEvent (select_standby_event);
  }

  /* NULL-terminate array */
  handle_array[nhandles] = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "nfds: %d, handles: %d, will wait: %llu mcs\n",
       nfds,
       nhandles,
       mcs_total);
  if (nhandles)
  {
    returncode
      = WaitForMultipleObjects (nhandles,
                                handle_array,
                                FALSE,
                                ms_rounded);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "WaitForMultipleObjects Returned: %d\n",
         returncode);
  }
  else if (nfds > 0)
  {
    GNUNET_break (0); /* This branch shouldn't actually be executed...*/
    i = (int) WaitForSingleObject (select_finished_event,
                                   INFINITE);
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
    if (0 != mcs_total)
      i = send (select_send_socket,
                (const char *) &returnedpos,
                1,
                0);
    i = (int) WaitForSingleObject (select_finished_event,
                                   INFINITE);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Finished waiting for the select thread: %d %d\n",
         i,
         sp.status);
    if (0 != mcs_total)
    {
      do
      {
        i = recv (select_wakeup_socket,
                  (char *) &returnedpos,
                  1, 0);
      } while (1 == i);
    }
    /* Check aexcept, add its contents to awrite */
    for (i = 0; i < aexcept.fd_count; i++)
      FD_SET (aexcept.fd_array[i], &awrite);
  }

  returnedpos = returncode - WAIT_OBJECT_0;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "return pos is: %d\n",
       returnedpos);

  if (rfds)
  {
    /* We queued a zero-long read on each pipe to check
     * its state, now we must cancel these read operations.
     * This must be done while rfds->handles_pos is still
     * intact and matches the number of read handles that we
     * got from the caller.
     */
    for (i = 0; i < rfds->handles_pos; i++)
    {
      fh = rfds->handles[i];
      if (GNUNET_DISK_HANLDE_TYPE_PIPE == fh->type)
        CancelIo (fh->h);
    }

    /* We may have some pipes ready for reading. */
    if (returnedpos < read_pipes_off)
      retcode += check_handles_status (rfds, GNUNET_NO, handle_array[returnedpos]);
    else
      rfds->handles_pos = 0;

    if (-1 != sp.status)
      GNUNET_NETWORK_fdset_copy_native (rfds, &aread, retcode);
  }
  if (wfds)
  {
    retcode += wfds->handles_pos;
    /* wfds handles remain untouched */
    if (-1 != sp.status)
      GNUNET_NETWORK_fdset_copy_native (wfds, &awrite, retcode);
  }
  if (efds)
  {
    retcode += check_handles_status (rfds,
                                     GNUNET_YES,
                                     returnedpos < nhandles ? handle_array[returnedpos] : NULL);
    if (-1 != sp.status)
      GNUNET_NETWORK_fdset_copy_native (efds, &aexcept, retcode);
  }

  if (sp.status > 0)
    retcode += sp.status;

  return retcode;
}

/* MINGW */
#endif

/* end of network.c */
