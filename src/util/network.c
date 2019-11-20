/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
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

#define LOG(kind, ...) GNUNET_log_from (kind, "util-network", __VA_ARGS__)
#define LOG_STRERROR_FILE(kind, syscall, \
                          filename) GNUNET_log_from_strerror_file (kind, \
                                                                   "util-network", \
                                                                   syscall, \
                                                                   filename)
#define LOG_STRERROR(kind, syscall) GNUNET_log_from_strerror (kind, \
                                                              "util-network", \
                                                              syscall)

#define DEBUG_NETWORK GNUNET_EXTRA_LOGGING


#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif


/**
 * @brief handle to a socket
 */
struct GNUNET_NETWORK_Handle
{
  int fd;

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
  static int cache_v4 = -1;
  static int cache_v6 = -1;
  static int cache_un = -1;
  int s;
  int ret;

  switch (pf)
  {
  case PF_INET:
    if (-1 != cache_v4)
      return cache_v4;
    break;

  case PF_INET6:
    if (-1 != cache_v6)
      return cache_v6;
    break;

#ifdef PF_UNIX
  case PF_UNIX:
    if (-1 != cache_un)
      return cache_un;
    break;
#endif
  }
  s = socket (pf, SOCK_STREAM, 0);
  if (-1 == s)
  {
    if (EAFNOSUPPORT != errno)
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
                           "socket");
      return GNUNET_SYSERR;
    }
    ret = GNUNET_NO;
  }
  else
  {
    close (s);
    ret = GNUNET_OK;
  }
  switch (pf)
  {
  case PF_INET:
    cache_v4 = ret;
    break;

  case PF_INET6:
    cache_v6 = ret;
    break;

#ifdef PF_UNIX
  case PF_UNIX:
    cache_un = ret;
    break;
#endif
  }
  return ret;
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

  upm = sizeof(dummy.sun_path);
  slen = strlen (unixpath);
  if (slen < upm)
    return unixpath; /* no shortening required */
  GNUNET_CRYPTO_hash (unixpath, slen, &sh);
  while (16 + strlen (unixpath) >= upm)
  {
    if (NULL == (end = strrchr (unixpath, '/')))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _ (
                    "Unable to shorten unix path `%s' while keeping name unique\n"),
                  unixpath);
      GNUNET_free (unixpath);
      return NULL;
    }
    *end = '\0';
  }
  GNUNET_CRYPTO_hash_to_enc (&sh, &ae);
  ae.encoding[16] = '\0';
  strcat (unixpath, (char *) ae.encoding);
  return unixpath;
}


/**
 * If services crash, they can leave a unix domain socket file on the
 * disk. This needs to be manually removed, because otherwise both
 * bind() and connect() for the respective address will fail.  In this
 * function, we test if such a left-over file exists, and if so,
 * remove it (unless there is a listening service at the address).
 *
 * @param un unix domain socket address to check
 */
void
GNUNET_NETWORK_unix_precheck (const struct sockaddr_un *un)
{
  int s;
  int eno;
  struct stat sbuf;
  int ret;

  s = socket (AF_UNIX, SOCK_STREAM, 0);
  if (-1 == s)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
                         "Failed to open AF_UNIX socket");
    return;
  }
  ret = connect (s,
                 (struct sockaddr *) un,
                 sizeof(struct sockaddr_un));
  eno = errno;
  GNUNET_break (0 == close (s));
  if (0 == ret)
    return; /* another process is listening, do not remove! */
  if (ECONNREFUSED != eno)
    return; /* some other error, likely "no such file or directory" -- all well */
  /* should unlink, but sanity checks first */
  if (0 != stat (un->sun_path,
                 &sbuf))
    return; /* failed to 'stat', likely does not exist after all */
  if (S_IFSOCK != (S_IFMT & sbuf.st_mode))
    return; /* refuse to unlink anything except sockets */
  /* finally, really unlink */
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Removing left-over `%s' from previous exeuction\n",
              un->sun_path);
  if (0 != unlink (un->sun_path))
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
                              "unlink",
                              un->sun_path);
}


#ifndef FD_COPY
#define FD_COPY(s, d) do { GNUNET_memcpy ((d), (s), sizeof(fd_set)); } while (0)
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


#ifdef DARWIN
/**
 * The MSG_NOSIGNAL equivalent on Mac OS X
 *
 * @param h the socket to make non-delaying
 */
static int
socket_set_nosigpipe (const struct GNUNET_NETWORK_Handle *h)
{
  int abs_value = 1;

  if (0 !=
      setsockopt (h->fd, SOL_SOCKET, SO_NOSIGPIPE,
                  (const void *) &abs_value,
                  sizeof(abs_value)))
    return GNUNET_SYSERR;
  return GNUNET_OK;
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
  int value = 1;

  if (0 !=
      setsockopt (h->fd,
                  IPPROTO_TCP,
                  TCP_NODELAY,
                  &value, sizeof(value)))
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING,
                  "setsockopt");
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
    eno = errno;
    GNUNET_free (h);
    errno = eno;
    return GNUNET_SYSERR;
  }

  if (h->fd >= FD_SETSIZE)
  {
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (h));
    errno = EMFILE;
    return GNUNET_SYSERR;
  }

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
  if (GNUNET_SYSERR == socket_set_nosigpipe (h))
  {
    eno = errno;
    GNUNET_break (0);
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (h));
    errno = eno;
    return GNUNET_SYSERR;
  }
#endif
  if ((type == SOCK_STREAM)
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
    socklen_t namelen = sizeof(name);

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
                                 (NULL != address) ? address->sa_family :
                                 desc->af,
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
      if (setsockopt (desc->fd,
                      IPPROTO_IPV6,
                      IPV6_V6ONLY,
                      (const void *) &on,
                      sizeof(on)))
        LOG_STRERROR (GNUNET_ERROR_TYPE_DEBUG,
                      "setsockopt");
  }
#endif
#endif
  if (AF_UNIX == address->sa_family)
    GNUNET_NETWORK_unix_precheck ((const struct sockaddr_un *) address);
  {
    const int on = 1;

    /* This is required here for TCP sockets, but only on UNIX */
    if ((SOCK_STREAM == desc->type) &&
        (0 != setsockopt (desc->fd,
                          SOL_SOCKET,
                          SO_REUSEADDR,
                          &on, sizeof(on))))
      LOG_STRERROR (GNUNET_ERROR_TYPE_DEBUG,
                    "setsockopt");
  }
  {
    /* set permissions of newly created non-abstract UNIX domain socket to
       "user-only"; applications can choose to relax this later */
    mode_t old_mask = 0; /* assigned to make compiler happy */
    const struct sockaddr_un *un = (const struct sockaddr_un *) address;
    int not_abstract = 0;

    if ((AF_UNIX == address->sa_family)
        && ('\0' != un->sun_path[0]))  /* Not an abstract socket */
      not_abstract = 1;
    if (not_abstract)
      old_mask = umask (S_IWGRP | S_IRGRP | S_IXGRP | S_IWOTH | S_IROTH
                        | S_IXOTH);

    ret = bind (desc->fd,
                address,
                address_len);

    if (not_abstract)
      (void) umask (old_mask);
  }
  if (0 != ret)
    return GNUNET_SYSERR;

  desc->addr = GNUNET_malloc (address_len);
  GNUNET_memcpy (desc->addr, address, address_len);
  desc->addrlen = address_len;

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

  ret = close (desc->fd);

  const struct sockaddr_un *un = (const struct sockaddr_un *) desc->addr;

  /* Cleanup the UNIX domain socket and its parent directories in case of non
     abstract sockets */
  if ((AF_UNIX == desc->af) &&
      (NULL != desc->addr) &&
      ('\0' != un->sun_path[0]))
  {
    char *dirname = GNUNET_strndup (un->sun_path,
                                    sizeof(un->sun_path));

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
GNUNET_NETWORK_socket_box_native (int fd)
{
  struct GNUNET_NETWORK_Handle *ret;

  if (fcntl (fd, F_GETFD) < 0)
    return NULL;                /* invalid FD */
  ret = GNUNET_new (struct GNUNET_NETWORK_Handle);
  ret->fd = fd;
  ret->af = AF_UNSPEC;
  return ret;
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

  return ret == 0 ? GNUNET_OK : GNUNET_SYSERR;
}


/**
 * How much data is available to be read on this descriptor?
 *
 * @param desc socket
 * @returns #GNUNET_SYSERR if no data is available, or on error!
 */
ssize_t
GNUNET_NETWORK_socket_recvfrom_amount (const struct GNUNET_NETWORK_Handle *desc)
{
  int error;

  /* How much is there to be read? */
  int pending;

  error = ioctl (desc->fd,
                 FIONREAD,
                 &pending);
  if (0 == error)
    return (ssize_t) pending;
  return GNUNET_SYSERR;
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

#ifdef __linux__
  int value = 0;

  if (0 !=
      (ret =
         setsockopt (desc->fd,
                     SOL_SOCKET,
                     SO_SNDBUF,
                     &value,
                     sizeof(value))))
    LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING,
                  "setsockopt");
  if (0 !=
      (ret =
         setsockopt (desc->fd,
                     SOL_SOCKET,
                     SO_RCVBUF,
                     &value,
                     sizeof(value))))
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
  int nfds;

  for (nfds = src->nsds; nfds >= 0; nfds--)
    if (FD_ISSET (nfds, &src->sds))
      FD_SET (nfds, &dst->sds);
  dst->nsds = GNUNET_MAX (dst->nsds,
                          src->nsds);
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
}


/**
 * Return file descriptor for this network handle
 *
 * @param desc wrapper to process
 * @return POSIX file descriptor
 */
int
GNUNET_NETWORK_get_fd (const struct GNUNET_NETWORK_Handle *desc)
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
GNUNET_NETWORK_get_addr (const struct GNUNET_NETWORK_Handle *desc)
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
GNUNET_NETWORK_get_addrlen (const struct GNUNET_NETWORK_Handle *desc)
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
  if ((-1 == nfd) ||
      (NULL == to))
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
  int fd;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_DISK_internal_file_handle_ (h,
                                                    &fd,
                                                    sizeof(int)));
  FD_SET (fd,
          &fds->sds);
  fds->nsds = GNUNET_MAX (fd + 1,
                          fds->nsds);
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
  GNUNET_NETWORK_fdset_handle_set (fds, h);
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
  return FD_ISSET (h->fd,
                   &fds->sds);
}


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
  int nfds;

  nfds = GNUNET_MIN (fds1->nsds,
                     fds2->nsds);
  while (nfds > 0)
  {
    nfds--;
    if ((FD_ISSET (nfds,
                   &fds1->sds)) &&
        (FD_ISSET (nfds,
                   &fds2->sds)))
      return GNUNET_YES;
  }
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
  GNUNET_free (fds);
}


/**
 * Test if the given @a port is available.
 *
 * @param ipproto transport protocol to test (i.e. IPPROTO_TCP)
 * @param port port number to test
 * @return #GNUNET_OK if the port is available, #GNUNET_NO if not
 */
int
GNUNET_NETWORK_test_port_free (int ipproto,
                               uint16_t port)
{
  struct GNUNET_NETWORK_Handle *socket;
  int bind_status;
  int socktype;
  char open_port_str[6];
  struct addrinfo hint;
  struct addrinfo *ret;
  struct addrinfo *ai;

  GNUNET_snprintf (open_port_str,
                   sizeof(open_port_str),
                   "%u",
                   (unsigned int) port);
  socktype = (IPPROTO_TCP == ipproto) ? SOCK_STREAM : SOCK_DGRAM;
  ret = NULL;
  memset (&hint, 0, sizeof(hint));
  hint.ai_family = AF_UNSPEC; /* IPv4 and IPv6 */
  hint.ai_socktype = socktype;
  hint.ai_protocol = ipproto;
  hint.ai_addrlen = 0;
  hint.ai_addr = NULL;
  hint.ai_canonname = NULL;
  hint.ai_next = NULL;
  hint.ai_flags = AI_PASSIVE | AI_NUMERICSERV; /* Wild card address */
  GNUNET_assert (0 == getaddrinfo (NULL,
                                   open_port_str,
                                   &hint,
                                   &ret));
  bind_status = GNUNET_NO;
  for (ai = ret; NULL != ai; ai = ai->ai_next)
  {
    socket = GNUNET_NETWORK_socket_create (ai->ai_family,
                                           ai->ai_socktype,
                                           ai->ai_protocol);
    if (NULL == socket)
      continue;
    bind_status = GNUNET_NETWORK_socket_bind (socket,
                                              ai->ai_addr,
                                              ai->ai_addrlen);
    GNUNET_NETWORK_socket_close (socket);
    if (GNUNET_OK != bind_status)
      break;
  }
  freeaddrinfo (ret);
  return bind_status;
}


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
         _ (
           "Fatal internal logic error, process hangs in `%s' (abort with CTRL-C)!\n"),
         "select");
  }
  if (timeout.rel_value_us / GNUNET_TIME_UNIT_SECONDS.rel_value_us > (unsigned
                                                                      long long)
      LONG_MAX)
  {
    tv.tv_sec = LONG_MAX;
    tv.tv_usec = 999999L;
  }
  else
  {
    tv.tv_sec = (long) (timeout.rel_value_us
                        / GNUNET_TIME_UNIT_SECONDS.rel_value_us);
    tv.tv_usec =
      (timeout.rel_value_us
       - (tv.tv_sec * GNUNET_TIME_UNIT_SECONDS.rel_value_us));
  }
  return select (nfds,
                 (NULL != rfds) ? &rfds->sds : NULL,
                 (NULL != wfds) ? &wfds->sds : NULL,
                 (NULL != efds) ? &efds->sds : NULL,
                 (timeout.rel_value_us ==
                  GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us) ? NULL : &tv);
}


/* end of network.c */
