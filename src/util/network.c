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
 * @file util/network.c
 * @brief basic, low-level networking interface
 * @author Nils Durner
 */

#include "platform.h"
#include "gnunet_disk_lib.h"
#include "disk.h"
#include "gnunet_container_lib.h"

#define DEBUG_NETWORK GNUNET_NO

#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif


struct GNUNET_NETWORK_Handle
{
  int fd;
};


struct GNUNET_NETWORK_FDSet
{

  /**
   * Maximum number of any socket socket descriptor in the set
   */
  int nsds;

  /**
   * Bitset with the descriptors.
   */
  fd_set sds;

#ifdef WINDOWS
  /**
   * Linked list of handles 
   */
  struct GNUNET_CONTAINER_SList *handles;
#endif

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
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "ioctlsocket");
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;

#else
  /* not MINGW */
  int flags = fcntl (fd->fd, F_GETFL);
  if (flags == -1)

    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "fcntl");
      return GNUNET_SYSERR;
    }
  if (doBlock)
    flags &= ~O_NONBLOCK;

  else
    flags |= O_NONBLOCK;
  if (0 != fcntl (fd->fd, F_SETFL, flags))

    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "fcntl");
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
  if (i == (i | FD_CLOEXEC))
    return GNUNET_OK;
  return (fcntl (h->fd, F_SETFD, i | FD_CLOEXEC) == 0)
    ? GNUNET_OK : GNUNET_SYSERR;
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
  int value = 1;
  if (0 !=
      setsockopt (h->fd, SOL_SOCKET, SO_NOSIGPIPE, &value, sizeof (value)))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "setsockopt");
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
      setsockopt (h->fd, IPPROTO_TCP, TCP_NODELAY, &value, sizeof (value)))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "setsockopt");
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
                              struct sockaddr *address,
                              socklen_t * address_len)
{
  struct GNUNET_NETWORK_Handle *ret;
  ret = GNUNET_malloc (sizeof (struct GNUNET_NETWORK_Handle));
  ret->fd = accept (desc->fd, address, address_len);
  if (ret->fd == INVALID_SOCKET)
    {
#ifdef MINGW
      SetErrnoFromWinsockError (WSAGetLastError ());
#endif
      GNUNET_free (ret);
      return NULL;
    }
#ifndef MINGW
  if (ret->fd >= FD_SETSIZE)
    {
      GNUNET_break (0 == close (ret->fd));
      GNUNET_free (ret);
      errno = EMFILE;
      return NULL;
    }
#endif
  if (GNUNET_SYSERR == socket_set_blocking (ret, GNUNET_NO))

    {

      /* we might want to treat this one as fatal... */
      GNUNET_break (0);
      GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (ret));
      return NULL;
    }

#ifndef MINGW
  if (GNUNET_OK != socket_set_inheritable (ret))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                         "socket_set_inheritable");
#endif
#ifdef DARWIN
  socket_set_nosigpipe (ret);
#endif
  socket_set_nodelay (ret);
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

  ret = bind (desc->fd, address, address_len);
#ifdef MINGW
  if (SOCKET_ERROR == ret)
    SetErrnoFromWinsockError (WSAGetLastError ());
#endif
  return ret == 0 ? GNUNET_OK : GNUNET_SYSERR;
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
  int eno;

#ifdef MINGW
  ret = closesocket (desc->fd);
  SetErrnoFromWinsockError (WSAGetLastError ());
#else
  ret = close (desc->fd);
#endif
  eno = errno;
  GNUNET_free (desc);
  errno = eno;
  return (ret == 0) ? GNUNET_OK : GNUNET_SYSERR;
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

#endif /*  */
  ret = recv (desc->fd, buffer, length, flags);

#ifdef MINGW
  if (SOCKET_ERROR == ret)
    SetErrnoFromWinsockError (WSAGetLastError ());

#endif /*  */
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

#endif /*  */
#ifdef MSG_NOSIGNAL
  flags |= MSG_NOSIGNAL;

#endif /*  */
  ret = send (desc->fd, buffer, length, flags);

#ifdef MINGW
  if (SOCKET_ERROR == ret)
    SetErrnoFromWinsockError (WSAGetLastError ());

#endif /*  */
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
GNUNET_NETWORK_socket_setsockopt (struct GNUNET_NETWORK_Handle *fd,
                                  int level, int option_name,
                                  const void *option_value,
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
  if (INVALID_SOCKET == ret->fd)
    {
#ifdef MINGW
      SetErrnoFromWinsockError (WSAGetLastError ());
#endif
      GNUNET_free (ret);
      return NULL;
    }

#ifndef MINGW
  if (ret->fd >= FD_SETSIZE)
    {
      GNUNET_break (0 == close (ret->fd));
      GNUNET_free (ret);
      errno = EMFILE;
      return NULL;
    }

#endif
  if (GNUNET_SYSERR == socket_set_blocking (ret, GNUNET_NO))
    {
      /* we might want to treat this one as fatal... */
      GNUNET_break (0);
      GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (ret));
      return NULL;
    }

#ifndef MINGW
  if (GNUNET_OK != socket_set_inheritable (ret))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
                         "socket_set_inheritable");
#endif
#ifdef DARWIN
  socket_set_nosigpipe (ret);
#endif
  if (type == SOCK_STREAM)
    socket_set_nodelay (ret);
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
 * Add a file handle to the fd set
 * @param fds fd set
 * @param h the file handle to add
 */
void
GNUNET_NETWORK_fdset_handle_set (struct GNUNET_NETWORK_FDSet *fds,
                                 const struct GNUNET_DISK_FileHandle *h)
{

#ifdef MINGW
  HANDLE hw;
  GNUNET_DISK_internal_file_handle_ (h, &hw, sizeof (HANDLE));
  GNUNET_CONTAINER_slist_add (fds->handles, GNUNET_CONTAINER_SLIST_DISPOSITION_TRANSIENT, &hw, sizeof (HANDLE));

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
  return GNUNET_CONTAINER_slist_contains (fds->handles, &h->h,
                                          sizeof (HANDLE));
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
  int nfds;
  nfds = fds1->nsds;
  if (nfds < fds2->nsds)
    nfds = fds2->nsds;
  for (; nfds >= 0; nfds--)
    if (FD_ISSET (nfds, &fds1->sds) && FD_ISSET (nfds, &fds2->sds))
      return GNUNET_YES;
#ifdef MINGW
  {
      struct GNUNET_CONTAINER_SList_Iterator *it;

      for(it = GNUNET_CONTAINER_slist_begin (fds1->handles); GNUNET_CONTAINER_slist_end (it) != GNUNET_YES; GNUNET_CONTAINER_slist_next (it))
        {
          HANDLE *h;

          h = GNUNET_CONTAINER_slist_get (it, NULL);
          if (GNUNET_CONTAINER_slist_contains (fds2->handles, h, sizeof (HANDLE)))
            {
              GNUNET_CONTAINER_slist_iter_destroy (it);
              return GNUNET_YES;
            }
        }
      GNUNET_CONTAINER_slist_iter_destroy (it);
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
  int nfds;
#ifdef MINGW
  int handles;
#endif
  nfds = 0;
#ifdef MINGW
  handles = 0;
#endif
  if (NULL != rfds)
    {
      nfds = rfds->nsds;
#ifdef MINGW
      handles = GNUNET_CONTAINER_slist_count (rfds->handles);
#endif
    }
  if (NULL != wfds)
    {
      nfds = GNUNET_MAX (nfds, wfds->nsds);
#ifdef MINGW
      handles += GNUNET_CONTAINER_slist_count (wfds->handles);
#endif
    }
  if (NULL != efds)
    {
      nfds = GNUNET_MAX (nfds, efds->nsds);
#ifdef MINGW
      handles += GNUNET_CONTAINER_slist_count (efds->handles);
#endif
    }

  struct timeval tv;
  tv.tv_sec = timeout.value / GNUNET_TIME_UNIT_SECONDS.value;
  tv.tv_usec =
    1000 * (timeout.value - (tv.tv_sec * GNUNET_TIME_UNIT_SECONDS.value));
  if ((nfds == 0) && (timeout.value == GNUNET_TIME_UNIT_FOREVER_REL.value)
#ifdef MINGW
      && handles == 0
#endif
    )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _
                  ("Fatal internal logic error, process hangs in `%s' (abort with CTRL-C)!\n"),
                  "select");
      GNUNET_break (0);
    }
#ifndef MINGW
  return select (nfds + 1,
                 (rfds != NULL) ? &rfds->sds : NULL,
                 (wfds != NULL) ? &wfds->sds : NULL,
                 (efds != NULL) ? &efds->sds : NULL,
                 (timeout.value == GNUNET_TIME_UNIT_FOREVER_REL.value)
                 ? NULL : &tv);

#else
  DWORD limit;
  fd_set sock_read, sock_write, sock_except;
  fd_set aread, awrite, aexcept;
  struct GNUNET_CONTAINER_SList *handles_read, *handles_write, *handles_except;

  int i;
  struct timeval tvslice;
  int retcode;
  DWORD ms_total;

#define SAFE_FD_ISSET(fd, set)  (set != NULL && FD_ISSET(fd, set))

  /* calculate how long we need to wait in milliseconds */
  if (timeout.value == GNUNET_TIME_UNIT_FOREVER_REL.value)
    ms_total = INFINITE;

  else
    ms_total = timeout.value / GNUNET_TIME_UNIT_MILLISECONDS.value;

  /* select() may be used as a portable way to sleep */
  if (!(rfds || wfds || efds))

    {
      Sleep (ms_total);
      return 0;
    }

  handles_read = GNUNET_CONTAINER_slist_create ();
  handles_write = GNUNET_CONTAINER_slist_create ();
  handles_except = GNUNET_CONTAINER_slist_create ();

  if (rfds)
    sock_read = rfds->sds;
  else
    FD_ZERO (&sock_read);
  if (wfds)
    sock_write = wfds->sds;
  else
    FD_ZERO (&sock_write);
  if (efds)
    sock_except = efds->sds;
  else
    FD_ZERO (&sock_except);

  /* multiplex between winsock select() and waiting on the handles */
  FD_ZERO (&aread);
  FD_ZERO (&awrite);
  FD_ZERO (&aexcept);
  limit = GetTickCount () + ms_total;

  do
    {
      retcode = 0;
      if (nfds > 0)

        {

          /* overwrite the zero'd sets here; the select call
           * will clear those that are not active */
          FD_COPY (&sock_read, &aread);
          FD_COPY (&sock_write, &awrite);
          FD_COPY (&sock_except, &aexcept);
          tvslice.tv_sec = 0;
          tvslice.tv_usec = 100000;
          if ((retcode =
               select (nfds + 1, &aread, &awrite, &aexcept,
                       &tvslice)) == SOCKET_ERROR)

            {
              SetErrnoFromWinsockError (WSAGetLastError ());
              if (errno == ENOTSOCK)
                errno = EBADF;

#if DEBUG_NETWORK
              GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "select");

#endif
              goto select_loop_end;
            }
        }

      /* Poll read pipes */
      if (rfds)

        {
          struct GNUNET_CONTAINER_SList_Iterator *i;
          for (i = GNUNET_CONTAINER_slist_begin (rfds->handles);
               GNUNET_CONTAINER_slist_end (i) != GNUNET_YES;
               GNUNET_CONTAINER_slist_next (i))

            {
              HANDLE h;
              DWORD dwBytes;
              h = *(HANDLE *) GNUNET_CONTAINER_slist_get (i, NULL);
              if (!PeekNamedPipe (h, NULL, 0, NULL, &dwBytes, NULL))
                {
                  retcode = -1;
                  SetErrnoFromWinError (GetLastError ());

#if DEBUG_NETWORK
                  GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
                                       "PeekNamedPipe");

#endif
                  goto select_loop_end;
                }
              else if (dwBytes)

                {
                  GNUNET_CONTAINER_slist_add (handles_read,
                      GNUNET_CONTAINER_SLIST_DISPOSITION_TRANSIENT, &h,
                      sizeof (HANDLE));
                  retcode++;
                }
            }
          GNUNET_CONTAINER_slist_iter_destroy (i);
        }

      /* Poll for faulty pipes */
      if (efds)

        {
          struct GNUNET_CONTAINER_SList_Iterator *i;
          for (i = GNUNET_CONTAINER_slist_begin (efds->handles);
               GNUNET_CONTAINER_slist_end (i) != GNUNET_YES;
               GNUNET_CONTAINER_slist_next (i))

            {
              HANDLE h;
              DWORD dwBytes;
              h = *(HANDLE *) GNUNET_CONTAINER_slist_get (i, NULL);
              if (!PeekNamedPipe (h, NULL, 0, NULL, &dwBytes, NULL))

                {
                  GNUNET_CONTAINER_slist_add (handles_except,
                      GNUNET_CONTAINER_SLIST_DISPOSITION_TRANSIENT, &h,
                      sizeof (HANDLE));
                  retcode++;
                }
            }
          GNUNET_CONTAINER_slist_iter_destroy (i);
        }

      if (wfds)
        {
          GNUNET_CONTAINER_slist_append (handles_write, wfds->handles);
          retcode += GNUNET_CONTAINER_slist_count (wfds->handles);
        }

      /* Check for closed sockets */
      for (i = 0; i < nfds; i++)

        {
          if (SAFE_FD_ISSET (i, &sock_read))

            {
              struct sockaddr addr;
              int len;
              if (getpeername (i, &addr, &len) == SOCKET_ERROR)

                {
                  int err, len;
                  len = sizeof (err);
                  if (getsockopt
                      (i, SOL_SOCKET, SO_ERROR, (char *) &err, &len) == 0
                      && err == WSAENOTCONN)

                    {
                      if (!SAFE_FD_ISSET (i, &aread))

                        {
                          FD_SET (i, &aread);
                          retcode++;
                        }
                    }
                }
            }
        }
    select_loop_end:
      if (retcode == 0 && nfds == 0)
        Sleep (GNUNET_MIN (100, limit - GetTickCount ()));
    }
  while (retcode == 0 && (ms_total == INFINITE || GetTickCount () < limit));

  if (retcode != -1)

    {
      if (rfds)

        {
          GNUNET_NETWORK_fdset_zero (rfds);
          GNUNET_NETWORK_fdset_copy_native (rfds, &aread, retcode);
          GNUNET_CONTAINER_slist_clear (rfds->handles);
          GNUNET_CONTAINER_slist_append (rfds->handles, handles_read);

        }
      if (wfds)

        {
          GNUNET_NETWORK_fdset_zero (wfds);
          GNUNET_NETWORK_fdset_copy_native (wfds, &awrite, retcode);
          GNUNET_CONTAINER_slist_clear (wfds->handles);
          GNUNET_CONTAINER_slist_append (wfds->handles, handles_write);
        }
      if (efds)

        {
          GNUNET_NETWORK_fdset_zero (efds);
          GNUNET_NETWORK_fdset_copy_native (efds, &aexcept, retcode);
          GNUNET_CONTAINER_slist_clear (efds->handles);
          GNUNET_CONTAINER_slist_append (efds->handles, handles_except);
        }
    }

  GNUNET_CONTAINER_slist_destroy (handles_read);
  GNUNET_CONTAINER_slist_destroy (handles_write);
  GNUNET_CONTAINER_slist_destroy (handles_except);

  return retcode;
#endif
}


/* end of network.c */
