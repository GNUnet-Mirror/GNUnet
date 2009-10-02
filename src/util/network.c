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

#define DEBUG_SOCK GNUNET_NO

struct GNUNET_NETWORK_Handle
{
  int fd;
};

struct GNUNET_NETWORK_FDSet
{
  /* socket descriptors */
  int nsds;
  fd_set sds;
#ifdef WINDOWS
  /* handles */
  struct GNUNET_CONTAINER_Vector *handles;
#endif
};

#ifndef FD_COPY
#define FD_COPY(s, d) (memcpy ((d), (s), sizeof (fd_set)))
#endif

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
#ifdef MINGW
  if (INVALID_SOCKET == ret->fd)
    SetErrnoFromWinsockError (WSAGetLastError ());
#endif
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
 * Set if a socket should use blocking or non-blocking IO.
 * @param fd socket
 * @param doBlock blocking mode
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
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
  ret = closesocket (desc->fd);
  if (SOCKET_ERROR != ret)
    GNUNET_free (desc);
  else
    SetErrnoFromWinsockError (WSAGetLastError ());
#else
  /* FIXME: Nils, this is very strange code here... */
  ret = close (desc->fd);
  if (0 == ret)
    GNUNET_free (desc);
#endif

  return ret == 0 ? GNUNET_OK : GNUNET_SYSERR;
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
 * Read data from a connected socket
 * @param desc socket
 * @param buffer buffer
 * @param length length of buffer
 * @param flags type of message reception
 */
ssize_t
GNUNET_NETWORK_socket_recv (const struct GNUNET_NETWORK_Handle * desc,
                            void *buffer, size_t length, int flags)
{
  int ret;

  ret = recv (desc->fd, buffer, length, flags);
#ifdef MINGW
  if (SOCKET_ERROR == ret)
    SetErrnoFromWinsockError (WSAGetLastError ());
#endif

  return ret;
}

/**
 * Send data
 * @param desc socket
 * @param buffer data to send
 * @param length size of the buffer
 * @param flags type of message transmission
 * @return number of bytes sent, GNUNET_SYSERR on error
 */
ssize_t
GNUNET_NETWORK_socket_send (const struct GNUNET_NETWORK_Handle * desc,
                            const void *buffer, size_t length, int flags)
{
  int ret;

  ret = send (desc->fd, buffer, length, flags);
#ifdef MINGW
  if (SOCKET_ERROR == ret)
    SetErrnoFromWinsockError (WSAGetLastError ());
#endif

  return ret;
}

/**
 * Send data
 * @param desc socket
 * @param message data to send
 * @param length size of the data
 * @param flags type of message transmission
 * @param dest_addr destination address
 * @param dest_len length of address
 * @return number of bytes sent, GNUNET_SYSERR on error
 */
ssize_t
GNUNET_NETWORK_socket_sendto (const struct GNUNET_NETWORK_Handle * desc,
                              const void *message, size_t length, int flags,
                              const struct sockaddr * dest_addr,
                              socklen_t dest_len)
{
  int ret;

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
 * Create a new socket
 * @param domain domain of the socket
 * @param type socket type
 * @param protocol network protocol
 * @return new socket, NULL on error
 */
struct GNUNET_NETWORK_Handle *
GNUNET_NETWORK_socket_socket (int domain, int type, int protocol)
{
  struct GNUNET_NETWORK_Handle *ret;

  ret = GNUNET_malloc (sizeof (struct GNUNET_NETWORK_Handle));
  ret->fd = socket (domain, type, protocol);
#ifdef MINGW
  if (INVALID_SOCKET == ret->fd)
    SetErrnoFromWinsockError (WSAGetLastError ());
#endif

  if (ret->fd < 0)
    {
      GNUNET_free (ret);
      ret = NULL;
    }

  return ret;
}

/**
 * Shut down socket operations
 * @param desc socket
 * @param how type of shutdown
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 */
int
GNUNET_NETWORK_socket_shutdown (struct GNUNET_NETWORK_Handle *desc,
                                int how)
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
 * Make a non-inheritable to child processes
 * @param socket
 * @return GNUNET_OK on success, GNUNET_SYSERR otherwise
 * @warning Not implemented on Windows
 */
int
GNUNET_NETWORK_socket_set_inheritable (const struct GNUNET_NETWORK_Handle
                                       *desc)
{
#ifdef MINGW
  errno = ENOSYS;
  return GNUNET_SYSERR;
#else
  return fcntl (desc->fd, F_SETFD,
                fcntl (desc->fd,
                       F_GETFD) | FD_CLOEXEC) ==
    0 ? GNUNET_OK : GNUNET_SYSERR;
#endif
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
  if (fds->handles)
    GNUNET_CONTAINER_vector_destroy (fds->handles);
  fds->handles = GNUNET_CONTAINER_vector_create (2);
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
}


/**
 * Copy one fd set to another
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
  void *obj;

  if (to->handles)
    GNUNET_CONTAINER_vector_destroy (to->handles);
  to->handles = GNUNET_CONTAINER_vector_create (2);
  for (obj = GNUNET_CONTAINER_vector_get_first (from->handles); obj != NULL;
       obj = GNUNET_CONTAINER_vector_get_next (from->handles))
    {
      GNUNET_CONTAINER_vector_insert_last (to->handles, obj);
    }
#endif
}


/**
 * Copy a native fd set
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

  GNUNET_internal_disk_file_handle (h, &hw, sizeof (HANDLE));
  GNUNET_CONTAINER_vector_insert_last (fds->handles, h);
#else
  int fd;

  GNUNET_internal_disk_file_handle (h, &fd, sizeof (int));
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
  return GNUNET_CONTAINER_vector_index_of (fds->handles, h->h) !=
    (unsigned int) -1;
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
  fds->handles = NULL;
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
  GNUNET_CONTAINER_vector_destroy (fds->handles);
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

  nfds = 0;
  if (NULL != rfds)
    nfds = rfds->nsds;
  if (NULL != wfds)
    nfds = GNUNET_MAX (nfds, wfds->nsds);
  if (NULL != efds)
    nfds = GNUNET_MAX (nfds, efds->nsds);

#ifndef MINGW
  struct timeval tv;

  tv.tv_sec = timeout.value / GNUNET_TIME_UNIT_SECONDS.value;
  tv.tv_usec = 1000 * (timeout.value - (tv.tv_sec * GNUNET_TIME_UNIT_SECONDS.value));
  if ( (nfds == 0) &&
       (timeout.value == GNUNET_TIME_UNIT_FOREVER_REL.value) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Fatal internal logic error, process hangs in `%s' (abort with CTRL-C)!\n"),
		  "select");
      GNUNET_break (0);
    }
  return select (nfds + 1, 
		 (rfds != NULL) ? &rfds->sds : NULL, 
		 (wfds != NULL) ? &wfds->sds : NULL,
		 (efds != NULL) ? &efds->sds : NULL, 
		 (timeout.value == GNUNET_TIME_UNIT_FOREVER_REL.value) 
		 ? NULL 
		 : &tv);
#else
  DWORD limit;
  fd_set sock_read, sock_write, sock_except;
  fd_set aread, awrite, aexcept;
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

  if (rfds)
    sock_read = rfds->sds;
  else
    FD_ZERO(&sock_read);

  if (wfds)
    sock_write = wfds->sds;
  else
    FD_ZERO(&sock_write);

  if (efds)
    sock_except = efds->sds;
  else
    FD_ZERO(&sock_except);

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

#if DEBUG_SOCK
            GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "select");
#endif

              goto select_loop_end;
            }
        }

      /* Poll read pipes */
      if (rfds)
        for (i = GNUNET_CONTAINER_vector_size (rfds->handles) - 1; i >= 0; i--)
          {
            DWORD dwBytes;

            if (!PeekNamedPipe
                (GNUNET_CONTAINER_vector_get_at (rfds->handles, i), NULL, 0,
                 NULL, &dwBytes, NULL))
              {
                GNUNET_CONTAINER_vector_remove_at (rfds->handles, i);

                retcode = -1;
                SetErrnoFromWinError (GetLastError ());
#if DEBUG_SOCK
            GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "PeekNamedPipe");
#endif
               goto select_loop_end;
              }
            else if (dwBytes)
              {
                retcode++;
              }
            else
              GNUNET_CONTAINER_vector_remove_at (rfds->handles, i);
          }

      /* Poll for faulty pipes */
      if (efds)
        for (i = GNUNET_CONTAINER_vector_size (efds->handles); i >= 0; i--)
          {
            DWORD dwBytes;

            if (PeekNamedPipe
                (GNUNET_CONTAINER_vector_get_at (rfds->handles, i), NULL, 0,
                 NULL, &dwBytes, NULL))
              {
                GNUNET_CONTAINER_vector_remove_at (efds->handles, i);

                retcode++;
              }
          }

      /* FIXME */
      if (wfds)
        GNUNET_assert (GNUNET_CONTAINER_vector_size (wfds->handles) == 0);

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

    select_loop_end:;
    }
  while (retcode == 0 && (ms_total == INFINITE || GetTickCount () < limit));

  if (retcode != -1)
    {
      if (rfds)
        {
          GNUNET_NETWORK_fdset_zero (rfds);
          GNUNET_NETWORK_fdset_copy_native (rfds, &aread, retcode);
        }

      if (wfds)
        {
          GNUNET_NETWORK_fdset_zero (wfds);
          GNUNET_NETWORK_fdset_copy_native (wfds, &awrite, retcode);
        }

      if (efds)
        {
          GNUNET_NETWORK_fdset_zero (efds);
          GNUNET_NETWORK_fdset_copy_native (efds, &aexcept, retcode);
        }
    }

  return retcode;
#endif
}


/* end of network.c */
