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
 * @file util/sock.c
 * @brief basic, low-level networking interface
 * @author Nils Durner
 */

#include "platform.h"
#include "gnunet_disk_lib.h"
#include "disk.h"
#include "gnunet_container_lib.h"

#define DEBUG_SOCK GNUNET_NO

struct GNUNET_NETWORK_Descriptor
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

struct GNUNET_NETWORK_Descriptor *
GNUNET_NETWORK_socket_accept (const struct GNUNET_NETWORK_Descriptor *desc,
                              struct sockaddr *address,
                              socklen_t * address_len)
{
  struct GNUNET_NETWORK_Descriptor *ret;

  ret = GNUNET_malloc (sizeof (struct GNUNET_NETWORK_Descriptor));
  ret->fd = accept (desc->fd, address, address_len);
#ifdef MINGW
  if (INVALID_SOCKET == ret->fd)
    SetErrnoFromWinsockError (WSAGetLastError ());
#endif
  return ret;
}

int
GNUNET_NETWORK_socket_bind (struct GNUNET_NETWORK_Descriptor *desc,
                            const struct sockaddr *address,
                            socklen_t address_len)
{
  int ret;

  ret = bind (desc->fd, address, address_len);
#ifdef MINGW
  if (SOCKET_ERROR == ret)
    SetErrnoFromWinsockError (WSAGetLastError ());
#endif
  return ret;
}

/**
 * Set if a socket should use blocking or non-blocking IO.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_NETWORK_socket_set_blocking (struct GNUNET_NETWORK_Descriptor *fd,
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

int
GNUNET_NETWORK_socket_close (struct GNUNET_NETWORK_Descriptor *desc)
{
  int ret;
#ifdef MINGW
  ret = closesocket (desc->fd);
  if (SOCKET_ERROR != ret)
    GNUNET_free (desc);
  else
    SetErrnoFromWinsockError (WSAGetLastError ());
#else
  ret = close (desc->fd);
  if (-1 == ret)
    {
      GNUNET_free (desc);
    }
#endif

  return ret;
}

int
GNUNET_NETWORK_socket_connect (const struct GNUNET_NETWORK_Descriptor *desc,
                               const struct sockaddr *address,
                               socklen_t address_len)
{
  int ret;

  ret = connect (desc->fd, address, address_len);
#ifdef MINGW
  if (SOCKET_ERROR == ret)
    SetErrnoFromWinsockError (WSAGetLastError ());
#endif
  return ret;
}

int
GNUNET_NETWORK_socket_getsockopt (const struct GNUNET_NETWORK_Descriptor *desc,
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
  return ret;
}

int
GNUNET_NETWORK_socket_listen (const struct GNUNET_NETWORK_Descriptor *desc,
                              int backlog)
{
  int ret;

  ret = listen (desc->fd, backlog);
#ifdef MINGW
  if (SOCKET_ERROR == ret)
    SetErrnoFromWinsockError (WSAGetLastError ());
#endif

  return ret;
}

ssize_t
GNUNET_NETWORK_socket_recv (const struct GNUNET_NETWORK_Descriptor * desc,
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

ssize_t
GNUNET_NETWORK_socket_send (const struct GNUNET_NETWORK_Descriptor * desc,
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

ssize_t
GNUNET_NETWORK_socket_sendto (const struct GNUNET_NETWORK_Descriptor * desc,
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

int
GNUNET_NETWORK_socket_setsockopt (struct GNUNET_NETWORK_Descriptor *fd,
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

  return ret;
}

struct GNUNET_NETWORK_Descriptor *
GNUNET_NETWORK_socket_socket (int domain, int type, int protocol)
{
  struct GNUNET_NETWORK_Descriptor *ret;

  ret = GNUNET_malloc (sizeof (struct GNUNET_NETWORK_Descriptor));
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

int
GNUNET_NETWORK_socket_shutdown (struct GNUNET_NETWORK_Descriptor *desc,
                                int how)
{
  int ret;

  ret = shutdown (desc->fd, how);
#ifdef MINGW
  if (ret != 0)
    SetErrnoFromWinsockError (WSAGetLastError ());
#endif

  return ret;
}

int
GNUNET_NETWORK_socket_set_inheritable (const struct GNUNET_NETWORK_Descriptor
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

void
GNUNET_NETWORK_fdset_set (struct GNUNET_NETWORK_FDSet *fds,
                          const struct GNUNET_NETWORK_Descriptor *desc)
{
  FD_SET (desc->fd, &fds->sds);

  if (desc->fd + 1 > fds->nsds)
    fds->nsds = desc->fd + 1;
}

int
GNUNET_NETWORK_fdset_isset (const struct GNUNET_NETWORK_FDSet *fds,
                            const struct GNUNET_NETWORK_Descriptor *desc)
{
  return FD_ISSET (desc->fd, &fds->sds);
}

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

void
GNUNET_NETWORK_fdset_copy_native (struct GNUNET_NETWORK_FDSet *to,
                                  const fd_set * from, int nfds)
{
  FD_COPY (from, &to->sds);
  to->nsds = nfds;
}

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

void
GNUNET_NETWORK_fdset_destroy (struct GNUNET_NETWORK_FDSet *fds)
{
#ifdef MINGW
  GNUNET_CONTAINER_vector_destroy (fds->handles);
#endif
  GNUNET_free (fds);
}

int
GNUNET_NETWORK_socket_select (struct GNUNET_NETWORK_FDSet *rfds,
                              struct GNUNET_NETWORK_FDSet *wfds,
                              struct GNUNET_NETWORK_FDSet *efds,
                              const struct GNUNET_TIME_Relative timeout)
{
  int nfds;

  nfds = 0;

  if (rfds)
    nfds = rfds->nsds;
  if (wfds && wfds->nsds > nfds)
    nfds = wfds->nsds;
  if (efds && efds->nsds > nfds)
    nfds = efds->nsds;

#ifndef MINGW
  struct timeval tv;

  tv.tv_sec = timeout.value / GNUNET_TIME_UNIT_SECONDS.value;
  tv.tv_usec = (timeout.value - (tv.tv_sec * GNUNET_TIME_UNIT_SECONDS.value))
    / GNUNET_TIME_UNIT_MILLISECONDS.value;

  return select (nfds + 1, rfds ? &rfds->sds : NULL, wfds ? &wfds->sds : NULL,
      efds ? &efds->sds : NULL, timeout.value
          == GNUNET_TIME_UNIT_FOREVER_REL.value ? NULL : &tv);
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

  /*
  if (rfds)
    FD_COPY (&rfds->sds, &sock_read);
  else
    FD_ZERO(&sock_read);

  if (wfds)
    FD_COPY (&wfds->sds, &sock_write);
  else
    FD_ZERO(&sock_write);

  if (efds)
    FD_COPY (&efds->sds, &sock_except);
  else
    FD_ZERO(&sock_except);
*/

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

/* end of network_socket.c */
