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
 * @file include/gnunet_network_lib.h
 * @brief basic low-level networking interface
 * @author Nils Durner
 */

#ifndef GNUNET_NETWORK_LIB_H
#define GNUNET_NETWORK_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_disk_lib.h"
#include "gnunet_time_lib.h"


/**
 * @brief handle to a socket
 */
struct GNUNET_NETWORK_Descriptor;

/**
 * @brief collection of IO descriptors
 */
struct GNUNET_NETWORK_FDSet;


struct GNUNET_NETWORK_Descriptor *GNUNET_NETWORK_socket_accept (const struct GNUNET_NETWORK_Descriptor *desc,
                      struct sockaddr *address,
                      socklen_t *address_len);

int
GNUNET_NETWORK_socket_set_inheritable (const struct GNUNET_NETWORK_Descriptor
                                       *desc);


int GNUNET_NETWORK_socket_bind (struct GNUNET_NETWORK_Descriptor *desc,
                    const struct sockaddr *address, socklen_t address_len);

int GNUNET_NETWORK_socket_close (struct GNUNET_NETWORK_Descriptor *desc);

int GNUNET_NETWORK_socket_connect (const struct GNUNET_NETWORK_Descriptor *desc,
                       const struct sockaddr *address, socklen_t address_len);

int GNUNET_NETWORK_socket_getsockopt(const struct GNUNET_NETWORK_Descriptor *desc, int level, int optname,
       void *optval, socklen_t *optlen);

int GNUNET_NETWORK_socket_listen (const struct GNUNET_NETWORK_Descriptor *desc, int backlog);

ssize_t GNUNET_NETWORK_socket_read (const struct GNUNET_NETWORK_Descriptor *desc, void *buf,
                        size_t nbyte);

ssize_t GNUNET_NETWORK_socket_recv (const struct GNUNET_NETWORK_Descriptor *desc, void *buffer,
                        size_t length, int flags);

int GNUNET_NETWORK_socket_select (struct GNUNET_NETWORK_FDSet *rfds,
    struct GNUNET_NETWORK_FDSet *wfds, struct GNUNET_NETWORK_FDSet *efds,
    struct GNUNET_TIME_Relative timeout);

/**
 * Set if a socket should use blocking or non-blocking IO.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int GNUNET_NETWORK_socket_set_blocking (struct GNUNET_NETWORK_Descriptor *fd, int doBlock);

ssize_t GNUNET_NETWORK_socket_send (const struct GNUNET_NETWORK_Descriptor *desc,
                        const void *buffer, size_t length, int flags);

ssize_t GNUNET_NETWORK_socket_sendto (const struct GNUNET_NETWORK_Descriptor *desc,
                          const void *message, size_t length, int flags,
                          const struct sockaddr *dest_addr,
                          socklen_t dest_len);

int GNUNET_NETWORK_socket_setsockopt(struct GNUNET_NETWORK_Descriptor *fd, int level, int option_name,
       const void *option_value, socklen_t option_len);

int GNUNET_NETWORK_socket_shutdown (struct GNUNET_NETWORK_Descriptor *desc, int how);

struct GNUNET_NETWORK_Descriptor *GNUNET_NETWORK_socket_socket (int domain, int type, int protocol);

ssize_t GNUNET_NETWORK_socket_write (const struct GNUNET_NETWORK_Descriptor *desc,
                         const void *buf, size_t nbyte);


void GNUNET_NETWORK_fdset_zero(struct GNUNET_NETWORK_FDSet *fds);

void GNUNET_NETWORK_fdset_set(struct GNUNET_NETWORK_FDSet *fds,
    const struct GNUNET_NETWORK_Descriptor *desc);

int GNUNET_NETWORK_fdset_isset(const struct GNUNET_NETWORK_FDSet *fds,
    const struct GNUNET_NETWORK_Descriptor *desc);

void GNUNET_NETWORK_fdset_add (struct GNUNET_NETWORK_FDSet *dst,
    const struct GNUNET_NETWORK_FDSet *src);

void GNUNET_NETWORK_fdset_copy(struct GNUNET_NETWORK_FDSet *to,
    const struct GNUNET_NETWORK_FDSet *from);

void GNUNET_NETWORK_fdset_copy_native (struct GNUNET_NETWORK_FDSet *to, const fd_set *from,
    int nfds);

void GNUNET_NETWORK_fdset_handle_set (struct GNUNET_NETWORK_FDSet *fds,
    const struct GNUNET_DISK_FileHandle *h);

int GNUNET_NETWORK_fdset_handle_isset (const struct GNUNET_NETWORK_FDSet *fds,
    const struct GNUNET_DISK_FileHandle *h);

int GNUNET_NETWORK_fdset_overlap (const struct GNUNET_NETWORK_FDSet *fds1, const struct GNUNET_NETWORK_FDSet *fds2);

struct GNUNET_NETWORK_FDSet *GNUNET_NETWORK_fdset_create (void);

void GNUNET_NETWORK_fdset_destroy (struct GNUNET_NETWORK_FDSet *fds);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif /* GNUNET_NETWORK_LIB_H */
