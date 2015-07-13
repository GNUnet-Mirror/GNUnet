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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
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


/**
 * @brief handle to a socket
 */
struct GNUNET_NETWORK_Handle;


/**
 * @brief collection of IO descriptors
 */
struct GNUNET_NETWORK_FDSet
{

  /**
   * Maximum number of any socket socket descriptor in the set (plus one)
   */
  int nsds;

  /**
   * Bitset with the descriptors.
   */
  fd_set sds;

#ifdef WINDOWS
  /**
   * Array of file handles (from pipes) that are also in
   * the FDSet.  Needed as those cannot go into @e sds
   * on W32.
   */
  const struct GNUNET_DISK_FileHandle **handles;

  /**
   * Size of the @e handles array
   */
  unsigned int handles_size;

  /**
   * Number of @e handles slots in use. Always
   * smaller than @e handles_size.
   */
  unsigned int handles_pos;

#endif

};

#include "gnunet_disk_lib.h"
#include "gnunet_time_lib.h"

/**
 * Test if the given protocol family is supported by this system.
 *
 * @param pf protocol family to test (PF_INET, PF_INET6, PF_UNIX)
 * @return #GNUNET_OK if the PF is supported
 */
int
GNUNET_NETWORK_test_pf (int pf);


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
GNUNET_NETWORK_shorten_unixpath (char *unixpath);


#ifndef WINDOWS
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
GNUNET_NETWORK_unix_precheck (const struct sockaddr_un *un);
#endif


/**
 * Accept a new connection on a socket.  Configure it for non-blocking
 * IO and mark it as non-inheritable to child processes (set the
 * close-on-exec flag).
 *
 * @param desc bound socket
 * @param address address of the connecting peer, may be NULL
 * @param address_len length of address
 * @return client socket
 */
struct GNUNET_NETWORK_Handle *
GNUNET_NETWORK_socket_accept (const struct GNUNET_NETWORK_Handle *desc,
                              struct sockaddr *address,
                              socklen_t *address_len);


/**
 * Box a native socket (and check that it is a socket).
 *
 * @param fd socket to box
 * @return NULL on error (including not supported on target platform)
 */
struct GNUNET_NETWORK_Handle *
GNUNET_NETWORK_socket_box_native (SOCKTYPE fd);


/**
 * Set if a socket should use blocking or non-blocking IO.
 *
 * @param fd socket
 * @param doBlock blocking mode
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_NETWORK_socket_set_blocking (struct GNUNET_NETWORK_Handle *fd,
				    int doBlock);


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
                            socklen_t address_len);

/**
 * Close a socket.
 *
 * @param desc socket to close
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
int
GNUNET_NETWORK_socket_close (struct GNUNET_NETWORK_Handle *desc);


/**
 * Only free memory of a socket, keep the file descriptor untouched.
 *
 * @param desc socket
 */
void
GNUNET_NETWORK_socket_free_memory_only_ (struct GNUNET_NETWORK_Handle *desc);


/**
 * Connect a socket to some remote address.
 *
 * @param desc socket to connect
 * @param address peer address
 * @param address_len of @a address
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
int
GNUNET_NETWORK_socket_connect (const struct GNUNET_NETWORK_Handle *desc,
                               const struct sockaddr *address,
                               socklen_t address_len);


/**
 * Get socket options
 *
 * @param desc socket to inspect
 * @param level protocol level of the option
 * @param optname identifier of the option
 * @param optval options
 * @param optlen length of optval
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
int
GNUNET_NETWORK_socket_getsockopt (const struct GNUNET_NETWORK_Handle *desc,
                                  int level,
                                  int optname,
                                  void *optval,
                                  socklen_t *optlen);


/**
 * Listen on a socket
 *
 * @param desc socket to start listening on
 * @param backlog length of the listen queue
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
int
GNUNET_NETWORK_socket_listen (const struct GNUNET_NETWORK_Handle *desc,
                              int backlog);


/**
 * How much data is available to be read on this descriptor?
 *
 * @param desc socket
 * @returns #GNUNET_NO if no data is available, or on error!
 */
ssize_t
GNUNET_NETWORK_socket_recvfrom_amount (const struct GNUNET_NETWORK_Handle *desc);


/**
 * Read data from a socket (always non-blocking).
 *
 * @param desc socket
 * @param buffer buffer
 * @param length length of buffer
 * @param src_addr either the source to recv from, or all zeroes
 *        to be filled in by recvfrom
 * @param addrlen length of the addr
 */
ssize_t
GNUNET_NETWORK_socket_recvfrom (const struct GNUNET_NETWORK_Handle *desc,
                                void *buffer,
                                size_t length,
                                struct sockaddr *src_addr,
                                socklen_t *addrlen);


/**
 * Read data from a connected socket (always non-blocking).
 *
 * @param desc socket
 * @param buffer buffer
 * @param length length of buffer
 * @return number of bytes read
 */
ssize_t
GNUNET_NETWORK_socket_recv (const struct GNUNET_NETWORK_Handle *desc,
                            void *buffer,
                            size_t length);


/**
 * Check if sockets meet certain conditions.
 *
 * @param rfds set of sockets to be checked for readability
 * @param wfds set of sockets to be checked for writability
 * @param efds set of sockets to be checked for exceptions
 * @param timeout relative value when to return
 * @return number of selected sockets, #GNUNET_SYSERR on error
 */
int
GNUNET_NETWORK_socket_select (struct GNUNET_NETWORK_FDSet *rfds,
                              struct GNUNET_NETWORK_FDSet *wfds,
                              struct GNUNET_NETWORK_FDSet *efds,
                              struct GNUNET_TIME_Relative timeout);


/**
 * Send data (always non-blocking).
 *
 * @param desc socket
 * @param buffer data to send
 * @param length size of the buffer
 * @return number of bytes sent, #GNUNET_SYSERR on error
 */
ssize_t
GNUNET_NETWORK_socket_send (const struct GNUNET_NETWORK_Handle *desc,
                            const void *buffer,
                            size_t length);


/**
 * Send data to a particular destination (always non-blocking).
 * This function only works for UDP sockets.
 *
 * @param desc socket
 * @param message data to send
 * @param length size of the data in @a message
 * @param dest_addr destination address
 * @param dest_len length of @a dest_addr
 * @return number of bytes sent, #GNUNET_SYSERR on error
 */
ssize_t
GNUNET_NETWORK_socket_sendto (const struct GNUNET_NETWORK_Handle *desc,
                              const void *message,
                              size_t length,
                              const struct sockaddr *dest_addr,
                              socklen_t dest_len);


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
                                  socklen_t option_len);


/**
 * Shut down socket operations
 *
 * @param desc socket
 * @param how type of shutdown
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
int
GNUNET_NETWORK_socket_shutdown (struct GNUNET_NETWORK_Handle *desc,
                                int how);


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
GNUNET_NETWORK_socket_disable_corking (struct GNUNET_NETWORK_Handle *desc);


/**
 * Create a new socket.   Configure it for non-blocking IO and
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
                              int protocol);


/**
 * Reset FD set (clears all file descriptors).
 *
 * @param fds fd set to clear
 */
void
GNUNET_NETWORK_fdset_zero (struct GNUNET_NETWORK_FDSet *fds);


/**
 * Add a socket to the FD set
 *
 * @param fds fd set
 * @param desc socket to add
 */
void
GNUNET_NETWORK_fdset_set (struct GNUNET_NETWORK_FDSet *fds,
                          const struct GNUNET_NETWORK_Handle *desc);


#if WINDOWS
/**
 * Add a W32 file handle to the fd set
 *
 * @param fds fd set
 * @param h the file handle to add
 */
void
GNUNET_NETWORK_fdset_handle_set_native_w32_handle (struct GNUNET_NETWORK_FDSet *fds,
                                                   HANDLE h);
#endif


/**
 * Check whether a socket is part of the fd set
 *
 * @param fds fd set
 * @param desc socket
 * @return #GNUNET_YES if the socket is in the set
 */
int
GNUNET_NETWORK_fdset_isset (const struct GNUNET_NETWORK_FDSet *fds,
                            const struct GNUNET_NETWORK_Handle *desc);


/**
 * Add one fd set to another (computes the union).
 *
 * @param dst the fd set to add to
 * @param src the fd set to add from
 */
void
GNUNET_NETWORK_fdset_add (struct GNUNET_NETWORK_FDSet *dst,
                          const struct GNUNET_NETWORK_FDSet *src);


/**
 * Copy one fd set to another
 *
 * @param to destination
 * @param from source
 */
void
GNUNET_NETWORK_fdset_copy (struct GNUNET_NETWORK_FDSet *to,
                           const struct GNUNET_NETWORK_FDSet *from);


/**
 * Return file descriptor for this network handle
 *
 * @param desc wrapper to process
 * @return POSIX file descriptor
 */
int
GNUNET_NETWORK_get_fd (struct GNUNET_NETWORK_Handle *desc);


/**
 * Return the sockaddr for this network handle
 *
 * @param desc wrapper to process
 * @return POSIX file descriptor
 */
struct sockaddr*
GNUNET_NETWORK_get_addr (struct GNUNET_NETWORK_Handle *desc);


/**
 * Return sockaddr length for this network handle
 *
 * @param desc wrapper to process
 * @return socklen_t for sockaddr
 */
socklen_t
GNUNET_NETWORK_get_addrlen (struct GNUNET_NETWORK_Handle *desc);


/**
 * Copy a native fd set into the GNUnet representation.
 *
 * @param to destination
 * @param from native source set
 * @param nfds the biggest socket number in from + 1
 */
void
GNUNET_NETWORK_fdset_copy_native (struct GNUNET_NETWORK_FDSet *to,
                                  const fd_set *from,
                                  int nfds);


/**
 * Set a native fd in a set
 *
 * @param to destination
 * @param nfd native FD to set
 */
void
GNUNET_NETWORK_fdset_set_native (struct GNUNET_NETWORK_FDSet *to,
                                 int nfd);


/**
 * Test native fd in a set
 *
 * @param to set to test, NULL for empty set
 * @param nfd native FD to test, -1 for none
 * @return #GNUNET_YES if to contains nfd
 */
int
GNUNET_NETWORK_fdset_test_native (const struct GNUNET_NETWORK_FDSet *to,
                                  int nfd);


/**
 * Add a file handle to the fd set
 *
 * @param fds fd set
 * @param h the file handle to add
 */
void
GNUNET_NETWORK_fdset_handle_set (struct GNUNET_NETWORK_FDSet *fds,
                                 const struct GNUNET_DISK_FileHandle *h);


/**
 * Add a file handle to the fd set
 * On W32: ensure that the handle is first in the array.
 *
 * @param fds fd set
 * @param h the file handle to add
 */
void
GNUNET_NETWORK_fdset_handle_set_first (struct GNUNET_NETWORK_FDSet *fds,
                                       const struct GNUNET_DISK_FileHandle *h);


/**
 * Check if a file handle is part of an fd set
 *
 * @param fds fd set
 * @param h file handle
 * @return #GNUNET_YES if the file handle is part of the set
 */
int
GNUNET_NETWORK_fdset_handle_isset (const struct GNUNET_NETWORK_FDSet *fds,
                                   const struct GNUNET_DISK_FileHandle *h);


/**
 * Checks if two fd sets overlap
 *
 * @param fds1 first fd set
 * @param fds2 second fd set
 * @return #GNUNET_YES if they do overlap, #GNUNET_NO otherwise
 */
int
GNUNET_NETWORK_fdset_overlap (const struct GNUNET_NETWORK_FDSet *fds1,
                              const struct GNUNET_NETWORK_FDSet *fds2);


/**
 * Creates an fd set
 *
 * @return a new fd set
 */
struct GNUNET_NETWORK_FDSet *
GNUNET_NETWORK_fdset_create (void);


/**
 * Releases the associated memory of an fd set
 *
 * @param fds fd set
 */
void
GNUNET_NETWORK_fdset_destroy (struct GNUNET_NETWORK_FDSet *fds);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif /* GNUNET_NETWORK_LIB_H */
