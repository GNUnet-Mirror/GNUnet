/*
     This file is part of GNUnet.
     (C) 2011, Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_stream_lib.h
 * @brief stream handling using mesh API
 * @author Sree Harsha Totakura
 */

#ifndef GNUNET_STREAM_LIB_H_
#define GNUNET_STREAM_LIB_H_

#ifdef __cplusplus
extern "C" 
{
#if 0
}
#endif
#endif

#include "gnunet_util_lib.h"
#include "gnunet_mesh_service.h"

/**
 * Stream status 
 */
enum GNUNET_STREAM_Status
  {
    /**
     * All previous read/write operations are successfully done
     */
    GNUNET_STREAM_OK = 0,

    /**
     * A timeout occured while reading/writing the stream
     */
    GNUNET_STREAM_TIMEOUT = 1,

    /**
     * A serious error occured while operating of this stream
     */
    GNUNET_STREAM_SYSERR = 2
  };

/**
 * Opaque handler for stream
 */
struct GNUNET_STREAM_socket;

/**
 * Functions of this type will be called when a stream is established
 *
 * @param cls the closure from GNUNET_STREAM_open
 */
typedef void (*GNUNET_STREAM_OpenCallback) (void *cls);

/**
 * Tries to open a stream to the target peer
 *
 * @param cls the closure
 * @param target the target peer to which the stream has to be opened
 * @param app_port the application port number which uniquely identifies this
 *            stream
 * @param open_cb this function will be called after stream has be established 
 * @return if successful it returns the stream socket; NULL if stream cannot be
 *         opened 
 */
struct GNUNET_STREAM_socket *
GNUNET_STREAM_open (void *cls,
                    const struct GNUNET_PeerIdentity *target,
                    GNUNET_MESH_ApplicationType app_port,
                    GNUNET_STREAM_OpenCallback open_cb);

/**
 * Functions of this type are called upon new stream connection from other peers
 *
 * @param cls the closure from GNUNET_STREAM_listen
 * @param socket the socket representing the stream
 * @param initiator the identity of the peer who wants to establish a stream
 *            with us
 * @return GNUNET_OK to keep the socket open, GNUNET_SYSERR to close the
 *             stream (the socket will be invalid after the call)
 */
typedef int (*GNUNET_STREAM_ListenCallback) (void *cls,
                                             struct GNUNET_STREAM_socket *socket,
                                             const struct 
                                             GNUNET_PeerIdentity *initiator);

/**
 * Listens for stream connections for a specific application ports
 *
 * @param app_port the application port for which new streams will be accepted
 * @param listen_cb this function will be called when a peer tries to establish
 *            a stream with us
 * @return GNUNET_OK if we are listening, GNUNET_SYSERR for any error
 */
int
GNUNET_STREAM_listen (GNUNET_MESH_ApplicationType app_port,
                      GNUNET_STREAM_ListenCallback listen_cb,
                      void *cls);

/**
 * Functions of this signature are called whenever reading/writing operations
 * on a stream are executed
 *
 * @param cls the closure from GNUNET_STREAM_write/read
 * @param status the status of the stream at the time this function is called
 * @param size the number of bytes read or written
 */
typedef void (*GNUNET_STREAM_CompletionCallback) (void *cls,
                                                  enum GNUNET_STREAM_Status
                                                  status,
                                                  size_t size);

/**
 * Tries to write the given data to the stream
 *
 * @param socket the socket representing a stream
 * @param data the data buffer from where the data is written into the stream
 * @param size the number of bytes to be written from the data buffer
 * @param write_cb the function to call upon writing some bytes into the stream
 * @param timeout the timeout period
 * @param cls the closure
 */
void
GNUNET_STREAM_write (const struct GNUNET_STREAM_socket *socket,
                     void *data,
                     size_t size,
                     GNUNET_STREAM_CompletionCallback write_cb,
                     struct GNUNET_TIME_Relative timeout,
                     void *cls);

/**
 * Tries to read data from the stream
 *
 * @param socket the socket representing a stream
 * @param buffer the buffer into which the read data is stored
 * @param size the number of bytes that are to be read
 * @param read_cb the completion callback function which is called after
 *            attempting to read size number of bytes from the stream
 * @param timeout the timeout period
 * @param cls the closure
 */
void
GNUNET_STREAM_read (const struct GNUNET_STREAM_socket *socket,
                    void *buffer,
                    size_t size,
                    GNUNET_STREAM_CompletionCallback read_cb,
                    struct GNUNET_TIME_Relative timeout,
                    void *cls);
/**
 * Closes the stream
 *
 * @param socket the stream socket
 */
void
GNUNET_STREAM_close (struct GNUNET_STREAM_socket *socket);

#if 0
{
#endif
#ifdef __cplusplus
}
#endif

#endif
