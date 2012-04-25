/*
     This file is part of GNUnet.
     (C) 2011, 2012 Christian Grothoff (and other contributing authors)

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

#ifndef GNUNET_STREAM_LIB_H
#define GNUNET_STREAM_LIB_H

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
     * Other side has shutdown the socket for this type of operation
     * (reading/writing)
     */
    GNUNET_STREAM_SHUTDOWN = 2,

    /**
     * A serious error occured while operating on this stream
     */
    GNUNET_STREAM_SYSERR = 3,
    
    /**
     * An error resulted in an unusable stream
     */
    GNUNET_STREAM_BROKEN
  };

/**
 * Opaque handler for stream
 */
struct GNUNET_STREAM_Socket;

/**
 * Functions of this type will be called when a stream is established
 *
 * @param cls the closure from GNUNET_STREAM_open
 * @param socket socket to use to communicate with the other side (read/write)
 */
typedef void (*GNUNET_STREAM_OpenCallback) (void *cls,
					    struct GNUNET_STREAM_Socket *socket);


/**
 * Options for the stream.
 */
enum GNUNET_STREAM_Option
  {
    /**
     * End of the option list.
     */
    GNUNET_STREAM_OPTION_END = 0,

    /**
     * Option to set the initial retransmission timeout (when do we retransmit
     * a packet that did not yield an acknowledgement for the first time?).  
     * Repeated retransmissions will then use an exponential back-off.
     * Takes a 'struct GNUNET_TIME_Relative' as the only argument.  A value
     * of '0' means to use the round-trip time (plus a tiny grace period);
     * this is also the default.
     */
    GNUNET_STREAM_OPTION_INITIAL_RETRANSMIT_TIMEOUT
  };


/**
 * Tries to open a stream to the target peer
 *
 * @param cfg configuration to use
 * @param target the target peer to which the stream has to be opened
 * @param app_port the application port number which uniquely identifies this
 *            stream
 * @param open_cb this function will be called after stream has be established 
 * @param open_cb_cls the closure for open_cb
 * @param ... options to the stream, terminated by GNUNET_STREAM_OPTION_END
 * @return if successful it returns the stream socket; NULL if stream cannot be
 *         opened 
 */
struct GNUNET_STREAM_Socket *
GNUNET_STREAM_open (const struct GNUNET_CONFIGURATION_Handle *cfg,
                    const struct GNUNET_PeerIdentity *target,
                    GNUNET_MESH_ApplicationType app_port,
                    GNUNET_STREAM_OpenCallback open_cb,
		    void *open_cb_cls,
		    ...);


/**
 * Handle for shutdown
 */
struct GNUNET_STREAM_ShutdownHandle;


/**
 * Completion callback for shutdown
 *
 * @param cls the closure from GNUNET_STREAM_shutdown call
 * @param operation the operation that was shutdown (SHUT_RD, SHUT_WR,
 *          SHUT_RDWR) 
 */
typedef void (*GNUNET_STREAM_ShutdownCompletion) (void *cls,
                                                  int operation);


/**
 * Shutdown the stream for reading or writing (similar to man 2 shutdown).
 *
 * @param socket the stream socket
 * @param operation SHUT_RD, SHUT_WR or SHUT_RDWR
 * @param completion_cb the callback that will be called upon successful
 *          shutdown of given operation
 * @param completion_cls the closure for the completion callback
 * @return the shutdown handle; NULL in case of any error
 */
struct GNUNET_STREAM_ShutdownHandle *
GNUNET_STREAM_shutdown (struct GNUNET_STREAM_Socket *socket,
			int operation,
                        GNUNET_STREAM_ShutdownCompletion completion_cb,
                        void *completion_cls);


/**
 * Cancels a pending shutdown
 *
 * @param handle the shutdown handle returned from GNUNET_STREAM_shutdown
 */
void
GNUNET_STREAM_shutdown_cancel (struct GNUNET_STREAM_ShutdownHandle *handle);


/**
 * Closes the stream and frees the associated state. The stream should be
 * shutdown before closing.
 *
 * @param socket the stream socket
 */
void
GNUNET_STREAM_close (struct GNUNET_STREAM_Socket *socket);


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
                                             struct GNUNET_STREAM_Socket *socket,
                                             const struct 
                                             GNUNET_PeerIdentity *initiator);


/**
 * A socket for listening.
 */
struct GNUNET_STREAM_ListenSocket;

/**
 * Listens for stream connections for a specific application ports
 *
 * @param cfg the configuration to use
 * @param app_port the application port for which new streams will be accepted
 * @param listen_cb this function will be called when a peer tries to establish
 *            a stream with us
 * @param listen_cb_cls closure for listen_cb
 * @return listen socket, NULL for any error
 */
struct GNUNET_STREAM_ListenSocket *
GNUNET_STREAM_listen (const struct GNUNET_CONFIGURATION_Handle *cfg,
                      GNUNET_MESH_ApplicationType app_port,
                      GNUNET_STREAM_ListenCallback listen_cb,
                      void *listen_cb_cls);


/**
 * Closes the listen socket
 *
 * @param lsocket the listen socket
 */
void
GNUNET_STREAM_listen_close (struct GNUNET_STREAM_ListenSocket *lsocket);


/**
 * Functions of this signature are called whenever writing operations
 * on a stream are executed
 *
 * @param cls the closure from GNUNET_STREAM_write
 * @param status the status of the stream at the time this function is called
 * @param size the number of bytes written
 */
typedef void (*GNUNET_STREAM_CompletionContinuation) (void *cls,
						      enum GNUNET_STREAM_Status
						      status,
						      size_t size);


/**
 * Handle to cancel IO write operations.
 */
struct GNUNET_STREAM_IOWriteHandle;


/**
 * Handle to cancel IO read operations.
 */
struct GNUNET_STREAM_IOReadHandle;

/**
 * Tries to write the given data to the stream. The maximum size of data that
 * can be written as part of a write operation is (64 * (64000 - sizeof (struct
 * GNUNET_STREAM_DataMessage))). If size is greater than this it is not an API
 * violation, however only the said number of maximum bytes will be written.
 *
 * @param socket the socket representing a stream
 * @param data the data buffer from where the data is written into the stream
 * @param size the number of bytes to be written from the data buffer
 * @param timeout the timeout period
 * @param write_cont the function to call upon writing some bytes into the
 *          stream 
 * @param write_cont_cls the closure
 *
 * @return handle to cancel the operation; if a previous write is pending or
 *           the stream has been shutdown for this operation then write_cont is
 *           immediately called and NULL is returned.
 */
struct GNUNET_STREAM_IOWriteHandle *
GNUNET_STREAM_write (struct GNUNET_STREAM_Socket *socket,
                     const void *data,
                     size_t size,
                     struct GNUNET_TIME_Relative timeout,
                     GNUNET_STREAM_CompletionContinuation write_cont,
                     void *write_cont_cls);


/**
 * Functions of this signature are called whenever data is available from the
 * stream.
 *
 * @param cls the closure from GNUNET_STREAM_read
 * @param status the status of the stream at the time this function is called
 * @param data traffic from the other side
 * @param size the number of bytes available in data read; will be 0 on timeout 
 * @return number of bytes of processed from 'data' (any data remaining should be
 *         given to the next time the read processor is called).
 */
typedef size_t (*GNUNET_STREAM_DataProcessor) (void *cls,
                                               enum GNUNET_STREAM_Status status,
                                               const void *data,
                                               size_t size);


/**
 * Tries to read data from the stream.
 *
 * @param socket the socket representing a stream
 * @param timeout the timeout period
 * @param proc function to call with data (once only)
 * @param proc_cls the closure for proc
 *
 * @return handle to cancel the operation; if the stream has been shutdown for
 *           this type of opeartion then the DataProcessor is immediately
 *           called with GNUNET_STREAM_SHUTDOWN as status and NULL if returned
 */
struct GNUNET_STREAM_IOReadHandle *
GNUNET_STREAM_read (struct GNUNET_STREAM_Socket *socket,
                    struct GNUNET_TIME_Relative timeout,
		    GNUNET_STREAM_DataProcessor proc,
		    void *proc_cls);


/**
 * Cancels pending write operation. Also cancels packet retransmissions which
 * may have resulted otherwise.
 *
 * CAUTION: Normally a write operation is considered successful if the data
 * given to it is sent and acknowledged by the receiver. As data is divided
 * into packets, it is possible that not all packets are received by the
 * receiver. Any missing packets are then retransmitted till the receiver
 * acknowledges all packets or until a timeout . During this scenario if the
 * write operation is cancelled all such retransmissions are also
 * cancelled. This may leave the receiver's receive buffer incompletely filled
 * as some missing packets are never retransmitted. So this operation should be
 * used before shutting down transmission from our side or before closing the
 * socket.
 *
 * @param ioh handle to operation to cancel
 */
void
GNUNET_STREAM_io_write_cancel (struct GNUNET_STREAM_IOWriteHandle *iowh);


/**
 * Cancel pending read operation.
 *
 * @param ioh handle to operation to cancel
 */
void
GNUNET_STREAM_io_read_cancel (struct GNUNET_STREAM_IOReadHandle *iorh);


#if 0
{
#endif
#ifdef __cplusplus
}
#endif

#endif  /* STREAM_PROTOCOL_H */
