/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_server_lib.h
 * @brief library for building GNUnet network servers
 *
 * @author Christian Grothoff
 */

#ifndef GNUNET_SERVER_LIB_H
#define GNUNET_SERVER_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_common.h"
#include "gnunet_connection_lib.h"


/**
 * Largest supported message.
 */
#define GNUNET_SERVER_MAX_MESSAGE_SIZE 65536

/**
 * Smallest supported message.
 */
#define GNUNET_SERVER_MIN_BUFFER_SIZE sizeof (struct GNUNET_MessageHeader)

/**
 * @brief handle for a server
 */
struct GNUNET_SERVER_Handle;

/**
 * @brief opaque handle for a client of the server
 */
struct GNUNET_SERVER_Client;

/**
 * @brief opaque handle server returns for aborting transmission to a client.
 */
struct GNUNET_SERVER_TransmitHandle;


/**
 * Functions with this signature are called whenever a message is
 * received.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
typedef void (*GNUNET_SERVER_MessageCallback) (void *cls,
                                               struct GNUNET_SERVER_Client *
                                               client,
                                               const struct GNUNET_MessageHeader
                                               * message);



/**
 * Message handler.  Each struct specifies how to handle on particular
 * type of message received.
 */
struct GNUNET_SERVER_MessageHandler
{
  /**
   * Function to call for messages of "type".
   */
  GNUNET_SERVER_MessageCallback callback;

  /**
   * Closure argument for "callback".
   */
  void *callback_cls;

  /**
   * Type of the message this handler covers.
   */
  uint16_t type;

  /**
   * Expected size of messages of this type.  Use 0 for
   * variable-size.  If non-zero, messages of the given
   * type will be discarded (and the connection closed)
   * if they do not have the right size.
   */
  uint16_t expected_size;

};


/**
 * Create a new server.
 *
 * @param access function for access control
 * @param access_cls closure for access
 * @param lsocks NULL-terminated array of listen sockets
 * @param idle_timeout after how long should we timeout idle connections?
 * @param require_found if YES, connections sending messages of unknown type
 *        will be closed
 * @return handle for the new server, NULL on error
 *         (typically, "port" already in use)
 */
struct GNUNET_SERVER_Handle *
GNUNET_SERVER_create_with_sockets (GNUNET_CONNECTION_AccessCheck access,
                                   void *access_cls,
                                   struct GNUNET_NETWORK_Handle **lsocks,
                                   struct GNUNET_TIME_Relative idle_timeout,
                                   int require_found);

/**
 * Create a new server.
 *
 * @param access function for access control
 * @param access_cls closure for access
 * @param serverAddr address toes listen on (including port), NULL terminated array
 * @param socklen lengths of respective serverAddr
 * @param idle_timeout after how long should we timeout idle connections?
 * @param require_found if YES, connections sending messages of unknown type
 *        will be closed
 * @return handle for the new server, NULL on error
 *         (typically, "port" already in use)
 */
struct GNUNET_SERVER_Handle *
GNUNET_SERVER_create (GNUNET_CONNECTION_AccessCheck access, void *access_cls,
                      struct sockaddr *const *serverAddr,
                      const socklen_t * socklen,
                      struct GNUNET_TIME_Relative idle_timeout,
                      int require_found);


/**
 * Stop the listen socket and get ready to shutdown the server
 * once only 'monitor' clients are left.
 *
 * @param server server to stop listening on
 */
void
GNUNET_SERVER_stop_listening (struct GNUNET_SERVER_Handle *server);


/**
 * Free resources held by this server.
 *
 * @param server server to destroy
 */
void
GNUNET_SERVER_destroy (struct GNUNET_SERVER_Handle *server);


/**
 * Add additional handlers to an existing server.
 *
 * @param server the server to add handlers to
 * @param handlers array of message handlers for
 *        incoming messages; the last entry must
 *        have "NULL" for the "callback"; multiple
 *        entries for the same type are allowed,
 *        they will be called in order of occurence.
 *        These handlers can be removed later;
 *        the handlers array must exist until removed
 *        (or server is destroyed).
 */
void
GNUNET_SERVER_add_handlers (struct GNUNET_SERVER_Handle *server,
                            const struct GNUNET_SERVER_MessageHandler
                            *handlers);


/**
 * Notify us when the server has enough space to transmit
 * a message of the given size to the given client.
 *
 * @param client client to transmit message to
 * @param size requested amount of buffer space
 * @param timeout after how long should we give up (and call
 *        notify with buf NULL and size 0)?
 * @param callback function to call when space is available
 * @param callback_cls closure for callback
 * @return non-NULL if the notify callback was queued; can be used
 *           to cancel the request using
 *           GNUNET_SERVER_notify_transmit_ready_cancel.
 *         NULL if we are already going to notify someone else (busy)
 */
struct GNUNET_SERVER_TransmitHandle *
GNUNET_SERVER_notify_transmit_ready (struct GNUNET_SERVER_Client *client,
                                     size_t size,
                                     struct GNUNET_TIME_Relative timeout,
                                     GNUNET_CONNECTION_TransmitReadyNotify
                                     callback, void *callback_cls);


/**
 * Abort transmission request.
 *
 * @param th request to abort
 */
void
GNUNET_SERVER_notify_transmit_ready_cancel (struct GNUNET_SERVER_TransmitHandle *th);


/**
 * Set the 'monitor' flag on this client.  Clients which have been
 * marked as 'monitors' won't prevent the server from shutting down
 * once 'GNUNET_SERVER_stop_listening' has been invoked.  The idea is
 * that for "normal" clients we likely want to allow them to process
 * their requests; however, monitor-clients are likely to 'never'
 * disconnect during shutdown and thus will not be considered when
 * determining if the server should continue to exist after
 * 'GNUNET_SERVER_destroy' has been called.
 *
 * @param client the client to set the 'monitor' flag on
 */
void
GNUNET_SERVER_client_mark_monitor (struct GNUNET_SERVER_Client *client);


/**
 * Set the persistent flag on this client, used to setup client connection
 * to only be killed when the service it's connected to is actually dead.
 *
 * @param client the client to set the persistent flag on
 */
void
GNUNET_SERVER_client_persist_ (struct GNUNET_SERVER_Client *client);


/**
 * Resume receiving from this client, we are done processing the
 * current request.  This function must be called from within each
 * GNUNET_SERVER_MessageCallback (or its respective continuations).
 *
 * @param client client we were processing a message of
 * @param success GNUNET_OK to keep the connection open and
 *                          continue to receive
 *                GNUNET_NO to close the connection (normal behavior)
 *                GNUNET_SYSERR to close the connection (signal
 *                          serious error)
 */
void
GNUNET_SERVER_receive_done (struct GNUNET_SERVER_Client *client, int success);


/**
 * Change the timeout for a particular client.  Decreasing the timeout
 * may not go into effect immediately (only after the previous timeout
 * times out or activity happens on the socket).
 *
 * @param client the client to update
 * @param timeout new timeout for activities on the socket
 */
void
GNUNET_SERVER_client_set_timeout (struct GNUNET_SERVER_Client *client,
                                  struct GNUNET_TIME_Relative timeout);


/**
 * Disable the warning the server issues if a message is not acknowledged
 * in a timely fashion.  Use this call if a client is intentionally delayed
 * for a while.  Only applies to the current message.
 *
 * @param client client for which to disable the warning
 */
void
GNUNET_SERVER_disable_receive_done_warning (struct GNUNET_SERVER_Client
                                            *client);


/**
 * Inject a message into the server, pretend it came
 * from the specified client.  Delivery of the message
 * will happen instantly (if a handler is installed;
 * otherwise the call does nothing).
 *
 * @param server the server receiving the message
 * @param sender the "pretended" sender of the message
 *        can be NULL!
 * @param message message to transmit
 * @return GNUNET_OK if the message was OK and the
 *                   connection can stay open
 *         GNUNET_SYSERR if the connection to the
 *         client should be shut down
 */
int
GNUNET_SERVER_inject (struct GNUNET_SERVER_Handle *server,
                      struct GNUNET_SERVER_Client *sender,
                      const struct GNUNET_MessageHeader *message);


/**
 * Add a TCP socket-based connection to the set of handles managed by
 * this server.  Use this function for outgoing (P2P) connections that
 * we initiated (and where this server should process incoming
 * messages).
 *
 * @param server the server to use
 * @param connection the connection to manage (client must
 *        stop using this connection from now on)
 * @return the client handle (client should call
 *         "client_drop" on the return value eventually)
 */
struct GNUNET_SERVER_Client *
GNUNET_SERVER_connect_socket (struct GNUNET_SERVER_Handle *server,
                              struct GNUNET_CONNECTION_Handle *connection);


/**
 * Notify the server that the given client handle should
 * be kept (keeps the connection up if possible, increments
 * the internal reference counter).
 *
 * @param client the client to keep
 */
void
GNUNET_SERVER_client_keep (struct GNUNET_SERVER_Client *client);


/**
 * Notify the server that the given client handle is no
 * longer required.  Decrements the reference counter.  If
 * that counter reaches zero an inactive connection maybe
 * closed.
 *
 * @param client the client to drop
 */
void
GNUNET_SERVER_client_drop (struct GNUNET_SERVER_Client *client);


/**
 * Obtain the network address of the other party.
 *
 * @param client the client to get the address for
 * @param addr where to store the address
 * @param addrlen where to store the length of the address
 * @return GNUNET_OK on success
 */
int
GNUNET_SERVER_client_get_address (struct GNUNET_SERVER_Client *client,
                                  void **addr, size_t * addrlen);


/**
 * Functions with this signature are called whenever a client
 * is disconnected on the network level.
 *
 * @param cls closure
 * @param client identification of the client; NULL
 *        for the last call when the server is destroyed
 */
typedef void (*GNUNET_SERVER_DisconnectCallback) (void *cls,
                                                  struct GNUNET_SERVER_Client *
                                                  client);


/**
 * Ask the server to notify us whenever a client disconnects.
 * This function is called whenever the actual network connection
 * is closed; the reference count may be zero or larger than zero
 * at this point.  If the server is destroyed before this
 * notification is explicitly cancelled, the 'callback' will
 * once be called with a 'client' argument of NULL to indicate
 * that the server itself is now gone (and that the callback
 * won't be called anymore and also can no longer be cancelled).
 *
 * @param server the server manageing the clients
 * @param callback function to call on disconnect
 * @param callback_cls closure for callback
 */
void
GNUNET_SERVER_disconnect_notify (struct GNUNET_SERVER_Handle *server,
                                 GNUNET_SERVER_DisconnectCallback callback,
                                 void *callback_cls);


/**
 * Ask the server to stop notifying us whenever a client disconnects.
 *
 * @param server the server manageing the clients
 * @param callback function to call on disconnect
 * @param callback_cls closure for callback
 */
void
GNUNET_SERVER_disconnect_notify_cancel (struct GNUNET_SERVER_Handle *server,
                                        GNUNET_SERVER_DisconnectCallback
                                        callback, void *callback_cls);


/**
 * Ask the server to disconnect from the given client.
 * This is the same as returning GNUNET_SYSERR from a message
 * handler, except that it allows dropping of a client even
 * when not handling a message from that client.
 *
 * @param client the client to disconnect from
 */
void
GNUNET_SERVER_client_disconnect (struct GNUNET_SERVER_Client *client);


/**
 * Disable the "CORK" feature for communication with the given client,
 * forcing the OS to immediately flush the buffer on transmission
 * instead of potentially buffering multiple messages.
 *
 * @param client handle to the client
 * @return GNUNET_OK on success
 */
int
GNUNET_SERVER_client_disable_corking (struct GNUNET_SERVER_Client *client);


/**
 * The tansmit context is the key datastructure for a conveniance API
 * used for transmission of complex results to the client followed
 * ONLY by signaling receive_done with success or error
 */
struct GNUNET_SERVER_TransmitContext;


/**
 * Create a new transmission context for the
 * given client.
 *
 * @param client client to create the context for.
 * @return NULL on error
 */
struct GNUNET_SERVER_TransmitContext *
GNUNET_SERVER_transmit_context_create (struct GNUNET_SERVER_Client *client);


/**
 * Append a message to the transmission context.
 * All messages in the context will be sent by
 * the transmit_context_run method.
 *
 * @param tc context to use
 * @param data what to append to the result message
 * @param length length of data
 * @param type type of the message
 */
void
GNUNET_SERVER_transmit_context_append_data (struct GNUNET_SERVER_TransmitContext
                                            *tc, const void *data,
                                            size_t length, uint16_t type);


/**
 * Append a message to the transmission context.
 * All messages in the context will be sent by
 * the transmit_context_run method.
 *
 * @param tc context to use
 * @param msg message to append
 */
void
GNUNET_SERVER_transmit_context_append_message (struct
                                               GNUNET_SERVER_TransmitContext
                                               *tc,
                                               const struct GNUNET_MessageHeader
                                               *msg);


/**
 * Execute a transmission context.  If there is an error in the
 * transmission, the receive_done method will be called with an error
 * code (GNUNET_SYSERR), otherwise with GNUNET_OK.
 *
 * @param tc transmission context to use
 * @param timeout when to time out and abort the transmission
 */
void
GNUNET_SERVER_transmit_context_run (struct GNUNET_SERVER_TransmitContext *tc,
                                    struct GNUNET_TIME_Relative timeout);


/**
 * Destroy a transmission context.  This function must not be called
 * after 'GNUNET_SERVER_transmit_context_run'.
 *
 * @param tc transmission context to destroy
 * @param success code to give to 'GNUNET_SERVER_receive_done' for
 *        the client:  GNUNET_OK to keep the connection open and
 *                          continue to receive
 *                GNUNET_NO to close the connection (normal behavior)
 *                GNUNET_SYSERR to close the connection (signal
 *                          serious error)
 */
void
GNUNET_SERVER_transmit_context_destroy (struct GNUNET_SERVER_TransmitContext
                                        *tc, int success);


/**
 * The notification context is the key datastructure for a conveniance
 * API used for transmission of notifications to the client until the
 * client disconnects (or the notification context is destroyed, in
 * which case we disconnect these clients).  Essentially, all
 * (notification) messages are queued up until the client is able to
 * read them.
 */
struct GNUNET_SERVER_NotificationContext;


/**
 * Create a new notification context.
 *
 * @param server server for which this function creates the context
 * @param queue_length maximum number of messages to keep in
 *        the notification queue; optional messages are dropped
 *        if the queue gets longer than this number of messages
 * @return handle to the notification context
 */
struct GNUNET_SERVER_NotificationContext *
GNUNET_SERVER_notification_context_create (struct GNUNET_SERVER_Handle *server,
                                           unsigned int queue_length);


/**
 * Destroy the context, force disconnect for all clients.
 *
 * @param nc context to destroy.
 */
void
GNUNET_SERVER_notification_context_destroy (struct
                                            GNUNET_SERVER_NotificationContext
                                            *nc);


/**
 * Add a client to the notification context.
 *
 * @param nc context to modify
 * @param client client to add
 */
void
GNUNET_SERVER_notification_context_add (struct GNUNET_SERVER_NotificationContext
                                        *nc,
                                        struct GNUNET_SERVER_Client *client);


/**
 * Send a message to a particular client; must have
 * already been added to the notification context.
 *
 * @param nc context to modify
 * @param client client to transmit to
 * @param msg message to send
 * @param can_drop can this message be dropped due to queue length limitations
 */
void
GNUNET_SERVER_notification_context_unicast (struct
                                            GNUNET_SERVER_NotificationContext
                                            *nc,
                                            struct GNUNET_SERVER_Client *client,
                                            const struct GNUNET_MessageHeader
                                            *msg, int can_drop);


/**
 * Send a message to all clients of this context.
 *
 * @param nc context to modify
 * @param msg message to send
 * @param can_drop can this message be dropped due to queue length limitations
 */
void
GNUNET_SERVER_notification_context_broadcast (struct
                                              GNUNET_SERVER_NotificationContext
                                              *nc,
                                              const struct GNUNET_MessageHeader
                                              *msg, int can_drop);



/**
 * Handle to a message stream tokenizer.
 */
struct GNUNET_SERVER_MessageStreamTokenizer;

/**
 * Functions with this signature are called whenever a
 * complete message is received by the tokenizer.
 *
 * Do not call GNUNET_SERVER_mst_destroy in callback
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR to stop further processing
 */
typedef int (*GNUNET_SERVER_MessageTokenizerCallback) (void *cls, void *client,
                                                        const struct
                                                        GNUNET_MessageHeader *
                                                        message);


/**
 * Create a message stream tokenizer.
 *
 * @param cb function to call on completed messages
 * @param cb_cls closure for cb
 * @return handle to tokenizer
 */
struct GNUNET_SERVER_MessageStreamTokenizer *
GNUNET_SERVER_mst_create (GNUNET_SERVER_MessageTokenizerCallback cb,
                          void *cb_cls);


/**
 * Add incoming data to the receive buffer and call the
 * callback for all complete messages.
 *
 * @param mst tokenizer to use
 * @param client_identity ID of client for which this is a buffer,
 *        can be NULL (will be passed back to 'cb')
 * @param buf input data to add
 * @param size number of bytes in buf
 * @param purge should any excess bytes in the buffer be discarded
 *       (i.e. for packet-based services like UDP)
 * @param one_shot only call callback once, keep rest of message in buffer
 * @return GNUNET_OK if we are done processing (need more data)
 *         GNUNET_NO if one_shot was set and we have another message ready
 *         GNUNET_SYSERR if the data stream is corrupt
 */
int
GNUNET_SERVER_mst_receive (struct GNUNET_SERVER_MessageStreamTokenizer *mst,
                           void *client_identity, const char *buf, size_t size,
                           int purge, int one_shot);


/**
 * Destroys a tokenizer.
 *
 * @param mst tokenizer to destroy
 */
void
GNUNET_SERVER_mst_destroy (struct GNUNET_SERVER_MessageStreamTokenizer *mst);


/**
 * Signature of a function to create a custom tokenizer.
 *
 * @param cls closure from 'GNUNET_SERVER_set_callbacks'
 * @param client handle to client the tokenzier will be used for
 * @return handle to custom tokenizer ('mst')
 */
typedef void* (*GNUNET_SERVER_MstCreateCallback) (void *cls,
                                                  struct GNUNET_SERVER_Client *client);

/**
 * Signature of a function to destroy a custom tokenizer.
 *
 * @param cls closure from 'GNUNET_SERVER_set_callbacks'
 * @param mst custom tokenizer handle
 */
typedef void (*GNUNET_SERVER_MstDestroyCallback) (void *cls, void *mst);

/**
 * Signature of a function to destroy a custom tokenizer.
 *
 * @param cls closure from 'GNUNET_SERVER_set_callbacks'
 * @param mst custom tokenizer handle
 * @param client_identity ID of client for which this is a buffer,
 *        can be NULL (will be passed back to 'cb')
 * @param buf input data to add
 * @param size number of bytes in buf
 * @param purge should any excess bytes in the buffer be discarded
 *       (i.e. for packet-based services like UDP)
 * @param one_shot only call callback once, keep rest of message in buffer
 * @return GNUNET_OK if we are done processing (need more data)
 *         GNUNET_NO if one_shot was set and we have another message ready
 *         GNUNET_SYSERR if the data stream is corrupt 
 */
typedef int (*GNUNET_SERVER_MstReceiveCallback) (void *cls, void *mst,
                                                 struct GNUNET_SERVER_Client *client,
                                                 const char *buf, size_t size,
                                                 int purge, int one_shot);


/**
 * Change functions used by the server to tokenize the message stream.
 * (very rarely used).
 *
 * @param server server to modify
 * @param create new tokenizer initialization function
 * @param destroy new tokenizer destruction function
 * @param receive new tokenizer receive function
 * @param cls closure for 'create', 'receive', 'destroy' 
 */
void
GNUNET_SERVER_set_callbacks (struct GNUNET_SERVER_Handle *server,
                             GNUNET_SERVER_MstCreateCallback create,
                             GNUNET_SERVER_MstDestroyCallback destroy,
                             GNUNET_SERVER_MstReceiveCallback receive,
                             void *cls);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_SERVER_LIB_H */
#endif
/* end of gnunet_server_lib.h */
