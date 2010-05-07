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
#include "gnunet_scheduler_lib.h"


/**
 * Largest supported message.
 */
#define GNUNET_SERVER_MAX_MESSAGE_SIZE 65536


/**
 * @brief handle for a server
 */
struct GNUNET_SERVER_Handle;


/**
 * @brief opaque handle for a client of the server
 */
struct GNUNET_SERVER_Client;


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
                                               const struct
                                               GNUNET_MessageHeader *
                                               message);



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
 * @param sched scheduler to use
 * @param access function for access control
 * @param access_cls closure for access
 * @param serverAddr address toes listen on (including port), NULL terminated array
 * @param socklen lengths of respective serverAddr 
 * @param maxbuf maximum write buffer size for accepted sockets
 * @param idle_timeout after how long should we timeout idle connections?
 * @param require_found if YES, connections sending messages of unknown type
 *        will be closed
 * @return handle for the new server, NULL on error
 *         (typically, "port" already in use)
 */
struct GNUNET_SERVER_Handle *GNUNET_SERVER_create (struct
                                                   GNUNET_SCHEDULER_Handle
                                                   *sched,
                                                   GNUNET_CONNECTION_AccessCheck
                                                   access, void *access_cls,
						   struct sockaddr *const*serverAddr,
                                                   const socklen_t *socklen,
                                                   size_t maxbuf,
                                                   struct GNUNET_TIME_Relative
                                                   idle_timeout,
                                                   int require_found);


/**
 * Free resources held by this server.
 *
 * @param s server to destroy
 */
void GNUNET_SERVER_destroy (struct GNUNET_SERVER_Handle *s);


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
 *           GNUNET_CONNECTION_notify_transmit_ready_cancel.
 *         NULL if we are already going to notify someone else (busy)
 */
struct GNUNET_CONNECTION_TransmitHandle
  *GNUNET_SERVER_notify_transmit_ready (struct GNUNET_SERVER_Client *client,
                                        size_t size,
                                        struct GNUNET_TIME_Relative timeout,
                                        GNUNET_CONNECTION_TransmitReadyNotify
                                        callback, void *callback_cls);


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
struct GNUNET_SERVER_Client *GNUNET_SERVER_connect_socket (struct
                                                           GNUNET_SERVER_Handle
                                                           *server,
                                                           struct
                                                           GNUNET_CONNECTION_Handle
                                                           *connection);


/**
 * Receive data from the given connection.  This function should call
 * "receiver" asynchronously using the scheduler.  It must return
 * "immediately".
 *
 * @param cls closure
 * @param sched scheduler to use
 * @param max maximum number of bytes to read
 * @param timeout maximum amount of time to wait (use -1 for "forever")
 * @param receiver function to call with received data
 * @param receiver_cls closure for receiver
 */
typedef void
  (*GNUNET_SERVER_ReceiveCallback) (void *cls,
                                    size_t max,
                                    struct GNUNET_TIME_Relative timeout,
                                    GNUNET_CONNECTION_Receiver
                                    receiver, void *receiver_cls);


/**
 * Cancel receive request.
 *
 * @param cls closure
 */
typedef void (*GNUNET_SERVER_ReceiveCancelCallback) (void *cls);


/**
 * Notify us when the connection is ready to transmit size bytes.
 *
 * @param cls closure
 * @param size number of bytes to be ready for sending
 * @param timeout after how long should we give up (and call
 *        notify with buf NULL and size 0)?
 * @param notify function to call
 * @param notify_cls closure for notify
 * @return a handle that can be used to cancel
 *         the transmission request or NULL if
 *         queueing a transmission request failed
 */
typedef void *(*GNUNET_SERVER_TransmitReadyCallback) (void *cls,
                                                      size_t size,
                                                      struct
                                                      GNUNET_TIME_Relative
                                                      timeout,
                                                      GNUNET_CONNECTION_TransmitReadyNotify
                                                      notify,
                                                      void *notify_cls);


/**
 * Cancel an earlier transmit notification request.
 *
 * @param cls closure
 * @param ctx handle that was returned by the TransmitReadyCallback
 */
typedef void (*GNUNET_SERVER_TransmitReadyCancelCallback) (void *cls,
                                                           void *ctx);


/**
 * Check if connection is still valid (no fatal errors have happened so far).
 *
 * @param cls closure
 * @return GNUNET_YES if valid, GNUNET_NO otherwise
 */
typedef int (*GNUNET_SERVER_CheckCallback) (void *cls);


/**
 * Destroy this connection (free resources).
 *
 * @param cls closure
 * @param persist when connection is closed, "leak" socket
 */
typedef void (*GNUNET_SERVER_DestroyCallback) (void *cls, int persist);


/**
 * Add an arbitrary connection to the set of handles managed by this
 * server.  This can be used if a sending and receiving does not
 * really go over the network (internal transmission) or for servers
 * using UDP.
 *
 * @param server the server to use
 * @param chandle opaque handle for the connection
 * @param creceive receive function for the connection
 * @param ccancel cancel receive function for the connection
 * @param cnotify transmit notification function for the connection
 * @param cnotify_cancel transmit notification cancellation function for the connection
 * @param ccheck function to test if the connection is still up
 * @param cdestroy function to close and free the connection
 * @return the client handle (client should call
 *         "client_drop" on the return value eventually)
 */
struct GNUNET_SERVER_Client *GNUNET_SERVER_connect_callback (struct
                                                             GNUNET_SERVER_Handle
                                                             *server,
                                                             void *chandle,
                                                             GNUNET_SERVER_ReceiveCallback
                                                             creceive,
                                                             GNUNET_SERVER_ReceiveCancelCallback
                                                             ccancel,
                                                             GNUNET_SERVER_TransmitReadyCallback
                                                             cnotify,
                                                             GNUNET_SERVER_TransmitReadyCancelCallback
                                                             cnotify_cancel,
                                                             GNUNET_SERVER_CheckCallback
                                                             ccheck,
                                                             GNUNET_SERVER_DestroyCallback
                                                             cdestroy);


/**
 * Notify the server that the given client handle should
 * be kept (keeps the connection up if possible, increments
 * the internal reference counter).
 *
 * @param client the client to keep
 */
void GNUNET_SERVER_client_keep (struct GNUNET_SERVER_Client *client);


/**
 * Notify the server that the given client handle is no
 * longer required.  Decrements the reference counter.  If
 * that counter reaches zero an inactive connection maybe
 * closed.
 *
 * @param client the client to drop
 */
void GNUNET_SERVER_client_drop (struct GNUNET_SERVER_Client *client);


/**
 * Obtain the network address of the other party.
 *
 * @param client the client to get the address for
 * @param addr where to store the address
 * @param addrlen where to store the length of the address
 * @return GNUNET_OK on success
 */
int GNUNET_SERVER_client_get_address (struct GNUNET_SERVER_Client *client,
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
                                                  struct GNUNET_SERVER_Client
                                                  * client);


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
void GNUNET_SERVER_disconnect_notify (struct GNUNET_SERVER_Handle *server,
                                      GNUNET_SERVER_DisconnectCallback
                                      callback, void *callback_cls);


/**
 * Ask the server to stop notifying us whenever a client disconnects.
 *
 * @param server the server manageing the clients
 * @param callback function to call on disconnect
 * @param callback_cls closure for callback
 */
void GNUNET_SERVER_disconnect_notify_cancel (struct GNUNET_SERVER_Handle *server,
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
void GNUNET_SERVER_client_disconnect (struct GNUNET_SERVER_Client *client);


/**
 * Configure this server's connections to continue handling client
 * requests as usual even after we get a shutdown signal.  The change
 * only applies to clients that connect to the server from the outside
 * using TCP after this call.  Clients managed previously or those
 * added using GNUNET_SERVER_connect_socket and
 * GNUNET_SERVER_connect_callback are not affected by this option.
 *
 * @param h server handle
 * @param do_ignore GNUNET_YES to ignore, GNUNET_NO to restore default
 */
void
GNUNET_SERVER_ignore_shutdown (struct GNUNET_SERVER_Handle *h,
			       int do_ignore);



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
struct GNUNET_SERVER_TransmitContext
  *GNUNET_SERVER_transmit_context_create (struct GNUNET_SERVER_Client
                                          *client);


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
					    *tc, const void *data, size_t length,
					    uint16_t type);


/**
 * Append a message to the transmission context.
 * All messages in the context will be sent by
 * the transmit_context_run method.
 *
 * @param tc context to use
 * @param msg message to append
 */
void
GNUNET_SERVER_transmit_context_append_message (struct GNUNET_SERVER_TransmitContext
					       *tc, const struct GNUNET_MessageHeader *msg);


/**
 * Execute a transmission context.  If there is
 * an error in the transmission, the receive_done
 * method will be called with an error code (GNUNET_SYSERR),
 * otherwise with GNUNET_OK.
 *
 * @param tc transmission context to use
 * @param timeout when to time out and abort the transmission
 */
void
GNUNET_SERVER_transmit_context_run (struct GNUNET_SERVER_TransmitContext *tc,
                                    struct GNUNET_TIME_Relative timeout);



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
 *        it the queue gets longer than this number of messages
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
GNUNET_SERVER_notification_context_destroy (struct GNUNET_SERVER_NotificationContext *nc);


/**
 * Add a client to the notification context.
 *
 * @param nc context to modify
 * @param client client to add
 */
void
GNUNET_SERVER_notification_context_add (struct GNUNET_SERVER_NotificationContext *nc,
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
GNUNET_SERVER_notification_context_unicast (struct GNUNET_SERVER_NotificationContext *nc,
					    struct GNUNET_SERVER_Client *client,
					    const struct GNUNET_MessageHeader *msg,
					    int can_drop);


/**
 * Send a message to all clients of this context.
 *
 * @param nc context to modify
 * @param msg message to send
 * @param can_drop can this message be dropped due to queue length limitations
 */
void
GNUNET_SERVER_notification_context_broadcast (struct GNUNET_SERVER_NotificationContext *nc,
					      const struct GNUNET_MessageHeader *msg,
					      int can_drop);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_SERVER_LIB_H */
#endif
/* end of gnunet_server_lib.h */
