/*
     This file is part of GNUnet.
     Copyright (C) 2013 GNUnet e.V.

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
 * @author Gabor X Toth
 *
 * @file
 * Client manager; higher level client API with transmission queue
 * and message handler registration.
 *
 * @defgroup client-manager  Client manager library
 * Higher level client-side communication with services.
 *
 * Provides a higher level client API
 * with transmission queue and message handler registration.
 * @{
 */
#ifndef GNUNET_CLIENT_MANAGER_LIB_H
#define GNUNET_CLIENT_MANAGER_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Client manager connection handle.
 */
struct GNUNET_CLIENT_MANAGER_Connection;


/**
 * Functions with this signature are called whenever a message is
 * received.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
typedef void
(*GNUNET_CLIENT_MANAGER_MessageCallback) (void *cls,
                                          struct GNUNET_CLIENT_MANAGER_Connection *mgr,
                                          const struct GNUNET_MessageHeader *msg);


/**
 * Message handler.  Each struct specifies how to handle on particular
 * type of message received.
 */
struct GNUNET_CLIENT_MANAGER_MessageHandler
{
  /**
   * Function to call for messages of @a type.
   */
  GNUNET_CLIENT_MANAGER_MessageCallback callback;

  /**
   * Closure argument for @a callback.
   */
  void *callback_cls;

  /**
   * Type of the message this handler covers.
   * Use 0 to handle loss of connection.
   */
  uint16_t type;

  /**
   * Expected size of messages of this type.  Use 0 to skip size check.
   * If non-zero, messages of the given type will be discarded
   * (and the connection closed) if they do not have the right size.
   */
  uint16_t expected_size;

  /**
   * #GNUNET_NO for fixed-size messages.
   * #GNUNET_YES if the message size can vary.
   * In this case @a expected_size is treated as minimum size.
   */
  uint8_t is_variable_size;
};


/**
 * Connect to a service.
 *
 * @param cfg
 *        Configuration to use.
 * @param service_name
 *        Service name to connect to.
 * @param handlers
 *        Message handlers.
 *
 * @return Client manager connection handle.
 */
struct GNUNET_CLIENT_MANAGER_Connection *
GNUNET_CLIENT_MANAGER_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                               const char *service_name,
                               const struct
                               GNUNET_CLIENT_MANAGER_MessageHandler *handlers);


/**
 * Disconnect from the service.
 *
 * @param mgr
 *        Client manager connection.
 * @param transmit_queue
 *        Transmit pending messages in queue before disconnecting.
 * @param disconnect_cb
 *        Function called after disconnected from the service.
 * @param cls
 *        Closure for @a disconnect_cb.
 */
void
GNUNET_CLIENT_MANAGER_disconnect (struct GNUNET_CLIENT_MANAGER_Connection *mgr,
                                  int transmit_queue,
                                  GNUNET_ContinuationCallback disconnect_cb,
                                  void *cls);


/**
 * Reschedule connect to the service using exponential back-off.
 *
 * @param mgr
 *        Client manager connection.
 */
void
GNUNET_CLIENT_MANAGER_reconnect (struct GNUNET_CLIENT_MANAGER_Connection *mgr);


/**
 * Add a message to the end of the transmission queue.
 *
 * @param mgr
 *        Client manager connection.
 * @param msg
 *        Message to transmit, should be allocated with GNUNET_malloc() or
 *        GNUNET_new(), as it is freed with GNUNET_free() after transmission.
 */
void
GNUNET_CLIENT_MANAGER_transmit (struct GNUNET_CLIENT_MANAGER_Connection *mgr,
                                struct GNUNET_MessageHeader *msg);


/**
 * Add a message to the beginning of the transmission queue.
 *
 * @param mgr
 *        Client manager connection.
 * @param msg
 *        Message to transmit, should be allocated with GNUNET_malloc() or
 *        GNUNET_new(), as it is freed with GNUNET_free() after transmission.
 */
void
GNUNET_CLIENT_MANAGER_transmit_now (struct GNUNET_CLIENT_MANAGER_Connection *mgr,
                                    struct GNUNET_MessageHeader *msg);


/**
 * Drop all queued messages.
 *
 * @param mgr
 *        Client manager connection.
 */
void
GNUNET_CLIENT_MANAGER_drop_queue (struct GNUNET_CLIENT_MANAGER_Connection *mgr);


/**
 * Obtain client connection handle.
 *
 * @param mgr
 *        Client manager connection.
 *
 * @return Client connection handle.
 */
struct GNUNET_CLIENT_Connection *
GNUNET_CLIENT_MANAGER_get_client (struct GNUNET_CLIENT_MANAGER_Connection *mgr);


/**
 * Return user context associated with the given client manager.
 * Note: you should probably use the macro (call without the underscore).
 *
 * @param mgr
 *        Client manager connection.
 * @param size
 *        Number of bytes in user context struct (for verification only).
 */
void *
GNUNET_CLIENT_MANAGER_get_user_context_ (struct GNUNET_CLIENT_MANAGER_Connection *mgr,
                                         size_t size);


/**
 * Set user context to be associated with the given client manager.
 * Note: you should probably use the macro (call without the underscore).
 *
 * @param mgr
 *        Client manager connection.
 * @param ctx
 *        User context.
 * @param size
 *        Number of bytes in user context struct (for verification only).
 */
void
GNUNET_CLIENT_MANAGER_set_user_context_ (struct GNUNET_CLIENT_MANAGER_Connection *mgr,
                                         void *ctx,
                                         size_t size);


/**
 * Return user context associated with the given client manager.
 *
 * @param mgr
 *        Client manager connection.
 * @param type
 *        Type of context (for size verification).
 */
#define GNUNET_CLIENT_MANAGER_get_user_context(mgr, type)               \
  (type *) GNUNET_CLIENT_MANAGER_get_user_context_ (mgr, sizeof (type))


/**
 * Set user context to be associated with the given client manager.
 *
 * @param mgr
 *        Client manager connection.
 * @param ctx
 *        Pointer to user context.
 */
#define GNUNET_CLIENT_MANAGER_set_user_context(mgr, ctx)                 \
  GNUNET_CLIENT_MANAGER_set_user_context_ (mgr, ctx, sizeof (*ctx))


/**
 * Get a unique operation ID to distinguish between asynchronous requests.
 *
 * @param mgr
 *        Client manager connection.
 *
 * @return Operation ID to use.
 */
uint64_t
GNUNET_CLIENT_MANAGER_op_get_next_id (struct GNUNET_CLIENT_MANAGER_Connection *mgr);


/**
 * Find operation by ID.
 *
 * @param mgr
 *        Client manager connection.
 * @param op_id
 *        Operation ID to look up.
 * @param[out] result_cb
 *        If an operation was found, its result callback is returned here.
 * @param[out] cls
 *        If an operation was found, its closure is returned here.
 *
 * @return #GNUNET_YES if an operation was found,
 *         #GNUNET_NO  if not found.
 */
int
GNUNET_CLIENT_MANAGER_op_find (struct GNUNET_CLIENT_MANAGER_Connection *mgr,
                               uint64_t op_id,
                               GNUNET_ResultCallback *result_cb,
                               void **cls);


/**
 * Add a new operation.
 *
 * @param mgr
 *        Client manager connection.
 * @param result_cb
 *        Function to call with the result of the operation.
 * @param cls
 *        Closure for @a result_cb.
 *
 * @return ID of the new operation.
 */
uint64_t
GNUNET_CLIENT_MANAGER_op_add (struct GNUNET_CLIENT_MANAGER_Connection *mgr,
                              GNUNET_ResultCallback result_cb,
                              void *cls);


/**
 * Call the result callback and remove the operation.
 *
 * @param mgr
 *        Client manager connection.
 * @param op_id
 *        Operation ID.
 * @param result_code
 *        Result of the operation.
 * @param data
 *        Data result of the operation.
 * @param data_size
 *        Size of @a data.
 *
 * @return #GNUNET_YES if the operation was found and removed,
 *         #GNUNET_NO  if the operation was not found.
 */
int
GNUNET_CLIENT_MANAGER_op_result (struct GNUNET_CLIENT_MANAGER_Connection *mgr,
                                 uint64_t op_id, int64_t result_code,
                                 const void *data, uint16_t data_size);


/**
 * Cancel an operation.
 *
 * @param mgr
 *        Client manager connection.
 * @param op_id
 *        Operation ID.
 *
 * @return #GNUNET_YES if the operation was found and removed,
 *         #GNUNET_NO  if the operation was not found.
 */
int
GNUNET_CLIENT_MANAGER_op_cancel (struct GNUNET_CLIENT_MANAGER_Connection *mgr,
                                 uint64_t op_id);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_CLIENT_MANAGER_LIB_H */
#endif

/** @} */ /* end of group */
