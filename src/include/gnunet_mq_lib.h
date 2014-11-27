/*
     This file is part of GNUnet.
     (C) 2012-2013 Christian Grothoff (and other contributing authors)

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
 * @author Florian Dold
 * @file include/gnunet_mq_lib.h
 * @brief general purpose message queue
 * @defgroup mq general purpose message queue
 * @{
 */
#ifndef GNUNET_MQ_H
#define GNUNET_MQ_H


/**
 * Allocate an envelope, with extra space allocated after the space needed
 * by the message struct.
 * The allocated message will already have the type and size field set.
 *
 * @param mvar variable to store the allocated message in;
 *             must have a header field
 * @param esize extra space to allocate after the message
 * @param type type of the message
 * @return the MQ message
 */
#define GNUNET_MQ_msg_extra(mvar, esize, type) GNUNET_MQ_msg_(((struct GNUNET_MessageHeader**) &(mvar)), (esize) + sizeof *(mvar), (type))

/**
 * Allocate a GNUNET_MQ_Envelope.
 * The contained message will already have the type and size field set.
 *
 * @param mvar variable to store the allocated message in;
 *             must have a header field
 * @param type type of the message
 * @return the allocated envelope
 */
#define GNUNET_MQ_msg(mvar, type) GNUNET_MQ_msg_extra(mvar, 0, type)


/**
 * Allocate a GNUNET_MQ_Envelope, where the message only consists of a header.
 * The allocated message will already have the type and size field set.
 *
 * @param type type of the message
 */
#define GNUNET_MQ_msg_header(type) GNUNET_MQ_msg_ (NULL, sizeof (struct GNUNET_MessageHeader), type)


/**
 * Allocate a GNUNET_MQ_Envelope, where the message only consists of a header and extra space.
 * The allocated message will already have the type and size field set.
 *
 * @param mh pointer that will changed to point at to the allocated message header
 * @param esize extra space to allocate after the message header
 * @param type type of the message
 */
#define GNUNET_MQ_msg_header_extra(mh, esize, type) GNUNET_MQ_msg_ (&mh, (esize) + sizeof (struct GNUNET_MessageHeader), type)


/**
 * Allocate a GNUNET_MQ_Envelope, and append a payload message after the given
 * message struct.
 *
 * @param mvar pointer to a message struct, will be changed to point at the newly allocated message,
 *        whose size is 'sizeof(*mvar) + ntohs (mh->size)'
 * @param type message type of the allocated message, has no effect on the nested message
 * @param mh message to nest
 * @return a newly allocated 'struct GNUNET_MQ_Envelope *'
 */
#define GNUNET_MQ_msg_nested_mh(mvar, type, mh) GNUNET_MQ_msg_nested_mh_((((void)(mvar)->header), (struct GNUNET_MessageHeader**) &(mvar)), sizeof (*(mvar)), (type), mh)


/**
 * Return a pointer to the message at the end of the given message.
 *
 * @param var pointer to a message struct, the type of the expression determines the base size,
 *        the space after the base size is the nested message
 * @return a 'struct GNUNET_MessageHeader *' that points at the nested message of the given message,
 *         or NULL if the given message in @a var does not have any space after the message struct
 */
#define GNUNET_MQ_extract_nested_mh(var) GNUNET_MQ_extract_nested_mh_ ((struct GNUNET_MessageHeader *) (var), sizeof (*(var)))


/**
 * Implementation of the GNUNET_MQ_extract_nexted_mh macro.
 *
 * @param mh message header to extract nested message header from
 * @param base_size size of the message before the nested message's header appears
 * @return pointer to the nested message, does not copy the message
 */
const struct GNUNET_MessageHeader *
GNUNET_MQ_extract_nested_mh_ (const struct GNUNET_MessageHeader *mh,
                              uint16_t base_size);


/**
 * Implementation of the GNUNET_MQ_msg_nested_mh macro.
 *
 * @param mhp pointer to the message header pointer that will be changed to allocate at
 *        the newly allocated space for the message.
 * @param base_size size of the data before the nested message
 * @param type type of the message in the envelope
 * @param nested_mh the message to append to the message after base_size
 */
struct GNUNET_MQ_Envelope *
GNUNET_MQ_msg_nested_mh_ (struct GNUNET_MessageHeader **mhp, uint16_t base_size, uint16_t type,
                          const struct GNUNET_MessageHeader *nested_mh);



/**
 * End-marker for the handlers array
 */
#define GNUNET_MQ_HANDLERS_END {NULL, 0, 0}


/**
 * Opaque handle to a message queue.
 */
struct GNUNET_MQ_Handle;

/**
 * Opaque handle to an envelope.
 */
struct GNUNET_MQ_Envelope;


/**
 * Error codes for the queue.
 */
enum GNUNET_MQ_Error
{
  /**
   * FIXME: document!
   */
  GNUNET_MQ_ERROR_READ = 1,

  /**
   * FIXME: document!
   */
  GNUNET_MQ_ERROR_WRITE = 2,

  /**
   * FIXME: document!
   */
  GNUNET_MQ_ERROR_TIMEOUT = 4
};


/**
 * Called when a message has been received.
 *
 * @param cls closure
 * @param msg the received message
 */
typedef void
(*GNUNET_MQ_MessageCallback) (void *cls,
                              const struct GNUNET_MessageHeader *msg);


/**
 * Signature of functions implementing the
 * sending functionality of a message queue.
 *
 * @param mq the message queue
 * @param msg the message to send
 * @param impl_state state of the implementation
 */
typedef void
(*GNUNET_MQ_SendImpl) (struct GNUNET_MQ_Handle *mq,
                       const struct GNUNET_MessageHeader *msg,
                       void *impl_state);


/**
 * Signature of functions implementing the
 * destruction of a message queue.
 * Implementations must not free @a mq, but should
 * take care of @a impl_state.
 *
 * @param mq the message queue to destroy
 * @param impl_state state of the implementation
 */
typedef void
(*GNUNET_MQ_DestroyImpl) (struct GNUNET_MQ_Handle *mq, void *impl_state);


/**
 * Implementation function that cancels the currently sent message.
 *
 * @param mq message queue
 * @param impl_state state specific to the implementation
 */
typedef void
(*GNUNET_MQ_CancelImpl) (struct GNUNET_MQ_Handle *mq, void *impl_state);


/**
 * Callback used for notifications
 *
 * @param cls closure
 */
typedef void
(*GNUNET_MQ_NotifyCallback) (void *cls);


/**
 * Generic error handler, called with the appropriate
 * error code and the same closure specified at the creation of
 * the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure, same closure as for the message handlers
 * @param error error code
 */
typedef void
(*GNUNET_MQ_ErrorHandler) (void *cls, enum GNUNET_MQ_Error error);


/**
 * Message handler for a specific message type.
 */
struct GNUNET_MQ_MessageHandler
{
  /**
   * Callback, called every time a new message of
   * the specified type has been receied.
   */
  GNUNET_MQ_MessageCallback cb;

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
 * Create a new envelope.
 *
 * @param mhp message header to store the allocated message header in, can be NULL
 * @param size size of the message to allocate
 * @param type type of the message, will be set in the allocated message
 * @return the allocated MQ message
 */
struct GNUNET_MQ_Envelope *
GNUNET_MQ_msg_ (struct GNUNET_MessageHeader **mhp, uint16_t size, uint16_t type);


/**
 * Discard the message queue message, free all
 * allocated resources. Must be called in the event
 * that a message is created but should not actually be sent.
 *
 * @param mqm the message to discard
 */
void
GNUNET_MQ_discard (struct GNUNET_MQ_Envelope *mqm);


/**
 * Send a message with the give message queue.
 * May only be called once per message.
 *
 * @param mq message queue
 * @param ev the envelope with the message to send.
 */
void
GNUNET_MQ_send (struct GNUNET_MQ_Handle *mq,
		struct GNUNET_MQ_Envelope *ev);


/**
 * Cancel sending the message. Message must have been sent with
 * #GNUNET_MQ_send before.  May not be called after the notify sent
 * callback has been called
 *
 * @param ev queued envelope to cancel
 */
void
GNUNET_MQ_send_cancel (struct GNUNET_MQ_Envelope *ev);


/**
 * Associate the assoc_data in mq with a unique request id.
 *
 * @param mq message queue, id will be unique for the queue
 * @param assoc_data to associate
 */
uint32_t
GNUNET_MQ_assoc_add (struct GNUNET_MQ_Handle *mq, void *assoc_data);


/**
 * Get the data associated with a request id in a queue
 *
 * @param mq the message queue with the association
 * @param request_id the request id we are interested in
 * @return the associated data
 */
void *
GNUNET_MQ_assoc_get (struct GNUNET_MQ_Handle *mq, uint32_t request_id);


/**
 * Remove the association for a request id
 *
 * @param mq the message queue with the association
 * @param request_id the request id we want to remove
 * @return the associated data
 */
void *
GNUNET_MQ_assoc_remove (struct GNUNET_MQ_Handle *mq, uint32_t request_id);


/**
 * Create a message queue for a GNUNET_CLIENT_Connection.
 * If handlers are specfied, receive messages from the connection.
 *
 * @param connection the client connection
 * @param handlers handlers for receiving messages
 * @param error_handler error handler
 * @param cls closure for the handlers
 * @return the message queue
 */
struct GNUNET_MQ_Handle *
GNUNET_MQ_queue_for_connection_client (struct GNUNET_CLIENT_Connection *connection,
                                       const struct GNUNET_MQ_MessageHandler *handlers,
                                       GNUNET_MQ_ErrorHandler error_handler,
                                       void *cls);


/**
 * Create a message queue for a GNUNET_SERVER_Client.
 *
 * @param client the client
 * @return the message queue
 */
struct GNUNET_MQ_Handle *
GNUNET_MQ_queue_for_server_client (struct GNUNET_SERVER_Client *client);


/**
 * Create a message queue for the specified handlers.
 *
 * @param send function the implements sending messages
 * @param destroy function that implements destroying the queue
 * @param cancel function that implements canceling a message
 * @param impl_state for the queue, passed to @a send, @a destroy and @a cancel
 * @param handlers array of message handlers
 * @param error_handler handler for read and write errors
 * @param cls closure for message handlers and error handler
 * @return a new message queue
 */
struct GNUNET_MQ_Handle *
GNUNET_MQ_queue_for_callbacks (GNUNET_MQ_SendImpl send,
                               GNUNET_MQ_DestroyImpl destroy,
                               GNUNET_MQ_CancelImpl cancel,
                               void *impl_state,
                               const struct GNUNET_MQ_MessageHandler *handlers,
                               GNUNET_MQ_ErrorHandler error_handler,
                               void *cls);



/**
 * Replace the handlers of a message queue with new handlers.  Takes
 * effect immediately, even for messages that already have been
 * received, but for with the handler has not been called.
 *
 * If the message queue does not support receiving messages,
 * this function has no effect.
 *
 * @param mq message queue
 * @param new_handlers new handlers
 * @param cls new closure for the handlers
 */
void
GNUNET_MQ_replace_handlers (struct GNUNET_MQ_Handle *mq,
                            const struct GNUNET_MQ_MessageHandler *new_handlers,
                            void *cls);


/**
 * Call a callback once the envelope has been sent, that is,
 * sending it can not be canceled anymore.
 * There can be only one notify sent callback per envelope.
 *
 * @param ev message to call the notify callback for
 * @param cb the notify callback
 * @param cls closure for the callback
 */
void
GNUNET_MQ_notify_sent (struct GNUNET_MQ_Envelope *ev,
                       GNUNET_MQ_NotifyCallback cb,
                       void *cls);


/**
 * Destroy the message queue.
 *
 * @param mq message queue to destroy
 */
void
GNUNET_MQ_destroy (struct GNUNET_MQ_Handle *mq);


/**
 * Call the message message handler that was registered
 * for the type of the given message in the given message queue.
 *
 * This function is indended to be used for the implementation
 * of message queues.
 *
 * @param mq message queue with the handlers
 * @param mh message to dispatch
 */
void
GNUNET_MQ_inject_message (struct GNUNET_MQ_Handle *mq,
                          const struct GNUNET_MessageHeader *mh);


/**
 * Call the error handler of a message queue with the given
 * error code.  If there is no error handler, log a warning.
 *
 * This function is intended to be used for the implementation
 * of message queues.
 *
 * @param mq message queue
 * @param error the error type
 */
void
GNUNET_MQ_inject_error (struct GNUNET_MQ_Handle *mq,
                        enum GNUNET_MQ_Error error);


/**
 * Call the send implementation for the next queued message,
 * if any.
 * Only useful for implementing message queues,
 * results in undefined behavior if not used carefully.
 *
 * @param mq message queue to send the next message with
 */
void
GNUNET_MQ_impl_send_continue (struct GNUNET_MQ_Handle *mq);


/**
 * Get the message that should currently be sent.
 * The returned message is only valid until #GNUNET_MQ_impl_send_continue
 * is called.
 * Fails if there is no current message.
 * Only useful for implementing message queues,
 * results in undefined behavior if not used carefully.
 *
 * @param mq message queue with the current message, only valid
 *        until #GNUNET_MQ_impl_send_continue is called
 * @return message to send, never NULL
 */
const struct GNUNET_MessageHeader *
GNUNET_MQ_impl_current (struct GNUNET_MQ_Handle *mq);


/**
 * Get the implementation state associated with the
 * message queue.
 *
 * While the GNUNET_MQ_Impl* callbacks receive the
 * implementation state, continuations that are scheduled
 * by the implementation function often only have one closure
 * argument, with this function it is possible to get at the
 * implementation state when only passing the GNUNET_MQ_Handle
 * as closure.
 *
 * @param mq message queue with the current message
 * @return message to send, never NULL
 */
void *
GNUNET_MQ_impl_state (struct GNUNET_MQ_Handle *mq);


/** @} */ /* end of group mq */

#endif
