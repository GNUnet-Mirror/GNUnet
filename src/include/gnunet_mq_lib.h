/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @author Florian Dold
 * @file set/mq.h
 * @brief general purpose request queue
 */
#ifndef GNUNET_MQ_H
#define GNUNET_MQ_H

#include "gnunet_common.h"


/**
 * Allocate a GNUNET_MQ_Message, with extra space allocated after the space needed
 * by the message struct.
 * The allocated message will already have the type and size field set.
 *
 * @param mvar variable to store the allocated message in;
 *             must have a header field
 * @param esize extra space to allocate after the message
 * @param type type of the message
 * @return the MQ message
 */
#define GNUNET_MQ_msg_extra(mvar, esize, type) GNUNET_MQ_msg_((((void)(mvar)->header), (struct GNUNET_MessageHeader**) &(mvar)), (esize) + sizeof *(mvar), (type))

/**
 * Allocate a GNUNET_MQ_Message.
 * The allocated message will already have the type and size field set.
 *
 * @param mvar variable to store the allocated message in;
 *             must have a header field
 * @param type type of the message
 * @return the MQ message
 */
#define GNUNET_MQ_msg(mvar, type) GNUNET_MQ_msg_extra(mvar, 0, type)


/**
 * Allocate a GNUNET_MQ_Message, where the message only consists of a header.
 * The allocated message will already have the type and size field set.
 *
 * @param type type of the message
 */
#define GNUNET_MQ_msg_header(type) GNUNET_MQ_msg_ (NULL, sizeof (struct GNUNET_MessageHeader), type)


/**
 * Allocate a GNUNET_MQ_Message, where the message only consists of a header and extra space.
 * The allocated message will already have the type and size field set.
 *
 * @param mh pointer that will changed to point at to the allocated message header
 * @param esize extra space to allocate after the message header
 * @param type type of the message
 */
#define GNUNET_MQ_msg_header_extra(mh, esize, type) GNUNET_MQ_msg_ (&mh, (esize) + sizeof (struct GNUNET_MessageHeader), type)


/**
 * Allocate a GNUNET_MQ_Message, and append a payload message after the given
 * message struct.
 *
 * @param mvar pointer to a message struct, will be changed to point at the newly allocated message,
 *        whose size is 'sizeof(*mvar) + ntohs (mh->size)'
 * @param type message type of the allocated message, has no effect on the nested message
 * @param mh message to nest
 * @return a newly allocated 'struct GNUNET_MQ_Message *'
 */
#define GNUNET_MQ_msg_nested_mh(mvar, type, mh) GNUNET_MQ_msg_nested_mh_((((void)(mvar)->header), (struct GNUNET_MessageHeader**) &(mvar)), sizeof (*(mvar)), (type), mh)


/**
 * Return a pointer to the message at the end of the given message.
 *
 * @param var pointer to a message struct, the type of the expression determines the base size,
 *        the space after the base size is the nested message
 * @return a 'struct GNUNET_MessageHeader *' that points at the nested message of the given message,
 *         or NULL if the given message in 'var' does not have any space after the message struct
 */
#define GNUNET_MQ_extract_nested_mh(var) GNUNET_MQ_extract_nested_mh_ ((struct GNUNET_MessageHeader *) (var), sizeof (*(var)))


struct GNUNET_MessageHeader *
GNUNET_MQ_extract_nested_mh_ (const struct GNUNET_MessageHeader *mh, uint16_t base_size);


struct GNUNET_MQ_Message *
GNUNET_MQ_msg_nested_mh_ (struct GNUNET_MessageHeader **mhp, uint16_t base_size, uint16_t type,
                          const struct GNUNET_MessageHeader *nested_mh);



/**
 * End-marker for the handlers array
 */
#define GNUNET_MQ_HANDLERS_END {NULL, 0, 0}


struct GNUNET_MQ_MessageQueue;

struct GNUNET_MQ_Message;

enum GNUNET_MQ_Error
{
  GNUNET_MQ_ERROR_READ = 1,
  GNUNET_MQ_ERROR_WRITE = 2,
  GNUNET_MQ_ERROR_TIMEOUT = 4
};


/**
 * Called when a message has been received.
 *
 * @param cls closure
 * @param msg the received message
 */
typedef void
(*GNUNET_MQ_MessageCallback) (void *cls, const struct GNUNET_MessageHeader *msg);


/**
 * Signature of functions implementing the
 * sending part of a message queue
 *
 * @param q the message queue
 * @param m the message
 */
typedef void
(*GNUNET_MQ_SendImpl) (struct GNUNET_MQ_MessageQueue *q, struct GNUNET_MQ_Message *m);


typedef void
(*GNUNET_MQ_DestroyImpl) (struct GNUNET_MQ_MessageQueue *q);


/**
 * Callback used for notifications
 *
 * @param cls closure
 */
typedef void
(*GNUNET_MQ_NotifyCallback) (void *cls);


typedef void
(*GNUNET_MQ_ErrorHandler) (void *cls, enum GNUNET_MQ_Error error);


struct GNUNET_MQ_Message
{
  /**
   * Messages are stored in a linked list
   */
  struct GNUNET_MQ_Message *next;

  /**
   * Messages are stored in a linked list
   */
  struct GNUNET_MQ_Message *prev;

  /**
   * Actual allocated message header,
   * usually points to the end of the containing GNUNET_MQ_Message
   */
  struct GNUNET_MessageHeader *mh;

  /**
   * Queue the message is queued in, NULL if message is not queued.
   */
  struct GNUNET_MQ_MessageQueue *parent_queue;

  /**
   * Called after the message was sent irrevokably
   */
  GNUNET_MQ_NotifyCallback sent_cb;

  /**
   * Closure for send_cb
   */
  void *sent_cls;
};


/**
 * Handle to a message queue.
 */
struct GNUNET_MQ_MessageQueue
{
  /**
   * Handlers array, or NULL if the queue should not receive messages
   */
  const struct GNUNET_MQ_Handler *handlers;

  /**
   * Closure for the handler callbacks,
   * as well as for the error handler.
   */
  void *handlers_cls;

  /**
   * Actual implementation of message sending,
   * called when a message is added
   */
  GNUNET_MQ_SendImpl send_impl;

  /**
   * Implementation-dependent queue destruction function
   */
  GNUNET_MQ_DestroyImpl destroy_impl;

  /**
   * Implementation-specific state
   */
  void *impl_state;

  /**
   * Callback will be called when an error occurs.
   */
  GNUNET_MQ_ErrorHandler error_handler;

  /**
   * Linked list of messages pending to be sent
   */
  struct GNUNET_MQ_Message *msg_head;

  /**
   * Linked list of messages pending to be sent
   */
  struct GNUNET_MQ_Message *msg_tail;

  /**
   * Message that is currently scheduled to be
   * sent. Not the head of the message queue, as the implementation
   * needs to know if sending has been already scheduled or not.
   */
  struct GNUNET_MQ_Message *current_msg;

  /**
   * Map of associations, lazily allocated
   */
  struct GNUNET_CONTAINER_MultiHashMap32 *assoc_map;

  /**
   * Next id that should be used for the assoc_map,
   * initialized lazily to a random value together with
   * assoc_map
   */
  uint32_t assoc_id;
};


/**
 * Message handler for a specific message type.
 */
struct GNUNET_MQ_Handler
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
 * Create a new message for MQ.
 * 
 * @param mhp message header to store the allocated message header in, can be NULL
 * @param size size of the message to allocate
 * @param type type of the message, will be set in the allocated message
 * @return the allocated MQ message
 */
struct GNUNET_MQ_Message *
GNUNET_MQ_msg_ (struct GNUNET_MessageHeader **mhp, uint16_t size, uint16_t type);


/**
 * Discard the message queue message, free all
 * allocated resources. Must be called in the event
 * that a message is created but should not actually be sent.
 *
 * @param mqm the message to discard
 */
void
GNUNET_MQ_discard (struct GNUNET_MQ_Message *mqm);


/**
 * Send a message with the give message queue.
 * May only be called once per message.
 * 
 * @param mq message queue
 * @param mqm the message to send.
 */
void
GNUNET_MQ_send (struct GNUNET_MQ_MessageQueue *mq, struct GNUNET_MQ_Message *mqm);


/**
 * Cancel sending the message. Message must have been sent with GNUNET_MQ_send before.
 * May not be called after the notify sent callback has been called
 *
 * @param mqm queued message to cancel
 */
void
GNUNET_MQ_send_cancel (struct GNUNET_MQ_Message *mqm);


/**
 * Associate the assoc_data in mq with a unique request id.
 *
 * @param mq message queue, id will be unique for the queue
 * @param mqm message to associate
 * @param assoc_data to associate
 */
uint32_t
GNUNET_MQ_assoc_add (struct GNUNET_MQ_MessageQueue *mq,
                     struct GNUNET_MQ_Message *mqm,
                     void *assoc_data);

/**
 * Get the data associated with a request id in a queue
 *
 * @param mq the message queue with the association
 * @param request_id the request id we are interested in
 * @return the associated data
 */
void *
GNUNET_MQ_assoc_get (struct GNUNET_MQ_MessageQueue *mq, uint32_t request_id);


/**
 * Remove the association for a request id
 *
 * @param mq the message queue with the association
 * @param request_id the request id we want to remove
 * @return the associated data
 */
void *
GNUNET_MQ_assoc_remove (struct GNUNET_MQ_MessageQueue *mq, uint32_t request_id);



/**
 * Create a message queue for a GNUNET_CLIENT_Connection.
 * If handlers are specfied, receive messages from the connection.
 *
 * @param connection the client connection
 * @param handlers handlers for receiving messages
 * @param cls closure for the handlers
 * @return the message queue
 */
struct GNUNET_MQ_MessageQueue *
GNUNET_MQ_queue_for_connection_client (struct GNUNET_CLIENT_Connection *connection,
                                       const struct GNUNET_MQ_Handler *handlers,
                                       void *cls);


/**
 * Create a message queue for a GNUNET_STREAM_Socket.
 *
 * @param client the client
 * @return the message queue
 */
struct GNUNET_MQ_MessageQueue *
GNUNET_MQ_queue_for_server_client (struct GNUNET_SERVER_Client *client);


/**
 * Create a message queue for the specified handlers.
 *
 * @param send function the implements sending messages
 * @param destroy function that implements destroying the queue
 * @param state for the queue, passed to 'send' and 'destroy'
 * @param handlers array of message handlers
 * @param error_handler handler for read and write errors
 * @return a new message queue
 */
struct GNUNET_MQ_MessageQueue *
GNUNET_MQ_queue_for_callbacks (GNUNET_MQ_SendImpl send,
                               GNUNET_MQ_DestroyImpl destroy,
                               void *impl_state,
                               struct GNUNET_MQ_Handler *handlers,
                               GNUNET_MQ_ErrorHandler error_handler,
                               void *cls);
                               


/**
 * Replace the handlers of a message queue with new handlers.
 * Takes effect immediately, even for messages that already have been received, but for
 * with the handler has not been called.
 *
 * @param mq message queue
 * @param new_handlers new handlers
 * @param cls new closure for the handlers
 */
void
GNUNET_MQ_replace_handlers (struct GNUNET_MQ_MessageQueue *mq,
                            const struct GNUNET_MQ_Handler *new_handlers,
                            void *cls);


/**
 * Call a callback once the message has been sent, that is, the message
 * can not be canceled anymore.
 * There can be only one notify sent callback per message.
 *
 * @param mqm message to call the notify callback for
 * @param cb the notify callback
 * @param cls closure for the callback
 */
void
GNUNET_MQ_notify_sent (struct GNUNET_MQ_Message *mqm,
                       GNUNET_MQ_NotifyCallback cb,
                       void *cls);


/**
 * Destroy the message queue.
 *
 * @param mq message queue to destroy
 */
void
GNUNET_MQ_destroy (struct GNUNET_MQ_MessageQueue *mq);


/**
 * Call the right callback for a message.
 *
 * @param mq message queue with the handlers
 * @param mh message to dispatch
 */
void
GNUNET_MQ_dispatch (struct GNUNET_MQ_MessageQueue *mq,
                    const struct GNUNET_MessageHeader *mh);

#endif
