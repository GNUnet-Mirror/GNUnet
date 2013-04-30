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
#ifndef MQ_H
#define MQ_H

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_connection_lib.h"
#include "gnunet_server_lib.h"
#include "gnunet_stream_lib.h"


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
 * Append data to the end of an existing MQ message.
 * If the operation is successful, mqm is changed to point to the new MQ message,
 * and GNUNET_OK is returned.
 * On failure, GNUNET_SYSERR is returned, and the pointer mqm is not changed,
 * the user of this API must take care of disposing the already allocated message
 * (either by sending it, or by using GNUNET_MQ_discard)
 *
 * @param mqm MQ message to augment with additional data
 * @param src source buffer for the additional data
 * @param len length of the additional data
 * @return FIXME
 */
#define GNUNET_MQ_nest(mqm, src, len) GNUNET_MQ_nest_ (&mqm, src, len)



/**
 * Append a message to the end of an existing MQ message.
 * If the operation is successful, mqm is changed to point to the new MQ message,
 * and GNUNET_OK is returned.
 * On failure, GNUNET_SYSERR is returned, and the pointer mqm is not changed,
 * the user of this API must take care of disposing the already allocated message
 * (either by sending it, or by using GNUNET_MQ_discard)
 *
 * @param mqm MQ message to augment with additional data
 * @param mh the message to append, must be of type 'struct GNUNET_MessageHeader *'
 */
#define GNUNET_MQ_nest_mh(mqm, mh) ((NULL == mh) ? (GNUNET_OK) : GNUNET_MQ_nest((mqm), (mh), ntohs ((mh)->size)))


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
#define GNUNET_MQ_msg_header_extra(mh, esize, type) GNUNET_MQ_msg_ (&mh, sizeof (struct GNUNET_MessageHeader), type)


/**
 * End-marker for the handlers array
 */
#define GNUNET_MQ_HANDLERS_END {NULL, 0, 0}

/**
 * Opaque handle to a message queue
 */
struct GNUNET_MQ_MessageQueue;

/**
 * Opaque handle to an allocated message
 */
struct GNUNET_MQ_Message; // Entry (/ Request)

/**
 * Called when a message has been received.
 *
 * @param cls closure
 * @param msg the received message
 */
typedef void (*GNUNET_MQ_MessageCallback) (void *cls, const struct GNUNET_MessageHeader *msg);


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
 * Callback used for notifications
 *
 * @param cls closure
 */
typedef void (*GNUNET_MQ_NotifyCallback) (void *cls);

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


int
GNUNET_MQ_nest_ (struct GNUNET_MQ_Message **mqmp,
                 const void *src, uint16_t len);


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
 * Create a message queue for a GNUNET_STREAM_Socket.
 * If handlers are specfied, receive messages from the stream socket.
 *
 * @param socket the stream socket
 * @param handlers handlers for receiving messages
 * @param cls closure for the handlers
 * @return the message queue
 */
struct GNUNET_MQ_MessageQueue *
GNUNET_MQ_queue_for_stream_socket (struct GNUNET_STREAM_Socket *socket,
                                   const struct GNUNET_MQ_Handler *handlers,
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
 * Call a callback once all messages queued have been sent,
 * i.e. the message queue is empty.
 *
 * @param mqm the message queue to send the notification for
 * @param cb the callback to call on an empty queue
 * @param cls closure for cb
 */
void
GNUNET_MQ_notify_empty (struct GNUNET_MQ_MessageQueue *mqm,
                        GNUNET_MQ_NotifyCallback cb,
                        void *cls);


/**
 * Call a callback if reading encountered an error.
 *
 * @param mqm the message queue to send the notification for
 * @param cb the callback to call on a read error
 * @param cls closure for cb
 */
void
GNUNET_MQ_notify_read_error (struct GNUNET_MQ_MessageQueue *mqm,
                             GNUNET_MQ_NotifyCallback cb,
                             void *cls);


/**
 * Destroy the message queue.
 *
 * @param mq message queue to destroy
 */
void
GNUNET_MQ_destroy (struct GNUNET_MQ_MessageQueue *mq);

#endif
