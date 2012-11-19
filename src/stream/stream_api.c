/*
  This file is part of GNUnet.
  (C) 2012 Christian Grothoff (and other contributing authors)

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

/* TODO:
 *
 * Checks for matching the sender and socket->other_peer in server
 * message handlers  
 *
 * Add code for write io timeout
 *
 * Include retransmission for control messages
 **/

/**
 * @file stream/stream_api.c
 * @brief Implementation of the stream library
 * @author Sree Harsha Totakura
 */


#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_lockmanager_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet_stream_lib.h"
#include "stream_protocol.h"

/**
 * Generic logging shorthand
 */
#define LOG(kind,...)                                   \
  GNUNET_log_from (kind, "stream-api", __VA_ARGS__)

/**
 * Debug logging shorthand
 */
#define LOG_DEBUG(...)                          \
  LOG (GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__)

/**
 * Time in relative seconds shorthand
 */
#define TIME_REL_SECS(sec) \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, sec)

/**
 * The maximum packet size of a stream packet
 */
#define DEFAULT_MAX_PAYLOAD_SIZE 64000

/**
 * Receive buffer
 */
#define RECEIVE_BUFFER_SIZE 4096000

/**
 * states in the Protocol
 */
enum State
  {
    /**
     * Client initialization state
     */
    STATE_INIT,

    /**
     * Listener initialization state 
     */
    STATE_LISTEN,

    /**
     * Pre-connection establishment state
     */
    STATE_HELLO_WAIT,

    /**
     * State where a connection has been established
     */
    STATE_ESTABLISHED,

    /**
     * State where the socket is closed on our side and waiting to be ACK'ed
     */
    STATE_RECEIVE_CLOSE_WAIT,

    /**
     * State where the socket is closed for reading
     */
    STATE_RECEIVE_CLOSED,

    /**
     * State where the socket is closed on our side and waiting to be ACK'ed
     */
    STATE_TRANSMIT_CLOSE_WAIT,

    /**
     * State where the socket is closed for writing
     */
    STATE_TRANSMIT_CLOSED,

    /**
     * State where the socket is closed on our side and waiting to be ACK'ed
     */
    STATE_CLOSE_WAIT,

    /**
     * State where the socket is closed
     */
    STATE_CLOSED 
  };


/**
 * Functions of this type are called when a message is written
 *
 * @param cls the closure from queue_message
 * @param socket the socket the written message was bound to
 */
typedef void (*SendFinishCallback) (void *cls,
                                    struct GNUNET_STREAM_Socket *socket);


/**
 * The send message queue
 */
struct MessageQueue
{
  /**
   * The message
   */
  struct GNUNET_STREAM_MessageHeader *message;

  /**
   * Callback to be called when the message is sent
   */
  SendFinishCallback finish_cb;

  /**
   * The closure for finish_cb
   */
  void *finish_cb_cls;

  /**
   * The next message in queue. Should be NULL in the last message
   */
  struct MessageQueue *next;

  /**
   * The next message in queue. Should be NULL in the first message
   */
  struct MessageQueue *prev;
};


/**
 * The STREAM Socket Handler
 */
struct GNUNET_STREAM_Socket
{
  /**
   * The mesh handle
   */
  struct GNUNET_MESH_Handle *mesh;

  /**
   * Handle to statistics
   */
  struct GNUNET_STATISTICS_Handle *stat_handle;

  /**
   * The mesh tunnel handle
   */
  struct GNUNET_MESH_Tunnel *tunnel;

  /**
   * Stream open closure
   */
  void *open_cls;

  /**
   * Stream open callback
   */
  GNUNET_STREAM_OpenCallback open_cb;

  /**
   * The current transmit handle (if a pending transmit request exists)
   */
  struct GNUNET_MESH_TransmitHandle *transmit_handle;

  /**
   * The current message associated with the transmit handle
   */
  struct MessageQueue *queue_head;

  /**
   * The queue tail, should always point to the last message in queue
   */
  struct MessageQueue *queue_tail;

  /**
   * The write IO_handle associated with this socket
   */
  struct GNUNET_STREAM_IOWriteHandle *write_handle;

  /**
   * The read IO_handle associated with this socket
   */
  struct GNUNET_STREAM_IOReadHandle *read_handle;

  /**
   * The shutdown handle associated with this socket
   */
  struct GNUNET_STREAM_ShutdownHandle *shutdown_handle;

  /**
   * Buffer for storing received messages
   */
  void *receive_buffer;

  /**
   * The listen socket from which this socket is derived. Should be NULL if it
   * is not a derived socket
   */
  struct GNUNET_STREAM_ListenSocket *lsocket;

  /**
   * The peer identity of the peer at the other end of the stream
   */
  struct GNUNET_PeerIdentity other_peer;

  /**
   * The Acknowledgement Bitmap
   */
  GNUNET_STREAM_AckBitmap ack_bitmap;

  /**
   * Task identifier for retransmission task after timeout
   */
  GNUNET_SCHEDULER_TaskIdentifier data_retransmission_task_id;

  /**
   * Task identifier for retransmission of control messages
   */
  GNUNET_SCHEDULER_TaskIdentifier control_retransmission_task_id;

  /**
   * The task for sending timely Acks
   */
  GNUNET_SCHEDULER_TaskIdentifier ack_task_id;

  /**
   * Retransmission timeout
   */
  struct GNUNET_TIME_Relative retransmit_timeout;

  /**
   * Time when the Acknowledgement was queued
   */
  struct GNUNET_TIME_Absolute ack_time_registered;

  /**
   * Queued Acknowledgement deadline
   */
  struct GNUNET_TIME_Relative ack_time_deadline;

  /**
   * The state of the protocol associated with this socket
   */
  enum State state;

  /**
   * The status of the socket
   */
  enum GNUNET_STREAM_Status status;

  /**
   * The number of previous timeouts; FIXME: currently not used
   */
  unsigned int retries;

  /**
   * Whether testing mode is active or not
   */
  int testing_active;

  /**
   * Is receive closed
   */
  int receive_closed;

  /**
   * Is transmission closed
   */
  int transmit_closed;

  /**
   * The application port number (type: uint32_t)
   */
  GNUNET_MESH_ApplicationType app_port;

  /**
   * The write sequence number to be set incase of testing
   */
  uint32_t testing_set_write_sequence_number_value;

  /**
   * Write sequence number. Set to random when sending HELLO(client) and
   * HELLO_ACK(server) 
   */
  uint32_t write_sequence_number;

  /**
   * Read sequence number. This number's value is determined during handshake
   */
  uint32_t read_sequence_number;

  /**
   * The receiver buffer size
   */
  uint32_t receive_buffer_size;

  /**
   * The receiver buffer boundaries
   */
  uint32_t receive_buffer_boundaries[GNUNET_STREAM_ACK_BITMAP_BIT_LENGTH];

  /**
   * receiver's available buffer after the last acknowledged packet
   */
  uint32_t receiver_window_available;

  /**
   * The offset pointer used during write operation
   */
  uint32_t write_offset;

  /**
   * The offset after which we are expecting data
   */
  uint32_t read_offset;

  /**
   * The offset upto which user has read from the received buffer
   */
  uint32_t copy_offset;

  /**
   * The maximum size of the data message payload this stream handle can send
   */
  uint16_t max_payload_size;
};


/**
 * A socket for listening
 */
struct GNUNET_STREAM_ListenSocket
{
  /**
   * The mesh handle
   */
  struct GNUNET_MESH_Handle *mesh;

  /**
   * Handle to statistics
   */
  struct GNUNET_STATISTICS_Handle *stat_handle;

  /**
   * Our configuration
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Handle to the lock manager service
   */
  struct GNUNET_LOCKMANAGER_Handle *lockmanager;

  /**
   * The active LockingRequest from lockmanager
   */
  struct GNUNET_LOCKMANAGER_LockingRequest *locking_request;

  /**
   * Callback to call after acquring a lock and listening
   */
  GNUNET_STREAM_ListenSuccessCallback listen_ok_cb;

  /**
   * The callback function which is called after successful opening socket
   */
  GNUNET_STREAM_ListenCallback listen_cb;

  /**
   * The call back closure
   */
  void *listen_cb_cls;

  /**
   * The service port
   */
  GNUNET_MESH_ApplicationType port;
  
  /**
   * The id of the lockmanager timeout task
   */
  GNUNET_SCHEDULER_TaskIdentifier lockmanager_acquire_timeout_task;

  /**
   * The retransmit timeout
   */
  struct GNUNET_TIME_Relative retransmit_timeout;
  
  /**
   * Listen enabled?
   */
  int listening;

  /**
   * Whether testing mode is active or not
   */
  int testing_active;

  /**
   * The write sequence number to be set incase of testing
   */
  uint32_t testing_set_write_sequence_number_value;

  /**
   * The maximum size of the data message payload this stream handle can send
   */
  uint16_t max_payload_size;

};


/**
 * The IO Write Handle
 */
struct GNUNET_STREAM_IOWriteHandle
{
  /**
   * The socket to which this write handle is associated
   */
  struct GNUNET_STREAM_Socket *socket;

  /**
   * The packet_buffers associated with this Handle
   */
  struct GNUNET_STREAM_DataMessage *messages[GNUNET_STREAM_ACK_BITMAP_BIT_LENGTH];

  /**
   * The write continuation callback
   */
  GNUNET_STREAM_CompletionContinuation write_cont;

  /**
   * Write continuation closure
   */
  void *write_cont_cls;

  /**
   * The bitmap of this IOHandle; Corresponding bit for a message is set when
   * it has been acknowledged by the receiver
   */
  GNUNET_STREAM_AckBitmap ack_bitmap;

  /**
   * Number of bytes in this write handle
   */
  size_t size;

  /**
   * Number of packets already transmitted from this IO handle. Retransmitted
   * packets are not taken into account here. This is used to determine which
   * packets account for retransmission and which packets occupy buffer space at
   * the receiver.
   */
  unsigned int packets_sent;
};


/**
 * The IO Read Handle
 */
struct GNUNET_STREAM_IOReadHandle
{
  /**
   * The socket to which this read handle is associated
   */
  struct GNUNET_STREAM_Socket *socket;
  
  /**
   * Callback for the read processor
   */
  GNUNET_STREAM_DataProcessor proc;

  /**
   * The closure pointer for the read processor callback
   */
  void *proc_cls;

  /**
   * Task identifier for the read io timeout task
   */
  GNUNET_SCHEDULER_TaskIdentifier read_io_timeout_task_id;

  /**
   * Task scheduled to continue a read operation.
   */
  GNUNET_SCHEDULER_TaskIdentifier read_task_id;
};


/**
 * Handle for Shutdown
 */
struct GNUNET_STREAM_ShutdownHandle
{
  /**
   * The socket associated with this shutdown handle
   */
  struct GNUNET_STREAM_Socket *socket;

  /**
   * Shutdown completion callback
   */
  GNUNET_STREAM_ShutdownCompletion completion_cb;

  /**
   * Closure for completion callback
   */
  void *completion_cls;

  /**
   * Close message retransmission task id
   */
  GNUNET_SCHEDULER_TaskIdentifier close_msg_retransmission_task_id;

  /**
   * Task scheduled to call the shutdown continuation callback
   */
  GNUNET_SCHEDULER_TaskIdentifier call_cont_task_id;

  /**
   * Which operation to shutdown? SHUT_RD, SHUT_WR or SHUT_RDWR
   */
  int operation;  
};


/**
 * Default value in seconds for various timeouts
 */
static const unsigned int default_timeout = 10;

/**
 * The domain name for locks we use here
 */
static const char *locking_domain = "GNUNET_STREAM_APPLOCK";


/**
 * Callback function for sending queued message
 *
 * @param cls closure the socket
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
send_message_notify (void *cls, size_t size, void *buf)
{
  struct GNUNET_STREAM_Socket *socket = cls;
  struct MessageQueue *head;
  size_t ret;

  socket->transmit_handle = NULL; /* Remove the transmit handle */
  head = socket->queue_head;
  if (NULL == head)
    return 0; /* just to be safe */
  if (0 == size)                /* request timed out */
  {
    socket->retries++;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%s: Message sending timed out. Retry %d \n",
         GNUNET_i2s (&socket->other_peer),
         socket->retries);
    socket->transmit_handle = 
      GNUNET_MESH_notify_transmit_ready (socket->tunnel,
                                         GNUNET_NO, /* Corking */
                                         /* FIXME: exponential backoff */
                                         socket->retransmit_timeout,
                                         &socket->other_peer,
                                         ntohs (head->message->header.size),
                                         &send_message_notify,
                                         socket);
    return 0;
  }
  ret = ntohs (head->message->header.size);
  GNUNET_assert (size >= ret);
  memcpy (buf, head->message, ret);
  if (NULL != head->finish_cb)
  {
    head->finish_cb (head->finish_cb_cls, socket);
  }
  GNUNET_CONTAINER_DLL_remove (socket->queue_head,
			       socket->queue_tail,
			       head);
  GNUNET_free (head->message);
  GNUNET_free (head);
  head = socket->queue_head;
  if (NULL != head)    /* more pending messages to send */
  {
    socket->retries = 0;
    socket->transmit_handle = 
      GNUNET_MESH_notify_transmit_ready (socket->tunnel,
                                         GNUNET_NO, /* Corking */
                                         /* FIXME: exponential backoff */
                                         socket->retransmit_timeout,
                                         &socket->other_peer,
                                         ntohs (head->message->header.size),
                                         &send_message_notify,
                                         socket);
  }
  return ret;
}


/**
 * Queues a message for sending using the mesh connection of a socket
 *
 * @param socket the socket whose mesh connection is used
 * @param message the message to be sent
 * @param finish_cb the callback to be called when the message is sent
 * @param finish_cb_cls the closure for the callback
 * @param urgent set to GNUNET_YES to add the message to the beginning of the
 *          queue; GNUNET_NO to add at the tail
 */
static void
queue_message (struct GNUNET_STREAM_Socket *socket,
               struct GNUNET_STREAM_MessageHeader *message,
               SendFinishCallback finish_cb,
               void *finish_cb_cls,
               int urgent)
{
  struct MessageQueue *queue_entity;

  GNUNET_assert 
    ((ntohs (message->header.type) >= GNUNET_MESSAGE_TYPE_STREAM_DATA)
     && (ntohs (message->header.type) <= GNUNET_MESSAGE_TYPE_STREAM_CLOSE_ACK));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%s: Queueing message of type %d and size %d\n",
       GNUNET_i2s (&socket->other_peer),
       ntohs (message->header.type),
       ntohs (message->header.size));
  GNUNET_assert (NULL != message);
  queue_entity = GNUNET_malloc (sizeof (struct MessageQueue));
  queue_entity->message = message;
  queue_entity->finish_cb = finish_cb;
  queue_entity->finish_cb_cls = finish_cb_cls;
  if (GNUNET_YES == urgent)
  {
    GNUNET_CONTAINER_DLL_insert (socket->queue_head, socket->queue_tail,
                                 queue_entity);
    if (NULL != socket->transmit_handle)
    {
      GNUNET_MESH_notify_transmit_ready_cancel (socket->transmit_handle);
      socket->transmit_handle = NULL;
    }
  }
  else
    GNUNET_CONTAINER_DLL_insert_tail (socket->queue_head,
                                      socket->queue_tail,
                                      queue_entity);
  if (NULL == socket->transmit_handle)
  {
    socket->retries = 0;
    socket->transmit_handle = 
	GNUNET_MESH_notify_transmit_ready (socket->tunnel,
					   GNUNET_NO, /* Corking */
					   socket->retransmit_timeout,
					   &socket->other_peer,
					   ntohs (message->header.size),
					   &send_message_notify,
					   socket);
  }
}


/**
 * Copies a message and queues it for sending using the mesh connection of
 * given socket 
 *
 * @param socket the socket whose mesh connection is used
 * @param message the message to be sent
 * @param finish_cb the callback to be called when the message is sent
 * @param finish_cb_cls the closure for the callback
 */
static void
copy_and_queue_message (struct GNUNET_STREAM_Socket *socket,
                        const struct GNUNET_STREAM_MessageHeader *message,
                        SendFinishCallback finish_cb,
                        void *finish_cb_cls)
{
  struct GNUNET_STREAM_MessageHeader *msg_copy;
  uint16_t size;
  
  size = ntohs (message->header.size);
  msg_copy = GNUNET_malloc (size);
  memcpy (msg_copy, message, size);
  queue_message (socket, msg_copy, finish_cb, finish_cb_cls, GNUNET_NO);
}


/**
 * Writes data using the given socket. The amount of data written is limited by
 * the receiver_window_size
 *
 * @param socket the socket to use
 */
static void 
write_data (struct GNUNET_STREAM_Socket *socket);


/**
 * Task for retransmitting data messages if they aren't ACK before their ack
 * deadline 
 *
 * @param cls the socket
 * @param tc the Task context
 */
static void
data_retransmission_task (void *cls,
                          const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_STREAM_Socket *socket = cls;
  
  socket->data_retransmission_task_id = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    return;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%s: Retransmitting DATA...\n", GNUNET_i2s (&socket->other_peer));
  write_data (socket);
}


/**
 * Task for sending ACK message
 *
 * @param cls the socket
 * @param tc the Task context
 */
static void
ack_task (void *cls,
          const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_STREAM_Socket *socket = cls;
  struct GNUNET_STREAM_AckMessage *ack_msg;

  socket->ack_task_id = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    return;
  /* Create the ACK Message */
  ack_msg = GNUNET_malloc (sizeof (struct GNUNET_STREAM_AckMessage));
  ack_msg->header.header.size = htons (sizeof (struct 
                                               GNUNET_STREAM_AckMessage));
  ack_msg->header.header.type = htons (GNUNET_MESSAGE_TYPE_STREAM_ACK);
  ack_msg->bitmap = GNUNET_htonll (socket->ack_bitmap);
  ack_msg->base_sequence_number = htonl (socket->read_sequence_number);
  ack_msg->receive_window_remaining = 
    htonl (RECEIVE_BUFFER_SIZE - socket->receive_buffer_size);
  /* Queue up ACK for immediate sending */
  queue_message (socket, &ack_msg->header, NULL, NULL, GNUNET_YES);
}


/**
 * Retransmission task for shutdown messages
 *
 * @param cls the shutdown handle
 * @param tc the Task Context
 */
static void
close_msg_retransmission_task (void *cls,
                               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_STREAM_ShutdownHandle *shutdown_handle = cls;
  struct GNUNET_STREAM_MessageHeader *msg;
  struct GNUNET_STREAM_Socket *socket;

  shutdown_handle->close_msg_retransmission_task_id = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_assert (NULL != shutdown_handle);
  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    return;
  socket = shutdown_handle->socket;
  msg = GNUNET_malloc (sizeof (struct GNUNET_STREAM_MessageHeader));
  msg->header.size = htons (sizeof (struct GNUNET_STREAM_MessageHeader));
  switch (shutdown_handle->operation)
  {
  case SHUT_RDWR:
    msg->header.type = htons (GNUNET_MESSAGE_TYPE_STREAM_CLOSE);
    break;
  case SHUT_RD:
    msg->header.type = htons (GNUNET_MESSAGE_TYPE_STREAM_RECEIVE_CLOSE);
    break;
  case SHUT_WR:
    msg->header.type = htons (GNUNET_MESSAGE_TYPE_STREAM_TRANSMIT_CLOSE);
    break;
  default:
    GNUNET_free (msg);
    shutdown_handle->close_msg_retransmission_task_id = 
      GNUNET_SCHEDULER_NO_TASK;
    return;
  }
  queue_message (socket, msg, NULL, NULL, GNUNET_NO);
  shutdown_handle->close_msg_retransmission_task_id =
    GNUNET_SCHEDULER_add_delayed (socket->retransmit_timeout,
                                  &close_msg_retransmission_task,
                                  shutdown_handle);
}


/**
 * Function to modify a bit in GNUNET_STREAM_AckBitmap
 *
 * @param bitmap the bitmap to modify
 * @param bit the bit number to modify
 * @param value GNUNET_YES to on, GNUNET_NO to off
 */
static void
ackbitmap_modify_bit (GNUNET_STREAM_AckBitmap *bitmap,
		      unsigned int bit, 
		      int value)
{
  GNUNET_assert (bit < GNUNET_STREAM_ACK_BITMAP_BIT_LENGTH);
  if (GNUNET_YES == value)
    *bitmap |= (1LL << bit);
  else
    *bitmap &= ~(1LL << bit);
}


/**
 * Function to check if a bit is set in the GNUNET_STREAM_AckBitmap
 *
 * @param bitmap address of the bitmap that has to be checked
 * @param bit the bit number to check
 * @return GNUNET_YES if the bit is set; GNUNET_NO if not
 */
static uint8_t
ackbitmap_is_bit_set (const GNUNET_STREAM_AckBitmap *bitmap,
                      unsigned int bit)
{
  GNUNET_assert (bit < GNUNET_STREAM_ACK_BITMAP_BIT_LENGTH);
  return 0 != (*bitmap & (1LL << bit));
}


/**
 * Writes data using the given socket. The amount of data written is limited by
 * the receiver_window_size
 *
 * @param socket the socket to use
 */
static void 
write_data (struct GNUNET_STREAM_Socket *socket)
{
  struct GNUNET_STREAM_IOWriteHandle *io_handle = socket->write_handle;
  unsigned int packet;
  
  for (packet=0; packet < io_handle->packets_sent; packet++)
  {
    if (GNUNET_NO == ackbitmap_is_bit_set (&io_handle->ack_bitmap,
					   packet))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
	   "%s: Retransmitting DATA message with sequence %u\n",
	   GNUNET_i2s (&socket->other_peer),
	   ntohl (io_handle->messages[packet]->sequence_number));
      copy_and_queue_message (socket,
			      &io_handle->messages[packet]->header,
			      NULL,
			      NULL);
    }
  }
  /* Now send new packets if there is enough buffer space */
  while ((packet < GNUNET_STREAM_ACK_BITMAP_BIT_LENGTH) &&
         (NULL != io_handle->messages[packet]) &&
         (socket->receiver_window_available 
          >= ntohs (io_handle->messages[packet]->header.header.size)))
  {
    socket->receiver_window_available -= 
      ntohs (io_handle->messages[packet]->header.header.size);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%s: Placing DATA message with sequence %u in send queue\n",
         GNUNET_i2s (&socket->other_peer),
         ntohl (io_handle->messages[packet]->sequence_number));
    copy_and_queue_message (socket,
                            &io_handle->messages[packet]->header,
                            NULL,
                            NULL);
    packet++;
  }
  io_handle->packets_sent = packet;
  // FIXME: 8s is not good, should use GNUNET_TIME_STD_BACKOFF...
  if (GNUNET_SCHEDULER_NO_TASK == socket->data_retransmission_task_id)
    socket->data_retransmission_task_id = 
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply 
                                    (GNUNET_TIME_UNIT_SECONDS, 8),
                                    &data_retransmission_task,
                                    socket);
}


/**
 * Task for calling the read processor
 *
 * @param cls the socket
 * @param tc the task context
 */
static void
call_read_processor (void *cls,
                     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_STREAM_Socket *socket = cls;
  struct GNUNET_STREAM_IOReadHandle *read_handle;
  size_t read_size;
  size_t valid_read_size;
  unsigned int packet;
  uint32_t sequence_increase;
  uint32_t offset_increase;

  read_handle = socket->read_handle;
  GNUNET_assert (NULL != read_handle);
  read_handle->read_task_id = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  if (NULL == socket->receive_buffer) 
    return;
  GNUNET_assert (NULL != socket->read_handle);
  GNUNET_assert (NULL != socket->read_handle->proc);
  /* Check the bitmap for any holes */
  for (packet=0; packet < GNUNET_STREAM_ACK_BITMAP_BIT_LENGTH; packet++)
  {
    if (GNUNET_NO == ackbitmap_is_bit_set (&socket->ack_bitmap,
                                           packet))
      break;
  }
  /* We only call read processor if we have the first packet */
  GNUNET_assert (0 < packet);
  valid_read_size = 
    socket->receive_buffer_boundaries[packet-1] - socket->copy_offset;
  GNUNET_assert (0 != valid_read_size);
  /* Cancel the read_io_timeout_task */
  GNUNET_SCHEDULER_cancel (read_handle->read_io_timeout_task_id);
  read_handle->read_io_timeout_task_id = GNUNET_SCHEDULER_NO_TASK;
  /* Call the data processor */
  LOG (GNUNET_ERROR_TYPE_DEBUG, "%s: Calling read processor\n",
       GNUNET_i2s (&socket->other_peer));
  read_size = 
      socket->read_handle->proc (socket->read_handle->proc_cls,
				 socket->status,
				 socket->receive_buffer + socket->copy_offset,
				 valid_read_size);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "%s: Read processor read %d bytes\n",
       GNUNET_i2s (&socket->other_peer), read_size);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "%s: Read processor completed successfully\n",
       GNUNET_i2s (&socket->other_peer));
  /* Free the read handle */
  GNUNET_free (socket->read_handle);
  socket->read_handle = NULL;
  GNUNET_assert (read_size <= valid_read_size);
  socket->copy_offset += read_size;
  /* Determine upto which packet we can remove from the buffer */
  for (packet = 0; packet < GNUNET_STREAM_ACK_BITMAP_BIT_LENGTH; packet++)
  {
    if (socket->copy_offset == socket->receive_buffer_boundaries[packet])
    { 
      packet++; 
      break;
    }
    if (socket->copy_offset < socket->receive_buffer_boundaries[packet])
      break;
  }
  /* If no packets can be removed we can't move the buffer */
  if (0 == packet) 
    return;
  sequence_increase = packet;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%s: Sequence increase after read processor completion: %u\n",
       GNUNET_i2s (&socket->other_peer), sequence_increase);
  /* Shift the data in the receive buffer */
  socket->receive_buffer = 
    memmove (socket->receive_buffer,
	     socket->receive_buffer 
	     + socket->receive_buffer_boundaries[sequence_increase-1],
	     socket->receive_buffer_size
	     - socket->receive_buffer_boundaries[sequence_increase-1]);
  /* Shift the bitmap */
  socket->ack_bitmap = socket->ack_bitmap >> sequence_increase;
  /* Set read_sequence_number */
  socket->read_sequence_number += sequence_increase;
  /* Set read_offset */
  offset_increase = socket->receive_buffer_boundaries[sequence_increase-1];
  socket->read_offset += offset_increase;
  /* Fix copy_offset */
  GNUNET_assert (offset_increase <= socket->copy_offset);
  socket->copy_offset -= offset_increase;
  /* Fix relative boundaries */
  for (packet=0; packet < GNUNET_STREAM_ACK_BITMAP_BIT_LENGTH; packet++)
  {
    if (packet < (GNUNET_STREAM_ACK_BITMAP_BIT_LENGTH - sequence_increase))
    {
      uint32_t ahead_buffer_boundary;

      ahead_buffer_boundary = 
	socket->receive_buffer_boundaries[packet + sequence_increase];
      if (0 == ahead_buffer_boundary)
	socket->receive_buffer_boundaries[packet] = 0;
      else
      {
	GNUNET_assert (offset_increase < ahead_buffer_boundary);
	socket->receive_buffer_boundaries[packet] = 
	  ahead_buffer_boundary - offset_increase;
      }
    }
    else
      socket->receive_buffer_boundaries[packet] = 0;
  }
}


/**
 * Cancels the existing read io handle
 *
 * @param cls the closure from the SCHEDULER call
 * @param tc the task context
 */
static void
read_io_timeout (void *cls,
                 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_STREAM_Socket *socket = cls;
  struct GNUNET_STREAM_IOReadHandle *read_handle;
  GNUNET_STREAM_DataProcessor proc;
  void *proc_cls;

  read_handle = socket->read_handle;
  GNUNET_assert (NULL != read_handle);
  read_handle->read_io_timeout_task_id = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    return;
  if (read_handle->read_task_id != GNUNET_SCHEDULER_NO_TASK)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%s: Read task timedout - Cancelling it\n",
         GNUNET_i2s (&socket->other_peer));
    GNUNET_SCHEDULER_cancel (read_handle->read_task_id);
    read_handle->read_task_id = GNUNET_SCHEDULER_NO_TASK;
  }
  proc = read_handle->proc;
  proc_cls = read_handle->proc_cls;
  GNUNET_free (read_handle);
  socket->read_handle = NULL;
  /* Call the read processor to signal timeout */
  proc (proc_cls,
        GNUNET_STREAM_TIMEOUT,
        NULL,
        0);
}


/**
 * Handler for DATA messages; Same for both client and server
 *
 * @param socket the socket through which the ack was received
 * @param tunnel connection to the other end
 * @param sender who sent the message
 * @param msg the data message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_data (struct GNUNET_STREAM_Socket *socket,
             struct GNUNET_MESH_Tunnel *tunnel,
             const struct GNUNET_PeerIdentity *sender,
             const struct GNUNET_STREAM_DataMessage *msg,
             const struct GNUNET_ATS_Information*atsi)
{
  const void *payload;
  struct GNUNET_TIME_Relative ack_deadline_rel;
  uint32_t bytes_needed;
  uint32_t relative_offset;
  uint32_t relative_sequence_number;
  uint16_t size;

  size = htons (msg->header.header.size);
  if (size < sizeof (struct GNUNET_STREAM_DataMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (0 != memcmp (sender, &socket->other_peer,
		   sizeof (struct GNUNET_PeerIdentity)))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "%s: Received DATA from non-confirming peer\n",
	 GNUNET_i2s (&socket->other_peer));
    return GNUNET_YES;
  }
  switch (socket->state)
  {
  case STATE_ESTABLISHED:
  case STATE_TRANSMIT_CLOSED:
  case STATE_TRANSMIT_CLOSE_WAIT:      
    /* check if the message's sequence number is in the range we are
       expecting */
    relative_sequence_number = 
      ntohl (msg->sequence_number) - socket->read_sequence_number;
    if ( relative_sequence_number >= GNUNET_STREAM_ACK_BITMAP_BIT_LENGTH)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "%s: Ignoring received message with sequence number %u\n",
           GNUNET_i2s (&socket->other_peer),
           ntohl (msg->sequence_number));
      /* Start ACK sending task if one is not already present */
      if (GNUNET_SCHEDULER_NO_TASK == socket->ack_task_id)
      {
        socket->ack_task_id = 
          GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_ntoh
                                        (msg->ack_deadline),
                                        &ack_task,
                                        socket);
      }
      return GNUNET_YES;
    }      
    /* Check if we have already seen this message */
    if (GNUNET_YES == ackbitmap_is_bit_set (&socket->ack_bitmap,
                                            relative_sequence_number))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "%s: Ignoring already received message with sequence number %u\n",
           GNUNET_i2s (&socket->other_peer),
           ntohl (msg->sequence_number));
      /* Start ACK sending task if one is not already present */
      if (GNUNET_SCHEDULER_NO_TASK == socket->ack_task_id)
      {
        socket->ack_task_id = 
          GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_ntoh
                                        (msg->ack_deadline), &ack_task, socket);
      }
      return GNUNET_YES;
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%s: Receiving DATA with sequence number: %u and size: %d from %s\n",
         GNUNET_i2s (&socket->other_peer), ntohl (msg->sequence_number),
         ntohs (msg->header.header.size), GNUNET_i2s (&socket->other_peer));
    /* Check if we have to allocate the buffer */
    size -= sizeof (struct GNUNET_STREAM_DataMessage);
    relative_offset = ntohl (msg->offset) - socket->read_offset;
    bytes_needed = relative_offset + size;
    if (bytes_needed > socket->receive_buffer_size)
    {
      if (bytes_needed <= RECEIVE_BUFFER_SIZE)
      {
        socket->receive_buffer = GNUNET_realloc (socket->receive_buffer,
                                                 bytes_needed);
        socket->receive_buffer_size = bytes_needed;
      }
      else
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "%s: Cannot accommodate packet %d as buffer is full\n",
             GNUNET_i2s (&socket->other_peer), ntohl (msg->sequence_number));
        return GNUNET_YES;
      }
    }
    /* Copy Data to buffer */
    payload = &msg[1];
    GNUNET_assert (relative_offset + size <= socket->receive_buffer_size);
    memcpy (socket->receive_buffer + relative_offset, payload, size);
    socket->receive_buffer_boundaries[relative_sequence_number] = 
	relative_offset + size;
    /* Modify the ACK bitmap */
    ackbitmap_modify_bit (&socket->ack_bitmap, relative_sequence_number,
			  GNUNET_YES);
    /* Start ACK sending task if one is not already present */
    ack_deadline_rel = GNUNET_TIME_relative_ntoh (msg->ack_deadline);
    if (GNUNET_SCHEDULER_NO_TASK == socket->ack_task_id)
    {
      ack_deadline_rel = 
	  GNUNET_TIME_relative_min (ack_deadline_rel,
				    GNUNET_TIME_relative_multiply
				    (GNUNET_TIME_UNIT_SECONDS, 300));
      socket->ack_task_id = 
	  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_ntoh 
					(msg->ack_deadline), &ack_task, socket);
      socket->ack_time_registered = GNUNET_TIME_absolute_get ();
      socket->ack_time_deadline = ack_deadline_rel;
    }
    else
    {
      struct GNUNET_TIME_Relative ack_time_past;
      struct GNUNET_TIME_Relative ack_time_remaining;
      struct GNUNET_TIME_Relative ack_time_min;
      ack_time_past = 
	  GNUNET_TIME_absolute_get_duration (socket->ack_time_registered);
      ack_time_remaining = GNUNET_TIME_relative_subtract
	  (socket->ack_time_deadline, ack_time_past);
      ack_time_min = GNUNET_TIME_relative_min (ack_time_remaining,
					       ack_deadline_rel);
      if (0 == memcmp(&ack_deadline_rel, &ack_time_min,
		      sizeof (struct GNUNET_TIME_Relative)))
      {
	ack_deadline_rel = ack_time_min;
	GNUNET_SCHEDULER_cancel (socket->ack_task_id);
	socket->ack_task_id = GNUNET_SCHEDULER_add_delayed (ack_deadline_rel,
							    &ack_task, socket);
	socket->ack_time_registered = GNUNET_TIME_absolute_get ();
	socket->ack_time_deadline = ack_deadline_rel;
      }
    }
    if ((NULL != socket->read_handle) /* A read handle is waiting */
        /* There is no current read task */
        && (GNUNET_SCHEDULER_NO_TASK == socket->read_handle->read_task_id)
        /* We have the first packet */
        && (GNUNET_YES == ackbitmap_is_bit_set(&socket->ack_bitmap, 0)))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "%s: Scheduling read processor\n",
	   GNUNET_i2s (&socket->other_peer));
      socket->read_handle->read_task_id =
	  GNUNET_SCHEDULER_add_now (&call_read_processor, socket);
    }
    break;
  default:
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%s: Received data message when it cannot be handled\n",
         GNUNET_i2s (&socket->other_peer));
    break;
  }
  return GNUNET_YES;
}


/**
 * Client's message Handler for GNUNET_MESSAGE_TYPE_STREAM_DATA
 *
 * @param cls the socket (set from GNUNET_MESH_connect)
 * @param tunnel connection to the other end
 * @param tunnel_ctx place to store local state associated with the tunnel
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
client_handle_data (void *cls,
                    struct GNUNET_MESH_Tunnel *tunnel,
                    void **tunnel_ctx,
                    const struct GNUNET_PeerIdentity *sender,
                    const struct GNUNET_MessageHeader *message,
                    const struct GNUNET_ATS_Information*atsi)
{
  struct GNUNET_STREAM_Socket *socket = cls;

  return handle_data (socket, tunnel, sender, 
                      (const struct GNUNET_STREAM_DataMessage *) message, atsi);
}


/**
 * Callback to set state to ESTABLISHED
 *
 * @param cls the closure NULL;
 * @param socket the socket to requiring state change
 */
static void
set_state_established (void *cls,
                       struct GNUNET_STREAM_Socket *socket)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, 
       "%s: Attaining ESTABLISHED state\n",
       GNUNET_i2s (&socket->other_peer));
  socket->write_offset = 0;
  socket->read_offset = 0;
  socket->state = STATE_ESTABLISHED;
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK !=
                 socket->control_retransmission_task_id);
  GNUNET_SCHEDULER_cancel (socket->control_retransmission_task_id);
  socket->control_retransmission_task_id = GNUNET_SCHEDULER_NO_TASK;
  if (NULL != socket->lsocket)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%s: Calling listen callback\n",
         GNUNET_i2s (&socket->other_peer));
    if (GNUNET_SYSERR == 
        socket->lsocket->listen_cb (socket->lsocket->listen_cb_cls,
                                    socket,
                                    &socket->other_peer))
    {
      socket->state = STATE_CLOSED;
      /* FIXME: We should close in a decent way (send RST) */
      GNUNET_MESH_tunnel_destroy (socket->tunnel); /* Destroy the tunnel */
      GNUNET_free (socket);
    }
  }
  else
    socket->open_cb (socket->open_cls, socket);
}


/**
 * Callback to set state to HELLO_WAIT
 *
 * @param cls the closure from queue_message
 * @param socket the socket to requiring state change
 */
static void
set_state_hello_wait (void *cls,
                      struct GNUNET_STREAM_Socket *socket)
{
  GNUNET_assert (STATE_INIT == socket->state);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%s: Attaining HELLO_WAIT state\n",
       GNUNET_i2s (&socket->other_peer));
  socket->state = STATE_HELLO_WAIT;
}


/**
 * Callback to set state to CLOSE_WAIT
 *
 * @param cls the closure from queue_message
 * @param socket the socket requiring state change
 */
static void
set_state_close_wait (void *cls,
                      struct GNUNET_STREAM_Socket *socket)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%s: Attaing CLOSE_WAIT state\n",
       GNUNET_i2s (&socket->other_peer));
  socket->state = STATE_CLOSE_WAIT;
  GNUNET_free_non_null (socket->receive_buffer); /* Free the receive buffer */
  socket->receive_buffer = NULL;
  socket->receive_buffer_size = 0;
}


/**
 * Callback to set state to RECEIVE_CLOSE_WAIT
 *
 * @param cls the closure from queue_message
 * @param socket the socket requiring state change
 */
static void
set_state_receive_close_wait (void *cls,
                              struct GNUNET_STREAM_Socket *socket)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%s: Attaing RECEIVE_CLOSE_WAIT state\n",
       GNUNET_i2s (&socket->other_peer));
  socket->state = STATE_RECEIVE_CLOSE_WAIT;
  GNUNET_free_non_null (socket->receive_buffer); /* Free the receive buffer */
  socket->receive_buffer = NULL;
  socket->receive_buffer_size = 0;
}


/**
 * Callback to set state to TRANSMIT_CLOSE_WAIT
 *
 * @param cls the closure from queue_message
 * @param socket the socket requiring state change
 */
static void
set_state_transmit_close_wait (void *cls,
                               struct GNUNET_STREAM_Socket *socket)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%s: Attaing TRANSMIT_CLOSE_WAIT state\n",
       GNUNET_i2s (&socket->other_peer));
  socket->state = STATE_TRANSMIT_CLOSE_WAIT;
}


/**
 * Callback to set state to CLOSED
 *
 * @param cls the closure from queue_message
 * @param socket the socket requiring state change
 */
static void
set_state_closed (void *cls,
                  struct GNUNET_STREAM_Socket *socket)
{
  socket->state = STATE_CLOSED;
}


/**
 * Returns GNUNET_MESSAGE_TYPE_STREAM_HELLO
 *
 * @return the generate hello message
 */
static struct GNUNET_STREAM_MessageHeader *
generate_hello (void)
{
  struct GNUNET_STREAM_MessageHeader *msg;

  msg = GNUNET_malloc (sizeof (struct GNUNET_STREAM_MessageHeader));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_STREAM_HELLO);
  msg->header.size = htons (sizeof (struct GNUNET_STREAM_MessageHeader));
  return msg;
}


/**
 * Returns a new HelloAckMessage. Also sets the write sequence number for the
 * socket
 *
 * @param socket the socket for which this HelloAckMessage has to be generated
 * @param generate_seq GNUNET_YES to generate the write sequence number,
 *          GNUNET_NO to use the existing sequence number
 * @return the HelloAckMessage
 */
static struct GNUNET_STREAM_HelloAckMessage *
generate_hello_ack (struct GNUNET_STREAM_Socket *socket,
                    int generate_seq)
{
  struct GNUNET_STREAM_HelloAckMessage *msg;

  if (GNUNET_YES == generate_seq)
  {
    if (GNUNET_YES == socket->testing_active)
      socket->write_sequence_number =
        socket->testing_set_write_sequence_number_value;
    else
      socket->write_sequence_number = 
        GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE, UINT32_MAX);
    LOG_DEBUG ("%s: write sequence number %u\n",
               GNUNET_i2s (&socket->other_peer),
               (unsigned int) socket->write_sequence_number);
  }
  msg = GNUNET_malloc (sizeof (struct GNUNET_STREAM_HelloAckMessage));
  msg->header.header.size = 
    htons (sizeof (struct GNUNET_STREAM_HelloAckMessage));
  msg->header.header.type = htons (GNUNET_MESSAGE_TYPE_STREAM_HELLO_ACK);
  msg->sequence_number = htonl (socket->write_sequence_number);
  msg->receiver_window_size = htonl (RECEIVE_BUFFER_SIZE);
  return msg;
}


/**
 * Task for retransmitting control messages if they aren't ACK'ed before a
 * deadline
 *
 * @param cls the socket
 * @param tc the Task context
 */
static void
control_retransmission_task (void *cls,
                             const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_STREAM_Socket *socket = cls;
    
  socket->control_retransmission_task_id = GNUNET_SCHEDULER_NO_TASK;
  if (GNUNET_SCHEDULER_REASON_SHUTDOWN == tc->reason)
    return;
  LOG_DEBUG ("%s: Retransmitting a control message\n",
                 GNUNET_i2s (&socket->other_peer));
  switch (socket->state)
  {
  case STATE_INIT:    
    GNUNET_break (0);
    break;
  case STATE_LISTEN:
    GNUNET_break (0);
    break;
  case STATE_HELLO_WAIT:
    if (NULL == socket->lsocket) /* We are client */
      queue_message (socket, generate_hello (), NULL, NULL, GNUNET_NO);
    else
      queue_message (socket,
                     (struct GNUNET_STREAM_MessageHeader *)
                     generate_hello_ack (socket, GNUNET_NO), NULL, NULL,
                     GNUNET_NO);
    socket->control_retransmission_task_id =
    GNUNET_SCHEDULER_add_delayed (socket->retransmit_timeout,
                                  &control_retransmission_task, socket);
    break;
  case STATE_ESTABLISHED:
    if (NULL == socket->lsocket)
      queue_message (socket,
                     (struct GNUNET_STREAM_MessageHeader *)
                     generate_hello_ack (socket, GNUNET_NO), NULL, NULL,
                     GNUNET_NO);
    else
      GNUNET_break (0);
    break;
  default:
    GNUNET_break (0);
  }  
}


/**
 * Client's message handler for GNUNET_MESSAGE_TYPE_STREAM_HELLO_ACK
 *
 * @param cls the socket (set from GNUNET_MESH_connect)
 * @param tunnel connection to the other end
 * @param tunnel_ctx this is NULL
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
client_handle_hello_ack (void *cls,
                         struct GNUNET_MESH_Tunnel *tunnel,
                         void **tunnel_ctx,
                         const struct GNUNET_PeerIdentity *sender,
                         const struct GNUNET_MessageHeader *message,
                         const struct GNUNET_ATS_Information*atsi)
{
  struct GNUNET_STREAM_Socket *socket = cls;
  const struct GNUNET_STREAM_HelloAckMessage *ack_msg;
  struct GNUNET_STREAM_HelloAckMessage *reply;

  if (0 != memcmp (sender, &socket->other_peer,
		   sizeof (struct GNUNET_PeerIdentity)))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%s: Received HELLO_ACK from non-confirming peer\n",
         GNUNET_i2s (&socket->other_peer));
    return GNUNET_YES;
  }
  ack_msg = (const struct GNUNET_STREAM_HelloAckMessage *) message;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "%s: Received HELLO_ACK from %s\n",
       GNUNET_i2s (&socket->other_peer), GNUNET_i2s (&socket->other_peer));
  GNUNET_assert (socket->tunnel == tunnel);
  switch (socket->state)
  {
  case STATE_HELLO_WAIT:
    socket->read_sequence_number = ntohl (ack_msg->sequence_number);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%s: Read sequence number %u\n",
         GNUNET_i2s (&socket->other_peer),
         (unsigned int) socket->read_sequence_number);
    socket->receiver_window_available = ntohl (ack_msg->receiver_window_size);
    reply = generate_hello_ack (socket, GNUNET_YES);
    queue_message (socket, &reply->header, &set_state_established,
                   NULL, GNUNET_NO);    
    return GNUNET_OK;
  case STATE_ESTABLISHED:
    // call statistics (# ACKs ignored++)
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK ==
                   socket->control_retransmission_task_id);
    socket->control_retransmission_task_id =
      GNUNET_SCHEDULER_add_now (&control_retransmission_task, socket);
    return GNUNET_OK;
  default:
    LOG_DEBUG ("%s: Server %s sent HELLO_ACK when in state %d\n", 
               GNUNET_i2s (&socket->other_peer),
	       GNUNET_i2s (&socket->other_peer), socket->state);
    socket->state = STATE_CLOSED; // introduce STATE_ERROR?
    return GNUNET_SYSERR;
  }
}


/**
 * Client's message handler for GNUNET_MESSAGE_TYPE_STREAM_RESET
 *
 * @param cls the socket (set from GNUNET_MESH_connect)
 * @param tunnel connection to the other end
 * @param tunnel_ctx this is NULL
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
client_handle_reset (void *cls,
                     struct GNUNET_MESH_Tunnel *tunnel,
                     void **tunnel_ctx,
                     const struct GNUNET_PeerIdentity *sender,
                     const struct GNUNET_MessageHeader *message,
                     const struct GNUNET_ATS_Information*atsi)
{
  // struct GNUNET_STREAM_Socket *socket = cls;

  return GNUNET_OK;
}


/**
 * Common message handler for handling TRANSMIT_CLOSE messages
 *
 * @param socket the socket through which the ack was received
 * @param tunnel connection to the other end
 * @param sender who sent the message
 * @param msg the transmit close message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_transmit_close (struct GNUNET_STREAM_Socket *socket,
                       struct GNUNET_MESH_Tunnel *tunnel,
                       const struct GNUNET_PeerIdentity *sender,
                       const struct GNUNET_STREAM_MessageHeader *msg,
                       const struct GNUNET_ATS_Information*atsi)
{
  struct GNUNET_STREAM_MessageHeader *reply;

  switch (socket->state)
  {
  case STATE_ESTABLISHED:
    socket->state = STATE_RECEIVE_CLOSED;
    /* Send TRANSMIT_CLOSE_ACK */
    reply = GNUNET_malloc (sizeof (struct GNUNET_STREAM_MessageHeader));
    reply->header.type = 
      htons (GNUNET_MESSAGE_TYPE_STREAM_TRANSMIT_CLOSE_ACK);
    reply->header.size = htons (sizeof (struct GNUNET_STREAM_MessageHeader));
    queue_message (socket, reply, NULL, NULL, GNUNET_NO);
    break;
  default:
    /* FIXME: Call statistics? */
    break;
  }
  return GNUNET_YES;
}


/**
 * Client's message handler for GNUNET_MESSAGE_TYPE_STREAM_TRANSMIT_CLOSE
 *
 * @param cls the socket (set from GNUNET_MESH_connect)
 * @param tunnel connection to the other end
 * @param tunnel_ctx this is NULL
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
client_handle_transmit_close (void *cls,
                              struct GNUNET_MESH_Tunnel *tunnel,
                              void **tunnel_ctx,
                              const struct GNUNET_PeerIdentity *sender,
                              const struct GNUNET_MessageHeader *message,
                              const struct GNUNET_ATS_Information*atsi)
{
  struct GNUNET_STREAM_Socket *socket = cls;
  
  return handle_transmit_close (socket,
                                tunnel,
                                sender,
                                (struct GNUNET_STREAM_MessageHeader *)message,
                                atsi);
}


/**
 * Task for calling the shutdown continuation callback
 *
 * @param cls the socket
 * @param tc the scheduler task context
 */
static void
call_cont_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_STREAM_Socket *socket = cls;
  
  GNUNET_assert (NULL != socket->shutdown_handle);
  socket->shutdown_handle->call_cont_task_id = GNUNET_SCHEDULER_NO_TASK;
  if (NULL != socket->shutdown_handle->completion_cb)
    socket->shutdown_handle->completion_cb
        (socket->shutdown_handle->completion_cls,
         socket->shutdown_handle->operation);
  GNUNET_free (socket->shutdown_handle);
  socket->shutdown_handle = NULL;
}


/**
 * Generic handler for GNUNET_MESSAGE_TYPE_STREAM_*_CLOSE_ACK messages
 *
 * @param socket the socket
 * @param tunnel connection to the other end
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @param operation the close operation which is being ACK'ed
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_generic_close_ack (struct GNUNET_STREAM_Socket *socket,
                          struct GNUNET_MESH_Tunnel *tunnel,
                          const struct GNUNET_PeerIdentity *sender,
                          const struct GNUNET_STREAM_MessageHeader *message,
                          const struct GNUNET_ATS_Information *atsi,
                          int operation)
{
  struct GNUNET_STREAM_ShutdownHandle *shutdown_handle;

  shutdown_handle = socket->shutdown_handle;
  if (NULL == shutdown_handle)
  {
    /* This happens when the shudown handle is cancelled */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%s: Received CLOSE_ACK when shutdown handle is NULL\n",
         GNUNET_i2s (&socket->other_peer));
    return GNUNET_OK;
  }
  switch (operation)
  {
  case SHUT_RDWR:
    switch (socket->state)
    {
    case STATE_CLOSE_WAIT:
      if (SHUT_RDWR != shutdown_handle->operation)
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "%s: Received CLOSE_ACK when shutdown handle is not for "
             "SHUT_RDWR\n", GNUNET_i2s (&socket->other_peer));
        return GNUNET_OK;
      }
      LOG (GNUNET_ERROR_TYPE_DEBUG, "%s: Received CLOSE_ACK from %s\n",
           GNUNET_i2s (&socket->other_peer), GNUNET_i2s (&socket->other_peer));
      socket->state = STATE_CLOSED;
      break;
    default:
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "%s: Received CLOSE_ACK when in it not expected\n",
           GNUNET_i2s (&socket->other_peer));
      return GNUNET_OK;
    }
    break;
  case SHUT_RD:
    switch (socket->state)
    {
    case STATE_RECEIVE_CLOSE_WAIT:
      if (SHUT_RD != shutdown_handle->operation)
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "%s: Received RECEIVE_CLOSE_ACK when shutdown handle "
             "is not for SHUT_RD\n", GNUNET_i2s (&socket->other_peer));
        return GNUNET_OK;
      }
      LOG (GNUNET_ERROR_TYPE_DEBUG, "%s: Received RECEIVE_CLOSE_ACK from %s\n",
           GNUNET_i2s (&socket->other_peer), GNUNET_i2s (&socket->other_peer));
      socket->state = STATE_RECEIVE_CLOSED;
      break;
    default:
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "%s: Received RECEIVE_CLOSE_ACK when in it not expected\n",
           GNUNET_i2s (&socket->other_peer));
      return GNUNET_OK;
    }
    break;
  case SHUT_WR:
    switch (socket->state)
    {
    case STATE_TRANSMIT_CLOSE_WAIT:
      if (SHUT_WR != shutdown_handle->operation)
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "%s: Received TRANSMIT_CLOSE_ACK when shutdown handle "
             "is not for SHUT_WR\n",
             GNUNET_i2s (&socket->other_peer));
        return GNUNET_OK;
      }
      LOG (GNUNET_ERROR_TYPE_DEBUG, "%s: Received TRANSMIT_CLOSE_ACK from %s\n",
           GNUNET_i2s (&socket->other_peer), GNUNET_i2s (&socket->other_peer));
      socket->state = STATE_TRANSMIT_CLOSED;
      break;
    default:
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "%s: Received TRANSMIT_CLOSE_ACK when in it not expected\n",
           GNUNET_i2s (&socket->other_peer));          
      return GNUNET_OK;
    }
    break;
  default:
    GNUNET_assert (0);
  }
  shutdown_handle->call_cont_task_id = GNUNET_SCHEDULER_add_now
      (&call_cont_task, socket);
  if (GNUNET_SCHEDULER_NO_TASK
      != shutdown_handle->close_msg_retransmission_task_id)
  {
    GNUNET_SCHEDULER_cancel
      (shutdown_handle->close_msg_retransmission_task_id);
    shutdown_handle->close_msg_retransmission_task_id =
	GNUNET_SCHEDULER_NO_TASK;
  }
  return GNUNET_OK;
}


/**
 * Client's message handler for GNUNET_MESSAGE_TYPE_STREAM_TRANSMIT_CLOSE_ACK
 *
 * @param cls the socket (set from GNUNET_MESH_connect)
 * @param tunnel connection to the other end
 * @param tunnel_ctx this is NULL
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
client_handle_transmit_close_ack (void *cls,
                                  struct GNUNET_MESH_Tunnel *tunnel,
                                  void **tunnel_ctx,
                                  const struct GNUNET_PeerIdentity *sender,
                                  const struct GNUNET_MessageHeader *message,
                                  const struct GNUNET_ATS_Information*atsi)
{
  struct GNUNET_STREAM_Socket *socket = cls;

  return handle_generic_close_ack (socket,
                                   tunnel,
                                   sender,
                                   (const struct GNUNET_STREAM_MessageHeader *)
                                   message,
                                   atsi,
                                   SHUT_WR);
}


/**
 * Generic handler for GNUNET_MESSAGE_TYPE_STREAM_RECEIVE_CLOSE
 *
 * @param socket the socket
 * @param tunnel connection to the other end
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_receive_close (struct GNUNET_STREAM_Socket *socket,
                      struct GNUNET_MESH_Tunnel *tunnel,
                      const struct GNUNET_PeerIdentity *sender,
                      const struct GNUNET_STREAM_MessageHeader *message,
                      const struct GNUNET_ATS_Information *atsi)
{
  struct GNUNET_STREAM_MessageHeader *receive_close_ack;

  switch (socket->state)
  {
  case STATE_INIT:
  case STATE_LISTEN:
  case STATE_HELLO_WAIT:
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%s: Ignoring RECEIVE_CLOSE as it cannot be handled now\n",
         GNUNET_i2s (&socket->other_peer));
    return GNUNET_OK;
  default:
    break;
  }
  
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%s: Received RECEIVE_CLOSE from %s\n",
       GNUNET_i2s (&socket->other_peer),
       GNUNET_i2s (&socket->other_peer));
  receive_close_ack =
    GNUNET_malloc (sizeof (struct GNUNET_STREAM_MessageHeader));
  receive_close_ack->header.size =
    htons (sizeof (struct GNUNET_STREAM_MessageHeader));
  receive_close_ack->header.type =
    htons (GNUNET_MESSAGE_TYPE_STREAM_RECEIVE_CLOSE_ACK);
  queue_message (socket, receive_close_ack, &set_state_closed,
                 NULL, GNUNET_NO);  
  /* FIXME: Handle the case where write handle is present; the write operation
     should be deemed as finised and the write continuation callback
     has to be called with the stream status GNUNET_STREAM_SHUTDOWN */
  return GNUNET_OK;
}


/**
 * Client's message handler for GNUNET_MESSAGE_TYPE_STREAM_RECEIVE_CLOSE
 *
 * @param cls the socket (set from GNUNET_MESH_connect)
 * @param tunnel connection to the other end
 * @param tunnel_ctx this is NULL
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
client_handle_receive_close (void *cls,
                             struct GNUNET_MESH_Tunnel *tunnel,
                             void **tunnel_ctx,
                             const struct GNUNET_PeerIdentity *sender,
                             const struct GNUNET_MessageHeader *message,
                             const struct GNUNET_ATS_Information*atsi)
{
  struct GNUNET_STREAM_Socket *socket = cls;

  return
    handle_receive_close (socket,
                          tunnel,
                          sender,
                          (const struct GNUNET_STREAM_MessageHeader *) message,
                          atsi);
}


/**
 * Client's message handler for GNUNET_MESSAGE_TYPE_STREAM_RECEIVE_CLOSE_ACK
 *
 * @param cls the socket (set from GNUNET_MESH_connect)
 * @param tunnel connection to the other end
 * @param tunnel_ctx this is NULL
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
client_handle_receive_close_ack (void *cls,
                                 struct GNUNET_MESH_Tunnel *tunnel,
                                 void **tunnel_ctx,
                                 const struct GNUNET_PeerIdentity *sender,
                                 const struct GNUNET_MessageHeader *message,
                                 const struct GNUNET_ATS_Information*atsi)
{
  struct GNUNET_STREAM_Socket *socket = cls;

  return handle_generic_close_ack (socket,
                                   tunnel,
                                   sender,
                                   (const struct GNUNET_STREAM_MessageHeader *)
                                   message,
                                   atsi,
                                   SHUT_RD);
}


/**
 * Generic handler for GNUNET_MESSAGE_TYPE_STREAM_CLOSE
 *
 * @param socket the socket
 * @param tunnel connection to the other end
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_close (struct GNUNET_STREAM_Socket *socket,
              struct GNUNET_MESH_Tunnel *tunnel,
              const struct GNUNET_PeerIdentity *sender,
              const struct GNUNET_STREAM_MessageHeader *message,
              const struct GNUNET_ATS_Information*atsi)
{
  struct GNUNET_STREAM_MessageHeader *close_ack;

  switch (socket->state)
  {
  case STATE_INIT:
  case STATE_LISTEN:
  case STATE_HELLO_WAIT:
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%s: Ignoring RECEIVE_CLOSE as it cannot be handled now\n",
         GNUNET_i2s (&socket->other_peer));
    return GNUNET_OK;
  default:
    break;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%s: Received CLOSE from %s\n",
       GNUNET_i2s (&socket->other_peer),
       GNUNET_i2s (&socket->other_peer));
  close_ack = GNUNET_malloc (sizeof (struct GNUNET_STREAM_MessageHeader));
  close_ack->header.size = htons (sizeof (struct GNUNET_STREAM_MessageHeader));
  close_ack->header.type = htons (GNUNET_MESSAGE_TYPE_STREAM_CLOSE_ACK);
  queue_message (socket, close_ack, &set_state_closed, NULL, GNUNET_NO);
  if (STATE_CLOSED == socket->state)
    return GNUNET_OK;
  socket->receive_closed = GNUNET_YES;
  socket->transmit_closed = GNUNET_YES;
  GNUNET_free_non_null (socket->receive_buffer); /* Free the receive buffer */
  socket->receive_buffer = NULL;
  socket->receive_buffer_size = 0;
  return GNUNET_OK;
}


/**
 * Client's message handler for GNUNET_MESSAGE_TYPE_STREAM_CLOSE
 *
 * @param cls the socket (set from GNUNET_MESH_connect)
 * @param tunnel connection to the other end
 * @param tunnel_ctx this is NULL
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
client_handle_close (void *cls,
                     struct GNUNET_MESH_Tunnel *tunnel,
                     void **tunnel_ctx,
                     const struct GNUNET_PeerIdentity *sender,
                     const struct GNUNET_MessageHeader *message,
                     const struct GNUNET_ATS_Information*atsi)
{
  struct GNUNET_STREAM_Socket *socket = cls;

  return handle_close (socket,
                       tunnel,
                       sender,
                       (const struct GNUNET_STREAM_MessageHeader *) message,
                       atsi);
}


/**
 * Client's message handler for GNUNET_MESSAGE_TYPE_STREAM_CLOSE_ACK
 *
 * @param cls the socket (set from GNUNET_MESH_connect)
 * @param tunnel connection to the other end
 * @param tunnel_ctx this is NULL
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
client_handle_close_ack (void *cls,
                         struct GNUNET_MESH_Tunnel *tunnel,
                         void **tunnel_ctx,
                         const struct GNUNET_PeerIdentity *sender,
                         const struct GNUNET_MessageHeader *message,
                         const struct GNUNET_ATS_Information *atsi)
{
  struct GNUNET_STREAM_Socket *socket = cls;

  return handle_generic_close_ack (socket,
                                   tunnel,
                                   sender,
                                   (const struct GNUNET_STREAM_MessageHeader *) 
                                   message,
                                   atsi,
                                   SHUT_RDWR);
}

/*****************************/
/* Server's Message Handlers */
/*****************************/

/**
 * Server's message Handler for GNUNET_MESSAGE_TYPE_STREAM_DATA
 *
 * @param cls the closure
 * @param tunnel connection to the other end
 * @param tunnel_ctx the socket
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
server_handle_data (void *cls,
                    struct GNUNET_MESH_Tunnel *tunnel,
                    void **tunnel_ctx,
                    const struct GNUNET_PeerIdentity *sender,
                    const struct GNUNET_MessageHeader *message,
                    const struct GNUNET_ATS_Information*atsi)
{
  struct GNUNET_STREAM_Socket *socket = *tunnel_ctx;

  return handle_data (socket,
                      tunnel,
                      sender,
                      (const struct GNUNET_STREAM_DataMessage *)message,
                      atsi);
}


/**
 * Server's message handler for GNUNET_MESSAGE_TYPE_STREAM_HELLO
 *
 * @param cls the closure
 * @param tunnel connection to the other end
 * @param tunnel_ctx the socket
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
server_handle_hello (void *cls,
                     struct GNUNET_MESH_Tunnel *tunnel,
                     void **tunnel_ctx,
                     const struct GNUNET_PeerIdentity *sender,
                     const struct GNUNET_MessageHeader *message,
                     const struct GNUNET_ATS_Information*atsi)
{
  struct GNUNET_STREAM_Socket *socket = *tunnel_ctx;
  struct GNUNET_STREAM_HelloAckMessage *reply;

  if (0 != memcmp (sender,
                   &socket->other_peer,
                   sizeof (struct GNUNET_PeerIdentity)))
  {
    LOG_DEBUG ("%s: Received HELLO from non-confirming peer\n",
               GNUNET_i2s (&socket->other_peer));
    return GNUNET_YES;
  }
  GNUNET_assert (GNUNET_MESSAGE_TYPE_STREAM_HELLO == ntohs (message->type));
  GNUNET_assert (socket->tunnel == tunnel);
  LOG_DEBUG ("%s: Received HELLO from %s\n", GNUNET_i2s (&socket->other_peer),
             GNUNET_i2s (&socket->other_peer));
  switch (socket->state)
  {
  case STATE_INIT:
    reply = generate_hello_ack (socket, GNUNET_YES);
    queue_message (socket, &reply->header, &set_state_hello_wait, NULL,
                   GNUNET_NO);
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK ==
                   socket->control_retransmission_task_id);
    socket->control_retransmission_task_id =
      GNUNET_SCHEDULER_add_delayed (socket->retransmit_timeout,
                                    &control_retransmission_task, socket);
    break;
  case STATE_HELLO_WAIT:
    /* Perhaps our HELLO_ACK was lost */
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK != 
                   socket->control_retransmission_task_id);
    GNUNET_SCHEDULER_cancel (socket->control_retransmission_task_id);
    socket->control_retransmission_task_id =
      GNUNET_SCHEDULER_add_now (&control_retransmission_task, socket);
    break;
  default:
    LOG_DEBUG( "%s: Client sent HELLO when in state %d\n",
               GNUNET_i2s (&socket->other_peer), socket->state);
    /* FIXME: Send RESET? */
  }
  return GNUNET_OK;
}


/**
 * Server's message handler for GNUNET_MESSAGE_TYPE_STREAM_HELLO_ACK
 *
 * @param cls the closure
 * @param tunnel connection to the other end
 * @param tunnel_ctx the socket
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
server_handle_hello_ack (void *cls,
                         struct GNUNET_MESH_Tunnel *tunnel,
                         void **tunnel_ctx,
                         const struct GNUNET_PeerIdentity *sender,
                         const struct GNUNET_MessageHeader *message,
                         const struct GNUNET_ATS_Information*atsi)
{
  struct GNUNET_STREAM_Socket *socket = *tunnel_ctx;
  const struct GNUNET_STREAM_HelloAckMessage *ack_message;

  GNUNET_assert (GNUNET_MESSAGE_TYPE_STREAM_HELLO_ACK ==
                 ntohs (message->type));
  GNUNET_assert (socket->tunnel == tunnel);
  ack_message = (struct GNUNET_STREAM_HelloAckMessage *) message;
  switch (socket->state)  
  {
  case STATE_HELLO_WAIT:
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%s: Received HELLO_ACK from %s\n",
         GNUNET_i2s (&socket->other_peer),
         GNUNET_i2s (&socket->other_peer));
    socket->read_sequence_number = ntohl (ack_message->sequence_number);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%s: Read sequence number %u\n",
         GNUNET_i2s (&socket->other_peer),
         (unsigned int) socket->read_sequence_number);
    socket->receiver_window_available = 
      ntohl (ack_message->receiver_window_size);
    set_state_established (NULL, socket);
    break;
  default:
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Client sent HELLO_ACK when in state %d\n", socket->state);    
  }
  return GNUNET_OK;
}


/**
 * Server's message handler for GNUNET_MESSAGE_TYPE_STREAM_RESET
 *
 * @param cls the closure
 * @param tunnel connection to the other end
 * @param tunnel_ctx the socket
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
server_handle_reset (void *cls,
                     struct GNUNET_MESH_Tunnel *tunnel,
                     void **tunnel_ctx,
                     const struct GNUNET_PeerIdentity *sender,
                     const struct GNUNET_MessageHeader *message,
                     const struct GNUNET_ATS_Information*atsi)
{
  // struct GNUNET_STREAM_Socket *socket = *tunnel_ctx;

  return GNUNET_OK;
}


/**
 * Server's message handler for GNUNET_MESSAGE_TYPE_STREAM_TRANSMIT_CLOSE
 *
 * @param cls the closure
 * @param tunnel connection to the other end
 * @param tunnel_ctx the socket
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
server_handle_transmit_close (void *cls,
                              struct GNUNET_MESH_Tunnel *tunnel,
                              void **tunnel_ctx,
                              const struct GNUNET_PeerIdentity *sender,
                              const struct GNUNET_MessageHeader *message,
                              const struct GNUNET_ATS_Information*atsi)
{
  struct GNUNET_STREAM_Socket *socket = *tunnel_ctx;

  return handle_transmit_close (socket,
                                tunnel,
                                sender,
                                (struct GNUNET_STREAM_MessageHeader *)message,
                                atsi);
}


/**
 * Server's message handler for GNUNET_MESSAGE_TYPE_STREAM_TRANSMIT_CLOSE_ACK
 *
 * @param cls the closure
 * @param tunnel connection to the other end
 * @param tunnel_ctx the socket
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
server_handle_transmit_close_ack (void *cls,
                                  struct GNUNET_MESH_Tunnel *tunnel,
                                  void **tunnel_ctx,
                                  const struct GNUNET_PeerIdentity *sender,
                                  const struct GNUNET_MessageHeader *message,
                                  const struct GNUNET_ATS_Information*atsi)
{
  struct GNUNET_STREAM_Socket *socket = *tunnel_ctx;

  return handle_generic_close_ack (socket,
                                   tunnel,
                                   sender,
                                   (const struct GNUNET_STREAM_MessageHeader *)
                                   message,
                                   atsi,
                                   SHUT_WR);
}


/**
 * Server's message handler for GNUNET_MESSAGE_TYPE_STREAM_RECEIVE_CLOSE
 *
 * @param cls the closure
 * @param tunnel connection to the other end
 * @param tunnel_ctx the socket
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
server_handle_receive_close (void *cls,
                             struct GNUNET_MESH_Tunnel *tunnel,
                             void **tunnel_ctx,
                             const struct GNUNET_PeerIdentity *sender,
                             const struct GNUNET_MessageHeader *message,
                             const struct GNUNET_ATS_Information*atsi)
{
  struct GNUNET_STREAM_Socket *socket = *tunnel_ctx;

  return
    handle_receive_close (socket,
                          tunnel,
                          sender,
                          (const struct GNUNET_STREAM_MessageHeader *) message,
                          atsi);
}


/**
 * Server's message handler for GNUNET_MESSAGE_TYPE_STREAM_RECEIVE_CLOSE_ACK
 *
 * @param cls the closure
 * @param tunnel connection to the other end
 * @param tunnel_ctx the socket
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
server_handle_receive_close_ack (void *cls,
                                 struct GNUNET_MESH_Tunnel *tunnel,
                                 void **tunnel_ctx,
                                 const struct GNUNET_PeerIdentity *sender,
                                 const struct GNUNET_MessageHeader *message,
                                 const struct GNUNET_ATS_Information*atsi)
{
  struct GNUNET_STREAM_Socket *socket = *tunnel_ctx;

  return handle_generic_close_ack (socket,
                                   tunnel,
                                   sender,
                                   (const struct GNUNET_STREAM_MessageHeader *)
                                   message,
                                   atsi,
                                   SHUT_RD);
}


/**
 * Server's message handler for GNUNET_MESSAGE_TYPE_STREAM_CLOSE
 *
 * @param cls the listen socket (from GNUNET_MESH_connect in
 *          GNUNET_STREAM_listen) 
 * @param tunnel connection to the other end
 * @param tunnel_ctx the socket
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
server_handle_close (void *cls,
                     struct GNUNET_MESH_Tunnel *tunnel,
                     void **tunnel_ctx,
                     const struct GNUNET_PeerIdentity *sender,
                     const struct GNUNET_MessageHeader *message,
                     const struct GNUNET_ATS_Information*atsi)
{
  struct GNUNET_STREAM_Socket *socket = *tunnel_ctx;
  
  return handle_close (socket,
                       tunnel,
                       sender,
                       (const struct GNUNET_STREAM_MessageHeader *) message,
                       atsi);
}


/**
 * Server's message handler for GNUNET_MESSAGE_TYPE_STREAM_CLOSE_ACK
 *
 * @param cls the closure
 * @param tunnel connection to the other end
 * @param tunnel_ctx the socket
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
server_handle_close_ack (void *cls,
                         struct GNUNET_MESH_Tunnel *tunnel,
                         void **tunnel_ctx,
                         const struct GNUNET_PeerIdentity *sender,
                         const struct GNUNET_MessageHeader *message,
                         const struct GNUNET_ATS_Information*atsi)
{
  struct GNUNET_STREAM_Socket *socket = *tunnel_ctx;

  return handle_generic_close_ack (socket,
                                   tunnel,
                                   sender,
                                   (const struct GNUNET_STREAM_MessageHeader *) 
                                   message,
                                   atsi,
                                   SHUT_RDWR);
}


/**
 * Handler for DATA_ACK messages
 *
 * @param socket the socket through which the ack was received
 * @param tunnel connection to the other end
 * @param sender who sent the message
 * @param ack the acknowledgment message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_ack (struct GNUNET_STREAM_Socket *socket,
	    struct GNUNET_MESH_Tunnel *tunnel,
	    const struct GNUNET_PeerIdentity *sender,
	    const struct GNUNET_STREAM_AckMessage *ack,
	    const struct GNUNET_ATS_Information*atsi)
{
  unsigned int packet;
  int need_retransmission;
  uint32_t sequence_difference;
  
  if (0 != memcmp (sender,
                   &socket->other_peer,
                   sizeof (struct GNUNET_PeerIdentity)))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%s: Received ACK from non-confirming peer\n",
         GNUNET_i2s (&socket->other_peer));
    return GNUNET_YES;
  }
  switch (socket->state)
  {
  case (STATE_ESTABLISHED):
  case (STATE_RECEIVE_CLOSED):
  case (STATE_RECEIVE_CLOSE_WAIT):
    if (NULL == socket->write_handle)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "%s: Received DATA_ACK when write_handle is NULL\n",
           GNUNET_i2s (&socket->other_peer));
      return GNUNET_OK;
    }
    sequence_difference = 
	socket->write_sequence_number - ntohl (ack->base_sequence_number);
    if (!(sequence_difference <= GNUNET_STREAM_ACK_BITMAP_BIT_LENGTH))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "%s: Received DATA_ACK with unexpected base sequence number\n",
           GNUNET_i2s (&socket->other_peer));
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "%s: Current write sequence: %u; Ack's base sequence: %u\n",
           GNUNET_i2s (&socket->other_peer),
           socket->write_sequence_number,
           ntohl (ack->base_sequence_number));
      return GNUNET_OK;
    }
    /* FIXME: include the case when write_handle is cancelled - ignore the 
       acks */
    LOG (GNUNET_ERROR_TYPE_DEBUG, "%s: Received DATA_ACK from %s\n",
         GNUNET_i2s (&socket->other_peer), GNUNET_i2s (&socket->other_peer));
    /* Cancel the retransmission task */
    if (GNUNET_SCHEDULER_NO_TASK != socket->data_retransmission_task_id)
    {
      GNUNET_SCHEDULER_cancel (socket->data_retransmission_task_id);
      socket->data_retransmission_task_id = GNUNET_SCHEDULER_NO_TASK;
    }
    for (packet=0; packet < GNUNET_STREAM_ACK_BITMAP_BIT_LENGTH; packet++)
    {
      if (NULL == socket->write_handle->messages[packet]) break;
      /* BS: Base sequence from ack; PS: sequence num of current packet */
      sequence_difference = ntohl (ack->base_sequence_number)
        - ntohl (socket->write_handle->messages[packet]->sequence_number);
      if ((0 == sequence_difference) ||
	  (GNUNET_STREAM_ACK_BITMAP_BIT_LENGTH < sequence_difference))
	continue; /* The message in our handle is not yet received */
      /* case where BS = PS + GNUNET_STREAM_ACK_BITMAP_BIT_LENGTH */
      /* sequence_difference <= GNUNET_STREAM_ACK_BITMAP_BIT_LENGTH */
      ackbitmap_modify_bit (&socket->write_handle->ack_bitmap,
			    packet, GNUNET_YES);
    }
    /* Update the receive window remaining
       FIXME : Should update with the value from a data ack with greater
       sequence number */
    socket->receiver_window_available = 
      ntohl (ack->receive_window_remaining);
    /* Check if we have received all acknowledgements */
    need_retransmission = GNUNET_NO;
    for (packet=0; packet < GNUNET_STREAM_ACK_BITMAP_BIT_LENGTH; packet++)
    {
      if (NULL == socket->write_handle->messages[packet]) break;
      if (GNUNET_YES != ackbitmap_is_bit_set 
          (&socket->write_handle->ack_bitmap,packet))
      {
        need_retransmission = GNUNET_YES;
        break;
      }
    }
    if (GNUNET_YES == need_retransmission)
    {
      write_data (socket);
    }
    else      /* We have to call the write continuation callback now */
    {
      struct GNUNET_STREAM_IOWriteHandle *write_handle;
      
      /* Free the packets */
      for (packet=0; packet < GNUNET_STREAM_ACK_BITMAP_BIT_LENGTH; packet++)
      {
        GNUNET_free_non_null (socket->write_handle->messages[packet]);
      }
      write_handle = socket->write_handle;
      socket->write_handle = NULL;
      if (NULL != write_handle->write_cont)
        write_handle->write_cont (write_handle->write_cont_cls,
				  socket->status,
				  write_handle->size);
      /* We are done with the write handle - Freeing it */
      GNUNET_free (write_handle);
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "%s: Write completion callback completed\n",
           GNUNET_i2s (&socket->other_peer));      
    }
    break;
  default:
    break;
  }
  return GNUNET_OK;
}


/**
 * Handler for DATA_ACK messages
 *
 * @param cls the 'struct GNUNET_STREAM_Socket'
 * @param tunnel connection to the other end
 * @param tunnel_ctx unused
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
client_handle_ack (void *cls,
		   struct GNUNET_MESH_Tunnel *tunnel,
		   void **tunnel_ctx,
		   const struct GNUNET_PeerIdentity *sender,
		   const struct GNUNET_MessageHeader *message,
		   const struct GNUNET_ATS_Information*atsi)
{
  struct GNUNET_STREAM_Socket *socket = cls;
  const struct GNUNET_STREAM_AckMessage *ack = (const struct GNUNET_STREAM_AckMessage *) message;
 
  return handle_ack (socket, tunnel, sender, ack, atsi);
}


/**
 * Handler for DATA_ACK messages
 *
 * @param cls the server's listen socket
 * @param tunnel connection to the other end
 * @param tunnel_ctx pointer to the 'struct GNUNET_STREAM_Socket*'
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
server_handle_ack (void *cls,
		   struct GNUNET_MESH_Tunnel *tunnel,
		   void **tunnel_ctx,
		   const struct GNUNET_PeerIdentity *sender,
		   const struct GNUNET_MessageHeader *message,
		   const struct GNUNET_ATS_Information*atsi)
{
  struct GNUNET_STREAM_Socket *socket = *tunnel_ctx;
  const struct GNUNET_STREAM_AckMessage *ack = (const struct GNUNET_STREAM_AckMessage *) message;
 
  return handle_ack (socket, tunnel, sender, ack, atsi);
}


/**
 * For client message handlers, the stream socket is in the
 * closure argument.
 */
static struct GNUNET_MESH_MessageHandler client_message_handlers[] = {
  {&client_handle_data, GNUNET_MESSAGE_TYPE_STREAM_DATA, 0},
  {&client_handle_ack, GNUNET_MESSAGE_TYPE_STREAM_ACK, 
   sizeof (struct GNUNET_STREAM_AckMessage) },
  {&client_handle_hello_ack, GNUNET_MESSAGE_TYPE_STREAM_HELLO_ACK,
   sizeof (struct GNUNET_STREAM_HelloAckMessage)},
  {&client_handle_reset, GNUNET_MESSAGE_TYPE_STREAM_RESET,
   sizeof (struct GNUNET_STREAM_MessageHeader)},
  {&client_handle_transmit_close, GNUNET_MESSAGE_TYPE_STREAM_TRANSMIT_CLOSE,
   sizeof (struct GNUNET_STREAM_MessageHeader)},
  {&client_handle_transmit_close_ack, GNUNET_MESSAGE_TYPE_STREAM_TRANSMIT_CLOSE_ACK,
   sizeof (struct GNUNET_STREAM_MessageHeader)},
  {&client_handle_receive_close, GNUNET_MESSAGE_TYPE_STREAM_RECEIVE_CLOSE,
   sizeof (struct GNUNET_STREAM_MessageHeader)},
  {&client_handle_receive_close_ack, GNUNET_MESSAGE_TYPE_STREAM_RECEIVE_CLOSE_ACK,
   sizeof (struct GNUNET_STREAM_MessageHeader)},
  {&client_handle_close, GNUNET_MESSAGE_TYPE_STREAM_CLOSE,
   sizeof (struct GNUNET_STREAM_MessageHeader)},
  {&client_handle_close_ack, GNUNET_MESSAGE_TYPE_STREAM_CLOSE_ACK,
   sizeof (struct GNUNET_STREAM_MessageHeader)},
  {NULL, 0, 0}
};


/**
 * For server message handlers, the stream socket is in the
 * tunnel context, and the listen socket in the closure argument.
 */
static struct GNUNET_MESH_MessageHandler server_message_handlers[] = {
  {&server_handle_data, GNUNET_MESSAGE_TYPE_STREAM_DATA, 0},
  {&server_handle_ack, GNUNET_MESSAGE_TYPE_STREAM_ACK, 
   sizeof (struct GNUNET_STREAM_AckMessage) },
  {&server_handle_hello, GNUNET_MESSAGE_TYPE_STREAM_HELLO, 
   sizeof (struct GNUNET_STREAM_MessageHeader)},
  {&server_handle_hello_ack, GNUNET_MESSAGE_TYPE_STREAM_HELLO_ACK,
   sizeof (struct GNUNET_STREAM_HelloAckMessage)},
  {&server_handle_reset, GNUNET_MESSAGE_TYPE_STREAM_RESET,
   sizeof (struct GNUNET_STREAM_MessageHeader)},
  {&server_handle_transmit_close, GNUNET_MESSAGE_TYPE_STREAM_TRANSMIT_CLOSE,
   sizeof (struct GNUNET_STREAM_MessageHeader)},
  {&server_handle_transmit_close_ack, GNUNET_MESSAGE_TYPE_STREAM_TRANSMIT_CLOSE_ACK,
   sizeof (struct GNUNET_STREAM_MessageHeader)},
  {&server_handle_receive_close, GNUNET_MESSAGE_TYPE_STREAM_RECEIVE_CLOSE,
   sizeof (struct GNUNET_STREAM_MessageHeader)},
  {&server_handle_receive_close_ack, GNUNET_MESSAGE_TYPE_STREAM_RECEIVE_CLOSE_ACK,
   sizeof (struct GNUNET_STREAM_MessageHeader)},
  {&server_handle_close, GNUNET_MESSAGE_TYPE_STREAM_CLOSE,
   sizeof (struct GNUNET_STREAM_MessageHeader)},
  {&server_handle_close_ack, GNUNET_MESSAGE_TYPE_STREAM_CLOSE_ACK,
   sizeof (struct GNUNET_STREAM_MessageHeader)},
  {NULL, 0, 0}
};


/**
 * Function called when our target peer is connected to our tunnel
 *
 * @param cls the socket for which this tunnel is created
 * @param peer the peer identity of the target
 * @param atsi performance data for the connection
 */
static void
mesh_peer_connect_callback (void *cls,
                            const struct GNUNET_PeerIdentity *peer,
                            const struct GNUNET_ATS_Information * atsi)
{
  struct GNUNET_STREAM_Socket *socket = cls;
  struct GNUNET_STREAM_MessageHeader *message;
  
  if (0 != memcmp (peer,
                   &socket->other_peer,
                   sizeof (struct GNUNET_PeerIdentity)))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%s: A peer which is not our target has connected to our tunnel\n",
         GNUNET_i2s(peer));
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%s: Target peer %s connected\n",
       GNUNET_i2s (&socket->other_peer),
       GNUNET_i2s (&socket->other_peer));
  /* Set state to INIT */
  socket->state = STATE_INIT;
  /* Send HELLO message */
  message = generate_hello ();
  queue_message (socket, message, &set_state_hello_wait, NULL, GNUNET_NO);
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK ==
                 socket->control_retransmission_task_id);
  socket->control_retransmission_task_id =
    GNUNET_SCHEDULER_add_delayed (socket->retransmit_timeout,
                                  &control_retransmission_task, socket);
}


/**
 * Function called when our target peer is disconnected from our tunnel
 *
 * @param cls the socket associated which this tunnel
 * @param peer the peer identity of the target
 */
static void
mesh_peer_disconnect_callback (void *cls,
                               const struct GNUNET_PeerIdentity *peer)
{
  struct GNUNET_STREAM_Socket *socket=cls;
  
  /* If the state is SHUTDOWN its ok; else set the state of the socket to SYSERR */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%s: Other peer %s disconnected \n",
       GNUNET_i2s (&socket->other_peer),
       GNUNET_i2s (&socket->other_peer));
}


/**
 * Method called whenever a peer creates a tunnel to us
 *
 * @param cls closure
 * @param tunnel new handle to the tunnel
 * @param initiator peer that started the tunnel
 * @param atsi performance information for the tunnel
 * @return initial tunnel context for the tunnel
 *         (can be NULL -- that's not an error)
 */
static void *
new_tunnel_notify (void *cls,
                   struct GNUNET_MESH_Tunnel *tunnel,
                   const struct GNUNET_PeerIdentity *initiator,
                   const struct GNUNET_ATS_Information *atsi)
{
  struct GNUNET_STREAM_ListenSocket *lsocket = cls;
  struct GNUNET_STREAM_Socket *socket;

  /* FIXME: If a tunnel is already created, we should not accept new tunnels
     from the same peer again until the socket is closed */

  if (GNUNET_NO == lsocket->listening)
  {
    GNUNET_MESH_tunnel_destroy (tunnel);
    return NULL;
  }
  socket = GNUNET_malloc (sizeof (struct GNUNET_STREAM_Socket));
  socket->other_peer = *initiator;
  socket->tunnel = tunnel;
  socket->state = STATE_INIT;
  socket->lsocket = lsocket;
  socket->stat_handle = lsocket->stat_handle;
  socket->retransmit_timeout = lsocket->retransmit_timeout;
  socket->testing_active = lsocket->testing_active;
  socket->testing_set_write_sequence_number_value =
      lsocket->testing_set_write_sequence_number_value;
  socket->max_payload_size = lsocket->max_payload_size;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%s: Peer %s initiated tunnel to us\n", 
       GNUNET_i2s (&socket->other_peer),
       GNUNET_i2s (&socket->other_peer));
  if (NULL != socket->stat_handle)
  {
    GNUNET_STATISTICS_update (socket->stat_handle,
                              "total inbound connections received",
                              1, GNUNET_NO);
    GNUNET_STATISTICS_update (socket->stat_handle,
                              "inbound connections", 1, GNUNET_NO);
  }
  
  return socket;
}


/**
 * Function called whenever an inbound tunnel is destroyed.  Should clean up
 * any associated state.  This function is NOT called if the client has
 * explicitly asked for the tunnel to be destroyed using
 * GNUNET_MESH_tunnel_destroy. It must NOT call GNUNET_MESH_tunnel_destroy on
 * the tunnel.
 *
 * @param cls closure (set from GNUNET_MESH_connect)
 * @param tunnel connection to the other end (henceforth invalid)
 * @param tunnel_ctx place where local state associated
 *                   with the tunnel is stored
 */
static void 
tunnel_cleaner (void *cls,
                const struct GNUNET_MESH_Tunnel *tunnel,
                void *tunnel_ctx)
{
  struct GNUNET_STREAM_Socket *socket = tunnel_ctx;
  struct MessageQueue *head;

  GNUNET_assert (tunnel == socket->tunnel);
  GNUNET_break_op(0);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%s: Peer %s has terminated connection abruptly\n",
       GNUNET_i2s (&socket->other_peer),
       GNUNET_i2s (&socket->other_peer));
  if (NULL != socket->stat_handle)
  {
    GNUNET_STATISTICS_update (socket->stat_handle,
                              "connections terminated abruptly", 1, GNUNET_NO);
    GNUNET_STATISTICS_update (socket->stat_handle,
                              "inbound connections", -1, GNUNET_NO);
  }
  socket->status = GNUNET_STREAM_SHUTDOWN;
  /* Clear Transmit handles */
  if (NULL != socket->transmit_handle)
  {
    GNUNET_MESH_notify_transmit_ready_cancel (socket->transmit_handle);
    socket->transmit_handle = NULL;
  }
  /* Stop Tasks using socket->tunnel */
  if (GNUNET_SCHEDULER_NO_TASK != socket->ack_task_id)
  {
    GNUNET_SCHEDULER_cancel (socket->ack_task_id);
    socket->ack_task_id = GNUNET_SCHEDULER_NO_TASK;
  }
  if (GNUNET_SCHEDULER_NO_TASK != socket->data_retransmission_task_id)
  {
    GNUNET_SCHEDULER_cancel (socket->data_retransmission_task_id);
    socket->data_retransmission_task_id = GNUNET_SCHEDULER_NO_TASK;
  }  
  /* Terminate the control retransmission tasks */
  if (GNUNET_SCHEDULER_NO_TASK != socket->control_retransmission_task_id)
  {
    GNUNET_SCHEDULER_cancel (socket->control_retransmission_task_id);
    socket->control_retransmission_task_id = GNUNET_SCHEDULER_NO_TASK;
  }
  /* Clear Transmit handles */
  if (NULL != socket->transmit_handle)
  {
    GNUNET_MESH_notify_transmit_ready_cancel (socket->transmit_handle);
    socket->transmit_handle = NULL;
  }
  /* Clear existing message queue */
  while (NULL != (head = socket->queue_head)) {
    GNUNET_CONTAINER_DLL_remove (socket->queue_head,
				 socket->queue_tail,
				 head);
    GNUNET_free (head->message);
    GNUNET_free (head);
  }
  socket->tunnel = NULL;
}


/**
 * Callback to signal timeout on lockmanager lock acquire
 *
 * @param cls the ListenSocket
 * @param tc the scheduler task context
 */
static void
lockmanager_acquire_timeout (void *cls, 
                             const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_STREAM_ListenSocket *lsocket = cls;
  GNUNET_STREAM_ListenCallback listen_cb;
  void *listen_cb_cls;

  lsocket->lockmanager_acquire_timeout_task = GNUNET_SCHEDULER_NO_TASK;
  listen_cb = lsocket->listen_cb;
  listen_cb_cls = lsocket->listen_cb_cls;
  if (NULL != listen_cb)
    listen_cb (listen_cb_cls, NULL, NULL);
}


/**
 * Callback to notify us on the status changes on app_port lock
 *
 * @param cls the ListenSocket
 * @param domain the domain name of the lock
 * @param lock the app_port
 * @param status the current status of the lock
 */
static void
lock_status_change_cb (void *cls, const char *domain, uint32_t lock,
                       enum GNUNET_LOCKMANAGER_Status status)
{
  struct GNUNET_STREAM_ListenSocket *lsocket = cls;

  GNUNET_assert (lock == (uint32_t) lsocket->port);
  if (GNUNET_LOCKMANAGER_SUCCESS == status)
  {
    lsocket->listening = GNUNET_YES;
    if (GNUNET_SCHEDULER_NO_TASK != lsocket->lockmanager_acquire_timeout_task)
    {
      GNUNET_SCHEDULER_cancel (lsocket->lockmanager_acquire_timeout_task);
      lsocket->lockmanager_acquire_timeout_task = GNUNET_SCHEDULER_NO_TASK;
    }
    if (NULL == lsocket->mesh)
    {
      GNUNET_MESH_ApplicationType ports[] = {lsocket->port, 0};

      lsocket->mesh = GNUNET_MESH_connect (lsocket->cfg,
                                           lsocket, /* Closure */
                                           &new_tunnel_notify,
                                           &tunnel_cleaner,
                                           server_message_handlers,
                                           ports);
      GNUNET_assert (NULL != lsocket->mesh);
      if (NULL != lsocket->listen_ok_cb)
      {
        (void) lsocket->listen_ok_cb ();
      }
    }
  }
  if (GNUNET_LOCKMANAGER_RELEASE == status)
    lsocket->listening = GNUNET_NO;
}


/*****************/
/* API functions */
/*****************/


/**
 * Tries to open a stream to the target peer
 *
 * @param cfg configuration to use
 * @param target the target peer to which the stream has to be opened
 * @param app_port the application port number which uniquely identifies this
 *            stream
 * @param open_cb this function will be called after stream has be established;
 *          cannot be NULL
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
                    ...)
{
  struct GNUNET_STREAM_Socket *socket;
  enum GNUNET_STREAM_Option option;
  GNUNET_MESH_ApplicationType ports[] = {app_port, 0};
  va_list vargs;
  uint16_t payload_size;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%s\n", __func__);
  GNUNET_assert (NULL != open_cb);
  socket = GNUNET_malloc (sizeof (struct GNUNET_STREAM_Socket));
  socket->other_peer = *target;
  socket->open_cb = open_cb;
  socket->open_cls = open_cb_cls;
  /* Set defaults */
  socket->retransmit_timeout = TIME_REL_SECS (default_timeout);
  socket->testing_active = GNUNET_NO;
  socket->max_payload_size = DEFAULT_MAX_PAYLOAD_SIZE;
  va_start (vargs, open_cb_cls); /* Parse variable args */
  do {
    option = va_arg (vargs, enum GNUNET_STREAM_Option);
    switch (option)
    {
    case GNUNET_STREAM_OPTION_INITIAL_RETRANSMIT_TIMEOUT:
      /* Expect struct GNUNET_TIME_Relative */
      socket->retransmit_timeout = va_arg (vargs,
                                           struct GNUNET_TIME_Relative);
      break;
    case GNUNET_STREAM_OPTION_TESTING_SET_WRITE_SEQUENCE_NUMBER:
      socket->testing_active = GNUNET_YES;
      socket->testing_set_write_sequence_number_value = va_arg (vargs,
                                                                uint32_t);
      break;
    case GNUNET_STREAM_OPTION_LISTEN_TIMEOUT:
      GNUNET_break (0);          /* Option irrelevant in STREAM_open */
      break;
    case GNUNET_STREAM_OPTION_SIGNAL_LISTEN_SUCCESS:
      GNUNET_break (0);          /* Option irrelevant in STREAM_open */
      break;
    case GNUNET_STREAM_OPTION_MAX_PAYLOAD_SIZE:
      payload_size = (uint16_t) va_arg (vargs, unsigned int);
      GNUNET_assert (0 != payload_size);
      if (payload_size < socket->max_payload_size)
	socket->max_payload_size = payload_size;
      break;
    case GNUNET_STREAM_OPTION_END:
      break;
    }
  } while (GNUNET_STREAM_OPTION_END != option);
  va_end (vargs);               /* End of variable args parsing */
  socket->mesh = GNUNET_MESH_connect (cfg, /* the configuration handle */
                                      socket, /* cls */
                                      NULL, /* No inbound tunnel handler */
                                      NULL, /* No in-tunnel cleaner */
                                      client_message_handlers,
                                      ports); /* We don't get inbound tunnels */
  if (NULL == socket->mesh)   /* Fail if we cannot connect to mesh */
  {
    GNUNET_free (socket);
    return NULL;
  }
  /* Now create the mesh tunnel to target */
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Creating MESH Tunnel\n");
  socket->tunnel = GNUNET_MESH_tunnel_create (socket->mesh,
                                              NULL, /* Tunnel context */
                                              &mesh_peer_connect_callback,
                                              &mesh_peer_disconnect_callback,
                                              socket);
  GNUNET_assert (NULL != socket->tunnel);
  GNUNET_MESH_peer_request_connect_add (socket->tunnel,
                                        &socket->other_peer);
  socket->stat_handle = GNUNET_STATISTICS_create ("stream", cfg);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "%s() END\n", __func__);
  return socket;
}


/**
 * Shutdown the stream for reading or writing (similar to man 2 shutdown).
 *
 * @param socket the stream socket
 * @param operation SHUT_RD, SHUT_WR or SHUT_RDWR
 * @param completion_cb the callback that will be called upon successful
 *          shutdown of given operation
 * @param completion_cls the closure for the completion callback
 * @return the shutdown handle
 */
struct GNUNET_STREAM_ShutdownHandle *
GNUNET_STREAM_shutdown (struct GNUNET_STREAM_Socket *socket,
			int operation,
                        GNUNET_STREAM_ShutdownCompletion completion_cb,
                        void *completion_cls)
{
  struct GNUNET_STREAM_ShutdownHandle *handle;
  struct GNUNET_STREAM_MessageHeader *msg;
  
  GNUNET_assert (NULL == socket->shutdown_handle);
  handle = GNUNET_malloc (sizeof (struct GNUNET_STREAM_ShutdownHandle));
  handle->socket = socket;
  handle->completion_cb = completion_cb;
  handle->completion_cls = completion_cls;
  socket->shutdown_handle = handle;
  if ( ((GNUNET_YES == socket->receive_closed) && (SHUT_RD == operation))
       || ((GNUNET_YES == socket->transmit_closed) && (SHUT_WR == operation))
       || ((GNUNET_YES == socket->transmit_closed) 
           && (GNUNET_YES == socket->receive_closed)
           && (SHUT_RDWR == operation)) )
  {
    handle->operation = operation;
    handle->call_cont_task_id = GNUNET_SCHEDULER_add_now (&call_cont_task,
                                                          socket);
    return handle;
  }
  msg = GNUNET_malloc (sizeof (struct GNUNET_STREAM_MessageHeader));
  msg->header.size = htons (sizeof (struct GNUNET_STREAM_MessageHeader));
  switch (operation)
  {
  case SHUT_RD:
    handle->operation = SHUT_RD;
    if (NULL != socket->read_handle)
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "Existing read handle should be cancelled before shutting"
           " down reading\n");
    msg->header.type = htons (GNUNET_MESSAGE_TYPE_STREAM_RECEIVE_CLOSE);
    queue_message (socket, msg, &set_state_receive_close_wait, NULL,
                   GNUNET_NO);
    break;
  case SHUT_WR:
    handle->operation = SHUT_WR;
    if (NULL != socket->write_handle)
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "Existing write handle should be cancelled before shutting"
           " down writing\n");
    msg->header.type = htons (GNUNET_MESSAGE_TYPE_STREAM_TRANSMIT_CLOSE);
    queue_message (socket, msg, &set_state_transmit_close_wait, NULL,
                   GNUNET_NO);
    break;
  case SHUT_RDWR:
    handle->operation = SHUT_RDWR;
    if (NULL != socket->write_handle)
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "Existing write handle should be cancelled before shutting"
           " down writing\n");
    if (NULL != socket->read_handle)
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "Existing read handle should be cancelled before shutting"
           " down reading\n");
    msg->header.type = htons (GNUNET_MESSAGE_TYPE_STREAM_CLOSE);
    queue_message (socket, msg, &set_state_close_wait, NULL, GNUNET_NO);
    break;
  default:
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "GNUNET_STREAM_shutdown called with invalid value for "
         "parameter operation -- Ignoring\n");
    GNUNET_free (msg);
    GNUNET_free (handle);
    return NULL;
  }
  handle->close_msg_retransmission_task_id =
    GNUNET_SCHEDULER_add_delayed (socket->retransmit_timeout,
                                  &close_msg_retransmission_task,
                                  handle);
  return handle;
}


/**
 * Cancels a pending shutdown. Note that the shutdown messages may already be
 * sent and the stream is shutdown already for the operation given to
 * GNUNET_STREAM_shutdown(). This function only clears up any retranmissions of
 * shutdown messages and frees the shutdown handle.
 *
 * @param handle the shutdown handle returned from GNUNET_STREAM_shutdown
 */
void
GNUNET_STREAM_shutdown_cancel (struct GNUNET_STREAM_ShutdownHandle *handle)
{
  if (GNUNET_SCHEDULER_NO_TASK != handle->close_msg_retransmission_task_id)
    GNUNET_SCHEDULER_cancel (handle->close_msg_retransmission_task_id);
  if (GNUNET_SCHEDULER_NO_TASK != handle->call_cont_task_id)
    GNUNET_SCHEDULER_cancel (handle->call_cont_task_id);
  handle->socket->shutdown_handle = NULL;
  GNUNET_free (handle);
}


/**
 * Closes the stream
 *
 * @param socket the stream socket
 */
void
GNUNET_STREAM_close (struct GNUNET_STREAM_Socket *socket)
{
  struct MessageQueue *head;

  if (NULL != socket->read_handle)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
	 "Closing STREAM socket when a read handle is pending\n");
    GNUNET_STREAM_io_read_cancel (socket->read_handle);
  }
  if (NULL != socket->write_handle)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
	 "Closing STREAM socket when a write handle is pending\n");
    GNUNET_STREAM_io_write_cancel (socket->write_handle);
    //socket->write_handle = NULL;
  }
  /* Terminate the ack'ing task if they are still present */
  if (socket->ack_task_id != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (socket->ack_task_id);
    socket->ack_task_id = GNUNET_SCHEDULER_NO_TASK;
  }
  /* Terminate the control retransmission tasks */
  if (GNUNET_SCHEDULER_NO_TASK != socket->control_retransmission_task_id)
  {
    GNUNET_SCHEDULER_cancel (socket->control_retransmission_task_id);
  }
  /* Clear Transmit handles */
  if (NULL != socket->transmit_handle)
  {
    GNUNET_MESH_notify_transmit_ready_cancel (socket->transmit_handle);
    socket->transmit_handle = NULL;
  }
  /* Clear existing message queue */
  while (NULL != (head = socket->queue_head)) {
    GNUNET_CONTAINER_DLL_remove (socket->queue_head,
				 socket->queue_tail,
				 head);
    GNUNET_free (head->message);
    GNUNET_free (head);
  }
  /* Close associated tunnel */
  if (NULL != socket->tunnel)
  {
    GNUNET_MESH_tunnel_destroy (socket->tunnel);
    socket->tunnel = NULL;
  }
  /* Close mesh connection */
  if ((NULL != socket->mesh) && (NULL == socket->lsocket))
  {
    GNUNET_MESH_disconnect (socket->mesh);
    socket->mesh = NULL;
  }
  /* Close statistics connection */
  if ( (NULL != socket->stat_handle) && (NULL == socket->lsocket) )
    GNUNET_STATISTICS_destroy (socket->stat_handle, GNUNET_YES);
  /* Release receive buffer */
  if (NULL != socket->receive_buffer)
  {
    GNUNET_free (socket->receive_buffer);
  }
  GNUNET_free (socket);
}


/**
 * Listens for stream connections for a specific application ports
 *
 * @param cfg the configuration to use
 * @param app_port the application port for which new streams will be accepted
 * @param listen_cb this function will be called when a peer tries to establish
 *            a stream with us
 * @param listen_cb_cls closure for listen_cb
 * @param ... options to the stream, terminated by GNUNET_STREAM_OPTION_END
 * @return listen socket, NULL for any error
 */
struct GNUNET_STREAM_ListenSocket *
GNUNET_STREAM_listen (const struct GNUNET_CONFIGURATION_Handle *cfg,
                      GNUNET_MESH_ApplicationType app_port,
                      GNUNET_STREAM_ListenCallback listen_cb,
                      void *listen_cb_cls,
                      ...)
{
  struct GNUNET_STREAM_ListenSocket *lsocket;
  struct GNUNET_TIME_Relative listen_timeout;
  enum GNUNET_STREAM_Option option;
  va_list vargs;
  uint16_t payload_size;

  GNUNET_assert (NULL != listen_cb);
  lsocket = GNUNET_malloc (sizeof (struct GNUNET_STREAM_ListenSocket));
  lsocket->cfg = GNUNET_CONFIGURATION_dup (cfg);
  lsocket->lockmanager = GNUNET_LOCKMANAGER_connect (lsocket->cfg);
  if (NULL == lsocket->lockmanager)
  {
    GNUNET_CONFIGURATION_destroy (lsocket->cfg);
    GNUNET_free (lsocket);
    return NULL;
  }
  lsocket->listening = GNUNET_NO;/* We listen when we get a lock on app_port */  
  /* Set defaults */
  lsocket->retransmit_timeout = TIME_REL_SECS (default_timeout);
  lsocket->testing_active = GNUNET_NO;
  lsocket->listen_ok_cb = NULL;
  lsocket->max_payload_size = DEFAULT_MAX_PAYLOAD_SIZE;
  listen_timeout = TIME_REL_SECS (60); /* A minute for listen timeout */  
  va_start (vargs, listen_cb_cls);
  do {
    option = va_arg (vargs, enum GNUNET_STREAM_Option);
    switch (option)
    {
    case GNUNET_STREAM_OPTION_INITIAL_RETRANSMIT_TIMEOUT:
      lsocket->retransmit_timeout = va_arg (vargs,
                                            struct GNUNET_TIME_Relative);
      break;
    case GNUNET_STREAM_OPTION_TESTING_SET_WRITE_SEQUENCE_NUMBER:
      lsocket->testing_active = GNUNET_YES;
      lsocket->testing_set_write_sequence_number_value = va_arg (vargs,
                                                                 uint32_t);
      break;
    case GNUNET_STREAM_OPTION_LISTEN_TIMEOUT:
      listen_timeout = GNUNET_TIME_relative_multiply
        (GNUNET_TIME_UNIT_MILLISECONDS, va_arg (vargs, uint32_t));
      break;
    case GNUNET_STREAM_OPTION_SIGNAL_LISTEN_SUCCESS:
      lsocket->listen_ok_cb = va_arg (vargs,
                                      GNUNET_STREAM_ListenSuccessCallback);
      break;
    case GNUNET_STREAM_OPTION_MAX_PAYLOAD_SIZE:
      payload_size = (uint16_t) va_arg (vargs, unsigned int);
      GNUNET_assert (0 != payload_size);
      if (payload_size < lsocket->max_payload_size)
	lsocket->max_payload_size = payload_size;
      break;
    case GNUNET_STREAM_OPTION_END:
      break;
    }
  } while (GNUNET_STREAM_OPTION_END != option);
  va_end (vargs);
  lsocket->port = app_port;
  lsocket->listen_cb = listen_cb;
  lsocket->listen_cb_cls = listen_cb_cls;
  lsocket->locking_request = 
    GNUNET_LOCKMANAGER_acquire_lock (lsocket->lockmanager, locking_domain,
                                     (uint32_t) lsocket->port,
                                     &lock_status_change_cb, lsocket);
  lsocket->lockmanager_acquire_timeout_task =
    GNUNET_SCHEDULER_add_delayed (listen_timeout,
                                  &lockmanager_acquire_timeout, lsocket);
  lsocket->stat_handle = GNUNET_STATISTICS_create ("stream",
                                                   lsocket->cfg);
  return lsocket;
}


/**
 * Closes the listen socket
 *
 * @param lsocket the listen socket
 */
void
GNUNET_STREAM_listen_close (struct GNUNET_STREAM_ListenSocket *lsocket)
{
  /* Close MESH connection */
  if (NULL != lsocket->mesh)
    GNUNET_MESH_disconnect (lsocket->mesh);
  if (NULL != lsocket->stat_handle)
    GNUNET_STATISTICS_destroy (lsocket->stat_handle, GNUNET_YES);
  GNUNET_CONFIGURATION_destroy (lsocket->cfg);
  if (GNUNET_SCHEDULER_NO_TASK != lsocket->lockmanager_acquire_timeout_task)
    GNUNET_SCHEDULER_cancel (lsocket->lockmanager_acquire_timeout_task);
  if (NULL != lsocket->locking_request)
    GNUNET_LOCKMANAGER_cancel_request (lsocket->locking_request);
  if (NULL != lsocket->lockmanager)
    GNUNET_LOCKMANAGER_disconnect (lsocket->lockmanager);
  GNUNET_free (lsocket);
}


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
                     void *write_cont_cls)
{
  struct GNUNET_STREAM_IOWriteHandle *io_handle;
  struct GNUNET_STREAM_DataMessage *data_msg;
  const void *sweep;
  struct GNUNET_TIME_Relative ack_deadline;
  unsigned int num_needed_packets;
  unsigned int packet;
  uint32_t packet_size;
  uint32_t payload_size;
  uint16_t max_data_packet_size;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%s\n", __func__);
  if (NULL != socket->write_handle)
  {
    GNUNET_break (0);
    return NULL;
  }
  switch (socket->state)
  {
  case STATE_TRANSMIT_CLOSED:
  case STATE_TRANSMIT_CLOSE_WAIT:
  case STATE_CLOSED:
  case STATE_CLOSE_WAIT:
    if (NULL != write_cont)
      write_cont (write_cont_cls, GNUNET_STREAM_SHUTDOWN, 0);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%s() END\n", __func__);
    return NULL;
  case STATE_INIT:
  case STATE_LISTEN:
  case STATE_HELLO_WAIT:
    if (NULL != write_cont)
      /* FIXME: GNUNET_STREAM_SYSERR?? */
      write_cont (write_cont_cls, GNUNET_STREAM_SYSERR, 0);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%s() END\n", __func__);
    return NULL;
  case STATE_ESTABLISHED:
  case STATE_RECEIVE_CLOSED:
  case STATE_RECEIVE_CLOSE_WAIT:
    break;
  }
  if (GNUNET_STREAM_ACK_BITMAP_BIT_LENGTH * socket->max_payload_size < size)
    size = GNUNET_STREAM_ACK_BITMAP_BIT_LENGTH  * socket->max_payload_size;
  num_needed_packets =
      (size + (socket->max_payload_size - 1)) / socket->max_payload_size;
  io_handle = GNUNET_malloc (sizeof (struct GNUNET_STREAM_IOWriteHandle));
  io_handle->socket = socket;
  io_handle->write_cont = write_cont;
  io_handle->write_cont_cls = write_cont_cls;
  io_handle->size = size;
  io_handle->packets_sent = 0;
  sweep = data;
  /* FIXME: Remove the fixed delay for ack deadline; Set it to the value
     determined from RTT */
  ack_deadline = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5);
  /* Divide the given buffer into packets for sending */
  max_data_packet_size =
      socket->max_payload_size + sizeof (struct GNUNET_STREAM_DataMessage);
  for (packet=0; packet < num_needed_packets; packet++)
  {
    if ((packet + 1) * socket->max_payload_size < size) 
    {
      payload_size = socket->max_payload_size;
      packet_size = max_data_packet_size;
    }
    else 
    {
      payload_size = size - packet * socket->max_payload_size;
      packet_size = 
	  payload_size + sizeof (struct GNUNET_STREAM_DataMessage);
    }
    io_handle->messages[packet] = GNUNET_malloc (packet_size);
    io_handle->messages[packet]->header.header.size = htons (packet_size);
    io_handle->messages[packet]->header.header.type =
      htons (GNUNET_MESSAGE_TYPE_STREAM_DATA);
    io_handle->messages[packet]->sequence_number =
      htonl (socket->write_sequence_number++);
    io_handle->messages[packet]->offset = htonl (socket->write_offset);
    /* FIXME: Remove the fixed delay for ack deadline; Set it to the value
       determined from RTT */
    io_handle->messages[packet]->ack_deadline =
      GNUNET_TIME_relative_hton (ack_deadline);
    data_msg = io_handle->messages[packet];
    /* Copy data from given buffer to the packet */
    memcpy (&data_msg[1], sweep, payload_size);
    sweep += payload_size;
    socket->write_offset += payload_size;
  }
  /* ack the last data message. FIXME: remove when we figure out how to do this
     using RTT */
  io_handle->messages[num_needed_packets - 1]->ack_deadline = 
      GNUNET_TIME_relative_hton (GNUNET_TIME_UNIT_ZERO);
  socket->write_handle = io_handle;
  write_data (socket);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%s() END\n", __func__);
  return io_handle;
}


/**
 * Tries to read data from the stream.
 *
 * @param socket the socket representing a stream
 * @param timeout the timeout period
 * @param proc function to call with data (once only)
 * @param proc_cls the closure for proc
 *
 * @return handle to cancel the operation; NULL is returned if: the stream has
 *           been shutdown for this type of opeartion (the DataProcessor is
 *           immediately called with GNUNET_STREAM_SHUTDOWN as status) OR another
 *           read handle is present (only one read handle per socket is present
 *           at any time)
 */
struct GNUNET_STREAM_IOReadHandle *
GNUNET_STREAM_read (struct GNUNET_STREAM_Socket *socket,
                    struct GNUNET_TIME_Relative timeout,
		    GNUNET_STREAM_DataProcessor proc,
		    void *proc_cls)
{
  struct GNUNET_STREAM_IOReadHandle *read_handle;
  
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%s: %s()\n", 
       GNUNET_i2s (&socket->other_peer),
       __func__);
  /* Return NULL if there is already a read handle; the user has to cancel that
     first before continuing or has to wait until it is completed */
  if (NULL != socket->read_handle) 
    return NULL;
  GNUNET_assert (NULL != proc);
  switch (socket->state)
  {
  case STATE_RECEIVE_CLOSED:
  case STATE_RECEIVE_CLOSE_WAIT:
  case STATE_CLOSED:
  case STATE_CLOSE_WAIT:
    proc (proc_cls, GNUNET_STREAM_SHUTDOWN, NULL, 0);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%s: %s() END\n",
         GNUNET_i2s (&socket->other_peer),
         __func__);
    return NULL;
  default:
    break;
  }
  read_handle = GNUNET_malloc (sizeof (struct GNUNET_STREAM_IOReadHandle));
  read_handle->proc = proc;
  read_handle->proc_cls = proc_cls;
  read_handle->socket = socket;
  socket->read_handle = read_handle;
  if (GNUNET_YES == ackbitmap_is_bit_set (&socket->ack_bitmap,
                                          0))
    read_handle->read_task_id = GNUNET_SCHEDULER_add_now (&call_read_processor,
							  socket);   
  read_handle->read_io_timeout_task_id =
      GNUNET_SCHEDULER_add_delayed (timeout, &read_io_timeout, socket);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "%s: %s() END\n",
       GNUNET_i2s (&socket->other_peer), __func__);
  return read_handle;
}


/**
 * Cancel pending write operation.
 *
 * @param ioh handle to operation to cancel
 */
void
GNUNET_STREAM_io_write_cancel (struct GNUNET_STREAM_IOWriteHandle *ioh)
{
  struct GNUNET_STREAM_Socket *socket = ioh->socket;
  unsigned int packet;

  GNUNET_assert (NULL != socket->write_handle);
  GNUNET_assert (socket->write_handle == ioh);

  if (GNUNET_SCHEDULER_NO_TASK != socket->data_retransmission_task_id)
  {
    GNUNET_SCHEDULER_cancel (socket->data_retransmission_task_id);
    socket->data_retransmission_task_id = GNUNET_SCHEDULER_NO_TASK;
  }

  for (packet=0; packet < GNUNET_STREAM_ACK_BITMAP_BIT_LENGTH; packet++)
  {
    if (NULL == ioh->messages[packet]) break;
    GNUNET_free (ioh->messages[packet]);
  }
      
  GNUNET_free (socket->write_handle);
  socket->write_handle = NULL;
}


/**
 * Cancel pending read operation.
 *
 * @param ioh handle to operation to cancel
 */
void
GNUNET_STREAM_io_read_cancel (struct GNUNET_STREAM_IOReadHandle *ioh)
{
  struct GNUNET_STREAM_Socket *socket;
  
  socket = ioh->socket;
  GNUNET_assert (NULL != socket->read_handle);
  GNUNET_assert (ioh == socket->read_handle);
  /* Read io time task should be there; if it is already executed then this
  read handle is not valid; However upon scheduler shutdown the read io task
  may be executed before */
  if (GNUNET_SCHEDULER_NO_TASK != ioh->read_io_timeout_task_id)
    GNUNET_SCHEDULER_cancel (ioh->read_io_timeout_task_id);
  /* reading task may be present; if so we have to stop it */
  if (GNUNET_SCHEDULER_NO_TASK != ioh->read_task_id)
    GNUNET_SCHEDULER_cancel (ioh->read_task_id);
  GNUNET_free (ioh);
  socket->read_handle = NULL;
}

/* end of stream_api.c */
