/*
     This file is part of GNUnet.
     Copyright (C) 2019 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file transport/transport-testing2.c
 * @brief functions related to testing-tng
 * @author Christian Grothoff
 * @author Julius Bünger
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_constants.h"
#include "transport-testing2.h"
#include "gnunet_ats_transport_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_signatures.h"
#include "transport.h"
#include <inttypes.h>

#define LOG(kind, ...) GNUNET_log_from (kind, "transport-testing2", __VA_ARGS__)

struct MyClient
{
  struct MyClient *prev;
  struct MyClient *next;
  /**
   * @brief Handle to the client
   */
  struct GNUNET_SERVICE_Client *client;

  /**
   * @brief Handle to the client
   */
  struct GNUNET_MQ_Handle *c_mq;

  /**
   * The TCH
   */
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc;

};

/**
 * @brief Handle to a transport communicator
 */
struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle
{
  /**
   * Clients
   */
  struct MyClient *client_head;
  struct MyClient *client_tail;

  /**
  * @brief Handle to the client
  */
  struct GNUNET_MQ_Handle *c_mq;

  /**
    * @brief Handle to the configuration
    */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * @brief File name of configuration file
   */
  char *cfg_filename;

  struct GNUNET_PeerIdentity peer_id;

  /**
   * @brief Handle to the transport service
   */
  struct GNUNET_SERVICE_Handle *tsh;

  /**
   * @brief Task that will be run on shutdown to stop and clean transport
   * service
   */
  struct GNUNET_SCHEDULER_Task *ts_shutdown_task;


  /**
   * @brief Process of the communicator
   */
  struct GNUNET_OS_Process *c_proc;

  /**
   * NAT process
   */
  struct GNUNET_OS_Process *nat_proc;

  /**
   * resolver service process
   */
  struct GNUNET_OS_Process *resolver_proc;

  /**
   * @brief Task that will be run on shutdown to stop and clean communicator
   */
  struct GNUNET_SCHEDULER_Task *c_shutdown_task;

  /**
   * @brief Characteristics of the communicator
   */
  enum GNUNET_TRANSPORT_CommunicatorCharacteristics c_characteristics;

  /**
   * @brief Specifies supported addresses
   */
  char *c_addr_prefix;

  /**
   * @brief Specifies supported addresses
   */
  char *c_address;

  /**
   * @brief Head of the DLL of queues associated with this communicator
   */
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorQueue *queue_head;

  /**
   * @brief Tail of the DLL of queues associated with this communicator
   */
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorQueue *queue_tail;

  /* Callbacks + Closures */
  /**
   * @brief Callback called when a new communicator connects
   */
  GNUNET_TRANSPORT_TESTING_CommunicatorAvailableCallback
    communicator_available_cb;

  /**
   * @brief Callback called when a new communicator connects
   */
  GNUNET_TRANSPORT_TESTING_AddAddressCallback add_address_cb;

  /**
   * @brief Callback called when a new communicator connects
   */
  GNUNET_TRANSPORT_TESTING_QueueCreateReplyCallback queue_create_reply_cb;

  /**
   * @brief Callback called when a new communicator connects
   */
  GNUNET_TRANSPORT_TESTING_AddQueueCallback add_queue_cb;

  /**
   * @brief Callback called when a new communicator connects
   */
  GNUNET_TRANSPORT_TESTING_IncomingMessageCallback incoming_msg_cb;

  /**
   * @brief Backchannel callback
   */
  GNUNET_TRANSPORT_TESTING_BackchannelCallback bc_cb;

  /**
   * Our service handle
   */
  struct GNUNET_SERVICE_Handle *sh;

  /**
   * @brief Closure to the callback
   */
  void *cb_cls;

  /**
   * Backchannel supported
   */
  int bc_enabled;
};


/**
 * @brief Queue of a communicator and some context
 */
struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorQueue
{
  /**
   * @brief Handle to the TransportCommunicator
   */
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h;

  /**
   * @brief Envelope to a message that requests the opening of the queue.
   *
   * If the client already requests queue(s), but the communicator is not yet
   * connected, we cannot send the request to open the queue. Save it until the
   * communicator becomes available and send it then.
   */
  struct GNUNET_MQ_Envelope *open_queue_env;

  /**
   * @brief Peer ID of the peer on the other side of the queue
   */
  struct GNUNET_PeerIdentity peer_id;

  /**
   * @brief Queue ID
   */
  uint32_t qid;

  /**
   * @brief Current message id
   */
  uint64_t mid;

  /**
   * An `enum GNUNET_NetworkType` in NBO.
   */
  uint32_t nt;

  /**
   * Maximum transmission unit.  UINT32_MAX for unlimited.
   */
  uint32_t mtu;

  /**
   * Queue length.  UINT64_MAX for unlimited.
   */
  uint64_t q_len;

  /**
   * Queue prio
   */
  uint32_t priority;

  /**
   * An `enum GNUNET_TRANSPORT_ConnectionStatus` in NBO.
   */
  uint32_t cs;

  /**
   * @brief Next element inside a DLL
   */
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorQueue *next;

  /**
   * @brief Previous element inside a DLL
   */
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorQueue *prev;
};


/**
 * @brief Handle/Context to a single transmission
 */
struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorTransmission
{
};


/**
 * @brief Check whether incoming msg indicating available communicator is
 * correct
 *
 * @param cls Closure
 * @param msg Message struct
 *
 * @return GNUNET_YES in case message is correct
 */
static int
check_communicator_available (
  void *cls,
  const struct GNUNET_TRANSPORT_CommunicatorAvailableMessage *msg)
{
  uint16_t size;

  size = ntohs (msg->header.size) - sizeof(*msg);
  if (0 == size)
    return GNUNET_OK; /* receive-only communicator */
  GNUNET_MQ_check_zero_termination (msg);
  return GNUNET_OK;
}


/**
 * @brief Handle new communicator
 *
 * Store characteristics of communicator, call respective client callback.
 *
 * @param cls Closure - communicator handle
 * @param msg Message struct
 */
static void
handle_communicator_available (
  void *cls,
  const struct GNUNET_TRANSPORT_CommunicatorAvailableMessage *msg)
{
  struct MyClient *client = cls;
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h =
    client->tc;
  uint16_t size;
  tc_h->c_mq = client->c_mq;

  size = ntohs (msg->header.size) - sizeof(*msg);
  if (0 == size)
  {
    GNUNET_SERVICE_client_continue (client->client);
    return; /* receive-only communicator */
  }
  tc_h->c_characteristics = ntohl (msg->cc);
  tc_h->c_addr_prefix = GNUNET_strdup ((const char *) &msg[1]);
  if (NULL != tc_h->communicator_available_cb)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "calling communicator_available_cb()\n");
    tc_h->communicator_available_cb (tc_h->cb_cls,
                                     tc_h,
                                     tc_h->c_characteristics,
                                     tc_h->c_addr_prefix);
  }
  GNUNET_SERVICE_client_continue (client->client);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "finished communicator_available_cb()\n");

}


/**
 * Incoming message.  Test message is well-formed.
 *
 * @param cls the client
 * @param msg the send message that was sent
 * @return #GNUNET_OK if message is well-formed
 */
static int
check_communicator_backchannel (void *cls,
                                const struct
                                GNUNET_TRANSPORT_CommunicatorBackchannel *msg)
{
  // struct TransportClient *tc = cls;

  // if (CT_COMMUNICATOR != tc->type)
  // {
  //  GNUNET_break (0);
  //  return GNUNET_SYSERR;
  // }
  // GNUNET_MQ_check_boxed_message (msg);
  return GNUNET_OK;
}


/**
 * @brief Receive an incoming message.
 *
 * Pass the message to the client.
 *
 * @param cls Closure - communicator handle
 * @param msg Message
 */
static void
handle_communicator_backchannel (void *cls,
                                 const struct
                                 GNUNET_TRANSPORT_CommunicatorBackchannel *
                                 bc_msg)
{
  struct MyClient *client = cls;
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h =
    client->tc;
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *other_tc_h;
  struct GNUNET_MessageHeader *msg;
  msg = (struct GNUNET_MessageHeader *) &bc_msg[1];
  uint16_t isize = ntohs (msg->size);
  const char *target_communicator = ((const char *) msg) + isize;
  struct GNUNET_TRANSPORT_CommunicatorBackchannelIncoming *cbi;
  struct GNUNET_MQ_Envelope *env;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received backchannel message\n");
  if (tc_h->bc_enabled != GNUNET_YES)
  {
    GNUNET_SERVICE_client_continue (client->client);
    return;
  }
  /* Find client providing this communicator */
  /* Finally, deliver backchannel message to communicator */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Delivering backchannel message of type %u to %s\n",
       ntohs (msg->type),
       target_communicator);
  other_tc_h = tc_h->bc_cb (tc_h, msg, (struct
                                        GNUNET_PeerIdentity*) &bc_msg->pid);
  env = GNUNET_MQ_msg_extra (
    cbi,
    isize,
    GNUNET_MESSAGE_TYPE_TRANSPORT_COMMUNICATOR_BACKCHANNEL_INCOMING);
  cbi->pid = tc_h->peer_id;
  memcpy (&cbi[1], msg, isize);


  GNUNET_MQ_send (other_tc_h->c_mq, env);
  GNUNET_SERVICE_client_continue (client->client);
}


/**
 * Address of our peer added.  Test message is well-formed.
 *
 * @param cls the client
 * @param aam the send message that was sent
 * @return #GNUNET_OK if message is well-formed
 */
static int
check_add_address (void *cls,
                   const struct GNUNET_TRANSPORT_AddAddressMessage *msg)
{
  // if (CT_COMMUNICATOR != tc->type)
  // {
  //  GNUNET_break (0);
  //  return GNUNET_SYSERR;
  // }
  GNUNET_MQ_check_zero_termination (msg);
  return GNUNET_OK;
}


/**
 * @brief The communicator informs about an address.
 *
 * Store address and call client callback.
 *
 * @param cls Closure - communicator handle
 * @param msg Message
 */
static void
handle_add_address (void *cls,
                    const struct GNUNET_TRANSPORT_AddAddressMessage *msg)
{
  struct MyClient *client = cls;
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h =
    client->tc;
  uint16_t size;
  size = ntohs (msg->header.size) - sizeof(*msg);
  if (0 == size)
    return; /* receive-only communicator */
  LOG (GNUNET_ERROR_TYPE_DEBUG, "received add address cb %u\n", size);
  tc_h->c_address = GNUNET_strdup ((const char *) &msg[1]);
  if (NULL != tc_h->add_address_cb)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "calling add_address_cb()\n");
    tc_h->add_address_cb (tc_h->cb_cls,
                          tc_h,
                          tc_h->c_address,
                          GNUNET_TIME_relative_ntoh (msg->expiration),
                          msg->aid,
                          ntohl (msg->nt));
  }
  GNUNET_SERVICE_client_continue (client->client);
}


/**
 * Incoming message.  Test message is well-formed.
 *
 * @param cls the client
 * @param msg the send message that was sent
 * @return #GNUNET_OK if message is well-formed
 */
static int
check_incoming_msg (void *cls,
                    const struct GNUNET_TRANSPORT_IncomingMessage *msg)
{
  // struct TransportClient *tc = cls;

  // if (CT_COMMUNICATOR != tc->type)
  // {
  //  GNUNET_break (0);
  //  return GNUNET_SYSERR;
  // }
  GNUNET_MQ_check_boxed_message (msg);
  return GNUNET_OK;
}


/**
 * @brief Receive an incoming message.
 *
 * Pass the message to the client.
 *
 * @param cls Closure - communicator handle
 * @param msg Message
 */
static void
handle_incoming_msg (void *cls,
                     const struct GNUNET_TRANSPORT_IncomingMessage *inc_msg)
{
  struct MyClient *client = cls;
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h =
    client->tc;
  struct GNUNET_MessageHeader *msg;
  msg = (struct GNUNET_MessageHeader *) &inc_msg[1];
  size_t payload_len = ntohs (msg->size) - sizeof (struct
                                                   GNUNET_MessageHeader);
  if (NULL != tc_h->incoming_msg_cb)
  {
    tc_h->incoming_msg_cb (tc_h->cb_cls,
                           tc_h,
                           (char*) &msg[1],
                           payload_len);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Incoming message from communicator but no handler!\n");
  }
  if (GNUNET_YES == ntohl (inc_msg->fc_on))
  {
    /* send ACK when done to communicator for flow control! */
    struct GNUNET_MQ_Envelope *env;
    struct GNUNET_TRANSPORT_IncomingMessageAck *ack;

    env = GNUNET_MQ_msg (ack, GNUNET_MESSAGE_TYPE_TRANSPORT_INCOMING_MSG_ACK);
    GNUNET_assert (NULL != env);
    ack->reserved = htonl (0);
    ack->fc_id = inc_msg->fc_id;
    ack->sender = inc_msg->sender;
    GNUNET_MQ_send (tc_h->c_mq, env);
  }

  GNUNET_SERVICE_client_continue (client->client);
}


/**
 * @brief Communicator informs that it tries to establish requested queue
 *
 * @param cls Closure - communicator handle
 * @param msg Message
 */
static void
handle_queue_create_ok (void *cls,
                        const struct GNUNET_TRANSPORT_CreateQueueResponse *msg)
{
  struct MyClient *client = cls;
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h =
    client->tc;

  if (NULL != tc_h->queue_create_reply_cb)
  {
    tc_h->queue_create_reply_cb (tc_h->cb_cls, tc_h, GNUNET_YES);
  }
  GNUNET_SERVICE_client_continue (client->client);
}


/**
 * @brief Communicator informs that it wont try establishing requested queue.
 *
 * It will not do so probably because the address is bougus (see comment to
 * #GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_CREATE_FAIL)
 *
 * @param cls Closure - communicator handle
 * @param msg Message
 */
static void
handle_queue_create_fail (
  void *cls,
  const struct GNUNET_TRANSPORT_CreateQueueResponse *msg)
{
  struct MyClient *client = cls;
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h =
    client->tc;

  if (NULL != tc_h->queue_create_reply_cb)
  {
    tc_h->queue_create_reply_cb (tc_h->cb_cls, tc_h, GNUNET_NO);
  }
  GNUNET_SERVICE_client_continue (client->client);
}


/**
 * New queue became available.  Check message.
 *
 * @param cls the client
 * @param aqm the send message that was sent
 */
static int
check_add_queue_message (void *cls,
                         const struct GNUNET_TRANSPORT_AddQueueMessage *aqm)
{
  GNUNET_MQ_check_zero_termination (aqm);
  return GNUNET_OK;
}


/**
 * @brief Handle new queue
 *
 * Store context and call client callback.
 *
 * @param cls Closure - communicator handle
 * @param msg Message struct
 */
static void
handle_add_queue_message (void *cls,
                          const struct GNUNET_TRANSPORT_AddQueueMessage *msg)
{
  struct MyClient *client = cls;
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h =
    client->tc;
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorQueue *tc_queue;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Got queue with ID %u\n", msg->qid);
  for (tc_queue = tc_h->queue_head; NULL != tc_queue; tc_queue = tc_queue->next)
  {
    if (tc_queue->qid == msg->qid)
      break;
  }
  if (NULL == tc_queue)
  {
    tc_queue =
      GNUNET_new (struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorQueue);
    tc_queue->tc_h = tc_h;
    tc_queue->qid = msg->qid;
    tc_queue->peer_id = msg->receiver;
    GNUNET_CONTAINER_DLL_insert (tc_h->queue_head, tc_h->queue_tail, tc_queue);
  }
  GNUNET_assert (tc_queue->qid == msg->qid);
  GNUNET_assert (0 == GNUNET_memcmp (&tc_queue->peer_id, &msg->receiver));
  tc_queue->nt = msg->nt;
  tc_queue->mtu = ntohl (msg->mtu);
  tc_queue->cs = msg->cs;
  tc_queue->priority = ntohl (msg->priority);
  tc_queue->q_len = GNUNET_ntohll (msg->q_len);
  if (NULL != tc_h->add_queue_cb)
  {
    tc_h->add_queue_cb (tc_h->cb_cls, tc_h, tc_queue, tc_queue->mtu);
  }
  GNUNET_SERVICE_client_continue (client->client);
}


/**
 * @brief Handle new queue
 *
 * Store context and call client callback.
 *
 * @param cls Closure - communicator handle
 * @param msg Message struct
 */
static void
handle_update_queue_message (void *cls,
                             const struct
                             GNUNET_TRANSPORT_UpdateQueueMessage *msg)
{
  struct MyClient *client = cls;
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h =
    client->tc;
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorQueue *tc_queue;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received queue update message for %u with q_len %"PRIu64"\n",
       msg->qid, GNUNET_ntohll(msg->q_len));
  tc_queue = tc_h->queue_head;
  if (NULL != tc_queue)
  {
    while (tc_queue->qid != msg->qid)
    {
      tc_queue = tc_queue->next;
    }
  }
  GNUNET_assert (tc_queue->qid == msg->qid);
  GNUNET_assert (0 == GNUNET_memcmp (&tc_queue->peer_id, &msg->receiver));
  tc_queue->nt = msg->nt;
  tc_queue->mtu = ntohl (msg->mtu);
  tc_queue->cs = msg->cs;
  tc_queue->priority = ntohl (msg->priority);
  tc_queue->q_len += GNUNET_ntohll (msg->q_len);
  GNUNET_SERVICE_client_continue (client->client);
}


/**
 * @brief Shut down the service
 *
 * @param cls Closure - Handle to the service
 */
static void
shutdown_service (void *cls)
{
  struct GNUNET_SERVICE_Handle *h = cls;

  GNUNET_SERVICE_stop (h);
}


/**
 * @brief Callback called when new Client (Communicator) connects
 *
 * @param cls Closure - TransporCommmunicator Handle
 * @param client Client
 * @param mq Messagequeue
 *
 * @return TransportCommunicator Handle
 */
static void *
connect_cb (void *cls,
            struct GNUNET_SERVICE_Client *client,
            struct GNUNET_MQ_Handle *mq)
{
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h = cls;
  struct MyClient *new_c;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Client %p connected to %p.\n",
       client, tc_h);
  new_c = GNUNET_new (struct MyClient);
  new_c->client = client;
  new_c->c_mq = mq;
  new_c->tc = tc_h;
  GNUNET_CONTAINER_DLL_insert (tc_h->client_head,
                               tc_h->client_tail,
                               new_c);

  if (NULL == tc_h->queue_head)
    return new_c;
  /* Iterate over queues. They are yet to be opened. Request opening. */
  for (struct
       GNUNET_TRANSPORT_TESTING_TransportCommunicatorQueue *tc_queue_iter =
         tc_h->queue_head;
       NULL != tc_queue_iter;
       tc_queue_iter = tc_queue_iter->next)
  {
    if (NULL == tc_queue_iter->open_queue_env)
      continue;
    /* Send the previously created mq envelope to request the creation of the
     * queue. */
    GNUNET_MQ_send (tc_h->c_mq,
                    tc_queue_iter->open_queue_env);
    tc_queue_iter->open_queue_env = NULL;
  }
  return new_c;
}


/**
 * @brief Callback called when Client disconnects
 *
 * @param cls Closure - TransportCommunicator Handle
 * @param client Client
 * @param internal_cls TransporCommmunicator Handle
 */
static void
disconnect_cb (void *cls,
               struct GNUNET_SERVICE_Client *client,
               void *internal_cls)
{
  struct MyClient *cl = cls;
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h = cls;

  for (cl = tc_h->client_head; NULL != cl; cl = cl->next)
  {
    if (cl->client != client)
      continue;
    GNUNET_CONTAINER_DLL_remove (tc_h->client_head,
                                 tc_h->client_tail,
                                 cl);
    if (cl->c_mq == tc_h->c_mq)
      tc_h->c_mq = NULL;
    GNUNET_free (cl);
    break;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Client disconnected.\n");
}


/**
 * Message was transmitted.  Process the request.
 *
 * @param cls the client
 * @param sma the send message that was sent
 */
static void
handle_send_message_ack (void *cls,
                         const struct GNUNET_TRANSPORT_SendMessageToAck *sma)
{
  struct MyClient *client = cls;
  GNUNET_SERVICE_client_continue (client->client);
  // NOP
}


/**
 * @brief Start the communicator part of the transport service
 *
 * @param communicator_available Callback to be called when a new communicator
 * becomes available
 * @param cfg Configuration
 */
static void
transport_communicator_start (
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h)
{
  struct GNUNET_MQ_MessageHandler mh[] = {
    GNUNET_MQ_hd_var_size (communicator_available,
                           GNUNET_MESSAGE_TYPE_TRANSPORT_NEW_COMMUNICATOR,
                           struct GNUNET_TRANSPORT_CommunicatorAvailableMessage,
                           tc_h),
    GNUNET_MQ_hd_var_size (communicator_backchannel,
                           GNUNET_MESSAGE_TYPE_TRANSPORT_COMMUNICATOR_BACKCHANNEL,
                           struct GNUNET_TRANSPORT_CommunicatorBackchannel,
                           tc_h),
    GNUNET_MQ_hd_var_size (add_address,
                           GNUNET_MESSAGE_TYPE_TRANSPORT_ADD_ADDRESS,
                           struct GNUNET_TRANSPORT_AddAddressMessage,
                           tc_h),
    // GNUNET_MQ_hd_fixed_size (del_address,
    //                         GNUNET_MESSAGE_TYPE_TRANSPORT_DEL_ADDRESS,
    //                         struct GNUNET_TRANSPORT_DelAddressMessage,
    //                         NULL),
    GNUNET_MQ_hd_var_size (incoming_msg,
                           GNUNET_MESSAGE_TYPE_TRANSPORT_INCOMING_MSG,
                           struct GNUNET_TRANSPORT_IncomingMessage,
                           tc_h),
    GNUNET_MQ_hd_fixed_size (queue_create_ok,
                             GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_CREATE_OK,
                             struct GNUNET_TRANSPORT_CreateQueueResponse,
                             tc_h),
    GNUNET_MQ_hd_fixed_size (queue_create_fail,
                             GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_CREATE_FAIL,
                             struct GNUNET_TRANSPORT_CreateQueueResponse,
                             tc_h),
    GNUNET_MQ_hd_var_size (add_queue_message,
                           GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_SETUP,
                           struct GNUNET_TRANSPORT_AddQueueMessage,
                           tc_h),
    GNUNET_MQ_hd_fixed_size (update_queue_message,
                             GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_UPDATE,
                             struct GNUNET_TRANSPORT_UpdateQueueMessage,
                             tc_h),
    // GNUNET_MQ_hd_fixed_size (del_queue_message,
    //                         GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_TEARDOWN,
    //                         struct GNUNET_TRANSPORT_DelQueueMessage,
    //                         NULL),
    GNUNET_MQ_hd_fixed_size (send_message_ack,
                             GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_MSG_ACK,
                             struct GNUNET_TRANSPORT_SendMessageToAck,
                             tc_h),
    GNUNET_MQ_handler_end ()
  };


  tc_h->sh = GNUNET_SERVICE_start ("transport",
                                   tc_h->cfg,
                                   &connect_cb,
                                   &disconnect_cb,
                                   tc_h,
                                   mh);
  GNUNET_assert (NULL != tc_h->sh);
}


/**
 * @brief Task run at shutdown to kill communicator and clean up
 *
 * @param cls Closure - Process of communicator
 */
static void
shutdown_process (struct GNUNET_OS_Process *proc)
{
  if (0 != GNUNET_OS_process_kill (proc, SIGTERM))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Error shutting down process with SIGERM, trying SIGKILL\n");
    if (0 != GNUNET_OS_process_kill (proc, SIGKILL))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           "Error shutting down process with SIGERM and SIGKILL\n");
    }
  }
  GNUNET_OS_process_destroy (proc);
}


static void
shutdown_communicator (void *cls)
{
  struct GNUNET_OS_Process *proc = cls;
  shutdown_process (proc);
}


/**
 * @brief Start the communicator
 *
 * @param cfgname Name of the communicator
 */
static void
communicator_start (
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h,
  const char *binary_name)
{
  char *binary;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "communicator_start\n");
  binary = GNUNET_OS_get_libexec_binary_path (binary_name);
  tc_h->c_proc = GNUNET_OS_start_process (GNUNET_YES,
                                          GNUNET_OS_INHERIT_STD_OUT_AND_ERR,
                                          NULL,
                                          NULL,
                                          NULL,
                                          binary,
                                          binary_name,
                                          "-c",
                                          tc_h->cfg_filename,
                                          NULL);
  if (NULL == tc_h->c_proc)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to start communicator!");
    return;
  }
  LOG (GNUNET_ERROR_TYPE_INFO, "started communicator\n");
  GNUNET_free (binary);
}


/**
 * @brief Task run at shutdown to kill communicator and clean up
 *
 * @param cls Closure - Process of communicator
 */
static void
shutdown_nat (void *cls)
{
  struct GNUNET_OS_Process *proc = cls;
  shutdown_process (proc);
}

/**
 * @brief Task run at shutdown to kill the resolver process
 *
 * @param cls Closure - Process of communicator
 */
static void
shutdown_resolver (void *cls)
{
  struct GNUNET_OS_Process *proc = cls;
  shutdown_process (proc);
}

static void
resolver_start (struct
                GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h)
{
  char *binary;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "resolver_start\n");
  binary = GNUNET_OS_get_libexec_binary_path ("gnunet-service-resolver");
  tc_h->resolver_proc = GNUNET_OS_start_process (GNUNET_YES,
                                                 GNUNET_OS_INHERIT_STD_OUT_AND_ERR,
                                                 NULL,
                                                 NULL,
                                                 NULL,
                                                 binary,
                                                 "gnunet-service-resolver",
                                                 "-c",
                                                 tc_h->cfg_filename,
                                                 NULL);
  if (NULL == tc_h->resolver_proc)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to start resolver service!");
    return;
  }
  LOG (GNUNET_ERROR_TYPE_INFO, "started resolver service\n");
  GNUNET_free (binary);

}

/**
 * @brief Start NAT
 *
 */
static void
nat_start (
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h)
{
  char *binary;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "nat_start\n");
  binary = GNUNET_OS_get_libexec_binary_path ("gnunet-service-nat");
  tc_h->nat_proc = GNUNET_OS_start_process (GNUNET_YES,
                                            GNUNET_OS_INHERIT_STD_OUT_AND_ERR,
                                            NULL,
                                            NULL,
                                            NULL,
                                            binary,
                                            "gnunet-service-nat",
                                            "-c",
                                            tc_h->cfg_filename,
                                            NULL);
  if (NULL == tc_h->nat_proc)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to start NAT!");
    return;
  }
  LOG (GNUNET_ERROR_TYPE_INFO, "started NAT\n");
  GNUNET_free (binary);
}


/**
 * @brief Start communicator part of transport service and communicator
 *
 * @param service_name Name of the service
 * @param cfg Configuration handle
 * @param communicator_available_cb Callback that is called when a new
 * @param add_address_cb Callback that is called when a new
 * communicator becomes available
 * @param cb_cls Closure to @a communicator_available_cb and @a
 *
 * @return Handle to the communicator duo
 */
struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *
GNUNET_TRANSPORT_TESTING_transport_communicator_service_start (
  const char *service_name,
  const char *binary_name,
  const char *cfg_filename,
  const struct GNUNET_PeerIdentity *peer_id,
  GNUNET_TRANSPORT_TESTING_CommunicatorAvailableCallback
  communicator_available_cb,
  GNUNET_TRANSPORT_TESTING_AddAddressCallback add_address_cb,
  GNUNET_TRANSPORT_TESTING_QueueCreateReplyCallback queue_create_reply_cb,
  GNUNET_TRANSPORT_TESTING_AddQueueCallback add_queue_cb,
  GNUNET_TRANSPORT_TESTING_IncomingMessageCallback incoming_message_cb,
  GNUNET_TRANSPORT_TESTING_BackchannelCallback bc_cb,
  void *cb_cls)
{
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Starting new transport/communicator combo with config %s\n",
       cfg_filename);
  tc_h =
    GNUNET_new (struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle);
  tc_h->cfg_filename = GNUNET_strdup (cfg_filename);
  tc_h->cfg = GNUNET_CONFIGURATION_create ();
  if ((GNUNET_SYSERR == GNUNET_CONFIGURATION_load (tc_h->cfg, cfg_filename)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Malformed configuration file `%s', exit ...\n"),
                cfg_filename);
    GNUNET_free (tc_h->cfg_filename);
    GNUNET_CONFIGURATION_destroy (tc_h->cfg);
    GNUNET_free (tc_h);
    return NULL;
  }
  tc_h->bc_enabled = GNUNET_CONFIGURATION_get_value_yesno (tc_h->cfg,
                                                           "communicator-test",
                                                           "BACKCHANNEL_ENABLED");
  tc_h->communicator_available_cb = communicator_available_cb;
  tc_h->add_address_cb = add_address_cb;
  tc_h->queue_create_reply_cb = queue_create_reply_cb;
  tc_h->add_queue_cb = add_queue_cb;
  tc_h->incoming_msg_cb = incoming_message_cb;
  tc_h->bc_cb = bc_cb;
  tc_h->peer_id = *peer_id;
  tc_h->cb_cls = cb_cls;

  /* Start communicator part of service */
  transport_communicator_start (tc_h);
  /* Start NAT */
  nat_start (tc_h);
  /* Start resolver service */
  resolver_start (tc_h);
  /* Schedule start communicator */
  communicator_start (tc_h,
                      binary_name);
  return tc_h;
}


void
GNUNET_TRANSPORT_TESTING_transport_communicator_service_stop (
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h)
{
  shutdown_communicator (tc_h->c_proc);
  shutdown_service (tc_h->sh);
  shutdown_nat (tc_h->nat_proc);
  shutdown_resolver (tc_h->resolver_proc);
  GNUNET_CONFIGURATION_destroy (tc_h->cfg);
  GNUNET_free (tc_h);
}


/**
 * @brief Instruct communicator to open a queue
 *
 * @param tc_h Handle to communicator which shall open queue
 * @param peer_id Towards which peer
 * @param address For which address
 */
void
GNUNET_TRANSPORT_TESTING_transport_communicator_open_queue (
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h,
  const struct GNUNET_PeerIdentity *peer_id,
  const char *address)
{
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorQueue *tc_queue;
  static uint32_t idgen;
  char *prefix;
  struct GNUNET_TRANSPORT_CreateQueue *msg;
  struct GNUNET_MQ_Envelope *env;
  size_t alen;

  tc_queue =
    GNUNET_new (struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorQueue);
  tc_queue->tc_h = tc_h;
  prefix = GNUNET_HELLO_address_to_prefix (address);
  if (NULL == prefix)
  {
    GNUNET_break (0);  /* We got an invalid address!? */
    GNUNET_free (tc_queue);
    return;
  }
  GNUNET_free (prefix);
  alen = strlen (address) + 1;
  env =
    GNUNET_MQ_msg_extra (msg, alen, GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_CREATE);
  msg->request_id = htonl (idgen++);
  tc_queue->qid = msg->request_id;
  msg->receiver = *peer_id;
  tc_queue->peer_id = *peer_id;
  memcpy (&msg[1], address, alen);
  if (NULL != tc_h->c_mq)
  {
    GNUNET_MQ_send (tc_h->c_mq, env);
  }
  else
  {
    tc_queue->open_queue_env = env;
  }
  GNUNET_CONTAINER_DLL_insert (tc_h->queue_head, tc_h->queue_tail, tc_queue);
}


/**
 * @brief Instruct communicator to send data
 *
 * @param tc_queue The queue to use for sending
 * @param cont function to call when done sending
 * @param cont_cls closure for @a cont
 * @param payload Data to send
 * @param payload_size Size of the @a payload
 */
void
GNUNET_TRANSPORT_TESTING_transport_communicator_send
  (struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorHandle *tc_h,
  GNUNET_SCHEDULER_TaskCallback cont,
  void *cont_cls,
  const void *payload,
  size_t payload_size)
{
  struct GNUNET_MessageHeader *mh;
  struct GNUNET_TRANSPORT_SendMessageTo *msg;
  struct GNUNET_MQ_Envelope *env;
  size_t inbox_size;
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorQueue *tc_queue;
  struct GNUNET_TRANSPORT_TESTING_TransportCommunicatorQueue *tc_queue_tmp;

  tc_queue = NULL;
  for (tc_queue_tmp = tc_h->queue_head;
       NULL != tc_queue_tmp;
       tc_queue_tmp = tc_queue_tmp->next)
  {
    if (tc_queue_tmp->q_len <= 0)
      continue;
    if (NULL == tc_queue)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Selecting queue with prio %u, len %" PRIu64 " and MTU %u\n",
           tc_queue_tmp->priority,
           tc_queue_tmp->q_len,
           tc_queue_tmp->mtu);
      tc_queue = tc_queue_tmp;
      continue;
    }
    if (tc_queue->priority < tc_queue_tmp->priority)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Selecting queue with prio %u, len %" PRIu64 " and MTU %u\n",
           tc_queue_tmp->priority,
           tc_queue_tmp->q_len,
           tc_queue_tmp->mtu);
      tc_queue = tc_queue_tmp;
    }
  }
  GNUNET_assert (NULL != tc_queue);
  if (tc_queue->q_len != GNUNET_TRANSPORT_QUEUE_LENGTH_UNLIMITED)
    tc_queue->q_len--;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending message\n");
  inbox_size = sizeof (struct GNUNET_MessageHeader) + payload_size;
  env = GNUNET_MQ_msg_extra (msg,
                             inbox_size,
                             GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_MSG);
  GNUNET_assert (NULL != env);
  msg->qid = htonl (tc_queue->qid);
  msg->mid = tc_queue->mid++;
  msg->receiver = tc_queue->peer_id;
  mh = (struct GNUNET_MessageHeader *) &msg[1];
  mh->size = htons (inbox_size);
  mh->type = GNUNET_MESSAGE_TYPE_DUMMY;
  memcpy (&mh[1],
          payload,
          payload_size);
  if (NULL != cont)
    GNUNET_MQ_notify_sent (env,
                           cont,
                           cont_cls);
  GNUNET_MQ_send (tc_queue->tc_h->c_mq,
                  env);
}
