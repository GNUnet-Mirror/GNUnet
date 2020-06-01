/*
     This file is part of GNUnet.
     Copyright (C) 2018 GNUnet e.V.

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
 * @file transport/transport_api2_communication.c
 * @brief implementation of the gnunet_transport_communication_service.h API
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_transport_communication_service.h"
#include "gnunet_ats_transport_service.h"
#include "transport.h"


/**
 * How many messages do we keep at most in the queue to the
 * transport service before we start to drop (default,
 * can be changed via the configuration file).
 */
#define DEFAULT_MAX_QUEUE_LENGTH 16


/**
 * Information we track per packet to enable flow control.
 */
struct FlowControl
{
  /**
   * Kept in a DLL.
   */
  struct FlowControl *next;

  /**
   * Kept in a DLL.
   */
  struct FlowControl *prev;

  /**
   * Function to call once the message was processed.
   */
  GNUNET_TRANSPORT_MessageCompletedCallback cb;

  /**
   * Closure for @e cb
   */
  void *cb_cls;

  /**
   * Which peer is this about?
   */
  struct GNUNET_PeerIdentity sender;

  /**
   * More-or-less unique ID for the message.
   */
  uint64_t id;
};


/**
 * Information we track per message to tell the transport about
 * success or failures.
 */
struct AckPending
{
  /**
   * Kept in a DLL.
   */
  struct AckPending *next;

  /**
   * Kept in a DLL.
   */
  struct AckPending *prev;

  /**
   * Communicator this entry belongs to.
   */
  struct GNUNET_TRANSPORT_CommunicatorHandle *ch;

  /**
   * Which peer is this about?
   */
  struct GNUNET_PeerIdentity receiver;

  /**
   * More-or-less unique ID for the message.
   */
  uint64_t mid;
};


/**
 * Opaque handle to the transport service for communicators.
 */
struct GNUNET_TRANSPORT_CommunicatorHandle
{
  /**
   * Head of DLL of addresses this communicator offers to the transport service.
   */
  struct GNUNET_TRANSPORT_AddressIdentifier *ai_head;

  /**
   * Tail of DLL of addresses this communicator offers to the transport service.
   */
  struct GNUNET_TRANSPORT_AddressIdentifier *ai_tail;

  /**
   * DLL of messages awaiting flow control confirmation (ack).
   */
  struct FlowControl *fc_head;

  /**
   * DLL of messages awaiting flow control confirmation (ack).
   */
  struct FlowControl *fc_tail;

  /**
   * DLL of messages awaiting transmission confirmation (ack).
   */
  struct AckPending *ap_head;

  /**
   * DLL of messages awaiting transmission confirmation (ack).
   */
  struct AckPending *ap_tail;

  /**
   * DLL of queues we offer.
   */
  struct GNUNET_TRANSPORT_QueueHandle *queue_head;

  /**
   * DLL of queues we offer.
   */
  struct GNUNET_TRANSPORT_QueueHandle *queue_tail;

  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Config section to use.
   */
  const char *config_section;

  /**
   * Address prefix to use.
   */
  const char *addr_prefix;

  /**
   * Function to call when the transport service wants us to initiate
   * a communication channel with another peer.
   */
  GNUNET_TRANSPORT_CommunicatorMqInit mq_init;

  /**
   * Closure for @e mq_init.
   */
  void *mq_init_cls;

  /**
   * Function to call when the transport service receives messages
   * for a communicator (i.e. for NAT traversal or for non-bidirectional
   * communicators).
   */
  GNUNET_TRANSPORT_CommunicatorNotify notify_cb;

  /**
   * Closure for @e notify_Cb.
   */
  void *notify_cb_cls;

  /**
   * Queue to talk to the transport service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Maximum permissable queue length.
   */
  unsigned long long max_queue_length;

  /**
   * Flow-control identifier generator.
   */
  uint64_t fc_gen;

  /**
   * Internal UUID for the address used in communication with the
   * transport service.
   */
  uint32_t aid_gen;

  /**
   * Queue identifier generator.
   */
  uint32_t queue_gen;

  /**
   * Characteristics of the communicator.
   */
  enum GNUNET_TRANSPORT_CommunicatorCharacteristics cc;
};


/**
 * Handle returned to identify the internal data structure the transport
 * API has created to manage a message queue to a particular peer.
 */
struct GNUNET_TRANSPORT_QueueHandle
{
  /**
   * Kept in a DLL.
   */
  struct GNUNET_TRANSPORT_QueueHandle *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_TRANSPORT_QueueHandle *prev;

  /**
   * Handle this queue belongs to.
   */
  struct GNUNET_TRANSPORT_CommunicatorHandle *ch;

  /**
   * Address used by the communication queue.
   */
  char *address;

  /**
   * The queue itself.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Which peer we can communciate with.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Network type of the communciation queue.
   */
  enum GNUNET_NetworkType nt;

  /**
   * Communication status of the queue.
   */
  enum GNUNET_TRANSPORT_ConnectionStatus cs;

  /**
   * ID for this queue when talking to the transport service.
   */
  uint32_t queue_id;

  /**
   * Maximum transmission unit for the queue.
   */
  uint32_t mtu;

  /**
   * Queue length.
   */
  uint64_t q_len;
  /**
   * Queue priority.
   */
  uint32_t priority;
};


/**
 * Internal representation of an address a communicator is
 * currently providing for the transport service.
 */
struct GNUNET_TRANSPORT_AddressIdentifier
{
  /**
   * Kept in a DLL.
   */
  struct GNUNET_TRANSPORT_AddressIdentifier *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_TRANSPORT_AddressIdentifier *prev;

  /**
   * Transport handle where the address was added.
   */
  struct GNUNET_TRANSPORT_CommunicatorHandle *ch;

  /**
   * The actual address.
   */
  char *address;

  /**
   * When does the address expire? (Expected lifetime of the
   * address.)
   */
  struct GNUNET_TIME_Relative expiration;

  /**
   * Internal UUID for the address used in communication with the
   * transport service.
   */
  uint32_t aid;

  /**
   * Network type for the address.
   */
  enum GNUNET_NetworkType nt;
};


/**
 * (re)connect our communicator to the transport service
 *
 * @param ch handle to reconnect
 */
static void
reconnect (struct GNUNET_TRANSPORT_CommunicatorHandle *ch);


/**
 * Send message to the transport service about address @a ai
 * being now available.
 *
 * @param ai address to add
 */
static void
send_add_address (struct GNUNET_TRANSPORT_AddressIdentifier *ai)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_TRANSPORT_AddAddressMessage *aam;

  if (NULL == ai->ch->mq)
    return;
  env = GNUNET_MQ_msg_extra (aam,
                             strlen (ai->address) + 1,
                             GNUNET_MESSAGE_TYPE_TRANSPORT_ADD_ADDRESS);
  aam->expiration = GNUNET_TIME_relative_hton (ai->expiration);
  aam->nt = htonl ((uint32_t) ai->nt);
  memcpy (&aam[1], ai->address, strlen (ai->address) + 1);
  GNUNET_MQ_send (ai->ch->mq, env);
}


/**
 * Send message to the transport service about address @a ai
 * being no longer available.
 *
 * @param ai address to delete
 */
static void
send_del_address (struct GNUNET_TRANSPORT_AddressIdentifier *ai)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_TRANSPORT_DelAddressMessage *dam;

  if (NULL == ai->ch->mq)
    return;
  env = GNUNET_MQ_msg (dam, GNUNET_MESSAGE_TYPE_TRANSPORT_DEL_ADDRESS);
  dam->aid = htonl (ai->aid);
  GNUNET_MQ_send (ai->ch->mq, env);
}


/**
 * Send message to the transport service about queue @a qh
 * being now available.
 *
 * @param qh queue to add
 */
static void
send_add_queue (struct GNUNET_TRANSPORT_QueueHandle *qh)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_TRANSPORT_AddQueueMessage *aqm;

  if (NULL == qh->ch->mq)
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending `GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_SETUP` message\n");
  env = GNUNET_MQ_msg_extra (aqm,
                             strlen (qh->address) + 1,
                             GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_SETUP);
  aqm->qid = htonl (qh->queue_id);
  aqm->receiver = qh->peer;
  aqm->nt = htonl ((uint32_t) qh->nt);
  aqm->mtu = htonl (qh->mtu);
  aqm->q_len = GNUNET_htonll (qh->q_len);
  aqm->priority = htonl (qh->priority);
  aqm->cs = htonl ((uint32_t) qh->cs);
  memcpy (&aqm[1], qh->address, strlen (qh->address) + 1);
  GNUNET_MQ_send (qh->ch->mq, env);
}

/**
 * Send message to the transport service about queue @a qh
 * updated.
 *
 * @param qh queue to add
 */
static void
send_update_queue (struct GNUNET_TRANSPORT_QueueHandle *qh)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_TRANSPORT_UpdateQueueMessage *uqm;

  if (NULL == qh->ch->mq)
    return;
  env = GNUNET_MQ_msg (uqm, GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_UPDATE);
  uqm->qid = htonl (qh->queue_id);
  uqm->receiver = qh->peer;
  uqm->nt = htonl ((uint32_t) qh->nt);
  uqm->mtu = htonl (qh->mtu);
  uqm->q_len = GNUNET_htonll (qh->q_len);
  uqm->priority = htonl (qh->priority);
  uqm->cs = htonl ((uint32_t) qh->cs);
  GNUNET_MQ_send (qh->ch->mq, env);
}



/**
 * Send message to the transport service about queue @a qh
 * being no longer available.
 *
 * @param qh queue to delete
 */
static void
send_del_queue (struct GNUNET_TRANSPORT_QueueHandle *qh)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_TRANSPORT_DelQueueMessage *dqm;

  if (NULL == qh->ch->mq)
    return;
  env = GNUNET_MQ_msg (dqm, GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_TEARDOWN);
  dqm->qid = htonl (qh->queue_id);
  dqm->receiver = qh->peer;
  GNUNET_MQ_send (qh->ch->mq, env);
}


/**
 * Disconnect from the transport service.  Purges
 * all flow control entries as we will no longer receive
 * the ACKs.  Purges the ack pending entries as the
 * transport will no longer expect the confirmations.
 *
 * @param ch service to disconnect from
 */
static void
disconnect (struct GNUNET_TRANSPORT_CommunicatorHandle *ch)
{
  struct FlowControl *fcn;
  struct AckPending *apn;

  for (struct FlowControl *fc = ch->fc_head; NULL != fc; fc = fcn)
  {
    fcn = fc->next;
    GNUNET_CONTAINER_DLL_remove (ch->fc_head, ch->fc_tail, fc);
    fc->cb (fc->cb_cls, GNUNET_SYSERR);
    GNUNET_free (fc);
  }
  for (struct AckPending *ap = ch->ap_head; NULL != ap; ap = apn)
  {
    apn = ap->next;
    GNUNET_CONTAINER_DLL_remove (ch->ap_head, ch->ap_tail, ap);
    GNUNET_free (ap);
  }
  if (NULL == ch->mq)
    return;
  GNUNET_MQ_destroy (ch->mq);
  ch->mq = NULL;
}


/**
 * Function called on MQ errors.
 */
static void
error_handler (void *cls, enum GNUNET_MQ_Error error)
{
  struct GNUNET_TRANSPORT_CommunicatorHandle *ch = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "MQ failure %d, reconnecting to transport service.\n",
              error);
  disconnect (ch);
  /* TODO: maybe do this with exponential backoff/delay */
  reconnect (ch);
}


/**
 * Transport service acknowledged a message we gave it
 * (with flow control enabled). Tell the communicator.
 *
 * @param cls our `struct GNUNET_TRANSPORT_CommunicatorHandle *`
 * @param incoming_ack the ack
 */
static void
handle_incoming_ack (
  void *cls,
  const struct GNUNET_TRANSPORT_IncomingMessageAck *incoming_ack)
{
  struct GNUNET_TRANSPORT_CommunicatorHandle *ch = cls;

  for (struct FlowControl *fc = ch->fc_head; NULL != fc; fc = fc->next)
  {
    if ((fc->id == incoming_ack->fc_id) &&
        (0 == memcmp (&fc->sender,
                      &incoming_ack->sender,
                      sizeof(struct GNUNET_PeerIdentity))))
    {
      GNUNET_CONTAINER_DLL_remove (ch->fc_head, ch->fc_tail, fc);
      fc->cb (fc->cb_cls, GNUNET_OK);
      GNUNET_free (fc);
      return;
    }
  }
  GNUNET_break (0);
  disconnect (ch);
  /* TODO: maybe do this with exponential backoff/delay */
  reconnect (ch);
}


/**
 * Transport service wants us to create a queue. Check if @a cq
 * is well-formed.
 *
 * @param cls our `struct GNUNET_TRANSPORT_CommunicatorHandle *`
 * @param cq the queue creation request
 * @return #GNUNET_OK if @a smt is well-formed
 */
static int
check_create_queue (void *cls, const struct GNUNET_TRANSPORT_CreateQueue *cq)
{
  (void) cls;
  GNUNET_MQ_check_zero_termination (cq);
  return GNUNET_OK;
}


/**
 * Transport service wants us to create a queue. Tell the communicator.
 *
 * @param cls our `struct GNUNET_TRANSPORT_CommunicatorHandle *`
 * @param cq the queue creation request
 */
static void
handle_create_queue (void *cls, const struct GNUNET_TRANSPORT_CreateQueue *cq)
{
  struct GNUNET_TRANSPORT_CommunicatorHandle *ch = cls;
  const char *addr = (const char *) &cq[1];
  struct GNUNET_TRANSPORT_CreateQueueResponse *cqr;
  struct GNUNET_MQ_Envelope *env;

  if (GNUNET_OK != ch->mq_init (ch->mq_init_cls, &cq->receiver, addr))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Address `%s' invalid for this communicator\n",
                addr);
    env = GNUNET_MQ_msg (cqr, GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_CREATE_FAIL);
  }
  else
  {
    env = GNUNET_MQ_msg (cqr, GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_CREATE_OK);
  }
  cqr->request_id = cq->request_id;
  GNUNET_MQ_send (ch->mq, env);
}


/**
 * Transport service wants us to send a message. Check if @a smt
 * is well-formed.
 *
 * @param cls our `struct GNUNET_TRANSPORT_CommunicatorHandle *`
 * @param smt the transmission request
 * @return #GNUNET_OK if @a smt is well-formed
 */
static int
check_send_msg (void *cls, const struct GNUNET_TRANSPORT_SendMessageTo *smt)
{
  (void) cls;
  GNUNET_MQ_check_boxed_message (smt);
  return GNUNET_OK;
}


/**
 * Notify transport service about @a status of a message with
 * @a mid sent to @a receiver.
 *
 * @param ch handle
 * @param status #GNUNET_OK on success, #GNUNET_SYSERR on failure
 * @param receiver which peer was the receiver
 * @param mid message that the ack is about
 */
static void
send_ack (struct GNUNET_TRANSPORT_CommunicatorHandle *ch,
          int status,
          const struct GNUNET_PeerIdentity *receiver,
          uint64_t mid)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_TRANSPORT_SendMessageToAck *ack;

  env = GNUNET_MQ_msg (ack, GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_MSG_ACK);
  ack->status = htonl (status);
  ack->mid = mid;
  ack->receiver = *receiver;
  GNUNET_MQ_send (ch->mq, env);
}


/**
 * Message queue transmission by communicator was successful,
 * notify transport service.
 *
 * @param cls an `struct AckPending *`
 */
static void
send_ack_cb (void *cls)
{
  struct AckPending *ap = cls;
  struct GNUNET_TRANSPORT_CommunicatorHandle *ch = ap->ch;

  GNUNET_CONTAINER_DLL_remove (ch->ap_head, ch->ap_tail, ap);
  send_ack (ch, GNUNET_OK, &ap->receiver, ap->mid);
  GNUNET_free (ap);
}


/**
 * Transport service wants us to send a message. Tell the communicator.
 *
 * @param cls our `struct GNUNET_TRANSPORT_CommunicatorHandle *`
 * @param smt the transmission request
 */
static void
handle_send_msg (void *cls, const struct GNUNET_TRANSPORT_SendMessageTo *smt)
{
  struct GNUNET_TRANSPORT_CommunicatorHandle *ch = cls;
  const struct GNUNET_MessageHeader *mh;
  struct GNUNET_MQ_Envelope *env;
  struct AckPending *ap;
  struct GNUNET_TRANSPORT_QueueHandle *qh;

  for (qh = ch->queue_head; NULL != qh; qh = qh->next)
    if ((qh->queue_id == smt->qid) &&
        (0 == memcmp (&qh->peer,
                      &smt->receiver,
                      sizeof(struct GNUNET_PeerIdentity))))
      break;
  if (NULL == qh)
  {
    /* queue is already gone, tell transport this one failed */
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Transmission failed, queue no longer exists.\n");
    send_ack (ch, GNUNET_NO, &smt->receiver, smt->mid);
    return;
  }
  ap = GNUNET_new (struct AckPending);
  ap->ch = ch;
  ap->receiver = smt->receiver;
  ap->mid = smt->mid;
  GNUNET_CONTAINER_DLL_insert (ch->ap_head, ch->ap_tail, ap);
  mh = (const struct GNUNET_MessageHeader *) &smt[1];
  env = GNUNET_MQ_msg_copy (mh);
  GNUNET_MQ_notify_sent (env, &send_ack_cb, ap);
  GNUNET_MQ_send (qh->mq, env);
}


/**
 * Transport service gives us backchannel message. Check if @a bi
 * is well-formed.
 *
 * @param cls our `struct GNUNET_TRANSPORT_CommunicatorHandle *`
 * @param bi the backchannel message
 * @return #GNUNET_OK if @a smt is well-formed
 */
static int
check_backchannel_incoming (
  void *cls,
  const struct GNUNET_TRANSPORT_CommunicatorBackchannelIncoming *bi)
{
  (void) cls;
  GNUNET_MQ_check_boxed_message (bi);
  return GNUNET_OK;
}


/**
 * Transport service gives us backchannel message. Handle it.
 *
 * @param cls our `struct GNUNET_TRANSPORT_CommunicatorHandle *`
 * @param bi the backchannel message
 */
static void
handle_backchannel_incoming (
  void *cls,
  const struct GNUNET_TRANSPORT_CommunicatorBackchannelIncoming *bi)
{
  struct GNUNET_TRANSPORT_CommunicatorHandle *ch = cls;
  if (NULL != ch->notify_cb)
    ch->notify_cb (ch->notify_cb_cls,
                   &bi->pid,
                   (const struct GNUNET_MessageHeader *) &bi[1]);
  else
    GNUNET_log (
      GNUNET_ERROR_TYPE_INFO,
      _ ("Dropped backchanel message: handler not provided by communicator\n"));
}


/**
 * (re)connect our communicator to the transport service
 *
 * @param ch handle to reconnect
 */
static void
reconnect (struct GNUNET_TRANSPORT_CommunicatorHandle *ch)
{
  struct GNUNET_MQ_MessageHandler handlers[] =
  { GNUNET_MQ_hd_fixed_size (incoming_ack,
                             GNUNET_MESSAGE_TYPE_TRANSPORT_INCOMING_MSG_ACK,
                             struct GNUNET_TRANSPORT_IncomingMessageAck,
                             ch),
    GNUNET_MQ_hd_var_size (create_queue,
                           GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_CREATE,
                           struct GNUNET_TRANSPORT_CreateQueue,
                           ch),
    GNUNET_MQ_hd_var_size (send_msg,
                           GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_MSG,
                           struct GNUNET_TRANSPORT_SendMessageTo,
                           ch),
    GNUNET_MQ_hd_var_size (
      backchannel_incoming,
      GNUNET_MESSAGE_TYPE_TRANSPORT_COMMUNICATOR_BACKCHANNEL_INCOMING,
      struct GNUNET_TRANSPORT_CommunicatorBackchannelIncoming,
      ch),
    GNUNET_MQ_handler_end () };
  struct GNUNET_TRANSPORT_CommunicatorAvailableMessage *cam;
  struct GNUNET_MQ_Envelope *env;

  ch->mq =
    GNUNET_CLIENT_connect (ch->cfg, "transport", handlers, &error_handler, ch);
  if (NULL == ch->mq)
    return;
  env = GNUNET_MQ_msg_extra (cam,
                             strlen (ch->addr_prefix) + 1,
                             GNUNET_MESSAGE_TYPE_TRANSPORT_NEW_COMMUNICATOR);
  cam->cc = htonl ((uint32_t) ch->cc);
  memcpy (&cam[1], ch->addr_prefix, strlen (ch->addr_prefix) + 1);
  GNUNET_MQ_send (ch->mq, env);
  for (struct GNUNET_TRANSPORT_AddressIdentifier *ai = ch->ai_head; NULL != ai;
       ai = ai->next)
    send_add_address (ai);
  for (struct GNUNET_TRANSPORT_QueueHandle *qh = ch->queue_head; NULL != qh;
       qh = qh->next)
    send_add_queue (qh);
}


/**
 * Connect to the transport service.
 *
 * @param cfg configuration to use
 * @param config_section section of the configuration to use for options
 * @param addr_prefix address prefix for addresses supported by this
 *        communicator, could be NULL for incoming-only communicators
 * @param cc what characteristics does the communicator have?
 * @param mtu maximum message size supported by communicator, 0 if
 *            sending is not supported, SIZE_MAX for no MTU
 * @param mq_init function to call to initialize a message queue given
 *                the address of another peer, can be NULL if the
 *                communicator only supports receiving messages
 * @param mq_init_cls closure for @a mq_init
 * @param notify_cb function to pass backchannel messages to communicator
 * @param notify_cb_cls closure for @a notify_cb
 * @return NULL on error
 */
struct GNUNET_TRANSPORT_CommunicatorHandle *
GNUNET_TRANSPORT_communicator_connect (
  const struct GNUNET_CONFIGURATION_Handle *cfg,
  const char *config_section,
  const char *addr_prefix,
  enum GNUNET_TRANSPORT_CommunicatorCharacteristics cc,
  GNUNET_TRANSPORT_CommunicatorMqInit mq_init,
  void *mq_init_cls,
  GNUNET_TRANSPORT_CommunicatorNotify notify_cb,
  void *notify_cb_cls)
{
  struct GNUNET_TRANSPORT_CommunicatorHandle *ch;

  ch = GNUNET_new (struct GNUNET_TRANSPORT_CommunicatorHandle);
  ch->cfg = cfg;
  ch->config_section = config_section;
  ch->addr_prefix = addr_prefix;
  ch->mq_init = mq_init;
  ch->mq_init_cls = mq_init_cls;
  ch->notify_cb = notify_cb;
  ch->notify_cb_cls = notify_cb_cls;
  ch->cc = cc;
  reconnect (ch);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg,
                                             config_section,
                                             "MAX_QUEUE_LENGTH",
                                             &ch->max_queue_length))
    ch->max_queue_length = DEFAULT_MAX_QUEUE_LENGTH;
  if (NULL == ch->mq)
  {
    GNUNET_free (ch);
    return NULL;
  }
  return ch;
}


/**
 * Disconnect from the transport service.
 *
 * @param ch handle returned from connect
 */
void
GNUNET_TRANSPORT_communicator_disconnect (
  struct GNUNET_TRANSPORT_CommunicatorHandle *ch)
{
  disconnect (ch);
  while (NULL != ch->ai_head)
  {
    GNUNET_break (0);  /* communicator forgot to remove address, warn! */
    GNUNET_TRANSPORT_communicator_address_remove (ch->ai_head);
  }
  GNUNET_free (ch);
}


/* ************************* Receiving *************************** */


/**
 * Notify transport service that the communicator has received
 * a message.
 *
 * @param ch connection to transport service
 * @param sender presumed sender of the message (details to be checked
 *        by higher layers)
 * @param msg the message
 * @param expected_addr_validity how long does the communicator believe it
 *        will continue to be able to receive messages from the same address
 *        on which it received this message?
 * @param cb function to call once handling the message is done, NULL if
 *         flow control is not supported by this communicator
 * @param cb_cls closure for @a cb
 * @return #GNUNET_OK if all is well, #GNUNET_NO if the message was
 *         immediately dropped due to memory limitations (communicator
 *         should try to apply back pressure),
 *         #GNUNET_SYSERR if the message could not be delivered because
 *         the tranport service is not yet up
 */
int
GNUNET_TRANSPORT_communicator_receive (
  struct GNUNET_TRANSPORT_CommunicatorHandle *ch,
  const struct GNUNET_PeerIdentity *sender,
  const struct GNUNET_MessageHeader *msg,
  struct GNUNET_TIME_Relative expected_addr_validity,
  GNUNET_TRANSPORT_MessageCompletedCallback cb,
  void *cb_cls)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_TRANSPORT_IncomingMessage *im;
  uint16_t msize;

  if (NULL == ch->mq)
    return GNUNET_SYSERR;
  if ((NULL == cb) && (GNUNET_MQ_get_length (ch->mq) >= ch->max_queue_length))
  {
    GNUNET_log (
      GNUNET_ERROR_TYPE_WARNING,
      "Dropping message: transport is too slow, queue length %llu exceeded\n",
      ch->max_queue_length);
    return GNUNET_NO;
  }

  msize = ntohs (msg->size);
  env =
    GNUNET_MQ_msg_extra (im, msize, GNUNET_MESSAGE_TYPE_TRANSPORT_INCOMING_MSG);
  if (NULL == env)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  im->expected_address_validity =
    GNUNET_TIME_relative_hton (expected_addr_validity);
  im->sender = *sender;
  // FIXME: this is expensive, would be better if we would
  // re-design the API to allow us to create the envelope first,
  // and then have the application fill in the body so we do
  // not have to memcpy()
  memcpy (&im[1], msg, msize);
  im->fc_on = htonl (GNUNET_NO);
  if (NULL != cb)
  {
    struct FlowControl *fc;

    im->fc_on = htonl (GNUNET_YES);
    im->fc_id = ch->fc_gen++;
    fc = GNUNET_new (struct FlowControl);
    fc->sender = *sender;
    fc->id = im->fc_id;
    fc->cb = cb;
    fc->cb_cls = cb_cls;
    GNUNET_CONTAINER_DLL_insert (ch->fc_head, ch->fc_tail, fc);
  }
  GNUNET_MQ_send (ch->mq, env);
  return GNUNET_OK;
}


/* ************************* Discovery *************************** */


/**
 * Notify transport service that an MQ became available due to an
 * "inbound" connection or because the communicator discovered the
 * presence of another peer.
 *
 * @param ch connection to transport service
 * @param peer peer with which we can now communicate
 * @param address address in human-readable format, 0-terminated, UTF-8
 * @param mtu maximum message size supported by queue, 0 if
 *            sending is not supported, SIZE_MAX for no MTU
 * @param q_len number of messages that can be send through this queue
 * @param priority queue priority. Queues with highest priority should be
 *                 used
 * @param nt which network type does the @a address belong to?
 * @param cc what characteristics does the communicator have?
 * @param cs what is the connection status of the queue?
 * @param mq message queue of the @a peer
 * @return API handle identifying the new MQ
 */
struct GNUNET_TRANSPORT_QueueHandle *
GNUNET_TRANSPORT_communicator_mq_add (
  struct GNUNET_TRANSPORT_CommunicatorHandle *ch,
  const struct GNUNET_PeerIdentity *peer,
  const char *address,
  uint32_t mtu,
  uint64_t q_len,
  uint32_t priority,
  enum GNUNET_NetworkType nt,
  enum GNUNET_TRANSPORT_ConnectionStatus cs,
  struct GNUNET_MQ_Handle *mq)
{
  struct GNUNET_TRANSPORT_QueueHandle *qh;

  qh = GNUNET_new (struct GNUNET_TRANSPORT_QueueHandle);
  qh->ch = ch;
  qh->peer = *peer;
  qh->address = GNUNET_strdup (address);
  qh->nt = nt;
  qh->mtu = mtu;
  qh->q_len = q_len;
  qh->priority = priority;
  qh->cs = cs;
  qh->mq = mq;
  qh->queue_id = ch->queue_gen++;
  GNUNET_CONTAINER_DLL_insert (ch->queue_head, ch->queue_tail, qh);
  send_add_queue (qh);
  return qh;
}


/**
 * Notify transport service that an MQ was updated
 *
 * @param ch connection to transport service
 * @param qh the queue to update
 * @param q_len number of messages that can be send through this queue
 * @param priority queue priority. Queues with highest priority should be
 *                 used
 */
void
GNUNET_TRANSPORT_communicator_mq_update (
  struct GNUNET_TRANSPORT_CommunicatorHandle *ch,
  const struct GNUNET_TRANSPORT_QueueHandle *u_qh,
  uint64_t q_len,
  uint32_t priority)
{
  struct GNUNET_TRANSPORT_QueueHandle *qh;

  for (qh = ch->queue_head; NULL != qh; qh = qh->next)
  {
    if (u_qh == qh)
      break;
  }
  GNUNET_assert (NULL != qh);
  qh->q_len = q_len;
  qh->priority = priority;
  send_update_queue (qh);
}



/**
 * Notify transport service that an MQ became unavailable due to a
 * disconnect or timeout.
 *
 * @param qh handle for the queue that must be invalidated
 */
void
GNUNET_TRANSPORT_communicator_mq_del (struct GNUNET_TRANSPORT_QueueHandle *qh)
{
  struct GNUNET_TRANSPORT_CommunicatorHandle *ch = qh->ch;

  send_del_queue (qh);
  GNUNET_CONTAINER_DLL_remove (ch->queue_head, ch->queue_tail, qh);
  GNUNET_MQ_destroy (qh->mq);
  GNUNET_free (qh->address);
  GNUNET_free (qh);
}


/**
 * Notify transport service about an address that this communicator
 * provides for this peer.
 *
 * @param ch connection to transport service
 * @param address our address in human-readable format, 0-terminated, UTF-8
 * @param nt which network type does the address belong to?
 * @param expiration when does the communicator forsee this address expiring?
 */
struct GNUNET_TRANSPORT_AddressIdentifier *
GNUNET_TRANSPORT_communicator_address_add (
  struct GNUNET_TRANSPORT_CommunicatorHandle *ch,
  const char *address,
  enum GNUNET_NetworkType nt,
  struct GNUNET_TIME_Relative expiration)
{
  struct GNUNET_TRANSPORT_AddressIdentifier *ai;

  ai = GNUNET_new (struct GNUNET_TRANSPORT_AddressIdentifier);
  ai->ch = ch;
  ai->address = GNUNET_strdup (address);
  ai->nt = nt;
  ai->expiration = expiration;
  ai->aid = ch->aid_gen++;
  GNUNET_CONTAINER_DLL_insert (ch->ai_head, ch->ai_tail, ai);
  send_add_address (ai);
  return ai;
}


/**
 * Notify transport service about an address that this communicator no
 * longer provides for this peer.
 *
 * @param ai address that is no longer provided
 */
void
GNUNET_TRANSPORT_communicator_address_remove (
  struct GNUNET_TRANSPORT_AddressIdentifier *ai)
{
  struct GNUNET_TRANSPORT_CommunicatorHandle *ch = ai->ch;

  send_del_address (ai);
  GNUNET_CONTAINER_DLL_remove (ch->ai_head, ch->ai_tail, ai);
  GNUNET_free (ai->address);
  GNUNET_free (ai);
}


/* ************************* Backchannel *************************** */


/**
 * The communicator asks the transport service to route a message via
 * a different path to another communicator service at another peer.
 * This must only be done for special control traffic (as there is no
 * flow control for this API), such as acknowledgements, and generally
 * only be done if the communicator is uni-directional (i.e. cannot
 * send the message back itself).
 *
 * @param ch handle of this communicator
 * @param pid peer to send the message to
 * @param comm name of the communicator to send the message to
 * @param header header of the message to transmit and pass via the
 *        notify-API to @a pid's communicator @a comm
 */
void
GNUNET_TRANSPORT_communicator_notify (
  struct GNUNET_TRANSPORT_CommunicatorHandle *ch,
  const struct GNUNET_PeerIdentity *pid,
  const char *comm,
  const struct GNUNET_MessageHeader *header)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_TRANSPORT_CommunicatorBackchannel *cb;
  size_t slen = strlen (comm) + 1;
  uint16_t mlen = ntohs (header->size);

  GNUNET_assert (mlen + slen + sizeof(*cb) < UINT16_MAX);
  env =
    GNUNET_MQ_msg_extra (cb,
                         slen + mlen,
                         GNUNET_MESSAGE_TYPE_TRANSPORT_COMMUNICATOR_BACKCHANNEL);
  cb->pid = *pid;
  memcpy (&cb[1], header, mlen);
  memcpy (((char *) &cb[1]) + mlen, comm, slen);
  GNUNET_MQ_send (ch->mq, env);
}


/* end of transport_api2_communication.c */
