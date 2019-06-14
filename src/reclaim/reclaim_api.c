/*
   This file is part of GNUnet.
   Copyright (C) 2016 GNUnet e.V.

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
 * @file reclaim/reclaim_api.c
 * @brief api to interact with the reclaim service
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_mq_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_reclaim_attribute_lib.h"
#include "gnunet_reclaim_service.h"
#include "reclaim.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "reclaim-api", __VA_ARGS__)


/**
 * Handle for an operation with the service.
 */
struct GNUNET_RECLAIM_Operation
{

  /**
   * Main handle.
   */
  struct GNUNET_RECLAIM_Handle *h;

  /**
   * We keep operations in a DLL.
   */
  struct GNUNET_RECLAIM_Operation *next;

  /**
   * We keep operations in a DLL.
   */
  struct GNUNET_RECLAIM_Operation *prev;

  /**
   * Message to send to the service.
   * Allocated at the end of this struct.
   */
  const struct GNUNET_MessageHeader *msg;

  /**
   * Continuation to invoke after attribute store call
   */
  GNUNET_RECLAIM_ContinuationWithStatus as_cb;

  /**
   * Attribute result callback
   */
  GNUNET_RECLAIM_AttributeResult ar_cb;

  /**
   * Revocation result callback
   */
  GNUNET_RECLAIM_ContinuationWithStatus rvk_cb;

  /**
   * Ticket result callback
   */
  GNUNET_RECLAIM_TicketCallback tr_cb;

  /**
   * Envelope with the message for this queue entry.
   */
  struct GNUNET_MQ_Envelope *env;

  /**
   * request id
   */
  uint32_t r_id;

  /**
   * Closure for @e cont or @e cb.
   */
  void *cls;
};


/**
 * Handle for a ticket iterator operation
 */
struct GNUNET_RECLAIM_TicketIterator
{

  /**
   * Kept in a DLL.
   */
  struct GNUNET_RECLAIM_TicketIterator *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_RECLAIM_TicketIterator *prev;

  /**
   * Main handle to access the idp.
   */
  struct GNUNET_RECLAIM_Handle *h;

  /**
   * Function to call on completion.
   */
  GNUNET_SCHEDULER_TaskCallback finish_cb;

  /**
   * Closure for @e finish_cb.
   */
  void *finish_cb_cls;

  /**
   * The continuation to call with the results
   */
  GNUNET_RECLAIM_TicketCallback tr_cb;

  /**
   * Closure for @e tr_cb.
   */
  void *cls;

  /**
   * Function to call on errors.
   */
  GNUNET_SCHEDULER_TaskCallback error_cb;

  /**
   * Closure for @e error_cb.
   */
  void *error_cb_cls;

  /**
   * Envelope of the message to send to the service, if not yet
   * sent.
   */
  struct GNUNET_MQ_Envelope *env;

  /**
   * The operation id this zone iteration operation has
   */
  uint32_t r_id;
};


/**
 * Handle for a attribute iterator operation
 */
struct GNUNET_RECLAIM_AttributeIterator
{

  /**
   * Kept in a DLL.
   */
  struct GNUNET_RECLAIM_AttributeIterator *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_RECLAIM_AttributeIterator *prev;

  /**
   * Main handle to access the service.
   */
  struct GNUNET_RECLAIM_Handle *h;

  /**
   * Function to call on completion.
   */
  GNUNET_SCHEDULER_TaskCallback finish_cb;

  /**
   * Closure for @e finish_cb.
   */
  void *finish_cb_cls;

  /**
   * The continuation to call with the results
   */
  GNUNET_RECLAIM_AttributeResult proc;

  /**
   * Closure for @e proc.
   */
  void *proc_cls;

  /**
   * Function to call on errors.
   */
  GNUNET_SCHEDULER_TaskCallback error_cb;

  /**
   * Closure for @e error_cb.
   */
  void *error_cb_cls;

  /**
   * Envelope of the message to send to the service, if not yet
   * sent.
   */
  struct GNUNET_MQ_Envelope *env;

  /**
   * Private key of the zone.
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey identity;

  /**
   * The operation id this zone iteration operation has
   */
  uint32_t r_id;
};


/**
 * Handle to the service.
 */
struct GNUNET_RECLAIM_Handle
{
  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Socket (if available).
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Closure for 'cb'.
   */
  void *cb_cls;

  /**
   * Head of active operations.
   */
  struct GNUNET_RECLAIM_Operation *op_head;

  /**
   * Tail of active operations.
   */
  struct GNUNET_RECLAIM_Operation *op_tail;

  /**
   * Head of active iterations
   */
  struct GNUNET_RECLAIM_AttributeIterator *it_head;

  /**
   * Tail of active iterations
   */
  struct GNUNET_RECLAIM_AttributeIterator *it_tail;

  /**
   * Head of active iterations
   */
  struct GNUNET_RECLAIM_TicketIterator *ticket_it_head;

  /**
   * Tail of active iterations
   */
  struct GNUNET_RECLAIM_TicketIterator *ticket_it_tail;

  /**
   * Currently pending transmission request, or NULL for none.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * Task doing exponential back-off trying to reconnect.
   */
  struct GNUNET_SCHEDULER_Task *reconnect_task;

  /**
   * Time for next connect retry.
   */
  struct GNUNET_TIME_Relative reconnect_backoff;

  /**
   * Connection to service (if available).
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Request Id generator.  Incremented by one for each request.
   */
  uint32_t r_id_gen;

  /**
   * Are we polling for incoming messages right now?
   */
  int in_receive;
};


/**
 * Try again to connect to the service.
 *
 * @param h handle to the reclaim service.
 */
static void
reconnect (struct GNUNET_RECLAIM_Handle *h);


/**
 * Reconnect
 *
 * @param cls the handle
 */
static void
reconnect_task (void *cls)
{
  struct GNUNET_RECLAIM_Handle *handle = cls;

  handle->reconnect_task = NULL;
  reconnect (handle);
}


/**
 * Disconnect from service and then reconnect.
 *
 * @param handle our service
 */
static void
force_reconnect (struct GNUNET_RECLAIM_Handle *handle)
{
  GNUNET_MQ_destroy (handle->mq);
  handle->mq = NULL;
  handle->reconnect_backoff =
    GNUNET_TIME_STD_BACKOFF (handle->reconnect_backoff);
  handle->reconnect_task =
    GNUNET_SCHEDULER_add_delayed (handle->reconnect_backoff,
                                  &reconnect_task,
                                  handle);
}


/**
 * Free @a it.
 *
 * @param it entry to free
 */
static void
free_it (struct GNUNET_RECLAIM_AttributeIterator *it)
{
  struct GNUNET_RECLAIM_Handle *h = it->h;

  GNUNET_CONTAINER_DLL_remove (h->it_head, h->it_tail, it);
  if (NULL != it->env)
    GNUNET_MQ_discard (it->env);
  GNUNET_free (it);
}

/**
 * Free @a op
 *
 * @param op the operation to free
 */
static void
free_op (struct GNUNET_RECLAIM_Operation *op)
{
  if (NULL == op)
    return;
  if (NULL != op->env)
    GNUNET_MQ_discard (op->env);
  GNUNET_free (op);
}


/**
 * Generic error handler, called with the appropriate error code and
 * the same closure specified at the creation of the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_GNS_Handle *`
 * @param error error code
 */
static void
mq_error_handler (void *cls, enum GNUNET_MQ_Error error)
{
  struct GNUNET_RECLAIM_Handle *handle = cls;
  force_reconnect (handle);
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_RECLAIM_SUCCESS_RESPONSE
 *
 * @param cls
 * @param msg the message we received
 */
static void
handle_success_response (void *cls, const struct SuccessResultMessage *msg)
{
  struct GNUNET_RECLAIM_Handle *h = cls;
  struct GNUNET_RECLAIM_Operation *op;
  uint32_t r_id = ntohl (msg->id);
  int res;
  const char *emsg;

  for (op = h->op_head; NULL != op; op = op->next)
    if (op->r_id == r_id)
      break;
  if (NULL == op)
    return;

  res = ntohl (msg->op_result);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received SUCCESS_RESPONSE with result %d\n",
       res);

  /* TODO: add actual error message to response... */
  if (GNUNET_SYSERR == res)
    emsg = _ ("failed to store record\n");
  else
    emsg = NULL;
  if (NULL != op->as_cb)
    op->as_cb (op->cls, res, emsg);
  GNUNET_CONTAINER_DLL_remove (h->op_head, h->op_tail, op);
  free_op (op);
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_RECLAIM_CONSUME_TICKET_RESULT
 *
 * @param cls
 * @param msg the message we received
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
check_consume_ticket_result (void *cls,
                             const struct ConsumeTicketResultMessage *msg)
{
  size_t msg_len;
  size_t attrs_len;

  msg_len = ntohs (msg->header.size);
  attrs_len = ntohs (msg->attrs_len);
  if (msg_len != sizeof (struct ConsumeTicketResultMessage) + attrs_len)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_RECLAIM_CONSUME_TICKET_RESULT
 *
 * @param cls
 * @param msg the message we received
 */
static void
handle_consume_ticket_result (void *cls,
                              const struct ConsumeTicketResultMessage *msg)
{
  struct GNUNET_RECLAIM_Handle *h = cls;
  struct GNUNET_RECLAIM_Operation *op;
  size_t attrs_len;
  uint32_t r_id = ntohl (msg->id);

  attrs_len = ntohs (msg->attrs_len);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Processing attribute result.\n");


  for (op = h->op_head; NULL != op; op = op->next)
    if (op->r_id == r_id)
      break;
  if (NULL == op)
    return;

  {
    struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs;
    struct GNUNET_RECLAIM_ATTRIBUTE_ClaimListEntry *le;
    attrs =
      GNUNET_RECLAIM_ATTRIBUTE_list_deserialize ((char *) &msg[1], attrs_len);
    if (NULL != op->ar_cb)
    {
      if (NULL == attrs)
      {
        op->ar_cb (op->cls, &msg->identity, NULL);
      }
      else
      {
        for (le = attrs->list_head; NULL != le; le = le->next)
          op->ar_cb (op->cls, &msg->identity, le->claim);
        GNUNET_RECLAIM_ATTRIBUTE_list_destroy (attrs);
        attrs = NULL;
      }
      op->ar_cb (op->cls, NULL, NULL);
    }
    GNUNET_CONTAINER_DLL_remove (h->op_head, h->op_tail, op);
    free_op (op);
    GNUNET_free_non_null (attrs);
    return;
  }
  GNUNET_assert (0);
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_RESULT
 *
 * @param cls
 * @param msg the message we received
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
check_attribute_result (void *cls, const struct AttributeResultMessage *msg)
{
  size_t msg_len;
  size_t attr_len;

  msg_len = ntohs (msg->header.size);
  attr_len = ntohs (msg->attr_len);
  if (msg_len != sizeof (struct AttributeResultMessage) + attr_len)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_RESULT
 *
 * @param cls
 * @param msg the message we received
 */
static void
handle_attribute_result (void *cls, const struct AttributeResultMessage *msg)
{
  static struct GNUNET_CRYPTO_EcdsaPrivateKey identity_dummy;
  struct GNUNET_RECLAIM_Handle *h = cls;
  struct GNUNET_RECLAIM_AttributeIterator *it;
  struct GNUNET_RECLAIM_Operation *op;
  size_t attr_len;
  uint32_t r_id = ntohl (msg->id);

  attr_len = ntohs (msg->attr_len);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Processing attribute result.\n");


  for (it = h->it_head; NULL != it; it = it->next)
    if (it->r_id == r_id)
      break;
  for (op = h->op_head; NULL != op; op = op->next)
    if (op->r_id == r_id)
      break;
  if ((NULL == it) && (NULL == op))
    return;

  if ((0 ==
       (memcmp (&msg->identity, &identity_dummy, sizeof (identity_dummy)))))
  {
    if ((NULL == it) && (NULL == op))
    {
      GNUNET_break (0);
      force_reconnect (h);
      return;
    }
    if (NULL != it)
    {
      if (NULL != it->finish_cb)
        it->finish_cb (it->finish_cb_cls);
      free_it (it);
    }
    if (NULL != op)
    {
      if (NULL != op->ar_cb)
        op->ar_cb (op->cls, NULL, NULL);
      GNUNET_CONTAINER_DLL_remove (h->op_head, h->op_tail, op);
      free_op (op);
    }
    return;
  }

  {
    struct GNUNET_RECLAIM_ATTRIBUTE_Claim *attr;
    attr = GNUNET_RECLAIM_ATTRIBUTE_deserialize ((char *) &msg[1], attr_len);
    if (NULL != it)
    {
      if (NULL != it->proc)
        it->proc (it->proc_cls, &msg->identity, attr);
    }
    else if (NULL != op)
    {
      if (NULL != op->ar_cb)
        op->ar_cb (op->cls, &msg->identity, attr);
    }
    GNUNET_free (attr);
    return;
  }
  GNUNET_assert (0);
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_RESULT
 *
 * @param cls
 * @param msg the message we received
 */
static void
handle_ticket_result (void *cls, const struct TicketResultMessage *msg)
{
  struct GNUNET_RECLAIM_Handle *handle = cls;
  struct GNUNET_RECLAIM_Operation *op;
  struct GNUNET_RECLAIM_TicketIterator *it;
  uint32_t r_id = ntohl (msg->id);
  static const struct GNUNET_RECLAIM_Ticket ticket;
  for (op = handle->op_head; NULL != op; op = op->next)
    if (op->r_id == r_id)
      break;
  for (it = handle->ticket_it_head; NULL != it; it = it->next)
    if (it->r_id == r_id)
      break;
  if ((NULL == op) && (NULL == it))
    return;
  if (NULL != op)
  {
    GNUNET_CONTAINER_DLL_remove (handle->op_head, handle->op_tail, op);
    if (0 ==
        memcmp (&msg->ticket, &ticket, sizeof (struct GNUNET_RECLAIM_Ticket)))
    {
      if (NULL != op->tr_cb)
        op->tr_cb (op->cls, NULL);
    }
    else
    {
      if (NULL != op->tr_cb)
        op->tr_cb (op->cls, &msg->ticket);
    }
    free_op (op);
    return;
  }
  else if (NULL != it)
  {
    if (0 ==
        memcmp (&msg->ticket, &ticket, sizeof (struct GNUNET_RECLAIM_Ticket)))
    {
      GNUNET_CONTAINER_DLL_remove (handle->ticket_it_head,
                                   handle->ticket_it_tail,
                                   it);
      it->finish_cb (it->finish_cb_cls);
      GNUNET_free (it);
    }
    else
    {
      if (NULL != it->tr_cb)
        it->tr_cb (it->cls, &msg->ticket);
    }
    return;
  }
  GNUNET_break (0);
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_RECLAIM_REVOKE_TICKET_RESULT
 *
 * @param cls
 * @param msg the message we received
 */
static void
handle_revoke_ticket_result (void *cls,
                             const struct RevokeTicketResultMessage *msg)
{
  struct GNUNET_RECLAIM_Handle *h = cls;
  struct GNUNET_RECLAIM_Operation *op;
  uint32_t r_id = ntohl (msg->id);
  int32_t success;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Processing revocation result.\n");


  for (op = h->op_head; NULL != op; op = op->next)
    if (op->r_id == r_id)
      break;
  if (NULL == op)
    return;
  success = ntohl (msg->success);
  {
    if (NULL != op->rvk_cb)
    {
      op->rvk_cb (op->cls, success, NULL);
    }
    GNUNET_CONTAINER_DLL_remove (h->op_head, h->op_tail, op);
    free_op (op);
    return;
  }
  GNUNET_assert (0);
}


/**
 * Try again to connect to the service.
 *
 * @param h handle to the reclaim service.
 */
static void
reconnect (struct GNUNET_RECLAIM_Handle *h)
{
  struct GNUNET_MQ_MessageHandler handlers[] =
    {GNUNET_MQ_hd_fixed_size (success_response,
                              GNUNET_MESSAGE_TYPE_RECLAIM_SUCCESS_RESPONSE,
                              struct SuccessResultMessage,
                              h),
     GNUNET_MQ_hd_var_size (attribute_result,
                            GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_RESULT,
                            struct AttributeResultMessage,
                            h),
     GNUNET_MQ_hd_fixed_size (ticket_result,
                              GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_RESULT,
                              struct TicketResultMessage,
                              h),
     GNUNET_MQ_hd_var_size (consume_ticket_result,
                            GNUNET_MESSAGE_TYPE_RECLAIM_CONSUME_TICKET_RESULT,
                            struct ConsumeTicketResultMessage,
                            h),
     GNUNET_MQ_hd_fixed_size (revoke_ticket_result,
                              GNUNET_MESSAGE_TYPE_RECLAIM_REVOKE_TICKET_RESULT,
                              struct RevokeTicketResultMessage,
                              h),
     GNUNET_MQ_handler_end ()};
  struct GNUNET_RECLAIM_Operation *op;

  GNUNET_assert (NULL == h->mq);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Connecting to reclaim service.\n");

  h->mq =
    GNUNET_CLIENT_connect (h->cfg, "reclaim", handlers, &mq_error_handler, h);
  if (NULL == h->mq)
    return;
  for (op = h->op_head; NULL != op; op = op->next)
    GNUNET_MQ_send_copy (h->mq, op->env);
}


/**
 * Connect to the reclaim service.
 *
 * @param cfg the configuration to use
 * @return handle to use
 */
struct GNUNET_RECLAIM_Handle *
GNUNET_RECLAIM_connect (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_RECLAIM_Handle *h;

  h = GNUNET_new (struct GNUNET_RECLAIM_Handle);
  h->cfg = cfg;
  reconnect (h);
  if (NULL == h->mq)
  {
    GNUNET_free (h);
    return NULL;
  }
  return h;
}


/**
 * Cancel an operation. Note that the operation MAY still
 * be executed; this merely cancels the continuation; if the request
 * was already transmitted, the service may still choose to complete
 * the operation.
 *
 * @param op operation to cancel
 */
void
GNUNET_RECLAIM_cancel (struct GNUNET_RECLAIM_Operation *op)
{
  struct GNUNET_RECLAIM_Handle *h = op->h;

  GNUNET_CONTAINER_DLL_remove (h->op_head, h->op_tail, op);
  free_op (op);
}


/**
 * Disconnect from service
 *
 * @param h handle to destroy
 */
void
GNUNET_RECLAIM_disconnect (struct GNUNET_RECLAIM_Handle *h)
{
  GNUNET_assert (NULL != h);
  if (NULL != h->mq)
  {
    GNUNET_MQ_destroy (h->mq);
    h->mq = NULL;
  }
  if (NULL != h->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (h->reconnect_task);
    h->reconnect_task = NULL;
  }
  GNUNET_assert (NULL == h->op_head);
  GNUNET_free (h);
}

/**
 * Store an attribute.  If the attribute is already present,
 * it is replaced with the new attribute.
 *
 * @param h handle to the re:claimID service
 * @param pkey private key of the identity
 * @param attr the attribute value
 * @param exp_interval the relative expiration interval for the attribute
 * @param cont continuation to call when done
 * @param cont_cls closure for @a cont
 * @return handle to abort the request
 */
struct GNUNET_RECLAIM_Operation *
GNUNET_RECLAIM_attribute_store (
  struct GNUNET_RECLAIM_Handle *h,
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *pkey,
  const struct GNUNET_RECLAIM_ATTRIBUTE_Claim *attr,
  const struct GNUNET_TIME_Relative *exp_interval,
  GNUNET_RECLAIM_ContinuationWithStatus cont,
  void *cont_cls)
{
  struct GNUNET_RECLAIM_Operation *op;
  struct AttributeStoreMessage *sam;
  size_t attr_len;

  op = GNUNET_new (struct GNUNET_RECLAIM_Operation);
  op->h = h;
  op->as_cb = cont;
  op->cls = cont_cls;
  op->r_id = h->r_id_gen++;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, op);
  attr_len = GNUNET_RECLAIM_ATTRIBUTE_serialize_get_size (attr);
  op->env = GNUNET_MQ_msg_extra (sam,
                                 attr_len,
                                 GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_STORE);
  sam->identity = *pkey;
  sam->id = htonl (op->r_id);
  sam->exp = GNUNET_htonll (exp_interval->rel_value_us);

  GNUNET_RECLAIM_ATTRIBUTE_serialize (attr, (char *) &sam[1]);

  sam->attr_len = htons (attr_len);
  if (NULL != h->mq)
    GNUNET_MQ_send_copy (h->mq, op->env);
  return op;
}


/**
 * Delete an attribute. Tickets used to share this attribute are updated
 * accordingly.
 *
 * @param h handle to the re:claimID service
 * @param pkey Private key of the identity to add an attribute to
 * @param attr The attribute
 * @param cont Continuation to call when done
 * @param cont_cls Closure for @a cont
 * @return handle Used to to abort the request
 */
struct GNUNET_RECLAIM_Operation *
GNUNET_RECLAIM_attribute_delete (
  struct GNUNET_RECLAIM_Handle *h,
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *pkey,
  const struct GNUNET_RECLAIM_ATTRIBUTE_Claim *attr,
  GNUNET_RECLAIM_ContinuationWithStatus cont,
  void *cont_cls)
{
  struct GNUNET_RECLAIM_Operation *op;
  struct AttributeDeleteMessage *dam;
  size_t attr_len;

  op = GNUNET_new (struct GNUNET_RECLAIM_Operation);
  op->h = h;
  op->as_cb = cont;
  op->cls = cont_cls;
  op->r_id = h->r_id_gen++;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, op);
  attr_len = GNUNET_RECLAIM_ATTRIBUTE_serialize_get_size (attr);
  op->env = GNUNET_MQ_msg_extra (dam,
                                 attr_len,
                                 GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_DELETE);
  dam->identity = *pkey;
  dam->id = htonl (op->r_id);
  GNUNET_RECLAIM_ATTRIBUTE_serialize (attr, (char *) &dam[1]);

  dam->attr_len = htons (attr_len);
  if (NULL != h->mq)
    GNUNET_MQ_send_copy (h->mq, op->env);
  return op;
}


/**
 * List all attributes for a local identity.
 * This MUST lock the `struct GNUNET_RECLAIM_Handle`
 * for any other calls than #GNUNET_RECLAIM_get_attributes_next() and
 * #GNUNET_RECLAIM_get_attributes_stop. @a proc will be called once
 * immediately, and then again after
 * #GNUNET_RECLAIM_get_attributes_next() is invoked.
 *
 * On error (disconnect), @a error_cb will be invoked.
 * On normal completion, @a finish_cb proc will be
 * invoked.
 *
 * @param h Handle to the re:claimID service
 * @param identity Identity to iterate over
 * @param error_cb Function to call on error (i.e. disconnect),
 *        the handle is afterwards invalid
 * @param error_cb_cls Closure for @a error_cb
 * @param proc Function to call on each attribute
 * @param proc_cls Closure for @a proc
 * @param finish_cb Function to call on completion
 *        the handle is afterwards invalid
 * @param finish_cb_cls Closure for @a finish_cb
 * @return an iterator Handle to use for iteration
 */
struct GNUNET_RECLAIM_AttributeIterator *
GNUNET_RECLAIM_get_attributes_start (
  struct GNUNET_RECLAIM_Handle *h,
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *identity,
  GNUNET_SCHEDULER_TaskCallback error_cb,
  void *error_cb_cls,
  GNUNET_RECLAIM_AttributeResult proc,
  void *proc_cls,
  GNUNET_SCHEDULER_TaskCallback finish_cb,
  void *finish_cb_cls)
{
  struct GNUNET_RECLAIM_AttributeIterator *it;
  struct GNUNET_MQ_Envelope *env;
  struct AttributeIterationStartMessage *msg;
  uint32_t rid;

  rid = h->r_id_gen++;
  it = GNUNET_new (struct GNUNET_RECLAIM_AttributeIterator);
  it->h = h;
  it->error_cb = error_cb;
  it->error_cb_cls = error_cb_cls;
  it->finish_cb = finish_cb;
  it->finish_cb_cls = finish_cb_cls;
  it->proc = proc;
  it->proc_cls = proc_cls;
  it->r_id = rid;
  it->identity = *identity;
  GNUNET_CONTAINER_DLL_insert_tail (h->it_head, h->it_tail, it);
  env =
    GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_ITERATION_START);
  msg->id = htonl (rid);
  msg->identity = *identity;
  if (NULL == h->mq)
    it->env = env;
  else
    GNUNET_MQ_send (h->mq, env);
  return it;
}


/**
 * Calls the record processor specified in #GNUNET_RECLAIM_get_attributes_start
 * for the next record.
 *
 * @param it the iterator
 */
void
GNUNET_RECLAIM_get_attributes_next (struct GNUNET_RECLAIM_AttributeIterator *it)
{
  struct GNUNET_RECLAIM_Handle *h = it->h;
  struct AttributeIterationNextMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  env =
    GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_ITERATION_NEXT);
  msg->id = htonl (it->r_id);
  GNUNET_MQ_send (h->mq, env);
}


/**
 * Stops iteration and releases the handle for further calls. Must
 * be called on any iteration that has not yet completed prior to calling
 * #GNUNET_RECLAIM_disconnect.
 *
 * @param it the iterator
 */
void
GNUNET_RECLAIM_get_attributes_stop (struct GNUNET_RECLAIM_AttributeIterator *it)
{
  struct GNUNET_RECLAIM_Handle *h = it->h;
  struct GNUNET_MQ_Envelope *env;
  struct AttributeIterationStopMessage *msg;

  if (NULL != h->mq)
  {
    env =
      GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_ITERATION_STOP);
    msg->id = htonl (it->r_id);
    GNUNET_MQ_send (h->mq, env);
  }
  free_it (it);
}


/**
 * Issues a ticket to another relying party. The identity may use
 * @GNUNET_RECLAIM_ticket_consume to consume the ticket
 * and retrieve the attributes specified in the attribute list.
 *
 * @param h the reclaim to use
 * @param iss the issuing identity (= the user)
 * @param rp the subject of the ticket (= the relying party)
 * @param attrs the attributes that the relying party is given access to
 * @param cb the callback
 * @param cb_cls the callback closure
 * @return handle to abort the operation
 */
struct GNUNET_RECLAIM_Operation *
GNUNET_RECLAIM_ticket_issue (
  struct GNUNET_RECLAIM_Handle *h,
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *iss,
  const struct GNUNET_CRYPTO_EcdsaPublicKey *rp,
  const struct GNUNET_RECLAIM_ATTRIBUTE_ClaimList *attrs,
  GNUNET_RECLAIM_TicketCallback cb,
  void *cb_cls)
{
  struct GNUNET_RECLAIM_Operation *op;
  struct IssueTicketMessage *tim;
  size_t attr_len;
  fprintf (stderr, "Issuing ticket\n");
  op = GNUNET_new (struct GNUNET_RECLAIM_Operation);
  op->h = h;
  op->tr_cb = cb;
  op->cls = cb_cls;
  op->r_id = h->r_id_gen++;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, op);
  attr_len = GNUNET_RECLAIM_ATTRIBUTE_list_serialize_get_size (attrs);
  op->env = GNUNET_MQ_msg_extra (tim,
                                 attr_len,
                                 GNUNET_MESSAGE_TYPE_RECLAIM_ISSUE_TICKET);
  tim->identity = *iss;
  tim->rp = *rp;
  tim->id = htonl (op->r_id);

  GNUNET_RECLAIM_ATTRIBUTE_list_serialize (attrs, (char *) &tim[1]);

  tim->attr_len = htons (attr_len);
  if (NULL != h->mq)
    GNUNET_MQ_send_copy (h->mq, op->env);
  return op;
}


/**
 * Consumes an issued ticket. The ticket is persisted
 * and used to retrieve identity information from the issuer
 *
 * @param h the reclaim to use
 * @param identity the identity that is the subject of the issued ticket (the
 * relying party)
 * @param ticket the issued ticket to consume
 * @param cb the callback to call
 * @param cb_cls the callback closure
 * @return handle to abort the operation
 */
struct GNUNET_RECLAIM_Operation *
GNUNET_RECLAIM_ticket_consume (
  struct GNUNET_RECLAIM_Handle *h,
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *identity,
  const struct GNUNET_RECLAIM_Ticket *ticket,
  GNUNET_RECLAIM_AttributeResult cb,
  void *cb_cls)
{
  struct GNUNET_RECLAIM_Operation *op;
  struct ConsumeTicketMessage *ctm;

  op = GNUNET_new (struct GNUNET_RECLAIM_Operation);
  op->h = h;
  op->ar_cb = cb;
  op->cls = cb_cls;
  op->r_id = h->r_id_gen++;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, op);
  op->env = GNUNET_MQ_msg (ctm, GNUNET_MESSAGE_TYPE_RECLAIM_CONSUME_TICKET);
  ctm->identity = *identity;
  ctm->id = htonl (op->r_id);
  ctm->ticket = *ticket;
  if (NULL != h->mq)
    GNUNET_MQ_send_copy (h->mq, op->env);
  return op;
}


/**
 * Lists all tickets that have been issued to remote
 * identites (relying parties)
 *
 * @param h the reclaim to use
 * @param identity the issuing identity
 * @param error_cb function to call on error (i.e. disconnect),
 *        the handle is afterwards invalid
 * @param error_cb_cls closure for @a error_cb
 * @param proc function to call on each ticket; it
 *        will be called repeatedly with a value (if available)
 * @param proc_cls closure for @a proc
 * @param finish_cb function to call on completion
 *        the handle is afterwards invalid
 * @param finish_cb_cls closure for @a finish_cb
 * @return an iterator handle to use for iteration
 */
struct GNUNET_RECLAIM_TicketIterator *
GNUNET_RECLAIM_ticket_iteration_start (
  struct GNUNET_RECLAIM_Handle *h,
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *identity,
  GNUNET_SCHEDULER_TaskCallback error_cb,
  void *error_cb_cls,
  GNUNET_RECLAIM_TicketCallback proc,
  void *proc_cls,
  GNUNET_SCHEDULER_TaskCallback finish_cb,
  void *finish_cb_cls)
{
  struct GNUNET_RECLAIM_TicketIterator *it;
  struct GNUNET_MQ_Envelope *env;
  struct TicketIterationStartMessage *msg;
  uint32_t rid;

  rid = h->r_id_gen++;
  it = GNUNET_new (struct GNUNET_RECLAIM_TicketIterator);
  it->h = h;
  it->error_cb = error_cb;
  it->error_cb_cls = error_cb_cls;
  it->finish_cb = finish_cb;
  it->finish_cb_cls = finish_cb_cls;
  it->tr_cb = proc;
  it->cls = proc_cls;
  it->r_id = rid;
  GNUNET_CONTAINER_DLL_insert_tail (h->ticket_it_head, h->ticket_it_tail, it);
  env = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_ITERATION_START);
  msg->id = htonl (rid);
  msg->identity = *identity;
  if (NULL == h->mq)
    it->env = env;
  else
    GNUNET_MQ_send (h->mq, env);
  return it;
}


/**
 * Calls the ticket processor specified in
 * #GNUNET_RECLAIM_ticket_iteration_start for the next record.
 *
 * @param it the iterator
 */
void
GNUNET_RECLAIM_ticket_iteration_next (struct GNUNET_RECLAIM_TicketIterator *it)
{
  struct GNUNET_RECLAIM_Handle *h = it->h;
  struct TicketIterationNextMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  env = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_ITERATION_NEXT);
  msg->id = htonl (it->r_id);
  GNUNET_MQ_send (h->mq, env);
}


/**
 * Stops iteration and releases the handle for further calls.  Must
 * be called on any iteration that has not yet completed prior to calling
 * #GNUNET_RECLAIM_disconnect.
 *
 * @param it the iterator
 */
void
GNUNET_RECLAIM_ticket_iteration_stop (struct GNUNET_RECLAIM_TicketIterator *it)
{
  struct GNUNET_RECLAIM_Handle *h = it->h;
  struct GNUNET_MQ_Envelope *env;
  struct TicketIterationStopMessage *msg;

  if (NULL != h->mq)
  {
    env =
      GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_ITERATION_STOP);
    msg->id = htonl (it->r_id);
    GNUNET_MQ_send (h->mq, env);
  }
  GNUNET_free (it);
}


/**
 * Revoked an issued ticket. The relying party will be unable to retrieve
 * attributes. Other issued tickets remain unaffected.
 * This includes tickets issued to other relying parties as well as to
 * other tickets issued to the audience specified in this ticket.
 *
 * @param h the identity provider to use
 * @param identity the issuing identity
 * @param ticket the ticket to revoke
 * @param cb the callback
 * @param cb_cls the callback closure
 * @return handle to abort the operation
 */
struct GNUNET_RECLAIM_Operation *
GNUNET_RECLAIM_ticket_revoke (
  struct GNUNET_RECLAIM_Handle *h,
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *identity,
  const struct GNUNET_RECLAIM_Ticket *ticket,
  GNUNET_RECLAIM_ContinuationWithStatus cb,
  void *cb_cls)
{
  struct GNUNET_RECLAIM_Operation *op;
  struct RevokeTicketMessage *msg;
  uint32_t rid;

  rid = h->r_id_gen++;
  op = GNUNET_new (struct GNUNET_RECLAIM_Operation);
  op->h = h;
  op->rvk_cb = cb;
  op->cls = cb_cls;
  op->r_id = rid;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, op);
  op->env = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_RECLAIM_REVOKE_TICKET);
  msg->id = htonl (rid);
  msg->identity = *identity;
  msg->ticket = *ticket;
  if (NULL != h->mq)
  {
    GNUNET_MQ_send (h->mq, op->env);
    op->env = NULL;
  }
  return op;
}


/* end of reclaim_api.c */
