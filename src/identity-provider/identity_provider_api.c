/*
     This file is part of GNUnet.
     Copyright (C) 2016 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
*/

/**
 * @file identity-provider/identity_provider_api.c
 * @brief api to interact with the identity provider service
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_mq_lib.h"
#include "gnunet_identity_provider_service.h"
#include "gnunet_identity_attribute_lib.h"
#include "identity_provider.h"

#define LOG(kind,...) GNUNET_log_from (kind, "identity-api",__VA_ARGS__)


/**
 * Handle for an operation with the service.
 */
struct GNUNET_IDENTITY_PROVIDER_Operation
{

  /**
   * Main handle.
   */
  struct GNUNET_IDENTITY_PROVIDER_Handle *h;

  /**
   * We keep operations in a DLL.
   */
  struct GNUNET_IDENTITY_PROVIDER_Operation *next;

  /**
   * We keep operations in a DLL.
   */
  struct GNUNET_IDENTITY_PROVIDER_Operation *prev;

  /**
   * Message to send to the service.
   * Allocated at the end of this struct.
   */
  const struct GNUNET_MessageHeader *msg;

  /**
   * Continuation to invoke after attribute store call
   */
  GNUNET_IDENTITY_PROVIDER_ContinuationWithStatus as_cb;

  /**
   * Attribute result callback
   */
  GNUNET_IDENTITY_PROVIDER_AttributeResult ar_cb;

  /**
   * Revocation result callback
   */
  GNUNET_IDENTITY_PROVIDER_ContinuationWithStatus rvk_cb;

  /**
   * Ticket result callback
   */
  GNUNET_IDENTITY_PROVIDER_TicketCallback tr_cb;

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
struct GNUNET_IDENTITY_PROVIDER_TicketIterator
{

  /**
   * Kept in a DLL.
   */
  struct GNUNET_IDENTITY_PROVIDER_TicketIterator *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_IDENTITY_PROVIDER_TicketIterator *prev;

  /**
   * Main handle to access the idp.
   */
  struct GNUNET_IDENTITY_PROVIDER_Handle *h;

  /**
   * Function to call on completion.
   */
  GNUNET_SCHEDULER_TaskCallback finish_cb;

  /**
   * Closure for @e error_cb.
   */
  void *finish_cb_cls;

  /**
   * The continuation to call with the results
   */
  GNUNET_IDENTITY_PROVIDER_TicketCallback tr_cb;

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
struct GNUNET_IDENTITY_PROVIDER_AttributeIterator
{

  /**
   * Kept in a DLL.
   */
  struct GNUNET_IDENTITY_PROVIDER_AttributeIterator *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_IDENTITY_PROVIDER_AttributeIterator *prev;

  /**
   * Main handle to access the idp.
   */
  struct GNUNET_IDENTITY_PROVIDER_Handle *h;

  /**
   * Function to call on completion.
   */
  GNUNET_SCHEDULER_TaskCallback finish_cb;

  /**
   * Closure for @e error_cb.
   */
  void *finish_cb_cls;

  /**
   * The continuation to call with the results
   */
  GNUNET_IDENTITY_PROVIDER_AttributeResult proc;

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
 * Handle for the service.
 */
struct GNUNET_IDENTITY_PROVIDER_Handle
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
  struct GNUNET_IDENTITY_PROVIDER_Operation *op_head;

  /**
   * Tail of active operations.
   */
  struct GNUNET_IDENTITY_PROVIDER_Operation *op_tail;

  /**
   * Head of active iterations
   */
  struct GNUNET_IDENTITY_PROVIDER_AttributeIterator *it_head;

  /**
   * Tail of active iterations
   */
  struct GNUNET_IDENTITY_PROVIDER_AttributeIterator *it_tail;

  /**
   * Head of active iterations
   */
  struct GNUNET_IDENTITY_PROVIDER_TicketIterator *ticket_it_head;

  /**
   * Tail of active iterations
   */
  struct GNUNET_IDENTITY_PROVIDER_TicketIterator *ticket_it_tail;


  /**
   * Currently pending transmission request, or NULL for none.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * Task doing exponential back-off trying to reconnect.
   */
  struct GNUNET_SCHEDULER_Task * reconnect_task;

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
 * @param h handle to the identity provider service.
 */
static void
reconnect (struct GNUNET_IDENTITY_PROVIDER_Handle *h);

/**
 * Reconnect
 *
 * @param cls the handle
 */
static void
reconnect_task (void *cls)
{
  struct GNUNET_IDENTITY_PROVIDER_Handle *handle = cls;

  handle->reconnect_task = NULL;
  reconnect (handle);
}


/**
 * Disconnect from service and then reconnect.
 *
 * @param handle our service
 */
static void
force_reconnect (struct GNUNET_IDENTITY_PROVIDER_Handle *handle)
{
  GNUNET_MQ_destroy (handle->mq);
  handle->mq = NULL;
  handle->reconnect_backoff
    = GNUNET_TIME_STD_BACKOFF (handle->reconnect_backoff);
  handle->reconnect_task
    = GNUNET_SCHEDULER_add_delayed (handle->reconnect_backoff,
                                    &reconnect_task,
                                    handle);
}

/**
 * Free @a it.
 *
 * @param it entry to free
 */
static void
free_it (struct GNUNET_IDENTITY_PROVIDER_AttributeIterator *it)
{
  struct GNUNET_IDENTITY_PROVIDER_Handle *h = it->h;

  GNUNET_CONTAINER_DLL_remove (h->it_head,
                               h->it_tail,
                               it);
  if (NULL != it->env)
    GNUNET_MQ_discard (it->env);
  GNUNET_free (it);
}

static void
free_op (struct GNUNET_IDENTITY_PROVIDER_Operation* op)
{
  if (NULL == op)
    return;
  if (NULL != op->env)
    GNUNET_MQ_discard (op->env);
  GNUNET_free(op);
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
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_IDENTITY_PROVIDER_Handle *handle = cls;
  force_reconnect (handle);
}

/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_STORE_RESPONSE
 *
 * @param cls
 * @param msg the message we received
 */
static void
handle_attribute_store_response (void *cls,
			      const struct AttributeStoreResultMessage *msg)
{
  struct GNUNET_IDENTITY_PROVIDER_Handle *h = cls;
  struct GNUNET_IDENTITY_PROVIDER_Operation *op;
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
       "Received ATTRIBUTE_STORE_RESPONSE with result %d\n",
       res);

  /* TODO: add actual error message to response... */
  if (GNUNET_SYSERR == res)
    emsg = _("failed to store record\n");
  else
    emsg = NULL;
  if (NULL != op->as_cb)
    op->as_cb (op->cls,
              res,
              emsg);
  GNUNET_CONTAINER_DLL_remove (h->op_head,
                               h->op_tail,
                               op);
  free_op (op);

}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_CONSUME_TICKET_RESULT
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
 * #GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_CONSUME_TICKET_RESULT
 *
 * @param cls
 * @param msg the message we received
 */
static void
handle_consume_ticket_result (void *cls,
                              const struct ConsumeTicketResultMessage *msg)
{
  struct GNUNET_IDENTITY_PROVIDER_Handle *h = cls;
  struct GNUNET_IDENTITY_PROVIDER_Operation *op;
  size_t attrs_len;
  uint32_t r_id = ntohl (msg->id);

  attrs_len = ntohs (msg->attrs_len);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Processing attribute result.\n");


  for (op = h->op_head; NULL != op; op = op->next)
    if (op->r_id == r_id)
      break;
  if (NULL == op)
    return;

  {
    struct GNUNET_IDENTITY_ATTRIBUTE_ClaimList *attrs;
    struct GNUNET_IDENTITY_ATTRIBUTE_ClaimListEntry *le;
    attrs = GNUNET_IDENTITY_ATTRIBUTE_list_deserialize ((char*)&msg[1],
                                        attrs_len);
    if (NULL != op->ar_cb)
    {
      if (NULL == attrs)
      {
        op->ar_cb (op->cls,
                   &msg->identity,
                   NULL);
      }
      else
      {
        for (le = attrs->list_head; NULL != le; le = le->next)
          op->ar_cb (op->cls,
                     &msg->identity,
                     le->claim);
        GNUNET_IDENTITY_ATTRIBUTE_list_destroy (attrs);
      }
    }
    if (NULL != op)
    {
      op->ar_cb (op->cls,
                 NULL,
                 NULL);
      GNUNET_CONTAINER_DLL_remove (h->op_head,
                                   h->op_tail,
                                   op);
      free_op (op);
    }
    return;
  }
  GNUNET_assert (0);
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_ATTRIBUTE_RESULT
 *
 * @param cls
 * @param msg the message we received
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
check_attribute_result (void *cls,
                        const struct AttributeResultMessage *msg)
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
 * #GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_ATTRIBUTE_RESULT
 *
 * @param cls
 * @param msg the message we received
 */
static void
handle_attribute_result (void *cls,
                         const struct AttributeResultMessage *msg)
{
  static struct GNUNET_CRYPTO_EcdsaPrivateKey identity_dummy;
  struct GNUNET_IDENTITY_PROVIDER_Handle *h = cls;
  struct GNUNET_IDENTITY_PROVIDER_AttributeIterator *it;
  struct GNUNET_IDENTITY_PROVIDER_Operation *op;
  size_t attr_len;
  uint32_t r_id = ntohl (msg->id);

  attr_len = ntohs (msg->attr_len);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Processing attribute result.\n");


  for (it = h->it_head; NULL != it; it = it->next)
    if (it->r_id == r_id)
      break;
  for (op = h->op_head; NULL != op; op = op->next)
    if (op->r_id == r_id)
      break;
  if ((NULL == it) && (NULL == op))
    return;

  if ( (0 == (memcmp (&msg->identity,
                      &identity_dummy,
                      sizeof (identity_dummy)))) )
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
        op->ar_cb (op->cls,
                   NULL,
                   NULL);
      GNUNET_CONTAINER_DLL_remove (h->op_head,
                                   h->op_tail,
                                   op);
      free_op (op);

    }
    return;
  }

  {
    struct GNUNET_IDENTITY_ATTRIBUTE_Claim *attr;
    attr = GNUNET_IDENTITY_ATTRIBUTE_deserialize ((char*)&msg[1],
                                                  attr_len);
    if (NULL != it)
    {
      if (NULL != it->proc)
        it->proc (it->proc_cls,
                  &msg->identity,
                  attr);
    } else if (NULL != op)
    {
      if (NULL != op->ar_cb)
        op->ar_cb (op->cls,
                   &msg->identity,
                   attr);

    }
    GNUNET_free (attr);
    return;
  }
  GNUNET_assert (0);
}

/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_TICKET_RESULT
 *
 * @param cls
 * @param msg the message we received
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
check_ticket_result (void *cls,
                     const struct TicketResultMessage *msg)
{
  size_t msg_len;

  msg_len = ntohs (msg->header.size);
  if (msg_len < sizeof (struct TicketResultMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}



/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_TICKET_RESULT
 *
 * @param cls
 * @param msg the message we received
 */
static void
handle_ticket_result (void *cls,
                      const struct TicketResultMessage *msg)
{
  struct GNUNET_IDENTITY_PROVIDER_Handle *handle = cls;
  struct GNUNET_IDENTITY_PROVIDER_Operation *op;
  struct GNUNET_IDENTITY_PROVIDER_TicketIterator *it;
  const struct GNUNET_IDENTITY_PROVIDER_Ticket *ticket;
  uint32_t r_id = ntohl (msg->id);
  size_t msg_len;

  for (op = handle->op_head; NULL != op; op = op->next)
    if (op->r_id == r_id)
      break;
  for (it = handle->ticket_it_head; NULL != it; it = it->next)
    if (it->r_id == r_id)
      break;
  if ((NULL == op) && (NULL == it))
    return;
  msg_len = ntohs (msg->header.size);
  if (NULL != op)
  {
    GNUNET_CONTAINER_DLL_remove (handle->op_head,
                                 handle->op_tail,
                                 op);
    if (msg_len == sizeof (struct TicketResultMessage))
    {
      if (NULL != op->tr_cb)
        op->tr_cb (op->cls, NULL);
    } else {
      ticket = (struct GNUNET_IDENTITY_PROVIDER_Ticket *)&msg[1];
      if (NULL != op->tr_cb)
        op->tr_cb (op->cls, ticket);
    }
    free_op (op);
    return;
  } else if (NULL != it) {
    if (msg_len == sizeof (struct TicketResultMessage))
    {
      if (NULL != it->tr_cb)
        GNUNET_CONTAINER_DLL_remove (handle->ticket_it_head,
                                     handle->ticket_it_tail,
                                     it);
      it->finish_cb (it->finish_cb_cls);
      GNUNET_free (it);
    } else {
      ticket = (struct GNUNET_IDENTITY_PROVIDER_Ticket *)&msg[1];
      if (NULL != it->tr_cb)
        it->tr_cb (it->cls, ticket);
    }
    return;
  }
  GNUNET_break (0);
}


/**
 * Handle an incoming message of type
 * #GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_REVOKE_TICKET_RESULT
 *
 * @param cls
 * @param msg the message we received
 */
static void
handle_revoke_ticket_result (void *cls,
                             const struct RevokeTicketResultMessage *msg)
{
  struct GNUNET_IDENTITY_PROVIDER_Handle *h = cls;
  struct GNUNET_IDENTITY_PROVIDER_Operation *op;
  uint32_t r_id = ntohl (msg->id);
  int32_t success;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Processing revocation result.\n");


  for (op = h->op_head; NULL != op; op = op->next)
    if (op->r_id == r_id)
      break;
  if (NULL == op)
    return;
  success = ntohl (msg->success);
  {
    if (NULL != op->rvk_cb)
    {
      op->rvk_cb (op->cls,
                  success,
                  NULL);
    }
    GNUNET_CONTAINER_DLL_remove (h->op_head,
                                 h->op_tail,
                                 op);
    free_op (op);
    return;
  }
  GNUNET_assert (0);
}



/**
 * Try again to connect to the service.
 *
 * @param h handle to the identity provider service.
 */
static void
reconnect (struct GNUNET_IDENTITY_PROVIDER_Handle *h)
{
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_fixed_size (attribute_store_response,
                             GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_ATTRIBUTE_STORE_RESPONSE,
                             struct AttributeStoreResultMessage,
                             h),
    GNUNET_MQ_hd_var_size (attribute_result,
                           GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_ATTRIBUTE_RESULT,
                           struct AttributeResultMessage,
                           h),
    GNUNET_MQ_hd_var_size (ticket_result,
                           GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_TICKET_RESULT,
                           struct TicketResultMessage,
                           h),
    GNUNET_MQ_hd_var_size (consume_ticket_result,
                           GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_CONSUME_TICKET_RESULT,
                           struct ConsumeTicketResultMessage,
                           h),
    GNUNET_MQ_hd_fixed_size (revoke_ticket_result,
                             GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_REVOKE_TICKET_RESULT,
                             struct RevokeTicketResultMessage,
                             h),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_IDENTITY_PROVIDER_Operation *op;

  GNUNET_assert (NULL == h->mq);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connecting to identity provider service.\n");

  h->mq = GNUNET_CLIENT_connect (h->cfg,
                                 "identity-provider",
                                 handlers,
                                 &mq_error_handler,
                                 h);
  if (NULL == h->mq)
    return;
  for (op = h->op_head; NULL != op; op = op->next)
    GNUNET_MQ_send_copy (h->mq,
                         op->env);
}


/**
 * Connect to the identity provider service.
 *
 * @param cfg the configuration to use
 * @return handle to use
 */
struct GNUNET_IDENTITY_PROVIDER_Handle *
GNUNET_IDENTITY_PROVIDER_connect (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_IDENTITY_PROVIDER_Handle *h;

  h = GNUNET_new (struct GNUNET_IDENTITY_PROVIDER_Handle);
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
GNUNET_IDENTITY_PROVIDER_cancel (struct GNUNET_IDENTITY_PROVIDER_Operation *op)
{
  struct GNUNET_IDENTITY_PROVIDER_Handle *h = op->h;

  GNUNET_CONTAINER_DLL_remove (h->op_head,
                               h->op_tail,
                               op);
  free_op (op);
}


/**
 * Disconnect from service
 *
 * @param h handle to destroy
 */
void
GNUNET_IDENTITY_PROVIDER_disconnect (struct GNUNET_IDENTITY_PROVIDER_Handle *h)
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
 * @param h handle to the identity provider
 * @param pkey private key of the identity
 * @param attr the attribute value
 * @param exp_interval the relative expiration interval for the attribute
 * @param cont continuation to call when done
 * @param cont_cls closure for @a cont
 * @return handle to abort the request
 */
struct GNUNET_IDENTITY_PROVIDER_Operation *
GNUNET_IDENTITY_PROVIDER_attribute_store (struct GNUNET_IDENTITY_PROVIDER_Handle *h,
                                          const struct GNUNET_CRYPTO_EcdsaPrivateKey *pkey,
                                          const struct GNUNET_IDENTITY_ATTRIBUTE_Claim *attr,
                                          const struct GNUNET_TIME_Relative *exp_interval,
                                          GNUNET_IDENTITY_PROVIDER_ContinuationWithStatus cont,
                                          void *cont_cls)
{
  struct GNUNET_IDENTITY_PROVIDER_Operation *op;
  struct AttributeStoreMessage *sam;
  size_t attr_len;

  op = GNUNET_new (struct GNUNET_IDENTITY_PROVIDER_Operation);
  op->h = h;
  op->as_cb = cont;
  op->cls = cont_cls;
  op->r_id = h->r_id_gen++;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head,
                                    h->op_tail,
                                    op);
  attr_len = GNUNET_IDENTITY_ATTRIBUTE_serialize_get_size (attr);
  op->env = GNUNET_MQ_msg_extra (sam,
                                 attr_len,
                                 GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_ATTRIBUTE_STORE);
  sam->identity = *pkey;
  sam->id = htonl (op->r_id);
  sam->exp = GNUNET_htonll (exp_interval->rel_value_us);

  GNUNET_IDENTITY_ATTRIBUTE_serialize (attr,
                                       (char*)&sam[1]);

  sam->attr_len = htons (attr_len);
  if (NULL != h->mq)
    GNUNET_MQ_send_copy (h->mq,
                         op->env);
  return op;

}


/**
 * List all attributes for a local identity.
 * This MUST lock the `struct GNUNET_IDENTITY_PROVIDER_Handle`
 * for any other calls than #GNUNET_IDENTITY_PROVIDER_get_attributes_next() and
 * #GNUNET_IDENTITY_PROVIDER_get_attributes_stop. @a proc will be called once
 * immediately, and then again after
 * #GNUNET_IDENTITY_PROVIDER_get_attributes_next() is invoked.
 *
 * On error (disconnect), @a error_cb will be invoked.
 * On normal completion, @a finish_cb proc will be
 * invoked.
 *
 * @param h handle to the idp
 * @param identity identity to access
 * @param error_cb function to call on error (i.e. disconnect),
 *        the handle is afterwards invalid
 * @param error_cb_cls closure for @a error_cb
 * @param proc function to call on each attribute; it
 *        will be called repeatedly with a value (if available)
 * @param proc_cls closure for @a proc
 * @param finish_cb function to call on completion
 *        the handle is afterwards invalid
 * @param finish_cb_cls closure for @a finish_cb
 * @return an iterator handle to use for iteration
 */
struct GNUNET_IDENTITY_PROVIDER_AttributeIterator *
GNUNET_IDENTITY_PROVIDER_get_attributes_start (struct GNUNET_IDENTITY_PROVIDER_Handle *h,
                                               const struct GNUNET_CRYPTO_EcdsaPrivateKey *identity,
                                               GNUNET_SCHEDULER_TaskCallback error_cb,
                                               void *error_cb_cls,
                                               GNUNET_IDENTITY_PROVIDER_AttributeResult proc,
                                               void *proc_cls,
                                               GNUNET_SCHEDULER_TaskCallback finish_cb,
                                               void *finish_cb_cls)
{
  struct GNUNET_IDENTITY_PROVIDER_AttributeIterator *it;
  struct GNUNET_MQ_Envelope *env;
  struct AttributeIterationStartMessage *msg;
  uint32_t rid;

  rid = h->r_id_gen++;
  it = GNUNET_new (struct GNUNET_IDENTITY_PROVIDER_AttributeIterator);
  it->h = h;
  it->error_cb = error_cb;
  it->error_cb_cls = error_cb_cls;
  it->finish_cb = finish_cb;
  it->finish_cb_cls = finish_cb_cls;
  it->proc = proc;
  it->proc_cls = proc_cls;
  it->r_id = rid;
  it->identity = *identity;
  GNUNET_CONTAINER_DLL_insert_tail (h->it_head,
                                    h->it_tail,
                                    it);
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_ATTRIBUTE_ITERATION_START);
  msg->id = htonl (rid);
  msg->identity = *identity;
  if (NULL == h->mq)
    it->env = env;
  else
    GNUNET_MQ_send (h->mq,
                    env);
  return it;
}


/**
 * Calls the record processor specified in #GNUNET_IDENTITY_PROVIDER_get_attributes_start
 * for the next record.
 *
 * @param it the iterator
 */
void
GNUNET_IDENTITY_PROVIDER_get_attributes_next (struct GNUNET_IDENTITY_PROVIDER_AttributeIterator *it)
{
  struct GNUNET_IDENTITY_PROVIDER_Handle *h = it->h;
  struct AttributeIterationNextMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_ATTRIBUTE_ITERATION_NEXT);
  msg->id = htonl (it->r_id);
  GNUNET_MQ_send (h->mq,
                  env);
}


/**
 * Stops iteration and releases the idp handle for further calls.  Must
 * be called on any iteration that has not yet completed prior to calling
 * #GNUNET_IDENTITY_PROVIDER_disconnect.
 *
 * @param it the iterator
 */
void
GNUNET_IDENTITY_PROVIDER_get_attributes_stop (struct GNUNET_IDENTITY_PROVIDER_AttributeIterator *it)
{
  struct GNUNET_IDENTITY_PROVIDER_Handle *h = it->h;
  struct GNUNET_MQ_Envelope *env;
  struct AttributeIterationStopMessage *msg;

  if (NULL != h->mq)
  {
    env = GNUNET_MQ_msg (msg,
                         GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_ATTRIBUTE_ITERATION_STOP);
    msg->id = htonl (it->r_id);
    GNUNET_MQ_send (h->mq,
                    env);
  }
  free_it (it);
}


/** TODO
 * Issues a ticket to another identity. The identity may use
 * @GNUNET_IDENTITY_PROVIDER_authorization_ticket_consume to consume the ticket
 * and retrieve the attributes specified in the AttributeList.
 *
 * @param h the identity provider to use
 * @param iss the issuing identity
 * @param rp the subject of the ticket (the relying party)
 * @param attrs the attributes that the relying party is given access to
 * @param cb the callback
 * @param cb_cls the callback closure
 * @return handle to abort the operation
 */
struct GNUNET_IDENTITY_PROVIDER_Operation *
GNUNET_IDENTITY_PROVIDER_ticket_issue (struct GNUNET_IDENTITY_PROVIDER_Handle *h,
                                       const struct GNUNET_CRYPTO_EcdsaPrivateKey *iss,
                                       const struct GNUNET_CRYPTO_EcdsaPublicKey *rp,
                                       const struct GNUNET_IDENTITY_ATTRIBUTE_ClaimList *attrs,
                                       GNUNET_IDENTITY_PROVIDER_TicketCallback cb,
                                       void *cb_cls)
{
  struct GNUNET_IDENTITY_PROVIDER_Operation *op;
  struct IssueTicketMessage *tim;
  size_t attr_len;

  op = GNUNET_new (struct GNUNET_IDENTITY_PROVIDER_Operation);
  op->h = h;
  op->tr_cb = cb;
  op->cls = cb_cls;
  op->r_id = h->r_id_gen++;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head,
                                    h->op_tail,
                                    op);
  attr_len = GNUNET_IDENTITY_ATTRIBUTE_list_serialize_get_size (attrs);
  op->env = GNUNET_MQ_msg_extra (tim,
                                 attr_len,
                                 GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_ISSUE_TICKET);
  tim->identity = *iss;
  tim->rp = *rp;
  tim->id = htonl (op->r_id);

  GNUNET_IDENTITY_ATTRIBUTE_list_serialize (attrs,
                                            (char*)&tim[1]);

  tim->attr_len = htons (attr_len);
  if (NULL != h->mq)
    GNUNET_MQ_send_copy (h->mq,
                         op->env);
  return op;
}

/**
 * Consumes an issued ticket. The ticket is persisted
 * and used to retrieve identity information from the issuer
 *
 * @param h the identity provider to use
 * @param identity the identity that is the subject of the issued ticket (the relying party)
 * @param ticket the issued ticket to consume
 * @param cb the callback to call
 * @param cb_cls the callback closure
 * @return handle to abort the operation
 */
struct GNUNET_IDENTITY_PROVIDER_Operation *
GNUNET_IDENTITY_PROVIDER_ticket_consume (struct GNUNET_IDENTITY_PROVIDER_Handle *h,
                                         const struct GNUNET_CRYPTO_EcdsaPrivateKey *identity,
                                         const struct GNUNET_IDENTITY_PROVIDER_Ticket *ticket,
                                         GNUNET_IDENTITY_PROVIDER_AttributeResult cb,
                                         void *cb_cls)
{
  struct GNUNET_IDENTITY_PROVIDER_Operation *op;
  struct ConsumeTicketMessage *ctm;

  op = GNUNET_new (struct GNUNET_IDENTITY_PROVIDER_Operation);
  op->h = h;
  op->ar_cb = cb;
  op->cls = cb_cls;
  op->r_id = h->r_id_gen++;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head,
                                    h->op_tail,
                                    op);
  op->env = GNUNET_MQ_msg_extra (ctm,
                                 sizeof (const struct GNUNET_IDENTITY_PROVIDER_Ticket),
                                 GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_CONSUME_TICKET);
  ctm->identity = *identity;
  ctm->id = htonl (op->r_id);

  GNUNET_memcpy ((char*)&ctm[1],
                 ticket,
                 sizeof (const struct GNUNET_IDENTITY_PROVIDER_Ticket));

  if (NULL != h->mq)
    GNUNET_MQ_send_copy (h->mq,
                         op->env);
  return op;

}


/**
 * Lists all tickets that have been issued to remote
 * identites (relying parties)
 *
 * @param h the identity provider to use
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
struct GNUNET_IDENTITY_PROVIDER_TicketIterator *
GNUNET_IDENTITY_PROVIDER_ticket_iteration_start (struct GNUNET_IDENTITY_PROVIDER_Handle *h,
                                                 const struct GNUNET_CRYPTO_EcdsaPrivateKey *identity,
                                                 GNUNET_SCHEDULER_TaskCallback error_cb,
                                                 void *error_cb_cls,
                                                 GNUNET_IDENTITY_PROVIDER_TicketCallback proc,
                                                 void *proc_cls,
                                                 GNUNET_SCHEDULER_TaskCallback finish_cb,
                                                 void *finish_cb_cls)
{
  struct GNUNET_IDENTITY_PROVIDER_TicketIterator *it;
  struct GNUNET_CRYPTO_EcdsaPublicKey identity_pub;
  struct GNUNET_MQ_Envelope *env;
  struct TicketIterationStartMessage *msg;
  uint32_t rid;

  GNUNET_CRYPTO_ecdsa_key_get_public (identity,
                                      &identity_pub);
  rid = h->r_id_gen++;
  it = GNUNET_new (struct GNUNET_IDENTITY_PROVIDER_TicketIterator);
  it->h = h;
  it->error_cb = error_cb;
  it->error_cb_cls = error_cb_cls;
  it->finish_cb = finish_cb;
  it->finish_cb_cls = finish_cb_cls;
  it->tr_cb = proc;
  it->cls = proc_cls;
  it->r_id = rid;
  GNUNET_CONTAINER_DLL_insert_tail (h->ticket_it_head,
                                    h->ticket_it_tail,
                                    it);
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_TICKET_ITERATION_START);
  msg->id = htonl (rid);
  msg->identity = identity_pub;
  msg->is_audience = htonl (GNUNET_NO);
  if (NULL == h->mq)
    it->env = env;
  else
    GNUNET_MQ_send (h->mq,
                    env);
  return it;

}


/**
 * Lists all tickets that have been issued to remote
 * identites (relying parties)
 *
 * @param h the identity provider to use
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
struct GNUNET_IDENTITY_PROVIDER_TicketIterator *
GNUNET_IDENTITY_PROVIDER_ticket_iteration_start_rp (struct GNUNET_IDENTITY_PROVIDER_Handle *h,
                                                    const struct GNUNET_CRYPTO_EcdsaPublicKey *identity,
                                                    GNUNET_SCHEDULER_TaskCallback error_cb,
                                                    void *error_cb_cls,
                                                    GNUNET_IDENTITY_PROVIDER_TicketCallback proc,
                                                    void *proc_cls,
                                                    GNUNET_SCHEDULER_TaskCallback finish_cb,
                                                    void *finish_cb_cls)
{
  struct GNUNET_IDENTITY_PROVIDER_TicketIterator *it;
  struct GNUNET_MQ_Envelope *env;
  struct TicketIterationStartMessage *msg;
  uint32_t rid;

  rid = h->r_id_gen++;
  it = GNUNET_new (struct GNUNET_IDENTITY_PROVIDER_TicketIterator);
  it->h = h;
  it->error_cb = error_cb;
  it->error_cb_cls = error_cb_cls;
  it->finish_cb = finish_cb;
  it->finish_cb_cls = finish_cb_cls;
  it->tr_cb = proc;
  it->cls = proc_cls;
  it->r_id = rid;
  GNUNET_CONTAINER_DLL_insert_tail (h->ticket_it_head,
                                    h->ticket_it_tail,
                                    it);
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_TICKET_ITERATION_START);
  msg->id = htonl (rid);
  msg->identity = *identity;
  msg->is_audience = htonl (GNUNET_YES);
  if (NULL == h->mq)
    it->env = env;
  else
    GNUNET_MQ_send (h->mq,
                    env);
  return it;


}

/**
 * Calls the record processor specified in #GNUNET_IDENTITY_PROVIDER_ticket_iteration_start
 * for the next record.
 *
 * @param it the iterator
 */
void
GNUNET_IDENTITY_PROVIDER_ticket_iteration_next (struct GNUNET_IDENTITY_PROVIDER_TicketIterator *it)
{
  struct GNUNET_IDENTITY_PROVIDER_Handle *h = it->h;
  struct TicketIterationNextMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_TICKET_ITERATION_NEXT);
  msg->id = htonl (it->r_id);
  GNUNET_MQ_send (h->mq,
                  env);
}


/**
 * Stops iteration and releases the idp handle for further calls.  Must
 * be called on any iteration that has not yet completed prior to calling
 * #GNUNET_IDENTITY_PROVIDER_disconnect.
 *
 * @param it the iterator
 */
void
GNUNET_IDENTITY_PROVIDER_ticket_iteration_stop (struct GNUNET_IDENTITY_PROVIDER_TicketIterator *it)
{
  struct GNUNET_IDENTITY_PROVIDER_Handle *h = it->h;
  struct GNUNET_MQ_Envelope *env;
  struct TicketIterationStopMessage *msg;

  if (NULL != h->mq)
  {
    env = GNUNET_MQ_msg (msg,
                         GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_TICKET_ITERATION_STOP);
    msg->id = htonl (it->r_id);
    GNUNET_MQ_send (h->mq,
                    env);
  }
  GNUNET_free (it);
}

/**
 * Revoked an issued ticket. The relying party will be unable to retrieve
 * updated attributes.
 *
 * @param h the identity provider to use
 * @param identity the issuing identity
 * @param ticket the ticket to revoke
 * @param cb the callback
 * @param cb_cls the callback closure
 * @return handle to abort the operation
 */
struct GNUNET_IDENTITY_PROVIDER_Operation *
GNUNET_IDENTITY_PROVIDER_ticket_revoke (struct GNUNET_IDENTITY_PROVIDER_Handle *h,
                                        const struct GNUNET_CRYPTO_EcdsaPrivateKey *identity,
                                        const struct GNUNET_IDENTITY_PROVIDER_Ticket *ticket,
                                        GNUNET_IDENTITY_PROVIDER_ContinuationWithStatus cb,
                                        void *cb_cls)
{
  struct GNUNET_IDENTITY_PROVIDER_Operation *op;
  struct GNUNET_MQ_Envelope *env;
  struct RevokeTicketMessage *msg;
  uint32_t rid;

  rid = h->r_id_gen++;
  op = GNUNET_new (struct GNUNET_IDENTITY_PROVIDER_Operation);
  op->h = h;
  op->rvk_cb = cb;
  op->cls = cb_cls;
  op->r_id = rid;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head,
                                    h->op_tail,
                                    op);
  env = GNUNET_MQ_msg_extra (msg,
                             sizeof (struct GNUNET_IDENTITY_PROVIDER_Ticket),
                             GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_REVOKE_TICKET);
  msg->id = htonl (rid);
  msg->identity = *identity;
  GNUNET_memcpy (&msg[1],
                 ticket,
                 sizeof (struct GNUNET_IDENTITY_PROVIDER_Ticket));
  if (NULL == h->mq)
    op->env = env;
  else
    GNUNET_MQ_send (h->mq,
                    env);
  return op;
}



/* end of identity_provider_api.c */
