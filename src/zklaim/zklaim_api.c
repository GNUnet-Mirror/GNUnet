/*
     This file is part of GNUnet.
     Copyright (C) 2013, 2016 GNUnet e.V.

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
*/

/**
 * @file zklaim/zklaim_api.c
 * @brief api to interact with the zklaim service
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_zklaim_service.h"
#include "zklaim/zklaim.h"
#include "zklaim_api.h"
#include "zklaim_functions.h"

#define LOG(kind,...) GNUNET_log_from (kind, "zklaim-api",__VA_ARGS__)


/**
 * Handle for an operation with the service.
 */
struct GNUNET_ZKLAIM_Operation
{

  /**
   * Main handle.
   */
  struct GNUNET_ZKLAIM_Handle *h;

  /**
   * We keep operations in a DLL.
   */
  struct GNUNET_ZKLAIM_Operation *next;

  /**
   * We keep operations in a DLL.
   */
  struct GNUNET_ZKLAIM_Operation *prev;

  /**
   * Message to send to the zklaim service.
   * Allocated at the end of this struct.
   */
  const struct GNUNET_MessageHeader *msg;

  /**
   * Continuation to invoke with the result of the transmission; @e cb
   * will be NULL in this case.
   */
  GNUNET_ZKLAIM_ContinuationWithStatus cont;

  /**
   * Context result
   */
  GNUNET_ZKLAIM_ContextResult ctx_cont;

  /**
   * Closure for @e cont or @e cb.
   */
  void *cls;

};


/**
 * Handle for the service.
 */
struct GNUNET_ZKLAIM_Handle
{
  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Connection to service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Hash map from the hash of the public key to the
   * respective `GNUNET_ZKLAIM_Ego` handle.
   */
  struct GNUNET_CONTAINER_MultiHashMap *egos;

  /**
   * Closure for @e cb.
   */
  void *cb_cls;

  /**
   * Head of active operations.
   */
  struct GNUNET_ZKLAIM_Operation *op_head;

  /**
   * Tail of active operations.
   */
  struct GNUNET_ZKLAIM_Operation *op_tail;

  /**
   * Task doing exponential back-off trying to reconnect.
   */
  struct GNUNET_SCHEDULER_Task *reconnect_task;

  /**
   * Time for next connect retry.
   */
  struct GNUNET_TIME_Relative reconnect_delay;

};


/**
 * Try again to connect to the zklaim service.
 *
 * @param cls handle to the zklaim service.
 */
static void
reconnect (void *cls);

/**
 * Reschedule a connect attempt to the service.
 *
 * @param h transport service to reconnect
 */
static void
reschedule_connect (struct GNUNET_ZKLAIM_Handle *h)
{
  struct GNUNET_ZKLAIM_Operation *op;

  GNUNET_assert (NULL == h->reconnect_task);

  if (NULL != h->mq)
  {
    GNUNET_MQ_destroy (h->mq);
    h->mq = NULL;
  }
  while (NULL != (op = h->op_head))
  {
    GNUNET_CONTAINER_DLL_remove (h->op_head,
                                 h->op_tail,
                                 op);
    if (NULL != op->cont)
      op->cont (op->cls,
                GNUNET_SYSERR,
                "Error in communication with the zklaim service");
    GNUNET_free (op);
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Scheduling task to reconnect to zklaim service in %s.\n",
       GNUNET_STRINGS_relative_time_to_string (h->reconnect_delay,
                                               GNUNET_YES));
  h->reconnect_task =
      GNUNET_SCHEDULER_add_delayed (h->reconnect_delay,
                                    &reconnect,
                                    h);
  h->reconnect_delay = GNUNET_TIME_STD_BACKOFF (h->reconnect_delay);
}


/**
 * Generic error handler, called with the appropriate error code and
 * the same closure specified at the creation of the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_ZKLAIM_Handle *`
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_ZKLAIM_Handle *h = cls;

  reschedule_connect (h);
}


/**
 * We received a result code from the service.  Check the message
 * is well-formed.
 *
 * @param cls closure
 * @param rcm result message received
 * @return #GNUNET_OK if the message is well-formed
 */
static int
check_zklaim_result_code (void *cls,
                            const struct ResultCodeMessage *rcm)
{
  uint16_t size = ntohs (rcm->header.size) - sizeof (*rcm);
  const char *str = (const char *) &rcm[1];

  if (0 == size)
    return GNUNET_OK;
  if ('\0' != str[size - 1])
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * We received a result code from the service.
 *
 * @param cls closure
 * @param rcm result message received
 */
static void
handle_zklaim_result_code (void *cls,
                             const struct ResultCodeMessage *rcm)
{
  struct GNUNET_ZKLAIM_Handle *h = cls;
  struct GNUNET_ZKLAIM_Operation *op;
  uint16_t size = ntohs (rcm->header.size) - sizeof (*rcm);
  const char *str = (0 == size) ? NULL : (const char *) &rcm[1];

  op = h->op_head;
  if (NULL == op)
  {
    GNUNET_break (0);
    reschedule_connect (h);
    return;
  }
  GNUNET_CONTAINER_DLL_remove (h->op_head,
                               h->op_tail,
                               op);
  if (NULL != op->cont)
    op->cont (op->cls,
              ntohl(rcm->result_code),
              str);
  GNUNET_free (op);
}

/**
 * We received a result code from the service.  Check the message
 * is well-formed.
 *
 * @param cls closure
 * @param rcm result message received
 * @return #GNUNET_OK if the message is well-formed
 */
static int
check_zklaim_result_ctx (void *cls,
                         const struct ContextMessage *cm)
{
  //TODO check for data sanity
  return GNUNET_OK;
}


/**
 * We received a context result from the service.
 *
 * @param cls closure
 * @param rcm result message received
 */
static void
handle_zklaim_result_ctx (void *cls,
                          const struct ContextMessage *cm)
{
  struct GNUNET_ZKLAIM_Handle *h = cls;
  struct GNUNET_ZKLAIM_Operation *op;
  struct GNUNET_ZKLAIM_Context ctx;
  uint16_t ctx_len = ntohl (cm->ctx_len);

  op = h->op_head;
  if (NULL == op)
  {
    GNUNET_break (0);
    reschedule_connect (h);
    return;
  }
  GNUNET_CONTAINER_DLL_remove (h->op_head,
                               h->op_tail,
                               op);
  ctx.attrs = (char*)&cm[1];
  ctx.ctx = zklaim_context_new ();
  zklaim_ctx_deserialize (ctx.ctx,
                          (unsigned char *) &cm[1] + strlen (ctx.attrs) + 1,
                          ctx_len - strlen (ctx.attrs) - 1);
  if (NULL != op->ctx_cont)
  {
    if (0 > ctx_len)
      op->ctx_cont (op->cls,
                    &ctx);
    else
      op->ctx_cont (op->cls,
                    &ctx);
  }
  zklaim_ctx_free (ctx.ctx);
  GNUNET_free (op);
}



/**
 * Try again to connect to the zklaim service.
 *
 * @param cls handle to the zklaim service.
 */
static void
reconnect (void *cls)
{
  struct GNUNET_ZKLAIM_Handle *h = cls;
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (zklaim_result_code,
                           GNUNET_MESSAGE_TYPE_ZKLAIM_RESULT_CODE,
                           struct ResultCodeMessage,
                           h),
    GNUNET_MQ_hd_var_size (zklaim_result_ctx,
                           GNUNET_MESSAGE_TYPE_ZKLAIM_RESULT_CTX,
                           struct ContextMessage,
                           h),
    GNUNET_MQ_handler_end ()
  };

  h->reconnect_task = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connecting to zklaim service.\n");
  GNUNET_assert (NULL == h->mq);
  h->mq = GNUNET_CLIENT_connect (h->cfg,
                                 "zklaim",
                                 handlers,
                                 &mq_error_handler,
                                 h);
  if (NULL == h->mq)
    return;
}


/**
 * Connect to the zklaim service.
 *
 * @param cfg the configuration to use
 * @param cb function to call on all zklaim events, can be NULL
 * @param cb_cls closure for @a cb
 * @return handle to use
 */
struct GNUNET_ZKLAIM_Handle *
GNUNET_ZKLAIM_connect (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_ZKLAIM_Handle *h;

  h = GNUNET_new (struct GNUNET_ZKLAIM_Handle);
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
 * Create a new zklaim with the given name.
 *
 * @param h zklaim service to use
 * @param name desired name
 * @param cont function to call with the result (will only be called once)
 * @param cont_cls closure for @a cont
 * @return handle to abort the operation
 */
struct GNUNET_ZKLAIM_Operation *
GNUNET_ZKLAIM_context_create (struct GNUNET_ZKLAIM_Handle *h,
                              const struct GNUNET_CRYPTO_EcdsaPrivateKey *pk,
                              const char *name,
                              const char *attr_list,
                              GNUNET_ZKLAIM_ContinuationWithStatus cont,
                              void *cont_cls)
{
  struct GNUNET_ZKLAIM_Operation *op;
  struct GNUNET_MQ_Envelope *env;
  struct CreateRequestMessage *crm;
  size_t slen;
  size_t alen;

  if (NULL == h->mq)
    return NULL;
  slen = strlen (name) + 1;
  alen = strlen (attr_list) + 1;
  if (slen+alen >= GNUNET_MAX_MESSAGE_SIZE - sizeof (struct CreateRequestMessage))
  {
    GNUNET_break (0);
    return NULL;
  }
  op = GNUNET_new (struct GNUNET_ZKLAIM_Operation);
  op->h = h;
  op->cont = cont;
  op->cls = cont_cls;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head,
                                    h->op_tail,
                                    op);
  env = GNUNET_MQ_msg_extra (crm,
                             slen + alen,
                             GNUNET_MESSAGE_TYPE_ZKLAIM_CREATE);
  crm->name_len = htons (slen);
  crm->attrs_len = htons (alen);
  crm->reserved = htons (0);
  crm->private_key = *pk;
  GNUNET_memcpy (&crm[1],
                 name,
                 slen);
  GNUNET_memcpy (((char*)&crm[1]) + slen,
                 attr_list,
                 alen);
  GNUNET_MQ_send (h->mq,
                  env);
  //TODO add attrs
  return op;
}


/**
 * Cancel an zklaim operation. Note that the operation MAY still
 * be executed; this merely cancels the continuation; if the request
 * was already transmitted, the service may still choose to complete
 * the operation.
 *
 * @param op operation to cancel
 */
void
GNUNET_ZKLAIM_cancel (struct GNUNET_ZKLAIM_Operation *op)
{
  op->cont = NULL;
}


/**
 * Disconnect from zklaim service
 *
 * @param h handle to destroy
 */
void
GNUNET_ZKLAIM_disconnect (struct GNUNET_ZKLAIM_Handle *h)
{
  struct GNUNET_ZKLAIM_Operation *op;

  GNUNET_assert (NULL != h);
  if (h->reconnect_task != NULL)
  {
    GNUNET_SCHEDULER_cancel (h->reconnect_task);
    h->reconnect_task = NULL;
  }
  while (NULL != (op = h->op_head))
  {
    GNUNET_break (NULL == op->cont);
    GNUNET_CONTAINER_DLL_remove (h->op_head,
                                 h->op_tail,
                                 op);
    GNUNET_free (op);
  }
  if (NULL != h->mq)
  {
    GNUNET_MQ_destroy (h->mq);
    h->mq = NULL;
  }
  GNUNET_free (h);
}

/**
 * Lookup context
 */
struct GNUNET_ZKLAIM_Operation*
GNUNET_ZKLAIM_lookup_context (struct GNUNET_ZKLAIM_Handle *h,
                              const char *name,
                              const struct GNUNET_CRYPTO_EcdsaPrivateKey *key,
                              GNUNET_ZKLAIM_ContextResult cont,
                              void* cont_cls)
{
  struct GNUNET_ZKLAIM_Operation *op;
  struct GNUNET_MQ_Envelope *env;
  struct LookupMessage *lm;
  size_t slen;

  if (NULL == h->mq)
    return NULL;
  slen = strlen (name) + 1;
  if (slen >= GNUNET_MAX_MESSAGE_SIZE - sizeof (struct LookupMessage))
  {
    GNUNET_break (0);
    return NULL;
  }
  op = GNUNET_new (struct GNUNET_ZKLAIM_Operation);
  op->h = h;
  op->ctx_cont = cont;
  op->cls = cont_cls;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head,
                                    h->op_tail,
                                    op);
  env = GNUNET_MQ_msg_extra (lm,
                             slen,
                             GNUNET_MESSAGE_TYPE_ZKLAIM_LOOKUP_CTX);
  lm->name_len = htons (slen);
  lm->reserved = htons (0);
  lm->private_key = *key;
  GNUNET_memcpy (&lm[1],
                 name,
                 slen);
  GNUNET_MQ_send (h->mq,
                  env);
  return op;
}

int
GNUNET_ZKLAIM_issue_from_context (struct GNUNET_ZKLAIM_Context *ctx,
                                  struct GNUNET_CRYPTO_EcdsaPrivateKey *key,
                                  GNUNET_ZKLAIM_PayloadIterator iter,
                                  void* iter_cls)
{
  return ZKLAIM_context_issue (ctx,
                               key,
                               iter,
                               iter_cls);
}

size_t
GNUNET_ZKLAIM_context_serialize (const struct GNUNET_ZKLAIM_Context *ctx,
                                 char **buf)
{
  char *pos;
  char *tmp;
  size_t len;
  size_t len_w;
  size_t ret_len = 0;
  len = zklaim_ctx_serialize (ctx->ctx,
                              (unsigned char**) &tmp);
  ret_len += strlen (ctx->attrs) + 1 + sizeof (size_t) + len;
  *buf = GNUNET_malloc (ret_len);
  pos = *buf;
  memcpy (pos, ctx->attrs, strlen (ctx->attrs) + 1);
  pos += strlen (ctx->attrs) + 1;
  len_w = htonl (len);
  memcpy (pos, &len_w, sizeof (size_t));
  pos += sizeof (size_t);
  memcpy (pos, tmp, len);
  GNUNET_free (tmp);
  return ret_len;
}


struct GNUNET_ZKLAIM_Context *
GNUNET_ZKLAIM_context_deserialize (char *data,
                                   size_t data_len)
{
  struct GNUNET_ZKLAIM_Context *ctx;
  char *pos;
  size_t len;

  ctx = GNUNET_new (struct GNUNET_ZKLAIM_Context);
  ctx->attrs = GNUNET_strdup (data);
  pos = data + strlen (ctx->attrs) + 1;
  len = ntohl (*((size_t*)pos));
  ctx->ctx = zklaim_context_new ();
  pos += sizeof (size_t);
  if (0 != zklaim_ctx_deserialize (ctx->ctx,
                                   (unsigned char*) pos,
                                   len))
    return NULL;
  return ctx;
}

int
GNUNET_ZKLAIM_context_prove (struct GNUNET_ZKLAIM_Context *ctx,
                             GNUNET_ZKLAIM_PredicateIterator iter,
                             void* iter_cls)
{
  return ZKLAIM_context_prove (ctx,
                               iter,
                               iter_cls);
}

/* end of zklaim_api.c */
