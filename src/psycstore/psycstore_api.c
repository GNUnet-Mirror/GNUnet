/*
 * This file is part of GNUnet
 * Copyright (C) 2013 GNUnet e.V.
 *
 * GNUnet is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 3, or (at your
 * option) any later version.
 *
 * GNUnet is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNUnet; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

/**
 * @file psycstore/psycstore_api.c
 * @brief API to interact with the PSYCstore service
 * @author Gabor X Toth
 * @author Christian Grothoff
 */

#include <inttypes.h>

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_psycstore_service.h"
#include "gnunet_multicast_service.h"
#include "psycstore.h"

#define LOG(kind,...) GNUNET_log_from (kind, "psycstore-api",__VA_ARGS__)

/**
 * Handle for an operation with the PSYCstore service.
 */
struct GNUNET_PSYCSTORE_OperationHandle
{

  /**
   * Main PSYCstore handle.
   */
  struct GNUNET_PSYCSTORE_Handle *h;

  /**
   * Data callbacks.
   */
  union {
    GNUNET_PSYCSTORE_FragmentCallback fragment_cb;
    GNUNET_PSYCSTORE_CountersCallback counters_cb;
    GNUNET_PSYCSTORE_StateCallback state_cb;
  };

  /**
   * Closure for callbacks.
   */
  void *cls;

  /**
   * Message envelope.
   */
  struct GNUNET_MQ_Envelope *env;

  /**
   * Operation ID.
   */
  uint64_t op_id;
};


/**
 * Handle for the service.
 */
struct GNUNET_PSYCSTORE_Handle
{
  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Client connection.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Async operations.
   */
  struct GNUNET_OP_Handle *op;

  /**
   * Task doing exponential back-off trying to reconnect.
   */
  struct GNUNET_SCHEDULER_Task *reconnect_task;

  /**
   * Delay for next connect retry.
   */
  struct GNUNET_TIME_Relative reconnect_delay;


  GNUNET_PSYCSTORE_FragmentCallback *fragment_cb;

  GNUNET_PSYCSTORE_CountersCallback *counters_cb;

  GNUNET_PSYCSTORE_StateCallback *state_cb;
  /**
   * Closure for callbacks.
   */
  void *cb_cls;
};


static int
check_result_code (void *cls, const struct OperationResult *opres)
{
  uint16_t size = ntohs (opres->header.size);
  const char *str = (const char *) &opres[1];
  if ( (sizeof (*opres) < size) &&
       ('\0' != str[size - sizeof (*opres) - 1]) )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  return GNUNET_OK;
}


static void
handle_result_code (void *cls, const struct OperationResult *opres)
{
  struct GNUNET_PSYCSTORE_Handle *h = cls;
  struct GNUNET_PSYCSTORE_OperationHandle *op = NULL;
  uint16_t size = ntohs (opres->header.size);

  const char *
    str = (sizeof (*opres) < size) ? (const char *) &opres[1] : "";

  if (GNUNET_YES == GNUNET_OP_result (h->op, GNUNET_ntohll (opres->op_id),
                                      GNUNET_ntohll (opres->result_code) + INT64_MIN,
                                      str, size - sizeof (*opres), (void **) &op))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "handle_result_code: Received result message with operation ID: %" PRIu64 "\n",
         GNUNET_ntohll (opres->op_id));
    GNUNET_free (op);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "handle_result_code: No callback registered for operation with ID %" PRIu64 ".\n",
         GNUNET_ntohll (opres->op_id));
  }
  h->reconnect_delay = GNUNET_TIME_UNIT_MILLISECONDS;
}


static void
handle_result_counters (void *cls, const struct CountersResult *cres)
{
  struct GNUNET_PSYCSTORE_Handle *h = cls;
  struct GNUNET_PSYCSTORE_OperationHandle *op = NULL;

  if (GNUNET_YES == GNUNET_OP_get (h->op, GNUNET_ntohll (cres->op_id),
                                   NULL, NULL, (void **) &op))
  {
    GNUNET_assert (NULL != op);
    if (NULL != op->counters_cb)
    {
      op->counters_cb (op->cls,
                       ntohl (cres->result_code),
                       GNUNET_ntohll (cres->max_fragment_id),
                       GNUNET_ntohll (cres->max_message_id),
                       GNUNET_ntohll (cres->max_group_generation),
                       GNUNET_ntohll (cres->max_state_message_id));
    }
    GNUNET_OP_remove (h->op, GNUNET_ntohll (cres->op_id));
    GNUNET_free (op);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "handle_result_counters: No callback registered for operation with ID %" PRIu64 ".\n",
         GNUNET_ntohll (cres->op_id));
  }
  h->reconnect_delay = GNUNET_TIME_UNIT_MILLISECONDS;
}


static int
check_result_fragment (void *cls, const struct FragmentResult *fres)
{
  uint16_t size = ntohs (fres->header.size);
  struct GNUNET_MULTICAST_MessageHeader *mmsg =
    (struct GNUNET_MULTICAST_MessageHeader *) &fres[1];
  if (sizeof (*fres) + sizeof (*mmsg) < size
      && sizeof (*fres) + ntohs (mmsg->header.size) != size)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "check_result_fragment: Received message with invalid length %lu bytes.\n",
         size, sizeof (*fres));
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


static void
handle_result_fragment (void *cls, const struct FragmentResult *fres)
{
  struct GNUNET_PSYCSTORE_Handle *h = cls;
  struct GNUNET_PSYCSTORE_OperationHandle *op = NULL;

  if (GNUNET_YES == GNUNET_OP_get (h->op, GNUNET_ntohll (fres->op_id),
                                   NULL, NULL, (void **) &op))
  {
    GNUNET_assert (NULL != op);
    if (NULL != op->fragment_cb)
      op->fragment_cb (op->cls,
                       (struct GNUNET_MULTICAST_MessageHeader *) &fres[1],
                       ntohl (fres->psycstore_flags));
    //GNUNET_OP_remove (h->op, GNUNET_ntohll (fres->op_id));
    //GNUNET_free (op);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "handle_result_fragment: No callback registered for operation with ID %" PRIu64 ".\n",
         GNUNET_ntohll (fres->op_id));
  }
  h->reconnect_delay = GNUNET_TIME_UNIT_MILLISECONDS;
}


static int
check_result_state (void *cls, const struct StateResult *sres)
{
  const char *name = (const char *) &sres[1];
  uint16_t size = ntohs (sres->header.size);
  uint16_t name_size = ntohs (sres->name_size);

  if (name_size <= 2
      || size - sizeof (*sres) < name_size
      || '\0' != name[name_size - 1])
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "check_result_state: Received state result message with invalid name.\n");
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


static void
handle_result_state (void *cls, const struct StateResult *sres)
{
  struct GNUNET_PSYCSTORE_Handle *h = cls;
  struct GNUNET_PSYCSTORE_OperationHandle *op = NULL;

  const char *name = (const char *) &sres[1];
  uint16_t name_size = ntohs (sres->name_size);

  if (GNUNET_YES == GNUNET_OP_get (h->op, GNUNET_ntohll (sres->op_id),
                                   NULL, NULL, (void **) &op))
  {
    GNUNET_assert (NULL != op);
    if (NULL != op->state_cb)
       op->state_cb (op->cls, name, (char *) &sres[1] + name_size,
                     ntohs (sres->header.size) - sizeof (*sres) - name_size);
    //GNUNET_OP_remove (h->op, GNUNET_ntohll (sres->op_id));
    //GNUNET_free (op);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "handle_result_state: No callback registered for operation with ID %" PRIu64 ".\n",
         GNUNET_ntohll (sres->op_id));
  }
  h->reconnect_delay = GNUNET_TIME_UNIT_MILLISECONDS;
}


static void
reconnect (void *cls);


/**
 * Client disconnected from service.
 *
 * Reconnect after backoff period.=
 */
static void
disconnected (void *cls, enum GNUNET_MQ_Error error)
{
  struct GNUNET_PSYCSTORE_Handle *h = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Origin client disconnected (%d), re-connecting\n",
       (int) error);
  if (NULL != h->mq)
  {
    GNUNET_MQ_destroy (h->mq);
    GNUNET_OP_destroy (h->op);
    h->mq = NULL;
    h->op = NULL;
  }

  h->reconnect_task = GNUNET_SCHEDULER_add_delayed (h->reconnect_delay,
                                                    &reconnect, h);
  h->reconnect_delay = GNUNET_TIME_STD_BACKOFF (h->reconnect_delay);
}


static void
do_connect (struct GNUNET_PSYCSTORE_Handle *h)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connecting to PSYCstore service.\n");

  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (result_code,
                           GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_CODE,
                           struct OperationResult,
                           h),
    GNUNET_MQ_hd_fixed_size (result_counters,
                             GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_COUNTERS,
                             struct CountersResult,
                             h),
    GNUNET_MQ_hd_var_size (result_fragment,
                           GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_FRAGMENT,
                           struct FragmentResult,
                           h),
    GNUNET_MQ_hd_var_size (result_state,
                           GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_STATE,
                           struct StateResult,
                           h),
    GNUNET_MQ_handler_end ()
  };

  h->op = GNUNET_OP_create ();
  GNUNET_assert (NULL == h->mq);
  h->mq = GNUNET_CLIENT_connecT (h->cfg, "psycstore",
                                 handlers, disconnected, h);
  GNUNET_assert (NULL != h->mq);
}


/**
 * Try again to connect to the PSYCstore service.
 *
 * @param cls Handle to the PSYCstore service.
 */
static void
reconnect (void *cls)
{
  do_connect (cls);
}


/**
 * Connect to the PSYCstore service.
 *
 * @param cfg The configuration to use
 * @return Handle to use
 */
struct GNUNET_PSYCSTORE_Handle *
GNUNET_PSYCSTORE_connect (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_PSYCSTORE_Handle *h
    = GNUNET_new (struct GNUNET_PSYCSTORE_Handle);
  h->cfg = cfg;
  h->reconnect_delay = GNUNET_TIME_UNIT_MILLISECONDS;
  do_connect (h);
  return h;
}


/**
 * Disconnect from PSYCstore service
 *
 * @param h Handle to destroy
 */
void
GNUNET_PSYCSTORE_disconnect (struct GNUNET_PSYCSTORE_Handle *h)
{
  GNUNET_assert (NULL != h);
  if (h->reconnect_task != NULL)
  {
    GNUNET_SCHEDULER_cancel (h->reconnect_task);
    h->reconnect_task = NULL;
  }
  if (NULL != h->mq)
  {
    // FIXME: free data structures for pending operations
    GNUNET_MQ_destroy (h->mq);
    h->mq = NULL;
  }
  GNUNET_free (h);
}


/**
 * Message sent notification.
 *
 * Remove invalidated envelope pointer.
 */
static void
message_sent (void *cls)
{
  struct GNUNET_PSYCSTORE_OperationHandle *op = cls;
  op->env = NULL;
}


/**
 * Create a new operation.
 */
static struct GNUNET_PSYCSTORE_OperationHandle *
op_create (struct GNUNET_PSYCSTORE_Handle *h,
           struct GNUNET_OP_Handle *hop,
           GNUNET_PSYCSTORE_ResultCallback result_cb,
           void *cls)
{
  struct GNUNET_PSYCSTORE_OperationHandle *
    op = GNUNET_malloc (sizeof (*op));
  op->h = h;
  op->op_id = GNUNET_OP_add (hop,
                             (GNUNET_ResultCallback) result_cb,
                             cls, op);
  return op;
}


/**
 * Send a message associated with an operation.
 *
 * @param h
 *        PSYCstore handle.
 * @param op
 *        Operation handle.
 * @param env
 *        Message envelope to send.
 * @param[out] op_id
 *        Operation ID to write in network byte order. NULL if not needed.
 *
 * @return Operation handle.
 *
 */
static struct GNUNET_PSYCSTORE_OperationHandle *
op_send (struct GNUNET_PSYCSTORE_Handle *h,
         struct GNUNET_PSYCSTORE_OperationHandle *op,
         struct GNUNET_MQ_Envelope *env,
         uint64_t *op_id)
{
  op->env = env;
  if (NULL != op_id)
    *op_id = GNUNET_htonll (op->op_id);

  GNUNET_MQ_notify_sent (env, message_sent, op);
  GNUNET_MQ_send (h->mq, env);
  return op;
}


/**
 * Cancel a PSYCstore operation. Note that the operation MAY still
 * be executed; this merely cancels the continuation; if the request
 * was already transmitted, the service may still choose to complete
 * the operation.
 *
 * @param op Operation to cancel.
 *
 * @return #GNUNET_YES if message was not sent yet and got discarded,
 *         #GNUNET_NO  if it was already sent, and only the callbacks got cancelled.
 */
int
GNUNET_PSYCSTORE_operation_cancel (struct GNUNET_PSYCSTORE_OperationHandle *op)
{
  struct GNUNET_PSYCSTORE_Handle *h = op->h;
  int ret = GNUNET_NO;

  if (NULL != op->env)
  {
    GNUNET_MQ_send_cancel (op->env);
    ret = GNUNET_YES;
  }

  GNUNET_OP_remove (h->op, op->op_id);
  GNUNET_free (op);

  return ret;
}


/**
 * Store join/leave events for a PSYC channel in order to be able to answer
 * membership test queries later.
 *
 * @param h
 *        Handle for the PSYCstore.
 * @param channel_key
 *        The channel where the event happened.
 * @param slave_key
 *        Public key of joining/leaving slave.
 * @param did_join
 *        #GNUNET_YES on join, #GNUNET_NO on part.
 * @param announced_at
 *        ID of the message that announced the membership change.
 * @param effective_since
 *        Message ID this membership change is in effect since.
 *        For joins it is <= announced_at, for parts it is always 0.
 * @param group_generation
 *        In case of a part, the last group generation the slave has access to.
 *        It has relevance when a larger message have fragments with different
 *        group generations.
 * @param result_cb
 *        Callback to call with the result of the storage operation.
 * @param cls
 *        Closure for the callback.
 *
 * @return Operation handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_membership_store (struct GNUNET_PSYCSTORE_Handle *h,
                                   const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                                   const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key,
                                   int did_join,
                                   uint64_t announced_at,
                                   uint64_t effective_since,
                                   uint64_t group_generation,
                                   GNUNET_PSYCSTORE_ResultCallback result_cb,
                                   void *cls)
{
  GNUNET_assert (NULL != h);
  GNUNET_assert (NULL != channel_key);
  GNUNET_assert (NULL != slave_key);
  GNUNET_assert (GNUNET_YES == did_join || GNUNET_NO == did_join);
  GNUNET_assert (did_join
                 ? effective_since <= announced_at
                 : effective_since == 0);

  struct MembershipStoreRequest *req;
  struct GNUNET_MQ_Envelope *
    env = GNUNET_MQ_msg (req, GNUNET_MESSAGE_TYPE_PSYCSTORE_MEMBERSHIP_STORE);
  req->channel_key = *channel_key;
  req->slave_key = *slave_key;
  req->did_join = did_join;
  req->announced_at = GNUNET_htonll (announced_at);
  req->effective_since = GNUNET_htonll (effective_since);
  req->group_generation = GNUNET_htonll (group_generation);

  return
    op_send (h, op_create (h, h->op, result_cb, cls),
             env, &req->op_id);
}


/**
 * Test if a member was admitted to the channel at the given message ID.
 *
 * This is useful when relaying and replaying messages to check if a particular
 * slave has access to the message fragment with a given group generation.  It
 * is also used when handling join requests to determine whether the slave is
 * currently admitted to the channel.
 *
 * @param h
 *        Handle for the PSYCstore.
 * @param channel_key
 *        The channel we are interested in.
 * @param slave_key
 *        Public key of slave whose membership to check.
 * @param message_id
 *        Message ID for which to do the membership test.
 * @param group_generation
 *        Group generation of the fragment of the message to test.
 *        It has relevance if the message consists of multiple fragments with
 *        different group generations.
 * @param result_cb
 *        Callback to call with the test result.
 * @param cls
 *        Closure for the callback.
 *
 * @return Operation handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_membership_test (struct GNUNET_PSYCSTORE_Handle *h,
                                  const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                                  const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key,
                                  uint64_t message_id,
                                  uint64_t group_generation,
                                  GNUNET_PSYCSTORE_ResultCallback result_cb,
                                  void *cls)
{
  struct MembershipTestRequest *req;
  struct GNUNET_MQ_Envelope *
    env = GNUNET_MQ_msg (req, GNUNET_MESSAGE_TYPE_PSYCSTORE_MEMBERSHIP_TEST);
  req->channel_key = *channel_key;
  req->slave_key = *slave_key;
  req->message_id = GNUNET_htonll (message_id);
  req->group_generation = GNUNET_htonll (group_generation);

  return
    op_send (h, op_create (h, h->op, result_cb, cls),
             env, &req->op_id);
}


/**
 * Store a message fragment sent to a channel.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_key The channel the message belongs to.
 * @param message Message to store.
 * @param psycstore_flags Flags indicating whether the PSYC message contains
 *        state modifiers.
 * @param result_cb Callback to call with the result of the operation.
 * @param cls Closure for the callback.
 *
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_fragment_store (struct GNUNET_PSYCSTORE_Handle *h,
                                 const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                                 const struct GNUNET_MULTICAST_MessageHeader *msg,
                                 enum GNUNET_PSYCSTORE_MessageFlags psycstore_flags,
                                 GNUNET_PSYCSTORE_ResultCallback result_cb,
                                 void *cls)
{
  uint16_t size = ntohs (msg->header.size);
  struct FragmentStoreRequest *req;
  struct GNUNET_MQ_Envelope *
    env = GNUNET_MQ_msg_extra (req, size,
                               GNUNET_MESSAGE_TYPE_PSYCSTORE_FRAGMENT_STORE);
  req->channel_key = *channel_key;
  req->psycstore_flags = htonl (psycstore_flags);
  GNUNET_memcpy (&req[1], msg, size);

  return
    op_send (h, op_create (h, h->op, result_cb, cls),
             env, &req->op_id);
}


/**
 * Retrieve message fragments by fragment ID range.
 *
 * @param h
 *        Handle for the PSYCstore.
 * @param channel_key
 *        The channel we are interested in.
 * @param slave_key
 *        The slave requesting the fragment.  If not NULL, a membership test is
 *        performed first and the fragment is only returned if the slave has
 *        access to it.
 * @param first_fragment_id
 *        First fragment ID to retrieve.
 *        Use 0 to get the latest message fragment.
 * @param last_fragment_id
 *        Last consecutive fragment ID to retrieve.
 *        Use 0 to get the latest message fragment.
 * @param fragment_limit
 *        Maximum number of fragments to retrieve.
 * @param fragment_cb
 *        Callback to call with the retrieved fragments.
 * @param result_cb
 *        Callback to call with the result of the operation.
 * @param cls
 *        Closure for the callbacks.
 *
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_fragment_get (struct GNUNET_PSYCSTORE_Handle *h,
                               const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                               const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key,
                               uint64_t first_fragment_id,
                               uint64_t last_fragment_id,
                               GNUNET_PSYCSTORE_FragmentCallback fragment_cb,
                               GNUNET_PSYCSTORE_ResultCallback result_cb,
                               void *cls)
{
  struct FragmentGetRequest *req;
  struct GNUNET_MQ_Envelope *
    env = GNUNET_MQ_msg (req, GNUNET_MESSAGE_TYPE_PSYCSTORE_FRAGMENT_GET);
  req->channel_key = *channel_key;
  req->first_fragment_id = GNUNET_htonll (first_fragment_id);
  req->last_fragment_id = GNUNET_htonll (last_fragment_id);
  if (NULL != slave_key)
  {
    req->slave_key = *slave_key;
    req->do_membership_test = GNUNET_YES;
  }

  struct GNUNET_PSYCSTORE_OperationHandle *
    op = op_create (h, h->op, result_cb, cls);
  op->fragment_cb = fragment_cb;
  op->cls = cls;
  return op_send (h, op, env, &req->op_id);
}


/**
 * Retrieve latest message fragments.
 *
 * @param h
 *        Handle for the PSYCstore.
 * @param channel_key
 *        The channel we are interested in.
 * @param slave_key
 *        The slave requesting the fragment.  If not NULL, a membership test is
 *        performed first and the fragment is only returned if the slave has
 *        access to it.
 * @param first_fragment_id
 *        First fragment ID to retrieve.
 *        Use 0 to get the latest message fragment.
 * @param last_fragment_id
 *        Last consecutive fragment ID to retrieve.
 *        Use 0 to get the latest message fragment.
 * @param fragment_limit
 *        Maximum number of fragments to retrieve.
 * @param fragment_cb
 *        Callback to call with the retrieved fragments.
 * @param result_cb
 *        Callback to call with the result of the operation.
 * @param cls
 *        Closure for the callbacks.
 *
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_fragment_get_latest (struct GNUNET_PSYCSTORE_Handle *h,
                                      const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                                      const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key,
                                      uint64_t fragment_limit,
                                      GNUNET_PSYCSTORE_FragmentCallback fragment_cb,
                                      GNUNET_PSYCSTORE_ResultCallback result_cb,
                                      void *cls)
{
  struct FragmentGetRequest *req;
  struct GNUNET_MQ_Envelope *
    env = GNUNET_MQ_msg (req, GNUNET_MESSAGE_TYPE_PSYCSTORE_FRAGMENT_GET);
  req->channel_key = *channel_key;
  req->fragment_limit = GNUNET_ntohll (fragment_limit);
  if (NULL != slave_key)
  {
    req->slave_key = *slave_key;
    req->do_membership_test = GNUNET_YES;
  }

  struct GNUNET_PSYCSTORE_OperationHandle *
    op = op_create (h, h->op, result_cb, cls);
  op->fragment_cb = fragment_cb;
  op->cls = cls;
  return op_send (h, op, env, &req->op_id);
}


/**
 * Retrieve all fragments of messages in a message ID range.
 *
 * @param h
 *        Handle for the PSYCstore.
 * @param channel_key
 *        The channel we are interested in.
 * @param slave_key
 *        The slave requesting the message.
 *        If not NULL, a membership test is performed first
 *        and the message is only returned if the slave has access to it.
 * @param first_message_id
 *        First message ID to retrieve.
 * @param last_message_id
 *        Last consecutive message ID to retrieve.
 * @param fragment_limit
 *        Maximum number of fragments to retrieve.
 * @param method_prefix
 *        Retrieve only messages with a matching method prefix.
 * @todo Implement method_prefix query.
 * @param fragment_cb
 *        Callback to call with the retrieved fragments.
 * @param result_cb
 *        Callback to call with the result of the operation.
 * @param cls
 *        Closure for the callbacks.
 *
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_message_get (struct GNUNET_PSYCSTORE_Handle *h,
                              const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                              const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key,
                              uint64_t first_message_id,
                              uint64_t last_message_id,
                              uint64_t fragment_limit,
                              const char *method_prefix,
                              GNUNET_PSYCSTORE_FragmentCallback fragment_cb,
                              GNUNET_PSYCSTORE_ResultCallback result_cb,
                              void *cls)
{
  struct MessageGetRequest *req;
  if (NULL == method_prefix)
    method_prefix = "";
  uint16_t method_size = strnlen (method_prefix,
                                  GNUNET_SERVER_MAX_MESSAGE_SIZE
                                  - sizeof (*req)) + 1;

  struct GNUNET_MQ_Envelope *
    env = GNUNET_MQ_msg_extra (req, method_size,
                               GNUNET_MESSAGE_TYPE_PSYCSTORE_MESSAGE_GET);
  req->channel_key = *channel_key;
  req->first_message_id = GNUNET_htonll (first_message_id);
  req->last_message_id = GNUNET_htonll (last_message_id);
  req->fragment_limit = GNUNET_htonll (fragment_limit);
  if (NULL != slave_key)
  {
    req->slave_key = *slave_key;
    req->do_membership_test = GNUNET_YES;
  }
  GNUNET_memcpy (&req[1], method_prefix, method_size);
  ((char *) &req[1])[method_size - 1] = '\0';

  struct GNUNET_PSYCSTORE_OperationHandle *
    op = op_create (h, h->op, result_cb, cls);
  op->fragment_cb = fragment_cb;
  op->cls = cls;
  return op_send (h, op, env, &req->op_id);
}


/**
 * Retrieve all fragments of the latest messages.
 *
 * @param h
 *        Handle for the PSYCstore.
 * @param channel_key
 *        The channel we are interested in.
 * @param slave_key
 *        The slave requesting the message.
 *        If not NULL, a membership test is performed first
 *        and the message is only returned if the slave has access to it.
 * @param message_limit
 *        Maximum number of messages to retrieve.
 * @param method_prefix
 *        Retrieve only messages with a matching method prefix.
 * @todo Implement method_prefix query.
 * @param fragment_cb
 *        Callback to call with the retrieved fragments.
 * @param result_cb
 *        Callback to call with the result of the operation.
 * @param cls
 *        Closure for the callbacks.
 *
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_message_get_latest (struct GNUNET_PSYCSTORE_Handle *h,
                                     const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                                     const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key,
                                     uint64_t message_limit,
                                     const char *method_prefix,
                                     GNUNET_PSYCSTORE_FragmentCallback fragment_cb,
                                     GNUNET_PSYCSTORE_ResultCallback result_cb,
                                     void *cls)
{
  struct MessageGetRequest *req;

  if (NULL == method_prefix)
    method_prefix = "";
  uint16_t method_size = strnlen (method_prefix,
                                  GNUNET_SERVER_MAX_MESSAGE_SIZE
                                  - sizeof (*req)) + 1;
  GNUNET_assert ('\0' == method_prefix[method_size - 1]);

  struct GNUNET_MQ_Envelope *
    env = GNUNET_MQ_msg_extra (req, method_size,
                               GNUNET_MESSAGE_TYPE_PSYCSTORE_MESSAGE_GET);
  req->channel_key = *channel_key;
  req->message_limit = GNUNET_ntohll (message_limit);
  if (NULL != slave_key)
  {
    req->slave_key = *slave_key;
    req->do_membership_test = GNUNET_YES;
  }
  GNUNET_memcpy (&req[1], method_prefix, method_size);

  struct GNUNET_PSYCSTORE_OperationHandle *
    op = op_create (h, h->op, result_cb, cls);
  op->fragment_cb = fragment_cb;
  op->cls = cls;
  return op_send (h, op, env, &req->op_id);
}


/**
 * Retrieve a fragment of message specified by its message ID and fragment
 * offset.
 *
 * @param h
 *        Handle for the PSYCstore.
 * @param channel_key
 *        The channel we are interested in.
 * @param slave_key
 *        The slave requesting the message fragment.  If not NULL, a membership
 *        test is performed first and the message fragment is only returned
 *        if the slave has access to it.
 * @param message_id
 *        Message ID to retrieve.  Use 0 to get the latest message.
 * @param fragment_offset
 *        Offset of the fragment to retrieve.
 * @param fragment_cb
 *        Callback to call with the retrieved fragments.
 * @param result_cb
 *        Callback to call with the result of the operation.
 * @param cls
 *        Closure for the callbacks.
 *
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_message_get_fragment (struct GNUNET_PSYCSTORE_Handle *h,
                                       const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                                       const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key,
                                       uint64_t message_id,
                                       uint64_t fragment_offset,
                                       GNUNET_PSYCSTORE_FragmentCallback fragment_cb,
                                       GNUNET_PSYCSTORE_ResultCallback result_cb,
                                       void *cls)
{
  struct MessageGetFragmentRequest *req;
  struct GNUNET_MQ_Envelope *
    env = GNUNET_MQ_msg (req, GNUNET_MESSAGE_TYPE_PSYCSTORE_MESSAGE_GET_FRAGMENT);

  req->channel_key = *channel_key;
  req->message_id = GNUNET_htonll (message_id);
  req->fragment_offset = GNUNET_htonll (fragment_offset);
  if (NULL != slave_key)
  {
    req->slave_key = *slave_key;
    req->do_membership_test = GNUNET_YES;
  }

  struct GNUNET_PSYCSTORE_OperationHandle *
    op = op_create (h, h->op, result_cb, cls);
  op->fragment_cb = fragment_cb;
  op->cls = cls;
  return op_send (h, op, env, &req->op_id);
}


/**
 * Retrieve latest values of counters for a channel master.
 *
 * The current value of counters are needed when a channel master is restarted,
 * so that it can continue incrementing the counters from their last value.
 *
 * @param h
 *        Handle for the PSYCstore.
 * @param channel_key
 *        Public key that identifies the channel.
 * @param ccb
 *        Callback to call with the result.
 * @param ccb_cls
 *        Closure for the @a ccb callback.
 *
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_counters_get (struct GNUNET_PSYCSTORE_Handle *h,
                               struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                               GNUNET_PSYCSTORE_CountersCallback counters_cb,
                               void *cls)
{
  struct OperationRequest *req;
  struct GNUNET_MQ_Envelope *
    env = GNUNET_MQ_msg (req, GNUNET_MESSAGE_TYPE_PSYCSTORE_COUNTERS_GET);
  req->channel_key = *channel_key;

  struct GNUNET_PSYCSTORE_OperationHandle *
    op = op_create (h, h->op, NULL, NULL);
  op->counters_cb = counters_cb;
  op->cls = cls;
  return op_send (h, op, env, &req->op_id);
}


/**
 * Apply modifiers of a message to the current channel state.
 *
 * An error is returned if there are missing messages containing state
 * operations before the current one.
 *
 * @param h
 *        Handle for the PSYCstore.
 * @param channel_key
 *        The channel we are interested in.
 * @param message_id
 *        ID of the message that contains the @a modifiers.
 * @param state_delta
 *        Value of the _state_delta PSYC header variable of the message.
 * @param result_cb
 *        Callback to call with the result of the operation.
 * @param cls
 *        Closure for @a result_cb.
 *
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_state_modify (struct GNUNET_PSYCSTORE_Handle *h,
                               const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                               uint64_t message_id,
                               uint64_t state_delta,
                               GNUNET_PSYCSTORE_ResultCallback result_cb,
                               void *cls)
{
  struct StateModifyRequest *req;
  struct GNUNET_MQ_Envelope *
    env = GNUNET_MQ_msg (req, GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_MODIFY);
  req->channel_key = *channel_key;
  req->message_id = GNUNET_htonll (message_id);
  req->state_delta = GNUNET_htonll (state_delta);

  return op_send (h, op_create (h, h->op, result_cb, cls),
                  env, &req->op_id);
}


struct StateSyncClosure
{
  GNUNET_PSYCSTORE_ResultCallback result_cb;
  void *cls;
  uint8_t last;
};


static void
state_sync_result (void *cls, int64_t result,
                   const char *err_msg, uint16_t err_msg_size)
{
  struct StateSyncClosure *ssc = cls;
  if (GNUNET_OK != result || ssc->last)
    ssc->result_cb (ssc->cls, result, err_msg, err_msg_size);
  GNUNET_free (ssc);
}


/**
 * Store synchronized state.
 *
 * @param h
 *        Handle for the PSYCstore.
 * @param channel_key
 *        The channel we are interested in.
 * @param max_state_message_id
 *        ID of the last stateful message before @a state_hash_message_id.
 * @param state_hash_message_id
 *        ID of the message that contains the state_hash PSYC header variable.
 * @param modifier_count
 *        Number of elements in the @a modifiers array.
 * @param modifiers
 *        Full state to store.
 * @param result_cb
 *        Callback to call with the result of the operation.
 * @param cls
 *        Closure for the callback.
 *
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_state_sync (struct GNUNET_PSYCSTORE_Handle *h,
                             const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                             uint64_t max_state_message_id,
                             uint64_t state_hash_message_id,
                             size_t modifier_count,
                             const struct GNUNET_PSYC_Modifier *modifiers,
                             GNUNET_PSYCSTORE_ResultCallback result_cb,
                             void *cls)
{
  struct GNUNET_PSYCSTORE_OperationHandle *op = NULL;
  size_t i;

  for (i = 0; i < modifier_count; i++) {
    struct StateSyncRequest *req;
    uint16_t name_size = strlen (modifiers[i].name) + 1;

    struct GNUNET_MQ_Envelope *
      env = GNUNET_MQ_msg_extra (req,
                                 sizeof (*req) + name_size + modifiers[i].value_size,
                                 GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_SYNC);

    req->header.type = htons (GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_SYNC);
    req->header.size = htons (sizeof (*req) + name_size
                              + modifiers[i].value_size);
    req->channel_key = *channel_key;
    req->max_state_message_id = GNUNET_htonll (max_state_message_id);
    req->state_hash_message_id = GNUNET_htonll (state_hash_message_id);
    req->name_size = htons (name_size);
    req->flags
      = (0 == i)
      ? STATE_OP_FIRST
      : (modifier_count - 1 == i)
      ? STATE_OP_LAST
      : 0;

    GNUNET_memcpy (&req[1], modifiers[i].name, name_size);
    GNUNET_memcpy ((char *) &req[1] + name_size, modifiers[i].value, modifiers[i].value_size);

    struct StateSyncClosure *ssc = GNUNET_malloc (sizeof (*ssc));
    ssc->last = (req->flags & STATE_OP_LAST);
    ssc->result_cb = result_cb;
    ssc->cls = cls;

    op_send (h, op_create (h, h->op, state_sync_result, ssc),
             env, &req->op_id);
  }
  // FIXME: only one operation is returned,
  //        add pointers to other operations and make all cancellable.
  return op;
}


/**
 * Reset the state of a channel.
 *
 * Delete all state variables stored for the given channel.
 *
 * @param h
 *        Handle for the PSYCstore.
 * @param channel_key
 *        The channel we are interested in.
 * @param result_cb
 *        Callback to call with the result of the operation.
 * @param cls
 *        Closure for the callback.
 *
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_state_reset (struct GNUNET_PSYCSTORE_Handle *h,
                              const struct GNUNET_CRYPTO_EddsaPublicKey
                              *channel_key,
                              GNUNET_PSYCSTORE_ResultCallback result_cb,
                              void *cls)
{
  struct OperationRequest *req;
  struct GNUNET_MQ_Envelope *
    env = GNUNET_MQ_msg (req, GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_RESET);
  req->channel_key = *channel_key;

  return
    op_send (h, op_create (h, h->op, result_cb, cls),
             env, &req->op_id);
}


/**
 * Update signed values of state variables in the state store.
 *
 * @param h
 *        Handle for the PSYCstore.
 * @param channel_key
 *        The channel we are interested in.
 * @param message_id
 *        Message ID that contained the state @a hash.
 * @param hash
 *        Hash of the serialized full state.
 * @param result_cb
 *        Callback to call with the result of the operation.
 * @param cls
 *        Closure for the callback.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_state_hash_update (struct GNUNET_PSYCSTORE_Handle *h,
                                    const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                                    uint64_t message_id,
                                    const struct GNUNET_HashCode *hash,
                                    GNUNET_PSYCSTORE_ResultCallback result_cb,
                                    void *cls)
{
  struct StateHashUpdateRequest *req;
  struct GNUNET_MQ_Envelope *
    env = GNUNET_MQ_msg (req, GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_HASH_UPDATE);
  req->channel_key = *channel_key;
  req->hash = *hash;

  return
    op_send (h, op_create (h, h->op, result_cb, cls),
             env, &req->op_id);
}


/**
 * Retrieve the best matching state variable.
 *
 * @param h
 *        Handle for the PSYCstore.
 * @param channel_key
 *        The channel we are interested in.
 * @param name
 *        Name of variable to match, the returned variable might be less specific.
 * @param state_cb
 *        Callback to return the matching state variable.
 * @param result_cb
 *        Callback to call with the result of the operation.
 * @param cls
 *        Closure for the callbacks.
 *
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_state_get (struct GNUNET_PSYCSTORE_Handle *h,
                            const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                            const char *name,
                            GNUNET_PSYCSTORE_StateCallback state_cb,
                            GNUNET_PSYCSTORE_ResultCallback result_cb,
                            void *cls)
{
  size_t name_size = strlen (name) + 1;
  struct OperationRequest *req;
  struct GNUNET_MQ_Envelope *
    env = GNUNET_MQ_msg_extra (req, name_size,
                               GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_GET);
  req->channel_key = *channel_key;
  GNUNET_memcpy (&req[1], name, name_size);

  struct GNUNET_PSYCSTORE_OperationHandle *
    op = op_create (h, h->op, result_cb, cls);
  op->state_cb = state_cb;
  op->cls = cls;
  return op_send (h, op, env, &req->op_id);
}


/**
 * Retrieve all state variables for a channel with the given prefix.
 *
 * @param h
 *        Handle for the PSYCstore.
 * @param channel_key
 *        The channel we are interested in.
 * @param name_prefix
 *        Prefix of state variable names to match.
 * @param state_cb
 *        Callback to return matching state variables.
 * @param result_cb
 *        Callback to call with the result of the operation.
 * @param cls
 *        Closure for the callbacks.
 *
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_state_get_prefix (struct GNUNET_PSYCSTORE_Handle *h,
                                   const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                                   const char *name_prefix,
                                   GNUNET_PSYCSTORE_StateCallback state_cb,
                                   GNUNET_PSYCSTORE_ResultCallback result_cb,
                                   void *cls)
{
  size_t name_size = strlen (name_prefix) + 1;
  struct OperationRequest *req;
  struct GNUNET_MQ_Envelope *
    env = GNUNET_MQ_msg_extra (req, name_size,
                               GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_GET_PREFIX);
  req->channel_key = *channel_key;
  GNUNET_memcpy (&req[1], name_prefix, name_size);

  struct GNUNET_PSYCSTORE_OperationHandle *
    op = op_create (h, h->op, result_cb, cls);
  op->state_cb = state_cb;
  op->cls = cls;
  return op_send (h, op, env, &req->op_id);
}

/* end of psycstore_api.c */
