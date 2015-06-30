/*
 * This file is part of GNUnet
 * Copyright (C) 2013 Christian Grothoff (and other contributing authors)
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

typedef void (*DataCallback) ();

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
   * We keep operations in a DLL.
   */
  struct GNUNET_PSYCSTORE_OperationHandle *next;

  /**
   * We keep operations in a DLL.
   */
  struct GNUNET_PSYCSTORE_OperationHandle *prev;

  /**
   * Continuation to invoke with the result of an operation.
   */
  GNUNET_PSYCSTORE_ResultCallback res_cb;

  /**
   * Continuation to invoke with the result of an operation returning data.
   */
  DataCallback data_cb;

  /**
   * Closure for the callbacks.
   */
  void *cls;

  /**
   * Operation ID.
   */
  uint64_t op_id;

  /**
   * Message to send to the PSYCstore service.
   * Allocated at the end of this struct.
   */
  const struct GNUNET_MessageHeader *msg;
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
   * Socket (if available).
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Head of operations to transmit.
   */
  struct GNUNET_PSYCSTORE_OperationHandle *transmit_head;

  /**
   * Tail of operations to transmit.
   */
  struct GNUNET_PSYCSTORE_OperationHandle *transmit_tail;

  /**
   * Head of active operations waiting for response.
   */
  struct GNUNET_PSYCSTORE_OperationHandle *op_head;

  /**
   * Tail of active operations waiting for response.
   */
  struct GNUNET_PSYCSTORE_OperationHandle *op_tail;

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
  struct GNUNET_TIME_Relative reconnect_delay;

  /**
   * Last operation ID used.
   */
  uint64_t last_op_id;

  /**
   * Are we polling for incoming messages right now?
   */
  uint8_t in_receive;
};


/**
 * Get a fresh operation ID to distinguish between PSYCstore requests.
 *
 * @param h Handle to the PSYCstore service.
 * @return next operation id to use
 */
static uint64_t
get_next_op_id (struct GNUNET_PSYCSTORE_Handle *h)
{
  return h->last_op_id++;
}


/**
 * Find operation by ID.
 *
 * @return OperationHandle if found, or NULL otherwise.
 */
static struct GNUNET_PSYCSTORE_OperationHandle *
find_op_by_id (struct GNUNET_PSYCSTORE_Handle *h, uint64_t op_id)
{
  struct GNUNET_PSYCSTORE_OperationHandle *op = h->op_head;
  while (NULL != op)
  {
    if (op->op_id == op_id)
      return op;
    op = op->next;
  }
  return NULL;
}


/**
 * Try again to connect to the PSYCstore service.
 *
 * @param cls handle to the PSYCstore service.
 * @param tc scheduler context
 */
static void
reconnect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Reschedule a connect attempt to the service.
 *
 * @param h transport service to reconnect
 */
static void
reschedule_connect (struct GNUNET_PSYCSTORE_Handle *h)
{
  GNUNET_assert (h->reconnect_task == NULL);

  if (NULL != h->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->th);
    h->th = NULL;
  }
  if (NULL != h->client)
  {
    GNUNET_CLIENT_disconnect (h->client);
    h->client = NULL;
  }
  h->in_receive = GNUNET_NO;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Scheduling task to reconnect to PSYCstore service in %s.\n",
       GNUNET_STRINGS_relative_time_to_string (h->reconnect_delay, GNUNET_YES));
  h->reconnect_task =
      GNUNET_SCHEDULER_add_delayed (h->reconnect_delay, &reconnect, h);
  h->reconnect_delay = GNUNET_TIME_STD_BACKOFF (h->reconnect_delay);
}


/**
 * Schedule transmission of the next message from our queue.
 *
 * @param h PSYCstore handle
 */
static void
transmit_next (struct GNUNET_PSYCSTORE_Handle *h);


/**
 * Type of a function to call when we receive a message
 * from the service.
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
static void
message_handler (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_PSYCSTORE_Handle *h = cls;
  struct GNUNET_PSYCSTORE_OperationHandle *op;
  const struct OperationResult *opres;
  const struct CountersResult *cres;
  const struct FragmentResult *fres;
  const struct StateResult *sres;
  const char *str;

  if (NULL == msg)
  {
    reschedule_connect (h);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received message of type %d from PSYCstore service.\n",
       ntohs (msg->type));
  uint16_t size = ntohs (msg->size);
  uint16_t type = ntohs (msg->type);
  switch (type)
  {
  case GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_CODE:
    if (size < sizeof (struct OperationResult))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           "Received message of type %d with length %lu bytes. "
           "Expected >= %lu\n",
           type, size, sizeof (struct OperationResult));
      GNUNET_break (0);
      reschedule_connect (h);
      return;
    }

    opres = (const struct OperationResult *) msg;
    str = (const char *) &opres[1];
    if ( (size > sizeof (struct OperationResult)) &&
	 ('\0' != str[size - sizeof (struct OperationResult) - 1]) )
    {
      GNUNET_break (0);
      reschedule_connect (h);
      return;
    }
    if (size == sizeof (struct OperationResult))
      str = "";

    op = find_op_by_id (h, GNUNET_ntohll (opres->op_id));
    if (NULL == op)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "No callback registered for operation with ID %" PRIu64 ".\n",
           type, GNUNET_ntohll (opres->op_id));
    }
    else
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Received result message (type %d) with operation ID: %" PRIu64 "\n",
           type, op->op_id);

      int64_t result_code = GNUNET_ntohll (opres->result_code) + INT64_MIN;
      GNUNET_CONTAINER_DLL_remove (h->op_head, h->op_tail, op);
      if (NULL != op->res_cb)
      {
        const struct StateModifyRequest *smreq;
        const struct StateSyncRequest *ssreq;
        switch (ntohs (op->msg->type))
        {
        case GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_MODIFY:
          smreq = (const struct StateModifyRequest *) op->msg;
          if (!(smreq->flags & STATE_OP_LAST
                || GNUNET_OK != result_code))
            op->res_cb = NULL;
          break;
        case GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_SYNC:
          ssreq = (const struct StateSyncRequest *) op->msg;
          if (!(ssreq->flags & STATE_OP_LAST
                || GNUNET_OK != result_code))
            op->res_cb = NULL;
          break;
        }
      }
      if (NULL != op->res_cb)
        op->res_cb (op->cls, result_code, str, size - sizeof (*opres));
      GNUNET_free (op);
    }
    break;

  case GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_COUNTERS:
    if (size != sizeof (struct CountersResult))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           "Received message of type %d with length %lu bytes. "
           "Expected %lu\n",
           type, size, sizeof (struct CountersResult));
      GNUNET_break (0);
      reschedule_connect (h);
      return;
    }

    cres = (const struct CountersResult *) msg;

    op = find_op_by_id (h, GNUNET_ntohll (cres->op_id));
    if (NULL == op)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "No callback registered for operation with ID %" PRIu64 ".\n",
           type, GNUNET_ntohll (cres->op_id));
    }
    else
    {
      GNUNET_CONTAINER_DLL_remove (h->op_head, h->op_tail, op);
      if (NULL != op->data_cb)
        ((GNUNET_PSYCSTORE_CountersCallback)
         op->data_cb) (op->cls,
                       ntohl (cres->result_code) + INT32_MIN,
                       GNUNET_ntohll (cres->max_fragment_id),
                       GNUNET_ntohll (cres->max_message_id),
                       GNUNET_ntohll (cres->max_group_generation),
                       GNUNET_ntohll (cres->max_state_message_id));
      GNUNET_free (op);
    }
    break;

  case GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_FRAGMENT:
    if (size < sizeof (struct FragmentResult))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           "Received message of type %d with length %lu bytes. "
           "Expected >= %lu\n",
           type, size, sizeof (struct FragmentResult));
      GNUNET_break (0);
      reschedule_connect (h);
      return;
    }

    fres = (const struct FragmentResult *) msg;
    struct GNUNET_MULTICAST_MessageHeader *mmsg =
      (struct GNUNET_MULTICAST_MessageHeader *) &fres[1];
    if (size != sizeof (struct FragmentResult) + ntohs (mmsg->header.size))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           "Received message of type %d with length %lu bytes. "
           "Expected = %lu\n",
           type, size,
           sizeof (struct FragmentResult) + ntohs (mmsg->header.size));
      GNUNET_break (0);
      reschedule_connect (h);
      return;
    }

    op = find_op_by_id (h, GNUNET_ntohll (fres->op_id));
    if (NULL == op)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "No callback registered for operation with ID %" PRIu64 ".\n",
           type, GNUNET_ntohll (fres->op_id));
    }
    else
    {
      if (NULL != op->data_cb)
        ((GNUNET_PSYCSTORE_FragmentCallback)
         op->data_cb) (op->cls, mmsg, ntohl (fres->psycstore_flags));
    }
    break;

  case GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_STATE:
    if (size < sizeof (struct StateResult))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           "Received message of type %d with length %lu bytes. "
           "Expected >= %lu\n",
           type, size, sizeof (struct StateResult));
      GNUNET_break (0);
      reschedule_connect (h);
      return;
    }

    sres = (const struct StateResult *) msg;
    const char *name = (const char *) &sres[1];
    uint16_t name_size = ntohs (sres->name_size);

    if (name_size <= 2 || '\0' != name[name_size - 1])
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           "Received state result message (type %d) with invalid name.\n",
           type);
      GNUNET_break (0);
      reschedule_connect (h);
      return;
    }

    op = find_op_by_id (h, GNUNET_ntohll (sres->op_id));
    if (NULL == op)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "No callback registered for operation with ID %" PRIu64 ".\n",
           type, GNUNET_ntohll (sres->op_id));
    }
    else
    {
      if (NULL != op->data_cb)
        ((GNUNET_PSYCSTORE_StateCallback)
         op->data_cb) (op->cls, name, (char *) &sres[1] + name_size,
                       ntohs (sres->header.size) - sizeof (*sres) - name_size);
    }
    break;

  default:
    GNUNET_break (0);
    reschedule_connect (h);
    return;
  }

  GNUNET_CLIENT_receive (h->client, &message_handler, h,
                         GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Transmit next message to service.
 *
 * @param cls The 'struct GNUNET_PSYCSTORE_Handle'.
 * @param size Number of bytes available in buf.
 * @param buf Where to copy the message.
 * @return Number of bytes copied to buf.
 */
static size_t
send_next_message (void *cls, size_t size, void *buf)
{
  struct GNUNET_PSYCSTORE_Handle *h = cls;
  struct GNUNET_PSYCSTORE_OperationHandle *op = h->transmit_head;
  size_t ret;

  h->th = NULL;
  if (NULL == op)
    return 0;
  ret = ntohs (op->msg->size);
  if (ret > size)
  {
    reschedule_connect (h);
    return 0;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending message of type %d to PSYCstore service. ID: %" PRIu64 "\n",
       ntohs (op->msg->type), op->op_id);
  memcpy (buf, op->msg, ret);

  GNUNET_CONTAINER_DLL_remove (h->transmit_head, h->transmit_tail, op);

  if (NULL == op->res_cb && NULL == op->data_cb)
  {
    GNUNET_free (op);
  }
  else
  {
    GNUNET_CONTAINER_DLL_insert_tail (h->op_head, h->op_tail, op);
  }

  if (NULL != h->transmit_head)
    transmit_next (h);

  if (GNUNET_NO == h->in_receive)
  {
    h->in_receive = GNUNET_YES;
    GNUNET_CLIENT_receive (h->client, &message_handler, h,
			   GNUNET_TIME_UNIT_FOREVER_REL);
  }
  return ret;
}


/**
 * Schedule transmission of the next message from our queue.
 *
 * @param h PSYCstore handle.
 */
static void
transmit_next (struct GNUNET_PSYCSTORE_Handle *h)
{
  if (NULL != h->th || NULL == h->client)
    return;

  struct GNUNET_PSYCSTORE_OperationHandle *op = h->transmit_head;
  if (NULL == op)
    return;

  h->th = GNUNET_CLIENT_notify_transmit_ready (h->client,
					       ntohs (op->msg->size),
					       GNUNET_TIME_UNIT_FOREVER_REL,
					       GNUNET_NO,
					       &send_next_message,
					       h);
}


/**
 * Try again to connect to the PSYCstore service.
 *
 * @param cls Handle to the PSYCstore service.
 * @param tc Scheduler context.
 */
static void
reconnect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_PSYCSTORE_Handle *h = cls;

  h->reconnect_task = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connecting to PSYCstore service.\n");
  GNUNET_assert (NULL == h->client);
  h->client = GNUNET_CLIENT_connect ("psycstore", h->cfg);
  GNUNET_assert (NULL != h->client);
  transmit_next (h);
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
  h->reconnect_delay = GNUNET_TIME_UNIT_ZERO;
  h->reconnect_task = GNUNET_SCHEDULER_add_now (&reconnect, h);
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
  if (NULL != h->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->th);
    h->th = NULL;
  }
  if (NULL != h->client)
  {
    GNUNET_CLIENT_disconnect (h->client);
    h->client = NULL;
  }
  GNUNET_free (h);
}


/**
 * Cancel a PSYCstore operation. Note that the operation MAY still
 * be executed; this merely cancels the continuation; if the request
 * was already transmitted, the service may still choose to complete
 * the operation.
 *
 * @param op Operation to cancel.
 */
void
GNUNET_PSYCSTORE_operation_cancel (struct GNUNET_PSYCSTORE_OperationHandle *op)
{
  struct GNUNET_PSYCSTORE_Handle *h = op->h;

  if (h->transmit_head != NULL && (h->transmit_head != op || NULL == h->client))
  {
    /* request not active, can simply remove */
    GNUNET_CONTAINER_DLL_remove (h->transmit_head, h->transmit_tail, op);
    GNUNET_free (op);
    return;
  }
  if (NULL != h->th)
  {
    /* request active but not yet with service, can still abort */
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->th);
    h->th = NULL;
    GNUNET_CONTAINER_DLL_remove (h->transmit_head, h->transmit_tail, op);
    GNUNET_free (op);
    transmit_next (h);
    return;
  }
  /* request active with service, simply ensure continuations are not called */
  op->res_cb = NULL;
  op->data_cb = NULL;
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
 * @param rcb
 *        Callback to call with the result of the storage operation.
 * @param rcb_cls
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
                                   GNUNET_PSYCSTORE_ResultCallback rcb,
                                   void *rcb_cls)
{
  GNUNET_assert (NULL != h);
  GNUNET_assert (NULL != channel_key);
  GNUNET_assert (NULL != slave_key);
  GNUNET_assert (GNUNET_YES == did_join || GNUNET_NO == did_join);
  GNUNET_assert (did_join
                 ? effective_since <= announced_at
                 : effective_since == 0);

  struct MembershipStoreRequest *req;
  struct GNUNET_PSYCSTORE_OperationHandle *
    op = GNUNET_malloc (sizeof (*op) + sizeof (*req));
  op->h = h;
  op->res_cb = rcb;
  op->cls = rcb_cls;

  req = (struct MembershipStoreRequest *) &op[1];
  op->msg = (struct GNUNET_MessageHeader *) req;
  req->header.type = htons (GNUNET_MESSAGE_TYPE_PSYCSTORE_MEMBERSHIP_STORE);
  req->header.size = htons (sizeof (*req));
  req->channel_key = *channel_key;
  req->slave_key = *slave_key;
  req->did_join = did_join;
  req->announced_at = GNUNET_htonll (announced_at);
  req->effective_since = GNUNET_htonll (effective_since);
  req->group_generation = GNUNET_htonll (group_generation);

  op->op_id = get_next_op_id (h);
  req->op_id = GNUNET_htonll (op->op_id);

  GNUNET_CONTAINER_DLL_insert_tail (h->transmit_head, h->transmit_tail, op);
  transmit_next (h);

  return op;
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
 * @param rcb
 *        Callback to call with the test result.
 * @param rcb_cls
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
                                  GNUNET_PSYCSTORE_ResultCallback rcb,
                                  void *rcb_cls)
{
  struct MembershipTestRequest *req;
  struct GNUNET_PSYCSTORE_OperationHandle *
    op = GNUNET_malloc (sizeof (*op) + sizeof (*req));
  op->h = h;
  op->res_cb = rcb;
  op->cls = rcb_cls;

  req = (struct MembershipTestRequest *) &op[1];
  op->msg = (struct GNUNET_MessageHeader *) req;
  req->header.type = htons (GNUNET_MESSAGE_TYPE_PSYCSTORE_MEMBERSHIP_TEST);
  req->header.size = htons (sizeof (*req));
  req->channel_key = *channel_key;
  req->slave_key = *slave_key;
  req->message_id = GNUNET_htonll (message_id);
  req->group_generation = GNUNET_htonll (group_generation);

  op->op_id = get_next_op_id (h);
  req->op_id = GNUNET_htonll (op->op_id);

  GNUNET_CONTAINER_DLL_insert_tail (h->transmit_head, h->transmit_tail, op);
  transmit_next (h);

  return op;
}


/**
 * Store a message fragment sent to a channel.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_key The channel the message belongs to.
 * @param message Message to store.
 * @param psycstore_flags Flags indicating whether the PSYC message contains
 *        state modifiers.
 * @param rcb Callback to call with the result of the operation.
 * @param rcb_cls Closure for the callback.
 *
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_fragment_store (struct GNUNET_PSYCSTORE_Handle *h,
                                 const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                                 const struct GNUNET_MULTICAST_MessageHeader *msg,
                                 enum GNUNET_PSYCSTORE_MessageFlags psycstore_flags,
                                 GNUNET_PSYCSTORE_ResultCallback rcb,
                                 void *rcb_cls)
{
  uint16_t size = ntohs (msg->header.size);
  struct FragmentStoreRequest *req;
  struct GNUNET_PSYCSTORE_OperationHandle *
    op = GNUNET_malloc (sizeof (*op) + sizeof (*req) + size);
  op->h = h;
  op->res_cb = rcb;
  op->cls = rcb_cls;

  req = (struct FragmentStoreRequest *) &op[1];
  op->msg = (struct GNUNET_MessageHeader *) req;
  req->header.type = htons (GNUNET_MESSAGE_TYPE_PSYCSTORE_FRAGMENT_STORE);
  req->header.size = htons (sizeof (*req) + size);
  req->channel_key = *channel_key;
  req->psycstore_flags = htonl (psycstore_flags);
  memcpy (&req[1], msg, size);

  op->op_id = get_next_op_id (h);
  req->op_id = GNUNET_htonll (op->op_id);

  GNUNET_CONTAINER_DLL_insert_tail (h->transmit_head, h->transmit_tail, op);
  transmit_next (h);

  return op;
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
 * @param rcb
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
                               GNUNET_PSYCSTORE_ResultCallback rcb,
                               void *cls)
{
  struct FragmentGetRequest *req;
  struct GNUNET_PSYCSTORE_OperationHandle *
    op = GNUNET_malloc (sizeof (*op) + sizeof (*req));
  op->h = h;
  op->data_cb = (DataCallback) fragment_cb;
  op->res_cb = rcb;
  op->cls = cls;

  req = (struct FragmentGetRequest *) &op[1];
  op->msg = (struct GNUNET_MessageHeader *) req;
  req->header.type = htons (GNUNET_MESSAGE_TYPE_PSYCSTORE_FRAGMENT_GET);
  req->header.size = htons (sizeof (*req));
  req->channel_key = *channel_key;
  req->first_fragment_id = GNUNET_htonll (first_fragment_id);
  req->last_fragment_id = GNUNET_htonll (last_fragment_id);
  if (NULL != slave_key)
  {
    req->slave_key = *slave_key;
    req->do_membership_test = GNUNET_YES;
  }

  op->op_id = get_next_op_id (h);
  req->op_id = GNUNET_htonll (op->op_id);

  GNUNET_CONTAINER_DLL_insert_tail (h->transmit_head, h->transmit_tail, op);
  transmit_next (h);

  return op;
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
 * @param rcb
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
                                      GNUNET_PSYCSTORE_ResultCallback rcb,
                                      void *cls)
{
  struct FragmentGetRequest *req;
  struct GNUNET_PSYCSTORE_OperationHandle *
    op = GNUNET_malloc (sizeof (*op) + sizeof (*req));
  op->h = h;
  op->data_cb = (DataCallback) fragment_cb;
  op->res_cb = rcb;
  op->cls = cls;

  req = (struct FragmentGetRequest *) &op[1];
  op->msg = (struct GNUNET_MessageHeader *) req;
  req->header.type = htons (GNUNET_MESSAGE_TYPE_PSYCSTORE_FRAGMENT_GET);
  req->header.size = htons (sizeof (*req));
  req->channel_key = *channel_key;
  req->fragment_limit = GNUNET_ntohll (fragment_limit);
  if (NULL != slave_key)
  {
    req->slave_key = *slave_key;
    req->do_membership_test = GNUNET_YES;
  }

  op->op_id = get_next_op_id (h);
  req->op_id = GNUNET_htonll (op->op_id);

  GNUNET_CONTAINER_DLL_insert_tail (h->transmit_head, h->transmit_tail, op);
  transmit_next (h);

  return op;
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
                              const char *method_prefix,
                              GNUNET_PSYCSTORE_FragmentCallback fragment_cb,
                              GNUNET_PSYCSTORE_ResultCallback rcb,
                              void *cls)
{
  struct MessageGetRequest *req;
  if (NULL == method_prefix)
    method_prefix = "";
  uint16_t method_size = strnlen (method_prefix,
                                  GNUNET_SERVER_MAX_MESSAGE_SIZE
                                  - sizeof (*req)) + 1;

  struct GNUNET_PSYCSTORE_OperationHandle *
    op = GNUNET_malloc (sizeof (*op) + sizeof (*req));
  op->h = h;
  op->data_cb = (DataCallback) fragment_cb;
  op->res_cb = rcb;
  op->cls = cls;

  req = (struct MessageGetRequest *) &op[1];
  op->msg = (struct GNUNET_MessageHeader *) req;
  req->header.type = htons (GNUNET_MESSAGE_TYPE_PSYCSTORE_MESSAGE_GET);
  req->header.size = htons (sizeof (*req) + method_size);
  req->channel_key = *channel_key;
  req->first_message_id = GNUNET_htonll (first_message_id);
  req->last_message_id = GNUNET_htonll (last_message_id);
  if (NULL != slave_key)
  {
    req->slave_key = *slave_key;
    req->do_membership_test = GNUNET_YES;
  }
  memcpy (&req[1], method_prefix, method_size);
  ((char *) &req[1])[method_size - 1] = '\0';

  op->op_id = get_next_op_id (h);
  req->op_id = GNUNET_htonll (op->op_id);

  GNUNET_CONTAINER_DLL_insert_tail (h->transmit_head, h->transmit_tail, op);
  transmit_next (h);

  return op;
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
                                     GNUNET_PSYCSTORE_ResultCallback rcb,
                                     void *cls)
{
  struct MessageGetRequest *req;

  if (NULL == method_prefix)
    method_prefix = "";
  uint16_t method_size = strnlen (method_prefix,
                                  GNUNET_SERVER_MAX_MESSAGE_SIZE
                                  - sizeof (*req)) + 1;
  GNUNET_assert ('\0' == method_prefix[method_size - 1]);

  struct GNUNET_PSYCSTORE_OperationHandle *
    op = GNUNET_malloc (sizeof (*op) + sizeof (*req) + method_size);
  op->h = h;
  op->data_cb = (DataCallback) fragment_cb;
  op->res_cb = rcb;
  op->cls = cls;

  req = (struct MessageGetRequest *) &op[1];
  op->msg = (struct GNUNET_MessageHeader *) req;
  req->header.type = htons (GNUNET_MESSAGE_TYPE_PSYCSTORE_MESSAGE_GET);
  req->header.size = htons (sizeof (*req) + method_size);
  req->channel_key = *channel_key;
  req->message_limit = GNUNET_ntohll (message_limit);
  if (NULL != slave_key)
  {
    req->slave_key = *slave_key;
    req->do_membership_test = GNUNET_YES;
  }

  op->op_id = get_next_op_id (h);
  req->op_id = GNUNET_htonll (op->op_id);
  memcpy (&req[1], method_prefix, method_size);

  GNUNET_CONTAINER_DLL_insert_tail (h->transmit_head, h->transmit_tail, op);
  transmit_next (h);

  return op;
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
                                       GNUNET_PSYCSTORE_ResultCallback rcb,
                                       void *cls)
{
  struct MessageGetFragmentRequest *req;
  struct GNUNET_PSYCSTORE_OperationHandle *
    op = GNUNET_malloc (sizeof (*op) + sizeof (*req));
  op->h = h;
  op->data_cb = (DataCallback) fragment_cb;
  op->res_cb = rcb;
  op->cls = cls;

  req = (struct MessageGetFragmentRequest *) &op[1];
  op->msg = (struct GNUNET_MessageHeader *) req;
  req->header.type = htons (GNUNET_MESSAGE_TYPE_PSYCSTORE_MESSAGE_GET_FRAGMENT);
  req->header.size = htons (sizeof (*req));
  req->channel_key = *channel_key;
  req->message_id = GNUNET_htonll (message_id);
  req->fragment_offset = GNUNET_htonll (fragment_offset);
  if (NULL != slave_key)
  {
    req->slave_key = *slave_key;
    req->do_membership_test = GNUNET_YES;
  }

  op->op_id = get_next_op_id (h);
  req->op_id = GNUNET_htonll (op->op_id);

  GNUNET_CONTAINER_DLL_insert_tail (h->transmit_head, h->transmit_tail, op);
  transmit_next (h);

  return op;
}


/**
 * Retrieve latest values of counters for a channel master.
 *
 * The current value of counters are needed when a channel master is restarted,
 * so that it can continue incrementing the counters from their last value.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_key Public key that identifies the channel.
 * @param ccb Callback to call with the result.
 * @param ccb_cls Closure for the @a ccb callback.
 *
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_counters_get (struct GNUNET_PSYCSTORE_Handle *h,
                               struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                               GNUNET_PSYCSTORE_CountersCallback ccb,
                               void *ccb_cls)
{
  struct OperationRequest *req;
  struct GNUNET_PSYCSTORE_OperationHandle *
    op = GNUNET_malloc (sizeof (*op) + sizeof (*req));
  op->h = h;
  op->data_cb = ccb;
  op->cls = ccb_cls;

  req = (struct OperationRequest *) &op[1];
  op->msg = (struct GNUNET_MessageHeader *) req;
  req->header.type = htons (GNUNET_MESSAGE_TYPE_PSYCSTORE_COUNTERS_GET);
  req->header.size = htons (sizeof (*req));
  req->channel_key = *channel_key;

  op->op_id = get_next_op_id (h);
  req->op_id = GNUNET_htonll (op->op_id);

  GNUNET_CONTAINER_DLL_insert_tail (h->transmit_head, h->transmit_tail, op);
  transmit_next (h);

  return op;
}


/**
 * Apply modifiers of a message to the current channel state.
 *
 * An error is returned if there are missing messages containing state
 * operations before the current one.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_key The channel we are interested in.
 * @param message_id ID of the message that contains the @a modifiers.
 * @param state_delta Value of the _state_delta PSYC header variable of the message.
 * @param modifier_count Number of elements in the @a modifiers array.
 * @param modifiers List of modifiers to apply.
 * @param rcb Callback to call with the result of the operation.
 * @param rcb_cls Closure for the @a rcb callback.
 *
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_state_modify (struct GNUNET_PSYCSTORE_Handle *h,
                               const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                               uint64_t message_id,
                               uint64_t state_delta,
                               size_t modifier_count,
                               const struct GNUNET_ENV_Modifier *modifiers,
                               GNUNET_PSYCSTORE_ResultCallback rcb,
                               void *rcb_cls)
{
  struct GNUNET_PSYCSTORE_OperationHandle *op = NULL;
  size_t i;

  for (i = 0; i < modifier_count; i++) {
    struct StateModifyRequest *req;
    uint16_t name_size = strlen (modifiers[i].name) + 1;

    op = GNUNET_malloc (sizeof (*op) + sizeof (*req) + name_size +
                        modifiers[i].value_size);
    op->h = h;
    op->res_cb = rcb;
    op->cls = rcb_cls;

    req = (struct StateModifyRequest *) &op[1];
    op->msg = (struct GNUNET_MessageHeader *) req;
    req->header.type = htons (GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_MODIFY);
    req->header.size = htons (sizeof (*req) + name_size
                              + modifiers[i].value_size);
    req->channel_key = *channel_key;
    req->message_id = GNUNET_htonll (message_id);
    req->state_delta = GNUNET_htonll (state_delta);
    req->oper = modifiers[i].oper;
    req->name_size = htons (name_size);
    req->flags
      = 0 == i
      ? STATE_OP_FIRST
      : modifier_count - 1 == i
      ? STATE_OP_LAST
      : 0;

    memcpy (&req[1], modifiers[i].name, name_size);
    memcpy ((char *) &req[1] + name_size, modifiers[i].value, modifiers[i].value_size);

    op->op_id = get_next_op_id (h);
    req->op_id = GNUNET_htonll (op->op_id);

    GNUNET_CONTAINER_DLL_insert_tail (h->transmit_head, h->transmit_tail, op);
    transmit_next (h);
  }
  return op;
  /* FIXME: only the last operation is returned,
   *        operation_cancel() should be able to cancel all of them.
   */
}


/**
 * Store synchronized state.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_key The channel we are interested in.
 * @param message_id ID of the message that contains the state_hash PSYC header variable.
 * @param modifier_count Number of elements in the @a modifiers array.
 * @param modifiers Full state to store.
 * @param rcb Callback to call with the result of the operation.
 * @param rcb_cls Closure for the callback.
 *
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_state_sync (struct GNUNET_PSYCSTORE_Handle *h,
                             const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                             uint64_t message_id,
                             size_t modifier_count,
                             const struct GNUNET_ENV_Modifier *modifiers,
                             GNUNET_PSYCSTORE_ResultCallback rcb,
                             void *rcb_cls)
{
  struct GNUNET_PSYCSTORE_OperationHandle *op = NULL;
  size_t i;

  for (i = 0; i < modifier_count; i++) {
    struct StateSyncRequest *req;
    uint16_t name_size = strlen (modifiers[i].name) + 1;

    op = GNUNET_malloc (sizeof (*op) + sizeof (*req) + name_size +
                        modifiers[i].value_size);
    op->h = h;
    op->res_cb = rcb;
    op->cls = rcb_cls;

    req = (struct StateSyncRequest *) &op[1];
    op->msg = (struct GNUNET_MessageHeader *) req;
    req->header.type = htons (GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_SYNC);
    req->header.size = htons (sizeof (*req) + name_size
                              + modifiers[i].value_size);
    req->channel_key = *channel_key;
    req->message_id = GNUNET_htonll (message_id);
    req->name_size = htons (name_size);
    req->flags
      = (0 == i)
      ? STATE_OP_FIRST
      : (modifier_count - 1 == i)
      ? STATE_OP_LAST
      : 0;

    memcpy (&req[1], modifiers[i].name, name_size);
    memcpy ((char *) &req[1] + name_size, modifiers[i].value, modifiers[i].value_size);

    op->op_id = get_next_op_id (h);
    req->op_id = GNUNET_htonll (op->op_id);

    GNUNET_CONTAINER_DLL_insert_tail (h->transmit_head, h->transmit_tail, op);
    transmit_next (h);
  }
  return op;
}


/**
 * Reset the state of a channel.
 *
 * Delete all state variables stored for the given channel.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_key The channel we are interested in.
 * @param rcb Callback to call with the result of the operation.
 * @param rcb_cls Closure for the callback.
 *
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_state_reset (struct GNUNET_PSYCSTORE_Handle *h,
                              const struct GNUNET_CRYPTO_EddsaPublicKey
                              *channel_key,
                              GNUNET_PSYCSTORE_ResultCallback rcb,
                              void *rcb_cls)
{
  struct OperationRequest *req;
  struct GNUNET_PSYCSTORE_OperationHandle *
    op = GNUNET_malloc (sizeof (*op) + sizeof (*req));
  op->h = h;
  op->res_cb = rcb;
  op->cls = rcb_cls;

  req = (struct OperationRequest *) &op[1];
  op->msg = (struct GNUNET_MessageHeader *) req;
  req->header.type = htons (GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_RESET);
  req->header.size = htons (sizeof (*req));
  req->channel_key = *channel_key;

  op->op_id = get_next_op_id (h);
  req->op_id = GNUNET_htonll (op->op_id);

  GNUNET_CONTAINER_DLL_insert_tail (h->transmit_head, h->transmit_tail, op);
  transmit_next (h);

  return op;
}



/**
 * Update signed values of state variables in the state store.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_key The channel we are interested in.
 * @param message_id Message ID that contained the state @a hash.
 * @param hash Hash of the serialized full state.
 * @param rcb Callback to call with the result of the operation.
 * @param rcb_cls Closure for the callback.
 *
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_state_hash_update (struct GNUNET_PSYCSTORE_Handle *h,
                                    const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                                    uint64_t message_id,
                                    const struct GNUNET_HashCode *hash,
                                    GNUNET_PSYCSTORE_ResultCallback rcb,
                                    void *rcb_cls)
{
  struct StateHashUpdateRequest *req;
  struct GNUNET_PSYCSTORE_OperationHandle *
    op = GNUNET_malloc (sizeof (*op) + sizeof (*req));
  op->h = h;
  op->res_cb = rcb;
  op->cls = rcb_cls;

  req = (struct StateHashUpdateRequest *) &op[1];
  op->msg = (struct GNUNET_MessageHeader *) req;
  req->header.type = htons (GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_RESET);
  req->header.size = htons (sizeof (*req));
  req->channel_key = *channel_key;
  req->hash = *hash;

  op->op_id = get_next_op_id (h);
  req->op_id = GNUNET_htonll (op->op_id);

  GNUNET_CONTAINER_DLL_insert_tail (h->transmit_head, h->transmit_tail, op);
  transmit_next (h);

  return op;
}


/**
 * Retrieve the best matching state variable.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_key The channel we are interested in.
 * @param name Name of variable to match, the returned variable might be less specific.
 * @param scb Callback to return the matching state variable.
 * @param rcb Callback to call with the result of the operation.
 * @param cls Closure for the callbacks.
 *
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_state_get (struct GNUNET_PSYCSTORE_Handle *h,
                            const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                            const char *name,
                            GNUNET_PSYCSTORE_StateCallback scb,
                            GNUNET_PSYCSTORE_ResultCallback rcb,
                            void *cls)
{
  size_t name_size = strlen (name) + 1;
  struct OperationRequest *req;
  struct GNUNET_PSYCSTORE_OperationHandle *
    op = GNUNET_malloc (sizeof (*op) + sizeof (*req) + name_size);
  op->h = h;
  op->data_cb = (DataCallback) scb;
  op->res_cb = rcb;
  op->cls = cls;

  req = (struct OperationRequest *) &op[1];
  op->msg = (struct GNUNET_MessageHeader *) req;
  req->header.type = htons (GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_GET);
  req->header.size = htons (sizeof (*req) + name_size);
  req->channel_key = *channel_key;
  memcpy (&req[1], name, name_size);

  op->op_id = get_next_op_id (h);
  req->op_id = GNUNET_htonll (op->op_id);

  GNUNET_CONTAINER_DLL_insert_tail (h->transmit_head, h->transmit_tail, op);
  transmit_next (h);

  return op;
}



/**
 * Retrieve all state variables for a channel with the given prefix.
 *
 * @param h Handle for the PSYCstore.
 * @param channel_key The channel we are interested in.
 * @param name_prefix Prefix of state variable names to match.
 * @param scb Callback to return matching state variables.
 * @param rcb Callback to call with the result of the operation.
 * @param cls Closure for the callbacks.
 *
 * @return Handle that can be used to cancel the operation.
 */
struct GNUNET_PSYCSTORE_OperationHandle *
GNUNET_PSYCSTORE_state_get_prefix (struct GNUNET_PSYCSTORE_Handle *h,
                                   const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                                   const char *name_prefix,
                                   GNUNET_PSYCSTORE_StateCallback scb,
                                   GNUNET_PSYCSTORE_ResultCallback rcb,
                                   void *cls)
{
  size_t name_size = strlen (name_prefix) + 1;
  struct OperationRequest *req;
  struct GNUNET_PSYCSTORE_OperationHandle *
    op = GNUNET_malloc (sizeof (*op) + sizeof (*req) + name_size);
  op->h = h;
  op->data_cb = (DataCallback) scb;
  op->res_cb = rcb;
  op->cls = cls;

  req = (struct OperationRequest *) &op[1];
  op->msg = (struct GNUNET_MessageHeader *) req;
  req->header.type = htons (GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_GET_PREFIX);
  req->header.size = htons (sizeof (*req) + name_size);
  req->channel_key = *channel_key;
  memcpy (&req[1], name_prefix, name_size);

  op->op_id = get_next_op_id (h);
  req->op_id = GNUNET_htonll (op->op_id);

  GNUNET_CONTAINER_DLL_insert_tail (h->transmit_head, h->transmit_tail, op);
  transmit_next (h);

  return op;
}

/* end of psycstore_api.c */
