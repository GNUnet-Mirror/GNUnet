/*
     This file is part of GNUnet.
     (C) 2013 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public Liceidentity as published
     by the Free Software Foundation; either version 3, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public Liceidentity for more details.

     You should have received a copy of the GNU General Public Liceidentity
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file psycstore/psycstore_api.c
 * @brief API to interact with the PSYCstore service
 * @author Gabor X Toth
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_psycstore_service.h"
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
   * We keep operations in a DLL.
   */
  struct GNUNET_PSYCSTORE_OperationHandle *next;

  /**
   * We keep operations in a DLL.
   */
  struct GNUNET_PSYCSTORE_OperationHandle *prev;

  /**
   * Message to send to the PSYCstore service.
   * Allocated at the end of this struct.
   */
  const struct GNUNET_MessageHeader *msg;

  /**
   * Continuation to invoke with the result of an operation.
   */
  GNUNET_PSYCSTORE_ResultCallback res_cb;

  /**
   * Continuation to invoke with the result of an operation returning a fragment.
   */
  GNUNET_PSYCSTORE_FragmentCallback frag_cb;

  /**
   * Continuation to invoke with the result of an operation returning a state variable.
   */
  GNUNET_PSYCSTORE_StateCallback state_cb;

  /**
   * Closure for the callbacks.
   */
  void *cls;

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
   * Head of active operations.
   */ 
  struct GNUNET_PSYCSTORE_OperationHandle *op_head;

  /**
   * Tail of active operations.
   */ 
  struct GNUNET_PSYCSTORE_OperationHandle *op_tail;

  /**
   * Currently pending transmission request, or NULL for none.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * Task doing exponential back-off trying to reconnect.
   */
  GNUNET_SCHEDULER_TaskIdentifier reconnect_task;

  /**
   * Time for next connect retry.
   */
  struct GNUNET_TIME_Relative reconnect_delay;

  /**
   * Are we polling for incoming messages right now?
   */
  int in_receive;

};


/**
 * Try again to connect to the PSYCstore service.
 *
 * @param cls handle to the PSYCstore service.
 * @param tc scheduler context
 */
static void
reconnect (void *cls,
	   const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Reschedule a connect attempt to the service.
 *
 * @param h transport service to reconnect
 */
static void
reschedule_connect (struct GNUNET_PSYCSTORE_Handle *h)
{
  GNUNET_assert (h->reconnect_task == GNUNET_SCHEDULER_NO_TASK);

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
 * Type of a function to call when we receive a message
 * from the service.
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
static void
message_handler (void *cls, 
		 const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_PSYCSTORE_Handle *h = cls;
  struct GNUNET_PSYCSTORE_OperationHandle *op;
  const struct GNUNET_PSYCSTORE_ResultCodeMessage *rcm;
  const char *str;
  uint16_t size;

  if (NULL == msg)
  {
    reschedule_connect (h);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received message of type %d from PSYCstore service\n",
       ntohs (msg->type));
  size = ntohs (msg->size);
  switch (ntohs (msg->type))
  {
  case GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_CODE:
    if (size < sizeof (struct GNUNET_PSYCSTORE_ResultCodeMessage))
    {
      GNUNET_break (0);
      reschedule_connect (h);
      return;
    }
    rcm = (const struct GNUNET_PSYCSTORE_ResultCodeMessage *) msg;
    str = (const char *) &rcm[1];
    if ( (size > sizeof (struct GNUNET_PSYCSTORE_ResultCodeMessage)) &&
	 ('\0' != str[size - sizeof (struct GNUNET_PSYCSTORE_ResultCodeMessage) - 1]) )
    {
      GNUNET_break (0);
      reschedule_connect (h);
      return;
    }
    if (size == sizeof (struct GNUNET_PSYCSTORE_ResultCodeMessage))
      str = NULL;

    op = h->op_head;
    GNUNET_CONTAINER_DLL_remove (h->op_head,
				 h->op_tail,
				 op);
    GNUNET_CLIENT_receive (h->client, &message_handler, h,
			   GNUNET_TIME_UNIT_FOREVER_REL);
    if (NULL != op->res_cb)
      op->res_cb (op->cls, rcm->result_code , str);
    GNUNET_free (op);
    break;
  default:
    GNUNET_break (0);
    reschedule_connect (h);
    return;
  }
}


/**
 * Schedule transmission of the next message from our queue.
 *
 * @param h PSYCstore handle
 */
static void
transmit_next (struct GNUNET_PSYCSTORE_Handle *h);


/**
 * Transmit next message to service.
 *
 * @param cls the 'struct GNUNET_PSYCSTORE_Handle'.
 * @param size number of bytes available in buf
 * @param buf where to copy the message
 * @return number of bytes copied to buf
 */
static size_t
send_next_message (void *cls, 
		   size_t size, 
		   void *buf)
{
  struct GNUNET_PSYCSTORE_Handle *h = cls;
  struct GNUNET_PSYCSTORE_OperationHandle *op = h->op_head;
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
       "Sending message of type %d to PSYCstore service\n",
       ntohs (op->msg->type));
  memcpy (buf, op->msg, ret);
  if ( (NULL == op->res_cb) &&
       (NULL == op->frag_cb) &&
       (NULL == op->state_cb))
  {
    GNUNET_CONTAINER_DLL_remove (h->op_head,
				 h->op_tail,
				 op);
    GNUNET_free (op);
    transmit_next (h);
  }
  if (GNUNET_NO == h->in_receive)
  {
    h->in_receive = GNUNET_YES;
    GNUNET_CLIENT_receive (h->client,
			   &message_handler, h,
			   GNUNET_TIME_UNIT_FOREVER_REL);
  }
  return ret;
}


/**
 * Schedule transmission of the next message from our queue.
 *
 * @param h PSYCstore handle
 */
static void
transmit_next (struct GNUNET_PSYCSTORE_Handle *h)
{
  struct GNUNET_PSYCSTORE_OperationHandle *op = h->op_head;

  GNUNET_assert (NULL == h->th);
  if (NULL == op)
    return;
  if (NULL == h->client)
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
 * @param cls the handle to the PSYCstore service
 * @param tc scheduler context
 */
static void
reconnect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_PSYCSTORE_Handle *h = cls;

  h->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connecting to PSYCstore service.\n");
  GNUNET_assert (NULL == h->client);
  h->client = GNUNET_CLIENT_connect ("psycstore", h->cfg);
  GNUNET_assert (NULL != h->client);
/*
  struct GNUNET_PSYCSTORE_OperationHandle *op;
  struct GNUNET_MessageHeader msg;
  op = GNUNET_malloc (sizeof (struct GNUNET_PSYCSTORE_OperationHandle) + 
		      sizeof (struct GNUNET_MessageHeader));
  op->h = h;
  op->msg = (const struct GNUNET_MessageHeader *) &op[1];
  msg.size = htons (sizeof (msg));
  msg.type = htons (GNUNET_MESSAGE_TYPE_PSYCSTORE_START);
  memcpy (&op[1], &msg, sizeof (msg));
  GNUNET_CONTAINER_DLL_insert (h->op_head,
			       h->op_tail,
			       op);
  transmit_next (h);
  GNUNET_assert (NULL != h->th);
*/
}


/**
 * Connect to the PSYCstore service.
 *
 * @param cfg the configuration to use
 * @return handle to use
 */
struct GNUNET_PSYCSTORE_Handle *
GNUNET_PSYCSTORE_connect (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_PSYCSTORE_Handle *h;

  h = GNUNET_new (struct GNUNET_PSYCSTORE_Handle);
  h->cfg = cfg;
  h->reconnect_delay = GNUNET_TIME_UNIT_ZERO;
  h->reconnect_task = GNUNET_SCHEDULER_add_now (&reconnect, h);
  return h;
}


/**
 * Cancel a PSYCstore operation. Note that the operation MAY still
 * be executed; this merely cancels the continuation; if the request
 * was already transmitted, the service may still choose to complete
 * the operation.
 *
 * @param op operation to cancel
 */
void
GNUNET_PSYCSTORE_operation_cancel (struct GNUNET_PSYCSTORE_OperationHandle *op)
{
  struct GNUNET_PSYCSTORE_Handle *h = op->h;

  if ( (h->op_head != op) ||
       (NULL == h->client) )
  {
    /* request not active, can simply remove */
    GNUNET_CONTAINER_DLL_remove (h->op_head,
				 h->op_tail,
				 op);
    GNUNET_free (op);
    return;
  }
  if (NULL != h->th)
  {
    /* request active but not yet with service, can still abort */
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->th);
    h->th = NULL;
    GNUNET_CONTAINER_DLL_remove (h->op_head,
				 h->op_tail,
				 op);
    GNUNET_free (op);
    transmit_next (h);
    return;
  }
  /* request active with service, simply ensure continuations are not called */
  op->res_cb = NULL;
  op->frag_cb = NULL;
  op->state_cb = NULL;
}


/**
 * Disconnect from PSYCstore service
 *
 * @param h handle to destroy
 */
void
GNUNET_PSYCSTORE_disconnect (struct GNUNET_PSYCSTORE_Handle *h)
{
  GNUNET_assert (NULL != h);
  GNUNET_assert (h->op_head == h->op_tail);
  if (h->reconnect_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (h->reconnect_task);
    h->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
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

/* end of psycstore_api.c */
