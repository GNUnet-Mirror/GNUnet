/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2012, 2013 Christian Grothoff (and other contributing authors)

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

/**
 * @file arm/arm_api.c
 * @brief API for accessing the ARM service
 * @author Christian Grothoff
 * @author LRN
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_arm_service.h"
#include "gnunet_protocols.h"
#include "arm.h"

#define LOG(kind,...) GNUNET_log_from (kind, "arm-api",__VA_ARGS__)

/**
 * Handle for interacting with ARM.
 */
struct GNUNET_ARM_Handle
{
  /**
   * Our control connection to the ARM service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * The configuration that we are using.
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Handle for our current transmission request.
   */
  struct GNUNET_CLIENT_TransmitHandle *cth;

  /**
   * Head of doubly-linked list of pending requests.
   */
  struct ARMControlMessage *control_pending_head;

  /**
   * Tail of doubly-linked list of pending requests.
   */
  struct ARMControlMessage *control_pending_tail;

  /**
   * Head of doubly-linked list of sent requests.
   */
  struct ARMControlMessage *control_sent_head;

  /**
   * Tail of doubly-linked list of sent requests.
   */
  struct ARMControlMessage *control_sent_tail;

  /**
   * Callback to invoke on connection/disconnection.
   */
  GNUNET_ARM_ConnectionStatusCallback conn_status;

  /**
   * Closure for conn_status.
   */
  void *conn_status_cls;

  /**
   * ARM control message for the 'arm_termination_handler'
   * with the continuation to call once the ARM shutdown is done.
   */
  struct ARMControlMessage *thm;

  /**
   * ID of the reconnect task (if any).
   */
  struct GNUNET_SCHEDULER_Task * reconnect_task;

  /**
   * Current delay we use for re-trying to connect to core.
   */
  struct GNUNET_TIME_Relative retry_backoff;

  /**
   * Counter for request identifiers
   */
  uint64_t request_id_counter;

  /**
   * Are we currently disconnected and hence unable to send?
   */
  unsigned char currently_down;

  /**
   * GNUNET_YES if we're running a service test.
   */
  unsigned char service_test_is_active;
};


/**
 * Entry in a doubly-linked list of control messages to be transmitted
 * to the arm service.
 *
 * The actual message is allocated at the end of this struct.
 */
struct ARMControlMessage
{
  /**
   * This is a doubly-linked list.
   */
  struct ARMControlMessage *next;

  /**
   * This is a doubly-linked list.
   */
  struct ARMControlMessage *prev;

  /**
   * ARM handle.
   */
  struct GNUNET_ARM_Handle *h;

  /**
   * Message to send.
   */
  struct GNUNET_ARM_Message *msg;

  /**
   * Callback for service state change requests.
   */
  GNUNET_ARM_ResultCallback result_cont;

  /**
   * Callback for service list requests.
   */
  GNUNET_ARM_ServiceListCallback list_cont;

  /**
   * Closure for 'result_cont' or 'list_cont'.
   */
  void *cont_cls;

  /**
   * Timeout for the operation.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Task to run when request times out.
   */
  struct GNUNET_SCHEDULER_Task * timeout_task_id;

  /**
   * Flags for passing std descriptors to ARM (when starting ARM).
   */
  enum GNUNET_OS_InheritStdioFlags std_inheritance;

  /**
   * Type of the request expressed as a message type (start, stop or list).
   */
  uint16_t type;
};


/**
 * Connect to arm.
 *
 * @param h arm handle
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
static int
reconnect_arm (struct GNUNET_ARM_Handle *h);


/**
 * Check the list of pending requests, send the next
 * one to the arm.
 *
 * @param h arm handle
 * @param ignore_currently_down transmit message even if not initialized?
 */
static void
trigger_next_request (struct GNUNET_ARM_Handle *h, int ignore_currently_down);


/**
 * Task scheduled to try to re-connect to arm.
 *
 * @param cls the 'struct GNUNET_ARM_Handle'
 * @param tc task context
 */
static void
reconnect_arm_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_ARM_Handle *h = cls;

  h->reconnect_task = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Connecting to ARM service after delay\n");
  reconnect_arm (h);
}


/**
 * Close down any existing connection to the ARM service and
 * try re-establishing it later.
 *
 * @param h our handle
 */
static void
reconnect_arm_later (struct GNUNET_ARM_Handle *h)
{
  if (GNUNET_NO != h->currently_down)
    return;
  if (NULL != h->cth)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->cth);
    h->cth = NULL;
  }
  if (NULL != h->client)
  {
    GNUNET_CLIENT_disconnect (h->client);
    h->client = NULL;
  }
  h->currently_down = GNUNET_YES;
  GNUNET_assert (NULL == h->reconnect_task);
  h->reconnect_task =
      GNUNET_SCHEDULER_add_delayed (h->retry_backoff, &reconnect_arm_task, h);
  /* Don't clear pending messages on disconnection, deliver them later
  clear_pending_messages (h, GNUNET_ARM_REQUEST_DISCONNECTED);
  GNUNET_assert (NULL == h->control_pending_head);
  */
  h->retry_backoff = GNUNET_TIME_STD_BACKOFF (h->retry_backoff);
  if (NULL != h->conn_status)
    h->conn_status (h->conn_status_cls, GNUNET_NO);
}


/**
 * Find a control message by its unique ID.
 *
 * @param h ARM handle
 * @param id unique message ID to use for the lookup
 * @return NULL if not found
 */
static struct ARMControlMessage *
find_cm_by_id (struct GNUNET_ARM_Handle *h, uint64_t id)
{
  struct ARMControlMessage *result;
  for (result = h->control_sent_head; result; result = result->next)
    if (id == result->msg->request_id)
      return result;
  return NULL;
}


/**
 * Handler for ARM 'termination' reply (failure to receive).
 *
 * @param cls our "struct GNUNET_ARM_Handle"
 * @param msg expected to be NULL
 */
static void
arm_termination_handler (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_ARM_Handle *h = cls;
  struct ARMControlMessage *cm;

  if (NULL != msg)
  {
    GNUNET_break (0);
    GNUNET_CLIENT_receive (h->client, &arm_termination_handler, h,
			   GNUNET_TIME_UNIT_FOREVER_REL);
    return;
  }
  cm = h->thm;
  h->thm = NULL;
  h->currently_down = GNUNET_YES;
  GNUNET_CLIENT_disconnect (h->client);
  h->client = NULL;
  if (NULL != cm->result_cont)
    cm->result_cont (cm->cont_cls,
		     GNUNET_ARM_REQUEST_SENT_OK,
		     (const char *) &cm->msg[1],
		     GNUNET_ARM_RESULT_STOPPED);
  GNUNET_free (cm->msg);
  GNUNET_free (cm);
}


/**
 * Handler for ARM replies.
 *
 * @param cls our `struct GNUNET_ARM_Handle`
 * @param msg the message received from the arm service
 */
static void
client_notify_handler (void *cls,
                       const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_ARM_Handle *h = cls;
  const struct GNUNET_ARM_Message *arm_msg;
  const struct GNUNET_ARM_ResultMessage *res;
  const struct GNUNET_ARM_ListResultMessage *lres;
  struct ARMControlMessage *cm;
  const char **list;
  const char *pos;
  uint64_t id;
  enum GNUNET_ARM_Result result;
  uint16_t size_check;
  uint16_t rcount;
  uint16_t msize;
  unsigned char fail;

  list = NULL;
  rcount = 0;
  if (NULL == msg)
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         _("Client was disconnected from arm service, trying to reconnect.\n"));
    reconnect_arm_later (h);
    return;
  }
  msize = ntohs (msg->size);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Processing message of type %u and size %u from arm service\n",
       ntohs (msg->type), msize);
  if (msize < sizeof (struct GNUNET_ARM_Message))
  {
    GNUNET_break (0);
    reconnect_arm_later (h);
    return;
  }
  arm_msg = (const struct GNUNET_ARM_Message *) msg;
  GNUNET_break (0 == ntohl (arm_msg->reserved));
  id = GNUNET_ntohll (arm_msg->request_id);
  cm = find_cm_by_id (h, id);
  if (NULL == cm)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Message with unknown id %llu\n",
         id);
    return;
  }
  fail = GNUNET_NO;
  switch (ntohs (msg->type))
  {
  case GNUNET_MESSAGE_TYPE_ARM_RESULT:
    if (msize < sizeof (struct GNUNET_ARM_ResultMessage))
    {
      GNUNET_assert (0);
      fail = GNUNET_YES;
    }
    break;
  case GNUNET_MESSAGE_TYPE_ARM_LIST_RESULT:
    if (msize < sizeof (struct GNUNET_ARM_ListResultMessage))
    {
      GNUNET_break (0);
      fail = GNUNET_YES;
      break;
    }
    size_check = 0;
    lres = (const struct GNUNET_ARM_ListResultMessage *) msg;
    rcount = ntohs (lres->count);
    {
      unsigned int i;

      list = GNUNET_malloc (sizeof (const char *) * rcount);
      pos = (const char *)&lres[1];
      for (i = 0; i < rcount; i++)
      {
        const char *end = memchr (pos, 0, msize - size_check);
        if (NULL == end)
        {
          GNUNET_break (0);
          fail = GNUNET_YES;
          break;
        }
        list[i] = pos;
        size_check += (end - pos) + 1;
        pos = end + 1;
      }
      if (GNUNET_YES == fail)
      {
        GNUNET_free (list);
        list = NULL;
      }
    }
    break;
  default:
    fail = GNUNET_YES;
    break;
  }
  GNUNET_assert (NULL != cm->timeout_task_id);
  GNUNET_SCHEDULER_cancel (cm->timeout_task_id);
  GNUNET_CONTAINER_DLL_remove (h->control_sent_head,
                               h->control_sent_tail, cm);
  if (GNUNET_YES == fail)
  {
    reconnect_arm_later (h);
    GNUNET_free (cm->msg);
    GNUNET_free (cm);
    return;
  }
  if ( (GNUNET_MESSAGE_TYPE_ARM_RESULT == ntohs (msg->type)) &&
       (0 == strcasecmp ((const char *) &cm->msg[1],
			 "arm")) &&
       (NULL != (res = (const struct GNUNET_ARM_ResultMessage *) msg)) &&
       (GNUNET_ARM_RESULT_STOPPING == ntohl (res->result)) )
  {
    /* special case: if we are stopping 'gnunet-service-arm', we do not just
       wait for the result message, but also wait for the service to close
       the connection (and then we have to close our client handle as well);
       this is done by installing a different receive handler, waiting for
       the connection to go down */
    if (NULL != h->thm)
    {
      GNUNET_break (0);
      cm->result_cont (h->thm->cont_cls,
		       GNUNET_ARM_REQUEST_SENT_OK,
                       (const char *) &h->thm->msg[1],
		       GNUNET_ARM_RESULT_IS_NOT_KNOWN);
      GNUNET_free (h->thm->msg);
      GNUNET_free (h->thm);
    }
    h->thm = cm;
    GNUNET_CLIENT_receive (h->client, &arm_termination_handler, h,
			   GNUNET_TIME_UNIT_FOREVER_REL);
    return;
  }
  GNUNET_CLIENT_receive (h->client, &client_notify_handler, h,
                         GNUNET_TIME_UNIT_FOREVER_REL);
  switch (ntohs (msg->type))
  {
  case GNUNET_MESSAGE_TYPE_ARM_RESULT:
    res = (const struct GNUNET_ARM_ResultMessage *) msg;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received response from ARM for service `%s': %u\n",
         (const char *) &cm->msg[1], ntohs (msg->type));
    result = (enum GNUNET_ARM_Result) ntohl (res->result);
    if (NULL != cm->result_cont)
      cm->result_cont (cm->cont_cls, GNUNET_ARM_REQUEST_SENT_OK,
                       (const char *) &cm->msg[1], result);
    break;
  case GNUNET_MESSAGE_TYPE_ARM_LIST_RESULT:
    if (NULL != cm->list_cont)
        cm->list_cont (cm->cont_cls, GNUNET_ARM_REQUEST_SENT_OK, rcount,
                       list);
    GNUNET_free_non_null (list);
    break;
  }
  GNUNET_free (cm->msg);
  GNUNET_free (cm);
}


/**
 * Transmit the next message to the arm service.
 *
 * @param cls closure with the `struct GNUNET_ARM_Handle`
 * @param size number of bytes available in @a buf
 * @param buf where the callee should write the message
 * @return number of bytes written to @a buf
 */
static size_t
transmit_arm_message (void *cls, size_t size, void *buf)
{
  struct GNUNET_ARM_Handle *h = cls;
  struct ARMControlMessage *cm;
  struct GNUNET_ARM_Message *arm_msg;
  uint64_t request_id;
  int notify_connection;
  uint16_t msize;

  notify_connection = GNUNET_NO;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "transmit_arm_message is running with %p buffer of size %lu. ARM is known to be %s\n",
       buf, size, h->currently_down ? "unconnected" : "connected");
  GNUNET_assert (NULL == h->reconnect_task);
  h->cth = NULL;
  if ((GNUNET_YES == h->currently_down) && (NULL != buf))
  {
    h->currently_down = GNUNET_NO;
    notify_connection = GNUNET_YES;
    h->retry_backoff = GNUNET_TIME_UNIT_MILLISECONDS;
    GNUNET_CLIENT_receive (h->client, &client_notify_handler, h,
                           GNUNET_TIME_UNIT_FOREVER_REL);
  }
  if (NULL == buf)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Transmission failed, initiating reconnect\n");
    reconnect_arm_later (h);
    return 0;
  }
  if (NULL == (cm = h->control_pending_head))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Queue is empty, not sending anything\n");
    msize = 0;
    goto end;
  }
  GNUNET_assert (NULL != cm->msg);
  msize = ntohs (cm->msg->header.size);
  if (size < msize)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Request is too big (%u < %u), not sending it\n", size, msize);
    trigger_next_request (h, GNUNET_NO);
    msize = 0;
    goto end;
  }
  arm_msg = cm->msg;
  if (0 == h->request_id_counter)
    h->request_id_counter++;
  request_id = h->request_id_counter++;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Transmitting control message with %u bytes of type %u to arm with id %llu\n",
       (unsigned int) msize, (unsigned int) ntohs (cm->msg->header.type), request_id);
  arm_msg->reserved = htonl (0);
  arm_msg->request_id = GNUNET_htonll (request_id);
  memcpy (buf, cm->msg, msize);
  /* Otherwise we won't be able to find it later! */
  arm_msg->request_id = request_id;
  GNUNET_CONTAINER_DLL_remove (h->control_pending_head,
                               h->control_pending_tail, cm);
  GNUNET_CONTAINER_DLL_insert_tail (h->control_sent_head,
                                    h->control_sent_tail, cm);
  /* Don't free msg, keep it around (kind of wasteful, but then we don't
   * really have many messages to handle, and it'll be freed when it times
   * out anyway.
   */
  trigger_next_request (h, GNUNET_NO);

 end:
  if ((GNUNET_YES == notify_connection) && (NULL != h->conn_status))
    h->conn_status (h->conn_status_cls, GNUNET_YES);
  return msize;
}


/**
 * Check the list of pending requests, send the next
 * one to the arm.
 *
 * @param h arm handle
 * @param ignore_currently_down transmit message even if not initialized?
 */
static void
trigger_next_request (struct GNUNET_ARM_Handle *h, int ignore_currently_down)
{
  uint16_t msize;

  msize = sizeof (struct GNUNET_MessageHeader);
  if ((GNUNET_YES == h->currently_down) && (ignore_currently_down == GNUNET_NO))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "ARM connection down, not processing queue\n");
    return;
  }
  if (NULL != h->cth)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Request pending, not processing queue\n");
    return;
  }
  if (NULL != h->control_pending_head)
    msize =
        ntohs (h->control_pending_head->msg->header.size);
  else if (GNUNET_NO == ignore_currently_down)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Request queue empty, not processing queue\n");
    return;                     /* no pending message */
  }
  h->cth =
      GNUNET_CLIENT_notify_transmit_ready (h->client, msize,
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           GNUNET_NO, &transmit_arm_message, h);
}


/**
 * Connect to arm.
 *
 * @param h arm handle
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
static int
reconnect_arm (struct GNUNET_ARM_Handle *h)
{
  GNUNET_assert (NULL == h->client);
  GNUNET_assert (GNUNET_YES == h->currently_down);
  h->client = GNUNET_CLIENT_connect ("arm", h->cfg);
  if (NULL == h->client)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	   "arm_api, GNUNET_CLIENT_connect returned NULL\n");
    if (NULL != h->conn_status)
      h->conn_status (h->conn_status_cls, GNUNET_SYSERR);
    return GNUNET_SYSERR;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "arm_api, GNUNET_CLIENT_connect returned non-NULL\n");
  trigger_next_request (h, GNUNET_YES);
  return GNUNET_OK;
}


/**
 * Set up a context for communicating with ARM, then
 * start connecting to the ARM service using that context.
 *
 * @param cfg configuration to use (needed to contact ARM;
 *        the ARM service may internally use a different
 *        configuration to determine how to start the service).
 * @param conn_status will be called when connecting/disconnecting
 * @param cls closure for conn_status
 * @return context to use for further ARM operations, NULL on error.
 */
struct GNUNET_ARM_Handle *
GNUNET_ARM_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                    GNUNET_ARM_ConnectionStatusCallback conn_status, void *cls)
{
  struct GNUNET_ARM_Handle *h;

  h = GNUNET_new (struct GNUNET_ARM_Handle);
  h->cfg = GNUNET_CONFIGURATION_dup (cfg);
  h->currently_down = GNUNET_YES;
  h->reconnect_task = NULL;
  h->conn_status = conn_status;
  h->conn_status_cls = cls;
  if (GNUNET_OK != reconnect_arm (h))
  {
    GNUNET_free (h);
    return NULL;
  }
  return h;
}


/**
 * Disconnect from the ARM service (if connected) and destroy the context.
 *
 * @param h the handle that was being used
 */
void
GNUNET_ARM_disconnect_and_free (struct GNUNET_ARM_Handle *h)
{
  struct ARMControlMessage *cm;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Disconnecting from ARM service\n");
  if (NULL != h->cth)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->cth);
    h->cth = NULL;
  }
  while ((NULL != (cm = h->control_pending_head))
         || (NULL != (cm = h->control_sent_head)) )
  {
    if (NULL != h->control_pending_head)
      GNUNET_CONTAINER_DLL_remove (h->control_pending_head,
                                   h->control_pending_tail, cm);
    else
      GNUNET_CONTAINER_DLL_remove (h->control_sent_head,
                                   h->control_sent_tail, cm);
    GNUNET_assert (NULL != cm->timeout_task_id);
    GNUNET_SCHEDULER_cancel (cm->timeout_task_id);
    if (NULL != cm->result_cont)
      cm->result_cont (cm->cont_cls, GNUNET_ARM_REQUEST_DISCONNECTED,
                       NULL, 0);
    /* FIXME: What about list callback? */
    GNUNET_free_non_null (cm->msg);
    GNUNET_free (cm);
  }
  if (NULL != h->client)
  {
    GNUNET_CLIENT_disconnect (h->client);
    h->client = NULL;
  }
  if (NULL != h->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (h->reconnect_task);
    h->reconnect_task = NULL;
  }
  if (GNUNET_NO == h->service_test_is_active)
  {
    GNUNET_CONFIGURATION_destroy (h->cfg);
    GNUNET_free (h);
  }
}


/**
 * Message timed out. Remove it from the queue.
 *
 * @param cls the message (struct ARMControlMessage *)
 * @param tc task context
 */
static void
control_message_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ARMControlMessage *cm = cls;
  struct GNUNET_ARM_Message *arm_msg;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Control message timed out\n");
  arm_msg = cm->msg;
  if ((NULL == arm_msg) || (0 == arm_msg->request_id))
  {
    GNUNET_CONTAINER_DLL_remove (cm->h->control_pending_head,
                                 cm->h->control_pending_tail, cm);
  }
  else
  {
    GNUNET_CONTAINER_DLL_remove (cm->h->control_sent_head,
                                 cm->h->control_sent_tail, cm);
  }
  if (NULL != cm->result_cont)
    cm->result_cont (cm->cont_cls, GNUNET_ARM_REQUEST_TIMEOUT, NULL, 0);
  else if (NULL != cm->list_cont)
    cm->list_cont (cm->cont_cls, GNUNET_ARM_REQUEST_TIMEOUT, 0, NULL);
  GNUNET_free_non_null (cm->msg);
  GNUNET_free (cm);
}


/**
 * A client specifically requested starting of ARM itself.
 * This function is called with information about whether
 * or not ARM is running; if it is, report success.  If
 * it is not, start the ARM process.
 *
 * @param cls the context for the request that we will report on (struct ARMControlMessage *)
 * @param result GNUNET_YES if ARM is running
 */
static void
arm_service_report (void *cls,
		    int result)
{
  struct ARMControlMessage *cm = cls;
  struct GNUNET_ARM_Handle *h;
  struct GNUNET_OS_Process *proc;
  unsigned char test_is_active;
  char *cbinary;
  char *binary;
  char *quotedbinary;
  char *config;
  char *loprefix;
  char *lopostfix;

  test_is_active = cm->h->service_test_is_active;
  if ((GNUNET_YES == test_is_active) &&
      (GNUNET_YES == result))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Looks like `%s' is already running.\n",
	 "gnunet-service-arm");
    /* arm is running! */
    if (cm->result_cont)
      cm->result_cont (cm->cont_cls,
		       GNUNET_ARM_REQUEST_SENT_OK, "arm",
		       GNUNET_ARM_RESULT_IS_STARTED_ALREADY);
  }
  if (GNUNET_NO == test_is_active)
  {
    /* User disconnected & destroyed ARM handle in the middle of
     * the service test, so we kept the handle around until now.
     */
    GNUNET_CONFIGURATION_destroy (cm->h->cfg);
    GNUNET_free (cm->h);
  }
  if ((GNUNET_YES == result) ||
      (GNUNET_NO == test_is_active))
  {
    GNUNET_free (cm);
    return;
  }
  cm->h->service_test_is_active = GNUNET_NO;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Looks like `%s' is not running, will start it.\n",
       "gnunet-service-arm");
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (
      cm->h->cfg, "arm", "PREFIX", &loprefix))
    loprefix = GNUNET_strdup ("");
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (
      cm->h->cfg, "arm", "OPTIONS", &lopostfix))
    lopostfix = GNUNET_strdup ("");
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (
      cm->h->cfg, "arm", "BINARY", &cbinary))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_WARNING, "arm", "BINARY");
    if (cm->result_cont)
      cm->result_cont (cm->cont_cls,
		       GNUNET_ARM_REQUEST_SENT_OK, "arm",
		       GNUNET_ARM_RESULT_IS_NOT_KNOWN);
    GNUNET_free (cm);
    GNUNET_free (loprefix);
    GNUNET_free (lopostfix);
    return;
  }
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (
      cm->h->cfg, "arm", "CONFIG", &config))
    config = NULL;
  binary = GNUNET_OS_get_libexec_binary_path (cbinary);
  GNUNET_asprintf (&quotedbinary,
		   "\"%s\"",
		   binary);
  GNUNET_free (cbinary);
  if ((GNUNET_YES == GNUNET_CONFIGURATION_have_value (
          cm->h->cfg, "TESTING", "WEAKRANDOM")) &&
      (GNUNET_YES == GNUNET_CONFIGURATION_get_value_yesno (
          cm->h->cfg, "TESTING", "WEAKRANDOM")) &&
      (GNUNET_NO == GNUNET_CONFIGURATION_have_value (
          cm->h->cfg, "TESTING", "HOSTFILE")))
  {
    /* Means we are ONLY running locally */
    /* we're clearly running a test, don't daemonize */
    if (NULL == config)
      proc = GNUNET_OS_start_process_s (GNUNET_NO, cm->std_inheritance,
                                        NULL, loprefix, quotedbinary,
                                        /* no daemonization! */
                                        lopostfix, NULL);
    else
      proc = GNUNET_OS_start_process_s (GNUNET_NO, cm->std_inheritance,
			       NULL, loprefix, quotedbinary, "-c", config,
                                        /* no daemonization! */
                                        lopostfix, NULL);
  }
  else
  {
    if (NULL == config)
      proc = GNUNET_OS_start_process_s (GNUNET_NO, cm->std_inheritance,
                                        NULL, loprefix, quotedbinary,
                                        "-d", lopostfix, NULL);
    else
      proc = GNUNET_OS_start_process_s (GNUNET_NO, cm->std_inheritance,
                                        NULL, loprefix, quotedbinary, "-c",
                                        config,
                                        "-d", lopostfix, NULL);
  }
  GNUNET_free (binary);
  GNUNET_free (quotedbinary);
  GNUNET_free_non_null (config);
  GNUNET_free (loprefix);
  GNUNET_free (lopostfix);
  if (NULL == proc)
  {
    if (cm->result_cont)
      cm->result_cont (cm->cont_cls, GNUNET_ARM_REQUEST_SENT_OK, "arm",
          GNUNET_ARM_RESULT_START_FAILED);
    GNUNET_free (cm);
    return;
  }
  if (cm->result_cont)
    cm->result_cont (cm->cont_cls, GNUNET_ARM_REQUEST_SENT_OK, "arm",
        GNUNET_ARM_RESULT_STARTING);
  GNUNET_OS_process_destroy (proc);
  h = cm->h;
  GNUNET_free (cm);
  reconnect_arm (h);
}


/**
 * Start or stop a service.
 *
 * @param h handle to ARM
 * @param service_name name of the service
 * @param timeout how long to wait before failing for good
 * @param cb callback to invoke when service is ready
 * @param cb_cls closure for callback
 * @param type type of the request
 */
static void
change_service (struct GNUNET_ARM_Handle *h, const char *service_name,
		struct GNUNET_TIME_Relative timeout, GNUNET_ARM_ResultCallback cb,
		void *cb_cls, uint16_t type)
{
  struct ARMControlMessage *cm;
  size_t slen;
  struct GNUNET_ARM_Message *msg;

  slen = strlen (service_name) + 1;
  if (slen + sizeof (struct GNUNET_ARM_Message) >=
      GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    if (cb != NULL)
      cb (cb_cls, GNUNET_ARM_REQUEST_TOO_LONG, NULL, 0);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Requesting %s of service `%s'.\n",
       (GNUNET_MESSAGE_TYPE_ARM_START == type) ? "start" : "termination",
       service_name);
  cm = GNUNET_malloc (sizeof (struct ARMControlMessage) + slen);
  cm->h = h;
  cm->result_cont = cb;
  cm->cont_cls = cb_cls;
  cm->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  memcpy (&cm[1], service_name, slen);
  msg = GNUNET_malloc (sizeof (struct GNUNET_ARM_Message) + slen);
  msg->header.size = htons (sizeof (struct GNUNET_ARM_Message) + slen);
  msg->header.type = htons (type);
  msg->reserved = htonl (0);
  memcpy (&msg[1], service_name, slen);
  cm->msg = msg;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Inserting a control message into the queue. Timeout is %s\n",
       GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_remaining (cm->timeout),
					       GNUNET_NO));
  GNUNET_CONTAINER_DLL_insert_tail (h->control_pending_head,
                                    h->control_pending_tail, cm);
  cm->timeout_task_id =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_absolute_get_remaining
                                    (cm->timeout), &control_message_timeout, cm);
  trigger_next_request (h, GNUNET_NO);
}


/**
 * Request for a service to be started.
 *
 * @param h handle to ARM
 * @param service_name name of the service
 * @param std_inheritance inheritance of std streams
 * @param timeout how long to wait before failing for good
 * @param cont callback to invoke after request is sent or not sent
 * @param cont_cls closure for callback
 */
void
GNUNET_ARM_request_service_start (struct GNUNET_ARM_Handle *h,
				  const char *service_name,
				  enum GNUNET_OS_InheritStdioFlags std_inheritance,
				  struct GNUNET_TIME_Relative timeout,
				  GNUNET_ARM_ResultCallback cont,
				  void *cont_cls)
{
  struct ARMControlMessage *cm;
  size_t slen;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Asked to start service `%s' within %s\n", service_name,
       GNUNET_STRINGS_relative_time_to_string (timeout, GNUNET_NO));
  if (0 == strcasecmp ("arm", service_name))
  {
    /* Possible cases:
     * 1) We're connected to ARM already. Invoke the callback immediately.
     * 2) We're not connected to ARM.
     *    Cancel any reconnection attempts temporarily, then perform
     *    a service test.
     */
    if (GNUNET_NO == h->currently_down)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "ARM is already running\n");
      if (NULL != cont)
        cont (cont_cls, GNUNET_ARM_REQUEST_SENT_OK, "arm", GNUNET_ARM_RESULT_IS_STARTED_ALREADY);
    }
    else if (GNUNET_NO == h->service_test_is_active)
    {
      if (NULL != h->cth)
      {
        GNUNET_CLIENT_notify_transmit_ready_cancel (h->cth);
        h->cth = NULL;
      }
      if (NULL != h->client)
      {
        GNUNET_CLIENT_disconnect (h->client);
        h->client = NULL;
      }
      if (NULL != h->reconnect_task)
      {
        GNUNET_SCHEDULER_cancel (h->reconnect_task);
        h->reconnect_task = NULL;
      }

      LOG (GNUNET_ERROR_TYPE_DEBUG,
          "Not connected to ARM, will do a service test\n");

      slen = strlen ("arm") + 1;
      cm = GNUNET_malloc (sizeof (struct ARMControlMessage) + slen);
      cm->h = h;
      cm->result_cont = cont;
      cm->cont_cls = cont_cls;
      cm->timeout = GNUNET_TIME_relative_to_absolute (timeout);
      cm->std_inheritance = std_inheritance;
      memcpy (&cm[1], service_name, slen);
      h->service_test_is_active = GNUNET_YES;
      GNUNET_CLIENT_service_test ("arm", h->cfg, timeout, &arm_service_report,
				  cm);
    }
    else
    {
      /* Service test is already running - tell user to chill out and try
       * again later.
       */
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Service test is already in progress, we're busy\n");
      if (NULL != cont)
        cont (cont_cls, GNUNET_ARM_REQUEST_BUSY, NULL, 0);
    }
    return;
  }
  change_service (h, service_name, timeout, cont, cont_cls,
		  GNUNET_MESSAGE_TYPE_ARM_START);
}


/**
 * Request a service to be stopped.
 * Stopping arm itself will not invalidate its handle, and
 * ARM API will try to restore connection to the ARM service,
 * even if ARM connection was lost because you asked for ARM to be stopped.
 * Call GNUNET_ARM_disconnect_and_free () to free the handle and prevent
 * further connection attempts.
 *
 * @param h handle to ARM
 * @param service_name name of the service
 * @param timeout how long to wait before failing for good
 * @param cont callback to invoke after request is sent or is not sent
 * @param cont_cls closure for callback
 */
void
GNUNET_ARM_request_service_stop (struct GNUNET_ARM_Handle *h,
				 const char *service_name,
				 struct GNUNET_TIME_Relative timeout,
				 GNUNET_ARM_ResultCallback cont,
				 void *cont_cls)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Stopping service `%s' within %s\n",
       service_name,
       GNUNET_STRINGS_relative_time_to_string (timeout, GNUNET_NO));
  change_service (h, service_name, timeout, cont, cont_cls,
		  GNUNET_MESSAGE_TYPE_ARM_STOP);
}


/**
 * Request a list of running services.
 *
 * @param h handle to ARM
 * @param timeout how long to wait before failing for good
 * @param cont callback to invoke after request is sent or is not sent
 * @param cont_cls closure for callback
 */
void
GNUNET_ARM_request_service_list (struct GNUNET_ARM_Handle *h,
                                 struct GNUNET_TIME_Relative timeout,
                                 GNUNET_ARM_ServiceListCallback cont,
                                 void *cont_cls)
{
  struct ARMControlMessage *cm;
  struct GNUNET_ARM_Message *msg;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Requesting LIST from ARM service with timeout: %s\n",
       GNUNET_STRINGS_relative_time_to_string (timeout, GNUNET_YES));
  cm = GNUNET_new (struct ARMControlMessage);
  cm->h = h;
  cm->list_cont = cont;
  cm->cont_cls = cont_cls;
  cm->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  msg = GNUNET_malloc (sizeof (struct GNUNET_ARM_Message));
  msg->header.size = htons (sizeof (struct GNUNET_ARM_Message));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_ARM_LIST);
  msg->reserved = htonl (0);
  cm->msg = msg;
  GNUNET_CONTAINER_DLL_insert_tail (h->control_pending_head,
                                    h->control_pending_tail, cm);
  cm->timeout_task_id =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_absolute_get_remaining
                                    (cm->timeout), &control_message_timeout, cm);
  trigger_next_request (h, GNUNET_NO);
}


/* end of arm_api.c */
