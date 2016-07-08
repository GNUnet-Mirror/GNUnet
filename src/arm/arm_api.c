/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2012, 2013, 2016 GNUnet e.V.

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
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
 * Entry in a doubly-linked list of operations awaiting for replies
 * (in-order) from the ARM service.
 */
struct GNUNET_ARM_Operation
{
  /**
   * This is a doubly-linked list.
   */
  struct GNUNET_ARM_Operation *next;

  /**
   * This is a doubly-linked list.
   */
  struct GNUNET_ARM_Operation *prev;

  /**
   * ARM handle.
   */
  struct GNUNET_ARM_Handle *h;

  /**
   * Callback for service state change requests.
   */
  GNUNET_ARM_ResultCallback result_cont;

  /**
   * Callback for service list requests.
   */
  GNUNET_ARM_ServiceListCallback list_cont;

  /**
   * Closure for @e result_cont or @e list_cont.
   */
  void *cont_cls;

  /**
   * Task for async completion.
   */
  struct GNUNET_SCHEDULER_Task *async;

  /**
   * Unique ID for the request.
   */
  uint64_t id;

  /**
   * Result of this operation for #notify_starting().
   */
  enum GNUNET_ARM_Result starting_ret;

  /**
   * Is this an operation to stop the ARM service?
   */
  int is_arm_stop;
};


/**
 * Handle for interacting with ARM.
 */
struct GNUNET_ARM_Handle
{
  /**
   * Our connection to the ARM service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * The configuration that we are using.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Head of doubly-linked list of pending operations.
   */
  struct GNUNET_ARM_Operation *operation_pending_head;

  /**
   * Tail of doubly-linked list of pending operations.
   */
  struct GNUNET_ARM_Operation *operation_pending_tail;

  /**
   * Callback to invoke on connection/disconnection.
   */
  GNUNET_ARM_ConnectionStatusCallback conn_status;

  /**
   * Closure for @e conn_status.
   */
  void *conn_status_cls;

  /**
   * ARM operation where the goal is to wait for ARM shutdown to
   * complete.  This operation is special in that it waits for an
   * error on the @e mq.  So we complete it by calling the
   * continuation in the #mq_error_handler().  Note that the operation
   * is no longer in the @e operation_pending_head DLL once it is
   * referenced from this field.
   */
  struct GNUNET_ARM_Operation *thm;

  /**
   * ID of the reconnect task (if any).
   */
  struct GNUNET_SCHEDULER_Task *reconnect_task;

  /**
   * Current delay we use for re-trying to connect to core.
   */
  struct GNUNET_TIME_Relative retry_backoff;

  /**
   * Counter for request identifiers.  They are used to match replies
   * from ARM to operations in the @e operation_pending_head DLL.
   */
  uint64_t request_id_counter;

  /**
   * Have we detected that ARM is up?
   */
  int currently_up;

};


/**
 * Connect to arm.
 *
 * @param h arm handle
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
static int
reconnect_arm (struct GNUNET_ARM_Handle *h);


/**
 * Task scheduled to try to re-connect to arm.
 *
 * @param cls the `struct GNUNET_ARM_Handle`
 */
static void
reconnect_arm_task (void *cls)
{
  struct GNUNET_ARM_Handle *h = cls;

  h->reconnect_task = NULL;
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
  struct GNUNET_ARM_Operation *op;

  if (NULL != h->mq)
  {
    GNUNET_MQ_destroy (h->mq);
    h->mq = NULL;
  }
  h->currently_up = GNUNET_NO;
  GNUNET_assert (NULL == h->reconnect_task);
  h->reconnect_task =
      GNUNET_SCHEDULER_add_delayed (h->retry_backoff,
				    &reconnect_arm_task,
				    h);
  while (NULL != (op = h->operation_pending_head))
  {
    if (NULL != op->result_cont)
      op->result_cont (op->cont_cls,
                       GNUNET_ARM_REQUEST_DISCONNECTED,
                       0);
    if (NULL != op->list_cont)
      op->list_cont (op->cont_cls,
                     GNUNET_ARM_REQUEST_DISCONNECTED,
                     0,
                     NULL);
    GNUNET_ARM_operation_cancel (op);
  }
  GNUNET_assert (NULL == h->operation_pending_head);
  h->retry_backoff = GNUNET_TIME_STD_BACKOFF (h->retry_backoff);
  if (NULL != h->conn_status)
    h->conn_status (h->conn_status_cls,
                    GNUNET_NO);
}


/**
 * Find a control message by its unique ID.
 *
 * @param h ARM handle
 * @param id unique message ID to use for the lookup
 * @return NULL if not found
 */
static struct GNUNET_ARM_Operation *
find_op_by_id (struct GNUNET_ARM_Handle *h,
               uint64_t id)
{
  struct GNUNET_ARM_Operation *result;

  for (result = h->operation_pending_head; NULL != result; result = result->next)
    if (id == result->id)
      return result;
  return NULL;
}


/**
 * Handler for ARM replies.
 *
 * @param cls our `struct GNUNET_ARM_Handle`
 * @param res the message received from the arm service
 */
static void
handle_arm_result (void *cls,
                   const struct GNUNET_ARM_ResultMessage *res)
{
  struct GNUNET_ARM_Handle *h = cls;
  struct GNUNET_ARM_Operation *op;
  uint64_t id;
  enum GNUNET_ARM_Result result;
  GNUNET_ARM_ResultCallback result_cont;
  void *result_cont_cls;

  id = GNUNET_ntohll (res->arm_msg.request_id);
  op = find_op_by_id (h,
                      id);
  if (NULL == op)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Message with unknown id %llu\n",
         (unsigned long long) id);
    return;
  }

  result = (enum GNUNET_ARM_Result) ntohl (res->result);
  if ( (GNUNET_YES == op->is_arm_stop) &&
       (GNUNET_ARM_RESULT_STOPPING == result) )
  {
    /* special case: if we are stopping 'gnunet-service-arm', we do not just
       wait for the result message, but also wait for the service to close
       the connection (and then we have to close our client handle as well);
       this is done by installing a different receive handler, waiting for
       the connection to go down */
    if (NULL != h->thm)
    {
      GNUNET_break (0);
      op->result_cont (h->thm->cont_cls,
		       GNUNET_ARM_REQUEST_SENT_OK,
		       GNUNET_ARM_RESULT_IS_NOT_KNOWN);
      GNUNET_free (h->thm);
    }
    GNUNET_CONTAINER_DLL_remove (h->operation_pending_head,
                                 h->operation_pending_tail,
                                 op);
    h->thm = op;
    return;
  }
  result_cont = op->result_cont;
  result_cont_cls = op->cont_cls;
  GNUNET_ARM_operation_cancel (op);
  if (NULL != result_cont)
    result_cont (result_cont_cls,
                 GNUNET_ARM_REQUEST_SENT_OK,
                 result);
}


/**
 * Checked that list result message is well-formed.
 *
 * @param cls our `struct GNUNET_ARM_Handle`
 * @param lres the message received from the arm service
 * @return #GNUNET_OK if message is well-formed
 */
static int
check_arm_list_result (void *cls,
                       const struct GNUNET_ARM_ListResultMessage *lres)
{
  const char *pos = (const char *) &lres[1];
  uint16_t rcount = ntohs (lres->count);
  uint16_t msize = ntohs (lres->arm_msg.header.size) - sizeof (*lres);
  uint16_t size_check;

  size_check = 0;
  for (unsigned int i = 0; i < rcount; i++)
  {
    const char *end = memchr (pos, 0, msize - size_check);
    if (NULL == end)
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    size_check += (end - pos) + 1;
    pos = end + 1;
  }
  return GNUNET_OK;
}


/**
 * Handler for ARM list replies.
 *
 * @param cls our `struct GNUNET_ARM_Handle`
 * @param lres the message received from the arm service
 */
static void
handle_arm_list_result (void *cls,
                        const struct GNUNET_ARM_ListResultMessage *lres)
{
  struct GNUNET_ARM_Handle *h = cls;
  uint16_t rcount = ntohs (lres->count);
  const char *list[rcount];
  const char *pos = (const char *) &lres[1];
  uint16_t msize = ntohs (lres->arm_msg.header.size) - sizeof (*lres);
  struct GNUNET_ARM_Operation *op;
  uint16_t size_check;
  uint64_t id;

  id = GNUNET_ntohll (lres->arm_msg.request_id);
  op = find_op_by_id (h,
                      id);
  if (NULL == op)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Message with unknown id %llu\n",
         (unsigned long long) id);
    return;
  }
  size_check = 0;
  for (unsigned int i = 0; i < rcount; i++)
  {
    const char *end = memchr (pos,
                              0,
                              msize - size_check);

    /* Assert, as this was already checked in #check_arm_list_result() */
    GNUNET_assert (NULL != end);
    list[i] = pos;
    size_check += (end - pos) + 1;
    pos = end + 1;
  }
  if (NULL != op->list_cont)
    op->list_cont (op->cont_cls,
                   GNUNET_ARM_REQUEST_SENT_OK,
                   rcount,
                   list);
  GNUNET_ARM_operation_cancel (op);
}


/**
 * Receive confirmation from test, ARM service is up.
 *
 * @param cls closure with the `struct GNUNET_ARM_Handle`
 * @param msg message received
 */
static void
handle_confirm (void *cls,
                const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_ARM_Handle *h = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Got confirmation from ARM that we are up!\n");
  if (GNUNET_NO == h->currently_up)
  {
    h->currently_up = GNUNET_YES;
    if (NULL != h->conn_status)
      h->conn_status (h->conn_status_cls,
                      GNUNET_YES);
  }
}


/**
 * Generic error handler, called with the appropriate error code and
 * the same closure specified at the creation of the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_ARM_Handle *`
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_ARM_Handle *h = cls;
  struct GNUNET_ARM_Operation *op;

  h->currently_up = GNUNET_NO;
  if (NULL != (op = h->thm))
  {
    h->thm = NULL;
    op->result_cont (op->cont_cls,
		     GNUNET_ARM_REQUEST_SENT_OK,
		     GNUNET_ARM_RESULT_STOPPED);
    GNUNET_free (op);
  }
  reconnect_arm_later (h);
}


/**
 * Connect to arm.
 *
 * @param h arm handle
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
static int
reconnect_arm (struct GNUNET_ARM_Handle *h)
{
  GNUNET_MQ_hd_fixed_size (arm_result,
                           GNUNET_MESSAGE_TYPE_ARM_RESULT,
                           struct GNUNET_ARM_ResultMessage);
  GNUNET_MQ_hd_var_size (arm_list_result,
                         GNUNET_MESSAGE_TYPE_ARM_LIST_RESULT,
                         struct GNUNET_ARM_ListResultMessage);
  GNUNET_MQ_hd_fixed_size (confirm,
                           GNUNET_MESSAGE_TYPE_TEST,
                           struct GNUNET_MessageHeader);
  struct GNUNET_MQ_MessageHandler handlers[] = {
    make_arm_result_handler (h),
    make_arm_list_result_handler (h),
    make_confirm_handler (h),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MessageHeader *test;
  struct GNUNET_MQ_Envelope *env;

  if (NULL != h->mq)
    return GNUNET_OK;
  GNUNET_assert (GNUNET_NO == h->currently_up);
  h->mq = GNUNET_CLIENT_connecT (h->cfg,
                                 "arm",
                                 handlers,
                                 &mq_error_handler,
                                 h);
  if (NULL == h->mq)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "GNUNET_CLIENT_connect returned NULL\n");
    if (NULL != h->conn_status)
      h->conn_status (h->conn_status_cls,
                      GNUNET_SYSERR);
    return GNUNET_SYSERR;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending TEST message to ARM\n");
  env = GNUNET_MQ_msg (test,
                       GNUNET_MESSAGE_TYPE_TEST);
  GNUNET_MQ_send (h->mq,
                  env);
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
 * @param conn_status_cls closure for @a conn_status
 * @return context to use for further ARM operations, NULL on error.
 */
struct GNUNET_ARM_Handle *
GNUNET_ARM_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                    GNUNET_ARM_ConnectionStatusCallback conn_status,
		    void *conn_status_cls)
{
  struct GNUNET_ARM_Handle *h;

  h = GNUNET_new (struct GNUNET_ARM_Handle);
  h->cfg = cfg;
  h->conn_status = conn_status;
  h->conn_status_cls = conn_status_cls;
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
GNUNET_ARM_disconnect (struct GNUNET_ARM_Handle *h)
{
  struct GNUNET_ARM_Operation *op;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Disconnecting from ARM service\n");
  while (NULL != (op = h->operation_pending_head))
  {
    GNUNET_CONTAINER_DLL_remove (h->operation_pending_head,
                                 h->operation_pending_tail,
                                 op);
    if (NULL != op->result_cont)
      op->result_cont (op->cont_cls,
                       GNUNET_ARM_REQUEST_DISCONNECTED,
                       0);
    if (NULL != op->list_cont)
      op->list_cont (op->cont_cls,
                     GNUNET_ARM_REQUEST_DISCONNECTED,
                     0,
                     NULL);
    if (NULL != op->async)
    {
      GNUNET_SCHEDULER_cancel (op->async);
      op->async = NULL;
    }
    GNUNET_free (op);
  }
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
  GNUNET_free (h);
}


/**
 * A client specifically requested starting of ARM itself.
 * Starts the ARM service.
 *
 * @param h the handle with configuration details
 * @param std_inheritance inheritance of std streams
 * @return operation status code
 */
static enum GNUNET_ARM_Result
start_arm_service (struct GNUNET_ARM_Handle *h,
                   enum GNUNET_OS_InheritStdioFlags std_inheritance)
{
  struct GNUNET_OS_Process *proc;
  char *cbinary;
  char *binary;
  char *quotedbinary;
  char *config;
  char *loprefix;
  char *lopostfix;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (h->cfg,
                                             "arm",
                                             "PREFIX",
                                             &loprefix))
    loprefix = GNUNET_strdup ("");
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (h->cfg,
                                             "arm",
                                             "OPTIONS",
                                             &lopostfix))
    lopostfix = GNUNET_strdup ("");
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (h->cfg,
                                             "arm",
                                             "BINARY",
                                             &cbinary))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_WARNING,
                               "arm",
                               "BINARY");
    GNUNET_free (loprefix);
    GNUNET_free (lopostfix);
    return GNUNET_ARM_RESULT_IS_NOT_KNOWN;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (h->cfg,
                                               "arm",
                                               "CONFIG",
                                               &config))
    config = NULL;
  binary = GNUNET_OS_get_libexec_binary_path (cbinary);
  GNUNET_asprintf (&quotedbinary,
		   "\"%s\"",
		   binary);
  GNUNET_free (cbinary);
  if ( (GNUNET_YES ==
        GNUNET_CONFIGURATION_have_value (h->cfg,
                                         "TESTING",
                                         "WEAKRANDOM")) &&
       (GNUNET_YES ==
        GNUNET_CONFIGURATION_get_value_yesno (h->cfg,
                                              "TESTING",
                                              "WEAKRANDOM")) &&
       (GNUNET_NO ==
        GNUNET_CONFIGURATION_have_value (h->cfg,
                                         "TESTING",
                                         "HOSTFILE")))
  {
    /* Means we are ONLY running locally */
    /* we're clearly running a test, don't daemonize */
    if (NULL == config)
      proc = GNUNET_OS_start_process_s (GNUNET_NO,
                                        std_inheritance,
                                        NULL,
                                        loprefix,
                                        quotedbinary,
                                        /* no daemonization! */
                                        lopostfix,
                                        NULL);
    else
      proc = GNUNET_OS_start_process_s (GNUNET_NO,
                                        std_inheritance,
                                        NULL,
                                        loprefix,
                                        quotedbinary,
                                        "-c", config,
                                        /* no daemonization! */
                                        lopostfix,
                                        NULL);
  }
  else
  {
    if (NULL == config)
      proc = GNUNET_OS_start_process_s (GNUNET_NO,
                                        std_inheritance,
                                        NULL,
                                        loprefix,
                                        quotedbinary,
                                        "-d", /* do daemonize */
                                        lopostfix, NULL);
    else
      proc = GNUNET_OS_start_process_s (GNUNET_NO,
                                        std_inheritance,
                                        NULL,
                                        loprefix,
                                        quotedbinary,
                                        "-c", config,
                                        "-d", /* do daemonize */
                                        lopostfix,
                                        NULL);
  }
  GNUNET_free (binary);
  GNUNET_free (quotedbinary);
  GNUNET_free_non_null (config);
  GNUNET_free (loprefix);
  GNUNET_free (lopostfix);
  if (NULL == proc)
    return GNUNET_ARM_RESULT_START_FAILED;
  GNUNET_OS_process_destroy (proc);
  return GNUNET_ARM_RESULT_STARTING;
}


/**
 * Abort an operation.  Only prevents the callback from being
 * called, the operation may still complete.
 *
 * @param op operation to cancel
 */
void
GNUNET_ARM_operation_cancel (struct GNUNET_ARM_Operation *op)
{
  struct GNUNET_ARM_Handle *h = op->h;

  if (h->thm == op)
  {
    op->result_cont = NULL;
    return;
  }
  GNUNET_CONTAINER_DLL_remove (h->operation_pending_head,
                               h->operation_pending_tail,
                               op);
  GNUNET_free (op);
}


/**
 * Start or stop a service.
 *
 * @param h handle to ARM
 * @param service_name name of the service
 * @param cb callback to invoke when service is ready
 * @param cb_cls closure for @a cb
 * @param type type of the request
 * @return handle to queue, NULL on error
 */
static struct GNUNET_ARM_Operation *
change_service (struct GNUNET_ARM_Handle *h,
                const char *service_name,
                GNUNET_ARM_ResultCallback cb,
		void *cb_cls,
                uint16_t type)
{
  struct GNUNET_ARM_Operation *op;
  size_t slen;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_ARM_Message *msg;

  slen = strlen (service_name) + 1;
  if (slen + sizeof (struct GNUNET_ARM_Message) >=
      GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return NULL;
  }
  if (0 == h->request_id_counter)
    h->request_id_counter++;
  op = GNUNET_new (struct GNUNET_ARM_Operation);
  op->h = h;
  op->result_cont = cb;
  op->cont_cls = cb_cls;
  op->id = h->request_id_counter++;
  GNUNET_CONTAINER_DLL_insert_tail (h->operation_pending_head,
                                    h->operation_pending_tail,
                                    op);
  env = GNUNET_MQ_msg_extra (msg,
                             slen,
                             type);
  msg->reserved = htonl (0);
  msg->request_id = GNUNET_htonll (op->id);
  GNUNET_memcpy (&msg[1],
          service_name,
          slen);
  GNUNET_MQ_send (h->mq,
                  env);
  return op;
}


/**
 * Task run to notify application that ARM is already up.
 *
 * @param cls the operation that asked ARM to be started
 */
static void
notify_running (void *cls)
{
  struct GNUNET_ARM_Operation *op = cls;
  struct GNUNET_ARM_Handle *h = op->h;

  op->async = NULL;
  GNUNET_CONTAINER_DLL_remove (h->operation_pending_head,
                               h->operation_pending_tail,
                               op);
  if (NULL != op->result_cont)
    op->result_cont (op->cont_cls,
                     GNUNET_ARM_REQUEST_SENT_OK,
                     GNUNET_ARM_RESULT_IS_STARTED_ALREADY);
  if ( (GNUNET_YES == h->currently_up) &&
       (NULL != h->conn_status) )
    h->conn_status (h->conn_status_cls,
                    GNUNET_YES);
  GNUNET_free (op);
}


/**
 * Task run to notify application that ARM is being started.
 *
 * @param cls the operation that asked ARM to be started
 */
static void
notify_starting (void *cls)
{
  struct GNUNET_ARM_Operation *op = cls;
  struct GNUNET_ARM_Handle *h = op->h;

  op->async = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Notifying client that we started the ARM service\n");
  GNUNET_CONTAINER_DLL_remove (h->operation_pending_head,
                               h->operation_pending_tail,
                               op);
  if (NULL != op->result_cont)
    op->result_cont (op->cont_cls,
                     GNUNET_ARM_REQUEST_SENT_OK,
                     op->starting_ret);
  GNUNET_free (op);
}


/**
 * Request for a service to be started.
 *
 * @param h handle to ARM
 * @param service_name name of the service
 * @param std_inheritance inheritance of std streams
 * @param cont callback to invoke after request is sent or not sent
 * @param cont_cls closure for @a cont
 * @return handle for the operation, NULL on error
 */
struct GNUNET_ARM_Operation *
GNUNET_ARM_request_service_start (struct GNUNET_ARM_Handle *h,
				  const char *service_name,
				  enum GNUNET_OS_InheritStdioFlags std_inheritance,
				  GNUNET_ARM_ResultCallback cont,
				  void *cont_cls)
{
  struct GNUNET_ARM_Operation *op;
  enum GNUNET_ARM_Result ret;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Starting service `%s'\n",
       service_name);
  if (0 != strcasecmp ("arm",
                       service_name))
    return change_service (h,
                           service_name,
                           cont,
                           cont_cls,
                           GNUNET_MESSAGE_TYPE_ARM_START);

  /* Possible cases:
   * 1) We're connected to ARM already. Invoke the callback immediately.
   * 2) We're not connected to ARM.
   *    Cancel any reconnection attempts temporarily, then perform
   *    a service test.
   */
  if (GNUNET_YES == h->currently_up)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "ARM is already running\n");
    op = GNUNET_new (struct GNUNET_ARM_Operation);
    op->h = h;
    op->result_cont = cont;
    op->cont_cls = cont_cls;
    GNUNET_CONTAINER_DLL_insert_tail (h->operation_pending_head,
                                      h->operation_pending_tail,
                                      op);
    op->async = GNUNET_SCHEDULER_add_now (&notify_running,
                                          op);
    return op;
  }
  /* This is an inherently uncertain choice, as it is of course
     theoretically possible that ARM is up and we just did not
     yet complete the MQ handshake.  However, given that users
     are unlikely to hammer 'gnunet-arm -s' on a busy system,
     the above check should catch 99.99% of the cases where ARM
     is already running. */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Starting ARM service\n");
  ret = start_arm_service (h,
                           std_inheritance);
  if (GNUNET_ARM_RESULT_STARTING == ret)
    reconnect_arm (h);
  op = GNUNET_new (struct GNUNET_ARM_Operation);
  op->h = h;
  op->result_cont = cont;
  op->cont_cls = cont_cls;
  GNUNET_CONTAINER_DLL_insert_tail (h->operation_pending_head,
                                    h->operation_pending_tail,
                                    op);
  op->starting_ret = ret;
  op->async = GNUNET_SCHEDULER_add_now (&notify_starting,
                                        op);
  return op;
}


/**
 * Request a service to be stopped.  Stopping arm itself will not
 * invalidate its handle, and ARM API will try to restore connection
 * to the ARM service, even if ARM connection was lost because you
 * asked for ARM to be stopped.  Call
 * #GNUNET_ARM_disconnect() to free the handle and prevent
 * further connection attempts.
 *
 * @param h handle to ARM
 * @param service_name name of the service
 * @param cont callback to invoke after request is sent or is not sent
 * @param cont_cls closure for @a cont
 * @return handle for the operation, NULL on error
 */
struct GNUNET_ARM_Operation *
GNUNET_ARM_request_service_stop (struct GNUNET_ARM_Handle *h,
				 const char *service_name,
				 GNUNET_ARM_ResultCallback cont,
				 void *cont_cls)
{
  struct GNUNET_ARM_Operation *op;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Stopping service `%s'\n",
       service_name);
  op = change_service (h,
                       service_name,
                       cont,
                       cont_cls,
                       GNUNET_MESSAGE_TYPE_ARM_STOP);
  if (NULL == op)
    return NULL;
  /* If the service is ARM, set a flag as we will use MQ errors
     to detect that the process is really gone. */
  if (0 == strcasecmp (service_name,
                       "arm"))
    op->is_arm_stop = GNUNET_YES;
  return op;
}


/**
 * Request a list of running services.
 *
 * @param h handle to ARM
 * @param cont callback to invoke after request is sent or is not sent
 * @param cont_cls closure for @a cont
 * @return handle for the operation, NULL on error
 */
struct GNUNET_ARM_Operation *
GNUNET_ARM_request_service_list (struct GNUNET_ARM_Handle *h,
                                 GNUNET_ARM_ServiceListCallback cont,
                                 void *cont_cls)
{
  struct GNUNET_ARM_Operation *op;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_ARM_Message *msg;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Requesting LIST from ARM service\n");
  if (0 == h->request_id_counter)
    h->request_id_counter++;
  op = GNUNET_new (struct GNUNET_ARM_Operation);
  op->h = h;
  op->list_cont = cont;
  op->cont_cls = cont_cls;
  op->id = h->request_id_counter++;
  GNUNET_CONTAINER_DLL_insert_tail (h->operation_pending_head,
                                    h->operation_pending_tail,
                                    op);
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_ARM_LIST);
  msg->reserved = htonl (0);
  msg->request_id = GNUNET_htonll (op->id);
  GNUNET_MQ_send (h->mq,
                  env);
  return op;
}


/* end of arm_api.c */
