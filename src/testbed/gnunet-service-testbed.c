/*
  This file is part of GNUnet.
  (C) 2008--2013 Christian Grothoff (and other contributing authors)

  GNUnet is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 2, or (at your
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
 * @file testbed/gnunet-service-testbed.c
 * @brief implementation of the TESTBED service
 * @author Sree Harsha Totakura
 */

#include "gnunet-service-testbed.h"


/***********/
/* Globals */
/***********/

/**
 * Our configuration
 */
struct GNUNET_CONFIGURATION_Handle *our_config;

/**
 * The master context; generated with the first INIT message
 */
struct Context *GST_context;

/**
 * A list of directly linked neighbours
 */
struct Slave **GST_slave_list;

/**
 * Array of hosts
 */
struct GNUNET_TESTBED_Host **GST_host_list;

/**
 * DLL head for forwarded operation contexts
 */
struct ForwardedOperationContext *fopcq_head;

/**
 * DLL tail for forwarded operation contexts
 */
struct ForwardedOperationContext *fopcq_tail;

/**
 * Operation queue for open file descriptors
 */
struct OperationQueue *GST_opq_openfds;

/**
 * Timeout for operations which may take some time
 */
const struct GNUNET_TIME_Relative GST_timeout;

/**
 * The size of the host list
 */
unsigned int GST_host_list_size;

/**
 * The size of directly linked neighbours list
 */
unsigned int GST_slave_list_size;

/**
 * The size of the peer list
 */
unsigned int GST_peer_list_size;


/***********************************/
/* Local definitions and variables */
/***********************************/

/**
 * The message queue for sending messages to clients
 */
struct MessageQueue
{
  /**
   * The message to be sent
   */
  struct GNUNET_MessageHeader *msg;

  /**
   * The client to send the message to
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * next pointer for DLL
   */
  struct MessageQueue *next;

  /**
   * prev pointer for DLL
   */
  struct MessageQueue *prev;
};

/**
 * Our hostname; we give this to all the peers we start
 */
static char *hostname;

/**
 * Current Transmit Handle; NULL if no notify transmit exists currently
 */
static struct GNUNET_SERVER_TransmitHandle *transmit_handle;

/**
 * The head for the LCF queue
 */
static struct LCFContextQueue *lcfq_head;

/**
 * The tail for the LCF queue
 */
static struct LCFContextQueue *lcfq_tail;

/**
 * The message queue head
 */
static struct MessageQueue *mq_head;

/**
 * The message queue tail
 */
static struct MessageQueue *mq_tail;

/**
 * The hashmap of shared services
 */
static struct GNUNET_CONTAINER_MultiHashMap *ss_map;

/**
 * A list of routes
 */
static struct Route **route_list;

/**
 * The event mask for the events we listen from sub-controllers
 */
static uint64_t event_mask;

/**
 * The size of the route list
 */
static unsigned int route_list_size;

/**
 * The lcf_task handle
 */
static GNUNET_SCHEDULER_TaskIdentifier lcf_proc_task_id;

/**
 * The shutdown task handle
 */
static GNUNET_SCHEDULER_TaskIdentifier shutdown_task_id;


/**
 * Function called to notify a client about the connection begin ready to queue
 * more data.  "buf" will be NULL and "size" zero if the connection was closed
 * for writing in the meantime.
 *
 * @param cls NULL
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_ready_notify (void *cls, size_t size, void *buf)
{
  struct MessageQueue *mq_entry;

  transmit_handle = NULL;
  mq_entry = mq_head;
  GNUNET_assert (NULL != mq_entry);
  if (0 == size)
    return 0;
  GNUNET_assert (ntohs (mq_entry->msg->size) <= size);
  size = ntohs (mq_entry->msg->size);
  memcpy (buf, mq_entry->msg, size);
  GNUNET_free (mq_entry->msg);
  GNUNET_SERVER_client_drop (mq_entry->client);
  GNUNET_CONTAINER_DLL_remove (mq_head, mq_tail, mq_entry);
  GNUNET_free (mq_entry);
  mq_entry = mq_head;
  if (NULL != mq_entry)
    transmit_handle =
        GNUNET_SERVER_notify_transmit_ready (mq_entry->client,
                                             ntohs (mq_entry->msg->size),
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             &transmit_ready_notify, NULL);
  return size;
}


/**
 * Queues a message in send queue for sending to the service
 *
 * @param client the client to whom the queued message has to be sent
 * @param msg the message to queue
 */
void
GST_queue_message (struct GNUNET_SERVER_Client *client,
                   struct GNUNET_MessageHeader *msg)
{
  struct MessageQueue *mq_entry;
  uint16_t type;
  uint16_t size;

  type = ntohs (msg->type);
  size = ntohs (msg->size);
  GNUNET_assert ((GNUNET_MESSAGE_TYPE_TESTBED_INIT <= type) &&
                 (GNUNET_MESSAGE_TYPE_TESTBED_MAX > type));
  mq_entry = GNUNET_malloc (sizeof (struct MessageQueue));
  mq_entry->msg = msg;
  mq_entry->client = client;
  GNUNET_SERVER_client_keep (client);
  LOG_DEBUG ("Queueing message of type %u, size %u for sending\n", type,
             ntohs (msg->size));
  GNUNET_CONTAINER_DLL_insert_tail (mq_head, mq_tail, mq_entry);
  if (NULL == transmit_handle)
    transmit_handle =
        GNUNET_SERVER_notify_transmit_ready (client, size,
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             &transmit_ready_notify, NULL);
}


/**
 * Function to add a host to the current list of known hosts
 *
 * @param host the host to add
 * @return GNUNET_OK on success; GNUNET_SYSERR on failure due to host-id
 *           already in use
 */
static int
host_list_add (struct GNUNET_TESTBED_Host *host)
{
  uint32_t host_id;

  host_id = GNUNET_TESTBED_host_get_id_ (host);
  if (GST_host_list_size <= host_id)
    GST_array_grow_large_enough (GST_host_list, GST_host_list_size, host_id);
  if (NULL != GST_host_list[host_id])
  {
    LOG_DEBUG ("A host with id: %u already exists\n", host_id);
    return GNUNET_SYSERR;
  }
  GST_host_list[host_id] = host;
  return GNUNET_OK;
}


/**
 * Adds a route to the route list
 *
 * @param route the route to add
 */
static void
route_list_add (struct Route *route)
{
  if (route->dest >= route_list_size)
    GST_array_grow_large_enough (route_list, route_list_size, route->dest);
  GNUNET_assert (NULL == route_list[route->dest]);
  route_list[route->dest] = route;
}


/**
 * Adds a slave to the slave array
 *
 * @param slave the slave controller to add
 */
static void
slave_list_add (struct Slave *slave)
{
  if (slave->host_id >= GST_slave_list_size)
    GST_array_grow_large_enough (GST_slave_list, GST_slave_list_size,
                                 slave->host_id);
  GNUNET_assert (NULL == GST_slave_list[slave->host_id]);
  GST_slave_list[slave->host_id] = slave;
}


/**
 * Finds the route with directly connected host as destination through which
 * the destination host can be reached
 *
 * @param host_id the id of the destination host
 * @return the route with directly connected destination host; NULL if no route
 *           is found
 */
struct Route *
GST_find_dest_route (uint32_t host_id)
{
  struct Route *route;

  if (route_list_size <= host_id)
    return NULL;
  while (NULL != (route = route_list[host_id]))
  {
    if (route->thru == GST_context->host_id)
      break;
    host_id = route->thru;
  }
  return route;
}


/**
 * Routes message to a host given its host_id
 *
 * @param host_id the id of the destination host
 * @param msg the message to be routed
 */
static void
route_message (uint32_t host_id, const struct GNUNET_MessageHeader *msg)
{
  GNUNET_break (0);
}


/**
 * Send operation failure message to client
 *
 * @param client the client to which the failure message has to be sent to
 * @param operation_id the id of the failed operation
 * @param emsg the error message; can be NULL
 */
void
GST_send_operation_fail_msg (struct GNUNET_SERVER_Client *client,
                             uint64_t operation_id, const char *emsg)
{
  struct GNUNET_TESTBED_OperationFailureEventMessage *msg;
  uint16_t msize;
  uint16_t emsg_len;

  msize = sizeof (struct GNUNET_TESTBED_OperationFailureEventMessage);
  emsg_len = (NULL == emsg) ? 0 : strlen (emsg) + 1;
  msize += emsg_len;
  msg = GNUNET_malloc (msize);
  msg->header.size = htons (msize);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_OPERATION_FAIL_EVENT);
  msg->event_type = htonl (GNUNET_TESTBED_ET_OPERATION_FINISHED);
  msg->operation_id = GNUNET_htonll (operation_id);
  if (0 != emsg_len)
    memcpy (&msg[1], emsg, emsg_len);
  GST_queue_message (client, &msg->header);
}


/**
 * Function to send generic operation success message to given client
 *
 * @param client the client to send the message to
 * @param operation_id the id of the operation which was successful
 */
void
GST_send_operation_success_msg (struct GNUNET_SERVER_Client *client,
                                uint64_t operation_id)
{
  struct GNUNET_TESTBED_GenericOperationSuccessEventMessage *msg;
  uint16_t msize;

  msize = sizeof (struct GNUNET_TESTBED_GenericOperationSuccessEventMessage);
  msg = GNUNET_malloc (msize);
  msg->header.size = htons (msize);
  msg->header.type =
      htons (GNUNET_MESSAGE_TYPE_TESTBED_GENERIC_OPERATION_SUCCESS);
  msg->operation_id = GNUNET_htonll (operation_id);
  msg->event_type = htonl (GNUNET_TESTBED_ET_OPERATION_FINISHED);
  GST_queue_message (client, &msg->header);
}


/**
 * Function to send a failure reponse for controller link operation
 *
 * @param client the client to send the message to
 * @param operation_id the operation ID of the controller link request
 * @param cfg the configuration with which the delegated controller is started.
 *          Can be NULL if the delegated controller is not started but just
 *          linked to.
 * @param emsg set to an error message explaining why the controller link
 *          failed.  Setting this to NULL signifies success.  !This should be
 *          NULL if cfg is set!
 */
static void
send_controller_link_response (struct GNUNET_SERVER_Client *client,
                               uint64_t operation_id,
                               const struct GNUNET_CONFIGURATION_Handle
                               *cfg,
                               const char *emsg)
{
  struct GNUNET_TESTBED_ControllerLinkResponse *msg;
  char *xconfig;
  size_t config_size;
  size_t xconfig_size;  
  uint16_t msize;

  GNUNET_assert ((NULL == cfg) || (NULL == emsg));
  xconfig = NULL;
  xconfig_size = 0;
  config_size = 0;
  msize = sizeof (struct GNUNET_TESTBED_ControllerLinkResponse);
  if (NULL != cfg)
  {
    xconfig = GNUNET_TESTBED_compress_cfg_ (cfg,
                                            &config_size,
                                            &xconfig_size);
    msize += xconfig_size;
  }
  if (NULL != emsg)
    msize += strlen (emsg);
  msg = GNUNET_malloc (msize);
  msg->header.type = htons
      (GNUNET_MESSAGE_TYPE_TESTBED_LINK_CONTROLLERS_RESULT);
  msg->header.size = htons (msize);
  if (NULL == emsg)
    msg->success = htons (GNUNET_YES);
  msg->operation_id = GNUNET_htonll (operation_id);
  msg->config_size = htons ((uint16_t) config_size);
  if (NULL != xconfig)
    memcpy (&msg[1], xconfig, xconfig_size);
  if (NULL != emsg)
    memcpy (&msg[1], emsg, strlen (emsg));
  GST_queue_message (client, &msg->header);
}

/**
 * Callback which will be called after a host registration succeeded or failed
 *
 * @param cls the handle to the slave at which the registration is completed
 * @param emsg the error message; NULL if host registration is successful
 */
static void
hr_completion (void *cls, const char *emsg);


/**
 * Attempts to register the next host in the host registration queue
 *
 * @param slave the slave controller whose host registration queue is checked
 *          for host registrations
 */
static void
register_next_host (struct Slave *slave)
{
  struct HostRegistration *hr;

  hr = slave->hr_dll_head;
  GNUNET_assert (NULL != hr);
  GNUNET_assert (NULL == slave->rhandle);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Registering host %u at %u\n",
       GNUNET_TESTBED_host_get_id_ (hr->host),
       GNUNET_TESTBED_host_get_id_ (GST_host_list[slave->host_id]));
  slave->rhandle =
      GNUNET_TESTBED_register_host (slave->controller, hr->host, hr_completion,
                                    slave);
}


/**
 * Callback which will be called to after a host registration succeeded or failed
 *
 * @param cls the handle to the slave at which the registration is completed
 * @param emsg the error message; NULL if host registration is successful
 */
static void
hr_completion (void *cls, const char *emsg)
{
  struct Slave *slave = cls;
  struct HostRegistration *hr;

  slave->rhandle = NULL;
  hr = slave->hr_dll_head;
  GNUNET_assert (NULL != hr);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Registering host %u at %u successful\n",
       GNUNET_TESTBED_host_get_id_ (hr->host),
       GNUNET_TESTBED_host_get_id_ (GST_host_list[slave->host_id]));
  GNUNET_CONTAINER_DLL_remove (slave->hr_dll_head, slave->hr_dll_tail, hr);
  if (NULL != hr->cb)
    hr->cb (hr->cb_cls, emsg);
  GNUNET_free (hr);
  if (NULL != slave->hr_dll_head)
    register_next_host (slave);
}


/**
 * Adds a host registration's request to a slave's registration queue
 *
 * @param slave the slave controller at which the given host has to be
 *          registered
 * @param cb the host registration completion callback
 * @param cb_cls the closure for the host registration completion callback
 * @param host the host which has to be registered
 */
void
GST_queue_host_registration (struct Slave *slave,
                             GNUNET_TESTBED_HostRegistrationCompletion cb,
                             void *cb_cls, struct GNUNET_TESTBED_Host *host)
{
  struct HostRegistration *hr;
  int call_register;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Queueing host registration for host %u at %u\n",
       GNUNET_TESTBED_host_get_id_ (host),
       GNUNET_TESTBED_host_get_id_ (GST_host_list[slave->host_id]));
  hr = GNUNET_malloc (sizeof (struct HostRegistration));
  hr->cb = cb;
  hr->cb_cls = cb_cls;
  hr->host = host;
  call_register = (NULL == slave->hr_dll_head) ? GNUNET_YES : GNUNET_NO;
  GNUNET_CONTAINER_DLL_insert_tail (slave->hr_dll_head, slave->hr_dll_tail, hr);
  if (GNUNET_YES == call_register)
    register_next_host (slave);
}


/**
 * The  Link Controller forwarding task
 *
 * @param cls the LCFContext
 * @param tc the Task context from scheduler
 */
static void
lcf_proc_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Completion callback for host registrations while forwarding Link Controller messages
 *
 * @param cls the LCFContext
 * @param emsg the error message; NULL if host registration is successful
 */
static void
lcf_proc_cc (void *cls, const char *emsg)
{
  struct LCFContext *lcf = cls;

  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == lcf_proc_task_id);
  switch (lcf->state)
  {
  case INIT:
    if (NULL != emsg)
      goto registration_error;
    lcf->state = DELEGATED_HOST_REGISTERED;
    lcf_proc_task_id = GNUNET_SCHEDULER_add_now (&lcf_proc_task, lcf);
    break;
  case DELEGATED_HOST_REGISTERED:
    if (NULL != emsg)
      goto registration_error;
    lcf->state = SLAVE_HOST_REGISTERED;
    lcf_proc_task_id = GNUNET_SCHEDULER_add_now (&lcf_proc_task, lcf);
    break;
  default:
    GNUNET_assert (0);          /* Shouldn't reach here */
  }
  return;

registration_error:
  LOG (GNUNET_ERROR_TYPE_WARNING, "Host registration failed with message: %s\n",
       emsg);
  lcf->state = FINISHED;
  lcf_proc_task_id = GNUNET_SCHEDULER_add_now (&lcf_proc_task, lcf);
}


/**
 * Callback to relay the reply msg of a forwarded operation back to the client
 *
 * @param cls ForwardedOperationContext
 * @param msg the message to relay
 */
void
GST_forwarded_operation_reply_relay (void *cls,
                                     const struct GNUNET_MessageHeader *msg)
{
  struct ForwardedOperationContext *fopc = cls;
  struct GNUNET_MessageHeader *dup_msg;
  uint16_t msize;

  msize = ntohs (msg->size);
  LOG_DEBUG ("Relaying message with type: %u, size: %u\n", ntohs (msg->type),
             msize);
  dup_msg = GNUNET_copy_message (msg);
  GST_queue_message (fopc->client, dup_msg);
  GNUNET_SERVER_client_drop (fopc->client);
  GNUNET_SCHEDULER_cancel (fopc->timeout_task);
  GNUNET_CONTAINER_DLL_remove (fopcq_head, fopcq_tail, fopc);
  GNUNET_free (fopc);
}


/**
 * Task to free resources when forwarded operation has been timedout
 *
 * @param cls the ForwardedOperationContext
 * @param tc the task context from scheduler
 */
void
GST_forwarded_operation_timeout (void *cls,
                                 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ForwardedOperationContext *fopc = cls;

  GNUNET_TESTBED_forward_operation_msg_cancel_ (fopc->opc);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "A forwarded operation has timed out\n");
  GST_send_operation_fail_msg (fopc->client, fopc->operation_id,
                               "A forwarded operation has timed out");
  GNUNET_SERVER_client_drop (fopc->client);
  GNUNET_CONTAINER_DLL_remove (fopcq_head, fopcq_tail, fopc);
  GNUNET_free (fopc);
}


/**
 * The  Link Controller forwarding task
 *
 * @param cls the LCFContext
 * @param tc the Task context from scheduler
 */
static void
lcf_proc_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Task to free resources when forwarded link controllers has been timedout
 *
 * @param cls the LCFContext
 * @param tc the task context from scheduler
 */
static void
lcf_forwarded_operation_timeout (void *cls,
                                 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct LCFContext *lcf = cls;

  lcf->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  //  GST_forwarded_operation_timeout (lcf->fopc, tc);
  LOG (GNUNET_ERROR_TYPE_WARNING,
       "A forwarded controller link operation has timed out\n");
  send_controller_link_response (lcf->client, lcf->operation_id, NULL,
                                 "A forwarded controller link operation has "
                                 "timed out\n");
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == lcf_proc_task_id);
  lcf_proc_task_id = GNUNET_SCHEDULER_add_now (&lcf_proc_task, lcf);
}


/**
 * The  Link Controller forwarding task
 *
 * @param cls the LCFContext
 * @param tc the Task context from scheduler
 */
static void
lcf_proc_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct LCFContext *lcf = cls;
  struct LCFContextQueue *lcfq;

  lcf_proc_task_id = GNUNET_SCHEDULER_NO_TASK;
  switch (lcf->state)
  {
  case INIT:
    if (GNUNET_NO ==
        GNUNET_TESTBED_is_host_registered_ (GST_host_list
                                            [lcf->delegated_host_id],
                                            lcf->gateway->controller))
    {
      GST_queue_host_registration (lcf->gateway, lcf_proc_cc, lcf,
                                   GST_host_list[lcf->delegated_host_id]);
    }
    else
    {
      lcf->state = DELEGATED_HOST_REGISTERED;
      lcf_proc_task_id = GNUNET_SCHEDULER_add_now (&lcf_proc_task, lcf);
    }
    break;
  case DELEGATED_HOST_REGISTERED:
    if (GNUNET_NO ==
        GNUNET_TESTBED_is_host_registered_ (GST_host_list[lcf->slave_host_id],
                                            lcf->gateway->controller))
    {
      GST_queue_host_registration (lcf->gateway, lcf_proc_cc, lcf,
                                   GST_host_list[lcf->slave_host_id]);
    }
    else
    {
      lcf->state = SLAVE_HOST_REGISTERED;
      lcf_proc_task_id = GNUNET_SCHEDULER_add_now (&lcf_proc_task, lcf);
    }
    break;
  case SLAVE_HOST_REGISTERED:
    lcf->op = GNUNET_TESTBED_controller_link (lcf,
                                              lcf->gateway->controller,
                                              GST_host_list[lcf->delegated_host_id],
                                              GST_host_list[lcf->slave_host_id],
                                              NULL,
                                              lcf->is_subordinate);
    lcf->timeout_task =
        GNUNET_SCHEDULER_add_delayed (GST_timeout, &lcf_forwarded_operation_timeout,
                                      lcf);
    lcf->state = FINISHED;
    break;
  case FINISHED:
    lcfq = lcfq_head;
    GNUNET_assert (lcfq->lcf == lcf);
    GNUNET_assert (NULL != lcf->cfg);
    GNUNET_CONFIGURATION_destroy (lcf->cfg);
    GNUNET_SERVER_client_drop (lcf->client);
    GNUNET_TESTBED_operation_done (lcf->op);
    GNUNET_free (lcf);
    GNUNET_CONTAINER_DLL_remove (lcfq_head, lcfq_tail, lcfq);
    GNUNET_free (lcfq);
    if (NULL != lcfq_head)
      lcf_proc_task_id =
          GNUNET_SCHEDULER_add_now (&lcf_proc_task, lcfq_head->lcf);
  }
}


/**
 * Callback for event from slave controllers
 *
 * @param cls struct Slave *
 * @param event information about the event
 */
static void
slave_event_callback (void *cls,
                      const struct GNUNET_TESTBED_EventInformation *event)
{
  struct RegisteredHostContext *rhc;
  struct LCFContext *lcf;
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_TESTBED_Operation *old_op;

  /* We currently only get here when working on RegisteredHostContexts and
     LCFContexts */
  GNUNET_assert (GNUNET_TESTBED_ET_OPERATION_FINISHED == event->type);
  rhc = event->op_cls;
  if (CLOSURE_TYPE_RHC == rhc->type)
  {
    GNUNET_assert (rhc->sub_op == event->op);
    switch (rhc->state)
    {
    case RHC_GET_CFG:
      cfg = event->details.operation_finished.generic;
      old_op = rhc->sub_op;
      rhc->state = RHC_LINK;
      rhc->sub_op =
          GNUNET_TESTBED_controller_link (rhc, rhc->gateway->controller,
                                          rhc->reg_host, rhc->host, cfg,
                                          GNUNET_NO);
      GNUNET_TESTBED_operation_done (old_op);
      break;
    case RHC_LINK:
      LOG_DEBUG ("OL: Linking controllers successfull\n");
      GNUNET_TESTBED_operation_done (rhc->sub_op);
      rhc->sub_op = NULL;
      rhc->state = RHC_OL_CONNECT;
      GST_process_next_focc (rhc);
      break;
    default:
      GNUNET_assert (0);
    }
    return;
  }
  lcf = event->op_cls;
  if (CLOSURE_TYPE_LCF == lcf->type)
  {    
    GNUNET_assert (lcf->op == event->op);
    GNUNET_assert (FINISHED == lcf->state);
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK != lcf->timeout_task);
    GNUNET_SCHEDULER_cancel (lcf->timeout_task);
    if (NULL == event->details.operation_finished.emsg)
      send_controller_link_response (lcf->client, lcf->operation_id,
                                     GNUNET_TESTBED_host_get_cfg_ 
                                     (GST_host_list[lcf->delegated_host_id]),
                                     NULL);
    else
      send_controller_link_response (lcf->client, lcf->operation_id,
                                     NULL,
                                     event->details.operation_finished.emsg);
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == lcf_proc_task_id);
    lcf_proc_task_id = GNUNET_SCHEDULER_add_now (&lcf_proc_task, lcf);
    return;
  }
  GNUNET_assert (0);
}


/**
 * Callback to signal successfull startup of the controller process
 *
 * @param cls the handle to the slave whose status is to be found here
 * @param cfg the configuration with which the controller has been started;
 *          NULL if status is not GNUNET_OK
 * @param status GNUNET_OK if the startup is successfull; GNUNET_SYSERR if not,
 *          GNUNET_TESTBED_controller_stop() shouldn't be called in this case
 */
static void
slave_status_callback (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg,
                       int status)
{
  struct Slave *slave = cls;
  struct LinkControllersContext *lcc;

  lcc = slave->lcc;
  if (GNUNET_SYSERR == status)
  {
    slave->controller_proc = NULL;
    GST_slave_list[slave->host_id] = NULL;
    GNUNET_free (slave);
    slave = NULL;
    LOG (GNUNET_ERROR_TYPE_WARNING, "Unexpected slave shutdown\n");
    GNUNET_SCHEDULER_shutdown ();       /* We too shutdown */
    goto clean_lcc;
  }
  slave->controller =
      GNUNET_TESTBED_controller_connect (cfg, GST_host_list[slave->host_id],
                                         event_mask, &slave_event_callback,
                                         slave);
  if (NULL != slave->controller)
  {
    send_controller_link_response (lcc->client, lcc->operation_id, cfg, NULL);
  }
  else
  {
    send_controller_link_response (lcc->client, lcc->operation_id, NULL,
                                   "Could not connect to delegated controller");
    GNUNET_TESTBED_controller_stop (slave->controller_proc);
    GST_slave_list[slave->host_id] = NULL;
    GNUNET_free (slave);
    slave = NULL;
  }

clean_lcc:
  if (NULL != lcc)
  {
    if (NULL != lcc->client)
    {
      GNUNET_SERVER_receive_done (lcc->client, GNUNET_OK);
      GNUNET_SERVER_client_drop (lcc->client);
      lcc->client = NULL;
    }
    GNUNET_free (lcc);
  }
  if (NULL != slave)
    slave->lcc = NULL;
}


/**
 * Message handler for GNUNET_MESSAGE_TYPE_TESTBED_INIT messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_init (void *cls, struct GNUNET_SERVER_Client *client,
             const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TESTBED_InitMessage *msg;
  struct GNUNET_TESTBED_Host *host;
  const char *controller_hostname;
  uint16_t msize;

  if (NULL != GST_context)
  {
    LOG_DEBUG ("We are being connected to laterally\n");
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  msg = (const struct GNUNET_TESTBED_InitMessage *) message;
  msize = ntohs (message->size);
  if (msize <= sizeof (struct GNUNET_TESTBED_InitMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  msize -= sizeof (struct GNUNET_TESTBED_InitMessage);
  controller_hostname = (const char *) &msg[1];
  if ('\0' != controller_hostname[msize - 1])
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GST_context = GNUNET_malloc (sizeof (struct Context));
  GNUNET_SERVER_client_keep (client);
  GST_context->client = client;
  GST_context->host_id = ntohl (msg->host_id);
  GST_context->master_ip = GNUNET_strdup (controller_hostname);
  LOG_DEBUG ("Our IP: %s\n", GST_context->master_ip);
  GST_context->system =
      GNUNET_TESTING_system_create ("testbed", GST_context->master_ip,
                                    hostname);
  host =
      GNUNET_TESTBED_host_create_with_id (GST_context->host_id,
                                          GST_context->master_ip, NULL,
                                          our_config, 0);
  host_list_add (host);
  LOG_DEBUG ("Created master context with host ID: %u\n", GST_context->host_id);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Message handler for GNUNET_MESSAGE_TYPE_TESTBED_ADDHOST messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_add_host (void *cls, struct GNUNET_SERVER_Client *client,
                 const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_TESTBED_Host *host;
  const struct GNUNET_TESTBED_AddHostMessage *msg;
  struct GNUNET_TESTBED_HostConfirmedMessage *reply;
  struct GNUNET_CONFIGURATION_Handle *host_cfg;
  char *username;
  char *hostname;
  char *emsg;
  const void *ptr;
  uint32_t host_id;
  uint16_t username_length;
  uint16_t hostname_length;
  uint16_t reply_size;
  uint16_t msize;

  msg = (const struct GNUNET_TESTBED_AddHostMessage *) message;
  msize = ntohs (msg->header.size);
  if (msize <= sizeof (struct GNUNET_TESTBED_AddHostMessage))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  username_length = ntohs (msg->username_length);
  hostname_length = ntohs (msg->hostname_length);
  /* msg must contain hostname */
  if ((msize <= (sizeof (struct GNUNET_TESTBED_AddHostMessage) + 
                 username_length))
      || (0 == hostname_length))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  /* msg must contain configuration */
  if (msize <= (sizeof (struct GNUNET_TESTBED_AddHostMessage) +
                username_length + hostname_length))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  username = NULL;
  hostname = NULL;
  ptr = &msg[1];
  if (0 != username_length)
  {
    username = GNUNET_malloc (username_length + 1);
    strncpy (username, ptr, username_length);
    ptr += username_length;
  }
  hostname = GNUNET_malloc (hostname_length + 1);
  strncpy (hostname, ptr, hostname_length);
  ptr += hostname_length;
  if (NULL == (host_cfg = GNUNET_TESTBED_extract_config_ (message)))
  {
    GNUNET_free_non_null (username);
    GNUNET_free_non_null (hostname);
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  host_id = ntohl (msg->host_id);
  LOG_DEBUG ("Received ADDHOST %u message\n", host_id);
  LOG_DEBUG ("-------host id: %u\n", host_id);
  LOG_DEBUG ("-------hostname: %s\n", hostname);
  if (NULL != username)
    LOG_DEBUG ("-------username: %s\n", username);
  else
    LOG_DEBUG ("-------username: <not given>\n");
  LOG_DEBUG ("-------ssh port: %u\n", ntohs (msg->ssh_port));
  host =
      GNUNET_TESTBED_host_create_with_id (host_id, hostname, username,
                                          host_cfg, ntohs (msg->ssh_port));
  GNUNET_free_non_null (username);
  GNUNET_free (hostname);
  GNUNET_CONFIGURATION_destroy (host_cfg);
  if (NULL == host)
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  reply_size = sizeof (struct GNUNET_TESTBED_HostConfirmedMessage);
  if (GNUNET_OK != host_list_add (host))
  {
    /* We are unable to add a host */
    emsg = "A host exists with given host-id";
    LOG_DEBUG ("%s: %u", emsg, host_id);
    GNUNET_TESTBED_host_destroy (host);
    reply_size += strlen (emsg) + 1;
    reply = GNUNET_malloc (reply_size);
    memcpy (&reply[1], emsg, strlen (emsg) + 1);
  }
  else
  {
    LOG_DEBUG ("Added host %u at %u\n", host_id, GST_context->host_id);
    reply = GNUNET_malloc (reply_size);
  }
  reply->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_ADD_HOST_SUCCESS);
  reply->header.size = htons (reply_size);
  reply->host_id = htonl (host_id);
  GST_queue_message (client, &reply->header);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Iterator over hash map entries.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
int
ss_exists_iterator (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct SharedService *queried_ss = cls;
  struct SharedService *ss = value;

  if (0 == strcmp (ss->name, queried_ss->name))
    return GNUNET_NO;
  else
    return GNUNET_YES;
}


/**
 * Message handler for GNUNET_MESSAGE_TYPE_TESTBED_ADDHOST messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_configure_shared_service (void *cls, struct GNUNET_SERVER_Client *client,
                                 const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TESTBED_ConfigureSharedServiceMessage *msg;
  struct SharedService *ss;
  char *service_name;
  struct GNUNET_HashCode hash;
  uint16_t msg_size;
  uint16_t service_name_size;

  msg = (const struct GNUNET_TESTBED_ConfigureSharedServiceMessage *) message;
  msg_size = ntohs (message->size);
  if (msg_size <= sizeof (struct GNUNET_TESTBED_ConfigureSharedServiceMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  service_name_size =
      msg_size - sizeof (struct GNUNET_TESTBED_ConfigureSharedServiceMessage);
  service_name = (char *) &msg[1];
  if ('\0' != service_name[service_name_size - 1])
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  LOG_DEBUG ("Received service sharing request for %s, with %d peers\n",
             service_name, ntohl (msg->num_peers));
  if (ntohl (msg->host_id) != GST_context->host_id)
  {
    route_message (ntohl (msg->host_id), message);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  ss = GNUNET_malloc (sizeof (struct SharedService));
  ss->name = strdup (service_name);
  ss->num_shared = ntohl (msg->num_peers);
  GNUNET_CRYPTO_hash (ss->name, service_name_size, &hash);
  if (GNUNET_SYSERR ==
      GNUNET_CONTAINER_multihashmap_get_multiple (ss_map, &hash,
                                                  &ss_exists_iterator, ss))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Service %s already configured as a shared service. "
         "Ignoring service sharing request \n", ss->name);
    GNUNET_free (ss->name);
    GNUNET_free (ss);
    return;
  }
  GNUNET_CONTAINER_multihashmap_put (ss_map, &hash, ss,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
}


/**
 * Message handler for GNUNET_MESSAGE_TYPE_TESTBED_LCONTROLLERS message
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_link_controllers (void *cls, struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TESTBED_ControllerLinkRequest *msg;
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct LCFContextQueue *lcfq;
  struct Route *route;
  struct Route *new_route;
  uint32_t delegated_host_id;
  uint32_t slave_host_id;
  uint16_t msize;

  if (NULL == GST_context)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  msize = ntohs (message->size);
  if (sizeof (struct GNUNET_TESTBED_ControllerLinkRequest) >= msize)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  msg = (const struct GNUNET_TESTBED_ControllerLinkRequest *) message;
  delegated_host_id = ntohl (msg->delegated_host_id);
  if (delegated_host_id == GST_context->host_id)
  {
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_WARNING, "Trying to link ourselves\n");
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  if ((delegated_host_id >= GST_host_list_size) ||
      (NULL == GST_host_list[delegated_host_id]))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Delegated host %u not registered with us\n", delegated_host_id);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  slave_host_id = ntohl (msg->slave_host_id);
  if ((slave_host_id >= GST_host_list_size) ||
      (NULL == GST_host_list[slave_host_id]))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "Slave host %u not registered with us\n",
         slave_host_id);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  if (slave_host_id == delegated_host_id)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "Slave and delegated host are same\n");
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  cfg = GNUNET_TESTBED_extract_config_ (message); /* destroy cfg here or in lcfcontext */
  if (NULL == cfg)
  {
    GNUNET_break (0);         /* Configuration parsing error */
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  if (slave_host_id == GST_context->host_id)    /* Link from us */
  {
    struct Slave *slave;
    struct LinkControllersContext *lcc;

    if ((delegated_host_id < GST_slave_list_size) &&
        (NULL != GST_slave_list[delegated_host_id]))
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
    slave = GNUNET_malloc (sizeof (struct Slave));
    slave->host_id = delegated_host_id;
    slave->reghost_map = GNUNET_CONTAINER_multihashmap_create (100, GNUNET_NO);
    slave_list_add (slave);
    if (1 != msg->is_subordinate)
    {
      slave->controller =
          GNUNET_TESTBED_controller_connect (cfg, GST_host_list[slave->host_id],
                                             event_mask, &slave_event_callback,
                                             slave);
      if (NULL != slave->controller)
        send_controller_link_response (client,
                                       GNUNET_ntohll (msg->operation_id),
                                       NULL,
                                       NULL);
      else
        send_controller_link_response (client,
                                       GNUNET_ntohll (msg->operation_id),
                                       NULL,
                                       "Could not connect to delegated controller");
      GNUNET_SERVER_receive_done (client, GNUNET_OK);
      return;
    }
    lcc = GNUNET_malloc (sizeof (struct LinkControllersContext));
    lcc->operation_id = GNUNET_ntohll (msg->operation_id);
    GNUNET_SERVER_client_keep (client);
    lcc->client = client;
    slave->lcc = lcc;
    slave->controller_proc =
        GNUNET_TESTBED_controller_start (GST_context->master_ip,
                                         GST_host_list[slave->host_id], cfg,
                                         &slave_status_callback, slave);
    GNUNET_CONFIGURATION_destroy (cfg);
    new_route = GNUNET_malloc (sizeof (struct Route));
    new_route->dest = delegated_host_id;
    new_route->thru = GST_context->host_id;
    route_list_add (new_route);
    return;
  }

  /* Route the request */
  if (slave_host_id >= route_list_size)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "No route towards slave host");
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  lcfq = GNUNET_malloc (sizeof (struct LCFContextQueue));
  lcfq->lcf = GNUNET_malloc (sizeof (struct LCFContext));
  lcfq->lcf->type = CLOSURE_TYPE_LCF;
  lcfq->lcf->delegated_host_id = delegated_host_id;
  lcfq->lcf->slave_host_id = slave_host_id;
  route = GST_find_dest_route (slave_host_id);
  GNUNET_assert (NULL != route);        /* because we add routes carefully */
  GNUNET_assert (route->dest < GST_slave_list_size);
  GNUNET_assert (NULL != GST_slave_list[route->dest]);
  lcfq->lcf->cfg = cfg;
  lcfq->lcf->is_subordinate = msg->is_subordinate;
  lcfq->lcf->state = INIT;
  lcfq->lcf->operation_id = GNUNET_ntohll (msg->operation_id);
  lcfq->lcf->gateway = GST_slave_list[route->dest];
  GNUNET_SERVER_client_keep (client);
  lcfq->lcf->client = client;
  if (NULL == lcfq_head)
  {
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == lcf_proc_task_id);
    GNUNET_CONTAINER_DLL_insert_tail (lcfq_head, lcfq_tail, lcfq);
    lcf_proc_task_id = GNUNET_SCHEDULER_add_now (&lcf_proc_task, lcfq->lcf);
  }
  else
    GNUNET_CONTAINER_DLL_insert_tail (lcfq_head, lcfq_tail, lcfq);
  /* FIXME: Adding a new route should happen after the controllers are linked
   * successfully */
  if (1 != msg->is_subordinate)
  {
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  if ((delegated_host_id < route_list_size) &&
      (NULL != route_list[delegated_host_id]))
  {
    GNUNET_break_op (0);        /* Are you trying to link delegated host twice
                                 * with is subordinate flag set to GNUNET_YES? */
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  new_route = GNUNET_malloc (sizeof (struct Route));
  new_route->dest = delegated_host_id;
  new_route->thru = route->dest;
  route_list_add (new_route);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handler for GNUNET_MESSAGE_TYPE_TESTBED_GETSLAVECONFIG messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_slave_get_config (void *cls, struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_TESTBED_SlaveGetConfigurationMessage *msg;
  struct Slave *slave;
  struct GNUNET_TESTBED_SlaveConfiguration *reply;
  const struct GNUNET_CONFIGURATION_Handle *cfg;
  char *config;
  char *xconfig;
  size_t config_size;
  size_t xconfig_size;
  size_t reply_size;
  uint64_t op_id;
  uint32_t slave_id;

  msg = (struct GNUNET_TESTBED_SlaveGetConfigurationMessage *) message;
  slave_id = ntohl (msg->slave_id);
  op_id = GNUNET_ntohll (msg->operation_id);
  if ((GST_slave_list_size <= slave_id) || (NULL == GST_slave_list[slave_id]))
  {
    /* FIXME: Add forwardings for this type of message here.. */
    GST_send_operation_fail_msg (client, op_id, "Slave not found");
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  slave = GST_slave_list[slave_id];
  GNUNET_assert (NULL != (cfg = GNUNET_TESTBED_host_get_cfg_ (GST_host_list[slave->host_id])));
  config = GNUNET_CONFIGURATION_serialize (cfg, &config_size);
  xconfig_size =
      GNUNET_TESTBED_compress_config_ (config, config_size, &xconfig);
  GNUNET_free (config);
  reply_size = xconfig_size + sizeof (struct GNUNET_TESTBED_SlaveConfiguration);
  GNUNET_break (reply_size <= UINT16_MAX);
  GNUNET_break (config_size <= UINT16_MAX);
  reply = GNUNET_realloc (xconfig, reply_size);
  (void) memmove (&reply[1], reply, xconfig_size);
  reply->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_SLAVE_CONFIGURATION);
  reply->header.size = htons ((uint16_t) reply_size);
  reply->slave_id = msg->slave_id;
  reply->operation_id = msg->operation_id;
  reply->config_size = htons ((uint16_t) config_size);
  GST_queue_message (client, &reply->header);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Clears the forwarded operations queue
 */
void
GST_clear_fopcq ()
{
  struct ForwardedOperationContext *fopc;
  
  while (NULL != (fopc = fopcq_head))
  {
    GNUNET_CONTAINER_DLL_remove (fopcq_head, fopcq_tail, fopc);
    GNUNET_TESTBED_forward_operation_msg_cancel_ (fopc->opc);
    if (GNUNET_SCHEDULER_NO_TASK != fopc->timeout_task)
      GNUNET_SCHEDULER_cancel (fopc->timeout_task);
    GNUNET_SERVER_client_drop (fopc->client);
    switch (fopc->type)
    {
    case OP_PEER_CREATE:
      GNUNET_free (fopc->cls);
      break;
    case OP_SHUTDOWN_PEERS:
      {
        struct HandlerContext_ShutdownPeers *hc = fopc->cls;
        
        GNUNET_assert (0 < hc->nslaves);
        hc->nslaves--;
        if (0 == hc->nslaves)
          GNUNET_free (hc);
      }
      break;
    case OP_PEER_START:
    case OP_PEER_STOP:
    case OP_PEER_DESTROY:
    case OP_PEER_INFO:
    case OP_OVERLAY_CONNECT:
    case OP_LINK_CONTROLLERS:
    case OP_GET_SLAVE_CONFIG:
    case OP_MANAGE_SERVICE:
      break;
    case OP_FORWARDED:
      GNUNET_assert (0);
    };
    GNUNET_free (fopc);
  }
}


/**
 * Iterator over hash map entries.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
static int
ss_map_free_iterator (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct SharedService *ss = value;

  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (ss_map, key, value));
  GNUNET_free (ss->name);
  GNUNET_free (ss);
  return GNUNET_YES;
}


/**
 * Iterator for freeing hash map entries in a slave's reghost_map
 *
 * @param cls handle to the slave
 * @param key current key code
 * @param value value in the hash map
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
static int
reghost_free_iterator (void *cls, const struct GNUNET_HashCode *key,
                       void *value)
{
  struct Slave *slave = cls;
  struct RegisteredHostContext *rhc = value;
  struct ForwardedOverlayConnectContext *focc;

  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (slave->reghost_map, key,
                                                       value));
  while (NULL != (focc = rhc->focc_dll_head))
  {
    GNUNET_CONTAINER_DLL_remove (rhc->focc_dll_head, rhc->focc_dll_tail, focc);
    GST_cleanup_focc (focc);
  }
  if (NULL != rhc->sub_op)
    GNUNET_TESTBED_operation_done (rhc->sub_op);
  if (NULL != rhc->client)
    GNUNET_SERVER_client_drop (rhc->client);
  GNUNET_free (value);
  return GNUNET_YES;
}


/**
 * Task to clean up and shutdown nicely
 *
 * @param cls NULL
 * @param tc the TaskContext from scheduler
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct LCFContextQueue *lcfq;
  struct MessageQueue *mq_entry;
  uint32_t id;

  shutdown_task_id = GNUNET_SCHEDULER_NO_TASK;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Shutting down testbed service\n");
  (void) GNUNET_CONTAINER_multihashmap_iterate (ss_map, &ss_map_free_iterator,
                                                NULL);
  GNUNET_CONTAINER_multihashmap_destroy (ss_map);
  /* cleanup any remaining forwarded operations */
  GST_clear_fopcq ();
  if (NULL != lcfq_head)
  {
    if (GNUNET_SCHEDULER_NO_TASK != lcf_proc_task_id)
    {
      GNUNET_SCHEDULER_cancel (lcf_proc_task_id);
      lcf_proc_task_id = GNUNET_SCHEDULER_NO_TASK;
    }
  }
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == lcf_proc_task_id);
  for (lcfq = lcfq_head; NULL != lcfq; lcfq = lcfq_head)
  {
    GNUNET_SERVER_client_drop (lcfq->lcf->client);
    GNUNET_assert (NULL != lcfq->lcf->cfg);
    GNUNET_CONFIGURATION_destroy (lcfq->lcf->cfg);
    GNUNET_free (lcfq->lcf);
    GNUNET_CONTAINER_DLL_remove (lcfq_head, lcfq_tail, lcfq);
    GNUNET_free (lcfq);
  }
  GST_free_mctxq ();
  GST_free_occq ();
  GST_free_roccq ();
  /* Clear peer list */
  GST_destroy_peers ();
  /* Clear host list */
  for (id = 0; id < GST_host_list_size; id++)
    if (NULL != GST_host_list[id])
      GNUNET_TESTBED_host_destroy (GST_host_list[id]);
  GNUNET_free_non_null (GST_host_list);
  /* Clear route list */
  for (id = 0; id < route_list_size; id++)
    if (NULL != route_list[id])
      GNUNET_free (route_list[id]);
  GNUNET_free_non_null (route_list);
  /* Clear GST_slave_list */
  for (id = 0; id < GST_slave_list_size; id++)
    if (NULL != GST_slave_list[id])
    {
      struct HostRegistration *hr_entry;

      while (NULL != (hr_entry = GST_slave_list[id]->hr_dll_head))
      {
        GNUNET_CONTAINER_DLL_remove (GST_slave_list[id]->hr_dll_head,
                                     GST_slave_list[id]->hr_dll_tail, hr_entry);
        GNUNET_free (hr_entry);
      }
      if (NULL != GST_slave_list[id]->rhandle)
        GNUNET_TESTBED_cancel_registration (GST_slave_list[id]->rhandle);
      (void)
          GNUNET_CONTAINER_multihashmap_iterate (GST_slave_list
                                                 [id]->reghost_map,
                                                 reghost_free_iterator,
                                                 GST_slave_list[id]);
      GNUNET_CONTAINER_multihashmap_destroy (GST_slave_list[id]->reghost_map);
      if (NULL != GST_slave_list[id]->controller)
        GNUNET_TESTBED_controller_disconnect (GST_slave_list[id]->controller);
      if (NULL != GST_slave_list[id]->controller_proc)
        GNUNET_TESTBED_controller_stop (GST_slave_list[id]->controller_proc);
      GNUNET_free (GST_slave_list[id]);
    }
  GNUNET_free_non_null (GST_slave_list);
  if (NULL != GST_context)
  {
    GNUNET_free_non_null (GST_context->master_ip);
    if (NULL != GST_context->system)
      GNUNET_TESTING_system_destroy (GST_context->system, GNUNET_YES);
    GNUNET_SERVER_client_drop (GST_context->client);
    GNUNET_free (GST_context);
    GST_context = NULL;
  }
  if (NULL != transmit_handle)
    GNUNET_SERVER_notify_transmit_ready_cancel (transmit_handle);
  while (NULL != (mq_entry = mq_head))
  {
    GNUNET_free (mq_entry->msg);
    GNUNET_SERVER_client_drop (mq_entry->client);
    GNUNET_CONTAINER_DLL_remove (mq_head, mq_tail, mq_entry);
    GNUNET_free (mq_entry);
  }
  GNUNET_free_non_null (hostname);
  GNUNET_CONFIGURATION_destroy (our_config);
  /* Free hello cache */
  GST_cache_clear ();
  GNUNET_TESTBED_operation_queue_destroy_ (GST_opq_openfds);
  GST_opq_openfds = NULL;
  GST_stats_destroy ();
}


/**
 * Callback for client disconnect
 *
 * @param cls NULL
 * @param client the client which has disconnected
 */
static void
client_disconnect_cb (void *cls, struct GNUNET_SERVER_Client *client)
{
  if (NULL == GST_context)
    return;
  if (client == GST_context->client)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Master client disconnected\n");
    /* should not be needed as we're terminated by failure to read
     * from stdin, but if stdin fails for some reason, this shouldn't
     * hurt for now --- might need to revise this later if we ever
     * decide that master connections might be temporarily down
     * for some reason */
    //GNUNET_SCHEDULER_shutdown ();
  }
}


/**
 * Testbed setup
 *
 * @param cls closure
 * @param server the initialized server
 * @param cfg configuration to use
 */
static void
testbed_run (void *cls, struct GNUNET_SERVER_Handle *server,
             const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  static const struct GNUNET_SERVER_MessageHandler message_handlers[] = {
    {&handle_init, NULL, GNUNET_MESSAGE_TYPE_TESTBED_INIT, 0},
    {&handle_add_host, NULL, GNUNET_MESSAGE_TYPE_TESTBED_ADD_HOST, 0},
    {&handle_configure_shared_service, NULL,
     GNUNET_MESSAGE_TYPE_TESTBED_SHARE_SERVICE, 0},
    {&handle_link_controllers, NULL,
     GNUNET_MESSAGE_TYPE_TESTBED_LINK_CONTROLLERS, 0},
    {&GST_handle_peer_create, NULL, GNUNET_MESSAGE_TYPE_TESTBED_CREATE_PEER, 0},
    {&GST_handle_peer_destroy, NULL, GNUNET_MESSAGE_TYPE_TESTBED_DESTROY_PEER,
     sizeof (struct GNUNET_TESTBED_PeerDestroyMessage)},
    {&GST_handle_peer_start, NULL, GNUNET_MESSAGE_TYPE_TESTBED_START_PEER,
     sizeof (struct GNUNET_TESTBED_PeerStartMessage)},
    {&GST_handle_peer_stop, NULL, GNUNET_MESSAGE_TYPE_TESTBED_STOP_PEER,
     sizeof (struct GNUNET_TESTBED_PeerStopMessage)},
    {&GST_handle_peer_get_config, NULL,
     GNUNET_MESSAGE_TYPE_TESTBED_GET_PEER_CONFIGURATION,
     sizeof (struct GNUNET_TESTBED_PeerGetConfigurationMessage)},
    {&GST_handle_overlay_connect, NULL,
     GNUNET_MESSAGE_TYPE_TESTBED_OVERLAY_CONNECT,
     sizeof (struct GNUNET_TESTBED_OverlayConnectMessage)},
    {&GST_handle_remote_overlay_connect, NULL,
     GNUNET_MESSAGE_TYPE_TESTBED_REMOTE_OVERLAY_CONNECT, 0},
    {&GST_handle_manage_peer_service, NULL,
     GNUNET_MESSAGE_TYPE_TESTBED_MANAGE_PEER_SERVICE, 0},
    {&handle_slave_get_config, NULL,
     GNUNET_MESSAGE_TYPE_TESTBED_GET_SLAVE_CONFIGURATION,
     sizeof (struct GNUNET_TESTBED_SlaveGetConfigurationMessage)},
    {&GST_handle_shutdown_peers, NULL, GNUNET_MESSAGE_TYPE_TESTBED_SHUTDOWN_PEERS,
     sizeof (struct GNUNET_TESTBED_ShutdownPeersMessage)},
    {NULL}
  };
  char *logfile;
  unsigned long long num;

  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_filename (cfg, "TESTBED", "LOG_FILE",
                                               &logfile))
  {
    GNUNET_break (GNUNET_OK == GNUNET_log_setup ("testbed", "DEBUG", logfile));
    GNUNET_free (logfile);
  }
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_number (cfg, "TESTBED",
                                                        "CACHE_SIZE", &num));
  GST_cache_init ((unsigned int) num);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_number (cfg, "TESTBED",
                                                        "MAX_OPEN_FDS", &num));
  GST_opq_openfds = GNUNET_TESTBED_operation_queue_create_ ((unsigned int) num);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_time (cfg, "TESTBED",
                                                      "OPERATION_TIMEOUT",
                                                      (struct
                                                       GNUNET_TIME_Relative *)
                                                      &GST_timeout));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_string (cfg, "testbed",
                                                        "HOSTNAME", &hostname));
  our_config = GNUNET_CONFIGURATION_dup (cfg);
  GNUNET_SERVER_add_handlers (server, message_handlers);
  GNUNET_SERVER_disconnect_notify (server, &client_disconnect_cb, NULL);
  ss_map = GNUNET_CONTAINER_multihashmap_create (5, GNUNET_NO);
  shutdown_task_id =
      GNUNET_SCHEDULER_add_delayed_with_priority (GNUNET_TIME_UNIT_FOREVER_REL,
                                                  GNUNET_SCHEDULER_PRIORITY_IDLE,
                                                  &shutdown_task, NULL);
  LOG_DEBUG ("Testbed startup complete\n");
  event_mask = 1LL << GNUNET_TESTBED_ET_OPERATION_FINISHED;
  GST_stats_init (our_config);
}


/**
 * The starting point of execution
 */
int
main (int argc, char *const *argv)
{
  //sleep (15);                 /* Debugging */
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "testbed", GNUNET_SERVICE_OPTION_NONE,
                              &testbed_run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-testbed.c */
