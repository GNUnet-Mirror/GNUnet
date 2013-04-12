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
 * @file testbed/gnunet-service-testbed_links.c
 * @brief TESTBED service components that deals with starting slave controllers
 *          and establishing lateral links between controllers
 * @author Sree Harsha Totakura
 */

#include "gnunet-service-testbed.h"

/**
 * Redefine LOG with a changed log component string
 */
#ifdef LOG
#undef LOG
#endif
#define LOG(kind,...)                                   \
  GNUNET_log_from (kind, "testbed-links", __VA_ARGS__)

/**
 * The event mask for the events we listen from sub-controllers
 */
#define EVENT_MASK (1LL << GNUNET_TESTBED_ET_OPERATION_FINISHED)


/**
 * States of LCFContext
 */
enum LCFContextState
{
  /**
   * The Context has been initialized; Nothing has been done on it
   */
  INIT,

  /**
   * Delegated host has been registered at the forwarding controller
   */
  DELEGATED_HOST_REGISTERED,

  /**
   * The slave host has been registred at the forwarding controller
   */
  SLAVE_HOST_REGISTERED,

  /**
   * The context has been finished (may have error)
   */
  FINISHED
};


/**
 * Link controllers request forwarding context
 */
struct LCFContext
{
  /**
   * The type of this data structure. Set this to CLOSURE_TYPE_LCF
   */
  enum ClosureType type;
  
  /**
   * The gateway which will pass the link message to delegated host
   */
  struct Slave *gateway;

  /**
   * The client which has asked to perform this operation
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Handle for operations which are forwarded while linking controllers
   */
  struct GNUNET_TESTBED_Operation *op;

  /**
   * The timeout task
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * The id of the operation which created this context
   */
  uint64_t operation_id;
  
  /**
   * should the slave controller start the delegated controller?
   */
  int is_subordinate;

  /**
   * The state of this context
   */
  enum LCFContextState state;

  /**
   * The delegated host
   */
  uint32_t delegated_host_id;

  /**
   * The slave host
   */
  uint32_t slave_host_id;

};


/**
 * Structure of a queue entry in LCFContext request queue
 */
struct LCFContextQueue
{
  /**
   * The LCFContext
   */
  struct LCFContext *lcf;

  /**
   * Head prt for DLL
   */
  struct LCFContextQueue *next;

  /**
   * Tail ptr for DLL
   */
  struct LCFContextQueue *prev;
};

struct NeighbourConnectNotification
{
  struct NeighbourConnectNotification *next;
  struct NeighbourConnectNotification *prev;
  struct Neighbour *n;
  GST_NeigbourConnectNotifyCallback cb;
  void *cb_cls;
};
  
/**
 * A connected controller which is not our child
 */
struct Neighbour
{
  /**
   * The controller handle
   */
  struct GNUNET_TESTBED_Controller *controller;
  
  /**
   * Operation handle for opening a lateral connection to another controller.
   * Will be NULL if the slave controller is started by this controller
   */
  struct GNUNET_TESTBED_Operation *conn_op;

  struct NeighbourConnectNotification *nl_head;

  struct NeighbourConnectNotification *nl_tail;

  GNUNET_SCHEDULER_TaskIdentifier notify_task;

  unsigned int reference_cnt;
  
  /**
   * The id of the host this controller is running on
   */
  uint32_t host_id;
  
  int8_t inactive;
};

static struct Neighbour **neighbour_list;
static unsigned int neighbour_list_size;

struct NeighbourConnectCtxt
{
  struct NeighbourConnectCtxt *next;
  struct NeighbourConnectCtxt *prev;
  struct Neighbour *n;
  struct GNUNET_SERVER_Client *client;
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;
  struct NeighbourConnectNotification *nh;
  uint64_t op_id;
};

struct NeighbourConnectCtxt *ncc_head;
struct NeighbourConnectCtxt *ncc_tail;

/**
 * A list of directly linked neighbours
 */
struct Slave **GST_slave_list;

/**
 * The size of directly linked neighbours list
 */
unsigned int GST_slave_list_size;

/**
 * A list of routes
 */
static struct Route **route_list;

/**
 * The head for the LCF queue
 */
static struct LCFContextQueue *lcfq_head;

/**
 * The tail for the LCF queue
 */
static struct LCFContextQueue *lcfq_tail;

/**
 * The lcf_task handle
 */
static GNUNET_SCHEDULER_TaskIdentifier lcf_proc_task_id;

/**
 * The size of the route list
 */
static unsigned int route_list_size;


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

static void
neighbour_list_add (struct Neighbour *n)
{
  if (n->host_id >= neighbour_list_size)
    GST_array_grow_large_enough (neighbour_list, neighbour_list_size, n->host_id);
  GNUNET_assert (NULL == neighbour_list[n->host_id]);
  neighbour_list[n->host_id] = n;
}


/**
 * Cleans up the route list
 */
void
GST_route_list_clear ()
{
  unsigned int id;
  
  for (id = 0; id < route_list_size; id++)
    if (NULL != route_list[id])
      GNUNET_free (route_list[id]);
  GNUNET_free_non_null (route_list);
  route_list = NULL;
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
 * Cleans up the slave list
 */
void
GST_slave_list_clear ()
{
  unsigned int id;
  struct HostRegistration *hr_entry;

  for (id = 0; id < GST_slave_list_size; id++)
    if (NULL != GST_slave_list[id])
    {
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
  GST_slave_list = NULL;
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
  {
    memcpy (&msg[1], xconfig, xconfig_size);
    GNUNET_free (xconfig);
  }
  if (NULL != emsg)
    memcpy (&msg[1], emsg, strlen (emsg));
  GST_queue_message (client, &msg->header);
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
 * @param cls NULL
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

static void
slave_status_callback (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg,
                       int status);

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
      GNUNET_TESTBED_controller_connect (GST_host_list[slave->host_id],
                                         EVENT_MASK, &slave_event_callback,
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

static void
neighbour_connect_notify_task (void *cls, 
                               const struct GNUNET_SCHEDULER_TaskContext *tc);

static void
trigger_notifications (struct Neighbour *n)
{
  GNUNET_assert (NULL != n->conn_op);
  if (NULL == n->nl_head)
    return;
  if (NULL == n->controller)
    return;
  if (GNUNET_SCHEDULER_NO_TASK != n->notify_task)
    return;
  n->notify_task = 
      GNUNET_SCHEDULER_add_now (&neighbour_connect_notify_task, n->nl_head);
}

static void
neighbour_connect_notify_task (void *cls, 
                               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct NeighbourConnectNotification *h = cls;
  struct Neighbour *n;

  n = h->n;  
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK != n->notify_task);  
  n->notify_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_assert (NULL != n->controller);
  GNUNET_CONTAINER_DLL_remove (n->nl_head, n->nl_tail, h);  
  trigger_notifications (n);
  if ((0 == n->reference_cnt) && (1 == n->inactive))
  {
    GNUNET_TESTBED_operation_activate_ (n->conn_op);
    n->inactive = 0;
  }
  n->reference_cnt++;
  h->cb (h->cb_cls, n->controller);
  GNUNET_free (h);
}

static void
opstart_neighbour_conn (void *cls)
{
  struct Neighbour *n = cls;
  
  GNUNET_assert (NULL != n->conn_op);
  GNUNET_assert (NULL == n->controller);
  LOG_DEBUG ("Opening connection to controller on host %u\n", n->host_id);
  n->controller = GNUNET_TESTBED_controller_connect (GST_host_list[n->host_id],
                                                     EVENT_MASK,
                                                     &slave_event_callback,
                                                     NULL);
  trigger_notifications (n);
}

static void
oprelease_neighbour_conn (void *cls)
{
   struct Neighbour *n = cls;

   GNUNET_assert (0 == n->reference_cnt);
   GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == n->notify_task);
   GNUNET_assert (NULL == n->nl_head);
   LOG_DEBUG ("Closing connection to controller on host %u\n", n->host_id);
   GNUNET_TESTBED_controller_disconnect (n->controller);
   n->controller = NULL;
   n->conn_op = NULL;
}

struct NeighbourConnectNotification *
GST_neighbour_get_connection (struct Neighbour *n,
                              GST_NeigbourConnectNotifyCallback cb,
                              void *cb_cls)
{
  struct NeighbourConnectNotification *h;

  GNUNET_assert (NULL != cb);
  LOG_DEBUG ("Attempting to get connection to controller on host %u\n",
             n->host_id);
  h = GNUNET_malloc (sizeof (struct NeighbourConnectNotification));
  h->n = n;
  h->cb  = cb;
  h->cb_cls = cb_cls;
  GNUNET_CONTAINER_DLL_insert_tail (n->nl_head, n->nl_tail, h);
  if (NULL == n->conn_op)
  {
    GNUNET_assert (NULL == n->controller);
    n->conn_op = GNUNET_TESTBED_operation_create_ (n, &opstart_neighbour_conn,
                                                   &oprelease_neighbour_conn);
    GNUNET_TESTBED_operation_queue_insert_ (GST_opq_openfds, n->conn_op);
    GNUNET_TESTBED_operation_begin_wait_ (n->conn_op);
    return h;
  }
  trigger_notifications (n);
  return h;
}

void
GST_neighbour_get_connection_cancel (struct NeighbourConnectNotification *h)
{
  struct Neighbour *n;
  
  n = h->n;
  if ((h == n->nl_head) && (GNUNET_SCHEDULER_NO_TASK != n->notify_task))
  {
    GNUNET_SCHEDULER_cancel (n->notify_task);
    n->notify_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_CONTAINER_DLL_remove (n->nl_head, n->nl_tail, h);
  GNUNET_free (h);
}

void
GST_neighbour_release_connection (struct Neighbour *n)
{
  GNUNET_assert (0 == n->inactive);
  GNUNET_assert (0 < n->reference_cnt);
  n->reference_cnt--;
  if (0 == n->reference_cnt)
  {
    GNUNET_TESTBED_operation_inactivate_ (n->conn_op);
    n->inactive = 1;
  }
}

static void
cleanup_ncc (struct NeighbourConnectCtxt *ncc)
{
  if (NULL != ncc->nh)
    GST_neighbour_get_connection_cancel (ncc->nh);
  if (GNUNET_SCHEDULER_NO_TASK != ncc->timeout_task)
    GNUNET_SCHEDULER_cancel (ncc->timeout_task);
  GNUNET_SERVER_client_drop (ncc->client);
  GNUNET_CONTAINER_DLL_remove (ncc_head, ncc_tail, ncc);
  GNUNET_free (ncc);
}

void
GST_neighbour_list_clean()
{
  struct Neighbour *n;
  unsigned int id;

  for (id = 0; id < neighbour_list_size; id++)
  {
    if (NULL == (n = neighbour_list[id]))
      continue;
    if (NULL != n->conn_op)
      GNUNET_TESTBED_operation_release_ (n->conn_op);
    GNUNET_free (n);
    neighbour_list[id] = NULL;
  }
  GNUNET_free_non_null (neighbour_list);
}

struct Neighbour *
GST_get_neighbour (uint32_t id)
{
  if (neighbour_list_size <= id)
    return NULL;
  else
    return neighbour_list[id];
}

void
GST_free_nccq ()
{
  while (NULL != ncc_head)
    cleanup_ncc (ncc_head);
}

static void
timeout_neighbour_connect (void *cls, 
                           const struct GNUNET_SCHEDULER_TaskContext *tc)
{
 struct NeighbourConnectCtxt *ncc = cls;

 ncc->timeout_task = GNUNET_SCHEDULER_NO_TASK;
 send_controller_link_response (ncc->client, ncc->op_id, NULL,
                                "Could not connect to delegated controller");
 cleanup_ncc (ncc);
}

static void
neighbour_connect_cb (void *cls, struct GNUNET_TESTBED_Controller *c)
{
  struct NeighbourConnectCtxt *ncc = cls;

  GNUNET_SCHEDULER_cancel (ncc->timeout_task);
  ncc->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  ncc->nh = NULL;
  GST_neighbour_release_connection (ncc->n);
  send_controller_link_response (ncc->client, ncc->op_id, NULL, NULL);
  cleanup_ncc (ncc);
}

/**
 * Message handler for GNUNET_MESSAGE_TYPE_TESTBED_LCONTROLLERS message
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
void
GST_handle_link_controllers (void *cls, struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TESTBED_ControllerLinkRequest *msg;
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct LCFContextQueue *lcfq;
  struct Route *route;
  struct Route *new_route;
  uint64_t op_id;
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
  GNUNET_CONFIGURATION_destroy (cfg);
  cfg = NULL;
  op_id = GNUNET_ntohll (msg->operation_id);
  if (slave_host_id == GST_context->host_id)    /* Link from us */
  {
    struct Slave *slave;
    struct LinkControllersContext *lcc;

    
    if (1 != msg->is_subordinate)
    {
      struct Neighbour *n;
      struct NeighbourConnectCtxt *ncc;

      if ((delegated_host_id < neighbour_list_size) &&
        (NULL != neighbour_list[delegated_host_id]))
      {
        GNUNET_break (0);
        GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
        return;
      }
      LOG_DEBUG ("Received request to establish a link to host %u\n",
                 delegated_host_id);
      n = GNUNET_malloc (sizeof (struct Neighbour));
      n->host_id = delegated_host_id;
      neighbour_list_add (n);   /* just add; connect on-demand */
      ncc = GNUNET_malloc (sizeof (struct NeighbourConnectCtxt));
      ncc->n = n;
      ncc->op_id = op_id;
      ncc->client = client;
      GNUNET_SERVER_client_keep (client);      
      ncc->nh = GST_neighbour_get_connection (n, neighbour_connect_cb, ncc);
      ncc->timeout_task = GNUNET_SCHEDULER_add_delayed (GST_timeout,
                                                        &timeout_neighbour_connect,
                                                        ncc);
      GNUNET_CONTAINER_DLL_insert_tail (ncc_head, ncc_tail, ncc);      
      GNUNET_SERVER_receive_done (client, GNUNET_OK);
      return;
    }
    if ((delegated_host_id < GST_slave_list_size) &&
        (NULL != GST_slave_list[delegated_host_id]))
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
    LOG_DEBUG ("Received request to start and establish a link to host %u\n",
               delegated_host_id);
    slave = GNUNET_malloc (sizeof (struct Slave));
    slave->host_id = delegated_host_id;
    slave->reghost_map = GNUNET_CONTAINER_multihashmap_create (100, GNUNET_NO);
    slave_list_add (slave);
    lcc = GNUNET_malloc (sizeof (struct LinkControllersContext));
    lcc->operation_id = op_id;
    GNUNET_SERVER_client_keep (client);
    lcc->client = client;
    slave->lcc = lcc;
    slave->controller_proc =
        GNUNET_TESTBED_controller_start (GST_context->master_ip,
                                         GST_host_list[slave->host_id],
                                         &slave_status_callback, slave);
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
  lcfq->lcf->is_subordinate = msg->is_subordinate;
  lcfq->lcf->state = INIT;
  lcfq->lcf->operation_id = op_id;
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
 * Cleans up the queue used for forwarding link controllers requests
 */
void
GST_free_lcfq ()
{
  struct LCFContextQueue *lcfq;
  
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
    GNUNET_free (lcfq->lcf);
    GNUNET_CONTAINER_DLL_remove (lcfq_head, lcfq_tail, lcfq);
    GNUNET_free (lcfq);
  }
}
