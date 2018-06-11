/*
  This file is part of GNUnet.
  Copyright (C) 2008--2013 GNUnet e.V.

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
   * The LCFContext
   */
  struct LCFContext *next;

  /**
   * The LCFContext
   */
  struct LCFContext *prev;

  /**
   * The gateway which will pass the link message to delegated host
   */
  struct Slave *gateway;

  /**
   * The client which has asked to perform this operation
   */
  struct GNUNET_SERVICE_Client *client;

  /**
   * Handle for operations which are forwarded while linking controllers
   */
  struct GNUNET_TESTBED_Operation *op;

  /**
   * The timeout task
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

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
 * Notification context to be used to notify when connection to the neighbour's
 * controller is opened
 */
struct NeighbourConnectNotification
{
  /**
   * DLL next for inclusion in neighbour's list of notification requests
   */
  struct NeighbourConnectNotification *next;

  /**
   * DLL prev
   */
  struct NeighbourConnectNotification *prev;

  /**
   * The neighbour
   */
  struct Neighbour *n;

  /**
   * The notification callback to call when we are connect to neighbour
   */
  GST_NeigbourConnectNotifyCallback cb;

  /**
   * The closure for the above callback
   */
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

  /**
   * DLL head for the list of notification requests
   */
  struct NeighbourConnectNotification *nl_head;

  /**
   * DLL tail for the list of notification requests
   */
  struct NeighbourConnectNotification *nl_tail;

  /**
   * Task id for the task to call notifications from the notification list
   */
  struct GNUNET_SCHEDULER_Task * notify_task;

  /**
   * How many references are present currently to this neighbour's connection
   */
  unsigned int reference_cnt;

  /**
   * Is the conn_op inactivated?
   */
  unsigned int inactive;

  /**
   * The id of the host this controller is running on
   */
  uint32_t host_id;
};


/**
 * The neighbour list
 */
static struct Neighbour **neighbour_list;

/**
 * The size of the neighbour list
 */
static unsigned int neighbour_list_size;


/**
 * Context information for establishing a link to neighbour (Used is
 * GST_handle_link_controllers()
 */
struct NeighbourConnectCtxt
{
  /**
   * DLL next for inclusion in the corresponding context list
   */
  struct NeighbourConnectCtxt *next;

  /**
   * DLL tail
   */
  struct NeighbourConnectCtxt *prev;

  /**
   * The neighbour to whom connection should be made
   */
  struct Neighbour *n;

  /**
   * The client requesting the connection
   */
  struct GNUNET_SERVICE_Client *client;

  /**
   * Task to be run upon timeout
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

  /**
   * The notification handle associated with the neighbour's connection request
   */
  struct NeighbourConnectNotification *nh;

  /**
   * The id of the link-controllers operation responsible for creating this
   * context
   */
  uint64_t op_id;
};

/**
 * DLL head for the list of neighbour connect contexts
 */
struct NeighbourConnectCtxt *ncc_head;

/**
 * DLL tail for the list of neighbour connect contexts
 */
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
 * The LCF queue
 */
static struct LCFContext *lcf_head;

/**
 * The tail for the LCF queue
 */
static struct LCFContext *lcf_tail;

/**
 * The lcf_task handle
 */
static struct GNUNET_SCHEDULER_Task * lcf_proc_task_id;

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
    GST_array_grow_large_enough (GST_slave_list,
                                 GST_slave_list_size,
                                 slave->host_id);
  GNUNET_assert (NULL == GST_slave_list[slave->host_id]);
  GST_slave_list[slave->host_id] = slave;
}


/**
 * Clean up all forwarded operation overlay context matching the
 * client given in @a cls.
 *
 * @param cls a `struct GNUNET_SERVICE_Client *` to match
 * @param key unused
 * @param value the `struct RegisteredHostContext` to search for @a cls
 * @return #GNUNET_OK (continue iterating)
 */
static int
drop_client_entries (void *cls,
                     const struct GNUNET_HashCode *key,
                     void *value)
{
  struct GNUNET_SERVICE_Client *client = cls;
  struct RegisteredHostContext *rhc = value;
  struct ForwardedOverlayConnectContext *focc;
  struct ForwardedOverlayConnectContext *foccn;

  for (focc = rhc->focc_dll_head; NULL != focc; focc = foccn)
  {
    foccn = focc->next;
    if (focc->client == client)
      GST_cleanup_focc (focc);
  }
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
 * Add a neighbour to the neighbour list.  Grows the neighbour list
 * automatically.
 *
 * @param n the neighbour to add
 */
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
 * @return #GNUNET_YES if we should continue to iterate,
 *         #GNUNET_NO if not.
 */
static int
reghost_free_iterator (void *cls,
                       const struct GNUNET_HashCode *key,
                       void *value)
{
  struct Slave *slave = cls;
  struct RegisteredHostContext *rhc = value;
  struct ForwardedOverlayConnectContext *focc;

  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (slave->reghost_map, key,
                                                       value));
  while (NULL != (focc = rhc->focc_dll_head))
    GST_cleanup_focc (focc);
  GNUNET_free (value);
  return GNUNET_YES;
}


/**
 * Kill a #Slave object
 *
 * @param slave the #Slave object
 */
static void
kill_slave (struct Slave *slave)
{
  struct HostRegistration *hr_entry;

  while (NULL != (hr_entry = slave->hr_dll_head))
  {
    GNUNET_CONTAINER_DLL_remove (slave->hr_dll_head, slave->hr_dll_tail,
                                 hr_entry);
    GNUNET_free (hr_entry);
  }
  if (NULL != slave->rhandle)
    GNUNET_TESTBED_cancel_registration (slave->rhandle);
  GNUNET_assert (GNUNET_SYSERR !=
                 GNUNET_CONTAINER_multihashmap_iterate (slave->reghost_map,
                                                        reghost_free_iterator,
                                                        slave));
  GNUNET_CONTAINER_multihashmap_destroy (slave->reghost_map);
  if (NULL != slave->controller)
    GNUNET_TESTBED_controller_disconnect (slave->controller);
  if (NULL != slave->controller_proc)
  {
    LOG_DEBUG ("Stopping a slave\n");
    GNUNET_TESTBED_controller_kill_ (slave->controller_proc);
  }
}


/**
 * Destroy a #Slave object
 *
 * @param slave the #Slave object
 */
static void
destroy_slave (struct Slave *slave)
{
  if (NULL != slave->controller_proc)
  {
    GNUNET_TESTBED_controller_destroy_ (slave->controller_proc);
    LOG_DEBUG ("Slave stopped\n");
  }
  GST_slave_list[slave->host_id] = NULL;
  GNUNET_free (slave);
}


/**
 * Cleans up the slave list
 */
void
GST_slave_list_clear ()
{
  struct Slave *slave;
  unsigned int id;

  for (id = 0; id < GST_slave_list_size; id++)
  {
    slave = GST_slave_list[id];
    if (NULL == slave)
      continue;
    kill_slave (slave);
  }
  for (id = 0; id < GST_slave_list_size; id++)
  {
    slave = GST_slave_list[id];
    if (NULL == slave)
      continue;
    destroy_slave (slave);
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
send_controller_link_response (struct GNUNET_SERVICE_Client *client,
                               uint64_t operation_id,
                               const struct GNUNET_CONFIGURATION_Handle *cfg,
                               const char *emsg)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_TESTBED_ControllerLinkResponse *msg;
  char *xconfig;
  size_t config_size;
  size_t xconfig_size;
  uint16_t msize;

  GNUNET_assert ((NULL == cfg) || (NULL == emsg));
  xconfig = NULL;
  xconfig_size = 0;
  config_size = 0;
  msize = 0;
  if (NULL != cfg)
  {
    xconfig = GNUNET_TESTBED_compress_cfg_ (cfg,
                                            &config_size,
                                            &xconfig_size);
    msize += xconfig_size;
  }
  if (NULL != emsg)
    msize += strlen (emsg);
  env = GNUNET_MQ_msg_extra (msg,
                             msize,
                             GNUNET_MESSAGE_TYPE_TESTBED_LINK_CONTROLLERS_RESULT);
  if (NULL == emsg)
    msg->success = htons (GNUNET_YES);
  msg->operation_id = GNUNET_htonll (operation_id);
  msg->config_size = htons ((uint16_t) config_size);
  if (NULL != xconfig)
  {
    GNUNET_memcpy (&msg[1],
                   xconfig,
                   xconfig_size);
    GNUNET_free (xconfig);
  }
  if (NULL != emsg)
    GNUNET_memcpy (&msg[1],
                   emsg,
                   strlen (emsg));
  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (client),
                  env);
}


/**
 * The  Link Controller forwarding task
 *
 * @param cls the LCFContext
 */
static void
lcf_proc_task (void *cls);


/**
 * Completion callback for host registrations while forwarding Link Controller messages
 *
 * @param cls the LCFContext
 * @param emsg the error message; NULL if host registration is successful
 */
static void
lcf_proc_cc (void *cls,
             const char *emsg)
{
  struct LCFContext *lcf = cls;

  GNUNET_assert (NULL == lcf_proc_task_id);
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
  LOG (GNUNET_ERROR_TYPE_WARNING,
       "Host registration failed with message: %s\n",
       emsg);
  lcf->state = FINISHED;
  lcf_proc_task_id = GNUNET_SCHEDULER_add_now (&lcf_proc_task,
                                               lcf);
}


/**
 * The  Link Controller forwarding task
 *
 * @param cls the LCFContext
 */
static void
lcf_proc_task (void *cls);


/**
 * Task to free resources when forwarded link controllers has been timedout
 *
 * @param cls the LCFContext
 */
static void
lcf_forwarded_operation_timeout (void *cls)
{
  struct LCFContext *lcf = cls;

  lcf->timeout_task = NULL;
  //  GST_forwarded_operation_timeout (lcf->fopc, tc);
  LOG (GNUNET_ERROR_TYPE_WARNING,
       "A forwarded controller link operation has timed out\n");
  send_controller_link_response (lcf->client,
                                 lcf->operation_id,
                                 NULL,
                                 "A forwarded controller link operation has timed out\n");
  GNUNET_assert (NULL == lcf_proc_task_id);
  lcf_proc_task_id = GNUNET_SCHEDULER_add_now (&lcf_proc_task,
                                               lcf);
}


/**
 * The  Link Controller forwarding task
 *
 * @param cls the LCFContext
 */
static void
lcf_proc_task (void *cls)
{
  struct LCFContext *lcf = cls;

  lcf_proc_task_id = NULL;
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
                                              lcf->is_subordinate);
    lcf->timeout_task =
        GNUNET_SCHEDULER_add_delayed (GST_timeout,
                                      &lcf_forwarded_operation_timeout,
                                      lcf);
    lcf->state = FINISHED;
    break;
  case FINISHED:
    if (NULL != lcf->op)
      GNUNET_TESTBED_operation_done (lcf->op);
    GNUNET_CONTAINER_DLL_remove (lcf_head,
                                 lcf_tail,
                                 lcf);
    GNUNET_free (lcf);
    if (NULL != lcf_head)
      lcf_proc_task_id = GNUNET_SCHEDULER_add_now (&lcf_proc_task,
                                                   lcf_head);
  }
}


/**
 * Callback for event from slave controllers
 *
 * @param cls NULL
 * @param event information about the event
 */
static void
slave_event_cb (void *cls, const struct GNUNET_TESTBED_EventInformation *event)
{
  struct LCFContext *lcf;

  /* We currently only get here when working on LCFContexts */
  GNUNET_assert (GNUNET_TESTBED_ET_OPERATION_FINISHED == event->type);
  lcf = event->op_cls;
  GNUNET_assert (lcf->op == event->op);
  GNUNET_TESTBED_operation_done (lcf->op);
  lcf->op = NULL;
  GNUNET_assert (FINISHED == lcf->state);
  GNUNET_assert (NULL != lcf->timeout_task);
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
  GNUNET_assert (NULL == lcf_proc_task_id);
  lcf_proc_task_id = GNUNET_SCHEDULER_add_now (&lcf_proc_task, lcf);
  return;
}


/**
 * Callback to signal successfull startup of the controller process
 *
 * @param cls the handle to the slave whose status is to be found here
 * @param cfg the configuration with which the controller has been started;
 *          NULL if status is not #GNUNET_OK
 * @param status #GNUNET_OK if the startup is successfull; #GNUNET_SYSERR if not,
 *          GNUNET_TESTBED_controller_stop() shouldn't be called in this case
 */
static void
slave_status_cb (void *cls,
                 const struct GNUNET_CONFIGURATION_Handle *cfg,
                 int status)
{
  struct Slave *slave = cls;
  struct LinkControllersContext *lcc;

  lcc = slave->lcc;
  if (GNUNET_SYSERR == status)
  {
    slave->controller_proc = NULL;
    /* Stop all link controller forwarding tasks since we shutdown here anyway
       and as these tasks they depend on the operation queues which are created
       through GNUNET_TESTBED_controller_connect() and in kill_slave() we call
       the destructor function GNUNET_TESTBED_controller_disconnect() */
    GST_free_lcf ();
    kill_slave (slave);
    destroy_slave (slave);
    slave = NULL;
    LOG (GNUNET_ERROR_TYPE_WARNING, "Unexpected slave shutdown\n");
    GNUNET_SCHEDULER_shutdown ();       /* We too shutdown */
    goto clean_lcc;
  }
  slave->controller =
      GNUNET_TESTBED_controller_connect (GST_host_list[slave->host_id],
                                         EVENT_MASK, &slave_event_cb,
                                         slave);
  if (NULL != slave->controller)
  {
    send_controller_link_response (lcc->client, lcc->operation_id, cfg, NULL);
  }
  else
  {
    send_controller_link_response (lcc->client, lcc->operation_id, NULL,
                                   "Could not connect to delegated controller");
    kill_slave (slave);
    destroy_slave (slave);
    slave = NULL;
  }

 clean_lcc:
  if (NULL != lcc)
  {
    if (NULL != lcc->client)
    {
      GNUNET_SERVICE_client_continue (lcc->client);
      lcc->client = NULL;
    }
    GNUNET_free (lcc);
  }
  if (NULL != slave)
    slave->lcc = NULL;
}


/**
 * Trigger notification task if there are notification requests currently
 * waiting in the given neighbour.  Also activates the neighbour connect operation
 * if it was previously inactivated so that the connection to the neighbour can
 * be re-used
 *
 * @param n the neighbour
 */
static void
trigger_notifications (struct Neighbour *n);


/**
 * Task to call the notification queued in the notifications list of the given
 * neighbour
 *
 * @param cls the neighbour
 */
static void
neighbour_connect_notify_task (void *cls)
{
  struct Neighbour *n = cls;
  struct NeighbourConnectNotification *h;

  GNUNET_assert (NULL != (h = n->nl_head));
  GNUNET_assert (NULL != n->notify_task);
  n->notify_task = NULL;
  GNUNET_assert (NULL != n->controller);
  GNUNET_CONTAINER_DLL_remove (n->nl_head, n->nl_tail, h);
  trigger_notifications (n);
  h->cb (h->cb_cls, n->controller);
  GNUNET_free (h);
}


/**
 * Trigger notification task if there are notification requests currently
 * waiting in the given neighbour.  Also activates the neighbour connect operation
 * if it was previously inactivated so that the connection to the neighbour can
 * be re-used
 *
 * @param n the neighbour
 */
static void
trigger_notifications (struct Neighbour *n)
{
  GNUNET_assert (NULL != n->conn_op);
  if (NULL == n->nl_head)
    return;
  if (NULL == n->controller)
    return;
  if (NULL != n->notify_task)
    return;
  if (1 == n->inactive)
  {
    GNUNET_assert (0 == n->reference_cnt);
    GNUNET_TESTBED_operation_activate_ (n->conn_op);
    n->inactive = 0;
  }
  n->reference_cnt++;
  n->notify_task =
      GNUNET_SCHEDULER_add_now (&neighbour_connect_notify_task, n);
}


/**
 * Callback to be called when the neighbour connect operation is started.  The
 * connection to the neigbour is opened here and any pending notifications are
 * trigger.
 *
 * @param cls the neighbour
 */
static void
opstart_neighbour_conn (void *cls)
{
  struct Neighbour *n = cls;

  GNUNET_assert (NULL != n->conn_op);
  GNUNET_assert (NULL == n->controller);
  LOG_DEBUG ("Opening connection to controller on host %u\n", n->host_id);
  n->controller = GNUNET_TESTBED_controller_connect (GST_host_list[n->host_id],
                                                     EVENT_MASK,
                                                     &slave_event_cb,
                                                     NULL);
  trigger_notifications (n);
}


/**
 * Callback to be called when the neighbour connect operation is released
 *
 * @param cls the neighbour
 */
static void
oprelease_neighbour_conn (void *cls)
{
   struct Neighbour *n = cls;

   GNUNET_assert (0 == n->reference_cnt);
   GNUNET_assert (NULL == n->notify_task);
   GNUNET_assert (NULL == n->nl_head);
   if (NULL != n->controller)
   {
     LOG_DEBUG ("Closing connection to controller on host %u\n", n->host_id);
     GNUNET_TESTBED_controller_disconnect (n->controller);
     n->controller = NULL;
   }
   n->conn_op = NULL;
   n->inactive = 0;
}


/**
 * Try to open a connection to the given neigbour.  If the connection is open
 * already, then it is re-used.  If not, the request is queued in the operation
 * queues responsible for bounding the total number of file descriptors.  The
 * actual connection will happen when the operation queue marks the
 * corresponding operation as active.
 *
 * @param n the neighbour to open a connection to
 * @param cb the notification callback to call when the connection is opened
 * @param cb_cls the closure for the above callback
 */
struct NeighbourConnectNotification *
GST_neighbour_get_connection (struct Neighbour *n,
                              GST_NeigbourConnectNotifyCallback cb,
                              void *cb_cls)
{
  struct NeighbourConnectNotification *h;

  GNUNET_assert (NULL != cb);
  LOG_DEBUG ("Attempting to get connection to controller on host %u\n",
             n->host_id);
  h = GNUNET_new (struct NeighbourConnectNotification);
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


/**
 * Cancel the request for opening a connection to the neighbour
 *
 * @param h the notification handle
 */
void
GST_neighbour_get_connection_cancel (struct NeighbourConnectNotification *h)
{
  struct Neighbour *n;
  int cleanup_task;

  n = h->n;
  cleanup_task = (h == n->nl_head) ? GNUNET_YES : GNUNET_NO;
  GNUNET_CONTAINER_DLL_remove (n->nl_head, n->nl_tail, h);
  GNUNET_free (h);
  if (GNUNET_NO == cleanup_task)
    return;
  if (NULL == n->notify_task)
    return;
  GNUNET_assert (0 < n->reference_cnt);
  n->reference_cnt--;
  GNUNET_SCHEDULER_cancel (n->notify_task);
  n->notify_task = NULL;
  if (NULL == n->nl_head)
  {
    if ( (0 == n->reference_cnt) && (0 == n->inactive) )
    {
      n->inactive = 1;
      GNUNET_TESTBED_operation_inactivate_ (n->conn_op);
    }
    return;
  }
  trigger_notifications (n);
}


/**
 * Release the connection to the neighbour.  The actual connection will be
 * closed if connections to other neighbour are waiting (to maintain a bound on
 * the total number of connections that are open).
 *
 * @param n the neighbour whose connection can be closed
 */
void
GST_neighbour_release_connection (struct Neighbour *n)
{
  GNUNET_assert (0 == n->inactive);
  GNUNET_assert (0 < n->reference_cnt);
  n->reference_cnt--;
  if (0 == n->reference_cnt)
  {
    n->inactive = 1;
    GNUNET_TESTBED_operation_inactivate_ (n->conn_op);
  }
}


/**
 * Cleanup neighbour connect contexts
 *
 * @param ncc the neighbour connect context to cleanup
 */
static void
cleanup_ncc (struct NeighbourConnectCtxt *ncc)
{
  if (NULL != ncc->nh)
    GST_neighbour_get_connection_cancel (ncc->nh);
  if (NULL != ncc->timeout_task)
    GNUNET_SCHEDULER_cancel (ncc->timeout_task);
  GNUNET_CONTAINER_DLL_remove (ncc_head,
                               ncc_tail,
                               ncc);
  GNUNET_free (ncc);
}


/**
 * Cleans up the neighbour list
 */
void
GST_neighbour_list_clean ()
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


/**
 * Get a neighbour from the neighbour list
 *
 * @param id the index of the neighbour in the neighbour list
 * @return the Neighbour; NULL if the given index in invalid (index greater than
 *           the list size or neighbour at that index is NULL)
 */
struct Neighbour *
GST_get_neighbour (uint32_t id)
{
  if (neighbour_list_size <= id)
    return NULL;
  return neighbour_list[id];
}


/**
 * Function to cleanup the neighbour connect contexts
 */
void
GST_free_nccq ()
{
  while (NULL != ncc_head)
    cleanup_ncc (ncc_head);
}


/**
 * Task to be run upon timeout while attempting to connect to the neighbour
 *
 * @param cls the NeighbourConnectCtxt created in GST_handle_link_controllers()
 */
static void
timeout_neighbour_connect (void *cls)
{
 struct NeighbourConnectCtxt *ncc = cls;

 ncc->timeout_task = NULL;
 send_controller_link_response (ncc->client,
                                ncc->op_id,
                                NULL,
                                "Could not connect to delegated controller");
 cleanup_ncc (ncc);
}


/**
 * Callback called when a connection to the neighbour is made
 *
 * @param cls the NeighbourConnectCtxt created in GST_handle_link_controllers()
 * @param c the handle the neighbour's controller
 */
static void
neighbour_connect_cb (void *cls,
                      struct GNUNET_TESTBED_Controller *c)
{
  struct NeighbourConnectCtxt *ncc = cls;

  GNUNET_SCHEDULER_cancel (ncc->timeout_task);
  ncc->timeout_task = NULL;
  ncc->nh = NULL;
  GST_neighbour_release_connection (ncc->n);
  send_controller_link_response (ncc->client,
                                 ncc->op_id,
                                 NULL,
                                 NULL);
  cleanup_ncc (ncc);
}


/**
 * Function to create a neigbour and add it into the neighbour list
 *
 * @param host the host of the neighbour
 */
struct Neighbour *
GST_create_neighbour (struct GNUNET_TESTBED_Host *host)
{
  struct Neighbour *n;

  n = GNUNET_new (struct Neighbour);
  n->host_id = GNUNET_TESTBED_host_get_id_ (host);
  neighbour_list_add (n);   /* just add; connect on-demand */
  return n;
}


/**
 * Message handler for #GNUNET_MESSAGE_TYPE_TESTBED_LCONTROLLERS message
 *
 * @param cls identification of the client
 * @param msg the actual message
 */
void
handle_link_controllers (void *cls,
                         const struct GNUNET_TESTBED_ControllerLinkRequest *msg)
{
  struct GNUNET_SERVICE_Client *client = cls;
  struct LCFContext *lcf;
  struct Route *route;
  struct Route *new_route;
  uint64_t op_id;
  uint32_t delegated_host_id;
  uint32_t slave_host_id;

  if (NULL == GST_context)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (client);
    return;
  }
  delegated_host_id = ntohl (msg->delegated_host_id);
  if (delegated_host_id == GST_context->host_id)
  {
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Trying to link ourselves\n");
    GNUNET_SERVICE_client_drop (client);
    return;
  }
  if ((delegated_host_id >= GST_host_list_size) ||
      (NULL == GST_host_list[delegated_host_id]))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Delegated host %u not registered with us\n",
         delegated_host_id);
    GNUNET_SERVICE_client_drop (client);
    return;
  }
  slave_host_id = ntohl (msg->slave_host_id);
  if ((slave_host_id >= GST_host_list_size) ||
      (NULL == GST_host_list[slave_host_id]))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Slave host %u not registered with us\n",
         slave_host_id);
    GNUNET_SERVICE_client_drop (client);
    return;
  }
  if (slave_host_id == delegated_host_id)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Slave and delegated host are same\n");
    GNUNET_SERVICE_client_drop (client);
    return;
  }
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
        GNUNET_SERVICE_client_drop (client);
        return;
      }
      LOG_DEBUG ("Received request to establish a link to host %u\n",
                 delegated_host_id);
      n = GST_create_neighbour (GST_host_list[delegated_host_id]);
      ncc = GNUNET_new (struct NeighbourConnectCtxt);
      ncc->n = n;
      ncc->op_id = op_id;
      ncc->client = client;
      ncc->nh = GST_neighbour_get_connection (n,
                                              &neighbour_connect_cb,
                                              ncc);
      ncc->timeout_task
        = GNUNET_SCHEDULER_add_delayed (GST_timeout,
                                        &timeout_neighbour_connect,
                                        ncc);
      GNUNET_CONTAINER_DLL_insert_tail (ncc_head,
                                        ncc_tail,
                                        ncc);
      GNUNET_SERVICE_client_continue (client);
      return;
    }
    if ( (delegated_host_id < GST_slave_list_size) &&
         (NULL != GST_slave_list[delegated_host_id]) )
    {
      GNUNET_break (0);
      GNUNET_SERVICE_client_drop (client);
      return;
    }
    LOG_DEBUG ("Received request to start and establish a link to host %u\n",
               delegated_host_id);
    slave = GNUNET_new (struct Slave);
    slave->host_id = delegated_host_id;
    slave->reghost_map = GNUNET_CONTAINER_multihashmap_create (100,
                                                               GNUNET_NO);
    slave_list_add (slave);
    lcc = GNUNET_new (struct LinkControllersContext);
    lcc->operation_id = op_id;
    lcc->client = client;
    slave->lcc = lcc;
    slave->controller_proc
      = GNUNET_TESTBED_controller_start (GST_context->master_ip,
                                         GST_host_list[slave->host_id],
                                         &slave_status_cb,
                                         slave);
    new_route = GNUNET_new (struct Route);
    new_route->dest = delegated_host_id;
    new_route->thru = GST_context->host_id;
    route_list_add (new_route);
    return;
  }

  /* Route the request */
  if (slave_host_id >= route_list_size)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "No route towards slave host");
    GNUNET_SERVICE_client_drop (client);
    return;
  }
  lcf = GNUNET_new (struct LCFContext);
  lcf->delegated_host_id = delegated_host_id;
  lcf->slave_host_id = slave_host_id;
  route = GST_find_dest_route (slave_host_id);
  GNUNET_assert (NULL != route);        /* because we add routes carefully */
  GNUNET_assert (route->dest < GST_slave_list_size);
  GNUNET_assert (NULL != GST_slave_list[route->dest]);
  lcf->is_subordinate = msg->is_subordinate;
  lcf->state = INIT;
  lcf->operation_id = op_id;
  lcf->gateway = GST_slave_list[route->dest];
  lcf->client = client;
  if (NULL == lcf_head)
  {
    GNUNET_assert (NULL == lcf_proc_task_id);
    GNUNET_CONTAINER_DLL_insert_tail (lcf_head,
                                      lcf_tail,
                                      lcf);
    lcf_proc_task_id = GNUNET_SCHEDULER_add_now (&lcf_proc_task,
                                                 lcf);
  }
  else
  {
    GNUNET_CONTAINER_DLL_insert_tail (lcf_head,
                                      lcf_tail,
                                      lcf);
  }
  /* FIXME: Adding a new route should happen after the controllers are linked
   * successfully */
  if (1 != msg->is_subordinate)
  {
    GNUNET_SERVICE_client_continue (client);
    return;
  }
  if ( (delegated_host_id < route_list_size) &&
       (NULL != route_list[delegated_host_id]) )
  {
    GNUNET_break_op (0);        /* Are you trying to link delegated host twice
                                 * with is subordinate flag set to GNUNET_YES? */
    GNUNET_SERVICE_client_drop (client);
    return;
  }
  new_route = GNUNET_new (struct Route);
  new_route->dest = delegated_host_id;
  new_route->thru = route->dest;
  route_list_add (new_route);
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Clean up @a client handle if we stored any via #handle_link_controllers(),
 * the given client disconnected.
 *
 * @param client the client that is history
 */
void
GST_link_notify_disconnect (struct GNUNET_SERVICE_Client *client)
{
  struct NeighbourConnectCtxt *ncc;
  struct NeighbourConnectCtxt *nccn;
  struct LCFContext *lcf;
  struct LCFContext *lcfn;

  for (ncc = ncc_head; NULL != ncc; ncc = nccn)
  {
    nccn = ncc->next;
    if (ncc->client == client)
      cleanup_ncc (ncc);
  }
  for (unsigned int i=0;i<GST_slave_list_size;i++)
  {
    struct Slave *slave = GST_slave_list[i];
    struct LinkControllersContext *lcc;

    if (NULL == slave)
      continue;
    GNUNET_CONTAINER_multihashmap_iterate (slave->reghost_map,
                                           &drop_client_entries,
                                           client);
    lcc = slave->lcc;
    if (NULL == lcc)
      continue;
    if (lcc->client == client)
    {
      slave->lcc = NULL;
      GNUNET_free (lcc);
    }
  }
  for (lcf = lcf_head; NULL != lcf; lcf = lcfn)
  {
    lcfn = lcf->next;
    if ( (NULL != lcf) &&
         (client == lcf->client) )
    {
      if (NULL != lcf->op)
        GNUNET_TESTBED_operation_done (lcf->op);
      GNUNET_CONTAINER_DLL_remove (lcf_head,
                                   lcf_tail,
                                   lcf);
      GNUNET_free (lcf);
    }
  }
}


/**
 * Cleans up the queue used for forwarding link controllers requests
 */
void
GST_free_lcf ()
{
  struct LCFContext *lcf;

  if (NULL != lcf_head)
  {
    if (NULL != lcf_proc_task_id)
    {
      GNUNET_SCHEDULER_cancel (lcf_proc_task_id);
      lcf_proc_task_id = NULL;
    }
  }
  GNUNET_assert (NULL == lcf_proc_task_id);
  for (lcf = lcf_head; NULL != lcf; lcf = lcf_head)
  {
    if (NULL != lcf->op)
      GNUNET_TESTBED_operation_done (lcf->op);
    if (NULL != lcf->timeout_task)
      GNUNET_SCHEDULER_cancel (lcf->timeout_task);
    GNUNET_CONTAINER_DLL_remove (lcf_head,
                                 lcf_tail,
                                 lcf);
    GNUNET_free (lcf);
  }
}
