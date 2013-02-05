/*
  This file is part of GNUnet
  (C) 2008--2012 Christian Grothoff (and other contributing authors)

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
 * @file testbed/testbed_api_testbed.c
 * @brief high-level testbed management
 * @author Christian Grothoff
 * @author Sree Harsha Totakura
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"
#include "testbed_api_peers.h"
#include "testbed_api_hosts.h"
#include "testbed_api_topology.h"

/**
 * Generic loggins shorthand
 */
#define LOG(kind,...)                                           \
  GNUNET_log_from (kind, "testbed-api-testbed", __VA_ARGS__)

/**
 * Debug logging shortcut
 */
#define DEBUG(...)                              \
  LOG (GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__)

/**
 * DLL of operations
 */
struct DLLOperation
{
  /**
   * The testbed operation handle
   */
  struct GNUNET_TESTBED_Operation *op;

  /**
   * Context information for GNUNET_TESTBED_run()
   */
  struct RunContext *rc;

  /**
   * Closure
   */
  void *cls;

  /**
   * The next pointer for DLL
   */
  struct DLLOperation *next;

  /**
   * The prev pointer for DLL
   */
  struct DLLOperation *prev;
};


/**
 * States of RunContext
 */
enum State
{
  /**
   * Initial state
   */
  RC_INIT = 0,

  /**
   * Controllers on given hosts started and linked
   */
  RC_LINKED,

  /**
   * Peers are created
   */
  RC_PEERS_CREATED,

  /**
   * The testbed run is ready and the master callback can be called now. At this
   * time the peers are all started and if a topology is provided in the
   * configuration the topology would have been attempted
   */
  RC_READY,

  /**
   * Peers are stopped
   */
  RC_PEERS_STOPPED,

  /**
   * Peers are destroyed
   */
  RC_PEERS_DESTROYED
};


/**
 * Testbed Run Handle
 */
struct RunContext
{
  /**
   * The controller handle
   */
  struct GNUNET_TESTBED_Controller *c;

  /**
   * The configuration of the controller. This is based on the cfg given to the
   * function GNUNET_TESTBED_run(). We also use this config as a template while
   * for peers
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Handle to the host on which the controller runs
   */
  struct GNUNET_TESTBED_Host *h;

  /**
   * The handle to the controller process
   */
  struct GNUNET_TESTBED_ControllerProc *cproc;

  /**
   * The callback to use as controller callback
   */
  GNUNET_TESTBED_ControllerCallback cc;

  /**
   * The pointer to the controller callback
   */
  void *cc_cls;

  /**
   * The trusted IP string
   */
  char *trusted_ip;

  /**
   * TestMaster callback to call when testbed initialization is done
   */
  GNUNET_TESTBED_TestMaster test_master;

  /**
   * The closure for the TestMaster callback
   */
  void *test_master_cls;

  /**
   * The head element of DLL operations
   */
  struct DLLOperation *dll_op_head;

  /**
   * The tail element of DLL operations
   */
  struct DLLOperation *dll_op_tail;

  /**
   * An array of hosts loaded from the hostkeys file
   */
  struct GNUNET_TESTBED_Host **hosts;

  /**
   * The handle for whether a host is habitable or not
   */
  struct GNUNET_TESTBED_HostHabitableCheckHandle **hc_handles;

  /**
   * Array of peers which we create
   */
  struct GNUNET_TESTBED_Peer **peers;

  /**
   * The topology generation operation. Will be null if no topology is set in
   * the configuration
   */
  struct GNUNET_TESTBED_Operation *topology_operation;

  /**
   * The file containing topology data. Only used if the topology is set to 'FROM_FILE'
   */
  char *topo_file;

  /**
   * Host registration handle
   */
  struct GNUNET_TESTBED_HostRegistrationHandle *reg_handle;

  /**
   * Profiling start time
   */
  struct GNUNET_TIME_Absolute pstart_time;

  /**
   * Host registration task
   */
  GNUNET_SCHEDULER_TaskIdentifier register_hosts_task;

  /**
   * Task to be run while shutting down
   */
  GNUNET_SCHEDULER_TaskIdentifier shutdown_run_task;

  /**
   * The event mask for the controller
   */
  uint64_t event_mask;

  /**
   * State of this context
   */
  enum State state;

  /**
   * The topology which has to be achieved with the peers started in this context
   */
  enum GNUNET_TESTBED_TopologyOption topology;

  /**
   * Have we already shutdown
   */
  int shutdown;

  /**
   * Number of hosts in the given host file
   */
  unsigned int num_hosts;

  /**
   * Number of registered hosts. Also used as a counter while checking
   * habitabillity of hosts
   */
  unsigned int reg_hosts;

  /**
   * Current peer count for an operation; Set this to 0 and increment for each
   * successful operation on a peer
   */
  unsigned int peer_count;

  /**
   * number of peers to start
   */
  unsigned int num_peers;

  /**
   * counter to count overlay connect attempts. This counter includes both
   * successful and failed overlay connects
   */
  unsigned int oc_count;

  /**
   * Expected overlay connects. Should be zero if no topology is relavant
   */
  unsigned int num_oc;

  /**
   * Number of random links to established
   */
  unsigned int random_links;

};


/**
 * Function to return the string representation of the duration between current
 * time and `pstart_time' in `RunContext'
 *
 * @param rc the RunContext
 * @return the representation string; this is NOT reentrant
 */
static const char *
prof_time (struct RunContext *rc)
{
  struct GNUNET_TIME_Relative ptime;

  ptime = GNUNET_TIME_absolute_get_duration (rc->pstart_time);
  return GNUNET_STRINGS_relative_time_to_string (ptime, GNUNET_YES);
}


/**
 * Task for starting peers
 *
 * @param cls the RunHandle
 * @param tc the task context from scheduler
 */
static void
start_peers_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct RunContext *rc = cls;
  struct DLLOperation *dll_op;
  unsigned int peer;

  DEBUG ("Starting Peers\n");
  rc->pstart_time = GNUNET_TIME_absolute_get ();
  for (peer = 0; peer < rc->num_peers; peer++)
  {
    dll_op = GNUNET_malloc (sizeof (struct DLLOperation));
    dll_op->op = GNUNET_TESTBED_peer_start (NULL, rc->peers[peer], NULL, NULL);
    dll_op->cls = rc->peers[peer];
    GNUNET_CONTAINER_DLL_insert_tail (rc->dll_op_head, rc->dll_op_tail, dll_op);
  }
  rc->peer_count = 0;
}


/**
 * Functions of this signature are called when a peer has been successfully
 * created
 *
 * @param cls the closure from GNUNET_TESTBED_peer_create()
 * @param peer the handle for the created peer; NULL on any error during
 *          creation
 * @param emsg NULL if peer is not NULL; else MAY contain the error description
 */
static void
peer_create_cb (void *cls, struct GNUNET_TESTBED_Peer *peer, const char *emsg)
{
  struct DLLOperation *dll_op = cls;
  struct RunContext *rc;

  GNUNET_assert (NULL != dll_op);
  rc = dll_op->rc;
  GNUNET_assert (NULL != rc);
  GNUNET_CONTAINER_DLL_remove (rc->dll_op_head, rc->dll_op_tail, dll_op);
  GNUNET_TESTBED_operation_done (dll_op->op);
  GNUNET_free (dll_op);
  if (NULL == peer)
  {
    if (NULL != emsg)
      LOG (GNUNET_ERROR_TYPE_WARNING, "Error while creating a peer: %s\n",
           emsg);
    /* FIXME: GNUNET_TESTBED_shutdown_run()? */
    return;
  }
  rc->peers[rc->peer_count] = peer;
  rc->peer_count++;
  if (rc->peer_count < rc->num_peers)
    return;
  DEBUG ("%u peers created in %s\n", rc->num_peers, prof_time (rc));
  rc->state = RC_PEERS_CREATED;
  GNUNET_SCHEDULER_add_now (&start_peers_task, rc);
}


/**
 * Assuming all peers have been destroyed cleanup run handle
 *
 * @param cls the run handle
 * @param tc the task context from scheduler
 */
static void
cleanup_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct RunContext *rc = cls;
  struct DLLOperation *dll_op;
  unsigned int hid;

  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == rc->register_hosts_task);
  GNUNET_assert (NULL == rc->reg_handle);
  GNUNET_assert (NULL == rc->peers);
  GNUNET_assert (NULL == rc->hc_handles);
  GNUNET_assert (RC_PEERS_DESTROYED == rc->state);
  if (NULL != rc->dll_op_head)
  {                             /* cancel our pending operations */
    while (NULL != (dll_op = rc->dll_op_head))
    {
      GNUNET_TESTBED_operation_done (dll_op->op);
      GNUNET_CONTAINER_DLL_remove (rc->dll_op_head, rc->dll_op_tail, dll_op);
      GNUNET_free (dll_op);
    }
  }
  if (NULL != rc->c)
    GNUNET_TESTBED_controller_disconnect (rc->c);
  if (NULL != rc->cproc)
    GNUNET_TESTBED_controller_stop (rc->cproc);
  if (NULL != rc->h)
    GNUNET_TESTBED_host_destroy (rc->h);
  for (hid = 0; hid < rc->num_hosts; hid++)
    GNUNET_TESTBED_host_destroy (rc->hosts[hid]);
  GNUNET_free_non_null (rc->hosts);
  if (NULL != rc->cfg)
    GNUNET_CONFIGURATION_destroy (rc->cfg);
  GNUNET_free_non_null (rc->topo_file);
  GNUNET_free_non_null (rc->trusted_ip);
  GNUNET_free (rc);
}


/**
 * Stops the testbed run and releases any used resources
 *
 * @param cls the tesbed run handle
 * @param tc the task context from scheduler
 */
static void
shutdown_run (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Function to shutdown now
 *
 * @param rc the RunContext
 */
static void
shutdown_now (struct RunContext *rc)
{
  if (GNUNET_YES == rc->shutdown)
    return;
  if (GNUNET_SCHEDULER_NO_TASK != rc->shutdown_run_task)
    GNUNET_SCHEDULER_cancel (rc->shutdown_run_task);
  rc->shutdown_run_task = GNUNET_SCHEDULER_add_now (&shutdown_run, rc);
}


/**
 * Stops the testbed run and releases any used resources
 *
 * @param cls the tesbed run handle
 * @param tc the task context from scheduler
 */
static void
shutdown_run (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct RunContext *rc = cls;
  struct DLLOperation *dll_op;
  int all_peers_destroyed;
  unsigned int peer;
  unsigned int nhost;

  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK != rc->shutdown_run_task);
  rc->shutdown_run_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_assert (GNUNET_NO == rc->shutdown);
  rc->shutdown = GNUNET_YES;
  if (NULL != rc->hc_handles)
  {
    for (nhost = 0; nhost < rc->num_hosts; nhost++)
      if (NULL != rc->hc_handles[nhost])
        GNUNET_TESTBED_is_host_habitable_cancel (rc->hc_handles[nhost]);
    GNUNET_free (rc->hc_handles);
    rc->hc_handles = NULL;
  }
  /* Stop register hosts task if it is running */
  if (GNUNET_SCHEDULER_NO_TASK != rc->register_hosts_task)
  {
    GNUNET_SCHEDULER_cancel (rc->register_hosts_task);
    rc->register_hosts_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != rc->reg_handle)
  {
    GNUNET_TESTBED_cancel_registration (rc->reg_handle);
    rc->reg_handle = NULL;
  }
  if (NULL != rc->c)
  {
    if (NULL != rc->peers)
    {
      if (NULL != rc->topology_operation)
      {
        GNUNET_TESTBED_operation_done (rc->topology_operation);
        rc->topology_operation = NULL;
      }
      if (RC_INIT == rc->state)
        rc->state = RC_READY;   /* Even though we haven't called the master callback */
      rc->peer_count = 0;
      /* Check if some peers are stopped */
      for (peer = 0; peer < rc->num_peers; peer++)
      {
        if (NULL == rc->peers[peer])
          continue;
        if (PS_STOPPED != rc->peers[peer]->state)
          break;
      }
      if (peer == rc->num_peers)
      {
        /* All peers are stopped */
        rc->state = RC_PEERS_STOPPED;
        all_peers_destroyed = GNUNET_YES;
        for (peer = 0; peer < rc->num_peers; peer++)
        {
          if (NULL == rc->peers[peer])
            continue;
          all_peers_destroyed = GNUNET_NO;
          dll_op = GNUNET_malloc (sizeof (struct DLLOperation));
          dll_op->op = GNUNET_TESTBED_peer_destroy (rc->peers[peer]);
          GNUNET_CONTAINER_DLL_insert_tail (rc->dll_op_head, rc->dll_op_tail,
                                            dll_op);
        }
        if (all_peers_destroyed == GNUNET_NO)
        {
          DEBUG ("Destroying peers\n");
          rc->pstart_time = GNUNET_TIME_absolute_get ();
          return;
        }
      }
      /* Some peers are stopped */
      DEBUG ("Stopping peers\n");
      rc->pstart_time = GNUNET_TIME_absolute_get ();
      for (peer = 0; peer < rc->num_peers; peer++)
      {
        if ((NULL == rc->peers[peer]) || (PS_STARTED != rc->peers[peer]->state))
        {
          rc->peer_count++;
          continue;
        }
        dll_op = GNUNET_malloc (sizeof (struct DLLOperation));
        dll_op->op = GNUNET_TESTBED_peer_stop (rc->peers[peer], NULL, NULL);
        dll_op->cls = rc->peers[peer];
        GNUNET_CONTAINER_DLL_insert_tail (rc->dll_op_head, rc->dll_op_tail,
                                          dll_op);
      }
      if (rc->peer_count != rc->num_peers)
        return;
      GNUNET_free (rc->peers);
      rc->peers = NULL;
    }
  }
  rc->state = RC_PEERS_DESTROYED;       /* No peers are present so we consider the
                                         * state where all peers are destroyed  */
  GNUNET_SCHEDULER_add_now (&cleanup_task, rc);
}


/**
 * Task to call master task
 *
 * @param cls the run context
 * @param tc the task context
 */
static void
call_master (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct RunContext *rc = cls;

  if (NULL != rc->topology_operation)
  {
    DEBUG ("Overlay topology generated in %s\n", prof_time (rc));
    GNUNET_TESTBED_operation_done (rc->topology_operation);
    rc->topology_operation = NULL;
  }
  if (NULL != rc->test_master)
    rc->test_master (rc->test_master_cls, rc->num_peers, rc->peers);
}


/**
 * Function to create peers
 *
 * @param rc the RunContext
 */
static void
create_peers (struct RunContext *rc)
{
  struct DLLOperation *dll_op;
  unsigned int peer;

  DEBUG ("Creating peers\n");
  rc->pstart_time = GNUNET_TIME_absolute_get ();
  rc->peers =
      GNUNET_malloc (sizeof (struct GNUNET_TESTBED_Peer *) * rc->num_peers);
  GNUNET_assert (NULL != rc->c);
  rc->peer_count = 0;
  for (peer = 0; peer < rc->num_peers; peer++)
  {
    dll_op = GNUNET_malloc (sizeof (struct DLLOperation));
    dll_op->rc = rc;
    dll_op->op =
        GNUNET_TESTBED_peer_create (rc->c,
                                    (0 ==
                                     rc->num_hosts) ? rc->h : rc->hosts[peer %
                                                                        rc->num_hosts],
                                    rc->cfg, peer_create_cb, dll_op);
    GNUNET_CONTAINER_DLL_insert_tail (rc->dll_op_head, rc->dll_op_tail, dll_op);
  }
}


/**
 * Signature of the event handler function called by the
 * respective event controller.
 *
 * @param cls closure
 * @param event information about the event
 */
static void
event_cb (void *cls, const struct GNUNET_TESTBED_EventInformation *event)
{
  struct RunContext *rc = cls;
  struct DLLOperation *dll_op;
  unsigned int peer_id;

  if (RC_INIT == rc->state)
  {
    switch (event->type)
    {
    case GNUNET_TESTBED_ET_OPERATION_FINISHED:
      dll_op = event->details.operation_finished.op_cls;
      if (NULL != event->details.operation_finished.emsg)
      {
        LOG (GNUNET_ERROR_TYPE_ERROR, _("Linking controllers failed. Exiting"));
        shutdown_now (rc);
      }
      else
        rc->reg_hosts++;
      GNUNET_assert (event->details.operation_finished.operation == dll_op->op);
      GNUNET_CONTAINER_DLL_remove (rc->dll_op_head, rc->dll_op_tail, dll_op);
      GNUNET_TESTBED_operation_done (dll_op->op);
      GNUNET_free (dll_op);
      if (rc->reg_hosts == rc->num_hosts)
      {
        rc->state = RC_LINKED;
        create_peers (rc);
      }
      return;
    default:
      GNUNET_break (0);
      shutdown_now (rc);
      return;
    }
  }
  if (NULL != rc->topology_operation)
  {
    switch (event->type)
    {
    case GNUNET_TESTBED_ET_OPERATION_FINISHED:
    case GNUNET_TESTBED_ET_CONNECT:
      rc->oc_count++;
      break;
    default:
      GNUNET_break (0);
      shutdown_now (rc);
      return;
    }
    if (rc->oc_count == rc->num_oc)
    {
      rc->state = RC_READY;
      GNUNET_SCHEDULER_add_continuation (&call_master, rc,
                                         GNUNET_SCHEDULER_REASON_PREREQ_DONE);
    }
    goto call_cc;
  }
  for (dll_op = rc->dll_op_head; NULL != dll_op; dll_op = dll_op->next)
  {
    if ((GNUNET_TESTBED_ET_OPERATION_FINISHED == event->type) &&
        (event->details.operation_finished.operation == dll_op->op))
      break;
    if ((GNUNET_TESTBED_ET_PEER_STOP == event->type) &&
        (event->details.peer_stop.peer == dll_op->cls))
      break;
  }
  if (NULL == dll_op)
    goto call_cc;
  GNUNET_CONTAINER_DLL_remove (rc->dll_op_head, rc->dll_op_tail, dll_op);
  GNUNET_TESTBED_operation_done (dll_op->op);
  GNUNET_free (dll_op);
  rc->peer_count++;
  if (rc->peer_count < rc->num_peers)
    return;
  switch (rc->state)
  {
  case RC_PEERS_CREATED:
  case RC_READY:
    rc->state = RC_PEERS_STOPPED;
    DEBUG ("Peers stopped in %s\n", prof_time (rc));
    DEBUG ("Destroying peers\n");
    rc->pstart_time = GNUNET_TIME_absolute_get ();
    rc->peer_count = 0;
    for (peer_id = 0; peer_id < rc->num_peers; peer_id++)
    {
      dll_op = GNUNET_malloc (sizeof (struct DLLOperation));
      dll_op->op = GNUNET_TESTBED_peer_destroy (rc->peers[peer_id]);
      GNUNET_CONTAINER_DLL_insert_tail (rc->dll_op_head, rc->dll_op_tail,
                                        dll_op);
    }
    break;
  case RC_PEERS_STOPPED:
    rc->state = RC_PEERS_DESTROYED;
    GNUNET_free (rc->peers);
    rc->peers = NULL;
    DEBUG ("Peers destroyed in %s\n", prof_time (rc));
    GNUNET_SCHEDULER_add_now (&cleanup_task, rc);
    break;
  default:
    GNUNET_assert (0);
  }
  return;

call_cc:
  if ((0 != (rc->event_mask & (1LL << event->type))) && (NULL != rc->cc))
    rc->cc (rc->cc_cls, event);
  if (GNUNET_TESTBED_ET_PEER_START != event->type)
    return;
  for (dll_op = rc->dll_op_head; NULL != dll_op; dll_op = dll_op->next)
    if ((NULL != dll_op->cls) &&
        (event->details.peer_start.peer == dll_op->cls))
      break;
  if (NULL == dll_op)           /* Not our operation */
    return;
  GNUNET_CONTAINER_DLL_remove (rc->dll_op_head, rc->dll_op_tail, dll_op);
  GNUNET_TESTBED_operation_done (dll_op->op);
  GNUNET_free (dll_op);
  rc->peer_count++;
  if (rc->peer_count < rc->num_peers)
    return;
  DEBUG ("%u peers started in %s\n", rc->num_peers, prof_time (rc));
  if (GNUNET_TESTBED_TOPOLOGY_NONE != rc->topology)
  {
    if ((GNUNET_TESTBED_TOPOLOGY_ERDOS_RENYI == rc->topology) ||
        (GNUNET_TESTBED_TOPOLOGY_SMALL_WORLD_RING == rc->topology) ||
        (GNUNET_TESTBED_TOPOLOGY_SMALL_WORLD == rc->topology))
    {
      rc->topology_operation =
          GNUNET_TESTBED_overlay_configure_topology (NULL, rc->num_peers,
                                                     rc->peers, &rc->num_oc,
                                                     NULL,
                                                     NULL,
                                                     rc->topology,
                                                     rc->random_links,
                                                     GNUNET_TESTBED_TOPOLOGY_OPTION_END);
    }
    else if (GNUNET_TESTBED_TOPOLOGY_FROM_FILE == rc->topology)
    {
      GNUNET_assert (NULL != rc->topo_file);
      rc->topology_operation =
          GNUNET_TESTBED_overlay_configure_topology (NULL, rc->num_peers,
                                                     rc->peers, &rc->num_oc,
                                                     NULL,
                                                     NULL,
                                                     rc->topology,
                                                     rc->topo_file,
                                                     GNUNET_TESTBED_TOPOLOGY_OPTION_END);
    }
    else
      rc->topology_operation =
          GNUNET_TESTBED_overlay_configure_topology (NULL, rc->num_peers,
                                                     rc->peers, &rc->num_oc,
                                                     NULL,
                                                     NULL,
                                                     rc->topology,
                                                     GNUNET_TESTBED_TOPOLOGY_OPTION_END);
    if (NULL == rc->topology_operation)
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "Not generating topology. Check number of peers\n");
    else
    {
      DEBUG ("Creating overlay topology\n");
      rc->pstart_time = GNUNET_TIME_absolute_get ();
      return;
    }
  }
  rc->state = RC_READY;
  GNUNET_SCHEDULER_add_continuation (&call_master, rc,
                                     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
}


/**
 * Task to register all hosts available in the global host list
 *
 * @param cls the RunContext
 * @param tc the scheduler task context
 */
static void
register_hosts (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Callback which will be called to after a host registration succeeded or failed
 *
 * @param cls the closure
 * @param emsg the error message; NULL if host registration is successful
 */
static void
host_registration_completion (void *cls, const char *emsg)
{
  struct RunContext *rc = cls;

  rc->reg_handle = NULL;
  if (NULL != emsg)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("Host registration failed for a host. Error: %s\n"), emsg);
    shutdown_now (rc);
    return;
  }
  rc->register_hosts_task = GNUNET_SCHEDULER_add_now (&register_hosts, rc);
}


/**
 * Task to register all hosts available in the global host list
 *
 * @param cls RunContext
 * @param tc the scheduler task context
 */
static void
register_hosts (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct RunContext *rc = cls;
  struct DLLOperation *dll_op;
  unsigned int slave;

  rc->register_hosts_task = GNUNET_SCHEDULER_NO_TASK;
  if (rc->reg_hosts == rc->num_hosts)
  {
    DEBUG ("All hosts successfully registered\n");
    /* Start slaves */
    for (slave = 0; slave < rc->num_hosts; slave++)
    {
      dll_op = GNUNET_malloc (sizeof (struct DLLOperation));
      dll_op->rc = rc;
      dll_op->op =
          GNUNET_TESTBED_controller_link (dll_op, rc->c, rc->hosts[slave],
                                          rc->h, rc->cfg, GNUNET_YES);
      GNUNET_CONTAINER_DLL_insert_tail (rc->dll_op_head, rc->dll_op_tail,
                                        dll_op);
    }
    rc->reg_hosts = 0;
    return;
  }
  rc->reg_handle =
      GNUNET_TESTBED_register_host (rc->c, rc->hosts[rc->reg_hosts],
                                    host_registration_completion, rc);
  rc->reg_hosts++;
}


/**
 * Callback to signal successfull startup of the controller process
 *
 * @param cls the closure from GNUNET_TESTBED_controller_start()
 * @param cfg the configuration with which the controller has been started;
 *          NULL if status is not GNUNET_OK
 * @param status GNUNET_OK if the startup is successfull; GNUNET_SYSERR if not,
 *          GNUNET_TESTBED_controller_stop() shouldn't be called in this case
 */
static void
controller_status_cb (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg,
                      int status)
{
  struct RunContext *rc = cls;
  uint64_t event_mask;

  if (status != GNUNET_OK)
  {
    switch (rc->state)
    {
    case RC_INIT:
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Testbed startup failed\n");
      return;
    default:
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Controller crash detected. Shutting down.\n");
      rc->cproc = NULL;
      shutdown_now (rc);
      return;
    }
  }
  GNUNET_CONFIGURATION_destroy (rc->cfg);
  rc->cfg = GNUNET_CONFIGURATION_dup (cfg);
  event_mask = rc->event_mask;
  event_mask |= (1LL << GNUNET_TESTBED_ET_PEER_STOP);
  event_mask |= (1LL << GNUNET_TESTBED_ET_OPERATION_FINISHED);
  event_mask |= (1LL << GNUNET_TESTBED_ET_PEER_START);
  if (rc->topology < GNUNET_TESTBED_TOPOLOGY_NONE)
    event_mask |= GNUNET_TESTBED_ET_CONNECT;
  rc->c =
      GNUNET_TESTBED_controller_connect (rc->cfg, rc->h, event_mask, &event_cb,
                                         rc);
  if (0 < rc->num_hosts)
  {
    rc->reg_hosts = 0;
    rc->register_hosts_task = GNUNET_SCHEDULER_add_now (&register_hosts, rc);
    return;
  }
  rc->state = RC_LINKED;
  create_peers (rc);
}


/**
 * Callback function invoked for each interface found.
 *
 * @param cls closure
 * @param name name of the interface (can be NULL for unknown)
 * @param isDefault is this presumably the default interface
 * @param addr address of this interface (can be NULL for unknown or unassigned)
 * @param broadcast_addr the broadcast address (can be NULL for unknown or unassigned)
 * @param netmask the network mask (can be NULL for unknown or unassigned))
 * @param addrlen length of the address
 * @return GNUNET_OK to continue iteration, GNUNET_SYSERR to abort
 */
static int
netint_proc (void *cls, const char *name, int isDefault,
             const struct sockaddr *addr, const struct sockaddr *broadcast_addr,
             const struct sockaddr *netmask, socklen_t addrlen)
{
  struct RunContext *rc = cls;
  char hostip[NI_MAXHOST];
  char *buf;

  if (sizeof (struct sockaddr_in) != addrlen)
    return GNUNET_OK;           /* Only consider IPv4 for now */
  if (0 !=
      getnameinfo (addr, addrlen, hostip, NI_MAXHOST, NULL, 0, NI_NUMERICHOST))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "getnameinfo");
  if (NULL == rc->trusted_ip)
  {
    rc->trusted_ip = GNUNET_strdup (hostip);
    return GNUNET_YES;
  }
  (void) GNUNET_asprintf (&buf, "%s; %s", rc->trusted_ip, hostip);
  GNUNET_free (rc->trusted_ip);
  rc->trusted_ip = buf;
  return GNUNET_YES;
}


/**
 * Callbacks of this type are called by GNUNET_TESTBED_is_host_habitable to
 * inform whether the given host is habitable or not. The Handle returned by
 * GNUNET_TESTBED_is_host_habitable() is invalid after this callback is called
 *
 * @param cls NULL
 * @param host the host whose status is being reported; will be NULL if the host
 *          given to GNUNET_TESTBED_is_host_habitable() is NULL
 * @param status GNUNET_YES if it is habitable; GNUNET_NO if not
 */
static void
host_habitable_cb (void *cls, const struct GNUNET_TESTBED_Host *host,
                   int status)
{
  struct RunContext *rc = cls;
  struct GNUNET_TESTBED_Host **old_hosts;
  unsigned int nhost;

  for (nhost = 0; nhost < rc->num_hosts; nhost++)
  {
    if (host == rc->hosts[nhost])
      break;
  }
  GNUNET_assert (nhost != rc->num_hosts);
  rc->hc_handles[nhost] = NULL;
  if (GNUNET_NO == status)
  {
    if ((NULL != host) && (NULL != GNUNET_TESTBED_host_get_hostname (host)))
      LOG (GNUNET_ERROR_TYPE_ERROR, _("Host %s cannot start testbed\n"),
           GNUNET_TESTBED_host_get_hostname (host));
    else
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _("Testbed cannot be started on localhost\n"));
    shutdown_now (rc);
    return;
  }
  rc->reg_hosts++;
  if (rc->reg_hosts < rc->num_hosts)
    return;
  GNUNET_free (rc->hc_handles);
  rc->hc_handles = NULL;
  rc->h = rc->hosts[0];
  rc->num_hosts--;
  if (0 < rc->num_hosts)
  {
    old_hosts = rc->hosts;
    rc->hosts =
        GNUNET_malloc (sizeof (struct GNUNET_TESTBED_Host *) * rc->num_hosts);
    memcpy (rc->hosts, &old_hosts[1],
            (sizeof (struct GNUNET_TESTBED_Host *) * rc->num_hosts));
    GNUNET_free (old_hosts);
  }
  else
  {
    GNUNET_free (rc->hosts);
    rc->hosts = NULL;
  }
  GNUNET_OS_network_interfaces_list (netint_proc, rc);
  if (NULL == rc->trusted_ip)
    rc->trusted_ip = GNUNET_strdup ("127.0.0.1");
  rc->cproc =
      GNUNET_TESTBED_controller_start (rc->trusted_ip, rc->h, rc->cfg,
                                       &controller_status_cb, rc);
  GNUNET_free (rc->trusted_ip);
  rc->trusted_ip = NULL;
  if (NULL == rc->cproc)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, _("Cannot start the master controller"));
    shutdown_now (rc);
  }
}


/**
 * Convenience method for running a testbed with
 * a single call.  Underlay and overlay topology
 * are configured using the "UNDERLAY" and "OVERLAY"
 * options in the "[testbed]" section of the configuration\
 * (with possible options given in "UNDERLAY_XXX" and/or
 * "OVERLAY_XXX").
 *
 * The testbed is to be terminated using a call to
 * "GNUNET_SCHEDULER_shutdown".
 *
 * @param host_filename name of the file with the 'hosts', NULL
 *        to run everything on 'localhost'
 * @param cfg configuration to use (for testbed, controller and peers)
 * @param num_peers number of peers to start; FIXME: maybe put that ALSO into cfg?
 * @param event_mask bit mask with set of events to call 'cc' for;
 *                   or-ed values of "1LL" shifted by the
 *                   respective 'enum GNUNET_TESTBED_EventType'
 *                   (i.e.  "(1LL << GNUNET_TESTBED_ET_CONNECT) || ...")
 * @param cc controller callback to invoke on events; This callback is called
 *          for all peer start events even if GNUNET_TESTBED_ET_PEER_START isn't
 *          set in the event_mask as this is the only way get access to the
 *          handle of each peer
 * @param cc_cls closure for cc
 * @param test_master this callback will be called once the test is ready
 * @param test_master_cls closure for 'test_master'.
 */
void
GNUNET_TESTBED_run (const char *host_filename,
                    const struct GNUNET_CONFIGURATION_Handle *cfg,
                    unsigned int num_peers, uint64_t event_mask,
                    GNUNET_TESTBED_ControllerCallback cc, void *cc_cls,
                    GNUNET_TESTBED_TestMaster test_master,
                    void *test_master_cls)
{
  struct RunContext *rc;
  char *topology;
  unsigned long long random_links;
  unsigned int hid;
  unsigned int nhost;

  GNUNET_assert (num_peers > 0);
  rc = GNUNET_malloc (sizeof (struct RunContext));
  if (NULL != host_filename)
  {
    rc->num_hosts =
        GNUNET_TESTBED_hosts_load_from_file (host_filename, &rc->hosts);
    if (0 == rc->num_hosts)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING,
           _("No hosts loaded. Need at least one host\n"));
      goto error_cleanup;
    }
  }
  else
    rc->h = GNUNET_TESTBED_host_create (NULL, NULL, 0);
  rc->cfg = GNUNET_CONFIGURATION_dup (cfg);
  rc->num_peers = num_peers;
  rc->event_mask = event_mask;
  rc->cc = cc;
  rc->cc_cls = cc_cls;
  rc->test_master = test_master;
  rc->test_master_cls = test_master_cls;
  rc->state = RC_INIT;
  rc->topology = GNUNET_TESTBED_TOPOLOGY_NONE;
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_string (rc->cfg, "testbed",
                                             "OVERLAY_TOPOLOGY", &topology))
  {
    if (GNUNET_NO == GNUNET_TESTBED_topology_get_ (&rc->topology, topology))
    {
      GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR, "testbed",
                                 "OVERLAY_TOPLOGY",
                                 _
                                 ("Specified topology must be supported by testbed"));
    }
    GNUNET_free (topology);
  }
  switch (rc->topology)
  {
  case GNUNET_TESTBED_TOPOLOGY_ERDOS_RENYI:
  case GNUNET_TESTBED_TOPOLOGY_SMALL_WORLD_RING:
  case GNUNET_TESTBED_TOPOLOGY_SMALL_WORLD:
    if (GNUNET_OK !=
        GNUNET_CONFIGURATION_get_value_number (rc->cfg, "testbed",
                                               "OVERLAY_RANDOM_LINKS",
                                               &random_links))
    {
      /* OVERLAY option RANDOM & SMALL_WORLD_RING requires OVERLAY_RANDOM_LINKS
       * option to be set to the number of random links to be established  */
      GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR, "testbed",
                                 "OVERLAY_RANDOM_LINKS");
      goto error_cleanup;
    }
    if (random_links > UINT32_MAX)
    {
      GNUNET_break (0);         /* Too big number */
      goto error_cleanup;
    }
    rc->random_links = (unsigned int) random_links;
    break;
  case GNUNET_TESTBED_TOPOLOGY_FROM_FILE:
    if (GNUNET_OK !=
        GNUNET_CONFIGURATION_get_value_string (rc->cfg, "testbed",
                                               "OVERLAY_TOPOLOGY_FILE",
                                               &rc->topo_file))
    {
      GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR, "testbed",
                                 "OVERLAY_TOPOLOGY_FILE");
      goto error_cleanup;
    }
  default:
    /* Warn if OVERLAY_RANDOM_LINKS is present that it will be ignored */
    if (GNUNET_YES ==
        GNUNET_CONFIGURATION_have_value (rc->cfg, "testbed",
                                         "OVERLAY_RANDOM_LINKS"))
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "Ignoring value of `OVERLAY_RANDOM_LINKS' in given configuration\n");
    break;
  }
  if (NULL != host_filename)
  {
    rc->hc_handles =
        GNUNET_malloc (sizeof (struct GNUNET_TESTBED_HostHabitableCheckHandle *)
                       * rc->num_hosts);
    for (nhost = 0; nhost < rc->num_hosts; nhost++)
    {
      if (NULL ==
          (rc->hc_handles[nhost] =
           GNUNET_TESTBED_is_host_habitable (rc->hosts[nhost], rc->cfg,
                                             &host_habitable_cb, rc)))
      {
        GNUNET_break (0);
        for (nhost = 0; nhost < rc->num_hosts; nhost++)
          if (NULL != rc->hc_handles[nhost])
            GNUNET_TESTBED_is_host_habitable_cancel (rc->hc_handles[nhost]);
        GNUNET_free (rc->hc_handles);
        rc->hc_handles = NULL;
        goto error_cleanup;
      }
    }
  }
  else
    rc->cproc =
        GNUNET_TESTBED_controller_start ("127.0.0.1", rc->h, rc->cfg,
                                         &controller_status_cb, rc);
  rc->shutdown_run_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_run,
                                    rc);
  return;

error_cleanup:
  if (NULL != rc->h)
    GNUNET_TESTBED_host_destroy (rc->h);
  if (NULL != rc->hosts)
  {
    for (hid = 0; hid < rc->num_hosts; hid++)
      if (NULL != rc->hosts[hid])
        GNUNET_TESTBED_host_destroy (rc->hosts[hid]);
    GNUNET_free (rc->hosts);
  }
  GNUNET_free (rc);
}


/* end of testbed_api_testbed.c */
