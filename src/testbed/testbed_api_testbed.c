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
 * Opaque handle to an abstract operation to be executed by the testing framework.
 */
struct GNUNET_TESTBED_Testbed
{
  /**
   * The array of hosts
   */
  struct GNUNET_TESTBED_Host **hosts;

  /**
   * The number of hosts in the hosts array
   */
  unsigned int num_hosts;

  /**
   * The controller handle
   */
  struct GNUNET_TESTBED_Controller *c;
};


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
   * Master task to call when testbed initialization is done
   */
  GNUNET_SCHEDULER_Task master;

  /**
   * The closure for the master task
   */
  void *master_cls;

  /**
   * The head element of DLL operations
   */
  struct DLLOperation *dll_op_head;

  /**
   * The tail element of DLL operations
   */
  struct DLLOperation *dll_op_tail;

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
  
};


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

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Starting Peers\n");
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
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Required peers created successfully\n");
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

  GNUNET_assert (NULL == rc->peers);
  GNUNET_assert (RC_PEERS_DESTROYED == rc->state);
  if (NULL != rc->c)
    GNUNET_TESTBED_controller_disconnect (rc->c);
  if (NULL != rc->cproc)
    GNUNET_TESTBED_controller_stop (rc->cproc);
  if (NULL != rc->h)
    GNUNET_TESTBED_host_destroy (rc->h);
  if (NULL != rc->dll_op_head)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("Some operations are still pending. Cancelling them\n"));
    while (NULL != (dll_op = rc->dll_op_head))
    {
      GNUNET_TESTBED_operation_done (dll_op->op);
      GNUNET_CONTAINER_DLL_remove (rc->dll_op_head, rc->dll_op_tail, dll_op);
      GNUNET_free (dll_op);
    }
  }
  GNUNET_free (rc);
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
    GNUNET_TESTBED_operation_done (rc->topology_operation);
    rc->topology_operation = NULL;
  }
  if (NULL != rc->master)
    GNUNET_SCHEDULER_add_continuation (rc->master, rc->master_cls,
                                       GNUNET_SCHEDULER_REASON_PREREQ_DONE);
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

  if (NULL != rc->topology_operation)
  {
    switch (event->type)
    {
    case GNUNET_TESTBED_ET_OPERATION_FINISHED:
    case GNUNET_TESTBED_ET_CONNECT:
      rc->oc_count++;
      break;
    default:
      GNUNET_assert (0);
    }
    if (rc->oc_count == rc->num_oc)
    {
      rc->state = RC_READY;
      GNUNET_SCHEDULER_add_continuation (&call_master, rc,
                                         GNUNET_SCHEDULER_REASON_PREREQ_DONE);
    }
    return;
  }
  if ((RC_INIT != rc->state) &&
      ((GNUNET_TESTBED_ET_OPERATION_FINISHED == event->type) ||
       (GNUNET_TESTBED_ET_PEER_STOP == event->type)))
  {
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
    case RC_READY:
      rc->state = RC_PEERS_STOPPED;
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
      LOG (GNUNET_ERROR_TYPE_DEBUG, "All peers successfully destroyed\n");
      GNUNET_SCHEDULER_add_now (&cleanup_task, rc);
      break;
    default:
      GNUNET_assert (0);
    }
    return;
  }

call_cc:
  if ((0 != (rc->event_mask && (1LL << event->type))) && (NULL != rc->cc))
    rc->cc (rc->cc_cls, event);
  if (GNUNET_TESTBED_ET_PEER_START != event->type)
    return;
  for (dll_op = rc->dll_op_head; NULL != dll_op; dll_op = dll_op->next)
    if ((NULL != dll_op->cls) &&
        (event->details.peer_start.peer == dll_op->cls))
      break;
  GNUNET_assert (NULL != dll_op);
  GNUNET_CONTAINER_DLL_remove (rc->dll_op_head, rc->dll_op_tail, dll_op);
  GNUNET_TESTBED_operation_done (dll_op->op);
  GNUNET_free (dll_op);
  rc->peer_count++;
  if (rc->peer_count < rc->num_peers)
    return;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Peers started successfully\n");
  if (GNUNET_TESTBED_TOPOLOGY_NONE != rc->topology)
  {
    if ( (GNUNET_TESTBED_TOPOLOGY_ERDOS_RENYI == rc->topology)
         || (GNUNET_TESTBED_TOPOLOGY_SMALL_WORLD_RING == rc->topology))
      rc->topology_operation =
          GNUNET_TESTBED_overlay_configure_topology (NULL,
                                                     rc->num_peers,
                                                     rc->peers,
                                                     rc->topology,
                                                     (GNUNET_TESTBED_TOPOLOGY_ERDOS_RENYI
                                                      == rc->topology) ?
                                                     rc->num_oc : 
                                                     (rc->num_oc - rc->num_peers),
                                                     GNUNET_TESTBED_TOPOLOGY_OPTION_END);
    else
      rc->topology_operation =
          GNUNET_TESTBED_overlay_configure_topology (NULL,
                                                     rc->num_peers,
                                                     rc->peers,
                                                     rc->topology,
                                                     GNUNET_TESTBED_TOPOLOGY_OPTION_END);
    if (NULL == rc->topology_operation)
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "Not generating topology. Check number of peers\n");
    else
      return;
  }
  rc->state = RC_READY;
  GNUNET_SCHEDULER_add_continuation (&call_master, rc,
                                     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
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
  struct DLLOperation *dll_op;
  uint64_t event_mask;
  unsigned int peer;

  if (status != GNUNET_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Testbed startup failed\n");
    return;
  }
  event_mask = rc->event_mask;
  event_mask |= (1LL << GNUNET_TESTBED_ET_PEER_STOP);
  event_mask |= (1LL << GNUNET_TESTBED_ET_OPERATION_FINISHED);
  if (rc->topology < GNUNET_TESTBED_TOPOLOGY_NONE)
    event_mask |= GNUNET_TESTBED_ET_CONNECT;
  rc->c =
      GNUNET_TESTBED_controller_connect (cfg, rc->h, event_mask, &event_cb, rc);
  rc->peers =
      GNUNET_malloc (sizeof (struct GNUNET_TESTBED_Peer *) * rc->num_peers);
  GNUNET_assert (NULL != rc->c);
  rc->peer_count = 0;
  for (peer = 0; peer < rc->num_peers; peer++)
  {
    dll_op = GNUNET_malloc (sizeof (struct DLLOperation));
    dll_op->rc = rc;
    dll_op->op =
        GNUNET_TESTBED_peer_create (rc->c, rc->h, cfg, peer_create_cb, dll_op);
    GNUNET_CONTAINER_DLL_insert_tail (rc->dll_op_head, rc->dll_op_tail, dll_op);
  }
}


/**
 * Stops the testbed run and releases any used resources
 *
 * @param cls the tesbed run handle
 * @param tc the task context from scheduler
 */
static void
shutdown_run_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct RunContext *rc = cls;
  struct DLLOperation *dll_op;
  unsigned int peer;

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
        if (PS_STOPPED != rc->peers[peer]->state)
          break;
      }
      if (peer == rc->num_peers)
      {
        /* All peers are stopped */
        rc->state = RC_PEERS_STOPPED;
        for (peer = 0; peer < rc->num_peers; peer++)
        {
          dll_op = GNUNET_malloc (sizeof (struct DLLOperation));
          dll_op->op = GNUNET_TESTBED_peer_destroy (rc->peers[peer]);
          GNUNET_CONTAINER_DLL_insert_tail (rc->dll_op_head, rc->dll_op_tail,
                                            dll_op);
        }
        return;
      }
      /* Some peers are stopped */
      for (peer = 0; peer < rc->num_peers; peer++)
      {
        if (PS_STARTED != rc->peers[peer]->state)
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
    }
  }
  rc->state = RC_PEERS_DESTROYED;       /* No peers are present so we consider the
                                         * state where all peers are destroyed  */
  GNUNET_SCHEDULER_add_now (&cleanup_task, rc);
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
 * @param master task to run once the testbed is ready
 * @param master_cls
 */
void
GNUNET_TESTBED_run (const char *host_filename,
                    const struct GNUNET_CONFIGURATION_Handle *cfg,
                    unsigned int num_peers, uint64_t event_mask,
                    GNUNET_TESTBED_ControllerCallback cc, void *cc_cls,
                    GNUNET_SCHEDULER_Task master, void *master_cls)
{
  struct RunContext *rc;
  char *topology;
  unsigned long long random_links;

  GNUNET_break (NULL == host_filename); /* Currently we do not support host
                                         * files */
  GNUNET_assert (NULL != cc);
  GNUNET_assert (num_peers > 0);
  host_filename = NULL;
  rc = GNUNET_malloc (sizeof (struct RunContext));
  rc->h = GNUNET_TESTBED_host_create (NULL, NULL, 0);
  GNUNET_assert (NULL != rc->h);
  rc->cproc =
      GNUNET_TESTBED_controller_start ("127.0.0.1", rc->h, cfg,
                                       &controller_status_cb, rc);
  GNUNET_assert (NULL != rc->cproc);
  rc->num_peers = num_peers;
  rc->event_mask = event_mask;
  rc->event_mask |= (1LL << GNUNET_TESTBED_ET_PEER_START);
  rc->cc = cc;
  rc->cc_cls = cc_cls;
  rc->master = master;
  rc->master_cls = master_cls;
  rc->state = RC_INIT;
  rc->topology = GNUNET_TESTBED_TOPOLOGY_NONE;
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string (cfg, "testbed",
                                                          "OVERLAY_TOPOLOGY",
                                                          &topology))
  {
    if (0 == strcasecmp (topology, "RANDOM"))
    {
      rc->topology = GNUNET_TESTBED_TOPOLOGY_ERDOS_RENYI;      
    }
    else if (0 == strcasecmp (topology, "SMALL_WORLD_RING"))
    {
      rc->topology = GNUNET_TESTBED_TOPOLOGY_SMALL_WORLD_RING;
    }
    else if (0 == strcasecmp (topology, "CLIQUE"))
    {
      rc->topology = GNUNET_TESTBED_TOPOLOGY_CLIQUE;
      rc->num_oc = num_peers * (num_peers - 1);
    }
    else if (0 == strcasecmp (topology, "LINE"))
    {
      rc->topology = GNUNET_TESTBED_TOPOLOGY_LINE;
      rc->num_oc = num_peers - 1;
    }
    else if (0 == strcasecmp (topology, "RING"))
    {
      rc->topology = GNUNET_TESTBED_TOPOLOGY_RING;
      rc->num_oc = num_peers;
    }
    else if (0 == strcasecmp (topology, "2D_TORUS"))
    {
      rc->topology = GNUNET_TESTBED_TOPOLOGY_2D_TORUS;
      rc->num_oc = GNUNET_TESTBED_2dtorus_calc_links (num_peers, NULL, NULL);
    }
    else
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "Unknown topology %s given in configuration\n", topology);
    GNUNET_free (topology);
  }
  if ( (GNUNET_TESTBED_TOPOLOGY_ERDOS_RENYI == rc->topology)
       || (GNUNET_TESTBED_TOPOLOGY_SMALL_WORLD_RING == rc->topology))
  { 
    if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (cfg, "testbed",
                                                            "OVERLAY_RANDOM_LINKS",
                                                            &random_links))
    {
      /* OVERLAY option RANDOM & SMALL_WORLD_RING requires OVERLAY_RANDOM_LINKS
         option to be set to the number of random links to be established  */
      GNUNET_break (0);
      GNUNET_free (rc);
      return;
    }
    if (random_links > UINT32_MAX)
    {
      GNUNET_break (0);       /* Too big number */
      GNUNET_free (rc);
      return;
    }
    rc->num_oc = (unsigned int) random_links;
    if (GNUNET_TESTBED_TOPOLOGY_SMALL_WORLD_RING == rc->topology)
      rc->num_oc += num_peers;
  }
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                &shutdown_run_task, rc);
}


/**
 * Configure and run a testbed using the given
 * master controller on 'num_hosts' starting
 * 'num_peers' using the given peer configuration.
 *
 * @param controller master controller for the testbed
 *                   (must not be destroyed until after the
 *                    testbed is destroyed).
 * @param num_hosts number of hosts in 'hosts', 0 to only
 *        use 'localhost'
 * @param hosts list of hosts to use for the testbed
 * @param num_peers number of peers to start
 * @param cfg the configuration to use as a template for peers and also for
 *         checking the value of testbed helper binary
 * @param underlay_topology underlay topology to create
 * @param va topology-specific options
 * @return handle to the testbed; NULL upon error (error messaage will be printed)
 */
struct GNUNET_TESTBED_Testbed *
GNUNET_TESTBED_create_va (struct GNUNET_TESTBED_Controller *controller,
                          unsigned int num_hosts,
                          struct GNUNET_TESTBED_Host **hosts,
                          unsigned int num_peers,
                          const struct GNUNET_CONFIGURATION_Handle *cfg,
                          enum GNUNET_TESTBED_TopologyOption underlay_topology,
                          va_list va)
{
  unsigned int nhost;

  GNUNET_assert (underlay_topology < GNUNET_TESTBED_TOPOLOGY_NONE);
  if (num_hosts != 0)
  {
    for (nhost = 0; nhost < num_hosts; nhost++)
    {
      if (GNUNET_YES != GNUNET_TESTBED_is_host_habitable (hosts[nhost], cfg))
      {
        LOG (GNUNET_ERROR_TYPE_ERROR, _("Host %s cannot start testbed\n"),
             GNUNET_TESTBED_host_get_hostname_ (hosts[nhost]));
        break;
      }
    }
    if (num_hosts != nhost)
      return NULL;
  }
  /* We need controller callback here to get operation done events while
     linking hosts */
  GNUNET_break (0);
  return NULL;
}


/**
 * Configure and run a testbed using the given
 * master controller on 'num_hosts' starting
 * 'num_peers' using the given peer configuration.
 *
 * @param controller master controller for the testbed
 *                   (must not be destroyed until after the
 *                    testbed is destroyed).
 * @param num_hosts number of hosts in 'hosts', 0 to only
 *        use 'localhost'
 * @param hosts list of hosts to use for the testbed
 * @param num_peers number of peers to start
 * @param cfg the configuration to use as a template for peers and also for
 *         checking the value of testbed helper binary
 * @param underlay_topology underlay topology to create
 * @param ... topology-specific options
 */
struct GNUNET_TESTBED_Testbed *
GNUNET_TESTBED_create (struct GNUNET_TESTBED_Controller *controller,
                       unsigned int num_hosts,
                       struct GNUNET_TESTBED_Host **hosts,
                       unsigned int num_peers,
                       const struct GNUNET_CONFIGURATION_Handle *cfg,
                       enum GNUNET_TESTBED_TopologyOption underlay_topology,
                       ...)
{
  struct GNUNET_TESTBED_Testbed *testbed;
  va_list vargs;
  
  va_start (vargs, underlay_topology);
  testbed = GNUNET_TESTBED_create_va (controller, num_hosts, hosts, num_peers,
                                      cfg, underlay_topology, vargs);
  va_end (vargs);
  return testbed;
}


/**
 * Destroy a testbed.  Stops all running peers and then
 * destroys all peers.  Does NOT destroy the master controller.
 *
 * @param testbed testbed to destroy
 */
void
GNUNET_TESTBED_destroy (struct GNUNET_TESTBED_Testbed *testbed)
{
  GNUNET_break (0);
}


/* end of testbed_api_testbed.c */
