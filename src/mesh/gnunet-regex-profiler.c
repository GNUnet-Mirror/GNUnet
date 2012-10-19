/*
     This file is part of GNUnet.
     (C) 2011, 2012 Christian Grothoff (and other contributing authors)

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
 * @file mesh/gnunet-regex-profiler.c
 * @brief Regex profiler for testing distributed regex use.
 * @author Bart Polot
 * @author Max Szengel
 */

#include <string.h>

#include "platform.h"
#include "gnunet_applications.h"
#include "gnunet_util_lib.h"
#include "gnunet_mesh_service.h"
#include "gnunet_stream_lib.h"
#include "gnunet_testbed_service.h"

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
 * Available states during profiling
 */
enum State
{
  /**
   * Initial state
   */
  STATE_INIT = 0,

  /**
   * Starting slaves
   */
  STATE_SLAVES_STARTING,

  /**
   * Creating peers
   */
  STATE_PEERS_CREATING,

  /**
   * Starting peers
   */
  STATE_PEERS_STARTING,

  /**
   * Linking peers
   */
  STATE_PEERS_LINKING,

  /**
   * Destroying peers; we can do this as the controller takes care of stopping a
   * peer if it is running
   */
  STATE_PEERS_DESTROYING
};


/**
 * An array of hosts loaded from the hostkeys file
 */
static struct GNUNET_TESTBED_Host **hosts;

/**
 * Peer handles.
 */
struct Peer
{
  /**
   * The actual testbed peer handle.
   */
  struct GNUNET_TESTBED_Peer *peer_handle;

  /**
   * Peer's mesh handle.
   */
  struct GNUNET_MESH_Handle *mesh_handle;

  /**
   * Host on which the peer is running.
   */
  struct GNUNET_TESTBED_Host *host_handle;

  /**
   * Testbed operation handle.
   */
  struct GNUNET_TESTBED_Operation *op_handle;
};

/**
 * Array of peer handles used to pass to
 * GNUNET_TESTBED_overlay_configure_topology
 */
struct GNUNET_TESTBED_Peer **peer_handles;

/**
 * The array of peers; we fill this as the peers are given to us by the testbed
 */
static struct Peer *peers;

/**
 * Host registration handle
 */
static struct GNUNET_TESTBED_HostRegistrationHandle *reg_handle;

/**
 * Handle to the master controller process
 */
struct GNUNET_TESTBED_ControllerProc *mc_proc;

/**
 * Handle to the master controller
 */
struct GNUNET_TESTBED_Controller *mc;

/**
 * Handle to global configuration
 */
struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Head of the operations list
 */
struct DLLOperation *dll_op_head;

/**
 * Tail of the operations list
 */
struct DLLOperation *dll_op_tail;

/**
 * Peer linking - topology operation
 */
struct GNUNET_TESTBED_Operation *topology_op;

/**
 * Abort task identifier
 */
static GNUNET_SCHEDULER_TaskIdentifier abort_task;

/**
 * Host registration task identifier
 */
static GNUNET_SCHEDULER_TaskIdentifier register_hosts_task;

/**
 * Global event mask for all testbed events
 */
uint64_t event_mask;

/**
 * The starting time of a profiling step
 */
struct GNUNET_TIME_Absolute prof_start_time;

/**
 * Duration profiling step has taken
 */
struct GNUNET_TIME_Relative prof_time;

/**
 * Current peer id
 */
unsigned int peer_id;

/**
 * Number of peers to be started by the profiler
 */
static unsigned int num_peers;

/**
 * Number of hosts in the hosts array
 */
static unsigned int num_hosts;

/**
 * Number of random links to be established between peers
 */
static unsigned int num_links;

/**
 * Global testing status
 */
static int result;

/**
 * current state of profiling
 */
enum State state;


/**
 * Shutdown nicely
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct DLLOperation *dll_op;
  unsigned int nhost;

  if (GNUNET_SCHEDULER_NO_TASK != abort_task)
    GNUNET_SCHEDULER_cancel (abort_task);
  if (GNUNET_SCHEDULER_NO_TASK != register_hosts_task)
    GNUNET_SCHEDULER_cancel (register_hosts_task);
  if (NULL != reg_handle)
    GNUNET_TESTBED_cancel_registration (reg_handle);
  if (NULL != topology_op)
    GNUNET_TESTBED_operation_cancel (topology_op);
  for (nhost = 0; nhost < num_hosts; nhost++)
    if (NULL != hosts[nhost])
      GNUNET_TESTBED_host_destroy (hosts[nhost]);
  GNUNET_free_non_null (hosts);
  while (NULL != (dll_op = dll_op_head))
  {
    GNUNET_TESTBED_operation_cancel (dll_op->op);
    GNUNET_CONTAINER_DLL_remove (dll_op_head, dll_op_tail, dll_op);
    GNUNET_free (dll_op);
  }
  if (NULL != mc)
    GNUNET_TESTBED_controller_disconnect (mc);
  if (NULL != mc_proc)
    GNUNET_TESTBED_controller_stop (mc_proc);
  if (NULL != cfg)
    GNUNET_CONFIGURATION_destroy (cfg);

  //FIXME       GNUNET_MESH_disconnect (peers[i].mesh_handle);

  GNUNET_SCHEDULER_shutdown ();	/* Stop scheduler to shutdown testbed run */
}


/**
 * abort task to run on test timed out
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_abort (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Aborting\n");
  abort_task = GNUNET_SCHEDULER_NO_TASK;
  result = GNUNET_SYSERR;
  GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
}


/**
 * Method called whenever another peer has added us to a tunnel
 * the other peer initiated.
 * Only called (once) upon reception of data with a message type which was
 * subscribed to in GNUNET_MESH_connect. A call to GNUNET_MESH_tunnel_destroy
 * causes te tunnel to be ignored and no further notifications are sent about
 * the same tunnel.
 *
 * @param cls closure
 * @param tunnel new handle to the tunnel
 * @param initiator peer that started the tunnel
 * @param atsi performance information for the tunnel
 * @return initial tunnel context for the tunnel
 *         (can be NULL -- that's not an error)
 */
void *
mesh_inbound_tunnel_handler (void *cls, struct GNUNET_MESH_Tunnel *tunnel,
                             const struct GNUNET_PeerIdentity *initiator,
                             const struct GNUNET_ATS_Information *atsi)
{
  return NULL;
}


/**
 * Function called whenever an inbound tunnel is destroyed.  Should clean up
 * any associated state.  This function is NOT called if the client has
 * explicitly asked for the tunnel to be destroyed using
 * GNUNET_MESH_tunnel_destroy. It must NOT call GNUNET_MESH_tunnel_destroy on
 * the tunnel.
 *
 * @param cls closure (set from GNUNET_MESH_connect)
 * @param tunnel connection to the other end (henceforth invalid)
 * @param tunnel_ctx place where local state associated
 *                   with the tunnel is stored
 */
void
mesh_tunnel_end_handler (void *cls, const struct GNUNET_MESH_Tunnel *tunnel,
                         void *tunnel_ctx)
{

}


/**
 * Mesh connect callback.
 *
 * @param cls internal peer id.
 * @param op operation handle.
 * @param ca_result connect adapter result.
 * @param emsg error message.
 */
void
mesh_connect_cb (void *cls, struct GNUNET_TESTBED_Operation *op,
                 void *ca_result, const char *emsg)
{
  static unsigned int connected_mesh_handles;
  struct Peer *peer = (struct Peer *) cls;
  unsigned int peer_cnt;

  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Mesh connect failed: %s\n", emsg);
    GNUNET_assert (0);
  }

  GNUNET_assert (peer->op_handle == op);
  GNUNET_assert (peer->mesh_handle == ca_result);

  printf (".");
  fflush (stdout);

  if (++connected_mesh_handles == num_peers)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "All mesh handles connected\n");

    // TODO announce regexes...

    for (peer_cnt = 0; peer_cnt < num_peers; peer_cnt++)
    {
      GNUNET_TESTBED_operation_done (peers[peer_cnt].op_handle);
    }
  }
  
}


/**
 * Mesh connect adapter.
 *
 * @param cls not used.
 * @param cfg configuration handle.
 *
 * @return
 */
void *
mesh_ca (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct Peer *peer = (struct Peer *) cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "mesh connect adapter\n");

  static struct GNUNET_MESH_MessageHandler handlers[] = {
    {NULL, 0, 0}
  };

  static GNUNET_MESH_ApplicationType apptypes[] = {
    GNUNET_APPLICATION_TYPE_END
  };

  peer->mesh_handle =
      GNUNET_MESH_connect (cfg, cls, &mesh_inbound_tunnel_handler,
                           &mesh_tunnel_end_handler, handlers, apptypes);

  return peer->mesh_handle;
}


/**
 * Adapter function called to destroy a connection to
 * the mesh service
 *
 * @param cls closure
 * @param op_result service handle returned from the connect adapter
 */
void
mesh_da (void *cls, void *op_result)
{
  static unsigned int disconnected_mesh_handles;
  struct Peer *peer = (struct Peer *) cls;

  GNUNET_assert (peer->mesh_handle == op_result);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "mesh disconnect adapter\n");

  GNUNET_MESH_disconnect (peer->mesh_handle);
  peer->mesh_handle = NULL;

  if (++disconnected_mesh_handles == num_peers)
  {
    GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
  }
}


/**
 * Functions of this signature are called when a peer has been successfully
 * started or stopped.
 *
 * @param cls the closure from GNUNET_TESTBED_peer_start/stop()
 * @param emsg NULL on success; otherwise an error description
 */
static void
peer_churn_cb (void *cls, const char *emsg)
{
  struct DLLOperation *dll_op = cls;
  struct GNUNET_TESTBED_Operation *op;
  static unsigned int started_peers;
  unsigned int peer_cnt;

  op = dll_op->op;
  GNUNET_CONTAINER_DLL_remove (dll_op_head, dll_op_tail, dll_op);
  GNUNET_free (dll_op);
  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
         _("An operation has failed while starting peers\n"));
    GNUNET_TESTBED_operation_done (op);
    GNUNET_SCHEDULER_cancel (abort_task);
    abort_task = GNUNET_SCHEDULER_add_now (&do_abort, NULL);
    return;
  }
  GNUNET_TESTBED_operation_done (op);
  if (++started_peers == num_peers)
  {
    prof_time = GNUNET_TIME_absolute_get_duration (prof_start_time);
    printf ("All peers started successfully in %.2f seconds\n",
            ((double) prof_time.rel_value) / 1000.00);
    result = GNUNET_OK;
    if (0 == num_links)
    {
      GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
      return;
    }

    peer_handles = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_Peer *) * num_peers);
    for (peer_cnt = 0; peer_cnt < num_peers; peer_cnt++)
      peer_handles[peer_cnt] = peers[peer_cnt].peer_handle;

    state = STATE_PEERS_LINKING;
    /* Do overlay connect */
    prof_start_time = GNUNET_TIME_absolute_get ();
    topology_op =
        GNUNET_TESTBED_overlay_configure_topology (NULL, num_peers, peer_handles,
                                                   GNUNET_TESTBED_TOPOLOGY_ERDOS_RENYI,
                                                   num_links);
    if (NULL == topology_op)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Cannot create topology, op handle was NULL\n");
      GNUNET_assert (0);
    }
  }
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
  struct Peer *peer_ptr;
  static unsigned int created_peers;
  unsigned int peer_cnt;

  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
         _("Creating a peer failed. Error: %s\n"), emsg);
    GNUNET_TESTBED_operation_done (dll_op->op);
    GNUNET_CONTAINER_DLL_remove (dll_op_head, dll_op_tail, dll_op);
    GNUNET_free (dll_op);
    GNUNET_SCHEDULER_cancel (abort_task);
    abort_task = GNUNET_SCHEDULER_add_now (&do_abort, NULL);
    return;
  }

  peer_ptr = dll_op->cls;
  GNUNET_assert (NULL == peer_ptr->peer_handle);
  peer_ptr->peer_handle = peer;
  GNUNET_TESTBED_operation_done (dll_op->op);
  GNUNET_CONTAINER_DLL_remove (dll_op_head, dll_op_tail, dll_op);
  GNUNET_free (dll_op);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer %i created on host %s\n",
              created_peers,
              GNUNET_TESTBED_host_get_hostname (peer_ptr->host_handle));

  if (++created_peers == num_peers)
  {
    prof_time = GNUNET_TIME_absolute_get_duration (prof_start_time);
    printf ("All peers created successfully in %.2f seconds\n",
            ((double) prof_time.rel_value) / 1000.00);
    /* Now peers are to be started */
    state = STATE_PEERS_STARTING;
    prof_start_time = GNUNET_TIME_absolute_get ();
    for (peer_cnt = 0; peer_cnt < num_peers; peer_cnt++)
    {
      dll_op = GNUNET_malloc (sizeof (struct DLLOperation));
      dll_op->op = GNUNET_TESTBED_peer_start (dll_op, peers[peer_cnt].peer_handle,
                                              &peer_churn_cb, dll_op);
      GNUNET_CONTAINER_DLL_insert_tail (dll_op_head, dll_op_tail, dll_op);
    }
  }
}


/**
 * Controller event callback
 *
 * @param cls NULL
 * @param event the controller event
 */
static void
controller_event_cb (void *cls,
                     const struct GNUNET_TESTBED_EventInformation *event)
{
  struct DLLOperation *dll_op;
  struct GNUNET_TESTBED_Operation *op;

  switch (state)
  {
  case STATE_SLAVES_STARTING:
    switch (event->type)
    {
    case GNUNET_TESTBED_ET_OPERATION_FINISHED:
      {
        static unsigned int slaves_started;
        unsigned int peer_cnt;

        dll_op = event->details.operation_finished.op_cls;
        GNUNET_CONTAINER_DLL_remove (dll_op_head, dll_op_tail, dll_op);
        GNUNET_free (dll_op);
        op = event->details.operation_finished.operation;
        if (NULL != event->details.operation_finished.emsg)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
               _("An operation has failed while starting slaves\n"));
          GNUNET_TESTBED_operation_done (op);
          GNUNET_SCHEDULER_cancel (abort_task);
          abort_task = GNUNET_SCHEDULER_add_now (&do_abort, NULL);
          return;
        }
        GNUNET_TESTBED_operation_done (op);
        /* Proceed to start peers */
        if (++slaves_started == num_hosts - 1)
        {
          printf ("All slaves started successfully\n");
          state = STATE_PEERS_CREATING;
          prof_start_time = GNUNET_TIME_absolute_get ();
          peers = GNUNET_malloc (sizeof (struct Peer) * num_peers);
          for (peer_cnt = 0; peer_cnt < num_peers; peer_cnt++)
          {
            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Creating peer %i on host %s\n",
                        peer_cnt,
                        GNUNET_TESTBED_host_get_hostname (hosts[peer_cnt % num_hosts]));

            peers[peer_cnt].host_handle = hosts[peer_cnt % num_hosts];

            dll_op = GNUNET_malloc (sizeof (struct DLLOperation));
            dll_op->cls = &peers[peer_cnt];
            dll_op->op = GNUNET_TESTBED_peer_create (mc,
                                                     hosts[peer_cnt % num_hosts],
                                                     cfg,
                                                     &peer_create_cb,
                                                     dll_op);
            GNUNET_CONTAINER_DLL_insert_tail (dll_op_head, dll_op_tail, dll_op);
          }
        }
      }
      break;
    default:
      GNUNET_assert (0);
    }
    break;
  case STATE_PEERS_STARTING:
    switch (event->type)
    {
    case GNUNET_TESTBED_ET_OPERATION_FINISHED:
      /* Control reaches here when peer start fails */
    case GNUNET_TESTBED_ET_PEER_START:
      /* we handle peer starts in peer_churn_cb */
      break;
    default:
      GNUNET_assert (0);
    }
    break;
  case STATE_PEERS_LINKING:
   switch (event->type)
    {
    case GNUNET_TESTBED_ET_OPERATION_FINISHED:
      /* Control reaches here when a peer linking operation fails */
      if (NULL != event->details.operation_finished.emsg)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
             _("An operation has failed while linking\n"));
        GNUNET_SCHEDULER_cancel (abort_task);
        abort_task = GNUNET_SCHEDULER_add_now (&do_abort, NULL);
      }
      break;
    case GNUNET_TESTBED_ET_CONNECT:
      {
        static unsigned int established_links;
        unsigned int peer_cnt;

        if (0 == established_links)
          printf ("Establishing links\n .");
        else
        {
          printf (".");
          fflush (stdout);
        }
        if (++established_links == num_links)
        {
          prof_time = GNUNET_TIME_absolute_get_duration (prof_start_time);
          printf ("\n%u links established in %.2f seconds\n",
                  num_links, ((double) prof_time.rel_value) / 1000.00);
          result = GNUNET_OK;
          GNUNET_free (peer_handles);
          printf ("\nConnecting to mesh service...\n");
          for (peer_cnt = 0; peer_cnt < num_peers; peer_cnt++)
          {
            peers[peer_cnt].op_handle = GNUNET_TESTBED_service_connect (NULL,
                                                                        peers[peer_cnt].peer_handle,
                                                                        "mesh",
                                                                        &mesh_connect_cb,
                                                                        &peers[peer_cnt],
                                                                        &mesh_ca,
                                                                        &mesh_da,
                                                                        &peers[peer_cnt]);
          }
        }
      }
      break;
    default:
      GNUNET_assert (0);
    }
    break;
  default:
    GNUNET_assert (0);
  }
}


/**
 * Task to register all hosts available in the global host list
 *
 * @param cls NULL
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
  reg_handle = NULL;
  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Host registration failed for a host. Error: %s\n"), emsg);
    GNUNET_SCHEDULER_cancel (abort_task);
    abort_task = GNUNET_SCHEDULER_add_now (&do_abort, NULL);
    return;
  }
  register_hosts_task = GNUNET_SCHEDULER_add_now (&register_hosts, NULL);
}


/**
 * Task to register all hosts available in the global host list
 *
 * @param cls NULL
 * @param tc the scheduler task context
 */
static void
register_hosts (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct DLLOperation *dll_op;
  static unsigned int reg_host;
  unsigned int slave;

  register_hosts_task = GNUNET_SCHEDULER_NO_TASK;
  if (reg_host == num_hosts - 1)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "All hosts successfully registered\n");
    /* Start slaves */
    state = STATE_SLAVES_STARTING;
    for (slave = 1; slave < num_hosts; slave++)
    {
      dll_op = GNUNET_malloc (sizeof (struct DLLOperation));
      dll_op->op = GNUNET_TESTBED_controller_link (dll_op,
                                                   mc,
                                                   hosts[slave],
                                                   hosts[0],
                                                   cfg,
                                                   GNUNET_YES);
      GNUNET_CONTAINER_DLL_insert_tail (dll_op_head, dll_op_tail, dll_op);
    }
    return;
  }
  reg_handle = GNUNET_TESTBED_register_host (mc, hosts[++reg_host],
                                             host_registration_completion,
                                             NULL);
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
status_cb (void *cls, const struct GNUNET_CONFIGURATION_Handle *config, int status)
{
  GNUNET_SCHEDULER_cancel (abort_task);
  if (GNUNET_OK != status)
  {
    mc_proc = NULL;
    abort_task = GNUNET_SCHEDULER_add_now (&do_abort, NULL);
    return;
  }
  event_mask = 0;
  event_mask |= (1LL << GNUNET_TESTBED_ET_PEER_START);
  event_mask |= (1LL << GNUNET_TESTBED_ET_PEER_STOP);
  event_mask |= (1LL << GNUNET_TESTBED_ET_CONNECT);
  event_mask |= (1LL << GNUNET_TESTBED_ET_DISCONNECT);
  event_mask |= (1LL << GNUNET_TESTBED_ET_OPERATION_FINISHED);
  mc = GNUNET_TESTBED_controller_connect (config, hosts[0], event_mask,
                                          &controller_event_cb, NULL);
  if (NULL == mc)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Unable to connect to master controller -- Check config\n"));
    abort_task = GNUNET_SCHEDULER_add_now (&do_abort, NULL);
    return;
  }
  register_hosts_task = GNUNET_SCHEDULER_add_now (&register_hosts, NULL);
  abort_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                             &do_abort, NULL);
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param config configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *config)
{
  unsigned int nhost;

  if (NULL == args[0])
  {
    fprintf (stderr, _("No hosts-file specified on command line\n"));
    return;
  }
  if (0 == num_peers)
  {
    result = GNUNET_OK;
    return;
  }
  num_hosts = GNUNET_TESTBED_hosts_load_from_file (args[0], &hosts);
  if (0 == num_hosts)
  {
    fprintf (stderr, _("No hosts loaded. Need at least one host\n"));
    return;
  }
  for (nhost = 0; nhost < num_hosts; nhost++)
  {
    if (GNUNET_YES != GNUNET_TESTBED_is_host_habitable (hosts[nhost]))
    {
      fprintf (stderr, _("Host %s cannot start testbed\n"),
                         GNUNET_TESTBED_host_get_hostname (hosts[nhost]));
      break;
    }
  }
  if (num_hosts != nhost)
  {
    fprintf (stderr, _("Exiting\n"));
    GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }
  if (NULL == config)
  {
    fprintf (stderr, _("No configuration file given. Exiting\n"));
    GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }

  cfg = GNUNET_CONFIGURATION_dup (config);
  mc_proc =
      GNUNET_TESTBED_controller_start (GNUNET_TESTBED_host_get_hostname
                                       (hosts[0]),
                                       hosts[0],
                                       cfg,
                                       status_cb,
                                       NULL);
  abort_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_SECONDS, 5), &do_abort,
                                    NULL);
}


/**
 * Main function.
 *
 * @return 0 on success
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    { 'p', "num-peers", "COUNT",
      gettext_noop ("create COUNT number of peers"),
      GNUNET_YES, &GNUNET_GETOPT_set_uint, &num_peers },
    { 'n', "num-links", "COUNT",
      gettext_noop ("create COUNT number of random links"),
      GNUNET_YES, &GNUNET_GETOPT_set_uint, &num_links },
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  result = GNUNET_SYSERR;
  ret =
      GNUNET_PROGRAM_run (argc, argv, "gnunet-regex-profiler [OPTIONS] hosts-file",
                          _("Profiler for regex/mesh"),
                          options, &run, NULL);
  if (GNUNET_OK != ret)
    return ret;
  if (GNUNET_OK != result)
    return 1;
  return 0;
}
