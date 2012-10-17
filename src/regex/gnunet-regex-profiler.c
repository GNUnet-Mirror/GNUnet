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
 * @file regex/gnunet-regex-profiler.c
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
 * Total number of hosts.
 */
#define NUM_HOSTS 2

/**
 * Number of peers per host.
 */
#define PEER_PER_HOST 1

/**
 * Total number of peers.
 */
#define TOTAL_PEERS (NUM_HOSTS * PEER_PER_HOST)


/**
 * Different states in test setup
 */
enum SetupState
{
  /**
   * The initial state
   */
  INIT,

  /**
   * Connecting to slave controller
   */
  LINKING,

  LINKING_SLAVES,

  LINKING_SLAVES_SUCCESS,

  CONNECTING_PEERS,

  CREATING_PEER,

  STARTING_PEER
};


/**
 * Event Mask for operation callbacks
 */
uint64_t event_mask;

/**
 * Testbed operation handle
 */
static struct GNUNET_TESTBED_Operation *op[NUM_HOSTS];

/**
 * Setup state.
 */
static enum SetupState state[NUM_HOSTS];

/**
 * Abort task.
 */
static GNUNET_SCHEDULER_TaskIdentifier abort_task;

/**
 * Global test result
 */
static int result;

/**
 * Hosts successfully registered
 */
static unsigned int host_registered;

/**
 * Peers successfully started
 */
static unsigned int peers_started;

/**
 * The master controller host
 */
struct GNUNET_TESTBED_Host *master_host;

/**
 * The master controller process
 */
static struct GNUNET_TESTBED_ControllerProc *master_proc;

/**
 * Handle to master controller
 */
static struct GNUNET_TESTBED_Controller *master_ctrl;


/**
 * Slave host registration handles
 */
static struct GNUNET_TESTBED_HostRegistrationHandle *rh;


/**
 * Handle to global configuration
 */
static struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Structure for storing host handles
 */
struct Host
{
  /**
   * IP address of this host.
   */
  char *ip;

  /**
   * Host handle.
   */
  struct GNUNET_TESTBED_Host *host;

  /**
   * Registration state of this host.
   */
  int host_registered;

  /**
   * Operation handle.
   */
  struct GNUNET_TESTBED_Operation *op;

  /**
   * Host state.
   */
  enum SetupState state;
};

/**
 * List of slaves.
 */
static struct Host slaves[NUM_HOSTS] = { {"192.168.1.33", NULL, 0, NULL, INIT},
{"192.168.1.34", NULL, 0, NULL, INIT}
};

/**
 * Structure for holding peer's handles.
 */
struct PeerData
{
  /**
   * Handle to testbed peer.
   */
  struct GNUNET_TESTBED_Peer *peer;

  /**
   * Peer's mesh handle.
   */
  struct GNUNET_MESH_Handle *mesh_handle;

  /**
   * The service connect operation to stream
   */
  struct GNUNET_TESTBED_Operation *op;

  /**
   * Peer setup state.
   */
  enum SetupState state;

  /**
   * Our Peer id
   */
  struct GNUNET_PeerIdentity our_id;
};

/**
 * The peers
 */
struct PeerData peers[TOTAL_PEERS];



/**
 * Close sockets and stop testing deamons nicely
 */
void
do_close (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  unsigned int i;

  if (GNUNET_SCHEDULER_NO_TASK != abort_task)
    GNUNET_SCHEDULER_cancel (abort_task);

  for (i = 0; i < TOTAL_PEERS; i++)
  {
    if (NULL != peers[i].mesh_handle)
      GNUNET_MESH_disconnect (peers[i].mesh_handle);
    if (NULL != peers[i].op)
      GNUNET_TESTBED_operation_done (peers[i].op);
  }

  GNUNET_SCHEDULER_shutdown (); /* For shutting down testbed */
}


/**
 * Something went wrong and timed out. Kill everything and set error flag.
 *
 * @param cls close.
 * @param tc task context.
 */
static void
do_abort (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "test: ABORT\n");
  result = GNUNET_SYSERR;
  abort_task = 0;
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
  long i = (long) cls;

  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Mesh connect failed: %s\n", emsg);
    GNUNET_assert (0);
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "mesh connect callback for peer %i\n",
              i);
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
  struct PeerData *peer = (struct PeerData *) cls;

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

  return NULL;
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "mesh disconnect adapter\n");
}


/**
 * Functions of this signature are called when a peer has been successfully
 * started or stopped.
 *
 * @param cls the closure from GNUNET_TESTBED_peer_start/stop()
 * @param emsg NULL on success; otherwise an error description
 */
static void
peer_start_cb (void *cls, const char *emsg)
{
  unsigned int cnt;
  long i = (long) cls;

  GNUNET_TESTBED_operation_done (op[i]);
  peers_started++;
  // FIXME create and start rest of PEERS_PER_HOST
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " %u peer(s) started\n", peers_started);

  if (TOTAL_PEERS == peers_started)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "All peers started.\n");
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Linking slave controllers\n");

    for (cnt = 0; cnt < NUM_HOSTS - 1; cnt++)
    {
      state[cnt] = LINKING_SLAVES;
      op[cnt] =
          GNUNET_TESTBED_get_slave_config ((void *) (long) cnt, master_ctrl,
                                           slaves[cnt + 1].host);
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
  long i = (long) cls;
  long peer_id;

//   GNUNET_TESTBED_operation_done(op[i]);
  peer_id = i;                  // FIXME  A * i + B
  peers[peer_id].peer = peer;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " Peer %i created\n", peer_id);
  op[i] = GNUNET_TESTBED_peer_start (NULL, peer, peer_start_cb, (void *) i);
}


/**
 * Signature of the event handler function called by the
 * respective event controller.
 *
 * @param cls closure
 * @param event information about the event
 */
static void
controller_cb (void *cls, const struct GNUNET_TESTBED_EventInformation *event)
{
  long i;

  switch (event->type)
  {
  case GNUNET_TESTBED_ET_PEER_START:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " Peer started\n");
    /* event->details.peer_start.peer; */
    /* event->details.peer_start.host; */

    break;
  case GNUNET_TESTBED_ET_PEER_STOP:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer stopped\n");
    break;
  case GNUNET_TESTBED_ET_CONNECT:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Overlay Connected\n");
    for (i = 0; i < TOTAL_PEERS; i++)
    {
      GNUNET_TESTBED_service_connect (NULL, peers[i].peer, "mesh",
                                      &mesh_connect_cb, (void *) i, &mesh_ca,
                                      &mesh_da, NULL);
    }
    break;
  case GNUNET_TESTBED_ET_OPERATION_FINISHED:
    if (NULL != event->details.operation_finished.emsg)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Testbed error: %s\n",
                  event->details.operation_finished.emsg);
      GNUNET_assert (0);
    }

    i = (long) event->details.operation_finished.op_cls;
    switch (state[i])
    {
    case INIT:
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  Init: %u\n", i);
      GNUNET_TESTBED_operation_done (event->details.
                                     operation_finished.operation);
      op[i] = NULL;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  Operation %u finished\n", i);
      break;
    }
    case LINKING:
    {
      GNUNET_assert (NULL != slaves[i].op);

      GNUNET_TESTBED_operation_done (slaves[i].op);
      slaves[i].op = NULL;

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  Operation %u finished\n", i);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   Linked host %i\n", i);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   Creating peer...\n");

      state[i] = CREATING_PEER;
      op[i] =
          GNUNET_TESTBED_peer_create (master_ctrl, slaves[i].host, cfg,
                                      peer_create_cb, (void *) i);
      break;
    }
    case CREATING_PEER:
    {
      GNUNET_TESTBED_operation_done (event->details.
                                     operation_finished.operation);
      op[i] = NULL;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  Operation %u finished\n", i);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  Peer create\n");
      break;
    }
    case LINKING_SLAVES:
    {
      struct GNUNET_CONFIGURATION_Handle *slave_cfg;

      GNUNET_assert (NULL != event->details.operation_finished.generic);
      slave_cfg =
          GNUNET_CONFIGURATION_dup ((struct GNUNET_CONFIGURATION_Handle *)
                                    event->details.operation_finished.generic);
      GNUNET_TESTBED_operation_done (event->details.
                                     operation_finished.operation);
      op[i] = NULL;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  Operation %u finished\n", i);
      state[i] = LINKING_SLAVES_SUCCESS;
      op[i] =
          GNUNET_TESTBED_controller_link ((void *) (long) i, master_ctrl,
                                          slaves[i + 1].host, slaves[i].host,
                                          slave_cfg, GNUNET_NO);
      GNUNET_CONFIGURATION_destroy (slave_cfg);
      break;
    }
    case LINKING_SLAVES_SUCCESS:
    {
      unsigned int peer_cnt;
      struct GNUNET_TESTBED_Peer *peer_handles[TOTAL_PEERS];

      GNUNET_TESTBED_operation_done (event->details.
                                     operation_finished.operation);
      op[i] = NULL;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  Operation %u finished\n", i);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " Linking slave %i succeeded\n", i);
      state[0] = CONNECTING_PEERS;

      for (peer_cnt = 0; peer_cnt < TOTAL_PEERS; peer_cnt++)
      {
        peer_handles[peer_cnt] = peers[peer_cnt].peer;
      }
      op[0] =
          GNUNET_TESTBED_overlay_configure_topology (NULL, TOTAL_PEERS,
                                                     peer_handles,
                                                     GNUNET_TESTBED_TOPOLOGY_LINE);
      GNUNET_assert (NULL != op[0]);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connecting peers...\n");
      break;
    }
    case CONNECTING_PEERS:
    {
      GNUNET_TESTBED_operation_done (event->details.
                                     operation_finished.operation);
      op[i] = NULL;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  Operation %u finished\n", i);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peers connected\n");
      break;
    }
    default:
      GNUNET_break (0);
    }
    break;
  default:
    GNUNET_break (0);
  }
}


/**
 * Callback which will be called to after a host registration succeeded or
 * failed. Registration of all slave hosts is continued and linking of the hosts
 * is started.
 *
 * @param cls not used.
 * @param emsg the error message; NULL if host registration is successful.
 */
static void
registration_cont (void *cls, const char *emsg)
{
  struct Host *slave = (struct Host *) cls;

  if (NULL != emsg || NULL == slave)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s\n", emsg);
    GNUNET_assert (0);
  }

  state[host_registered] = LINKING;
  slave->state = LINKING;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " Linking host %u\n", host_registered);
  slave->op =
      GNUNET_TESTBED_controller_link ((void *) (long) host_registered,
                                      master_ctrl, slave->host, NULL, cfg,
                                      GNUNET_YES);
  host_registered++;
  if (NUM_HOSTS != host_registered)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " Registering host %u with ip %s\n",
                host_registered, slaves[host_registered].ip);
    rh = GNUNET_TESTBED_register_host (master_ctrl,
                                       slaves[host_registered].host,
                                       &registration_cont,
                                       &slaves[host_registered]);
    return;
  }
}


/**
 * Callback to signal successfull startup of the controller process. If the
 * startup was successfull the master controller and all slave hosts are
 * created. Registering the slave hosts is started and continued in
 * registration_cont.
 *
 * @param cls not used.
 * @param config the configuration with which the controller has been started;
 *          NULL if status is not GNUNET_OK
 * @param status GNUNET_OK if the startup is successfull; GNUNET_SYSERR if not,
 *          GNUNET_TESTBED_controller_stop() shouldn't be called in this case
 */
static void
status_cb (void *cls, const struct GNUNET_CONFIGURATION_Handle *config,
           int status)
{
  unsigned int i;

  if (NULL == config || GNUNET_OK != status)
    return;

  event_mask = 0;
  event_mask |= (1L << GNUNET_TESTBED_ET_PEER_START);
  event_mask |= (1L << GNUNET_TESTBED_ET_PEER_STOP);
  event_mask |= (1L << GNUNET_TESTBED_ET_CONNECT);
  event_mask |= (1L << GNUNET_TESTBED_ET_OPERATION_FINISHED);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connecting to master controller\n");
  master_ctrl =
      GNUNET_TESTBED_controller_connect (config, master_host, event_mask,
                                         &controller_cb, NULL);
  GNUNET_assert (NULL != master_ctrl);

  for (i = 0; i < NUM_HOSTS; i++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " Creating host %u with ip %s\n", i,
                slaves[i].ip);
    slaves[i].host = GNUNET_TESTBED_host_create (slaves[i].ip, NULL, 0);
    GNUNET_assert (NULL != slaves[i].host);
  }
  host_registered = 0;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " Registering host %u with ip %s\n",
              host_registered, slaves[0].ip);
  rh = GNUNET_TESTBED_register_host (master_ctrl, slaves[0].host,
                                     &registration_cont, &slaves[0]);
  GNUNET_assert (NULL != rh);
}


/**
 * Main run function.
 *
 * @param cls not used.
 * @param args arguments passed to GNUNET_PROGRAM_run
 * @param cfgfile the path to configuration file
 * @param config the configuration file handle
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *config)
{
  master_host = GNUNET_TESTBED_host_create ("192.168.1.33", NULL, 0);
  GNUNET_assert (NULL != master_host);
  cfg = GNUNET_CONFIGURATION_dup (config);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting master controller\n");
  master_proc =
      GNUNET_TESTBED_controller_start ("192.168.1.33", master_host, cfg,
                                       status_cb, NULL);
  abort_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_MINUTES, 60), &do_abort,
                                    NULL);
}


/**
 * Main function for profiling the regex/mesh implementation.  Checks if all ssh
 * connections to each of the hosts in 'slave_ips' is possible before setting up
 * the testbed.
 *
 * @param argc argument count.
 * @param argv argument values.
 *
 * @return 0 on success.
 */
int
main (int argc, char **argv)
{
  int ret;
  int test_hosts;
  unsigned int i;

  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  char *const argv2[] = { "gnunet-regex-profiler",
    "-c", "regex_profiler_test.conf",
    NULL
  };

  test_hosts = GNUNET_OK;
  for (i = 0; i < NUM_HOSTS; i++)
  {
    char *const remote_args[] = {
      "ssh", "-o", "BatchMode=yes", slaves[i].ip,
      "gnunet-helper-testbed --help > /dev/null", NULL
    };
    struct GNUNET_OS_Process *auxp;
    enum GNUNET_OS_ProcessStatusType type;
    unsigned long code;

    fprintf (stderr, "Testing host %i\n", i);
    auxp =
        GNUNET_OS_start_process_vap (GNUNET_NO, GNUNET_OS_INHERIT_STD_ALL, NULL,
                                     NULL, "ssh", remote_args);
    GNUNET_assert (NULL != auxp);
    do
    {
      ret = GNUNET_OS_process_status (auxp, &type, &code);
      GNUNET_assert (GNUNET_SYSERR != ret);
      (void) usleep (300);
    }
    while (GNUNET_NO == ret);
    (void) GNUNET_OS_process_wait (auxp);
    GNUNET_OS_process_destroy (auxp);
    if (0 != code)
    {
      fprintf (stderr,
               "Unable to run the test as this system is not configured "
               "to use password less SSH logins to host %s.\n", slaves[i].ip);
      test_hosts = GNUNET_SYSERR;
    }
  }
  if (test_hosts != GNUNET_OK)
  {
    fprintf (stderr, "Some hosts have failed the ssh check. Exiting.\n");
    return 1;
  }
  fprintf (stderr, "START.\n");

  result = GNUNET_SYSERR;

  ret =
      GNUNET_PROGRAM_run ((sizeof (argv2) / sizeof (char *)) - 1, argv2,
                          "gnunet-regex-profiler", "nohelp", options, &run,
                          NULL);

  fprintf (stderr, "END.\n");

  if (GNUNET_SYSERR == result || GNUNET_OK != ret)
    return 1;
  return 0;
}
