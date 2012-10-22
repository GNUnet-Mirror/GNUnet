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
 * @file testbed/gnunet-testbed-profiler.c
 * @brief Profiling driver for the testbed.
 * @author Sree Harsha Totakura <sreeharsha@totakura.in> 
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_testbed_service.h"
#include "testbed_api_hosts.h"

/**
 * Generic loggins shorthand
 */
#define LOG(kind,...)                                           \
  GNUNET_log (kind, __VA_ARGS__)


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
 * Availanle states during profiling
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
 * The array of peers; we fill this as the peers are given to us by the testbed
 */
static struct GNUNET_TESTBED_Peer **peers;

/* /\** */
/*  * Operation handle */
/*  *\/ */
/* static struct GNUNET_TESTBED_Operation *op; */

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
 * Shutdown task identifier
 */
static GNUNET_SCHEDULER_TaskIdentifier shutdown_task;

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
 * Number of timeout failures to tolerate
 */
static unsigned int num_cont_fails;

/**
 * Continuous failures during overlay connect operations
 */
static unsigned int cont_fails;

/**
 * Links which are successfully established
 */
static unsigned int established_links;

/**
 * Links which are not successfully established
 */
static unsigned int failed_links;

/**
 * Global testing status
 */
static int result;

/**
 * current state of profiling
 */
enum State state;

/**
 * The topology we want to acheive
 */
enum GNUNET_TESTBED_TopologyOption topology;


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

  shutdown_task = GNUNET_SCHEDULER_NO_TASK;
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
  LOG (GNUNET_ERROR_TYPE_WARNING, "Aborting\n");
  abort_task = GNUNET_SCHEDULER_NO_TASK;
  result = GNUNET_SYSERR;
  if (GNUNET_SCHEDULER_NO_TASK != shutdown_task)
    GNUNET_SCHEDULER_cancel (shutdown_task);
  shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
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

  op = dll_op->op;
  GNUNET_CONTAINER_DLL_remove (dll_op_head, dll_op_tail, dll_op);
  GNUNET_free (dll_op);
  if (NULL != emsg)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
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
    printf ("%u peers started successfully in %.2f seconds\n",
            num_peers, ((double) prof_time.rel_value) / 1000.00);
    fflush (stdout);
    result = GNUNET_OK;
    if (0 == num_links)
    {      
      shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
      return;
    }
    state = STATE_PEERS_LINKING;
    /* Do overlay connect */
    prof_start_time = GNUNET_TIME_absolute_get ();
    switch (topology)
    {
    case GNUNET_TESTBED_TOPOLOGY_ERDOS_RENYI:
      topology_op =
          GNUNET_TESTBED_overlay_configure_topology (NULL, num_peers, peers,
                                                     topology,
                                                     num_links,
                                                     GNUNET_TESTBED_TOPOLOGY_DISABLE_AUTO_RETRY,
                                                     GNUNET_TESTBED_TOPOLOGY_OPTION_END);
      break;
    case GNUNET_TESTBED_TOPOLOGY_CLIQUE:
      topology_op =
          GNUNET_TESTBED_overlay_configure_topology (NULL, num_peers, peers,
                                                     topology,
                                                     GNUNET_TESTBED_TOPOLOGY_DISABLE_AUTO_RETRY,
                                                     GNUNET_TESTBED_TOPOLOGY_OPTION_END);
      break;
    default:
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
  struct GNUNET_TESTBED_Peer **peer_ptr;
  static unsigned int created_peers;
  unsigned int peer_cnt;

  if (NULL != emsg)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("Creating a peer failed. Error: %s\n"), emsg);
    GNUNET_TESTBED_operation_done (dll_op->op);
    GNUNET_CONTAINER_DLL_remove (dll_op_head, dll_op_tail, dll_op);
    GNUNET_free (dll_op);
    GNUNET_SCHEDULER_cancel (abort_task);
    abort_task = GNUNET_SCHEDULER_add_now (&do_abort, NULL);
    return;
  }
  peer_ptr = dll_op->cls;
  GNUNET_assert (NULL == *peer_ptr);
  *peer_ptr = peer;
  GNUNET_TESTBED_operation_done (dll_op->op);
  GNUNET_CONTAINER_DLL_remove (dll_op_head, dll_op_tail, dll_op);
  GNUNET_free (dll_op);
  if (++created_peers == num_peers)
  {
    prof_time = GNUNET_TIME_absolute_get_duration (prof_start_time);    
    printf ("%u peers created successfully in %.2f seconds\n",
            num_peers, ((double) prof_time.rel_value) / 1000.00);
    fflush (stdout);
    /* Now peers are to be started */
    state = STATE_PEERS_STARTING;
    prof_start_time = GNUNET_TIME_absolute_get ();
    for (peer_cnt = 0; peer_cnt < num_peers; peer_cnt++)
    {
      dll_op = GNUNET_malloc (sizeof (struct DLLOperation));
      dll_op->op = GNUNET_TESTBED_peer_start (dll_op, peers[peer_cnt], 
                                              &peer_churn_cb, dll_op);
      GNUNET_CONTAINER_DLL_insert_tail (dll_op_head, dll_op_tail, dll_op);
    }
  }
}


/**
 * Function to print summary about how many overlay links we have made and how
 * many failed
 */
static void
print_overlay_links_summary ()
{
  prof_time = GNUNET_TIME_absolute_get_duration (prof_start_time);
  printf ("\n%u links established in %.2f seconds\n",
	  established_links, ((double) prof_time.rel_value) / 1000.00);
  printf ("%u links failed due to timeouts\n", failed_links);
}


/**
 * Function to start peers
 */
static void
start_peers ()
{
  struct DLLOperation *dll_op;
  unsigned int peer_cnt;
  
  state = STATE_PEERS_CREATING;
  prof_start_time = GNUNET_TIME_absolute_get ();
  peers = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_Peer *)
                         * num_peers);
  for (peer_cnt = 0; peer_cnt < num_peers; peer_cnt++)
  {
    dll_op = GNUNET_malloc (sizeof (struct DLLOperation));
    dll_op->cls = &peers[peer_cnt];
    dll_op->op = GNUNET_TESTBED_peer_create (mc,
                                             hosts
                                             [peer_cnt % num_hosts],
                                             cfg,
                                             &peer_create_cb,
                                             dll_op);
    GNUNET_CONTAINER_DLL_insert_tail (dll_op_head, dll_op_tail, dll_op);
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
        
        dll_op = event->details.operation_finished.op_cls;
        GNUNET_CONTAINER_DLL_remove (dll_op_head, dll_op_tail, dll_op);
        GNUNET_free (dll_op);
        op = event->details.operation_finished.operation;
        if (NULL != event->details.operation_finished.emsg)
        {
          LOG (GNUNET_ERROR_TYPE_WARNING,
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
          printf ("%u controllers started successfully\n", num_hosts);
	  fflush (stdout);
          start_peers ();
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
	printf ("F");
	fflush (stdout);
        failed_links++;
	if (++cont_fails > num_cont_fails)
	{
	  printf ("\nAborting due to very high failure rate");
	  print_overlay_links_summary ();	  
	  GNUNET_SCHEDULER_cancel (abort_task);
	  abort_task = GNUNET_SCHEDULER_add_now (&do_abort, NULL);
	}
      }
      break;
    case GNUNET_TESTBED_ET_CONNECT:
      {
	if (0 != cont_fails)
	  cont_fails--;
	if (0 == established_links)
	  printf ("Establishing links. Please wait\n");
	printf (".");
	fflush (stdout);
        established_links++;
        if ((established_links + failed_links) == 
            (GNUNET_TESTBED_TOPOLOGY_CLIQUE == topology ? 
             num_peers * (num_peers -1) : num_links))
        {
	  print_overlay_links_summary ();
	  result = GNUNET_OK;
          shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
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
    LOG (GNUNET_ERROR_TYPE_WARNING,
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
    LOG (GNUNET_ERROR_TYPE_DEBUG,
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
 * @param config the configuration with which the controller has been started;
 *          NULL if status is not GNUNET_OK
 * @param status GNUNET_OK if the startup is successfull; GNUNET_SYSERR if not,
 *          GNUNET_TESTBED_controller_stop() shouldn't be called in this case
 */
static void
status_cb (void *cls, const struct GNUNET_CONFIGURATION_Handle *config, int status)
{
  if (GNUNET_SCHEDULER_NO_TASK != abort_task)
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
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("Unable to connect to master controller -- Check config\n"));
    abort_task = GNUNET_SCHEDULER_add_now (&do_abort, NULL);
    return;
  }
  if (num_hosts > 1)
    register_hosts_task = GNUNET_SCHEDULER_add_now (&register_hosts, NULL);
  else
    start_peers ();
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
    fprintf (stderr, _("No hosts loaded. Need atleast one host\n"));
    return;
  }
  for (nhost = 0; nhost < num_hosts; nhost++)
  {
    if (GNUNET_YES != GNUNET_TESTBED_is_host_habitable (hosts[nhost]))
    {
      fprintf (stderr, _("Host %s cannot start testbed\n"),
	       GNUNET_TESTBED_host_get_hostname_ (hosts[nhost]));
      break;
    }
  }
  if (num_hosts != nhost)
  {
    fprintf (stderr, _("Exiting\n"));
    shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }
  cfg = GNUNET_CONFIGURATION_dup (config);
  mc_proc = 
      GNUNET_TESTBED_controller_start (GNUNET_TESTBED_host_get_hostname_ 
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
 * Set an option of type 'char *' from the command line.
 * A pointer to this function should be passed as part of the
 * 'struct GNUNET_GETOPT_CommandLineOption' array to initialize options
 * of this type.  It should be followed by a pointer to a value of
 * type 'char *'.
 *
 * @param ctx command line processing context
 * @param scls additional closure (will point to the 'char *',
 *             which will be allocated)
 * @param option name of the option
 * @param value actual value of the option (a string)
 * @return GNUNET_OK to continue procesing; GNUNET_SYSERR to signal error
 */
int
set_topology (struct GNUNET_GETOPT_CommandLineProcessorContext *ctx,
              void *scls, const char *option, const char *value)
{
  enum GNUNET_TESTBED_TopologyOption *val = scls;

  if (0 == strncasecmp ("CLIQUE", value, strlen ("CLIQUE")))
  {  
    *val = GNUNET_TESTBED_TOPOLOGY_CLIQUE;
    return GNUNET_OK;
  }
  if (0 == strncasecmp ("RANDOM", value, strlen ("RANDOM")))
  {  
    *val = GNUNET_TESTBED_TOPOLOGY_ERDOS_RENYI;
    return GNUNET_OK;
  }
  FPRINTF (stderr, _("Only `CLIQUE' and `RANDOM' are permitted"));
  return GNUNET_SYSERR;
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
    { 'e', "num-errors", "COUNT",
      gettext_noop ("tolerate COUNT number of continious timeout failures"),
      GNUNET_YES, &GNUNET_GETOPT_set_uint, &num_cont_fails },
    { 't', "topology", "TOPOLOGY",
      gettext_noop ("Try to acheive TOPOLOGY. This options takes either CLIQUE "
                    "or RANDOM. For CLIQUE the parameter -n is ignored. The "
                    "default is to acheive a random graph topology."),
      GNUNET_YES, &GNUNET_GETOPT_set_string, &topology },
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  topology = GNUNET_TESTBED_TOPOLOGY_ERDOS_RENYI;
  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;
  
  result = GNUNET_SYSERR;
  ret =
      GNUNET_PROGRAM_run (argc, argv, "gnunet-testbed-profiler [OPTIONS] hosts-file",
                          _("Profiler for testbed"),
                          options, &run, NULL);
  if (GNUNET_OK != ret)
    return ret;
  if (GNUNET_OK != result)
    return 1;
  return 0;
}
