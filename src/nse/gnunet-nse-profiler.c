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
 * @file nse/gnunet-nse-profiler.c
 *
 * @brief Profiling driver for the network size estimation service.
 *        Generally, the profiler starts a given number of peers,
 *        then churns some off, waits a certain amount of time, then
 *        churns again, and repeats.
 * @author Christian Grothoff
 * @author Nathan Evans
 * @author Sree Harsha Totakura
 */

#include "platform.h"
#include "gnunet_testbed_service.h"
#include "gnunet_nse_service.h"

/**
 * Generic loggins shorthand
 */
#define LOG(kind,...)                                           \
  GNUNET_log (kind, __VA_ARGS__)

/**
 * Debug logging shorthand
 */
#define LOG_DEBUG(...)                          \
  LOG (GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__)


/**
 * Information we track for a peer in the testbed.
 */
struct NSEPeer
{
  /**
   * Prev reference in DLL.
   */
  struct NSEPeer *prev;

  /**
   * Next reference in DLL.
   */
  struct NSEPeer *next;

  /**
   * Handle with testbed.
   */
  struct GNUNET_TESTBED_Peer *daemon;

  /**
   * Testbed operation to connect to NSE service.
   */
  struct GNUNET_TESTBED_Operation *nse_op;

  /**
   * Testbed operation to connect to statistics service
   */
  struct GNUNET_TESTBED_Operation *stat_op;

  /**
   * Handle to the statistics service
   */
  struct GNUNET_STATISTICS_Handle *sh;
};


/**
 * Operation map entry
 */
struct OpListEntry
{
  /**
   * DLL next ptr
   */
  struct OpListEntry *next;

  /**
   * DLL prev ptr
   */
  struct OpListEntry *prev;

  /**
   * The testbed operation
   */
  struct GNUNET_TESTBED_Operation *op;

  /**
   * Depending on whether we start or stop NSE service at the peer set this to 1
   * or -1
   */
  int delta;
};


/**
 * Head of DLL of peers we monitor closely.
 */
static struct NSEPeer *peer_head;

/**
 * Tail of DLL of peers we monitor closely.
 */
static struct NSEPeer *peer_tail;

/**
 * Return value from 'main' (0 == success)
 */
static int ok;

/**
 * Be verbose (configuration option)
 */
static int verbose;

/**
 * Name of the file with the hosts to run the test over (configuration option)
 */
static char *hosts_file;

/**
 * Maximum number of peers in the test.
 */
static unsigned int num_peers;

/**
 * Total number of rounds to execute.
 */
static unsigned int num_rounds;

/**
 * Current round we are in.
 */
static unsigned int current_round;

/**
 * Array of size 'num_rounds' with the requested number of peers in the given round.
 */
static unsigned int *num_peers_in_round;

/**
 * How many peers are running right now?
 */
static unsigned int peers_running;

/**
 * Specification for the numbers of peers to have in each round.
 */
static char *num_peer_spec;

/**
 * Handles to all of the running peers.
 */
static struct GNUNET_TESTBED_Peer **daemons;

/**
 * Global configuration file
 */
static struct GNUNET_CONFIGURATION_Handle *testing_cfg;

/**
 * The shutdown task
 */
static struct GNUNET_SCHEDULER_Task * shutdown_task_id;

/**
 * Maximum number of connections to NSE services.
 */
static unsigned int connection_limit;

/**
 * Total number of connections in the whole network.
 */
static unsigned int total_connections;

/**
 * File to report results to.
 */
static struct GNUNET_DISK_FileHandle *output_file;

/**
 * Filename to log results to.
 */
static char *output_filename;

/**
 * File to log connection info, statistics to.
 */
static struct GNUNET_DISK_FileHandle *data_file;

/**
 * Filename to log connection info, statistics to.
 */
static char *data_filename;

/**
 * How long to wait before triggering next round?
 * Default: 60 s.
 */
static struct GNUNET_TIME_Relative wait_time = { 60 * 1000 };

/**
 * DLL head for operation list
 */
static struct OpListEntry *oplist_head;

/**
 * DLL tail for operation list
 */
static struct OpListEntry *oplist_tail;

/**
 * Are we shutting down
 */
static int shutting_down;


/**
 * Clean up all of the monitoring connections to NSE and
 * STATISTICS that we keep to selected peers.
 */
static void
close_monitor_connections ()
{
  struct NSEPeer *pos;
  struct OpListEntry *oplist_entry;

  while (NULL != (pos = peer_head))
  {
    if (NULL != pos->nse_op)
      GNUNET_TESTBED_operation_done (pos->nse_op);
    if (NULL != pos->stat_op)
      GNUNET_TESTBED_operation_done (pos->stat_op);
    GNUNET_CONTAINER_DLL_remove (peer_head, peer_tail, pos);
    GNUNET_free (pos);
  }
  while (NULL != (oplist_entry = oplist_head))
  {
    GNUNET_CONTAINER_DLL_remove (oplist_head, oplist_tail, oplist_entry);
    GNUNET_TESTBED_operation_done (oplist_entry->op);
    GNUNET_free (oplist_entry);
  }
}


/**
 * Task run on shutdown; cleans up everything.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  shutdown_task_id = NULL;
  if (GNUNET_YES == shutting_down)
    return;
  shutting_down = GNUNET_YES;
  LOG_DEBUG ("Ending test.\n");
  close_monitor_connections ();
  if (NULL != data_file)
  {
    GNUNET_DISK_file_close (data_file);
    data_file = NULL;
  }
  if (NULL != output_file)
  {
    GNUNET_DISK_file_close (output_file);
    output_file = NULL;
  }
  if (NULL != testing_cfg)
    GNUNET_CONFIGURATION_destroy (testing_cfg);
  testing_cfg = NULL;
}


/**
 * Schedules shutdown task to be run now
 */
static void
shutdown_now ()
{
  if (NULL != shutdown_task_id)
    GNUNET_SCHEDULER_cancel (shutdown_task_id);
  shutdown_task_id = GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
}


/**
 * Callback to call when network size estimate is updated.
 *
 * @param cls closure with the 'struct NSEPeer' providing the update
 * @param timestamp server timestamp
 * @param estimate the value of the current network size estimate
 * @param std_dev standard deviation (rounded down to nearest integer)
 *                of the size estimation values seen
 */
static void
handle_estimate (void *cls,
		 struct GNUNET_TIME_Absolute timestamp,
                 double estimate, double std_dev)
{
  struct NSEPeer *peer = cls;
  char output_buffer[512];
  size_t size;

  if (NULL == output_file)
    {
      FPRINTF (stderr,
	       "Received network size estimate from peer %p. Size: %f std.dev. %f\n",
	       peer, estimate, std_dev);
      return;
    }
  size = GNUNET_snprintf (output_buffer,
			  sizeof (output_buffer),
			  "%p %llu %llu %f %f %f\n",
			  peer, peers_running,
			  (unsigned long long) timestamp.abs_value_us,
			  GNUNET_NSE_log_estimate_to_n (estimate), estimate,
			  std_dev);
  if (size != GNUNET_DISK_file_write (output_file, output_buffer, size))
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		"Unable to write to file!\n");
}


/**
 * Adapter function called to establish a connection to
 * NSE service.
 *
 * @param cls closure (the 'struct NSEPeer')
 * @param cfg configuration of the peer to connect to; will be available until
 *          GNUNET_TESTBED_operation_done() is called on the operation returned
 *          from GNUNET_TESTBED_service_connect()
 * @return service handle to return in 'op_result', NULL on error
 */
static void *
nse_connect_adapter (void *cls,
		     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct NSEPeer *current_peer = cls;

  return GNUNET_NSE_connect (cfg, &handle_estimate, current_peer);
}


/**
 * Adapter function called to destroy a connection to
 * NSE service.
 *
 * @param cls closure
 * @param op_result service handle returned from the connect adapter
 */
static void
nse_disconnect_adapter (void *cls,
			void *op_result)
{
  GNUNET_NSE_disconnect (op_result);
}


/**
 * Callback function to process statistic values.
 *
 * @param cls `struct NSEPeer`
 * @param subsystem name of subsystem that created the statistic
 * @param name the name of the datum
 * @param value the current value
 * @param is_persistent #GNUNET_YES if the value is persistent, #GNUNET_NO if not
 * @return #GNUNET_OK to continue, #GNUNET_SYSERR to abort iteration
 */
static int
stat_iterator (void *cls,
	       const char *subsystem,
	       const char *name,
	       uint64_t value, int is_persistent)
{
  char *output_buffer;
  struct GNUNET_TIME_Absolute now;
  size_t size;
  unsigned int flag;

  GNUNET_assert (NULL != data_file);
  now = GNUNET_TIME_absolute_get ();
  flag = strcasecmp (subsystem, "core");
  if (0 != flag)
    flag = 1;
  size = GNUNET_asprintf (&output_buffer, "%llu %llu %u\n",
                          now.abs_value_us / 1000LL / 1000LL,
			  value, flag);
  if (size != GNUNET_DISK_file_write (data_file, output_buffer, size))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Unable to write to file!\n");
    GNUNET_free (output_buffer);
    return GNUNET_SYSERR;
  }
  GNUNET_free (output_buffer);
  return GNUNET_OK;
}


/**
 * Called to open a connection to the peer's statistics
 *
 * @param cls peer context
 * @param cfg configuration of the peer to connect to; will be available until
 *          GNUNET_TESTBED_operation_done() is called on the operation returned
 *          from GNUNET_TESTBED_service_connect()
 * @return service handle to return in 'op_result', NULL on error
 */
static void *
stat_connect_adapter (void *cls,
                      const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct NSEPeer *peer = cls;

  peer->sh = GNUNET_STATISTICS_create ("nse-profiler", cfg);
  return peer->sh;
}


/**
 * Called to disconnect from peer's statistics service
 *
 * @param cls peer context
 * @param op_result service handle returned from the connect adapter
 */
static void
stat_disconnect_adapter (void *cls, void *op_result)
{
  struct NSEPeer *peer = cls;

  GNUNET_break (GNUNET_OK == GNUNET_STATISTICS_watch_cancel
                (peer->sh, "core", "# peers connected",
                 stat_iterator, peer));
  GNUNET_break (GNUNET_OK == GNUNET_STATISTICS_watch_cancel
                (peer->sh, "nse", "# peers connected",
                 stat_iterator, peer));
  GNUNET_STATISTICS_destroy (op_result, GNUNET_NO);
  peer->sh = NULL;
}


/**
 * Called after successfully opening a connection to a peer's statistics
 * service; we register statistics monitoring for CORE and NSE here.
 *
 * @param cls the callback closure from functions generating an operation
 * @param op the operation that has been finished
 * @param ca_result the service handle returned from GNUNET_TESTBED_ConnectAdapter()
 * @param emsg error message in case the operation has failed; will be NULL if
 *          operation has executed successfully.
 */
static void
stat_comp_cb (void *cls, struct GNUNET_TESTBED_Operation *op,
              void *ca_result, const char *emsg )
{
  struct GNUNET_STATISTICS_Handle *sh = ca_result;
  struct NSEPeer *peer = cls;

  if (NULL != emsg)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_break (GNUNET_OK == GNUNET_STATISTICS_watch
                (sh, "core", "# peers connected",
                 stat_iterator, peer));
  GNUNET_break (GNUNET_OK == GNUNET_STATISTICS_watch
                (sh, "nse", "# peers connected",
                 stat_iterator, peer));
}


/**
 * Task run to connect to the NSE and statistics services to a subset of
 * all of the running peers.
 */
static void
connect_nse_service ()
{
  struct NSEPeer *current_peer;
  unsigned int i;
  unsigned int connections;

  if (0 == connection_limit)
    return;
  LOG_DEBUG ("Connecting to nse service of peers\n");
  connections = 0;
  for (i = 0; i < num_peers_in_round[current_round]; i++)
  {
    if ((num_peers_in_round[current_round] > connection_limit) &&
	(0 != (i % (num_peers_in_round[current_round] / connection_limit))))
      continue;
    LOG_DEBUG ("Connecting to nse service of peer %d\n", i);
    current_peer = GNUNET_new (struct NSEPeer);
    current_peer->daemon = daemons[i];
    current_peer->nse_op
        = GNUNET_TESTBED_service_connect (NULL,
                                          current_peer->daemon,
                                          "nse",
                                          NULL, NULL,
                                          &nse_connect_adapter,
                                          &nse_disconnect_adapter,
                                          current_peer);
    if (NULL != data_file)
      current_peer->stat_op
          = GNUNET_TESTBED_service_connect (NULL,
                                            current_peer->daemon,
                                            "statistics",
                                            stat_comp_cb,
                                            current_peer,
                                            &stat_connect_adapter,
                                            &stat_disconnect_adapter,
                                            current_peer);
    GNUNET_CONTAINER_DLL_insert (peer_head, peer_tail, current_peer);
    if (++connections == connection_limit)
      break;
  }
}


/**
 * Task that starts/stops peers to move to the next round.
 *
 * @param cls NULL, unused
 * @param tc scheduler context (unused)
 */
static void
next_round (void *cls,
	    const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * We're at the end of a round.  Stop monitoring, write total
 * number of connections to log and get full stats.  Then trigger
 * the next round.
 *
 * @param cls unused, NULL
 * @param tc unused
 */
static void
finish_round (void *cls,
	      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    return;
  LOG (GNUNET_ERROR_TYPE_INFO, "Have %u connections\n", total_connections);
  close_monitor_connections ();
  GNUNET_SCHEDULER_add_now (&next_round, NULL);
}


/**
 * We have reached the desired number of peers for the current round.
 * Run it (by connecting and monitoring a few peers and waiting the
 * specified delay before finishing the round).
 */
static void
run_round ()
{
  LOG_DEBUG ("Running round %u\n", current_round);
  connect_nse_service ();
  GNUNET_SCHEDULER_add_delayed (wait_time,
				&finish_round,
				NULL);
}


/**
 * Creates an oplist entry and adds it to the oplist DLL
 */
static struct OpListEntry *
make_oplist_entry ()
{
  struct OpListEntry *entry;

  entry = GNUNET_new (struct OpListEntry);
  GNUNET_CONTAINER_DLL_insert_tail (oplist_head, oplist_tail, entry);
  return entry;
}


/**
 * Callback to be called when NSE service is started or stopped at peers
 *
 * @param cls NULL
 * @param op the operation handle
 * @param emsg NULL on success; otherwise an error description
 */
static void
manage_service_cb (void *cls, struct GNUNET_TESTBED_Operation *op,
                   const char *emsg)
{
  struct OpListEntry *entry = cls;

  GNUNET_TESTBED_operation_done (entry->op);
  if (NULL != emsg)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, "Failed to start/stop NSE at a peer\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_assert (0 != entry->delta);
  peers_running += entry->delta;
  GNUNET_CONTAINER_DLL_remove (oplist_head, oplist_tail, entry);
  GNUNET_free (entry);
  if (num_peers_in_round[current_round] == peers_running)
    run_round ();
}


/**
 * Adjust the number of running peers to match the required number of running
 * peers for the round
 */
static void
adjust_running_peers ()
{
  struct OpListEntry *entry;
  unsigned int i;

  /* start peers if we have too few */
  for (i=peers_running;i<num_peers_in_round[current_round];i++)
  {
    entry = make_oplist_entry ();
    entry->delta = 1;
    entry->op = GNUNET_TESTBED_peer_manage_service (NULL,
                                                    daemons[i],
                                                    "nse",
                                                    &manage_service_cb,
                                                    entry,
                                                    1);
  }
  /* stop peers if we have too many */
  for (i=num_peers_in_round[current_round];i<peers_running;i++)
  {
    entry = make_oplist_entry ();
    entry->delta = -1;
    entry->op =  GNUNET_TESTBED_peer_manage_service (NULL,
                                                     daemons[i],
                                                     "nse",
                                                     &manage_service_cb,
                                                     entry,
                                                     0);
  }
}


/**
 * Task run at the end of a round.  Disconnect from all monitored
 * peers; then get statistics from *all* peers.
 *
 * @param cls NULL, unused
 * @param tc unused
 */
static void
next_round (void *cls,
	    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    return;
  LOG_DEBUG ("Disconnecting nse service of peers\n");
  current_round++;
  if (current_round == num_rounds)
    {
      /* this was the last round, terminate */
      ok = 0;
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
  if (num_peers_in_round[current_round] == peers_running)
    {
      /* no need to churn, just run next round */
      run_round ();
      return;
    }
  adjust_running_peers ();
}


/**
 * Function that will be called whenever something in the
 * testbed changes.
 *
 * @param cls closure, NULL
 * @param event information on what is happening
 */
static void
master_controller_cb (void *cls,
		      const struct GNUNET_TESTBED_EventInformation *event)
{
  switch (event->type)
    {
    case GNUNET_TESTBED_ET_CONNECT:
      total_connections++;
      break;
    case GNUNET_TESTBED_ET_DISCONNECT:
      total_connections--;
      break;
    default:
      break;
    }
}


/**
 * Signature of a main function for a testcase.
 *
 * @param cls NULL
 * @param h the run handle
 * @param num_peers_ number of peers in 'peers'
 * @param peers handle to peers run in the testbed.  NULL upon timeout (see
 *          GNUNET_TESTBED_test_run()).
 * @param links_succeeded the number of overlay link connection attempts that
 *          succeeded
 * @param links_failed the number of overlay link connection attempts that
 *          failed
 */
static void
test_master (void *cls,
             struct GNUNET_TESTBED_RunHandle *h,
             unsigned int num_peers_,
             struct GNUNET_TESTBED_Peer **peers,
             unsigned int links_succeeded,
             unsigned int links_failed)
{
  if (NULL == peers)
  {
    shutdown_now ();
    return;
  }
  daemons = peers;
  GNUNET_break (num_peers_ == num_peers);
  peers_running = num_peers;
  if (num_peers_in_round[current_round] == peers_running)
  {
    /* no need to churn, just run the starting round */
    run_round ();
    return;
  }
  adjust_running_peers ();
}


/**
 * Actual main function that runs the emulation.
 *
 * @param cls unused
 * @param args remaining args, unused
 * @param cfgfile name of the configuration
 * @param cfg configuration handle
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char *tok;
  uint64_t event_mask;
  unsigned int num;

  ok = 1;
  testing_cfg = GNUNET_CONFIGURATION_dup (cfg);
  LOG_DEBUG ("Starting daemons.\n");
  if (NULL == num_peer_spec)
  {
    fprintf (stderr, "You need to specify the number of peers to run\n");
    return;
  }
  for (tok = strtok (num_peer_spec, ","); NULL != tok; tok = strtok (NULL, ","))
    {
      if (1 != sscanf (tok, "%u", &num))
	{
	  fprintf (stderr, "You need to specify numbers, not `%s'\n", tok);
	  return;
	}
      if (0 == num)
	{
	  fprintf (stderr, "Refusing to run a round with 0 peers\n");
	  return;
	}
      GNUNET_array_append (num_peers_in_round, num_rounds, num);
      num_peers = GNUNET_MAX (num_peers, num);
    }
  if (0 == num_peers)
    {
      fprintf (stderr, "Refusing to run a testbed with no rounds\n");
      return;
    }
  if ( (NULL != data_filename) &&
       (NULL == (data_file =
		 GNUNET_DISK_file_open (data_filename,
					GNUNET_DISK_OPEN_READWRITE |
					GNUNET_DISK_OPEN_TRUNCATE |
					GNUNET_DISK_OPEN_CREATE,
					GNUNET_DISK_PERM_USER_READ |
					GNUNET_DISK_PERM_USER_WRITE))) )
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
			      "open",
			      data_filename);

  if ( (NULL != output_filename) &&
       (NULL == (output_file =
		 GNUNET_DISK_file_open (output_filename,
					GNUNET_DISK_OPEN_READWRITE |
					GNUNET_DISK_OPEN_CREATE,
					GNUNET_DISK_PERM_USER_READ |
					GNUNET_DISK_PERM_USER_WRITE))) )
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "open",
			      output_filename);
  event_mask = 0LL;
  event_mask |= (1LL << GNUNET_TESTBED_ET_PEER_START);
  event_mask |= (1LL << GNUNET_TESTBED_ET_PEER_STOP);
  event_mask |= (1LL << GNUNET_TESTBED_ET_CONNECT);
  event_mask |= (1LL << GNUNET_TESTBED_ET_DISCONNECT);
  GNUNET_TESTBED_run (hosts_file,
                      cfg,
                      num_peers,
                      event_mask,
                      master_controller_cb,
                      NULL,     /* master_controller_cb cls */
                      &test_master,
                      NULL);    /* test_master cls */
  shutdown_task_id =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                    &shutdown_task, NULL);
}


/**
 * Main function.
 *
 * @return 0 on success
 */
int
main (int argc, char *const *argv)
{
  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'C', "connections", "COUNT",
     gettext_noop ("limit to the number of connections to NSE services, 0 for none"),
     1, &GNUNET_GETOPT_set_uint, &connection_limit},
    {'d', "details", "FILENAME",
     gettext_noop ("name of the file for writing connection information and statistics"),
     1, &GNUNET_GETOPT_set_string, &data_filename},
    {'H', "hosts", "FILENAME",
     gettext_noop ("name of the file with the login information for the testbed"),
     1, &GNUNET_GETOPT_set_string, &hosts_file},
    {'o', "output", "FILENAME",
     gettext_noop ("name of the file for writing the main results"),
     1, &GNUNET_GETOPT_set_string, &output_filename},
    {'p', "peers", "NETWORKSIZESPEC",
     gettext_noop ("Number of peers to run in each round, separated by commas"),
     1, &GNUNET_GETOPT_set_string, &num_peer_spec},
    {'V', "verbose", NULL,
     gettext_noop ("be verbose (print progress information)"),
     0, &GNUNET_GETOPT_increment_value, &verbose},
    {'w', "wait", "DELAY",
     gettext_noop ("delay between rounds"),
     1, &GNUNET_GETOPT_set_relative_time, &wait_time},
    GNUNET_GETOPT_OPTION_END
  };
  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;
  if (GNUNET_OK !=
      GNUNET_PROGRAM_run (argc, argv, "nse-profiler",
			  gettext_noop
			  ("Measure quality and performance of the NSE service."),
			  options, &run, NULL))
    ok = 1;
  return ok;
}

/* end of nse-profiler.c */
