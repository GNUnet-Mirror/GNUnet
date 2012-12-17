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
 *
 * TODO:
 * - need to enable user to specify topology options
 * - need to check for leaks (especially FD leaks)
 * - need to TEST
 */
#include "platform.h"
#include "gnunet_testbed_service.h"
#include "gnunet_nse_service.h"


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
   * Handle to statistics service of the peer.
   */
  struct GNUNET_STATISTICS_Handle *stats;

  /**
   * Testbed operation to connect to statistics service.
   */
  struct GNUNET_TESTBED_Operation *stats_op;
  
  /**
   * Task scheduled to get statistics from this peer.
   */
  GNUNET_SCHEDULER_TaskIdentifier stats_task;
};


/**
 * Context for the stats task?
 */
struct StatsContext
{

  /**
   * How many messages have peers received during the test.
   */
  unsigned long long total_nse_received_messages;

  /**
   * How many messages have peers send during the test (should be == received).
   */
  unsigned long long total_nse_transmitted_messages;

  /**
   * How many messages have travelled an edge in both directions.
   */
  unsigned long long total_nse_cross;

  /**
   * How many extra messages per edge (corrections) have been received.
   */
  unsigned long long total_nse_extra;

  /**
   * How many messages have been discarded.
   */
  unsigned long long total_discarded;
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
 * IP address of this system, as seen by the rest of the system (configuration option)
 */
static char *controller_ip;

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
 * How often do we query for statistics during a round?
 * Default: 1 s.
 */
static struct GNUNET_TIME_Relative interval = { 1000 };

/**
 * Name of the file where we write the topology for each round; NULL for
 * none.
 */
static char *topology_file;

/**
 * List of hosts we use for the testbed.
 */
static struct GNUNET_TESTBED_Host **hosts;

/**
 * Size of the 'hosts' array.
 */
static unsigned int num_hosts;

/**
 * Handle to the master controller.
 */
static struct GNUNET_TESTBED_Controller *controller;

/**
 * Controller start handle.
 */
static struct GNUNET_TESTBED_ControllerProc *copro;

/* /\** */
/*  * Testbed handle. */
/*  *\/ */
/* static struct GNUNET_TESTBED_Testbed *testbed; */


/**
 * Clean up all of the monitoring connections to NSE and
 * STATISTICS that we keep to selected peers.
 */
static void
close_monitor_connections ()
{
  struct NSEPeer *pos;

  while (NULL != (pos = peer_head))
  {
    if (NULL != pos->nse_op)
      GNUNET_TESTBED_operation_done (pos->nse_op);
    if (NULL != pos->stats_op)
      GNUNET_TESTBED_operation_done (pos->stats_op);
    GNUNET_CONTAINER_DLL_remove (peer_head, peer_tail, pos);
    if (GNUNET_SCHEDULER_NO_TASK != pos->stats_task)
      GNUNET_SCHEDULER_cancel (pos->stats_task);
    GNUNET_free (pos);
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Ending test.\n");    
  close_monitor_connections ();
  /* if (NULL != testbed) */
  /*   GNUNET_TESTBED_destroy (testbed); */
  if (NULL != controller)
    GNUNET_TESTBED_controller_disconnect (controller);
  if (NULL != copro)
      GNUNET_TESTBED_controller_stop (copro);
  while (0 < num_hosts)
    GNUNET_TESTBED_host_destroy (hosts[--num_hosts]);
  // FIXME: what about closing other files!?
  if (NULL != data_file)
    GNUNET_DISK_file_close (data_file);
}


/**
 * Callback to call when network size estimate is updated.
 *
 * @param cls closure with the 'struct NSEPeer' providing the update
 * @param timestamp server timestamp
 * @param estimate the value of the current network size estimate
 * @param std_dev standard deviation (rounded down to nearest integer)
 *                of the size estimation values seen
 *
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
			  timestamp.abs_value,
			  GNUNET_NSE_log_estimate_to_n (estimate), estimate,
			  std_dev);
  if (size != GNUNET_DISK_file_write (output_file, output_buffer, size))
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		"Unable to write to file!\n");
}


/**
 * Process core statistic values.
 *
 * @param cls closure
 * @param subsystem name of subsystem that created the statistic
 * @param name the name of the datum
 * @param value the current value
 * @param is_persistent GNUNET_YES if the value is persistent, GNUNET_NO if not
 * @return GNUNET_OK to continue, GNUNET_SYSERR to abort iteration
 */
static int
core_stats_iterator (void *cls, const char *subsystem, const char *name,
                     uint64_t value, int is_persistent)
{
  struct NSEPeer *peer = cls;
  char output_buffer[512];
  size_t size;

  if (NULL == output_file)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  "%p -> %s [%s]: %llu\n",
		  peer, subsystem, name, value);
      return GNUNET_OK;
    }
  size =
    GNUNET_snprintf (output_buffer,
		     sizeof (output_buffer),
		     "%p [%s] %s %llu\n",
		     peer,
		     subsystem, name, value);
  if (size != GNUNET_DISK_file_write (output_file, output_buffer, size))
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Unable to write to file!\n");
  return GNUNET_OK;
}


/**
 * Continuation called by "get_stats" function once we are done.
 *
 * @param cls closure
 * @param success GNUNET_OK if statistics were
 *        successfully obtained, GNUNET_SYSERR if not.
 */
static void
core_stats_cont (void *cls, int success);


/**
 * Function invoked periodically to get the statistics.
 *
 * @param cls 'struct NSEPeer' to get stats from
 * @param tc scheduler context
 */
static void
core_get_stats (void *cls,
		const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct NSEPeer *peer = cls;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    GNUNET_TESTBED_operation_done (peer->stats_op);
    peer->stats = NULL;
    peer->stats_op = NULL;
    return;
  }
  /* FIXME: code duplication! */
  GNUNET_STATISTICS_get (peer->stats, "core", NULL,
			 GNUNET_TIME_UNIT_FOREVER_REL,
			 &core_stats_cont, 
			 &core_stats_iterator, peer);
  GNUNET_STATISTICS_get (peer->stats, "transport", NULL,
			 GNUNET_TIME_UNIT_FOREVER_REL,
			 NULL,
			 &core_stats_iterator, peer);
  GNUNET_STATISTICS_get (peer->stats, "nse", NULL,
			 GNUNET_TIME_UNIT_FOREVER_REL,
			 NULL, 
			 &core_stats_iterator, peer);
  peer->stats_task = GNUNET_SCHEDULER_NO_TASK;
}


/**
 * Continuation called by "get_stats" function.
 *
 * @param cls closure
 * @param success GNUNET_OK if statistics were
 *        successfully obtained, GNUNET_SYSERR if not.
 */
static void
core_stats_cont (void *cls, 
		 int success)
{
  struct NSEPeer *peer = cls;

  if (GNUNET_OK != success)
    return;
  peer->stats_task = GNUNET_SCHEDULER_add_delayed (interval,
						   &core_get_stats, peer);
}


/**
 * Adapter function called to establish a connection to
 * statistics service.
 * 
 * @param cls closure
 * @param cfg configuration of the peer to connect to; will be available until
 *          GNUNET_TESTBED_operation_done() is called on the operation returned
 *          from GNUNET_TESTBED_service_connect()
 * @return service handle to return in 'op_result', NULL on error
 */
static void *
statistics_connect_adapter (void *cls,
			    const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  return GNUNET_STATISTICS_create ("<driver>",
				   cfg);
}


/**
 * Adapter function called to destroy a connection to
 * statistics service.
 * 
 * @param cls closure
 * @param op_result service handle returned from the connect adapter
 */
static void 
statistics_disconnect_adapter (void *cls,
			       void *op_result)
{
  GNUNET_STATISTICS_destroy (op_result, GNUNET_NO);
}


/**
 * Function called by testbed once we are connected to stats service.
 *
 * @param cls the 'struct NSEPeer' for which we connected to stats
 * @param op connect operation handle
 * @param ca_result handle to stats service
 * @param emsg error message on failure
 */
static void
stat_run (void *cls, 
	  struct GNUNET_TESTBED_Operation *op,
	  void *ca_result,
	  const char *emsg)
{
  struct NSEPeer *current_peer = cls;

  if (NULL == ca_result)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  "Failed to connect to statistics service: %s\n",
		  emsg);
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
  current_peer->stats = ca_result;
  GNUNET_STATISTICS_get (current_peer->stats, "core", NULL,
			 GNUNET_TIME_UNIT_FOREVER_REL,
			 &core_stats_cont, 
			 &core_stats_iterator, current_peer);
  GNUNET_STATISTICS_get (current_peer->stats, "transport", NULL,
			 GNUNET_TIME_UNIT_FOREVER_REL,
			 NULL, 
			 &core_stats_iterator, current_peer);
  GNUNET_STATISTICS_get (current_peer->stats, "nse", NULL,
			 GNUNET_TIME_UNIT_FOREVER_REL,
			 NULL, 
			 &core_stats_iterator, current_peer);
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
 * Task run to connect to the NSE and statistics services to a subset of
 * all of the running peers.
 */
static void
connect_nse_service ()
{
  struct NSEPeer *current_peer;
  unsigned int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connecting to nse service of peers\n");
  for (i = 0; i < num_peers; i++)
  {
    if ((connection_limit > 0) &&
	(num_peers > connection_limit) && 
	(0 != (i % (num_peers / connection_limit))))
      continue;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "nse-profiler: connecting to nse service of peer %d\n", i);
    current_peer = GNUNET_malloc (sizeof (struct NSEPeer));
    current_peer->daemon = daemons[i];
    current_peer->nse_op 
      = GNUNET_TESTBED_service_connect (NULL,
					current_peer->daemon,
					"nse",
					NULL, NULL,
					&nse_connect_adapter,
					&nse_disconnect_adapter,
					current_peer);	
    current_peer->stats_op 
      = GNUNET_TESTBED_service_connect (NULL,
					current_peer->daemon,
					"statistics",
					&stat_run, current_peer,
					&statistics_connect_adapter,
					&statistics_disconnect_adapter,
					NULL);  
    GNUNET_CONTAINER_DLL_insert (peer_head, peer_tail, current_peer);
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
 * Continuation called by the "get_all" and "get" functions at the
 * end of a round.  Obtains the final statistics and writes them to
 * the file, then either starts the next round, or, if this was the
 * last round, terminates the run.
 *
 * @param cls struct StatsContext
 * @param op operation handle
 * @param emsg error message, NULL on success
 */
static void
stats_finished_callback (void *cls,
			 struct GNUNET_TESTBED_Operation *op,
			 const char *emsg)
{
  struct StatsContext *stats_context = cls;
  char buf[512];
  size_t buf_len;

  if (NULL != emsg)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  "Failed to get statistics: %s\n",
		  emsg);
      GNUNET_SCHEDULER_shutdown ();
      GNUNET_free (stats_context);
      return;
    }
  if (NULL != data_file)
    {
      /* Stats lookup successful, write out data */
      buf_len =
	GNUNET_snprintf (buf, sizeof (buf),
			 "TOTAL_NSE_RECEIVED_MESSAGES_%u: %u \n",
			 current_round,
                         stats_context->total_nse_received_messages);
      GNUNET_DISK_file_write (data_file, buf, buf_len);
      buf_len =
	GNUNET_snprintf (buf, sizeof (buf),
			 "TOTAL_NSE_TRANSMITTED_MESSAGES_%u: %u\n",
			 current_round,
			 stats_context->total_nse_transmitted_messages);
      GNUNET_DISK_file_write (data_file, buf, buf_len);    
      buf_len =
	GNUNET_snprintf (buf, sizeof (buf),
			 "TOTAL_NSE_CROSS_%u: %u \n",
			 current_round,
			 stats_context->total_nse_cross);
      GNUNET_DISK_file_write (data_file, buf, buf_len);
      buf_len =
	GNUNET_snprintf (buf, sizeof (buf),
			 "TOTAL_NSE_EXTRA_%u: %u \n",
			 current_round,
			 stats_context->total_nse_extra);
      GNUNET_DISK_file_write (data_file, buf, buf_len);
      buf_len =
	GNUNET_snprintf (buf, sizeof (buf),
			 "TOTAL_NSE_DISCARDED_%u: %u \n",
			 current_round,
			 stats_context->total_discarded);
      GNUNET_DISK_file_write (data_file, buf, buf_len);    
    }  
  GNUNET_SCHEDULER_add_now (&next_round, NULL);
  GNUNET_free (stats_context);
}


/**
 * Callback function to process statistic values.
 *
 * @param cls struct StatsContext
 * @param peer the peer the statistics belong to
 * @param subsystem name of subsystem that created the statistic
 * @param name the name of the datum
 * @param value the current value
 * @param is_persistent GNUNET_YES if the value is persistent, GNUNET_NO if not
 * @return GNUNET_OK to continue, GNUNET_SYSERR to abort iteration
 */
static int
statistics_iterator (void *cls, 
		     const struct GNUNET_TESTBED_Peer *peer,
                     const char *subsystem, const char *name, uint64_t value,
                     int is_persistent)
{
  struct StatsContext *stats_context = cls;
  char buf[512];
  size_t buf_len;

  if (0 != strcmp (subsystem, "nse"))
    return GNUNET_OK;
  if (0 == strcmp (name, "# flood messages received"))
    {
      stats_context->total_nse_received_messages += value;
      if ( (verbose > 1) && 
	   (NULL != data_file) )
	{
	  buf_len =
            GNUNET_snprintf (buf, sizeof (buf),
			     "%p %u RECEIVED\n", 
			     peer, value);
	  GNUNET_DISK_file_write (data_file, buf, buf_len);
	}
    }
  if (0 == strcmp (name, "# flood messages transmitted"))
    {
      stats_context->total_nse_transmitted_messages += value;
      if ( (verbose > 1) &&
	   (NULL != data_file) )
	{
	  buf_len =
            GNUNET_snprintf (buf, sizeof (buf),
			     "%p %u TRANSMITTED\n", 
                             peer, value);
	  GNUNET_DISK_file_write (data_file, buf, buf_len);
	}
    }
  if (0 == strcmp (name, "# cross messages"))
    stats_context->total_nse_cross += value;    
  if (0 == strcmp (name, "# extra messages"))    
    stats_context->total_nse_extra += value;
  if (0 == strcmp (name, "# flood messages discarded (clock skew too large)"))
    stats_context->total_discarded += value;    
  return GNUNET_OK;
}


/**
 * Function called upon completion of the node start/stop operations
 * for the current round.  Writes the new topology to disk.
 */
static void
write_topology ()
{
  char temp_output_file[1024];

  if (NULL != topology_file)
    {
      GNUNET_snprintf (temp_output_file, sizeof (temp_output_file),
		       "%s_%llu.dot", 
		       topology_file, current_round);
      GNUNET_TESTBED_overlay_write_topology_to_file (controller,
						     temp_output_file);
    }
}


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
  struct StatsContext *stats_context;
  char buf[1024];
  size_t buf_len;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
	      "Have %u connections\n",
              total_connections);
  if (NULL != data_file)
    {
      buf_len = GNUNET_snprintf (buf, sizeof (buf),
				 "CONNECTIONS_0: %u\n", 
				 total_connections);
      GNUNET_DISK_file_write (data_file, buf, buf_len);
    }
  close_monitor_connections ();    
  stats_context = GNUNET_malloc (sizeof (struct StatsContext));
  GNUNET_TESTBED_get_statistics (num_peers_in_round[current_round], 
				 daemons,				 
				 &statistics_iterator,
				 &stats_finished_callback,
				 stats_context);
}


/**
 * We have reached the desired number of peers for the current round.
 * Run it (by connecting and monitoring a few peers and waiting the
 * specified delay before finishing the round).
 */
static void
run_round ()
{
  write_topology ();
  connect_nse_service ();
  GNUNET_SCHEDULER_add_delayed (wait_time,
				&finish_round,
				NULL);
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
  unsigned int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "disconnecting nse service of peers\n");
  current_round++;
  
  if (current_round == num_rounds)
    {
      /* this was the last round, terminate */
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
  if (num_peers_in_round[current_round] == peers_running)
    {
      /* no need to churn, just run next round */
      run_round ();
      return;
    }

  /* start peers if we have too few */
  for (i=peers_running;i<num_peers_in_round[current_round];i++)
    GNUNET_TESTBED_peer_start (NULL, daemons[i], NULL, NULL);

  /* stop peers if we have too many */
  for (i=num_peers_in_round[current_round];i<peers_running;i++)
    GNUNET_TESTBED_peer_stop (daemons[i], NULL, NULL);
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
    case GNUNET_TESTBED_ET_PEER_START:
      peers_running++;
      if (num_peers_in_round[current_round] == peers_running)
	run_round ();
      break;
    case GNUNET_TESTBED_ET_PEER_STOP:
      peers_running--;
      if (num_peers_in_round[current_round] == peers_running)
	run_round ();
      break;
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


static void
controller_start_cb (void *cls,
		     const struct GNUNET_CONFIGURATION_Handle *cfg,
		     int status)
{
  if (GNUNET_OK != status)
    {
      copro = NULL;
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
  num_hosts = GNUNET_TESTBED_hosts_load_from_file (hosts_file,
						   &hosts);
  if (0 == num_hosts)
    {
      fprintf (stderr,
	       "Failed to read host information from `%s'\n", 
	       hosts_file);
      return;
    }
  controller = GNUNET_TESTBED_controller_connect (cfg,
					       NULL, 
					       0 /* mask */,
					       &master_controller_cb, NULL);

  /* testbed = GNUNET_TESTBED_create (controller, */
  /*       			   num_hosts, hosts,  */
  /*       			   num_peers, */
  /*       			   cfg, */
  /*       			   0 /\* FIXME: topology *\/, */
  /*       			   NULL /\* FIXME: topology options *\/); */
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
  unsigned int num;

  ok = 1;
  testing_cfg = GNUNET_CONFIGURATION_dup (cfg);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting daemons.\n");
  if (verbose)
    GNUNET_CONFIGURATION_set_value_string (testing_cfg, "testing",
					   "use_progressbars", "YES");
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
      GNUNET_array_grow (num_peers_in_round, num_rounds, num);
      num_peers = GNUNET_MAX (num_peers, num);
    }
  if (0 == num_peers)
    {
      fprintf (stderr, "Refusing to run a testbed with no rounds\n");
      return;
    }
  daemons = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_Peer*) * num_peers); 
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

  if (NULL ==
      (copro = GNUNET_TESTBED_controller_start (controller_ip, NULL,
						cfg,
						&controller_start_cb, NULL)))
    {
      fprintf (stderr,
	       "Failed to start controller\n");
      return;
    }
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
     1, &GNUNET_GETOPT_set_string, &num_peer_spec},
    {'d', "details", "FILENAME",
     gettext_noop ("name of the file for writing connection information and statistics"),
     1, &GNUNET_GETOPT_set_string, &data_filename},
    {'H', "hosts", "FILENAME",
     gettext_noop ("name of the file with the login information for the testbed"),
     1, &GNUNET_GETOPT_set_string, &hosts_file},
    {'i', "ip", "CONTROLLER_IP",
     gettext_noop ("IP address of this system as seen by the rest of the testbed"),
     1, &GNUNET_GETOPT_set_string, &controller_ip},
    {'I', "interval", "DELAY",
     gettext_noop ("delay between queries to statistics during a round"),
     1, &GNUNET_GETOPT_set_relative_time, &interval},
    {'t', "topology", "FILENAME",
     gettext_noop ("prefix of the filenames we use for writing the topology for each round"),
     1, &GNUNET_GETOPT_set_string, &topology_file},
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
  GNUNET_log_setup ("nse-profiler", "WARNING", NULL);
  if (GNUNET_OK !=
      GNUNET_PROGRAM_run (argc, argv, "nse-profiler",
			  gettext_noop
			  ("Measure quality and performance of the NSE service."),
			  options, &run, NULL))
    ok = 1;
  return ok;
}

/* end of nse-profiler.c */
