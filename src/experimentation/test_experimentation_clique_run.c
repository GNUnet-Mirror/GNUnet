/*
  This file is part of GNUnet
  (C) 2008--2013 Christian Grothoff (and other contributing authors)

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
 * @file src/experimentation/test_experimentation_clique_run.c
 * @brief test case to run experiments with experimentation daemons in a clique
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 * @author Matthias Wachs
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_testbed_service.h"


/**
 * Number of peers we want to start
 */
#define NUM_PEERS 2

#define NUM_ISSUER 1

#define NUM_EXPERIMENTS 2

#define TEST_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, (5 * NUM_PEERS) + 20)

/**
 * Array of peers
 */
static struct GNUNET_TESTBED_Peer **peers;

/**
 * Operation handle
 */
static struct GNUNET_TESTBED_Operation *op;

/**
 * Shutdown task
 */
static GNUNET_SCHEDULER_TaskIdentifier shutdown_task;

/**
 * Testing result
 */
static int result;

/**
 * Counter for counting overlay connections
 */
static unsigned int overlay_connects;

/**
 * Information we track for a peer in the testbed.
 */
struct ExperimentationPeer
{
  /**
   * Handle with testbed.
   */
  struct GNUNET_TESTBED_Peer *daemon;

  /**
   * Testbed operation to connect to statistics service
   */
  struct GNUNET_TESTBED_Operation *stat_op;

  /**
   * Handle to the statistics service
   */
  struct GNUNET_STATISTICS_Handle *sh;

  unsigned int active_nodes;
  unsigned int requested_nodes;
  unsigned int inactive_nodes;
  unsigned int issuer;
  unsigned int experiments_active;
  unsigned int experiments_running;
};


struct ExperimentationPeer ph[NUM_PEERS];

/**
 * Shutdown nicely
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  unsigned int peer;
	shutdown_task = GNUNET_SCHEDULER_NO_TASK;

  for (peer = 0; peer < NUM_PEERS; peer++)
  {
  	if (NULL != ph[peer].stat_op)
  		GNUNET_TESTBED_operation_done (ph[peer].stat_op);
  	ph[peer].stat_op = NULL;
  }

  if (NULL != op)
  {
    GNUNET_TESTBED_operation_done (op);
    op = NULL;
  }
  GNUNET_SCHEDULER_shutdown ();
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
  switch (event->type)
  {
  case GNUNET_TESTBED_ET_CONNECT:
    overlay_connects++;
    if ((NUM_PEERS * (NUM_PEERS - 1)) == overlay_connects)
    {
      result = GNUNET_OK;
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "All %u peers connected \n", NUM_PEERS);
      if (GNUNET_SCHEDULER_NO_TASK != shutdown_task)
      {
      		GNUNET_SCHEDULER_cancel (shutdown_task);
      }
      shutdown_task = GNUNET_SCHEDULER_add_delayed (TEST_TIMEOUT, do_shutdown, NULL);
    }
    break;
  case GNUNET_TESTBED_ET_OPERATION_FINISHED:
    break;
  default:
    GNUNET_break (0);
    result = GNUNET_SYSERR;
    GNUNET_SCHEDULER_cancel (shutdown_task);
    shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
  }
}

static void
check_end ()
{

	static int last_experiments_value = 0;
  unsigned int peer;
  unsigned int t_running_experiments = 0;

	for (peer = 0; peer < NUM_PEERS; peer++)
	{
		t_running_experiments += ph[peer].experiments_running;
	}

	if (last_experiments_value < t_running_experiments)
		fprintf (stderr, ".");
	last_experiments_value = t_running_experiments;

	if (t_running_experiments == (NUM_PEERS * NUM_EXPERIMENTS))
	{
			fprintf (stderr, "\n");
			GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "All %u peers are running experiments\n", NUM_PEERS);
			GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
	}
}



/**
 * Callback function to process statistic values.
 *
 * @param cls struct StatsContext
 * @param subsystem name of subsystem that created the statistic
 * @param name the name of the datum
 * @param value the current value
 * @param is_persistent GNUNET_YES if the value is persistent, GNUNET_NO if not
 * @return GNUNET_OK to continue, GNUNET_SYSERR to abort iteration
 */
static int
stat_iterator (void *cls, const char *subsystem, const char *name,
                     uint64_t value, int is_persistent)
{
  struct ExperimentationPeer *peer = cls;

	if (0 == strcmp (name, "# experiments active"))
	{
			peer->experiments_active = value;
	}

	if (0 == strcmp (name, "# experiments running"))
	{
			peer->experiments_running = value;
	}

	check_end ();

	return GNUNET_OK;
}

/**
 * Called after successfully opening a connection to a peer's statistics
 * service; we register statistics monitoring here.
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
  //struct GNUNET_STATISTICS_Handle *sh = ca_result;
  struct ExperimentationPeer *peer = cls;

  if (NULL != emsg)
  {
    GNUNET_break (0);
    return;
  }

  GNUNET_break (GNUNET_OK == GNUNET_STATISTICS_watch
                (peer->sh, "experimentation", "# experiments active",
                 stat_iterator, peer));
  GNUNET_break (GNUNET_OK == GNUNET_STATISTICS_watch
                (peer->sh, "experimentation", "# experiments running",
                 stat_iterator, peer));
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
  struct ExperimentationPeer *peer = cls;
  peer->sh = GNUNET_STATISTICS_create ("experimentation", cfg);
  if (NULL == peer->sh)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to create statistics \n");
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
  struct ExperimentationPeer *peer = cls;
  GNUNET_break (GNUNET_OK == GNUNET_STATISTICS_watch_cancel
                (peer->sh, "experimentation", "# experiments active",
                 stat_iterator, peer));
  GNUNET_break (GNUNET_OK == GNUNET_STATISTICS_watch_cancel
                (peer->sh, "experimentation", "# experiments running",
                 stat_iterator, peer));
  GNUNET_STATISTICS_destroy (op_result, GNUNET_NO);
  peer->sh = NULL;
}



/**
 * Signature of a main function for a testcase.
 *
 * @param cls closure
 * @param num_peers number of peers in 'peers'
 * @param peers_ handle to peers run in the testbed
 * @param links_succeeded the number of overlay link connection attempts that
 *          succeeded
 * @param links_failed the number of overlay link connection attempts that
 *          failed
 */
static void
test_master (void *cls, unsigned int num_peers,
             struct GNUNET_TESTBED_Peer **peers_,
             unsigned int links_succeeded,
             unsigned int links_failed)
{
  unsigned int peer;

  GNUNET_assert (NULL == cls);
  GNUNET_assert (NUM_PEERS == num_peers);
  GNUNET_assert (NULL != peers_);
  for (peer = 0; peer < num_peers; peer++)
  {
    GNUNET_assert (NULL != peers_[peer]);
    /* Connect to peer's statistic service */
    ph[peer].stat_op = GNUNET_TESTBED_service_connect (NULL,
    																peers_[peer], "statistics",
    																&stat_comp_cb, &ph[peer],
                                    &stat_connect_adapter,
                                    &stat_disconnect_adapter,
                                    &ph[peer]);

  }
  peers = peers_;
  overlay_connects = 0;
  op = GNUNET_TESTBED_overlay_configure_topology (NULL, NUM_PEERS, peers, NULL,
                                                  NULL,
                                                  NULL,
                                                  GNUNET_TESTBED_TOPOLOGY_CLIQUE,
                                                  /* GNUNET_TESTBED_TOPOLOGY_ERDOS_RENYI, */
                                                  /* NUM_PEERS, */
                                                  GNUNET_TESTBED_TOPOLOGY_OPTION_END);
  GNUNET_assert (NULL != op);
  shutdown_task = GNUNET_SCHEDULER_add_delayed (TEST_TIMEOUT, do_shutdown, NULL);
}


/**
 * Main function
 */
int
main (int argc, char **argv)
{
  uint64_t event_mask;

  result = GNUNET_SYSERR;
  event_mask = 0;
  event_mask |= (1LL << GNUNET_TESTBED_ET_CONNECT);
  event_mask |= (1LL << GNUNET_TESTBED_ET_OPERATION_FINISHED);
  (void) GNUNET_TESTBED_test_run ("test_experimentation_clique_run",
                                  "test_experimentation_clique.conf", NUM_PEERS,
                                  event_mask, &controller_event_cb, NULL,
                                  &test_master, NULL);
  if (GNUNET_OK != result)
    return 1;
  return 0;
}

/* end of test_experimentation_clique_run.c */
