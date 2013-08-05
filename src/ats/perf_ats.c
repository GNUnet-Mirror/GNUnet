/*
     This file is part of GNUnet.
     (C) 2010,2011 Christian Grothoff (and other contributing authors)

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
 * @file ats/test_ats.c
 * @brief ats benchmark: start peers and modify preferences, monitor change over time
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"
#include "gnunet_ats_service.h"

#define TEST_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)
#define TESTNAME_PREFIX "perf_ats_"
#define NUM_PEERS 4 /* At least 2 */

/**
 * Information we track for a peer in the testbed.
 */
struct BenchmarkPeer
{
  /**
   * Handle with testbed.
   */
  struct GNUNET_TESTBED_Peer *daemon;

  /**
   * Testbed operation to connect to statistics service
   */
  struct GNUNET_TESTBED_Operation *stat_op;

  struct GNUNET_ATS_PerformanceHandle *p_handle;
  struct GNUNET_ATS_SchedulingHandle *s_handle;

};

struct BenchmarkPeer ph[NUM_PEERS];



/**
 * Shutdown task
 */
static GNUNET_SCHEDULER_TaskIdentifier shutdown_task;

static int result;
static char *solver;
static char *preference;

/**
 * Shutdown nicely
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
	shutdown_task = GNUNET_SCHEDULER_NO_TASK;

	GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Benchmarking done\n"));


	GNUNET_SCHEDULER_shutdown();
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

}

static void
ats_performance_info_cb (void *cls,
												const struct GNUNET_HELLO_Address *address,
												int address_active,
												struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
												struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
												const struct GNUNET_ATS_Information *ats,
												uint32_t ats_count)
{

}

/**
 * Called to open a connection to the peer's ATS performance
 *
 * @param cls peer context
 * @param cfg configuration of the peer to connect to; will be available until
 *          GNUNET_TESTBED_operation_done() is called on the operation returned
 *          from GNUNET_TESTBED_service_connect()
 * @return service handle to return in 'op_result', NULL on error
 */
static void *
ats_perf_connect_adapter (void *cls,
                      const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct BenchmarkPeer *peer = cls;
  peer->p_handle = GNUNET_ATS_performance_init (cfg, &ats_performance_info_cb, peer);
  if (NULL == peer->p_handle)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to create ATS performance handle \n");
  return peer->p_handle;
}

/**
 * Called to disconnect from peer's statistics service
 *
 * @param cls peer context
 * @param op_result service handle returned from the connect adapter
 */
static void
ats_perf_disconnect_adapter (void *cls, void *op_result)
{
  struct BenchmarkPeer *peer = cls;

  GNUNET_ATS_performance_done(peer->p_handle);
  peer->p_handle = NULL;
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
  int c_p;
	GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Benchmarking solver `%s' on preference `%s'\n"), solver, preference);

  shutdown_task = GNUNET_SCHEDULER_add_delayed (TEST_TIMEOUT, &do_shutdown, NULL);

  GNUNET_assert (NULL == cls);
  GNUNET_assert (NUM_PEERS == num_peers);
  GNUNET_assert (NULL != peers_);

  for (c_p = 0; c_p < num_peers; c_p++)
  {
    GNUNET_assert (NULL != peers_[c_p]);
    /* Connect to ATS service */
    /*
    ph[c_p].stat_op = GNUNET_TESTBED_service_connect (NULL,
    																peers_[c_p], "ats",
    																NULL, &ph[c_p],
                                    &ats_perf_connect_adapter,
                                    &ats_perf_disconnect_adapter,
                                    &ph[c_p]);
                                    */
  }


}


int
main (int argc, char *argv[])
{
	char *tmp;
	char *tmp_sep;
	char *test_name;
	char *conf_name;

  result = 1;

  /* figure out testname */
  tmp = strstr (argv[0], TESTNAME_PREFIX);
  if (NULL == tmp)
  {
  	fprintf (stderr, "Unable to parse test name `%s'\n", argv[0]);
  	return GNUNET_SYSERR;
  }
  tmp += strlen(TESTNAME_PREFIX);
  solver = GNUNET_strdup (tmp);
  tmp_sep = strchr (solver, '_');
  if (NULL == tmp_sep)
  {
  	fprintf (stderr, "Unable to parse test name `%s'\n", argv[0]);
  	GNUNET_free (solver);
  	return GNUNET_SYSERR;
  }
  tmp_sep[0] = '\0';
  preference = GNUNET_strdup(tmp_sep + 1);

  GNUNET_asprintf(&conf_name, "%s%s_%s.conf", TESTNAME_PREFIX, solver, preference);
  GNUNET_asprintf(&test_name, "%s%s_%s", TESTNAME_PREFIX, solver, preference);

  /* Start topology */
  uint64_t event_mask;
  result = GNUNET_SYSERR;
  event_mask = 0;
  event_mask |= (1LL << GNUNET_TESTBED_ET_CONNECT);
  event_mask |= (1LL << GNUNET_TESTBED_ET_OPERATION_FINISHED);
  (void) GNUNET_TESTBED_test_run (test_name,
                                  conf_name, NUM_PEERS,
                                  event_mask, &controller_event_cb, NULL,
                                  &test_master, NULL);

  GNUNET_free (solver);
  GNUNET_free (preference);
  GNUNET_free (conf_name);
  GNUNET_free (test_name);

  return result;
}

/* end of file perf_ats.c */
