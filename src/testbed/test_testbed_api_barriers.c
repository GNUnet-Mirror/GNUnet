/*
      This file is part of GNUnet
      Copyright (C) 2008--2013 Christian Grothoff (and other contributing authors)

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
      Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
      Boston, MA 02110-1301, USA.
 */

/**
 * @file testbed/test_testbed_api_barriers.c
 * @brief testcase binary for testing testbed barriers API
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"
#include "test_testbed_api_barriers.h"


/**
 * logging short hand
 */
#define LOG(type,...) \
  GNUNET_log (type, __VA_ARGS__);

/**
 * Number of peers we start in this test case
 */
#define NUM_PEERS 3


/**
 * Our barrier
 */
struct GNUNET_TESTBED_Barrier *barrier;

/**
 * Identifier for the shutdown task
 */
static struct GNUNET_SCHEDULER_Task * shutdown_task;

/**
 * Result of this test case
 */
static int result;


/**
 * Shutdown this test case when it takes too long
 *
 * @param cls NULL
 * @param tc scheduler task context
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  shutdown_task = NULL;
  if (NULL != barrier)
  {
    GNUNET_TESTBED_barrier_cancel (barrier);
    barrier = NULL;
  }

  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Functions of this type are to be given as callback argument to
 * GNUNET_TESTBED_barrier_init().  The callback will be called when status
 * information is available for the barrier.
 *
 * @param cls the closure given to GNUNET_TESTBED_barrier_init()
 * @param name the name of the barrier
 * @param barrier the barrier handle
 * @param status status of the barrier; GNUNET_OK if the barrier is crossed;
 *   GNUNET_SYSERR upon error
 * @param emsg if the status were to be GNUNET_SYSERR, this parameter has the
 *   error messsage
 */
static void
barrier_cb (void *cls,
            const char *name,
            struct GNUNET_TESTBED_Barrier *_barrier,
            enum GNUNET_TESTBED_BarrierStatus status,
            const char *emsg)
{
  static enum GNUNET_TESTBED_BarrierStatus old_status;

  GNUNET_assert (NULL == cls);
  GNUNET_assert (_barrier == barrier);
  switch (status)
  {
  case GNUNET_TESTBED_BARRIERSTATUS_INITIALISED:
    LOG (GNUNET_ERROR_TYPE_INFO, "Barrier initialised\n");
    old_status = status;
    return;
  case GNUNET_TESTBED_BARRIERSTATUS_ERROR:
    LOG (GNUNET_ERROR_TYPE_ERROR, "Barrier initialisation failed: %s",
         (NULL == emsg) ? "unknown reason" : emsg);
    barrier = NULL;
    GNUNET_SCHEDULER_shutdown ();
    return;
  case GNUNET_TESTBED_BARRIERSTATUS_CROSSED:
    LOG (GNUNET_ERROR_TYPE_INFO, "Barrier crossed\n");
    if (old_status == GNUNET_TESTBED_BARRIERSTATUS_INITIALISED)
      result = GNUNET_OK;
    barrier = NULL;
    GNUNET_SCHEDULER_shutdown ();
    return;
  default:
    GNUNET_assert (0);
  }
}


/**
 * Signature of a main function for a testcase.
 *
 * @param cls closure
 * @param h the run handle
 * @param num_peers number of peers in 'peers'
 * @param peers_ handle to peers run in the testbed
 * @param links_succeeded the number of overlay link connection attempts that
 *          succeeded
 * @param links_failed the number of overlay link connection attempts that
 *          failed
 */
static void
test_master (void *cls,
             struct GNUNET_TESTBED_RunHandle *h,
             unsigned int num_peers,
             struct GNUNET_TESTBED_Peer **peers_,
             unsigned int links_succeeded,
             unsigned int links_failed)
{
  struct GNUNET_TESTBED_Controller *c;

  GNUNET_assert (NULL == cls);
  if (NULL == peers_)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failing test due to timeout\n");
    return;
  }
  GNUNET_assert (NUM_PEERS == num_peers);
  c = GNUNET_TESTBED_run_get_controller_handle (h);
  barrier = GNUNET_TESTBED_barrier_init (c, TEST_BARRIER_NAME, 100,
                                         &barrier_cb, NULL);
  shutdown_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_SECONDS,
                                     10 * (NUM_PEERS + 1)),
                                    &do_shutdown, NULL);
}


/**
 * Main function
 */
int
main (int argc, char **argv)
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  char pwd[PATH_MAX];
  char *binary;
  uint64_t event_mask;

  result = GNUNET_SYSERR;
  event_mask = 0;
  cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONFIGURATION_parse (cfg,
                                             "test_testbed_api_barriers.conf.in"));
  if (NULL == getcwd (pwd, PATH_MAX))
    return 1;
  GNUNET_assert (0 < GNUNET_asprintf (&binary, "%s/%s", pwd,
                                      "gnunet-service-test-barriers"));
  GNUNET_CONFIGURATION_set_value_string (cfg, "test-barriers","BINARY", binary);
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_write
                 (cfg, "test_testbed_api_barriers.conf"));
  GNUNET_CONFIGURATION_destroy (cfg);
  cfg = NULL;
  GNUNET_free (binary);
  binary = NULL;
  (void) GNUNET_TESTBED_test_run ("test_testbed_api_barriers",
                                  "test_testbed_api_barriers.conf", NUM_PEERS,
                                  event_mask, NULL, NULL,
                                  &test_master, NULL);
  (void) unlink ("test_testbed_api_barriers.conf");
  if (GNUNET_OK != result)
    return 1;
  return 0;
}
