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
 * @file testbed/test_testbed_api_peer_reconfiguration.c
 * @brief testcase for testing GNUNET_TESTBED_peer_manage_service()
 *          implementation
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"

/**
 * Number of peers we want to start
 */
#define NUM_PEERS 1

/**
 * The array of peers; we get them from the testbed
 */
static struct GNUNET_TESTBED_Peer **peers;

/**
 * Operation handle
 */
static struct GNUNET_TESTBED_Operation *op;

/**
 * Abort task identifier
 */
static struct GNUNET_SCHEDULER_Task * abort_task;

/**
 * States in this test
 */
enum {

  /**
   * Test has just been initialized
   */
  STATE_INIT,

  /**
   * Peers have been started
   */
  STATE_PEER_STARTED,

  /**
   * Peer has been reconfigured.  Test completed successfully
   */
  STATE_PEER_RECONFIGURED

} state;

/**
 * Fail testcase
 */
#define FAIL_TEST(cond, ret) do {                               \
    if (!(cond)) {                                              \
      GNUNET_break(0);                                          \
      if (NULL != abort_task)               \
        GNUNET_SCHEDULER_cancel (abort_task);                   \
      abort_task = GNUNET_SCHEDULER_add_now (&do_abort, NULL);  \
      ret;                                                      \
    }                                                           \
  } while (0)


/**
 * Abort task
 *
 * @param cls NULL
 * @param tc scheduler task context
 */
static void
do_abort (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Aborting\n");
  abort_task = NULL;
  if (NULL != op)
  {
    GNUNET_TESTBED_operation_done (op);
    op = NULL;
  }
  GNUNET_SCHEDULER_shutdown();
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
  if (STATE_PEER_STARTED != state)
    return;
  if (GNUNET_TESTBED_ET_OPERATION_FINISHED != event->type)
  {
    GNUNET_TESTBED_operation_done (op);
    op = NULL;
    FAIL_TEST (0, return);
  }
  if (NULL != event->details.operation_finished.emsg)
  {
    fprintf (stderr, "Operation failed: %s\n",
             event->details.operation_finished.emsg);
    GNUNET_TESTBED_operation_done (op);
    op = NULL;
    FAIL_TEST (0, return);
  }
  GNUNET_TESTBED_operation_done (op);
  state = STATE_PEER_RECONFIGURED;
  GNUNET_SCHEDULER_cancel (abort_task);
  abort_task = NULL;
  GNUNET_SCHEDULER_shutdown ();
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
  struct GNUNET_CONFIGURATION_Handle *cfg;

  FAIL_TEST (NUM_PEERS == num_peers, return);
  state = STATE_PEER_STARTED;
  peers = peers_;
  cfg = GNUNET_CONFIGURATION_create ();
  FAIL_TEST (GNUNET_OK == GNUNET_CONFIGURATION_load
             (cfg, "test_testbed_api_testbed_run_topologyrandom.conf"), return);
  op = GNUNET_TESTBED_peer_update_configuration (peers[0], cfg);
  GNUNET_CONFIGURATION_destroy (cfg);
  FAIL_TEST (NULL != op, return);
  abort_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                             (GNUNET_TIME_UNIT_SECONDS, 30),
                                             &do_abort, NULL);
}


/**
 * Main function
 */
int
main (int argc, char **argv)
{
  state = STATE_INIT;
  (void) GNUNET_TESTBED_test_run ("test_testbed_api_peer_reconfiguration",
                                  "test_testbed_api.conf",
                                  NUM_PEERS,
                                  1LL << GNUNET_TESTBED_ET_OPERATION_FINISHED,
                                  &controller_cb, NULL,
                                  &test_master, NULL);
  if (STATE_PEER_RECONFIGURED != state)
    return 1;
  return 0;
}
