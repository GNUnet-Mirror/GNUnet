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
 * @file testbed/test_testbed_api_peers_manage_services.c
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
#define NUM_PEERS 2

/**
 * The array of peers; we get them from the testbed
 */
static struct GNUNET_TESTBED_Peer **peers;

/**
 * Operation handle
 */
static struct GNUNET_TESTBED_Operation *op;

/**
 * dummy pointer
 */
static void *dummy_cls = (void *) 0xDEAD0001;

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
  STATE_PEERS_STARTED,

  /**
   * statistics service went down
   */
  STATE_SERVICE_DOWN,

  /**
   * statistics service went up
   */
  STATE_SERVICE_UP,

  /**
   * Testing completed successfully
   */
  STATE_OK
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
 * Callback to be called when an operation is completed
 *
 * @param cls the callback closure from functions generating an operation
 * @param op the operation that has been finished
 * @param emsg error message in case the operation has failed; will be NULL if
 *          operation has executed successfully.
 */
static void
op_comp_cb (void *cls,
            struct GNUNET_TESTBED_Operation *op,
            const char *emsg)
{
  FAIL_TEST (cls == dummy_cls, return);
  FAIL_TEST (NULL == emsg, return);
  GNUNET_TESTBED_operation_done (op);
  op = NULL;
  switch (state)
  {
  case STATE_PEERS_STARTED:
    state = STATE_SERVICE_DOWN;
    op = GNUNET_TESTBED_peer_manage_service (dummy_cls,
                                             peers[1],
                                             "topology",
                                             op_comp_cb,
                                             dummy_cls,
                                             0);
    GNUNET_assert (NULL != op);
    break;
  case STATE_SERVICE_DOWN:
    state = STATE_SERVICE_UP;
    GNUNET_SCHEDULER_cancel (abort_task);
    abort_task = NULL;
    state = STATE_OK;
    GNUNET_SCHEDULER_shutdown ();
    break;
  default:
    FAIL_TEST (0, return);
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
  FAIL_TEST (NUM_PEERS == num_peers, return);
  state = STATE_PEERS_STARTED;
  peers = peers_;
  op = GNUNET_TESTBED_peer_manage_service (dummy_cls,
                                           peers[1],
                                           "topology",
                                           op_comp_cb,
                                           dummy_cls,
                                           1);
  FAIL_TEST (NULL != op, return);
  abort_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                             (GNUNET_TIME_UNIT_MINUTES, 1),
                                             &do_abort, NULL);
}


/**
 * Main function
 */
int
main (int argc, char **argv)
{
  state = STATE_INIT;
  (void) GNUNET_TESTBED_test_run ("test_testbed_api_peers_manage_services",
                                  "test_testbed_api.conf",
                                  NUM_PEERS,
                                  1LL, NULL, NULL,
                                  &test_master, NULL);
  if (STATE_OK != state)
    return 1;
  return 0;
}
