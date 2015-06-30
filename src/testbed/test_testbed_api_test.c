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
 * @file src/testbed/test_testbed_api_test.c
 * @brief testing cases for testing high level testbed api helper functions
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"


/**
 * Generic logging shortcut
 */
#define LOG(kind,...)				\
  GNUNET_log (kind, __VA_ARGS__)

/**
 * Number of peers we want to start
 */
#define NUM_PEERS 2

/**
 * Array of peers
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
 * shutdown task identifier
 */
static struct GNUNET_SCHEDULER_Task * shutdown_task;

/**
 * Testing result
 */
static int result;


/**
 * Shutdown nicely
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  shutdown_task = NULL;
  if (NULL != abort_task)
    GNUNET_SCHEDULER_cancel (abort_task);
  if (NULL != op)
    GNUNET_TESTBED_operation_done (op);
  GNUNET_SCHEDULER_shutdown ();
}

/**
 * shortcut to exit during failure
 */
#define FAIL_TEST(cond) do {                                            \
    if (!(cond)) {                                                      \
      GNUNET_break(0);                                                  \
      if (NULL != abort_task)                       \
        GNUNET_SCHEDULER_cancel (abort_task);                           \
      abort_task = NULL;                            \
      if (NULL == shutdown_task)                    \
        shutdown_task = GNUNET_SCHEDULER_add_now (do_shutdown, NULL);   \
      return;                                                           \
    }                                                                   \
  } while (0)


/**
 * abort task to run on test timed out
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_abort (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  LOG (GNUNET_ERROR_TYPE_WARNING, "Test timedout -- Aborting\n");
  abort_task = NULL;
  if (NULL != shutdown_task)
    GNUNET_SCHEDULER_cancel (shutdown_task);
  do_shutdown (cls, tc);
}


/**
 * Callback to be called when the requested peer information is available
 *
 * @param cb_cls the closure from GNUNET_TETSBED_peer_get_information()
 * @param op the operation this callback corresponds to
 * @param pinfo the result; will be NULL if the operation has failed
 * @param emsg error message if the operation has failed; will be NULL if the
 *          operation is successfull
 */
static void
peerinfo_cb (void *cb_cls, struct GNUNET_TESTBED_Operation *op_,
             const struct GNUNET_TESTBED_PeerInformation *pinfo,
             const char *emsg)
{
  FAIL_TEST (op == op_);
  FAIL_TEST (NULL == cb_cls);
  FAIL_TEST (NULL == emsg);
  FAIL_TEST (GNUNET_TESTBED_PIT_IDENTITY == pinfo->pit);
  FAIL_TEST (NULL != pinfo->result.id);
  GNUNET_TESTBED_operation_done (op);
  op = NULL;
  result = GNUNET_OK;
  shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
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
op_comp_cb (void *cls, struct GNUNET_TESTBED_Operation *op_, const char *emsg)
{
  FAIL_TEST (NULL == cls);
  FAIL_TEST (op == op_);
  if (NULL != emsg)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "%s\n", emsg);
    FAIL_TEST (0);
  }
  GNUNET_TESTBED_operation_done (op);
  op = GNUNET_TESTBED_peer_get_information (peers[0],
                                            GNUNET_TESTBED_PIT_IDENTITY,
                                            &peerinfo_cb, NULL);
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
    FAIL_TEST (event->details.peer_connect.peer1 == peers[0]);
    FAIL_TEST (event->details.peer_connect.peer2 == peers[1]);
    break;
  default:
    FAIL_TEST (0);
  }
}


/**
 * Signature of a main function for a testcase.
 *
 * @param cls closure
 * @param h the run handle
 * @param num_peers number of peers in 'peers'
 * @param peers- handle to peers run in the testbed
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
  unsigned int peer;

  FAIL_TEST (NULL == cls);
  FAIL_TEST (NUM_PEERS == num_peers);
  FAIL_TEST (NULL != peers_);
  for (peer = 0; peer < num_peers; peer++)
    FAIL_TEST (NULL != peers_[peer]);
  peers = peers_;
  op = GNUNET_TESTBED_overlay_connect (NULL, &op_comp_cb, NULL, peers[0],
                                       peers[1]);
  abort_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_MINUTES, 3), &do_abort,
                                    NULL);
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
  (void) GNUNET_TESTBED_test_run ("test_testbed_api_test",
                                  "test_testbed_api.conf", NUM_PEERS,
                                  event_mask, &controller_event_cb, NULL,
                                  &test_master, NULL);
  if (GNUNET_OK != result)
    return 1;
  return 0;
}

/* end of test_testbed_api_test.c */
