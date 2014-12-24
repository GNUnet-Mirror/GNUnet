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
 * @file src/testbed/test_testbed_api_topology.c
 * @brief testing cases for testing high level testbed api helper functions
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"

/**
 * Number of peers we want to start
 */
#define NUM_PEERS 10

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
static struct GNUNET_SCHEDULER_Task * shutdown_task;

/**
 * Testing result
 */
static int result;

/**
 * Counter for counting overlay connections
 */
static unsigned int overlay_connects;


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
    if ((NUM_PEERS) == overlay_connects)
    {
      result = GNUNET_OK;
      GNUNET_SCHEDULER_cancel (shutdown_task);
      shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    }
    break;
  case GNUNET_TESTBED_ET_OPERATION_FINISHED:
    GNUNET_assert (NULL != event->details.operation_finished.emsg);
    break;
  default:
    GNUNET_break (0);
    if ((GNUNET_TESTBED_ET_OPERATION_FINISHED == event->type) &&
        (NULL != event->details.operation_finished.emsg))
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "An operation failed with error: %s\n",
                  event->details.operation_finished.emsg);
    result = GNUNET_SYSERR;
    GNUNET_SCHEDULER_cancel (shutdown_task);
    shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
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
  unsigned int peer;

  GNUNET_assert (NULL == cls);
  if (NULL == peers_)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failing test due to timeout\n");
    return;
  }
  GNUNET_assert (NUM_PEERS == num_peers);
  for (peer = 0; peer < num_peers; peer++)
    GNUNET_assert (NULL != peers_[peer]);
  peers = peers_;
  overlay_connects = 0;
  op = GNUNET_TESTBED_overlay_configure_topology (NULL, NUM_PEERS, peers, NULL,
                                                  NULL,
                                                  NULL,
                                                  GNUNET_TESTBED_TOPOLOGY_ERDOS_RENYI,
                                                  NUM_PEERS,
                                                  GNUNET_TESTBED_TOPOLOGY_OPTION_END);
  GNUNET_assert (NULL != op);
  shutdown_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_SECONDS, 300),
                                    do_shutdown, NULL);
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

/* end of test_testbed_api_topology.c */
