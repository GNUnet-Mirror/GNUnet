/*
  This file is part of GNUnet
  (C) 2008--2012 Christian Grothoff (and other contributing authors)

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
#include "gnunet_common.h"
#include "gnunet_testbed_service.h"

/**
 * Number of peers we want to start
 */
#define NUM_PEERS 50

/**
 * Array of peers
 */
static struct GNUNET_TESTBED_Peer **peers;

/**
 * Operation handle
 */
static struct GNUNET_TESTBED_Operation *op;

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
      GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    }
    break;
  default:
    GNUNET_break (0);
    if ((GNUNET_TESTBED_ET_OPERATION_FINISHED == event->type) && 
        (NULL != event->details.operation_finished.emsg))
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "An operation failed with error: %s\n",
                  event->details.operation_finished.emsg);
    result = GNUNET_SYSERR;
    GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
  }  
}


/**
 * Signature of a main function for a testcase.
 *
 * @param cls closure
 * @param num_peers number of peers in 'peers'
 * @param peers handle to peers run in the testbed
 */
static void
test_master (void *cls, unsigned int num_peers,
             struct GNUNET_TESTBED_Peer **peers_)
{
  unsigned int peer;

  GNUNET_assert (NULL == cls);
  GNUNET_assert (NUM_PEERS == num_peers);
  GNUNET_assert (NULL != peers_);
  for (peer = 0; peer < num_peers; peer++)
    GNUNET_assert (NULL != peers_[peer]);
  peers = peers_;
  overlay_connects = 0;
  op = GNUNET_TESTBED_overlay_configure_topology (NULL, NUM_PEERS, peers,
						  GNUNET_TESTBED_TOPOLOGY_ERDOS_RENYI,
                                                  NUM_PEERS);
  GNUNET_assert (NULL != op);
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
  GNUNET_TESTBED_test_run ("test_testbed_api_test", "test_testbed_api.conf",
                           NUM_PEERS, event_mask, &controller_event_cb, NULL,
                           &test_master, NULL);
  if (GNUNET_OK != result)
    return 1;
  return 0;
}

/* end of test_testbed_api_topology.c */
