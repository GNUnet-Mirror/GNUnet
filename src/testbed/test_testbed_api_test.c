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
 * @file src/testbed/test_testbed_api_test.c
 * @brief testing cases for testing high level testbed api helper functions
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_testbed_service.h"

/**
 * Number of peers we want to start
 */
#define NUM_PEERS 25

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
do_shutdown (void *cls, const const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_SCHEDULER_shutdown ();
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
             struct GNUNET_TESTBED_Peer **peers)
{
  unsigned int peer;

  GNUNET_assert (NULL == cls);
  GNUNET_assert (NUM_PEERS == num_peers);
  GNUNET_assert (NULL != peers);
  for (peer = 0; peer < num_peers; peer++)
    GNUNET_assert (NULL != peers[peer]);
  result = GNUNET_OK;
  /* Artificial delay for shutdown */
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &do_shutdown, NULL);
}


/**
 * Main function
 */
int
main (int argc, char **argv)
{
  result = GNUNET_SYSERR;
  GNUNET_TESTBED_test_run ("test_testbed_api_test", "test_testbed_api.conf",
                           NUM_PEERS, &test_master, NULL);
  if (GNUNET_OK != result)
    return 1;
  return 0;
}

/* end of test_testbed_api_test.c */
