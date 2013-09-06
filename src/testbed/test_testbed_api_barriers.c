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
 * @file testbed/test_testbed_api_barriers.c
 * @brief testcase binary for testing testbed barriers API
 * @author Sree Harsha Totakura <sreeharsha@totakura.in> 
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"

/**
 * Number of peers we start in this test case
 */
#define NUM_PEERS 3

/**
 * Result of this test case
 */
static int result;


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

  GNUNET_assert (NULL == cls);
  if (NULL == peers_)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failing test due to timeout\n");
    return;
  }
  GNUNET_assert (NUM_PEERS == num_peers);
  
  result = GNUNET_OK;
  GNUNET_SCHEDULER_shutdown ();
  /* shutdown_task = */
  /*     GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply */
  /*                                   (GNUNET_TIME_UNIT_SECONDS, 300), */
  /*                                   do_shutdown, NULL); */
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
  (void) GNUNET_TESTBED_test_run ("test_testbed_api_test",
                                  "test_testbed_api_barriers.conf", NUM_PEERS,
                                  event_mask, NULL, NULL,
                                  &test_master, NULL);
  if (GNUNET_OK != result)
    return 1;
  return 0;
}
