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
  Free Software Foundation, Inc., 59 Temple Place - Suite 330,
  Boston, MA 02111-1307, USA.
*/

/**
 * @file src/testbed/test_testbed_api_test.c
 * @brief testing cases for testing notications via test master callback upon
 *          timeout while setting up testbed using functions
 *          GNUNET_TESTBED_test_run()
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
#define NUM_PEERS 25

/**
 * Testing result
 */
static int result;


/**
 * shortcut to exit during failure
 */
#define FAIL_TEST(cond) do {                                            \
    if (!(cond)) {                                                      \
      GNUNET_break(0);                                                  \
      GNUNET_SCHEDULER_shutdown ();                                     \
      return;                                                           \
    }                                                                   \
  } while (0)


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
  FAIL_TEST (0);
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
  FAIL_TEST (NULL == cls);
  FAIL_TEST (0 == num_peers);
  FAIL_TEST (NULL == peers_);
  result = GNUNET_OK;
  GNUNET_SCHEDULER_shutdown ();
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
                                  "test_testbed_api_test_timeout.conf", NUM_PEERS,
                                  event_mask, &controller_event_cb, NULL,
                                  &test_master, NULL);
  if (GNUNET_OK != result)
    return 1;
  return 0;
}

/* end of test_testbed_api_test.c */
