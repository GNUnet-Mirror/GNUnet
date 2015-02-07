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
 * @file testbed/test_testbed_underlay.c
 * @brief testcase binary for testing testbed underlay restrictions
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

static struct GNUNET_TESTBED_Operation *op;


/**
 * Shutdown testcase
 *
 * @param cls NULL
 * @param tc scheduler task context
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != op)
    GNUNET_TESTBED_operation_done (op);
  op = NULL;
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
overlay_connect_status (void *cls,
                        struct GNUNET_TESTBED_Operation *op_,
                        const char *emsg)
{
  GNUNET_assert (op_ == op);
  GNUNET_TESTBED_operation_done (op);
  op = NULL;
  if (NULL == emsg)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Peers 0 and 2 should not get connected\n");
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peers 0 and 2 not connected: %s.  Success!\n", emsg);
    result = GNUNET_OK;
  }
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
  GNUNET_assert (NULL == cls);
  if (NULL == peers_)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failing test due to timeout\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_assert (NUM_PEERS == num_peers);
  op = GNUNET_TESTBED_overlay_connect (NULL,
                                       &overlay_connect_status,
                                       NULL,
                                       peers_[0],
                                       peers_[2]);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
                                                               60),
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
  char *dbfile;
  uint64_t event_mask;

  result = GNUNET_SYSERR;
  event_mask = 0;
  cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONFIGURATION_parse (cfg,
                                             "test_testbed_underlay.conf.in"));
  if (NULL == getcwd (pwd, PATH_MAX))
    return 1;
  GNUNET_assert (0 < GNUNET_asprintf (&dbfile, "%s/%s", pwd,
                                      "test-underlay.sqlite"));
  GNUNET_CONFIGURATION_set_value_string (cfg, "TESTBED-UNDERLAY","DBFILE", dbfile);
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_write
                 (cfg, "test_testbed_underlay.conf"));
  GNUNET_CONFIGURATION_destroy (cfg);
  cfg = NULL;
  GNUNET_free (dbfile);
  dbfile = NULL;
  (void) GNUNET_TESTBED_test_run ("test_testbed_underlay",
                                  "test_testbed_underlay.conf", NUM_PEERS,
                                  event_mask, NULL, NULL,
                                  &test_master, NULL);
  (void) unlink ("test_testbed_underlay.conf");
  if (GNUNET_OK != result)
    return 1;
  return 0;
}
