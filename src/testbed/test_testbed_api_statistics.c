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
 * @file testbed/test_testbed_api_statistics.c
 * @brief testcase for testing GNUNET_TESTBED_get_statistics() implementation
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"

/**
 * Number of peers we want to start
 */
#define NUM_PEERS 5

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
 * Global testing result
 */
static int result;

/**
 * The peers we have seen in the statistics iterator
 */
static struct GNUNET_TESTBED_Peer **seen_peers;

/**
 * Number of peers in the above array
 */
static unsigned int num_seen_peers;


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
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Test timed out -- Aborting\n");
  abort_task = NULL;
  if (NULL != op)
  {
    GNUNET_TESTBED_operation_done (op);
    op = NULL;
  }
  result = GNUNET_SYSERR;
}


/**
 * Callback function to process statistic values from all peers.
 *
 * @param cls closure
 * @param peer the peer the statistic belong to
 * @param subsystem name of subsystem that created the statistic
 * @param name the name of the datum
 * @param value the current value
 * @param is_persistent GNUNET_YES if the value is persistent, GNUNET_NO if not
 * @return GNUNET_OK to continue, GNUNET_SYSERR to abort iteration
 */
static int
stats_iterator (void *cls,
                const struct GNUNET_TESTBED_Peer *peer,
                const char *subsystem, const char *name, uint64_t value,
                int is_persistent)
{
  unsigned int cnt;

  FAIL_TEST (cls == dummy_cls, return GNUNET_SYSERR);
  for (cnt = 0; cnt < num_seen_peers; cnt++)
    FAIL_TEST (peer != seen_peers[cnt], return GNUNET_SYSERR);
  FAIL_TEST (NULL != subsystem, return GNUNET_SYSERR);
  FAIL_TEST (NULL != name, return GNUNET_SYSERR);
  GNUNET_array_append (seen_peers, num_seen_peers,
                       (struct GNUNET_TESTBED_Peer *) peer);
  return GNUNET_SYSERR;
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
  result = GNUNET_OK;
  GNUNET_TESTBED_operation_done (op);
  op = NULL;
  GNUNET_SCHEDULER_cancel (abort_task);
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
  FAIL_TEST (NUM_PEERS == num_peers, return);
  peers = peers_;
  op = GNUNET_TESTBED_get_statistics (num_peers, peers,
                                      NULL, NULL,
                                      &stats_iterator,
                                      &op_comp_cb,
                                      dummy_cls);
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
  (void) GNUNET_TESTBED_test_run ("test_testbed_api_statistics",
                                  "test_testbed_api_statistics.conf",
                                  NUM_PEERS,
                                  1LL, NULL, NULL,
                                  &test_master, NULL);
  GNUNET_free_non_null (seen_peers);
  if (GNUNET_OK != result)
    return 1;
  return 0;
}
