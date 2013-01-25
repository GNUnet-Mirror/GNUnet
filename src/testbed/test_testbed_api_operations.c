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
 * @file testbed/test_testbed_api_operations.c
 * @brief tests cases for testbed_api_operations.c
 * @author Sree Harsha Totakura
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "testbed_api_operations.h"

/**
 * Generic logging shortcut
 */
#define LOG(kind,...)				\
  GNUNET_log (kind, __VA_ARGS__)

/**
 * Queue A. Initially the max active is set to 2 and then reduced to 0 - this
 * should block op2 even after op1 has finished. Later the max active is set to
 * 2 and this should start op2
 */
struct OperationQueue *q1;

/**
 * Queue B. Max active set to 2 is not changed throughout the test
 */
struct OperationQueue *q2;

/**
 * This operation should go into both queues and block op2 until it is done
 */
struct GNUNET_TESTBED_Operation *op1;

/**
 * This operation should go into q1 and q2
 */
struct GNUNET_TESTBED_Operation *op2;

/**
 * This operation should go into both queues and should consume 2 units of
 * resources on both queues. Since op2 needs a resource from both queues and is
 * queues before this operation, it will be blocked until op2 is released even
 * though q1 has
 */
struct GNUNET_TESTBED_Operation *op3;

/**
 * Just like op3, this operation also consumes 2 units of resources on both
 * queues. Since this is queued after op3 and both queues are at max active
 * 2. This will be blocked until op3 is done.
 */
struct GNUNET_TESTBED_Operation *op4;

/**
 * This operation is started after op4 is released and should consume only 1
 * resource on queue q1. It should be started along with op6 and op7
 */
struct GNUNET_TESTBED_Operation *op5;

/**
 * This operation is started after op4 is released and should consume only 1
 * resource on q2. It should be started along with op5 and op7
 */
struct GNUNET_TESTBED_Operation *op6;

/**
 * This operation is started after op4 is released and should consume 1 resource
 * on both queues q1 and q1. It should be started along with op5 and op6
 */
struct GNUNET_TESTBED_Operation *op7;

/**
 * The delay task identifier
 */
GNUNET_SCHEDULER_TaskIdentifier step_task;


/**
 * Enumeration of test stages
 */
enum Test
{
    /**
     * Initial stage
     */
  TEST_INIT,

    /**
     * op1 has been started
     */
  TEST_OP1_STARTED,

    /**
     * op1 has been released
     */
  TEST_OP1_RELEASED,

  /**
   * Temporary pause where no operations should start as we set max active in q1
   * to 0 in stage TEST_OP1_STARTED
   */
  TEST_PAUSE,

    /**
     * op2 has started
     */
  TEST_OP2_STARTED,

    /**
     * op2 released
     */
  TEST_OP2_RELEASED,

  /**
   * op3 has started
   */
  TEST_OP3_STARTED,

  /**
   * op3 has finished
   */
  TEST_OP3_RELEASED,

  /**
   * op4 has started
   */
  TEST_OP4_STARTED,

  /**
   * op4 has released
   */
  TEST_OP4_RELEASED,

  /**
   * op5, op6, op7 started
   */
  TEST_OP5_6_7_STARTED,

  /**
   * op5 has released
   */
  TEST_OP5_RELEASED,

  /**
   * op6 has released
   */
  TEST_OP6_RELEASED,

  /**
   * op7 has released
   */
  TEST_OP7_RELEASED
};

/**
 * The test result
 */
enum Test result;


/**
 * Function to call to start an operation once all
 * queues the operation is part of declare that the
 * operation can be activated.
 */
static void
start_cb (void *cls);


/**
 * Function to cancel an operation (release all associated resources).  This can
 * be because of a call to "GNUNET_TESTBED_operation_cancel" (before the
 * operation generated an event) or AFTER the operation generated an event due
 * to a call to "GNUNET_TESTBED_operation_done".  Thus it is not guaranteed that
 * a callback to the 'OperationStart' preceeds the call to 'OperationRelease'.
 * Implementations of this function are expected to clean up whatever state is
 * in 'cls' and release all resources associated with the operation.
 */
static void
release_cb (void *cls);


/**
 * Task to simulate artificial delay and change the test stage
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
step (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK != step_task);
  step_task = GNUNET_SCHEDULER_NO_TASK;
  switch (result)
  {
  case TEST_OP1_STARTED:
    GNUNET_TESTBED_operation_release_ (op1);
    GNUNET_TESTBED_operation_queue_reset_max_active_ (q1, 0);
    op3 = GNUNET_TESTBED_operation_create_ (&op3, &start_cb, &release_cb);
    GNUNET_TESTBED_operation_queue_insert2_ (q1, op3, 2);
    GNUNET_TESTBED_operation_queue_insert2_ (q2, op3, 2);
    GNUNET_TESTBED_operation_begin_wait_ (op3);
    op4 = GNUNET_TESTBED_operation_create_ (&op4, &start_cb, &release_cb);
    GNUNET_TESTBED_operation_queue_insert2_ (q1, op4, 2);
    GNUNET_TESTBED_operation_queue_insert2_ (q2, op4, 2);
    GNUNET_TESTBED_operation_begin_wait_ (op4);
    break;
  case TEST_OP1_RELEASED:
    result = TEST_PAUSE;
    GNUNET_TESTBED_operation_queue_reset_max_active_ (q1, 2);
    break;
  case TEST_OP2_STARTED:
    GNUNET_TESTBED_operation_release_ (op2);
    break;
  case TEST_OP3_STARTED:
    GNUNET_TESTBED_operation_release_ (op3);
    break;
  case TEST_OP4_STARTED:
    GNUNET_TESTBED_operation_release_ (op4);
    break;
  default:
    GNUNET_assert (0);
  }
}


/**
 * Function to call to start an operation once all
 * queues the operation is part of declare that the
 * operation can be activated.
 */
static void
start_cb (void *cls)
{
  switch (result)
  {
  case TEST_INIT:
    GNUNET_assert (&op1 == cls);
    result = TEST_OP1_STARTED;
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == step_task);
    step_task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &step, NULL);
    break;
  case TEST_PAUSE:
    GNUNET_assert (&op2 == cls);
    result = TEST_OP2_STARTED;
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == step_task);
    step_task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &step, NULL);
    break;
  case TEST_OP2_RELEASED:
    GNUNET_assert (&op3 == cls);
    result = TEST_OP3_STARTED;
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == step_task);
    step_task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &step, NULL);
    break;
  case TEST_OP3_RELEASED:
    GNUNET_assert (&op4 == cls);
    result = TEST_OP4_STARTED;
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == step_task);
    step_task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &step, NULL);
    break;
  case TEST_OP4_RELEASED:
  {
    static int nops;

    nops++;
    if (nops == 3)
    {
      result = TEST_OP5_6_7_STARTED;
      GNUNET_TESTBED_operation_release_ (op5);
      op5 = NULL;
    }
  }
    break;
  default:
    GNUNET_assert (0);
  }
}


/**
 * Function to cancel an operation (release all associated resources).  This can
 * be because of a call to "GNUNET_TESTBED_operation_cancel" (before the
 * operation generated an event) or AFTER the operation generated an event due
 * to a call to "GNUNET_TESTBED_operation_done".  Thus it is not guaranteed that
 * a callback to the 'OperationStart' preceeds the call to 'OperationRelease'.
 * Implementations of this function are expected to clean up whatever state is
 * in 'cls' and release all resources associated with the operation.
 */
static void
release_cb (void *cls)
{
  switch (result)
  {
  case TEST_OP1_STARTED:
    GNUNET_assert (&op1 == cls);
    result = TEST_OP1_RELEASED;
    op1 = NULL;
    step_task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &step, NULL);
    break;
  case TEST_OP2_STARTED:
    GNUNET_assert (&op2 == cls);
    result = TEST_OP2_RELEASED;
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == step_task);
    //step_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &step, NULL);
    break;
  case TEST_OP3_STARTED:
    GNUNET_assert (&op3 == cls);
    result = TEST_OP3_RELEASED;
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == step_task);
    break;
  case TEST_OP4_STARTED:
    GNUNET_assert (&op4 == cls);
    result = TEST_OP4_RELEASED;
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == step_task);
    op5 = GNUNET_TESTBED_operation_create_ (&op5, &start_cb, &release_cb);
    GNUNET_TESTBED_operation_queue_insert2_ (q1, op5, 1);
    GNUNET_TESTBED_operation_begin_wait_ (op5);
    op6 = GNUNET_TESTBED_operation_create_ (&op6, &start_cb, &release_cb);
    GNUNET_TESTBED_operation_queue_insert2_ (q2, op6, 1);
    GNUNET_TESTBED_operation_begin_wait_ (op6);
    op7 = GNUNET_TESTBED_operation_create_ (&op7, &start_cb, &release_cb);
    GNUNET_TESTBED_operation_queue_insert2_ (q1, op7, 1);
    GNUNET_TESTBED_operation_queue_insert2_ (q2, op7, 1);
    GNUNET_TESTBED_operation_begin_wait_ (op7);
    break;
  case TEST_OP5_6_7_STARTED:
    result = TEST_OP5_RELEASED;
    op5 = NULL;
    GNUNET_TESTBED_operation_release_ (op6);
    break;
  case TEST_OP5_RELEASED:
    op6 = NULL;
    result = TEST_OP6_RELEASED;
    GNUNET_TESTBED_operation_release_ (op7);
    break;
  case TEST_OP6_RELEASED:
    result = TEST_OP7_RELEASED;
    op7 = NULL;
    GNUNET_TESTBED_operation_queue_destroy_ (q1);
    GNUNET_TESTBED_operation_queue_destroy_ (q2);
    q1 = NULL;
    q2 = NULL;
    break;
  default:
    GNUNET_assert (0);
  }
}


/**
 * Main run function.
 *
 * @param cls NULL
 * @param args arguments passed to GNUNET_PROGRAM_run
 * @param cfgfile the path to configuration file
 * @param cfg the configuration file handle
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *config)
{
  q1 = GNUNET_TESTBED_operation_queue_create_ (1);
  GNUNET_assert (NULL != q1);
  q2 = GNUNET_TESTBED_operation_queue_create_ (2);
  GNUNET_assert (NULL != q2);
  op1 = GNUNET_TESTBED_operation_create_ (&op1, start_cb, release_cb);
  GNUNET_assert (NULL != op1);
  op2 = GNUNET_TESTBED_operation_create_ (&op2, start_cb, release_cb);
  GNUNET_TESTBED_operation_queue_insert_ (q1, op1);
  GNUNET_TESTBED_operation_queue_insert_ (q2, op1);
  GNUNET_TESTBED_operation_begin_wait_ (op1);
  GNUNET_TESTBED_operation_queue_insert_ (q1, op2);
  GNUNET_TESTBED_operation_queue_insert_ (q2, op2);
  GNUNET_TESTBED_operation_begin_wait_ (op2);
  result = TEST_INIT;
}


/**
 * Main function
 */
int
main (int argc, char **argv)
{
  int ret;
  char *const argv2[] =
      { "test_testbed_api_operations", "-c", "test_testbed_api.conf", NULL };
  struct GNUNET_GETOPT_CommandLineOption options[] =
      { GNUNET_GETOPT_OPTION_END };

  ret =
      GNUNET_PROGRAM_run ((sizeof (argv2) / sizeof (char *)) - 1, argv2,
                          "test_testbed_api_operations", "nohelp", options,
                          &run, NULL);
  if ((GNUNET_OK != ret) || (TEST_OP7_RELEASED != result))
    return 1;
  op1 = NULL;
  op2 = NULL;
  op3 = NULL;
  q1 = NULL;
  q2 = NULL;
  return 0;
}

/* end of test_testbed_api_operations.c */
