/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file lockmanager/test_lockmanager_api_servercrash.c
 * @brief Test cases for lockmanager_api where the server crashes
 * @author Sree Harsha Totakura
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_lockmanager_service.h"

#define VERBOSE GNUNET_YES

#define VERBOSE_ARM 1

#define LOG(kind,...)                           \
  GNUNET_log (kind, __VA_ARGS__)

#define TIME_REL_SECONDS(min)                                   \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, min)

/**
 * Various steps of the test
 */
enum Test
  {
    /**
     * Signal test failure
     */
    TEST_FAIL,

    /**
     * Testing just began
     */
    TEST_INIT,

    /**
     * Client 1 has got the lock successfully; Client 2 should try to acquire
     * the lock now; after some time client 1 has to release the lock
     */
    TEST_CLIENT1_LOCK_SUCCESS,

    /**
     * Client 2 has got the lock; Server should crash now;
     */
    TEST_CLIENT2_LOCK_SUCCESS,

    /**
     * Client 2 should get lock release due to server crash; Should call
     * shutdown now
     */
    TEST_CLIENT2_SERVER_CRASH_SUCCESS
  };

/**
 * The testing result
 */
static enum Test result;

/**
 * The process id of the GNUNET ARM process
 */
static struct GNUNET_OS_Process *arm_pid = NULL;

/**
 * Configuration Handle
 */
static struct GNUNET_CONFIGURATION_Handle *config;

/**
 * The handle to the lockmanager service
 */
static struct GNUNET_LOCKMANAGER_Handle *handle;

/**
 * A second client handle to the lockmanager service
 */
static struct GNUNET_LOCKMANAGER_Handle *handle2;

/**
 * The locking request
 */
static struct GNUNET_LOCKMANAGER_LockingRequest *request;

/**
 * The locking request of second client
 */
static struct GNUNET_LOCKMANAGER_LockingRequest *request2;

/**
 * Abort task identifier
 */
static GNUNET_SCHEDULER_TaskIdentifier abort_task_id;


/**
 * Shutdown nicely
 *
 * @param cls
 * @param tc the task context
 */
static void
do_shutdown (void *cls, const const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (GNUNET_SCHEDULER_NO_TASK != abort_task_id)
  {
    GNUNET_SCHEDULER_cancel (abort_task_id);
    abort_task_id = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != handle)
    GNUNET_LOCKMANAGER_disconnect (handle);
  if (NULL != handle2)
    GNUNET_LOCKMANAGER_disconnect (handle2);
  if (NULL != arm_pid)
  {
    if (0 != GNUNET_OS_process_kill (arm_pid, SIGTERM))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Kill gnunet-service-arm manually\n");
    }
    GNUNET_OS_process_wait (arm_pid);
    GNUNET_OS_process_destroy (arm_pid);
  }
  if (NULL != config)
    GNUNET_CONFIGURATION_destroy (config);
}


/**
 * Abort
 *
 * @param cls
 * @param tc the task context
 */
static void
do_abort (void *cls, const const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Aborting test...\n");
  abort_task_id = GNUNET_SCHEDULER_NO_TASK;
  result = TEST_FAIL;
  do_shutdown (cls, tc);
}


/**
 * Callback for lock status changes
 *
 * @param cls the handle
 *
 * @param domain_name the locking domain of the lock 
 *
 * @param lock the lock for which this status is relevant
 *
 * @param status GNUNET_LOCKMANAGER_SUCCESS if the lock has been successfully
 *          acquired; GNUNET_LOCKMANAGER_RELEASE when the acquired lock is lost
 */
static void 
status_cb (void *cls,
           const char *domain_name,
           uint32_t lock,
           enum GNUNET_LOCKMANAGER_Status status)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Status change callback called on lock: %d of domain: %s\n",
       lock, domain_name);
  switch (result)
  {
  case TEST_INIT:
    GNUNET_assert (handle == cls);
    GNUNET_assert (GNUNET_LOCKMANAGER_SUCCESS == status);
    result = TEST_CLIENT1_LOCK_SUCCESS;
    request2 = GNUNET_LOCKMANAGER_acquire_lock (handle2,
                                                "GNUNET_LOCKMANAGER_TESTING",
                                                99,
                                                &status_cb,
                                                handle2);
    GNUNET_assert (NULL != request2);
    GNUNET_LOCKMANAGER_cancel_request (request);
    request = NULL;
    break;
  case TEST_CLIENT1_LOCK_SUCCESS:
    GNUNET_assert (handle2 == cls);
    GNUNET_assert (GNUNET_LOCKMANAGER_SUCCESS == status);
    result = TEST_CLIENT2_LOCK_SUCCESS;
    /* We should kill the lockmanager process */
    if (0 != GNUNET_OS_process_kill (arm_pid, SIGTERM))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Kill gnunet-service-arm manually\n");
    }
    GNUNET_OS_process_wait (arm_pid);
    GNUNET_OS_process_destroy (arm_pid);
    arm_pid =NULL;
    break;
  case TEST_CLIENT2_LOCK_SUCCESS:
    GNUNET_assert (handle2 == cls);
    GNUNET_assert (GNUNET_LOCKMANAGER_RELEASE == status);
    GNUNET_assert (99 == lock);
    GNUNET_assert (0 == strcmp (domain_name, "GNUNET_LOCKMANAGER_TESTING"));
    result = TEST_CLIENT2_SERVER_CRASH_SUCCESS;
    GNUNET_SCHEDULER_add_delayed (TIME_REL_SECONDS (1),
                                  &do_shutdown,
                                  NULL);
    break;
  default:
    GNUNET_assert (0);          /* We should never reach here */
  }

}


/**
 * Testing function
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
test (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{ 
  result = TEST_INIT;
  handle = GNUNET_LOCKMANAGER_connect (config);
  GNUNET_assert (NULL != handle);
  handle2 = GNUNET_LOCKMANAGER_connect (config);
  
  request = GNUNET_LOCKMANAGER_acquire_lock (handle,
                                             "GNUNET_LOCKMANAGER_TESTING",
                                             99,
                                             &status_cb,
                                             handle);
  GNUNET_assert (NULL != request);
  abort_task_id = GNUNET_SCHEDULER_add_delayed (TIME_REL_SECONDS (10),
                                                &do_abort,
                                                NULL);
}


/**
 * Main point of test execution
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Starting test...\n");
  config = GNUNET_CONFIGURATION_dup (cfg);
  arm_pid = 
    GNUNET_OS_start_process (GNUNET_YES, NULL, NULL, "gnunet-service-arm",
                             "gnunet-service-arm",
#if VERBOSE_ARM
                             "-L", "DEBUG",
#endif
                             "-c", "test_lockmanager_api.conf", NULL);

  GNUNET_assert (NULL != arm_pid);
  GNUNET_SCHEDULER_add_delayed (TIME_REL_SECONDS (3),
                                &test,
                                NULL);
}


/**
 * Main function
 */
int main (int argc, char **argv)
{
  int ret;

  char *const argv2[] = { "test-lockmanager-api-servercrash",
                          "-c", "test_lockmanager_api.conf",
#if VERBOSE
                          "-L", "DEBUG",
#endif
                          NULL
  };
  
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  
  GNUNET_log_setup ("test-lockmanager-api-servercrash",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);

  ret =
    GNUNET_PROGRAM_run ((sizeof (argv2) / sizeof (char *)) - 1, argv2,
                        "test-lockmanager-api-servercrash",
                        "nohelp", options, &run, NULL);

  if (GNUNET_OK != ret)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "run failed with error code %d\n",
         ret);
    return 1;
  }
  if (TEST_CLIENT2_SERVER_CRASH_SUCCESS != result)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "test failed\n");
    return 1;
  }
  LOG (GNUNET_ERROR_TYPE_INFO, "test OK\n");
  return 0;
}
