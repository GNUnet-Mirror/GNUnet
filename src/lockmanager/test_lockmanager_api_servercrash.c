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
#include "gnunet_testing_lib.h"

/**
 * Generic logging shorthand
 */
#define LOG(kind,...)                           \
  GNUNET_log (kind, __VA_ARGS__)

/**
 * Relative seconds shorthand
 */
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
 * Configuration Handle
 */
static const struct GNUNET_CONFIGURATION_Handle *config;

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
 * Our peer
 */
static struct GNUNET_TESTING_Peer *self;


/**
 * Shutdown nicely
 *
 * @param cls
 * @param tc the task context
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
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
}


/**
 * Abort
 *
 * @param cls
 * @param tc the task context
 */
static void
do_abort (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
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
status_cb (void *cls, const char *domain_name, uint32_t lock,
           enum GNUNET_LOCKMANAGER_Status status)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Status change callback called on lock: %d of domain: %s\n", lock,
       domain_name);
  switch (result)
  {
  case TEST_INIT:
    GNUNET_assert (handle == cls);
    GNUNET_assert (GNUNET_LOCKMANAGER_SUCCESS == status);
    result = TEST_CLIENT1_LOCK_SUCCESS;
    request2 =
        GNUNET_LOCKMANAGER_acquire_lock (handle2, "GNUNET_LOCKMANAGER_TESTING",
                                         99, &status_cb, handle2);
    GNUNET_assert (NULL != request2);
    GNUNET_LOCKMANAGER_cancel_request (request);
    request = NULL;
    break;
  case TEST_CLIENT1_LOCK_SUCCESS:
    GNUNET_assert (handle2 == cls);
    GNUNET_assert (GNUNET_LOCKMANAGER_SUCCESS == status);
    result = TEST_CLIENT2_LOCK_SUCCESS;
    /* We should stop our peer to simulate crash in lockmanager service */
    GNUNET_TESTING_peer_stop (self);
    break;
  case TEST_CLIENT2_LOCK_SUCCESS:
    GNUNET_assert (handle2 == cls);
    GNUNET_assert (GNUNET_LOCKMANAGER_RELEASE == status);
    GNUNET_assert (99 == lock);
    GNUNET_assert (0 == strcmp (domain_name, "GNUNET_LOCKMANAGER_TESTING"));
    result = TEST_CLIENT2_SERVER_CRASH_SUCCESS;
    GNUNET_LOCKMANAGER_cancel_request (request2);
    request2 = NULL;
    GNUNET_SCHEDULER_add_delayed (TIME_REL_SECONDS (1), &do_shutdown, NULL);
    break;
  default:
    GNUNET_assert (0);          /* We should never reach here */
  }
}


/**
 * Main point of test execution
 */
static void
run (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  config = cfg;
  self = peer;
  result = TEST_INIT;
  handle = GNUNET_LOCKMANAGER_connect (config);
  GNUNET_assert (NULL != handle);
  handle2 = GNUNET_LOCKMANAGER_connect (config);

  request =
      GNUNET_LOCKMANAGER_acquire_lock (handle, "GNUNET_LOCKMANAGER_TESTING", 99,
                                       &status_cb, handle);
  GNUNET_assert (NULL != request);
  abort_task_id =
      GNUNET_SCHEDULER_add_delayed (TIME_REL_SECONDS (10), &do_abort, NULL);
}


/**
 * Main function
 */
int
main (int argc, char **argv)
{
  if (0 !=
      GNUNET_TESTING_peer_run ("test_lockmanager_api_servercrash",
                               "test_lockmanager_api.conf", &run, NULL))
    return 1;
  return (TEST_CLIENT2_SERVER_CRASH_SUCCESS != result) ? 1 : 0;
}

/* end of test_lockmanager_api_servercrash.c */
