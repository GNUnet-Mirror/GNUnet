/*
      This file is part of GNUnet
      Copyright (C) 2008--2013 GNUnet e.V.

      GNUnet is free software: you can redistribute it and/or modify it
      under the terms of the GNU Affero General Public License as published
      by the Free Software Foundation, either version 3 of the License,
      or (at your option) any later version.

      GNUnet is distributed in the hope that it will be useful, but
      WITHOUT ANY WARRANTY; without even the implied warranty of
      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
      Affero General Public License for more details.

      You should have received a copy of the GNU Affero General Public License
      along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */
/**
 * @file testbed-logger/test_testbed_logger_api.c
 * @brief testcases for the testbed logger api
 * @author Sree Harsha Totakura
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_testbed_logger_service.h"

/**
 * Generic logging shortcut
 */
#define LOG(kind, ...)                           \
  GNUNET_log(kind, __VA_ARGS__)

/**
 * Relative time seconds shorthand
 */
#define TIME_REL_SECS(sec) \
  GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, sec)

/**
 * Opaque handle for the logging service
 */
static struct GNUNET_TESTBED_LOGGER_Handle *h;

static struct GNUNET_TESTING_Peer *peer;

static char *search_dir;

/**
 * Abort task identifier
 */
static struct GNUNET_SCHEDULER_Task *abort_task;
static struct GNUNET_SCHEDULER_Task *write_task;

static int result;

#define CANCEL_TASK(task) do {                  \
      if (NULL != task) \
        {                                           \
          GNUNET_SCHEDULER_cancel(task);     \
          task = NULL;    \
        }                                           \
  } while (0)

/**
 * shortcut to exit during failure
 */
#define FAIL_TEST(cond, ret) do {                               \
      if (!(cond)) {                                              \
          GNUNET_break(0);                                          \
          CANCEL_TASK(abort_task);                                 \
          abort_task = GNUNET_SCHEDULER_add_now(&do_abort, NULL);  \
          ret;                                                      \
        }                                                           \
  } while (0)


/**
 * Shutdown nicely
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
shutdown_now()
{
  CANCEL_TASK(abort_task);
  CANCEL_TASK(write_task);
  GNUNET_free_non_null(search_dir);
  if (NULL != h)
    GNUNET_TESTBED_LOGGER_disconnect(h);
  GNUNET_SCHEDULER_shutdown();
}


static void
do_abort(void *cls)
{
  LOG(GNUNET_ERROR_TYPE_WARNING,
      "Aborting\n");
  abort_task = NULL;
  shutdown_now();
}


#define BSIZE 1024


/**
 * Function called to iterate over a directory.
 *
 * @param cls closure
 * @param filename complete filename (absolute path)
 * @return #GNUNET_OK to continue to iterate,
 *  #GNUNET_NO to stop iteration with no error,
 *  #GNUNET_SYSERR to abort iteration with error!
 */
static int
iterator_cb(void *cls,
            const char *filename)
{
  const char *fn;
  size_t len;
  uint64_t fs;

  LOG(GNUNET_ERROR_TYPE_DEBUG,
      "Iterator sees file %s\n",
      filename);
  len = strlen(filename);
  fn = filename + len;
  if (0 != strcasecmp(".dat", fn - 4))
    return GNUNET_OK;
  if (GNUNET_OK !=
      GNUNET_DISK_file_size(filename,
                            &fs,
                            GNUNET_NO,
                            GNUNET_YES))
    {
      LOG(GNUNET_ERROR_TYPE_DEBUG,
          "Failed to obtain file size for file %s\n",
          filename);
      return GNUNET_SYSERR;
    }
  if ((BSIZE * 2) != fs)
    {
      LOG(GNUNET_ERROR_TYPE_DEBUG,
          "Unexpected file size for file %s\n",
          filename);
      /* The file size should be equal to what we
         have written */
      return GNUNET_SYSERR;
    }
  result = GNUNET_OK;
  return GNUNET_OK;
}


/**
 * Functions of this type are called to notify a successful
 * transmission of the message to the logger service
 *
 * @param cls the closure given to GNUNET_TESTBED_LOGGER_send()
 * @param size the amount of data sent
 */
static void
flush_comp(void *cls,
           size_t size)
{
  LOG(GNUNET_ERROR_TYPE_DEBUG,
      "Flush running\n");
  FAIL_TEST(&write_task == cls,
            return );
  FAIL_TEST((BSIZE * 2) == size,
            return );
  FAIL_TEST(GNUNET_OK ==
            GNUNET_TESTING_peer_stop(peer),
            return );
  LOG(GNUNET_ERROR_TYPE_DEBUG,
      "Peer stopped, scanning %s\n",
      search_dir);
  FAIL_TEST(GNUNET_SYSERR !=
            GNUNET_DISK_directory_scan(search_dir,
                                       &iterator_cb,
                                       NULL),
            return );
  shutdown_now();
}


static void
do_write(void *cls)
{
  static int i;
  char buf[BSIZE];

  write_task = NULL;
  LOG(GNUNET_ERROR_TYPE_DEBUG,
      "Write task running\n");
  if (0 == i)
    write_task = GNUNET_SCHEDULER_add_delayed(TIME_REL_SECS(1),
                                              &do_write,
                                              NULL);
  (void)memset(buf, i, BSIZE);
  GNUNET_TESTBED_LOGGER_write(h,
                              buf,
                              BSIZE);
  if (0 == i++)
    return;
  GNUNET_TESTBED_LOGGER_flush(h,
                              &flush_comp,
                              &write_task);
}


/**
 * Signature of the 'main' function for a (single-peer) testcase that
 * is run using #GNUNET_TESTING_peer_run().
 *
 * @param cls closure
 * @param cfg configuration of the peer that was started
 * @param peer identity of the peer that was created
 */
static void
test_main(void *cls,
          const struct GNUNET_CONFIGURATION_Handle *cfg,
          struct GNUNET_TESTING_Peer *p)
{
  LOG(GNUNET_ERROR_TYPE_DEBUG,
      "Connecting to logger\n");
  FAIL_TEST(NULL != (h = GNUNET_TESTBED_LOGGER_connect(cfg)),
            return );
  FAIL_TEST(GNUNET_OK ==
            GNUNET_CONFIGURATION_get_value_filename(cfg,
                                                    "testbed-logger",
                                                    "dir",
                                                    &search_dir),
            return );
  peer = p;
  write_task = GNUNET_SCHEDULER_add_now(&do_write,
                                        NULL);
  abort_task = GNUNET_SCHEDULER_add_delayed(TIME_REL_SECS(10),
                                            &do_abort,
                                            NULL);
}


/**
 * Main function
 */
int
main(int argc, char **argv)
{
  int ret;

  result = GNUNET_SYSERR;
  GNUNET_log_setup("test-testbed-logger-api",
                   "WARNING",
                   NULL);
  GNUNET_break(GNUNET_OK ==
               GNUNET_DISK_directory_remove("/tmp/test-testbed"));
  ret = GNUNET_TESTING_service_run("test-testbed-logger",
                                   "testbed-logger",
                                   "test_testbed_logger_api.conf",
                                   &test_main,
                                   NULL);
  GNUNET_break(GNUNET_OK ==
               GNUNET_DISK_directory_remove("/tmp/test-testbed"));
  if (0 != ret)
    return 1;
  if (GNUNET_OK != result)
    return 2;
  return 0;
}
