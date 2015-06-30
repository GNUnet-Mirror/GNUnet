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
      Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
      Boston, MA 02110-1301, USA.
 */

/**
 * @file testbed/test_testbed_logger_api.c
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
#define LOG(kind,...)				\
  GNUNET_log (kind, __VA_ARGS__)

/**
 * Relative time seconds shorthand
 */
#define TIME_REL_SECS(sec) \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, sec)

/**
 * Opaque handle for the logging service
 */
static struct GNUNET_TESTBED_LOGGER_Handle *h;

static struct GNUNET_TESTING_Peer *peer;

static char *search_dir;

/**
 * Abort task identifier
 */
static struct GNUNET_SCHEDULER_Task * abort_task;
static struct GNUNET_SCHEDULER_Task * write_task;

static int result;

#define CANCEL_TASK(task) do {                  \
    if (NULL != task) \
    {                                           \
      GNUNET_SCHEDULER_cancel (task);     \
      task = NULL;    \
    }                                           \
  } while (0)

/**
 * shortcut to exit during failure
 */
#define FAIL_TEST(cond, ret) do {                               \
    if (!(cond)) {                                              \
      GNUNET_break(0);                                          \
      CANCEL_TASK (abort_task);                                 \
      abort_task = GNUNET_SCHEDULER_add_now (&do_abort, NULL);  \
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
shutdown_now ()
{
  CANCEL_TASK (abort_task);
  CANCEL_TASK (write_task);
  GNUNET_free_non_null (search_dir);
  if (NULL != h)
    GNUNET_TESTBED_LOGGER_disconnect (h);
  GNUNET_SCHEDULER_shutdown ();
}


static void
do_abort (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  LOG (GNUNET_ERROR_TYPE_WARNING, "Aborting\n");
  abort_task = NULL;
  shutdown_now ();
}


#define BSIZE 1024


/**
 * Function called to iterate over a directory.
 *
 * @param cls closure
 * @param di argument to pass to "GNUNET_DISK_directory_iterator_next" to
 *           get called on the next entry (or finish cleanly);
 *           NULL on error (will be the last call in that case)
 * @param filename complete filename (absolute path)
 * @param dirname directory name (absolute path)
 */
static void
iterator_cb (void *cls, struct GNUNET_DISK_DirectoryIterator *di,
             const char *filename, const char *dirname)
{
  const char *fn;
  size_t len;
  uint64_t fs;
  int cancel;

  cancel = GNUNET_NO;
  if (NULL == filename)
    goto iteration_cont;
  len = strlen (filename);
  if (len < 5)                  /* log file: `pid'.dat */
    goto iteration_cont;
  fn = filename + len;
  if (0 != strcasecmp (".dat", fn - 4))
    goto iteration_cont;
  if (GNUNET_OK != GNUNET_DISK_file_size (filename, &fs,
                                          GNUNET_NO, GNUNET_YES))
    goto iteration_cont;
  if ((BSIZE * 2) != fs)        /* The file size should be equal to what we
                                   have written */
    goto iteration_cont;

  cancel = GNUNET_YES;
  result = GNUNET_OK;

 iteration_cont:
  if ( (NULL != di) &&
       (GNUNET_YES == GNUNET_DISK_directory_iterator_next (di, cancel)) )
    return;
  shutdown_now ();
}

/**
 * Functions of this type are called to notify a successful transmission of the
 * message to the logger service
 *
 * @param cls the closure given to GNUNET_TESTBED_LOGGER_send()
 * @param size the amount of data sent
 */
static void
flush_comp (void *cls, size_t size)
{
  FAIL_TEST (&write_task == cls, return);
  FAIL_TEST ((BSIZE * 2) == size, return);
  FAIL_TEST (GNUNET_OK == GNUNET_TESTING_peer_stop (peer), return);
  FAIL_TEST (GNUNET_YES == GNUNET_DISK_directory_iterator_start
             (GNUNET_SCHEDULER_PRIORITY_DEFAULT, search_dir,
              &iterator_cb, NULL), return);
}


static void
do_write (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static int i;
  char buf[BSIZE];

  write_task = NULL;
  if (0 == i)
    write_task = GNUNET_SCHEDULER_add_delayed (TIME_REL_SECS(1), &do_write, NULL);
  (void) memset (buf, i, BSIZE);
  GNUNET_TESTBED_LOGGER_write (h, buf, BSIZE);
  if (0 == i++)
    return;
  GNUNET_TESTBED_LOGGER_flush (h, GNUNET_TIME_UNIT_FOREVER_REL,
                               &flush_comp, &write_task);
}


/**
 * Signature of the 'main' function for a (single-peer) testcase that
 * is run using 'GNUNET_TESTING_peer_run'.
 *
 * @param cls closure
 * @param cfg configuration of the peer that was started
 * @param peer identity of the peer that was created
 */
static void
test_main (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg,
           struct GNUNET_TESTING_Peer *p)
{
  FAIL_TEST (NULL != (h = GNUNET_TESTBED_LOGGER_connect (cfg)), return);
  FAIL_TEST (GNUNET_OK == GNUNET_CONFIGURATION_get_value_filename
             (cfg, "testbed-logger", "dir", &search_dir), return);
  peer = p;
  write_task = GNUNET_SCHEDULER_add_now (&do_write, NULL);
  abort_task = GNUNET_SCHEDULER_add_delayed (TIME_REL_SECS (10),
                                             &do_abort, NULL);
}


/**
 * Main function
 */
int
main (int argc, char **argv)
{
  int ret;

  result = GNUNET_SYSERR;
  ret = GNUNET_TESTING_service_run ("test-testbed-logger",
                                    "testbed-logger",
                                    "test_testbed_logger_api.conf",
                                    &test_main,
                                    NULL);
  if (0 != ret)
    return 1;
  if (GNUNET_OK != result)
    return 2;
  return 0;
}
