/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2011, 2012 Christian Grothoff (and other contributing authors)

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
 * @file statistics/test_statistics_api_watch.c
 * @brief testcase for statistics_api.c watch functions
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"


static int ok;

static struct GNUNET_STATISTICS_Handle *h;

static struct GNUNET_STATISTICS_Handle *h2;

static struct GNUNET_SCHEDULER_Task * shutdown_task;


static void
force_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  fprintf (stderr, "Timeout, failed to receive notifications: %d\n", ok);
  GNUNET_STATISTICS_destroy (h, GNUNET_NO);
  GNUNET_STATISTICS_destroy (h2, GNUNET_NO);
  ok = 7;
}


static void
normal_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_STATISTICS_destroy (h, GNUNET_NO);
  GNUNET_STATISTICS_destroy (h2, GNUNET_NO);
}


static int
watch_1 (void *cls, const char *subsystem, const char *name, uint64_t value,
         int is_persistent)
{
  GNUNET_assert (value == 42);
  GNUNET_assert (0 == strcmp (name, "test-1"));
  ok &= ~1;
  if (0 == ok)
  {
    GNUNET_SCHEDULER_cancel (shutdown_task);
    GNUNET_SCHEDULER_add_now (&normal_shutdown, NULL);
  }
  return GNUNET_OK;
}


static int
watch_2 (void *cls, const char *subsystem, const char *name, uint64_t value,
         int is_persistent)
{
  GNUNET_assert (value == 43);
  GNUNET_assert (0 == strcmp (name, "test-2"));
  ok &= ~2;
  if (0 == ok)
  {
    GNUNET_SCHEDULER_cancel (shutdown_task);
    GNUNET_SCHEDULER_add_now (&normal_shutdown, NULL);
  }
  return GNUNET_OK;
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  h = GNUNET_STATISTICS_create ("dummy", cfg);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_STATISTICS_watch (h, "test-statistics-api-watch",
                                          "test-1", &watch_1, NULL));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_STATISTICS_watch (h, "test-statistics-api-watch",
                                          "test-2", &watch_2, NULL));
  h2 = GNUNET_STATISTICS_create ("test-statistics-api-watch", cfg);
  GNUNET_STATISTICS_set (h2, "test-1", 42, GNUNET_NO);
  GNUNET_STATISTICS_set (h2, "test-2", 43, GNUNET_NO);
  shutdown_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MINUTES, &force_shutdown,
                                    NULL);
}


int
main (int argc, char *argv_ign[])
{
  char *const argv[] = { "test-statistics-api",
    "-c",
    "test_statistics_api_data.conf",
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  struct GNUNET_OS_Process *proc;
  char *binary;

  binary = GNUNET_OS_get_libexec_binary_path ("gnunet-service-statistics");
  proc =
    GNUNET_OS_start_process (GNUNET_YES, GNUNET_OS_INHERIT_STD_OUT_AND_ERR,
                             NULL, NULL, NULL,
			     binary,
			     "gnunet-service-statistics",
			     "-c", "test_statistics_api_data.conf", NULL);
  GNUNET_assert (NULL != proc);
  ok = 3;
  GNUNET_PROGRAM_run (3, argv, "test-statistics-api", "nohelp", options, &run,
                      NULL);
  if (0 != GNUNET_OS_process_kill (proc, GNUNET_TERM_SIG))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
    ok = 1;
  }
  GNUNET_OS_process_wait (proc);
  GNUNET_OS_process_destroy (proc);
  proc = NULL;
  GNUNET_free (binary);
  return ok;
}


/* end of test_statistics_api_watch.c */
