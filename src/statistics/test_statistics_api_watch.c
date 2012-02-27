/*
     This file is part of GNUnet.
     (C) 2009, 2011 Christian Grothoff (and other contributing authors)

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
 * @file statistics/test_statistics_api_watch.c
 * @brief testcase for statistics_api.c watch functions
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_statistics_service.h"

#define VERBOSE GNUNET_NO

#define START_SERVICE GNUNET_YES

static int ok;

static struct GNUNET_STATISTICS_Handle *h;

static struct GNUNET_STATISTICS_Handle *h2;

static GNUNET_SCHEDULER_TaskIdentifier shutdown_task;


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


static int
check ()
{
  char *const argv[] = { "test-statistics-api",
    "-c",
    "test_statistics_api_data.conf",
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
#if START_SERVICE
  struct GNUNET_OS_Process *proc;

  proc =
    GNUNET_OS_start_process (GNUNET_YES, NULL, NULL, "gnunet-service-statistics",
                               "gnunet-service-statistics",
#if VERBOSE
                               "-L", "DEBUG",
#endif
                               "-c", "test_statistics_api_data.conf", NULL);
#endif
  GNUNET_assert (NULL != proc);
  ok = 3;
  GNUNET_PROGRAM_run (3, argv, "test-statistics-api", "nohelp", options, &run,
                      NULL);
#if START_SERVICE
  if (0 != GNUNET_OS_process_kill (proc, SIGTERM))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
    ok = 1;
  }
  GNUNET_OS_process_wait (proc);
  GNUNET_OS_process_close (proc);
  proc = NULL;
#endif
  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  ret = check ();

  return ret;
}

/* end of test_statistics_api_watch.c */
