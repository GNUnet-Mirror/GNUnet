/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file statistics/test_statistics_api.c
 * @brief testcase for statistics_api.c
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_statistics_service.h"

#define VERBOSE GNUNET_NO

static int
check_1 (void *cls,
         const char *subsystem,
         const char *name, uint64_t value, int is_persistent)
{
  GNUNET_assert (0 == strcmp (name, "test-1"));
  GNUNET_assert (0 == strcmp (subsystem, "test-statistics-api"));
  GNUNET_assert (value == 1);
  GNUNET_assert (is_persistent == GNUNET_NO);
  return GNUNET_OK;
}

static int
check_2 (void *cls,
         const char *subsystem,
         const char *name, uint64_t value, int is_persistent)
{
  GNUNET_assert (0 == strcmp (name, "test-2"));
  GNUNET_assert (0 == strcmp (subsystem, "test-statistics-api"));
  GNUNET_assert (value == 2);
  GNUNET_assert (is_persistent == GNUNET_NO);
  return GNUNET_OK;
}

static int
check_3 (void *cls,
         const char *subsystem,
         const char *name, uint64_t value, int is_persistent)
{
  GNUNET_assert (0 == strcmp (name, "test-3"));
  GNUNET_assert (0 == strcmp (subsystem, "test-statistics-api"));
  GNUNET_assert (value == 3);
  GNUNET_assert (is_persistent == GNUNET_YES);
  return GNUNET_OK;
}

static struct GNUNET_STATISTICS_Handle *h;

static void
next_fin (void *cls, int success)
{
  int *ok = cls;

  GNUNET_STATISTICS_destroy (h, GNUNET_NO);
  GNUNET_assert (success == GNUNET_OK);
  *ok = 0;
}

static void
next (void *cls, int success)
{
  GNUNET_assert (success == GNUNET_OK);
  GNUNET_STATISTICS_get (h, NULL, "test-2",
                         GNUNET_TIME_UNIT_SECONDS, &next_fin, &check_2, cls);
}

static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *sched,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{

  h = GNUNET_STATISTICS_create (sched, "test-statistics-api", cfg);
  GNUNET_STATISTICS_set (h, "test-1", 1, GNUNET_NO);
  GNUNET_STATISTICS_set (h, "test-2", 2, GNUNET_NO);
  GNUNET_STATISTICS_set (h, "test-3", 2, GNUNET_NO);
  GNUNET_STATISTICS_update (h, "test-3", 1, GNUNET_YES);
  GNUNET_STATISTICS_get (h, NULL, "test-1",
                         GNUNET_TIME_UNIT_SECONDS, &next, &check_1, cls);
}

static void
run_more (void *cls,
          struct GNUNET_SCHEDULER_Handle *sched,
          char *const *args,
          const char *cfgfile,
	  const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  h = GNUNET_STATISTICS_create (sched, "test-statistics-api", cfg);
  GNUNET_STATISTICS_get (h, NULL, "test-3",
                         GNUNET_TIME_UNIT_SECONDS, &next_fin, &check_3, cls);
}

static int
check ()
{
  int ok = 1;
  pid_t pid;
  char *const argv[] = { "test-statistics-api",
    "-c",
    "test_statistics_api_data.conf",
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  pid = GNUNET_OS_start_process (NULL, NULL, "gnunet-service-statistics",
                                 "gnunet-service-statistics",
#if DEBUG_STATISTICS
                                 "-L", "DEBUG",
#endif
                                 "-c", "test_statistics_api_data.conf", NULL);
  GNUNET_PROGRAM_run (3, argv, "test-statistics-api", "nohelp",
                      options, &run, &ok);
  if (0 != PLIBC_KILL (pid, SIGTERM))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
      ok = 1;
    }
  GNUNET_OS_process_wait(pid);
  if (ok != 0)
    return ok;
  ok = 1;
  /* restart to check persistence! */
  pid = GNUNET_OS_start_process (NULL, NULL, "gnunet-service-statistics",
                                 "gnunet-service-statistics",
#if DEBUG_STATISTICS
                                 "-L", "DEBUG",
#endif
                                 "-c", "test_statistics_api_data.conf", NULL);
  GNUNET_PROGRAM_run (3, argv, "test-statistics-api", "nohelp",
                      options, &run_more, &ok);
  if (0 != PLIBC_KILL (pid, SIGTERM))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
      ok = 1;
    }
  GNUNET_OS_process_wait(pid);
  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  ret = check ();

  return ret;
}

/* end of test_statistics_api.c */
