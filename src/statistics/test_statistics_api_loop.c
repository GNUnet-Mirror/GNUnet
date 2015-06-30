/*
     This file is part of GNUnet.
     Copyright (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file statistics/test_statistics_api_loop.c
 * @brief testcase for statistics_api.c
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"

#define ROUNDS (1024 * 1024)

static struct GNUNET_STATISTICS_Handle *h;


static int
check_1 (void *cls, const char *subsystem, const char *name, uint64_t value,
         int is_persistent)
{
  GNUNET_assert (0 == strcmp (name, "test-0"));
  GNUNET_assert (0 == strcmp (subsystem, "test-statistics-api-loop"));
  GNUNET_assert (is_persistent == GNUNET_NO);
  return GNUNET_OK;
}


static void
next (void *cls, int success)
{
  int *ok = cls;

  GNUNET_STATISTICS_destroy (h, GNUNET_NO);
  GNUNET_assert (success == GNUNET_OK);
  *ok = 0;
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  unsigned int i;
  char name[128];

  h = GNUNET_STATISTICS_create ("test-statistics-api-loop", cfg);
  for (i = 0; i < ROUNDS; i++)
  {
    GNUNET_snprintf (name, sizeof (name), "test-%d", i % 256);
    GNUNET_STATISTICS_set (h, name, i, GNUNET_NO);
    GNUNET_snprintf (name, sizeof (name), "test-%d", i % 128);
    GNUNET_STATISTICS_update (h, name, 1, GNUNET_NO);
  }
  i = 0;
  GNUNET_break (NULL !=
                GNUNET_STATISTICS_get (h, NULL, "test-0",
                                       GNUNET_TIME_UNIT_MINUTES, &next,
                                       &check_1, cls));
}


int
main (int argc, char *argv_ign[])
{
  int ok = 1;

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
  GNUNET_PROGRAM_run (3, argv, "test-statistics-api", "nohelp", options, &run,
                      &ok);
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

/* end of test_statistics_api_loop.c */
