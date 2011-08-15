/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file util/test_program.c
 * @brief tests for program.c
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_program_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_time_lib.h"

static int setme1, setme2;

static struct GNUNET_GETOPT_CommandLineOption options1[] = {
  {'n', "name", NULL, "description", 0, &GNUNET_GETOPT_set_one, &setme1},
  GNUNET_GETOPT_OPTION_END
};

static struct GNUNET_GETOPT_CommandLineOption options2[] = {
  {'n', "name", NULL, "description", 0, &GNUNET_GETOPT_set_one, &setme1},
  {'N', "number", NULL, "description", 0, &GNUNET_GETOPT_set_one, &setme2},
  GNUNET_GETOPT_OPTION_END
};

static struct GNUNET_GETOPT_CommandLineOption options3[] = {
  {'N', "number", NULL, "description", 0, &GNUNET_GETOPT_set_one, &setme1},
  {'n', "name", NULL, "description", 0, &GNUNET_GETOPT_set_one, &setme2},
  GNUNET_GETOPT_OPTION_END
};

static struct GNUNET_GETOPT_CommandLineOption options4[] = {
  {'n', "name", NULL, "description", 0, &GNUNET_GETOPT_set_one, &setme1},
  {'n', "number", NULL, "description", 0, &GNUNET_GETOPT_set_one, &setme2},
  GNUNET_GETOPT_OPTION_END
};

/**
 * Main function that will be run.
 */

static void
runner (void *cls, char *const *args, const char *cfgfile,
        const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  int *ok = cls;

  GNUNET_assert (setme1 == 1);
  GNUNET_assert (0 == strcmp (args[0], "extra"));
  GNUNET_assert (args[1] == NULL);
  GNUNET_assert (0 == strcmp (cfgfile, "test_program_data.conf"));

  *ok = 0;
}

/**
 * Main method, starts scheduler with task1,
 * checks that "ok" is correct at the end.
 */
static int
check ()
{
  int ok = 1;

  char *const argv[] = {
    "test_program",
    "-c",
    "test_program_data.conf",
    "-L",
    "WARNING",
    "-n",
    "extra",
    NULL
  };

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PROGRAM_run (7, argv, "test_program", "A test",
                                     options1, &runner, &ok));

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PROGRAM_run (7, argv, "test_program", "A test",
                                     options2, &runner, &ok));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PROGRAM_run (7, argv, "test_program", "A test",
                                     options3, &runner, &ok));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PROGRAM_run (7, argv, "test_program", "A test",
                                     options4, &runner, &ok));

  return ok;
}

int
main (int argc, char *argv[])
{
  int ret = 0;

  GNUNET_log_setup ("test_program", "WARNING", NULL);
  ret += check ();

  return ret;
}

/* end of test_program.c */
