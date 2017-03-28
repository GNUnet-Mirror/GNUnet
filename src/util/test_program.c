/*
     This file is part of GNUnet.
     Copyright (C) 2009 GNUnet e.V.

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
 * @file util/test_program.c
 * @brief tests for program.c
 */
#include "platform.h"
#include "gnunet_util_lib.h"


static int setme1;

static int setme2;


/**
 * Main function that will be run.
 */
static void
runner (void *cls,
        char *const *args,
        const char *cfgfile,
        const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  int *ok = cls;

  GNUNET_assert (setme1 == 1);
  GNUNET_assert (0 == strcmp (args[0], "extra"));
  GNUNET_assert (args[1] == NULL);
  GNUNET_assert (NULL != strstr (cfgfile, "/test_program_data.conf"));
  *ok = 0;
}


int
main (int argc, char *argv[])
{
  int ok = 1;
  char *const argvx[] = {
    "test_program",
    "-c",
    "test_program_data.conf",
    "-L",
    "WARNING",
    "-n",
    "extra",
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options1[] = {
    GNUNET_GETOPT_option_flag ('n',
                                  "name",
                                  "description",
                                  &setme1),
    GNUNET_GETOPT_OPTION_END
  };
  struct GNUNET_GETOPT_CommandLineOption options2[] = {
    GNUNET_GETOPT_option_flag ('n',
                                  "name",
                                  "description",
                                  &setme1),
    GNUNET_GETOPT_option_flag ('N',
                                  "number",
                                  "description",
                                  &setme2),
    GNUNET_GETOPT_OPTION_END
  };
  struct GNUNET_GETOPT_CommandLineOption options3[] = {
    GNUNET_GETOPT_option_flag ('N',
                                  "number",
                                  "description",
                                  &setme1),
    GNUNET_GETOPT_option_flag ('n',
                                  "name",
                                  "description",
                                  &setme2),
    GNUNET_GETOPT_OPTION_END
  };
  struct GNUNET_GETOPT_CommandLineOption options4[] = {
    GNUNET_GETOPT_option_flag ('n',
                                  "name",
                                  "description",
                                  &setme1),
    GNUNET_GETOPT_option_flag ('n',
                                  "name",
                                  "description",
                                  &setme2),
    GNUNET_GETOPT_OPTION_END
  };


  GNUNET_log_setup ("test_program",
                    "WARNING",
                    NULL);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PROGRAM_run (7, argvx,
                                     "test_program",
                                     "A test",
                                     options1,
                                     &runner, &ok));

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PROGRAM_run (7, argvx,
                                     "test_program", "A test",
                                     options2,
                                     &runner, &ok));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PROGRAM_run (7, argvx,
                                     "test_program", "A test",
                                     options3,
                                     &runner, &ok));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_PROGRAM_run (7, argvx,
                                     "test_program", "A test",
                                     options4,
                                     &runner, &ok));

  return ok;
}

/* end of test_program.c */
