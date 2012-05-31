/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2006, 2009 Christian Grothoff (and other contributing authors)

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
 * @file util/test_speedup.c
 * @brief testcase for speedup.c
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_program_lib.h"
#include "gnunet_time_lib.h"
#include "gnunet_strings_lib.h"


#define VERBOSE GNUNET_NO

static struct GNUNET_TIME_Absolute start;
static struct GNUNET_TIME_Absolute end;
static int cycles;

static void
run (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{

  cycles ++;
  printf ("..%u", cycles);
  fflush(stdout);
  if (cycles <= 5)
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &run, NULL);
  else
  {
    end = GNUNET_TIME_absolute_get();
    printf ("\n");
    fflush(stdout);
  }
}

void check (void *cls, char *const *args,
                                     const char *cfgfile,
                                     const struct GNUNET_CONFIGURATION_Handle *
                                     cfg)
{
  printf ("0");
  fflush(stdout);
  GNUNET_SCHEDULER_add_now(&run, NULL);
}


int
main (int argc, char *argv[])
{
  time_t start_real;
  time_t end_real;
  struct GNUNET_TIME_Relative delta;

  static char *const argvn[] = { "test-speedup",
    "-c",
    "test_speedup_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  start_real = time (NULL);
  start = GNUNET_TIME_absolute_get();
  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_PROGRAM_run ((sizeof (argvn) / sizeof (char *)) - 1, argvn, "test-speedup",
                      "nohelp", options, &check, NULL);

  end_real = time (NULL);
  delta = GNUNET_TIME_absolute_get_difference(start, end);

  if (delta.rel_value >  ((end_real - start_real) * 1500))
  {
    GNUNET_log  (GNUNET_ERROR_TYPE_DEBUG, "Execution time in GNUnet time: %llu ms\n", delta.rel_value);
    GNUNET_log  (GNUNET_ERROR_TYPE_DEBUG, "Execution time in system time: %llu ms\n", (end_real - start_real) * 1000);
    return 0;
  }
  else
  {
    GNUNET_log  (GNUNET_ERROR_TYPE_ERROR, "Execution time in GNUnet time: %llu ms\n", delta.rel_value);
    GNUNET_log  (GNUNET_ERROR_TYPE_ERROR, "Execution time in system time: %llu ms\n", (end_real - start_real) * 1000);
    return 1;
  }
}

/* end of test_speedup.c */
