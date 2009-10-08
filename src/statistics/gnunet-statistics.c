/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2006, 2007, 2009 Christian Grothoff (and other contributing authors)

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
 * @file statistics/gnunet-statistics.c
 * @brief tool to obtain statistics
 * @author Christian Grothoff
 * @author Igor Wronsky
 */
#include "platform.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_statistics_service.h"
#include "statistics.h"

#define GET_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15)

/**
 * Final status code.
 */
static int ret;

/**
 * Set to subsystem that we're going to get stats for (or NULL for all).
 */
static char *subsystem;

/**
 * Set to the specific stat value that we are after (or NULL for all).
 */
static char *name;

/**
 * Make the value that is being set persistent.
 */
static int persistent;

/**
 * Callback function to process statistic values.
 *
 * @param cls closure
 * @param subsystem name of subsystem that created the statistic
 * @param name the name of the datum
 * @param value the current value
 * @param is_persistent GNUNET_YES if the value is persistent, GNUNET_NO if not
 * @return GNUNET_OK to continue, GNUNET_SYSERR to abort iteration
 */
static int
printer (void *cls,
         const char *subsystem,
         const char *name, unsigned long long value, int is_persistent)
{
  FPRINTF (stdout,
           "%s%-20s %-40s: %16llu\n",
           is_persistent ? "!" : " ", subsystem, _(name), value);
  return GNUNET_OK;
}


/**
 * Function called last by the statistics code.
 *
 * @param cls closure
 * @param success GNUNET_OK if statistics were
 *        successfully obtained, GNUNET_SYSERR if not.
 */
static void
cleanup (void *cls, int success)
{
  struct GNUNET_STATISTICS_Handle *h = cls;

  if (success != GNUNET_OK)
    ret = 1;
  if (h != NULL)
    GNUNET_STATISTICS_destroy (h);
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param sched the scheduler to use
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *sched,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_STATISTICS_Handle *h;
  unsigned long long val;

  if (args[0] != NULL)
    {
      if ((1 != SSCANF (args[0], "%llu", &val)) ||
          (subsystem == NULL) || (name == NULL))
        {
          FPRINTF (stderr, _("Invalid argument `%s'\n"), args[0]);
          ret = 1;
          return;
        }
      h = GNUNET_STATISTICS_create (sched, subsystem, cfg);
      if (h == NULL)
        {
          ret = 1;
          return;
        }
      GNUNET_STATISTICS_set (h, name, val, persistent);
      GNUNET_STATISTICS_destroy (h);
      return;
    }
  h = GNUNET_STATISTICS_create (sched, "gnunet-statistics", cfg);
  if (h == NULL)
    {
      ret = 1;
      return;
    }
  GNUNET_STATISTICS_get (h,
                         subsystem, name, GET_TIMEOUT, &cleanup, &printer, h);
}

/**
 * gnunet-statistics command line options
 */
static struct GNUNET_GETOPT_CommandLineOption options[] = {
  {'n', "name", "NAME",
   gettext_noop ("limit output to statistcs for the given NAME"), 1,
   &GNUNET_GETOPT_set_string, &name},
  {'p', "persistent", NULL,
   gettext_noop ("make the value being set persistent"), 0,
   &GNUNET_GETOPT_set_one, &persistent},
  {'s', "subsystem", "SUBSYSTEM",
   gettext_noop ("limit output to the given SUBSYSTEM"), 1,
   &GNUNET_GETOPT_set_string, &subsystem},
  GNUNET_GETOPT_OPTION_END
};


/**
 * The main function to obtain statistics in GNUnet.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc,
                              argv,
                              "gnunet-statistics",
                              gettext_noop
                              ("Print statistics about GNUnet operations."),
                              options, &run, NULL)) ? ret : 1;
}

/* end of gnunet-statistics.c */
