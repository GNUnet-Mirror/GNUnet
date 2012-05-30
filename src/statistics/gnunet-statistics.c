/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2006, 2007, 2009 Christian Grothoff (and other contributing authors)

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
 * @file statistics/gnunet-statistics.c
 * @brief tool to obtain statistics
 * @author Christian Grothoff
 * @author Igor Wronsky
 */
#include "platform.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "statistics.h"

#define GET_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)

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
 * Watch value continuously
 */
static int watch;

/**
 * Quiet mode
 */
static int quiet;


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
printer (void *cls, const char *subsystem, const char *name, uint64_t value,
         int is_persistent)
{
  struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get();
  char * now_str;
  if (quiet == GNUNET_NO)
  {
    if (GNUNET_YES == watch)
    {
      now_str = GNUNET_STRINGS_absolute_time_to_string(now);
      FPRINTF (stdout, "%24s %s%12s %50s: %16llu \n",
               now_str,
               is_persistent ? "!" : " ",
               subsystem, _(name), (unsigned long long) value);
      GNUNET_free (now_str);
    }
    else
    {
      FPRINTF (stdout, "%s%12s %50s: %16llu \n",
               is_persistent ? "!" : " ",
               subsystem, _(name), (unsigned long long) value);
    }
  }
  else
    FPRINTF (stdout, "%llu\n", (unsigned long long) value);

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
  {
    FPRINTF (stderr, "%s", _("Failed to obtain statistics.\n"));
    ret = 1;
  }
  if (NULL != h)
  {
    GNUNET_STATISTICS_destroy (h, GNUNET_NO);
    h = NULL;
  }
}


static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_STATISTICS_Handle *h = cls;

  GNUNET_STATISTICS_watch_cancel (h, subsystem, name, &printer, h);
  if (NULL != h)
  {
    GNUNET_STATISTICS_destroy (h, GNUNET_NO);
    h = NULL;
  }
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_STATISTICS_Handle *h;
  unsigned long long val;

  if (args[0] != NULL)
  {
    if ((1 != SSCANF (args[0], "%llu", &val)) || (subsystem == NULL) ||
        (name == NULL))
    {
      FPRINTF (stderr, _("Invalid argument `%s'\n"), args[0]);
      ret = 1;
      return;
    }
    h = GNUNET_STATISTICS_create (subsystem, cfg);
    if (NULL == h)
    {
      ret = 1;
      return;
    }
    GNUNET_STATISTICS_set (h, name, (uint64_t) val, persistent);
    GNUNET_STATISTICS_destroy (h, GNUNET_YES);
    h = NULL;
    return;
  }
  h = GNUNET_STATISTICS_create ("gnunet-statistics", cfg);
  if (NULL == h)
  {
    ret = 1;
    return;
  }
  if (GNUNET_NO == watch)
  {
    if (NULL ==
      GNUNET_STATISTICS_get (h, subsystem, name, GET_TIMEOUT, &cleanup,
                             &printer, h))
    cleanup (h, GNUNET_SYSERR);
  }
  else
  {
    if ((NULL == subsystem) || (NULL == name))
    {
      printf (_("No subsystem or name given\n"));
      if (h != NULL)
        GNUNET_STATISTICS_destroy (h, GNUNET_NO);
      ret = 1;
      return;
    }
    if (GNUNET_OK != GNUNET_STATISTICS_watch (h, subsystem, name, &printer, h))
    {
      fprintf (stderr, _("Failed to initialize watch routine\n"));
      GNUNET_SCHEDULER_add_now (&shutdown_task, h);
      return;
    }
    GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task, h);
  }
}

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
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'n', "name", "NAME",
     gettext_noop ("limit output to statistics for the given NAME"), 1,
     &GNUNET_GETOPT_set_string, &name},
    {'p', "persistent", NULL,
     gettext_noop ("make the value being set persistent"), 0,
     &GNUNET_GETOPT_set_one, &persistent},
    {'s', "subsystem", "SUBSYSTEM",
     gettext_noop ("limit output to the given SUBSYSTEM"), 1,
     &GNUNET_GETOPT_set_string, &subsystem},
    {'q', "quiet", NULL,
     gettext_noop ("just print the statistics value"), 0,
     &GNUNET_GETOPT_set_one, &quiet},
    {'w', "watch", NULL,
     gettext_noop ("watch value continously"), 0,
     &GNUNET_GETOPT_set_one, &watch},
    GNUNET_GETOPT_OPTION_END
  };
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-statistics [options [value]]",
                              gettext_noop
                              ("Print statistics about GNUnet operations."),
                              options, &run, NULL)) ? ret : 1;
}

/* end of gnunet-statistics.c */
