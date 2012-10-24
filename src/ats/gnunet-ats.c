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
 * @file ats/gnunet-ats.c
 * @brief ATS command line tool
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_ats_service.h"

/**
 * Final status code.
 */
static int ret;
static int results;

static struct GNUNET_ATS_PerformanceHandle *ph;

GNUNET_SCHEDULER_TaskIdentifier end_task;

void ats_perf_cb (void *cls,
                  const struct
                  GNUNET_HELLO_Address *
                  address,
                  struct
                  GNUNET_BANDWIDTH_Value32NBO
                  bandwidth_out,
                  struct
                  GNUNET_BANDWIDTH_Value32NBO
                  bandwidth_in,
                  const struct
                  GNUNET_ATS_Information *
                  ats, uint32_t ats_count)
{
  fprintf (stderr, "Peer `%s'\n", GNUNET_i2s (&address->peer));
  results++;
}

void end (void *cls,
          const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_ATS_performance_done (ph);
  ph = NULL;
  /*FIXME */fprintf (stderr, "NOT IMPLEMENTED!\n");
  fprintf (stderr, "ATS returned %u addresses\n", results);
  ret = 0;
}

void testservice_task (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CONFIGURATION_Handle *cfg = cls;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_TIMEOUT))
  {
      FPRINTF (stderr, _("Service `%s' is not running\n"), "ats");
      return;
  }

  ph = GNUNET_ATS_performance_init (cfg, NULL, NULL);
  if (NULL == ph)
    fprintf (stderr, "Cannot connect to ATS service, exiting...\n");

  end_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &end, NULL);
  ret = 1;
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
  GNUNET_CLIENT_service_test ("ats", cfg,
                              GNUNET_TIME_UNIT_SECONDS,
                              &testservice_task,
                              (void *) cfg);
}


/**
 * The main function.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  int res;
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  res = GNUNET_PROGRAM_run (argc, argv, "gnunet-ats",
                              gettext_noop ("Print information about ATS state"), options, &run,
                              NULL);
  GNUNET_free ((void *) argv);

  if (GNUNET_OK == res)
    return ret;
  else
    return 1;

}

/* end of gnunet-ats.c */
