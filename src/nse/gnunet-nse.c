/*
      This file is part of GNUnet
      Copyright (C) 2008--2014 Christian Grothoff (and other contributing authors)

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
 * @file nse/gnunet-nse.c
 * @brief Program to display network size estimates from the NSE service
 * @author Sree Harsha Totakura <sreeharsha@totakura.in> 
 */

#include "platform.h"
#include "gnunet_nse_service.h"

/**
 * Handle to our configuration
 */
static struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * The handle to the NSE service
 */
static struct GNUNET_NSE_Handle *nse;

/**
 * The handle to test if NSE service is running or not
 */
static struct GNUNET_CLIENT_TestHandle *test;

/**
 * Shutdown task
 */
static struct GNUNET_SCHEDULER_Task * shutdown_task;

/**
 * The program status; 0 for success.
 */
static int status;


/**
 * Task to shutdown and clean up all state
 *
 * @param cls NULL
 * @param tc the scheduler task context
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  shutdown_task = NULL;
  if (NULL != test)
    GNUNET_CLIENT_service_test_cancel (test);
  if (NULL != nse)
    GNUNET_NSE_disconnect (nse);
  if (NULL != cfg)
    GNUNET_CONFIGURATION_destroy (cfg);
}


/**
 * Callback to call when network size estimate is updated.
 *
 * @param cls NULL
 * @param timestamp server timestamp
 * @param estimate the value of the current network size estimate
 * @param std_dev standard deviation (rounded down to nearest integer)
 *                of the size estimation values seen
 */
static void
handle_estimate (void *cls,
		 struct GNUNET_TIME_Absolute timestamp,
                 double estimate, double std_dev)
{
  FPRINTF (stdout, "%llu %f %f %f\n",
           (unsigned long long) timestamp.abs_value_us,
           GNUNET_NSE_log_estimate_to_n (estimate),
           estimate,
           std_dev);
}


/**
 * Function called with the result on the service test for the NSE service
 *
 * @param cls NULL
 * @param result #GNUNET_YES if the service is running,
 *               #GNUNET_NO if the service is not running
 *               #GNUNET_SYSERR if the configuration is invalid
 */
static void
nse_test_result (void *cls, int result)
{
  test = NULL;
  switch (result)
  {
  case GNUNET_YES:
    nse = GNUNET_NSE_connect (cfg, &handle_estimate, NULL);
    status = 0;
    break;
  case GNUNET_NO:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("NSE service is not running\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Error while checking if NSE service is running or not\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
}


/**
 * Actual main function that runs the emulation.
 *
 * @param cls unused
 * @param args remaining args, unused
 * @param cfgfile name of the configuration
 * @param cfg configuration handle
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *_cfg)
{
  cfg = GNUNET_CONFIGURATION_dup (_cfg);
  test = GNUNET_CLIENT_service_test ("nse",
                                     cfg,
                                     GNUNET_TIME_UNIT_SECONDS,
                                     nse_test_result,
                                     NULL);
  shutdown_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                                &do_shutdown, NULL);
}


/**
 * Main function.
 *
 * @return 0 on success
 */
int
main (int argc, char *const *argv)
{
  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  
  status = 1;
  if (GNUNET_OK !=
      GNUNET_PROGRAM_run (argc, argv, "gnunet-nse",
			  gettext_noop
			  ("Show network size estimates from NSE service."),
			  options, &run, NULL))
    return 2;
  return status;
}
