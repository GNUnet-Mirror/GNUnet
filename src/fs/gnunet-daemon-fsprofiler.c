/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff

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
 * @file fs/gnunet-daemon-fsprofiler.c
 * @brief daemon that publishes and downloads (random) files
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_fs_service.h"
#include "gnunet_statistics_service.h"

/**
 * Return value from 'main'.
 */
static int global_ret;

/**
 * Configuration we use.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to the statistics service.
 */
static struct GNUNET_STATISTICS_Handle *stats_handle;

/**
 * Peer's FS handle.
 */
static struct GNUNET_FS_Handle *fs_handle;

/**
 * Unique number for this peer in the testbed.
 */
static unsigned long long my_peerid;





/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != fs_handle)
  {
    GNUNET_FS_stop (fs_handle);
    fs_handle = NULL;
  }

  if (NULL != stats_handle)
  {
    GNUNET_STATISTICS_destroy (stats_handle, GNUNET_YES);
    stats_handle = NULL;
  }
}


/**
 * Notification of FS to a client about the progress of an
 * operation.  Callbacks of this type will be used for uploads,
 * downloads and searches.  Some of the arguments depend a bit
 * in their meaning on the context in which the callback is used.
 *
 * @param cls closure
 * @param info details about the event, specifying the event type
 *        and various bits about the event
 * @return client-context (for the next progress call
 *         for this operation; should be set to NULL for
 *         SUSPEND and STOPPED events).  The value returned
 *         will be passed to future callbacks in the respective
 *         field in the GNUNET_FS_ProgressInfo struct.
 */
static void *
progress_cb (void *cls,
	     const struct GNUNET_FS_ProgressInfo *info)
{
  return NULL;
}


/**
 * @brief Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg_ configuration
 */
static void
run (void *cls, char *const *args GNUNET_UNUSED,
     const char *cfgfile GNUNET_UNUSED,
     const struct GNUNET_CONFIGURATION_Handle *cfg_)
{
  cfg = cfg_;
  /* Scheduled the task to clean up when shutdown is called */
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, 
					     "TESTBED", "PEERID",
                                             &my_peerid))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
			       "TESTBED", "PEERID");
    global_ret = GNUNET_SYSERR;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  stats_handle = GNUNET_STATISTICS_create ("fsprofiler", cfg);
  fs_handle =
    GNUNET_FS_start (cfg,
		     "fsprofiler",
		     &progress_cb, NULL,
		     GNUNET_FS_FLAGS_NONE,
		     GNUNET_FS_OPTIONS_DOWNLOAD_PARALLELISM, 1,
		     GNUNET_FS_OPTIONS_REQUEST_PARALLELISM, 1,
		     GNUNET_FS_OPTIONS_END);

  if (NULL == fs_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Could not acquire FS handle. Exiting.\n");
    global_ret = GNUNET_SYSERR;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

}


/**
 * Program that performs various "random" FS activities.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-daemon-fsprofiler",
                              gettext_noop
                              ("Daemon to use file-sharing to measure its performance."),
                              options, &run, NULL)) ? global_ret : 1;
}

/* end of gnunet-daemon-fsprofiler.c */
