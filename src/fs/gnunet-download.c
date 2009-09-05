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
 * @file fs/gnunet-download.c
 * @brief downloading for files on GNUnet
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author James Blackwell
 * @author Igor Wronsky
 *
 * TODO:
 * - all
 */
#include "platform.h"
#include "gnunet_fs_service.h"

static int ret;

static const struct GNUNET_CONFIGURATION_Handle *cfg;

static struct GNUNET_FS_Handle *ctx;

static struct GNUNET_TIME_Absolute start_time;

static unsigned int anonymity = 1;


/**
 * Called by FS client to give information about the progress of an 
 * operation.
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
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  /* FIXME: check arguments */
  cfg = c;
  ctx = GNUNET_FS_start (sched,
			 cfg,
			 "gnunet-download",
			 &progress_cb,
			 NULL);
  if (NULL == ctx)
    {
      fprintf (stderr,
	       _("Could not initialize `%s' subsystem.\n"),
	       "FS");
      ret = 1;
      return;
    }
  start_time = GNUNET_TIME_absolute_get ();
  // FIXME: start download
}


/**
 * gnunet-download command line options
 */
static struct GNUNET_GETOPT_CommandLineOption options[] = {
  {'a', "anonymity", "LEVEL",
   gettext_noop ("set the desired LEVEL of receiver-anonymity"),
   1, &GNUNET_GETOPT_set_uint, &anonymity},
  // FIXME: options!
  GNUNET_GETOPT_OPTION_END
};


/**
 * The main function to download GNUnet.
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
                              "gnunet-download",
                              gettext_noop
                              ("Download files from GNUnet."),
                              options, &run, NULL)) ? ret : 1;
}

/* end of gnunet-download.c */

