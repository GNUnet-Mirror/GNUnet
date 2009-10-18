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
 * - many command-line options
 */
#include "platform.h"
#include "gnunet_fs_service.h"

static int ret;

static int verbose;

static int delete_incomplete;

static const struct GNUNET_CONFIGURATION_Handle *cfg;

static struct GNUNET_FS_Handle *ctx;

static struct GNUNET_FS_DownloadContext *dc;

static unsigned int anonymity = 1;

static char *filename;

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
  switch (info->status)
    {
    case GNUNET_FS_STATUS_DOWNLOAD_START:
      break;
    case GNUNET_FS_STATUS_DOWNLOAD_PROGRESS:
      if (verbose)
	fprintf (stdout,
		 _("Downloading `%s' at %llu/%llu (%s remaining, %s/s)\n"),
		 info->value.download.filename,
		 (unsigned long long) info->value.download.completed,
		 (unsigned long long) info->value.download.size,
		 GNUNET_STRINGS_relative_time_to_string(info->value.download.eta),
		 GNUNET_STRINGS_byte_size_fancy(info->value.download.completed * 1000 / (info->value.download.duration.value + 1)));
      break;
    case GNUNET_FS_STATUS_DOWNLOAD_ERROR:
      fprintf (stderr,
	       _("Error downloading: %s.\n"),
	       info->value.download.specifics.error.message);
      GNUNET_FS_download_stop (dc, delete_incomplete); 
      break;
    case GNUNET_FS_STATUS_DOWNLOAD_COMPLETED:
      fprintf (stdout,
	       _("Downloading `%s' done (%s/s).\n"),
	       info->value.download.filename,
	       GNUNET_STRINGS_byte_size_fancy(info->value.download.completed * 1000 / (info->value.download.duration.value + 1)));
      if (info->value.download.dc == dc)
	GNUNET_FS_download_stop (dc, delete_incomplete);
      break;
    case GNUNET_FS_STATUS_DOWNLOAD_STOPPED: 
      if (info->value.download.dc == dc)
	GNUNET_FS_stop (ctx);
      break;      
    default:
      fprintf (stderr,
	       _("Unexpected status: %d\n"),
	       info->status);
      break;
    }
  return NULL;
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param sched the scheduler to use
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param c configuration
 */
static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *sched,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  struct GNUNET_FS_Uri *uri;
  char *emsg;
  enum GNUNET_FS_DownloadOptions options;

  /* FIXME: check arguments */
  uri = GNUNET_FS_uri_parse (args[0],
			     &emsg);
  if (NULL == uri)
    {
      fprintf (stderr,
	       _("Failed to parse URI: %s\n"),
	       emsg);
      GNUNET_free (emsg);
      ret = 1;
      return;
    }
  if (! GNUNET_FS_uri_test_chk (uri))
    {
      fprintf (stderr,
	       "Only CHK URIs supported right now.\n");
      ret = 1;
      GNUNET_FS_uri_destroy (uri);
      return;		 
    }
  if (NULL == filename)
    {
      fprintf (stderr,
	       "Target filename must be specified.\n");
      ret = 1;
      GNUNET_FS_uri_destroy (uri);
      return;		 
    }
  cfg = c;
  ctx = GNUNET_FS_start (sched,
			 cfg,
			 "gnunet-download",
			 &progress_cb,
			 NULL,
			 GNUNET_FS_FLAGS_NONE,
			 GNUNET_FS_OPTIONS_END);
  if (NULL == ctx)
    {
      fprintf (stderr,
	       _("Could not initialize `%s' subsystem.\n"),
	       "FS");
      GNUNET_FS_uri_destroy (uri);
      ret = 1;
      return;
    }
  options = GNUNET_FS_DOWNLOAD_OPTION_NONE;
  dc = GNUNET_FS_download_start (ctx,
				 uri,
				 NULL,
				 filename,
				 0,
				 GNUNET_FS_uri_chk_get_file_size (uri),
				 anonymity,
				 options,
				 NULL);
  GNUNET_FS_uri_destroy (uri);
}


/**
 * gnunet-download command line options
 */
static struct GNUNET_GETOPT_CommandLineOption options[] = {
  {'a', "anonymity", "LEVEL",
   gettext_noop ("set the desired LEVEL of receiver-anonymity"),
   1, &GNUNET_GETOPT_set_uint, &anonymity},
#if 0
  // FIXME: options!
  {'d', "directory", NULL,
   gettext_noop
   ("download a GNUnet directory that has already been downloaded.  Requires that a filename of an existing file is specified instead of the URI.  The download will only download the top-level files in the directory unless the `-R' option is also specified."),
   0, &GNUNET_getopt_configure_set_one, &do_directory},
  {'D', "delete-incomplete", NULL,
   gettext_noop ("delete incomplete downloads (when aborted with CTRL-C)"),
   0, &GNUNET_getopt_configure_set_one, &do_delete_incomplete},
#endif
  {'o', "output", "FILENAME",
   gettext_noop ("write the file to FILENAME"),
   1, &GNUNET_GETOPT_set_string, &filename},
#if 0
  {'p', "parallelism", "DOWNLOADS",
   gettext_noop
   ("set the maximum number of parallel downloads that are allowed"),
   1, &GNUNET_getopt_configure_set_uint, &parallelism},
  {'R', "recursive", NULL,
   gettext_noop ("download a GNUnet directory recursively"),
   0, &GNUNET_getopt_configure_set_one, &do_recursive},
#endif
  {'V', "verbose", NULL,
   gettext_noop ("be verbose (print progress information)"),
   0, &GNUNET_GETOPT_set_one, &verbose},
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

