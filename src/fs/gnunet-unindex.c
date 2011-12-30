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
 * @file fs/gnunet-unindex.c
 * @brief unindex files published on GNUnet
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author James Blackwell
 * @author Igor Wronsky
 */
#include "platform.h"
#include "gnunet_fs_service.h"

static int ret;

static int verbose;

static const struct GNUNET_CONFIGURATION_Handle *cfg;

static struct GNUNET_FS_Handle *ctx;

static struct GNUNET_FS_UnindexContext *uc;


static void
cleanup_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_FS_stop (ctx);
  ctx = NULL;
}


static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_UnindexContext *u;

  if (uc != NULL)
  {
    u = uc;
    uc = NULL;
    GNUNET_FS_unindex_stop (u);
  }
}

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
progress_cb (void *cls, const struct GNUNET_FS_ProgressInfo *info)
{
  char *s;

  switch (info->status)
  {
  case GNUNET_FS_STATUS_UNINDEX_START:
    break;
  case GNUNET_FS_STATUS_UNINDEX_PROGRESS:
    if (verbose)
    {
      s = GNUNET_STRINGS_relative_time_to_string (info->value.unindex.eta);
      FPRINTF (stdout, _("Unindexing at %llu/%llu (%s remaining)\n"),
               (unsigned long long) info->value.unindex.completed,
               (unsigned long long) info->value.unindex.size, s);
      GNUNET_free (s);
    }
    break;
  case GNUNET_FS_STATUS_UNINDEX_ERROR:
    FPRINTF (stderr, _("Error unindexing: %s.\n"),
             info->value.unindex.specifics.error.message);
    GNUNET_SCHEDULER_shutdown ();
    break;
  case GNUNET_FS_STATUS_UNINDEX_COMPLETED:
    FPRINTF (stdout, "%s",  _("Unindexing done.\n"));
    GNUNET_SCHEDULER_shutdown ();
    break;
  case GNUNET_FS_STATUS_UNINDEX_STOPPED:
    GNUNET_SCHEDULER_add_continuation (&cleanup_task, NULL,
                                       GNUNET_SCHEDULER_REASON_PREREQ_DONE);
    break;
  default:
    FPRINTF (stderr, _("Unexpected status: %d\n"), info->status);
    break;
  }
  return NULL;
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param c configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  /* check arguments */
  if ((args[0] == NULL) || (args[1] != NULL))
  {
    printf (_("You must specify one and only one filename for unindexing.\n"));
    ret = -1;
    return;
  }
  cfg = c;
  ctx =
      GNUNET_FS_start (cfg, "gnunet-unindex", &progress_cb, NULL,
                       GNUNET_FS_FLAGS_NONE, GNUNET_FS_OPTIONS_END);
  if (NULL == ctx)
  {
    FPRINTF (stderr, _("Could not initialize `%s' subsystem.\n"), "FS");
    ret = 1;
    return;
  }
  uc = GNUNET_FS_unindex_start (ctx, args[0], NULL);
  if (NULL == uc)
  {
    FPRINTF (stderr, "%s",  _("Could not start unindex operation.\n"));
    GNUNET_FS_stop (ctx);
    return;
  }
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);
}


/**
 * The main function to unindex content.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'V', "verbose", NULL,
     gettext_noop ("be verbose (print progress information)"),
     0, &GNUNET_GETOPT_set_one, &verbose},
    GNUNET_GETOPT_OPTION_END
  };
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-unindex [OPTIONS] FILENAME",
                              gettext_noop
                              ("Unindex a file that was previously indexed with gnunet-publish."),
                              options, &run, NULL)) ? ret : 1;
}

/* end of gnunet-unindex.c */
