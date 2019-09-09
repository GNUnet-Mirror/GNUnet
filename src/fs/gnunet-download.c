/*
     This file is part of GNUnet.
     Copyright (C) 2001, 2002, 2004, 2005, 2006, 2007, 2009 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */
/**
 * @file fs/gnunet-download.c
 * @brief downloading for files on GNUnet
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author James Blackwell
 * @author Igor Wronsky
 */
#include "platform.h"
#include "gnunet_fs_service.h"

static int ret;

static unsigned int verbose;

static int delete_incomplete;

static const struct GNUNET_CONFIGURATION_Handle *cfg;

static struct GNUNET_FS_Handle *ctx;

static struct GNUNET_FS_DownloadContext *dc;

static unsigned int anonymity = 1;

static unsigned int parallelism = 16;

static unsigned int request_parallelism = 4092;

static int do_recursive;

static char *filename;

static int local_only;


static void
cleanup_task(void *cls)
{
  GNUNET_FS_stop(ctx);
  ctx = NULL;
}


static void
shutdown_task(void *cls)
{
  if (NULL != dc)
    {
      GNUNET_FS_download_stop(dc, delete_incomplete);
      dc = NULL;
    }
}


/**
 * Display progress bar (if tty).
 *
 * @param x current position in the download
 * @param n total size of the download
 * @param w desired number of steps in the progress bar
 */
static void
display_bar(unsigned long long x, unsigned long long n, unsigned int w)
{
  char buf[w + 20];
  unsigned int p;
  unsigned int endeq;
  float ratio_complete;

  if (0 == isatty(1))
    return;
  ratio_complete = x / (float)n;
  endeq = ratio_complete * w;
  GNUNET_snprintf(buf, sizeof(buf), "%3d%% [", (int)(ratio_complete * 100));
  for (p = 0; p < endeq; p++)
    strcat(buf, "=");
  for (p = endeq; p < w; p++)
    strcat(buf, " ");
  strcat(buf, "]\r");
  printf("%s", buf);
  fflush(stdout);
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
 *         field in the `struct GNUNET_FS_ProgressInfo`
 */
static void *
progress_cb(void *cls, const struct GNUNET_FS_ProgressInfo *info)
{
  char *s;
  const char *s2;
  char *t;

  switch (info->status)
    {
    case GNUNET_FS_STATUS_DOWNLOAD_START:
      if (verbose > 1)
        fprintf(stderr,
                _("Starting download `%s'.\n"),
                info->value.download.filename);
      break;

    case GNUNET_FS_STATUS_DOWNLOAD_PROGRESS:
      if (verbose)
        {
          s = GNUNET_strdup(
            GNUNET_STRINGS_relative_time_to_string(info->value.download.eta,
                                                   GNUNET_YES));
          if (info->value.download.specifics.progress.block_download_duration
              .rel_value_us == GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us)
            s2 = _("<unknown time>");
          else
            s2 = GNUNET_STRINGS_relative_time_to_string(info->value.download
                                                        .specifics.progress
                                                        .block_download_duration,
                                                        GNUNET_YES);
          t = GNUNET_STRINGS_byte_size_fancy(
            info->value.download.completed * 1000LL /
            (info->value.download.duration.rel_value_us + 1));
          fprintf(
            stdout,
            _(
              "Downloading `%s' at %llu/%llu (%s remaining, %s/s). Block took %s to download\n"),
            info->value.download.filename,
            (unsigned long long)info->value.download.completed,
            (unsigned long long)info->value.download.size,
            s,
            t,
            s2);
          GNUNET_free(s);
          GNUNET_free(t);
        }
      else
        {
          display_bar(info->value.download.completed,
                      info->value.download.size,
                      60);
        }
      break;

    case GNUNET_FS_STATUS_DOWNLOAD_ERROR:
      if (0 != isatty(1))
        fprintf(stdout, "\n");
      fprintf(stderr,
              _("Error downloading: %s.\n"),
              info->value.download.specifics.error.message);
      GNUNET_SCHEDULER_shutdown();
      break;

    case GNUNET_FS_STATUS_DOWNLOAD_COMPLETED:
      s = GNUNET_STRINGS_byte_size_fancy(
        info->value.download.completed * 1000 /
        (info->value.download.duration.rel_value_us + 1));
      if (0 != isatty(1))
        fprintf(stdout, "\n");
      fprintf(stdout,
              _("Downloading `%s' done (%s/s).\n"),
              info->value.download.filename,
              s);
      GNUNET_free(s);
      if (info->value.download.dc == dc)
        GNUNET_SCHEDULER_shutdown();
      break;

    case GNUNET_FS_STATUS_DOWNLOAD_STOPPED:
      if (info->value.download.dc == dc)
        GNUNET_SCHEDULER_add_now(&cleanup_task, NULL);
      break;

    case GNUNET_FS_STATUS_DOWNLOAD_ACTIVE:
    case GNUNET_FS_STATUS_DOWNLOAD_INACTIVE:
      break;

    default:
      fprintf(stderr, _("Unexpected status: %d\n"), info->status);
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
run(void *cls,
    char *const *args,
    const char *cfgfile,
    const struct GNUNET_CONFIGURATION_Handle *c)
{
  struct GNUNET_FS_Uri *uri;
  char *emsg;
  enum GNUNET_FS_DownloadOptions options;

  if (NULL == args[0])
    {
      fprintf(stderr, "%s", _("You need to specify a URI argument.\n"));
      return;
    }
  uri = GNUNET_FS_uri_parse(args[0], &emsg);
  if (NULL == uri)
    {
      fprintf(stderr, _("Failed to parse URI: %s\n"), emsg);
      GNUNET_free(emsg);
      ret = 1;
      return;
    }
  if ((!GNUNET_FS_uri_test_chk(uri)) && (!GNUNET_FS_uri_test_loc(uri)))
    {
      fprintf(stderr, "%s", _("Only CHK or LOC URIs supported.\n"));
      ret = 1;
      GNUNET_FS_uri_destroy(uri);
      return;
    }
  if (NULL == filename)
    {
      fprintf(stderr, "%s", _("Target filename must be specified.\n"));
      ret = 1;
      GNUNET_FS_uri_destroy(uri);
      return;
    }
  cfg = c;
  ctx = GNUNET_FS_start(cfg,
                        "gnunet-download",
                        &progress_cb,
                        NULL,
                        GNUNET_FS_FLAGS_NONE,
                        GNUNET_FS_OPTIONS_DOWNLOAD_PARALLELISM,
                        parallelism,
                        GNUNET_FS_OPTIONS_REQUEST_PARALLELISM,
                        request_parallelism,
                        GNUNET_FS_OPTIONS_END);
  if (NULL == ctx)
    {
      fprintf(stderr, _("Could not initialize `%s' subsystem.\n"), "FS");
      GNUNET_FS_uri_destroy(uri);
      ret = 1;
      return;
    }
  options = GNUNET_FS_DOWNLOAD_OPTION_NONE;
  if (do_recursive)
    options |= GNUNET_FS_DOWNLOAD_OPTION_RECURSIVE;
  if (local_only)
    options |= GNUNET_FS_DOWNLOAD_OPTION_LOOPBACK_ONLY;
  dc = GNUNET_FS_download_start(ctx,
                                uri,
                                NULL,
                                filename,
                                NULL,
                                0,
                                GNUNET_FS_uri_chk_get_file_size(uri),
                                anonymity,
                                options,
                                NULL,
                                NULL);
  GNUNET_FS_uri_destroy(uri);
  if (dc == NULL)
    {
      GNUNET_FS_stop(ctx);
      ctx = NULL;
      return;
    }
  GNUNET_SCHEDULER_add_shutdown(&shutdown_task, NULL);
}


/**
 * The main function to download GNUnet.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main(int argc, char *const *argv)
{
  struct GNUNET_GETOPT_CommandLineOption options[] =
  { GNUNET_GETOPT_option_uint('a',
                              "anonymity",
                              "LEVEL",
                              gettext_noop(
                                "set the desired LEVEL of receiver-anonymity"),
                              &anonymity),

    GNUNET_GETOPT_option_flag(
      'D',
      "delete-incomplete",
      gettext_noop("delete incomplete downloads (when aborted with CTRL-C)"),
      &delete_incomplete),

    GNUNET_GETOPT_option_flag(
      'n',
      "no-network",
      gettext_noop("only search the local peer (no P2P network search)"),
      &local_only),
    GNUNET_GETOPT_option_string('o',
                                "output",
                                "FILENAME",
                                gettext_noop("write the file to FILENAME"),
                                &filename),
    GNUNET_GETOPT_option_uint(
      'p',
      "parallelism",
      "DOWNLOADS",
      gettext_noop(
        "set the maximum number of parallel downloads that is allowed"),
      &parallelism),
    GNUNET_GETOPT_option_uint(
      'r',
      "request-parallelism",
      "REQUESTS",
      gettext_noop(
        "set the maximum number of parallel requests for blocks that is allowed"),
      &request_parallelism),
    GNUNET_GETOPT_option_flag('R',
                              "recursive",
                              gettext_noop(
                                "download a GNUnet directory recursively"),
                              &do_recursive),
    GNUNET_GETOPT_option_increment_uint(
      'V',
      "verbose",
      gettext_noop("be verbose (print progress information)"),
      &verbose),
    GNUNET_GETOPT_OPTION_END };

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args(argc, argv, &argc, &argv))
    return 2;

  ret =
    (GNUNET_OK ==
     GNUNET_PROGRAM_run(
       argc,
       argv,
       "gnunet-download [OPTIONS] URI",
       gettext_noop(
         "Download files from GNUnet using a GNUnet CHK or LOC URI (gnunet://fs/chk/...)"),
       options,
       &run,
       NULL))
    ? ret
    : 1;
  GNUNET_free((void *)argv);
  return ret;
}

/* end of gnunet-download.c */
