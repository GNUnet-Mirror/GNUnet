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
 * @file fs/gnunet-search.c
 * @brief searching for files on GNUnet
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author James Blackwell
 * @author Igor Wronsky
 */
#include "platform.h"
#include "gnunet_fs_service.h"

static int ret;

static const struct GNUNET_CONFIGURATION_Handle *cfg;

static struct GNUNET_FS_Handle *ctx;

static struct GNUNET_FS_SearchContext *sc;

static char *output_filename;

static struct GNUNET_FS_DirectoryBuilder *db;

static unsigned int anonymity = 1;

static unsigned long long timeout;

static unsigned int results_limit;

static unsigned int results = 0;

static int verbose;

static int local_only;

/**
 * Type of a function that libextractor calls for each
 * meta data item found.
 *
 * @param cls closure (user-defined, unused)
 * @param plugin_name name of the plugin that produced this value;
 *        special values can be used (i.e. '&lt;zlib&gt;' for zlib being
 *        used in the main libextractor library and yielding
 *        meta data).
 * @param type libextractor-type describing the meta data
 * @param format basic format information about data
 * @param data_mime_type mime-type of data (not of the original file);
 *        can be NULL (if mime-type is not known)
 * @param data actual meta-data found
 * @param data_size number of bytes in data
 * @return 0 to continue extracting, 1 to abort
 */
static int
item_printer (void *cls, const char *plugin_name, enum EXTRACTOR_MetaType type,
              enum EXTRACTOR_MetaFormat format, const char *data_mime_type,
              const char *data, size_t data_size)
{
  if ((format != EXTRACTOR_METAFORMAT_UTF8) &&
      (format != EXTRACTOR_METAFORMAT_C_STRING))
    return 0;
  if (type == EXTRACTOR_METATYPE_GNUNET_ORIGINAL_FILENAME)
    return 0;
  printf ("\t%20s: %s\n",
          dgettext (LIBEXTRACTOR_GETTEXT_DOMAIN,
                    EXTRACTOR_metatype_to_string (type)), data);
  return 0;
}


static void
clean_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  size_t dsize;
  void *ddata;

  GNUNET_FS_stop (ctx);
  ctx = NULL;
  if (output_filename == NULL)
    return;
  if (GNUNET_OK != GNUNET_FS_directory_builder_finish (db, &dsize, &ddata))
  {
    GNUNET_break (0);
    GNUNET_free (output_filename);
    return;
  }
  if (dsize !=
      GNUNET_DISK_fn_write (output_filename, ddata, dsize,
                            GNUNET_DISK_PERM_USER_READ |
                            GNUNET_DISK_PERM_USER_WRITE))
  {
    FPRINTF (stderr,
             _("Failed to write directory with search results to `%s'\n"),
             output_filename);
  }
  GNUNET_free_non_null (ddata);
  GNUNET_free (output_filename);
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
  static unsigned int cnt;
  char *uri;
  char *dotdot;
  char *filename;

  switch (info->status)
  {
  case GNUNET_FS_STATUS_SEARCH_START:
    break;
  case GNUNET_FS_STATUS_SEARCH_RESULT:
    if (db != NULL)
      GNUNET_FS_directory_builder_add (db,
                                       info->value.search.specifics.result.uri,
                                       info->value.search.specifics.result.meta,
                                       NULL);
    uri = GNUNET_FS_uri_to_string (info->value.search.specifics.result.uri);
    printf ("#%u:\n", cnt++);
    filename =
        GNUNET_CONTAINER_meta_data_get_by_type (info->value.search.
                                                specifics.result.meta,
                                                EXTRACTOR_METATYPE_GNUNET_ORIGINAL_FILENAME);
    if (filename != NULL)
    {
      while (NULL != (dotdot = strstr (filename, "..")))
        dotdot[0] = dotdot[1] = '_';
      printf ("gnunet-download -o \"%s\" %s\n", filename, uri);
    }
    else
      printf ("gnunet-download %s\n", uri);
    if (verbose)
      GNUNET_CONTAINER_meta_data_iterate (info->value.search.specifics.
                                          result.meta, &item_printer, NULL);
    printf ("\n");
    fflush (stdout);
    GNUNET_free_non_null (filename);
    GNUNET_free (uri);
    results++;
    if ((results_limit > 0) && (results >= results_limit))
      GNUNET_SCHEDULER_shutdown ();
    break;
  case GNUNET_FS_STATUS_SEARCH_UPDATE:
    break;
  case GNUNET_FS_STATUS_SEARCH_RESULT_STOPPED:
    /* ignore */
    break;
  case GNUNET_FS_STATUS_SEARCH_ERROR:
    FPRINTF (stderr, _("Error searching: %s.\n"),
             info->value.search.specifics.error.message);
    GNUNET_SCHEDULER_shutdown ();
    break;
  case GNUNET_FS_STATUS_SEARCH_STOPPED:
    GNUNET_SCHEDULER_add_continuation (&clean_task, NULL,
                                       GNUNET_SCHEDULER_REASON_PREREQ_DONE);
    break;
  default:
    FPRINTF (stderr, _("Unexpected status: %d\n"), info->status);
    break;
  }
  return NULL;
}


static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (sc != NULL)
  {
    GNUNET_FS_search_stop (sc);
    sc = NULL;
  }
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
  struct GNUNET_FS_Uri *uri;
  unsigned int argc;
  enum GNUNET_FS_SearchOptions options;
  struct GNUNET_TIME_Relative delay;

  argc = 0;
  while (NULL != args[argc])
    argc++;
  uri = GNUNET_FS_uri_ksk_create_from_args (argc, (const char **) args);
  if (NULL == uri)
  {
    FPRINTF (stderr, "%s",  _("Could not create keyword URI from arguments.\n"));
    ret = 1;
    return;
  }
  cfg = c;
  ctx =
      GNUNET_FS_start (cfg, "gnunet-search", &progress_cb, NULL,
                       GNUNET_FS_FLAGS_NONE, GNUNET_FS_OPTIONS_END);
  if (NULL == ctx)
  {
    FPRINTF (stderr, _("Could not initialize `%s' subsystem.\n"), "FS");
    GNUNET_FS_uri_destroy (uri);
    ret = 1;
    return;
  }
  if (output_filename != NULL)
    db = GNUNET_FS_directory_builder_create (NULL);
  options = GNUNET_FS_SEARCH_OPTION_NONE;
  if (local_only)
    options |= GNUNET_FS_SEARCH_OPTION_LOOPBACK_ONLY;
  sc = GNUNET_FS_search_start (ctx, uri, anonymity, options, NULL);
  GNUNET_FS_uri_destroy (uri);
  if (NULL == sc)
  {
    FPRINTF (stderr, "%s",  _("Could not start searching.\n"));
    GNUNET_FS_stop (ctx);
    ret = 1;
    return;
  }
  if (timeout != 0)
  {
    delay.rel_value = timeout;
    GNUNET_SCHEDULER_add_delayed (delay, &shutdown_task, NULL);
  }
  else
  {
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                  NULL);
  }
}


/**
 * The main function to search GNUnet.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'a', "anonymity", "LEVEL",
     gettext_noop ("set the desired LEVEL of receiver-anonymity"),
     1, &GNUNET_GETOPT_set_uint, &anonymity},
    {'n', "no-network", NULL,
     gettext_noop ("only search the local peer (no P2P network search)"),
     0, &GNUNET_GETOPT_set_one, &local_only},
    {'o', "output", "PREFIX",
     gettext_noop ("write search results to file starting with PREFIX"),
     1, &GNUNET_GETOPT_set_string, &output_filename},
    {'t', "timeout", "VALUE",
     gettext_noop ("automatically terminate search after VALUE ms"),
     1, &GNUNET_GETOPT_set_ulong, &timeout},
    {'V', "verbose", NULL,
     gettext_noop ("be verbose (print progress information)"),
     0, &GNUNET_GETOPT_set_one, &verbose},
    {'N', "results", "VALUE",
     gettext_noop
     ("automatically terminate search after VALUE results are found"),
     1, &GNUNET_GETOPT_set_uint, &results_limit},
    GNUNET_GETOPT_OPTION_END
  };
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-search [OPTIONS] KEYWORD",
                              gettext_noop
                              ("Search GNUnet for files that were published on GNUnet"),
                              options, &run, NULL)) ? ret : 1;
}

/* end of gnunet-search.c */
