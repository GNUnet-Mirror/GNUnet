/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2006, 2007, 2009, 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file fs/gnunet-publish.c
 * @brief publishing files on GNUnet
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

static struct GNUNET_FS_PublishContext *pc;

static struct GNUNET_CONTAINER_MetaData *meta;

static struct GNUNET_FS_Uri *topKeywords;

static struct GNUNET_FS_Uri *uri;

static struct GNUNET_FS_BlockOptions bo = { {0LL}, 1, 365, 1 };

static char *uri_string;

static char *next_id;

static char *this_id;

static char *pseudonym;

static int do_insert;

static int disable_extractor;

static int do_simulate;

static int extract_only;

static int do_disable_creation_time;

static GNUNET_SCHEDULER_TaskIdentifier kill_task;

static struct GNUNET_FS_DirScanner *ds;

static struct GNUNET_FS_ShareTreeItem * directory_scan_result;

static struct GNUNET_FS_Namespace *namespace;

/**
 * FIXME: docu
 */
static void
do_stop_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_PublishContext *p;

  kill_task = GNUNET_SCHEDULER_NO_TASK;
  if (pc != NULL)
  {
    p = pc;
    pc = NULL;
    GNUNET_FS_publish_stop (p);
  }
  if (NULL != meta)
  {
    GNUNET_CONTAINER_meta_data_destroy (meta);
    meta = NULL;
  }  
}


/**
 * Stop the directory scanner (we had an error).
 *
 * @param cls closure
 * @param tc scheduler context
 */
static void
stop_scanner_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  kill_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_FS_directory_scan_abort (ds);
  ds = NULL;
  if (namespace != NULL)
  {
    GNUNET_FS_namespace_delete (namespace, GNUNET_NO);
    namespace = NULL;
  }
  GNUNET_FS_stop (ctx);
  ctx = NULL;
  ret = 1;
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
  case GNUNET_FS_STATUS_PUBLISH_START:
    break;
  case GNUNET_FS_STATUS_PUBLISH_PROGRESS:
    if (verbose)
    {
      s = GNUNET_STRINGS_relative_time_to_string (info->value.publish.eta);
      FPRINTF (stdout, _("Publishing `%s' at %llu/%llu (%s remaining)\n"),
               info->value.publish.filename,
               (unsigned long long) info->value.publish.completed,
               (unsigned long long) info->value.publish.size, s);
      GNUNET_free (s);
    }
    break;
  case GNUNET_FS_STATUS_PUBLISH_ERROR:
    FPRINTF (stderr, _("Error publishing: %s.\n"),
             info->value.publish.specifics.error.message);
    if (kill_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (kill_task);
      kill_task = GNUNET_SCHEDULER_NO_TASK;
    }
    kill_task = GNUNET_SCHEDULER_add_now (&do_stop_task, NULL);
    break;
  case GNUNET_FS_STATUS_PUBLISH_COMPLETED:
    FPRINTF (stdout, _("Publishing `%s' done.\n"),
             info->value.publish.filename);
    s = GNUNET_FS_uri_to_string (info->value.publish.specifics.
                                 completed.chk_uri);
    FPRINTF (stdout, _("URI is `%s'.\n"), s);
    GNUNET_free (s);
    if (info->value.publish.pctx == NULL)
    {
      if (kill_task != GNUNET_SCHEDULER_NO_TASK)
      {
        GNUNET_SCHEDULER_cancel (kill_task);
        kill_task = GNUNET_SCHEDULER_NO_TASK;
      }
      kill_task = GNUNET_SCHEDULER_add_now (&do_stop_task, NULL);
    }
    break;
  case GNUNET_FS_STATUS_PUBLISH_STOPPED:
    GNUNET_break (NULL == pc);
    return NULL;
  case GNUNET_FS_STATUS_UNINDEX_PROGRESS:
    return NULL;
  case GNUNET_FS_STATUS_UNINDEX_COMPLETED:
    FPRINTF (stderr, "%s",  _("Cleanup after abort complete.\n"));
    return NULL;
  default:
    FPRINTF (stderr, _("Unexpected status: %d\n"), info->status);
    return NULL;
  }
  return "";                    /* non-null */
}


/**
 * Print metadata entries (except binary
 * metadata and the filename).
 *
 * @param cls closure
 * @param plugin_name name of the plugin that generated the meta data
 * @param type type of the meta data
 * @param format format of data
 * @param data_mime_type mime type of data
 * @param data value of the meta data
 * @param data_size number of bytes in data
 * @return always 0
 */
static int
meta_printer (void *cls, const char *plugin_name, enum EXTRACTOR_MetaType type,
              enum EXTRACTOR_MetaFormat format, const char *data_mime_type,
              const char *data, size_t data_size)
{
  if ((format != EXTRACTOR_METAFORMAT_UTF8) &&
      (format != EXTRACTOR_METAFORMAT_C_STRING))
    return 0;
  if (type == EXTRACTOR_METATYPE_GNUNET_ORIGINAL_FILENAME)
    return 0;
  FPRINTF (stdout, "\t%s - %s\n", EXTRACTOR_metatype_to_string (type), data);
  return 0;
}


/**
 * Iterator printing keywords
 *
 * @param cls closure
 * @param keyword the keyword
 * @param is_mandatory is the keyword mandatory (in a search)
 * @return GNUNET_OK to continue to iterate, GNUNET_SYSERR to abort
 */
static int
keyword_printer (void *cls, const char *keyword, int is_mandatory)
{
  FPRINTF (stdout, "\t%s\n", keyword);
  return GNUNET_OK;
}


/**
 * Function called on all entries before the publication.  This is
 * where we perform modifications to the default based on command-line
 * options.
 *
 * @param cls closure
 * @param fi the entry in the publish-structure
 * @param length length of the file or directory
 * @param m metadata for the file or directory (can be modified)
 * @param uri pointer to the keywords that will be used for this entry (can be modified)
 * @param bo block options
 * @param do_index should we index?
 * @param client_info pointer to client context set upon creation (can be modified)
 * @return GNUNET_OK to continue, GNUNET_NO to remove
 *         this entry from the directory, GNUNET_SYSERR
 *         to abort the iteration
 */
static int
publish_inspector (void *cls, struct GNUNET_FS_FileInformation *fi,
                   uint64_t length, struct GNUNET_CONTAINER_MetaData *m,
                   struct GNUNET_FS_Uri **uri,
                   struct GNUNET_FS_BlockOptions *bo, int *do_index,
                   void **client_info)
{
  char *fn;
  char *fs;
  struct GNUNET_FS_Uri *new_uri;

  if (cls == fi)
    return GNUNET_OK;
  if (NULL != topKeywords)
  {
    if (*uri != NULL)
    {
      new_uri = GNUNET_FS_uri_ksk_merge (topKeywords, *uri);
      GNUNET_FS_uri_destroy (*uri);
      *uri = new_uri;
      GNUNET_FS_uri_destroy (topKeywords);
    }
    else
    {
      *uri = topKeywords;
    }
    topKeywords = NULL;
  }
  if (NULL != meta)
  {
    GNUNET_CONTAINER_meta_data_merge (m, meta);
    GNUNET_CONTAINER_meta_data_destroy (meta);
    meta = NULL;
  }
  if (!do_disable_creation_time)
    GNUNET_CONTAINER_meta_data_add_publication_date (m);
  if ( (disable_extractor) &&
       (NULL != *uri) )
  {
    GNUNET_FS_uri_destroy (*uri);
    *uri = NULL;
  }
  if (extract_only)
  {
    fn = GNUNET_CONTAINER_meta_data_get_by_type (m,
                                                 EXTRACTOR_METATYPE_GNUNET_ORIGINAL_FILENAME);
    fs = GNUNET_STRINGS_byte_size_fancy (length);
    FPRINTF (stdout, _("Meta data for file `%s' (%s)\n"), fn, fs);
    GNUNET_CONTAINER_meta_data_iterate (m, &meta_printer, NULL);
    FPRINTF (stdout, _("Keywords for file `%s' (%s)\n"), fn, fs);
    GNUNET_free (fn);
    GNUNET_free (fs);
    if (NULL != *uri)
      GNUNET_FS_uri_ksk_get_keywords (*uri, &keyword_printer, NULL);
    FPRINTF (stdout, "%s",  "\n");
  }
  if (GNUNET_YES == GNUNET_FS_meta_data_test_for_directory (m))
    GNUNET_FS_file_information_inspect (fi, &publish_inspector, fi);
  return GNUNET_OK;
}


/**
 * FIXME: docu
 */
static void
uri_sks_continuation (void *cls, const struct GNUNET_FS_Uri *ksk_uri,
                      const char *emsg)
{
  if (emsg != NULL)
  {
    FPRINTF (stderr, "%s\n", emsg);
    ret = 1;
  }
  GNUNET_FS_uri_destroy (uri);
  uri = NULL;
  GNUNET_FS_stop (ctx);
  ctx = NULL;
}


/**
 * FIXME: docu
 */
static void
uri_ksk_continuation (void *cls, const struct GNUNET_FS_Uri *ksk_uri,
                      const char *emsg)
{
  struct GNUNET_FS_Namespace *ns;

  if (emsg != NULL)
  {
    FPRINTF (stderr, "%s\n", emsg);
    ret = 1;
  }
  if (pseudonym != NULL)
  {
    ns = GNUNET_FS_namespace_create (ctx, pseudonym);
    if (ns == NULL)
    {
      FPRINTF (stderr, _("Failed to create namespace `%s'\n"), pseudonym);
      ret = 1;
    }
    else
    {
      GNUNET_FS_publish_sks (ctx, ns, this_id, next_id, meta, uri, &bo,
                             GNUNET_FS_PUBLISH_OPTION_NONE,
                             &uri_sks_continuation, NULL);
      GNUNET_assert (GNUNET_OK == GNUNET_FS_namespace_delete (ns, GNUNET_NO));
      return;
    }
  }
  GNUNET_FS_uri_destroy (uri);
  uri = NULL;
  GNUNET_FS_stop (ctx);
  ctx = NULL;
}


/**
 * FIXME: docu
 */
static struct GNUNET_FS_FileInformation *
get_file_information (struct GNUNET_FS_ShareTreeItem *item)
{
  struct GNUNET_FS_FileInformation *fi;
  struct GNUNET_FS_FileInformation *fic;
  struct GNUNET_FS_ShareTreeItem *child;

  if (item->is_directory == GNUNET_YES)
  {
    GNUNET_CONTAINER_meta_data_delete (item->meta,
        EXTRACTOR_METATYPE_MIMETYPE, NULL, 0);
    GNUNET_FS_meta_data_make_directory (item->meta);
    if (NULL == item->ksk_uri)
    {
      const char *mime = GNUNET_FS_DIRECTORY_MIME;
      item->ksk_uri = GNUNET_FS_uri_ksk_create_from_args (1, &mime);
    }
    else
      GNUNET_FS_uri_ksk_add_keyword (item->ksk_uri, GNUNET_FS_DIRECTORY_MIME,
        GNUNET_NO);
    fi = GNUNET_FS_file_information_create_empty_directory (
        ctx, NULL, item->ksk_uri,
        item->meta, &bo, item->filename);
    for (child = item->children_head; child; child = child->next)
    {
      fic = get_file_information (child);
      GNUNET_break (GNUNET_OK == GNUNET_FS_file_information_add (fi, fic));
    }
  }
  else
  {
    fi = GNUNET_FS_file_information_create_from_file (
        ctx, NULL, item->filename,
        item->ksk_uri, item->meta, !do_insert,
        &bo);
  }
  return fi;
}


/**
 * FIXME: docu
 */
static void
directory_trim_complete ()
{
  struct GNUNET_FS_FileInformation *fi;

  fi = get_file_information (directory_scan_result);
  GNUNET_FS_share_tree_free (directory_scan_result);
  directory_scan_result = NULL;
  if (fi == NULL)
  {
    FPRINTF (stderr, "%s", _("Could not publish\n"));
    if (namespace != NULL)
      GNUNET_FS_namespace_delete (namespace, GNUNET_NO);
    GNUNET_FS_stop (ctx);
    ret = 1;
    return;
  }
  GNUNET_FS_file_information_inspect (fi, &publish_inspector, NULL);
  if (extract_only)
  {
    if (namespace != NULL)
      GNUNET_FS_namespace_delete (namespace, GNUNET_NO);
    GNUNET_FS_file_information_destroy (fi, NULL, NULL);
    GNUNET_FS_stop (ctx);
    if (kill_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (kill_task);
      kill_task = GNUNET_SCHEDULER_NO_TASK;
    }
    return;
  }
  pc = GNUNET_FS_publish_start (ctx, fi, namespace, this_id, next_id,
                                (do_simulate) ?
                                GNUNET_FS_PUBLISH_OPTION_SIMULATE_ONLY :
                                GNUNET_FS_PUBLISH_OPTION_NONE);
  if (NULL == pc)
  {
    FPRINTF (stderr, "%s",  _("Could not start publishing.\n"));
    GNUNET_FS_stop (ctx);
    ret = 1;
    return;
  }
}


/**
 * Function called by the directory scanner as we build the tree
 * that we will need to publish later.
 *
 * @param cls closure
 * @param filename which file we are making progress on
 * @param is_directory GNUNET_YES if this is a directory,
 *                     GNUNET_NO if this is a file
 *                     GNUNET_SYSERR if it is neither (or unknown)
 * @param reason kind of progress we are making
 */
static void
directory_scan_cb (void *cls, 
		   const char *filename, 
		   int is_directory,
		   enum GNUNET_FS_DirScannerProgressUpdateReason reason)
{
  switch (reason)
  {
  case GNUNET_FS_DIRSCANNER_FILE_START:
    if (verbose > 1)
    {
      if (is_directory == GNUNET_YES)
	FPRINTF (stdout, _("Scanning directory `%s'.\n"), filename);
      else
	FPRINTF (stdout, _("Scanning file `%s'.\n"), filename);      
    }
    break;
  case GNUNET_FS_DIRSCANNER_FILE_IGNORED:
    FPRINTF (stderr, 
	     _("There was trouble processing file `%s', skipping it.\n"),
	     filename);
    break;
  case GNUNET_FS_DIRSCANNER_ALL_COUNTED:
    if (verbose)
      FPRINTF (stdout, "%s", _("Preprocessing complete.\n"));      
    break;
  case GNUNET_FS_DIRSCANNER_EXTRACT_FINISHED:
    if (verbose > 2)
      FPRINTF (stdout, _("Extracting meta data from file `%s' complete.\n"), filename);      
    break;
  case GNUNET_FS_DIRSCANNER_FINISHED:
    if (verbose > 1)
      FPRINTF (stdout, "%s", _("Meta data extraction has finished.\n"));
    directory_scan_result = GNUNET_FS_directory_scan_get_result (ds);
    ds = NULL;
    GNUNET_FS_share_tree_trim (directory_scan_result);
    directory_trim_complete ();
    break;
  case GNUNET_FS_DIRSCANNER_INTERNAL_ERROR:
    FPRINTF (stdout, "%s", _("Internal error scanning directory.\n"));
    if (kill_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (kill_task);
      kill_task = GNUNET_SCHEDULER_NO_TASK;
    }
    kill_task = GNUNET_SCHEDULER_add_now (&stop_scanner_task, NULL);
    break;
  default:
    GNUNET_assert (0);
    break;
  }
  fflush (stdout);
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
  char *ex;
  char *emsg;

  /* check arguments */
  if ((uri_string != NULL) && (extract_only))
  {
    printf (_("Cannot extract metadata from a URI!\n"));
    ret = -1;
    return;
  }
  if (((uri_string == NULL) || (extract_only)) &&
      ((args[0] == NULL) || (args[1] != NULL)))
  {
    printf (_("You must specify one and only one filename for insertion.\n"));
    ret = -1;
    return;
  }
  if ((uri_string != NULL) && (args[0] != NULL))
  {
    printf (_("You must NOT specify an URI and a filename.\n"));
    ret = -1;
    return;
  }
  if (pseudonym != NULL)
  {
    if (NULL == this_id)
    {
      FPRINTF (stderr, _("Option `%s' is required when using option `%s'.\n"),
               "-t", "-P");
      ret = -1;
      return;
    }
  }
  else
  {                             /* ordinary insertion checks */
    if (NULL != next_id)
    {
      FPRINTF (stderr, _("Option `%s' makes no sense without option `%s'.\n"),
               "-N", "-P");
      ret = -1;
      return;
    }
    if (NULL != this_id)
    {
      FPRINTF (stderr, _("Option `%s' makes no sense without option `%s'.\n"),
               "-t", "-P");
      ret = -1;
      return;
    }
  }
  cfg = c;
  ctx =
      GNUNET_FS_start (cfg, "gnunet-publish", &progress_cb, NULL,
                       GNUNET_FS_FLAGS_NONE, GNUNET_FS_OPTIONS_END);
  if (NULL == ctx)
  {
    FPRINTF (stderr, _("Could not initialize `%s' subsystem.\n"), "FS");
    ret = 1;
    return;
  }
  namespace = NULL;
  if (NULL != pseudonym)
  {
    namespace = GNUNET_FS_namespace_create (ctx, pseudonym);
    if (NULL == namespace)
    {
      FPRINTF (stderr, _("Could not create namespace `%s'\n"), pseudonym);
      GNUNET_FS_stop (ctx);
      ret = 1;
      return;
    }
  }
  if (NULL != uri_string)
  {
    emsg = NULL;
    uri = GNUNET_FS_uri_parse (uri_string, &emsg);
    if (uri == NULL)
    {
      FPRINTF (stderr, _("Failed to parse URI: %s\n"), emsg);
      GNUNET_free (emsg);
      if (namespace != NULL)
        GNUNET_FS_namespace_delete (namespace, GNUNET_NO);
      GNUNET_FS_stop (ctx);
      ret = 1;
      return;
    }
    GNUNET_FS_publish_ksk (ctx, topKeywords, meta, uri, &bo,
                           GNUNET_FS_PUBLISH_OPTION_NONE, &uri_ksk_continuation,
                           NULL);
    if (namespace != NULL)
      GNUNET_FS_namespace_delete (namespace, GNUNET_NO);
    return;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "FS", "EXTRACTORS", &ex))
    ex = NULL;
  if (0 != ACCESS (args[0], R_OK))
  {
    FPRINTF (stderr,
	     _("Failed to access `%s': %s\n"),
	     args[0],
	     STRERROR (errno));
    return;
  }
  ds = GNUNET_FS_directory_scan_start (args[0],
				       disable_extractor, 
				       ex, 
				       &directory_scan_cb, NULL);
  if (NULL == ds)
  {
    FPRINTF (stderr,
	     "%s", _("Failed to start meta directory scanner.  Is gnunet-helper-publish-fs installed?\n"));
    return;
  }
  kill_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &do_stop_task,
                                    NULL);
}


/**
 * The main function to publish content to GNUnet.
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
     gettext_noop ("set the desired LEVEL of sender-anonymity"),
     1, &GNUNET_GETOPT_set_uint, &bo.anonymity_level},
    {'d', "disable-creation-time", NULL,
     gettext_noop
     ("disable adding the creation time to the metadata of the uploaded file"),
     0, &GNUNET_GETOPT_set_one, &do_disable_creation_time},
    {'D', "disable-extractor", NULL,
     gettext_noop ("do not use libextractor to add keywords or metadata"),
     0, &GNUNET_GETOPT_set_one, &disable_extractor},
    {'e', "extract", NULL,
     gettext_noop
     ("print list of extracted keywords that would be used, but do not perform upload"),
     0, &GNUNET_GETOPT_set_one, &extract_only},
    {'k', "key", "KEYWORD",
     gettext_noop
     ("add an additional keyword for the top-level file or directory"
      " (this option can be specified multiple times)"),
     1, &GNUNET_FS_getopt_set_keywords, &topKeywords},
    {'m', "meta", "TYPE:VALUE",
     gettext_noop ("set the meta-data for the given TYPE to the given VALUE"),
     1, &GNUNET_FS_getopt_set_metadata, &meta},
    {'n', "noindex", NULL,
     gettext_noop ("do not index, perform full insertion (stores entire "
                   "file in encrypted form in GNUnet database)"),
     0, &GNUNET_GETOPT_set_one, &do_insert},
    {'N', "next", "ID",
     gettext_noop
     ("specify ID of an updated version to be published in the future"
      " (for namespace insertions only)"),
     1, &GNUNET_GETOPT_set_string, &next_id},
    {'p', "priority", "PRIORITY",
     gettext_noop ("specify the priority of the content"),
     1, &GNUNET_GETOPT_set_uint, &bo.content_priority},
    {'P', "pseudonym", "NAME",
     gettext_noop
     ("publish the files under the pseudonym NAME (place file into namespace)"),
     1, &GNUNET_GETOPT_set_string, &pseudonym},
    {'r', "replication", "LEVEL",
     gettext_noop ("set the desired replication LEVEL"),
     1, &GNUNET_GETOPT_set_uint, &bo.replication_level},
    {'s', "simulate-only", NULL,
     gettext_noop ("only simulate the process but do not do any "
                   "actual publishing (useful to compute URIs)"),
     0, &GNUNET_GETOPT_set_one, &do_simulate},
    {'t', "this", "ID",
     gettext_noop ("set the ID of this version of the publication"
                   " (for namespace insertions only)"),
     1, &GNUNET_GETOPT_set_string, &this_id},
    {'u', "uri", "URI",
     gettext_noop ("URI to be published (can be used instead of passing a "
                   "file to add keywords to the file with the respective URI)"),
     1, &GNUNET_GETOPT_set_string, &uri_string},
    {'V', "verbose", NULL,
     gettext_noop ("be verbose (print progress information)"),
     0, &GNUNET_GETOPT_set_one, &verbose},
    GNUNET_GETOPT_OPTION_END
  };
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
	      "GNUnet publish starts\n");
  bo.expiration_time =
      GNUNET_FS_year_to_time (GNUNET_FS_get_current_year () + 2);
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-publish [OPTIONS] FILENAME",
                              gettext_noop
                              ("Publish a file or directory on GNUnet"),
                              options, &run, NULL)) ? ret : 1;
}

/* end of gnunet-publish.c */
