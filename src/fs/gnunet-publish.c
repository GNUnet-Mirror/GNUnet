/*
     This file is part of GNUnet.
     Copyright (C) 2001-2013 Christian Grothoff (and other contributing authors)

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
 * @file fs/gnunet-publish.c
 * @brief publishing files on GNUnet
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author James Blackwell
 * @author Igor Wronsky
 */
#include "platform.h"
#include "gnunet_fs_service.h"
#include "gnunet_identity_service.h"

/**
 * Global return value from 'main'.
 */
static int ret = 1;

/**
 * Command line option 'verbose' set
 */
static int verbose;

/**
 * Handle to our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle for interaction with file-sharing service.
 */
static struct GNUNET_FS_Handle *ctx;

/**
 * Handle to FS-publishing operation.
 */
static struct GNUNET_FS_PublishContext *pc;

/**
 * Meta-data provided via command-line option.
 */
static struct GNUNET_CONTAINER_MetaData *meta;

/**
 * Keywords provided via command-line option.
 */
static struct GNUNET_FS_Uri *topKeywords;

/**
 * Options we set for published blocks.
 */
static struct GNUNET_FS_BlockOptions bo = { {0LL}, 1, 365, 1 };

/**
 * Value of URI provided on command-line (when not publishing
 * a file but just creating UBlocks to refer to an existing URI).
 */
static char *uri_string;

/**
 * Value of URI provided on command-line (when not publishing
 * a file but just creating UBlocks to refer to an existing URI);
 * parsed version of 'uri_string'.
 */
static struct GNUNET_FS_Uri *uri;

/**
 * Command-line option for namespace publishing: identifier for updates
 * to this publication.
 */
static char *next_id;

/**
 * Command-line option for namespace publishing: identifier for this
 * publication.
 */
static char *this_id;

/**
 * Command-line option identifying the pseudonym to use for the publication.
 */
static char *pseudonym;

/**
 * Command-line option for 'inserting'
 */
static int do_insert;

/**
 * Command-line option to disable meta data extraction.
 */
static int disable_extractor;

/**
 * Command-line option to merely simulate publishing operation.
 */
static int do_simulate;

/**
 * Command-line option to only perform meta data extraction, but not publish.
 */
static int extract_only;

/**
 * Command-line option to disable adding creation time.
 */
static int do_disable_creation_time;

/**
 * Task run on CTRL-C to kill everything nicely.
 */
static struct GNUNET_SCHEDULER_Task * kill_task;

/**
 * Handle to the directory scanner (for recursive insertions).
 */
static struct GNUNET_FS_DirScanner *ds;

/**
 * Which namespace do we publish to? NULL if we do not publish to
 * a namespace.
 */
static struct GNUNET_IDENTITY_Ego *namespace;

/**
 * Handle to identity service.
 */
static struct GNUNET_IDENTITY_Handle *identity;


/**
 * We are finished with the publishing operation, clean up all
 * FS state.
 *
 * @param cls NULL
 * @param tc scheduler context
 */
static void
do_stop_task (void *cls,
              const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_PublishContext *p;

  kill_task = NULL;
  if (NULL != identity)
  {
    GNUNET_IDENTITY_disconnect (identity);
    identity = NULL;
  }
  if (NULL != pc)
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
  kill_task = NULL;
  if (NULL != ds)
  {
    GNUNET_FS_directory_scan_abort (ds);
    ds = NULL;
  }
  if (NULL != identity)
  {
    GNUNET_IDENTITY_disconnect (identity);
    identity = NULL;
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
progress_cb (void *cls,
             const struct GNUNET_FS_ProgressInfo *info)
{
  const char *s;
  char *suri;

  switch (info->status)
  {
  case GNUNET_FS_STATUS_PUBLISH_START:
    break;
  case GNUNET_FS_STATUS_PUBLISH_PROGRESS:
    if (verbose)
    {
      s = GNUNET_STRINGS_relative_time_to_string (info->value.publish.eta,
						  GNUNET_YES);
      FPRINTF (stdout,
               _("Publishing `%s' at %llu/%llu (%s remaining)\n"),
               info->value.publish.filename,
               (unsigned long long) info->value.publish.completed,
               (unsigned long long) info->value.publish.size, s);
    }
    break;
  case GNUNET_FS_STATUS_PUBLISH_PROGRESS_DIRECTORY:
    if (verbose)
    {
      s = GNUNET_STRINGS_relative_time_to_string (info->value.publish.specifics.progress_directory.eta,
						  GNUNET_YES);
      FPRINTF (stdout,
               _("Publishing `%s' at %llu/%llu (%s remaining)\n"),
               info->value.publish.filename,
               (unsigned long long) info->value.publish.specifics.progress_directory.completed,
               (unsigned long long) info->value.publish.specifics.progress_directory.total, s);
    }
    break;
  case GNUNET_FS_STATUS_PUBLISH_ERROR:
    FPRINTF (stderr, _("Error publishing: %s.\n"),
             info->value.publish.specifics.error.message);
    if (kill_task != NULL)
    {
      GNUNET_SCHEDULER_cancel (kill_task);
      kill_task = NULL;
    }
    kill_task = GNUNET_SCHEDULER_add_now (&do_stop_task, NULL);
    break;
  case GNUNET_FS_STATUS_PUBLISH_COMPLETED:
    FPRINTF (stdout,
             _("Publishing `%s' done.\n"),
             info->value.publish.filename);
    suri = GNUNET_FS_uri_to_string (info->value.publish.specifics.
                                    completed.chk_uri);
    FPRINTF (stdout,
             _("URI is `%s'.\n"),
             suri);
    GNUNET_free (suri);
    if (NULL != info->value.publish.specifics.completed.sks_uri)
    {
      suri = GNUNET_FS_uri_to_string (info->value.publish.specifics.
                                      completed.sks_uri);
      FPRINTF (stdout,
               _("Namespace URI is `%s'.\n"),
               suri);
      GNUNET_free (suri);
    }
    if (NULL == info->value.publish.pctx)
    {
      if (NULL != kill_task)
        GNUNET_SCHEDULER_cancel (kill_task);
      kill_task = GNUNET_SCHEDULER_add_now (&do_stop_task, NULL);
    }
    ret = 0;
    break;
  case GNUNET_FS_STATUS_PUBLISH_STOPPED:
    GNUNET_break (NULL == pc);
    return NULL;
  case GNUNET_FS_STATUS_UNINDEX_START:
    FPRINTF (stderr,
             "%s",
             _("Starting cleanup after abort\n"));
    return NULL;
  case GNUNET_FS_STATUS_UNINDEX_PROGRESS:
    return NULL;
  case GNUNET_FS_STATUS_UNINDEX_COMPLETED:
    FPRINTF (stderr,
             "%s",
             _("Cleanup after abort completed.\n"));
    GNUNET_FS_unindex_stop (info->value.unindex.uc);
    return NULL;
  case GNUNET_FS_STATUS_UNINDEX_ERROR:
    FPRINTF (stderr,
             "%s",
             _("Cleanup after abort failed.\n"));
    GNUNET_FS_unindex_stop (info->value.unindex.uc);
    return NULL;
  case GNUNET_FS_STATUS_UNINDEX_STOPPED:
    return NULL;
  default:
    FPRINTF (stderr,
             _("Unexpected status: %d\n"),
             info->status);
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
 * @param data_mime_type mime type of @a data
 * @param data value of the meta data
 * @param data_size number of bytes in @a data
 * @return always 0
 */
static int
meta_printer (void *cls,
              const char *plugin_name,
              enum EXTRACTOR_MetaType type,
              enum EXTRACTOR_MetaFormat format,
              const char *data_mime_type,
              const char *data, size_t data_size)
{
  if ((EXTRACTOR_METAFORMAT_UTF8 != format) &&
      (EXTRACTOR_METAFORMAT_C_STRING != format))
    return 0;
  if (EXTRACTOR_METATYPE_GNUNET_ORIGINAL_FILENAME == type)
    return 0;
#if HAVE_LIBEXTRACTOR
  FPRINTF (stdout, "\t%s - %s\n", EXTRACTOR_metatype_to_string (type), data);
#else
  FPRINTF (stdout, "\t%d - %s\n", type, data);
#endif
  return 0;
}


/**
 * Iterator printing keywords
 *
 * @param cls closure
 * @param keyword the keyword
 * @param is_mandatory is the keyword mandatory (in a search)
 * @return #GNUNET_OK to continue to iterate, #GNUNET_SYSERR to abort
 */
static int
keyword_printer (void *cls,
                 const char *keyword,
                 int is_mandatory)
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
 * @return #GNUNET_OK to continue, #GNUNET_NO to remove
 *         this entry from the directory, #GNUNET_SYSERR
 *         to abort the iteration
 */
static int
publish_inspector (void *cls,
                   struct GNUNET_FS_FileInformation *fi,
                   uint64_t length,
                   struct GNUNET_CONTAINER_MetaData *m,
                   struct GNUNET_FS_Uri **uri,
                   struct GNUNET_FS_BlockOptions *bo,
                   int *do_index,
                   void **client_info)
{
  char *fn;
  char *fs;
  struct GNUNET_FS_Uri *new_uri;

  if (cls == fi)
    return GNUNET_OK;
  if ( (disable_extractor) &&
       (NULL != *uri) )
  {
    GNUNET_FS_uri_destroy (*uri);
    *uri = NULL;
  }
  if (NULL != topKeywords)
  {
    if (NULL != *uri)
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
 * Function called upon completion of the publishing
 * of the UBLOCK for the SKS URI.  As this is the last
 * step, stop our interaction with FS (clean up).
 *
 * @param cls NULL (closure)
 * @param sks_uri URI for the block that was published
 * @param emsg error message, NULL on success
 */
static void
uri_sks_continuation (void *cls,
                      const struct GNUNET_FS_Uri *sks_uri,
                      const char *emsg)
{
  if (NULL != emsg)
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
 * Function called upon completion of the publishing
 * of the UBLOCK for the KSK URI.  Continue with
 * publishing the SKS URI (if applicable) or clean up.
 *
 * @param cls NULL (closure)
 * @param ksk_uri URI for the block that was published
 * @param emsg error message, NULL on success
 */
static void
uri_ksk_continuation (void *cls,
                      const struct GNUNET_FS_Uri *ksk_uri,
                      const char *emsg)
{
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv;

  if (NULL != emsg)
  {
    FPRINTF (stderr, "%s\n", emsg);
    ret = 1;
  }
  if (NULL != namespace)
  {
    priv = GNUNET_IDENTITY_ego_get_private_key (namespace);
    GNUNET_FS_publish_sks (ctx, priv, this_id, next_id, meta, uri, &bo,
			   GNUNET_FS_PUBLISH_OPTION_NONE,
			   &uri_sks_continuation, NULL);
    return;
  }
  GNUNET_FS_uri_destroy (uri);
  uri = NULL;
  GNUNET_FS_stop (ctx);
  ctx = NULL;
}


/**
 * Iterate over the results from the directory scan and extract
 * the desired information for the publishing operation.
 *
 * @param item root with the data from the directroy scan
 * @return handle with the information for the publishing operation
 */
static struct GNUNET_FS_FileInformation *
get_file_information (struct GNUNET_FS_ShareTreeItem *item)
{
  struct GNUNET_FS_FileInformation *fi;
  struct GNUNET_FS_FileInformation *fic;
  struct GNUNET_FS_ShareTreeItem *child;

  if (GNUNET_YES == item->is_directory)
  {
    if (NULL == item->meta)
      item->meta = GNUNET_CONTAINER_meta_data_create ();
    GNUNET_CONTAINER_meta_data_delete (item->meta,
				       EXTRACTOR_METATYPE_MIMETYPE,
				       NULL, 0);
    GNUNET_FS_meta_data_make_directory (item->meta);
    if (NULL == item->ksk_uri)
    {
      const char *mime = GNUNET_FS_DIRECTORY_MIME;
      item->ksk_uri = GNUNET_FS_uri_ksk_create_from_args (1, &mime);
    }
    else
      GNUNET_FS_uri_ksk_add_keyword (item->ksk_uri, GNUNET_FS_DIRECTORY_MIME,
				     GNUNET_NO);
    fi = GNUNET_FS_file_information_create_empty_directory (ctx, NULL,
							    item->ksk_uri,
							    item->meta,
							    &bo, item->filename);
    for (child = item->children_head; child; child = child->next)
    {
      fic = get_file_information (child);
      GNUNET_break (GNUNET_OK == GNUNET_FS_file_information_add (fi, fic));
    }
  }
  else
  {
    fi = GNUNET_FS_file_information_create_from_file (ctx, NULL,
						      item->filename,
						      item->ksk_uri, item->meta,
						      !do_insert,
						      &bo);
  }
  return fi;
}


/**
 * We've finished scanning the directory and optimized the meta data.
 * Begin the publication process.
 *
 * @param directory_scan_result result from the directory scan, freed in this function
 */
static void
directory_trim_complete (struct GNUNET_FS_ShareTreeItem *directory_scan_result)
{
  struct GNUNET_FS_FileInformation *fi;
  const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv;

  fi = get_file_information (directory_scan_result);
  GNUNET_FS_share_tree_free (directory_scan_result);
  if (NULL == fi)
  {
    FPRINTF (stderr,
             "%s",
             _("Could not publish\n"));
    GNUNET_SCHEDULER_shutdown ();
    ret = 1;
    return;
  }
  GNUNET_FS_file_information_inspect (fi, &publish_inspector, NULL);
  if (extract_only)
  {
    GNUNET_FS_file_information_destroy (fi, NULL, NULL);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (NULL == namespace)
    priv = NULL;
  else
    priv = GNUNET_IDENTITY_ego_get_private_key (namespace);
  pc = GNUNET_FS_publish_start (ctx, fi,
				priv, this_id, next_id,
                                (do_simulate) ?
                                GNUNET_FS_PUBLISH_OPTION_SIMULATE_ONLY :
                                GNUNET_FS_PUBLISH_OPTION_NONE);
  if (NULL == pc)
  {
    FPRINTF (stderr,
             "%s",
             _("Could not start publishing.\n"));
    GNUNET_SCHEDULER_shutdown ();
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
 * @param is_directory #GNUNET_YES if this is a directory,
 *                     #GNUNET_NO if this is a file
 *                     #GNUNET_SYSERR if it is neither (or unknown)
 * @param reason kind of progress we are making
 */
static void
directory_scan_cb (void *cls,
		   const char *filename,
		   int is_directory,
		   enum GNUNET_FS_DirScannerProgressUpdateReason reason)
{
  struct GNUNET_FS_ShareTreeItem *directory_scan_result;

  switch (reason)
  {
  case GNUNET_FS_DIRSCANNER_FILE_START:
    if (verbose > 1)
    {
      if (is_directory == GNUNET_YES)
	FPRINTF (stdout,
                 _("Scanning directory `%s'.\n"),
                 filename);
      else
	FPRINTF (stdout,
                 _("Scanning file `%s'.\n"),
                 filename);
    }
    break;
  case GNUNET_FS_DIRSCANNER_FILE_IGNORED:
    FPRINTF (stderr,
	     _("There was trouble processing file `%s', skipping it.\n"),
	     filename);
    break;
  case GNUNET_FS_DIRSCANNER_ALL_COUNTED:
    if (verbose)
      FPRINTF (stdout,
               "%s",
               _("Preprocessing complete.\n"));
    break;
  case GNUNET_FS_DIRSCANNER_EXTRACT_FINISHED:
    if (verbose > 2)
      FPRINTF (stdout,
               _("Extracting meta data from file `%s' complete.\n"),
               filename);
    break;
  case GNUNET_FS_DIRSCANNER_FINISHED:
    if (verbose > 1)
      FPRINTF (stdout,
               "%s",
               _("Meta data extraction has finished.\n"));
    directory_scan_result = GNUNET_FS_directory_scan_get_result (ds);
    ds = NULL;
    GNUNET_FS_share_tree_trim (directory_scan_result);
    directory_trim_complete (directory_scan_result);
    break;
  case GNUNET_FS_DIRSCANNER_INTERNAL_ERROR:
    FPRINTF (stdout,
             "%s",
             _("Internal error scanning directory.\n"));
    if (kill_task != NULL)
    {
      GNUNET_SCHEDULER_cancel (kill_task);
      kill_task = NULL;
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
 * Continuation proceeding with initialization after identity subsystem
 * has been initialized.
 *
 * @param args0 filename to publish
 */
static void
identity_continuation (const char *args0)
{
  char *ex;
  char *emsg;

  if ( (NULL != pseudonym) &&
       (NULL == namespace) )
  {
    FPRINTF (stderr,
             _("Selected pseudonym `%s' unknown\n"),
             pseudonym);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (NULL != uri_string)
  {
    emsg = NULL;
    if (NULL == (uri = GNUNET_FS_uri_parse (uri_string, &emsg)))
    {
      FPRINTF (stderr,
               _("Failed to parse URI: %s\n"),
               emsg);
      GNUNET_free (emsg);
      GNUNET_SCHEDULER_shutdown ();
      ret = 1;
      return;
    }
    GNUNET_FS_publish_ksk (ctx, topKeywords,
                           meta, uri,
                           &bo,
                           GNUNET_FS_PUBLISH_OPTION_NONE,
                           &uri_ksk_continuation,
                           NULL);
    return;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "FS", "EXTRACTORS", &ex))
    ex = NULL;
  if (0 != ACCESS (args0, R_OK))
  {
    FPRINTF (stderr,
	     _("Failed to access `%s': %s\n"),
	     args0,
	     STRERROR (errno));
    GNUNET_free_non_null (ex);
    return;
  }
  ds = GNUNET_FS_directory_scan_start (args0,
				       disable_extractor,
				       ex,
				       &directory_scan_cb, NULL);
  if (NULL == ds)
  {
    FPRINTF (stderr,
	     "%s",
             _("Failed to start meta directory scanner.  Is gnunet-helper-publish-fs installed?\n"));
    GNUNET_free_non_null (ex);
    return;
  }
  GNUNET_free_non_null (ex);
}


/**
 * Function called by identity service with known pseudonyms.
 *
 * @param cls closure with 'const char *' of filename to publish
 * @param ego ego handle
 * @param ctx context for application to store data for this ego
 *                 (during the lifetime of this process, initially NULL)
 * @param name name assigned by the user for this ego,
 *                   NULL if the user just deleted the ego and it
 *                   must thus no longer be used
 */
static void
identity_cb (void *cls,
	     struct GNUNET_IDENTITY_Ego *ego,
	     void **ctx,
	     const char *name)
{
  const char *args0 = cls;

  if (NULL == ego)
  {
    identity_continuation (args0);
    return;
  }
  if (NULL == name)
    return;
  if (0 == strcmp (name, pseudonym))
    namespace = ego;
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
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  /* check arguments */
  if ((NULL != uri_string) && (extract_only))
  {
    printf (_("Cannot extract metadata from a URI!\n"));
    ret = -1;
    return;
  }
  if (((NULL == uri_string) || (extract_only)) &&
      ((NULL == args[0]) || (NULL != args[1])))
  {
    printf (_("You must specify one and only one filename for insertion.\n"));
    ret = -1;
    return;
  }
  if ((NULL != uri_string) && (NULL != args[0]))
  {
    printf (_("You must NOT specify an URI and a filename.\n"));
    ret = -1;
    return;
  }
  if (NULL != pseudonym)
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
      FPRINTF (stderr,
               _("Option `%s' makes no sense without option `%s'.\n"),
               "-N", "-P");
      ret = -1;
      return;
    }
    if (NULL != this_id)
    {
      FPRINTF (stderr,
               _("Option `%s' makes no sense without option `%s'.\n"),
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
    FPRINTF (stderr,
             _("Could not initialize `%s' subsystem.\n"),
             "FS");
    ret = 1;
    return;
  }
  kill_task =
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                  &do_stop_task,
                                  NULL);
  if (NULL != pseudonym)
    identity = GNUNET_IDENTITY_connect (cfg,
					&identity_cb,
                                        args[0]);
  else
    identity_continuation (args[0]);
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
  bo.expiration_time =
      GNUNET_TIME_year_to_time (GNUNET_TIME_get_current_year () + 2);

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;
  ret = (GNUNET_OK ==
	 GNUNET_PROGRAM_run (argc, argv, "gnunet-publish [OPTIONS] FILENAME",
			     gettext_noop
			     ("Publish a file or directory on GNUnet"),
			     options, &run, NULL)) ? ret : 1;
  GNUNET_free ((void*) argv);
  return ret;
}

/* end of gnunet-publish.c */
