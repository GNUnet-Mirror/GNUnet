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
 * @file fs/gnunet-publish.c
 * @brief publishing files on GNUnet
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author James Blackwell
 * @author Igor Wronsky
 *
 * TODO:
 * - support for some options is still missing (uri argument)
 */
#include "platform.h"
#include "gnunet_fs_service.h"

#define DEFAULT_EXPIRATION GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_YEARS, 2)

static int ret;

static int verbose;

static const struct GNUNET_CONFIGURATION_Handle *cfg;

static struct GNUNET_FS_Handle *ctx;

static struct GNUNET_FS_PublishContext *pc;

static struct GNUNET_CONTAINER_MetaData *meta;

static struct GNUNET_FS_Uri *topKeywords;

static unsigned int anonymity = 1;

static unsigned int priority = 365;

static char *uri_string;

static char *next_id;

static char *this_id;

static char *pseudonym;

static int do_insert;

static int disable_extractor;

static int do_simulate;

static int extract_only;

static int do_disable_creation_time;


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
    case GNUNET_FS_STATUS_PUBLISH_START:
      break;
    case GNUNET_FS_STATUS_PUBLISH_PROGRESS:
      if (verbose)
	fprintf (stdout,
		 _("Publishing `%s' at %llu/%llu (%s remaining)\n"),
		 info->value.publish.filename,
		 (unsigned long long) info->value.publish.completed,
		 (unsigned long long) info->value.publish.size,
		 GNUNET_STRINGS_relative_time_to_string(info->value.publish.eta));
      break;
    case GNUNET_FS_STATUS_PUBLISH_ERROR:
      fprintf (stderr,
	       _("Error publishing: %s.\n"),
	       info->value.publish.specifics.error.message);
      GNUNET_FS_publish_stop (pc);      
      break;
    case GNUNET_FS_STATUS_PUBLISH_COMPLETED:
      fprintf (stdout,
	       _("Publishing `%s' done.\n"),
	       info->value.publish.filename);
      if (info->value.publish.pctx == NULL)
	GNUNET_FS_publish_stop (pc);
      break;
    case GNUNET_FS_STATUS_PUBLISH_STOPPED: 
      if (info->value.publish.sc == pc)
	GNUNET_FS_stop (ctx);
      return NULL;      
    default:
      fprintf (stderr,
	       _("Unexpected status: %d\n"),
	       info->status);
      return NULL;
    }
  return ""; /* non-null */
}


/**
 * Print metadata entries (except binary
 * metadata and the filename).
 *
 * @param cls closure
 * @param type type of the meta data
 * @param data value of the meta data
 * @return GNUNET_OK to continue to iterate, GNUNET_SYSERR to abort
 */
static int
meta_printer (void *cls,
	      EXTRACTOR_KeywordType type,
	      const char *data)
{
  if ( (type == EXTRACTOR_FILENAME) ||
       (EXTRACTOR_isBinaryType (type)) )
    return GNUNET_OK;
  fprintf (stdout, 
	   "%s - %s",
	   EXTRACTOR_getKeywordTypeAsString (type),
	   data);
  return GNUNET_OK;
}


/**
 * Merge metadata entries (except binary
 * metadata).
 *
 * @param cls closure, target metadata structure
 * @param type type of the meta data
 * @param data value of the meta data
 * @return GNUNET_OK to continue to iterate, GNUNET_SYSERR to abort
 */
static int
meta_merger (void *cls,
	     EXTRACTOR_KeywordType type,
	     const char *data)
{
  struct GNUNET_CONTAINER_MetaData *m = cls;
  GNUNET_CONTAINER_meta_data_insert (m,
				     type, 
				     data);
  return GNUNET_OK;
}


/**
 * Function called on all entries before the
 * publication.  This is where we perform
 * modifications to the default based on
 * command-line options.
 *
 * @param cls closure
 * @param fi the entry in the publish-structure
 * @param length length of the file or directory
 * @param m metadata for the file or directory (can be modified)
 * @param uri pointer to the keywords that will be used for this entry (can be modified)
 * @param anonymity pointer to selected anonymity level (can be modified)
 * @param priority pointer to selected priority (can be modified)
 * @param expirationTime pointer to selected expiration time (can be modified)
 * @param client_info pointer to client context set upon creation (can be modified)
 * @return GNUNET_OK to continue, GNUNET_NO to remove
 *         this entry from the directory, GNUNET_SYSERR
 *         to abort the iteration
 */
static int
publish_inspector (void *cls,
		   struct GNUNET_FS_FileInformation *fi,
		   uint64_t length,
		   struct GNUNET_CONTAINER_MetaData *m,
		   struct GNUNET_FS_Uri **uri,
		   unsigned int *anonymity,
		   unsigned int *priority,
		   struct GNUNET_TIME_Absolute *expirationTime,
		   void **client_info)
{
  char *fn;
  char *fs;
  struct GNUNET_FS_Uri *new_uri;

  if (! do_disable_creation_time)
    GNUNET_CONTAINER_meta_data_add_publication_date (meta);
  if (NULL != topKeywords)
    {
      new_uri = GNUNET_FS_uri_ksk_merge (topKeywords,
					 *uri);
      GNUNET_FS_uri_destroy (*uri);
      *uri = new_uri;
      GNUNET_FS_uri_destroy (topKeywords);
      topKeywords = NULL;
    }
  if (NULL != meta)
    {
      GNUNET_CONTAINER_meta_data_get_contents (meta,
					       &meta_merger,
					       m);
      GNUNET_CONTAINER_meta_data_destroy (meta);
      meta = NULL;
    }
  if (extract_only)
    {
      fn = GNUNET_CONTAINER_meta_data_get_by_type (meta,
						   EXTRACTOR_FILENAME);
      fs = GNUNET_STRINGS_byte_size_fancy (length);
      fprintf (stdout,
	       _("Keywords for file `%s' (%s)\n"),
	       fn,
	       fs);
      GNUNET_free (fn);
      GNUNET_free (fs);
      GNUNET_CONTAINER_meta_data_get_contents (meta,
					       &meta_printer,
					       NULL);
      fprintf (stdout, "\n");
    }
  if (GNUNET_FS_meta_data_test_for_directory (meta))
    GNUNET_FS_file_information_inspect (fi,
					&publish_inspector,
					NULL);
  return GNUNET_OK;
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
  struct GNUNET_FS_FileInformation *fi;
  struct GNUNET_FS_Namespace *namespace;
  EXTRACTOR_ExtractorList *l;
  char *ex;
  char *emsg;
  
  /* check arguments */
  if ( ( (uri_string == NULL) || (extract_only) ) 
       && ( (args[0] == NULL) || (args[1] != NULL) ) )
    {
      printf (_
              ("You must specify one and only one filename for insertion.\n"));
      ret = -1;
      return;
    }
  if ((uri_string != NULL) && (args[0] != NULL))
    {
      printf (_("You must NOT specify an URI and a filename.\n"));
      ret = -1;
      return;
    }
  if ((uri_string != NULL) && (extract_only))
    {
      printf (_("Cannot extract metadata from a URI!\n"));
      ret = -1;
      return;
    }
  if (pseudonym != NULL)
    {
      if (NULL == this_id)
        {
          fprintf (stderr,
                   _("Option `%s' is required when using option `%s'.\n"),
                   "-t", "-P");
          ret = -1;
          return;
        }
    }
  else
    {                           /* ordinary insertion checks */
      if (NULL != next_id)
        {
          fprintf (stderr,
                   _("Option `%s' makes no sense without option `%s'.\n"),
                   "-N", "-P");
          ret = -1;
          return;
        }
      if (NULL != this_id)
        {
          fprintf (stderr,
                   _("Option `%s' makes no sense without option `%s'.\n"),
                   "-t", "-P");
          ret = -1;
	  return;
        }
    }
  if (args[0] == NULL)
    {
      fprintf (stderr,
	       _("Need the name of a file to publish!\n"));
      ret = 1;
      return;
    }
  cfg = c;
  ctx = GNUNET_FS_start (sched,
			 cfg,
			 "gnunet-publish",
			 &progress_cb,
			 NULL,
			 GNUNET_FS_FLAGS_NONE,
			 GNUNET_FS_OPTIONS_END);
  if (NULL == ctx)
    {
      fprintf (stderr,
	       _("Could not initialize `%s' subsystem.\n"),
	       "FS");
      ret = 1;
      return;
    }
  namespace = NULL;
  if (NULL != pseudonym)
    {
      namespace = GNUNET_FS_namespace_create (ctx,
					      pseudonym);
      if (NULL == namespace)
	{
	  fprintf (stderr,
		   _("Could not create namespace `%s'\n"),
		   pseudonym);
	  GNUNET_FS_stop (ctx);
	  ret = 1;
	  return;
	}
    }
  if (NULL != uri_string)
    {
      // FIXME -- implement!
      return;
    }

  l = NULL;
  if (! disable_extractor)
    {
      l = EXTRACTOR_loadDefaultLibraries ();
      if (GNUNET_OK ==
	  GNUNET_CONFIGURATION_get_value_string (cfg, "FS", "EXTRACTORS",
						 &ex))
	{
	  if (strlen (ex) > 0)
	    l = EXTRACTOR_loadConfigLibraries (l, ex);
	  GNUNET_free (ex);
	}
    }
  fi = GNUNET_FS_file_information_create_from_directory (NULL,
							 args[0],
							 &GNUNET_FS_directory_scanner_default,
							 l,
							 !do_insert,
							 anonymity,
							 priority,
							 GNUNET_TIME_relative_to_absolute (DEFAULT_EXPIRATION),
							 &emsg);
  EXTRACTOR_removeAll (l);  
  if (fi == NULL)
    {
      fprintf (stderr,
	       _("Could not publish `%s': %s\n"),
	       args[0],
	       emsg);
      GNUNET_free (emsg);
      if (namespace != NULL)
	GNUNET_FS_namespace_delete (namespace, GNUNET_NO);
      GNUNET_FS_stop (ctx);
      ret = 1;
      return;
    }
  GNUNET_FS_file_information_inspect (fi,
				      &publish_inspector,
				      NULL);
  if (extract_only)
    {
      if (namespace != NULL)
	GNUNET_FS_namespace_delete (namespace, GNUNET_NO);
      GNUNET_FS_file_information_destroy (fi, NULL, NULL);
      GNUNET_FS_stop (ctx);
      return;
    }
  pc = GNUNET_FS_publish_start (ctx,
				fi,
				namespace,
				this_id,
				next_id,
				(do_simulate) 
				? GNUNET_FS_PUBLISH_OPTION_SIMULATE_ONLY
				: GNUNET_FS_PUBLISH_OPTION_NONE);
  if (NULL == pc)
    {
      fprintf (stderr,
	       _("Could not start publishing.\n"));
      GNUNET_FS_stop (ctx);
      ret = 1;
      return;
    }
}


/**
 * gnunet-publish command line options
 */
static struct GNUNET_GETOPT_CommandLineOption options[] = {
  {'a', "anonymity", "LEVEL",
   gettext_noop ("set the desired LEVEL of sender-anonymity"),
   1, &GNUNET_GETOPT_set_uint, &anonymity},
  {'d', "disable-creation-time", NULL,
   gettext_noop
   ("disable adding the creation time to the metadata of the uploaded file"),
   0, &GNUNET_GETOPT_set_one, &do_disable_creation_time},
  {'D', "disable-extractor", NULL,
   gettext_noop
   ("do not use libextractor to add keywords or metadata"),
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
  // *: option not yet used... (can handle in a pass over FI)
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
   1, &GNUNET_GETOPT_set_uint, &priority},
  {'P', "pseudonym", "NAME",
   gettext_noop
   ("publish the files under the pseudonym NAME (place file into namespace)"),
   1, &GNUNET_GETOPT_set_string, &pseudonym},
  // *: option not yet used... (need FS API support!)
  {'s', "simulate-only", NULL,
   gettext_noop ("only simulate the process but do not do any "
                 "actual publishing (useful to compute URIs)"),
   0, &GNUNET_GETOPT_set_one, &do_simulate},
  {'t', "this", "ID",
   gettext_noop ("set the ID of this version of the publication"
                 " (for namespace insertions only)"),
   1, &GNUNET_GETOPT_set_string, &this_id},
  // *: option not yet used... (need FS API support!)
  {'u', "uri", "URI",
   gettext_noop ("URI to be published (can be used instead of passing a "
                 "file to add keywords to the file with the respective URI)"),
   1, &GNUNET_GETOPT_set_string, &uri_string}, 
  {'V', "verbose", NULL,
   gettext_noop ("be verbose (print progress information)"),
   0, &GNUNET_GETOPT_set_one, &verbose},
  GNUNET_GETOPT_OPTION_END
};


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
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc,
                              argv,
                              "gnunet-publish",
                              gettext_noop
                              ("Publish files on GNUnet."),
                              options, &run, NULL)) ? ret : 1;
}

/* end of gnunet-publish.c */

////////////////////////////////////////////////////////////////

#if 0
/**
 * Print progess message.
 */
static void *
printstatus (void *ctx, const GNUNET_FSUI_Event * event)
{
  unsigned long long delta;
  char *fstring;

  switch (event->type)
    {
    case GNUNET_FSUI_upload_progress:
      if (*verboselevel)
        {
          char *ret;
          GNUNET_CronTime now;

          now = GNUNET_get_time ();
          delta = event->data.UploadProgress.eta - now;
          if (event->data.UploadProgress.eta < now)
            delta = 0;
          ret = GNUNET_get_time_interval_as_fancy_string (delta);
          PRINTF (_("%16llu of %16llu bytes inserted "
                    "(estimating %6s to completion) - %s\n"),
                  event->data.UploadProgress.completed,
                  event->data.UploadProgress.total,
                  ret, event->data.UploadProgress.filename);
          GNUNET_free (ret);
        }
      break;
    case GNUNET_FSUI_upload_completed:
      if (*verboselevel)
        {
          delta = GNUNET_get_time () - start_time;
          PRINTF (_("Upload of `%s' complete, "
                    "%llu bytes took %llu seconds (%8.3f KiB/s).\n"),
                  event->data.UploadCompleted.filename,
                  event->data.UploadCompleted.total,
                  delta / GNUNET_CRON_SECONDS,
                  (delta == 0)
                  ? (double) (-1.0)
                  : (double) (event->data.UploadCompleted.total
                              / 1024.0 * GNUNET_CRON_SECONDS / delta));
        }
      fstring = GNUNET_ECRS_uri_to_string (event->data.UploadCompleted.uri);
      printf (_("File `%s' has URI: %s\n"),
              event->data.UploadCompleted.filename, fstring);
      GNUNET_free (fstring);
      if (ul == event->data.UploadCompleted.uc.pos)
        {
          postProcess (event->data.UploadCompleted.uri);
          errorCode = 0;
          GNUNET_shutdown_initiate ();
        }
      break;
    case GNUNET_FSUI_upload_aborted:
      printf (_("\nUpload aborted.\n"));
      errorCode = 2;
      GNUNET_shutdown_initiate ();
      break;
    case GNUNET_FSUI_upload_error:
      printf (_("\nError uploading file: %s"),
              event->data.UploadError.message);
      errorCode = 3;
      GNUNET_shutdown_initiate ();
      break;
    case GNUNET_FSUI_upload_started:
    case GNUNET_FSUI_upload_stopped:
      break;
    default:
      printf (_("\nUnexpected event: %d\n"), event->type);
      GNUNET_GE_BREAK (ectx, 0);
      break;
    }
  return NULL;
}
#endif

/* end of gnunet-publish.c */
