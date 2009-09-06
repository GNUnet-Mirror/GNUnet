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
 * @file fs/gnunet-search.c
 * @brief searching for files on GNUnet
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author James Blackwell
 * @author Igor Wronsky
 *
 * TODO:
 * - add many options (timeout, namespace search, etc.)
 */
#include "platform.h"
#include "gnunet_fs_service.h"

static int ret;

static const struct GNUNET_CONFIGURATION_Handle *cfg;

static struct GNUNET_FS_Handle *ctx;

static struct GNUNET_FS_SearchContext *sc;

static unsigned int anonymity = 1;

static int verbose;

static int
item_printer (void *cls,
	      EXTRACTOR_KeywordType type, 
	      const char *data)
{
  printf ("\t%20s: %s\n",
          dgettext (LIBEXTRACTOR_GETTEXT_DOMAIN,
                    EXTRACTOR_getKeywordTypeAsString (type)),
	  data);
  return GNUNET_OK;
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
  char *uri;
  char *dotdot;
  char *filename;

  switch (info->status)
    {
    case GNUNET_FS_STATUS_SEARCH_START:
      break;
    case GNUNET_FS_STATUS_SEARCH_RESULT:
      uri = GNUNET_FS_uri_to_string (info->value.search.specifics.result.uri);
      printf ("%s:\n", uri);
      filename =
        GNUNET_CONTAINER_meta_data_get_by_type (info->value.search.specifics.result.meta,
						EXTRACTOR_FILENAME);
      if (filename != NULL)
        {
          while (NULL != (dotdot = strstr (filename, "..")))
            dotdot[0] = dotdot[1] = '_';
          printf ("gnunet-download -o \"%s\" %s\n", 
		  filename, 
		  uri);
        }
      else
        printf ("gnunet-download %s\n", uri);
      if (verbose)
	GNUNET_CONTAINER_meta_data_get_contents (info->value.search.specifics.result.meta, 
						 &item_printer,
						 NULL);
      printf ("\n");
      fflush(stdout);
      GNUNET_free_non_null (filename);
      GNUNET_free (uri);
      break;
    case GNUNET_FS_STATUS_SEARCH_UPDATE:
      break;
    case GNUNET_FS_STATUS_SEARCH_ERROR:
      fprintf (stderr,
	       _("Error searching: %s.\n"),
	       info->value.search.specifics.error.message);
      GNUNET_FS_search_stop (sc);      
      break;
    case GNUNET_FS_STATUS_SEARCH_STOPPED: 
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
 * @param cfg configuration
 */
static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *sched,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  struct GNUNET_FS_Uri *uri;
  unsigned int argc;

  argc = 0;
  while (NULL != args[argc])
    argc++;
  uri = GNUNET_FS_uri_ksk_create_from_args (argc,
					    (const char **) args);
  if (NULL == uri)
    {
      fprintf (stderr,
	       _("Could not create keyword URI from arguments.\n"));
      ret = 1;
      GNUNET_FS_uri_destroy (uri);
      return;
    }
  cfg = c;
  ctx = GNUNET_FS_start (sched,
			 cfg,
			 "gnunet-search",
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
      GNUNET_FS_stop (ctx);
      ret = 1;
      return;
    }
  sc = GNUNET_FS_search_start (ctx,
			       uri,
			       anonymity);
  GNUNET_FS_uri_destroy (uri);
  if (NULL == sc)
    {
      fprintf (stderr,
	       _("Could not start searching.\n"));
      ret = 1;
      return;
    }
}


/**
 * gnunet-search command line options
 */
static struct GNUNET_GETOPT_CommandLineOption options[] = {
  {'a', "anonymity", "LEVEL",
   gettext_noop ("set the desired LEVEL of receiver-anonymity"),
   1, &GNUNET_GETOPT_set_uint, &anonymity},
  // FIXME: options!
  GNUNET_GETOPT_OPTION_END
};


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
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc,
                              argv,
                              "gnunet-search",
                              gettext_noop
                              ("Search GNUnet."),
                              options, &run, NULL)) ? ret : 1;
}

/* end of gnunet-search.c */

