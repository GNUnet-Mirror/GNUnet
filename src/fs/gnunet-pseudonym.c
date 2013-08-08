/*
     This file is part of GNUnet.
     (C) 2001-2013 Christian Grothoff (and other contributing authors)

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
 * @file fs/gnunet-pseudonym.c
 * @brief manage GNUnet namespaces / pseudonyms
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_fs_service.h"
#include "gnunet_identity_service.h"


/**
 * -A option
 */
static char *advertise_ns;

/**
 * -k option
 */
static struct GNUNET_FS_Uri *ksk_uri;

/**
 * -m option.
 */
static struct GNUNET_CONTAINER_MetaData *adv_metadata;

/**
 * Our block options (-p, -r, -a).
 */
static struct GNUNET_FS_BlockOptions bo = { {0LL}, 1, 365, 1 };

/**
 * -q option given.
 */
static int no_remote_printing;

/**
 * -r option.
 */
static char *root_identifier;

/**
 * -s option.
 */
static char *rating_change;

/**
 * Handle to fs service.
 */
static struct GNUNET_FS_Handle *h;

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to identity service.
 */
static struct GNUNET_IDENTITY_Handle *identity;

/**
 * Target namespace.
 */
static struct GNUNET_IDENTITY_Ego *namespace;

/**
 * URI to advertise.
 */
static struct GNUNET_FS_Uri *sks_uri;

/**
 * Global return value.
 */ 
static int ret;


/**
 * Progress callback given to FS.
 * 
 * @param cls unused
 * @param info progress information, unused
 */ 
static void *
progress_cb (void *cls, const struct GNUNET_FS_ProgressInfo *info)
{
  return NULL;
}


/**
 * Output information about a pseudonym.
 *
 * @param cls closure
 * @param pseudonym hash code of public key of pseudonym
 * @param name name of the pseudonym (might be NULL)
 * @param unique_name unique name of the pseudonym (might be NULL)
 * @param md meta data known about the pseudonym
 * @param rating the local rating of the pseudonym
 * @return GNUNET_OK to continue iteration, GNUNET_SYSERR to abort
 */
static int
pseudo_printer (void *cls, 
		const struct GNUNET_CRYPTO_EccPublicKey *pseudonym,
                const char *name, 
		const char *unique_name,
                const struct GNUNET_CONTAINER_MetaData *md, 
		int32_t rating)
{
  char *id;
  char *unique_id;
  int getinfo_result;

  /* While we get a name from the caller, it might be NULL.
   * GNUNET_FS_pseudonym_get_info () never returns NULL.
   */
  getinfo_result = GNUNET_FS_pseudonym_get_info (cfg, pseudonym,
						 NULL, NULL, &id, NULL);
  if (GNUNET_OK != getinfo_result)
  {
    GNUNET_break (0);
    return GNUNET_OK;
  }
  unique_id = GNUNET_FS_pseudonym_name_uniquify (cfg, pseudonym, id, NULL);
  GNUNET_free (id);
  FPRINTF (stdout, 
	   "%s (%d):\n", 
	   unique_id, rating);
  GNUNET_CONTAINER_meta_data_iterate (md, &EXTRACTOR_meta_data_print, stdout);
  FPRINTF (stdout, 
	   "%s",
	   "\n");
  GNUNET_free (unique_id);
  return GNUNET_OK;
}


/**
 * Function called once advertising is finished.
 * 
 * @param cls closure (NULL)
 * @param uri the advertised URI
 * @param emsg error message, NULL on success
 */
static void
post_advertising (void *cls,
		  const struct GNUNET_FS_Uri *uri, 
		  const char *emsg)
{
  if (emsg != NULL)
  {
    FPRINTF (stderr, "%s", emsg);
    ret = 1;
  }
  GNUNET_FS_stop (h);
  GNUNET_IDENTITY_disconnect (identity);
}


/**
 * Function called by identity service with known pseudonyms.
 *
 * @param cls closure, NULL
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
  char *emsg;
  struct GNUNET_CRYPTO_EccPublicKey pub;

  if (NULL == ego) 
  {
    if (NULL == namespace)
    {
      ret = 1;
      return;
    }
    if (NULL != root_identifier)
    {
      if (NULL == ksk_uri)
      {
	emsg = NULL;
	ksk_uri = GNUNET_FS_uri_parse ("gnunet://fs/ksk/namespace", &emsg);
	GNUNET_assert (NULL == emsg);
      }
      GNUNET_IDENTITY_ego_get_public_key (namespace,
					  &pub);
      sks_uri = GNUNET_FS_uri_sks_create (&pub,
					  root_identifier);
      GNUNET_FS_publish_ksk (h, ksk_uri, adv_metadata, sks_uri,
			     &bo,
			     GNUNET_FS_PUBLISH_OPTION_NONE,
			     &post_advertising, NULL);
      GNUNET_FS_uri_destroy (sks_uri);
      return;
    }
    else
    {
      if (NULL != ksk_uri)
	FPRINTF (stderr, _("Option `%s' ignored\n"), "-k");
      if (NULL != advertise_ns)
	FPRINTF (stderr, _("Option `%s' ignored\n"), "-A");
    }
    return;
  }
  if (0 == strcmp (name, advertise_ns))
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
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  struct GNUNET_CRYPTO_EccPublicKey nsid;
  char *set;
  int delta;

  cfg = c;
  h = GNUNET_FS_start (cfg, "gnunet-pseudonym", &progress_cb, NULL,
                       GNUNET_FS_FLAGS_NONE, GNUNET_FS_OPTIONS_END);
  if (NULL != rating_change)
  {
    set = rating_change;
    while ((*set != '\0') && (*set != ':'))
      set++;
    if (*set != ':')
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
		  _("Invalid argument `%s'\n"),
                  rating_change);
    }
    else
    {
      *set = '\0';
      delta = strtol (&set[1], NULL,    /* no error handling yet */
                      10);
      if (GNUNET_OK == GNUNET_FS_pseudonym_name_to_id (cfg, rating_change, &nsid))
      {
        (void) GNUNET_FS_pseudonym_rank (cfg, &nsid, delta);
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
                    ("Namespace `%s' unknown. Make sure you specify its numeric suffix, if any.\n"),
                    rating_change);
      }
    }
    GNUNET_free (rating_change);
    rating_change = NULL;
  }
  if (0 == no_remote_printing)
    GNUNET_FS_pseudonym_list_all (cfg, &pseudo_printer, NULL);

  if (NULL != advertise_ns)
    identity = GNUNET_IDENTITY_connect (cfg, 
					&identity_cb, 
					NULL);
}


/**
 * The main function to manipulate GNUnet pseudonyms (and publish
 * to namespaces).
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
    {'A', "advertise", "NAME",
     gettext_noop ("advertise namespace NAME"),
     1, &GNUNET_GETOPT_set_string, &advertise_ns},
    {'k', "keyword", "VALUE",
     gettext_noop ("add an additional keyword for the advertisment"
                   " (this option can be specified multiple times)"),
     1, &GNUNET_FS_getopt_set_keywords, &ksk_uri},
    {'m', "meta", "TYPE:VALUE",
     gettext_noop ("set the meta-data for the given TYPE to the given VALUE"),
     1, &GNUNET_FS_getopt_set_metadata, &adv_metadata},
    {'p', "priority", "PRIORITY",
     gettext_noop ("use the given PRIORITY for the advertisments"),
     1, &GNUNET_GETOPT_set_uint, &bo.content_priority},
    {'q', "quiet", NULL,
     gettext_noop ("do not print names of remote namespaces"),
     0, &GNUNET_GETOPT_set_one, &no_remote_printing},
    {'r', "replication", "LEVEL",
     gettext_noop ("set the desired replication LEVEL"),
     1, &GNUNET_GETOPT_set_uint, &bo.replication_level},
    {'R', "root", "ID",
     gettext_noop ("specify ID of the root of the namespace"),
     1, &GNUNET_GETOPT_set_string, &root_identifier},
    {'s', "set-rating", "ID:VALUE",
     gettext_noop ("change rating of namespace ID by VALUE"),
     1, &GNUNET_GETOPT_set_string, &rating_change},
    GNUNET_GETOPT_OPTION_END
  };
  bo.expiration_time =
      GNUNET_FS_year_to_time (GNUNET_FS_get_current_year () + 2);

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  ret = (GNUNET_OK ==
	 GNUNET_PROGRAM_run (argc, argv, "gnunet-pseudonym [OPTIONS]",
			     gettext_noop ("Manage GNUnet pseudonyms."),
			     options, &run, NULL)) ? ret : 1;
  GNUNET_free ((void*) argv);
  return ret;
}

/* end of gnunet-pseudonym.c */
