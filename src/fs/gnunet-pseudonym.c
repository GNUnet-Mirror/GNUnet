/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2006, 2007, 2009, 2010 Christian Grothoff (and other contributing authors)

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

/**
 * -C option
 */
static char *create_ns;

/**
 * -D option
 */
static char *delete_ns;

/**
 * -k option
 */
static struct GNUNET_FS_Uri *ksk_uri;

/**
 * -l option.
 */
static int print_local_only;

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
 * Namespace we are looking at.
 */
static struct GNUNET_FS_Namespace *ns;

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

static int ret;

static void *
progress_cb (void *cls, const struct GNUNET_FS_ProgressInfo *info)
{
  return NULL;
}


static void
ns_printer (void *cls, const char *name, const GNUNET_HashCode * id)
{
  struct GNUNET_CRYPTO_HashAsciiEncoded enc;

  GNUNET_CRYPTO_hash_to_enc (id, &enc);
  FPRINTF (stdout, "%s (%s)\n", name, (const char *) &enc);
}


static int
pseudo_printer (void *cls, const GNUNET_HashCode * pseudonym,
                const struct GNUNET_CONTAINER_MetaData *md, int rating)
{
  char *id;

  id = GNUNET_PSEUDONYM_id_to_name (cfg, pseudonym);
  if (id == NULL)
  {
    GNUNET_break (0);
    return GNUNET_OK;
  }
  FPRINTF (stdout, "%s (%d):\n", id, rating);
  GNUNET_CONTAINER_meta_data_iterate (md, &EXTRACTOR_meta_data_print, stdout);
  FPRINTF (stdout, "%s",  "\n");
  GNUNET_free (id);
  return GNUNET_OK;
}


static void
post_advertising (void *cls, const struct GNUNET_FS_Uri *uri, const char *emsg)
{
  GNUNET_HashCode nsid;
  char *set;
  int delta;

  if (emsg != NULL)
  {
    FPRINTF (stderr, "%s", emsg);
    ret = 1;
  }
  if (ns != NULL)
  {
    if (GNUNET_OK != GNUNET_FS_namespace_delete (ns, GNUNET_NO))
      ret = 1;
  }
  if (NULL != rating_change)
  {
    set = rating_change;
    while ((*set != '\0') && (*set != ':'))
      set++;
    if (*set != ':')
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Invalid argument `%s'\n"),
                  rating_change);
    }
    else
    {
      *set = '\0';
      delta = strtol (&set[1], NULL,    /* no error handling yet */
                      10);
      if (GNUNET_OK == GNUNET_PSEUDONYM_name_to_id (cfg, rating_change, &nsid))
      {
        (void) GNUNET_PSEUDONYM_rank (cfg, &nsid, delta);
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Namespace `%s' unknown.\n"),
                    rating_change);
      }
    }
    GNUNET_free (rating_change);
    rating_change = NULL;
  }
  if (0 != print_local_only)
  {
    GNUNET_FS_namespace_list (h, &ns_printer, NULL);
  }
  else if (0 == no_remote_printing)
  {
    GNUNET_PSEUDONYM_list_all (cfg, &pseudo_printer, NULL);
  }
  GNUNET_FS_stop (h);
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
  char *emsg;

  cfg = c;
  h = GNUNET_FS_start (cfg, "gnunet-pseudonym", &progress_cb, NULL,
                       GNUNET_FS_FLAGS_NONE, GNUNET_FS_OPTIONS_END);
  if (NULL != delete_ns)
  {
    ns = GNUNET_FS_namespace_create (h, delete_ns);
    if (ns == NULL)
    {
      ret = 1;
    }
    else
    {
      if (GNUNET_OK != GNUNET_FS_namespace_delete (ns, GNUNET_YES))
        ret = 1;
      ns = NULL;
    }
  }
  if (NULL != create_ns)
  {
    ns = GNUNET_FS_namespace_create (h, create_ns);
    if (ns == NULL)
    {
      ret = 1;
    }
    else
    {
      if (NULL != root_identifier)
      {
        if (ksk_uri == NULL)
        {
          emsg = NULL;
          ksk_uri = GNUNET_FS_uri_parse ("gnunet://fs/ksk/namespace", &emsg);
          GNUNET_assert (NULL == emsg);
        }
        GNUNET_FS_namespace_advertise (h, ksk_uri, ns, adv_metadata, &bo,
                                       root_identifier, &post_advertising,
                                       NULL);
        return;
      }
      else
      {
        if (ksk_uri != NULL)
          FPRINTF (stderr, _("Option `%s' ignored\n"), "-k");
      }
    }
  }
  else
  {
    if (root_identifier != NULL)
      FPRINTF (stderr, _("Option `%s' ignored\n"), "-r");
    if (ksk_uri != NULL)
      FPRINTF (stderr, _("Option `%s' ignored\n"), "-k");
  }

  post_advertising (NULL, NULL, NULL);
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
    {'C', "create", "NAME",
     gettext_noop ("create or advertise namespace NAME"),
     1, &GNUNET_GETOPT_set_string, &create_ns},
    {'D', "delete", "NAME",
     gettext_noop ("delete namespace NAME "),
     1, &GNUNET_GETOPT_set_string, &delete_ns},
    {'k', "keyword", "VALUE",
     gettext_noop ("add an additional keyword for the advertisment"
                   " (this option can be specified multiple times)"),
     1, &GNUNET_FS_getopt_set_keywords, &ksk_uri},
    {'m', "meta", "TYPE:VALUE",
     gettext_noop ("set the meta-data for the given TYPE to the given VALUE"),
     1, &GNUNET_FS_getopt_set_metadata, &adv_metadata},
    {'o', "only-local", NULL,
     gettext_noop ("print names of local namespaces"),
     0, &GNUNET_GETOPT_set_one, &print_local_only},
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
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-pseudonym [OPTIONS]",
                              gettext_noop ("Manage GNUnet pseudonyms."),
                              options, &run, NULL)) ? ret : 1;
}

/* end of gnunet-pseudonym.c */
