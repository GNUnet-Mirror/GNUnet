/*
     This file is part of GNUnet.
     (C) 2012-2013 Christian Grothoff (and other contributing authors)

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
 * @file gnunet-gns.c
 * @brief command line tool to access distributed GNS
 * @author Christian Grothoff
 */
#include "platform.h"
#include <gnunet_util_lib.h>
#include <gnunet_dnsparser_lib.h>
#include <gnunet_identity_service.h>
#include <gnunet_namestore_service.h>
#include <gnunet_gns_service.h>

/**
 * Configuration we are using.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to GNS service.
 */
static struct GNUNET_GNS_Handle *gns;

/**
 * GNS name to lookup. (-u option)
 */
static char *lookup_name;

/**
 * record type to look up (-t option)
 */
static char *lookup_type;

/**
 * Identity of the zone to use for the lookup (-z option)
 */
static char *zone_ego_name;

/**
 * Public key of the zone to use for the lookup (-p option)
 */
static char *public_key;

/**
 * raw output
 */
static int raw;

/**
 * Requested record type.
 */
static int rtype;

/**
 * Handle to lookup request 
 */
static struct GNUNET_GNS_LookupRequest *lookup_request;

/**
 * Handle to the identity service.
 */
static struct GNUNET_IDENTITY_Handle *identity;


/**
 * Task run on shutdown.  Cleans up everything.
 *
 * @param cls unused
 * @param tc scheduler context
 */
static void
do_shutdown (void *cls,
	     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != identity)
  {
    GNUNET_IDENTITY_disconnect (identity);
    identity = NULL;
  }
  if (NULL != lookup_request)
  {
    GNUNET_GNS_lookup_cancel (lookup_request);
    lookup_request = NULL;
  }
  if (NULL != gns)
  {
    GNUNET_GNS_disconnect (gns);
    gns = NULL;
  }
}


/**
 * Function called with the result of a GADS lookup.
 *
 * @param cls the 'const char *' name that was resolved
 * @param rd_count number of records returned
 * @param rd array of 'rd_count' records with the results
 */
static void
process_lookup_result (void *cls, uint32_t rd_count,
		       const struct GNUNET_NAMESTORE_RecordData *rd)
{
  const char *name = cls;
  uint32_t i;
  const char *typename;
  char* string_val;

  lookup_request = NULL; 
  if (!raw) 
  {
    if (0 == rd_count)
      printf ("No results.\n");
    else
      printf ("%s:\n", 
	      name);
  }
  for (i=0; i<rd_count; i++)
  {
    typename = GNUNET_NAMESTORE_number_to_typename (rd[i].record_type);
    string_val = GNUNET_NAMESTORE_value_to_string (rd[i].record_type,
						   rd[i].data,
						   rd[i].data_size);
    if (raw)
      printf ("%s\n", 
	      string_val);
    else
      printf ("Got `%s' record: %s\n",
	      typename, 
	      string_val);
    GNUNET_free_non_null (string_val);
  }
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Perform the actual resolution, starting with the zone
 * identified by the given public key.
 *
 * @param pkey public key to use for the zone
 */
static void
lookup_with_public_key (const struct GNUNET_CRYPTO_EccPublicKey *pkey)
{
  char *keyfile;
  struct GNUNET_CRYPTO_EccPrivateKey *shorten_key;

  if (GNUNET_OK != 
      GNUNET_CONFIGURATION_get_value_filename (cfg, "gns",
					       "SHORTEN_ZONEKEY", &keyfile))
  {
    shorten_key = NULL;
  }
  else
  {
    // FIXME: use identity service!
    shorten_key = GNUNET_CRYPTO_ecc_key_create_from_file (keyfile);
    GNUNET_free (keyfile);
  }
    
  if (NULL != lookup_type)
    rtype = GNUNET_NAMESTORE_typename_to_number (lookup_type);
  else
    rtype = GNUNET_DNSPARSER_TYPE_A;

  if (NULL != lookup_name)
  {
    lookup_request = GNUNET_GNS_lookup (gns, 
					lookup_name,
					pkey,
					rtype,
					GNUNET_NO, /* Use DHT */
					shorten_key,
					&process_lookup_result, 
					lookup_name);
  }
  else
  {
    fprintf (stderr,
	     _("Please specify name to lookup!\n"));
    GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }
  GNUNET_free_non_null (shorten_key);
}


/** 
 * Method called to inform about the egos of this peer.
 *
 * When used with #GNUNET_IDENTITY_connect, this function is
 * initially called for all egos and then again whenever a
 * ego's name changes or if it is deleted.  At the end of
 * the initial pass over all egos, the function is once called
 * with 'NULL' for @a ego. That does NOT mean that the callback won't
 * be invoked in the future or that there was an error.
 *
 * If the @a name matches the `zone_ego_name`, we found the zone
 * for our computation and will begin resolving against that zone.
 * If we have iterated over all egos and not found the name, we
 * terminate the program with an error message.
 *
 * @param cls closure (NULL, unused)
 * @param ego ego handle
 * @param ego_ctx context for application to store data for this ego
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
  struct GNUNET_CRYPTO_EccPublicKey pkey;
  
  if ( (NULL != zone_ego_name) &&
       (NULL != name) &&
       (0 == strcmp (name,
		     zone_ego_name)) )
  {
    GNUNET_IDENTITY_ego_get_public_key (ego, &pkey);
    lookup_with_public_key (&pkey);
    GNUNET_free (zone_ego_name);
    zone_ego_name = NULL;
    GNUNET_IDENTITY_disconnect (identity);
    identity = NULL;
    return;
  }
  if ( (NULL == ego) &&
       (NULL != identity) &&
       (NULL != zone_ego_name) )
  {
    fprintf (stderr,
	     _("Ego `%s' not found\n"),
	     zone_ego_name);
    GNUNET_free (zone_ego_name);
    zone_ego_name = NULL;
    GNUNET_IDENTITY_disconnect (identity);
    identity = NULL;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
}


/**
 * Main function that will be run.
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
  struct GNUNET_CRYPTO_EccPublicKey pkey;

  cfg = c;
  gns = GNUNET_GNS_connect (cfg);
  if (NULL == gns)
  {
    fprintf (stderr,
	     _("Failed to connect to GNS\n"));
    return;
  }
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
				&do_shutdown, NULL);
  if (NULL != public_key)
  {
    if (GNUNET_OK !=
	GNUNET_CRYPTO_ecc_public_key_from_string (public_key,
						  strlen (public_key),
						  &pkey))
    {
      fprintf (stderr, 
	       _("Public key `%s' is not well-formed\n"),
	       public_key);
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    lookup_with_public_key (&pkey);
    return;
  }
  if (NULL != zone_ego_name)
  {
    identity = GNUNET_IDENTITY_connect (cfg, 
					&identity_cb,
					NULL);
    return;
  }
  if ( (NULL != lookup_name) &&
       (strlen (lookup_name) > 4) &&
       (0 == strcmp (".zkey",
		     &lookup_name[strlen (lookup_name) - 4])) )
  {
    /* no zone required, use 'anonymous' zone */
    GNUNET_CRYPTO_ecc_key_get_public (GNUNET_CRYPTO_ecc_key_get_anonymous (),
				      &pkey);
    lookup_with_public_key (&pkey);
  }
  else
  {
    fprintf (stderr,
	     _("I need a zone (`-p' or `-z' option) to resolve this name\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
}


/**
 * The main function for gnunet-gns.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'u', "lookup", "NAME",
      gettext_noop ("Lookup a record for the given name"), 1,
      &GNUNET_GETOPT_set_string, &lookup_name},
    {'t', "type", "TYPE",
      gettext_noop ("Specify the type of the record to lookup"), 1,
      &GNUNET_GETOPT_set_string, &lookup_type},
    {'r', "raw", NULL,
      gettext_noop ("No unneeded output"), 0,
      &GNUNET_GETOPT_set_one, &raw},
    {'p', "public-key", "PKEY",
      gettext_noop ("Specify the public key of the zone to lookup the record in"), 1,
      &GNUNET_GETOPT_set_string, &public_key},
    {'z', "zone", "NAME",
      gettext_noop ("Specify the name of the ego of the zone to lookup the record in"), 1,
      &GNUNET_GETOPT_set_string, &zone_ego_name},
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  GNUNET_log_setup ("gnunet-gns", "WARNING", NULL);
  ret =
      (GNUNET_OK ==
       GNUNET_PROGRAM_run (argc, argv, "gnunet-gns",
                           _("GNUnet GNS resolver tool"), 
			   options,
                           &run, NULL)) ? 0 : 1;
  GNUNET_free ((void*) argv);
  return ret;
}

/* end of gnunet-gns.c */
