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
#include <gnunet_gnsrecord_lib.h>
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
 * Desired timeout for the lookup (default is no timeout).
 */
static struct GNUNET_TIME_Relative timeout;

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
 * Set to GNUNET_GNS_LO_LOCAL_MASTER if we are looking up in the master zone.
 */
static enum GNUNET_GNS_LocalOptions local_options;

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
 * Lookup an ego with the identity service.
 */
static struct GNUNET_IDENTITY_EgoLookup *el;

/**
 * Handle for identity service.
 */
static struct GNUNET_IDENTITY_Handle *identity;

/**
 * Active operation on identity service.
 */
static struct GNUNET_IDENTITY_Operation *id_op;


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
  if (NULL != el)
  {
    GNUNET_IDENTITY_ego_lookup_cancel (el);
    el = NULL;
  }
  if (NULL != id_op)
  {
    GNUNET_IDENTITY_cancel (id_op);
    id_op = NULL;
  }
  if (NULL != lookup_request)
  {
    GNUNET_GNS_lookup_cancel (lookup_request);
    lookup_request = NULL;
  }
  if (NULL != identity)
  {
    GNUNET_IDENTITY_disconnect (identity);
    identity = NULL;
  }
  if (NULL != gns)
  {
    GNUNET_GNS_disconnect (gns);
    gns = NULL;
  }
}


/**
 * Function called with the result of a GNS lookup.
 *
 * @param cls the 'const char *' name that was resolved
 * @param rd_count number of records returned
 * @param rd array of @a rd_count records with the results
 */
static void
process_lookup_result (void *cls, uint32_t rd_count,
		       const struct GNUNET_GNSRECORD_Data *rd)
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
    if ( (rd[i].record_type != rtype) &&
	 (GNUNET_GNSRECORD_TYPE_ANY != rtype) )
      continue;
    typename = GNUNET_GNSRECORD_number_to_typename (rd[i].record_type);
    string_val = GNUNET_GNSRECORD_value_to_string (rd[i].record_type,
						   rd[i].data,
						   rd[i].data_size);
    if (NULL == string_val)
    {
      fprintf (stderr,
	       "Record %u of type %d malformed, skipping\n",
	       (unsigned int) i,
	       (int) rd[i].record_type);
      continue;
    }
    if (raw)
      printf ("%s\n",
	      string_val);
    else
      printf ("Got `%s' record: %s\n",
	      typename,
	      string_val);
    GNUNET_free (string_val);
  }
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Perform the actual resolution, starting with the zone
 * identified by the given public key and the shorten zone.
 *
 * @param pkey public key to use for the zone, can be NULL
 * @param shorten_key private key used for shortening, can be NULL
 */
static void
lookup_with_keys (const struct GNUNET_CRYPTO_EcdsaPublicKey *pkey,
		  const struct GNUNET_CRYPTO_EcdsaPrivateKey *shorten_key)
{
  if (NULL != lookup_type)
    rtype = GNUNET_GNSRECORD_typename_to_number (lookup_type);
  else
    rtype = GNUNET_DNSPARSER_TYPE_A;
  if (UINT32_MAX == rtype)
  {
    fprintf (stderr,
             _("Invalid typename specified, assuming `ANY'\n"));
    rtype = GNUNET_GNSRECORD_TYPE_ANY;
  }

  if (NULL != lookup_name)
  {
    lookup_request = GNUNET_GNS_lookup (gns,
					lookup_name,
					pkey,
					rtype,
					local_options,
					shorten_key,
					&process_lookup_result,
					lookup_name);
  }
  else
  {
    fprintf (stderr,
	     _("Please specify name to lookup!\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
}


/**
 * Method called to with the ego we are to use for shortening
 * during the lookup.
 *
 * @param cls closure contains the public key to use
 * @param ego ego handle, NULL if not found
 * @param ctx context for application to store data for this ego
 *                 (during the lifetime of this process, initially NULL)
 * @param name name assigned by the user for this ego,
 *                   NULL if the user just deleted the ego and it
 *                   must thus no longer be used
 */
static void
identity_shorten_cb (void *cls,
		     struct GNUNET_IDENTITY_Ego *ego,
		     void **ctx,
		     const char *name)
{
  struct GNUNET_CRYPTO_EcdsaPublicKey *pkeym = cls;

  id_op = NULL;
  if (NULL == ego)
    lookup_with_keys (pkeym, NULL);
  else
    lookup_with_keys (pkeym,
		      GNUNET_IDENTITY_ego_get_private_key (ego));
  GNUNET_free (pkeym);
}


/**
 * Perform the actual resolution, starting with the zone
 * identified by the given public key.
 *
 * @param pkey public key to use for the zone
 */
static void
lookup_with_public_key (const struct GNUNET_CRYPTO_EcdsaPublicKey *pkey)
{
  struct GNUNET_CRYPTO_EcdsaPublicKey *pkeym;

  GNUNET_assert (NULL != pkey);
  pkeym = GNUNET_new (struct GNUNET_CRYPTO_EcdsaPublicKey);
  *pkeym = *pkey;
  GNUNET_break (NULL == id_op);
  id_op = GNUNET_IDENTITY_get (identity,
			       "gns-short",
			       &identity_shorten_cb,
			       pkeym);
  if (NULL == id_op)
  {
    GNUNET_break (0);
    lookup_with_keys (pkey, NULL);
  }
}


/**
 * Method called to with the ego we are to use for the lookup,
 * when the ego is determined by a name.
 *
 * @param cls closure (NULL, unused)
 * @param ego ego handle, NULL if not found
 */
static void
identity_zone_cb (void *cls,
		  const struct GNUNET_IDENTITY_Ego *ego)
{
  struct GNUNET_CRYPTO_EcdsaPublicKey pkey;

  el = NULL;
  if (NULL == ego)
  {
    fprintf (stderr,
	     _("Ego for `%s' not found, cannot perform lookup.\n"),
	     zone_ego_name);
    GNUNET_SCHEDULER_shutdown ();
  }
  else
  {
    GNUNET_IDENTITY_ego_get_public_key (ego, &pkey);
    lookup_with_public_key (&pkey);
  }
  GNUNET_free_non_null (zone_ego_name);
  zone_ego_name = NULL;
}


/**
 * Method called to with the ego we are to use for the lookup,
 * when the ego is the one for the default master zone.
 *
 * @param cls closure (NULL, unused)
 * @param ego ego handle, NULL if not found
 * @param ctx context for application to store data for this ego
 *                 (during the lifetime of this process, initially NULL)
 * @param name name assigned by the user for this ego,
 *                   NULL if the user just deleted the ego and it
 *                   must thus no longer be used
 */
static void
identity_master_cb (void *cls,
		    struct GNUNET_IDENTITY_Ego *ego,
		    void **ctx,
		    const char *name)
{
  struct GNUNET_CRYPTO_EcdsaPublicKey pkey;
  const char *dot;

  id_op = NULL;
  if (NULL == ego)
  {
    fprintf (stderr,
	     _("Ego for `gns-master' not found, cannot perform lookup.  Did you run gnunet-gns-import.sh?\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_IDENTITY_ego_get_public_key (ego, &pkey);
  /* main name is our own master zone, do no look for that in the DHT */
  local_options = GNUNET_GNS_LO_LOCAL_MASTER;

  /* if the name is of the form 'label.gnu', never go to the DHT */
  dot = NULL;
  if (NULL != lookup_name)
    dot = strchr (lookup_name, '.');
  if ( (NULL != dot) &&
       (0 == strcasecmp (dot, ".gnu")) )
    local_options = GNUNET_GNS_LO_NO_DHT;
  lookup_with_public_key (&pkey);
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
  struct GNUNET_CRYPTO_EcdsaPublicKey pkey;

  cfg = c;
  gns = GNUNET_GNS_connect (cfg);
  identity = GNUNET_IDENTITY_connect (cfg, NULL, NULL);
  if (NULL == gns)
  {
    fprintf (stderr,
	     _("Failed to connect to GNS\n"));
    return;
  }
  GNUNET_SCHEDULER_add_delayed (timeout,
				&do_shutdown, NULL);
  if (NULL != public_key)
  {
    if (GNUNET_OK !=
	GNUNET_CRYPTO_ecdsa_public_key_from_string (public_key,
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
    el = GNUNET_IDENTITY_ego_lookup (cfg,
				     zone_ego_name,
				     &identity_zone_cb,
				     NULL);
    return;
  }
  if ( (NULL != lookup_name) &&
       (strlen (lookup_name) > 4) &&
       (0 == strcmp (".zkey",
		     &lookup_name[strlen (lookup_name) - 4])) )
  {
    /* no zone required, use 'anonymous' zone */
    GNUNET_CRYPTO_ecdsa_key_get_public (GNUNET_CRYPTO_ecdsa_key_get_anonymous (),
				      &pkey);
    lookup_with_public_key (&pkey);
  }
  else
  {
    GNUNET_break (NULL == id_op);
    id_op = GNUNET_IDENTITY_get (identity,
				 "gns-master",
				 &identity_master_cb,
				 NULL);
    GNUNET_assert (NULL != id_op);
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
    { 'T', "timeout", "DELAY",
      gettext_noop ("Specify timeout for the lookup"), 1,
      &GNUNET_GETOPT_set_relative_time, &timeout },
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

  timeout = GNUNET_TIME_UNIT_FOREVER_REL;
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
