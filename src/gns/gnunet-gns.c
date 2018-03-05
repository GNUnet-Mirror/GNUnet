/*
     This file is part of GNUnet.
     Copyright (C) 2012-2013, 2017-2018 GNUnet e.V.

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
 * Task scheduled to handle timeout.
 */
static struct GNUNET_SCHEDULER_Task *tt;

/**
 * Global return value.
 * 0 on success (default),
 * 1 on internal failures, 2 on launch failure,
 * 3 if the name is not a GNS-supported TLD,
 * 4 on timeout
 */
static int global_ret;


/**
 * Task run on shutdown.  Cleans up everything.
 *
 * @param cls unused
 */
static void
do_shutdown (void *cls)
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
  if (NULL != tt)
  {
    GNUNET_SCHEDULER_cancel (tt);
    tt = NULL;
  }
}


/**
 * Task run on timeout. Triggers shutdown.
 *
 * @param cls unused
 */
static void
do_timeout (void *cls)
{
  tt = NULL;
  GNUNET_SCHEDULER_shutdown ();
  global_ret = 4;
}


/**
 * Function called with the result of a GNS lookup.
 *
 * @param cls the 'const char *' name that was resolved
 * @param rd_count number of records returned
 * @param rd array of @a rd_count records with the results
 */
static void
process_lookup_result (void *cls,
                       uint32_t rd_count,
		       const struct GNUNET_GNSRECORD_Data *rd)
{
  const char *name = cls;
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
  for (uint32_t i=0; i<rd_count; i++)
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
 */
static void
lookup_with_public_key (const struct GNUNET_CRYPTO_EcdsaPublicKey *pkey)
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
    global_ret = 3; /* Not a GNS TLD */
    GNUNET_SCHEDULER_shutdown ();
  }
  else
  {
    GNUNET_IDENTITY_ego_get_public_key (ego,
                                        &pkey);
    lookup_with_public_key (&pkey);
  }
}


/**
 * Obtain the TLD of the given @a name.
 *
 * @param name a name
 * @return the part of @a name after the last ".",
 *         or @a name if @a name does not contain a "."
 */
static const char *
get_tld (const char *name)
{
  const char *tld;

  tld = strrchr (name,
                 (unsigned char) '.');
  if (NULL == tld)
    tld = name;
  else
    tld++; /* skip the '.' */
  return tld;
}


/**
 * Eat the TLD of the given @a name.
 *
 * @param name a name
 */
static void
eat_tld (char *name)
{
  char *tld;

  GNUNET_assert (0 < strlen (name));
  tld = strrchr (name,
                 (unsigned char) '.');
  if (NULL == tld)
    strcpy (name,
            GNUNET_GNS_MASTERZONE_STR);
  else
    *tld = '\0';
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
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  struct GNUNET_CRYPTO_EcdsaPublicKey pkey;
  const char *tld;
  char *dot_tld;
  char *zonestr;

  cfg = c;
  gns = GNUNET_GNS_connect (cfg);
  if (NULL == gns)
  {
    fprintf (stderr,
	     _("Failed to connect to GNS\n"));
    return;
  }
  tt = GNUNET_SCHEDULER_add_delayed (timeout,
                                     &do_timeout,
                                     NULL);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
                                 NULL);
  /* start with trivial case: TLD is zkey */
  tld = get_tld (lookup_name);
  if (GNUNET_OK ==
      GNUNET_CRYPTO_ecdsa_public_key_from_string (tld,
                                                  strlen (tld),
                                                  &pkey))
  {
    eat_tld (lookup_name);
    lookup_with_public_key (&pkey);
    return;
  }

  /* second case: TLD is mapped in our configuration file */
  GNUNET_asprintf (&dot_tld,
                   ".%s",
                   tld);
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             "gns",
                                             dot_tld,
                                             &zonestr))
  {
    if (GNUNET_OK !=
        GNUNET_CRYPTO_ecdsa_public_key_from_string (zonestr,
                                                    strlen (zonestr),
                                                    &pkey))
    {
      GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                                 "gns",
                                 dot_tld,
                                 _("Expected a base32-encoded public zone key\n"));
      GNUNET_free (zonestr);
      GNUNET_free (dot_tld);
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    GNUNET_free (dot_tld);
    GNUNET_free (zonestr);
    eat_tld (lookup_name);
    lookup_with_public_key (&pkey);
    return;
  }
  GNUNET_free (dot_tld);

  /* Final case: TLD matches one of our egos */
  eat_tld (lookup_name);

  /* if the name is of the form 'label.gnu', never go to the DHT */
  if (NULL == strchr (lookup_name,
                      (unsigned char) '.'))
    local_options = GNUNET_GNS_LO_NO_DHT;
  identity = GNUNET_IDENTITY_connect (cfg,
                                      NULL,
                                      NULL);
  el = GNUNET_IDENTITY_ego_lookup (cfg,
                                   tld,
                                   &identity_zone_cb,
                                   NULL);
}


/**
 * The main function for gnunet-gns.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc,
      char *const *argv)
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_mandatory
    (GNUNET_GETOPT_option_string ('u',
                                  "lookup",
                                  "NAME",
                                  gettext_noop ("Lookup a record for the given name"),
                                  &lookup_name)),
    GNUNET_GETOPT_option_string ('t',
                                 "type",
                                 "TYPE",
                                 gettext_noop ("Specify the type of the record to lookup"),
                                 &lookup_type),
    GNUNET_GETOPT_option_relative_time ('T',
                                        "timeout",
                                        "DELAY",
                                        gettext_noop ("Specify timeout for the lookup"),
                                        &timeout),
    GNUNET_GETOPT_option_flag ('r',
                               "raw",
                               gettext_noop ("No unneeded output"),
                               &raw),
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  timeout = GNUNET_TIME_UNIT_FOREVER_REL;
  if (GNUNET_OK !=
      GNUNET_STRINGS_get_utf8_args (argc, argv,
                                    &argc, &argv))
    return 2;

  GNUNET_log_setup ("gnunet-gns",
                    "WARNING",
                    NULL);
  ret = GNUNET_PROGRAM_run (argc, argv,
                            "gnunet-gns",
                            _("GNUnet GNS resolver tool"),
                            options,
                            &run, NULL);
  GNUNET_free ((void*) argv);
  if (GNUNET_OK != ret)
    return 1;
  return global_ret;
}

/* end of gnunet-gns.c */
