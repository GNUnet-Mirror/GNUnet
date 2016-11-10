/*
     This file is part of GNUnet.
     Copyright (C) 2012-2013 GNUnet e.V.

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
 * @file gnunet-credential.c
 * @brief command line tool to access command line Credential service
 * @author Adnan Husain
 */
#include "platform.h"
#include <gnunet_util_lib.h>
#include <gnunet_identity_service.h>
#include <gnunet_credential_service.h>

/**
 * Configuration we are using.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to Credential service.
 */
static struct GNUNET_CREDENTIAL_Handle *credential;

/**
 * Desired timeout for the lookup (default is no timeout).
 */
static struct GNUNET_TIME_Relative timeout;

/**
 * Credential to lookup. (-u option)
 */
static char *lookup_credential;

/**
 * Handle to lookup request
 */
static struct GNUNET_CREDENTIAL_LookupRequest *lookup_request;

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
 * Subject pubkey string
 */
static char *subject_key;

/**
 * Subject pubkey string
 */
static char *issuer_key;

/*
 * Credential flags
 */
static int credential_flags;

/*
 * Maximum delegation depth
 */
static int max_delegation_depth;



/**
 * Identity of the zone to use for the lookup (-z option)
 */
static char *zone_ego_name;


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
    GNUNET_CREDENTIAL_lookup_cancel (lookup_request);
    lookup_request = NULL;
  }
  if (NULL != identity)
  {
    GNUNET_IDENTITY_disconnect (identity);
    identity = NULL;
  }
  if (NULL != credential)
  {
    GNUNET_CREDENTIAL_disconnect (credential);
    credential = NULL;
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
}


/**
 * Function called with the result of a Credential lookup.
 *
 * @param cls the 'const char *' name that was resolved
 * @param cd_count number of records returned
 * @param cd array of @a cd_count records with the results
 */
static void
handle_lookup_result (void *cls,
				struct GNUNET_IDENTITY_Ego *issuer,
              	uint16_t issuer_len,
				const struct GNUNET_CREDENTIAL_RecordData *data)
{
  

  lookup_request = NULL;
  if (0 == issuer_len)
    printf ("No results.\n");
  else
  	printf ("%u\n",
    	  issuer_len);

  
  GNUNET_SCHEDULER_shutdown ();
}




/**
 * Perform the actual resolution, with the subject pkey and
 * the issuer public key
 *
 * @param pkey public key to use for the zone, can be NULL
 * @param shorten_key private key used for shortening, can be NULL
 */
static void
lookup_credentials (struct GNUNET_IDENTITY_Ego *ego)
{
  
  struct GNUNET_CRYPTO_EcdsaPublicKey subject_pkey;
  struct GNUNET_CRYPTO_EcdsaPublicKey issuer_pkey;

  if (NULL != subject_key && NULL != issuer_key && NULL != lookup_credential)
  {
    if (GNUNET_OK !=
        GNUNET_CRYPTO_ecdsa_public_key_from_string (subject_key,
                                                    strlen (subject_key),
                                                    &subject_pkey))
    {
      fprintf (stderr,
               _("Subject public key `%s' is not well-formed\n"),
               subject_key);
      GNUNET_SCHEDULER_shutdown ();
      return;
    }

    if (GNUNET_OK !=
        GNUNET_CRYPTO_ecdsa_public_key_from_string (issuer_key,
                                                    strlen (issuer_key),
                                                    &issuer_pkey))
    {
      fprintf (stderr,
               _("Authority public key `%s' is not well-formed\n"),
               issuer_key);
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    
  lookup_request = GNUNET_CREDENTIAL_lookup(credential,
                    lookup_credential,
                    ego,
                    &subject_pkey,
                    &issuer_pkey,
                    credential_flags,
                    max_delegation_depth,
                    &handle_lookup_result,
                    NULL);
   return;
  }
  else
  {
    fprintf (stderr,
       _("Please specify name to lookup, subject key and issuer key!\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
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
  
  id_op = NULL;
  if (NULL == ego)
  {
    fprintf (stderr,
	     _("Ego for `gns-master' not found, cannot perform lookup.  Did you run gnunet-gns-import.sh?\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  lookup_credentials(ego);

  
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
  
  cfg = c;
  credential = GNUNET_CREDENTIAL_connect (cfg);
  identity = GNUNET_IDENTITY_connect (cfg, NULL, NULL);

 

  
  if (NULL == credential)
  {
    fprintf (stderr,
	     _("Failed to connect to CREDENTIAL\n"));
    return;
  }
  if (NULL == identity)
  {
    fprintf (stderr,
	     _("Failed to connect to IDENTITY\n"));
    return;
  }
  tt = GNUNET_SCHEDULER_add_delayed (timeout,
				     &do_timeout, NULL);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown, NULL);
  

  
	GNUNET_break (NULL == id_op);
	id_op = GNUNET_IDENTITY_get (identity,
			 "gns-master",//# TODO: Create credential-master
			 &identity_master_cb,
			 cls);
	GNUNET_assert (NULL != id_op);


 

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
    {'u', "lookup", "CREDENTIAL",
      gettext_noop ("Lookup a record for the given credential"), 1,
      &GNUNET_GETOPT_set_string, &lookup_credential},
   /** { 'T', "timeout", "DELAY",
      gettext_noop ("Specify timeout for the lookup"), 1,
      &GNUNET_GETOPT_set_relative_time, &timeout },
    {'t', "type", "TYPE",
      gettext_noop ("Specify the type of the record to lookup"), 1,
    &GNUNET_GETOPT_set_string, &lookup_type},**/
    {'z', "zone", "NAME",
    gettext_noop ("Specify the name of the ego of the zone to lookup the record in"), 1,
    &GNUNET_GETOPT_set_string, &zone_ego_name},
    {'s', "subject", "PKEY",
      gettext_noop ("Specify the public key of the subject to lookup the credential for"), 1,
      &GNUNET_GETOPT_set_string, &subject_key},
    {'i', "issuer", "PKEY",
      gettext_noop ("Specify the public key of the authority to verify the credential against"), 1,
      &GNUNET_GETOPT_set_string, &issuer_key},
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  timeout = GNUNET_TIME_UNIT_FOREVER_REL;
  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  GNUNET_log_setup ("gnunet-credential", "WARNING", NULL);
  ret =
      (GNUNET_OK ==
       GNUNET_PROGRAM_run (argc, argv, "gnunet-credential",
                           _("GNUnet credential resolver tool"),
			   options,
                           &run, NULL)) ? 0 : 1;
  GNUNET_free ((void*) argv);
  return ret;
}

/* end of gnunet-credential.c */
