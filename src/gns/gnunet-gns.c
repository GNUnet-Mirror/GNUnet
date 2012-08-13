/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 *
 */
#include "platform.h"
#include <gnunet_util_lib.h>
#include <gnunet_dnsparser_lib.h>
#include <gnunet_namestore_service.h>
#include <gnunet_gns_service.h>

/**
 * Handle to GNS service.
 */
static struct GNUNET_GNS_Handle *gns;

/**
 * GNS name to shorten. (-s option)
 */
static char *shorten_name;

/**
 * GNS name to lookup. (-u option)
 */
static char *lookup_name;


/**
 * record type to look up (-t option)
 */
static char *lookup_type;

/**
 * name to look up authority for (-a option)
 */
static char *auth_name;

/**
 * raw output
 */
static int raw = 0;

static enum GNUNET_GNS_RecordType rtype;

/* Handle to lookup request */
static struct GNUNET_GNS_LookupRequest *lookup_request;

/* Handle to shorten request */
static struct GNUNET_GNS_ShortenRequest *shorten_request;

/* Handle to get authority request */
static struct GNUNET_GNS_GetAuthRequest *getauth_request;

/* shutdown task */
static GNUNET_SCHEDULER_TaskIdentifier shutdown_task;

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
  if (NULL != lookup_request)
    GNUNET_GNS_cancel_lookup_request (lookup_request);

  if (NULL != shorten_request)
    GNUNET_GNS_cancel_shorten_request (shorten_request);

  if (NULL != getauth_request)
    GNUNET_GNS_cancel_get_auth_request (getauth_request);

  if (NULL != gns)
    GNUNET_GNS_disconnect (gns);
}


static void
process_shorten_result(void* cls, const char* nshort)
{
  shorten_request = NULL;
  if (raw)
    printf("%s", nshort);
  else
    printf("%s shortened to %s\n", (char*) cls, nshort);
  GNUNET_SCHEDULER_cancel (shutdown_task);
  GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
}

static void
process_lookup_result(void* cls, uint32_t rd_count,
                      const struct GNUNET_NAMESTORE_RecordData *rd)
{
  int i;
  char* name = (char*) cls;
  const char* typename;
  char* string_val;
  lookup_request = NULL;
  
  if (!raw) {
    if (rd_count == 0)
      printf("No results.\n");
    else
      printf("%s:\n", name);
  }



  for (i=0; i<rd_count; i++)
  {
    typename = GNUNET_NAMESTORE_number_to_typename (rd[i].record_type);
    string_val = GNUNET_NAMESTORE_value_to_string(rd[i].record_type,
                                                  rd[i].data,
                                                  rd[i].data_size);
    if (raw)
      printf("%s\n", string_val);
    else
      printf("Got %s record: %s\n", typename, string_val);

  }
  GNUNET_SCHEDULER_cancel (shutdown_task);
  GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
}

static void
process_auth_result(void* cls, const char* auth)
{
  getauth_request = NULL;
  printf ("%s\n", auth);
  GNUNET_SCHEDULER_cancel (shutdown_task);
  GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
}

/**
 * Main function that will be run.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char* keyfile;
  struct GNUNET_CRYPTO_RsaPrivateKey *key = NULL;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pkey;
  struct GNUNET_CRYPTO_ShortHashCode *zone = NULL;
  struct GNUNET_CRYPTO_ShortHashCode user_zone;
  struct GNUNET_CRYPTO_ShortHashAsciiEncoded zonename;
  struct GNUNET_CRYPTO_RsaPrivateKey *shorten_key = NULL;
  struct GNUNET_CRYPTO_RsaPrivateKey *private_key = NULL;
  struct GNUNET_CRYPTO_ShortHashCode *private_zone = NULL;
  struct GNUNET_CRYPTO_ShortHashCode *shorten_zone = NULL;

  shorten_request = NULL;
  lookup_request = NULL;
  getauth_request = NULL;

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (cfg, "gns",
                                                           "ZONEKEY", &keyfile))
  {
    if (!raw)
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "No private key for root zone found, using default!\n");
    zone = NULL;
  }
  else
  {
    if (GNUNET_YES == GNUNET_DISK_file_test (keyfile))
    {
      key = GNUNET_CRYPTO_rsa_key_create_from_file (keyfile);
      GNUNET_CRYPTO_rsa_key_get_public (key, &pkey);
      GNUNET_CRYPTO_short_hash(&pkey,
                         sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                         &user_zone);
      zone = &user_zone;
      GNUNET_CRYPTO_short_hash_to_enc (zone, &zonename);
      if (!raw)
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Using zone: %s!\n", &zonename);
      GNUNET_CRYPTO_rsa_key_free(key);
    }
    GNUNET_free(keyfile);
  }
  
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (cfg, "gns",
                                                   "SHORTEN_ZONEKEY", &keyfile))
  {
    if (!raw)
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "No shorten key found!\n");
    shorten_key = NULL;
  }
  else
  {
    if (GNUNET_YES == GNUNET_DISK_file_test (keyfile))
    {
      shorten_key = GNUNET_CRYPTO_rsa_key_create_from_file (keyfile);
      GNUNET_CRYPTO_rsa_key_get_public (shorten_key, &pkey);
      shorten_zone = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_ShortHashCode));
      GNUNET_CRYPTO_short_hash(&pkey,
                         sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                         shorten_zone);
      GNUNET_CRYPTO_short_hash_to_enc (shorten_zone, &zonename);
      if (!raw)
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Using shorten zone: %s!\n", &zonename);

    }
    GNUNET_free(keyfile);
  }
  
  
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (cfg, "gns",
							    "PRIVATE_ZONEKEY", &keyfile))
  {
    if (!raw)
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "No private zone key file name specified in configuration!\n");
    shorten_key = NULL;
  }
  else
  {
    if (GNUNET_YES == GNUNET_DISK_file_test (keyfile))
    {
      private_key = GNUNET_CRYPTO_rsa_key_create_from_file (keyfile);
      GNUNET_CRYPTO_rsa_key_get_public (private_key, &pkey);
      private_zone = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_ShortHashCode));
      GNUNET_CRYPTO_short_hash(&pkey,
                         sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                         private_zone);
      GNUNET_CRYPTO_short_hash_to_enc (private_zone, &zonename);
      if (!raw)
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Using private zone: %s!\n", &zonename);
    }
    else
    {
      /* FIXME: shouldn't we just create the private key in this case? */
      if (!raw)
        fprintf (stderr,
		 _("Key file `%s' for private zone does not exist!\n"),
		 keyfile);

    }
    GNUNET_free(keyfile);
    if (NULL != private_key)
    {
      GNUNET_CRYPTO_rsa_key_free (private_key);
      private_key = NULL;
    }
  }
  
  
  gns = GNUNET_GNS_connect (cfg);
  if (NULL != lookup_type)
    rtype = GNUNET_NAMESTORE_typename_to_number (lookup_type);
  else
    rtype = GNUNET_GNS_RECORD_A;

  if (NULL == gns)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Failed to connect to GNS\n"));
    return;
  }
  
  if (NULL != shorten_name)
  {
    shorten_request = GNUNET_GNS_shorten_zone (gns, shorten_name,
                             private_zone,
                             shorten_zone,
                             zone,
                             &process_shorten_result,
                             shorten_name);
  }

  if (NULL != lookup_name)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Lookup\n");
    lookup_request = GNUNET_GNS_lookup_zone (gns, lookup_name,
                            zone,
                            rtype,
                            GNUNET_NO, //Use DHT
                            shorten_key,
                            &process_lookup_result, lookup_name);
  }

  if (NULL != auth_name)
  {
    getauth_request = GNUNET_GNS_get_authority(gns, auth_name,
                                               &process_auth_result, auth_name);
  }

  if (NULL != shorten_key)
    GNUNET_CRYPTO_rsa_key_free (shorten_key);

  if (NULL != shorten_zone)
    GNUNET_free (shorten_zone);

  if (NULL != private_zone)
    GNUNET_free (private_zone);
  
  if ((NULL == auth_name) &&
      (NULL == shorten_name) &&
      (NULL == lookup_name))
  {
    if (!raw)
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                 "Please specify lookup, shorten or authority operation!\n");
    GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }

  shutdown_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                                &do_shutdown, NULL);
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
    {'s', "shorten", NULL,
     gettext_noop ("try to shorten a given name"), 1,
     &GNUNET_GETOPT_set_string, &shorten_name},
    {'u', "lookup", NULL,
      gettext_noop ("Lookup a record for the given name"), 1,
      &GNUNET_GETOPT_set_string, &lookup_name},
    {'a', "authority", NULL,
      gettext_noop ("Get the authority of a particular name"), 1,
      &GNUNET_GETOPT_set_string, &auth_name},
    {'t', "type", NULL,
      gettext_noop ("Specify the type of the record to lookup"), 1,
      &GNUNET_GETOPT_set_string, &lookup_type},
    {'r', "raw", NULL,
      gettext_noop ("No unneeded output"), 0,
      &GNUNET_GETOPT_set_one, &raw},
    GNUNET_GETOPT_OPTION_END
  };

  int ret;

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  GNUNET_log_setup ("gnunet-gns", "WARNING", NULL);
  ret =
      (GNUNET_OK ==
       GNUNET_PROGRAM_run (argc, argv, "gnunet-gns",
                           _("GNUnet GNS access tool"), 
			   options,
                           &run, NULL)) ? 0 : 1;

  return ret;
}

/* end of gnunet-gns.c */
