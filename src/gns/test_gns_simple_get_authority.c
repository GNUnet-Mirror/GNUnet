/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file gns/test_gns_simple_shorten.c
 * @brief basic shorten test for gns api
 *
 */
#include "platform.h"
#include "gnunet_testing_lib.h"
#include "gnunet_core_service.h"
#include "block_dns.h"
#include "gnunet_signatures.h"
#include "gnunet_namestore_service.h"
#include "../namestore/namestore.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_gns_service.h"

/* DEFINES */
#define VERBOSE GNUNET_YES

/* Timeout for entire testcase */
#define TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 20)

/* If number of peers not in config file, use this number */
#define DEFAULT_NUM_PEERS 2

/* test records to resolve */
#define TEST_DOMAIN "www.alice.bob.gnunet"
#define TEST_IP "127.0.0.1"
#define TEST_RECORD_NAME "www"

#define TEST_AUTHORITY_BOB "bob"
#define TEST_AUTHORITY_ALICE "alice"
#define TEST_ALICE_PSEU "carol"
#define TEST_EXPECTED_RESULT "alice.bob.gnunet"

#define KEYFILE_BOB "../namestore/zonefiles/HGU0A0VCU334DN7F2I9UIUMVQMM7JMSD142LIMNUGTTV9R0CF4EG.zkey"
#define KEYFILE_ALICE "../namestore/zonefiles/N0UJMP015AFUNR2BTNM3FKPBLG38913BL8IDMCO2H0A1LIB81960.zkey"

/* Globals */

/**
 * Directory to store temp data in, defined in config file
 */
static char *test_directory;

static struct GNUNET_TESTING_PeerGroup *pg;

/* Task handle to use to schedule test failure */
GNUNET_SCHEDULER_TaskIdentifier die_task;

/* Global return value (0 for success, anything else for failure) */
static int ok;

static struct GNUNET_NAMESTORE_Handle *namestore_handle;

static struct GNUNET_GNS_Handle *gns_handle;

const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Check whether peers successfully shut down.
 */
static void
shutdown_callback (void *cls, const char *emsg)
{
  if (emsg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Error on shutdown! ret=%d\n", ok);
    if (ok == 0)
      ok = 2;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "done(ret=%d)!\n", ok);
}

/**
 * Called when gns_get_authority finishes
 */
static void
process_auth_result(void* cls, const char* aname)
{
  GNUNET_GNS_disconnect(gns_handle);

  ok = 0;

  if (aname == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "get_authority test failed!\n");
    ok = 1;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s authority is %s\n", (char*)cls, aname);
    if (0 != strcmp(aname, TEST_EXPECTED_RESULT))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "get_authority test failed! (wanted: %s got: %s\n",
                  TEST_EXPECTED_RESULT, aname);
      ok = 1;
    }

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "get_authority test finished!\n");

  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Shutting down peer1!\n");
  GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
}

/**
 * Function scheduled to be run on the successful start of services
 * tries to shorten the name TEST_DOMAIN using gns
 */
static void
commence_testing (void *cls, int32_t success, const char *emsg)
{
  
  

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "disconnecting from namestore\n");
  GNUNET_NAMESTORE_disconnect(namestore_handle, GNUNET_YES);
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "connecting to gns\n");
  gns_handle = GNUNET_GNS_connect(cfg);

  if (NULL == gns_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "failed to connect to gns\n");
    ok = 1;
    return;
  }

  GNUNET_GNS_get_authority(gns_handle, TEST_DOMAIN, &process_auth_result,
                     TEST_DOMAIN);
  
}

/**
 * Continuation for the GNUNET_DHT_get_stop call, so that we don't shut
 * down the peers without freeing memory associated with GET request.
 */
static void
end_badly_cont (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{

  if (pg != NULL)
    GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
  GNUNET_SCHEDULER_cancel (die_task);
}

/**
 * Check if the get_handle is being used, if so stop the request.  Either
 * way, schedule the end_badly_cont function which actually shuts down the
 * test.
 */
static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failing test with error: `%s'!\n",
              (char *) cls);
  GNUNET_SCHEDULER_add_now (&end_badly_cont, NULL);
  ok = 1;
}

static void
do_shorten(void *cls, const struct GNUNET_PeerIdentity *id,
          const struct GNUNET_CONFIGURATION_Handle *_cfg,
          struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded our_pkey;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded alice_pkey;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded bob_pkey;
  struct GNUNET_CRYPTO_RsaPrivateKey *our_key;
  struct GNUNET_CRYPTO_RsaPrivateKey *alice_key;
  struct GNUNET_CRYPTO_RsaPrivateKey *bob_key;
  struct GNUNET_CRYPTO_ShortHashCode bob_hash;
  struct GNUNET_CRYPTO_ShortHashCode alice_hash;
  struct GNUNET_CRYPTO_RsaSignature *sig;
  char* our_keyfile;

  cfg = _cfg;

  GNUNET_SCHEDULER_cancel (die_task);

  /* put records into namestore */
  namestore_handle = GNUNET_NAMESTORE_connect(cfg);
  if (NULL == namestore_handle)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to connect to namestore\n");
    ok = -1;
    return;
  }

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (cfg, "gns",
                                                          "ZONEKEY",
                                                          &our_keyfile))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to get key from cfg\n");
    ok = -1;
    return;
  }

  our_key = GNUNET_CRYPTO_rsa_key_create_from_file (our_keyfile);
  GNUNET_free(our_keyfile);

  bob_key = GNUNET_CRYPTO_rsa_key_create_from_file (KEYFILE_BOB);
  alice_key = GNUNET_CRYPTO_rsa_key_create_from_file (KEYFILE_ALICE);
  
  GNUNET_CRYPTO_rsa_key_get_public (our_key, &our_pkey);
  GNUNET_CRYPTO_rsa_key_get_public (alice_key, &alice_pkey);
  GNUNET_CRYPTO_rsa_key_get_public (bob_key, &bob_pkey);

  struct GNUNET_NAMESTORE_RecordData rd;
  char* ip = TEST_IP;
  struct in_addr *web = GNUNET_malloc(sizeof(struct in_addr));
  rd.expiration = GNUNET_TIME_UNIT_FOREVER_ABS;
  GNUNET_assert(1 == inet_pton (AF_INET, ip, web));
  
  GNUNET_CRYPTO_short_hash(&bob_pkey, sizeof(bob_pkey), &bob_hash);

  rd.data_size = sizeof(struct GNUNET_CRYPTO_ShortHashCode);
  rd.data = &bob_hash;
  rd.record_type = GNUNET_GNS_RECORD_PKEY;
  
  /* put bob into our zone */
  GNUNET_NAMESTORE_record_create (namestore_handle,
                                  our_key,
                                  TEST_AUTHORITY_BOB,
                                  &rd,
                                  NULL,
                                  NULL);
  
  /* put alice into bobs zone */
  GNUNET_CRYPTO_short_hash(&alice_pkey, sizeof(alice_pkey), &alice_hash);
  rd.data = &alice_hash;
  sig = GNUNET_NAMESTORE_create_signature(bob_key, GNUNET_TIME_UNIT_FOREVER_ABS, TEST_AUTHORITY_ALICE,
                                          &rd, 1);

  GNUNET_NAMESTORE_record_put (namestore_handle,
                               &bob_pkey,
                               TEST_AUTHORITY_ALICE,
                               GNUNET_TIME_UNIT_FOREVER_ABS,
                               1,
                               &rd,
                               sig,
                               NULL,
                               NULL);

  /* put www A record and PSEU into alice's zone */

  rd.data_size = sizeof(struct in_addr);
  rd.data = web;
  rd.record_type = GNUNET_DNSPARSER_TYPE_A;
  sig = GNUNET_NAMESTORE_create_signature(alice_key,GNUNET_TIME_UNIT_FOREVER_ABS,  TEST_RECORD_NAME,
                                          &rd, 1);

  GNUNET_NAMESTORE_record_put (namestore_handle,
                               &alice_pkey,
                               TEST_RECORD_NAME,
                               GNUNET_TIME_UNIT_FOREVER_ABS,
                               1,
                               &rd,
                               sig,
                               NULL,
                               NULL);

  rd.data_size = strlen(TEST_ALICE_PSEU);
  rd.data = TEST_ALICE_PSEU;
  rd.record_type = GNUNET_GNS_RECORD_PSEU;
  GNUNET_free(sig);

  sig = GNUNET_NAMESTORE_create_signature(alice_key,GNUNET_TIME_UNIT_FOREVER_ABS,  "",
                                          &rd, 1);

  GNUNET_NAMESTORE_record_put (namestore_handle,
                               &alice_pkey,
                               "",
                               GNUNET_TIME_UNIT_FOREVER_ABS,
                               1,
                               &rd,
                               sig,
                               &commence_testing,
                               NULL);

  GNUNET_free(sig);

}

static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  cfg = c;
   /* Get path from configuration file */
  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "paths", "servicehome",
                                             &test_directory))
  {
    ok = 404;
    return;
  }

    
  /* Set up a task to end testing if peer start fails */
  die_task =
      GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly,
                                    "didn't start all daemons in reasonable amount of time!!!");
  
  /* Start alice */
  pg = GNUNET_TESTING_daemons_start(cfg, 1, 1, 1, TIMEOUT,
                                    NULL, NULL, &do_shorten, NULL,
                                    NULL, NULL, NULL);
}

static int
check ()
{
  int ret;

  /* Arguments for GNUNET_PROGRAM_run */
  char *const argv[] = { "test-gns-simple-get-authority", /* Name to give running binary */
    "-c",
    "test_gns_simple_lookup.conf",       /* Config file to use */
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  /* Run the run function as a new program */
  ret =
      GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv,
                          "test-gns-simple-get-authority", "nohelp", options, &run,
                          &ok);
  if (ret != GNUNET_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "`test-gns-simple-get-authority': Failed with error code %d\n", ret);
  }
  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-gns-simple-lookup",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();
  /**
   * Need to remove base directory, subdirectories taken care
   * of by the testing framework.
   */
  return ret;
}

/* end of test_gns_twopeer.c */
