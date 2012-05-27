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
 * @file gns/test_gns_dht_delegated_lookup.c
 * @brief test for record lookup via DHT
 *
 */
#include "platform.h"
#include "gnunet_testing_lib.h"
#include "gnunet_core_service.h"
#include "block_gns.h"
#include "gnunet_signatures.h"
#include "gnunet_namestore_service.h"
#include "../namestore/namestore.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_gns_service.h"

/* DEFINES */
#define VERBOSE GNUNET_YES

/* Timeout for entire testcase */
#define TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 20)

/* If number of peers not in config file, use this number */
#define DEFAULT_NUM_PEERS 2

/* test records to resolve */
#define TEST_DOMAIN "www.bob.gnunet"
#define TEST_IP "127.0.0.1"
#define TEST_RECORD_NAME "www"

#define TEST_AUTHORITY_NAME "bob"

#define DHT_OPERATION_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)

#define KEYFILE_BOB "../namestore/zonefiles/HGU0A0VCU334DN7F2I9UIUMVQMM7JMSD142LIMNUGTTV9R0CF4EG.zkey"

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

static struct GNUNET_DHT_Handle *dht_handle;

const struct GNUNET_CONFIGURATION_Handle *cfg;

struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded alice_pkey;
struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded bob_pkey;
struct GNUNET_CRYPTO_RsaPrivateKey *alice_key;
struct GNUNET_CRYPTO_RsaPrivateKey *bob_key;

/**
 * Check whether peers successfully shut down.
 */
void
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


static void
on_lookup_result(void *cls, uint32_t rd_count,
                 const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct in_addr a;
  int i;
  char* addr;
  
  if (rd_count == 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Lookup failed, rp_filtering?\n");
    ok = 2;
  }
  else
  {
    ok = 1;
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "name: %s\n", (char*)cls);
    for (i=0; i<rd_count; i++)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "type: %d\n", rd[i].record_type);
      if (rd[i].record_type == GNUNET_GNS_RECORD_TYPE_A)
      {
        memcpy(&a, rd[i].data, sizeof(a));
        addr = inet_ntoa(a);
        GNUNET_log (GNUNET_ERROR_TYPE_INFO, "address: %s\n", addr);
        if (0 == strcmp(addr, TEST_IP))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                    "%s correctly resolved to %s!\n", TEST_DOMAIN, addr);
          ok = 0;
        }
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No resolution!\n");
      }
    }
  }
  GNUNET_GNS_disconnect(gns_handle);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Shutting down peer1!\n");
  //GNUNET_TESTING_daemon_stop (d1, TIMEOUT, &shutdown_callback, NULL,
  //                            GNUNET_YES, GNUNET_NO);
  GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
}


/**
 * Function scheduled to be run on the successful start of services
 * tries to look up the dns record for TEST_DOMAIN
 */
static void
commence_testing (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_NAMESTORE_disconnect(namestore_handle, GNUNET_YES);

  gns_handle = GNUNET_GNS_connect(cfg);

  if (NULL == gns_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to connect to GNS!\n");
  }

  GNUNET_GNS_lookup(gns_handle, TEST_DOMAIN, GNUNET_GNS_RECORD_TYPE_A,
                    &on_lookup_result, TEST_DOMAIN);
}

/**
 * Continuation for the GNUNET_DHT_get_stop call, so that we don't shut
 * down the peers without freeing memory associated with GET request.
 */
static void
end_badly_cont (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{

  if (pg != NULL) {
    GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
  }
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
put_dht(void *cls, int32_t success, const char *emsg)
{
  struct GNSNameRecordBlock *nrb;
  struct GNUNET_CRYPTO_ShortHashCode name_hash;
  struct GNUNET_CRYPTO_ShortHashCode zone_hash;
  GNUNET_HashCode xor_hash;
  GNUNET_HashCode name_hash_double;
  GNUNET_HashCode zone_hash_double;
  uint32_t rd_payload_length;
  char* nrb_data = NULL;
  struct GNUNET_CRYPTO_RsaSignature *sig;
  struct GNUNET_NAMESTORE_RecordData rd;
  char* ip = TEST_IP;
  struct in_addr *web = GNUNET_malloc(sizeof(struct in_addr));
  
  rd.expiration = GNUNET_TIME_UNIT_FOREVER_ABS;
  GNUNET_assert(1 == inet_pton (AF_INET, ip, web));
  rd.data_size = sizeof(struct in_addr);
  rd.data = web;
  rd.record_type = GNUNET_DNSPARSER_TYPE_A;

  sig = GNUNET_NAMESTORE_create_signature(bob_key, GNUNET_TIME_UNIT_FOREVER_ABS, TEST_RECORD_NAME,
                                          &rd, 1);
  rd_payload_length = GNUNET_NAMESTORE_records_get_size (1, &rd);
  nrb = GNUNET_malloc(rd_payload_length + strlen(TEST_RECORD_NAME) + 1
                      + sizeof(struct GNSNameRecordBlock));
  nrb->signature = *sig;
  nrb->public_key = bob_pkey;
  nrb->rd_count = htonl(1);
  memset(&nrb[1], 0, strlen(TEST_RECORD_NAME) + 1);
  strcpy((char*)&nrb[1], TEST_RECORD_NAME);
  nrb_data = (char*)&nrb[1];
  nrb_data += strlen(TEST_RECORD_NAME) + 1;

  if (-1 == GNUNET_NAMESTORE_records_serialize (1,
                                                &rd,
                                                rd_payload_length,
                                                nrb_data))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Record serialization failed!\n");
    ok = 3;
    GNUNET_free (nrb);
    return;
  }
  GNUNET_CRYPTO_short_hash(TEST_RECORD_NAME, strlen(TEST_RECORD_NAME), &name_hash);
  GNUNET_CRYPTO_short_hash(&bob_pkey,
                     sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                     &zone_hash);
  GNUNET_CRYPTO_short_hash_double(&zone_hash, &zone_hash_double);
  GNUNET_CRYPTO_short_hash_double(&name_hash, &name_hash_double);
  GNUNET_CRYPTO_hash_xor(&zone_hash_double, &name_hash_double, &xor_hash);

  rd_payload_length += sizeof(struct GNSNameRecordBlock) +
    strlen(TEST_RECORD_NAME) + 1;
  GNUNET_DHT_put (dht_handle, &xor_hash,
                  0,
                  GNUNET_DHT_RO_NONE,
                  GNUNET_BLOCK_TYPE_GNS_NAMERECORD,
                  rd_payload_length,
                  (char*)nrb,
                  rd.expiration,
                  DHT_OPERATION_TIMEOUT,
                  NULL,
                  NULL);
  GNUNET_free (nrb);
  GNUNET_SCHEDULER_add_delayed(TIMEOUT, &commence_testing, NULL);
}

static void
do_lookup(void *cls, const struct GNUNET_PeerIdentity *id,
          const struct GNUNET_CONFIGURATION_Handle *_cfg,
          struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  
  
  char* alice_keyfile;
  struct GNUNET_CRYPTO_ShortHashCode bob_hash;
  
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
  
  /* dht */
  dht_handle = GNUNET_DHT_connect(cfg, 1);
  if (NULL == dht_handle)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to connect to dht\n");
    ok = -1;
    return;
  }

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (cfg, "gns",
                                                          "ZONEKEY",
                                                          &alice_keyfile))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to get key from cfg\n");
    ok = -1;
    return;
  }

  alice_key = GNUNET_CRYPTO_rsa_key_create_from_file (alice_keyfile);
  bob_key = GNUNET_CRYPTO_rsa_key_create_from_file (KEYFILE_BOB);
  
  GNUNET_free(alice_keyfile);

  GNUNET_CRYPTO_rsa_key_get_public (alice_key, &alice_pkey);
  GNUNET_CRYPTO_rsa_key_get_public (bob_key, &bob_pkey);
  GNUNET_CRYPTO_short_hash(&bob_pkey, sizeof(bob_pkey), &bob_hash);

  struct GNUNET_NAMESTORE_RecordData rd;
  rd.expiration = GNUNET_TIME_UNIT_FOREVER_ABS;
  rd.data_size = sizeof(struct GNUNET_CRYPTO_ShortHashCode);
  rd.data = &bob_hash;
  rd.record_type = GNUNET_GNS_RECORD_PKEY;

  GNUNET_NAMESTORE_record_create (namestore_handle,
                                  alice_key,
                                  TEST_AUTHORITY_NAME,
                                  &rd,
                                  &put_dht,
                                  NULL);

  

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
  //d1 = GNUNET_TESTING_daemon_start(cfg, TIMEOUT, GNUNET_NO, NULL, NULL, 0,
  //                                 NULL, NULL, NULL, &do_lookup, NULL);
  pg = GNUNET_TESTING_daemons_start(cfg, 1, 1, 1, TIMEOUT,
                               NULL, NULL, &do_lookup, NULL, NULL, NULL, NULL);
}

static int
check ()
{
  int ret;

  /* Arguments for GNUNET_PROGRAM_run */
  char *const argv[] = { "test-gns-dht-delegated-lookup", /* Name to give running binary */
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
                          "test-gns-dht-delegated-lookup", "nohelp", options, &run,
                          &ok);
  if (ret != GNUNET_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "`test-gns-dht-delegated-lookup': Failed with error code %d\n", ret);
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
