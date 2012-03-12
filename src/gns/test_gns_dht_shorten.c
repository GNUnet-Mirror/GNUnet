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
 * @file gns/test_gns_twopeer.c
 * @brief base testcase for testing DHT service with
 *        two running peers.
 *
 * This testcase starts peers using the GNUNET_TESTING_daemons_start
 * function call.  On peer start, connects to the peers DHT service
 * by calling GNUNET_DHT_connected.  Once notified about all peers
 * being started (by the peers_started_callback function), calls
 * GNUNET_TESTING_connect_topology, which connects the peers in a
 * "straight line" topology.  On notification that all peers have
 * been properly connected, calls the do_get function which initiates
 * a GNUNET_DHT_get from the *second* peer. Once the GNUNET_DHT_get
 * function starts, runs the do_put function to insert data at the first peer.
 *   If the GET is successful, schedules finish_testing
 * to stop the test and shut down peers.  If GET is unsuccessful
 * after GET_TIMEOUT seconds, prints an error message and shuts down
 * the peers.
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
#define TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 10)

/* If number of peers not in config file, use this number */
#define DEFAULT_NUM_PEERS 2

/* test records to resolve */
#define TEST_DOMAIN "www.alice.bob.gnunet"
#define TEST_IP "127.0.0.1"
#define TEST_RECORD_NAME "www"

#define TEST_AUTHORITY_NAME "bob"
#define TEST_AUTHORITY_ALICE "alice"
#define TEST_ALICE_PSEU "carol"
#define TEST_EXPECTED_RESULT "www.carol.gnunet"

#define DHT_OPERATION_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)

/* Globals */

/**
 * Directory to store temp data in, defined in config file
 */
static char *test_directory;

struct GNUNET_TESTING_Daemon *d1;


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


/**
 * Called when gns shorten finishes
 */
static void
process_shorten_result(void* cls, const char* sname)
{
  GNUNET_GNS_disconnect(gns_handle);

  ok = 0;

  if (sname == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "shorten test failed!\n");
    ok = 1;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s shortened to %s\n", (char*)cls, sname);
    if (0 != strcmp(sname, TEST_EXPECTED_RESULT))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "shorten test failed! (wanted: %s got: %s\n",
                  (char*)cls, sname);
      ok = 1;
    }

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "shorten test succeeded!\n");

  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Shutting down peer1!\n");
  GNUNET_TESTING_daemon_stop (d1, TIMEOUT, &shutdown_callback, NULL,
                              GNUNET_YES, GNUNET_NO);
}

/**
 * Function scheduled to be run on the successful start of services
 * tries to look up the dns record for TEST_DOMAIN
 */
static void
commence_testing (void* cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_NAMESTORE_disconnect(namestore_handle, GNUNET_YES);

  gns_handle = GNUNET_GNS_connect(cfg);

  if (NULL == gns_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to connect to GNS!\n");
    ok = 1;
  }

  GNUNET_GNS_shorten(gns_handle, TEST_DOMAIN, &process_shorten_result,
                     TEST_DOMAIN);
}

/**
 * Continuation for the GNUNET_DHT_get_stop call, so that we don't shut
 * down the peers without freeing memory associated with GET request.
 */
static void
end_badly_cont (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{

  if (d1 != NULL)
    GNUNET_TESTING_daemon_stop (d1, TIMEOUT, &shutdown_callback, NULL,
                                GNUNET_YES, GNUNET_NO);
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
put_www_dht(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNSNameRecordBlock *nrb;
  GNUNET_HashCode name_hash;
  GNUNET_HashCode xor_hash;
  GNUNET_HashCode zone_hash;
  uint32_t rd_payload_length;
  char* nrb_data = NULL;
  struct GNUNET_CRYPTO_RsaSignature *sig;
  struct GNUNET_NAMESTORE_RecordData rd;
  char* ip = TEST_IP;
  struct in_addr *web = GNUNET_malloc(sizeof(struct in_addr));
  
  rd.expiration = GNUNET_TIME_absolute_get_forever ();
  GNUNET_assert(1 == inet_pton (AF_INET, ip, web));
  rd.data_size = sizeof(struct in_addr);
  rd.data = web;
  rd.record_type = GNUNET_DNSPARSER_TYPE_A;

  sig = GNUNET_NAMESTORE_create_signature(alice_key,
                                          GNUNET_TIME_absolute_get_forever(),
                                          TEST_RECORD_NAME,
                                          &rd, 1);
  rd_payload_length = GNUNET_NAMESTORE_records_get_size (1, &rd);
  nrb = GNUNET_malloc(rd_payload_length + strlen(TEST_RECORD_NAME) + 1
                      + sizeof(struct GNSNameRecordBlock));
  nrb->signature = *sig;
  nrb->public_key = alice_pkey;
  nrb->rd_count = htonl(1);
  memset(&nrb[1], 0, strlen(TEST_RECORD_NAME) + 1);
  memcpy(&nrb[1], TEST_RECORD_NAME, strlen(TEST_RECORD_NAME));
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
  GNUNET_CRYPTO_hash(TEST_RECORD_NAME, strlen(TEST_RECORD_NAME), &name_hash);
  GNUNET_CRYPTO_hash(&alice_pkey,
                     sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                     &zone_hash);
  GNUNET_CRYPTO_hash_xor(&zone_hash, &name_hash, &xor_hash);

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
put_alice_pseu_dht(void *cls, int32_t success, const char *emsg)
{
  struct GNSNameRecordBlock *nrb;
  GNUNET_HashCode name_hash;
  GNUNET_HashCode xor_hash;
  GNUNET_HashCode zone_hash;
  uint32_t rd_payload_length;
  char* nrb_data = NULL;
  struct GNUNET_CRYPTO_RsaSignature *sig;
  struct GNUNET_NAMESTORE_RecordData rd;
  
  rd.expiration = GNUNET_TIME_absolute_get_forever ();
  rd.data_size = strlen(TEST_ALICE_PSEU);
  rd.data = TEST_ALICE_PSEU;
  rd.record_type = GNUNET_GNS_RECORD_PSEU;

  sig = GNUNET_NAMESTORE_create_signature(alice_key,
                                          GNUNET_TIME_absolute_get_forever(),
                                          "+", //empty name for pseu
                                          &rd, 1);
  rd_payload_length = GNUNET_NAMESTORE_records_get_size (1, &rd);
  nrb = GNUNET_malloc(rd_payload_length + strlen("") + 1
                      + sizeof(struct GNSNameRecordBlock));
  nrb->signature = *sig;
  nrb->public_key = alice_pkey;
  nrb->rd_count = htonl(1);
  memset(&nrb[1], 0, strlen("+") + 1);
  memcpy(&nrb[1], "+", strlen("+"));
  nrb_data = (char*)&nrb[1];
  nrb_data += strlen("+") + 1;

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
  GNUNET_CRYPTO_hash("+", strlen("+"), &name_hash);
  GNUNET_CRYPTO_hash(&alice_pkey,
                     sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                     &zone_hash);
  GNUNET_CRYPTO_hash_xor(&zone_hash, &name_hash, &xor_hash);

  rd_payload_length += sizeof(struct GNSNameRecordBlock) +
    strlen("+") + 1;
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
  GNUNET_SCHEDULER_add_delayed(TIMEOUT, &put_www_dht, NULL);
}

static void
do_shorten(void *cls, const struct GNUNET_PeerIdentity *id,
          const struct GNUNET_CONFIGURATION_Handle *cfg,
          struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  
  char* my_keyfile;
  struct GNUNET_CRYPTO_RsaPrivateKey *my_key;
  GNUNET_HashCode bob_hash;
  GNUNET_HashCode alice_hash;
  struct GNUNET_CRYPTO_RsaSignature *sig;
  

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

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (cfg, "gns",
                                                          "ZONEKEY",
                                                          &my_keyfile))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to get key from cfg\n");
    ok = -1;
    return;
  }

  my_key = GNUNET_CRYPTO_rsa_key_create_from_file (my_keyfile);
  alice_key = GNUNET_CRYPTO_rsa_key_create ();
  bob_key = GNUNET_CRYPTO_rsa_key_create ();

  GNUNET_CRYPTO_rsa_key_get_public (alice_key, &alice_pkey);
  GNUNET_CRYPTO_rsa_key_get_public (bob_key, &bob_pkey);
  GNUNET_CRYPTO_hash(&bob_pkey, sizeof(bob_pkey), &bob_hash);
  GNUNET_CRYPTO_hash(&alice_pkey, sizeof(alice_pkey), &alice_hash);

  struct GNUNET_NAMESTORE_RecordData rd;
  rd.expiration = GNUNET_TIME_absolute_get_forever ();
  rd.data_size = sizeof(GNUNET_HashCode);
  rd.data = &bob_hash;
  rd.record_type = GNUNET_GNS_RECORD_PKEY;

  GNUNET_NAMESTORE_record_create (namestore_handle,
                                  my_key,
                                  TEST_AUTHORITY_NAME,
                                  &rd,
                                  NULL,
                                  NULL);
  
  rd.data = &alice_hash;

  sig = GNUNET_NAMESTORE_create_signature(bob_key,
                                          GNUNET_TIME_absolute_get_forever(),
                                          TEST_AUTHORITY_ALICE,
                                          &rd,
                                          1);

  GNUNET_NAMESTORE_record_put (namestore_handle,
                               &bob_pkey,
                               TEST_AUTHORITY_ALICE,
                               GNUNET_TIME_absolute_get_forever(),
                               1,
                               &rd,
                               sig,
                               &put_alice_pseu_dht,
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
  d1 = GNUNET_TESTING_daemon_start(cfg, TIMEOUT, GNUNET_NO, NULL, NULL, 0,
                                   NULL, NULL, NULL, &do_shorten, NULL);
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
