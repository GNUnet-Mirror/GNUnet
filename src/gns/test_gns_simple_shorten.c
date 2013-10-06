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

/* Timeout for entire testcase */
#define TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 20)

/* test records to resolve */
#define TEST_DOMAIN "www.alice.bob.gnu"
#define TEST_IP "127.0.0.1"
#define TEST_RECORD_NAME "www"

#define TEST_AUTHORITY_BOB "bob"
#define TEST_AUTHORITY_ALICE "alice"
#define TEST_ALICE_PSEU "carol"
#define TEST_EXPECTED_RESULT "www.carol.gnu"

#define KEYFILE_BOB "../namestore/zonefiles/HGU0A0VCU334DN7F2I9UIUMVQMM7JMSD142LIMNUGTTV9R0CF4EG.zkey"
#define KEYFILE_ALICE "../namestore/zonefiles/N0UJMP015AFUNR2BTNM3FKPBLG38913BL8IDMCO2H0A1LIB81960.zkey"


/* Task handle to use to schedule test failure */
GNUNET_SCHEDULER_TaskIdentifier die_task;

/* Global return value (0 for success, anything else for failure) */
static int ok;

static struct GNUNET_NAMESTORE_Handle *namestore_handle;

static struct GNUNET_GNS_Handle *gns_handle;

const struct GNUNET_CONFIGURATION_Handle *cfg;

struct GNUNET_CRYPTO_EccPublicSignKey priv_pkey;
struct GNUNET_CRYPTO_EccPublicSignKey short_pkey;
struct GNUNET_CRYPTO_EccPrivateKey *priv_key;
struct GNUNET_CRYPTO_EccPrivateKey *short_key;

struct GNUNET_CRYPTO_ShortHashCode priv_zone;
struct GNUNET_CRYPTO_ShortHashCode short_zone;


/**
 * Check if the get_handle is being used, if so stop the request.  Either
 * way, schedule the end_badly_cont function which actually shuts down the
 * test.
 */
static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  die_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_SCHEDULER_shutdown ();
  ok = 1;
}

void end_badly_now ()
{
  GNUNET_SCHEDULER_cancel (die_task);
  die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
}

static void shutdown_task (void *cls,
                           const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_GNS_disconnect(gns_handle);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Shutting down peer!\n");
  GNUNET_SCHEDULER_shutdown ();
}

/**
 * Called when gns shorten finishes
 */
static void
process_shorten_result(void* cls, const char* sname)
{

  if (GNUNET_SCHEDULER_NO_TASK != die_task)
  {
      GNUNET_SCHEDULER_cancel (die_task);
      die_task = GNUNET_SCHEDULER_NO_TASK;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Disconnecting from namestore\n");
  GNUNET_NAMESTORE_disconnect (namestore_handle);

  if (sname == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Shorten test failed!\n");
    ok = 1;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s shortened to %s\n", (char*)cls, sname);
    if (0 != strcmp(sname, TEST_EXPECTED_RESULT))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Shorten test failed! (wanted: %s got: %s\n",
                  (char*)cls, sname);
      ok = 1;
    }

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Shorten test succeeded!\n");
    ok = 0;
  }

  GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
}

/**
 * Function scheduled to be run on the successful start of services
 * tries to shorten the name TEST_DOMAIN using gns
 */
static void
commence_testing (void *cls, int32_t success, const char *emsg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connecting to gns\n");
  gns_handle = GNUNET_GNS_connect(cfg);
  if (NULL == gns_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to connect to gns\n");
    end_badly_now ();
    return;
  }

  GNUNET_assert (NULL != GNUNET_GNS_shorten (gns_handle, TEST_DOMAIN,
                      &priv_zone,
                      &short_zone,
                      &process_shorten_result,
                      TEST_DOMAIN));
}



void do_check (void *cls,
              const struct GNUNET_CONFIGURATION_Handle *ccfg,
              struct GNUNET_TESTING_Peer *peer)
{
  struct GNUNET_CRYPTO_EccPublicSignKey our_pkey;
  struct GNUNET_CRYPTO_EccPublicSignKey alice_pkey;
  struct GNUNET_CRYPTO_EccPublicSignKey bob_pkey;
  struct GNUNET_CRYPTO_EccPrivateKey *our_key;
  struct GNUNET_CRYPTO_EccPrivateKey *alice_key;
  struct GNUNET_CRYPTO_EccPrivateKey *bob_key;
  struct GNUNET_CRYPTO_ShortHashCode bob_hash;
  struct GNUNET_CRYPTO_ShortHashCode alice_hash;
  struct GNUNET_CRYPTO_EccSignature *sig;
  char* our_keyfile;
  char* private_keyfile;
  char* shorten_keyfile;

  cfg = ccfg;
  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Running test\n");


  /* put records into namestore */
  namestore_handle = GNUNET_NAMESTORE_connect(cfg);
  if (NULL == namestore_handle)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to connect to namestore\n");
    end_badly_now ();
    return;
  }

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (cfg, "gns",
                                                          "ZONEKEY",
                                                          &our_keyfile))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to get key from cfg\n");
    end_badly_now ();
    return;
  }

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (cfg, "gns",
                                                            "SHORTEN_ZONEKEY",
                                                            &shorten_keyfile))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
               "Failed to get shorten zone key from cfg\n");
    end_badly_now ();
    return;
  }

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (cfg, "gns",
                                                            "PRIVATE_ZONEKEY",
                                                            &private_keyfile))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
               "Failed to get private zone key from cfg\n");
    end_badly_now ();
    return;
  }

  our_key = GNUNET_CRYPTO_ecc_key_create_from_file (our_keyfile);
  GNUNET_free(our_keyfile);

  bob_key = GNUNET_CRYPTO_ecc_key_create_from_file (KEYFILE_BOB);
  alice_key = GNUNET_CRYPTO_ecc_key_create_from_file (KEYFILE_ALICE);
  priv_key = GNUNET_CRYPTO_ecc_key_create_from_file (private_keyfile);
  short_key = GNUNET_CRYPTO_ecc_key_create_from_file (shorten_keyfile);

  GNUNET_free(shorten_keyfile);
  GNUNET_free(private_keyfile);

  GNUNET_CRYPTO_ecc_key_get_public_for_signature (our_key, &our_pkey);
  GNUNET_CRYPTO_ecc_key_get_public_for_signature (alice_key, &alice_pkey);
  GNUNET_CRYPTO_ecc_key_get_public_for_signature (bob_key, &bob_pkey);
  GNUNET_CRYPTO_ecc_key_get_public_for_signature (priv_key, &priv_pkey);
  GNUNET_CRYPTO_ecc_key_get_public_for_signature (short_key, &short_pkey);

  GNUNET_CRYPTO_short_hash(&priv_pkey, sizeof(priv_pkey), &priv_zone);
  GNUNET_CRYPTO_short_hash(&short_pkey, sizeof(short_pkey), &short_zone);

  struct GNUNET_NAMESTORE_RecordData rd;
  char* ip = TEST_IP;
  struct in_addr *web = GNUNET_malloc(sizeof(struct in_addr));
  rd.expiration_time = UINT64_MAX;
  GNUNET_assert(1 == inet_pton (AF_INET, ip, web));

  GNUNET_CRYPTO_short_hash(&bob_pkey, sizeof(bob_pkey), &bob_hash);

  rd.data_size = sizeof(struct GNUNET_CRYPTO_ShortHashCode);
  rd.data = &bob_hash;
  rd.record_type = GNUNET_NAMESTORE_TYPE_PKEY;
  rd.flags = GNUNET_NAMESTORE_RF_NONE;

  /* put bob into our zone */
  GNUNET_NAMESTORE_record_put_by_authority (namestore_handle,
					    our_key,
					    TEST_AUTHORITY_BOB,
					    1,
					    &rd,
					    NULL,
					    NULL);

  /* put alice into bobs zone */
  GNUNET_CRYPTO_short_hash(&alice_pkey, sizeof(alice_pkey), &alice_hash);
  rd.data = &alice_hash;
  sig = GNUNET_NAMESTORE_create_signature(bob_key,
                                          GNUNET_TIME_UNIT_FOREVER_ABS,
                                          TEST_AUTHORITY_ALICE,
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
  GNUNET_free(sig);
  /* put www A record and PSEU into alice's zone */

  rd.data_size = sizeof(struct in_addr);
  rd.data = web;
  rd.record_type = GNUNET_DNSPARSER_TYPE_A;
  sig = GNUNET_NAMESTORE_create_signature(alice_key,
                                          GNUNET_TIME_UNIT_FOREVER_ABS,
                                          TEST_RECORD_NAME,
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

  rd.data_size = sizeof(struct GNUNET_CRYPTO_ShortHashCode);
  rd.data = &alice_hash;
  rd.record_type = GNUNET_NAMESTORE_TYPE_PKEY;
  GNUNET_free(sig);

  GNUNET_NAMESTORE_record_put_by_authority (namestore_handle,
					    our_key,
					    TEST_ALICE_PSEU,
					    1, &rd,
					    &commence_testing,
					    NULL);

  GNUNET_free(web);
  GNUNET_free(our_key);
  GNUNET_free(bob_key);
  GNUNET_free(alice_key);
  GNUNET_free(priv_key);
  GNUNET_free(short_key);

}


int
main (int argc, char *argv[])
{
  ok = 1;
  GNUNET_log_setup ("test-gns-simple-shorten",
                    "WARNING",
                    NULL);
  GNUNET_TESTING_peer_run ("test-gns-simple-shorten",
			   "test_gns_simple_lookup.conf",
			   &do_check, NULL);
  return ok;
}

/* end of test_gns_simple_shorten.c */
