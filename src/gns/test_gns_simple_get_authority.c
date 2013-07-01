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
 * @file gns/test_gns_simple_get_authority.c
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
#define TEST_DOMAIN "www.alice.bob.gads"
#define TEST_IP "127.0.0.1"
#define TEST_RECORD_NAME "www"

#define TEST_AUTHORITY_BOB "bob"
#define TEST_AUTHORITY_ALICE "alice"
#define TEST_ALICE_PSEU "carol"
#define TEST_EXPECTED_RESULT "alice.bob.gads"

#define KEYFILE_BOB "../namestore/zonefiles/HGU0A0VCU334DN7F2I9UIUMVQMM7JMSD142LIMNUGTTV9R0CF4EG.zkey"
#define KEYFILE_ALICE "../namestore/zonefiles/N0UJMP015AFUNR2BTNM3FKPBLG38913BL8IDMCO2H0A1LIB81960.zkey"

/* Globals */

/* Task handle to use to schedule test failure */
GNUNET_SCHEDULER_TaskIdentifier die_task;

/* Global return value (0 for success, anything else for failure) */
static int ok;

static struct GNUNET_NAMESTORE_Handle *namestore_handle;

static struct GNUNET_GNS_Handle *gns_handle;

const struct GNUNET_CONFIGURATION_Handle *cfg;


/**
 * Check if the get_handle is being used, if so stop the request.  Either
 * way, schedule the end_badly_cont function which actually shuts down the
 * test.
 */
static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  die_task = GNUNET_SCHEDULER_NO_TASK;
  if (NULL != gns_handle)
  {
    GNUNET_GNS_disconnect(gns_handle);
    gns_handle = NULL;
  }

  if (NULL != namestore_handle)
  {
    GNUNET_NAMESTORE_disconnect (namestore_handle);
    namestore_handle = NULL;
  }
  GNUNET_break (0);
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
 * Called when gns_get_authority finishes
 */
static void
process_auth_result(void* cls, const char* aname)
{

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Disconnecting from namestore\n");
  GNUNET_NAMESTORE_disconnect (namestore_handle);

  if (GNUNET_SCHEDULER_NO_TASK != die_task)
  {
      GNUNET_SCHEDULER_cancel (die_task);
      die_task = GNUNET_SCHEDULER_NO_TASK;
  }

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
    else
    {
      ok = 0;
    }

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "get_authority test finished!\n");

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
    end_badly_now();
    return;
  }

  GNUNET_GNS_get_authority(gns_handle, TEST_DOMAIN, &process_auth_result,
                     TEST_DOMAIN);
}



void do_check (void *cls,
              const struct GNUNET_CONFIGURATION_Handle *ccfg,
              struct GNUNET_TESTING_Peer *peer)
{
  struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded our_pkey;
  struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded alice_pkey;
  struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded bob_pkey;
  struct GNUNET_CRYPTO_EccPrivateKey *our_key;
  struct GNUNET_CRYPTO_EccPrivateKey *alice_key;
  struct GNUNET_CRYPTO_EccPrivateKey *bob_key;
  struct GNUNET_CRYPTO_ShortHashCode bob_hash;
  struct GNUNET_CRYPTO_ShortHashCode alice_hash;
  struct GNUNET_CRYPTO_EccSignature *sig;
  char* our_keyfile;

  cfg = ccfg;
  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Running test\n");

  /* put records into namestore */
  namestore_handle = GNUNET_NAMESTORE_connect(cfg);
  if (NULL == namestore_handle)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to connect to namestore\n");
    end_badly_now();
    return;
  }

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (cfg, "gns",
                                                          "ZONEKEY",
                                                          &our_keyfile))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to get key from cfg\n");
    end_badly_now();
    return;
  }

  our_key = GNUNET_CRYPTO_ecc_key_create_from_file (our_keyfile);
  GNUNET_free(our_keyfile);

  bob_key = GNUNET_CRYPTO_ecc_key_create_from_file (KEYFILE_BOB);
  alice_key = GNUNET_CRYPTO_ecc_key_create_from_file (KEYFILE_ALICE);

  GNUNET_CRYPTO_ecc_key_get_public (our_key, &our_pkey);
  GNUNET_CRYPTO_ecc_key_get_public (alice_key, &alice_pkey);
  GNUNET_CRYPTO_ecc_key_get_public (bob_key, &bob_pkey);

  struct GNUNET_NAMESTORE_RecordData rd;
  char* ip = TEST_IP;
  struct in_addr *web = GNUNET_malloc (sizeof(struct in_addr));
  rd.expiration_time = UINT64_MAX;
  GNUNET_assert (1 == inet_pton (AF_INET, ip, web));

  GNUNET_CRYPTO_short_hash(&bob_pkey, sizeof(bob_pkey), &bob_hash);

  rd.data_size = sizeof(struct GNUNET_CRYPTO_ShortHashCode);
  rd.data = &bob_hash;
  rd.record_type = GNUNET_GNS_RECORD_PKEY;
  rd.flags = GNUNET_NAMESTORE_RF_AUTHORITY;

  /* put bob into our zone */
  GNUNET_NAMESTORE_record_put_by_authority (namestore_handle,
					    our_key,
					    TEST_AUTHORITY_BOB,
					    1, &rd,
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

  GNUNET_free (sig);

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

  GNUNET_free (web);
  GNUNET_free (sig);
  GNUNET_CRYPTO_ecc_key_free (alice_key);
  GNUNET_CRYPTO_ecc_key_free (bob_key);
  GNUNET_CRYPTO_ecc_key_free (our_key);
}


int
main (int argc, char *argv[])
{
  ok = 1;
  GNUNET_log_setup ("test-gns-simple-get-authority",
                    "WARNING",
                    NULL);
  GNUNET_TESTING_peer_run ("test-gns-simple-get-authority",
			   "test_gns_simple_lookup.conf", 
			   &do_check, NULL);
  return ok;
}

/* end of test-gns-simple-get-authority.c */

