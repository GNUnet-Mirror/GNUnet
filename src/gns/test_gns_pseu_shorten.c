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
 * @file gns/test_gns_pseu_shorten.c
 * @brief base testcase for testing on the fly pseu import and shorten
 *
 */
#include "platform.h"
#include "gnunet_testing_lib-new.h"
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
#define TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 30)

/* If number of peers not in config file, use this number */
#define DEFAULT_NUM_PEERS 2

/* test records to resolve */
#define TEST_DOMAIN "www.alicewonderland.bobbuilder.gads"
#define TEST_IP "127.0.0.1"
#define TEST_RECORD_NAME "www"

#define TEST_PRIVATE_ZONE "private"
#define TEST_SHORTEN_ZONE "short"
#define TEST_AUTHORITY_BOB "bobbuilder"
#define TEST_AUTHORITY_ALICE "alicewonderland"
#define TEST_PSEU_ALICE "carol"
#define TEST_EXPECTED_RESULT "www.carol.short.private.gads"

#define DHT_OPERATION_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

#define KEYFILE_SHORTEN = "zonefiles/188JSUMKEF25GVU8TTV0PBNNN8JVCPUEDFV1UHJJU884JD25V0T0.zkey"
#define KEYFILE_PRIVATE = "zonefiles/OEFL7A4VEF1B40QLEMTG5D8G1CN6EN16QUSG5R2DT71GRJN34LSG.zkey"
#define KEYFILE_BOB "../namestore/zonefiles/HGU0A0VCU334DN7F2I9UIUMVQMM7JMSD142LIMNUGTTV9R0CF4EG.zkey"
#define KEYFILE_ALICE "../namestore/zonefiles/N0UJMP015AFUNR2BTNM3FKPBLG38913BL8IDMCO2H0A1LIB81960.zkey"

/* Globals */

/* Task handle to use to schedule test failure */
static GNUNET_SCHEDULER_TaskIdentifier die_task;

/* Global return value (0 for success, anything else for failure) */
static int ok;

static struct GNUNET_NAMESTORE_Handle *namestore_handle;

static struct GNUNET_GNS_Handle *gns_handle;

static struct GNUNET_DHT_Handle *dht_handle;

const struct GNUNET_CONFIGURATION_Handle *cfg;

struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded alice_pkey;
struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded bob_pkey;
struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded our_pkey;
struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded priv_pkey;
struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded short_pkey;
struct GNUNET_CRYPTO_RsaPrivateKey *alice_key;
struct GNUNET_CRYPTO_RsaPrivateKey *bob_key;
struct GNUNET_CRYPTO_RsaPrivateKey *our_key;
struct GNUNET_CRYPTO_RsaPrivateKey *priv_key;
struct GNUNET_CRYPTO_RsaPrivateKey *short_key;
struct GNUNET_CRYPTO_ShortHashCode alice_hash;
struct GNUNET_CRYPTO_ShortHashCode bob_hash;
struct GNUNET_CRYPTO_ShortHashCode our_zone;
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

  if (NULL != dht_handle)
  {
    GNUNET_DHT_disconnect (dht_handle);
    dht_handle = NULL;
  }

  GNUNET_break (0);
  GNUNET_SCHEDULER_shutdown ();
  ok = 1;
}

static void
end_badly_now ()
{
  GNUNET_SCHEDULER_cancel (die_task);
  die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
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

  if (NULL != gns_handle)
  {
    GNUNET_GNS_disconnect(gns_handle);
    gns_handle = NULL;
  }

  if (NULL != dht_handle)
  {
    GNUNET_DHT_disconnect (dht_handle);
    dht_handle = NULL;
  }

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
                  TEST_EXPECTED_RESULT, sname);
      ok = 1;
    }

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "shorten test succeeded!\n");
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Shutting down peer!\n");
  GNUNET_SCHEDULER_shutdown ();
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
      if (rd[i].record_type == GNUNET_GNS_RECORD_A)
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
  GNUNET_GNS_shorten_zone (gns_handle, TEST_DOMAIN,
                           &priv_zone,
                           &short_zone,
                           &our_zone,
                           &process_shorten_result,
                           TEST_DOMAIN);
}


/**
 * Function scheduled to be run on the successful start of services
 * tries to look up the dns record for TEST_DOMAIN
 */
static void
commence_testing (void *cls, int success)
{

  GNUNET_CRYPTO_rsa_key_free(our_key);
  GNUNET_CRYPTO_rsa_key_free(bob_key);
  GNUNET_CRYPTO_rsa_key_free(alice_key);

  GNUNET_NAMESTORE_disconnect (namestore_handle);
  namestore_handle = NULL;

  gns_handle = GNUNET_GNS_connect(cfg);
  if (NULL == gns_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to connect to GNS!\n");
  }

  GNUNET_GNS_lookup_zone (gns_handle, TEST_DOMAIN,
                          &our_zone,
                          GNUNET_GNS_RECORD_A,
                          GNUNET_NO,
                          short_key,
                          &on_lookup_result, TEST_DOMAIN);
}


static void
put_pseu_dht(void *cls, int success)
{
  struct GNSNameRecordBlock *nrb;
  struct GNUNET_CRYPTO_ShortHashCode name_hash;
  struct GNUNET_CRYPTO_ShortHashCode zone_hash;
  struct GNUNET_HashCode xor_hash;
  struct GNUNET_HashCode name_hash_double;
  struct GNUNET_HashCode zone_hash_double;
  uint32_t rd_payload_length;
  char* nrb_data = NULL;
  struct GNUNET_CRYPTO_RsaSignature *sig;
  struct GNUNET_NAMESTORE_RecordData rd;
  
  memset (&rd, 0, sizeof (struct GNUNET_NAMESTORE_RecordData));
  rd.expiration_time = GNUNET_TIME_UNIT_FOREVER_ABS.abs_value;
  rd.data_size = strlen(TEST_PSEU_ALICE)+1;
  rd.data = TEST_PSEU_ALICE;
  rd.record_type = GNUNET_GNS_RECORD_PSEU;
  rd.flags = 0;

  sig = GNUNET_NAMESTORE_create_signature(alice_key,
                                           GNUNET_TIME_UNIT_FOREVER_ABS,
                                           "+",
                                           &rd, 1);

  GNUNET_assert (NULL != sig);

  GNUNET_break (GNUNET_OK == GNUNET_NAMESTORE_verify_signature (&alice_pkey,
                                                                 GNUNET_TIME_UNIT_FOREVER_ABS,
                                                                 "+",
                                                                 1,
                                                                 &rd,
                                                                 sig));
  rd_payload_length = GNUNET_NAMESTORE_records_get_size (1, &rd);
  nrb = GNUNET_malloc(rd_payload_length + strlen("+") + 1
                      + sizeof(struct GNSNameRecordBlock));
  nrb->signature = *sig;
  nrb->public_key = alice_pkey;
  nrb->rd_count = htonl(1);
  memset(&nrb[1], 0, strlen("+") + 1);
  strcpy((char*)&nrb[1], "+");
  nrb_data = (char*)&nrb[1];
  nrb_data += strlen("+") + 1;

  if (-1 == GNUNET_NAMESTORE_records_serialize (1,
                                                &rd,
                                                rd_payload_length,
                                                nrb_data))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Record serialization failed!\n");
    ok = 3;
    GNUNET_CRYPTO_rsa_key_free(our_key);
    GNUNET_CRYPTO_rsa_key_free(bob_key);
    GNUNET_CRYPTO_rsa_key_free(alice_key);
    GNUNET_free(sig);
    GNUNET_free (nrb);
    end_badly_now ();
    return;
  }
  GNUNET_CRYPTO_short_hash("+", strlen("+"), &name_hash);
  GNUNET_CRYPTO_short_hash(&alice_pkey,
                     sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                     &zone_hash);

  GNUNET_CRYPTO_short_hash_double(&name_hash, &name_hash_double);
  GNUNET_CRYPTO_short_hash_double(&zone_hash, &zone_hash_double);
  GNUNET_CRYPTO_hash_xor(&zone_hash_double, &name_hash_double, &xor_hash);

  rd_payload_length += sizeof(struct GNSNameRecordBlock) +
    strlen("+") + 1;

  GNUNET_DHT_put (dht_handle, &xor_hash,
                  0,
                  GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,
                  GNUNET_BLOCK_TYPE_GNS_NAMERECORD,
                  rd_payload_length,
                  (char*)nrb,
                  GNUNET_TIME_UNIT_FOREVER_ABS,
                  DHT_OPERATION_TIMEOUT,
                  &commence_testing,
                  NULL);
  
  GNUNET_free(sig);
  GNUNET_free (nrb);
}

static void
put_www_dht(void *cls, int success)
{
  struct GNSNameRecordBlock *nrb;
  struct GNUNET_CRYPTO_ShortHashCode name_hash;
  struct GNUNET_CRYPTO_ShortHashCode zone_hash;
  struct GNUNET_HashCode xor_hash;
  struct GNUNET_HashCode name_hash_double;
  struct GNUNET_HashCode zone_hash_double;
  uint32_t rd_payload_length;
  char* nrb_data = NULL;
  struct GNUNET_CRYPTO_RsaSignature *sig;
  struct GNUNET_NAMESTORE_RecordData rd;
  char* ip = TEST_IP;
  struct in_addr *web = GNUNET_malloc(sizeof(struct in_addr));
  
  rd.expiration_time = UINT64_MAX;
  GNUNET_assert(1 == inet_pton (AF_INET, ip, web));
  rd.data_size = sizeof(struct in_addr);
  rd.data = web;
  rd.record_type = GNUNET_DNSPARSER_TYPE_A;
  rd.flags = GNUNET_NAMESTORE_RF_AUTHORITY;
  
  sig = GNUNET_NAMESTORE_create_signature(alice_key,
                                          GNUNET_TIME_UNIT_FOREVER_ABS,
                                          TEST_RECORD_NAME,
                                          &rd, 1);
  
  GNUNET_break (GNUNET_OK == GNUNET_NAMESTORE_verify_signature (&alice_pkey,
                                                                 GNUNET_TIME_UNIT_FOREVER_ABS,
                                                                 TEST_RECORD_NAME,
                                                                 1,
                                                                 &rd,
                                                                 sig));
  rd_payload_length = GNUNET_NAMESTORE_records_get_size (1, &rd);
  nrb = GNUNET_malloc(rd_payload_length + strlen(TEST_RECORD_NAME) + 1
                      + sizeof(struct GNSNameRecordBlock));
  nrb->signature = *sig;
  nrb->public_key = alice_pkey;
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
    GNUNET_CRYPTO_rsa_key_free(our_key);
    GNUNET_CRYPTO_rsa_key_free(bob_key);
    GNUNET_CRYPTO_rsa_key_free(alice_key);
    GNUNET_free (sig);
    GNUNET_free(web);
    GNUNET_free (nrb);
    end_badly_now();
    return;
  }
  GNUNET_CRYPTO_short_hash(TEST_RECORD_NAME, strlen(TEST_RECORD_NAME), &name_hash);
  GNUNET_CRYPTO_short_hash(&alice_pkey,
                     sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                     &zone_hash);
  GNUNET_CRYPTO_short_hash_double(&zone_hash, &zone_hash_double);
  GNUNET_CRYPTO_short_hash_double(&name_hash, &name_hash_double);
  GNUNET_CRYPTO_hash_xor(&zone_hash_double, &name_hash_double, &xor_hash);

  rd_payload_length += sizeof(struct GNSNameRecordBlock) +
    strlen(TEST_RECORD_NAME) + 1;

  GNUNET_DHT_put (dht_handle, &xor_hash,
                  0,
                  GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,
                  GNUNET_BLOCK_TYPE_GNS_NAMERECORD,
                  rd_payload_length,
                  (char*)nrb,
		  GNUNET_TIME_UNIT_FOREVER_ABS,
                  DHT_OPERATION_TIMEOUT,
                  &put_pseu_dht,
                  NULL);
  GNUNET_free (sig);
  GNUNET_free (web);
  GNUNET_free (nrb);
}


static void
put_pkey_dht(void *cls, int32_t success, const char *emsg)
{
  struct GNSNameRecordBlock *nrb;
  struct GNUNET_CRYPTO_ShortHashCode name_hash;
  struct GNUNET_CRYPTO_ShortHashCode zone_hash;
  struct GNUNET_HashCode xor_hash;
  struct GNUNET_HashCode name_hash_double;
  struct GNUNET_HashCode zone_hash_double;
  uint32_t rd_payload_length;
  char* nrb_data = NULL;
  struct GNUNET_CRYPTO_RsaSignature *sig;
  struct GNUNET_NAMESTORE_RecordData rd;
  
  rd.expiration_time = UINT64_MAX;
  rd.data_size = sizeof(struct GNUNET_CRYPTO_ShortHashCode);
  rd.data = &alice_hash;
  rd.record_type = GNUNET_GNS_RECORD_PKEY;
  rd.flags = GNUNET_NAMESTORE_RF_AUTHORITY;
  
  sig = GNUNET_NAMESTORE_create_signature(bob_key,
                                          GNUNET_TIME_UNIT_FOREVER_ABS,
                                          TEST_AUTHORITY_ALICE,
                                          &rd,
                                          1);

  rd_payload_length = GNUNET_NAMESTORE_records_get_size (1, &rd);
  nrb = GNUNET_malloc(rd_payload_length + strlen(TEST_AUTHORITY_ALICE) + 1
                      + sizeof(struct GNSNameRecordBlock));
  nrb->signature = *sig;
  nrb->public_key = bob_pkey;
  nrb->rd_count = htonl(1);
  memset(&nrb[1], 0, strlen(TEST_AUTHORITY_ALICE) + 1);
  strcpy((char*)&nrb[1], TEST_AUTHORITY_ALICE);
  nrb_data = (char*)&nrb[1];
  nrb_data += strlen(TEST_AUTHORITY_ALICE) + 1;

  if (-1 == GNUNET_NAMESTORE_records_serialize (1,
                                                &rd,
                                                rd_payload_length,
                                                nrb_data))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Record serialization failed!\n");
    ok = 3;
    
    GNUNET_CRYPTO_rsa_key_free (our_key);
    GNUNET_CRYPTO_rsa_key_free (bob_key);
    GNUNET_CRYPTO_rsa_key_free (alice_key);
    GNUNET_free (sig);
    GNUNET_free (nrb);
    end_badly_now ();
    return;
  }


  GNUNET_CRYPTO_short_hash(TEST_AUTHORITY_ALICE,
                     strlen(TEST_AUTHORITY_ALICE), &name_hash);
  GNUNET_CRYPTO_short_hash(&bob_pkey,
                     sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                     &zone_hash);
  GNUNET_CRYPTO_short_hash_double(&zone_hash, &zone_hash_double);
  GNUNET_CRYPTO_short_hash_double(&name_hash, &name_hash_double);
  GNUNET_CRYPTO_hash_xor(&zone_hash_double, &name_hash_double, &xor_hash); 

  rd_payload_length += sizeof(struct GNSNameRecordBlock) +
    strlen(TEST_AUTHORITY_ALICE) + 1;
  GNUNET_DHT_put (dht_handle, &xor_hash,
                  0,
                  GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,
                  GNUNET_BLOCK_TYPE_GNS_NAMERECORD,
                  rd_payload_length,
                  (char*)nrb,
                  GNUNET_TIME_UNIT_FOREVER_ABS,
                  DHT_OPERATION_TIMEOUT,
                  &put_www_dht,
                  NULL);
  GNUNET_free (sig);
  GNUNET_free (nrb);
}

static void
fin_init_zone (void *cls, int32_t success, const char *emsg)
{
  struct GNUNET_NAMESTORE_RecordData rd;
  rd.expiration_time = UINT64_MAX;
  rd.data_size = sizeof(struct GNUNET_CRYPTO_ShortHashCode);
  rd.data = &bob_hash;
  rd.record_type = GNUNET_GNS_RECORD_PKEY;
  rd.flags = GNUNET_NAMESTORE_RF_AUTHORITY;
  
  GNUNET_NAMESTORE_record_create (namestore_handle,
                                  our_key,
                                  TEST_AUTHORITY_BOB,
                                  &rd,
                                  &put_pkey_dht,
                                  NULL);

}

static void
cont_init_zone (void *cls, int32_t success, const char *emsg)
{

  struct GNUNET_NAMESTORE_RecordData rd;
  rd.expiration_time = UINT64_MAX;
  rd.data_size = sizeof(struct GNUNET_CRYPTO_ShortHashCode);
  rd.data = &short_zone;
  rd.record_type = GNUNET_GNS_RECORD_PKEY;
  rd.flags = GNUNET_NAMESTORE_RF_AUTHORITY;

  GNUNET_NAMESTORE_record_create (namestore_handle,
                                  priv_key,
                                  TEST_SHORTEN_ZONE,
                                  &rd,
                                  &fin_init_zone,
                                  NULL);
}

static void
do_check (void *cls,
          const struct GNUNET_CONFIGURATION_Handle *ccfg,
          struct GNUNET_TESTING_Peer *peer)
{
  char* private_keyfile;
  char* shorten_keyfile;
  char* our_keyfile;
  
  cfg = ccfg;
  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);

  /* put records into namestore */
  namestore_handle = GNUNET_NAMESTORE_connect(cfg);
  if (NULL == namestore_handle)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to connect to namestore\n");
    end_badly_now();
    return;
  }
  
  /* dht */
  dht_handle = GNUNET_DHT_connect(cfg, 1);
  if (NULL == dht_handle)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to connect to dht\n");
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
  
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (cfg, "gns",
                                                          "SHORTEN_ZONEKEY",
                                                          &shorten_keyfile))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
               "Failed to get shorten zone key from cfg\n");
    end_badly_now();
    return;
  }
  
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (cfg, "gns",
                                                          "PRIVATE_ZONEKEY",
                                                          &private_keyfile))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
               "Failed to get private zone key from cfg\n");
    end_badly_now();
    return;
  }
  our_key = GNUNET_CRYPTO_rsa_key_create_from_file (our_keyfile);
  priv_key = GNUNET_CRYPTO_rsa_key_create_from_file (private_keyfile);
  short_key = GNUNET_CRYPTO_rsa_key_create_from_file (shorten_keyfile);
  bob_key = GNUNET_CRYPTO_rsa_key_create_from_file (KEYFILE_BOB);
  alice_key = GNUNET_CRYPTO_rsa_key_create_from_file (KEYFILE_ALICE);
  
  GNUNET_free(our_keyfile);
  GNUNET_free(shorten_keyfile);
  GNUNET_free(private_keyfile);

  GNUNET_CRYPTO_rsa_key_get_public (our_key, &our_pkey);
  GNUNET_CRYPTO_rsa_key_get_public (priv_key, &priv_pkey);
  GNUNET_CRYPTO_rsa_key_get_public (short_key, &short_pkey);
  GNUNET_CRYPTO_rsa_key_get_public (bob_key, &bob_pkey);
  GNUNET_CRYPTO_rsa_key_get_public (alice_key, &alice_pkey);
  GNUNET_CRYPTO_short_hash(&bob_pkey, sizeof(bob_pkey), &bob_hash);
  GNUNET_CRYPTO_short_hash(&alice_pkey, sizeof(alice_pkey), &alice_hash);
  GNUNET_CRYPTO_short_hash(&our_pkey, sizeof(our_pkey), &our_zone);
  GNUNET_CRYPTO_short_hash(&priv_pkey, sizeof(priv_pkey), &priv_zone);
  GNUNET_CRYPTO_short_hash(&short_pkey, sizeof(short_pkey), &short_zone);
  
  struct GNUNET_NAMESTORE_RecordData rd;
  rd.expiration_time = UINT64_MAX;
  rd.data_size = sizeof(struct GNUNET_CRYPTO_ShortHashCode);
  rd.data = &priv_zone;
  rd.record_type = GNUNET_GNS_RECORD_PKEY;
  rd.flags = GNUNET_NAMESTORE_RF_AUTHORITY;

  GNUNET_NAMESTORE_record_create (namestore_handle,
                                  our_key,
                                  TEST_PRIVATE_ZONE,
                                  &rd,
                                  &cont_init_zone,
                                  NULL);
}

int
main (int argc, char *argv[])
{
  ok = 1;

  GNUNET_log_setup ("test-gns-pseu-shorten",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  GNUNET_TESTING_peer_run ("test-gns-pseu-shorten", "test_gns_simple_lookup.conf", &do_check, NULL);
  return ok;
}

/* end of test_gns_pseu_shorten.c */
