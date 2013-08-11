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
 * @file gns/test_gns_simple_mx_lookup.c
 * @brief base testcase for testing GNS MX lookups
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
#define TEST_DOMAIN "bob.gads"
#define TEST_IP "127.0.0.1"
#define TEST_RECORD_NAME "mail"
#define TEST_MX_NAME "mail.+"
#define TEST_EXPECTED_MX "mail.bob.gads"

#define TEST_AUTHORITY_NAME "bob"

#define KEYFILE_BOB "../namestore/zonefiles/HGU0A0VCU334DN7F2I9UIUMVQMM7JMSD142LIMNUGTTV9R0CF4EG.zkey"

/* Task handle to use to schedule test failure */
static GNUNET_SCHEDULER_TaskIdentifier die_task;

/* Global return value (0 for success, anything else for failure) */
static int ok;

static struct GNUNET_NAMESTORE_Handle *namestore_handle;

static struct GNUNET_GNS_Handle *gns_handle;

static const struct GNUNET_CONFIGURATION_Handle *cfg;


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


static void
end_badly_now ()
{
  GNUNET_SCHEDULER_cancel (die_task);
  die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
}


static void 
shutdown_task (void *cls,
	       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_GNS_disconnect(gns_handle);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Shutting down peer!\n");
  GNUNET_SCHEDULER_shutdown ();
}


static void
on_lookup_result(void *cls, uint32_t rd_count,
                 const struct GNUNET_NAMESTORE_RecordData *rd)
{
  int i;
  uint16_t mx_preference;
  char* mx;
  
  if (GNUNET_SCHEDULER_NO_TASK != die_task)
  {
      GNUNET_SCHEDULER_cancel (die_task);
      die_task = GNUNET_SCHEDULER_NO_TASK;
  }

  GNUNET_NAMESTORE_disconnect (namestore_handle);
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
      if (rd[i].record_type == GNUNET_GNS_RECORD_MX)
      {
        mx = (char*)rd[i].data+sizeof(uint16_t);
        mx_preference = *(uint16_t*)rd[i].data;
        GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                    "Got MX %s with preference %d\n", mx, mx_preference);
        if (0 == strcmp(mx, TEST_EXPECTED_MX))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                      "%s correctly resolved to %s!\n", TEST_DOMAIN,
                      TEST_EXPECTED_MX);
          ok = 0;
        }
      }
    }
  }
  
  GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);

}


/**
 * Function scheduled to be run on the successful start of services
 * tries to look up the dns record for TEST_DOMAIN
 */
static void
commence_testing (void *cls, int32_t success, const char *emsg)
{
  gns_handle = GNUNET_GNS_connect(cfg);
  if (NULL == gns_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to connect to GNS!\n");
    end_badly_now();
    return;
  }
  GNUNET_GNS_lookup(gns_handle, TEST_DOMAIN, GNUNET_GNS_RECORD_MX,
                    GNUNET_NO,
                    NULL,
                    &on_lookup_result, TEST_DOMAIN);
}


static void
do_check (void *cls,
          const struct GNUNET_CONFIGURATION_Handle *ccfg,
          struct GNUNET_TESTING_Peer *peer)
{
  struct GNUNET_CRYPTO_EccPublicKey alice_pkey;
  struct GNUNET_CRYPTO_EccPublicKey bob_pkey;
  struct GNUNET_CRYPTO_EccPrivateKey *alice_key;
  struct GNUNET_CRYPTO_EccPrivateKey *bob_key;
  struct GNUNET_CRYPTO_ShortHashCode bob_hash;
  struct GNUNET_CRYPTO_EccSignature *sig;
  char* alice_keyfile;
  struct GNUNET_TIME_Absolute et;

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

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (cfg, "gns",
                                                          "ZONEKEY",
                                                          &alice_keyfile))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to get key from cfg\n");
    end_badly_now();
    return;
  }

  alice_key = GNUNET_CRYPTO_ecc_key_create_from_file (alice_keyfile);
  bob_key = GNUNET_CRYPTO_ecc_key_create_from_file (KEYFILE_BOB);

  GNUNET_CRYPTO_ecc_key_get_public (alice_key, &alice_pkey);
  GNUNET_CRYPTO_ecc_key_get_public (bob_key, &bob_pkey);

  struct GNUNET_NAMESTORE_RecordData rd;
  char* ip = TEST_IP;
  struct in_addr *mail = GNUNET_malloc(sizeof(struct in_addr));
  char *mx_record;
  uint16_t mx_preference = 1;
  rd.expiration_time = UINT64_MAX;
  GNUNET_assert(1 == inet_pton (AF_INET, ip, mail));
  
  GNUNET_CRYPTO_short_hash(&bob_pkey, sizeof(bob_pkey), &bob_hash);

  rd.data_size = sizeof(struct GNUNET_CRYPTO_ShortHashCode);
  rd.data = &bob_hash;
  rd.record_type = GNUNET_GNS_RECORD_PKEY;
  rd.flags = GNUNET_NAMESTORE_RF_AUTHORITY;

  GNUNET_NAMESTORE_record_put_by_authority (namestore_handle,
					    alice_key,
					    TEST_AUTHORITY_NAME,
					    1, &rd,
					    NULL,
					    NULL);

  rd.data_size = sizeof(struct in_addr);
  rd.data = mail;
  rd.record_type = GNUNET_DNSPARSER_TYPE_A;
  sig = GNUNET_NAMESTORE_create_signature(bob_key,
                                          GNUNET_TIME_UNIT_FOREVER_ABS,
                                          TEST_RECORD_NAME,
                                          &rd, 1);
  et.abs_value_us = rd.expiration_time;
  GNUNET_NAMESTORE_record_put (namestore_handle,
                               &bob_pkey,
                               TEST_RECORD_NAME,
                               et,
                               1,
                               &rd,
                               sig,
                               NULL,
                               NULL);
  GNUNET_free (sig);
  
  rd.data_size = sizeof(struct GNUNET_DNSPARSER_MxRecord)+strlen(TEST_MX_NAME)+1;
  mx_record = GNUNET_malloc(sizeof(struct GNUNET_DNSPARSER_MxRecord)+strlen(TEST_MX_NAME)+1);
  memcpy(mx_record, &mx_preference, sizeof(uint16_t));
  strcpy(mx_record+sizeof(uint16_t), TEST_MX_NAME);
  rd.data = mx_record;
  rd.record_type = GNUNET_GNS_RECORD_MX;
  sig = GNUNET_NAMESTORE_create_signature(bob_key,
                                          GNUNET_TIME_UNIT_FOREVER_ABS,
                                          GNUNET_GNS_MASTERZONE_STR,
                                          &rd, 1);
  et.abs_value_us = rd.expiration_time;
  GNUNET_NAMESTORE_record_put (namestore_handle,
                               &bob_pkey,
                               GNUNET_GNS_MASTERZONE_STR,
                               et,
                               1,
                               &rd,
                               sig,
                               &commence_testing,
                               NULL);

  GNUNET_free (alice_keyfile);
  GNUNET_free (mx_record);
  GNUNET_free (mail);
  GNUNET_free (sig);
  GNUNET_CRYPTO_ecc_key_free (bob_key);
  GNUNET_CRYPTO_ecc_key_free (alice_key);
}


int
main (int argc, char *argv[])
{
  ok = 1;
  GNUNET_log_setup ("test-gns-simple-mx-lookup",
                    "WARNING",
                    NULL);
  GNUNET_TESTING_peer_run ("test-gns-simple-mx-lookup", "test_gns_simple_lookup.conf", &do_check, NULL);
  return ok;
}

/* end of test_gns_simple_mx_lookup.c */
