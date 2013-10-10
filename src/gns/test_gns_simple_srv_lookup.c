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
 * @file gns/test_gns_simple_srv_lookup.c
 * @brief base testcase for testing GNS SRV lookups
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
#include "gns_protocol.h"
#include "gnunet_gns_service.h"

/* Timeout for entire testcase */
#define TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 20)

/* test records to resolve */
#define TEST_DOMAIN "_sip._tcp.bob.gnu"
#define TEST_IP "127.0.0.1"
#define TEST_RECORD_NAME "sipserver"
#define TEST_RECORD_NAME_SRV "_sip._tcp"
#define TEST_SRV_NAME "sipserver.+"
#define TEST_EXPECTED_SRV "sipserver.bob.gnu"

#define TEST_AUTHORITY_NAME "bob"

#define KEYFILE_BOB "../namestore/zonefiles/HGU0A0VCU334DN7F2I9UIUMVQMM7JMSD142LIMNUGTTV9R0CF4EG.zkey"

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

static void
end_badly_now ()
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

static void
on_lookup_result(void *cls, uint32_t rd_count,
                 const struct GNUNET_NAMESTORE_RecordData *rd)
{
  int i;
  uint16_t *srv_data;
  char* srv;

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
      if (rd[i].record_type == GNUNET_DNSPARSER_TYPE_SRV)
      {
        srv_data = (uint16_t*)rd[i].data;
        srv = (char*)&srv_data[3];
        GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                    "Got SRV %s with p=%d,w=%d,port=%d\n",
                    srv, srv_data, &srv_data[1], &srv_data[2]);
        if (0 == strcmp(srv, TEST_EXPECTED_SRV))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                      "%s correctly resolved to %s!\n", TEST_DOMAIN,
                      TEST_EXPECTED_SRV);
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

  GNUNET_GNS_lookup(gns_handle, TEST_DOMAIN, GNUNET_DNSPARSER_TYPE_SRV,
                    GNUNET_NO,
                    NULL,
                    &on_lookup_result, TEST_DOMAIN);
}


static void
do_check (void *cls,
          const struct GNUNET_CONFIGURATION_Handle *ccfg,
          struct GNUNET_TESTING_Peer *peer)
{
  struct GNUNET_CRYPTO_EcdsaPublicKey alice_pkey;
  struct GNUNET_CRYPTO_EcdsaPublicKey bob_pkey;
  struct GNUNET_CRYPTO_EcdsaPrivateKey *alice_key;
  struct GNUNET_CRYPTO_EcdsaPrivateKey *bob_key;
  struct GNUNET_CRYPTO_ShortHashCode bob_hash;
  struct GNUNET_CRYPTO_EcdsaSignature *sig;
  char* alice_keyfile;
  struct GNUNET_TUN_DnsSrvRecord *srv_data;
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

  alice_key = GNUNET_CRYPTO_ecdsa_key_create_from_file (alice_keyfile);
  bob_key = GNUNET_CRYPTO_ecdsa_key_create_from_file (KEYFILE_BOB);

  GNUNET_CRYPTO_ecdsa_key_get_public (alice_key, &alice_pkey);
  GNUNET_CRYPTO_ecdsa_key_get_public (bob_key, &bob_pkey);

  struct GNUNET_NAMESTORE_RecordData rd;
  char* ip = TEST_IP;
  struct in_addr *sipserver = GNUNET_malloc (sizeof (struct in_addr));
  srv_data = GNUNET_malloc (sizeof (struct GNUNET_TUN_DnsSrvRecord) + strlen (TEST_SRV_NAME) + 1);
  uint16_t srv_weight = 60;
  uint16_t srv_prio = 50;
  uint16_t srv_port = 5060;

  rd.expiration_time = UINT64_MAX;
  GNUNET_assert(1 == inet_pton (AF_INET, ip, sipserver));

  GNUNET_CRYPTO_short_hash(&bob_pkey, sizeof(bob_pkey), &bob_hash);

  rd.data_size = sizeof(struct GNUNET_CRYPTO_ShortHashCode);
  rd.data = &bob_hash;
  rd.record_type = GNUNET_NAMESTORE_TYPE_PKEY;
  rd.flags = GNUNET_NAMESTORE_RF_NONE;

  GNUNET_NAMESTORE_record_put_by_authority (namestore_handle,
					    alice_key,
					    TEST_AUTHORITY_NAME,
					    1, &rd,
					    NULL,
					    NULL);

  rd.data_size = sizeof (struct in_addr);
  rd.data = sipserver;
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

  rd.data_size = sizeof (struct GNUNET_TUN_DnsSrvRecord)+strlen(TEST_SRV_NAME)+1;
  srv_data->port = srv_port;
  srv_data->prio = srv_prio;
  srv_data->weight = srv_weight;
  strcpy((char*)&srv_data[1], TEST_SRV_NAME);
  rd.data = srv_data;
  rd.record_type = GNUNET_DNSPARSER_TYPE_SRV;
  sig = GNUNET_NAMESTORE_create_signature(bob_key,
                                          GNUNET_TIME_UNIT_FOREVER_ABS,
                                          TEST_RECORD_NAME_SRV,
                                          &rd, 1);
  et.abs_value_us = rd.expiration_time;
  GNUNET_NAMESTORE_record_put (namestore_handle,
                               &bob_pkey,
                               TEST_RECORD_NAME_SRV,
                               et,
                               1,
                               &rd,
                               sig,
                               &commence_testing,
                               NULL);
  GNUNET_free (alice_keyfile);
  GNUNET_free (srv_data);
  GNUNET_free (sipserver);
  GNUNET_free (sig);
  GNUNET_free (bob_key);
  GNUNET_free (alice_key);
}


int
main (int argc, char *argv[])
{
  ok = 1;
  GNUNET_log_setup ("test-gns-simple-srv-lookup",
                    "WARNING",
                    NULL);
  GNUNET_TESTING_peer_run ("test-gns-simple-srv-lookup", "test_gns_simple_lookup.conf", &do_check, NULL);
  GNUNET_DISK_directory_remove ("test-gns-simple-srv-lookup");
  return ok;
}

/* end of test_gns_simple_srv_lookup.c */
