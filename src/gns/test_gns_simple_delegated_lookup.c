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
 * @file gns/test_gns_simple_delegated_lookup.c
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
#include "block_dns.h"
#include "gnunet_signatures.h"
#include "gnunet_namestore_service.h"
#include "../namestore/namestore.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_gns_service.h"

/* Timeout for entire testcase */
#define TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 20)

/* test records to resolve */
#define TEST_DOMAIN "www.bob.gnu"
#define TEST_IP "127.0.0.1"
#define TEST_RECORD_NAME "www"

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
shutdown_task (void *cls,
	       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_GNS_disconnect (gns_handle);
  gns_handle = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Shutting down peer!\n");
  GNUNET_SCHEDULER_shutdown ();
}


static void
on_lookup_result (void *cls, uint32_t rd_count,
		  const struct GNUNET_NAMESTORE_RecordData *rd)
{
  const char *name = cls;
  uint32_t i;
  const char* addr;
  struct in_addr a;

  GNUNET_NAMESTORE_disconnect (namestore_handle);
  namestore_handle = NULL;
  if (0 == rd_count)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Lookup failed!\n");
    ok = 2;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (GNUNET_SCHEDULER_NO_TASK != die_task)
  {
      GNUNET_SCHEDULER_cancel (die_task);
      die_task = GNUNET_SCHEDULER_NO_TASK;
  }
  ok = 1;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      "name: %s\n", 
	      name);
  for (i=0; i<rd_count; i++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "type: %d\n", rd[i].record_type);
    if (rd[i].record_type != GNUNET_DNSPARSER_TYPE_A)
      continue;
    memcpy (&a, rd[i].data, sizeof (a));
    addr = inet_ntoa (a);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		"address: %s\n", addr);
    if (0 != strcmp (addr, TEST_IP))
      continue;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"%s correctly resolved to %s!\n", TEST_DOMAIN, addr);
    ok = 0;
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
  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to store record in namestore: %s\n",
		emsg);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  gns_handle = GNUNET_GNS_connect(cfg);
  if (NULL == gns_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to connect to GNS!\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_GNS_lookup (gns_handle, TEST_DOMAIN, GNUNET_DNSPARSER_TYPE_A,
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
  struct GNUNET_NAMESTORE_RecordData rd;
  const char* ip = TEST_IP;
  struct in_addr web;

  cfg = ccfg;
  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);

  /* put records into namestore */
  namestore_handle = GNUNET_NAMESTORE_connect(cfg);
  if (NULL == namestore_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
		"Failed to connect to namestore\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  if (GNUNET_OK != 
      GNUNET_CONFIGURATION_get_value_filename (cfg, "gns",
					       "ZONEKEY",
					       &alice_keyfile))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to get key from cfg\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  alice_key = GNUNET_CRYPTO_ecc_key_create_from_file (alice_keyfile);
  bob_key = GNUNET_CRYPTO_ecc_key_create_from_file (KEYFILE_BOB);
  GNUNET_CRYPTO_ecc_key_get_public (alice_key, &alice_pkey);
  GNUNET_CRYPTO_ecc_key_get_public (bob_key, &bob_pkey);
  rd.expiration_time = UINT64_MAX;
  GNUNET_assert (1 == inet_pton (AF_INET, ip, &web));
  GNUNET_CRYPTO_short_hash (&bob_pkey, sizeof(bob_pkey), &bob_hash);
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
  rd.data_size = sizeof(struct in_addr);
  rd.data = &web;
  rd.record_type = GNUNET_DNSPARSER_TYPE_A;
  sig = GNUNET_NAMESTORE_create_signature (bob_key,
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
                               &commence_testing,
                               NULL);
  GNUNET_free (sig);
  GNUNET_free (alice_keyfile);
  GNUNET_free (bob_key);
  GNUNET_free (alice_key);
}


int
main (int argc, char *argv[])
{
  ok = 1;
  GNUNET_log_setup ("test-gns-simple-delegated-lookup",
                    "WARNING",
                    NULL);
  GNUNET_TESTING_peer_run ("test-gns-simple-delegated-lookup", 
			   "test_gns_simple_lookup.conf",
			   &do_check, NULL);
  return ok;
}

/* end of test_gns_simple_delegated_lookup.c */
