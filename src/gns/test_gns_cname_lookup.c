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
 * @file gns/test_gns_cname_lookup.c
 * @brief base testcase for testing a local GNS record lookup
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_testing_lib.h"
#include "gnunet_core_service.h"
#include "block_dns.h"
#include "gnunet_signatures.h"
#include "gnunet_namestore_service.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_gns_service.h"


/**
 * Timeout for entire testcase 
 */
#define TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 20)

/* test records to resolve */
#define TEST_DOMAIN_PLUS "www.gads"
#define TEST_DOMAIN_ZKEY "www2.gads"
#define TEST_DOMAIN_DNS  "www3.gads"
#define TEST_IP_PLUS "127.0.0.1"
#define TEST_IP_ZKEY "127.0.0.2"
#define TEST_IP_DNS  "131.159.74.67"
#define TEST_RECORD_CNAME_SERVER "server.gads"
#define TEST_RECORD_CNAME_PLUS "server.+"
#define TEST_RECORD_CNAME_ZKEY "www.J7POEUT41A8PBFS7KVVDRF88GBOU4HK8PSU5QKVLVE3R9T91E99G.zkey"
#define TEST_RECORD_CNAME_DNS "gnunet.org"
#define TEST_RECORD_NAME_SERVER "server"
#define TEST_RECORD_NAME_PLUS "www"
#define TEST_RECORD_NAME_ZKEY "www2"
#define TEST_RECORD_NAME_DNS "www3"

#define KEYFILE_BOB "zonefiles/J7POEUT41A8PBFS7KVVDRF88GBOU4HK8PSU5QKVLVE3R9T91E99G.zkey"


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
    GNUNET_GNS_disconnect (gns_handle);
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
on_lookup_result_cname (void *cls, 
			uint32_t rd_count,
			const struct GNUNET_NAMESTORE_RecordData *rd)
{
  uint32_t i;
  
  if (GNUNET_SCHEDULER_NO_TASK != die_task)
  {
      GNUNET_SCHEDULER_cancel (die_task);
      die_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_NAMESTORE_disconnect (namestore_handle);
  namestore_handle = NULL;
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
      if (rd[i].record_type == GNUNET_GNS_RECORD_CNAME)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_INFO, "CNAME: %s\n", rd[i].data);
        if (0 == strcmp(rd[i].data, TEST_RECORD_CNAME_SERVER))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                    "%s correctly resolved to %s!\n", TEST_DOMAIN_PLUS, rd[i].data);
          ok = 0;
        }
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No resolution!\n");
      }
    }
  }
  GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
}


static void
on_lookup_result_dns (void *cls,
		      uint32_t rd_count,
		      const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct in_addr a;
  uint32_t i;
  char* addr;
  
  if (rd_count == 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "CNAME to DNS delegation failed. System offline?\n");
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
	if (0 == strcmp(addr, TEST_IP_DNS))
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		      "%s correctly resolved to %s!\n", TEST_DOMAIN_DNS, addr);
	  ok = 0;
	}
      }
      else
      {
	GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No resolution!\n");
      }
    }
  }
  GNUNET_GNS_lookup (gns_handle, TEST_DOMAIN_PLUS, GNUNET_GNS_RECORD_CNAME,
                     GNUNET_YES,
                     NULL,
                     &on_lookup_result_cname, TEST_DOMAIN_PLUS);
}


static void
on_lookup_result_zkey (void *cls, uint32_t rd_count,
		       const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct in_addr a;
  uint32_t i;
  char* addr;
  
  if (rd_count == 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Lookup failed, rp_filtering?\n");
    ok = 2;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  ok = 1;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      "name: %s\n", (char*)cls);
  for (i=0; i<rd_count; i++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		"type: %d\n", rd[i].record_type);
    if (rd[i].record_type == GNUNET_GNS_RECORD_A)
    {
      memcpy (&a, rd[i].data, sizeof(a));
      addr = inet_ntoa(a);
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
		  "address: %s\n", addr);
      if (0 == strcmp (addr, TEST_IP_ZKEY))
      {
	GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		    "%s correctly resolved to %s!\n", 
		    TEST_DOMAIN_ZKEY, addr);
	ok = 0;
      }
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  "No resolution!\n");
    }
  }  
  GNUNET_GNS_lookup (gns_handle, TEST_DOMAIN_DNS, GNUNET_GNS_RECORD_A,
		     GNUNET_YES,
		     NULL,
		     &on_lookup_result_dns, TEST_DOMAIN_DNS);
}


static void
on_lookup_result_plus (void *cls, uint32_t rd_count,
		       const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct in_addr a;
  uint32_t i;
  char* addr;
  
  if (rd_count == 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Lookup failed, rp_filtering?\n");
    ok = 2;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
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
      if (0 == strcmp(addr, TEST_IP_PLUS))
      {
	GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		    "%s correctly resolved to %s!\n", TEST_DOMAIN_PLUS, addr);
	ok = 0;
      }
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No resolution!\n");
    }
  }
  GNUNET_GNS_lookup (gns_handle, TEST_DOMAIN_ZKEY, GNUNET_GNS_RECORD_A,
		     GNUNET_YES,
		     NULL,
		     &on_lookup_result_zkey, TEST_DOMAIN_ZKEY);
}


/**
 * Function scheduled to be run on the successful start of services
 * tries to look up the dns record for TEST_DOMAIN
 *
 * @param cls closure
 * @param success GNUNET_SYSERR on failure (including timeout/queue drop/failure to validate)
 *                GNUNET_NO if content was already there or not found
 *                GNUNET_YES (or other positive value) on success
 * @param emsg NULL on success, otherwise an error message
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
  GNUNET_GNS_lookup (gns_handle, TEST_DOMAIN_PLUS, GNUNET_GNS_RECORD_A,
		     GNUNET_YES,
		     NULL,
		     &on_lookup_result_plus, TEST_DOMAIN_PLUS);
}


static void
do_check (void *cls,
          const struct GNUNET_CONFIGURATION_Handle *ccfg,
          struct GNUNET_TESTING_Peer *peer)
{
  struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded alice_pkey;
  struct GNUNET_CRYPTO_EccPrivateKey *alice_key;
  struct GNUNET_CRYPTO_EccPrivateKey *bob_key;
  char* alice_keyfile;
  struct GNUNET_NAMESTORE_RecordData rd;
  const char* ip = TEST_IP_PLUS;
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

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (cfg, "gns",
                                                          "ZONEKEY",
                                                          &alice_keyfile))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Failed to get key from cfg\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  alice_key = GNUNET_CRYPTO_ecc_key_create_from_file (alice_keyfile);
  GNUNET_CRYPTO_ecc_key_get_public (alice_key, &alice_pkey);
  GNUNET_free(alice_keyfile);

  bob_key = GNUNET_CRYPTO_ecc_key_create_from_file (KEYFILE_BOB);

  rd.expiration_time = UINT64_MAX;
  GNUNET_assert(1 == inet_pton (AF_INET, ip, &web));
  rd.data_size = sizeof(struct in_addr);
  rd.data = &web;
  rd.record_type = GNUNET_DNSPARSER_TYPE_A;
  rd.flags = GNUNET_NAMESTORE_RF_AUTHORITY;

  GNUNET_NAMESTORE_record_put_by_authority (namestore_handle,
					    alice_key,
					    TEST_RECORD_NAME_SERVER,
					    1, &rd,
					    NULL,
					    NULL);

  rd.data_size = strlen (TEST_RECORD_CNAME_PLUS);
  rd.data = TEST_RECORD_CNAME_PLUS;
  rd.record_type = GNUNET_GNS_RECORD_CNAME;

  GNUNET_NAMESTORE_record_put_by_authority (namestore_handle,
					    alice_key,
					    TEST_RECORD_NAME_PLUS,
					    1, &rd,
					    NULL,
					    NULL);

  rd.data_size = strlen (TEST_RECORD_CNAME_ZKEY);
  rd.data = TEST_RECORD_CNAME_ZKEY;
  rd.record_type = GNUNET_GNS_RECORD_CNAME;

  GNUNET_NAMESTORE_record_put_by_authority (namestore_handle,
					    alice_key,
					    TEST_RECORD_NAME_ZKEY,
					    1, &rd,
					    NULL,
					    NULL);

  rd.data_size = strlen (TEST_RECORD_CNAME_DNS);
  rd.data = TEST_RECORD_CNAME_DNS;
  rd.record_type = GNUNET_GNS_RECORD_CNAME;

  GNUNET_NAMESTORE_record_put_by_authority (namestore_handle,
					    alice_key,
					    TEST_RECORD_NAME_DNS,
					    1, &rd,
					    NULL,
					    NULL);

  GNUNET_assert(1 == inet_pton (AF_INET, TEST_IP_ZKEY, &web));
  rd.data_size = sizeof(struct in_addr);
  rd.data = &web;
  rd.record_type = GNUNET_DNSPARSER_TYPE_A;
  
  GNUNET_NAMESTORE_record_put_by_authority (namestore_handle,
					    bob_key,
					    TEST_RECORD_NAME_PLUS,
					    1, &rd,
					    &commence_testing,
					    NULL);
  GNUNET_CRYPTO_ecc_key_free(alice_key);
  GNUNET_CRYPTO_ecc_key_free(bob_key);
}


int
main (int argc, char *argv[])
{
  ok = 1;

  GNUNET_log_setup ("test-gns-simple-cname-lookup",
                    "WARNING",
                    NULL);
  GNUNET_TESTING_peer_run ("test-gns-simple-cname-lookup", "test_gns_simple_lookup.conf", &do_check, NULL);
  return ok;
}

/* end of test_gns_cname_lookup.c */
