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
 * @file gns/test_gns_ns_lookup.c
 * @brief base testcase for testing a local GNS record lookup through NS
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_testing_lib.h"
#include "gnunet_core_service.h"
#include "block_dns.h"
#include "gnunet_signatures.h"
#include "gnunet_namestore_service.h"
#include "gnunet_resolver_service.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_gns_service.h"

/* Timeout for entire testcase */
#define TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 20)

/* test records to resolve */
#define TEST_DOMAIN "www.homepage.gads"
#define TEST_DOMAIN_ALT "homepage.gads"
#define TEST_DOMAIN_ALT2 "uk.homepage.gads"
#define TEST_IP_ALT2 "81.187.252.184"
#define TEST_IP "131.159.74.67"
#define TEST_IP_NS "216.69.185.1" //ns01.domaincontrol.com
#define TEST_RECORD_NAME "homepage"
#define TEST_RECORD_NS "gnunet.org"

/* Task handle to use to schedule test failure */
static GNUNET_SCHEDULER_TaskIdentifier die_task;

/* Global return value (0 for success, anything else for failure) */
static int ok;

static int resolver_working;

static struct GNUNET_NAMESTORE_Handle *namestore_handle;

static struct GNUNET_GNS_Handle *gns_handle;

static struct GNUNET_RESOLVER_RequestHandle *resolver_handle;

static const struct GNUNET_CONFIGURATION_Handle *cfg;

static struct GNUNET_GNS_LookupRequest *lr;


/**
 * Check if the get_handle is being used, if so stop the request.  Either
 * way, schedule the end_badly_cont function which actually shuts down the
 * test.
 */
static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  die_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Test failed, shutting down...\n");
  if (NULL != lr)
  {
    GNUNET_GNS_cancel_lookup_request (lr);
    lr = NULL;
  }
  if (NULL != resolver_handle)
  {
    GNUNET_RESOLVER_request_cancel (resolver_handle);
    resolver_handle = NULL;
  }
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
end_now (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, 
	     "Test successful, shutting down...\n");
  if (GNUNET_SCHEDULER_NO_TASK != die_task)
  {
      GNUNET_SCHEDULER_cancel (die_task);
      die_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != resolver_handle)
  {
    GNUNET_RESOLVER_request_cancel (resolver_handle);
    resolver_handle = NULL;
  }
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
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Shutting down peer!\n");
  GNUNET_SCHEDULER_shutdown ();
}


static void
on_lookup_result_alt2 (void *cls, uint32_t rd_count,
		       const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct in_addr a;
  uint32_t i;
  char* addr;

  lr = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received alternative results 2\n");
  if (rd_count == 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Lookup failed\n");
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
        if (0 == strcmp(addr, TEST_IP_ALT2))
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
  GNUNET_SCHEDULER_add_now (&end_now, NULL);
}


static void
on_lookup_result_alt (void *cls, uint32_t rd_count,
		      const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct in_addr a;
  uint32_t i;
  char* addr;

  lr = NULL;
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Received alternative results\n");
  if (rd_count == 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Lookup failed\n");
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

  lr = GNUNET_GNS_lookup (gns_handle, TEST_DOMAIN_ALT2, GNUNET_GNS_RECORD_A,
			  GNUNET_YES,
			  NULL,
			  &on_lookup_result_alt2, TEST_DOMAIN_ALT2);
}


static void
on_lookup_result(void *cls, uint32_t rd_count,
                 const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct in_addr a;
  uint32_t i;
  char* addr;

  lr = NULL;
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Received results\n");
  if (rd_count == 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Lookup failed\n");
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

  lr = GNUNET_GNS_lookup (gns_handle, TEST_DOMAIN_ALT, GNUNET_GNS_RECORD_A,
			  GNUNET_YES,
			  NULL,
			  &on_lookup_result_alt, TEST_DOMAIN_ALT);
}


static void
start_lookup ()
{
  GNUNET_NAMESTORE_disconnect (namestore_handle);
  namestore_handle = NULL;

  gns_handle = GNUNET_GNS_connect (cfg);
  if (NULL == gns_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to connect to GNS!\n");
    end_badly_now ();
    return;
  }

  lr = GNUNET_GNS_lookup (gns_handle, TEST_DOMAIN, GNUNET_GNS_RECORD_A,
			  GNUNET_YES,
			  NULL,
			  &on_lookup_result, TEST_DOMAIN);
}


static void
handle_dns_test (void *cls,
                 const struct sockaddr *addr,
                 socklen_t addrlen)
{
  struct sockaddr_in* sai;

  resolver_handle = NULL;
  if (NULL == addr)
  {
    /* end of results */
    if (GNUNET_YES != resolver_working)
    {
      ok = 0;
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "System resolver not working. Test inconclusive!\n");
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Shutting down peer1!\n");
      GNUNET_SCHEDULER_add_now (&end_now, NULL);
      return;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		"Starting lookup \n");
    start_lookup ();
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Received DNS response\n");
  if (addrlen == sizeof (struct sockaddr_in))
  {
    sai = (struct sockaddr_in*) addr;
    if (0 == strcmp (TEST_IP, inet_ntoa (sai->sin_addr)))
    {
      resolver_working = GNUNET_YES;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Resolver is working\n");
    }
  }
}


/**
 * Function scheduled to be run on the successful start of services
 * tries to look up the dns record for TEST_DOMAIN
 */
static void
commence_testing (void *cls, int32_t success, const char *emsg)
{
  resolver_working = GNUNET_NO;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Resolving NS record\n");
  GNUNET_RESOLVER_connect (cfg);
  resolver_handle = GNUNET_RESOLVER_ip_get (TEST_RECORD_NS,
                                            AF_INET,
                                            TIMEOUT,
                                            &handle_dns_test,
                                            NULL);
}


static void
do_check (void *cls,
          const struct GNUNET_CONFIGURATION_Handle *ccfg,
          struct GNUNET_TESTING_Peer *peer)
{
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded alice_pkey;
  struct GNUNET_CRYPTO_RsaPrivateKey *alice_key;
  char* alice_keyfile;
  struct GNUNET_NAMESTORE_RecordData rd;
  const char* ip = TEST_IP_NS;
  struct in_addr ns;
  
  cfg = ccfg;
  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);

  /* put records into namestore */
  namestore_handle = GNUNET_NAMESTORE_connect(cfg);
  if (NULL == namestore_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
		"Failed to connect to namestore\n");
    end_badly_now ();
    return;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg, "gns",
					       "ZONEKEY",
					       &alice_keyfile))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Failed to get key from cfg\n");
    end_badly_now ();
    return;
  }

  alice_key = GNUNET_CRYPTO_rsa_key_create_from_file (alice_keyfile);
  GNUNET_CRYPTO_rsa_key_get_public (alice_key, &alice_pkey);
  GNUNET_free(alice_keyfile);

  rd.expiration_time = UINT64_MAX;
  GNUNET_assert(1 == inet_pton (AF_INET, ip, &ns));
  rd.data_size = sizeof(struct in_addr);
  rd.data = &ns;
  rd.record_type = GNUNET_DNSPARSER_TYPE_A;
  rd.flags = GNUNET_NAMESTORE_RF_AUTHORITY;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Creating records\n");
  GNUNET_NAMESTORE_record_create (namestore_handle,
                                  alice_key,
                                  TEST_RECORD_NAME,
                                  &rd,
                                  NULL,
                                  NULL);
  rd.data_size = strlen (TEST_RECORD_NS);
  rd.data = TEST_RECORD_NS;
  rd.record_type = GNUNET_GNS_RECORD_NS;
  GNUNET_NAMESTORE_record_create (namestore_handle,
                                  alice_key,
                                  TEST_RECORD_NAME,
                                  &rd,
                                  &commence_testing,
                                  NULL);
  GNUNET_CRYPTO_rsa_key_free(alice_key);
}


int
main (int argc, char *argv[])
{
  ok = 1;
  GNUNET_log_setup ("test-gns-simple-ns-lookup",
                    "WARNING",
                    NULL);
  GNUNET_TESTING_peer_run ("test-gns-simple-ns-lookup", "test_gns_simple_lookup.conf",
			   &do_check, NULL);
  return ok;
}

/* end of test_gns_ns_lookup.c */
