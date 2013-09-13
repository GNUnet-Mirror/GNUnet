/*
     This file is part of GNUnet.
     (C) 2012, 2013 Christian Grothoff (and other contributing authors)

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

/**
 * Timeout for entire testcase 
 */
#define TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 20)

/**
 * Name to resolve for testing.  NS record on 'homepage.gnu' redirects to
 * DNS 'TEST_RECORD_NS' domain and thus names should be resolved within
 * that target domain.
 */
#define TEST_DOMAIN "www.homepage.gnu"

/**
 * Name to resolve for testing.  NS record on 'homepage.gnu' redirects to
 * DNS 'TEST_RECORD_NS' domain and thus names should be resolved within
 * that target domain.
 */
#define TEST_DOMAIN_ALT "homepage.gnu"

/**
 * Name to resolve for testing.  NS record on 'homepage.gnu' redirects to
 * DNS 'TEST_RECORD_NS' domain and thus names should be resolved within
 * that target domain.
 */
#define TEST_DOMAIN_ALT2 "uk.homepage.gnu"

/**
 * Expected test value (matching TEST_DOMAIN_ALT2).
 * Currently 'uk.gnunet.org' / 'stat.wensley.org.uk'.
 */
#define TEST_IP_ALT2 "81.187.252.184"

/**
 * Must be the IP address for TEST_RECORD_NS in DNS and TEST_DOMAIN in GADS;
 * used to check that DNS is working as expected.  We use the IPv4
 * address of gnunet.org.
 */
#define TEST_IP "131.159.74.67"

/**
 * DNS domain name used for testing.
 */
#define TEST_RECORD_NS "gnunet.org"

/**
 * Nameserver for 'TEST_RECORD_NS', currently 'a.ns.joker.com'.
 */
#define TEST_IP_NS "184.172.157.218" 

/**
 * Name we use within our GADS zone.
 */
#define TEST_RECORD_NAME "homepage"

/**
 * Task handle to use to schedule test failure 
 */
static GNUNET_SCHEDULER_TaskIdentifier die_task;

/**
 * Global return value (0 for success, anything else for failure) 
 */
static int ok;

/**
 * Flag we set if the DNS resolver seems to be working.
 */
static int resolver_working;

/**
 * Handle to namestore.
 */
static struct GNUNET_NAMESTORE_Handle *namestore_handle;

/**
 * Handle to GNS resolver.
 */
static struct GNUNET_GNS_Handle *gns_handle;

/**
 * Handle for DNS request.
 */
static struct GNUNET_RESOLVER_RequestHandle *resolver_handle;

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle for active GNS lookup.
 */
static struct GNUNET_GNS_LookupRequest *lr;

/**
 * Queue for storing records in namestore.
 */
static struct GNUNET_NAMESTORE_QueueEntry *qe;

/**
 * Our private key for signing records.
 */
static struct GNUNET_CRYPTO_EccPrivateKey *alice_key;


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
  if (NULL != qe)
  {
    GNUNET_NAMESTORE_cancel (qe);
    qe = NULL;
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
  if (NULL != alice_key)
  {
    GNUNET_free (alice_key);
    alice_key = NULL;
  }
  GNUNET_break (0);
  GNUNET_SCHEDULER_shutdown ();
  ok = 1;
}


/**
 * We hit a hard failure, shutdown now.
 */
static void
end_badly_now ()
{
  GNUNET_SCHEDULER_cancel (die_task);
  die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
}


/**
 * Testcase is finished, terminate everything.
 */
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
  if (NULL != qe)
  {
    GNUNET_NAMESTORE_cancel (qe);
    qe = NULL;
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
  if (NULL != alice_key)
  {
    GNUNET_free (alice_key);
    alice_key = NULL;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Shutting down peer!\n");
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * We got resolution result for 'TEST_DOMAIN_ALT2', check if
 * they match our expectations, then finish the test with success.
 *
 * @param cls unused
 * @param rd_count number of records in rd
 * @param rd records returned from naming system for the name
 */
static void
on_lookup_result_alt2 (void *cls, uint32_t rd_count,
		       const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct in_addr a;
  uint32_t i;
  char* addr;

  lr = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received alternative results 2\n");
  if (0 == rd_count)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Lookup for `%s' failed\n",
		TEST_DOMAIN_ALT2);
    ok = 2;
    GNUNET_SCHEDULER_add_now (&end_now, NULL);
    return;
  }
  ok = 1;
  for (i=0; i<rd_count; i++)
  {
    if (rd[i].record_type == GNUNET_DNSPARSER_TYPE_A)
    {
      memcpy(&a, rd[i].data, sizeof(a));
      addr = inet_ntoa(a);
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "address: %s\n", addr);
      if (0 == strcmp(addr, TEST_IP_ALT2))
      {
	GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                    "%s correctly resolved to %s!\n", 
		    TEST_DOMAIN_ALT2, addr);
	ok = 0;
      }
      else
	GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
		    "Got unexpected address %s for %s\n",
		    addr,
		    TEST_DOMAIN);
    }
  }
  if (1 == ok)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		"None of the results matched the expected value %s for %s\n",
		TEST_IP,
		TEST_DOMAIN);
    GNUNET_SCHEDULER_add_now (&end_now, NULL);
    return;
  }

  GNUNET_SCHEDULER_add_now (&end_now, NULL);
}


/**
 * We got resolution result for 'TEST_DOMAIN_ALT', check if
 * they match our expectations, then move on to the next
 * resolution.
 *
 * @param cls unused
 * @param rd_count number of records in rd
 * @param rd records returned from naming system for the name
 */
static void
on_lookup_result_alt (void *cls, uint32_t rd_count,
		      const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct in_addr a;
  uint32_t i;
  char* addr;

  lr = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received alternative results\n");
  if (0 == rd_count)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Lookup for `%s' failed\n",
		TEST_DOMAIN_ALT);
    ok = 2;
    GNUNET_SCHEDULER_add_now (&end_now, NULL);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Received %u results for %s\n",
	      (unsigned int) rd_count,
	      TEST_DOMAIN_ALT);
  ok = 1;
  for (i=0; i<rd_count; i++)
  {
    if (rd[i].record_type == GNUNET_DNSPARSER_TYPE_A)
    {
      memcpy (&a, rd[i].data, sizeof(a));
      addr = inet_ntoa (a);
      if (0 == strcmp(addr, TEST_IP))
      {
	GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		    "%s correctly resolved to %s!\n", TEST_DOMAIN, addr);
	ok = 0;
      }
      else
	GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
		    "Got unexpected address %s for %s\n",
		    addr,
		    TEST_DOMAIN_ALT);
    }
  }
  if (1 == ok)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		"None of the results matched the expected value %s for %s\n",
		TEST_IP,
		TEST_DOMAIN_ALT);
    GNUNET_SCHEDULER_add_now (&end_now, NULL);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Starting lookup for `%s'\n",
	      TEST_DOMAIN_ALT2);
  lr = GNUNET_GNS_lookup (gns_handle, 
			  TEST_DOMAIN_ALT2, GNUNET_DNSPARSER_TYPE_A,
			  GNUNET_YES,
			  NULL,
			  &on_lookup_result_alt2, NULL);
}


/**
 * We got resolution result for 'TEST_DOMAIN', check if
 * they match our expectations, then move on to the next
 * resolution.
 *
 * @param cls unused
 * @param rd_count number of records in rd
 * @param rd records returned from naming system for the name
 */
static void
on_lookup_result (void *cls, uint32_t rd_count,
		  const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct in_addr a;
  uint32_t i;
  char* addr;

  lr = NULL;
  if (0 == rd_count)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Lookup for `%s' failed\n",
		TEST_DOMAIN);
    ok = 2;
    GNUNET_SCHEDULER_add_now (&end_now, NULL);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Received %u results for %s\n",
	      (unsigned int) rd_count,
	      TEST_DOMAIN);
  ok = 1;
  for (i=0; i<rd_count; i++)
  {
    if (rd[i].record_type == GNUNET_DNSPARSER_TYPE_A)
    {
      memcpy (&a, rd[i].data, sizeof(a));
      addr = inet_ntoa(a);
      if (0 == strcmp (addr, TEST_IP))
      {
	GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                    "%s correctly resolved to %s!\n", 
		    TEST_DOMAIN, addr);
	ok = 0;
      }
      else
	GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
		    "Got unexpected address %s for %s\n",
		    addr,
		    TEST_DOMAIN);
    }
  }
  if (1 == ok)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		"None of the results matched the expected value %s for %s\n",
		TEST_IP,
		TEST_DOMAIN);
    GNUNET_SCHEDULER_add_now (&end_now, NULL);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Starting lookup for `%s'\n",
	      TEST_DOMAIN_ALT);

  lr = GNUNET_GNS_lookup (gns_handle, TEST_DOMAIN_ALT, GNUNET_DNSPARSER_TYPE_A,
			  GNUNET_YES,
			  NULL,
			  &on_lookup_result_alt, NULL);
}


/**
 * Start the actual NS-based lookup.
 */
static void
start_lookup ()
{
  gns_handle = GNUNET_GNS_connect (cfg);
  if (NULL == gns_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to connect to GNS!\n");
    end_badly_now ();
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Records ready, starting lookup for `%s'\n",
	      TEST_DOMAIN);
  lr = GNUNET_GNS_lookup (gns_handle, TEST_DOMAIN, GNUNET_DNSPARSER_TYPE_A,
			  GNUNET_YES,
			  NULL,
			  &on_lookup_result, NULL);
}


/**
 * Function called with the result of resolving the "NS" record
 * for TEST_RECORD_NS.  Check if the NS record is set as expected,
 * and if so, continue with the test.
 *
 * @param cls closure, unused
 * @param addr NULL for last address,
 * @param addrlen number of bytes in addr
 */
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
                  "System resolver not working as expected. Test inconclusive!\n");
      GNUNET_SCHEDULER_add_now (&end_now, NULL);
      return;
    }
    /* done preparing records, start lookup */
    GNUNET_NAMESTORE_disconnect (namestore_handle);
    namestore_handle = NULL;
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
		  "Resolver is working (returned expected A record %s for %s)\n",
		  TEST_IP,
		  TEST_RECORD_NS);
    }
  }
}


/**
 * Function scheduled to be run on the successful start of services
 * tries to look up the dns record for TEST_DOMAIN
 *
 * @param cls closure, unused
 * @param success GNUNET_OK on success
 * @param emsg error message, NULL on success
 */
static void
commence_testing (void *cls, int32_t success, const char *emsg)
{
  qe = NULL;
  if (NULL != emsg)
    FPRINTF (stderr, "Failed to create record: %s\n", emsg);
  GNUNET_assert (GNUNET_YES == success);
  resolver_working = GNUNET_NO;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Resolving NS record for %s\n",
	      TEST_RECORD_NS);
  GNUNET_RESOLVER_connect (cfg);
  resolver_handle = GNUNET_RESOLVER_ip_get (TEST_RECORD_NS,
                                            AF_INET,
                                            TIMEOUT,
                                            &handle_dns_test,
                                            NULL);
}


/**
 * Peer is ready, run the actual test.  Begins by storing
 * a record in the namestore.
 *
 * @param cls closure, NULL
 * @param ccfg our configuration
 * @param peer handle to the peer
 */
static void
do_check (void *cls,
          const struct GNUNET_CONFIGURATION_Handle *ccfg,
          struct GNUNET_TESTING_Peer *peer)
{
  struct GNUNET_CRYPTO_EccPublicSignKey alice_pkey;
  char* alice_keyfile;
  struct GNUNET_NAMESTORE_RecordData rd[2];
  struct in_addr ns;
  
  cfg = ccfg;
  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, NULL);

  /* put records into namestore */
  namestore_handle = GNUNET_NAMESTORE_connect (cfg);
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

  alice_key = GNUNET_CRYPTO_ecc_key_create_from_file (alice_keyfile);
  GNUNET_CRYPTO_ecc_key_get_public_for_signature (alice_key, &alice_pkey);
  GNUNET_free (alice_keyfile);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Creating NS records\n");
  rd[0].expiration_time = UINT64_MAX;
  GNUNET_assert(1 == inet_pton (AF_INET, TEST_IP_NS, &ns));
  rd[0].data_size = sizeof (struct in_addr);
  rd[0].data = &ns;
  rd[0].record_type = GNUNET_DNSPARSER_TYPE_A;
  rd[0].flags = GNUNET_NAMESTORE_RF_NONE;
  
  rd[1].expiration_time = UINT64_MAX;
  rd[1].data_size = strlen (TEST_RECORD_NS);
  rd[1].data = TEST_RECORD_NS;
  rd[1].record_type = GNUNET_DNSPARSER_TYPE_NS;
  rd[1].flags = GNUNET_NAMESTORE_RF_NONE;

  qe = GNUNET_NAMESTORE_record_put_by_authority (namestore_handle,
						 alice_key,
						 TEST_RECORD_NAME,
						 2, rd,
						 &commence_testing,
						 NULL);
}


int
main (int argc, char *argv[])
{
  ok = 1;
  GNUNET_TESTING_peer_run ("test-gns-simple-ns-lookup", "test_gns_simple_lookup.conf",
			   &do_check, NULL);
  return ok;
}

/* end of test_gns_ns_lookup.c */
