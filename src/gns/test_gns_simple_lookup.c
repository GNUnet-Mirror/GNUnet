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
 * @file gns/test_gns_simple_lookup.c
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
#define TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 120)

/* test records to resolve */
#define TEST_DOMAIN "www.gnu"
#define TEST_IP "127.0.0.1"
#define TEST_RECORD_NAME "www"

/**
 * Task handle to use to schedule test failure 
 */
static GNUNET_SCHEDULER_TaskIdentifier die_task;

/**
 * Global return value (0 for success, anything else for failure) 
 */
static int ok;

static struct GNUNET_NAMESTORE_Handle *namestore_handle;

static struct GNUNET_GNS_Handle *gns_handle;

static const struct GNUNET_CONFIGURATION_Handle *cfg;

static struct GNUNET_GNS_LookupRequest *lr;

static struct GNUNET_NAMESTORE_QueueEntry *nsqe;


/**
 * Check if the get_handle is being used, if so stop the request.  Either
 * way, schedule the end_badly_cont function which actually shuts down the
 * test.
 */
static void
end_badly (void *cls, 
	   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != nsqe)
  {
    GNUNET_NAMESTORE_cancel (nsqe);
    nsqe = NULL;
  }
  if (NULL != lr)
  {
    GNUNET_GNS_cancel_lookup_request (lr);
    lr = NULL;
  }
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
end_badly_now ()
{
  GNUNET_SCHEDULER_cancel (die_task);
  die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
}


static void 
shutdown_task (void *cls,
	       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_GNS_disconnect (gns_handle);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Shutting down peer!\n");
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Function called on result for a GNS lookup
 *
 * @param cls closure, unused
 * @param rd_count number of records
 * @param rd the records in reply
 */
static void
on_lookup_result(void *cls, uint32_t rd_count,
                 const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct in_addr a;
  uint32_t i;
  char* addr;

  lr = NULL;
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
      if (rd[i].record_type == GNUNET_DNSPARSER_TYPE_A)
      {
        memcpy (&a, rd[i].data, sizeof(a));
        addr = inet_ntoa(a);
        GNUNET_log (GNUNET_ERROR_TYPE_INFO, "address: %s\n", addr);
        if (0 == strcmp (addr, TEST_IP))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		      "%s correctly resolved to %s!\n",
		      TEST_DOMAIN, addr);
          ok = 0;
        }
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		    "No resolution!\n");
      }
    }
  }
  GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
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
commence_testing (void *cls,
		  int32_t success,
		  const char *emsg)
{
  nsqe = NULL;
  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to store record in namestore: %s\n",
		emsg);
    end_badly_now ();
    return;
  }
  gns_handle = GNUNET_GNS_connect (cfg);
  if (NULL == gns_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to connect to GNS!\n");
    end_badly_now ();
    return;
  }
  lr = GNUNET_GNS_lookup (gns_handle, TEST_DOMAIN, GNUNET_DNSPARSER_TYPE_A,
			  GNUNET_YES,
			  NULL,
			  &on_lookup_result, TEST_DOMAIN);
}


static void
do_check (void *cls,
          const struct GNUNET_CONFIGURATION_Handle *ccfg,
          struct GNUNET_TESTING_Peer *peer)
{
  struct GNUNET_CRYPTO_EccPublicKey alice_pkey;
  struct GNUNET_CRYPTO_EccPrivateKey *alice_key;
  struct GNUNET_NAMESTORE_RecordData rd;
  char* alice_keyfile;
  char* ip = TEST_IP;
  struct in_addr web;

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

  alice_key = GNUNET_CRYPTO_ecc_key_create_from_file (alice_keyfile);
  GNUNET_CRYPTO_ecc_key_get_public (alice_key, &alice_pkey);
  GNUNET_free (alice_keyfile);
  rd.expiration_time = UINT64_MAX;
  GNUNET_assert (1 == inet_pton (AF_INET, ip, &web));
  rd.data_size = sizeof(struct in_addr);
  rd.data = &web;
  rd.record_type = GNUNET_DNSPARSER_TYPE_A;
  rd.flags = GNUNET_NAMESTORE_RF_AUTHORITY;
  nsqe = GNUNET_NAMESTORE_record_put_by_authority (namestore_handle,
						   alice_key,
						   TEST_RECORD_NAME,
						   1, &rd,
						   &commence_testing,
						   NULL);
  GNUNET_free (alice_key);
}


int
main (int argc, char *argv[])
{
  ok = 1;
  GNUNET_log_setup ("test-gns-simple-lookup",
                    "WARNING",
                    NULL);
  GNUNET_TESTING_peer_run ("test-gns-simple-lookup", 
			   "test_gns_simple_lookup.conf", 
			   &do_check, NULL);
  return ok;
}
 
/* end of test_gns_simple_lookup.c */
