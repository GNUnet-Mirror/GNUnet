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
#include "gnunet_gns_service.h"

/* DEFINES */
#define VERBOSE GNUNET_YES

/* Timeout for entire testcase */
#define TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 20)

/* If number of peers not in config file, use this number */
#define DEFAULT_NUM_PEERS 2

/* test records to resolve */
#define TEST_DOMAIN "_sip._tcp.bob.gnunet"
#define TEST_IP "127.0.0.1"
#define TEST_RECORD_NAME "sipserver"
#define TEST_RECORD_NAME_SRV "_sip._tcp"
#define TEST_SRV_NAME "sipserver.+"
#define TEST_EXPECTED_SRV "sipserver.bob.gnunet"

#define TEST_AUTHORITY_NAME "bob"

#define KEYFILE_BOB "../namestore/zonefiles/HGU0A0VCU334DN7F2I9UIUMVQMM7JMSD142LIMNUGTTV9R0CF4EG.zkey"

/* Globals */

/**
 * Directory to store temp data in, defined in config file
 */
static char *test_directory;

static struct GNUNET_TESTING_PeerGroup *pg;

/* Task handle to use to schedule test failure */
GNUNET_SCHEDULER_TaskIdentifier die_task;

/* Global return value (0 for success, anything else for failure) */
static int ok;

static struct GNUNET_NAMESTORE_Handle *namestore_handle;

static struct GNUNET_GNS_Handle *gns_handle;

const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Check whether peers successfully shut down.
 */
void
shutdown_callback (void *cls, const char *emsg)
{
  if (emsg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Error on shutdown! ret=%d\n", ok);
    if (ok == 0)
      ok = 2;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "done(ret=%d)!\n", ok);
}

static void
on_lookup_result(void *cls, uint32_t rd_count,
                 const struct GNUNET_NAMESTORE_RecordData *rd)
{
  int i;
  uint16_t *srv_data;
  char* srv;
  
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
      if (rd[i].record_type == GNUNET_GNS_RECORD_TYPE_SRV)
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

  GNUNET_GNS_disconnect(gns_handle);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Shutting down peer1!\n");
  GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
}


/**
 * Function scheduled to be run on the successful start of services
 * tries to look up the dns record for TEST_DOMAIN
 */
static void
commence_testing (void *cls, int32_t success, const char *emsg)
{
  GNUNET_NAMESTORE_disconnect(namestore_handle, GNUNET_YES);

  gns_handle = GNUNET_GNS_connect(cfg);

  if (NULL == gns_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to connect to GNS!\n");
  }

  GNUNET_GNS_lookup(gns_handle, TEST_DOMAIN, GNUNET_GNS_RECORD_TYPE_SRV,
                    GNUNET_NO,
                    NULL,
                    &on_lookup_result, TEST_DOMAIN);
}

/**
 * Continuation for the GNUNET_DHT_get_stop call, so that we don't shut
 * down the peers without freeing memory associated with GET request.
 */
static void
end_badly_cont (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{

  if (pg != NULL)
    GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
  GNUNET_SCHEDULER_cancel (die_task);
}

/**
 * Check if the get_handle is being used, if so stop the request.  Either
 * way, schedule the end_badly_cont function which actually shuts down the
 * test.
 */
static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failing test with error: `%s'!\n",
              (char *) cls);
  GNUNET_SCHEDULER_add_now (&end_badly_cont, NULL);
  ok = 1;
}

GNUNET_NETWORK_STRUCT_BEGIN
struct srv_data
{
  uint16_t prio GNUNET_PACKED;
  uint16_t weight GNUNET_PACKED;
  uint16_t port GNUNET_PACKED;
};
GNUNET_NETWORK_STRUCT_END

static void
do_lookup(void *cls, const struct GNUNET_PeerIdentity *id,
          const struct GNUNET_CONFIGURATION_Handle *_cfg,
          struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded alice_pkey;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded bob_pkey;
  struct GNUNET_CRYPTO_RsaPrivateKey *alice_key;
  struct GNUNET_CRYPTO_RsaPrivateKey *bob_key;
  struct GNUNET_CRYPTO_ShortHashCode bob_hash;
  struct GNUNET_CRYPTO_RsaSignature *sig;
  char* alice_keyfile;
  struct srv_data *srv_data;
  struct GNUNET_TIME_Absolute et;

  cfg = _cfg;

  GNUNET_SCHEDULER_cancel (die_task);

  /* put records into namestore */
  namestore_handle = GNUNET_NAMESTORE_connect(cfg);
  if (NULL == namestore_handle)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to connect to namestore\n");
    ok = -1;
    return;
  }

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (cfg, "gns",
                                                          "ZONEKEY",
                                                          &alice_keyfile))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to get key from cfg\n");
    ok = -1;
    return;
  }

  alice_key = GNUNET_CRYPTO_rsa_key_create_from_file (alice_keyfile);
  bob_key = GNUNET_CRYPTO_rsa_key_create_from_file (KEYFILE_BOB);

  GNUNET_CRYPTO_rsa_key_get_public (alice_key, &alice_pkey);
  GNUNET_CRYPTO_rsa_key_get_public (bob_key, &bob_pkey);

  struct GNUNET_NAMESTORE_RecordData rd;
  char* ip = TEST_IP;
  struct in_addr *sipserver = GNUNET_malloc (sizeof (struct in_addr));
  srv_data = GNUNET_malloc (sizeof (struct srv_data) + strlen (TEST_SRV_NAME) + 1);
  uint16_t srv_weight = 60;
  uint16_t srv_prio = 50;
  uint16_t srv_port = 5060;

  rd.expiration_time = UINT64_MAX;
  GNUNET_assert(1 == inet_pton (AF_INET, ip, sipserver));
  
  GNUNET_CRYPTO_short_hash(&bob_pkey, sizeof(bob_pkey), &bob_hash);

  rd.data_size = sizeof(struct GNUNET_CRYPTO_ShortHashCode);
  rd.data = &bob_hash;
  rd.record_type = GNUNET_GNS_RECORD_PKEY;
  rd.flags = GNUNET_NAMESTORE_RF_AUTHORITY;

  GNUNET_NAMESTORE_record_create (namestore_handle,
                                  alice_key,
                                  TEST_AUTHORITY_NAME,
                                  &rd,
                                  NULL,
                                  NULL);

  rd.data_size = sizeof (struct in_addr);
  rd.data = sipserver;
  rd.record_type = GNUNET_DNSPARSER_TYPE_A;
  sig = GNUNET_NAMESTORE_create_signature(bob_key,
                                          GNUNET_TIME_UNIT_FOREVER_ABS,
                                          TEST_RECORD_NAME,
                                          &rd, 1);
  et.abs_value = rd.expiration_time;
  GNUNET_NAMESTORE_record_put (namestore_handle,
                               &bob_pkey,
                               TEST_RECORD_NAME,
                               et,
                               1,
                               &rd,
                               sig,
                               NULL,
                               NULL);
  
  rd.data_size = sizeof (struct srv_data)+strlen(TEST_SRV_NAME)+1;
  srv_data->port = srv_port;
  srv_data->prio = srv_prio;
  srv_data->weight = srv_weight;
  strcpy((char*)&srv_data[1], TEST_SRV_NAME);
  rd.data = srv_data;
  rd.record_type = GNUNET_GNS_RECORD_TYPE_SRV;
  sig = GNUNET_NAMESTORE_create_signature(bob_key,
                                          GNUNET_TIME_UNIT_FOREVER_ABS,
                                          TEST_RECORD_NAME_SRV,
                                          &rd, 1);
  et.abs_value = rd.expiration_time;
  GNUNET_NAMESTORE_record_put (namestore_handle,
                               &bob_pkey,
                               TEST_RECORD_NAME_SRV,
                               et,
                               1,
                               &rd,
                               sig,
                               &commence_testing,
                               NULL);
  GNUNET_free(srv_data);
  GNUNET_free(sipserver);
  GNUNET_free(sig);
  GNUNET_CRYPTO_rsa_key_free(bob_key);
  GNUNET_CRYPTO_rsa_key_free(alice_key);
}

static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  cfg = c;
   /* Get path from configuration file */
  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "paths", "servicehome",
                                             &test_directory))
  {
    ok = 404;
    return;
  }

    
  /* Set up a task to end testing if peer start fails */
  die_task =
      GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly,
                                    "didn't start all daemons in reasonable amount of time!!!");
  
  /* Start alice */
  pg = GNUNET_TESTING_daemons_start(cfg, 1, 1, 1, TIMEOUT,
                                    NULL, NULL, &do_lookup, NULL,
                                    NULL, NULL, NULL);
}

static int
check ()
{
  int ret;

  /* Arguments for GNUNET_PROGRAM_run */
  char *const argv[] = { "test-gns-simple-mx-lookup", /* Name to give running binary */
    "-c",
    "test_gns_simple_lookup.conf",       /* Config file to use */
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  /* Run the run function as a new program */
  ret =
      GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv,
                          "test-gns-simple-mx-lookup", "nohelp", options, &run,
                          &ok);
  if (ret != GNUNET_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "`test-gns-simple-mx-lookup': Failed with error code %d\n", ret);
  }
  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-gns-simple-mx-lookup",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();
  /**
   * Need to remove base directory, subdirectories taken care
   * of by the testing framework.
   */
  return ret;
}

/* end of test_gns_simple_mx_lookup.c */
