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
 * @file gns/test_gns_twopeer.c
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
#include "gnunet_dnsparser_lib.h"
#include "gnunet_gns_service.h"

/* DEFINES */
#define VERBOSE GNUNET_YES

/* Timeout for entire testcase */
#define TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 10)

/* If number of peers not in config file, use this number */
#define DEFAULT_NUM_PEERS 2

/* test records to resolve */
#define TEST_DOMAIN "www.gnunet"
#define TEST_IP "127.0.0.1"
#define TEST_RECORD_NAME "www"

/* Globals */

/**
 * Directory to store temp data in, defined in config file
 */
static char *test_directory;

struct GNUNET_TESTING_Daemon *d1;


/* Task handle to use to schedule test failure */
GNUNET_SCHEDULER_TaskIdentifier die_task;

/* Global return value (0 for success, anything else for failure) */
static int ok;

static struct GNUNET_NAMESTORE_Handle *namestore_handle;

const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Check whether peers successfully shut down.
 */
void
shutdown_callback (void *cls, const char *emsg)
{
  if (emsg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Error on shutdown!\n", ok);
    if (ok == 0)
      ok = 2;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "done(ret=%d)!\n", ok);
}

/**
 * Function scheduled to be run on the successful start of services
 * tries to look up the dns record for TEST_DOMAIN
 */
static void
finish_testing (void *cls, int32_t success, const char *emsg)
{
  struct hostent *he;
  struct in_addr a;
  char* addr;
  
  GNUNET_NAMESTORE_disconnect(namestore_handle, GNUNET_YES);

  he = gethostbyname (TEST_DOMAIN);

  if (!he)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "gethostbyname failed, rp_filtering?\n");
    ok = 2;
  }
  else
  {
    ok = 1;
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "name: %s\n", he->h_name);
    while (*he->h_addr_list)
    {
      memcpy(&a, *he->h_addr_list++, sizeof(a));
      addr = inet_ntoa(a);
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "address: %s\n", addr);
      if (0 == strcmp(addr, TEST_IP))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                    "%s correctly resolved to %s!\n", TEST_DOMAIN, addr);
        ok = 0;
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No resolution!\n");
      }
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Shutting down peer1!\n");
  GNUNET_TESTING_daemon_stop (d1, TIMEOUT, &shutdown_callback, NULL,
                              GNUNET_YES, GNUNET_NO);
}

/**
 * Continuation for the GNUNET_DHT_get_stop call, so that we don't shut
 * down the peers without freeing memory associated with GET request.
 */
static void
end_badly_cont (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{

  if (d1 != NULL)
    GNUNET_TESTING_daemon_stop (d1, TIMEOUT, &shutdown_callback, NULL,
                                GNUNET_YES, GNUNET_NO);
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

static void
do_lookup(void *cls, const struct GNUNET_PeerIdentity *id,
          const struct GNUNET_CONFIGURATION_Handle *cfg,
          struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded alice_pkey;
  struct GNUNET_CRYPTO_RsaPrivateKey *alice_key;
  char* alice_keyfile;

  GNUNET_SCHEDULER_cancel (die_task);

  /* put records into namestore */
  namestore_handle = GNUNET_NAMESTORE_connect(cfg);
  if (NULL == namestore_handle)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to connect to namestore\n");
    ok = -1;
    return;
  }

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (cfg, "gns",
                                                          "ZONEKEY",
                                                          &alice_keyfile))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to get key from cfg\n");
    ok = -1;
    return;
  }

  alice_key = GNUNET_CRYPTO_rsa_key_create_from_file (alice_keyfile);

  GNUNET_CRYPTO_rsa_key_get_public (alice_key, &alice_pkey);

  struct GNUNET_NAMESTORE_RecordData rd;
  char* ip = TEST_IP;
  struct in_addr *web = GNUNET_malloc(sizeof(struct in_addr));
  rd.expiration = GNUNET_TIME_absolute_get_forever ();
  GNUNET_assert(1 == inet_pton (AF_INET, ip, web));
  rd.data_size = sizeof(struct in_addr);
  rd.data = web;
  rd.record_type = GNUNET_DNSPARSER_TYPE_A;

  GNUNET_NAMESTORE_record_create (namestore_handle,
                                  alice_key,
                                  TEST_RECORD_NAME,
                                  &rd,
                                  &finish_testing,
                                  NULL);

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
  d1 = GNUNET_TESTING_daemon_start(cfg, TIMEOUT, GNUNET_NO, NULL, NULL, 0,
                                   NULL, NULL, NULL, &do_lookup, NULL);
}

static int
check ()
{
  int ret;

  /* Arguments for GNUNET_PROGRAM_run */
  char *const argv[] = { "test-gns-simple-lookup", /* Name to give running binary */
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
                          "test-gns-simple-lookup", "nohelp", options, &run,
                          &ok);
  if (ret != GNUNET_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "`test-gns-simple-lookup': Failed with error code %d\n", ret);
  }
  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-gns-simple-lookup",
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

/* end of test_gns_twopeer.c */
