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
 * @file gns/test_gns_dht_threepeer.c
 * @brief tests dht lookup over 3 peers
 *
 * topology:
 * alice <----> bob <-----> dave
 *
 * alice queries for www.buddy.bob.gnunet
 *
 */
#include "platform.h"
#include "gnunet_disk_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_dht_service.h"
#include "block_dns.h"
#include "gnunet_signatures.h"
#include "gnunet_namestore_service.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_gns_service.h"

/* DEFINES */
#define VERBOSE GNUNET_YES

/* Timeout for entire testcase */
#define TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 180)
#define ZONE_PUT_WAIT_TIME GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 30)

/* If number of peers not in config file, use this number */
#define DEFAULT_NUM_PEERS 2

#define TEST_DOMAIN "www.buddy.bob.gnunet"
#define TEST_IP "1.1.1.1"
#define TEST_DAVE_PSEU "hagbard"
#define TEST_NUM_PEERS 3
#define TEST_NUM_CON 3

/* Globals */

/**
 * Directory to store temp data in, defined in config file
 */
static char *test_directory;

/**
 * Variable used to store the number of connections we should wait for.
 */
static unsigned int expected_connections;

/**
 * Variable used to keep track of how many peers aren't yet started.
 */
static unsigned long long peers_left;

struct GNUNET_TESTING_Daemon *d1;
struct GNUNET_TESTING_Daemon *d2;
struct GNUNET_TESTING_Daemon *d3;


/**
 * Total number of peers to run, set based on config file.
 */
static unsigned long long num_peers;

/**
 * Global used to count how many connections we have currently
 * been notified about (how many times has topology_callback been called
 * with success?)
 */
static unsigned int total_connections;

/**
 * Global used to count how many failed connections we have
 * been notified about (how many times has topology_callback
 * been called with failure?)
 */
static unsigned int failed_connections;

/* Task handle to use to schedule test failure */
GNUNET_SCHEDULER_TaskIdentifier die_task;

GNUNET_SCHEDULER_TaskIdentifier bob_task;

/* Global return value (0 for success, anything else for failure) */
static int ok;

int bob_online, alice_online, dave_online;

const struct GNUNET_CONFIGURATION_Handle *alice_cfg;
struct GNUNET_CONFIGURATION_Handle *cfg_bob;
struct GNUNET_CONFIGURATION_Handle *cfg_dave;

struct GNUNET_CRYPTO_ShortHashCode bob_hash;
struct GNUNET_CRYPTO_ShortHashCode dave_hash;
struct GNUNET_TESTING_Daemon *alice_daemon;
struct GNUNET_TESTING_Daemon *bob_daemon;
struct GNUNET_TESTING_Daemon *dave_daemon;

struct GNUNET_TESTING_PeerGroup *pg;
struct GNUNET_GNS_Handle *gh;

/**
 * Function scheduled to be run on the successful completion of this
 * testcase.  Specifically, called when our get request completes.
 */
static void
finish_testing (void *cls, const char *emsg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Test finished! (ret=%d)\n", ok);
}

/**
 * Continuation for the GNUNET_DHT_get_stop call, so that we don't shut
 * down the peers without freeing memory associated with GET request.
 */
static void
end_badly_cont (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  die_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &finish_testing, NULL);
}

/**
 * Check if the get_handle is being used, if so stop the request.  Either
 * way, schedule the end_badly_cont function which actually shuts down the
 * test.
 */
static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  die_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Failing test with error: `%s'!\n",
              (char *) cls);
  die_task = GNUNET_SCHEDULER_add_now (&end_badly_cont, NULL);
  ok = 1;
}


static void
on_lookup_result(void *cls, uint32_t rd_count,
                 const struct GNUNET_NAMESTORE_RecordData *rd)
{
  int i;
  char* string_val;
  const char* typename;

  if (rd_count == 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Lookup failed!\n");
    ok = 2;
  }
  else
  {
    ok = 1;
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "name: %s\n", (char*)cls);
    for (i=0; i<rd_count; i++)
    {
      typename = GNUNET_NAMESTORE_number_to_typename (rd[i].record_type);
      string_val = GNUNET_NAMESTORE_value_to_string(rd[i].record_type,
                                                    rd[i].data,
                                                    rd[i].data_size);
      printf("Got %s record: %s\n", typename, string_val);
      if (0 == strcmp(string_val, TEST_IP))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                    "%s correctly resolved to %s!\n", TEST_DOMAIN, string_val);
        ok = 0;
      }
    }
  }
  GNUNET_GNS_disconnect(gh);
  GNUNET_SCHEDULER_cancel(die_task);
  die_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &finish_testing, NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Shutting down!\n");

}

static void
commence_testing(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  

  gh = GNUNET_GNS_connect(alice_cfg);

  GNUNET_GNS_lookup(gh, TEST_DOMAIN, GNUNET_GNS_RECORD_TYPE_A,
                    &on_lookup_result, TEST_DOMAIN);
  die_task =
    GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, "from lookup");
}


/**
 * This function is called whenever a connection attempt is finished between two of
 * the started peers (started with GNUNET_TESTING_daemons_start).  The total
 * number of times this function is called should equal the number returned
 * from the GNUNET_TESTING_connect_topology call.
 *
 * The emsg variable is NULL on success (peers connected), and non-NULL on
 * failure (peers failed to connect).
 */
void
daemon_connected (void *cls, const struct GNUNET_PeerIdentity *first,
                   const struct GNUNET_PeerIdentity *second, uint32_t distance,
                   const struct GNUNET_CONFIGURATION_Handle *first_cfg,
                   const struct GNUNET_CONFIGURATION_Handle *second_cfg,
                   struct GNUNET_TESTING_Daemon *first_daemon,
                   struct GNUNET_TESTING_Daemon *second_daemon,
                   const char *emsg)
{
  if (emsg == NULL)
  {
    total_connections++;
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "connected peer %s to peer %s, distance %u\n",
                first_daemon->shortname, second_daemon->shortname, distance);
#endif
  }
#if VERBOSE
  else
  {
    failed_connections++;
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Failed to connect peer %s to peer %s with error :\n%s\n",
                first_daemon->shortname, second_daemon->shortname, emsg);
  }
#endif

  if (total_connections == expected_connections)
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Created %d total connections, which is our target number!  Starting next phase of testing.\n",
                total_connections);
#endif
    GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_NO_TASK;
    //die_task =
    //    GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, "from connect");
   
    //commence_testing();
    
  }
  else if (total_connections + failed_connections == expected_connections)
  {
    GNUNET_SCHEDULER_cancel (die_task);
    die_task =
        GNUNET_SCHEDULER_add_now (&end_badly,
                                  "from topology_callback (too many failed connections)");
  }
}

void
all_connected(void *cls, const char *emsg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Created all connections!  Starting next phase of testing.\n");
  GNUNET_SCHEDULER_add_delayed (ZONE_PUT_WAIT_TIME, &commence_testing, NULL);
}

void
ns_create_cont(void *cls, int32_t s, const char *emsg)
{
  GNUNET_NAMESTORE_disconnect((struct GNUNET_NAMESTORE_Handle *)cls, 0);
}

static void
daemon_started (void *cls, const struct GNUNET_PeerIdentity *id,
                const struct GNUNET_CONFIGURATION_Handle *cfg,
                struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  struct GNUNET_NAMESTORE_Handle *ns;
  char* keyfile;
  struct GNUNET_CRYPTO_RsaPrivateKey *key;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pkey;
  struct in_addr *web;
  struct GNUNET_NAMESTORE_RecordData rd;

  rd.flags = GNUNET_NAMESTORE_RF_AUTHORITY | GNUNET_NAMESTORE_RF_NONE;
  rd.expiration = GNUNET_TIME_UNIT_FOREVER_ABS;
  
  if (NULL == dave_daemon)
  {
    if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (cfg, "gns",
                                                              "ZONEKEY",
                                                              &keyfile))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to get key from cfg\n");
      ok = -1;
      return;
    }
    dave_daemon = d;

    key = GNUNET_CRYPTO_rsa_key_create_from_file (keyfile);

    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "This is now dave\n");
    ns = GNUNET_NAMESTORE_connect(cfg);
    
    GNUNET_CRYPTO_rsa_key_get_public (key, &pkey);
    GNUNET_CRYPTO_short_hash(&pkey, sizeof(pkey), &dave_hash);
    
    web = GNUNET_malloc(sizeof(struct in_addr));
    GNUNET_assert(1 == inet_pton (AF_INET, TEST_IP, web));
    rd.data_size = sizeof(struct in_addr);
    rd.data = web;
    rd.record_type = GNUNET_GNS_RECORD_TYPE_A;

    GNUNET_NAMESTORE_record_create (ns, key, "www", &rd, NULL, NULL);

    rd.data_size = strlen(TEST_DAVE_PSEU);
    rd.data = TEST_DAVE_PSEU;
    rd.record_type = GNUNET_GNS_RECORD_PSEU;

    GNUNET_NAMESTORE_record_create (ns, key, "+", &rd, ns_create_cont, ns);

    GNUNET_CRYPTO_rsa_key_free(key);
    GNUNET_free(keyfile);
    GNUNET_free(web);

    return;
  }
  
  
  if (NULL == bob_daemon)
  {
    if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (cfg, "gns",
                                                              "ZONEKEY",
                                                              &keyfile))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to get key from cfg\n");
      ok = -1;
      return;
    }
    bob_daemon = d;

    key = GNUNET_CRYPTO_rsa_key_create_from_file (keyfile);

    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "This is now bob\n");
    ns = GNUNET_NAMESTORE_connect(cfg);
    
    GNUNET_CRYPTO_rsa_key_get_public (key, &pkey);
    GNUNET_CRYPTO_short_hash(&pkey, sizeof(pkey), &bob_hash);
    
    rd.data_size = sizeof(struct GNUNET_CRYPTO_ShortHashCode);
    rd.data = &dave_hash;
    rd.record_type = GNUNET_GNS_RECORD_PKEY;

    GNUNET_NAMESTORE_record_create (ns, key, "buddy", &rd, ns_create_cont, ns);

    GNUNET_CRYPTO_rsa_key_free(key);
    GNUNET_free(keyfile);

    return;
  }

  
  
  if (NULL == alice_daemon)
  {

    if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (cfg, "gns",
                                                              "ZONEKEY",
                                                              &keyfile))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Failed to get key from cfg\n");
      ok = -1;
      return;
    }
    alice_daemon = d;
    alice_cfg = cfg;

    key = GNUNET_CRYPTO_rsa_key_create_from_file (keyfile);

    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "This is now alice\n");
    ns = GNUNET_NAMESTORE_connect(cfg);
    
    rd.data_size = sizeof(struct GNUNET_CRYPTO_ShortHashCode);
    rd.data = &bob_hash;
    rd.record_type = GNUNET_GNS_RECORD_PKEY;

    GNUNET_NAMESTORE_record_create (ns, key, "bob", &rd, ns_create_cont, ns);

    GNUNET_CRYPTO_rsa_key_free(key);
    GNUNET_free(keyfile);

    GNUNET_TESTING_connect_topology (pg, GNUNET_TESTING_TOPOLOGY_CLIQUE,
                                     GNUNET_TESTING_TOPOLOGY_OPTION_ALL,
                                     0,
                                     TIMEOUT,
                                     3,
                                     &all_connected, NULL);
    return;

  }

  

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "This is a random guy\n");
}

static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{

  /* Get path from configuration file */
  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "paths", "servicehome",
                                             &test_directory))
  {
    ok = 404;
    return;
  }

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "starting\n");

  /* Get number of peers to start from configuration (should be two) */
  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "testing", "num_peers",
                                             &num_peers))
    num_peers = DEFAULT_NUM_PEERS;

  /* Set peers_left so we know when all peers started */
  peers_left = num_peers;
  
  bob_daemon = NULL;
  dave_daemon = NULL;
  alice_daemon = NULL;

  pg = GNUNET_TESTING_daemons_start (cfg, TEST_NUM_PEERS, TEST_NUM_CON,
                                TEST_NUM_CON, TIMEOUT, NULL, NULL, &daemon_started, NULL,
                                &daemon_connected, NULL, NULL);
  
  /* Set up a task to end testing if peer start fails */
  die_task =
      GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly,
                                    "didn't start all daemons in reasonable amount of time!!!");
  
  alice_online = 0;
  bob_online = 0;
  dave_online = 0;
  expected_connections = 2;
  
  /* Start alice */
  //d1 = GNUNET_TESTING_daemon_start(cfg_alice, TIMEOUT, GNUNET_NO, NULL, NULL, 0,
  //                                 NULL, NULL, NULL, &alice_started, NULL);
  
  


}

static int
check ()
{
  int ret;

  /* Arguments for GNUNET_PROGRAM_run */
  char *const argv[] = { "test-gns-twopeer",    /* Name to give running binary */
    "-c",
    "test_gns_dht_default.conf",       /* Config file to use */
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
                          "test-gns-threepeer", "nohelp", options, &run,
                          &ok);
  if (ret != GNUNET_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "`test-gns-threepeer': Failed with error code %d\n", ret);
  }
  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-gns-threepeer",
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

/* end of test_gns_threepeer.c */
