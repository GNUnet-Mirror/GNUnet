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
#define TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 80)

/* If number of peers not in config file, use this number */
#define DEFAULT_NUM_PEERS 2

#define TEST_DOMAIN "www.buddy.bob.gnunet"
#define TEST_IP "1.1.1.1"

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

struct GNUNET_CONFIGURATION_Handle *cfg_alice;
struct GNUNET_CONFIGURATION_Handle *cfg_bob;
struct GNUNET_CONFIGURATION_Handle *cfg_dave;

/**
 * Check whether peers successfully shut down.
 */
void
shutdown_callback (void *cls, const char *emsg)
{
  if (emsg != NULL)
  {
    if (ok == 0)
      ok = 2;
  }
}

/**
 * Function scheduled to be run on the successful completion of this
 * testcase.  Specifically, called when our get request completes.
 */
static void
finish_testing (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  ok = 0;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Shutting down alice!\n");
  GNUNET_TESTING_daemon_stop (d1, TIMEOUT, &shutdown_callback, NULL,
                              GNUNET_YES, GNUNET_NO);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Shutting down bob!\n");
  GNUNET_TESTING_daemon_stop (d2, TIMEOUT, &shutdown_callback, NULL,
                              GNUNET_YES, GNUNET_NO);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Shutting down dave\n");
  GNUNET_TESTING_daemon_stop (d3, TIMEOUT, &shutdown_callback, NULL,
                              GNUNET_YES, GNUNET_NO);
  GNUNET_DISK_file_copy ("testdb/sqlite-alice.db.bak",
                         "testdb/sqlite-alice.db.bak");
  GNUNET_SCHEDULER_cancel(die_task);
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
  if (d2 != NULL)
    GNUNET_TESTING_daemon_stop (d2, TIMEOUT, &shutdown_callback, NULL,
                                GNUNET_YES, GNUNET_NO);
;
  if (d3 != NULL)
    GNUNET_TESTING_daemon_stop (d3, TIMEOUT, &shutdown_callback, NULL,
                                GNUNET_YES, GNUNET_NO);
}

/**
 * Check if the get_handle is being used, if so stop the request.  Either
 * way, schedule the end_badly_cont function which actually shuts down the
 * test.
 */
static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Failing test with error: `%s'!\n",
              (char *) cls);
  GNUNET_SCHEDULER_add_now (&end_badly_cont, NULL);
  ok = 1;
}

static void
commence_testing(void)
{
  struct hostent *he;
  struct in_addr a;
  char* addr;

  he = gethostbyname (TEST_DOMAIN);

  if (he)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_INFO, "name: %s\n", he->h_name);
    while (*he->h_addr_list)
    {
      bcopy(*he->h_addr_list++, (char *) &a, sizeof(a));
      addr = inet_ntoa(a);
      GNUNET_log(GNUNET_ERROR_TYPE_INFO, "address: %s\n", addr);
      if (strcmp(addr, TEST_IP) == 0)
        ok = 0;
    }
  }
  else
    ok = 1;
  //do lookup here
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                (GNUNET_TIME_UNIT_SECONDS, 30),
                                 &finish_testing, NULL);
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
notify_connect (void *cls, const struct GNUNET_PeerIdentity *first,
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
    die_task =
        GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly, "from connect");
    commence_testing();
    
  }
  else if (total_connections + failed_connections == expected_connections)
  {
    GNUNET_SCHEDULER_cancel (die_task);
    die_task =
        GNUNET_SCHEDULER_add_now (&end_badly,
                                  "from topology_callback (too many failed connections)");
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Connecting peers dave, bob\n");
    GNUNET_TESTING_daemons_connect (d3, d2, TIMEOUT, 5, 1,
                                         &notify_connect, NULL);
  }
}

/**
 * Set up some data, and call API PUT function
 */
static void
connect_ab (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Connecting peers alice, bob\n");
  GNUNET_TESTING_daemons_connect (d1, d2, TIMEOUT, 5, 1,
                                         &notify_connect, NULL);
}


static void
dave_started (void *cls, const struct GNUNET_PeerIdentity *id,
                        const struct GNUNET_CONFIGURATION_Handle *cfg,
                        struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  if (emsg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Failed to start daemon with error: `%s'\n", emsg);
    return;
  }
  GNUNET_assert (id != NULL);
  
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                (GNUNET_TIME_UNIT_SECONDS, 2),
                                &connect_ab, NULL);
}



static void
bob_started (void *cls, const struct GNUNET_PeerIdentity *id,
                        const struct GNUNET_CONFIGURATION_Handle *cfg,
                        struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  if (emsg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Failed to start daemon with error: `%s'\n", emsg);
    return;
  }
  GNUNET_assert (id != NULL);
  
  //Start bob
  d3 = GNUNET_TESTING_daemon_start(cfg_dave, TIMEOUT, GNUNET_NO, NULL, NULL, 0,
                                   NULL, NULL, NULL, &dave_started, NULL);

}



/**
 * Callback which is called whenever a peer is started (as a result of the
 * GNUNET_TESTING_daemons_start call.
 *
 * @param cls closure argument given to GNUNET_TESTING_daemons_start
 * @param id the GNUNET_PeerIdentity of the started peer
 * @param cfg the configuration for this specific peer (needed to connect
 *            to the DHT)
 * @param d the handle to the daemon started
 * @param emsg NULL if peer started, non-NULL on error
 */
static void
alice_started (void *cls, const struct GNUNET_PeerIdentity *id,
                        const struct GNUNET_CONFIGURATION_Handle *cfg,
                        struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  if (emsg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Failed to start daemon with error: `%s'\n", emsg);
    return;
  }
  GNUNET_assert (id != NULL);
  
  //Start bob
  d2 = GNUNET_TESTING_daemon_start(cfg_bob, TIMEOUT, GNUNET_NO, NULL, NULL, 0,
                                   NULL, NULL, NULL, &bob_started, NULL);
  
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

  /* Get number of peers to start from configuration (should be two) */
  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "testing", "num_peers",
                                             &num_peers))
    num_peers = DEFAULT_NUM_PEERS;

  /* Set peers_left so we know when all peers started */
  peers_left = num_peers;
  
  /**
   * Modify some config options for peers
   */
  cfg_alice = GNUNET_CONFIGURATION_create();
  GNUNET_CONFIGURATION_load (cfg_alice, "test_gns_dht_alice.conf");

  cfg_bob = GNUNET_CONFIGURATION_create();
  GNUNET_CONFIGURATION_load (cfg_bob, "test_gns_dht_bob.conf");
  
  cfg_dave = GNUNET_CONFIGURATION_create();
  GNUNET_CONFIGURATION_load (cfg_dave, "test_gns_dht_dave.conf");

  GNUNET_CONFIGURATION_load (cfg_alice, "test_gns_dht_alice.conf");
  GNUNET_CONFIGURATION_load (cfg_bob, "test_gns_dht_bob.conf");
  GNUNET_CONFIGURATION_load (cfg_dave, "test_gns_dht_dave.conf");

  /* Set up a task to end testing if peer start fails */
  die_task =
      GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly,
                                    "didn't start all daemons in reasonable amount of time!!!");
  
  alice_online = 0;
  bob_online = 0;
  dave_online = 0;
  expected_connections = 2;
  
  /* Start alice */
  d1 = GNUNET_TESTING_daemon_start(cfg_alice, TIMEOUT, GNUNET_NO, NULL, NULL, 0,
                                   NULL, NULL, NULL, &alice_started, NULL);
  
  


}

static int
check ()
{
  int ret;

  /* Arguments for GNUNET_PROGRAM_run */
  char *const argv[] = { "test-gns-twopeer",    /* Name to give running binary */
    "-c",
    "test_gns_twopeer.conf",       /* Config file to use */
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
                          "test-gns-twopeer", "nohelp", options, &run,
                          &ok);
  if (ret != GNUNET_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "`test-gns-twopeer': Failed with error code %d\n", ret);
  }
  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-gns-twopeer",
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
