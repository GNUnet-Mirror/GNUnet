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
 * @file dht/test_dht_multipeer.c
 * @brief testcase for testing DHT service with
 *        multiple peers.
 */
#include "platform.h"
#include "gnunet_testing_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_dht_service.h"

/* DEFINES */
#define VERBOSE GNUNET_NO

/* Timeout for entire testcase */
#define TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 5)

/* Timeout for waiting for replies to get requests */
#define GET_TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 90)

/* Timeout for waiting for gets to complete */
#define GET_DELAY GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 1)

/* Timeout for waiting for puts to complete */
#define PUT_DELAY GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 1)

#define SECONDS_PER_PEER_START 45

/* If number of peers not in config file, use this number */
#define DEFAULT_NUM_PEERS 5

#define TEST_DATA_SIZE 8

#define MAX_OUTSTANDING_PUTS 10

#define MAX_OUTSTANDING_GETS 10

#define PATH_TRACKING GNUNET_YES

/* Structs */

struct TestPutContext
{
  /**
   * This is a linked list 
   */
  struct TestPutContext *next;

  /**
   * Handle to the first peers DHT service (via the API)
   */
  struct GNUNET_DHT_Handle *dht_handle;

  /**
   *  Handle to the PUT peer daemon
   */
  struct GNUNET_TESTING_Daemon *daemon;

  /**
   *  Identifier for this PUT
   */
  uint32_t uid;

  /**
   * Task for disconnecting DHT handles
   */
  GNUNET_SCHEDULER_TaskIdentifier disconnect_task;
};

struct TestGetContext
{
  /* This is a linked list */
  struct TestGetContext *next;

  /**
   * Handle to the first peers DHT service (via the API)
   */
  struct GNUNET_DHT_Handle *dht_handle;

  /**
   * Handle for the DHT get request
   */
  struct GNUNET_DHT_GetHandle *get_handle;

  /**
   *  Handle to the GET peer daemon
   */
  struct GNUNET_TESTING_Daemon *daemon;

  /**
   *  Identifier for this GET
   */
  uint32_t uid;

  /**
   * Task for disconnecting DHT handles (and stopping GET)
   */
  GNUNET_SCHEDULER_TaskIdentifier disconnect_task;

  /**
   * Whether or not this request has been fulfilled already.
   */
  int succeeded;
};

/* Globals */

/**
 * List of GETS to perform
 */
struct TestGetContext *all_gets;

/**
 * List of PUTS to perform
 */
struct TestPutContext *all_puts;

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

/**
 * Handle to the set of all peers run for this test.
 */
static struct GNUNET_TESTING_PeerGroup *pg;


/**
 * Total number of peers to run, set based on config file.
 */
static unsigned long long num_peers;

/**
 * Total number of items to insert.
 */
static unsigned long long num_puts;

/**
 * Total number of items to attempt to get.
 */
static unsigned long long num_gets;

/**
 * How many puts do we currently have in flight?
 */
static unsigned long long outstanding_puts;

/**
 * How many puts are done?
 */
static unsigned long long puts_completed;

/**
 * How many puts do we currently have in flight?
 */
static unsigned long long outstanding_gets;

/**
 * How many gets are done?
 */
static unsigned long long gets_completed;

/**
 * How many gets failed?
 */
static unsigned long long gets_failed;

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

enum GNUNET_DHT_RouteOption route_option;

/* Task handle to use to schedule test failure */
GNUNET_SCHEDULER_TaskIdentifier die_task;

static char *blacklist_transports;

static enum GNUNET_TESTING_Topology topology;

static enum GNUNET_TESTING_Topology blacklist_topology = GNUNET_TESTING_TOPOLOGY_NONE;  /* Don't do any blacklisting */

static enum GNUNET_TESTING_Topology connection_topology = GNUNET_TESTING_TOPOLOGY_NONE; /* NONE actually means connect all allowed peers */

static enum GNUNET_TESTING_TopologyOption connect_topology_option =
    GNUNET_TESTING_TOPOLOGY_OPTION_ALL;

static double connect_topology_option_modifier = 0.0;

/* Global return value (0 for success, anything else for failure) */
static int ok;

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
 * Task to release DHT handles for PUT
 */
static void
put_disconnect_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct TestPutContext *test_put = cls;

  test_put->disconnect_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_DHT_disconnect (test_put->dht_handle);
  test_put->dht_handle = NULL;
}

/**
 * Function scheduled to be run on the successful completion of this
 * testcase.
 */
static void
finish_testing (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_assert (pg != NULL);
  struct TestPutContext *test_put = all_puts;
  struct TestGetContext *test_get = all_gets;

  while (test_put != NULL)
  {
    if (test_put->disconnect_task != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (test_put->disconnect_task);
    if (test_put->dht_handle != NULL)
      GNUNET_DHT_disconnect (test_put->dht_handle);
    test_put = test_put->next;
  }

  while (test_get != NULL)
  {
    if (test_get->disconnect_task != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (test_get->disconnect_task);
    if (test_get->get_handle != NULL)
      GNUNET_DHT_get_stop (test_get->get_handle);
    if (test_get->dht_handle != NULL)
      GNUNET_DHT_disconnect (test_get->dht_handle);
    test_get = test_get->next;
  }

  GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
  ok = 0;
}


/**
 * Check if the get_handle is being used, if so stop the request.  Either
 * way, schedule the end_badly_cont function which actually shuts down the
 * test.
 */
static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Failing test with error: `%s'!\n",
              (char *) cls);

  struct TestPutContext *test_put = all_puts;
  struct TestGetContext *test_get = all_gets;

  while (test_put != NULL)
  {
    if (test_put->disconnect_task != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (test_put->disconnect_task);
    if (test_put->dht_handle != NULL)
      GNUNET_DHT_disconnect (test_put->dht_handle);
    test_put = test_put->next;
  }

  while (test_get != NULL)
  {
    if (test_get->disconnect_task != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (test_get->disconnect_task);
    if (test_get->get_handle != NULL)
      GNUNET_DHT_get_stop (test_get->get_handle);
    if (test_get->dht_handle != NULL)
      GNUNET_DHT_disconnect (test_get->dht_handle);
    test_get = test_get->next;
  }

  GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
  ok = 1;
}

/**
 * Task to release DHT handle associated with GET request.
 */
static void
get_stop_finished (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct TestGetContext *test_get = cls;

  outstanding_gets--;           /* GET is really finished */
  GNUNET_DHT_disconnect (test_get->dht_handle);
  test_get->dht_handle = NULL;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%d gets succeeded, %d gets failed!\n",
              gets_completed, gets_failed);
  if ((gets_completed == num_gets) && (outstanding_gets == 0))  /* All gets successful */
  {
    GNUNET_SCHEDULER_cancel (die_task);
    //GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 5), &get_topology, NULL);
    GNUNET_SCHEDULER_add_now (&finish_testing, NULL);
  }
  else if ((gets_completed + gets_failed == num_gets) && (outstanding_gets == 0))       /* Had some failures */
  {
    GNUNET_SCHEDULER_cancel (die_task);
    GNUNET_SCHEDULER_add_now (&end_badly, "not all gets succeeded!\n");
  }
}

/**
 * Task to release get handle.
 */
static void
get_stop_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct TestGetContext *test_get = cls;
  GNUNET_HashCode search_key;   /* Key stored under */
  char original_data[TEST_DATA_SIZE];   /* Made up data to store */

  memset (original_data, test_get->uid, sizeof (original_data));
  GNUNET_CRYPTO_hash (original_data, TEST_DATA_SIZE, &search_key);

  if ((tc->reason & GNUNET_SCHEDULER_REASON_TIMEOUT) != 0)
  {
    gets_failed++;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Get from peer %s for key %s failed!\n",
                test_get->daemon->shortname, GNUNET_h2s (&search_key));
  }
  GNUNET_assert (test_get->get_handle != NULL);
  GNUNET_DHT_get_stop (test_get->get_handle);
  GNUNET_SCHEDULER_add_now (&get_stop_finished, test_get);
  test_get->get_handle = NULL;
  test_get->disconnect_task = GNUNET_SCHEDULER_NO_TASK;
}

/**
 * Iterator called if the GET request initiated returns a response.
 *
 * @param cls closure
 * @param exp when will this value expire
 * @param key key of the result
 * @param type type of the result
 * @param size number of bytes in data
 * @param data pointer to the result data
 */
void
get_result_iterator (void *cls,
                     struct GNUNET_TIME_Absolute exp,
                     const GNUNET_HashCode * key,
                     const struct GNUNET_PeerIdentity *const *get_path,
                     const struct GNUNET_PeerIdentity *const *put_path,
                     enum GNUNET_BLOCK_Type type, size_t size, const void *data)
{
  struct TestGetContext *test_get = cls;
  GNUNET_HashCode search_key;   /* Key stored under */
  char original_data[TEST_DATA_SIZE];   /* Made up data to store */
  unsigned int i;

  memset (original_data, test_get->uid, sizeof (original_data));
  GNUNET_CRYPTO_hash (original_data, TEST_DATA_SIZE, &search_key);

  if (test_get->succeeded == GNUNET_YES)
    return;                     /* Get has already been successful, probably ending now */

#if PATH_TRACKING
  if (put_path != NULL)
  {
    fprintf (stderr, "PUT Path: ");
    for (i = 0; put_path[i] != NULL; i++)
      fprintf (stderr, "%s%s", i == 0 ? "" : "->", GNUNET_i2s (put_path[i]));
    fprintf (stderr, "\n");
  }
  if (get_path != NULL)
  {
    fprintf (stderr, "GET Path: ");
    for (i = 0; get_path[i] != NULL; i++)
      fprintf (stderr, "%s%s", i == 0 ? "" : "->", GNUNET_i2s (get_path[i]));
    fprintf (stderr, "\n");
  }
#endif

  if ((0 != memcmp (&search_key, key, sizeof (GNUNET_HashCode))) ||
      (0 != memcmp (original_data, data, sizeof (original_data))))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Key or data is not the same as was inserted!\n");
  }
  else
  {
    gets_completed++;
    test_get->succeeded = GNUNET_YES;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received correct GET response!\n");
  GNUNET_SCHEDULER_cancel (test_get->disconnect_task);
  GNUNET_SCHEDULER_add_continuation (&get_stop_task, test_get,
                                     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
}


/**
 * Set up some data, and call API PUT function
 */
static void
do_get (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct TestGetContext *test_get = cls;
  GNUNET_HashCode key;          /* Made up key to store data under */
  char data[TEST_DATA_SIZE];    /* Made up data to store */

  if (test_get == NULL)
    return;                     /* End of the list */
  memset (data, test_get->uid, sizeof (data));
  GNUNET_CRYPTO_hash (data, TEST_DATA_SIZE, &key);

  if (outstanding_gets > MAX_OUTSTANDING_GETS)
  {
    GNUNET_SCHEDULER_add_delayed (GET_DELAY, &do_get, test_get);
    return;
  }

  test_get->dht_handle = GNUNET_DHT_connect (test_get->daemon->cfg, 10);
  /* Insert the data at the first peer */
  GNUNET_assert (test_get->dht_handle != NULL);
  outstanding_gets++;
  test_get->get_handle = GNUNET_DHT_get_start (test_get->dht_handle,
                                               GNUNET_TIME_UNIT_FOREVER_REL,
                                               GNUNET_BLOCK_TYPE_TEST,
                                               &key,
                                               DEFAULT_GET_REPLICATION,
                                               route_option,
                                               NULL, 0,
                                               NULL, 0,
                                               &get_result_iterator, test_get);
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting get for uid %u from peer %s\n",
              test_get->uid, test_get->daemon->shortname);
#endif
  test_get->disconnect_task =
      GNUNET_SCHEDULER_add_delayed (GET_TIMEOUT, &get_stop_task, test_get);
  GNUNET_SCHEDULER_add_now (&do_get, test_get->next);
}

/**
 * Called when the PUT request has been transmitted to the DHT service.
 * Schedule the GET request for some time in the future.
 */
static void
put_finished (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct TestPutContext *test_put = cls;

  outstanding_puts--;
  puts_completed++;

  GNUNET_SCHEDULER_cancel (test_put->disconnect_task);
  test_put->disconnect_task =
      GNUNET_SCHEDULER_add_now (&put_disconnect_task, test_put);
  if (puts_completed == num_puts)
  {
    GNUNET_assert (outstanding_puts == 0);
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_SECONDS, 10), &do_get,
                                  all_gets);
    return;
  }
}

/**
 * Set up some data, and call API PUT function
 */
static void
do_put (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct TestPutContext *test_put = cls;
  GNUNET_HashCode key;          /* Made up key to store data under */
  char data[TEST_DATA_SIZE];    /* Made up data to store */

  if (test_put == NULL)
    return;                     /* End of list */

  memset (data, test_put->uid, sizeof (data));
  GNUNET_CRYPTO_hash (data, TEST_DATA_SIZE, &key);

  if (outstanding_puts > MAX_OUTSTANDING_PUTS)
  {
    GNUNET_SCHEDULER_add_delayed (PUT_DELAY, &do_put, test_put);
    return;
  }

#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting put for uid %u from peer %s\n",
              test_put->uid, test_put->daemon->shortname);
#endif
  test_put->dht_handle = GNUNET_DHT_connect (test_put->daemon->cfg, 10);

  GNUNET_assert (test_put->dht_handle != NULL);
  outstanding_puts++;
  GNUNET_DHT_put (test_put->dht_handle,
                  &key,
                  DEFAULT_PUT_REPLICATION,
                  route_option,
                  GNUNET_BLOCK_TYPE_TEST,
                  sizeof (data), data,
                  GNUNET_TIME_UNIT_FOREVER_ABS,
                  GNUNET_TIME_UNIT_FOREVER_REL, &put_finished, test_put);
  test_put->disconnect_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_get_forever (),
                                    &put_disconnect_task, test_put);
  GNUNET_SCHEDULER_add_now (&do_put, test_put->next);
}


/**
 * Set up some all of the put and get operations we want
 * to do.  Allocate data structure for each, add to list,
 * then call actual insert functions.
 */
static void
setup_puts_and_gets (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int i;
  uint32_t temp_daemon;
  struct TestPutContext *test_put;
  struct TestGetContext *test_get;
  int remember[num_puts][num_peers];

  for (i = 0; i < num_puts; i++)
  {
    test_put = GNUNET_malloc (sizeof (struct TestPutContext));
    test_put->uid = i;
    temp_daemon =
        GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, num_peers);
    test_put->daemon = GNUNET_TESTING_daemon_get (pg, temp_daemon);
    test_put->next = all_puts;
    all_puts = test_put;
  }

  for (i = 0; i < num_gets; i++)
  {
    test_get = GNUNET_malloc (sizeof (struct TestGetContext));
    test_get->uid =
        GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, num_puts);
    temp_daemon =
        GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, num_peers);
    while (remember[test_get->uid][temp_daemon] == 1)
      temp_daemon =
          GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, num_peers);
    test_get->daemon = GNUNET_TESTING_daemon_get (pg, temp_daemon);
    remember[test_get->uid][temp_daemon] = 1;
    test_get->next = all_gets;
    all_gets = test_get;
  }

  GNUNET_SCHEDULER_add_now (&do_put, all_puts);
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
topology_callback (void *cls,
                   const struct GNUNET_PeerIdentity *first,
                   const struct GNUNET_PeerIdentity *second,
                   uint32_t distance,
                   const struct GNUNET_CONFIGURATION_Handle *first_cfg,
                   const struct GNUNET_CONFIGURATION_Handle *second_cfg,
                   struct GNUNET_TESTING_Daemon *first_daemon,
                   struct GNUNET_TESTING_Daemon *second_daemon,
                   const char *emsg)
{
  if (emsg == NULL)
  {
    total_connections++;
#if VERBOSE > 1
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "connected peer %s to peer %s, distance %u\n",
                first_daemon->shortname, second_daemon->shortname, distance);
#endif
  }
#if VERBOSE
  else
  {
    failed_connections++;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Failed to connect peer %s to peer %s with error :\n%s\n",
                first_daemon->shortname, second_daemon->shortname, emsg);
  }
#endif

  if (total_connections == expected_connections)
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Created %d total connections, which is our target number!  Starting next phase of testing.\n",
                total_connections);
#endif
    GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
                                             &end_badly,
                                             "from setup puts/gets");

    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_SECONDS, 2),
                                  &setup_puts_and_gets, NULL);
  }
  else if (total_connections + failed_connections == expected_connections)
  {
    GNUNET_SCHEDULER_cancel (die_task);
    die_task =
        GNUNET_SCHEDULER_add_now (&end_badly,
                                  "from topology_callback (too many failed connections)");
  }
}

static void
peers_started_callback (void *cls,
                        const struct GNUNET_PeerIdentity *id,
                        const struct GNUNET_CONFIGURATION_Handle *cfg,
                        struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  if (emsg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Failed to start daemon with error: `%s'\n", emsg);
    return;
  }
  GNUNET_assert (id != NULL);

#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Started daemon %llu out of %llu\n",
              (num_peers - peers_left) + 1, num_peers);
#endif

  peers_left--;
  if (peers_left == 0)
  {

#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "All %d daemons started, now connecting peers!\n", num_peers);
#endif
    GNUNET_SCHEDULER_cancel (die_task);

    expected_connections = -1;
    if ((pg != NULL) && (peers_left == 0))
    {
      expected_connections = GNUNET_TESTING_connect_topology (pg,
                                                              connection_topology,
                                                              connect_topology_option,
                                                              connect_topology_option_modifier,
                                                              TIMEOUT,
                                                              num_peers,
                                                              NULL, NULL);
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Have %d expected connections\n", expected_connections);
#endif
    }

    if (expected_connections == GNUNET_SYSERR)
    {
      die_task =
          GNUNET_SCHEDULER_add_now (&end_badly,
                                    "from connect topology (bad return)");
    }

    die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
                                             &end_badly,
                                             "from connect topology (timeout)");

    ok = 0;
  }
}

static void
create_topology ()
{
  peers_left = num_peers;       /* Reset counter */
  if (GNUNET_TESTING_create_topology
      (pg, topology, blacklist_topology, blacklist_transports) != GNUNET_SYSERR)
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Topology set up, now starting peers!\n");
#endif
    GNUNET_TESTING_daemons_continue_startup (pg);
  }
  else
  {
    GNUNET_SCHEDULER_cancel (die_task);
    die_task =
        GNUNET_SCHEDULER_add_now (&end_badly,
                                  "from create topology (bad return)");
  }
  GNUNET_SCHEDULER_cancel (die_task);
  die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
                                           &end_badly,
                                           "from continue startup (timeout)");
}

/**
 * Callback indicating that the hostkey was created for a peer.
 *
 * @param cls NULL
 * @param id the peer identity
 * @param d the daemon handle (pretty useless at this point, remove?)
 * @param emsg non-null on failure
 */
void
hostkey_callback (void *cls,
                  const struct GNUNET_PeerIdentity *id,
                  struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  if (emsg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Hostkey callback received error: %s\n", emsg);
  }

#if VERBOSE > 1
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Hostkey (%d/%d) created for peer `%s'\n",
              num_peers - peers_left, num_peers, GNUNET_i2s (id));
#endif


  peers_left--;
  if (peers_left == 0)
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "All %d hostkeys created, now creating topology!\n", num_peers);
#endif
    GNUNET_SCHEDULER_cancel (die_task);
    /* Set up task in case topology creation doesn't finish
     * within a reasonable amount of time */
    die_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
                                             &end_badly,
                                             "from create_topology");
    GNUNET_SCHEDULER_add_now (&create_topology, NULL);
    ok = 0;
  }
}


static void
run (void *cls,
     char *const *args,
     const char *cfgfile, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char *topology_str;
  char *connect_topology_str;
  char *blacklist_topology_str;
  char *connect_topology_option_str;
  char *connect_topology_option_modifier_string;

#if PATH_TRACKING
  route_option = GNUNET_DHT_RO_RECORD_ROUTE;
#else
  route_option = GNUNET_DHT_RO_NONE;
#endif

  /* Get path from configuration file */
  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "paths", "servicehome",
                                             &test_directory))
  {
    ok = 404;
    return;
  }

  if ((GNUNET_YES ==
       GNUNET_CONFIGURATION_get_value_string (cfg, "testing", "topology",
                                              &topology_str)) &&
      (GNUNET_NO == GNUNET_TESTING_topology_get (&topology, topology_str)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Invalid topology `%s' given for section %s option %s\n",
                topology_str, "TESTING", "TOPOLOGY");
    topology = GNUNET_TESTING_TOPOLOGY_CLIQUE;  /* Defaults to NONE, so set better default here */
  }

  if ((GNUNET_YES ==
       GNUNET_CONFIGURATION_get_value_string (cfg, "testing",
                                              "connect_topology",
                                              &connect_topology_str)) &&
      (GNUNET_NO ==
       GNUNET_TESTING_topology_get (&connection_topology,
                                    connect_topology_str)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Invalid connect topology `%s' given for section %s option %s\n",
                connect_topology_str, "TESTING", "CONNECT_TOPOLOGY");
  }
  GNUNET_free_non_null (connect_topology_str);
  if ((GNUNET_YES ==
       GNUNET_CONFIGURATION_get_value_string (cfg, "testing",
                                              "connect_topology_option",
                                              &connect_topology_option_str)) &&
      (GNUNET_NO ==
       GNUNET_TESTING_topology_option_get (&connect_topology_option,
                                           connect_topology_option_str)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Invalid connect topology option `%s' given for section %s option %s\n",
                connect_topology_option_str, "TESTING",
                "CONNECT_TOPOLOGY_OPTION");
    connect_topology_option = GNUNET_TESTING_TOPOLOGY_OPTION_ALL;       /* Defaults to NONE, set to ALL */
  }
  GNUNET_free_non_null (connect_topology_option_str);
  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "testing",
                                             "connect_topology_option_modifier",
                                             &connect_topology_option_modifier_string))
  {
    if (sscanf
        (connect_topology_option_modifier_string, "%lf",
         &connect_topology_option_modifier) != 1)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _
                  ("Invalid value `%s' for option `%s' in section `%s': expected float\n"),
                  connect_topology_option_modifier_string,
                  "connect_topology_option_modifier", "TESTING");
    }
    GNUNET_free (connect_topology_option_modifier_string);
  }

  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "testing",
                                             "blacklist_transports",
                                             &blacklist_transports))
    blacklist_transports = NULL;

  if ((GNUNET_YES ==
       GNUNET_CONFIGURATION_get_value_string (cfg, "testing",
                                              "blacklist_topology",
                                              &blacklist_topology_str)) &&
      (GNUNET_NO ==
       GNUNET_TESTING_topology_get (&blacklist_topology,
                                    blacklist_topology_str)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Invalid topology `%s' given for section %s option %s\n",
                topology_str, "TESTING", "BLACKLIST_TOPOLOGY");
  }
  GNUNET_free_non_null (topology_str);
  GNUNET_free_non_null (blacklist_topology_str);

  /* Get number of peers to start from configuration */
  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "testing", "num_peers",
                                             &num_peers))
    num_peers = DEFAULT_NUM_PEERS;

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing", "num_puts",
                                             &num_puts))
    num_puts = DEFAULT_NUM_PEERS;

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing", "num_gets",
                                             &num_gets))
    num_gets = DEFAULT_NUM_PEERS;

  /* Set peers_left so we know when all peers started */
  peers_left = num_peers;

  /* Set up a task to end testing if peer start fails */
  die_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_SECONDS,
                                     SECONDS_PER_PEER_START * num_peers),
                                    &end_badly,
                                    "didn't generate all hostkeys within a reasonable amount of time!!!");

  pg = GNUNET_TESTING_daemons_start (cfg, peers_left,   /* Total number of peers */
                                     peers_left,        /* Number of outstanding connections */
                                     peers_left,        /* Number of parallel ssh connections, or peers being started at once */
                                     GNUNET_TIME_relative_multiply
                                     (GNUNET_TIME_UNIT_SECONDS,
                                      SECONDS_PER_PEER_START * num_peers),
                                     &hostkey_callback, NULL,
                                     &peers_started_callback, NULL,
                                     &topology_callback, NULL, NULL);

}

static int
check ()
{
  int ret;

  /* Arguments for GNUNET_PROGRAM_run */
  char *const argv[] = { "test-dht-multipeer",  /* Name to give running binary */
    "-c",
    "test_dht_multipeer_data.conf",     /* Config file to use */
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  /* Run the run function as a new program */
  ret = GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
                            argv, "test-dht-multipeer", "nohelp",
                            options, &run, &ok);
  if (ret != GNUNET_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "`test-dht-multipeer': Failed with error code %d\n", ret);
  }
  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-dht-multipeer",
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
  if (GNUNET_DISK_directory_remove (test_directory) != GNUNET_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Failed to remove testing directory %s\n", test_directory);
  }
  return ret;
}

/* end of test_dht_twopeer_put_get.c */
