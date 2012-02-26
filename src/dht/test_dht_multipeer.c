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
#define TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 30)

/* Timeout for waiting for replies to get requests */
#define GET_TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 300)

/* */
#define START_DELAY GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 30)

/* Timeout for waiting for gets to complete */
#define GET_DELAY GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS, 50)

/* Timeout for waiting for puts to complete */
#define PUT_DELAY GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS, 50)

/* If number of peers not in config file, use this number */
#define DEFAULT_NUM_PEERS 10

#define TEST_DATA_SIZE 8

#define MAX_OUTSTANDING_PUTS 100

#define MAX_OUTSTANDING_GETS 100

#define PATH_TRACKING GNUNET_NO



struct TestPutContext
{
  /**
   * This is a linked list
   */
  struct TestPutContext *next;

  /**
   * This is a linked list
   */
  struct TestPutContext *prev;

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
   * Task handle for processing of the put.
   */
  GNUNET_SCHEDULER_TaskIdentifier task;
};


struct TestGetContext
{
  /**
   * This is a linked list
   */
  struct TestGetContext *next;

  /**
   * This is a linked list
   */
  struct TestGetContext *prev;

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
  GNUNET_SCHEDULER_TaskIdentifier task;

  /**
   * Whether or not this request has been fulfilled already.
   */
  int succeeded;
};


/**
 * List of GETS to perform
 */
static struct TestGetContext *all_gets_head;

/**
 * List of GETS to perform
 */
static struct TestGetContext *all_gets_tail;

/**
 * List of PUTS to perform
 */
static struct TestPutContext *all_puts_head;

/**
 * List of PUTS to perform
 */
static struct TestPutContext *all_puts_tail;

/**
 * Handle to the set of all peers run for this test.
 */
static struct GNUNET_TESTING_PeerGroup *pg;

/**
 * Total number of peers to run, set based on config file.
 */
static unsigned long long num_peers;

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
 * Directory to remove on shutdown.
 */
static char *test_directory;

/**
 * Option to use when routing.
 */
static enum GNUNET_DHT_RouteOption route_option;

/**
 * Task handle to use to schedule test failure / success.
 */
static GNUNET_SCHEDULER_TaskIdentifier die_task;

/**
 * Task handle to use to schedule test shutdown
 */
GNUNET_SCHEDULER_TaskIdentifier shutdown_task;

/**
 * Global return value (0 for success, anything else for failure)
 */
static int ok;


/**
 * Check whether peers successfully shut down.
 */
static void
shutdown_callback (void *cls, const char *emsg)
{
  if (emsg != NULL)
  {
    FPRINTF (stderr, "Failed to shutdown testing topology: %s\n", emsg);
    if (ok == 0)
      ok = 2;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Shutdown callback completed.\n");
}

static void
do_stop (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) == 0)
  {
    if (GNUNET_SCHEDULER_NO_TASK != shutdown_task)
    {
      GNUNET_SCHEDULER_cancel(shutdown_task);
      shutdown_task = GNUNET_SCHEDULER_NO_TASK;
    }
  }
  else
  {
    shutdown_task = GNUNET_SCHEDULER_NO_TASK ;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Shutdown requested.\n");
  if (NULL != pg)
    GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
  pg = NULL;
}


/**
 * Master context for 'stat_run'.
 */
struct StatMaster
{
  struct GNUNET_STATISTICS_Handle *stat;
  unsigned int daemon;
  unsigned int value;
};

struct StatValues
{
  const char *subsystem;
  const char *name;
  unsigned long long total;
};

/**
 * Statistics we print out.
 */
static struct StatValues stats[] = {
  {"core", "# bytes decrypted", 0},
  {"core", "# bytes encrypted", 0},
  {"core", "# type maps received", 0},
  {"core", "# session keys confirmed via PONG", 0},
  {"core", "# entries in session map", 0},
  {"core", "# key exchanges initiated", 0},
  {"core", "# send requests dropped (disconnected)", 0},
  {"core", "# transmissions delayed due to corking", 0},
  {"core", "# messages discarded (expired prior to transmission)", 0},
  {"core", "# messages discarded (disconnected)", 0},
  {"core", "# discarded CORE_SEND requests", 0},
  {"core", "# discarded lower priority CORE_SEND requests", 0},
  {"transport", "# bytes received via TCP", 0},
  {"transport", "# bytes transmitted via TCP", 0},
  {"dht", "# PUT messages queued for transmission", 0},
  {"dht", "# P2P PUT requests received", 0},
  {"dht", "# GET messages queued for transmission", 0},
  {"dht", "# P2P GET requests received", 0},
  {"dht", "# RESULT messages queued for transmission", 0},
  {"dht", "# P2P RESULTS received", 0},
  {"dht", "# Queued messages discarded (peer disconnected)", 0},
  {"dht", "# Peers excluded from routing due to Bloomfilter", 0},
  {"dht", "# Peer selection failed", 0},
  {"dht", "# FIND PEER requests ignored due to Bloomfilter", 0},
  {"dht", "# FIND PEER requests ignored due to lack of HELLO", 0},
  {"dht", "# P2P FIND PEER requests processed", 0},
  {"dht", "# P2P GET requests ONLY routed", 0},
  {"dht", "# Preference updates given to core", 0},
  {"dht", "# REPLIES ignored for CLIENTS (no match)", 0},
  {"dht", "# GET requests from clients injected", 0},
  {"dht", "# GET requests received from clients", 0},
  {"dht", "# GET STOP requests received from clients", 0},
  {"dht", "# ITEMS stored in datacache", 0},
  {"dht", "# Good RESULTS found in datacache", 0},
  {"dht", "# GET requests given to datacache", 0},
  {NULL, NULL, 0}
};


/**
 * Callback function to process statistic values.
 *
 * @param cls closure
 * @param subsystem name of subsystem that created the statistic
 * @param name the name of the datum
 * @param value the current value
 * @param is_persistent GNUNET_YES if the value is persistent, GNUNET_NO if not
 * @return GNUNET_OK to continue, GNUNET_SYSERR to abort iteration
 */
static int
print_stat (void *cls, const char *subsystem, const char *name, uint64_t value,
            int is_persistent)
{
  struct StatMaster *sm = cls;

  stats[sm->value].total += value;
  FPRINTF (stderr, "Peer %2u: %12s/%50s = %12llu\n", sm->daemon, subsystem,
           name, (unsigned long long) value);
  return GNUNET_OK;
}


/**
 * Function that gathers stats from all daemons.
 */
static void
stat_run (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Function called when GET operation on stats is done.
 */
static void
get_done (void *cls, int success)
{
  struct StatMaster *sm = cls;

  GNUNET_break (GNUNET_OK == success);
  sm->value++;
  GNUNET_SCHEDULER_add_now (&stat_run, sm);
}


/**
 * Function that gathers stats from all daemons.
 */
static void
stat_run (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct StatMaster *sm = cls;
  unsigned int i;

  die_task = GNUNET_SCHEDULER_NO_TASK;
  if (stats[sm->value].name != NULL)
  {
    GNUNET_STATISTICS_get (sm->stat,
#if 0
                           NULL, NULL,
#else
                           stats[sm->value].subsystem, stats[sm->value].name,
#endif
                           GNUNET_TIME_UNIT_FOREVER_REL, &get_done, &print_stat,
                           sm);
    return;
  }
  GNUNET_STATISTICS_destroy (sm->stat, GNUNET_NO);
  sm->value = 0;
  sm->daemon++;
  if (sm->daemon == num_peers)
  {
    GNUNET_free (sm);
    i = 0;
    while (stats[i].name != NULL)
    {
      FPRINTF (stderr, "Total  : %12s/%50s = %12llu\n", stats[i].subsystem,
               stats[i].name, (unsigned long long) stats[i].total);
      i++;
    }
    die_task = GNUNET_SCHEDULER_add_now (&do_stop, NULL);
    return;
  }
  sm->stat =
      GNUNET_STATISTICS_create ("<driver>",
                                GNUNET_TESTING_daemon_get (pg,
                                                           sm->daemon)->cfg);
  die_task = GNUNET_SCHEDULER_add_now (&stat_run, sm);
}


/**
 * Function scheduled to be run on the successful completion of this
 * testcase.
 */
static void
finish_testing (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct TestPutContext *test_put;
  struct TestGetContext *test_get;
  struct StatMaster *sm;

  die_task = GNUNET_SCHEDULER_NO_TASK;
  while (NULL != (test_put = all_puts_head))
  {
    if (test_put->task != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (test_put->task);
    if (test_put->dht_handle != NULL)
      GNUNET_DHT_disconnect (test_put->dht_handle);
    GNUNET_CONTAINER_DLL_remove (all_puts_head, all_puts_tail, test_put);
    GNUNET_free (test_put);
  }

  while (NULL != (test_get = all_gets_head))
  {
    if (test_get->task != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (test_get->task);
    if (test_get->get_handle != NULL)
      GNUNET_DHT_get_stop (test_get->get_handle);
    if (test_get->dht_handle != NULL)
      GNUNET_DHT_disconnect (test_get->dht_handle);
    GNUNET_CONTAINER_DLL_remove (all_gets_head, all_gets_tail, test_get);
    GNUNET_free (test_get);
  }
  sm = GNUNET_malloc (sizeof (struct StatMaster));
  sm->stat =
      GNUNET_STATISTICS_create ("<driver>",
                                GNUNET_TESTING_daemon_get (pg,
                                                           sm->daemon)->cfg);
  die_task = GNUNET_SCHEDULER_add_now (&stat_run, sm);
}


/**
 * Check if the get_handle is being used, if so stop the request.  Either
 * way, schedule the end_badly_cont function which actually shuts down the
 * test.
 */
static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  const char *emsg = cls;
  struct TestPutContext *test_put;
  struct TestGetContext *test_get;

  die_task = GNUNET_SCHEDULER_NO_TASK;
  FPRINTF (stderr, "Failing test with error: `%s'!\n", emsg);
  while (NULL != (test_put = all_puts_head))
  {
    if (test_put->task != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (test_put->task);
    if (test_put->dht_handle != NULL)
      GNUNET_DHT_disconnect (test_put->dht_handle);
    GNUNET_CONTAINER_DLL_remove (all_puts_head, all_puts_tail, test_put);
    GNUNET_free (test_put);
  }

  while (NULL != (test_get = all_gets_head))
  {
    if (test_get->task != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (test_get->task);
    if (test_get->get_handle != NULL)
      GNUNET_DHT_get_stop (test_get->get_handle);
    if (test_get->dht_handle != NULL)
      GNUNET_DHT_disconnect (test_get->dht_handle);
    GNUNET_CONTAINER_DLL_remove (all_gets_head, all_gets_tail, test_get);
    GNUNET_free (test_get);
  }
  ok = 1;
  /* testing_peergroup will do that in its own end_badly() handler */
  /*GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL); */
  pg = NULL;
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

  test_get->task = GNUNET_SCHEDULER_NO_TASK;
  memset (original_data, test_get->uid, sizeof (original_data));
  GNUNET_CRYPTO_hash (original_data, TEST_DATA_SIZE, &search_key);
  if (test_get->succeeded != GNUNET_YES)
  {
    gets_failed++;
    FPRINTF (stderr, "Get from peer %s for key %s failed!\n",
             GNUNET_i2s (&test_get->daemon->id), GNUNET_h2s (&search_key));
  }
  GNUNET_assert (test_get->get_handle != NULL);
  GNUNET_DHT_get_stop (test_get->get_handle);
  test_get->get_handle = NULL;

  outstanding_gets--;           /* GET is really finished */
  GNUNET_DHT_disconnect (test_get->dht_handle);
  test_get->dht_handle = NULL;

  GNUNET_CONTAINER_DLL_remove (all_gets_head, all_gets_tail, test_get);
  GNUNET_free (test_get);
  if ((gets_failed > 10) && (outstanding_gets == 0))
  {
    /* Had more than 10% failures */
    FPRINTF (stderr, "%llu gets succeeded, %llu gets failed!\n", gets_completed,
             gets_failed);
    GNUNET_SCHEDULER_cancel (die_task);
    ok = 1;
    die_task =
        GNUNET_SCHEDULER_add_now (&finish_testing, "not all gets succeeded");
    return;
  }
  if ((gets_completed + gets_failed == num_peers * num_peers) && (outstanding_gets == 0))       /* All gets successful */
  {
    FPRINTF (stderr, "%llu gets succeeded, %llu gets failed!\n", gets_completed,
             gets_failed);
    GNUNET_SCHEDULER_cancel (die_task);
    ok = 0;
    die_task = GNUNET_SCHEDULER_add_now (&finish_testing, NULL);
  }
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
static void
get_result_iterator (void *cls, struct GNUNET_TIME_Absolute exp,
                     const GNUNET_HashCode * key,
                     const struct GNUNET_PeerIdentity *get_path,
                     unsigned int get_path_length,
                     const struct GNUNET_PeerIdentity *put_path,
                     unsigned int put_path_length, enum GNUNET_BLOCK_Type type,
                     size_t size, const void *data)
{
  struct TestGetContext *test_get = cls;
  GNUNET_HashCode search_key;   /* Key stored under */
  char original_data[TEST_DATA_SIZE];   /* Made up data to store */

  memset (original_data, test_get->uid, sizeof (original_data));
  GNUNET_CRYPTO_hash (original_data, TEST_DATA_SIZE, &search_key);
  if (test_get->succeeded == GNUNET_YES)
    return;                     /* Get has already been successful, probably ending now */

#if PATH_TRACKING
  if (put_path != NULL)
  {
    unsigned int i;

    FPRINTF (stderr, "PUT (%u) Path: ", test_get->uid);
    for (i = 0; i < put_path_length; i++)
      FPRINTF (stderr, "%s%s", i == 0 ? "" : "->", GNUNET_i2s (&put_path[i]));
    FPRINTF (stderr, "%s",  "\n");
  }
  if (get_path != NULL)
  {
    unsigned int i;

    FPRINTF (stderr, "GET (%u) Path: ", test_get->uid);
    for (i = 0; i < get_path_length; i++)
      FPRINTF (stderr, "%s%s", i == 0 ? "" : "->", GNUNET_i2s (&get_path[i]));
    FPRINTF (stderr, "%s%s\n", get_path_length > 0 ? "->" : "",
             GNUNET_i2s (&test_get->daemon->id));
  }
#endif

  if ((0 != memcmp (&search_key, key, sizeof (GNUNET_HashCode))) ||
      (0 != memcmp (original_data, data, sizeof (original_data))))
  {
    FPRINTF (stderr, "%s",  "Key or data is not the same as was inserted!\n");
    return;
  }
  gets_completed++;
  test_get->succeeded = GNUNET_YES;
  GNUNET_SCHEDULER_cancel (test_get->task);
  test_get->task = GNUNET_SCHEDULER_add_now (&get_stop_task, test_get);
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

  if (outstanding_gets > MAX_OUTSTANDING_GETS)
  {
    test_get->task =
        GNUNET_SCHEDULER_add_delayed (GET_DELAY, &do_get, test_get);
    return;
  }
  memset (data, test_get->uid, sizeof (data));
  GNUNET_CRYPTO_hash (data, TEST_DATA_SIZE, &key);
  test_get->dht_handle = GNUNET_DHT_connect (test_get->daemon->cfg, 10);
  GNUNET_assert (test_get->dht_handle != NULL);
  outstanding_gets++;
  test_get->get_handle =
      GNUNET_DHT_get_start (test_get->dht_handle, GNUNET_TIME_UNIT_FOREVER_REL,
                            GNUNET_BLOCK_TYPE_TEST, &key, 1, route_option, NULL,
                            0, &get_result_iterator, test_get);
  test_get->task =
      GNUNET_SCHEDULER_add_delayed (GET_TIMEOUT, &get_stop_task, test_get);
}


/**
 * Task to release DHT handles for PUT
 */
static void
put_disconnect_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct TestPutContext *test_put = cls;

  test_put->task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_DHT_disconnect (test_put->dht_handle);
  test_put->dht_handle = NULL;
  GNUNET_CONTAINER_DLL_remove (all_puts_head, all_puts_tail, test_put);
  GNUNET_free (test_put);
}


/**
 * Schedule the GET requests
 */
static void
start_gets (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  unsigned long long i;
  unsigned long long j;
  struct TestGetContext *test_get;

#if VERBOSE
  FPRINTF (stderr, "Issuing %llu GETs\n",
           (unsigned long long) (num_peers * num_peers));
#endif
  for (i = 0; i < num_peers; i++)
    for (j = 0; j < num_peers; j++)
    {
      test_get = GNUNET_malloc (sizeof (struct TestGetContext));
      test_get->uid = i + j * num_peers;
      test_get->daemon = GNUNET_TESTING_daemon_get (pg, j);
      GNUNET_CONTAINER_DLL_insert (all_gets_head, all_gets_tail, test_get);
      test_get->task = GNUNET_SCHEDULER_add_now (&do_get, test_get);
    }
}


/**
 * Called when the PUT request has been transmitted to the DHT service.
 */
static void
put_finished (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct TestPutContext *test_put = cls;

  outstanding_puts--;
  puts_completed++;
  if (GNUNET_SCHEDULER_NO_TASK != test_put->task)
  {
    GNUNET_SCHEDULER_cancel (test_put->task);
  }
  test_put->task = GNUNET_SCHEDULER_add_now (&put_disconnect_task, test_put);
  if (puts_completed != num_peers * num_peers)
    return;

  GNUNET_assert (outstanding_puts == 0);
  GNUNET_SCHEDULER_add_delayed (START_DELAY, &start_gets, NULL);
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

  test_put->task = GNUNET_SCHEDULER_NO_TASK;
  if (outstanding_puts > MAX_OUTSTANDING_PUTS)
  {
    test_put->task =
        GNUNET_SCHEDULER_add_delayed (PUT_DELAY, &do_put, test_put);
    return;
  }
  memset (data, test_put->uid, sizeof (data));
  GNUNET_CRYPTO_hash (data, TEST_DATA_SIZE, &key);
  test_put->dht_handle = GNUNET_DHT_connect (test_put->daemon->cfg, 10);
  GNUNET_assert (test_put->dht_handle != NULL);
  outstanding_puts++;
#if VERBOSE > 2
  FPRINTF (stderr, "PUT %u at `%s'\n", test_put->uid,
           GNUNET_i2s (&test_put->daemon->id));
#endif
  GNUNET_DHT_put (test_put->dht_handle, &key, 1, route_option,
                  GNUNET_BLOCK_TYPE_TEST, sizeof (data), data,
                  GNUNET_TIME_UNIT_FOREVER_ABS, GNUNET_TIME_UNIT_FOREVER_REL,
                  &put_finished, test_put);
  test_put->task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                    &put_disconnect_task, test_put);
}


static void
run_dht_test (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  unsigned long long i;
  struct TestPutContext *test_put;

  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
  {
    ok = 1;
    return;
  }
#if PATH_TRACKING
  route_option =
      GNUNET_DHT_RO_RECORD_ROUTE | GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE;
#else
  route_option = GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE;
#endif
  die_task =
      GNUNET_SCHEDULER_add_delayed (TIMEOUT, &end_badly,
                                    "from setup puts/gets");
  FPRINTF (stderr, "Issuing %llu PUTs (one per peer)\n",
           (unsigned long long) (num_peers * num_peers));
  for (i = 0; i < num_peers * num_peers; i++)
  {
    test_put = GNUNET_malloc (sizeof (struct TestPutContext));
    test_put->uid = i;
    test_put->daemon = GNUNET_TESTING_daemon_get (pg, i % num_peers);
    test_put->task = GNUNET_SCHEDULER_add_now (&do_put, test_put);
    GNUNET_CONTAINER_DLL_insert (all_puts_head, all_puts_tail, test_put);
  }
}


/**
 * This function is called once testing has finished setting up the topology.
 *
 * @param cls unused
 * @param emsg variable is NULL on success (peers connected), and non-NULL on
 * failure (peers failed to connect).
 */
static void
startup_done (void *cls, const char *emsg)
{
  if (emsg != NULL)
  {
    FPRINTF (stderr, "Failed to setup topology: %s\n", emsg);
    die_task = GNUNET_SCHEDULER_add_now (&end_badly, "topology setup failed");
    return;
  }
  die_task =
      GNUNET_SCHEDULER_add_delayed (START_DELAY, &run_dht_test,
                                    "from setup puts/gets");
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
    GNUNET_break (0);
    ok = 404;
    return;
  }
  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "testing", "num_peers",
                                             &num_peers))
    num_peers = DEFAULT_NUM_PEERS;
  pg = GNUNET_TESTING_peergroup_start (cfg, num_peers, TIMEOUT, NULL,
                                       &startup_done, NULL, NULL);
  GNUNET_assert (NULL != pg);
  shutdown_task = GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_UNIT_FOREVER_REL,
                                               &do_stop, NULL);
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
  ret =
      GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv,
                          "test-dht-multipeer", "nohelp", options, &run, &ok);
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

/* end of test_dht_multipeer.c */
