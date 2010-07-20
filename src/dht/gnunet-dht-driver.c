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
 * @file dht/gnunet-dht-driver.c
 * @brief Driver for setting up a group of gnunet peers and
 *        then issuing GETS and PUTS on the DHT.  Coarse results
 *        are reported, fine grained results (if requested) are
 *        logged to a (mysql) database.
 *
 *  TODO: Add multiple database support; alternatively, dump
 *        sql readable (or easily transformed) logs to disk
 *        for reassembly later.  This could remove the mysql
 *        server as a bottleneck during testing.
 */
#include "platform.h"
#include "gnunet_testing_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_dht_service.h"
#include "dhtlog.h"

/* DEFINES */
#define VERBOSE GNUNET_YES

/* Timeout for entire driver to run */
#define DEFAULT_TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 5)

/* Timeout for waiting for (individual) replies to get requests */
#define DEFAULT_GET_TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 90)

/* Timeout for waiting for gets to be sent to the service */
#define DEFAULT_GET_DELAY GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 10)

/* Timeout for waiting for puts to be sent to the service */
#define DEFAULT_PUT_DELAY GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 10)

#define DEFAULT_SECONDS_PER_PEER_START GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 45)

#define DEFAULT_TEST_DATA_SIZE 8

#define DEFAULT_MAX_OUTSTANDING_PUTS 10

#define DEFAULT_MAX_OUTSTANDING_GETS 10

#define DEFAULT_CONNECT_TIMEOUT 60

#define DEFAULT_TOPOLOGY_TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 8)

/* Structs */

struct TestPutContext
{
  /* This is a linked list */
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

/**
 * Simple struct to keep track of progress, and print a
 * nice little percentage meter for long running tasks.
 */
struct ProgressMeter
{
  unsigned int total;

  unsigned int modnum;

  unsigned int dotnum;

  unsigned int completed;

  int print;

  char *startup_string;
};

/* Globals */

/**
 * Timeout to let all get requests happen.
 */
static struct GNUNET_TIME_Relative all_get_timeout;

/**
 * Per get timeout
 */
static struct GNUNET_TIME_Relative get_timeout;

static struct GNUNET_TIME_Relative get_delay;

static struct GNUNET_TIME_Relative put_delay;

static struct GNUNET_TIME_Relative seconds_per_peer_start;

static unsigned long long test_data_size = DEFAULT_TEST_DATA_SIZE;

static unsigned long long max_outstanding_puts = DEFAULT_MAX_OUTSTANDING_PUTS;

static unsigned long long max_outstanding_gets = DEFAULT_MAX_OUTSTANDING_GETS;

static unsigned long long malicious_getters;

static unsigned long long malicious_putters;

static unsigned long long malicious_droppers;

static unsigned long long settle_time;

static struct GNUNET_DHTLOG_Handle *dhtlog_handle;

static unsigned long long trialuid;

/**
 * List of GETS to perform
 */
struct TestGetContext *all_gets;

/**
 * List of PUTS to perform
 */
struct TestPutContext *all_puts;

/**
 * Directory to store temporary data in, defined in config file
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
 * Global scheduler, used for all GNUNET_SCHEDULER_* functions.
 */
static struct GNUNET_SCHEDULER_Handle *sched;

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

/* Task handle to use to schedule shutdown if something goes wrong */
GNUNET_SCHEDULER_TaskIdentifier die_task;

static char *blacklist_transports;

static enum GNUNET_TESTING_Topology topology;

static enum GNUNET_TESTING_Topology blacklist_topology = GNUNET_TESTING_TOPOLOGY_NONE; /* Don't do any blacklisting */

static enum GNUNET_TESTING_Topology connect_topology = GNUNET_TESTING_TOPOLOGY_NONE; /* NONE actually means connect all allowed peers */

static enum GNUNET_TESTING_TopologyOption connect_topology_option = GNUNET_TESTING_TOPOLOGY_OPTION_ALL;

static double connect_topology_option_modifier = 0.0;

static struct ProgressMeter *hostkey_meter;

static struct ProgressMeter *peer_start_meter;

static struct ProgressMeter *peer_connect_meter;

static struct ProgressMeter *put_meter;

static struct ProgressMeter *get_meter;

/* Global return value (0 for success, anything else for failure) */
static int ok;

/**
 * Create a meter to keep track of the progress of some task.
 *
 * @param total the total number of items to complete
 * @param start_string a string to prefix the meter with (if printing)
 * @param print GNUNET_YES to print the meter, GNUNET_NO to count
 *              internally only
 *
 * @return the progress meter
 */
static struct ProgressMeter *
create_meter(unsigned int total, char * start_string, int print)
{
  struct ProgressMeter *ret;
  ret = GNUNET_malloc(sizeof(struct ProgressMeter));
  ret->print = print;
  ret->total = total;
  ret->modnum = total / 4;
  ret->dotnum = (total / 50) + 1;
  if (start_string != NULL)
    ret->startup_string = GNUNET_strdup(start_string);
  else
    ret->startup_string = GNUNET_strdup("");

  return ret;
}

/**
 * Update progress meter (increment by one).
 *
 * @param meter the meter to update and print info for
 *
 * @return GNUNET_YES if called the total requested,
 *         GNUNET_NO if more items expected
 */
static int
update_meter(struct ProgressMeter *meter)
{
  if (meter->print == GNUNET_YES)
    {
      if (meter->completed % meter->modnum == 0)
        {
          if (meter->completed == 0)
            {
              fprintf(stdout, "%sProgress: [0%%", meter->startup_string);
            }
          else
            fprintf(stdout, "%d%%", (int)(((float)meter->completed / meter->total) * 100));
        }
      else if (meter->completed % meter->dotnum == 0)
        fprintf(stdout, ".");

      if (meter->completed + 1 == meter->total)
        fprintf(stdout, "%d%%]\n", 100);
      fflush(stdout);
    }
  meter->completed++;

  if (meter->completed == meter->total)
    return GNUNET_YES;
  return GNUNET_NO;
}

/**
 * Release resources for meter
 *
 * @param meter the meter to free
 */
static void
free_meter(struct ProgressMeter *meter)
{
  GNUNET_free_non_null(meter->startup_string);
  GNUNET_free_non_null(meter);
}

/**
 * Check whether peers successfully shut down.
 */
void shutdown_callback (void *cls,
                        const char *emsg)
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
put_disconnect_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  struct TestPutContext *test_put = cls;
  test_put->disconnect_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_DHT_disconnect(test_put->dht_handle);
  test_put->dht_handle = NULL;
}

/**
 * Function scheduled to be run on the successful completion of this
 * testcase.
 */
static void
finish_testing (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  GNUNET_assert (pg != NULL);
  struct TestPutContext *test_put = all_puts;
  struct TestGetContext *test_get = all_gets;

  while (test_put != NULL)
    {
      if (test_put->disconnect_task != GNUNET_SCHEDULER_NO_TASK)
        GNUNET_SCHEDULER_cancel(sched, test_put->disconnect_task);
      if (test_put->dht_handle != NULL)
        GNUNET_DHT_disconnect(test_put->dht_handle);
      test_put = test_put->next;
    }

  while (test_get != NULL)
    {
      if (test_get->disconnect_task != GNUNET_SCHEDULER_NO_TASK)
        GNUNET_SCHEDULER_cancel(sched, test_get->disconnect_task);
      if (test_get->get_handle != NULL)
        GNUNET_DHT_get_stop(test_get->get_handle, NULL, NULL);
      if (test_get->dht_handle != NULL)
        GNUNET_DHT_disconnect(test_get->dht_handle);
      test_get = test_get->next;
    }

  GNUNET_TESTING_daemons_stop (pg, DEFAULT_TIMEOUT, &shutdown_callback, NULL);

  /* FIXME: optionally get stats for dropped messages, etc. */
  if (dhtlog_handle != NULL)
    dhtlog_handle->update_trial (trialuid, 0, 0, 0);

  if (hostkey_meter != NULL)
    free_meter(hostkey_meter);
  if (hostkey_meter != NULL)
    free_meter(peer_start_meter);
  if (hostkey_meter != NULL)
    free_meter(peer_connect_meter);
  if (hostkey_meter != NULL)
    free_meter(put_meter);
  if (hostkey_meter != NULL)
    free_meter(get_meter);

  ok = 0;
}


/**
 * Check if the get_handle is being used, if so stop the request.  Either
 * way, schedule the end_badly_cont function which actually shuts down the
 * test.
 */
static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Failing test with error: `%s'!\n", (char *)cls);

  struct TestPutContext *test_put = all_puts;
  struct TestGetContext *test_get = all_gets;

  while (test_put != NULL)
    {
      if (test_put->disconnect_task != GNUNET_SCHEDULER_NO_TASK)
        GNUNET_SCHEDULER_cancel(sched, test_put->disconnect_task);
      if (test_put->dht_handle != NULL)
        GNUNET_DHT_disconnect(test_put->dht_handle);
      test_put = test_put->next;
    }

  while (test_get != NULL)
    {
      if (test_get->disconnect_task != GNUNET_SCHEDULER_NO_TASK)
        GNUNET_SCHEDULER_cancel(sched, test_get->disconnect_task);
      if (test_get->get_handle != NULL)
        GNUNET_DHT_get_stop(test_get->get_handle, NULL, NULL);
      if (test_get->dht_handle != NULL)
        GNUNET_DHT_disconnect(test_get->dht_handle);
      test_get = test_get->next;
    }

  GNUNET_TESTING_daemons_stop (pg, DEFAULT_TIMEOUT, &shutdown_callback, NULL);

  if (hostkey_meter != NULL)
    free_meter(hostkey_meter);
  if (hostkey_meter != NULL)
    free_meter(peer_start_meter);
  if (hostkey_meter != NULL)
    free_meter(peer_connect_meter);
  if (hostkey_meter != NULL)
    free_meter(put_meter);
  if (hostkey_meter != NULL)
    free_meter(get_meter);

  ok = 1;
}

/**
 * Task to release DHT handle associated with GET request.
 */
static void
get_stop_finished (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  struct TestGetContext *test_get = cls;
  outstanding_gets--; /* GET is really finished */
  GNUNET_DHT_disconnect(test_get->dht_handle);
  test_get->dht_handle = NULL;

#if VERBOSE > 1
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%d gets succeeded, %d gets failed!\n", gets_completed, gets_failed);
#endif
  update_meter(get_meter);
  if ((gets_completed == num_gets) && (outstanding_gets == 0))/* All gets successful */
    {
      GNUNET_SCHEDULER_cancel(sched, die_task);
      GNUNET_SCHEDULER_add_now(sched, &finish_testing, NULL);
    }
  else if ((gets_completed + gets_failed == num_gets) && (outstanding_gets == 0)) /* Had some failures */
    {
      GNUNET_SCHEDULER_cancel(sched, die_task);
      GNUNET_SCHEDULER_add_now(sched, &finish_testing, NULL);
    }
}

/**
 * Task to release get handle.
 */
static void
get_stop_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  struct TestGetContext *test_get = cls;

  if (tc->reason == GNUNET_SCHEDULER_REASON_TIMEOUT)
    gets_failed++;
  GNUNET_assert(test_get->get_handle != NULL);
  GNUNET_DHT_get_stop(test_get->get_handle, &get_stop_finished, test_get);
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
void get_result_iterator (void *cls,
                          struct GNUNET_TIME_Absolute exp,
                          const GNUNET_HashCode * key,
                          uint32_t type,
                          uint32_t size,
                          const void *data)
{
  struct TestGetContext *test_get = cls;
  GNUNET_HashCode search_key; /* Key stored under */
  char original_data[test_data_size]; /* Made up data to store */

  memset(original_data, test_get->uid, sizeof(original_data));
  GNUNET_CRYPTO_hash(original_data, test_data_size, &search_key);

  if (test_get->succeeded == GNUNET_YES)
    return; /* Get has already been successful, probably ending now */

  if ((0 != memcmp(&search_key, key, sizeof (GNUNET_HashCode))) || (0 != memcmp(original_data, data, sizeof(original_data))))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Key or data is not the same as was inserted!\n");
    }
  else
    {
      gets_completed++;
      test_get->succeeded = GNUNET_YES;
    }
#if VERBOSE > 1
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received correct GET response!\n");
#endif
  GNUNET_SCHEDULER_cancel(sched, test_get->disconnect_task);
  GNUNET_SCHEDULER_add_continuation(sched, &get_stop_task, test_get, GNUNET_SCHEDULER_REASON_PREREQ_DONE);
}

/**
 * Continuation telling us GET request was sent.
 */
static void
get_continuation (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  // Is there something to be done here?
  if (tc->reason != GNUNET_SCHEDULER_REASON_PREREQ_DONE)
    return;
}

/**
 * Set up some data, and call API PUT function
 */
static void
do_get (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  struct TestGetContext *test_get = cls;
  GNUNET_HashCode key; /* Made up key to store data under */
  char data[test_data_size]; /* Made up data to store */

  if (num_gets == 0)
    {
      GNUNET_SCHEDULER_cancel(sched, die_task);
      GNUNET_SCHEDULER_add_now(sched, &finish_testing, NULL);
    }
  if (test_get == NULL)
    return; /* End of the list */
  memset(data, test_get->uid, sizeof(data));
  GNUNET_CRYPTO_hash(data, test_data_size, &key);

  if (outstanding_gets > max_outstanding_gets)
    {
      GNUNET_SCHEDULER_add_delayed (sched, get_delay, &do_get, test_get);
      return;
    }

  test_get->dht_handle = GNUNET_DHT_connect(sched, test_get->daemon->cfg, 10);
  /* Insert the data at the first peer */
  GNUNET_assert(test_get->dht_handle != NULL);
  outstanding_gets++;
  test_get->get_handle = GNUNET_DHT_get_start(test_get->dht_handle,
                                              GNUNET_TIME_relative_get_forever(),
                                              1,
                                              &key,
                                              &get_result_iterator,
                                              test_get,
                                              &get_continuation,
                                              test_get);
#if VERBOSE > 1
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting get for uid %u from peer %s\n",
             test_get->uid,
             test_get->daemon->shortname);
#endif
  test_get->disconnect_task = GNUNET_SCHEDULER_add_delayed(sched, get_timeout, &get_stop_task, test_get);
  GNUNET_SCHEDULER_add_now (sched, &do_get, test_get->next);
}

/**
 * Called when the PUT request has been transmitted to the DHT service.
 * Schedule the GET request for some time in the future.
 */
static void
put_finished (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  struct TestPutContext *test_put = cls;
  outstanding_puts--;
  puts_completed++;

  GNUNET_SCHEDULER_cancel(sched, test_put->disconnect_task);
  test_put->disconnect_task = GNUNET_SCHEDULER_add_now(sched, &put_disconnect_task, test_put);
  if (GNUNET_YES == update_meter(put_meter))
    {
      GNUNET_assert(outstanding_puts == 0);
      GNUNET_SCHEDULER_cancel (sched, die_task);
      die_task = GNUNET_SCHEDULER_add_delayed (sched, all_get_timeout,
                                               &end_badly, "from do gets");
      GNUNET_SCHEDULER_add_delayed(sched, GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 100), &do_get, all_gets);
      return;
    }
}

/**
 * Set up some data, and call API PUT function
 */
static void
do_put (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  struct TestPutContext *test_put = cls;
  GNUNET_HashCode key; /* Made up key to store data under */
  char data[test_data_size]; /* Made up data to store */
  uint32_t rand;

  if (test_put == NULL)
    return; /* End of list */

  memset(data, test_put->uid, sizeof(data));
  GNUNET_CRYPTO_hash(data, test_data_size, &key);

  if (outstanding_puts > max_outstanding_puts)
    {
      GNUNET_SCHEDULER_add_delayed (sched, put_delay, &do_put, test_put);
      return;
    }

#if VERBOSE > 1
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting put for uid %u from peer %s\n",
               test_put->uid,
               test_put->daemon->shortname);
#endif
  test_put->dht_handle = GNUNET_DHT_connect(sched, test_put->daemon->cfg, 10);

  GNUNET_assert(test_put->dht_handle != NULL);
  outstanding_puts++;
  GNUNET_DHT_put(test_put->dht_handle,
                 &key,
                 1,
                 sizeof(data), data,
                 GNUNET_TIME_absolute_get_forever(),
                 GNUNET_TIME_relative_get_forever(),
                 &put_finished, test_put);
  test_put->disconnect_task = GNUNET_SCHEDULER_add_delayed(sched, GNUNET_TIME_relative_get_forever(), &put_disconnect_task, test_put);
  rand = GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, 2);
  GNUNET_SCHEDULER_add_delayed(sched, GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, rand), &do_put, test_put->next);
}


/**
 * Set up some all of the put and get operations we want
 * to do.  Allocate data structure for each, add to list,
 * then call actual insert functions.
 */
static void
setup_puts_and_gets (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  int i;
  uint32_t temp_daemon;
  struct TestPutContext *test_put;
  struct TestGetContext *test_get;
  int remember[num_puts][num_peers];

  for (i = 0; i < num_puts; i++)
    {
      test_put = GNUNET_malloc(sizeof(struct TestPutContext));
      test_put->uid = i;
      temp_daemon = GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, num_peers);
      test_put->daemon = GNUNET_TESTING_daemon_get(pg, temp_daemon);
      test_put->next = all_puts;
      all_puts = test_put;
    }

  for (i = 0; i < num_gets; i++)
    {
      test_get = GNUNET_malloc(sizeof(struct TestGetContext));
      test_get->uid = GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, num_puts);
      temp_daemon = GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, num_peers);
      while (remember[test_get->uid][temp_daemon] == 1)
        temp_daemon = GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, num_peers);
      test_get->daemon = GNUNET_TESTING_daemon_get(pg, temp_daemon);
      remember[test_get->uid][temp_daemon] = 1;
      test_get->next = all_gets;
      all_gets = test_get;
    }

  GNUNET_SCHEDULER_cancel (sched, die_task);
  die_task = GNUNET_SCHEDULER_add_delayed (sched, GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, num_puts * 2),
                                           &end_badly, "from do puts");
  GNUNET_SCHEDULER_add_now (sched, &do_put, all_puts);
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
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "connected peer %s to peer %s, distance %u\n",
                 first_daemon->shortname,
                 second_daemon->shortname,
                 distance);
#endif
    }
#if VERBOSE
  else
    {
      failed_connections++;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Failed to connect peer %s to peer %s with error :\n%s\n",
                  first_daemon->shortname,
                  second_daemon->shortname, emsg);
    }
#endif
  GNUNET_assert(peer_connect_meter != NULL);
  if (GNUNET_YES == update_meter(peer_connect_meter))
    {
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Created %d total connections, which is our target number!  Starting next phase of testing.\n",
                  total_connections);
#endif
      if (dhtlog_handle != NULL)
        dhtlog_handle->update_connections (trialuid, total_connections);

      GNUNET_SCHEDULER_cancel (sched, die_task);
      die_task = GNUNET_SCHEDULER_add_delayed (sched, DEFAULT_TIMEOUT,
                                               &end_badly, "from setup puts/gets");

      GNUNET_SCHEDULER_add_delayed (sched, GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, settle_time), &setup_puts_and_gets, NULL);
    }
  else if (total_connections + failed_connections == expected_connections)
    {
      GNUNET_SCHEDULER_cancel (sched, die_task);
      die_task = GNUNET_SCHEDULER_add_now (sched,
                                           &end_badly, "from topology_callback (too many failed connections)");
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
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Failed to start daemon with error: `%s'\n",
                  emsg);
      return;
    }
  GNUNET_assert (id != NULL);

#if VERBOSE > 1
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Started daemon %llu out of %llu\n",
              (num_peers - peers_left) + 1, num_peers);
#endif

  peers_left--;

  if (GNUNET_YES == update_meter(peer_start_meter))
    {
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "All %d daemons started, now connecting peers!\n",
                  num_peers);
#endif
      GNUNET_SCHEDULER_cancel (sched, die_task);

      expected_connections = -1;
      if ((pg != NULL) && (peers_left == 0))
        {
          expected_connections = GNUNET_TESTING_connect_topology (pg, connect_topology, connect_topology_option, connect_topology_option_modifier);
          peer_connect_meter = create_meter(expected_connections, "Peer connection ", GNUNET_YES);
#if VERBOSE
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Have %d expected connections\n", expected_connections);
#endif
        }

      if (expected_connections == GNUNET_SYSERR)
        {
          die_task = GNUNET_SCHEDULER_add_now (sched,
                                               &end_badly, "from connect topology (bad return)");
        }

      die_task = GNUNET_SCHEDULER_add_delayed (sched,
                                               GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, DEFAULT_CONNECT_TIMEOUT * expected_connections),
                                               &end_badly, "from connect topology (timeout)");

      ok = 0;
    }
}

static void
create_topology ()
{
  peers_left = num_peers; /* Reset counter */
  if (GNUNET_TESTING_create_topology (pg, topology, blacklist_topology, blacklist_transports) != GNUNET_SYSERR)
    {
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Topology set up, now starting peers!\n");
#endif
      GNUNET_TESTING_daemons_continue_startup(pg);
    }
  else
    {
      GNUNET_SCHEDULER_cancel (sched, die_task);
      die_task = GNUNET_SCHEDULER_add_now (sched,
                                           &end_badly, "from create topology (bad return)");
    }
  GNUNET_SCHEDULER_cancel (sched, die_task);
  die_task = GNUNET_SCHEDULER_add_delayed (sched,
                                           GNUNET_TIME_relative_multiply(seconds_per_peer_start, num_peers),
                                           &end_badly, "from continue startup (timeout)");
}

/**
 * Callback indicating that the hostkey was created for a peer.
 *
 * @param cls NULL
 * @param id the peer identity
 * @param d the daemon handle (pretty useless at this point, remove?)
 * @param emsg non-null on failure
 */
void hostkey_callback (void *cls,
                       const struct GNUNET_PeerIdentity *id,
                       struct GNUNET_TESTING_Daemon *d,
                       const char *emsg)
{
  if (emsg != NULL)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Hostkey callback received error: %s\n", emsg);
    }

#if VERBOSE > 1
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Hostkey (%d/%d) created for peer `%s'\n",
                num_peers - peers_left, num_peers, GNUNET_i2s(id));
#endif

    peers_left--;
    if (GNUNET_YES == update_meter(hostkey_meter))
      {
#if VERBOSE
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "All %d hostkeys created, now creating topology!\n",
                    num_peers);
#endif
        GNUNET_SCHEDULER_cancel (sched, die_task);
        /* Set up task in case topology creation doesn't finish
         * within a reasonable amount of time */
        die_task = GNUNET_SCHEDULER_add_delayed (sched,
                                                 DEFAULT_TOPOLOGY_TIMEOUT,
                                                 &end_badly, "from create_topology");
        GNUNET_SCHEDULER_add_now(sched, &create_topology, NULL);
        ok = 0;
      }
}


static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *s,
     char *const *args,
     const char *cfgfile, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char * topology_str;
  char * connect_topology_str;
  char * blacklist_topology_str;
  char * connect_topology_option_str;
  char * connect_topology_option_modifier_string;
  char *trialmessage;
  char * topology_percentage_str;
  float topology_percentage;
  char * topology_probability_str;
  float topology_probability;
  unsigned long long temp_config_number;

  sched = s;

  /* Get path from configuration file */
  if (GNUNET_YES != GNUNET_CONFIGURATION_get_value_string(cfg, "paths", "servicehome", &test_directory))
    {
      ok = 404;
      return;
    }

  /**
   * Get DHT specific testing options.
   */
  if ((GNUNET_YES == GNUNET_CONFIGURATION_get_value_yesno(cfg, "dht_testing", "mysql_logging"))||
      (GNUNET_YES == GNUNET_CONFIGURATION_get_value_yesno(cfg, "dht_testing", "mysql_logging_extended")))
    {
      dhtlog_handle = GNUNET_DHTLOG_connect(cfg);
      if (dhtlog_handle == NULL)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                      "Could not connect to mysql server for logging, will NOT log dht operations!");
          ok = 3306;
          return;
        }
    }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "dht_testing", "comment",
                                                 &trialmessage))
    trialmessage = NULL;

  if (GNUNET_OK !=
          GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing", "malicious_getters",
                                                 &malicious_getters))
    malicious_getters = 0;

  if (GNUNET_OK !=
          GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing", "malicious_putters",
                                                 &malicious_putters))
    malicious_putters = 0;

  if (GNUNET_OK !=
            GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing", "malicious_droppers",
                                                   &malicious_droppers))
    malicious_droppers = 0;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing", "settle_time",
                                                 &settle_time))
    settle_time = 0;

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing", "num_puts",
                                             &num_puts))
    num_puts = num_peers;

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing", "num_gets",
                                             &num_gets))
    num_gets = num_peers;

  if (GNUNET_OK ==
        GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing", "get_timeout",
                                               &temp_config_number))
    get_timeout = GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, temp_config_number);
  else
    get_timeout = DEFAULT_GET_TIMEOUT;

  if (GNUNET_OK ==
        GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing", "concurrent_puts",
                                               &temp_config_number))
    max_outstanding_puts = temp_config_number;
  else
    max_outstanding_puts = DEFAULT_MAX_OUTSTANDING_PUTS;

  if (GNUNET_OK ==
        GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing", "concurrent_gets",
                                               &temp_config_number))
    max_outstanding_gets = temp_config_number;
  else
    max_outstanding_gets = DEFAULT_MAX_OUTSTANDING_GETS;

  if (GNUNET_OK ==
        GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing", "timeout",
                                               &temp_config_number))
    all_get_timeout = GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, temp_config_number);
  else
    all_get_timeout.value = get_timeout.value * ((num_gets / max_outstanding_gets) + 1);

  if (GNUNET_OK ==
        GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing", "get_delay",
                                               &temp_config_number))
    get_delay = GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, temp_config_number);
  else
    get_delay = DEFAULT_GET_DELAY;

  if (GNUNET_OK ==
        GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing", "put_delay",
                                               &temp_config_number))
    put_delay = GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, temp_config_number);
  else
    put_delay = DEFAULT_PUT_DELAY;

  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing", "peer_start_timeout",
                                             &temp_config_number))
    seconds_per_peer_start = GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, temp_config_number);
  else
    seconds_per_peer_start = DEFAULT_SECONDS_PER_PEER_START;

  if (GNUNET_OK ==
        GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing", "data_size",
                                               &temp_config_number))
    test_data_size = temp_config_number;
  else
    test_data_size = DEFAULT_TEST_DATA_SIZE;

  /**
   * Get testing related options.
   */
  if ((GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_string(cfg, "testing", "topology",
                                            &topology_str)) && (GNUNET_NO == GNUNET_TESTING_topology_get(&topology, topology_str)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Invalid topology `%s' given for section %s option %s\n", topology_str, "TESTING", "TOPOLOGY");
      topology = GNUNET_TESTING_TOPOLOGY_CLIQUE; /* Defaults to NONE, so set better default here */
    }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "testing", "percentage",
                                                 &topology_percentage_str))
    topology_percentage = 0.5;
  else
    {
      topology_percentage = atof (topology_percentage_str);
    }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "testing", "probability",
                                                 &topology_probability_str))
    topology_probability = 0.5;
  else
    {
     topology_probability = atof (topology_probability_str);
    }

  if ((GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_string(cfg, "testing", "connect_topology",
                                            &connect_topology_str)) && (GNUNET_NO == GNUNET_TESTING_topology_get(&connect_topology, connect_topology_str)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Invalid connect topology `%s' given for section %s option %s\n", connect_topology_str, "TESTING", "CONNECT_TOPOLOGY");
    }
  GNUNET_free_non_null(connect_topology_str);
  if ((GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_string(cfg, "testing", "connect_topology_option",
                                            &connect_topology_option_str)) && (GNUNET_NO == GNUNET_TESTING_topology_option_get(&connect_topology_option, connect_topology_option_str)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Invalid connect topology option `%s' given for section %s option %s\n", connect_topology_option_str, "TESTING", "CONNECT_TOPOLOGY_OPTION");
      connect_topology_option = GNUNET_TESTING_TOPOLOGY_OPTION_ALL; /* Defaults to NONE, set to ALL */
    }
  GNUNET_free_non_null(connect_topology_option_str);
  if (GNUNET_YES ==
        GNUNET_CONFIGURATION_get_value_string (cfg, "testing", "connect_topology_option_modifier",
                                               &connect_topology_option_modifier_string))
    {
      if (sscanf(connect_topology_option_modifier_string, "%lf", &connect_topology_option_modifier) != 1)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
        _("Invalid value `%s' for option `%s' in section `%s': expected float\n"),
        connect_topology_option_modifier_string,
        "connect_topology_option_modifier",
        "TESTING");
      }
      GNUNET_free (connect_topology_option_modifier_string);
    }

  if (GNUNET_YES != GNUNET_CONFIGURATION_get_value_string (cfg, "testing", "blacklist_transports",
                                         &blacklist_transports))
    blacklist_transports = NULL;

  if ((GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_string(cfg, "testing", "blacklist_topology",
                                            &blacklist_topology_str)) &&
      (GNUNET_NO == GNUNET_TESTING_topology_get(&blacklist_topology, blacklist_topology_str)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Invalid topology `%s' given for section %s option %s\n", topology_str, "TESTING", "BLACKLIST_TOPOLOGY");
    }
  GNUNET_free_non_null(topology_str);
  GNUNET_free_non_null(blacklist_topology_str);

  /* Get number of peers to start from configuration */
  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "testing", "num_peers",
                                             &num_peers))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Number of peers must be specified in section %s option %s\n", topology_str, "TESTING", "NUM_PEERS");
    }

  /* Set peers_left so we know when all peers started */
  peers_left = num_peers;

  /* Set up a task to end testing if peer start fails */
  die_task = GNUNET_SCHEDULER_add_delayed (sched,
                                           GNUNET_TIME_relative_multiply(seconds_per_peer_start, num_peers),
                                           &end_badly, "didn't generate all hostkeys within allowed startup time!");

  if (dhtlog_handle == NULL)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "dhtlog_handle is NULL!");

  if ((trialmessage != NULL) && (dhtlog_handle != NULL))
    {
      dhtlog_handle->insert_trial (&trialuid, peers_left, topology,
                                    blacklist_topology, connect_topology,
                                    connect_topology_option,
                                    connect_topology_option_modifier, topology_percentage,
                                    topology_probability, num_puts, num_gets,
                                    max_outstanding_gets, settle_time, 1,
                                    malicious_getters, malicious_putters,
                                    malicious_droppers, trialmessage);
    }
  else if (dhtlog_handle != NULL)
    {
      dhtlog_handle->insert_trial (&trialuid, peers_left, topology,
                                    blacklist_topology, connect_topology,
                                    connect_topology_option,
                                    connect_topology_option_modifier, topology_percentage,
                                    topology_probability, num_puts, num_gets,
                                    max_outstanding_gets, settle_time, 1,
                                    malicious_getters, malicious_putters,
                                    malicious_droppers, "");
    }

  hostkey_meter = create_meter(peers_left, "Hostkeys created ", GNUNET_YES);
  peer_start_meter = create_meter(peers_left, "Peers started ", GNUNET_YES);

  put_meter = create_meter(num_gets, "Puts completed ", GNUNET_YES);
  get_meter = create_meter(num_gets, "Gets completed ", GNUNET_YES);
  pg = GNUNET_TESTING_daemons_start (sched, cfg,
                                     peers_left,
                                     GNUNET_TIME_relative_multiply(seconds_per_peer_start, num_peers),
                                     &hostkey_callback, NULL,
                                     &peers_started_callback, NULL,
                                     &topology_callback, NULL,
                                     NULL);

}


int
main (int argc, char *argv[])
{
  int ret;
  struct GNUNET_GETOPT_CommandLineOption options[] = {
      GNUNET_GETOPT_OPTION_END
    };

  ret = GNUNET_PROGRAM_run (argc,
                            argv, "gnunet-dht-driver", "nohelp",
                            options, &run, &ok);

  if (ret != GNUNET_OK)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "`gnunet-dht-driver': Failed with error code %d\n", ret);
    }

  /**
   * Need to remove base directory, subdirectories taken care
   * of by the testing framework.
   */
  if (GNUNET_DISK_directory_remove (test_directory) != GNUNET_OK)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Failed to remove testing directory %s\n", test_directory);
    }
  return ret;
}

/* end of test_dht_twopeer_put_get.c */
