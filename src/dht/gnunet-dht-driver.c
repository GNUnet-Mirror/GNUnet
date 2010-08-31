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
 *        logged to a (mysql) database, or to file.
 *
 * FIXME: Do churn!
 */
#include "platform.h"
#include "gnunet_testing_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_dht_service.h"
#include "dhtlog.h"
#include "dht.h"

/* DEFINES */
#define VERBOSE GNUNET_NO

/* Timeout for entire driver to run */
#define DEFAULT_TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 5)

/* Timeout for waiting for (individual) replies to get requests */
#define DEFAULT_GET_TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 90)

#define DEFAULT_TOPOLOGY_CAPTURE_TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 90)

/* Timeout for waiting for gets to be sent to the service */
#define DEFAULT_GET_DELAY GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 10)

/* Timeout for waiting for puts to be sent to the service */
#define DEFAULT_PUT_DELAY GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 10)

/* Timeout for waiting for puts to be sent to the service */
#define DEFAULT_FIND_PEER_DELAY GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 40)

#define DEFAULT_SECONDS_PER_PEER_START GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 45)

#define DEFAULT_TEST_DATA_SIZE 8

#define DEFAULT_BUCKET_SIZE 4

#define FIND_PEER_THRESHOLD DEFAULT_BUCKET_SIZE * 2

#define DEFAULT_MAX_OUTSTANDING_PUTS 10

#define DEFAULT_MAX_OUTSTANDING_FIND_PEERS 10

#define DEFAULT_FIND_PEER_OFFSET GNUNET_TIME_relative_divide (DEFAULT_FIND_PEER_DELAY, DEFAULT_MAX_OUTSTANDING_FIND_PEERS)

#define DEFAULT_MAX_OUTSTANDING_GETS 10

#define DEFAULT_CONNECT_TIMEOUT 60

#define DEFAULT_TOPOLOGY_TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 8)

/*
 * Default frequency for sending malicious get messages
 */
#define DEFAULT_MALICIOUS_GET_FREQUENCY 1000 /* Number of milliseconds */

/*
 * Default frequency for sending malicious put messages
 */
#define DEFAULT_MALICIOUS_PUT_FREQUENCY 1000 /* Default is in milliseconds */

/* Structs */

struct MaliciousContext
{
  /**
   * Handle to DHT service (via the API)
   */
  struct GNUNET_DHT_Handle *dht_handle;

  /**
   *  Handle to the peer daemon
   */
  struct GNUNET_TESTING_Daemon *daemon;

  /**
   * Task for disconnecting DHT handles
   */
  GNUNET_SCHEDULER_TaskIdentifier disconnect_task;

  /**
   * What type of malicious to set this peer to.
   */
  int malicious_type;
};

struct TestFindPeer
{
  /* This is a linked list */
  struct TestFindPeer *next;

  /* Handle to the bigger context */
  struct FindPeerContext *find_peer_context;

  /**
   * Handle to the peer's DHT service (via the API)
   */
  struct GNUNET_DHT_Handle *dht_handle;

  /**
   *  Handle to the peer daemon
   */
  struct GNUNET_TESTING_Daemon *daemon;

  /**
   * Task for disconnecting DHT handles
   */
  GNUNET_SCHEDULER_TaskIdentifier disconnect_task;
};

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

/**
 * Linked list of information for populating statistics
 * before ending trial.
 */
struct StatisticsIteratorContext
{
  const struct GNUNET_PeerIdentity *peer;
  unsigned int stat_routes;
  unsigned int stat_route_forwards;
  unsigned int stat_results;
  unsigned int stat_results_to_client;
  unsigned int stat_result_forwards;
  unsigned int stat_gets;
  unsigned int stat_puts;
  unsigned int stat_puts_inserted;
  unsigned int stat_find_peer;
  unsigned int stat_find_peer_start;
  unsigned int stat_get_start;
  unsigned int stat_put_start;
  unsigned int stat_find_peer_reply;
  unsigned int stat_get_reply;
  unsigned int stat_find_peer_answer;
  unsigned int stat_get_response_start;
};

/**
 * Context for getting a topology, logging it, and continuing
 * on with some next operation.
 */
struct TopologyIteratorContext
{
  unsigned int total_connections;
  struct GNUNET_PeerIdentity *peer;
  GNUNET_SCHEDULER_Task cont;
  void *cls;
  struct GNUNET_TIME_Relative timeout;
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

static struct GNUNET_TIME_Relative find_peer_delay;

static struct GNUNET_TIME_Relative find_peer_offset;

static struct GNUNET_TIME_Relative seconds_per_peer_start;

static int do_find_peer;

static unsigned long long test_data_size = DEFAULT_TEST_DATA_SIZE;

static unsigned long long max_outstanding_puts = DEFAULT_MAX_OUTSTANDING_PUTS;

static unsigned long long max_outstanding_gets = DEFAULT_MAX_OUTSTANDING_GETS;

static unsigned long long malicious_getters;

static unsigned long long max_outstanding_find_peers;

static unsigned long long malicious_putters;

static unsigned long long malicious_droppers;

static unsigned long long malicious_get_frequency;

static unsigned long long malicious_put_frequency;

static unsigned long long settle_time;

static struct GNUNET_DHTLOG_Handle *dhtlog_handle;

static unsigned long long trialuid;

/**
 * Hash map of stats contexts.
 */
struct GNUNET_CONTAINER_MultiHashMap *stats_map;

/**
 * LL of malicious settings.
 */
struct MaliciousContext *all_malicious;

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
 * Global config handle.
 */
const struct GNUNET_CONFIGURATION_Handle *config;

/**
 * Total number of peers to run, set based on config file.
 */
static unsigned long long num_peers;

/**
 * Total number of items to insert.
 */
static unsigned long long num_puts;

/**
 * How many puts do we currently have in flight?
 */
static unsigned long long outstanding_puts;

/**
 * How many puts are done?
 */
static unsigned long long puts_completed;

/**
 * Total number of items to attempt to get.
 */
static unsigned long long num_gets;

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
 * How many malicious control messages do
 * we currently have in flight?
 */
static unsigned long long outstanding_malicious;

/**
 * How many set malicious peers are done?
 */
static unsigned long long malicious_completed;

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
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Ending test normally!\n", (char *)cls);
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

  if (dhtlog_handle != NULL)
    {
      fprintf(stderr, "Update trial endtime\n");
      dhtlog_handle->update_trial (trialuid, gets_completed);
      GNUNET_DHTLOG_disconnect(dhtlog_handle);
      dhtlog_handle = NULL;
    }

  if (hostkey_meter != NULL)
    free_meter(hostkey_meter);
  if (peer_start_meter != NULL)
    free_meter(peer_start_meter);
  if (peer_connect_meter != NULL)
    free_meter(peer_connect_meter);
  if (put_meter != NULL)
    free_meter(put_meter);
  if (get_meter != NULL)
    free_meter(get_meter);

  ok = 0;
}

/**
 * Callback for iterating over all the peer connections of a peer group.
 */
void log_topology_cb (void *cls,
                      const struct GNUNET_PeerIdentity *first,
                      const struct GNUNET_PeerIdentity *second,
                      struct GNUNET_TIME_Relative latency,
                      uint32_t distance,
                      const char *emsg)
{
  struct TopologyIteratorContext *topo_ctx = cls;
  if ((first != NULL) && (second != NULL))
    {
      topo_ctx->total_connections++;
      if (GNUNET_YES == GNUNET_CONFIGURATION_get_value_yesno(config, "dht_testing", "mysql_logging_extended"))
        dhtlog_handle->insert_extended_topology(first, second);
    }
  else
    {
      GNUNET_assert(dhtlog_handle != NULL);
      fprintf(stderr, "topology iteration finished (%u connections), scheduling continuation\n", topo_ctx->total_connections);
      dhtlog_handle->update_topology(topo_ctx->total_connections);
      if (topo_ctx->cont != NULL)
        GNUNET_SCHEDULER_add_now (sched, topo_ctx->cont, topo_ctx->cls);
      GNUNET_free(topo_ctx);
    }
}

/**
 * Iterator over hash map entries.
 *
 * @param cls closure - always NULL
 * @param key current key code
 * @param value value in the hash map, a stats context
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
static int stats_iterate (void *cls,
                          const GNUNET_HashCode * key,
                          void *value)
{
  struct StatisticsIteratorContext *stats_ctx;
  if (value == NULL)
    return GNUNET_NO;
  stats_ctx = value;
  dhtlog_handle->insert_stat(stats_ctx->peer, stats_ctx->stat_routes, stats_ctx->stat_route_forwards, stats_ctx->stat_results,
                             stats_ctx->stat_results_to_client, stats_ctx->stat_result_forwards, stats_ctx->stat_gets,
                             stats_ctx->stat_puts, stats_ctx->stat_puts_inserted, stats_ctx->stat_find_peer,
                             stats_ctx->stat_find_peer_start, stats_ctx->stat_get_start, stats_ctx->stat_put_start,
                             stats_ctx->stat_find_peer_reply, stats_ctx->stat_get_reply, stats_ctx->stat_find_peer_answer,
                             stats_ctx->stat_get_response_start);
  GNUNET_free(stats_ctx);
  return GNUNET_YES;
}

static void stats_finished (void *cls, int result)
{
  fprintf(stderr, "Finished getting all peers statistics, iterating!\n");
  GNUNET_CONTAINER_multihashmap_iterate(stats_map, &stats_iterate, NULL);
  GNUNET_CONTAINER_multihashmap_destroy(stats_map);
  GNUNET_SCHEDULER_add_now (sched, &finish_testing, NULL);
}

/**
 * Callback function to process statistic values.
 *
 * @param cls closure
 * @param peer the peer the statistics belong to
 * @param subsystem name of subsystem that created the statistic
 * @param name the name of the datum
 * @param value the current value
 * @param is_persistent GNUNET_YES if the value is persistent, GNUNET_NO if not
 * @return GNUNET_OK to continue, GNUNET_SYSERR to abort iteration
 */
static int stats_handle  (void *cls,
                          const struct GNUNET_PeerIdentity *peer,
                          const char *subsystem,
                          const char *name,
                          uint64_t value,
                          int is_persistent)
{
  struct StatisticsIteratorContext *stats_ctx;

  if (dhtlog_handle != NULL)
    dhtlog_handle->add_generic_stat(peer, name, subsystem, value);
  if (GNUNET_CONTAINER_multihashmap_contains(stats_map, &peer->hashPubKey))
    {
      stats_ctx = GNUNET_CONTAINER_multihashmap_get(stats_map, &peer->hashPubKey);
    }
  else
    {
      stats_ctx = GNUNET_malloc(sizeof(struct StatisticsIteratorContext));
      stats_ctx->peer = peer;
      GNUNET_CONTAINER_multihashmap_put(stats_map, &peer->hashPubKey, stats_ctx, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
    }
  GNUNET_assert(stats_ctx != NULL);

  if (strcmp(name, STAT_ROUTES) == 0)
    stats_ctx->stat_routes = value;
  else if (strcmp(name, STAT_ROUTE_FORWARDS) == 0)
    stats_ctx->stat_route_forwards = value;
  else if (strcmp(name, STAT_RESULTS) == 0)
    stats_ctx->stat_results = value;
  else if (strcmp(name, STAT_RESULTS_TO_CLIENT) == 0)
    stats_ctx->stat_results_to_client = value;
  else if (strcmp(name, STAT_RESULT_FORWARDS) == 0)
    stats_ctx->stat_result_forwards = value;
  else if (strcmp(name, STAT_GETS) == 0)
    stats_ctx->stat_gets = value;
  else if (strcmp(name, STAT_PUTS) == 0)
    stats_ctx->stat_puts = value;
  else if (strcmp(name, STAT_PUTS_INSERTED) == 0)
    stats_ctx->stat_puts_inserted = value;
  else if (strcmp(name, STAT_FIND_PEER) == 0)
    stats_ctx->stat_find_peer = value;
  else if (strcmp(name, STAT_FIND_PEER_START) == 0)
    stats_ctx->stat_find_peer_start = value;
  else if (strcmp(name, STAT_GET_START) == 0)
    stats_ctx->stat_get_start = value;
  else if (strcmp(name, STAT_PUT_START) == 0)
    stats_ctx->stat_put_start = value;
  else if (strcmp(name, STAT_FIND_PEER_REPLY) == 0)
    stats_ctx->stat_find_peer_reply = value;
  else if (strcmp(name, STAT_GET_REPLY) == 0)
    stats_ctx->stat_get_reply = value;
  else if (strcmp(name, STAT_FIND_PEER_ANSWER) == 0)
    stats_ctx->stat_find_peer_answer = value;
  else if (strcmp(name, STAT_GET_RESPONSE_START) == 0)
    stats_ctx->stat_get_response_start = value;

  return GNUNET_OK;
}

/**
 * Connect to statistics service for each peer and get the appropriate
 * dht statistics for safe keeping.
 */
static void
log_dht_statistics (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  stats_map = GNUNET_CONTAINER_multihashmap_create(num_peers);
  fprintf(stderr, "Starting statistics logging\n");
  GNUNET_TESTING_get_statistics(pg, &stats_finished, &stats_handle, NULL);
}


/**
 * Connect to all peers in the peer group and iterate over their
 * connections.
 */
static void
capture_current_topology (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  struct TopologyIteratorContext *topo_ctx = cls;
  dhtlog_handle->insert_topology(0);
  GNUNET_TESTING_get_topology (pg, &log_topology_cb, topo_ctx);
}


/**
 * Check if the get_handle is being used, if so stop the request.  Either
 * way, schedule the end_badly_cont function which actually shuts down the
 * test.
 */
static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Failing test with error: `%s'!\n", (char *)cls);

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

  if (dhtlog_handle != NULL)
    {
      fprintf(stderr, "Update trial endtime\n");
      dhtlog_handle->update_trial (trialuid, gets_completed);
      GNUNET_DHTLOG_disconnect(dhtlog_handle);
      dhtlog_handle = NULL;
    }

  if (hostkey_meter != NULL)
    free_meter(hostkey_meter);
  if (peer_start_meter != NULL)
    free_meter(peer_start_meter);
  if (peer_connect_meter != NULL)
    free_meter(peer_connect_meter);
  if (put_meter != NULL)
    free_meter(put_meter);
  if (get_meter != NULL)
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
  struct TopologyIteratorContext *topo_ctx;
  outstanding_gets--; /* GET is really finished */
  GNUNET_DHT_disconnect(test_get->dht_handle);
  test_get->dht_handle = NULL;

#if VERBOSE > 1
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%d gets succeeded, %d gets failed!\n", gets_completed, gets_failed);
#endif
  update_meter(get_meter);
  if ((gets_completed + gets_failed == num_gets) && (outstanding_gets == 0))
    {
      GNUNET_SCHEDULER_cancel(sched, die_task);
      //GNUNET_SCHEDULER_add_now(sched, &finish_testing, NULL);
      if (dhtlog_handle != NULL)
        {
          topo_ctx = GNUNET_malloc(sizeof(struct TopologyIteratorContext));
          topo_ctx->cont = &log_dht_statistics;
          GNUNET_SCHEDULER_add_now(sched, &capture_current_topology, topo_ctx);
        }
      else
        GNUNET_SCHEDULER_add_now (sched, &finish_testing, NULL);
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
  struct TopologyIteratorContext *topo_ctx;
  outstanding_puts--;
  puts_completed++;

  if (tc->reason == GNUNET_SCHEDULER_REASON_TIMEOUT)
    fprintf(stderr, "PUT Request failed!\n");

  GNUNET_SCHEDULER_cancel(sched, test_put->disconnect_task);
  test_put->disconnect_task = GNUNET_SCHEDULER_add_now(sched, &put_disconnect_task, test_put);
  if (GNUNET_YES == update_meter(put_meter))
    {
      GNUNET_assert(outstanding_puts == 0);
      GNUNET_SCHEDULER_cancel (sched, die_task);
      if (dhtlog_handle != NULL)
        {
          topo_ctx = GNUNET_malloc(sizeof(struct TopologyIteratorContext));
          topo_ctx->cont = &do_get;
          topo_ctx->cls = all_gets;
          topo_ctx->timeout = DEFAULT_GET_TIMEOUT;
          die_task = GNUNET_SCHEDULER_add_delayed (sched, GNUNET_TIME_relative_add(GNUNET_TIME_relative_add(DEFAULT_GET_TIMEOUT, all_get_timeout), DEFAULT_TOPOLOGY_CAPTURE_TIMEOUT),
                                                   &end_badly, "from do gets");
          GNUNET_SCHEDULER_add_now(sched, &capture_current_topology, topo_ctx);
        }
      else
        {
          die_task = GNUNET_SCHEDULER_add_delayed (sched, GNUNET_TIME_relative_add(DEFAULT_GET_TIMEOUT, all_get_timeout),
                                                       &end_badly, "from do gets");
          GNUNET_SCHEDULER_add_delayed(sched, DEFAULT_GET_TIMEOUT, &do_get, all_gets);
          GNUNET_SCHEDULER_add_now (sched, &finish_testing, NULL);
        }
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
 * Context for sending out find peer requests.
 */
struct FindPeerContext
{
  struct GNUNET_DHT_Handle *dht_handle;
  struct GNUNET_TIME_Absolute endtime;
  unsigned int current_peers;
  unsigned int previous_peers;
  unsigned int outstanding;
  unsigned int total;
};

static void
schedule_find_peer_requests (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc);

/**
 * Given a number of total peers and a bucket size, estimate the number of
 * connections in a perfect kademlia topology.
 */
static unsigned int connection_estimate(unsigned int peer_count, unsigned int bucket_size)
{
  unsigned int i;
  unsigned int filled;
  i = num_peers;

  filled = 0;
  while (i > bucket_size)
    {
      filled++;
      i = i/2;
    }
  return filled * bucket_size * peer_count;

}

/**
 * Callback for iterating over all the peer connections of a peer group.
 */
void count_peers_cb (void *cls,
                      const struct GNUNET_PeerIdentity *first,
                      const struct GNUNET_PeerIdentity *second,
                      struct GNUNET_TIME_Relative latency,
                      uint32_t distance,
                      const char *emsg)
{
  struct FindPeerContext *find_peer_context = cls;
  if ((first != NULL) && (second != NULL))
    {
      find_peer_context->current_peers++;
    }
  else
    {
      GNUNET_assert(dhtlog_handle != NULL);
      fprintf(stderr, "peer count finished (%u connections), %u new peers, connection estimate %u\n", find_peer_context->current_peers, find_peer_context->current_peers - find_peer_context->previous_peers, connection_estimate(num_peers, DEFAULT_BUCKET_SIZE));
      if ((find_peer_context->current_peers - find_peer_context->previous_peers > FIND_PEER_THRESHOLD) &&
          (find_peer_context->current_peers < connection_estimate(num_peers, DEFAULT_BUCKET_SIZE)) &&
          (GNUNET_TIME_absolute_get_remaining(find_peer_context->endtime).value > 0))
        {
          GNUNET_SCHEDULER_add_now(sched, schedule_find_peer_requests, find_peer_context);
        }
      else
        {
          fprintf(stderr, "Not sending any more find peer requests.\n");
        }
    }
}

/**
 * Connect to all peers in the peer group and iterate over their
 * connections.
 */
static void
count_new_peers (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  struct FindPeerContext *find_peer_context = cls;
  find_peer_context->previous_peers = find_peer_context->current_peers;
  find_peer_context->current_peers = 0;
  GNUNET_TESTING_get_topology (pg, &count_peers_cb, find_peer_context);
}


static void
decrement_find_peers (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  struct TestFindPeer *test_find_peer = cls;
  GNUNET_assert(test_find_peer->find_peer_context->outstanding > 0);
  test_find_peer->find_peer_context->outstanding--;
  test_find_peer->find_peer_context->total--;
  if ((0 == test_find_peer->find_peer_context->total) &&
      (GNUNET_TIME_absolute_get_remaining(test_find_peer->find_peer_context->endtime).value > 0))
  {
    GNUNET_SCHEDULER_add_now(sched, &count_new_peers, test_find_peer->find_peer_context);
  }
  GNUNET_free(test_find_peer);
}

/**
 * A find peer request has been sent to the server, now we will schedule a task
 * to wait the appropriate time to allow the request to go out and back.
 *
 * @param cls closure - a TestFindPeer struct
 * @param tc context the task is being called with
 */
static void
handle_find_peer_sent (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  struct TestFindPeer *test_find_peer = cls;

  GNUNET_DHT_disconnect(test_find_peer->dht_handle);
  GNUNET_SCHEDULER_add_delayed(sched, find_peer_delay, &decrement_find_peers, test_find_peer);
}

static void
send_find_peer_request (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  struct TestFindPeer *test_find_peer = cls;

  if (test_find_peer->find_peer_context->outstanding > max_outstanding_find_peers)
  {
    GNUNET_SCHEDULER_add_delayed(sched, DEFAULT_FIND_PEER_OFFSET, &send_find_peer_request, test_find_peer);
    return;
  }

  test_find_peer->find_peer_context->outstanding++;
  if (GNUNET_TIME_absolute_get_remaining(test_find_peer->find_peer_context->endtime).value == 0)
  {
    GNUNET_SCHEDULER_add_now(sched, &decrement_find_peers, test_find_peer);
    return;
  }

  test_find_peer->dht_handle = GNUNET_DHT_connect(sched, test_find_peer->daemon->cfg, 1);
  GNUNET_assert(test_find_peer->dht_handle != NULL);
  GNUNET_DHT_find_peers (test_find_peer->dht_handle,
                         &handle_find_peer_sent, test_find_peer);
}

/**
 * Set up a single find peer request for each peer in the topology.  Do this
 * until the settle time is over, limited by the number of outstanding requests
 * and the time allowed for each one!
 */
static void
schedule_find_peer_requests (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  struct FindPeerContext *find_peer_ctx = cls;
  struct TestFindPeer *test_find_peer;
  uint32_t i;
  uint32_t random;

  for (i = 0; i < max_outstanding_find_peers; i++)
    {
      test_find_peer = GNUNET_malloc(sizeof(struct TestFindPeer));
      random = GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, num_peers);
      test_find_peer->daemon  = GNUNET_TESTING_daemon_get(pg, random);
      test_find_peer->find_peer_context = find_peer_ctx;
      find_peer_ctx->total++;
      GNUNET_SCHEDULER_add_delayed(sched, GNUNET_TIME_relative_multiply(DEFAULT_FIND_PEER_OFFSET, i), &send_find_peer_request, test_find_peer);
    }
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

  memset(&remember, 0, sizeof(int) * num_puts * num_peers);
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

  /*GNUNET_SCHEDULER_cancel (sched, die_task);*/
  die_task = GNUNET_SCHEDULER_add_delayed (sched, GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, num_puts * 2),
                                           &end_badly, "from do puts");
  GNUNET_SCHEDULER_add_now (sched, &do_put, all_puts);
}

/**
 * Set up some all of the put and get operations we want
 * to do.  Allocate data structure for each, add to list,
 * then call actual insert functions.
 */
static void
continue_puts_and_gets (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  int i;
  int max;
  struct TopologyIteratorContext *topo_ctx;
  struct FindPeerContext *find_peer_context;
  if (dhtlog_handle != NULL)
    {
      if (settle_time >= 60 * 2)
        max = (settle_time / 60) - 2;
      else
        max = 1;
      for (i = 1; i < max; i++)
        {
          topo_ctx = GNUNET_malloc(sizeof(struct TopologyIteratorContext));
          fprintf(stderr, "scheduled topology iteration in %d minutes\n", i);
          GNUNET_SCHEDULER_add_delayed(sched, GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, i), &capture_current_topology, topo_ctx);
        }
      topo_ctx = GNUNET_malloc(sizeof(struct TopologyIteratorContext));
      topo_ctx->cont = &setup_puts_and_gets;
      GNUNET_SCHEDULER_add_delayed(sched, GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, settle_time), &capture_current_topology, topo_ctx);
    }
  else
    GNUNET_SCHEDULER_add_delayed(sched, GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, settle_time), &setup_puts_and_gets, NULL);

  if (GNUNET_YES == do_find_peer)
  {
    find_peer_context = GNUNET_malloc(sizeof(struct FindPeerContext));
    find_peer_context->endtime = GNUNET_TIME_relative_to_absolute(GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, settle_time));
    GNUNET_SCHEDULER_add_now(sched, &schedule_find_peer_requests, find_peer_context);
  }
}

/**
 * Task to release DHT handles
 */
static void
malicious_disconnect_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  struct MaliciousContext *ctx = cls;
  outstanding_malicious--;
  malicious_completed++;
  ctx->disconnect_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_DHT_disconnect(ctx->dht_handle);
  ctx->dht_handle = NULL;
  GNUNET_free(ctx);

  if (malicious_completed == malicious_getters + malicious_putters + malicious_droppers)
    {
      GNUNET_SCHEDULER_cancel(sched, die_task);
      fprintf(stderr, "Finished setting all malicious peers up, calling continuation!\n");
      if (dhtlog_handle != NULL)
        GNUNET_SCHEDULER_add_now (sched,
                                  &continue_puts_and_gets, NULL);
      else
        GNUNET_SCHEDULER_add_delayed (sched,
                                    GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, settle_time),
                                    &continue_puts_and_gets, NULL);
    }

}

/**
 * Task to release DHT handles
 */
static void
malicious_done_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  struct MaliciousContext *ctx = cls;
  GNUNET_SCHEDULER_cancel(sched, ctx->disconnect_task);
  GNUNET_SCHEDULER_add_now(sched, &malicious_disconnect_task, ctx);
}

/**
 * Set up some data, and call API PUT function
 */
static void
set_malicious (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  struct MaliciousContext *ctx = cls;
  int ret;

  if (outstanding_malicious > DEFAULT_MAX_OUTSTANDING_GETS)
    {
      GNUNET_SCHEDULER_add_delayed (sched, GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS, 100), &set_malicious, ctx);
      return;
    }

  if (ctx->dht_handle == NULL)
    {
      ctx->dht_handle = GNUNET_DHT_connect(sched, ctx->daemon->cfg, 1);
      outstanding_malicious++;
    }

  GNUNET_assert(ctx->dht_handle != NULL);


#if VERBOSE > 1
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Setting peer %s malicious type %d\n",
                ctx->daemon->shortname, ctx->malicious_type);
#endif

  ret = GNUNET_YES;
  switch (ctx->malicious_type)
  {
  case GNUNET_MESSAGE_TYPE_DHT_MALICIOUS_GET:
    ret = GNUNET_DHT_set_malicious_getter(ctx->dht_handle, malicious_get_frequency, &malicious_done_task, ctx);
    break;
  case GNUNET_MESSAGE_TYPE_DHT_MALICIOUS_PUT:
    ret = GNUNET_DHT_set_malicious_putter(ctx->dht_handle, malicious_put_frequency, &malicious_done_task, ctx);
    break;
  case GNUNET_MESSAGE_TYPE_DHT_MALICIOUS_DROP:
    ret = GNUNET_DHT_set_malicious_dropper(ctx->dht_handle, &malicious_done_task, ctx);
    break;
  default:
    break;
  }

  if (ret == GNUNET_NO)
    {
      GNUNET_SCHEDULER_add_delayed (sched, GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS, 100), &set_malicious, ctx);
    }
  else
    ctx->disconnect_task = GNUNET_SCHEDULER_add_delayed(sched, GNUNET_TIME_relative_get_forever(), &malicious_disconnect_task, ctx);
}

/**
 * Select randomly from set of known peers,
 * set the desired number of peers to the
 * proper malicious types.
 */
static void
setup_malicious_peers (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  struct MaliciousContext *ctx;
  int i;
  uint32_t temp_daemon;

  for (i = 0; i < malicious_getters; i++)
    {
      ctx = GNUNET_malloc(sizeof(struct MaliciousContext));
      temp_daemon = GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, num_peers);
      ctx->daemon = GNUNET_TESTING_daemon_get(pg, temp_daemon);
      ctx->malicious_type = GNUNET_MESSAGE_TYPE_DHT_MALICIOUS_GET;
      GNUNET_SCHEDULER_add_now (sched, &set_malicious, ctx);

    }

  for (i = 0; i < malicious_putters; i++)
    {
      ctx = GNUNET_malloc(sizeof(struct MaliciousContext));
      temp_daemon = GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, num_peers);
      ctx->daemon = GNUNET_TESTING_daemon_get(pg, temp_daemon);
      ctx->malicious_type = GNUNET_MESSAGE_TYPE_DHT_MALICIOUS_PUT;
      GNUNET_SCHEDULER_add_now (sched, &set_malicious, ctx);

    }

  for (i = 0; i < malicious_droppers; i++)
    {
      ctx = GNUNET_malloc(sizeof(struct MaliciousContext));
      temp_daemon = GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, num_peers);
      ctx->daemon = GNUNET_TESTING_daemon_get(pg, temp_daemon);
      ctx->malicious_type = GNUNET_MESSAGE_TYPE_DHT_MALICIOUS_DROP;
      GNUNET_SCHEDULER_add_now (sched, &set_malicious, ctx);
    }

  if (malicious_getters + malicious_putters + malicious_droppers > 0)
    die_task = GNUNET_SCHEDULER_add_delayed (sched, GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, (malicious_getters + malicious_putters + malicious_droppers) * 2),
                                             &end_badly, "from set malicious");
  else
    {
      if (dhtlog_handle != NULL)
        GNUNET_SCHEDULER_add_now (sched,
                                  &continue_puts_and_gets, NULL);
      else
        GNUNET_SCHEDULER_add_delayed (sched,
                                    GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, settle_time),
                                    &continue_puts_and_gets, NULL);
    }

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
  struct TopologyIteratorContext *topo_ctx;
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
        {
          dhtlog_handle->update_connections (trialuid, total_connections);
          dhtlog_handle->insert_topology(expected_connections);
        }

      GNUNET_SCHEDULER_cancel (sched, die_task);
      /*die_task = GNUNET_SCHEDULER_add_delayed (sched, DEFAULT_TIMEOUT,
                                               &end_badly, "from setup puts/gets");*/
      if ((dhtlog_handle != NULL) && (settle_time > 0))
        {
          topo_ctx = GNUNET_malloc(sizeof(struct TopologyIteratorContext));
          topo_ctx->cont = &setup_malicious_peers;
          //topo_ctx->cont = &continue_puts_and_gets;
          GNUNET_SCHEDULER_add_now(sched, &capture_current_topology, topo_ctx);
        }
      else
        {
          GNUNET_SCHEDULER_add_now(sched, &setup_malicious_peers, NULL);
          /*GNUNET_SCHEDULER_add_delayed (sched,
                                        GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, settle_time),
                                        &continue_puts_and_gets, NULL);*/
        }
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
          fprintf(stderr, "Have %d expected connections\n", expected_connections);
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
  GNUNET_free_non_null(blacklist_transports);
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
  struct stat frstat;
  struct GNUNET_TESTING_Host *hosts;
  struct GNUNET_TESTING_Host *temphost;
  char *topology_str;
  char *connect_topology_str;
  char *blacklist_topology_str;
  char *connect_topology_option_str;
  char *connect_topology_option_modifier_string;
  char *trialmessage;
  char *topology_percentage_str;
  float topology_percentage;
  char *topology_probability_str;
  char *hostfile;
  float topology_probability;
  unsigned long long temp_config_number;
  int stop_closest;
  int stop_found;
  int strict_kademlia;
  char *buf;
  char *data;
  int count;

  sched = s;
  config = cfg;
  /* Get path from configuration file */
  if (GNUNET_YES != GNUNET_CONFIGURATION_get_value_string(cfg, "paths", "servicehome", &test_directory))
    {
      ok = 404;
      return;
    }

  /**
   * Get DHT specific testing options.
   */
  if ((GNUNET_YES == GNUNET_CONFIGURATION_get_value_yesno(cfg, "dht_testing", "mysql_logging")) ||
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

  stop_closest = GNUNET_CONFIGURATION_get_value_yesno(cfg, "dht", "stop_on_closest");
  if (stop_closest == GNUNET_SYSERR)
    stop_closest = GNUNET_NO;

  stop_found = GNUNET_CONFIGURATION_get_value_yesno(cfg, "dht", "stop_found");
  if (stop_found == GNUNET_SYSERR)
    stop_found = GNUNET_NO;

  strict_kademlia = GNUNET_CONFIGURATION_get_value_yesno(cfg, "dht", "strict_kademlia");
  if (strict_kademlia == GNUNET_SYSERR)
    strict_kademlia = GNUNET_NO;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "dht_testing", "comment",
                                             &trialmessage))
    trialmessage = NULL;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "testing", "hostfile",
                                             &hostfile))
    hostfile = NULL;

  hosts = NULL;
  temphost = NULL;
  if (hostfile != NULL)
    {
      if (GNUNET_OK != GNUNET_DISK_file_test (hostfile))
          GNUNET_DISK_fn_write (hostfile, NULL, 0, GNUNET_DISK_PERM_USER_READ
            | GNUNET_DISK_PERM_USER_WRITE);
      if ((0 != STAT (hostfile, &frstat)) || (frstat.st_size == 0))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                      "Could not open file specified for host list, ending test!");
          ok = 1119;
          GNUNET_free_non_null(trialmessage);
          GNUNET_free(hostfile);
          return;
        }

    data = GNUNET_malloc_large (frstat.st_size);
    GNUNET_assert(data != NULL);
    if (frstat.st_size !=
        GNUNET_DISK_fn_read (hostfile, data, frstat.st_size))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Could not read file %s specified for host list, ending test!", hostfile);
        GNUNET_free (hostfile);
        GNUNET_free (data);
        GNUNET_free_non_null(trialmessage);
        return;
      }

    GNUNET_free_non_null(hostfile);

    buf = data;
    count = 0;
    while (count < frstat.st_size)
      {
        count++;
        if (((data[count] == '\n') || (data[count] == '\0')) && (buf != &data[count]))
          {
            data[count] = '\0';
            temphost = GNUNET_malloc(sizeof(struct GNUNET_TESTING_Host));
            temphost->hostname = buf;
            temphost->next = hosts;
            hosts = temphost;
            buf = &data[count + 1];
          }
        else if ((data[count] == '\n') || (data[count] == '\0'))
          buf = &data[count + 1];
      }
    }

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
        GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing", "find_peer_delay",
                                               &temp_config_number))
    find_peer_delay = GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, temp_config_number);
  else
    find_peer_delay = DEFAULT_FIND_PEER_DELAY;

  if (GNUNET_OK ==
        GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing", "concurrent_find_peers",
                                               &temp_config_number))
    max_outstanding_find_peers = temp_config_number;
  else
    max_outstanding_find_peers = DEFAULT_MAX_OUTSTANDING_FIND_PEERS;

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

  if (GNUNET_NO == GNUNET_CONFIGURATION_get_value_number (cfg, "DHT_TESTING",
                                                          "MALICIOUS_GET_FREQUENCY",
                                                          &malicious_get_frequency))
    malicious_get_frequency = DEFAULT_MALICIOUS_GET_FREQUENCY;


  if (GNUNET_NO == GNUNET_CONFIGURATION_get_value_number (cfg, "DHT_TESTING",
                                                          "MALICIOUS_PUT_FREQUENCY",
                                                          &malicious_put_frequency))
    malicious_put_frequency = DEFAULT_MALICIOUS_PUT_FREQUENCY;

  if (GNUNET_NO ==
        GNUNET_CONFIGURATION_get_value_yesno(cfg, "dht",
                                             "find_peers"))
    {
      do_find_peer = GNUNET_NO;
    }
  else
    do_find_peer = GNUNET_YES;

  if (GNUNET_YES == GNUNET_CONFIGURATION_get_value_number (cfg, "DHT_TESTING",
                                                          "FIND_PEER_DELAY",
                                                          &temp_config_number))
    {
      find_peer_delay = GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, temp_config_number);
    }
  else
    find_peer_delay = DEFAULT_FIND_PEER_DELAY;

  if (GNUNET_NO == GNUNET_CONFIGURATION_get_value_number (cfg, "DHT_TESTING",
                                                            "OUTSTANDING_FIND_PEERS",
                                                            &max_outstanding_find_peers))
      max_outstanding_find_peers = DEFAULT_MAX_OUTSTANDING_FIND_PEERS;

  if (GNUNET_YES == GNUNET_CONFIGURATION_get_value_yesno(cfg, "dht", "strict_kademlia"))
    max_outstanding_find_peers = max_outstanding_find_peers * 1;

  find_peer_offset = GNUNET_TIME_relative_divide (find_peer_delay, max_outstanding_find_peers);

  topology_str = NULL;
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
      GNUNET_free(topology_percentage_str);
    }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "testing", "probability",
                                                 &topology_probability_str))
    topology_probability = 0.5;
  else
    {
     topology_probability = atof (topology_probability_str);
     GNUNET_free(topology_probability_str);
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
  GNUNET_assert(num_peers > 0 && num_peers < (unsigned long long)-1);
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
                                    malicious_droppers, malicious_get_frequency,
                                    malicious_put_frequency, stop_closest, stop_found,
                                    strict_kademlia, 0, trialmessage);
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
                                    malicious_droppers, malicious_get_frequency,
                                    malicious_put_frequency, stop_closest, stop_found,
                                    strict_kademlia, 0, "");
    }

  GNUNET_free_non_null(trialmessage);

  hostkey_meter = create_meter(peers_left, "Hostkeys created ", GNUNET_YES);
  peer_start_meter = create_meter(peers_left, "Peers started ", GNUNET_YES);

  put_meter = create_meter(num_puts, "Puts completed ", GNUNET_YES);
  get_meter = create_meter(num_gets, "Gets completed ", GNUNET_YES);
  pg = GNUNET_TESTING_daemons_start (sched, cfg,
                                     peers_left,
                                     GNUNET_TIME_relative_multiply(seconds_per_peer_start, num_peers),
                                     &hostkey_callback, NULL,
                                     &peers_started_callback, NULL,
                                     &topology_callback, NULL,
                                     hosts);

  GNUNET_free_non_null(temphost);
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
