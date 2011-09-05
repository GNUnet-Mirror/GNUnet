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
 * @author Nathan Evans (who to blame)
 */
#include "platform.h"
#ifndef HAVE_MALICIOUS
#error foo
#endif
#include "gnunet_testing_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_dht_service.h"
#include "dhtlog.h"
#include "dht.h"
#include "gauger.h"

/* DEFINES */
#define VERBOSE GNUNET_NO

/* Timeout for entire driver to run */
#define DEFAULT_TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 5)

/* Timeout for waiting for (individual) replies to get requests */
#define DEFAULT_GET_TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 10)

#define DEFAULT_TOPOLOGY_CAPTURE_TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 90)

/* Timeout for waiting for gets to be sent to the service */
#define DEFAULT_GET_DELAY GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 10)

/* Timeout for waiting for puts to be sent to the service */
#define DEFAULT_PUT_DELAY GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 10)

/* Time to allow a find peer request to take */
#define DEFAULT_FIND_PEER_DELAY GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 40)

/* Time to wait for all peers disconnected due to to churn to actually be removed from system */
#define DEFAULT_PEER_DISCONNECT_TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 5)

#define DEFAULT_SECONDS_PER_PEER_START GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 45)

#define DEFAULT_TEST_DATA_SIZE 8

#define DEFAULT_BUCKET_SIZE 4

/* If more than this many peers are added, slow down sending */
#define MAX_FIND_PEER_CUTOFF 2000

/* If less than this many peers are added, speed up sending */
#define MIN_FIND_PEER_CUTOFF 500

/* How often (in seconds) to print out connection information */
#define CONN_UPDATE_DURATION 10

#define DEFAULT_MAX_OUTSTANDING_PUTS 10

#define DEFAULT_MAX_OUTSTANDING_FIND_PEERS 64

#define DEFAULT_FIND_PEER_OFFSET GNUNET_TIME_relative_divide (DEFAULT_FIND_PEER_DELAY, DEFAULT_MAX_OUTSTANDING_FIND_PEERS)

#define DEFAULT_MAX_OUTSTANDING_GETS 10

#define DEFAULT_CONNECT_TIMEOUT 60

#define DEFAULT_TOPOLOGY_TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 8)

#define DEFAULT_RECONNECT_ATTEMPTS 8

/*
 * Default frequency for sending malicious get messages
 */
#define DEFAULT_MALICIOUS_GET_FREQUENCY GNUNET_TIME_UNIT_SECONDS

/*
 * Default frequency for sending malicious put messages
 */
#define DEFAULT_MALICIOUS_PUT_FREQUENCY GNUNET_TIME_UNIT_SECONDS

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
  unsigned int total_iterations;
  unsigned int current_iteration;
  unsigned int total_connections;
  unsigned int total_peers;
  struct GNUNET_CONTAINER_MultiHashMap *peers_seen;
  struct GNUNET_PeerIdentity *peer;
  GNUNET_SCHEDULER_Task cont;
  void *cls;
  struct GNUNET_TIME_Relative timeout;
};

struct PeerCount
{
  /** Node in the heap */
  struct GNUNET_CONTAINER_HeapNode *heap_node;

  /** Peer the count refers to */
  struct GNUNET_PeerIdentity peer_id;

  /** Count of connections this peer has */
  unsigned int count;
};

/**
 * Context for sending out find peer requests.
 */
struct FindPeerContext
{
  /**
   * How long to send find peer requests, once the settle time
   * is over don't send any more out!
   */
  struct GNUNET_TIME_Absolute endtime;

  /**
   * Number of connections in the current topology
   * (after this round of find peer requests has ended).
   */
  unsigned int current_peers;

  /**
   * Number of connections in the current topology
   * (before this round of find peer requests started).
   */
  unsigned int previous_peers;

  /**
   * Number of find peer requests we have currently
   * outstanding.
   */
  unsigned int outstanding;

  /**
   * Number of find peer requests to send in this round.
   */
  unsigned int total;

  /**
   * Number of find peer requests sent last time around.
   */
  unsigned int last_sent;

  /**
   * Hashmap of peers in the current topology, value
   * is a PeerCount, with the number of connections
   * this peer has.
   */
  struct GNUNET_CONTAINER_MultiHashMap *peer_hash;

  /**
   * Handle to an active attempt to connect this peer.
   */
  struct GNUNET_TESTING_ConnectContext *cc;

  /**
   * Min heap which orders values in the peer_hash for
   * easy lookup.
   */
  struct GNUNET_CONTAINER_Heap *peer_min_heap;

  /**
   * Callback for counting the peers in the current topology.
   */
  GNUNET_TESTING_NotifyTopology count_peers_cb;
};

enum DHT_ROUND_TYPES
{
  /**
   * Next full round (puts + gets).
   */
  DHT_ROUND_NORMAL,

  /**
   * Next round of gets.
   */
  DHT_ROUND_GET,

  /**
   * Next round of puts.
   */
  DHT_ROUND_PUT,

  /**
   * Next round of churn.
   */
  DHT_ROUND_CHURN
};

/* Globals */

/**
 * How long to try to connect two peers.
 */
struct GNUNET_TIME_Relative connect_timeout;

/**
 * How many times to re-attempt connecting two peers.
 */
static unsigned long long connect_attempts;

/**
 * Timeout to let all GET requests happen.
 */
static struct GNUNET_TIME_Relative all_get_timeout;

/**
 * Per get timeout
 */
static struct GNUNET_TIME_Relative get_timeout;

/**
 * Time to allow for GET requests to be sent to service.
 */
static struct GNUNET_TIME_Relative get_delay;

/**
 * Time to allow for PUT requests to be sent to service.
 */
static struct GNUNET_TIME_Relative put_delay;

/**
 * Delay between sending find peer requests (if
 * handled by the driver, no effect if sent by service).
 */
static struct GNUNET_TIME_Relative find_peer_delay;

/**
 * Time between find peer requests
 * (find_peer_delay / max_outstanding_find_peer)
 */
static struct GNUNET_TIME_Relative find_peer_offset;

/**
 * How many seconds to allow each peer to start.
 */
static struct GNUNET_TIME_Relative seconds_per_peer_start;

/**
 * At what time did we start the connection process.
 */
static struct GNUNET_TIME_Absolute connect_start_time;

/**
 * What was the last time we updated connection/second information.
 */
static struct GNUNET_TIME_Absolute connect_last_time;

/**
 * At what time did we start the hostkey creation process.
 */
static struct GNUNET_TIME_Absolute hostkey_start_time;

/**
 * At what time did we start the peer startup process.
 */
static struct GNUNET_TIME_Absolute peer_start_time;

/**
 * Boolean value, should the driver issue find peer requests
 * (GNUNET_YES) or should it be left to the service (GNUNET_NO)
 */
static unsigned int do_find_peer;

/**
 * Whether or not to insert gauger data.
 */
static unsigned int insert_gauger_data;

/**
 * Boolean value, should replication be done by the dht
 * service (GNUNET_YES) or by the driver (GNUNET_NO)
 */
static unsigned int in_dht_replication;

/**
 * Size of test data to insert/retrieve during testing.
 */
static unsigned long long test_data_size = DEFAULT_TEST_DATA_SIZE;

/**
 * Maximum number of concurrent connections to peers.
 */
static unsigned long long max_outstanding_connections;

/**
 * Maximum number of concurrent ssh instances to peers.
 */
static unsigned long long max_concurrent_ssh;

/**
 * Maximum number of concurrent PUT requests.
 */
static unsigned long long max_outstanding_puts = DEFAULT_MAX_OUTSTANDING_PUTS;

/**
 * Maximum number of concurrent GET requests.
 */
static unsigned long long max_outstanding_gets = DEFAULT_MAX_OUTSTANDING_GETS;

/**
 * Number of nodes issuing malicious GET messages.
 */
static unsigned long long malicious_getters;

/**
 * Maximum number of concurrent find peer messages being sent.
 */
static unsigned long long max_outstanding_find_peers;

/**
 * Number of nodes issuing malicious PUT messages.
 */
static unsigned long long malicious_putters;

/**
 * Time (in seconds) to delay between rounds.
 */
static unsigned long long round_delay;

/**
 * The identifier for this trial (if we have one)
 * for external data collection.
 */
static unsigned long long trial_to_run;

/**
 * How many malicious droppers to seed in the network.
 */
static unsigned long long malicious_droppers;

/**
 * Bloom filter to restrict malicious nodes chosen.
 */
struct GNUNET_CONTAINER_BloomFilter *malicious_bloom;

/**
 * Whether malicious droppers should be chosen based on proximity to a key.
 */
static int malicious_sybil;

/**
 * Target for the malicious sybil nodes (choose the closest to this key).
 */
static GNUNET_HashCode sybil_target;

/**
 * How often to send malicious GET messages.
 */
static struct GNUNET_TIME_Relative malicious_get_frequency;

/**
 * How often to send malicious PUT messages.
 */
static struct GNUNET_TIME_Relative malicious_put_frequency;

/**
 * How long to send find peer requests.
 */
static unsigned long long settle_time;

/**
 * Handle to the dhtlog service.
 */
static struct GNUNET_DHTLOG_Handle *dhtlog_handle;

/**
 * Replication value for GET requests.
 */
static unsigned long long get_replication;

/**
 * Replication value for PUT requests.
 */
static unsigned long long put_replication;

/**
 * If GNUNET_YES, insert data at the same peers every time.
 * Otherwise, choose a new random peer to insert at each time.
 */
static unsigned int replicate_same;

/**
 * If GNUNET_YES, issue GET requests at the same peers every time.
 * Otherwise, choose a new random peer/data combination to search
 * each time.
 */
static unsigned int get_from_same;

/**
 * Should malicious peers be set after allowing for settle time?
 * Default is to set them malicious after initial connection setup.
 */
static unsigned int malicious_after_settle;

/**
 * Number of rounds for testing (PUTS + GETS)
 */
static unsigned long long total_rounds;

/**
 * Target number of connections (will stop sending find peer
 * messages when this number is exceeded)
 */
static unsigned long long target_total_connections;

/**
 * Number of rounds already run
 */
static unsigned int rounds_finished;

/**
 * Number of rounds of churn to read from the file (first line, should be a single number).
 */
static unsigned int churn_rounds;

/**
 * Current round we are in for churn, tells us how many peers to connect/disconnect.
 */
static unsigned int current_churn_round;

/**
 * Number of times to churn per round
 */
static unsigned long long churns_per_round;

/**
 * Array of churn values.
 */
static unsigned int *churn_array;

/**
 * Hash map of stats contexts.
 */
static struct GNUNET_CONTAINER_MultiHashMap *stats_map;

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
 * Global config handle.
 */
static const struct GNUNET_CONFIGURATION_Handle *config;

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
 * If non-zero, end testing if this many GETs
 * complete in a single round.
 */
static unsigned long long target_completions;

/**
 * Total number of items to attempt to get.
 */
static unsigned long long cumulative_num_gets;

/**
 * How many gets are done?
 */
static unsigned long long cumulative_successful_gets;

/**
 * How many gets failed?
 */
static unsigned long long gets_failed;

#ifndef HAVE_MALICIOUS
/**
 * How many malicious control messages do
 * we currently have in flight?
 */
static unsigned long long outstanding_malicious;

/**
 * How many set malicious peers are done?
 */
static unsigned int malicious_completed;
#endif

/**
 * For gauger logging, what specific identifier (svn revision)
 * should be used?
 */
static unsigned long long revision;

/**
 * Global used to count how many connections we have currently
 * been notified about (how many times has topology_callback been called
 * with success?)
 */
static uint64_t total_connections;

/**
 * Previous connections, for counting new connections during some duration.
 */
static uint64_t previous_connections;

/**
 * For counting failed connections during some duration.
 */
static uint64_t previous_failed_connections;

/**
 * Global used to count how many failed connections we have
 * been notified about (how many times has topology_callback
 * been called with failure?)
 */
static uint64_t failed_connections;

/**
 * If GNUNET_YES, only log PUT/GET round data to mysql, otherwise
 * log everything (including each dht service logging).
 */
static unsigned int dhtlog_minimal;

/* Task handle to use to schedule shutdown if something goes wrong */
GNUNET_SCHEDULER_TaskIdentifier die_task;

static char *blacklist_transports;

static enum GNUNET_TESTING_Topology topology;

static enum GNUNET_TESTING_Topology blacklist_topology = GNUNET_TESTING_TOPOLOGY_NONE;  /* Don't do any blacklisting */

static enum GNUNET_TESTING_Topology connect_topology = GNUNET_TESTING_TOPOLOGY_NONE;    /* NONE actually means connect all allowed peers */

static enum GNUNET_TESTING_TopologyOption connect_topology_option =
    GNUNET_TESTING_TOPOLOGY_OPTION_ALL;

static double connect_topology_option_modifier = 0.0;

static struct ProgressMeter *hostkey_meter;

static struct ProgressMeter *peer_start_meter;

static struct ProgressMeter *peer_connect_meter;

static struct ProgressMeter *put_meter;

static struct ProgressMeter *get_meter;

static GNUNET_HashCode *known_keys;

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
create_meter (unsigned int total, char *start_string, int print)
{
  struct ProgressMeter *ret;

  ret = GNUNET_malloc (sizeof (struct ProgressMeter));
  ret->print = print;
  ret->total = total;
  ret->modnum = total / 4;
  ret->dotnum = (total / 50) + 1;
  if (start_string != NULL)
    ret->startup_string = GNUNET_strdup (start_string);
  else
    ret->startup_string = GNUNET_strdup ("");

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
update_meter (struct ProgressMeter *meter)
{
  if (meter->print == GNUNET_YES)
  {
    if (meter->completed % meter->modnum == 0)
    {
      if (meter->completed == 0)
      {
        fprintf (stdout, "%sProgress: [0%%", meter->startup_string);
      }
      else
        fprintf (stdout, "%d%%",
                 (int) (((float) meter->completed / meter->total) * 100));
    }
    else if (meter->completed % meter->dotnum == 0)
      fprintf (stdout, ".");

    if (meter->completed + 1 == meter->total)
      fprintf (stdout, "%d%%]\n", 100);
    fflush (stdout);
  }
  meter->completed++;

  if (meter->completed == meter->total)
    return GNUNET_YES;
  return GNUNET_NO;
}

/**
 * Reset progress meter.
 *
 * @param meter the meter to reset
 *
 * @return GNUNET_YES if meter reset,
 *         GNUNET_SYSERR on error
 */
static int
reset_meter (struct ProgressMeter *meter)
{
  if (meter == NULL)
    return GNUNET_SYSERR;

  meter->completed = 0;
  return GNUNET_YES;
}

/**
 * Release resources for meter
 *
 * @param meter the meter to free
 */
static void
free_meter (struct ProgressMeter *meter)
{
  GNUNET_free_non_null (meter->startup_string);
  GNUNET_free (meter);
}

/**
 * Check whether peers successfully shut down.
 */
static void
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
  if (replicate_same == GNUNET_NO)
    test_put->daemon =
        GNUNET_TESTING_daemon_get (pg,
                                   GNUNET_CRYPTO_random_u32
                                   (GNUNET_CRYPTO_QUALITY_WEAK, num_peers));
}

/**
 * Function scheduled to be run on the successful completion of this
 * testcase.
 */
static void
finish_testing (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Ending test normally!\n",
              (char *) cls);
  GNUNET_assert (pg != NULL);
  struct TestPutContext *test_put = all_puts;
  struct TestGetContext *test_get = all_gets;
  char *temp_get_string;
  char *revision_str;

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

  GNUNET_TESTING_daemons_stop (pg, DEFAULT_TIMEOUT, &shutdown_callback, NULL);

  if (dhtlog_handle != NULL)
  {
    fprintf (stderr, "Update trial endtime\n");
    dhtlog_handle->update_trial (cumulative_successful_gets);
    GNUNET_DHTLOG_disconnect (dhtlog_handle);
    dhtlog_handle = NULL;
  }

  if (hostkey_meter != NULL)
    free_meter (hostkey_meter);
  if (peer_start_meter != NULL)
    free_meter (peer_start_meter);
  if (peer_connect_meter != NULL)
    free_meter (peer_connect_meter);
  if (put_meter != NULL)
    free_meter (put_meter);
  if (get_meter != NULL)
    free_meter (get_meter);

  GNUNET_asprintf (&temp_get_string, "DHT Successful GETs", trial_to_run);
  GNUNET_asprintf (&revision_str, "%llu", revision);
  if (GNUNET_YES == insert_gauger_data)
    GAUGER_ID ("DHT_TESTING", temp_get_string,
               cumulative_successful_gets / (double) cumulative_num_gets,
               "percent successful", revision_str);
  fprintf (stderr,
           "Finished trial, had %llu successful gets out of %llu total, %.2f percent succeeded\n",
           cumulative_successful_gets, cumulative_num_gets,
           cumulative_successful_gets / (double) cumulative_num_gets);
  GNUNET_free (temp_get_string);

  ok = 0;
}

/**
 * Callback for iterating over all the peer connections of a peer group.
 */
static void
log_topology_cb (void *cls, const struct GNUNET_PeerIdentity *first,
                 const struct GNUNET_PeerIdentity *second, const char *emsg)
{
  struct TopologyIteratorContext *topo_ctx = cls;

  if ((first != NULL) && (second != NULL))
  {
    if ((topo_ctx->peers_seen != NULL) &&
        (GNUNET_NO ==
         GNUNET_CONTAINER_multihashmap_contains (topo_ctx->peers_seen,
                                                 &first->hashPubKey)))
    {
      GNUNET_CONTAINER_multihashmap_put (topo_ctx->peers_seen,
                                         &first->hashPubKey, NULL,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
      topo_ctx->total_peers++;
    }
    topo_ctx->total_connections++;
    if ((GNUNET_NO == dhtlog_minimal) && (dhtlog_handle != NULL))
      dhtlog_handle->insert_extended_topology (first, second);
  }
  else
  {
    GNUNET_assert (dhtlog_handle != NULL);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Topology iteration (%u/%u) finished (%u connections, %u peers)\n",
                topo_ctx->current_iteration, topo_ctx->total_iterations,
                topo_ctx->total_connections, topo_ctx->total_peers);
    dhtlog_handle->update_topology (topo_ctx->total_connections);
    if (topo_ctx->cont != NULL)
      GNUNET_SCHEDULER_add_now (topo_ctx->cont, topo_ctx->cls);
    if (topo_ctx->peers_seen != NULL)
      GNUNET_CONTAINER_multihashmap_destroy (topo_ctx->peers_seen);
    GNUNET_free (topo_ctx);
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
static int
stats_iterate (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct StatisticsIteratorContext *stats_ctx;

  if (value == NULL)
    return GNUNET_NO;
  stats_ctx = value;
  dhtlog_handle->insert_stat (stats_ctx->peer, stats_ctx->stat_routes,
                              stats_ctx->stat_route_forwards,
                              stats_ctx->stat_results,
                              stats_ctx->stat_results_to_client,
                              stats_ctx->stat_result_forwards,
                              stats_ctx->stat_gets, stats_ctx->stat_puts,
                              stats_ctx->stat_puts_inserted,
                              stats_ctx->stat_find_peer,
                              stats_ctx->stat_find_peer_start,
                              stats_ctx->stat_get_start,
                              stats_ctx->stat_put_start,
                              stats_ctx->stat_find_peer_reply,
                              stats_ctx->stat_get_reply,
                              stats_ctx->stat_find_peer_answer,
                              stats_ctx->stat_get_response_start);
  GNUNET_free (stats_ctx);
  return GNUNET_YES;
}

static void
stats_finished (void *cls, int result)
{
  fprintf (stderr, "Finished getting all peers statistics, iterating!\n");
  GNUNET_CONTAINER_multihashmap_iterate (stats_map, &stats_iterate, NULL);
  GNUNET_CONTAINER_multihashmap_destroy (stats_map);
  GNUNET_SCHEDULER_add_now (&finish_testing, NULL);
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
static int
stats_handle (void *cls, const struct GNUNET_PeerIdentity *peer,
              const char *subsystem, const char *name, uint64_t value,
              int is_persistent)
{
  struct StatisticsIteratorContext *stats_ctx;

  if (dhtlog_handle != NULL)
    dhtlog_handle->add_generic_stat (peer, name, subsystem, value);
  if (GNUNET_CONTAINER_multihashmap_contains (stats_map, &peer->hashPubKey))
  {
    stats_ctx =
        GNUNET_CONTAINER_multihashmap_get (stats_map, &peer->hashPubKey);
  }
  else
  {
    stats_ctx = GNUNET_malloc (sizeof (struct StatisticsIteratorContext));
    stats_ctx->peer = peer;
    GNUNET_CONTAINER_multihashmap_put (stats_map, &peer->hashPubKey, stats_ctx,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  }
  GNUNET_assert (stats_ctx != NULL);

  if (strcmp (name, STAT_ROUTES) == 0)
    stats_ctx->stat_routes = value;
  else if (strcmp (name, STAT_ROUTE_FORWARDS) == 0)
    stats_ctx->stat_route_forwards = value;
  else if (strcmp (name, STAT_RESULTS) == 0)
    stats_ctx->stat_results = value;
  else if (strcmp (name, STAT_RESULTS_TO_CLIENT) == 0)
    stats_ctx->stat_results_to_client = value;
  else if (strcmp (name, STAT_RESULT_FORWARDS) == 0)
    stats_ctx->stat_result_forwards = value;
  else if (strcmp (name, STAT_GETS) == 0)
    stats_ctx->stat_gets = value;
  else if (strcmp (name, STAT_PUTS) == 0)
    stats_ctx->stat_puts = value;
  else if (strcmp (name, STAT_PUTS_INSERTED) == 0)
    stats_ctx->stat_puts_inserted = value;
  else if (strcmp (name, STAT_FIND_PEER) == 0)
    stats_ctx->stat_find_peer = value;
  else if (strcmp (name, STAT_FIND_PEER_START) == 0)
    stats_ctx->stat_find_peer_start = value;
  else if (strcmp (name, STAT_GET_START) == 0)
    stats_ctx->stat_get_start = value;
  else if (strcmp (name, STAT_PUT_START) == 0)
    stats_ctx->stat_put_start = value;
  else if (strcmp (name, STAT_FIND_PEER_REPLY) == 0)
    stats_ctx->stat_find_peer_reply = value;
  else if (strcmp (name, STAT_GET_REPLY) == 0)
    stats_ctx->stat_get_reply = value;
  else if (strcmp (name, STAT_FIND_PEER_ANSWER) == 0)
    stats_ctx->stat_find_peer_answer = value;
  else if (strcmp (name, STAT_GET_RESPONSE_START) == 0)
    stats_ctx->stat_get_response_start = value;

  return GNUNET_OK;
}

/**
 * Connect to statistics service for each peer and get the appropriate
 * dht statistics for safe keeping.
 */
static void
log_dht_statistics (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  stats_map = GNUNET_CONTAINER_multihashmap_create (num_peers);
  fprintf (stderr, "Starting statistics logging\n");
  GNUNET_TESTING_get_statistics (pg, &stats_finished, &stats_handle, NULL);
}

/**
 * Connect to all peers in the peer group and iterate over their
 * connections.
 */
static void
capture_current_topology (void *cls,
                          const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct TopologyIteratorContext *topo_ctx = cls;

  dhtlog_handle->insert_topology (0);
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Called capture_current_topology\n");
  GNUNET_TESTING_get_topology (pg, &log_topology_cb, topo_ctx);
}

/**
 * Check if the get_handle is being used, if so stop the request.  Either
 * way, schedule the end_badly_cont function which actually shuts down the
 * test.
 */
static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Failing test with error: `%s'!\n",
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

  GNUNET_TESTING_daemons_stop (pg, DEFAULT_TIMEOUT, &shutdown_callback, NULL);

  if (dhtlog_handle != NULL)
  {
    fprintf (stderr, "Update trial endtime\n");
    dhtlog_handle->update_trial (gets_completed);
    GNUNET_DHTLOG_disconnect (dhtlog_handle);
    dhtlog_handle = NULL;
  }

  if (hostkey_meter != NULL)
    free_meter (hostkey_meter);
  if (peer_start_meter != NULL)
    free_meter (peer_start_meter);
  if (peer_connect_meter != NULL)
    free_meter (peer_connect_meter);
  if (put_meter != NULL)
    free_meter (put_meter);
  if (get_meter != NULL)
    free_meter (get_meter);

  ok = 1;
}

/**
 * Forward declaration.
 */
static void
do_put (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

/**
 * Forward declaration.
 */
static void
do_get (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

/**
 * Iterator over hash map entries.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
static int
remove_peer_count (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct PeerCount *peer_count = value;

  GNUNET_CONTAINER_heap_remove_node (peer_count->heap_node);
  GNUNET_free (peer_count);

  return GNUNET_YES;
}

/**
 * Connect to all peers in the peer group and iterate over their
 * connections.
 */
static void
count_new_peers (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct FindPeerContext *find_peer_context = cls;

  find_peer_context->previous_peers = find_peer_context->current_peers;
  find_peer_context->current_peers = 0;
  GNUNET_TESTING_get_topology (pg, find_peer_context->count_peers_cb,
                               find_peer_context);
}

static void
decrement_find_peers (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct TestFindPeer *test_find_peer = cls;

  GNUNET_assert (test_find_peer->find_peer_context->outstanding > 0);
  test_find_peer->find_peer_context->outstanding--;
  test_find_peer->find_peer_context->total--;
  if (0 == test_find_peer->find_peer_context->total)
  {
    GNUNET_SCHEDULER_add_now (&count_new_peers,
                              test_find_peer->find_peer_context);
  }
  GNUNET_free (test_find_peer);
}

/**
 * A find peer request has been sent to the server, now we will schedule a task
 * to wait the appropriate time to allow the request to go out and back.
 *
 * @param cls closure - a TestFindPeer struct
 * @param tc context the task is being called with
 */
static void
handle_find_peer_sent (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct TestFindPeer *test_find_peer = cls;

  GNUNET_DHT_disconnect (test_find_peer->dht_handle);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_divide
                                (find_peer_delay, 2), &decrement_find_peers,
                                test_find_peer);
}

static void
send_find_peer_request (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct TestFindPeer *test_find_peer = cls;

  if (test_find_peer->find_peer_context->outstanding >
      max_outstanding_find_peers)
  {
    GNUNET_SCHEDULER_add_delayed (find_peer_offset, &send_find_peer_request,
                                  test_find_peer);
    return;
  }

  test_find_peer->find_peer_context->outstanding++;
  if (GNUNET_TIME_absolute_get_remaining
      (test_find_peer->find_peer_context->endtime).rel_value == 0)
  {
    GNUNET_SCHEDULER_add_now (&decrement_find_peers, test_find_peer);
    return;
  }

  test_find_peer->dht_handle =
      GNUNET_DHT_connect (test_find_peer->daemon->cfg, 1);
  GNUNET_assert (test_find_peer->dht_handle != NULL);
  GNUNET_DHT_find_peers (test_find_peer->dht_handle, &handle_find_peer_sent,
                         test_find_peer);
}

/**
 * Add a connection to the find_peer_context given.  This may
 * be complete overkill, but allows us to choose the peers with
 * the least connections to initiate find peer requests from.
 */
static void
add_new_connection (struct FindPeerContext *find_peer_context,
                    const struct GNUNET_PeerIdentity *first,
                    const struct GNUNET_PeerIdentity *second)
{
  struct PeerCount *first_count;
  struct PeerCount *second_count;

  if (GNUNET_CONTAINER_multihashmap_contains
      (find_peer_context->peer_hash, &first->hashPubKey))
  {
    first_count =
        GNUNET_CONTAINER_multihashmap_get (find_peer_context->peer_hash,
                                           &first->hashPubKey);
    GNUNET_assert (first_count != NULL);
    first_count->count++;
    GNUNET_CONTAINER_heap_update_cost (find_peer_context->peer_min_heap,
                                       first_count->heap_node,
                                       first_count->count);
  }
  else
  {
    first_count = GNUNET_malloc (sizeof (struct PeerCount));
    first_count->count = 1;
    memcpy (&first_count->peer_id, first, sizeof (struct GNUNET_PeerIdentity));
    first_count->heap_node =
        GNUNET_CONTAINER_heap_insert (find_peer_context->peer_min_heap,
                                      first_count, first_count->count);
    GNUNET_CONTAINER_multihashmap_put (find_peer_context->peer_hash,
                                       &first->hashPubKey, first_count,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  }

  if (GNUNET_CONTAINER_multihashmap_contains
      (find_peer_context->peer_hash, &second->hashPubKey))
  {
    second_count =
        GNUNET_CONTAINER_multihashmap_get (find_peer_context->peer_hash,
                                           &second->hashPubKey);
    GNUNET_assert (second_count != NULL);
    second_count->count++;
    GNUNET_CONTAINER_heap_update_cost (find_peer_context->peer_min_heap,
                                       second_count->heap_node,
                                       second_count->count);
  }
  else
  {
    second_count = GNUNET_malloc (sizeof (struct PeerCount));
    second_count->count = 1;
    memcpy (&second_count->peer_id, second,
            sizeof (struct GNUNET_PeerIdentity));
    second_count->heap_node =
        GNUNET_CONTAINER_heap_insert (find_peer_context->peer_min_heap,
                                      second_count, second_count->count);
    GNUNET_CONTAINER_multihashmap_put (find_peer_context->peer_hash,
                                       &second->hashPubKey, second_count,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  }
}

static void
did_connect (void *cls, 
	     const struct
	     GNUNET_PeerIdentity * first,
	     const struct
	     GNUNET_PeerIdentity * second,
	     uint32_t distance,
	     const struct
	     GNUNET_CONFIGURATION_Handle *
	     first_cfg,
	     const struct
	     GNUNET_CONFIGURATION_Handle *
	     second_cfg,
	     struct GNUNET_TESTING_Daemon *
	     first_daemon,
	     struct GNUNET_TESTING_Daemon *
	     second_daemon,
	     const char *emsg)
{
  struct FindPeerContext *find_peer_context = cls;

  find_peer_context->cc = NULL;
}

/**
 * Iterate over min heap of connections per peer.  For any
 * peer that has 0 connections, attempt to connect them to
 * some random peer.
 *
 * @param cls closure a struct FindPeerContext
 * @param node internal node of the heap
 * @param element value stored, a struct PeerCount
 * @param cost cost associated with the node
 * @return GNUNET_YES if we should continue to iterate,
 *         GNUNET_NO if not.
 */
static int
iterate_min_heap_peers (void *cls, struct GNUNET_CONTAINER_HeapNode *node,
                        void *element, GNUNET_CONTAINER_HeapCostType cost)
{
  struct FindPeerContext *find_peer_context = cls;
  struct PeerCount *peer_count = element;
  struct GNUNET_TESTING_Daemon *d1;
  struct GNUNET_TESTING_Daemon *d2;
  struct GNUNET_TIME_Relative timeout;

  if (cost == 0)
  {
    d1 = GNUNET_TESTING_daemon_get_by_id (pg, &peer_count->peer_id);
    GNUNET_assert (d1 != NULL);
    d2 = d1;
    while ((d2 == d1) || (GNUNET_YES != GNUNET_TESTING_test_daemon_running (d2)))
    {
      d2 = GNUNET_TESTING_daemon_get (pg,
                                      GNUNET_CRYPTO_random_u32
                                      (GNUNET_CRYPTO_QUALITY_WEAK, num_peers));
      GNUNET_assert (d2 != NULL);
    }

      /** Just try to connect the peers, don't worry about callbacks, etc. **/
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Peer %s has 0 connections.  Trying to connect to %s...\n",
                GNUNET_i2s (&peer_count->peer_id), d2->shortname);
    timeout =
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
                                       DEFAULT_CONNECT_TIMEOUT);
    if (GNUNET_TIME_relative_to_absolute (timeout).abs_value >
        find_peer_context->endtime.abs_value)
    {
      timeout = GNUNET_TIME_absolute_get_remaining (find_peer_context->endtime);
    }
    if (NULL != find_peer_context->cc)
      GNUNET_TESTING_daemons_connect_cancel (find_peer_context->cc);
    find_peer_context->cc = GNUNET_TESTING_daemons_connect (d1, d2, timeout, DEFAULT_RECONNECT_ATTEMPTS,
							    GNUNET_YES, 
							    &did_connect, 
							    find_peer_context);
  }
  if (GNUNET_TIME_absolute_get_remaining (find_peer_context->endtime).rel_value
      > 0)
    return GNUNET_YES;
  return GNUNET_NO;
}

/**
 * Forward declaration.
 */
static void
schedule_churn_find_peer_requests (void *cls,
                                   const struct GNUNET_SCHEDULER_TaskContext
                                   *tc);

/**
 * Callback for iterating over all the peer connections of a peer group.
 * Used after we have churned on some peers to find which ones have zero
 * connections so we can make them issue find peer requests.
 */
static void
count_peers_churn_cb (void *cls, const struct GNUNET_PeerIdentity *first,
                      const struct GNUNET_PeerIdentity *second,
                      const char *emsg)
{
  struct FindPeerContext *find_peer_context = cls;
  struct TopologyIteratorContext *topo_ctx;
  struct PeerCount *peer_count;

  if ((first != NULL) && (second != NULL))
  {
    add_new_connection (find_peer_context, first, second);
    find_peer_context->current_peers++;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Peer count finished (%u connections)\n",
                find_peer_context->current_peers);
    peer_count = GNUNET_CONTAINER_heap_peek (find_peer_context->peer_min_heap);
    GNUNET_assert (peer_count != NULL);
    /* WAIT. When peers are churned they will come back with their peers (at least in peerinfo), because the HOSTS file doesn't likely get removed. CRAP. */
    /* NO they won't, because we have disabled peerinfo writing to disk (remember?) so we WILL have to give them new connections */
    /* Best course of action: have DHT automatically try to add peers from peerinfo on startup. This way IF peerinfo writes to file
     * then some peers will end up connected.
     *
     * Also, find any peers that have zero connections here and set up a task to choose at random another peer in the network to
     * connect to.  Of course, if they are blacklisted from that peer they won't be able to connect, so we will have to keep trying
     * until they get a peer.
     */
    /* However, they won't automatically be connected to any of their previous peers... How can we handle that? */
    /* So now we have choices: do we want them to come back with all their connections?  Probably not, but it solves this mess. */

    /* Second problem, which is still a problem, is that a FIND_PEER request won't work when a peer has no connections */

      /**
       * Okay, so here's how this *should* work now.
       *
       * 1. We check the min heap for any peers that have 0 connections.
       *    a. If any are found, we iterate over the heap and just randomly
       *       choose another peer and ask testing to please connect the two.
       *       This takes care of the case that a peer just randomly joins the
       *       network.  However, if there are strict topology restrictions
       *       (imagine a ring) choosing randomly most likely won't help.
       *       We make sure the connection attempt doesn't take longer than
       *       the total timeout, but don't care too much about the result.
       *    b. After that, we still schedule the find peer requests (concurrently
       *       with the connect attempts most likely).  This handles the case
       *       that the DHT iterates over peerinfo and just needs to try to send
       *       a message to get connected.  This should handle the case that the
       *       topology is very strict.
       *
       * 2. If all peers have > 0 connections, we still send find peer requests
       *    as long as possible (until timeout is reached) to help out those
       *    peers that were newly churned and need more connections.  This is because
       *    once all new peers have established a single connection, they won't be
       *    well connected.
       *
       * 3. Once we reach the timeout, we can do no more.  We must schedule the
       *    next iteration of get requests regardless of connections that peers
       *    may or may not have.
       *
       * Caveat: it would be nice to get peers to take data offline with them and
       *         come back with it (or not) based on the testing framework.  The
       *         same goes for remembering previous connections, but putting either
       *         into the general testing churn options seems like overkill because
       *         these are very specialized cases.
       */
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Out of %u peers, fewest connections is %d\n",
                GNUNET_CONTAINER_heap_get_size
                (find_peer_context->peer_min_heap), peer_count->count);
    if ((peer_count->count == 0) &&
        (GNUNET_TIME_absolute_get_remaining
         (find_peer_context->endtime).rel_value > 0))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Found peer with no connections, will choose some peer(s) at random to connect to!\n");
      GNUNET_CONTAINER_heap_iterate (find_peer_context->peer_min_heap,
                                     &iterate_min_heap_peers,
                                     find_peer_context);
      GNUNET_SCHEDULER_add_now (&schedule_churn_find_peer_requests,
                                find_peer_context);
    }
    else if ((GNUNET_TIME_absolute_get_remaining
              (find_peer_context->endtime).rel_value > 0) &&
             (find_peer_context->last_sent != 0))
    {
      GNUNET_SCHEDULER_add_now (&schedule_churn_find_peer_requests,
                                find_peer_context);
    }
    else
    {
      GNUNET_CONTAINER_multihashmap_iterate (find_peer_context->peer_hash,
                                             &remove_peer_count,
                                             find_peer_context);
      GNUNET_CONTAINER_multihashmap_destroy (find_peer_context->peer_hash);
      GNUNET_CONTAINER_heap_destroy (find_peer_context->peer_min_heap);
      if (NULL != find_peer_context->cc)
	GNUNET_TESTING_daemons_connect_cancel (find_peer_context->cc);
      GNUNET_free (find_peer_context);
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Churn round %u of %llu finished, scheduling next GET round.\n",
                  current_churn_round, churn_rounds);
      if (dhtlog_handle != NULL)
      {
        topo_ctx = GNUNET_malloc (sizeof (struct TopologyIteratorContext));
        topo_ctx->cont = &do_get;
        topo_ctx->cls = all_gets;
        topo_ctx->timeout = DEFAULT_GET_TIMEOUT;
        topo_ctx->peers_seen = GNUNET_CONTAINER_multihashmap_create (num_peers);
        die_task =
            GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_add
                                          (GNUNET_TIME_relative_add
                                           (DEFAULT_GET_TIMEOUT,
                                            all_get_timeout),
                                           DEFAULT_TOPOLOGY_CAPTURE_TIMEOUT),
                                          &end_badly,
                                          "from do gets (count_peers_churn_cb)");
        GNUNET_SCHEDULER_add_now (&capture_current_topology, topo_ctx);
      }
      else
      {
        die_task =
            GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_add
                                          (GNUNET_TIME_relative_add
                                           (DEFAULT_GET_TIMEOUT,
                                            all_get_timeout),
                                           DEFAULT_TOPOLOGY_CAPTURE_TIMEOUT),
                                          &end_badly,
                                          "from do gets (count_peers_churn_cb)");
        GNUNET_SCHEDULER_add_now (&do_get, all_gets);
      }
    }
  }
}

/**
 * Set up a single find peer request for each peer in the topology.  Do this
 * until the settle time is over, limited by the number of outstanding requests
 * and the time allowed for each one!
 */
static void
schedule_churn_find_peer_requests (void *cls,
                                   const struct GNUNET_SCHEDULER_TaskContext
                                   *tc)
{
  struct FindPeerContext *find_peer_ctx = cls;
  struct TestFindPeer *test_find_peer;
  struct PeerCount *peer_count;
  uint32_t i;

  if (find_peer_ctx->previous_peers == 0)       /* First time, go slowly */
    find_peer_ctx->total = 1;
  else if (find_peer_ctx->current_peers - find_peer_ctx->previous_peers <
           MIN_FIND_PEER_CUTOFF)
    find_peer_ctx->total = find_peer_ctx->total / 2;
  else if (find_peer_ctx->current_peers - find_peer_ctx->previous_peers > MAX_FIND_PEER_CUTOFF) /* Found LOTS of peers, still go slowly */
    find_peer_ctx->total =
        find_peer_ctx->last_sent - (find_peer_ctx->last_sent / 4);
  else
    find_peer_ctx->total = find_peer_ctx->last_sent * 4;

  if (find_peer_ctx->total > max_outstanding_find_peers)
    find_peer_ctx->total = max_outstanding_find_peers;

  find_peer_ctx->last_sent = find_peer_ctx->total;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Sending %u find peer messages (after churn)\n",
              find_peer_ctx->total);

  if (find_peer_ctx->total > 0)
    find_peer_offset =
        GNUNET_TIME_relative_divide (find_peer_delay, find_peer_ctx->total);
  else
  {
    find_peer_ctx->previous_peers = find_peer_ctx->current_peers;
    find_peer_ctx->current_peers = 0;
    GNUNET_TESTING_get_topology (pg, &count_peers_churn_cb, find_peer_ctx);
  }

  for (i = 0; i < find_peer_ctx->total; i++)
  {
    test_find_peer = GNUNET_malloc (sizeof (struct TestFindPeer));
    /* If we have sent requests, choose peers with a low number of connections to send requests from */
    peer_count =
        GNUNET_CONTAINER_heap_remove_root (find_peer_ctx->peer_min_heap);
    GNUNET_assert (peer_count != NULL);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Sending find peer request from peer with %u connections\n",
                peer_count->count);
    GNUNET_CONTAINER_multihashmap_remove (find_peer_ctx->peer_hash,
                                          &peer_count->peer_id.hashPubKey,
                                          peer_count);
    test_find_peer->daemon =
        GNUNET_TESTING_daemon_get_by_id (pg, &peer_count->peer_id);
    GNUNET_assert (test_find_peer->daemon != NULL);
    test_find_peer->find_peer_context = find_peer_ctx;
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (find_peer_offset, i),
                                  &send_find_peer_request, test_find_peer);
  }

  if ((find_peer_ctx->peer_hash == NULL) &&
      (find_peer_ctx->peer_min_heap == NULL))
  {
    find_peer_ctx->peer_hash = GNUNET_CONTAINER_multihashmap_create (num_peers);
    find_peer_ctx->peer_min_heap =
        GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  }
  else
  {
    GNUNET_CONTAINER_multihashmap_iterate (find_peer_ctx->peer_hash,
                                           &remove_peer_count, find_peer_ctx);
    GNUNET_CONTAINER_multihashmap_destroy (find_peer_ctx->peer_hash);
    find_peer_ctx->peer_hash = GNUNET_CONTAINER_multihashmap_create (num_peers);
  }

  GNUNET_assert (0 ==
                 GNUNET_CONTAINER_multihashmap_size (find_peer_ctx->peer_hash));
  GNUNET_assert (0 ==
                 GNUNET_CONTAINER_heap_get_size (find_peer_ctx->peer_min_heap));
}

static void
schedule_churn_get_topology (void *cls,
                             const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct FindPeerContext *find_peer_context = cls;

  GNUNET_TESTING_get_topology (pg, &count_peers_churn_cb, find_peer_context);
}

/**
 * Called when churning of the topology has finished.
 *
 * @param cls closure unused
 * @param emsg NULL on success, or a printable error on failure
 */
static void
churn_complete (void *cls, const char *emsg)
{
  struct FindPeerContext *find_peer_context = cls;
  struct PeerCount *peer_count;
  unsigned int i;
  struct GNUNET_TESTING_Daemon *temp_daemon;
  struct TopologyIteratorContext *topo_ctx;
  struct GNUNET_TIME_Relative calc_timeout;
  int count_added;

  if (emsg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Ending test, churning of peers failed with error `%s'", emsg);
    GNUNET_SCHEDULER_add_now (&end_badly, (void *) emsg);
    return;
  }

  /**
   * If we switched any peers on, we have to somehow force connect the new peer to
   * SOME bootstrap peer in the network.  First schedule a task to find all peers
   * with no connections, then choose a random peer for each and connect them.
   */
  if (find_peer_context != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "We have churned on some peers, so we must schedule find peer requests for them!\n");
    count_added = 0;
    for (i = 0; i < num_peers; i++)
    {
      temp_daemon = GNUNET_TESTING_daemon_get (pg, i);
      if (GNUNET_YES == GNUNET_TESTING_test_daemon_running (temp_daemon))
      {
        peer_count = GNUNET_malloc (sizeof (struct PeerCount));
        memcpy (&peer_count->peer_id, &temp_daemon->id,
                sizeof (struct GNUNET_PeerIdentity));
        GNUNET_assert (peer_count->count == 0);
        peer_count->heap_node =
            GNUNET_CONTAINER_heap_insert (find_peer_context->peer_min_heap,
                                          peer_count, peer_count->count);
        GNUNET_CONTAINER_multihashmap_put (find_peer_context->peer_hash,
                                           &temp_daemon->id.hashPubKey,
                                           peer_count,
                                           GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
        count_added++;
      }
    }
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Added %d peers to heap, total size %d\n", count_added,
                GNUNET_CONTAINER_heap_get_size
                (find_peer_context->peer_min_heap));
    GNUNET_SCHEDULER_add_delayed (DEFAULT_PEER_DISCONNECT_TIMEOUT,
                                  &schedule_churn_get_topology,
                                  find_peer_context);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Only churned off peers, no find peer requests, scheduling more gets (after allowing time for peers to disconnect properly!)...\n");
    if (dhtlog_handle != NULL)
    {
      topo_ctx = GNUNET_malloc (sizeof (struct TopologyIteratorContext));
      topo_ctx->cont = &do_get;
      topo_ctx->cls = all_gets;
      topo_ctx->timeout = DEFAULT_GET_TIMEOUT;
      topo_ctx->peers_seen = GNUNET_CONTAINER_multihashmap_create (num_peers);
      calc_timeout =
          GNUNET_TIME_relative_add (DEFAULT_GET_TIMEOUT, all_get_timeout);
      calc_timeout =
          GNUNET_TIME_relative_add (calc_timeout,
                                    DEFAULT_TOPOLOGY_CAPTURE_TIMEOUT);
      calc_timeout =
          GNUNET_TIME_relative_add (calc_timeout,
                                    DEFAULT_PEER_DISCONNECT_TIMEOUT);
      die_task =
          GNUNET_SCHEDULER_add_delayed (calc_timeout, &end_badly,
                                        "from do gets (churn_complete)");
      GNUNET_SCHEDULER_add_delayed (DEFAULT_PEER_DISCONNECT_TIMEOUT,
                                    &capture_current_topology, topo_ctx);
      dhtlog_handle->insert_round (DHT_ROUND_GET, rounds_finished);
    }
    else
    {
      calc_timeout =
          GNUNET_TIME_relative_add (DEFAULT_GET_TIMEOUT, all_get_timeout);
      calc_timeout =
          GNUNET_TIME_relative_add (calc_timeout,
                                    DEFAULT_PEER_DISCONNECT_TIMEOUT);
      die_task =
          GNUNET_SCHEDULER_add_delayed (calc_timeout, &end_badly,
                                        "from do gets (churn_complete)");
      GNUNET_SCHEDULER_add_delayed (DEFAULT_PEER_DISCONNECT_TIMEOUT, &do_get,
                                    all_gets);
    }
  }
}

/**
 * Decide how many peers to turn on or off in this round, make sure the
 * numbers actually make sense, then do so.  This function sets in motion
 * churn, find peer requests for newly joined peers, and issuing get
 * requests once the new peers have done so.
 *
 * @param cls closure (unused)
 * @param tc task context (unused)
 */
static void
churn_peers (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  unsigned int count_running;
  unsigned int churn_up;
  unsigned int churn_down;
  struct GNUNET_TIME_Relative timeout;
  struct FindPeerContext *find_peer_context;

  churn_up = churn_down = 0;
  count_running = GNUNET_TESTING_daemons_running (pg);
  if (count_running > churn_array[current_churn_round])
    churn_down = count_running - churn_array[current_churn_round];
  else if (count_running < churn_array[current_churn_round])
    churn_up = churn_array[current_churn_round] - count_running;
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Not churning any peers, topology unchanged.\n");

  if (churn_up > num_peers - count_running)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Churn file specified %u peers (up); only have %u!",
                churn_array[current_churn_round], num_peers);
    churn_up = num_peers - count_running;
  }
  else if (churn_down > count_running)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Churn file specified %u peers (down); only have %u!",
                churn_array[current_churn_round], count_running);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "This will leave NO peers running (mistake in churn configuration?)!");
    churn_down = count_running;
  }
  //timeout = GNUNET_TIME_relative_multiply(seconds_per_peer_start, churn_up > 0 ? churn_up : churn_down);
  //timeout = GNUNET_TIME_relative_multiply (seconds_per_peer_start, churn_up > 0 ? churn_up : churn_down);
  timeout = GNUNET_TIME_relative_multiply (DEFAULT_TIMEOUT, 2); /* FIXME: Lack of intelligent choice here */
  find_peer_context = NULL;
  if (churn_up > 0)             /* Only need to do find peer requests if we turned new peers on */
  {
    find_peer_context = GNUNET_malloc (sizeof (struct FindPeerContext));
    find_peer_context->count_peers_cb = &count_peers_churn_cb;
    find_peer_context->previous_peers = 0;
    find_peer_context->current_peers = 0;
    find_peer_context->endtime = GNUNET_TIME_relative_to_absolute (timeout);
    find_peer_context->peer_hash =
        GNUNET_CONTAINER_multihashmap_create (num_peers);
    find_peer_context->peer_min_heap =
        GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "churn_peers: want %u total, %u running, starting %u, stopping %u\n",
              churn_array[current_churn_round], count_running, churn_up,
              churn_down);
  GNUNET_TESTING_daemons_churn (pg, NULL, churn_down, churn_up, timeout,
                                &churn_complete, find_peer_context);
  current_churn_round++;
}

/**
 * Task to release DHT handle associated with GET request.
 */
static void
get_stop_finished (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct TestGetContext *test_get = cls;
  struct TopologyIteratorContext *topo_ctx;

  /* The dht_handle may be null if this get was scheduled from a down peer */
  if (test_get->dht_handle != NULL)
  {
    GNUNET_DHT_disconnect (test_get->dht_handle);
    outstanding_gets--;         /* GET is really finished */
    test_get->dht_handle = NULL;
  }

  /* Reset the uid (which item to search for) and the daemon (which peer to search from) for later get request iterations */
  if (get_from_same == GNUNET_NO)
  {
    test_get->uid =
        GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, num_puts);
    test_get->daemon =
        GNUNET_TESTING_daemon_get (pg,
                                   GNUNET_CRYPTO_random_u32
                                   (GNUNET_CRYPTO_QUALITY_WEAK, num_peers));
  }

#if VERBOSE > 1
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%d gets succeeded, %d gets failed!\n",
              gets_completed, gets_failed);
#endif
  update_meter (get_meter);
  if ((gets_completed + gets_failed == num_gets) && (outstanding_gets == 0))
  {
    fprintf (stderr,
             "Canceling die task (get_stop_finished) %llu gets completed, %llu gets failed\n",
             gets_completed, gets_failed);
    if ((GNUNET_YES == dhtlog_minimal) && (NULL != dhtlog_handle))
      dhtlog_handle->insert_round_details (DHT_ROUND_GET, rounds_finished,
                                           num_gets, gets_completed);
    GNUNET_SCHEDULER_cancel (die_task);
    reset_meter (put_meter);
    reset_meter (get_meter);
    if ((target_completions > 0) && (gets_completed > target_completions))
      fprintf (stderr, "Ending test early due to GET success!\n");
      /**
       *  Handle all cases:
       *    1) Testing is completely finished, call the topology iteration dealy and die
       *    2) Testing is not finished, churn the network and do gets again (current_churn_round < churn_rounds)
       *    3) Testing is not finished, reschedule all the PUTS *and* GETS again (num_rounds > 1)
       */
    if ((rounds_finished == total_rounds - 1) || ((target_completions > 0) && (gets_completed > target_completions)))   /* Everything is finished, end testing */
    {
      if ((dhtlog_handle != NULL) && (GNUNET_NO == dhtlog_minimal))
      {
        topo_ctx = GNUNET_malloc (sizeof (struct TopologyIteratorContext));
        topo_ctx->cont = &log_dht_statistics;
        topo_ctx->peers_seen = GNUNET_CONTAINER_multihashmap_create (num_peers);
        GNUNET_SCHEDULER_add_now (&capture_current_topology, topo_ctx);
      }
      else
        GNUNET_SCHEDULER_add_now (&finish_testing, NULL);
    }
    else if (current_churn_round < churns_per_round * (rounds_finished + 1))    /* Do next round of churn */
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Current churn round %u, real round %u, scheduling next round of churn.\n",
                  current_churn_round, rounds_finished + 1);
      gets_completed = 0;
      gets_failed = 0;

      if (dhtlog_handle != NULL)
        dhtlog_handle->insert_round (DHT_ROUND_CHURN, rounds_finished);

      GNUNET_SCHEDULER_add_now (&churn_peers, NULL);
    }
    else if (rounds_finished < total_rounds - 1)        /* Start a new complete round */
    {
      rounds_finished++;
      gets_completed = 0;
      gets_failed = 0;
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Round %u of %llu finished, scheduling next round.\n",
                  rounds_finished, total_rounds);

          /** We reset the peer daemon for puts and gets on each disconnect, so all we need to do is start another round! */
      if (GNUNET_YES == in_dht_replication)     /* Replication done in DHT, don't redo puts! */
      {
        if (dhtlog_handle != NULL)
          dhtlog_handle->insert_round (DHT_ROUND_GET, rounds_finished);

        die_task =
            GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_add
                                          (GNUNET_TIME_relative_add
                                           (GNUNET_TIME_relative_multiply
                                            (GNUNET_TIME_UNIT_SECONDS,
                                             round_delay), all_get_timeout),
                                           DEFAULT_TOPOLOGY_CAPTURE_TIMEOUT),
                                          &end_badly,
                                          "from do gets (next round)");
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                      (GNUNET_TIME_UNIT_SECONDS, round_delay),
                                      &do_get, all_gets);
      }
      else
      {
        if (dhtlog_handle != NULL)
          dhtlog_handle->insert_round (DHT_ROUND_NORMAL, rounds_finished);
        die_task =
            GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_add
                                          (GNUNET_TIME_relative_multiply
                                           (GNUNET_TIME_UNIT_SECONDS,
                                            round_delay),
                                           GNUNET_TIME_relative_multiply
                                           (GNUNET_TIME_UNIT_SECONDS,
                                            num_puts * 2)), &end_badly,
                                          "from do puts");
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                      (GNUNET_TIME_UNIT_SECONDS, round_delay),
                                      &do_put, all_puts);
      }
    }
  }
}

/**
 * Task to release get handle.
 */
static void
get_stop_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct TestGetContext *test_get = cls;

  if ((tc->reason & GNUNET_SCHEDULER_REASON_TIMEOUT) != 0)
    gets_failed++;
  else
    cumulative_successful_gets++;

  GNUNET_assert (test_get->get_handle != NULL);
  GNUNET_DHT_get_stop (test_get->get_handle);
  test_get->get_handle = NULL;
  test_get->disconnect_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_SCHEDULER_add_now (&get_stop_finished, test_get);
}

/**
 * Iterator called if the GET request initiated returns a response.
 *
 * @param cls closure
 * @param exp when will this value expire
 * @param key key of the result
 * @param get_path NULL-terminated array of pointers
 *                 to the peers on reverse GET path (or NULL if not recorded)
 * @param put_path NULL-terminated array of pointers
 *                 to the peers on the PUT path (or NULL if not recorded)
 * @param type type of the result
 * @param size number of bytes in data
 * @param data pointer to the result data
 */
static void
get_result_iterator (void *cls, struct GNUNET_TIME_Absolute exp,
                     const GNUNET_HashCode * key,
                     const struct GNUNET_PeerIdentity *const *get_path,
                     const struct GNUNET_PeerIdentity *const *put_path,
                     enum GNUNET_BLOCK_Type type, size_t size, const void *data)
{
  struct TestGetContext *test_get = cls;

  if (test_get->succeeded == GNUNET_YES)
    return;                     /* Get has already been successful, probably ending now */

  if (0 != memcmp (&known_keys[test_get->uid], key, sizeof (GNUNET_HashCode)))  /* || (0 != memcmp(original_data, data, sizeof(original_data)))) */
  {
    gets_completed++;
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Key or data is not the same as was inserted!\n");
  }
  else
  {
    gets_completed++;
    test_get->succeeded = GNUNET_YES;
  }
#if VERBOSE > 1
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received correct GET response!\n");
#endif
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

  if (num_gets == 0)
  {
    GNUNET_SCHEDULER_cancel (die_task);
    GNUNET_SCHEDULER_add_now (&finish_testing, NULL);
  }

  if (test_get == NULL)
    return;                     /* End of the list */

  /* Set this here in case we are re-running gets */
  test_get->succeeded = GNUNET_NO;

  if (GNUNET_YES != GNUNET_TESTING_test_daemon_running (test_get->daemon))   /* If the peer has been churned off, don't try issuing request from it! */
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Peer we should issue get request from is down, skipping.\n");
    gets_failed++;
    GNUNET_SCHEDULER_add_now (&get_stop_finished, test_get);
    GNUNET_SCHEDULER_add_now (&do_get, test_get->next);
    return;
  }

  /* Check if more gets are outstanding than should be */
  if (outstanding_gets > max_outstanding_gets)
  {
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_MILLISECONDS, 200), &do_get,
                                  test_get);
    return;
  }

  /* Connect to the first peer's DHT */
  test_get->dht_handle = GNUNET_DHT_connect (test_get->daemon->cfg, 10);
  GNUNET_assert (test_get->dht_handle != NULL);
  outstanding_gets++;

  cumulative_num_gets++;
  /* Insert the data at the first peer */
  test_get->get_handle =
      GNUNET_DHT_get_start (test_get->dht_handle, get_delay,
                            GNUNET_BLOCK_TYPE_TEST, &known_keys[test_get->uid],
                            get_replication, GNUNET_DHT_RO_NONE, NULL, 0, NULL,
                            0, &get_result_iterator, test_get);

#if VERBOSE > 1
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting get for uid %u from peer %s\n",
              test_get->uid, test_get->daemon->shortname);
#endif
  test_get->disconnect_task =
      GNUNET_SCHEDULER_add_delayed (get_timeout, &get_stop_task, test_get);

  /* Schedule the next request in the linked list of get requests */
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
  struct TopologyIteratorContext *topo_ctx;

  outstanding_puts--;
  puts_completed++;

  if ((tc->reason & GNUNET_SCHEDULER_REASON_TIMEOUT) != 0)
    fprintf (stderr, "PUT Request failed!\n");

  /* Reset the daemon (which peer to insert at) for later put request iterations */
  if (replicate_same == GNUNET_NO)
    test_put->daemon =
        GNUNET_TESTING_daemon_get (pg,
                                   GNUNET_CRYPTO_random_u32
                                   (GNUNET_CRYPTO_QUALITY_WEAK, num_peers));

  GNUNET_SCHEDULER_cancel (test_put->disconnect_task);
  test_put->disconnect_task =
      GNUNET_SCHEDULER_add_now (&put_disconnect_task, test_put);
  if (GNUNET_YES == update_meter (put_meter))
  {
    GNUNET_assert (outstanding_puts == 0);
    GNUNET_SCHEDULER_cancel (die_task);
    if ((dhtlog_handle != NULL) && (GNUNET_NO == dhtlog_minimal))
    {
      topo_ctx = GNUNET_malloc (sizeof (struct TopologyIteratorContext));
      topo_ctx->cont = &do_get;
      topo_ctx->cls = all_gets;
      topo_ctx->timeout = DEFAULT_GET_TIMEOUT;
      topo_ctx->peers_seen = GNUNET_CONTAINER_multihashmap_create (num_peers);
      die_task =
          GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_add
                                        (GNUNET_TIME_relative_add
                                         (DEFAULT_GET_TIMEOUT, all_get_timeout),
                                         DEFAULT_TOPOLOGY_CAPTURE_TIMEOUT),
                                        &end_badly,
                                        "from do gets (put finished)");
      GNUNET_SCHEDULER_add_now (&capture_current_topology, topo_ctx);
    }
    else
    {
      fprintf (stderr, "Scheduling die task (put finished)\n");
      die_task =
          GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_add
                                        (DEFAULT_GET_TIMEOUT, all_get_timeout),
                                        &end_badly,
                                        "from do gets (put finished)");
      GNUNET_SCHEDULER_add_delayed (DEFAULT_GET_TIMEOUT, &do_get, all_gets);
    }
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
  char data[test_data_size];    /* Made up data to store */
  uint32_t rand;
  int i;

  if (test_put == NULL)
    return;                     /* End of list */

  if (GNUNET_YES != GNUNET_TESTING_test_daemon_running (test_put->daemon))   /* If the peer has been churned off, don't try issuing request from it! */
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Peer we should issue put request at is down, skipping.\n");
    update_meter (put_meter);
    GNUNET_SCHEDULER_add_now (&do_put, test_put->next);
    return;
  }

  for (i = 0; i < sizeof (data); i++)
  {
    memset (&data[i],
            GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, UINT32_MAX),
            1);
  }

  if (outstanding_puts > max_outstanding_puts)
  {
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_MILLISECONDS, 200), &do_put,
                                  test_put);
    return;
  }

#if VERBOSE > 1
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting put for uid %u from peer %s\n",
              test_put->uid, test_put->daemon->shortname);
#endif
  test_put->dht_handle = GNUNET_DHT_connect (test_put->daemon->cfg, 10);

  GNUNET_assert (test_put->dht_handle != NULL);
  outstanding_puts++;
  GNUNET_DHT_put (test_put->dht_handle, &known_keys[test_put->uid],
                  put_replication, GNUNET_DHT_RO_NONE, GNUNET_BLOCK_TYPE_TEST,
                  sizeof (data), data, GNUNET_TIME_UNIT_FOREVER_ABS, put_delay,
                  &put_finished, test_put);
  test_put->disconnect_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_get_forever (),
                                    &put_disconnect_task, test_put);
  rand = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 2);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                (GNUNET_TIME_UNIT_SECONDS, rand), &do_put,
                                test_put->next);
}

static void
schedule_find_peer_requests (void *cls,
                             const struct GNUNET_SCHEDULER_TaskContext *tc);

#if HAVE_MALICIOUS
static void
setup_malicious_peers (void *cls,
                       const struct GNUNET_SCHEDULER_TaskContext *tc);
#endif

/**
 * Given a number of total peers and a bucket size, estimate the number of
 * connections in a perfect kademlia topology.
 */
static unsigned int
connection_estimate (unsigned int peer_count, unsigned int bucket_size)
{
  unsigned int i;
  unsigned int filled;

  i = num_peers;

  filled = 0;
  while (i >= bucket_size)
  {
    filled++;
    i = i / 2;
  }
  filled++;                     /* Add one filled bucket to account for one "half full" and some miscellaneous */
  return filled * bucket_size * peer_count;

}

/**
 * Callback for iterating over all the peer connections of a peer group.
 */
static void
count_peers_cb (void *cls, const struct GNUNET_PeerIdentity *first,
                const struct GNUNET_PeerIdentity *second, const char *emsg)
{
  struct FindPeerContext *find_peer_context = cls;

  if ((first != NULL) && (second != NULL))
  {
    add_new_connection (find_peer_context, first, second);
    find_peer_context->current_peers++;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Peer count finished (%u connections), %u new peers, connection estimate %u (target %u)\n",
                find_peer_context->current_peers,
                find_peer_context->current_peers -
                find_peer_context->previous_peers,
                connection_estimate (num_peers, DEFAULT_BUCKET_SIZE),
                target_total_connections);

    if ((find_peer_context->last_sent < 8) ||
        ((find_peer_context->current_peers <
          2 * connection_estimate (num_peers, DEFAULT_BUCKET_SIZE)) &&
         (GNUNET_TIME_absolute_get_remaining
          (find_peer_context->endtime).rel_value > 0) &&
         (find_peer_context->current_peers < target_total_connections)))
    {
      GNUNET_SCHEDULER_add_now (&schedule_find_peer_requests,
                                find_peer_context);
    }
    else
    {
      GNUNET_CONTAINER_multihashmap_iterate (find_peer_context->peer_hash,
                                             &remove_peer_count,
                                             find_peer_context);
      GNUNET_CONTAINER_multihashmap_destroy (find_peer_context->peer_hash);
      GNUNET_CONTAINER_heap_destroy (find_peer_context->peer_min_heap);
      if (NULL != find_peer_context->cc)
	GNUNET_TESTING_daemons_connect_cancel (find_peer_context->cc);
      GNUNET_free (find_peer_context);
      fprintf (stderr, "Not sending any more find peer requests.\n");

#if HAVE_MALICIOUS
      if (GNUNET_YES == malicious_after_settle)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    "calling setup_malicious_peers\n");
        GNUNET_SCHEDULER_add_now (&setup_malicious_peers, NULL);
      }
#endif
    }
  }
}

/**
 * Set up a single find peer request for each peer in the topology.  Do this
 * until the settle time is over, limited by the number of outstanding requests
 * and the time allowed for each one!
 */
static void
schedule_find_peer_requests (void *cls,
                             const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct FindPeerContext *find_peer_ctx = cls;
  struct TestFindPeer *test_find_peer;
  struct PeerCount *peer_count;
  uint32_t i;
  uint32_t random;

  if (find_peer_ctx->previous_peers == 0)       /* First time, go slowly */
    find_peer_ctx->total = 1;
  else if (find_peer_ctx->current_peers - find_peer_ctx->previous_peers > MAX_FIND_PEER_CUTOFF) /* Found LOTS of peers, still go slowly */
    find_peer_ctx->total =
        find_peer_ctx->last_sent - (find_peer_ctx->last_sent / 8);
  else
    find_peer_ctx->total = find_peer_ctx->last_sent * 2;

  if (find_peer_ctx->total > max_outstanding_find_peers)
    find_peer_ctx->total = max_outstanding_find_peers;

  if (find_peer_ctx->total > num_peers) /* Don't try to send more messages than we have peers! */
    find_peer_ctx->total = num_peers;

  find_peer_ctx->last_sent = find_peer_ctx->total;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Sending %u find peer messages (goal at least %u connections)\n",
              find_peer_ctx->total, target_total_connections);

  find_peer_offset =
      GNUNET_TIME_relative_divide (find_peer_delay, find_peer_ctx->total);
  for (i = 0; i < find_peer_ctx->total; i++)
  {
    test_find_peer = GNUNET_malloc (sizeof (struct TestFindPeer));
    /* If we haven't sent any requests yet, choose random peers */
    /* Also choose random in _half_ of all cases, so we don't
     * get stuck choosing topologically restricted peers with
     * few connections that will never be able to find any new
     * peers! */
    if ((find_peer_ctx->previous_peers == 0) || (i % 2 == 0))
    {
          /**
           * Attempt to spread find peer requests across even sections of the peer address
           * space.  Choose basically 1 peer in every num_peers / max_outstanding_requests
           * each time, then offset it by a randomish value.
           *
           * For instance, if num_peers is 100 and max_outstanding is 10, first chosen peer
           * will be between 0 - 10, second between 10 - 20, etc.
           */
      random = (num_peers / find_peer_ctx->total) * i;
      random =
          random + GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                             (num_peers /
                                              find_peer_ctx->total));
      if (random >= num_peers)
      {
        random = random - num_peers;
      }
#if REAL_RANDOM
      random = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, num_peers);
#endif
      test_find_peer->daemon = GNUNET_TESTING_daemon_get (pg, random);
    }
    else                        /* If we have sent requests, choose peers with a low number of connections to send requests from */
    {
      peer_count =
          GNUNET_CONTAINER_heap_remove_root (find_peer_ctx->peer_min_heap);
      GNUNET_assert (GNUNET_YES ==
                     GNUNET_CONTAINER_multihashmap_remove
                     (find_peer_ctx->peer_hash, &peer_count->peer_id.hashPubKey,
                      peer_count));
      test_find_peer->daemon =
          GNUNET_TESTING_daemon_get_by_id (pg, &peer_count->peer_id);
      GNUNET_assert (test_find_peer->daemon != NULL);
    }

    test_find_peer->find_peer_context = find_peer_ctx;
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (find_peer_offset, i),
                                  &send_find_peer_request, test_find_peer);
  }

  if ((find_peer_ctx->peer_hash == NULL) &&
      (find_peer_ctx->peer_min_heap == NULL))
  {
    find_peer_ctx->peer_hash = GNUNET_CONTAINER_multihashmap_create (num_peers);
    find_peer_ctx->peer_min_heap =
        GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  }
  else
  {
    GNUNET_CONTAINER_multihashmap_iterate (find_peer_ctx->peer_hash,
                                           &remove_peer_count, find_peer_ctx);
    GNUNET_CONTAINER_multihashmap_destroy (find_peer_ctx->peer_hash);
    find_peer_ctx->peer_hash = GNUNET_CONTAINER_multihashmap_create (num_peers);
  }

  GNUNET_assert (0 ==
                 GNUNET_CONTAINER_multihashmap_size (find_peer_ctx->peer_hash));
  GNUNET_assert (0 ==
                 GNUNET_CONTAINER_heap_get_size (find_peer_ctx->peer_min_heap));

}

/**
 * Convert unique ID to hash code.
 *
 * @param uid unique ID to convert
 * @param hash set to uid (extended with zeros)
 */
static void
hash_from_uid (uint32_t uid, GNUNET_HashCode * hash)
{
  memset (hash, 0, sizeof (GNUNET_HashCode));
  *((uint32_t *) hash) = uid;
}

/**
 * Set up all of the put and get operations we want to do
 * in the current round.  Allocate data structure for each,
 * add to list, then schedule the actual PUT operations.
 */
static void
setup_puts_and_gets (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int i;
  struct TestPutContext *test_put;
  struct TestGetContext *test_get;
  uint32_t temp_peer;
  GNUNET_HashCode uid_hash;
  int count;

#if REMEMBER
  int remember[num_puts][num_peers];

  memset (&remember, 0, sizeof (int) * num_puts * num_peers);
#endif
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "in setup_puts_and_gets\n");
  known_keys = GNUNET_malloc (sizeof (GNUNET_HashCode) * num_puts);
  for (i = 0; i < num_puts; i++)
  {
    test_put = GNUNET_malloc (sizeof (struct TestPutContext));
    test_put->uid = i;
    GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_WEAK,
                                      &known_keys[i]);
    /* Set first X bits to match the chosen sybil location if we want to do the sybil attack! */
    if (GNUNET_YES == malicious_sybil)
    {
      memcpy (&known_keys[i], &sybil_target, sizeof (GNUNET_HashCode) / 2);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Distance between sybil location and key is %d\n",
                  GNUNET_CRYPTO_hash_matching_bits (&known_keys[i],
                                                    &sybil_target));
    }
    temp_peer =
        GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, num_peers);
    test_put->daemon = GNUNET_TESTING_daemon_get (pg, temp_peer);
    /* Don't start PUTs at malicious peers! */
    if (malicious_bloom != NULL)
    {
      count = 0;
      hash_from_uid (temp_peer, &uid_hash);
      while ((GNUNET_YES ==
              GNUNET_CONTAINER_bloomfilter_test (malicious_bloom, &uid_hash)) &&
             (count < num_peers))
      {
        temp_peer =
            GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, num_peers);
        hash_from_uid (temp_peer, &uid_hash);
        test_put->daemon = GNUNET_TESTING_daemon_get (pg, temp_peer);
        count++;
      }
      if (count == num_peers)
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    "Couldn't find peer not in malicious bloom to select!\n");
    }

    test_put->next = all_puts;
    all_puts = test_put;
  }

  for (i = 0; i < num_gets; i++)
  {
    test_get = GNUNET_malloc (sizeof (struct TestGetContext));
    test_get->uid =
        GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, num_puts);
#if REMEMBER
    while (remember[test_get->uid][temp_daemon] == 1)
      temp_daemon =
          GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, num_peers);
    remember[test_get->uid][temp_daemon] = 1;
#endif
    temp_peer =
        GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, num_peers);
    test_get->daemon = GNUNET_TESTING_daemon_get (pg, temp_peer);
    /* Don't start GETs at malicious peers! */
    if (malicious_bloom != NULL)
    {
      hash_from_uid (temp_peer, &uid_hash);
      count = 0;
      while ((GNUNET_YES ==
              GNUNET_CONTAINER_bloomfilter_test (malicious_bloom, &uid_hash)) &&
             (count < num_peers))
      {
        temp_peer =
            GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, num_peers);
        hash_from_uid (temp_peer, &uid_hash);
        test_get->daemon = GNUNET_TESTING_daemon_get (pg, temp_peer);
        count++;
      }
      if (count == num_peers)
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    "Couldn't find peer not in malicious bloom to select!\n");
    }
    test_get->next = all_gets;
    all_gets = test_get;
  }

  /*GNUNET_SCHEDULER_cancel (die_task); */
  die_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_SECONDS, num_puts * 2),
                                    &end_badly, "from do puts");
  GNUNET_SCHEDULER_add_now (&do_put, all_puts);

}

/**
 * Set up some all of the put and get operations we want
 * to do.  Allocate data structure for each, add to list,
 * then call actual insert functions.
 */
static void
continue_puts_and_gets (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  int i;
  int max;
  struct TopologyIteratorContext *topo_ctx;
  struct FindPeerContext *find_peer_context;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "In continue_puts_and_gets\n");
  if ((dhtlog_handle != NULL) && (GNUNET_NO == dhtlog_minimal))
  {
    if (settle_time >= 180 * 2)
      max = (settle_time / 180) - 2;
    else
      max = 1;
    for (i = 1; i < max; i++)
    {
      topo_ctx = GNUNET_malloc (sizeof (struct TopologyIteratorContext));
      topo_ctx->current_iteration = i;
      topo_ctx->total_iterations = max;
      topo_ctx->peers_seen = GNUNET_CONTAINER_multihashmap_create (num_peers);
      //fprintf(stderr, "scheduled topology iteration in %d minutes\n", i);
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_MINUTES, i * 3),
                                    &capture_current_topology, topo_ctx);
    }
    topo_ctx = GNUNET_malloc (sizeof (struct TopologyIteratorContext));
    topo_ctx->cont = &setup_puts_and_gets;
    topo_ctx->peers_seen = GNUNET_CONTAINER_multihashmap_create (num_peers);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "setting setup_puts_and_gets for %d seconds in the future\n",
                settle_time + 10);
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_SECONDS,
                                   (settle_time + 10)),
                                  &capture_current_topology, topo_ctx);
  }
  else
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_SECONDS,
                                   (settle_time + 10)), &setup_puts_and_gets,
                                  NULL);

  if (dhtlog_handle != NULL)
    dhtlog_handle->insert_round (DHT_ROUND_NORMAL, rounds_finished);

#if HAVE_MALICIOUS
  if ((GNUNET_YES != malicious_after_settle) || (settle_time == 0))
  {
    GNUNET_SCHEDULER_add_now (&setup_malicious_peers, NULL);
  }
#endif

  if ((GNUNET_YES == do_find_peer) && (settle_time > 0))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Scheduling find peer requests during \"settle\" time.\n");
    find_peer_context = GNUNET_malloc (sizeof (struct FindPeerContext));
    find_peer_context->count_peers_cb = &count_peers_cb;
    find_peer_context->endtime =
        GNUNET_TIME_relative_to_absolute (GNUNET_TIME_relative_multiply
                                          (GNUNET_TIME_UNIT_SECONDS,
                                           settle_time));
    GNUNET_SCHEDULER_add_now (&schedule_find_peer_requests, find_peer_context);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Assuming automatic DHT find peer requests.\n");
  }
}

#if HAVE_MALICIOUS
/**
 * Task to release DHT handles
 */
static void
malicious_disconnect_task (void *cls,
                           const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MaliciousContext *ctx = cls;

  outstanding_malicious--;
  malicious_completed++;
  ctx->disconnect_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_DHT_disconnect (ctx->dht_handle);
  ctx->dht_handle = NULL;
  GNUNET_free (ctx);

  if (malicious_completed ==
      malicious_getters + malicious_putters + malicious_droppers)
  {
    fprintf (stderr, "Finished setting all malicious peers up!\n");
  }
}

/**
 * Task to release DHT handles
 */
static void
malicious_done_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MaliciousContext *ctx = cls;

  GNUNET_SCHEDULER_cancel (ctx->disconnect_task);
  GNUNET_SCHEDULER_add_now (&malicious_disconnect_task, ctx);
}

/**
 * Set up some data, and call API PUT function
 */
static void
set_malicious (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MaliciousContext *ctx = cls;

  if (outstanding_malicious > DEFAULT_MAX_OUTSTANDING_GETS)
  {
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_MILLISECONDS, 100),
                                  &set_malicious, ctx);
    return;
  }

  if (ctx->dht_handle == NULL)
  {
    ctx->dht_handle = GNUNET_DHT_connect (ctx->daemon->cfg, 1);
    outstanding_malicious++;
  }

  GNUNET_assert (ctx->dht_handle != NULL);

#if VERBOSE > 1
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Setting peer %s malicious type %d\n",
              ctx->daemon->shortname, ctx->malicious_type);
#endif

  switch (ctx->malicious_type)
  {
  case GNUNET_MESSAGE_TYPE_DHT_MALICIOUS_GET:
    GNUNET_DHT_set_malicious_getter (ctx->dht_handle, malicious_get_frequency,
                                     &malicious_done_task, ctx);
    break;
  case GNUNET_MESSAGE_TYPE_DHT_MALICIOUS_PUT:
    GNUNET_DHT_set_malicious_putter (ctx->dht_handle, malicious_put_frequency,
                                     &malicious_done_task, ctx);
    break;
  case GNUNET_MESSAGE_TYPE_DHT_MALICIOUS_DROP:
    GNUNET_DHT_set_malicious_dropper (ctx->dht_handle, &malicious_done_task,
                                      ctx);
    break;
  default:
    break;
  }

  ctx->disconnect_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                    &malicious_disconnect_task, ctx);
}

/**
 * Choose the next peer from the peer group to set as malicious.
 * If we are doing a sybil attack, find the nearest peer to the
 * sybil location that has not already been set malicious.  Otherwise
 * just choose a random not already chosen peer.
 *
 * @param pg the peer group
 * @param bloom the bloomfilter which contains all peer already
 *        chosen to be malicious
 */
static uint32_t
choose_next_malicious (struct GNUNET_TESTING_PeerGroup *pg,
                       struct GNUNET_CONTAINER_BloomFilter *bloom)
{
  int i;
  int nearest;
  int bits_match;
  int curr_distance;
  int count;
  struct GNUNET_TESTING_Daemon *temp_daemon;
  GNUNET_HashCode uid_hash;

  curr_distance = 0;
  nearest = 0;
  GNUNET_assert (bloom != NULL);

  if (GNUNET_YES == malicious_sybil)
  {
    for (i = 0; i < num_peers; i++)
    {
      temp_daemon = GNUNET_TESTING_daemon_get (pg, i);
      hash_from_uid (i, &uid_hash);
      /* Check if this peer matches the bloomfilter */
      if ((GNUNET_NO == GNUNET_TESTING_test_daemon_running (temp_daemon)) ||
          (GNUNET_YES == GNUNET_CONTAINER_bloomfilter_test (bloom, &uid_hash)))
        continue;

      bits_match =
          GNUNET_CRYPTO_hash_matching_bits (&temp_daemon->id.hashPubKey,
                                            &sybil_target);
      if (bits_match >= curr_distance)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Found nearer peer %s to %s, old matching bits %d, new %d\n",
                    GNUNET_i2s (&temp_daemon->id), GNUNET_h2s (&sybil_target),
                    curr_distance, bits_match);
        nearest = i;
        curr_distance = bits_match;
      }
    }
  }
  else
  {
    nearest = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, num_peers);
    hash_from_uid (nearest, &uid_hash);
    count = 0;
    while ((GNUNET_YES == GNUNET_CONTAINER_bloomfilter_test (bloom, &uid_hash))
           && (count < num_peers))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Peer %d already in bloom (tried %d times)\n", nearest,
                  count);
      nearest =
          GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, num_peers);
      hash_from_uid (nearest, &uid_hash);
      count++;
    }
    if (count == num_peers)
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Tried %d times to find a peer, selecting %d at random!!\n",
                  count, nearest);
  }

  return nearest;
}

/**
 * Select randomly from set of known peers,
 * set the desired number of peers to the
 * proper malicious types.
 */
static void
setup_malicious_peers (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MaliciousContext *ctx;
  int i;
  uint32_t temp_daemon;
  GNUNET_HashCode uid_hash;

  for (i = 0; i < malicious_getters; i++)
  {
    ctx = GNUNET_malloc (sizeof (struct MaliciousContext));
    temp_daemon = choose_next_malicious (pg, malicious_bloom);
    ctx->daemon = GNUNET_TESTING_daemon_get (pg, temp_daemon);
    hash_from_uid (temp_daemon, &uid_hash);
    GNUNET_CONTAINER_bloomfilter_add (malicious_bloom, &uid_hash);
    ctx->malicious_type = GNUNET_MESSAGE_TYPE_DHT_MALICIOUS_GET;
    GNUNET_SCHEDULER_add_now (&set_malicious, ctx);

  }

  for (i = 0; i < malicious_putters; i++)
  {
    ctx = GNUNET_malloc (sizeof (struct MaliciousContext));
    temp_daemon = choose_next_malicious (pg, malicious_bloom);
    ctx->daemon = GNUNET_TESTING_daemon_get (pg, temp_daemon);
    hash_from_uid (temp_daemon, &uid_hash);
    GNUNET_CONTAINER_bloomfilter_add (malicious_bloom, &uid_hash);
    ctx->malicious_type = GNUNET_MESSAGE_TYPE_DHT_MALICIOUS_PUT;
    GNUNET_SCHEDULER_add_now (&set_malicious, ctx);

  }

  for (i = 0; i < malicious_droppers; i++)
  {
    ctx = GNUNET_malloc (sizeof (struct MaliciousContext));
    temp_daemon = choose_next_malicious (pg, malicious_bloom);
    ctx->daemon = GNUNET_TESTING_daemon_get (pg, temp_daemon);
    hash_from_uid (temp_daemon, &uid_hash);
    GNUNET_CONTAINER_bloomfilter_add (malicious_bloom, &uid_hash);
    ctx->malicious_type = GNUNET_MESSAGE_TYPE_DHT_MALICIOUS_DROP;
    GNUNET_SCHEDULER_add_now (&set_malicious, ctx);
  }
}
#endif

/**
 * This function is called whenever a connection attempt is finished between two of
 * the started peers (started with GNUNET_TESTING_daemons_start).  The total
 * number of times this function is called should equal the number returned
 * from the GNUNET_TESTING_connect_topology call.
 *
 * The emsg variable is NULL on success (peers connected), and non-NULL on
 * failure (peers failed to connect).
 */
static void
topology_callback (void *cls, const struct GNUNET_PeerIdentity *first,
                   const struct GNUNET_PeerIdentity *second, uint32_t distance,
                   const struct GNUNET_CONFIGURATION_Handle *first_cfg,
                   const struct GNUNET_CONFIGURATION_Handle *second_cfg,
                   struct GNUNET_TESTING_Daemon *first_daemon,
                   struct GNUNET_TESTING_Daemon *second_daemon,
                   const char *emsg)
{
  struct TopologyIteratorContext *topo_ctx;
  uint64_t duration;
  uint64_t total_duration;
  uint64_t new_connections;
  uint64_t new_failed_connections;
  double conns_per_sec_recent;
  double conns_per_sec_total;
  double failed_conns_per_sec_recent;
  double failed_conns_per_sec_total;
  char *temp_conn_string;
  char *temp_conn_failed_string;
  char *revision_str;

  if (GNUNET_TIME_absolute_get_difference
      (connect_last_time,
       GNUNET_TIME_absolute_get ()).rel_value >
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
                                     CONN_UPDATE_DURATION).rel_value)
  {
    /* Get number of new connections */
    new_connections = total_connections - previous_connections;

    /* Get number of new FAILED connections */
    new_failed_connections = failed_connections - previous_failed_connections;

    /* Get duration in seconds */
    duration =
        GNUNET_TIME_absolute_get_difference (connect_last_time,
                                             GNUNET_TIME_absolute_get
                                             ()).rel_value / 1000;
    total_duration =
        GNUNET_TIME_absolute_get_difference (connect_start_time,
                                             GNUNET_TIME_absolute_get
                                             ()).rel_value / 1000;

    failed_conns_per_sec_recent =
        (double) new_failed_connections / (double) duration;
    failed_conns_per_sec_total =
        (double) failed_connections / (double) total_duration;
    conns_per_sec_recent = (double) new_connections / (double) duration;
    conns_per_sec_total = (double) total_connections / (double) total_duration;
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Recent: %.2f/s, Total: %.2f/s, Recent failed: %.2f/s, total failed %.2f/s\n",
                conns_per_sec_recent, conns_per_sec_total,
                failed_conns_per_sec_recent, failed_conns_per_sec_total);
    connect_last_time = GNUNET_TIME_absolute_get ();
    previous_connections = total_connections;
    previous_failed_connections = failed_connections;
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "have %llu total_connections, %llu failed\n", total_connections,
                failed_connections);
  }

  if (emsg == NULL)
  {
    total_connections++;
#if VERBOSE > 1
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "connected peer %s to peer %s, distance %u\n",
                first_daemon->shortname, second_daemon->shortname, distance);
#endif
  }
  else
  {
    failed_connections++;
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Failed to connect peer %s to peer %s with error :\n%s\n",
                first_daemon->shortname, second_daemon->shortname, emsg);

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Failed to connect peer %s to peer %s with error :\n%s\n",
                first_daemon->shortname, second_daemon->shortname, emsg);
#endif
  }

  GNUNET_assert (peer_connect_meter != NULL);
  if (GNUNET_YES == update_meter (peer_connect_meter))
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Created %d total connections, which is our target number!  Starting next phase of testing.\n",
                total_connections);
#endif
    if (failed_connections > 0)
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "While connecting, had %u failed connections.\n",
                  failed_connections);
    if (dhtlog_handle != NULL)
    {
      dhtlog_handle->update_connections (total_connections);
      dhtlog_handle->insert_topology (expected_connections);
    }

    total_duration =
        GNUNET_TIME_absolute_get_difference (connect_start_time,
                                             GNUNET_TIME_absolute_get
                                             ()).rel_value / 1000;
    failed_conns_per_sec_total =
        (long double) failed_connections / total_duration;
    conns_per_sec_total = (long double) total_connections / total_duration;
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Overall connection info --- Total: %u, Total Failed %u/s\n",
                total_connections, failed_connections);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Overall connection info --- Total: %.2f/s, Total Failed %.2f/s\n",
                conns_per_sec_total, failed_conns_per_sec_total);

    GNUNET_asprintf (&temp_conn_string, "DHT Profiler Connection/s",
                     trial_to_run);
    GNUNET_asprintf (&temp_conn_failed_string,
                     "DHT Profiler Connection/s failed", trial_to_run);
    GNUNET_asprintf (&revision_str, "%llu", revision);

    if (GNUNET_YES == insert_gauger_data)
      GAUGER_ID ("DHT_TESTING", temp_conn_string,
                 (long double) conns_per_sec_total, "conns/s", revision_str);
    if (GNUNET_YES == insert_gauger_data)
      GAUGER_ID ("DHT_TESTING", temp_conn_failed_string,
                 (long double) failed_conns_per_sec_total, "failed_conns",
                 revision_str);

    GNUNET_free (temp_conn_string);
    GNUNET_free (temp_conn_failed_string);
    GNUNET_asprintf (&temp_conn_string, "DHT Profiler Total Connections",
                     trial_to_run);
    GNUNET_asprintf (&temp_conn_failed_string,
                     "DHT Profiler Total Connections failed", trial_to_run);
    if (GNUNET_YES == insert_gauger_data)
      GAUGER_ID ("DHT_TESTING", temp_conn_string, (double) total_connections,
                 "conns", revision_str);
    if (GNUNET_YES == insert_gauger_data)
      GAUGER_ID ("DHT_TESTING", temp_conn_failed_string,
                 (double) failed_connections, "failed conns", revision_str);
    GNUNET_free (temp_conn_string);
    GNUNET_free (temp_conn_failed_string);
    GNUNET_free (revision_str);

    GNUNET_SCHEDULER_cancel (die_task);

    if ((GNUNET_YES == dhtlog_minimal) && (NULL != dhtlog_handle))
    {
      topo_ctx = GNUNET_malloc (sizeof (struct TopologyIteratorContext));
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Setting continue gets and puts as topo_cont\n");
      topo_ctx->cont = &continue_puts_and_gets;
      topo_ctx->peers_seen = GNUNET_CONTAINER_multihashmap_create (num_peers);
      GNUNET_SCHEDULER_add_now (&capture_current_topology, topo_ctx);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "For some reason, NOT scheduling final topology capture (settle_time %d, dhtlog_handle %s)!\n",
                  settle_time, dhtlog_handle);
      GNUNET_SCHEDULER_add_now (&continue_puts_and_gets, NULL);
    }
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
peers_started_callback (void *cls, const struct GNUNET_PeerIdentity *id,
                        const struct GNUNET_CONFIGURATION_Handle *cfg,
                        struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  char *revision_str;

  if (emsg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Failed to start daemon with error: `%s'\n", emsg);
    return;
  }
  GNUNET_assert (id != NULL);

#if VERBOSE > 1
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Started daemon %llu out of %llu\n",
              (num_peers - peers_left) + 1, num_peers);
#endif

  peers_left--;

  if (GNUNET_YES == update_meter (peer_start_meter))
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "All %d daemons started, now connecting peers!\n", num_peers);
#endif
    GNUNET_SCHEDULER_cancel (die_task);

    GNUNET_asprintf (&revision_str, "%llu", revision);
    if (GNUNET_YES == insert_gauger_data)
      GAUGER_ID ("DHT_TESTING", "peer_startup_time",
                 GNUNET_TIME_absolute_get_duration (peer_start_time).rel_value /
                 (double) num_peers, "ms/peer", revision_str);
    GNUNET_free (revision_str);

    expected_connections = UINT_MAX;
    if ((pg != NULL) && (peers_left == 0))
    {
      connect_start_time = GNUNET_TIME_absolute_get ();
      expected_connections =
          GNUNET_TESTING_connect_topology (pg, connect_topology,
                                           connect_topology_option,
                                           connect_topology_option_modifier,
                                           connect_timeout, connect_attempts,
                                           NULL, NULL);

      peer_connect_meter =
          create_meter (expected_connections, "Peer connection ", GNUNET_YES);
      fprintf (stderr, "Have %d expected connections\n", expected_connections);
    }

    if (expected_connections == 0)
    {
      die_task =
          GNUNET_SCHEDULER_add_now (&end_badly,
                                    "from connect topology (bad return)");
    }

    die_task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                      (GNUNET_TIME_UNIT_SECONDS,
                                       DEFAULT_CONNECT_TIMEOUT *
                                       expected_connections), &end_badly,
                                      "from connect topology (timeout)");

    ok = 0;
  }
}

static void
create_topology ()
{
  unsigned int create_expected_connections;

  peers_left = num_peers;       /* Reset counter */
  create_expected_connections =
      GNUNET_TESTING_create_topology (pg, topology, blacklist_topology,
                                      blacklist_transports);
  if (create_expected_connections > 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Topology set up, have %u expected connections, now starting peers!\n",
                create_expected_connections);
    GNUNET_TESTING_daemons_continue_startup (pg);
    peer_start_time = GNUNET_TIME_absolute_get ();
  }
  else
  {
    GNUNET_SCHEDULER_cancel (die_task);
    die_task =
        GNUNET_SCHEDULER_add_now (&end_badly,
                                  "from create topology (bad return)");
  }
  GNUNET_free_non_null (blacklist_transports);
  GNUNET_SCHEDULER_cancel (die_task);
  die_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (seconds_per_peer_start, num_peers),
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
static void
hostkey_callback (void *cls, const struct GNUNET_PeerIdentity *id,
                  struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  char *revision_str;

  if (emsg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Hostkey callback received error: %s\n", emsg);
  }

#if VERBOSE > 1
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Hostkey (%d/%d) created for peer `%s'\n", num_peers - peers_left,
              num_peers, GNUNET_i2s (id));
#endif

  peers_left--;
  if (GNUNET_YES == update_meter (hostkey_meter))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "All %d hostkeys created, now creating topology!\n", num_peers);

    GNUNET_asprintf (&revision_str, "%llu", revision);
    if (GNUNET_YES == insert_gauger_data)
    {
      if (GNUNET_YES ==
          GNUNET_CONFIGURATION_have_value (config, "TESTING", "HOSTKEYSFILE"))
      {
        GAUGER_ID ("DHT_TESTING", "HOSTKEY_GENERATION",
                   GNUNET_TIME_absolute_get_duration
                   (hostkey_start_time).rel_value / (double) num_peers,
                   "ms/hostkey", revision_str);
      }
      else
      {
        GAUGER_ID ("DHT_TESTING", "HOSTKEY_GENERATION_REAL",
                   GNUNET_TIME_absolute_get_duration
                   (hostkey_start_time).rel_value / (double) num_peers,
                   "ms/hostkey", revision_str);
      }
    }

    GNUNET_free (revision_str);

    GNUNET_SCHEDULER_cancel (die_task);
    /* Set up task in case topology creation doesn't finish
     * within a reasonable amount of time */
    die_task =
        GNUNET_SCHEDULER_add_delayed (DEFAULT_TOPOLOGY_TIMEOUT, &end_badly,
                                      "from create_topology");
    GNUNET_SCHEDULER_add_now (&create_topology, NULL);
    ok = 0;
  }
}

static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct stat frstat;
  struct GNUNET_DHTLOG_TrialInfo trial_info;
  struct GNUNET_TESTING_Host *hosts;
  struct GNUNET_TESTING_Host *temphost;
  struct GNUNET_TESTING_Host *tempnext;
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
  char *churn_data;
  char *churn_filename;
  int count;
  int ret;
  int line_number;
  int k;

  config = cfg;
  rounds_finished = 0;
  memset (&trial_info, 0, sizeof (struct GNUNET_DHTLOG_TrialInfo));
  /* Get path from configuration file */
  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "paths", "servicehome",
                                             &test_directory))
  {
    ok = 404;
    return;
  }

  /* Get number of peers to start from configuration */
  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "testing", "num_peers",
                                             &num_peers))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Number of peers must be specified in section %s option %s\n",
                "TESTING", "NUM_PEERS");
  }
  GNUNET_assert (num_peers > 0 && num_peers < ULONG_MAX);

  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "testing", "connect_timeout",
                                             &temp_config_number))
    connect_timeout =
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
                                       temp_config_number);
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Must provide option %s:%s!\n",
                "testing", "connect_timeout");
    return;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "testing", "connect_attempts",
                                             &connect_attempts))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Must provide option %s:%s!\n",
                "testing", "connect_attempts");
    return;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "testing",
                                             "max_outstanding_connections",
                                             &max_outstanding_connections))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Must provide option %s:%s!\n",
                "testing", "max_outstanding_connections");
    return;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "testing",
                                             "max_concurrent_ssh",
                                             &max_concurrent_ssh))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Must provide option %s:%s!\n",
                "testing", "max_concurrent_ssh");
    return;
  }

  /**
   * Get DHT specific testing options.
   */
  if ((GNUNET_YES ==
       GNUNET_CONFIGURATION_get_value_yesno (cfg, "dht_testing",
                                             "mysql_logging")) ||
      (GNUNET_YES ==
       GNUNET_CONFIGURATION_get_value_yesno (cfg, "dht_testing",
                                             "mysql_logging_extended")) ||
      (GNUNET_YES ==
       GNUNET_CONFIGURATION_get_value_yesno (cfg, "dht_testing",
                                             "mysql_logging_minimal")))
  {
    if (GNUNET_YES ==
        GNUNET_CONFIGURATION_get_value_yesno (cfg, "dht_testing",
                                              "mysql_logging_minimal"))
      dhtlog_minimal = GNUNET_YES;

    dhtlog_handle = GNUNET_DHTLOG_connect (cfg);
    if (dhtlog_handle == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Could not connect to mysql server for logging, will NOT log dht operations!");
      ok = 3306;
      return;
    }
  }

  stop_closest =
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "dht", "stop_on_closest");
  if (stop_closest == GNUNET_SYSERR)
    stop_closest = GNUNET_NO;

  stop_found = GNUNET_CONFIGURATION_get_value_yesno (cfg, "dht", "stop_found");
  if (stop_found == GNUNET_SYSERR)
    stop_found = GNUNET_NO;

  strict_kademlia =
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "dht", "strict_kademlia");
  if (strict_kademlia == GNUNET_SYSERR)
    strict_kademlia = GNUNET_NO;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "dht_testing", "comment",
                                             &trialmessage))
    trialmessage = NULL;

  churn_data = NULL;
  /** Check for a churn file to do churny simulation */
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "dht_testing", "churn_file",
                                             &churn_filename))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Reading churn data from %s\n",
                churn_filename);
    if (GNUNET_OK != GNUNET_DISK_file_test (churn_filename))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Error reading churn file!\n");
      GNUNET_free_non_null (trialmessage);
      GNUNET_free (churn_filename);
      return;
    }
    if ((0 != STAT (churn_filename, &frstat)) || (frstat.st_size == 0))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Could not open file specified for churn data, ending test!");
      ok = 1119;
      GNUNET_free_non_null (trialmessage);
      GNUNET_free (churn_filename);
      return;
    }

    churn_data = GNUNET_malloc_large (frstat.st_size);
    GNUNET_assert (churn_data != NULL);
    if (frstat.st_size !=
        GNUNET_DISK_fn_read (churn_filename, churn_data, frstat.st_size))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Could not read file %s specified for churn, ending test!",
                  churn_filename);
      GNUNET_free (churn_filename);
      GNUNET_free (churn_data);
      GNUNET_free_non_null (trialmessage);
      return;
    }

    GNUNET_free_non_null (churn_filename);

    buf = churn_data;
    count = 0;
    /* Read the first line */
    while (count < frstat.st_size)
    {
      count++;
      if (((churn_data[count] == '\n')) && (buf != &churn_data[count]))
      {
        churn_data[count] = '\0';
        if (1 != sscanf (buf, "%u", &churn_rounds))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                      "Failed to read number of rounds from churn file, ending test!\n");
          ret = 4200;
          GNUNET_free_non_null (trialmessage);
          GNUNET_free_non_null (churn_data);
          return;
        }
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    "Read %u rounds from churn file\n", churn_rounds);
        buf = &churn_data[count + 1];
        churn_array = GNUNET_malloc (sizeof (unsigned int) * churn_rounds);
        break;                  /* Done with this part */
      }
    }

    if (GNUNET_OK !=
        GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing",
                                               "churns_per_round",
                                               &churns_per_round))
    {
      churns_per_round = (unsigned long long) churn_rounds;
    }

    line_number = 0;
    while ((count < frstat.st_size) && (line_number < churn_rounds))
    {
      count++;
      if (((churn_data[count] == '\n')) && (buf != &churn_data[count]))
      {
        churn_data[count] = '\0';

        ret = sscanf (buf, "%u", &churn_array[line_number]);
        if (1 == ret)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Read %u peers in round %u\n",
                      churn_array[line_number], line_number);
          line_number++;
        }
        else
        {
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                      "Error reading line `%s' in hostfile\n", buf);
          buf = &churn_data[count + 1];
          continue;
        }
        buf = &churn_data[count + 1];
      }
      else if (churn_data[count] == '\n')       /* Blank line */
        buf = &churn_data[count + 1];
    }
  }
  GNUNET_free_non_null (churn_data);

  /* Check for a hostfile containing user@host:port triples */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "testing", "hostfile",
                                             &hostfile))
    hostfile = NULL;

  hosts = NULL;
  temphost = NULL;
  data = NULL;
  if (hostfile != NULL)
  {
    if (GNUNET_OK != GNUNET_DISK_file_test (hostfile))
      GNUNET_DISK_fn_write (hostfile, NULL, 0,
                            GNUNET_DISK_PERM_USER_READ |
                            GNUNET_DISK_PERM_USER_WRITE);
    if ((0 != STAT (hostfile, &frstat)) || (frstat.st_size == 0))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Could not open file specified for host list, ending test!");
      ok = 1119;
      GNUNET_free_non_null (trialmessage);
      GNUNET_free (hostfile);
      return;
    }

    data = GNUNET_malloc_large (frstat.st_size);
    GNUNET_assert (data != NULL);
    if (frstat.st_size != GNUNET_DISK_fn_read (hostfile, data, frstat.st_size))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Could not read file %s specified for host list, ending test!",
                  hostfile);
      GNUNET_free (hostfile);
      GNUNET_free (data);
      GNUNET_free_non_null (trialmessage);
      return;
    }

    GNUNET_free_non_null (hostfile);

    buf = data;
    count = 0;
    while (count < frstat.st_size - 1)
    {
      count++;
      if (((data[count] == '\n')) && (buf != &data[count]))
      {
        data[count] = '\0';
        temphost = GNUNET_malloc (sizeof (struct GNUNET_TESTING_Host));
        ret =
            sscanf (buf, "%a[a-zA-Z0-9_]@%a[a-zA-Z0-9.]:%hd",
                    &temphost->username, &temphost->hostname, &temphost->port);
        if (3 == ret)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Successfully read host %s, port %d and user %s from file\n",
                      temphost->hostname, temphost->port, temphost->username);
        }
        else
        {
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                      "Error reading line `%s' in hostfile\n", buf);
          GNUNET_free (temphost);
          buf = &data[count + 1];
          continue;
        }
        temphost->next = hosts;
        hosts = temphost;
        buf = &data[count + 1];
      }
      else if ((data[count] == '\n') || (data[count] == '\0'))
        buf = &data[count + 1];
    }
  }
  GNUNET_free_non_null (data);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing",
                                             "malicious_getters",
                                             &malicious_getters))
    malicious_getters = 0;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing",
                                             "malicious_putters",
                                             &malicious_putters))
    malicious_putters = 0;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing",
                                             "malicious_droppers",
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
      GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing",
                                             "put_replication",
                                             &put_replication))
    put_replication = DEFAULT_PUT_REPLICATION;

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing", "num_gets",
                                             &num_gets))
    num_gets = num_peers;

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing",
                                             "get_replication",
                                             &get_replication))
    get_replication = DEFAULT_GET_REPLICATION;

  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing",
                                             "find_peer_delay",
                                             &temp_config_number))
    find_peer_delay =
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
                                       temp_config_number);
  else
    find_peer_delay = DEFAULT_FIND_PEER_DELAY;

  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing",
                                             "concurrent_find_peers",
                                             &temp_config_number))
    max_outstanding_find_peers = temp_config_number;
  else
    max_outstanding_find_peers = DEFAULT_MAX_OUTSTANDING_FIND_PEERS;

  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing", "get_timeout",
                                             &temp_config_number))
    get_timeout =
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
                                       temp_config_number);
  else
    get_timeout = DEFAULT_GET_TIMEOUT;

  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing",
                                             "concurrent_puts",
                                             &temp_config_number))
    max_outstanding_puts = temp_config_number;
  else
    max_outstanding_puts = DEFAULT_MAX_OUTSTANDING_PUTS;

  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing",
                                             "concurrent_gets",
                                             &temp_config_number))
    max_outstanding_gets = temp_config_number;
  else
    max_outstanding_gets = DEFAULT_MAX_OUTSTANDING_GETS;

  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing", "timeout",
                                             &temp_config_number))
    all_get_timeout =
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
                                       temp_config_number);
  else
    all_get_timeout.rel_value = get_timeout.rel_value * num_gets;

  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing", "get_delay",
                                             &temp_config_number))
    get_delay =
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
                                       temp_config_number);
  else
    get_delay = DEFAULT_GET_DELAY;

  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing", "put_delay",
                                             &temp_config_number))
    put_delay =
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
                                       temp_config_number);
  else
    put_delay = DEFAULT_PUT_DELAY;

  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing",
                                             "peer_start_timeout",
                                             &temp_config_number))
    seconds_per_peer_start =
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
                                       temp_config_number);
  else
    seconds_per_peer_start = DEFAULT_SECONDS_PER_PEER_START;

  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing", "data_size",
                                             &temp_config_number))
    test_data_size = temp_config_number;
  else
    test_data_size = DEFAULT_TEST_DATA_SIZE;

  /**
   * Get DHT testing related options.
   */
  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "DHT_TESTING",
                                            "REPLICATE_SAME"))
    replicate_same = GNUNET_YES;

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing",
                                             "target_completions",
                                             &target_completions))
    target_completions = 0;     /* Not required, on stack */

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "DHT_TESTING",
                                            "GET_FROM_SAME"))
    get_from_same = GNUNET_YES;

  if (GNUNET_NO ==
      GNUNET_CONFIGURATION_get_value_time (cfg, "DHT_TESTING",
                                           "MALICIOUS_GET_FREQUENCY",
                                           &malicious_get_frequency))
    malicious_get_frequency = DEFAULT_MALICIOUS_GET_FREQUENCY;

  if (GNUNET_NO ==
      GNUNET_CONFIGURATION_get_value_time (cfg, "DHT_TESTING",
                                           "MALICIOUS_PUT_FREQUENCY",
                                           &malicious_put_frequency))
    malicious_put_frequency = DEFAULT_MALICIOUS_PUT_FREQUENCY;

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "DHT_TESTING",
                                            "MALICIOUS_AFTER_SETTLE"))
    malicious_after_settle = GNUNET_YES;

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "DHT_TESTING",
                                            "MALICIOUS_SYBIL"))
  {
    /* Set up the malicious target at random for this round */
    GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_WEAK,
                                      &sybil_target);
    malicious_sybil = GNUNET_YES;
  }

  /* Create the bloomfilter for choosing which peers to set malicious */

  /* Bloomfilter size must be 2^k for some integer k */
  k = 1;
  while (1 << k < malicious_droppers)
    k++;
  if (malicious_droppers > 0)
    malicious_bloom =
        GNUNET_CONTAINER_bloomfilter_init (NULL, 1 << k, DHT_BLOOM_K);

  /* The normal behavior of the DHT is to do find peer requests
   * on its own.  Only if this is explicitly turned off should
   * the testing driver issue find peer requests (even though
   * this is likely the default when testing).
   */
  if (GNUNET_NO ==
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "dht", "do_find_peer"))
    do_find_peer = GNUNET_YES;

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "dht_testing",
                                            "insert_gauger_data"))
    insert_gauger_data = GNUNET_YES;

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "dht", "republish"))
    in_dht_replication = GNUNET_YES;

  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "DHT_TESTING", "TRIAL_TO_RUN",
                                             &trial_to_run))
    trial_to_run = 0;

  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "DHT_TESTING", "REVISION",
                                             &revision))
    revision = 0;

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "DHT_TESTING",
                                             "FIND_PEER_DELAY",
                                             &temp_config_number))
    find_peer_delay =
        GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
                                       temp_config_number);
  else
    find_peer_delay = DEFAULT_FIND_PEER_DELAY;

  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "DHT_TESTING", "ROUND_DELAY",
                                             &round_delay))
    round_delay = 0;

  if (GNUNET_NO ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "DHT_TESTING",
                                             "OUTSTANDING_FIND_PEERS",
                                             &max_outstanding_find_peers))
    max_outstanding_find_peers = DEFAULT_MAX_OUTSTANDING_FIND_PEERS;

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "dht", "strict_kademlia"))
    max_outstanding_find_peers = max_outstanding_find_peers * 1;

  find_peer_offset =
      GNUNET_TIME_relative_divide (find_peer_delay, max_outstanding_find_peers);

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing", "num_rounds",
                                             &total_rounds))
    total_rounds = 1;

  if ((GNUNET_SYSERR ==
       GNUNET_CONFIGURATION_get_value_number (cfg, "dht_testing",
                                              "target_total_connections",
                                              &target_total_connections)) ||
      (target_total_connections == 0))
    target_total_connections =
        connection_estimate (num_peers, DEFAULT_BUCKET_SIZE);

  topology_str = NULL;
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

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "testing", "percentage",
                                             &topology_percentage_str))
    topology_percentage = 0.5;
  else
  {
    topology_percentage = atof (topology_percentage_str);
    GNUNET_free (topology_percentage_str);
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "testing", "probability",
                                             &topology_probability_str))
    topology_probability = 0.5;
  else
  {
    topology_probability = atof (topology_probability_str);
    GNUNET_free (topology_probability_str);
  }

  if ((GNUNET_YES ==
       GNUNET_CONFIGURATION_get_value_string (cfg, "testing",
                                              "connect_topology",
                                              &connect_topology_str)) &&
      (GNUNET_NO ==
       GNUNET_TESTING_topology_get (&connect_topology, connect_topology_str)))
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

  /* Set peers_left so we know when all peers started */
  peers_left = num_peers;

  /* Set up a task to end testing if peer start fails */
  die_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (seconds_per_peer_start, num_peers),
                                    &end_badly,
                                    "didn't generate all hostkeys within allowed startup time!");

  if (dhtlog_handle == NULL)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "dhtlog_handle is NULL!");

  trial_info.other_identifier = (unsigned int) trial_to_run;
  trial_info.num_nodes = peers_left;
  trial_info.topology = topology;
  trial_info.blacklist_topology = blacklist_topology;
  trial_info.connect_topology = connect_topology;
  trial_info.connect_topology_option = connect_topology_option;
  trial_info.connect_topology_option_modifier =
      connect_topology_option_modifier;
  trial_info.topology_percentage = topology_percentage;
  trial_info.topology_probability = topology_probability;
  trial_info.puts = num_puts;
  trial_info.gets = num_gets;
  trial_info.concurrent = max_outstanding_gets;
  trial_info.settle_time = settle_time;
  trial_info.num_rounds = total_rounds;
  trial_info.malicious_getters = malicious_getters;
  trial_info.malicious_putters = malicious_putters;
  trial_info.malicious_droppers = malicious_droppers;
  trial_info.malicious_get_frequency = malicious_get_frequency.rel_value;
  trial_info.malicious_put_frequency = malicious_put_frequency.rel_value;
  trial_info.stop_closest = stop_closest;
  trial_info.stop_found = stop_found;
  trial_info.strict_kademlia = strict_kademlia;

  if (trialmessage != NULL)
    trial_info.message = trialmessage;
  else
    trial_info.message = "";

  if (dhtlog_handle != NULL)
    dhtlog_handle->insert_trial (&trial_info);

  GNUNET_free_non_null (trialmessage);

  hostkey_meter = create_meter (peers_left, "Hostkeys created ", GNUNET_YES);
  peer_start_meter = create_meter (peers_left, "Peers started ", GNUNET_YES);

  put_meter = create_meter (num_puts, "Puts completed ", GNUNET_YES);
  get_meter = create_meter (num_gets, "Gets completed ", GNUNET_YES);
  hostkey_start_time = GNUNET_TIME_absolute_get ();
  pg = GNUNET_TESTING_daemons_start (cfg, peers_left,
                                     max_outstanding_connections,
                                     max_concurrent_ssh,
                                     GNUNET_TIME_relative_multiply
                                     (seconds_per_peer_start, num_peers),
                                     &hostkey_callback, NULL,
                                     &peers_started_callback, NULL,
                                     &topology_callback, NULL, hosts);
  temphost = hosts;
  while (temphost != NULL)
  {
    tempnext = temphost->next;
    GNUNET_free (temphost->username);
    GNUNET_free (temphost->hostname);
    GNUNET_free (temphost);
    temphost = tempnext;
  }
}

int
main (int argc, char *argv[])
{
  int ret;

  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  ret =
      GNUNET_PROGRAM_run (argc, argv, "gnunet-dht-driver", "nohelp", options,
                          &run, &ok);

  if (malicious_bloom != NULL)
    GNUNET_CONTAINER_bloomfilter_free (malicious_bloom);

  if (ret != GNUNET_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "`gnunet-dht-driver': Failed with error code %d\n", ret);
  }

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

/* end of gnunet-dht-driver.c */
