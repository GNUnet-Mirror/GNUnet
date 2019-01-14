/*
     This file is part of GNUnet.
     Copyright (C) 2014, 2018 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
    
     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
*/

/**
 * @file dht/gnunet_dht_profiler.c
 * @brief Profiler for GNUnet DHT
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"
#include "gnunet_dht_service.h"
#include "gnunet_constants.h"


#define MESSAGE(...)                                       \
  GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE, __VA_ARGS__)

#define DEBUG(...)                                           \
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__)

/**
 * Number of peers which should perform a PUT out of 100 peers
 */
static unsigned int put_probability = 100;

/**
 * Configuration
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Name of the file with the hosts to run the test over
 */
static char *hosts_file;

/**
 * Context for a peer which actively does DHT PUT/GET
 */
struct ActiveContext;

/**
 * Context to hold data of peer
 */
struct Context
{
  /**
   * The testbed peer this context belongs to
   */
  struct GNUNET_TESTBED_Peer *peer;

  /**
   * Testbed operation acting on this peer
   */
  struct GNUNET_TESTBED_Operation *op;

  /**
   * Active context; NULL if this peer is not an active peer
   */
  struct ActiveContext *ac;

};


/**
 * Context for a peer which actively does DHT PUT/GET
 */
struct ActiveContext
{
  /**
   * The linked peer context
   */
  struct Context *ctx;

  /**
   * Handler to the DHT service
   */
  struct GNUNET_DHT_Handle *dht;

  /**
   * The active context used for our DHT GET
   */
  struct ActiveContext *get_ac;

  /**
   * The put handle
   */
  struct GNUNET_DHT_PutHandle *dht_put;

  /**
   * The get handle
   */
  struct GNUNET_DHT_GetHandle *dht_get;

  /**
   * The hashes of the values stored via this activity context.
   * Array of length #num_puts_per_peer.
   */
  struct GNUNET_HashCode *hash;

  /**
   * Delay task
   */
  struct GNUNET_SCHEDULER_Task *delay_task;

  /**
   * How many puts should we still issue?
   */
  unsigned int put_count;

  /**
   * The number of peers currently doing GET on our data
   */
  uint16_t nrefs;
};


/**
 * An array of contexts.  The size of this array should be equal to @a num_peers
 */
static struct Context *a_ctx;

/**
 * Array of active peers
 */
static struct ActiveContext *a_ac;

/**
 * The delay between rounds for collecting statistics
 */
static struct GNUNET_TIME_Relative delay_stats;

/**
 * The delay to start puts.
 */
static struct GNUNET_TIME_Relative delay_put;

/**
 * The delay to start puts.
 */
static struct GNUNET_TIME_Relative delay_get;

/**
 * The timeout for GET and PUT
 */
static struct GNUNET_TIME_Relative timeout;

/**
 * Number of peers
 */
static unsigned int num_peers;

/**
 * Number of active peers
 */
static unsigned int n_active;

/**
 * Number of DHT service connections we currently have
 */
static unsigned int n_dht;

/**
 * Number of DHT PUTs made
 */
static unsigned long long n_puts;

/**
 * Number of DHT PUTs to be made per peer.
 */
static unsigned int num_puts_per_peer = 1;

/**
 * Number of DHT PUTs succeeded
 */
static unsigned long long n_puts_ok;

/**
 * Number of DHT GETs made
 */
static unsigned int n_gets;

/**
 * Number of DHT GETs succeeded
 */
static unsigned int n_gets_ok;

/**
 * Number of DHT GETs succeeded
 */
static unsigned int n_gets_fail;

/**
 * Replication degree
 */
static unsigned int replication;

/**
 * Testbed Operation (to get stats).
 */
static struct GNUNET_TESTBED_Operation *bandwidth_stats_op;

/**
 * Testbed peer handles.
 */
static struct GNUNET_TESTBED_Peer **testbed_handles;

/**
 * Total number of messages sent by peer.
 */
static uint64_t outgoing_bandwidth;

/**
 * Total number of messages received by peer.
 */
static uint64_t incoming_bandwidth;

/**
 * Average number of hops taken to do put.
 */
static double average_put_path_length;

/**
 * Average number of hops taken to do get.
 */
static double average_get_path_length;

/**
 * Total put path length across all peers.
 */
static unsigned int total_put_path_length;

/**
 * Total get path length across all peers.
 */
static unsigned int total_get_path_length;

/**
 * Counter to keep track of peers added to peer_context lists.
 */
static int peers_started = 0;

/**
 * Should we do a PUT (mode = 0) or GET (mode = 1);
 */
static enum
{
  MODE_PUT = 0,

  MODE_GET = 1
} mode;


/**
 * Are we shutting down
 */
static int in_shutdown = 0;


/**
 * Connect to DHT services of active peers
 */
static void
start_profiling (void);


/**
 * Shutdown task.  Cleanup all resources and operations.
 *
 * @param cls NULL
 */
static void
do_shutdown (void *cls)
{
  struct ActiveContext *ac;

  in_shutdown = GNUNET_YES;
  if (NULL != a_ctx)
  {
    for (unsigned int cnt=0; cnt < num_peers; cnt++)
    {
      /* Cleanup active context if this peer is an active peer */
      ac = a_ctx[cnt].ac;
      if (NULL != ac)
      {
        if (NULL != ac->delay_task)
          GNUNET_SCHEDULER_cancel (ac->delay_task);
        if (NULL != ac->hash)
          free (ac->hash);
        if (NULL != ac->dht_put)
          GNUNET_DHT_put_cancel (ac->dht_put);
        if (NULL != ac->dht_get)
          GNUNET_DHT_get_stop (ac->dht_get);
      }
      /* Cleanup testbed operation handle at the last as this operation may
         contain service connection to DHT */
      if (NULL != a_ctx[cnt].op)
        GNUNET_TESTBED_operation_done (a_ctx[cnt].op);
    }
    GNUNET_free (a_ctx);
    a_ctx = NULL;
  }
  //FIXME: Should we collect stats only for put/get not for other messages.
  if (NULL != bandwidth_stats_op)
  {
    GNUNET_TESTBED_operation_done (bandwidth_stats_op);
    bandwidth_stats_op = NULL;
  }
  GNUNET_free_non_null (a_ac);
}


/**
 * Stats callback. Finish the stats testbed operation and when all stats have
 * been iterated, shutdown the test.
 *
 * @param cls closure
 * @param op the operation that has been finished
 * @param emsg error message in case the operation has failed; will be NULL if
 *          operation has executed successfully.
 */
static void
bandwidth_stats_cont (void *cls,
                      struct GNUNET_TESTBED_Operation *op,
                      const char *emsg)
{
  MESSAGE ("# Outgoing (core) bandwidth: %llu bytes\n",
           (unsigned long long) outgoing_bandwidth);
  MESSAGE ("# Incoming (core) bandwidth: %llu bytes\n",
           (unsigned long long) incoming_bandwidth);
  fprintf (stderr,
           "Benchmark done. Collect data via gnunet-statistics, then press ENTER to exit.\n");
  (void) getchar ();
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Process statistic values.
 *
 * @param cls closure
 * @param peer the peer the statistic belong to
 * @param subsystem name of subsystem that created the statistic
 * @param name the name of the datum
 * @param value the current value
 * @param is_persistent #GNUNET_YES if the value is persistent, #GNUNET_NO if not
 * @return #GNUNET_OK to continue, #GNUNET_SYSERR to abort iteration
 */
static int
bandwidth_stats_iterator (void *cls,
                          const struct GNUNET_TESTBED_Peer *peer,
                          const char *subsystem,
                          const char *name,
                          uint64_t value,
                          int is_persistent)
{
  static const char *s_sent = "# bytes encrypted";
  static const char *s_recv = "# bytes decrypted";

  if (0 == strncmp (s_sent, name, strlen (s_sent)))
    outgoing_bandwidth = outgoing_bandwidth + value;
  else if (0 == strncmp(s_recv, name, strlen (s_recv)))
    incoming_bandwidth = incoming_bandwidth + value;
  return GNUNET_OK;
}


static void
summarize ()
{
  MESSAGE ("# PUTS started: %llu\n",
        n_puts);
  MESSAGE ("# PUTS succeeded: %llu\n",
        n_puts_ok);
  MESSAGE ("# GETS made: %u\n",
        n_gets);
  MESSAGE ("# GETS succeeded: %u\n",
        n_gets_ok);
  MESSAGE ("# GETS failed: %u\n",
        n_gets_fail);
  MESSAGE ("# average_put_path_length: %f\n",
        average_put_path_length);
  MESSAGE ("# average_get_path_length: %f\n",
        average_get_path_length);

  if (NULL == testbed_handles)
  {
    MESSAGE ("No peers found\n");
    return;
  }
  /* Collect Stats*/
  bandwidth_stats_op = GNUNET_TESTBED_get_statistics (n_active,
                                                      testbed_handles,
                                                      "core",
                                                      NULL,
                                                      &bandwidth_stats_iterator,
                                                      &bandwidth_stats_cont,
                                                      NULL);
}


/**
 * Task to cancel DHT GET.
 *
 * @param cls NULL
 */
static void
cancel_get (void *cls)
{
  struct ActiveContext *ac = cls;
  struct Context *ctx = ac->ctx;

  ac->delay_task = NULL;
  GNUNET_assert (NULL != ac->dht_get);
  GNUNET_DHT_get_stop (ac->dht_get);
  ac->dht_get = NULL;
  n_gets_fail++;
  GNUNET_assert (NULL != ctx->op);
  GNUNET_TESTBED_operation_done (ctx->op);
  ctx->op = NULL;

  /* If profiling is complete, summarize */
  if (n_active == n_gets_fail + n_gets_ok)
  {
    average_put_path_length = (double)total_put_path_length/(double)n_active;
    average_get_path_length = (double)total_get_path_length/(double )n_gets_ok;
    summarize ();
  }
}


/**
 * Iterator called on each result obtained for a DHT
 * operation that expects a reply
 *
 * @param cls closure
 * @param exp when will this value expire
 * @param key key of the result
 * @param get_path peers on reply path (or NULL if not recorded)
 *                 [0] = datastore's first neighbor, [length - 1] = local peer
 * @param get_path_length number of entries in @a get_path
 * @param put_path peers on the PUT path (or NULL if not recorded)
 *                 [0] = origin, [length - 1] = datastore
 * @param put_path_length number of entries in @a put_path
 * @param type type of the result
 * @param size number of bytes in @a data
 * @param data pointer to the result data
 */
static void
get_iter (void *cls,
          struct GNUNET_TIME_Absolute exp,
          const struct GNUNET_HashCode *key,
          const struct GNUNET_PeerIdentity *get_path,
          unsigned int get_path_length,
          const struct GNUNET_PeerIdentity *put_path,
          unsigned int put_path_length,
          enum GNUNET_BLOCK_Type type,
          size_t size, const void *data)
{
  struct ActiveContext *ac = cls;
  struct ActiveContext *get_ac = ac->get_ac;
  struct Context *ctx = ac->ctx;

  /* we found the data we are looking for */
  DEBUG ("We found a GET request; %u remaining\n",
         n_gets - (n_gets_fail + n_gets_ok)); //FIXME: It always prints 1.
  n_gets_ok++;
  get_ac->nrefs--;
  GNUNET_DHT_get_stop (ac->dht_get);
  ac->dht_get = NULL;
  if (ac->delay_task != NULL)
    GNUNET_SCHEDULER_cancel (ac->delay_task);
  ac->delay_task = NULL;
  GNUNET_assert (NULL != ctx->op);
  GNUNET_TESTBED_operation_done (ctx->op);
  ctx->op = NULL;

  total_put_path_length = total_put_path_length + (double)put_path_length;
  total_get_path_length = total_get_path_length + (double)get_path_length;
  DEBUG ("total_put_path_length = %u,put_path \n",
         total_put_path_length);
  /* Summarize if profiling is complete */
  if (n_active == n_gets_fail + n_gets_ok)
  {
    average_put_path_length = (double)total_put_path_length/(double)n_active;
    average_get_path_length = (double)total_get_path_length/(double )n_gets_ok;
    summarize ();
  }
}


/**
 * Task to do DHT GETs
 *
 * @param cls the active context
 */
static void
delayed_get (void *cls)
{
  struct ActiveContext *ac = cls;
  struct ActiveContext *get_ac;
  unsigned int r;

  ac->delay_task = NULL;
  get_ac = NULL;
  while (1)
  {
    r = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                  n_active);
    get_ac = &a_ac[r];
    if (NULL != get_ac->hash)
      break;
  }
  get_ac->nrefs++;
  ac->get_ac = get_ac;
  r = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                num_puts_per_peer);
  DEBUG ("GET_REQUEST_START key %s \n",
         GNUNET_h2s(&get_ac->hash[r]));
  ac->dht_get = GNUNET_DHT_get_start (ac->dht,
                                      GNUNET_BLOCK_TYPE_TEST,
                                      &get_ac->hash[r],
                                      1, /* replication level */
                                      GNUNET_DHT_RO_NONE,
                                      NULL,
                                      0, /* extended query and size */
                                      &get_iter,
                                      ac); /* GET iterator and closure */
  n_gets++;

  /* schedule the timeout task for GET */
  ac->delay_task = GNUNET_SCHEDULER_add_delayed (timeout,
                                                 &cancel_get,
                                                 ac);
}


/**
 * Task to do DHT PUTs.  If the "put_count" hits zero,
 * we stop the TESTBED operation (connection to DHT)
 * so that others PUTs have a chance.
 *
 * @param cls the active context
 */
static void
delayed_put (void *cls);


/**
 * Conclude individual PUT operation, schedule the
 * next one.
 *
 * @param cls the active context
 */
static void
put_cont (void *cls)
{
  struct ActiveContext *ac = cls;

  ac->dht_put = NULL;
  n_puts_ok++;
  ac->delay_task = GNUNET_SCHEDULER_add_now (&delayed_put,
                                             ac);
}


/**
 * Task to do DHT PUTs.  If the "put_count" hits zero,
 * we stop the TESTBED operation (connection to DHT)
 * so that others PUTs have a chance.
 *
 * @param cls the active context
 */
static void
delayed_put (void *cls)
{
  struct ActiveContext *ac = cls;
  char block[65536];
  size_t block_size;

  ac->delay_task = NULL;
  if (0 == ac->put_count)
  {
    struct Context *ctx = ac->ctx;
    struct GNUNET_TESTBED_Operation *op;

    GNUNET_assert (NULL != ctx);
    op = ctx->op;
    ctx->op = NULL;
    GNUNET_TESTBED_operation_done (op);
    return;
  }


  /* Generate and DHT PUT some random data */
  block_size = 16; /* minimum */
  /* make random payload, reserve 512 - 16 bytes for DHT headers */
  block_size += GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                          GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE - 512);
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK,
                              block,
                              block_size);
  ac->put_count--;
  GNUNET_CRYPTO_hash (block,
                      block_size,
                      &ac->hash[ac->put_count]);
  DEBUG ("PUT_REQUEST_START key %s\n",
         GNUNET_h2s (&ac->hash[ac->put_count]));
  ac->dht_put = GNUNET_DHT_put (ac->dht,
                                &ac->hash[ac->put_count],
                                replication,
                                GNUNET_DHT_RO_RECORD_ROUTE,
                                GNUNET_BLOCK_TYPE_TEST,
                                block_size,
                                block,
                                GNUNET_TIME_UNIT_FOREVER_ABS, /* expiration time */
                                &put_cont,
                                ac);                /* continuation and its closure */
  n_puts++;
}


/**
 * Connection to DHT has been established.  Call the delay task.
 *
 * @param cls the active context
 * @param op the operation that has been finished
 * @param ca_result the service handle returned from GNUNET_TESTBED_ConnectAdapter()
 * @param emsg error message in case the operation has failed; will be NULL if
 *          operation has executed successfully.
 */
static void
dht_connected (void *cls,
               struct GNUNET_TESTBED_Operation *op,
               void *ca_result,
               const char *emsg)
{
  struct ActiveContext *ac = cls;
  struct Context *ctx = ac->ctx;

  GNUNET_assert (NULL != ctx); //FIXME: Fails
  GNUNET_assert (NULL != ctx->op);
  GNUNET_assert (ctx->op == op);
  ac->dht = (struct GNUNET_DHT_Handle *) ca_result;
  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Connection to DHT service failed: %s\n",
                emsg);
    GNUNET_TESTBED_operation_done (ctx->op); /* Calls dht_disconnect() */
    ctx->op = NULL;
    return;
  }
  switch (mode)
  {
  case MODE_PUT:
    {
      struct GNUNET_TIME_Relative peer_delay_put;

      peer_delay_put.rel_value_us =
        GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                  delay_put.rel_value_us);
      ac->put_count = num_puts_per_peer;
      ac->hash = calloc (ac->put_count,
                         sizeof (struct GNUNET_HashCode));
      if (NULL == ac->hash)
      {
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
                             "calloc");
        GNUNET_SCHEDULER_shutdown ();
        return;
      }
      ac->delay_task = GNUNET_SCHEDULER_add_delayed (peer_delay_put,
                                                     &delayed_put,
                                                     ac);
      break;
    }
  case MODE_GET:
    {
      struct GNUNET_TIME_Relative peer_delay_get;

      peer_delay_get.rel_value_us =
        delay_get.rel_value_us +
        GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                  delay_get.rel_value_us);
      ac->delay_task = GNUNET_SCHEDULER_add_delayed (peer_delay_get,
                                                     &delayed_get,
                                                     ac);
      break;
    }
  }
}


/**
 * Connect to DHT service and return the DHT client handler
 *
 * @param cls the active context
 * @param cfg configuration of the peer to connect to; will be available until
 *          GNUNET_TESTBED_operation_done() is called on the operation returned
 *          from GNUNET_TESTBED_service_connect()
 * @return service handle to return in 'op_result', NULL on error
 */
static void *
dht_connect (void *cls,
             const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  n_dht++;
  return GNUNET_DHT_connect (cfg,
                             10);
}


/**
 * Adapter function called to destroy a connection to
 * a service.
 *
 * @param cls the active context
 * @param op_result service handle returned from the connect adapter
 */
static void
dht_disconnect (void *cls,
                void *op_result)
{
  struct ActiveContext *ac = cls;

  GNUNET_assert (NULL != ac->dht);
  GNUNET_assert (ac->dht == op_result);
  GNUNET_DHT_disconnect (ac->dht);
  ac->dht = NULL;
  n_dht--;
  if (0 != n_dht)
    return;
  if (GNUNET_YES == in_shutdown)
    return;
  switch (mode)
  {
  case MODE_PUT:
    if (n_puts_ok != ((unsigned long long) n_active) * num_puts_per_peer)
      return;
    /* Start GETs if all PUTs have been made */
    mode = MODE_GET;
    start_profiling ();
    return;
  case MODE_GET:
    if ((n_gets_ok + n_gets_fail) != n_active)
      return;
    break;
  }
}


/**
 * Connect to DHT services of active peers
 */
static void
start_profiling()
{
  struct Context *ctx;

  DEBUG ("GNUNET_TESTBED_service_connect\n");
  GNUNET_break (GNUNET_YES != in_shutdown);
  for (unsigned int i = 0; i < n_active; i++)
  {
    struct ActiveContext *ac = &a_ac[i];
    GNUNET_assert (NULL != (ctx = ac->ctx));
    GNUNET_assert (NULL == ctx->op);
    ctx->op = GNUNET_TESTBED_service_connect (ctx,
                                              ctx->peer,
                                              "dht",
                                              &dht_connected, ac,
                                              &dht_connect,
                                              &dht_disconnect,
                                              ac);
  }
}


/**
 * Callback called when DHT service on the peer is started
 *
 * @param cls the context
 * @param op the operation that has been finished
 * @param emsg error message in case the operation has failed; will be NULL if
 *          operation has executed successfully.
 */
static void
service_started (void *cls,
                 struct GNUNET_TESTBED_Operation *op,
                 const char *emsg)
{
  struct Context *ctx = cls;

  GNUNET_assert (NULL != ctx);
  GNUNET_assert (NULL != ctx->op);
  GNUNET_TESTBED_operation_done (ctx->op);
  ctx->op = NULL;
  peers_started++;
  DEBUG ("Peers Started = %d; num_peers = %d \n",
         peers_started,
         num_peers);
  if (peers_started == num_peers)
    start_profiling ();
}


/**
 * Signature of a main function for a testcase.
 *
 * @param cls closure
 * @param h the run handle
 * @param num_peers number of peers in 'peers'
 * @param peers handle to peers run in the testbed
 * @param links_succeeded the number of overlay link connection attempts that
 *          succeeded
 * @param links_failed the number of overlay link
 */
static void
test_run (void *cls,
          struct GNUNET_TESTBED_RunHandle *h,
          unsigned int num_peers,
          struct GNUNET_TESTBED_Peer **peers,
          unsigned int links_succeeded,
          unsigned int links_failed)
{
  unsigned int ac_cnt;

  testbed_handles = peers;
  if (NULL == peers)
  {
    /* exit */
    GNUNET_assert (0);
  }
  MESSAGE ("%u peers started, %u/%u links up\n",
           num_peers,
           links_succeeded,
           links_succeeded + links_failed);
  a_ctx = GNUNET_new_array (num_peers,
                            struct Context);
  /* select the peers which actively participate in profiling */
  n_active = num_peers * put_probability / 100;
  if (0 == n_active)
  {
    GNUNET_SCHEDULER_shutdown ();
    GNUNET_free (a_ctx);
    a_ctx = NULL;
    return;
  }

  a_ac = GNUNET_new_array (n_active,
                           struct ActiveContext);
  ac_cnt = 0;
  for (unsigned int cnt = 0; cnt < num_peers && ac_cnt < n_active; cnt++)
  {
    if (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                  100) >= put_probability)
      continue;

    a_ctx[cnt].ac = &a_ac[ac_cnt];
    a_ac[ac_cnt].ctx = &a_ctx[cnt];
    ac_cnt++;
  }
  n_active = ac_cnt;

  /* start DHT service on all peers */
  for (unsigned int cnt = 0; cnt < num_peers; cnt++)
  {
    a_ctx[cnt].peer = peers[cnt];
    a_ctx[cnt].op = GNUNET_TESTBED_peer_manage_service (&a_ctx[cnt],
                                                        peers[cnt],
                                                        "dht",
                                                        &service_started,
                                                        &a_ctx[cnt],
                                                        1);
  }
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param config configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *config)
{
  uint64_t event_mask;

  if (0 == num_peers)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Exiting as the number of peers is %u\n"),
                num_peers);
    return;
  }
  cfg = config;
  event_mask = 0;
  GNUNET_TESTBED_run (hosts_file,
                      cfg,
                      num_peers,
                      event_mask,
                      NULL,
                      NULL,
                      &test_run,
                      NULL);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
				 NULL);
}


/**
 * Main function.
 *
 * @return 0 on success
 */
int
main (int argc,
      char *const *argv)
{
  int rc;
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_uint ('n',
                               "peers",
                               "COUNT",
                               gettext_noop ("number of peers to start"),
                               &num_peers),
    GNUNET_GETOPT_option_uint ('p',
                               "peer-put-count",
                               "COUNT",
                               gettext_noop ("number of PUTs to perform per peer"),
                               &num_puts_per_peer),
    GNUNET_GETOPT_option_string ('H',
                                 "hosts",
                                 "FILENAME",
                                 gettext_noop ("name of the file with the login information for the testbed"),
                                 &hosts_file),
    GNUNET_GETOPT_option_relative_time ('D',
                                        "delay",
                                        "DELAY",
                                        gettext_noop ("delay between rounds for collecting statistics (default: 30 sec)"),
                                        &delay_stats),
    GNUNET_GETOPT_option_relative_time ('P',
                                        "PUT-delay",
                                        "DELAY",
                                        gettext_noop ("delay to start doing PUTs (default: 1 sec)"),
                                        &delay_put),
    GNUNET_GETOPT_option_relative_time ('G',
                                        "GET-delay",
                                        "DELAY",
                                        gettext_noop ("delay to start doing GETs (default: 5 min)"),
                                        &delay_get),
    GNUNET_GETOPT_option_uint ('r',
                               "replication",
                               "DEGREE",
                               gettext_noop ("replication degree for DHT PUTs"),
                               &replication),
    GNUNET_GETOPT_option_uint ('R',
                               "random-chance",
                               "PROBABILITY",
                               gettext_noop ("chance that a peer is selected at random for PUTs"),
                               &put_probability),
    GNUNET_GETOPT_option_relative_time ('t',
                                        "timeout",
                                        "TIMEOUT",
                                        gettext_noop ("timeout for DHT PUT and GET requests (default: 1 min)"),
                                        &timeout),
    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK !=
      GNUNET_STRINGS_get_utf8_args (argc, argv,
                                    &argc, &argv))
    return 2;
  /* set default delays */
  delay_stats = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10);
  delay_put = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10);
  delay_get = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10);
  timeout = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10);
  replication = 1;      /* default replication */
  rc = 0;
  if (GNUNET_OK !=
      GNUNET_PROGRAM_run (argc,
                          argv,
                          "gnunet-dht-profiler",
			  gettext_noop ("Measure quality and performance of the DHT service."),
			  options,
                          &run,
                          NULL))
    rc = 1;
  return rc;
}
