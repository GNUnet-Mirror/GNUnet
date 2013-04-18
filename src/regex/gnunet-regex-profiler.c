/*
     This file is part of GNUnet.
     (C) 2011 - 2013 Christian Grothoff (and other contributing authors)

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
 * @file regex/gnunet-regex-profiler.c
 * @brief Regex profiler for testing distributed regex use.
 * @author Bartlomiej Polot
 * @author Maximilian Szengel
 *
 */

#include <string.h>

#include "platform.h"
#include "gnunet_applications.h"
#include "gnunet_util_lib.h"
#include "gnunet_regex_lib.h"
#include "gnunet_arm_service.h"
#include "gnunet_dht_service.h"
#include "gnunet_testbed_service.h"

#define FIND_TIMEOUT \
        GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 90)
#define SEARCHES_IN_PARALLEL 5

/**
 * DLL of operations
 */
struct DLLOperation
{
  /**
   * The testbed operation handle
   */
  struct GNUNET_TESTBED_Operation *op;

  /**
   * Closure
   */
  void *cls;

  /**
   * The next pointer for DLL
   */
  struct DLLOperation *next;

  /**
   * The prev pointer for DLL
   */
  struct DLLOperation *prev;
};


/**
 * Available states during profiling
 */
enum State
{
  /**
   * Initial state
   */
  STATE_INIT = 0,

  /**
   * Starting slaves
   */
  STATE_SLAVES_STARTING,

  /**
   * Creating peers
   */
  STATE_PEERS_CREATING,

  /**
   * Starting peers
   */
  STATE_PEERS_STARTING,

  /**
   * Linking peers
   */
  STATE_PEERS_LINKING,

  /**
   * Matching strings against announced regexes
   */
  STATE_SEARCH_REGEX,

  /**
   * Destroying peers; we can do this as the controller takes care of stopping a
   * peer if it is running
   */
  STATE_PEERS_DESTROYING
};


/**
 * Peer handles.
 */
struct RegexPeer
{
  /**
   * Peer id.
   */
  unsigned int id;

  /**
   * Peer configuration handle.
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * The actual testbed peer handle.
   */
  struct GNUNET_TESTBED_Peer *peer_handle;

  /**
   * Host on which the peer is running.
   */
  struct GNUNET_TESTBED_Host *host_handle;

  /**
   * Filename of the peer's policy file.
   */
  char *policy_file;

  /**
   * Peer's search string.
   */
  const char *search_str;

  /**
   * Set to GNUNET_YES if the peer successfully matched the above
   * search string. GNUNET_NO if the string could not be matched
   * during the profiler run. GNUNET_SYSERR if the string matching
   * timed out. Undefined if search_str is NULL
   */
  int search_str_matched;

  /**
   * Peer's DHT handle.
   */
  struct GNUNET_DHT_Handle *dht_handle;

  /**
   * Handle to a running regex search.
   */
   struct GNUNET_REGEX_search_handle *search_handle;

  /**
   * Testbed operation handle for DHT.
   */
  struct GNUNET_TESTBED_Operation *op_handle;

  /**
   * Peers's statistics handle.
   */
  struct GNUNET_STATISTICS_Handle *stats_handle;

  /**
   * Testbed operation handle for the statistics service.
   */
  struct GNUNET_TESTBED_Operation *stats_op_handle;

  /**
   * The starting time of a profiling step.
   */
  struct GNUNET_TIME_Absolute prof_start_time;

  /**
   * Operation timeout
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout;

  /**
   * Deamon start
   */
  struct GNUNET_TESTBED_Operation *daemon_op;
};


/**
 * The array of peers; we fill this as the peers are given to us by the testbed
 */
static struct RegexPeer *peers;

/**
 * Host registration handle
 */
static struct GNUNET_TESTBED_HostRegistrationHandle *reg_handle;

/**
 * Handle to the master controller process
 */
static struct GNUNET_TESTBED_ControllerProc *mc_proc;

/**
 * Handle to the master controller
 */
static struct GNUNET_TESTBED_Controller *mc;

/**
 * Handle to global configuration
 */
static struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Abort task identifier
 */
static GNUNET_SCHEDULER_TaskIdentifier abort_task;

/**
 * Shutdown task identifier
 */
static GNUNET_SCHEDULER_TaskIdentifier shutdown_task;

/**
 * Host registration task identifier
 */
static GNUNET_SCHEDULER_TaskIdentifier register_hosts_task;

/**
 * Global event mask for all testbed events
 */
static uint64_t event_mask;

/**
 * The starting time of a profiling step
 */
static struct GNUNET_TIME_Absolute prof_start_time;

/**
 * Duration profiling step has taken
 */
static struct GNUNET_TIME_Relative prof_time;

/**
 * Number of peers to be started by the profiler
 */
static unsigned int num_peers;

/**
 * Factor of number of links. num_links = num_peers * linking_factor.
 */
static unsigned int linking_factor;

/**
 * Global testing status
 */
static int result;

/**
 * current state of profiling
 */
enum State state;

/**
 * Folder where policy files are stored.
 */
static char * policy_dir;

/**
 * Search strings.
 */
static char **search_strings;

/**
 * Number of search strings.
 */
static int num_search_strings;

/**
 * How many searches are running in parallel
 */
static unsigned int parallel_searches;

/**
 * Number of peers found with search strings.
 */
static unsigned int peers_found;

/**
 * Index of peer to start next announce/search.
 */
static unsigned int next_search;

/**
 * Search timeout task identifier.
 */
static GNUNET_SCHEDULER_TaskIdentifier search_timeout_task;

/**
 * Search timeout in seconds.
 */
static struct GNUNET_TIME_Relative search_timeout_time = { 60000 };

/**
 * How long do we wait before starting the search?
 * Default: 1 m.
 */
static struct GNUNET_TIME_Relative search_delay = { 60000 };

/**
 * File to log statistics to.
 */
static struct GNUNET_DISK_FileHandle *data_file;

/**
 * Filename to log statistics to.
 */
static char *data_filename;

/**
 * Maximal path compression length.
 */
static unsigned int max_path_compression;

/**
 * Prefix used for regex announcing. We need to prefix the search
 * strings with it, in order to find something.
 */
static char * regex_prefix;

/**
 * What's the maximum regex reannounce period.
 */
static struct GNUNET_TIME_Relative reannounce_period_max;


/******************************************************************************/
/******************************  DECLARATIONS  ********************************/
/******************************************************************************/

/**
 * DHT connect callback.
 *
 * @param cls internal peer id.
 * @param op operation handle.
 * @param ca_result connect adapter result.
 * @param emsg error message.
 */
static void
dht_connect_cb (void *cls, struct GNUNET_TESTBED_Operation *op,
                void *ca_result, const char *emsg);

/**
 * DHT connect adapter.
 *
 * @param cls not used.
 * @param cfg configuration handle.
 *
 * @return
 */
static void *
dht_ca (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Adapter function called to destroy a connection to
 * the DHT service
 *
 * @param cls closure
 * @param op_result service handle returned from the connect adapter
 */
static void
dht_da (void *cls, void *op_result);


/**
 * Function called by testbed once we are connected to stats
 * service. Get the statistics for the services of interest.
 *
 * @param cls the 'struct RegexPeer' for which we connected to stats
 * @param op connect operation handle
 * @param ca_result handle to stats service
 * @param emsg error message on failure
 */
static void
stats_connect_cb (void *cls,
                  struct GNUNET_TESTBED_Operation *op,
                  void *ca_result,
                  const char *emsg);


/**
 * Task to collect all statistics from s, will shutdown the
 * profiler, when done.
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_collect_stats (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Start announcing the next regex in the DHT.
 *
 * @param cls Index of the next peer in the peers array.
 * @param tc TaskContext.
 */
static void
announce_next_regex (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/******************************************************************************/
/********************************  SHUTDOWN  **********************************/
/******************************************************************************/


/**
 * Shutdown nicely
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct RegexPeer *peer;
  unsigned int peer_cnt;
  unsigned int search_str_cnt;
  char output_buffer[512];
  size_t size;

  shutdown_task = GNUNET_SCHEDULER_NO_TASK;
  if (GNUNET_SCHEDULER_NO_TASK != abort_task)
    GNUNET_SCHEDULER_cancel (abort_task);
  if (GNUNET_SCHEDULER_NO_TASK != register_hosts_task)
    GNUNET_SCHEDULER_cancel (register_hosts_task);

  for (peer_cnt = 0; peer_cnt < num_peers; peer_cnt++)
  {
    peer = &peers[peer_cnt];

    if (GNUNET_YES != peer->search_str_matched && NULL != data_file)
    {
      prof_time = GNUNET_TIME_absolute_get_duration (peer->prof_start_time);
      size =
        GNUNET_snprintf (output_buffer,
                         sizeof (output_buffer),
                         "%p Search string not found: %s (%d)\n%p On peer: %u (%p)\n%p With policy file: %s\n%p After: %s\n",
                         peer, peer->search_str, peer->search_str_matched,
                         peer, peer->id, peer,
                         peer, peer->policy_file,
                         peer,
                         GNUNET_STRINGS_relative_time_to_string (prof_time,
                                                                 GNUNET_NO));
      if (size != GNUNET_DISK_file_write (data_file, output_buffer, size))
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Unable to write to file!\n");
    }

    if (NULL != peers[peer_cnt].op_handle)
      GNUNET_TESTBED_operation_done (peers[peer_cnt].op_handle);
    if (NULL != peers[peer_cnt].stats_op_handle)
      GNUNET_TESTBED_operation_done (peers[peer_cnt].stats_op_handle);
  }

  if (NULL != data_file)
    GNUNET_DISK_file_close (data_file);

  for (search_str_cnt = 0;
       search_str_cnt < num_search_strings && NULL != search_strings;
       search_str_cnt++)
  {
    GNUNET_free_non_null (search_strings[search_str_cnt]);
  }
  GNUNET_free_non_null (search_strings);

  if (NULL != reg_handle)
    GNUNET_TESTBED_cancel_registration (reg_handle);

  if (NULL != mc)
    GNUNET_TESTBED_controller_disconnect (mc);
  if (NULL != mc_proc)
    GNUNET_TESTBED_controller_stop (mc_proc);
  if (NULL != cfg)
    GNUNET_CONFIGURATION_destroy (cfg);

  GNUNET_SCHEDULER_shutdown (); /* Stop scheduler to shutdown testbed run */
}


/**
 * abort task to run on test timed out
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_abort (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  unsigned long i = (unsigned long) cls;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Aborting %lu...\n", i);
  abort_task = GNUNET_SCHEDULER_NO_TASK;
  result = GNUNET_SYSERR;
  if (GNUNET_SCHEDULER_NO_TASK != shutdown_task)
    GNUNET_SCHEDULER_cancel (shutdown_task);
  shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
}


/******************************************************************************/
/*********************  STATISTICS SERVICE CONNECTIONS  ***********************/
/******************************************************************************/

/**
 * Adapter function called to establish a connection to
 * statistics service.
 *
 * @param cls closure
 * @param cfg configuration of the peer to connect to; will be available until
 *          GNUNET_TESTBED_operation_done() is called on the operation returned
 *          from GNUNET_TESTBED_service_connect()
 * @return service handle to return in 'op_result', NULL on error
 */
static void *
stats_ca (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  return GNUNET_STATISTICS_create ("<driver>", cfg);
}


/**
 * Adapter function called to destroy a connection to
 * statistics service.
 *
 * @param cls closure
 * @param op_result service handle returned from the connect adapter
 */
static void
stats_da (void *cls, void *op_result)
{
  struct RegexPeer *peer = cls;

  GNUNET_assert (op_result == peer->stats_handle);

  GNUNET_STATISTICS_destroy (peer->stats_handle, GNUNET_NO);
  peer->stats_handle = NULL;
}


/**
 * Process statistic values. Write all values to global 'data_file', if present.
 *
 * @param cls closure
 * @param subsystem name of subsystem that created the statistic
 * @param name the name of the datum
 * @param value the current value
 * @param is_persistent GNUNET_YES if the value is persistent, GNUNET_NO if not
 * @return GNUNET_OK to continue, GNUNET_SYSERR to abort iteration
 */
static int
stats_iterator (void *cls, const char *subsystem, const char *name,
                uint64_t value, int is_persistent)
{
  struct RegexPeer *peer = cls;
  char output_buffer[512];
  size_t size;

  if (NULL == data_file)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "%p -> %s [%s]: %llu\n",
                peer, subsystem, name, value);
    return GNUNET_OK;
  }
  size =
    GNUNET_snprintf (output_buffer,
                     sizeof (output_buffer),
                     "%p [%s] %llu %s\n",
                     peer,
                     subsystem, value, name);
  if (size != GNUNET_DISK_file_write (data_file, output_buffer, size))
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Unable to write to file!\n");

  return GNUNET_OK;
}


/**
 * Stats callback. Finish the stats testbed operation and when all stats have
 * been iterated, shutdown the profiler.
 *
 * @param cls closure
 * @param success GNUNET_OK if statistics were
 *        successfully obtained, GNUNET_SYSERR if not.
 */
static void
stats_cb (void *cls,
          int success)
{
  static unsigned int peer_cnt;
  struct RegexPeer *peer = cls;

  if (GNUNET_OK != success)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Getting statistics for peer %u failed!\n",
                peer->id);
    return;
  }

  GNUNET_assert (NULL != peer->stats_op_handle);

  GNUNET_TESTBED_operation_done (peer->stats_op_handle);
  peer->stats_op_handle = NULL;

  peer_cnt++;
  peer = &peers[peer_cnt];

  if (peer_cnt == num_peers)
  {
    struct GNUNET_TIME_Relative delay = { 100 };
    shutdown_task = GNUNET_SCHEDULER_add_delayed (delay, &do_shutdown, NULL);
  }
  else
  {
    peer->stats_op_handle =
      GNUNET_TESTBED_service_connect (NULL,
                                      peer->peer_handle,
                                      "statistics",
                                      &stats_connect_cb,
                                      peer,
                                      &stats_ca,
                                      &stats_da,
                                      peer);
  }
}


/**
 * Function called by testbed once we are connected to stats
 * service. Get the statistics for the services of interest.
 *
 * @param cls the 'struct RegexPeer' for which we connected to stats
 * @param op connect operation handle
 * @param ca_result handle to stats service
 * @param emsg error message on failure
 */
static void
stats_connect_cb (void *cls,
                  struct GNUNET_TESTBED_Operation *op,
                  void *ca_result,
                  const char *emsg)
{
  struct RegexPeer *peer = cls;

  if (NULL == ca_result || NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to connect to statistics service on peer %u: %s\n",
                peer->id, emsg);

    peer->stats_handle = NULL;
    return;
  }

  peer->stats_handle = ca_result;

  if (NULL == GNUNET_STATISTICS_get (peer->stats_handle, NULL, NULL,
                                     GNUNET_TIME_UNIT_FOREVER_REL,
                                     &stats_cb,
                                     &stats_iterator, peer))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not get statistics of peer %u!\n", peer->id);
  }
}


/**
 * Task to collect all statistics from all peers, will shutdown the
 * profiler, when done.
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_collect_stats (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct RegexPeer *peer = &peers[0];

  GNUNET_assert (NULL != peer->peer_handle);

  peer->stats_op_handle =
    GNUNET_TESTBED_service_connect (NULL,
                                    peer->peer_handle,
                                    "statistics",
                                    &stats_connect_cb,
                                    peer,
                                    &stats_ca,
                                    &stats_da,
                                    peer);
}


/******************************************************************************/
/************************   REGEX FIND CONNECTIONS   **************************/
/******************************************************************************/


/**
 * Start searching for the next string in the DHT.
 *
 * @param cls Index of the next peer in the peers array.
 * @param tc TaskContext.
 */
static void
find_string (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Method called when we've found a peer that announced a regex
 * that matches our search string. Now get the statistics.
 *
 * @param cls Closure provided in GNUNET_REGEX_search.
 * @param id Peer providing a regex that matches the string.
 * @param get_path Path of the get request.
 * @param get_path_length Lenght of get_path.
 * @param put_path Path of the put request.
 * @param put_path_length Length of the put_path.
 */
static void
regex_found_handler (void *cls,
                     const struct GNUNET_PeerIdentity *id,
                     const struct GNUNET_PeerIdentity *get_path,
                     unsigned int get_path_length,
                     const struct GNUNET_PeerIdentity *put_path,
                     unsigned int put_path_length)
{
  struct RegexPeer *peer = cls;
  char output_buffer[512];
  size_t size;

  if (GNUNET_YES == peer->search_str_matched)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
                "String %s on peer %u already matched!\n",
                peer->search_str, peer->id);
    return;
  }

  peers_found++;
  parallel_searches--;

  if (GNUNET_SCHEDULER_NO_TASK != peer->timeout)
  {
    GNUNET_SCHEDULER_cancel (peer->timeout);
    peer->timeout = GNUNET_SCHEDULER_NO_TASK;
    GNUNET_SCHEDULER_add_now (&announce_next_regex, NULL);
  }

  if (NULL == id)
  {
    // FIXME not possible right now
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "String matching timed out for string %s on peer %u (%i/%i)\n",
                peer->search_str, peer->id, peers_found, num_search_strings);
    peer->search_str_matched = GNUNET_SYSERR;
  }
  else
  {
    prof_time = GNUNET_TIME_absolute_get_duration (peer->prof_start_time);

    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "String %s found on peer %u after %s (%i/%i) (%u||)\n",
                peer->search_str, peer->id,
                GNUNET_STRINGS_relative_time_to_string (prof_time, GNUNET_NO),
                peers_found, num_search_strings, parallel_searches);

    peer->search_str_matched = GNUNET_YES;

    if (NULL != data_file)
    {
      size =
        GNUNET_snprintf (output_buffer,
                         sizeof (output_buffer),
                         "%p Peer: %u\n%p Host: %s\n%p Policy file: %s\n"
                         "%p Search string: %s\n%p Search duration: %s\n\n",
                         peer, peer->id,
                         peer,
                         GNUNET_TESTBED_host_get_hostname (peer->host_handle),
                         peer, peer->policy_file,
                         peer, peer->search_str,
                         peer,
                         GNUNET_STRINGS_relative_time_to_string (prof_time,
                                                                 GNUNET_NO));

      if (size != GNUNET_DISK_file_write (data_file, output_buffer, size))
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Unable to write to file!\n");
    }
  }

  GNUNET_TESTBED_operation_done (peer->op_handle);
  peer->op_handle = NULL;

  if (peers_found == num_search_strings)
  {
    prof_time = GNUNET_TIME_absolute_get_duration (prof_start_time);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "All strings successfully matched in %s\n",
                GNUNET_STRINGS_relative_time_to_string (prof_time, GNUNET_NO));

    if (GNUNET_SCHEDULER_NO_TASK != search_timeout_task)
      GNUNET_SCHEDULER_cancel (search_timeout_task);

    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Collecting stats and shutting down.\n");
    GNUNET_SCHEDULER_add_now (&do_collect_stats, NULL);
  }
}


/**
 * Connect by string timeout task. This will cancel the profiler after the
 * specified timeout 'search_timeout'.
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
search_timeout (void *cls,
                              const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Finding matches to all strings did not succeed after %s.\n",
              GNUNET_STRINGS_relative_time_to_string (search_timeout_time,
                                                      GNUNET_NO));
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Found %i of %i strings\n", peers_found, num_search_strings);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Search timed out after %s."
              "Collecting stats and shutting down.\n", 
              GNUNET_STRINGS_relative_time_to_string (search_timeout_time,
                                                      GNUNET_NO));

  GNUNET_SCHEDULER_add_now (&do_collect_stats, NULL);
}


/**
 * Search timed out. It might still complete in the future,
 * but we should start another one.
 *
 * @param cls Index of the next peer in the peers array.
 * @param tc TaskContext.
 */
static void
find_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct RegexPeer *p = cls;

  p->timeout = GNUNET_SCHEDULER_NO_TASK;

  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Searching for string \"%s\" on peer %d timed out. Starting new search.\n",
              p->search_str,
              p->id);
  GNUNET_SCHEDULER_add_now (&announce_next_regex, NULL);
}


/**
 * Start searching for a string in the DHT.
 *
 * @param cls Index of the next peer in the peers array.
 * @param tc TaskContext.
 */
static void
find_string (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  unsigned int search_peer = (unsigned int) (long) cls;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) ||
      search_peer >= num_search_strings)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Searching for string \"%s\" on peer %d with file %s (%u||)\n",
              peers[search_peer].search_str,
              search_peer,
              peers[search_peer].policy_file,
              parallel_searches);

  peers[search_peer].op_handle =
    GNUNET_TESTBED_service_connect (NULL,
                                    peers[search_peer].peer_handle,
                                    "dht",
                                    &dht_connect_cb,
                                    &peers[search_peer],
                                    &dht_ca,
                                    &dht_da,
                                    &peers[search_peer]);
  GNUNET_assert (NULL != peers[search_peer].op_handle);
  peers[search_peer].timeout = GNUNET_SCHEDULER_add_delayed (FIND_TIMEOUT,
                                                          &find_timeout,
                                                          &peers[search_peer]);
}




/**
 * Callback called when testbed has started the daemon we asked for.
 *
 * @param cls NULL
 * @param op the operation handle
 * @param emsg NULL on success; otherwise an error description
 */
static void
daemon_started (void *cls, struct GNUNET_TESTBED_Operation *op,
                const char *emsg)
{
  struct RegexPeer *peer = (struct RegexPeer *) cls;
  unsigned long search_peer;
  unsigned int i;
  unsigned int me;

  GNUNET_TESTBED_operation_done (peer->daemon_op);
  me = peer - peers;
  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Failed to start/stop daemon at peer %u: %s\n", me, emsg);
    GNUNET_abort ();
  }

  /* Find a peer to look for a string matching the regex announced */
  search_peer = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                          num_peers);
  for (i = 0; peers[search_peer].search_str != NULL; i++)
  {
    search_peer = (search_peer + 1) % num_peers;
    if (i > num_peers)
      GNUNET_abort (); /* we ran out of peers, must be a bug */
  }
  peers[search_peer].search_str = search_strings[me];
  peers[search_peer].search_str_matched = GNUNET_NO;
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply(
                                  reannounce_period_max,
                                  2),
                                &find_string,
                                (void *) search_peer);
  if (next_search >= num_peers &&
      GNUNET_SCHEDULER_NO_TASK == search_timeout_task)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "All daemons started.\n");
    /* FIXME start GLOBAL timeout to abort experiment */
    search_timeout_task = GNUNET_SCHEDULER_add_delayed (search_timeout_time,
                                                        &search_timeout,
                                                        NULL);
  }
}


/**
 * Task to start the daemons on each peer so that the regexes are announced
 * into the DHT.
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_announce (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  unsigned int i;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Starting announce.\n");

  for (i = 0; i < SEARCHES_IN_PARALLEL; i++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "  scheduling announce %u\n",
                i);
    (void) GNUNET_SCHEDULER_add_now (&announce_next_regex, NULL);
  }
}


/**
 * Start announcing the next regex in the DHT.
 *
 * @param cls Closure (unused).
 * @param tc TaskContext.
 */
static void
announce_next_regex (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct RegexPeer *peer;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) ||
            next_search >= num_peers)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Starting daemon %u\n", next_search);
  peer = &peers[next_search];
  peer->daemon_op = 
  GNUNET_TESTBED_peer_manage_service (NULL,
                                      peer->peer_handle,
                                      "regexprofiler",
                                      &daemon_started,
                                      peer,
                                      1);
  next_search++;
  parallel_searches++;
}

/**
 * DHT connect callback. Called when we are connected to the dht service for
 * the peer in 'cls'. If successfull we connect to the stats service of this
 * peer and then try to match the search string of this peer.
 *
 * @param cls internal peer id.
 * @param op operation handle.
 * @param ca_result connect adapter result.
 * @param emsg error message.
 */
static void
dht_connect_cb (void *cls, struct GNUNET_TESTBED_Operation *op,
                void *ca_result, const char *emsg)
{
  struct RegexPeer *peer = (struct RegexPeer *) cls;

  if (NULL != emsg || NULL == op || NULL == ca_result)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "DHT connect failed: %s\n", emsg);
    GNUNET_abort ();
  }

  GNUNET_assert (NULL != peer->dht_handle);
  GNUNET_assert (peer->op_handle == op);
  GNUNET_assert (peer->dht_handle == ca_result);

  peer->search_str_matched = GNUNET_NO;
  peer->search_handle = GNUNET_REGEX_search (peer->dht_handle,
                                             peer->search_str,
                                             &regex_found_handler, peer,
                                             NULL);
  peer->prof_start_time = GNUNET_TIME_absolute_get ();
}


/**
 * DHT connect adapter. Opens a connection to the dht service.
 *
 * @param cls Closure (peer).
 * @param cfg Configuration handle.
 *
 * @return
 */
static void *
dht_ca (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct RegexPeer *peer = cls;

  peer->dht_handle = GNUNET_DHT_connect (cfg, 32);

  return peer->dht_handle;
}


/**
 * Adapter function called to destroy a connection to the dht service.
 *
 * @param cls Closure (peer).
 * @param op_result Service handle returned from the connect adapter.
 */
static void
dht_da (void *cls, void *op_result)
{
  struct RegexPeer *peer = (struct RegexPeer *) cls;

  GNUNET_assert (peer->dht_handle == op_result);

  if (NULL != peer->search_handle)
  {
    GNUNET_REGEX_search_cancel (peer->search_handle);
    peer->search_handle = NULL;
  }

  if (NULL != peer->dht_handle)
  {
    GNUNET_DHT_disconnect (peer->dht_handle);
    peer->dht_handle = NULL;
  }
}


/**
 * Signature of a main function for a testcase.
 *
 * @param cls NULL
 * @param num_peers_ number of peers in 'peers'
 * @param peers handle to peers run in the testbed.  NULL upon timeout (see
 *          GNUNET_TESTBED_test_run()).
 * @param links_succeeded the number of overlay link connection attempts that
 *          succeeded
 * @param links_failed the number of overlay link connection attempts that
 *          failed
 */
static void 
test_master (void *cls,
             unsigned int num_peers_,
             struct GNUNET_TESTBED_Peer **testbed_peers,
             unsigned int links_succeeded,
             unsigned int links_failed)
{
  unsigned int i;

  for (i = 0; i < num_peers; i++) 
  GNUNET_SCHEDULER_add_now (&do_announce, NULL);
}


/******************************************************************************/
/***************************  TESTBED PEER SETUP  *****************************/
/******************************************************************************/


/**
 * Load search strings from given filename. One search string per line.
 *
 * @param filename filename of the file containing the search strings.
 * @param strings set of strings loaded from file. Caller needs to free this
 *                if number returned is greater than zero.
 * @param limit upper limit on the number of strings read from the file
 * @return number of strings found in the file. GNUNET_SYSERR on error.
 */
static int
load_search_strings (const char *filename, char ***strings, unsigned int limit)
{
  char *data;
  char *buf;
  uint64_t filesize;
  unsigned int offset;
  int str_cnt;
  unsigned int i;

  if (NULL == filename)
  {
    return GNUNET_SYSERR;
  }

  if (GNUNET_YES != GNUNET_DISK_file_test (filename))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Could not find search strings file %s\n", filename);
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK != GNUNET_DISK_file_size (filename, &filesize, GNUNET_YES, GNUNET_YES))
    filesize = 0;
  if (0 == filesize)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Search strings file %s is empty.\n", filename);
    return GNUNET_SYSERR;
  }
  data = GNUNET_malloc (filesize);
  if (filesize != GNUNET_DISK_fn_read (filename, data, filesize))
  {
    GNUNET_free (data);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Could not read search strings file %s.\n",
         filename);
    return GNUNET_SYSERR;
  }
  buf = data;
  offset = 0;
  str_cnt = 0;
  while (offset < (filesize - 1) && str_cnt < limit)
  {
    offset++;
    if (((data[offset] == '\n')) && (buf != &data[offset]))
    {
      data[offset] = '\0';
      str_cnt++;
      buf = &data[offset + 1];
    }
    else if ((data[offset] == '\n') || (data[offset] == '\0'))
      buf = &data[offset + 1];
  }
  *strings = GNUNET_malloc (sizeof (char *) * str_cnt);
  offset = 0;
  for (i = 0; i < str_cnt; i++)
  {
    GNUNET_asprintf (&(*strings)[i], "%s%s", regex_prefix, &data[offset]);
    offset += strlen (&data[offset]) + 1;
  }
  GNUNET_free (data);
  return str_cnt;
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
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *config)
{
  unsigned int nsearchstrs;
  unsigned int i;
  char *hosts_file;
  char *strings_file;

  if (NULL == config)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("No configuration file given. Exiting\n"));
    shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (config, "REGEXPROFILER",
                                             "REGEX_PREFIX",
                                             &regex_prefix))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Configuration option \"regex_prefix\" missing. Exiting\n"));
    shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }

  hosts_file = args[0];
  if (NULL == hosts_file)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("No hosts-file specified on command line. Exiting.\n"));
    return;
  }
  policy_dir = args[1];
  if (NULL == policy_dir)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("No policy directory specified on command line. Exiting.\n"));
    return;
  }


  if ( (NULL != data_filename) &&
       (NULL == (data_file =
                 GNUNET_DISK_file_open (data_filename,
                                        GNUNET_DISK_OPEN_READWRITE |
                                        GNUNET_DISK_OPEN_TRUNCATE |
                                        GNUNET_DISK_OPEN_CREATE,
                                        GNUNET_DISK_PERM_USER_READ |
                                        GNUNET_DISK_PERM_USER_WRITE))) )
  {
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
                              "open",
                              data_filename);
  }
  if (GNUNET_YES != GNUNET_DISK_directory_test (policy_dir, GNUNET_YES))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Specified policies directory does not exist. Exiting.\n"));
    shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }
  strings_file = args[2];
  if (GNUNET_YES != GNUNET_DISK_file_test (strings_file))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("No search strings file given. Exiting.\n"));
    shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }
  nsearchstrs = load_search_strings (strings_file,
                                     &search_strings,
                                     num_search_strings);
  if (num_search_strings != nsearchstrs)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Error loading search strings."
                  "Given file does not contain enough strings. Exiting.\n"));
    shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }
  if (0 >= num_search_strings || NULL == search_strings)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Error loading search strings. Exiting.\n"));
    shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }
  cfg = GNUNET_CONFIGURATION_dup (config);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (cfg, "REGEXPROFILER",
                                           "REANNOUNCE_PERIOD_MAX",
                                           &reannounce_period_max))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
                "reannounce_period_max not given. Using 10 minutes.\n");
    reannounce_period_max =
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 10);
  }
  for (i = 0; i < num_search_strings; i++)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "search string: %s\n",
                search_strings[i]);
  event_mask = 0LL;
/*  event_mask |= (1LL << GNUNET_TESTBED_ET_PEER_START);
  event_mask |= (1LL << GNUNET_TESTBED_ET_PEER_STOP);
  event_mask |= (1LL << GNUNET_TESTBED_ET_CONNECT);
  event_mask |= (1LL << GNUNET_TESTBED_ET_DISCONNECT);*/
  GNUNET_TESTBED_run (args[0],
                      cfg,
                      num_peers,
                      event_mask,
                      NULL,     /* master_controller_cb, */
                      NULL,     /* master_controller_cb cls */
                      &test_master,
                      NULL);    /* test_master cls */
  abort_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_SECONDS, 5),
                                    &do_abort,
                                    (void*) __LINE__);
}


/**
 * Main function.
 *
 * @param argc argument count
 * @param argv argument values
 * @return 0 on success
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'d', "details", "FILENAME",
     gettext_noop ("name of the file for writing statistics"),
     1, &GNUNET_GETOPT_set_string, &data_filename},
    {'n', "num-links", "COUNT",
      gettext_noop ("create COUNT number of random links between peers"),
      GNUNET_YES, &GNUNET_GETOPT_set_uint, &linking_factor },
    {'t', "matching-timeout", "TIMEOUT",
      gettext_noop ("wait TIMEOUT before considering a string match as failed"),
      GNUNET_YES, &GNUNET_GETOPT_set_relative_time, &search_timeout_time
        },
    {'s', "search-delay", "DELAY",
      gettext_noop ("wait DELAY before starting string search"),
      GNUNET_YES, &GNUNET_GETOPT_set_relative_time, &search_delay },
    {'a', "num-search-strings", "COUNT",
      gettext_noop ("number of search strings to read from search strings file"),
      GNUNET_YES, &GNUNET_GETOPT_set_uint, &num_search_strings },
    {'p', "max-path-compression", "MAX_PATH_COMPRESSION",
     gettext_noop ("maximum path compression length"),
     1, &GNUNET_GETOPT_set_uint, &max_path_compression},
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  result = GNUNET_SYSERR;
  ret =
      GNUNET_PROGRAM_run (argc, argv,
                          "gnunet-regex-profiler [OPTIONS] hosts-file policy-dir search-strings-file",
                          _("Profiler for regex"),
                          options, &run, NULL);

  if (GNUNET_OK != ret)
    return ret;
  if (GNUNET_OK != result)
    return 1;
  return 0;
}
