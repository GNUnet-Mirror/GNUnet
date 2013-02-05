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
#include "gnunet_dht_service.h"
#include "gnunet_testbed_service.h"

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
   * Peers search string.
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
   * Peer's dht handle.
   */
  struct GNUNET_DHT_Handle *dht_handle;

  /**
   * Handle to a running regex search.
   */
   struct GNUNET_REGEX_search_handle *search_handle;

  /**
   * Testbed operation handle for the dht service.
   */
  struct GNUNET_TESTBED_Operation *dht_op_handle;

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
};


/**
 * An array of hosts loaded from the hostkeys file
 */
static struct GNUNET_TESTBED_Host **hosts;

/**
 * Array of peer handles used to pass to
 * GNUNET_TESTBED_overlay_configure_topology
 */
static struct GNUNET_TESTBED_Peer **peer_handles;

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
 * Head of the operations list
 */
static struct DLLOperation *dll_op_head;

/**
 * Tail of the operations list
 */
static struct DLLOperation *dll_op_tail;

/**
 * Peer linking - topology operation
 */
static struct GNUNET_TESTBED_Operation *topology_op;

/**
 * The handle for whether a host is habitable or not
 */
struct GNUNET_TESTBED_HostHabitableCheckHandle **hc_handles;

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
 * Number of hosts in the hosts array
 */
static unsigned int num_hosts;

/**
 * Factor of number of links. num_links = num_peers * linking_factor.
 */
static unsigned int linking_factor;

/**
 * Number of random links to be established between peers
 */
static unsigned int num_links;

/**
 * Number of times we try overlay connect operations
 */
static unsigned int retry_links;

/**
 * Continuous failures during overlay connect operations
 */
static unsigned int cont_fails;

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
 * Number of peers found with search strings.
 */
static unsigned int peers_found;

/**
 * Search task identifier
 */
static GNUNET_SCHEDULER_TaskIdentifier search_task;

/**
 * Search timeout task identifier.
 */
static GNUNET_SCHEDULER_TaskIdentifier search_timeout_task;

/**
 * Search timeout in seconds.
 */
static struct GNUNET_TIME_Relative search_timeout = { 60000 };

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
 * If we should distribute the search evenly throught all peers (each
 * peer searches for a string) or if only one peer should search for
 * all strings.
 */
static int no_distributed_search;

/**
 * Prefix used for regex announcing. We need to prefix the search
 * strings with it, in order to find something.
 */
static char * regex_prefix;


/******************************************************************************/
/******************************  DECLARATIONS  ********************************/
/******************************************************************************/


/**
 * Search callback function.
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
                     unsigned int put_path_length);


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
 * Task to collect all statistics from all peers, will shutdown the
 * profiler, when done.
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_collect_stats (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


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
  struct DLLOperation *dll_op;
  struct RegexPeer *peer;
  unsigned int nhost;
  unsigned int peer_cnt;
  unsigned int search_str_cnt;
  char output_buffer[512];
  size_t size;

  shutdown_task = GNUNET_SCHEDULER_NO_TASK;
  if (GNUNET_SCHEDULER_NO_TASK != abort_task)
    GNUNET_SCHEDULER_cancel (abort_task);
  if (NULL != hc_handles)
  {
    for (nhost = 0; nhost < num_hosts; nhost++)
      if (NULL != hc_handles[nhost])
        GNUNET_TESTBED_is_host_habitable_cancel (hc_handles[nhost]);
    GNUNET_free (hc_handles);
    hc_handles = NULL;
  }
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

    if (NULL != peers[peer_cnt].dht_op_handle)
      GNUNET_TESTBED_operation_done (peers[peer_cnt].dht_op_handle);
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
  if (NULL != topology_op)
    GNUNET_TESTBED_operation_done (topology_op);
  for (nhost = 0; nhost < num_hosts; nhost++)
    if (NULL != hosts[nhost])
      GNUNET_TESTBED_host_destroy (hosts[nhost]);
  GNUNET_free_non_null (hosts);

  while (NULL != (dll_op = dll_op_head))
  {
    GNUNET_TESTBED_operation_done (dll_op->op);
    GNUNET_CONTAINER_DLL_remove (dll_op_head, dll_op_tail, dll_op);
    GNUNET_free (dll_op);
  }
  if (NULL != mc)
    GNUNET_TESTBED_controller_disconnect (mc);
  if (NULL != mc_proc)
    GNUNET_TESTBED_controller_stop (mc_proc);
  if (NULL != cfg)
    GNUNET_CONFIGURATION_destroy (cfg);

  GNUNET_SCHEDULER_shutdown ();	/* Stop scheduler to shutdown testbed run */
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
/************************  MESH SERVICE CONNECTIONS  **************************/
/******************************************************************************/

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

  if (NULL == id)
  {
    // FIXME not possible right now
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "String matching timed out for string %s on peer %u (%i/%i)\n",
                peer->search_str, peer->id, peers_found, num_search_strings);

    printf ("String matching timed out for string %s on peer %u (%i/%i)\n",
            peer->search_str, peer->id, peers_found, num_search_strings);

    peer->search_str_matched = GNUNET_SYSERR;
  }
  else
  {
    prof_time = GNUNET_TIME_absolute_get_duration (peer->prof_start_time);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "String %s successfully matched on peer %u after %s (%i/%i)\n",
                peer->search_str, peer->id, GNUNET_STRINGS_relative_time_to_string (prof_time, GNUNET_NO),
                peers_found, num_search_strings);

    printf ("String %s successfully matched on peer %u after %s (%i/%i)\n",
            peer->search_str, peer->id, GNUNET_STRINGS_relative_time_to_string (prof_time, GNUNET_NO),
            peers_found, num_search_strings);
    fflush (stdout);

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

  GNUNET_TESTBED_operation_done (peer->dht_op_handle);
  peer->dht_op_handle = NULL;

  if (peers_found == num_search_strings)
  {
    prof_time = GNUNET_TIME_absolute_get_duration (prof_start_time);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "All strings successfully matched in %s\n",
                GNUNET_STRINGS_relative_time_to_string (prof_time, GNUNET_NO));
    printf ("All strings successfully matched.\n");
    fflush (stdout);

    if (GNUNET_SCHEDULER_NO_TASK != search_timeout_task)
      GNUNET_SCHEDULER_cancel (search_timeout_task);

    printf ("Collecting stats and shutting down.\n");
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
do_connect_by_string_timeout (void *cls,
                              const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Finding matches to all strings did not succeed after %s.\n",
              GNUNET_STRINGS_relative_time_to_string (search_timeout, GNUNET_NO));
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Found %i of %i strings\n", peers_found, num_search_strings);

  printf ("Search timed out after %s. Collecting stats and shutting down.\n", 
	  GNUNET_STRINGS_relative_time_to_string (search_timeout, GNUNET_NO));
  fflush (stdout);

  GNUNET_SCHEDULER_add_now (&do_collect_stats, NULL);
}


/**
 * Connect by string task that is run to search for a string in the
 * NFA. It first connects to the mesh service and when a connection is
 * established it starts to search for the string.
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_connect_by_string (void *cls,
                      const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  printf ("Starting string search.\n");
  fflush (stdout);

  peers[0].search_str = search_strings[0];
  peers[0].search_str_matched = GNUNET_NO;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      "Searching for string \"%s\" on peer %d with file %s\n",
	      peers[0].search_str, 0, peers[0].policy_file);

    /* First connect to mesh service, then search for string. Next
       connect will be in mesh_connect_cb */
    peers[0].dht_op_handle =
      GNUNET_TESTBED_service_connect (NULL,
                                      peers[0].peer_handle,
                                      "dht",
                                      &dht_connect_cb,
                                      &peers[0],
                                      &dht_ca,
                                      &dht_da,
                                      &peers[0]);

  search_timeout_task = GNUNET_SCHEDULER_add_delayed (search_timeout,
                                                      &do_connect_by_string_timeout, NULL);
}

/**
 * Start searching for the next string in the DHT.
 *
 * @param cls Index of the next peer in the peers array.
 * @param tc TaskContext.
 */
void
find_next_string (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  long next_p = (long) cls;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Searching for string \"%s\" on peer %d with file %s\n",
              peers[next_p].search_str, next_p, peers[next_p].policy_file);

  /* FIXME
    * dont connect to a new dht for each peer, we might want to seach for n
    * strings on m peers where n > m
    */
  peers[next_p].dht_op_handle =
    GNUNET_TESTBED_service_connect (NULL,
                                    peers[next_p].peer_handle,
                                    "dht",
                                    &dht_connect_cb,
                                    &peers[next_p],
                                    &dht_ca,
                                    &dht_da,
                                    &peers[next_p]);
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
  static unsigned int peer_cnt;
  unsigned int next_p;

  if (NULL != emsg || NULL == op || NULL == ca_result)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "DHT connect failed: %s\n", emsg);
    GNUNET_abort ();
  }

  GNUNET_assert (NULL != peer->dht_handle);
  GNUNET_assert (peer->dht_op_handle == op);
  GNUNET_assert (peer->dht_handle == ca_result);

  peer->search_str_matched = GNUNET_NO;
  peer->search_handle = GNUNET_REGEX_search (peer->dht_handle,
                                             peer->search_str,
                                             &regex_found_handler, peer,
                                             NULL);
  peer->prof_start_time = GNUNET_TIME_absolute_get ();

  if (peer_cnt < (num_search_strings - 1))
  {
    if (GNUNET_YES == no_distributed_search)
      next_p = 0;
    else
      next_p = (++peer_cnt % num_peers);

    peers[next_p].search_str = search_strings[next_p];
    peers[next_p].search_str_matched = GNUNET_NO;

    /* Don't start all searches at once */
    /* TODO add some intelligence to the timeout */
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                  &find_next_string,
                                  (void *) (long) next_p);
  }
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


/******************************************************************************/
/***************************  TESTBED PEER SETUP  *****************************/
/******************************************************************************/


/**
 * Configure the peer overlay topology.
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_configure_topology (void *cls,
                       const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  /*
    if (0 == linking_factor)
    linking_factor = 1;
    num_links = linking_factor * num_peers;
  */
  /* num_links = num_peers - 1; */
  num_links = linking_factor;

  /* Do overlay connect */
  prof_start_time = GNUNET_TIME_absolute_get ();
  topology_op =
    GNUNET_TESTBED_overlay_configure_topology (NULL, num_peers, peer_handles,
                                               NULL,
                                               NULL,
                                               NULL,
                                               GNUNET_TESTBED_TOPOLOGY_ERDOS_RENYI,
                                               num_links,
                                               GNUNET_TESTBED_TOPOLOGY_RETRY_CNT,
                                               (unsigned int) 0,
                                               GNUNET_TESTBED_TOPOLOGY_OPTION_END);
  if (NULL == topology_op)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Cannot create topology, op handle was NULL\n");
    GNUNET_assert (0);
  }
}


/**
 * Functions of this signature are called when a peer has been successfully
 * started or stopped.
 *
 * @param cls the closure from GNUNET_TESTBED_peer_start/stop()
 * @param emsg NULL on success; otherwise an error description
 */
static void
peer_churn_cb (void *cls, const char *emsg)
{
  struct DLLOperation *dll_op = cls;
  struct GNUNET_TESTBED_Operation *op;
  static unsigned int started_peers;
  unsigned int peer_cnt;

  op = dll_op->op;
  GNUNET_CONTAINER_DLL_remove (dll_op_head, dll_op_tail, dll_op);
  GNUNET_free (dll_op);
  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
         _("An operation has failed while starting peers\n"));
    GNUNET_TESTBED_operation_done (op);
    if (GNUNET_SCHEDULER_NO_TASK != abort_task)
      GNUNET_SCHEDULER_cancel (abort_task);
    abort_task = GNUNET_SCHEDULER_add_now (&do_abort, (void*) __LINE__);
    return;
  }
  GNUNET_TESTBED_operation_done (op);
  if (++started_peers == num_peers)
  {
    prof_time = GNUNET_TIME_absolute_get_duration (prof_start_time);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "All peers started successfully in %s\n",
                GNUNET_STRINGS_relative_time_to_string (prof_time, GNUNET_NO));
    result = GNUNET_OK;

    peer_handles = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_Peer *) * num_peers);
    for (peer_cnt = 0; peer_cnt < num_peers; peer_cnt++)
      peer_handles[peer_cnt] = peers[peer_cnt].peer_handle;

    state = STATE_PEERS_LINKING;
    GNUNET_SCHEDULER_add_now (&do_configure_topology, NULL);
  }
}


/**
 * Functions of this signature are called when a peer has been successfully
 * created
 *
 * @param cls the closure from GNUNET_TESTBED_peer_create()
 * @param peer the handle for the created peer; NULL on any error during
 *          creation
 * @param emsg NULL if peer is not NULL; else MAY contain the error description
 */
static void
peer_create_cb (void *cls, struct GNUNET_TESTBED_Peer *peer, const char *emsg)
{
  struct DLLOperation *dll_op = cls;
  struct RegexPeer *peer_ptr;
  static unsigned int created_peers;
  unsigned int peer_cnt;

  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
         _("Creating a peer failed. Error: %s\n"), emsg);
    GNUNET_TESTBED_operation_done (dll_op->op);
    GNUNET_CONTAINER_DLL_remove (dll_op_head, dll_op_tail, dll_op);
    GNUNET_free (dll_op);
    if (GNUNET_SCHEDULER_NO_TASK != abort_task)
      GNUNET_SCHEDULER_cancel (abort_task);
    abort_task = GNUNET_SCHEDULER_add_now (&do_abort, (void*) __LINE__);
    return;
  }

  peer_ptr = dll_op->cls;
  GNUNET_assert (NULL == peer_ptr->peer_handle);
  GNUNET_CONFIGURATION_destroy (peer_ptr->cfg);
  peer_ptr->cfg = NULL;
  peer_ptr->peer_handle = peer;
  GNUNET_TESTBED_operation_done (dll_op->op);
  GNUNET_CONTAINER_DLL_remove (dll_op_head, dll_op_tail, dll_op);
  GNUNET_free (dll_op);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer %i created on host %s\n",
              peer_ptr->id,
              GNUNET_TESTBED_host_get_hostname (peer_ptr->host_handle));

  if (++created_peers == num_peers)
  {
    prof_time = GNUNET_TIME_absolute_get_duration (prof_start_time);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "All peers created successfully in %s\n",
                GNUNET_STRINGS_relative_time_to_string (prof_time, GNUNET_NO));
    /* Now peers are to be started */
    state = STATE_PEERS_STARTING;
    prof_start_time = GNUNET_TIME_absolute_get ();
    for (peer_cnt = 0; peer_cnt < num_peers; peer_cnt++)
    {
      dll_op = GNUNET_malloc (sizeof (struct DLLOperation));
      dll_op->op = GNUNET_TESTBED_peer_start (dll_op, peers[peer_cnt].peer_handle,
                                              &peer_churn_cb, dll_op);
      GNUNET_CONTAINER_DLL_insert_tail (dll_op_head, dll_op_tail, dll_op);
    }
  }
}


/**
 * Function called with a filename for each file in the policy directory. Create
 * a peer for each filename and update the peer's configuration to include the
 * max_path_compression specified as a command line argument as well as the
 * policy_file for this peer. The gnunet-service-regexprofiler service is
 * automatically started on this peer. The service reads the configurration and
 * announces the regexes stored in the policy file 'filename'.
 *
 * @param cls closure
 * @param filename complete filename (absolute path)
 * @return GNUNET_OK to continue to iterate,
 *  GNUNET_SYSERR to abort iteration with error!
 */
static int
policy_filename_cb (void *cls, const char *filename)
{
  static unsigned int peer_cnt;
  struct DLLOperation *dll_op;
  struct RegexPeer *peer = &peers[peer_cnt];

  GNUNET_assert (NULL != peer);

  peer->policy_file = GNUNET_strdup (filename);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Creating peer %i on host %s for policy file %s\n",
              peer->id,
              GNUNET_TESTBED_host_get_hostname (peer->host_handle),
              filename);

  /* Set configuration options specific for this peer
     (max_path_compression and policy_file */
  peer->cfg = GNUNET_CONFIGURATION_dup (cfg);
  GNUNET_CONFIGURATION_set_value_number (peer->cfg, "REGEXPROFILER",
                                         "MAX_PATH_COMPRESSION",
                                         (unsigned long long)max_path_compression);
  GNUNET_CONFIGURATION_set_value_string (peer->cfg, "REGEXPROFILER",
                                         "POLICY_FILE", filename);

  dll_op = GNUNET_malloc (sizeof (struct DLLOperation));
  dll_op->cls = &peers[peer_cnt];
  dll_op->op = GNUNET_TESTBED_peer_create (mc,
                                           peer->host_handle,
                                           peer->cfg,
                                           &peer_create_cb,
                                           dll_op);
  GNUNET_CONTAINER_DLL_insert_tail (dll_op_head, dll_op_tail, dll_op);

  peer_cnt++;

  return GNUNET_OK;
}


/**
 * Controller event callback.
 *
 * @param cls NULL
 * @param event the controller event
 */
static void
controller_event_cb (void *cls,
                     const struct GNUNET_TESTBED_EventInformation *event)
{
  struct DLLOperation *dll_op;
  struct GNUNET_TESTBED_Operation *op;
  int ret;

  switch (state)
  {
  case STATE_SLAVES_STARTING:
    switch (event->type)
    {
    case GNUNET_TESTBED_ET_OPERATION_FINISHED:
      {
        static unsigned int slaves_started;
        unsigned int peer_cnt;

        dll_op = event->details.operation_finished.op_cls;
        GNUNET_CONTAINER_DLL_remove (dll_op_head, dll_op_tail, dll_op);
        GNUNET_free (dll_op);
        op = event->details.operation_finished.operation;
        if (NULL != event->details.operation_finished.emsg)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
               _("An operation has failed while starting slaves\n"));
          GNUNET_TESTBED_operation_done (op);
          if (GNUNET_SCHEDULER_NO_TASK != abort_task)
            GNUNET_SCHEDULER_cancel (abort_task);
          abort_task = GNUNET_SCHEDULER_add_now (&do_abort, (void*) __LINE__);
          return;
        }
        GNUNET_TESTBED_operation_done (op);
        /* Proceed to start peers */
        if (++slaves_started == num_hosts - 1)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                      "All slaves started successfully\n");

          state = STATE_PEERS_CREATING;
          prof_start_time = GNUNET_TIME_absolute_get ();

          if (-1 == (ret = GNUNET_DISK_directory_scan (policy_dir,
                                                       NULL,
                                                       NULL)))
          {
            GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                        _("No files found in `%s'\n"),
                        policy_dir);
            GNUNET_SCHEDULER_shutdown ();
            return;
          }
          num_peers = (unsigned int) ret;
          peers = GNUNET_malloc (sizeof (struct RegexPeer) * num_peers);

          /* Initialize peers */
          for (peer_cnt = 0; peer_cnt < num_peers; peer_cnt++)
          {
            struct RegexPeer *peer = &peers[peer_cnt];
            peer->id = peer_cnt;
            peer->policy_file = NULL;
            /* Do not start peers on hosts[0] (master controller) */
            peer->host_handle = hosts[1 + (peer_cnt % (num_hosts -1))];
            peer->dht_handle = NULL;
            peer->search_handle = NULL;
            peer->stats_handle = NULL;
            peer->stats_op_handle = NULL;
            peer->search_str = NULL;
            peer->search_str_matched = GNUNET_NO;
          }

          GNUNET_DISK_directory_scan (policy_dir,
                                      &policy_filename_cb,
                                      NULL);
        }
      }
      break;
    default:
      GNUNET_assert (0);
    }
    break;
  case STATE_PEERS_STARTING:
    switch (event->type)
    {
    case GNUNET_TESTBED_ET_OPERATION_FINISHED:
      /* Control reaches here when peer start fails */
    case GNUNET_TESTBED_ET_PEER_START:
      /* we handle peer starts in peer_churn_cb */
      break;
    default:
      GNUNET_assert (0);
    }
    break;
  case STATE_PEERS_LINKING:
   switch (event->type)
   {
     static unsigned int established_links;
   case GNUNET_TESTBED_ET_OPERATION_FINISHED:
     /* Control reaches here when a peer linking operation fails */
     if (NULL != event->details.operation_finished.emsg)
     {
       GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                   _("An operation has failed while linking\n"));
       printf ("F");
       fflush (stdout);
       retry_links++;
     }
     /* We do no retries, consider this link as established */
     /* break; */
   case GNUNET_TESTBED_ET_CONNECT:
   {
     char output_buffer[512];
     size_t size;

     if (0 == established_links)
       printf ("Establishing links .");
     else
     {
       printf (".");
       fflush (stdout);
     }
     if (++established_links == num_links)
     {
       fflush (stdout);
       prof_time = GNUNET_TIME_absolute_get_duration (prof_start_time);
       GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                   "%u links established in %s\n",
                   num_links,
                   GNUNET_STRINGS_relative_time_to_string (prof_time, GNUNET_NO));
       result = GNUNET_OK;
       GNUNET_free (peer_handles);

       if (NULL != data_file)
       {
         size =
           GNUNET_snprintf (output_buffer,
                            sizeof (output_buffer),
                            "# of peers: %u\n# of links established: %u\n"
                            "Time to establish links: %s\nLinking failures: %u\n"
                            "path compression length: %u\n# of search strings: %u\n",
                            num_peers,
                            (established_links - cont_fails),
                            GNUNET_STRINGS_relative_time_to_string (prof_time, GNUNET_NO),
                            cont_fails,
                            max_path_compression,
                            num_search_strings);

         if (size != GNUNET_DISK_file_write (data_file, output_buffer, size))
           GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Unable to write to file!\n");
       }

       printf ("\nWaiting %s before starting to search.\n",
               GNUNET_STRINGS_relative_time_to_string (search_delay, GNUNET_YES));
       fflush (stdout);

       GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                   "Waiting %s before starting to search.\n",
                   GNUNET_STRINGS_relative_time_to_string (search_delay, GNUNET_NO));

       state = STATE_SEARCH_REGEX;

       search_task = GNUNET_SCHEDULER_add_delayed (search_delay,
                                                   &do_connect_by_string, NULL);
     }
   }
   break;
   default:
     GNUNET_assert (0);
   }
   break;
  case STATE_SEARCH_REGEX:
  {
    /* Handled in service connect callback */
    break;
  }
  default:
    switch (state)
    {
    case STATE_PEERS_CREATING:
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Failed to create peer\n");
      break;
    default:
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Unexpected controller_cb with state %i!\n", state);
    }
    GNUNET_assert (0);
  }
}


/**
 * Task to register all hosts available in the global host list.
 *
 * @param cls NULL
 * @param tc the scheduler task context
 */
static void
register_hosts (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Callback which will be called to after a host registration succeeded or failed
 *
 * @param cls the closure
 * @param emsg the error message; NULL if host registration is successful
 */
static void
host_registration_completion (void *cls, const char *emsg)
{
  reg_handle = NULL;
  if (NULL != emsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Host registration failed for a host. Error: %s\n"), emsg);
    if (GNUNET_SCHEDULER_NO_TASK != abort_task)
      GNUNET_SCHEDULER_cancel (abort_task);
    abort_task = GNUNET_SCHEDULER_add_now (&do_abort, (void*) __LINE__);
    return;
  }
  register_hosts_task = GNUNET_SCHEDULER_add_now (&register_hosts, NULL);
}


/**
 * Task to register all hosts available in the global host list.
 *
 * @param cls NULL
 * @param tc the scheduler task context
 */
static void
register_hosts (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct DLLOperation *dll_op;
  static unsigned int reg_host;
  unsigned int slave;

  register_hosts_task = GNUNET_SCHEDULER_NO_TASK;
  if (reg_host == num_hosts - 1)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "All hosts successfully registered\n");
    /* Start slaves */
    state = STATE_SLAVES_STARTING;
    for (slave = 1; slave < num_hosts; slave++)
    {
      dll_op = GNUNET_malloc (sizeof (struct DLLOperation));
      dll_op->op = GNUNET_TESTBED_controller_link (dll_op,
                                                   mc,
                                                   hosts[slave],
                                                   hosts[0],
                                                   cfg,
                                                   GNUNET_YES);
      GNUNET_CONTAINER_DLL_insert_tail (dll_op_head, dll_op_tail, dll_op);
    }
    return;
  }
  reg_handle = GNUNET_TESTBED_register_host (mc, hosts[++reg_host],
                                             host_registration_completion,
                                             NULL);
}


/**
 * Callback to signal successfull startup of the controller process.
 *
 * @param cls the closure from GNUNET_TESTBED_controller_start()
 * @param config the configuration with which the controller has been started;
 *          NULL if status is not GNUNET_OK
 * @param status GNUNET_OK if the startup is successfull; GNUNET_SYSERR if not,
 *          GNUNET_TESTBED_controller_stop() shouldn't be called in this case
 */
static void
status_cb (void *cls, const struct GNUNET_CONFIGURATION_Handle *config, int status)
{
  if (GNUNET_SCHEDULER_NO_TASK != abort_task)
    GNUNET_SCHEDULER_cancel (abort_task);
  if (GNUNET_OK != status)
  {
    mc_proc = NULL;
    printf("CRAPPP\n");
    abort_task = GNUNET_SCHEDULER_add_now (&do_abort, (void*) __LINE__);
    return;
  }
  event_mask = 0;
  event_mask |= (1LL << GNUNET_TESTBED_ET_PEER_START);
  event_mask |= (1LL << GNUNET_TESTBED_ET_PEER_STOP);
  event_mask |= (1LL << GNUNET_TESTBED_ET_CONNECT);
  event_mask |= (1LL << GNUNET_TESTBED_ET_DISCONNECT);
  event_mask |= (1LL << GNUNET_TESTBED_ET_OPERATION_FINISHED);
  mc = GNUNET_TESTBED_controller_connect (config, hosts[0], event_mask,
                                          &controller_event_cb, NULL);
  if (NULL == mc)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Unable to connect to master controller -- Check config\n"));
    abort_task = GNUNET_SCHEDULER_add_now (&do_abort, (void*) __LINE__);
    return;
  }
  register_hosts_task = GNUNET_SCHEDULER_add_now (&register_hosts, NULL);
  abort_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                             &do_abort, (void*) __LINE__);
}


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
 * Callbacks of this type are called by GNUNET_TESTBED_is_host_habitable to
 * inform whether the given host is habitable or not. The Handle returned by
 * GNUNET_TESTBED_is_host_habitable() is invalid after this callback is called
 *
 * @param cls NULL
 * @param host the host whose status is being reported; will be NULL if the host
 *          given to GNUNET_TESTBED_is_host_habitable() is NULL
 * @param status GNUNET_YES if it is habitable; GNUNET_NO if not
 */
static void 
host_habitable_cb (void *cls, const struct GNUNET_TESTBED_Host *host, int status)
{
  struct GNUNET_TESTBED_HostHabitableCheckHandle **hc_handle = cls;
  static unsigned int hosts_checked;

  *hc_handle = NULL;
  if (GNUNET_NO == status)
  {
    if ((NULL != host) && (NULL != GNUNET_TESTBED_host_get_hostname (host)))
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Host %s cannot start testbed\n"),
                  GNUNET_TESTBED_host_get_hostname (host));
    else
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Testbed cannot be started on localhost\n"));
    GNUNET_SCHEDULER_cancel (abort_task);
    abort_task = GNUNET_SCHEDULER_add_now (&do_abort, (void*) __LINE__);
    return;
  }
  hosts_checked++;
  /* printf (_("\rChecked %u hosts"), hosts_checked); */
  /* fflush (stdout); */
  if (hosts_checked < num_hosts)
    return;
  /* printf (_("\nAll hosts can start testbed. Creating peers\n")); */
  GNUNET_free (hc_handles);
  hc_handles = NULL;
  mc_proc = 
      GNUNET_TESTBED_controller_start (GNUNET_TESTBED_host_get_hostname
                                       (hosts[0]),
                                       hosts[0],
                                       cfg,
                                       status_cb,
                                       NULL);
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
  unsigned int nhost;
  unsigned int nsearchstrs;

  if (NULL == args[0])
  {
    fprintf (stderr, _("No hosts-file specified on command line. Exiting.\n"));
    return;
  }
  if (NULL == args[1])
  {
    fprintf (stderr, _("No policy directory specified on command line. Exiting.\n"));
    return;
  }
  num_hosts = GNUNET_TESTBED_hosts_load_from_file (args[0], &hosts);
  if (0 == num_hosts)
  {
    fprintf (stderr, _("No hosts loaded. Need at least one host\n"));
    return;
  }
  printf (_("Checking whether given hosts can start testbed. Please wait\n"));
  hc_handles = GNUNET_malloc (sizeof (struct
                                      GNUNET_TESTBED_HostHabitableCheckHandle *) 
                              * num_hosts);
  for (nhost = 0; nhost < num_hosts; nhost++)
  {    
    if (NULL == (hc_handles[nhost] = GNUNET_TESTBED_is_host_habitable (hosts[nhost], config,
                                                                       &host_habitable_cb,
                                                                       &hc_handles[nhost])))
    {
      GNUNET_break (0);
      for (nhost = 0; nhost < num_hosts; nhost++)
        if (NULL != hc_handles[nhost])
          GNUNET_TESTBED_is_host_habitable_cancel (hc_handles[nhost]);
      GNUNET_free (hc_handles);
      hc_handles = NULL;
      break;
    }
  }
  if (num_hosts != nhost)
  {
    fprintf (stderr, _("Exiting\n"));
    shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }
  if (NULL == config)
  {
    fprintf (stderr, _("No configuration file given. Exiting\n"));
    shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (config, "REGEXPROFILER", "REGEX_PREFIX",
					     &regex_prefix))
  {
    fprintf (stderr, _("Configuration option (regex_prefix) missing. Exiting\n"));
    shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
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
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
                              "open",
                              data_filename);
  if (GNUNET_YES != GNUNET_DISK_directory_test (args[1], GNUNET_YES))
  {
    fprintf (stderr, _("Specified policies directory does not exist. Exiting.\n"));
    shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }
  policy_dir = args[1];
  if (GNUNET_YES != GNUNET_DISK_file_test (args[2]))
  {
    fprintf (stderr, _("No search strings file given. Exiting.\n"));
    shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }
  nsearchstrs = load_search_strings (args[2], &search_strings, num_search_strings);
  if (num_search_strings != nsearchstrs)
  {
    num_search_strings = nsearchstrs;
    fprintf (stderr, _("Error loading search strings. Given file does not contain enough strings. Exiting.\n"));
    shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }
  if (0 >= num_search_strings || NULL == search_strings)
  {
    fprintf (stderr, _("Error loading search strings. Exiting.\n"));
    shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }
  unsigned int i;
  for (i = 0; i < num_search_strings; i++)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "search string: %s\n", search_strings[i]);
  cfg = GNUNET_CONFIGURATION_dup (config);
  abort_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_SECONDS, 5), &do_abort,
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
      GNUNET_YES, &GNUNET_GETOPT_set_relative_time, &search_timeout },
    {'s', "search-delay", "DELAY",
      gettext_noop ("wait DELAY before starting string search"),
      GNUNET_YES, &GNUNET_GETOPT_set_relative_time, &search_delay },
    {'a', "num-search-strings", "COUNT",
      gettext_noop ("number of search strings to read from search strings file"),
      GNUNET_YES, &GNUNET_GETOPT_set_uint, &num_search_strings },
    {'p', "max-path-compression", "MAX_PATH_COMPRESSION",
     gettext_noop ("maximum path compression length"),
     1, &GNUNET_GETOPT_set_uint, &max_path_compression},
    {'i', "no-distributed-search", "",
     gettext_noop ("if this option is set, only one peer is responsible for searching all strings"),
     0, &GNUNET_GETOPT_set_one, &no_distributed_search},
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
