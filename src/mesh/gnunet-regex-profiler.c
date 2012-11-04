/**
     This file is part of GNUnet.
     (C) 2011, 2012 Christian Grothoff (and other contributing authors)

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
 * @file mesh/gnunet-regex-profiler.c
 * @brief Regex profiler for testing distributed regex use.
 * @author Bart Polot
 * @author Max Szengel
 *
 */

#include <string.h>

#include "platform.h"
#include "gnunet_applications.h"
#include "gnunet_util_lib.h"
#include "gnunet_mesh_service.h"
#include "gnunet_stream_lib.h"
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
   * Announcing regexes
   */
  STATE_ANNOUNCE_REGEX,

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
 * An array of hosts loaded from the hostkeys file
 */
static struct GNUNET_TESTBED_Host **hosts;

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
   * Peer's mesh handle.
   */
  struct GNUNET_MESH_Handle *mesh_handle;

  /**
   * Peer's mesh tunnel handle.
   */
  struct GNUNET_MESH_Tunnel *mesh_tunnel_handle;

  /**
   * Testbed operation handle for the mesh service.
   */
  struct GNUNET_TESTBED_Operation *mesh_op_handle;

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
 * Array of peer handles used to pass to
 * GNUNET_TESTBED_overlay_configure_topology
 */
struct GNUNET_TESTBED_Peer **peer_handles;

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
struct GNUNET_TESTBED_ControllerProc *mc_proc;

/**
 * Handle to the master controller
 */
struct GNUNET_TESTBED_Controller *mc;

/**
 * Handle to global configuration
 */
struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Head of the operations list
 */
struct DLLOperation *dll_op_head;

/**
 * Tail of the operations list
 */
struct DLLOperation *dll_op_tail;

/**
 * Peer linking - topology operation
 */
struct GNUNET_TESTBED_Operation *topology_op;

/**
 * Abort task identifier
 */
static GNUNET_SCHEDULER_TaskIdentifier abort_task;

/**
 * Host registration task identifier
 */
static GNUNET_SCHEDULER_TaskIdentifier register_hosts_task;

/**
 * Global event mask for all testbed events
 */
uint64_t event_mask;

/**
 * The starting time of a profiling step
 */
struct GNUNET_TIME_Absolute prof_start_time;

/**
 * Duration profiling step has taken
 */
struct GNUNET_TIME_Relative prof_time;

/**
 * Current peer id
 */
unsigned int peer_id;

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
 * Delay before setting mesh service op as done.
 */
static struct GNUNET_TIME_Relative mesh_done_delay = { 1000 };

/**
 * Delay to wait before starting to configure the overlay topology
 */
static struct GNUNET_TIME_Relative conf_topo_delay = { 10000 };

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

/******************************************************************************/
/******************************  DECLARATIONS  ********************************/
/******************************************************************************/


/**
 * Method called whenever a peer has connected to the tunnel.
 *
 * @param cls closure
 * @param peer_id peer identity the tunnel was created to, NULL on timeout
 * @param atsi performance data for the connection
 *
 */
void
mesh_peer_connect_handler (void *cls,
                           const struct GNUNET_PeerIdentity* peer_id,
                           const struct GNUNET_ATS_Information * atsi);


/**
 * Method called whenever a peer has disconnected from the tunnel.
 * Implementations of this callback must NOT call
 * GNUNET_MESH_tunnel_destroy immediately, but instead schedule those
 * to run in some other task later.  However, calling
 * "GNUNET_MESH_notify_transmit_ready_cancel" is allowed.
 *
 * @param cls closure
 * @param peer_id peer identity the tunnel stopped working with
 */
void
mesh_peer_disconnect_handler (void *cls,
                              const struct GNUNET_PeerIdentity * peer_id);

/**
 * Mesh connect callback.
 *
 * @param cls internal peer id.
 * @param op operation handle.
 * @param ca_result connect adapter result.
 * @param emsg error message.
 */
void
mesh_connect_cb (void *cls, struct GNUNET_TESTBED_Operation *op,
                 void *ca_result, const char *emsg);

/**
 * Mesh connect adapter.
 *
 * @param cls not used.
 * @param cfg configuration handle.
 *
 * @return
 */
void *
mesh_ca (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Adapter function called to destroy a connection to
 * the mesh service
 *
 * @param cls closure
 * @param op_result service handle returned from the connect adapter
 */
void
mesh_da (void *cls, void *op_result);


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
  unsigned int nhost;
  unsigned int peer_cnt;
  unsigned int search_str_cnt;

  if (GNUNET_SCHEDULER_NO_TASK != abort_task)
    GNUNET_SCHEDULER_cancel (abort_task);
  if (GNUNET_SCHEDULER_NO_TASK != register_hosts_task)
    GNUNET_SCHEDULER_cancel (register_hosts_task);

  for (peer_cnt = 0; peer_cnt < num_peers; peer_cnt++)
  {
    if (NULL != peers[peer_cnt].mesh_op_handle)
      GNUNET_TESTBED_operation_done (peers[peer_cnt].mesh_op_handle);
    if (NULL != peers[peer_cnt].stats_op_handle)
      GNUNET_TESTBED_operation_done (peers[peer_cnt].stats_op_handle);
  }

  if (NULL != data_file)
    GNUNET_DISK_file_close (data_file);

  for (search_str_cnt = 0; search_str_cnt < num_search_strings; search_str_cnt++)
    GNUNET_free (search_strings[search_str_cnt]);
  GNUNET_free (search_strings);

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
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Aborting\n");
  abort_task = GNUNET_SCHEDULER_NO_TASK;
  result = GNUNET_SYSERR;
  GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
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
 * Process statistic values.
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
 * Stats callback.
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

  GNUNET_TESTBED_operation_done (peer->stats_op_handle);
  peer->stats_op_handle = NULL;

  if (++peer_cnt == num_search_strings)
  {
    struct GNUNET_TIME_Relative delay = { 100 };
    GNUNET_SCHEDULER_add_delayed (delay, &do_shutdown, NULL);
  }
}


/**
 * Function called by testbed once we are connected to stats service.
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

  GNUNET_assert (NULL != peer->mesh_handle);

  peer->stats_handle = ca_result;

  peer->mesh_tunnel_handle = GNUNET_MESH_tunnel_create (peer->mesh_handle,
                                                        NULL,
							&mesh_peer_connect_handler,
                                                        &mesh_peer_disconnect_handler,
                                                        peer);

  peer->prof_start_time = GNUNET_TIME_absolute_get ();

  GNUNET_MESH_peer_request_connect_by_string (peer->mesh_tunnel_handle,
                                              peer->search_str);
}


/******************************************************************************/
/************************  MESH SERVICE CONNECTIONS  **************************/
/******************************************************************************/

/**
 * Method called whenever another peer has added us to a tunnel
 * the other peer initiated.
 * Only called (once) upon reception of data with a message type which was
 * subscribed to in GNUNET_MESH_connect. A call to GNUNET_MESH_tunnel_destroy
 * causes te tunnel to be ignored and no further notifications are sent about
 * the same tunnel.
 *
 * @param cls closure
 * @param tunnel new handle to the tunnel
 * @param initiator peer that started the tunnel
 * @param atsi performance information for the tunnel
 * @return initial tunnel context for the tunnel
 *         (can be NULL -- that's not an error)
 */
void *
mesh_inbound_tunnel_handler (void *cls, struct GNUNET_MESH_Tunnel *tunnel,
                             const struct GNUNET_PeerIdentity *initiator,
                             const struct GNUNET_ATS_Information *atsi)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Mesh inbound tunnel handler.\n");

  return NULL;
}


/**
 * Function called whenever an inbound tunnel is destroyed.  Should clean up
 * any associated state.  This function is NOT called if the client has
 * explicitly asked for the tunnel to be destroyed using
 * GNUNET_MESH_tunnel_destroy. It must NOT call GNUNET_MESH_tunnel_destroy on
 * the tunnel.
 *
 * @param cls closure (set from GNUNET_MESH_connect)
 * @param tunnel connection to the other end (henceforth invalid)
 * @param tunnel_ctx place where local state associated
 *                   with the tunnel is stored
 */
void
mesh_tunnel_end_handler (void *cls, const struct GNUNET_MESH_Tunnel *tunnel,
                         void *tunnel_ctx)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Mesh tunnel end handler.\n");
}


/**
 * Method called whenever a peer has disconnected from the tunnel.
 * Implementations of this callback must NOT call
 * GNUNET_MESH_tunnel_destroy immediately, but instead schedule those
 * to run in some other task later.  However, calling
 * "GNUNET_MESH_notify_transmit_ready_cancel" is allowed.
 *
 * @param cls closure
 * @param peer_id peer identity the tunnel stopped working with
 */
void
mesh_peer_disconnect_handler (void *cls,
                              const struct GNUNET_PeerIdentity * peer_id)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Mesh peer disconnect handler.\n");
}


/**
 * Method called whenever a peer has connected to the tunnel.
 *
 * @param cls closure
 * @param peer_id peer identity the tunnel was created to, NULL on timeout
 * @param atsi performance data for the connection
 *
 */
void
mesh_peer_connect_handler (void *cls,
                           const struct GNUNET_PeerIdentity* peer_id,
                           const struct GNUNET_ATS_Information * atsi)
{
  struct RegexPeer *peer = cls;
  char output_buffer[512];
  size_t size;

  peers_found++;

  if (NULL == peer_id)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "String matching timed out for string %s on peer %u (%i/%i)\n",
                peer->search_str, peer->id, peers_found, num_search_strings);

    printf ("String matching timed out for string %s on peer %u (%i/%i)\n",
	    peer->search_str, peer->id, peers_found, num_search_strings);
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

    if (NULL != data_file)
    {
      size =
        GNUNET_snprintf (output_buffer,
                         sizeof (output_buffer),
                         "Peer: %u (%p)\nHost: %s\nPolicy file: %s\nSearch string: %s\nSearch duration: %s\n\n",
                         peer->id,
                         peer,
                         GNUNET_TESTBED_host_get_hostname (peer->host_handle),
                         peer->policy_file,
                         peer->search_str,
                         GNUNET_STRINGS_relative_time_to_string (prof_time, GNUNET_NO));

      if (size != GNUNET_DISK_file_write (data_file, output_buffer, size))
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Unable to write to file!\n");
    }

    if (NULL == peer->stats_handle)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  "Cannot get statistics for peer %u, stats handle is NULL!\n");
      return;
    }

    if (NULL == GNUNET_STATISTICS_get (peer->stats_handle, "mesh", NULL,
                                       GNUNET_TIME_UNIT_FOREVER_REL,
                                       NULL,
                                       &stats_iterator, peer))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Could not get mesh statistics of peer %u!\n", peer->id);
    }
    if (NULL == GNUNET_STATISTICS_get (peer->stats_handle, "transport", NULL,
                                       GNUNET_TIME_UNIT_FOREVER_REL,
                                       NULL,
                                       &stats_iterator, peer))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Could not get transport statistics of peer %u!\n", peer->id);
    }
    if (NULL == GNUNET_STATISTICS_get (peer->stats_handle, "dht", NULL,
                                       GNUNET_TIME_UNIT_FOREVER_REL,
                                       &stats_cb,
                                       &stats_iterator, peer))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Could not get dht statistics of peer %u!\n", peer->id);
    }
  }

  if (peers_found == num_search_strings)
  {
    prof_time = GNUNET_TIME_absolute_get_duration (prof_start_time);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "All strings successfully matched in %s\n",
                GNUNET_STRINGS_relative_time_to_string (prof_time, GNUNET_NO));
    printf ("All strings successfully matched. Shutting down.\n");
    fflush (stdout);

    if (GNUNET_SCHEDULER_NO_TASK != search_timeout_task)
      GNUNET_SCHEDULER_cancel (search_timeout_task);
  }
}


/**
 * Connect by string timeout task
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

  GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
}


/**
 * Connect by string task that is run to search for a string in the NFA
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_connect_by_string (void *cls,
                      const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  unsigned int search_cnt;
  struct RegexPeer *peer;

  printf ("Starting string search.\n");
  fflush (stdout);

  for (search_cnt = 0; search_cnt < num_search_strings; search_cnt++)
  {
    peer = &peers[search_cnt % num_peers];
    peer->search_str = search_strings[search_cnt];

    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Searching for string \"%s\" on peer %d with file %s\n",
                peer->search_str, (search_cnt % num_peers), peer->policy_file);

    /* First connect to mesh service, then connect to stats service
       and then try connecting by string in stats_connect_cb */
    peer->mesh_op_handle =
      GNUNET_TESTBED_service_connect (NULL,
                                      peers->peer_handle,
                                      "mesh",
                                      &mesh_connect_cb,
                                      peer,
                                      &mesh_ca,
                                      &mesh_da,
                                      peer);
  }

  search_timeout_task = GNUNET_SCHEDULER_add_delayed (search_timeout,
                                                      &do_connect_by_string_timeout, NULL);
}


/**
 * Delayed operation done for mesh service disconnects.
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_mesh_op_done (void *cls,
		 const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  struct RegexPeer *peer = cls;
  static unsigned int peer_cnt;
  GNUNET_TESTBED_operation_done (peer->mesh_op_handle);
  peer->mesh_op_handle = NULL;

  if (++peer_cnt < num_peers)
  {
    peers[peer_cnt].mesh_op_handle =
      GNUNET_TESTBED_service_connect (NULL,
				      peers[peer_cnt].peer_handle,
				      "mesh",
				      &mesh_connect_cb,
				      &peers[peer_cnt],
				      &mesh_ca,
				      &mesh_da,
				      &peers[peer_cnt]);
  }
}


/**
 * Mesh connect callback.
 *
 * @param cls internal peer id.
 * @param op operation handle.
 * @param ca_result connect adapter result.
 * @param emsg error message.
 */
void
mesh_connect_cb (void *cls, struct GNUNET_TESTBED_Operation *op,
                 void *ca_result, const char *emsg)
{
  struct RegexPeer *peer = (struct RegexPeer *) cls;
  char *regex;
  char *data;
  char *buf;
  uint64_t filesize;
  unsigned int offset;

  if (NULL != emsg || NULL == op || NULL == ca_result)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Mesh connect failed: %s\n", emsg);
    GNUNET_assert (0);
  }
  
  GNUNET_assert (peer->mesh_handle != NULL);
  GNUNET_assert (peer->mesh_op_handle == op);
  GNUNET_assert (peer->mesh_handle == ca_result);
  GNUNET_assert (NULL != peer->policy_file);

  switch (state)
  {
  case STATE_ANNOUNCE_REGEX:
    {
      static unsigned int num_files_announced;

      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  "Announcing regexes for peer %u with file %s\n",
		  peer->id, peer->policy_file);
      
      if (GNUNET_YES != GNUNET_DISK_file_test (peer->policy_file))
      {
	GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		    "Could not find policy file %s\n", peer->policy_file);
	return;
      }
      if (GNUNET_OK != GNUNET_DISK_file_size (peer->policy_file, &filesize, GNUNET_YES, GNUNET_YES))
	filesize = 0;
      if (0 == filesize)
      {
	GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Policy file %s is empty.\n", peer->policy_file);
	return;
      }
      data = GNUNET_malloc (filesize);
      if (filesize != GNUNET_DISK_fn_read (peer->policy_file, data, filesize))
      {
	GNUNET_free (data);
	GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Could not read policy file %s.\n",
		    peer->policy_file);
	return;
      }
      buf = data;
      offset = 0;
      regex = NULL;
      while (offset < (filesize - 1))
      {
	offset++;
	if (((data[offset] == '\n')) && (buf != &data[offset]))
	{
	  data[offset] = '\0';
	  regex = buf;
	  GNUNET_assert (NULL != regex);
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Announcing regex: %s on peer %u \n",
		  regex, peer->id);
	  GNUNET_MESH_announce_regex (peer->mesh_handle, regex, max_path_compression);
	  buf = &data[offset + 1];
	}
	else if ((data[offset] == '\n') || (data[offset] == '\0'))
	  buf = &data[offset + 1];
      }
      GNUNET_free (data);

      GNUNET_SCHEDULER_add_delayed (mesh_done_delay, &do_mesh_op_done, peer);
      
      if (++num_files_announced == num_peers)
      {
	state = STATE_SEARCH_REGEX;

	prof_time = GNUNET_TIME_absolute_get_duration (prof_start_time);
	
	printf ("All files announced in %s.\n",
		GNUNET_STRINGS_relative_time_to_string (prof_time, GNUNET_NO));
	printf ("Waiting %s before starting to search.\n", 
		GNUNET_STRINGS_relative_time_to_string (search_delay, GNUNET_YES));
	fflush (stdout);
	
	GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		    "All regexes announced in %s. Waiting %s before starting to search.\n",
		    GNUNET_STRINGS_relative_time_to_string (prof_time, GNUNET_NO),
		    GNUNET_STRINGS_relative_time_to_string (search_delay, GNUNET_NO));
	
	search_task = GNUNET_SCHEDULER_add_delayed (search_delay,
						    &do_connect_by_string, NULL);    
      }
      break;
    }
  case STATE_SEARCH_REGEX:
    {
      /* First connect to the stats service, then start to search */
      peer->stats_op_handle =
	GNUNET_TESTBED_service_connect (NULL,
					peers->peer_handle,
					"statistics",
					&stats_connect_cb,
					peer,
					&stats_ca,
					&stats_da,
					peer);
      break;
    }
  default:
    GNUNET_break (0);
  }
}


/**
 * Mesh connect adapter.
 *
 * @param cls not used.
 * @param cfg configuration handle.
 *
 * @return
 */
void *
mesh_ca (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_MESH_ApplicationType app;
  struct RegexPeer *peer = cls;

  static struct GNUNET_MESH_MessageHandler handlers[] = {
    {NULL, 0, 0}
  };

  app = (GNUNET_MESH_ApplicationType)0;

  peer->mesh_handle =
    GNUNET_MESH_connect (cfg, cls, NULL, NULL, handlers, &app);

  return peer->mesh_handle;
}


/**
 * Adapter function called to destroy a connection to
 * the mesh service
 *
 * @param cls closure
 * @param op_result service handle returned from the connect adapter
 */
void
mesh_da (void *cls, void *op_result)
{
  struct RegexPeer *peer = (struct RegexPeer *) cls;

  GNUNET_assert (peer->mesh_handle == op_result);

  if (NULL != peer->mesh_tunnel_handle)
  {
    GNUNET_MESH_tunnel_destroy (peer->mesh_tunnel_handle);
    peer->mesh_tunnel_handle = NULL;
  }

  if (NULL != peer->mesh_handle)
  {
    GNUNET_MESH_disconnect (peer->mesh_handle);
    peer->mesh_handle = NULL;
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
					       GNUNET_TESTBED_TOPOLOGY_ERDOS_RENYI,
					       num_links,
					       GNUNET_TESTBED_TOPOLOGY_DISABLE_AUTO_RETRY,
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
    abort_task = GNUNET_SCHEDULER_add_now (&do_abort, NULL);
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

    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		"Waiting %s before starting to link peers\n", 
		GNUNET_STRINGS_relative_time_to_string (conf_topo_delay, GNUNET_YES));

    printf ("Waiting %s before starting to link peers\n", 
	    GNUNET_STRINGS_relative_time_to_string (conf_topo_delay, GNUNET_YES));
    fflush (stdout);

    state = STATE_PEERS_LINKING;
    GNUNET_SCHEDULER_add_delayed (conf_topo_delay, &do_configure_topology, NULL);
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
    abort_task = GNUNET_SCHEDULER_add_now (&do_abort, NULL);
    return;
  }

  peer_ptr = dll_op->cls;
  GNUNET_assert (NULL == peer_ptr->peer_handle);
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
 * Function called with a filename.
 *
 * @param cls closure
 * @param filename complete filename (absolute path)
 * @return GNUNET_OK to continue to iterate,
 *  GNUNET_SYSERR to abort iteration with error!
 */
int
policy_filename_cb (void *cls, const char *filename)
{
  static unsigned int peer_cnt;
  struct DLLOperation *dll_op;
  struct RegexPeer *peer = &peers[peer_cnt];

  GNUNET_assert (NULL != peer);

  peer->id = peer_cnt;
  peer->policy_file = GNUNET_strdup (filename);
  /* Do not start peers on hosts[0] (master controller) */
  peer->host_handle = hosts[1 + (peer_cnt % (num_hosts -1))];
  peer->mesh_handle = NULL;
  peer->mesh_tunnel_handle = NULL;
  peer->stats_handle = NULL;
  peer->stats_op_handle = NULL;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Creating peer %i on host %s for policy file %s\n",
              peer->id,
              GNUNET_TESTBED_host_get_hostname (peer->host_handle),
              filename);

  dll_op = GNUNET_malloc (sizeof (struct DLLOperation));
  dll_op->cls = &peers[peer_cnt];
  dll_op->op = GNUNET_TESTBED_peer_create (mc,
                                           peer->host_handle,
                                           cfg,
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

  switch (state)
  {
  case STATE_SLAVES_STARTING:
    switch (event->type)
    {
    case GNUNET_TESTBED_ET_OPERATION_FINISHED:
      {
        static unsigned int slaves_started;

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
          abort_task = GNUNET_SCHEDULER_add_now (&do_abort, NULL);
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

          num_peers = GNUNET_DISK_directory_scan (policy_dir,
                                                  NULL,
                                                  NULL);
          peers = GNUNET_malloc (sizeof (struct RegexPeer) * num_peers);

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
       
       GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		   "Connecting to mesh service and start announcing regex...\n");
       printf ("\nStarting to connect to mesh services and announce regex\n");
       fflush (stdout);
       
       prof_start_time = GNUNET_TIME_absolute_get ();
       peers[0].mesh_op_handle =
	 GNUNET_TESTBED_service_connect (NULL,
					 peers[0].peer_handle,
					 "mesh",
					 &mesh_connect_cb,
					 &peers[0],
					 &mesh_ca,
					 &mesh_da,
					 &peers[0]);
       state = STATE_ANNOUNCE_REGEX;
     }
   }
   break;
   default:
     GNUNET_assert (0);
   }
   break;
  case STATE_ANNOUNCE_REGEX:
  {
    /* Handled in service connect callback */
    break;
  }
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
 * Task to register all hosts available in the global host list
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
    abort_task = GNUNET_SCHEDULER_add_now (&do_abort, NULL);
    return;
  }
  register_hosts_task = GNUNET_SCHEDULER_add_now (&register_hosts, NULL);
}


/**
 * Task to register all hosts available in the global host list
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
 * Callback to signal successfull startup of the controller process
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
    abort_task = GNUNET_SCHEDULER_add_now (&do_abort, NULL);
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
    abort_task = GNUNET_SCHEDULER_add_now (&do_abort, NULL);
    return;
  }
  register_hosts_task = GNUNET_SCHEDULER_add_now (&register_hosts, NULL);
  abort_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                             &do_abort, NULL);
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
    (*strings)[i] = GNUNET_strdup (&data[offset]);
    offset += strlen ((*strings)[i]) + 1;
  }
  free (data);
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
  unsigned int nhost;

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
  for (nhost = 0; nhost < num_hosts; nhost++)
  {
    if (GNUNET_YES != GNUNET_TESTBED_is_host_habitable (hosts[nhost], config))
    {
      fprintf (stderr, _("Host %s cannot start testbed\n"),
                         GNUNET_TESTBED_host_get_hostname (hosts[nhost]));
      break;
    }
  }
  if (num_hosts != nhost)
  {
    fprintf (stderr, _("Exiting\n"));
    GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }
  if (NULL == config)
  {
    fprintf (stderr, _("No configuration file given. Exiting\n"));
    GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
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
  if (GNUNET_YES != GNUNET_DISK_directory_test (args[1]))
  {
    fprintf (stderr, _("Specified policies directory does not exist. Exiting.\n"));
    GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }
  policy_dir = args[1];
  if (GNUNET_YES != GNUNET_DISK_file_test (args[2]))
  {
    fprintf (stderr, _("No search strings file given. Exiting.\n"));
    GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }
  if (num_search_strings != load_search_strings (args[2], &search_strings, num_search_strings))
  {
    fprintf (stderr, _("Error loading search strings. Given file does not contain enough strings. Exiting.\n"));
    GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }
  if (0 >= num_search_strings || NULL == search_strings)
  {
    fprintf (stderr, _("Error loading search strings. Exiting.\n"));
    GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }
  unsigned int i;
  for (i = 0; i < num_search_strings; i++)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "search string: %s\n", search_strings[i]);
  cfg = GNUNET_CONFIGURATION_dup (config);
  mc_proc =
      GNUNET_TESTBED_controller_start (GNUNET_TESTBED_host_get_hostname
                                       (hosts[0]),
                                       hosts[0],
                                       cfg,
                                       status_cb,
                                       NULL);
  abort_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_SECONDS, 5), &do_abort,
                                    NULL);
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
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  result = GNUNET_SYSERR;
  ret =
      GNUNET_PROGRAM_run (argc, argv, "gnunet-regex-profiler [OPTIONS] hosts-file policy-dir search-strings-file",
                          _("Profiler for regex/mesh"),
                          options, &run, NULL);
  if (GNUNET_OK != ret)
    return ret;
  if (GNUNET_OK != result)
    return 1;
  return 0;
}
