/*
 This file is part of GNUnet
 (C) 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file testing/testing_group.c
 * @brief convenience API for writing testcases for GNUnet
 * @author Nathan Evans
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_arm_service.h"
#include "gnunet_testing_lib.h"
#include "gnunet_core_service.h"

#define USE_START_HELPER GNUNET_YES

#define OLD 1

/* Before connecting peers, send all of the HELLOs */
#define USE_SEND_HELLOS GNUNET_NO

#define TOPOLOGY_HACK GNUNET_YES


/**
 * Lowest port used for GNUnet testing.  Should be high enough to not
 * conflict with other applications running on the hosts but be low
 * enough to not conflict with client-ports (typically starting around
 * 32k).
 */
#define LOW_PORT 12000

/**
 * Highest port used for GNUnet testing.  Should be low enough to not
 * conflict with the port range for "local" ports (client apps; see
 * /proc/sys/net/ipv4/ip_local_port_range on Linux for example).
 */
#define HIGH_PORT 56000

/* Maximum time to delay connect attempt */
#define MAX_CONNECT_DELAY 300

/**
 * Which list of peers do we need to modify?
 */
enum PeerLists
{
  /** Modify allowed peers */
  ALLOWED,

  /** Modify connect peers */
  CONNECT,

  /** Modify blacklist peers */
  BLACKLIST,

  /** Modify workingset peers */
  WORKING_SET
};

/**
 * Prototype of a function called whenever two peers would be connected
 * in a certain topology.
 */
typedef unsigned int (*GNUNET_TESTING_ConnectionProcessor) (struct
                                                            GNUNET_TESTING_PeerGroup
                                                            * pg,
                                                            unsigned int first,
                                                            unsigned int second,
                                                            enum PeerLists list,
                                                            unsigned int check);

/**
 * Context for handling churning a peer group
 */
struct ChurnContext
{
  /**
   * The peergroup we are dealing with.
   */
  struct GNUNET_TESTING_PeerGroup *pg;

  /**
   * Name of the service to churn on/off, NULL
   * to churn entire peer.
   */
  char *service;

  /**
   * Callback used to notify of churning finished
   */
  GNUNET_TESTING_NotifyCompletion cb;

  /**
   * Closure for callback
   */
  void *cb_cls;

  /**
   * Number of peers that still need to be started
   */
  unsigned int num_to_start;

  /**
   * Number of peers that still need to be stopped
   */
  unsigned int num_to_stop;

  /**
   * Number of peers that failed to start
   */
  unsigned int num_failed_start;

  /**
   * Number of peers that failed to stop
   */
  unsigned int num_failed_stop;
};

struct RestartContext
{
  /**
   * The group of peers being restarted
   */
  struct GNUNET_TESTING_PeerGroup *peer_group;

  /**
   * How many peers have been restarted thus far
   */
  unsigned int peers_restarted;

  /**
   * How many peers got an error when restarting
   */
  unsigned int peers_restart_failed;

  /**
   * The function to call once all peers have been restarted
   */
  GNUNET_TESTING_NotifyCompletion callback;

  /**
   * Closure for callback function
   */
  void *callback_cls;

};

struct SendHelloContext
{
  /**
   * Global handle to the peer group.
   */
  struct GNUNET_TESTING_PeerGroup *pg;

  /**
   * The data about this specific peer.
   */
  struct PeerData *peer;

  /**
   * The next HELLO that needs sent to this peer.
   */
  struct PeerConnection *peer_pos;

  /**
   * Are we connected to CORE yet?
   */
  unsigned int core_ready;

  /**
   * How many attempts should we make for failed connections?
   */
  unsigned int connect_attempts;

  /**
   * Task for scheduling core connect requests to be sent.
   */
  GNUNET_SCHEDULER_TaskIdentifier core_connect_task;
};

struct ShutdownContext
{
  struct GNUNET_TESTING_PeerGroup *pg;
  /**
   * Total peers to wait for
   */
  unsigned int total_peers;

  /**
   * Number of peers successfully shut down
   */
  unsigned int peers_down;

  /**
   * Number of peers failed to shut down
   */
  unsigned int peers_failed;

  /**
   * Number of peers we have started shutting
   * down.  If too many, wait on them.
   */
  unsigned int outstanding;

  /**
   * Timeout for shutdown.
   */
  struct GNUNET_TIME_Relative timeout;

  /**
   * Callback to call when all peers either
   * shutdown or failed to shutdown
   */
  GNUNET_TESTING_NotifyCompletion cb;

  /**
   * Closure for cb
   */
  void *cb_cls;

  /**
   * Should we delete all of the files from the peers?
   */
  int delete_files;
};

/**
 * Individual shutdown context for a particular peer.
 */
struct PeerShutdownContext
{
  /**
   * Pointer to the high level shutdown context.
   */
  struct ShutdownContext *shutdown_ctx;

  /**
   * The daemon handle for the peer to shut down.
   */
  struct GNUNET_TESTING_Daemon *daemon;
};

/**
 * Individual shutdown context for a particular peer.
 */
struct PeerRestartContext
{
  /**
   * Pointer to the high level restart context.
   */
  struct ChurnRestartContext *churn_restart_ctx;

  /**
   * The daemon handle for the peer to shut down.
   */
  struct GNUNET_TESTING_Daemon *daemon;
};

struct ServiceStartContext
{
  struct GNUNET_TESTING_PeerGroup *pg;
  unsigned int remaining;
  GNUNET_TESTING_NotifyCompletion cb;
  unsigned int outstanding;
  char *service;
  struct GNUNET_TIME_Relative timeout;
  void *cb_cls;
};

/**
 * Individual shutdown context for a particular peer.
 */
struct PeerServiceStartContext
{
  /**
   * Pointer to the high level start context.
   */
  struct ServiceStartContext *start_ctx;

  /**
   * The daemon handle for the peer to start the service on.
   */
  struct GNUNET_TESTING_Daemon *daemon;
};

struct CreateTopologyContext
{

  /**
   * Function to call with number of connections
   */
  GNUNET_TESTING_NotifyConnections cont;

  /**
   * Closure for connection notification
   */
  void *cls;
};

enum States
{
  /** Waiting to read number of peers */
  NUM_PEERS,

  /** Should find next peer index */
  PEER_INDEX,

  /** Should find colon */
  COLON,

  /** Should read other peer index, space, or endline */
  OTHER_PEER_INDEX
};

#if OLD
struct PeerConnection
{
  /**
   * Doubly Linked list
   */
  struct PeerConnection *prev;

  /*
   * Doubly Linked list
   */
  struct PeerConnection *next;

  /*
   * Index of daemon in pg->peers
   */
  uint32_t index;

};
#endif

struct InternalStartContext
{
  /**
   * Pointer to peerdata
   */
  struct PeerData *peer;

  /**
   * Timeout for peer startup
   */
  struct GNUNET_TIME_Relative timeout;

  /**
   * Client callback for hostkey notification
   */
  GNUNET_TESTING_NotifyHostkeyCreated hostkey_callback;

  /**
   * Closure for hostkey_callback
   */
  void *hostkey_cls;

  /**
   * Client callback for peer start notification
   */
  GNUNET_TESTING_NotifyDaemonRunning start_cb;

  /**
   * Closure for cb
   */
  void *start_cb_cls;

  /**
   * Hostname, where to start the peer
   */
  const char *hostname;

  /**
   * Username to use when connecting to the
   * host via ssh.
   */
  const char *username;

  /**
   * Pointer to starting memory location of a hostkey
   */
  const char *hostkey;

  /**
   * Port to use for ssh.
   */
  uint16_t sshport;

};

struct ChurnRestartContext
{
  /**
   * PeerGroup that we are working with.
   */
  struct GNUNET_TESTING_PeerGroup *pg;

  /**
   * Number of restarts currently in flight.
   */
  unsigned int outstanding;

  /**
   * Handle to the underlying churn context.
   */
  struct ChurnContext *churn_ctx;

  /**
   * How long to allow the operation to take.
   */
  struct GNUNET_TIME_Relative timeout;
};

struct OutstandingSSH
{
  struct OutstandingSSH *next;

  struct OutstandingSSH *prev;

  /**
   * Number of current ssh connections.
   */
  uint32_t outstanding;

  /**
   * The hostname of this peer.
   */
  const char *hostname;
};

/**
 * Data we keep per peer.
 */
struct PeerData
{
  /**
   * (Initial) configuration of the host.
   * (initial because clients could change
   *  it and we would not know about those
   *  updates).
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Handle for controlling the daemon.
   */
  struct GNUNET_TESTING_Daemon *daemon;

  /**
   * The peergroup this peer belongs to.
   */
  struct GNUNET_TESTING_PeerGroup *pg;

#if OLD
  /**
   * Linked list of allowed peer connections.
   */
  struct PeerConnection *allowed_peers_head;

  /**
   * Linked list of allowed peer connections.
   */
  struct PeerConnection *allowed_peers_tail;

  /**
   * Linked list of blacklisted peer connections.
   */
  struct PeerConnection *blacklisted_peers_head;

  /**
   * Linked list of blacklisted peer connections.
   */
  struct PeerConnection *blacklisted_peers_tail;

  /**
   * Linked list of connect peer connections.
   */
  struct PeerConnection *connect_peers_head;

  /**
   * Linked list of connect peer connections.
   */
  struct PeerConnection *connect_peers_tail;

  /**
   * Linked list of connect peer connections.
   */
  struct PeerConnection *connect_peers_working_set_head;

  /**
   * Linked list of connect peer connections.
   */
  struct PeerConnection *connect_peers_working_set_tail;

#else
  /**
   * Hash map of allowed peer connections (F2F created topology)
   */
  struct GNUNET_CONTAINER_MultiHashMap *allowed_peers;

  /**
   * Hash map of blacklisted peers
   */
  struct GNUNET_CONTAINER_MultiHashMap *blacklisted_peers;

  /**
   * Hash map of peer connections
   */
  struct GNUNET_CONTAINER_MultiHashMap *connect_peers;

  /**
   * Temporary hash map of peer connections
   */
  struct GNUNET_CONTAINER_MultiHashMap *connect_peers_working_set;
#endif

  /**
   * Temporary variable for topology creation, should be reset before
   * creating any topology so the count is valid once finished.
   */
  int num_connections;

  /**
   * Context to keep track of peers being started, to
   * stagger hostkey generation and peer startup.
   */
  struct InternalStartContext internal_context;

  /**
   * Task ID for the queued internal_continue_startup task
   */
  GNUNET_SCHEDULER_TaskIdentifier startup_task;

};

/**
 * Linked list of per-host data.
 */
struct HostData
{
  /**
   * Name of the host.
   */
  char *hostname;

  /**
   * SSH username to use when connecting to this host.
   */
  char *username;

  /**
   * SSH port to use when connecting to this host.
   */
  uint16_t sshport;

  /**
   * Lowest port that we have not yet used
   * for GNUnet.
   */
  uint16_t minport;
};

struct TopologyIterateContext
{
  /**
   * The peergroup we are working with.
   */
  struct GNUNET_TESTING_PeerGroup *pg;

  /**
   * Callback for notifying of two connected peers.
   */
  GNUNET_TESTING_NotifyTopology topology_cb;

  /**
   * Closure for topology_cb
   */
  void *cls;

  /**
   * Number of peers currently connected to.
   */
  unsigned int connected;

  /**
   * Number of peers we have finished iterating.
   */
  unsigned int completed;

  /**
   * Number of peers total.
   */
  unsigned int total;
};

struct StatsIterateContext
{
  /**
   * The peergroup that we are dealing with.
   */
  struct GNUNET_TESTING_PeerGroup *pg;

  /**
   * Continuation to call once all stats information has been retrieved.
   */
  GNUNET_STATISTICS_Callback cont;

  /**
   * Proc function to call on each value received.
   */
  GNUNET_TESTING_STATISTICS_Iterator proc;

  /**
   * Closure for topology_cb
   */
  void *cls;

  /**
   * Number of peers currently connected to.
   */
  unsigned int connected;

  /**
   * Number of peers we have finished iterating.
   */
  unsigned int completed;

  /**
   * Number of peers total.
   */
  unsigned int total;
};

struct CoreContext
{
  void *iter_context;
  struct GNUNET_TESTING_Daemon *daemon;
};

struct StatsCoreContext
{
  void *iter_context;
  struct GNUNET_TESTING_Daemon *daemon;
  /**
   * Handle to the statistics service.
   */
  struct GNUNET_STATISTICS_Handle *stats_handle;

  /**
   * Handle for getting statistics.
   */
  struct GNUNET_STATISTICS_GetHandle *stats_get_handle;
};

struct ConnectTopologyContext
{
  /**
   * How many connections are left to create.
   */
  unsigned int remaining_connections;

  /**
   * Handle to group of peers.
   */
  struct GNUNET_TESTING_PeerGroup *pg;

  /**
   * How long to try this connection before timing out.
   */
  struct GNUNET_TIME_Relative connect_timeout;

  /**
   * How many times to retry connecting the two peers.
   */
  unsigned int connect_attempts;

  /**
   * Temp value set for each iteration.
   */
  //struct PeerData *first;

  /**
   * Notification that all peers are connected.
   */
  GNUNET_TESTING_NotifyCompletion notify_connections_done;

  /**
   * Closure for notify.
   */
  void *notify_cls;
};

struct ConnectContext;

/**
 * Handle to a group of GNUnet peers.
 */
struct GNUNET_TESTING_PeerGroup
{
  /**
   * Configuration template.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  struct ConnectContext *cc_head;

  struct ConnectContext *cc_tail;

  /**
   * Function to call on each started daemon.
   */
  //GNUNET_TESTING_NotifyDaemonRunning cb;

  /**
   * Closure for cb.
   */
  //void *cb_cls;

  /*
   * Function to call on each topology connection created
   */
  GNUNET_TESTING_NotifyConnection notify_connection;

  /*
   * Callback for notify_connection
   */
  void *notify_connection_cls;

  /**
   * Array of information about hosts.
   */
  struct HostData *hosts;

  /**
   * Number of hosts (size of HostData)
   */
  unsigned int num_hosts;

  /**
   * Array of "total" peers.
   */
  struct PeerData *peers;

  /**
   * Number of peers in this group.
   */
  unsigned int total;

  /**
   * At what time should we fail the peer startup process?
   */
  struct GNUNET_TIME_Absolute max_timeout;

  /**
   * How many peers are being started right now?
   */
  unsigned int starting;

  /**
   * How many peers have already been started?
   */
  unsigned int started;

  /**
   * Number of possible connections to peers
   * at a time.
   */
  unsigned int max_outstanding_connections;

  /**
   * Number of ssh connections to peers (max).
   */
  unsigned int max_concurrent_ssh;

  /**
   * Number of connects we are waiting on, allows us to rate limit
   * connect attempts.
   */
  unsigned int outstanding_connects;

  /**
   * Number of HELLOs we have yet to send.
   */
  unsigned int remaining_hellos;

  /**
   * How many connects have already been scheduled?
   */
  unsigned int total_connects_scheduled;

  /**
   * Hostkeys loaded from a file.
   */
  char *hostkey_data;

  /**
   * Head of DLL to keep track of the number of outstanding
   * ssh connections per peer.
   */
  struct OutstandingSSH *ssh_head;

  /**
   * Tail of DLL to keep track of the number of outstanding
   * ssh connections per peer.
   */
  struct OutstandingSSH *ssh_tail;

  /**
   * Stop scheduling peers connecting.
   */
  unsigned int stop_connects;

  /**
   * Connection context for peer group.
   */
  struct ConnectTopologyContext ct_ctx;
};

struct UpdateContext
{
  /**
   * The altered configuration.
   */
  struct GNUNET_CONFIGURATION_Handle *ret;

  /**
   * The original configuration to alter.
   */
  const struct GNUNET_CONFIGURATION_Handle *orig;

  /**
   * The hostname that this peer will run on.
   */
  const char *hostname;

  /**
   * The next possible port to assign.
   */
  unsigned int nport;

  /**
   * Unique number for unix domain sockets.
   */
  unsigned int upnum;

  /**
   * Unique number for this peer/host to offset
   * things that are grouped by host.
   */
  unsigned int fdnum;
};

struct ConnectContext
{

  struct ConnectContext *next;

  struct ConnectContext *prev;

  /**
   * Index of peer to connect second to.
   */
  uint32_t first_index;

  /**
   * Index of peer to connect first to.
   */
  uint32_t second_index;

  /**
   * Task associated with the attempt to connect.
   */
  GNUNET_SCHEDULER_TaskIdentifier task;

  /**
   * Context in 'testing.c', to cancel connection attempt.
   */
  struct GNUNET_TESTING_ConnectContext *cc;

  /**
   * Higher level topology connection context.
   */
  struct ConnectTopologyContext *ct_ctx;

  /**
   * Whether this connection has been accounted for in the schedule_connect call.
   */
  int counted;
};

struct UnblacklistContext
{
  /**
   * The peergroup
   */
  struct GNUNET_TESTING_PeerGroup *pg;

  /**
   * uid of the first peer
   */
  uint32_t first_uid;
};

struct RandomContext
{
  /**
   * The peergroup
   */
  struct GNUNET_TESTING_PeerGroup *pg;

  /**
   * uid of the first peer
   */
  uint32_t first_uid;

  /**
   * Peer data for first peer.
   */
  struct PeerData *first;

  /**
   * Random percentage to use
   */
  double percentage;
};

struct MinimumContext
{
  /**
   * The peergroup
   */
  struct GNUNET_TESTING_PeerGroup *pg;

  /**
   * uid of the first peer
   */
  uint32_t first_uid;

  /**
   * Peer data for first peer.
   */
  struct PeerData *first;

  /**
   * Number of conns per peer
   */
  unsigned int num_to_add;

  /**
   * Permuted array of all possible connections.  Only add the Nth
   * peer if it's in the Nth position.
   */
  unsigned int *pg_array;

  /**
   * What number is the current element we are iterating over?
   */
  unsigned int current;
};

struct DFSContext
{
  /**
   * The peergroup
   */
  struct GNUNET_TESTING_PeerGroup *pg;

  /**
   * uid of the first peer
   */
  uint32_t first_uid;

  /**
   * uid of the second peer
   */
  uint32_t second_uid;

  /**
   * Peer data for first peer.
   */
  struct PeerData *first;

  /**
   * Which peer has been chosen as the one to add?
   */
  unsigned int chosen;

  /**
   * What number is the current element we are iterating over?
   */
  unsigned int current;
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

#if !OLD
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
 * Convert hash code to unique ID.
 *
 * @param uid unique ID to convert
 * @param hash set to uid (extended with zeros)
 */
static void
uid_from_hash (const GNUNET_HashCode * hash, uint32_t * uid)
{
  memcpy (uid, hash, sizeof (uint32_t));
}
#endif

#if USE_SEND_HELLOS
static struct GNUNET_CORE_MessageHandler no_handlers[] = {
  {NULL, 0, 0}
};
#endif

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
  if (ret->modnum == 0)         /* Divide by zero check */
    ret->modnum = 1;
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
        FPRINTF (stdout, "%sProgress: [0%%", meter->startup_string);
      }
      else
        FPRINTF (stdout, "%d%%",
                 (int) (((float) meter->completed / meter->total) * 100));
    }
    else if (meter->completed % meter->dotnum == 0)
      FPRINTF (stdout, "%s",  ".");

    if (meter->completed + 1 == meter->total)
      FPRINTF (stdout, "%d%%]\n", 100);
    fflush (stdout);
  }
  meter->completed++;

  if (meter->completed == meter->total)
    return GNUNET_YES;
  if (meter->completed > meter->total)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Progress meter overflow!!\n");
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
 * Get a topology from a string input.
 *
 * @param topology where to write the retrieved topology
 * @param topology_string The string to attempt to
 *        get a configuration value from
 * @return GNUNET_YES if topology string matched a
 *         known topology, GNUNET_NO if not
 */
int
GNUNET_TESTING_topology_get (enum GNUNET_TESTING_Topology *topology,
                             const char *topology_string)
{
  /**
   * Strings representing topologies in enum
   */
  static const char *topology_strings[] = {
    /**
     * A clique (everyone connected to everyone else).
     */
    "CLIQUE",

    /**
     * Small-world network (2d torus plus random links).
     */
    "SMALL_WORLD",

    /**
     * Small-world network (ring plus random links).
     */
    "SMALL_WORLD_RING",

    /**
     * Ring topology.
     */
    "RING",

    /**
     * 2-d torus.
     */
    "2D_TORUS",

    /**
     * Random graph.
     */
    "ERDOS_RENYI",

    /**
     * Certain percentage of peers are unable to communicate directly
     * replicating NAT conditions
     */
    "INTERNAT",

    /**
     * Scale free topology.
     */
    "SCALE_FREE",

    /**
     * Straight line topology.
     */
    "LINE",

    /**
     * All peers are disconnected.
     */
    "NONE",

    /**
     * Read the topology from a file.
     */
    "FROM_FILE",

    NULL
  };

  int curr = 0;

  if (topology_string == NULL)
    return GNUNET_NO;
  while (topology_strings[curr] != NULL)
  {
    if (strcasecmp (topology_strings[curr], topology_string) == 0)
    {
      *topology = curr;
      return GNUNET_YES;
    }
    curr++;
  }
  *topology = GNUNET_TESTING_TOPOLOGY_NONE;
  return GNUNET_NO;
}

/**
 * Get connect topology option from string input.
 *
 * @param topology_option where to write the retrieved topology
 * @param topology_string The string to attempt to
 *        get a configuration value from
 * @return GNUNET_YES if string matched a known
 *         topology option, GNUNET_NO if not
 */
int
GNUNET_TESTING_topology_option_get (enum GNUNET_TESTING_TopologyOption
                                    *topology_option,
                                    const char *topology_string)
{
  /**
   * Options for connecting a topology as strings.
   */
  static const char *topology_option_strings[] = {
    /**
     * Try to connect all peers specified in the topology.
     */
    "CONNECT_ALL",

    /**
     * Choose a random subset of connections to create.
     */
    "CONNECT_RANDOM_SUBSET",

    /**
     * Create at least X connections for each peer.
     */
    "CONNECT_MINIMUM",

    /**
     * Using a depth first search, create one connection
     * per peer.  If any are missed (graph disconnected)
     * start over at those peers until all have at least one
     * connection.
     */
    "CONNECT_DFS",

    /**
     * Find the N closest peers to each allowed peer in the
     * topology and make sure a connection to those peers
     * exists in the connect topology.
     */
    "CONNECT_CLOSEST",

    /**
     * No options specified.
     */
    "CONNECT_NONE",

    NULL
  };
  int curr = 0;

  if (topology_string == NULL)
    return GNUNET_NO;
  while (NULL != topology_option_strings[curr])
  {
    if (strcasecmp (topology_option_strings[curr], topology_string) == 0)
    {
      *topology_option = curr;
      return GNUNET_YES;
    }
    curr++;
  }
  *topology_option = GNUNET_TESTING_TOPOLOGY_OPTION_NONE;
  return GNUNET_NO;
}

/**
 * Function to iterate over options.  Copies
 * the options to the target configuration,
 * updating PORT values as needed.
 *
 * @param cls closure
 * @param section name of the section
 * @param option name of the option
 * @param value value of the option
 */
static void
update_config (void *cls, const char *section, const char *option,
               const char *value)
{
  struct UpdateContext *ctx = cls;
  unsigned int ival;
  char cval[12];
  char uval[128];
  char *single_variable;
  char *per_host_variable;
  unsigned long long num_per_host;

  GNUNET_asprintf (&single_variable, "single_%s_per_host", section);
  GNUNET_asprintf (&per_host_variable, "num_%s_per_host", section);

  if ((0 == strcmp (option, "PORT")) && (1 == SSCANF (value, "%u", &ival)))
  {
    if ((ival != 0) &&
        (GNUNET_YES !=
         GNUNET_CONFIGURATION_get_value_yesno (ctx->orig, "testing",
                                               single_variable)))
    {
      GNUNET_snprintf (cval, sizeof (cval), "%u", ctx->nport++);
      value = cval;
    }
    else if ((ival != 0) &&
             (GNUNET_YES ==
              GNUNET_CONFIGURATION_get_value_yesno (ctx->orig, "testing",
                                                    single_variable)) &&
             GNUNET_CONFIGURATION_get_value_number (ctx->orig, "testing",
                                                    per_host_variable,
                                                    &num_per_host))
    {
      GNUNET_snprintf (cval, sizeof (cval), "%u",
                       ival + ctx->fdnum % num_per_host);
      value = cval;
    }

    /* FIXME: REMOVE FOREVER HACK HACK HACK */
    if (0 == strcasecmp (section, "transport-tcp"))
      GNUNET_CONFIGURATION_set_value_string (ctx->ret, section,
                                             "ADVERTISED_PORT", value);
  }

  if (0 == strcmp (option, "UNIXPATH"))
  {
    if (GNUNET_YES !=
        GNUNET_CONFIGURATION_get_value_yesno (ctx->orig, "testing",
                                              single_variable))
    {
      GNUNET_snprintf (uval, sizeof (uval), "/tmp/test-service-%s-%u", section,
                       ctx->upnum++);
      value = uval;
    }
    else if ((GNUNET_YES ==
              GNUNET_CONFIGURATION_get_value_number (ctx->orig, "testing",
                                                     per_host_variable,
                                                     &num_per_host)) &&
             (num_per_host > 0))

    {
      GNUNET_snprintf (uval, sizeof (uval), "/tmp/test-service-%s-%u", section,
                       ctx->fdnum % num_per_host);
      value = uval;
    }
  }

  if ((0 == strcmp (option, "HOSTNAME")) && (ctx->hostname != NULL))
  {
    value = ctx->hostname;
  }
  GNUNET_free (single_variable);
  GNUNET_free (per_host_variable);
  GNUNET_CONFIGURATION_set_value_string (ctx->ret, section, option, value);
}

/**
 * Create a new configuration using the given configuration
 * as a template; however, each PORT in the existing cfg
 * must be renumbered by incrementing "*port".  If we run
 * out of "*port" numbers, return NULL.
 *
 * @param cfg template configuration
 * @param off the current peer offset
 * @param port port numbers to use, update to reflect
 *             port numbers that were used
 * @param upnum number to make unix domain socket names unique
 * @param hostname hostname of the controlling host, to allow control connections from
 * @param fdnum number used to offset the unix domain socket for grouped processes
 *              (such as statistics or peerinfo, which can be shared among others)
 *
 * @return new configuration, NULL on error
 */
struct GNUNET_CONFIGURATION_Handle *
GNUNET_TESTING_create_cfg (const struct GNUNET_CONFIGURATION_Handle *cfg, uint32_t off,
             uint16_t * port, uint32_t * upnum, const char *hostname,
             uint32_t * fdnum)
{
  struct UpdateContext uc;
  uint16_t orig;
  char *control_host;
  char *allowed_hosts;
  unsigned long long skew_variance;
  unsigned long long skew_offset;
  long long actual_offset;

  orig = *port;
  uc.nport = *port;
  uc.upnum = *upnum;
  uc.fdnum = *fdnum;
  uc.ret = GNUNET_CONFIGURATION_create ();
  uc.hostname = hostname;
  uc.orig = cfg;

  GNUNET_CONFIGURATION_iterate (cfg, &update_config, &uc);
  if (uc.nport >= HIGH_PORT)
  {
    *port = orig;
    GNUNET_CONFIGURATION_destroy (uc.ret);
    return NULL;
  }

  if ((GNUNET_OK ==
       GNUNET_CONFIGURATION_get_value_number (cfg, "testing", "skew_variance",
                                              &skew_variance)) &&
      (skew_variance > 0))
  {
    skew_offset =
        GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                  skew_variance + 1);
    actual_offset =
        skew_offset - GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                                skew_variance + 1);
    /* Min is -skew_variance, Max is skew_variance */
    skew_offset = skew_variance + actual_offset;        /* Normal distribution around 0 */
    GNUNET_CONFIGURATION_set_value_number (uc.ret, "testing", "skew_offset",
                                           skew_offset);
  }

  if (GNUNET_CONFIGURATION_get_value_string
      (cfg, "testing", "control_host", &control_host) == GNUNET_OK)
  {
    if (hostname != NULL)
      GNUNET_asprintf (&allowed_hosts, "%s; 127.0.0.1; %s;", control_host,
                       hostname);
    else
      GNUNET_asprintf (&allowed_hosts, "%s; 127.0.0.1;", control_host);

    GNUNET_CONFIGURATION_set_value_string (uc.ret, "core", "ACCEPT_FROM",
                                           allowed_hosts);

    GNUNET_CONFIGURATION_set_value_string (uc.ret, "nse", "ACCEPT_FROM",
                                           allowed_hosts);

    GNUNET_CONFIGURATION_set_value_string (uc.ret, "transport", "ACCEPT_FROM",
                                           allowed_hosts);
    GNUNET_CONFIGURATION_set_value_string (uc.ret, "dht", "ACCEPT_FROM",
                                           allowed_hosts);
    GNUNET_CONFIGURATION_set_value_string (uc.ret, "statistics", "ACCEPT_FROM",
                                           allowed_hosts);

    GNUNET_CONFIGURATION_set_value_string (uc.ret, "core", "UNIXPATH", "");
    GNUNET_CONFIGURATION_set_value_string (uc.ret, "transport", "UNIXPATH", "");
    GNUNET_CONFIGURATION_set_value_string (uc.ret, "dht", "UNIXPATH", "");
    GNUNET_CONFIGURATION_set_value_string (uc.ret, "statistics", "UNIXPATH",
                                           "");
    GNUNET_CONFIGURATION_set_value_string (uc.ret, "nse", "UNIXPATH", "");

    GNUNET_CONFIGURATION_set_value_string (uc.ret, "nat",
                                           "USE_LOCALADDR", "YES");
    GNUNET_free_non_null (control_host);
    GNUNET_free (allowed_hosts);
  }

  /* arm needs to know to allow connections from the host on which it is running,
   * otherwise gnunet-arm is unable to connect to it in some instances */
  if (hostname != NULL)
  {
    GNUNET_asprintf (&allowed_hosts, "%s; 127.0.0.1;", hostname);
    GNUNET_CONFIGURATION_set_value_string (uc.ret, "nat", "BINDTO", hostname);
    GNUNET_CONFIGURATION_set_value_string (uc.ret, "nat", "INTERNAL_ADDRESS",
                                           hostname);
    GNUNET_CONFIGURATION_set_value_string (uc.ret, "nat", "EXTERNAL_ADDRESS",
                                           hostname);
    GNUNET_CONFIGURATION_set_value_string (uc.ret, "disablev6", "BINDTO",
                                           "YES");
    GNUNET_CONFIGURATION_set_value_string (uc.ret, "transport-tcp",
                                           "USE_LOCALADDR", "YES");
    GNUNET_CONFIGURATION_set_value_string (uc.ret, "transport-udp",
                                           "USE_LOCALADDR", "YES");
    GNUNET_CONFIGURATION_set_value_string (uc.ret, "arm", "ACCEPT_FROM",
                                           allowed_hosts);
    GNUNET_free (allowed_hosts);
  }
  else
  {
    GNUNET_CONFIGURATION_set_value_string (uc.ret, "nat",
                                           "USE_LOCALADDR", "YES");
    GNUNET_CONFIGURATION_set_value_string (uc.ret, "nat", "BINDTO",
                                           "127.0.0.1");
    GNUNET_CONFIGURATION_set_value_string (uc.ret, "nat", "INTERNAL_ADDRESS",
                                           "127.0.0.1");
    GNUNET_CONFIGURATION_set_value_string (uc.ret, "nat", "EXTERNAL_ADDRESS",
                                           "127.0.0.1");
    GNUNET_CONFIGURATION_set_value_string (uc.ret, "nat", "disablev6",
                                           "YES");
  }

  *port = (uint16_t) uc.nport;
  *upnum = uc.upnum;
  uc.fdnum++;
  *fdnum = uc.fdnum;
  return uc.ret;
}

/*
 * Remove entries from the peer connection list
 *
 * @param pg the peer group we are working with
 * @param first index of the first peer
 * @param second index of the second peer
 * @param list the peer list to use
 * @param check UNUSED
 *
 * @return the number of connections added (can be 0, 1 or 2)
 *
 */
static unsigned int
remove_connections (struct GNUNET_TESTING_PeerGroup *pg, unsigned int first,
                    unsigned int second, enum PeerLists list,
                    unsigned int check)
{
  int removed;

#if OLD
  struct PeerConnection **first_list;
  struct PeerConnection **second_list;
  struct PeerConnection *first_iter;
  struct PeerConnection *second_iter;
  struct PeerConnection **first_tail;
  struct PeerConnection **second_tail;

#else
  GNUNET_HashCode hash_first;
  GNUNET_HashCode hash_second;

  hash_from_uid (first, &hash_first);
  hash_from_uid (second, &hash_second);
#endif

  removed = 0;
#if OLD
  switch (list)
  {
  case ALLOWED:
    first_list = &pg->peers[first].allowed_peers_head;
    second_list = &pg->peers[second].allowed_peers_head;
    first_tail = &pg->peers[first].allowed_peers_tail;
    second_tail = &pg->peers[second].allowed_peers_tail;
    break;
  case CONNECT:
    first_list = &pg->peers[first].connect_peers_head;
    second_list = &pg->peers[second].connect_peers_head;
    first_tail = &pg->peers[first].connect_peers_tail;
    second_tail = &pg->peers[second].connect_peers_tail;
    break;
  case BLACKLIST:
    first_list = &pg->peers[first].blacklisted_peers_head;
    second_list = &pg->peers[second].blacklisted_peers_head;
    first_tail = &pg->peers[first].blacklisted_peers_tail;
    second_tail = &pg->peers[second].blacklisted_peers_tail;
    break;
  case WORKING_SET:
    first_list = &pg->peers[first].connect_peers_working_set_head;
    second_list = &pg->peers[second].connect_peers_working_set_head;
    first_tail = &pg->peers[first].connect_peers_working_set_tail;
    second_tail = &pg->peers[second].connect_peers_working_set_tail;
    break;
  default:
    GNUNET_break (0);
    return 0;
  }

  first_iter = *first_list;
  while (first_iter != NULL)
  {
    if (first_iter->index == second)
    {
      GNUNET_CONTAINER_DLL_remove (*first_list, *first_tail, first_iter);
      GNUNET_free (first_iter);
      removed++;
      break;
    }
    first_iter = first_iter->next;
  }

  second_iter = *second_list;
  while (second_iter != NULL)
  {
    if (second_iter->index == first)
    {
      GNUNET_CONTAINER_DLL_remove (*second_list, *second_tail, second_iter);
      GNUNET_free (second_iter);
      removed++;
      break;
    }
    second_iter = second_iter->next;
  }
#else
  if (GNUNET_YES ==
      GNUNET_CONTAINER_multihashmap_contains (pg->
                                              peers[first].blacklisted_peers,
                                              &hash_second))
  {
    GNUNET_CONTAINER_multihashmap_remove_all (pg->
                                              peers[first].blacklisted_peers,
                                              &hash_second);
  }

  if (GNUNET_YES ==
      GNUNET_CONTAINER_multihashmap_contains (pg->
                                              peers[second].blacklisted_peers,
                                              &hash_first))
  {
    GNUNET_CONTAINER_multihashmap_remove_all (pg->
                                              peers[second].blacklisted_peers,
                                              &hash_first);
  }
#endif

  return removed;
}

/**
 * Add entries to the some list
 *
 * @param pg the peer group we are working with
 * @param first index of the first peer
 * @param second index of the second peer
 * @param list the list type that we should modify
 * @param check GNUNET_YES to check lists before adding
 *              GNUNET_NO to force add
 *
 * @return the number of connections added (can be 0, 1 or 2)
 *
 */
static unsigned int
add_connections (struct GNUNET_TESTING_PeerGroup *pg, unsigned int first,
                 unsigned int second, enum PeerLists list, unsigned int check)
{
  int added;
  int add_first;
  int add_second;

  struct PeerConnection **first_list;
  struct PeerConnection **second_list;
  struct PeerConnection *first_iter;
  struct PeerConnection *second_iter;
  struct PeerConnection *new_first;
  struct PeerConnection *new_second;
  struct PeerConnection **first_tail;
  struct PeerConnection **second_tail;

  switch (list)
  {
  case ALLOWED:
    first_list = &pg->peers[first].allowed_peers_head;
    second_list = &pg->peers[second].allowed_peers_head;
    first_tail = &pg->peers[first].allowed_peers_tail;
    second_tail = &pg->peers[second].allowed_peers_tail;
    break;
  case CONNECT:
    first_list = &pg->peers[first].connect_peers_head;
    second_list = &pg->peers[second].connect_peers_head;
    first_tail = &pg->peers[first].connect_peers_tail;
    second_tail = &pg->peers[second].connect_peers_tail;
    break;
  case BLACKLIST:
    first_list = &pg->peers[first].blacklisted_peers_head;
    second_list = &pg->peers[second].blacklisted_peers_head;
    first_tail = &pg->peers[first].blacklisted_peers_tail;
    second_tail = &pg->peers[second].blacklisted_peers_tail;
    break;
  case WORKING_SET:
    first_list = &pg->peers[first].connect_peers_working_set_head;
    second_list = &pg->peers[second].connect_peers_working_set_head;
    first_tail = &pg->peers[first].connect_peers_working_set_tail;
    second_tail = &pg->peers[second].connect_peers_working_set_tail;
    break;
  default:
    GNUNET_break (0);
    return 0;
  }

  add_first = GNUNET_YES;
  add_second = GNUNET_YES;

  if (check == GNUNET_YES)
  {
    first_iter = *first_list;
    while (first_iter != NULL)
    {
      if (first_iter->index == second)
      {
        add_first = GNUNET_NO;
        break;
      }
      first_iter = first_iter->next;
    }

    second_iter = *second_list;
    while (second_iter != NULL)
    {
      if (second_iter->index == first)
      {
        add_second = GNUNET_NO;
        break;
      }
      second_iter = second_iter->next;
    }
  }

  added = 0;
  if (add_first)
  {
    new_first = GNUNET_malloc (sizeof (struct PeerConnection));
    new_first->index = second;
    GNUNET_CONTAINER_DLL_insert (*first_list, *first_tail, new_first);
    pg->peers[first].num_connections++;
    added++;
  }

  if (add_second)
  {
    new_second = GNUNET_malloc (sizeof (struct PeerConnection));
    new_second->index = first;
    GNUNET_CONTAINER_DLL_insert (*second_list, *second_tail, new_second);
    pg->peers[second].num_connections++;
    added++;
  }

  return added;
}

/**
 * Scale free network construction as described in:
 *
 * "Emergence of Scaling in Random Networks." Science 286, 509-512, 1999.
 *
 * Start with a network of "one" peer, then progressively add
 * peers up to the total number.  At each step, iterate over
 * all possible peers and connect new peer based on number of
 * existing connections of the target peer.
 *
 * @param pg the peer group we are dealing with
 * @param proc the connection processor to use
 * @param list the peer list to use
 *
 * @return the number of connections created
 */
static unsigned int
create_scale_free (struct GNUNET_TESTING_PeerGroup *pg,
                   GNUNET_TESTING_ConnectionProcessor proc, enum PeerLists list)
{

  unsigned int total_connections;
  unsigned int outer_count;
  unsigned int i;
  unsigned int previous_total_connections;
  double random;
  double probability;

  GNUNET_assert (pg->total > 1);

  /* Add a connection between the first two nodes */
  total_connections = proc (pg, 0, 1, list, GNUNET_YES);

  for (outer_count = 1; outer_count < pg->total; outer_count++)
  {
    previous_total_connections = total_connections;
    for (i = 0; i < outer_count; i++)
    {
      probability =
          pg->peers[i].num_connections / (double) previous_total_connections;
      random =
          ((double)
           GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                     UINT64_MAX)) / ((double) UINT64_MAX);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Considering connecting peer %d to peer %d\n", outer_count,
                  i);
      if (random < probability)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connecting peer %d to peer %d\n",
                    outer_count, i);
        total_connections += proc (pg, outer_count, i, list, GNUNET_YES);
      }
    }
  }

  return total_connections;
}

/**
 * Create a topology given a peer group (set of running peers)
 * and a connection processor.  Creates a small world topology
 * according to the rewired ring construction.  The basic
 * behavior is that a ring topology is created, but with some
 * probability instead of connecting a peer to the next
 * neighbor in the ring a connection will be created to a peer
 * selected uniformly at random.   We use the TESTING
 * PERCENTAGE option to specify what number of
 * connections each peer should have.  Default is 2,
 * which makes the ring, any given number is multiplied by
 * the log of the network size; i.e. a PERCENTAGE of 2 makes
 * each peer have on average 2logn connections.  The additional
 * connections are made at increasing distance around the ring
 * from the original peer, or to random peers based on the re-
 * wiring probability. The TESTING
 * PROBABILITY option is used as the probability that a given
 * connection is rewired.
 *
 * @param pg the peergroup to create the topology on
 * @param proc the connection processor to call to actually set
 *        up connections between two peers
 * @param list the peer list to use
 *
 * @return the number of connections that were set up
 *
 */
static unsigned int
create_small_world_ring (struct GNUNET_TESTING_PeerGroup *pg,
                         GNUNET_TESTING_ConnectionProcessor proc,
                         enum PeerLists list)
{
  unsigned int i, j;
  int nodeToConnect;
  unsigned int natLog;
  unsigned int randomPeer;
  double random, logNModifier, probability;
  unsigned int smallWorldConnections;
  int connsPerPeer;
  char *p_string;
  int max;
  int min;
  unsigned int useAnd;
  int connect_attempts;

  logNModifier = 0.5;           /* FIXME: default value? */
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_string (pg->cfg, "TESTING", "PERCENTAGE",
                                             &p_string))
  {
    if (SSCANF (p_string, "%lf", &logNModifier) != 1)
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _
                  ("Invalid value `%s' for option `%s' in section `%s': expected float\n"),
                  p_string, "LOGNMODIFIER", "TESTING");
    GNUNET_free (p_string);
  }
  probability = 0.5;            /* FIXME: default percentage? */
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_string (pg->cfg, "TESTING", "PROBABILITY",
                                             &p_string))
  {
    if (SSCANF (p_string, "%lf", &probability) != 1)
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _
                  ("Invalid value `%s' for option `%s' in section `%s': expected float\n"),
                  p_string, "PERCENTAGE", "TESTING");
    GNUNET_free (p_string);
  }
  natLog = log (pg->total);
  connsPerPeer = ceil (natLog * logNModifier);

  if (connsPerPeer % 2 == 1)
    connsPerPeer += 1;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Target is %d connections per peer.",
              connsPerPeer);

  smallWorldConnections = 0;
  connect_attempts = 0;
  for (i = 0; i < pg->total; i++)
  {
    useAnd = 0;
    max = i + connsPerPeer / 2;
    min = i - connsPerPeer / 2;

    if (max > pg->total - 1)
    {
      max = max - pg->total;
      useAnd = 1;
    }

    if (min < 0)
    {
      min = pg->total - 1 + min;
      useAnd = 1;
    }

    for (j = 0; j < connsPerPeer / 2; j++)
    {
      random =
          ((double)
           GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                     UINT64_MAX) / ((double) UINT64_MAX));
      if (random < probability)
      {
        /* Connect to uniformly selected random peer */
        randomPeer =
            GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, pg->total);
        while ((((randomPeer < max) && (randomPeer > min)) && (useAnd == 0)) ||
               (((randomPeer > min) || (randomPeer < max)) && (useAnd == 1)))
        {
          randomPeer =
              GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, pg->total);
        }
        smallWorldConnections += proc (pg, i, randomPeer, list, GNUNET_YES);
      }
      else
      {
        nodeToConnect = i + j + 1;
        if (nodeToConnect > pg->total - 1)
        {
          nodeToConnect = nodeToConnect - pg->total;
        }
        connect_attempts += proc (pg, i, nodeToConnect, list, GNUNET_YES);
      }
    }

  }

  connect_attempts += smallWorldConnections;

  return connect_attempts;
}

/**
 * Create a topology given a peer group (set of running peers)
 * and a connection processor.
 *
 * @param pg the peergroup to create the topology on
 * @param proc the connection processor to call to actually set
 *        up connections between two peers
 * @param list the peer list to use
 *
 * @return the number of connections that were set up
 *
 */
static unsigned int
create_nated_internet (struct GNUNET_TESTING_PeerGroup *pg,
                       GNUNET_TESTING_ConnectionProcessor proc,
                       enum PeerLists list)
{
  unsigned int outer_count, inner_count;
  unsigned int cutoff;
  int connect_attempts;
  double nat_percentage;
  char *p_string;

  nat_percentage = 0.6;         /* FIXME: default percentage? */
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_string (pg->cfg, "TESTING", "PERCENTAGE",
                                             &p_string))
  {
    if (SSCANF (p_string, "%lf", &nat_percentage) != 1)
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _
                  ("Invalid value `%s' for option `%s' in section `%s': expected float\n"),
                  p_string, "PERCENTAGE", "TESTING");
    GNUNET_free (p_string);
  }

  cutoff = (unsigned int) (nat_percentage * pg->total);
  connect_attempts = 0;
  for (outer_count = 0; outer_count < pg->total - 1; outer_count++)
  {
    for (inner_count = outer_count + 1; inner_count < pg->total; inner_count++)
    {
      if ((outer_count > cutoff) || (inner_count > cutoff))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connecting peer %d to peer %d\n",
                    outer_count, inner_count);
        connect_attempts +=
            proc (pg, outer_count, inner_count, list, GNUNET_YES);
      }
    }
  }
  return connect_attempts;
}

#if TOPOLOGY_HACK
/**
 * Create a topology given a peer group (set of running peers)
 * and a connection processor.
 *
 * @param pg the peergroup to create the topology on
 * @param proc the connection processor to call to actually set
 *        up connections between two peers
 * @param list the peer list to use
 *
 * @return the number of connections that were set up
 *
 */
static unsigned int
create_nated_internet_copy (struct GNUNET_TESTING_PeerGroup *pg,
                            GNUNET_TESTING_ConnectionProcessor proc,
                            enum PeerLists list)
{
  unsigned int outer_count, inner_count;
  unsigned int cutoff;
  int connect_attempts;
  double nat_percentage;
  char *p_string;
  unsigned int count;
  struct ProgressMeter *conn_meter;

  nat_percentage = 0.6;         /* FIXME: default percentage? */
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_string (pg->cfg, "TESTING", "PERCENTAGE",
                                             &p_string))
  {
    if (SSCANF (p_string, "%lf", &nat_percentage) != 1)
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _
                  ("Invalid value `%s' for option `%s' in section `%s': expected float\n"),
                  p_string, "PERCENTAGE", "TESTING");
    GNUNET_free (p_string);
  }

  cutoff = (unsigned int) (nat_percentage * pg->total);
  count = 0;
  for (outer_count = 0; outer_count < pg->total - 1; outer_count++)
  {
    for (inner_count = outer_count + 1; inner_count < pg->total; inner_count++)
    {
      if ((outer_count > cutoff) || (inner_count > cutoff))
      {
        count++;
      }
    }
  }
  conn_meter = create_meter (count, "NAT COPY", GNUNET_YES);
  connect_attempts = 0;
  for (outer_count = 0; outer_count < pg->total - 1; outer_count++)
  {
    for (inner_count = outer_count + 1; inner_count < pg->total; inner_count++)
    {
      if ((outer_count > cutoff) || (inner_count > cutoff))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connecting peer %d to peer %d\n",
                    outer_count, inner_count);
        connect_attempts +=
            proc (pg, outer_count, inner_count, list, GNUNET_YES);
        add_connections (pg, outer_count, inner_count, ALLOWED, GNUNET_NO);
        update_meter (conn_meter);
      }
    }
  }
  free_meter (conn_meter);

  return connect_attempts;
}
#endif

/**
 * Create a topology given a peer group (set of running peers)
 * and a connection processor.
 *
 * @param pg the peergroup to create the topology on
 * @param proc the connection processor to call to actually set
 *        up connections between two peers
 * @param list the peer list to use
 *
 * @return the number of connections that were set up
 *
 */
static unsigned int
create_small_world (struct GNUNET_TESTING_PeerGroup *pg,
                    GNUNET_TESTING_ConnectionProcessor proc,
                    enum PeerLists list)
{
  unsigned int i, j, k;
  unsigned int square;
  unsigned int rows;
  unsigned int cols;
  unsigned int toggle = 1;
  unsigned int nodeToConnect;
  unsigned int natLog;
  unsigned int node1Row;
  unsigned int node1Col;
  unsigned int node2Row;
  unsigned int node2Col;
  unsigned int distance;
  double probability, random, percentage;
  unsigned int smallWorldConnections;
  unsigned int small_world_it;
  char *p_string;
  int connect_attempts;

  square = floor (sqrt (pg->total));
  rows = square;
  cols = square;

  percentage = 0.5;             /* FIXME: default percentage? */
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_string (pg->cfg, "TESTING", "PERCENTAGE",
                                             &p_string))
  {
    if (SSCANF (p_string, "%lf", &percentage) != 1)
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _
                  ("Invalid value `%s' for option `%s' in section `%s': expected float\n"),
                  p_string, "PERCENTAGE", "TESTING");
    GNUNET_free (p_string);
  }
  if (percentage < 0.0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _
                ("Invalid value `%s' for option `%s' in section `%s': got %f, needed value greater than 0\n"),
                "PERCENTAGE", "TESTING", percentage);
    percentage = 0.5;
  }
  probability = 0.5;            /* FIXME: default percentage? */
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_string (pg->cfg, "TESTING", "PROBABILITY",
                                             &p_string))
  {
    if (SSCANF (p_string, "%lf", &probability) != 1)
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _
                  ("Invalid value `%s' for option `%s' in section `%s': expected float\n"),
                  p_string, "PROBABILITY", "TESTING");
    GNUNET_free (p_string);
  }
  if (square * square != pg->total)
  {
    while (rows * cols < pg->total)
    {
      if (toggle % 2 == 0)
        rows++;
      else
        cols++;

      toggle++;
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connecting nodes in 2d torus topology: %u rows %u columns\n",
              rows, cols);
  connect_attempts = 0;
  /* Rows and columns are all sorted out, now iterate over all nodes and connect each
   * to the node to its right and above.  Once this is over, we'll have our torus!
   * Special case for the last node (if the rows and columns are not equal), connect
   * to the first in the row to maintain topology.
   */
  for (i = 0; i < pg->total; i++)
  {
    /* First connect to the node to the right */
    if (((i + 1) % cols != 0) && (i + 1 != pg->total))
      nodeToConnect = i + 1;
    else if (i + 1 == pg->total)
      nodeToConnect = rows * cols - cols;
    else
      nodeToConnect = i - cols + 1;

    connect_attempts += proc (pg, i, nodeToConnect, list, GNUNET_YES);

    if (i < cols)
    {
      nodeToConnect = (rows * cols) - cols + i;
      if (nodeToConnect >= pg->total)
        nodeToConnect -= cols;
    }
    else
      nodeToConnect = i - cols;

    if (nodeToConnect < pg->total)
      connect_attempts += proc (pg, i, nodeToConnect, list, GNUNET_YES);
  }
  natLog = log (pg->total);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "natural log of %d is %d, will run %d iterations\n", pg->total,
              natLog, (int) (natLog * percentage));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Total connections added thus far: %u!\n", connect_attempts);
  smallWorldConnections = 0;
  small_world_it = (unsigned int) (natLog * percentage);
  if (small_world_it < 1)
    small_world_it = 1;
  GNUNET_assert (small_world_it > 0 && small_world_it < (unsigned int) -1);
  for (i = 0; i < small_world_it; i++)
  {
    for (j = 0; j < pg->total; j++)
    {
      /* Determine the row and column of node at position j on the 2d torus */
      node1Row = j / cols;
      node1Col = j - (node1Row * cols);
      for (k = 0; k < pg->total; k++)
      {
        /* Determine the row and column of node at position k on the 2d torus */
        node2Row = k / cols;
        node2Col = k - (node2Row * cols);
        /* Simple Cartesian distance */
        distance = abs (node1Row - node2Row) + abs (node1Col - node2Col);
        if (distance > 1)
        {
          /* Calculate probability as 1 over the square of the distance */
          probability = 1.0 / (distance * distance);
          /* Choose a random value between 0 and 1 */
          random =
              ((double)
               GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                         UINT64_MAX)) / ((double) UINT64_MAX);
          /* If random < probability, then connect the two nodes */
          if (random < probability)
            smallWorldConnections += proc (pg, j, k, list, GNUNET_YES);

        }
      }
    }
  }
  connect_attempts += smallWorldConnections;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Total connections added for small world: %d!\n",
              smallWorldConnections);
  return connect_attempts;
}

/**
 * Create a topology given a peer group (set of running peers)
 * and a connection processor.
 *
 * @param pg the peergroup to create the topology on
 * @param proc the connection processor to call to actually set
 *        up connections between two peers
 * @param list the peer list to use
 *
 * @return the number of connections that were set up
 *
 */
static unsigned int
create_erdos_renyi (struct GNUNET_TESTING_PeerGroup *pg,
                    GNUNET_TESTING_ConnectionProcessor proc,
                    enum PeerLists list)
{
  double temp_rand;
  unsigned int outer_count;
  unsigned int inner_count;
  int connect_attempts;
  double probability;
  char *p_string;

  probability = 0.5;            /* FIXME: default percentage? */
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_string (pg->cfg, "TESTING", "PROBABILITY",
                                             &p_string))
  {
    if (SSCANF (p_string, "%lf", &probability) != 1)
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _
                  ("Invalid value `%s' for option `%s' in section `%s': expected float\n"),
                  p_string, "PROBABILITY", "TESTING");
    GNUNET_free (p_string);
  }
  connect_attempts = 0;
  for (outer_count = 0; outer_count < pg->total - 1; outer_count++)
  {
    for (inner_count = outer_count + 1; inner_count < pg->total; inner_count++)
    {
      temp_rand =
          ((double)
           GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                     UINT64_MAX)) / ((double) UINT64_MAX);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "rand is %f probability is %f\n",
                  temp_rand, probability);
      if (temp_rand < probability)
      {
        connect_attempts +=
            proc (pg, outer_count, inner_count, list, GNUNET_YES);
      }
    }
  }

  return connect_attempts;
}

/**
 * Create a topology given a peer group (set of running peers)
 * and a connection processor.  This particular function creates
 * the connections for a 2d-torus, plus additional "closest"
 * connections per peer.
 *
 * @param pg the peergroup to create the topology on
 * @param proc the connection processor to call to actually set
 *        up connections between two peers
 * @param list the peer list to use
 *
 * @return the number of connections that were set up
 *
 */
static unsigned int
create_2d_torus (struct GNUNET_TESTING_PeerGroup *pg,
                 GNUNET_TESTING_ConnectionProcessor proc, enum PeerLists list)
{
  unsigned int i;
  unsigned int square;
  unsigned int rows;
  unsigned int cols;
  unsigned int toggle = 1;
  unsigned int nodeToConnect;
  int connect_attempts;

  connect_attempts = 0;

  square = floor (sqrt (pg->total));
  rows = square;
  cols = square;

  if (square * square != pg->total)
  {
    while (rows * cols < pg->total)
    {
      if (toggle % 2 == 0)
        rows++;
      else
        cols++;

      toggle++;
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connecting nodes in 2d torus topology: %u rows %u columns\n",
              rows, cols);
  /* Rows and columns are all sorted out, now iterate over all nodes and connect each
   * to the node to its right and above.  Once this is over, we'll have our torus!
   * Special case for the last node (if the rows and columns are not equal), connect
   * to the first in the row to maintain topology.
   */
  for (i = 0; i < pg->total; i++)
  {
    /* First connect to the node to the right */
    if (((i + 1) % cols != 0) && (i + 1 != pg->total))
      nodeToConnect = i + 1;
    else if (i + 1 == pg->total)
      nodeToConnect = rows * cols - cols;
    else
      nodeToConnect = i - cols + 1;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connecting peer %d to peer %d\n", i,
                nodeToConnect);
    connect_attempts += proc (pg, i, nodeToConnect, list, GNUNET_YES);

    /* Second connect to the node immediately above */
    if (i < cols)
    {
      nodeToConnect = (rows * cols) - cols + i;
      if (nodeToConnect >= pg->total)
        nodeToConnect -= cols;
    }
    else
      nodeToConnect = i - cols;

    if (nodeToConnect < pg->total)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connecting peer %d to peer %d\n", i,
                  nodeToConnect);
      connect_attempts += proc (pg, i, nodeToConnect, list, GNUNET_YES);
    }

  }

  return connect_attempts;
}

/**
 * Create a topology given a peer group (set of running peers)
 * and a connection processor.
 *
 * @param pg the peergroup to create the topology on
 * @param proc the connection processor to call to actually set
 *        up connections between two peers
 * @param list the peer list to use
 * @param check does the connection processor need to check before
 *              performing an action on the list?
 *
 * @return the number of connections that were set up
 *
 */
static unsigned int
create_clique (struct GNUNET_TESTING_PeerGroup *pg,
               GNUNET_TESTING_ConnectionProcessor proc, enum PeerLists list,
               unsigned int check)
{
  unsigned int outer_count;
  unsigned int inner_count;
  int connect_attempts;
  struct ProgressMeter *conn_meter;

  connect_attempts = 0;

  conn_meter =
      create_meter ((((pg->total * pg->total) + pg->total) / 2) - pg->total,
                    "Create Clique ", GNUNET_NO);
  for (outer_count = 0; outer_count < pg->total - 1; outer_count++)
  {
    for (inner_count = outer_count + 1; inner_count < pg->total; inner_count++)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connecting peer %d to peer %d\n",
                  outer_count, inner_count);
      connect_attempts += proc (pg, outer_count, inner_count, list, check);
      update_meter (conn_meter);
    }
  }
  reset_meter (conn_meter);
  free_meter (conn_meter);
  return connect_attempts;
}

#if !OLD
/**
 * Iterator over hash map entries.
 *
 * @param cls closure the peer group
 * @param key the key stored in the hashmap is the
 *            index of the peer to connect to
 * @param value value in the hash map, handle to the peer daemon
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
static int
unblacklist_iterator (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct UnblacklistContext *un_ctx = cls;
  uint32_t second_pos;

  uid_from_hash (key, &second_pos);

  unblacklist_connections (un_ctx->pg, un_ctx->first_uid, second_pos);

  return GNUNET_YES;
}
#endif

#if !OLD
/**
 * Create a blacklist topology based on the allowed topology
 * which disallows any connections not in the allowed topology
 * at the transport level.
 *
 * @param pg the peergroup to create the topology on
 * @param proc the connection processor to call to allow
 *        up connections between two peers
 *
 * @return the number of connections that were set up
 *
 */
static unsigned int
copy_allowed (struct GNUNET_TESTING_PeerGroup *pg,
              GNUNET_TESTING_ConnectionProcessor proc)
{
  unsigned int count;
  unsigned int total;
  struct PeerConnection *iter;

#if !OLD
  struct UnblacklistContext un_ctx;

  un_ctx.pg = pg;
#endif
  total = 0;
  for (count = 0; count < pg->total - 1; count++)
  {
#if OLD
    iter = pg->peers[count].allowed_peers_head;
    while (iter != NULL)
    {
      remove_connections (pg, count, iter->index, BLACKLIST, GNUNET_YES);
      //unblacklist_connections(pg, count, iter->index);
      iter = iter->next;
    }
#else
    un_ctx.first_uid = count;
    total +=
        GNUNET_CONTAINER_multihashmap_iterate (pg->peers[count].allowed_peers,
                                               &unblacklist_iterator, &un_ctx);
#endif
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Unblacklisted %u peers\n", total);
  return total;
}
#endif

/**
 * Create a topology given a peer group (set of running peers)
 * and a connection processor.
 *
 * @param pg the peergroup to create the topology on
 * @param proc the connection processor to call to actually set
 *        up connections between two peers
 * @param list which list should be modified
 *
 * @return the number of connections that were set up
 *
 */
static unsigned int
create_line (struct GNUNET_TESTING_PeerGroup *pg,
             GNUNET_TESTING_ConnectionProcessor proc, enum PeerLists list)
{
  unsigned int count;
  unsigned int connect_attempts;

  connect_attempts = 0;
  /* Connect each peer to the next highest numbered peer */
  for (count = 0; count < pg->total - 1; count++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connecting peer %d to peer %d\n",
                count, count + 1);
    connect_attempts += proc (pg, count, count + 1, list, GNUNET_YES);
  }

  return connect_attempts;
}

/**
 * Create a topology given a peer group (set of running peers)
 * and a connection processor.
 *
 * @param pg the peergroup to create the topology on
 * @param filename the file to read topology information from
 * @param proc the connection processor to call to actually set
 *        up connections between two peers
 * @param list the peer list to use
 *
 * @return the number of connections that were set up
 *
 */
static unsigned int
create_from_file (struct GNUNET_TESTING_PeerGroup *pg, char *filename,
                  GNUNET_TESTING_ConnectionProcessor proc, enum PeerLists list)
{
  int connect_attempts;
  unsigned int first_peer_index;
  unsigned int second_peer_index;
  struct stat frstat;
  int count;
  char *data;
  const char *buf;
  unsigned int total_peers;
  enum States curr_state;

  connect_attempts = 0;
  if (GNUNET_OK != GNUNET_DISK_file_test (filename))
    GNUNET_DISK_fn_write (filename, NULL, 0, GNUNET_DISK_PERM_USER_READ);

  if ((0 != STAT (filename, &frstat)) || (frstat.st_size == 0))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not open file `%s' specified for topology!", filename);
    return connect_attempts;
  }

  data = GNUNET_malloc_large (frstat.st_size);
  GNUNET_assert (data != NULL);
  if (frstat.st_size != GNUNET_DISK_fn_read (filename, data, frstat.st_size))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not read file %s specified for host list, ending test!",
                filename);
    GNUNET_free (data);
    return connect_attempts;
  }

  buf = data;
  count = 0;
  first_peer_index = 0;
  /* First line should contain a single integer, specifying the number of peers */
  /* Each subsequent line should contain this format PEER_INDEX:OTHER_PEER_INDEX[,...] */
  curr_state = NUM_PEERS;
  while (count < frstat.st_size - 1)
  {
    if ((buf[count] == '\n') || (buf[count] == ' '))
    {
      count++;
      continue;
    }

    switch (curr_state)
    {
    case NUM_PEERS:
      errno = 0;
      total_peers = strtoul (&buf[count], NULL, 10);
      if (errno != 0)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    "Failed to read number of peers from topology file!\n");
        GNUNET_free (data);
        return connect_attempts;
      }
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Found %u total peers in topology\n",
                  total_peers);
      GNUNET_assert (total_peers == pg->total);
      curr_state = PEER_INDEX;
      while ((buf[count] != '\n') && (count < frstat.st_size - 1))
        count++;
      count++;
      break;
    case PEER_INDEX:
      errno = 0;
      first_peer_index = strtoul (&buf[count], NULL, 10);
      if (errno != 0)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    "Failed to read peer index from topology file!\n");
        GNUNET_free (data);
        return connect_attempts;
      }
      while ((buf[count] != ':') && (count < frstat.st_size - 1))
        count++;
      count++;
      curr_state = OTHER_PEER_INDEX;
      break;
    case COLON:
      if (1 == sscanf (&buf[count], ":"))
        curr_state = OTHER_PEER_INDEX;
      count++;
      break;
    case OTHER_PEER_INDEX:
      errno = 0;
      second_peer_index = strtoul (&buf[count], NULL, 10);
      if (errno != 0)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    "Failed to peer index from topology file!\n");
        GNUNET_free (data);
        return connect_attempts;
      }
      /* Assume file is written with first peer 1, but array index is 0 */
      connect_attempts +=
          proc (pg, first_peer_index - 1, second_peer_index - 1, list,
                GNUNET_YES);
      while ((buf[count] != '\n') && (buf[count] != ',') &&
             (count < frstat.st_size - 1))
        count++;
      if (buf[count] == '\n')
      {
        curr_state = PEER_INDEX;
      }
      else if (buf[count] != ',')
      {
        curr_state = OTHER_PEER_INDEX;
      }
      count++;
      break;
    default:
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Found bad data in topology file while in state %d!\n",
                  curr_state);
      GNUNET_break (0);
      GNUNET_free (data);
      return connect_attempts;
    }
  }
  GNUNET_free (data);
  return connect_attempts;
}

/**
 * Create a topology given a peer group (set of running peers)
 * and a connection processor.
 *
 * @param pg the peergroup to create the topology on
 * @param proc the connection processor to call to actually set
 *        up connections between two peers
 * @param list the peer list to use
 *
 * @return the number of connections that were set up
 *
 */
static unsigned int
create_ring (struct GNUNET_TESTING_PeerGroup *pg,
             GNUNET_TESTING_ConnectionProcessor proc, enum PeerLists list)
{
  unsigned int count;
  int connect_attempts;

  connect_attempts = 0;

  /* Connect each peer to the next highest numbered peer */
  for (count = 0; count < pg->total - 1; count++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connecting peer %d to peer %d\n",
                count, count + 1);
    connect_attempts += proc (pg, count, count + 1, list, GNUNET_YES);
  }

  /* Connect the last peer to the first peer */
  connect_attempts += proc (pg, pg->total - 1, 0, list, GNUNET_YES);

  return connect_attempts;
}

#if !OLD
/**
 * Iterator for writing friends of a peer to a file.
 *
 * @param cls closure, an open writable file handle
 * @param key the key the daemon was stored under
 * @param value the GNUNET_TESTING_Daemon that needs to be written.
 *
 * @return GNUNET_YES to continue iteration
 *
 * TODO: Could replace friend_file_iterator and blacklist_file_iterator
 *       with a single file_iterator that takes a closure which contains
 *       the prefix to write before the peer.  Then this could be used
 *       for blacklisting multiple transports and writing the friend
 *       file.  I'm sure *someone* will complain loudly about other
 *       things that negate these functions even existing so no point in
 *       "fixing" now.
 */
static int
friend_file_iterator (void *cls, const GNUNET_HashCode * key, void *value)
{
  FILE *temp_friend_handle = cls;
  struct GNUNET_TESTING_Daemon *peer = value;
  struct GNUNET_PeerIdentity *temppeer;
  struct GNUNET_CRYPTO_HashAsciiEncoded peer_enc;

  temppeer = &peer->id;
  GNUNET_CRYPTO_hash_to_enc (&temppeer->hashPubKey, &peer_enc);
  FPRINTF (temp_friend_handle, "%s\n", (char *) &peer_enc);

  return GNUNET_YES;
}

struct BlacklistContext
{
  /*
   * The (open) file handle to write to
   */
  FILE *temp_file_handle;

  /*
   * The transport that this peer will be blacklisted on.
   */
  char *transport;
};

/**
 * Iterator for writing blacklist data to appropriate files.
 *
 * @param cls closure, an open writable file handle
 * @param key the key the daemon was stored under
 * @param value the GNUNET_TESTING_Daemon that needs to be written.
 *
 * @return GNUNET_YES to continue iteration
 */
static int
blacklist_file_iterator (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct BlacklistContext *blacklist_ctx = cls;
  struct GNUNET_TESTING_Daemon *peer = value;
  struct GNUNET_PeerIdentity *temppeer;
  struct GNUNET_CRYPTO_HashAsciiEncoded peer_enc;

  temppeer = &peer->id;
  GNUNET_CRYPTO_hash_to_enc (&temppeer->hashPubKey, &peer_enc);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Writing entry %s:%s to file\n",
              blacklist_ctx->transport, (char *) &peer_enc);
  FPRINTF (blacklist_ctx->temp_file_handle, "%s:%s\n", blacklist_ctx->transport,
           (char *) &peer_enc);

  return GNUNET_YES;
}
#endif

/*
 * Create the friend files based on the PeerConnection's
 * of each peer in the peer group, and copy the files
 * to the appropriate place
 *
 * @param pg the peer group we are dealing with
 */
static int
create_and_copy_friend_files (struct GNUNET_TESTING_PeerGroup *pg)
{
  FILE *temp_friend_handle;
  unsigned int pg_iter;
  char *temp_service_path;
  struct GNUNET_OS_Process **procarr;
  char *arg;
  char *mytemp;

#if NOT_STUPID
  enum GNUNET_OS_ProcessStatusType type;
  unsigned long return_code;
  int count;
  int max_wait = 10;
#endif
  int ret;

  ret = GNUNET_OK;
#if OLD
  struct GNUNET_CRYPTO_HashAsciiEncoded peer_enc;
  struct PeerConnection *conn_iter;
#endif
  procarr = GNUNET_malloc (sizeof (struct GNUNET_OS_Process *) * pg->total);
  for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
  {
    mytemp = GNUNET_DISK_mktemp ("friends");
    GNUNET_assert (mytemp != NULL);
    temp_friend_handle = FOPEN (mytemp, "wt");
    GNUNET_assert (temp_friend_handle != NULL);
#if OLD
    conn_iter = pg->peers[pg_iter].allowed_peers_head;
    while (conn_iter != NULL)
    {
      GNUNET_CRYPTO_hash_to_enc (&pg->peers[conn_iter->index].daemon->
                                 id.hashPubKey, &peer_enc);
      FPRINTF (temp_friend_handle, "%s\n", (char *) &peer_enc);
      conn_iter = conn_iter->next;
    }
#else
    GNUNET_CONTAINER_multihashmap_iterate (pg->peers[pg_iter].allowed_peers,
                                           &friend_file_iterator,
                                           temp_friend_handle);
#endif
    FCLOSE (temp_friend_handle);

    if (GNUNET_OK !=
        GNUNET_CONFIGURATION_get_value_string (pg->peers[pg_iter].daemon->cfg,
                                               "PATHS", "SERVICEHOME",
                                               &temp_service_path))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _
                  ("No `%s' specified in peer configuration in section `%s', cannot copy friends file!\n"),
                  "SERVICEHOME", "PATHS");
      if (UNLINK (mytemp) != 0)
        GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink", mytemp);
      GNUNET_free (mytemp);
      break;
    }

    if (pg->peers[pg_iter].daemon->hostname == NULL)    /* Local, just copy the file */
    {
      GNUNET_asprintf (&arg, "%s/friends", temp_service_path);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Copying file with RENAME(%s,%s)\n", mytemp, arg);
      RENAME (mytemp, arg);
      procarr[pg_iter] = NULL;
      GNUNET_free (arg);
    }
    else                        /* Remote, scp the file to the correct place */
    {
      if (NULL != pg->peers[pg_iter].daemon->username)
        GNUNET_asprintf (&arg, "%s@%s:%s/friends",
                         pg->peers[pg_iter].daemon->username,
                         pg->peers[pg_iter].daemon->hostname,
                         temp_service_path);
      else
        GNUNET_asprintf (&arg, "%s:%s/friends",
                         pg->peers[pg_iter].daemon->hostname,
                         temp_service_path);
      procarr[pg_iter] =
	GNUNET_OS_start_process (GNUNET_NO, NULL, NULL, "scp", "scp", mytemp, arg, NULL);
      GNUNET_assert (procarr[pg_iter] != NULL);
      ret = GNUNET_OS_process_wait (procarr[pg_iter]);  /* FIXME: schedule this, throttle! */
      GNUNET_OS_process_destroy (procarr[pg_iter]);
      if (ret != GNUNET_OK)
      {
        /* FIXME: free contents of 'procarr' array */
        GNUNET_free (procarr);
        GNUNET_free (temp_service_path);
        GNUNET_free (mytemp);
        GNUNET_free (arg);
        return ret;
      }
      procarr[pg_iter] = NULL;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Copying file with command scp %s %s\n", mytemp, arg);
      GNUNET_free (arg);
    }
    GNUNET_free (temp_service_path);
    GNUNET_free (mytemp);
  }

#if NOT_STUPID
  count = 0;
  ret = GNUNET_SYSERR;
  while ((count < max_wait) && (ret != GNUNET_OK))
  {
    ret = GNUNET_OK;
    for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Checking copy status of file %d\n",
                  pg_iter);
      if (procarr[pg_iter] != NULL)     /* Check for already completed! */
      {
        if (GNUNET_OS_process_status (procarr[pg_iter], &type, &return_code) !=
            GNUNET_OK)
        {
          ret = GNUNET_SYSERR;
        }
        else if ((type != GNUNET_OS_PROCESS_EXITED) || (return_code != 0))
        {
          ret = GNUNET_SYSERR;
        }
        else
        {
          GNUNET_OS_process_destroy (procarr[pg_iter]);
          procarr[pg_iter] = NULL;
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "File %d copied\n", pg_iter);
        }
      }
    }
    count++;
    if (ret == GNUNET_SYSERR)
    {
      /* FIXME: why sleep here? -CG */
      sleep (1);
    }
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Finished copying all friend files!\n");
#endif
  GNUNET_free (procarr);
  return ret;
}

/*
 * Create the blacklist files based on the PeerConnection's
 * of each peer in the peer group, and copy the files
 * to the appropriate place.
 *
 * @param pg the peer group we are dealing with
 * @param transports space delimited list of transports to blacklist
 */
static int
create_and_copy_blacklist_files (struct GNUNET_TESTING_PeerGroup *pg,
                                 const char *transports)
{
  FILE *temp_file_handle;
  unsigned int pg_iter;
  char *temp_service_path;
  struct GNUNET_OS_Process **procarr;
  char *arg;
  char *mytemp;
  enum GNUNET_OS_ProcessStatusType type;
  unsigned long return_code;
  int count;
  int ret;
  int max_wait = 10;
  int transport_len;
  unsigned int i;
  char *pos;
  char *temp_transports;

#if OLD
  struct GNUNET_CRYPTO_HashAsciiEncoded peer_enc;
  struct PeerConnection *conn_iter;
#else
  static struct BlacklistContext blacklist_ctx;
#endif

  procarr = GNUNET_malloc (sizeof (struct GNUNET_OS_Process *) * pg->total);
  for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
  {
    mytemp = GNUNET_DISK_mktemp ("blacklist");
    GNUNET_assert (mytemp != NULL);
    temp_file_handle = FOPEN (mytemp, "wt");
    GNUNET_assert (temp_file_handle != NULL);
    temp_transports = GNUNET_strdup (transports);
#if !OLD
    blacklist_ctx.temp_file_handle = temp_file_handle;
#endif
    transport_len = strlen (temp_transports) + 1;
    pos = NULL;

    for (i = 0; i < transport_len; i++)
    {
      if ((temp_transports[i] == ' ') && (pos == NULL))
        continue;               /* At start of string (whitespace) */
      else if ((temp_transports[i] == ' ') || (temp_transports[i] == '\0'))     /* At end of string */
      {
        temp_transports[i] = '\0';
#if OLD
        conn_iter = pg->peers[pg_iter].blacklisted_peers_head;
        while (conn_iter != NULL)
        {
          GNUNET_CRYPTO_hash_to_enc (&pg->peers[conn_iter->index].daemon->
                                     id.hashPubKey, &peer_enc);
          FPRINTF (temp_file_handle, "%s:%s\n", pos, (char *) &peer_enc);
          conn_iter = conn_iter->next;
        }
#else
        blacklist_ctx.transport = pos;
        (void) GNUNET_CONTAINER_multihashmap_iterate (pg->
                                                      peers
                                                      [pg_iter].blacklisted_peers,
                                                      &blacklist_file_iterator,
                                                      &blacklist_ctx);
#endif
        pos = NULL;
      }                         /* At beginning of actual string */
      else if (pos == NULL)
      {
        pos = &temp_transports[i];
      }
    }

    GNUNET_free (temp_transports);
    FCLOSE (temp_file_handle);

    if (GNUNET_OK !=
        GNUNET_CONFIGURATION_get_value_string (pg->peers[pg_iter].daemon->cfg,
                                               "PATHS", "SERVICEHOME",
                                               &temp_service_path))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _
                  ("No `%s' specified in peer configuration in section `%s', cannot copy friends file!\n"),
                  "SERVICEHOME", "PATHS");
      if (UNLINK (mytemp) != 0)
        GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink", mytemp);
      GNUNET_free (mytemp);
      break;
    }

    if (pg->peers[pg_iter].daemon->hostname == NULL)    /* Local, just copy the file */
    {
      GNUNET_asprintf (&arg, "%s/blacklist", temp_service_path);
      RENAME (mytemp, arg);
      procarr[pg_iter] = NULL;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Copying file with RENAME (%s,%s)\n", mytemp, arg);
      GNUNET_free (arg);
    }
    else                        /* Remote, scp the file to the correct place */
    {
      if (NULL != pg->peers[pg_iter].daemon->username)
        GNUNET_asprintf (&arg, "%s@%s:%s/blacklist",
                         pg->peers[pg_iter].daemon->username,
                         pg->peers[pg_iter].daemon->hostname,
                         temp_service_path);
      else
        GNUNET_asprintf (&arg, "%s:%s/blacklist",
                         pg->peers[pg_iter].daemon->hostname,
                         temp_service_path);
      procarr[pg_iter] =
	GNUNET_OS_start_process (GNUNET_NO, NULL, NULL, "scp", "scp", mytemp, arg, NULL);
      GNUNET_assert (procarr[pg_iter] != NULL);
      GNUNET_OS_process_wait (procarr[pg_iter]);        /* FIXME: add scheduled blacklist file copy that parallelizes file copying! */

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Copying file with command scp %s %s\n", mytemp, arg);
      GNUNET_free (arg);
    }
    GNUNET_free (temp_service_path);
    GNUNET_free (mytemp);
  }

  count = 0;
  ret = GNUNET_SYSERR;
  while ((count < max_wait) && (ret != GNUNET_OK))
  {
    ret = GNUNET_OK;
    for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Checking copy status of file %d\n", pg_iter);
      if (procarr[pg_iter] != NULL)     /* Check for already completed! */
      {
        if (GNUNET_OS_process_status (procarr[pg_iter], &type, &return_code) !=
            GNUNET_OK)
        {
          ret = GNUNET_SYSERR;
        }
        else if ((type != GNUNET_OS_PROCESS_EXITED) || (return_code != 0))
        {
          ret = GNUNET_SYSERR;
        }
        else
        {
          GNUNET_OS_process_destroy (procarr[pg_iter]);
          procarr[pg_iter] = NULL;
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "File %d copied\n", pg_iter);
        }
      }
    }
    count++;
    if (ret == GNUNET_SYSERR)
    {
      /* FIXME: why sleep here? -CG */
      sleep (1);
    }
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Finished copying all blacklist files!\n");
  GNUNET_free (procarr);
  return ret;
}

/* Forward Declaration */
static void
schedule_connect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

/**
 * Choose a random peer's next connection to create, and
 * call schedule_connect to set up the connect task.
 *
 * @param pg the peer group to connect
 */
static void
preschedule_connect (struct GNUNET_TESTING_PeerGroup *pg)
{
  struct ConnectTopologyContext *ct_ctx = &pg->ct_ctx;
  struct PeerConnection *connection_iter;
  struct ConnectContext *connect_context;
  uint32_t random_peer;

  if (ct_ctx->remaining_connections == 0)
    return;
  random_peer =
      GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, pg->total);
  while (pg->peers[random_peer].connect_peers_head == NULL)
    random_peer =
        GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, pg->total);

  connection_iter = pg->peers[random_peer].connect_peers_head;
  connect_context = GNUNET_malloc (sizeof (struct ConnectContext));
  connect_context->first_index = random_peer;
  connect_context->second_index = connection_iter->index;
  connect_context->ct_ctx = ct_ctx;
  connect_context->task =
      GNUNET_SCHEDULER_add_now (&schedule_connect, connect_context);
  GNUNET_CONTAINER_DLL_insert (pg->cc_head, pg->cc_tail, connect_context);
  GNUNET_CONTAINER_DLL_remove (pg->peers[random_peer].connect_peers_head,
                               pg->peers[random_peer].connect_peers_tail,
                               connection_iter);
  GNUNET_free (connection_iter);
  ct_ctx->remaining_connections--;
}

#if USE_SEND_HELLOS
/* Forward declaration */
static void
schedule_send_hellos (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

/**
 * Close connections and free the hello context.
 *
 * @param cls the 'struct SendHelloContext *'
 * @param tc scheduler context
 */
static void
free_hello_context (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct SendHelloContext *send_hello_context = cls;

  if (send_hello_context->peer->daemon->server != NULL)
  {
    GNUNET_CORE_disconnect (send_hello_context->peer->daemon->server);
    send_hello_context->peer->daemon->server = NULL;
  }
  if (send_hello_context->peer->daemon->th != NULL)
  {
    GNUNET_TRANSPORT_disconnect (send_hello_context->peer->daemon->th);
    send_hello_context->peer->daemon->th = NULL;
  }
  if (send_hello_context->core_connect_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (send_hello_context->core_connect_task);
    send_hello_context->core_connect_task = GNUNET_SCHEDULER_NO_TASK;
  }
  send_hello_context->pg->outstanding_connects--;
  GNUNET_free (send_hello_context);
}

/**
 * For peers that haven't yet connected, notify
 * the caller that they have failed (timeout).
 *
 * @param cls the 'struct SendHelloContext *'
 * @param tc scheduler context
 */
static void
notify_remaining_connections_failed (void *cls,
                                     const struct GNUNET_SCHEDULER_TaskContext
                                     *tc)
{
  struct SendHelloContext *send_hello_context = cls;
  struct GNUNET_TESTING_PeerGroup *pg = send_hello_context->pg;
  struct PeerConnection *connection;

  GNUNET_CORE_disconnect (send_hello_context->peer->daemon->server);
  send_hello_context->peer->daemon->server = NULL;

  connection = send_hello_context->peer->connect_peers_head;

  while (connection != NULL)
  {
    if (pg->notify_connection != NULL)
    {
      pg->notify_connection (pg->notify_connection_cls, &send_hello_context->peer->daemon->id, &pg->peers[connection->index].daemon->id, 0,     /* FIXME */
                             send_hello_context->peer->daemon->cfg,
                             pg->peers[connection->index].daemon->cfg,
                             send_hello_context->peer->daemon,
                             pg->peers[connection->index].daemon,
                             "Peers failed to connect (timeout)");
    }
    GNUNET_CONTAINER_DLL_remove (send_hello_context->peer->connect_peers_head,
                                 send_hello_context->peer->connect_peers_tail,
                                 connection);
    GNUNET_free (connection);
    connection = connection->next;
  }
  GNUNET_SCHEDULER_add_now (&free_hello_context, send_hello_context);
#if BAD
  other_peer = &pg->peers[connection->index];
#endif
}

/**
 * For peers that haven't yet connected, send
 * CORE connect requests.
 *
 * @param cls the 'struct SendHelloContext *'
 * @param tc scheduler context
 */
static void
send_core_connect_requests (void *cls,
                            const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct SendHelloContext *send_hello_context = cls;
  struct PeerConnection *conn;

  GNUNET_assert (send_hello_context->peer->daemon->server != NULL);

  send_hello_context->core_connect_task = GNUNET_SCHEDULER_NO_TASK;

  send_hello_context->connect_attempts++;
  if (send_hello_context->connect_attempts <
      send_hello_context->pg->ct_ctx.connect_attempts)
  {
    conn = send_hello_context->peer->connect_peers_head;
    while (conn != NULL)
    {
      GNUNET_TRANSPORT_try_connect (send_hello_context->peer->daemon->th,
                                    &send_hello_context->pg->peers[conn->
                                                                   index].daemon->
                                    id);
      conn = conn->next;
    }
    send_hello_context->core_connect_task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_divide
                                      (send_hello_context->pg->
                                       ct_ctx.connect_timeout,
                                       send_hello_context->pg->
                                       ct_ctx.connect_attempts),
                                      &send_core_connect_requests,
                                      send_hello_context);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Timeout before all connections created, marking rest as failed!\n");
    GNUNET_SCHEDULER_add_now (&notify_remaining_connections_failed,
                              send_hello_context);
  }

}

/**
 * Success, connection is up.  Signal client our success.
 *
 * @param cls our "struct SendHelloContext"
 * @param peer identity of the peer that has connected
 * @param atsi performance information
 *
 * FIXME: remove peers from BOTH lists, call notify twice, should
 * double the speed of connections as long as the list iteration
 * doesn't take too long!
 */
static void
core_connect_notify (void *cls, const struct GNUNET_PeerIdentity *peer,
                     const struct GNUNET_ATS_Information *atsi)
{
  struct SendHelloContext *send_hello_context = cls;
  struct PeerConnection *connection;
  struct GNUNET_TESTING_PeerGroup *pg = send_hello_context->pg;

#if BAD
  struct PeerData *other_peer;
#endif
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connected peer %s to peer %s\n",
              ctx->d1->shortname, GNUNET_i2s (peer));
  if (0 ==
      memcmp (&send_hello_context->peer->daemon->id, peer,
              sizeof (struct GNUNET_PeerIdentity)))
    return;

  connection = send_hello_context->peer->connect_peers_head;
#if BAD
  other_peer = NULL;
#endif

  while ((connection != NULL) &&
         (0 !=
          memcmp (&pg->peers[connection->index].daemon->id, peer,
                  sizeof (struct GNUNET_PeerIdentity))))
  {
    connection = connection->next;
  }

  if (connection == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Connected peer %s to %s, not in list (no problem(?))\n",
                GNUNET_i2s (peer), send_hello_context->peer->daemon->shortname);
  }
  else
  {
#if BAD
    other_peer = &pg->peers[connection->index];
#endif
    if (pg->notify_connection != NULL)
    {
      pg->notify_connection (pg->notify_connection_cls, &send_hello_context->peer->daemon->id, peer, 0, /* FIXME */
                             send_hello_context->peer->daemon->cfg,
                             pg->peers[connection->index].daemon->cfg,
                             send_hello_context->peer->daemon,
                             pg->peers[connection->index].daemon, NULL);
    }
    GNUNET_CONTAINER_DLL_remove (send_hello_context->peer->connect_peers_head,
                                 send_hello_context->peer->connect_peers_tail,
                                 connection);
    GNUNET_free (connection);
  }

#if BAD
  /* Notify of reverse connection and remove from other peers list of outstanding */
  if (other_peer != NULL)
  {
    connection = other_peer->connect_peers_head;
    while ((connection != NULL) &&
           (0 !=
            memcmp (&send_hello_context->peer->daemon->id,
                    &pg->peers[connection->index].daemon->id,
                    sizeof (struct GNUNET_PeerIdentity))))
    {
      connection = connection->next;
    }
    if (connection != NULL)
    {
      if (pg->notify_connection != NULL)
      {
        pg->notify_connection (pg->notify_connection_cls, peer, &send_hello_context->peer->daemon->id, 0,       /* FIXME */
                               pg->peers[connection->index].daemon->cfg,
                               send_hello_context->peer->daemon->cfg,
                               pg->peers[connection->index].daemon,
                               send_hello_context->peer->daemon, NULL);
      }

      GNUNET_CONTAINER_DLL_remove (other_peer->connect_peers_head,
                                   other_peer->connect_peers_tail, connection);
      GNUNET_free (connection);
    }
  }
#endif

  if (send_hello_context->peer->connect_peers_head == NULL)
  {
    GNUNET_SCHEDULER_add_now (&free_hello_context, send_hello_context);
  }
}

/**
 * Notify of a successful connection to the core service.
 *
 * @param cls a struct SendHelloContext *
 * @param server handle to the core service
 * @param my_identity the peer identity of this peer
 */
void
core_init (void *cls, struct GNUNET_CORE_Handle *server,
           struct GNUNET_PeerIdentity *my_identity)
{
  struct SendHelloContext *send_hello_context = cls;

  send_hello_context->core_ready = GNUNET_YES;
}

/**
 * Function called once a hello has been sent
 * to the transport, move on to the next one
 * or go away forever.
 *
 * @param cls the 'struct SendHelloContext *'
 * @param tc scheduler context
 */
static void
hello_sent_callback (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct SendHelloContext *send_hello_context = cls;

  //unsigned int pg_iter;
  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
  {
    GNUNET_free (send_hello_context);
    return;
  }

  send_hello_context->pg->remaining_hellos--;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sent HELLO, have %d remaining!\n",
              send_hello_context->pg->remaining_hellos);
  if (send_hello_context->peer_pos == NULL)     /* All HELLOs (for this peer!) have been transmitted! */
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "All hellos for this peer sent, disconnecting transport!\n");
    GNUNET_assert (send_hello_context->peer->daemon->th != NULL);
    GNUNET_TRANSPORT_disconnect (send_hello_context->peer->daemon->th);
    send_hello_context->peer->daemon->th = NULL;
    GNUNET_assert (send_hello_context->peer->daemon->server == NULL);
    send_hello_context->peer->daemon->server =
        GNUNET_CORE_connect (send_hello_context->peer->cfg, 1,
                             send_hello_context, &core_init,
                             &core_connect_notify, NULL, NULL, NULL, GNUNET_NO,
                             NULL, GNUNET_NO, no_handlers);

    send_hello_context->core_connect_task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_divide
                                      (send_hello_context->pg->
                                       ct_ctx.connect_timeout,
                                       send_hello_context->pg->
                                       ct_ctx.connect_attempts),
                                      &send_core_connect_requests,
                                      send_hello_context);
  }
  else
    GNUNET_SCHEDULER_add_now (&schedule_send_hellos, send_hello_context);
}

/**
 * Connect to a peer, give it all the HELLO's of those peers
 * we will later ask it to connect to.
 *
 * @param ct_ctx the overall connection context
 */
static void
schedule_send_hellos (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct SendHelloContext *send_hello_context = cls;
  struct GNUNET_TESTING_PeerGroup *pg = send_hello_context->pg;

  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
  {
    GNUNET_free (send_hello_context);
    return;
  }

  GNUNET_assert (send_hello_context->peer_pos != NULL); /* All of the HELLO sends to be scheduled have been scheduled! */

  if (((send_hello_context->peer->daemon->th == NULL) &&
       (pg->outstanding_connects > pg->max_outstanding_connections)) ||
      (pg->stop_connects == GNUNET_YES))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Delaying connect, we have too many outstanding connections!\n");
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_MILLISECONDS, 100),
                                  &schedule_send_hellos, send_hello_context);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Creating connection, outstanding_connections is %d\n",
                outstanding_connects);
    if (send_hello_context->peer->daemon->th == NULL)
    {
      pg->outstanding_connects++;       /* Actual TRANSPORT, CORE connections! */
      send_hello_context->peer->daemon->th =
          GNUNET_TRANSPORT_connect (send_hello_context->peer->cfg, NULL,
                                    send_hello_context, NULL, NULL, NULL);
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Offering HELLO of peer %s to peer %s\n",
                send_hello_context->peer->daemon->shortname,
                pg->peers[send_hello_context->peer_pos->index].
                daemon->shortname);
    GNUNET_TRANSPORT_offer_hello (send_hello_context->peer->daemon->th,
                                  (const struct GNUNET_MessageHeader *)
                                  pg->peers[send_hello_context->peer_pos->
                                            index].daemon->hello,
                                  &hello_sent_callback, send_hello_context);
    send_hello_context->peer_pos = send_hello_context->peer_pos->next;
    GNUNET_assert (send_hello_context->peer->daemon->th != NULL);
  }
}
#endif

/**
 * Internal notification of a connection, kept so that we can ensure some connections
 * happen instead of flooding all testing daemons with requests to connect.
 */
static void
internal_connect_notify (void *cls, const struct GNUNET_PeerIdentity *first,
                         const struct GNUNET_PeerIdentity *second,
                         uint32_t distance,
                         const struct GNUNET_CONFIGURATION_Handle *first_cfg,
                         const struct GNUNET_CONFIGURATION_Handle *second_cfg,
                         struct GNUNET_TESTING_Daemon *first_daemon,
                         struct GNUNET_TESTING_Daemon *second_daemon,
                         const char *emsg)
{
  struct ConnectContext *connect_ctx = cls;
  struct ConnectTopologyContext *ct_ctx = connect_ctx->ct_ctx;
  struct GNUNET_TESTING_PeerGroup *pg = ct_ctx->pg;
  struct PeerConnection *connection;

  GNUNET_assert (NULL != connect_ctx->cc);
  connect_ctx->cc = NULL;
  GNUNET_assert (0 < pg->outstanding_connects);
  pg->outstanding_connects--;
  GNUNET_CONTAINER_DLL_remove (pg->cc_head, pg->cc_tail, connect_ctx);
  /*
   * Check whether the inverse connection has been scheduled yet,
   * if not, we can remove it from the other peers list and avoid
   * even trying to connect them again!
   */
  connection = pg->peers[connect_ctx->second_index].connect_peers_head;
#if BAD
  other_peer = NULL;
#endif

  while ((connection != NULL) &&
         (0 !=
          memcmp (first, &pg->peers[connection->index].daemon->id,
                  sizeof (struct GNUNET_PeerIdentity))))
    connection = connection->next;

  if (connection != NULL)       /* Can safely remove! */
  {
    GNUNET_assert (0 < ct_ctx->remaining_connections);
    ct_ctx->remaining_connections--;
    if (pg->notify_connection != NULL)  /* Notify of reverse connection */
      pg->notify_connection (pg->notify_connection_cls, second, first, distance,
                             second_cfg, first_cfg, second_daemon, first_daemon,
                             emsg);

    GNUNET_CONTAINER_DLL_remove (pg->
                                 peers[connect_ctx->
                                       second_index].connect_peers_head,
                                 pg->peers[connect_ctx->
                                           second_index].connect_peers_tail,
                                 connection);
    GNUNET_free (connection);
  }

  if (ct_ctx->remaining_connections == 0)
  {
    if (ct_ctx->notify_connections_done != NULL)
    {
      ct_ctx->notify_connections_done (ct_ctx->notify_cls, NULL);
      ct_ctx->notify_connections_done = NULL;
    }
  }
  else
    preschedule_connect (pg);

  if (pg->notify_connection != NULL)
    pg->notify_connection (pg->notify_connection_cls, first, second, distance,
                           first_cfg, second_cfg, first_daemon, second_daemon,
                           emsg);
  GNUNET_free (connect_ctx);
}

/**
 * Either delay a connection (because there are too many outstanding)
 * or schedule it for right now.
 *
 * @param cls a connection context
 * @param tc the task runtime context
 */
static void
schedule_connect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ConnectContext *connect_context = cls;
  struct GNUNET_TESTING_PeerGroup *pg = connect_context->ct_ctx->pg;

  connect_context->task = GNUNET_SCHEDULER_NO_TASK;
  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;

  if ((pg->outstanding_connects > pg->max_outstanding_connections) ||
      (pg->stop_connects == GNUNET_YES))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Delaying connect, we have too many outstanding connections!\n");
    connect_context->task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                      (GNUNET_TIME_UNIT_MILLISECONDS, 100),
                                      &schedule_connect, connect_context);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Creating connection, outstanding_connections is %d (max %d)\n",
              pg->outstanding_connects, pg->max_outstanding_connections);
  pg->outstanding_connects++;
  pg->total_connects_scheduled++;
  GNUNET_assert (NULL == connect_context->cc);
  connect_context->cc =
      GNUNET_TESTING_daemons_connect (pg->
                                      peers[connect_context->
                                            first_index].daemon,
                                      pg->peers[connect_context->
                                                second_index].daemon,
                                      connect_context->ct_ctx->connect_timeout,
                                      connect_context->ct_ctx->connect_attempts,
#if USE_SEND_HELLOS
                                      GNUNET_NO,
#else
                                      GNUNET_YES,
#endif
                                      &internal_connect_notify,
                                      connect_context);

}

#if !OLD
/**
 * Iterator for actually scheduling connections to be created
 * between two peers.
 *
 * @param cls closure, a GNUNET_TESTING_Daemon
 * @param key the key the second Daemon was stored under
 * @param value the GNUNET_TESTING_Daemon that the first is to connect to
 *
 * @return GNUNET_YES to continue iteration
 */
static int
connect_iterator (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct ConnectTopologyContext *ct_ctx = cls;
  struct PeerData *first = ct_ctx->first;
  struct GNUNET_TESTING_Daemon *second = value;
  struct ConnectContext *connect_context;

  connect_context = GNUNET_malloc (sizeof (struct ConnectContext));
  connect_context->first = first->daemon;
  connect_context->second = second;
  connect_context->ct_ctx = ct_ctx;
  connect_context->task =
      GNUNET_SCHEDULER_add_now (&schedule_connect, connect_context);
  GNUNET_CONTAINER_DLL_insert (ct_ctx->pg->cc_head, ct_ctx->pg->cc_tail,
                               connect_context);
  return GNUNET_YES;
}
#endif

#if !OLD
/**
 * Iterator for copying all entries in the allowed hashmap to the
 * connect hashmap.
 *
 * @param cls closure, a GNUNET_TESTING_Daemon
 * @param key the key the second Daemon was stored under
 * @param value the GNUNET_TESTING_Daemon that the first is to connect to
 *
 * @return GNUNET_YES to continue iteration
 */
static int
copy_topology_iterator (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct PeerData *first = cls;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap_put (first->connect_peers, key,
                                                    value,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));

  return GNUNET_YES;
}
#endif

/**
 * Make the peers to connect the same as those that are allowed to be
 * connected.
 *
 * @param pg the peer group
 */
static int
copy_allowed_topology (struct GNUNET_TESTING_PeerGroup *pg)
{
  unsigned int pg_iter;
  int ret;
  int total;

#if OLD
  struct PeerConnection *iter;
#endif
  total = 0;
  ret = 0;
  for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
  {
#if OLD
    iter = pg->peers[pg_iter].allowed_peers_head;
    while (iter != NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Creating connection between %d and %d\n", pg_iter,
                  iter->index);
      total += add_connections (pg, pg_iter, iter->index, CONNECT, GNUNET_YES);
      //total += add_actual_connections(pg, pg_iter, iter->index);
      iter = iter->next;
    }
#else
    ret =
        GNUNET_CONTAINER_multihashmap_iterate (pg->peers[pg_iter].allowed_peers,
                                               &copy_topology_iterator,
                                               &pg->peers[pg_iter]);
#endif
    if (GNUNET_SYSERR == ret)
      return GNUNET_SYSERR;

    total = total + ret;
  }

  return total;
}

/**
 * Connect the topology as specified by the PeerConnection's
 * of each peer in the peer group
 *
 * @param pg the peer group we are dealing with
 * @param connect_timeout how long try connecting two peers
 * @param connect_attempts how many times (max) to attempt
 * @param notify_callback callback to notify when finished
 * @param notify_cls closure for notify callback
 *
 * @return the number of connections that will be attempted
 */
static int
connect_topology (struct GNUNET_TESTING_PeerGroup *pg,
                  struct GNUNET_TIME_Relative connect_timeout,
                  unsigned int connect_attempts,
                  GNUNET_TESTING_NotifyCompletion notify_callback,
                  void *notify_cls)
{
  unsigned int pg_iter;
  unsigned int total;

#if OLD
  struct PeerConnection *connection_iter;
#endif
#if USE_SEND_HELLOS
  struct SendHelloContext *send_hello_context;
#endif

  total = 0;
  pg->ct_ctx.notify_connections_done = notify_callback;
  pg->ct_ctx.notify_cls = notify_cls;
  pg->ct_ctx.pg = pg;

  for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
  {
#if OLD
    connection_iter = pg->peers[pg_iter].connect_peers_head;
    while (connection_iter != NULL)
    {
      connection_iter = connection_iter->next;
      total++;
    }
#else
    total +=
        GNUNET_CONTAINER_multihashmap_size (pg->peers[pg_iter].connect_peers);
#endif
  }

  if (total == 0)
    return total;

  pg->ct_ctx.connect_timeout = connect_timeout;
  pg->ct_ctx.connect_attempts = connect_attempts;
  pg->ct_ctx.remaining_connections = total;

#if USE_SEND_HELLOS
  /* First give all peers the HELLO's of other peers (connect to first peer's transport service, give HELLO's of other peers, continue...) */
  pg->remaining_hellos = total;
  for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
  {
    send_hello_context = GNUNET_malloc (sizeof (struct SendHelloContext));
    send_hello_context->peer = &pg->peers[pg_iter];
    send_hello_context->peer_pos = pg->peers[pg_iter].connect_peers_head;
    send_hello_context->pg = pg;
    GNUNET_SCHEDULER_add_now (&schedule_send_hellos, send_hello_context);
  }
#else
  for (pg_iter = 0; pg_iter < pg->max_outstanding_connections; pg_iter++)
  {
    preschedule_connect (pg);
  }
#endif
  return total;

}

/**
 * Takes a peer group and creates a topology based on the
 * one specified.  Creates a topology means generates friend
 * files for the peers so they can only connect to those allowed
 * by the topology.  This will only have an effect once peers
 * are started if the FRIENDS_ONLY option is set in the base
 * config.  Also takes an optional restrict topology which
 * disallows connections based on particular transports
 * UNLESS they are specified in the restricted topology.
 *
 * @param pg the peer group struct representing the running peers
 * @param topology which topology to connect the peers in
 * @param restrict_topology disallow restrict_transports transport
 *                          connections to peers NOT in this topology
 *                          use GNUNET_TESTING_TOPOLOGY_NONE for no restrictions
 * @param restrict_transports space delimited list of transports to blacklist
 *                            to create restricted topology
 *
 * @return the maximum number of connections were all allowed peers
 *         connected to each other
 */
unsigned int
GNUNET_TESTING_create_topology (struct GNUNET_TESTING_PeerGroup *pg,
                                enum GNUNET_TESTING_Topology topology,
                                enum GNUNET_TESTING_Topology restrict_topology,
                                const char *restrict_transports)
{
  int ret;

  unsigned int num_connections;
  int unblacklisted_connections;
  char *filename;
  struct PeerConnection *conn_iter;
  struct PeerConnection *temp_conn;
  unsigned int off;

#if !OLD
  unsigned int i;

  for (i = 0; i < pg->total; i++)
  {
    pg->peers[i].allowed_peers = GNUNET_CONTAINER_multihashmap_create (100);
    pg->peers[i].connect_peers = GNUNET_CONTAINER_multihashmap_create (100);
    pg->peers[i].blacklisted_peers = GNUNET_CONTAINER_multihashmap_create (100);
    pg->peers[i].pg = pg;
  }
#endif

  switch (topology)
  {
  case GNUNET_TESTING_TOPOLOGY_CLIQUE:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Creating clique topology\n");
    num_connections = create_clique (pg, &add_connections, ALLOWED, GNUNET_NO);
    break;
  case GNUNET_TESTING_TOPOLOGY_SMALL_WORLD_RING:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Creating small world (ring) topology\n");
    num_connections = create_small_world_ring (pg, &add_connections, ALLOWED);
    break;
  case GNUNET_TESTING_TOPOLOGY_SMALL_WORLD:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Creating small world (2d-torus) topology\n");
    num_connections = create_small_world (pg, &add_connections, ALLOWED);
    break;
  case GNUNET_TESTING_TOPOLOGY_RING:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Creating ring topology\n");
    num_connections = create_ring (pg, &add_connections, ALLOWED);
    break;
  case GNUNET_TESTING_TOPOLOGY_2D_TORUS:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Creating 2d torus topology\n");
    num_connections = create_2d_torus (pg, &add_connections, ALLOWED);
    break;
  case GNUNET_TESTING_TOPOLOGY_ERDOS_RENYI:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Creating Erdos-Renyi topology\n");
    num_connections = create_erdos_renyi (pg, &add_connections, ALLOWED);
    break;
  case GNUNET_TESTING_TOPOLOGY_INTERNAT:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Creating InterNAT topology\n");
    num_connections = create_nated_internet (pg, &add_connections, ALLOWED);
    break;
  case GNUNET_TESTING_TOPOLOGY_SCALE_FREE:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Creating Scale Free topology\n");
    num_connections = create_scale_free (pg, &add_connections, ALLOWED);
    break;
  case GNUNET_TESTING_TOPOLOGY_LINE:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Creating straight line topology\n");
    num_connections = create_line (pg, &add_connections, ALLOWED);
    break;
  case GNUNET_TESTING_TOPOLOGY_FROM_FILE:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Creating topology from file!\n");
    if (GNUNET_OK ==
        GNUNET_CONFIGURATION_get_value_string (pg->cfg, "testing",
                                               "topology_file", &filename))
      num_connections =
          create_from_file (pg, filename, &add_connections, ALLOWED);
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Missing configuration option TESTING:TOPOLOGY_FILE for creating topology from file!\n");
      num_connections = 0;
    }
    break;
  case GNUNET_TESTING_TOPOLOGY_NONE:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                _
                ("Creating no allowed topology (all peers can connect at core level)\n"));
    num_connections = pg->total * pg->total;    /* Clique is allowed! */
    break;
  default:
    num_connections = 0;
    break;
  }

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (pg->cfg, "TESTING", "F2F"))
  {
    ret = create_and_copy_friend_files (pg);
    if (ret != GNUNET_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Failed during friend file copying!\n");
      return GNUNET_SYSERR;
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Friend files created/copied successfully!\n");
    }
  }

  /* Use the create clique method to initially set all connections as blacklisted. */
  if ((restrict_topology != GNUNET_TESTING_TOPOLOGY_NONE) &&
      (restrict_topology != GNUNET_TESTING_TOPOLOGY_FROM_FILE))
    create_clique (pg, &add_connections, BLACKLIST, GNUNET_NO);
  else
    return num_connections;

  unblacklisted_connections = 0;
  /* Un-blacklist connections as per the topology specified */
  switch (restrict_topology)
  {
  case GNUNET_TESTING_TOPOLOGY_CLIQUE:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Blacklisting all but clique topology\n");
    unblacklisted_connections =
        create_clique (pg, &remove_connections, BLACKLIST, GNUNET_NO);
    break;
  case GNUNET_TESTING_TOPOLOGY_SMALL_WORLD_RING:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Blacklisting all but small world (ring) topology\n");
    unblacklisted_connections =
        create_small_world_ring (pg, &remove_connections, BLACKLIST);
    break;
  case GNUNET_TESTING_TOPOLOGY_SMALL_WORLD:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Blacklisting all but small world (2d-torus) topology\n");
    unblacklisted_connections =
        create_small_world (pg, &remove_connections, BLACKLIST);
    break;
  case GNUNET_TESTING_TOPOLOGY_RING:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Blacklisting all but ring topology\n");
    unblacklisted_connections =
        create_ring (pg, &remove_connections, BLACKLIST);
    break;
  case GNUNET_TESTING_TOPOLOGY_2D_TORUS:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Blacklisting all but 2d torus topology\n");
    unblacklisted_connections =
        create_2d_torus (pg, &remove_connections, BLACKLIST);
    break;
  case GNUNET_TESTING_TOPOLOGY_ERDOS_RENYI:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Blacklisting all but Erdos-Renyi topology\n");
    unblacklisted_connections =
        create_erdos_renyi (pg, &remove_connections, BLACKLIST);
    break;
  case GNUNET_TESTING_TOPOLOGY_INTERNAT:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Blacklisting all but InterNAT topology\n");

#if TOPOLOGY_HACK
    for (off = 0; off < pg->total; off++)
    {
      conn_iter = pg->peers[off].allowed_peers_head;
      while (conn_iter != NULL)
      {
        temp_conn = conn_iter->next;
        GNUNET_free (conn_iter);
        conn_iter = temp_conn;
      }
      pg->peers[off].allowed_peers_head = NULL;
      pg->peers[off].allowed_peers_tail = NULL;

      conn_iter = pg->peers[off].connect_peers_head;
      while (conn_iter != NULL)
      {
        temp_conn = conn_iter->next;
        GNUNET_free (conn_iter);
        conn_iter = temp_conn;
      }
      pg->peers[off].connect_peers_head = NULL;
      pg->peers[off].connect_peers_tail = NULL;
    }
    unblacklisted_connections =
        create_nated_internet_copy (pg, &remove_connections, BLACKLIST);
#else
    unblacklisted_connections =
        create_nated_internet (pg, &remove_connections, BLACKLIST);
#endif

    break;
  case GNUNET_TESTING_TOPOLOGY_SCALE_FREE:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Blacklisting all but Scale Free topology\n");
    unblacklisted_connections =
        create_scale_free (pg, &remove_connections, BLACKLIST);
    break;
  case GNUNET_TESTING_TOPOLOGY_LINE:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Blacklisting all but straight line topology\n");
    unblacklisted_connections =
        create_line (pg, &remove_connections, BLACKLIST);
  default:
    break;
  }

  if ((unblacklisted_connections > 0) && (restrict_transports != NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Creating blacklist with `%s'\n",
                restrict_transports);
    ret = create_and_copy_blacklist_files (pg, restrict_transports);
    if (ret != GNUNET_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Failed during blacklist file copying!\n");
      return 0;
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Blacklist files created/copied successfully!\n");
    }
  }
  return num_connections;
}

#if !OLD
/**
 * Iterator for choosing random peers to connect.
 *
 * @param cls closure, a RandomContext
 * @param key the key the second Daemon was stored under
 * @param value the GNUNET_TESTING_Daemon that the first is to connect to
 *
 * @return GNUNET_YES to continue iteration
 */
static int
random_connect_iterator (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct RandomContext *random_ctx = cls;
  double random_number;
  uint32_t second_pos;
  GNUNET_HashCode first_hash;

  random_number =
      ((double)
       GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                 UINT64_MAX)) / ((double) UINT64_MAX);
  if (random_number < random_ctx->percentage)
  {
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multihashmap_put (random_ctx->
                                                      first->connect_peers_working_set,
                                                      key, value,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }

  /* Now we have considered this particular connection, remove it from the second peer so it's not double counted */
  uid_from_hash (key, &second_pos);
  hash_from_uid (random_ctx->first_uid, &first_hash);
  GNUNET_assert (random_ctx->pg->total > second_pos);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (random_ctx->
                                                       pg->peers
                                                       [second_pos].connect_peers,
                                                       &first_hash,
                                                       random_ctx->
                                                       first->daemon));

  return GNUNET_YES;
}

/**
 * Iterator for adding at least X peers to a peers connection set.
 *
 * @param cls closure, MinimumContext
 * @param key the key the second Daemon was stored under
 * @param value the GNUNET_TESTING_Daemon that the first is to connect to
 *
 * @return GNUNET_YES to continue iteration
 */
static int
minimum_connect_iterator (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct MinimumContext *min_ctx = cls;
  uint32_t second_pos;
  GNUNET_HashCode first_hash;
  unsigned int i;

  if (GNUNET_CONTAINER_multihashmap_size
      (min_ctx->first->connect_peers_working_set) < min_ctx->num_to_add)
  {
    for (i = 0; i < min_ctx->num_to_add; i++)
    {
      if (min_ctx->pg_array[i] == min_ctx->current)
      {
        GNUNET_assert (GNUNET_OK ==
                       GNUNET_CONTAINER_multihashmap_put (min_ctx->
                                                          first->connect_peers_working_set,
                                                          key, value,
                                                          GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
        uid_from_hash (key, &second_pos);
        hash_from_uid (min_ctx->first_uid, &first_hash);
        GNUNET_assert (min_ctx->pg->total > second_pos);
        GNUNET_assert (GNUNET_OK ==
                       GNUNET_CONTAINER_multihashmap_put (min_ctx->
                                                          pg->peers
                                                          [second_pos].connect_peers_working_set,
                                                          &first_hash,
                                                          min_ctx->first->
                                                          daemon,
                                                          GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
        /* Now we have added this particular connection, remove it from the second peer's map so it's not double counted */
        GNUNET_assert (GNUNET_YES ==
                       GNUNET_CONTAINER_multihashmap_remove (min_ctx->
                                                             pg->peers
                                                             [second_pos].connect_peers,
                                                             &first_hash,
                                                             min_ctx->
                                                             first->daemon));
      }
    }
    min_ctx->current++;
    return GNUNET_YES;
  }
  else
    return GNUNET_NO;           /* We can stop iterating, we have enough peers! */

}

/**
 * Iterator for adding peers to a connection set based on a depth first search.
 *
 * @param cls closure, MinimumContext
 * @param key the key the second daemon was stored under
 * @param value the GNUNET_TESTING_Daemon that the first is to connect to
 *
 * @return GNUNET_YES to continue iteration
 */
static int
dfs_connect_iterator (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct DFSContext *dfs_ctx = cls;
  GNUNET_HashCode first_hash;

  if (dfs_ctx->current == dfs_ctx->chosen)
  {
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multihashmap_put (dfs_ctx->
                                                      first->connect_peers_working_set,
                                                      key, value,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
    uid_from_hash (key, &dfs_ctx->second_uid);
    hash_from_uid (dfs_ctx->first_uid, &first_hash);
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multihashmap_put (dfs_ctx->
                                                      pg->peers[dfs_ctx->
                                                                second_uid].connect_peers_working_set,
                                                      &first_hash,
                                                      dfs_ctx->first->daemon,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multihashmap_remove (dfs_ctx->
                                                         pg->peers
                                                         [dfs_ctx->second_uid].connect_peers,
                                                         &first_hash,
                                                         dfs_ctx->
                                                         first->daemon));
    /* Can't remove second from first yet because we are currently iterating, hence the return value in the DFSContext! */
    return GNUNET_NO;           /* We have found our peer, don't iterate more */
  }

  dfs_ctx->current++;
  return GNUNET_YES;
}
#endif

/**
 * From the set of connections possible, choose percentage percent of connections
 * to actually connect.
 *
 * @param pg the peergroup we are dealing with
 * @param percentage what percent of total connections to make
 */
void
choose_random_connections (struct GNUNET_TESTING_PeerGroup *pg,
                           double percentage)
{
  uint32_t pg_iter;

#if OLD
  struct PeerConnection *conn_iter;
  double random_number;
#else
  struct RandomContext random_ctx;
#endif

  for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
  {
#if OLD
    conn_iter = pg->peers[pg_iter].connect_peers_head;
    while (conn_iter != NULL)
    {
      random_number =
          ((double)
           GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                     UINT64_MAX)) / ((double) UINT64_MAX);
      if (random_number < percentage)
      {
        add_connections (pg, pg_iter, conn_iter->index, WORKING_SET,
                         GNUNET_YES);
      }
      conn_iter = conn_iter->next;
    }
#else
    random_ctx.first_uid = pg_iter;
    random_ctx.first = &pg->peers[pg_iter];
    random_ctx.percentage = percentage;
    random_ctx.pg = pg;
    pg->peers[pg_iter].connect_peers_working_set =
        GNUNET_CONTAINER_multihashmap_create (pg->total);
    GNUNET_CONTAINER_multihashmap_iterate (pg->peers[pg_iter].connect_peers,
                                           &random_connect_iterator,
                                           &random_ctx);
    /* Now remove the old connections */
    GNUNET_CONTAINER_multihashmap_destroy (pg->peers[pg_iter].connect_peers);
    /* And replace with the random set */
    pg->peers[pg_iter].connect_peers =
        pg->peers[pg_iter].connect_peers_working_set;
#endif
  }

  for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
  {
    conn_iter = pg->peers[pg_iter].connect_peers_head;
    while (pg->peers[pg_iter].connect_peers_head != NULL)
      remove_connections (pg, pg_iter,
                          pg->peers[pg_iter].connect_peers_head->index, CONNECT,
                          GNUNET_YES);

    pg->peers[pg_iter].connect_peers_head =
        pg->peers[pg_iter].connect_peers_working_set_head;
    pg->peers[pg_iter].connect_peers_tail =
        pg->peers[pg_iter].connect_peers_working_set_tail;
    pg->peers[pg_iter].connect_peers_working_set_head = NULL;
    pg->peers[pg_iter].connect_peers_working_set_tail = NULL;
  }
}

/**
 * Count the number of connections in a linked list of connections.
 *
 * @param conn_list the connection list to get the count of
 *
 * @return the number of elements in the list
 */
static unsigned int
count_connections (struct PeerConnection *conn_list)
{
  struct PeerConnection *iter;
  unsigned int count;

  count = 0;
  iter = conn_list;
  while (iter != NULL)
  {
    iter = iter->next;
    count++;
  }
  return count;
}

static unsigned int
count_workingset_connections (struct GNUNET_TESTING_PeerGroup *pg)
{
  unsigned int count;
  unsigned int pg_iter;

#if OLD
  struct PeerConnection *conn_iter;
#endif
  count = 0;

  for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
  {
#if OLD
    conn_iter = pg->peers[pg_iter].connect_peers_working_set_head;
    while (conn_iter != NULL)
    {
      count++;
      conn_iter = conn_iter->next;
    }
#else
    count +=
        GNUNET_CONTAINER_multihashmap_size (pg->
                                            peers
                                            [pg_iter].connect_peers_working_set);
#endif
  }

  return count;
}

static unsigned int
count_allowed_connections (struct GNUNET_TESTING_PeerGroup *pg)
{
  unsigned int count;
  unsigned int pg_iter;

#if OLD
  struct PeerConnection *conn_iter;
#endif

  count = 0;
  for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
  {
#if OLD
    conn_iter = pg->peers[pg_iter].allowed_peers_head;
    while (conn_iter != NULL)
    {
      count++;
      conn_iter = conn_iter->next;
    }
#else
    count +=
        GNUNET_CONTAINER_multihashmap_size (pg->peers[pg_iter].allowed_peers);
#endif
  }

  return count;
}

/**
 * From the set of connections possible, choose at least num connections per
 * peer.
 *
 * @param pg the peergroup we are dealing with
 * @param num how many connections at least should each peer have (if possible)?
 */
static void
choose_minimum (struct GNUNET_TESTING_PeerGroup *pg, unsigned int num)
{
#if !OLD
  struct MinimumContext minimum_ctx;
#else
  struct PeerConnection *conn_iter;
  unsigned int temp_list_size;
  unsigned int i;
  unsigned int count;
  uint32_t random;              /* Random list entry to connect peer to */
#endif
  uint32_t pg_iter;

#if OLD
  for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
  {
    temp_list_size = count_connections (pg->peers[pg_iter].connect_peers_head);
    if (temp_list_size == 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Peer %d has 0 connections!?!?\n",
                  pg_iter);
      break;
    }
    for (i = 0; i < num; i++)
    {
      random =
          GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, temp_list_size);
      conn_iter = pg->peers[pg_iter].connect_peers_head;
      for (count = 0; count < random; count++)
        conn_iter = conn_iter->next;
      /* We now have a random connection, connect it! */
      GNUNET_assert (conn_iter != NULL);
      add_connections (pg, pg_iter, conn_iter->index, WORKING_SET, GNUNET_YES);
    }
  }
#else
  for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
  {
    pg->peers[pg_iter].connect_peers_working_set =
        GNUNET_CONTAINER_multihashmap_create (num);
  }

  for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
  {
    minimum_ctx.first_uid = pg_iter;
    minimum_ctx.pg_array =
        GNUNET_CRYPTO_random_permute (GNUNET_CRYPTO_QUALITY_WEAK,
                                      GNUNET_CONTAINER_multihashmap_size
                                      (pg->peers[pg_iter].connect_peers));
    minimum_ctx.first = &pg->peers[pg_iter];
    minimum_ctx.pg = pg;
    minimum_ctx.num_to_add = num;
    minimum_ctx.current = 0;
    GNUNET_CONTAINER_multihashmap_iterate (pg->peers[pg_iter].connect_peers,
                                           &minimum_connect_iterator,
                                           &minimum_ctx);
  }

  for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
  {
    /* Remove the "old" connections */
    GNUNET_CONTAINER_multihashmap_destroy (pg->peers[pg_iter].connect_peers);
    /* And replace with the working set */
    pg->peers[pg_iter].connect_peers =
        pg->peers[pg_iter].connect_peers_working_set;
  }
#endif
  for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
  {
    while (pg->peers[pg_iter].connect_peers_head != NULL)
    {
      conn_iter = pg->peers[pg_iter].connect_peers_head;
      GNUNET_CONTAINER_DLL_remove (pg->peers[pg_iter].connect_peers_head,
                                   pg->peers[pg_iter].connect_peers_tail,
                                   conn_iter);
      GNUNET_free (conn_iter);
      /*remove_connections(pg, pg_iter, pg->peers[pg_iter].connect_peers_head->index, CONNECT, GNUNET_YES); */
    }

    pg->peers[pg_iter].connect_peers_head =
        pg->peers[pg_iter].connect_peers_working_set_head;
    pg->peers[pg_iter].connect_peers_tail =
        pg->peers[pg_iter].connect_peers_working_set_tail;
    pg->peers[pg_iter].connect_peers_working_set_head = NULL;
    pg->peers[pg_iter].connect_peers_working_set_tail = NULL;
  }
}

#if !OLD
struct FindClosestContext
{
    /**
     * The currently known closest peer.
     */
  struct GNUNET_TESTING_Daemon *closest;

    /**
     * The info for the peer we are adding connections for.
     */
  struct PeerData *curr_peer;

    /**
     * The distance (bits) between the current
     * peer and the currently known closest.
     */
  unsigned int closest_dist;

    /**
     * The offset of the closest known peer in
     * the peer group.
     */
  unsigned int closest_num;
};

/**
 * Iterator over hash map entries of the allowed
 * peer connections.  Find the closest, not already
 * connected peer and return it.
 *
 * @param cls closure (struct FindClosestContext)
 * @param key current key code (hash of offset in pg)
 * @param value value in the hash map - a GNUNET_TESTING_Daemon
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
static int
find_closest_peers (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct FindClosestContext *closest_ctx = cls;
  struct GNUNET_TESTING_Daemon *daemon = value;

  if (((closest_ctx->closest == NULL) ||
       (GNUNET_CRYPTO_hash_matching_bits
        (&daemon->id.hashPubKey,
         &closest_ctx->curr_peer->daemon->id.hashPubKey) >
        closest_ctx->closest_dist)) &&
      (GNUNET_YES !=
       GNUNET_CONTAINER_multihashmap_contains (closest_ctx->
                                               curr_peer->connect_peers, key)))
  {
    closest_ctx->closest_dist =
        GNUNET_CRYPTO_hash_matching_bits (&daemon->id.hashPubKey,
                                          &closest_ctx->curr_peer->daemon->
                                          id.hashPubKey);
    closest_ctx->closest = daemon;
    uid_from_hash (key, &closest_ctx->closest_num);
  }
  return GNUNET_YES;
}

/**
 * From the set of connections possible, choose at num connections per
 * peer based on depth which are closest out of those allowed.  Guaranteed
 * to add num peers to connect to, provided there are that many peers
 * in the underlay topology to connect to.
 *
 * @param pg the peergroup we are dealing with
 * @param num how many connections at least should each peer have (if possible)?
 * @param proc processor to actually add the connections
 * @param list the peer list to use
 */
void
add_closest (struct GNUNET_TESTING_PeerGroup *pg, unsigned int num,
             GNUNET_TESTING_ConnectionProcessor proc, enum PeerLists list)
{
#if OLD

#else
  struct FindClosestContext closest_ctx;
#endif
  uint32_t pg_iter;
  uint32_t i;

  for (i = 0; i < num; i++)     /* Each time find a closest peer (from those available) */
  {
    for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
    {
      closest_ctx.curr_peer = &pg->peers[pg_iter];
      closest_ctx.closest = NULL;
      closest_ctx.closest_dist = 0;
      closest_ctx.closest_num = 0;
      GNUNET_CONTAINER_multihashmap_iterate (pg->peers[pg_iter].allowed_peers,
                                             &find_closest_peers, &closest_ctx);
      if (closest_ctx.closest != NULL)
      {
        GNUNET_assert (closest_ctx.closest_num < pg->total);
        proc (pg, pg_iter, closest_ctx.closest_num, list);
      }
    }
  }
}
#endif

/**
 * From the set of connections possible, choose at least num connections per
 * peer based on depth first traversal of peer connections.  If DFS leaves
 * peers unconnected, ensure those peers get connections.
 *
 * @param pg the peergroup we are dealing with
 * @param num how many connections at least should each peer have (if possible)?
 */
void
perform_dfs (struct GNUNET_TESTING_PeerGroup *pg, unsigned int num)
{
  uint32_t pg_iter;
  uint32_t dfs_count;
  uint32_t starting_peer;
  uint32_t least_connections;
  uint32_t random_connection;

#if OLD
  unsigned int temp_count;
  struct PeerConnection *peer_iter;
#else
  struct DFSContext dfs_ctx;
  GNUNET_HashCode second_hash;
#endif

#if OLD
  starting_peer = 0;
  dfs_count = 0;
  while ((count_workingset_connections (pg) < num * pg->total) &&
         (count_allowed_connections (pg) > 0))
  {
    if (dfs_count % pg->total == 0)     /* Restart the DFS at some weakly connected peer */
    {
      least_connections = -1;   /* Set to very high number */
      for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
      {
        temp_count =
            count_connections (pg->
                               peers[pg_iter].connect_peers_working_set_head);
        if (temp_count < least_connections)
        {
          starting_peer = pg_iter;
          least_connections = temp_count;
        }
      }
    }

    temp_count =
        count_connections (pg->peers[starting_peer].connect_peers_head);
    if (temp_count == 0)
      continue;                 /* FIXME: infinite loop? */

    random_connection =
        GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, temp_count);
    temp_count = 0;
    peer_iter = pg->peers[starting_peer].connect_peers_head;
    while (temp_count < random_connection)
    {
      peer_iter = peer_iter->next;
      temp_count++;
    }
    GNUNET_assert (peer_iter != NULL);
    add_connections (pg, starting_peer, peer_iter->index, WORKING_SET,
                     GNUNET_NO);
    remove_connections (pg, starting_peer, peer_iter->index, CONNECT,
                        GNUNET_YES);
    starting_peer = peer_iter->index;
    dfs_count++;
  }

#else
  for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
  {
    pg->peers[pg_iter].connect_peers_working_set =
        GNUNET_CONTAINER_multihashmap_create (num);
  }

  starting_peer = 0;
  dfs_count = 0;
  while ((count_workingset_connections (pg) < num * pg->total) &&
         (count_allowed_connections (pg) > 0))
  {
    if (dfs_count % pg->total == 0)     /* Restart the DFS at some weakly connected peer */
    {
      least_connections = -1;   /* Set to very high number */
      for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
      {
        if (GNUNET_CONTAINER_multihashmap_size
            (pg->peers[pg_iter].connect_peers_working_set) < least_connections)
        {
          starting_peer = pg_iter;
          least_connections =
              GNUNET_CONTAINER_multihashmap_size (pg->
                                                  peers
                                                  [pg_iter].connect_peers_working_set);
        }
      }
    }

    if (GNUNET_CONTAINER_multihashmap_size (pg->peers[starting_peer].connect_peers) == 0)       /* Ensure there is at least one peer left to connect! */
    {
      dfs_count = 0;
      continue;
    }

    /* Choose a random peer from the chosen peers set of connections to add */
    dfs_ctx.chosen =
        GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                  GNUNET_CONTAINER_multihashmap_size (pg->peers
                                                                      [starting_peer].connect_peers));
    dfs_ctx.first_uid = starting_peer;
    dfs_ctx.first = &pg->peers[starting_peer];
    dfs_ctx.pg = pg;
    dfs_ctx.current = 0;

    GNUNET_CONTAINER_multihashmap_iterate (pg->
                                           peers[starting_peer].connect_peers,
                                           &dfs_connect_iterator, &dfs_ctx);
    /* Remove the second from the first, since we will be continuing the search and may encounter the first peer again! */
    hash_from_uid (dfs_ctx.second_uid, &second_hash);
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multihashmap_remove (pg->peers
                                                         [starting_peer].connect_peers,
                                                         &second_hash,
                                                         pg->
                                                         peers
                                                         [dfs_ctx.second_uid].daemon));
    starting_peer = dfs_ctx.second_uid;
  }

  for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
  {
    /* Remove the "old" connections */
    GNUNET_CONTAINER_multihashmap_destroy (pg->peers[pg_iter].connect_peers);
    /* And replace with the working set */
    pg->peers[pg_iter].connect_peers =
        pg->peers[pg_iter].connect_peers_working_set;
  }
#endif
}

/**
 * Internal callback for topology information for a particular peer.
 */
static void
internal_topology_callback (void *cls, const struct GNUNET_PeerIdentity *peer,
                            const struct GNUNET_ATS_Information *atsi,
                            unsigned int atsi_count)
{
  struct CoreContext *core_ctx = cls;
  struct TopologyIterateContext *iter_ctx = core_ctx->iter_context;

  if (peer == NULL)             /* Either finished, or something went wrong */
  {
    iter_ctx->completed++;
    iter_ctx->connected--;
    /* One core context allocated per iteration, must free! */
    GNUNET_free (core_ctx);
  }
  else
  {
    iter_ctx->topology_cb (iter_ctx->cls, &core_ctx->daemon->id, peer, NULL);
  }

  if (iter_ctx->completed == iter_ctx->total)
  {
    iter_ctx->topology_cb (iter_ctx->cls, NULL, NULL, NULL);
    /* Once all are done, free the iteration context */
    GNUNET_free (iter_ctx);
  }
}

/**
 * Check running topology iteration tasks, if below max start a new one, otherwise
 * schedule for some time in the future.
 */
static void
schedule_get_topology (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct CoreContext *core_context = cls;
  struct TopologyIterateContext *topology_context =
      (struct TopologyIterateContext *) core_context->iter_context;
  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;

  if (topology_context->connected >
      topology_context->pg->max_outstanding_connections)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Delaying connect, we have too many outstanding connections!\n");
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_MILLISECONDS, 100),
                                  &schedule_get_topology, core_context);
  }
  else
  {
    topology_context->connected++;

    if (GNUNET_OK !=
        GNUNET_CORE_iterate_peers (core_context->daemon->cfg,
                                   &internal_topology_callback, core_context))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Topology iteration failed.\n");
      internal_topology_callback (core_context, NULL, NULL, 0);
    }
  }
}

/**
 * Iterate over all (running) peers in the peer group, retrieve
 * all connections that each currently has.
 */
void
GNUNET_TESTING_get_topology (struct GNUNET_TESTING_PeerGroup *pg,
                             GNUNET_TESTING_NotifyTopology cb, void *cls)
{
  struct TopologyIterateContext *topology_context;
  struct CoreContext *core_ctx;
  unsigned int i;
  unsigned int total_count;

  /* Allocate a single topology iteration context */
  topology_context = GNUNET_malloc (sizeof (struct TopologyIterateContext));
  topology_context->topology_cb = cb;
  topology_context->cls = cls;
  topology_context->pg = pg;
  total_count = 0;
  for (i = 0; i < pg->total; i++)
  {
    if (pg->peers[i].daemon->running == GNUNET_YES)
    {
      /* Allocate one core context per core we need to connect to */
      core_ctx = GNUNET_malloc (sizeof (struct CoreContext));
      core_ctx->daemon = pg->peers[i].daemon;
      /* Set back pointer to topology iteration context */
      core_ctx->iter_context = topology_context;
      GNUNET_SCHEDULER_add_now (&schedule_get_topology, core_ctx);
      total_count++;
    }
  }
  if (total_count == 0)
  {
    cb (cls, NULL, NULL, "Cannot iterate over topology, no running peers!");
    GNUNET_free (topology_context);
  }
  else
    topology_context->total = total_count;
  return;
}

/**
 * Callback function to process statistic values.
 * This handler is here only really to insert a peer
 * identity (or daemon) so the statistics can be uniquely
 * tied to a single running peer.
 *
 * @param cls closure
 * @param subsystem name of subsystem that created the statistic
 * @param name the name of the datum
 * @param value the current value
 * @param is_persistent GNUNET_YES if the value is persistent, GNUNET_NO if not
 * @return GNUNET_OK to continue, GNUNET_SYSERR to abort iteration
 */
static int
internal_stats_callback (void *cls, const char *subsystem, const char *name,
                         uint64_t value, int is_persistent)
{
  struct StatsCoreContext *core_context = cls;
  struct StatsIterateContext *stats_context =
      (struct StatsIterateContext *) core_context->iter_context;

  return stats_context->proc (stats_context->cls, &core_context->daemon->id,
                              subsystem, name, value, is_persistent);
}


/**
 * We don't need the statistics handle anymore, destroy it.
 * 
 * @param cls Closure (the statistics handle to destroy)
 * @param tc Task Context
 */
static void
internal_destroy_statistics (void *cls,
                             const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_STATISTICS_Handle *h = cls;

  GNUNET_STATISTICS_destroy (h, GNUNET_NO);
}


/**
 * Internal continuation call for statistics iteration.
 *
 * @param cls closure, the CoreContext for this iteration
 * @param success whether or not the statistics iterations
 *        was canceled or not (we don't care)
 */
static void
internal_stats_cont (void *cls, int success)
{
  struct StatsCoreContext *core_context = cls;
  struct StatsIterateContext *stats_context =
      (struct StatsIterateContext *) core_context->iter_context;

  stats_context->connected--;
  stats_context->completed++;

  if (stats_context->completed == stats_context->total)
  {
    stats_context->cont (stats_context->cls, GNUNET_YES);
    GNUNET_free (stats_context);
  }

  if (core_context->stats_handle != NULL)
    /* Cannot destroy handle inside the continuation */
    GNUNET_SCHEDULER_add_now (&internal_destroy_statistics,
                              core_context->stats_handle);

  GNUNET_free (core_context);
}

/**
 * Check running topology iteration tasks, if below max start a new one, otherwise
 * schedule for some time in the future.
 */
static void
schedule_get_statistics (void *cls,
                         const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct StatsCoreContext *core_context = cls;
  struct StatsIterateContext *stats_context =
      (struct StatsIterateContext *) core_context->iter_context;

  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;

  if (stats_context->connected > stats_context->pg->max_outstanding_connections)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Delaying connect, we have too many outstanding connections!\n");
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_MILLISECONDS, 100),
                                  &schedule_get_statistics, core_context);
  }
  else
  {
    stats_context->connected++;
    core_context->stats_handle =
        GNUNET_STATISTICS_create ("testing", core_context->daemon->cfg);
    if (core_context->stats_handle == NULL)
    {
      internal_stats_cont (core_context, GNUNET_NO);
      return;
    }

    core_context->stats_get_handle =
        GNUNET_STATISTICS_get (core_context->stats_handle, NULL, NULL,
                               GNUNET_TIME_UNIT_FOREVER_REL,
                               &internal_stats_cont, &internal_stats_callback,
                               core_context);
    if (core_context->stats_get_handle == NULL)
      internal_stats_cont (core_context, GNUNET_NO);

  }
}

struct DuplicateStats
{
  /**
   * Next item in the list
   */
  struct DuplicateStats *next;

  /**
   * Nasty string, concatenation of relevant information.
   */
  char *unique_string;
};

/**
 * Check whether the combination of port/host/unix domain socket
 * already exists in the list of peers being checked for statistics.
 *
 * @param pg the peergroup in question
 * @param specific_peer the peer we're concerned with
 * @param stats_list the list to return to the caller
 *
 * @return GNUNET_YES if the statistics instance has been seen already,
 *         GNUNET_NO if not (and we may have added it to the list)
 */
static int
stats_check_existing (struct GNUNET_TESTING_PeerGroup *pg,
                      struct PeerData *specific_peer,
                      struct DuplicateStats **stats_list)
{
  struct DuplicateStats *pos;
  char *unix_domain_socket;
  unsigned long long port;
  char *to_match;

  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_get_value_yesno (pg->cfg, "testing",
                                            "single_statistics_per_host"))
    return GNUNET_NO;           /* Each peer has its own statistics instance, do nothing! */

  pos = *stats_list;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (specific_peer->cfg, "statistics",
                                             "unixpath", &unix_domain_socket))
    return GNUNET_NO;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (specific_peer->cfg, "statistics",
                                             "port", &port))
  {
    GNUNET_free (unix_domain_socket);
    return GNUNET_NO;
  }

  if (specific_peer->daemon->hostname != NULL)
    GNUNET_asprintf (&to_match, "%s%s%llu", specific_peer->daemon->hostname,
                     unix_domain_socket, port);
  else
    GNUNET_asprintf (&to_match, "%s%llu", unix_domain_socket, port);

  while (pos != NULL)
  {
    if (0 == strcmp (to_match, pos->unique_string))
    {
      GNUNET_free (unix_domain_socket);
      GNUNET_free (to_match);
      return GNUNET_YES;
    }
    pos = pos->next;
  }
  pos = GNUNET_malloc (sizeof (struct DuplicateStats));
  pos->unique_string = to_match;
  pos->next = *stats_list;
  *stats_list = pos;
  GNUNET_free (unix_domain_socket);
  return GNUNET_NO;
}

/**
 * Iterate over all (running) peers in the peer group, retrieve
 * all statistics from each.
 *
 * @param pg the peergroup to iterate statistics of
 * @param cont continuation to call once all stats have been retrieved
 * @param proc processing function for each statistic from each peer
 * @param cls closure to pass to proc
 *
 */
void
GNUNET_TESTING_get_statistics (struct GNUNET_TESTING_PeerGroup *pg,
                               GNUNET_STATISTICS_Callback cont,
                               GNUNET_TESTING_STATISTICS_Iterator proc,
                               void *cls)
{
  struct StatsIterateContext *stats_context;
  struct StatsCoreContext *core_ctx;
  unsigned int i;
  unsigned int total_count;
  struct DuplicateStats *stats_list;
  struct DuplicateStats *pos;

  stats_list = NULL;

  /* Allocate a single stats iteration context */
  stats_context = GNUNET_malloc (sizeof (struct StatsIterateContext));
  stats_context->cont = cont;
  stats_context->proc = proc;
  stats_context->cls = cls;
  stats_context->pg = pg;
  total_count = 0;

  for (i = 0; i < pg->total; i++)
  {
    if ((pg->peers[i].daemon->running == GNUNET_YES) &&
        (GNUNET_NO == stats_check_existing (pg, &pg->peers[i], &stats_list)))
    {
      /* Allocate one core context per core we need to connect to */
      core_ctx = GNUNET_malloc (sizeof (struct StatsCoreContext));
      core_ctx->daemon = pg->peers[i].daemon;
      /* Set back pointer to topology iteration context */
      core_ctx->iter_context = stats_context;
      GNUNET_SCHEDULER_add_now (&schedule_get_statistics, core_ctx);
      total_count++;
    }
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Retrieving stats from %u total instances.\n", total_count);
  if (0 != total_count)
    stats_context->total = total_count;
  else
    GNUNET_free (stats_context);
  if (stats_list != NULL)
  {
    pos = stats_list;
    while (pos != NULL)
    {
      GNUNET_free (pos->unique_string);
      stats_list = pos->next;
      GNUNET_free (pos);
      pos = stats_list->next;
    }
  }
  return;
}

/**
 * Stop the connection process temporarily.
 *
 * @param pg the peer group to stop connecting
 */
void
GNUNET_TESTING_stop_connections (struct GNUNET_TESTING_PeerGroup *pg)
{
  pg->stop_connects = GNUNET_YES;
}

/**
 * Resume the connection process temporarily.
 *
 * @param pg the peer group to resume connecting
 */
void
GNUNET_TESTING_resume_connections (struct GNUNET_TESTING_PeerGroup *pg)
{
  pg->stop_connects = GNUNET_NO;
}

/**
 * There are many ways to connect peers that are supported by this function.
 * To connect peers in the same topology that was created via the
 * GNUNET_TESTING_create_topology, the topology variable must be set to
 * GNUNET_TESTING_TOPOLOGY_NONE.  If the topology variable is specified,
 * a new instance of that topology will be generated and attempted to be
 * connected.  This could result in some connections being impossible,
 * because some topologies are non-deterministic.
 *
 * @param pg the peer group struct representing the running peers
 * @param topology which topology to connect the peers in
 * @param options options for connecting the topology
 * @param option_modifier modifier for options that take a parameter
 * @param connect_timeout how long to wait before giving up on connecting
 *                        two peers
 * @param connect_attempts how many times to attempt to connect two peers
 *                         over the connect_timeout duration
 * @param notify_callback notification to be called once all connections completed
 * @param notify_cls closure for notification callback
 *
 * @return the number of connections that will be attempted, GNUNET_SYSERR on error
 */
int
GNUNET_TESTING_connect_topology (struct GNUNET_TESTING_PeerGroup *pg,
                                 enum GNUNET_TESTING_Topology topology,
                                 enum GNUNET_TESTING_TopologyOption options,
                                 double option_modifier,
                                 struct GNUNET_TIME_Relative connect_timeout,
                                 unsigned int connect_attempts,
                                 GNUNET_TESTING_NotifyCompletion
                                 notify_callback, void *notify_cls)
{
  switch (topology)
  {
  case GNUNET_TESTING_TOPOLOGY_CLIQUE:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Creating clique CONNECT topology\n");
    create_clique (pg, &add_connections, CONNECT, GNUNET_NO);
    break;
  case GNUNET_TESTING_TOPOLOGY_SMALL_WORLD_RING:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Creating small world (ring) CONNECT topology\n");
    create_small_world_ring (pg, &add_connections, CONNECT);
    break;
  case GNUNET_TESTING_TOPOLOGY_SMALL_WORLD:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Creating small world (2d-torus) CONNECT topology\n");
    create_small_world (pg, &add_connections, CONNECT);
    break;
  case GNUNET_TESTING_TOPOLOGY_RING:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Creating ring CONNECT topology\n");
    create_ring (pg, &add_connections, CONNECT);
    break;
  case GNUNET_TESTING_TOPOLOGY_2D_TORUS:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Creating 2d torus CONNECT topology\n");
    create_2d_torus (pg, &add_connections, CONNECT);
    break;
  case GNUNET_TESTING_TOPOLOGY_ERDOS_RENYI:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Creating Erdos-Renyi CONNECT topology\n");
    create_erdos_renyi (pg, &add_connections, CONNECT);
    break;
  case GNUNET_TESTING_TOPOLOGY_INTERNAT:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Creating InterNAT CONNECT topology\n");
    create_nated_internet (pg, &add_connections, CONNECT);
    break;
  case GNUNET_TESTING_TOPOLOGY_SCALE_FREE:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Creating Scale Free CONNECT topology\n");
    create_scale_free (pg, &add_connections, CONNECT);
    break;
  case GNUNET_TESTING_TOPOLOGY_LINE:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Creating straight line CONNECT topology\n");
    create_line (pg, &add_connections, CONNECT);
    break;
  case GNUNET_TESTING_TOPOLOGY_NONE:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Creating no CONNECT topology\n");
    copy_allowed_topology (pg);
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Unknown topology specification, can't connect peers!\n"));
    return GNUNET_SYSERR;
  }

  switch (options)
  {
  case GNUNET_TESTING_TOPOLOGY_OPTION_RANDOM:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Connecting random subset (%'.2f percent) of possible peers\n",
                100 * option_modifier);
    choose_random_connections (pg, option_modifier);
    break;
  case GNUNET_TESTING_TOPOLOGY_OPTION_MINIMUM:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Connecting a minimum of %u peers each (if possible)\n",
                (unsigned int) option_modifier);
    choose_minimum (pg, (unsigned int) option_modifier);
    break;
  case GNUNET_TESTING_TOPOLOGY_OPTION_DFS:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Using DFS to connect a minimum of %u peers each (if possible)\n",
                (unsigned int) option_modifier);
#if FIXME
    perform_dfs (pg, (int) option_modifier);
#endif
    break;
  case GNUNET_TESTING_TOPOLOGY_OPTION_ADD_CLOSEST:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Finding additional %u closest peers each (if possible)\n",
                (unsigned int) option_modifier);
#if FIXME
    add_closest (pg, (unsigned int) option_modifier, &add_connections, CONNECT);
#endif
    break;
  case GNUNET_TESTING_TOPOLOGY_OPTION_NONE:
    break;
  case GNUNET_TESTING_TOPOLOGY_OPTION_ALL:
    break;
  default:
    break;
  }

  return connect_topology (pg, connect_timeout, connect_attempts,
                           notify_callback, notify_cls);
}

/**
 * Lookup and return the number of SSH connections to a host.
 *
 * @param hostname the hostname to lookup in the list
 * @param pg the peergroup that the host belongs to
 *
 * @return the number of current ssh connections to the host
 */
static unsigned int
count_outstanding_at_host (const char *hostname,
                           struct GNUNET_TESTING_PeerGroup *pg)
{
  struct OutstandingSSH *pos;

  pos = pg->ssh_head;
  while ((pos != NULL) && (strcmp (pos->hostname, hostname) != 0))
    pos = pos->next;
  GNUNET_assert (pos != NULL);
  return pos->outstanding;
}

/**
 * Increment the number of SSH connections to a host by one.
 *
 * @param hostname the hostname to lookup in the list
 * @param pg the peergroup that the host belongs to
 *
 */
static void
increment_outstanding_at_host (const char *hostname,
                               struct GNUNET_TESTING_PeerGroup *pg)
{
  struct OutstandingSSH *pos;

  pos = pg->ssh_head;
  while ((NULL != pos) && (strcmp (pos->hostname, hostname) != 0))
    pos = pos->next;
  GNUNET_assert (NULL != pos);
  pos->outstanding++;
}

/**
 * Decrement the number of SSH connections to a host by one.
 *
 * @param hostname the hostname to lookup in the list
 * @param pg the peergroup that the host belongs to
 *
 */
static void
decrement_outstanding_at_host (const char *hostname,
                               struct GNUNET_TESTING_PeerGroup *pg)
{
  struct OutstandingSSH *pos;

  pos = pg->ssh_head;
  while ((pos != NULL) && (strcmp (pos->hostname, hostname) != 0))
    pos = pos->next;
  GNUNET_assert (pos != NULL);
  pos->outstanding--;
}

/**
 * Callback that is called whenever a hostkey is generated
 * for a peer.  Call the real callback and decrement the
 * starting counter for the peergroup.
 *
 * @param cls closure
 * @param id identifier for the daemon, NULL on error
 * @param d handle for the daemon
 * @param emsg error message (NULL on success)
 */
static void
internal_hostkey_callback (void *cls, const struct GNUNET_PeerIdentity *id,
                           struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  struct InternalStartContext *internal_context = cls;

  internal_context->peer->pg->starting--;
  internal_context->peer->pg->started++;
  if (internal_context->hostname != NULL)
    decrement_outstanding_at_host (internal_context->hostname,
                                   internal_context->peer->pg);
  if (internal_context->hostkey_callback != NULL)
    internal_context->hostkey_callback (internal_context->hostkey_cls, id, d,
                                        emsg);
  else if (internal_context->peer->pg->started ==
           internal_context->peer->pg->total)
  {
    internal_context->peer->pg->started = 0;    /* Internal startup may use this counter! */
    GNUNET_TESTING_daemons_continue_startup (internal_context->peer->pg);
  }
}

/**
 * Callback that is called whenever a peer has finished starting.
 * Call the real callback and decrement the starting counter
 * for the peergroup.
 *
 * @param cls closure
 * @param id identifier for the daemon, NULL on error
 * @param cfg config
 * @param d handle for the daemon
 * @param emsg error message (NULL on success)
 */
static void
internal_startup_callback (void *cls, const struct GNUNET_PeerIdentity *id,
                           const struct GNUNET_CONFIGURATION_Handle *cfg,
                           struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  struct InternalStartContext *internal_context = cls;

  internal_context->peer->pg->starting--;
  if (internal_context->hostname != NULL)
    decrement_outstanding_at_host (internal_context->hostname,
                                   internal_context->peer->pg);
  if (internal_context->start_cb != NULL)
    internal_context->start_cb (internal_context->start_cb_cls, id, cfg, d,
                                emsg);
}


/**
 * Calls GNUNET_TESTING_daemon_continue_startup to set the daemon's state
 * from HOSTKEY_CREATED to TOPOLOGY_SETUP. Makes sure not to saturate a host
 * with requests delaying them when needed.
 *
 * @param cls closure: internal context of the daemon.
 * @param tc TaskContext
 */
static void
internal_continue_startup (void *cls,
                           const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct InternalStartContext *internal_context = cls;

  internal_context->peer->startup_task = GNUNET_SCHEDULER_NO_TASK;

  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
  {
    return;
  }

  if ((internal_context->peer->pg->starting <
       internal_context->peer->pg->max_concurrent_ssh) ||
      ((internal_context->hostname != NULL) &&
       (count_outstanding_at_host
        (internal_context->hostname,
         internal_context->peer->pg) <
        internal_context->peer->pg->max_concurrent_ssh)))
  {
    if (internal_context->hostname != NULL)
      increment_outstanding_at_host (internal_context->hostname,
                                     internal_context->peer->pg);
    internal_context->peer->pg->starting++;
    GNUNET_TESTING_daemon_continue_startup (internal_context->peer->daemon);
  }
  else
  {
    internal_context->peer->startup_task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                      (GNUNET_TIME_UNIT_MILLISECONDS, 100),
                                      &internal_continue_startup,
                                      internal_context);
  }
}

/**
 * Callback for informing us about a successful
 * or unsuccessful churn start call.
 *
 * @param cls a ChurnContext
 * @param id the peer identity of the started peer
 * @param cfg the handle to the configuration of the peer
 * @param d handle to the daemon for the peer
 * @param emsg NULL on success, non-NULL on failure
 *
 */
void
churn_start_callback (void *cls, const struct GNUNET_PeerIdentity *id,
                      const struct GNUNET_CONFIGURATION_Handle *cfg,
                      struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  struct ChurnRestartContext *startup_ctx = cls;
  struct ChurnContext *churn_ctx = startup_ctx->churn_ctx;

  unsigned int total_left;
  char *error_message;

  error_message = NULL;
  if (emsg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Churn stop callback failed with error `%s'\n", emsg);
    churn_ctx->num_failed_start++;
  }
  else
  {
    churn_ctx->num_to_start--;
  }

  total_left =
      (churn_ctx->num_to_stop - churn_ctx->num_failed_stop) +
      (churn_ctx->num_to_start - churn_ctx->num_failed_start);

  if (total_left == 0)
  {
    if ((churn_ctx->num_failed_stop > 0) || (churn_ctx->num_failed_start > 0))
      GNUNET_asprintf (&error_message,
                       "Churn didn't complete successfully, %u peers failed to start %u peers failed to be stopped!",
                       churn_ctx->num_failed_start, churn_ctx->num_failed_stop);
    churn_ctx->cb (churn_ctx->cb_cls, error_message);
    GNUNET_free_non_null (error_message);
    GNUNET_free (churn_ctx);
    GNUNET_free (startup_ctx);
  }
}

static void
schedule_churn_restart (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerRestartContext *peer_restart_ctx = cls;
  struct ChurnRestartContext *startup_ctx = peer_restart_ctx->churn_restart_ctx;

  if (startup_ctx->outstanding > startup_ctx->pg->max_concurrent_ssh)
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_MILLISECONDS, 100),
                                  &schedule_churn_restart, peer_restart_ctx);
  else
  {
    if (startup_ctx->churn_ctx->service != NULL)
      GNUNET_TESTING_daemon_start_stopped_service (peer_restart_ctx->daemon,
                                                   startup_ctx->
                                                   churn_ctx->service,
                                                   startup_ctx->timeout,
                                                   &churn_start_callback,
                                                   startup_ctx);
    else
      GNUNET_TESTING_daemon_start_stopped (peer_restart_ctx->daemon,
                                           startup_ctx->timeout,
                                           &churn_start_callback, startup_ctx);
    GNUNET_free (peer_restart_ctx);
  }
}

/**
 * Callback for informing us about a successful
 * or unsuccessful churn start call.
 *
 * @param cls a struct ServiceStartContext *startup_ctx
 * @param id the peer identity of the started peer
 * @param cfg the handle to the configuration of the peer
 * @param d handle to the daemon for the peer
 * @param emsg NULL on success, non-NULL on failure
 *
 */
void
service_start_callback (void *cls, const struct GNUNET_PeerIdentity *id,
                        const struct GNUNET_CONFIGURATION_Handle *cfg,
                        struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  struct ServiceStartContext *startup_ctx = (struct ServiceStartContext *) cls;

  if (emsg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Service start failed with error `%s'\n", emsg);
  }

  startup_ctx->outstanding--;
  startup_ctx->remaining--;

  if (startup_ctx->remaining == 0)
  {
    startup_ctx->cb (startup_ctx->cb_cls, NULL);
    GNUNET_free (startup_ctx->service);
    GNUNET_free (startup_ctx);
  }
}

static void
schedule_service_start (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerServiceStartContext *peer_ctx = cls;
  struct ServiceStartContext *startup_ctx = peer_ctx->start_ctx;

  if (startup_ctx->outstanding > startup_ctx->pg->max_concurrent_ssh)
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_MILLISECONDS, 100),
                                  &schedule_service_start, peer_ctx);
  else
  {

    GNUNET_TESTING_daemon_start_service (peer_ctx->daemon, startup_ctx->service,
                                         startup_ctx->timeout,
                                         &service_start_callback, startup_ctx);
    GNUNET_free (peer_ctx);
  }
}


static void
internal_start (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct InternalStartContext *internal_context = cls;

  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
  {
    return;
  }

  if ((internal_context->peer->pg->starting <
       internal_context->peer->pg->max_concurrent_ssh) ||
      ((internal_context->hostname != NULL) &&
       (count_outstanding_at_host
        (internal_context->hostname,
         internal_context->peer->pg) <
        internal_context->peer->pg->max_concurrent_ssh)))
  {
    if (internal_context->hostname != NULL)
      increment_outstanding_at_host (internal_context->hostname,
                                     internal_context->peer->pg);
    internal_context->peer->pg->starting++;
    internal_context->peer->daemon =
        GNUNET_TESTING_daemon_start (internal_context->peer->cfg,
                                     internal_context->timeout, GNUNET_NO,
                                     internal_context->hostname,
                                     internal_context->username,
                                     internal_context->sshport,
                                     internal_context->hostkey,
                                     &internal_hostkey_callback,
                                     internal_context,
                                     &internal_startup_callback,
                                     internal_context);
  }
  else
  {
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_MILLISECONDS, 100),
                                  &internal_start, internal_context);
  }
}

#if USE_START_HELPER

struct PeerStartHelperContext
{
  struct GNUNET_TESTING_PeerGroup *pg;

  struct HostData *host;

  struct GNUNET_OS_Process *proc;
};

static void
check_peers_started (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerStartHelperContext *helper = cls;
  enum GNUNET_OS_ProcessStatusType type;
  unsigned long code;
  unsigned int i;
  GNUNET_TESTING_NotifyDaemonRunning cb;

  if (GNUNET_NO == GNUNET_OS_process_status (helper->proc, &type, &code))       /* Still running, wait some more! */
  {
    GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_EXEC_WAIT,
                                  &check_peers_started, helper);
    return;
  }

  helper->pg->starting--;
  if (helper->pg->starting == 0)        /* All peers have finished starting! */
  {
    /* Call the peer started callback for each peer, set proper FSM state (?) */
    for (i = 0; i < helper->pg->total; i++)
    {
      cb = helper->pg->peers[i].daemon->cb;
      helper->pg->peers[i].daemon->cb = NULL;
      helper->pg->peers[i].daemon->running = GNUNET_YES;
      helper->pg->peers[i].daemon->phase = SP_START_DONE;
      if (NULL != cb)
      {
        if ((type != GNUNET_OS_PROCESS_EXITED) || (code != 0))
          cb (helper->pg->peers[i].daemon->cb_cls,
              &helper->pg->peers[i].daemon->id,
              helper->pg->peers[i].daemon->cfg, helper->pg->peers[i].daemon,
              "Failed to execute peerStartHelper.pl, or return code bad!");
        else
          cb (helper->pg->peers[i].daemon->cb_cls,
              &helper->pg->peers[i].daemon->id,
              helper->pg->peers[i].daemon->cfg, helper->pg->peers[i].daemon,
              NULL);

      }

    }
  }
  GNUNET_OS_process_destroy (helper->proc);
}

static void
start_peer_helper (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerStartHelperContext *helper = cls;
  char *baseservicehome;
  char *tempdir;
  char *arg;

  /* ssh user@host peerStartHelper /path/to/basedirectory */
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_string (helper->pg->cfg,
                                                        "PATHS", "SERVICEHOME",
                                                        &baseservicehome));
  GNUNET_asprintf (&tempdir, "%s/%s/", baseservicehome, helper->host->hostname);
  if (NULL != helper->host->username)
    GNUNET_asprintf (&arg, "%s@%s", helper->host->username,
                     helper->host->hostname);
  else
    GNUNET_asprintf (&arg, "%s", helper->host->hostname);

  /* FIXME: Doesn't support ssh_port option! */
  helper->proc =
    GNUNET_OS_start_process (GNUNET_NO, NULL, NULL, "ssh", "ssh", arg,
                               "peerStartHelper.pl", tempdir, NULL);
  GNUNET_assert (helper->proc != NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "starting peers with cmd ssh %s %s %s\n",
              arg, "peerStartHelper.pl", tempdir);
  GNUNET_SCHEDULER_add_now (&check_peers_started, helper);
  GNUNET_free (tempdir);
  GNUNET_free (baseservicehome);
  GNUNET_free (arg);
}
#endif

/**
 * Function which continues a peer group starting up
 * after successfully generating hostkeys for each peer.
 *
 * @param pg the peer group to continue starting
 *
 */
void
GNUNET_TESTING_daemons_continue_startup (struct GNUNET_TESTING_PeerGroup *pg)
{
  unsigned int i;

#if USE_START_HELPER
  if ((pg->num_hosts > 0) && (pg->hostkey_data != NULL))
  {
    struct PeerStartHelperContext *helper;

    pg->starting = pg->num_hosts;
    for (i = 0; i < pg->num_hosts; i++)
    {
      helper = GNUNET_malloc (sizeof (struct PeerStartHelperContext));
      helper->pg = pg;
      helper->host = &pg->hosts[i];
      GNUNET_SCHEDULER_add_now (&start_peer_helper, helper);
    }
  }
  else
  {
    pg->starting = 0;
    for (i = 0; i < pg->total; i++)
    {
      pg->peers[i].startup_task =
          GNUNET_SCHEDULER_add_now (&internal_continue_startup,
                                    &pg->peers[i].internal_context);
    }
  }
#else
  pg->starting = 0;
  for (i = 0; i < pg->total; i++)
  {
    pg->peers[i].startup_task =
        GNUNET_SCHEDULER_add_now (&internal_continue_startup,
                                  &pg->peers[i].internal_context);
  }
#endif
}

#if USE_START_HELPER
static void
call_hostkey_callbacks (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TESTING_PeerGroup *pg = cls;
  unsigned int i;

  for (i = 0; i < pg->total; i++)
  {
    if (pg->peers[i].internal_context.hostkey_callback != NULL)
      pg->peers[i].internal_context.hostkey_callback (pg->peers[i].
                                                      internal_context.hostkey_cls,
                                                      &pg->peers[i].daemon->id,
                                                      pg->peers[i].daemon,
                                                      NULL);
  }

  if (pg->peers[0].internal_context.hostkey_callback == NULL)
    GNUNET_TESTING_daemons_continue_startup (pg);
}
#endif

/**
 * Start count gnunet instances with the same set of transports and
 * applications.  The port numbers (any option called "PORT") will be
 * adjusted to ensure that no two peers running on the same system
 * have the same port(s) in their respective configurations.
 *
 * @param cfg configuration template to use
 * @param total number of daemons to start
 * @param max_concurrent_connections for testing, how many peers can
 *                                   we connect to simultaneously
 * @param max_concurrent_ssh when starting with ssh, how many ssh
 *        connections will we allow at once (based on remote hosts allowed!)
 * @param timeout total time allowed for peers to start
 * @param hostkey_callback function to call on each peers hostkey generation
 *        if NULL, peers will be started by this call, if non-null,
 *        GNUNET_TESTING_daemons_continue_startup must be called after
 *        successful hostkey generation
 * @param hostkey_cls closure for hostkey callback
 * @param cb function to call on each daemon that was started
 * @param cb_cls closure for cb
 * @param connect_callback function to call each time two hosts are connected
 * @param connect_callback_cls closure for connect_callback
 * @param hostnames linked list of host structs to use to start peers on
 *                  (NULL to run on localhost only)
 *
 * @return NULL on error, otherwise handle to control peer group
 */
struct GNUNET_TESTING_PeerGroup *
GNUNET_TESTING_daemons_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
                              unsigned int total,
                              unsigned int max_concurrent_connections,
                              unsigned int max_concurrent_ssh,
                              struct GNUNET_TIME_Relative timeout,
                              GNUNET_TESTING_NotifyHostkeyCreated
                              hostkey_callback, void *hostkey_cls,
                              GNUNET_TESTING_NotifyDaemonRunning cb,
                              void *cb_cls,
                              GNUNET_TESTING_NotifyConnection connect_callback,
                              void *connect_callback_cls,
                              const struct GNUNET_TESTING_Host *hostnames)
{
  struct GNUNET_TESTING_PeerGroup *pg;
  const struct GNUNET_TESTING_Host *hostpos;
  const char *hostname;
  const char *username;
  char *baseservicehome;
  char *newservicehome;
  char *tmpdir;
  char *hostkeys_file;
  char *arg;
  char *ssh_port_str;
  struct GNUNET_DISK_FileHandle *fd;
  struct GNUNET_CONFIGURATION_Handle *pcfg;
  unsigned int off;
  struct OutstandingSSH *ssh_entry;
  unsigned int hostcnt;
  unsigned int i;
  uint16_t minport;
  uint16_t sshport;
  uint32_t upnum;
  uint32_t fdnum;
  uint64_t fs;
  uint64_t total_hostkeys;
  struct GNUNET_OS_Process *proc;

  username = NULL;
  if (0 == total)
  {
    GNUNET_break (0);
    return NULL;
  }

  upnum = 0;
  fdnum = 0;
  pg = GNUNET_malloc (sizeof (struct GNUNET_TESTING_PeerGroup));
  pg->cfg = cfg;
  pg->notify_connection = connect_callback;
  pg->notify_connection_cls = connect_callback_cls;
  pg->total = total;
  pg->max_timeout = GNUNET_TIME_relative_to_absolute (timeout);
  pg->peers = GNUNET_malloc (total * sizeof (struct PeerData));
  pg->max_outstanding_connections = max_concurrent_connections;
  pg->max_concurrent_ssh = max_concurrent_ssh;
  if (NULL != hostnames)
  {
    off = 0;
    hostpos = hostnames;
    while (hostpos != NULL)
    {
      hostpos = hostpos->next;
      off++;
    }
    pg->hosts = GNUNET_malloc (off * sizeof (struct HostData));
    off = 0;

    hostpos = hostnames;
    while (hostpos != NULL)
    {
      pg->hosts[off].minport = LOW_PORT;
      pg->hosts[off].hostname = GNUNET_strdup (hostpos->hostname);
      if (hostpos->username != NULL)
        pg->hosts[off].username = GNUNET_strdup (hostpos->username);
      pg->hosts[off].sshport = hostpos->port;
      hostpos = hostpos->next;
      off++;
    }

    if (off == 0)
    {
      pg->hosts = NULL;
    }
    hostcnt = off;
    minport = 0;
    pg->num_hosts = off;
  }
  else
  {
    hostcnt = 0;
    minport = LOW_PORT;
  }

  /* Create the servicehome directory for each remote peer */
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_string (cfg, "PATHS",
                                                        "SERVICEHOME",
                                                        &baseservicehome));
  for (i = 0; i < pg->num_hosts; i++)
  {
    ssh_entry = GNUNET_malloc (sizeof (struct OutstandingSSH));
    ssh_entry->hostname = pg->hosts[i].hostname;        /* Don't free! */
    GNUNET_CONTAINER_DLL_insert (pg->ssh_head, pg->ssh_tail, ssh_entry);
    GNUNET_asprintf (&tmpdir, "%s/%s", baseservicehome, pg->hosts[i].hostname);
    if (NULL != pg->hosts[i].username)
      GNUNET_asprintf (&arg, "%s@%s", pg->hosts[i].username,
                       pg->hosts[i].hostname);
    else
      GNUNET_asprintf (&arg, "%s", pg->hosts[i].hostname);
    if (pg->hosts[i].sshport != 0)
    {
      GNUNET_asprintf (&ssh_port_str, "%d", pg->hosts[i].sshport);
      proc =
	GNUNET_OS_start_process (GNUNET_NO, NULL, NULL, "ssh", "ssh", "-P", ssh_port_str,
                                   "-q",
                                   arg, "mkdir -p", tmpdir, NULL);
    }
    else
      proc =
	GNUNET_OS_start_process (GNUNET_NO, NULL, NULL, "ssh", "ssh", arg, "mkdir -p",
                                   tmpdir, NULL);
    GNUNET_assert (proc != NULL);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Creating remote dir with command ssh %s %s %s\n", arg,
                " mkdir -p ", tmpdir);
    GNUNET_free (tmpdir);
    GNUNET_free (arg);
    GNUNET_OS_process_wait (proc);
    GNUNET_OS_process_destroy (proc);
  }
  GNUNET_free (baseservicehome);
  baseservicehome = NULL;

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "TESTING", "HOSTKEYSFILE",
                                             &hostkeys_file))
  {
    if (GNUNET_YES != GNUNET_DISK_file_test (hostkeys_file))
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Could not read hostkeys file!\n"));
    else
    {
      /* Check hostkey file size, read entire thing into memory */
      fd = GNUNET_DISK_file_open (hostkeys_file, GNUNET_DISK_OPEN_READ,
                                  GNUNET_DISK_PERM_NONE);
      if (NULL == fd)
      {
        GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "open",
                                  hostkeys_file);
        GNUNET_free (hostkeys_file);
        for (i = 0; i < pg->num_hosts; i++)
        {
          GNUNET_free (pg->hosts[i].hostname);
          GNUNET_free_non_null (pg->hosts[i].username);
        }
        GNUNET_free (pg->peers);
        GNUNET_free (pg->hosts);
        GNUNET_free (pg);
        return NULL;
      }

      if (GNUNET_OK != GNUNET_DISK_file_size (hostkeys_file, &fs, GNUNET_YES, GNUNET_YES))
        fs = 0;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Found file size %llu for hostkeys\n", fs);
      if (0 != (fs % HOSTKEYFILESIZE))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    "File size %llu seems incorrect for hostkeys...\n", fs);
      }
      else
      {
        total_hostkeys = fs / HOSTKEYFILESIZE;
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Will read %llu hostkeys from file\n", total_hostkeys);
        pg->hostkey_data = GNUNET_malloc_large (fs);
        GNUNET_assert (fs == GNUNET_DISK_file_read (fd, pg->hostkey_data, fs));
      }
      GNUNET_assert (GNUNET_OK == GNUNET_DISK_file_close (fd));
    }
    GNUNET_free (hostkeys_file);
  }

  for (off = 0; off < total; off++)
  {
    if (hostcnt > 0)
    {
      hostname = pg->hosts[off % hostcnt].hostname;
      username = pg->hosts[off % hostcnt].username;
      sshport = pg->hosts[off % hostcnt].sshport;
      pcfg =
          GNUNET_TESTING_create_cfg (cfg, off, &pg->hosts[off % hostcnt].minport, &upnum,
                       hostname, &fdnum);
    }
    else
    {
      hostname = NULL;
      username = NULL;
      sshport = 0;
      pcfg = GNUNET_TESTING_create_cfg (cfg, off, &minport, &upnum, hostname, &fdnum);
    }

    if (NULL == pcfg)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _
                  ("Could not create configuration for peer number %u on `%s'!\n"),
                  off, hostname == NULL ? "localhost" : hostname);
      continue;
    }

    if (GNUNET_YES ==
        GNUNET_CONFIGURATION_get_value_string (pcfg, "PATHS", "SERVICEHOME",
                                               &baseservicehome))
    {
      if (hostname != NULL)
        GNUNET_asprintf (&newservicehome, "%s/%s/%d/", baseservicehome,
                         hostname, off);
      else
        GNUNET_asprintf (&newservicehome, "%s/%d/", baseservicehome, off);
      GNUNET_free (baseservicehome);
      baseservicehome = NULL;
    }
    else
    {
      tmpdir = getenv ("TMPDIR");
      tmpdir = tmpdir ? tmpdir : "/tmp";
      if (hostname != NULL)
        GNUNET_asprintf (&newservicehome, "%s/%s/%s/%d/", tmpdir, hostname,
                         "gnunet-testing-test-test", off);
      else
        GNUNET_asprintf (&newservicehome, "%s/%s/%d/", tmpdir,
                         "gnunet-testing-test-test", off);
    }
    GNUNET_CONFIGURATION_set_value_string (pcfg, "PATHS", "SERVICEHOME",
                                           newservicehome);
    GNUNET_free (newservicehome);
    pg->peers[off].cfg = pcfg;
    pg->peers[off].pg = pg;
    pg->peers[off].internal_context.peer = &pg->peers[off];
    pg->peers[off].internal_context.timeout = timeout;
    pg->peers[off].internal_context.hostname = hostname;
    pg->peers[off].internal_context.username = username;
    pg->peers[off].internal_context.sshport = sshport;
    if (pg->hostkey_data != NULL)
      pg->peers[off].internal_context.hostkey =
          &pg->hostkey_data[off * HOSTKEYFILESIZE];
    pg->peers[off].internal_context.hostkey_callback = hostkey_callback;
    pg->peers[off].internal_context.hostkey_cls = hostkey_cls;
    pg->peers[off].internal_context.start_cb = cb;
    pg->peers[off].internal_context.start_cb_cls = cb_cls;
#if !USE_START_HELPER
    GNUNET_SCHEDULER_add_now (&internal_start,
                              &pg->peers[off].internal_context);
#else
    if ((pg->hostkey_data != NULL) && (hostcnt > 0))
    {
      pg->peers[off].daemon =
          GNUNET_TESTING_daemon_start (pcfg, timeout, GNUNET_YES, hostname,
                                       username, sshport,
                                       pg->peers[off].internal_context.hostkey,
                                       &internal_hostkey_callback,
                                       &pg->peers[off].internal_context,
                                       &internal_startup_callback,
                                       &pg->peers[off].internal_context);
          /**
           * At this point, given that we had a hostkeyfile,
           * we can call the hostkey callback!
           * But first, we should copy (rsync) all of the configs
           * and hostkeys to the remote peers.  Then let topology
           * creation happen, then call the peer start helper processes,
           * then set pg->whatever_phase for each peer and let them
           * enter the fsm to get the HELLO's for peers and start connecting.
           */
    }
    else
    {
      GNUNET_SCHEDULER_add_now (&internal_start,
                                &pg->peers[off].internal_context);
    }

#endif
  }

#if USE_START_HELPER            /* Now the peergroup has been set up, hostkeys and configs written to files. */
  if ((pg->hostkey_data != NULL) && (hostcnt > 0))
  {
    for (off = 0; off < hostcnt; off++)
    {

      if (hostcnt > 0)
      {
        hostname = pg->hosts[off % hostcnt].hostname;
        username = pg->hosts[off % hostcnt].username;
        sshport = pg->hosts[off % hostcnt].sshport;
      }
      else
      {
        hostname = NULL;
        username = NULL;
        sshport = 0;
      }

      if (GNUNET_YES ==
          GNUNET_CONFIGURATION_get_value_string (cfg, "PATHS", "SERVICEHOME",
                                                 &baseservicehome))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "baseservice home is %s\n",
                    baseservicehome);
        if (hostname != NULL)
          GNUNET_asprintf (&newservicehome, "%s/%s/", baseservicehome,
                           hostname);
        else
          GNUNET_asprintf (&newservicehome, "%s/", baseservicehome);
        GNUNET_free (baseservicehome);
        baseservicehome = NULL;
      }
      else
      {
        tmpdir = getenv ("TMPDIR");
        tmpdir = tmpdir ? tmpdir : "/tmp";
        if (hostname != NULL)
          GNUNET_asprintf (&newservicehome, "%s/%s/%s/", tmpdir, hostname,
                           "gnunet-testing-test-test");
        else
          GNUNET_asprintf (&newservicehome, "%s/%s/", tmpdir,
                           "gnunet-testing-test-test", off);
      }

      if (NULL != username)
        GNUNET_asprintf (&arg, "%s@%s:%s", username, pg->hosts[off].hostname,
                         newservicehome);
      else
        GNUNET_asprintf (&arg, "%s:%s", pg->hosts[off].hostname,
                         newservicehome);

      /* FIXME: Doesn't support ssh_port option! */
      proc =
	GNUNET_OS_start_process (GNUNET_NO, NULL, NULL, "rsync", "rsync", "-r",
                                   newservicehome, arg, NULL);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "copying directory with command rsync -r %s %s\n",
                  newservicehome, arg);
      GNUNET_free (newservicehome);
      GNUNET_free (arg);
      if (NULL == proc)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _
                    ("Could not start `%s' process to copy configuration directory.\n"),
                    "scp");
        GNUNET_assert (0);
      }
      GNUNET_OS_process_wait (proc);
      GNUNET_OS_process_destroy (proc);
    }
    /* Now all the configuration files and hostkeys are copied to the remote host.  Call the hostkey callback for each peer! */
    GNUNET_SCHEDULER_add_now (&call_hostkey_callbacks, pg);
  }
#endif
  return pg;
}

/*
 * Get a daemon by number, so callers don't have to do nasty
 * offsetting operation.
 */
struct GNUNET_TESTING_Daemon *
GNUNET_TESTING_daemon_get (struct GNUNET_TESTING_PeerGroup *pg,
                           unsigned int position)
{
  if (position < pg->total)
    return pg->peers[position].daemon;
  return NULL;
}

/*
 * Get a daemon by peer identity, so callers can
 * retrieve the daemon without knowing it's offset.
 *
 * @param pg the peer group to retrieve the daemon from
 * @param peer_id the peer identity of the daemon to retrieve
 *
 * @return the daemon on success, or NULL if no such peer identity is found
 */
struct GNUNET_TESTING_Daemon *
GNUNET_TESTING_daemon_get_by_id (struct GNUNET_TESTING_PeerGroup *pg,
                                 const struct GNUNET_PeerIdentity *peer_id)
{
  unsigned int i;

  for (i = 0; i < pg->total; i++)
  {
    if (0 ==
        memcmp (&pg->peers[i].daemon->id, peer_id,
                sizeof (struct GNUNET_PeerIdentity)))
      return pg->peers[i].daemon;
  }
  return NULL;
}

/**
 * Prototype of a function that will be called when a
 * particular operation was completed the testing library.
 *
 * @param cls closure (a struct RestartContext)
 * @param id id of the peer that was restarted
 * @param cfg handle to the configuration of the peer
 * @param d handle to the daemon that was restarted
 * @param emsg NULL on success
 */
static void
restart_callback (void *cls, const struct GNUNET_PeerIdentity *id,
                  const struct GNUNET_CONFIGURATION_Handle *cfg,
                  struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  struct RestartContext *restart_context = cls;

  if (emsg == NULL)
  {
    restart_context->peers_restarted++;
  }
  else
  {
    restart_context->peers_restart_failed++;
  }

  if (restart_context->peers_restarted == restart_context->peer_group->total)
  {
    restart_context->callback (restart_context->callback_cls, NULL);
    GNUNET_free (restart_context);
  }
  else if (restart_context->peers_restart_failed +
           restart_context->peers_restarted ==
           restart_context->peer_group->total)
  {
    restart_context->callback (restart_context->callback_cls,
                               "Failed to restart peers!");
    GNUNET_free (restart_context);
  }

}

/**
 * Callback for informing us about a successful
 * or unsuccessful churn stop call.
 *
 * @param cls a ChurnContext
 * @param emsg NULL on success, non-NULL on failure
 *
 */
static void
churn_stop_callback (void *cls, const char *emsg)
{
  struct ShutdownContext *shutdown_ctx = cls;
  struct ChurnContext *churn_ctx = shutdown_ctx->cb_cls;
  unsigned int total_left;
  char *error_message;

  error_message = NULL;
  shutdown_ctx->outstanding--;

  if (emsg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Churn stop callback failed with error `%s'\n", emsg);
    churn_ctx->num_failed_stop++;
  }
  else
  {
    churn_ctx->num_to_stop--;
  }

  total_left =
      (churn_ctx->num_to_stop - churn_ctx->num_failed_stop) +
      (churn_ctx->num_to_start - churn_ctx->num_failed_start);

  if (total_left == 0)
  {
    if ((churn_ctx->num_failed_stop > 0) || (churn_ctx->num_failed_start > 0))
    {
      GNUNET_asprintf (&error_message,
                       "Churn didn't complete successfully, %u peers failed to start %u peers failed to be stopped!",
                       churn_ctx->num_failed_start, churn_ctx->num_failed_stop);
    }
    churn_ctx->cb (churn_ctx->cb_cls, error_message);
    GNUNET_free_non_null (error_message);
    GNUNET_free (churn_ctx);
    GNUNET_free (shutdown_ctx);
  }
}

/**
 * Count the number of running peers.
 *
 * @param pg handle for the peer group
 *
 * @return the number of currently running peers in the peer group
 */
unsigned int
GNUNET_TESTING_daemons_running (struct GNUNET_TESTING_PeerGroup *pg)
{
  unsigned int i;
  unsigned int running = 0;

  for (i = 0; i < pg->total; i++)
  {
    if (pg->peers[i].daemon->running == GNUNET_YES)
    {
      GNUNET_assert (running != -1);
      running++;
    }
  }
  return running;
}

/**
 * Task to rate limit the number of outstanding peer shutdown
 * requests.  This is necessary for making sure we don't do
 * too many ssh connections at once, but is generally nicer
 * to any system as well (graduated task starts, as opposed
 * to calling gnunet-arm N times all at once).
 */
static void
schedule_churn_shutdown_task (void *cls,
                              const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerShutdownContext *peer_shutdown_ctx = cls;
  struct ShutdownContext *shutdown_ctx;
  struct ChurnContext *churn_ctx;

  GNUNET_assert (peer_shutdown_ctx != NULL);
  shutdown_ctx = peer_shutdown_ctx->shutdown_ctx;
  GNUNET_assert (shutdown_ctx != NULL);
  churn_ctx = (struct ChurnContext *) shutdown_ctx->cb_cls;
  if (shutdown_ctx->outstanding > churn_ctx->pg->max_concurrent_ssh)
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_MILLISECONDS, 100),
                                  &schedule_churn_shutdown_task,
                                  peer_shutdown_ctx);
  else
  {
    shutdown_ctx->outstanding++;
    if (churn_ctx->service != NULL)
      GNUNET_TESTING_daemon_stop_service (peer_shutdown_ctx->daemon,
                                          churn_ctx->service,
                                          shutdown_ctx->timeout,
                                          shutdown_ctx->cb, shutdown_ctx);
    else
      GNUNET_TESTING_daemon_stop (peer_shutdown_ctx->daemon,
                                  shutdown_ctx->timeout, shutdown_ctx->cb,
                                  shutdown_ctx, GNUNET_NO, GNUNET_YES);
    GNUNET_free (peer_shutdown_ctx);
  }
}


/**
 * Simulate churn by stopping some peers (and possibly
 * re-starting others if churn is called multiple times).  This
 * function can only be used to create leave-join churn (peers "never"
 * leave for good).  First "voff" random peers that are currently
 * online will be taken offline; then "von" random peers that are then
 * offline will be put back online.  No notifications will be
 * generated for any of these operations except for the callback upon
 * completion.
 *
 * @param pg handle for the peer group
 * @param service the service to churn off/on, NULL to churn peer
 * @param voff number of peers that should go offline
 * @param von number of peers that should come back online;
 *            must be zero on first call (since "testbed_start"
 *            always starts all of the peers)
 * @param timeout how long to wait for operations to finish before
 *        giving up
 * @param cb function to call at the end
 * @param cb_cls closure for cb
 */
void
GNUNET_TESTING_daemons_churn (struct GNUNET_TESTING_PeerGroup *pg,
                              char *service, unsigned int voff,
                              unsigned int von,
                              struct GNUNET_TIME_Relative timeout,
                              GNUNET_TESTING_NotifyCompletion cb, void *cb_cls)
{
  struct ChurnContext *churn_ctx;
  struct ShutdownContext *shutdown_ctx;
  struct PeerShutdownContext *peer_shutdown_ctx;
  struct PeerRestartContext *peer_restart_ctx;
  struct ChurnRestartContext *churn_startup_ctx;

  unsigned int running;
  unsigned int stopped;
  unsigned int total_running;
  unsigned int total_stopped;
  unsigned int i;
  unsigned int *running_arr;
  unsigned int *stopped_arr;
  unsigned int *running_permute;
  unsigned int *stopped_permute;
  char *pos;

  shutdown_ctx = NULL;
  peer_shutdown_ctx = NULL;
  peer_restart_ctx = NULL;
  churn_startup_ctx = NULL;

  running = 0;
  stopped = 0;

  if ((von == 0) && (voff == 0))        /* No peers at all? */
  {
    cb (cb_cls, NULL);
    return;
  }

  for (i = 0; i < pg->total; i++)
  {
    if (service == NULL)
    {
      if (pg->peers[i].daemon->running == GNUNET_YES)
      {
        GNUNET_assert (running != -1);
        running++;
      }
      else
      {
        GNUNET_assert (stopped != -1);
        stopped++;
      }
    }
    else
    {
      /* FIXME: make churned services a list! */
      pos = pg->peers[i].daemon->churned_services;
      /* FIXME: while (pos != NULL) */
      if (pos != NULL)
      {
#if FIXME
        if (0 == strcasecmp (pos, service))
        {

          break;
        }
#endif
        GNUNET_assert (stopped != -1);
        stopped++;
        /* FIXME: pos = pos->next; */
      }
      if (pos == NULL)
      {
        GNUNET_assert (running != -1);
        running++;
      }
    }
  }

  if (voff > running)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Trying to stop more peers (%d) than are currently running (%d)!\n",
                voff, running);
    cb (cb_cls, "Trying to stop more peers than are currently running!");
    return;
  }

  if (von > stopped)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Trying to start more peers (%d) than are currently stopped (%d)!\n",
                von, stopped);
    cb (cb_cls, "Trying to start more peers than are currently stopped!");
    return;
  }

  churn_ctx = GNUNET_malloc (sizeof (struct ChurnContext));

  if (service != NULL)
    churn_ctx->service = GNUNET_strdup (service);
  running_arr = NULL;
  if (running > 0)
    running_arr = GNUNET_malloc (running * sizeof (unsigned int));

  stopped_arr = NULL;
  if (stopped > 0)
    stopped_arr = GNUNET_malloc (stopped * sizeof (unsigned int));

  running_permute = NULL;
  stopped_permute = NULL;

  if (running > 0)
    running_permute =
        GNUNET_CRYPTO_random_permute (GNUNET_CRYPTO_QUALITY_WEAK, running);
  if (stopped > 0)
    stopped_permute =
        GNUNET_CRYPTO_random_permute (GNUNET_CRYPTO_QUALITY_WEAK, stopped);

  total_running = running;
  total_stopped = stopped;
  running = 0;
  stopped = 0;

  churn_ctx->num_to_start = von;
  churn_ctx->num_to_stop = voff;
  churn_ctx->cb = cb;
  churn_ctx->cb_cls = cb_cls;
  churn_ctx->pg = pg;

  for (i = 0; i < pg->total; i++)
  {
    if (service == NULL)
    {
      if (pg->peers[i].daemon->running == GNUNET_YES)
      {
        GNUNET_assert ((running_arr != NULL) && (total_running > running));
        running_arr[running] = i;
        running++;
      }
      else
      {
        GNUNET_assert ((stopped_arr != NULL) && (total_stopped > stopped));
        stopped_arr[stopped] = i;
        stopped++;
      }
    }
    else
    {
      /* FIXME: make churned services a list! */
      pos = pg->peers[i].daemon->churned_services;
      /* FIXME: while (pos != NULL) */
      if (pos != NULL)
      {
        GNUNET_assert ((stopped_arr != NULL) && (total_stopped > stopped));
        stopped_arr[stopped] = i;
        stopped++;
        /* FIXME: pos = pos->next; */
      }
      if (pos == NULL)
      {
        GNUNET_assert ((running_arr != NULL) && (total_running > running));
        running_arr[running] = i;
        running++;
      }
    }
  }

  GNUNET_assert (running >= voff);
  if (voff > 0)
  {
    shutdown_ctx = GNUNET_malloc (sizeof (struct ShutdownContext));
    shutdown_ctx->cb = &churn_stop_callback;
    shutdown_ctx->cb_cls = churn_ctx;
    shutdown_ctx->total_peers = voff;
    shutdown_ctx->timeout = timeout;
  }

  for (i = 0; i < voff; i++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Stopping peer %d!\n",
                running_arr[running_permute[i]]);
    GNUNET_assert (running_arr != NULL);
    peer_shutdown_ctx = GNUNET_malloc (sizeof (struct PeerShutdownContext));
    peer_shutdown_ctx->daemon =
        pg->peers[running_arr[running_permute[i]]].daemon;
    peer_shutdown_ctx->shutdown_ctx = shutdown_ctx;
    GNUNET_SCHEDULER_add_now (&schedule_churn_shutdown_task, peer_shutdown_ctx);
  }

  GNUNET_assert (stopped >= von);
  if (von > 0)
  {
    churn_startup_ctx = GNUNET_malloc (sizeof (struct ChurnRestartContext));
    churn_startup_ctx->churn_ctx = churn_ctx;
    churn_startup_ctx->timeout = timeout;
    churn_startup_ctx->pg = pg;
  }
  for (i = 0; i < von; i++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting up peer %d!\n",
                stopped_arr[stopped_permute[i]]);
    GNUNET_assert (stopped_arr != NULL);
    peer_restart_ctx = GNUNET_malloc (sizeof (struct PeerRestartContext));
    peer_restart_ctx->churn_restart_ctx = churn_startup_ctx;
    peer_restart_ctx->daemon =
        pg->peers[stopped_arr[stopped_permute[i]]].daemon;
    GNUNET_SCHEDULER_add_now (&schedule_churn_restart, peer_restart_ctx);
  }

  GNUNET_free_non_null (running_arr);
  GNUNET_free_non_null (stopped_arr);
  GNUNET_free_non_null (running_permute);
  GNUNET_free_non_null (stopped_permute);
}

/*
 * Start a given service for each of the peers in the peer group.
 *
 * @param pg handle for the peer group
 * @param service the service to start
 * @param timeout how long to wait for operations to finish before
 *        giving up
 * @param cb function to call once finished
 * @param cb_cls closure for cb
 *
 */
void
GNUNET_TESTING_daemons_start_service (struct GNUNET_TESTING_PeerGroup *pg,
                                      char *service,
                                      struct GNUNET_TIME_Relative timeout,
                                      GNUNET_TESTING_NotifyCompletion cb,
                                      void *cb_cls)
{
  struct ServiceStartContext *start_ctx;
  struct PeerServiceStartContext *peer_start_ctx;
  unsigned int i;

  GNUNET_assert (service != NULL);

  start_ctx = GNUNET_malloc (sizeof (struct ServiceStartContext));
  start_ctx->pg = pg;
  start_ctx->remaining = pg->total;
  start_ctx->cb = cb;
  start_ctx->cb_cls = cb_cls;
  start_ctx->service = GNUNET_strdup (service);
  start_ctx->timeout = timeout;

  for (i = 0; i < pg->total; i++)
  {
    peer_start_ctx = GNUNET_malloc (sizeof (struct PeerServiceStartContext));
    peer_start_ctx->start_ctx = start_ctx;
    peer_start_ctx->daemon = pg->peers[i].daemon;
    GNUNET_SCHEDULER_add_now (&schedule_service_start, peer_start_ctx);
  }
}

/**
 * Restart all peers in the given group.
 *
 * @param pg the handle to the peer group
 * @param callback function to call on completion (or failure)
 * @param callback_cls closure for the callback function
 */
void
GNUNET_TESTING_daemons_restart (struct GNUNET_TESTING_PeerGroup *pg,
                                GNUNET_TESTING_NotifyCompletion callback,
                                void *callback_cls)
{
  struct RestartContext *restart_context;
  unsigned int off;

  if (pg->total > 0)
  {
    restart_context = GNUNET_malloc (sizeof (struct RestartContext));
    restart_context->peer_group = pg;
    restart_context->peers_restarted = 0;
    restart_context->callback = callback;
    restart_context->callback_cls = callback_cls;

    for (off = 0; off < pg->total; off++)
    {
      GNUNET_TESTING_daemon_restart (pg->peers[off].daemon, &restart_callback,
                                     restart_context);
    }
  }
}


/**
 * Start or stop an individual peer from the given group.
 *
 * @param pg handle to the peer group
 * @param offset which peer to start or stop
 * @param desired_status GNUNET_YES to have it running, GNUNET_NO to stop it
 * @param timeout how long to wait for shutdown
 * @param cb function to call at the end
 * @param cb_cls closure for cb
 */
void
GNUNET_TESTING_daemons_vary (struct GNUNET_TESTING_PeerGroup *pg,
                             unsigned int offset, int desired_status,
                             struct GNUNET_TIME_Relative timeout,
                             GNUNET_TESTING_NotifyCompletion cb, void *cb_cls)
{
  struct ShutdownContext *shutdown_ctx;
  struct ChurnRestartContext *startup_ctx;
  struct ChurnContext *churn_ctx;

  if (GNUNET_NO == desired_status)
  {
    if (NULL != pg->peers[offset].daemon)
    {
      shutdown_ctx = GNUNET_malloc (sizeof (struct ShutdownContext));
      churn_ctx = GNUNET_malloc (sizeof (struct ChurnContext));
      churn_ctx->num_to_start = 0;
      churn_ctx->num_to_stop = 1;
      churn_ctx->cb = cb;
      churn_ctx->cb_cls = cb_cls;
      shutdown_ctx->cb_cls = churn_ctx;
      GNUNET_TESTING_daemon_stop (pg->peers[offset].daemon, timeout,
                                  &churn_stop_callback, shutdown_ctx, GNUNET_NO,
                                  GNUNET_YES);
    }
  }
  else if (GNUNET_YES == desired_status)
  {
    if (NULL == pg->peers[offset].daemon)
    {
      startup_ctx = GNUNET_malloc (sizeof (struct ChurnRestartContext));
      churn_ctx = GNUNET_malloc (sizeof (struct ChurnContext));
      churn_ctx->num_to_start = 1;
      churn_ctx->num_to_stop = 0;
      churn_ctx->cb = cb;
      churn_ctx->cb_cls = cb_cls;
      startup_ctx->churn_ctx = churn_ctx;
      GNUNET_TESTING_daemon_start_stopped (pg->peers[offset].daemon, timeout,
                                           &churn_start_callback, startup_ctx);
    }
  }
  else
    GNUNET_break (0);
}


/**
 * Callback for shutting down peers in a peer group.
 *
 * @param cls closure (struct ShutdownContext)
 * @param emsg NULL on success
 */
static void
internal_shutdown_callback (void *cls, const char *emsg)
{
  struct PeerShutdownContext *peer_shutdown_ctx = cls;
  struct ShutdownContext *shutdown_ctx = peer_shutdown_ctx->shutdown_ctx;
  unsigned int off;
  int i;
  struct OutstandingSSH *ssh_pos;

  shutdown_ctx->outstanding--;
  if (peer_shutdown_ctx->daemon->hostname != NULL)
    decrement_outstanding_at_host (peer_shutdown_ctx->daemon->hostname,
                                   shutdown_ctx->pg);

  if (emsg == NULL)
  {
    shutdown_ctx->peers_down++;
  }
  else
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "internal_shutdown_callback",
                     "Failed to stop a peer: %s\n", emsg);
    shutdown_ctx->peers_failed++;
  }

  if ((shutdown_ctx->cb != NULL) &&
      (shutdown_ctx->peers_down + shutdown_ctx->peers_failed ==
       shutdown_ctx->total_peers))
  {
    if (shutdown_ctx->peers_failed > 0)
      shutdown_ctx->cb (shutdown_ctx->cb_cls,
                        "Not all peers successfully shut down!");
    else
      shutdown_ctx->cb (shutdown_ctx->cb_cls, NULL);

    for (i = 0; i < shutdown_ctx->pg->total; i++)
    {
      if (shutdown_ctx->pg->peers[i].startup_task != GNUNET_SCHEDULER_NO_TASK)
        GNUNET_SCHEDULER_cancel (shutdown_ctx->pg->peers[i].startup_task);
    }
    GNUNET_free (shutdown_ctx->pg->peers);
    GNUNET_free_non_null (shutdown_ctx->pg->hostkey_data);
    for (off = 0; off < shutdown_ctx->pg->num_hosts; off++)
    {
      GNUNET_free (shutdown_ctx->pg->hosts[off].hostname);
      GNUNET_free_non_null (shutdown_ctx->pg->hosts[off].username);
    }
    GNUNET_free_non_null (shutdown_ctx->pg->hosts);
    while (NULL != (ssh_pos = shutdown_ctx->pg->ssh_head))
    {
      GNUNET_CONTAINER_DLL_remove (shutdown_ctx->pg->ssh_head,
                                   shutdown_ctx->pg->ssh_tail, ssh_pos);
      GNUNET_free (ssh_pos);
    }
    GNUNET_free (shutdown_ctx->pg);
    GNUNET_free (shutdown_ctx);
  }
  GNUNET_free (peer_shutdown_ctx);
}


/**
 * Task to rate limit the number of outstanding peer shutdown
 * requests.  This is necessary for making sure we don't do
 * too many ssh connections at once, but is generally nicer
 * to any system as well (graduated task starts, as opposed
 * to calling gnunet-arm N times all at once).
 */
static void
schedule_shutdown_task (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerShutdownContext *peer_shutdown_ctx = cls;
  struct ShutdownContext *shutdown_ctx;
  struct GNUNET_TESTING_Daemon *d;

  GNUNET_assert (peer_shutdown_ctx != NULL);
  d = peer_shutdown_ctx->daemon;
  shutdown_ctx = peer_shutdown_ctx->shutdown_ctx;
  GNUNET_assert (shutdown_ctx != NULL);

  if ((shutdown_ctx->outstanding < shutdown_ctx->pg->max_concurrent_ssh) ||
      ((d->hostname != NULL) &&
       (count_outstanding_at_host
        (d->hostname,
         shutdown_ctx->pg) < shutdown_ctx->pg->max_concurrent_ssh)))
  {
    if (d->hostname != NULL)
      increment_outstanding_at_host (d->hostname,
                                     shutdown_ctx->pg);
    shutdown_ctx->outstanding++;
    GNUNET_TESTING_daemon_stop (d,
                                shutdown_ctx->timeout,
                                &internal_shutdown_callback, peer_shutdown_ctx,
                                shutdown_ctx->delete_files, GNUNET_NO);
  }
  else
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_MILLISECONDS, 100),
                                  &schedule_shutdown_task, peer_shutdown_ctx);

}

/**
 * Read a testing hosts file based on a configuration.
 * Returns a DLL of hosts (caller must free!) on success
 * or NULL on failure.
 *
 * @param cfg a configuration with a testing section
 *
 * @return DLL of hosts on success, NULL on failure
 */
struct GNUNET_TESTING_Host *
GNUNET_TESTING_hosts_load (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_TESTING_Host *hosts;
  struct GNUNET_TESTING_Host *temphost;
  char *data;
  char *buf;
  char *hostfile;
  struct stat frstat;
  int count;
  int ret;

  /* Check for a hostfile containing user@host:port triples */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "testing", "hostfile",
                                             &hostfile))
    return NULL;

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
      GNUNET_free (hostfile);
      return NULL;
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
      return NULL;
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
            SSCANF (buf, "%a[a-zA-Z0-9_]@%a[a-zA-Z0-9.]:%hd",
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

  return hosts;
}

/**
 * Shutdown all peers started in the given group.
 *
 * @param pg handle to the peer group
 * @param timeout how long to wait for shutdown
 * @param cb callback to notify upon success or failure
 * @param cb_cls closure for cb
 */
void
GNUNET_TESTING_daemons_stop (struct GNUNET_TESTING_PeerGroup *pg,
                             struct GNUNET_TIME_Relative timeout,
                             GNUNET_TESTING_NotifyCompletion cb, void *cb_cls)
{
  unsigned int off;
  struct ShutdownContext *shutdown_ctx;
  struct PeerShutdownContext *peer_shutdown_ctx;

#if OLD
  struct PeerConnection *conn_iter;
  struct PeerConnection *temp_conn;
#endif
  struct ConnectContext *cc;

  GNUNET_assert (pg->total > 0);
  while (NULL != (cc = pg->cc_head))
  {
    GNUNET_CONTAINER_DLL_remove (pg->cc_head, pg->cc_tail, cc);
    if (GNUNET_SCHEDULER_NO_TASK != cc->task)
      GNUNET_SCHEDULER_cancel (cc->task);
    if (NULL != cc->cc)
      GNUNET_TESTING_daemons_connect_cancel (cc->cc);
    GNUNET_free (cc);
  }

  shutdown_ctx = GNUNET_malloc (sizeof (struct ShutdownContext));
  shutdown_ctx->delete_files =
      GNUNET_CONFIGURATION_get_value_yesno (pg->cfg, "TESTING", "DELETE_FILES");
  shutdown_ctx->cb = cb;
  shutdown_ctx->cb_cls = cb_cls;
  shutdown_ctx->total_peers = pg->total;
  shutdown_ctx->timeout = timeout;
  shutdown_ctx->pg = pg;

  for (off = 0; off < pg->total; off++)
  {
    GNUNET_assert (NULL != pg->peers[off].daemon);
    peer_shutdown_ctx = GNUNET_malloc (sizeof (struct PeerShutdownContext));
    peer_shutdown_ctx->daemon = pg->peers[off].daemon;
    peer_shutdown_ctx->shutdown_ctx = shutdown_ctx;
    GNUNET_SCHEDULER_add_now (&schedule_shutdown_task, peer_shutdown_ctx);

    if (NULL != pg->peers[off].cfg)
    {
      GNUNET_CONFIGURATION_destroy (pg->peers[off].cfg);
      pg->peers[off].cfg = NULL;
    }
#if OLD
// FIXME Do DLL remove for all pg->peers[off].LIST
    conn_iter = pg->peers[off].allowed_peers_head;
    while (conn_iter != NULL)
    {
      temp_conn = conn_iter->next;
      GNUNET_free (conn_iter);
      conn_iter = temp_conn;
    }
    pg->peers[off].allowed_peers_head = NULL;

    conn_iter = pg->peers[off].connect_peers_head;
    while (conn_iter != NULL)
    {
      temp_conn = conn_iter->next;
      GNUNET_free (conn_iter);
      conn_iter = temp_conn;
    }
    pg->peers[off].connect_peers_head = NULL;

    conn_iter = pg->peers[off].blacklisted_peers_head;
    while (conn_iter != NULL)
    {
      temp_conn = conn_iter->next;
      GNUNET_free (conn_iter);
      conn_iter = temp_conn;
    }
    pg->peers[off].blacklisted_peers_head = NULL;

    conn_iter = pg->peers[off].connect_peers_working_set_head;
    while (conn_iter != NULL)
    {
      temp_conn = conn_iter->next;
      GNUNET_free (conn_iter);
      conn_iter = temp_conn;
    }
    pg->peers[off].connect_peers_working_set_head = NULL;
#else
    if (pg->peers[off].allowed_peers != NULL)
      GNUNET_CONTAINER_multihashmap_destroy (pg->peers[off].allowed_peers);
    if (pg->peers[off].connect_peers != NULL)
      GNUNET_CONTAINER_multihashmap_destroy (pg->peers[off].connect_peers);
    if (pg->peers[off].blacklisted_peers != NULL)
      GNUNET_CONTAINER_multihashmap_destroy (pg->peers[off].blacklisted_peers);
#endif
  }
}

/* end of testing_group.c */
