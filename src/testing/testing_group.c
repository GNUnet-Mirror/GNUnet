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
 *
 */
#include "platform.h"
#include "gnunet_arm_service.h"
#include "gnunet_testing_lib.h"
#include "gnunet_core_service.h"

#define VERBOSE_TESTING GNUNET_NO

#define VERBOSE_TOPOLOGY GNUNET_YES

#define DEBUG_CHURN GNUNET_NO

/**
 * Lowest port used for GNUnet testing.  Should be high enough to not
 * conflict with other applications running on the hosts but be low
 * enough to not conflict with client-ports (typically starting around
 * 32k).
 */
#define LOW_PORT 10000

/**
 * Highest port used for GNUnet testing.  Should be low enough to not
 * conflict with the port range for "local" ports (client apps; see
 * /proc/sys/net/ipv4/ip_local_port_range on Linux for example).
 */
#define HIGH_PORT 56000

#define MAX_OUTSTANDING_CONNECTIONS 20

#define MAX_CONCURRENT_HOSTKEYS 10

#define MAX_CONCURRENT_STARTING 10

#define MAX_CONCURRENT_SHUTDOWN 10

#define CONNECT_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 300)

#define CONNECT_ATTEMPTS 8

/**
 * Prototype of a function called whenever two peers would be connected
 * in a certain topology.
 */
typedef int (*GNUNET_TESTING_ConnectionProcessor)(struct GNUNET_TESTING_PeerGroup *pg, 
						  unsigned int first,
						  unsigned int second);


/**
 * Context for handling churning a peer group
 */
struct ChurnContext
{
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


struct ShutdownContext
{
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

#if OLD
struct PeerConnection
{
  /*
   * Linked list
   */
  struct PeerConnection *next;

  /*
   * Pointer to daemon handle
   */
  struct GNUNET_TESTING_Daemon *daemon;

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
   * Port to use for ssh.
   */
  uint16_t sshport;

};

struct ChurnRestartContext
{
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

/**
 * Handle to a group of GNUnet peers.
 */
struct GNUNET_TESTING_PeerGroup
{
  /**
   * Our scheduler.
   */
  struct GNUNET_SCHEDULER_Handle *sched;

  /**
   * Configuration template.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

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
};

struct UpdateContext
{
  struct GNUNET_CONFIGURATION_Handle *ret;
  const struct GNUNET_CONFIGURATION_Handle *orig;
  const char *hostname;
  unsigned int nport;
  unsigned int upnum;
  unsigned int fdnum;
};


struct ConnectContext
{
  struct GNUNET_TESTING_Daemon *first;

  struct GNUNET_TESTING_Daemon *second;

  struct GNUNET_TESTING_PeerGroup *pg;
};

/**
 * Convert unique ID to hash code.
 *
 * @param uid unique ID to convert
 * @param hash set to uid (extended with zeros)
 */
static void
hash_from_uid (uint32_t uid,
               GNUNET_HashCode *hash)
{
  memset (hash, 0, sizeof(GNUNET_HashCode));
  *((uint32_t*)hash) = uid;
}

/**
 * Convert hash code to unique ID.
 *
 * @param uid unique ID to convert
 * @param hash set to uid (extended with zeros)
 */
static void
uid_from_hash (const GNUNET_HashCode *hash, uint32_t *uid)
{
  memcpy (uid, hash, sizeof(uint32_t));
}

/**
 * Number of connects we are waiting on, allows us to rate limit
 * connect attempts.
 */
static int outstanding_connects;

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
GNUNET_TESTING_topology_get(enum GNUNET_TESTING_Topology *topology, char * topology_string)
{
  /**
   * Strings representing topologies in enum
   */
  static const char * topology_strings[] =
    {
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

      NULL
    };

  int curr = 0;
  if (topology_string == NULL)
    return GNUNET_NO;
  while (topology_strings[curr] != NULL)
    {
      if (strcasecmp(topology_strings[curr], topology_string) == 0)
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
GNUNET_TESTING_topology_option_get (enum GNUNET_TESTING_TopologyOption *topology_option,
				    char * topology_string)
{
  /**
   * Options for connecting a topology as strings.
   */
  static const char * topology_option_strings[] =
    {
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
      if (strcasecmp(topology_option_strings[curr], topology_string) == 0)
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
update_config (void *cls,
               const char *section, const char *option, const char *value)
{
  struct UpdateContext *ctx = cls;
  unsigned int ival;
  char cval[12];
  char uval[128];
  char *single_variable;
  char *per_host_variable;
  unsigned long long num_per_host;

  if ((0 == strcmp (option, "PORT")) && (1 == sscanf (value, "%u", &ival)))
    {
      GNUNET_asprintf(&single_variable, "single_%s_per_host", section);
      if ((ival != 0) && (GNUNET_YES != GNUNET_CONFIGURATION_get_value_yesno(ctx->orig, "testing", single_variable)))
	{
	  GNUNET_snprintf (cval, sizeof (cval), "%u", ctx->nport++);
	  value = cval;
	}

      GNUNET_free(single_variable);
    }

  if (0 == strcmp (option, "UNIXPATH"))
    {
      GNUNET_asprintf(&single_variable, "single_%s_per_host", section);
      GNUNET_asprintf(&per_host_variable, "num_%s_per_host", section);
      if (GNUNET_YES != GNUNET_CONFIGURATION_get_value_yesno(ctx->orig, "testing", single_variable))
        {
          GNUNET_snprintf (uval,
                           sizeof (uval),
                           "/tmp/test-service-%s-%u",
                           section,
                           ctx->upnum++);
          value = uval;
        }
      else if (GNUNET_YES == GNUNET_CONFIGURATION_get_value_number(ctx->orig, "testing", per_host_variable, &num_per_host))
        {
          GNUNET_snprintf (uval,
                           sizeof (uval),
                           "/tmp/test-service-%s-%u",
                           section,
                           ctx->fdnum % num_per_host);
          value = uval;
        }
      GNUNET_free(single_variable);
      GNUNET_free(per_host_variable);

    }

  if ((0 == strcmp (option, "HOSTNAME")) && (ctx->hostname != NULL))
    {
      value = ctx->hostname;
    }

  GNUNET_CONFIGURATION_set_value_string (ctx->ret, section, option, value);
}


/**
 * Create a new configuration using the given configuration
 * as a template; however, each PORT in the existing cfg
 * must be renumbered by incrementing "*port".  If we run
 * out of "*port" numbers, return NULL.
 *
 * @param cfg template configuration
 * @param port port numbers to use, update to reflect
 *             port numbers that were used
 * @param upnum number to make unix domain socket names unique
 * @param hostname hostname of the controlling host, to allow control connections from
 * @param fdnum number used to offset the unix domain socket for grouped processes
 *              (such as statistics or peerinfo, which can be shared among others)
 *
 * @return new configuration, NULL on error
 */
static struct GNUNET_CONFIGURATION_Handle *
make_config (const struct GNUNET_CONFIGURATION_Handle *cfg, 
	     uint16_t * port,
	     uint32_t * upnum,
	     const char *hostname, uint32_t * fdnum)
{
  struct UpdateContext uc;
  uint16_t orig;
  char *control_host;
  char *allowed_hosts;

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

  if (GNUNET_CONFIGURATION_get_value_string(cfg, "testing", "control_host", &control_host) == GNUNET_OK)
    {
      if (hostname != NULL)
        GNUNET_asprintf(&allowed_hosts, "%s; 127.0.0.1; %s;", control_host, hostname);
      else
        GNUNET_asprintf(&allowed_hosts, "%s; 127.0.0.1;", control_host);

      GNUNET_CONFIGURATION_set_value_string(uc.ret, "core", "ACCEPT_FROM", allowed_hosts);
      GNUNET_CONFIGURATION_set_value_string(uc.ret, "transport", "ACCEPT_FROM", allowed_hosts);
      GNUNET_CONFIGURATION_set_value_string(uc.ret, "dht", "ACCEPT_FROM", allowed_hosts);
      GNUNET_CONFIGURATION_set_value_string(uc.ret, "statistics", "ACCEPT_FROM", allowed_hosts);
      GNUNET_free_non_null(control_host);
      GNUNET_free(allowed_hosts);
    }


  /* arm needs to know to allow connections from the host on which it is running,
   * otherwise gnunet-arm is unable to connect to it in some instances */
  if (hostname != NULL)
    {
      GNUNET_asprintf(&allowed_hosts, "%s; 127.0.0.1;", hostname);
      GNUNET_CONFIGURATION_set_value_string(uc.ret, "transport-udp", "BINDTO", hostname);
      GNUNET_CONFIGURATION_set_value_string(uc.ret, "transport-tcp", "BINDTO", hostname);
      GNUNET_CONFIGURATION_set_value_string(uc.ret, "arm", "ACCEPT_FROM", allowed_hosts);
      GNUNET_free(allowed_hosts);
    }
  else
    {
      GNUNET_CONFIGURATION_set_value_string(uc.ret, "transport-tcp", "BINDTO", "127.0.0.1");
      GNUNET_CONFIGURATION_set_value_string(uc.ret, "transport-udp", "BINDTO", "127.0.0.1");
    }


  *port = (uint16_t) uc.nport;
  *upnum = uc.upnum;
  uc.fdnum++;
  *fdnum = uc.fdnum;
  return uc.ret;
}


/*
 * Add entries to the peers connect list
 *
 * @param pg the peer group we are working with
 * @param first index of the first peer
 * @param second index of the second peer
 *
 * @return the number of connections added
 *         technically should only be 0 or 2
 *
 */
static int
add_actual_connections(struct GNUNET_TESTING_PeerGroup *pg, unsigned int first, unsigned int second)
{
  int added;
  int add_first;
  int add_second;

  GNUNET_HashCode hash_first;
  GNUNET_HashCode hash_second;

  hash_from_uid(first, &hash_first);
  hash_from_uid(second, &hash_second);

  add_first = GNUNET_NO;
  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains(pg->peers[first].connect_peers, &hash_second))
    {
      add_first = GNUNET_YES;
    }

  add_second = GNUNET_NO;
  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains(pg->peers[second].connect_peers, &hash_first))
    {
      add_second = GNUNET_YES;
    }

  added = 0;
  if (add_first)
    {
      GNUNET_assert(GNUNET_OK == GNUNET_CONTAINER_multihashmap_put(pg->peers[first].connect_peers, &hash_second, pg->peers[second].daemon, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
      pg->peers[first].num_connections++;
      added++;
    }

  if (add_second)
    {
      GNUNET_assert(GNUNET_OK == GNUNET_CONTAINER_multihashmap_put(pg->peers[second].connect_peers, &hash_first, pg->peers[first].daemon, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
      pg->peers[second].num_connections++;
      added++;
    }

  return added;
}


/*
 * Add entries to the peers allowed connections list
 *
 * @param pg the peer group we are working with
 * @param first index of the first peer
 * @param second index of the second peer
 *
 * @return the number of connections added (can be 0, 1 or 2)
 *         technically should only be 0 or 2, but the small price
 *         of iterating over the lists (hashmaps in the future)
 *         for being sure doesn't bother me!
 *
 */
static int
add_allowed_connections(struct GNUNET_TESTING_PeerGroup *pg, unsigned int first, unsigned int second)
{
  int added;
#if OLD
  struct PeerConnection *first_iter;
  struct PeerConnection *second_iter;
  struct PeerConnection *new_first;
  struct PeerConnection *new_second;
#endif
  int add_first;
  int add_second;

  GNUNET_HashCode hash_first;
  GNUNET_HashCode hash_second;

  hash_from_uid(first, &hash_first);
  hash_from_uid(second, &hash_second);

  add_first = GNUNET_NO;
  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains(pg->peers[first].allowed_peers, &hash_second))
    {
      add_first = GNUNET_YES;
    }

  add_second = GNUNET_NO;
  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains(pg->peers[second].allowed_peers, &hash_first))
    {
      add_second = GNUNET_YES;
    }
#if OLD
  first_iter = pg->peers[first].connected_peers;
  while (first_iter != NULL)
    {
      if (first_iter->daemon == pg->peers[second].daemon)
        add_first = GNUNET_NO;
      first_iter = first_iter->next;
    }

  second_iter = pg->peers[second].connected_peers;
  add_second = GNUNET_YES;
  while (second_iter != NULL)
    {
      if (second_iter->daemon == pg->peers[first].daemon)
        add_second = GNUNET_NO;
      second_iter = second_iter->next;
    }
#endif

  added = 0;
  if (add_first)
    {
      GNUNET_assert(GNUNET_OK == GNUNET_CONTAINER_multihashmap_put(pg->peers[first].allowed_peers, &hash_second, pg->peers[second].daemon, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
#if OLD
      new_first = GNUNET_malloc(sizeof(struct PeerConnection));
      new_first->daemon = pg->peers[second].daemon;
      new_first->next = pg->peers[first].connected_peers;
      pg->peers[first].connected_peers = new_first;
#endif
      pg->peers[first].num_connections++;
      added++;
    }

  if (add_second)
    {
      GNUNET_assert(GNUNET_OK == GNUNET_CONTAINER_multihashmap_put(pg->peers[second].allowed_peers, &hash_first, pg->peers[first].daemon, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
#if OLD
      new_second = GNUNET_malloc(sizeof(struct PeerConnection));
      new_second->daemon = pg->peers[first].daemon;
      new_second->next = pg->peers[second].connected_peers;
      pg->peers[second].connected_peers = new_second;
      pg->peers[first].num_connections++;
#endif
      pg->peers[second].num_connections++;
      added++;
    }

  return added;
}

/*
 * Add entries to the peers blacklisted list
 *
 * @param pg the peer group we are working with
 * @param first index of the first peer
 * @param second index of the second peer
 *
 * @return the number of connections added (can be 0, 1 or 2)
 *
 */
static int
blacklist_connections(struct GNUNET_TESTING_PeerGroup *pg, unsigned int first, unsigned int second)
{
  int added;
  int add_first;
  int add_second;
  GNUNET_HashCode hash_first;
  GNUNET_HashCode hash_second;

  hash_from_uid(first, &hash_first);
  hash_from_uid(second, &hash_second);

  add_first = GNUNET_NO;
  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains(pg->peers[first].blacklisted_peers, &hash_second))
    {
      add_first = GNUNET_YES;
    }

  add_second = GNUNET_NO;
  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains(pg->peers[second].blacklisted_peers, &hash_first))
    {
      add_second = GNUNET_YES;
    }

  added = 0;
  if (add_first)
    {
      GNUNET_assert(GNUNET_OK == GNUNET_CONTAINER_multihashmap_put(pg->peers[first].blacklisted_peers, &hash_second, pg->peers[second].daemon, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
      pg->peers[first].num_connections++;
      added++;
    }

  if (add_second)
    {
      GNUNET_assert(GNUNET_OK == GNUNET_CONTAINER_multihashmap_put(pg->peers[second].blacklisted_peers, &hash_first, pg->peers[first].daemon, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
      pg->peers[second].num_connections++;
      added++;
    }

  return added;
}

/*
 * Remove entries from the peers blacklisted list
 *
 * @param pg the peer group we are working with
 * @param first index of the first peer
 * @param second index of the second peer
 *
 * @return the number of connections removed (can be 0, 1 or 2)
 *
 */
static int
unblacklist_connections(struct GNUNET_TESTING_PeerGroup *pg, unsigned int first, unsigned int second)
{
  int removed;
  int remove_first;
  int remove_second;
  GNUNET_HashCode hash_first;
  GNUNET_HashCode hash_second;

  hash_from_uid(first, &hash_first);
  hash_from_uid(second, &hash_second);

  remove_first = GNUNET_CONTAINER_multihashmap_contains(pg->peers[first].blacklisted_peers, &hash_second);
  remove_second = GNUNET_CONTAINER_multihashmap_contains(pg->peers[second].blacklisted_peers, &hash_first);

  removed = 0;
  if (remove_first)
    {
      GNUNET_assert(GNUNET_YES == GNUNET_CONTAINER_multihashmap_remove(pg->peers[first].blacklisted_peers, &hash_second, pg->peers[second].daemon));
      removed++;
    }

  if (remove_second)
    {
      GNUNET_assert(GNUNET_YES == GNUNET_CONTAINER_multihashmap_remove(pg->peers[second].blacklisted_peers, &hash_first, pg->peers[first].daemon));
      removed++;
    }

  return removed;
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
 *
 * @return the number of connections created
 */
static int
create_scale_free (struct GNUNET_TESTING_PeerGroup *pg, GNUNET_TESTING_ConnectionProcessor proc)
{

  unsigned int total_connections;
  unsigned int outer_count;
  unsigned int i;
  unsigned int previous_total_connections;
  double random;
  double probability;

  GNUNET_assert(pg->total > 1);

  /* Add a connection between the first two nodes */
  total_connections = proc(pg, 0, 1);

  for (outer_count = 1; outer_count < pg->total; outer_count++)
    {
      previous_total_connections = total_connections;
      for (i = 0; i < outer_count; i++)
        {
          probability = pg->peers[i].num_connections / (double)previous_total_connections;
          random = ((double) GNUNET_CRYPTO_random_u64(GNUNET_CRYPTO_QUALITY_WEAK,
                                                      UINT64_MAX)) / ( (double) UINT64_MAX);
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Considering connecting peer %d to peer %d\n",
                      outer_count, i);
#endif
          if (random < probability)
            {
#if VERBOSE_TESTING
              GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                          "Connecting peer %d to peer %d\n",
                          outer_count, i);
#endif
              total_connections += proc(pg, outer_count, i);
            }
        }
    }

  return total_connections;
}

/**
 * Create a topology given a peer group (set of running peers)
 * and a connection processor.
 *
 * @param pg the peergroup to create the topology on
 * @param proc the connection processor to call to actually set
 *        up connections between two peers
 *
 * @return the number of connections that were set up
 *
 */
int
create_small_world_ring(struct GNUNET_TESTING_PeerGroup *pg, GNUNET_TESTING_ConnectionProcessor proc)
{
  unsigned int i, j;
  int nodeToConnect;
  unsigned int natLog;
  unsigned int randomPeer;
  double random, logNModifier, percentage;
  unsigned int smallWorldConnections;
  int connsPerPeer;
  char *p_string;
  int max;
  int min;
  unsigned int useAnd;
  int connect_attempts;

  logNModifier = 0.5; /* FIXME: default value? */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(pg->cfg,
							 "TESTING",
							 "LOGNMODIFIER",
							 &p_string))
    {
      if (sscanf(p_string, "%lf", &logNModifier) != 1)
	GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		    _("Invalid value `%s' for option `%s' in section `%s': expected float\n"),
		    p_string,
		    "LOGNMODIFIER",
		    "TESTING");
      GNUNET_free (p_string);
    }
  percentage = 0.5; /* FIXME: default percentage? */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(pg->cfg,
							 "TESTING",
							 "PERCENTAGE",
							 &p_string))
    {
      if (sscanf(p_string, "%lf", &percentage) != 1)
	GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		    _("Invalid value `%s' for option `%s' in section `%s': expected float\n"),
		    p_string,
		    "PERCENTAGE",
		    "TESTING");
      GNUNET_free (p_string);
    }
  natLog = log (pg->total);
  connsPerPeer = ceil (natLog * logNModifier);

  if (connsPerPeer % 2 == 1)
    connsPerPeer += 1;

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
          random = ((double) GNUNET_CRYPTO_random_u64(GNUNET_CRYPTO_QUALITY_WEAK,
						      UINT64_MAX) / ( (double) UINT64_MAX));
          if (random < percentage)
            {
              /* Connect to uniformly selected random peer */
              randomPeer =
                GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                   pg->total);
              while ((((randomPeer < max) && (randomPeer > min))
                      && (useAnd == 0)) || (((randomPeer > min)
                                             || (randomPeer < max))
                                            && (useAnd == 1)))
                {
                  randomPeer =
                      GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                                         pg->total);
                }
              smallWorldConnections +=
                proc (pg, i, randomPeer);
            }
          else
            {
              nodeToConnect = i + j + 1;
              if (nodeToConnect > pg->total - 1)
                {
                  nodeToConnect = nodeToConnect - pg->total;
                }
              connect_attempts +=
                proc (pg, i, nodeToConnect);
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
 *
 * @return the number of connections that were set up
 *
 */
static int
create_nated_internet (struct GNUNET_TESTING_PeerGroup *pg, GNUNET_TESTING_ConnectionProcessor proc)
{
  unsigned int outer_count, inner_count;
  unsigned int cutoff;
  int connect_attempts;
  double nat_percentage;
  char *p_string;

  nat_percentage = 0.6; /* FIXME: default percentage? */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(pg->cfg,
							 "TESTING",
							 "NATPERCENTAGE",
							 &p_string))
    {
      if (sscanf(p_string, "%lf", &nat_percentage) != 1)
	GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		    _("Invalid value `%s' for option `%s' in section `%s': expected float\n"),
		    p_string,
		    "NATPERCENTAGE",
		    "TESTING");
      GNUNET_free (p_string);
    }



  cutoff = (unsigned int) (nat_percentage * pg->total);

  connect_attempts = 0;

  for (outer_count = 0; outer_count < pg->total - 1; outer_count++)
    {
      for (inner_count = outer_count + 1; inner_count < pg->total;
           inner_count++)
        {
          if ((outer_count > cutoff) || (inner_count > cutoff))
            {
#if VERBOSE_TESTING
              GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                          "Connecting peer %d to peer %d\n",
                          outer_count, inner_count);
#endif
              connect_attempts += proc(pg, outer_count, inner_count);
            }
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
 *
 * @return the number of connections that were set up
 *
 */
static int
create_small_world (struct GNUNET_TESTING_PeerGroup *pg, GNUNET_TESTING_ConnectionProcessor proc)
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

  percentage = 0.5; /* FIXME: default percentage? */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(pg->cfg,
							 "TESTING",
							 "PERCENTAGE",
							 &p_string))
    {
      if (sscanf(p_string, "%lf", &percentage) != 1)
	GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		    _("Invalid value `%s' for option `%s' in section `%s': expected float\n"),
		    p_string,
		    "PERCENTAGE",
		    "TESTING");
      GNUNET_free (p_string);
    }
  if (percentage < 0.0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Invalid value `%s' for option `%s' in section `%s': got %f, needed value greater than 0\n"),
                  "PERCENTAGE", "TESTING", percentage);
      percentage = 0.5;
    }
  probability = 0.5; /* FIXME: default percentage? */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(pg->cfg,
							 "TESTING",
							 "PROBABILITY",
							 &p_string))
    {
      if (sscanf(p_string, "%lf", &probability) != 1)
	GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		    _("Invalid value `%s' for option `%s' in section `%s': expected float\n"),
		    p_string,
		    "PROBABILITY",
		    "TESTING");
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
#if VERBOSE_TESTING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Connecting nodes in 2d torus topology: %u rows %u columns\n"),
                  rows, cols);
#endif

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

      connect_attempts += proc (pg, i, nodeToConnect);

      if (i < cols)
        nodeToConnect = (rows * cols) - cols + i;
      else
        nodeToConnect = i - cols;

      if (nodeToConnect < pg->total)
        connect_attempts += proc (pg, i, nodeToConnect);
    }
  natLog = log (pg->total);
#if VERBOSE_TESTING > 2
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _("natural log of %d is %d, will run %d iterations\n"),
             pg->total, natLog, (int) (natLog * percentage));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _("Total connections added thus far: %u!\n"), connect_attempts);
#endif
  smallWorldConnections = 0;
  small_world_it = (unsigned int)(natLog * percentage);
  GNUNET_assert(small_world_it > 0 && small_world_it < (unsigned int)-1);
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
		  random = ((double) GNUNET_CRYPTO_random_u64(GNUNET_CRYPTO_QUALITY_WEAK,
							      UINT64_MAX)) / ( (double) UINT64_MAX);
                  /* If random < probability, then connect the two nodes */
                  if (random < probability)
                    smallWorldConnections += proc (pg, j, k);

                }
            }
        }
    }
  connect_attempts += smallWorldConnections;
#if VERBOSE_TESTING > 2
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Total connections added for small world: %d!\n"),
                      smallWorldConnections);
#endif
  return connect_attempts;
}

/**
 * Create a topology given a peer group (set of running peers)
 * and a connection processor.
 *
 * @param pg the peergroup to create the topology on
 * @param proc the connection processor to call to actually set
 *        up connections between two peers
 *
 * @return the number of connections that were set up
 *
 */
static int
create_erdos_renyi (struct GNUNET_TESTING_PeerGroup *pg, GNUNET_TESTING_ConnectionProcessor proc)
{
  double temp_rand;
  unsigned int outer_count;
  unsigned int inner_count;
  int connect_attempts;
  double probability;
  char *p_string;

  probability = 0.5; /* FIXME: default percentage? */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(pg->cfg,
							 "TESTING",
							 "PROBABILITY",
							 &p_string))
    {
      if (sscanf(p_string, "%lf", &probability) != 1)
	GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		    _("Invalid value `%s' for option `%s' in section `%s': expected float\n"),
		    p_string,
		    "PROBABILITY",
		    "TESTING");
      GNUNET_free (p_string);
    }
  connect_attempts = 0;
  for (outer_count = 0; outer_count < pg->total - 1; outer_count++)
    {
      for (inner_count = outer_count + 1; inner_count < pg->total;
           inner_count++)
        {
          temp_rand = ((double) GNUNET_CRYPTO_random_u64(GNUNET_CRYPTO_QUALITY_WEAK,
							 UINT64_MAX)) / ( (double) UINT64_MAX);
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("rand is %f probability is %f\n"), temp_rand,
                      probability);
#endif
          if (temp_rand < probability)
            {
              connect_attempts += proc (pg, outer_count, inner_count);
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
 *
 * @return the number of connections that were set up
 *
 */
static int
create_2d_torus (struct GNUNET_TESTING_PeerGroup *pg, GNUNET_TESTING_ConnectionProcessor proc)
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
#if VERBOSE_TESTING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Connecting nodes in 2d torus topology: %u rows %u columns\n"),
                  rows, cols);
#endif
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
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Connecting peer %d to peer %d\n",
                      i, nodeToConnect);
#endif
      connect_attempts += proc(pg, i, nodeToConnect);

      /* Second connect to the node immediately above */
      if (i < cols)
        nodeToConnect = (rows * cols) - cols + i;
      else
        nodeToConnect = i - cols;

      if (nodeToConnect < pg->total)
        {
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Connecting peer %d to peer %d\n",
                      i, nodeToConnect);
#endif
          connect_attempts += proc(pg, i, nodeToConnect);
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
 *
 * @return the number of connections that were set up
 *
 */
static int
create_clique (struct GNUNET_TESTING_PeerGroup *pg, GNUNET_TESTING_ConnectionProcessor proc)
{
  unsigned int outer_count;
  unsigned int inner_count;
  int connect_attempts;

  connect_attempts = 0;

  for (outer_count = 0; outer_count < pg->total - 1; outer_count++)
    {
      for (inner_count = outer_count + 1; inner_count < pg->total;
           inner_count++)
        {
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Connecting peer %d to peer %d\n",
                      outer_count, inner_count);
#endif
          connect_attempts += proc(pg, outer_count, inner_count);
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
 *
 * @return the number of connections that were set up
 *
 */
static int
create_line (struct GNUNET_TESTING_PeerGroup *pg, GNUNET_TESTING_ConnectionProcessor proc)
{
  unsigned int count;
  int connect_attempts;

  connect_attempts = 0;

  /* Connect each peer to the next highest numbered peer */
  for (count = 0; count < pg->total - 1; count++)
    {
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Connecting peer %d to peer %d\n",
                      count, count + 1);
#endif
      connect_attempts += proc(pg, count, count + 1);
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
 *
 * @return the number of connections that were set up
 *
 */
static int
create_ring (struct GNUNET_TESTING_PeerGroup *pg, GNUNET_TESTING_ConnectionProcessor proc)
{
  unsigned int count;
  int connect_attempts;

  connect_attempts = 0;

  /* Connect each peer to the next highest numbered peer */
  for (count = 0; count < pg->total - 1; count++)
    {
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Connecting peer %d to peer %d\n",
                      count, count + 1);
#endif
      connect_attempts += proc(pg, count, count + 1);
    }

  /* Connect the last peer to the first peer */
  connect_attempts += proc(pg, pg->total - 1, 0);

  return connect_attempts;
}


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
friend_file_iterator (void *cls,
                  const GNUNET_HashCode * key,
                  void *value)
{
  FILE *temp_friend_handle = cls;
  struct GNUNET_TESTING_Daemon *peer = value;
  struct GNUNET_PeerIdentity *temppeer;
  struct GNUNET_CRYPTO_HashAsciiEncoded peer_enc;

  temppeer = &peer->id;
  GNUNET_CRYPTO_hash_to_enc(&temppeer->hashPubKey, &peer_enc);
  fprintf(temp_friend_handle, "%s\n", (char *)&peer_enc);

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
blacklist_file_iterator (void *cls,
                         const GNUNET_HashCode * key,
                         void *value)
{
  struct BlacklistContext *blacklist_ctx = cls;
  //FILE *temp_blacklist_handle = cls;
  struct GNUNET_TESTING_Daemon *peer = value;
  struct GNUNET_PeerIdentity *temppeer;
  struct GNUNET_CRYPTO_HashAsciiEncoded peer_enc;

  temppeer = &peer->id;
  GNUNET_CRYPTO_hash_to_enc(&temppeer->hashPubKey, &peer_enc);
  fprintf(blacklist_ctx->temp_file_handle, "%s:%s\n", blacklist_ctx->transport, (char *)&peer_enc);

  return GNUNET_YES;
}

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
  pid_t *pidarr;
  char *arg;
  char * mytemp;
  enum GNUNET_OS_ProcessStatusType type;
  unsigned long return_code;
  int count;
  int ret;
  int max_wait = 10;

  pidarr = GNUNET_malloc(sizeof(pid_t) * pg->total);
  for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
    {
      mytemp = GNUNET_DISK_mktemp("friends");
      GNUNET_assert(mytemp != NULL);
      temp_friend_handle = fopen (mytemp, "wt");
      GNUNET_assert(temp_friend_handle != NULL);
      GNUNET_CONTAINER_multihashmap_iterate(pg->peers[pg_iter].allowed_peers, &friend_file_iterator, temp_friend_handle);
      fclose(temp_friend_handle);

      if (GNUNET_OK !=
	  GNUNET_CONFIGURATION_get_value_string(pg->peers[pg_iter].daemon->cfg, "PATHS", "SERVICEHOME", &temp_service_path))
	{
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		      _("No `%s' specified in peer configuration in section `%s', cannot copy friends file!\n"),
		      "SERVICEHOME",
		      "PATHS");
          if (UNLINK (mytemp) != 0)
            GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink", mytemp);
	  GNUNET_free (mytemp);
          break;
        }

      if (pg->peers[pg_iter].daemon->hostname == NULL) /* Local, just copy the file */
        {
          GNUNET_asprintf (&arg, "%s/friends", temp_service_path);
          pidarr[pg_iter] = GNUNET_OS_start_process (NULL, NULL, "mv",
                                         "mv", mytemp, arg, NULL);
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Copying file with command cp %s %s\n"), mytemp, arg);
#endif

          GNUNET_free(arg);
        }
      else /* Remote, scp the file to the correct place */
        {
          if (NULL != pg->peers[pg_iter].daemon->username)
            GNUNET_asprintf (&arg, "%s@%s:%s/friends", pg->peers[pg_iter].daemon->username, pg->peers[pg_iter].daemon->hostname, temp_service_path);
          else
            GNUNET_asprintf (&arg, "%s:%s/friends", pg->peers[pg_iter].daemon->hostname, temp_service_path);
          pidarr[pg_iter] = GNUNET_OS_start_process (NULL, NULL, "scp",
                                         "scp", mytemp, arg, NULL);

#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Copying file with command scp %s %s\n"), mytemp, arg);
#endif
          GNUNET_free(arg);
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
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Checking copy status of file %d\n"), pg_iter);
#endif
          if (pidarr[pg_iter] != 0) /* Check for already completed! */
            {
              if (GNUNET_OS_process_status(pidarr[pg_iter], &type, &return_code) != GNUNET_OK)
                {
                  ret = GNUNET_SYSERR;
                }
              else if ((type != GNUNET_OS_PROCESS_EXITED) || (return_code != 0))
                {
                  ret = GNUNET_SYSERR;
                }
              else
                {
                  pidarr[pg_iter] = 0;
#if VERBOSE_TESTING
            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("File %d copied\n"), pg_iter);
#endif
                }
            }
        }
      count++;
      if (ret == GNUNET_SYSERR)
        {
	  /* FIXME: why sleep here? -CG */
          sleep(1);
        }
    }

#if VERBOSE_TESTING
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                _("Finished copying all friend files!\n"));
#endif
  GNUNET_free(pidarr);
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
create_and_copy_blacklist_files (struct GNUNET_TESTING_PeerGroup *pg, char *transports)
{
  FILE *temp_file_handle;
  static struct BlacklistContext blacklist_ctx;
  unsigned int pg_iter;
  char *temp_service_path;
  pid_t *pidarr;
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

  pidarr = GNUNET_malloc(sizeof(pid_t) * pg->total);
  for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
    {
      mytemp = GNUNET_DISK_mktemp("blacklist");
      GNUNET_assert(mytemp != NULL);
      temp_file_handle = fopen (mytemp, "wt");
      GNUNET_assert(temp_file_handle != NULL);
      temp_transports = GNUNET_strdup(transports);
      blacklist_ctx.temp_file_handle = temp_file_handle;
      transport_len = strlen(temp_transports) + 1;
      pos = NULL;

      for (i = 0; i < transport_len; i++)
      {
        if ((temp_transports[i] == ' ') && (pos == NULL))
          continue; /* At start of string (whitespace) */
        else if ((temp_transports[i] == ' ') || (temp_transports[i] == '\0')) /* At end of string */
        {
          temp_transports[i] = '\0';
          blacklist_ctx.transport = pos;
          GNUNET_CONTAINER_multihashmap_iterate(pg->peers[pg_iter].blacklisted_peers, &blacklist_file_iterator, &blacklist_ctx);
          pos = NULL;
        } /* At beginning of actual string */
        else if (pos == NULL)
        {
          pos = &temp_transports[i];
        }
      }

      GNUNET_free (temp_transports);
      fclose(temp_file_handle);

      if (GNUNET_OK !=
          GNUNET_CONFIGURATION_get_value_string(pg->peers[pg_iter].daemon->cfg, "PATHS", "SERVICEHOME", &temp_service_path))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                      _("No `%s' specified in peer configuration in section `%s', cannot copy friends file!\n"),
                      "SERVICEHOME",
                      "PATHS");
          if (UNLINK (mytemp) != 0)
            GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink", mytemp);
          GNUNET_free (mytemp);
          break;
        }

      if (pg->peers[pg_iter].daemon->hostname == NULL) /* Local, just copy the file */
        {
          GNUNET_asprintf (&arg, "%s/blacklist", temp_service_path);
          pidarr[pg_iter] = GNUNET_OS_start_process (NULL, NULL, "mv",
                                         "mv", mytemp, arg, NULL);
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Copying file with command cp %s %s\n"), mytemp, arg);
#endif

          GNUNET_free(arg);
        }
      else /* Remote, scp the file to the correct place */
        {
          if (NULL != pg->peers[pg_iter].daemon->username)
            GNUNET_asprintf (&arg, "%s@%s:%s/blacklist", pg->peers[pg_iter].daemon->username, pg->peers[pg_iter].daemon->hostname, temp_service_path);
          else
            GNUNET_asprintf (&arg, "%s:%s/blacklist", pg->peers[pg_iter].daemon->hostname, temp_service_path);
          pidarr[pg_iter] = GNUNET_OS_start_process (NULL, NULL, "scp",
                                         "scp", mytemp, arg, NULL);

#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Copying file with command scp %s %s\n"), mytemp, arg);
#endif
          GNUNET_free(arg);
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
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Checking copy status of file %d\n"), pg_iter);
#endif
          if (pidarr[pg_iter] != 0) /* Check for already completed! */
            {
              if (GNUNET_OS_process_status(pidarr[pg_iter], &type, &return_code) != GNUNET_OK)
                {
                  ret = GNUNET_SYSERR;
                }
              else if ((type != GNUNET_OS_PROCESS_EXITED) || (return_code != 0))
                {
                  ret = GNUNET_SYSERR;
                }
              else
                {
                  pidarr[pg_iter] = 0;
#if VERBOSE_TESTING
            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("File %d copied\n"), pg_iter);
#endif
                }
            }
        }
      count++;
      if (ret == GNUNET_SYSERR)
        {
	  /* FIXME: why sleep here? -CG */
          sleep(1);
        }
    }

#if VERBOSE_TESTING
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                _("Finished copying all blacklist files!\n"));
#endif
  GNUNET_free(pidarr);
  return ret;
}


/**
 * Internal notification of a connection, kept so that we can ensure some connections
 * happen instead of flooding all testing daemons with requests to connect.
 */
static void internal_connect_notify (void *cls,
                                     const struct GNUNET_PeerIdentity *first,
                                     const struct GNUNET_PeerIdentity *second,
                                     uint32_t distance,
                                     const struct GNUNET_CONFIGURATION_Handle *first_cfg,
                                     const struct GNUNET_CONFIGURATION_Handle *second_cfg,
                                     struct GNUNET_TESTING_Daemon *first_daemon,
                                     struct GNUNET_TESTING_Daemon *second_daemon,
                                     const char *emsg)
{
  struct GNUNET_TESTING_PeerGroup *pg = cls;
  outstanding_connects--;

  pg->notify_connection(pg->notify_connection_cls, first, second, distance, first_cfg, second_cfg, first_daemon, second_daemon, emsg);
}


/**
 * Either delay a connection (because there are too many outstanding)
 * or schedule it for right now.
 *
 * @param cls a connection context
 * @param tc the task runtime context
 */
static void schedule_connect(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ConnectContext *connect_context = cls;

  if (tc->reason == GNUNET_SCHEDULER_REASON_SHUTDOWN)
    return;

  if (outstanding_connects > MAX_OUTSTANDING_CONNECTIONS)
    {
#if VERBOSE_TESTING > 2
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Delaying connect, we have too many outstanding connections!\n"));
#endif
      GNUNET_SCHEDULER_add_delayed(connect_context->pg->sched, GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS, 100), &schedule_connect, connect_context);
    }
  else
    {
#if VERBOSE_TESTING > 2
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Creating connection, outstanding_connections is %d\n"), outstanding_connects);
#endif
      outstanding_connects++;
      GNUNET_TESTING_daemons_connect (connect_context->first,
                                      connect_context->second,
                                      CONNECT_TIMEOUT,
                                      CONNECT_ATTEMPTS,
                                      &internal_connect_notify,
                                      connect_context->pg);
      GNUNET_free(connect_context);
    }
}


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
connect_iterator (void *cls,
                  const GNUNET_HashCode * key,
                  void *value)
{
  struct PeerData *first = cls;
  struct GNUNET_TESTING_Daemon *second = value;
  struct ConnectContext *connect_context;

  connect_context = GNUNET_malloc(sizeof(struct ConnectContext));
  connect_context->pg = first->pg;
  connect_context->first = first->daemon;
  connect_context->second = second;
  GNUNET_SCHEDULER_add_now(first->pg->sched, &schedule_connect, connect_context);

  return GNUNET_YES;
}


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
copy_topology_iterator (void *cls,
                  const GNUNET_HashCode * key,
                  void *value)
{
  struct PeerData *first = cls;

  GNUNET_assert(GNUNET_OK == GNUNET_CONTAINER_multihashmap_put(first->connect_peers, key, value, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));

  return GNUNET_YES;
}

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

  total = 0;
  for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
    {
      ret = GNUNET_CONTAINER_multihashmap_iterate(pg->peers[pg_iter].allowed_peers, &copy_topology_iterator, &pg->peers[pg_iter]);
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
 * @return the number of connections that will be attempted
 */
static int
connect_topology (struct GNUNET_TESTING_PeerGroup *pg)
{
  unsigned int pg_iter;
  int ret;
  int total;
#if OLD
  struct PeerConnection *connection_iter;
  struct ConnectContext *connect_context;
#endif

  total = 0;
  for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
    {
      ret = GNUNET_CONTAINER_multihashmap_iterate(pg->peers[pg_iter].connect_peers, &connect_iterator, &pg->peers[pg_iter]);
      if (GNUNET_SYSERR == ret)
        return GNUNET_SYSERR;

      total = total + ret;

#if OLD
      connection_iter = ;
      while (connection_iter != NULL)
        {
          connect_context = GNUNET_malloc(sizeof(struct ConnectContext));
          connect_context->pg = pg;
          connect_context->first = ;
          connect_context->second = connection_iter->daemon;
          GNUNET_SCHEDULER_add_now(pg->sched, &schedule_connect, connect_context);
          connection_iter = connection_iter->next;
        }
#endif
    }
  return total;
}


/**
 * Takes a peer group and creates a topology based on the
 * one specified.  Creates a topology means generates friend
 * files for the peers so they can only connect to those allowed
 * by the topology.  This will only have an effect once peers
 * are started if the FRIENDS_ONLY option is set in the base
 * config.  Also takes an optional restrict topology which
 * disallows connections based on a particular transport
 * UNLESS they are specified in the restricted topology.
 *
 * @param pg the peer group struct representing the running peers
 * @param topology which topology to connect the peers in
 * @param restrict_topology allow only direct TCP connections in this topology
 *                          use GNUNET_TESTING_TOPOLOGY_NONE for no restrictions
 * @param restrict_transports space delimited list of transports to blacklist
 *                            to create restricted topology
 *
 * @return the maximum number of connections were all allowed peers
 *         connected to each other
 */
int
GNUNET_TESTING_create_topology (struct GNUNET_TESTING_PeerGroup *pg,
                                enum GNUNET_TESTING_Topology topology,
                                enum GNUNET_TESTING_Topology restrict_topology,
                                char *restrict_transports)
{
  int ret;
  int num_connections;
  int unblacklisted_connections;

  GNUNET_assert (pg->notify_connection != NULL);

  switch (topology)
    {
    case GNUNET_TESTING_TOPOLOGY_CLIQUE:
#if VERBOSE_TESTING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Creating clique topology\n"));
#endif
      num_connections = create_clique (pg, &add_allowed_connections);
      break;
    case GNUNET_TESTING_TOPOLOGY_SMALL_WORLD_RING:
#if VERBOSE_TESTING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Creating small world (ring) topology\n"));
#endif
      num_connections = create_small_world_ring (pg, &add_allowed_connections);
      break;
    case GNUNET_TESTING_TOPOLOGY_SMALL_WORLD:
#if VERBOSE_TESTING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Creating small world (2d-torus) topology\n"));
#endif
      num_connections = create_small_world (pg, &add_allowed_connections);
      break;
    case GNUNET_TESTING_TOPOLOGY_RING:
#if VERBOSE_TESTING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Creating ring topology\n"));
#endif
      num_connections = create_ring (pg, &add_allowed_connections);
      break;
    case GNUNET_TESTING_TOPOLOGY_2D_TORUS:
#if VERBOSE_TESTING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Creating 2d torus topology\n"));
#endif
      num_connections = create_2d_torus (pg, &add_allowed_connections);
      break;
    case GNUNET_TESTING_TOPOLOGY_ERDOS_RENYI:
#if VERBOSE_TESTING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Creating Erdos-Renyi topology\n"));
#endif
      num_connections = create_erdos_renyi (pg, &add_allowed_connections);
      break;
    case GNUNET_TESTING_TOPOLOGY_INTERNAT:
#if VERBOSE_TESTING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Creating InterNAT topology\n"));
#endif
      num_connections = create_nated_internet (pg, &add_allowed_connections);
      break;
    case GNUNET_TESTING_TOPOLOGY_SCALE_FREE:
#if VERBOSE_TESTING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Creating Scale Free topology\n"));
#endif
      num_connections = create_scale_free (pg, &add_allowed_connections);
      break;
    case GNUNET_TESTING_TOPOLOGY_LINE:
#if VERBOSE_TESTING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Creating straight line topology\n"));
#endif
      num_connections = create_line (pg, &add_allowed_connections);
      break;
    case GNUNET_TESTING_TOPOLOGY_NONE:
#if VERBOSE_TESTING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Creating no allowed topology (all peers can connect at core level)\n"));
#endif
      num_connections = 0;
      break;
    default:
      num_connections = 0;
      break;
    }

  if (num_connections < 0)
    return GNUNET_SYSERR;

  if (GNUNET_YES == GNUNET_CONFIGURATION_get_value_yesno (pg->cfg, "TESTING", "F2F"))
    {
      ret = create_and_copy_friend_files(pg);
      if (ret != GNUNET_OK)
        {
#if VERBOSE_TESTING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Failed during friend file copying!\n"));
#endif
          return GNUNET_SYSERR;
        }
      else
        {
#if VERBOSE_TESTING
              GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                          _("Friend files created/copied successfully!\n"));
#endif
        }
    }

  /* Use the create clique method to initially set all connections as blacklisted. */
  if (restrict_topology != GNUNET_TESTING_TOPOLOGY_NONE)
    create_clique (pg, &blacklist_connections);
  unblacklisted_connections = 0;
  /* Un-blacklist connections as per the topology specified */
  switch (restrict_topology)
    {
    case GNUNET_TESTING_TOPOLOGY_CLIQUE:
#if VERBOSE_TESTING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Blacklisting all but clique topology\n"));
#endif
      unblacklisted_connections = create_clique (pg, &unblacklist_connections);
      break;
    case GNUNET_TESTING_TOPOLOGY_SMALL_WORLD_RING:
#if VERBOSE_TESTING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Blacklisting all but small world (ring) topology\n"));
#endif
      unblacklisted_connections = create_small_world_ring (pg, &unblacklist_connections);
      break;
    case GNUNET_TESTING_TOPOLOGY_SMALL_WORLD:
#if VERBOSE_TESTING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Blacklisting all but small world (2d-torus) topology\n"));
#endif
      unblacklisted_connections = create_small_world (pg, &unblacklist_connections);
      break;
    case GNUNET_TESTING_TOPOLOGY_RING:
#if VERBOSE_TESTING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Blacklisting all but ring topology\n"));
#endif
      unblacklisted_connections = create_ring (pg, &unblacklist_connections);
      break;
    case GNUNET_TESTING_TOPOLOGY_2D_TORUS:
#if VERBOSE_TESTING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Blacklisting all but 2d torus topology\n"));
#endif
      unblacklisted_connections = create_2d_torus (pg, &unblacklist_connections);
      break;
    case GNUNET_TESTING_TOPOLOGY_ERDOS_RENYI:
#if VERBOSE_TESTING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Blacklisting all but Erdos-Renyi topology\n"));
#endif
      unblacklisted_connections = create_erdos_renyi (pg, &unblacklist_connections);
      break;
    case GNUNET_TESTING_TOPOLOGY_INTERNAT:
#if VERBOSE_TESTING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Blacklisting all but InterNAT topology\n"));
#endif
      unblacklisted_connections = create_nated_internet (pg, &unblacklist_connections);
      break;
    case GNUNET_TESTING_TOPOLOGY_SCALE_FREE:
#if VERBOSE_TESTING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Blacklisting all but Scale Free topology\n"));
#endif
      unblacklisted_connections = create_scale_free (pg, &unblacklist_connections);
      break;
    case GNUNET_TESTING_TOPOLOGY_LINE:
#if VERBOSE_TESTING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Blacklisting all but straight line topology\n"));
#endif
      unblacklisted_connections = create_line (pg, &unblacklist_connections);
      break;
    case GNUNET_TESTING_TOPOLOGY_NONE:
#if VERBOSE_TESTING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Creating no blacklist topology (all peers can connect at transport level)\n"));
#endif
    default:
      break;
    }

  if ((unblacklisted_connections > 0) && (restrict_transports != NULL))
  {
    ret = create_and_copy_blacklist_files(pg, restrict_transports);
    if (ret != GNUNET_OK)
      {
#if VERBOSE_TESTING
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    _("Failed during blacklist file copying!\n"));
#endif
        return GNUNET_SYSERR;
      }
    else
      {
#if VERBOSE_TESTING
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    _("Blacklist files created/copied successfully!\n"));
#endif
      }
  }
  return num_connections;
}

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
 * Iterator for choosing random peers to connect.
 *
 * @param cls closure, a RandomContext
 * @param key the key the second Daemon was stored under
 * @param value the GNUNET_TESTING_Daemon that the first is to connect to
 *
 * @return GNUNET_YES to continue iteration
 */
static int
random_connect_iterator (void *cls,
                         const GNUNET_HashCode * key,
                         void *value)
{
  struct RandomContext *random_ctx = cls;
  double random_number;
  uint32_t second_pos;
  GNUNET_HashCode first_hash;
  random_number = ((double) GNUNET_CRYPTO_random_u64(GNUNET_CRYPTO_QUALITY_WEAK,
						     UINT64_MAX)) / ( (double) UINT64_MAX);
  if (random_number < random_ctx->percentage)
  {
    GNUNET_assert(GNUNET_OK == GNUNET_CONTAINER_multihashmap_put(random_ctx->first->connect_peers_working_set, key, value, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }
  /* Now we have considered this particular connection, remove it from the second peer so it's not double counted */
  uid_from_hash(key, &second_pos);
  hash_from_uid(random_ctx->first_uid, &first_hash);
  GNUNET_assert(random_ctx->pg->total > second_pos);
  GNUNET_assert(GNUNET_YES == GNUNET_CONTAINER_multihashmap_remove(random_ctx->pg->peers[second_pos].connect_peers, &first_hash, random_ctx->first->daemon));

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
minimum_connect_iterator (void *cls,
                  const GNUNET_HashCode * key,
                  void *value)
{
  struct MinimumContext *min_ctx = cls;
  uint32_t second_pos;
  GNUNET_HashCode first_hash;
  unsigned int i;

  if (GNUNET_CONTAINER_multihashmap_size(min_ctx->first->connect_peers_working_set) < min_ctx->num_to_add)
  {
    for (i = 0; i < min_ctx->num_to_add; i++)
    {
      if (min_ctx->pg_array[i] == min_ctx->current)
      {
        GNUNET_assert(GNUNET_OK == GNUNET_CONTAINER_multihashmap_put(min_ctx->first->connect_peers_working_set, key, value, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
        uid_from_hash(key, &second_pos);
        hash_from_uid(min_ctx->first_uid, &first_hash);
        GNUNET_assert(min_ctx->pg->total > second_pos);
        GNUNET_assert(GNUNET_OK == GNUNET_CONTAINER_multihashmap_put(min_ctx->pg->peers[second_pos].connect_peers_working_set, &first_hash, min_ctx->first->daemon, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
        /* Now we have added this particular connection, remove it from the second peer's map so it's not double counted */
        GNUNET_assert(GNUNET_YES == GNUNET_CONTAINER_multihashmap_remove(min_ctx->pg->peers[second_pos].connect_peers, &first_hash, min_ctx->first->daemon));
      }
    }
    min_ctx->current++;
    return GNUNET_YES;
  }
  else
    return GNUNET_NO; /* We can stop iterating, we have enough peers! */

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
dfs_connect_iterator (void *cls,
                  const GNUNET_HashCode * key,
                  void *value)
{
  struct DFSContext *dfs_ctx = cls;
  GNUNET_HashCode first_hash;

  if (dfs_ctx->current == dfs_ctx->chosen)
    {
      GNUNET_assert(GNUNET_OK == GNUNET_CONTAINER_multihashmap_put(dfs_ctx->first->connect_peers_working_set, key, value, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
      uid_from_hash(key, &dfs_ctx->second_uid);
      hash_from_uid(dfs_ctx->first_uid, &first_hash);
      GNUNET_assert(GNUNET_OK == GNUNET_CONTAINER_multihashmap_put(dfs_ctx->pg->peers[dfs_ctx->second_uid].connect_peers_working_set, &first_hash, dfs_ctx->first->daemon, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
      GNUNET_assert(GNUNET_YES == GNUNET_CONTAINER_multihashmap_remove(dfs_ctx->pg->peers[dfs_ctx->second_uid].connect_peers, &first_hash, dfs_ctx->first->daemon));
      /* Can't remove second from first yet because we are currently iterating, hence the return value in the DFSContext! */
      return GNUNET_NO; /* We have found our peer, don't iterate more */
    }

  dfs_ctx->current++;
  return GNUNET_YES;
}


/**
 * From the set of connections possible, choose percentage percent of connections
 * to actually connect.
 *
 * @param pg the peergroup we are dealing with
 * @param percentage what percent of total connections to make
 */
void
choose_random_connections(struct GNUNET_TESTING_PeerGroup *pg, double percentage)
{
  struct RandomContext random_ctx;
  uint32_t pg_iter;

  for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
    {
      random_ctx.first_uid = pg_iter;
      random_ctx.first = &pg->peers[pg_iter];
      random_ctx.percentage = percentage;
      random_ctx.pg = pg;
      pg->peers[pg_iter].connect_peers_working_set = GNUNET_CONTAINER_multihashmap_create(pg->total);
      GNUNET_CONTAINER_multihashmap_iterate(pg->peers[pg_iter].connect_peers, &random_connect_iterator, &random_ctx);
      /* Now remove the old connections */
      GNUNET_CONTAINER_multihashmap_destroy(pg->peers[pg_iter].connect_peers);
      /* And replace with the random set */
      pg->peers[pg_iter].connect_peers = pg->peers[pg_iter].connect_peers_working_set;
    }
}

/**
 * From the set of connections possible, choose at least num connections per
 * peer.
 *
 * @param pg the peergroup we are dealing with
 * @param num how many connections at least should each peer have (if possible)?
 */
static void
choose_minimum(struct GNUNET_TESTING_PeerGroup *pg, unsigned int num)
{
  struct MinimumContext minimum_ctx;
  uint32_t pg_iter;

  for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
   {
     pg->peers[pg_iter].connect_peers_working_set = GNUNET_CONTAINER_multihashmap_create(num);
   }

  for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
    {
      minimum_ctx.first_uid = pg_iter;
      minimum_ctx.pg_array = GNUNET_CRYPTO_random_permute(GNUNET_CRYPTO_QUALITY_WEAK, 
							  GNUNET_CONTAINER_multihashmap_size(pg->peers[pg_iter].connect_peers));
      minimum_ctx.first = &pg->peers[pg_iter];
      minimum_ctx.pg = pg;
      minimum_ctx.num_to_add = num;
      minimum_ctx.current = 0;
      GNUNET_CONTAINER_multihashmap_iterate(pg->peers[pg_iter].connect_peers,
					    &minimum_connect_iterator, 
					    &minimum_ctx);
    }

  for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
    {
      /* Remove the "old" connections */
      GNUNET_CONTAINER_multihashmap_destroy(pg->peers[pg_iter].connect_peers);
      /* And replace with the working set */
      pg->peers[pg_iter].connect_peers = pg->peers[pg_iter].connect_peers_working_set;
    }

}


static unsigned int
count_workingset_connections(struct GNUNET_TESTING_PeerGroup *pg)
{
  unsigned int count;
  unsigned int pg_iter;

  count = 0;

  for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
    {
      count += GNUNET_CONTAINER_multihashmap_size(pg->peers[pg_iter].connect_peers_working_set);
    }

  return count;
}


static unsigned int count_allowed_connections(struct GNUNET_TESTING_PeerGroup *pg)
{
  unsigned int count;
  unsigned int pg_iter;

  count = 0;

  for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
    {
      count += GNUNET_CONTAINER_multihashmap_size(pg->peers[pg_iter].connect_peers);
    }

  return count;
}


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
static
int find_closest_peers (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct FindClosestContext *closest_ctx = cls;
  struct GNUNET_TESTING_Daemon *daemon = value;

  if (((closest_ctx->closest == NULL) ||
       (GNUNET_CRYPTO_hash_matching_bits(&daemon->id.hashPubKey, &closest_ctx->curr_peer->daemon->id.hashPubKey) > closest_ctx->closest_dist))
      && (GNUNET_YES != GNUNET_CONTAINER_multihashmap_contains(closest_ctx->curr_peer->connect_peers, key)))
    {
      closest_ctx->closest_dist = GNUNET_CRYPTO_hash_matching_bits(&daemon->id.hashPubKey, &closest_ctx->curr_peer->daemon->id.hashPubKey);
      closest_ctx->closest = daemon;
      uid_from_hash(key, &closest_ctx->closest_num);
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
 */
void
add_closest (struct GNUNET_TESTING_PeerGroup *pg, unsigned int num, GNUNET_TESTING_ConnectionProcessor proc)
{
  struct FindClosestContext closest_ctx;
  uint32_t pg_iter;
  uint32_t i;

  for (i = 0; i < num; i++) /* Each time find a closest peer (from those available) */
    {
      for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
        {
          closest_ctx.curr_peer = &pg->peers[pg_iter];
          closest_ctx.closest = NULL;
          closest_ctx.closest_dist = 0;
          closest_ctx.closest_num = 0;
          GNUNET_CONTAINER_multihashmap_iterate(pg->peers[pg_iter].allowed_peers, &find_closest_peers, &closest_ctx);
          if (closest_ctx.closest != NULL)
            {
              GNUNET_assert((0 <= closest_ctx.closest_num) && (closest_ctx.closest_num < pg->total));
              proc(pg, pg_iter, closest_ctx.closest_num);
            }
        }
    }
}

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
  struct DFSContext dfs_ctx;
  uint32_t pg_iter;
  uint32_t dfs_count;
  uint32_t starting_peer;
  uint32_t least_connections;
  GNUNET_HashCode second_hash;

  for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
    {
      pg->peers[pg_iter].connect_peers_working_set = GNUNET_CONTAINER_multihashmap_create(num);
    }

  starting_peer = 0;
  dfs_count = 0;
  while ((count_workingset_connections(pg) < num * pg->total) && (count_allowed_connections(pg) > 0))
    {
      if (dfs_count % pg->total == 0) /* Restart the DFS at some weakly connected peer */
        {
          least_connections = -1; /* Set to very high number */
          for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
            {
              if (GNUNET_CONTAINER_multihashmap_size(pg->peers[pg_iter].connect_peers_working_set) < least_connections)
                {
                  starting_peer = pg_iter;
                  least_connections = GNUNET_CONTAINER_multihashmap_size(pg->peers[pg_iter].connect_peers_working_set);
                }
            }
        }

      if (GNUNET_CONTAINER_multihashmap_size(pg->peers[starting_peer].connect_peers) == 0)  /* Ensure there is at least one peer left to connect! */
        {
          dfs_count = 0;
          continue;
        }

      /* Choose a random peer from the chosen peers set of connections to add */
      dfs_ctx.chosen = GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, GNUNET_CONTAINER_multihashmap_size(pg->peers[starting_peer].connect_peers));
      dfs_ctx.first_uid = starting_peer;
      dfs_ctx.first = &pg->peers[starting_peer];
      dfs_ctx.pg = pg;
      dfs_ctx.current = 0;

      GNUNET_CONTAINER_multihashmap_iterate(pg->peers[starting_peer].connect_peers, &dfs_connect_iterator, &dfs_ctx);
      /* Remove the second from the first, since we will be continuing the search and may encounter the first peer again! */
      hash_from_uid(dfs_ctx.second_uid, &second_hash);
      GNUNET_assert(GNUNET_YES == GNUNET_CONTAINER_multihashmap_remove(pg->peers[starting_peer].connect_peers, &second_hash, pg->peers[dfs_ctx.second_uid].daemon));
      starting_peer = dfs_ctx.second_uid;
    }

  for (pg_iter = 0; pg_iter < pg->total; pg_iter++)
    {
      /* Remove the "old" connections */
      GNUNET_CONTAINER_multihashmap_destroy(pg->peers[pg_iter].connect_peers);
      /* And replace with the working set */
      pg->peers[pg_iter].connect_peers = pg->peers[pg_iter].connect_peers_working_set;
    }
}

/**
 * Internal callback for topology information for a particular peer.
 */
static void
internal_topology_callback(void *cls,
                           const struct GNUNET_PeerIdentity *peer,
                           struct GNUNET_TIME_Relative latency, uint32_t distance)
{
  struct CoreContext *core_ctx = cls;
  struct TopologyIterateContext *iter_ctx = core_ctx->iter_context;

  if (peer == NULL) /* Either finished, or something went wrong */
    {
      iter_ctx->completed++;
      iter_ctx->connected--;
      /* One core context allocated per iteration, must free! */
      GNUNET_free(core_ctx);
    }
  else
    {
      iter_ctx->topology_cb(iter_ctx->cls, &core_ctx->daemon->id, peer, latency, distance, NULL);
    }

  if (iter_ctx->completed == iter_ctx->total)
    {
      iter_ctx->topology_cb(iter_ctx->cls, NULL, NULL, GNUNET_TIME_relative_get_zero(), 0, NULL);
      /* Once all are done, free the iteration context */
      GNUNET_free(iter_ctx);
    }
}


/**
 * Check running topology iteration tasks, if below max start a new one, otherwise
 * schedule for some time in the future.
 */
static void
schedule_get_topology(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct CoreContext *core_context = cls;
  struct TopologyIterateContext *topology_context = (struct TopologyIterateContext *)core_context->iter_context;
  if (tc->reason == GNUNET_SCHEDULER_REASON_SHUTDOWN)
    return;

  if (topology_context->connected > MAX_OUTSTANDING_CONNECTIONS)
    {
#if VERBOSE_TESTING > 2
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Delaying connect, we have too many outstanding connections!\n"));
#endif
      GNUNET_SCHEDULER_add_delayed(core_context->daemon->sched, GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS, 100), &schedule_get_topology, core_context);
    }
  else
    {
#if VERBOSE_TESTING > 2
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Creating connection, outstanding_connections is %d\n"), outstanding_connects);
#endif
      topology_context->connected++;
      if (GNUNET_OK != GNUNET_CORE_iterate_peers (core_context->daemon->sched, core_context->daemon->cfg, &internal_topology_callback, core_context))
        internal_topology_callback(core_context, NULL, GNUNET_TIME_relative_get_zero(), 0);

    }
}

/**
 * Iterate over all (running) peers in the peer group, retrieve
 * all connections that each currently has.
 */
void
GNUNET_TESTING_get_topology (struct GNUNET_TESTING_PeerGroup *pg, GNUNET_TESTING_NotifyTopology cb, void *cls)
{
  struct TopologyIterateContext *topology_context;
  struct CoreContext *core_ctx;
  unsigned int i;
  unsigned int total_count;

  /* Allocate a single topology iteration context */
  topology_context = GNUNET_malloc(sizeof(struct TopologyIterateContext));
  topology_context->topology_cb = cb;
  topology_context->cls = cls;
  total_count = 0;
  for (i = 0; i < pg->total; i++)
    {
      if (pg->peers[i].daemon->running == GNUNET_YES)
        {
          /* Allocate one core context per core we need to connect to */
          core_ctx = GNUNET_malloc(sizeof(struct CoreContext));
          core_ctx->daemon = pg->peers[i].daemon;
          /* Set back pointer to topology iteration context */
          core_ctx->iter_context = topology_context;
          GNUNET_SCHEDULER_add_now(pg->sched, &schedule_get_topology, core_ctx);
          total_count++;
        }
    }
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
static int internal_stats_callback (void *cls,
                                    const char *subsystem,
                                    const char *name,
                                    uint64_t value,
                                    int is_persistent)
{
  struct StatsCoreContext *core_context = cls;
  struct StatsIterateContext *stats_context = (struct StatsIterateContext *)core_context->iter_context;

  return stats_context->proc(stats_context->cls, &core_context->daemon->id, subsystem, name, value, is_persistent);
}

/**
 * Internal continuation call for statistics iteration.
 *
 * @param cls closure, the CoreContext for this iteration
 * @param success whether or not the statistics iterations
 *        was canceled or not (we don't care)
 */
static void internal_stats_cont (void *cls, int success)
{
  struct StatsCoreContext *core_context = cls;
  struct StatsIterateContext *stats_context = (struct StatsIterateContext *)core_context->iter_context;

  stats_context->connected--;
  stats_context->completed++;

  if (stats_context->completed == stats_context->total)
    {
      stats_context->cont(stats_context->cls, GNUNET_YES);
      GNUNET_free(stats_context);
    }

  if (core_context->stats_handle != NULL)
    GNUNET_STATISTICS_destroy(core_context->stats_handle, GNUNET_NO);

  GNUNET_free(core_context);
}

/**
 * Check running topology iteration tasks, if below max start a new one, otherwise
 * schedule for some time in the future.
 */
static void
schedule_get_statistics(void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct StatsCoreContext *core_context = cls;
  struct StatsIterateContext *stats_context = (struct StatsIterateContext *)core_context->iter_context;

  if (tc->reason == GNUNET_SCHEDULER_REASON_SHUTDOWN)
    return;

  if (stats_context->connected > MAX_OUTSTANDING_CONNECTIONS)
    {
#if VERBOSE_TESTING > 2
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Delaying connect, we have too many outstanding connections!\n"));
#endif
      GNUNET_SCHEDULER_add_delayed(core_context->daemon->sched, GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS, 100), &schedule_get_statistics, core_context);
    }
  else
    {
#if VERBOSE_TESTING > 2
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      _("Creating connection, outstanding_connections is %d\n"), outstanding_connects);
#endif

      stats_context->connected++;
      core_context->stats_handle = GNUNET_STATISTICS_create(core_context->daemon->sched, "testing", core_context->daemon->cfg);
      if (core_context->stats_handle == NULL)
        {
          internal_stats_cont (core_context, GNUNET_NO);
          return;
        }

      core_context->stats_get_handle = GNUNET_STATISTICS_get(core_context->stats_handle, NULL, NULL, GNUNET_TIME_relative_get_forever(), &internal_stats_cont, &internal_stats_callback, core_context);
      if (core_context->stats_get_handle == NULL)
        internal_stats_cont (core_context, GNUNET_NO);

    }
}


/**
 * Iterate over all (running) peers in the peer group, retrieve
 * all statistics from each.
 */
void
GNUNET_TESTING_get_statistics (struct GNUNET_TESTING_PeerGroup *pg,
                               GNUNET_STATISTICS_Callback cont,
                               GNUNET_TESTING_STATISTICS_Iterator proc, void *cls)
{
  struct StatsIterateContext *stats_context;
  struct StatsCoreContext *core_ctx;
  unsigned int i;
  unsigned int total_count;

  /* Allocate a single stats iteration context */
  stats_context = GNUNET_malloc(sizeof(struct StatsIterateContext));
  stats_context->cont = cont;
  stats_context->proc = proc;
  stats_context->cls = cls;
  total_count = 0;
  for (i = 0; i < pg->total; i++)
    {
      if (pg->peers[i].daemon->running == GNUNET_YES)
        {
          /* Allocate one core context per core we need to connect to */
          core_ctx = GNUNET_malloc(sizeof(struct StatsCoreContext));
          core_ctx->daemon = pg->peers[i].daemon;
          /* Set back pointer to topology iteration context */
          core_ctx->iter_context = stats_context;
          GNUNET_SCHEDULER_add_now(pg->sched, &schedule_get_statistics, core_ctx);
          total_count++;
        }
    }
  stats_context->total = total_count;
  return;
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
 * @return the number of connections that will be attempted, GNUNET_SYSERR on error
 */
int
GNUNET_TESTING_connect_topology (struct GNUNET_TESTING_PeerGroup *pg,
                                 enum GNUNET_TESTING_Topology topology,
                                 enum GNUNET_TESTING_TopologyOption options,
                                 double option_modifier)
{
  switch (topology)
      {
      case GNUNET_TESTING_TOPOLOGY_CLIQUE:
#if VERBOSE_TOPOLOGY
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Creating clique CONNECT topology\n"));
#endif
        create_clique (pg, &add_actual_connections);
        break;
      case GNUNET_TESTING_TOPOLOGY_SMALL_WORLD_RING:
#if VERBOSE_TOPOLOGY
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Creating small world (ring) CONNECT topology\n"));
#endif
        create_small_world_ring (pg, &add_actual_connections);
        break;
      case GNUNET_TESTING_TOPOLOGY_SMALL_WORLD:
#if VERBOSE_TOPOLOGY
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Creating small world (2d-torus) CONNECT topology\n"));
#endif
        create_small_world (pg, &add_actual_connections);
        break;
      case GNUNET_TESTING_TOPOLOGY_RING:
#if VERBOSE_TOPOLOGY
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Creating ring CONNECT topology\n"));
#endif
        create_ring (pg, &add_actual_connections);
        break;
      case GNUNET_TESTING_TOPOLOGY_2D_TORUS:
#if VERBOSE_TOPOLOGY
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Creating 2d torus CONNECT topology\n"));
#endif
        create_2d_torus (pg, &add_actual_connections);
        break;
      case GNUNET_TESTING_TOPOLOGY_ERDOS_RENYI:
#if VERBOSE_TOPOLOGY
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Creating Erdos-Renyi CONNECT topology\n"));
#endif
        create_erdos_renyi (pg, &add_actual_connections);
        break;
      case GNUNET_TESTING_TOPOLOGY_INTERNAT:
#if VERBOSE_TOPOLOGY
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Creating InterNAT CONNECT topology\n"));
#endif
        create_nated_internet (pg, &add_actual_connections);
        break;
      case GNUNET_TESTING_TOPOLOGY_SCALE_FREE:
#if VERBOSE_TOPOLOGY
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Creating Scale Free CONNECT topology\n"));
#endif
        create_scale_free (pg, &add_actual_connections);
        break;
      case GNUNET_TESTING_TOPOLOGY_LINE:
#if VERBOSE_TOPOLOGY
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Creating straight line CONNECT topology\n"));
#endif
        create_line (pg, &add_actual_connections);
        break;
      case GNUNET_TESTING_TOPOLOGY_NONE:
#if VERBOSE_TOPOLOGY
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Creating no CONNECT topology\n"));
#endif
        copy_allowed_topology(pg);
        break;
      default:
        GNUNET_log(GNUNET_ERROR_TYPE_WARNING, 
		   _("Unknown topology specification, can't connect peers!\n"));
        return GNUNET_SYSERR;
      }

  switch (options)
    {
    case GNUNET_TESTING_TOPOLOGY_OPTION_RANDOM:
#if VERBOSE_TOPOLOGY
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Connecting random subset (%'.2f percent) of possible peers\n"), 100 * option_modifier);
#endif
      choose_random_connections(pg, option_modifier);
      break;
    case GNUNET_TESTING_TOPOLOGY_OPTION_MINIMUM:
#if VERBOSE_TOPOLOGY
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Connecting a minimum of %u peers each (if possible)\n"), (unsigned int)option_modifier);
#endif
      choose_minimum(pg, (unsigned int)option_modifier);
      break;
    case GNUNET_TESTING_TOPOLOGY_OPTION_DFS:
#if VERBOSE_TOPOLOGY
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _("Using DFS to connect a minimum of %u peers each (if possible)\n"), (unsigned int)option_modifier);
#endif
      perform_dfs(pg, (int)option_modifier);
      break;
    case GNUNET_TESTING_TOPOLOGY_OPTION_ADD_CLOSEST:
#if VERBOSE_TOPOLOGY
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Finding additional %u closest peers each (if possible)\n"), (unsigned int)option_modifier);
#endif
      add_closest(pg, (unsigned int)option_modifier, &add_actual_connections);
      break;
    case GNUNET_TESTING_TOPOLOGY_OPTION_NONE:
      break;
    case GNUNET_TESTING_TOPOLOGY_OPTION_ALL:
      break;
    default:
      break;
    }

  return connect_topology(pg);
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
static void internal_hostkey_callback (void *cls,
                                       const struct GNUNET_PeerIdentity *id,
                                       struct GNUNET_TESTING_Daemon *d,
                                       const char *emsg)
{
  struct InternalStartContext *internal_context = cls;
  internal_context->peer->pg->starting--;
  internal_context->peer->pg->started++;
  if (internal_context->hostkey_callback != NULL)
    internal_context->hostkey_callback(internal_context->hostkey_cls, id, d, emsg);
  else if (internal_context->peer->pg->started == internal_context->peer->pg->total)
    {
      internal_context->peer->pg->started = 0; /* Internal startup may use this counter! */
      GNUNET_TESTING_daemons_continue_startup(internal_context->peer->pg);
    }
}

/**
 * Callback that is called whenever a peer has finished starting.
 * Call the real callback and decrement the starting counter
 * for the peergroup.
 *
 * @param cls closure
 * @param id identifier for the daemon, NULL on error
 * @param d handle for the daemon
 * @param emsg error message (NULL on success)
 */
static void internal_startup_callback (void *cls,
                                       const struct GNUNET_PeerIdentity *id,
                                       const struct GNUNET_CONFIGURATION_Handle *cfg,
                                       struct GNUNET_TESTING_Daemon *d,
                                       const char *emsg)
{
  struct InternalStartContext *internal_context = cls;
  internal_context->peer->pg->starting--;
  if (internal_context->start_cb != NULL)
    internal_context->start_cb(internal_context->start_cb_cls, id, cfg, d, emsg);
}

static void
internal_continue_startup (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  struct InternalStartContext *internal_context = cls;

  if (tc->reason == GNUNET_SCHEDULER_REASON_SHUTDOWN)
    {
      return;
    }

  if (internal_context->peer->pg->starting < MAX_CONCURRENT_STARTING)
    {
      internal_context->peer->pg->starting++;
      GNUNET_TESTING_daemon_continue_startup (internal_context->peer->daemon);
    }
  else
    {
      GNUNET_SCHEDULER_add_delayed(internal_context->peer->pg->sched, GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS, 100), &internal_continue_startup, internal_context);
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
churn_start_callback (void *cls,
                      const struct GNUNET_PeerIdentity *id,
                      const struct GNUNET_CONFIGURATION_Handle *cfg,
                      struct GNUNET_TESTING_Daemon *d,
                      const char *emsg)
{
  struct ChurnRestartContext *startup_ctx = cls;
  struct ChurnContext *churn_ctx = startup_ctx->churn_ctx;

  unsigned int total_left;
  char *error_message;

  error_message = NULL;
  if (emsg != NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Churn stop callback failed with error `%s'\n",
                  emsg);
      churn_ctx->num_failed_start++;
    }
  else
    {
      churn_ctx->num_to_start--;
    }

#if DEBUG_CHURN
  GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
             "Started peer, %d left.\n",
             churn_ctx->num_to_start);
#endif

  total_left = (churn_ctx->num_to_stop - churn_ctx->num_failed_stop) + (churn_ctx->num_to_start - churn_ctx->num_failed_start);

  if (total_left == 0)
  {
    if ((churn_ctx->num_failed_stop > 0) || (churn_ctx->num_failed_start > 0))
      GNUNET_asprintf(&error_message,
                      "Churn didn't complete successfully, %u peers failed to start %u peers failed to be stopped!",
                      churn_ctx->num_failed_start,
                      churn_ctx->num_failed_stop);
    churn_ctx->cb(churn_ctx->cb_cls, error_message);
    GNUNET_free_non_null(error_message);
    GNUNET_free(churn_ctx);
    GNUNET_free(startup_ctx);
  }
}


static void schedule_churn_restart(void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  struct PeerRestartContext *peer_restart_ctx = cls;
  struct ChurnRestartContext *startup_ctx = peer_restart_ctx->churn_restart_ctx;

  if (startup_ctx->outstanding > MAX_CONCURRENT_STARTING)
    GNUNET_SCHEDULER_add_delayed(peer_restart_ctx->daemon->sched, GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS, 100), &schedule_churn_restart, peer_restart_ctx);
  else
    {
      GNUNET_TESTING_daemon_start_stopped(peer_restart_ctx->daemon,
                                          startup_ctx->timeout,
                                          &churn_start_callback,
                                          startup_ctx);
      GNUNET_free(peer_restart_ctx);
    }
}

static void
internal_start (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  struct InternalStartContext *internal_context = cls;

  if (tc->reason == GNUNET_SCHEDULER_REASON_SHUTDOWN)
    {
      return;
    }

  if (internal_context->peer->pg->starting < MAX_CONCURRENT_HOSTKEYS)
    {
      internal_context->peer->pg->starting++;
      internal_context->peer->daemon = GNUNET_TESTING_daemon_start (internal_context->peer->pg->sched,
                                                                    internal_context->peer->cfg,
                                                                    internal_context->timeout,
                                                                    internal_context->hostname,
                                                                    internal_context->username,
                                                                    internal_context->sshport,
                                                                    &internal_hostkey_callback,
                                                                    internal_context,
                                                                    &internal_startup_callback,
                                                                    internal_context);
    }
  else
    {
      GNUNET_SCHEDULER_add_delayed(internal_context->peer->pg->sched, GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS, 100), &internal_start, internal_context);
    }
}

/**
 * Function which continues a peer group starting up
 * after successfully generating hostkeys for each peer.
 *
 * @param pg the peer group to continue starting
 *
 */
void
GNUNET_TESTING_daemons_continue_startup(struct GNUNET_TESTING_PeerGroup *pg)
{
  unsigned int i;

  pg->starting = 0;
  for (i = 0; i < pg->total; i++)
    {
      GNUNET_SCHEDULER_add_now (pg->sched, &internal_continue_startup, &pg->peers[i].internal_context);
      //GNUNET_TESTING_daemon_continue_startup(pg->peers[i].daemon);
    }
}

/**
 * Start count gnunet instances with the same set of transports and
 * applications.  The port numbers (any option called "PORT") will be
 * adjusted to ensure that no two peers running on the same system
 * have the same port(s) in their respective configurations.
 *
 * @param sched scheduler to use
 * @param cfg configuration template to use
 * @param total number of daemons to start
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
 * @param hostnames linked list of hosts to use to start peers on (NULL to run on localhost only)
 *
 * @return NULL on error, otherwise handle to control peer group
 */
struct GNUNET_TESTING_PeerGroup *
GNUNET_TESTING_daemons_start (struct GNUNET_SCHEDULER_Handle *sched,
                              const struct GNUNET_CONFIGURATION_Handle *cfg,
                              unsigned int total,
                              struct GNUNET_TIME_Relative timeout,
                              GNUNET_TESTING_NotifyHostkeyCreated hostkey_callback,
                              void *hostkey_cls,
                              GNUNET_TESTING_NotifyDaemonRunning cb,
                              void *cb_cls,
                              GNUNET_TESTING_NotifyConnection
                              connect_callback, void *connect_callback_cls,
                              const struct GNUNET_TESTING_Host *hostnames)
{
  struct GNUNET_TESTING_PeerGroup *pg;
  const struct GNUNET_TESTING_Host *hostpos;
#if 0
  char *pos;
  const char *rpos;
  char *start;
#endif
  const char *hostname;
  const char *username;
  char *baseservicehome;
  char *newservicehome;
  char *tmpdir;
  struct GNUNET_CONFIGURATION_Handle *pcfg;
  unsigned int off;
  unsigned int hostcnt;
  uint16_t minport;
  uint16_t sshport;
  uint32_t upnum;
  uint32_t fdnum;

  if (0 == total)
    {
      GNUNET_break (0);
      return NULL;
    }
  upnum = 0;
  fdnum = 0;
  pg = GNUNET_malloc (sizeof (struct GNUNET_TESTING_PeerGroup));
  pg->sched = sched;
  pg->cfg = cfg;
  pg->notify_connection = connect_callback;
  pg->notify_connection_cls = connect_callback_cls;
  pg->total = total;
  pg->max_timeout = GNUNET_TIME_relative_to_absolute(timeout);
  pg->peers = GNUNET_malloc (total * sizeof (struct PeerData));
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
          pg->hosts[off].hostname = GNUNET_strdup(hostpos->hostname);
          if (hostpos->username != NULL)
            pg->hosts[off].username = GNUNET_strdup(hostpos->username);
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

#if NO_LL
      off = 2;
      /* skip leading spaces */
      while ((0 != *hostnames) && (isspace ( (unsigned char) *hostnames)))
        hostnames++;
      rpos = hostnames;
      while ('\0' != *rpos)
        {
          if (isspace ( (unsigned char) *rpos))
            off++;
          rpos++;
        }
      pg->hosts = GNUNET_malloc (off * sizeof (struct HostData));
      off = 0;
      start = GNUNET_strdup (hostnames);
      pos = start;
      while ('\0' != *pos)
        {
          if (isspace ( (unsigned char) *pos))
            {
              *pos = '\0';
              if (strlen (start) > 0)
                {
                  pg->hosts[off].minport = LOW_PORT;
                  pg->hosts[off++].hostname = start;
                }
              start = pos + 1;
            }
          pos++;
        }
      if (strlen (start) > 0)
        {
          pg->hosts[off].minport = LOW_PORT;
          pg->hosts[off++].hostname = start;
        }
      if (off == 0)
        {
          GNUNET_free (start);
          GNUNET_free (pg->hosts);
          pg->hosts = NULL;
        }
      hostcnt = off;
      minport = 0;              /* make gcc happy */
#endif
    }
  else
    {
      hostcnt = 0;
      minport = LOW_PORT;
    }
  for (off = 0; off < total; off++)
    {
      if (hostcnt > 0)
        {
          hostname = pg->hosts[off % hostcnt].hostname;
          username = pg->hosts[off % hostcnt].username;
          sshport = pg->hosts[off % hostcnt].sshport;
          pcfg = make_config (cfg, 
			      &pg->hosts[off % hostcnt].minport,
			      &upnum,
			      hostname, &fdnum);
        }
      else
        {
          hostname = NULL;
          username = NULL;
          sshport = 0;
          pcfg = make_config (cfg,
			      &minport,
			      &upnum,
			      hostname, &fdnum);
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
	  GNUNET_asprintf (&newservicehome,
			   "%s/%d/", baseservicehome, off);
	  GNUNET_free (baseservicehome);
        }
      else
        {
          tmpdir = getenv ("TMPDIR");
          tmpdir = tmpdir ? tmpdir : "/tmp";
	  GNUNET_asprintf (&newservicehome,
			   "%s/%s/%d/",
			   tmpdir,
			   "gnunet-testing-test-test", off);
        }
      GNUNET_CONFIGURATION_set_value_string (pcfg,
                                             "PATHS",
                                             "SERVICEHOME", newservicehome);
      GNUNET_free (newservicehome);
      pg->peers[off].cfg = pcfg;
      pg->peers[off].allowed_peers = GNUNET_CONTAINER_multihashmap_create(total);
      pg->peers[off].connect_peers = GNUNET_CONTAINER_multihashmap_create(total);
      pg->peers[off].blacklisted_peers = GNUNET_CONTAINER_multihashmap_create(total);
      pg->peers[off].pg = pg;

      pg->peers[off].internal_context.peer = &pg->peers[off];
      pg->peers[off].internal_context.timeout = timeout;
      pg->peers[off].internal_context.hostname = hostname;
      pg->peers[off].internal_context.username = username;
      pg->peers[off].internal_context.sshport = sshport;
      pg->peers[off].internal_context.hostkey_callback = hostkey_callback;
      pg->peers[off].internal_context.hostkey_cls = hostkey_cls;
      pg->peers[off].internal_context.start_cb = cb;
      pg->peers[off].internal_context.start_cb_cls = cb_cls;

      GNUNET_SCHEDULER_add_now (sched, &internal_start, &pg->peers[off].internal_context);

    }
  return pg;
}

/*
 * Get a daemon by number, so callers don't have to do nasty
 * offsetting operation.
 */
struct GNUNET_TESTING_Daemon *
GNUNET_TESTING_daemon_get (struct GNUNET_TESTING_PeerGroup *pg, unsigned int position)
{
  if (position < pg->total)
    return pg->peers[position].daemon;
  else
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
GNUNET_TESTING_daemon_get_by_id (struct GNUNET_TESTING_PeerGroup *pg, struct GNUNET_PeerIdentity *peer_id)
{
  unsigned int i;

  for (i = 0; i < pg->total; i ++)
    {
      if (0 == memcmp(&pg->peers[i].daemon->id, peer_id, sizeof(struct GNUNET_PeerIdentity)))
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
void restart_callback (void *cls,
                       const struct GNUNET_PeerIdentity *id,
                       const struct GNUNET_CONFIGURATION_Handle *cfg,
                       struct GNUNET_TESTING_Daemon *d,
                       const char *emsg)
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
      restart_context->callback(restart_context->callback_cls, NULL);
      GNUNET_free(restart_context);
    }
  else if (restart_context->peers_restart_failed + restart_context->peers_restarted == restart_context->peer_group->total)
    {
      restart_context->callback(restart_context->callback_cls, "Failed to restart peers!");
      GNUNET_free(restart_context);
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
void
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
      GNUNET_log(GNUNET_ERROR_TYPE_WARNING, 
		 "Churn stop callback failed with error `%s'\n", emsg);
      churn_ctx->num_failed_stop++;
    }
  else
    {
      churn_ctx->num_to_stop--;
    }

#if DEBUG_CHURN
  GNUNET_log(GNUNET_ERROR_TYPE_WARNING, 
	     "Stopped peer, %d left.\n", 
	     churn_ctx->num_to_stop);
#endif
  total_left = (churn_ctx->num_to_stop - churn_ctx->num_failed_stop) + (churn_ctx->num_to_start - churn_ctx->num_failed_start);

  if (total_left == 0)
  {
    if ((churn_ctx->num_failed_stop > 0) || (churn_ctx->num_failed_start > 0))
      {
        GNUNET_asprintf(&error_message, 
			"Churn didn't complete successfully, %u peers failed to start %u peers failed to be stopped!", 
			churn_ctx->num_failed_start, 
			churn_ctx->num_failed_stop);
      }
    churn_ctx->cb(churn_ctx->cb_cls, error_message);
    GNUNET_free_non_null(error_message);
    GNUNET_free(churn_ctx);
    GNUNET_free(shutdown_ctx);
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
      GNUNET_assert(running != -1);
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
schedule_churn_shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  struct PeerShutdownContext *peer_shutdown_ctx = cls;
  struct ShutdownContext *shutdown_ctx;

  GNUNET_assert(peer_shutdown_ctx != NULL);
  shutdown_ctx = peer_shutdown_ctx->shutdown_ctx;
  GNUNET_assert(shutdown_ctx != NULL);

  if (shutdown_ctx->outstanding > MAX_CONCURRENT_SHUTDOWN)
    GNUNET_SCHEDULER_add_delayed(peer_shutdown_ctx->daemon->sched, GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS, 100), &schedule_churn_shutdown_task, peer_shutdown_ctx);
  else
    {
      shutdown_ctx->outstanding++;
      GNUNET_TESTING_daemon_stop (peer_shutdown_ctx->daemon, shutdown_ctx->timeout, shutdown_ctx->cb, shutdown_ctx, GNUNET_NO, GNUNET_YES);
      GNUNET_free(peer_shutdown_ctx);
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
                              unsigned int voff,
                              unsigned int von,
                              struct GNUNET_TIME_Relative timeout,
                              GNUNET_TESTING_NotifyCompletion cb,
                              void *cb_cls)
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

  running = 0;
  stopped = 0;

  if ((von == 0) && (voff == 0)) /* No peers at all? */
    {
      cb(cb_cls, NULL);
      return;
    }

  for (i = 0; i < pg->total; i++)
  {
    if (pg->peers[i].daemon->running == GNUNET_YES)
    {
      GNUNET_assert(running != -1);
      running++;
    }
    else
    {
      GNUNET_assert(stopped != -1);
      stopped++;
    }
  }

  if (voff > running)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Trying to stop more peers than are currently running!\n");
    cb(cb_cls, "Trying to stop more peers than are currently running!");
    return;
  }

  if (von > stopped)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Trying to start more peers than are currently stopped!\n");
    cb(cb_cls, "Trying to start more peers than are currently stopped!");
    return;
  }

  churn_ctx = GNUNET_malloc(sizeof(struct ChurnContext));

  running_arr = NULL;
  if (running > 0)
    running_arr = GNUNET_malloc(running * sizeof(unsigned int));

  stopped_arr = NULL;
  if (stopped > 0)
    stopped_arr = GNUNET_malloc(stopped * sizeof(unsigned int));

  running_permute = NULL;
  stopped_permute = NULL;

  if (running > 0)
    running_permute = GNUNET_CRYPTO_random_permute(GNUNET_CRYPTO_QUALITY_WEAK, running);
  if (stopped > 0)
    stopped_permute = GNUNET_CRYPTO_random_permute(GNUNET_CRYPTO_QUALITY_WEAK, stopped);

  total_running = running;
  total_stopped = stopped;
  running = 0;
  stopped = 0;

  churn_ctx->num_to_start = von;
  churn_ctx->num_to_stop = voff;
  churn_ctx->cb = cb;
  churn_ctx->cb_cls = cb_cls;  

  for (i = 0; i < pg->total; i++)
  {
    if (pg->peers[i].daemon->running == GNUNET_YES)
    {
      GNUNET_assert((running_arr != NULL) && (total_running > running));
      running_arr[running] = i;
      running++;
    }
    else
    {
      GNUNET_assert((stopped_arr != NULL) && (total_stopped > stopped));
      stopped_arr[stopped] = i;
      stopped++;
    }
  }

  GNUNET_assert(running >= voff);
  if (voff > 0)
    {
      shutdown_ctx = GNUNET_malloc(sizeof(struct ShutdownContext));
      shutdown_ctx->cb = &churn_stop_callback;
      shutdown_ctx->cb_cls = churn_ctx;
      shutdown_ctx->total_peers = voff;
      shutdown_ctx->timeout = timeout;
    }

  for (i = 0; i < voff; i++)
  {
#if DEBUG_CHURN
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Stopping peer %d!\n", running_permute[i]);
#endif
    GNUNET_assert(running_arr != NULL);
    peer_shutdown_ctx = GNUNET_malloc(sizeof(struct PeerShutdownContext));
    peer_shutdown_ctx->daemon = pg->peers[running_arr[running_permute[i]]].daemon;
    peer_shutdown_ctx->shutdown_ctx = shutdown_ctx;
    GNUNET_SCHEDULER_add_now(peer_shutdown_ctx->daemon->sched, &schedule_churn_shutdown_task, peer_shutdown_ctx);

    /*
    GNUNET_TESTING_daemon_stop (pg->peers[running_arr[running_permute[i]]].daemon,
				timeout, 
				&churn_stop_callback, churn_ctx, 
				GNUNET_NO, GNUNET_YES); */
  }

  GNUNET_assert(stopped >= von);
  if (von > 0)
    {
      churn_startup_ctx = GNUNET_malloc(sizeof(struct ChurnRestartContext));
      churn_startup_ctx->churn_ctx = churn_ctx;
      churn_startup_ctx->timeout = timeout;
    }
  for (i = 0; i < von; i++)
    {
#if DEBUG_CHURN
      GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Starting up peer %d!\n", stopped_permute[i]);
#endif
      GNUNET_assert(stopped_arr != NULL);
      peer_restart_ctx = GNUNET_malloc(sizeof(struct PeerRestartContext));
      peer_restart_ctx->churn_restart_ctx = churn_startup_ctx;
      peer_restart_ctx->daemon = pg->peers[stopped_arr[stopped_permute[i]]].daemon;
      GNUNET_SCHEDULER_add_now(peer_restart_ctx->daemon->sched, &schedule_churn_restart, peer_restart_ctx);
      /*
      GNUNET_TESTING_daemon_start_stopped(pg->peers[stopped_arr[stopped_permute[i]]].daemon, 
					  timeout, &churn_start_callback, churn_ctx);*/
  }

  GNUNET_free_non_null(running_arr);
  GNUNET_free_non_null(stopped_arr);
  GNUNET_free_non_null(running_permute);
  GNUNET_free_non_null(stopped_permute);
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
      restart_context = GNUNET_malloc(sizeof(struct RestartContext));
      restart_context->peer_group = pg;
      restart_context->peers_restarted = 0;
      restart_context->callback = callback;
      restart_context->callback_cls = callback_cls;

      for (off = 0; off < pg->total; off++)
        {
          GNUNET_TESTING_daemon_restart (pg->peers[off].daemon, &restart_callback, restart_context);
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
			     unsigned int offset,
			     int desired_status,
			     struct GNUNET_TIME_Relative timeout,
			     GNUNET_TESTING_NotifyCompletion cb,
			     void *cb_cls)
{
  struct ShutdownContext *shutdown_ctx;
  struct ChurnRestartContext *startup_ctx;
  struct ChurnContext *churn_ctx;

  if (GNUNET_NO == desired_status)
    {
      if (NULL != pg->peers[offset].daemon)
	{
          shutdown_ctx = GNUNET_malloc(sizeof(struct ShutdownContext));
	  churn_ctx = GNUNET_malloc(sizeof(struct ChurnContext));
	  churn_ctx->num_to_start = 0;
	  churn_ctx->num_to_stop = 1;
	  churn_ctx->cb = cb;
	  churn_ctx->cb_cls = cb_cls;
	  shutdown_ctx->cb_cls = churn_ctx;
	  GNUNET_TESTING_daemon_stop(pg->peers[offset].daemon, 
				     timeout, &churn_stop_callback, shutdown_ctx,
				     GNUNET_NO, GNUNET_YES);	 
	}
    }
  else if (GNUNET_YES == desired_status)
    {
      if (NULL == pg->peers[offset].daemon)
	{
          startup_ctx = GNUNET_malloc(sizeof(struct ChurnRestartContext));
	  churn_ctx = GNUNET_malloc(sizeof(struct ChurnContext));
	  churn_ctx->num_to_start = 1;
	  churn_ctx->num_to_stop = 0;
	  churn_ctx->cb = cb;
	  churn_ctx->cb_cls = cb_cls;  
	  startup_ctx->churn_ctx = churn_ctx;
	  GNUNET_TESTING_daemon_start_stopped(pg->peers[offset].daemon, 
					      timeout, &churn_start_callback, startup_ctx);
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
void internal_shutdown_callback (void *cls,
                                 const char *emsg)
{
  struct ShutdownContext *shutdown_ctx = cls;

  shutdown_ctx->outstanding--;
  if (emsg == NULL)
    {
      shutdown_ctx->peers_down++;
    }
  else
    {
      shutdown_ctx->peers_failed++;
    }

  if ((shutdown_ctx->cb != NULL) && (shutdown_ctx->peers_down + shutdown_ctx->peers_failed == shutdown_ctx->total_peers))
    {
      if (shutdown_ctx->peers_failed > 0)
        shutdown_ctx->cb(shutdown_ctx->cb_cls, "Not all peers successfully shut down!");
      else
        shutdown_ctx->cb(shutdown_ctx->cb_cls, NULL);
      GNUNET_free(shutdown_ctx);
    }
}


/**
 * Task to rate limit the number of outstanding peer shutdown
 * requests.  This is necessary for making sure we don't do
 * too many ssh connections at once, but is generally nicer
 * to any system as well (graduated task starts, as opposed
 * to calling gnunet-arm N times all at once).
 */
static void
schedule_shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  struct PeerShutdownContext *peer_shutdown_ctx = cls;
  struct ShutdownContext *shutdown_ctx;

  GNUNET_assert(peer_shutdown_ctx != NULL);
  shutdown_ctx = peer_shutdown_ctx->shutdown_ctx;
  GNUNET_assert(shutdown_ctx != NULL);

  if (shutdown_ctx->outstanding > MAX_CONCURRENT_SHUTDOWN)
    GNUNET_SCHEDULER_add_delayed(peer_shutdown_ctx->daemon->sched, GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS, 100), &schedule_shutdown_task, peer_shutdown_ctx);
  else
    {
      shutdown_ctx->outstanding++;
      GNUNET_TESTING_daemon_stop (peer_shutdown_ctx->daemon, shutdown_ctx->timeout, &internal_shutdown_callback, shutdown_ctx, GNUNET_YES, GNUNET_NO);
      GNUNET_free(peer_shutdown_ctx);
    }
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
			     GNUNET_TESTING_NotifyCompletion cb,
                             void *cb_cls)
{
  unsigned int off;
  struct ShutdownContext *shutdown_ctx;
  struct PeerShutdownContext *peer_shutdown_ctx;

  GNUNET_assert(pg->total > 0);

  shutdown_ctx = GNUNET_malloc(sizeof(struct ShutdownContext));
  shutdown_ctx->cb = cb;
  shutdown_ctx->cb_cls = cb_cls;
  shutdown_ctx->total_peers = pg->total;
  shutdown_ctx->timeout = timeout;
  /* shtudown_ctx->outstanding = 0; */

  for (off = 0; off < pg->total; off++)
    {
      GNUNET_assert(NULL != pg->peers[off].daemon);
      peer_shutdown_ctx = GNUNET_malloc(sizeof(struct PeerShutdownContext));
      peer_shutdown_ctx->daemon = pg->peers[off].daemon;
      peer_shutdown_ctx->shutdown_ctx = shutdown_ctx;
      GNUNET_SCHEDULER_add_now(pg->peers[off].daemon->sched, &schedule_shutdown_task, peer_shutdown_ctx);
      //GNUNET_TESTING_daemon_stop (pg->peers[off].daemon, timeout, shutdown_cb, shutdown_ctx, GNUNET_YES, GNUNET_NO);
      if (NULL != pg->peers[off].cfg)
        GNUNET_CONFIGURATION_destroy (pg->peers[off].cfg);
      if (pg->peers[off].allowed_peers != NULL)
        GNUNET_CONTAINER_multihashmap_destroy(pg->peers[off].allowed_peers);
      if (pg->peers[off].connect_peers != NULL)
        GNUNET_CONTAINER_multihashmap_destroy(pg->peers[off].connect_peers);
      if (pg->peers[off].blacklisted_peers != NULL)
        GNUNET_CONTAINER_multihashmap_destroy(pg->peers[off].blacklisted_peers);
    }
  GNUNET_free (pg->peers);
  for (off = 0; off < pg->num_hosts; off++)
    {
      GNUNET_free (pg->hosts[off].hostname);
      GNUNET_free_non_null (pg->hosts[off].username);
    }
  GNUNET_free_non_null (pg->hosts);
  GNUNET_free (pg);
}


/* end of testing_group.c */
