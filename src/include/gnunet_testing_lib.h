/*
      This file is part of GNUnet
      (C) 2008, 2009 Christian Grothoff (and other contributing authors)

      GNUnet is free software; you can redistribute it and/or modify
      it under the terms of the GNU General Public License as published
      by the Free Software Foundation; either version 2, or (at your
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
 * @file include/gnunet_testing_lib.h
 * @brief convenience API for writing testcases for GNUnet
 *        Many testcases need to start and stop gnunetd,
 *        and this library is supposed to make that easier
 *        for TESTCASES.  Normal programs should always
 *        use functions from gnunet_{util,arm}_lib.h.  This API is
 *        ONLY for writing testcases!
 * @author Christian Grothoff
 */

#ifndef GNUNET_TESTING_LIB_H
#define GNUNET_TESTING_LIB_H

#include "gnunet_util_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Handle for a GNUnet daemon (technically a set of
 * daemons; the handle is really for the master ARM
 * daemon) started by the testing library.
 */
struct GNUNET_TESTING_Daemon;

/**
 * Prototype of a function that will be called whenever
 * a daemon was started by the testing library.
 *
 * @param cls closure
 * @param id identifier for the daemon, NULL on error
 * @param d handle for the daemon
 * @param emsg error message (NULL on success)
 */
typedef void (*GNUNET_TESTING_NotifyHostkeyCreated)(void *cls,
                                                    const struct GNUNET_PeerIdentity *id,
                                                    struct GNUNET_TESTING_Daemon *d,
                                                    const char *emsg);

/**
 * Prototype of a function that will be called whenever
 * a daemon was started by the testing library.
 *
 * @param cls closure
 * @param id identifier for the daemon, NULL on error
 * @param cfg configuration used by this daemon
 * @param d handle for the daemon
 * @param emsg error message (NULL on success)
 */
typedef void (*GNUNET_TESTING_NotifyDaemonRunning)(void *cls,
						   const struct GNUNET_PeerIdentity *id,
						   const struct GNUNET_CONFIGURATION_Handle *cfg,
						   struct GNUNET_TESTING_Daemon *d,
						   const char *emsg);


/**
 * Handle to an entire testbed of GNUnet peers.
 */
struct GNUNET_TESTING_Testbed;

/**
 * Phases of starting GNUnet on a system.
 */
enum GNUNET_TESTING_StartPhase
{
  /**
   * Copy the configuration file to the target system.
   */
  SP_COPYING,

  /**
   * Configuration file has been copied, generate hostkey.
   */
  SP_COPIED,

  /**
   * Create the hostkey for the peer.
   */
  SP_HOSTKEY_CREATE,

  /**
   * Hostkey generated, wait for topology to be finished.
   */
  SP_HOSTKEY_CREATED,

  /**
   * Topology has been created, now start ARM.
   */
  SP_TOPOLOGY_SETUP,

  /**
   * ARM has been started, check that it has properly daemonized and
   * then try to connect to the CORE service (which should be
   * auto-started by ARM).
   */
  SP_START_ARMING,

  /**
   * We're waiting for CORE to start.
   */
  SP_START_CORE,

  /**
   * Core has notified us that we've established a connection to the service.
   * The main FSM halts here and waits to be moved to UPDATE or CLEANUP.
   */
  SP_START_DONE,

  /**
   * We've been asked to terminate the instance and are now waiting for
   * the remote command to stop the gnunet-arm process and delete temporary
   * files.
   */
  SP_SHUTDOWN_START,

  /**
   * We've received a configuration update and are currently waiting for
   * the copy process for the update to complete.  Once it is, we will
   * return to "SP_START_DONE" (and rely on ARM to restart all affected
   * services).
   */
  SP_CONFIG_UPDATE
};

/**
 * Prototype of a function that will be called when a
 * particular operation was completed the testing library.
 *
 * @param cls closure
 * @param emsg NULL on success
 */
typedef void (*GNUNET_TESTING_NotifyCompletion)(void *cls,
                                                const char *emsg);

/**
 * Prototype of a function that will be called with the
 * number of connections created for a particular topology.
 *
 * @param cls closure
 * @param num_connections the number of connections created
 */
typedef void (*GNUNET_TESTING_NotifyConnections)(void *cls,
                                                unsigned int num_connections);

/**
 * Handle for a GNUnet daemon (technically a set of
 * daemons; the handle is really for the master ARM
 * daemon) started by the testing library.
 */
struct GNUNET_TESTING_Daemon
{
  /**
   * Our scheduler.
   */
  struct GNUNET_SCHEDULER_Handle *sched;

  /**
   * Our configuration.
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * At what time to give up starting the peer
   */
  struct GNUNET_TIME_Absolute max_timeout;

  /**
   * Host to run GNUnet on.
   */
  char *hostname;

  /**
   * Result of GNUNET_i2s of this peer,
   * for printing
   */
  char *shortname;

  /**
   * Username we are using.
   */
  char *username;

  /**
   * Name of the configuration file
   */
  char *cfgfile;

  /**
   * Callback to inform initiator that the peer's
   * hostkey has been created.
   */
  GNUNET_TESTING_NotifyHostkeyCreated hostkey_callback;

  /**
   * Closure for hostkey creation callback.
   */
  void *hostkey_cls;

  /**
   * Function to call when the peer is running.
   */
  GNUNET_TESTING_NotifyDaemonRunning cb;

  /**
   * Closure for cb.
   */
  void *cb_cls;

  /**
   * Arguments from "daemon_stop" call.
   */
  GNUNET_TESTING_NotifyCompletion dead_cb;

  /**
   * Closure for 'dead_cb'.
   */
  void *dead_cb_cls;

  /**
   * Arguments from "daemon_stop" call.
   */
  GNUNET_TESTING_NotifyCompletion update_cb;

  /**
   * Closure for 'update_cb'.
   */
  void *update_cb_cls;

  /**
   * Identity of this peer (once started).
   */
  struct GNUNET_PeerIdentity id;

  /**
   * Flag to indicate that we've already been asked
   * to terminate (but could not because some action
   * was still pending).
   */
  int dead;

  /**
   * PID of the process that we started last.
   */
  pid_t pid;

  /**
   * In which phase are we during the start of
   * this process?
   */
  enum GNUNET_TESTING_StartPhase phase;

  /**
   * ID of the current task.
   */
  GNUNET_SCHEDULER_TaskIdentifier task;

  /**
   * Handle to the server.
   */
  struct GNUNET_CORE_Handle *server;

  /**
   * Handle to the transport service of this peer
   */
  struct GNUNET_TRANSPORT_Handle *th;

  /**
   * HELLO message for this peer
   */
  struct GNUNET_HELLO_Message *hello;

  /**
   * Handle to a pipe for reading the hostkey.
   */
  struct GNUNET_DISK_PipeHandle *pipe_stdout;

  /**
   * Output from gnunet-peerinfo is read into this buffer.
   */
  char hostkeybuf[105];

  /**
   * Current position in 'hostkeybuf' (for reading from gnunet-peerinfo)
   */
  unsigned int hostkeybufpos;

  /**
   * Set to GNUNET_YES once the peer is up.
   */
  int running;

  /**
   * Used to tell shutdown not to remove configuration for the peer
   * (if it's going to be restarted later)
   */
  int churn;
};


/**
 * Handle to a group of GNUnet peers.
 */
struct GNUNET_TESTING_PeerGroup;


/**
 * Prototype of a function that will be called whenever
 * two daemons are connected by the testing library.
 *
 * @param cls closure
 * @param first peer id for first daemon
 * @param second peer id for the second daemon
 * @param first_cfg config for the first daemon
 * @param second_cfg config for the second daemon
 * @param first_daemon handle for the first daemon
 * @param second_daemon handle for the second daemon
 * @param emsg error message (NULL on success)
 */
typedef void (*GNUNET_TESTING_NotifyConnection)(void *cls,
                                                   const struct GNUNET_PeerIdentity *first,
                                                   const struct GNUNET_PeerIdentity *second,
                                                   const struct GNUNET_CONFIGURATION_Handle *first_cfg,
                                                   const struct GNUNET_CONFIGURATION_Handle *second_cfg,
                                                   struct GNUNET_TESTING_Daemon *first_daemon,
                                                   struct GNUNET_TESTING_Daemon *second_daemon,
                                                   const char *emsg);

/**
 * Starts a GNUnet daemon.  GNUnet must be installed on the target
 * system and available in the PATH.  The machine must furthermore be
 * reachable via "ssh" (unless the hostname is "NULL") without the
 * need to enter a password.
 *
 * @param sched scheduler to use
 * @param cfg configuration to use
 * @param timeout how long to wait starting up peers
 * @param hostname name of the machine where to run GNUnet
 *        (use NULL for localhost).
 * @param hostkey_callback function to call once the hostkey has been
 *        generated for this peer, but it hasn't yet been started
 *        (NULL to start immediately, otherwise waits on GNUNET_TESTING_daemon_continue_start)
 * @param hostkey_cls closure for hostkey callback
 * @param cb function to call with the result
 * @param cb_cls closure for cb
 * @return handle to the daemon (actual start will be completed asynchronously)
 */
struct GNUNET_TESTING_Daemon *
GNUNET_TESTING_daemon_start (struct GNUNET_SCHEDULER_Handle *sched,
                             const struct GNUNET_CONFIGURATION_Handle *cfg,
                             struct GNUNET_TIME_Relative timeout,
                             const char *hostname,
                             GNUNET_TESTING_NotifyHostkeyCreated hostkey_callback,
                             void *hostkey_cls,
                             GNUNET_TESTING_NotifyDaemonRunning cb,
                             void *cb_cls);

/**
 * Continues GNUnet daemon startup when user wanted to be notified
 * once a hostkey was generated (for creating friends files, blacklists,
 * etc.).
 *
 * @param daemon the daemon to finish starting
 */
void
GNUNET_TESTING_daemon_continue_startup(struct GNUNET_TESTING_Daemon *daemon);

/**
 * Restart (stop and start) a GNUnet daemon.
 *
 * @param d the daemon that should be restarted
 * @param cb function called once the daemon is (re)started
 * @param cb_cls closure for cb
 */
void
GNUNET_TESTING_daemon_restart (struct GNUNET_TESTING_Daemon *d,
                               GNUNET_TESTING_NotifyDaemonRunning cb, void *cb_cls);

/**
 * Start a peer that has previously been stopped using the daemon_stop
 * call (and files weren't deleted and the allow restart flag)
 *
 * @param daemon the daemon to start (has been previously stopped)
 * @param timeout how long to wait for restart
 * @param cb the callback for notification when the peer is running
 * @param cb_cls closure for the callback
 */
void
GNUNET_TESTING_daemon_start_stopped (struct GNUNET_TESTING_Daemon *daemon,
                                     struct GNUNET_TIME_Relative timeout,
                                     GNUNET_TESTING_NotifyDaemonRunning cb,
                                     void *cb_cls);

/**
 * Get a certain testing daemon handle.
 *
 * @param pg handle to the set of running peers
 * @param position the number of the peer to return
 */
struct GNUNET_TESTING_Daemon *
GNUNET_TESTING_daemon_get (struct GNUNET_TESTING_PeerGroup *pg, 
			   unsigned int position);


/**
 * Stops a GNUnet daemon.
 *
 * @param d the daemon that should be stopped
 * @param timeout how long to wait for process for shutdown to complete
 * @param cb function called once the daemon was stopped
 * @param cb_cls closure for cb
 * @param delete_files GNUNET_YES to remove files, GNUNET_NO
 *        to leave them (i.e. for restarting at a later time,
 *        or logfile inspection once finished)
 * @param allow_restart GNUNET_YES to restart peer later (using this API)
 *        GNUNET_NO to kill off and clean up for good
 */
void
GNUNET_TESTING_daemon_stop (struct GNUNET_TESTING_Daemon *d,
                            struct GNUNET_TIME_Relative timeout,
                            GNUNET_TESTING_NotifyCompletion cb, void *cb_cls,
                            int delete_files, int allow_restart);


/**
 * Changes the configuration of a GNUnet daemon.
 *
 * @param d the daemon that should be modified
 * @param cfg the new configuration for the daemon
 * @param cb function called once the configuration was changed
 * @param cb_cls closure for cb
 */
void GNUNET_TESTING_daemon_reconfigure (struct GNUNET_TESTING_Daemon *d,
					struct GNUNET_CONFIGURATION_Handle *cfg,
					GNUNET_TESTING_NotifyCompletion cb,
					void * cb_cls);


/**
 * Establish a connection between two GNUnet daemons.
 *
 * @param d1 handle for the first daemon
 * @param d2 handle for the second daemon
 * @param timeout how long is the connection attempt
 *        allowed to take?
 * @param max_connect_attempts how many times should we try to reconnect
 *        (within timeout)
 * @param cb function to call at the end
 * @param cb_cls closure for cb
 */
void GNUNET_TESTING_daemons_connect (struct GNUNET_TESTING_Daemon *d1,
				     struct GNUNET_TESTING_Daemon *d2,
				     struct GNUNET_TIME_Relative timeout,
				     unsigned int max_connect_attempts,
				     GNUNET_TESTING_NotifyConnection cb,
				     void *cb_cls);




/**
 * Start count gnunetd processes with the same set of transports and
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
 * @param hostnames space-separated list of hostnames to use; can be NULL (to run
 *        everything on localhost).
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
                              const char *hostnames);

/**
 * Function which continues a peer group starting up
 * after successfully generating hostkeys for each peer.
 *
 * @param pg the peer group to continue starting
 */
void
GNUNET_TESTING_daemons_continue_startup(struct GNUNET_TESTING_PeerGroup *pg);

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
                                void *callback_cls);


/**
 * Shutdown all peers started in the given group.
 *
 * @param pg handle to the peer group
 * @param timeout how long to wait for shutdown
 */
void
GNUNET_TESTING_daemons_stop (struct GNUNET_TESTING_PeerGroup *pg, 
			     struct GNUNET_TIME_Relative timeout);


/**
 * Simulate churn by stopping some peers (and possibly
 * re-starting others if churn is called multiple times).  This
 * function can only be used to create leave-join churn (peers "never"
 * leave for good).  First "voff" random peers that are currently
 * online will be taken offline; then "von" random peers that are then
 * offline will be put back online.  No notifications will be
 * generated for any of these operations except for the callback upon
 * completion.  Note that the implementation is at liberty to keep
 * the ARM service itself (but none of the other services or daemons)
 * running even though the "peer" is being varied offline.
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
                              void *cb_cls);


/**
 * Topologies supported for testbeds.
 */
enum GNUNET_TESTING_Topology
{
  /**
   * A clique (everyone connected to everyone else).
   */
  GNUNET_TESTING_TOPOLOGY_CLIQUE,

  /**
   * Small-world network (2d torus plus random links).
   */
  GNUNET_TESTING_TOPOLOGY_SMALL_WORLD,

  /**
   * Small-world network (ring plus random links).
   */
  GNUNET_TESTING_TOPOLOGY_SMALL_WORLD_RING,

  /**
   * Ring topology.
   */
  GNUNET_TESTING_TOPOLOGY_RING,

  /**
   * 2-d torus.
   */
  GNUNET_TESTING_TOPOLOGY_2D_TORUS,

  /**
   * Random graph.
   */
  GNUNET_TESTING_TOPOLOGY_ERDOS_RENYI,

  /**
   * Certain percentage of peers are unable to communicate directly
   * replicating NAT conditions
   */
  GNUNET_TESTING_TOPOLOGY_INTERNAT,

  /**
   * Scale free topology.
   */
  GNUNET_TESTING_TOPOLOGY_SCALE_FREE,

  /**
   * All peers are disconnected.
   */
  GNUNET_TESTING_TOPOLOGY_NONE
};

/**
 * Options for connecting a topology.
 */
enum GNUNET_TESTING_TopologyOption
{
  /**
   * Try to connect all peers specified in the topology.
   */
  GNUNET_TESTING_TOPOLOGY_OPTION_ALL,

  /**
   * Choose a random subset of connections to create.
   */
  GNUNET_TESTING_TOPOLOGY_OPTION_RANDOM,

  /**
   * Create at least X connections for each peer.
   */
  GNUNET_TESTING_TOPOLOGY_OPTION_MINIMUM,

  /**
   * Using a depth first search, create one connection
   * per peer.  If any are missed (graph disconnected)
   * start over at those peers until all have at least one
   * connection.
   */
  GNUNET_TESTING_TOPOLOGY_OPTION_DFS,

  /**
   * No options specified.
   */
  GNUNET_TESTING_TOPOLOGY_OPTION_NONE
};


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
GNUNET_TESTING_topology_get(enum GNUNET_TESTING_Topology *topology, char * topology_string);

/**
 * Get connect topology option from string input.
 *
 * @param topology where to write the retrieved topology
 * @param topology_string The string to attempt to
 *        get a configuration value from
 * @return GNUNET_YES if topology string matched a
 *         known topology, GNUNET_NO if not
 */
int
GNUNET_TESTING_topology_option_get(enum GNUNET_TESTING_TopologyOption *topology, char * topology_string);


/**
 * Takes a peer group and creates a topology based on the
 * one specified.  Creates a topology means generates friend
 * files for the peers so they can only connect to those allowed
 * by the topology.  This will only have an effect once peers
 * are started if the FRIENDS_ONLY option is set in the base
 * config.  Also takes an optional restrict topology which
 * disallows direct TCP connections UNLESS they are specified in
 * the restricted topology.
 *
 * @param pg the peer group struct representing the running peers
 * @param topology which topology to connect the peers in
 * @param restrict_topology allow only direct TCP connections in this topology
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
                                char *restrict_transports);

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
                                 double option_modifier);

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
			     void *cb_cls);


/**
 * Start "count" GNUnet daemons with a particular topology.
 *
 * @param sched scheduler to use
 * @param cfg configuration template to use
 * @param count number of peers the testbed should have
 * @param topology desired topology (enforced via F2F)
 * @param cb function to call on each daemon that was started
 * @param cb_cls closure for cb
 * @param hostname where to run the peers; can be NULL (to run
 *        everything on localhost). Additional
 *        hosts can be specified using a NULL-terminated list of
 *        varargs, hosts will then be used round-robin from that
 *        list.
 * @return handle to control the testbed
 */
struct GNUNET_TESTING_Testbed *
GNUNET_TESTING_testbed_start (struct GNUNET_SCHEDULER_Handle *sched,
			      const struct GNUNET_CONFIGURATION_Handle *cfg,
			      unsigned int count,
			      enum GNUNET_TESTING_Topology topology,
			      GNUNET_TESTING_NotifyDaemonRunning cb,
			      void *cb_cls,
			      const char *hostname,
			      ...);


/**
 * Stop all of the daemons started with the start function.
 *
 * @param tb handle for the testbed
 * @param cb function to call when done
 * @param cb_cls closure for cb
 */
void
GNUNET_TESTING_testbed_stop (struct GNUNET_TESTING_Testbed *tb,
			     GNUNET_TESTING_NotifyCompletion cb,
			     void *cb_cls );


/**
 * Simulate churn in the testbed by stopping some peers (and possibly
 * re-starting others if churn is called multiple times).  This
 * function can only be used to create leave-join churn (peers "never"
 * leave for good).  First "voff" random peers that are currently
 * online will be taken offline; then "von" random peers that are then
 * offline will be put back online.  No notifications will be
 * generated for any of these operations except for the callback upon
 * completion.  Note that the implementation is at liberty to keep
 * the ARM service itself (but none of the other services or daemons)
 * running even though the "peer" is being varied offline.
 *
 * @param tb handle for the testbed
 * @param voff number of peers that should go offline
 * @param von number of peers that should come back online;
 *            must be zero on first call (since "testbed_start"
 *            always starts all of the peers)
 * @param cb function to call at the end
 * @param cb_cls closure for cb
 */
void
GNUNET_TESTING_testbed_churn (struct GNUNET_TESTING_Testbed *tb,
			      unsigned int voff,
			      unsigned int von,
			      GNUNET_TESTING_NotifyCompletion cb,
			      void *cb_cls);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
