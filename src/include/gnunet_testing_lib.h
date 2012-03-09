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
#include "gnunet_statistics_service.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#define HOSTKEYFILESIZE 914

/**
 * Handle for a GNUnet daemon (technically a set of
 * daemons; the handle is really for the master ARM
 * daemon) started by the testing library.
 */
struct GNUNET_TESTING_Daemon;

/**
 * Linked list of hostnames and ports to use for starting daemons.
 */
struct GNUNET_TESTING_Host
{
  /**
   * Pointer to next item in the list.
   */
  struct GNUNET_TESTING_Host *next;

  /**
   * Hostname to connect to.
   */
  char *hostname;

  /**
   * Username to use when connecting (may be null).
   */
  char *username;

  /**
   * Port to use for SSH connection (used for ssh
   * connection forwarding, 0 to let ssh decide)
   */
  uint16_t port;
};

/**
 * Prototype of a function that will be called whenever
 * a daemon was started by the testing library.
 *
 * @param cls closure
 * @param id identifier for the daemon, NULL on error
 * @param d handle for the daemon
 * @param emsg error message (NULL on success)
 */
typedef void (*GNUNET_TESTING_NotifyHostkeyCreated) (void *cls,
                                                     const struct
                                                     GNUNET_PeerIdentity * id,
                                                     struct
                                                     GNUNET_TESTING_Daemon * d,
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
typedef void (*GNUNET_TESTING_NotifyDaemonRunning) (void *cls,
                                                    const struct
                                                    GNUNET_PeerIdentity * id,
                                                    const struct
                                                    GNUNET_CONFIGURATION_Handle
                                                    * cfg,
                                                    struct GNUNET_TESTING_Daemon
                                                    * d, const char *emsg);

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
   * CORE is up, now make sure we get the HELLO for this peer.
   */
  SP_GET_HELLO,

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
   * We should shutdown a *single* service via gnunet-arm.  Call the dead_cb
   * upon notification from gnunet-arm that the service has been stopped.
   */
  SP_SERVICE_SHUTDOWN_START,

  /**
   * We should start a *single* service via gnunet-arm.  Call the daemon cb
   * upon notification from gnunet-arm that the service has been started.
   */
  SP_SERVICE_START,

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
typedef void (*GNUNET_TESTING_NotifyCompletion) (void *cls, const char *emsg);

/**
 * Prototype of a function that will be called with the
 * number of connections created for a particular topology.
 *
 * @param cls closure
 * @param num_connections the number of connections created
 */
typedef void (*GNUNET_TESTING_NotifyConnections) (void *cls,
                                                  unsigned int num_connections);

/**
 * Handle for a GNUnet daemon (technically a set of
 * daemons; the handle is really for the master ARM
 * daemon) started by the testing library.
 */
struct GNUNET_TESTING_Daemon
{
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
   * Port to use for ssh, NULL to let system choose default.
   */
  char *ssh_port_str;

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
   * PID of the process we used to run gnunet-arm or SSH to start the peer.
   */
  struct GNUNET_OS_Process *proc_arm_start;

  /**
   * PID of the process we used to run gnunet-arm or SSH to stop the peer.
   */
  struct GNUNET_OS_Process *proc_arm_stop;

  /**
   * PID of the process we used to run gnunet-arm or SSH to manage services at the peer.
   */
  struct GNUNET_OS_Process *proc_arm_srv_start;

  /**
   * PID of the process we used to run gnunet-arm or SSH to manage services at the peer.
   */
  struct GNUNET_OS_Process *proc_arm_srv_stop;

  /**
   * PID of the process we used to run copy files
   */
  struct GNUNET_OS_Process *proc_arm_copying;

  /**
   * PID of the process we used to run gnunet-peerinfo.
   */
  struct GNUNET_OS_Process *proc_arm_peerinfo;

  /**
   * Handle to the server.
   */
  struct GNUNET_CORE_Handle *server;

  /**
   * Handle to the transport service of this peer
   */
  struct GNUNET_TRANSPORT_Handle *th;

  /**
   * Handle for getting HELLOs from transport
   */
  struct GNUNET_TRANSPORT_GetHelloHandle *ghh;

  /**
   * HELLO message for this peer
   */
  struct GNUNET_HELLO_Message *hello;

  /**
   * Handle to a pipe for reading the hostkey.
   */
  struct GNUNET_DISK_PipeHandle *pipe_stdout;

  /**
   * Currently, a single char * pointing to a service
   * that has been churned off.
   *
   * FIXME: make this a linked list of services that have been churned off!!!
   */
  char *churned_services;

  /**
   * ID of the current task.
   */
  GNUNET_SCHEDULER_TaskIdentifier task;

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
   * GNUNET_YES if the hostkey has been created
   * for this peer, GNUNET_NO otherwise.
   */
  int have_hostkey;

  /**
   * In which phase are we during the start of
   * this process?
   */
  enum GNUNET_TESTING_StartPhase phase;

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

  /**
   * Output from gnunet-peerinfo is read into this buffer.
   */
  char hostkeybuf[105];

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
 * @param distance distance between the connected peers
 * @param first_cfg config for the first daemon
 * @param second_cfg config for the second daemon
 * @param first_daemon handle for the first daemon
 * @param second_daemon handle for the second daemon
 * @param emsg error message (NULL on success)
 */
typedef void (*GNUNET_TESTING_NotifyConnection) (void *cls,
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
                                                 const char *emsg);


/**
 * Prototype of a callback function indicating that two peers
 * are currently connected.
 *
 * @param cls closure
 * @param first peer id for first daemon
 * @param second peer id for the second daemon
 * @param distance distance between the connected peers
 * @param emsg error message (NULL on success)
 */
typedef void (*GNUNET_TESTING_NotifyTopology) (void *cls,
                                               const struct GNUNET_PeerIdentity
                                               * first,
                                               const struct GNUNET_PeerIdentity
                                               * second, const char *emsg);


/**
 * Starts a GNUnet daemon.  GNUnet must be installed on the target
 * system and available in the PATH.  The machine must furthermore be
 * reachable via "ssh" (unless the hostname is "NULL") without the
 * need to enter a password.
 *
 * @param cfg configuration to use
 * @param timeout how long to wait starting up peers
 * @param pretend GNUNET_YES to set up files but not start peer GNUNET_NO
 *                to really start the peer (default)
 * @param hostname name of the machine where to run GNUnet
 *        (use NULL for localhost).
 * @param ssh_username ssh username to use when connecting to hostname
 * @param sshport port to pass to ssh process when connecting to hostname
 * @param hostkey pointer to a hostkey to be written to disk (instead of being generated)
 * @param hostkey_callback function to call once the hostkey has been
 *        generated for this peer, but it hasn't yet been started
 *        (NULL to start immediately, otherwise waits on GNUNET_TESTING_daemon_continue_start)
 * @param hostkey_cls closure for hostkey callback
 * @param cb function to call once peer is up, or failed to start
 * @param cb_cls closure for cb
 * @return handle to the daemon (actual start will be completed asynchronously)
 */
struct GNUNET_TESTING_Daemon *
GNUNET_TESTING_daemon_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
                             struct GNUNET_TIME_Relative timeout, int pretend,
                             const char *hostname, const char *ssh_username,
                             uint16_t sshport, const char *hostkey,
                             GNUNET_TESTING_NotifyHostkeyCreated
                             hostkey_callback, void *hostkey_cls,
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
GNUNET_TESTING_daemon_continue_startup (struct GNUNET_TESTING_Daemon *daemon);


/**
 * Check whether the given daemon is running.
 *
 * @param daemon the daemon to check
 * @return GNUNET_YES if the daemon is up, GNUNET_NO if the
 *         daemon is down, GNUNET_SYSERR on error.
 */
int
GNUNET_TESTING_test_daemon_running (struct GNUNET_TESTING_Daemon *daemon);


/**
 * Obtain the peer identity of the peer with the given configuration
 * handle.  This function reads the private key of the peer, obtains
 * the public key and hashes it.
 *
 * @param cfg configuration of the peer
 * @param pid where to store the peer identity
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
GNUNET_TESTING_get_peer_identity (const struct GNUNET_CONFIGURATION_Handle *cfg,
				  struct GNUNET_PeerIdentity *pid);


/**
 * Restart (stop and start) a GNUnet daemon.
 *
 * @param d the daemon that should be restarted
 * @param cb function called once the daemon is (re)started
 * @param cb_cls closure for cb
 */
void
GNUNET_TESTING_daemon_restart (struct GNUNET_TESTING_Daemon *d,
                               GNUNET_TESTING_NotifyDaemonRunning cb,
                               void *cb_cls);


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
 * Starts a GNUnet daemon's service.
 *
 * @param d the daemon for which the service should be started
 * @param service the name of the service to start
 * @param timeout how long to wait for process for startup
 * @param cb function called once gnunet-arm returns
 * @param cb_cls closure for cb
 */
void
GNUNET_TESTING_daemon_start_service (struct GNUNET_TESTING_Daemon *d,
                                     const char *service,
                                     struct GNUNET_TIME_Relative timeout,
                                     GNUNET_TESTING_NotifyDaemonRunning cb,
                                     void *cb_cls);


/**
 * Starts a GNUnet daemon's service which has been previously turned off.
 *
 * @param d the daemon for which the service should be started
 * @param service the name of the service to start
 * @param timeout how long to wait for process for startup
 * @param cb function called once gnunet-arm returns
 * @param cb_cls closure for cb
 */
void
GNUNET_TESTING_daemon_start_stopped_service (struct GNUNET_TESTING_Daemon *d,
                                             char *service,
                                             struct GNUNET_TIME_Relative
                                             timeout,
                                             GNUNET_TESTING_NotifyDaemonRunning
                                             cb, void *cb_cls);


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
                                 const struct GNUNET_PeerIdentity *peer_id);


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
             uint32_t * fdnum);

/**
 * Changes the configuration of a GNUnet daemon.
 *
 * @param d the daemon that should be modified
 * @param cfg the new configuration for the daemon
 * @param cb function called once the configuration was changed
 * @param cb_cls closure for cb
 */
void
GNUNET_TESTING_daemon_reconfigure (struct GNUNET_TESTING_Daemon *d,
                                   struct GNUNET_CONFIGURATION_Handle *cfg,
                                   GNUNET_TESTING_NotifyCompletion cb,
                                   void *cb_cls);


/**
 * Stops a single service of a GNUnet daemon.  Used like daemon_stop,
 * only doesn't stop the entire peer in any case.  If the service
 * is not currently running, this call is likely to fail after
 * timeout!
 *
 * @param d the daemon that should be stopped
 * @param service the name of the service to stop
 * @param timeout how long to wait for process for shutdown to complete
 * @param cb function called once the service was stopped
 * @param cb_cls closure for cb
 */
void
GNUNET_TESTING_daemon_stop_service (struct GNUNET_TESTING_Daemon *d,
                                    const char *service,
                                    struct GNUNET_TIME_Relative timeout,
                                    GNUNET_TESTING_NotifyCompletion cb,
                                    void *cb_cls);


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
GNUNET_TESTING_hosts_load (const struct GNUNET_CONFIGURATION_Handle *cfg);


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
                              const struct GNUNET_TESTING_Host *hostnames);


/**
 * Function which continues a peer group starting up
 * after successfully generating hostkeys for each peer.
 *
 * @param pg the peer group to continue starting
 */
void
GNUNET_TESTING_daemons_continue_startup (struct GNUNET_TESTING_PeerGroup *pg);


/**
 * Handle for an active request to connect two peers.
 */
struct GNUNET_TESTING_ConnectContext;


/**
 * Establish a connection between two GNUnet daemons.  The daemons
 * must both be running and not be stopped until either the
 * 'cb' callback is called OR the connection request has been
 * explicitly cancelled.
 *
 * @param d1 handle for the first daemon
 * @param d2 handle for the second daemon
 * @param timeout how long is the connection attempt
 *        allowed to take?
 * @param max_connect_attempts how many times should we try to reconnect
 *        (within timeout)
 * @param send_hello GNUNET_YES to send the HELLO, GNUNET_NO to assume
 *                   the HELLO has already been exchanged
 * @param cb function to call at the end
 * @param cb_cls closure for cb
 * @return handle to cancel the request, NULL on error
 */
struct GNUNET_TESTING_ConnectContext *
GNUNET_TESTING_daemons_connect (struct GNUNET_TESTING_Daemon *d1,
                                struct GNUNET_TESTING_Daemon *d2,
                                struct GNUNET_TIME_Relative timeout,
                                unsigned int max_connect_attempts,
                                int send_hello,
                                GNUNET_TESTING_NotifyConnection cb,
                                void *cb_cls);



/**
 * Cancel an attempt to connect two daemons.
 *
 * @param cc connect context
 */
void
GNUNET_TESTING_daemons_connect_cancel (struct GNUNET_TESTING_ConnectContext
                                       *cc);



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
 * @param cb callback to notify upon success or failure
 * @param cb_cls closure for cb
 */
void
GNUNET_TESTING_daemons_stop (struct GNUNET_TESTING_PeerGroup *pg,
                             struct GNUNET_TIME_Relative timeout,
                             GNUNET_TESTING_NotifyCompletion cb, void *cb_cls);


/**
 * Count the number of running peers.
 *
 * @param pg handle for the peer group
 *
 * @return the number of currently running peers in the peer group
 */
unsigned int
GNUNET_TESTING_daemons_running (struct GNUNET_TESTING_PeerGroup *pg);


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
 * @param service the service to churn on/off, NULL for all
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
                              GNUNET_TESTING_NotifyCompletion cb, void *cb_cls);


/**
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
                                      void *cb_cls);


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
typedef int (*GNUNET_TESTING_STATISTICS_Iterator) (void *cls,
                                                   const struct
                                                   GNUNET_PeerIdentity * peer,
                                                   const char *subsystem,
                                                   const char *name,
                                                   uint64_t value,
                                                   int is_persistent);


/**
 * Iterate over all (running) peers in the peer group, retrieve
 * all statistics from each.
 *
 * @param pg the peergroup to iterate statistics of
 * @param cont continuation to call once call is completed(?)
 * @param proc processing function for each statistic retrieved
 * @param cls closure to pass to proc
 */
void
GNUNET_TESTING_get_statistics (struct GNUNET_TESTING_PeerGroup *pg,
                               GNUNET_STATISTICS_Callback cont,
                               GNUNET_TESTING_STATISTICS_Iterator proc,
                               void *cls);


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
   * Straight line topology.
   */
  GNUNET_TESTING_TOPOLOGY_LINE,

  /**
   * All peers are disconnected.
   */
  GNUNET_TESTING_TOPOLOGY_NONE,

  /**
   * Read a topology from a given file.
   */
  GNUNET_TESTING_TOPOLOGY_FROM_FILE
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
   * Find the N closest peers to each allowed peer in the
   * topology and make sure a connection to those peers
   * exists in the connect topology.
   */
  GNUNET_TESTING_TOPOLOGY_OPTION_ADD_CLOSEST,

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
GNUNET_TESTING_topology_get (enum GNUNET_TESTING_Topology *topology,
                             const char *topology_string);


/**
 * Get connect topology option from string input.
 *
 * @param topology_option where to write the retrieved topology
 * @param topology_string The string to attempt to
 *        get a configuration value from
 * @return GNUNET_YES if topology string matched a
 *         known topology, GNUNET_NO if not
 */
int
GNUNET_TESTING_topology_option_get (enum GNUNET_TESTING_TopologyOption
                                    *topology_option,
                                    const char *topology_string);


/**
 * Takes a peer group and creates a topology based on the
 * one specified.  Creates a topology means generates friend
 * files for the peers so they can only connect to those allowed
 * by the topology.  This will only have an effect once peers
 * are started if the FRIENDS_ONLY option is set in the base
 * config.
 *
 * Also takes an optional restrict topology which
 * disallows direct connections UNLESS they are specified in
 * the restricted topology.
 *
 * A simple example; if the topology option is set to LINE
 * peers can ONLY connect in a LINE.  However, if the topology
 * option is set to 2D-torus and the restrict option is set to
 * line with restrict_transports equal to "tcp udp", then peers
 * may connect in a 2D-torus, but will be restricted to tcp and
 * udp connections only in a LINE.  Generally it only makes
 * sense to do this if restrict_topology is a subset of topology.
 *
 * For testing peer discovery, etc. it is generally better to
 * leave restrict_topology as GNUNET_TESTING_TOPOLOGY_NONE and
 * then use the connect_topology function to restrict the initial
 * connection set.
 *
 * @param pg the peer group struct representing the running peers
 * @param topology which topology to connect the peers in
 * @param restrict_topology allow only direct connections in this topology,
 *        based on those listed in restrict_transports, set to
 *        GNUNET_TESTING_TOPOLOGY_NONE for no restrictions
 * @param restrict_transports space delimited list of transports to blacklist
 *                            to create restricted topology, NULL for none
 *
 * @return the maximum number of connections were all allowed peers
 *         connected to each other
 */
unsigned int
GNUNET_TESTING_create_topology (struct GNUNET_TESTING_PeerGroup *pg,
                                enum GNUNET_TESTING_Topology topology,
                                enum GNUNET_TESTING_Topology restrict_topology,
                                const char *restrict_transports);


/**
 * Iterate over all (running) peers in the peer group, retrieve
 * all connections that each currently has.
 *
 * @param pg the peer group we are concerned with
 * @param cb callback for topology information
 * @param cls closure for callback
 */
void
GNUNET_TESTING_get_topology (struct GNUNET_TESTING_PeerGroup *pg,
                             GNUNET_TESTING_NotifyTopology cb, void *cls);


/**
 * Stop the connection process temporarily.
 *
 * @param pg the peer group to stop connecting
 */
void
GNUNET_TESTING_stop_connections (struct GNUNET_TESTING_PeerGroup *pg);


/**
 * Resume the connection process.
 *
 * @param pg the peer group to resume connecting
 */
void
GNUNET_TESTING_resume_connections (struct GNUNET_TESTING_PeerGroup *pg);


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
                                 notify_callback, void *notify_cls);


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
                             GNUNET_TESTING_NotifyCompletion cb, void *cb_cls);


/**
 * Start a peer group with a given number of peers.  Notify
 * on completion of peer startup and connection based on given
 * topological constraints.  Optionally notify on each
 * established connection.
 *
 * @param cfg configuration template to use
 * @param total number of daemons to start
 * @param timeout total time allowed for peers to start
 * @param connect_cb function to call each time two daemons are connected
 * @param peergroup_cb function to call once all peers are up and connected
 * @param peergroup_cls closure for peergroup callbacks
 * @param hostnames linked list of host structs to use to start peers on
 *                  (NULL to run on localhost only)
 *
 * @return NULL on error, otherwise handle to control peer group
 */
struct GNUNET_TESTING_PeerGroup *
GNUNET_TESTING_peergroup_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                unsigned int total,
                                struct GNUNET_TIME_Relative timeout,
                                GNUNET_TESTING_NotifyConnection connect_cb,
                                GNUNET_TESTING_NotifyCompletion peergroup_cb,
                                void *peergroup_cls,
                                const struct GNUNET_TESTING_Host *hostnames);


/**
 * Print current topology to a graphviz readable file.
 *
 * @param pg a currently running peergroup to print to file
 * @param output_filename the file to write the topology to
 * @param notify_cb callback to call upon completion or failure
 * @param notify_cb_cls closure for notify_cb
 *
 */
void
GNUNET_TESTING_peergroup_topology_to_file (struct GNUNET_TESTING_PeerGroup *pg,
                                           const char *output_filename,
                                           GNUNET_TESTING_NotifyCompletion
                                           notify_cb, void *notify_cb_cls);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
