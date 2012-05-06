/*
      This file is part of GNUnet
      (C) 2008, 2009, 2012 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_testbed_service.h
 * @brief API for writing tests and creating large-scale
 *        emulation testbeds for GNUnet.
 * @author Christian Grothoff
 */

#ifndef GNUNET_TESTBED_SERVICE_H
#define GNUNET_TESTBED_SERVICE_H

#include "gnunet_util_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Opaque handle to a host running experiments managed by the testbed framework.
 * The master process must be able to SSH to this host without password (via
 * ssh-agent).
 */
struct GNUNET_TESTBED_Host;

/**
 * Opaque handle to a peer controlled by the testbed framework.  A peer runs
 * at a particular host.
 */ 
struct GNUNET_TESTBED_Peer;

/**
 * Opaque handle to an abstract operation to be executed by the testbed framework.
 */
struct GNUNET_TESTBED_Operation;

/**
 * Handle to interact with a GNUnet testbed controller.  Each controller has at
 * least one master handle which is created when the controller is created; this
 * master handle interacts with the controller via stdin/stdout of the controller
 * process.  Additionally, controllers can interact with each other (in a P2P
 * fashion); those links are established via TCP/IP on the controller's service
 * port.
 */
struct GNUNET_TESTBED_Controller;

/**
 * Handle to a large-scale testbed that is managed at a high level.
 */
struct GNUNET_TESTBED_Testbed;


/**
 * Create a host to run peers and controllers on.
 * 
 * @param hostname name of the host, use "NULL" for localhost
 * @param username username to use for the login; may be NULL
 * @param port port number to use for ssh; use 0 to let ssh decide
 * @return handle to the host, NULL on error
 */
struct GNUNET_TESTBED_Host *
GNUNET_TESTBED_host_create (const char *hostname,
			    const char *username,
			    uint16_t port);


/**
 * Load a set of hosts from a configuration file.
 *
 * @param filename file with the host specification
 * @param hosts set to the hosts found in the file
 * @return number of hosts returned in 'hosts', 0 on error
 */
unsigned int
GNUNET_TESTBED_hosts_load_from_file (const char *filename,
				     struct GNUNET_TESTBED_Host **hosts);


/**
 * Destroy a host handle.  Must only be called once everything
 * running on that host has been stopped.
 *
 * @param host handle to destroy
 */
void
GNUNET_TESTBED_host_destroy (struct GNUNET_TESTBED_Host *host);


/**
 * Enumeration with (at most 64) possible event types that
 * can be monitored using the testbed framework.
 */
enum GNUNET_TESTBED_EventType
{
  /**
   * A peer has been started.
   */
  GNUNET_TESTBED_ET_PEER_START = 0,

  /**
   * A peer has been stopped.
   */
  GNUNET_TESTBED_ET_PEER_STOP = 1,

  /**
   * A connection between two peers was established.
   */
  GNUNET_TESTBED_ET_CONNECT = 2,

  /**
   * A connection between two peers was torn down.
   */
  GNUNET_TESTBED_ET_DISCONNECT = 3,

  /**
   * A requested testbed operation has been completed.
   */
  GNUNET_TESTBED_ET_OPERATION_FINISHED = 4,

  /**
   * The 'GNUNET_TESTBED_run' operation has been completed
   */
  GNUNET_TESTBED_ET_TESTBED_ONLINE = 5

};


/**
 * Types of information that can be requested about a peer.
 */
enum GNUNET_TESTBED_PeerInformationType
{

  /**
   * Special value (not valid for requesting information)
   * that is used in the event struct if a 'generic' pointer
   * is returned (for other operations not related to this
   * enumeration).
   */
  GNUNET_TESTBED_PIT_GENERIC = 0,

  /**
   * What host is the peer running on?  Returns a 'const struct
   * GNUNET_TESTBED_Host *'.  Valid until
   * 'GNUNET_TESTBED_operation_done' is called.
   */
  GNUNET_TESTBED_PIT_HOST,

  /**
   * What configuration is the peer using?  Returns a 'const struct
   * GNUNET_CONFIGURATION_Handle *'.  Valid until
   * 'GNUNET_TESTNIG_operation_done' is called.  However, the
   * values may be inaccurate if the peer is reconfigured in
   * the meantime.
   */
  GNUNET_TESTBED_PIT_CONFIGURATION,

  /**
   * What is the identity of the peer?  Returns a
   * 'const struct GNUNET_PeerIdentity *'.  Valid until
   * 'GNUNET_TESTNIG_operation_done' is called.
   */
  GNUNET_TESTBED_PIT_IDENTITY

};


/**
 * Argument to GNUNET_TESTBED_ControllerCallback with details about
 * the event.
 */
struct GNUNET_TESTBED_EventInformation
{
  
  /**
   * Type of the event.
   */
  enum GNUNET_TESTBED_EventType type;

  /**
   * Details about the event.
   */
  union
  {
    
    /**
     * Details about peer start event.
     */ 
    struct
    {
      /**
       * Handle for the host where the peer
       * was started.
       */
      struct GNUNET_TESTBED_Host *host;

      /**
       * Handle for the peer that was started.
       */
      struct GNUNET_TESTBED_Peer *peer;
      
    } peer_start;

    /**
     * Details about peer stop event.
     */ 
    struct
    {

      /**
       * Handle for the peer that was started.
       */
      struct GNUNET_TESTBED_Peer *peer;
      
    } peer_stop;

    /**
     * Details about connect event.
     */ 
    struct
    {
      /**
       * Handle for one of the connected peers.
       */
      struct GNUNET_TESTBED_Peer *peer1;

      /**
       * Handle for one of the connected peers.
       */
      struct GNUNET_TESTBED_Peer *peer2;

    } peer_connect;

    /**
     * Details about disconnect event.
     */ 
    struct
    {
      /**
       * Handle for one of the disconnected peers.
       */
      struct GNUNET_TESTBED_Peer *peer1;

      /**
       * Handle for one of the disconnected peers.
       */
      struct GNUNET_TESTBED_Peer *peer2;
      
    } peer_disconnect;

    /**
     * Details about an operation finished event.
     */ 
    struct 
    {

      /**
       * Handle for the operation that was finished.
       */
      struct GNUNET_TESTBED_Operation *operation;

      /**
       * Closure that was passed in when the event was
       * requested.
       */
      void *op_cls;

      /**
       * Error message for the operation, NULL on success.
       */ 
      const char *emsg;

      /**
       * Peer information type; captures which of the types
       * in the 'op_result' is actually in use.
       */
      enum GNUNET_TESTBED_PeerInformationType pit;

      /**
       * Pointer to an operation-specific return value; NULL on error;
       * can be NULL for certain operations.  Valid until
       * 'GNUNET_TESTBED_operation_done' is called.
       */
      union
      {
	/**
	 * No result (NULL pointer) or generic result
	 * (whatever the GNUNET_TESTBED_ConnectAdapter returned).
	 */
	void *generic;

	/**
	 * Identity of host running the peer.
	 */
	struct GNUNET_TESTBED_Host *host;

	/**
	 * Identity of the peer.
	 */
	const struct GNUNET_PeerIdentity *pid;

	/**
	 * Configuration of the peer.
	 */
	const struct GNUNET_CONFIGURATION_Handle *cfg;

      } op_result;

    } operation_finished;   


    /**
     * Details about an testbed run completed event.
     */ 
    struct 
    {

      /**
       * Error message for the operation, NULL on success.
       */ 
      const char *emsg;

      /**
       * Array of peers now running (valid until
       * 'GNUNET_TESTBED_testbed_stop' is called).  Note that it is
       * not allowed to call 'GNUNET_TESTBED_peer_destroy' on peers
       * from this array.
       */
      struct GNUNET_TESTBED_Peer **peers;

      /**
       * Size of the 'peers' array.
       */
      unsigned int num_peers;
      
    } testbed_run_finished;   

  } details;

};


/**
 * Signature of the event handler function called by the
 * respective event controller.
 *
 * @param cls closure
 * @param event information about the event
 */
typedef void (*GNUNET_TESTBED_ControllerCallback)(void *cls,
						  const struct GNUNET_TESTBED_EventInformation *event);						  


/**
 * Start a controller process using the given configuration at the
 * given host.
 *
 * @param cfg configuration to use
 * @param host host to run the controller on, NULL for 'localhost'
 * @param event_mask bit mask with set of events to call 'cc' for;
 *                   or-ed values of "1LL" shifted by the
 *                   respective 'enum GNUNET_TESTBED_EventType'
 *                   (i.e.  "(1LL << GNUNET_TESTBED_ET_CONNECT) | ...")
 * @param cc controller callback to invoke on events
 * @param cc_cls closure for cc
 * @return handle to the controller
 */
struct GNUNET_TESTBED_Controller *
GNUNET_TESTBED_controller_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
				 struct GNUNET_TESTBED_Host *host,
				 uint64_t event_mask,
				 GNUNET_TESTBED_ControllerCallback cc,
				 void *cc_cls);


/**
 * Configure shared services at a controller.  Using this function,
 * you can specify that certain services (such as "resolver")
 * should not be run for each peer but instead be shared
 * across N peers on the specified host.  This function
 * must be called before any peers are created at the host.
 * 
 * @param controller controller to configure
 * @param service_name name of the service to share
 * @param num_peers number of peers that should share one instance
 *        of the specified service (1 for no sharing is the default),
 *        use 0 to disable the service
 */
void
GNUNET_TESTBED_controller_configure_sharing (struct GNUNET_TESTBED_Controller *controller,
					     const char *service_name,
					     uint32_t num_peers);


/**
 * Stop the given controller (also will terminate all peers and
 * controllers dependent on this controller).  This function 
 * blocks until the testbed has been fully terminated (!).
 *
 * @param controller handle to controller to stop
 */
void
GNUNET_TESTBED_controller_stop (struct GNUNET_TESTBED_Controller *controller);


/**
 * Create a link from a 'master' controller to a slave controller.
 * Whenever the master controller is asked to start a peer at the
 * given 'delegated_host', it will delegate the request to the
 * specified slave controller.  Note that the slave controller runs at
 * the 'slave_host', which may or may not be the same host as the
 * 'delegated_host' (for hierarchical delegations).  The configuration
 * of the slave controller is given and to be used to either create
 * the slave controller or to connect to an existing slave controller
 * process.  'is_subordinate' specifies if the given slave controller
 * should be started and managed by the master controller, or if the
 * slave already has a master and this is just a secondary master that
 * is also allowed to use the existing slave.
 *
 * @param master handle to the master controller who creates the association
 * @param delegated_host requests to which host should be delegated
 * @param slave_host which host is used to run the slave controller 
 * @param slave_cfg configuration to use for the slave controller
 * @param is_subordinate GNUNET_YES if the slave should be started (and stopped)
 *                       by the master controller; GNUNET_NO if we are just
 *                       allowed to use the slave via TCP/IP
 */
void
GNUNET_TESTBED_controller_link (struct GNUNET_TESTBED_Controller *master,
				struct GNUNET_TESTBED_Host *delegated_host,
				struct GNUNET_TESTBED_Host *slave_host,
				const struct GNUNET_CONFIGURATION_Handle *slave_cfg,
				int is_subordinate);


/**
 * Create the given peer at the specified host using the given
 * controller.  If the given controller is not running on the target
 * host, it should find or create a controller at the target host and
 * delegate creating the peer.  Explicit delegation paths can be setup
 * using 'GNUNET_TESTBED_controller_link'.  If no explicit delegation
 * path exists, a direct link with a subordinate controller is setup
 * for the first delegated peer to a particular host; the subordinate
 * controller is then destroyed once the last peer that was delegated
 * to the remote host is stopped.
 *
 * Creating the peer only creates the handle to manipulate and further
 * configure the peer; use "GNUNET_TESTBED_peer_start" and
 * "GNUNET_TESTBED_peer_stop" to actually start/stop the peer's
 * processes.
 *
 * Note that the given configuration will be adjusted by the
 * controller to avoid port/path conflicts with other peers.
 * The "final" configuration can be obtained using
 * 'GNUNET_TESTBED_peer_get_information'.
 *
 * @param controller controller process to use
 * @param host host to run the peer on
 * @param cfg configuration to use for the peer
 * @return handle to the peer (actual startup will happen asynchronously)
 */
struct GNUNET_TESTBED_Peer *
GNUNET_TESTBED_peer_create (struct GNUNET_TESTBED_Controller *controller,
			    struct GNUNET_TESTBED_Host *host,
			    const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Start the given peer.
 *
 * @param peer peer to start
 * @return handle to the operation
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_peer_start (struct GNUNET_TESTBED_Peer *peer);


/**
 * Stop the given peer.  The handle remains valid (use
 * "GNUNET_TESTBED_peer_destroy" to fully clean up the 
 * state of the peer).
 *
 * @param peer peer to stop
 * @return handle to the operation
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_peer_stop (struct GNUNET_TESTBED_Peer *peer);


/**
 * Request information about a peer.
 *
 * @param peer peer to request information about
 * @param pit desired information
 * @return handle to the operation
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_peer_get_information (struct GNUNET_TESTBED_Peer *peer,
				     enum GNUNET_TESTBED_PeerInformationType pit);


/**
 * Change peer configuration.  Must only be called while the
 * peer is stopped.  Ports and paths cannot be changed this
 * way.
 *
 * @param peer peer to change configuration for
 * @param cfg new configuration (differences to existing
 *            configuration only)
 * @return handle to the operation
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_peer_update_configuration (struct GNUNET_TESTBED_Peer *peer,
					  const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Destroy the given peer; the peer should have been
 * stopped first (if it was started).
 *
 * @param peer peer to stop
 * @return handle to the operation
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_peer_destroy (struct GNUNET_TESTBED_Peer *peer);


/**
 * Options for peer connections.
 */
enum GNUNET_TESTBED_ConnectOption
{
  /**
   * No option (not valid as an argument).
   */
  GNUNET_TESTBED_CO_NONE = 0,
  
  /**
   * Allow or disallow a connection between the specified peers.  
   * Followed by GNUNET_NO (int) if a connection is disallowed
   * or GNUNET_YES if a connection is allowed.  Note that the
   * default (all connections allowed or disallowed) is
   * specified in the configuration of the controller.
   */
  GNUNET_TESTBED_CO_ALLOW = 1,
  
  /**
   * FIXME: add (and implement) options to limit connection to
   * particular transports, force simulation of particular latencies
   * or message loss rates, or set bandwidth limitations.
   */
  
};


/**
 * Manipulate the P2P underlay topology by configuring a link
 * between two peers.  
 *
 * @param op_cls closure argument to give with the operation event
 * @param p1 first peer
 * @param p2 second peer
 * @param co option to change
 * @param ap option-specific values
 * @return handle to the operation, NULL if configuring the link at this
 *         time is not allowed
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_underlay_configure_link_va (void *op_cls,
					   struct GNUNET_TESTBED_Peer *p1,
					   struct GNUNET_TESTBED_Peer *p2,
					   enum GNUNET_TESTBED_ConnectOption co,
					   va_list ap);


/**
 * Manipulate the P2P underlay topology by configuring a link
 * between two peers.  
 *
 * @param op_cls closure argument to give with the operation event
 * @param p1 first peer
 * @param p2 second peer
 * @param co option to change
 * @param ... option-specific values
 * @return handle to the operation, NULL if configuring the link at this
 *         time is not allowed
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_underlay_configure_link (void *op_cls,
					struct GNUNET_TESTBED_Peer *p1,
					struct GNUNET_TESTBED_Peer *p2,
					enum GNUNET_TESTBED_ConnectOption co, ...);



/**
 * Topologies supported for testbeds.
 */
enum GNUNET_TESTBED_TopologyOption
{
  /**
   * A clique (everyone connected to everyone else).  No options.
   */
  GNUNET_TESTBED_TOPOLOGY_CLIQUE,

  /**
   * Small-world network (2d torus plus random links).  Followed
   * by the number of random links to add (unsigned int).
   */
  GNUNET_TESTBED_TOPOLOGY_SMALL_WORLD,

  /**
   * Small-world network (ring plus random links).  Followed
   * by the number of random links to add (unsigned int).
   */
  GNUNET_TESTBED_TOPOLOGY_SMALL_WORLD_RING,

  /**
   * Ring topology.  No options.
   */
  GNUNET_TESTBED_TOPOLOGY_RING,

  /**
   * 2-d torus.  No options.
   */
  GNUNET_TESTBED_TOPOLOGY_2D_TORUS,

  /**
   * Random graph.  Followed by the link density, that is the
   * percentage of links present in relation to a clique
   * (float).
   */
  GNUNET_TESTBED_TOPOLOGY_ERDOS_RENYI,

  /**
   * Certain percentage of peers are unable to communicate directly
   * replicating NAT conditions.  Followed by the fraction of
   * NAT'ed peers (float).
   */
  GNUNET_TESTBED_TOPOLOGY_INTERNAT,

  /**
   * Scale free topology.   FIXME: options?
   */
  GNUNET_TESTBED_TOPOLOGY_SCALE_FREE,

  /**
   * Straight line topology.  No options.
   */
  GNUNET_TESTBED_TOPOLOGY_LINE,

  /**
   * All peers are disconnected.  No options.
   */
  GNUNET_TESTBED_TOPOLOGY_NONE,

  /**
   * Read a topology from a given file.  Followed by the name of the file (const char *).
   */
  GNUNET_TESTBED_TOPOLOGY_FROM_FILE
};


/**
 * Configure overall network topology to have a particular shape.
 *
 * @param op_cls closure argument to give with the operation event
 * @param num_peers number of peers in 'peers'
 * @param peers array of 'num_peers' with the peers to configure
 * @param topo desired underlay topology to use
 * @param ap topology-specific options
 * @return handle to the operation, NULL if configuring the topology
 *         is not allowed at this time
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_underlay_configure_topology_va (void *op_cls,
					       unsigned int num_peers,
					       struct GNUNET_TESTBED_Peer **peers,
					       enum GNUNET_TESTBED_TopologyOption topo,
					       va_list ap);


/**
 * Configure overall network topology to have a particular shape.
 *
 * @param op_cls closure argument to give with the operation event
 * @param num_peers number of peers in 'peers'
 * @param peers array of 'num_peers' with the peers to configure
 * @param topo desired underlay topology to use
 * @param ... topology-specific options
 * @return handle to the operation, NULL if configuring the topology
 *         is not allowed at this time
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_underlay_configure_topology (void *op_cls,
					    unsigned int num_peers,
					    struct GNUNET_TESTBED_Peer **peers,
					    enum GNUNET_TESTBED_TopologyOption topo,
					    ...);


/**
 * Both peers must have been started before calling this function.
 * This function then obtains a HELLO from 'p1', gives it to 'p2'
 * and asks 'p2' to connect to 'p1'.
 *
 * @param op_cls closure argument to give with the operation event
 * @param p1 first peer
 * @param p2 second peer
 * @return handle to the operation, NULL if connecting these two
 *         peers is fundamentally not possible at this time (peers
 *         not running or underlay disallows)
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_overlay_connect (void *op_cls,
				struct GNUNET_TESTBED_Peer *p1,
				struct GNUNET_TESTBED_Peer *p2);


/**
 * All peers must have been started before calling this function.
 * This function then connects the given peers in the P2P overlay
 * using the given topology.
 *
 * @param op_cls closure argument to give with the operation event
 * @param num_peers number of peers in 'peers'
 * @param peers array of 'num_peers' with the peers to configure
 * @param topo desired underlay topology to use
 * @param va topology-specific options
 * @return handle to the operation, NULL if connecting these 
 *         peers is fundamentally not possible at this time (peers
 *         not running or underlay disallows)
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_overlay_configure_topology_va (void *op_cls,
					      unsigned int num_peers,
					      struct GNUNET_TESTBED_Peer *peers,
					      enum GNUNET_TESTBED_TopologyOption topo,
					      va_list va);


/**
 * All peers must have been started before calling this function.
 * This function then connects the given peers in the P2P overlay
 * using the given topology.
 *
 * @param op_cls closure argument to give with the operation event
 * @param num_peers number of peers in 'peers'
 * @param peers array of 'num_peers' with the peers to configure
 * @param topo desired underlay topology to use
 * @param ... topology-specific options
 * @return handle to the operation, NULL if connecting these 
 *         peers is fundamentally not possible at this time (peers
 *         not running or underlay disallows)
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_overlay_configure_topology (void *op_cls,
					   unsigned int num_peers,
					   struct GNUNET_TESTBED_Peer *peers,
					   enum GNUNET_TESTBED_TopologyOption topo,
					   ...);



/**
 * Ask the testbed controller to write the current overlay topology to
 * a file.  Naturally, the file will only contain a snapshot as the
 * topology may evolve all the time.
 *
 * @param controller overlay controller to inspect
 * @param filename name of the file the topology should
 *        be written to.
 */
void
GNUNET_TESTBED_overlay_write_topology_to_file (struct GNUNET_TESTBED_Controller *controller,
					       const char *filename);


/**
 * Adapter function called to establish a connection to
 * a service.
 * 
 * @param cls closure
 * @param cfg configuration of the peer to connect to
 * @return service handle to return in 'op_result', NULL on error
 */
typedef void * (*GNUNET_TESTBED_ConnectAdapter)(void *cls,
						const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Adapter function called to destroy a connection to
 * a service.
 * 
 * @param cls closure
 * @param op_result service handle returned from the connect adapter
 */
typedef void (*GNUNET_TESTBED_DisconnectAdapter)(void *cls,
						 void *op_result);


/**
 * Connect to a service offered by the given peer.  Will ensure that
 * the request is queued to not overwhelm our ability to create and
 * maintain connections with other systems.  The actual service
 * handle is then returned via the 'op_result' member in the event
 * callback.  The 'ca' callback is used to create the connection
 * when the time is right; the 'da' callback will be used to 
 * destroy the connection (upon 'GNUNET_TESTBED_operation_done').
 * 'GNUNET_TESTBED_operation_cancel' can be used to abort this
 * operation until the event callback has been called.
 *
 * @param op_cls closure to pass in operation event
 * @param peer peer that runs the service
 * @param service_name name of the service to connect to
 * @param ca helper function to establish the connection
 * @param da helper function to close the connection
 * @param cada_cls closure for ca and da
 * @return handle for the operation
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_service_connect (void *op_cls,
				struct GNUNET_TESTBED_Peer *peer,
				const char *service_name,
				GNUNET_TESTBED_ConnectAdapter ca,
				GNUNET_TESTBED_DisconnectAdapter da,
				void *cada_cls);


/**
 * Cancel a pending operation.  Releases all resources
 * of the operation and will ensure that no event
 * is generated for the operation.  Does NOT guarantee
 * that the operation will be fully undone (or that
 * nothing ever happened).  
 * 
 * @param operation operation to cancel
 */
void
GNUNET_TESTBED_operation_cancel (struct GNUNET_TESTBED_Operation *operation);


/**
 * Signal that the information from an operation has been fully
 * processed.  This function MUST be called for each event
 * of type 'operation_finished' to fully remove the operation
 * from the operation queue.  After calling this function, the
 * 'op_result' becomes invalid (!).
 * 
 * @param operation operation to signal completion for
 */
void
GNUNET_TESTBED_operation_done (struct GNUNET_TESTBED_Operation *operation);


/**
 * Configure and run a testbed using the given
 * master controller on 'num_hosts' starting
 * 'num_peers' using the given peer configuration.
 *
 * @param controller master controller for the testbed
 *                   (must not be destroyed until after the
 *                    testbed is destroyed).
 * @param num_hosts number of hosts in 'hosts', 0 to only
 *        use 'localhost'
 * @param hosts list of hosts to use for the testbed
 * @param num_peers number of peers to start
 * @param peer_cfg peer configuration template to use
 * @param underlay_topology underlay topology to create
 * @param va topology-specific options
 * @return handle to the testbed
 */
struct GNUNET_TESTBED_Testbed *
GNUNET_TESTBED_create_va (struct GNUNET_TESTBED_Controller *controller,
			  unsigned int num_hosts,
			  struct GNUNET_TESTBED_Host **hosts,
			  unsigned int num_peers,
			  const struct GNUNET_CONFIGURATION_Handle *peer_cfg,
			  enum GNUNET_TESTBED_TopologyOption underlay_topology,
			  va_list va);


/**
 * Configure and run a testbed using the given
 * master controller on 'num_hosts' starting
 * 'num_peers' using the given peer configuration.
 *
 * @param controller master controller for the testbed
 *                   (must not be destroyed until after the
 *                    testbed is destroyed).
 * @param num_hosts number of hosts in 'hosts', 0 to only
 *        use 'localhost'
 * @param hosts list of hosts to use for the testbed
 * @param num_peers number of peers to start
 * @param peer_cfg peer configuration template to use
 * @param underlay_topology underlay topology to create
 * @param ... topology-specific options
 */
struct GNUNET_TESTBED_Testbed *
GNUNET_TESTBED_create (struct GNUNET_TESTBED_Controller *controller,
		       unsigned int num_hosts,
		       struct GNUNET_TESTBED_Host **hosts,
		       unsigned int num_peers,
		       const struct GNUNET_CONFIGURATION_Handle *peer_cfg,
		       enum GNUNET_TESTBED_TopologyOption underlay_topology,
		       ...);


/**
 * Destroy a testbed.  Stops all running peers and then
 * destroys all peers.  Does NOT destroy the master controller.
 *
 * @param testbed testbed to destroy
 */
void
GNUNET_TESTBED_destroy (struct GNUNET_TESTBED_Testbed *testbed);


/**
 * Convenience method for running a testbed with
 * a single call.  Underlay and overlay topology
 * are configured using the "UNDERLAY" and "OVERLAY"
 * options in the "[testbed]" section of the configuration\
 * (with possible options given in "UNDERLAY_XXX" and/or
 * "OVERLAY_XXX").
 *
 * The testbed is to be terminated using a call to
 * "GNUNET_SCHEDULER_shutdown".
 *
 * @param host_filename name of the file with the 'hosts', NULL
 *        to run everything on 'localhost'
 * @param cfg configuration to use (for testbed, controller and peers)
 * @param num_peers number of peers to start; FIXME: maybe put that ALSO into cfg?
 * @param event_mask bit mask with set of events to call 'cc' for;
 *                   or-ed values of "1LL" shifted by the
 *                   respective 'enum GNUNET_TESTBED_EventType'
 *                   (i.e.  "(1LL << GNUNET_TESTBED_ET_CONNECT) || ...")
 * @param cc controller callback to invoke on events
 * @param cc_cls closure for cc
 * @param master task to run once the testbed is ready
 * @param master_cls closure for 'task'.
 */
void
GNUNET_TESTBED_run (const char *host_filename,
		    const struct GNUNET_CONFIGURATION_Handle *cfg,
		    unsigned int num_peers,
		    uint64_t event_mask,
		    GNUNET_TESTBED_ControllerCallback cc,
		    void *cc_cls,
		    GNUNET_SCHEDULER_Task master,
		    void *master_cls);


/**
 * Signature of a main function for a testcase.
 * 
 * @param cls closure
 * @param num_peers number of peers in 'peers'
 * @param peers handle to peers run in the testbed
 */
typedef void (*GNUNET_TESTBED_TestMaster)(void *cls,
					  unsigned int num_peers,
					  struct GNUNET_TESTBED_Peer **peers);
					  

/**
 * Convenience method for running a "simple" test on the local system
 * with a single call from 'main'.  Underlay and overlay topology are
 * configured using the "UNDERLAY" and "OVERLAY" options in the
 * "[testbed]" section of the configuration (with possible options
 * given in "UNDERLAY_XXX" and/or "OVERLAY_XXX").
 *
 * The test is to be terminated using a call to
 * "GNUNET_SCHEDULER_shutdown".  If starting the test fails,
 * the program is stopped without 'master' ever being run.
 *
 * NOTE: this function should be called from 'main', NOT from
 * within a GNUNET_SCHEDULER-loop.  This function will initialze
 * the scheduler loop, the testbed and then pass control to
 * 'master'.
 *
 * @param testname name of the testcase (to configure logging, etc.)
 * @param cfg_filename configuration filename to use
 *              (for testbed, controller and peers)
 * @param num_peers number of peers to start
 * @param test_master task to run once the test is ready
 * @param test_master_cls closure for 'task'.
 */
void
GNUNET_TESTBED_test_run (const char *testname,
			 const char *cfg_filename,
			 unsigned int num_peers,
			 GNUNET_TESTBED_TestMaster test_master,
			 void *test_master_cls);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif


#ifdef __cplusplus
}
#endif

#endif
