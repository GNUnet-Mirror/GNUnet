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
#include "gnunet_testing_lib-new.h"

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
 * Handle to interact with a GNUnet testbed controller.  Each
 * controller has at least one master handle which is created when the
 * controller is created; this master handle interacts with the
 * controller process, destroying it destroys the controller (by
 * closing stdin of the controller process).  Additionally,
 * controllers can interact with each other (in a P2P fashion); those
 * links are established via TCP/IP on the controller's service port.
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
 * Create a host to run peers and controllers on.  This function is used
 * if a peer learns about a host via IPC between controllers (and thus 
 * some higher-level controller has already determined the unique IDs).
 * 
 * @param id global host ID assigned to the host; 0 is
 *        reserved to always mean 'localhost'
 * @param hostname name of the host, use "NULL" for localhost
 * @param username username to use for the login; may be NULL
 * @param port port number to use for ssh; use 0 to let ssh decide
 * @return handle to the host, NULL on error
 */
struct GNUNET_TESTBED_Host *
GNUNET_TESTBED_host_create_with_id (uint32_t id,
				    const char *hostname,
				    const char *username,
				    uint16_t port);


/**
 * Load a set of hosts from a configuration file.
 *
 * @param filename file with the host specification
 * @param hosts set to the hosts found in the file; caller must free this if
 *          number of hosts returned is greater than 0
 * @return number of hosts returned in 'hosts', 0 on error
 */
unsigned int
GNUNET_TESTBED_hosts_load_from_file (const char *filename,
				     struct GNUNET_TESTBED_Host ***hosts);


/**
 * Destroy a host handle.  Must only be called once everything
 * running on that host has been stopped.
 *
 * @param host handle to destroy
 */
void
GNUNET_TESTBED_host_destroy (struct GNUNET_TESTBED_Host *host);


/**
 * Checks whether a host can be used to start testbed service
 *
 * @param host the host to check
 * @return GNUNET_YES if testbed service can be started on the given host
 *           remotely; GNUNET_NO if not
 */
int
GNUNET_TESTBED_is_host_habitable (const struct GNUNET_TESTBED_Host *host);


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
       * No result (NULL pointer) or generic result
       * (whatever the GNUNET_TESTBED_ConnectAdapter returned).
       */
      void *generic;
      
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
 * Opaque Handle for Controller process
 */
struct GNUNET_TESTBED_ControllerProc;


/**
 * Callback to signal successfull startup of the controller process
 *
 * @param cls the closure from GNUNET_TESTBED_controller_start()
 * @param cfg the configuration with which the controller has been started;
 *          NULL if status is not GNUNET_OK
 * @param status GNUNET_OK if the startup is successfull; GNUNET_SYSERR if not,
 *          GNUNET_TESTBED_controller_stop() shouldn't be called in this case
 */
typedef void (*GNUNET_TESTBED_ControllerStatusCallback) (void *cls, 
                                                        const struct GNUNET_CONFIGURATION_Handle *cfg,
                                                        int status);


/**
 * Starts a controller process at the host. 
 *
 * @param controller_ip the ip address of the controller. Will be set as TRUSTED
 *          host when starting testbed controller at host
 * @param host the host where the controller has to be started; NULL for
 *          localhost
 * @param cfg template configuration to use for the remote controller; the
 *          remote controller will be started with a slightly modified
 *          configuration (port numbers, unix domain sockets and service home
 *          values are changed as per TESTING library on the remote host)
 * @param cb function called when the controller is successfully started or
 *          dies unexpectedly; GNUNET_TESTBED_controller_stop shouldn't be
 *          called if cb is called with GNUNET_SYSERR as status. Will never be
 *          called in the same task as 'GNUNET_TESTBED_controller_start'
 *          (synchronous errors will be signalled by returning NULL). This
 *          parameter cannot be NULL.
 * @param cls closure for above callbacks
 * @return the controller process handle, NULL on errors
 */
struct GNUNET_TESTBED_ControllerProc *
GNUNET_TESTBED_controller_start (const char *controller_ip,
				 struct GNUNET_TESTBED_Host *host,
				 const struct GNUNET_CONFIGURATION_Handle *cfg,
                                 GNUNET_TESTBED_ControllerStatusCallback cb,
				 void *cls);


/**
 * Stop the controller process (also will terminate all peers and controllers
 * dependent on this controller).  This function blocks until the testbed has
 * been fully terminated (!). The controller status cb from
 * GNUNET_TESTBED_controller_start() will not be called.
 *
 * @param cproc the controller process handle
 */
void
GNUNET_TESTBED_controller_stop (struct GNUNET_TESTBED_ControllerProc *cproc);


/**
 * Connect to a controller process using the given configuration at the
 * given host.
 *
 * @param cfg configuration to use
 * @param host host to run the controller on; This should be the same host if
 *          the controller was previously started with
 *          GNUNET_TESTBED_controller_start; NULL for localhost
 * @param host host where this controller is being run;
 * @param event_mask bit mask with set of events to call 'cc' for;
 *                   or-ed values of "1LL" shifted by the
 *                   respective 'enum GNUNET_TESTBED_EventType'
 *                   (i.e.  "(1LL << GNUNET_TESTBED_ET_CONNECT) | ...")
 * @param cc controller callback to invoke on events
 * @param cc_cls closure for cc
 * @return handle to the controller
 */
struct GNUNET_TESTBED_Controller *
GNUNET_TESTBED_controller_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
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
GNUNET_TESTBED_controller_disconnect (struct GNUNET_TESTBED_Controller *controller);


/**
 * Opaque handle for host registration
 */
struct GNUNET_TESTBED_HostRegistrationHandle;


/**
 * Callback which will be called to after a host registration succeeded or failed
 *
 * @param cls the closure
 * @param emsg the error message; NULL if host registration is successful
 */
typedef void (* GNUNET_TESTBED_HostRegistrationCompletion) (void *cls, 
                                                            const char *emsg);


/**
 * Register a host with the controller
 *
 * @param controller the controller handle
 * @param host the host to register
 * @param cc the completion callback to call to inform the status of
 *          registration. After calling this callback the registration handle
 *          will be invalid. Cannot be NULL
 * @param cc_cls the closure for the cc
 * @return handle to the host registration which can be used to cancel the
 *           registration; NULL if another registration handle is present and
 *           is not cancelled
 */
struct GNUNET_TESTBED_HostRegistrationHandle *
GNUNET_TESTBED_register_host (struct GNUNET_TESTBED_Controller *controller,
                              struct GNUNET_TESTBED_Host *host,
                              GNUNET_TESTBED_HostRegistrationCompletion cc,
                              void *cc_cls);


/**
 * Cancel the pending registration. Note that the registration message will
 * already be queued to be sent to the service, cancellation has only the
 * effect that the registration completion callback for the registration is
 * never called and from our perspective the host is not registered until the
 * completion callback is called.
 *
 * @param handle the registration handle to cancel
 */
void
GNUNET_TESTBED_cancel_registration (struct GNUNET_TESTBED_HostRegistrationHandle
                                    *handle);


/**
 * Callback to be called when an operation is completed
 *
 * @param cls the callback closure from functions generating an operation
 * @param op the operation that has been finished
 * @param emsg error message in case the operation has failed; will be NULL if
 *          operation has executed successfully.
 */
typedef void (*GNUNET_TESTBED_OperationCompletionCallback) (void *cls,
                                                            struct
                                                            GNUNET_TESTBED_Operation
                                                            *op,
                                                            const char *emsg);


/**
 * Create a link from slave controller to delegated controller. Whenever the
 * master controller is asked to start a peer at the delegated controller the
 * request will be routed towards slave controller (if a route exists). The
 * slave controller will then route it to the delegated controller. The
 * configuration of the delegated controller is given and is used to either
 * create the delegated controller or to connect to an existing controller. Note
 * that while starting the delegated controller the configuration will be
 * modified to accommodate available free ports.  the 'is_subordinate' specifies
 * if the given delegated controller should be started and managed by the slave
 * controller, or if the delegated controller already has a master and the slave
 * controller connects to it as a non master controller. The success or failure
 * of this operation will be signalled through the
 * GNUNET_TESTBED_ControllerCallback() with an event of type
 * GNUNET_TESTBED_ET_OPERATION_FINISHED
 *
 * @param op_cls the operation closure for the event which is generated to
 *          signal success or failure of this operation
 * @param master handle to the master controller who creates the association
 * @param delegated_host requests to which host should be delegated; cannot be NULL
 * @param slave_host which host is used to run the slave controller; use NULL to
 *          make the master controller connect to the delegated host
 * @param slave_cfg configuration to use for the slave controller
 * @param is_subordinate GNUNET_YES if the controller at delegated_host should
 *          be started by the slave controller; GNUNET_NO if the slave
 *          controller has to connect to the already started delegated
 *          controller via TCP/IP
 * @return the operation handle
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_controller_link (void *op_cls,
				struct GNUNET_TESTBED_Controller *master,
				struct GNUNET_TESTBED_Host *delegated_host,
				struct GNUNET_TESTBED_Host *slave_host,
				const struct GNUNET_CONFIGURATION_Handle
				*slave_cfg,
				int is_subordinate);


/**
 * Same as the GNUNET_TESTBED_controller_link, however expects configuration in
 * serialized and compressed
 *
 * @param op_cls the operation closure for the event which is generated to
 *          signal success or failure of this operation
 * @param master handle to the master controller who creates the association
 * @param delegated_host requests to which host should be delegated; cannot be NULL
 * @param slave_host which host is used to run the slave controller; use NULL to
 *          make the master controller connect to the delegated host
 * @param sxcfg serialized and compressed configuration
 * @param sxcfg_size the size sxcfg
 * @param scfg_size the size of uncompressed serialized configuration
 * @param is_subordinate GNUNET_YES if the controller at delegated_host should
 *          be started by the slave controller; GNUNET_NO if the slave
 *          controller has to connect to the already started delegated
 *          controller via TCP/IP
 * @return the operation handle
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_controller_link_2 (void *op_cls,
				  struct GNUNET_TESTBED_Controller *master,
				  struct GNUNET_TESTBED_Host *delegated_host,
				  struct GNUNET_TESTBED_Host *slave_host,
				  const char *sxcfg,
				  size_t sxcfg_size,
				  size_t scfg_size,
				  int is_subordinate);


/**
 * Function to acquire the configuration of a running slave controller. The
 * completion of the operation is signalled through the controller_cb from
 * GNUNET_TESTBED_controller_connect(). If the operation is successful the
 * handle to the configuration is available in the generic pointer of
 * operation_finished field of struct GNUNET_TESTBED_EventInformation.
 *
 * @param op_cls the closure for the operation
 * @param master the handle to master controller
 * @param slave_host the host where the slave controller is running; the handle
 *          to the slave_host should remain valid until this operation is
 *          cancelled or marked as finished
 * @return the operation handle; NULL if the slave_host is not registered at
 *           master
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_get_slave_config (void *op_cls,
                                 struct GNUNET_TESTBED_Controller *master,
                                 struct GNUNET_TESTBED_Host *slave_host);


/**
 * Functions of this signature are called when a peer has been successfully
 * created
 *
 * @param cls the closure from GNUNET_TESTBED_peer_create()
 * @param peer the handle for the created peer; NULL on any error during
 *          creation
 * @param emsg NULL if peer is not NULL; else MAY contain the error description
 */
typedef void (*GNUNET_TESTBED_PeerCreateCallback) (void *cls,
						   struct GNUNET_TESTBED_Peer *peer,
						   const char *emsg);


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
 * @param cfg Template configuration to use for the peer. Should exist until
 *          operation is cancelled or GNUNET_TESTBED_operation_done() is called
 * @param cb the callback to call when the peer has been created
 * @param cls the closure to the above callback
 * @return the operation handle
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_peer_create (struct GNUNET_TESTBED_Controller *controller,
			    struct GNUNET_TESTBED_Host *host,
			    const struct GNUNET_CONFIGURATION_Handle *cfg,
			    GNUNET_TESTBED_PeerCreateCallback cb,
			    void *cls);


/**
 * Functions of this signature are called when a peer has been successfully
 * started or stopped.
 *
 * @param cls the closure from GNUNET_TESTBED_peer_start/stop()
 * @param emsg NULL on success; otherwise an error description
 */
typedef void (*GNUNET_TESTBED_PeerChurnCallback) (void *cls,
						  const char *emsg);


/**
 * Start the given peer.
 *
 * @param op_cls the closure for this operation; will be set in
 *          event->details.operation_finished.op_cls when this operation fails.
 * @param peer peer to start
 * @param pcc function to call upon completion
 * @param pcc_cls closure for 'pcc'
 * @return handle to the operation
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_peer_start (void *op_cls,
			   struct GNUNET_TESTBED_Peer *peer,
			   GNUNET_TESTBED_PeerChurnCallback pcc,
			   void *pcc_cls);


/**
 * Stop the given peer.  The handle remains valid (use
 * "GNUNET_TESTBED_peer_destroy" to fully clean up the 
 * state of the peer).
 *
 * @param peer peer to stop
 * @param pcc function to call upon completion
 * @param pcc_cls closure for 'pcc'
 * @return handle to the operation
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_peer_stop (struct GNUNET_TESTBED_Peer *peer,
			  GNUNET_TESTBED_PeerChurnCallback pcc,
			  void *pcc_cls);


/**
 * Data returned from GNUNET_TESTBED_peer_get_information
 */
struct GNUNET_TESTBED_PeerInformation
{
  /**
   * Peer information type; captures which of the types
   * in the 'op_result' is actually in use.
   */
  enum GNUNET_TESTBED_PeerInformationType pit;
  
  /**
   * The result of the get information operation; Choose according to the pit
   */
  union
  { 
    /**
     * The configuration of the peer
     */
    struct GNUNET_CONFIGURATION_Handle *cfg;
  
    /**
     * The identity of the peer
     */
    struct GNUNET_PeerIdentity *id;
  } result;
};


/**
 * Callback to be called when the requested peer information is available
 *
 * @param cb_cls the closure from GNUNET_TETSBED_peer_get_information()
 * @param op the operation this callback corresponds to
 * @param pinfo the result; will be NULL if the operation has failed
 * @param emsg error message if the operation has failed; will be NULL if the
 *          operation is successfull
 */
typedef void (*GNUNET_TESTBED_PeerInfoCallback) (void *cb_cls,
						 struct GNUNET_TESTBED_Operation
						 *op,
						 const struct
						 GNUNET_TESTBED_PeerInformation
						 *pinfo,
						 const char *emsg);


/**
 * Request information about a peer. The controller callback will not be called
 * with event type GNUNET_TESTBED_ET_OPERATION_FINISHED when result for this
 * operation is available. Instead, the GNUNET_TESTBED_PeerInfoCallback() will
 * be called.
 *
 * @param peer peer to request information about
 * @param pit desired information
 * @param cb the convenience callback to be called when results for this
 *          operation are available
 * @param cb_cls the closure for the above callback
 * @return handle to the operation
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_peer_get_information (struct GNUNET_TESTBED_Peer *peer,
				     enum GNUNET_TESTBED_PeerInformationType
				     pit,
				     GNUNET_TESTBED_PeerInfoCallback cb,
				     void *cb_cls);


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
 * @param cb the callback to call when this operation has finished
 * @param cb_cls the closure for the above callback
 * @param p1 first peer
 * @param p2 second peer
 * @return handle to the operation, NULL if connecting these two
 *         peers is fundamentally not possible at this time (peers
 *         not running or underlay disallows)
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_overlay_connect (void *op_cls,
                                GNUNET_TESTBED_OperationCompletionCallback cb,
                                void *cb_cls,
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
 *         not running or underlay disallows) or if num_peers is less than 2
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_overlay_configure_topology_va (void *op_cls,
					      unsigned int num_peers,
					      struct GNUNET_TESTBED_Peer **peers,
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
 *         not running or underlay disallows) or if num_peers is less than 2
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_overlay_configure_topology (void *op_cls,
					   unsigned int num_peers,
					   struct GNUNET_TESTBED_Peer **peers,
					   enum GNUNET_TESTBED_TopologyOption topo,
					   ...);


/**
 * Ask the testbed controller to write the current overlay topology to
 * a file.  Naturally, the file will only contain a snapshot as the
 * topology may evolve all the time.
 * FIXME: needs continuation!?
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
 * @param cfg configuration of the peer to connect to; will be available until
 *          GNUNET_TESTBED_operation_done() is called on the operation returned
 *          from GNUNET_TESTBED_service_connect()
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
 * Callback to be called when a service connect operation is completed
 *
 * @param cls the callback closure from functions generating an operation
 * @param op the operation that has been finished
 * @param ca_result the service handle returned from GNUNET_TESTBED_ConnectAdapter()
 * @param emsg error message in case the operation has failed; will be NULL if
 *          operation has executed successfully.
 */
typedef void (*GNUNET_TESTBED_ServiceConnectCompletionCallback) (void *cls,
								 struct
								 GNUNET_TESTBED_Operation
								 *op,
								 void
								 *ca_result, 
								 const char
								 *emsg );


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
 * @param cb the callback to call when this operation finishes
 * @param cb_cls closure for the above callback
 * @param ca helper function to establish the connection
 * @param da helper function to close the connection
 * @param cada_cls closure for ca and da
 * @return handle for the operation
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_service_connect (void *op_cls,
				struct GNUNET_TESTBED_Peer *peer,
				const char *service_name,
                                GNUNET_TESTBED_ServiceConnectCompletionCallback cb,
                                void *cb_cls,
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
 * Callback function to process statistic values from all peers.
 *
 * @param cls closure
 * @param peer the peer the statistic belong to
 * @param subsystem name of subsystem that created the statistic
 * @param name the name of the datum
 * @param value the current value
 * @param is_persistent GNUNET_YES if the value is persistent, GNUNET_NO if not
 * @return GNUNET_OK to continue, GNUNET_SYSERR to abort iteration
 */
typedef int (*GNUNET_TESTBED_StatisticsIterator) (void *cls,
						  const struct GNUNET_TESTBED_Peer *peer,
						  const char *subsystem,
						  const char *name,
						  uint64_t value,
						  int is_persistent);


/**
 * Convenience method that iterates over all (running) peers 
 * and retrieves all statistics from each peer.
 *
 * @param num_peers number of peers to iterate over
 * @param peers array of peers to iterate over
 * @param proc processing function for each statistic retrieved
 * @param cont continuation to call once call is completed(?)
 * @param cls closure to pass to proc and cont
 * @return operation handle to cancel the operation
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_get_statistics (unsigned int num_peers,
			       struct GNUNET_TESTBED_Peer **peers,
                               GNUNET_TESTBED_StatisticsIterator proc,
                               GNUNET_TESTBED_OperationCompletionCallback cont,
                               void *cls);


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
 * @param num_peers number of peers to start; FIXME: maybe put that ALSO into
 *        cfg?; should be greater than 0
 * @param event_mask bit mask with set of events to call 'cc' for;
 *                   or-ed values of "1LL" shifted by the
 *                   respective 'enum GNUNET_TESTBED_EventType'
 *                   (i.e.  "(1LL << GNUNET_TESTBED_ET_CONNECT) || ...")
 * @param cc controller callback to invoke on events; This callback is called
 *        for all peer start events even if GNUNET_TESTBED_ET_PEER_START isn't
 *        set in the event_mask as this is the only way get access to the
 *        handle of each peer
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
 * @param num_peers number of peers to start; should be greter than 0
 * @param event_mask bit mask with set of events to call 'cc' for;
 *                   or-ed values of "1LL" shifted by the
 *                   respective 'enum GNUNET_TESTBED_EventType'
 *                   (i.e.  "(1LL << GNUNET_TESTBED_ET_CONNECT) || ...")
 * @param cc controller callback to invoke on events; This callback is called
 *        for all peer start events even if GNUNET_TESTBED_ET_PEER_START isn't
 *        set in the event_mask as this is the only way get access to the
 *        handle of each peer
 * @param cc_cls closure for cc
 * @param test_master task to run once the test is ready
 * @param test_master_cls closure for 'task'.
 */
void
GNUNET_TESTBED_test_run (const char *testname,
			 const char *cfg_filename,
			 unsigned int num_peers,
                         uint64_t event_mask,
                         GNUNET_TESTBED_ControllerCallback cc,
                         void *cc_cls,
			 GNUNET_TESTBED_TestMaster test_master,
			 void *test_master_cls);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif


#ifdef __cplusplus
}
#endif

#endif
