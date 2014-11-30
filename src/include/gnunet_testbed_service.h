/*
      This file is part of GNUnet
      (C) 2008--2013 Christian Grothoff (and other contributing authors)

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
#include "gnunet_testing_lib.h"

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
 * Create a host to run peers and controllers on.
 *
 * @param hostname name of the host, use "NULL" for localhost
 * @param username username to use for the login; may be NULL
 * @param cfg the configuration to use as a template while starting a controller
 *          on this host.  Operation queue sizes specific to a host are also
 *          read from this configuration handle
 * @param port port number to use for ssh; use 0 to let ssh decide
 * @return handle to the host, NULL on error
 */
struct GNUNET_TESTBED_Host *
GNUNET_TESTBED_host_create (const char *hostname,
                            const char *username,
                            const struct GNUNET_CONFIGURATION_Handle *cfg,
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
 * @param cfg the configuration to use as a template while starting a controller
 *          on this host.  Operation queue sizes specific to a host are also
 *          read from this configuration handle
 * @param port port number to use for ssh; use 0 to let ssh decide
 * @return handle to the host, NULL on error
 */
struct GNUNET_TESTBED_Host *
GNUNET_TESTBED_host_create_with_id (uint32_t id,
                                    const char *hostname,
                                    const char *username,
                                    const struct GNUNET_CONFIGURATION_Handle
                                    *cfg,
                                    uint16_t port);


/**
 * Load a set of hosts from a configuration file.  The hostfile format is
 * specified at https://gnunet.org/content/hosts-file-format
 *
 * @param filename file with the host specification
 * @param cfg the configuration to use as a template while starting a controller
 *          on any of the loaded hosts.  Operation queue sizes specific to a host
 *          are also read from this configuration handle
 * @param hosts set to the hosts found in the file; caller must free this if
 *          number of hosts returned is greater than 0
 * @return number of hosts returned in 'hosts', 0 on error
 */
unsigned int
GNUNET_TESTBED_hosts_load_from_file (const char *filename,
                                     const struct GNUNET_CONFIGURATION_Handle
                                     *cfg,
                                     struct GNUNET_TESTBED_Host ***hosts);


/**
 * Loads the set of host allocated by the LoadLeveler Job Scheduler.  This
 * function is only available when compiled with support for LoadLeveler and is
 * used for running on the SuperMUC
 *
 * @param cfg the configuration to use as a template while starting a controller
 *          on any of the loaded hosts.  Operation queue sizes specific to a host
 *          are also read from this configuration handle
 * @param hosts set to the hosts found in the file; caller must free this if
 *          number of hosts returned is greater than 0
 * @return number of hosts returned in 'hosts', 0 on error
 */
unsigned int
GNUNET_TESTBED_hosts_load_from_loadleveler (const struct
                                            GNUNET_CONFIGURATION_Handle *cfg,
                                            struct GNUNET_TESTBED_Host
                                            ***hosts);

/**
 * Destroy a host handle.  Must only be called once everything
 * running on that host has been stopped.
 *
 * @param host handle to destroy
 */
void
GNUNET_TESTBED_host_destroy (struct GNUNET_TESTBED_Host *host);


/**
 * The handle for whether a host is habitable or not
 */
struct GNUNET_TESTBED_HostHabitableCheckHandle;


/**
 * Callbacks of this type are called by GNUNET_TESTBED_is_host_habitable to
 * inform whether the given host is habitable or not. The Handle returned by
 * GNUNET_TESTBED_is_host_habitable() is invalid after this callback is called
 *
 * @param cls the closure given to GNUNET_TESTBED_is_host_habitable()
 * @param host the host whose status is being reported; will be NULL if the host
 *          given to GNUNET_TESTBED_is_host_habitable() is NULL
 * @param status GNUNET_YES if it is habitable; GNUNET_NO if not
 */
typedef void (*GNUNET_TESTBED_HostHabitableCallback) (void *cls,
                                                      const struct
                                                      GNUNET_TESTBED_Host
                                                      *host,
                                                      int status);


/**
 * Checks whether a host can be used to start testbed service
 *
 * @param host the host to check
 * @param config the configuration handle to lookup the path of the testbed
 *          helper
 * @param cb the callback to call to inform about habitability of the given host
 * @param cb_cls the closure for the callback
 * @return NULL upon any error or a handle which can be passed to
 *           GNUNET_TESTBED_is_host_habitable_cancel()
 */
struct GNUNET_TESTBED_HostHabitableCheckHandle *
GNUNET_TESTBED_is_host_habitable (const struct GNUNET_TESTBED_Host *host,
                                  const struct GNUNET_CONFIGURATION_Handle
                                  *config,
                                  GNUNET_TESTBED_HostHabitableCallback cb,
                                  void *cb_cls);


/**
 * Function to cancel a request started using GNUNET_TESTBED_is_host_habitable()
 *
 * @param handle the habitability check handle
 */
void
GNUNET_TESTBED_is_host_habitable_cancel (struct
                                         GNUNET_TESTBED_HostHabitableCheckHandle
                                         *handle);

/**
 * Obtain the host's hostname.
 *
 * @param host handle to the host, NULL means 'localhost'
 * @return hostname of the host
 */
const char *
GNUNET_TESTBED_host_get_hostname (const struct GNUNET_TESTBED_Host *host);


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
   * Handle for the corresponding operation that generated this event
   */
  struct GNUNET_TESTBED_Operation *op;

  /**
   * Closure given while creating the above operation
   */
  void *op_cls;

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
       * Error message for the operation, NULL on success.
       */
      const char *emsg;

      /**
       * No result (NULL pointer) or generic result
       * (whatever the GNUNET_TESTBED_ConnectAdapter returned).
       */
      void *generic;

    } operation_finished;

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
 * Starts a controller process at the given host.  The given host's configration
 * is used as a Template configuration to use for the remote controller; the
 * remote controller will be started with a slightly modified configuration
 * (port numbers, unix domain sockets and service home values are changed as per
 * TESTING library on the remote host).  The modified configuration replaces the
 * host's existing configuration before signalling success through the
 * GNUNET_TESTBED_ControllerStatusCallback()
 *
 * @param trusted_ip the ip address of the controller which will be set as TRUSTED
 *          HOST(all connections form this ip are permitted by the testbed) when
 *          starting testbed controller at host. This can either be a single ip
 *          address or a network address in CIDR notation.
 * @param host the host where the controller has to be started.  CANNOT be NULL.
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
GNUNET_TESTBED_controller_start (const char *trusted_ip,
                                 struct GNUNET_TESTBED_Host *host,
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
 * Connect to a controller process.  The configuration to use for the connection
 * is retreived from the given host where a controller is started using
 * GNUNET_TESTBED_controller_start().
 *
 * @param host host to run the controller on; This should be the same host if
 *          the controller was previously started with
 *          GNUNET_TESTBED_controller_start()
 * @param event_mask bit mask with set of events to call 'cc' for;
 *                   or-ed values of "1LL" shifted by the
 *                   respective 'enum GNUNET_TESTBED_EventType'
 *                   (i.e.  "(1LL << GNUNET_TESTBED_ET_CONNECT) | ...")
 * @param cc controller callback to invoke on events
 * @param cc_cls closure for cc
 * @return handle to the controller
 */
struct GNUNET_TESTBED_Controller *
GNUNET_TESTBED_controller_connect (struct GNUNET_TESTBED_Host *host,
                                   uint64_t event_mask,
                                   GNUNET_TESTBED_ControllerCallback cc,
                                   void *cc_cls);


/**
 * Stop the given controller (also will terminate all peers and
 * controllers dependent on this controller).  This function
 * blocks until the testbed has been fully terminated (!).
 *
 * @param c handle to controller to stop
 */
void
GNUNET_TESTBED_controller_disconnect (struct GNUNET_TESTBED_Controller *c);


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
 * Register a host with the controller. This makes the controller aware of the
 * host. A host should be registered at the controller before starting a
 * sub-controller on that host using GNUNET_TESTBED_controller_link().
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
 * #GNUNET_TESTBED_ET_OPERATION_FINISHED
 *
 * @param op_cls the operation closure for the event which is generated to
 *          signal success or failure of this operation
 * @param master handle to the master controller who creates the association
 * @param delegated_host requests to which host should be delegated; cannot be NULL
 * @param slave_host which host is used to run the slave controller; use NULL to
 *          make the master controller connect to the delegated host
 * @param is_subordinate #GNUNET_YES if the controller at delegated_host should
 *          be started by the slave controller; #GNUNET_NO if the slave
 *          controller has to connect to the already started delegated
 *          controller via TCP/IP
 * @return the operation handle
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_controller_link (void *op_cls,
                                struct GNUNET_TESTBED_Controller *master,
                                struct GNUNET_TESTBED_Host *delegated_host,
                                struct GNUNET_TESTBED_Host *slave_host,
                                int is_subordinate);


/**
 * Function to acquire the configuration of a running slave controller. The
 * completion of the operation is signalled through the controller_cb from
 * GNUNET_TESTBED_controller_connect(). If the operation is successful the
 * handle to the configuration is available in the generic pointer of
 * operation_finished field of `struct GNUNET_TESTBED_EventInformation`.
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
 * configure the peer; use #GNUNET_TESTBED_peer_start and
 * #GNUNET_TESTBED_peer_stop to actually start/stop the peer's
 * processes.
 *
 * Note that the given configuration will be adjusted by the
 * controller to avoid port/path conflicts with other peers.
 * The "final" configuration can be obtained using
 * #GNUNET_TESTBED_peer_get_information.
 *
 * @param controller controller process to use
 * @param host host to run the peer on; cannot be NULL
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
 * @param op_cls the closure for this operation; will be set in the event
 *          information
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
 * #GNUNET_TESTBED_peer_destroy to fully clean up the
 * state of the peer).
 *
 * @param op_cls the closure for this operation; will be set in the event
 *          information
 * @param peer peer to stop
 * @param pcc function to call upon completion
 * @param pcc_cls closure for 'pcc'
 * @return handle to the operation
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_peer_stop (void *op_cls,
                          struct GNUNET_TESTBED_Peer *peer,
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
 * The peer information in the callback is valid until the operation 'op' is canceled.
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
 * with event type #GNUNET_TESTBED_ET_OPERATION_FINISHED when result for this
 * operation is available. Instead, the GNUNET_TESTBED_PeerInfoCallback() will
 * be called.
 * The peer information in the callback is valid until the operation is canceled.
 *
 * @param peer peer to request information about
 * @param pit desired information
 * @param cb the convenience callback to be called when results for this
 *          operation are available
 * @param cb_cls the closure for @a cb
 * @return handle to the operation
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_peer_get_information (struct GNUNET_TESTBED_Peer *peer,
                                     enum GNUNET_TESTBED_PeerInformationType
                                     pit,
                                     GNUNET_TESTBED_PeerInfoCallback cb,
                                     void *cb_cls);


/**
 * Change @a peer configuration.  Ports and paths cannot be changed this
 * way.
 *
 * @param peer peer to change configuration for
 * @param cfg new configuration
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
 * Start or stop given service at a peer.  This should not be called to
 * start/stop the peer's ARM service.  Use GNUNET_TESTBED_peer_start(),
 * GNUNET_TESTBED_peer_stop() for starting/stopping peer's ARM service.  Success
 * or failure of the generated operation is signalled through the controller
 * event callback and/or operation completion callback.
 *
 * @param op_cls the closure for the operation
 * @param peer the peer whose service is to be started/stopped
 * @param service_name the name of the service
 * @param cb the operation completion callback
 * @param cb_cls the closure for @a cb
 * @param start 1 to start the service; 0 to stop the service
 * @return an operation handle; NULL upon error (peer not running)
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_peer_manage_service (void *op_cls,
                                    struct GNUNET_TESTBED_Peer *peer,
                                    const char *service_name,
                                    GNUNET_TESTBED_OperationCompletionCallback cb,
                                    void *cb_cls,
                                    unsigned int start);


/**
 * Stops and destroys all peers.  Is equivalent of calling
 * GNUNET_TESTBED_peer_stop() and GNUNET_TESTBED_peer_destroy() on all peers,
 * except that the peer stop event and operation finished event corresponding to
 * the respective functions are not generated.  This function should be called
 * when there are no other pending operations.  If there are pending operations,
 * it will return NULL
 *
 * @param c the controller to send this message to
 * @param op_cls closure for the operation
 * @param cb the callback to call when all peers are stopped and destroyed
 * @param cb_cls the closure for the callback
 * @return operation handle on success; NULL if any pending operations are
 *           present
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_shutdown_peers (struct GNUNET_TESTBED_Controller *c,
                               void *op_cls,
                               GNUNET_TESTBED_OperationCompletionCallback cb,
                               void *cb_cls);



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
   * Followed by #GNUNET_NO (int) if a connection is disallowed
   * or #GNUNET_YES if a connection is allowed.  Note that the
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
 * Topologies and topology options supported for testbeds. Options should always
 * end with GNUNET_TESTBED_TOPOLOGY_OPTION_END
 */
enum GNUNET_TESTBED_TopologyOption
{
  /**
   * A clique (everyone connected to everyone else).  No options. If there are N
   * peers this topology results in (N * (N -1)) connections.
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
   * Random graph.  Followed by the number of random links to be established
   * (unsigned int)
   */
  GNUNET_TESTBED_TOPOLOGY_ERDOS_RENYI,

  /**
   * Certain percentage of peers are unable to communicate directly
   * replicating NAT conditions.  Followed by the fraction of
   * NAT'ed peers (float).
   */
  GNUNET_TESTBED_TOPOLOGY_INTERNAT,

  /**
   * Scale free topology.  It is generated according to the method described in
   * "Emergence of Scaling in Random Networks." Science 286, 509-512, 1999.
   *
   * This options takes two arguments in the following order: an uint16_t to
   * determine the maximum number of edges a peer is permitted to have while
   * generating scale free topology, a good value for this argument is 70; and
   * an uint8_t to determine the number of edges to be established when adding a
   * new node to the scale free network, a good value for this argument is 4.
   */
  GNUNET_TESTBED_TOPOLOGY_SCALE_FREE,

  /**
   * Straight line topology.  No options.
   */
  GNUNET_TESTBED_TOPOLOGY_LINE,

  /**
   * Read a topology from a given file.  Followed by the name of the file (const char *).
   */
  GNUNET_TESTBED_TOPOLOGY_FROM_FILE,

  /**
   * All peers are disconnected.  No options.
   */
  GNUNET_TESTBED_TOPOLOGY_NONE,

  /**
   * The options should always end with this
   */
  GNUNET_TESTBED_TOPOLOGY_OPTION_END,

  /* The following are not topologies but influence how the topology has to be
     setup. These options should follow the topology specific options (if
     required by the chosen topology). Note that these should be given before
     GNUNET_TESTBED_TOPOLOGY_OPTION_END */

  /**
   * How many times should the failed overlay connect operations be retried
   * before giving up.  The default if this option is not specified is to retry
   * 3 times.  This option takes and unsigned integer as a parameter.  Use this
   * option with parameter 0 to disable retrying of failed overlay connect
   * operations.
   */
  GNUNET_TESTBED_TOPOLOGY_RETRY_CNT
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
 * This function then obtains a HELLO from @a p1, gives it to @a p2
 * and asks @a p2 to connect to @a p1.
 *
 * @param op_cls closure argument to give with the operation event
 * @param cb the callback to call when this operation has finished
 * @param cb_cls the closure for @a cb
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
 * Callbacks of this type are called when topology configuration is completed
 *
 * @param cls the operation closure given to
 *          GNUNET_TESTBED_overlay_configure_topology_va() and
 *          GNUNET_TESTBED_overlay_configure() calls
 * @param nsuccess the number of successful overlay connects
 * @param nfailures the number of overlay connects which failed
 */
typedef void (*GNUNET_TESTBED_TopologyCompletionCallback) (void *cls,
                                                          unsigned int nsuccess,
                                                          unsigned int nfailures);


/**
 * All peers must have been started before calling this function.
 * This function then connects the given peers in the P2P overlay
 * using the given topology.
 *
 * @param op_cls closure argument to give with the peer connect operation events
 *          generated through this function
 * @param num_peers number of peers in 'peers'
 * @param peers array of 'num_peers' with the peers to configure
 * @param max_connections the maximums number of overlay connections that will
 *          be made to achieve the given topology
 * @param comp_cb the completion callback to call when the topology generation
 *          is completed
 * @param comp_cb_cls closure for the @a comp_cb
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
                                              unsigned int *max_connections,
                                              GNUNET_TESTBED_TopologyCompletionCallback
                                              comp_cb,
                                              void *comp_cb_cls,
                                              enum GNUNET_TESTBED_TopologyOption topo,
                                              va_list va);


/**
 * All peers must have been started before calling this function.
 * This function then connects the given peers in the P2P overlay
 * using the given topology.
 *
 * @param op_cls closure argument to give with the peer connect operation events
 *          generated through this function
 * @param num_peers number of peers in 'peers'
 * @param peers array of 'num_peers' with the peers to configure
 * @param max_connections the maximums number of overlay connections that will
 *          be made to achieve the given topology
 * @param comp_cb the completion callback to call when the topology generation
 *          is completed
 * @param comp_cb_cls closure for the above completion callback
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
                                           unsigned int *max_connections,
                                           GNUNET_TESTBED_TopologyCompletionCallback
                                           comp_cb,
                                           void *comp_cb_cls,
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
 * callback.  The @a ca callback is used to create the connection
 * when the time is right; the @a da callback will be used to
 * destroy the connection (upon #GNUNET_TESTBED_operation_done).
 * #GNUNET_TESTBED_operation_done can be used to abort this
 * operation until the event callback has been called.
 *
 * @param op_cls closure to pass in operation event // FIXME: didn't we say we'd no longer use the global callback for these? -CG
 * @param peer peer that runs the service
 * @param service_name name of the service to connect to
 * @param cb the callback to call when this operation is ready (that is,
 *        right after the connect adapter returns)
 * @param cb_cls closure for @a cb
 * @param ca helper function to establish the connection
 * @param da helper function to close the connection
 * @param cada_cls closure for @a ca and @a da
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
 * This function is used to signal that the event information (struct
 * GNUNET_TESTBED_EventInformation) from an operation has been fully processed
 * i.e. if the event callback is ever called for this operation. If the event
 * callback for this operation has not yet been called, calling this function
 * cancels the operation, frees its resources and ensures the no event is
 * generated with respect to this operation. Note that however cancelling an
 * operation does NOT guarantee that the operation will be fully undone (or that
 * nothing ever happened).
 *
 * This function MUST be called for every operation to fully remove the
 * operation from the operation queue.  After calling this function, if
 * operation is completed and its event information is of type
 * GNUNET_TESTBED_ET_OPERATION_FINISHED, the 'op_result' becomes invalid (!).

 * If the operation is generated from GNUNET_TESTBED_service_connect() then
 * calling this function on such as operation calls the disconnect adapter if
 * the connect adapter was ever called.
 *
 * @param operation operation to signal completion or cancellation
 */
void
GNUNET_TESTBED_operation_done (struct GNUNET_TESTBED_Operation *operation);


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
 * @param subsystem limit to the specified subsystem, NULL for all subsystems
 * @param name name of the statistic value, NULL for all values
 * @param proc processing function for each statistic retrieved
 * @param cont continuation to call once call is completed.  The completion of this
 *          operation is *ONLY* signalled through this callback -- no
 *          GNUNET_TESTBED_ET_OPERATION_FINISHED is generated
 * @param cls closure to pass to proc and cont
 * @return operation handle to cancel the operation
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_get_statistics (unsigned int num_peers,
                               struct GNUNET_TESTBED_Peer **peers,
                               const char *subsystem, const char *name,
                               GNUNET_TESTBED_StatisticsIterator proc,
                               GNUNET_TESTBED_OperationCompletionCallback cont,
                               void *cls);


/**
 * Return the index of the peer inside of the total peer array,
 * aka. the peer's "unique ID".
 *
 * @param peer Peer handle.
 *
 * @return The peer's unique ID.
 */
uint32_t
GNUNET_TESTBED_get_index (const struct GNUNET_TESTBED_Peer *peer);


/**
 * Handle for testbed run helper funtions
 */
struct GNUNET_TESTBED_RunHandle;


/**
 * Signature of a main function for a testcase.
 *
 * @param cls closure
 * @param h the run handle
 * @param num_peers number of peers in 'peers'
 * @param peers handle to peers run in the testbed.  NULL upon timeout (see
 *          GNUNET_TESTBED_test_run()).
 * @param links_succeeded the number of overlay link connection attempts that
 *          succeeded
 * @param links_failed the number of overlay link connection attempts that
 *          failed
 * @see GNUNET_TESTBED_test_run()
 */
typedef void
(*GNUNET_TESTBED_TestMaster)(void *cls,
                             struct GNUNET_TESTBED_RunHandle *h,
                             unsigned int num_peers,
                             struct GNUNET_TESTBED_Peer **peers,
                             unsigned int links_succeeded,
                             unsigned int links_failed);


/**
 * Convenience method for running a testbed with
 * a single call.  Underlay and overlay topology
 * are configured using the "UNDERLAY" and "OVERLAY"
 * options in the "[testbed]" section of the configuration\
 * (with possible options given in "UNDERLAY_XXX" and/or
 * "OVERLAY_XXX").
 *
 * The test_master callback will be called once the testbed setup is finished or
 * upon a timeout.  This timeout is given through the configuration file by
 * setting the option "SETUP_TIMEOUT" in "[TESTBED]" section.
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
 * @param test_master this callback will be called once the test is ready or
 *          upon timeout
 * @param test_master_cls closure for 'test_master'.
 */
void
GNUNET_TESTBED_run (const char *host_filename,
                    const struct GNUNET_CONFIGURATION_Handle *cfg,
                    unsigned int num_peers,
                    uint64_t event_mask,
                    GNUNET_TESTBED_ControllerCallback cc,
                    void *cc_cls,
                    GNUNET_TESTBED_TestMaster test_master,
                    void *test_master_cls);


/**
 * Convenience method for running a "simple" test on the local system
 * with a single call from 'main'.  Underlay and overlay topology are
 * configured using the "UNDERLAY" and "OVERLAY" options in the
 * "[TESTBED]" section of the configuration (with possible options
 * given in "UNDERLAY_XXX" and/or "OVERLAY_XXX").
 *
 * The test_master callback will be called once the testbed setup is finished or
 * upon a timeout.  This timeout is given through the configuration file by
 * setting the option "SETUP_TIMEOUT" in "[TESTBED]" section.
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
 *        for all peer start events even if #GNUNET_TESTBED_ET_PEER_START isn't
 *        set in the event_mask as this is the only way get access to the
 *        handle of each peer
 * @param cc_cls closure for @a cc
 * @param test_master this callback will be called once the test is ready or
 *          upon timeout
 * @param test_master_cls closure for @a test_master.
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
int
GNUNET_TESTBED_test_run (const char *testname,
                         const char *cfg_filename,
                         unsigned int num_peers,
                         uint64_t event_mask,
                         GNUNET_TESTBED_ControllerCallback cc,
                         void *cc_cls,
                         GNUNET_TESTBED_TestMaster test_master,
                         void *test_master_cls);


/**
 * Obtain handle to the master controller from a testbed run.  The handle
 * returned should not be disconnected.
 *
 * @param h the testbed run handle
 * @return handle to the master controller
 */
struct GNUNET_TESTBED_Controller *
GNUNET_TESTBED_run_get_controller_handle (struct GNUNET_TESTBED_RunHandle *h);

/**
 * Opaque handle for barrier
 */
struct GNUNET_TESTBED_Barrier;


/**
 * Status of a barrier
 */
enum GNUNET_TESTBED_BarrierStatus
{
  /**
   * Barrier initialised successfully
   */
  GNUNET_TESTBED_BARRIERSTATUS_INITIALISED = 1,

  /**
   * Barrier is crossed
   */
  GNUNET_TESTBED_BARRIERSTATUS_CROSSED,

  /**
   * Error status
   */
  GNUNET_TESTBED_BARRIERSTATUS_ERROR,

};


/**
 * Functions of this type are to be given as callback argument to
 * GNUNET_TESTBED_barrier_init().  The callback will be called when status
 * information is available for the barrier.
 *
 * @param cls the closure given to GNUNET_TESTBED_barrier_init()
 * @param name the name of the barrier
 * @param barrier the barrier handle
 * @param status status of the barrier; GNUNET_OK if the barrier is crossed;
 *   GNUNET_SYSERR upon error
 * @param emsg if the status were to be GNUNET_SYSERR, this parameter has the
 *   error messsage
 */
typedef void (*GNUNET_TESTBED_barrier_status_cb) (void *cls,
                                                  const char *name,
                                                  struct GNUNET_TESTBED_Barrier
                                                  *barrier,
                                                  enum GNUNET_TESTBED_BarrierStatus status,
                                                  const char *emsg);


/**
 * Initialise a barrier and call the given callback when the required percentage
 * of peers (quorum) reach the barrier.
 *
 * @param controller the handle to the controller
 * @param name identification name of the barrier
 * @param quorum the percentage of peers that is required to reach the barrier.
 *   Peers signal reaching a barrier by calling
 *   GNUNET_TESTBED_barrier_reached().
 * @param cb the callback to call when the barrier is reached or upon error.
 *   Cannot be NULL.
 * @param cls closure for the above callback
 * @return barrier handle
 */
struct GNUNET_TESTBED_Barrier *
GNUNET_TESTBED_barrier_init (struct GNUNET_TESTBED_Controller *controller,
                             const char *name,
                             unsigned int quorum,
                             GNUNET_TESTBED_barrier_status_cb cb, void *cls);


/**
 * Cancel a barrier.
 *
 * @param barrier the barrier handle
 */
void
GNUNET_TESTBED_barrier_cancel (struct GNUNET_TESTBED_Barrier *barrier);


/**
 * Opaque handle for barrier wait
 */
struct GNUNET_TESTBED_BarrierWaitHandle;


/**
 * Functions of this type are to be given as acallback argumetn to
 * GNUNET_TESTBED_barrier_wait().  The callback will be called when the barrier
 * corresponding given in GNUNET_TESTBED_barrier_wait() is crossed or cancelled.
 *
 * @param cls closure pointer given to GNUNET_TESTBED_barrier_wait()
 * @param name the barrier name
 * @param status GNUNET_SYSERR in case of error while waiting for the barrier;
 *   GNUNET_OK if the barrier is crossed
 */
typedef void (*GNUNET_TESTBED_barrier_wait_cb) (void *cls,
                                                const char *name,
                                                int status);


/**
 * Wait for a barrier to be crossed.  This function should be called by the
 * peers which have been started by the testbed.  If the peer is not started by
 * testbed this function may return error
 *
 * @param name the name of the barrier
 * @param cb the barrier wait callback
 * @param cls the closure for the above callback
 * @return barrier wait handle which can be used to cancel the waiting at
 *   anytime before the callback is called.  NULL upon error.
 */
struct GNUNET_TESTBED_BarrierWaitHandle *
GNUNET_TESTBED_barrier_wait (const char *name,
                             GNUNET_TESTBED_barrier_wait_cb cb,
                             void *cls);


/**
 * Cancel a barrier wait handle.  Should not be called in or after the callback
 * given to GNUNET_TESTBED_barrier_wait() has been called.
 *
 * @param h the barrier wait handle
 */
void
GNUNET_TESTBED_barrier_wait_cancel (struct GNUNET_TESTBED_BarrierWaitHandle *h);


/**
 * Model for configuring underlay links of a peer
 * @ingroup underlay
 */
struct GNUNET_TESTBED_UnderlayLinkModel;


/**
 * The type of GNUNET_TESTBED_UnderlayLinkModel
 * @ingroup underlay
 */
enum GNUNET_TESTBED_UnderlayLinkModelType
{
  /**
   * The model is based on white listing of peers to which underlay connections
   * are permitted.  Underlay connections to all other peers will not be
   * permitted.
   */
  GNUNET_TESTBED_UNDERLAYLINKMODELTYPE_BLACKLIST,

  /**
   * The model is based on black listing of peers to which underlay connections
   * are not permitted.  Underlay connections to all other peers will be
   * permitted
   */
  GNUNET_TESTBED_UNDERLAYLINKMODELTYPE_WHITELIST
};


/**
 * Create a GNUNET_TESTBED_UnderlayLinkModel for the given peer.  A peer can
 * have ONLY ONE model and it can be either a blacklist or whitelist based one.
 *
 * @ingroup underlay
 * @param peer the peer for which the model has to be created
 * @param type the type of the model
 * @return the model
 */
struct GNUNET_TESTBED_UnderlayLinkModel *
GNUNET_TESTBED_underlaylinkmodel_create (struct GNUNET_TESTBED_Peer *peer,
                                         enum GNUNET_TESTBED_UnderlayLinkModelType type);


/**
 * Add a peer to the given model.  Underlay connections to the given peer will
 * be permitted if the model is whitelist based; otherwise they will not be
 * permitted.
 *
 * @ingroup underlay
 * @param model the model
 * @param peer the peer to add
 */
void
GNUNET_TESTBED_underlaylinkmodel_add_peer (struct GNUNET_TESTBED_UnderlayLinkModel *model,
                                           struct GNUNET_TESTBED_Peer *peer);


/**
 * Set the metrics for a link to the given peer in the underlay model.  The link
 * SHOULD be permittable according to the given model.
 *
 * @ingroup underlay
 * @param model the model
 * @param peer the other end peer of the link
 * @param latency latency of the link in microseconds
 * @param loss data loss of the link expressed as a percentage
 * @param bandwidth bandwidth of the link in kilobytes per second [kB/s]
 */
void
GNUNET_TESTBED_underlaylinkmodel_set_link (struct GNUNET_TESTBED_UnderlayLinkModel *model,
                                           struct GNUNET_TESTBED_Peer *peer,
                                           uint32_t latency,
                                           uint32_t loss,
                                           uint32_t bandwidth);


/**
 * Commit the model.  The model is freed in this function(!).
 *
 * @ingroup underlay
 * @param model the model to commit
 */
void
GNUNET_TESTBED_underlaylinkmodel_commit (struct GNUNET_TESTBED_UnderlayLinkModel *model);


/**
 * Free the resources of the model.  Use this function only if the model has not
 * be committed and has to be unallocated.  The peer can then have another model
 * created.
 *
 * @ingroup underlay
 * @param model the model to unallocate
 */
void
GNUNET_TESTBED_underlaylinkmodel_free (struct GNUNET_TESTBED_UnderlayLinkModel *model);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif


#ifdef __cplusplus
}
#endif

#endif
