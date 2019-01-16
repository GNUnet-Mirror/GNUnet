/*
      This file is part of GNUnet
      Copyright (C) 2008--2013 GNUnet e.V.

      GNUnet is free software: you can redistribute it and/or modify it
      under the terms of the GNU Affero General Public License as published
      by the Free Software Foundation, either version 3 of the License,
      or (at your option) any later version.

      GNUnet is distributed in the hope that it will be useful, but
      WITHOUT ANY WARRANTY; without even the implied warranty of
      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
      Affero General Public License for more details.
     
      You should have received a copy of the GNU Affero General Public License
      along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file testbed/testbed_api.h
 * @brief Interface for functions internally exported from testbed_api.c
 * @author Sree Harsha Totakura
 */

#ifndef TESTBED_API_H
#define TESTBED_API_H

#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"
#include "testbed.h"
#include "testbed_helper.h"

/**
 * Testbed Helper binary name
 */
#define HELPER_TESTBED_BINARY "gnunet-helper-testbed"


/**
 * Enumeration of operations
 */
enum OperationType
{
    /**
     * Peer create operation
     */
  OP_PEER_CREATE,

    /**
     * Peer start operation
     */
  OP_PEER_START,

    /**
     * Peer stop operation
     */
  OP_PEER_STOP,

    /**
     * Peer destroy operation
     */
  OP_PEER_DESTROY,

    /**
     * Get peer information operation
     */
  OP_PEER_INFO,

  /**
   * Reconfigure a peer
   */
  OP_PEER_RECONFIGURE,

    /**
     * Overlay connection operation
     */
  OP_OVERLAY_CONNECT,

    /**
     * Forwarded operation
     */
  OP_FORWARDED,

    /**
     * Link controllers operation
     */
  OP_LINK_CONTROLLERS,

  /**
   * Get slave config operation
   */
  OP_GET_SLAVE_CONFIG,

  /**
   * Stop and destroy all peers
   */
  OP_SHUTDOWN_PEERS,

  /**
   * Start/stop service at a peer
   */
  OP_MANAGE_SERVICE
};



/**
 * Enumeration of states of OperationContext
 */
enum OperationContextState
{
  /**
   * The initial state where the associated operation has just been created
   * and is waiting in the operation queues to be started
   */
  OPC_STATE_INIT = 0,

  /**
   * The operation has been started. It may occupy some resources which are to
   * be freed if cancelled.
   */
  OPC_STATE_STARTED,

  /**
   * The operation has finished. The end results of this operation may occupy
   * some resources which are to be freed by operation_done
   */
  OPC_STATE_FINISHED
};


/**
 * Context information for GNUNET_TESTBED_Operation
 */
struct OperationContext
{
  /**
   * The controller to which this operation context belongs to
   */
  struct GNUNET_TESTBED_Controller *c;

  /**
   * The operation
   */
  struct GNUNET_TESTBED_Operation *op;

  /**
   * The operation closure
   */
  void *op_cls;

  /**
   * Data relevant to the operation
   */
  void *data;

  /**
   * The id of the opearation
   */
  uint64_t id;

  /**
   * The type of operation
   */
  enum OperationType type;

  /**
   * The state of the operation
   */
  enum OperationContextState state;
};


/**
 * Operation empty callback
 *
 * @param cls closure
 */
typedef void
(*TESTBED_opcq_empty_cb) (void *cls);


/**
 * Handle to interact with a GNUnet testbed controller.  Each
 * controller has at least one master handle which is created when the
 * controller is created; this master handle interacts with the
 * controller process, destroying it destroys the controller (by
 * closing stdin of the controller process).  Additionally,
 * controllers can interact with each other (in a P2P fashion); those
 * links are established via TCP/IP on the controller's service port.
 */
struct GNUNET_TESTBED_Controller
{
  /**
   * The host where the controller is running
   */
  struct GNUNET_TESTBED_Host *host;

  /**
   * The controller callback
   */
  GNUNET_TESTBED_ControllerCallback cc;

  /**
   * The closure for controller callback
   */
  void *cc_cls;

  /**
   * The configuration to use while connecting to controller
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * The message queue to the controller service
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * The host registration handle; NULL if no current registration requests are
   * present
   */
  struct GNUNET_TESTBED_HostRegistrationHandle *rh;

  /**
   * The map of active operation contexts
   */
  struct GNUNET_CONTAINER_MultiHashMap32 *opc_map;

  /**
   * If this callback is not NULL, schedule it as a task when opc_map gets empty
   */
  TESTBED_opcq_empty_cb opcq_empty_cb;

  /**
   * Closure for the above task
   */
  void *opcq_empty_cls;

  /**
   * Operation queue for simultaneous operations
   */
  struct OperationQueue *opq_parallel_operations;

  /**
   * Operation queue for simultaneous service connections
   */
  struct OperationQueue *opq_parallel_service_connections;

  /**
   * Operation queue for simultaneous topology configuration operations
   */
  struct OperationQueue *opq_parallel_topology_config_operations;

  /**
   * handle for hashtable of barrier handles, values are
   * of type `struct GNUNET_TESTBED_Barrier`.
   */
  struct GNUNET_CONTAINER_MultiHashMap *barrier_map;

  /**
   * The controller event mask
   */
  uint64_t event_mask;

  /**
   * The operation id counter. use current value and increment
   */
  uint32_t operation_counter;

};


/**
 * Handle for barrier
 */
struct GNUNET_TESTBED_Barrier
{
  /**
   * hashcode identifying this barrier in the hashmap
   */
  struct GNUNET_HashCode key;

  /**
   * The controller handle given while initiliasing this barrier
   */
  struct GNUNET_TESTBED_Controller *c;

  /**
   * The name of the barrier
   */
  char *name;

  /**
   * The continuation callback to call when we have a status update on this
   */
  GNUNET_TESTBED_barrier_status_cb cb;

  /**
   * the closure for the above callback
   */
  void *cls;

  /**
   * Should the barrier crossed status message be echoed back to the controller?
   */
  int echo;
};



/**
 * Queues a message in send queue for sending to the service
 *
 * @param controller the handle to the controller
 * @param msg the message to queue
 * @deprecated
 */
void
GNUNET_TESTBED_queue_message_ (struct GNUNET_TESTBED_Controller *controller,
                               struct GNUNET_MessageHeader *msg);


/**
 * Inserts the given operation context into the operation context map of the
 * given controller.  Creates the operation context map if one does not exist
 * for the controller
 *
 * @param c the controller
 * @param opc the operation context to be inserted
 */
void
GNUNET_TESTBED_insert_opc_ (struct GNUNET_TESTBED_Controller *c,
                            struct OperationContext *opc);


/**
 * Removes the given operation context from the operation context map of the
 * given controller
 *
 * @param c the controller
 * @param opc the operation context to remove
 */
void
GNUNET_TESTBED_remove_opc_ (const struct GNUNET_TESTBED_Controller *c,
                            struct OperationContext *opc);


/**
 * Compresses given configuration using zlib compress
 *
 * @param config the serialized configuration
 * @param size the size of config
 * @param xconfig will be set to the compressed configuration (memory is fresly
 *          allocated)
 * @return the size of the xconfig
 */
size_t
GNUNET_TESTBED_compress_config_ (const char *config,
                                 size_t size,
                                 char **xconfig);


/**
 * Function to serialize and compress using zlib a configuration through a
 * configuration handle
 *
 * @param cfg the configuration
 * @param size the size of configuration when serialize.  Will be set on success.
 * @param xsize the sizeo of the compressed configuration.  Will be set on success.
 * @return the serialized and compressed configuration
 */
char *
GNUNET_TESTBED_compress_cfg_ (const struct GNUNET_CONFIGURATION_Handle *cfg,
                              size_t *size,
                              size_t *xsize);


/**
 * Creates a helper initialization message. This function is here because we
 * want to use this in testing
 *
 * @param trusted_ip the ip address of the controller which will be set as TRUSTED
 *          HOST(all connections form this ip are permitted by the testbed) when
 *          starting testbed controller at host. This can either be a single ip
 *          address or a network address in CIDR notation.
 * @param hostname the hostname of the destination this message is intended for
 * @param cfg the configuration that has to used to start the testbed service
 *          thru helper
 * @return the initialization message
 */
struct GNUNET_TESTBED_HelperInit *
GNUNET_TESTBED_create_helper_init_msg_ (const char *cname,
                                        const char *hostname,
                                        const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Sends the given message as an operation. The given callback is called when a
 * reply for the operation is available.  Call
 * GNUNET_TESTBED_forward_operation_msg_cancel_() to cleanup the returned
 * operation context if the cc hasn't been called
 *
 * @param controller the controller to which the message has to be sent
 * @param operation_id the operation id of the message
 * @param msg the message to send
 * @param cc the callback to call when reply is available
 * @param cc_cls the closure for the above callback
 * @return the operation context which can be used to cancel the forwarded
 *           operation
 */
struct OperationContext *
GNUNET_TESTBED_forward_operation_msg_ (struct GNUNET_TESTBED_Controller *controller,
                                       uint64_t operation_id,
                                       const struct GNUNET_MessageHeader *msg,
                                       GNUNET_MQ_MessageCallback cc,
                                       void *cc_cls);

/**
 * Function to cancel an operation created by simply forwarding an operation
 * message.
 *
 * @param opc the operation context from GNUNET_TESTBED_forward_operation_msg_()
 */
void
GNUNET_TESTBED_forward_operation_msg_cancel_ (struct OperationContext *opc);


/**
 * Generates configuration by uncompressing configuration in given message. The
 * given message should be of the following types:
 * #GNUNET_MESSAGE_TYPE_TESTBED_PEERCONFIG,
 * #GNUNET_MESSAGE_TYPE_TESTBED_SLAVECONFIG
 *
 * @param msg the message containing compressed configuration
 * @return handle to the parsed configuration
 */
struct GNUNET_CONFIGURATION_Handle *
GNUNET_TESTBED_extract_config_ (const struct GNUNET_MessageHeader *msg);


/**
 * Checks the integrity of the OpeationFailureEventMessage and if good returns
 * the error message it contains.
 *
 * @param msg the OperationFailureEventMessage
 * @return the error message
 */
const char *
GNUNET_TESTBED_parse_error_string_ (const struct GNUNET_TESTBED_OperationFailureEventMessage *msg);


/**
 * Function to return the operation id for a controller. The operation id is
 * created from the controllers host id and its internal operation counter.
 *
 * @param controller the handle to the controller whose operation id has to be incremented
 * @return the incremented operation id.
 */
uint64_t
GNUNET_TESTBED_get_next_op_id (struct GNUNET_TESTBED_Controller *controller);


/**
 * Like GNUNET_TESTBED_get_slave_config(), however without the host registration
 * check. Another difference is that this function takes the id of the slave
 * host.
 *
 * @param op_cls the closure for the operation
 * @param master the handle to master controller
 * @param slave_host_id id of the host where the slave controller is running to
 *          the slave_host should remain valid until this operation is cancelled
 *          or marked as finished
 * @return the operation handle;
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_get_slave_config_ (void *op_cls,
                                  struct GNUNET_TESTBED_Controller *master,
                                  uint32_t slave_host_id);



/**
 * Initialise a barrier and call the given callback when the required percentage
 * of peers (quorum) reach the barrier OR upon error.
 *
 * @param controller the handle to the controller
 * @param name identification name of the barrier
 * @param quorum the percentage of peers that is required to reach the barrier.
 *   Peers signal reaching a barrier by calling
 *   GNUNET_TESTBED_barrier_reached().
 * @param cb the callback to call when the barrier is reached or upon error.
 *   Cannot be NULL.
 * @param cls closure for the above callback
 * @param echo #GNUNET_YES to echo the barrier crossed status message back to the
 *   controller
 * @return barrier handle; NULL upon error
 */
struct GNUNET_TESTBED_Barrier *
GNUNET_TESTBED_barrier_init_ (struct GNUNET_TESTBED_Controller *controller,
                              const char *name,
                              unsigned int quorum,
                              GNUNET_TESTBED_barrier_status_cb cb,
                              void *cls,
                              int echo);


/**
 * Remove a barrier and it was the last one in the barrier hash map, destroy the
 * hash map
 *
 * @param barrier the barrier to remove
 */
void
GNUNET_TESTBED_barrier_remove_ (struct GNUNET_TESTBED_Barrier *barrier);



#endif
/* end of testbed_api.h */
