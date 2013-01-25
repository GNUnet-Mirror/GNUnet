/*
      This file is part of GNUnet
      (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file testbed/testbed_api.h
 * @brief Interface for functions internally exported from testbed_api.c
 * @author Sree Harsha Totakura
 */

#ifndef TESTBED_API_H
#define TESTBED_API_H

#include "gnunet_testbed_service.h"
#include "testbed.h"


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
  OP_GET_SLAVE_CONFIG
};


/**
 * The message queue for sending messages to the controller service
 */
struct MessageQueue;

/**
 * Structure for a controller link
 */
struct ControllerLink;


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
   * next ptr for DLL
   */
  struct OperationContext *next;

  /**
   * prev ptr for DLL
   */
  struct OperationContext *prev;

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
 * Opaque handle for SD calculations
 */
struct SDHandle;


/**
 * A slot to record time taken by an overlay connect operation
 */
struct TimeSlot
{
  /**
   * A key to identify this timeslot
   */
  void *key;

  /**
   * Time
   */
  struct GNUNET_TIME_Relative time;

  /**
   * Number of timing values accumulated
   */
  unsigned int nvals;
};


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
   * The client connection handle to the controller service
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * The head of the message queue
   */
  struct MessageQueue *mq_head;

  /**
   * The tail of the message queue
   */
  struct MessageQueue *mq_tail;

  /**
   * The head of the ControllerLink list
   */
  struct ControllerLink *cl_head;

  /**
   * The tail of the ControllerLink list
   */
  struct ControllerLink *cl_tail;

  /**
   * The client transmit handle
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * The host registration handle; NULL if no current registration requests are
   * present
   */
  struct GNUNET_TESTBED_HostRegistrationHandle *rh;

  /**
   * The head of the opeartion context queue
   */
  struct OperationContext *ocq_head;

  /**
   * The tail of the operation context queue
   */
  struct OperationContext *ocq_tail;

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
   * Operation queue for simultaneous overlay connect operations
   */
  struct OperationQueue *opq_parallel_overlay_connect_operations;

  /**
   * An array of timing slots; size should be equal to the current number of parallel
   * overlay connects
   */
  struct TimeSlot *tslots;

  /**
   * Handle for SD calculations amount parallel overlay connect operation finish
   * times
   */
  struct SDHandle *poc_sd;

  /**
   * The controller event mask
   */
  uint64_t event_mask;

  /**
   * Did we start the receive loop yet?
   */
  int in_receive;

  /**
   * Did we create the host for this?
   */
  int aux_host;

  /**
   * The number of parallel overlay connects we do currently
   */
  unsigned int num_parallel_connects;

  /**
   * Counter to indicate when all the available time slots are filled
   */
  unsigned int tslots_filled;

  /**
   * The operation id counter. use current value and increment
   */
  uint32_t operation_counter;

};


/**
 * Queues a message in send queue for sending to the service
 *
 * @param controller the handle to the controller
 * @param msg the message to queue
 */
void
GNUNET_TESTBED_queue_message_ (struct GNUNET_TESTBED_Controller *controller,
                               struct GNUNET_MessageHeader *msg);


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
GNUNET_TESTBED_compress_config_ (const char *config, size_t size,
                                 char **xconfig);


/**
 * Adds an operation to the queue of operations
 *
 * @param op the operation to add
 */
void
GNUNET_TESTBED_operation_add_ (struct GNUNET_TESTBED_Operation *op);


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
GNUNET_TESTBED_create_helper_init_msg_ (const char *cname, const char *hostname,
                                        const struct GNUNET_CONFIGURATION_Handle
                                        *cfg);


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
GNUNET_TESTBED_forward_operation_msg_ (struct GNUNET_TESTBED_Controller
                                       *controller, uint64_t operation_id,
                                       const struct GNUNET_MessageHeader *msg,
                                       GNUNET_CLIENT_MessageHandler cc,
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
 * GNUNET_MESSAGE_TYPE_TESTBED_PEERCONFIG,
 * GNUNET_MESSAGE_TYPE_TESTBED_SLAVECONFIG
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
GNUNET_TESTBED_parse_error_string_ (const struct
                                    GNUNET_TESTBED_OperationFailureEventMessage
                                    *msg);


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
 * Same as the GNUNET_TESTBED_controller_link_2, but with ids for delegated host
 * and slave host
 *
 * @param op_cls the operation closure for the event which is generated to
 *          signal success or failure of this operation
 * @param master handle to the master controller who creates the association
 * @param delegated_host_id id of the host to which requests should be delegated
 * @param slave_host_id id of the host which is used to run the slave controller
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
GNUNET_TESTBED_controller_link_2_ (void *op_cls,
                                   struct GNUNET_TESTBED_Controller *master,
                                   uint32_t delegated_host_id,
                                   uint32_t slave_host_id, const char *sxcfg,
                                   size_t sxcfg_size, size_t scfg_size,
                                   int is_subordinate);


/**
 * Same as the GNUNET_TESTBED_controller_link, but with ids for delegated host
 * and slave host
 *
 * @param op_cls the operation closure for the event which is generated to
 *          signal success or failure of this operation
 * @param master handle to the master controller who creates the association
 * @param delegated_host_id id of the host to which requests should be
 *          delegated; cannot be NULL
 * @param slave_host_id id of the host which should connect to controller
 *          running on delegated host ; use NULL to make the master controller
 *          connect to the delegated host
 * @param slave_cfg configuration to use for the slave controller
 * @param is_subordinate GNUNET_YES if the controller at delegated_host should
 *          be started by the slave controller; GNUNET_NO if the slave
 *          controller has to connect to the already started delegated
 *          controller via TCP/IP
 * @return the operation handle
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_controller_link_ (void *op_cls,
                                 struct GNUNET_TESTBED_Controller *master,
                                 uint32_t delegated_host_id,
                                 uint32_t slave_host_id,
                                 const struct GNUNET_CONFIGURATION_Handle
                                 *slave_cfg, int is_subordinate);


/**
 * Returns a timing slot which will be exclusively locked
 *
 * @param c the controller handle
 * @param key a pointer which is associated to the returned slot; should not be
 *          NULL. It serves as a key to determine the correct owner of the slot
 * @return the time slot index in the array of time slots in the controller
 *           handle
 */
unsigned int
GNUNET_TESTBED_get_tslot_ (struct GNUNET_TESTBED_Controller *c, void *key);


/**
 * Function to update a time slot
 *
 * @param c the controller handle
 * @param index the index of the time slot to update
 * @param key the key to identify ownership of the slot
 * @param time the new time
 * @param failed should this reading be treated as coming from a fail event
 */
void
GNUNET_TESTBED_update_time_slot_ (struct GNUNET_TESTBED_Controller *c,
                                  unsigned int index, void *key,
                                  struct GNUNET_TIME_Relative time, int failed);


/**
 * Releases a time slot thus making it available for be used again
 *
 * @param c the controller handle
 * @param index the index of the the time slot
 * @param key the key to prove ownership of the timeslot
 * @return GNUNET_YES if the time slot is successfully removed; GNUNET_NO if the
 *           time slot cannot be removed - this could be because of the index
 *           greater than existing number of time slots or `key' being different
 */
int
GNUNET_TESTBED_release_time_slot_ (struct GNUNET_TESTBED_Controller *c,
                                   unsigned int index, void *key);




#endif
/* end of testbed_api.h */
