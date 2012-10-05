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
 * Testbed operation structure
 */
struct GNUNET_TESTBED_Operation
{
  /**
   * next pointer for DLL
   */
  struct GNUNET_TESTBED_Operation *next;

  /**
   * prev pointer for DLL
   */
  struct GNUNET_TESTBED_Operation *prev;

  /**
   * The controller on which this operation operates
   */
  struct GNUNET_TESTBED_Controller *controller;

  /**
   * The ID for the operation;
   */
  uint64_t operation_id;

  /**
   * The type of operation
   */
  enum OperationType type;

  /**
   * Data specific to OperationType
   */
  void *data;
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
   * The operation id counter. use current value and increment
   */
  uint64_t operation_counter;

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
 * Creates a helper initialization message. Only for testing.
 *
 * @param cname the ip address of the controlling host
 * @param hostname the hostname of the destination this message is intended for
 * @param cfg the configuration that has to used to start the testbed service
 *          thru helper
 * @return the initialization message
 */
struct GNUNET_TESTBED_HelperInit *
GNUNET_TESTBED_create_helper_init_msg_ (const char *cname,
					const char *hostname,
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

#endif
/* end of testbed_api.h */
