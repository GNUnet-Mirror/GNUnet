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
   * Is this operation completed? (has there been a reply from the service)
   */
  int completed;

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
   * The head of the operation queue (FIXME: Remove, use ocq)
   */
  struct GNUNET_TESTBED_Operation *op_head;
  
  /**
   * The tail of the operation queue (FIXME: Remove, use ocq)
   */
  struct GNUNET_TESTBED_Operation *op_tail;

  /**
   * The head of the opeartion context queue
   */
  struct OperationContext *ocq_head;

  /**
   * The tail of the operation context queue
   */
  struct OperationContext *ocq_tail;

  /**
   * Operation queue for simultaneous peer creations
   */
  struct OperationQueue *opq_peer_create;

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
 * @param cfg the configuration that has to used to start the testbed service
 *          thru helper
 * @return the initialization message
 */
struct GNUNET_TESTBED_HelperInit *
GNUNET_TESTBED_create_helper_init_msg_ (const char *cname,
					const struct GNUNET_CONFIGURATION_Handle *cfg);

#endif
