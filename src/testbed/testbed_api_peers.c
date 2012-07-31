/*
      This file is part of GNUnet
      (C) 2008--2012 Christian Grothoff (and other contributing authors)

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
 * @file testbed/testbed_api_peers.c
 * @brief management of the knowledge about peers in this library
 *        (we know the peer ID, its host, pending operations, etc.)
 * @author Christian Grothoff
 */
#include "platform.h"
#include "testbed_api_peers.h"
#include "testbed_api.h"
#include "testbed.h"
#include "testbed_api_hosts.h"
#include "testbed_api_operations.h"

/**
 * Function to call to start a peer_create type operation once all
 * queues the operation is part of declare that the
 * operation can be activated.
 *
 * @param cls the closure from GNUNET_TESTBED_operation_create_()
 */
static void 
opstart_peer_create (void *cls)
{
  struct OperationContext *opc = cls;
  struct PeerCreateData *data;
  struct GNUNET_TESTBED_PeerCreateMessage *msg;
  char *config;
  char *xconfig;
  size_t c_size;
  size_t xc_size;
  uint16_t msize;

  GNUNET_assert (OP_PEER_CREATE == opc->type);  
  data = opc->data;
  GNUNET_assert (NULL != data);
  GNUNET_assert (NULL != data->peer);
  config = GNUNET_CONFIGURATION_serialize (data->cfg, &c_size);
  xc_size = GNUNET_TESTBED_compress_config_ (config, c_size, &xconfig);
  GNUNET_free (config);
  msize = xc_size + sizeof (struct GNUNET_TESTBED_PeerCreateMessage);
  msg = GNUNET_realloc (xconfig, msize);
  memmove (&msg[1], msg, xc_size);
  msg->header.size = htons (msize);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_CREATEPEER);
  msg->operation_id = GNUNET_htonll (opc->id);
  msg->host_id = htonl (GNUNET_TESTBED_host_get_id_ (data->peer->host));
  msg->peer_id = htonl (data->peer->unique_id);
  msg->config_size = htonl (c_size);
  GNUNET_CONTAINER_DLL_insert_tail (opc->c->ocq_head,
                                    opc->c->ocq_tail, opc);
  GNUNET_TESTBED_queue_message_ (opc->c,
				 (struct GNUNET_MessageHeader *) msg);
};


/**
 * Callback which will be called when peer_create type operation is released
 *
 * @param cls the closure from GNUNET_TESTBED_operation_create_()
 */
static void 
oprelease_peer_create (void *cls)
{
  struct OperationContext *opc = cls;  

  GNUNET_assert (NULL != opc->data);
  GNUNET_free (opc->data);  
  GNUNET_CONTAINER_DLL_remove (opc->c->ocq_head, opc->c->ocq_tail, opc);
  GNUNET_free (opc);
}


/**
 * Lookup a peer by ID.
 * 
 * @param id global peer ID assigned to the peer
 * @return handle to the host, NULL on error
 */
struct GNUNET_TESTBED_Peer *
GNUNET_TESTBED_peer_lookup_by_id_ (uint32_t id)
{
  GNUNET_break (0);
  return NULL;
}


/**
 * Create the given peer at the specified host using the given
 * controller.  If the given controller is not running on the target
 * host, it should find or create a controller at the target host and
 * delegate creating the peer.  Explicit delegation paths can be setup
 * using 'GNUNET_TESTBED_controller_link'.  If no explicit delegation
 * path exists, a direct link with a subordinate controller is setup
 * for the first delegated peer to a particular host; the subordinate
 * controller is then destroyed once the last peer that was delegated
 * to the remote host is stopped.  This function is used in particular
 * if some other controller has already assigned a unique ID to the
 * peer.
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
 * @param unique_id unique ID for this peer
 * @param controller controller process to use
 * @param host host to run the peer on
 * @param cfg Template configuration to use for the peer. Should exist until
 *          operation is cancelled or GNUNET_TESTBED_operation_done() is called
 * @param cb the callback to call when the peer has been created
 * @param cls the closure to the above callback
 * @return the operation handle
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_peer_create_with_id_ (uint32_t unique_id,
				     struct GNUNET_TESTBED_Controller *controller,
				     struct GNUNET_TESTBED_Host *host,
				     const struct GNUNET_CONFIGURATION_Handle *cfg,
				     GNUNET_TESTBED_PeerCreateCallback cb,
				     void *cls)
{
  struct GNUNET_TESTBED_Peer *peer;
  struct PeerCreateData *data;
  struct OperationContext *opc;

  peer = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_Peer));
  peer->controller = controller;
  peer->host = host;
  peer->unique_id = unique_id;
  peer->state = PS_INVALID;
  data = GNUNET_malloc (sizeof (struct PeerCreateData));
  data->host = host;
  data->cfg = cfg;
  data->cb = cb;
  data->cls = cls;
  data->peer = peer;
  opc = GNUNET_malloc (sizeof (struct OperationContext));
  opc->c = controller;
  opc->data = data;
  opc->id = controller->operation_counter++;
  opc->type = OP_PEER_CREATE;
  opc->op = GNUNET_TESTBED_operation_create_ (opc, &opstart_peer_create,
                                              &oprelease_peer_create);
  GNUNET_TESTBED_operation_queue_insert_ (controller->opq_peer_create, opc->op);
  return opc->op;
}


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
			    void *cls)
{
  static uint32_t id_gen;

  return GNUNET_TESTBED_peer_create_with_id_ (++id_gen,
					      controller,
					      host,
					      cfg,
					      cb, cls);
}


/**
 * Start the given peer.
 *
 * @param peer peer to start
 * @return handle to the operation
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_peer_start (struct GNUNET_TESTBED_Peer *peer)
{
  struct GNUNET_TESTBED_Operation *op;
  struct GNUNET_TESTBED_PeerStartMessage *msg;

  GNUNET_assert ((PS_CREATED == peer->state) || (PS_STOPPED == peer->state));
  op = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_Operation));
  op->operation_id = peer->controller->operation_counter++;
  op->controller = peer->controller;
  op->type = OP_PEER_START;
  op->data = peer;
  msg = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_PeerStartMessage));
  msg->header.size = htons (sizeof (struct GNUNET_TESTBED_PeerStartMessage));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_STARTPEER);
  msg->peer_id = htonl (peer->unique_id);
  msg->operation_id = GNUNET_htonll (op->operation_id);
  GNUNET_CONTAINER_DLL_insert_tail (peer->controller->op_head,
                                    peer->controller->op_tail, op);
  GNUNET_TESTBED_queue_message_ (peer->controller, &msg->header);
  return op;
}


/**
 * Stop the given peer.  The handle remains valid (use
 * "GNUNET_TESTBED_peer_destroy" to fully clean up the 
 * state of the peer).
 *
 * @param peer peer to stop
 * @return handle to the operation
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_peer_stop (struct GNUNET_TESTBED_Peer *peer)
{
  struct GNUNET_TESTBED_Operation *op;
  struct GNUNET_TESTBED_PeerStopMessage *msg;

  GNUNET_assert (PS_STARTED == peer->state);
  op = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_Operation));
  op->operation_id = peer->controller->operation_counter++;
  op->controller = peer->controller;
  op->type = OP_PEER_STOP;
  op->data = peer;
  msg = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_PeerStopMessage));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_STOPPEER);
  msg->header.size = htons (sizeof (struct GNUNET_TESTBED_PeerStopMessage));
  msg->peer_id = htonl (peer->unique_id);
  msg->operation_id = GNUNET_htonll (op->operation_id);
  GNUNET_CONTAINER_DLL_insert_tail (peer->controller->op_head,
                                    peer->controller->op_tail, op);
  GNUNET_TESTBED_queue_message_ (peer->controller, &msg->header);
  return op;
}


/**
 * Request information about a peer.
 *
 * @param peer peer to request information about
 * @param pit desired information
 * @return handle to the operation
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_peer_get_information (struct GNUNET_TESTBED_Peer *peer,
				     enum GNUNET_TESTBED_PeerInformationType pit)
{
  struct GNUNET_TESTBED_PeerGetConfigurationMessage *msg;
  struct GNUNET_TESTBED_Operation *op;
  struct PeerInfoData *data;
  
  GNUNET_assert (GNUNET_TESTBED_PIT_GENERIC != pit);
  data = GNUNET_malloc (sizeof (struct PeerInfoData));
  data->peer = peer;
  data->pit = pit;
  op = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_Operation));
  op->type = OP_PEER_INFO;
  op->operation_id = peer->controller->operation_counter++;
  op->controller = peer->controller;
  op->data = data;
  msg = GNUNET_malloc (sizeof (struct
                               GNUNET_TESTBED_PeerGetConfigurationMessage));
  msg->header.size = htons
    (sizeof (struct GNUNET_TESTBED_PeerGetConfigurationMessage));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_GETPEERCONFIG);
  msg->peer_id = htonl (peer->unique_id);
  msg->operation_id = GNUNET_htonll (op->operation_id);
  GNUNET_CONTAINER_DLL_insert_tail (peer->controller->op_head,
                                    peer->controller->op_tail, op);
  GNUNET_TESTBED_queue_message_ (peer->controller, &msg->header);
  return op;
}


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
					  const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  // FIXME: handle locally or delegate...
  GNUNET_break (0);
  return NULL;
}


/**
 * Destroy the given peer; the peer should have been
 * stopped first (if it was started).
 *
 * @param peer peer to stop
 * @return handle to the operation
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_peer_destroy (struct GNUNET_TESTBED_Peer *peer)
{
  struct GNUNET_TESTBED_Operation *op;
  struct PeerDestroyData *data;
  struct GNUNET_TESTBED_PeerDestroyMessage *msg;
  
  data = GNUNET_malloc (sizeof (struct PeerDestroyData));
  data->peer = peer;
  op = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_Operation));
  op->operation_id = peer->controller->operation_counter++;
  op->controller = peer->controller;
  op->type = OP_PEER_DESTROY;
  op->data = data;
  msg = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_PeerDestroyMessage));
  msg->header.size = htons (sizeof (struct GNUNET_TESTBED_PeerDestroyMessage));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_DESTROYPEER);
  msg->peer_id = htonl (peer->unique_id);
  msg->operation_id = GNUNET_htonll (op->operation_id);
  GNUNET_CONTAINER_DLL_insert_tail (peer->controller->op_head,
                                    peer->controller->op_tail, op);
  GNUNET_TESTBED_queue_message_ (peer->controller, 
				 (struct GNUNET_MessageHeader *) msg);
  return op;
}


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
					enum GNUNET_TESTBED_ConnectOption co, ...)
{
  GNUNET_break (0);
  return NULL;
}



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
				struct GNUNET_TESTBED_Peer *p2)
{
  struct GNUNET_TESTBED_Operation *op;
  struct OverlayConnectData *data;
  struct GNUNET_TESTBED_OverlayConnectMessage *msg;
  
  GNUNET_assert ((PS_STARTED == p1->state) && (PS_STARTED == p2->state));
  GNUNET_assert (p1->controller == p2->controller);
  data = GNUNET_malloc (sizeof (struct OverlayConnectData));
  data->p1 = p1;
  data->p2 = p2;  
  op = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_Operation)); 
  op->controller = p1->controller;
  op->operation_id = op->controller->operation_counter++;
  op->type = OP_OVERLAY_CONNECT;
  op->data = data;
  msg = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_OverlayConnectMessage));
  msg->header.size = htons (sizeof (struct
				    GNUNET_TESTBED_OverlayConnectMessage));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_OLCONNECT);
  msg->peer1 = htonl (p1->unique_id);
  msg->peer2 = htonl (p2->unique_id);
  msg->operation_id = GNUNET_htonll (op->operation_id);
  GNUNET_CONTAINER_DLL_insert_tail (op->controller->op_head,
                                    op->controller->op_tail, op);
  GNUNET_TESTBED_queue_message_ (op->controller, 
				 (struct GNUNET_MessageHeader *) msg);
  return NULL;
}



/* end of testbed_api_peers.c */
