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
 * @author Sree Harsha Totakura
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
  opc->state = OPC_STATE_STARTED;
  config = GNUNET_CONFIGURATION_serialize (data->cfg, &c_size);
  xc_size = GNUNET_TESTBED_compress_config_ (config, c_size, &xconfig);
  GNUNET_free (config);
  msize = xc_size + sizeof (struct GNUNET_TESTBED_PeerCreateMessage);
  msg = GNUNET_realloc (xconfig, msize);
  memmove (&msg[1], msg, xc_size);
  msg->header.size = htons (msize);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_CREATE_PEER);
  msg->operation_id = GNUNET_htonll (opc->id);
  msg->host_id = htonl (GNUNET_TESTBED_host_get_id_ (data->peer->host));
  msg->peer_id = htonl (data->peer->unique_id);
  msg->config_size = htonl (c_size);
  GNUNET_CONTAINER_DLL_insert_tail (opc->c->ocq_head, opc->c->ocq_tail, opc);
  GNUNET_TESTBED_queue_message_ (opc->c, &msg->header);
}


/**
 * Callback which will be called when peer_create type operation is released
 *
 * @param cls the closure from GNUNET_TESTBED_operation_create_()
 */
static void
oprelease_peer_create (void *cls)
{
  struct OperationContext *opc = cls;

  switch (opc->state)
  {
  case OPC_STATE_STARTED:
    GNUNET_CONTAINER_DLL_remove (opc->c->ocq_head, opc->c->ocq_tail, opc);
    /* No break we continue flow */
  case OPC_STATE_INIT:
    GNUNET_free (((struct PeerCreateData *) opc->data)->peer);
    GNUNET_free (opc->data);
    break;
  case OPC_STATE_FINISHED:
    break;
  }
  GNUNET_free (opc);
}


/**
 * Function called when a peer destroy operation is ready
 *
 * @param cls the closure from GNUNET_TESTBED_operation_create_()
 */
static void
opstart_peer_destroy (void *cls)
{
  struct OperationContext *opc = cls;
  struct GNUNET_TESTBED_Peer *peer;
  struct GNUNET_TESTBED_PeerDestroyMessage *msg;

  GNUNET_assert (OP_PEER_DESTROY == opc->type);
  peer = opc->data;
  GNUNET_assert (NULL != peer);
  opc->state = OPC_STATE_STARTED;
  msg = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_PeerDestroyMessage));
  msg->header.size = htons (sizeof (struct GNUNET_TESTBED_PeerDestroyMessage));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_DESTROY_PEER);
  msg->peer_id = htonl (peer->unique_id);
  msg->operation_id = GNUNET_htonll (opc->id);
  GNUNET_CONTAINER_DLL_insert_tail (opc->c->ocq_head, opc->c->ocq_tail, opc);
  GNUNET_TESTBED_queue_message_ (peer->controller, &msg->header);
}


/**
 * Callback which will be called when peer_create type operation is released
 *
 * @param cls the closure from GNUNET_TESTBED_operation_create_()
 */
static void
oprelease_peer_destroy (void *cls)
{
  struct OperationContext *opc = cls;

  if (OPC_STATE_FINISHED != opc->state)
    GNUNET_CONTAINER_DLL_remove (opc->c->ocq_head, opc->c->ocq_tail, opc);
  GNUNET_free (opc);
}


/**
 * Function called when a peer start operation is ready
 *
 * @param cls the closure from GNUNET_TESTBED_operation_create_()
 */
static void
opstart_peer_start (void *cls)
{
  struct OperationContext *opc = cls;
  struct GNUNET_TESTBED_PeerStartMessage *msg;
  struct PeerEventData *data;
  struct GNUNET_TESTBED_Peer *peer;

  GNUNET_assert (OP_PEER_START == opc->type);
  GNUNET_assert (NULL != opc->data);
  data = opc->data;
  GNUNET_assert (NULL != data->peer);
  peer = data->peer;
  GNUNET_assert ((PS_CREATED == peer->state) || (PS_STOPPED == peer->state));
  opc->state = OPC_STATE_STARTED;
  msg = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_PeerStartMessage));
  msg->header.size = htons (sizeof (struct GNUNET_TESTBED_PeerStartMessage));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_START_PEER);
  msg->peer_id = htonl (peer->unique_id);
  msg->operation_id = GNUNET_htonll (opc->id);
  GNUNET_CONTAINER_DLL_insert_tail (opc->c->ocq_head, opc->c->ocq_tail, opc);
  GNUNET_TESTBED_queue_message_ (peer->controller, &msg->header);
}


/**
 * Callback which will be called when peer start type operation is released
 *
 * @param cls the closure from GNUNET_TESTBED_operation_create_()
 */
static void
oprelease_peer_start (void *cls)
{
  struct OperationContext *opc = cls;

  if (OPC_STATE_FINISHED != opc->state)
  {
    GNUNET_free (opc->data);
    GNUNET_CONTAINER_DLL_remove (opc->c->ocq_head, opc->c->ocq_tail, opc);
  }
  GNUNET_free (opc);
}


/**
 * Function called when a peer stop operation is ready
 *
 * @param cls the closure from GNUNET_TESTBED_operation_create_()
 */
static void
opstart_peer_stop (void *cls)
{
  struct OperationContext *opc = cls;
  struct GNUNET_TESTBED_PeerStopMessage *msg;
  struct PeerEventData *data;
  struct GNUNET_TESTBED_Peer *peer;

  GNUNET_assert (NULL != opc->data);
  data = opc->data;
  GNUNET_assert (NULL != data->peer);
  peer = data->peer;
  GNUNET_assert (PS_STARTED == peer->state);
  opc->state = OPC_STATE_STARTED;
  msg = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_PeerStopMessage));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_STOP_PEER);
  msg->header.size = htons (sizeof (struct GNUNET_TESTBED_PeerStopMessage));
  msg->peer_id = htonl (peer->unique_id);
  msg->operation_id = GNUNET_htonll (opc->id);
  GNUNET_CONTAINER_DLL_insert_tail (opc->c->ocq_head, opc->c->ocq_tail, opc);
  GNUNET_TESTBED_queue_message_ (peer->controller, &msg->header);
}


/**
 * Callback which will be called when peer stop type operation is released
 *
 * @param cls the closure from GNUNET_TESTBED_operation_create_()
 */
static void
oprelease_peer_stop (void *cls)
{
  struct OperationContext *opc = cls;

  if (OPC_STATE_FINISHED != opc->state)
  {
    GNUNET_free (opc->data);
    GNUNET_CONTAINER_DLL_remove (opc->c->ocq_head, opc->c->ocq_tail, opc);
  }
  GNUNET_free (opc);
}


/**
 * Generate PeerGetConfigurationMessage
 *
 * @param peer_id the id of the peer whose information we have to get
 * @param operation_id the ip of the operation that should be represented in the
 *          message
 * @return the PeerGetConfigurationMessage
 */
struct GNUNET_TESTBED_PeerGetConfigurationMessage *
GNUNET_TESTBED_generate_peergetconfig_msg_ (uint32_t peer_id,
                                            uint64_t operation_id)
{
  struct GNUNET_TESTBED_PeerGetConfigurationMessage *msg;

  msg =
      GNUNET_malloc (sizeof
                     (struct GNUNET_TESTBED_PeerGetConfigurationMessage));
  msg->header.size =
      htons (sizeof (struct GNUNET_TESTBED_PeerGetConfigurationMessage));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_GET_PEER_CONFIGURATION);
  msg->peer_id = htonl (peer_id);
  msg->operation_id = GNUNET_htonll (operation_id);
  return msg;
}


/**
 * Function called when a peer get information operation is ready
 *
 * @param cls the closure from GNUNET_TESTBED_operation_create_()
 */
static void
opstart_peer_getinfo (void *cls)
{
  struct OperationContext *opc = cls;
  struct PeerInfoData *data;
  struct GNUNET_TESTBED_PeerGetConfigurationMessage *msg;

  data = opc->data;
  GNUNET_assert (NULL != data);
  opc->state = OPC_STATE_STARTED;
  msg =
      GNUNET_TESTBED_generate_peergetconfig_msg_ (data->peer->unique_id,
                                                  opc->id);
  GNUNET_CONTAINER_DLL_insert_tail (opc->c->ocq_head, opc->c->ocq_tail, opc);
  GNUNET_TESTBED_queue_message_ (opc->c, &msg->header);
}


/**
 * Callback which will be called when peer stop type operation is released
 *
 * @param cls the closure from GNUNET_TESTBED_operation_create_()
 */
static void
oprelease_peer_getinfo (void *cls)
{
  struct OperationContext *opc = cls;
  struct GNUNET_TESTBED_PeerInformation *data;

  if (OPC_STATE_FINISHED != opc->state)
  {
    GNUNET_free_non_null (opc->data);
    GNUNET_CONTAINER_DLL_remove (opc->c->ocq_head, opc->c->ocq_tail, opc);
  }
  else
  {
    data = opc->data;
    GNUNET_assert (NULL != data);
    switch (data->pit)
    {
    case GNUNET_TESTBED_PIT_CONFIGURATION:
      GNUNET_CONFIGURATION_destroy (data->result.cfg);
      break;
    case GNUNET_TESTBED_PIT_IDENTITY:
      GNUNET_free (data->result.id);
      break;
    default:
      GNUNET_assert (0);        /* We should never reach here */
    }
    GNUNET_free (data);
  }
  GNUNET_free (opc);
}


/**
 * Function called when a overlay connect operation is ready
 *
 * @param cls the closure from GNUNET_TESTBED_operation_create_()
 */
static void
opstart_overlay_connect (void *cls)
{
  struct OperationContext *opc = cls;
  struct GNUNET_TESTBED_OverlayConnectMessage *msg;
  struct OverlayConnectData *data;

  opc->state = OPC_STATE_STARTED;
  data = opc->data;
  GNUNET_assert (NULL != data);
  data->tslot_index = GNUNET_TESTBED_get_tslot_ (opc->c, data);
  data->tstart = GNUNET_TIME_absolute_get ();
  msg = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_OverlayConnectMessage));
  msg->header.size =
      htons (sizeof (struct GNUNET_TESTBED_OverlayConnectMessage));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_OVERLAY_CONNECT);
  msg->peer1 = htonl (data->p1->unique_id);
  msg->peer2 = htonl (data->p2->unique_id);
  msg->operation_id = GNUNET_htonll (opc->id);
  msg->peer2_host_id = htonl (GNUNET_TESTBED_host_get_id_ (data->p2->host));
  GNUNET_CONTAINER_DLL_insert_tail (opc->c->ocq_head, opc->c->ocq_tail, opc);
  GNUNET_TESTBED_queue_message_ (opc->c, &msg->header);
}


/**
 * Callback which will be called when overlay connect operation is released
 *
 * @param cls the closure from GNUNET_TESTBED_operation_create_()
 */
static void
oprelease_overlay_connect (void *cls)
{
  struct OperationContext *opc = cls;
  struct GNUNET_TIME_Relative duration;
  struct OverlayConnectData *data;

  data = opc->data;
  switch (opc->state)
  {
  case OPC_STATE_INIT:
    break;
  case OPC_STATE_STARTED:
    (void) GNUNET_TESTBED_release_time_slot_ (opc->c, data->tslot_index, data);
    GNUNET_CONTAINER_DLL_remove (opc->c->ocq_head, opc->c->ocq_tail, opc);
    break;
  case OPC_STATE_FINISHED:
    duration = GNUNET_TIME_absolute_get_duration (data->tstart);
    GNUNET_TESTBED_update_time_slot_ (opc->c, data->tslot_index, data, duration,
                                      data->failed);
  }
  GNUNET_free (data);
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
                            GNUNET_TESTBED_PeerCreateCallback cb, void *cls)
{

  struct GNUNET_TESTBED_Peer *peer;
  struct PeerCreateData *data;
  struct OperationContext *opc;
  static uint32_t id_gen;

  peer = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_Peer));
  peer->controller = controller;
  peer->host = host;
  peer->unique_id = id_gen++;
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
  opc->id = GNUNET_TESTBED_get_next_op_id (controller);
  opc->type = OP_PEER_CREATE;
  opc->op =
      GNUNET_TESTBED_operation_create_ (opc, &opstart_peer_create,
                                        &oprelease_peer_create);
  GNUNET_TESTBED_operation_queue_insert_ (controller->opq_parallel_operations,
                                          opc->op);
  GNUNET_TESTBED_operation_begin_wait_ (opc->op);
  return opc->op;
}


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
GNUNET_TESTBED_peer_start (void *op_cls, struct GNUNET_TESTBED_Peer *peer,
                           GNUNET_TESTBED_PeerChurnCallback pcc, void *pcc_cls)
{
  struct OperationContext *opc;
  struct PeerEventData *data;

  data = GNUNET_malloc (sizeof (struct PeerEventData));
  data->peer = peer;
  data->pcc = pcc;
  data->pcc_cls = pcc_cls;
  opc = GNUNET_malloc (sizeof (struct OperationContext));
  opc->c = peer->controller;
  opc->data = data;
  opc->op_cls = op_cls;
  opc->id = GNUNET_TESTBED_get_next_op_id (opc->c);
  opc->type = OP_PEER_START;
  opc->op =
      GNUNET_TESTBED_operation_create_ (opc, &opstart_peer_start,
                                        &oprelease_peer_start);
  GNUNET_TESTBED_operation_queue_insert_ (opc->c->opq_parallel_operations,
                                          opc->op);
  GNUNET_TESTBED_operation_begin_wait_ (opc->op);
  return opc->op;
}


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
                          GNUNET_TESTBED_PeerChurnCallback pcc, void *pcc_cls)
{
  struct OperationContext *opc;
  struct PeerEventData *data;

  data = GNUNET_malloc (sizeof (struct PeerEventData));
  data->peer = peer;
  data->pcc = pcc;
  data->pcc_cls = pcc_cls;
  opc = GNUNET_malloc (sizeof (struct OperationContext));
  opc->c = peer->controller;
  opc->data = data;
  opc->id = GNUNET_TESTBED_get_next_op_id (opc->c);
  opc->type = OP_PEER_STOP;
  opc->op =
      GNUNET_TESTBED_operation_create_ (opc, &opstart_peer_stop,
                                        &oprelease_peer_stop);
  GNUNET_TESTBED_operation_queue_insert_ (opc->c->opq_parallel_operations,
                                          opc->op);
  GNUNET_TESTBED_operation_begin_wait_ (opc->op);
  return opc->op;
}


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
                                     pit, GNUNET_TESTBED_PeerInfoCallback cb,
                                     void *cb_cls)
{
  struct OperationContext *opc;
  struct PeerInfoData *data;

  GNUNET_assert (GNUNET_TESTBED_PIT_GENERIC != pit);
  data = GNUNET_malloc (sizeof (struct PeerInfoData));
  data->peer = peer;
  data->pit = pit;
  data->cb = cb;
  data->cb_cls = cb_cls;
  opc = GNUNET_malloc (sizeof (struct OperationContext));
  opc->c = peer->controller;
  opc->data = data;
  opc->type = OP_PEER_INFO;
  opc->id = GNUNET_TESTBED_get_next_op_id (opc->c);
  opc->op =
      GNUNET_TESTBED_operation_create_ (opc, &opstart_peer_getinfo,
                                        &oprelease_peer_getinfo);
  GNUNET_TESTBED_operation_queue_insert_ (opc->c->opq_parallel_operations,
                                          opc->op);
  GNUNET_TESTBED_operation_begin_wait_ (opc->op);
  return opc->op;
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
                                          const struct
                                          GNUNET_CONFIGURATION_Handle *cfg)
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
  struct OperationContext *opc;

  opc = GNUNET_malloc (sizeof (struct OperationContext));
  opc->data = peer;
  opc->c = peer->controller;
  opc->id = GNUNET_TESTBED_get_next_op_id (peer->controller);
  opc->type = OP_PEER_DESTROY;
  opc->op =
      GNUNET_TESTBED_operation_create_ (opc, &opstart_peer_destroy,
                                        &oprelease_peer_destroy);
  GNUNET_TESTBED_operation_queue_insert_ (opc->c->opq_parallel_operations,
                                          opc->op);
  GNUNET_TESTBED_operation_begin_wait_ (opc->op);
  return opc->op;
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
                                        enum GNUNET_TESTBED_ConnectOption co,
                                        ...)
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
                                void *cb_cls, struct GNUNET_TESTBED_Peer *p1,
                                struct GNUNET_TESTBED_Peer *p2)
{
  struct OperationContext *opc;
  struct OverlayConnectData *data;

  GNUNET_assert ((PS_STARTED == p1->state) && (PS_STARTED == p2->state));
  data = GNUNET_malloc (sizeof (struct OverlayConnectData));
  data->p1 = p1;
  data->p2 = p2;
  data->cb = cb;
  data->cb_cls = cb_cls;
  opc = GNUNET_malloc (sizeof (struct OperationContext));
  opc->data = data;
  opc->c = p1->controller;
  opc->id = GNUNET_TESTBED_get_next_op_id (opc->c);
  opc->type = OP_OVERLAY_CONNECT;
  opc->op_cls = op_cls;
  opc->op =
      GNUNET_TESTBED_operation_create_ (opc, &opstart_overlay_connect,
                                        &oprelease_overlay_connect);
  GNUNET_TESTBED_operation_queue_insert_ (opc->
                                          c->opq_parallel_overlay_connect_operations,
                                          opc->op);
  GNUNET_TESTBED_operation_begin_wait_ (opc->op);
  return opc->op;
}



/* end of testbed_api_peers.c */
