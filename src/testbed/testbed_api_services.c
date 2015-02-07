/*
      This file is part of GNUnet
      Copyright (C) 2008--2013 Christian Grothoff (and other contributing authors)

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
 * @file testbed/testbed_api_services.c
 * @brief convenience functions for accessing services
 * @author Christian Grothoff
 */
#include "platform.h"
#include "testbed_api.h"
#include "testbed_api_peers.h"
#include "testbed_api_operations.h"


/**
 * States for Service connect operations
 */
enum State
{
  /**
   * Initial state
   */
  INIT,

  /**
   * The configuration request has been sent
   */
  CFG_REQUEST_QUEUED,

  /**
   * connected to service
   */
  SERVICE_CONNECTED
};


/**
 * Data accessed during service connections
 */
struct ServiceConnectData
{
  /**
   * helper function callback to establish the connection
   */
  GNUNET_TESTBED_ConnectAdapter ca;

  /**
   * helper function callback to close the connection
   */
  GNUNET_TESTBED_DisconnectAdapter da;

  /**
   * Closure to the above callbacks
   */
  void *cada_cls;

  /**
   * Service name
   */
  char *service_name;

  /**
   * Closure for operation event
   */
  void *op_cls;

  /**
   * The operation which created this structure
   */
  struct GNUNET_TESTBED_Operation *operation;

  /**
   * The operation context from GNUNET_TESTBED_forward_operation_msg_()
   */
  struct OperationContext *opc;

  /**
   * The peer handle
   */
  struct GNUNET_TESTBED_Peer *peer;

  /**
   * The acquired configuration of the peer
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * The op_result pointer from ConnectAdapter
   */
  void *op_result;

  /**
   * The operation completion callback
   */
  GNUNET_TESTBED_ServiceConnectCompletionCallback cb;

  /**
   * The closure for operation completion callback
   */
  void *cb_cls;

  /**
   * State information
   */
  enum State state;

};


/**
 * Type of a function to call when we receive a message
 * from the service.
 *
 * @param cls ServiceConnectData
 * @param msg message received, NULL on timeout or fatal error
 */
static void
configuration_receiver (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct ServiceConnectData *data = cls;
  struct GNUNET_TESTBED_Controller *c;
  const char *emsg;
  struct GNUNET_TESTBED_EventInformation info;
  uint16_t mtype;

  c = data->peer->controller;
  mtype = ntohs (msg->type);
  emsg = NULL;
  info.type = GNUNET_TESTBED_ET_OPERATION_FINISHED;
  info.op = data->operation;
  info.op_cls = data->op_cls;
  if (GNUNET_MESSAGE_TYPE_TESTBED_OPERATION_FAIL_EVENT == mtype)
  {
    emsg =
        GNUNET_TESTBED_parse_error_string_ ((const struct
                                             GNUNET_TESTBED_OperationFailureEventMessage
                                             *) msg);
    if (NULL == emsg)
      emsg = "Unknown error";
    info.details.operation_finished.emsg = emsg;
    info.details.operation_finished.generic = NULL;
    goto call_cb;
  }
  data->cfg = GNUNET_TESTBED_extract_config_ (msg);
  GNUNET_assert (NULL == data->op_result);
  data->op_result = data->ca (data->cada_cls, data->cfg);
  info.details.operation_finished.emsg = NULL;
  info.details.operation_finished.generic = data->op_result;
  data->state = SERVICE_CONNECTED;

call_cb:
  if ((0 != (GNUNET_TESTBED_ET_OPERATION_FINISHED & c->event_mask)) &&
      (NULL != c->cc))
    c->cc (c->cc_cls, &info);
  if (NULL != data->cb)
    data->cb (data->cb_cls, data->operation, data->op_result, emsg);
}


/**
 * Function called when a service connect operation is ready
 *
 * @param cls the closure from GNUNET_TESTBED_operation_create_()
 */
static void
opstart_service_connect (void *cls)
{
  struct ServiceConnectData *data = cls;
  struct GNUNET_TESTBED_PeerGetConfigurationMessage *msg;
  struct GNUNET_TESTBED_Controller *c;
  uint64_t op_id;

  GNUNET_assert (NULL != data);
  GNUNET_assert (NULL != data->peer);
  c = data->peer->controller;
  op_id = GNUNET_TESTBED_get_next_op_id (c);
  msg =
      GNUNET_TESTBED_generate_peergetconfig_msg_ (data->peer->unique_id, op_id);
  data->opc =
      GNUNET_TESTBED_forward_operation_msg_ (c, op_id, &msg->header,
                                             &configuration_receiver, data);
  GNUNET_free (msg);
  data->state = CFG_REQUEST_QUEUED;
}


/**
 * Callback which will be called when service connect type operation is
 * released
 *
 * @param cls the closure from GNUNET_TESTBED_operation_create_()
 */
static void
oprelease_service_connect (void *cls)
{
  struct ServiceConnectData *data = cls;

  switch (data->state)
  {
  case INIT:
    break;
  case CFG_REQUEST_QUEUED:
    GNUNET_assert (NULL != data->opc);
    GNUNET_TESTBED_forward_operation_msg_cancel_ (data->opc);
    break;
  case SERVICE_CONNECTED:
    GNUNET_assert (NULL != data->cfg);
    GNUNET_CONFIGURATION_destroy (data->cfg);
    if (NULL != data->da)
      data->da (data->cada_cls, data->op_result);
    break;
  }
  GNUNET_free (data);
}


/**
 * Connect to a service offered by the given peer.  Will ensure that
 * the request is queued to not overwhelm our ability to create and
 * maintain connections with other systems.  The actual service
 * handle is then returned via the 'op_result' member in the event
 * callback.  The 'ca' callback is used to create the connection
 * when the time is right; the 'da' callback will be used to
 * destroy the connection (upon 'GNUNET_TESTBED_operation_done').
 * 'GNUNET_TESTBED_operation_done' can be used to abort this
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
GNUNET_TESTBED_service_connect (void *op_cls, struct GNUNET_TESTBED_Peer *peer,
                                const char *service_name,
                                GNUNET_TESTBED_ServiceConnectCompletionCallback
                                cb, void *cb_cls,
                                GNUNET_TESTBED_ConnectAdapter ca,
                                GNUNET_TESTBED_DisconnectAdapter da,
                                void *cada_cls)
{
  struct ServiceConnectData *data;

  data = GNUNET_new (struct ServiceConnectData);
  data->ca = ca;
  data->da = da;
  data->cada_cls = cada_cls;
  data->op_cls = op_cls;
  data->peer = peer;
  data->state = INIT;
  data->cb = cb;
  data->cb_cls = cb_cls;
  data->operation =
      GNUNET_TESTBED_operation_create_ (data, &opstart_service_connect,
                                        &oprelease_service_connect);
  GNUNET_TESTBED_operation_queue_insert_ (peer->
                                          controller->opq_parallel_service_connections,
                                          data->operation);
  GNUNET_TESTBED_operation_queue_insert_ (peer->
                                          controller->opq_parallel_operations,
                                          data->operation);
  GNUNET_TESTBED_operation_begin_wait_ (data->operation);
  return data->operation;
}

/* end of testbed_api_services.c */
