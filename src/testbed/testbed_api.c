/*
      This file is part of GNUnet
      Copyright (C) 2008--2013 GNUnet e.V.

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
      Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
      Boston, MA 02110-1301, USA.
 */

/**
 * @file testbed/testbed_api.c
 * @brief API for accessing the GNUnet testing service.
 *        This library is supposed to make it easier to write
 *        testcases and script large-scale benchmarks.
 * @author Christian Grothoff
 * @author Sree Harsha Totakura
 */
#include "platform.h"
#include "gnunet_testbed_service.h"
#include "gnunet_core_service.h"
#include "gnunet_constants.h"
#include "gnunet_transport_service.h"
#include "gnunet_hello_lib.h"
#include <zlib.h>

#include "testbed.h"
#include "testbed_api.h"
#include "testbed_api_hosts.h"
#include "testbed_api_peers.h"
#include "testbed_api_operations.h"
#include "testbed_api_sd.h"

/**
 * Generic logging shorthand
 */
#define LOG(kind, ...)                          \
  GNUNET_log_from (kind, "testbed-api", __VA_ARGS__)

/**
 * Debug logging
 */
#define LOG_DEBUG(...)                          \
  LOG (GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__)

/**
 * Relative time seconds shorthand
 */
#define TIME_REL_SECS(sec) \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, sec)


/**
 * Default server message sending retry timeout
 */
#define TIMEOUT_REL TIME_REL_SECS(1)


/**
 * Context data for forwarded Operation
 */
struct ForwardedOperationData
{

  /**
   * The callback to call when reply is available
   */
  GNUNET_MQ_MessageCallback cc;

  /**
   * The closure for the above callback
   */
  void *cc_cls;

};


/**
 * Context data for get slave config operations
 */
struct GetSlaveConfigData
{
  /**
   * The id of the slave controller
   */
  uint32_t slave_id;

};


/**
 * Context data for controller link operations
 */
struct ControllerLinkData
{
  /**
   * The controller link message
   */
  struct GNUNET_TESTBED_ControllerLinkRequest *msg;

  /**
   * The id of the host which is hosting the controller to be linked
   */
  uint32_t host_id;

};


/**
 * Date context for OP_SHUTDOWN_PEERS operations
 */
struct ShutdownPeersData
{
  /**
   * The operation completion callback to call
   */
  GNUNET_TESTBED_OperationCompletionCallback cb;

  /**
   * The closure for the above callback
   */
  void *cb_cls;
};


/**
 * An entry in the stack for keeping operations which are about to expire
 */
struct ExpireOperationEntry
{
  /**
   * DLL head; new entries are to be inserted here
   */
  struct ExpireOperationEntry *next;

  /**
   * DLL tail; entries are deleted from here
   */
  struct ExpireOperationEntry *prev;

  /**
   * The operation.  This will be a dangling pointer when the operation is freed
   */
  const struct GNUNET_TESTBED_Operation *op;
};


/**
 * DLL head for list of operations marked for expiry
 */
static struct ExpireOperationEntry *exop_head;

/**
 * DLL tail for list of operation marked for expiry
 */
static struct ExpireOperationEntry *exop_tail;


/**
 * Inserts an operation into the list of operations marked for expiry
 *
 * @param op the operation to insert
 */
static void
exop_insert (struct GNUNET_TESTBED_Operation *op)
{
  struct ExpireOperationEntry *entry;

  entry = GNUNET_new (struct ExpireOperationEntry);
  entry->op = op;
  GNUNET_CONTAINER_DLL_insert_tail (exop_head, exop_tail, entry);
}


/**
 * Checks if an operation is present in the list of operations marked for
 * expiry.  If the operation is found, it and the tail of operations after it
 * are removed from the list.
 *
 * @param op the operation to check
 * @return GNUNET_NO if the operation is not present in the list; GNUNET_YES if
 *           the operation is found in the list (the operation is then removed
 *           from the list -- calling this function again with the same
 *           paramenter will return GNUNET_NO)
 */
static int
exop_check (const struct GNUNET_TESTBED_Operation *const op)
{
  struct ExpireOperationEntry *entry;
  struct ExpireOperationEntry *entry2;
  int found;

  found = GNUNET_NO;
  entry = exop_head;
  while (NULL != entry)
  {
    if (op == entry->op)
    {
      found = GNUNET_YES;
      break;
    }
    entry = entry->next;
  }
  if (GNUNET_NO == found)
    return GNUNET_NO;
  /* Truncate the tail */
  while (NULL != entry)
  {
    entry2 = entry->next;
    GNUNET_CONTAINER_DLL_remove (exop_head,
                                 exop_tail,
                                 entry);
    GNUNET_free (entry);
    entry = entry2;
  }
  return GNUNET_YES;
}


/**
 * Context information to be used while searching for operation contexts
 */
struct SearchContext
{
  /**
   * The result of the search
   */
  struct OperationContext *opc;

  /**
   * The id of the operation context we are searching for
   */
  uint64_t id;
};


/**
 * Search iterator for searching an operation context
 *
 * @param cls the serach context
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES if we should continue to iterate,
 *         #GNUNET_NO if not.
 */
static int
opc_search_iterator (void *cls,
                     uint32_t key,
                     void *value)
{
  struct SearchContext *sc = cls;
  struct OperationContext *opc = value;

  GNUNET_assert (NULL != opc);
  GNUNET_assert (NULL == sc->opc);
  if (opc->id != sc->id)
    return GNUNET_YES;
  sc->opc = opc;
  return GNUNET_NO;
}


/**
 * Returns the operation context with the given id if found in the Operation
 * context queues of the controller
 *
 * @param c the controller whose operation context map is searched
 * @param id the id which has to be checked
 * @return the matching operation context; NULL if no match found
 */
static struct OperationContext *
find_opc (const struct GNUNET_TESTBED_Controller *c, const uint64_t id)
{
  struct SearchContext sc;

  sc.id = id;
  sc.opc = NULL;
  GNUNET_assert (NULL != c->opc_map);
  if (GNUNET_SYSERR !=
      GNUNET_CONTAINER_multihashmap32_get_multiple (c->opc_map, (uint32_t) id,
                                                    &opc_search_iterator, &sc))
    return NULL;
  return sc.opc;
}


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
                            struct OperationContext *opc)
{
  if (NULL == c->opc_map)
    c->opc_map = GNUNET_CONTAINER_multihashmap32_create (256);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap32_put (c->opc_map,
                                                      (uint32_t) opc->id, opc,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
}


/**
 * Removes the given operation context from the operation context map of the
 * given controller
 *
 * @param c the controller
 * @param opc the operation context to remove
 */
void
GNUNET_TESTBED_remove_opc_ (const struct GNUNET_TESTBED_Controller *c,
                            struct OperationContext *opc)
{
  GNUNET_assert (NULL != c->opc_map);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap32_remove (c->opc_map,
                                                         (uint32_t) opc->id,
                                                         opc));
  if ( (0 == GNUNET_CONTAINER_multihashmap32_size (c->opc_map))
       && (NULL != c->opcq_empty_cb) )
    c->opcq_empty_cb (c->opcq_empty_cls);
}



/**
 * Check #GNUNET_MESSAGE_TYPE_TESTBED_ADDHOSTCONFIRM message is well-formed.
 *
 * @param cls the controller handler
 * @param msg message received
 * @return #GNUNET_OK if message is well-formed
 */
static int
check_add_host_confirm (void *cls,
                        const struct GNUNET_TESTBED_HostConfirmedMessage *msg)
{
  const char *emsg;
  uint16_t msg_size;

  msg_size = ntohs (msg->header.size) - sizeof (*msg);
  if (0 == msg_size)
    return GNUNET_OK;
  /* We have an error message */
  emsg = (const char *) &msg[1];
  if ('\0' != emsg[msg_size - 1])
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handler for #GNUNET_MESSAGE_TYPE_TESTBED_ADDHOSTCONFIRM message from
 * controller (testbed service)
 *
 * @param cls the controller handler
 * @param msg message received
 */
static void
handle_add_host_confirm (void *cls,
                         const struct GNUNET_TESTBED_HostConfirmedMessage *msg)
{
  struct GNUNET_TESTBED_Controller *c = cls;
  struct GNUNET_TESTBED_HostRegistrationHandle *rh = c->rh;
  const char *emsg;
  uint16_t msg_size;

  if (NULL == rh)
    return;
  if (GNUNET_TESTBED_host_get_id_ (rh->host) != ntohl (msg->host_id))
  {
    LOG_DEBUG ("Mismatch in host id's %u, %u of host confirm msg\n",
               GNUNET_TESTBED_host_get_id_ (rh->host),
               ntohl (msg->host_id));
    return;
  }
  c->rh = NULL;
  msg_size = ntohs (msg->header.size) - sizeof (*msg);
  if (0 == msg_size)
  {
    LOG_DEBUG ("Host %u successfully registered\n",
               ntohl (msg->host_id));
    GNUNET_TESTBED_mark_host_registered_at_ (rh->host,
                                             c);
    rh->cc (rh->cc_cls,
            NULL);
    GNUNET_free (rh);
    return;
  }
  /* We have an error message */
  emsg = (const char *) &msg[1];
  LOG (GNUNET_ERROR_TYPE_ERROR,
       _("Adding host %u failed with error: %s\n"),
       ntohl (msg->host_id),
       emsg);
  rh->cc (rh->cc_cls,
          emsg);
  GNUNET_free (rh);
}


/**
 * Handler for forwarded operations
 *
 * @param c the controller handle
 * @param opc the opearation context
 * @param msg the message
 */
static void
handle_forwarded_operation_msg (void *cls,
                                struct OperationContext *opc,
                                const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_TESTBED_Controller *c = cls;
  struct ForwardedOperationData *fo_data;

  fo_data = opc->data;
  if (NULL != fo_data->cc)
    fo_data->cc (fo_data->cc_cls, msg);
  GNUNET_TESTBED_remove_opc_ (c, opc);
  GNUNET_free (fo_data);
  GNUNET_free (opc);
}


/**
 * Handler for #GNUNET_MESSAGE_TYPE_TESTBED_ADD_HOST_SUCCESS message from
 * controller (testbed service)
 *
 * @param c the controller handler
 * @param msg message received
 */
static void
handle_opsuccess (void *cls,
                  const struct GNUNET_TESTBED_GenericOperationSuccessEventMessage *msg)
{
  struct GNUNET_TESTBED_Controller *c = cls;
  struct OperationContext *opc;
  GNUNET_TESTBED_OperationCompletionCallback op_comp_cb;
  void *op_comp_cb_cls;
  struct GNUNET_TESTBED_EventInformation event;
  uint64_t op_id;

  op_id = GNUNET_ntohll (msg->operation_id);
  LOG_DEBUG ("Operation %lu successful\n", op_id);
  if (NULL == (opc = find_opc (c, op_id)))
  {
    LOG_DEBUG ("Operation not found\n");
    return;
  }
  event.type = GNUNET_TESTBED_ET_OPERATION_FINISHED;
  event.op = opc->op;
  event.op_cls = opc->op_cls;
  event.details.operation_finished.emsg = NULL;
  event.details.operation_finished.generic = NULL;
  op_comp_cb = NULL;
  op_comp_cb_cls = NULL;
  switch (opc->type)
  {
  case OP_FORWARDED:
    {
      handle_forwarded_operation_msg (c, opc,
                                      (const struct GNUNET_MessageHeader *) msg);
      return;
    }
    break;
  case OP_PEER_DESTROY:
  {
    struct GNUNET_TESTBED_Peer *peer;

    peer = opc->data;
    GNUNET_TESTBED_peer_deregister_ (peer);
    GNUNET_free (peer);
    opc->data = NULL;
    //PEERDESTROYDATA
  }
    break;
  case OP_SHUTDOWN_PEERS:
  {
    struct ShutdownPeersData *data;

    data = opc->data;
    op_comp_cb = data->cb;
    op_comp_cb_cls = data->cb_cls;
    GNUNET_free (data);
    opc->data = NULL;
    GNUNET_TESTBED_cleanup_peers_ ();
  }
    break;
  case OP_MANAGE_SERVICE:
  {
    struct ManageServiceData *data;

    GNUNET_assert (NULL != (data = opc->data));
    op_comp_cb = data->cb;
    op_comp_cb_cls = data->cb_cls;
    GNUNET_free (data);
    opc->data = NULL;
  }
    break;
  case OP_PEER_RECONFIGURE:
    break;
  default:
    GNUNET_assert (0);
  }
  GNUNET_TESTBED_remove_opc_ (opc->c, opc);
  opc->state = OPC_STATE_FINISHED;
  exop_insert (event.op);
  if (0 != (c->event_mask & (1L << GNUNET_TESTBED_ET_OPERATION_FINISHED)))
  {
    if (NULL != c->cc)
      c->cc (c->cc_cls, &event);
    if (GNUNET_NO == exop_check (event.op))
      return;
  }
  else
    LOG_DEBUG ("Not calling callback\n");
  if (NULL != op_comp_cb)
    op_comp_cb (op_comp_cb_cls, event.op, NULL);
   /* You could have marked the operation as done by now */
  GNUNET_break (GNUNET_NO == exop_check (event.op));
}


/**
 * Handler for #GNUNET_MESSAGE_TYPE_TESTBED_CREATE_PEER_SUCCESS message from
 * controller (testbed service)
 *
 * @param c the controller handle
 * @param msg message received
 */
static void
handle_peer_create_success (void *cls,
                            const struct GNUNET_TESTBED_PeerCreateSuccessEventMessage *msg)
{
  struct GNUNET_TESTBED_Controller *c = cls;
  struct OperationContext *opc;
  struct PeerCreateData *data;
  struct GNUNET_TESTBED_Peer *peer;
  struct GNUNET_TESTBED_Operation *op;
  GNUNET_TESTBED_PeerCreateCallback cb;
  void *cb_cls;
  uint64_t op_id;

  GNUNET_assert (sizeof (struct GNUNET_TESTBED_PeerCreateSuccessEventMessage) ==
                 ntohs (msg->header.size));
  op_id = GNUNET_ntohll (msg->operation_id);
  if (NULL == (opc = find_opc (c, op_id)))
  {
    LOG_DEBUG ("Operation context for PeerCreateSuccessEvent not found\n");
    return;
  }
  if (OP_FORWARDED == opc->type)
  {
    handle_forwarded_operation_msg (c, opc,
                                    (const struct GNUNET_MessageHeader *) msg);
    return;
  }
  GNUNET_assert (OP_PEER_CREATE == opc->type);
  GNUNET_assert (NULL != opc->data);
  data = opc->data;
  GNUNET_assert (NULL != data->peer);
  peer = data->peer;
  GNUNET_assert (peer->unique_id == ntohl (msg->peer_id));
  peer->state = TESTBED_PS_CREATED;
  GNUNET_TESTBED_peer_register_ (peer);
  cb = data->cb;
  cb_cls = data->cls;
  op = opc->op;
  GNUNET_free (opc->data);
  GNUNET_TESTBED_remove_opc_ (opc->c, opc);
  opc->state = OPC_STATE_FINISHED;
  exop_insert (op);
  if (NULL != cb)
    cb (cb_cls, peer, NULL);
   /* You could have marked the operation as done by now */
  GNUNET_break (GNUNET_NO == exop_check (op));
}


/**
 * Handler for #GNUNET_MESSAGE_TYPE_TESTBED_PEER_EVENT message from
 * controller (testbed service)
 *
 * @param c the controller handler
 * @param msg message received
 */
static void
handle_peer_event (void *cls,
                   const struct GNUNET_TESTBED_PeerEventMessage *msg)
{
  struct GNUNET_TESTBED_Controller *c = cls;
  struct OperationContext *opc;
  struct GNUNET_TESTBED_Peer *peer;
  struct PeerEventData *data;
  GNUNET_TESTBED_PeerChurnCallback pcc;
  void *pcc_cls;
  struct GNUNET_TESTBED_EventInformation event;
  uint64_t op_id;
  uint64_t mask;

  GNUNET_assert (sizeof (struct GNUNET_TESTBED_PeerEventMessage) ==
                 ntohs (msg->header.size));
  op_id = GNUNET_ntohll (msg->operation_id);
  if (NULL == (opc = find_opc (c, op_id)))
  {
    LOG_DEBUG ("Operation not found\n");
    return;
  }
  if (OP_FORWARDED == opc->type)
  {
    handle_forwarded_operation_msg (c, opc,
                                    (const struct GNUNET_MessageHeader *) msg);
    return;
  }
  GNUNET_assert ((OP_PEER_START == opc->type) || (OP_PEER_STOP == opc->type));
  data = opc->data;
  GNUNET_assert (NULL != data);
  peer = data->peer;
  GNUNET_assert (NULL != peer);
  event.type = (enum GNUNET_TESTBED_EventType) ntohl (msg->event_type);
  event.op = opc->op;
  event.op_cls = opc->op_cls;
  switch (event.type)
  {
  case GNUNET_TESTBED_ET_PEER_START:
    peer->state = TESTBED_PS_STARTED;
    event.details.peer_start.host = peer->host;
    event.details.peer_start.peer = peer;
    break;
  case GNUNET_TESTBED_ET_PEER_STOP:
    peer->state = TESTBED_PS_STOPPED;
    event.details.peer_stop.peer = peer;
    break;
  default:
    GNUNET_assert (0);          /* We should never reach this state */
  }
  pcc = data->pcc;
  pcc_cls = data->pcc_cls;
  GNUNET_free (data);
  GNUNET_TESTBED_remove_opc_ (opc->c, opc);
  opc->state = OPC_STATE_FINISHED;
  exop_insert (event.op);
  mask = 1LL << GNUNET_TESTBED_ET_PEER_START;
  mask |= 1LL << GNUNET_TESTBED_ET_PEER_STOP;
  if (0 != (mask & c->event_mask))
  {
    if (NULL != c->cc)
      c->cc (c->cc_cls, &event);
    if (GNUNET_NO == exop_check (event.op))
      return;
  }
  if (NULL != pcc)
    pcc (pcc_cls, NULL);
   /* You could have marked the operation as done by now */
  GNUNET_break (GNUNET_NO == exop_check (event.op));
}


/**
 * Handler for #GNUNET_MESSAGE_TYPE_TESTBED_PEER_CONNECT_EVENT message from
 * controller (testbed service)
 *
 * @param c the controller handler
 * @param msg message received
 */
static void
handle_peer_conevent (void *cls,
                      const struct GNUNET_TESTBED_ConnectionEventMessage *msg)
{
  struct GNUNET_TESTBED_Controller *c = cls;
  struct OperationContext *opc;
  struct OverlayConnectData *data;
  GNUNET_TESTBED_OperationCompletionCallback cb;
  void *cb_cls;
  struct GNUNET_TESTBED_EventInformation event;
  uint64_t op_id;
  uint64_t mask;

  op_id = GNUNET_ntohll (msg->operation_id);
  if (NULL == (opc = find_opc (c, op_id)))
  {
    LOG_DEBUG ("Operation not found\n");
    return;
  }
  if (OP_FORWARDED == opc->type)
  {
    handle_forwarded_operation_msg (c, opc,
                                    (const struct GNUNET_MessageHeader *) msg);
    return;
  }
  GNUNET_assert (OP_OVERLAY_CONNECT == opc->type);
  GNUNET_assert (NULL != (data = opc->data));
  GNUNET_assert ((ntohl (msg->peer1) == data->p1->unique_id) &&
                 (ntohl (msg->peer2) == data->p2->unique_id));
  event.type = (enum GNUNET_TESTBED_EventType) ntohl (msg->event_type);
  event.op = opc->op;
  event.op_cls = opc->op_cls;
  switch (event.type)
  {
  case GNUNET_TESTBED_ET_CONNECT:
    event.details.peer_connect.peer1 = data->p1;
    event.details.peer_connect.peer2 = data->p2;
    break;
  case GNUNET_TESTBED_ET_DISCONNECT:
    GNUNET_assert (0);          /* FIXME: implement */
    break;
  default:
    GNUNET_assert (0);          /* Should never reach here */
    break;
  }
  cb = data->cb;
  cb_cls = data->cb_cls;
  GNUNET_TESTBED_remove_opc_ (opc->c, opc);
  opc->state = OPC_STATE_FINISHED;
  exop_insert (event.op);
  mask = 1LL << GNUNET_TESTBED_ET_CONNECT;
  mask |= 1LL << GNUNET_TESTBED_ET_DISCONNECT;
  if (0 != (mask & c->event_mask))
  {
    if (NULL != c->cc)
      c->cc (c->cc_cls, &event);
    if (GNUNET_NO == exop_check (event.op))
      return;
  }
  if (NULL != cb)
    cb (cb_cls, opc->op, NULL);
   /* You could have marked the operation as done by now */
  GNUNET_break (GNUNET_NO == exop_check (event.op));
}


/**
 * Validate #GNUNET_MESSAGE_TYPE_TESTBED_PEER_INFORMATION message from
 * controller (testbed service)
 *
 * @param c the controller handler
 * @param msg message received
 */
static int
check_peer_config (void *cls,
                   const struct GNUNET_TESTBED_PeerConfigurationInformationMessage *msg)
{
  /* anything goes? */
  return GNUNET_OK;
}


/**
 * Handler for #GNUNET_MESSAGE_TYPE_TESTBED_PEER_INFORMATION message from
 * controller (testbed service)
 *
 * @param c the controller handler
 * @param msg message received
 */
static void
handle_peer_config (void *cls,
                    const struct GNUNET_TESTBED_PeerConfigurationInformationMessage *msg)
{
  struct GNUNET_TESTBED_Controller *c = cls;
  struct OperationContext *opc;
  struct GNUNET_TESTBED_Peer *peer;
  struct PeerInfoData *data;
  struct GNUNET_TESTBED_PeerInformation *pinfo;
  GNUNET_TESTBED_PeerInfoCallback cb;
  void *cb_cls;
  uint64_t op_id;

  op_id = GNUNET_ntohll (msg->operation_id);
  if (NULL == (opc = find_opc (c, op_id)))
  {
    LOG_DEBUG ("Operation not found\n");
    return;
  }
  if (OP_FORWARDED == opc->type)
  {
    handle_forwarded_operation_msg (c,
                                    opc,
                                    &msg->header);
    return;
  }
  data = opc->data;
  GNUNET_assert (NULL != data);
  peer = data->peer;
  GNUNET_assert (NULL != peer);
  GNUNET_assert (ntohl (msg->peer_id) == peer->unique_id);
  pinfo = GNUNET_new (struct GNUNET_TESTBED_PeerInformation);
  pinfo->pit = data->pit;
  cb = data->cb;
  cb_cls = data->cb_cls;
  GNUNET_assert (NULL != cb);
  GNUNET_free (data);
  opc->data = NULL;
  switch (pinfo->pit)
  {
  case GNUNET_TESTBED_PIT_IDENTITY:
    pinfo->result.id = GNUNET_new (struct GNUNET_PeerIdentity);
    GNUNET_memcpy (pinfo->result.id,
                   &msg->peer_identity,
                   sizeof (struct GNUNET_PeerIdentity));
    break;
  case GNUNET_TESTBED_PIT_CONFIGURATION:
    pinfo->result.cfg =         /* Freed in oprelease_peer_getinfo */
        GNUNET_TESTBED_extract_config_ (&msg->header);
    break;
  case GNUNET_TESTBED_PIT_GENERIC:
    GNUNET_assert (0);          /* never reach here */
    break;
  }
  opc->data = pinfo;
  GNUNET_TESTBED_remove_opc_ (opc->c, opc);
  opc->state = OPC_STATE_FINISHED;
  cb (cb_cls, opc->op, pinfo, NULL);
  /* We dont check whether the operation is marked as done here as the
     operation contains data (cfg/identify) which will be freed at a later point
  */
}


/**
 * Validate #GNUNET_MESSAGE_TYPE_TESTBED_OPERATION_FAIL_EVENT message from
 * controller (testbed service)
 *
 * @param c the controller handler
 * @param msg message received
 * @return #GNUNET_OK if message is well-formed
 */
static int
check_op_fail_event (void *cls,
                     const struct GNUNET_TESTBED_OperationFailureEventMessage *msg)
{
  /* we accept anything as a valid error message */
  return GNUNET_OK;
}


/**
 * Handler for #GNUNET_MESSAGE_TYPE_TESTBED_OPERATION_FAIL_EVENT message from
 * controller (testbed service)
 *
 * @param c the controller handler
 * @param msg message received
 */
static void
handle_op_fail_event (void *cls,
                      const struct GNUNET_TESTBED_OperationFailureEventMessage *msg)
{
  struct GNUNET_TESTBED_Controller *c = cls;
  struct OperationContext *opc;
  const char *emsg;
  uint64_t op_id;
  uint64_t mask;
  struct GNUNET_TESTBED_EventInformation event;

  op_id = GNUNET_ntohll (msg->operation_id);
  if (NULL == (opc = find_opc (c, op_id)))
  {
    LOG_DEBUG ("Operation not found\n");
    return;
  }
  if (OP_FORWARDED == opc->type)
  {
    handle_forwarded_operation_msg (c, opc,
                                    (const struct GNUNET_MessageHeader *) msg);
    return;
  }
  GNUNET_TESTBED_remove_opc_ (opc->c, opc);
  opc->state = OPC_STATE_FINISHED;
  emsg = GNUNET_TESTBED_parse_error_string_ (msg);
  if (NULL == emsg)
    emsg = "Unknown error";
  if (OP_PEER_INFO == opc->type)
  {
    struct PeerInfoData *data;

    data = opc->data;
    if (NULL != data->cb)
      data->cb (data->cb_cls, opc->op, NULL, emsg);
    GNUNET_free (data);
    return;          /* We do not call controller callback for peer info */
  }
  event.type = GNUNET_TESTBED_ET_OPERATION_FINISHED;
  event.op = opc->op;
  event.op_cls = opc->op_cls;
  event.details.operation_finished.emsg = emsg;
  event.details.operation_finished.generic = NULL;
  mask = (1LL << GNUNET_TESTBED_ET_OPERATION_FINISHED);
  if ((0 != (mask & c->event_mask)) && (NULL != c->cc))
  {
    exop_insert (event.op);
    c->cc (c->cc_cls, &event);
    if (GNUNET_NO == exop_check (event.op))
      return;
  }
  switch (opc->type)
  {
  case OP_PEER_CREATE:
    {
      struct PeerCreateData *data;

      data = opc->data;
      GNUNET_free (data->peer);
      if (NULL != data->cb)
        data->cb (data->cls, NULL, emsg);
      GNUNET_free (data);
    }
    break;
  case OP_PEER_START:
  case OP_PEER_STOP:
    {
      struct PeerEventData *data;

      data = opc->data;
      if (NULL != data->pcc)
        data->pcc (data->pcc_cls, emsg);
      GNUNET_free (data);
    }
    break;
  case OP_PEER_DESTROY:
    break;
  case OP_PEER_INFO:
    GNUNET_assert (0);
  case OP_OVERLAY_CONNECT:
    {
      struct OverlayConnectData *data;

      data = opc->data;
      GNUNET_TESTBED_operation_mark_failed (opc->op);
      if (NULL != data->cb)
        data->cb (data->cb_cls, opc->op, emsg);
    }
    break;
  case OP_FORWARDED:
    GNUNET_assert (0);
  case OP_LINK_CONTROLLERS:    /* No secondary callback */
    break;
  case OP_SHUTDOWN_PEERS:
    {
      struct ShutdownPeersData *data;

      data = opc->data;
      GNUNET_free (data);         /* FIXME: Decide whether we call data->op_cb */
      opc->data = NULL;
    }
    break;
  case OP_MANAGE_SERVICE:
    {
      struct ManageServiceData *data = opc->data;
      GNUNET_TESTBED_OperationCompletionCallback cb;
      void *cb_cls;

      GNUNET_assert (NULL != data);
      cb = data->cb;
      cb_cls = data->cb_cls;
      GNUNET_free (data);
      opc->data = NULL;
      exop_insert (event.op);
      if (NULL != cb)
        cb (cb_cls, opc->op, emsg);
      /* You could have marked the operation as done by now */
      GNUNET_break (GNUNET_NO == exop_check (event.op));
    }
    break;
  default:
    GNUNET_break (0);
  }
}


/**
 * Function to build GET_SLAVE_CONFIG message
 *
 * @param op_id the id this message should contain in its operation id field
 * @param slave_id the id this message should contain in its slave id field
 * @return newly allocated SlaveGetConfigurationMessage
 */
static struct GNUNET_TESTBED_SlaveGetConfigurationMessage *
GNUNET_TESTBED_generate_slavegetconfig_msg_ (uint64_t op_id, uint32_t slave_id)
{
  struct GNUNET_TESTBED_SlaveGetConfigurationMessage *msg;
  uint16_t msize;

  msize = sizeof (struct GNUNET_TESTBED_SlaveGetConfigurationMessage);
  msg = GNUNET_malloc (msize);
  msg->header.size = htons (msize);
  msg->header.type =
      htons (GNUNET_MESSAGE_TYPE_TESTBED_GET_SLAVE_CONFIGURATION);
  msg->operation_id = GNUNET_htonll (op_id);
  msg->slave_id = htonl (slave_id);
  return msg;
}



/**
 * Validate #GNUNET_MESSAGE_TYPE_TESTBED_SLAVE_INFORMATION message from
 * controller (testbed service)
 *
 * @param c the controller handler
 * @param msg message received
 */
static int
check_slave_config (void *cls,
                    const struct GNUNET_TESTBED_SlaveConfiguration *msg)
{
  /* anything goes? */
  return GNUNET_OK;
}


/**
 * Handler for #GNUNET_MESSAGE_TYPE_TESTBED_SLAVE_CONFIGURATION message from controller
 * (testbed service)
 *
 * @param c the controller handler
 * @param msg message received
 */
static void
handle_slave_config (void *cls,
                     const struct GNUNET_TESTBED_SlaveConfiguration *msg)
{
  struct GNUNET_TESTBED_Controller *c = cls;
  struct OperationContext *opc;
  uint64_t op_id;
  uint64_t mask;
  struct GNUNET_TESTBED_EventInformation event;

  op_id = GNUNET_ntohll (msg->operation_id);
  if (NULL == (opc = find_opc (c, op_id)))
  {
    LOG_DEBUG ("Operation not found\n");
    return;
  }
  if (OP_GET_SLAVE_CONFIG != opc->type)
  {
    GNUNET_break (0);
    return;
  }
  opc->state = OPC_STATE_FINISHED;
  GNUNET_TESTBED_remove_opc_ (opc->c, opc);
  mask = 1LL << GNUNET_TESTBED_ET_OPERATION_FINISHED;
  if ((0 != (mask & c->event_mask)) &&
      (NULL != c->cc))
  {
    opc->data = GNUNET_TESTBED_extract_config_ (&msg->header);
    event.type = GNUNET_TESTBED_ET_OPERATION_FINISHED;
    event.op = opc->op;
    event.op_cls = opc->op_cls;
    event.details.operation_finished.generic = opc->data;
    event.details.operation_finished.emsg = NULL;
    c->cc (c->cc_cls, &event);
  }
}


/**
 * Check #GNUNET_MESSAGE_TYPE_TESTBED_LINK_CONTROLLERS_RESULT message from controller
 * (testbed service)
 *
 * @param c the controller handler
 * @param msg message received
 * @return #GNUNET_OK if @a msg is well-formed
 */
static int
check_link_controllers_result (void *cls,
                                const struct GNUNET_TESTBED_ControllerLinkResponse *msg)
{
  /* actual check to be implemented */
  return GNUNET_OK;
}


/**
 * Handler for #GNUNET_MESSAGE_TYPE_TESTBED_LINK_CONTROLLERS_RESULT message from controller
 * (testbed service)
 *
 * @param c the controller handler
 * @param msg message received
 */
static void
handle_link_controllers_result (void *cls,
                                const struct GNUNET_TESTBED_ControllerLinkResponse *msg)
{
  struct GNUNET_TESTBED_Controller *c = cls;
  struct OperationContext *opc;
  struct ControllerLinkData *data;
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_TESTBED_Host *host;
  char *emsg;
  uint64_t op_id;
  struct GNUNET_TESTBED_EventInformation event;

  op_id = GNUNET_ntohll (msg->operation_id);
  if (NULL == (opc = find_opc (c, op_id)))
  {
    LOG_DEBUG ("Operation not found\n");
    return;
  }
  if (OP_FORWARDED == opc->type)
  {
    handle_forwarded_operation_msg (c, opc,
                                    (const struct GNUNET_MessageHeader *) msg);
    return;
  }
  if (OP_LINK_CONTROLLERS != opc->type)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_assert (NULL != (data = opc->data));
  host = GNUNET_TESTBED_host_lookup_by_id_ (data->host_id);
  GNUNET_assert (NULL != host);
  GNUNET_free (data);
  opc->data = NULL;
  opc->state = OPC_STATE_FINISHED;
  GNUNET_TESTBED_remove_opc_ (opc->c, opc);
  event.type = GNUNET_TESTBED_ET_OPERATION_FINISHED;
  event.op = opc->op;
  event.op_cls = opc->op_cls;
  event.details.operation_finished.emsg = NULL;
  event.details.operation_finished.generic = NULL;
  emsg = NULL;
  cfg = NULL;
  if (GNUNET_NO == ntohs (msg->success))
  {
    emsg = GNUNET_malloc (ntohs (msg->header.size)
                          - sizeof (struct
                                    GNUNET_TESTBED_ControllerLinkResponse) + 1);
    GNUNET_memcpy (emsg,
                   &msg[1],
                   ntohs (msg->header.size)- sizeof (struct GNUNET_TESTBED_ControllerLinkResponse));
    event.details.operation_finished.emsg = emsg;
  }
  else
  {
    if (0 != ntohs (msg->config_size))
    {
      cfg = GNUNET_TESTBED_extract_config_ ((const struct GNUNET_MessageHeader *) msg);
      GNUNET_assert (NULL != cfg);
      GNUNET_TESTBED_host_replace_cfg_ (host, cfg);
    }
  }
  if (0 != (c->event_mask & (1L << GNUNET_TESTBED_ET_OPERATION_FINISHED)))
  {
    if (NULL != c->cc)
      c->cc (c->cc_cls, &event);
  }
  else
    LOG_DEBUG ("Not calling callback\n");
  if (NULL != cfg)
    GNUNET_CONFIGURATION_destroy (cfg);
  GNUNET_free_non_null (emsg);
}


/**
 * Validate #GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_STATUS message.
 *
 * @param cls the controller handle to determine the connection this message
 *   belongs to
 * @param msg the barrier status message
 * @return #GNUNET_OK if the message is valid; #GNUNET_SYSERR to tear it
 *   down signalling an error (message malformed)
 */
static int
check_barrier_status (void *cls,
                      const struct GNUNET_TESTBED_BarrierStatusMsg *msg)
{
  uint16_t msize;
  uint16_t name_len;
  int status;
  const char *name;
  size_t emsg_len;

  msize = ntohs (msg->header.size);
  name = msg->data;
  name_len = ntohs (msg->name_len);

  if (sizeof (struct GNUNET_TESTBED_BarrierStatusMsg) + name_len + 1 > msize)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if ('\0' != name[name_len])
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  status = ntohs (msg->status);
  if (GNUNET_TESTBED_BARRIERSTATUS_ERROR == status)
  {
    emsg_len = msize - (sizeof (struct GNUNET_TESTBED_BarrierStatusMsg) + name_len
                        + 1); /* +1!? */
    if (0 == emsg_len)
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  }
  return GNUNET_OK;
}


/**
 * Handler for #GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_STATUS messages
 *
 * @param cls the controller handle to determine the connection this message
 *   belongs to
 * @param msg the barrier status message
 */
static void
handle_barrier_status (void *cls,
                       const struct GNUNET_TESTBED_BarrierStatusMsg *msg)
{
  struct GNUNET_TESTBED_Controller *c = cls;
  struct GNUNET_TESTBED_Barrier *barrier;
  char *emsg;
  const char *name;
  struct GNUNET_HashCode key;
  size_t emsg_len;
  int status;
  uint16_t msize;
  uint16_t name_len;

  emsg = NULL;
  barrier = NULL;
  msize = ntohs (msg->header.size);
  if (msize <= sizeof (struct GNUNET_TESTBED_BarrierStatusMsg))
  {
    GNUNET_break_op (0);
    goto cleanup;
  }
  name = msg->data;
  name_len = ntohs (msg->name_len);
  if (name_len >=  //name_len is strlen(barrier_name)
      (msize - ((sizeof msg->header) + sizeof (msg->status)) )   )
  {
    GNUNET_break_op (0);
    goto cleanup;
  }
  if ('\0' != name[name_len])
  {
    GNUNET_break_op (0);
    goto cleanup;
  }
  LOG_DEBUG ("Received BARRIER_STATUS msg\n");
  status = ntohs (msg->status);
  if (GNUNET_TESTBED_BARRIERSTATUS_ERROR == status)
  {
    status = -1;
    //unlike name_len, emsg_len includes the trailing zero
    emsg_len = msize - (sizeof (struct GNUNET_TESTBED_BarrierStatusMsg)
                        + (name_len + 1));
    if (0 == emsg_len)
    {
      GNUNET_break_op (0);
      goto cleanup;
    }
    if ('\0' != (msg->data[(name_len + 1) + (emsg_len - 1)]))
    {
      GNUNET_break_op (0);
      goto cleanup;
    }
    emsg = GNUNET_malloc (emsg_len);
    GNUNET_memcpy (emsg,
                   msg->data + name_len + 1,
                   emsg_len);
  }
  if (NULL == c->barrier_map)
  {
    GNUNET_break_op (0);
    goto cleanup;
  }
  GNUNET_CRYPTO_hash (name, name_len, &key);
  barrier = GNUNET_CONTAINER_multihashmap_get (c->barrier_map, &key);
  if (NULL == barrier)
  {
    GNUNET_break_op (0);
    goto cleanup;
  }
  GNUNET_assert (NULL != barrier->cb);
  if ((GNUNET_YES == barrier->echo) &&
      (GNUNET_TESTBED_BARRIERSTATUS_CROSSED == status))
    GNUNET_TESTBED_queue_message_ (c,
                                   GNUNET_copy_message (&msg->header));
  barrier->cb (barrier->cls,
               name,
               barrier,
               status,
               emsg);
  if (GNUNET_TESTBED_BARRIERSTATUS_INITIALISED == status)
    return;           /* just initialised; skip cleanup */

 cleanup:
  GNUNET_free_non_null (emsg);
  /**
   * Do not remove the barrier if we did not echo the status back; this is
   * required at the chained testbed controller setup to ensure the only the
   * test-driver echos the status and the controller hierarchy properly
   * propagates the status.
   */
  if ((NULL != barrier) && (GNUNET_YES == barrier->echo))
    GNUNET_TESTBED_barrier_remove_ (barrier);
}


/**
 * Queues a message in send queue for sending to the service
 *
 * @param controller the handle to the controller
 * @param msg the message to queue
 */
void
GNUNET_TESTBED_queue_message_ (struct GNUNET_TESTBED_Controller *controller,
                               struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *m2;
  uint16_t type;
  uint16_t size;

  type = ntohs (msg->type);
  size = ntohs (msg->size);
  GNUNET_assert ((GNUNET_MESSAGE_TYPE_TESTBED_INIT <= type) &&
                 (GNUNET_MESSAGE_TYPE_TESTBED_MAX > type));
  env = GNUNET_MQ_msg_extra (m2,
                             size - sizeof (*m2),
                             type);
  GNUNET_memcpy (m2, msg, size);
  GNUNET_free (msg);
  GNUNET_MQ_send (controller->mq,
                  env);
}


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
                                       void *cc_cls)
{
  struct OperationContext *opc;
  struct ForwardedOperationData *data;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *m2;
  uint16_t type = ntohs (msg->type);
  uint16_t size = ntohs (msg->size);

  env = GNUNET_MQ_msg_extra (m2,
                             size - sizeof (*m2),
                             type);
  GNUNET_memcpy (m2,
                 msg,
                 size);
  GNUNET_MQ_send (controller->mq,
                  env);
  data = GNUNET_new (struct ForwardedOperationData);
  data->cc = cc;
  data->cc_cls = cc_cls;
  opc = GNUNET_new (struct OperationContext);
  opc->c = controller;
  opc->type = OP_FORWARDED;
  opc->data = data;
  opc->id = operation_id;
  GNUNET_TESTBED_insert_opc_ (controller,
                              opc);
  return opc;
}


/**
 * Function to cancel an operation created by simply forwarding an operation
 * message.
 *
 * @param opc the operation context from GNUNET_TESTBED_forward_operation_msg_()
 */
void
GNUNET_TESTBED_forward_operation_msg_cancel_ (struct OperationContext *opc)
{
  GNUNET_TESTBED_remove_opc_ (opc->c,
                              opc);
  GNUNET_free (opc->data);
  GNUNET_free (opc);
}


/**
 * Function to call to start a link-controllers type operation once all queues
 * the operation is part of declare that the operation can be activated.
 *
 * @param cls the closure from GNUNET_TESTBED_operation_create_()
 */
static void
opstart_link_controllers (void *cls)
{
  struct OperationContext *opc = cls;
  struct ControllerLinkData *data;
  struct GNUNET_TESTBED_ControllerLinkRequest *msg;

  GNUNET_assert (NULL != opc->data);
  data = opc->data;
  msg = data->msg;
  data->msg = NULL;
  opc->state = OPC_STATE_STARTED;
  GNUNET_TESTBED_insert_opc_ (opc->c, opc);
  GNUNET_TESTBED_queue_message_ (opc->c, &msg->header);
}


/**
 * Callback which will be called when link-controllers type operation is released
 *
 * @param cls the closure from GNUNET_TESTBED_operation_create_()
 */
static void
oprelease_link_controllers (void *cls)
{
  struct OperationContext *opc = cls;
  struct ControllerLinkData *data;

  data = opc->data;
  switch (opc->state)
  {
  case OPC_STATE_INIT:
    GNUNET_free (data->msg);
    break;
  case OPC_STATE_STARTED:
    GNUNET_TESTBED_remove_opc_ (opc->c, opc);
    break;
  case OPC_STATE_FINISHED:
    break;
  }
  GNUNET_free_non_null (data);
  GNUNET_free (opc);
}


/**
 * Function to be called when get slave config operation is ready
 *
 * @param cls the OperationContext of type OP_GET_SLAVE_CONFIG
 */
static void
opstart_get_slave_config (void *cls)
{
  struct OperationContext *opc = cls;
  struct GetSlaveConfigData *data = opc->data;
  struct GNUNET_TESTBED_SlaveGetConfigurationMessage *msg;

  GNUNET_assert (NULL != data);
  msg = GNUNET_TESTBED_generate_slavegetconfig_msg_ (opc->id, data->slave_id);
  GNUNET_free (opc->data);
  data = NULL;
  opc->data = NULL;
  GNUNET_TESTBED_insert_opc_ (opc->c, opc);
  GNUNET_TESTBED_queue_message_ (opc->c, &msg->header);
  opc->state = OPC_STATE_STARTED;
}


/**
 * Function to be called when get slave config operation is cancelled or finished
 *
 * @param cls the OperationContext of type OP_GET_SLAVE_CONFIG
 */
static void
oprelease_get_slave_config (void *cls)
{
  struct OperationContext *opc = cls;

  switch (opc->state)
  {
  case OPC_STATE_INIT:
    GNUNET_free (opc->data);
    break;
  case OPC_STATE_STARTED:
    GNUNET_TESTBED_remove_opc_ (opc->c, opc);
    break;
  case OPC_STATE_FINISHED:
    if (NULL != opc->data)
      GNUNET_CONFIGURATION_destroy (opc->data);
    break;
  }
  GNUNET_free (opc);
}


/**
 * Generic error handler, called with the appropriate error code and
 * the same closure specified at the creation of the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure, a `struct GNUNET_TESTBED_Controller *`
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  /* struct GNUNET_TESTBED_Controller *c = cls; */

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Encountered MQ error: %d\n",
              error);
  /* now what? */
  GNUNET_SCHEDULER_shutdown (); /* seems most reasonable */
}


/**
 * Start a controller process using the given configuration at the
 * given host.
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
                                   void *cc_cls)
{
  struct GNUNET_TESTBED_Controller *controller
    = GNUNET_new (struct GNUNET_TESTBED_Controller);
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (add_host_confirm,
                           GNUNET_MESSAGE_TYPE_TESTBED_ADD_HOST_SUCCESS,
                           struct GNUNET_TESTBED_HostConfirmedMessage,
                           controller),
    GNUNET_MQ_hd_fixed_size (peer_conevent,
                             GNUNET_MESSAGE_TYPE_TESTBED_PEER_CONNECT_EVENT,
                             struct GNUNET_TESTBED_ConnectionEventMessage,
                             controller),
    GNUNET_MQ_hd_fixed_size (opsuccess,
                             GNUNET_MESSAGE_TYPE_TESTBED_GENERIC_OPERATION_SUCCESS,
                             struct GNUNET_TESTBED_GenericOperationSuccessEventMessage,
                             controller),
    GNUNET_MQ_hd_var_size (op_fail_event,
                           GNUNET_MESSAGE_TYPE_TESTBED_OPERATION_FAIL_EVENT,
                           struct GNUNET_TESTBED_OperationFailureEventMessage,
                           controller),
    GNUNET_MQ_hd_fixed_size (peer_create_success,
                             GNUNET_MESSAGE_TYPE_TESTBED_CREATE_PEER_SUCCESS,
                             struct GNUNET_TESTBED_PeerCreateSuccessEventMessage,
                             controller),
    GNUNET_MQ_hd_fixed_size (peer_event,
                             GNUNET_MESSAGE_TYPE_TESTBED_PEER_EVENT,
                             struct GNUNET_TESTBED_PeerEventMessage,
                             controller),
    GNUNET_MQ_hd_var_size (peer_config,
                           GNUNET_MESSAGE_TYPE_TESTBED_PEER_INFORMATION,
                           struct GNUNET_TESTBED_PeerConfigurationInformationMessage,
                           controller),
    GNUNET_MQ_hd_var_size (slave_config,
                           GNUNET_MESSAGE_TYPE_TESTBED_SLAVE_CONFIGURATION,
                           struct GNUNET_TESTBED_SlaveConfiguration,
                           controller),
    GNUNET_MQ_hd_var_size (link_controllers_result,
                           GNUNET_MESSAGE_TYPE_TESTBED_LINK_CONTROLLERS_RESULT,
                           struct GNUNET_TESTBED_ControllerLinkResponse,
                           controller),
    GNUNET_MQ_hd_var_size (barrier_status,
                           GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_STATUS,
                           struct GNUNET_TESTBED_BarrierStatusMsg,
                           controller),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_TESTBED_InitMessage *msg;
  struct GNUNET_MQ_Envelope *env;
  const struct GNUNET_CONFIGURATION_Handle *cfg;
  const char *controller_hostname;
  unsigned long long max_parallel_operations;
  unsigned long long max_parallel_service_connections;
  unsigned long long max_parallel_topology_config_operations;
  size_t slen;

  GNUNET_assert (NULL != (cfg = GNUNET_TESTBED_host_get_cfg_ (host)));
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "testbed",
                                             "MAX_PARALLEL_OPERATIONS",
                                             &max_parallel_operations))
  {
    GNUNET_break (0);
    GNUNET_free (controller);
    return NULL;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "testbed",
                                             "MAX_PARALLEL_SERVICE_CONNECTIONS",
                                             &max_parallel_service_connections))
  {
    GNUNET_break (0);
    GNUNET_free (controller);
    return NULL;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "testbed",
                                             "MAX_PARALLEL_TOPOLOGY_CONFIG_OPERATIONS",
                                             &max_parallel_topology_config_operations))
  {
    GNUNET_break (0);
    GNUNET_free (controller);
    return NULL;
  }
  controller->cc = cc;
  controller->cc_cls = cc_cls;
  controller->event_mask = event_mask;
  controller->cfg = GNUNET_CONFIGURATION_dup (cfg);
  controller->mq = GNUNET_CLIENT_connect (controller->cfg,
                                          "testbed",
                                          handlers,
                                          &mq_error_handler,
                                          controller);
  if (NULL == controller->mq)
  {
    GNUNET_break (0);
    GNUNET_TESTBED_controller_disconnect (controller);
    return NULL;
  }
  GNUNET_TESTBED_mark_host_registered_at_ (host, controller);
  controller->host = host;
  controller->opq_parallel_operations =
      GNUNET_TESTBED_operation_queue_create_ (OPERATION_QUEUE_TYPE_FIXED,
                                              (unsigned int) max_parallel_operations);
  controller->opq_parallel_service_connections =
      GNUNET_TESTBED_operation_queue_create_ (OPERATION_QUEUE_TYPE_FIXED,
                                              (unsigned int)
                                              max_parallel_service_connections);
  controller->opq_parallel_topology_config_operations =
      GNUNET_TESTBED_operation_queue_create_ (OPERATION_QUEUE_TYPE_FIXED,
                                              (unsigned int)
                                              max_parallel_topology_config_operations);
  controller_hostname = GNUNET_TESTBED_host_get_hostname (host);
  if (NULL == controller_hostname)
    controller_hostname = "127.0.0.1";
  slen = strlen (controller_hostname) + 1;
  env = GNUNET_MQ_msg_extra (msg,
                             slen,
                             GNUNET_MESSAGE_TYPE_TESTBED_INIT);
  msg->host_id = htonl (GNUNET_TESTBED_host_get_id_ (host));
  msg->event_mask = GNUNET_htonll (controller->event_mask);
  GNUNET_memcpy (&msg[1],
                 controller_hostname,
                 slen);
  GNUNET_MQ_send (controller->mq,
                  env);
  return controller;
}


/**
 * Iterator to free opc map entries
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES if we should continue to iterate,
 *         #GNUNET_NO if not.
 */
static int
opc_free_iterator (void *cls, uint32_t key, void *value)
{
  struct GNUNET_CONTAINER_MultiHashMap32 *map = cls;
  struct OperationContext *opc = value;

  GNUNET_assert (NULL != opc);
  GNUNET_break (0);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap32_remove (map, key, value));
  GNUNET_free (opc);
  return GNUNET_YES;
}


/**
 * Stop the given controller (also will terminate all peers and
 * controllers dependent on this controller).  This function
 * blocks until the testbed has been fully terminated (!).
 *
 * @param c handle to controller to stop
 */
void
GNUNET_TESTBED_controller_disconnect (struct GNUNET_TESTBED_Controller *c)
{
  if (NULL != c->mq)
  {
    GNUNET_MQ_destroy (c->mq);
    c->mq = NULL;
  }
  if (NULL != c->host)
    GNUNET_TESTBED_deregister_host_at_ (c->host, c);
  GNUNET_CONFIGURATION_destroy (c->cfg);
  GNUNET_TESTBED_operation_queue_destroy_ (c->opq_parallel_operations);
  GNUNET_TESTBED_operation_queue_destroy_
      (c->opq_parallel_service_connections);
  GNUNET_TESTBED_operation_queue_destroy_
      (c->opq_parallel_topology_config_operations);
  if (NULL != c->opc_map)
  {
    GNUNET_assert (GNUNET_SYSERR !=
                   GNUNET_CONTAINER_multihashmap32_iterate (c->opc_map,
                                                            &opc_free_iterator,
                                                            c->opc_map));
    GNUNET_assert (0 == GNUNET_CONTAINER_multihashmap32_size (c->opc_map));
    GNUNET_CONTAINER_multihashmap32_destroy (c->opc_map);
  }
  GNUNET_free (c);
}


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
                                 char **xconfig)
{
  size_t xsize;

  xsize = compressBound ((uLong) size);
  *xconfig = GNUNET_malloc (xsize);
  GNUNET_assert (Z_OK ==
                 compress2 ((Bytef *) * xconfig, (uLongf *) & xsize,
                            (const Bytef *) config, (uLongf) size,
                            Z_BEST_SPEED));
  return xsize;
}


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
                              size_t *size, size_t *xsize)
{
  char *config;
  char *xconfig;
  size_t size_;
  size_t xsize_;

  config = GNUNET_CONFIGURATION_serialize (cfg, &size_);
  xsize_ = GNUNET_TESTBED_compress_config_ (config, size_, &xconfig);
  GNUNET_free (config);
  *size = size_;
  *xsize = xsize_;
  return xconfig;
}


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
                                int is_subordinate)
{
  struct OperationContext *opc;
  struct GNUNET_TESTBED_ControllerLinkRequest *msg;
  struct ControllerLinkData *data;
  uint32_t slave_host_id;
  uint32_t delegated_host_id;
  uint16_t msg_size;

  GNUNET_assert (GNUNET_YES ==
                 GNUNET_TESTBED_is_host_registered_ (delegated_host, master));
  slave_host_id =
      GNUNET_TESTBED_host_get_id_ ((NULL !=
                                    slave_host) ? slave_host : master->host);
  delegated_host_id = GNUNET_TESTBED_host_get_id_ (delegated_host);
  if ((NULL != slave_host) && (0 != slave_host_id))
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_TESTBED_is_host_registered_ (slave_host, master));
  msg_size = sizeof (struct GNUNET_TESTBED_ControllerLinkRequest);
  msg = GNUNET_malloc (msg_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_LINK_CONTROLLERS);
  msg->header.size = htons (msg_size);
  msg->delegated_host_id = htonl (delegated_host_id);
  msg->slave_host_id = htonl (slave_host_id);
  msg->is_subordinate = (GNUNET_YES == is_subordinate) ? 1 : 0;
  data = GNUNET_new (struct ControllerLinkData);
  data->msg = msg;
  data->host_id = delegated_host_id;
  opc = GNUNET_new (struct OperationContext);
  opc->c = master;
  opc->data = data;
  opc->type = OP_LINK_CONTROLLERS;
  opc->id = GNUNET_TESTBED_get_next_op_id (opc->c);
  opc->state = OPC_STATE_INIT;
  opc->op_cls = op_cls;
  msg->operation_id = GNUNET_htonll (opc->id);
  opc->op =
      GNUNET_TESTBED_operation_create_ (opc, &opstart_link_controllers,
                                        &oprelease_link_controllers);
  GNUNET_TESTBED_operation_queue_insert_ (master->opq_parallel_operations,
                                          opc->op);
  GNUNET_TESTBED_operation_begin_wait_ (opc->op);
  return opc->op;
}


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
                                  uint32_t slave_host_id)
{
  struct OperationContext *opc;
  struct GetSlaveConfigData *data;

  data = GNUNET_new (struct GetSlaveConfigData);
  data->slave_id = slave_host_id;
  opc = GNUNET_new (struct OperationContext);
  opc->state = OPC_STATE_INIT;
  opc->c = master;
  opc->id = GNUNET_TESTBED_get_next_op_id (master);
  opc->type = OP_GET_SLAVE_CONFIG;
  opc->data = data;
  opc->op_cls = op_cls;
  opc->op =
      GNUNET_TESTBED_operation_create_ (opc, &opstart_get_slave_config,
                                        &oprelease_get_slave_config);
  GNUNET_TESTBED_operation_queue_insert_ (master->opq_parallel_operations,
                                          opc->op);
  GNUNET_TESTBED_operation_begin_wait_ (opc->op);
  return opc->op;
}


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
                                 struct GNUNET_TESTBED_Host *slave_host)
{
  if (GNUNET_NO == GNUNET_TESTBED_is_host_registered_ (slave_host, master))
    return NULL;
  return GNUNET_TESTBED_get_slave_config_ (op_cls, master,
                                           GNUNET_TESTBED_host_get_id_
                                           (slave_host));
}


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
GNUNET_TESTBED_overlay_write_topology_to_file (struct GNUNET_TESTBED_Controller
                                               *controller,
                                               const char *filename)
{
  GNUNET_break (0);
}


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
GNUNET_TESTBED_create_helper_init_msg_ (const char *trusted_ip,
                                        const char *hostname,
                                        const struct GNUNET_CONFIGURATION_Handle
                                        *cfg)
{
  struct GNUNET_TESTBED_HelperInit *msg;
  char *config;
  char *xconfig;
  size_t config_size;
  size_t xconfig_size;
  uint16_t trusted_ip_len;
  uint16_t hostname_len;
  uint16_t msg_size;

  config = GNUNET_CONFIGURATION_serialize (cfg, &config_size);
  GNUNET_assert (NULL != config);
  xconfig_size =
      GNUNET_TESTBED_compress_config_ (config, config_size, &xconfig);
  GNUNET_free (config);
  trusted_ip_len = strlen (trusted_ip);
  hostname_len = (NULL == hostname) ? 0 : strlen (hostname);
  msg_size =
      xconfig_size + trusted_ip_len + 1 +
      sizeof (struct GNUNET_TESTBED_HelperInit);
  msg_size += hostname_len;
  msg = GNUNET_realloc (xconfig, msg_size);
  (void) memmove (((void *) &msg[1]) + trusted_ip_len + 1 + hostname_len, msg,
                  xconfig_size);
  msg->header.size = htons (msg_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_HELPER_INIT);
  msg->trusted_ip_size = htons (trusted_ip_len);
  msg->hostname_size = htons (hostname_len);
  msg->config_size = htons (config_size);
  (void) strcpy ((char *) &msg[1], trusted_ip);
  if (0 != hostname_len)
    (void) strncpy (((char *) &msg[1]) + trusted_ip_len + 1, hostname,
                    hostname_len);
  return msg;
}


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
GNUNET_TESTBED_operation_done (struct GNUNET_TESTBED_Operation *operation)
{
  (void) exop_check (operation);
  GNUNET_TESTBED_operation_release_ (operation);
}


/**
 * Generates configuration by uncompressing configuration in given message. The
 * given message should be of the following types:
 * #GNUNET_MESSAGE_TYPE_TESTBED_PEER_INFORMATION,
 * #GNUNET_MESSAGE_TYPE_TESTBED_SLAVE_CONFIGURATION,
 * #GNUNET_MESSAGE_TYPE_TESTBED_ADD_HOST,
 * #GNUNET_MESSAGE_TYPE_TESTBED_LINK_CONTROLLERS,
 * #GNUNET_MESSAGE_TYPE_TESTBED_LINK_CONTROLLERS_RESULT,
 *
 * FIXME: This API is incredibly ugly.
 *
 * @param msg the message containing compressed configuration
 * @return handle to the parsed configuration; NULL upon error while parsing the message
 */
struct GNUNET_CONFIGURATION_Handle *
GNUNET_TESTBED_extract_config_ (const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  Bytef *data;
  const Bytef *xdata;
  uLong data_len;
  uLong xdata_len;
  int ret;

  switch (ntohs (msg->type))
  {
  case GNUNET_MESSAGE_TYPE_TESTBED_PEER_INFORMATION:
  {
    const struct GNUNET_TESTBED_PeerConfigurationInformationMessage *imsg;

    imsg =
        (const struct GNUNET_TESTBED_PeerConfigurationInformationMessage *) msg;
    data_len = (uLong) ntohs (imsg->config_size);
    xdata_len =
        ntohs (imsg->header.size) -
        sizeof (struct GNUNET_TESTBED_PeerConfigurationInformationMessage);
    xdata = (const Bytef *) &imsg[1];
  }
    break;
  case GNUNET_MESSAGE_TYPE_TESTBED_SLAVE_CONFIGURATION:
  {
    const struct GNUNET_TESTBED_SlaveConfiguration *imsg;

    imsg = (const struct GNUNET_TESTBED_SlaveConfiguration *) msg;
    data_len = (uLong) ntohs (imsg->config_size);
    xdata_len =
        ntohs (imsg->header.size) -
        sizeof (struct GNUNET_TESTBED_SlaveConfiguration);
    xdata = (const Bytef *) &imsg[1];
  }
  break;
  case GNUNET_MESSAGE_TYPE_TESTBED_ADD_HOST:
    {
      const struct GNUNET_TESTBED_AddHostMessage *imsg;
      uint16_t osize;

      imsg = (const struct GNUNET_TESTBED_AddHostMessage *) msg;
      data_len = (uLong) ntohs (imsg->config_size);
      osize = sizeof (struct GNUNET_TESTBED_AddHostMessage) +
          ntohs (imsg->username_length) + ntohs (imsg->hostname_length);
      xdata_len = ntohs (imsg->header.size) - osize;
      xdata = (const Bytef *) ((const void *) imsg + osize);
    }
    break;
  case GNUNET_MESSAGE_TYPE_TESTBED_LINK_CONTROLLERS_RESULT:
    {
      const struct GNUNET_TESTBED_ControllerLinkResponse *imsg;

      imsg = (const struct GNUNET_TESTBED_ControllerLinkResponse *) msg;
      data_len = ntohs (imsg->config_size);
      xdata_len = ntohs (imsg->header.size) -
          sizeof (const struct GNUNET_TESTBED_ControllerLinkResponse);
      xdata = (const Bytef *) &imsg[1];
    }
    break;
  case GNUNET_MESSAGE_TYPE_TESTBED_CREATE_PEER:
    {
      const struct GNUNET_TESTBED_PeerCreateMessage *imsg;

      imsg = (const struct GNUNET_TESTBED_PeerCreateMessage *) msg;
      data_len = ntohs (imsg->config_size);
      xdata_len = ntohs (imsg->header.size) -
          sizeof (struct GNUNET_TESTBED_PeerCreateMessage);
      xdata = (const Bytef *) &imsg[1];
    }
    break;
  case GNUNET_MESSAGE_TYPE_TESTBED_RECONFIGURE_PEER:
    {
      const struct GNUNET_TESTBED_PeerReconfigureMessage *imsg;

      imsg = (const struct GNUNET_TESTBED_PeerReconfigureMessage *) msg;
      data_len =  ntohs (imsg->config_size);
      xdata_len = ntohs (imsg->header.size) -
          sizeof (struct GNUNET_TESTBED_PeerReconfigureMessage);
      xdata = (const Bytef *) &imsg[1];
    }
    break;
  default:
    GNUNET_assert (0);
  }
  data = GNUNET_malloc (data_len);
  if (Z_OK != (ret = uncompress (data, &data_len, xdata, xdata_len)))
  {
    GNUNET_free (data);
    GNUNET_break_op (0);        /* Un-compression failure */
    return NULL;
  }
  cfg = GNUNET_CONFIGURATION_create ();
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_deserialize (cfg,
					(const char *) data,
                                        (size_t) data_len,
                                        NULL))
  {
    GNUNET_free (data);
    GNUNET_break_op (0);        /* De-serialization failure */
    return NULL;
  }
  GNUNET_free (data);
  return cfg;
}


/**
 * Checks the integrity of the OperationFailureEventMessage and if good returns
 * the error message it contains.
 *
 * @param msg the OperationFailureEventMessage
 * @return the error message
 */
const char *
GNUNET_TESTBED_parse_error_string_ (const struct
                                    GNUNET_TESTBED_OperationFailureEventMessage
                                    *msg)
{
  uint16_t msize;
  const char *emsg;

  msize = ntohs (msg->header.size);
  if (sizeof (struct GNUNET_TESTBED_OperationFailureEventMessage) >= msize)
    return NULL;
  msize -= sizeof (struct GNUNET_TESTBED_OperationFailureEventMessage);
  emsg = (const char *) &msg[1];
  if ('\0' != emsg[msize - 1])
  {
    GNUNET_break (0);
    return NULL;
  }
  return emsg;
}


/**
 * Function to return the operation id for a controller. The operation id is
 * created from the controllers host id and its internal operation counter.
 *
 * @param controller the handle to the controller whose operation id has to be incremented
 * @return the incremented operation id.
 */
uint64_t
GNUNET_TESTBED_get_next_op_id (struct GNUNET_TESTBED_Controller * controller)
{
  uint64_t op_id;

  op_id = (uint64_t) GNUNET_TESTBED_host_get_id_ (controller->host);
  op_id = op_id << 32;
  op_id |= (uint64_t) controller->operation_counter++;
  return op_id;
}


/**
 * Function called when a shutdown peers operation is ready
 *
 * @param cls the closure from GNUNET_TESTBED_operation_create_()
 */
static void
opstart_shutdown_peers (void *cls)
{
  struct OperationContext *opc = cls;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_TESTBED_ShutdownPeersMessage *msg;

  opc->state = OPC_STATE_STARTED;
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_TESTBED_SHUTDOWN_PEERS);
  msg->operation_id = GNUNET_htonll (opc->id);
  GNUNET_TESTBED_insert_opc_ (opc->c,
                              opc);
  GNUNET_MQ_send (opc->c->mq,
                  env);
}


/**
 * Callback which will be called when shutdown peers operation is released
 *
 * @param cls the closure from GNUNET_TESTBED_operation_create_()
 */
static void
oprelease_shutdown_peers (void *cls)
{
  struct OperationContext *opc = cls;

  switch (opc->state)
  {
  case OPC_STATE_STARTED:
    GNUNET_TESTBED_remove_opc_ (opc->c, opc);
    /* no break; continue */
  case OPC_STATE_INIT:
    GNUNET_free (opc->data);
    break;
  case OPC_STATE_FINISHED:
    break;
  }
  GNUNET_free (opc);
}


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
                               void *cb_cls)
{
  struct OperationContext *opc;
  struct ShutdownPeersData *data;

  if (0 != GNUNET_CONTAINER_multihashmap32_size (c->opc_map))
    return NULL;
  data = GNUNET_new (struct ShutdownPeersData);
  data->cb = cb;
  data->cb_cls = cb_cls;
  opc = GNUNET_new (struct OperationContext);
  opc->c = c;
  opc->op_cls = op_cls;
  opc->data = data;
  opc->id =  GNUNET_TESTBED_get_next_op_id (c);
  opc->type = OP_SHUTDOWN_PEERS;
  opc->state = OPC_STATE_INIT;
  opc->op = GNUNET_TESTBED_operation_create_ (opc, &opstart_shutdown_peers,
                                              &oprelease_shutdown_peers);
  GNUNET_TESTBED_operation_queue_insert_ (opc->c->opq_parallel_operations,
                                        opc->op);
  GNUNET_TESTBED_operation_begin_wait_ (opc->op);
  return opc->op;
}


/**
 * Return the index of the peer inside of the total peer array,
 * aka. the peer's "unique ID".
 *
 * @param peer Peer handle.
 *
 * @return The peer's unique ID.
 */
uint32_t
GNUNET_TESTBED_get_index (const struct GNUNET_TESTBED_Peer *peer)
{
  return peer->unique_id;
}


/**
 * Remove a barrier and it was the last one in the barrier hash map, destroy the
 * hash map
 *
 * @param barrier the barrier to remove
 */
void
GNUNET_TESTBED_barrier_remove_ (struct GNUNET_TESTBED_Barrier *barrier)
{
  struct GNUNET_TESTBED_Controller *c = barrier->c;

  GNUNET_assert (NULL != c->barrier_map); /* No barriers present */
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap_remove (c->barrier_map,
                                                       &barrier->key,
                                                       barrier));
  GNUNET_free (barrier->name);
  GNUNET_free (barrier);
  if (0 == GNUNET_CONTAINER_multihashmap_size (c->barrier_map))
  {
    GNUNET_CONTAINER_multihashmap_destroy (c->barrier_map);
    c->barrier_map = NULL;
  }
}


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
 * @param echo GNUNET_YES to echo the barrier crossed status message back to the
 *   controller
 * @return barrier handle; NULL upon error
 */
struct GNUNET_TESTBED_Barrier *
GNUNET_TESTBED_barrier_init_ (struct GNUNET_TESTBED_Controller *controller,
                              const char *name,
                              unsigned int quorum,
                              GNUNET_TESTBED_barrier_status_cb cb, void *cls,
                              int echo)
{
  struct GNUNET_TESTBED_BarrierInit *msg;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_TESTBED_Barrier *barrier;
  struct GNUNET_HashCode key;
  size_t name_len;

  GNUNET_assert (quorum <= 100);
  GNUNET_assert (NULL != cb);
  name_len = strlen (name);
  GNUNET_assert (0 < name_len);
  GNUNET_CRYPTO_hash (name, name_len, &key);
  if (NULL == controller->barrier_map)
    controller->barrier_map = GNUNET_CONTAINER_multihashmap_create (3, GNUNET_YES);
  if (GNUNET_YES ==
      GNUNET_CONTAINER_multihashmap_contains (controller->barrier_map,
                                              &key))
  {
    GNUNET_break (0);
    return NULL;
  }
  LOG_DEBUG ("Initialising barrier `%s'\n", name);
  barrier = GNUNET_new (struct GNUNET_TESTBED_Barrier);
  barrier->c = controller;
  barrier->name = GNUNET_strdup (name);
  barrier->cb = cb;
  barrier->cls = cls;
  barrier->echo = echo;
  GNUNET_memcpy (&barrier->key, &key, sizeof (struct GNUNET_HashCode));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap_put (controller->barrier_map,
                                                    &barrier->key,
                                                    barrier,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST));

  env = GNUNET_MQ_msg_extra (msg,
                             name_len,
                             GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_INIT);
  msg->quorum = (uint8_t) quorum;
  GNUNET_memcpy (msg->name,
                 barrier->name,
                 name_len);
  GNUNET_MQ_send (barrier->c->mq,
                  env);
  return barrier;
}


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
 * @return barrier handle; NULL upon error
 */
struct GNUNET_TESTBED_Barrier *
GNUNET_TESTBED_barrier_init (struct GNUNET_TESTBED_Controller *controller,
                             const char *name,
                             unsigned int quorum,
                             GNUNET_TESTBED_barrier_status_cb cb, void *cls)
{
  return GNUNET_TESTBED_barrier_init_ (controller,
                                       name, quorum, cb, cls, GNUNET_YES);
}


/**
 * Cancel a barrier.
 *
 * @param barrier the barrier handle
 */
void
GNUNET_TESTBED_barrier_cancel (struct GNUNET_TESTBED_Barrier *barrier)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_TESTBED_BarrierCancel *msg;
  size_t slen;

  slen = strlen (barrier->name);
  env = GNUNET_MQ_msg_extra (msg,
                             slen,
                             GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_CANCEL);
  GNUNET_memcpy (msg->name,
                 barrier->name,
                 slen);
  GNUNET_MQ_send (barrier->c->mq,
                  env);
  GNUNET_TESTBED_barrier_remove_ (barrier);
}


/* end of testbed_api.c */
