/*
  This file is part of GNUnet.
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
  Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
  Boston, MA 02110-1301, USA.
*/


/**
 * @file testbed/gnunet-service-testbed_peers.c
 * @brief implementation of TESTBED service that deals with peer management
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */

#include "gnunet-service-testbed.h"
#include "gnunet_arm_service.h"
#include <zlib.h>


/**
 * A list of peers we know about
 */
struct Peer **GST_peer_list;

/**
 * The current number of peers running locally under this controller
 */
unsigned int GST_num_local_peers;


/**
 * Context information to manage peers' services
 */
struct ManageServiceContext
{
  /**
   * DLL next ptr
   */
  struct ManageServiceContext *next;

  /**
   * DLL prev ptr
   */
  struct ManageServiceContext *prev;

  /**
   * The ARM handle of the peer
   */
  struct GNUNET_ARM_Handle *ah;

  /**
   * peer whose service has to be managed
   */
  struct Peer *peer;

  /**
   * The client which requested to manage the peer's service
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * The operation id of the associated request
   */
  uint64_t op_id;

  /**
   * 1 if the service at the peer has to be started; 0 if it has to be stopped
   */
  uint8_t start;

  /**
   * Is this context expired?  Do not work on this context if it is set to
   * GNUNET_YES
   */
  uint8_t expired;
};


/**
 * Context information for peer re-configure operations
 */
struct PeerReconfigureContext
{
  /**
   * DLL next for inclusoin in peer reconfigure operations list
   */
  struct PeerReconfigureContext *next;

  /**
   * DLL prev
   */
  struct PeerReconfigureContext *prev;

  /**
   * The client which gave this operation to us
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * The configuration handle to use as the new template
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * The id of the operation
   */
  uint64_t op_id;

  /**
   * The id of the peer which has to be reconfigured
   */
  uint32_t peer_id;

  /**
   * The the peer stopped?  Used while cleaning up this context to decide
   * whether the asynchronous stop request through Testing/ARM API has to be
   * cancelled
   */
  uint8_t stopped;
};

/**
 * The DLL head for the peer reconfigure list
 */
static struct PeerReconfigureContext *prc_head;

/**
 * The DLL tail for the peer reconfigure list
 */
static struct PeerReconfigureContext *prc_tail;



/**
 * DLL head for queue of manage service requests
 */
static struct ManageServiceContext *mctx_head;

/**
 * DLL tail for queue of manage service requests
 */
static struct ManageServiceContext *mctx_tail;


/**
 * Adds a peer to the peer array
 *
 * @param peer the peer to add
 */
static void
peer_list_add (struct Peer *peer)
{
  if (peer->id >= GST_peer_list_size)
    GST_array_grow_large_enough (GST_peer_list, GST_peer_list_size, peer->id);
  GNUNET_assert (NULL == GST_peer_list[peer->id]);
  GST_peer_list[peer->id] = peer;
  if (GNUNET_NO == peer->is_remote)
    GST_num_local_peers++;
}


/**
 * Removes a the give peer from the peer array
 *
 * @param peer the peer to be removed
 */
static void
peer_list_remove (struct Peer *peer)
{
  unsigned int orig_size;
  uint32_t id;

  if (GNUNET_NO == peer->is_remote)
    GST_num_local_peers--;
  GST_peer_list[peer->id] = NULL;
  orig_size = GST_peer_list_size;
  while (GST_peer_list_size >= LIST_GROW_STEP)
  {
    for (id = GST_peer_list_size - 1;
         (id >= GST_peer_list_size - LIST_GROW_STEP) && (id != UINT32_MAX);
         id--)
      if (NULL != GST_peer_list[id])
        break;
    if (id != ((GST_peer_list_size - LIST_GROW_STEP) - 1))
      break;
    GST_peer_list_size -= LIST_GROW_STEP;
  }
  if (orig_size == GST_peer_list_size)
    return;
  GST_peer_list =
      GNUNET_realloc (GST_peer_list,
                      sizeof (struct Peer *) * GST_peer_list_size);
}


/**
 * The task to be executed if the forwarded peer create operation has been
 * timed out
 *
 * @param cls the FowardedOperationContext
 * @param tc the TaskContext from the scheduler
 */
static void
peer_create_forward_timeout (void *cls,
                             const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ForwardedOperationContext *fopc = cls;

  GNUNET_free (fopc->cls);
  GST_forwarded_operation_timeout (fopc, tc);
}


/**
 * Callback to be called when forwarded peer create operation is successfull. We
 * have to relay the reply msg back to the client
 *
 * @param cls ForwardedOperationContext
 * @param msg the peer create success message
 */
static void
peer_create_success_cb (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct ForwardedOperationContext *fopc = cls;
  struct Peer *remote_peer;

  if (ntohs (msg->type) == GNUNET_MESSAGE_TYPE_TESTBED_CREATE_PEER_SUCCESS)
  {
    GNUNET_assert (NULL != fopc->cls);
    remote_peer = fopc->cls;
    peer_list_add (remote_peer);
  }
  GST_forwarded_operation_reply_relay (fopc, msg);
}


/**
 * Function to destroy a peer
 *
 * @param peer the peer structure to destroy
 */
void
GST_destroy_peer (struct Peer *peer)
{
  GNUNET_break (0 == peer->reference_cnt);
  if (GNUNET_YES == peer->is_remote)
  {
    peer_list_remove (peer);
    GNUNET_free (peer);
    return;
  }
  if (GNUNET_YES == peer->details.local.is_running)
  {
    GNUNET_TESTING_peer_stop (peer->details.local.peer);
    peer->details.local.is_running = GNUNET_NO;
  }
  GNUNET_TESTING_peer_destroy (peer->details.local.peer);
  GNUNET_CONFIGURATION_destroy (peer->details.local.cfg);
  peer_list_remove (peer);
  GNUNET_free (peer);
}


/**
 * Callback to be called when forwarded peer destroy operation is successfull. We
 * have to relay the reply msg back to the client
 *
 * @param cls ForwardedOperationContext
 * @param msg the peer create success message
 */
static void
peer_destroy_success_cb (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct ForwardedOperationContext *fopc = cls;
  struct Peer *remote_peer;

  if (GNUNET_MESSAGE_TYPE_TESTBED_GENERIC_OPERATION_SUCCESS ==
      ntohs (msg->type))
  {
    remote_peer = fopc->cls;
    GNUNET_assert (NULL != remote_peer);
    remote_peer->destroy_flag = GNUNET_YES;
    if (0 == remote_peer->reference_cnt)
      GST_destroy_peer (remote_peer);
  }
  GST_forwarded_operation_reply_relay (fopc, msg);
}


/**
 * Handler for GNUNET_MESSAGE_TYPE_TESTBED_CREATEPEER messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
void
GST_handle_peer_create (void *cls, struct GNUNET_SERVER_Client *client,
                        const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TESTBED_PeerCreateMessage *msg;
  struct GNUNET_TESTBED_PeerCreateSuccessEventMessage *reply;
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct ForwardedOperationContext *fo_ctxt;
  struct Route *route;
  struct Peer *peer;
  char *emsg;
  uint32_t host_id;
  uint32_t peer_id;
  uint16_t msize;


  msize = ntohs (message->size);
  if (msize <= sizeof (struct GNUNET_TESTBED_PeerCreateMessage))
  {
    GNUNET_break (0);           /* We need configuration */
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  msg = (const struct GNUNET_TESTBED_PeerCreateMessage *) message;
  host_id = ntohl (msg->host_id);
  peer_id = ntohl (msg->peer_id);
  if (VALID_PEER_ID (peer_id))
  {
    (void) GNUNET_asprintf (&emsg, "Peer with ID %u already exists", peer_id);
    GST_send_operation_fail_msg (client, GNUNET_ntohll (msg->operation_id),
                                 emsg);
    GNUNET_free (emsg);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  if (UINT32_MAX == peer_id)
  {
    GST_send_operation_fail_msg (client, GNUNET_ntohll (msg->operation_id),
                                 "Cannot create peer with given ID");
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  if (host_id == GST_context->host_id)
  {
    /* We are responsible for this peer */
    cfg = GNUNET_TESTBED_extract_config_ (message);
    if (NULL == cfg)
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
    GNUNET_CONFIGURATION_set_value_number (cfg, "TESTBED", "PEERID",
                                           (unsigned long long) peer_id);

    GNUNET_CONFIGURATION_set_value_number (cfg, "PATHS", "PEERID",
                                           (unsigned long long) peer_id);
    peer = GNUNET_new (struct Peer);
    peer->is_remote = GNUNET_NO;
    peer->details.local.cfg = cfg;
    peer->id = peer_id;
    LOG_DEBUG ("Creating peer with id: %u\n", (unsigned int) peer->id);
    peer->details.local.peer =
        GNUNET_TESTING_peer_configure (GST_context->system,
                                       peer->details.local.cfg, peer->id,
                                       NULL /* Peer id */ ,
                                       &emsg);
    if (NULL == peer->details.local.peer)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING, "Configuring peer failed: %s\n", emsg);
      GNUNET_free (emsg);
      GNUNET_free (peer);
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
    peer->details.local.is_running = GNUNET_NO;
    peer_list_add (peer);
    reply = GNUNET_new (struct GNUNET_TESTBED_PeerCreateSuccessEventMessage);
    reply->header.size =
        htons (sizeof (struct GNUNET_TESTBED_PeerCreateSuccessEventMessage));
    reply->header.type =
        htons (GNUNET_MESSAGE_TYPE_TESTBED_CREATE_PEER_SUCCESS);
    reply->peer_id = msg->peer_id;
    reply->operation_id = msg->operation_id;
    GST_queue_message (client, &reply->header);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  /* Forward peer create request */
  route = GST_find_dest_route (host_id);
  if (NULL == route)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  peer = GNUNET_new (struct Peer);
  peer->is_remote = GNUNET_YES;
  peer->id = peer_id;
  peer->details.remote.slave = GST_slave_list[route->dest];
  peer->details.remote.remote_host_id = host_id;
  fo_ctxt = GNUNET_new (struct ForwardedOperationContext);
  GNUNET_SERVER_client_keep (client);
  fo_ctxt->client = client;
  fo_ctxt->operation_id = GNUNET_ntohll (msg->operation_id);
  fo_ctxt->cls = peer;
  fo_ctxt->type = OP_PEER_CREATE;
  fo_ctxt->opc =
      GNUNET_TESTBED_forward_operation_msg_ (GST_slave_list
                                             [route->dest]->controller,
                                             fo_ctxt->operation_id,
                                             &msg->header,
                                             peer_create_success_cb, fo_ctxt);
  fo_ctxt->timeout_task =
      GNUNET_SCHEDULER_add_delayed (GST_timeout, &peer_create_forward_timeout,
                                    fo_ctxt);
  GNUNET_CONTAINER_DLL_insert_tail (fopcq_head, fopcq_tail, fo_ctxt);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Message handler for GNUNET_MESSAGE_TYPE_TESTBED_DESTROYPEER messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
void
GST_handle_peer_destroy (void *cls, struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TESTBED_PeerDestroyMessage *msg;
  struct ForwardedOperationContext *fopc;
  struct Peer *peer;
  uint32_t peer_id;

  msg = (const struct GNUNET_TESTBED_PeerDestroyMessage *) message;
  peer_id = ntohl (msg->peer_id);
  LOG_DEBUG ("Received peer destory on peer: %u and operation id: %ul\n",
             peer_id, GNUNET_ntohll (msg->operation_id));
  if (!VALID_PEER_ID (peer_id))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Asked to destroy a non existent peer with id: %u\n", peer_id);
    GST_send_operation_fail_msg (client, GNUNET_ntohll (msg->operation_id),
                                 "Peer doesn't exist");
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  peer = GST_peer_list[peer_id];
  if (GNUNET_YES == peer->is_remote)
  {
    /* Forward the destory message to sub controller */
    fopc = GNUNET_new (struct ForwardedOperationContext);
    GNUNET_SERVER_client_keep (client);
    fopc->client = client;
    fopc->cls = peer;
    fopc->type = OP_PEER_DESTROY;
    fopc->operation_id = GNUNET_ntohll (msg->operation_id);
    fopc->opc =
        GNUNET_TESTBED_forward_operation_msg_ (peer->details.remote.
                                               slave->controller,
                                               fopc->operation_id, &msg->header,
                                               &peer_destroy_success_cb, fopc);
    fopc->timeout_task =
        GNUNET_SCHEDULER_add_delayed (GST_timeout, &GST_forwarded_operation_timeout,
                                      fopc);
    GNUNET_CONTAINER_DLL_insert_tail (fopcq_head, fopcq_tail, fopc);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  peer->destroy_flag = GNUNET_YES;
  if (0 == peer->reference_cnt)
    GST_destroy_peer (peer);
  else
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Delaying peer destroy as peer is currently in use\n");
  GST_send_operation_success_msg (client, GNUNET_ntohll (msg->operation_id));
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Stats a peer
 *
 * @param peer the peer to start
 * @return GNUNET_OK upon success; GNUNET_SYSERR upon failure
 */
static int
start_peer (struct Peer *peer)
{
  GNUNET_assert (GNUNET_NO == peer->is_remote);
  if (GNUNET_OK != GNUNET_TESTING_peer_start (peer->details.local.peer))
    return GNUNET_SYSERR;
  peer->details.local.is_running = GNUNET_YES;
  return GNUNET_OK;
}


/**
 * Stops a peer
 *
 * @param peer the peer to stop
 * @return GNUNET_OK upon success; GNUNET_SYSERR upon failure
 */
static int
stop_peer (struct Peer *peer)
{
  GNUNET_assert (GNUNET_NO == peer->is_remote);
  if (GNUNET_OK != GNUNET_TESTING_peer_kill (peer->details.local.peer))
    return GNUNET_SYSERR;
  peer->details.local.is_running = GNUNET_NO;
  return GNUNET_OK;
}


/**
 * Message handler for GNUNET_MESSAGE_TYPE_TESTBED_DESTROYPEER messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
void
GST_handle_peer_start (void *cls, struct GNUNET_SERVER_Client *client,
                       const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TESTBED_PeerStartMessage *msg;
  struct GNUNET_TESTBED_PeerEventMessage *reply;
  struct ForwardedOperationContext *fopc;
  struct Peer *peer;
  uint32_t peer_id;

  msg = (const struct GNUNET_TESTBED_PeerStartMessage *) message;
  peer_id = ntohl (msg->peer_id);
  if (!VALID_PEER_ID (peer_id))
  {
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Asked to start a non existent peer with id: %u\n", peer_id);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  peer = GST_peer_list[peer_id];
  if (GNUNET_YES == peer->is_remote)
  {
    fopc = GNUNET_new (struct ForwardedOperationContext);
    GNUNET_SERVER_client_keep (client);
    fopc->client = client;
    fopc->operation_id = GNUNET_ntohll (msg->operation_id);
    fopc->type = OP_PEER_START;
    fopc->opc =
        GNUNET_TESTBED_forward_operation_msg_ (peer->details.remote.
                                               slave->controller,
                                               fopc->operation_id, &msg->header,
                                               &GST_forwarded_operation_reply_relay,
                                               fopc);
    fopc->timeout_task =
        GNUNET_SCHEDULER_add_delayed (GST_timeout, &GST_forwarded_operation_timeout,
                                      fopc);
    GNUNET_CONTAINER_DLL_insert_tail (fopcq_head, fopcq_tail, fopc);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  if (GNUNET_OK != start_peer (peer))
  {
    GST_send_operation_fail_msg (client, GNUNET_ntohll (msg->operation_id),
                                 "Failed to start");
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  reply = GNUNET_new (struct GNUNET_TESTBED_PeerEventMessage);
  reply->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_PEER_EVENT);
  reply->header.size = htons (sizeof (struct GNUNET_TESTBED_PeerEventMessage));
  reply->event_type = htonl (GNUNET_TESTBED_ET_PEER_START);
  reply->host_id = htonl (GST_context->host_id);
  reply->peer_id = msg->peer_id;
  reply->operation_id = msg->operation_id;
  GST_queue_message (client, &reply->header);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Message handler for GNUNET_MESSAGE_TYPE_TESTBED_DESTROYPEER messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
void
GST_handle_peer_stop (void *cls, struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TESTBED_PeerStopMessage *msg;
  struct GNUNET_TESTBED_PeerEventMessage *reply;
  struct ForwardedOperationContext *fopc;
  struct Peer *peer;
  uint32_t peer_id;

  msg = (const struct GNUNET_TESTBED_PeerStopMessage *) message;
  peer_id = ntohl (msg->peer_id);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Received PEER_STOP for peer %u\n", peer_id);
  if (!VALID_PEER_ID (peer_id))
  {
    GST_send_operation_fail_msg (client, GNUNET_ntohll (msg->operation_id),
                                 "Peer not found");
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  peer = GST_peer_list[peer_id];
  if (GNUNET_YES == peer->is_remote)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Forwarding PEER_STOP for peer %u\n",
         peer_id);
    fopc = GNUNET_new (struct ForwardedOperationContext);
    GNUNET_SERVER_client_keep (client);
    fopc->client = client;
    fopc->operation_id = GNUNET_ntohll (msg->operation_id);
    fopc->type = OP_PEER_STOP;
    fopc->opc =
        GNUNET_TESTBED_forward_operation_msg_ (peer->details.remote.
                                               slave->controller,
                                               fopc->operation_id, &msg->header,
                                               &GST_forwarded_operation_reply_relay,
                                               fopc);
    fopc->timeout_task =
        GNUNET_SCHEDULER_add_delayed (GST_timeout, &GST_forwarded_operation_timeout,
                                      fopc);
    GNUNET_CONTAINER_DLL_insert_tail (fopcq_head, fopcq_tail, fopc);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  if (GNUNET_OK != stop_peer (peer))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "Stopping peer %u failed\n", peer_id);
    GST_send_operation_fail_msg (client, GNUNET_ntohll (msg->operation_id),
                                 "Peer not running");
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Peer %u successfully stopped\n", peer_id);
  reply = GNUNET_new (struct GNUNET_TESTBED_PeerEventMessage);
  reply->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_PEER_EVENT);
  reply->header.size = htons (sizeof (struct GNUNET_TESTBED_PeerEventMessage));
  reply->event_type = htonl (GNUNET_TESTBED_ET_PEER_STOP);
  reply->host_id = htonl (GST_context->host_id);
  reply->peer_id = msg->peer_id;
  reply->operation_id = msg->operation_id;
  GST_queue_message (client, &reply->header);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  GNUNET_TESTING_peer_wait (peer->details.local.peer);
}


/**
 * Handler for GNUNET_MESSAGE_TYPE_TESTBED_GETPEERCONFIG messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
void
GST_handle_peer_get_config (void *cls, struct GNUNET_SERVER_Client *client,
                            const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TESTBED_PeerGetConfigurationMessage *msg;
  struct GNUNET_TESTBED_PeerConfigurationInformationMessage *reply;
  struct ForwardedOperationContext *fopc;
  struct Peer *peer;
  char *config;
  char *xconfig;
  size_t c_size;
  size_t xc_size;
  uint32_t peer_id;
  uint16_t msize;

  msg = (const struct GNUNET_TESTBED_PeerGetConfigurationMessage *) message;
  peer_id = ntohl (msg->peer_id);
  LOG_DEBUG ("Received GET_CONFIG for peer %u\n", peer_id);
  if (!VALID_PEER_ID (peer_id))
  {
    GST_send_operation_fail_msg (client, GNUNET_ntohll (msg->operation_id),
                                 "Peer not found");
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  peer = GST_peer_list[peer_id];
  if (GNUNET_YES == peer->is_remote)
  {
    LOG_DEBUG ("Forwarding PEER_GET_CONFIG for peer: %u\n", peer_id);
    fopc = GNUNET_new (struct ForwardedOperationContext);
    GNUNET_SERVER_client_keep (client);
    fopc->client = client;
    fopc->operation_id = GNUNET_ntohll (msg->operation_id);
    fopc->type = OP_PEER_INFO;
    fopc->opc =
        GNUNET_TESTBED_forward_operation_msg_ (peer->details.remote.
                                               slave->controller,
                                               fopc->operation_id, &msg->header,
                                               &GST_forwarded_operation_reply_relay,
                                               fopc);
    fopc->timeout_task =
        GNUNET_SCHEDULER_add_delayed (GST_timeout, &GST_forwarded_operation_timeout,
                                      fopc);
    GNUNET_CONTAINER_DLL_insert_tail (fopcq_head, fopcq_tail, fopc);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  LOG_DEBUG ("Received PEER_GET_CONFIG for peer: %u\n", peer_id);
  config =
      GNUNET_CONFIGURATION_serialize (GST_peer_list[peer_id]->details.local.cfg,
                                      &c_size);
  xc_size = GNUNET_TESTBED_compress_config_ (config, c_size, &xconfig);
  GNUNET_free (config);
  msize =
      xc_size +
      sizeof (struct GNUNET_TESTBED_PeerConfigurationInformationMessage);
  reply = GNUNET_realloc (xconfig, msize);
  (void) memmove (&reply[1], reply, xc_size);
  reply->header.size = htons (msize);
  reply->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_PEER_INFORMATION);
  reply->peer_id = msg->peer_id;
  reply->operation_id = msg->operation_id;
  GNUNET_TESTING_peer_get_identity (GST_peer_list[peer_id]->details.local.peer,
                                    &reply->peer_identity);
  reply->config_size = htons ((uint16_t) c_size);
  GST_queue_message (client, &reply->header);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Cleans up the given PeerReconfigureContext
 *
 * @param prc the PeerReconfigureContext
 */
static void
cleanup_prc (struct PeerReconfigureContext *prc)
{
  struct Peer *peer;

  if (VALID_PEER_ID (prc->peer_id))
  {
    peer = GST_peer_list [prc->peer_id];
    if (1 != prc->stopped)
    {
      GNUNET_TESTING_peer_stop_async_cancel (peer->details.local.peer);
      stop_peer (peer);         /* Stop the peer synchronously */
    }
  }
  if (NULL != prc->cfg)
    GNUNET_CONFIGURATION_destroy (prc->cfg);
  GNUNET_SERVER_client_drop (prc->client);
  GNUNET_CONTAINER_DLL_remove (prc_head, prc_tail, prc);
  GNUNET_free (prc);
}


/**
 * Cleans up the Peer reconfigure context list
 */
void
GST_free_prcq ()
{
  while (NULL != prc_head)
    cleanup_prc (prc_head);
}


/**
 * Update peer configuration
 *
 * @param peer the peer to update
 * @param cfg the new configuration
 * @return error message (freshly allocated); NULL upon success
 */
static char *
update_peer_config (struct Peer *peer,
                    struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char *emsg;

  GNUNET_TESTING_peer_destroy (peer->details.local.peer);
  GNUNET_CONFIGURATION_destroy (peer->details.local.cfg);
  peer->details.local.cfg = cfg;
  emsg = NULL;
  peer->details.local.peer
      = GNUNET_TESTING_peer_configure (GST_context->system,
                                       peer->details.local.cfg, peer->id,
                                       NULL /* Peer id */ ,
                                       &emsg);
  return emsg;
}


/**
 * Callback to inform whether the peer is running or stopped.
 *
 * @param cls the closure given to GNUNET_TESTING_peer_stop_async()
 * @param p the respective peer whose status is being reported
 * @param success GNUNET_YES if the peer is stopped; GNUNET_SYSERR upon any
 *          error
 */
static void
prc_stop_cb (void *cls, struct GNUNET_TESTING_Peer *p, int success)
{
  struct PeerReconfigureContext *prc = cls;
  struct Peer *peer;
  char *emsg;

  GNUNET_assert (VALID_PEER_ID (prc->peer_id));
  peer = GST_peer_list [prc->peer_id];
  GNUNET_assert (GNUNET_NO == peer->is_remote);
  emsg = update_peer_config (peer, prc->cfg);
  prc->cfg = NULL;
  prc->stopped = 1;
  if (NULL != emsg)
  {
    GST_send_operation_fail_msg (prc->client, prc->op_id, emsg);
    goto cleanup;
  }
  if (GNUNET_OK != start_peer (peer))
  {
    GST_send_operation_fail_msg (prc->client, prc->op_id,
                                 "Failed to start reconfigured peer");
    goto cleanup;
  }
  GST_send_operation_success_msg (prc->client, prc->op_id);

 cleanup:
  cleanup_prc (prc);
  return;
}


/**
 * Handler for GNUNET_MESSAGE_TYPDE_TESTBED_RECONFIGURE_PEER type messages.
 * Should stop the peer asyncronously, destroy it and create it again with the
 * new configuration.
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
void
GST_handle_peer_reconfigure (void *cls, struct GNUNET_SERVER_Client *client,
                             const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TESTBED_PeerReconfigureMessage *msg;
  struct Peer *peer;
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct ForwardedOperationContext *fopc;
  struct PeerReconfigureContext *prc;
  char *emsg;
  uint64_t op_id;
  uint32_t peer_id;
  uint16_t msize;

  msize = ntohs (message->size);
  if (msize <= sizeof (struct GNUNET_TESTBED_PeerReconfigureMessage))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  msg = (const struct GNUNET_TESTBED_PeerReconfigureMessage *) message;
  peer_id = ntohl (msg->peer_id);
  op_id = GNUNET_ntohll (msg->operation_id);
  if (!VALID_PEER_ID (peer_id))
  {
    GNUNET_break (0);
    GST_send_operation_fail_msg (client, op_id, "Peer not found");
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  peer = GST_peer_list[peer_id];
  if (GNUNET_YES == peer->is_remote)
  {
    LOG_DEBUG ("Forwarding PEER_RECONFIGURE for peer: %u\n", peer_id);
    fopc = GNUNET_new (struct ForwardedOperationContext);
    GNUNET_SERVER_client_keep (client);
    fopc->client = client;
    fopc->operation_id = op_id;
    fopc->type = OP_PEER_RECONFIGURE;
    fopc->opc =
        GNUNET_TESTBED_forward_operation_msg_ (peer->details.remote.
                                               slave->controller,
                                               fopc->operation_id, &msg->header,
                                               &GST_forwarded_operation_reply_relay,
                                               fopc);
    fopc->timeout_task =
        GNUNET_SCHEDULER_add_delayed (GST_timeout, &GST_forwarded_operation_timeout,
                                      fopc);
    GNUNET_CONTAINER_DLL_insert_tail (fopcq_head, fopcq_tail, fopc);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  LOG_DEBUG ("Received PEER_RECONFIGURE for peer %u\n", peer_id);
  if (0 < peer->reference_cnt)
  {
    GNUNET_break (0);
    GST_send_operation_fail_msg (client, op_id, "Peer in use");
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  if (GNUNET_YES == peer->destroy_flag)
  {
    GNUNET_break (0);
    GST_send_operation_fail_msg (client, op_id, "Peer is being destroyed");
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  cfg = GNUNET_TESTBED_extract_config_ (message);
  if (NULL == cfg)
  {
    GNUNET_break (0);
    GST_send_operation_fail_msg (client, op_id, "Compression error");
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  if (GNUNET_NO == peer->details.local.is_running)
  {
    emsg = update_peer_config (peer, cfg);
    if (NULL != emsg)
      GST_send_operation_fail_msg (client, op_id, emsg);
    GST_send_operation_success_msg (client, op_id);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    GNUNET_free_non_null (emsg);
    return;
  }
  prc = GNUNET_new (struct PeerReconfigureContext);
  if (GNUNET_OK !=
      GNUNET_TESTING_peer_stop_async (peer->details.local.peer, &prc_stop_cb,
                                      prc))
  {
    GNUNET_assert (0 < GNUNET_asprintf (&emsg,
                                        "Error trying to stop peer %u asynchronously\n",
                                        peer_id));
    LOG (GNUNET_ERROR_TYPE_ERROR, "%s\n", emsg);
    GST_send_operation_fail_msg (client, op_id, emsg);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    GNUNET_free (prc);
    GNUNET_free (emsg);
    return;
  }
  prc->cfg = cfg;
  prc->peer_id = peer_id;
  prc->op_id = op_id;
  prc->client = client;
  GNUNET_SERVER_client_keep (client);
  GNUNET_CONTAINER_DLL_insert_tail (prc_head, prc_tail, prc);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Cleanup the context information created for managing a peer's service
 *
 * @param mctx the ManageServiceContext
 */
static void
cleanup_mctx (struct ManageServiceContext *mctx)
{
  mctx->expired = GNUNET_YES;
  GNUNET_CONTAINER_DLL_remove (mctx_head, mctx_tail, mctx);
  GNUNET_SERVER_client_drop (mctx->client);
  GNUNET_ARM_disconnect_and_free (mctx->ah);
  GNUNET_assert (0 < mctx->peer->reference_cnt);
  mctx->peer->reference_cnt--;
  if ( (GNUNET_YES == mctx->peer->destroy_flag)
       && (0 == mctx->peer->reference_cnt) )
    GST_destroy_peer (mctx->peer);
  GNUNET_free (mctx);
}


/**
 * Frees the ManageServiceContext queue
 */
void
GST_free_mctxq ()
{
  while (NULL != mctx_head)
    cleanup_mctx (mctx_head);
}


/**
 * Returns a string interpretation of 'rs'
 *
 * @param rs the request status from ARM
 * @return a string interpretation of the request status
 */
static const char *
arm_req_string (enum GNUNET_ARM_RequestStatus rs)
{
  switch (rs)
  {
  case GNUNET_ARM_REQUEST_SENT_OK:
    return _("Message was sent successfully");
  case GNUNET_ARM_REQUEST_CONFIGURATION_ERROR:
    return _("Misconfiguration (can't connect to the ARM service)");
  case GNUNET_ARM_REQUEST_DISCONNECTED:
    return _("We disconnected from ARM before we could send a request");
  case GNUNET_ARM_REQUEST_BUSY:
    return _("ARM API is busy");
  case GNUNET_ARM_REQUEST_TOO_LONG:
    return _("Request doesn't fit into a message");
  case GNUNET_ARM_REQUEST_TIMEOUT:
    return _("Request timed out");
  }
  return _("Unknown request status");
}


/**
 * Returns a string interpretation of the 'result'
 *
 * @param result the arm result
 * @return a string interpretation
 */
static const char *
arm_ret_string (enum GNUNET_ARM_Result result)
{
  switch (result)
  {
  case GNUNET_ARM_RESULT_STOPPED:
    return _("%s is stopped");
  case GNUNET_ARM_RESULT_STARTING:
    return _("%s is starting");
  case GNUNET_ARM_RESULT_STOPPING:
    return _("%s is stopping");
  case GNUNET_ARM_RESULT_IS_STARTING_ALREADY:
    return _("%s is starting already");
  case GNUNET_ARM_RESULT_IS_STOPPING_ALREADY:
    return _("%s is stopping already");
  case GNUNET_ARM_RESULT_IS_STARTED_ALREADY:
    return _("%s is started already");
  case GNUNET_ARM_RESULT_IS_STOPPED_ALREADY:
    return _("%s is stopped already");
  case GNUNET_ARM_RESULT_IS_NOT_KNOWN:
    return _("%s service is not known to ARM");
  case GNUNET_ARM_RESULT_START_FAILED:
    return _("%s service failed to start");
  case GNUNET_ARM_RESULT_IN_SHUTDOWN:
    return _("%s service can't be started because ARM is shutting down");
  }
  return _("%.s Unknown result code.");
}


/**
 * Function called in response to a start/stop request.
 * Will be called when request was not sent successfully,
 * or when a reply comes. If the request was not sent successfully,
 * 'rs' will indicate that, and 'service' and 'result' will be undefined.
 *
 * @param cls ManageServiceContext
 * @param rs status of the request
 * @param service service name
 * @param result result of the operation
 */
static void
service_manage_result_cb (void *cls,
                          enum GNUNET_ARM_RequestStatus rs,
                          const char *service, enum GNUNET_ARM_Result result)
{
  struct ManageServiceContext *mctx = cls;
  char *emsg;

  emsg = NULL;
  if (GNUNET_YES == mctx->expired)
    return;
  if (GNUNET_ARM_REQUEST_SENT_OK != rs)
  {
    GNUNET_asprintf (&emsg, "Error communicating with Peer %u's ARM: %s",
                     mctx->peer->id, arm_req_string (rs));
    goto ret;
  }
  if (1 == mctx->start)
    goto service_start_check;
  if (! ((GNUNET_ARM_RESULT_STOPPED == result)
            || (GNUNET_ARM_RESULT_STOPPING == result)
            || (GNUNET_ARM_RESULT_IS_STOPPING_ALREADY == result)
            || (GNUNET_ARM_RESULT_IS_STOPPED_ALREADY == result)) )
  {
    /* stopping a service failed */
    GNUNET_asprintf (&emsg, arm_ret_string (result), service);
    goto ret;
  }
  /* service stopped successfully */
  goto ret;

 service_start_check:
  if (! ((GNUNET_ARM_RESULT_STARTING == result)
            || (GNUNET_ARM_RESULT_IS_STARTING_ALREADY == result)
            || (GNUNET_ARM_RESULT_IS_STARTED_ALREADY == result)) )
  {
    /* starting a service failed */
    GNUNET_asprintf (&emsg, arm_ret_string (result), service);
    goto ret;
  }
  /* service started successfully */

 ret:
  if (NULL != emsg)
  {
    LOG_DEBUG ("%s\n", emsg);
    GST_send_operation_fail_msg (mctx->client, mctx->op_id, emsg);
  }
  else
    GST_send_operation_success_msg (mctx->client, mctx->op_id);
  GNUNET_free_non_null (emsg);
  cleanup_mctx (mctx);
}


/**
 * Handler for GNUNET_TESTBED_ManagePeerServiceMessage message
 *
 * @param cls NULL
 * @param client identification of client
 * @param message the actual message
 */
void
GST_handle_manage_peer_service (void *cls, struct GNUNET_SERVER_Client *client,
                                const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TESTBED_ManagePeerServiceMessage *msg;
  const char* service;
  struct Peer *peer;
  char *emsg;
  struct GNUNET_ARM_Handle *ah;
  struct ManageServiceContext *mctx;
  struct ForwardedOperationContext *fopc;
  uint64_t op_id;
  uint32_t peer_id;
  uint16_t msize;


  msize = ntohs (message->size);
  if (msize <= sizeof (struct GNUNET_TESTBED_ManagePeerServiceMessage))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  msg = (const struct GNUNET_TESTBED_ManagePeerServiceMessage *) message;
  service = (const char *) &msg[1];
  if ('\0' != service[msize - sizeof
                      (struct GNUNET_TESTBED_ManagePeerServiceMessage) - 1])
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  if (1 < msg->start)
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  peer_id = ntohl (msg->peer_id);
  op_id = GNUNET_ntohll (msg->operation_id);
  LOG_DEBUG ("Received request to manage service %s on peer %u\n",
             service, (unsigned int) peer_id);
  if ((GST_peer_list_size <= peer_id)
      || (NULL == (peer = GST_peer_list[peer_id])))
  {
    GNUNET_asprintf (&emsg, "Asked to manage service of a non existent peer "
                     "with id: %u", peer_id);
    goto err_ret;
  }
  if (0 == strcasecmp ("arm", service))
  {
    emsg = GNUNET_strdup ("Cannot start/stop peer's ARM service.  "
                          "Use peer start/stop for that");
    goto err_ret;
  }
  if (GNUNET_YES == peer->is_remote)
  {
    /* Forward the destory message to sub controller */
    fopc = GNUNET_new (struct ForwardedOperationContext);
    GNUNET_SERVER_client_keep (client);
    fopc->client = client;
    fopc->cls = peer;
    fopc->type = OP_MANAGE_SERVICE;
    fopc->operation_id = op_id;
    fopc->opc =
        GNUNET_TESTBED_forward_operation_msg_ (peer->details.remote.
                                               slave->controller,
                                               fopc->operation_id, &msg->header,
                                               &GST_forwarded_operation_reply_relay,
                                               fopc);
    fopc->timeout_task =
        GNUNET_SCHEDULER_add_delayed (GST_timeout, &GST_forwarded_operation_timeout,
                                      fopc);
    GNUNET_CONTAINER_DLL_insert_tail (fopcq_head, fopcq_tail, fopc);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  if (GNUNET_NO == peer->details.local.is_running)
  {
    emsg = GNUNET_strdup ("Peer not running\n");
    goto err_ret;
  }
  if ((0 != peer->reference_cnt)
      && ( (0 == strcasecmp ("core", service))
           || (0 == strcasecmp ("transport", service)) )  )
  {
    GNUNET_asprintf (&emsg, "Cannot stop %s service of peer with id: %u "
                     "since it is required by existing operations",
                     service, peer_id);
    goto err_ret;
  }
  ah = GNUNET_ARM_connect (peer->details.local.cfg, NULL, NULL);
  if (NULL == ah)
  {
    GNUNET_asprintf (&emsg,
                     "Cannot connect to ARM service of peer with id: %u",
                     peer_id);
    goto err_ret;
  }
  mctx = GNUNET_new (struct ManageServiceContext);
  mctx->peer = peer;
  peer->reference_cnt++;
  mctx->op_id = op_id;
  mctx->ah = ah;
  GNUNET_SERVER_client_keep (client);
  mctx->client = client;
  mctx->start = msg->start;
  GNUNET_CONTAINER_DLL_insert_tail (mctx_head, mctx_tail, mctx);
  if (1 == mctx->start)
    GNUNET_ARM_request_service_start (mctx->ah, service,
                                      GNUNET_OS_INHERIT_STD_ERR,
                                      GST_timeout,
                                      service_manage_result_cb,
                                      mctx);
  else
    GNUNET_ARM_request_service_stop (mctx->ah, service,
                                     GST_timeout,
                                     service_manage_result_cb,
                                     mctx);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  return;

 err_ret:
  LOG (GNUNET_ERROR_TYPE_ERROR, "%s\n", emsg);
  GST_send_operation_fail_msg (client, op_id, emsg);
  GNUNET_free (emsg);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Stops and destroys all peers
 */
void
GST_destroy_peers ()
{
  struct Peer *peer;
  unsigned int id;

  if (NULL == GST_peer_list)
    return;
  for (id = 0; id < GST_peer_list_size; id++)
  {
    peer = GST_peer_list[id];
    if (NULL == peer)
      continue;
    /* If destroy flag is set it means that this peer should have been
     * destroyed by a context which we destroy before */
    GNUNET_break (GNUNET_NO == peer->destroy_flag);
    /* counter should be zero as we free all contexts before */
    GNUNET_break (0 == peer->reference_cnt);
    if ((GNUNET_NO == peer->is_remote) &&
        (GNUNET_YES == peer->details.local.is_running))
      GNUNET_TESTING_peer_kill (peer->details.local.peer);
  }
  for (id = 0; id < GST_peer_list_size; id++)
  {
    peer = GST_peer_list[id];
    if (NULL == peer)
      continue;
    if (GNUNET_NO == peer->is_remote)
    {
      if (GNUNET_YES == peer->details.local.is_running)
        GNUNET_TESTING_peer_wait (peer->details.local.peer);
      GNUNET_TESTING_peer_destroy (peer->details.local.peer);
      GNUNET_CONFIGURATION_destroy (peer->details.local.cfg);
    }
    GNUNET_free (peer);
  }
  GNUNET_free_non_null (GST_peer_list);
  GST_peer_list = NULL;
  GST_peer_list_size = 0;
}


/**
 * The reply msg handler forwarded SHUTDOWN_PEERS operation.  Checks if a
 * success reply is received from all clients and then sends the success message
 * to the client
 *
 * @param cls ForwardedOperationContext
 * @param msg the message to relay
 */
static void
shutdown_peers_reply_cb (void *cls,
                         const struct GNUNET_MessageHeader *msg)
{
  struct ForwardedOperationContext *fo_ctxt = cls;
  struct HandlerContext_ShutdownPeers *hc;

  hc = fo_ctxt->cls;
  GNUNET_assert (0 < hc->nslaves);
  hc->nslaves--;
  if (GNUNET_MESSAGE_TYPE_TESTBED_GENERIC_OPERATION_SUCCESS !=
      ntohs (msg->type))
    hc->timeout = GNUNET_YES;
  if (0 == hc->nslaves)
  {
    if (GNUNET_YES == hc->timeout)
      GST_send_operation_fail_msg (fo_ctxt->client, fo_ctxt->operation_id,
                                   "Timeout at a slave controller");
    else
      GST_send_operation_success_msg (fo_ctxt->client, fo_ctxt->operation_id);
    GNUNET_free (hc);
    hc = NULL;
  }
  GNUNET_SERVER_client_drop (fo_ctxt->client);
  GNUNET_CONTAINER_DLL_remove (fopcq_head, fopcq_tail, fo_ctxt);
  GNUNET_free (fo_ctxt);
}


/**
 * Handler for GNUNET_MESSAGE_TYPE_TESTBED_SHUTDOWN_PEERS messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
void
GST_handle_shutdown_peers (void *cls, struct GNUNET_SERVER_Client *client,
                           const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TESTBED_ShutdownPeersMessage *msg;
  struct HandlerContext_ShutdownPeers *hc;
  struct Slave *slave;
  struct ForwardedOperationContext *fo_ctxt;
  uint64_t op_id;
  unsigned int cnt;

  msg = (const struct GNUNET_TESTBED_ShutdownPeersMessage *) message;
  LOG_DEBUG ("Received SHUTDOWN_PEERS\n");
    /* Stop and destroy all peers */
  GST_free_mctxq ();
  GST_free_occq ();
  GST_free_roccq ();
  GST_clear_fopcq ();
  /* Forward to all slaves which we have started */
  op_id = GNUNET_ntohll (msg->operation_id);
  hc = GNUNET_new (struct HandlerContext_ShutdownPeers);
  /* FIXME: have a better implementation where we track which slaves are
     started by this controller */
  for (cnt = 0; cnt < GST_slave_list_size; cnt++)
  {
    slave = GST_slave_list[cnt];
    if (NULL == slave)
      continue;
    if (NULL == slave->controller_proc) /* We didn't start the slave */
      continue;
    LOG_DEBUG ("Forwarding SHUTDOWN_PEERS\n");
    hc->nslaves++;
    fo_ctxt = GNUNET_new (struct ForwardedOperationContext);
    GNUNET_SERVER_client_keep (client);
    fo_ctxt->client = client;
    fo_ctxt->operation_id = op_id;
    fo_ctxt->cls = hc;
    fo_ctxt->type = OP_SHUTDOWN_PEERS;
    fo_ctxt->opc =
        GNUNET_TESTBED_forward_operation_msg_ (slave->controller,
                                               fo_ctxt->operation_id,
                                               &msg->header,
                                               shutdown_peers_reply_cb,
                                               fo_ctxt);
    GNUNET_CONTAINER_DLL_insert_tail (fopcq_head, fopcq_tail, fo_ctxt);
  }
  LOG_DEBUG ("Shutting down peers\n");
  GST_destroy_peers ();
  if (0 == hc->nslaves)
  {
    GST_send_operation_success_msg (client, op_id);
    GNUNET_free (hc);
  }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}
