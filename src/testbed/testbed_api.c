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

/**
 * Generic logging shorthand
 */
#define LOG(kind, ...)                          \
  GNUNET_log_from (kind, "testbed-api", __VA_ARGS__);

/**
 * Debug logging
 */
#define LOG_DEBUG(...)                          \
  LOG (GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__);

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
 * The message queue for sending messages to the controller service
 */
struct MessageQueue
{
  /**
   * The message to be sent
   */
  struct GNUNET_MessageHeader *msg;

  /**
   * next pointer for DLL
   */
  struct MessageQueue *next;
  
  /**
   * prev pointer for DLL
   */
  struct MessageQueue *prev;
};


/**
 * Structure for a controller link
 */
struct ControllerLink
{
  /**
   * The next ptr for DLL
   */
  struct ControllerLink *next;

  /**
   * The prev ptr for DLL
   */
  struct ControllerLink *prev;

  /**
   * The host which will be referred in the peer start request. This is the
   * host where the peer should be started
   */
  struct GNUNET_TESTBED_Host *delegated_host;

  /**
   * The host which will contacted to delegate the peer start request
   */
  struct GNUNET_TESTBED_Host *slave_host;

  /**
   * The configuration to be used to connect to slave host
   */
  const struct GNUNET_CONFIGURATION_Handle *slave_cfg;

  /**
   * GNUNET_YES if the slave should be started (and stopped) by us; GNUNET_NO
   * if we are just allowed to use the slave via TCP/IP
   */
  int is_subordinate;
};


/**
 * handle for host registration
 */
struct GNUNET_TESTBED_HostRegistrationHandle
{
  /**
   * The host being registered
   */
  struct GNUNET_TESTBED_Host *host;

  /**
   * The controller at which this host is being registered
   */
  struct GNUNET_TESTBED_Controller *c;

  /**
   * The Registartion completion callback
   */
  GNUNET_TESTBED_HostRegistrationCompletion cc;

  /**
   * The closure for above callback
   */
  void *cc_cls;
};


/**
 * Context data for forwarded Operation
 */
struct ForwardedOperationData
{
  
  /**
   * The callback to call when reply is available
   */
  GNUNET_CLIENT_MessageHandler cc;  

  /**
   * The closure for the above callback
   */
  void *cc_cls;
  
};


/**
 * Returns the operation context with the given id if found in the Operation
 * context queues of the controller
 *
 * @param c the controller whose queues are searched
 * @param id the id which has to be checked
 * @return the matching operation context; NULL if no match found
 */
static struct OperationContext *
find_opc (const struct GNUNET_TESTBED_Controller *c, const uint64_t id)
{
  struct OperationContext *opc;

  for (opc = c->ocq_head; NULL != opc; opc = opc->next)
  {
    if (id == opc->id)
      return opc;
  }
  return NULL;
}


/**
 * Handler for GNUNET_MESSAGE_TYPE_TESTBED_ADDHOSTCONFIRM message from
 * controller (testbed service)
 *
 * @param c the controller handler
 * @param msg message received
 * @return GNUNET_YES if we can continue receiving from service; GNUNET_NO if
 *           not
 */
static int
handle_addhostconfirm (struct GNUNET_TESTBED_Controller *c,
                       const struct GNUNET_TESTBED_HostConfirmedMessage *msg)
{
  struct GNUNET_TESTBED_HostRegistrationHandle *rh;
  char *emsg;
  uint16_t msg_size;

  rh = c->rh;
  if (NULL == rh)
  {  
    return GNUNET_OK;    
  }
  if (GNUNET_TESTBED_host_get_id_ (rh->host) != ntohl (msg->host_id))
  {
    LOG_DEBUG ("Mismatch in host id's %u, %u of host confirm msg\n",
               GNUNET_TESTBED_host_get_id_ (rh->host), ntohl (msg->host_id));
    return GNUNET_OK;
  }
  c->rh = NULL;
  msg_size = ntohs (msg->header.size);
  if (sizeof (struct GNUNET_TESTBED_HostConfirmedMessage) == msg_size)
  {
    LOG_DEBUG ("Host %u successfully registered\n", ntohl (msg->host_id));
    GNUNET_TESTBED_mark_host_registered_at_  (rh->host, c);
    rh->cc (rh->cc_cls, NULL);
    GNUNET_free (rh);
    return GNUNET_OK;
  } 
  /* We have an error message */
  emsg = (char *) &msg[1];
  if ('\0' != emsg[msg_size - 
                   sizeof (struct GNUNET_TESTBED_HostConfirmedMessage)])
  {
    GNUNET_break (0);
    GNUNET_free (rh);
    return GNUNET_NO;
  }  
  LOG (GNUNET_ERROR_TYPE_ERROR, _("Adding host %u failed with error: %s\n"),
       ntohl (msg->host_id), emsg);
  rh->cc (rh->cc_cls, emsg);
  GNUNET_free (rh);
  return GNUNET_OK;
}


/**
 * Handler for GNUNET_MESSAGE_TYPE_TESTBED_ADDHOSTCONFIRM message from
 * controller (testbed service)
 *
 * @param c the controller handler
 * @param msg message received
 * @return GNUNET_YES if we can continue receiving from service; GNUNET_NO if
 *           not
 */
static int
handle_opsuccess (struct GNUNET_TESTBED_Controller *c,
                  const struct
                  GNUNET_TESTBED_GenericOperationSuccessEventMessage *msg)
{
  struct OperationContext *opc;
  struct GNUNET_TESTBED_EventInformation *event;
  uint64_t op_id;
  
  op_id = GNUNET_ntohll (msg->operation_id);
  LOG_DEBUG ("Operation %ul successful\n", op_id);
  if (NULL == (opc = find_opc (c, op_id)))
  {
    LOG_DEBUG ("Operation not found\n");
    return GNUNET_YES;
  }
  event = NULL;
  if (0 != (c->event_mask & (1L << GNUNET_TESTBED_ET_OPERATION_FINISHED)))
    event = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_EventInformation));
  if (NULL != event)
    event->type = GNUNET_TESTBED_ET_OPERATION_FINISHED;
  switch (opc->type)
  {
  case OP_FORWARDED:
    {
      struct ForwardedOperationData *fo_data;
    
      fo_data = opc->data;
      if (NULL != fo_data->cc)
	fo_data->cc (fo_data->cc_cls, (const struct GNUNET_MessageHeader *) msg);
      GNUNET_CONTAINER_DLL_remove (c->ocq_head, c->ocq_tail, opc);
      GNUNET_free (fo_data);
      GNUNET_free (opc);    
      return GNUNET_YES;    
    }
    break;
  case OP_PEER_DESTROY:
    {
      struct GNUNET_TESTBED_Peer *peer;     
      peer = opc->data;
      GNUNET_free (peer);
      opc->data = NULL;
      //PEERDESTROYDATA
    }
    break;
  case OP_LINK_CONTROLLERS:    
    break;
  default:
    GNUNET_assert (0);
  }
  if (NULL != event)
  {
    event->details.operation_finished.operation = opc->op;
    event->details.operation_finished.op_cls = NULL;
    event->details.operation_finished.emsg = NULL;
    event->details.operation_finished.pit = GNUNET_TESTBED_PIT_GENERIC;
    event->details.operation_finished.op_result.generic = NULL;
  }
  GNUNET_CONTAINER_DLL_remove (opc->c->ocq_head, opc->c->ocq_tail, opc);
  opc->state = OPC_STATE_FINISHED;
  if (NULL != event)
  {
    if (NULL != c->cc)
      c->cc (c->cc_cls, event);
    GNUNET_free (event);
  }  
  return GNUNET_YES;  
}


/**
 * Handler for GNUNET_MESSAGE_TYPE_TESTBED_PEERCREATESUCCESS message from
 * controller (testbed service)
 *
 * @param c the controller handler
 * @param msg message received
 * @return GNUNET_YES if we can continue receiving from service; GNUNET_NO if
 *           not
 */
static int
handle_peer_create_success (struct GNUNET_TESTBED_Controller *c,
			    const struct
			    GNUNET_TESTBED_PeerCreateSuccessEventMessage *msg)
{
  struct OperationContext *opc;
  struct PeerCreateData *data;
  struct GNUNET_TESTBED_Peer *peer;
  GNUNET_TESTBED_PeerCreateCallback cb;
  void *cls;
  uint64_t op_id;

  GNUNET_assert (sizeof (struct GNUNET_TESTBED_PeerCreateSuccessEventMessage)
		 == ntohs (msg->header.size));
  op_id = GNUNET_ntohll (msg->operation_id);
  if (NULL == (opc = find_opc (c, op_id)))
  {
    LOG_DEBUG ("Operation context for PeerCreateSuccessEvent not found\n");
    return GNUNET_YES;
  }
  if (OP_FORWARDED == opc->type)
  {
    struct ForwardedOperationData *fo_data;
    
    fo_data = opc->data;
    if (NULL != fo_data->cc)
      fo_data->cc (fo_data->cc_cls, (const struct GNUNET_MessageHeader *) msg);
    GNUNET_CONTAINER_DLL_remove (c->ocq_head, c->ocq_tail, opc);
    GNUNET_free (fo_data);
    GNUNET_free (opc);    
    return GNUNET_YES;    
  }  
  GNUNET_assert (OP_PEER_CREATE == opc->type);
  GNUNET_assert (NULL != opc->data);
  data = opc->data;
  GNUNET_assert (NULL != data->peer);
  peer = data->peer;
  GNUNET_assert (peer->unique_id == ntohl (msg->peer_id));
  peer->state = PS_CREATED;
  cb = data->cb;
  cls = data->cls;
  GNUNET_free (opc->data);  
  GNUNET_CONTAINER_DLL_remove (opc->c->ocq_head, opc->c->ocq_tail, opc);
  opc->state = OPC_STATE_FINISHED;
  if (NULL != cb)
    cb (cls, peer, NULL);
  return GNUNET_YES;
}


/**
 * Handler for GNUNET_MESSAGE_TYPE_TESTBED_PEEREVENT message from
 * controller (testbed service)
 *
 * @param c the controller handler
 * @param msg message received
 * @return GNUNET_YES if we can continue receiving from service; GNUNET_NO if
 *           not
 */
static int
handle_peer_event (struct GNUNET_TESTBED_Controller *c,
		   const struct GNUNET_TESTBED_PeerEventMessage *msg)
{
  struct OperationContext *opc;
  struct GNUNET_TESTBED_Peer *peer;
  struct GNUNET_TESTBED_EventInformation event;
  uint64_t op_id;

  GNUNET_assert (sizeof (struct GNUNET_TESTBED_PeerEventMessage)
		 == ntohs (msg->header.size));
  op_id = GNUNET_ntohll (msg->operation_id);
  if (NULL == (opc = find_opc (c, op_id)))
  {
    LOG_DEBUG ("Operation not found\n");
    return GNUNET_YES;
  }
  GNUNET_assert ((OP_PEER_START == opc->type) || (OP_PEER_STOP == opc->type));
  peer = opc->data;
  GNUNET_assert (NULL != peer);
  event.type = (enum GNUNET_TESTBED_EventType) ntohl (msg->event_type);
  switch (event.type)
  {
  case GNUNET_TESTBED_ET_PEER_START:
    peer->state = PS_STARTED;
    event.details.peer_start.host = peer->host;
    event.details.peer_start.peer = peer;
    break;
  case GNUNET_TESTBED_ET_PEER_STOP:
    peer->state = PS_STOPPED;    
    event.details.peer_stop.peer = peer;  
    break;
  default:
    GNUNET_assert (0);		/* We should never reach this state */
  }
  GNUNET_CONTAINER_DLL_remove (opc->c->ocq_head, opc->c->ocq_tail, opc);
  opc->state = OPC_STATE_FINISHED;
  if (0 != ((GNUNET_TESTBED_ET_PEER_START | GNUNET_TESTBED_ET_PEER_STOP)
	    & c->event_mask))
  {
    if (NULL != c->cc)
      c->cc (c->cc_cls, &event);
  }    
  return GNUNET_YES;
}


/**
 * Handler for GNUNET_MESSAGE_TYPE_TESTBED_PEERCONEVENT message from
 * controller (testbed service)
 *
 * @param c the controller handler
 * @param msg message received
 * @return GNUNET_YES if we can continue receiving from service; GNUNET_NO if
 *           not
 */
static int
handle_peer_conevent (struct GNUNET_TESTBED_Controller *c,
                      const struct GNUNET_TESTBED_ConnectionEventMessage *msg)
{
  struct OperationContext *opc;
  struct OverlayConnectData *data;
  struct GNUNET_TESTBED_EventInformation event;
  uint64_t op_id;

  op_id = GNUNET_ntohll (msg->operation_id);
  if (NULL == (opc = find_opc (c, op_id)))
  {
    LOG_DEBUG ("Operation not found\n");
    return GNUNET_YES;
  }
  data = opc->data;
  GNUNET_assert (NULL != data);
  GNUNET_assert ((ntohl (msg->peer1) == data->p1->unique_id)
                  && (ntohl (msg->peer2) == data->p2->unique_id));
  event.type = (enum GNUNET_TESTBED_EventType) ntohl (msg->event_type);
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
  GNUNET_CONTAINER_DLL_remove (opc->c->ocq_head, opc->c->ocq_tail, opc);
  opc->state = OPC_STATE_FINISHED;
  GNUNET_free (data);
  if (0 != ((GNUNET_TESTBED_ET_CONNECT | GNUNET_TESTBED_ET_DISCONNECT)
            & c->event_mask))
  {
    if (NULL != c->cc)
      c->cc (c->cc_cls, &event);
  }
  return GNUNET_YES;
}


/**
 * Handler for GNUNET_MESSAGE_TYPE_TESTBED_PEERCONFIG message from
 * controller (testbed service)
 *
 * @param c the controller handler
 * @param msg message received
 * @return GNUNET_YES if we can continue receiving from service; GNUNET_NO if
 *           not
 */
static int
handle_peer_config (struct GNUNET_TESTBED_Controller *c,
		    const struct GNUNET_TESTBED_PeerConfigurationInformationMessage *msg)
{
  struct OperationContext *opc;
  struct GNUNET_TESTBED_Peer *peer;
  struct PeerInfoData *data;
  struct PeerInfoData2 *response_data;
  struct GNUNET_TESTBED_EventInformation info;
  uint64_t op_id;
  
  op_id = GNUNET_ntohll (msg->operation_id);
  if (NULL == (opc = find_opc (c, op_id)))
  {
    LOG_DEBUG ("Operation not found\n");
    return GNUNET_YES;
  }
  data = opc->data;
  GNUNET_assert (NULL != data);
  peer = data->peer;
  GNUNET_assert (NULL != peer);
  GNUNET_assert (ntohl (msg->peer_id) == peer->unique_id);
  if (0 == (c->event_mask & (1L << GNUNET_TESTBED_ET_OPERATION_FINISHED)))
  {
    LOG_DEBUG ("Skipping operation callback as flag not set\n");
    return GNUNET_YES;
  }
  response_data = GNUNET_malloc (sizeof (struct PeerInfoData2));
  response_data->pit = data->pit;
  GNUNET_free (data);
  opc->data = NULL;
  info.type = GNUNET_TESTBED_ET_OPERATION_FINISHED;
  info.details.operation_finished.operation = opc->op;
  info.details.operation_finished.op_cls = NULL;
  info.details.operation_finished.emsg = NULL;
  info.details.operation_finished.pit = response_data->pit;
  switch (response_data->pit)
  {
  case GNUNET_TESTBED_PIT_IDENTITY:
    {
      struct GNUNET_PeerIdentity *peer_identity;

      peer_identity = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity));
      (void) memcpy (peer_identity, &msg->peer_identity, 
		     sizeof (struct GNUNET_PeerIdentity));
      response_data->details.peer_identity = peer_identity;      
      info.details.operation_finished.op_result.pid = peer_identity;
    }
    break;
  case GNUNET_TESTBED_PIT_CONFIGURATION:
    {
      struct GNUNET_CONFIGURATION_Handle *cfg;
      char *config;
      uLong config_size;
      int ret;
      uint16_t msize;
      
      config_size = (uLong) ntohs (msg->config_size);
      config = GNUNET_malloc (config_size);
      msize = ntohs (msg->header.size);
      msize -= sizeof (struct GNUNET_TESTBED_PeerConfigurationInformationMessage);
      if (Z_OK != (ret = uncompress ((Bytef *) config, &config_size,
				     (const Bytef *) &msg[1], (uLong) msize)))
	GNUNET_assert (0);
      cfg = GNUNET_CONFIGURATION_create (); /* Freed in oprelease_peer_getinfo */
      GNUNET_assert (GNUNET_OK == 
		     GNUNET_CONFIGURATION_deserialize (cfg, config,
						       (size_t) config_size,
						       GNUNET_NO));
      GNUNET_free (config);
      response_data->details.cfg = cfg;
      info.details.operation_finished.op_result.cfg = cfg;
    }
    break;
  case GNUNET_TESTBED_PIT_GENERIC:
    GNUNET_assert (0);		/* never reach here */
    break;
  }
  opc->data = response_data;
  GNUNET_CONTAINER_DLL_remove (opc->c->ocq_head, opc->c->ocq_tail, opc);
  opc->state = OPC_STATE_FINISHED;
  c->cc (c->cc_cls, &info);  
  return GNUNET_YES;
}


/**
 * Handler for messages from controller (testbed service)
 *
 * @param cls the controller handler
 * @param msg message received, NULL on timeout or fatal error
 */
static void 
message_handler (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_TESTBED_Controller *c = cls;
  int status;
  uint16_t msize;

  c->in_receive = GNUNET_NO;
  /* FIXME: Add checks for message integrity */
  if (NULL == msg)
  {
    LOG_DEBUG ("Receive timed out or connection to service dropped\n");
    return;
  }
  status = GNUNET_OK;
  msize = ntohs (msg->size);
  switch (ntohs (msg->type))
  {
  case GNUNET_MESSAGE_TYPE_TESTBED_ADDHOSTCONFIRM:
    GNUNET_assert (msize >= sizeof (struct
				    GNUNET_TESTBED_HostConfirmedMessage));
    status =
      handle_addhostconfirm (c, (const struct GNUNET_TESTBED_HostConfirmedMessage *) msg);
    break;
  case GNUNET_MESSAGE_TYPE_TESTBED_GENERICOPSUCCESS:
    GNUNET_assert 
      (msize == sizeof (struct GNUNET_TESTBED_GenericOperationSuccessEventMessage));
    status =
      handle_opsuccess (c, (const struct
                            GNUNET_TESTBED_GenericOperationSuccessEventMessage
                            *) msg);
    break;
  case GNUNET_MESSAGE_TYPE_TESTBED_PEERCREATESUCCESS:
    GNUNET_assert (msize == 
		   sizeof (struct GNUNET_TESTBED_PeerCreateSuccessEventMessage));
    status =
      handle_peer_create_success 
      (c, (const struct GNUNET_TESTBED_PeerCreateSuccessEventMessage *)msg);
    break;
  case GNUNET_MESSAGE_TYPE_TESTBED_PEEREVENT:
    GNUNET_assert (msize == sizeof (struct GNUNET_TESTBED_PeerEventMessage));
    status =
      handle_peer_event (c, (const struct GNUNET_TESTBED_PeerEventMessage *) msg);
    
    break;
  case GNUNET_MESSAGE_TYPE_TESTBED_PEERCONFIG:
    GNUNET_assert (msize >= 
		   sizeof (struct GNUNET_TESTBED_PeerConfigurationInformationMessage));
    status = 
      handle_peer_config 
      (c, (const struct GNUNET_TESTBED_PeerConfigurationInformationMessage *)
  msg);
    break;
  case GNUNET_MESSAGE_TYPE_TESTBED_PEERCONEVENT:
    GNUNET_assert (msize ==
                   sizeof (struct GNUNET_TESTBED_ConnectionEventMessage));
    status = 
      handle_peer_conevent (c, (const struct
                                GNUNET_TESTBED_ConnectionEventMessage *) msg);
    break;
  default:
    GNUNET_break (0);
  }
  if ((GNUNET_OK == status) && (GNUNET_NO == c->in_receive))
  {
    c->in_receive = GNUNET_YES;
    GNUNET_CLIENT_receive (c->client, &message_handler, c,
                           GNUNET_TIME_UNIT_FOREVER_REL);    
  }
}


/**
 * Function called to notify a client about the connection begin ready to queue
 * more data.  "buf" will be NULL and "size" zero if the connection was closed
 * for writing in the meantime.
 *
 * @param cls closure
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_ready_notify (void *cls, size_t size, void *buf)
{
  struct GNUNET_TESTBED_Controller *c = cls;
  struct MessageQueue *mq_entry;

  c->th = NULL;
  mq_entry = c->mq_head;
  GNUNET_assert (NULL != mq_entry);
  if ((0 == size) && (NULL == buf)) /* Timeout */
  {
    LOG_DEBUG ("Message sending timed out -- retrying\n");
    c->th =
      GNUNET_CLIENT_notify_transmit_ready (c->client,
                                           ntohs (mq_entry->msg->size),
                                           TIMEOUT_REL,
                                           GNUNET_YES, &transmit_ready_notify,
                                           c);
    return 0;
  }
  GNUNET_assert (ntohs (mq_entry->msg->size) <= size);
  size = ntohs (mq_entry->msg->size);  
  memcpy (buf, mq_entry->msg, size);
  LOG_DEBUG ("Message of type: %u and size: %u sent\n",
	     ntohs (mq_entry->msg->type), size);
  GNUNET_free (mq_entry->msg);
  GNUNET_CONTAINER_DLL_remove (c->mq_head, c->mq_tail, mq_entry);
  GNUNET_free (mq_entry);
  mq_entry = c->mq_head;
  if (NULL != mq_entry)
    c->th = 
      GNUNET_CLIENT_notify_transmit_ready (c->client,
                                           ntohs (mq_entry->msg->size),
                                           TIMEOUT_REL,
                                           GNUNET_YES, &transmit_ready_notify,
                                           c);
  if (GNUNET_NO == c->in_receive)
  {
    c->in_receive = GNUNET_YES;
    GNUNET_CLIENT_receive (c->client, &message_handler, c,
			   GNUNET_TIME_UNIT_FOREVER_REL);
  }
  return size;
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
  struct MessageQueue *mq_entry;
  uint16_t type;
  uint16_t size;

  type = ntohs (msg->type);
  size = ntohs (msg->size);
  GNUNET_assert ((GNUNET_MESSAGE_TYPE_TESTBED_INIT <= type) &&
                 (GNUNET_MESSAGE_TYPE_TESTBED_MAX > type));                 
  mq_entry = GNUNET_malloc (sizeof (struct MessageQueue));
  mq_entry->msg = msg;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Queueing message of type %u, size %u for sending\n", type,
       ntohs (msg->size));
  GNUNET_CONTAINER_DLL_insert_tail (controller->mq_head, controller->mq_tail,
                                    mq_entry);
  if (NULL == controller->th)
    controller->th = 
      GNUNET_CLIENT_notify_transmit_ready (controller->client, size,
                                           TIMEOUT_REL,
                                           GNUNET_YES, &transmit_ready_notify,
                                           controller);
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
GNUNET_TESTBED_forward_operation_msg_ (struct GNUNET_TESTBED_Controller
                                       * controller,
                                       uint64_t operation_id,
                                       const struct GNUNET_MessageHeader *msg,
                                       GNUNET_CLIENT_MessageHandler cc,
                                       void *cc_cls)
{
  struct OperationContext *opc;
  struct ForwardedOperationData *data;
  struct GNUNET_MessageHeader *dup_msg;  
  uint16_t msize;
  
  data = GNUNET_malloc (sizeof (struct ForwardedOperationData));
  data->cc = cc;
  data->cc_cls = cc_cls;  
  opc = GNUNET_malloc (sizeof (struct OperationContext));
  opc->c = controller;  
  opc->type = OP_FORWARDED;
  opc->data = data;
  opc->id = operation_id;
  msize = ntohs (msg->size);
  dup_msg = GNUNET_malloc (msize);
  (void) memcpy (dup_msg, msg, msize);  
  GNUNET_TESTBED_queue_message_ (opc->c, dup_msg);
  GNUNET_CONTAINER_DLL_insert_tail (controller->ocq_head,
                                    controller->ocq_tail, opc);
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
  GNUNET_CONTAINER_DLL_remove (opc->c->ocq_head, opc->c->ocq_tail, opc);
  GNUNET_free (opc->data);
  GNUNET_free (opc);  
}


/**
 * Handle for controller process
 */
struct GNUNET_TESTBED_ControllerProc
{
  /**
   * The process handle
   */
  struct GNUNET_HELPER_Handle *helper;

  /**
   * The host where the helper is run
   */
  struct GNUNET_TESTBED_Host *host;

  /**
   * The controller error callback
   */
  GNUNET_TESTBED_ControllerStatusCallback cb;

  /**
   * The closure for the above callback
   */
  void *cls;

  /**
   * The send handle for the helper
   */
  struct GNUNET_HELPER_SendHandle *shandle;

  /**
   * The message corresponding to send handle
   */
  struct GNUNET_MessageHeader *msg;

  /**
   * The port number for ssh; used for helpers starting ssh
   */
  char *port;

  /**
   * The ssh destination string; used for helpers starting ssh
   */
  char *dst;

  /**
   * The configuration of the running testbed service
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

};


/**
 * Functions with this signature are called whenever a
 * complete message is received by the tokenizer.
 *
 * Do not call GNUNET_SERVER_mst_destroy in callback
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR to stop further processing
 */
static int helper_mst (void *cls, void *client,
                       const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_TESTBED_ControllerProc *cp = cls;
  const struct GNUNET_TESTBED_HelperReply *msg;
  const char *hostname;
  char *config;
  uLongf config_size;
  uLongf xconfig_size;
    
  msg = (const struct GNUNET_TESTBED_HelperReply *) message;
  GNUNET_assert (sizeof (struct GNUNET_TESTBED_HelperReply) 
		 < ntohs (msg->header.size));
  GNUNET_assert (GNUNET_MESSAGE_TYPE_TESTBED_HELPER_REPLY 
                 == ntohs (msg->header.type));
  config_size = (uLongf) ntohs (msg->config_size);
  xconfig_size = (uLongf) (ntohs (msg->header.size)
                           - sizeof (struct GNUNET_TESTBED_HelperReply));
  config = GNUNET_malloc (config_size);
  GNUNET_assert (Z_OK == uncompress ((Bytef *) config, &config_size,
                                     (const Bytef *) &msg[1], xconfig_size));
  GNUNET_assert (NULL == cp->cfg);
  cp->cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_assert (GNUNET_CONFIGURATION_deserialize (cp->cfg, config, 
						   config_size, GNUNET_NO));
  GNUNET_free (config);
  if ((NULL == cp->host) || 
      (NULL == (hostname = GNUNET_TESTBED_host_get_hostname_ (cp->host))))
    hostname = "localhost";
  /* Change the hostname so that we can connect to it */
  GNUNET_CONFIGURATION_set_value_string (cp->cfg, "testbed", "hostname", 
					 hostname);
  cp->cb (cp->cls, cp->cfg, GNUNET_OK);
  return GNUNET_OK;
}


/**
 * Continuation function from GNUNET_HELPER_send()
 * 
 * @param cls closure
 * @param result GNUNET_OK on success,
 *               GNUNET_NO if helper process died
 *               GNUNET_SYSERR during GNUNET_HELPER_stop
 */
static void 
clear_msg (void *cls, int result)
{
  struct GNUNET_TESTBED_ControllerProc *cp = cls;
  
  GNUNET_assert (NULL != cp->shandle);
  cp->shandle = NULL;
  GNUNET_free (cp->msg);
}


/**
 * Callback that will be called when the helper process dies. This is not called
 * when the helper process is stoped using GNUNET_HELPER_stop()
 *
 * @param cls the closure from GNUNET_HELPER_start()
 */
static void 
helper_exp_cb (void *cls)
{
  struct GNUNET_TESTBED_ControllerProc *cp = cls;
  GNUNET_TESTBED_ControllerStatusCallback cb;
  void *cb_cls;

  cb = cp->cb;
  cb_cls = cp->cls;
  cp->helper = NULL;
  GNUNET_TESTBED_controller_stop (cp);
  if (NULL != cb)
    cb (cb_cls, NULL, GNUNET_SYSERR);
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
  struct GNUNET_TESTBED_ControllerLinkMessage *msg;

  GNUNET_assert (NULL != opc->data);
  msg = opc->data;
  opc->data = NULL;
  opc->state = OPC_STATE_STARTED;
  GNUNET_CONTAINER_DLL_insert_tail (opc->c->ocq_head, opc->c->ocq_tail, opc);
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

  if (OPC_STATE_INIT == opc->state)
    GNUNET_free (opc->data);
  if (OPC_STATE_STARTED == opc->state)
    GNUNET_CONTAINER_DLL_remove (opc->c->ocq_head, opc->c->ocq_tail, opc);
  GNUNET_free (opc);
}


/**
 * Starts a controller process at the host. FIXME: add controller start callback
 * with the configuration with which the controller is started
 *
 * @param controller_ip the ip address of the controller. Will be set as TRUSTED
 *          host when starting testbed controller at host
 * @param host the host where the controller has to be started; NULL for
 *          localhost
 * @param cfg template configuration to use for the remote controller; the
 *          remote controller will be started with a slightly modified
 *          configuration (port numbers, unix domain sockets and service home
 *          values are changed as per TESTING library on the remote host)
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
GNUNET_TESTBED_controller_start (const char *controller_ip,
				 struct GNUNET_TESTBED_Host *host,
				 const struct GNUNET_CONFIGURATION_Handle *cfg,
                                 GNUNET_TESTBED_ControllerStatusCallback cb,
				 void *cls)
{
  struct GNUNET_TESTBED_ControllerProc *cp;
  struct GNUNET_TESTBED_HelperInit *msg;
  
  cp = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_ControllerProc));
  if ((NULL == host) || (0 == GNUNET_TESTBED_host_get_id_ (host)))
  {
    char * const binary_argv[] = {
      "gnunet-testbed-helper", NULL
    };

    cp->helper = GNUNET_HELPER_start ("gnunet-testbed-helper", binary_argv, 
                                      &helper_mst, &helper_exp_cb, cp);
  }
  else
  {
    char *remote_args[6 + 1];
    unsigned int argp;
    const char *username;
    const char *hostname;

    username = GNUNET_TESTBED_host_get_username_ (host);
    hostname = GNUNET_TESTBED_host_get_hostname_ (host);
    GNUNET_asprintf (&cp->port, "%u", GNUNET_TESTBED_host_get_ssh_port_ (host));
    if (NULL == username)
      GNUNET_asprintf (&cp->dst, "%s", hostname);
    else 
      GNUNET_asprintf (&cp->dst, "%s@%s", username, hostname);
    LOG_DEBUG ("Starting SSH to destination %s\n", cp->dst);
    argp = 0;
    remote_args[argp++] = "ssh";
    remote_args[argp++] = "-p";
    remote_args[argp++] = cp->port;
    remote_args[argp++] = "-q";
    remote_args[argp++] = cp->dst;
    remote_args[argp++] = "gnunet-testbed-helper";
    remote_args[argp++] = NULL;
    GNUNET_assert (argp == 6 + 1);
    cp->helper = GNUNET_HELPER_start ("ssh", remote_args,
                                      &helper_mst, &helper_exp_cb, cp);
  }
  if (NULL == cp->helper)
  {
    GNUNET_free_non_null (cp->port);
    GNUNET_free_non_null (cp->dst);
    GNUNET_free (cp);
    return NULL;
  }
  cp->host = host;
  cp->cb = cb;
  cp->cls = cls;
  msg = GNUNET_TESTBED_create_helper_init_msg_ (controller_ip, cfg);
  cp->msg = &msg->header;
  cp->shandle = GNUNET_HELPER_send (cp->helper, &msg->header, GNUNET_NO,
                                    &clear_msg, cp);
  if (NULL == cp->shandle)
  {
    GNUNET_free (msg);
    GNUNET_TESTBED_controller_stop (cp);
    return NULL;
  }
  return cp;
}


/**
 * Stop the controller process (also will terminate all peers and controllers
 * dependent on this controller).  This function blocks until the testbed has
 * been fully terminated (!).
 *
 * @param cproc the controller process handle
 */
void
GNUNET_TESTBED_controller_stop (struct GNUNET_TESTBED_ControllerProc *cproc)
{
  if (NULL != cproc->shandle)
    GNUNET_HELPER_send_cancel (cproc->shandle);
  if (NULL != cproc->helper)
    GNUNET_HELPER_stop (cproc->helper);
  if (NULL != cproc->cfg)
    GNUNET_CONFIGURATION_destroy (cproc->cfg);
  GNUNET_free_non_null (cproc->port);
  GNUNET_free_non_null (cproc->dst);
  GNUNET_free (cproc);
}


/**
 * Start a controller process using the given configuration at the
 * given host.
 *
 * @param cfg configuration to use
 * @param host host to run the controller on; This should be the same host if
 *          the controller was previously started with
 *          GNUNET_TESTBED_controller_start; NULL for localhost
 * @param event_mask bit mask with set of events to call 'cc' for;
 *                   or-ed values of "1LL" shifted by the
 *                   respective 'enum GNUNET_TESTBED_EventType'
 *                   (i.e.  "(1LL << GNUNET_TESTBED_ET_CONNECT) | ...")
 * @param cc controller callback to invoke on events
 * @param cc_cls closure for cc
 * @return handle to the controller
 */
struct GNUNET_TESTBED_Controller *
GNUNET_TESTBED_controller_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
				   struct GNUNET_TESTBED_Host *host,
				   uint64_t event_mask,
				   GNUNET_TESTBED_ControllerCallback cc,
				   void *cc_cls)
{
  struct GNUNET_TESTBED_Controller *controller;
  struct GNUNET_TESTBED_InitMessage *msg;
  const char *controller_hostname;
  unsigned long long max_parallel_peer_create;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "testbed",
                                             "MAX_PARALLEL_PEER_CREATE",
                                             &max_parallel_peer_create))
  {
    GNUNET_break (0);
    return NULL;
  }                                                          
  controller = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_Controller));
  controller->cc = cc;
  controller->cc_cls = cc_cls;
  controller->event_mask = event_mask;
  controller->cfg = GNUNET_CONFIGURATION_dup (cfg);
  controller->client = GNUNET_CLIENT_connect ("testbed", controller->cfg);  
  if (NULL == controller->client)
  {
    GNUNET_TESTBED_controller_disconnect (controller);
    return NULL;
  }
  if (NULL == host)
  {
    host = GNUNET_TESTBED_host_create_by_id_ (0);
    if (NULL == host)           /* If the above host create fails */
    {
      LOG (GNUNET_ERROR_TYPE_WARNING,
	   "Treating NULL host as localhost. Multiple references to localhost "
	   "may break when localhost freed before calling disconnect \n");
      host = GNUNET_TESTBED_host_lookup_by_id_ (0);
    }
    else
    {
      controller->aux_host = GNUNET_YES;
    }
  }
  GNUNET_assert (NULL != host);
  GNUNET_TESTBED_mark_host_registered_at_ (host, controller);
  controller->host = host;
  controller->opq_peer_create =
    GNUNET_TESTBED_operation_queue_create_ ((unsigned int)
                                            max_parallel_peer_create);
  controller_hostname = GNUNET_TESTBED_host_get_hostname_ (host);
  if (NULL == controller_hostname)
    controller_hostname = "127.0.0.1";
  msg = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_InitMessage)
                       + strlen (controller_hostname) + 1);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_INIT);
  msg->header.size = htons (sizeof (struct GNUNET_TESTBED_InitMessage)
                            + strlen (controller_hostname) + 1);
  msg->host_id = htonl (GNUNET_TESTBED_host_get_id_ (host));
  msg->event_mask = GNUNET_htonll (controller->event_mask);
  strcpy ((char *) &msg[1], controller_hostname);
  GNUNET_TESTBED_queue_message_ (controller, (struct GNUNET_MessageHeader *)
                                 msg);  
  return controller;
}


/**
 * Configure shared services at a controller.  Using this function,
 * you can specify that certain services (such as "resolver")
 * should not be run for each peer but instead be shared
 * across N peers on the specified host.  This function
 * must be called before any peers are created at the host.
 * 
 * @param controller controller to configure
 * @param service_name name of the service to share
 * @param num_peers number of peers that should share one instance
 *        of the specified service (1 for no sharing is the default),
 *        use 0 to disable the service
 */
void
GNUNET_TESTBED_controller_configure_sharing (struct GNUNET_TESTBED_Controller *controller,
					     const char *service_name,
					     uint32_t num_peers)
{
  struct GNUNET_TESTBED_ConfigureSharedServiceMessage *msg;
  uint16_t service_name_size;
  uint16_t msg_size;
  
  service_name_size = strlen (service_name) + 1;
  msg_size = sizeof (struct GNUNET_TESTBED_ConfigureSharedServiceMessage)
    + service_name_size;
  msg = GNUNET_malloc (msg_size);
  msg->header.size = htons (msg_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_SERVICESHARE);
  msg->host_id = htonl (GNUNET_TESTBED_host_get_id_ (controller->host));
  msg->num_peers = htonl (num_peers);
  memcpy (&msg[1], service_name, service_name_size);
  GNUNET_TESTBED_queue_message_ (controller, (struct GNUNET_MessageHeader *) msg);
}


/**
 * disconnects from the controller.
 *
 * @param controller handle to controller to stop
 */
void
GNUNET_TESTBED_controller_disconnect (struct GNUNET_TESTBED_Controller *controller)
{
  struct MessageQueue *mq_entry;

  if (NULL != controller->th)
    GNUNET_CLIENT_notify_transmit_ready_cancel (controller->th);
 /* Clear the message queue */
  while (NULL != (mq_entry = controller->mq_head))
  {
    GNUNET_CONTAINER_DLL_remove (controller->mq_head,
				 controller->mq_tail,
				 mq_entry);
    GNUNET_free (mq_entry->msg);
    GNUNET_free (mq_entry);
  }
  if (NULL != controller->client)
    GNUNET_CLIENT_disconnect (controller->client);
  GNUNET_CONFIGURATION_destroy (controller->cfg);
  if (GNUNET_YES == controller->aux_host)
    GNUNET_TESTBED_host_destroy (controller->host);
  GNUNET_TESTBED_operation_queue_destroy_ (controller->opq_peer_create);
  GNUNET_free (controller);
}


/**
 * Register a host with the controller
 *
 * @param controller the controller handle
 * @param host the host to register
 * @param cc the completion callback to call to inform the status of
 *          registration. After calling this callback the registration handle
 *          will be invalid. Cannot be NULL.
 * @param cc_cls the closure for the cc
 * @return handle to the host registration which can be used to cancel the
 *           registration 
 */
struct GNUNET_TESTBED_HostRegistrationHandle *
GNUNET_TESTBED_register_host (struct GNUNET_TESTBED_Controller *controller,
                              struct GNUNET_TESTBED_Host *host,
                              GNUNET_TESTBED_HostRegistrationCompletion cc,
                              void *cc_cls)
{
  struct GNUNET_TESTBED_HostRegistrationHandle *rh;
  struct GNUNET_TESTBED_AddHostMessage *msg;
  const char *username;
  const char *hostname;
  uint16_t msg_size;
  uint16_t user_name_length;

  if (NULL != controller->rh)
    return NULL;
  hostname = GNUNET_TESTBED_host_get_hostname_ (host);
  if (GNUNET_YES == GNUNET_TESTBED_is_host_registered_ (host, controller))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Host hostname: %s already registered\n",
         (NULL == hostname) ? "localhost" : hostname);
    return NULL;
  }  
  rh = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_HostRegistrationHandle));
  rh->host = host;
  rh->c = controller;
  GNUNET_assert (NULL != cc);
  rh->cc = cc;
  rh->cc_cls = cc_cls;
  controller->rh = rh;
  username = GNUNET_TESTBED_host_get_username_ (host);
  msg_size = (sizeof (struct GNUNET_TESTBED_AddHostMessage));
  user_name_length = 0;
  if (NULL != username)
  {
    user_name_length = strlen (username) + 1;
    msg_size += user_name_length;
  }
  /* FIXME: what happens when hostname is NULL? localhost */
  GNUNET_assert (NULL != hostname);
  msg_size += strlen (hostname) + 1;
  msg = GNUNET_malloc (msg_size);
  msg->header.size = htons (msg_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_ADDHOST);
  msg->host_id = htonl (GNUNET_TESTBED_host_get_id_ (host));
  msg->ssh_port = htons (GNUNET_TESTBED_host_get_ssh_port_ (host));
  msg->user_name_length = htons (user_name_length);
  if (NULL != username)
    memcpy (&msg[1], username, user_name_length);
  strcpy (((void *) &msg[1]) + user_name_length, hostname);
  GNUNET_TESTBED_queue_message_ (controller, (struct GNUNET_MessageHeader *) msg);
  return rh;
}


/**
 * Cancel the pending registration. Note that if the registration message is
 * already sent to the service the cancellation has only the effect that the
 * registration completion callback for the registration is never called.
 *
 * @param handle the registration handle to cancel
 */
void
GNUNET_TESTBED_cancel_registration (struct GNUNET_TESTBED_HostRegistrationHandle
                                    *handle)
{
  if (handle != handle->c->rh)
  {
    GNUNET_break (0);
    return;
  }
  handle->c->rh = NULL;
  GNUNET_free (handle);  
}


/**
 * Same as the GNUNET_TESTBED_controller_link, however expects configuration in
 * serialized and compressed
 *
 * @param master handle to the master controller who creates the association
 * @param delegated_host requests to which host should be delegated; cannot be NULL
 * @param slave_host which host is used to run the slave controller; use NULL to
 *          make the master controller connect to the delegated host
 * @param sxcfg serialized and compressed configuration
 * @param sxcfg_size the size scfg
 * @param scfg_size the size of uncompressed serialized configuration
 * @param is_subordinate GNUNET_YES if the controller at delegated_host should
 *          be started by the master controller; GNUNET_NO if we are just
 *          allowed to use the slave via TCP/IP
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_controller_link_2 (struct GNUNET_TESTBED_Controller *master,
				  struct GNUNET_TESTBED_Host *delegated_host,
				  struct GNUNET_TESTBED_Host *slave_host,
				  const char *sxcfg,
				  size_t sxcfg_size,
				  size_t scfg_size,
				  int is_subordinate)
{
  struct OperationContext *opc;
  struct GNUNET_TESTBED_ControllerLinkMessage *msg;
  uint16_t msg_size;

  GNUNET_assert (GNUNET_YES == 
		 GNUNET_TESTBED_is_host_registered_ (delegated_host, master));
  if ((NULL != slave_host) && (0 != GNUNET_TESTBED_host_get_id_ (slave_host)))
    GNUNET_assert (GNUNET_YES == 
		   GNUNET_TESTBED_is_host_registered_ (slave_host, master));
  msg_size = sxcfg_size + sizeof (struct GNUNET_TESTBED_ControllerLinkMessage);
  msg = GNUNET_malloc (msg_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_LCONTROLLERS);  
  msg->header.size = htons (msg_size);
  msg->delegated_host_id = htonl (GNUNET_TESTBED_host_get_id_ (delegated_host));
  msg->slave_host_id = htonl (GNUNET_TESTBED_host_get_id_ 
			      ((NULL != slave_host) ? slave_host : master->host));
  msg->config_size = htons ((uint16_t) scfg_size);
  msg->is_subordinate = (GNUNET_YES == is_subordinate) ? 1 : 0;
  memcpy (&msg[1], sxcfg, sxcfg_size);
  opc = GNUNET_malloc (sizeof (struct OperationContext));
  opc->c = master;
  opc->data = msg;
  opc->type = OP_LINK_CONTROLLERS;
  opc->id = master->operation_counter++;
  opc->state = OPC_STATE_INIT;
  msg->operation_id = GNUNET_htonll (opc->id);
  opc->op = GNUNET_TESTBED_operation_create_ (opc, &opstart_link_controllers,
                                              &oprelease_link_controllers);
  GNUNET_TESTBED_operation_queue_insert_ (master->opq_peer_create, opc->op);
  return opc->op;
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
GNUNET_TESTBED_compress_config_ (const char *config, size_t size,
				 char **xconfig)
{
  size_t xsize;
  
  xsize = compressBound ((uLong) size);
  *xconfig = GNUNET_malloc (xsize);
  GNUNET_assert (Z_OK ==
		 compress2 ((Bytef *)* xconfig, (uLongf *) &xsize,
                            (const Bytef *) config, (uLongf) size, 
                            Z_BEST_SPEED));
  return xsize;
}
                                

/**
 * Create a link from slave controller to delegated controller. Whenever the
 * master controller is asked to start a peer at the delegated controller the
 * request will be routed towards slave controller (if a route exists). The
 * slave controller will then route it to the delegated controller. The
 * configuration of the slave controller is given and to be used to either
 * create the slave controller or to connect to an existing slave controller
 * process.  'is_subordinate' specifies if the given slave controller should be
 * started and managed by the master controller, or if the slave already has a
 * master and this is just a secondary master that is also allowed to use the
 * existing slave.
 *
 * @param master handle to the master controller who creates the association
 * @param delegated_host requests to which host should be delegated
 * @param slave_host which host is used to run the slave controller 
 * @param slave_cfg configuration to use for the slave controller
 * @param is_subordinate GNUNET_YES if the slave should be started (and stopped)
 *                       by the master controller; GNUNET_NO if we are just
 *                       allowed to use the slave via TCP/IP
 * @return the operation handle
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_controller_link (struct GNUNET_TESTBED_Controller *master,
				struct GNUNET_TESTBED_Host *delegated_host,
				struct GNUNET_TESTBED_Host *slave_host,
				const struct GNUNET_CONFIGURATION_Handle *slave_cfg,
				int is_subordinate)
{
  struct GNUNET_TESTBED_Operation *op;
  char *config;
  char *cconfig;
  size_t cc_size;
  size_t config_size;  
  
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_TESTBED_is_host_registered_ (delegated_host, master));
  if ((NULL != slave_host) && (0 != GNUNET_TESTBED_host_get_id_ (slave_host)))
    GNUNET_assert (GNUNET_YES ==
		   GNUNET_TESTBED_is_host_registered_ (slave_host, master));
  config = GNUNET_CONFIGURATION_serialize (slave_cfg, &config_size);
  cc_size = GNUNET_TESTBED_compress_config_ (config, config_size, &cconfig);
  GNUNET_free (config);
  GNUNET_assert ((UINT16_MAX -
		  sizeof (struct GNUNET_TESTBED_ControllerLinkMessage))
		  >= cc_size); /* Configuration doesn't fit in 1 message */
  op = GNUNET_TESTBED_controller_link_2 (master, delegated_host, slave_host,
				    (const char *) cconfig,
				    cc_size, config_size, is_subordinate);
  GNUNET_free (cconfig);
  return op;
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
GNUNET_TESTBED_overlay_write_topology_to_file (struct GNUNET_TESTBED_Controller *controller,
					       const char *filename)
{
  GNUNET_break (0);
}


/**
 * Creates a helper initialization message. This function is here because we
 * want to use this in testing
 *
 * @param cname the ip address of the controlling host
 * @param cfg the configuration that has to used to start the testbed service
 *          thru helper
 * @return the initialization message
 */
struct GNUNET_TESTBED_HelperInit *
GNUNET_TESTBED_create_helper_init_msg_ (const char *cname,
					 const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_TESTBED_HelperInit *msg;
  char *config;
  char *xconfig;
  size_t config_size;
  size_t xconfig_size;
  uint16_t cname_len;
  uint16_t msg_size;

  config = GNUNET_CONFIGURATION_serialize (cfg, &config_size);
  GNUNET_assert (NULL != config);
  xconfig_size =
    GNUNET_TESTBED_compress_config_ (config, config_size, &xconfig);
  GNUNET_free (config);
  cname_len = strlen (cname);
  msg_size = xconfig_size + cname_len + 1 + 
    sizeof (struct GNUNET_TESTBED_HelperInit);
  msg = GNUNET_realloc (xconfig, msg_size);
  (void) memmove ( ((void *) &msg[1]) + cname_len + 1, msg, xconfig_size);
  msg->header.size = htons (msg_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_HELPER_INIT);
  msg->cname_size = htons (cname_len);
  msg->config_size = htons (config_size);
  (void) strcpy ((char *) &msg[1], cname);
  return msg;
}


/**
 * Cancel a pending operation.  Releases all resources
 * of the operation and will ensure that no event
 * is generated for the operation.  Does NOT guarantee
 * that the operation will be fully undone (or that
 * nothing ever happened).  
 * 
 * @param operation operation to cancel
 */
void
GNUNET_TESTBED_operation_cancel (struct GNUNET_TESTBED_Operation *operation)
{
  GNUNET_TESTBED_operation_done (operation);
}


/**
 * Signal that the information from an operation has been fully
 * processed.  This function MUST be called for each event
 * of type 'operation_finished' to fully remove the operation
 * from the operation queue.  After calling this function, the
 * 'op_result' becomes invalid (!).
 * 
 * @param operation operation to signal completion for
 */
void
GNUNET_TESTBED_operation_done (struct GNUNET_TESTBED_Operation *operation)
{
  switch (operation->type)
  {
  case OP_PEER_CREATE:
  case OP_PEER_DESTROY:
  case OP_PEER_START:
  case OP_PEER_STOP:
  case OP_PEER_INFO:
  case OP_OVERLAY_CONNECT:
  case OP_LINK_CONTROLLERS:
    GNUNET_TESTBED_operation_release_ (operation);
    return;
  default:
    GNUNET_assert (0);
    break;
  }
}

/* end of testbed_api.c */
