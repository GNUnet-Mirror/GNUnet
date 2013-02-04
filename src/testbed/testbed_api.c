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
 * Handle for controller process
 */
struct GNUNET_TESTBED_ControllerProc
{
  /**
   * The process handle
   */
  struct GNUNET_HELPER_Handle *helper;

  /**
   * The arguments used to start the helper
   */
  char **helper_argv;

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
   * The configuration of the running testbed service
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

};


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
  struct GNUNET_TESTBED_ControllerLinkMessage *msg;

};


struct SDEntry
{
  /**
   * DLL next pointer
   */
  struct SDEntry *next;

  /**
   * DLL prev pointer
   */
  struct SDEntry *prev;

  /**
   * The value to store
   */
  unsigned int amount;
};


struct SDHandle
{
  /**
   * DLL head for storing entries
   */
  struct SDEntry *head;

  /**
   * DLL tail for storing entries
   */
  struct SDEntry *tail;

  /**
   * Squared sum of data values
   */
  unsigned long long sqsum;

  /**
   * Sum of the data values
   */
  unsigned long sum;

  /**
   * The average of data amounts
   */
  float avg;

  /**
   * The variance
   */
  double vr;

  /**
   * Number of data values; also the length of DLL containing SDEntries
   */
  unsigned int cnt;

  /**
   * max number of entries we can have in the DLL
   */
  unsigned int max_cnt;
};


/**
 * This variable is set to the operation that has been last marked as done. It
 * is used to verify whether the state associated with an operation is valid
 * after the first notify callback is called. Such checks are necessary for
 * certain operations where we have 2 notify callbacks. Examples are
 * OP_PEER_CREATE, OP_PEER_START/STOP, OP_OVERLAY_CONNECT.
 *
 * This variable should ONLY be used to compare; it is a dangling pointer!!
 */
static const struct GNUNET_TESTBED_Operation *last_finished_operation;

/**
 * Initialize standard deviation calculation handle
 *
 * @param max_cnt the maximum number of readings to keep
 * @return the initialized handle
 */
static struct SDHandle *
SD_init (unsigned int max_cnt)
{
  struct SDHandle *h;

  GNUNET_assert (1 < max_cnt);
  h = GNUNET_malloc (sizeof (struct SDHandle));
  h->max_cnt = max_cnt;
  return h;
}


/**
 * Frees the memory allocated to the SD handle
 *
 * @param h the SD handle
 */
static void
SD_destroy (struct SDHandle *h)
{
  struct SDEntry *entry;

  while (NULL != (entry = h->head))
  {
    GNUNET_CONTAINER_DLL_remove (h->head, h->tail, entry);
    GNUNET_free (entry);
  }
  GNUNET_free (h);
}


/**
 * Add a reading to SD
 *
 * @param h the SD handle
 * @param amount the reading value
 */
static void
SD_add_data (struct SDHandle *h, unsigned int amount)
{
  struct SDEntry *entry;
  double sqavg;
  double sqsum_avg;

  entry = NULL;
  if (h->cnt == h->max_cnt)
  {
    entry = h->head;
    GNUNET_CONTAINER_DLL_remove (h->head, h->tail, entry);
    h->sum -= entry->amount;
    h->sqsum -=
        ((unsigned long) entry->amount) * ((unsigned long) entry->amount);
    h->cnt--;
  }
  GNUNET_assert (h->cnt < h->max_cnt);
  if (NULL == entry)
    entry = GNUNET_malloc (sizeof (struct SDEntry));
  entry->amount = amount;
  GNUNET_CONTAINER_DLL_insert_tail (h->head, h->tail, entry);
  h->sum += amount;
  h->cnt++;
  h->avg = ((float) h->sum) / ((float) h->cnt);
  h->sqsum += ((unsigned long) amount) * ((unsigned long) amount);
  sqsum_avg = ((double) h->sqsum) / ((double) h->cnt);
  sqavg = ((double) h->avg) * ((double) h->avg);
  h->vr = sqsum_avg - sqavg;
}


/**
 * Returns the factor by which the given amount differs from the standard deviation
 *
 * @param h the SDhandle
 * @param amount the value for which the deviation is returned

 * @return the deviation from the average; GNUNET_SYSERR if the deviation cannot
 *           be calculated OR 0 if the deviation is less than the average; a
 *           maximum of 4 is returned for deviations equal to or larger than 4
 */
static int
SD_deviation_factor (struct SDHandle *h, unsigned int amount)
{
  double diff;
  unsigned int n;

  if (h->cnt < 2)
    return GNUNET_SYSERR;
  if (((float) amount) > h->avg)
    diff = ((float) amount) - h->avg;
  else
    return 0;                   //diff = h->avg - ((float) amount);
  diff *= diff;
  for (n = 1; n < 4; n++)
    if (diff < (((double) (n * n)) * h->vr))
      break;
  return n;
}


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
    GNUNET_TESTBED_mark_host_registered_at_ (rh->host, c);
    rh->cc (rh->cc_cls, NULL);
    GNUNET_free (rh);
    return GNUNET_OK;
  }
  /* We have an error message */
  emsg = (char *) &msg[1];
  if ('\0' !=
      emsg[msg_size - sizeof (struct GNUNET_TESTBED_HostConfirmedMessage)])
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
 * Handler for forwarded operations
 *
 * @param c the controller handle
 * @param opc the opearation context
 * @param msg the message
 */
static void
handle_forwarded_operation_msg (struct GNUNET_TESTBED_Controller *c,
                                struct OperationContext *opc,
                                const struct GNUNET_MessageHeader *msg)
{
  struct ForwardedOperationData *fo_data;

  fo_data = opc->data;
  if (NULL != fo_data->cc)
    fo_data->cc (fo_data->cc_cls, msg);
  GNUNET_CONTAINER_DLL_remove (c->ocq_head, c->ocq_tail, opc);
  GNUNET_free (fo_data);
  GNUNET_free (opc);
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
  struct GNUNET_TESTBED_EventInformation event;
  uint64_t op_id;

  op_id = GNUNET_ntohll (msg->operation_id);
  LOG_DEBUG ("Operation %lu successful\n", op_id);
  if (NULL == (opc = find_opc (c, op_id)))
  {
    LOG_DEBUG ("Operation not found\n");
    return GNUNET_YES;
  }
  event.type = GNUNET_TESTBED_ET_OPERATION_FINISHED;
  event.details.operation_finished.operation = opc->op;
  event.details.operation_finished.op_cls = opc->op_cls;
  event.details.operation_finished.emsg = NULL;
  event.details.operation_finished.generic = NULL;
  switch (opc->type)
  {
  case OP_FORWARDED:
  {
    handle_forwarded_operation_msg (c, opc,
                                    (const struct GNUNET_MessageHeader *) msg);
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
  {
    struct ControllerLinkData *data;

    data = opc->data;
    GNUNET_assert (NULL != data);
    GNUNET_free (data);
    opc->data = NULL;
  }
    break;
  default:
    GNUNET_assert (0);
  }
  GNUNET_CONTAINER_DLL_remove (opc->c->ocq_head, opc->c->ocq_tail, opc);
  opc->state = OPC_STATE_FINISHED;
  if (0 != (c->event_mask & (1L << GNUNET_TESTBED_ET_OPERATION_FINISHED)))
  {
    if (NULL != c->cc)
      c->cc (c->cc_cls, &event);
  }
  else
    LOG_DEBUG ("Not calling callback\n");
  return GNUNET_YES;
}


/**
 * Handler for GNUNET_MESSAGE_TYPE_TESTBED_PEERCREATESUCCESS message from
 * controller (testbed service)
 *
 * @param c the controller handle
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

  GNUNET_assert (sizeof (struct GNUNET_TESTBED_PeerCreateSuccessEventMessage) ==
                 ntohs (msg->header.size));
  op_id = GNUNET_ntohll (msg->operation_id);
  if (NULL == (opc = find_opc (c, op_id)))
  {
    LOG_DEBUG ("Operation context for PeerCreateSuccessEvent not found\n");
    return GNUNET_YES;
  }
  if (OP_FORWARDED == opc->type)
  {
    handle_forwarded_operation_msg (c, opc,
                                    (const struct GNUNET_MessageHeader *) msg);
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
  struct PeerEventData *data;
  GNUNET_TESTBED_PeerChurnCallback pcc;
  void *pcc_cls;
  struct GNUNET_TESTBED_EventInformation event;
  uint64_t op_id;

  GNUNET_assert (sizeof (struct GNUNET_TESTBED_PeerEventMessage) ==
                 ntohs (msg->header.size));
  op_id = GNUNET_ntohll (msg->operation_id);
  if (NULL == (opc = find_opc (c, op_id)))
  {
    LOG_DEBUG ("Operation not found\n");
    return GNUNET_YES;
  }
  if (OP_FORWARDED == opc->type)
  {
    handle_forwarded_operation_msg (c, opc,
                                    (const struct GNUNET_MessageHeader *) msg);
    return GNUNET_YES;
  }
  GNUNET_assert ((OP_PEER_START == opc->type) || (OP_PEER_STOP == opc->type));
  data = opc->data;
  GNUNET_assert (NULL != data);
  peer = data->peer;
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
    GNUNET_assert (0);          /* We should never reach this state */
  }
  pcc = data->pcc;
  pcc_cls = data->pcc_cls;
  GNUNET_free (data);
  GNUNET_CONTAINER_DLL_remove (opc->c->ocq_head, opc->c->ocq_tail, opc);
  opc->state = OPC_STATE_FINISHED;
  if (0 !=
      ((GNUNET_TESTBED_ET_PEER_START | GNUNET_TESTBED_ET_PEER_STOP) &
       c->event_mask))
  {
    if (NULL != c->cc)
      c->cc (c->cc_cls, &event);
  }
  if (NULL != pcc)
    pcc (pcc_cls, NULL);
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
  GNUNET_TESTBED_OperationCompletionCallback cb;
  void *cb_cls;
  struct GNUNET_TESTBED_EventInformation event;
  uint64_t op_id;

  op_id = GNUNET_ntohll (msg->operation_id);
  if (NULL == (opc = find_opc (c, op_id)))
  {
    LOG_DEBUG ("Operation not found\n");
    return GNUNET_YES;
  }
  if (OP_FORWARDED == opc->type)
  {
    handle_forwarded_operation_msg (c, opc,
                                    (const struct GNUNET_MessageHeader *) msg);
    return GNUNET_YES;
  }
  GNUNET_assert (OP_OVERLAY_CONNECT == opc->type);
  data = opc->data;
  GNUNET_assert (NULL != data);
  GNUNET_assert ((ntohl (msg->peer1) == data->p1->unique_id) &&
                 (ntohl (msg->peer2) == data->p2->unique_id));
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
  cb = data->cb;
  cb_cls = data->cb_cls;
  GNUNET_CONTAINER_DLL_remove (opc->c->ocq_head, opc->c->ocq_tail, opc);
  opc->state = OPC_STATE_FINISHED;
  if (NULL != cb)
    cb (cb_cls, opc->op, NULL);
  if (0 !=
      ((GNUNET_TESTBED_ET_CONNECT | GNUNET_TESTBED_ET_DISCONNECT) &
       c->event_mask))
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
                    const struct
                    GNUNET_TESTBED_PeerConfigurationInformationMessage *msg)
{
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
    return GNUNET_YES;
  }
  if (OP_FORWARDED == opc->type)
  {
    handle_forwarded_operation_msg (c, opc,
                                    (const struct GNUNET_MessageHeader *) msg);
    return GNUNET_YES;
  }
  data = opc->data;
  GNUNET_assert (NULL != data);
  peer = data->peer;
  GNUNET_assert (NULL != peer);
  GNUNET_assert (ntohl (msg->peer_id) == peer->unique_id);
  pinfo = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_PeerInformation));
  pinfo->pit = data->pit;
  cb = data->cb;
  cb_cls = data->cb_cls;
  GNUNET_free (data);
  opc->data = NULL;
  switch (pinfo->pit)
  {
  case GNUNET_TESTBED_PIT_IDENTITY:
    pinfo->result.id = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity));
    (void) memcpy (pinfo->result.id, &msg->peer_identity,
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
  GNUNET_CONTAINER_DLL_remove (opc->c->ocq_head, opc->c->ocq_tail, opc);
  opc->state = OPC_STATE_FINISHED;
  if (NULL != cb)
    cb (cb_cls, opc->op, pinfo, NULL);
  return GNUNET_YES;
}


/**
 * Handler for GNUNET_MESSAGE_TYPE_TESTBED_OPERATIONFAILEVENT message from
 * controller (testbed service)
 *
 * @param c the controller handler
 * @param msg message received
 * @return GNUNET_YES if we can continue receiving from service; GNUNET_NO if
 *           not
 */
static int
handle_op_fail_event (struct GNUNET_TESTBED_Controller *c,
                      const struct GNUNET_TESTBED_OperationFailureEventMessage
                      *msg)
{
  struct OperationContext *opc;
  const char *emsg;
  uint64_t op_id;
  struct GNUNET_TESTBED_EventInformation event;

  op_id = GNUNET_ntohll (msg->operation_id);
  if (NULL == (opc = find_opc (c, op_id)))
  {
    LOG_DEBUG ("Operation not found\n");
    return GNUNET_YES;
  }
  if (OP_FORWARDED == opc->type)
  {
    handle_forwarded_operation_msg (c, opc,
                                    (const struct GNUNET_MessageHeader *) msg);
    return GNUNET_YES;
  }
  GNUNET_CONTAINER_DLL_remove (opc->c->ocq_head, opc->c->ocq_tail, opc);
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
    return GNUNET_YES;          /* We do not call controller callback for peer info */
  }
  if ((0 != (GNUNET_TESTBED_ET_OPERATION_FINISHED & c->event_mask)) &&
      (NULL != c->cc))
  {
    event.type = GNUNET_TESTBED_ET_OPERATION_FINISHED;
    event.details.operation_finished.operation = opc->op;
    event.details.operation_finished.op_cls = opc->op_cls;
    event.details.operation_finished.emsg = emsg;
    event.details.operation_finished.generic = NULL;
    c->cc (c->cc_cls, &event);
    if (event.details.operation_finished.operation == last_finished_operation)
      return GNUNET_YES;
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
    data->failed = GNUNET_YES;
    if (NULL != data->cb)
      data->cb (data->cb_cls, opc->op, emsg);
  }
    break;
  case OP_FORWARDED:
    GNUNET_assert (0);
  case OP_LINK_CONTROLLERS:    /* No secondary callback */
    break;
  default:
    GNUNET_break (0);
  }
  return GNUNET_YES;
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
 * Handler for GNUNET_MESSAGE_TYPE_TESTBED_SLAVECONFIG message from controller
 * (testbed service)
 *
 * @param c the controller handler
 * @param msg message received
 * @return GNUNET_YES if we can continue receiving from service; GNUNET_NO if
 *           not
 */
static int
handle_slave_config (struct GNUNET_TESTBED_Controller *c,
                     const struct GNUNET_TESTBED_SlaveConfiguration *msg)
{
  struct OperationContext *opc;
  uint64_t op_id;
  struct GNUNET_TESTBED_EventInformation event;

  op_id = GNUNET_ntohll (msg->operation_id);
  if (NULL == (opc = find_opc (c, op_id)))
  {
    LOG_DEBUG ("Operation not found\n");
    return GNUNET_YES;
  }
  if (OP_GET_SLAVE_CONFIG != opc->type)
  {
    GNUNET_break (0);
    return GNUNET_YES;
  }
  GNUNET_free (opc->data);
  opc->data = NULL;
  opc->state = OPC_STATE_FINISHED;
  GNUNET_CONTAINER_DLL_remove (opc->c->ocq_head, opc->c->ocq_tail, opc);
  if ((0 != (GNUNET_TESTBED_ET_OPERATION_FINISHED & c->event_mask)) &&
      (NULL != c->cc))
  {
    opc->data = GNUNET_TESTBED_extract_config_ (&msg->header);
    event.type = GNUNET_TESTBED_ET_OPERATION_FINISHED;
    event.details.operation_finished.generic = opc->data;
    event.details.operation_finished.operation = opc->op;
    event.details.operation_finished.op_cls = opc->op_cls;
    event.details.operation_finished.emsg = NULL;
    c->cc (c->cc_cls, &event);
  }
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
  case GNUNET_MESSAGE_TYPE_TESTBED_ADD_HOST_SUCCESS:
    GNUNET_assert (msize >=
                   sizeof (struct GNUNET_TESTBED_HostConfirmedMessage));
    status =
        handle_addhostconfirm (c,
                               (const struct GNUNET_TESTBED_HostConfirmedMessage
                                *) msg);
    break;
  case GNUNET_MESSAGE_TYPE_TESTBED_GENERIC_OPERATION_SUCCESS:
    GNUNET_assert (msize ==
                   sizeof (struct
                           GNUNET_TESTBED_GenericOperationSuccessEventMessage));
    status =
        handle_opsuccess (c,
                          (const struct
                           GNUNET_TESTBED_GenericOperationSuccessEventMessage *)
                          msg);
    break;
  case GNUNET_MESSAGE_TYPE_TESTBED_CREATE_PEER_SUCCESS:
    GNUNET_assert (msize ==
                   sizeof (struct
                           GNUNET_TESTBED_PeerCreateSuccessEventMessage));
    status =
        handle_peer_create_success (c,
                                    (const struct
                                     GNUNET_TESTBED_PeerCreateSuccessEventMessage
                                     *) msg);
    break;
  case GNUNET_MESSAGE_TYPE_TESTBED_PEER_EVENT:
    GNUNET_assert (msize == sizeof (struct GNUNET_TESTBED_PeerEventMessage));
    status =
        handle_peer_event (c,
                           (const struct GNUNET_TESTBED_PeerEventMessage *)
                           msg);

    break;
  case GNUNET_MESSAGE_TYPE_TESTBED_PEER_CONFIGURATION:
    GNUNET_assert (msize >=
                   sizeof (struct
                           GNUNET_TESTBED_PeerConfigurationInformationMessage));
    status =
        handle_peer_config (c,
                            (const struct
                             GNUNET_TESTBED_PeerConfigurationInformationMessage
                             *) msg);
    break;
  case GNUNET_MESSAGE_TYPE_TESTBED_PEER_CONNECT_EVENT:
    GNUNET_assert (msize ==
                   sizeof (struct GNUNET_TESTBED_ConnectionEventMessage));
    status =
        handle_peer_conevent (c,
                              (const struct
                               GNUNET_TESTBED_ConnectionEventMessage *) msg);
    break;
  case GNUNET_MESSAGE_TYPE_TESTBED_OPERATION_FAIL_EVENT:
    GNUNET_assert (msize >=
                   sizeof (struct GNUNET_TESTBED_OperationFailureEventMessage));
    status =
        handle_op_fail_event (c,
                              (const struct
                               GNUNET_TESTBED_OperationFailureEventMessage *)
                              msg);
    break;
  case GNUNET_MESSAGE_TYPE_TESTBED_SLAVE_CONFIGURATION:
    GNUNET_assert (msize > sizeof (struct GNUNET_TESTBED_SlaveConfiguration));
    status =
        handle_slave_config (c,
                             (const struct GNUNET_TESTBED_SlaveConfiguration *)
                             msg);
    break;
  default:
    GNUNET_assert (0);
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
  if ((0 == size) && (NULL == buf))     /* Timeout */
  {
    LOG_DEBUG ("Message sending timed out -- retrying\n");
    c->th =
        GNUNET_CLIENT_notify_transmit_ready (c->client,
                                             ntohs (mq_entry->msg->size),
                                             TIMEOUT_REL, GNUNET_YES,
                                             &transmit_ready_notify, c);
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
                                             TIMEOUT_REL, GNUNET_YES,
                                             &transmit_ready_notify, c);
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
                                             TIMEOUT_REL, GNUNET_YES,
                                             &transmit_ready_notify,
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
                                       *controller, uint64_t operation_id,
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
  GNUNET_CONTAINER_DLL_insert_tail (controller->ocq_head, controller->ocq_tail,
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
  GNUNET_CONTAINER_DLL_remove (opc->c->ocq_head, opc->c->ocq_tail, opc);
  GNUNET_free (opc->data);
  GNUNET_free (opc);
}


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
static int
helper_mst (void *cls, void *client, const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_TESTBED_ControllerProc *cp = cls;
  const struct GNUNET_TESTBED_HelperReply *msg;
  const char *hostname;
  char *config;
  uLongf config_size;
  uLongf xconfig_size;

  msg = (const struct GNUNET_TESTBED_HelperReply *) message;
  GNUNET_assert (sizeof (struct GNUNET_TESTBED_HelperReply) <
                 ntohs (msg->header.size));
  GNUNET_assert (GNUNET_MESSAGE_TYPE_TESTBED_HELPER_REPLY ==
                 ntohs (msg->header.type));
  config_size = (uLongf) ntohs (msg->config_size);
  xconfig_size =
      (uLongf) (ntohs (msg->header.size) -
                sizeof (struct GNUNET_TESTBED_HelperReply));
  config = GNUNET_malloc (config_size);
  GNUNET_assert (Z_OK ==
                 uncompress ((Bytef *) config, &config_size,
                             (const Bytef *) &msg[1], xconfig_size));
  GNUNET_assert (NULL == cp->cfg);
  cp->cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_assert (GNUNET_CONFIGURATION_deserialize
                 (cp->cfg, config, config_size, GNUNET_NO));
  GNUNET_free (config);
  if ((NULL == cp->host) ||
      (NULL == (hostname = GNUNET_TESTBED_host_get_hostname (cp->host))))
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
  struct ControllerLinkData *data;
  struct GNUNET_TESTBED_ControllerLinkMessage *msg;

  GNUNET_assert (NULL != opc->data);
  data = opc->data;
  msg = data->msg;
  data->msg = NULL;
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
  struct ControllerLinkData *data;

  data = opc->data;
  switch (opc->state)
  {
  case OPC_STATE_INIT:
    GNUNET_free (data->msg);
    break;
  case OPC_STATE_STARTED:
    GNUNET_CONTAINER_DLL_remove (opc->c->ocq_head, opc->c->ocq_tail, opc);
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
  struct GetSlaveConfigData *data;
  struct GNUNET_TESTBED_SlaveGetConfigurationMessage *msg;

  data = opc->data;
  msg = GNUNET_TESTBED_generate_slavegetconfig_msg_ (opc->id, data->slave_id);
  GNUNET_CONTAINER_DLL_insert_tail (opc->c->ocq_head, opc->c->ocq_tail, opc);
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
    GNUNET_free (opc->data);
    GNUNET_CONTAINER_DLL_remove (opc->c->ocq_head, opc->c->ocq_tail, opc);
    break;
  case OPC_STATE_FINISHED:
    if (NULL != opc->data)
      GNUNET_CONFIGURATION_destroy (opc->data);
    break;
  }
  GNUNET_free (opc);
}


/**
 * Initializes the operation queue for parallel overlay connects
 *
 * @param c the controller handle
 * @param npoc the number of parallel overlay connects - the queue size
 */
static void
GNUNET_TESTBED_set_num_parallel_overlay_connects_ (struct
                                                   GNUNET_TESTBED_Controller *c,
                                                   unsigned int npoc)
{
  fprintf (stderr, "%d", npoc);
  GNUNET_free_non_null (c->tslots);
  c->tslots_filled = 0;
  c->num_parallel_connects = npoc;
  c->tslots = GNUNET_malloc (npoc * sizeof (struct TimeSlot));
  GNUNET_TESTBED_operation_queue_reset_max_active_
      (c->opq_parallel_overlay_connect_operations, npoc);
}


/**
 * Function to copy NULL terminated list of arguments
 *
 * @param argv the NULL terminated list of arguments. Cannot be NULL.
 * @return the copied NULL terminated arguments
 */
static char **
copy_argv (const char *const *argv)
{
  char **argv_dup;
  unsigned int argp;

  GNUNET_assert (NULL != argv);
  for (argp = 0; NULL != argv[argp]; argp++) ;
  argv_dup = GNUNET_malloc (sizeof (char *) * (argp + 1));
  for (argp = 0; NULL != argv[argp]; argp++)
    argv_dup[argp] = strdup (argv[argp]);
  return argv_dup;
}


/**
 * Function to join NULL terminated list of arguments
 *
 * @param argv1 the NULL terminated list of arguments. Cannot be NULL.
 * @param argv2 the NULL terminated list of arguments. Cannot be NULL.
 * @return the joined NULL terminated arguments
 */
static char **
join_argv (const char *const *argv1, const char *const *argv2)
{
  char **argvj;
  char *argv;
  unsigned int carg;
  unsigned int cnt;

  carg = 0;
  argvj = NULL;
  for (cnt = 0; NULL != argv1[cnt]; cnt++)
  {
    argv = GNUNET_strdup (argv1[cnt]);
    GNUNET_array_append (argvj, carg, argv);
  }
  for (cnt = 0; NULL != argv2[cnt]; cnt++)
  {
    argv = GNUNET_strdup (argv2[cnt]);
    GNUNET_array_append (argvj, carg, argv);
  }
  GNUNET_array_append (argvj, carg, NULL);
  return argvj;
}


/**
 * Frees the given NULL terminated arguments
 *
 * @param argv the NULL terminated list of arguments
 */
static void
free_argv (char **argv)
{
  unsigned int argp;

  for (argp = 0; NULL != argv[argp]; argp++)
    GNUNET_free (argv[argp]);
  GNUNET_free (argv);
}


/**
 * Generates arguments for opening a remote shell. Builds up the arguments
 * from the environment variable GNUNET_TESTBED_RSH_CMD. The variable
 * should not mention `-p' (port) option and destination address as these will
 * be set locally in the function from its parameteres. If the environmental
 * variable is not found then it defaults to `ssh -o BatchMode=yes -o
 * NoHostAuthenticationForLocalhost=yes'
 *
 * @param port the destination port number
 * @param dst the destination address
 * @return NULL terminated list of arguments
 */
static char **
gen_rsh_args (const char *port, const char *dst)
{
  static const char *default_ssh_args[] = {
    "ssh",
    "-o",
    "BatchMode=yes",
    "-o",
    "NoHostAuthenticationForLocalhost=yes",
    NULL
  };
  char **ssh_args;
  char *ssh_cmd;
  char *ssh_cmd_cp;
  char *arg;
  unsigned int cnt;

  ssh_args = NULL;
  if (NULL != (ssh_cmd = getenv ("GNUNET_TESTBED_RSH_CMD")))
  {
    ssh_cmd = GNUNET_strdup (ssh_cmd);
    ssh_cmd_cp = ssh_cmd;
    for (cnt = 0; NULL != (arg = strtok (ssh_cmd, " ")); ssh_cmd = NULL)
      GNUNET_array_append (ssh_args, cnt, GNUNET_strdup (arg));
    GNUNET_free (ssh_cmd_cp);
  }
  else
  {
    ssh_args = copy_argv (default_ssh_args);
    cnt = (sizeof (default_ssh_args)) / (sizeof (const char *));
    GNUNET_array_grow (ssh_args, cnt, cnt - 1);
  }
  GNUNET_array_append (ssh_args, cnt, GNUNET_strdup ("-p"));
  GNUNET_array_append (ssh_args, cnt, GNUNET_strdup (port));
  GNUNET_array_append (ssh_args, cnt, GNUNET_strdup (dst));
  GNUNET_array_append (ssh_args, cnt, NULL);
  return ssh_args;
}


/**
 * Generates the arguments needed for executing the given binary in a remote
 * shell. Builds the arguments from the environmental variable
 * GNUNET_TETSBED_RSH_CMD_SUFFIX. If the environmental variable is not found,
 * only the given binary name will be present in the returned arguments
 *
 * @param helper_binary_path the path of the binary to execute
 * @return NULL-terminated args
 */
static char **
gen_rsh_suffix_args (const char *helper_binary_path)
{
  char **rshell_args;
  char *rshell_cmd;
  char *rshell_cmd_cp;
  char *arg;
  unsigned int cnt;

  rshell_args = NULL;
  cnt = 0;
  if (NULL != (rshell_cmd = getenv ("GNUNET_TESTBED_RSH_CMD_SUFFIX")))
  {
    rshell_cmd = GNUNET_strdup (rshell_cmd);
    rshell_cmd_cp = rshell_cmd;
    for (; NULL != (arg = strtok (rshell_cmd, " ")); rshell_cmd = NULL)
      GNUNET_array_append (rshell_args, cnt, GNUNET_strdup (arg));
    GNUNET_free (rshell_cmd_cp);
  }
  GNUNET_array_append (rshell_args, cnt, GNUNET_strdup (helper_binary_path));
  GNUNET_array_append (rshell_args, cnt, NULL);
  return rshell_args;
}


/**
 * Starts a controller process at the given host
 *
 * @param trusted_ip the ip address of the controller which will be set as TRUSTED
 *          HOST(all connections form this ip are permitted by the testbed) when
 *          starting testbed controller at host. This can either be a single ip
 *          address or a network address in CIDR notation.
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
GNUNET_TESTBED_controller_start (const char *trusted_ip,
                                 struct GNUNET_TESTBED_Host *host,
                                 const struct GNUNET_CONFIGURATION_Handle *cfg,
                                 GNUNET_TESTBED_ControllerStatusCallback cb,
                                 void *cls)
{
  struct GNUNET_TESTBED_ControllerProc *cp;
  struct GNUNET_TESTBED_HelperInit *msg;
  const char *hostname;

  static char *const binary_argv[] = {
    HELPER_TESTBED_BINARY, NULL
  };

  hostname = NULL;
  cp = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_ControllerProc));
  if ((NULL == host) || (0 == GNUNET_TESTBED_host_get_id_ (host)))
  {
    cp->helper =
        GNUNET_HELPER_start (GNUNET_YES, HELPER_TESTBED_BINARY, binary_argv,
                             &helper_mst, &helper_exp_cb, cp);
  }
  else
  {
    char *helper_binary_path;
    char **ssh_args;
    char **rshell_args;
    const char *username;
    char *port;
    char *dst;

    username = GNUNET_TESTBED_host_get_username_ (host);
    hostname = GNUNET_TESTBED_host_get_hostname (host);
    GNUNET_asprintf (&port, "%u", GNUNET_TESTBED_host_get_ssh_port_ (host));
    if (NULL == username)
      GNUNET_asprintf (&dst, "%s", hostname);
    else
      GNUNET_asprintf (&dst, "%s@%s", username, hostname);
    LOG_DEBUG ("Starting SSH to destination %s\n", dst);

    if (GNUNET_OK !=
        GNUNET_CONFIGURATION_get_value_string (cfg, "testbed",
                                               "HELPER_BINARY_PATH",
                                               &helper_binary_path))
      helper_binary_path =
          GNUNET_OS_get_libexec_binary_path (HELPER_TESTBED_BINARY);
    ssh_args = gen_rsh_args (port, dst);
    rshell_args = gen_rsh_suffix_args (helper_binary_path);
    cp->helper_argv =
        join_argv ((const char **) ssh_args, (const char **) rshell_args);
    free_argv (ssh_args);
    free_argv (rshell_args);
    GNUNET_free (port);
    GNUNET_free (dst);
    cp->helper =
        GNUNET_HELPER_start (GNUNET_NO, "ssh", cp->helper_argv, &helper_mst,
                             &helper_exp_cb, cp);
    GNUNET_free (helper_binary_path);
  }
  if (NULL == cp->helper)
  {
    if (NULL != cp->helper_argv)
      free_argv (cp->helper_argv);
    GNUNET_free (cp);
    return NULL;
  }
  cp->host = host;
  cp->cb = cb;
  cp->cls = cls;
  msg = GNUNET_TESTBED_create_helper_init_msg_ (trusted_ip, hostname, cfg);
  cp->msg = &msg->header;
  cp->shandle =
      GNUNET_HELPER_send (cp->helper, &msg->header, GNUNET_NO, &clear_msg, cp);
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
 * been fully terminated (!). The controller status cb from
 * GNUNET_TESTBED_controller_start() will not be called.
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
  if (NULL != cproc->helper_argv)
    free_argv (cproc->helper_argv);
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
GNUNET_TESTBED_controller_connect (const struct GNUNET_CONFIGURATION_Handle
                                   *cfg, struct GNUNET_TESTBED_Host *host,
                                   uint64_t event_mask,
                                   GNUNET_TESTBED_ControllerCallback cc,
                                   void *cc_cls)
{
  struct GNUNET_TESTBED_Controller *controller;
  struct GNUNET_TESTBED_InitMessage *msg;
  const char *controller_hostname;
  unsigned long long max_parallel_operations;
  unsigned long long max_parallel_service_connections;
  unsigned long long max_parallel_topology_config_operations;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "testbed",
                                             "MAX_PARALLEL_OPERATIONS",
                                             &max_parallel_operations))
  {
    GNUNET_break (0);
    return NULL;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "testbed",
                                             "MAX_PARALLEL_SERVICE_CONNECTIONS",
                                             &max_parallel_service_connections))
  {
    GNUNET_break (0);
    return NULL;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "testbed",
                                             "MAX_PARALLEL_TOPOLOGY_CONFIG_OPERATIONS",
                                             &max_parallel_topology_config_operations))
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
  controller->opq_parallel_operations =
      GNUNET_TESTBED_operation_queue_create_ ((unsigned int)
                                              max_parallel_operations);
  controller->opq_parallel_service_connections =
      GNUNET_TESTBED_operation_queue_create_ ((unsigned int)
                                              max_parallel_service_connections);
  controller->opq_parallel_topology_config_operations =
      GNUNET_TESTBED_operation_queue_create_ ((unsigned int)
                                              max_parallel_topology_config_operations);
  controller->opq_parallel_overlay_connect_operations =
      GNUNET_TESTBED_operation_queue_create_ (0);
  GNUNET_TESTBED_set_num_parallel_overlay_connects_ (controller, 1);
  controller->poc_sd = SD_init (10);
  controller_hostname = GNUNET_TESTBED_host_get_hostname (host);
  if (NULL == controller_hostname)
    controller_hostname = "127.0.0.1";
  msg =
      GNUNET_malloc (sizeof (struct GNUNET_TESTBED_InitMessage) +
                     strlen (controller_hostname) + 1);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_INIT);
  msg->header.size =
      htons (sizeof (struct GNUNET_TESTBED_InitMessage) +
             strlen (controller_hostname) + 1);
  msg->host_id = htonl (GNUNET_TESTBED_host_get_id_ (host));
  msg->event_mask = GNUNET_htonll (controller->event_mask);
  strcpy ((char *) &msg[1], controller_hostname);
  GNUNET_TESTBED_queue_message_ (controller,
                                 (struct GNUNET_MessageHeader *) msg);
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
GNUNET_TESTBED_controller_configure_sharing (struct GNUNET_TESTBED_Controller
                                             *controller,
                                             const char *service_name,
                                             uint32_t num_peers)
{
  struct GNUNET_TESTBED_ConfigureSharedServiceMessage *msg;
  uint16_t service_name_size;
  uint16_t msg_size;

  service_name_size = strlen (service_name) + 1;
  msg_size =
      sizeof (struct GNUNET_TESTBED_ConfigureSharedServiceMessage) +
      service_name_size;
  msg = GNUNET_malloc (msg_size);
  msg->header.size = htons (msg_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_SHARE_SERVICE);
  msg->host_id = htonl (GNUNET_TESTBED_host_get_id_ (controller->host));
  msg->num_peers = htonl (num_peers);
  memcpy (&msg[1], service_name, service_name_size);
  GNUNET_TESTBED_queue_message_ (controller,
                                 (struct GNUNET_MessageHeader *) msg);
  GNUNET_break (0);             /* This function is not yet implemented on the
                                 * testbed service */
}


/**
 * disconnects from the controller.
 *
 * @param controller handle to controller to stop
 */
void
GNUNET_TESTBED_controller_disconnect (struct GNUNET_TESTBED_Controller
                                      *controller)
{
  struct MessageQueue *mq_entry;

  if (NULL != controller->th)
    GNUNET_CLIENT_notify_transmit_ready_cancel (controller->th);
  /* Clear the message queue */
  while (NULL != (mq_entry = controller->mq_head))
  {
    GNUNET_CONTAINER_DLL_remove (controller->mq_head, controller->mq_tail,
                                 mq_entry);
    GNUNET_free (mq_entry->msg);
    GNUNET_free (mq_entry);
  }
  if (NULL != controller->client)
    GNUNET_CLIENT_disconnect (controller->client);
  GNUNET_CONFIGURATION_destroy (controller->cfg);
  if (GNUNET_YES == controller->aux_host)
    GNUNET_TESTBED_host_destroy (controller->host);
  GNUNET_TESTBED_operation_queue_destroy_ (controller->opq_parallel_operations);
  GNUNET_TESTBED_operation_queue_destroy_
      (controller->opq_parallel_service_connections);
  GNUNET_TESTBED_operation_queue_destroy_
      (controller->opq_parallel_topology_config_operations);
  GNUNET_TESTBED_operation_queue_destroy_
      (controller->opq_parallel_overlay_connect_operations);
  SD_destroy (controller->poc_sd);
  GNUNET_free_non_null (controller->tslots);
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
  hostname = GNUNET_TESTBED_host_get_hostname (host);
  if (GNUNET_YES == GNUNET_TESTBED_is_host_registered_ (host, controller))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "Host hostname: %s already registered\n",
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
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_ADD_HOST);
  msg->host_id = htonl (GNUNET_TESTBED_host_get_id_ (host));
  msg->ssh_port = htons (GNUNET_TESTBED_host_get_ssh_port_ (host));
  if (NULL != username)
  {
    msg->user_name_length = htons (user_name_length - 1);
    memcpy (&msg[1], username, user_name_length);
  }
  else
    msg->user_name_length = htons (user_name_length);
  strcpy (((void *) &msg[1]) + user_name_length, hostname);
  GNUNET_TESTBED_queue_message_ (controller,
                                 (struct GNUNET_MessageHeader *) msg);
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
                                   int is_subordinate)
{
  struct OperationContext *opc;
  struct GNUNET_TESTBED_ControllerLinkMessage *msg;
  struct ControllerLinkData *data;
  uint16_t msg_size;

  msg_size = sxcfg_size + sizeof (struct GNUNET_TESTBED_ControllerLinkMessage);
  msg = GNUNET_malloc (msg_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_LINK_CONTROLLERS);
  msg->header.size = htons (msg_size);
  msg->delegated_host_id = htonl (delegated_host_id);
  msg->slave_host_id = htonl (slave_host_id);
  msg->config_size = htons ((uint16_t) scfg_size);
  msg->is_subordinate = (GNUNET_YES == is_subordinate) ? 1 : 0;
  memcpy (&msg[1], sxcfg, sxcfg_size);
  data = GNUNET_malloc (sizeof (struct ControllerLinkData));
  data->msg = msg;
  opc = GNUNET_malloc (sizeof (struct OperationContext));
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
 * Same as the GNUNET_TESTBED_controller_link, however expects configuration in
 * serialized and compressed
 *
 * @param op_cls the operation closure for the event which is generated to
 *          signal success or failure of this operation
 * @param master handle to the master controller who creates the association
 * @param delegated_host requests to which host should be delegated; cannot be NULL
 * @param slave_host which host is used to run the slave controller; use NULL to
 *          make the master controller connect to the delegated host
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
GNUNET_TESTBED_controller_link_2 (void *op_cls,
                                  struct GNUNET_TESTBED_Controller *master,
                                  struct GNUNET_TESTBED_Host *delegated_host,
                                  struct GNUNET_TESTBED_Host *slave_host,
                                  const char *sxcfg, size_t sxcfg_size,
                                  size_t scfg_size, int is_subordinate)
{
  uint32_t delegated_host_id;
  uint32_t slave_host_id;

  GNUNET_assert (GNUNET_YES ==
                 GNUNET_TESTBED_is_host_registered_ (delegated_host, master));
  delegated_host_id = GNUNET_TESTBED_host_get_id_ (delegated_host);
  slave_host_id =
      GNUNET_TESTBED_host_get_id_ ((NULL !=
                                    slave_host) ? slave_host : master->host);
  if ((NULL != slave_host) && (0 != GNUNET_TESTBED_host_get_id_ (slave_host)))
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_TESTBED_is_host_registered_ (slave_host, master));

  return GNUNET_TESTBED_controller_link_2_ (op_cls, master, delegated_host_id,
                                            slave_host_id, sxcfg, sxcfg_size,
                                            scfg_size, is_subordinate);
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
                 compress2 ((Bytef *) * xconfig, (uLongf *) & xsize,
                            (const Bytef *) config, (uLongf) size,
                            Z_BEST_SPEED));
  return xsize;
}


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
                                 *slave_cfg, int is_subordinate)
{
  struct GNUNET_TESTBED_Operation *op;
  char *config;
  char *cconfig;
  size_t cc_size;
  size_t config_size;

  config = GNUNET_CONFIGURATION_serialize (slave_cfg, &config_size);
  cc_size = GNUNET_TESTBED_compress_config_ (config, config_size, &cconfig);
  GNUNET_free (config);
  /* Configuration doesn't fit in 1 message */
  GNUNET_assert ((UINT16_MAX -
                  sizeof (struct GNUNET_TESTBED_ControllerLinkMessage)) >=
                 cc_size);
  op = GNUNET_TESTBED_controller_link_2_ (op_cls, master, delegated_host_id,
                                          slave_host_id, (const char *) cconfig,
                                          cc_size, config_size, is_subordinate);
  GNUNET_free (cconfig);
  return op;
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
 * @param slave_cfg configuration to use for the slave controller
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
                                const struct GNUNET_CONFIGURATION_Handle
                                *slave_cfg, int is_subordinate)
{
  uint32_t slave_host_id;
  uint32_t delegated_host_id;

  GNUNET_assert (GNUNET_YES ==
                 GNUNET_TESTBED_is_host_registered_ (delegated_host, master));
  slave_host_id =
      GNUNET_TESTBED_host_get_id_ ((NULL !=
                                    slave_host) ? slave_host : master->host);
  delegated_host_id = GNUNET_TESTBED_host_get_id_ (delegated_host);
  if ((NULL != slave_host) && (0 != slave_host_id))
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_TESTBED_is_host_registered_ (slave_host, master));
  return GNUNET_TESTBED_controller_link_ (op_cls, master, delegated_host_id,
                                          slave_host_id, slave_cfg,
                                          is_subordinate);

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

  data = GNUNET_malloc (sizeof (struct GetSlaveConfigData));
  data->slave_id = slave_host_id;
  opc = GNUNET_malloc (sizeof (struct OperationContext));
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
  last_finished_operation = operation;
  GNUNET_TESTBED_operation_release_ (operation);
}


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
  case GNUNET_MESSAGE_TYPE_TESTBED_PEER_CONFIGURATION:
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
  default:
    GNUNET_assert (0);
  }
  data = GNUNET_malloc (data_len);
  if (Z_OK != (ret = uncompress (data, &data_len, xdata, xdata_len)))
    GNUNET_assert (0);
  cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_deserialize (cfg, (const char *) data,
                                                   (size_t) data_len,
                                                   GNUNET_NO));
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
 * Returns a timing slot which will be exclusively locked
 *
 * @param c the controller handle
 * @param key a pointer which is associated to the returned slot; should not be
 *          NULL. It serves as a key to determine the correct owner of the slot
 * @return the time slot index in the array of time slots in the controller
 *           handle
 */
unsigned int
GNUNET_TESTBED_get_tslot_ (struct GNUNET_TESTBED_Controller *c, void *key)
{
  unsigned int slot;

  GNUNET_assert (NULL != c->tslots);
  GNUNET_assert (NULL != key);
  for (slot = 0; slot < c->num_parallel_connects; slot++)
    if (NULL == c->tslots[slot].key)
    {
      c->tslots[slot].key = key;
      return slot;
    }
  GNUNET_assert (0);            /* We should always find a free tslot */
}


/**
 * Decides whether any change in the number of parallel overlay connects is
 * necessary to adapt to the load on the system
 *
 * @param c the controller handle
 */
static void
decide_npoc (struct GNUNET_TESTBED_Controller *c)
{
  struct GNUNET_TIME_Relative avg;
  int sd;
  unsigned int slot;
  unsigned int nvals;

  if (c->tslots_filled != c->num_parallel_connects)
    return;
  avg = GNUNET_TIME_UNIT_ZERO;
  nvals = 0;
  for (slot = 0; slot < c->num_parallel_connects; slot++)
  {
    avg = GNUNET_TIME_relative_add (avg, c->tslots[slot].time);
    nvals += c->tslots[slot].nvals;
  }
  GNUNET_assert (nvals >= c->num_parallel_connects);
  avg = GNUNET_TIME_relative_divide (avg, nvals);
  GNUNET_assert (GNUNET_TIME_UNIT_FOREVER_REL.rel_value != avg.rel_value);
  sd = SD_deviation_factor (c->poc_sd, (unsigned int) avg.rel_value);
  if ( (sd <= 5) ||
       (0 == GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
				       c->num_parallel_connects)) )
    SD_add_data (c->poc_sd, (unsigned int) avg.rel_value);
  if (GNUNET_SYSERR == sd)
  {
    GNUNET_TESTBED_set_num_parallel_overlay_connects_ (c,
                                                       c->num_parallel_connects);
    return;
  }
  GNUNET_assert (0 <= sd);
  if (0 == sd)
  {
    GNUNET_TESTBED_set_num_parallel_overlay_connects_ (c,
                                                       c->num_parallel_connects
                                                       * 2);
    return;
  }
  if (1 == sd)
  {
    GNUNET_TESTBED_set_num_parallel_overlay_connects_ (c,
                                                       c->num_parallel_connects
                                                       + 1);
    return;
  }
  if (1 == c->num_parallel_connects)
  {
    GNUNET_TESTBED_set_num_parallel_overlay_connects_ (c, 1);
    return;
  }
  if (2 == sd)
  {
    GNUNET_TESTBED_set_num_parallel_overlay_connects_ (c,
                                                       c->num_parallel_connects
                                                       - 1);
    return;
  }
  GNUNET_TESTBED_set_num_parallel_overlay_connects_ (c,
                                                     c->num_parallel_connects /
                                                     2);
}


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
                                   unsigned int index, void *key)
{
  struct TimeSlot *slot;

  GNUNET_assert (NULL != key);
  if (index >= c->num_parallel_connects)
    return GNUNET_NO;
  slot = &c->tslots[index];
  if (key != slot->key)
    return GNUNET_NO;
  slot->key = NULL;
  return GNUNET_YES;
}


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
                                  struct GNUNET_TIME_Relative time, int failed)
{
  struct TimeSlot *slot;

  if (GNUNET_YES == failed)
  {
    if (1 == c->num_parallel_connects)
    {
      GNUNET_TESTBED_set_num_parallel_overlay_connects_ (c, 1);
      return;
    }
    GNUNET_TESTBED_set_num_parallel_overlay_connects_ (c,
                                                       c->num_parallel_connects
                                                       - 1);
  }
  if (GNUNET_NO == GNUNET_TESTBED_release_time_slot_ (c, index, key))
    return;
  slot = &c->tslots[index];
  slot->nvals++;
  if (GNUNET_TIME_UNIT_ZERO.rel_value == slot->time.rel_value)
  {
    slot->time = time;
    c->tslots_filled++;
    decide_npoc (c);
    return;
  }
  slot->time = GNUNET_TIME_relative_add (slot->time, time);
}


/* end of testbed_api.c */
