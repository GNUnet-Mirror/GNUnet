/*
 * This file is part of GNUnet
 * Copyright (C) 2013 Christian Grothoff (and other contributing authors)
 *
 * GNUnet is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 3, or (at your
 * option) any later version.
 *
 * GNUnet is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNUnet; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

/**
 * @file psyc/psyc_api.c
 * @brief PSYC service; high-level access to the PSYC protocol
 *        note that clients of this API are NOT expected to
 *        understand the PSYC message format, only the semantics!
 *        Parsing (and serializing) the PSYC stream format is done
 *        within the implementation of the libgnunetpsyc library,
 *        and this API deliberately exposes as little as possible
 *        of the actual data stream format to the application!
 * @author Gabor X Toth
 */

#include <inttypes.h>

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_env_lib.h"
#include "gnunet_multicast_service.h"
#include "gnunet_psyc_service.h"
#include "gnunet_psyc_util_lib.h"
#include "psyc.h"

#define LOG(kind,...) GNUNET_log_from (kind, "psyc-api",__VA_ARGS__)


/**
 * Handle to access PSYC channel operations for both the master and slaves.
 */
struct GNUNET_PSYC_Channel
{
  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Client connection to the service.
   */
  struct GNUNET_CLIENT_MANAGER_Connection *client;

  /**
   * Transmission handle;
   */
  struct GNUNET_PSYC_TransmitHandle *tmit;

  /**
   * Receipt handle;
   */
  struct GNUNET_PSYC_ReceiveHandle *recv;

  /**
   * Message to send on reconnect.
   */
  struct GNUNET_MessageHeader *connect_msg;

  /**
   * Function called after disconnected from the service.
   */
  GNUNET_ContinuationCallback disconnect_cb;

  /**
   * Closure for @a disconnect_cb.
   */
  void *disconnect_cls;

  /**
   * Are we polling for incoming messages right now?
   */
  uint8_t in_receive;

  /**
   * Is this a master or slave channel?
   */
  uint8_t is_master;

  /**
   * Is this channel in the process of disconnecting from the service?
   * #GNUNET_YES or #GNUNET_NO
   */
  uint8_t is_disconnecting;
};


/**
 * Handle for the master of a PSYC channel.
 */
struct GNUNET_PSYC_Master
{
  struct GNUNET_PSYC_Channel chn;

  GNUNET_PSYC_MasterStartCallback start_cb;

  /**
   * Join request callback.
   */
  GNUNET_PSYC_JoinRequestCallback join_req_cb;

  /**
   * Closure for the callbacks.
   */
  void *cb_cls;
};


/**
 * Handle for a PSYC channel slave.
 */
struct GNUNET_PSYC_Slave
{
  struct GNUNET_PSYC_Channel chn;

  GNUNET_PSYC_SlaveConnectCallback connect_cb;

  GNUNET_PSYC_JoinDecisionCallback join_dcsn_cb;

  /**
   * Closure for the callbacks.
   */
  void *cb_cls;
};


/**
 * Handle that identifies a join request.
 *
 * Used to match calls to #GNUNET_PSYC_JoinRequestCallback to the
 * corresponding calls to GNUNET_PSYC_join_decision().
 */
struct GNUNET_PSYC_JoinHandle
{
  struct GNUNET_PSYC_Master *mst;
  struct GNUNET_CRYPTO_EcdsaPublicKey slave_key;
};


/**
 * Handle for a pending PSYC transmission operation.
 */
struct GNUNET_PSYC_SlaveTransmitHandle
{

};


struct GNUNET_PSYC_HistoryRequest
{
  /**
   * Channel.
   */
  struct GNUNET_PSYC_Channel *chn;

  /**
   * Operation ID.
   */
  uint64_t op_id;

  /**
   * Message handler.
   */
  struct GNUNET_PSYC_ReceiveHandle *recv;

  /**
   * Function to call when the operation finished.
   */
  GNUNET_ResultCallback result_cb;

  /**
   * Closure for @a result_cb.
   */
  void *cls;
};


struct GNUNET_PSYC_StateRequest
{
  /**
   * Channel.
   */
  struct GNUNET_PSYC_Channel *chn;

  /**
   * Operation ID.
   */
  uint64_t op_id;

  /**
   * State variable result callback.
   */
  GNUNET_PSYC_StateVarCallback var_cb;

  /**
   * Function to call when the operation finished.
   */
  GNUNET_ResultCallback result_cb;

  /**
   * Closure for @a result_cb.
   */
  void *cls;
};


static void
channel_send_connect_msg (struct GNUNET_PSYC_Channel *chn)
{
  uint16_t cmsg_size = ntohs (chn->connect_msg->size);
  struct GNUNET_MessageHeader * cmsg = GNUNET_malloc (cmsg_size);
  memcpy (cmsg, chn->connect_msg, cmsg_size);
  GNUNET_CLIENT_MANAGER_transmit_now (chn->client, cmsg);
}


static void
channel_recv_disconnect (void *cls,
                         struct GNUNET_CLIENT_MANAGER_Connection *client,
                         const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_PSYC_Channel *
    chn = GNUNET_CLIENT_MANAGER_get_user_context_ (client, sizeof (*chn));
  GNUNET_CLIENT_MANAGER_reconnect (client);
  channel_send_connect_msg (chn);
}


static void
channel_recv_result (void *cls,
                     struct GNUNET_CLIENT_MANAGER_Connection *client,
                     const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_PSYC_Channel *
    chn = GNUNET_CLIENT_MANAGER_get_user_context_ (client, sizeof (*chn));

  const struct GNUNET_OperationResultMessage *
    res = (const struct GNUNET_OperationResultMessage *) msg;

  uint16_t size = ntohs (msg->size);
  if (size < sizeof (*res))
  { /* Error, message too small. */
    GNUNET_break (0);
    return;
  }

  uint16_t data_size = size - sizeof (*res);
  const char *data = (0 < data_size) ? (void *) &res[1] : NULL;
  GNUNET_CLIENT_MANAGER_op_result (chn->client, GNUNET_ntohll (res->op_id),
                                   GNUNET_ntohll (res->result_code),
                                   data, data_size);
}


static void
op_recv_history_result (void *cls, int64_t result,
                        const void *data, uint16_t data_size)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received history replay result: %" PRId64 ".\n", result);

  struct GNUNET_PSYC_HistoryRequest *hist = cls;

  if (NULL != hist->result_cb)
    hist->result_cb (hist->cls, result, data, data_size);

  GNUNET_PSYC_receive_destroy (hist->recv);
  GNUNET_free (hist);
}


static void
op_recv_state_result (void *cls, int64_t result,
                      const void *data, uint16_t data_size)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received state request result: %" PRId64 ".\n", result);

  struct GNUNET_PSYC_StateRequest *sr = cls;

  if (NULL != sr->result_cb)
    sr->result_cb (sr->cls, result, data, data_size);

  GNUNET_free (sr);
}


static void
channel_recv_history_result (void *cls,
                             struct GNUNET_CLIENT_MANAGER_Connection *client,
                             const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_PSYC_Channel *
    chn = GNUNET_CLIENT_MANAGER_get_user_context_ (client, sizeof (*chn));

  const struct GNUNET_OperationResultMessage *
    res = (const struct GNUNET_OperationResultMessage *) msg;
  struct GNUNET_PSYC_MessageHeader *
    pmsg = (struct GNUNET_PSYC_MessageHeader *) &res[1];

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%p Received historic fragment for message #%" PRIu64 ".\n",
       chn, GNUNET_ntohll (pmsg->message_id));

  GNUNET_ResultCallback result_cb = NULL;
  struct GNUNET_PSYC_HistoryRequest *hist = NULL;

  if (GNUNET_YES != GNUNET_CLIENT_MANAGER_op_find (chn->client,
                                                   GNUNET_ntohll (res->op_id),
                                                   &result_cb, (void *) &hist))
  { /* Operation not found. */
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "%p Replay operation not found for historic fragment of message #%"
         PRIu64 ".\n",
         chn, GNUNET_ntohll (pmsg->message_id));
    return;
  }

  uint16_t size = ntohs (msg->size);
  if (size < sizeof (*res) + sizeof (*pmsg))
  { /* Error, message too small. */
    GNUNET_break (0);
    return;
  }

  GNUNET_PSYC_receive_message (hist->recv,
                               (const struct GNUNET_PSYC_MessageHeader *) pmsg);
}


static void
channel_recv_state_result (void *cls,
                           struct GNUNET_CLIENT_MANAGER_Connection *client,
                           const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_PSYC_Channel *
    chn = GNUNET_CLIENT_MANAGER_get_user_context_ (client, sizeof (*chn));

  const struct GNUNET_OperationResultMessage *
    res = (const struct GNUNET_OperationResultMessage *) msg;

  GNUNET_ResultCallback result_cb = NULL;
  struct GNUNET_PSYC_StateRequest *sr = NULL;

  if (GNUNET_YES != GNUNET_CLIENT_MANAGER_op_find (chn->client,
                                                   GNUNET_ntohll (res->op_id),
                                                   &result_cb, (void *) &sr))
  { /* Operation not found. */
    return;
  }

  const struct GNUNET_MessageHeader *
    mod = (struct GNUNET_MessageHeader *) &res[1];
  uint16_t mod_size = ntohs (mod->size);
  if (ntohs (msg->size) - sizeof (*res) != mod_size)
  {
    GNUNET_break (0);
    return;
  }
  switch (ntohs (mod->type))
  {
  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MODIFIER:
  {
    const struct GNUNET_PSYC_MessageModifier *
      pmod = (const struct GNUNET_PSYC_MessageModifier *) mod;

    const char *name = (const char *) &pmod[1];
    uint16_t name_size = ntohs (pmod->name_size);
    if ('\0' != name[name_size - 1])
    {
      GNUNET_break (0);
      return;
    }
    sr->var_cb (sr->cls, mod, name, name + name_size,
                ntohs (pmod->header.size) - sizeof (*pmod),
                ntohs (pmod->value_size));
    break;
  }

  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MOD_CONT:
    sr->var_cb (sr->cls, mod, NULL, (const char *) &mod[1],
                mod_size - sizeof (*mod), 0);
    break;
  }
}


static void
channel_recv_message (void *cls,
                      struct GNUNET_CLIENT_MANAGER_Connection *client,
                      const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_PSYC_Channel *
    chn = GNUNET_CLIENT_MANAGER_get_user_context_ (client, sizeof (*chn));
  GNUNET_PSYC_receive_message (chn->recv,
                               (const struct GNUNET_PSYC_MessageHeader *) msg);
}


static void
channel_recv_message_ack (void *cls,
                          struct GNUNET_CLIENT_MANAGER_Connection *client,
                          const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_PSYC_Channel *
    chn = GNUNET_CLIENT_MANAGER_get_user_context_ (client, sizeof (*chn));
  GNUNET_PSYC_transmit_got_ack (chn->tmit);
}


static void
master_recv_start_ack (void *cls,
                       struct GNUNET_CLIENT_MANAGER_Connection *client,
                       const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_PSYC_Master *
    mst = GNUNET_CLIENT_MANAGER_get_user_context_ (client,
                                                   sizeof (struct GNUNET_PSYC_Channel));

  struct GNUNET_PSYC_CountersResultMessage *
    cres = (struct GNUNET_PSYC_CountersResultMessage *) msg;
  int32_t result = ntohl (cres->result_code);
  if (GNUNET_OK != result && GNUNET_NO != result)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, "Could not start master: %ld\n", result);
    GNUNET_break (0);
    /* FIXME: disconnect */
  }
  if (NULL != mst->start_cb)
    mst->start_cb (mst->cb_cls, result, GNUNET_ntohll (cres->max_message_id));
}


static void
master_recv_join_request (void *cls,
                          struct GNUNET_CLIENT_MANAGER_Connection *client,
                          const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_PSYC_Master *
    mst = GNUNET_CLIENT_MANAGER_get_user_context_ (client,
                                                   sizeof (struct GNUNET_PSYC_Channel));
  if (NULL == mst->join_req_cb)
    return;

  const struct GNUNET_PSYC_JoinRequestMessage *
    req = (const struct GNUNET_PSYC_JoinRequestMessage *) msg;
  const struct GNUNET_PSYC_Message *join_msg = NULL;
  if (sizeof (*req) + sizeof (*join_msg) <= ntohs (req->header.size))
  {
    join_msg = (struct GNUNET_PSYC_Message *) &req[1];
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Received join_msg of type %u and size %u.\n",
         ntohs (join_msg->header.type), ntohs (join_msg->header.size));
  }

  struct GNUNET_PSYC_JoinHandle *jh = GNUNET_malloc (sizeof (*jh));
  jh->mst = mst;
  jh->slave_key = req->slave_key;

  if (NULL != mst->join_req_cb)
    mst->join_req_cb (mst->cb_cls, req, &req->slave_key, join_msg, jh);
}


static void
slave_recv_join_ack (void *cls,
                     struct GNUNET_CLIENT_MANAGER_Connection *client,
                     const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_PSYC_Slave *
    slv = GNUNET_CLIENT_MANAGER_get_user_context_ (client,
                                                   sizeof (struct GNUNET_PSYC_Channel));
  struct GNUNET_PSYC_CountersResultMessage *
    cres = (struct GNUNET_PSYC_CountersResultMessage *) msg;
  int32_t result = ntohl (cres->result_code);
  if (GNUNET_YES != result && GNUNET_NO != result)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, "Could not join slave.\n");
    GNUNET_break (0);
    /* FIXME: disconnect */
  }
  if (NULL != slv->connect_cb)
    slv->connect_cb (slv->cb_cls, result, GNUNET_ntohll (cres->max_message_id));
}


static void
slave_recv_join_decision (void *cls,
                          struct GNUNET_CLIENT_MANAGER_Connection *client,
                          const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_PSYC_Slave *
    slv = GNUNET_CLIENT_MANAGER_get_user_context_ (client,
                                                   sizeof (struct GNUNET_PSYC_Channel));
  const struct GNUNET_PSYC_JoinDecisionMessage *
    dcsn = (const struct GNUNET_PSYC_JoinDecisionMessage *) msg;

  struct GNUNET_PSYC_Message *pmsg = NULL;
  if (ntohs (dcsn->header.size) <= sizeof (*dcsn) + sizeof (*pmsg))
    pmsg = (struct GNUNET_PSYC_Message *) &dcsn[1];

  if (NULL != slv->join_dcsn_cb)
    slv->join_dcsn_cb (slv->cb_cls, dcsn, ntohl (dcsn->is_admitted), pmsg);
}


static struct GNUNET_CLIENT_MANAGER_MessageHandler master_handlers[] =
{
  { &channel_recv_message, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_MESSAGE,
    sizeof (struct GNUNET_PSYC_MessageHeader), GNUNET_YES },

  { &channel_recv_message_ack, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_ACK,
    sizeof (struct GNUNET_MessageHeader), GNUNET_NO },

  { &master_recv_start_ack, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_MASTER_START_ACK,
    sizeof (struct GNUNET_PSYC_CountersResultMessage), GNUNET_NO },

  { &master_recv_join_request, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_JOIN_REQUEST,
    sizeof (struct GNUNET_PSYC_JoinRequestMessage), GNUNET_YES },

  { &channel_recv_history_result, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_HISTORY_RESULT,
    sizeof (struct GNUNET_OperationResultMessage), GNUNET_YES },

  { &channel_recv_state_result, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_STATE_RESULT,
    sizeof (struct GNUNET_OperationResultMessage), GNUNET_YES },

  { &channel_recv_result, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_RESULT_CODE,
    sizeof (struct GNUNET_OperationResultMessage), GNUNET_YES },

  { &channel_recv_disconnect, NULL, 0, 0, GNUNET_NO },

  { NULL, NULL, 0, 0, GNUNET_NO }
};


static struct GNUNET_CLIENT_MANAGER_MessageHandler slave_handlers[] =
{
  { &channel_recv_message, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_MESSAGE,
    sizeof (struct GNUNET_PSYC_MessageHeader), GNUNET_YES },

  { &channel_recv_message_ack, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_ACK,
    sizeof (struct GNUNET_MessageHeader), GNUNET_NO },

  { &slave_recv_join_ack, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_SLAVE_JOIN_ACK,
    sizeof (struct GNUNET_PSYC_CountersResultMessage), GNUNET_NO },

  { &slave_recv_join_decision, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_JOIN_DECISION,
    sizeof (struct GNUNET_PSYC_JoinDecisionMessage), GNUNET_YES },

  { &channel_recv_history_result, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_HISTORY_RESULT,
    sizeof (struct GNUNET_OperationResultMessage), GNUNET_YES },

  { &channel_recv_state_result, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_STATE_RESULT,
    sizeof (struct GNUNET_OperationResultMessage), GNUNET_YES },

  { &channel_recv_result, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_RESULT_CODE,
    sizeof (struct GNUNET_OperationResultMessage), GNUNET_YES },

  { &channel_recv_disconnect, NULL, 0, 0, GNUNET_NO },

  { NULL, NULL, 0, 0, GNUNET_NO }
};


static void
channel_cleanup (struct GNUNET_PSYC_Channel *chn)
{
  GNUNET_PSYC_transmit_destroy (chn->tmit);
  GNUNET_PSYC_receive_destroy (chn->recv);
  GNUNET_free (chn->connect_msg);
  if (NULL != chn->disconnect_cb)
    chn->disconnect_cb (chn->disconnect_cls);
}


static void
master_cleanup (void *cls)
{
  struct GNUNET_PSYC_Master *mst = cls;
  channel_cleanup (&mst->chn);
  GNUNET_free (mst);
}


static void
slave_cleanup (void *cls)
{
  struct GNUNET_PSYC_Slave *slv = cls;
  channel_cleanup (&slv->chn);
  GNUNET_free (slv);
}


/**
 * Start a PSYC master channel.
 *
 * Will start a multicast group identified by the given ECC key.  Messages
 * received from group members will be given to the respective handler methods.
 * If a new member wants to join a group, the "join" method handler will be
 * invoked; the join handler must then generate a "join" message to approve the
 * joining of the new member.  The channel can also change group membership
 * without explicit requests.  Note that PSYC doesn't itself "understand" join
 * or part messages, the respective methods must call other PSYC functions to
 * inform PSYC about the meaning of the respective events.
 *
 * @param cfg  Configuration to use (to connect to PSYC service).
 * @param channel_key  ECC key that will be used to sign messages for this
 *        PSYC session. The public key is used to identify the PSYC channel.
 *        Note that end-users will usually not use the private key directly, but
 *        rather look it up in GNS for places managed by other users, or select
 *        a file with the private key(s) when setting up their own channels
 *        FIXME: we'll likely want to use NOT the p521 curve here, but a cheaper
 *        one in the future.
 * @param policy  Channel policy specifying join and history restrictions.
 *        Used to automate join decisions.
 * @param message_cb  Function to invoke on message parts received from slaves.
 * @param join_request_cb  Function to invoke when a slave wants to join.
 * @param master_start_cb  Function to invoke after the channel master started.
 * @param cls  Closure for @a method and @a join_cb.
 *
 * @return Handle for the channel master, NULL on error.
 */
struct GNUNET_PSYC_Master *
GNUNET_PSYC_master_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
                          const struct GNUNET_CRYPTO_EddsaPrivateKey *channel_key,
                          enum GNUNET_PSYC_Policy policy,
                          GNUNET_PSYC_MasterStartCallback start_cb,
                          GNUNET_PSYC_JoinRequestCallback join_request_cb,
                          GNUNET_PSYC_MessageCallback message_cb,
                          GNUNET_PSYC_MessagePartCallback message_part_cb,
                          void *cls)
{
  struct GNUNET_PSYC_Master *mst = GNUNET_malloc (sizeof (*mst));
  struct GNUNET_PSYC_Channel *chn = &mst->chn;

  struct MasterStartRequest *req = GNUNET_malloc (sizeof (*req));
  req->header.size = htons (sizeof (*req));
  req->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_MASTER_START);
  req->channel_key = *channel_key;
  req->policy = policy;

  chn->connect_msg = (struct GNUNET_MessageHeader *) req;
  chn->cfg = cfg;
  chn->is_master = GNUNET_YES;

  mst->start_cb = start_cb;
  mst->join_req_cb = join_request_cb;
  mst->cb_cls = cls;

  chn->client = GNUNET_CLIENT_MANAGER_connect (cfg, "psyc", master_handlers);
  GNUNET_CLIENT_MANAGER_set_user_context_ (chn->client, mst, sizeof (*chn));

  chn->tmit = GNUNET_PSYC_transmit_create (chn->client);
  chn->recv = GNUNET_PSYC_receive_create (message_cb, message_part_cb, cls);

  channel_send_connect_msg (chn);
  return mst;
}


/**
 * Stop a PSYC master channel.
 *
 * @param master PSYC channel master to stop.
 * @param keep_active  FIXME
 */
void
GNUNET_PSYC_master_stop (struct GNUNET_PSYC_Master *mst,
                         int keep_active,
                         GNUNET_ContinuationCallback stop_cb,
                         void *stop_cls)
{
  struct GNUNET_PSYC_Channel *chn = &mst->chn;

  /* FIXME: send msg to service */

  chn->is_disconnecting = GNUNET_YES;
  chn->disconnect_cb = stop_cb;
  chn->disconnect_cls = stop_cls;

  GNUNET_CLIENT_MANAGER_disconnect (mst->chn.client, GNUNET_YES,
                                    &master_cleanup, mst);
}


/**
 * Function to call with the decision made for a join request.
 *
 * Must be called once and only once in response to an invocation of the
 * #GNUNET_PSYC_JoinCallback.
 *
 * @param jh Join request handle.
 * @param is_admitted  #GNUNET_YES    if the join is approved,
 *                     #GNUNET_NO     if it is disapproved,
 *                     #GNUNET_SYSERR if we cannot answer the request.
 * @param relay_count Number of relays given.
 * @param relays Array of suggested peers that might be useful relays to use
 *        when joining the multicast group (essentially a list of peers that
 *        are already part of the multicast group and might thus be willing
 *        to help with routing).  If empty, only this local peer (which must
 *        be the multicast origin) is a good candidate for building the
 *        multicast tree.  Note that it is unnecessary to specify our own
 *        peer identity in this array.
 * @param join_resp  Application-dependent join response message.
 *
 * @return #GNUNET_OK on success,
 *         #GNUNET_SYSERR if the message is too large.
 */
int
GNUNET_PSYC_join_decision (struct GNUNET_PSYC_JoinHandle *jh,
                           int is_admitted,
                           uint32_t relay_count,
                           const struct GNUNET_PeerIdentity *relays,
                           const struct GNUNET_PSYC_Message *join_resp)
{
  struct GNUNET_PSYC_Channel *chn = &jh->mst->chn;
  struct GNUNET_PSYC_JoinDecisionMessage *dcsn;
  uint16_t join_resp_size
    = (NULL != join_resp) ? ntohs (join_resp->header.size) : 0;
  uint16_t relay_size = relay_count * sizeof (*relays);

  if (GNUNET_MULTICAST_FRAGMENT_MAX_PAYLOAD
      < sizeof (*dcsn) + relay_size + join_resp_size)
    return GNUNET_SYSERR;

  dcsn = GNUNET_malloc (sizeof (*dcsn) + relay_size + join_resp_size);
  dcsn->header.size = htons (sizeof (*dcsn) + relay_size + join_resp_size);
  dcsn->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_JOIN_DECISION);
  dcsn->is_admitted = htonl (is_admitted);
  dcsn->slave_key = jh->slave_key;

  if (0 < join_resp_size)
    memcpy (&dcsn[1], join_resp, join_resp_size);

  GNUNET_CLIENT_MANAGER_transmit (chn->client, &dcsn->header);
  GNUNET_free (jh);
  return GNUNET_OK;
}


/**
 * Send a message to call a method to all members in the PSYC channel.
 *
 * @param master Handle to the PSYC channel.
 * @param method_name Which method should be invoked.
 * @param notify_mod Function to call to obtain modifiers.
 * @param notify_data Function to call to obtain fragments of the data.
 * @param notify_cls Closure for @a notify_mod and @a notify_data.
 * @param flags Flags for the message being transmitted.
 *
 * @return Transmission handle, NULL on error (i.e. more than one request queued).
 */
struct GNUNET_PSYC_MasterTransmitHandle *
GNUNET_PSYC_master_transmit (struct GNUNET_PSYC_Master *mst,
                             const char *method_name,
                             GNUNET_PSYC_TransmitNotifyModifier notify_mod,
                             GNUNET_PSYC_TransmitNotifyData notify_data,
                             void *notify_cls,
                             enum GNUNET_PSYC_MasterTransmitFlags flags)
{
  if (GNUNET_OK
      == GNUNET_PSYC_transmit_message (mst->chn.tmit, method_name, NULL,
                                       notify_mod, notify_data, notify_cls,
                                       flags))
    return (struct GNUNET_PSYC_MasterTransmitHandle *) mst->chn.tmit;
  else
    return NULL;
}


/**
 * Resume transmission to the channel.
 *
 * @param tmit  Handle of the request that is being resumed.
 */
void
GNUNET_PSYC_master_transmit_resume (struct GNUNET_PSYC_MasterTransmitHandle *tmit)
{
  GNUNET_PSYC_transmit_resume ((struct GNUNET_PSYC_TransmitHandle *) tmit);
}


/**
 * Abort transmission request to the channel.
 *
 * @param tmit  Handle of the request that is being aborted.
 */
void
GNUNET_PSYC_master_transmit_cancel (struct GNUNET_PSYC_MasterTransmitHandle *tmit)
{
  GNUNET_PSYC_transmit_cancel ((struct GNUNET_PSYC_TransmitHandle *) tmit);
}


/**
 * Convert a channel @a master to a @e channel handle to access the @e channel
 * APIs.
 *
 * @param master Channel master handle.
 *
 * @return Channel handle, valid for as long as @a master is valid.
 */
struct GNUNET_PSYC_Channel *
GNUNET_PSYC_master_get_channel (struct GNUNET_PSYC_Master *master)
{
  return &master->chn;
}


/**
 * Join a PSYC channel.
 *
 * The entity joining is always the local peer.  The user must immediately use
 * the GNUNET_PSYC_slave_transmit() functions to transmit a @e join_msg to the
 * channel; if the join request succeeds, the channel state (and @e recent
 * method calls) will be replayed to the joining member.  There is no explicit
 * notification on failure (as the channel may simply take days to approve,
 * and disapproval is simply being ignored).
 *
 * @param cfg  Configuration to use.
 * @param channel_key  ECC public key that identifies the channel we wish to join.
 * @param slave_key  ECC private-public key pair that identifies the slave, and
 *        used by multicast to sign the join request and subsequent unicast
 *        requests sent to the master.
 * @param origin  Peer identity of the origin.
 * @param relay_count  Number of peers in the @a relays array.
 * @param relays  Peer identities of members of the multicast group, which serve
 *        as relays and used to join the group at.
 * @param message_cb  Function to invoke on message parts received from the
 *        channel, typically at least contains method handlers for @e join and
 *        @e part.
 * @param slave_connect_cb  Function invoked once we have connected to the
 *        PSYC service.
 * @param join_decision_cb  Function invoked once we have received a join
 *	  decision.
 * @param cls  Closure for @a message_cb and @a slave_joined_cb.
 * @param method_name  Method name for the join request.
 * @param env  Environment containing transient variables for the request, or NULL.
 * @param data  Payload for the join message.
 * @param data_size  Number of bytes in @a data.
 *
 * @return Handle for the slave, NULL on error.
 */
struct GNUNET_PSYC_Slave *
GNUNET_PSYC_slave_join (const struct GNUNET_CONFIGURATION_Handle *cfg,
                        const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                        const struct GNUNET_CRYPTO_EcdsaPrivateKey *slave_key,
                        const struct GNUNET_PeerIdentity *origin,
                        uint32_t relay_count,
                        const struct GNUNET_PeerIdentity *relays,
                        GNUNET_PSYC_MessageCallback message_cb,
                        GNUNET_PSYC_MessagePartCallback message_part_cb,
                        GNUNET_PSYC_SlaveConnectCallback connect_cb,
                        GNUNET_PSYC_JoinDecisionCallback join_decision_cb,
                        void *cls,
                        const struct GNUNET_PSYC_Message *join_msg)
{
  struct GNUNET_PSYC_Slave *slv = GNUNET_malloc (sizeof (*slv));
  struct GNUNET_PSYC_Channel *chn = &slv->chn;
  uint16_t relay_size = relay_count * sizeof (*relays);
  uint16_t join_msg_size;
  struct SlaveJoinRequest *req;

  if (NULL == join_msg)
    join_msg_size = 0;
  else
    join_msg_size = ntohs (join_msg->header.size);
  req = GNUNET_malloc (sizeof (*req) + relay_size + join_msg_size);
  req->header.size = htons (sizeof (*req)
                            + relay_count * sizeof (*relays));
  req->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_SLAVE_JOIN);
  req->channel_key = *channel_key;
  req->slave_key = *slave_key;
  req->origin = *origin;
  req->relay_count = htonl (relay_count);

  if (0 < relay_size)
    memcpy (&req[1], relays, relay_size);

  if (NULL != join_msg)
    memcpy ((char *) &req[1] + relay_size,
            join_msg,
            join_msg_size);

  chn->connect_msg = (struct GNUNET_MessageHeader *) req;
  chn->cfg = cfg;
  chn->is_master = GNUNET_NO;

  slv->connect_cb = connect_cb;
  slv->join_dcsn_cb = join_decision_cb;
  slv->cb_cls = cls;

  chn->client = GNUNET_CLIENT_MANAGER_connect (cfg, "psyc", slave_handlers);
  GNUNET_CLIENT_MANAGER_set_user_context_ (chn->client, slv, sizeof (*chn));

  chn->recv = GNUNET_PSYC_receive_create (message_cb, message_part_cb, cls);
  chn->tmit = GNUNET_PSYC_transmit_create (chn->client);

  channel_send_connect_msg (chn);
  return slv;
}


/**
 * Part a PSYC channel.
 *
 * Will terminate the connection to the PSYC service.  Polite clients should
 * first explicitly send a part request (via GNUNET_PSYC_slave_transmit()).
 *
 * @param slave Slave handle.
 */
void
GNUNET_PSYC_slave_part (struct GNUNET_PSYC_Slave *slv,
                        int keep_active,
                        GNUNET_ContinuationCallback part_cb,
                        void *part_cls)
{
  struct GNUNET_PSYC_Channel *chn = &slv->chn;

  /* FIXME: send msg to service */

  chn->is_disconnecting = GNUNET_YES;
  chn->disconnect_cb = part_cb;
  chn->disconnect_cls = part_cls;

  GNUNET_CLIENT_MANAGER_disconnect (slv->chn.client, GNUNET_YES,
                                    &slave_cleanup, slv);
}


/**
 * Request a message to be sent to the channel master.
 *
 * @param slave Slave handle.
 * @param method_name Which (PSYC) method should be invoked (on host).
 * @param notify_mod Function to call to obtain modifiers.
 * @param notify_data Function to call to obtain fragments of the data.
 * @param notify_cls Closure for @a notify.
 * @param flags Flags for the message being transmitted.
 *
 * @return Transmission handle, NULL on error (i.e. more than one request
 *         queued).
 */
struct GNUNET_PSYC_SlaveTransmitHandle *
GNUNET_PSYC_slave_transmit (struct GNUNET_PSYC_Slave *slv,
                            const char *method_name,
                            GNUNET_PSYC_TransmitNotifyModifier notify_mod,
                            GNUNET_PSYC_TransmitNotifyData notify_data,
                            void *notify_cls,
                            enum GNUNET_PSYC_SlaveTransmitFlags flags)

{
  if (GNUNET_OK
      == GNUNET_PSYC_transmit_message (slv->chn.tmit, method_name, NULL,
                                       notify_mod, notify_data, notify_cls,
                                       flags))
    return (struct GNUNET_PSYC_SlaveTransmitHandle *) slv->chn.tmit;
  else
    return NULL;
}


/**
 * Resume transmission to the master.
 *
 * @param tmit Handle of the request that is being resumed.
 */
void
GNUNET_PSYC_slave_transmit_resume (struct GNUNET_PSYC_SlaveTransmitHandle *tmit)
{
  GNUNET_PSYC_transmit_resume ((struct GNUNET_PSYC_TransmitHandle *) tmit);
}


/**
 * Abort transmission request to master.
 *
 * @param tmit Handle of the request that is being aborted.
 */
void
GNUNET_PSYC_slave_transmit_cancel (struct GNUNET_PSYC_SlaveTransmitHandle *tmit)
{
  GNUNET_PSYC_transmit_cancel ((struct GNUNET_PSYC_TransmitHandle *) tmit);
}


/**
 * Convert @a slave to a @e channel handle to access the @e channel APIs.
 *
 * @param slv Slave handle.
 *
 * @return Channel handle, valid for as long as @a slave is valid.
 */
struct GNUNET_PSYC_Channel *
GNUNET_PSYC_slave_get_channel (struct GNUNET_PSYC_Slave *slv)
{
  return &slv->chn;
}


/**
 * Add a slave to the channel's membership list.
 *
 * Note that this will NOT generate any PSYC traffic, it will merely update the
 * local database to modify how we react to <em>membership test</em> queries.
 * The channel master still needs to explicitly transmit a @e join message to
 * notify other channel members and they then also must still call this function
 * in their respective methods handling the @e join message.  This way, how @e
 * join and @e part operations are exactly implemented is still up to the
 * application; for example, there might be a @e part_all method to kick out
 * everyone.
 *
 * Note that channel slaves are explicitly trusted to execute such methods
 * correctly; not doing so correctly will result in either denying other slaves
 * access or offering access to channel data to non-members.
 *
 * @param chn
 *        Channel handle.
 * @param slave_key
 *        Identity of channel slave to add.
 * @param announced_at
 *        ID of the message that announced the membership change.
 * @param effective_since
 *        Addition of slave is in effect since this message ID.
 * @param result_cb
 *        Function to call with the result of the operation.
 *        The @e result_code argument is #GNUNET_OK on success, or
 *        #GNUNET_SYSERR on error.  In case of an error, the @e data argument
 *        can contain an optional error message.
 * @param cls
 *        Closure for @a result_cb.
 */
void
GNUNET_PSYC_channel_slave_add (struct GNUNET_PSYC_Channel *chn,
                               const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key,
                               uint64_t announced_at,
                               uint64_t effective_since,
                               GNUNET_ResultCallback result_cb,
                               void *cls)
{
  struct ChannelMembershipStoreRequest *req = GNUNET_malloc (sizeof (*req));
  req->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_CHANNEL_MEMBERSHIP_STORE);
  req->header.size = htons (sizeof (*req));
  req->slave_key = *slave_key;
  req->announced_at = GNUNET_htonll (announced_at);
  req->effective_since = GNUNET_htonll (effective_since);
  req->did_join = GNUNET_YES;
  req->op_id = GNUNET_htonll (GNUNET_CLIENT_MANAGER_op_add (chn->client,
                                                            result_cb, cls));

  GNUNET_CLIENT_MANAGER_transmit (chn->client, &req->header);
}


/**
 * Remove a slave from the channel's membership list.
 *
 * Note that this will NOT generate any PSYC traffic, it will merely update the
 * local database to modify how we react to <em>membership test</em> queries.
 * The channel master still needs to explicitly transmit a @e part message to
 * notify other channel members and they then also must still call this function
 * in their respective methods handling the @e part message.  This way, how
 * @e join and @e part operations are exactly implemented is still up to the
 * application; for example, there might be a @e part_all message to kick out
 * everyone.
 *
 * Note that channel members are explicitly trusted to perform these
 * operations correctly; not doing so correctly will result in either
 * denying members access or offering access to channel data to
 * non-members.
 *
 * @param chn
 *        Channel handle.
 * @param slave_key
 *        Identity of channel slave to remove.
 * @param announced_at
 *        ID of the message that announced the membership change.
 * @param result_cb
 *        Function to call with the result of the operation.
 *        The @e result_code argument is #GNUNET_OK on success, or
 *        #GNUNET_SYSERR on error.  In case of an error, the @e data argument
 *        can contain an optional error message.
 * @param cls
 *        Closure for @a result_cb.
 */
void
GNUNET_PSYC_channel_slave_remove (struct GNUNET_PSYC_Channel *chn,
                                  const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key,
                                  uint64_t announced_at,
                                  GNUNET_ResultCallback result_cb,
                                  void *cls)
{
  struct ChannelMembershipStoreRequest *req = GNUNET_malloc (sizeof (*req));
  req->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_CHANNEL_MEMBERSHIP_STORE);
  req->header.size = htons (sizeof (*req));
  req->slave_key = *slave_key;
  req->announced_at = GNUNET_htonll (announced_at);
  req->did_join = GNUNET_NO;
  req->op_id = GNUNET_htonll (GNUNET_CLIENT_MANAGER_op_add (chn->client,
                                                            result_cb, cls));

  GNUNET_CLIENT_MANAGER_transmit (chn->client, &req->header);
}


static struct GNUNET_PSYC_HistoryRequest *
channel_history_replay (struct GNUNET_PSYC_Channel *chn,
                        uint64_t start_message_id,
                        uint64_t end_message_id,
                        uint64_t message_limit,
                        const char *method_prefix,
                        uint32_t flags,
                        GNUNET_PSYC_MessageCallback message_cb,
                        GNUNET_PSYC_MessagePartCallback message_part_cb,
                        GNUNET_ResultCallback result_cb,
                        void *cls)
{
  struct GNUNET_PSYC_HistoryRequestMessage *req;
  struct GNUNET_PSYC_HistoryRequest *hist = GNUNET_malloc (sizeof (*hist));
  hist->chn = chn;
  hist->recv = GNUNET_PSYC_receive_create (message_cb, message_part_cb, cls);
  hist->result_cb = result_cb;
  hist->cls = cls;
  hist->op_id = GNUNET_CLIENT_MANAGER_op_add (chn->client,
                                            &op_recv_history_result, hist);

  GNUNET_assert (NULL != method_prefix);
  uint16_t method_size = strnlen (method_prefix,
                                  GNUNET_SERVER_MAX_MESSAGE_SIZE
                                  - sizeof (*req)) + 1;
  GNUNET_assert ('\0' == method_prefix[method_size - 1]);
  req = GNUNET_malloc (sizeof (*req) + method_size);
  req->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_HISTORY_REPLAY);
  req->header.size = htons (sizeof (*req) + method_size);
  req->start_message_id = GNUNET_htonll (start_message_id);
  req->end_message_id = GNUNET_htonll (end_message_id);
  req->message_limit = GNUNET_htonll (message_limit);
  req->flags = htonl (flags);
  req->op_id = GNUNET_htonll (hist->op_id);
  memcpy (&req[1], method_prefix, method_size);

  GNUNET_CLIENT_MANAGER_transmit (chn->client, &req->header);
  return hist;
}


/**
 * Request to replay a part of the message history of the channel.
 *
 * Historic messages (but NOT the state at the time) will be replayed and given
 * to the normal method handlers with a #GNUNET_PSYC_MESSAGE_HISTORIC flag set.
 *
 * Messages are retrieved from the local PSYCstore if available,
 * otherwise requested from the network.
 *
 * @param channel
 *        Which channel should be replayed?
 * @param start_message_id
 *        Earliest interesting point in history.
 * @param end_message_id
 *        Last (inclusive) interesting point in history.
 * @param method_prefix
 *        Retrieve only messages with a matching method prefix.
 * @param flags
 *        OR'ed enum GNUNET_PSYC_HistoryReplayFlags
 * @param result_cb
 *        Function to call when the requested history has been fully replayed.
 * @param cls
 *        Closure for the callbacks.
 *
 * @return Handle to cancel history replay operation.
 */
struct GNUNET_PSYC_HistoryRequest *
GNUNET_PSYC_channel_history_replay (struct GNUNET_PSYC_Channel *chn,
                                    uint64_t start_message_id,
                                    uint64_t end_message_id,
                                    const char *method_prefix,
                                    uint32_t flags,
                                    GNUNET_PSYC_MessageCallback message_cb,
                                    GNUNET_PSYC_MessagePartCallback message_part_cb,
                                    GNUNET_ResultCallback result_cb,
                                    void *cls)
{
  return channel_history_replay (chn, start_message_id, end_message_id, 0,
                                 method_prefix, flags,
                                 message_cb, message_part_cb, result_cb, cls);
}


/**
 * Request to replay the latest messages from the message history of the channel.
 *
 * Historic messages (but NOT the state at the time) will be replayed (given to
 * the normal method handlers) if available and if access is permitted.
 *
 * @param channel
 *        Which channel should be replayed?
 * @param message_limit
 *        Maximum number of messages to replay.
 * @param method_prefix
 *        Retrieve only messages with a matching method prefix.
 *        Use NULL or "" to retrieve all.
 * @param flags
 *        OR'ed enum GNUNET_PSYC_HistoryReplayFlags
 * @param result_cb
 *        Function to call when the requested history has been fully replayed.
 * @param cls
 *        Closure for the callbacks.
 *
 * @return Handle to cancel history replay operation.
 */
struct GNUNET_PSYC_HistoryRequest *
GNUNET_PSYC_channel_history_replay_latest (struct GNUNET_PSYC_Channel *chn,
                                           uint64_t message_limit,
                                           const char *method_prefix,
                                           uint32_t flags,
                                           GNUNET_PSYC_MessageCallback message_cb,
                                           GNUNET_PSYC_MessagePartCallback message_part_cb,
                                           GNUNET_ResultCallback result_cb,
                                           void *cls)
{
  return channel_history_replay (chn, 0, 0, message_limit, method_prefix, flags,
                                 message_cb, message_part_cb, result_cb, cls);
}


void
GNUNET_PSYC_channel_history_replay_cancel (struct GNUNET_PSYC_Channel *channel,
                                           struct GNUNET_PSYC_HistoryRequest *hist)
{
  GNUNET_PSYC_receive_destroy (hist->recv);
  GNUNET_CLIENT_MANAGER_op_cancel (hist->chn->client, hist->op_id);
  GNUNET_free (hist);
}


/**
 * Retrieve the best matching channel state variable.
 *
 * If the requested variable name is not present in the state, the nearest
 * less-specific name is matched; for example, requesting "_a_b" will match "_a"
 * if "_a_b" does not exist.
 *
 * @param channel
 *        Channel handle.
 * @param full_name
 *        Full name of the requested variable.
 *        The actual variable returned might have a shorter name.
 * @param var_cb
 *        Function called once when a matching state variable is found.
 *        Not called if there's no matching state variable.
 * @param result_cb
 *        Function called after the operation finished.
 *        (i.e. all state variables have been returned via @a state_cb)
 * @param cls
 *        Closure for the callbacks.
 */
static struct GNUNET_PSYC_StateRequest *
channel_state_get (struct GNUNET_PSYC_Channel *chn,
                   uint16_t type, const char *name,
                   GNUNET_PSYC_StateVarCallback var_cb,
                   GNUNET_ResultCallback result_cb, void *cls)
{
  struct StateRequest *req;
  struct GNUNET_PSYC_StateRequest *sr = GNUNET_malloc (sizeof (*sr));
  sr->chn = chn;
  sr->var_cb = var_cb;
  sr->result_cb = result_cb;
  sr->cls = cls;
  sr->op_id = GNUNET_CLIENT_MANAGER_op_add (chn->client,
                                            &op_recv_state_result, sr);

  GNUNET_assert (NULL != name);
  size_t name_size = strnlen (name, GNUNET_SERVER_MAX_MESSAGE_SIZE
                              - sizeof (*req)) + 1;
  req = GNUNET_malloc (sizeof (*req) + name_size);
  req->header.type = htons (type);
  req->header.size = htons (sizeof (*req) + name_size);
  req->op_id = GNUNET_htonll (sr->op_id);
  memcpy (&req[1], name, name_size);

  GNUNET_CLIENT_MANAGER_transmit (chn->client, &req->header);
  return sr;
}


/**
 * Retrieve the best matching channel state variable.
 *
 * If the requested variable name is not present in the state, the nearest
 * less-specific name is matched; for example, requesting "_a_b" will match "_a"
 * if "_a_b" does not exist.
 *
 * @param channel
 *        Channel handle.
 * @param full_name
 *        Full name of the requested variable.
 *        The actual variable returned might have a shorter name.
 * @param var_cb
 *        Function called once when a matching state variable is found.
 *        Not called if there's no matching state variable.
 * @param result_cb
 *        Function called after the operation finished.
 *        (i.e. all state variables have been returned via @a state_cb)
 * @param cls
 *        Closure for the callbacks.
 */
struct GNUNET_PSYC_StateRequest *
GNUNET_PSYC_channel_state_get (struct GNUNET_PSYC_Channel *chn,
                               const char *full_name,
                               GNUNET_PSYC_StateVarCallback var_cb,
                               GNUNET_ResultCallback result_cb,
                               void *cls)
{
  return channel_state_get (chn, GNUNET_MESSAGE_TYPE_PSYC_STATE_GET,
                            full_name, var_cb, result_cb, cls);

}


/**
 * Return all channel state variables whose name matches a given prefix.
 *
 * A name matches if it starts with the given @a name_prefix, thus requesting
 * the empty prefix ("") will match all values; requesting "_a_b" will also
 * return values stored under "_a_b_c".
 *
 * The @a state_cb is invoked on all matching state variables asynchronously, as
 * the state is stored in and retrieved from the PSYCstore,
 *
 * @param channel
 *        Channel handle.
 * @param name_prefix
 *        Prefix of the state variable name to match.
 * @param var_cb
 *        Function called once when a matching state variable is found.
 *        Not called if there's no matching state variable.
 * @param result_cb
 *        Function called after the operation finished.
 *        (i.e. all state variables have been returned via @a state_cb)
 * @param cls
 *        Closure for the callbacks.
 */
struct GNUNET_PSYC_StateRequest *
GNUNET_PSYC_channel_state_get_prefix (struct GNUNET_PSYC_Channel *chn,
                                      const char *name_prefix,
                                      GNUNET_PSYC_StateVarCallback var_cb,
                                      GNUNET_ResultCallback result_cb,
                                      void *cls)
{
  return channel_state_get (chn, GNUNET_MESSAGE_TYPE_PSYC_STATE_GET_PREFIX,
                            name_prefix, var_cb, result_cb, cls);
}


/**
 * Cancel a state request operation.
 *
 * @param sr
 *        Handle for the operation to cancel.
 */
void
GNUNET_PSYC_channel_state_get_cancel (struct GNUNET_PSYC_StateRequest *sr)
{
  GNUNET_CLIENT_MANAGER_op_cancel (sr->chn->client, sr->op_id);
  GNUNET_free (sr);
}

/* end of psyc_api.c */
