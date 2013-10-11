/*
 * This file is part of GNUnet
 * (C) 2013 Christian Grothoff (and other contributing authors)
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
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
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

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_env_lib.h"
#include "gnunet_psyc_service.h"
#include "psyc.h"

#define LOG(kind,...) GNUNET_log_from (kind, "psyc-api",__VA_ARGS__)


struct OperationHandle
{
  struct OperationHandle *prev;
  struct OperationHandle *next;
  const struct GNUNET_MessageHeader *msg;
};

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
   * Socket (if available).
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Currently pending transmission request, or NULL for none.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * Head of operations to transmit.
   */
  struct OperationHandle *transmit_head;

  /**
   * Tail of operations to transmit.
   */
  struct OperationHandle *transmit_tail;

  /**
   * Message to send on reconnect.
   */
  struct GNUNET_MessageHeader *reconnect_msg;

  /**
   * Task doing exponential back-off trying to reconnect.
   */
  GNUNET_SCHEDULER_TaskIdentifier reconnect_task;

  /**
   * Time for next connect retry.
   */
  struct GNUNET_TIME_Relative reconnect_delay;

  GNUNET_PSYC_Method method_cb;

  GNUNET_PSYC_JoinCallback join_cb;

  void *cb_cls;

  /**
   * Are we polling for incoming messages right now?
   */
  int in_receive;

  /**
   * Are we currently transmitting a message?
   */
  int in_transmit;

  /**
   * Is this a master or slave channel?
   */
  int is_master;

  /**
   * Buffer space available for transmitting the next data fragment.
   */
  uint16_t tmit_buf_avail;
};


/**
 * Handle for a pending PSYC transmission operation.
 */
struct GNUNET_PSYC_MasterTransmitHandle
{
  struct GNUNET_PSYC_Master *master;
  GNUNET_PSYC_MasterTransmitNotify notify;
  void *notify_cls;
  enum GNUNET_PSYC_DataStatus status;
};


/**
 * Handle for the master of a PSYC channel.
 */
struct GNUNET_PSYC_Master
{
  struct GNUNET_PSYC_Channel ch;

  struct GNUNET_PSYC_MasterTransmitHandle *tmit;

  GNUNET_PSYC_MasterStartCallback start_cb;

  uint64_t max_message_id;
};


/**
 * Handle for a PSYC channel slave.
 */
struct GNUNET_PSYC_Slave
{
  struct GNUNET_PSYC_Channel ch;
};


/**
 * Handle that identifies a join request.
 *
 * Used to match calls to #GNUNET_PSYC_JoinCallback to the
 * corresponding calls to GNUNET_PSYC_join_decision().
 */
struct GNUNET_PSYC_JoinHandle
{

};


/**
 * Handle for a pending PSYC transmission operation.
 */
struct GNUNET_PSYC_SlaveTransmitHandle
{

};


/**
 * Handle to a story telling operation.
 */
struct GNUNET_PSYC_Story
{

};


/**
 * Handle for a state query operation.
 */
struct GNUNET_PSYC_StateQuery
{

};


/**
 * Try again to connect to the PSYC service.
 *
 * @param cls Handle to the PSYC service.
 * @param tc Scheduler context
 */
static void
reconnect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Reschedule a connect attempt to the service.
 *
 * @param h transport service to reconnect
 */
static void
reschedule_connect (struct GNUNET_PSYC_Channel *c)
{
  GNUNET_assert (c->reconnect_task == GNUNET_SCHEDULER_NO_TASK);

  if (NULL != c->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (c->th);
    c->th = NULL;
  }
  if (NULL != c->client)
  {
    GNUNET_CLIENT_disconnect (c->client);
    c->client = NULL;
  }
  c->in_receive = GNUNET_NO;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Scheduling task to reconnect to PSYC service in %s.\n",
       GNUNET_STRINGS_relative_time_to_string (c->reconnect_delay, GNUNET_YES));
  c->reconnect_task =
      GNUNET_SCHEDULER_add_delayed (c->reconnect_delay, &reconnect, c);
  c->reconnect_delay = GNUNET_TIME_STD_BACKOFF (c->reconnect_delay);
}


/**
 * Schedule transmission of the next message from our queue.
 *
 * @param h PSYC handle
 */
static void
transmit_next (struct GNUNET_PSYC_Channel *c);


void
master_transmit_data (struct GNUNET_PSYC_Master *mst)
{
  struct GNUNET_PSYC_Channel *ch = &mst->ch;
  size_t data_size = ch->tmit_buf_avail;
  struct GNUNET_PSYC_MessageData *pdata;
  struct OperationHandle *op
    = GNUNET_malloc (sizeof (*op) + sizeof (*pdata) + data_size);
  pdata = (struct GNUNET_PSYC_MessageData *) &op[1];
  op->msg = (struct GNUNET_MessageHeader *) pdata;
  pdata->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_DATA);

  switch (mst->tmit->notify (mst->tmit->notify_cls, &data_size, &pdata[1]))
  {
  case GNUNET_NO:
    mst->tmit->status = GNUNET_PSYC_DATA_CONT;
    break;

  case GNUNET_YES:
    mst->tmit->status = GNUNET_PSYC_DATA_END;
    break;

  default:
    mst->tmit->status = GNUNET_PSYC_DATA_CANCEL;
    data_size = 0;
    LOG (GNUNET_ERROR_TYPE_ERROR, "MasterTransmitNotify returned error\n");
  }

  if ((GNUNET_PSYC_DATA_CONT == mst->tmit->status && 0 == data_size))
  {
    /* Transmission paused, nothing to send. */
    GNUNET_free (op);
  }
  else
  {
    GNUNET_assert (data_size <= ch->tmit_buf_avail);
    pdata->header.size = htons (sizeof (*pdata) + data_size);
    pdata->status = htons (mst->tmit->status);
    GNUNET_CONTAINER_DLL_insert_tail (ch->transmit_head, ch->transmit_tail, op);
    transmit_next (ch);
  }
}


/**
 * Type of a function to call when we receive a message
 * from the service.
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
static void
message_handler (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_PSYC_Channel *ch = cls;
  struct GNUNET_PSYC_Master *mst = cls;
  struct GNUNET_PSYC_Slave *slv = cls;

  if (NULL == msg)
  {
    reschedule_connect (ch);
    return;
  }
  uint16_t size_eq = 0;
  uint16_t size_min = 0;
  uint16_t size = ntohs (msg->size);
  uint16_t type = ntohs (msg->type);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received message of type %d from PSYC service\n", type);

  switch (type)
  {
  case GNUNET_MESSAGE_TYPE_PSYC_MASTER_START_ACK:
  case GNUNET_MESSAGE_TYPE_PSYC_SLAVE_JOIN_ACK:
    size_eq = sizeof (struct CountersResult);
    break;
  case GNUNET_MESSAGE_TYPE_PSYC_TRANSMIT_ACK:
    size_eq = sizeof (struct TransmitAck);
    break;
  }

  if (! ((0 < size_eq && size == size_eq)
         || (0 < size_min && size >= size_min)))
  {
    GNUNET_break (0);
    reschedule_connect (ch);
    return;
  }

  struct CountersResult *cres;
  struct TransmitAck *tack;

  switch (type)
  {
  case GNUNET_MESSAGE_TYPE_PSYC_MASTER_START_ACK:
    cres = (struct CountersResult *) msg;
    mst->max_message_id = GNUNET_ntohll (cres->max_message_id);
    if (NULL != mst->start_cb)
      mst->start_cb (ch->cb_cls, mst->max_message_id);
    break;

  case GNUNET_MESSAGE_TYPE_PSYC_SLAVE_JOIN_ACK:
    cres = (struct CountersResult *) msg;
#if TODO
    slv->max_message_id = GNUNET_ntohll (cres->max_message_id);
    if (NULL != slv->join_ack_cb)
      mst->join_ack_cb (ch->cb_cls, mst->max_message_id);
#endif
    break;

  case GNUNET_MESSAGE_TYPE_PSYC_TRANSMIT_ACK:
    tack = (struct TransmitAck *) msg;
    if (ch->is_master)
    {
      GNUNET_assert (NULL != mst->tmit);
      if (GNUNET_PSYC_DATA_CONT != mst->tmit->status
          || NULL == mst->tmit->notify)
      {
        GNUNET_free (mst->tmit);
        mst->tmit = NULL;
      }
      else
      {
        ch->tmit_buf_avail = ntohs (tack->buf_avail);
        master_transmit_data (mst);
      }
    }
    else
    {
      /* TODO: slave */
    }
    break;
  }

  GNUNET_CLIENT_receive (ch->client, &message_handler, ch,
                         GNUNET_TIME_UNIT_FOREVER_REL);
}

/**
 * Transmit next message to service.
 *
 * @param cls The 'struct GNUNET_PSYC_Channel'.
 * @param size Number of bytes available in buf.
 * @param buf Where to copy the message.
 * @return Number of bytes copied to buf.
 */
static size_t
send_next_message (void *cls, size_t size, void *buf)
{
  struct GNUNET_PSYC_Channel *ch = cls;
  struct OperationHandle *op = ch->transmit_head;
  size_t ret;

  ch->th = NULL;
  if (NULL == op->msg)
    return 0;
  ret = ntohs (op->msg->size);
  if (ret > size)
  {
    reschedule_connect (ch);
    return 0;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending message of type %d to PSYC service\n",
       ntohs (op->msg->type));
  memcpy (buf, op->msg, ret);

  GNUNET_CONTAINER_DLL_remove (ch->transmit_head, ch->transmit_tail, op);
  GNUNET_free (op);

  if (NULL != ch->transmit_head)
    transmit_next (ch);

  if (GNUNET_NO == ch->in_receive)
  {
    ch->in_receive = GNUNET_YES;
    GNUNET_CLIENT_receive (ch->client, &message_handler, ch,
                           GNUNET_TIME_UNIT_FOREVER_REL);
  }
  return ret;
}


/**
 * Schedule transmission of the next message from our queue.
 *
 * @param h PSYC handle.
 */
static void
transmit_next (struct GNUNET_PSYC_Channel *ch)
{
  if (NULL != ch->th || NULL == ch->client)
    return;

  struct OperationHandle *op = ch->transmit_head;
  if (NULL == op)
    return;

  ch->th = GNUNET_CLIENT_notify_transmit_ready (ch->client,
                                                ntohs (op->msg->size),
                                                GNUNET_TIME_UNIT_FOREVER_REL,
                                                GNUNET_NO,
                                                &send_next_message,
                                                ch);
}


/**
 * Try again to connect to the PSYC service.
 *
 * @param cls Channel handle.
 * @param tc Scheduler context.
 */
static void
reconnect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_PSYC_Channel *ch = cls;

  ch->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connecting to PSYC service.\n");
  GNUNET_assert (NULL == ch->client);
  ch->client = GNUNET_CLIENT_connect ("psyc", ch->cfg);
  GNUNET_assert (NULL != ch->client);

  if (NULL == ch->transmit_head ||
      ch->transmit_head->msg->type != ch->reconnect_msg->type)
  {
    uint16_t reconn_size = ntohs (ch->reconnect_msg->size);
    struct OperationHandle *op = GNUNET_malloc (sizeof (*op) + reconn_size);
    memcpy (&op[1], ch->reconnect_msg, reconn_size);
    op->msg = (struct GNUNET_MessageHeader *) &op[1];
    GNUNET_CONTAINER_DLL_insert (ch->transmit_head, ch->transmit_tail, op);
  }
  transmit_next (ch);
}


/**
 * Disconnect from the PSYC service.
 *
 * @param cls Channel handle.
 * @param tc Scheduler context.
 */
static void
disconnect (void *c)
{
  struct GNUNET_PSYC_Channel *ch = c;
  GNUNET_assert (NULL != ch);
  if (ch->transmit_head != ch->transmit_tail)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Disconnecting while there are still outstanding messages!\n");
    GNUNET_break (0);
  }
  if (ch->reconnect_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (ch->reconnect_task);
    ch->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != ch->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (ch->th);
    ch->th = NULL;
  }
  if (NULL != ch->client)
  {
    GNUNET_CLIENT_disconnect (ch->client);
    ch->client = NULL;
  }
  if (NULL != ch->reconnect_msg)
  {
    GNUNET_free (ch->reconnect_msg);
    ch->reconnect_msg = NULL;
  }
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
 * @param cfg Configuration to use (to connect to PSYC service).
 * @param channel_key ECC key that will be used to sign messages for this
 *        PSYC session. The public key is used to identify the PSYC channel.
 *        Note that end-users will usually not use the private key directly, but
 *        rather look it up in GNS for places managed by other users, or select
 *        a file with the private key(s) when setting up their own channels
 *        FIXME: we'll likely want to use NOT the p521 curve here, but a cheaper
 *        one in the future.
 * @param policy Channel policy specifying join and history restrictions.
 *        Used to automate join decisions.
 * @param method Function to invoke on messages received from slaves.
 * @param join_cb Function to invoke when a peer wants to join.
 * @param cls Closure for @a method and @a join_cb.
 * @return Handle for the channel master, NULL on error.
 */
struct GNUNET_PSYC_Master *
GNUNET_PSYC_master_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
                          const struct GNUNET_CRYPTO_EddsaPrivateKey *channel_key,
                          enum GNUNET_PSYC_Policy policy,
                          GNUNET_PSYC_Method method,
                          GNUNET_PSYC_JoinCallback join_cb,
                          GNUNET_PSYC_MasterStartCallback master_started_cb,
                          void *cls)
{
  struct GNUNET_PSYC_Master *mst = GNUNET_malloc (sizeof (*mst));
  struct GNUNET_PSYC_Channel *ch = &mst->ch;
  struct MasterStartRequest *req = GNUNET_malloc (sizeof (*req));

  req->header.size = htons (sizeof (*req));
  req->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_MASTER_START);
  req->channel_key = *channel_key;
  req->policy = policy;

  ch->cfg = cfg;
  ch->is_master = GNUNET_YES;
  ch->reconnect_msg = (struct GNUNET_MessageHeader *) req;
  ch->reconnect_delay = GNUNET_TIME_UNIT_ZERO;
  ch->reconnect_task = GNUNET_SCHEDULER_add_now (&reconnect, mst);

  ch->method_cb = method;
  ch->join_cb = join_cb;
  ch->cb_cls = cls;
  mst->start_cb = master_started_cb;

  return mst;
}


/**
 * Stop a PSYC master channel.
 *
 * @param master PSYC channel master to stop.
 */
void
GNUNET_PSYC_master_stop (struct GNUNET_PSYC_Master *mst)
{
  disconnect (mst);
  GNUNET_free (mst);
}


/**
 * Function to call with the decision made for a join request.
 *
 * Must be called once and only once in response to an invocation of the
 * #GNUNET_PSYC_JoinCallback.
 *
 * @param jh Join request handle.
 * @param is_admitted #GNUNET_YES if joining is approved,
 *        #GNUNET_NO if it is disapproved.
 * @param relay_count Number of relays given.
 * @param relays Array of suggested peers that might be useful relays to use
 *        when joining the multicast group (essentially a list of peers that
 *        are already part of the multicast group and might thus be willing
 *        to help with routing).  If empty, only this local peer (which must
 *        be the multicast origin) is a good candidate for building the
 *        multicast tree.  Note that it is unnecessary to specify our own
 *        peer identity in this array.
 * @param method_name Method name for the message transmitted with the response.
 * @param env Environment containing transient variables for the message, or NULL.
 * @param data Data of the message.
 * @param data_size Size of @a data.
 */
void
GNUNET_PSYC_join_decision (struct GNUNET_PSYC_JoinHandle *jh,
                           int is_admitted,
                           uint32_t relay_count,
                           const struct GNUNET_PeerIdentity *relays,
                           const char *method_name,
                           const struct GNUNET_ENV_Environment *env,
                           const void *data,
                           size_t data_size)
{

}


/* FIXME: split up value into <64K chunks and transmit the continuations in
 *        MOD_CONT msgs */
int
send_modifier (void *cls, struct GNUNET_ENV_Modifier *mod)
{
  struct GNUNET_PSYC_Channel *ch = cls;
  size_t name_size = strlen (mod->name) + 1;
  struct GNUNET_PSYC_MessageModifier *pmod;
  struct OperationHandle *op = GNUNET_malloc (sizeof (*op) + sizeof (*pmod)
                                              + name_size + mod->value_size);
  pmod = (struct GNUNET_PSYC_MessageModifier *) &op[1];
  op->msg = (struct GNUNET_MessageHeader *) pmod;

  pmod->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MODIFIER);
  pmod->header.size = htons (sizeof (*pmod) + name_size + mod->value_size);
  pmod->name_size = htons (name_size);
  memcpy (&pmod[1], mod->name, name_size);
  memcpy ((char *) &pmod[1] + name_size, mod->value, mod->value_size);

  GNUNET_CONTAINER_DLL_insert_tail (ch->transmit_head, ch->transmit_tail, op);
  return GNUNET_YES;
}


/**
 * Send a message to call a method to all members in the PSYC channel.
 *
 * @param mst Handle to the PSYC channel.
 * @param method_name Which method should be invoked.
 * @param env Environment containing state operations and transient variables
 *            for the message, or NULL.
 * @param notify Function to call to obtain the arguments.
 * @param notify_cls Closure for @a notify.
 * @param flags Flags for the message being transmitted.
 * @return Transmission handle, NULL on error (i.e. more than one request
 *         queued).
 */
struct GNUNET_PSYC_MasterTransmitHandle *
GNUNET_PSYC_master_transmit (struct GNUNET_PSYC_Master *mst,
                             const char *method_name,
                             const struct GNUNET_ENV_Environment *env,
                             GNUNET_PSYC_MasterTransmitNotify notify,
                             void *notify_cls,
                             enum GNUNET_PSYC_MasterTransmitFlags flags)
{
  GNUNET_assert (NULL != mst);
  struct GNUNET_PSYC_Channel *ch = &mst->ch;
  if (GNUNET_NO != ch->in_transmit)
    return NULL;
  ch->in_transmit = GNUNET_YES;

  size_t size = strlen (method_name) + 1;
  struct GNUNET_PSYC_MessageMethod *pmeth;
  struct OperationHandle *op
    = GNUNET_malloc (sizeof (*op) + sizeof (*pmeth) + size);
  pmeth = (struct GNUNET_PSYC_MessageMethod *) &op[1];
  op->msg = (struct GNUNET_MessageHeader *) pmeth;

  pmeth->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_METHOD);
  pmeth->header.size = htons (sizeof (*pmeth) + size);
  pmeth->flags = htonl (flags);
  pmeth->mod_count = GNUNET_ntohll (GNUNET_ENV_environment_get_mod_count (env));
  memcpy (&pmeth[1], method_name, size);

  GNUNET_CONTAINER_DLL_insert_tail (ch->transmit_head, ch->transmit_tail, op);
  GNUNET_ENV_environment_iterate (env, send_modifier, mst);
  transmit_next (ch);

  mst->tmit = GNUNET_malloc (sizeof (*mst->tmit));
  mst->tmit->master = mst;
  mst->tmit->notify = notify;
  mst->tmit->notify_cls = notify_cls;
  mst->tmit->status = GNUNET_PSYC_DATA_CONT;
  return mst->tmit;
}


/**
 * Resume transmission to the channel.
 *
 * @param th Handle of the request that is being resumed.
 */
void
GNUNET_PSYC_master_transmit_resume (struct GNUNET_PSYC_MasterTransmitHandle *th)
{
  master_transmit_data (th->master);
}


/**
 * Abort transmission request to the channel.
 *
 * @param th Handle of the request that is being aborted.
 */
void
GNUNET_PSYC_master_transmit_cancel (struct GNUNET_PSYC_MasterTransmitHandle *th)
{
  struct GNUNET_PSYC_Master *mst = th->master;
  struct GNUNET_PSYC_Channel *ch = &mst->ch;
  if (GNUNET_NO != ch->in_transmit)
    return;


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
 * @param cfg Configuration to use.
 * @param channel_key ECC public key that identifies the channel we wish to join.
 * @param slave_key ECC private-public key pair that identifies the slave, and
 *        used by multicast to sign the join request and subsequent unicast
 *        requests sent to the master.
 * @param origin Peer identity of the origin.
 * @param relay_count Number of peers in the @a relays array.
 * @param relays Peer identities of members of the multicast group, which serve
 *        as relays and used to join the group at.
 * @param method Function to invoke on messages received from the channel,
 *        typically at least contains functions for @e join and @e part.
 * @param join_cb Function to invoke when a peer wants to join.
 * @param cls Closure for @a method_cb and @a join_cb.
 * @param method_name Method name for the join request.
 * @param env Environment containing transient variables for the request, or NULL.
 * @param data Payload for the join message.
 * @param data_size Number of bytes in @a data.
 * @return Handle for the slave, NULL on error.
 */
struct GNUNET_PSYC_Slave *
GNUNET_PSYC_slave_join (const struct GNUNET_CONFIGURATION_Handle *cfg,
                        const struct GNUNET_CRYPTO_EddsaPublicKey *channel_key,
                        const struct GNUNET_CRYPTO_EddsaPrivateKey *slave_key,
                        const struct GNUNET_PeerIdentity *origin,
                        uint32_t relay_count,
                        const struct GNUNET_PeerIdentity *relays,
                        GNUNET_PSYC_Method method,
                        GNUNET_PSYC_JoinCallback join_cb,
                        GNUNET_PSYC_SlaveJoinCallback slave_joined_cb,
                        void *cls,
                        const char *method_name,
                        const struct GNUNET_ENV_Environment *env,
                        const void *data,
                        uint16_t data_size)
{
  struct GNUNET_PSYC_Slave *slv = GNUNET_malloc (sizeof (*slv));
  struct GNUNET_PSYC_Channel *ch = &slv->ch;
  struct SlaveJoinRequest *req = GNUNET_malloc (sizeof (*req));

  req->header.size = htons (sizeof (*req)
                            + sizeof (*channel_key) + sizeof (*slave_key)
                            + relay_count * sizeof (*relays));
  req->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_SLAVE_JOIN);
  req->channel_key = *channel_key;
  req->slave_key = *slave_key;
  req->origin = *origin;
  req->relay_count = relay_count;
  memcpy (&req[1], relays, relay_count * sizeof (*relays));

  ch->cfg = cfg;
  ch->is_master = GNUNET_NO;
  ch->reconnect_msg = (struct GNUNET_MessageHeader *) req;
  ch->reconnect_delay = GNUNET_TIME_UNIT_ZERO;
  ch->reconnect_task = GNUNET_SCHEDULER_add_now (&reconnect, slv);

  return slv;
}


/**
 * Part a PSYC channel.
 *
 * Will terminate the connection to the PSYC service.  Polite clients should
 * first explicitly send a @e part request (via GNUNET_PSYC_slave_transmit()).
 *
 * @param slv Slave handle.
 */
void
GNUNET_PSYC_slave_part (struct GNUNET_PSYC_Slave *slv)
{
  disconnect (slv);
  GNUNET_free (slv);
}


/**
 * Request a message to be sent to the channel master.
 *
 * @param slave Slave handle.
 * @param method_name Which (PSYC) method should be invoked (on host).
 * @param env Environment containing transient variables for the message, or
 *            NULL.
 * @param notify Function to call when we are allowed to transmit (to get data).
 * @param notify_cls Closure for @a notify.
 * @param flags Flags for the message being transmitted.
 * @return Transmission handle, NULL on error (i.e. more than one request
 *         queued).
 */
struct GNUNET_PSYC_SlaveTransmitHandle *
GNUNET_PSYC_slave_transmit (struct GNUNET_PSYC_Slave *slave,
                            const char *method_name,
                            const struct GNUNET_ENV_Environment *env,
                            GNUNET_PSYC_SlaveTransmitNotify notify,
                            void *notify_cls,
                            enum GNUNET_PSYC_SlaveTransmitFlags flags)
{
  return NULL;
}


/**
 * Resume transmission to the master.
 *
 * @param th Handle of the request that is being resumed.
 */
void
GNUNET_PSYC_slave_transmit_resume (struct GNUNET_PSYC_MasterTransmitHandle *th)
{

}


/**
 * Abort transmission request to master.
 *
 * @param th Handle of the request that is being aborted.
 */
void
GNUNET_PSYC_slave_transmit_cancel (struct GNUNET_PSYC_SlaveTransmitHandle *th)
{

}


/**
 * Convert a channel @a master to a @e channel handle to access the @e channel
 * APIs.
 *
 * @param master Channel master handle.
 * @return Channel handle, valid for as long as @a master is valid.
 */
struct GNUNET_PSYC_Channel *
GNUNET_PSYC_master_get_channel (struct GNUNET_PSYC_Master *master)
{
  return (struct GNUNET_PSYC_Channel *) master;
}


/**
 * Convert @a slave to a @e channel handle to access the @e channel APIs.
 *
 * @param slave Slave handle.
 * @return Channel handle, valid for as long as @a slave is valid.
 */
struct GNUNET_PSYC_Channel *
GNUNET_PSYC_slave_get_channel (struct GNUNET_PSYC_Slave *slave)
{
  return (struct GNUNET_PSYC_Channel *) slave;
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
 * @param ch Channel handle.
 * @param slave_key Identity of channel slave to add.
 * @param announced_at ID of the message that announced the membership change.
 * @param effective_since Addition of slave is in effect since this message ID.
 */
void
GNUNET_PSYC_channel_slave_add (struct GNUNET_PSYC_Channel *ch,
                               const struct GNUNET_CRYPTO_EddsaPublicKey
                               *slave_key,
                               uint64_t announced_at,
                               uint64_t effective_since)
{
  struct ChannelSlaveAdd *slvadd;
  struct OperationHandle *op = GNUNET_malloc (sizeof (*op) + sizeof (*slvadd));
  slvadd = (struct ChannelSlaveAdd *) &op[1];
  op->msg = (struct GNUNET_MessageHeader *) slvadd;

  slvadd->header.type = GNUNET_MESSAGE_TYPE_PSYC_CHANNEL_SLAVE_ADD;
  slvadd->header.size = htons (sizeof (*slvadd));
  slvadd->announced_at = GNUNET_htonll (announced_at);
  slvadd->effective_since = GNUNET_htonll (effective_since);

  GNUNET_CONTAINER_DLL_insert_tail (ch->transmit_head, ch->transmit_tail, op);
  transmit_next (ch);
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
 * @param ch Channel handle.
 * @param slave_key Identity of channel slave to remove.
 * @param announced_at ID of the message that announced the membership change.
 */
void
GNUNET_PSYC_channel_slave_remove (struct GNUNET_PSYC_Channel *ch,
                                  const struct GNUNET_CRYPTO_EddsaPublicKey
                                  *slave_key,
                                  uint64_t announced_at)
{
  struct ChannelSlaveRemove *slvrm;
  struct OperationHandle *op = GNUNET_malloc (sizeof (*op) + sizeof (*slvrm));
  slvrm = (struct ChannelSlaveRemove *) &op[1];
  op->msg = (struct GNUNET_MessageHeader *) slvrm;

  slvrm->header.type = GNUNET_MESSAGE_TYPE_PSYC_CHANNEL_SLAVE_RM;
  slvrm->header.size = htons (sizeof (*slvrm));
  slvrm->announced_at = GNUNET_htonll (announced_at);

  GNUNET_CONTAINER_DLL_insert_tail (ch->transmit_head, ch->transmit_tail, op);
  transmit_next (ch);
}


/**
 * Request to be told the message history of the channel.
 *
 * Historic messages (but NOT the state at the time) will be replayed (given to
 * the normal method handlers) if available and if access is permitted.
 *
 * To get the latest message, use 0 for both the start and end message ID.
 *
 * @param ch Which channel should be replayed?
 * @param start_message_id Earliest interesting point in history.
 * @param end_message_id Last (exclusive) interesting point in history.
 * @param method Function to invoke on messages received from the story.
 * @param finish_cb Function to call when the requested story has been fully
 *        told (counting message IDs might not suffice, as some messages
 *        might be secret and thus the listener would not know the story is
 *        finished without being told explicitly)
{
  return NULL;
} once this function
 *        has been called, the client must not call
 *        GNUNET_PSYC_channel_story_tell_cancel() anymore.
 * @param cls Closure for the callbacks.
 * @return Handle to cancel story telling operation.
 */
struct GNUNET_PSYC_Story *
GNUNET_PSYC_channel_story_tell (struct GNUNET_PSYC_Channel *ch,
                                uint64_t start_message_id,
                                uint64_t end_message_id,
                                GNUNET_PSYC_Method method,
                                GNUNET_PSYC_FinishCallback *finish_cb,
                                void *cls)
{
  return NULL;
}


/**
 * Abort story telling.
 *
 * This function must not be called from within method handlers (as given to
 * GNUNET_PSYC_slave_join()) of the slave.
 *
 * @param story Story telling operation to stop.
 */
void
GNUNET_PSYC_channel_story_tell_cancel (struct GNUNET_PSYC_Story *story)
{

}


/**
 * Retrieve the best matching channel state variable.
 *
 * If the requested variable name is not present in the state, the nearest
 * less-specific name is matched; for example, requesting "_a_b" will match "_a"
 * if "_a_b" does not exist.
 *
 * @param channel Channel handle.
 * @param full_name Full name of the requested variable, the actual variable
 *        returned might have a shorter name..
 * @param cb Function called once when a matching state variable is found.
 *        Not called if there's no matching state variable.
 * @param cb_cls Closure for the callbacks.
 * @return Handle that can be used to cancel the query operation.
 */
struct GNUNET_PSYC_StateQuery *
GNUNET_PSYC_channel_state_get (struct GNUNET_PSYC_Channel *channel,
                               const char *full_name,
                               GNUNET_PSYC_StateCallback cb,
                               void *cb_cls)
{
  return NULL;
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
 * @param channel Channel handle.
 * @param name_prefix Prefix of the state variable name to match.
 * @param cb Function to call with the matching state variables.
 * @param cb_cls Closure for the callbacks.
 * @return Handle that can be used to cancel the query operation.
 */
struct GNUNET_PSYC_StateQuery *
GNUNET_PSYC_channel_state_get_prefix (struct GNUNET_PSYC_Channel *channel,
                                      const char *name_prefix,
                                      GNUNET_PSYC_StateCallback cb,
                                      void *cb_cls)
{
  return NULL;
}


/**
 * Cancel a state query operation.
 *
 * @param query Handle for the operation to cancel.
 */
void
GNUNET_PSYC_channel_state_get_cancel (struct GNUNET_PSYC_StateQuery *query)
{

}


/* end of psyc_api.c */
