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

#include <inttypes.h>

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_env_lib.h"
#include "gnunet_multicast_service.h"
#include "gnunet_psyc_service.h"
#include "psyc.h"

#define LOG(kind,...) GNUNET_log_from (kind, "psyc-api",__VA_ARGS__)

struct OperationHandle
{
  struct OperationHandle *prev;
  struct OperationHandle *next;
  struct GNUNET_MessageHeader *msg;
};


/**
 * Handle for a pending PSYC transmission operation.
 */
struct GNUNET_PSYC_ChannelTransmitHandle
{
  struct GNUNET_PSYC_Channel *ch;
  GNUNET_PSYC_TransmitNotifyModifier notify_mod;
  GNUNET_PSYC_TransmitNotifyData notify_data;
  void *notify_cls;
  enum MessageState state;
};

/**
 * Handle to access PSYC channel operations for both the master and slaves.
 */
struct GNUNET_PSYC_Channel
{
  /**
   * Transmission handle;
   */
  struct GNUNET_PSYC_ChannelTransmitHandle tmit;

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
  struct OperationHandle *tmit_head;

  /**
   * Tail of operations to transmit.
   */
  struct OperationHandle *tmit_tail;

  /**
   * Message being transmitted to the PSYC service.
   */
  struct OperationHandle *tmit_msg;

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

  /**
   * Message part callback.
   */
  GNUNET_PSYC_MessageCallback message_cb;

  /**
   * Message part callback for historic message.
   */
  GNUNET_PSYC_MessageCallback hist_message_cb;

  /**
   * Join handler callback.
   */
  GNUNET_PSYC_JoinCallback join_cb;

  /**
   * Closure for @a message_cb and @a join_cb.
   */
  void *cb_cls;

  /**
   * ID of the message being received from the PSYC service.
   */
  uint64_t recv_message_id;

  /**
   * Public key of the slave from which a message is being received.
   */
  struct GNUNET_CRYPTO_EddsaPublicKey recv_slave_key;

  /**
   * State of the currently being received message from the PSYC service.
   */
  enum MessageState recv_state;

  /**
   * Flags for the currently being received message from the PSYC service.
   */
  enum GNUNET_PSYC_MessageFlags recv_flags;

  /**
   * Expected value size for the modifier being received from the PSYC service.
   */
  uint32_t recv_mod_value_size_expected;

  /**
   * Actual value size for the modifier being received from the PSYC service.
   */
  uint32_t recv_mod_value_size;

  /**
   * Is transmission paused?
   */
  uint8_t tmit_paused;

  /**
   * Are we still waiting for a PSYC_TRANSMIT_ACK?
   */
  uint8_t tmit_ack_pending;

  /**
   * Are we polling for incoming messages right now?
   */
  uint8_t in_receive;

  /**
   * Are we currently transmitting a message?
   */
  uint8_t in_transmit;

  /**
   * Is this a master or slave channel?
   */
  uint8_t is_master;
};


/**
 * Handle for the master of a PSYC channel.
 */
struct GNUNET_PSYC_Master
{
  struct GNUNET_PSYC_Channel ch;

  GNUNET_PSYC_MasterStartCallback start_cb;

  uint64_t max_message_id;
};


/**
 * Handle for a PSYC channel slave.
 */
struct GNUNET_PSYC_Slave
{
  struct GNUNET_PSYC_Channel ch;

  GNUNET_PSYC_SlaveJoinCallback join_cb;

  uint64_t max_message_id;
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


static void
reconnect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


static void
channel_transmit_data (struct GNUNET_PSYC_Channel *ch);


/**
 * Reschedule a connect attempt to the service.
 *
 * @param c channel to reconnect
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
 * @param ch PSYC channel handle
 */
static void
transmit_next (struct GNUNET_PSYC_Channel *ch);


/**
 * Reset data stored related to the last received message.
 */
static void
recv_reset (struct GNUNET_PSYC_Channel *ch)
{
  ch->recv_state = MSG_STATE_START;
  ch->recv_flags = 0;
  ch->recv_message_id = 0;
  //FIXME: ch->recv_slave_key = { 0 };
  ch->recv_mod_value_size = 0;
  ch->recv_mod_value_size_expected = 0;
}


static void
recv_error (struct GNUNET_PSYC_Channel *ch)
{
  GNUNET_PSYC_MessageCallback message_cb
    = ch->recv_flags & GNUNET_PSYC_MESSAGE_HISTORIC
    ? ch->hist_message_cb
    : ch->message_cb;

  if (NULL != message_cb)
    message_cb (ch->cb_cls, ch->recv_message_id, ch->recv_flags, NULL);

  recv_reset (ch);
}


/**
 * Queue a message part for transmission to the PSYC service.
 *
 * The message part is added to the current message buffer.
 * When this buffer is full, it is added to the transmission queue.
 *
 * @param ch Channel struct for the client.
 * @param msg Modifier message part, or NULL when there's no more modifiers.
 * @param end End of message.
 */
static void
queue_message (struct GNUNET_PSYC_Channel *ch,
               const struct GNUNET_MessageHeader *msg,
               uint8_t end)
{
  uint16_t size = msg ? ntohs (msg->size) : 0;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Queueing message of type %u and size %u (end: %u)).\n",
       ntohs (msg->type), size, end);

  struct OperationHandle *op = ch->tmit_msg;
  if (NULL != op)
  {
    if (NULL == msg
        || GNUNET_MULTICAST_FRAGMENT_MAX_PAYLOAD < op->msg->size + size)
    {
      /* End of message or buffer is full, add it to transmission queue
       * and start with empty buffer */
      op->msg->type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE);
      op->msg->size = htons (op->msg->size);
      GNUNET_CONTAINER_DLL_insert_tail (ch->tmit_head, ch->tmit_tail, op);
      ch->tmit_msg = op = NULL;
      ch->tmit_ack_pending++;
    }
    else
    {
      /* Message fits in current buffer, append */
      ch->tmit_msg = op
        = GNUNET_realloc (op, sizeof (*op) + op->msg->size + size);
      op->msg = (struct GNUNET_MessageHeader *) &op[1];
      memcpy ((char *) op->msg + op->msg->size, msg, size);
      op->msg->size += size;
    }
  }

  if (NULL == op && NULL != msg)
  {
    /* Empty buffer, copy over message. */
    ch->tmit_msg = op
      = GNUNET_malloc (sizeof (*op) + sizeof (*op->msg) + size);
    op->msg = (struct GNUNET_MessageHeader *) &op[1];
    op->msg->size = sizeof (*op->msg) + size;
    memcpy (&op->msg[1], msg, size);
  }

  if (NULL != op
      && (GNUNET_YES == end
          || (GNUNET_MULTICAST_FRAGMENT_MAX_PAYLOAD
              < op->msg->size + sizeof (struct GNUNET_MessageHeader))))
  {
    /* End of message or buffer is full, add it to transmission queue. */
    op->msg->type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE);
    op->msg->size = htons (op->msg->size);
    GNUNET_CONTAINER_DLL_insert_tail (ch->tmit_head, ch->tmit_tail, op);
    ch->tmit_msg = op = NULL;
    ch->tmit_ack_pending++;
  }

  if (GNUNET_YES == end)
    ch->in_transmit = GNUNET_NO;

  transmit_next (ch);
}


/**
 * Request a modifier from a client to transmit.
 *
 * @param mst Master handle.
 */
static void
channel_transmit_mod (struct GNUNET_PSYC_Channel *ch)
{
  uint16_t max_data_size, data_size;
  char data[GNUNET_MULTICAST_FRAGMENT_MAX_PAYLOAD] = "";
  struct GNUNET_MessageHeader *msg = (struct GNUNET_MessageHeader *) data;
  int notify_ret;

  switch (ch->tmit.state)
  {
  case MSG_STATE_MODIFIER:
  {
    struct GNUNET_PSYC_MessageModifier *mod
      = (struct GNUNET_PSYC_MessageModifier *) msg;
    max_data_size = data_size = GNUNET_PSYC_MODIFIER_MAX_PAYLOAD;
    msg->type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MODIFIER);
    msg->size = sizeof (struct GNUNET_PSYC_MessageModifier);
    notify_ret = ch->tmit.notify_mod (ch->tmit.notify_cls, &data_size, &mod[1],
                                      &mod->oper, &mod->value_size);
    mod->name_size = strnlen ((char *) &mod[1], data_size);
    if (mod->name_size < data_size)
    {
      mod->value_size = htonl (mod->value_size);
      mod->name_size = htons (mod->name_size);
    }
    else if (0 < data_size)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got invalid modifier name.\n");
      notify_ret = GNUNET_SYSERR;
    }
    break;
  }
  case MSG_STATE_MOD_CONT:
  {
    max_data_size = data_size = GNUNET_PSYC_MOD_CONT_MAX_PAYLOAD;
    msg->type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MOD_CONT);
    msg->size = sizeof (struct GNUNET_MessageHeader);
    notify_ret = ch->tmit.notify_mod (ch->tmit.notify_cls,
                                      &data_size, &msg[1], NULL, NULL);
    break;
  }
  default:
    GNUNET_assert (0);
  }

  switch (notify_ret)
  {
  case GNUNET_NO:
    if (0 == data_size)
    { /* Transmission paused, nothing to send. */
      ch->tmit_paused = GNUNET_YES;
      return;
    }
    ch->tmit.state = MSG_STATE_MOD_CONT;
    break;

  case GNUNET_YES:
    if (0 == data_size)
    {
      /* End of modifiers. */
      ch->tmit.state = MSG_STATE_DATA;
      if (0 == ch->tmit_ack_pending)
        channel_transmit_data (ch);

      return;
    }
    ch->tmit.state = MSG_STATE_MODIFIER;
    break;

  default:
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "MasterTransmitNotifyModifier returned error "
         "when requesting a modifier.\n");

    ch->tmit.state = MSG_STATE_CANCEL;
    msg->type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_CANCEL);
    msg->size = htons (sizeof (*msg));

    queue_message (ch, msg, GNUNET_YES);
    return;
  }

  if (0 < data_size)
  {
    GNUNET_assert (data_size <= max_data_size);
    msg->size = htons (msg->size + data_size);
    queue_message (ch, msg, GNUNET_NO);
  }

  channel_transmit_mod (ch);
}


/**
 * Request data from a client to transmit.
 *
 * @param mst Master handle.
 */
static void
channel_transmit_data (struct GNUNET_PSYC_Channel *ch)
{
  uint16_t data_size = GNUNET_PSYC_DATA_MAX_PAYLOAD;
  char data[GNUNET_MULTICAST_FRAGMENT_MAX_PAYLOAD] = "";
  struct GNUNET_MessageHeader *msg = (struct GNUNET_MessageHeader *) data;

  msg->type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_DATA);

  int notify_ret = ch->tmit.notify_data (ch->tmit.notify_cls,
                                         &data_size, &msg[1]);
  switch (notify_ret)
  {
  case GNUNET_NO:
    if (0 == data_size)
    {
      /* Transmission paused, nothing to send. */
      ch->tmit_paused = GNUNET_YES;
      return;
    }
    break;

  case GNUNET_YES:
    ch->tmit.state = MSG_STATE_END;
    break;

  default:
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "MasterTransmitNotify returned error when requesting data.\n");

    ch->tmit.state = MSG_STATE_CANCEL;
    msg->type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_CANCEL);
    msg->size = htons (sizeof (*msg));
    queue_message (ch, msg, GNUNET_YES);
    return;
  }

  if (0 < data_size)
  {
    GNUNET_assert (data_size <= GNUNET_PSYC_DATA_MAX_PAYLOAD);
    msg->size = htons (sizeof (*msg) + data_size);
    queue_message (ch, msg, !notify_ret);
  }

  /* End of message. */
  if (GNUNET_YES == notify_ret)
  {
    msg->type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_END);
    msg->size = htons (sizeof (*msg));
    queue_message (ch, msg, GNUNET_YES);
  }
}


/**
 * Send a message to a channel.
 *
 * @param ch Handle to the PSYC channel.
 * @param method_name Which method should be invoked.
 * @param notify_mod Function to call to obtain modifiers.
 * @param notify_data Function to call to obtain fragments of the data.
 * @param notify_cls Closure for @a notify_mod and @a notify_data.
 * @param flags Flags for the message being transmitted.
 * @return Transmission handle, NULL on error (i.e. more than one request queued).
 */
static struct GNUNET_PSYC_ChannelTransmitHandle *
channel_transmit (struct GNUNET_PSYC_Channel *ch,
                  const char *method_name,
                  GNUNET_PSYC_TransmitNotifyModifier notify_mod,
                  GNUNET_PSYC_TransmitNotifyData notify_data,
                  void *notify_cls,
                  uint32_t flags)
{
  if (GNUNET_NO != ch->in_transmit)
    return NULL;
  ch->in_transmit = GNUNET_YES;

  size_t size = strlen (method_name) + 1;
  struct GNUNET_PSYC_MessageMethod *pmeth;
  struct OperationHandle *op;

  ch->tmit_msg = op = GNUNET_malloc (sizeof (*op) + sizeof (*op->msg)
                                     + sizeof (*pmeth) + size);
  op->msg = (struct GNUNET_MessageHeader *) &op[1];
  op->msg->size = sizeof (*op->msg) + sizeof (*pmeth) + size;

  pmeth = (struct GNUNET_PSYC_MessageMethod *) &op->msg[1];
  pmeth->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_METHOD);
  pmeth->header.size = htons (sizeof (*pmeth) + size);
  pmeth->flags = htonl (flags);
  memcpy (&pmeth[1], method_name, size);

  ch->tmit.ch = ch;
  ch->tmit.notify_mod = notify_mod;
  ch->tmit.notify_data = notify_data;
  ch->tmit.notify_cls = notify_cls;
  ch->tmit.state = MSG_STATE_MODIFIER;

  channel_transmit_mod (ch);
  return &ch->tmit;
}


/**
 * Resume transmission to the channel.
 *
 * @param th Handle of the request that is being resumed.
 */
static void
channel_transmit_resume (struct GNUNET_PSYC_ChannelTransmitHandle *th)
{
  struct GNUNET_PSYC_Channel *ch = th->ch;
  if (0 == ch->tmit_ack_pending)
  {
    ch->tmit_paused = GNUNET_NO;
    channel_transmit_data (ch);
  }
}


/**
 * Abort transmission request to channel.
 *
 * @param th Handle of the request that is being aborted.
 */
static void
channel_transmit_cancel (struct GNUNET_PSYC_ChannelTransmitHandle *th)
{
  struct GNUNET_PSYC_Channel *ch = th->ch;
  if (GNUNET_NO == ch->in_transmit)
    return;
}


/**
 * Handle incoming message from the PSYC service.
 *
 * @param ch The channel the message is sent to.
 * @param pmsg The message.
 */
static void
handle_psyc_message (struct GNUNET_PSYC_Channel *ch,
                     const struct GNUNET_PSYC_MessageHeader *msg)
{
  uint16_t size = ntohs (msg->header.size);
  uint32_t flags = ntohl (msg->flags);

  GNUNET_PSYC_log_message (GNUNET_ERROR_TYPE_DEBUG,
                           (struct GNUNET_MessageHeader *) msg);

  if (MSG_STATE_START == ch->recv_state)
  {
    ch->recv_message_id = GNUNET_ntohll (msg->message_id);
    ch->recv_flags = flags;
    ch->recv_slave_key = msg->slave_key;
    ch->recv_mod_value_size = 0;
    ch->recv_mod_value_size_expected = 0;
  }
  else if (GNUNET_ntohll (msg->message_id) != ch->recv_message_id)
  {
    // FIXME
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Unexpected message ID. Got: %" PRIu64 ", expected: %" PRIu64 "\n",
         GNUNET_ntohll (msg->message_id), ch->recv_message_id);
    GNUNET_break_op (0);
    recv_error (ch);
    return;
  }
  else if (flags != ch->recv_flags)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Unexpected message flags. Got: %lu, expected: %lu\n",
         flags, ch->recv_flags);
    GNUNET_break_op (0);
    recv_error (ch);
    return;
  }

  uint16_t pos = 0, psize = 0, ptype, size_eq, size_min;

  for (pos = 0; sizeof (*msg) + pos < size; pos += psize)
  {
    const struct GNUNET_MessageHeader *pmsg
      = (const struct GNUNET_MessageHeader *) ((char *) &msg[1] + pos);
    psize = ntohs (pmsg->size);
    ptype = ntohs (pmsg->type);
    size_eq = size_min = 0;

    if (psize < sizeof (*pmsg) || sizeof (*msg) + pos + psize > size)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Dropping message of type %u with invalid size %u.\n",
                  ptype, psize);
      recv_error (ch);
      return;
    }

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received message part from PSYC.\n");
    GNUNET_PSYC_log_message (GNUNET_ERROR_TYPE_DEBUG, pmsg);

    switch (ptype)
    {
    case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_METHOD:
      size_min = sizeof (struct GNUNET_PSYC_MessageMethod);
      break;
    case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MODIFIER:
      size_min = sizeof (struct GNUNET_PSYC_MessageModifier);
      break;
    case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MOD_CONT:
    case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_DATA:
      size_min = sizeof (struct GNUNET_MessageHeader);
      break;
    case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_END:
    case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_CANCEL:
      size_eq = sizeof (struct GNUNET_MessageHeader);
      break;
    default:
      GNUNET_break_op (0);
      recv_error (ch);
      return;
    }

    if (! ((0 < size_eq && psize == size_eq)
           || (0 < size_min && size_min <= psize)))
    {
      GNUNET_break_op (0);
      recv_error (ch);
      return;
    }

    switch (ptype)
    {
    case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_METHOD:
    {
      struct GNUNET_PSYC_MessageMethod *meth
        = (struct GNUNET_PSYC_MessageMethod *) pmsg;

      if (MSG_STATE_START != ch->recv_state)
      {
        LOG (GNUNET_ERROR_TYPE_WARNING,
             "Dropping out of order message method (%u).\n",
             ch->recv_state);
        /* It is normal to receive an incomplete message right after connecting,
         * but should not happen later.
         * FIXME: add a check for this condition.
         */
        GNUNET_break_op (0);
        recv_error (ch);
        return;
      }

      if ('\0' != *((char *) meth + psize - 1))
      {
        LOG (GNUNET_ERROR_TYPE_WARNING,
             "Dropping message with malformed method. "
             "Message ID: %" PRIu64 "\n", ch->recv_message_id);
        GNUNET_break_op (0);
        recv_error (ch);
        return;
      }
      ch->recv_state = MSG_STATE_METHOD;
      break;
    }
    case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MODIFIER:
    {
      if (!(MSG_STATE_METHOD == ch->recv_state
            || MSG_STATE_MODIFIER == ch->recv_state
            || MSG_STATE_MOD_CONT == ch->recv_state))
      {
        LOG (GNUNET_ERROR_TYPE_WARNING,
             "Dropping out of order message modifier (%u).\n",
             ch->recv_state);
        GNUNET_break_op (0);
        recv_error (ch);
        return;
      }

      struct GNUNET_PSYC_MessageModifier *mod
        = (struct GNUNET_PSYC_MessageModifier *) pmsg;

      uint16_t name_size = ntohs (mod->name_size);
      ch->recv_mod_value_size_expected = ntohl (mod->value_size);
      ch->recv_mod_value_size = psize - sizeof (*mod) - name_size - 1;

      if (psize < sizeof (*mod) + name_size + 1
          || '\0' != *((char *) &mod[1] + name_size)
          || ch->recv_mod_value_size_expected < ch->recv_mod_value_size)
      {
        LOG (GNUNET_ERROR_TYPE_WARNING, "Dropping malformed modifier.\n");
        GNUNET_break_op (0);
        recv_error (ch);
        return;
      }
      ch->recv_state = MSG_STATE_MODIFIER;
      break;
    }
    case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MOD_CONT:
    {
      ch->recv_mod_value_size += psize - sizeof (*pmsg);

      if (!(MSG_STATE_MODIFIER == ch->recv_state
            || MSG_STATE_MOD_CONT == ch->recv_state)
          || ch->recv_mod_value_size_expected < ch->recv_mod_value_size)
      {
        LOG (GNUNET_ERROR_TYPE_WARNING,
             "Dropping out of order message modifier continuation "
             "!(%u == %u || %u == %u) || %lu < %lu.\n",
             MSG_STATE_MODIFIER, ch->recv_state,
             MSG_STATE_MOD_CONT, ch->recv_state,
             ch->recv_mod_value_size_expected, ch->recv_mod_value_size);
        GNUNET_break_op (0);
        recv_error (ch);
        return;
      }
      break;
    }
    case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_DATA:
    {
      if (ch->recv_state < MSG_STATE_METHOD
          || ch->recv_mod_value_size_expected != ch->recv_mod_value_size)
      {
        LOG (GNUNET_ERROR_TYPE_WARNING,
             "Dropping out of order message data fragment "
             "(%u < %u || %lu != %lu).\n",
             ch->recv_state, MSG_STATE_METHOD,
             ch->recv_mod_value_size_expected, ch->recv_mod_value_size);

        GNUNET_break_op (0);
        recv_error (ch);
        return;
      }
      ch->recv_state = MSG_STATE_DATA;
      break;
    }
    }

    GNUNET_PSYC_MessageCallback message_cb
      = ch->recv_flags & GNUNET_PSYC_MESSAGE_HISTORIC
      ? ch->hist_message_cb
      : ch->message_cb;

    if (NULL != message_cb)
      message_cb (ch->cb_cls, ch->recv_message_id, ch->recv_flags, pmsg);

    switch (ptype)
    {
    case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_END:
    case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_CANCEL:
      recv_reset (ch);
      break;
    }
  }
}


/**
 * Handle incoming message acknowledgement from the PSYC service.
 *
 * @param ch The channel the acknowledgement is sent to.
 */
static void
handle_psyc_message_ack (struct GNUNET_PSYC_Channel *ch)
{
  if (0 == ch->tmit_ack_pending)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "Ignoring extraneous message ACK\n");
    GNUNET_break (0);
    return;
  }
  ch->tmit_ack_pending--;

  switch (ch->tmit.state)
  {
  case MSG_STATE_MODIFIER:
  case MSG_STATE_MOD_CONT:
    if (GNUNET_NO == ch->tmit_paused)
      channel_transmit_mod (ch);
    break;

  case MSG_STATE_DATA:
    if (GNUNET_NO == ch->tmit_paused)
      channel_transmit_data (ch);
    break;

  case MSG_STATE_END:
  case MSG_STATE_CANCEL:
    break;

  default:
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Ignoring message ACK in state %u.\n", ch->tmit.state);
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
message_handler (void *cls,
                 const struct GNUNET_MessageHeader *msg)
{
  // YUCK! => please have disjoint message handlers...
  struct GNUNET_PSYC_Channel *ch = cls;
  struct GNUNET_PSYC_Master *mst = cls;
  struct GNUNET_PSYC_Slave *slv = cls;

  if (NULL == msg)
  {
    // timeout / disconnected from server, reconnect
    reschedule_connect (ch);
    return;
  }
  uint16_t size_eq = 0;
  uint16_t size_min = 0;
  uint16_t size = ntohs (msg->size);
  uint16_t type = ntohs (msg->type);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received message of type %d and size %u from PSYC service\n",
       type, size);

  switch (type)
  {
  case GNUNET_MESSAGE_TYPE_PSYC_MASTER_START_ACK:
  case GNUNET_MESSAGE_TYPE_PSYC_SLAVE_JOIN_ACK:
    size_eq = sizeof (struct CountersResult);
    break;
  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE:
    size_min = sizeof (struct GNUNET_PSYC_MessageHeader);
    break;
  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_ACK:
    size_eq = sizeof (struct GNUNET_MessageHeader);
    break;
  default:
    GNUNET_break_op (0);
    return;
  }

  if (! ((0 < size_eq && size == size_eq)
         || (0 < size_min && size_min <= size)))
  {
    GNUNET_break_op (0);
    return;
  }

  switch (type)
  {
  case GNUNET_MESSAGE_TYPE_PSYC_MASTER_START_ACK:
  {
    struct CountersResult *cres = (struct CountersResult *) msg;
    mst->max_message_id = GNUNET_ntohll (cres->max_message_id);
    if (NULL != mst->start_cb)
      mst->start_cb (ch->cb_cls, mst->max_message_id);
    break;
  }
  case GNUNET_MESSAGE_TYPE_PSYC_SLAVE_JOIN_ACK:
  {
    struct CountersResult *cres = (struct CountersResult *) msg;
    slv->max_message_id = GNUNET_ntohll (cres->max_message_id);
    if (NULL != slv->join_cb)
      slv->join_cb (ch->cb_cls, slv->max_message_id);
    break;
  }
  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_ACK:
  {
    handle_psyc_message_ack (ch);
    break;
  }

  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE:
    handle_psyc_message (ch, (const struct GNUNET_PSYC_MessageHeader *) msg);
    break;
  }

  if (NULL != ch->client)
  {
    GNUNET_CLIENT_receive (ch->client, &message_handler, ch,
                           GNUNET_TIME_UNIT_FOREVER_REL);
  }
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
  struct OperationHandle *op = ch->tmit_head;
  size_t ret;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "send_next_message()\n");
  ch->th = NULL;
  if (NULL == op->msg)
    return 0;
  ret = ntohs (op->msg->size);
  if (ret > size)
  {
    reschedule_connect (ch);
    return 0;
  }
  memcpy (buf, op->msg, ret);

  GNUNET_CONTAINER_DLL_remove (ch->tmit_head, ch->tmit_tail, op);
  GNUNET_free (op);

  if (NULL != ch->tmit_head)
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
 * @param ch PSYC handle.
 */
static void
transmit_next (struct GNUNET_PSYC_Channel *ch)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "transmit_next()\n");
  if (NULL != ch->th || NULL == ch->client)
    return;

  struct OperationHandle *op = ch->tmit_head;
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

  recv_reset (ch);
  ch->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connecting to PSYC service.\n");
  GNUNET_assert (NULL == ch->client);
  ch->client = GNUNET_CLIENT_connect ("psyc", ch->cfg);
  GNUNET_assert (NULL != ch->client);

  if (NULL == ch->tmit_head ||
      ch->tmit_head->msg->type != ch->reconnect_msg->type)
  {
    uint16_t reconn_size = ntohs (ch->reconnect_msg->size);
    struct OperationHandle *op = GNUNET_malloc (sizeof (*op) + reconn_size);
    memcpy (&op[1], ch->reconnect_msg, reconn_size);
    op->msg = (struct GNUNET_MessageHeader *) &op[1];
    GNUNET_CONTAINER_DLL_insert (ch->tmit_head, ch->tmit_tail, op);
  }
  transmit_next (ch);
}


/**
 * Disconnect from the PSYC service.
 *
 * @param c Channel handle to disconnect
 */
static void
disconnect (void *c)
{
  struct GNUNET_PSYC_Channel *ch = c;

  GNUNET_assert (NULL != ch);
  if (ch->tmit_head != ch->tmit_tail)
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
 * @param message_cb Function to invoke on message parts received from slaves.
 * @param join_cb Function to invoke when a peer wants to join.
 * @param master_started_cb Function to invoke after the channel master started.
 * @param cls Closure for @a master_started_cb and @a join_cb.
 * @return Handle for the channel master, NULL on error.
 */
struct GNUNET_PSYC_Master *
GNUNET_PSYC_master_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
                          const struct GNUNET_CRYPTO_EddsaPrivateKey *channel_key,
                          enum GNUNET_PSYC_Policy policy,
                          GNUNET_PSYC_MessageCallback message_cb,
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

  ch->message_cb = message_cb;
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
GNUNET_PSYC_master_stop (struct GNUNET_PSYC_Master *master)
{
  disconnect (master);
  GNUNET_free (master);
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


/**
 * Send a message to call a method to all members in the PSYC channel.
 *
 * @param master Handle to the PSYC channel.
 * @param method_name Which method should be invoked.
 * @param notify_mod Function to call to obtain modifiers.
 * @param notify_data Function to call to obtain fragments of the data.
 * @param notify_cls Closure for @a notify_mod and @a notify_data.
 * @param flags Flags for the message being transmitted.
 * @return Transmission handle, NULL on error (i.e. more than one request queued).
 */
struct GNUNET_PSYC_MasterTransmitHandle *
GNUNET_PSYC_master_transmit (struct GNUNET_PSYC_Master *master,
                             const char *method_name,
                             GNUNET_PSYC_TransmitNotifyModifier notify_mod,
                             GNUNET_PSYC_TransmitNotifyData notify_data,
                             void *notify_cls,
                             enum GNUNET_PSYC_MasterTransmitFlags flags)
{
  return (struct GNUNET_PSYC_MasterTransmitHandle *)
    channel_transmit (&master->ch, method_name, notify_mod, notify_data,
                      notify_cls, flags);
}


/**
 * Resume transmission to the channel.
 *
 * @param th Handle of the request that is being resumed.
 */
void
GNUNET_PSYC_master_transmit_resume (struct GNUNET_PSYC_MasterTransmitHandle *th)
{
  channel_transmit_resume ((struct GNUNET_PSYC_ChannelTransmitHandle *) th);
}


/**
 * Abort transmission request to the channel.
 *
 * @param th Handle of the request that is being aborted.
 */
void
GNUNET_PSYC_master_transmit_cancel (struct GNUNET_PSYC_MasterTransmitHandle *th)
{
  channel_transmit_cancel ((struct GNUNET_PSYC_ChannelTransmitHandle *) th);
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
 * @param message_cb Function to invoke on message parts received from the
 *        channel, typically at least contains method handlers for @e join and
 *        @e part.
 * @param join_cb function invoked once we have joined with the current
 *        message ID of the channel
 * @param slave_joined_cb Function to invoke when a peer wants to join.
 * @param cls Closure for @a message_cb and @a slave_joined_cb.
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
                        GNUNET_PSYC_MessageCallback message_cb,
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
  struct SlaveJoinRequest *req
    = GNUNET_malloc (sizeof (*req) + relay_count * sizeof (*relays));
  req->header.size = htons (sizeof (*req)
                            + relay_count * sizeof (*relays));
  req->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_SLAVE_JOIN);
  req->channel_key = *channel_key;
  req->slave_key = *slave_key;
  req->origin = *origin;
  req->relay_count = htonl (relay_count);
  memcpy (&req[1], relays, relay_count * sizeof (*relays));

  ch->message_cb = message_cb;
  ch->join_cb = join_cb;
  ch->cb_cls = cls;

  ch->cfg = cfg;
  ch->is_master = GNUNET_NO;
  ch->reconnect_msg = (struct GNUNET_MessageHeader *) req;
  ch->reconnect_delay = GNUNET_TIME_UNIT_ZERO;
  ch->reconnect_task = GNUNET_SCHEDULER_add_now (&reconnect, slv);

  slv->join_cb = slave_joined_cb;
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
GNUNET_PSYC_slave_part (struct GNUNET_PSYC_Slave *slave)
{
  disconnect (slave);
  GNUNET_free (slave);
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
 * @return Transmission handle, NULL on error (i.e. more than one request
 *         queued).
 */
struct GNUNET_PSYC_SlaveTransmitHandle *
GNUNET_PSYC_slave_transmit (struct GNUNET_PSYC_Slave *slave,
                            const char *method_name,
                            GNUNET_PSYC_TransmitNotifyModifier notify_mod,
                            GNUNET_PSYC_TransmitNotifyData notify_data,
                            void *notify_cls,
                            enum GNUNET_PSYC_SlaveTransmitFlags flags)
{
  return (struct GNUNET_PSYC_SlaveTransmitHandle *)
    channel_transmit (&slave->ch, method_name,
                      notify_mod, notify_data, notify_cls, flags);
}


/**
 * Resume transmission to the master.
 *
 * @param th Handle of the request that is being resumed.
 */
void
GNUNET_PSYC_slave_transmit_resume (struct GNUNET_PSYC_SlaveTransmitHandle *th)
{
  channel_transmit_resume ((struct GNUNET_PSYC_ChannelTransmitHandle *) th);
}


/**
 * Abort transmission request to master.
 *
 * @param th Handle of the request that is being aborted.
 */
void
GNUNET_PSYC_slave_transmit_cancel (struct GNUNET_PSYC_SlaveTransmitHandle *th)
{
  channel_transmit_cancel ((struct GNUNET_PSYC_ChannelTransmitHandle *) th);
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
  return &master->ch;
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
  return &slave->ch;
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
 * @param channel Channel handle.
 * @param slave_key Identity of channel slave to add.
 * @param announced_at ID of the message that announced the membership change.
 * @param effective_since Addition of slave is in effect since this message ID.
 */
void
GNUNET_PSYC_channel_slave_add (struct GNUNET_PSYC_Channel *channel,
                               const struct GNUNET_CRYPTO_EddsaPublicKey *slave_key,
                               uint64_t announced_at,
                               uint64_t effective_since)
{
  struct ChannelSlaveAdd *slvadd;
  struct OperationHandle *op = GNUNET_malloc (sizeof (*op) + sizeof (*slvadd));

  slvadd = (struct ChannelSlaveAdd *) &op[1];
  op->msg = (struct GNUNET_MessageHeader *) slvadd;

  slvadd->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_CHANNEL_SLAVE_ADD);
  slvadd->header.size = htons (sizeof (*slvadd));
  slvadd->announced_at = GNUNET_htonll (announced_at);
  slvadd->effective_since = GNUNET_htonll (effective_since);
  GNUNET_CONTAINER_DLL_insert_tail (channel->tmit_head,
                                    channel->tmit_tail,
                                    op);
  transmit_next (channel);
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
 * @param channel Channel handle.
 * @param slave_key Identity of channel slave to remove.
 * @param announced_at ID of the message that announced the membership change.
 */
void
GNUNET_PSYC_channel_slave_remove (struct GNUNET_PSYC_Channel *channel,
                                  const struct GNUNET_CRYPTO_EddsaPublicKey *slave_key,
                                  uint64_t announced_at)
{
  struct ChannelSlaveRemove *slvrm;
  struct OperationHandle *op = GNUNET_malloc (sizeof (*op) + sizeof (*slvrm));

  slvrm = (struct ChannelSlaveRemove *) &op[1];
  op->msg = (struct GNUNET_MessageHeader *) slvrm;
  slvrm->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_CHANNEL_SLAVE_RM);
  slvrm->header.size = htons (sizeof (*slvrm));
  slvrm->announced_at = GNUNET_htonll (announced_at);
  GNUNET_CONTAINER_DLL_insert_tail (channel->tmit_head,
                                    channel->tmit_tail,
                                    op);
  transmit_next (channel);
}


/**
 * Request to be told the message history of the channel.
 *
 * Historic messages (but NOT the state at the time) will be replayed (given to
 * the normal method handlers) if available and if access is permitted.
 *
 * To get the latest message, use 0 for both the start and end message ID.
 *
 * @param channel Which channel should be replayed?
 * @param start_message_id Earliest interesting point in history.
 * @param end_message_id Last (exclusive) interesting point in history.
 * @param message_cb Function to invoke on message parts received from the story.
 * @param finish_cb Function to call when the requested story has been fully
 *        told (counting message IDs might not suffice, as some messages
 *        might be secret and thus the listener would not know the story is
 *        finished without being told explicitly) once this function
 *        has been called, the client must not call
 *        GNUNET_PSYC_channel_story_tell_cancel() anymore.
 * @param cls Closure for the callbacks.
 * @return Handle to cancel story telling operation.
 */
struct GNUNET_PSYC_Story *
GNUNET_PSYC_channel_story_tell (struct GNUNET_PSYC_Channel *channel,
                                uint64_t start_message_id,
                                uint64_t end_message_id,
                                GNUNET_PSYC_MessageCallback message_cb,
                                GNUNET_PSYC_FinishCallback finish_cb,
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
