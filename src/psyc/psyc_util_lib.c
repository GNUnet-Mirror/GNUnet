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
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

/**
 * @file psyc/psyc_util_lib.c
 * @brief PSYC utilities; receiving/transmitting/logging PSYC messages.
 * @author Gabor X Toth
 */

#include <inttypes.h>

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_env_lib.h"
#include "gnunet_psyc_service.h"
#include "gnunet_psyc_util_lib.h"

#define LOG(kind,...) GNUNET_log_from (kind, "psyc-util",__VA_ARGS__)


struct GNUNET_PSYC_TransmitHandle
{
  /**
   * Client connection to service.
   */
  struct GNUNET_CLIENT_MANAGER_Connection *client;

  /**
   * Message currently being received from the client.
   */
  struct GNUNET_MessageHeader *msg;

  /**
   * Callback to request next modifier from client.
   */
  GNUNET_PSYC_TransmitNotifyModifier notify_mod;

  /**
   * Closure for the notify callbacks.
   */
  void *notify_mod_cls;

  /**
   * Callback to request next data fragment from client.
   */
  GNUNET_PSYC_TransmitNotifyData notify_data;

  /**
   * Closure for the notify callbacks.
   */
  void *notify_data_cls;

  /**
   * Modifier of the environment that is currently being transmitted.
   */
  struct GNUNET_ENV_Modifier *mod;

  /**
   *
   */
  const char *mod_value;

  /**
   * Number of bytes remaining to be transmitted from the current modifier value.
   */
  uint32_t mod_value_remaining;

  /**
   * State of the current message being received from client.
   */
  enum GNUNET_PSYC_MessageState state;

  /**
   * Number of PSYC_TRANSMIT_ACK messages we are still waiting for.
   */
  uint8_t acks_pending;

  /**
   * Is transmission paused?
   */
  uint8_t paused;

  /**
   * Are we currently transmitting a message?
   */
  uint8_t in_transmit;
};



struct GNUNET_PSYC_ReceiveHandle
{
  /**
   * Message callback.
   */
  GNUNET_PSYC_MessageCallback message_cb;

  /**
   * Message part callback.
   */
  GNUNET_PSYC_MessagePartCallback message_part_cb;

  /**
   * Closure for the callbacks.
   */
  void *cb_cls;

  /**
   * ID of the message being received from the PSYC service.
   */
  uint64_t message_id;

  /**
   * Public key of the slave from which a message is being received.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey slave_key;

  /**
   * State of the currently being received message from the PSYC service.
   */
  enum GNUNET_PSYC_MessageState state;

  /**
   * Flags for the currently being received message from the PSYC service.
   */
  enum GNUNET_PSYC_MessageFlags flags;

  /**
   * Expected value size for the modifier being received from the PSYC service.
   */
  uint32_t mod_value_size_expected;

  /**
   * Actual value size for the modifier being received from the PSYC service.
   */
  uint32_t mod_value_size;
};


/**** Messages ****/


/**
 * Create a PSYC message.
 *
 * @param method_name
 *        PSYC method for the message.
 * @param env
 *        Environment for the message.
 * @param data
 *        Data payload for the message.
 * @param data_size
 *        Size of @a data.
 *
 * @return Message header with size information,
 *         followed by the message parts.
 */
struct GNUNET_PSYC_Message *
GNUNET_PSYC_message_create (const char *method_name,
                            const struct GNUNET_ENV_Environment *env,
                            const void *data,
                            size_t data_size)
{
  struct GNUNET_ENV_Modifier *mod = NULL;
  struct GNUNET_PSYC_MessageMethod *pmeth = NULL;
  struct GNUNET_PSYC_MessageModifier *pmod = NULL;
  struct GNUNET_MessageHeader *pmsg = NULL;
  uint16_t env_size = 0;
  if (NULL != env)
  {
    mod = GNUNET_ENV_environment_head (env);
    while (NULL != mod)
    {
      env_size += sizeof (*pmod) + strlen (mod->name) + 1 + mod->value_size;
      mod = mod->next;
    }
  }

  struct GNUNET_PSYC_Message *msg;
  uint16_t method_name_size = strlen (method_name) + 1;
  if (method_name_size == 1)
    return NULL;

  uint16_t msg_size = sizeof (*msg)			/* header */
    + sizeof (*pmeth) + method_name_size	        /* method */
    + env_size						/* modifiers */
    + ((0 < data_size) ? sizeof (*pmsg) + data_size : 0)/* data */
    + sizeof (*pmsg);					/* end of message */
  msg = GNUNET_malloc (msg_size);
  msg->header.size = htons (msg_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE); /* FIXME */

  pmeth = (struct GNUNET_PSYC_MessageMethod *) &msg[1];
  pmeth->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_METHOD);
  pmeth->header.size = htons (sizeof (*pmeth) + method_name_size);
  memcpy (&pmeth[1], method_name, method_name_size);

  uint16_t p = sizeof (*msg) + sizeof (*pmeth) + method_name_size;
  if (NULL != env)
  {
    mod = GNUNET_ENV_environment_head (env);
    while (NULL != mod)
    {
      uint16_t mod_name_size = strlen (mod->name) + 1;
      pmod = (struct GNUNET_PSYC_MessageModifier *) ((char *) msg + p);
      pmod->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MODIFIER);
      pmod->header.size = sizeof (*pmod) + mod_name_size + mod->value_size;
      p += pmod->header.size;
      pmod->header.size = htons (pmod->header.size);

      memcpy (&pmod[1], mod->name, mod_name_size);
      if (0 < mod->value_size)
        memcpy ((char *) &pmod[1] + mod_name_size, mod->value, mod->value_size);

      mod = mod->next;
    }
  }

  if (0 < data_size)
  {
    pmsg = (struct GNUNET_MessageHeader *) ((char *) msg + p);
    pmsg->size = sizeof (*pmsg) + data_size;
    p += pmsg->size;
    pmsg->size = htons (pmsg->size);
    pmsg->type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_DATA);
    memcpy (&pmsg[1], data, data_size);
  }

  pmsg = (struct GNUNET_MessageHeader *) ((char *) msg + p);
  pmsg->size = htons (sizeof (*pmsg));
  pmsg->type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_END);

  GNUNET_assert (p + sizeof (*pmsg) == msg_size);
  return msg;
}


void
GNUNET_PSYC_log_message (enum GNUNET_ErrorType kind,
                         const struct GNUNET_MessageHeader *msg)
{
  uint16_t size = ntohs (msg->size);
  uint16_t type = ntohs (msg->type);
  GNUNET_log (kind, "Message of type %d and size %u:\n", type, size);
  switch (type)
  {
  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE:
  {
    struct GNUNET_PSYC_MessageHeader *pmsg
      = (struct GNUNET_PSYC_MessageHeader *) msg;
    GNUNET_log (kind, "\tID: %" PRIu64 "\tflags: %x" PRIu32 "\n",
                GNUNET_ntohll (pmsg->message_id), ntohl (pmsg->flags));
    break;
  }
  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_METHOD:
  {
    struct GNUNET_PSYC_MessageMethod *meth
      = (struct GNUNET_PSYC_MessageMethod *) msg;
    GNUNET_log (kind, "\t%.*s\n", size - sizeof (*meth), &meth[1]);
    break;
  }
  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MODIFIER:
  {
    struct GNUNET_PSYC_MessageModifier *mod
      = (struct GNUNET_PSYC_MessageModifier *) msg;
    uint16_t name_size = ntohs (mod->name_size);
    char oper = ' ' < mod->oper ? mod->oper : ' ';
    GNUNET_log (kind, "\t%c%.*s\t%.*s\n", oper, name_size, &mod[1],
                size - sizeof (*mod) - name_size,
                ((char *) &mod[1]) + name_size);
    break;
  }
  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MOD_CONT:
  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_DATA:
    GNUNET_log (kind, "\t%.*s\n", size - sizeof (*msg), &msg[1]);
    break;
  }
}


/**** Transmitting messages ****/


/**
 * Create a transmission handle.
 */
struct GNUNET_PSYC_TransmitHandle *
GNUNET_PSYC_transmit_create (struct GNUNET_CLIENT_MANAGER_Connection *client)
{
  struct GNUNET_PSYC_TransmitHandle *tmit = GNUNET_malloc (sizeof (*tmit));
  tmit->client = client;
  return tmit;
}


/**
 * Destroy a transmission handle.
 */
void
GNUNET_PSYC_transmit_destroy (struct GNUNET_PSYC_TransmitHandle *tmit)
{
  GNUNET_free (tmit);
}


/**
 * Queue a message part for transmission.
 *
 * The message part is added to the current message buffer.
 * When this buffer is full, it is added to the transmission queue.
 *
 * @param tmit
 *        Transmission handle.
 * @param msg
 *        Message part, or NULL.
 * @param end
 *        End of message?
 *        #GNUNET_YES or #GNUNET_NO.
 */
static void
transmit_queue_insert (struct GNUNET_PSYC_TransmitHandle *tmit,
                       const struct GNUNET_MessageHeader *msg,
                       uint8_t end)
{
  uint16_t size = (NULL != msg) ? ntohs (msg->size) : 0;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Queueing message part of type %u and size %u (end: %u)).\n",
       ntohs (msg->type), size, end);

  if (NULL != tmit->msg)
  {
    if (NULL == msg
        || GNUNET_MULTICAST_FRAGMENT_MAX_PAYLOAD < tmit->msg->size + size)
    {
      /* End of message or buffer is full, add it to transmission queue
       * and start with empty buffer */
      tmit->msg->type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE);
      tmit->msg->size = htons (tmit->msg->size);
      GNUNET_CLIENT_MANAGER_transmit (tmit->client, tmit->msg);
      tmit->msg = NULL;
      tmit->acks_pending++;
    }
    else
    {
      /* Message fits in current buffer, append */
      tmit->msg = GNUNET_realloc (tmit->msg, tmit->msg->size + size);
      memcpy ((char *) tmit->msg + tmit->msg->size, msg, size);
      tmit->msg->size += size;
    }
  }

  if (NULL == tmit->msg && NULL != msg)
  {
    /* Empty buffer, copy over message. */
    tmit->msg = GNUNET_malloc (sizeof (*tmit->msg) + size);
    tmit->msg->size = sizeof (*tmit->msg) + size;
    memcpy (&tmit->msg[1], msg, size);
  }

  if (NULL != tmit->msg
      && (GNUNET_YES == end
          || (GNUNET_MULTICAST_FRAGMENT_MAX_PAYLOAD
              < tmit->msg->size + sizeof (struct GNUNET_MessageHeader))))
  {
    /* End of message or buffer is full, add it to transmission queue. */
    tmit->msg->type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE);
    tmit->msg->size = htons (tmit->msg->size);
    GNUNET_CLIENT_MANAGER_transmit (tmit->client, tmit->msg);
    tmit->msg = NULL;
    tmit->acks_pending++;
  }

  if (GNUNET_YES == end)
    tmit->in_transmit = GNUNET_NO;
}


/**
 * Request data from client to transmit.
 *
 * @param tmit  Transmission handle.
 */
static void
transmit_data (struct GNUNET_PSYC_TransmitHandle *tmit)
{
  uint16_t data_size = GNUNET_PSYC_DATA_MAX_PAYLOAD;
  char data[GNUNET_MULTICAST_FRAGMENT_MAX_PAYLOAD] = "";
  struct GNUNET_MessageHeader *msg = (struct GNUNET_MessageHeader *) data;
  msg->type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_DATA);

  int notify_ret = tmit->notify_data (tmit->notify_data_cls, &data_size, &msg[1]);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "transmit_data (ret: %d, size: %u): %.*s\n",
       notify_ret, data_size, data_size, &msg[1]);
  switch (notify_ret)
  {
  case GNUNET_NO:
    if (0 == data_size)
    {
      /* Transmission paused, nothing to send. */
      tmit->paused = GNUNET_YES;
      return;
    }
    break;

  case GNUNET_YES:
    tmit->state = GNUNET_PSYC_MESSAGE_STATE_END;
    break;

  default:
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "TransmitNotifyData callback returned error when requesting data.\n");

    tmit->state = GNUNET_PSYC_MESSAGE_STATE_CANCEL;
    msg->type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_CANCEL);
    msg->size = htons (sizeof (*msg));
    transmit_queue_insert (tmit, msg, GNUNET_YES);
    return;
  }

  if (0 < data_size)
  {
    GNUNET_assert (data_size <= GNUNET_PSYC_DATA_MAX_PAYLOAD);
    msg->size = htons (sizeof (*msg) + data_size);
    transmit_queue_insert (tmit, msg, !notify_ret);
  }

  /* End of message. */
  if (GNUNET_YES == notify_ret)
  {
    msg->type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_END);
    msg->size = htons (sizeof (*msg));
    transmit_queue_insert (tmit, msg, GNUNET_YES);
  }
}


/**
 * Request a modifier from a client to transmit.
 *
 * @param tmit  Transmission handle.
 */
static void
transmit_mod (struct GNUNET_PSYC_TransmitHandle *tmit)
{
  uint16_t max_data_size, data_size;
  char data[GNUNET_MULTICAST_FRAGMENT_MAX_PAYLOAD] = "";
  struct GNUNET_MessageHeader *msg = (struct GNUNET_MessageHeader *) data;
  int notify_ret;

  switch (tmit->state)
  {
  case GNUNET_PSYC_MESSAGE_STATE_MODIFIER:
  {
    struct GNUNET_PSYC_MessageModifier *mod
      = (struct GNUNET_PSYC_MessageModifier *) msg;
    max_data_size = data_size = GNUNET_PSYC_MODIFIER_MAX_PAYLOAD;
    msg->type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MODIFIER);
    msg->size = sizeof (struct GNUNET_PSYC_MessageModifier);
    notify_ret = tmit->notify_mod (tmit->notify_mod_cls, &data_size, &mod[1],
                                   &mod->oper, &mod->value_size);

    mod->name_size = strnlen ((char *) &mod[1], data_size) + 1;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "transmit_mod (ret: %d, size: %u + %u): %.*s\n",
         notify_ret, mod->name_size, mod->value_size, data_size, &mod[1]);
    if (mod->name_size < data_size)
    {
      tmit->mod_value_remaining
        = mod->value_size - (data_size - mod->name_size);
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
  case GNUNET_PSYC_MESSAGE_STATE_MOD_CONT:
  {
    max_data_size = data_size = GNUNET_PSYC_MOD_CONT_MAX_PAYLOAD;
    msg->type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MOD_CONT);
    msg->size = sizeof (struct GNUNET_MessageHeader);
    notify_ret = tmit->notify_mod (tmit->notify_mod_cls,
                                   &data_size, &msg[1], NULL, NULL);
    tmit->mod_value_remaining -= data_size;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "transmit_mod (ret: %d, size: %u): %.*s\n",
         notify_ret, data_size, data_size, &msg[1]);
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
      tmit->paused = GNUNET_YES;
      return;
    }
    tmit->state
      = (0 == tmit->mod_value_remaining)
      ? GNUNET_PSYC_MESSAGE_STATE_MODIFIER
      : GNUNET_PSYC_MESSAGE_STATE_MOD_CONT;
    break;

  case GNUNET_YES: /* End of modifiers. */
    GNUNET_assert (0 == tmit->mod_value_remaining);
    break;

  default:
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "TransmitNotifyModifier callback returned with error.\n");

    tmit->state = GNUNET_PSYC_MESSAGE_STATE_CANCEL;
    msg->type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_CANCEL);
    msg->size = htons (sizeof (*msg));

    transmit_queue_insert (tmit, msg, GNUNET_YES);
    return;
  }

  if (0 < data_size)
  {
    GNUNET_assert (data_size <= max_data_size);
    msg->size = htons (msg->size + data_size);
    transmit_queue_insert (tmit, msg, GNUNET_NO);
  }

  if (GNUNET_YES == notify_ret)
  {
    tmit->state = GNUNET_PSYC_MESSAGE_STATE_DATA;
    if (0 == tmit->acks_pending)
      transmit_data (tmit);
  }
  else
  {
    transmit_mod (tmit);
  }
}


int
transmit_notify_env (void *cls, uint16_t *data_size, void *data, uint8_t *oper,
                     uint32_t *full_value_size)

{
  struct GNUNET_PSYC_TransmitHandle *tmit = cls;
  uint16_t name_size = 0;
  size_t value_size = 0;
  const char *value = NULL;

  if (NULL != oper)
  { /* New modifier */
    if (NULL != tmit->mod)
      tmit->mod = tmit->mod->next;
    if (NULL == tmit->mod)
    { /* No more modifiers, continue with data */
      *data_size = 0;
      return GNUNET_YES;
    }

    GNUNET_assert (tmit->mod->value_size < UINT32_MAX);
    *full_value_size = tmit->mod->value_size;
    *oper = tmit->mod->oper;
    name_size = strlen (tmit->mod->name) + 1;

    if (name_size + tmit->mod->value_size <= *data_size)
    {
      *data_size = name_size + tmit->mod->value_size;
    }
    else
    {
      value_size = *data_size - name_size;
      tmit->mod_value = tmit->mod->value + value_size;
    }

    memcpy (data, tmit->mod->name, name_size);
    memcpy ((char *)data + name_size, tmit->mod->value, value_size);
    return GNUNET_NO;
  }
  else
  { /* Modifier continuation */
    GNUNET_assert (NULL != tmit->mod_value && 0 < tmit->mod_value_remaining);
    value = tmit->mod_value;
    if (tmit->mod_value_remaining <= *data_size)
    {
      value_size = tmit->mod_value_remaining;
      tmit->mod_value = NULL;
    }
    else
    {
      value_size = *data_size;
      tmit->mod_value += value_size;
    }

    if (*data_size < value_size)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Value in environment larger than buffer: %u < %zu\n",
           *data_size, value_size);
      *data_size = 0;
      return GNUNET_NO;
    }

    *data_size = value_size;
    memcpy (data, value, value_size);
    return (NULL == tmit->mod_value) ? GNUNET_YES : GNUNET_NO;
  }
}


/**
 * Transmit a message.
 *
 * @param tmit
 *        Transmission handle.
 * @param method_name
 *        Which method should be invoked.
 * @param env
 *        Environment for the message.
 *        Should stay available until the first call to notify_data.
 *        Can be NULL if there are no modifiers or @a notify_mod is
 *        provided instead.
 * @param notify_mod
 *        Function to call to obtain modifiers.
 *        Can be NULL if there are no modifiers or @a env is provided instead.
 * @param notify_data
 *        Function to call to obtain fragments of the data.
 * @param notify_cls
 *        Closure for @a notify_mod and @a notify_data.
 * @param flags
 *        Flags for the message being transmitted.
 *
 * @return #GNUNET_OK if the transmission was started.
 *         #GNUNET_SYSERR if another transmission is already going on.
 */
int
GNUNET_PSYC_transmit_message (struct GNUNET_PSYC_TransmitHandle *tmit,
                              const char *method_name,
                              const struct GNUNET_ENV_Environment *env,
                              GNUNET_PSYC_TransmitNotifyModifier notify_mod,
                              GNUNET_PSYC_TransmitNotifyData notify_data,
                              void *notify_cls,
                              uint32_t flags)
{
  if (GNUNET_NO != tmit->in_transmit)
    return GNUNET_SYSERR;
  tmit->in_transmit = GNUNET_YES;

  size_t size = strlen (method_name) + 1;
  struct GNUNET_PSYC_MessageMethod *pmeth;
  tmit->msg = GNUNET_malloc (sizeof (*tmit->msg) + sizeof (*pmeth) + size);
  tmit->msg->size = sizeof (*tmit->msg) + sizeof (*pmeth) + size;

  pmeth = (struct GNUNET_PSYC_MessageMethod *) &tmit->msg[1];
  pmeth->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_METHOD);
  pmeth->header.size = htons (sizeof (*pmeth) + size);
  pmeth->flags = htonl (flags);
  memcpy (&pmeth[1], method_name, size);

  tmit->state = GNUNET_PSYC_MESSAGE_STATE_MODIFIER;
  tmit->notify_data = notify_data;
  tmit->notify_data_cls = notify_cls;

  if (NULL != notify_mod)
  {
    tmit->notify_mod = notify_mod;
    tmit->notify_mod_cls = notify_cls;
  }
  else
  {
    tmit->notify_mod = &transmit_notify_env;
    tmit->notify_mod_cls = tmit;
    if (NULL != env)
    {
      struct GNUNET_ENV_Modifier mod = {};
      mod.next = GNUNET_ENV_environment_head (env);
      tmit->mod = &mod;
    }
    else
    {
      tmit->mod = NULL;
    }
  }

  transmit_mod (tmit);
  return GNUNET_OK;
}


/**
 * Resume transmission.
 *
 * @param tmit  Transmission handle.
 */
void
GNUNET_PSYC_transmit_resume (struct GNUNET_PSYC_TransmitHandle *tmit)
{
  if (0 == tmit->acks_pending)
  {
    tmit->paused = GNUNET_NO;
    transmit_data (tmit);
  }
}


/**
 * Abort transmission request.
 *
 * @param tmit  Transmission handle.
 */
void
GNUNET_PSYC_transmit_cancel (struct GNUNET_PSYC_TransmitHandle *tmit)
{
  if (GNUNET_NO == tmit->in_transmit)
    return;

  tmit->state = GNUNET_PSYC_MESSAGE_STATE_CANCEL;
  tmit->in_transmit = GNUNET_NO;
  tmit->paused = GNUNET_NO;

  /* FIXME */
  struct GNUNET_MessageHeader msg;
  msg.type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_DATA);
  msg.type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_CANCEL);
  msg.size = htons (sizeof (msg));
  transmit_queue_insert (tmit, &msg, GNUNET_YES);
}


/**
 * Got acknowledgement of a transmitted message part, continue transmission.
 *
 * @param tmit  Transmission handle.
 */
void
GNUNET_PSYC_transmit_got_ack (struct GNUNET_PSYC_TransmitHandle *tmit)
{
  if (0 == tmit->acks_pending)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "Ignoring extraneous message ACK\n");
    GNUNET_break (0);
    return;
  }
  tmit->acks_pending--;

  switch (tmit->state)
  {
  case GNUNET_PSYC_MESSAGE_STATE_MODIFIER:
  case GNUNET_PSYC_MESSAGE_STATE_MOD_CONT:
    if (GNUNET_NO == tmit->paused)
      transmit_mod (tmit);
    break;

  case GNUNET_PSYC_MESSAGE_STATE_DATA:
    if (GNUNET_NO == tmit->paused)
      transmit_data (tmit);
    break;

  case GNUNET_PSYC_MESSAGE_STATE_END:
  case GNUNET_PSYC_MESSAGE_STATE_CANCEL:
    break;

  default:
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Ignoring message ACK in state %u.\n", tmit->state);
  }
}


/**** Receiving messages ****/


/**
 * Create handle for receiving messages.
 */
struct GNUNET_PSYC_ReceiveHandle *
GNUNET_PSYC_receive_create (GNUNET_PSYC_MessageCallback message_cb,
                            GNUNET_PSYC_MessagePartCallback message_part_cb,
                            void *cb_cls)
{
  struct GNUNET_PSYC_ReceiveHandle *recv = GNUNET_malloc (sizeof (*recv));
  recv->message_cb = message_cb;
  recv->message_part_cb = message_part_cb;
  recv->cb_cls = cb_cls;
  return recv;
}


/**
 * Destroy handle for receiving messages.
 */
void
GNUNET_PSYC_receive_destroy (struct GNUNET_PSYC_ReceiveHandle *recv)
{
  GNUNET_free (recv);
}


/**
 * Reset stored data related to the last received message.
 */
void
GNUNET_PSYC_receive_reset (struct GNUNET_PSYC_ReceiveHandle *recv)
{
  recv->state = GNUNET_PSYC_MESSAGE_STATE_START;
  recv->flags = 0;
  recv->message_id = 0;
  recv->mod_value_size = 0;
  recv->mod_value_size_expected = 0;
}


static void
recv_error (struct GNUNET_PSYC_ReceiveHandle *recv)
{
  if (NULL != recv->message_part_cb)
    recv->message_part_cb (recv->cb_cls, recv->message_id, 0, recv->flags, NULL);

  if (NULL != recv->message_cb)
    recv->message_cb (recv->cb_cls, recv->message_id, recv->flags, NULL);

  GNUNET_PSYC_receive_reset (recv);
}


/**
 * Handle incoming PSYC message.
 *
 * @param recv  Receive handle.
 * @param msg   The message.
 *
 * @return #GNUNET_OK on success,
 *         #GNUNET_SYSERR on receive error.
 */
int
GNUNET_PSYC_receive_message (struct GNUNET_PSYC_ReceiveHandle *recv,
                             const struct GNUNET_PSYC_MessageHeader *msg)
{
  uint16_t size = ntohs (msg->header.size);
  uint32_t flags = ntohl (msg->flags);
  uint64_t message_id;

  GNUNET_PSYC_log_message (GNUNET_ERROR_TYPE_DEBUG,
                           (struct GNUNET_MessageHeader *) msg);

  if (GNUNET_PSYC_MESSAGE_STATE_START == recv->state)
  {
    recv->message_id = GNUNET_ntohll (msg->message_id);
    recv->flags = flags;
    recv->slave_key = msg->slave_key;
    recv->mod_value_size = 0;
    recv->mod_value_size_expected = 0;
  }
  else if (GNUNET_ntohll (msg->message_id) != recv->message_id)
  {
    // FIXME
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Unexpected message ID. Got: %" PRIu64 ", expected: %" PRIu64 "\n",
         GNUNET_ntohll (msg->message_id), recv->message_id);
    GNUNET_break_op (0);
    recv_error (recv);
    return GNUNET_SYSERR;
  }
  else if (flags != recv->flags)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Unexpected message flags. Got: %lu, expected: %lu\n",
         flags, recv->flags);
    GNUNET_break_op (0);
    recv_error (recv);
    return GNUNET_SYSERR;
  }
  message_id = recv->message_id;

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
      recv_error (recv);
      return GNUNET_SYSERR;
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
      recv_error (recv);
      return GNUNET_SYSERR;
    }

    if (! ((0 < size_eq && psize == size_eq)
           || (0 < size_min && size_min <= psize)))
    {
      GNUNET_break_op (0);
      recv_error (recv);
      return GNUNET_SYSERR;
    }

    switch (ptype)
    {
    case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_METHOD:
    {
      struct GNUNET_PSYC_MessageMethod *meth
        = (struct GNUNET_PSYC_MessageMethod *) pmsg;

      if (GNUNET_PSYC_MESSAGE_STATE_START != recv->state)
      {
        LOG (GNUNET_ERROR_TYPE_WARNING,
             "Dropping out of order message method (%u).\n",
             recv->state);
        /* It is normal to receive an incomplete message right after connecting,
         * but should not happen later.
         * FIXME: add a check for this condition.
         */
        GNUNET_break_op (0);
        recv_error (recv);
        return GNUNET_SYSERR;
      }

      if ('\0' != *((char *) meth + psize - 1))
      {
        LOG (GNUNET_ERROR_TYPE_WARNING,
             "Dropping message with malformed method. "
             "Message ID: %" PRIu64 "\n", recv->message_id);
        GNUNET_break_op (0);
        recv_error (recv);
        return GNUNET_SYSERR;
      }
      recv->state = GNUNET_PSYC_MESSAGE_STATE_METHOD;
      break;
    }
    case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MODIFIER:
    {
      if (!(GNUNET_PSYC_MESSAGE_STATE_METHOD == recv->state
            || GNUNET_PSYC_MESSAGE_STATE_MODIFIER == recv->state
            || GNUNET_PSYC_MESSAGE_STATE_MOD_CONT == recv->state))
      {
        LOG (GNUNET_ERROR_TYPE_WARNING,
             "Dropping out of order message modifier (%u).\n",
             recv->state);
        GNUNET_break_op (0);
        recv_error (recv);
        return GNUNET_SYSERR;
      }

      struct GNUNET_PSYC_MessageModifier *mod
        = (struct GNUNET_PSYC_MessageModifier *) pmsg;

      uint16_t name_size = ntohs (mod->name_size);
      recv->mod_value_size_expected = ntohl (mod->value_size);
      recv->mod_value_size = psize - sizeof (*mod) - name_size;

      if (psize < sizeof (*mod) + name_size
          || '\0' != *((char *) &mod[1] + name_size - 1)
          || recv->mod_value_size_expected < recv->mod_value_size)
      {
        LOG (GNUNET_ERROR_TYPE_WARNING, "Dropping malformed modifier.\n");
        GNUNET_break_op (0);
        recv_error (recv);
        return GNUNET_SYSERR;
      }
      recv->state = GNUNET_PSYC_MESSAGE_STATE_MODIFIER;
      break;
    }
    case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MOD_CONT:
    {
      recv->mod_value_size += psize - sizeof (*pmsg);

      if (!(GNUNET_PSYC_MESSAGE_STATE_MODIFIER == recv->state
            || GNUNET_PSYC_MESSAGE_STATE_MOD_CONT == recv->state)
          || recv->mod_value_size_expected < recv->mod_value_size)
      {
        LOG (GNUNET_ERROR_TYPE_WARNING,
             "Dropping out of order message modifier continuation "
             "!(%u == %u || %u == %u) || %lu < %lu.\n",
             GNUNET_PSYC_MESSAGE_STATE_MODIFIER, recv->state,
             GNUNET_PSYC_MESSAGE_STATE_MOD_CONT, recv->state,
             recv->mod_value_size_expected, recv->mod_value_size);
        GNUNET_break_op (0);
        recv_error (recv);
        return GNUNET_SYSERR;
      }
      break;
    }
    case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_DATA:
    {
      if (recv->state < GNUNET_PSYC_MESSAGE_STATE_METHOD
          || recv->mod_value_size_expected != recv->mod_value_size)
      {
        LOG (GNUNET_ERROR_TYPE_WARNING,
             "Dropping out of order message data fragment "
             "(%u < %u || %lu != %lu).\n",
             recv->state, GNUNET_PSYC_MESSAGE_STATE_METHOD,
             recv->mod_value_size_expected, recv->mod_value_size);

        GNUNET_break_op (0);
        recv_error (recv);
        return GNUNET_SYSERR;
      }
      recv->state = GNUNET_PSYC_MESSAGE_STATE_DATA;
      break;
    }
    }

    if (NULL != recv->message_part_cb)
      recv->message_part_cb (recv->cb_cls, recv->message_id, 0, // FIXME: data_offset
                             recv->flags, pmsg);

    switch (ptype)
    {
    case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_END:
    case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_CANCEL:
      GNUNET_PSYC_receive_reset (recv);
      break;
    }
  }

  if (NULL != recv->message_cb)
    recv->message_cb (recv->cb_cls, message_id, flags, msg);
  return GNUNET_OK;
}


/**
 * Check if @a data contains a series of valid message parts.
 *
 * @param      data_size    Size of @a data.
 * @param      data	    Data.
 * @param[out] first_ptype  Type of first message part.
 * @param[out] last_ptype   Type of last message part.
 *
 * @return Number of message parts found in @a data.
 *         or GNUNET_SYSERR if the message contains invalid parts.
 */
int
GNUNET_PSYC_receive_check_parts (uint16_t data_size, const char *data,
                                 uint16_t *first_ptype, uint16_t *last_ptype)
{
  const struct GNUNET_MessageHeader *pmsg;
  uint16_t parts = 0, ptype = 0, psize = 0, pos = 0;
  if (NULL != first_ptype)
    *first_ptype = 0;
  if (NULL != last_ptype)
    *last_ptype = 0;

  for (pos = 0; pos < data_size; pos += psize, parts++)
  {
    pmsg = (const struct GNUNET_MessageHeader *) (data + pos);
    GNUNET_PSYC_log_message (GNUNET_ERROR_TYPE_DEBUG, pmsg);
    psize = ntohs (pmsg->size);
    ptype = ntohs (pmsg->type);
    if (0 == parts && NULL != first_ptype)
      *first_ptype = ptype;
    if (NULL != last_ptype
        && *last_ptype < GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_END)
      *last_ptype = ptype;
    if (psize < sizeof (*pmsg)
        || pos + psize > data_size
        || ptype < GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_METHOD
        || GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_CANCEL < ptype)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Invalid message part of type %u and size %u.\n",
                  ptype, psize);
      return GNUNET_SYSERR;
    }
    /* FIXME: check message part order */
  }
  return parts;
}


struct ParseMessageClosure
{
  struct GNUNET_ENV_Environment *env;
  const char **method_name;
  const void **data;
  uint16_t *data_size;
  enum GNUNET_PSYC_MessageState msg_state;
};


static void
parse_message_part_cb (void *cls, uint64_t message_id, uint64_t data_offset,
                       uint32_t flags, const struct GNUNET_MessageHeader *msg)
{
  struct ParseMessageClosure *pmc = cls;
  if (NULL == msg)
  {
    pmc->msg_state = GNUNET_PSYC_MESSAGE_STATE_ERROR;
    return;
  }

  switch (ntohs (msg->type))
  {
  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_METHOD:
  {
    struct GNUNET_PSYC_MessageMethod *
      pmeth = (struct GNUNET_PSYC_MessageMethod *) msg;
    *pmc->method_name = (const char *) &pmeth[1];
    pmc->msg_state = GNUNET_PSYC_MESSAGE_STATE_METHOD;
    break;
  }

  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MODIFIER:
  {
    struct GNUNET_PSYC_MessageModifier *
      pmod = (struct GNUNET_PSYC_MessageModifier *) msg;

    const char *name = (const char *) &pmod[1];
    const void *value = name + pmod->name_size;
    GNUNET_ENV_environment_add (pmc->env, pmod->oper, name, value,
                                pmod->value_size);
    pmc->msg_state = GNUNET_PSYC_MESSAGE_STATE_MODIFIER;
    break;
  }

  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_DATA:
    *pmc->data = &msg[1];
    *pmc->data_size = ntohs (msg->size) - sizeof (*msg);
    pmc->msg_state = GNUNET_PSYC_MESSAGE_STATE_DATA;
    break;

  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_END:
    pmc->msg_state = GNUNET_PSYC_MESSAGE_STATE_END;
    break;

  default:
    pmc->msg_state = GNUNET_PSYC_MESSAGE_STATE_ERROR;
  }
}


/**
 * Parse PSYC message.
 *
 * @param msg
 *        The PSYC message to parse.
 * @param[out] method_name
 *        Pointer to the method name inside @a pmsg.
 * @param env
 *        The environment for the message with a list of modifiers.
 * @param[out] data
 *        Pointer to data inside @a pmsg.
 * @param[out] data_size
 *        Size of @data is written here.
 *
 * @return #GNUNET_OK on success,
 *         #GNUNET_SYSERR on parse error.
 */
int
GNUNET_PSYC_message_parse (const struct GNUNET_PSYC_Message *msg,
                           const char **method_name,
                           struct GNUNET_ENV_Environment *env,
                           const void **data,
                           uint16_t *data_size)
{
  struct ParseMessageClosure cls;
  cls.env = env;
  cls.method_name = method_name;
  cls.data = data;
  cls.data_size = data_size;

  uint16_t msg_size = ntohs (msg->header.size);
  struct GNUNET_PSYC_MessageHeader *
    pmsg = GNUNET_malloc (sizeof (*pmsg) + msg_size - sizeof (*msg));
  memcpy (&pmsg[1], &msg[1], msg_size - sizeof (*msg));

  struct GNUNET_PSYC_ReceiveHandle *
    recv = GNUNET_PSYC_receive_create (NULL, &parse_message_part_cb, &cls);
  GNUNET_PSYC_receive_message (recv, pmsg);
  GNUNET_PSYC_receive_destroy (recv);
  GNUNET_free (pmsg);

  return (GNUNET_PSYC_MESSAGE_STATE_END == cls.msg_state)
    ? GNUNET_OK
    : GNUNET_SYSERR;
}
