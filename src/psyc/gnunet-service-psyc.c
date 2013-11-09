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
 * @file psyc/gnunet-service-psyc.c
 * @brief PSYC service
 * @author Gabor X Toth
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_statistics_service.h"
#include "gnunet_multicast_service.h"
#include "gnunet_psycstore_service.h"
#include "gnunet_psyc_service.h"
#include "psyc.h"


/**
 * Handle to our current configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to the statistics service.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Notification context, simplifies client broadcasts.
 */
static struct GNUNET_SERVER_NotificationContext *nc;

/**
 * Handle to the PSYCstore.
 */
static struct GNUNET_PSYCSTORE_Handle *store;

/**
 * Channel's pub_key_hash -> struct Channel
 */
static struct GNUNET_CONTAINER_MultiHashMap *clients;

/**
 * Message in the transmission queue.
 */
struct TransmitMessage
{
  struct TransmitMessage *prev;
  struct TransmitMessage *next;

  char *buf;
  uint16_t size;
  /**
   * enum GNUNET_PSYC_DataStatus
   */
  uint8_t status;
};

/**
 * Common part of the client context for both a master and slave channel.
 */
struct Channel
{
  struct GNUNET_SERVER_Client *client;

  struct TransmitMessage *tmit_head;
  struct TransmitMessage *tmit_tail;

  GNUNET_SCHEDULER_TaskIdentifier tmit_task;
  uint32_t tmit_mod_count;
  uint32_t tmit_mod_recvd;
  /**
   * enum GNUNET_PSYC_DataStatus
   */
  uint8_t tmit_status;

  uint8_t in_transmit;
  uint8_t is_master;
  uint8_t disconnected;
};

/**
 * Client context for a channel master.
 */
struct Master
{
  struct Channel channel;
  struct GNUNET_CRYPTO_EddsaPrivateKey priv_key;
  struct GNUNET_CRYPTO_EddsaPublicKey pub_key;
  struct GNUNET_HashCode pub_key_hash;

  struct GNUNET_MULTICAST_Origin *origin;
  struct GNUNET_MULTICAST_OriginMessageHandle *tmit_handle;

  uint64_t max_message_id;
  uint64_t max_state_message_id;
  uint64_t max_group_generation;

  /**
   * enum GNUNET_PSYC_Policy
   */
  uint32_t policy;
};


/**
 * Client context for a channel slave.
 */
struct Slave
{
  struct Channel channel;
  struct GNUNET_CRYPTO_EddsaPrivateKey slave_key;
  struct GNUNET_CRYPTO_EddsaPublicKey chan_key;
  struct GNUNET_HashCode chan_key_hash;

  struct GNUNET_MULTICAST_Member *member;
  struct GNUNET_MULTICAST_MemberRequestHandle *tmit_handle;

  struct GNUNET_PeerIdentity origin;
  struct GNUNET_PeerIdentity *relays;
  struct GNUNET_MessageHeader *join_req;

  uint64_t max_message_id;
  uint64_t max_request_id;

  uint32_t relay_count;
};


static void
transmit_message (struct Channel *ch, struct GNUNET_TIME_Relative delay);


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != nc)
  {
    GNUNET_SERVER_notification_context_destroy (nc);
    nc = NULL;
  }
  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
    stats = NULL;
  }
}


static void
client_cleanup (struct Channel *ch)
{
  if (ch->is_master)
  {
    struct Master *mst = (struct Master *) ch;
    if (NULL != mst->origin)
      GNUNET_MULTICAST_origin_stop (mst->origin);
  }
  else
  {
    struct Slave *slv = (struct Slave *) ch;
    if (NULL != slv->join_req)
      GNUNET_free (slv->join_req);
    if (NULL != slv->relays)
      GNUNET_free (slv->relays);
    if (NULL != slv->member)
      GNUNET_MULTICAST_member_part (slv->member);
  }

  GNUNET_free (ch);
}

/**
 * Called whenever a client is disconnected.
 * Frees our resources associated with that client.
 *
 * @param cls Closure.
 * @param client Identification of the client.
 */
static void
client_disconnect (void *cls, struct GNUNET_SERVER_Client *client)
{
  if (NULL == client)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Client %p disconnected\n", client);

  struct Channel *ch
    = GNUNET_SERVER_client_get_user_context (client, struct Channel);
  if (NULL == ch)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "User context is NULL in client_disconnect()\n");
    GNUNET_break (0);
    return;
  }

  ch->disconnected = GNUNET_YES;

  /* Send pending messages to multicast before cleanup. */
  if (NULL != ch->tmit_head)
  {
    transmit_message (ch, GNUNET_TIME_UNIT_ZERO);
  }
  else
  {
    client_cleanup (ch);
  }
}

void
join_cb (void *cls, const struct GNUNET_CRYPTO_EddsaPublicKey *member_key,
         const struct GNUNET_MessageHeader *join_req,
         struct GNUNET_MULTICAST_JoinHandle *jh)
{

}

void
membership_test_cb (void *cls,
                    const struct GNUNET_CRYPTO_EddsaPublicKey *member_key,
                    uint64_t message_id, uint64_t group_generation,
                    struct GNUNET_MULTICAST_MembershipTestHandle *mth)
{

}

void
replay_fragment_cb (void *cls,
                    const struct GNUNET_CRYPTO_EddsaPublicKey *member_key,
                    uint64_t fragment_id, uint64_t flags,
                    struct GNUNET_MULTICAST_ReplayHandle *rh)
{

}

void
replay_message_cb (void *cls,
                   const struct GNUNET_CRYPTO_EddsaPublicKey *member_key,
                   uint64_t message_id,
                   uint64_t fragment_offset,
                   uint64_t flags,
                   struct GNUNET_MULTICAST_ReplayHandle *rh)
{

}

void
request_cb (void *cls, const struct GNUNET_CRYPTO_EddsaPublicKey *member_key,
            const struct GNUNET_MessageHeader *req,
            enum GNUNET_MULTICAST_MessageFlags flags)
{

}


void
fragment_store_result (void *cls, int64_t result, const char *err_msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "fragment_store() returned %l (%s)\n", result, err_msg);
}

/**
 * Send PSYC messages in an incoming multicast message to a client.
 */
int
send_to_client (void *cls, const struct GNUNET_HashCode *ch_key_hash, void *chan)
{
  const struct GNUNET_MULTICAST_MessageHeader *msg = cls;
  struct Channel *ch = chan;

  uint16_t size = ntohs (msg->header.size);
  uint16_t pos = 0;

  while (sizeof (*msg) + pos < size)
  {
    const struct GNUNET_MessageHeader *pmsg
      = (const struct GNUNET_MessageHeader *) ((char *) &msg[1] + pos);
    uint16_t psize = ntohs (pmsg->size);
    if (sizeof (*msg) + pos + psize > size)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Ignoring message of type %u with invalid size. "
                  "(%u + %u + %u > %u)\n", ntohs (pmsg->type),
                  sizeof (*msg), pos, psize, size);
      break;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending message of type %u and size %u to client.\n",
                ntohs (pmsg->type), psize);

    GNUNET_SERVER_notification_context_add (nc, ch->client);
    GNUNET_SERVER_notification_context_unicast (nc, ch->client, pmsg,
                                                GNUNET_NO);
    pos += psize;
  }
  return GNUNET_YES;
}


/**
 * Incoming message fragment from multicast.
 *
 * Store it using PSYCstore and send it to all clients of the channel.
 */
void
message_cb (void *cls, const struct GNUNET_MessageHeader *msg)
{
  uint16_t type = ntohs (msg->type);
  uint16_t size = ntohs (msg->size);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received message of type %u and size %u from multicast.\n",
              type, size);

  struct Channel *ch = cls;
  struct Master *mst = cls;
  struct Slave *slv = cls;

  struct GNUNET_CRYPTO_EddsaPublicKey *ch_key
    = ch->is_master ? &mst->pub_key : &slv->chan_key;
  struct GNUNET_HashCode *ch_key_hash
    = ch->is_master ? &mst->pub_key_hash : &slv->chan_key_hash;

  switch (type)
  {
  case GNUNET_MESSAGE_TYPE_MULTICAST_MESSAGE:
    GNUNET_PSYCSTORE_fragment_store (store, ch_key,
                                     (const struct
                                      GNUNET_MULTICAST_MessageHeader *) msg,
                                     0, NULL, NULL);
    GNUNET_CONTAINER_multihashmap_get_multiple (clients, ch_key_hash,
                                                send_to_client, (void *) msg);
    break;

  default:
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Ignoring unknown message of type %u and size %u.\n",
                type, size);
  }
}


/**
 * Response from PSYCstore with the current counter values for a channel master.
 */
void
master_counters_cb (void *cls, int result, uint64_t max_fragment_id,
                    uint64_t max_message_id, uint64_t max_group_generation,
                    uint64_t max_state_message_id)
{
  struct Master *mst = cls;
  struct Channel *ch = &mst->channel;
  struct CountersResult *res = GNUNET_malloc (sizeof (*res));
  res->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_MASTER_START_ACK);
  res->header.size = htons (sizeof (*res));
  res->result_code = htonl (result);
  res->max_message_id = GNUNET_htonll (max_message_id);

  if (GNUNET_OK == result || GNUNET_NO == result)
  {
    mst->max_message_id = max_message_id;
    mst->max_state_message_id = max_state_message_id;
    mst->max_group_generation = max_group_generation;
    mst->origin
      = GNUNET_MULTICAST_origin_start (cfg, &mst->priv_key,
                                       max_fragment_id + 1,
                                       join_cb, membership_test_cb,
                                       replay_fragment_cb, replay_message_cb,
                                       request_cb, message_cb, ch);
  }
  GNUNET_SERVER_notification_context_add (nc, ch->client);
  GNUNET_SERVER_notification_context_unicast (nc, ch->client, &res->header,
                                              GNUNET_NO);
  GNUNET_free (res);
}


/**
 * Response from PSYCstore with the current counter values for a channel slave.
 */
void
slave_counters_cb (void *cls, int result, uint64_t max_fragment_id,
                   uint64_t max_message_id, uint64_t max_group_generation,
                   uint64_t max_state_message_id)
{
  struct Slave *slv = cls;
  struct Channel *ch = &slv->channel;
  struct CountersResult *res = GNUNET_malloc (sizeof (*res));
  res->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_SLAVE_JOIN_ACK);
  res->header.size = htons (sizeof (*res));
  res->result_code = htonl (result);
  res->max_message_id = GNUNET_htonll (max_message_id);

  if (GNUNET_OK == result || GNUNET_NO == result)
  {
    slv->max_message_id = max_message_id;
    slv->member
      = GNUNET_MULTICAST_member_join (cfg, &slv->chan_key, &slv->slave_key,
                                      &slv->origin,
                                      slv->relay_count, slv->relays,
                                      slv->join_req, join_cb,
                                      membership_test_cb,
                                      replay_fragment_cb, replay_message_cb,
                                      message_cb, ch);
  }

  GNUNET_SERVER_notification_context_add (nc, ch->client);
  GNUNET_SERVER_notification_context_unicast (nc, ch->client, &res->header,
                                              GNUNET_NO);
  GNUNET_free (res);
}


/**
 * Handle a connecting client starting a channel master.
 */
static void
handle_master_start (void *cls, struct GNUNET_SERVER_Client *client,
                     const struct GNUNET_MessageHeader *msg)
{
  const struct MasterStartRequest *req
    = (const struct MasterStartRequest *) msg;
  struct Master *mst = GNUNET_new (struct Master);
  mst->channel.client = client;
  mst->channel.is_master = GNUNET_YES;
  mst->policy = ntohl (req->policy);
  mst->priv_key = req->channel_key;
  GNUNET_CRYPTO_eddsa_key_get_public (&mst->priv_key,
                                                  &mst->pub_key);
  GNUNET_CRYPTO_hash (&mst->pub_key, sizeof (mst->pub_key), &mst->pub_key_hash);

  GNUNET_PSYCSTORE_counters_get (store, &mst->pub_key,
                                 master_counters_cb, mst);

  GNUNET_SERVER_client_set_user_context (client, &mst->channel);
  GNUNET_CONTAINER_multihashmap_put (clients, &mst->pub_key_hash, mst,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handle a connecting client joining as a channel slave.
 */
static void
handle_slave_join (void *cls, struct GNUNET_SERVER_Client *client,
                   const struct GNUNET_MessageHeader *msg)
{
  const struct SlaveJoinRequest *req
    = (const struct SlaveJoinRequest *) msg;
  struct Slave *slv = GNUNET_new (struct Slave);
  slv->channel.client = client;
  slv->channel.is_master = GNUNET_NO;
  slv->slave_key = req->slave_key;
  slv->chan_key = req->channel_key;
  GNUNET_CRYPTO_hash (&slv->chan_key, sizeof (slv->chan_key),
                      &slv->chan_key_hash);
  slv->origin = req->origin;
  slv->relay_count = ntohl (req->relay_count);

  const struct GNUNET_PeerIdentity *relays
    = (const struct GNUNET_PeerIdentity *) &req[1];
  slv->relays
    = GNUNET_malloc (slv->relay_count * sizeof (struct GNUNET_PeerIdentity));
  uint32_t i;
  for (i = 0; i < slv->relay_count; i++)
    memcpy (&slv->relays[i], &relays[i], sizeof (*relays));

  GNUNET_PSYCSTORE_counters_get (store, &slv->chan_key,
                                 slave_counters_cb, slv);

  GNUNET_SERVER_client_set_user_context (client, &slv->channel);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Send transmission acknowledgement to a client.
 *
 * Sent after the last GNUNET_PSYC_MessageModifier and after each
 * GNUNET_PSYC_MessageData.
 *
 * @param ch The channel struct for the client.
 */
static void
send_transmit_ack (struct Channel *ch)
{
  struct TransmitAck *res = GNUNET_malloc (sizeof (*res));
  res->header.size = htons (sizeof (*res));
  res->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_TRANSMIT_ACK);

  res->buf_avail = GNUNET_MULTICAST_FRAGMENT_MAX_SIZE;
  struct TransmitMessage *tmit_msg = ch->tmit_tail;
  if (NULL != tmit_msg && GNUNET_PSYC_DATA_CONT == tmit_msg->status)
    res->buf_avail -= tmit_msg->size;
  res->buf_avail = htons (res->buf_avail);

  GNUNET_SERVER_notification_context_add (nc, ch->client);
  GNUNET_SERVER_notification_context_unicast (nc, ch->client, &res->header,
                                              GNUNET_NO);
  GNUNET_free (res);
}


/**
 * Callback for the transmit functions of multicast.
 */
static int
transmit_notify (void *cls, size_t *data_size, void *data)
{
  struct Channel *ch = cls;
  struct TransmitMessage *msg = ch->tmit_head;

  if (NULL == msg || *data_size < msg->size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "transmit_notify: nothing to send.\n");
    *data_size = 0;
    return GNUNET_NO;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "transmit_notify: sending %u bytes.\n", msg->size);

  *data_size = msg->size;
  memcpy (data, msg->buf, *data_size);

  GNUNET_CONTAINER_DLL_remove (ch->tmit_head, ch->tmit_tail, msg);
  GNUNET_free (msg);

  int ret = (GNUNET_YES == ch->in_transmit) ? GNUNET_NO : GNUNET_YES;

  if (0 == ch->tmit_task)
  {
    if (NULL != ch->tmit_head)
    {
      transmit_message (ch, GNUNET_TIME_UNIT_ZERO);
    }
    else if (ch->disconnected)
    {
      /* FIXME: handle partial message (when still in_transmit) */
      client_cleanup (ch);
    }
  }

  return ret;
}


/**
 * Transmit a message from a channel master to the multicast group.
 */
static void
master_transmit_message (void *cls,
                         const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "master_transmit_message()\n");
  struct Master *mst = cls;
  mst->channel.tmit_task = 0;
  if (NULL == mst->tmit_handle)
  {
    mst->tmit_handle
      = GNUNET_MULTICAST_origin_to_all (mst->origin, ++mst->max_message_id,
                                        mst->max_group_generation,
                                        transmit_notify, mst);
  }
  else
  {
    GNUNET_MULTICAST_origin_to_all_resume (mst->tmit_handle);
  }
}


/**
 * Transmit a message from a channel slave to the multicast group.
 */
static void
slave_transmit_message (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Slave *slv = cls;
  slv->channel.tmit_task = 0;
  if (NULL == slv->tmit_handle)
  {
    slv->tmit_handle
      = GNUNET_MULTICAST_member_to_origin(slv->member, ++slv->max_request_id,
                                          transmit_notify, slv);
  }
  else
  {
    GNUNET_MULTICAST_member_to_origin_resume (slv->tmit_handle);
  }
}


/**
 * Schedule message transmission from a channel to the multicast group.
 *
 * @param ch The channel.
 * @param delay Transmission delay.
 */
static void
transmit_message (struct Channel *ch, struct GNUNET_TIME_Relative delay)
{
  if (0 != ch->tmit_task)
    GNUNET_SCHEDULER_cancel (ch->tmit_task);

  ch->tmit_task
    = ch->is_master
    ? GNUNET_SCHEDULER_add_delayed (delay, master_transmit_message, ch)
    : GNUNET_SCHEDULER_add_delayed (delay, slave_transmit_message, ch);
}

/**
 * Queue incoming message parts from a client for transmission, and send them to
 * the multicast group when the buffer is full or reached the end of message.
 *
 * @param ch Channel struct for the client.
 * @param msg Message from the client.
 *
 * @return #GNUNET_OK on success, else #GNUNET_SYSERR.
 */
static int
queue_message (struct Channel *ch, const struct GNUNET_MessageHeader *msg)
{
  uint16_t size = ntohs (msg->size);
  struct GNUNET_TIME_Relative tmit_delay = GNUNET_TIME_UNIT_ZERO;
  struct TransmitMessage *tmit_msg = ch->tmit_tail;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Queueing message of type %u and size %u "
              "for transmission to multicast.\n",
              ntohs (msg->type), size);

  if (GNUNET_MULTICAST_FRAGMENT_MAX_SIZE < size)
    return GNUNET_SYSERR;

  if (NULL == tmit_msg
      || tmit_msg->status != GNUNET_PSYC_DATA_CONT
      || GNUNET_MULTICAST_FRAGMENT_MAX_SIZE < tmit_msg->size + size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Appending message qto new buffer.\n");
    /* Start filling up new buffer */
    tmit_msg = GNUNET_new (struct TransmitMessage);
    tmit_msg->buf = GNUNET_malloc (size);
    memcpy (tmit_msg->buf, msg, size);
    tmit_msg->size = size;
    tmit_msg->status = ch->tmit_status;
    GNUNET_CONTAINER_DLL_insert_tail (ch->tmit_head, ch->tmit_tail, tmit_msg);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Appending message to existing buffer.\n");
    /* Append to existing buffer */
    tmit_msg->buf = GNUNET_realloc (tmit_msg->buf, tmit_msg->size + size);
    memcpy (tmit_msg->buf + tmit_msg->size, msg, size);
    tmit_msg->size += size;
    tmit_msg->status = ch->tmit_status;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "tmit_size: %u\n", tmit_msg->size);

  /* Wait a bit for the remaining message parts from the client
     if there's still some space left in the buffer. */
  if (GNUNET_PSYC_DATA_CONT == tmit_msg->status
      && (tmit_msg->size + sizeof (struct GNUNET_PSYC_MessageData)
          < GNUNET_MULTICAST_FRAGMENT_MAX_SIZE))
    tmit_delay = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 2);

  transmit_message (ch, tmit_delay);

  return GNUNET_OK;
}

/**
 * Incoming method from a client.
 */
static void
handle_transmit_method (void *cls, struct GNUNET_SERVER_Client *client,
                        const struct GNUNET_MessageHeader *msg)
{
  const struct GNUNET_PSYC_MessageMethod *meth
    = (const struct GNUNET_PSYC_MessageMethod *) msg;
  struct Channel *ch
    = GNUNET_SERVER_client_get_user_context (client, struct Channel);
  GNUNET_assert (NULL != ch);

  if (GNUNET_NO != ch->in_transmit)
  {
    /* FIXME: already transmitting a message, send back error message. */
    return;
  }

  ch->in_transmit = GNUNET_YES;
  ch->tmit_mod_recvd = 0;
  ch->tmit_mod_count = ntohl (meth->mod_count);
  ch->tmit_status = GNUNET_PSYC_DATA_CONT;

  queue_message (ch, msg);

  if (0 == ch->tmit_mod_count)
    send_transmit_ack (ch);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
};


/**
 * Incoming modifier from a client.
 */
static void
handle_transmit_modifier (void *cls, struct GNUNET_SERVER_Client *client,
                          const struct GNUNET_MessageHeader *msg)
{
  /*
  const struct GNUNET_PSYC_MessageModifier *mod
    = (const struct GNUNET_PSYC_MessageModifier *) msg;
  */
  struct Channel *ch
    = GNUNET_SERVER_client_get_user_context (client, struct Channel);
  GNUNET_assert (NULL != ch);

  ch->tmit_mod_recvd++;
  queue_message (ch, msg);

  if (ch->tmit_mod_recvd == ch->tmit_mod_count)
    send_transmit_ack (ch);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
};


/**
 * Incoming data from a client.
 */
static void
handle_transmit_data (void *cls, struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *msg)
{
  const struct GNUNET_PSYC_MessageData *data
    = (const struct GNUNET_PSYC_MessageData *) msg;
  struct Channel *ch
    = GNUNET_SERVER_client_get_user_context (client, struct Channel);
  GNUNET_assert (NULL != ch);

  ch->tmit_status = ntohs (data->status);
  queue_message (ch, msg);
  send_transmit_ack (ch);

  if (GNUNET_PSYC_DATA_CONT != ch->tmit_status)
    ch->in_transmit = GNUNET_NO;

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
};


/**
 * Initialize the PSYC service.
 *
 * @param cls Closure.
 * @param server The initialized server.
 * @param c Configuration to use.
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    { &handle_master_start, NULL,
      GNUNET_MESSAGE_TYPE_PSYC_MASTER_START, 0 },

    { &handle_slave_join, NULL,
      GNUNET_MESSAGE_TYPE_PSYC_SLAVE_JOIN, 0 },

    { &handle_transmit_method, NULL,
      GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_METHOD, 0 },

    { &handle_transmit_modifier, NULL,
      GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MODIFIER, 0 },

    { &handle_transmit_data, NULL,
      GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_DATA, 0 },

    { NULL, NULL, 0, 0 }
  };

  cfg = c;
  store = GNUNET_PSYCSTORE_connect (cfg);
  stats = GNUNET_STATISTICS_create ("psyc", cfg);
  clients = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);
  nc = GNUNET_SERVER_notification_context_create (server, 1);
  GNUNET_SERVER_add_handlers (server, handlers);
  GNUNET_SERVER_disconnect_notify (server, &client_disconnect, NULL);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);
}


/**
 * The main function for the service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "psyc",
			      GNUNET_SERVICE_OPTION_NONE,
                              &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-psycstore.c */
