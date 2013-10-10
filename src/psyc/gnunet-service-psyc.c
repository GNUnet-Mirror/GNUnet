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
 * channel's pub_key_hash -> struct Channel
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

  char *tmit_buf;
  GNUNET_SCHEDULER_TaskIdentifier tmit_task;
  uint32_t tmit_mod_count;
  uint32_t tmit_mod_recvd;
  uint16_t tmit_size;
  uint8_t tmit_status;

  uint8_t in_transmit;
  uint8_t is_master;
};

/**
 * Client context for a channel master.
 */
struct Master
{
  struct Channel channel;
  struct GNUNET_CRYPTO_EccPrivateKey priv_key;
  struct GNUNET_CRYPTO_EccPublicSignKey pub_key;
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
  struct GNUNET_CRYPTO_EccPrivateKey slave_key;
  struct GNUNET_CRYPTO_EccPublicSignKey chan_key;
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

  if (NULL != ch->tmit_buf)
  {
    GNUNET_free (ch->tmit_buf);
    ch->tmit_buf = NULL;
  }

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

void
join_cb (void *cls, const struct GNUNET_CRYPTO_EccPublicSignKey *member_key,
         const struct GNUNET_MessageHeader *join_req,
         struct GNUNET_MULTICAST_JoinHandle *jh)
{

}

void
membership_test_cb (void *cls,
                    const struct GNUNET_CRYPTO_EccPublicSignKey *member_key,
                    uint64_t message_id, uint64_t group_generation,
                    struct GNUNET_MULTICAST_MembershipTestHandle *mth)
{

}

void
replay_fragment_cb (void *cls,
                    const struct GNUNET_CRYPTO_EccPublicSignKey *member_key,
                    uint64_t fragment_id, uint64_t flags,
                    struct GNUNET_MULTICAST_ReplayHandle *rh)
{

}

void
replay_message_cb (void *cls,
                   const struct GNUNET_CRYPTO_EccPublicSignKey *member_key,
                   uint64_t message_id,
                   uint64_t fragment_offset,
                   uint64_t flags,
                   struct GNUNET_MULTICAST_ReplayHandle *rh)
{

}

void
request_cb (void *cls, const struct GNUNET_CRYPTO_EccPublicSignKey *member_key,
            const struct GNUNET_MessageHeader *req,
            enum GNUNET_MULTICAST_MessageFlags flags)
{

}

void
message_cb (void *cls, const struct GNUNET_MessageHeader *msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received message of type %u from multicast.\n",
              ntohs (msg->type));
}

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
  GNUNET_CRYPTO_ecc_key_get_public_for_signature (&mst->priv_key,
                                                  &mst->pub_key);
  GNUNET_CRYPTO_hash (&mst->pub_key, sizeof (mst->pub_key), &mst->pub_key_hash);

  GNUNET_PSYCSTORE_counters_get (store, &mst->pub_key,
                                 master_counters_cb, mst);

  GNUNET_SERVER_client_set_user_context (client, &mst->channel);
  GNUNET_CONTAINER_multihashmap_put (clients, &mst->pub_key_hash, mst,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


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


static void
send_transmit_ack (struct Channel *ch)
{
  struct TransmitAck *res = GNUNET_malloc (sizeof (*res));
  res->header.size = htons (sizeof (*res));
  res->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_TRANSMIT_ACK);
  res->buf_avail = htons (GNUNET_MULTICAST_FRAGMENT_MAX_SIZE - ch->tmit_size);

  GNUNET_SERVER_notification_context_add (nc, ch->client);
  GNUNET_SERVER_notification_context_unicast (nc, ch->client, &res->header,
                                              GNUNET_NO);
  GNUNET_free (res);
}


static int
transmit_notify (void *cls, size_t *data_size, void *data)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "transmit_notify()\n");
  struct Channel *ch = cls;
  struct TransmitMessage *msg = ch->tmit_head;

  if (NULL == msg || *data_size < ntohs (msg->size))
  {
    *data_size = 0;
    return GNUNET_NO;
  }

  *data_size = ntohs (msg->size);
  memcpy (data, msg->buf, *data_size);

  GNUNET_free (ch->tmit_buf);
  ch->tmit_buf = NULL;
  GNUNET_CONTAINER_DLL_remove (ch->tmit_head, ch->tmit_tail, msg);

  return (GNUNET_YES == ch->in_transmit) ? GNUNET_NO : GNUNET_YES;
}


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


static int
buffer_message (struct Channel *ch, const struct GNUNET_MessageHeader *msg)
{
  uint16_t size = ntohs (msg->size);
  struct GNUNET_TIME_Relative tmit_delay = GNUNET_TIME_UNIT_ZERO;

  if (GNUNET_MULTICAST_FRAGMENT_MAX_SIZE < size)
    return GNUNET_SYSERR;

  if (0 == ch->tmit_size)
  {
    ch->tmit_buf = GNUNET_malloc (size);
    memcpy (ch->tmit_buf, msg, size);
    ch->tmit_size = size;
  }
  else if (GNUNET_MULTICAST_FRAGMENT_MAX_SIZE <= ch->tmit_size + size)
  {
    ch->tmit_buf = GNUNET_realloc (ch->tmit_buf, ch->tmit_size + size);
    memcpy (ch->tmit_buf + ch->tmit_size, msg, size);
    ch->tmit_size += size;
  }

  if (GNUNET_MULTICAST_FRAGMENT_MAX_SIZE
      < ch->tmit_size + sizeof (struct GNUNET_PSYC_MessageData))
  {
    struct TransmitMessage *tmit_msg = GNUNET_new (struct TransmitMessage);
    tmit_msg->buf = (char *) msg;
    tmit_msg->size = size;
    tmit_msg->status = ch->tmit_status;
    GNUNET_CONTAINER_DLL_insert_tail (ch->tmit_head, ch->tmit_tail, tmit_msg);
    tmit_delay = GNUNET_TIME_UNIT_ZERO;
  }

  if (0 != ch->tmit_task)
    GNUNET_SCHEDULER_cancel (ch->tmit_task);

  ch->tmit_task
    = ch->is_master
    ? GNUNET_SCHEDULER_add_delayed (tmit_delay, master_transmit_message, ch)
    : GNUNET_SCHEDULER_add_delayed (tmit_delay, slave_transmit_message, ch);

  return GNUNET_OK;
}

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
    // FIXME: already transmitting a message, send back error message.
    return;
  }

  ch->in_transmit = GNUNET_YES;
  ch->tmit_buf = NULL;
  ch->tmit_size = 0;
  ch->tmit_mod_recvd = 0;
  ch->tmit_mod_count = ntohl (meth->mod_count);
  ch->tmit_status = GNUNET_PSYC_DATA_CONT;

  buffer_message (ch, msg);

  if (0 == ch->tmit_mod_count)
    send_transmit_ack (ch);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
};


static void
handle_transmit_modifier (void *cls, struct GNUNET_SERVER_Client *client,
                          const struct GNUNET_MessageHeader *msg)
{
  const struct GNUNET_PSYC_MessageModifier *mod
    = (const struct GNUNET_PSYC_MessageModifier *) msg;
  struct Channel *ch
    = GNUNET_SERVER_client_get_user_context (client, struct Channel);
  GNUNET_assert (NULL != ch);

  ch->tmit_mod_recvd++;
  buffer_message (ch, msg);

  if (ch->tmit_mod_recvd == ch->tmit_mod_count)
    send_transmit_ack (ch);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
};


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
  buffer_message (ch, msg);
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
