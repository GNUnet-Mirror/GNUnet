/*
 * This file is part of GNUnet
 * Copyright (C) 2013 GNUnet e.V.
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
 * @file psyc/gnunet-service-psyc.c
 * @brief PSYC service
 * @author Gabor X Toth
 */

#include <inttypes.h>

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_statistics_service.h"
#include "gnunet_multicast_service.h"
#include "gnunet_psycstore_service.h"
#include "gnunet_psyc_service.h"
#include "gnunet_psyc_util_lib.h"
#include "psyc.h"


/**
 * Handle to our current configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Service handle.
 */
struct GNUNET_SERVICE_Handle *service;

/**
 * Handle to the statistics service.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Handle to the PSYCstore.
 */
static struct GNUNET_PSYCSTORE_Handle *store;

/**
 * All connected masters.
 * Channel's pub_key_hash -> struct Master
 */
static struct GNUNET_CONTAINER_MultiHashMap *masters;

/**
 * All connected slaves.
 * Channel's pub_key_hash -> struct Slave
 */
static struct GNUNET_CONTAINER_MultiHashMap *slaves;

/**
 * Connected slaves per channel.
 * Channel's pub_key_hash -> Slave's pub_key -> struct Slave
 */
static struct GNUNET_CONTAINER_MultiHashMap *channel_slaves;


/**
 * Message in the transmission queue.
 */
struct TransmitMessage
{
  struct TransmitMessage *prev;
  struct TransmitMessage *next;

  struct GNUNET_SERVICE_Client *client;

  /**
   * ID assigned to the message.
   */
  uint64_t id;

  /**
   * Size of message.
   */
  uint16_t size;

  /**
   * Type of first message part.
   */
  uint16_t first_ptype;

  /**
   * Type of last message part.
   */
  uint16_t last_ptype;

  /* Followed by message */
};


/**
 * Cache for received message fragments.
 * Message fragments are only sent to clients after all modifiers arrived.
 *
 * chan_key -> MultiHashMap chan_msgs
 */
static struct GNUNET_CONTAINER_MultiHashMap *recv_cache;


/**
 * Entry in the chan_msgs hashmap of @a recv_cache:
 * fragment_id -> RecvCacheEntry
 */
struct RecvCacheEntry
{
  struct GNUNET_MULTICAST_MessageHeader *mmsg;
  uint16_t ref_count;
};


/**
 * Entry in the @a recv_frags hash map of a @a Channel.
 * message_id -> FragmentQueue
 */
struct FragmentQueue
{
  /**
   * Fragment IDs stored in @a recv_cache.
   */
  struct GNUNET_CONTAINER_Heap *fragments;

  /**
   * Total size of received fragments.
   */
  uint64_t size;

  /**
   * Total size of received header fragments (METHOD & MODIFIERs)
   */
  uint64_t header_size;

  /**
   * The @a state_delta field from struct GNUNET_PSYC_MessageMethod.
   */
  uint64_t state_delta;

  /**
   * The @a flags field from struct GNUNET_PSYC_MessageMethod.
   */
  uint32_t flags;

  /**
   * Receive state of message.
   *
   * @see MessageFragmentState
   */
  uint8_t state;

  /**
   * Whether the state is already modified in PSYCstore.
   */
  uint8_t state_is_modified;

  /**
   * Is the message queued for delivery to the client?
   * i.e. added to the recv_msgs queue
   */
  uint8_t is_queued;
};


/**
 * List of connected clients.
 */
struct ClientList
{
  struct ClientList *prev;
  struct ClientList *next;

  struct GNUNET_SERVICE_Client *client;
};


struct Operation
{
  struct Operation *prev;
  struct Operation *next;

  struct GNUNET_SERVICE_Client *client;
  struct Channel *channel;
  uint64_t op_id;
  uint32_t flags;
};


/**
 * Common part of the client context for both a channel master and slave.
 */
struct Channel
{
  struct ClientList *clients_head;
  struct ClientList *clients_tail;

  struct Operation *op_head;
  struct Operation *op_tail;

  struct TransmitMessage *tmit_head;
  struct TransmitMessage *tmit_tail;

  /**
   * Current PSYCstore operation.
   */
  struct GNUNET_PSYCSTORE_OperationHandle *store_op;

  /**
   * Received fragments not yet sent to the client.
   * message_id -> FragmentQueue
   */
  struct GNUNET_CONTAINER_MultiHashMap *recv_frags;

  /**
   * Received message IDs not yet sent to the client.
   */
  struct GNUNET_CONTAINER_Heap *recv_msgs;

  /**
   * Public key of the channel.
   */
  struct GNUNET_CRYPTO_EddsaPublicKey pub_key;

  /**
   * Hash of @a pub_key.
   */
  struct GNUNET_HashCode pub_key_hash;

  /**
   * Last message ID sent to the client.
   * 0 if there is no such message.
   */
  uint64_t max_message_id;

  /**
   * ID of the last stateful message, where the state operations has been
   * processed and saved to PSYCstore and which has been sent to the client.
   * 0 if there is no such message.
   */
  uint64_t max_state_message_id;

  /**
   * Expected value size for the modifier being received from the PSYC service.
   */
  uint32_t tmit_mod_value_size_expected;

  /**
   * Actual value size for the modifier being received from the PSYC service.
   */
  uint32_t tmit_mod_value_size;

  /**
   * Is this channel ready to receive messages from client?
   * #GNUNET_YES or #GNUNET_NO
   */
  uint8_t is_ready;

  /**
   * Is the client disconnected?
   * #GNUNET_YES or #GNUNET_NO
   */
  uint8_t is_disconnected;

  /**
   * Is this a channel master (#GNUNET_YES), or slave (#GNUNET_NO)?
   */
  uint8_t is_master;

  union {
    struct Master *master;
    struct Slave *slave;
  };
};


/**
 * Client context for a channel master.
 */
struct Master
{
  /**
   * Channel struct common for Master and Slave
   */
  struct Channel channel;

  /**
   * Private key of the channel.
   */
  struct GNUNET_CRYPTO_EddsaPrivateKey priv_key;

  /**
   * Handle for the multicast origin.
   */
  struct GNUNET_MULTICAST_Origin *origin;

  /**
   * Transmit handle for multicast.
   */
  struct GNUNET_MULTICAST_OriginTransmitHandle *tmit_handle;

  /**
   * Incoming join requests from multicast.
   * member_pub_key -> struct GNUNET_MULTICAST_JoinHandle *
   */
  struct GNUNET_CONTAINER_MultiHashMap *join_reqs;

  /**
   * Last message ID transmitted to this channel.
   *
   * Incremented before sending a message, thus the message_id in messages sent
   * starts from 1.
   */
  uint64_t max_message_id;

  /**
   * ID of the last message with state operations transmitted to the channel.
   * 0 if there is no such message.
   */
  uint64_t max_state_message_id;

  /**
   * Maximum group generation transmitted to the channel.
   */
  uint64_t max_group_generation;

  /**
   * @see enum GNUNET_PSYC_Policy
   */
  enum GNUNET_PSYC_Policy policy;
};


/**
 * Client context for a channel slave.
 */
struct Slave
{
  /**
   * Channel struct common for Master and Slave
   */
  struct Channel channel;

  /**
   * Private key of the slave.
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey priv_key;

  /**
   * Public key of the slave.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey pub_key;

  /**
   * Hash of @a pub_key.
   */
  struct GNUNET_HashCode pub_key_hash;

  /**
   * Handle for the multicast member.
   */
  struct GNUNET_MULTICAST_Member *member;

  /**
   * Transmit handle for multicast.
   */
  struct GNUNET_MULTICAST_MemberTransmitHandle *tmit_handle;

  /**
   * Peer identity of the origin.
   */
  struct GNUNET_PeerIdentity origin;

  /**
   * Number of items in @a relays.
   */
  uint32_t relay_count;

  /**
   * Relays that multicast can use to connect.
   */
  struct GNUNET_PeerIdentity *relays;

  /**
   * Join request to be transmitted to the master on join.
   */
  struct GNUNET_PSYC_Message *join_msg;

  /**
   * Join decision received from multicast.
   */
  struct GNUNET_PSYC_JoinDecisionMessage *join_dcsn;

  /**
   * Maximum request ID for this channel.
   */
  uint64_t max_request_id;

  /**
   * Join flags.
   */
  enum GNUNET_PSYC_SlaveJoinFlags join_flags;
};


/**
 * Client context.
 */
struct Client {
  struct GNUNET_SERVICE_Client *client;
  struct Channel *channel;
};


struct ReplayRequestKey
{
  uint64_t fragment_id;
  uint64_t message_id;
  uint64_t fragment_offset;
  uint64_t flags;
};


static void
transmit_message (struct Channel *chn);

static uint64_t
message_queue_run (struct Channel *chn);

static uint64_t
message_queue_drop (struct Channel *chn);


static void
schedule_transmit_message (void *cls)
{
  struct Channel *chn = cls;

  transmit_message (chn);
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 */
static void
shutdown_task (void *cls)
{
  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_YES);
    stats = NULL;
  }
}


static struct Operation *
op_add (struct Channel *chn, struct GNUNET_SERVICE_Client *client,
        uint64_t op_id, uint32_t flags)
{
  struct Operation *op = GNUNET_malloc (sizeof (*op));
  op->client = client;
  op->channel = chn;
  op->op_id = op_id;
  op->flags = flags;
  GNUNET_CONTAINER_DLL_insert (chn->op_head, chn->op_tail, op);
  return op;
}


static void
op_remove (struct Operation *op)
{
  GNUNET_CONTAINER_DLL_remove (op->channel->op_head, op->channel->op_tail, op);
  GNUNET_free (op);
}


/**
 * Clean up master data structures after a client disconnected.
 */
static void
cleanup_master (struct Master *mst)
{
  struct Channel *chn = &mst->channel;

  if (NULL != mst->origin)
    GNUNET_MULTICAST_origin_stop (mst->origin, NULL, NULL); // FIXME
  GNUNET_CONTAINER_multihashmap_destroy (mst->join_reqs);
  GNUNET_CONTAINER_multihashmap_remove (masters, &chn->pub_key_hash, mst);
}


/**
 * Clean up slave data structures after a client disconnected.
 */
static void
cleanup_slave (struct Slave *slv)
{
  struct Channel *chn = &slv->channel;
  struct GNUNET_CONTAINER_MultiHashMap *
    chn_slv = GNUNET_CONTAINER_multihashmap_get (channel_slaves,
                                                &chn->pub_key_hash);
  GNUNET_assert (NULL != chn_slv);
  GNUNET_CONTAINER_multihashmap_remove (chn_slv, &slv->pub_key_hash, slv);

  if (0 == GNUNET_CONTAINER_multihashmap_size (chn_slv))
  {
    GNUNET_CONTAINER_multihashmap_remove (channel_slaves, &chn->pub_key_hash,
                                          chn_slv);
    GNUNET_CONTAINER_multihashmap_destroy (chn_slv);
  }
  GNUNET_CONTAINER_multihashmap_remove (slaves, &chn->pub_key_hash, slv);

  if (NULL != slv->join_msg)
  {
    GNUNET_free (slv->join_msg);
    slv->join_msg = NULL;
  }
  if (NULL != slv->relays)
  {
    GNUNET_free (slv->relays);
    slv->relays = NULL;
  }
  if (NULL != slv->member)
  {
    GNUNET_MULTICAST_member_part (slv->member, NULL, NULL); // FIXME
    slv->member = NULL;
  }
  GNUNET_CONTAINER_multihashmap_remove (slaves, &chn->pub_key_hash, slv);
}


/**
 * Clean up channel data structures after a client disconnected.
 */
static void
cleanup_channel (struct Channel *chn)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Cleaning up channel %s. master? %u\n",
              chn,
              GNUNET_h2s (&chn->pub_key_hash),
              chn->is_master);
  message_queue_drop (chn);
  GNUNET_CONTAINER_multihashmap_destroy (chn->recv_frags);
  chn->recv_frags = NULL;

  if (NULL != chn->store_op)
  {
    GNUNET_PSYCSTORE_operation_cancel (chn->store_op);
    chn->store_op = NULL;
  }

  (GNUNET_YES == chn->is_master)
    ? cleanup_master (chn->master)
    : cleanup_slave (chn->slave);
  GNUNET_free (chn);
}


/**
 * Called whenever a client is disconnected.
 * Frees our resources associated with that client.
 *
 * @param cls closure
 * @param client identification of the client
 * @param app_ctx must match @a client
 */
static void
client_notify_disconnect (void *cls,
                          struct GNUNET_SERVICE_Client *client,
                          void *app_ctx)
{
  struct Client *c = app_ctx;
  struct Channel *chn = c->channel;
  GNUNET_free (c);

  if (NULL == chn)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%p User context is NULL in client_disconnect()\n",
                chn);
    GNUNET_break (0);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Client (%s) disconnected from channel %s\n",
              chn,
              (GNUNET_YES == chn->is_master) ? "master" : "slave",
              GNUNET_h2s (&chn->pub_key_hash));

  struct ClientList *cli = chn->clients_head;
  while (NULL != cli)
  {
    if (cli->client == client)
    {
      GNUNET_CONTAINER_DLL_remove (chn->clients_head, chn->clients_tail, cli);
      GNUNET_free (cli);
      break;
    }
    cli = cli->next;
  }

  struct Operation *op = chn->op_head;
  while (NULL != op)
  {
    if (op->client == client)
    {
      op->client = NULL;
      break;
    }
    op = op->next;
  }

  if (NULL == chn->clients_head)
  { /* Last client disconnected. */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%p Last client (%s) disconnected from channel %s\n",
                chn,
                (GNUNET_YES == chn->is_master) ? "master" : "slave",
                GNUNET_h2s (&chn->pub_key_hash));
    chn->is_disconnected = GNUNET_YES;
    if (NULL != chn->tmit_head)
    { /* Send pending messages to multicast before cleanup. */
      transmit_message (chn);
    }
    else
    {
      cleanup_channel (chn);
    }
  }
}


/**
 * A new client connected.
 *
 * @param cls NULL
 * @param client client to add
 * @param mq message queue for @a client
 * @return @a client
 */
static void *
client_notify_connect (void *cls,
                       struct GNUNET_SERVICE_Client *client,
                       struct GNUNET_MQ_Handle *mq)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Client connected: %p\n", client);

  struct Client *c = GNUNET_malloc (sizeof (*c));
  c->client = client;

  return c;
}


/**
 * Send message to all clients connected to the channel.
 */
static void
client_send_msg (const struct Channel *chn,
                 const struct GNUNET_MessageHeader *msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Sending message to clients.\n",
              chn);

  struct ClientList *cli = chn->clients_head;
  while (NULL != cli)
  {
    struct GNUNET_MQ_Envelope *
      env = GNUNET_MQ_msg_copy (msg);

    GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (cli->client),
                    env);

    cli = cli->next;
  }
}


/**
 * Send a result code back to the client.
 *
 * @param client
 *        Client that should receive the result code.
 * @param result_code
 *        Code to transmit.
 * @param op_id
 *        Operation ID in network byte order.
 * @param data
 *        Data payload or NULL.
 * @param data_size
 *        Size of @a data.
 */
static void
client_send_result (struct GNUNET_SERVICE_Client *client, uint64_t op_id,
                    int64_t result_code, const void *data, uint16_t data_size)
{
  struct GNUNET_OperationResultMessage *res;
  struct GNUNET_MQ_Envelope *
    env = GNUNET_MQ_msg_extra (res,
                               data_size,
                               GNUNET_MESSAGE_TYPE_PSYC_RESULT_CODE);
  res->result_code = GNUNET_htonll (result_code);
  res->op_id = op_id;
  if (0 < data_size)
    GNUNET_memcpy (&res[1], data, data_size);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "%p Sending result to client for operation #%" PRIu64 ": %" PRId64 " (size: %u)\n",
	      client,
              GNUNET_ntohll (op_id),
              result_code,
              data_size);

  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (client), env);
}


/**
 * Closure for join_mem_test_cb()
 */
struct JoinMemTestClosure
{
  struct GNUNET_CRYPTO_EcdsaPublicKey slave_pub_key;
  struct Channel *channel;
  struct GNUNET_MULTICAST_JoinHandle *join_handle;
  struct GNUNET_PSYC_JoinRequestMessage *join_msg;
};


/**
 * Membership test result callback used for join requests.
 */
static void
join_mem_test_cb (void *cls, int64_t result,
                  const char *err_msg, uint16_t err_msg_size)
{
  struct JoinMemTestClosure *jcls = cls;

  if (GNUNET_NO == result && GNUNET_YES == jcls->channel->is_master)
  { /* Pass on join request to client if this is a master channel */
    struct Master *mst = jcls->channel->master;
    struct GNUNET_HashCode slave_pub_hash;
    GNUNET_CRYPTO_hash (&jcls->slave_pub_key, sizeof (jcls->slave_pub_key),
                        &slave_pub_hash);
    GNUNET_CONTAINER_multihashmap_put (mst->join_reqs, &slave_pub_hash, jcls->join_handle,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
    client_send_msg (jcls->channel, &jcls->join_msg->header);
  }
  else
  {
    if (GNUNET_SYSERR == result)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Could not perform membership test (%.*s)\n",
                  err_msg_size, err_msg);
    }
    // FIXME: add relays
    GNUNET_MULTICAST_join_decision (jcls->join_handle, result, 0, NULL, NULL);
  }
  GNUNET_free (jcls->join_msg);
  GNUNET_free (jcls);
}


/**
 * Incoming join request from multicast.
 */
static void
mcast_recv_join_request (void *cls,
                         const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_pub_key,
                         const struct GNUNET_MessageHeader *join_msg,
                         struct GNUNET_MULTICAST_JoinHandle *jh)
{
  struct Channel *chn = cls;
  uint16_t join_msg_size = 0;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Got join request.\n",
              chn);
  if (NULL != join_msg)
  {
    if (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE == ntohs (join_msg->type))
    {
      join_msg_size = ntohs (join_msg->size);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "%p Got join message with invalid type %u.\n",
                  chn,
                  ntohs (join_msg->type));
    }
  }

  struct GNUNET_PSYC_JoinRequestMessage *
    req = GNUNET_malloc (sizeof (*req) + join_msg_size);
  req->header.size = htons (sizeof (*req) + join_msg_size);
  req->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_JOIN_REQUEST);
  req->slave_pub_key = *slave_pub_key;
  if (0 < join_msg_size)
    GNUNET_memcpy (&req[1], join_msg, join_msg_size);

  struct JoinMemTestClosure *jcls = GNUNET_malloc (sizeof (*jcls));
  jcls->slave_pub_key = *slave_pub_key;
  jcls->channel = chn;
  jcls->join_handle = jh;
  jcls->join_msg = req;

  GNUNET_PSYCSTORE_membership_test (store, &chn->pub_key, slave_pub_key,
                                    chn->max_message_id, 0,
                                    &join_mem_test_cb, jcls);
}


/**
 * Join decision received from multicast.
 */
static void
mcast_recv_join_decision (void *cls, int is_admitted,
                          const struct GNUNET_PeerIdentity *peer,
                          uint16_t relay_count,
                          const struct GNUNET_PeerIdentity *relays,
                          const struct GNUNET_MessageHeader *join_resp)
{
  struct Slave *slv = cls;
  struct Channel *chn = &slv->channel;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Got join decision: %d\n",
              slv,
              is_admitted);
  if (GNUNET_YES == chn->is_ready)
  {
    /* Already admitted */
    return;
  }

  uint16_t join_resp_size = (NULL != join_resp) ? ntohs (join_resp->size) : 0;
  struct GNUNET_PSYC_JoinDecisionMessage *
    dcsn = slv->join_dcsn = GNUNET_malloc (sizeof (*dcsn) + join_resp_size);
  dcsn->header.size = htons (sizeof (*dcsn) + join_resp_size);
  dcsn->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_JOIN_DECISION);
  dcsn->is_admitted = htonl (is_admitted);
  if (0 < join_resp_size)
    GNUNET_memcpy (&dcsn[1], join_resp, join_resp_size);

  client_send_msg (chn, &dcsn->header);

  if (GNUNET_YES == is_admitted
      && ! (GNUNET_PSYC_SLAVE_JOIN_LOCAL & slv->join_flags))
  {
    chn->is_ready = GNUNET_YES;
  }
}


static int
store_recv_fragment_replay (void *cls,
                            struct GNUNET_MULTICAST_MessageHeader *msg,
                            enum GNUNET_PSYCSTORE_MessageFlags flags)
{
  struct GNUNET_MULTICAST_ReplayHandle *rh = cls;

  GNUNET_MULTICAST_replay_response (rh, &msg->header, GNUNET_MULTICAST_REC_OK);
  return GNUNET_YES;
}


/**
 * Received result of GNUNET_PSYCSTORE_fragment_get() for multicast replay.
 */
static void
store_recv_fragment_replay_result (void *cls,
                                   int64_t result,
                                   const char *err_msg,
                                   uint16_t err_msg_size)
{
  struct GNUNET_MULTICAST_ReplayHandle *rh = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Fragment replay: PSYCSTORE returned %" PRId64 " (%.*s)\n",
              rh,
              result,
              err_msg_size,
              err_msg);
  switch (result)
  {
  case GNUNET_YES:
    break;

  case GNUNET_NO:
    GNUNET_MULTICAST_replay_response (rh, NULL,
                                      GNUNET_MULTICAST_REC_NOT_FOUND);
    return;

  case GNUNET_PSYCSTORE_MEMBERSHIP_TEST_FAILED:
    GNUNET_MULTICAST_replay_response (rh, NULL,
                                      GNUNET_MULTICAST_REC_ACCESS_DENIED);
    return;

  case GNUNET_SYSERR:
    GNUNET_MULTICAST_replay_response (rh, NULL,
                                      GNUNET_MULTICAST_REC_INTERNAL_ERROR);
    return;
  }
  /* GNUNET_MULTICAST_replay_response frees 'rh' when passed
   * an error code, so it must be ensured no further processing
   * is attempted on 'rh'. Maybe this should be refactored as
   * it doesn't look very intuitive.	--lynX
   */
  GNUNET_MULTICAST_replay_response_end (rh);
}


/**
 * Incoming fragment replay request from multicast.
 */
static void
mcast_recv_replay_fragment (void *cls,
                            const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_pub_key,
                            uint64_t fragment_id, uint64_t flags,
                            struct GNUNET_MULTICAST_ReplayHandle *rh)

{
  struct Channel *chn = cls;
  GNUNET_PSYCSTORE_fragment_get (store, &chn->pub_key, slave_pub_key,
                                 fragment_id, fragment_id,
                                 &store_recv_fragment_replay,
                                 &store_recv_fragment_replay_result, rh);
}


/**
 * Incoming message replay request from multicast.
 */
static void
mcast_recv_replay_message (void *cls,
                           const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_pub_key,
                           uint64_t message_id,
                           uint64_t fragment_offset,
                           uint64_t flags,
                           struct GNUNET_MULTICAST_ReplayHandle *rh)
{
  struct Channel *chn = cls;
  GNUNET_PSYCSTORE_message_get (store, &chn->pub_key, slave_pub_key,
                                message_id, message_id, 1, NULL,
                                &store_recv_fragment_replay,
                                &store_recv_fragment_replay_result, rh);
}


/**
 * Convert an uint64_t in network byte order to a HashCode
 * that can be used as key in a MultiHashMap
 */
static inline void
hash_key_from_nll (struct GNUNET_HashCode *key, uint64_t n)
{
  /* use little-endian order, as idx_of MultiHashMap casts key to unsigned int */
  /* TODO: use built-in byte swap functions if available */

  n = ((n <<  8) & 0xFF00FF00FF00FF00ULL) | ((n >>  8) & 0x00FF00FF00FF00FFULL);
  n = ((n << 16) & 0xFFFF0000FFFF0000ULL) | ((n >> 16) & 0x0000FFFF0000FFFFULL);

  *key = (struct GNUNET_HashCode) {};
  *((uint64_t *) key)
    = (n << 32) | (n >> 32);
}


/**
 * Convert an uint64_t in host byte order to a HashCode
 * that can be used as key in a MultiHashMap
 */
static inline void
hash_key_from_hll (struct GNUNET_HashCode *key, uint64_t n)
{
#if __BYTE_ORDER == __BIG_ENDIAN
  hash_key_from_nll (key, n);
#elif __BYTE_ORDER == __LITTLE_ENDIAN
  *key = (struct GNUNET_HashCode) {};
  *((uint64_t *) key) = n;
#else
  #error byteorder undefined
#endif
}


/**
 * Initialize PSYC message header.
 */
static inline void
psyc_msg_init (struct GNUNET_PSYC_MessageHeader *pmsg,
               const struct GNUNET_MULTICAST_MessageHeader *mmsg, uint32_t flags)
{
  uint16_t size = ntohs (mmsg->header.size);
  uint16_t psize = sizeof (*pmsg) + size - sizeof (*mmsg);

  pmsg->header.size = htons (psize);
  pmsg->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE);
  pmsg->message_id = mmsg->message_id;
  pmsg->fragment_offset = mmsg->fragment_offset;
  pmsg->flags = htonl (flags);

  GNUNET_memcpy (&pmsg[1], &mmsg[1], size - sizeof (*mmsg));
}


/**
 * Create a new PSYC message from a multicast message for sending it to clients.
 */
static inline struct GNUNET_PSYC_MessageHeader *
psyc_msg_new (const struct GNUNET_MULTICAST_MessageHeader *mmsg, uint32_t flags)
{
  struct GNUNET_PSYC_MessageHeader *pmsg;
  uint16_t size = ntohs (mmsg->header.size);
  uint16_t psize = sizeof (*pmsg) + size - sizeof (*mmsg);

  pmsg = GNUNET_malloc (psize);
  psyc_msg_init (pmsg, mmsg, flags);
  return pmsg;
}


/**
 * Send multicast message to all clients connected to the channel.
 */
static void
client_send_mcast_msg (struct Channel *chn,
                       const struct GNUNET_MULTICAST_MessageHeader *mmsg,
                       uint32_t flags)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Sending multicast message to client. fragment_id: %" PRIu64 ", message_id: %" PRIu64 "\n",
              chn,
              GNUNET_ntohll (mmsg->fragment_id),
              GNUNET_ntohll (mmsg->message_id));

  struct GNUNET_PSYC_MessageHeader *
    pmsg = GNUNET_PSYC_message_header_create (mmsg, flags);
  client_send_msg (chn, &pmsg->header);
  GNUNET_free (pmsg);
}


/**
 * Send multicast request to all clients connected to the channel.
 */
static void
client_send_mcast_req (struct Master *mst,
                       const struct GNUNET_MULTICAST_RequestHeader *req)
{
  struct Channel *chn = &mst->channel;

  struct GNUNET_PSYC_MessageHeader *pmsg;
  uint16_t size = ntohs (req->header.size);
  uint16_t psize = sizeof (*pmsg) + size - sizeof (*req);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Sending multicast request to client. fragment_id: %" PRIu64 ", message_id: %" PRIu64 "\n",
              chn,
              GNUNET_ntohll (req->fragment_id),
              GNUNET_ntohll (req->request_id));

  pmsg = GNUNET_malloc (psize);
  pmsg->header.size = htons (psize);
  pmsg->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE);
  pmsg->message_id = req->request_id;
  pmsg->fragment_offset = req->fragment_offset;
  pmsg->flags = htonl (GNUNET_PSYC_MESSAGE_REQUEST);
  pmsg->slave_pub_key = req->member_pub_key;
  GNUNET_memcpy (&pmsg[1], &req[1], size - sizeof (*req));

  client_send_msg (chn, &pmsg->header);

  /* FIXME: save req to PSYCstore so that it can be resent later to clients */

  GNUNET_free (pmsg);
}


/**
 * Insert a multicast message fragment into the queue belonging to the message.
 *
 * @param chn          Channel.
 * @param mmsg         Multicast message fragment.
 * @param msg_id_hash  Message ID of @a mmsg in a struct GNUNET_HashCode.
 * @param first_ptype  First PSYC message part type in @a mmsg.
 * @param last_ptype   Last PSYC message part type in @a mmsg.
 */
static void
fragment_queue_insert (struct Channel *chn,
                       const struct GNUNET_MULTICAST_MessageHeader *mmsg,
                       uint16_t first_ptype, uint16_t last_ptype)
{
  const uint16_t size = ntohs (mmsg->header.size);
  const uint64_t frag_offset = GNUNET_ntohll (mmsg->fragment_offset);
  struct GNUNET_CONTAINER_MultiHashMap
    *chan_msgs = GNUNET_CONTAINER_multihashmap_get (recv_cache,
                                                    &chn->pub_key_hash);

  struct GNUNET_HashCode msg_id_hash;
  hash_key_from_nll (&msg_id_hash, mmsg->message_id);

  struct FragmentQueue
    *fragq = GNUNET_CONTAINER_multihashmap_get (chn->recv_frags, &msg_id_hash);

  if (NULL == fragq)
  {
    fragq = GNUNET_malloc (sizeof (*fragq));
    fragq->state = MSG_FRAG_STATE_HEADER;
    fragq->fragments
      = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);

    GNUNET_CONTAINER_multihashmap_put (chn->recv_frags, &msg_id_hash, fragq,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);

    if (NULL == chan_msgs)
    {
      chan_msgs = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);
      GNUNET_CONTAINER_multihashmap_put (recv_cache, &chn->pub_key_hash, chan_msgs,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
    }
  }

  struct GNUNET_HashCode frag_id_hash;
  hash_key_from_nll (&frag_id_hash, mmsg->fragment_id);
  struct RecvCacheEntry
    *cache_entry = GNUNET_CONTAINER_multihashmap_get (chan_msgs, &frag_id_hash);
  if (NULL == cache_entry)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%p Adding message fragment to cache. message_id: %" PRIu64 ", fragment_id: %" PRIu64 "\n",
                chn,
                GNUNET_ntohll (mmsg->message_id),
                GNUNET_ntohll (mmsg->fragment_id));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%p header_size: %" PRIu64 " + %u\n",
                chn,
                fragq->header_size,
                size);
    cache_entry = GNUNET_malloc (sizeof (*cache_entry));
    cache_entry->ref_count = 1;
    cache_entry->mmsg = GNUNET_malloc (size);
    GNUNET_memcpy (cache_entry->mmsg, mmsg, size);
    GNUNET_CONTAINER_multihashmap_put (chan_msgs, &frag_id_hash, cache_entry,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  }
  else
  {
    cache_entry->ref_count++;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%p Message fragment is already in cache. message_id: %" PRIu64 ", fragment_id: %" PRIu64 ", ref_count: %u\n",
                chn,
                GNUNET_ntohll (mmsg->message_id),
                GNUNET_ntohll (mmsg->fragment_id),
                cache_entry->ref_count);
  }

  if (MSG_FRAG_STATE_HEADER == fragq->state)
  {
    if (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_METHOD == first_ptype)
    {
      struct GNUNET_PSYC_MessageMethod *
        pmeth = (struct GNUNET_PSYC_MessageMethod *) &mmsg[1];
      fragq->state_delta = GNUNET_ntohll (pmeth->state_delta);
      fragq->flags = ntohl (pmeth->flags);
    }

    if (last_ptype < GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_DATA)
    {
      fragq->header_size += size;
    }
    else if (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_METHOD == first_ptype
             || frag_offset == fragq->header_size)
    { /* header is now complete */
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "%p Header of message %" PRIu64 " is complete.\n",
                  chn,
                  GNUNET_ntohll (mmsg->message_id));

      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "%p Adding message %" PRIu64 " to queue.\n",
                  chn,
                  GNUNET_ntohll (mmsg->message_id));
      fragq->state = MSG_FRAG_STATE_DATA;
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "%p Header of message %" PRIu64 " is NOT complete yet: %" PRIu64 " != %" PRIu64 "\n",
                  chn,
                  GNUNET_ntohll (mmsg->message_id),
                  frag_offset,
                  fragq->header_size);
    }
  }

  switch (last_ptype)
  {
  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_END:
    if (frag_offset == fragq->size)
      fragq->state = MSG_FRAG_STATE_END;
    else
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "%p Message %" PRIu64 " is NOT complete yet: %" PRIu64 " != %" PRIu64 "\n",
                  chn,
                  GNUNET_ntohll (mmsg->message_id),
                  frag_offset,
                  fragq->size);
    break;

  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_CANCEL:
    /* Drop message without delivering to client if it's a single fragment */
    fragq->state =
      (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_METHOD == first_ptype)
      ? MSG_FRAG_STATE_DROP
      : MSG_FRAG_STATE_CANCEL;
  }

  switch (fragq->state)
  {
  case MSG_FRAG_STATE_DATA:
  case MSG_FRAG_STATE_END:
  case MSG_FRAG_STATE_CANCEL:
    if (GNUNET_NO == fragq->is_queued)
    {
      GNUNET_CONTAINER_heap_insert (chn->recv_msgs, NULL,
                                    GNUNET_ntohll (mmsg->message_id));
      fragq->is_queued = GNUNET_YES;
    }
  }

  fragq->size += size;
  GNUNET_CONTAINER_heap_insert (fragq->fragments, NULL,
                                GNUNET_ntohll (mmsg->fragment_id));
}


/**
 * Run fragment queue of a message.
 *
 * Send fragments of a message in order to client, after all modifiers arrived
 * from multicast.
 *
 * @param chn
 *        Channel.
 * @param msg_id
 *        ID of the message @a fragq belongs to.
 * @param fragq
 *        Fragment queue of the message.
 * @param drop
 *        Drop message without delivering to client?
 *        #GNUNET_YES or #GNUNET_NO.
 */
static void
fragment_queue_run (struct Channel *chn, uint64_t msg_id,
                    struct FragmentQueue *fragq, uint8_t drop)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "%p Running message fragment queue for message %" PRIu64 " (state: %u).\n",
              chn,
              msg_id,
              fragq->state);

  struct GNUNET_CONTAINER_MultiHashMap
    *chan_msgs = GNUNET_CONTAINER_multihashmap_get (recv_cache,
                                                    &chn->pub_key_hash);
  GNUNET_assert (NULL != chan_msgs);
  uint64_t frag_id;

  while (GNUNET_YES == GNUNET_CONTAINER_heap_peek2 (fragq->fragments, NULL,
                                                    &frag_id))
  {
    struct GNUNET_HashCode frag_id_hash;
    hash_key_from_hll (&frag_id_hash, frag_id);
    struct RecvCacheEntry *cache_entry
      = GNUNET_CONTAINER_multihashmap_get (chan_msgs, &frag_id_hash);
    if (cache_entry != NULL)
    {
      if (GNUNET_NO == drop)
      {
        client_send_mcast_msg (chn, cache_entry->mmsg, 0);
      }
      if (cache_entry->ref_count <= 1)
      {
        GNUNET_CONTAINER_multihashmap_remove (chan_msgs, &frag_id_hash,
                                              cache_entry);
        GNUNET_free (cache_entry->mmsg);
        GNUNET_free (cache_entry);
      }
      else
      {
        cache_entry->ref_count--;
      }
    }
#if CACHE_AGING_IMPLEMENTED
    else if (GNUNET_NO == drop)
    {
      /* TODO: fragment not in cache anymore, retrieve it from PSYCstore */
    }
#endif

    GNUNET_CONTAINER_heap_remove_root (fragq->fragments);
  }

  if (MSG_FRAG_STATE_END <= fragq->state)
  {
    struct GNUNET_HashCode msg_id_hash;
    hash_key_from_hll (&msg_id_hash, msg_id);

    GNUNET_CONTAINER_multihashmap_remove (chn->recv_frags, &msg_id_hash, fragq);
    GNUNET_CONTAINER_heap_destroy (fragq->fragments);
    GNUNET_free (fragq);
  }
  else
  {
    fragq->is_queued = GNUNET_NO;
  }
}


struct StateModifyClosure
{
  struct Channel *channel;
  uint64_t msg_id;
  struct GNUNET_HashCode msg_id_hash;
};


void
store_recv_state_modify_result (void *cls, int64_t result,
                                const char *err_msg, uint16_t err_msg_size)
{
  struct StateModifyClosure *mcls = cls;
  struct Channel *chn = mcls->channel;
  uint64_t msg_id = mcls->msg_id;

  struct FragmentQueue *
    fragq = GNUNET_CONTAINER_multihashmap_get (chn->recv_frags, &mcls->msg_id_hash);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p GNUNET_PSYCSTORE_state_modify() returned %" PRId64 " (%.*s)\n",
              chn, result, err_msg_size, err_msg);

  switch (result)
  {
  case GNUNET_OK:
  case GNUNET_NO:
    if (NULL != fragq)
      fragq->state_is_modified = GNUNET_YES;
    if (chn->max_state_message_id < msg_id)
      chn->max_state_message_id = msg_id;
    if (chn->max_message_id < msg_id)
      chn->max_message_id = msg_id;

    if (NULL != fragq)
      fragment_queue_run (chn, msg_id, fragq, MSG_FRAG_STATE_DROP == fragq->state);
    GNUNET_CONTAINER_heap_remove_root (chn->recv_msgs);
    message_queue_run (chn);
    break;

  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%p GNUNET_PSYCSTORE_state_modify() failed with error %" PRId64 " (%.*s)\n",
                chn, result, err_msg_size, err_msg);
    /** @todo FIXME: handle state_modify error */
  }
}


/**
 * Run message queue.
 *
 * Send messages in queue to client in order after a message has arrived from
 * multicast, according to the following:
 * - A message is only sent if all of its modifiers arrived.
 * - A stateful message is only sent if the previous stateful message
 *   has already been delivered to the client.
 *
 * @param chn  Channel.
 *
 * @return Number of messages removed from queue and sent to client.
 */
static uint64_t
message_queue_run (struct Channel *chn)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "%p Running message queue.\n", chn);
  uint64_t n = 0;
  uint64_t msg_id;

  while (GNUNET_YES == GNUNET_CONTAINER_heap_peek2 (chn->recv_msgs, NULL,
                                                    &msg_id))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "%p Processing message %" PRIu64 " in queue.\n", chn, msg_id);
    struct GNUNET_HashCode msg_id_hash;
    hash_key_from_hll (&msg_id_hash, msg_id);

    struct FragmentQueue *
      fragq = GNUNET_CONTAINER_multihashmap_get (chn->recv_frags, &msg_id_hash);

    if (NULL == fragq || fragq->state <= MSG_FRAG_STATE_HEADER)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "%p No fragq (%p) or header not complete.\n",
                  chn, fragq);
      break;
    }

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%p Fragment queue entry:  state: %u, state delta: "
                "%" PRIu64 " - %" PRIu64 " ?= %" PRIu64 "\n",
                chn, fragq->state, msg_id, fragq->state_delta, chn->max_state_message_id);

    if (MSG_FRAG_STATE_DATA <= fragq->state)
    {
      /* Check if there's a missing message before the current one */
      if (GNUNET_PSYC_STATE_NOT_MODIFIED == fragq->state_delta)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%p state NOT modified\n", chn);

        if (!(fragq->flags & GNUNET_PSYC_MESSAGE_ORDER_ANY)
            && (chn->max_message_id != msg_id - 1
                && chn->max_message_id != msg_id))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                      "%p Out of order message. "
                      "(%" PRIu64 " != %" PRIu64 " - 1)\n",
                      chn, chn->max_message_id, msg_id);
          break;
          // FIXME: keep track of messages processed in this queue run,
          //        and only stop after reaching the end
        }
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%p state modified\n", chn);
        if (GNUNET_YES != fragq->state_is_modified)
        {
          if (msg_id - fragq->state_delta != chn->max_state_message_id)
          {
            GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                        "%p Out of order stateful message. "
                        "(%" PRIu64 " - %" PRIu64 " != %" PRIu64 ")\n",
                        chn, msg_id, fragq->state_delta, chn->max_state_message_id);
            break;
            // FIXME: keep track of messages processed in this queue run,
            //        and only stop after reaching the end
          }

          struct StateModifyClosure *mcls = GNUNET_malloc (sizeof (*mcls));
          mcls->channel = chn;
          mcls->msg_id = msg_id;
          mcls->msg_id_hash = msg_id_hash;

          /* Apply modifiers to state in PSYCstore */
          GNUNET_PSYCSTORE_state_modify (store, &chn->pub_key, msg_id,
                                         fragq->state_delta,
                                         store_recv_state_modify_result, mcls);
          break; // continue after asynchronous state modify result
        }
      }
      chn->max_message_id = msg_id;
    }
    fragment_queue_run (chn, msg_id, fragq, MSG_FRAG_STATE_DROP == fragq->state);
    GNUNET_CONTAINER_heap_remove_root (chn->recv_msgs);
    n++;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Removed %" PRIu64 " messages from queue.\n", chn, n);
  return n;
}


/**
 * Drop message queue of a channel.
 *
 * Remove all messages in queue without sending it to clients.
 *
 * @param chn  Channel.
 *
 * @return Number of messages removed from queue.
 */
static uint64_t
message_queue_drop (struct Channel *chn)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "%p Dropping message queue.\n", chn);
  uint64_t n = 0;
  uint64_t msg_id;
  while (GNUNET_YES == GNUNET_CONTAINER_heap_peek2 (chn->recv_msgs, NULL,
                                                    &msg_id))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "%p Dropping message %" PRIu64 " from queue.\n", chn, msg_id);
    struct GNUNET_HashCode msg_id_hash;
    hash_key_from_hll (&msg_id_hash, msg_id);

    struct FragmentQueue *
      fragq = GNUNET_CONTAINER_multihashmap_get (chn->recv_frags, &msg_id_hash);
    GNUNET_assert (NULL != fragq);
    fragment_queue_run (chn, msg_id, fragq, GNUNET_YES);
    GNUNET_CONTAINER_heap_remove_root (chn->recv_msgs);
    n++;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Removed %" PRIu64 " messages from queue.\n", chn, n);
  return n;
}


/**
 * Received result of GNUNET_PSYCSTORE_fragment_store().
 */
static void
store_recv_fragment_store_result (void *cls, int64_t result,
                                  const char *err_msg, uint16_t err_msg_size)
{
  struct Channel *chn = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p GNUNET_PSYCSTORE_fragment_store() returned %" PRId64 " (%.*s)\n",
              chn, result, err_msg_size, err_msg);
}


/**
 * Handle incoming message fragment from multicast.
 *
 * Store it using PSYCstore and send it to the clients of the channel in order.
 */
static void
mcast_recv_message (void *cls, const struct GNUNET_MULTICAST_MessageHeader *mmsg)
{
  struct Channel *chn = cls;
  uint16_t size = ntohs (mmsg->header.size);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Received multicast message of size %u. "
              "fragment_id=%" PRIu64 ", message_id=%" PRIu64
              ", fragment_offset=%" PRIu64 ", flags=%" PRIu64 "\n",
              chn, size,
              GNUNET_ntohll (mmsg->fragment_id),
              GNUNET_ntohll (mmsg->message_id),
              GNUNET_ntohll (mmsg->fragment_offset),
              GNUNET_ntohll (mmsg->flags));

  GNUNET_PSYCSTORE_fragment_store (store, &chn->pub_key, mmsg, 0,
                                   &store_recv_fragment_store_result, chn);

  uint16_t first_ptype = 0, last_ptype = 0;
  int check = GNUNET_PSYC_receive_check_parts (size - sizeof (*mmsg),
                                               (const char *) &mmsg[1],
                                               &first_ptype, &last_ptype);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Message check result %d, first part type %u, last part type %u\n",
              chn, check, first_ptype, last_ptype);
  if (GNUNET_SYSERR == check)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "%p Dropping incoming multicast message with invalid parts.\n",
                chn);
    GNUNET_break_op (0);
    return;
  }

  fragment_queue_insert (chn, mmsg, first_ptype, last_ptype);
  message_queue_run (chn);
}


/**
 * Incoming request fragment from multicast for a master.
 *
 * @param cls	Master.
 * @param req	The request.
 */
static void
mcast_recv_request (void *cls,
                    const struct GNUNET_MULTICAST_RequestHeader *req)
{
  struct Master *mst = cls;
  uint16_t size = ntohs (req->header.size);

  char *str = GNUNET_CRYPTO_ecdsa_public_key_to_string (&req->member_pub_key);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Received multicast request of size %u from %s.\n",
              mst, size, str);
  GNUNET_free (str);

  uint16_t first_ptype = 0, last_ptype = 0;
  if (GNUNET_SYSERR
      == GNUNET_PSYC_receive_check_parts (size - sizeof (*req),
                                          (const char *) &req[1],
                                          &first_ptype, &last_ptype))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "%p Dropping incoming multicast request with invalid parts.\n",
                mst);
    GNUNET_break_op (0);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Message parts: first: type %u, last: type %u\n",
              first_ptype, last_ptype);

  /* FIXME: in-order delivery */
  client_send_mcast_req (mst, req);
}


/**
 * Response from PSYCstore with the current counter values for a channel master.
 */
static void
store_recv_master_counters (void *cls, int result, uint64_t max_fragment_id,
                            uint64_t max_message_id, uint64_t max_group_generation,
                            uint64_t max_state_message_id)
{
  struct Master *mst = cls;
  struct Channel *chn = &mst->channel;
  chn->store_op = NULL;

  struct GNUNET_PSYC_CountersResultMessage res;
  res.header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_MASTER_START_ACK);
  res.header.size = htons (sizeof (res));
  res.result_code = htonl (result);
  res.max_message_id = GNUNET_htonll (max_message_id);

  if (GNUNET_OK == result || GNUNET_NO == result)
  {
    mst->max_message_id = max_message_id;
    chn->max_message_id = max_message_id;
    chn->max_state_message_id = max_state_message_id;
    mst->max_group_generation = max_group_generation;
    mst->origin
      = GNUNET_MULTICAST_origin_start (cfg, &mst->priv_key, max_fragment_id,
                                       mcast_recv_join_request,
                                       mcast_recv_replay_fragment,
                                       mcast_recv_replay_message,
                                       mcast_recv_request,
                                       mcast_recv_message, chn);
    chn->is_ready = GNUNET_YES;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%p GNUNET_PSYCSTORE_counters_get() "
                "returned %d for channel %s.\n",
                chn, result, GNUNET_h2s (&chn->pub_key_hash));
  }

  client_send_msg (chn, &res.header);
}


/**
 * Response from PSYCstore with the current counter values for a channel slave.
 */
void
store_recv_slave_counters (void *cls, int result, uint64_t max_fragment_id,
                           uint64_t max_message_id, uint64_t max_group_generation,
                           uint64_t max_state_message_id)
{
  struct Slave *slv = cls;
  struct Channel *chn = &slv->channel;
  chn->store_op = NULL;

  struct GNUNET_PSYC_CountersResultMessage res;
  res.header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_SLAVE_JOIN_ACK);
  res.header.size = htons (sizeof (res));
  res.result_code = htonl (result);
  res.max_message_id = GNUNET_htonll (max_message_id);

  if (GNUNET_OK == result || GNUNET_NO == result)
  {
    chn->max_message_id = max_message_id;
    chn->max_state_message_id = max_state_message_id;
    slv->member
      = GNUNET_MULTICAST_member_join (cfg, &chn->pub_key, &slv->priv_key,
                                      &slv->origin,
                                      slv->relay_count, slv->relays,
                                      &slv->join_msg->header,
                                      mcast_recv_join_request,
                                      mcast_recv_join_decision,
                                      mcast_recv_replay_fragment,
                                      mcast_recv_replay_message,
                                      mcast_recv_message, chn);
    if (NULL != slv->join_msg)
    {
      GNUNET_free (slv->join_msg);
      slv->join_msg = NULL;
    }
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%p GNUNET_PSYCSTORE_counters_get() "
                "returned %d for channel %s.\n",
                chn, result, GNUNET_h2s (&chn->pub_key_hash));
  }

  client_send_msg (chn, &res.header);
}


static void
channel_init (struct Channel *chn)
{
  chn->recv_msgs
    = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  chn->recv_frags = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);
}


/**
 * Handle a connecting client starting a channel master.
 */
static void
handle_client_master_start (void *cls,
                            const struct MasterStartRequest *req)
{
  struct Client *c = cls;
  struct GNUNET_SERVICE_Client *client = c->client;

  struct GNUNET_CRYPTO_EddsaPublicKey pub_key;
  struct GNUNET_HashCode pub_key_hash;

  GNUNET_CRYPTO_eddsa_key_get_public (&req->channel_key, &pub_key);
  GNUNET_CRYPTO_hash (&pub_key, sizeof (pub_key), &pub_key_hash);

  struct Master *
    mst = GNUNET_CONTAINER_multihashmap_get (masters, &pub_key_hash);
  struct Channel *chn;

  if (NULL == mst)
  {
    mst = GNUNET_malloc (sizeof (*mst));
    mst->policy = ntohl (req->policy);
    mst->priv_key = req->channel_key;
    mst->join_reqs = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);

    chn = c->channel = &mst->channel;
    chn->master = mst;
    chn->is_master = GNUNET_YES;
    chn->pub_key = pub_key;
    chn->pub_key_hash = pub_key_hash;
    channel_init (chn);

    GNUNET_CONTAINER_multihashmap_put (masters, &chn->pub_key_hash, chn,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
    chn->store_op = GNUNET_PSYCSTORE_counters_get (store, &chn->pub_key,
                                                   store_recv_master_counters, mst);
  }
  else
  {
    chn = &mst->channel;

    struct GNUNET_PSYC_CountersResultMessage *res;
    struct GNUNET_MQ_Envelope *
      env = GNUNET_MQ_msg (res, GNUNET_MESSAGE_TYPE_PSYC_MASTER_START_ACK);
    res->result_code = htonl (GNUNET_OK);
    res->max_message_id = GNUNET_htonll (mst->max_message_id);

    GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (client), env);
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Client connected as master to channel %s.\n",
              mst, GNUNET_h2s (&chn->pub_key_hash));

  struct ClientList *cli = GNUNET_malloc (sizeof (*cli));
  cli->client = client;
  GNUNET_CONTAINER_DLL_insert (chn->clients_head, chn->clients_tail, cli);

  GNUNET_SERVICE_client_continue (client);
}


static int
check_client_slave_join (void *cls,
                         const struct SlaveJoinRequest *req)
{
  return GNUNET_OK;
}


/**
 * Handle a connecting client joining as a channel slave.
 */
static void
handle_client_slave_join (void *cls,
                          const struct SlaveJoinRequest *req)
{
  struct Client *c = cls;
  struct GNUNET_SERVICE_Client *client = c->client;

  uint16_t req_size = ntohs (req->header.size);

  struct GNUNET_CRYPTO_EcdsaPublicKey slv_pub_key;
  struct GNUNET_HashCode pub_key_hash, slv_pub_hash;

  GNUNET_CRYPTO_ecdsa_key_get_public (&req->slave_key, &slv_pub_key);
  GNUNET_CRYPTO_hash (&slv_pub_key, sizeof (slv_pub_key), &slv_pub_hash);
  GNUNET_CRYPTO_hash (&req->channel_pub_key, sizeof (req->channel_pub_key), &pub_key_hash);

  struct GNUNET_CONTAINER_MultiHashMap *
    chn_slv = GNUNET_CONTAINER_multihashmap_get (channel_slaves, &pub_key_hash);
  struct Slave *slv = NULL;
  struct Channel *chn;

  if (NULL != chn_slv)
  {
    slv = GNUNET_CONTAINER_multihashmap_get (chn_slv, &slv_pub_hash);
  }
  if (NULL == slv)
  {
    slv = GNUNET_malloc (sizeof (*slv));
    slv->priv_key = req->slave_key;
    slv->pub_key = slv_pub_key;
    slv->pub_key_hash = slv_pub_hash;
    slv->origin = req->origin;
    slv->relay_count = ntohl (req->relay_count);
    slv->join_flags = ntohl (req->flags);

    const struct GNUNET_PeerIdentity *
      relays = (const struct GNUNET_PeerIdentity *) &req[1];
    uint16_t relay_size = slv->relay_count * sizeof (*relays);
    uint16_t join_msg_size = 0;

    if (sizeof (*req) + relay_size + sizeof (struct GNUNET_MessageHeader)
        <= req_size)
    {
      struct GNUNET_PSYC_Message *
        join_msg = (struct GNUNET_PSYC_Message *) (((char *) &req[1]) + relay_size);
      join_msg_size = ntohs (join_msg->header.size);
      slv->join_msg = GNUNET_malloc (join_msg_size);
      GNUNET_memcpy (slv->join_msg, join_msg, join_msg_size);
    }
    if (sizeof (*req) + relay_size + join_msg_size != req_size)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "%u + %u + %u != %u\n",
                  (unsigned int) sizeof (*req),
                  relay_size,
                  join_msg_size,
                  req_size);
      GNUNET_break (0);
      GNUNET_SERVICE_client_drop (client);
      GNUNET_free (slv);
      return;
    }
    if (0 < slv->relay_count)
    {
      slv->relays = GNUNET_malloc (relay_size);
      GNUNET_memcpy (slv->relays, &req[1], relay_size);
    }

    chn = c->channel = &slv->channel;
    chn->slave = slv;
    chn->is_master = GNUNET_NO;
    chn->pub_key = req->channel_pub_key;
    chn->pub_key_hash = pub_key_hash;
    channel_init (chn);

    if (NULL == chn_slv)
    {
      chn_slv = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);
      GNUNET_CONTAINER_multihashmap_put (channel_slaves, &chn->pub_key_hash, chn_slv,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
    }
    GNUNET_CONTAINER_multihashmap_put (chn_slv, &slv->pub_key_hash, chn,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
    GNUNET_CONTAINER_multihashmap_put (slaves, &chn->pub_key_hash, chn,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
    chn->store_op = GNUNET_PSYCSTORE_counters_get (store, &chn->pub_key,
                                                  &store_recv_slave_counters, slv);
  }
  else
  {
    chn = &slv->channel;

    struct GNUNET_PSYC_CountersResultMessage *res;

    struct GNUNET_MQ_Envelope *
      env = GNUNET_MQ_msg (res, GNUNET_MESSAGE_TYPE_PSYC_SLAVE_JOIN_ACK);
    res->result_code = htonl (GNUNET_OK);
    res->max_message_id = GNUNET_htonll (chn->max_message_id);

    GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (client), env);

    if (GNUNET_PSYC_SLAVE_JOIN_LOCAL & slv->join_flags)
    {
      mcast_recv_join_decision (slv, GNUNET_YES,
                                NULL, 0, NULL, NULL);
    }
    else if (NULL == slv->member)
    {
      slv->member
        = GNUNET_MULTICAST_member_join (cfg, &chn->pub_key, &slv->priv_key,
                                        &slv->origin,
                                        slv->relay_count, slv->relays,
                                        &slv->join_msg->header,
                                        &mcast_recv_join_request,
                                        &mcast_recv_join_decision,
                                        &mcast_recv_replay_fragment,
                                        &mcast_recv_replay_message,
                                        &mcast_recv_message, chn);
      if (NULL != slv->join_msg)
      {
        GNUNET_free (slv->join_msg);
        slv->join_msg = NULL;
      }
    }
    else if (NULL != slv->join_dcsn)
    {
      struct GNUNET_MQ_Envelope *
        env = GNUNET_MQ_msg_copy (&slv->join_dcsn->header);
      GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (client), env);
    }
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Client connected as slave to channel %s.\n",
              slv, GNUNET_h2s (&chn->pub_key_hash));

  struct ClientList *cli = GNUNET_malloc (sizeof (*cli));
  cli->client = client;
  GNUNET_CONTAINER_DLL_insert (chn->clients_head, chn->clients_tail, cli);

  GNUNET_SERVICE_client_continue (client);
}


struct JoinDecisionClosure
{
  int32_t is_admitted;
  struct GNUNET_MessageHeader *msg;
};


/**
 * Iterator callback for sending join decisions to multicast.
 */
static int
mcast_send_join_decision (void *cls, const struct GNUNET_HashCode *pub_key_hash,
                          void *value)
{
  struct JoinDecisionClosure *jcls = cls;
  struct GNUNET_MULTICAST_JoinHandle *jh = value;
  // FIXME: add relays
  GNUNET_MULTICAST_join_decision (jh, jcls->is_admitted, 0, NULL, jcls->msg);
  return GNUNET_YES;
}


static int
check_client_join_decision (void *cls,
                            const struct GNUNET_PSYC_JoinDecisionMessage *dcsn)
{
  return GNUNET_OK;
}


/**
 * Join decision from client.
 */
static void
handle_client_join_decision (void *cls,
                             const struct GNUNET_PSYC_JoinDecisionMessage *dcsn)
{
  struct Client *c = cls;
  struct GNUNET_SERVICE_Client *client = c->client;
  struct Channel *chn = c->channel;
  if (NULL == chn)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (client);
    return;
  }
  GNUNET_assert (GNUNET_YES == chn->is_master);
  struct Master *mst = chn->master;

  struct JoinDecisionClosure jcls;
  jcls.is_admitted = ntohl (dcsn->is_admitted);
  jcls.msg
    = (sizeof (*dcsn) + sizeof (*jcls.msg) <= ntohs (dcsn->header.size))
    ? (struct GNUNET_MessageHeader *) &dcsn[1]
    : NULL;

  struct GNUNET_HashCode slave_pub_hash;
  GNUNET_CRYPTO_hash (&dcsn->slave_pub_key, sizeof (dcsn->slave_pub_key),
                      &slave_pub_hash);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Got join decision (%d) from client for channel %s..\n",
              mst, jcls.is_admitted, GNUNET_h2s (&chn->pub_key_hash));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p ..and slave %s.\n",
              mst, GNUNET_h2s (&slave_pub_hash));

  GNUNET_CONTAINER_multihashmap_get_multiple (mst->join_reqs, &slave_pub_hash,
                                              &mcast_send_join_decision, &jcls);
  GNUNET_CONTAINER_multihashmap_remove_all (mst->join_reqs, &slave_pub_hash);
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Send acknowledgement to a client.
 *
 * Sent after a message fragment has been passed on to multicast.
 *
 * @param chn The channel struct for the client.
 */
static void
send_message_ack (struct Channel *chn, struct GNUNET_SERVICE_Client *client)
{
  struct GNUNET_MessageHeader *res;
  struct GNUNET_MQ_Envelope *
      env = GNUNET_MQ_msg (res, GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_ACK);

  /* FIXME? */
  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (client), env);
}


/**
 * Callback for the transmit functions of multicast.
 */
static int
transmit_notify (void *cls, size_t *data_size, void *data)
{
  struct Channel *chn = cls;
  struct TransmitMessage *tmit_msg = chn->tmit_head;

  if (NULL == tmit_msg || *data_size < tmit_msg->size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%p transmit_notify: nothing to send.\n", chn);
    if (NULL != tmit_msg && *data_size < tmit_msg->size)
      GNUNET_break (0);
    *data_size = 0;
    return GNUNET_NO;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p transmit_notify: sending %u bytes.\n", chn, tmit_msg->size);

  *data_size = tmit_msg->size;
  GNUNET_memcpy (data, &tmit_msg[1], *data_size);

  int ret
    = (tmit_msg->last_ptype < GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_END)
    ? GNUNET_NO
    : GNUNET_YES;

  /* FIXME: handle disconnecting clients */
  if (NULL != tmit_msg->client)
    send_message_ack (chn, tmit_msg->client);

  GNUNET_CONTAINER_DLL_remove (chn->tmit_head, chn->tmit_tail, tmit_msg);

  if (NULL != chn->tmit_head)
  {
    GNUNET_SCHEDULER_add_now (&schedule_transmit_message, chn);
  }
  else if (GNUNET_YES == chn->is_disconnected
           && tmit_msg->last_ptype < GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_END)
  {
    /* FIXME: handle partial message (when still in_transmit) */
    GNUNET_free (tmit_msg);
    return GNUNET_SYSERR;
  }
  GNUNET_free (tmit_msg);
  return ret;
}


/**
 * Callback for the transmit functions of multicast.
 */
static int
master_transmit_notify (void *cls, size_t *data_size, void *data)
{
  int ret = transmit_notify (cls, data_size, data);

  if (GNUNET_YES == ret)
  {
    struct Master *mst = cls;
    mst->tmit_handle = NULL;
  }
  return ret;
}


/**
 * Callback for the transmit functions of multicast.
 */
static int
slave_transmit_notify (void *cls, size_t *data_size, void *data)
{
  int ret = transmit_notify (cls, data_size, data);

  if (GNUNET_YES == ret)
  {
    struct Slave *slv = cls;
    slv->tmit_handle = NULL;
  }
  return ret;
}


/**
 * Transmit a message from a channel master to the multicast group.
 */
static void
master_transmit_message (struct Master *mst)
{
  struct Channel *chn = &mst->channel;
  struct TransmitMessage *tmit_msg = chn->tmit_head;
  if (NULL == tmit_msg)
    return;
  if (NULL == mst->tmit_handle)
  {
    mst->tmit_handle = (void *) &mst->tmit_handle;
    struct GNUNET_MULTICAST_OriginTransmitHandle *
      tmit_handle = GNUNET_MULTICAST_origin_to_all (mst->origin, tmit_msg->id,
                                                    mst->max_group_generation,
                                                    master_transmit_notify, mst);
    if (NULL != mst->tmit_handle)
      mst->tmit_handle = tmit_handle;
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
slave_transmit_message (struct Slave *slv)
{
  if (NULL == slv->channel.tmit_head)
    return;
  if (NULL == slv->tmit_handle)
  {
    slv->tmit_handle = (void *) &slv->tmit_handle;
    struct GNUNET_MULTICAST_MemberTransmitHandle *
      tmit_handle = GNUNET_MULTICAST_member_to_origin (slv->member, slv->channel.tmit_head->id,
                                                       slave_transmit_notify, slv);
    if (NULL != slv->tmit_handle)
      slv->tmit_handle = tmit_handle;
  }
  else
  {
    GNUNET_MULTICAST_member_to_origin_resume (slv->tmit_handle);
  }
}


static void
transmit_message (struct Channel *chn)
{
  chn->is_master
    ? master_transmit_message (chn->master)
    : slave_transmit_message (chn->slave);
}


/**
 * Queue a message from a channel master for sending to the multicast group.
 */
static void
master_queue_message (struct Master *mst, struct TransmitMessage *tmit_msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "%p master_queue_message()\n", mst);

  if (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_METHOD == tmit_msg->first_ptype)
  {
    tmit_msg->id = ++mst->max_message_id;
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "%p master_queue_message: message_id=%" PRIu64 "\n",
                mst, tmit_msg->id);
    struct GNUNET_PSYC_MessageMethod *pmeth
      = (struct GNUNET_PSYC_MessageMethod *) &tmit_msg[1];

    if (pmeth->flags & GNUNET_PSYC_MASTER_TRANSMIT_STATE_RESET)
    {
      pmeth->state_delta = GNUNET_htonll (GNUNET_PSYC_STATE_RESET);
    }
    else if (pmeth->flags & GNUNET_PSYC_MASTER_TRANSMIT_STATE_MODIFY)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "%p master_queue_message: state_delta=%" PRIu64 "\n",
                  mst, tmit_msg->id - mst->max_state_message_id);
      pmeth->state_delta = GNUNET_htonll (tmit_msg->id
                                          - mst->max_state_message_id);
      mst->max_state_message_id = tmit_msg->id;
    }
    else
    {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    "%p master_queue_message: state not modified\n", mst);
      pmeth->state_delta = GNUNET_htonll (GNUNET_PSYC_STATE_NOT_MODIFIED);
    }

    if (pmeth->flags & GNUNET_PSYC_MASTER_TRANSMIT_STATE_HASH)
    {
      /// @todo add state_hash to PSYC header
    }
  }
}


/**
 * Queue a message from a channel slave for sending to the multicast group.
 */
static void
slave_queue_message (struct Slave *slv, struct TransmitMessage *tmit_msg)
{
  if (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_METHOD == tmit_msg->first_ptype)
  {
    struct GNUNET_PSYC_MessageMethod *pmeth
      = (struct GNUNET_PSYC_MessageMethod *) &tmit_msg[1];
    pmeth->state_delta = GNUNET_htonll (GNUNET_PSYC_STATE_NOT_MODIFIED);
    tmit_msg->id = ++slv->max_request_id;
  }
}


/**
 * Queue PSYC message parts for sending to multicast.
 *
 * @param chn
 *        Channel to send to.
 * @param client
 *        Client the message originates from.
 * @param data_size
 *        Size of @a data.
 * @param data
 *        Concatenated message parts.
 * @param first_ptype
 *        First message part type in @a data.
 * @param last_ptype
 *        Last message part type in @a data.
 */
static struct TransmitMessage *
queue_message (struct Channel *chn,
               struct GNUNET_SERVICE_Client *client,
               size_t data_size,
               const void *data,
               uint16_t first_ptype, uint16_t last_ptype)
{
  struct TransmitMessage *
    tmit_msg = GNUNET_malloc (sizeof (*tmit_msg) + data_size);
  GNUNET_memcpy (&tmit_msg[1], data, data_size);
  tmit_msg->client = client;
  tmit_msg->size = data_size;
  tmit_msg->first_ptype = first_ptype;
  tmit_msg->last_ptype = last_ptype;

  /* FIXME: separate queue per message ID */

  GNUNET_CONTAINER_DLL_insert_tail (chn->tmit_head, chn->tmit_tail, tmit_msg);

  chn->is_master
    ? master_queue_message (chn->master, tmit_msg)
    : slave_queue_message (chn->slave, tmit_msg);
  return tmit_msg;
}


/**
 * Cancel transmission of current message.
 *
 * @param chn	  Channel to send to.
 * @param client  Client the message originates from.
 */
static void
transmit_cancel (struct Channel *chn, struct GNUNET_SERVICE_Client *client)
{
  uint16_t type = GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_CANCEL;

  struct GNUNET_MessageHeader msg;
  msg.size = htons (sizeof (msg));
  msg.type = htons (type);

  queue_message (chn, client, sizeof (msg), &msg, type, type);
  transmit_message (chn);

  /* FIXME: cleanup */
}


static int
check_client_psyc_message (void *cls,
                           const struct GNUNET_MessageHeader *msg)
{
  return GNUNET_OK;
}


/**
 * Incoming message from a master or slave client.
 */
static void
handle_client_psyc_message (void *cls,
                            const struct GNUNET_MessageHeader *msg)
{
  struct Client *c = cls;
  struct GNUNET_SERVICE_Client *client = c->client;
  struct Channel *chn = c->channel;
  if (NULL == chn)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (client);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Received message from client.\n", chn);
  GNUNET_PSYC_log_message (GNUNET_ERROR_TYPE_DEBUG, msg);

  if (GNUNET_YES != chn->is_ready)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "%p Channel is not ready yet, disconnecting client.\n", chn);
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (client);
    return;
  }

  uint16_t size = ntohs (msg->size);
  if (GNUNET_MULTICAST_FRAGMENT_MAX_PAYLOAD < size - sizeof (*msg))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%p Message payload too large: %u < %u.\n",
                chn,
                (unsigned int) GNUNET_MULTICAST_FRAGMENT_MAX_PAYLOAD,
                (unsigned int) (size - sizeof (*msg)));
    GNUNET_break (0);
    transmit_cancel (chn, client);
    GNUNET_SERVICE_client_drop (client);
    return;
  }

  uint16_t first_ptype = 0, last_ptype = 0;
  if (GNUNET_SYSERR
      == GNUNET_PSYC_receive_check_parts (size - sizeof (*msg),
                                          (const char *) &msg[1],
                                          &first_ptype, &last_ptype))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%p Received invalid message part from client.\n", chn);
    GNUNET_break (0);
    transmit_cancel (chn, client);
    GNUNET_SERVICE_client_drop (client);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Received message with first part type %u and last part type %u.\n",
              chn, first_ptype, last_ptype);

  queue_message (chn, client, size - sizeof (*msg), &msg[1],
                 first_ptype, last_ptype);
  transmit_message (chn);
  /* FIXME: send a few ACKs even before transmit_notify is called */

  GNUNET_SERVICE_client_continue (client);
};


/**
 * Received result of GNUNET_PSYCSTORE_membership_store()
 */
static void
store_recv_membership_store_result (void *cls,
                                    int64_t result,
                                    const char *err_msg,
                                    uint16_t err_msg_size)
{
  struct Operation *op = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p GNUNET_PSYCSTORE_membership_store() returned %" PRId64 " (%.*s)\n",
              op->channel,
              result,
              (int) err_msg_size,
              err_msg);

  if (NULL != op->client)
    client_send_result (op->client, op->op_id, result, err_msg, err_msg_size);
  op_remove (op);
}


/**
 * Client requests to add/remove a slave in the membership database.
 */
static void
handle_client_membership_store (void *cls,
                                const struct ChannelMembershipStoreRequest *req)
{
  struct Client *c = cls;
  struct GNUNET_SERVICE_Client *client = c->client;
  struct Channel *chn = c->channel;
  if (NULL == chn)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (client);
    return;
  }

  struct Operation *op = op_add (chn, client, req->op_id, 0);

  uint64_t announced_at = GNUNET_ntohll (req->announced_at);
  uint64_t effective_since = GNUNET_ntohll (req->effective_since);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Received membership store request from client.\n", chn);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p did_join: %u, announced_at: %" PRIu64 ", effective_since: %" PRIu64 "\n",
              chn, req->did_join, announced_at, effective_since);

  GNUNET_PSYCSTORE_membership_store (store, &chn->pub_key, &req->slave_pub_key,
                                     req->did_join, announced_at, effective_since,
                                     0, /* FIXME: group_generation */
                                     &store_recv_membership_store_result, op);
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Received a fragment for GNUNET_PSYCSTORE_fragment_get(),
 * in response to a history request from a client.
 */
static int
store_recv_fragment_history (void *cls,
                             struct GNUNET_MULTICAST_MessageHeader *mmsg,
                             enum GNUNET_PSYCSTORE_MessageFlags flags)
{
  struct Operation *op = cls;
  if (NULL == op->client)
  { /* Requesting client already disconnected. */
    return GNUNET_NO;
  }
  struct Channel *chn = op->channel;

  struct GNUNET_PSYC_MessageHeader *pmsg;
  uint16_t msize = ntohs (mmsg->header.size);
  uint16_t psize = sizeof (*pmsg) + msize - sizeof (*mmsg);

  struct GNUNET_OperationResultMessage *
    res = GNUNET_malloc (sizeof (*res) + psize);
  res->header.size = htons (sizeof (*res) + psize);
  res->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_HISTORY_RESULT);
  res->op_id = op->op_id;
  res->result_code = GNUNET_htonll (GNUNET_OK);

  pmsg = (struct GNUNET_PSYC_MessageHeader *) &res[1];
  GNUNET_PSYC_message_header_init (pmsg, mmsg, flags | GNUNET_PSYC_MESSAGE_HISTORIC);
  GNUNET_memcpy (&res[1], pmsg, psize);

  /** @todo FIXME: send only to requesting client */
  client_send_msg (chn, &res->header);

  GNUNET_free (res);
  return GNUNET_YES;
}


/**
 * Received the result of GNUNET_PSYCSTORE_fragment_get(),
 * in response to a history request from a client.
 */
static void
store_recv_fragment_history_result (void *cls, int64_t result,
                                    const char *err_msg, uint16_t err_msg_size)
{
  struct Operation *op = cls;
  if (NULL == op->client)
  { /* Requesting client already disconnected. */
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p History replay #%" PRIu64 ": "
              "PSYCSTORE returned %" PRId64 " (%.*s)\n",
              op->channel, GNUNET_ntohll (op->op_id), result, err_msg_size, err_msg);

  if (op->flags & GNUNET_PSYC_HISTORY_REPLAY_REMOTE)
  {
    /** @todo Multicast replay request for messages not found locally. */
  }

  client_send_result (op->client, op->op_id, result, err_msg, err_msg_size);
  op_remove (op);
}


static int
check_client_history_replay (void *cls,
                             const struct GNUNET_PSYC_HistoryRequestMessage *req)
{
  return GNUNET_OK;
}


/**
 * Client requests channel history.
 */
static void
handle_client_history_replay (void *cls,
                              const struct GNUNET_PSYC_HistoryRequestMessage *req)
{
  struct Client *c = cls;
  struct GNUNET_SERVICE_Client *client = c->client;
  struct Channel *chn = c->channel;
  if (NULL == chn)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (client);
    return;
  }

  uint16_t size = ntohs (req->header.size);
  const char *method_prefix = (const char *) &req[1];

  if (size < sizeof (*req) + 1
      || '\0' != method_prefix[size - sizeof (*req) - 1])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%p History replay #%" PRIu64 ": "
                "invalid method prefix. size: %u < %u?\n",
                chn,
                GNUNET_ntohll (req->op_id),
                size,
                (unsigned int) sizeof (*req) + 1);
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (client);
    return;
  }

  struct Operation *op = op_add (chn, client, req->op_id, ntohl (req->flags));

  if (0 == req->message_limit)
  {
    GNUNET_PSYCSTORE_message_get (store, &chn->pub_key, NULL,
                                  GNUNET_ntohll (req->start_message_id),
                                  GNUNET_ntohll (req->end_message_id),
                                  0, method_prefix,
                                  &store_recv_fragment_history,
                                  &store_recv_fragment_history_result, op);
  }
  else
  {
    GNUNET_PSYCSTORE_message_get_latest (store, &chn->pub_key, NULL,
                                         GNUNET_ntohll (req->message_limit),
                                         method_prefix,
                                         &store_recv_fragment_history,
                                         &store_recv_fragment_history_result,
                                         op);
  }
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Received state var from PSYCstore, send it to client.
 */
static int
store_recv_state_var (void *cls, const char *name,
                      const void *value, uint32_t value_size)
{
  struct Operation *op = cls;
  struct GNUNET_OperationResultMessage *res;
  struct GNUNET_MQ_Envelope *env;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p state_get #%" PRIu64 " - received var from PSYCstore: %s\n",
              op->channel, GNUNET_ntohll (op->op_id), name);

  if (NULL != name) /* First part */
  {
    uint16_t name_size = strnlen (name, GNUNET_PSYC_MODIFIER_MAX_PAYLOAD) + 1;
    struct GNUNET_PSYC_MessageModifier *mod;
    env = GNUNET_MQ_msg_extra (res,
                               sizeof (*mod) + name_size + value_size,
                               GNUNET_MESSAGE_TYPE_PSYC_STATE_RESULT);
    res->op_id = op->op_id;

    mod = (struct GNUNET_PSYC_MessageModifier *) &res[1];
    mod->header.size = htons (sizeof (*mod) + name_size + value_size);
    mod->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MODIFIER);
    mod->name_size = htons (name_size);
    mod->value_size = htonl (value_size);
    mod->oper = htons (GNUNET_PSYC_OP_ASSIGN);
    GNUNET_memcpy (&mod[1], name, name_size);
    GNUNET_memcpy (((char *) &mod[1]) + name_size, value, value_size);
  }
  else /* Continuation */
  {
    struct GNUNET_MessageHeader *mod;
    env = GNUNET_MQ_msg_extra (res,
                               sizeof (*mod) + value_size,
                               GNUNET_MESSAGE_TYPE_PSYC_STATE_RESULT);
    res->op_id = op->op_id;

    mod = (struct GNUNET_MessageHeader *) &res[1];
    mod->size = htons (sizeof (*mod) + value_size);
    mod->type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MOD_CONT);
    GNUNET_memcpy (&mod[1], value, value_size);
  }

  // FIXME: client might have been disconnected
  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (op->client), env);
  return GNUNET_YES;
}


/**
 * Received result of GNUNET_PSYCSTORE_state_get()
 * or GNUNET_PSYCSTORE_state_get_prefix()
 */
static void
store_recv_state_result (void *cls, int64_t result,
                         const char *err_msg, uint16_t err_msg_size)
{
  struct Operation *op = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p state_get #%" PRIu64 ": "
              "PSYCSTORE returned %" PRId64 " (%.*s)\n",
              op->channel, GNUNET_ntohll (op->op_id), result, err_msg_size, err_msg);

  // FIXME: client might have been disconnected
  client_send_result (op->client, op->op_id, result, err_msg, err_msg_size);
  op_remove (op);
}


static int
check_client_state_get (void *cls,
                         const struct StateRequest *req)
{
  struct Client *c = cls;
  struct Channel *chn = c->channel;
  if (NULL == chn)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  uint16_t name_size = ntohs (req->header.size) - sizeof (*req);
  const char *name = (const char *) &req[1];
  if (0 == name_size || '\0' != name[name_size - 1])
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  return GNUNET_OK;
}


/**
 * Client requests best matching state variable from PSYCstore.
 */
static void
handle_client_state_get (void *cls,
                         const struct StateRequest *req)
{
  struct Client *c = cls;
  struct GNUNET_SERVICE_Client *client = c->client;
  struct Channel *chn = c->channel;

  const char *name = (const char *) &req[1];
  struct Operation *op = op_add (chn, client, req->op_id, 0);
  GNUNET_PSYCSTORE_state_get (store, &chn->pub_key, name,
                              &store_recv_state_var,
                              &store_recv_state_result, op);
  GNUNET_SERVICE_client_continue (client);
}


static int
check_client_state_get_prefix (void *cls,
                               const struct StateRequest *req)
{
  struct Client *c = cls;
  struct Channel *chn = c->channel;
  if (NULL == chn)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  uint16_t name_size = ntohs (req->header.size) - sizeof (*req);
  const char *name = (const char *) &req[1];
  if (0 == name_size || '\0' != name[name_size - 1])
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  return GNUNET_OK;
}


/**
 * Client requests state variables with a given prefix from PSYCstore.
 */
static void
handle_client_state_get_prefix (void *cls,
                                const struct StateRequest *req)
{
  struct Client *c = cls;
  struct GNUNET_SERVICE_Client *client = c->client;
  struct Channel *chn = c->channel;

  const char *name = (const char *) &req[1];
  struct Operation *op = op_add (chn, client, req->op_id, 0);
  GNUNET_PSYCSTORE_state_get_prefix (store, &chn->pub_key, name,
                                     &store_recv_state_var,
                                     &store_recv_state_result, op);
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Initialize the PSYC service.
 *
 * @param cls Closure.
 * @param server The initialized server.
 * @param c Configuration to use.
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_SERVICE_Handle *svc)
{
  cfg = c;
  service = svc;
  store = GNUNET_PSYCSTORE_connect (cfg);
  stats = GNUNET_STATISTICS_create ("psyc", cfg);
  masters = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);
  slaves = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);
  channel_slaves = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);
  recv_cache = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task, NULL);
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
("psyc",
 GNUNET_SERVICE_OPTION_NONE,
 run,
 client_notify_connect,
 client_notify_disconnect,
 NULL,
 GNUNET_MQ_hd_fixed_size (client_master_start,
                          GNUNET_MESSAGE_TYPE_PSYC_MASTER_START,
                          struct MasterStartRequest,
                          NULL),
 GNUNET_MQ_hd_var_size (client_slave_join,
                        GNUNET_MESSAGE_TYPE_PSYC_SLAVE_JOIN,
                        struct SlaveJoinRequest,
                        NULL),
 GNUNET_MQ_hd_var_size (client_join_decision,
                        GNUNET_MESSAGE_TYPE_PSYC_JOIN_DECISION,
                        struct GNUNET_PSYC_JoinDecisionMessage,
                        NULL),
 GNUNET_MQ_hd_var_size (client_psyc_message,
                        GNUNET_MESSAGE_TYPE_PSYC_MESSAGE,
                        struct GNUNET_MessageHeader,
                        NULL),
 GNUNET_MQ_hd_fixed_size (client_membership_store,
                          GNUNET_MESSAGE_TYPE_PSYC_CHANNEL_MEMBERSHIP_STORE,
                          struct ChannelMembershipStoreRequest,
                          NULL),
 GNUNET_MQ_hd_var_size (client_history_replay,
                        GNUNET_MESSAGE_TYPE_PSYC_HISTORY_REPLAY,
                        struct GNUNET_PSYC_HistoryRequestMessage,
                        NULL),
 GNUNET_MQ_hd_var_size (client_state_get,
                        GNUNET_MESSAGE_TYPE_PSYC_STATE_GET,
                        struct StateRequest,
                        NULL),
 GNUNET_MQ_hd_var_size (client_state_get_prefix,
                        GNUNET_MESSAGE_TYPE_PSYC_STATE_GET_PREFIX,
                        struct StateRequest,
                        NULL));

/* end of gnunet-service-psyc.c */
