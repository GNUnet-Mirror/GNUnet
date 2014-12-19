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

  struct GNUNET_SERVER_Client *client;

  /**
   * ID assigned to the message.
   */
  uint64_t id;

  /**
   * Size of message.
   */
  uint16_t size;

  /**
   * @see enum MessageState
   */
  uint8_t state;

  /**
   * Whether a message ACK has already been sent to the client.
   * #GNUNET_YES or #GNUNET_NO
   */
  uint8_t ack_sent;

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
   * Is the message queued for delivery to the client?
   * i.e. added to the recv_msgs queue
   */
  uint8_t is_queued;
};


/**
 * List of connected clients.
 */
struct ClientListItem
{
  struct ClientListItem *prev;
  struct ClientListItem *next;
  struct GNUNET_SERVER_Client *client;
};


/**
 * Common part of the client context for both a channel master and slave.
 */
struct Channel
{
  struct ClientListItem *clients_head;
  struct ClientListItem *clients_tail;

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
   * @see enum MessageState
   */
  uint8_t tmit_state;

  /**
   * Is this a channel master (#GNUNET_YES), or slave (#GNUNET_NO)?
   */
  uint8_t is_master;

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
};


/**
 * Client context for a channel master.
 */
struct Master
{
  /**
   * Channel struct common for Master and Slave
   */
  struct Channel chn;

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
   * member_key -> struct GNUNET_MULTICAST_JoinHandle *
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
  struct Channel chn;

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
};


struct OperationClosure
{
  struct GNUNET_SERVER_Client *client;
  struct Channel *chn;
  uint64_t op_id;
};


static void
transmit_message (struct Channel *chn);


static uint64_t
message_queue_drop (struct Channel *chn);


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
    GNUNET_STATISTICS_destroy (stats, GNUNET_YES);
    stats = NULL;
  }
}


/**
 * Clean up master data structures after a client disconnected.
 */
static void
cleanup_master (struct Master *mst)
{
  struct Channel *chn = &mst->chn;

  if (NULL != mst->origin)
    GNUNET_MULTICAST_origin_stop (mst->origin, NULL, NULL); // FIXME
  GNUNET_CONTAINER_multihashmap_destroy (mst->join_reqs);
  GNUNET_CONTAINER_multihashmap_remove (masters, &chn->pub_key_hash, chn);
}


/**
 * Clean up slave data structures after a client disconnected.
 */
static void
cleanup_slave (struct Slave *slv)
{
  struct Channel *chn = &slv->chn;
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
  GNUNET_CONTAINER_multihashmap_remove (slaves, &chn->pub_key_hash, chn);
}


/**
 * Clean up channel data structures after a client disconnected.
 */
static void
cleanup_channel (struct Channel *chn)
{
  message_queue_drop (chn);
  GNUNET_CONTAINER_multihashmap_remove_all (recv_cache, &chn->pub_key_hash);

  if (NULL != chn->store_op)
  {
    GNUNET_PSYCSTORE_operation_cancel (chn->store_op);
    chn->store_op = NULL;
  }

  (GNUNET_YES == chn->is_master)
    ? cleanup_master ((struct Master *) chn)
    : cleanup_slave ((struct Slave *) chn);
  GNUNET_free (chn);
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

  struct Channel *
    chn = GNUNET_SERVER_client_get_user_context (client, struct Channel);

  if (NULL == chn)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%p User context is NULL in client_disconnect()\n", chn);
    GNUNET_break (0);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Client (%s) disconnected from channel %s\n",
              chn, (GNUNET_YES == chn->is_master) ? "master" : "slave",
              GNUNET_h2s (&chn->pub_key_hash));

  struct ClientListItem *cli = chn->clients_head;
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

  if (NULL == chn->clients_head)
  { /* Last client disconnected. */
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
 * Send message to all clients connected to the channel.
 */
static void
client_send_msg (const struct Channel *chn,
                 const struct GNUNET_MessageHeader *msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "%p Sending message to clients.\n", chn);

  struct ClientListItem *cli = chn->clients_head;
  while (NULL != cli)
  {
    GNUNET_SERVER_notification_context_add (nc, cli->client);
    GNUNET_SERVER_notification_context_unicast (nc, cli->client, msg, GNUNET_NO);
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
 * @param err_msg
 *        Error message to include (or NULL for none).
 */
static void
client_send_result (struct GNUNET_SERVER_Client *client, uint64_t op_id,
                    int64_t result_code, const char *err_msg)
{
  struct OperationResult *res;
  size_t err_size = 0;

  if (NULL != err_msg)
    err_size = strnlen (err_msg,
                        GNUNET_SERVER_MAX_MESSAGE_SIZE - sizeof (*res)) + 1;
  res = GNUNET_malloc (sizeof (struct OperationResult) + err_size);
  res->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_RESULT_CODE);
  res->header.size = htons (sizeof (struct OperationResult) + err_size);
  res->result_code = GNUNET_htonll (result_code + INT64_MAX + 1);
  res->op_id = op_id;
  if (0 < err_size)
  {
    memcpy (&res[1], err_msg, err_size);
    ((char *) &res[1])[err_size - 1] = '\0';
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "%p Sending result to client for operation #%" PRIu64 ": "
              "%" PRId64 " (%s)\n",
	      client, GNUNET_ntohll (op_id), result_code, err_msg);

  GNUNET_SERVER_notification_context_add (nc, client);
  GNUNET_SERVER_notification_context_unicast (nc, client, &res->header,
                                              GNUNET_NO);
  GNUNET_free (res);
}


/**
 * Closure for join_mem_test_cb()
 */
struct JoinMemTestClosure
{
  struct GNUNET_CRYPTO_EcdsaPublicKey slave_key;
  struct Channel *chn;
  struct GNUNET_MULTICAST_JoinHandle *jh;
  struct GNUNET_PSYC_JoinRequestMessage *join_msg;
};


/**
 * Membership test result callback used for join requests.
 */
static void
join_mem_test_cb (void *cls, int64_t result, const char *err_msg)
{
  struct JoinMemTestClosure *jcls = cls;

  if (GNUNET_NO == result && GNUNET_YES == jcls->chn->is_master)
  { /* Pass on join request to client if this is a master channel */
    struct Master *mst = (struct Master *) jcls->chn;
    struct GNUNET_HashCode slave_key_hash;
    GNUNET_CRYPTO_hash (&jcls->slave_key, sizeof (jcls->slave_key),
                        &slave_key_hash);
    GNUNET_CONTAINER_multihashmap_put (mst->join_reqs, &slave_key_hash, jcls->jh,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
    client_send_msg (jcls->chn, &jcls->join_msg->header);
  }
  else
  {
    // FIXME: add relays
    GNUNET_MULTICAST_join_decision (jcls->jh, result, 0, NULL, NULL);
  }
  GNUNET_free (jcls->join_msg);
  GNUNET_free (jcls);
}


/**
 * Incoming join request from multicast.
 */
static void
mcast_recv_join_request (void *cls,
                         const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key,
                         const struct GNUNET_MessageHeader *join_msg,
                         struct GNUNET_MULTICAST_JoinHandle *jh)
{
  struct Channel *chn = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%p Got join request.\n", chn);

  uint16_t join_msg_size = 0;
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
                  chn, ntohs (join_msg->type));
    }
  }

  struct GNUNET_PSYC_JoinRequestMessage *
    req = GNUNET_malloc (sizeof (*req) + join_msg_size);
  req->header.size = htons (sizeof (*req) + join_msg_size);
  req->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_JOIN_REQUEST);
  req->slave_key = *slave_key;
  if (0 < join_msg_size)
    memcpy (&req[1], join_msg, join_msg_size);

  struct JoinMemTestClosure *jcls = GNUNET_malloc (sizeof (*jcls));
  jcls->slave_key = *slave_key;
  jcls->chn = chn;
  jcls->jh = jh;
  jcls->join_msg = req;

  GNUNET_PSYCSTORE_membership_test (store, &chn->pub_key, slave_key,
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
  struct Channel *chn = &slv->chn;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Got join decision: %d\n", slv, is_admitted);

  uint16_t join_resp_size = (NULL != join_resp) ? ntohs (join_resp->size) : 0;
  struct GNUNET_PSYC_JoinDecisionMessage *
    dcsn = slv->join_dcsn = GNUNET_malloc (sizeof (*dcsn) + join_resp_size);
  dcsn->header.size = htons (sizeof (*dcsn) + join_resp_size);
  dcsn->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_JOIN_DECISION);
  dcsn->is_admitted = htonl (is_admitted);
  if (0 < join_resp_size)
    memcpy (&dcsn[1], join_resp, join_resp_size);

  client_send_msg (chn, &dcsn->header);

  if (GNUNET_YES == is_admitted)
  {
    chn->is_ready = GNUNET_YES;
  }
  else
  {
    slv->member = NULL;
  }
}


/**
 * Received result of GNUNET_PSYCSTORE_membership_test()
 */
static void
store_recv_membership_test_result (void *cls, int64_t result, const char *err_msg)
{
  struct GNUNET_MULTICAST_MembershipTestHandle *mth = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p GNUNET_PSYCSTORE_membership_test() returned %" PRId64 " (%s)\n",
              mth, result, err_msg);

  GNUNET_MULTICAST_membership_test_result (mth, result);
}


/**
 * Incoming membership test request from multicast.
 */
static void
mcast_recv_membership_test (void *cls,
                            const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key,
                            uint64_t message_id, uint64_t group_generation,
                            struct GNUNET_MULTICAST_MembershipTestHandle *mth)
{
  struct Channel *chn = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Received membership test request from multicast.\n",
              mth);
  GNUNET_PSYCSTORE_membership_test (store, &chn->pub_key, slave_key,
                                    message_id, group_generation,
                                    &store_recv_membership_test_result, mth);
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
store_recv_fragment_replay_result (void *cls, int64_t result, const char *err_msg)
{
  struct GNUNET_MULTICAST_ReplayHandle *rh = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Fragment replay: PSYCSTORE returned %" PRId64 " (%s)\n",
              rh, result, err_msg);

  switch (result)
  {
  case GNUNET_YES:
    break;

  case GNUNET_NO:
    GNUNET_MULTICAST_replay_response (rh, NULL,
                                      GNUNET_MULTICAST_REC_NOT_FOUND);
    break;

  case GNUNET_PSYCSTORE_MEMBERSHIP_TEST_FAILED:
    GNUNET_MULTICAST_replay_response (rh, NULL,
                                      GNUNET_MULTICAST_REC_ACCESS_DENIED);
    break;

  case GNUNET_SYSERR:
    GNUNET_MULTICAST_replay_response (rh, NULL,
                                      GNUNET_MULTICAST_REC_INTERNAL_ERROR);
    break;
  }
  GNUNET_MULTICAST_replay_response_end (rh);
}


/**
 * Incoming fragment replay request from multicast.
 */
static void
mcast_recv_replay_fragment (void *cls,
                            const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key,
                            uint64_t fragment_id, uint64_t flags,
                            struct GNUNET_MULTICAST_ReplayHandle *rh)

{
  struct Channel *chn = cls;
  GNUNET_PSYCSTORE_fragment_get (store, &chn->pub_key, slave_key,
                                 fragment_id, fragment_id,
                                 &store_recv_fragment_replay,
                                 &store_recv_fragment_replay_result, rh);
}


/**
 * Incoming message replay request from multicast.
 */
static void
mcast_recv_replay_message (void *cls,
                           const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key,
                           uint64_t message_id,
                           uint64_t fragment_offset,
                           uint64_t flags,
                           struct GNUNET_MULTICAST_ReplayHandle *rh)
{
  struct Channel *chn = cls;
  GNUNET_PSYCSTORE_message_get (store, &chn->pub_key, slave_key,
                                message_id, message_id,
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
 * Send multicast message to all clients connected to the channel.
 */
static void
client_send_mcast_msg (struct Channel *chn,
                       const struct GNUNET_MULTICAST_MessageHeader *mmsg,
                       uint32_t flags)
{
  struct GNUNET_PSYC_MessageHeader *pmsg;
  uint16_t size = ntohs (mmsg->header.size);
  uint16_t psize = sizeof (*pmsg) + size - sizeof (*mmsg);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Sending multicast message to client. "
              "fragment_id: %" PRIu64 ", message_id: %" PRIu64 "\n",
              chn, GNUNET_ntohll (mmsg->fragment_id),
              GNUNET_ntohll (mmsg->message_id));

  pmsg = GNUNET_malloc (psize);
  pmsg->header.size = htons (psize);
  pmsg->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE);
  pmsg->message_id = mmsg->message_id;
  pmsg->fragment_offset = mmsg->fragment_offset;
  pmsg->flags = htonl (flags);

  memcpy (&pmsg[1], &mmsg[1], size - sizeof (*mmsg));
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
  struct Channel *chn = &mst->chn;

  struct GNUNET_PSYC_MessageHeader *pmsg;
  uint16_t size = ntohs (req->header.size);
  uint16_t psize = sizeof (*pmsg) + size - sizeof (*req);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Sending multicast request to client. "
              "fragment_id: %" PRIu64 ", message_id: %" PRIu64 "\n",
              chn, GNUNET_ntohll (req->fragment_id),
              GNUNET_ntohll (req->request_id));

  pmsg = GNUNET_malloc (psize);
  pmsg->header.size = htons (psize);
  pmsg->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE);
  pmsg->message_id = req->request_id;
  pmsg->fragment_offset = req->fragment_offset;
  pmsg->flags = htonl (GNUNET_PSYC_MESSAGE_REQUEST);

  memcpy (&pmsg[1], &req[1], size - sizeof (*req));
  client_send_msg (chn, &pmsg->header);
  GNUNET_free (pmsg);
}


/**
 * Insert a multicast message fragment into the queue belonging to the message.
 *
 * @param chn           Channel.
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
    fragq = GNUNET_new (struct FragmentQueue);
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
                "%p Adding message fragment to cache. "
                "message_id: %" PRIu64 ", fragment_id: %" PRIu64 "\n",
                chn, GNUNET_ntohll (mmsg->message_id),
                GNUNET_ntohll (mmsg->fragment_id));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%p header_size: %" PRIu64 " + %u\n",
                chn, fragq->header_size, size);
    cache_entry = GNUNET_new (struct RecvCacheEntry);
    cache_entry->ref_count = 1;
    cache_entry->mmsg = GNUNET_malloc (size);
    memcpy (cache_entry->mmsg, mmsg, size);
    GNUNET_CONTAINER_multihashmap_put (chan_msgs, &frag_id_hash, cache_entry,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  }
  else
  {
    cache_entry->ref_count++;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%p Message fragment is already in cache. "
                "message_id: %" PRIu64 ", fragment_id: %" PRIu64
                ", ref_count: %u\n",
                chn, GNUNET_ntohll (mmsg->message_id),
                GNUNET_ntohll (mmsg->fragment_id), cache_entry->ref_count);
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
                  chn, GNUNET_ntohll (mmsg->message_id));

      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "%p Adding message %" PRIu64 " to queue.\n",
                  chn, GNUNET_ntohll (mmsg->message_id));
      fragq->state = MSG_FRAG_STATE_DATA;
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "%p Header of message %" PRIu64 " is NOT complete yet: "
                  "%" PRIu64 " != %" PRIu64 "\n",
                  chn, GNUNET_ntohll (mmsg->message_id), frag_offset,
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
                  "%p Message %" PRIu64 " is NOT complete yet: "
                  "%" PRIu64 " != %" PRIu64 "\n",
                  chn, GNUNET_ntohll (mmsg->message_id), frag_offset,
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
 * @param chn      Channel.
 * @param msg_id  ID of the message @a fragq belongs to.
 * @param fragq   Fragment queue of the message.
 * @param drop    Drop message without delivering to client?
 *                #GNUNET_YES or #GNUNET_NO.
 */
static void
fragment_queue_run (struct Channel *chn, uint64_t msg_id,
                    struct FragmentQueue *fragq, uint8_t drop)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "%p Running message fragment queue for message %" PRIu64
              " (state: %u).\n",
              chn, msg_id, fragq->state);

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

    if (MSG_FRAG_STATE_HEADER == fragq->state)
    {
      /* Check if there's a missing message before the current one */
      if (GNUNET_PSYC_STATE_NOT_MODIFIED == fragq->state_delta)
      {
        if (!(fragq->flags & GNUNET_PSYC_MESSAGE_ORDER_ANY)
            && msg_id - 1 != chn->max_message_id)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                      "%p Out of order message. "
                      "(%" PRIu64 " - 1 != %" PRIu64 ")\n",
                      chn, msg_id, chn->max_message_id);
          break;
        }
      }
      else
      {
        if (msg_id - fragq->state_delta != chn->max_state_message_id)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                      "%p Out of order stateful message. "
                      "(%" PRIu64 " - %" PRIu64 " != %" PRIu64 ")\n",
                      chn, msg_id, fragq->state_delta, chn->max_state_message_id);
          break;
        }
#if TODO
        /* FIXME: apply modifiers to state in PSYCstore */
        GNUNET_PSYCSTORE_state_modify (store, &chn->pub_key, message_id,
                                       store_recv_state_modify_result, cls);
#endif
        chn->max_state_message_id = msg_id;
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
store_recv_fragment_store_result (void *cls, int64_t result, const char *err_msg)
{
  struct Channel *chn = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p GNUNET_PSYCSTORE_fragment_store() returned %" PRId64 " (%s)\n",
              chn, result, err_msg);
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
              "%p Received multicast message of size %u.\n",
              chn, size);

  GNUNET_PSYCSTORE_fragment_store (store, &chn->pub_key, mmsg, 0,
                                   &store_recv_fragment_store_result, chn);

  uint16_t first_ptype = 0, last_ptype = 0;
  if (GNUNET_SYSERR
      == GNUNET_PSYC_receive_check_parts (size - sizeof (*mmsg),
                                          (const char *) &mmsg[1],
                                          &first_ptype, &last_ptype))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "%p Dropping incoming multicast message with invalid parts.\n",
                chn);
    GNUNET_break_op (0);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Message parts: first: type %u, last: type %u\n",
              first_ptype, last_ptype);

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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Received multicast request of size %u.\n",
              mst, size);

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
  struct Channel *chn = &mst->chn;
  chn->store_op = NULL;

  struct GNUNET_PSYC_CountersResultMessage res;
  res.header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_MASTER_START_ACK);
  res.header.size = htons (sizeof (res));
  res.result_code = htonl (result - INT32_MIN);
  res.max_message_id = GNUNET_htonll (max_message_id);

  if (GNUNET_OK == result || GNUNET_NO == result)
  {
    mst->max_message_id = max_message_id;
    chn->max_message_id = max_message_id;
    chn->max_state_message_id = max_state_message_id;
    mst->max_group_generation = max_group_generation;
    mst->origin
      = GNUNET_MULTICAST_origin_start (cfg, &mst->priv_key, max_fragment_id,
                                       &mcast_recv_join_request,
                                       &mcast_recv_membership_test,
                                       &mcast_recv_replay_fragment,
                                       &mcast_recv_replay_message,
                                       &mcast_recv_request,
                                       &mcast_recv_message, chn);
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
  struct Channel *chn = &slv->chn;
  chn->store_op = NULL;

  struct GNUNET_PSYC_CountersResultMessage res;
  res.header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_SLAVE_JOIN_ACK);
  res.header.size = htons (sizeof (res));
  res.result_code = htonl (result - INT32_MIN);
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
                                      &mcast_recv_join_request,
                                      &mcast_recv_join_decision,
                                      &mcast_recv_membership_test,
                                      &mcast_recv_replay_fragment,
                                      &mcast_recv_replay_message,
                                      &mcast_recv_message, chn);
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
client_recv_master_start (void *cls, struct GNUNET_SERVER_Client *client,
                          const struct GNUNET_MessageHeader *msg)
{
  const struct MasterStartRequest *req
    = (const struct MasterStartRequest *) msg;

  struct GNUNET_CRYPTO_EddsaPublicKey pub_key;
  struct GNUNET_HashCode pub_key_hash;

  GNUNET_CRYPTO_eddsa_key_get_public (&req->channel_key, &pub_key);
  GNUNET_CRYPTO_hash (&pub_key, sizeof (pub_key), &pub_key_hash);

  struct Master *
    mst = GNUNET_CONTAINER_multihashmap_get (masters, &pub_key_hash);
  struct Channel *chn;

  if (NULL == mst)
  {
    mst = GNUNET_new (struct Master);
    mst->policy = ntohl (req->policy);
    mst->priv_key = req->channel_key;
    mst->join_reqs = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);

    chn = &mst->chn;
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
    chn = &mst->chn;

    struct GNUNET_PSYC_CountersResultMessage res;
    res.header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_MASTER_START_ACK);
    res.header.size = htons (sizeof (res));
    res.result_code = htonl ((uint32_t) GNUNET_OK + INT32_MIN);
    res.max_message_id = GNUNET_htonll (mst->max_message_id);

    GNUNET_SERVER_notification_context_add (nc, client);
    GNUNET_SERVER_notification_context_unicast (nc, client, &res.header,
                                                GNUNET_NO);
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Client connected as master to channel %s.\n",
              mst, GNUNET_h2s (&chn->pub_key_hash));

  struct ClientListItem *cli = GNUNET_new (struct ClientListItem);
  cli->client = client;
  GNUNET_CONTAINER_DLL_insert (chn->clients_head, chn->clients_tail, cli);

  GNUNET_SERVER_client_set_user_context (client, chn);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handle a connecting client joining as a channel slave.
 */
static void
client_recv_slave_join (void *cls, struct GNUNET_SERVER_Client *client,
                        const struct GNUNET_MessageHeader *msg)
{
  const struct SlaveJoinRequest *req
    = (const struct SlaveJoinRequest *) msg;
  uint16_t req_size = ntohs (req->header.size);

  struct GNUNET_CRYPTO_EcdsaPublicKey slv_pub_key;
  struct GNUNET_HashCode pub_key_hash, slv_pub_key_hash;

  GNUNET_CRYPTO_ecdsa_key_get_public (&req->slave_key, &slv_pub_key);
  GNUNET_CRYPTO_hash (&slv_pub_key, sizeof (slv_pub_key), &slv_pub_key_hash);
  GNUNET_CRYPTO_hash (&req->channel_key, sizeof (req->channel_key), &pub_key_hash);

  struct GNUNET_CONTAINER_MultiHashMap *
    chn_slv = GNUNET_CONTAINER_multihashmap_get (channel_slaves, &pub_key_hash);
  struct Slave *slv = NULL;
  struct Channel *chn;

  if (NULL != chn_slv)
  {
    slv = GNUNET_CONTAINER_multihashmap_get (chn_slv, &slv_pub_key_hash);
  }
  if (NULL == slv)
  {
    slv = GNUNET_new (struct Slave);
    slv->priv_key = req->slave_key;
    slv->pub_key = slv_pub_key;
    slv->pub_key_hash = slv_pub_key_hash;
    slv->origin = req->origin;
    slv->relay_count = ntohl (req->relay_count);

    const struct GNUNET_PeerIdentity *
      relays = (const struct GNUNET_PeerIdentity *) &req[1];
    uint16_t relay_size = slv->relay_count * sizeof (*relays);
    uint16_t join_msg_size = 0;

    if (sizeof (*req) + relay_size + sizeof (struct GNUNET_MessageHeader)
        <= req_size)
    {
      join_msg_size = ntohs (slv->join_msg->header.size);
      slv->join_msg = GNUNET_malloc (join_msg_size);
      memcpy (slv->join_msg, ((char *) &req[1]) + relay_size, join_msg_size);
    }
    if (sizeof (*req) + relay_size + join_msg_size != req_size)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "%u + %u + %u != %u\n",
                  sizeof (*req), relay_size, join_msg_size, req_size);
      GNUNET_break (0);
      GNUNET_SERVER_client_disconnect (client);
      GNUNET_free (slv);
      return;
    }
    if (0 < slv->relay_count)
    {
      slv->relays = GNUNET_malloc (relay_size);
      memcpy (slv->relays, &req[1], relay_size);
    }

    chn = &slv->chn;
    chn->is_master = GNUNET_NO;
    chn->pub_key = req->channel_key;
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
    chn = &slv->chn;

    struct GNUNET_PSYC_CountersResultMessage res;
    res.header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_SLAVE_JOIN_ACK);
    res.header.size = htons (sizeof (res));
    res.result_code = htonl ((uint32_t) GNUNET_OK - INT32_MIN);
    res.max_message_id = GNUNET_htonll (chn->max_message_id);

    GNUNET_SERVER_notification_context_add (nc, client);
    GNUNET_SERVER_notification_context_unicast (nc, client, &res.header,
                                                GNUNET_NO);

    if (NULL == slv->member)
    {
      slv->member
        = GNUNET_MULTICAST_member_join (cfg, &chn->pub_key, &slv->priv_key,
                                        &slv->origin,
                                        slv->relay_count, slv->relays,
                                        &slv->join_msg->header,
                                        &mcast_recv_join_request,
                                        &mcast_recv_join_decision,
                                        &mcast_recv_membership_test,
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
      GNUNET_SERVER_notification_context_add (nc, client);
      GNUNET_SERVER_notification_context_unicast (nc, client,
                                                  &slv->join_dcsn->header,
                                                  GNUNET_NO);
    }
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Client connected as slave to channel %s.\n",
              slv, GNUNET_h2s (&chn->pub_key_hash));

  struct ClientListItem *cli = GNUNET_new (struct ClientListItem);
  cli->client = client;
  GNUNET_CONTAINER_DLL_insert (chn->clients_head, chn->clients_tail, cli);

  GNUNET_SERVER_client_set_user_context (client, chn);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
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


/**
 * Join decision from client.
 */
static void
client_recv_join_decision (void *cls, struct GNUNET_SERVER_Client *client,
                           const struct GNUNET_MessageHeader *msg)
{
  const struct GNUNET_PSYC_JoinDecisionMessage *dcsn
    = (const struct GNUNET_PSYC_JoinDecisionMessage *) msg;
  struct Channel *chn;
  struct Master *mst;
  struct JoinDecisionClosure jcls;

  chn = GNUNET_SERVER_client_get_user_context (client, struct Channel);
  if (NULL == chn)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_assert (GNUNET_YES == chn->is_master);
  mst = (struct Master *) chn;
  jcls.is_admitted = ntohl (dcsn->is_admitted);
  jcls.msg
    = (sizeof (*dcsn) + sizeof (*jcls.msg) <= ntohs (msg->size))
    ? (struct GNUNET_MessageHeader *) &dcsn[1]
    : NULL;

  struct GNUNET_HashCode slave_key_hash;
  GNUNET_CRYPTO_hash (&dcsn->slave_key, sizeof (dcsn->slave_key),
                      &slave_key_hash);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Got join decision (%d) from client for channel %s..\n",
              mst, jcls.is_admitted, GNUNET_h2s (&chn->pub_key_hash));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p ..and slave %s.\n",
              mst, GNUNET_h2s (&slave_key_hash));

  GNUNET_CONTAINER_multihashmap_get_multiple (mst->join_reqs, &slave_key_hash,
                                              &mcast_send_join_decision, &jcls);
  GNUNET_CONTAINER_multihashmap_remove_all (mst->join_reqs, &slave_key_hash);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Send acknowledgement to a client.
 *
 * Sent after a message fragment has been passed on to multicast.
 *
 * @param chn The channel struct for the client.
 */
static void
send_message_ack (struct Channel *chn, struct GNUNET_SERVER_Client *client)
{
  struct GNUNET_MessageHeader res;
  res.size = htons (sizeof (res));
  res.type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_ACK);

  /* FIXME */
  GNUNET_SERVER_notification_context_add (nc, client);
  GNUNET_SERVER_notification_context_unicast (nc, client, &res, GNUNET_NO);
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
    *data_size = 0;
    return GNUNET_NO;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p transmit_notify: sending %u bytes.\n", chn, tmit_msg->size);

  *data_size = tmit_msg->size;
  memcpy (data, &tmit_msg[1], *data_size);

  int ret = (MSG_STATE_END < chn->tmit_state) ? GNUNET_NO : GNUNET_YES;

  if (NULL != tmit_msg->client && GNUNET_NO == tmit_msg->ack_sent)
    send_message_ack (chn, tmit_msg->client);

  GNUNET_CONTAINER_DLL_remove (chn->tmit_head, chn->tmit_tail, tmit_msg);
  GNUNET_free (tmit_msg);

  if (NULL != chn->tmit_head)
  {
    transmit_message (chn);
  }
  else if (GNUNET_YES == chn->is_disconnected)
  {
    /* FIXME: handle partial message (when still in_transmit) */
    cleanup_channel (chn);
  }
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
  if (NULL == mst->tmit_handle)
  {
    mst->tmit_handle
      = GNUNET_MULTICAST_origin_to_all (mst->origin, mst->max_message_id,
                                        mst->max_group_generation,
                                        master_transmit_notify, mst);
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
  if (NULL == slv->tmit_handle)
  {
    slv->tmit_handle
      = GNUNET_MULTICAST_member_to_origin (slv->member, slv->max_request_id,
                                           slave_transmit_notify, slv);
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
    ? master_transmit_message ((struct Master *) chn)
    : slave_transmit_message ((struct Slave *) chn);
}


/**
 * Queue a message from a channel master for sending to the multicast group.
 */
static void
master_queue_message (struct Master *mst, struct TransmitMessage *tmit_msg,
                     uint16_t first_ptype, uint16_t last_ptype)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%p master_queue_message()\n", mst);

  if (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_METHOD == first_ptype)
  {
    tmit_msg->id = ++mst->max_message_id;
    struct GNUNET_PSYC_MessageMethod *pmeth
      = (struct GNUNET_PSYC_MessageMethod *) &tmit_msg[1];

    if (pmeth->flags & GNUNET_PSYC_MASTER_TRANSMIT_STATE_RESET)
    {
      pmeth->state_delta = GNUNET_htonll (GNUNET_PSYC_STATE_RESET);
    }
    else if (pmeth->flags & GNUNET_PSYC_MASTER_TRANSMIT_STATE_MODIFY)
    {
      pmeth->state_delta = GNUNET_htonll (tmit_msg->id
                                          - mst->max_state_message_id);
    }
    else
    {
      pmeth->state_delta = GNUNET_htonll (GNUNET_PSYC_STATE_NOT_MODIFIED);
    }
  }
}


/**
 * Queue a message from a channel slave for sending to the multicast group.
 */
static void
slave_queue_message (struct Slave *slv, struct TransmitMessage *tmit_msg,
                     uint16_t first_ptype, uint16_t last_ptype)
{
  if (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_METHOD == first_ptype)
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
 * @param chn           Channel to send to.
 * @param client       Client the message originates from.
 * @param data_size    Size of @a data.
 * @param data         Concatenated message parts.
 * @param first_ptype  First message part type in @a data.
 * @param last_ptype   Last message part type in @a data.
 */
static struct TransmitMessage *
queue_message (struct Channel *chn,
               struct GNUNET_SERVER_Client *client,
               size_t data_size,
               const void *data,
               uint16_t first_ptype, uint16_t last_ptype)
{
  struct TransmitMessage *
    tmit_msg = GNUNET_malloc (sizeof (*tmit_msg) + data_size);
  memcpy (&tmit_msg[1], data, data_size);
  tmit_msg->client = client;
  tmit_msg->size = data_size;
  tmit_msg->state = chn->tmit_state;

  /* FIXME: separate queue per message ID */

  GNUNET_CONTAINER_DLL_insert_tail (chn->tmit_head, chn->tmit_tail, tmit_msg);

  chn->is_master
    ? master_queue_message ((struct Master *) chn, tmit_msg,
                            first_ptype, last_ptype)
    : slave_queue_message ((struct Slave *) chn, tmit_msg,
                           first_ptype, last_ptype);
  return tmit_msg;
}


/**
 * Cancel transmission of current message.
 *
 * @param chn	  Channel to send to.
 * @param client  Client the message originates from.
 */
static void
transmit_cancel (struct Channel *chn, struct GNUNET_SERVER_Client *client)
{
  uint16_t type = GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_CANCEL;

  struct GNUNET_MessageHeader msg;
  msg.size = htons (sizeof (msg));
  msg.type = htons (type);

  queue_message (chn, client, sizeof (msg), &msg, type, type);
  transmit_message (chn);

  /* FIXME: cleanup */
}


/**
 * Incoming message from a master or slave client.
 */
static void
client_recv_psyc_message (void *cls, struct GNUNET_SERVER_Client *client,
                          const struct GNUNET_MessageHeader *msg)
{
  struct Channel *
    chn = GNUNET_SERVER_client_get_user_context (client, struct Channel);
  GNUNET_assert (NULL != chn);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Received message from client.\n", chn);
  GNUNET_PSYC_log_message (GNUNET_ERROR_TYPE_DEBUG, msg);

  if (GNUNET_YES != chn->is_ready)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "%p Channel is not ready yet, disconnecting client.\n", chn);
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  uint16_t size = ntohs (msg->size);
  if (GNUNET_MULTICAST_FRAGMENT_MAX_PAYLOAD < size - sizeof (*msg))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%p Message payload too large.\n", chn);
    GNUNET_break (0);
    transmit_cancel (chn, client);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
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
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Received message with first part type %u and last part type %u.\n",
              chn, first_ptype, last_ptype);

  queue_message (chn, client, size - sizeof (*msg), &msg[1],
                 first_ptype, last_ptype);
  transmit_message (chn);
  /* FIXME: send a few ACKs even before transmit_notify is called */

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
};


struct MembershipStoreClosure
{
  struct GNUNET_SERVER_Client *client;
  struct Channel *chn;
  uint64_t op_id;
};


/**
 * Received result of GNUNET_PSYCSTORE_membership_store()
 */
static void
store_recv_membership_store_result (void *cls, int64_t result, const char *err_msg)
{
  struct MembershipStoreClosure *mcls = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p GNUNET_PSYCSTORE_membership_store() returned %" PRId64 " (%s)\n",
              mcls->chn, result, err_msg);

  client_send_result (mcls->client, mcls->op_id, result, err_msg);
}


/**
 * Client requests to add/remove a slave in the membership database.
 */
static void
client_recv_membership_store (void *cls, struct GNUNET_SERVER_Client *client,
                              const struct GNUNET_MessageHeader *msg)
{
  struct Channel *
    chn = GNUNET_SERVER_client_get_user_context (client, struct Channel);
  GNUNET_assert (NULL != chn);

  const struct ChannelMembershipStoreRequest *
    req = (const struct ChannelMembershipStoreRequest *) msg;

  struct MembershipStoreClosure *mcls = GNUNET_malloc (sizeof (*mcls));
  mcls->client = client;
  mcls->chn = chn;
  mcls->op_id = req->op_id;

  uint64_t announced_at = GNUNET_ntohll (req->announced_at);
  uint64_t effective_since = GNUNET_ntohll (req->effective_since);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Received membership store request from client.\n", chn);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p did_join: %u, announced_at: %" PRIu64 ", effective_since: %" PRIu64 "\n",
              chn, req->did_join, announced_at, effective_since);

  GNUNET_PSYCSTORE_membership_store (store, &chn->pub_key, &req->slave_key,
                                     req->did_join, announced_at, effective_since,
                                     0, /* FIXME: group_generation */
                                     &store_recv_membership_store_result, mcls);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


static int
store_recv_fragment_history (void *cls,
                             struct GNUNET_MULTICAST_MessageHeader *msg,
                             enum GNUNET_PSYCSTORE_MessageFlags flags)
{
  struct OperationClosure *opcls = cls;
  struct Channel *chn = opcls->chn;
  client_send_mcast_msg (chn, msg, GNUNET_PSYC_MESSAGE_HISTORIC);
  return GNUNET_YES;
}


/**
 * Received result of GNUNET_PSYCSTORE_fragment_get() for multicast replay.
 */
static void
store_recv_fragment_history_result (void *cls, int64_t result, const char *err_msg)
{
  struct OperationClosure *opcls = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p History replay #%" PRIu64 ": "
              "PSYCSTORE returned %" PRId64 " (%s)\n",
              opcls->chn, opcls->op_id, result, err_msg);

  client_send_result (opcls->client, opcls->op_id, result, err_msg);
}


/**
 * Client requests channel history from PSYCstore.
 */
static void
client_recv_history_replay (void *cls, struct GNUNET_SERVER_Client *client,
                            const struct GNUNET_MessageHeader *msg)
{
  struct Channel *
    chn = GNUNET_SERVER_client_get_user_context (client, struct Channel);
  GNUNET_assert (NULL != chn);

  const struct HistoryRequest *
    req = (const struct HistoryRequest *) msg;

  struct OperationClosure *opcls = GNUNET_malloc (sizeof (*opcls));
  opcls->client = client;
  opcls->chn = chn;
  opcls->op_id = req->op_id;

  if (0 == req->message_limit)
    GNUNET_PSYCSTORE_message_get (store, &chn->pub_key, NULL,
                                  GNUNET_ntohll (req->start_message_id),
                                  GNUNET_ntohll (req->end_message_id),
                                  &store_recv_fragment_history,
                                  &store_recv_fragment_history_result, opcls);
  else
    GNUNET_PSYCSTORE_message_get_latest (store, &chn->pub_key, NULL,
                                         GNUNET_ntohll (req->message_limit),
                                         &store_recv_fragment_history,
                                         &store_recv_fragment_history_result,
                                         opcls);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Received state var from PSYCstore, send it to client.
 */
static int
store_recv_state_var (void *cls, const char *name,
                      const void *value, size_t value_size)
{
  struct OperationClosure *opcls = cls;
  struct OperationResult *op;

  if (NULL != name)
  {
    uint16_t name_size = strnlen (name, GNUNET_PSYC_MODIFIER_MAX_PAYLOAD) + 1;
    struct GNUNET_PSYC_MessageModifier *mod;
    op = GNUNET_malloc (sizeof (*op) + sizeof (*mod) + name_size + value_size);
    op->header.size = htons (sizeof (*op) + sizeof (*mod) + name_size + value_size);
    op->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_STATE_RESULT);
    op->op_id = opcls->op_id;

    mod = (struct GNUNET_PSYC_MessageModifier *) &op[1];
    mod->header.size = htons (sizeof (*mod) + name_size + value_size);
    mod->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MODIFIER);
    mod->name_size = htons (name_size);
    mod->value_size = htonl (value_size);
    mod->oper = htons (GNUNET_ENV_OP_ASSIGN);
    memcpy (&mod[1], name, name_size);
    memcpy (((char *) &mod[1]) + name_size, value, value_size);
  }
  else
  {
    struct GNUNET_MessageHeader *mod;
    op = GNUNET_malloc (sizeof (*op) + sizeof (*mod) + value_size);
    op->header.size = htons (sizeof (*op) + sizeof (*mod) + value_size);
    op->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_STATE_RESULT);
    op->op_id = opcls->op_id;

    mod = (struct GNUNET_MessageHeader *) &op[1];
    mod->size = htons (sizeof (*mod) + value_size);
    mod->type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MOD_CONT);
    memcpy (&mod[1], value, value_size);
  }

  GNUNET_SERVER_notification_context_add (nc, opcls->client);
  GNUNET_SERVER_notification_context_unicast (nc, opcls->client, &op->header,
                                              GNUNET_NO);
  GNUNET_free (op);
  return GNUNET_YES;
}


/**
 * Received result of GNUNET_PSYCSTORE_state_get()
 * or GNUNET_PSYCSTORE_state_get_prefix()
 */
static void
store_recv_state_result (void *cls, int64_t result, const char *err_msg)
{
  struct OperationClosure *opcls = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p History replay #%" PRIu64 ": "
              "PSYCSTORE returned %" PRId64 " (%s)\n",
              opcls->chn, opcls->op_id, result, err_msg);

  client_send_result (opcls->client, opcls->op_id, result, err_msg);
}


/**
 * Client requests best matching state variable from PSYCstore.
 */
static void
client_recv_state_get (void *cls, struct GNUNET_SERVER_Client *client,
                       const struct GNUNET_MessageHeader *msg)
{
  struct Channel *
    chn = GNUNET_SERVER_client_get_user_context (client, struct Channel);
  GNUNET_assert (NULL != chn);

  const struct StateRequest *
    req = (const struct StateRequest *) msg;

  uint16_t name_size = ntohs (req->header.size) - sizeof (*req);
  const char *name = (const char *) &req[1];
  if (0 == name_size || '\0' != name[name_size - 1])
  {
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  struct OperationClosure *opcls = GNUNET_malloc (sizeof (*opcls));
  opcls->client = client;
  opcls->chn = chn;
  opcls->op_id = req->op_id;

  GNUNET_PSYCSTORE_state_get (store, &chn->pub_key, name,
                              &store_recv_state_var,
                              &store_recv_state_result, opcls);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Client requests state variables with a given prefix from PSYCstore.
 */
static void
client_recv_state_get_prefix (void *cls, struct GNUNET_SERVER_Client *client,
                              const struct GNUNET_MessageHeader *msg)
{
  struct Channel *
    chn = GNUNET_SERVER_client_get_user_context (client, struct Channel);
  GNUNET_assert (NULL != chn);

  const struct StateRequest *
    req = (const struct StateRequest *) msg;

  uint16_t name_size = ntohs (req->header.size) - sizeof (*req);
  const char *name = (const char *) &req[1];
  if (0 == name_size || '\0' != name[name_size - 1])
  {
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  struct OperationClosure *opcls = GNUNET_malloc (sizeof (*opcls));
  opcls->client = client;
  opcls->chn = chn;
  opcls->op_id = req->op_id;

  GNUNET_PSYCSTORE_state_get_prefix (store, &chn->pub_key, name,
                                     &store_recv_state_var,
                                     &store_recv_state_result, opcls);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);

}


static const struct GNUNET_SERVER_MessageHandler server_handlers[] = {
  { &client_recv_master_start, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_MASTER_START, 0 },

  { &client_recv_slave_join, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_SLAVE_JOIN, 0 },

  { &client_recv_join_decision, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_JOIN_DECISION, 0 },

  { &client_recv_psyc_message, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_MESSAGE, 0 },

  { &client_recv_membership_store, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_CHANNEL_MEMBERSHIP_STORE, 0 },

  { &client_recv_history_replay, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_HISTORY_REPLAY, 0 },

  { &client_recv_state_get, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_STATE_GET, 0 },

  { &client_recv_state_get_prefix, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_STATE_GET_PREFIX, 0 },

  { NULL, NULL, 0, 0 }
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
  cfg = c;
  store = GNUNET_PSYCSTORE_connect (cfg);
  stats = GNUNET_STATISTICS_create ("psyc", cfg);
  masters = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);
  slaves = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);
  channel_slaves = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);
  recv_cache = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);
  nc = GNUNET_SERVER_notification_context_create (server, 1);
  GNUNET_SERVER_add_handlers (server, server_handlers);
  GNUNET_SERVER_disconnect_notify (server, &client_disconnect, NULL);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                &shutdown_task, NULL);
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

/* end of gnunet-service-psyc.c */
