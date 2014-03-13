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
 * All connected masters and slaves.
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

  /**
   * Buffer with message to be transmitted.
   */
  char *buf;

  /**
   * Size of @a buf
   */
  uint16_t size
;
  /**
   * @see enum MessageState
   */
  uint8_t state;
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
 * fragment_id -> FragmentEntry
 */
struct FragmentEntry
{
  struct GNUNET_MULTICAST_MessageHeader *mmsg;
  uint16_t ref_count;
};


/**
 * Entry in the @a recv_msgs hash map of a @a Channel.
 * message_id -> FragmentCache
 */
struct FragmentCache
{
  /**
   * Total size of header fragments (METHOD & MODIFIERs)
   */
  uint64_t header_size;

  /**
   * Fragment IDs stored in @a recv_cache.
   */
  struct GNUNET_CONTAINER_Heap *fragments;
};


/**
 * Common part of the client context for both a master and slave channel.
 */
struct Channel
{
  struct GNUNET_SERVER_Client *client;

  struct TransmitMessage *tmit_head;
  struct TransmitMessage *tmit_tail;

  /**
   * Received fragments not yet sent to the client.
   * message_id -> FragmentCache
   */
  struct GNUNET_CONTAINER_MultiHashMap *recv_msgs;

  /**
   * FIXME
   */
  GNUNET_SCHEDULER_TaskIdentifier tmit_task;

  /**
   * Public key of the channel.
   */
  struct GNUNET_CRYPTO_EddsaPublicKey pub_key;

  /**
   * Hash of @a pub_key.
   */
  struct GNUNET_HashCode pub_key_hash;

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
   * FIXME
   */
  uint8_t in_transmit;

  /**
   * Is this a channel master (#GNUNET_YES), or slave (#GNUNET_NO)?
   */
  uint8_t is_master;

  /**
   * Ready to receive messages from client? #GNUNET_YES or #GNUNET_NO
   */
  uint8_t ready;

  /**
   * Is the client disconnected? #GNUNET_YES or #GNUNET_NO
   */
  uint8_t disconnected;
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
  struct GNUNET_MULTICAST_OriginMessageHandle *tmit_handle;

  /**
   * Maximum message ID for this channel.
   *
   * Incremented before sending a message, thus the message_id in messages sent
   * starts from 1.
   */
  uint64_t max_message_id;

  /**
   * ID of the last message that contains any state operations.
   * 0 if there is no such message.
   */
  uint64_t max_state_message_id;

  /**
   * Maximum group generation for this channel.
   */
  uint64_t max_group_generation;

  /**
   * @see enum GNUNET_PSYC_Policy
   */
  uint32_t policy;
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
  struct GNUNET_CRYPTO_EddsaPrivateKey slave_key;

  /**
   * Handle for the multicast member.
   */
  struct GNUNET_MULTICAST_Member *member;

  /**
   * Transmit handle for multicast.
   */
  struct GNUNET_MULTICAST_MemberRequestHandle *tmit_handle;

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
  struct GNUNET_MessageHeader *join_req;

  /**
   * Maximum message ID for this channel.
   */
  uint64_t max_message_id;

  /**
   * Maximum request ID for this channel.
   */
  uint64_t max_request_id;
};


static inline void
transmit_message (struct Channel *ch, uint8_t inc_msg_id);


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
  /* FIXME: fragment_cache_clear */

  if (ch->is_master)
  {
    struct Master *mst = (struct Master *) ch;
    if (NULL != mst->origin)
      GNUNET_MULTICAST_origin_stop (mst->origin);
    GNUNET_CONTAINER_multihashmap_remove (clients, &ch->pub_key_hash, mst);
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

  struct Channel *ch
    = GNUNET_SERVER_client_get_user_context (client, struct Channel);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%p Client disconnected\n", ch);

  if (NULL == ch)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%p User context is NULL in client_disconnect()\n", ch);
    GNUNET_break (0);
    return;
  }

  ch->disconnected = GNUNET_YES;

  /* Send pending messages to multicast before cleanup. */
  if (NULL != ch->tmit_head)
  {
    transmit_message (ch, GNUNET_NO);
  }
  else
  {
    client_cleanup (ch);
  }
}


/**
 * Master receives a join request from a slave.
 */
static void
join_cb (void *cls, const struct GNUNET_CRYPTO_EddsaPublicKey *slave_key,
         const struct GNUNET_MessageHeader *join_req,
         struct GNUNET_MULTICAST_JoinHandle *jh)
{

}


static void
membership_test_cb (void *cls,
                    const struct GNUNET_CRYPTO_EddsaPublicKey *slave_key,
                    uint64_t message_id, uint64_t group_generation,
                    struct GNUNET_MULTICAST_MembershipTestHandle *mth)
{

}


static void
replay_fragment_cb (void *cls,
                    const struct GNUNET_CRYPTO_EddsaPublicKey *slave_key,
                    uint64_t fragment_id, uint64_t flags,
                    struct GNUNET_MULTICAST_ReplayHandle *rh)

{
}


static void
replay_message_cb (void *cls,
                   const struct GNUNET_CRYPTO_EddsaPublicKey *slave_key,
                   uint64_t message_id,
                   uint64_t fragment_offset,
                   uint64_t flags,
                   struct GNUNET_MULTICAST_ReplayHandle *rh)
{

}


static void
fragment_store_result (void *cls, int64_t result, const char *err_msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "fragment_store() returned %l (%s)\n", result, err_msg);
}


static void
message_to_client (struct Channel *ch,
                   const struct GNUNET_MULTICAST_MessageHeader *mmsg)
{
  uint16_t size = ntohs (mmsg->header.size);
  struct GNUNET_PSYC_MessageHeader *pmsg;
  uint16_t psize = sizeof (*pmsg) + size - sizeof (*mmsg);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Sending message to client. "
              "fragment_id: %" PRIu64 ", message_id: %" PRIu64 "\n",
              ch, GNUNET_ntohll (mmsg->fragment_id),
              GNUNET_ntohll (mmsg->message_id));

  pmsg = GNUNET_malloc (psize);
  pmsg->header.size = htons (psize);
  pmsg->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE);
  pmsg->message_id = mmsg->message_id;

  memcpy (&pmsg[1], &mmsg[1], size - sizeof (*mmsg));

  GNUNET_SERVER_notification_context_add (nc, ch->client);
  GNUNET_SERVER_notification_context_unicast (nc, ch->client,
                                              (const struct GNUNET_MessageHeader *) pmsg,
                                              GNUNET_NO);
  GNUNET_free (pmsg);
}


/**
 * Convert an uint64_t in network byte order to a HashCode
 * that can be used as key in a MultiHashMap
 */
static inline void
hash_key_from_nll (struct GNUNET_HashCode *key, uint64_t n)
{
  /* use little-endian order, as idx_of MultiHashMap casts key to unsigned int */

  n = ((n <<  8) & 0xFF00FF00FF00FF00ULL) | ((n >>  8) & 0x00FF00FF00FF00FFULL);
  n = ((n << 16) & 0xFFFF0000FFFF0000ULL) | ((n >> 16) & 0x0000FFFF0000FFFFULL);

  *key = (struct GNUNET_HashCode) {{ 0 }};
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
  *key = (struct GNUNET_HashCode) {{ 0 }};
  *((uint64_t *) key) = n;
#else
  #error byteorder undefined
#endif
}


static void
fragment_cache_insert (struct Channel *ch,
                       const struct GNUNET_HashCode *msg_id,
                       struct FragmentCache *frag_cache,
                       const struct GNUNET_MULTICAST_MessageHeader *mmsg,
                       uint16_t last_part_type)
{
  uint16_t size = ntohs (mmsg->header.size);
  struct GNUNET_CONTAINER_MultiHashMap
    *chan_msgs = GNUNET_CONTAINER_multihashmap_get (recv_cache,
                                                    &ch->pub_key_hash);

  if (NULL == frag_cache)
  {
    frag_cache = GNUNET_new (struct FragmentCache);
    frag_cache->fragments
      = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);

    if (NULL == ch->recv_msgs)
    {
      ch->recv_msgs = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);
    }
    GNUNET_CONTAINER_multihashmap_put (ch->recv_msgs, msg_id, frag_cache,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);

    if (NULL == chan_msgs)
    {
      chan_msgs = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);
      GNUNET_CONTAINER_multihashmap_put (recv_cache, &ch->pub_key_hash, chan_msgs,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
    }
  }

  struct GNUNET_HashCode *frag_id = GNUNET_new (struct GNUNET_HashCode);
  hash_key_from_nll (frag_id, mmsg->fragment_id);
  struct FragmentEntry
    *frag_entry = GNUNET_CONTAINER_multihashmap_get (chan_msgs, frag_id);
  if (NULL == frag_entry)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%p Adding message fragment to cache. "
                "fragment_id: %" PRIu64 ", "
                "header_size: %" PRIu64 " + %" PRIu64 ").\n",
                ch, GNUNET_ntohll (mmsg->fragment_id),
                frag_cache->header_size, size);
    frag_entry = GNUNET_new (struct FragmentEntry);
    frag_entry->ref_count = 1;
    frag_entry->mmsg = GNUNET_malloc (size);
    memcpy (frag_entry->mmsg, mmsg, size);
    GNUNET_CONTAINER_multihashmap_put (chan_msgs, frag_id, frag_entry,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  }
  else
  {
    frag_entry->ref_count++;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%p Message fragment already in cache. "
                "fragment_id: %" PRIu64 ", ref_count: %u\n",
                ch, GNUNET_ntohll (mmsg->fragment_id), frag_entry->ref_count);
  }

  switch (last_part_type)
  {
  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_METHOD:
  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MODIFIER:
  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MOD_CONT:
    frag_cache->header_size += size;
  }
  GNUNET_CONTAINER_heap_insert (frag_cache->fragments, frag_id,
                                GNUNET_ntohll (mmsg->fragment_id));
}


static void
fragment_cache_clear (struct Channel *ch,
                      const struct GNUNET_HashCode *msg_id,
                      struct FragmentCache *frag_cache,
                      uint8_t send_to_client)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Clearing message fragment cache.\n", ch);

  struct GNUNET_CONTAINER_MultiHashMap
    *chan_msgs = GNUNET_CONTAINER_multihashmap_get (recv_cache,
                                                    &ch->pub_key_hash);
  GNUNET_assert (NULL != chan_msgs);
  struct GNUNET_HashCode *frag_id;

  while ((frag_id = GNUNET_CONTAINER_heap_remove_root (frag_cache->fragments)))
  {
    struct FragmentEntry
      *frag_entry = GNUNET_CONTAINER_multihashmap_get (chan_msgs, frag_id);
    if (frag_entry != NULL)
    {
      if (GNUNET_YES == send_to_client)
      {
        message_to_client (ch, frag_entry->mmsg);
      }
      if (1 == frag_entry->ref_count)
      {
        GNUNET_CONTAINER_multihashmap_remove (chan_msgs, frag_id, frag_entry);
        GNUNET_free (frag_entry->mmsg);
        GNUNET_free (frag_entry);
      }
      else
      {
        frag_entry->ref_count--;
      }
    }
    GNUNET_free (frag_id);
  }

  GNUNET_CONTAINER_multihashmap_remove (ch->recv_msgs, msg_id, frag_cache);
  GNUNET_CONTAINER_heap_destroy (frag_cache->fragments);
  GNUNET_free (frag_cache);
}


/**
 * Incoming message fragment from multicast.
 *
 * Store it using PSYCstore and send it to the client of the channel.
 */
static void
message_cb (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct Channel *ch = cls;
  uint16_t type = ntohs (msg->type);
  uint16_t size = ntohs (msg->size);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Received message of type %u and size %u from multicast.\n",
              ch, type, size);

  switch (type)
  {
  case GNUNET_MESSAGE_TYPE_MULTICAST_MESSAGE:
  {
    GNUNET_PSYCSTORE_fragment_store (store, &ch->pub_key,
                                     (const struct
                                      GNUNET_MULTICAST_MessageHeader *) msg,
                                     0, NULL, NULL);

#if TODO
    /* FIXME: apply modifiers to state in PSYCstore */
    GNUNET_PSYCSTORE_state_modify (store, &ch->pub_key,
                                   GNUNET_ntohll (mmsg->message_id),
                                   meth->mod_count, mods,
                                   rcb, rcb_cls);
#endif

    const struct GNUNET_MULTICAST_MessageHeader
      *mmsg = (const struct GNUNET_MULTICAST_MessageHeader *) msg;

    uint16_t ptype = GNUNET_PSYC_message_last_part (size - sizeof (*mmsg),
                                                    (const char *) &mmsg[1]);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Last message part type %u\n", ptype);

    if (GNUNET_NO == ptype)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "%p Received message with invalid parts from multicast. "
                  "Dropping message.\n", ch);
      GNUNET_break_op (0);
      break;
    }

    struct GNUNET_HashCode msg_id;
    hash_key_from_nll (&msg_id, mmsg->message_id);

    struct FragmentCache *frag_cache = NULL;
    if (NULL != ch->recv_msgs)
      frag_cache = GNUNET_CONTAINER_multihashmap_get (ch->recv_msgs, &msg_id);

    switch (ptype)
    {
    case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_DATA:
    case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_END:
      /* FIXME: check state flag / max_state_message_id */
      if (NULL == frag_cache)
      {
        message_to_client (ch, mmsg);
        break;
      }
      else
      {
        if (GNUNET_ntohll (mmsg->fragment_offset) == frag_cache->header_size)
        { /* first data fragment after the header, send cached fragments */
          fragment_cache_clear (ch, &msg_id, frag_cache, GNUNET_YES);
          message_to_client (ch, mmsg);
          break;
        }
        else
        { /* still missing fragments from the header, cache data fragment */
          /* fall thru */
        }
      }

    case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_METHOD:
    case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MODIFIER:
    case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MOD_CONT:
      /* not all modifiers arrived yet, cache fragment */
      fragment_cache_insert (ch, &msg_id, frag_cache, mmsg, ptype);
      break;

    case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_CANCEL:
      if (NULL != frag_cache)
      { /* fragments not yet sent to client, remove from cache */
        fragment_cache_clear (ch, &msg_id, frag_cache, GNUNET_NO);
      }
      else
      {
        message_to_client (ch, mmsg);
      }
      break;
    }
    break;
  }
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "%p Dropping unknown message of type %u and size %u.\n",
                ch, type, size);
  }
}


/**
 * Incoming request fragment from multicast for a master.
 *
 * @param cls		Master.
 * @param slave_key	Sending slave's public key.
 * @param msg		The message.
 * @param flags		Request flags.
 */
static void
request_cb (void *cls, const struct GNUNET_CRYPTO_EddsaPublicKey *slave_key,
            const struct GNUNET_MessageHeader *msg,
            enum GNUNET_MULTICAST_MessageFlags flags)
{
  struct Master *mst = cls;
  struct Channel *ch = &mst->channel;

  uint16_t type = ntohs (msg->type);
  uint16_t size = ntohs (msg->size);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Received request of type %u and size %u from multicast.\n",
              ch, type, size);

  switch (type)
  {
  case GNUNET_MESSAGE_TYPE_MULTICAST_REQUEST:
  {
    const struct GNUNET_MULTICAST_RequestHeader *req
      = (const struct GNUNET_MULTICAST_RequestHeader *) msg;

    /* FIXME: see message_cb() */
    if (GNUNET_NO == GNUNET_PSYC_message_last_part (size - sizeof (*req),
                                                    (const char *) &req[1]))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "%p Dropping message with invalid parts "
                  "received from multicast.\n", ch);
      GNUNET_break_op (0);
      break;
    }

    struct GNUNET_PSYC_MessageHeader *pmsg;
    uint16_t psize = sizeof (*pmsg) + size - sizeof (*req);
    pmsg = GNUNET_malloc (psize);
    pmsg->header.size = htons (psize);
    pmsg->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE);
    pmsg->message_id = req->request_id;
    pmsg->flags = htonl (GNUNET_PSYC_MESSAGE_REQUEST);

    memcpy (&pmsg[1], &req[1], size - sizeof (*req));

    GNUNET_SERVER_notification_context_add (nc, ch->client);
    GNUNET_SERVER_notification_context_unicast (nc, ch->client,
                                                (const struct GNUNET_MessageHeader *) pmsg,
                                                GNUNET_NO);
    GNUNET_free (pmsg);
    break;
  }
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%p Dropping unknown request of type %u and size %u.\n",
                ch, type, size);
    GNUNET_break_op (0);
  }
}


/**
 * Response from PSYCstore with the current counter values for a channel master.
 */
static void
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
    ch->ready = GNUNET_YES;
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
      = GNUNET_MULTICAST_member_join (cfg, &ch->pub_key, &slv->slave_key,
                                      &slv->origin,
                                      slv->relay_count, slv->relays,
                                      slv->join_req, join_cb,
                                      membership_test_cb,
                                      replay_fragment_cb, replay_message_cb,
                                      message_cb, ch);
    ch->ready = GNUNET_YES;
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
  struct Channel *ch = &mst->channel;
  ch->client = client;
  ch->is_master = GNUNET_YES;
  mst->policy = ntohl (req->policy);
  mst->priv_key = req->channel_key;
  GNUNET_CRYPTO_eddsa_key_get_public (&mst->priv_key, &ch->pub_key);
  GNUNET_CRYPTO_hash (&ch->pub_key, sizeof (ch->pub_key), &ch->pub_key_hash);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Master connected to channel %s.\n",
              mst, GNUNET_h2s (&ch->pub_key_hash));

  GNUNET_PSYCSTORE_counters_get (store, &ch->pub_key, master_counters_cb, mst);

  GNUNET_SERVER_client_set_user_context (client, &mst->channel);
  GNUNET_CONTAINER_multihashmap_put (clients, &ch->pub_key_hash, mst,
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
  struct Channel *ch = &slv->channel;
  slv->channel.client = client;
  slv->channel.is_master = GNUNET_NO;
  slv->slave_key = req->slave_key;
  ch->pub_key = req->channel_key;
  GNUNET_CRYPTO_hash (&ch->pub_key, sizeof (ch->pub_key),
                      &ch->pub_key_hash);
  slv->origin = req->origin;
  slv->relay_count = ntohl (req->relay_count);
  if (0 < slv->relay_count)
  {
    const struct GNUNET_PeerIdentity *relays
      = (const struct GNUNET_PeerIdentity *) &req[1];
    slv->relays
      = GNUNET_malloc (slv->relay_count * sizeof (struct GNUNET_PeerIdentity));
    uint32_t i;
    for (i = 0; i < slv->relay_count; i++)
      memcpy (&slv->relays[i], &relays[i], sizeof (*relays));
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Slave connected to channel %s.\n",
              slv, GNUNET_h2s (&ch->pub_key_hash));

  GNUNET_PSYCSTORE_counters_get (store, &ch->pub_key, slave_counters_cb, slv);

  GNUNET_SERVER_client_set_user_context (client, &slv->channel);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Send acknowledgement to a client.
 *
 * Sent after a message fragment has been passed on to multicast.
 *
 * @param ch The channel struct for the client.
 */
static void
send_message_ack (struct Channel *ch)
{
  struct GNUNET_MessageHeader res;
  res.size = htons (sizeof (res));
  res.type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_ACK);

  GNUNET_SERVER_notification_context_add (nc, ch->client);
  GNUNET_SERVER_notification_context_unicast (nc, ch->client, &res,
                                              GNUNET_NO);
}


/**
 * Callback for the transmit functions of multicast.
 */
static int
transmit_notify (void *cls, size_t *data_size, void *data)
{
  struct Channel *ch = cls;
  struct TransmitMessage *tmit_msg = ch->tmit_head;

  if (NULL == tmit_msg || *data_size < tmit_msg->size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%p transmit_notify: nothing to send.\n", ch);
    *data_size = 0;
    return GNUNET_NO;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p transmit_notify: sending %u bytes.\n", ch, tmit_msg->size);

  *data_size = tmit_msg->size;
  memcpy (data, tmit_msg->buf, *data_size);

  GNUNET_CONTAINER_DLL_remove (ch->tmit_head, ch->tmit_tail, tmit_msg);
  GNUNET_free (tmit_msg);

  int ret = (MSG_STATE_END < ch->tmit_state) ? GNUNET_NO : GNUNET_YES;
  send_message_ack (ch);

  if (0 == ch->tmit_task)
  {
    if (NULL != ch->tmit_head)
    {
      transmit_message (ch, GNUNET_NO);
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
master_transmit_message (struct Master *mst, uint8_t inc_msg_id)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%p master_transmit_message()\n", mst);
  mst->channel.tmit_task = 0;
  if (NULL == mst->tmit_handle)
  {
    if (GNUNET_YES == inc_msg_id)
      mst->max_message_id++;
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
slave_transmit_message (struct Slave *slv, uint8_t inc_msg_id)
{
  slv->channel.tmit_task = 0;
  if (NULL == slv->tmit_handle)
  {
    if (GNUNET_YES == inc_msg_id)
      slv->max_message_id++;
    slv->tmit_handle
      = GNUNET_MULTICAST_member_to_origin (slv->member, slv->max_request_id,
                                           slave_transmit_notify, slv);
  }
  else
  {
    GNUNET_MULTICAST_member_to_origin_resume (slv->tmit_handle);
  }
}


static inline void
transmit_message (struct Channel *ch, uint8_t inc_msg_id)
{
  ch->is_master
    ? master_transmit_message ((struct Master *) ch, inc_msg_id)
    : slave_transmit_message ((struct Slave *) ch, inc_msg_id);
}


static void
transmit_error (struct Channel *ch)
{
  struct GNUNET_MessageHeader *msg;
  struct TransmitMessage *tmit_msg = GNUNET_malloc (sizeof (*tmit_msg)
                                                    + sizeof (*msg));
  msg = (struct GNUNET_MessageHeader *) &tmit_msg[1];
  msg->size = ntohs (sizeof (*msg));
  msg->type = ntohs (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_CANCEL);

  tmit_msg->buf = (char *) &tmit_msg[1];
  tmit_msg->size = sizeof (*msg);
  tmit_msg->state = ch->tmit_state;
  GNUNET_CONTAINER_DLL_insert_tail (ch->tmit_head, ch->tmit_tail, tmit_msg);
  transmit_message (ch, GNUNET_NO);

  /* FIXME: cleanup */
}


/**
 * Incoming message from a client.
 */
static void
handle_psyc_message (void *cls, struct GNUNET_SERVER_Client *client,
                     const struct GNUNET_MessageHeader *msg)
{
  struct Channel *ch
    = GNUNET_SERVER_client_get_user_context (client, struct Channel);
  GNUNET_assert (NULL != ch);

  if (GNUNET_YES != ch->ready)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "%p Dropping message from client, channel is not ready yet.\n",
                ch);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  uint8_t inc_msg_id = GNUNET_NO;
  uint16_t size = ntohs (msg->size);
  uint16_t psize = 0, ptype = 0, pos = 0;

  if (GNUNET_MULTICAST_FRAGMENT_MAX_PAYLOAD < size - sizeof (*msg))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%p Message payload too large\n", ch);
    GNUNET_break (0);
    transmit_error (ch);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Received message from client.\n", ch);
  GNUNET_PSYC_log_message (GNUNET_ERROR_TYPE_DEBUG, msg);

  for (pos = 0; sizeof (*msg) + pos < size; pos += psize)
  {
    const struct GNUNET_MessageHeader *pmsg
      = (const struct GNUNET_MessageHeader *) ((char *) &msg[1] + pos);
    psize = ntohs (pmsg->size);
    ptype = ntohs (pmsg->type);
    if (psize < sizeof (*pmsg) || sizeof (*msg) + pos + psize > size)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "%p Received invalid message part of type %u and size %u "
                  "from client.\n", ch, ptype, psize);
      GNUNET_break (0);
      transmit_error (ch);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%p Received message part from client.\n", ch);
    GNUNET_PSYC_log_message (GNUNET_ERROR_TYPE_DEBUG, pmsg);

    if (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_METHOD == ptype)
      inc_msg_id = GNUNET_YES;
  }

  size -= sizeof (*msg);
  struct TransmitMessage *tmit_msg = GNUNET_malloc (sizeof (*tmit_msg) + size);
  tmit_msg->buf = (char *) &tmit_msg[1];
  memcpy (tmit_msg->buf, &msg[1], size);
  tmit_msg->size = size;
  tmit_msg->state = ch->tmit_state;
  GNUNET_CONTAINER_DLL_insert_tail (ch->tmit_head, ch->tmit_tail, tmit_msg);
  transmit_message (ch, inc_msg_id);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
};


/**
 * Client requests to add a slave to the membership database.
 */
static void
handle_slave_add (void *cls, struct GNUNET_SERVER_Client *client,
                  const struct GNUNET_MessageHeader *msg)
{

}


/**
 * Client requests to remove a slave from the membership database.
 */
static void
handle_slave_remove (void *cls, struct GNUNET_SERVER_Client *client,
                     const struct GNUNET_MessageHeader *msg)
{

}


/**
 * Client requests channel history from PSYCstore.
 */
static void
handle_story_request (void *cls, struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *msg)
{

}


/**
 * Client requests best matching state variable from PSYCstore.
 */
static void
handle_state_get (void *cls, struct GNUNET_SERVER_Client *client,
                  const struct GNUNET_MessageHeader *msg)
{

}


/**
 * Client requests state variables with a given prefix from PSYCstore.
 */
static void
handle_state_get_prefix (void *cls, struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *msg)
{

}


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

    { &handle_psyc_message, NULL,
      GNUNET_MESSAGE_TYPE_PSYC_MESSAGE, 0 },

    { &handle_slave_add, NULL,
      GNUNET_MESSAGE_TYPE_PSYC_CHANNEL_SLAVE_ADD, 0 },

    { &handle_slave_remove, NULL,
      GNUNET_MESSAGE_TYPE_PSYC_CHANNEL_SLAVE_RM, 0 },

    { &handle_story_request, NULL,
      GNUNET_MESSAGE_TYPE_PSYC_STORY_REQUEST, 0 },

    { &handle_state_get, NULL,
      GNUNET_MESSAGE_TYPE_PSYC_STATE_GET, 0 },

    { &handle_state_get_prefix, NULL,
      GNUNET_MESSAGE_TYPE_PSYC_STATE_GET_PREFIX, 0 }
  };

  cfg = c;
  store = GNUNET_PSYCSTORE_connect (cfg);
  stats = GNUNET_STATISTICS_create ("psyc", cfg);
  clients = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);
  recv_cache = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);
  nc = GNUNET_SERVER_notification_context_create (server, 1);
  GNUNET_SERVER_add_handlers (server, handlers);
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

/* end of gnunet-service-psycstore.c */
