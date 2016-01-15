/*
     This file is part of GNUnet.
     Copyright (C) 2009 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file multicast/gnunet-service-multicast.c
 * @brief program that does multicast
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_signatures.h"
#include "gnunet_applications.h"
#include "gnunet_statistics_service.h"
#include "gnunet_core_service.h"
#include "gnunet_cadet_service.h"
#include "gnunet_multicast_service.h"
#include "multicast.h"

/**
 * Handle to our current configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Server handle.
 */
static struct GNUNET_SERVER_Handle *server;

/**
 * Core handle.
 * Only used during initialization.
 */
static struct GNUNET_CORE_Handle *core;

/**
 * CADET handle.
 */
static struct GNUNET_CADET_Handle *cadet;

/**
 * Identity of this peer.
 */
static struct GNUNET_PeerIdentity this_peer;

/**
 * Handle to the statistics service.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Notification context, simplifies client broadcasts.
 */
static struct GNUNET_SERVER_NotificationContext *nc;

/**
 * All connected origin clients.
 * Group's pub_key_hash -> struct Origin * (uniq)
 */
static struct GNUNET_CONTAINER_MultiHashMap *origins;

/**
 * All connected member clients.
 * Group's pub_key_hash -> struct Member * (multi)
 */
static struct GNUNET_CONTAINER_MultiHashMap *members;

/**
 * Connected member clients per group.
 * Group's pub_key_hash -> Member's pub_key_hash (uniq) -> struct Member * (uniq)
 */
static struct GNUNET_CONTAINER_MultiHashMap *group_members;

/**
 * Incoming CADET channels with connected children in the tree.
 * Group's pub_key_hash -> struct Channel * (multi)
 */
static struct GNUNET_CONTAINER_MultiHashMap *channels_in;

/**
 * Outgoing CADET channels connecting to parents in the tree.
 * Group's pub_key_hash -> struct Channel * (multi)
 */
static struct GNUNET_CONTAINER_MultiHashMap *channels_out;

/**
 * Incoming replay requests from CADET.
 * Group's pub_key_hash ->
 *   H(fragment_id, message_id, fragment_offset, flags) -> struct Channel *
 */
static struct GNUNET_CONTAINER_MultiHashMap *replay_req_cadet;

/**
 * Incoming replay requests from clients.
 * Group's pub_key_hash ->
 *   H(fragment_id, message_id, fragment_offset, flags) -> struct GNUNET_SERVER_Client *
 */
static struct GNUNET_CONTAINER_MultiHashMap *replay_req_client;


/**
 * Join status of a remote peer.
 */
enum JoinStatus
{
  JOIN_REFUSED  = -1,
  JOIN_NOT_ASKED = 0,
  JOIN_WAITING   = 1,
  JOIN_ADMITTED  = 2,
};

enum ChannelDirection
{
  DIR_INCOMING = 0,
  DIR_OUTGOING = 1,
};


/**
 * Context for a CADET channel.
 */
struct Channel
{
  /**
   * Group the channel belongs to.
   *
   * Only set for outgoing channels.
   */
  struct Group *grp;

  /**
   * CADET channel.
   */
  struct GNUNET_CADET_Channel *channel;

  /**
   * CADET transmission handle.
   */
  struct GNUNET_CADET_TransmitHandle *tmit_handle;

  /**
   * Public key of the target group.
   */
  struct GNUNET_CRYPTO_EddsaPublicKey group_pub_key;

  /**
   * Hash of @a group_pub_key.
   */
  struct GNUNET_HashCode group_pub_hash;

  /**
   * Public key of the joining member.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey member_pub_key;

  /**
   * Remote peer identity.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Is the remote peer admitted to the group?
   * @see enum JoinStatus
   */
  int8_t join_status;

  /**
   * Number of messages waiting to be sent to CADET.
   */
  uint8_t msgs_pending;

  /**
   * Channel direction.
   * @see enum ChannelDirection
   */
  uint8_t direction;
};


/**
 * List of connected clients.
 */
struct ClientList
{
  struct ClientList *prev;
  struct ClientList *next;
  struct GNUNET_SERVER_Client *client;
};

/**
 * Common part of the client context for both an origin and member.
 */
struct Group
{
  struct ClientList *clients_head;
  struct ClientList *clients_tail;

  /**
   * Public key of the group.
   */
  struct GNUNET_CRYPTO_EddsaPublicKey pub_key;

  /**
   * Hash of @a pub_key.
   */
  struct GNUNET_HashCode pub_key_hash;

  /**
   * Is this an origin (#GNUNET_YES), or member (#GNUNET_NO)?
   */
  uint8_t is_origin;

  /**
   * Is the client disconnected? #GNUNET_YES or #GNUNET_NO
   */
  uint8_t disconnected;
};


/**
 * Client context for a group's origin.
 */
struct Origin
{
  struct Group grp;

  /**
   * Private key of the group.
   */
  struct GNUNET_CRYPTO_EddsaPrivateKey priv_key;

  /**
   * Last message fragment ID sent to the group.
   */
  uint64_t max_fragment_id;
};


/**
 * Client context for a group member.
 */
struct Member
{
  struct Group grp;

  /**
   * Private key of the member.
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey priv_key;

  /**
   * Public key of the member.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey pub_key;

  /**
   * Hash of @a pub_key.
   */
  struct GNUNET_HashCode pub_key_hash;

  /**
   * Join request sent to the origin / members.
   */
  struct MulticastJoinRequestMessage *join_req;

  /**
   * Join decision sent in reply to our request.
   *
   * Only a positive decision is stored here, in case of a negative decision the
   * client is disconnected.
   */
  struct MulticastJoinDecisionMessageHeader *join_dcsn;

  /**
   * CADET channel to the origin.
   */
  struct Channel *origin_channel;

  /**
   * Peer identity of origin.
   */
  struct GNUNET_PeerIdentity origin;

  /**
   * Peer identity of relays (other members to connect).
   */
  struct GNUNET_PeerIdentity *relays;

  /**
   * Last request fragment ID sent to the origin.
   */
  uint64_t max_fragment_id;

  /**
   * Number of @a relays.
   */
  uint32_t relay_count;
};


struct ReplayRequestKey
{
  uint64_t fragment_id;
  uint64_t message_id;
  uint64_t fragment_offset;
  uint64_t flags;
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
  if (NULL != core)
  {
    GNUNET_CORE_disconnect (core);
    core = NULL;
  }
  if (NULL != cadet)
  {
    GNUNET_CADET_disconnect (cadet);
    cadet = NULL;
  }
  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_YES);
    stats = NULL;
  }
  /* FIXME: do more clean up here */
}


/**
 * Clean up origin data structures after a client disconnected.
 */
static void
cleanup_origin (struct Origin *orig)
{
  struct Group *grp = &orig->grp;
  GNUNET_CONTAINER_multihashmap_remove (origins, &grp->pub_key_hash, orig);
}


/**
 * Clean up member data structures after a client disconnected.
 */
static void
cleanup_member (struct Member *mem)
{
  struct Group *grp = &mem->grp;
  struct GNUNET_CONTAINER_MultiHashMap *
    grp_mem = GNUNET_CONTAINER_multihashmap_get (group_members,
                                                 &grp->pub_key_hash);
  GNUNET_assert (NULL != grp_mem);
  GNUNET_CONTAINER_multihashmap_remove (grp_mem, &mem->pub_key_hash, mem);

  if (0 == GNUNET_CONTAINER_multihashmap_size (grp_mem))
  {
    GNUNET_CONTAINER_multihashmap_remove (group_members, &grp->pub_key_hash,
                                          grp_mem);
    GNUNET_CONTAINER_multihashmap_destroy (grp_mem);
  }
  if (NULL != mem->join_dcsn)
  {
    GNUNET_free (mem->join_dcsn);
    mem->join_dcsn = NULL;
  }
  GNUNET_CONTAINER_multihashmap_remove (members, &grp->pub_key_hash, mem);
}


/**
 * Clean up group data structures after a client disconnected.
 */
static void
cleanup_group (struct Group *grp)
{
  (GNUNET_YES == grp->is_origin)
    ? cleanup_origin ((struct Origin *) grp)
    : cleanup_member ((struct Member *) grp);

  GNUNET_free (grp);
}


void
replay_key_hash (uint64_t fragment_id, uint64_t message_id,
                 uint64_t fragment_offset, uint64_t flags,
                 struct GNUNET_HashCode *key_hash)
{
  struct ReplayRequestKey key = {
    .fragment_id = fragment_id,
    .message_id = message_id,
    .fragment_offset = fragment_offset,
    .flags = flags,
  };
  GNUNET_CRYPTO_hash (&key, sizeof (key), key_hash);
}


/**
 * Remove channel from replay request hashmap.
 *
 * @param chn
 *        Channel to remove.
 *
 * @return #GNUNET_YES if there are more entries to process,
 *         #GNUNET_NO when reached end of hashmap.
 */
static int
replay_req_remove_cadet (struct Channel *chn)
{
  struct GNUNET_CONTAINER_MultiHashMap *
    grp_replay_req = GNUNET_CONTAINER_multihashmap_get (replay_req_cadet,
                                                        &chn->grp->pub_key_hash);
  if (NULL == grp_replay_req)
    return GNUNET_NO;

  struct GNUNET_CONTAINER_MultiHashMapIterator *
    it = GNUNET_CONTAINER_multihashmap_iterator_create (grp_replay_req);
  struct GNUNET_HashCode key;
  const struct Channel *c;
  while (GNUNET_YES
         == GNUNET_CONTAINER_multihashmap_iterator_next (it, &key,
                                                         (const void **) &c))
  {
    if (c == chn)
    {
      GNUNET_CONTAINER_multihashmap_remove (grp_replay_req, &key, chn);
      return GNUNET_YES;
    }
  }
  GNUNET_CONTAINER_multihashmap_iterator_destroy (it);
  return GNUNET_NO;
}


/**
 * Remove client from replay request hashmap.
 *
 * @param client
 *        Client to remove.
 *
 * @return #GNUNET_YES if there are more entries to process,
 *         #GNUNET_NO when reached end of hashmap.
 */
static int
replay_req_remove_client (struct Group *grp, struct GNUNET_SERVER_Client *client)
{
  struct GNUNET_CONTAINER_MultiHashMap *
    grp_replay_req = GNUNET_CONTAINER_multihashmap_get (replay_req_client,
                                                        &grp->pub_key_hash);
  if (NULL == grp_replay_req)
    return GNUNET_NO;

  struct GNUNET_CONTAINER_MultiHashMapIterator *
    it = GNUNET_CONTAINER_multihashmap_iterator_create (grp_replay_req);
  struct GNUNET_HashCode key;
  const struct GNUNET_SERVER_Client *c;
  while (GNUNET_YES
         == GNUNET_CONTAINER_multihashmap_iterator_next (it, &key,
                                                         (const void **) &c))
  {
    if (c == client)
    {
      GNUNET_CONTAINER_multihashmap_remove (replay_req_client, &key, client);
      return GNUNET_YES;
    }
  }
  GNUNET_CONTAINER_multihashmap_iterator_destroy (it);
  return GNUNET_NO;
}


/**
 * Called whenever a client is disconnected.
 *
 * Frees our resources associated with that client.
 *
 * @param cls  Closure.
 * @param client  Client handle.
 */
static void
client_notify_disconnect (void *cls, struct GNUNET_SERVER_Client *client)
{
  if (NULL == client)
    return;

  struct Group *grp
    = GNUNET_SERVER_client_get_user_context (client, struct Group);

  if (NULL == grp)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%p User context is NULL in client_disconnect()\n", grp);
    GNUNET_break (0);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Client (%s) disconnected from group %s\n",
              grp, (GNUNET_YES == grp->is_origin) ? "origin" : "member",
              GNUNET_h2s (&grp->pub_key_hash));

  struct ClientList *cl = grp->clients_head;
  while (NULL != cl)
  {
    if (cl->client == client)
    {
      GNUNET_CONTAINER_DLL_remove (grp->clients_head, grp->clients_tail, cl);
      GNUNET_free (cl);
      break;
    }
    cl = cl->next;
  }

  while (GNUNET_YES == replay_req_remove_client (grp, client));

  if (NULL == grp->clients_head)
  { /* Last client disconnected. */
#if FIXME
    if (NULL != grp->tmit_head)
    { /* Send pending messages via CADET before cleanup. */
      transmit_message (grp);
    }
    else
#endif
    {
      cleanup_group (grp);
    }
  }
}


/**
 * Send message to a client.
 */
static void
client_send (struct GNUNET_SERVER_Client *client,
             const struct GNUNET_MessageHeader *msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "%p Sending message to client.\n", client);

  GNUNET_SERVER_notification_context_add (nc, client);
  GNUNET_SERVER_notification_context_unicast (nc, client, msg, GNUNET_NO);
}


/**
 * Send message to all clients connected to the group.
 */
static void
client_send_group (const struct Group *grp,
                   const struct GNUNET_MessageHeader *msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "%p Sending message to all clients of the group.\n", grp);

  struct ClientList *cl = grp->clients_head;
  while (NULL != cl)
  {
    GNUNET_SERVER_notification_context_add (nc, cl->client);
    GNUNET_SERVER_notification_context_unicast (nc, cl->client, msg, GNUNET_NO);
    cl = cl->next;
  }
}


/**
 * Iterator callback for sending a message to origin clients.
 */
static int
client_send_origin_cb (void *cls, const struct GNUNET_HashCode *pub_key_hash,
                       void *origin)
{
  const struct GNUNET_MessageHeader *msg = cls;
  struct Member *orig = origin;

  client_send_group (&orig->grp, msg);
  return GNUNET_YES;
}


/**
 * Iterator callback for sending a message to member clients.
 */
static int
client_send_member_cb (void *cls, const struct GNUNET_HashCode *pub_key_hash,
                       void *member)
{
  const struct GNUNET_MessageHeader *msg = cls;
  struct Member *mem = member;

  if (NULL != mem->join_dcsn)
  { /* Only send message to admitted members */
    client_send_group (&mem->grp, msg);
  }
  return GNUNET_YES;
}


/**
 * Send message to all origin and member clients connected to the group.
 *
 * @param pub_key_hash
 *        H(key_pub) of the group.
 * @param msg
 *        Message to send.
 */
static int
client_send_all (struct GNUNET_HashCode *pub_key_hash,
                 const struct GNUNET_MessageHeader *msg)
{
  int n = 0;
  n += GNUNET_CONTAINER_multihashmap_get_multiple (origins, pub_key_hash,
                                                   client_send_origin_cb,
                                                   (void *) msg);
  n += GNUNET_CONTAINER_multihashmap_get_multiple (members, pub_key_hash,
                                                   client_send_member_cb,
                                                   (void *) msg);
  return n;
}


/**
 * Send message to a random origin client or a random member client.
 *
 * @param grp  The group to send @a msg to.
 * @param msg  Message to send.
 */
static int
client_send_random (struct GNUNET_HashCode *pub_key_hash,
                    const struct GNUNET_MessageHeader *msg)
{
  int n = 0;
  n = GNUNET_CONTAINER_multihashmap_get_random (origins, client_send_origin_cb,
                                                 (void *) msg);
  if (n <= 0)
    n = GNUNET_CONTAINER_multihashmap_get_random (members, client_send_member_cb,
                                                   (void *) msg);
  return n;
}


/**
 * Send message to all origin clients connected to the group.
 *
 * @param pub_key_hash
 *        H(key_pub) of the group.
 * @param msg
 *        Message to send.
 */
static int
client_send_origin (struct GNUNET_HashCode *pub_key_hash,
                    const struct GNUNET_MessageHeader *msg)
{
  int n = 0;
  n += GNUNET_CONTAINER_multihashmap_get_multiple (origins, pub_key_hash,
                                                   client_send_origin_cb,
                                                   (void *) msg);
  return n;
}


/**
 * Send fragment acknowledgement to all clients of the channel.
 *
 * @param pub_key_hash
 *        H(key_pub) of the group.
 */
static void
client_send_ack (struct GNUNET_HashCode *pub_key_hash)
{
  static struct GNUNET_MessageHeader *msg = NULL;
  if (NULL == msg)
  {
    msg = GNUNET_malloc (sizeof (*msg));
    msg->type = htons (GNUNET_MESSAGE_TYPE_MULTICAST_FRAGMENT_ACK);
    msg->size = htons (sizeof (*msg));
  }
  client_send_all (pub_key_hash, msg);
}


struct CadetTransmitClosure
{
  struct Channel *chn;
  const struct GNUNET_MessageHeader *msg;
};


/**
 * CADET is ready to transmit a message.
 */
size_t
cadet_notify_transmit_ready (void *cls, size_t buf_size, void *buf)
{
  if (0 == buf_size)
  {
    /* FIXME: connection closed */
    return 0;
  }
  struct CadetTransmitClosure *tcls = cls;
  struct Channel *chn = tcls->chn;
  uint16_t msg_size = ntohs (tcls->msg->size);
  GNUNET_assert (msg_size <= buf_size);
  memcpy (buf, tcls->msg, msg_size);
  GNUNET_free (tcls);

  if (0 == chn->msgs_pending)
  {
    GNUNET_break (0);
  }
  else if (0 == --chn->msgs_pending)
  {
    client_send_ack (&chn->group_pub_hash);
  }
  return msg_size;
}


/**
 * Send a message to a CADET channel.
 *
 * @param chn  Channel.
 * @param msg  Message.
 */
static void
cadet_send_channel (struct Channel *chn, const struct GNUNET_MessageHeader *msg)
{
  struct CadetTransmitClosure *tcls = GNUNET_malloc (sizeof (*tcls));
  tcls->chn = chn;
  tcls->msg = msg;

  chn->msgs_pending++;
  chn->tmit_handle
    = GNUNET_CADET_notify_transmit_ready (chn->channel, GNUNET_NO,
                                          GNUNET_TIME_UNIT_FOREVER_REL,
                                          ntohs (msg->size),
                                          &cadet_notify_transmit_ready,
                                          (void *) msg);
  GNUNET_assert (NULL != chn->tmit_handle);
}


/**
 * Create new outgoing CADET channel.
 *
 * @param peer
 *        Peer to connect to.
 * @param group_pub_key
 *        Public key of group the channel belongs to.
 * @param group_pub_hash
 *        Hash of @a group_pub_key.
 *
 * @return Channel.
 */
static struct Channel *
cadet_channel_create (struct Group *grp, struct GNUNET_PeerIdentity *peer)
{
  struct Channel *chn = GNUNET_malloc (sizeof (*chn));
  chn->grp = grp;
  chn->group_pub_key = grp->pub_key;
  chn->group_pub_hash = grp->pub_key_hash;
  chn->peer = *peer;
  chn->direction = DIR_OUTGOING;
  chn->join_status = JOIN_WAITING;
  chn->channel = GNUNET_CADET_channel_create (cadet, chn, &chn->peer,
                                              GNUNET_APPLICATION_TYPE_MULTICAST,
                                              GNUNET_CADET_OPTION_RELIABLE);
  GNUNET_CONTAINER_multihashmap_put (channels_out, &chn->group_pub_hash, chn,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  return chn;
}


/**
 * Create CADET channel and send a join request.
 */
static void
cadet_send_join_request (struct Member *mem)
{
  mem->origin_channel = cadet_channel_create (&mem->grp, &mem->origin);
  cadet_send_channel (mem->origin_channel, &mem->join_req->header);

  uint32_t i;
  for (i = 0; i < mem->relay_count; i++)
  {
    struct Channel *
      chn = cadet_channel_create (&mem->grp, &mem->relays[i]);
    cadet_send_channel (chn, &mem->join_req->header);
  }
}


static int
cadet_send_join_decision_cb (void *cls,
                             const struct GNUNET_HashCode *group_pub_hash,
                             void *channel)
{
  const struct MulticastJoinDecisionMessageHeader *hdcsn = cls;
  struct Channel *chn = channel;

  if (0 == memcmp (&hdcsn->member_pub_key, &chn->member_pub_key, sizeof (chn->member_pub_key))
      && 0 == memcmp (&hdcsn->peer, &chn->peer, sizeof (chn->peer)))
  {
    cadet_send_channel (chn, &hdcsn->header);
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Send join decision to a remote peer.
 */
static void
cadet_send_join_decision (struct Group *grp,
                          const struct MulticastJoinDecisionMessageHeader *hdcsn)
{
  GNUNET_CONTAINER_multihashmap_get_multiple (channels_in, &grp->pub_key_hash,
                                              &cadet_send_join_decision_cb,
                                              (void *) hdcsn);
}


/**
 * Iterator callback for sending a message to origin clients.
 */
static int
cadet_send_cb (void *cls, const struct GNUNET_HashCode *pub_key_hash,
               void *channel)
{
  const struct GNUNET_MessageHeader *msg = cls;
  struct Channel *chn = channel;
  if (JOIN_ADMITTED == chn->join_status)
    cadet_send_channel (chn, msg);
  return GNUNET_YES;
}


/**
 * Send message to all connected children.
 */
static int
cadet_send_children (struct GNUNET_HashCode *pub_key_hash,
                     const struct GNUNET_MessageHeader *msg)
{
  int n = 0;
  if (channels_in != NULL)
    n += GNUNET_CONTAINER_multihashmap_get_multiple (channels_in, pub_key_hash,
                                                     cadet_send_cb, (void *) msg);
  return n;
}


/**
 * Send message to all connected parents.
 */
static int
cadet_send_parents (struct GNUNET_HashCode *pub_key_hash,
                    const struct GNUNET_MessageHeader *msg)
{
  int n = 0;
  if (channels_in != NULL)
    n += GNUNET_CONTAINER_multihashmap_get_multiple (channels_out, pub_key_hash,
                                                     cadet_send_cb, (void *) msg);
  return n;
}


/**
 * Handle a connecting client starting an origin.
 */
static void
client_recv_origin_start (void *cls, struct GNUNET_SERVER_Client *client,
                          const struct GNUNET_MessageHeader *m)
{
  const struct MulticastOriginStartMessage *
    msg = (const struct MulticastOriginStartMessage *) m;

  struct GNUNET_CRYPTO_EddsaPublicKey pub_key;
  struct GNUNET_HashCode pub_key_hash;

  GNUNET_CRYPTO_eddsa_key_get_public (&msg->group_key, &pub_key);
  GNUNET_CRYPTO_hash (&pub_key, sizeof (pub_key), &pub_key_hash);

  struct Origin *
    orig = GNUNET_CONTAINER_multihashmap_get (origins, &pub_key_hash);
  struct Group *grp;

  if (NULL == orig)
  {
    orig = GNUNET_new (struct Origin);
    orig->priv_key = msg->group_key;
    orig->max_fragment_id = GNUNET_ntohll (msg->max_fragment_id);
    grp = &orig->grp;
    grp->is_origin = GNUNET_YES;
    grp->pub_key = pub_key;
    grp->pub_key_hash = pub_key_hash;

    GNUNET_CONTAINER_multihashmap_put (origins, &grp->pub_key_hash, orig,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  }
  else
  {
    grp = &orig->grp;
  }

  struct ClientList *cl = GNUNET_new (struct ClientList);
  cl->client = client;
  GNUNET_CONTAINER_DLL_insert (grp->clients_head, grp->clients_tail, cl);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Client connected as origin to group %s.\n",
              orig, GNUNET_h2s (&grp->pub_key_hash));

  GNUNET_SERVER_client_set_user_context (client, grp);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handle a connecting client joining a group.
 */
static void
client_recv_member_join (void *cls, struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *m)
{
  const struct MulticastMemberJoinMessage *
    msg = (const struct MulticastMemberJoinMessage *) m;
  uint16_t msg_size = ntohs (msg->header.size);

  struct GNUNET_CRYPTO_EcdsaPublicKey mem_pub_key;
  struct GNUNET_HashCode pub_key_hash, mem_pub_key_hash;

  GNUNET_CRYPTO_ecdsa_key_get_public (&msg->member_key, &mem_pub_key);
  GNUNET_CRYPTO_hash (&mem_pub_key, sizeof (mem_pub_key), &mem_pub_key_hash);
  GNUNET_CRYPTO_hash (&msg->group_pub_key, sizeof (msg->group_pub_key), &pub_key_hash);

  struct GNUNET_CONTAINER_MultiHashMap *
    grp_mem = GNUNET_CONTAINER_multihashmap_get (group_members, &pub_key_hash);
  struct Member *mem = NULL;
  struct Group *grp;

  if (NULL != grp_mem)
  {
    mem = GNUNET_CONTAINER_multihashmap_get (grp_mem, &mem_pub_key_hash);
  }
  if (NULL == mem)
  {
    mem = GNUNET_new (struct Member);
    mem->priv_key = msg->member_key;
    mem->pub_key = mem_pub_key;
    mem->pub_key_hash = mem_pub_key_hash;
    mem->max_fragment_id = 0; // FIXME

    grp = &mem->grp;
    grp->is_origin = GNUNET_NO;
    grp->pub_key = msg->group_pub_key;
    grp->pub_key_hash = pub_key_hash;

    if (NULL == grp_mem)
    {
      grp_mem = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);
      GNUNET_CONTAINER_multihashmap_put (group_members, &grp->pub_key_hash, grp_mem,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
    }
    GNUNET_CONTAINER_multihashmap_put (grp_mem, &mem->pub_key_hash, mem,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
    GNUNET_CONTAINER_multihashmap_put (members, &grp->pub_key_hash, mem,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  }
  else
  {
    grp = &mem->grp;
  }

  struct ClientList *cl = GNUNET_new (struct ClientList);
  cl->client = client;
  GNUNET_CONTAINER_DLL_insert (grp->clients_head, grp->clients_tail, cl);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Client connected to group %s..\n",
              mem, GNUNET_h2s (&grp->pub_key_hash));
  char *str = GNUNET_CRYPTO_ecdsa_public_key_to_string (&mem->pub_key);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p ..as member %s (%s).\n",
              mem, GNUNET_h2s (&mem->pub_key_hash), str);
  GNUNET_free (str);

  GNUNET_SERVER_client_set_user_context (client, grp);

  if (NULL != mem->join_dcsn)
  { /* Already got a join decision, send it to client. */
    GNUNET_SERVER_notification_context_add (nc, client);
    GNUNET_SERVER_notification_context_unicast (nc, client,
                                                (struct GNUNET_MessageHeader *)
                                                mem->join_dcsn,
                                                GNUNET_NO);
  }
  else
  { /* First client of the group, send join request. */
    struct GNUNET_PeerIdentity *relays = (struct GNUNET_PeerIdentity *) &msg[1];
    uint32_t relay_count = ntohl (msg->relay_count);
    uint16_t relay_size = relay_count * sizeof (*relays);
    struct GNUNET_MessageHeader *join_msg = NULL;
    uint16_t join_msg_size = 0;
    if (sizeof (*msg) + relay_size + sizeof (struct GNUNET_MessageHeader)
        <= msg_size)
    {
      join_msg = (struct GNUNET_MessageHeader *)
        (((char *) &msg[1]) + relay_size);
      join_msg_size = ntohs (join_msg->size);
    }
    if (sizeof (*msg) + relay_size + join_msg_size != msg_size)
    {
      GNUNET_break (0);
      GNUNET_SERVER_client_disconnect (client);
      return;
    }

    struct MulticastJoinRequestMessage *
      req = GNUNET_malloc (sizeof (*req) + join_msg_size);
    req->header.size = htons (sizeof (*req) + join_msg_size);
    req->header.type = htons (GNUNET_MESSAGE_TYPE_MULTICAST_JOIN_REQUEST);
    req->group_pub_key = grp->pub_key;
    req->peer = this_peer;
    GNUNET_CRYPTO_ecdsa_key_get_public (&mem->priv_key, &req->member_pub_key);
    if (0 < join_msg_size)
      memcpy (&req[1], join_msg, join_msg_size);

    req->member_pub_key = mem->pub_key;
    req->purpose.size = htonl (msg_size
                               - sizeof (req->header)
                               - sizeof (req->reserved)
                               - sizeof (req->signature));
    req->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_MULTICAST_REQUEST);

    if (GNUNET_OK != GNUNET_CRYPTO_ecdsa_sign (&mem->priv_key, &req->purpose,
                                               &req->signature))
    {
      /* FIXME: handle error */
      GNUNET_assert (0);
    }

    if (NULL != mem->join_req)
      GNUNET_free (mem->join_req);
    mem->join_req = req;

    if (0 == client_send_origin (&grp->pub_key_hash, &mem->join_req->header))
    { /* No local origins, send to remote origin */
      cadet_send_join_request (mem);
    }
  }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


static void
client_send_join_decision (struct Member *mem,
                           const struct MulticastJoinDecisionMessageHeader *hdcsn)
{
  client_send_group (&mem->grp, &hdcsn->header);

  const struct MulticastJoinDecisionMessage *
    dcsn = (const struct MulticastJoinDecisionMessage *) &hdcsn[1];
  if (GNUNET_YES == ntohl (dcsn->is_admitted))
  { /* Member admitted, store join_decision. */
    uint16_t dcsn_size = ntohs (dcsn->header.size);
    mem->join_dcsn = GNUNET_malloc (dcsn_size);
    memcpy (mem->join_dcsn, dcsn, dcsn_size);
  }
  else
  { /* Refused entry, but replay would be still possible for past members. */
  }
}


/**
 * Join decision from client.
 */
static void
client_recv_join_decision (void *cls, struct GNUNET_SERVER_Client *client,
                           const struct GNUNET_MessageHeader *m)
{
  struct Group *
    grp = GNUNET_SERVER_client_get_user_context (client, struct Group);
  const struct MulticastJoinDecisionMessageHeader *
    hdcsn = (const struct MulticastJoinDecisionMessageHeader *) m;

  if (NULL == grp)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Got join decision from client for group %s..\n",
              grp, GNUNET_h2s (&grp->pub_key_hash));

  struct GNUNET_CONTAINER_MultiHashMap *
    grp_mem = GNUNET_CONTAINER_multihashmap_get (group_members,
                                                 &grp->pub_key_hash);
  struct Member *mem = NULL;
  if (NULL != grp_mem)
  {
    struct GNUNET_HashCode member_key_hash;
    GNUNET_CRYPTO_hash (&hdcsn->member_pub_key, sizeof (hdcsn->member_pub_key),
                        &member_key_hash);
    mem = GNUNET_CONTAINER_multihashmap_get (grp_mem, &member_key_hash);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%p ..and member %s: %p\n",
                grp, GNUNET_h2s (&member_key_hash), mem);
  }
  if (NULL != mem)
  { /* Found local member */
    client_send_join_decision (mem, hdcsn);
  }
  else
  { /* Look for remote member */
    cadet_send_join_decision (grp, hdcsn);
  }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Incoming message from a client.
 */
static void
client_recv_multicast_message (void *cls, struct GNUNET_SERVER_Client *client,
                               const struct GNUNET_MessageHeader *m)
{
  struct Group *
    grp = GNUNET_SERVER_client_get_user_context (client, struct Group);
  struct GNUNET_MULTICAST_MessageHeader *out;
  struct Origin *orig;

  if (NULL == grp)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_assert (GNUNET_YES == grp->is_origin);
  orig = (struct Origin *) grp;

  /* FIXME: yucky, should use separate message structs for P2P and CS! */
  out = (struct GNUNET_MULTICAST_MessageHeader *) GNUNET_copy_message (m);
  out->fragment_id = GNUNET_htonll (++orig->max_fragment_id);
  out->purpose.size = htonl (ntohs (out->header.size)
                             - sizeof (out->header)
                             - sizeof (out->hop_counter)
                             - sizeof (out->signature));
  out->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_MULTICAST_MESSAGE);

  if (GNUNET_OK != GNUNET_CRYPTO_eddsa_sign (&orig->priv_key, &out->purpose,
                                             &out->signature))
  {
    GNUNET_assert (0);
  }

  client_send_all (&grp->pub_key_hash, &out->header);
  if (0 == cadet_send_children (&grp->pub_key_hash, &out->header))
  {
    client_send_ack (&grp->pub_key_hash);
  }
  GNUNET_free (out);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Incoming request from a client.
 */
static void
client_recv_multicast_request (void *cls, struct GNUNET_SERVER_Client *client,
                               const struct GNUNET_MessageHeader *m)
{
  struct Group *grp = GNUNET_SERVER_client_get_user_context (client, struct Group);
  struct Member *mem;
  struct GNUNET_MULTICAST_RequestHeader *out;
  if (NULL == grp)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_assert (GNUNET_NO == grp->is_origin);
  mem = (struct Member *) grp;

  /* FIXME: yucky, should use separate message structs for P2P and CS! */
  out = (struct GNUNET_MULTICAST_RequestHeader *) GNUNET_copy_message (m);
  out->member_pub_key = mem->pub_key;
  out->fragment_id = GNUNET_ntohll (++mem->max_fragment_id);
  out->purpose.size = htonl (ntohs (out->header.size)
                             - sizeof (out->header)
                             - sizeof (out->member_pub_key)
                             - sizeof (out->signature));
  out->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_MULTICAST_REQUEST);

  if (GNUNET_OK != GNUNET_CRYPTO_ecdsa_sign (&mem->priv_key, &out->purpose,
                                             &out->signature))
  {
    GNUNET_assert (0);
  }

  uint8_t send_ack = GNUNET_YES;
  if (0 == client_send_origin (&grp->pub_key_hash, &out->header))
  { /* No local origins, send to remote origin */
    if (NULL != mem->origin_channel)
    {
      cadet_send_channel (mem->origin_channel, &out->header);
      send_ack = GNUNET_NO;
    }
    else
    {
      /* FIXME: not yet connected to origin */
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      GNUNET_free (out);
      return;
    }
  }
  if (GNUNET_YES == send_ack)
  {
    client_send_ack (&grp->pub_key_hash);
  }
  GNUNET_free (out);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Incoming replay request from a client.
 */
static void
client_recv_replay_request (void *cls, struct GNUNET_SERVER_Client *client,
                            const struct GNUNET_MessageHeader *m)
{
  struct Group *grp = GNUNET_SERVER_client_get_user_context (client, struct Group);
  struct Member *mem;
  if (NULL == grp)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_assert (GNUNET_NO == grp->is_origin);
  mem = (struct Member *) grp;

  struct GNUNET_CONTAINER_MultiHashMap *
    grp_replay_req = GNUNET_CONTAINER_multihashmap_get (replay_req_client,
                                                        &grp->pub_key_hash);
  if (NULL == grp_replay_req)
  {
    grp_replay_req = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);
    GNUNET_CONTAINER_multihashmap_put (replay_req_client,
                                       &grp->pub_key_hash, grp_replay_req,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  }
  struct MulticastReplayRequestMessage *
    rep = (struct MulticastReplayRequestMessage *) m;
  struct GNUNET_HashCode key_hash;
  replay_key_hash (rep->fragment_id, rep->message_id, rep->fragment_offset,
                   rep->flags, &key_hash);
  GNUNET_CONTAINER_multihashmap_put (grp_replay_req, &key_hash, client,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);

  if (0 == client_send_origin (&grp->pub_key_hash, m))
  { /* No local origin, replay from remote members / origin. */
    if (NULL != mem->origin_channel)
    {
      cadet_send_channel (mem->origin_channel, m);
    }
    else
    {
      /* FIXME: not yet connected to origin */
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


static int
cadet_send_replay_response_cb (void *cls,
                               const struct GNUNET_HashCode *key_hash,
                               void *value)
{
  struct Channel *chn = value;
  struct GNUNET_MessageHeader *msg = cls;

  cadet_send_channel (chn, msg);
  return GNUNET_OK;
}


static int
client_send_replay_response_cb (void *cls,
                                const struct GNUNET_HashCode *key_hash,
                                void *value)
{
  struct GNUNET_SERVER_Client *client = value;
  struct GNUNET_MessageHeader *msg = cls;

  client_send (client, msg);
  return GNUNET_OK;
}


/**
 * End of replay response from a client.
 */
static void
client_recv_replay_response_end (void *cls, struct GNUNET_SERVER_Client *client,
                                 const struct GNUNET_MessageHeader *m)
{
  struct Group *grp = GNUNET_SERVER_client_get_user_context (client, struct Group);
  if (NULL == grp)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  struct MulticastReplayResponseMessage *
    res = (struct MulticastReplayResponseMessage *) m;

  struct GNUNET_HashCode key_hash;
  replay_key_hash (res->fragment_id, res->message_id, res->fragment_offset,
                   res->flags, &key_hash);

  struct GNUNET_CONTAINER_MultiHashMap *
    grp_replay_req_cadet = GNUNET_CONTAINER_multihashmap_get (replay_req_cadet,
                                                                &grp->pub_key_hash);
  if (NULL != grp_replay_req_cadet)
  {
    GNUNET_CONTAINER_multihashmap_remove_all (grp_replay_req_cadet, &key_hash);
  }
  struct GNUNET_CONTAINER_MultiHashMap *
    grp_replay_req_client = GNUNET_CONTAINER_multihashmap_get (replay_req_client,
                                                               &grp->pub_key_hash);
  if (NULL != grp_replay_req_client)
  {
    GNUNET_CONTAINER_multihashmap_remove_all (grp_replay_req_client, &key_hash);
  }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Incoming replay response from a client.
 *
 * Respond with a multicast message on success, or otherwise with an error code.
 */
static void
client_recv_replay_response (void *cls, struct GNUNET_SERVER_Client *client,
                             const struct GNUNET_MessageHeader *m)
{
  struct Group *grp = GNUNET_SERVER_client_get_user_context (client, struct Group);
  if (NULL == grp)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  struct MulticastReplayResponseMessage *
    res = (struct MulticastReplayResponseMessage *) m;

  const struct GNUNET_MessageHeader *msg = m;
  if (GNUNET_MULTICAST_REC_OK == res->error_code)
  {
    msg = (struct GNUNET_MessageHeader *) &res[1];
  }

  struct GNUNET_HashCode key_hash;
  replay_key_hash (res->fragment_id, res->message_id, res->fragment_offset,
                   res->flags, &key_hash);

  struct GNUNET_CONTAINER_MultiHashMap *
    grp_replay_req_cadet = GNUNET_CONTAINER_multihashmap_get (replay_req_cadet,
                                                              &grp->pub_key_hash);
  if (NULL != grp_replay_req_cadet)
  {
    GNUNET_CONTAINER_multihashmap_get_multiple (grp_replay_req_cadet, &key_hash,
                                                cadet_send_replay_response_cb,
                                                (void *) msg);
  }
  if (GNUNET_MULTICAST_REC_OK == res->error_code)
  {
    struct GNUNET_CONTAINER_MultiHashMap *
      grp_replay_req_client = GNUNET_CONTAINER_multihashmap_get (replay_req_client,
                                                                 &grp->pub_key_hash);
    if (NULL != grp_replay_req_client)
    {
      GNUNET_CONTAINER_multihashmap_get_multiple (grp_replay_req_client, &key_hash,
                                                  client_send_replay_response_cb,
                                                  (void *) msg);
    }
  }
  else
  {
    client_recv_replay_response_end (cls, client, m);
    return;
  }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * A new client connected.
 */
static void
client_notify_connect (void *cls, struct GNUNET_SERVER_Client *client)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Client connected: %p\n", client);
  /* FIXME: send connect ACK */
}


/**
 * Message handlers for the server.
 */
static const struct GNUNET_SERVER_MessageHandler server_handlers[] = {
  { client_recv_origin_start, NULL,
    GNUNET_MESSAGE_TYPE_MULTICAST_ORIGIN_START, 0 },

  { client_recv_member_join, NULL,
    GNUNET_MESSAGE_TYPE_MULTICAST_MEMBER_JOIN, 0 },

  { client_recv_join_decision, NULL,
    GNUNET_MESSAGE_TYPE_MULTICAST_JOIN_DECISION, 0 },

  { client_recv_multicast_message, NULL,
    GNUNET_MESSAGE_TYPE_MULTICAST_MESSAGE, 0 },

  { client_recv_multicast_request, NULL,
    GNUNET_MESSAGE_TYPE_MULTICAST_REQUEST, 0 },

  { client_recv_replay_request, NULL,
    GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_REQUEST, 0 },

  { client_recv_replay_response, NULL,
    GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_RESPONSE, 0 },

  { client_recv_replay_response_end, NULL,
    GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_RESPONSE_END, 0 },

  { NULL, NULL, 0, 0 }
};


/**
 * New incoming CADET channel.
 */
static void *
cadet_notify_channel_new (void *cls,
                          struct GNUNET_CADET_Channel *channel,
                          const struct GNUNET_PeerIdentity *initiator,
                          uint32_t port,
                          enum GNUNET_CADET_ChannelOption options)
{
  return NULL;
}


/**
 * CADET channel is being destroyed.
 */
static void
cadet_notify_channel_end (void *cls,
                          const struct GNUNET_CADET_Channel *channel,
                          void *ctx)
{
  if (NULL == ctx)
    return;

  struct Channel *chn = ctx;
  if (NULL != chn->grp)
  {
    if (GNUNET_NO == chn->grp->is_origin)
    {
      struct Member *mem = (struct Member *) chn->grp;
      if (chn == mem->origin_channel)
        mem->origin_channel = NULL;
    }
  }

  while (GNUNET_YES == replay_req_remove_cadet (chn));

  GNUNET_free (chn);
}


/**
 * Incoming join request message from CADET.
 */
int
cadet_recv_join_request (void *cls,
                         struct GNUNET_CADET_Channel *channel,
                         void **ctx,
                         const struct GNUNET_MessageHeader *m)
{
  const struct MulticastJoinRequestMessage *
    req = (const struct MulticastJoinRequestMessage *) m;
  uint16_t size = ntohs (m->size);
  if (size < sizeof (*req))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (NULL != *ctx)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (ntohl (req->purpose.size) != (size
                                    - sizeof (req->header)
                                    - sizeof (req->reserved)
                                    - sizeof (req->signature)))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK !=
      GNUNET_CRYPTO_ecdsa_verify (GNUNET_SIGNATURE_PURPOSE_MULTICAST_REQUEST,
                                  &req->purpose, &req->signature,
                                  &req->member_pub_key))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }

  struct GNUNET_HashCode group_pub_hash;
  GNUNET_CRYPTO_hash (&req->group_pub_key, sizeof (req->group_pub_key), &group_pub_hash);

  struct Channel *chn = GNUNET_malloc (sizeof *chn);
  chn->channel = channel;
  chn->group_pub_key = req->group_pub_key;
  chn->group_pub_hash = group_pub_hash;
  chn->member_pub_key = req->member_pub_key;
  chn->peer = req->peer;
  chn->join_status = JOIN_WAITING;
  GNUNET_CONTAINER_multihashmap_put (channels_in, &chn->group_pub_hash, chn,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);

  client_send_all (&group_pub_hash, m);
  return GNUNET_OK;
}


/**
 * Incoming join decision message from CADET.
 */
int
cadet_recv_join_decision (void *cls,
                          struct GNUNET_CADET_Channel *channel,
                          void **ctx,
                          const struct GNUNET_MessageHeader *m)
{
  const struct MulticastJoinDecisionMessage *
    dcsn = (const struct MulticastJoinDecisionMessage *) m;
  uint16_t size = ntohs (m->size);
  if (size < sizeof (*dcsn))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  struct Channel *chn = *ctx;
  if (NULL == chn)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (NULL == chn->grp || GNUNET_NO != chn->grp->is_origin)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  switch (chn->join_status)
  {
  case JOIN_REFUSED:
    return GNUNET_SYSERR;

  case JOIN_ADMITTED:
    return GNUNET_OK;

  case JOIN_NOT_ASKED:
  case JOIN_WAITING:
    break;
  }

  struct MulticastJoinDecisionMessageHeader *
    hdcsn = GNUNET_malloc (sizeof (*hdcsn) + size);
  hdcsn->peer = chn->peer;
  memcpy (&hdcsn[1], dcsn, sizeof (*hdcsn) + size);

  struct Member *mem = (struct Member *) chn->grp;
  client_send_join_decision (mem, hdcsn);
  GNUNET_free (hdcsn);
  if (GNUNET_YES == ntohs (dcsn->is_admitted))
  {
    chn->join_status = JOIN_ADMITTED;
    return GNUNET_OK;
  }
  else
  {
    chn->join_status = JOIN_REFUSED;
    return GNUNET_SYSERR;
  }
}

/**
 * Incoming multicast message from CADET.
 */
int
cadet_recv_message (void *cls,
                    struct GNUNET_CADET_Channel *channel,
                    void **ctx,
                    const struct GNUNET_MessageHeader *m)
{
  const struct GNUNET_MULTICAST_MessageHeader *
    msg = (const struct GNUNET_MULTICAST_MessageHeader *) m;
  uint16_t size = ntohs (m->size);
  if (size < sizeof (*msg))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  struct Channel *chn = *ctx;
  if (NULL == chn)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (ntohl (msg->purpose.size) != (size
                                    - sizeof (msg->header)
                                    - sizeof (msg->hop_counter)
                                    - sizeof (msg->signature)))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK !=
      GNUNET_CRYPTO_eddsa_verify (GNUNET_SIGNATURE_PURPOSE_MULTICAST_MESSAGE,
                                  &msg->purpose, &msg->signature,
                                  &chn->group_pub_key))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }

  client_send_all (&chn->group_pub_hash, m);
  return GNUNET_OK;
}


/**
 * Incoming multicast request message from CADET.
 */
int
cadet_recv_request (void *cls,
                    struct GNUNET_CADET_Channel *channel,
                    void **ctx,
                    const struct GNUNET_MessageHeader *m)
{
  const struct GNUNET_MULTICAST_RequestHeader *
    req = (const struct GNUNET_MULTICAST_RequestHeader *) m;
  uint16_t size = ntohs (m->size);
  if (size < sizeof (*req))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  struct Channel *chn = *ctx;
  if (NULL == chn)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (ntohl (req->purpose.size) != (size
                                    - sizeof (req->header)
                                    - sizeof (req->member_pub_key)
                                    - sizeof (req->signature)))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK !=
      GNUNET_CRYPTO_ecdsa_verify (GNUNET_SIGNATURE_PURPOSE_MULTICAST_REQUEST,
                                  &req->purpose, &req->signature,
                                  &req->member_pub_key))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }

  client_send_origin (&chn->group_pub_hash, m);
  return GNUNET_OK;
}


/**
 * Incoming multicast replay request from CADET.
 */
int
cadet_recv_replay_request (void *cls,
                           struct GNUNET_CADET_Channel *channel,
                           void **ctx,
                           const struct GNUNET_MessageHeader *m)
{
  struct MulticastReplayRequestMessage rep;
  uint16_t size = ntohs (m->size);
  if (size < sizeof (rep))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  struct Channel *chn = *ctx;

  memcpy (&rep, m, sizeof (rep));
  memcpy (&rep.member_pub_key, &chn->member_pub_key, sizeof (chn->member_pub_key));

  struct GNUNET_CONTAINER_MultiHashMap *
    grp_replay_req = GNUNET_CONTAINER_multihashmap_get (replay_req_cadet,
                                                        &chn->grp->pub_key_hash);
  if (NULL == grp_replay_req)
  {
    grp_replay_req = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);
    GNUNET_CONTAINER_multihashmap_put (replay_req_cadet,
                                       &chn->grp->pub_key_hash, grp_replay_req,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  }
  struct GNUNET_HashCode key_hash;
  replay_key_hash (rep.fragment_id, rep.message_id, rep.fragment_offset,
                   rep.flags, &key_hash);
  GNUNET_CONTAINER_multihashmap_put (grp_replay_req, &key_hash, chn,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);

  client_send_random (&chn->group_pub_hash, &rep.header);
  return GNUNET_OK;
}


/**
 * Incoming multicast replay response from CADET.
 */
int
cadet_recv_replay_response (void *cls,
                            struct GNUNET_CADET_Channel *channel,
                            void **ctx,
                            const struct GNUNET_MessageHeader *m)
{
  struct Channel *chn = *ctx;

  /* @todo FIXME: got replay error response, send request to other members */

  return GNUNET_OK;
}


/**
 * Message handlers for CADET.
 */
static const struct GNUNET_CADET_MessageHandler cadet_handlers[] = {
  { cadet_recv_join_request,
    GNUNET_MESSAGE_TYPE_MULTICAST_JOIN_REQUEST, 0 },

  { cadet_recv_message,
    GNUNET_MESSAGE_TYPE_MULTICAST_MESSAGE, 0 },

  { cadet_recv_request,
    GNUNET_MESSAGE_TYPE_MULTICAST_REQUEST, 0 },

  { cadet_recv_replay_request,
    GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_REQUEST, 0 },

  { cadet_recv_replay_response,
    GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_RESPONSE, 0 },

  { NULL, 0, 0 }
};


/**
 * Listening ports for CADET.
 */
static const uint32_t cadet_ports[] = { GNUNET_APPLICATION_TYPE_MULTICAST, 0 };


/**
 * Connected to core service.
 */
static void
core_connected_cb  (void *cls, const struct GNUNET_PeerIdentity *my_identity)
{
  this_peer = *my_identity;

  stats = GNUNET_STATISTICS_create ("multicast", cfg);
  origins = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);
  members = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);
  group_members = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);
  channels_in = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);
  channels_out = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);
  replay_req_cadet = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);
  replay_req_client = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);

  cadet = GNUNET_CADET_connect (cfg, NULL,
                                &cadet_notify_channel_new,
                                &cadet_notify_channel_end,
                                cadet_handlers, cadet_ports);

  nc = GNUNET_SERVER_notification_context_create (server, 1);
  GNUNET_SERVER_add_handlers (server, server_handlers);
  GNUNET_SERVER_disconnect_notify (server, &client_notify_disconnect, NULL);

  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);
}


/**
 * Service started.
 *
 * @param cls closure
 * @param server the initialized server
 * @param cfg configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *srv,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  cfg = c;
  server = srv;
  GNUNET_SERVER_connect_notify (server, &client_notify_connect, NULL);
  core = GNUNET_CORE_connect (cfg, NULL, &core_connected_cb, NULL, NULL,
                              NULL, GNUNET_NO, NULL, GNUNET_NO, NULL);
}


/**
 * The main function for the multicast service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "multicast",
                              GNUNET_SERVICE_OPTION_NONE, &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-multicast.c */
