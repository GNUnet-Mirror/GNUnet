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
 * Incoming CADET channels.
 * Group's pub_key_hash -> struct Channel * (multi)
 */
static struct GNUNET_CONTAINER_MultiHashMap *channels_in;

/**
 * Outgoing CADET channels.
 * Group's pub_key_hash -> struct Channel * (multi)
 */
static struct GNUNET_CONTAINER_MultiHashMap *channels_out;

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
  struct GNUNET_CRYPTO_EddsaPublicKey group_key;

  /**
   * Hash of @a group_key.
   */
  struct GNUNET_HashCode group_key_hash;

  /**
   * Public key of the joining member.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey member_key;

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
    GNUNET_assert (0);
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
 * Send message to all clients connected to the group.
 */
static void
client_send_msg (const struct Group *grp,
                 const struct GNUNET_MessageHeader *msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "%p Sending message to clients.\n", grp);

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

  client_send_msg (&orig->grp, msg);
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
    client_send_msg (&mem->grp, msg);
  }
  return GNUNET_YES;
}


/**
 * Send message to all origin and member clients connected to the group.
 *
 * @param grp  The group to send @a msg to.
 * @param msg  Message to send.
 */
static int
client_send_all (struct GNUNET_HashCode *pub_key_hash,
                 const struct GNUNET_MessageHeader *msg)
{
  int n = 0;
  if (origins != NULL)
    n += GNUNET_CONTAINER_multihashmap_get_multiple (origins, pub_key_hash,
                                                     client_send_origin_cb,
                                                     (void *) msg);
  if (members != NULL)
    n += GNUNET_CONTAINER_multihashmap_get_multiple (members, pub_key_hash,
                                                     client_send_member_cb,
                                                     (void *) msg);
  return n;
}


/**
 * Send message to all origin clients connected to the group.
 *
 * @param grp  The group to send @a msg to.
 * @param msg  Message to send.
 */
static int
client_send_origin (struct GNUNET_HashCode *pub_key_hash,
                    const struct GNUNET_MessageHeader *msg)
{
  int n = 0;
  if (origins != NULL)
    n += GNUNET_CONTAINER_multihashmap_get_multiple (origins, pub_key_hash,
                                                     client_send_origin_cb,
                                                     (void *) msg);
  return n;
}


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
  const struct GNUNET_MessageHeader *msg = cls;
  uint16_t msg_size = ntohs (msg->size);
  GNUNET_assert (msg_size <= buf_size);
  memcpy (buf, msg, msg_size);
  return msg_size;
}


/**
 * Send a message to a CADET channel.
 *
 * @param chn  Channel.
 * @param msg  Message.
 */
static void
cadet_send_msg (struct Channel *chn, const struct GNUNET_MessageHeader *msg)
{
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
 * @param group_key
 *        Public key of group the channel belongs to.
 * @param group_key_hash
 *        Hash of @a group_key.
 *
 * @return Channel.
 */
static struct Channel *
cadet_channel_create (struct Group *grp, struct GNUNET_PeerIdentity *peer)
{
  struct Channel *chn = GNUNET_malloc (sizeof (*chn));
  chn->grp = grp;
  chn->group_key = grp->pub_key;
  chn->group_key_hash = grp->pub_key_hash;
  chn->peer = *peer;
  chn->direction = DIR_OUTGOING;
  chn->join_status = JOIN_WAITING;
  chn->channel = GNUNET_CADET_channel_create (cadet, chn, &chn->peer,
                                              GNUNET_APPLICATION_TYPE_MULTICAST,
                                              GNUNET_CADET_OPTION_RELIABLE);
  GNUNET_CONTAINER_multihashmap_put (channels_out, &chn->group_key_hash, chn,
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
  cadet_send_msg (mem->origin_channel, &mem->join_req->header);

  uint32_t i;
  for (i = 0; i < mem->relay_count; i++)
  {
    struct Channel *
      chn = cadet_channel_create (&mem->grp, &mem->relays[i]);
    cadet_send_msg (chn, &mem->join_req->header);
  }
}


static int
cadet_send_join_decision_cb (void *cls,
                             const struct GNUNET_HashCode *group_key_hash,
                             void *channel)
{
  const struct MulticastJoinDecisionMessageHeader *hdcsn = cls;
  struct Channel *chn = channel;

  if (0 == memcmp (&hdcsn->member_key, &chn->member_key, sizeof (chn->member_key))
      && 0 == memcmp (&hdcsn->peer, &chn->peer, sizeof (chn->peer)))
  {
    cadet_send_msg (chn, &hdcsn->header);
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
cadet_send_members_cb (void *cls, const struct GNUNET_HashCode *pub_key_hash,
                       void *channel)
{
  const struct GNUNET_MessageHeader *msg = cls;
  struct Channel *chn = channel;
  if (JOIN_ADMITTED == chn->join_status)
    cadet_send_msg (chn, msg);
  return GNUNET_YES;
}


static int
cadet_send_members (struct GNUNET_HashCode *pub_key_hash,
                    const struct GNUNET_MessageHeader *msg)
{
  int n = 0;
  if (channels_in != NULL)
    n += GNUNET_CONTAINER_multihashmap_get_multiple (channels_in, pub_key_hash,
                                                     cadet_send_members_cb,
                                                     (void *) msg);
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
  GNUNET_CRYPTO_hash (&msg->group_key, sizeof (msg->group_key), &pub_key_hash);

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
    grp->pub_key = msg->group_key;
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
  else if (grp->clients_head == grp->clients_tail)
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
    req->group_key = grp->pub_key;
    req->peer = this_peer;
    GNUNET_CRYPTO_ecdsa_key_get_public (&mem->priv_key, &req->member_key);
    if (0 < join_msg_size)
      memcpy (&req[1], join_msg, join_msg_size);

    req->member_key = mem->pub_key;
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
  client_send_msg (&mem->grp, &hdcsn->header);

  const struct MulticastJoinDecisionMessage *
    dcsn = (const struct MulticastJoinDecisionMessage *) &hdcsn[1];
  if (GNUNET_YES == ntohl (dcsn->is_admitted))
  { /* Member admitted, store join_decision. */
    uint16_t dcsn_size = ntohs (dcsn->header.size);
    mem->join_dcsn = GNUNET_malloc (dcsn_size);
    memcpy (mem->join_dcsn, dcsn, dcsn_size);
  }
  else
  { /* Refused entry, disconnect clients. */
    struct ClientList *cl = mem->grp.clients_head;
    while (NULL != cl)
    {
      struct GNUNET_SERVER_Client *client = cl->client;
      cl = cl->next;
      GNUNET_SERVER_client_disconnect (client);
    }
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
    GNUNET_CRYPTO_hash (&hdcsn->member_key, sizeof (hdcsn->member_key),
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
  cadet_send_members (&grp->pub_key_hash, &out->header);
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

  out->member_key = mem->pub_key;
  out->fragment_id = GNUNET_ntohll (++mem->max_fragment_id);
  out->purpose.size = htonl (ntohs (out->header.size)
                             - sizeof (out->header)
                             - sizeof (out->member_key)
                             - sizeof (out->signature));
  out->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_MULTICAST_REQUEST);

  if (GNUNET_OK != GNUNET_CRYPTO_ecdsa_sign (&mem->priv_key, &out->purpose,
                                             &out->signature))
  {
    GNUNET_assert (0);
  }

  if (0 == client_send_origin (&grp->pub_key_hash, &out->header))
  { /* No local origins, send to remote origin */
    if (NULL != mem->origin_channel)
    {
      cadet_send_msg (mem->origin_channel, &out->header);
    }
    else
    {
      /* FIXME: not yet connected to origin */
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      GNUNET_free (out);
      return;
    }
  }
  GNUNET_free (out);
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
  { &client_recv_origin_start, NULL,
    GNUNET_MESSAGE_TYPE_MULTICAST_ORIGIN_START, 0 },

  { &client_recv_member_join, NULL,
    GNUNET_MESSAGE_TYPE_MULTICAST_MEMBER_JOIN, 0 },

  { &client_recv_join_decision, NULL,
    GNUNET_MESSAGE_TYPE_MULTICAST_JOIN_DECISION, 0 },

  { &client_recv_multicast_message, NULL,
    GNUNET_MESSAGE_TYPE_MULTICAST_MESSAGE, 0 },

  { &client_recv_multicast_request, NULL,
    GNUNET_MESSAGE_TYPE_MULTICAST_REQUEST, 0 },

  {NULL, NULL, 0, 0}
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
                                  &req->member_key))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }

  struct GNUNET_HashCode group_key_hash;
  GNUNET_CRYPTO_hash (&req->group_key, sizeof (req->group_key), &group_key_hash);

  struct Channel *chn = GNUNET_malloc (sizeof *chn);
  chn->channel = channel;
  chn->group_key = req->group_key;
  chn->group_key_hash = group_key_hash;
  chn->member_key = req->member_key;
  chn->peer = req->peer;
  chn->join_status = JOIN_WAITING;
  GNUNET_CONTAINER_multihashmap_put (channels_in, &chn->group_key_hash, chn,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);

  client_send_all (&group_key_hash, m);
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
                                  &chn->group_key))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }

  client_send_all (&chn->group_key_hash, m);
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
                                    - sizeof (req->member_key)
                                    - sizeof (req->signature)))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK !=
      GNUNET_CRYPTO_ecdsa_verify (GNUNET_SIGNATURE_PURPOSE_MULTICAST_REQUEST,
                                  &req->purpose, &req->signature,
                                  &req->member_key))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }

  client_send_origin (&chn->group_key_hash, m);
  return GNUNET_OK;
}


/**
 * Message handlers for CADET.
 */
static const struct GNUNET_CADET_MessageHandler cadet_handlers[] = {
  { &cadet_recv_join_request, GNUNET_MESSAGE_TYPE_MULTICAST_JOIN_REQUEST, 0 },
  { &cadet_recv_message, GNUNET_MESSAGE_TYPE_MULTICAST_MESSAGE, 0 },
  { &cadet_recv_request, GNUNET_MESSAGE_TYPE_MULTICAST_REQUEST, 0 },
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
