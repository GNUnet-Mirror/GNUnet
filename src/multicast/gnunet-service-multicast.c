/*
     This file is part of GNUnet.
     Copyright (C) 2009 GNUnet e.V.

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
#include "gnunet_cadet_service.h"
#include "gnunet_multicast_service.h"
#include "multicast.h"

/**
 * Handle to our current configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Service handle.
 */
static struct GNUNET_SERVICE_Handle *service;

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
 *   H(fragment_id, message_id, fragment_offset, flags) -> struct GNUNET_SERVICE_Client *
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
  struct Group *group;

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
   * Current window size, set by cadet_notify_window_change()
   */
  int32_t window_size;

  /**
   * Is the connection established?
   */
  int8_t is_connected;

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
  struct GNUNET_SERVICE_Client *client;
};


/**
 * Client context for an origin or member.
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
   * CADET port hash.
   */
  struct GNUNET_HashCode cadet_port_hash;

  /**
   * Is the client disconnected? #GNUNET_YES or #GNUNET_NO
   */
  uint8_t disconnected;

  /**
   * Is this an origin (#GNUNET_YES), or member (#GNUNET_NO)?
   */
  uint8_t is_origin;

  union {
    struct Origin *origin;
    struct Member *member;
  };
};


/**
* Client context for a group's origin.
 */
struct Origin
{
  struct Group group;

  /**
   * Private key of the group.
   */
  struct GNUNET_CRYPTO_EddsaPrivateKey priv_key;

  /**
   * CADET port.
   */
  struct GNUNET_CADET_Port *cadet_port;

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
  struct Group group;

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
 * Client context.
 */
struct Client {
  struct GNUNET_SERVICE_Client *client;
  struct Group *group;
};


struct ReplayRequestKey
{
  uint64_t fragment_id;
  uint64_t message_id;
  uint64_t fragment_offset;
  uint64_t flags;
};


static struct Channel *
cadet_channel_create (struct Group *grp, struct GNUNET_PeerIdentity *peer);

static void
cadet_channel_destroy (struct Channel *chn);

static void
client_send_join_decision (struct Member *mem,
                           const struct MulticastJoinDecisionMessageHeader *hdcsn);


/**
 * Task run during shutdown.
 *
 * @param cls unused
 */
static void
shutdown_task (void *cls)
{
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
  struct Group *grp = &orig->group;
  GNUNET_CONTAINER_multihashmap_remove (origins, &grp->pub_key_hash, orig);
  if (NULL != orig->cadet_port)
  {
    GNUNET_CADET_close_port (orig->cadet_port);
    orig->cadet_port = NULL;
  }
  GNUNET_free (orig);
}


/**
 * Clean up member data structures after a client disconnected.
 */
static void
cleanup_member (struct Member *mem)
{
  struct Group *grp = &mem->group;
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
  GNUNET_free (mem);
}


/**
 * Clean up group data structures after a client disconnected.
 */
static void
cleanup_group (struct Group *grp)
{
  (GNUNET_YES == grp->is_origin)
    ? cleanup_origin (grp->origin)
    : cleanup_member (grp->member);
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
                                                        &chn->group->pub_key_hash);
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
      GNUNET_CONTAINER_multihashmap_iterator_destroy (it);
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
replay_req_remove_client (struct Group *grp, struct GNUNET_SERVICE_Client *client)
{
  struct GNUNET_CONTAINER_MultiHashMap *
    grp_replay_req = GNUNET_CONTAINER_multihashmap_get (replay_req_client,
                                                        &grp->pub_key_hash);
  if (NULL == grp_replay_req)
    return GNUNET_NO;

  struct GNUNET_CONTAINER_MultiHashMapIterator *
    it = GNUNET_CONTAINER_multihashmap_iterator_create (grp_replay_req);
  struct GNUNET_HashCode key;
  const struct GNUNET_SERVICE_Client *c;
  while (GNUNET_YES
         == GNUNET_CONTAINER_multihashmap_iterator_next (it, &key,
                                                         (const void **) &c))
  {
    if (c == client)
    {
      GNUNET_CONTAINER_multihashmap_remove (grp_replay_req, &key, client);
      GNUNET_CONTAINER_multihashmap_iterator_destroy (it);
      return GNUNET_YES;
    }
  }
  GNUNET_CONTAINER_multihashmap_iterator_destroy (it);
  return GNUNET_NO;
}


/**
 * Send message to a client.
 */
static void
client_send (struct GNUNET_SERVICE_Client *client,
             const struct GNUNET_MessageHeader *msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "%p Sending message to client.\n", client);

  struct GNUNET_MQ_Envelope *
    env = GNUNET_MQ_msg_copy (msg);

  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (client),
                  env);
}


/**
 * Send message to all clients connected to the group.
 */
static void
client_send_group (const struct Group *grp,
                   const struct GNUNET_MessageHeader *msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "%p Sending message to all clients of the group.\n", grp);

  struct ClientList *cl = grp->clients_head;
  while (NULL != cl)
  {
    struct GNUNET_MQ_Envelope *
      env = GNUNET_MQ_msg_copy (msg);

    GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (cl->client),
                    env);
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

  client_send_group (&orig->group, msg);
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
    client_send_group (&mem->group, msg);
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
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Sending message ACK to client.\n");

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
 * Send a message to a CADET channel.
 *
 * @param chn  Channel.
 * @param msg  Message.
 */
static void
cadet_send_channel (struct Channel *chn, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_MQ_Envelope *
    env = GNUNET_MQ_msg_copy (msg);

  GNUNET_MQ_send (GNUNET_CADET_get_mq (chn->channel), env);

  if (0 < chn->window_size)
  {
    client_send_ack (&chn->group_pub_hash);
  }
  else
  {
    chn->msgs_pending++;
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "%p Queuing message. Pending messages: %u\n",
                chn, chn->msgs_pending);
  }
}


/**
 * Create CADET channel and send a join request.
 */
static void
cadet_send_join_request (struct Member *mem)
{
  mem->origin_channel = cadet_channel_create (&mem->group, &mem->origin);
  cadet_send_channel (mem->origin_channel, &mem->join_req->header);

  uint32_t i;
  for (i = 0; i < mem->relay_count; i++)
  {
    struct Channel *
      chn = cadet_channel_create (&mem->group, &mem->relays[i]);
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

  const struct MulticastJoinDecisionMessage *dcsn =
    (struct MulticastJoinDecisionMessage *) &hdcsn[1];

  if (0 == memcmp (&hdcsn->member_pub_key, &chn->member_pub_key, sizeof (chn->member_pub_key))
      && 0 == memcmp (&hdcsn->peer, &chn->peer, sizeof (chn->peer)))
  {
    if (GNUNET_YES == ntohl (dcsn->is_admitted))
    {
      chn->join_status = JOIN_ADMITTED;
    }
    else
    {
      chn->join_status = JOIN_REFUSED;
    }

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


#if 0	    // unused as yet
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
#endif


/**
 * CADET channel connect handler.
 *
 * @see GNUNET_CADET_ConnectEventHandler()
 */
static void *
cadet_notify_connect (void *cls,
                      struct GNUNET_CADET_Channel *channel,
                      const struct GNUNET_PeerIdentity *source)
{
  struct Channel *chn = GNUNET_malloc (sizeof *chn);
  chn->group = cls;
  chn->channel = channel;
  chn->direction = DIR_INCOMING;
  chn->join_status = JOIN_NOT_ASKED;

  GNUNET_CONTAINER_multihashmap_put (channels_in, &chn->group_pub_hash, chn,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  return chn;
}


/**
 * CADET window size change handler.
 *
 * @see GNUNET_CADET_WindowSizeEventHandler()
 */
static void
cadet_notify_window_change (void *cls,
                            const struct GNUNET_CADET_Channel *channel,
                            int window_size)
{
  struct Channel *chn = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "%p Window size changed to %d.  Pending messages: %u\n",
              chn, window_size, chn->msgs_pending);

  chn->is_connected = GNUNET_YES;
  chn->window_size = (int32_t) window_size;

  for (int i = 0; i < window_size; i++)
  {
    if (0 < chn->msgs_pending)
    {
      client_send_ack (&chn->group_pub_hash);
      chn->msgs_pending--;
    }
    else
    {
      break;
    }
  }
}


/**
 * CADET channel disconnect handler.
 *
 * @see GNUNET_CADET_DisconnectEventHandler()
 */
static void
cadet_notify_disconnect (void *cls,
                         const struct GNUNET_CADET_Channel *channel)
{
  if (NULL == cls)
    return;

  struct Channel *chn = cls;
  if (NULL != chn->group)
  {
    if (GNUNET_NO == chn->group->is_origin)
    {
      struct Member *mem = (struct Member *) chn->group;
      if (chn == mem->origin_channel)
        mem->origin_channel = NULL;
    }
  }

  int ret;
  do
  {
    ret = replay_req_remove_cadet (chn);
  }
  while (GNUNET_YES == ret);

  GNUNET_free (chn);
}


static int
check_cadet_join_request (void *cls,
                          const struct MulticastJoinRequestMessage *req)
{
  struct Channel *chn = cls;

  if (NULL == chn
      || JOIN_NOT_ASKED != chn->join_status)
  {
    return GNUNET_SYSERR;
  }

  uint16_t size = ntohs (req->header.size);
  if (size < sizeof (*req))
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

  return GNUNET_OK;
}


/**
 * Incoming join request message from CADET.
 */
static void
handle_cadet_join_request (void *cls,
                           const struct MulticastJoinRequestMessage *req)
{
  struct Channel *chn = cls;
  GNUNET_CADET_receive_done (chn->channel);

  struct GNUNET_HashCode group_pub_hash;
  GNUNET_CRYPTO_hash (&req->group_pub_key, sizeof (req->group_pub_key), &group_pub_hash);
  chn->group_pub_key = req->group_pub_key;
  chn->group_pub_hash = group_pub_hash;
  chn->member_pub_key = req->member_pub_key;
  chn->peer = req->peer;
  chn->join_status = JOIN_WAITING;

  client_send_all (&group_pub_hash, &req->header);
}


static int
check_cadet_join_decision (void *cls,
                           const struct MulticastJoinDecisionMessageHeader *hdcsn)
{
  uint16_t size = ntohs (hdcsn->header.size);
  if (size < sizeof (struct MulticastJoinDecisionMessageHeader) +
             sizeof (struct MulticastJoinDecisionMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }

  struct Channel *chn = cls;
  if (NULL == chn)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (NULL == chn->group || GNUNET_NO != chn->group->is_origin)
  {
    GNUNET_break (0);
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

  return GNUNET_OK;
}


/**
 * Incoming join decision message from CADET.
 */
static void
handle_cadet_join_decision (void *cls,
                            const struct MulticastJoinDecisionMessageHeader *hdcsn)
{
  const struct MulticastJoinDecisionMessage *
    dcsn = (const struct MulticastJoinDecisionMessage *) &hdcsn[1];

  struct Channel *chn = cls;
  GNUNET_CADET_receive_done (chn->channel);

  // FIXME: do we need to copy chn->peer or compare it with hdcsn->peer?
  struct Member *mem = (struct Member *) chn->group;
  client_send_join_decision (mem, hdcsn);
  if (GNUNET_YES == ntohl (dcsn->is_admitted))
  {
    chn->join_status = JOIN_ADMITTED;
  }
  else
  {
    chn->join_status = JOIN_REFUSED;
    cadet_channel_destroy (chn);
  }
}


static int
check_cadet_message (void *cls,
                     const struct GNUNET_MULTICAST_MessageHeader *msg)
{
  uint16_t size = ntohs (msg->header.size);
  if (size < sizeof (*msg))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }

  struct Channel *chn = cls;
  if (NULL == chn)
  {
    GNUNET_break (0);
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

  return GNUNET_OK;
}


/**
 * Incoming multicast message from CADET.
 */
static void
handle_cadet_message (void *cls,
                      const struct GNUNET_MULTICAST_MessageHeader *msg)
{
  struct Channel *chn = cls;
  GNUNET_CADET_receive_done (chn->channel);
  client_send_all (&chn->group_pub_hash, &msg->header);
}


static int
check_cadet_request (void *cls,
                     const struct GNUNET_MULTICAST_RequestHeader *req)
{
  uint16_t size = ntohs (req->header.size);
  if (size < sizeof (*req))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }

  struct Channel *chn = cls;
  if (NULL == chn)
  {
    GNUNET_break (0);
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

  return GNUNET_OK;
}


/**
 * Incoming multicast request message from CADET.
 */
static void
handle_cadet_request (void *cls,
                      const struct GNUNET_MULTICAST_RequestHeader *req)
{
  struct Channel *chn = cls;
  GNUNET_CADET_receive_done (chn->channel);
  client_send_origin (&chn->group_pub_hash, &req->header);
}


static int
check_cadet_replay_request (void *cls,
                            const struct MulticastReplayRequestMessage *req)
{
  uint16_t size = ntohs (req->header.size);
  if (size < sizeof (*req))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }

  struct Channel *chn = cls;
  if (NULL == chn)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }

  return GNUNET_OK;
}


/**
 * Incoming multicast replay request from CADET.
 */
static void
handle_cadet_replay_request (void *cls,
                             const struct MulticastReplayRequestMessage *req)
{
  struct Channel *chn = cls;
  GNUNET_CADET_receive_done (chn->channel);

  struct MulticastReplayRequestMessage rep = *req;
  GNUNET_memcpy (&rep.member_pub_key, &chn->member_pub_key, sizeof (chn->member_pub_key));

  struct GNUNET_CONTAINER_MultiHashMap *
    grp_replay_req = GNUNET_CONTAINER_multihashmap_get (replay_req_cadet,
                                                        &chn->group->pub_key_hash);
  if (NULL == grp_replay_req)
  {
    grp_replay_req = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);
    GNUNET_CONTAINER_multihashmap_put (replay_req_cadet,
                                       &chn->group->pub_key_hash, grp_replay_req,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  }
  struct GNUNET_HashCode key_hash;
  replay_key_hash (rep.fragment_id, rep.message_id, rep.fragment_offset,
                   rep.flags, &key_hash);
  GNUNET_CONTAINER_multihashmap_put (grp_replay_req, &key_hash, chn,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);

  client_send_random (&chn->group_pub_hash, &rep.header);
}


static int
check_cadet_replay_response (void *cls,
                             const struct MulticastReplayResponseMessage *res)
{
  struct Channel *chn = cls;
  if (NULL == chn)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Incoming multicast replay response from CADET.
 */
static void
handle_cadet_replay_response (void *cls,
                              const struct MulticastReplayResponseMessage *res)
{
  struct Channel *chn = cls;
  GNUNET_CADET_receive_done (chn->channel);

  /* @todo FIXME: got replay error response, send request to other members */
}


static void
group_set_cadet_port_hash (struct Group *grp)
{
  struct CadetPort {
    struct GNUNET_CRYPTO_EddsaPublicKey pub_key;
    uint32_t app_type;
  } port = {
    grp->pub_key,
    GNUNET_APPLICATION_TYPE_MULTICAST,
  };
  GNUNET_CRYPTO_hash (&port, sizeof (port), &grp->cadet_port_hash);
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
  chn->group = grp;
  chn->group_pub_key = grp->pub_key;
  chn->group_pub_hash = grp->pub_key_hash;
  chn->peer = *peer;
  chn->direction = DIR_OUTGOING;
  chn->is_connected = GNUNET_NO;
  chn->join_status = JOIN_WAITING;

  struct GNUNET_MQ_MessageHandler cadet_handlers[] = {
    GNUNET_MQ_hd_var_size (cadet_message,
                           GNUNET_MESSAGE_TYPE_MULTICAST_MESSAGE,
                           struct GNUNET_MULTICAST_MessageHeader,
                           chn),

    GNUNET_MQ_hd_var_size (cadet_join_decision,
                           GNUNET_MESSAGE_TYPE_MULTICAST_JOIN_DECISION,
                           struct MulticastJoinDecisionMessageHeader,
                           chn),

    GNUNET_MQ_hd_var_size (cadet_replay_request,
                           GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_REQUEST,
                           struct MulticastReplayRequestMessage,
                           chn),

    GNUNET_MQ_hd_var_size (cadet_replay_response,
                           GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_RESPONSE,
                           struct MulticastReplayResponseMessage,
                           chn),

    GNUNET_MQ_handler_end ()
  };

  chn->channel = GNUNET_CADET_channel_creatE (cadet, chn, &chn->peer,
                                              &grp->cadet_port_hash,
                                              GNUNET_CADET_OPTION_RELIABLE,
                                              cadet_notify_window_change,
                                              cadet_notify_disconnect,
                                              cadet_handlers);
  GNUNET_CONTAINER_multihashmap_put (channels_out, &chn->group_pub_hash, chn,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  return chn;
}


/**
 * Destroy outgoing CADET channel.
 */
static void
cadet_channel_destroy (struct Channel *chn)
{
  GNUNET_CADET_channel_destroy (chn->channel);
  GNUNET_CONTAINER_multihashmap_remove_all (channels_out, &chn->group_pub_hash);
  GNUNET_free (chn);
}

/**
 * Handle a connecting client starting an origin.
 */
static void
handle_client_origin_start (void *cls,
                            const struct MulticastOriginStartMessage *msg)
{
  struct Client *c = cls;
  struct GNUNET_SERVICE_Client *client = c->client;

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

    grp = c->group = &orig->group;
    grp->origin = orig;
    grp->is_origin = GNUNET_YES;
    grp->pub_key = pub_key;
    grp->pub_key_hash = pub_key_hash;

    GNUNET_CONTAINER_multihashmap_put (origins, &grp->pub_key_hash, orig,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);

    group_set_cadet_port_hash (grp);

    struct GNUNET_MQ_MessageHandler cadet_handlers[] = {
      GNUNET_MQ_hd_var_size (cadet_message,
                             GNUNET_MESSAGE_TYPE_MULTICAST_MESSAGE,
                             struct GNUNET_MULTICAST_MessageHeader,
                             grp),

      GNUNET_MQ_hd_var_size (cadet_request,
                             GNUNET_MESSAGE_TYPE_MULTICAST_REQUEST,
                             struct GNUNET_MULTICAST_RequestHeader,
                             grp),

      GNUNET_MQ_hd_var_size (cadet_join_request,
                             GNUNET_MESSAGE_TYPE_MULTICAST_JOIN_REQUEST,
                             struct MulticastJoinRequestMessage,
                             grp),

      GNUNET_MQ_hd_var_size (cadet_replay_request,
                             GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_REQUEST,
                             struct MulticastReplayRequestMessage,
                             grp),

      GNUNET_MQ_hd_var_size (cadet_replay_response,
                             GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_RESPONSE,
                             struct MulticastReplayResponseMessage,
                             grp),

      GNUNET_MQ_handler_end ()
    };


    orig->cadet_port = GNUNET_CADET_open_porT (cadet,
                                               &grp->cadet_port_hash,
                                               cadet_notify_connect,
                                               NULL,
                                               cadet_notify_window_change,
                                               cadet_notify_disconnect,
                                               cadet_handlers);
  }
  else
  {
    grp = &orig->group;
  }

  struct ClientList *cl = GNUNET_new (struct ClientList);
  cl->client = client;
  GNUNET_CONTAINER_DLL_insert (grp->clients_head, grp->clients_tail, cl);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Client connected as origin to group %s.\n",
              orig, GNUNET_h2s (&grp->pub_key_hash));
  GNUNET_SERVICE_client_continue (client);
}


static int
check_client_member_join (void *cls,
                          const struct MulticastMemberJoinMessage *msg)
{
  uint16_t msg_size = ntohs (msg->header.size);
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
  return
    msg_size == (sizeof (*msg) + relay_size + join_msg_size)
    ? GNUNET_OK
    : GNUNET_SYSERR;
}


/**
 * Handle a connecting client joining a group.
 */
static void
handle_client_member_join (void *cls,
                           const struct MulticastMemberJoinMessage *msg)
{
  struct Client *c = cls;
  struct GNUNET_SERVICE_Client *client = c->client;

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
    mem->origin = msg->origin;
    mem->priv_key = msg->member_key;
    mem->pub_key = mem_pub_key;
    mem->pub_key_hash = mem_pub_key_hash;
    mem->max_fragment_id = 0; // FIXME

    grp = c->group = &mem->group;
    grp->member = mem;
    grp->is_origin = GNUNET_NO;
    grp->pub_key = msg->group_pub_key;
    grp->pub_key_hash = pub_key_hash;
    group_set_cadet_port_hash (grp);

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
    grp = &mem->group;
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

  if (NULL != mem->join_dcsn)
  { /* Already got a join decision, send it to client. */
    struct GNUNET_MQ_Envelope *
      env = GNUNET_MQ_msg_copy (&mem->join_dcsn->header);

    GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (client),
                    env);
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

    uint16_t req_msg_size = sizeof (struct MulticastJoinRequestMessage) + join_msg_size;
    struct MulticastJoinRequestMessage *
      req = GNUNET_malloc (req_msg_size);
    req->header.size = htons (req_msg_size);
    req->header.type = htons (GNUNET_MESSAGE_TYPE_MULTICAST_JOIN_REQUEST);
    req->group_pub_key = grp->pub_key;
    req->peer = this_peer;
    GNUNET_CRYPTO_ecdsa_key_get_public (&mem->priv_key, &req->member_pub_key);
    if (0 < join_msg_size)
      GNUNET_memcpy (&req[1], join_msg, join_msg_size);

    req->member_pub_key = mem->pub_key;
    req->purpose.size = htonl (req_msg_size
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
  GNUNET_SERVICE_client_continue (client);
}


static void
client_send_join_decision (struct Member *mem,
                           const struct MulticastJoinDecisionMessageHeader *hdcsn)
{
  client_send_group (&mem->group, &hdcsn->header);

  const struct MulticastJoinDecisionMessage *
    dcsn = (const struct MulticastJoinDecisionMessage *) &hdcsn[1];
  if (GNUNET_YES == ntohl (dcsn->is_admitted))
  { /* Member admitted, store join_decision. */
    uint16_t dcsn_size = ntohs (dcsn->header.size);
    mem->join_dcsn = GNUNET_malloc (dcsn_size);
    GNUNET_memcpy (mem->join_dcsn, dcsn, dcsn_size);
  }
  else
  { /* Refused entry, but replay would be still possible for past members. */
  }
}


static int
check_client_join_decision (void *cls,
                            const struct MulticastJoinDecisionMessageHeader *hdcsn)
{
  return GNUNET_OK;
}


/**
 * Join decision from client.
 */
static void
handle_client_join_decision (void *cls,
                             const struct MulticastJoinDecisionMessageHeader *hdcsn)
{
  struct Client *c = cls;
  struct GNUNET_SERVICE_Client *client = c->client;
  struct Group *grp = c->group;

  if (NULL == grp)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (client);
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
  GNUNET_SERVICE_client_continue (client);
}


static int
check_client_multicast_message (void *cls,
                                const struct GNUNET_MULTICAST_MessageHeader *msg)
{
  return GNUNET_OK;
}


/**
 * Incoming message from a client.
 */
static void
handle_client_multicast_message (void *cls,
                                 const struct GNUNET_MULTICAST_MessageHeader *msg)
{
  struct Client *c = cls;
  struct GNUNET_SERVICE_Client *client = c->client;
  struct Group *grp = c->group;

  if (NULL == grp)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (client);
    return;
  }
  GNUNET_assert (GNUNET_YES == grp->is_origin);
  struct Origin *orig = grp->origin;

  /* FIXME: yucky, should use separate message structs for P2P and CS! */
  struct GNUNET_MULTICAST_MessageHeader *
    out = (struct GNUNET_MULTICAST_MessageHeader *) GNUNET_copy_message (&msg->header);
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
  cadet_send_children (&grp->pub_key_hash, &out->header);
  client_send_ack (&grp->pub_key_hash);
  GNUNET_free (out);

  GNUNET_SERVICE_client_continue (client);
}


static int
check_client_multicast_request (void *cls,
                                const struct GNUNET_MULTICAST_RequestHeader *req)
{
  return GNUNET_OK;
}


/**
 * Incoming request from a client.
 */
static void
handle_client_multicast_request (void *cls,
                                 const struct GNUNET_MULTICAST_RequestHeader *req)
{
  struct Client *c = cls;
  struct GNUNET_SERVICE_Client *client = c->client;
  struct Group *grp = c->group;

  if (NULL == grp)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (client);
    return;
  }
  GNUNET_assert (GNUNET_NO == grp->is_origin);
  struct Member *mem = grp->member;

  /* FIXME: yucky, should use separate message structs for P2P and CS! */
  struct GNUNET_MULTICAST_RequestHeader *
    out = (struct GNUNET_MULTICAST_RequestHeader *) GNUNET_copy_message (&req->header);
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
      GNUNET_SERVICE_client_drop (client);
      GNUNET_free (out);
      return;
    }
  }
  if (GNUNET_YES == send_ack)
  {
    client_send_ack (&grp->pub_key_hash);
  }
  GNUNET_free (out);
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Incoming replay request from a client.
 */
static void
handle_client_replay_request (void *cls,
                              const struct MulticastReplayRequestMessage *rep)
{
  struct Client *c = cls;
  struct GNUNET_SERVICE_Client *client = c->client;
  struct Group *grp = c->group;

  if (NULL == grp)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (client);
    return;
  }
  GNUNET_assert (GNUNET_NO == grp->is_origin);
  struct Member *mem = grp->member;

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

  struct GNUNET_HashCode key_hash;
  replay_key_hash (rep->fragment_id, rep->message_id, rep->fragment_offset,
                   rep->flags, &key_hash);
  GNUNET_CONTAINER_multihashmap_put (grp_replay_req, &key_hash, client,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);

  if (0 == client_send_origin (&grp->pub_key_hash, &rep->header))
  { /* No local origin, replay from remote members / origin. */
    if (NULL != mem->origin_channel)
    {
      cadet_send_channel (mem->origin_channel, &rep->header);
    }
    else
    {
      /* FIXME: not yet connected to origin */
      GNUNET_SERVICE_client_drop (client);
      return;
    }
  }
  GNUNET_SERVICE_client_continue (client);
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
  struct GNUNET_SERVICE_Client *client = value;
  struct GNUNET_MessageHeader *msg = cls;

  client_send (client, msg);
  return GNUNET_OK;
}


static int
check_client_replay_response_end (void *cls,
                                  const struct MulticastReplayResponseMessage *res)
{
  return GNUNET_OK;
}


/**
 * End of replay response from a client.
 */
static void
handle_client_replay_response_end (void *cls,
                                   const struct MulticastReplayResponseMessage *res)
{
  struct Client *c = cls;
  struct GNUNET_SERVICE_Client *client = c->client;
  struct Group *grp = c->group;

  if (NULL == grp)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (client);
    return;
  }

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
  GNUNET_SERVICE_client_continue (client);
}


static int
check_client_replay_response (void *cls,
                              const struct MulticastReplayResponseMessage *res)
{
  const struct GNUNET_MessageHeader *msg = &res->header;
  if (GNUNET_MULTICAST_REC_OK == res->error_code)
  {
    msg = GNUNET_MQ_extract_nested_mh (res);
    if (NULL == msg)
    {
      return GNUNET_SYSERR;
    }
  }
  return GNUNET_OK;
}


/**
 * Incoming replay response from a client.
 *
 * Respond with a multicast message on success, or otherwise with an error code.
 */
static void
handle_client_replay_response (void *cls,
                               const struct MulticastReplayResponseMessage *res)
{
  struct Client *c = cls;
  struct GNUNET_SERVICE_Client *client = c->client;
  struct Group *grp = c->group;

  if (NULL == grp)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (client);
    return;
  }

  const struct GNUNET_MessageHeader *msg = &res->header;
  if (GNUNET_MULTICAST_REC_OK == res->error_code)
  {
    msg = GNUNET_MQ_extract_nested_mh (res);
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
    handle_client_replay_response_end (c, res);
    return;
  }
  GNUNET_SERVICE_client_continue (client);
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
  /* FIXME: send connect ACK */

  struct Client *c = GNUNET_new (struct Client);
  c->client = client;

  return c;
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
  struct Group *grp = c->group;
  GNUNET_free (c);

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
 * Service started.
 *
 * @param cls closure
 * @param server the initialized server
 * @param cfg configuration to use
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_SERVICE_Handle *svc)
{
  cfg = c;
  service = svc;
  GNUNET_CRYPTO_get_peer_identity (cfg, &this_peer);

  stats = GNUNET_STATISTICS_create ("multicast", cfg);
  origins = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);
  members = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);
  group_members = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);
  channels_in = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);
  channels_out = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);
  replay_req_cadet = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);
  replay_req_client = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);

  cadet = GNUNET_CADET_connecT (cfg);

  GNUNET_assert (NULL != cadet);

  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
				 NULL);
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
("multicast",
 GNUNET_SERVICE_OPTION_NONE,
 run,
 client_notify_connect,
 client_notify_disconnect,
 NULL,
 GNUNET_MQ_hd_fixed_size (client_origin_start,
                          GNUNET_MESSAGE_TYPE_MULTICAST_ORIGIN_START,
                          struct MulticastOriginStartMessage,
                          NULL),
 GNUNET_MQ_hd_var_size (client_member_join,
                        GNUNET_MESSAGE_TYPE_MULTICAST_MEMBER_JOIN,
                        struct MulticastMemberJoinMessage,
                        NULL),
 GNUNET_MQ_hd_var_size (client_join_decision,
                        GNUNET_MESSAGE_TYPE_MULTICAST_JOIN_DECISION,
                        struct MulticastJoinDecisionMessageHeader,
                        NULL),
 GNUNET_MQ_hd_var_size (client_multicast_message,
                        GNUNET_MESSAGE_TYPE_MULTICAST_MESSAGE,
                        struct GNUNET_MULTICAST_MessageHeader,
                        NULL),
 GNUNET_MQ_hd_var_size (client_multicast_request,
                        GNUNET_MESSAGE_TYPE_MULTICAST_REQUEST,
                        struct GNUNET_MULTICAST_RequestHeader,
                        NULL),
 GNUNET_MQ_hd_fixed_size (client_replay_request,
                          GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_REQUEST,
                          struct MulticastReplayRequestMessage,
                          NULL),
 GNUNET_MQ_hd_var_size (client_replay_response,
                        GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_RESPONSE,
                        struct MulticastReplayResponseMessage,
                        NULL),
 GNUNET_MQ_hd_var_size (client_replay_response_end,
                        GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_RESPONSE_END,
                        struct MulticastReplayResponseMessage,
                        NULL));

/* end of gnunet-service-multicast.c */
