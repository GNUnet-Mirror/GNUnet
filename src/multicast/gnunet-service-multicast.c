/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file multicast/gnunet-service-multicast.c
 * @brief program that does multicast
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_signatures.h"
#include "gnunet_statistics_service.h"
#include "gnunet_core_service.h"
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
 * All connected origins.
 * Group's pub_key_hash -> struct Origin
 */
static struct GNUNET_CONTAINER_MultiHashMap *origins;

/**
 * All connected members.
 * Group's pub_key_hash -> struct Member
 */
static struct GNUNET_CONTAINER_MultiHashMap *members;

/**
 * Connected members per group.
 * Group's pub_key_hash -> Member's pub_key -> struct Member
 */
static struct GNUNET_CONTAINER_MultiHashMap *group_members;

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
   * Last request fragment ID sent to the origin.
   */
  uint64_t max_fragment_id;
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
client_disconnect (void *cls, struct GNUNET_SERVER_Client *client)
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
message_to_clients (const struct Group *grp,
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
origin_message_cb (void *cls, const struct GNUNET_HashCode *pub_key_hash,
                   void *origin)
{
  const struct GNUNET_MessageHeader *msg = cls;
  struct Member *orig = origin;

  message_to_clients (&orig->grp, msg);
  return GNUNET_YES;
}


/**
 * Iterator callback for sending a message to member clients.
 */
static int
member_message_cb (void *cls, const struct GNUNET_HashCode *pub_key_hash,
                   void *member)
{
  const struct GNUNET_MessageHeader *msg = cls;
  struct Member *mem = member;

  if (NULL != mem->join_dcsn)
  { /* Only send message to admitted members */
    message_to_clients (&mem->grp, msg);
  }
  return GNUNET_YES;
}


/**
 * Send message to all origin and member clients connected to the group.
 *
 * @param grp  The group to send @a msg to.
 * @param msg  Message to send.
 */
static void
message_to_group (struct Group *grp, const struct GNUNET_MessageHeader *msg)
{
  if (origins != NULL)
    GNUNET_CONTAINER_multihashmap_get_multiple (origins, &grp->pub_key_hash,
                                                origin_message_cb, (void *) msg);
  if (members != NULL)
    GNUNET_CONTAINER_multihashmap_get_multiple (members, &grp->pub_key_hash,
                                                member_message_cb, (void *) msg);
}


/**
 * Send message to all origin clients connected to the group.
 *
 * @param grp  The group to send @a msg to.
 * @param msg  Message to send.
 */
static void
message_to_origin (struct Group *grp, const struct GNUNET_MessageHeader *msg)
{
  if (origins != NULL)
    GNUNET_CONTAINER_multihashmap_get_multiple (origins, &grp->pub_key_hash,
                                                origin_message_cb, (void *) msg);
}


/**
 * Handle a connecting client starting an origin.
 */
static void
client_origin_start (void *cls, struct GNUNET_SERVER_Client *client,
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
client_member_join (void *cls, struct GNUNET_SERVER_Client *client,
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
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p ..as member %s.\n",
              mem, GNUNET_h2s (&mem_pub_key_hash));

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
    uint32_t relay_count = ntohs (msg->relay_count);
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
    req->member_peer = this_peer;
    GNUNET_CRYPTO_ecdsa_key_get_public (&mem->priv_key, &req->member_key);
    if (0 < join_msg_size)
      memcpy (&req[1], join_msg, join_msg_size);

    req->purpose.size = htonl (sizeof (*req) + join_msg_size
                               - sizeof (req->header)
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

    if (GNUNET_YES
        == GNUNET_CONTAINER_multihashmap_contains (origins, &grp->pub_key_hash))
    { /* Local origin */
      message_to_origin (grp, (struct GNUNET_MessageHeader *) mem->join_req);
    }
    else
    {
      /* FIXME: send join request to remote peers */
    }
  }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Join decision from client.
 */
static void
client_join_decision (void *cls, struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *m)
{
  struct Group *
    grp = GNUNET_SERVER_client_get_user_context (client, struct Group);
  const struct MulticastJoinDecisionMessageHeader *
    hdcsn = (const struct MulticastJoinDecisionMessageHeader *) m;
  const struct MulticastJoinDecisionMessage *
    dcsn = (const struct MulticastJoinDecisionMessage *) &hdcsn[1];

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Got join decision from client for group %s..\n",
              grp, GNUNET_h2s (&grp->pub_key_hash));

  if (GNUNET_YES
      == GNUNET_CONTAINER_multihashmap_contains (origins, &grp->pub_key_hash))
  { /* Local origin */
    struct GNUNET_CONTAINER_MultiHashMap *
      grp_mem = GNUNET_CONTAINER_multihashmap_get (group_members,
                                                   &grp->pub_key_hash);
    if (NULL != grp_mem)
    {
      struct GNUNET_HashCode member_key_hash;
      GNUNET_CRYPTO_hash (&hdcsn->member_key, sizeof (hdcsn->member_key),
                          &member_key_hash);
      struct Member *
        mem = GNUNET_CONTAINER_multihashmap_get (grp_mem, &member_key_hash);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "%p ..and member %s: %p\n",
                  grp, GNUNET_h2s (&member_key_hash), mem);
      if (NULL != mem)
      {
        message_to_clients (&mem->grp, (struct GNUNET_MessageHeader *) hdcsn);
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
    }
  }
  else
  {
    /* FIXME: send join decision to hdcsn->peer */
  }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}

/**
 * Incoming message from a client.
 */
static void
client_multicast_message (void *cls, struct GNUNET_SERVER_Client *client,
                          const struct GNUNET_MessageHeader *m)
{
  struct Group *
    grp = GNUNET_SERVER_client_get_user_context (client, struct Group);
  GNUNET_assert (GNUNET_YES == grp->is_origin);
  struct Origin *orig = (struct Origin *) grp;
  struct GNUNET_MULTICAST_MessageHeader *
    msg = (struct GNUNET_MULTICAST_MessageHeader *) m;

  msg->fragment_id = GNUNET_htonll (++orig->max_fragment_id);
  msg->purpose.size = htonl (sizeof (*msg) + ntohs (m->size)
                             - sizeof (msg->header)
                             - sizeof (msg->hop_counter)
                             - sizeof (msg->signature));
  msg->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_MULTICAST_MESSAGE);

  if (GNUNET_OK != GNUNET_CRYPTO_eddsa_sign (&orig->priv_key, &msg->purpose,
                                             &msg->signature))
  {
    /* FIXME: handle error */
    GNUNET_assert (0);
  }

  /* FIXME: send to remote members */

  message_to_group (grp, m);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Incoming request from a client.
 */
static void
client_multicast_request (void *cls, struct GNUNET_SERVER_Client *client,
                          const struct GNUNET_MessageHeader *m)
{
  struct Group *
    grp = GNUNET_SERVER_client_get_user_context (client, struct Group);
  GNUNET_assert (GNUNET_NO == grp->is_origin);
  struct Member *mem = (struct Member *) grp;

  struct GNUNET_MULTICAST_RequestHeader *
    req = (struct GNUNET_MULTICAST_RequestHeader *) m;

  req->fragment_id = GNUNET_ntohll (++mem->max_fragment_id);
  req->purpose.size = htonl (sizeof (*req) + ntohs (m->size)
                             - sizeof (req->header)
                             - sizeof (req->member_key)
                             - sizeof (req->signature));
  req->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_MULTICAST_REQUEST);

  if (GNUNET_OK != GNUNET_CRYPTO_ecdsa_sign (&mem->priv_key, &req->purpose,
                                             &req->signature))
  {
    /* FIXME: handle error */
    GNUNET_assert (0);
  }

  if (GNUNET_YES
      == GNUNET_CONTAINER_multihashmap_contains (origins, &grp->pub_key_hash))
  { /* Local origin */
    message_to_origin (grp, m);
  }
  else
  {
    /* FIXME: send to remote origin */
  }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Connected to core service.
 */
static void
core_connected_cb  (void *cls, const struct GNUNET_PeerIdentity *my_identity)
{
  this_peer = *my_identity;

  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    { &client_origin_start, NULL,
      GNUNET_MESSAGE_TYPE_MULTICAST_ORIGIN_START, 0 },

    { &client_member_join, NULL,
      GNUNET_MESSAGE_TYPE_MULTICAST_MEMBER_JOIN, 0 },

    { &client_join_decision, NULL,
      GNUNET_MESSAGE_TYPE_MULTICAST_JOIN_DECISION, 0 },

    { &client_multicast_message, NULL,
      GNUNET_MESSAGE_TYPE_MULTICAST_MESSAGE, 0 },

    { &client_multicast_request, NULL,
      GNUNET_MESSAGE_TYPE_MULTICAST_REQUEST, 0 },

    {NULL, NULL, 0, 0}
  };

  stats = GNUNET_STATISTICS_create ("multicast", cfg);
  origins = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);
  members = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);
  group_members = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);
  nc = GNUNET_SERVER_notification_context_create (server, 1);

  GNUNET_SERVER_add_handlers (server, handlers);
  GNUNET_SERVER_disconnect_notify (server, &client_disconnect, NULL);
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
  core = GNUNET_CORE_connect (cfg, NULL, core_connected_cb, NULL, NULL,
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
