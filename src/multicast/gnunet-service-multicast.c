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
#include "gnunet_multicast_service.h"
#include "multicast.h"

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
 * All connected origins.
 * Group's pub_key_hash -> struct Group
 */
static struct GNUNET_CONTAINER_MultiHashMap *origins;

/**
 * All connected members.
 * Group's pub_key_hash -> struct Group
 */
static struct GNUNET_CONTAINER_MultiHashMap *members;

/**
 * Common part of the client context for both an origin and member.
 */
struct Group
{
  struct GNUNET_SERVER_Client *client;

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
  struct GNUNET_CRYPTO_EddsaPrivateKey priv_key;

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
cleanup_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  /* FIXME: do clean up here */
}


/**
 * Iterator callback for sending a message to clients.
 */
static int
message_callback (void *cls, const struct GNUNET_HashCode *pub_key_hash,
                  void *group)
{
  const struct GNUNET_MessageHeader *msg = cls;
  struct Group *grp = group;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "%p Sending message to client.\n", grp);

  GNUNET_SERVER_notification_context_add (nc, grp->client);
  GNUNET_SERVER_notification_context_unicast (nc, grp->client, msg, GNUNET_NO);

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
                                                message_callback, (void *) msg);
  if (members != NULL)
    GNUNET_CONTAINER_multihashmap_get_multiple (members, &grp->pub_key_hash,
                                                message_callback, (void *) msg);
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
                                                message_callback, (void *) msg);
}


/**
 * Handle a connecting client starting an origin.
 */
static void
handle_origin_start (void *cls, struct GNUNET_SERVER_Client *client,
                     const struct GNUNET_MessageHeader *m)
{
  const struct MulticastOriginStartMessage *
    msg = (const struct MulticastOriginStartMessage *) m;

  struct Origin *orig = GNUNET_new (struct Origin);
  orig->priv_key = msg->group_key;

  struct Group *grp = &orig->grp;
  grp->is_origin = GNUNET_YES;
  grp->client = client;

  GNUNET_CRYPTO_eddsa_key_get_public (&orig->priv_key, &grp->pub_key);
  GNUNET_CRYPTO_hash (&grp->pub_key, sizeof (grp->pub_key), &grp->pub_key_hash);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Client connected as origin to group %s.\n",
              orig, GNUNET_h2s (&grp->pub_key_hash));

  GNUNET_SERVER_client_set_user_context (client, grp);
  GNUNET_CONTAINER_multihashmap_put (origins, &grp->pub_key_hash, orig,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handle a client stopping an origin.
 */
static void
handle_origin_stop (void *cls, struct GNUNET_SERVER_Client *client,
                    const struct GNUNET_MessageHeader *msg)
{
}


/**
 * Handle a connecting client joining a group.
 */
static void
handle_member_join (void *cls, struct GNUNET_SERVER_Client *client,
                     const struct GNUNET_MessageHeader *m)
{
  struct MulticastMemberJoinMessage *
    msg = (struct MulticastMemberJoinMessage *) m;

  struct Member *mem = GNUNET_new (struct Member);
  mem->priv_key = msg->member_key;

  struct Group *grp = &mem->grp;
  grp->is_origin = GNUNET_NO;
  grp->client = client;
  grp->pub_key = msg->group_key;
  GNUNET_CRYPTO_hash (&grp->pub_key, sizeof (grp->pub_key), &grp->pub_key_hash);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Client connected as member to group %s.\n",
              mem, GNUNET_h2s (&grp->pub_key_hash));

  GNUNET_SERVER_client_set_user_context (client, grp);
  GNUNET_CONTAINER_multihashmap_put (members, &grp->pub_key_hash, mem,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handle a client parting a group.
 */
static void
handle_member_part (void *cls, struct GNUNET_SERVER_Client *client,
                    const struct GNUNET_MessageHeader *msg)
{

}


/**
 * Incoming message from a client.
 */
static void
handle_multicast_message (void *cls, struct GNUNET_SERVER_Client *client,
                          const struct GNUNET_MessageHeader *m)
{
  struct Group *
    grp = GNUNET_SERVER_client_get_user_context (client, struct Group);
  GNUNET_assert (GNUNET_YES == grp->is_origin);
  struct Origin *orig = (struct Origin *) grp;
  struct GNUNET_MULTICAST_MessageHeader *
    msg = (struct GNUNET_MULTICAST_MessageHeader *) m;

  msg->fragment_id = GNUNET_htonll (orig->max_fragment_id++);
  msg->purpose.size = htonl (sizeof (*msg) + ntohs (m->size)
                             - sizeof (msg->header)
                             - sizeof (msg->hop_counter)
                             - sizeof (msg->signature));
  msg->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_MULTICAST_MESSAGE);

  if (GNUNET_OK != GNUNET_CRYPTO_eddsa_sign (&orig->priv_key, &msg->purpose,
                                             &msg->signature))
  {
    /* FIXME: handle error */
    return;
  }

  /* FIXME: send to remote members */

  message_to_group (grp, m);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Incoming request from a client.
 */
static void
handle_multicast_request (void *cls, struct GNUNET_SERVER_Client *client,
                          const struct GNUNET_MessageHeader *m)
{
  struct Group *
    grp = GNUNET_SERVER_client_get_user_context (client, struct Group);
  GNUNET_assert (GNUNET_NO == grp->is_origin);
  struct Member *mem = (struct Member *) grp;

  struct GNUNET_MULTICAST_RequestHeader *
    req = (struct GNUNET_MULTICAST_RequestHeader *) m;

  req->fragment_id = GNUNET_ntohll (mem->max_fragment_id++);

  req->purpose.size = htonl (sizeof (*req) + ntohs (m->size)
                             - sizeof (req->header)
                             - sizeof (req->member_key)
                             - sizeof (req->signature));
  req->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_MULTICAST_MESSAGE);

  if (GNUNET_OK != GNUNET_CRYPTO_eddsa_sign (&mem->priv_key, &req->purpose,
                                             &req->signature))
  {
    /* FIXME: handle error */
    return;
  }

  /* FIXME: send to remote origin */

  message_to_origin (grp, m);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}

/**
 * Process multicast requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param cfg configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    { &handle_origin_start, NULL,
      GNUNET_MESSAGE_TYPE_MULTICAST_ORIGIN_START, 0 },

    { &handle_origin_stop, NULL,
      GNUNET_MESSAGE_TYPE_MULTICAST_ORIGIN_STOP, 0 },

    { &handle_member_join, NULL,
      GNUNET_MESSAGE_TYPE_MULTICAST_MEMBER_JOIN, 0 },

    { &handle_member_part, NULL,
      GNUNET_MESSAGE_TYPE_MULTICAST_MEMBER_PART, 0 },

    { &handle_multicast_message, NULL,
      GNUNET_MESSAGE_TYPE_MULTICAST_MESSAGE, 0 },

    { &handle_multicast_request, NULL,
      GNUNET_MESSAGE_TYPE_MULTICAST_REQUEST, 0 },

    {NULL, NULL, 0, 0}
  };

  cfg = c;
  stats = GNUNET_STATISTICS_create ("multicast", cfg);
  origins = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);
  members = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);
  nc = GNUNET_SERVER_notification_context_create (server, 1);

  GNUNET_SERVER_add_handlers (server, handlers);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &cleanup_task,
                                NULL);
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
