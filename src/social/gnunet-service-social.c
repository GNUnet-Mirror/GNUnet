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
 * @file social/gnunet-service-social.c
 * @brief Social service
 * @author Gabor X Toth
 */

#include <inttypes.h>

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_statistics_service.h"
#include "gnunet_psyc_service.h"
#include "gnunet_psyc_util_lib.h"
#include "gnunet_social_service.h"
#include "social.h"


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
 * All connected hosts.
 * Place's pub_key_hash -> struct Host
 */
static struct GNUNET_CONTAINER_MultiHashMap *hosts;

/**
 * All connected guests.
 * Place's pub_key_hash -> struct Guest
 */
static struct GNUNET_CONTAINER_MultiHashMap *guests;

/**
 * Connected guests per place.
 * Place's pub_key_hash -> Guest's pub_key -> struct Guest
 */
static struct GNUNET_CONTAINER_MultiHashMap *place_guests;


/**
 * Message fragment transmission queue.
 */
struct FragmentTransmitQueue
{
  struct FragmentTransmitQueue *prev;
  struct FragmentTransmitQueue *next;

  struct GNUNET_SERVER_Client *client;

  /**
   * Pointer to the next message part inside the data after this struct.
   */
  struct GNUNET_MessageHeader *next_part;

  /**
   * Size of message.
   */
  uint16_t size;

  /**
   * @see enum GNUNET_PSYC_MessageState
   */
  uint8_t state;

  /* Followed by one or more message parts. */
};


/**
 * Message transmission queue.
 */
struct MessageTransmitQueue
{
  struct MessageTransmitQueue *prev;
  struct MessageTransmitQueue *next;

  struct FragmentTransmitQueue *frags_head;
  struct FragmentTransmitQueue *frags_tail;

  struct GNUNET_SERVER_Client *client;
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
 * Common part of the client context for both a host and guest.
 */
struct Place
{
  struct ClientListItem *clients_head;
  struct ClientListItem *clients_tail;

  struct MessageTransmitQueue *tmit_msgs_head;
  struct MessageTransmitQueue *tmit_msgs_tail;

  /**
   * Public key of the channel.
   */
  struct GNUNET_CRYPTO_EddsaPublicKey pub_key;

  /**
   * Hash of @a pub_key.
   */
  struct GNUNET_HashCode pub_key_hash;

  /**
   * Last message ID received for the place.
   * 0 if there is no such message.
   */
  uint64_t max_message_id;

  /**
   * Is this a host (#GNUNET_YES), or guest (#GNUNET_NO)?
   */
  uint8_t is_host;

  /**
   * Is this place ready to receive messages from client?
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
 * Client context for a host.
 */
struct Host
{
  /**
   * Place struct common for Host and Guest
   */
  struct Place plc;

  /**
   * Private key of the channel.
   */
  struct GNUNET_CRYPTO_EddsaPrivateKey priv_key;

  /**
   * Handle for the multicast origin.
   */
  struct GNUNET_PSYC_Master *master;

  /**
   * Transmit handle for multicast.
   */
  struct GNUNET_PSYC_MasterTransmitHandle *tmit_handle;

  /**
   * Incoming join requests.
   * guest_key -> struct GNUNET_PSYC_JoinHandle *
   */
  struct GNUNET_CONTAINER_MultiHashMap *join_reqs;

  /**
   * @see enum GNUNET_PSYC_Policy
   */
  enum GNUNET_PSYC_Policy policy;
};


/**
 * Client context for a guest.
 */
struct Guest
{
  /**
   * Place struct common for Host and Guest.
   */
  struct Place plc;

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
   * Handle for the PSYC slave.
   */
  struct GNUNET_PSYC_Slave *slave;

  /**
   * Transmit handle for multicast.
   */
  struct GNUNET_PSYC_SlaveTransmitHandle *tmit_handle;

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
   * Join decision received from PSYC.
   */
  struct GNUNET_PSYC_JoinDecisionMessage *join_dcsn;

};


struct Client
{
  /**
   * Place where the client entered.
   */
  struct Place *plc;

  /**
   * Message queue for the message currently being transmitted
   * by this client.
   */
  struct MessageTransmitQueue *tmit_msg;
};


static int
psyc_transmit_message (struct Place *plc);


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
 * Clean up host data structures after a client disconnected.
 */
static void
cleanup_host (struct Host *hst)
{
  struct Place *plc = &hst->plc;

  if (NULL != hst->master)
    GNUNET_PSYC_master_stop (hst->master, GNUNET_NO, NULL, NULL); // FIXME
  GNUNET_CONTAINER_multihashmap_destroy (hst->join_reqs);
  GNUNET_CONTAINER_multihashmap_remove (hosts, &plc->pub_key_hash, plc);
}


/**
 * Clean up guest data structures after a client disconnected.
 */
static void
cleanup_guest (struct Guest *gst)
{
  struct Place *plc = &gst->plc;
  struct GNUNET_CONTAINER_MultiHashMap *
    plc_gst = GNUNET_CONTAINER_multihashmap_get (place_guests,
                                                &plc->pub_key_hash);
  GNUNET_assert (NULL != plc_gst);
  GNUNET_CONTAINER_multihashmap_remove (plc_gst, &gst->pub_key_hash, gst);

  if (0 == GNUNET_CONTAINER_multihashmap_size (plc_gst))
  {
    GNUNET_CONTAINER_multihashmap_remove (place_guests, &plc->pub_key_hash,
                                          plc_gst);
    GNUNET_CONTAINER_multihashmap_destroy (plc_gst);
  }
  GNUNET_CONTAINER_multihashmap_remove (guests, &plc->pub_key_hash, gst);

  if (NULL != gst->join_req)
    GNUNET_free (gst->join_req);
  if (NULL != gst->relays)
    GNUNET_free (gst->relays);
  if (NULL != gst->slave)
    GNUNET_PSYC_slave_part (gst->slave, GNUNET_NO, NULL, NULL); // FIXME
  GNUNET_CONTAINER_multihashmap_remove (guests, &plc->pub_key_hash, plc);
}


/**
 * Clean up place data structures after a client disconnected.
 */
static void
cleanup_place (struct Place *plc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Cleaning up place %s\n",
              plc, GNUNET_h2s (&plc->pub_key_hash));

  (GNUNET_YES == plc->is_host)
    ? cleanup_host ((struct Host *) plc)
    : cleanup_guest ((struct Guest *) plc);
  GNUNET_free (plc);
}


static void
schedule_cleanup_place (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  cleanup_place (cls);
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

  struct Client *
    ctx = GNUNET_SERVER_client_get_user_context (client, struct Client);
  if (NULL == ctx)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%p User context is NULL in client_disconnect()\n", ctx);
    GNUNET_break (0);
    return;
  }

  struct Place *plc = ctx->plc;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Client (%s) disconnected from place %s\n",
              plc, (GNUNET_YES == plc->is_host) ? "host" : "guest",
              GNUNET_h2s (&plc->pub_key_hash));

  struct ClientListItem *cli = plc->clients_head;
  while (NULL != cli)
  {
    if (cli->client == client)
    {
      GNUNET_CONTAINER_DLL_remove (plc->clients_head, plc->clients_tail, cli);
      GNUNET_free (cli);
      break;
    }
    cli = cli->next;
  }

  if (NULL == plc->clients_head)
  { /* Last client disconnected. */
    if (GNUNET_YES != plc->is_disconnected)
    {
      plc->is_disconnected = GNUNET_YES;
      if (NULL != plc->tmit_msgs_head)
      { /* Send pending messages to PSYC before cleanup. */
        psyc_transmit_message (plc);
      }
      else
      {
        cleanup_place (plc);
      }
    }
  }
}


/**
 * Send message to all clients connected to the channel.
 */
static void
client_send_msg (const struct Place *plc,
                 const struct GNUNET_MessageHeader *msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "%p Sending message to clients.\n", plc);

  struct ClientListItem *cli = plc->clients_head;
  while (NULL != cli)
  {
    GNUNET_SERVER_notification_context_add (nc, cli->client);
    GNUNET_SERVER_notification_context_unicast (nc, cli->client, msg, GNUNET_NO);
    cli = cli->next;
  }
}


/**
 * Called after a PSYC master is started.
 */
static void
psyc_master_started (void *cls, int result, uint64_t max_message_id)
{
  struct Host *hst = cls;
  struct Place *plc = &hst->plc;
  plc->max_message_id = max_message_id;
  plc->is_ready = GNUNET_YES;

  struct GNUNET_PSYC_CountersResultMessage res;
  res.header.type = htons (GNUNET_MESSAGE_TYPE_SOCIAL_HOST_ENTER_ACK);
  res.header.size = htons (sizeof (res));
  res.result_code = htonl (result - INT32_MIN);
  res.max_message_id = GNUNET_htonll (plc->max_message_id);

  client_send_msg (plc, &res.header);
}


/**
 * Called when a PSYC master receives a join request.
 */
static void
psyc_recv_join_request (void *cls,
                        const struct GNUNET_PSYC_JoinRequestMessage *req,
                        const struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key,
                        const struct GNUNET_PSYC_Message *join_msg,
                        struct GNUNET_PSYC_JoinHandle *jh)
{
  struct Host *hst = cls;
  struct GNUNET_HashCode slave_key_hash;
  GNUNET_CRYPTO_hash (slave_key, sizeof (*slave_key), &slave_key_hash);
  GNUNET_CONTAINER_multihashmap_put (hst->join_reqs, &slave_key_hash, jh,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  client_send_msg (&hst->plc, &req->header);
}


/**
 * Called after a PSYC slave is connected.
 */
static void
psyc_slave_connected (void *cls, int result, uint64_t max_message_id)
{
  struct Guest *gst = cls;
  struct Place *plc = &gst->plc;
  plc->max_message_id = max_message_id;
  plc->is_ready = GNUNET_YES;

  struct GNUNET_PSYC_CountersResultMessage res;
  res.header.type = htons (GNUNET_MESSAGE_TYPE_SOCIAL_GUEST_ENTER_ACK);
  res.header.size = htons (sizeof (res));
  res.result_code = htonl (result - INT32_MIN);
  res.max_message_id = GNUNET_htonll (plc->max_message_id);

  client_send_msg (plc, &res.header);
}


/**
 * Called when a PSYC slave receives a join decision.
 */
static void
psyc_recv_join_dcsn (void *cls,
                     const struct GNUNET_PSYC_JoinDecisionMessage *dcsn,
                     int is_admitted,
                     const struct GNUNET_PSYC_Message *join_msg)
{
  struct Guest *gst = cls;
  client_send_msg (&gst->plc, &dcsn->header);
}


/**
 * Called when a PSYC master or slave receives a message.
 */
static void
psyc_recv_message (void *cls,
                   uint64_t message_id,
                   uint32_t flags,
                   const struct GNUNET_PSYC_MessageHeader *msg)
{
  struct Place *plc = cls;
  client_send_msg (plc, &msg->header);

  /* FIXME: further processing */
}


/**
 * Initialize place data structure.
 */
static void
place_init (struct Place *plc)
{

}


/**
 * Handle a connecting client entering a place as host.
 */
static void
client_recv_host_enter (void *cls, struct GNUNET_SERVER_Client *client,
                        const struct GNUNET_MessageHeader *msg)
{
  const struct HostEnterRequest *req
    = (const struct HostEnterRequest *) msg;

  struct GNUNET_CRYPTO_EddsaPublicKey pub_key;
  struct GNUNET_HashCode pub_key_hash;

  GNUNET_CRYPTO_eddsa_key_get_public (&req->place_key, &pub_key);
  GNUNET_CRYPTO_hash (&pub_key, sizeof (pub_key), &pub_key_hash);

  struct Host *
    hst = GNUNET_CONTAINER_multihashmap_get (hosts, &pub_key_hash);
  struct Place *plc;

  if (NULL == hst)
  {
    hst = GNUNET_new (struct Host);
    hst->policy = ntohl (req->policy);
    hst->priv_key = req->place_key;
    hst->join_reqs = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);

    plc = &hst->plc;
    plc->is_host = GNUNET_YES;
    plc->pub_key = pub_key;
    plc->pub_key_hash = pub_key_hash;
    place_init (plc);

    GNUNET_CONTAINER_multihashmap_put (hosts, &plc->pub_key_hash, plc,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
    hst->master = GNUNET_PSYC_master_start (cfg, &hst->priv_key, hst->policy,
                                            &psyc_master_started,
                                            &psyc_recv_join_request,
                                            &psyc_recv_message, NULL, hst);
  }
  else
  {
    plc = &hst->plc;

    struct GNUNET_PSYC_CountersResultMessage res;
    res.header.type = htons (GNUNET_MESSAGE_TYPE_SOCIAL_HOST_ENTER_ACK);
    res.header.size = htons (sizeof (res));
    res.result_code = htonl (GNUNET_OK);
    res.max_message_id = GNUNET_htonll (plc->max_message_id);

    GNUNET_SERVER_notification_context_add (nc, client);
    GNUNET_SERVER_notification_context_unicast (nc, client, &res.header,
                                                GNUNET_NO);
  }

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "%p Client connected as host to place %s.\n",
              hst, GNUNET_h2s (&plc->pub_key_hash));

  struct ClientListItem *cli = GNUNET_new (struct ClientListItem);
  cli->client = client;
  GNUNET_CONTAINER_DLL_insert (plc->clients_head, plc->clients_tail, cli);

  struct Client *ctx = GNUNET_new (struct Client);
  ctx->plc = plc;
  GNUNET_SERVER_client_set_user_context (client, ctx);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handle a connecting client entering a place as guest.
 */
static void
client_recv_guest_enter (void *cls, struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *msg)
{
  const struct GuestEnterRequest *req
    = (const struct GuestEnterRequest *) msg;
  uint16_t req_size = ntohs (req->header.size);

  struct GNUNET_CRYPTO_EcdsaPublicKey gst_pub_key;
  struct GNUNET_HashCode pub_key_hash, gst_pub_key_hash;

  GNUNET_CRYPTO_ecdsa_key_get_public (&req->guest_key, &gst_pub_key);
  GNUNET_CRYPTO_hash (&gst_pub_key, sizeof (gst_pub_key), &gst_pub_key_hash);
  GNUNET_CRYPTO_hash (&req->place_key, sizeof (req->place_key), &pub_key_hash);

  struct GNUNET_CONTAINER_MultiHashMap *
    plc_gst = GNUNET_CONTAINER_multihashmap_get (place_guests, &pub_key_hash);
  struct Guest *gst = NULL;
  struct Place *plc;

  if (NULL != plc_gst)
  {
    gst = GNUNET_CONTAINER_multihashmap_get (plc_gst, &gst_pub_key_hash);
  }
  if (NULL == gst || NULL == gst->slave)
  {
    gst = GNUNET_new (struct Guest);
    gst->priv_key = req->guest_key;
    gst->pub_key = gst_pub_key;
    gst->pub_key_hash = gst_pub_key_hash;
    gst->origin = req->origin;
    gst->relay_count = ntohl (req->relay_count);

    const struct GNUNET_PeerIdentity *
      relays = (const struct GNUNET_PeerIdentity *) &req[1];
    uint16_t relay_size = gst->relay_count * sizeof (*relays);
    struct GNUNET_PSYC_Message *join_msg = NULL;
    uint16_t join_msg_size = 0;

    if (sizeof (*req) + relay_size + sizeof (struct GNUNET_MessageHeader)
        <= req_size)
    {
      join_msg = (struct GNUNET_PSYC_Message *)
        (((char *) &req[1]) + relay_size);
      join_msg_size = ntohs (join_msg->header.size);
    }
    if (sizeof (*req) + relay_size + join_msg_size != req_size)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "%u + %u + %u != %u\n",
                  sizeof (*req), relay_size, join_msg_size, req_size);
      GNUNET_break (0);
      GNUNET_SERVER_client_disconnect (client);
      GNUNET_free (gst);
      return;
    }
    if (0 < gst->relay_count)
    {
      gst->relays = GNUNET_malloc (relay_size);
      memcpy (gst->relays, &req[1], relay_size);
    }

    plc = &gst->plc;
    plc->is_host = GNUNET_NO;
    plc->pub_key = req->place_key;
    plc->pub_key_hash = pub_key_hash;
    place_init (plc);

    if (NULL == plc_gst)
    {
      plc_gst = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);
      (void) GNUNET_CONTAINER_multihashmap_put (place_guests, &plc->pub_key_hash, plc_gst,
                                                GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
    }
    (void) GNUNET_CONTAINER_multihashmap_put (plc_gst, &gst->pub_key_hash, gst,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
    (void) GNUNET_CONTAINER_multihashmap_put (guests, &plc->pub_key_hash, gst,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
    gst->slave
      = GNUNET_PSYC_slave_join (cfg, &plc->pub_key, &gst->priv_key,
                                &gst->origin, gst->relay_count, gst->relays,
                                &psyc_recv_message, NULL, &psyc_slave_connected,
                                &psyc_recv_join_dcsn, gst, join_msg);
  }
  else
  {
    plc = &gst->plc;

    struct GNUNET_PSYC_CountersResultMessage res;
    res.header.type = htons (GNUNET_MESSAGE_TYPE_SOCIAL_GUEST_ENTER_ACK);
    res.header.size = htons (sizeof (res));
    res.result_code = htonl (GNUNET_OK);
    res.max_message_id = GNUNET_htonll (plc->max_message_id);

    GNUNET_SERVER_notification_context_add (nc, client);
    GNUNET_SERVER_notification_context_unicast (nc, client, &res.header,
                                                GNUNET_NO);
    if (NULL != gst->join_dcsn)
    {
      GNUNET_SERVER_notification_context_add (nc, client);
      GNUNET_SERVER_notification_context_unicast (nc, client,
                                                  &gst->join_dcsn->header,
                                                  GNUNET_NO);
    }
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Client connected as guest to place %s.\n",
              gst, GNUNET_h2s (&plc->pub_key_hash));

  struct ClientListItem *cli = GNUNET_new (struct ClientListItem);
  cli->client = client;
  GNUNET_CONTAINER_DLL_insert (plc->clients_head, plc->clients_tail, cli);

  struct Client *ctx = GNUNET_new (struct Client);
  ctx->plc = plc;
  GNUNET_SERVER_client_set_user_context (client, ctx);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


struct JoinDecisionClosure
{
  int32_t is_admitted;
  struct GNUNET_PSYC_Message *msg;
};


/**
 * Iterator callback for responding to join requests.
 */
static int
psyc_send_join_decision (void *cls, const struct GNUNET_HashCode *pub_key_hash,
                         void *value)
{
  struct JoinDecisionClosure *jcls = cls;
  struct GNUNET_PSYC_JoinHandle *jh = value;
  // FIXME: add relays
  GNUNET_PSYC_join_decision (jh, jcls->is_admitted, 0, NULL, jcls->msg);
  return GNUNET_YES;
}


/**
 * Handle an entry decision from a host client.
 */
static void
client_recv_join_decision (void *cls, struct GNUNET_SERVER_Client *client,
                           const struct GNUNET_MessageHeader *msg)
{
  struct Client *
    ctx = GNUNET_SERVER_client_get_user_context (client, struct Client);
  GNUNET_assert (NULL != ctx);
  struct Place *plc = ctx->plc;
  GNUNET_assert (GNUNET_YES == plc->is_host);
  struct Host *hst = (struct Host *) plc;

  struct GNUNET_PSYC_JoinDecisionMessage *
    dcsn = (struct GNUNET_PSYC_JoinDecisionMessage *) msg;
  struct JoinDecisionClosure jcls;
  jcls.is_admitted = ntohl (dcsn->is_admitted);
  jcls.msg
    = (sizeof (*dcsn) + sizeof (*jcls.msg) <= ntohs (msg->size))
    ? (struct GNUNET_PSYC_Message *) &dcsn[1]
    : NULL;

  struct GNUNET_HashCode slave_key_hash;
  GNUNET_CRYPTO_hash (&dcsn->slave_key, sizeof (dcsn->slave_key),
                      &slave_key_hash);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Got join decision (%d) from client for place %s..\n",
              hst, jcls.is_admitted, GNUNET_h2s (&plc->pub_key_hash));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p ..and slave %s.\n",
              hst, GNUNET_h2s (&slave_key_hash));

  GNUNET_CONTAINER_multihashmap_get_multiple (hst->join_reqs, &slave_key_hash,
                                              &psyc_send_join_decision, &jcls);
  GNUNET_CONTAINER_multihashmap_remove_all (hst->join_reqs, &slave_key_hash);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Send acknowledgement to a client.
 *
 * Sent after a message fragment has been passed on to multicast.
 *
 * @param plc The place struct for the client.
 */
static void
send_message_ack (struct Place *plc, struct GNUNET_SERVER_Client *client)
{
  struct GNUNET_MessageHeader res;
  res.size = htons (sizeof (res));
  res.type = htons (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_ACK);

  GNUNET_SERVER_notification_context_add (nc, client);
  GNUNET_SERVER_notification_context_unicast (nc, client, &res, GNUNET_NO);
}


/**
 * Proceed to the next message part in the transmission queue.
 *
 * @param plc
 *        Place where the transmission is going on.
 * @param tmit_msg
 *        Currently transmitted message.
 * @param tmit_frag
 *        Currently transmitted message fragment.
 *
 * @return @a tmit_frag, or NULL if reached the end of fragment.
 */
static struct FragmentTransmitQueue *
psyc_transmit_queue_next_part (struct Place *plc,
                               struct MessageTransmitQueue *tmit_msg,
                               struct FragmentTransmitQueue *tmit_frag)
{
  uint16_t psize = ntohs (tmit_frag->next_part->size);
  if ((char *) tmit_frag->next_part + psize - ((char *) &tmit_frag[1])
      < tmit_frag->size)
  {
    tmit_frag->next_part
      = (struct GNUNET_MessageHeader *) ((char *) tmit_frag->next_part + psize);
  }
  else /* Reached end of current fragment. */
  {
    if (NULL != tmit_frag->client)
      send_message_ack (plc, tmit_frag->client);
    GNUNET_CONTAINER_DLL_remove (tmit_msg->frags_head, tmit_msg->frags_tail, tmit_frag);
    GNUNET_free (tmit_frag);
    tmit_frag = NULL;
  }
  return tmit_frag;
}


/**
 * Proceed to next message in transmission queue.
 *
 * @param plc
 *        Place where the transmission is going on.
 * @param tmit_msg
 *        Currently transmitted message.
 *
 * @return The next message in queue, or NULL if queue is empty.
 */
static struct MessageTransmitQueue *
psyc_transmit_queue_next_msg (struct Place *plc,
                              struct MessageTransmitQueue *tmit_msg)
{
  GNUNET_CONTAINER_DLL_remove (plc->tmit_msgs_head, plc->tmit_msgs_tail, tmit_msg);
  GNUNET_free (tmit_msg);
  return plc->tmit_msgs_head;
}


/**
 * Callback for data transmission to PSYC.
 */
static int
psyc_transmit_notify_data (void *cls, uint16_t *data_size, void *data)
{
  struct Place *plc = cls;
  struct MessageTransmitQueue *tmit_msg = plc->tmit_msgs_head;
  GNUNET_assert (NULL != tmit_msg);
  struct FragmentTransmitQueue *tmit_frag = tmit_msg->frags_head;
  if (NULL == tmit_frag)
  { /* Rest of the message have not arrived yet, pause transmission */
    *data_size = 0;
    return GNUNET_NO;
  }
  struct GNUNET_MessageHeader *pmsg = tmit_frag->next_part;
  if (NULL == pmsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%p psyc_transmit_notify_data: nothing to send.\n", plc);
    *data_size = 0;
    return GNUNET_NO;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p psyc_transmit_notify_data()\n", plc);
  GNUNET_PSYC_log_message (GNUNET_ERROR_TYPE_DEBUG, pmsg);

  uint16_t ptype = ntohs (pmsg->type);
  uint16_t pdata_size = ntohs (pmsg->size) - sizeof (*pmsg);
  int ret;

  switch (ptype)
  {
  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_DATA:
    if (*data_size < pdata_size)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%p psyc_transmit_notify_data: buffer size too small for data.\n", plc);
      *data_size = 0;
      return GNUNET_NO;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%p psyc_transmit_notify_data: sending %u bytes.\n",
                plc, pdata_size);

    *data_size = pdata_size;
    memcpy (data, &pmsg[1], *data_size);
    ret = GNUNET_NO;
    break;

  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_END:
    *data_size = 0;
    ret = GNUNET_YES;
    break;

  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_CANCEL:
    *data_size = 0;
    ret = GNUNET_SYSERR;
    break;

  default:
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "%p psyc_transmit_notify_data: unexpected message part of type %u.\n",
                plc, ptype);
    ret = GNUNET_SYSERR;
  }

  if (GNUNET_SYSERR == ret && GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_CANCEL != ptype)
  {
    *data_size = 0;
    tmit_msg = psyc_transmit_queue_next_msg (plc, tmit_msg);
    plc->is_disconnected = GNUNET_YES;
    GNUNET_SERVER_client_disconnect (tmit_frag->client);
    GNUNET_SCHEDULER_add_now (&schedule_cleanup_place, plc);
    return ret;
  }
  else
  {
    tmit_frag = psyc_transmit_queue_next_part (plc, tmit_msg, tmit_frag);
    if (NULL != tmit_frag)
    {
      struct GNUNET_MessageHeader *pmsg = tmit_frag->next_part;
      ptype = ntohs (pmsg->type);
      switch (ptype)
      {
      case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_END:
        ret = GNUNET_YES;
        break;
      case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_CANCEL:
        ret = GNUNET_SYSERR;
        break;
      }
      switch (ptype)
      {
      case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_END:
      case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_CANCEL:
        tmit_frag = psyc_transmit_queue_next_part (plc, tmit_msg, tmit_frag);
      }
    }

    if (NULL == tmit_msg->frags_head
        && GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_END <= ptype)
    { /* Reached end of current message. */
      tmit_msg = psyc_transmit_queue_next_msg (plc, tmit_msg);
    }
  }

  if (ret != GNUNET_NO)
  {
    if (NULL != tmit_msg)
    {
      psyc_transmit_message (plc);
    }
    else if (GNUNET_YES == plc->is_disconnected)
    {
      /* FIXME: handle partial message (when still in_transmit) */
      cleanup_place (plc);
    }
  }
  return ret;
}


/**
 * Callback for modifier transmission to PSYC.
 */
static int
psyc_transmit_notify_mod (void *cls, uint16_t *data_size, void *data,
                          uint8_t *oper, uint32_t *full_value_size)
{
  struct Place *plc = cls;
  struct MessageTransmitQueue *tmit_msg = plc->tmit_msgs_head;
  GNUNET_assert (NULL != tmit_msg);
  struct FragmentTransmitQueue *tmit_frag = tmit_msg->frags_head;
  if (NULL == tmit_frag)
  { /* Rest of the message have not arrived yet, pause transmission */
    *data_size = 0;
    return GNUNET_NO;
  }
  struct GNUNET_MessageHeader *pmsg = tmit_frag->next_part;
  if (NULL == pmsg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%p psyc_transmit_notify_mod: nothing to send.\n", plc);
    *data_size = 0;
    return GNUNET_NO;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p psyc_transmit_notify_mod()\n", plc);
  GNUNET_PSYC_log_message (GNUNET_ERROR_TYPE_DEBUG, pmsg);

  uint16_t ptype = ntohs (pmsg->type);
  int ret;

  switch (ptype)
  {
  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MODIFIER:
  {
    if (NULL == oper)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "%p psyc_transmit_notify_mod: oper is NULL.\n", plc);
      ret = GNUNET_SYSERR;
      break;
    }
    struct GNUNET_PSYC_MessageModifier *
      pmod = (struct GNUNET_PSYC_MessageModifier *) tmit_frag->next_part;
    uint16_t mod_size = ntohs (pmod->header.size) - sizeof (*pmod);

    if (*data_size < mod_size)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%p psyc_transmit_notify_mod: buffer size too small for data.\n", plc);
      *data_size = 0;
      return GNUNET_NO;
    }

    *full_value_size = ntohl (pmod->value_size);
    *oper = pmod->oper;
    *data_size = mod_size;
    memcpy (data, &pmod[1], mod_size);
    ret = GNUNET_NO;
    break;
  }

  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MOD_CONT:
  {
    if (NULL != oper)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "%p psyc_transmit_notify_mod: oper is not NULL.\n", plc);
      ret = GNUNET_SYSERR;
      break;
    }
    uint16_t mod_size = ntohs (pmsg->size) - sizeof (*pmsg);
    if (*data_size < mod_size)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%p psyc_transmit_notify_mod: buffer size too small for data.\n", plc);
      *data_size = 0;
      return GNUNET_NO;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%p psyc_transmit_notify_mod: sending %u bytes.\n", plc, mod_size);

    *data_size = mod_size;
    memcpy (data, &pmsg[1], *data_size);
    ret = GNUNET_NO;
    break;
  }

  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_DATA:
  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_END:
  case GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_CANCEL:
    *data_size = 0;
    ret = GNUNET_YES;
    break;

  default:
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "%p psyc_transmit_notify_mod: unexpected message part of type %u.\n",
                plc, ptype);
    ret = GNUNET_SYSERR;
  }

  if (GNUNET_SYSERR == ret)
  {
    *data_size = 0;
    ret = GNUNET_SYSERR;
    tmit_msg = psyc_transmit_queue_next_msg (plc, tmit_msg);
    plc->is_disconnected = GNUNET_YES;
    GNUNET_SERVER_client_disconnect (tmit_frag->client);
    GNUNET_SCHEDULER_add_now (&schedule_cleanup_place, plc);
  }
  else
  {
    if (GNUNET_YES != ret)
      psyc_transmit_queue_next_part (plc, tmit_msg, tmit_frag);

    if (NULL == tmit_msg->frags_head
        && GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_END <= ptype)
    { /* Reached end of current message. */
      tmit_msg = psyc_transmit_queue_next_msg (plc, tmit_msg);
    }
  }
  return ret;
}

/**
 * Callback for data transmission from a host to PSYC.
 */
static int
host_transmit_notify_data (void *cls, uint16_t *data_size, void *data)
{
  int ret = psyc_transmit_notify_data (cls, data_size, data);

  if (GNUNET_NO != ret)
  {
    struct Host *hst = cls;
    hst->tmit_handle = NULL;
  }
  return ret;
}


/**
 * Callback for the transmit functions of multicast.
 */
static int
guest_transmit_notify_data (void *cls, uint16_t *data_size, void *data)
{
  int ret = psyc_transmit_notify_data (cls, data_size, data);

  if (GNUNET_NO != ret)
  {
    struct Guest *gst = cls;
    gst->tmit_handle = NULL;
  }
  return ret;
}


/**
 * Callback for modifier transmission from a host to PSYC.
 */
static int
host_transmit_notify_mod (void *cls, uint16_t *data_size, void *data,
                          uint8_t *oper, uint32_t *full_value_size)
{
  int ret = psyc_transmit_notify_mod (cls, data_size, data,
                                      oper, full_value_size);
  if (GNUNET_SYSERR == ret)
  {
    struct Host *hst = cls;
    hst->tmit_handle = NULL;
  }
  return ret;
}


/**
 * Callback for modifier transmission from a guest to PSYC.
 */
static int
guest_transmit_notify_mod (void *cls, uint16_t *data_size, void *data,
                           uint8_t *oper, uint32_t *full_value_size)
{
  int ret = psyc_transmit_notify_mod (cls, data_size, data,
                                      oper, full_value_size);
  if (GNUNET_SYSERR == ret)
  {
    struct Guest *gst = cls;
    gst->tmit_handle = NULL;
  }
  return ret;
}


/**
 * Get method part of next message from transmission queue.
 *
 * @param tmit_msg
 *        Next item in message transmission queue.
 * @param[out] pmeth
 *        The message method is returned here.
 *
 * @return #GNUNET_OK on success
 *         #GNUNET_NO if there are no more messages in queue.
 *         #GNUNET_SYSERR if the next message is malformed.
 */
static int
psyc_transmit_queue_next_method (struct Place *plc,
                                 struct GNUNET_PSYC_MessageMethod **pmeth)
{
  struct MessageTransmitQueue *tmit_msg = plc->tmit_msgs_head;
  if (NULL == tmit_msg)
    return GNUNET_NO;

  struct FragmentTransmitQueue *tmit_frag = tmit_msg->frags_head;
  if (NULL == tmit_frag)
  {
    GNUNET_break (0);
    return GNUNET_NO;
  }

  struct GNUNET_MessageHeader *pmsg = tmit_frag->next_part;
  if (NULL == pmsg
      || GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_METHOD != ntohs (pmsg->type))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "%p psyc_transmit_queue_next_method: unexpected message part of type %u.\n",
                plc, ntohs (pmsg->type));
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  uint16_t psize = ntohs (pmsg->size);
  *pmeth = (struct GNUNET_PSYC_MessageMethod *) pmsg;
  if (psize < sizeof (**pmeth) + 1 || '\0' != *((char *) *pmeth + psize - 1))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "%p psyc_transmit_queue_next_method: invalid method name.\n",
                plc, ntohs (pmsg->type));
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "%u <= %u || NUL != %u\n",
                sizeof (**pmeth), psize, *((char *) *pmeth + psize - 1));
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  psyc_transmit_queue_next_part (plc, tmit_msg, tmit_frag);
  return GNUNET_OK;
}


/**
 * Transmit the next message in queue from the host to the PSYC channel.
 */
static int
psyc_master_transmit_message (struct Host *hst)
{

  if (NULL == hst->tmit_handle)
  {
    struct GNUNET_PSYC_MessageMethod *pmeth = NULL;
    int ret = psyc_transmit_queue_next_method (&hst->plc, &pmeth);
    if (GNUNET_OK != ret)
      return ret;

    hst->tmit_handle
      = GNUNET_PSYC_master_transmit (hst->master, (const char *) &pmeth[1],
                                     &host_transmit_notify_mod,
                                     &host_transmit_notify_data, hst,
                                     pmeth->flags);
  }
  else
  {
    GNUNET_PSYC_master_transmit_resume (hst->tmit_handle);
  }
  return GNUNET_OK;
}


/**
 * Transmit the next message in queue from a guest to the PSYC channel.
 */
static int
psyc_slave_transmit_message (struct Guest *gst)
{
  if (NULL == gst->tmit_handle)
  {
    struct GNUNET_PSYC_MessageMethod *pmeth = NULL;
    int ret = psyc_transmit_queue_next_method (&gst->plc, &pmeth);
    if (GNUNET_OK != ret)
      return ret;

    gst->tmit_handle
      = GNUNET_PSYC_slave_transmit (gst->slave, (const char *) &pmeth[1],
                                    &guest_transmit_notify_mod,
                                    &guest_transmit_notify_data, gst,
                                    pmeth->flags);
  }
  else
  {
    GNUNET_PSYC_slave_transmit_resume (gst->tmit_handle);
  }
  return GNUNET_OK;
}


/**
 * Transmit a message to PSYC.
 */
static int
psyc_transmit_message (struct Place *plc)
{
  return
    (plc->is_host)
    ? psyc_master_transmit_message ((struct Host *) plc)
    : psyc_slave_transmit_message ((struct Guest *) plc);
}


/**
 * Queue message parts for sending to PSYC.
 *
 * @param plc          Place to send to.
 * @param client       Client the message originates from.
 * @param data_size    Size of @a data.
 * @param data         Concatenated message parts.
 * @param first_ptype  First message part type in @a data.
 * @param last_ptype   Last message part type in @a data.
 */
static struct MessageTransmitQueue *
psyc_transmit_queue_message (struct Place *plc,
                             struct GNUNET_SERVER_Client *client,
                             size_t data_size,
                             const void *data,
                             uint16_t first_ptype, uint16_t last_ptype,
                             struct MessageTransmitQueue *tmit_msg)
{
  if (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_METHOD == first_ptype)
  {
    tmit_msg = GNUNET_malloc (sizeof (*tmit_msg));
    GNUNET_CONTAINER_DLL_insert_tail (plc->tmit_msgs_head, plc->tmit_msgs_tail, tmit_msg);
  }
  else if (NULL == tmit_msg)
  {
    return NULL;
  }

  struct FragmentTransmitQueue *
    tmit_frag = GNUNET_malloc (sizeof (*tmit_frag) + data_size);
  memcpy (&tmit_frag[1], data, data_size);
  tmit_frag->next_part = (struct GNUNET_MessageHeader *) &tmit_frag[1];
  tmit_frag->client = client;
  tmit_frag->size = data_size;

  GNUNET_CONTAINER_DLL_insert_tail (tmit_msg->frags_head, tmit_msg->frags_tail, tmit_frag);
  tmit_msg->client = client;
  return tmit_msg;
}


/**
 * Cancel transmission of current message to PSYC.
 *
 * @param plc	  Place to send to.
 * @param client  Client the message originates from.
 */
static void
psyc_transmit_cancel (struct Place *plc, struct GNUNET_SERVER_Client *client)
{
  uint16_t type = GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_CANCEL;

  struct GNUNET_MessageHeader msg;
  msg.size = htons (sizeof (msg));
  msg.type = htons (type);

  psyc_transmit_queue_message (plc, client, sizeof (msg), &msg, type, type, NULL);
  psyc_transmit_message (plc);

  /* FIXME: cleanup */
}


/**
 * Handle an incoming message from a client, to be transmitted to the place.
 */
static void
client_recv_psyc_message (void *cls, struct GNUNET_SERVER_Client *client,
                          const struct GNUNET_MessageHeader *msg)
{
  struct Client *
    ctx = GNUNET_SERVER_client_get_user_context (client, struct Client);
  GNUNET_assert (NULL != ctx);
  struct Place *plc = ctx->plc;
  int ret = GNUNET_SYSERR;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Received message from client.\n", plc);
  GNUNET_PSYC_log_message (GNUNET_ERROR_TYPE_DEBUG, msg);

  if (GNUNET_YES != plc->is_ready)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "%p Place is not ready yet, disconnecting client.\n", plc);
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  uint16_t size = ntohs (msg->size);
  uint16_t psize = size - sizeof (*msg);
  if (psize < sizeof (struct GNUNET_MessageHeader)
      || GNUNET_MULTICAST_FRAGMENT_MAX_PAYLOAD < psize)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%p Received message with invalid payload size (%u) from client.\n",
                plc, psize);
    GNUNET_break (0);
    psyc_transmit_cancel (plc, client);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  uint16_t first_ptype = 0, last_ptype = 0;
  if (GNUNET_SYSERR
      == GNUNET_PSYC_receive_check_parts (psize, (const char *) &msg[1],
                                          &first_ptype, &last_ptype))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%p Received invalid message part from client.\n", plc);
    GNUNET_break (0);
    psyc_transmit_cancel (plc, client);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Received message with first part type %u and last part type %u.\n",
              plc, first_ptype, last_ptype);

  ctx->tmit_msg
    = psyc_transmit_queue_message (plc, client, psize, &msg[1],
                                   first_ptype, last_ptype, ctx->tmit_msg);
  if (NULL != ctx->tmit_msg)
  {
    if (GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_END <= last_ptype)
      ctx->tmit_msg = NULL;
    ret = psyc_transmit_message (plc);
  }

  if (GNUNET_OK != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%p Received invalid message part from client.\n", plc);
    GNUNET_break (0);
    psyc_transmit_cancel (plc, client);
    ret = GNUNET_SYSERR;
  }
  GNUNET_SERVER_receive_done (client, ret);
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
    { &client_recv_host_enter, NULL,
      GNUNET_MESSAGE_TYPE_SOCIAL_HOST_ENTER, 0 },

    { &client_recv_guest_enter, NULL,
      GNUNET_MESSAGE_TYPE_SOCIAL_GUEST_ENTER, 0 },

    { &client_recv_join_decision, NULL,
      GNUNET_MESSAGE_TYPE_PSYC_JOIN_DECISION, 0 },

    { &client_recv_psyc_message, NULL,
      GNUNET_MESSAGE_TYPE_PSYC_MESSAGE, 0 }
  };

  cfg = c;
  stats = GNUNET_STATISTICS_create ("social", cfg);
  hosts = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);
  guests = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);
  place_guests = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);
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
          GNUNET_SERVICE_run (argc, argv, "social",
			      GNUNET_SERVICE_OPTION_NONE,
                              &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-social.c */
