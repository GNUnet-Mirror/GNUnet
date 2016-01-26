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
 * @file social/gnunet-service-social.c
 * @brief Social service
 * @author Gabor X Toth
 */

#include <inttypes.h>
#include <strings.h>

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_core_service.h"
#include "gnunet_identity_service.h"
#include "gnunet_namestore_service.h"
#include "gnunet_gns_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet_psyc_service.h"
#include "gnunet_psyc_util_lib.h"
#include "gnunet_social_service.h"
#include "social.h"


/**
 * Handle to our current configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/* Handles to other services */
static struct GNUNET_CORE_Handle *core;
static struct GNUNET_IDENTITY_Handle *id;
static struct GNUNET_GNS_Handle *gns;
static struct GNUNET_NAMESTORE_Handle *namestore;
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * ID of this peer.
 */
static struct GNUNET_PeerIdentity this_peer;

/**
 * Notification context, simplifies client broadcasts.
 */
static struct GNUNET_SERVER_NotificationContext *nc;

/**
 * All connected hosts.
 * H(place_pub_key) -> struct Host
 */
static struct GNUNET_CONTAINER_MultiHashMap *hosts;

/**
 * All connected guests.
 * H(place_pub_key) -> struct Guest
 */
static struct GNUNET_CONTAINER_MultiHashMap *guests;

/**
 * Connected guests per place.
 * H(place_pub_key) -> ego_pub_key -> struct Guest
 */
static struct GNUNET_CONTAINER_MultiHashMap *place_guests;

/**
 * Places entered as host or guest.
 * H(place_pub_key) -> struct HostEnterRequest OR struct GuestEnterRequest
 */
static struct GNUNET_CONTAINER_MultiHashMap *places;

/**
 * Places entered per application.
 * H(app_id) -> H(place_pub_key) -> NULL
 */
static struct GNUNET_CONTAINER_MultiHashMap *apps_places;

/**
 * Application subscriptions per place.
 * H(place_pub_key) -> H(app_id)
 */
static struct GNUNET_CONTAINER_MultiHashMap *places_apps;

/**
 * Connected applications.
 * H(app_id) -> struct Application
 */
static struct GNUNET_CONTAINER_MultiHashMap *apps;

/**
 * All egos.
 * H(ego_pub_key) -> struct Ego
 */
static struct GNUNET_CONTAINER_MultiHashMap *egos;

/**
 * Directory for storing social data.
 * Default: $GNUNET_DATA_HOME/social
 */
static char *dir_social;

/**
 * Directory for storing place data.
 * $dir_social/places
 */
static char *dir_places;

/**
 * Directory for storing app data.
 * $dir_social/apps
 */
static char *dir_apps;


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

  struct GNUNET_PSYC_Channel *channel;

  /**
   * Private key of home in case of a host.
   */
  struct GNUNET_CRYPTO_EddsaPublicKey key;

  /**
   * Public key of place.
   */
  struct GNUNET_CRYPTO_EddsaPublicKey pub_key;

  /**
   * Hash of @a pub_key.
   */
  struct GNUNET_HashCode pub_key_hash;

  /**
   * Private key of ego.
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey ego_key;

  /**
   * Public key of ego.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey ego_pub_key;

  /**
   * Hash of @a ego_pub_key.
   */
  struct GNUNET_HashCode ego_pub_hash;

  /**
   * Slicer for processing incoming messages.
   */
  struct GNUNET_PSYC_Slicer *slicer;

  /**
   * Last message ID received for the place.
   * 0 if there is no such message.
   */
  uint64_t max_message_id;

  /**
   * Offset where the file is currently being written.
   */
  uint64_t file_offset;

  /**
   * Whether or not to save the file (#GNUNET_YES or #GNUNET_NO)
   */
  uint8_t file_save;

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

  /**
   * Join flags for the PSYC service.
   */
  enum GNUNET_PSYC_SlaveJoinFlags join_flags;
};


/**
 * Context for a client.
 */
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

  /**
   * ID for application clients.
   */
  char *app_id;
};


struct Application
{
  struct ClientListItem *clients_head;
  struct ClientListItem *clients_tail;
};


struct Ego {
  struct GNUNET_CRYPTO_EcdsaPrivateKey key;
  char *name;
};


struct OperationClosure
{
  struct GNUNET_SERVER_Client *client;
  struct Place *plc;
  uint64_t op_id;
  uint32_t flags;
};


static int
psyc_transmit_message (struct Place *plc);


static void
cleanup_place (struct Place *plc);


int
place_entry_cleanup (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  cleanup_place (value);
  return GNUNET_YES;
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_CONTAINER_multihashmap_iterate (hosts, place_entry_cleanup, NULL);
  GNUNET_CONTAINER_multihashmap_iterate (guests, place_entry_cleanup, NULL);

  if (NULL != nc)
  {
    GNUNET_SERVER_notification_context_destroy (nc);
    nc = NULL;
  }
  if (NULL != core)
  {
    GNUNET_CORE_disconnect (core);
    core = NULL;
  }
  if (NULL != id)
  {
    GNUNET_IDENTITY_disconnect (id);
    id = NULL;
  }
  if (NULL != namestore)
  {
    GNUNET_NAMESTORE_disconnect (namestore);
    namestore = NULL;
  }
  if (NULL != gns)
  {
    GNUNET_GNS_disconnect (gns);
    gns = NULL;
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
  GNUNET_assert (NULL != plc_gst); // FIXME
  GNUNET_CONTAINER_multihashmap_remove (plc_gst, &plc->ego_pub_hash, gst);

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

  GNUNET_PSYC_slicer_destroy (plc->slicer);
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
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%p User context is NULL in client_disconnect()\n", ctx);
    return;
  }

  struct Place *plc = ctx->plc;

  if (NULL != ctx->app_id)
    GNUNET_free (ctx->app_id);

  GNUNET_free (ctx);

  if (NULL == plc)
    return; // application client, nothing to do

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
}


/**
 * Send message to a client.
 */
static inline void
client_send_msg (struct GNUNET_SERVER_Client *client,
                 const struct GNUNET_MessageHeader *msg)
{
  GNUNET_SERVER_notification_context_add (nc, client);
  GNUNET_SERVER_notification_context_unicast (nc, client, msg, GNUNET_NO);
}


/**
 * Send message to all clients connected to a place.
 */
static void
place_send_msg (const struct Place *plc,
                 const struct GNUNET_MessageHeader *msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Sending message to clients of place.\n", plc);

  struct ClientListItem *cli = plc->clients_head;
  while (NULL != cli)
  {
    client_send_msg (cli->client, msg);
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
client_send_result (struct GNUNET_SERVER_Client *client, uint64_t op_id,
                    int64_t result_code, const void *data, uint16_t data_size)
{
  struct GNUNET_OperationResultMessage *res;

  res = GNUNET_malloc (sizeof (*res) + data_size);
  res->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_RESULT_CODE);
  res->header.size = htons (sizeof (*res) + data_size);
  res->result_code = GNUNET_htonll (result_code);
  res->op_id = op_id;
  if (0 < data_size)
    memcpy (&res[1], data, data_size);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "%p Sending result to client for operation #%" PRIu64 ": "
              "%" PRId64 " (size: %u)\n",
	      client, GNUNET_ntohll (op_id), result_code, data_size);

  client_send_msg (client, &res->header);
  GNUNET_free (res);
}


static void
client_send_host_enter_ack (struct GNUNET_SERVER_Client *client,
                            struct Host *hst, uint32_t result)
{
  struct Place *plc = &hst->plc;

  struct HostEnterAck hack;
  hack.header.type = htons (GNUNET_MESSAGE_TYPE_SOCIAL_HOST_ENTER_ACK);
  hack.header.size = htons (sizeof (hack));
  hack.result_code = htonl (result);
  hack.max_message_id = GNUNET_htonll (plc->max_message_id);
  hack.place_pub_key = plc->pub_key;

  if (NULL != client)
    client_send_msg (client, &hack.header);
  else
    place_send_msg (plc, &hack.header);
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

  client_send_host_enter_ack (NULL, hst, result);
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
  place_send_msg (&hst->plc, &req->header);
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
  res.result_code = htonl (result);
  res.max_message_id = GNUNET_htonll (plc->max_message_id);

  place_send_msg (plc, &res.header);
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
  place_send_msg (&gst->plc, &dcsn->header);
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

  char *str = GNUNET_CRYPTO_ecdsa_public_key_to_string (&msg->slave_pub_key);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Received PSYC message of size %u from %s.\n",
              plc, ntohs (msg->header.size), str);
  GNUNET_free (str);

  GNUNET_PSYC_slicer_message (plc->slicer, msg);

  place_send_msg (plc, &msg->header);
}


static void
place_recv_relay_method (void *cls,
                         const struct GNUNET_PSYC_MessageMethod *meth,
                         uint64_t message_id,
                         uint32_t flags,
                         uint64_t fragment_offset,
                         uint32_t tmit_flags,
                         const struct GNUNET_CRYPTO_EcdsaPublicKey *nym_pub_key,
                         const char *method_name)
{
  struct Host *hst = cls;
  struct Place *plc = &hst->plc;


}


static void
place_recv_relay_modifier (void *cls,
                           const struct GNUNET_MessageHeader *msg,
                           uint64_t message_id,
                           uint32_t flags,
                           uint64_t fragment_offset,
                           enum GNUNET_PSYC_Operator oper,
                           const char *name,
                           const void *value,
                           uint16_t value_size,
                           uint16_t full_value_size)
{

}


static void
place_recv_relay_eom (void *cls,
                      const struct GNUNET_MessageHeader *msg,
                      uint64_t message_id,
                      uint32_t flags,
                      uint64_t fragment_offset,
                      uint8_t cancelled)
{

}


static void
place_recv_relay_data (void *cls,
                       const struct GNUNET_MessageHeader *msg,
                       uint64_t message_id,
                       uint32_t flags,
                       uint64_t fragment_offset,
                       const void *data,
                       uint16_t data_size)
{

}


static void
place_recv_save_method (void *cls,
                        const struct GNUNET_PSYC_MessageMethod *meth,
                        uint64_t message_id,
                        uint32_t flags,
                        uint64_t fragment_offset,
                        uint32_t tmit_flags,
                        const struct GNUNET_CRYPTO_EcdsaPublicKey *nym_pub_key,
                        const char *method_name)
{
  struct Place *plc = cls;
  plc->file_offset = 0;
  plc->file_save = GNUNET_NO;

  struct GNUNET_CRYPTO_HashAsciiEncoded place_pub_hash_ascii;
  memcpy (&place_pub_hash_ascii.encoding,
          GNUNET_h2s_full (&plc->pub_key_hash), sizeof (place_pub_hash_ascii));

  char *filename = NULL;
  GNUNET_asprintf (&filename, "%s%c%s%c%s%c%.part" PRIu64,
                   dir_social, DIR_SEPARATOR,
                   "files", DIR_SEPARATOR,
                   place_pub_hash_ascii.encoding, DIR_SEPARATOR,
                   message_id);

  /* save if does not already exist */
  if (GNUNET_NO == GNUNET_DISK_file_test (filename))
  {
    plc->file_save = GNUNET_YES;
  }

  GNUNET_free (filename);
}


static void
place_recv_save_data (void *cls,
                      const struct GNUNET_MessageHeader *msg,
                      uint64_t message_id,
                      uint32_t flags,
                      uint64_t fragment_offset,
                      const void *data,
                      uint16_t data_size)
{
  struct Place *plc = cls;
  if (GNUNET_YES != plc->file_save)
    return;

  struct GNUNET_CRYPTO_HashAsciiEncoded place_pub_hash_ascii;
  memcpy (&place_pub_hash_ascii.encoding,
          GNUNET_h2s_full (&plc->pub_key_hash), sizeof (place_pub_hash_ascii));

  char *filename = NULL;
  GNUNET_asprintf (&filename, "%s%c%s%c%s%c%.part" PRIu64,
                   dir_social, DIR_SEPARATOR,
                   "files", DIR_SEPARATOR,
                   place_pub_hash_ascii.encoding, DIR_SEPARATOR,
                   message_id);
  GNUNET_DISK_directory_create_for_file (filename);
  struct GNUNET_DISK_FileHandle *
    fh = GNUNET_DISK_file_open (filename, GNUNET_DISK_OPEN_WRITE,
                                GNUNET_DISK_PERM_USER_READ
                                | GNUNET_DISK_PERM_USER_WRITE);
  GNUNET_free (filename);

  GNUNET_DISK_file_seek (fh, plc->file_offset, GNUNET_DISK_SEEK_SET);
  GNUNET_DISK_file_write (fh, data, data_size);
  GNUNET_DISK_file_close (fh);
  plc->file_offset += data_size;
}


static void
place_recv_save_eom (void *cls,
                     const struct GNUNET_MessageHeader *msg,
                     uint64_t message_id,
                     uint32_t flags,
                     uint64_t fragment_offset,
                     uint8_t cancelled)
{
  struct Place *plc = cls;
  if (GNUNET_YES != plc->file_save)
    return;

  struct GNUNET_CRYPTO_HashAsciiEncoded place_pub_hash_ascii;
  memcpy (&place_pub_hash_ascii.encoding,
          GNUNET_h2s_full (&plc->pub_key_hash), sizeof (place_pub_hash_ascii));

  char *fn_part = NULL;
  GNUNET_asprintf (&fn_part, "%s%c%s%c%s%c%.part" PRIu64,
                   dir_social, DIR_SEPARATOR,
                   "files", DIR_SEPARATOR,
                   place_pub_hash_ascii.encoding, DIR_SEPARATOR,
                   message_id);

  char *fn = NULL;
  GNUNET_asprintf (&fn, "%s%c%s%c%s%c%" PRIu64,
                   dir_social, DIR_SEPARATOR,
                   "files", DIR_SEPARATOR,
                   place_pub_hash_ascii.encoding, DIR_SEPARATOR,
                   message_id);

  rename (fn_part, fn);

  GNUNET_free (fn);
  GNUNET_free (fn_part);
}


/**
 * Initialize place data structure.
 */
static void
place_init (struct Place *plc)
{

}

/**
 * Add a place to the @e places hash map.
 *
 * @param ereq
 *        Entry request.
 *
 * @return #GNUNET_OK if the place was added
 *         #GNUNET_NO if the place already exists in the hash map
 *         #GNUNET_SYSERR on error
 */
static int
place_add (const struct PlaceEnterRequest *ereq)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Adding place to hashmap:\n");

  struct EgoPlacePublicKey ego_place_pub_key = {
    .ego_pub_key = ereq->ego_pub_key,
    .place_pub_key = ereq->place_pub_key,
  };
  struct GNUNET_HashCode ego_place_pub_hash;
  GNUNET_CRYPTO_hash (&ego_place_pub_key, sizeof (ego_place_pub_key), &ego_place_pub_hash);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "  ego_place_pub_hash = %s\n", GNUNET_h2s (&ego_place_pub_hash));

  struct GNUNET_MessageHeader *
    place_msg = GNUNET_CONTAINER_multihashmap_get (places, &ego_place_pub_hash);
  if (NULL != place_msg)
    return GNUNET_NO;

  place_msg = GNUNET_copy_message (&ereq->header);
  if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (places, &ego_place_pub_hash, place_msg,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
  {
    GNUNET_break (0);
    GNUNET_free (place_msg);
    return GNUNET_SYSERR;
  }

  return GNUNET_OK;
}

/**
 * Add a place to the @e app_places hash map.
 *
 * @param app_id
 *        Application ID.
 * @param msg
 *        Entry message.
 *
 * @return #GNUNET_OK if the place was added
 *         #GNUNET_NO if the place already exists in the hash map
 *         #GNUNET_SYSERR on error
 */
static int
app_place_add (const char *app_id,
               const struct PlaceEnterRequest *ereq)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Adding app place to hashmap:\n");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "  app_id = %s\n", app_id);

  struct GNUNET_HashCode app_id_hash;
  GNUNET_CRYPTO_hash (app_id, strlen (app_id) + 1, &app_id_hash);

  struct EgoPlacePublicKey ego_place_pub_key = {
    .ego_pub_key = ereq->ego_pub_key,
    .place_pub_key = ereq->place_pub_key,
  };
  struct GNUNET_HashCode ego_place_pub_hash;
  GNUNET_CRYPTO_hash (&ego_place_pub_key, sizeof (ego_place_pub_key), &ego_place_pub_hash);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "  ego_place_pub_hash = %s\n", GNUNET_h2s (&ego_place_pub_hash));

  struct GNUNET_CONTAINER_MultiHashMap *
    app_places = GNUNET_CONTAINER_multihashmap_get (apps_places, &app_id_hash);
  if (NULL == app_places)
  {
    app_places = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);
    GNUNET_CONTAINER_multihashmap_put (apps_places, &app_id_hash, app_places,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  }

  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (app_places, &ego_place_pub_hash))
    return GNUNET_NO;

  if (GNUNET_SYSERR == place_add (ereq))
    return GNUNET_SYSERR;

  if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (app_places, &ego_place_pub_hash, NULL,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  struct GNUNET_HashCode place_pub_hash;
  GNUNET_CRYPTO_hash (&ereq->place_pub_key, sizeof (ereq->place_pub_key), &place_pub_hash);

  struct GNUNET_CONTAINER_MultiHashMap *
    place_apps = GNUNET_CONTAINER_multihashmap_get (places_apps, &place_pub_hash);
  if (NULL == place_apps)
  {
    place_apps = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);
    if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (places_apps, &place_pub_hash, place_apps,
                                                        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
    {
      GNUNET_break (0);
    }
  }


  size_t app_id_size = strlen (app_id);
  void *app_id_value = GNUNET_malloc (app_id_size);
  memcpy (app_id_value, app_id, app_id_size);

  if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (place_apps, &app_id_hash, app_id_value,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
  {
    GNUNET_break (0);
  }

  return GNUNET_OK;
}


/**
 * Save place entry message to disk.
 *
 * @param app_id
 *        Application ID.
 * @param msg
 *        Entry message.
 */
static int
app_place_save (const char *app_id,
                const struct PlaceEnterRequest *ereq)
{
  app_place_add (app_id, ereq);

  if (NULL == dir_places)
    return GNUNET_SYSERR;

  struct GNUNET_HashCode ego_pub_hash;
  struct GNUNET_HashCode place_pub_hash;
  GNUNET_CRYPTO_hash (&ereq->ego_pub_key, sizeof (ereq->ego_pub_key),
                      &ego_pub_hash);
  GNUNET_CRYPTO_hash (&ereq->place_pub_key, sizeof (ereq->place_pub_key),
                      &place_pub_hash);

  struct GNUNET_CRYPTO_HashAsciiEncoded ego_pub_hash_ascii;
  struct GNUNET_CRYPTO_HashAsciiEncoded place_pub_hash_ascii;
  memcpy (&ego_pub_hash_ascii.encoding,
          GNUNET_h2s_full (&ego_pub_hash), sizeof (ego_pub_hash_ascii));
  memcpy (&place_pub_hash_ascii.encoding,
          GNUNET_h2s_full (&place_pub_hash), sizeof (place_pub_hash_ascii));

  char *filename = NULL;
  GNUNET_asprintf (&filename, "%s%c" "%s%c" "%s%c" "%s",
                   dir_social, DIR_SEPARATOR,
                   "places", DIR_SEPARATOR,
                   ego_pub_hash_ascii.encoding, DIR_SEPARATOR,
                   place_pub_hash_ascii.encoding);
  int ret = GNUNET_DISK_directory_create_for_file (filename);
  if (GNUNET_OK != ret
      || 0 > GNUNET_DISK_fn_write (filename, ereq, ntohs (ereq->header.size),
                                   GNUNET_DISK_PERM_USER_READ
                                   | GNUNET_DISK_PERM_USER_WRITE))
  {
    GNUNET_break (0);
    ret = GNUNET_SYSERR;
  }
  GNUNET_free (filename);

  if (ret == GNUNET_OK)
  {
    GNUNET_asprintf (&filename, "%s%c" "%s%c" "%s%c" "%s%c" "%s",
                     dir_social, DIR_SEPARATOR,
                     "apps", DIR_SEPARATOR,
                     app_id, DIR_SEPARATOR,
                     ego_pub_hash_ascii.encoding, DIR_SEPARATOR,
                     place_pub_hash_ascii.encoding);
    ret = GNUNET_DISK_directory_create_for_file (filename);
    if (GNUNET_OK != ret
        || 0 > GNUNET_DISK_fn_write (filename, "", 0,
                                     GNUNET_DISK_PERM_USER_READ
                                     | GNUNET_DISK_PERM_USER_WRITE))
    {
      GNUNET_break (0);
      ret = GNUNET_SYSERR;
    }
    GNUNET_free (filename);
  }
  return ret;
}


int
app_place_remove (const char *app_id,
                  const struct GNUNET_CRYPTO_EddsaPublicKey *place_pub_key)
{
  struct GNUNET_HashCode place_pub_hash;
  GNUNET_CRYPTO_hash (place_pub_key, sizeof (*place_pub_key), &place_pub_hash);

  struct GNUNET_CRYPTO_HashAsciiEncoded place_pub_hash_ascii;
  memcpy (&place_pub_hash_ascii.encoding,
          GNUNET_h2s_full (&place_pub_hash), sizeof (place_pub_hash_ascii));

  char *app_place_filename = NULL;
  GNUNET_asprintf (&app_place_filename,
                   "%s%c" "%s%/",
                   dir_social, DIR_SEPARATOR,
                   "apps", DIR_SEPARATOR,
                   app_id, DIR_SEPARATOR,
                   place_pub_hash_ascii.encoding);

  struct GNUNET_HashCode app_id_hash;
  GNUNET_CRYPTO_hash (app_id, strlen (app_id) + 1, &app_id_hash);

  struct GNUNET_CONTAINER_MultiHashMap *
    app_places = GNUNET_CONTAINER_multihashmap_get (apps_places, &app_id_hash);

  if (NULL != app_places)
    GNUNET_CONTAINER_multihashmap_remove (app_places, &place_pub_hash, NULL);

  struct GNUNET_CONTAINER_MultiHashMap *
    place_apps = GNUNET_CONTAINER_multihashmap_get (places_apps, &place_pub_hash);
  if (NULL != place_apps)
  {
    void *app_id_value = GNUNET_CONTAINER_multihashmap_get (place_apps, &app_id_hash);
    if (NULL != app_id_value)
    {
      GNUNET_free (app_id_value);
      GNUNET_CONTAINER_multihashmap_remove_all (place_apps, &app_id_hash);
    }
  }


  int ret = unlink (app_place_filename);
  GNUNET_free (app_place_filename);
  if (0 != ret)
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Error removing app place: unlink returned %d\n", errno);
    return GNUNET_SYSERR;
  }

  return GNUNET_OK;
}


/**
 * Enter place as host.
 *
 * @param req
 *        Entry request.
 * @param[out] ret_hst
 *        Returned Host struct.
 *
 * @return #GNUNET_YES if the host entered the place just now,
 *         #GNUNET_NO  if the place is already entered,
 *         #GNUNET_SYSERR if place_pub_key was set
 *                        but its private key was not found
 */
static int
host_enter (const struct HostEnterRequest *hreq, struct Host **ret_hst)
{
  int ret = GNUNET_NO;
  struct GNUNET_HashCode place_pub_hash;
  GNUNET_CRYPTO_hash (&hreq->place_pub_key, sizeof (hreq->place_pub_key),
                      &place_pub_hash);
  struct Host *hst = GNUNET_CONTAINER_multihashmap_get (hosts, &place_pub_hash);

  if (NULL == hst)
  {
    hst = GNUNET_new (struct Host);
    hst->policy = hreq->policy;
    hst->join_reqs = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);

    struct Place *plc = &hst->plc;
    place_init (plc);
    plc->is_host = GNUNET_YES;
    plc->pub_key = hreq->place_pub_key;
    plc->pub_key_hash = place_pub_hash;
    plc->slicer = GNUNET_PSYC_slicer_create ();

    GNUNET_CONTAINER_multihashmap_put (hosts, &plc->pub_key_hash, plc,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
    hst->master = GNUNET_PSYC_master_start (cfg, &hreq->place_key, hst->policy,
                                            &psyc_master_started,
                                            &psyc_recv_join_request,
                                            &psyc_recv_message, NULL, hst);
    plc->channel = GNUNET_PSYC_master_get_channel (hst->master);
    ret = GNUNET_YES;
  }

  if (NULL != ret_hst)
    *ret_hst = hst;
  return ret;
}


const struct MsgProcRequest *
msg_proc_parse (const struct GNUNET_MessageHeader *msg,
                uint32_t *flags,
                const char **method_prefix,
                struct GNUNET_HashCode *method_hash)
{
  const struct MsgProcRequest *mpreq = (const struct MsgProcRequest *) msg;
  uint8_t method_size = ntohs (mpreq->header.size) - sizeof (*mpreq);
  uint16_t offset = GNUNET_STRINGS_buffer_tokenize ((const char *) &mpreq[1],
                                                    method_size, 1, method_prefix);

  if (0 == offset || offset != method_size || *method_prefix == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "offset = %u, method_size = %u, method_name = %s\n",
                offset, method_size, *method_prefix);
    return NULL;
  }

  GNUNET_CRYPTO_hash (*method_prefix, method_size, method_hash);
  *flags = ntohl (mpreq->flags);
  return mpreq;
}


/**
 * Handle a client setting message proccesing flags for a method prefix.
 */
static void
client_recv_msg_proc_set (void *cls, struct GNUNET_SERVER_Client *client,
                          const struct GNUNET_MessageHeader *msg)
{
  struct Client *
    ctx = GNUNET_SERVER_client_get_user_context (client, struct Client);
  GNUNET_assert (NULL != ctx);
  struct Place *plc = ctx->plc;

  const char *method_prefix = NULL;
  uint32_t flags = 0;
  struct GNUNET_HashCode method_hash;
  const struct MsgProcRequest *
    mpreq = msg_proc_parse (msg, &flags, &method_prefix, &method_hash);

  if (NULL == mpreq) {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  GNUNET_PSYC_slicer_method_remove (plc->slicer, method_prefix,
                                    place_recv_relay_method,
                                    place_recv_relay_modifier,
                                    place_recv_relay_data,
                                    place_recv_relay_eom);
  GNUNET_PSYC_slicer_method_remove (plc->slicer, method_prefix,
                                    place_recv_save_method,
                                    NULL,
                                    place_recv_save_data,
                                    place_recv_save_eom);

  if (flags & GNUNET_SOCIAL_MSG_PROC_RELAY)
  {
    GNUNET_PSYC_slicer_method_add (plc->slicer, method_prefix,
                                   place_recv_relay_method,
                                   place_recv_relay_modifier,
                                   place_recv_relay_data,
                                   place_recv_relay_eom,
                                   plc);
  }
  if (flags & GNUNET_SOCIAL_MSG_PROC_SAVE)
  {
    GNUNET_PSYC_slicer_method_add (plc->slicer, method_prefix,
                                   place_recv_save_method,
                                   NULL,
                                   place_recv_save_data,
                                   place_recv_save_eom,
                                   plc);
  }

  /** @todo Save flags to be able to resume relaying/saving after restart */

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handle a connecting client requesting to clear all relay rules.
 */
static void
client_recv_msg_proc_clear (void *cls, struct GNUNET_SERVER_Client *client,
                            const struct GNUNET_MessageHeader *msg)
{
  struct Client *
    ctx = GNUNET_SERVER_client_get_user_context (client, struct Client);
  GNUNET_assert (NULL != ctx);
  struct Place *plc = ctx->plc;
  if (GNUNET_YES != plc->is_host) {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  struct Host *hst = (struct Host *) plc;

  GNUNET_PSYC_slicer_clear (plc->slicer);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handle a connecting client entering a place as host.
 */
static void
client_recv_host_enter (void *cls, struct GNUNET_SERVER_Client *client,
                        const struct GNUNET_MessageHeader *msg)
{
  struct HostEnterRequest *hreq
    = (struct HostEnterRequest *) GNUNET_copy_message (msg);

  uint8_t app_id_size = ntohs (hreq->header.size) - sizeof (*hreq);
  const char *app_id = NULL;
  uint16_t offset = GNUNET_STRINGS_buffer_tokenize ((const char *) &hreq[1],
                                                    app_id_size, 1, &app_id);
  if (0 == offset || offset != app_id_size || app_id == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "offset = %u, app_id_size = %u, app_id = %s\n",
                offset, app_id_size, app_id);
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  struct Host *hst = NULL;
  struct Place *plc = NULL;
  int ret = GNUNET_OK;

  struct GNUNET_CRYPTO_EddsaPublicKey empty_pub_key;
  memset (&empty_pub_key, 0, sizeof (empty_pub_key));

  if (0 == memcmp (&hreq->place_pub_key, &empty_pub_key, sizeof (empty_pub_key)))
  { // no public key set: create new private key & save the place
    struct GNUNET_CRYPTO_EddsaPrivateKey *
      place_key = GNUNET_CRYPTO_eddsa_key_create ();
    hreq->place_key = *place_key;
    GNUNET_CRYPTO_eddsa_key_get_public (place_key, &hreq->place_pub_key);
    GNUNET_CRYPTO_eddsa_key_clear (place_key);
    GNUNET_free (place_key);

    app_place_save (app_id, (const struct PlaceEnterRequest *) hreq);
  }

  switch (host_enter (hreq, &hst))
  {
  case GNUNET_YES:
    plc = &hst->plc;
    break;

  case GNUNET_NO:
  {
    plc = &hst->plc;
    client_send_host_enter_ack (client, hst, GNUNET_OK);
    break;
  }
  case GNUNET_SYSERR:
    ret = GNUNET_SYSERR;
  }

  if (ret != GNUNET_SYSERR)
  {

    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "%p Client connected as host to place %s.\n",
                hst, GNUNET_h2s (&plc->pub_key_hash));

    struct ClientListItem *cli = GNUNET_new (struct ClientListItem);
    cli->client = client;
    GNUNET_CONTAINER_DLL_insert (plc->clients_head, plc->clients_tail, cli);

    struct Client *ctx = GNUNET_new (struct Client);
    ctx->plc = plc;
    GNUNET_SERVER_client_set_user_context (client, ctx);
  }

  GNUNET_CRYPTO_eddsa_key_clear (&hreq->place_key);
  GNUNET_free (hreq);
  GNUNET_SERVER_receive_done (client, ret);
}


/**
 * Enter place as guest.
 *
 * @param req
 *        Entry request.
 * @param[out] ret_gst
 *        Returned Guest struct.
 *
 * @return #GNUNET_YES if the guest entered the place just now,
 *         #GNUNET_NO  if the place is already entered,
 *         #GNUNET_SYSERR on error.
 */
static int
guest_enter (const struct GuestEnterRequest *greq, struct Guest **ret_gst)
{
  int ret = GNUNET_NO;
  uint16_t greq_size = ntohs (greq->header.size);

  struct GNUNET_CRYPTO_EcdsaPublicKey ego_pub_key = greq->ego_pub_key;
  struct GNUNET_HashCode ego_pub_hash;
  GNUNET_CRYPTO_hash (&ego_pub_key, sizeof (ego_pub_key), &ego_pub_hash);
  struct Ego *ego = GNUNET_CONTAINER_multihashmap_get (egos, &ego_pub_hash);

  if (NULL == ego)
    return GNUNET_SYSERR;

  struct GNUNET_HashCode place_pub_hash;
  GNUNET_CRYPTO_hash (&greq->place_pub_key, sizeof (greq->place_pub_key),
                      &place_pub_hash);

  struct GNUNET_CONTAINER_MultiHashMap *
    plc_gst = GNUNET_CONTAINER_multihashmap_get (place_guests, &place_pub_hash);
  struct Guest *gst = NULL;

  if (NULL != plc_gst)
    gst = GNUNET_CONTAINER_multihashmap_get (plc_gst, &ego_pub_hash);

  if (NULL == gst || NULL == gst->slave)
  {
    gst = GNUNET_new (struct Guest);
    gst->origin = greq->origin;
    gst->relay_count = ntohl (greq->relay_count);

    uint16_t len;
    uint16_t remaining = ntohs (greq->header.size) - sizeof (*greq);
    const char *app_id = (const char *) &greq[1];
    const char *p = app_id;

    len = strnlen (app_id, remaining);
    if (len == remaining)
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    p += len + 1;
    remaining -= len + 1;

    const struct GNUNET_PeerIdentity *relays = NULL;
    uint16_t relay_size = gst->relay_count * sizeof (*relays);
    if (remaining < relay_size)
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    if (0 < relay_size)
      relays = (const struct GNUNET_PeerIdentity *) p;
    p += relay_size;
    remaining -= relay_size;

    struct GNUNET_PSYC_Message *join_msg = NULL;
    uint16_t join_msg_size = 0;

    if (sizeof (struct GNUNET_MessageHeader) <= remaining)
    {
      join_msg = (struct GNUNET_PSYC_Message *) p;
      join_msg_size = ntohs (join_msg->header.size);
      p += join_msg_size;
      remaining -= join_msg_size;
    }
    if (0 != remaining)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "%u + %u + %u != %u\n",
                  sizeof (*greq), relay_size, join_msg_size, greq_size);
      GNUNET_break (0);
      GNUNET_free (gst);
      return GNUNET_SYSERR;
    }
    if (0 < relay_size)
    {
      gst->relays = GNUNET_malloc (relay_size);
      memcpy (gst->relays, relays, relay_size);
    }

    gst->join_flags = ntohl (greq->flags);

    struct Place *plc = &gst->plc;
    place_init (plc);
    plc->is_host = GNUNET_NO;
    plc->pub_key = greq->place_pub_key;
    plc->pub_key_hash = place_pub_hash;
    plc->ego_pub_key = ego_pub_key;
    plc->ego_pub_hash = ego_pub_hash;
    plc->ego_key = ego->key;
    plc->slicer = GNUNET_PSYC_slicer_create ();

    if (NULL == plc_gst)
    {
      plc_gst = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);
      (void) GNUNET_CONTAINER_multihashmap_put (place_guests, &plc->pub_key_hash, plc_gst,
                                                GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
    }
    (void) GNUNET_CONTAINER_multihashmap_put (plc_gst, &plc->ego_pub_hash, gst,
                                              GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
    (void) GNUNET_CONTAINER_multihashmap_put (guests, &plc->pub_key_hash, gst,
                                              GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
    gst->slave
      = GNUNET_PSYC_slave_join (cfg, &plc->pub_key, &plc->ego_key,
                                gst->join_flags, &gst->origin,
                                gst->relay_count, gst->relays,
                                &psyc_recv_message, NULL,
                                &psyc_slave_connected,
                                &psyc_recv_join_dcsn,
                                gst, join_msg);
    plc->channel = GNUNET_PSYC_slave_get_channel (gst->slave);
    ret = GNUNET_YES;
  }

  if (NULL != ret_gst)
    *ret_gst = gst;
  return ret;
}


/**
 * Handle a connecting client entering a place as guest.
 */
static void
client_recv_guest_enter (void *cls, struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *msg)
{
  const struct GuestEnterRequest *
    greq = (const struct GuestEnterRequest *) msg;

  uint16_t remaining = ntohs (greq->header.size) - sizeof (*greq);
  const char *app_id = NULL;
  uint16_t offset = GNUNET_STRINGS_buffer_tokenize ((const char *) &greq[1],
                                                    remaining, 1, &app_id);
  if (0 == offset)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  struct Guest *gst = NULL;
  struct Place *plc = NULL;

  switch (guest_enter (greq, &gst))
  {
  case GNUNET_YES:
    plc = &gst->plc;
    app_place_save (app_id, (const struct PlaceEnterRequest *) greq);
    break;

  case GNUNET_NO:
  {
    plc = &gst->plc;

    struct GNUNET_PSYC_CountersResultMessage res;
    res.header.type = htons (GNUNET_MESSAGE_TYPE_SOCIAL_GUEST_ENTER_ACK);
    res.header.size = htons (sizeof (res));
    res.result_code = htonl (GNUNET_OK);
    res.max_message_id = GNUNET_htonll (plc->max_message_id);

    client_send_msg (client, &res.header);
    if (NULL != gst->join_dcsn)
      client_send_msg (client, &gst->join_dcsn->header);

    break;
  }
  case GNUNET_SYSERR:
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
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


struct GuestEnterByNameClosure
{
  struct GNUNET_SERVER_Client *client;
  char *app_id;
  char *password;
  struct GNUNET_CRYPTO_EcdsaPublicKey ego_pub_key;
  struct GNUNET_MessageHeader *join_msg;
};


/**
 * Result of a GNS name lookup for entering a place.
 *
 * @see GNUNET_SOCIAL_guest_enter_by_name
 */
static void
gns_result_guest_enter (void *cls, uint32_t rd_count,
                        const struct GNUNET_GNSRECORD_Data *rd)
{
  struct GuestEnterByNameClosure *gcls = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "%p GNS result: %u records.\n", gcls->client, rd_count);

  const struct GNUNET_GNSRECORD_PlaceData *
    rec = (const struct GNUNET_GNSRECORD_PlaceData *) rd->data;

  if (0 == rd_count || rd->data_size < sizeof (*rec))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (gcls->client, GNUNET_SYSERR);
    return;
  }

  uint16_t relay_count = ntohl (rec->relay_count);
  struct GNUNET_PeerIdentity *relays = NULL;

  if (0 < relay_count)
  {
    if (rd->data_size == sizeof (*rec) + relay_count * sizeof (struct GNUNET_PeerIdentity))
    {
      relays = (struct GNUNET_PeerIdentity *) &rec[1];
    }
    else
    {
      relay_count = 0;
      GNUNET_break_op (0);
    }
  }

  uint16_t app_id_size = strlen (gcls->app_id) + 1;
  uint16_t relay_size = relay_count * sizeof (*relays);
  uint16_t join_msg_size = 0;
  if (NULL != gcls->join_msg)
    join_msg_size = ntohs (gcls->join_msg->size);
  uint16_t greq_size = sizeof (struct GuestEnterRequest)
    + app_id_size + relay_size + join_msg_size;
  struct GuestEnterRequest *greq = GNUNET_malloc (greq_size);
  greq->header.size = htons (greq_size);
  greq->header.type = htons (GNUNET_MESSAGE_TYPE_SOCIAL_GUEST_ENTER);
  greq->ego_pub_key = gcls->ego_pub_key;
  greq->place_pub_key = rec->place_pub_key;
  greq->origin = rec->origin;
  greq->relay_count = rec->relay_count;

  void *p = &greq[1];
  memcpy (p, gcls->app_id, app_id_size);
  p += app_id_size;
  memcpy (p, relays, relay_size);
  p += relay_size;
  memcpy (p, gcls->join_msg, join_msg_size);

  client_recv_guest_enter (NULL, gcls->client, &greq->header);

  GNUNET_free (gcls->app_id);
  if (NULL != gcls->password)
    GNUNET_free (gcls->password);
  if (NULL != gcls->join_msg)
    GNUNET_free (gcls->join_msg);
  GNUNET_free (gcls);
  GNUNET_free (greq);
}


/**
 * Handle a connecting client entering a place as guest using a GNS address.
 *
 * Look up GNS address and generate a GuestEnterRequest from that.
 */
static void
client_recv_guest_enter_by_name (void *cls, struct GNUNET_SERVER_Client *client,
                                 const struct GNUNET_MessageHeader *msg)
{
  const struct GuestEnterByNameRequest *
    greq = (const struct GuestEnterByNameRequest *) msg;

  struct GuestEnterByNameClosure *gcls = GNUNET_malloc (sizeof (*gcls));
  gcls->client = client;
  gcls->ego_pub_key = greq->ego_pub_key;

  const char *p = (const char *) &greq[1];
  const char *app_id = NULL, *password = NULL, *gns_name = NULL;
  uint16_t remaining = ntohs (greq->header.size) - sizeof (*greq);
  uint16_t offset = GNUNET_STRINGS_buffer_tokenize (p, remaining, 3,
                                                    &app_id,
                                                    &gns_name,
                                                    &password);
  p += offset;
  remaining -= offset;

  if (0 != offset && sizeof (*gcls->join_msg) <= remaining)
  {
    gcls->join_msg = GNUNET_copy_message ((struct GNUNET_MessageHeader *) p);
    remaining -= ntohs (gcls->join_msg->size);
  }

  if (0 == offset || 0 != remaining)
  {
    if (NULL != gcls->join_msg)
      GNUNET_free (gcls->join_msg);
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  uint16_t app_id_size = strlen (app_id) + 1;
  gcls->app_id = GNUNET_malloc (app_id_size);
  memcpy (gcls->app_id, app_id, app_id_size);

  uint16_t password_size = strlen (password);
  if (0 < password_size++)
  {
    gcls->password = GNUNET_malloc (password_size);
    memcpy (gcls->password, password, password_size);
  }

  GNUNET_GNS_lookup (gns, gns_name, &greq->ego_pub_key,
                     GNUNET_GNSRECORD_TYPE_PLACE, GNUNET_GNS_LO_DEFAULT,
                     NULL, gns_result_guest_enter, gcls);
}


void
app_notify_place (struct GNUNET_MessageHeader *msg,
                  struct GNUNET_SERVER_Client *client)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Sending place notification of type %u to client.\n",
              client, ntohs (msg->type));

  uint16_t msg_size = ntohs (msg->size);
  struct AppPlaceMessage amsg;
  amsg.header.type = htons (GNUNET_MESSAGE_TYPE_SOCIAL_APP_PLACE);
  amsg.header.size = htons (sizeof (amsg));
  // FIXME: also notify about not entered places
  amsg.place_state = GNUNET_SOCIAL_PLACE_STATE_ENTERED;

  switch (ntohs (msg->type))
  {
  case GNUNET_MESSAGE_TYPE_SOCIAL_HOST_ENTER:
    if (msg_size < sizeof (struct HostEnterRequest))
      return;
    struct HostEnterRequest *hreq = (struct HostEnterRequest *) msg;
    amsg.is_host = GNUNET_YES;
    amsg.ego_pub_key = hreq->ego_pub_key;
    amsg.place_pub_key = hreq->place_pub_key;
    break;

  case GNUNET_MESSAGE_TYPE_SOCIAL_GUEST_ENTER:
    if (msg_size < sizeof (struct GuestEnterRequest))
      return;
    struct GuestEnterRequest *greq = (struct GuestEnterRequest *) msg;
    amsg.is_host = GNUNET_NO;
    amsg.ego_pub_key = greq->ego_pub_key;
    amsg.place_pub_key = greq->place_pub_key;
    break;

  default:
    return;
  }

  client_send_msg (client, &amsg.header);
}


void
app_notify_ego (struct Ego *ego, struct GNUNET_SERVER_Client *client)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Sending ego notification to client: %s\n",
              client, ego->name);

  size_t name_size = strlen (ego->name) + 1;
  struct AppEgoMessage *emsg = GNUNET_malloc (sizeof (*emsg) + name_size);
  emsg->header.type = htons (GNUNET_MESSAGE_TYPE_SOCIAL_APP_EGO);
  emsg->header.size = htons (sizeof (*emsg) + name_size);

  GNUNET_CRYPTO_ecdsa_key_get_public (&ego->key, &emsg->ego_pub_key);
  memcpy (&emsg[1], ego->name, name_size);

  client_send_msg (client, &emsg->header);
  GNUNET_free (emsg);
}


int
app_place_entry_notify (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct GNUNET_MessageHeader *
    msg = GNUNET_CONTAINER_multihashmap_get (places, key);
  if (NULL != msg)
    app_notify_place (msg, cls);
  return GNUNET_YES;
}


int
ego_entry (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  app_notify_ego (value, cls);
  return GNUNET_YES;
}


/**
 * Handle application connection.
 */
static void
client_recv_app_connect (void *cls, struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *msg)
{
  const struct AppConnectRequest *creq
    = (const struct AppConnectRequest *) msg;

  uint8_t app_id_size = ntohs (creq->header.size) - sizeof (*creq);
  const char *app_id = NULL;
  uint16_t offset = GNUNET_STRINGS_buffer_tokenize ((const char *) &creq[1],
                                                    app_id_size, 1, &app_id);
  if (0 == offset || offset != app_id_size)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  struct GNUNET_HashCode app_id_hash;
  GNUNET_CRYPTO_hash (app_id, app_id_size, &app_id_hash);

  GNUNET_CONTAINER_multihashmap_iterate (egos, ego_entry, client);

  struct GNUNET_CONTAINER_MultiHashMap *
    app_places = GNUNET_CONTAINER_multihashmap_get (apps_places, &app_id_hash);
  if (NULL != app_places)
    GNUNET_CONTAINER_multihashmap_iterate (app_places, app_place_entry_notify, client);

  struct ClientListItem *cli = GNUNET_new (struct ClientListItem);
  cli->client = client;
  struct Application *app = GNUNET_CONTAINER_multihashmap_get (apps,
                                                               &app_id_hash);
  if (NULL == app) {
    app = GNUNET_malloc (sizeof (*app));
    (void) GNUNET_CONTAINER_multihashmap_put (apps, &app_id_hash, app,
                                              GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  }
  GNUNET_CONTAINER_DLL_insert (app->clients_head, app->clients_tail, cli);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Application %s connected.\n", app, app_id);

  struct Client *ctx = GNUNET_new (struct Client);
  ctx->app_id = GNUNET_malloc (app_id_size);
  memcpy (ctx->app_id, app_id, app_id_size);

  GNUNET_SERVER_client_set_user_context (client, ctx);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handle application detach request.
 */
static void
client_recv_app_detach (void *cls, struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *msg)
{
  struct Client *
    ctx = GNUNET_SERVER_client_get_user_context (client, struct Client);
  GNUNET_assert (NULL != ctx);

  const struct AppDetachRequest *req
    = (const struct AppDetachRequest *) msg;

  int ret = app_place_remove (ctx->app_id, &req->place_pub_key);
  client_send_result (client, req->op_id, ret, NULL, 0);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


int
app_places_entry_remove (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  app_place_remove (value, cls);
  return GNUNET_YES;
}


/**
 * Handle application detach request.
 */
static void
client_recv_place_leave (void *cls, struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *msg)
{
  struct Client *
    ctx = GNUNET_SERVER_client_get_user_context (client, struct Client);
  GNUNET_assert (NULL != ctx);
  struct Place *plc = ctx->plc;

  /* FIXME: remove all app subscriptions and leave this place  */

  struct GNUNET_CONTAINER_MultiHashMap *
    place_apps = GNUNET_CONTAINER_multihashmap_get (places_apps, &plc->pub_key_hash);
  if (NULL != place_apps)
  {
    GNUNET_CONTAINER_multihashmap_iterate (place_apps, app_places_entry_remove, &plc->pub_key);
  }

  /* FIXME: disconnect from the network, but keep local connection for history access */

  /* Disconnect all clients connected to the place */
  struct ClientListItem *cli = plc->clients_head, *next;
  while (NULL != cli)
  {
    GNUNET_CONTAINER_DLL_remove (plc->clients_head, plc->clients_tail, cli);
    GNUNET_SERVER_client_disconnect (cli->client);
    next = cli->next;
    GNUNET_free (cli);
    cli = next;
  }

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
  if (GNUNET_YES != plc->is_host) {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  struct Host *hst = (struct Host *) plc;

  struct GNUNET_PSYC_JoinDecisionMessage *
    dcsn = (struct GNUNET_PSYC_JoinDecisionMessage *) msg;
  struct JoinDecisionClosure jcls;
  jcls.is_admitted = ntohl (dcsn->is_admitted);
  jcls.msg
    = (sizeof (*dcsn) + sizeof (*jcls.msg) <= ntohs (msg->size))
    ? (struct GNUNET_PSYC_Message *) &dcsn[1]
    : NULL;

  struct GNUNET_HashCode slave_pub_hash;
  GNUNET_CRYPTO_hash (&dcsn->slave_pub_key, sizeof (dcsn->slave_pub_key),
                      &slave_pub_hash);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Got join decision (%d) from client for place %s..\n",
              hst, jcls.is_admitted, GNUNET_h2s (&plc->pub_key_hash));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p ..and slave %s.\n",
              hst, GNUNET_h2s (&slave_pub_hash));

  GNUNET_CONTAINER_multihashmap_get_multiple (hst->join_reqs, &slave_pub_hash,
                                              &psyc_send_join_decision, &jcls);
  GNUNET_CONTAINER_multihashmap_remove_all (hst->join_reqs, &slave_pub_hash);
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
  client_send_msg (client, &res);
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
                plc, NULL != pmsg ? ntohs (pmsg->type) : 0);
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
 * A historic message arrived from PSYC.
 */
static void
psyc_recv_history_message (void *cls, uint64_t message_id, uint32_t flags,
                           const struct GNUNET_PSYC_MessageHeader *msg)
{
  struct OperationClosure *opcls = cls;
  struct Place *plc = opcls->plc;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Received historic message #%" PRId64 " (flags: %x)\n",
              plc, message_id, flags);

  uint16_t size = ntohs (msg->header.size);

  struct GNUNET_OperationResultMessage *
    res = GNUNET_malloc (sizeof (*res) + size);
  res->header.size = htons (sizeof (*res) + size);
  res->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_HISTORY_RESULT);
  res->op_id = opcls->op_id;
  res->result_code = GNUNET_htonll (GNUNET_OK);

  memcpy (&res[1], msg, size);

  /** @todo FIXME: send only to requesting client */
  place_send_msg (plc, &res->header);
}


/**
 * Result of message history replay from PSYC.
 */
static void
psyc_recv_history_result (void *cls, int64_t result,
                          const void *err_msg, uint16_t err_msg_size)
{
  struct OperationClosure *opcls = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p History replay #%" PRIu64 ": "
              "PSYCstore returned %" PRId64 " (%.*s)\n",
              opcls->plc, GNUNET_ntohll (opcls->op_id), result, err_msg_size, err_msg);

  // FIXME: place might have been destroyed
  client_send_result (opcls->client, opcls->op_id, result, err_msg, err_msg_size);
}


/**
 * Client requests channel history.
 */
static void
client_recv_history_replay (void *cls, struct GNUNET_SERVER_Client *client,
                            const struct GNUNET_MessageHeader *msg)
{
  struct Client *
    ctx = GNUNET_SERVER_client_get_user_context (client, struct Client);
  GNUNET_assert (NULL != ctx);
  struct Place *plc = ctx->plc;

  const struct GNUNET_PSYC_HistoryRequestMessage *
    req = (const struct GNUNET_PSYC_HistoryRequestMessage *) msg;
  uint16_t size = ntohs (msg->size);
  const char *method_prefix = (const char *) &req[1];

  if (size < sizeof (*req) + 1
      || '\0' != method_prefix[size - sizeof (*req) - 1])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%p History replay #%" PRIu64 ": "
                "invalid method prefix. size: %u < %u?\n",
                plc, GNUNET_ntohll (req->op_id), size, sizeof (*req) + 1);
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  struct OperationClosure *opcls = GNUNET_malloc (sizeof (*opcls));
  opcls->client = client;
  opcls->plc = plc;
  opcls->op_id = req->op_id;
  opcls->flags = ntohl (req->flags);

  if (0 == req->message_limit)
    GNUNET_PSYC_channel_history_replay (plc->channel,
                                        GNUNET_ntohll (req->start_message_id),
                                        GNUNET_ntohll (req->end_message_id),
                                        method_prefix, opcls->flags,
                                        &psyc_recv_history_message, NULL,
                                        &psyc_recv_history_result, opcls);
  else
    GNUNET_PSYC_channel_history_replay_latest (plc->channel,
                                               GNUNET_ntohll (req->message_limit),
                                               method_prefix, opcls->flags,
                                               &psyc_recv_history_message, NULL,
                                               &psyc_recv_history_result, opcls);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * A state variable part arrived from PSYC.
 */
void
psyc_recv_state_var (void *cls,
                     const struct GNUNET_MessageHeader *mod,
                     const char *name,
                     const void *value,
                     uint32_t value_size,
                     uint32_t full_value_size)
{
  struct OperationClosure *opcls = cls;
  struct Place *plc = opcls->plc;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Received state variable %s from PSYC\n",
              plc, name);

  uint16_t size = ntohs (mod->size);

  struct GNUNET_OperationResultMessage *
    res = GNUNET_malloc (sizeof (*res) + size);
  res->header.size = htons (sizeof (*res) + size);
  res->header.type = htons (GNUNET_MESSAGE_TYPE_PSYC_STATE_RESULT);
  res->op_id = opcls->op_id;
  res->result_code = GNUNET_htonll (GNUNET_OK);

  memcpy (&res[1], mod, size);

  /** @todo FIXME: send only to requesting client */
  place_send_msg (plc, &res->header);
}


/**
 * Result of retrieving state variable from PSYC.
 */
static void
psyc_recv_state_result (void *cls, int64_t result,
                        const void *err_msg, uint16_t err_msg_size)
{
  struct OperationClosure *opcls = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p State get #%" PRIu64 ": "
              "PSYCstore returned %" PRId64 " (%.*s)\n",
              opcls->plc, GNUNET_ntohll (opcls->op_id), result, err_msg_size, err_msg);

  // FIXME: place might have been destroyed
  client_send_result (opcls->client, opcls->op_id, result, err_msg, err_msg_size);
}


/**
 * Client requests channel history.
 */
static void
client_recv_state_get (void *cls, struct GNUNET_SERVER_Client *client,
                       const struct GNUNET_MessageHeader *msg)
{
  struct Client *
    ctx = GNUNET_SERVER_client_get_user_context (client, struct Client);
  GNUNET_assert (NULL != ctx);
  struct Place *plc = ctx->plc;

  const struct GNUNET_PSYC_StateRequestMessage *
    req = (const struct GNUNET_PSYC_StateRequestMessage *) msg;
  uint16_t size = ntohs (msg->size);
  const char *name = (const char *) &req[1];

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "%p State get #%" PRIu64 ": %s\n",
              plc, GNUNET_ntohll (req->op_id), name);

  if (size < sizeof (*req) + 1
      || '\0' != name[size - sizeof (*req) - 1])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%p State get #%" PRIu64 ": "
                "invalid name. size: %u < %u?\n",
                plc, GNUNET_ntohll (req->op_id), size, sizeof (*req) + 1);
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  struct OperationClosure *opcls = GNUNET_malloc (sizeof (*opcls));
  opcls->client = client;
  opcls->plc = plc;
  opcls->op_id = req->op_id;

  switch (ntohs (msg->type))
  {
  case GNUNET_MESSAGE_TYPE_PSYC_STATE_GET:
      GNUNET_PSYC_channel_state_get (plc->channel, name,
                                     psyc_recv_state_var,
                                     psyc_recv_state_result, opcls);
      break;

  case GNUNET_MESSAGE_TYPE_PSYC_STATE_GET_PREFIX:
      GNUNET_PSYC_channel_state_get_prefix (plc->channel, name,
                                            psyc_recv_state_var,
                                            psyc_recv_state_result, opcls);
      break;

  default:
      GNUNET_assert (0);
  }

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


static void
namestore_recv_records_store_result (void *cls, int32_t result,
                                     const char *err_msg)
{
  struct OperationClosure *ocls = cls;
  client_send_result (ocls->client, ocls->op_id, result, err_msg,
                      (NULL != err_msg) ? strlen (err_msg) : 0);
  GNUNET_free (ocls);
}


/**
 * Handle request to add PLACE record to GNS zone.
 */
static void
client_recv_zone_add_place (void *cls, struct GNUNET_SERVER_Client *client,
                             const struct GNUNET_MessageHeader *msg)
{
  const struct ZoneAddPlaceRequest *preq
    = (const struct ZoneAddPlaceRequest *) msg;

  uint16_t remaining = ntohs (preq->header.size) - sizeof (*preq);
  const char *p = (const char *) &preq[1];
  const char *name = NULL, *password = NULL;
  uint16_t offset = GNUNET_STRINGS_buffer_tokenize (p, remaining, 2,
                                                    &name, &password);
  remaining -= offset;
  p += offset;
  const struct GNUNET_PeerIdentity *
    relays = (const struct GNUNET_PeerIdentity *) p;
  uint16_t relay_size = ntohl (preq->relay_count) * sizeof (*relays);

  if (0 == offset || remaining != relay_size)
  {
    GNUNET_break (0);
    client_send_result (client, preq->op_id, GNUNET_SYSERR, NULL, 0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  struct GNUNET_GNSRECORD_Data rd = { };
  rd.record_type = GNUNET_GNSRECORD_TYPE_PLACE;
  rd.flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
  rd.expiration_time = GNUNET_ntohll (preq->expiration_time);

  struct GNUNET_GNSRECORD_PlaceData *
    rec = GNUNET_malloc (sizeof (*rec) + relay_size);
  rec->place_pub_key = preq->place_pub_key;
  rec->origin = this_peer;
  rec->relay_count = preq->relay_count;
  memcpy (&rec[1], relays, relay_size);

  rd.data = rec;
  rd.data_size = sizeof (*rec) + relay_size;

  struct GNUNET_HashCode ego_pub_hash;
  GNUNET_CRYPTO_hash (&preq->ego_pub_key, sizeof (preq->ego_pub_key), &ego_pub_hash);
  struct Ego *ego = GNUNET_CONTAINER_multihashmap_get (egos, &ego_pub_hash);
  if (NULL == ego)
  {
    client_send_result (client, preq->op_id, GNUNET_SYSERR, NULL, 0);
  }
  else
  {
    struct OperationClosure *ocls = GNUNET_malloc (sizeof (*ocls));
    ocls->client = client;
    ocls->op_id = preq->op_id;
    GNUNET_NAMESTORE_records_store (namestore, &ego->key,
                                    name, 1, &rd,
                                    namestore_recv_records_store_result, ocls);
  }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handle request to add PLACE record to GNS zone.
 */
static void
client_recv_zone_add_nym (void *cls, struct GNUNET_SERVER_Client *client,
                          const struct GNUNET_MessageHeader *msg)
{
  const struct ZoneAddNymRequest *nreq
    = (const struct ZoneAddNymRequest *) msg;

  uint16_t name_size = ntohs (nreq->header.size) - sizeof (*nreq);
  const char *name = NULL;
  uint16_t offset = GNUNET_STRINGS_buffer_tokenize ((const char *) &nreq[1],
                                                    name_size, 1, &name);
  if (0 == offset || offset != name_size)
  {
    GNUNET_break (0);
    client_send_result (client, nreq->op_id, GNUNET_SYSERR, NULL, 0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  struct GNUNET_GNSRECORD_Data rd = { };
  rd.record_type = GNUNET_GNSRECORD_TYPE_PKEY;
  rd.flags = GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION;
  rd.expiration_time = GNUNET_ntohll (nreq->expiration_time);
  rd.data = &nreq->nym_pub_key;
  rd.data_size = sizeof (nreq->nym_pub_key);

  struct GNUNET_HashCode ego_pub_hash;
  GNUNET_CRYPTO_hash (&nreq->ego_pub_key, sizeof (nreq->ego_pub_key), &ego_pub_hash);
  struct Ego *ego = GNUNET_CONTAINER_multihashmap_get (egos, &ego_pub_hash);
  if (NULL == ego)
  {
    client_send_result (client, nreq->op_id, GNUNET_SYSERR, NULL, 0);
  }
  else
  {
    struct OperationClosure *ocls = GNUNET_malloc (sizeof (*ocls));
    ocls->client = client;
    ocls->op_id = nreq->op_id;
    GNUNET_NAMESTORE_records_store (namestore, &ego->key,
                                      name, 1, &rd,
                                      namestore_recv_records_store_result, ocls);
  }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


static const struct GNUNET_SERVER_MessageHandler handlers[] = {
  { client_recv_host_enter, NULL,
    GNUNET_MESSAGE_TYPE_SOCIAL_HOST_ENTER, 0 },

  { client_recv_guest_enter, NULL,
    GNUNET_MESSAGE_TYPE_SOCIAL_GUEST_ENTER, 0 },

  { client_recv_guest_enter_by_name, NULL,
    GNUNET_MESSAGE_TYPE_SOCIAL_GUEST_ENTER_BY_NAME, 0 },

  { client_recv_join_decision, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_JOIN_DECISION, 0 },

  { client_recv_psyc_message, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_MESSAGE, 0 },

  { client_recv_history_replay, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_HISTORY_REPLAY, 0 },

  { client_recv_state_get, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_STATE_GET, 0 },

  { client_recv_state_get, NULL,
    GNUNET_MESSAGE_TYPE_PSYC_STATE_GET_PREFIX, 0 },

  { client_recv_zone_add_place, NULL,
    GNUNET_MESSAGE_TYPE_SOCIAL_ZONE_ADD_PLACE, 0 },

  { client_recv_zone_add_nym, NULL,
    GNUNET_MESSAGE_TYPE_SOCIAL_ZONE_ADD_NYM, 0 },

  { client_recv_app_connect, NULL,
    GNUNET_MESSAGE_TYPE_SOCIAL_APP_CONNECT, 0 },

  { client_recv_app_detach, NULL,
    GNUNET_MESSAGE_TYPE_SOCIAL_APP_DETACH, 0 },

  { client_recv_place_leave, NULL,
    GNUNET_MESSAGE_TYPE_SOCIAL_PLACE_LEAVE, 0 },

  { client_recv_msg_proc_set, NULL,
    GNUNET_MESSAGE_TYPE_SOCIAL_MSG_PROC_SET, 0 },

  { client_recv_msg_proc_clear, NULL,
    GNUNET_MESSAGE_TYPE_SOCIAL_MSG_PROC_CLEAR, 0 },

  { NULL, NULL, 0, 0 }
};


const char *
path_basename (const char *path)
{
  const char *basename = strrchr (path, DIR_SEPARATOR);
  if (NULL != basename)
    basename++;

  if (NULL == basename || '\0' == basename)
    return NULL;

  return basename;
}


struct PlaceLoadClosure
{
  const char *app_id;
  const char *ego_pub_hash_str;
};


/** Load a place file */
int
file_place_load (void *cls, const char *filename)
{
  char *app_id = cls;
  uint64_t file_size = 0;
  if (GNUNET_OK !=
      GNUNET_DISK_file_size (filename, &file_size, GNUNET_YES, GNUNET_YES)
      || file_size < sizeof (struct HostEnterRequest))
    return GNUNET_OK;

  struct PlaceEnterRequest *ereq = GNUNET_malloc (file_size);
  ssize_t read_size = GNUNET_DISK_fn_read (filename, ereq, file_size);
  if (read_size < 0 || read_size < sizeof (*ereq))
    return GNUNET_OK;

  uint16_t ereq_size = ntohs (ereq->header.size);
  if (read_size != ereq_size)
    return GNUNET_OK;

  switch (ntohs (ereq->header.type))
  {
  case GNUNET_MESSAGE_TYPE_SOCIAL_HOST_ENTER:
    if (ereq_size < sizeof (struct HostEnterRequest))
      return GNUNET_OK;
    struct HostEnterRequest *hreq = (struct HostEnterRequest *) ereq;
    host_enter (hreq, NULL);
    break;

  case GNUNET_MESSAGE_TYPE_SOCIAL_GUEST_ENTER:
    if (ereq_size < sizeof (struct GuestEnterRequest))
      return GNUNET_OK;
    struct GuestEnterRequest *greq = (struct GuestEnterRequest *) ereq;
    guest_enter (greq, NULL);
    break;

  default:
    return GNUNET_OK;
  }

  app_place_add (app_id, ereq);
  return GNUNET_OK;
}


/** Load an ego place file */
int
file_ego_place_load (void *cls, const char *place_filename)
{
  struct PlaceLoadClosure *plcls = cls;

  const char *place_pub_hash_str = path_basename (place_filename);
  if (NULL == place_pub_hash_str)
  {
    GNUNET_break (0);
    return GNUNET_OK;
  }

  char *filename = NULL;
  GNUNET_asprintf (&filename, "%s%c" "%s%c" "%s%c" "%s",
                   dir_social, DIR_SEPARATOR,
                   "places", DIR_SEPARATOR,
                   plcls->ego_pub_hash_str, DIR_SEPARATOR,
                   place_pub_hash_str);

  struct PlaceEnterRequest ereq[GNUNET_SERVER_MAX_MESSAGE_SIZE];

  int read_size = GNUNET_DISK_fn_read (filename, &ereq,
                                       GNUNET_SERVER_MAX_MESSAGE_SIZE);
  GNUNET_free (filename);

  if (read_size < (ssize_t) sizeof (ereq))
    return GNUNET_OK;

  app_place_add (plcls->app_id, ereq);
  return GNUNET_OK;
}


/**
 * Read @e place_pub_hash_str entries in @a dir_ego
 *
 * @param dir_ego
 *        Data directory of an application ego.
 *        $GNUNET_DATA_HOME/social/apps/$app_id/$ego_pub_hash_str/
 */
int
scan_app_ego_dir (void *cls, const char *dir_ego)
{
  struct PlaceLoadClosure *plcls = cls;
  plcls->ego_pub_hash_str = path_basename (dir_ego);

  if (NULL != plcls->ego_pub_hash_str)
    GNUNET_DISK_directory_scan (dir_ego, file_ego_place_load, plcls);

  return GNUNET_OK;
}

/**
 * Read @e ego_pub_hash_str entries in @a dir_app
 *
 * @param dir_app
 *        Data directory of an application.
 *        $GNUNET_DATA_HOME/social/apps/$app_id/
 */
int
scan_app_dir (void *cls, const char *dir_app)
{
  if (GNUNET_YES != GNUNET_DISK_directory_test (dir_app, GNUNET_YES))
    return GNUNET_OK;

  struct PlaceLoadClosure plcls;
  plcls.app_id = path_basename (dir_app);

  if (NULL != plcls.app_id)
    GNUNET_DISK_directory_scan (dir_app, scan_app_ego_dir, &plcls);

  return GNUNET_OK;
}


static void
identity_recv_ego (void *cls, struct GNUNET_IDENTITY_Ego *id_ego,
                   void **ctx, const char *name)
{
  if (NULL == id_ego) // end of initial list of egos
    return;

  struct GNUNET_CRYPTO_EcdsaPublicKey ego_pub_key;
  GNUNET_IDENTITY_ego_get_public_key (id_ego, &ego_pub_key);

  struct GNUNET_HashCode ego_pub_hash;
  GNUNET_CRYPTO_hash (&ego_pub_key, sizeof (ego_pub_key), &ego_pub_hash);

  struct Ego *ego = GNUNET_CONTAINER_multihashmap_get (egos, &ego_pub_hash);
  if (NULL != ego)
  {
    GNUNET_free (ego->name);
    if (NULL == name) // deleted
    {
      GNUNET_CONTAINER_multihashmap_remove (egos, &ego_pub_hash, ego);
      GNUNET_free (ego);
      ego = NULL;
    }
  }
  else
  {
    ego = GNUNET_malloc (sizeof (*ego));
  }
  if (NULL != ego)
  {
    ego->key = *(GNUNET_IDENTITY_ego_get_private_key (id_ego));
    size_t name_size = strlen (name) + 1;
    ego->name = GNUNET_malloc (name_size);
    memcpy (ego->name, name, name_size);

    GNUNET_CONTAINER_multihashmap_put (egos, &ego_pub_hash, ego,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);
  }
}


/**
 * Connected to core service.
 */
static void
core_connected (void *cls, const struct GNUNET_PeerIdentity *my_identity)
{
  this_peer = *my_identity;
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
  cfg = c;

  hosts = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);
  guests = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);
  place_guests = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);

  egos = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);
  apps = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);
  places = GNUNET_CONTAINER_multihashmap_create(1, GNUNET_NO);
  apps_places = GNUNET_CONTAINER_multihashmap_create(1, GNUNET_NO);
  places_apps = GNUNET_CONTAINER_multihashmap_create(1, GNUNET_NO);

  core = GNUNET_CORE_connect (cfg, NULL, core_connected, NULL, NULL,
                              NULL, GNUNET_NO, NULL, GNUNET_NO, NULL);
  id = GNUNET_IDENTITY_connect (cfg, &identity_recv_ego, NULL);
  gns = GNUNET_GNS_connect (cfg);
  namestore = GNUNET_NAMESTORE_connect (cfg);
  stats = GNUNET_STATISTICS_create ("social", cfg);

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg, "social", "DATA_HOME",
                                               &dir_social))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "social", "DATA_HOME");
    GNUNET_break (0);
    return;
  }
  GNUNET_asprintf (&dir_places, "%s%c%s",
                   dir_social, DIR_SEPARATOR, "places");
  GNUNET_asprintf (&dir_apps, "%s%c%s",
                   dir_social, DIR_SEPARATOR, "apps");

  GNUNET_DISK_directory_scan (dir_apps, scan_app_dir, NULL);

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
