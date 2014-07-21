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
   * Size of @a buf
   */
  uint16_t size;

  /**
   * @see enum MessageState
   */
  uint8_t state;

  /* Followed by message */
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
 * Common part of the client context for both a host and guest.
 */
struct Place
{
  struct ClientList *clients_head;
  struct ClientList *clients_tail;

  struct TransmitMessage *tmit_head;
  struct TransmitMessage *tmit_tail;

  /**
   * Public key of the channel.
   */
  struct GNUNET_CRYPTO_EddsaPublicKey pub_key;

  /**
   * Hash of @a pub_key.
   */
  struct GNUNET_HashCode pub_key_hash;

  /**
   * Is this a host (#GNUNET_YES), or guest (#GNUNET_NO)?
   */
  uint8_t is_host;
};


/**
 * Client context for a host.
 */
struct Host
{
  /**
   * Place struct common for Host and Guest
   */
  struct Place pl;

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
  struct Place pl;

  /**
   * Private key of the slave.
   */
  struct GNUNET_CRYPTO_EddsaPrivateKey priv_key;

  /**
   * Public key of the slave.
   */
  struct GNUNET_CRYPTO_EddsaPublicKey pub_key;

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
};


// FIXME uncomment when used, otherwise gcc is unhappy
/*static*/ inline void
transmit_message (struct Place *pl);


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
  struct Place *pl = &hst->pl;

  if (NULL != hst->master)
    GNUNET_PSYC_master_stop (hst->master);
  GNUNET_CONTAINER_multihashmap_destroy (hst->join_reqs);
  GNUNET_CONTAINER_multihashmap_remove (hosts, &pl->pub_key_hash, pl);
}


/**
 * Clean up guest data structures after a client disconnected.
 */
static void
cleanup_guest (struct Guest *gst)
{
  struct Place *pl = &gst->pl;
  struct GNUNET_CONTAINER_MultiHashMap *
    pl_gst = GNUNET_CONTAINER_multihashmap_get (place_guests,
                                                &pl->pub_key_hash);
  GNUNET_assert (NULL != pl_gst);
  GNUNET_CONTAINER_multihashmap_remove (pl_gst, &gst->pub_key_hash, gst);

  if (0 == GNUNET_CONTAINER_multihashmap_size (pl_gst))
  {
    GNUNET_CONTAINER_multihashmap_remove (place_guests, &pl->pub_key_hash,
                                          pl_gst);
    GNUNET_CONTAINER_multihashmap_destroy (pl_gst);
  }
  GNUNET_CONTAINER_multihashmap_remove (guests, &pl->pub_key_hash, gst);

  if (NULL != gst->join_req)
    GNUNET_free (gst->join_req);
  if (NULL != gst->relays)
    GNUNET_free (gst->relays);
  if (NULL != gst->slave)
    GNUNET_PSYC_slave_part (gst->slave);
  GNUNET_CONTAINER_multihashmap_remove (guests, &pl->pub_key_hash, pl);
}


/**
 * Clean up place data structures after a client disconnected.
 */
static void
cleanup_place (struct Place *pl)
{
  (GNUNET_YES == pl->is_host)
    ? cleanup_host ((struct Host *) pl)
    : cleanup_guest ((struct Guest *) pl);
  GNUNET_free (pl);
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

  struct Place *
    pl = GNUNET_SERVER_client_get_user_context (client, struct Place);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%p Client (%s) disconnected from place %s\n",
              pl, (GNUNET_YES == pl->is_host) ? "host" : "guest",
              GNUNET_h2s (&pl->pub_key_hash));

  if (NULL == pl)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%p User context is NULL in client_disconnect()\n", pl);
    GNUNET_break (0);
    return;
  }

  struct ClientList *cl = pl->clients_head;
  while (NULL != cl)
  {
    if (cl->client == client)
    {
      GNUNET_CONTAINER_DLL_remove (pl->clients_head, pl->clients_tail, cl);
      GNUNET_free (cl);
      break;
    }
    cl = cl->next;
  }

  if (NULL == pl->clients_head)
  { /* Last client disconnected. */
    if (NULL != pl->tmit_head)
    { /* Send pending messages to PSYC before cleanup. */
      //FIXME: transmit_message (pl);
    }
    else
    {
      cleanup_place (pl);
    }
  }
}


static void
client_home_enter (void *cls, struct GNUNET_SERVER_Client *client,
                   const struct GNUNET_MessageHeader *msg)
{

}


static void
client_place_enter (void *cls, struct GNUNET_SERVER_Client *client,
                    const struct GNUNET_MessageHeader *msg)
{

}


static void
client_join_decision (void *cls, struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *msg)
{

}


static void
client_psyc_message (void *cls, struct GNUNET_SERVER_Client *client,
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
// FIXME please commit gnunet_protocols.h and uncoment!
//     { &client_home_enter, NULL,
//       GNUNET_MESSAGE_TYPE_SOCIAL_HOME_ENTER, 0 },
//
//     { &client_place_enter, NULL,
//       GNUNET_MESSAGE_TYPE_SOCIAL_PLACE_ENTER, 0 },
//
//     { &client_join_decision, NULL,
//       GNUNET_MESSAGE_TYPE_SOCIAL_JOIN_DECISION, 0 },

    { &client_psyc_message, NULL,
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
