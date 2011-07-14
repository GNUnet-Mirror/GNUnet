/*
     This file is part of GNUnet.
     (C) 2009, 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file nse/gnunet-service-nse.c
 * @brief network size estimation service
 * @author Nathan Evans
 *
 * The purpose of this service is to estimate the size of the network.
 * Given a specified interval, each peer hashes the most recent
 * timestamp which is evenly divisible by that interval.  This hash
 * is compared in distance to the peer identity to choose an offset.
 * The closer the peer identity to the hashed timestamp, the earlier
 * the peer sends out a "nearest peer" message.  The closest peer's
 * message should thus be received before any others, which stops
 * those peer from sending their messages at a later duration.  So
 * every peer should receive the same nearest peer message, and
 * from this can calculate the expected number of peers in the
 * network.
 *
 */
#include "platform.h"
#include "gnunet_client_lib.h"
#include "gnunet_constants.h"
#include "gnunet_container_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_signatures.h"
#include "gnunet_service_lib.h"
#include "gnunet_server_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_time_lib.h"
#include "gnunet_nse_service.h"
#include "nse.h"

#define DEFAULT_HISTORY_SIZE 10

#define DEFAULT_CORE_QUEUE_SIZE 32

#define DEFAULT_NSE_PRIORITY 0

/**
 * Entry in the list of clients which
 * should be notified upon a new network
 * size estimate calculation.
 */
struct ClientListEntry
{
  /**
   *  Pointer to previous entry
   */
  struct ClientListEntry *prev;

  /**
   *  Pointer to next entry
   */
  struct ClientListEntry *next;

  /**
   * Client to notify.
   */
  struct GNUNET_SERVER_Client *client;
};

/**
 * Per-peer information.
 */
struct NSEPeerEntry
{
  /**
   * Next peer entry (DLL)
   */
  struct NSEPeerEntry *next;

  /**
   *  Prev peer entry (DLL)
   */
  struct NSEPeerEntry *prev;

  /**
   * Pending message for this peer.
   */
  struct GNUNET_MessageHeader *pending_message;

  /**
   * Core handle for sending messages to this peer.
   */
  struct GNUNET_CORE_TransmitHandle *th;

  /**
   * What is the identity of the peer?
   */
  struct GNUNET_PeerIdentity id;
};

/**
 * Handle to our current configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to the core service.
 */
static struct GNUNET_CORE_Handle *coreAPI;

/**
 * Head of global list of peers.
 */
static struct NSEPeerEntry *peers_head;

/**
 * Head of global list of clients.
 */
static struct NSEPeerEntry *peers_tail;

/**
 * Head of global list of clients.
 */
static struct ClientListEntry *cle_head;

/**
 * Tail of global list of clients.
 */
static struct ClientListEntry *cle_tail;

/**
 * The current network size estimate.
 * Number of bits matching on average
 * thus far.
 */
static double current_size_estimate;

/**
 * The standard deviation of the last
 * DEFAULT_HISTORY_SIZE network size estimates.
 */
static double current_std_dev;

/**
 * Array of the last DEFAULT_HISTORY_SIZE
 * network size estimates (matching bits, actually).
 */
static unsigned int size_estimates[DEFAULT_HISTORY_SIZE];

/**
 * Array of size estimate messages.
 */
static struct GNUNET_NSE_FloodMessage size_estimate_messages[DEFAULT_HISTORY_SIZE];

/**
 * Index of most recent estimate.
 */
static unsigned int estimate_index;

/**
 * Task scheduled to send flood message.
 */
static GNUNET_SCHEDULER_TaskIdentifier flood_task;

/**
 * Task to schedule flood message and update state.
 */
static GNUNET_SCHEDULER_TaskIdentifier schedule_flood_task;

/**
 * Notification context, simplifies client broadcasts.
 */
static struct GNUNET_SERVER_NotificationContext *nc;

/**
 * The previous major time.
 */
static struct GNUNET_TIME_Absolute previous_timestamp;

/**
 * The next major time.
 */
static struct GNUNET_TIME_Absolute next_timestamp;

/**
 * Base increment of time to add to send time.
 */
static struct GNUNET_TIME_Relative increment;

/**
 * The current network size estimate message.
 */
static struct GNUNET_NSE_ClientMessage current_estimate_message;

/**
 * The public key of this peer.
 */
static struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded my_public_key;

/**
 * The private key of this peer.
 */
static struct GNUNET_CRYPTO_RsaPrivateKey *my_private_key;

/**
 * The peer identity of this peer.
 */
static struct GNUNET_PeerIdentity my_identity;

/**
 * Our flood message, updated whenever a flood is sent.
 */
static struct GNUNET_NSE_FloodMessage flood_message;

/**
 * Handler for START message from client, triggers an
 * immediate current network estimate notification.
 * Also, we remember the client for updates upon future
 * estimate measurements.
 *
 * @param cls unused
 * @param client who sent the message
 * @param message the message received
 */
static void
handle_start_message (void *cls,
                      struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *message)
{
  if ((ntohs (message->size) != sizeof(struct GNUNET_MessageHeader))
      || (ntohs (message->type) != GNUNET_MESSAGE_TYPE_NSE_START))
    return;

#if DEBUG_NSE
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "NSE", "Received START message from client\n");
#endif
  GNUNET_SERVER_notification_context_add (nc, client);
  GNUNET_SERVER_receive_done(client, GNUNET_OK);
}


/**
 * Called when core is ready to send a message we asked for
 * out to the destination.
 *
 * @param cls closure (NULL)
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_ready (void *cls, size_t size, void *buf)
{
  struct NSEPeerEntry *peer_entry = cls;
  char *cbuf = buf;

  size_t msize;
  peer_entry->th = NULL;
  if (buf == NULL) /* client disconnected */
    return 0;

  if (peer_entry->pending_message == NULL)
    return 0;

  msize = ntohs(peer_entry->pending_message->size);
  if (msize <= size)
    memcpy(cbuf, peer_entry->pending_message, msize);

  return msize;
}

/**
 * We sent on our flood message or one that we received
 * which was validated and closer than ours.  Update the
 * global list of recent messages and the average.  Also
 * re-broadcast the message to any clients.
 *
 * @param message the network flood message
 */
static void update_network_size_estimate(struct GNUNET_NSE_FloodMessage *message)
{
  unsigned int i;
  unsigned int count;
  double average;

  size_estimates[estimate_index] = htons(message->distance);
  memcpy(&size_estimate_messages[estimate_index], message, sizeof(struct GNUNET_NSE_FloodMessage));

  count = 0;
  for (i = 0; i < DEFAULT_HISTORY_SIZE; i++)
    {
      if (size_estimate_messages[i].distance != 0)
        {
          average += 1 << htons(size_estimate_messages[i].distance);
          count++;
        }
    }
  average /= (double)count;
  current_estimate_message.size_estimate = average;
  /* Finally, broadcast the current estimate to all clients */
  GNUNET_SERVER_notification_context_broadcast (nc,
                                                &current_estimate_message.header,
                                                GNUNET_NO);
}

static void
send_flood_message (void *cls,
                    const struct GNUNET_SCHEDULER_TaskContext * tc);

/**
 * Schedule a flood message to be sent.
 *
 * @param cls unused
 * @param tc context for this message
 *
 * This should be called on startup,
 * when a valid flood message is received (and
 * the next send flood message hasn't been
 * scheduled yet) and when this peer sends
 * a valid flood message.  As such, there should
 * always be a message scheduled to be sent.
 */
static void
schedule_flood_message (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_HashCode timestamp_hash;
  struct GNUNET_TIME_Absolute curr_time;
  struct GNUNET_TIME_Relative offset;
  struct GNUNET_CRYPTO_RsaSignaturePurpose purpose;
  unsigned int matching_bits;
  double millisecond_offset;

  schedule_flood_task = GNUNET_SCHEDULER_NO_TASK;
  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;

  GNUNET_assert(flood_task == GNUNET_SCHEDULER_NO_TASK);

  if (0 != GNUNET_TIME_absolute_get_remaining(next_timestamp).rel_value)
    {
      GNUNET_break(0); /* Shouldn't ever happen! */
      schedule_flood_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_absolute_get_remaining(next_timestamp), &schedule_flood_message, NULL);
    }

  /* Get the current UTC time */
  curr_time = GNUNET_TIME_absolute_get();
  /* Find the previous interval start time */
  previous_timestamp.abs_value = (curr_time.abs_value / GNUNET_NSE_INTERVAL) * GNUNET_NSE_INTERVAL;
  /* Find the next interval start time */
  next_timestamp.abs_value = (curr_time.abs_value / GNUNET_NSE_INTERVAL) * (GNUNET_NSE_INTERVAL + 1);

  GNUNET_CRYPTO_hash(&next_timestamp.abs_value, sizeof(uint64_t), &timestamp_hash);
  matching_bits = GNUNET_CRYPTO_hash_matching_bits(&timestamp_hash, &my_identity.hashPubKey);

  flood_message.timestamp = GNUNET_TIME_absolute_hton(next_timestamp);
  flood_message.distance = htons(matching_bits);
  flood_message.enc_type = htons(0);
  flood_message.proof_of_work = htonl(0);
  purpose.purpose = GNUNET_SIGNATURE_PURPOSE_NSE_SEND;
  purpose.size = sizeof(struct GNUNET_NSE_FloodMessage) - sizeof(struct GNUNET_MessageHeader) - sizeof(flood_message.proof_of_work) - sizeof(flood_message.signature);
  GNUNET_CRYPTO_rsa_sign(my_private_key, &purpose, &flood_message.signature);

  /*S + f/2 - (f / pi) * (atan(x - p'))*/

  // S is next_timestamp
  // f is frequency (GNUNET_NSE_INTERVAL)
  // x is matching_bits
  // p' is current_size_estimate
  millisecond_offset = ((double)GNUNET_NSE_INTERVAL / (double)2) - ((GNUNET_NSE_INTERVAL / M_PI) * atan(matching_bits - current_size_estimate));

  fprintf(stderr, "my id matches %d bits, offset is %lu\n", matching_bits, (uint64_t)millisecond_offset);

  estimate_index += 1;

  if (estimate_index >= DEFAULT_HISTORY_SIZE)
    estimate_index = 0;

  offset.rel_value = (uint64_t)millisecond_offset + GNUNET_TIME_absolute_get_remaining (next_timestamp).rel_value;
  flood_task = GNUNET_SCHEDULER_add_delayed (offset,
                                             &send_flood_message, NULL);

}

/**
 * Core handler for size estimate flooding messages.
 *
 * @param cls closure unused
 * @param message message
 * @param peer peer identity this message is from (ignored)
 * @param atsi performance data (ignored)
 *
 */
static int
handle_p2p_size_estimate(void *cls, const struct GNUNET_PeerIdentity *peer,
                         const struct GNUNET_MessageHeader *message,
                         const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
  struct GNUNET_NSE_FloodMessage *incoming_flood;

  if (ntohs(message->size) != sizeof(struct GNUNET_NSE_FloodMessage))
    return GNUNET_NO;

  incoming_flood = (struct GNUNET_NSE_FloodMessage *)message;
  if (ntohs(incoming_flood->distance) <= ntohs(size_estimate_messages[estimate_index].distance)) /* Not closer than our most recent message */
    return GNUNET_OK;

  /* Have a new, better size estimate! */
  update_network_size_estimate(incoming_flood);

  if (schedule_flood_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel(schedule_flood_task);
  schedule_flood_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_absolute_get_remaining(next_timestamp), &schedule_flood_message, NULL);

  return GNUNET_OK;
}

/**
 * Send a flood message.
 *
 * If we've gotten here, it means we haven't received
 * a network size estimate message closer than ours.
 */
static void
send_flood_message (void *cls,
                    const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  struct NSEPeerEntry *peer_entry;

  flood_task = GNUNET_SCHEDULER_NO_TASK;
  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;

  peer_entry = peers_head;

  while (peer_entry != NULL)
    {
      peer_entry->th
          = GNUNET_CORE_notify_transmit_ready (coreAPI,
                                               GNUNET_YES,
                                               DEFAULT_NSE_PRIORITY,
                                               GNUNET_TIME_absolute_get_remaining (
                                                                                   next_timestamp),
                                               &peer_entry->id,
                                               ntohs (flood_message.header.size),
                                               &transmit_ready, peer_entry);
      peer_entry = peer_entry->next;
    }

  update_network_size_estimate(&flood_message);
  if (schedule_flood_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel(schedule_flood_task);
  schedule_flood_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_absolute_get_remaining(next_timestamp), &schedule_flood_message, NULL);
}

/**
 * Method called whenever a peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param atsi performance data
 */
static void
handle_core_connect (void *cls,
                     const struct GNUNET_PeerIdentity *peer,
                     const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
  struct NSEPeerEntry *peer_entry;

  peer_entry = GNUNET_malloc(sizeof(struct NSEPeerEntry));
  memcpy(&peer_entry->id, peer, sizeof(struct GNUNET_PeerIdentity));
  GNUNET_CONTAINER_DLL_insert(peers_head, peers_tail, peer_entry);
}


/**
 * Method called whenever a peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
handle_core_disconnect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct NSEPeerEntry *pos;

  pos = peers_head;
  while ((NULL != pos) && (0 != memcmp(&pos->id, peer, sizeof(struct GNUNET_PeerIdentity))))
    pos = pos->next;
  if (pos == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Received disconnect before connect!\n");
      GNUNET_break(0); /* Should never receive a disconnect message for a peer we don't know about... */
      return;
    }

  if (pos->pending_message != NULL)
    GNUNET_free(pos->pending_message);

  if (pos->th != NULL)
    GNUNET_CORE_notify_transmit_ready_cancel(pos->th);
  GNUNET_CONTAINER_DLL_remove(peers_head, peers_tail, pos);
  GNUNET_free(pos);
}


/**
 * A client disconnected. Remove it from the
 * global DLL of clients.
 *
 * @param cls closure, NULL
 * @param client identification of the client
 */
static void
handle_client_disconnect (void *cls,
                          struct GNUNET_SERVER_Client* client)
{
  struct ClientListEntry *cle;

  while (NULL != (cle = cle_head))
    cle = cle->next;

  if (cle != NULL)
    {
      GNUNET_SERVER_client_drop(cle->client);
      GNUNET_CONTAINER_DLL_remove(cle_head,
                                  cle_tail,
                                  cle);
      GNUNET_free(cle);
    }
  if (coreAPI != NULL)
    {
      GNUNET_CORE_disconnect(coreAPI);
      coreAPI = NULL;
    }
}

/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ClientListEntry *cle;

  if (flood_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel(flood_task);
  GNUNET_SERVER_notification_context_destroy (nc);
  nc = NULL;
  while (NULL != (cle = cle_head))
    {
      GNUNET_SERVER_client_drop (cle->client);
      GNUNET_CONTAINER_DLL_remove (cle_head,
                                   cle_tail,
                                   cle);
      GNUNET_free (cle);
    }

  if (coreAPI != NULL)
    {
      GNUNET_CORE_disconnect(coreAPI);
      coreAPI = NULL;
    }

}


/**
 * Called on core init/fail.
 *
 * @param cls service closure
 * @param server handle to the server for this service
 * @param identity the public identity of this peer
 * @param publicKey the public key of this peer
 */
void
core_init (void *cls,
           struct GNUNET_CORE_Handle *server,
           const struct GNUNET_PeerIdentity *identity,
           const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *publicKey)
{
  if (server == NULL)
    {
#if DEBUG_NSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "%s: Connection to core FAILED!\n", "nse",
                  GNUNET_i2s (identity));
#endif
      GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
      return;
    }
#if DEBUG_NSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Core connection initialized, I am peer: %s\n", "nse",
              GNUNET_i2s (identity));
#endif

  /* Copy our identity so we can use it */
  memcpy (&my_identity, identity, sizeof (struct GNUNET_PeerIdentity));
  /* Copy our public key for inclusion in flood messages */
  memcpy (&my_public_key, publicKey, sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));

  flood_message.header.size = htons(sizeof(struct GNUNET_NSE_FloodMessage));
  flood_message.header.type = htons(GNUNET_MESSAGE_TYPE_NSE_P2P_FLOOD);
  memcpy(&flood_message.pkey, &my_public_key, sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));

  if (flood_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel(flood_task);

  schedule_flood_task = GNUNET_SCHEDULER_add_now(&schedule_flood_message, NULL);

  GNUNET_SERVER_notification_context_broadcast (nc,
                                                &current_estimate_message.header,
                                                GNUNET_NO);
}

/**
 * Handle network size estimate clients.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls,
     struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  char *keyfile;
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_start_message, NULL, GNUNET_MESSAGE_TYPE_NSE_START, 0},
    {NULL, NULL, 0, 0}
  };

  static const struct GNUNET_CORE_MessageHandler core_handlers[] = {
    {&handle_p2p_size_estimate, GNUNET_MESSAGE_TYPE_NSE_P2P_FLOOD, 0},
    {NULL, 0, 0}
  };

  cfg = c;

  if (GNUNET_OK !=
        GNUNET_CONFIGURATION_get_value_filename (c,
                                                 "GNUNETD",
                                                 "HOSTKEY", &keyfile))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _
                  ("NSE service is lacking key configuration settings.  Exiting.\n"));
      GNUNET_SCHEDULER_shutdown ();
      return;
    }

  my_private_key = GNUNET_CRYPTO_rsa_key_create_from_file (keyfile);
  GNUNET_free (keyfile);
  if (my_private_key == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                       _("NSE Service could not access hostkey.  Exiting.\n"));
      GNUNET_SCHEDULER_shutdown ();
      return;
    }

  GNUNET_SERVER_add_handlers (server, handlers);
  nc = GNUNET_SERVER_notification_context_create (server, 16);
  GNUNET_SERVER_disconnect_notify (server,
                                   &handle_client_disconnect,
                                   NULL);

  flood_task = GNUNET_SCHEDULER_NO_TASK;
  /** Connect to core service and register core handlers */
  coreAPI = GNUNET_CORE_connect (cfg,   /* Main configuration */
                                 DEFAULT_CORE_QUEUE_SIZE,       /* queue size */
                                 NULL,  /* Closure passed to functions */
                                 &core_init,    /* Call core_init once connected */
                                 &handle_core_connect,  /* Handle connects */
                                 &handle_core_disconnect,       /* Handle disconnects */
                                 NULL,  /* Do we care about "status" updates? */
                                 NULL,  /* Don't want notified about all incoming messages */
                                 GNUNET_NO,     /* For header only inbound notification */
                                 NULL,  /* Don't want notified about all outbound messages */
                                 GNUNET_NO,     /* For header only outbound notification */
                                 core_handlers);        /* Register these handlers */

  if (coreAPI == NULL)
    {
      GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
      return;
    }

  increment
      = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS,
                                       GNUNET_NSE_INTERVAL
                                           / (sizeof(GNUNET_HashCode)
                                               * 8));
  /* Set we have no idea defaults for network size estimate */
  current_size_estimate = 0.0;
  current_std_dev = NAN;
  size_estimates[estimate_index] = 0;
  current_estimate_message.header.size = htons(sizeof(struct GNUNET_NSE_ClientMessage));
  current_estimate_message.header.type = htons(GNUNET_MESSAGE_TYPE_NSE_ESTIMATE);
  current_estimate_message.size_estimate = current_size_estimate;
  current_estimate_message.std_deviation = current_std_dev;

  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                &shutdown_task,
                                NULL);
}


/**
 * The main function for the statistics service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc,
                              argv,
                              "nse",
                              GNUNET_SERVICE_OPTION_NONE,
                              &run, NULL)) ? 0 : 1;
}

/* End of gnunet-service-nse.c */

