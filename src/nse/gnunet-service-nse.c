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
#include "gnunet_service_lib.h"
#include "gnunet_server_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_time_lib.h"
#include "gnunet_nse_service.h"
#include "nse.h"

#define DEFAULT_HISTORY_SIZE 10

#define DEFAULT_CORE_QUEUE_SIZE 32

#define MILLISECONDS_PER_DAY 86400000

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
 * Handle to our current configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to the core service.
 */
struct GNUNET_CORE_Handle *coreAPI;

/**
 * Copy of this peer's identity.
 */
static struct GNUNET_PeerIdentity my_identity;

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
 */
static double current_size_estimate;

/**
 * The standard deviation of the last
 * DEFAULT_HISTORY_SIZE network size estimates.
 */
static double current_std_dev;

/**
 * Array of the last DEFAULT_HISTORY_SIZE
 * network size estimates.
 */
//static double *size_estimates[DEFAULT_HISTORY_SIZE];

/**
 * Task scheduled to send flood message.
 */
static GNUNET_SCHEDULER_TaskIdentifier flood_task;

/**
 * Notification context, simplifies client broadcasts.
 */
static struct GNUNET_SERVER_NotificationContext *nc;

/**
 * The previous major time.
 */
struct GNUNET_TIME_Absolute previous_timestamp;

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
  GNUNET_SERVER_notification_context_unicast (nc, client,
                                              &current_estimate_message.header,
                                              GNUNET_NO);
  GNUNET_SERVER_receive_done(client, GNUNET_OK);
}

/**
 * Core handler for size estimate flooding messages.
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @param atsi performance data
 *
 */
static int
handle_p2p_size_estimate (void *cls,
                              const struct GNUNET_PeerIdentity *peer,
                              const struct GNUNET_MessageHeader *message,
                              const struct GNUNET_TRANSPORT_ATS_Information
                              *atsi)
{

  return GNUNET_OK;
}


/**
 * Send a flood message containing our peer's public key
 * and the hashed current timestamp.
 */
static void
send_flood_message (void *cls,
                    const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;
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
 * Task to schedule a flood message to be sent.
 *
 * @param cls closure
 * @param tc context information (why was this task triggered now)
 */
static void schedule_flood_message (void *cls,
                                    const struct
                                    GNUNET_SCHEDULER_TaskContext * tc)
{
  GNUNET_HashCode timestamp_hash;
  struct GNUNET_TIME_Absolute curr_time;
  unsigned int matching_bits;

  /* Get the current UTC time */
  curr_time = GNUNET_TIME_absolute_get();
  /* Find the previous interval start time */
  previous_timestamp.abs_value = (curr_time.abs_value / GNUNET_NSE_INTERVAL) * GNUNET_NSE_INTERVAL;
  /* Find the next interval start time */
  next_timestamp.abs_value = (curr_time.abs_value / GNUNET_NSE_INTERVAL) * (GNUNET_NSE_INTERVAL + 1);

  GNUNET_CRYPTO_hash(&next_timestamp.abs_value, sizeof(uint64_t), &timestamp_hash);
  matching_bits = GNUNET_CRYPTO_hash_matching_bits(&timestamp_hash, &my_identity.hashPubKey);

  GNUNET_SCHEDULER_add_delayed (
                                GNUNET_TIME_relative_add (
                                                          GNUNET_TIME_relative_multiply (
                                                                                         increment,
                                                                                         matching_bits),
                                                          GNUNET_TIME_absolute_get_remaining (
                                                                                              next_timestamp)),
                                &send_flood_message, NULL);
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

  flood_task = GNUNET_SCHEDULER_add_now(&schedule_flood_message, NULL);
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
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_start_message, NULL, GNUNET_MESSAGE_TYPE_NSE_START, 0},
    {NULL, NULL, 0, 0}
  };

  static const struct GNUNET_CORE_MessageHandler core_handlers[] = {
    {&handle_p2p_size_estimate, GNUNET_MESSAGE_TYPE_NSE_P2P_FLOOD, 0},
    {NULL, 0, 0}
  };

  cfg = c;
  GNUNET_SERVER_add_handlers (server, handlers);
  nc = GNUNET_SERVER_notification_context_create (server, 16);
  GNUNET_SERVER_disconnect_notify (server,
                                   &handle_client_disconnect,
                                   NULL);

  /** Connect to core service and register core handlers */
  coreAPI = GNUNET_CORE_connect (cfg,   /* Main configuration */
                                 DEFAULT_CORE_QUEUE_SIZE,       /* queue size */
                                 NULL,  /* Closure passed to functions */
                                 &core_init,    /* Call core_init once connected */
                                 NULL,  /* Handle connects */
                                 NULL,       /* Handle disconnects */
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
  current_size_estimate = NAN;
  current_std_dev = NAN;

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

