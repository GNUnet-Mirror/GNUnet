/*
     This file is part of GNUnet.
     Copyright (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file ats/gnunet-service-ats_reservations.c
 * @brief ats service, inbound bandwidth reservation management
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-ats_reservations.h"
#include "gnunet-service-ats.h"
#include "ats.h"

/**
 * Number of seconds that available bandwidth carries over
 * (can accumulate).  Note that the
 * test_ats_reservation_api test depends on this value!
 */
#define MAX_BANDWIDTH_CARRY_S 5


/**
 * Map of peer identities to `struct GNUNET_BANDWIDTH_Tracker *`s
 */
static struct GNUNET_CONTAINER_MultiPeerMap *trackers;


/**
 * Reserve the given amount of incoming bandwidth (in bytes) from the
 * given peer.  If a reservation is not possible right now, return how
 * long the client should wait before trying again.
 *
 * @param peer peer to reserve bandwidth from
 * @param amount number of bytes to reserve
 * @return 0 if the reservation was successful, FOREVER if the
 *         peer is not connected, otherwise the time to wait
 *         until the reservation might succeed
 */
static struct GNUNET_TIME_Relative
reservations_reserve (const struct GNUNET_PeerIdentity *peer,
                      int32_t amount)
{
  struct GNUNET_BANDWIDTH_Tracker *tracker;
  struct GNUNET_TIME_Relative ret;

  tracker = GNUNET_CONTAINER_multipeermap_get (trackers,
                                               peer);
  if (NULL == tracker)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Not connected, allowing reservation of %d bytes\n",
                (int) amount);
    return GNUNET_TIME_UNIT_ZERO;       /* not connected, satisfy now */
  }
  if (amount >= 0)
  {
    ret = GNUNET_BANDWIDTH_tracker_get_delay (tracker, amount);
    if (ret.rel_value_us > 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Delay to satisfy reservation for %d bytes is %s\n",
                  (int) amount,
		  GNUNET_STRINGS_relative_time_to_string (ret,
							  GNUNET_YES));
      return ret;
    }
  }
  (void) GNUNET_BANDWIDTH_tracker_consume (tracker, amount);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Reserved %d bytes\n",
              (int) amount);
  return GNUNET_TIME_UNIT_ZERO;
}


/**
 * Set the amount of bandwidth the other peer could currently transmit
 * to us (as far as we know) to the given value.
 *
 * @param peer identity of the peer
 * @param bandwidth_in currently available bandwidth from that peer to
 *        this peer (estimate)
 */
void
GAS_reservations_set_bandwidth (const struct GNUNET_PeerIdentity *peer,
                                struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in)
{
  struct GNUNET_BANDWIDTH_Tracker *tracker;

  tracker = GNUNET_CONTAINER_multipeermap_get (trackers, peer);
  if (0 == ntohl (bandwidth_in.value__))
  {
    if (NULL == tracker)
      return;
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multipeermap_remove (trackers,
                                                         peer,
                                                         tracker));
    GNUNET_free (tracker);
    return;
  }
  if (NULL == tracker)
  {
    tracker = GNUNET_new (struct GNUNET_BANDWIDTH_Tracker);
    GNUNET_BANDWIDTH_tracker_init (tracker,
                                   NULL,
                                   NULL,
                                   bandwidth_in,
                                   MAX_BANDWIDTH_CARRY_S);
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multipeermap_put (trackers,
                                                      peer,
                                                      tracker,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
    return;
  }
  GNUNET_BANDWIDTH_tracker_update_quota (tracker,
                                         bandwidth_in);
}


/**
 * Handle 'reservation request' messages from clients.
 *
 * @param cls unused, NULL
 * @param client client that sent the request
 * @param message the request message
 */
void
GAS_handle_reservation_request (void *cls,
                                struct GNUNET_SERVER_Client *client,
                                const struct GNUNET_MessageHeader *message)
{
  const struct ReservationRequestMessage *msg =
      (const struct ReservationRequestMessage *) message;
  struct ReservationResultMessage result;
  int32_t amount;
  struct GNUNET_TIME_Relative res_delay;
  struct GNUNET_SERVER_NotificationContext *nc;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received RESERVATION_REQUEST message\n");
  nc = *GNUNET_SERVER_client_get_user_context (client,
                                               struct GNUNET_SERVER_NotificationContext *);
  if (NULL == nc)
  {
    GNUNET_break (0);
    return;
  }
  amount = (int32_t) ntohl (msg->amount);
  res_delay = reservations_reserve (&msg->peer, amount);
  if (res_delay.rel_value_us > 0)
    amount = 0;
  result.header.size = htons (sizeof (struct ReservationResultMessage));
  result.header.type = htons (GNUNET_MESSAGE_TYPE_ATS_RESERVATION_RESULT);
  result.amount = htonl (amount);
  result.peer = msg->peer;
  result.res_delay = GNUNET_TIME_relative_hton (res_delay);
  GNUNET_STATISTICS_update (GSA_stats,
                            "# reservation requests processed",
                            1,
                            GNUNET_NO);

  GNUNET_SERVER_notification_context_unicast (nc,
                                              client,
                                              &result.header,
                                              GNUNET_NO);
  GNUNET_SERVER_receive_done (client,
                              GNUNET_OK);
}


/**
 * Initialize reservations subsystem.
 *
 * @param server handle to our server
 */
void
GAS_reservations_init (struct GNUNET_SERVER_Handle *server)
{
  trackers = GNUNET_CONTAINER_multipeermap_create (128,
                                                   GNUNET_NO);
}


/**
 * Free memory of bandwidth tracker.
 *
 * @param cls NULL
 * @param key peer identity (unused)
 * @param value the `struct GNUNET_BANDWIDTH_Tracker` to free
 * @return #GNUNET_OK (continue to iterate)
 */
static int
free_tracker (void *cls,
	      const struct GNUNET_PeerIdentity *key, void *value)
{
  struct GNUNET_BANDWIDTH_Tracker *tracker = value;

  GNUNET_free (tracker);
  return GNUNET_OK;
}


/**
 * Shutdown reservations subsystem.
 */
void
GAS_reservations_done ()
{
  GNUNET_CONTAINER_multipeermap_iterate (trackers,
                                         &free_tracker,
                                         NULL);
  GNUNET_CONTAINER_multipeermap_destroy (trackers);
}

/* end of gnunet-service-ats_reservations.c */
