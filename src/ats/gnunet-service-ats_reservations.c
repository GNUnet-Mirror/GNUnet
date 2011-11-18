/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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

/**
 * Number of seconds that available bandwidth carries over
 * (can accumulate).
 */
#define MAX_BANDWIDTH_CARRY_S 5


/**
 * Map of peer identities to 'struct GNUNET_BANDWIDTH_Tracker *'s
 */
static struct GNUNET_CONTAINER_MultiHashMap *trackers;


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
struct GNUNET_TIME_Relative
GAS_reservations_reserve (const struct GNUNET_PeerIdentity *peer,
                          int32_t amount)
{
  struct GNUNET_BANDWIDTH_Tracker *tracker;
  struct GNUNET_TIME_Relative ret;

  tracker = GNUNET_CONTAINER_multihashmap_get (trackers, &peer->hashPubKey);
  if (NULL == tracker)
    return GNUNET_TIME_UNIT_ZERO;       /* not connected, satisfy now */
  if (amount >= 0)
  {
    ret = GNUNET_BANDWIDTH_tracker_get_delay (tracker, amount);
    if (ret.rel_value > 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Delay to satisfy reservation for %d bytes is %llu ms\n",
                  (int) amount, (unsigned long long) ret.rel_value);
      return ret;
    }
  }
  (void) GNUNET_BANDWIDTH_tracker_consume (tracker, amount);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Reserved %d bytes\n", (int) amount);
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

  tracker = GNUNET_CONTAINER_multihashmap_get (trackers, &peer->hashPubKey);
  if (0 == ntohl (bandwidth_in.value__))
  {
    if (NULL == tracker)
      return;
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multihashmap_remove (trackers,
                                                         &peer->hashPubKey,
                                                         tracker));
    GNUNET_free (tracker);
    return;
  }
  if (NULL == tracker)
  {
    tracker = GNUNET_malloc (sizeof (struct GNUNET_BANDWIDTH_Tracker));
    GNUNET_BANDWIDTH_tracker_init (tracker, bandwidth_in,
                                   MAX_BANDWIDTH_CARRY_S);
    GNUNET_CONTAINER_multihashmap_put (trackers, &peer->hashPubKey, tracker,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
    return;
  }
  GNUNET_BANDWIDTH_tracker_update_quota (tracker, bandwidth_in);
}


/**
 * Initialize reservations subsystem.
 */
void
GAS_reservations_init ()
{
  trackers = GNUNET_CONTAINER_multihashmap_create (128);
}


/**
 * Free memory of bandwidth tracker.
 *
 * @param cls NULL
 * @param key peer identity (unused)
 * @param value the 'struct GNUNET_BANDWIDTH_Tracker' to free
 * @return GNUNET_OK (continue to iterate)
 */
static int
free_tracker (void *cls, const GNUNET_HashCode * key, void *value)
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
  GNUNET_CONTAINER_multihashmap_iterate (trackers, &free_tracker, NULL);
  GNUNET_CONTAINER_multihashmap_destroy (trackers);
}

/* end of gnunet-service-ats_reservations.c */
