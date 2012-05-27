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
 * @author Christian Grothoff
 *
 * The purpose of this service is to estimate the size of the network.
 * Given a specified interval, each peer hashes the most recent
 * timestamp which is evenly divisible by that interval.  This hash is
 * compared in distance to the peer identity to choose an offset.  The
 * closer the peer identity to the hashed timestamp, the earlier the
 * peer sends out a "nearest peer" message.  The closest peer's
 * message should thus be received before any others, which stops
 * those peer from sending their messages at a later duration.  So
 * every peer should receive the same nearest peer message, and from
 * this can calculate the expected number of peers in the network.
 */
#include "platform.h"
#include <math.h>
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_signatures.h"
#include "gnunet_statistics_service.h"
#include "gnunet_core_service.h"
#include "gnunet_nse_service.h"
#include "nse.h"

/**
 * Should messages be delayed randomly?  This option should be set to
 * GNUNET_NO only for experiments, not in production.  It should also
 * be removed once the initial experiments have been completed.
 */
#define USE_RANDOM_DELAYS GNUNET_YES

/**
 * Should we generate a histogram with the time stamps of when we received
 * NSE messages to disk? (for performance evaluation only, not useful in
 * production).  The associated code should also probably be removed
 * once we're done with experiments.
 */
#define ENABLE_HISTOGRAM GNUNET_NO

/**
 * Over how many values do we calculate the weighted average?
 */
#define HISTORY_SIZE 64

/**
 * Message priority to use.
 */
#define NSE_PRIORITY 5

#if FREEBSD
#define log2(a) (log(a)/log(2))
#endif

/**
 * Amount of work required (W-bit collisions) for NSE proofs, in collision-bits.
 */
static unsigned long long nse_work_required;

/**
 * Interval for sending network size estimation flood requests.
 */
static struct GNUNET_TIME_Relative gnunet_nse_interval;

/**
 * Interval between proof find runs.
 */
static struct GNUNET_TIME_Relative proof_find_delay;

#if ENABLE_HISTOGRAM
/**
 * Handle for writing when we received messages to disk.
 */
static struct GNUNET_BIO_WriteHandle *wh;
#endif


/**
 * Per-peer information.
 */
struct NSEPeerEntry
{

  /**
   * Core handle for sending messages to this peer.
   */
  struct GNUNET_CORE_TransmitHandle *th;

  /**
   * What is the identity of the peer?
   */
  struct GNUNET_PeerIdentity id;

  /**
   * Task scheduled to send message to this peer.
   */
  GNUNET_SCHEDULER_TaskIdentifier transmit_task;

  /**
   * Did we receive or send a message about the previous round
   * to this peer yet?   GNUNET_YES if the previous round has
   * been taken care of.
   */
  int previous_round;

#if ENABLE_HISTOGRAM

  /**
   * Amount of messages received from this peer on this round.
   */
  unsigned int received_messages;

  /**
   * Amount of messages transmitted to this peer on this round.
   */
  unsigned int transmitted_messages;

  /**
   * Which size did we tell the peer the network is?
   */
  unsigned int last_transmitted_size;

#endif

};


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Network size estimate reply; sent when "this"
 * peer's timer has run out before receiving a
 * valid reply from another peer.
 */
struct GNUNET_NSE_FloodMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_NSE_P2P_FLOOD
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of hops this message has taken so far.
   */
  uint32_t hop_count GNUNET_PACKED;

  /**
   * Purpose.
   */
  struct GNUNET_CRYPTO_RsaSignaturePurpose purpose;

  /**
   * The current timestamp value (which all
   * peers should agree on).
   */
  struct GNUNET_TIME_AbsoluteNBO timestamp;

  /**
   * Number of matching bits between the hash
   * of timestamp and the initiator's public
   * key.
   */
  uint32_t matching_bits GNUNET_PACKED;

  /**
   * Public key of the originator.
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pkey;

  /**
   * Proof of work, causing leading zeros when hashed with pkey.
   */
  uint64_t proof_of_work GNUNET_PACKED;

  /**
   * Signature (over range specified in purpose).
   */
  struct GNUNET_CRYPTO_RsaSignature signature;
};
GNUNET_NETWORK_STRUCT_END

/**
 * Handle to our current configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to the statistics service.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Handle to the core service.
 */
static struct GNUNET_CORE_Handle *coreAPI;

/**
 * Map of all connected peers.
 */
static struct GNUNET_CONTAINER_MultiHashMap *peers;

/**
 * The current network size estimate.  Number of bits matching on
 * average thus far.
 */
static double current_size_estimate;

/**
 * The standard deviation of the last HISTORY_SIZE network
 * size estimates.
 */
static double current_std_dev = NAN;

/**
 * Current hop counter estimate (estimate for network diameter).
 */
static uint32_t hop_count_max;

/**
 * Message for the next round, if we got any.
 */
static struct GNUNET_NSE_FloodMessage next_message;

/**
 * Array of recent size estimate messages.
 */
static struct GNUNET_NSE_FloodMessage size_estimate_messages[HISTORY_SIZE];

/**
 * Index of most recent estimate.
 */
static unsigned int estimate_index;

/**
 * Number of valid entries in the history.
 */
static unsigned int estimate_count;

/**
 * Task scheduled to update our flood message for the next round.
 */
static GNUNET_SCHEDULER_TaskIdentifier flood_task;

/**
 * Task scheduled to compute our proof.
 */
static GNUNET_SCHEDULER_TaskIdentifier proof_task;

/**
 * Notification context, simplifies client broadcasts.
 */
static struct GNUNET_SERVER_NotificationContext *nc;

/**
 * The next major time.
 */
static struct GNUNET_TIME_Absolute next_timestamp;

/**
 * The current major time.
 */
static struct GNUNET_TIME_Absolute current_timestamp;

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
 * Proof of work for this peer.
 */
static uint64_t my_proof;


/**
 * Initialize a message to clients with the current network
 * size estimate.
 *
 * @param em message to fill in
 */
static void
setup_estimate_message (struct GNUNET_NSE_ClientMessage *em)
{
  unsigned int i;
  unsigned int j;
  double mean;
  double sum;
  double std_dev;
  double variance;
  double val;
  double nsize;

#define WEST 1
  /* Weighted incremental algorithm for stddev according to West (1979) */
#if WEST
  double sumweight;
  double weight;
  double q;
  double r;
  double temp;

  mean = 0.0;
  sum = 0.0;
  sumweight = 0.0;
  variance = 0.0;
  for (i = 0; i < estimate_count; i++)
  {
    j = (estimate_index - i + HISTORY_SIZE) % HISTORY_SIZE;
    val = htonl (size_estimate_messages[j].matching_bits);
    weight = estimate_count + 1 - i;

    temp = weight + sumweight;
    q = val - mean;
    r = q * weight / temp;
    mean += r;
    sum += sumweight * q * r;
    sumweight = temp;
  }
  if (estimate_count > 0)
    variance = (sum / sumweight) * estimate_count / (estimate_count - 1.0);
#else
  /* trivial version for debugging */
  double vsq;

  /* non-weighted trivial version */
  sum = 0.0;
  vsq = 0.0;
  variance = 0.0;
  mean = 0.0;

  for (i = 0; i < estimate_count; i++)
  {
    j = (estimate_index - i + HISTORY_SIZE) % HISTORY_SIZE;
    val = htonl (size_estimate_messages[j].matching_bits);
    sum += val;
    vsq += val * val;
  }
  if (0 != estimate_count)
  {
    mean = sum / estimate_count;
    variance = (vsq - mean * sum) / (estimate_count - 1.0);     // terrible for numerical stability...
  }
#endif
  if (variance >= 0)
    std_dev = sqrt (variance);
  else
    std_dev = variance;         /* must be infinity due to estimate_count == 0 */
  current_std_dev = std_dev;
  current_size_estimate = mean;

  em->header.size = htons (sizeof (struct GNUNET_NSE_ClientMessage));
  em->header.type = htons (GNUNET_MESSAGE_TYPE_NSE_ESTIMATE);
  em->reserved = htonl (0);
  em->timestamp = GNUNET_TIME_absolute_hton (GNUNET_TIME_absolute_get ());
  double se = mean - 0.332747;
  nsize = log2 (GNUNET_CONTAINER_multihashmap_size (peers) + 1);
  em->size_estimate = GNUNET_hton_double (GNUNET_MAX (se, nsize));
  em->std_deviation = GNUNET_hton_double (std_dev);
  GNUNET_STATISTICS_set (stats, "# nodes in the network (estimate)",
                         (uint64_t) pow (2, mean - 1.0 / 3.0), GNUNET_NO);
}


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
handle_start_message (void *cls, struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_NSE_ClientMessage em;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received START message from client\n");
  GNUNET_SERVER_notification_context_add (nc, client);
  setup_estimate_message (&em);
  GNUNET_SERVER_notification_context_unicast (nc, client, &em.header,
                                              GNUNET_YES);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * How long should we delay a message to go the given number of
 * matching bits?
 *
 * @param matching_bits number of matching bits to consider
 */
static double
get_matching_bits_delay (uint32_t matching_bits)
{
  /* Calculated as: S + f/2 - (f / pi) * (atan(x - p')) */
  // S is next_timestamp (ignored in return value)
  // f is frequency (gnunet_nse_interval)
  // x is matching_bits
  // p' is current_size_estimate
  return ((double) gnunet_nse_interval.rel_value / (double) 2.0) -
      ((gnunet_nse_interval.rel_value / M_PI) *
       atan (matching_bits - current_size_estimate));
}


/**
 * What delay randomization should we apply for a given number of matching bits?
 *
 * @param matching_bits number of matching bits
 * @return random delay to apply
 */
static struct GNUNET_TIME_Relative
get_delay_randomization (uint32_t matching_bits)
{
#if USE_RANDOM_DELAYS
  struct GNUNET_TIME_Relative ret;
  uint32_t i;
  double d;

  d = get_matching_bits_delay (matching_bits);
  i = (uint32_t) (d / (double) (hop_count_max + 1));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Randomizing flood using latencies up to %u ms\n",
	      (unsigned int) i);
  ret.rel_value = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, i + 1);
  return ret;
#else
  return GNUNET_TIME_UNIT_ZERO;
#endif
}


/**
 * Get the number of matching bits that the given timestamp has to the given peer ID.
 *
 * @param timestamp time to generate key
 * @param id peer identity to compare with
 * @return number of matching bits
 */
static uint32_t
get_matching_bits (struct GNUNET_TIME_Absolute timestamp,
                   const struct GNUNET_PeerIdentity *id)
{
  GNUNET_HashCode timestamp_hash;

  GNUNET_CRYPTO_hash (&timestamp.abs_value, sizeof (timestamp.abs_value),
                      &timestamp_hash);
  return GNUNET_CRYPTO_hash_matching_bits (&timestamp_hash, &id->hashPubKey);
}


/**
 * Get the transmission delay that should be applied for a
 * particular round.
 *
 * @param round_offset -1 for the previous round (random delay between 0 and 50ms)
 *                      0 for the current round (based on our proximity to time key)
 * @return delay that should be applied
 */
static struct GNUNET_TIME_Relative
get_transmit_delay (int round_offset)
{
  struct GNUNET_TIME_Relative ret;
  struct GNUNET_TIME_Absolute tgt;
  double dist_delay;
  uint32_t matching_bits;

  switch (round_offset)
  {
  case -1:
    /* previous round is randomized between 0 and 50 ms */
#if USE_RANDOM_DELAYS
    ret.rel_value = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK, 50);
#else
    ret = GNUNET_TIME_UNIT_ZERO;
#endif
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Transmitting previous round behind schedule in %llu ms\n",
                (unsigned long long) ret.rel_value);
    return ret;
  case 0:
    /* current round is based on best-known matching_bits */
    matching_bits =
        ntohl (size_estimate_messages[estimate_index].matching_bits);
    dist_delay = get_matching_bits_delay (matching_bits);
    dist_delay += get_delay_randomization (matching_bits).rel_value;
    ret.rel_value = (uint64_t) dist_delay;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "For round %llu, delay for %u matching bits is %llu ms\n",
                (unsigned long long) current_timestamp.abs_value,
                (unsigned int) matching_bits,
                (unsigned long long) ret.rel_value);
    /* now consider round start time and add delay to it */
    tgt = GNUNET_TIME_absolute_add (current_timestamp, ret);
    return GNUNET_TIME_absolute_get_remaining (tgt);
  }
  GNUNET_break (0);
  return GNUNET_TIME_UNIT_FOREVER_REL;
}


/**
 * Task that triggers a NSE P2P transmission.
 *
 * @param cls the 'struct NSEPeerEntry'
 * @param tc scheduler context
 */
static void
transmit_task_cb (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


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
  unsigned int idx;

  peer_entry->th = NULL;
  if (NULL == buf)
  {
    /* client disconnected */
    return 0;
  }
  GNUNET_assert (size >= sizeof (struct GNUNET_NSE_FloodMessage));
  idx = estimate_index;
  if (GNUNET_NO == peer_entry->previous_round)
  {
    idx = (idx + HISTORY_SIZE - 1) % HISTORY_SIZE;
    peer_entry->previous_round = GNUNET_YES;
    peer_entry->transmit_task =
        GNUNET_SCHEDULER_add_delayed (get_transmit_delay (0), &transmit_task_cb,
                                      peer_entry);
  }
  if ((ntohl (size_estimate_messages[idx].hop_count) == 0) &&
      (GNUNET_SCHEDULER_NO_TASK != proof_task))
  {
    GNUNET_STATISTICS_update (stats,
                              "# flood messages not generated (no proof yet)",
                              1, GNUNET_NO);
    return 0;
  }
  if (ntohs (size_estimate_messages[idx].header.size) == 0)
  {
    GNUNET_STATISTICS_update (stats,
                              "# flood messages not generated (lack of history)",
                              1, GNUNET_NO);
    return 0;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "In round %llu, sending to `%s' estimate with %u bits\n",
              (unsigned long long)
              GNUNET_TIME_absolute_ntoh (size_estimate_messages[idx].
                                         timestamp).abs_value,
              GNUNET_i2s (&peer_entry->id),
              (unsigned int) ntohl (size_estimate_messages[idx].matching_bits));
  if (ntohl (size_estimate_messages[idx].hop_count) == 0)
    GNUNET_STATISTICS_update (stats, "# flood messages started", 1, GNUNET_NO);
  GNUNET_STATISTICS_update (stats, "# flood messages transmitted", 1,
                            GNUNET_NO);
#if ENABLE_HISTOGRAM
  peer_entry->transmitted_messages++;
  peer_entry->last_transmitted_size = 
      ntohl(size_estimate_messages[idx].matching_bits);
#endif
  memcpy (buf, &size_estimate_messages[idx],
          sizeof (struct GNUNET_NSE_FloodMessage));
  return sizeof (struct GNUNET_NSE_FloodMessage);
}


/**
 * Task that triggers a NSE P2P transmission.
 *
 * @param cls the 'struct NSEPeerEntry'
 * @param tc scheduler context
 */
static void
transmit_task_cb (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct NSEPeerEntry *peer_entry = cls;

  peer_entry->transmit_task = GNUNET_SCHEDULER_NO_TASK;

  GNUNET_assert (NULL == peer_entry->th);
  peer_entry->th =
      GNUNET_CORE_notify_transmit_ready (coreAPI, GNUNET_NO, NSE_PRIORITY,
                                         GNUNET_TIME_UNIT_FOREVER_REL,
                                         &peer_entry->id,
                                         sizeof (struct
                                                 GNUNET_NSE_FloodMessage),
                                         &transmit_ready, peer_entry);
}


/**
 * We've sent on our flood message or one that we received which was
 * validated and closer than ours.  Update the global list of recent
 * messages and the average.  Also re-broadcast the message to any
 * clients.
 */
static void
update_network_size_estimate ()
{
  struct GNUNET_NSE_ClientMessage em;

  setup_estimate_message (&em);
  GNUNET_SERVER_notification_context_broadcast (nc, &em.header, GNUNET_YES);
}


/**
 * Setup a flood message in our history array at the given
 * slot offset for the given timestamp.
 *
 * @param slot index to use
 * @param ts timestamp to use
 */
static void
setup_flood_message (unsigned int slot, struct GNUNET_TIME_Absolute ts)
{
  struct GNUNET_NSE_FloodMessage *fm;
  uint32_t matching_bits;

  matching_bits = get_matching_bits (ts, &my_identity);
  fm = &size_estimate_messages[slot];
  fm->header.size = htons (sizeof (struct GNUNET_NSE_FloodMessage));
  fm->header.type = htons (GNUNET_MESSAGE_TYPE_NSE_P2P_FLOOD);
  fm->hop_count = htonl (0);
  fm->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_NSE_SEND);
  fm->purpose.size =
      htonl (sizeof (struct GNUNET_NSE_FloodMessage) -
             sizeof (struct GNUNET_MessageHeader) - sizeof (uint32_t) -
             sizeof (struct GNUNET_CRYPTO_RsaSignature));
  fm->matching_bits = htonl (matching_bits);
  fm->timestamp = GNUNET_TIME_absolute_hton (ts);
  fm->pkey = my_public_key;
  fm->proof_of_work = my_proof;
  if (nse_work_required > 0)
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CRYPTO_rsa_sign (my_private_key, &fm->purpose,
                                           &fm->signature));
  else
    memset (&fm->signature, 0, sizeof (fm->signature));
}


/**
 * Schedule transmission for the given peer for the current round based
 * on what we know about the desired delay.
 *
 * @param cls unused
 * @param key hash of peer identity
 * @param value the 'struct NSEPeerEntry'
 * @return GNUNET_OK (continue to iterate)
 */
static int
schedule_current_round (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct NSEPeerEntry *peer_entry = value;
  struct GNUNET_TIME_Relative delay;

  if (NULL != peer_entry->th)
  {
    peer_entry->previous_round = GNUNET_NO;
    return GNUNET_OK;
  }
  if (GNUNET_SCHEDULER_NO_TASK != peer_entry->transmit_task)
  {
    GNUNET_SCHEDULER_cancel (peer_entry->transmit_task);
    peer_entry->previous_round = GNUNET_NO;
  }
#if ENABLE_HISTOGRAM
  if (peer_entry->received_messages > 1)
    GNUNET_STATISTICS_update(stats, "# extra messages",
                             peer_entry->received_messages - 1, GNUNET_NO);
  peer_entry->transmitted_messages = 0;
  peer_entry->last_transmitted_size = 0;
  peer_entry->received_messages = 0;
#endif
  delay =
      get_transmit_delay ((peer_entry->previous_round == GNUNET_NO) ? -1 : 0);
  peer_entry->transmit_task =
      GNUNET_SCHEDULER_add_delayed (delay, &transmit_task_cb, peer_entry);
  return GNUNET_OK;
}


/**
 * Update our flood message to be sent (and our timestamps).
 *
 * @param cls unused
 * @param tc context for this message
 */
static void
update_flood_message (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TIME_Relative offset;
  unsigned int i;

  flood_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  offset = GNUNET_TIME_absolute_get_remaining (next_timestamp);
  if (0 != offset.rel_value)
  {
    /* somehow run early, delay more */
    flood_task =
        GNUNET_SCHEDULER_add_delayed (offset, &update_flood_message, NULL);
    return;
  }
  estimate_index = (estimate_index + 1) % HISTORY_SIZE;
  if (estimate_count < HISTORY_SIZE)
    estimate_count++;
  current_timestamp = next_timestamp;
  next_timestamp =
      GNUNET_TIME_absolute_add (current_timestamp, gnunet_nse_interval);
  if ((current_timestamp.abs_value ==
      GNUNET_TIME_absolute_ntoh (next_message.timestamp).abs_value) &&
      (get_matching_bits (current_timestamp, &my_identity) <
      ntohl(next_message.matching_bits)))
  {
    /* we received a message for this round way early, use it! */
    size_estimate_messages[estimate_index] = next_message;
    size_estimate_messages[estimate_index].hop_count =
        htonl (1 + ntohl (next_message.hop_count));
  }
  else
    setup_flood_message (estimate_index, current_timestamp);
  next_message.matching_bits = htonl (0);       /* reset for 'next' round */
  hop_count_max = 0;
  for (i = 0; i < HISTORY_SIZE; i++)
    hop_count_max =
        GNUNET_MAX (ntohl (size_estimate_messages[i].hop_count), hop_count_max);
  GNUNET_CONTAINER_multihashmap_iterate (peers, &schedule_current_round, NULL);
  flood_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_absolute_get_remaining
                                    (next_timestamp), &update_flood_message,
                                    NULL);
}


/**
 * Count the leading zeroes in hash.
 *
 * @param hash
 * @return the number of leading zero bits.
 */
static unsigned int
count_leading_zeroes (const GNUNET_HashCode * hash)
{
  unsigned int hash_count;

  hash_count = 0;
  while ((0 == GNUNET_CRYPTO_hash_get_bit (hash, hash_count)))
    hash_count++;
  return hash_count;
}


/**
 * Check whether the given public key
 * and integer are a valid proof of work.
 *
 * @param pkey the public key
 * @param val the integer
 *
 * @return GNUNET_YES if valid, GNUNET_NO if not
 */
static int
check_proof_of_work (const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *pkey,
                     uint64_t val)
{
  char buf[sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded) +
           sizeof (val)] GNUNET_ALIGN;
  GNUNET_HashCode result;

  memcpy (buf, &val, sizeof (val));
  memcpy (&buf[sizeof (val)], pkey,
          sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));
  GNUNET_CRYPTO_hash (buf, sizeof (buf), &result);
  return (count_leading_zeroes (&result) >=
          nse_work_required) ? GNUNET_YES : GNUNET_NO;
}


/**
 * Write our current proof to disk.
 */
static void
write_proof ()
{
  char *proof;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg, "NSE", "PROOFFILE", &proof))
    return;
  if (sizeof (my_proof) !=
      GNUNET_DISK_fn_write (proof, &my_proof, sizeof (my_proof),
                            GNUNET_DISK_PERM_USER_READ |
                            GNUNET_DISK_PERM_USER_WRITE))
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "write", proof);
  GNUNET_free (proof);

}


/**
 * Find our proof of work.
 *
 * @param cls closure (unused)
 * @param tc task context
 */
static void
find_proof (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
#define ROUND_SIZE 10
  uint64_t counter;
  char buf[sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded) +
           sizeof (uint64_t)] GNUNET_ALIGN;
  GNUNET_HashCode result;
  unsigned int i;

  proof_task = GNUNET_SCHEDULER_NO_TASK;
  memcpy (&buf[sizeof (uint64_t)], &my_public_key,
          sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));
  i = 0;
  counter = my_proof;
  while ((counter != UINT64_MAX) && (i < ROUND_SIZE))
  {
    memcpy (buf, &counter, sizeof (uint64_t));
    GNUNET_CRYPTO_hash (buf, sizeof (buf), &result);
    if (nse_work_required <= count_leading_zeroes (&result))
    {
      my_proof = counter;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Proof of work found: %llu!\n",
                  (unsigned long long) GNUNET_ntohll (counter));
      write_proof ();
      setup_flood_message (estimate_index, current_timestamp);
      return;
    }
    counter++;
    i++;
  }
  if (my_proof / (100 * ROUND_SIZE) < counter / (100 * ROUND_SIZE))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Testing proofs currently at %llu\n",
                (unsigned long long) counter);
    /* remember progress every 100 rounds */
    my_proof = counter;
    write_proof ();
  }
  else
  {
    my_proof = counter;
  }
  proof_task =
      GNUNET_SCHEDULER_add_delayed_with_priority (proof_find_delay,
						  GNUNET_SCHEDULER_PRIORITY_IDLE,
						  &find_proof, NULL);
}


/**
 * An incoming flood message has been received which claims
 * to have more bits matching than any we know in this time
 * period.  Verify the signature and/or proof of work.
 *
 * @param incoming_flood the message to verify
 *
 * @return GNUNET_YES if the message is verified
 *         GNUNET_NO if the key/signature don't verify
 */
static int
verify_message_crypto (const struct GNUNET_NSE_FloodMessage *incoming_flood)
{
  if (GNUNET_YES !=
      check_proof_of_work (&incoming_flood->pkey,
                           incoming_flood->proof_of_work))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Proof of work invalid: %llu!\n"),
                (unsigned long long)
                GNUNET_ntohll (incoming_flood->proof_of_work));
    GNUNET_break_op (0);
    return GNUNET_NO;
  }
  if ((nse_work_required > 0) &&
      (GNUNET_OK !=
       GNUNET_CRYPTO_rsa_verify (GNUNET_SIGNATURE_PURPOSE_NSE_SEND,
                                 &incoming_flood->purpose,
                                 &incoming_flood->signature,
                                 &incoming_flood->pkey)))
  {
    GNUNET_break_op (0);
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Update transmissions for the given peer for the current round based
 * on updated proximity information.
 *
 * @param cls peer entry to exclude from updates
 * @param key hash of peer identity
 * @param value the 'struct NSEPeerEntry'
 * @return GNUNET_OK (continue to iterate)
 */
static int
update_flood_times (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct NSEPeerEntry *exclude = cls;
  struct NSEPeerEntry *peer_entry = value;
  struct GNUNET_TIME_Relative delay;

  if (peer_entry->th != NULL)
    return GNUNET_OK;           /* already active */
  if (peer_entry == exclude)
    return GNUNET_OK;           /* trigger of the update */
  if (peer_entry->previous_round == GNUNET_NO)
  {
    /* still stuck in previous round, no point to update, check that
     * we are active here though... */
    if (GNUNET_SCHEDULER_NO_TASK == peer_entry->transmit_task &&
        NULL == peer_entry->th)
    {
        GNUNET_break (0);
    }
    return GNUNET_OK;
  }
  if (peer_entry->transmit_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (peer_entry->transmit_task);
    peer_entry->transmit_task = GNUNET_SCHEDULER_NO_TASK;
  }
  delay = get_transmit_delay (0);
  peer_entry->transmit_task =
      GNUNET_SCHEDULER_add_delayed (delay, &transmit_task_cb, peer_entry);
  return GNUNET_OK;
}


/**
 * Core handler for size estimate flooding messages.
 *
 * @param cls closure unused
 * @param message message
 * @param peer peer identity this message is from (ignored)
 * @param atsi performance data (ignored)
 * @param atsi_count number of records in 'atsi'
 */
static int
handle_p2p_size_estimate (void *cls, const struct GNUNET_PeerIdentity *peer,
                          const struct GNUNET_MessageHeader *message,
                          const struct GNUNET_ATS_Information *atsi,
                          unsigned int atsi_count)
{
  const struct GNUNET_NSE_FloodMessage *incoming_flood;
  struct GNUNET_TIME_Absolute ts;
  struct NSEPeerEntry *peer_entry;
  uint32_t matching_bits;
  unsigned int idx;

#if ENABLE_HISTOGRAM
  if (NULL != wh)
    GNUNET_break (GNUNET_OK == GNUNET_BIO_write_int64 (wh, GNUNET_TIME_absolute_get ().abs_value));
#endif
  incoming_flood = (const struct GNUNET_NSE_FloodMessage *) message;
  GNUNET_STATISTICS_update (stats, "# flood messages received", 1, GNUNET_NO);
  matching_bits = ntohl (incoming_flood->matching_bits);
#if DEBUG_NSE
  {
    char origin[5];
    char pred[5];
    struct GNUNET_PeerIdentity os;

    GNUNET_CRYPTO_hash (&incoming_flood->pkey,
                        sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                        &os.hashPubKey);
    GNUNET_snprintf (origin, sizeof (origin), "%s", GNUNET_i2s (&os));
    GNUNET_snprintf (pred, sizeof (pred), "%s", GNUNET_i2s (peer));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Flood at %llu from `%s' via `%s' at `%s' with bits %u\n",
                (unsigned long long)
                GNUNET_TIME_absolute_ntoh (incoming_flood->timestamp).abs_value,
                origin, pred, GNUNET_i2s (&my_identity),
                (unsigned int) matching_bits);
  }
#endif

  peer_entry = GNUNET_CONTAINER_multihashmap_get (peers, &peer->hashPubKey);
  if (NULL == peer_entry)
  {
    GNUNET_break (0);
    return GNUNET_OK;
  }
#if ENABLE_HISTOGRAM
  peer_entry->received_messages++;
  if (peer_entry->transmitted_messages > 0 && 
      peer_entry->last_transmitted_size >= matching_bits)
    GNUNET_STATISTICS_update(stats, "# cross messages", 1, GNUNET_NO);
#endif

  ts = GNUNET_TIME_absolute_ntoh (incoming_flood->timestamp);
  if (ts.abs_value == current_timestamp.abs_value)
    idx = estimate_index;
  else if (ts.abs_value ==
           current_timestamp.abs_value - gnunet_nse_interval.rel_value)
    idx = (estimate_index + HISTORY_SIZE - 1) % HISTORY_SIZE;
  else if (ts.abs_value == next_timestamp.abs_value)
  {
    if (matching_bits <= ntohl (next_message.matching_bits))
      return GNUNET_OK;         /* ignore, simply too early/late */
    if (GNUNET_YES != verify_message_crypto (incoming_flood))
    {
      GNUNET_break_op (0);
      return GNUNET_OK;
    }
    next_message = *incoming_flood;
    return GNUNET_OK;
  }
  else
  {
    GNUNET_STATISTICS_update (stats,
                              "# flood messages discarded (clock skew too large)",
                              1, GNUNET_NO);
    return GNUNET_OK;
  }
  if (0 == (memcmp (peer, &my_identity, sizeof (struct GNUNET_PeerIdentity))))
  {
    /* send to self, update our own estimate IF this also comes from us! */
    if (0 ==
        memcmp (&incoming_flood->pkey, &my_public_key, sizeof (my_public_key)))
      update_network_size_estimate ();
    return GNUNET_OK;
  }
  if (matching_bits == ntohl (size_estimate_messages[idx].matching_bits))
  {
    /* Cancel transmission in the other direction, as this peer clearly has
       up-to-date information already. Even if we didn't talk to this peer in
       the previous round, we should no longer send it stale information as it
       told us about the current round! */
    peer_entry->previous_round = GNUNET_YES;
    if (idx != estimate_index)
    {
      /* do not transmit information for the previous round to this peer 
         anymore (but allow current round) */
      return GNUNET_OK;
    }
    /* got up-to-date information for current round, cancel transmission to
     * this peer altogether */
    if (GNUNET_SCHEDULER_NO_TASK != peer_entry->transmit_task)
    {
      GNUNET_SCHEDULER_cancel (peer_entry->transmit_task);
      peer_entry->transmit_task = GNUNET_SCHEDULER_NO_TASK;
    }
    if (peer_entry->th != NULL)
    {
      GNUNET_CORE_notify_transmit_ready_cancel (peer_entry->th);
      peer_entry->th = NULL;
    }
    return GNUNET_OK;
  }
  if (matching_bits < ntohl (size_estimate_messages[idx].matching_bits))
  {
    if ((idx < estimate_index) && (peer_entry->previous_round == GNUNET_YES)) {
      peer_entry->previous_round = GNUNET_NO;
    }
    /* push back our result now, that peer is spreading bad information... */
    if (NULL == peer_entry->th)
    {
      if (peer_entry->transmit_task != GNUNET_SCHEDULER_NO_TASK)
        GNUNET_SCHEDULER_cancel (peer_entry->transmit_task);
      peer_entry->transmit_task =
          GNUNET_SCHEDULER_add_now (&transmit_task_cb, peer_entry);
    }
    /* Not closer than our most recent message, no need to do work here */
    GNUNET_STATISTICS_update (stats,
                              "# flood messages ignored (had closer already)",
                              1, GNUNET_NO);
    return GNUNET_OK;
  }
  if (GNUNET_YES != verify_message_crypto (incoming_flood))
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  GNUNET_assert (matching_bits >
                 ntohl (size_estimate_messages[idx].matching_bits));
  /* Cancel transmission in the other direction, as this peer clearly has
   * up-to-date information already.
   */
  peer_entry->previous_round = GNUNET_YES;
  if (idx == estimate_index)
  {
      /* cancel any activity for current round */
      if (peer_entry->transmit_task != GNUNET_SCHEDULER_NO_TASK)
      {
        GNUNET_SCHEDULER_cancel (peer_entry->transmit_task);
        peer_entry->transmit_task = GNUNET_SCHEDULER_NO_TASK;
      }
      if (peer_entry->th != NULL)
      {
        GNUNET_CORE_notify_transmit_ready_cancel (peer_entry->th);
        peer_entry->th = NULL;
      }
  }
  size_estimate_messages[idx] = *incoming_flood;
  size_estimate_messages[idx].hop_count =
      htonl (ntohl (incoming_flood->hop_count) + 1);
  hop_count_max =
      GNUNET_MAX (ntohl (incoming_flood->hop_count) + 1, hop_count_max);
  GNUNET_STATISTICS_set (stats,
			 "# estimated network diameter",
			 hop_count_max, GNUNET_NO);

  /* have a new, better size estimate, inform clients */
  update_network_size_estimate ();

  /* flood to rest */
  GNUNET_CONTAINER_multihashmap_iterate (peers, &update_flood_times,
                                         peer_entry);
  return GNUNET_OK;
}



/**
 * Method called whenever a peer connects. Sets up the PeerEntry and
 * schedules the initial size info transmission to this peer.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param atsi performance data
 * @param atsi_count number of records in 'atsi'
 */
static void
handle_core_connect (void *cls, const struct GNUNET_PeerIdentity *peer,
                     const struct GNUNET_ATS_Information *atsi,
                     unsigned int atsi_count)
{
  struct NSEPeerEntry *peer_entry;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer `%s' connected to us\n",
              GNUNET_i2s (peer));
  peer_entry = GNUNET_malloc (sizeof (struct NSEPeerEntry));
  peer_entry->id = *peer;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap_put (peers, &peer->hashPubKey,
                                                    peer_entry,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  peer_entry->transmit_task =
      GNUNET_SCHEDULER_add_delayed (get_transmit_delay (-1), &transmit_task_cb,
                                    peer_entry);
  GNUNET_STATISTICS_update (stats, "# peers connected", 1, GNUNET_NO);
}


/**
 * Method called whenever a peer disconnects. Deletes the PeerEntry and cancels
 * any pending transmission requests to that peer.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
handle_core_disconnect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct NSEPeerEntry *pos;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer `%s' disconnected from us\n",
              GNUNET_i2s (peer));
  pos = GNUNET_CONTAINER_multihashmap_get (peers, &peer->hashPubKey);
  if (NULL == pos)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (peers, &peer->hashPubKey,
                                                       pos));
  if (pos->transmit_task != GNUNET_SCHEDULER_NO_TASK) {
    GNUNET_SCHEDULER_cancel (pos->transmit_task);
    pos->transmit_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (pos->th != NULL)
  {
    GNUNET_CORE_notify_transmit_ready_cancel (pos->th);
    pos->th = NULL;
  }
  GNUNET_free (pos);
  GNUNET_STATISTICS_update (stats, "# peers connected", -1, GNUNET_NO);
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
  if (flood_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (flood_task);
    flood_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (proof_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (proof_task);
    proof_task = GNUNET_SCHEDULER_NO_TASK;
    write_proof ();             /* remember progress */
  }
  if (nc != NULL)
  {
    GNUNET_SERVER_notification_context_destroy (nc);
    nc = NULL;
  }
  if (coreAPI != NULL)
  {
    GNUNET_CORE_disconnect (coreAPI);
    coreAPI = NULL;
  }
  if (stats != NULL)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
    stats = NULL;
  }
  if (peers != NULL)
  {
    GNUNET_CONTAINER_multihashmap_destroy (peers);
    peers = NULL;
  }
  if (my_private_key != NULL)
  {
    GNUNET_CRYPTO_rsa_key_free (my_private_key);
    my_private_key = NULL;
  }
#if ENABLE_HISTOGRAM
  if (wh != NULL)
  {
    GNUNET_break (GNUNET_OK == GNUNET_BIO_write_close (wh));
    wh = NULL;
  }
#endif
}


/**
 * Called on core init/fail.
 *
 * @param cls service closure
 * @param server handle to the server for this service
 * @param identity the public identity of this peer
 */
static void
core_init (void *cls, struct GNUNET_CORE_Handle *server,
           const struct GNUNET_PeerIdentity *identity)
{
  struct GNUNET_TIME_Absolute now;
  struct GNUNET_TIME_Absolute prev_time;

  if (NULL == server)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Connection to core FAILED!\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_assert (0 ==
                 memcmp (&my_identity, identity,
                         sizeof (struct GNUNET_PeerIdentity)));
  now = GNUNET_TIME_absolute_get ();
  current_timestamp.abs_value =
      (now.abs_value / gnunet_nse_interval.rel_value) *
      gnunet_nse_interval.rel_value;
  next_timestamp =
      GNUNET_TIME_absolute_add (current_timestamp, gnunet_nse_interval);
  estimate_index = HISTORY_SIZE - 1;
  estimate_count = 0;
  if (GNUNET_YES == check_proof_of_work (&my_public_key, my_proof))
  {
    int idx = (estimate_index + HISTORY_SIZE - 1) % HISTORY_SIZE;
    prev_time.abs_value =
        current_timestamp.abs_value - gnunet_nse_interval.rel_value;
    setup_flood_message (idx, prev_time);
    setup_flood_message (estimate_index, current_timestamp);
    estimate_count++;
  }
  flood_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_absolute_get_remaining
                                    (next_timestamp), &update_flood_message,
                                    NULL);
}


/**
 * Handle network size estimate clients.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  char *keyfile;
  char *proof;

  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_start_message, NULL, GNUNET_MESSAGE_TYPE_NSE_START,
     sizeof (struct GNUNET_MessageHeader)},
    {NULL, NULL, 0, 0}
  };
  static const struct GNUNET_CORE_MessageHandler core_handlers[] = {
    {&handle_p2p_size_estimate, GNUNET_MESSAGE_TYPE_NSE_P2P_FLOOD,
     sizeof (struct GNUNET_NSE_FloodMessage)},
    {NULL, 0, 0}
  };
  cfg = c;

  if ((GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_time (cfg, "NSE", "INTERVAL",
                                            &gnunet_nse_interval)) ||
      (GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_time (cfg, "NSE", "WORKDELAY",
                                            &proof_find_delay)) ||
      (GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_number (cfg, "NSE", "WORKBITS",
                                              &nse_work_required)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _
                ("NSE service is lacking key configuration settings.  Exiting.\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (nse_work_required >= sizeof (GNUNET_HashCode) * 8)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Invalid work requirement for NSE service. Exiting.\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }


  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg, "GNUNETD", "HOSTKEY",
                                               &keyfile))
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
                _("NSE service could not access hostkey.  Exiting.\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_CRYPTO_rsa_key_get_public (my_private_key, &my_public_key);
  GNUNET_CRYPTO_hash (&my_public_key, sizeof (my_public_key),
                      &my_identity.hashPubKey);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg, "NSE", "PROOFFILE", &proof))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _
                ("NSE service is lacking key configuration settings.  Exiting.\n"));
    if (my_private_key != NULL)
    {
      GNUNET_CRYPTO_rsa_key_free (my_private_key);
      my_private_key = NULL;
    }
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if ((GNUNET_YES != GNUNET_DISK_file_test (proof)) ||
      (sizeof (my_proof) !=
       GNUNET_DISK_fn_read (proof, &my_proof, sizeof (my_proof))))
    my_proof = 0;
  GNUNET_free (proof);
  proof_task =
      GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_IDLE,
                                          &find_proof, NULL);

  peers = GNUNET_CONTAINER_multihashmap_create (128);
  GNUNET_SERVER_add_handlers (server, handlers);
  nc = GNUNET_SERVER_notification_context_create (server, 1);
  /* Connect to core service and register core handlers */
  coreAPI = GNUNET_CORE_connect (cfg,   /* Main configuration */
                                 1, NULL,       /* Closure passed to functions */
                                 &core_init,    /* Call core_init once connected */
                                 &handle_core_connect,  /* Handle connects */
                                 &handle_core_disconnect,       /* Handle disconnects */
                                 NULL,  /* Don't want notified about all incoming messages */
                                 GNUNET_NO,     /* For header only inbound notification */
                                 NULL,  /* Don't want notified about all outbound messages */
                                 GNUNET_NO,     /* For header only outbound notification */
                                 core_handlers);        /* Register these handlers */
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);
#if ENABLE_HISTOGRAM
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_filename (cfg, "NSE", "HISTOGRAM", &proof))
  {
    wh = GNUNET_BIO_write_open (proof);
    GNUNET_free (proof);
  }
#endif
  if (coreAPI == NULL)
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  stats = GNUNET_STATISTICS_create ("nse", cfg);
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
          GNUNET_SERVICE_run (argc, argv, "nse", GNUNET_SERVICE_OPTION_NONE,
                              &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-nse.c */
