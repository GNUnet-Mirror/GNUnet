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
 * @file dht/gnunet-service-dht.c
 * @brief GNUnet DHT service
 * @author Christian Grothoff
 * @author Nathan Evans
 *
 * TODO:
 * - use OPTION_MULTIPLE instead of linked list for the forward_list.hashmap
 * - use different 'struct DHT_MessageContext' for the different types of
 *   messages (currently rather confusing, especially with things like
 *   peer bloom filters occuring when processing replies).
 */

#include "platform.h"
#include "gnunet_block_lib.h"
#include "gnunet_client_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_service_lib.h"
#include "gnunet_nse_service.h"
#include "gnunet_core_service.h"
#include "gnunet_signal_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_datacache_lib.h"
#include "gnunet_transport_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_statistics_service.h"
#include "dht.h"
#include <fenv.h>


/**
 * Defines whether find peer requests send their HELLO's outgoing,
 * or expect replies to contain hellos.
 */
#define FIND_PEER_WITH_HELLO GNUNET_YES

#define DEFAULT_CORE_QUEUE_SIZE 32

/**
 * Minimum number of peers we need for "good" routing,
 * any less than this and we will allow messages to
 * travel much further through the network!
 */
#define MINIMUM_PEER_THRESHOLD 20

/**
 * How long do we wait at most when queueing messages with core
 * that we are sending on behalf of other peers.
 */
#define DHT_DEFAULT_P2P_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

/**
 * Default importance for handling messages on behalf of other peers.
 */
#define DHT_DEFAULT_P2P_IMPORTANCE 0

/**
 * How long to keep recent requests around by default.
 */
#define DEFAULT_RECENT_REMOVAL GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)

/**
 * Default time to wait to send find peer messages sent by the dht service.
 */
#define DHT_DEFAULT_FIND_PEER_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

/**
 * Default importance for find peer messages sent by the dht service.
 */
#define DHT_DEFAULT_FIND_PEER_IMPORTANCE 8

/**
 * Default replication parameter for find peer messages sent by the dht service.
 */
#define DHT_DEFAULT_FIND_PEER_REPLICATION 4

/**
 * How long at least to wait before sending another find peer request.
 */
#define DHT_MINIMUM_FIND_PEER_INTERVAL GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 2)

/**
 * How long at most to wait before sending another find peer request.
 */
#define DHT_MAXIMUM_FIND_PEER_INTERVAL GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 8)

/**
 * How often to update our preference levels for peers in our routing tables.
 */
#define DHT_DEFAULT_PREFERENCE_INTERVAL GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 2)

/**
 * How long at most on average will we allow a reply forward to take
 * (before we quit sending out new requests)
 */
#define MAX_REQUEST_TIME GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)

/**
 * How many time differences between requesting a core send and
 * the actual callback to remember.
 */
#define MAX_REPLY_TIMES 8




/**
 * How many peers have we added since we sent out our last
 * find peer request?
 */
static unsigned int newly_found_peers;

/**
 * Handle for the statistics service.
 */
struct GNUNET_STATISTICS_Handle *stats;

/**
 * Handle to get our current HELLO.
 */
static struct GNUNET_TRANSPORT_GetHelloHandle *ghh;

/**
 * The configuration the DHT service is running with
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to the core service
 */
static struct GNUNET_CORE_Handle *coreAPI;

/**
 * Handle to the transport service, for getting our hello
 */
static struct GNUNET_TRANSPORT_Handle *transport_handle;

/**
 * The identity of our peer.
 */
static struct GNUNET_PeerIdentity my_identity;

/**
 * Our HELLO
 */
static struct GNUNET_MessageHeader *my_hello;

/**
 * Task to run when we shut down, cleaning up all our trash
 */
static GNUNET_SCHEDULER_TaskIdentifier cleanup_task;

/**
 * Recently seen find peer requests.
 */
static struct GNUNET_CONTAINER_MultiHashMap *recent_find_peer_requests;

/**
 * Our handle to the BLOCK library.
 */
static struct GNUNET_BLOCK_Context *block_context;




/**
 * Given the largest send delay, artificially decrease it
 * so the next time around we may have a chance at sending
 * again.
 */
static void
decrease_max_send_delay (struct GNUNET_TIME_Relative max_time)
{
  unsigned int i;

  for (i = 0; i < MAX_REPLY_TIMES; i++)
  {
    if (reply_times[i].rel_value == max_time.rel_value)
    {
      reply_times[i].rel_value = reply_times[i].rel_value / 2;
      return;
    }
  }
}


/**
 * Find the maximum send time of the recently sent values.
 *
 * @return the average time between asking core to send a message
 *         and when the buffer for copying it is passed
 */
static struct GNUNET_TIME_Relative
get_max_send_delay ()
{
  unsigned int i;
  struct GNUNET_TIME_Relative max_time;

  max_time = GNUNET_TIME_relative_get_zero ();

  for (i = 0; i < MAX_REPLY_TIMES; i++)
  {
    if (reply_times[i].rel_value > max_time.rel_value)
      max_time.rel_value = reply_times[i].rel_value;
  }
#if DEBUG_DHT
  if (max_time.rel_value > MAX_REQUEST_TIME.rel_value)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Max send delay was %llu\n",
                (unsigned long long) max_time.rel_value);
#endif
  return max_time;
}


static void
increment_stats (const char *value)
{
  if (stats == NULL)
    return;
  GNUNET_STATISTICS_update (stats, value, 1, GNUNET_NO);
}


static void
decrement_stats (const char *value)
{
  if (stats == NULL)
    return;
  GNUNET_STATISTICS_update (stats, value, -1, GNUNET_NO);
}



/**
 * Compute the distance between have and target as a 32-bit value.
 * Differences in the lower bits must count stronger than differences
 * in the higher bits.
 *
 * @return 0 if have==target, otherwise a number
 *           that is larger as the distance between
 *           the two hash codes increases
 */
static unsigned int
distance (const GNUNET_HashCode * target, const GNUNET_HashCode * have)
{
  unsigned int bucket;
  unsigned int msb;
  unsigned int lsb;
  unsigned int i;

  /* We have to represent the distance between two 2^9 (=512)-bit
   * numbers as a 2^5 (=32)-bit number with "0" being used for the
   * two numbers being identical; furthermore, we need to
   * guarantee that a difference in the number of matching
   * bits is always represented in the result.
   *
   * We use 2^32/2^9 numerical values to distinguish between
   * hash codes that have the same LSB bit distance and
   * use the highest 2^9 bits of the result to signify the
   * number of (mis)matching LSB bits; if we have 0 matching
   * and hence 512 mismatching LSB bits we return -1 (since
   * 512 itself cannot be represented with 9 bits) */

  /* first, calculate the most significant 9 bits of our
   * result, aka the number of LSBs */
  bucket = GNUNET_CRYPTO_hash_matching_bits (target, have);
  /* bucket is now a value between 0 and 512 */
  if (bucket == 512)
    return 0;                   /* perfect match */
  if (bucket == 0)
    return (unsigned int) -1;   /* LSB differs; use max (if we did the bit-shifting
                                 * below, we'd end up with max+1 (overflow)) */

  /* calculate the most significant bits of the final result */
  msb = (512 - bucket) << (32 - 9);
  /* calculate the 32-9 least significant bits of the final result by
   * looking at the differences in the 32-9 bits following the
   * mismatching bit at 'bucket' */
  lsb = 0;
  for (i = bucket + 1;
       (i < sizeof (GNUNET_HashCode) * 8) && (i < bucket + 1 + 32 - 9); i++)
  {
    if (GNUNET_CRYPTO_hash_get_bit (target, i) !=
        GNUNET_CRYPTO_hash_get_bit (have, i))
      lsb |= (1 << (bucket + 32 - 9 - i));      /* first bit set will be 10,
                                                 * last bit set will be 31 -- if
                                                 * i does not reach 512 first... */
  }
  return msb | lsb;
}


/**
 * Return a number that is larger the closer the
 * "have" GNUNET_hash code is to the "target".
 *
 * @return inverse distance metric, non-zero.
 *         Must fudge the value if NO bits match.
 */
static unsigned int
inverse_distance (const GNUNET_HashCode * target, const GNUNET_HashCode * have)
{
  if (GNUNET_CRYPTO_hash_matching_bits (target, have) == 0)
    return 1;                   /* Never return 0! */
  return ((unsigned int) -1) - distance (target, have);
}



/* Forward declaration */
static void
update_core_preference (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Function called with statistics about the given peer.
 *
 * @param cls closure
 * @param peer identifies the peer
 * @param bpm_out set to the current bandwidth limit (sending) for this peer
 * @param amount set to the amount that was actually reserved or unreserved;
 *               either the full requested amount or zero (no partial reservations)
 * @param res_delay if the reservation could not be satisfied (amount was 0), how
 *        long should the client wait until re-trying?
 * @param preference current traffic preference for the given peer
 */
static void
update_core_preference_finish (void *cls,
                               const struct GNUNET_PeerIdentity *peer,
                               struct GNUNET_BANDWIDTH_Value32NBO bpm_out,
                               int32_t amount,
                               struct GNUNET_TIME_Relative res_delay,
                               uint64_t preference)
{
  struct PeerInfo *peer_info = cls;

  peer_info->info_ctx = NULL;
  GNUNET_SCHEDULER_add_delayed (DHT_DEFAULT_PREFERENCE_INTERVAL,
                                &update_core_preference, peer_info);
}

static void
update_core_preference (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerInfo *peer = cls;
  uint64_t preference;
  unsigned int matching;

  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
  {
    return;
  }
  matching =
      GNUNET_CRYPTO_hash_matching_bits (&my_identity.hashPubKey,
                                        &peer->id.hashPubKey);
  if (matching >= 64)
  {
#if DEBUG_DHT
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Peer identifier matches by %u bits, only shifting as much as we can!\n",
                matching);
#endif
    matching = 63;
  }
  preference = 1LL << matching;
  peer->info_ctx =
      GNUNET_CORE_peer_change_preference (coreAPI, &peer->id,
                                          GNUNET_TIME_UNIT_FOREVER_REL,
                                          GNUNET_BANDWIDTH_VALUE_MAX, 0,
                                          preference,
                                          &update_core_preference_finish, peer);
}



/**
 * Server handler for initiating local dht find peer requests
 *
 * @param find_msg the actual find peer message
 * @param msg_ctx struct containing pertinent information about the request
 *
 */
static void
handle_dht_find_peer (const struct GNUNET_MessageHeader *find_msg,
                      struct DHT_MessageContext *msg_ctx)
{
  struct GNUNET_MessageHeader *find_peer_result;
  struct GNUNET_DHT_FindPeerMessage *find_peer_message;
  struct DHT_MessageContext *new_msg_ctx;
  struct GNUNET_CONTAINER_BloomFilter *incoming_bloom;
  size_t hello_size;
  size_t tsize;
  GNUNET_HashCode *recent_hash;
  struct GNUNET_MessageHeader *other_hello;
  size_t other_hello_size;
  struct GNUNET_PeerIdentity peer_id;

  find_peer_message = (struct GNUNET_DHT_FindPeerMessage *) find_msg;
  GNUNET_break_op (ntohs (find_msg->size) >=
                   (sizeof (struct GNUNET_DHT_FindPeerMessage)));
  if (ntohs (find_msg->size) < sizeof (struct GNUNET_DHT_FindPeerMessage))
    return;
  other_hello = NULL;
  other_hello_size = 0;
  if (ntohs (find_msg->size) > sizeof (struct GNUNET_DHT_FindPeerMessage))
  {
    other_hello_size =
        ntohs (find_msg->size) - sizeof (struct GNUNET_DHT_FindPeerMessage);
    other_hello = GNUNET_malloc (other_hello_size);
    memcpy (other_hello, &find_peer_message[1], other_hello_size);
    if ((GNUNET_HELLO_size ((struct GNUNET_HELLO_Message *) other_hello) == 0)
        || (GNUNET_OK !=
            GNUNET_HELLO_get_id ((struct GNUNET_HELLO_Message *) other_hello,
                                 &peer_id)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Received invalid HELLO message in find peer request!\n");
      GNUNET_free (other_hello);
      return;
    }
#if FIND_PEER_WITH_HELLO
    if (GNUNET_YES == consider_peer (&peer_id))
    {
      increment_stats (STAT_HELLOS_PROVIDED);
      GNUNET_TRANSPORT_offer_hello (transport_handle, other_hello, NULL, NULL);
      GNUNET_CORE_peer_request_connect (coreAPI, &peer_id, NULL, NULL);
      route_message (find_msg, msg_ctx);
      GNUNET_free (other_hello);
      return;
    }
    else                        /* We don't want this peer! */
    {
      route_message (find_msg, msg_ctx);
      GNUNET_free (other_hello);
      return;
    }
#endif
  }

#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s:%s': Received `%s' request from client, key %s (msg size %d, we expected %d)\n",
              my_short_id, "DHT", "FIND PEER", GNUNET_h2s (&msg_ctx->key),
              ntohs (find_msg->size), sizeof (struct GNUNET_MessageHeader));
#endif
  if (my_hello == NULL)
  {
#if DEBUG_DHT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "`%s': Our HELLO is null, can't return.\n", "DHT");
#endif
    GNUNET_free_non_null (other_hello);
    route_message (find_msg, msg_ctx);
    return;
  }

  incoming_bloom =
      GNUNET_CONTAINER_bloomfilter_init (find_peer_message->bloomfilter,
                                         DHT_BLOOM_SIZE, DHT_BLOOM_K);
  if (GNUNET_YES ==
      GNUNET_CONTAINER_bloomfilter_test (incoming_bloom,
                                         &my_identity.hashPubKey))
  {
    increment_stats (STAT_BLOOM_FIND_PEER);
    GNUNET_CONTAINER_bloomfilter_free (incoming_bloom);
    GNUNET_free_non_null (other_hello);
    route_message (find_msg, msg_ctx);
    return;                     /* We match the bloomfilter, do not send a response to this peer (they likely already know us!) */
  }
  GNUNET_CONTAINER_bloomfilter_free (incoming_bloom);

  /**
   * Ignore any find peer requests from a peer we have seen very recently.
   */
  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (recent_find_peer_requests, &msg_ctx->key))  /* We have recently responded to a find peer request for this peer! */
  {
    increment_stats ("# dht find peer requests ignored (recently seen!)");
    GNUNET_free_non_null (other_hello);
    return;
  }

  /**
   * Use this check to only allow the peer to respond to find peer requests if
   * it would be beneficial to have the requesting peer in this peers routing
   * table.  Can be used to thwart peers flooding the network with find peer
   * requests that we don't care about.  However, if a new peer is joining
   * the network and has no other peers this is a problem (assume all buckets
   * full, no one will respond!).
   */
  memcpy (&peer_id.hashPubKey, &msg_ctx->key, sizeof (GNUNET_HashCode));
  if (GNUNET_NO == consider_peer (&peer_id))
  {
    increment_stats ("# dht find peer requests ignored (do not need!)");
    GNUNET_free_non_null (other_hello);
    route_message (find_msg, msg_ctx);
    return;
  }

  recent_hash = GNUNET_malloc (sizeof (GNUNET_HashCode));
  memcpy (recent_hash, &msg_ctx->key, sizeof (GNUNET_HashCode));
  if (GNUNET_SYSERR !=
      GNUNET_CONTAINER_multihashmap_put (recent_find_peer_requests,
                                         &msg_ctx->key, NULL,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
  {
#if DEBUG_DHT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Adding recent remove task for key `%s`!\n",
                GNUNET_h2s (&msg_ctx->key));
#endif
    /* Only add a task if there wasn't one for this key already! */
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_SECONDS, 30),
                                  &remove_recent_find_peer, recent_hash);
  }
  else
  {
    GNUNET_free (recent_hash);
#if DEBUG_DHT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received duplicate find peer request too soon!\n");
#endif
  }

  /* Simplistic find_peer functionality, always return our hello */
  hello_size = ntohs (my_hello->size);
  tsize = hello_size + sizeof (struct GNUNET_MessageHeader);

  if (tsize >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break_op (0);
    GNUNET_free_non_null (other_hello);
    return;
  }

  find_peer_result = GNUNET_malloc (tsize);
  find_peer_result->type = htons (GNUNET_MESSAGE_TYPE_DHT_FIND_PEER_RESULT);
  find_peer_result->size = htons (tsize);
  memcpy (&find_peer_result[1], my_hello, hello_size);
#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Sending hello size %d to requesting peer.\n", "DHT",
              hello_size);
#endif

  new_msg_ctx = GNUNET_malloc (sizeof (struct DHT_MessageContext));
  memcpy (new_msg_ctx, msg_ctx, sizeof (struct DHT_MessageContext));
  new_msg_ctx->peer = my_identity;
  new_msg_ctx->bloom =
      GNUNET_CONTAINER_bloomfilter_init (NULL, DHT_BLOOM_SIZE, DHT_BLOOM_K);
  new_msg_ctx->hop_count = 0;
  new_msg_ctx->importance = DHT_DEFAULT_P2P_IMPORTANCE + 2;     /* Make find peer requests a higher priority */
  new_msg_ctx->timeout = DHT_DEFAULT_P2P_TIMEOUT;
  increment_stats (STAT_FIND_PEER_ANSWER);
  if (GNUNET_DHT_RO_RECORD_ROUTE ==
      (msg_ctx->msg_options & GNUNET_DHT_RO_RECORD_ROUTE))
  {
    new_msg_ctx->msg_options = GNUNET_DHT_RO_RECORD_ROUTE;
    new_msg_ctx->path_history_len = msg_ctx->path_history_len;
    /* Assign to previous msg_ctx path history, caller should free after our return */
    new_msg_ctx->path_history = msg_ctx->path_history;
  }
  route_result_message (find_peer_result, new_msg_ctx);
  GNUNET_free (new_msg_ctx);
  GNUNET_free_non_null (other_hello);
  GNUNET_free (find_peer_result);
  route_message (find_msg, msg_ctx);
}



/**
 * Receive the HELLO from transport service,
 * free current and replace if necessary.
 *
 * @param cls NULL
 * @param message HELLO message of peer
 */
static void
process_hello (void *cls, const struct GNUNET_MessageHeader *message)
{
#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received our `%s' from transport service\n", "HELLO");
#endif
  GNUNET_assert (message != NULL);
  GNUNET_free_non_null (my_hello);
  my_hello = GNUNET_malloc (ntohs (message->size));
  memcpy (my_hello, message, ntohs (message->size));
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
  if (NULL != ghh)
  {
    GNUNET_TRANSPORT_get_hello_cancel (ghh);
    ghh = NULL;
  }
  if (transport_handle != NULL)
  {
    GNUNET_free_non_null (my_hello);
    GNUNET_TRANSPORT_disconnect (transport_handle);
    transport_handle = NULL;
  }
  GDS_NEIGHBOURS_done ();
  GDS_DATACACHE_done ();
  GDS_ROUTING_done ();
  GDS_CLIENT_done ();
  GDS_NSE_done ();
  if (stats != NULL)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_YES);
    stats = NULL;
  }
  if (block_context != NULL)
  {
    GNUNET_BLOCK_context_destroy (block_context);
    block_context = NULL;
  }
}



/**
 * Process dht requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  struct GNUNET_TIME_Relative next_send_time;
  unsigned long long temp_config_num;

  cfg = c;
  GDS_DATACACHE_init ();
  coreAPI = GNUNET_CORE_connect (cfg,   /* Main configuration */
                                 DEFAULT_CORE_QUEUE_SIZE,       /* queue size */
                                 NULL,  /* Closure passed to DHT functions */
                                 &core_init,    /* Call core_init once connected */
                                 &handle_core_connect,  /* Handle connects */
                                 &handle_core_disconnect,       /* remove peers on disconnects */
                                 NULL,  /* Do we care about "status" updates? */
                                 NULL,  /* Don't want notified about all incoming messages */
                                 GNUNET_NO,     /* For header only inbound notification */
                                 NULL,  /* Don't want notified about all outbound messages */
                                 GNUNET_NO,     /* For header only outbound notification */
                                 core_handlers);        /* Register these handlers */

  if (coreAPI == NULL)
    return;
  transport_handle =
      GNUNET_TRANSPORT_connect (cfg, NULL, NULL, NULL, NULL, NULL);
  if (transport_handle != NULL)
    ghh = GNUNET_TRANSPORT_get_hello (transport_handle, &process_hello, NULL);
  else
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Failed to connect to transport service!\n");
  block_context = GNUNET_BLOCK_context_create (cfg);
  lowest_bucket = MAX_BUCKETS - 1;
  all_known_peers = GNUNET_CONTAINER_multihashmap_create (MAX_BUCKETS / 8);
  GNUNET_assert (all_known_peers != NULL);

  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "DHT", "bucket_size",
                                             &temp_config_num))
  {
    bucket_size = (unsigned int) temp_config_num;
  }

  stats = GNUNET_STATISTICS_create ("dht", cfg);
  next_send_time.rel_value =
    DHT_MINIMUM_FIND_PEER_INTERVAL.rel_value +
    GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_STRONG,
			      (DHT_MAXIMUM_FIND_PEER_INTERVAL.rel_value /
			       2) -
			      DHT_MINIMUM_FIND_PEER_INTERVAL.rel_value);
  find_peer_context.start = GNUNET_TIME_absolute_get ();
  GNUNET_SCHEDULER_add_delayed (next_send_time, &send_find_peer_message,
				&find_peer_context);  

  /* Scheduled the task to clean up when shutdown is called */
  cleanup_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                    &shutdown_task, NULL);
}


/**
 * The main function for the dht service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
	  GNUNET_SERVICE_run (argc, argv, "dht", GNUNET_SERVICE_OPTION_NONE, &run,
			      NULL)) ? 0 : 1;
}

/* end of gnunet-service-dht.c */
