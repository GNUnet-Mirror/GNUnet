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
 * - decide which 'benchmark'/test functions to keep (malicious code, kademlia, etc.)
 * - decide on 'stop_on_closest', 'stop_on_found', 'do_find_peer', 'paper_forwarding'
 * - use OPTION_MULTIPLE instead of linked list ofr the forward_list.hashmap
 * - use different 'struct DHT_MessageContext' for the different types of
 *   messages (currently rather confusing, especially with things like
 *   peer bloom filters occuring when processing replies).
 * - why do we have request UIDs again?
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
#include "dhtlog.h"
#include "dht.h"
#include <fenv.h>


/**
 * How many buckets will we allow total.
 */
#define MAX_BUCKETS sizeof (GNUNET_HashCode) * 8

/**
 * Should the DHT issue FIND_PEER requests to get better routing tables?
 */
#define DEFAULT_DO_FIND_PEER GNUNET_YES

/**
 * Defines whether find peer requests send their HELLO's outgoing,
 * or expect replies to contain hellos.
 */
#define FIND_PEER_WITH_HELLO GNUNET_YES

/**
 * What is the maximum number of peers in a given bucket.
 */
#define DEFAULT_BUCKET_SIZE 4

#define DEFAULT_CORE_QUEUE_SIZE 32

/**
 * Minimum number of peers we need for "good" routing,
 * any less than this and we will allow messages to
 * travel much further through the network!
 */
#define MINIMUM_PEER_THRESHOLD 20

/**
 * Number of requests we track at most (for routing replies).
 */
#define DHT_MAX_RECENT (1024 * 16)

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
 * How many initial requests to send out (in true Kademlia fashion)
 */
#define DEFAULT_KADEMLIA_REPLICATION 3

/**
 * Default frequency for sending malicious get messages
 */
#define DEFAULT_MALICIOUS_GET_FREQUENCY GNUNET_TIME_UNIT_SECONDS

/**
 * Default frequency for sending malicious put messages
 */
#define DEFAULT_MALICIOUS_PUT_FREQUENCY GNUNET_TIME_UNIT_SECONDS

/**
 * How many time differences between requesting a core send and
 * the actual callback to remember.
 */
#define MAX_REPLY_TIMES 8


/**
 * Linked list of messages to send to clients.
 */
struct P2PPendingMessage
{
  /**
   * Pointer to next item in the list
   */
  struct P2PPendingMessage *next;

  /**
   * Pointer to previous item in the list
   */
  struct P2PPendingMessage *prev;

  /**
   * Message importance level.
   */
  unsigned int importance;

  /**
   * Time when this request was scheduled to be sent.
   */
  struct GNUNET_TIME_Absolute scheduled;

  /**
   * How long to wait before sending message.
   */
  struct GNUNET_TIME_Relative timeout;

  /**
   * Actual message to be sent; // avoid allocation
   */
  const struct GNUNET_MessageHeader *msg;       // msg = (cast) &pm[1]; // memcpy (&pm[1], data, len);

};


/**
 * Per-peer information.
 */
struct PeerInfo
{
  /**
   * Next peer entry (DLL)
   */
  struct PeerInfo *next;

  /**
   *  Prev peer entry (DLL)
   */
  struct PeerInfo *prev;

  /**
   * Count of outstanding messages for peer.
   */
  unsigned int pending_count;

  /**
   * Head of pending messages to be sent to this peer.
   */
  struct P2PPendingMessage *head;

  /**
   * Tail of pending messages to be sent to this peer.
   */
  struct P2PPendingMessage *tail;

  /**
   * Core handle for sending messages to this peer.
   */
  struct GNUNET_CORE_TransmitHandle *th;

  /**
   * Task for scheduling message sends.
   */
  GNUNET_SCHEDULER_TaskIdentifier send_task;

  /**
   * Task for scheduling preference updates
   */
  GNUNET_SCHEDULER_TaskIdentifier preference_task;

  /**
   * Preference update context
   */
  struct GNUNET_CORE_InformationRequestContext *info_ctx;

  /**
   * What is the identity of the peer?
   */
  struct GNUNET_PeerIdentity id;

#if 0
  /**
   * What is the average latency for replies received?
   */
  struct GNUNET_TIME_Relative latency;

  /**
   * Transport level distance to peer.
   */
  unsigned int distance;
#endif

  /**
   * Task for scheduling periodic ping messages for this peer.
   */
  GNUNET_SCHEDULER_TaskIdentifier ping_task;
};


/**
 * Peers are grouped into buckets.
 */
struct PeerBucket
{
  /**
   * Head of DLL
   */
  struct PeerInfo *head;

  /**
   * Tail of DLL
   */
  struct PeerInfo *tail;

  /**
   * Number of peers in the bucket.
   */
  unsigned int peers_size;
};


/**
 * Linked list of messages to send to clients.
 */
struct PendingMessage
{
  /**
   * Pointer to next item in the list
   */
  struct PendingMessage *next;

  /**
   * Pointer to previous item in the list
   */
  struct PendingMessage *prev;

  /**
   * Actual message to be sent; // avoid allocation
   */
  const struct GNUNET_MessageHeader *msg;       // msg = (cast) &pm[1]; // memcpy (&pm[1], data, len);

};


/**
 * Struct containing information about a client,
 * handle to connect to it, and any pending messages
 * that need to be sent to it.
 */
struct ClientList
{
  /**
   * Linked list of active clients
   */
  struct ClientList *next;

  /**
   * The handle to this client
   */
  struct GNUNET_SERVER_Client *client_handle;

  /**
   * Handle to the current transmission request, NULL
   * if none pending.
   */
  struct GNUNET_CONNECTION_TransmitHandle *transmit_handle;

  /**
   * Linked list of pending messages for this client
   */
  struct PendingMessage *pending_head;

  /**
   * Tail of linked list of pending messages for this client
   */
  struct PendingMessage *pending_tail;
};


/**
 * Context containing information about a DHT message received.
 */
struct DHT_MessageContext
{
  /**
   * The client this request was received from.
   * (NULL if received from another peer)
   */
  struct ClientList *client;

  /**
   * The peer this request was received from.
   * (NULL if received from local client)
   */
  const struct GNUNET_PeerIdentity *peer;

  /**
   * Bloomfilter for this routing request.
   */
  struct GNUNET_CONTAINER_BloomFilter *bloom;

  /**
   * extended query (see gnunet_block_lib.h).
   */
  const void *xquery;

  /**
   * Bloomfilter to filter out duplicate replies.
   */
  struct GNUNET_CONTAINER_BloomFilter *reply_bf;

  /**
   * The key this request was about
   */
  GNUNET_HashCode key;

  /**
   * How long should we wait to transmit this request?
   */
  struct GNUNET_TIME_Relative timeout;

  /**
   * The unique identifier of this request
   */
  uint64_t unique_id;

  /**
   * Number of bytes in xquery.
   */
  size_t xquery_size;

  /**
   * Mutator value for the reply_bf, see gnunet_block_lib.h
   */
  uint32_t reply_bf_mutator;

  /**
   * Desired replication level
   */
  uint32_t replication;

  /**
   * Network size estimate, either ours or the sum of
   * those routed to thus far. =~ Log of number of peers
   * chosen from for this request.
   */
  uint32_t network_size;

  /**
   * Any message options for this request
   */
  uint32_t msg_options;

  /**
   * How many hops has the message already traversed?
   */
  uint32_t hop_count;

  /**
   * How many peer identities are present in the path history?
   */
  uint32_t path_history_len;

  /**
   * Path history.
   */
  char *path_history;

  /**
   * How important is this message?
   */
  unsigned int importance;

  /**
   * Should we (still) forward the request on to other peers?
   */
  int do_forward;

  /**
   * Did we forward this message? (may need to remember it!)
   */
  int forwarded;

  /**
   * Are we the closest known peer to this key (out of our neighbors?)
   */
  int closest;
};


/**
 * Record used for remembering what peers are waiting for what
 * responses (based on search key).
 */
struct DHTRouteSource
{
  /**
   * This is a DLL.
   */
  struct DHTRouteSource *next;

  /**
   * This is a DLL.
   */
  struct DHTRouteSource *prev;

  /**
   * UID of the request
   */
  uint64_t uid;

  /**
   * Source of the request.  Replies should be forwarded to
   * this peer.
   */
  struct GNUNET_PeerIdentity source;

  /**
   * If this was a local request, remember the client; otherwise NULL.
   */
  struct ClientList *client;

  /**
   * Pointer to this nodes heap location (for removal)
   */
  struct GNUNET_CONTAINER_HeapNode *hnode;

  /**
   * Back pointer to the record storing this information.
   */
  struct DHTQueryRecord *record;

  /**
   * Task to remove this entry on timeout.
   */
  GNUNET_SCHEDULER_TaskIdentifier delete_task;

  /**
   * Bloomfilter of peers we have already sent back as
   * replies to the initial request.  Allows us to not
   * forward the same peer multiple times for a find peer
   * request.
   */
  struct GNUNET_CONTAINER_BloomFilter *find_peers_responded;

};


/**
 * Entry in the DHT routing table.
 */
struct DHTQueryRecord
{
  /**
   * Head of DLL for result forwarding.
   */
  struct DHTRouteSource *head;

  /**
   * Tail of DLL for result forwarding.
   */
  struct DHTRouteSource *tail;

  /**
   * Key that the record concerns.
   */
  GNUNET_HashCode key;

};


/**
 * Context used to calculate the number of find peer messages
 * per X time units since our last scheduled find peer message
 * was sent.  If we have seen too many messages, delay or don't
 * send our own out.
 */
struct FindPeerMessageContext
{
  unsigned int count;

  struct GNUNET_TIME_Absolute start;

  struct GNUNET_TIME_Absolute end;
};


/**
 * DHT Routing results structure
 */
struct DHTResults
{
  /*
   * Min heap for removal upon reaching limit
   */
  struct GNUNET_CONTAINER_Heap *minHeap;

  /*
   * Hashmap for fast key based lookup
   */
  struct GNUNET_CONTAINER_MultiHashMap *hashmap;

};


/**
 * DHT structure for recent requests.
 */
struct RecentRequests
{
  /*
   * Min heap for removal upon reaching limit
   */
  struct GNUNET_CONTAINER_Heap *minHeap;

  /*
   * Hashmap for key based lookup
   */
  struct GNUNET_CONTAINER_MultiHashMap *hashmap;
};


struct RecentRequest
{
  /**
   * Position of this node in the min heap.
   */
  struct GNUNET_CONTAINER_HeapNode *heap_node;

  /**
   * Bloomfilter containing entries for peers
   * we forwarded this request to.
   */
  struct GNUNET_CONTAINER_BloomFilter *bloom;

  /**
   * Timestamp of this request, for ordering
   * the min heap.
   */
  struct GNUNET_TIME_Absolute timestamp;

  /**
   * Key of this request.
   */
  GNUNET_HashCode key;

  /**
   * Unique identifier for this request.
   */
  uint64_t uid;

  /**
   * Task to remove this entry on timeout.
   */
  GNUNET_SCHEDULER_TaskIdentifier remove_task;
};


/**
 * log of the current network size estimate, used as the point where
 * we switch between random and deterministic routing.  Default
 * value of 4.0 is used if NSE module is not available (i.e. not
 * configured).
 */
static double log_of_network_size_estimate = 4.0;

/**
 * Recent requests by hash/uid and by time inserted.
 */
static struct RecentRequests recent;

/**
 * Context to use to calculate find peer rates.
 */
static struct FindPeerMessageContext find_peer_context;

/**
 * Don't use our routing algorithm, always route
 * to closest peer; initially send requests to 3
 * peers.
 */
static int strict_kademlia;

/**
 * Routing option to end routing when closest peer found.
 */
static int stop_on_closest;

/**
 * Routing option to end routing when data is found.
 */
static int stop_on_found;

/**
 * Whether DHT needs to manage find peer requests, or
 * an external force will do it on behalf of the DHT.
 */
static int do_find_peer;

/**
 * Use exactly the forwarding formula as described in
 * the paper if set to GNUNET_YES, otherwise use the
 * slightly modified version.
 */
static int paper_forwarding;

/**
 * PUT Peer Identities of peers we know about into
 * the datacache.
 */
static int put_peer_identities;

/**
 * Use the "real" distance metric when selecting the
 * next routing hop.  Can be less accurate.
 */
static int use_real_distance;

/**
 * How many peers have we added since we sent out our last
 * find peer request?
 */
static unsigned int newly_found_peers;

/**
 * Container of active queries we should remember
 */
static struct DHTResults forward_list;

/**
 * Handle to the datacache service (for inserting/retrieving data)
 */
static struct GNUNET_DATACACHE_Handle *datacache;

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
 * Short id of the peer, for printing
 */
static char *my_short_id;

/**
 * Our HELLO
 */
static struct GNUNET_MessageHeader *my_hello;

/**
 * Task to run when we shut down, cleaning up all our trash
 */
static GNUNET_SCHEDULER_TaskIdentifier cleanup_task;

/**
 * The lowest currently used bucket.
 */
static unsigned int lowest_bucket;      /* Initially equal to MAX_BUCKETS - 1 */

/**
 * The buckets (Kademlia routing table, complete with growth).
 * Array of size MAX_BUCKET_SIZE.
 */
static struct PeerBucket k_buckets[MAX_BUCKETS];

/**
 * Hash map of all known peers, for easy removal from k_buckets on disconnect.
 */
static struct GNUNET_CONTAINER_MultiHashMap *all_known_peers;

/**
 * Recently seen find peer requests.
 */
static struct GNUNET_CONTAINER_MultiHashMap *recent_find_peer_requests;

/**
 * Maximum size for each bucket.
 */
static unsigned int bucket_size = DEFAULT_BUCKET_SIZE;

/**
 * List of active clients.
 */
static struct ClientList *client_list;

/**
 * Handle to the DHT logger.
 */
static struct GNUNET_DHTLOG_Handle *dhtlog_handle;

/**
 * Whether or not to send routing debugging information
 * to the dht logging server
 */
static unsigned int debug_routes;

/**
 * Whether or not to send FULL route information to
 * logging server
 */
static unsigned int debug_routes_extended;

/**
 * GNUNET_YES or GNUNET_NO, whether or not to act as
 * a malicious node which drops all messages
 */
static unsigned int malicious_dropper;

/**
 * GNUNET_YES or GNUNET_NO, whether or not to act as
 * a malicious node which sends out lots of GETS
 */
static unsigned int malicious_getter;

/**
 * GNUNET_YES or GNUNET_NO, whether or not to act as
 * a malicious node which sends out lots of PUTS
 */
static unsigned int malicious_putter;

/**
 * Frequency for malicious get requests.
 */
static struct GNUNET_TIME_Relative malicious_get_frequency;

/**
 * Frequency for malicious put requests.
 */
static struct GNUNET_TIME_Relative malicious_put_frequency;

/**
 * Kademlia replication
 */
static unsigned long long kademlia_replication;

/**
 * Reply times for requests, if we are busy, don't send any
 * more requests!
 */
static struct GNUNET_TIME_Relative reply_times[MAX_REPLY_TIMES];

/**
 * Current counter for replies.
 */
static unsigned int reply_counter;

/**
 * Our handle to the BLOCK library.
 */
static struct GNUNET_BLOCK_Context *block_context;

/**
 * Network size estimation handle.
 */
static struct GNUNET_NSE_Handle *nse;


/**
 * Callback that is called when network size estimate is updated.
 *
 * @param cls closure
 * @param timestamp time when the estimate was received from the server (or created by the server)
 * @param logestimate the log(Base 2) value of the current network size estimate
 * @param std_dev standard deviation for the estimate
 *
 */
static void
update_network_size_estimate (void *cls, struct GNUNET_TIME_Absolute timestamp,
                              double logestimate, double std_dev)
{
  log_of_network_size_estimate = logestimate;
}


/**
 * Forward declaration.
 */
static size_t
send_generic_reply (void *cls, size_t size, void *buf);


/** Declare here so retry_core_send is aware of it */
static size_t
core_transmit_notify (void *cls, size_t size, void *buf);


/**
 * Convert unique ID to hash code.
 *
 * @param uid unique ID to convert
 * @param hash set to uid (extended with zeros)
 */
static void
hash_from_uid (uint64_t uid, GNUNET_HashCode * hash)
{
  memset (hash, 0, sizeof (GNUNET_HashCode));
  *((uint64_t *) hash) = uid;
}


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
 *  Try to send another message from our core send list
 */
static void
try_core_send (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerInfo *peer = cls;
  struct P2PPendingMessage *pending;
  size_t ssize;

  peer->send_task = GNUNET_SCHEDULER_NO_TASK;

  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;

  if (peer->th != NULL)
    return;                     /* Message send already in progress */

  pending = peer->head;
  if (pending != NULL)
  {
    ssize = ntohs (pending->msg->size);
#if DEBUG_DHT > 1
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "`%s:%s': Calling notify_transmit_ready with size %d for peer %s\n",
                my_short_id, "DHT", ssize, GNUNET_i2s (&peer->id));
#endif
    pending->scheduled = GNUNET_TIME_absolute_get ();
    reply_counter++;
    if (reply_counter >= MAX_REPLY_TIMES)
      reply_counter = 0;
    peer->th =
        GNUNET_CORE_notify_transmit_ready (coreAPI, GNUNET_YES,
                                           pending->importance,
                                           pending->timeout, &peer->id, ssize,
                                           &core_transmit_notify, peer);
    if (peer->th == NULL)
      increment_stats ("# notify transmit ready failed");
  }
}


/**
 * Function called to send a request out to another peer.
 * Called both for locally initiated requests and those
 * received from other peers.
 *
 * @param msg the encapsulated message
 * @param peer the peer to forward the message to
 * @param msg_ctx the context of the message (hop count, bloom, etc.)
 */
static void
forward_result_message (const struct GNUNET_MessageHeader *msg,
                        struct PeerInfo *peer,
                        struct DHT_MessageContext *msg_ctx)
{
  struct GNUNET_DHT_P2PRouteResultMessage *result_message;
  struct P2PPendingMessage *pending;
  size_t msize;
  size_t psize;
  char *path_start;
  char *path_offset;

#if DEBUG_PATH
  unsigned int i;
#endif

  increment_stats (STAT_RESULT_FORWARDS);
  msize =
      sizeof (struct GNUNET_DHT_P2PRouteResultMessage) + ntohs (msg->size) +
      (sizeof (struct GNUNET_PeerIdentity) * msg_ctx->path_history_len);
  GNUNET_assert (msize <= GNUNET_SERVER_MAX_MESSAGE_SIZE);
  psize = sizeof (struct P2PPendingMessage) + msize;
  pending = GNUNET_malloc (psize);
  pending->msg = (struct GNUNET_MessageHeader *) &pending[1];
  pending->importance = DHT_SEND_PRIORITY;
  pending->timeout = GNUNET_TIME_relative_get_forever ();
  result_message = (struct GNUNET_DHT_P2PRouteResultMessage *) pending->msg;
  result_message->header.size = htons (msize);
  result_message->header.type =
      htons (GNUNET_MESSAGE_TYPE_DHT_P2P_ROUTE_RESULT);
  result_message->outgoing_path_length = htonl (msg_ctx->path_history_len);
  if (msg_ctx->path_history_len > 0)
  {
    /* End of pending is where enc_msg starts */
    path_start = (char *) &pending[1];
    /* Offset by the size of the enc_msg */
    path_start += ntohs (msg->size);
    memcpy (path_start, msg_ctx->path_history,
            msg_ctx->path_history_len * (sizeof (struct GNUNET_PeerIdentity)));
#if DEBUG_PATH
    for (i = 0; i < msg_ctx->path_history_len; i++)
    {
      path_offset =
          &msg_ctx->path_history[i * sizeof (struct GNUNET_PeerIdentity)];
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "(forward_result) Key %s Found peer %d:%s\n",
                  GNUNET_h2s (&msg_ctx->key), i,
                  GNUNET_i2s ((struct GNUNET_PeerIdentity *) path_offset));
    }
#endif
  }
  result_message->options = htonl (msg_ctx->msg_options);
  result_message->hop_count = htonl (msg_ctx->hop_count + 1);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_bloomfilter_get_raw_data (msg_ctx->bloom,
                                                            result_message->
                                                            bloomfilter,
                                                            DHT_BLOOM_SIZE));
  result_message->unique_id = GNUNET_htonll (msg_ctx->unique_id);
  memcpy (&result_message->key, &msg_ctx->key, sizeof (GNUNET_HashCode));
  /* Copy the enc_msg, then the path history as well! */
  memcpy (&result_message[1], msg, ntohs (msg->size));
  path_offset = (char *) &result_message[1];
  path_offset += ntohs (msg->size);
  /* If we have path history, copy it to the end of the whole thing */
  if (msg_ctx->path_history_len > 0)
    memcpy (path_offset, msg_ctx->path_history,
            msg_ctx->path_history_len * (sizeof (struct GNUNET_PeerIdentity)));
#if DEBUG_DHT > 1
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s:%s Adding pending message size %d for peer %s\n", my_short_id,
              "DHT", msize, GNUNET_i2s (&peer->id));
#endif
  peer->pending_count++;
  increment_stats ("# pending messages scheduled");
  GNUNET_CONTAINER_DLL_insert_after (peer->head, peer->tail, peer->tail,
                                     pending);
  if (peer->send_task == GNUNET_SCHEDULER_NO_TASK)
    peer->send_task = GNUNET_SCHEDULER_add_now (&try_core_send, peer);
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
core_transmit_notify (void *cls, size_t size, void *buf)
{
  struct PeerInfo *peer = cls;
  char *cbuf = buf;
  struct P2PPendingMessage *pending;

  size_t off;
  size_t msize;

  peer->th = NULL;
  if (buf == NULL)
  {
    /* client disconnected */
#if DEBUG_DHT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "`%s:%s': buffer was NULL\n",
                my_short_id, "DHT");
#endif
    return 0;
  }

  if (peer->head == NULL)
    return 0;

  off = 0;
  pending = peer->head;
#if DUMB
  reply_times[reply_counter] =
      GNUNET_TIME_absolute_get_difference (pending->scheduled,
                                           GNUNET_TIME_absolute_get ());
  msize = ntohs (pending->msg->size);
  if (msize <= size)
  {
    off = msize;
    memcpy (cbuf, pending->msg, msize);
    peer->pending_count--;
    increment_stats ("# pending messages sent");
    GNUNET_assert (peer->pending_count >= 0);
    GNUNET_CONTAINER_DLL_remove (peer->head, peer->tail, pending);
    GNUNET_free (pending);
  }
#else
  while (NULL != pending &&
         (size - off >= (msize = ntohs (pending->msg->size))))
  {
    memcpy (&cbuf[off], pending->msg, msize);
    off += msize;
    peer->pending_count--;
    increment_stats ("# pending messages sent");
    GNUNET_CONTAINER_DLL_remove (peer->head, peer->tail, pending);
    GNUNET_free (pending);
    pending = peer->head;
  }
#endif
  if ((peer->head != NULL) && (peer->send_task == GNUNET_SCHEDULER_NO_TASK))
    peer->send_task = GNUNET_SCHEDULER_add_now (&try_core_send, peer);

  return off;
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


/**
 * Find the optimal bucket for this key, regardless
 * of the current number of buckets in use.
 *
 * @param hc the hashcode to compare our identity to
 *
 * @return the proper bucket index, or GNUNET_SYSERR
 *         on error (same hashcode)
 */
static int
find_bucket (const GNUNET_HashCode * hc)
{
  unsigned int bits;

  bits = GNUNET_CRYPTO_hash_matching_bits (&my_identity.hashPubKey, hc);
  if (bits == MAX_BUCKETS)
    return GNUNET_SYSERR;
  return MAX_BUCKETS - bits - 1;
}


/**
 * Find which k-bucket this peer should go into,
 * taking into account the size of the k-bucket
 * array.  This means that if more bits match than
 * there are currently buckets, lowest_bucket will
 * be returned.
 *
 * @param hc GNUNET_HashCode we are finding the bucket for.
 *
 * @return the proper bucket index for this key,
 *         or GNUNET_SYSERR on error (same hashcode)
 */
static int
find_current_bucket (const GNUNET_HashCode * hc)
{
  int actual_bucket;

  actual_bucket = find_bucket (hc);
  if (actual_bucket == GNUNET_SYSERR)   /* hc and our peer identity match! */
    return lowest_bucket;
  if (actual_bucket < lowest_bucket)    /* actual_bucket not yet used */
    return lowest_bucket;
  return actual_bucket;
}


/**
 * Find a routing table entry from a peer identity
 *
 * @param peer the peer identity to look up
 *
 * @return the routing table entry, or NULL if not found
 */
static struct PeerInfo *
find_peer_by_id (const struct GNUNET_PeerIdentity *peer)
{
  int bucket;
  struct PeerInfo *pos;

  bucket = find_current_bucket (&peer->hashPubKey);

  if (0 == memcmp (&my_identity, peer, sizeof (struct GNUNET_PeerIdentity)))
    return NULL;

  pos = k_buckets[bucket].head;
  while (pos != NULL)
  {
    if (0 == memcmp (&pos->id, peer, sizeof (struct GNUNET_PeerIdentity)))
      return pos;
    pos = pos->next;
  }
  return NULL;                  /* No such peer. */
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
 * Given a peer and its corresponding bucket,
 * remove it from that bucket.  Does not free
 * the PeerInfo struct, nor cancel messages
 * or free messages waiting to be sent to this
 * peer!
 *
 * @param peer the peer to remove
 * @param bucket the bucket the peer belongs to
 */
static void
remove_peer (struct PeerInfo *peer, unsigned int bucket)
{
  GNUNET_assert (k_buckets[bucket].peers_size > 0);
  GNUNET_CONTAINER_DLL_remove (k_buckets[bucket].head, k_buckets[bucket].tail,
                               peer);
  k_buckets[bucket].peers_size--;
#if CHANGE_LOWEST
  if ((bucket == lowest_bucket) && (k_buckets[lowest_bucket].peers_size == 0) &&
      (lowest_bucket < MAX_BUCKETS - 1))
    lowest_bucket++;
#endif
}

/**
 * Removes peer from a bucket, then frees associated
 * resources and frees peer.
 *
 * @param peer peer to be removed and freed
 * @param bucket which bucket this peer belongs to
 */
static void
delete_peer (struct PeerInfo *peer, unsigned int bucket)
{
  struct P2PPendingMessage *pos;
  struct P2PPendingMessage *next;

  remove_peer (peer, bucket);   /* First remove the peer from its bucket */
  if (peer->send_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (peer->send_task);
  if ((peer->th != NULL) && (coreAPI != NULL))
    GNUNET_CORE_notify_transmit_ready_cancel (peer->th);

  pos = peer->head;
  while (pos != NULL)           /* Remove any pending messages for this peer */
  {
    increment_stats
        ("# dht pending messages discarded (due to disconnect/shutdown)");
    next = pos->next;
    GNUNET_free (pos);
    pos = next;
  }

  GNUNET_assert (GNUNET_CONTAINER_multihashmap_contains
                 (all_known_peers, &peer->id.hashPubKey));
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (all_known_peers,
                                                       &peer->id.hashPubKey,
                                                       peer));
  GNUNET_free (peer);
  decrement_stats (STAT_PEERS_KNOWN);
}


/**
 * Iterator over hash map entries.
 *
 * @param cls closure
 * @param key current key code
 * @param value PeerInfo of the peer to move to new lowest bucket
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
static int
move_lowest_bucket (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct PeerInfo *peer = value;
  int new_bucket;

  GNUNET_assert (lowest_bucket > 0);
  new_bucket = lowest_bucket - 1;
  remove_peer (peer, lowest_bucket);
  GNUNET_CONTAINER_DLL_insert_after (k_buckets[new_bucket].head,
                                     k_buckets[new_bucket].tail,
                                     k_buckets[new_bucket].tail, peer);
  k_buckets[new_bucket].peers_size++;
  return GNUNET_YES;
}


/**
 * The current lowest bucket is full, so change the lowest
 * bucket to the next lower down, and move any appropriate
 * entries in the current lowest bucket to the new bucket.
 */
static void
enable_next_bucket ()
{
  struct GNUNET_CONTAINER_MultiHashMap *to_remove;
  struct PeerInfo *pos;

  GNUNET_assert (lowest_bucket > 0);
  to_remove = GNUNET_CONTAINER_multihashmap_create (bucket_size);
  pos = k_buckets[lowest_bucket].head;

  /* Populate the array of peers which should be in the next lowest bucket */
  while (pos != NULL)
  {
    if (find_bucket (&pos->id.hashPubKey) < lowest_bucket)
      GNUNET_CONTAINER_multihashmap_put (to_remove, &pos->id.hashPubKey, pos,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
    pos = pos->next;
  }

  /* Remove peers from lowest bucket, insert into next lowest bucket */
  GNUNET_CONTAINER_multihashmap_iterate (to_remove, &move_lowest_bucket, NULL);
  GNUNET_CONTAINER_multihashmap_destroy (to_remove);
  lowest_bucket = lowest_bucket - 1;
}


/**
 * Find the closest peer in our routing table to the
 * given hashcode.
 *
 * @return The closest peer in our routing table to the
 *         key, or NULL on error.
 */
static struct PeerInfo *
find_closest_peer (const GNUNET_HashCode * hc)
{
  struct PeerInfo *pos;
  struct PeerInfo *current_closest;
  unsigned int lowest_distance;
  unsigned int temp_distance;
  int bucket;
  int count;

  lowest_distance = -1;

  if (k_buckets[lowest_bucket].peers_size == 0)
    return NULL;

  current_closest = NULL;
  for (bucket = lowest_bucket; bucket < MAX_BUCKETS; bucket++)
  {
    pos = k_buckets[bucket].head;
    count = 0;
    while ((pos != NULL) && (count < bucket_size))
    {
      temp_distance = distance (&pos->id.hashPubKey, hc);
      if (temp_distance <= lowest_distance)
      {
        lowest_distance = temp_distance;
        current_closest = pos;
      }
      pos = pos->next;
      count++;
    }
  }
  GNUNET_assert (current_closest != NULL);
  return current_closest;
}


/**
 * Function called to send a request out to another peer.
 * Called both for locally initiated requests and those
 * received from other peers.
 *
 * @param msg the encapsulated message
 * @param peer the peer to forward the message to
 * @param msg_ctx the context of the message (hop count, bloom, etc.)
 */
static void
forward_message (const struct GNUNET_MessageHeader *msg, struct PeerInfo *peer,
                 struct DHT_MessageContext *msg_ctx)
{
  struct GNUNET_DHT_P2PRouteMessage *route_message;
  struct P2PPendingMessage *pending;
  size_t msize;
  size_t psize;
  char *route_path;

  increment_stats (STAT_ROUTE_FORWARDS);
  GNUNET_assert (peer != NULL);
  if ((msg_ctx->closest != GNUNET_YES) &&
      (peer == find_closest_peer (&msg_ctx->key)))
    increment_stats (STAT_ROUTE_FORWARDS_CLOSEST);

  msize =
      sizeof (struct GNUNET_DHT_P2PRouteMessage) + ntohs (msg->size) +
      (msg_ctx->path_history_len * sizeof (struct GNUNET_PeerIdentity));
  GNUNET_assert (msize <= GNUNET_SERVER_MAX_MESSAGE_SIZE);
  psize = sizeof (struct P2PPendingMessage) + msize;
  pending = GNUNET_malloc (psize);
  pending->msg = (struct GNUNET_MessageHeader *) &pending[1];
  pending->importance = msg_ctx->importance;
  pending->timeout = msg_ctx->timeout;
  route_message = (struct GNUNET_DHT_P2PRouteMessage *) pending->msg;
  route_message->header.size = htons (msize);
  route_message->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_P2P_ROUTE);
  route_message->options = htonl (msg_ctx->msg_options);
  route_message->hop_count = htonl (msg_ctx->hop_count + 1);
  route_message->network_size = htonl (msg_ctx->network_size);
  route_message->desired_replication_level = htonl (msg_ctx->replication);
  route_message->unique_id = GNUNET_htonll (msg_ctx->unique_id);
  if (msg_ctx->bloom != NULL)
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_bloomfilter_get_raw_data (msg_ctx->bloom,
                                                              route_message->
                                                              bloomfilter,
                                                              DHT_BLOOM_SIZE));
  memcpy (&route_message->key, &msg_ctx->key, sizeof (GNUNET_HashCode));
  memcpy (&route_message[1], msg, ntohs (msg->size));
  if (GNUNET_DHT_RO_RECORD_ROUTE ==
      (msg_ctx->msg_options & GNUNET_DHT_RO_RECORD_ROUTE))
  {
    route_message->outgoing_path_length = htonl (msg_ctx->path_history_len);
    /* Set pointer to start of enc_msg */
    route_path = (char *) &route_message[1];
    /* Offset to the end of the enc_msg */
    route_path += ntohs (msg->size);
    /* Copy the route_path after enc_msg */
    memcpy (route_path, msg_ctx->path_history,
            msg_ctx->path_history_len * sizeof (struct GNUNET_PeerIdentity));
  }
#if DEBUG_DHT > 1
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s:%s Adding pending message size %d for peer %s\n", my_short_id,
              "DHT", msize, GNUNET_i2s (&peer->id));
#endif
  peer->pending_count++;
  increment_stats ("# pending messages scheduled");
  GNUNET_CONTAINER_DLL_insert_after (peer->head, peer->tail, peer->tail,
                                     pending);
  if (peer->send_task == GNUNET_SCHEDULER_NO_TASK)
    peer->send_task = GNUNET_SCHEDULER_add_now (&try_core_send, peer);
}


/**
 * Task run to check for messages that need to be sent to a client.
 *
 * @param client a ClientList, containing the client and any messages to be sent to it
 */
static void
process_pending_messages (struct ClientList *client)
{
  if ((client->pending_head == NULL) || (client->transmit_handle != NULL))
    return;
  client->transmit_handle =
      GNUNET_SERVER_notify_transmit_ready (client->client_handle,
                                           ntohs (client->pending_head->
                                                  msg->size),
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           &send_generic_reply, client);
}

/**
 * Callback called as a result of issuing a GNUNET_SERVER_notify_transmit_ready
 * request.  A ClientList is passed as closure, take the head of the list
 * and copy it into buf, which has the result of sending the message to the
 * client.
 *
 * @param cls closure to this call
 * @param size maximum number of bytes available to send
 * @param buf where to copy the actual message to
 *
 * @return the number of bytes actually copied, 0 indicates failure
 */
static size_t
send_generic_reply (void *cls, size_t size, void *buf)
{
  struct ClientList *client = cls;
  char *cbuf = buf;
  struct PendingMessage *reply;
  size_t off;
  size_t msize;

  client->transmit_handle = NULL;
  if (buf == NULL)
  {
    /* client disconnected */
    return 0;
  }
  off = 0;
  while ((NULL != (reply = client->pending_head)) &&
         (size >= off + (msize = ntohs (reply->msg->size))))
  {
    GNUNET_CONTAINER_DLL_remove (client->pending_head, client->pending_tail,
                                 reply);
    memcpy (&cbuf[off], reply->msg, msize);
    GNUNET_free (reply);
    off += msize;
  }
  process_pending_messages (client);
#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmitted %u bytes of replies to client\n",
              (unsigned int) off);
#endif
  return off;
}


/**
 * Add a PendingMessage to the clients list of messages to be sent
 *
 * @param client the active client to send the message to
 * @param pending_message the actual message to send
 */
static void
add_pending_message (struct ClientList *client,
                     struct PendingMessage *pending_message)
{
  GNUNET_CONTAINER_DLL_insert_after (client->pending_head, client->pending_tail,
                                     client->pending_tail, pending_message);
  process_pending_messages (client);
}


/**
 * Called when a reply needs to be sent to a client, as
 * a result it found to a GET or FIND PEER request.
 *
 * @param client the client to send the reply to
 * @param message the encapsulated message to send
 * @param msg_ctx the context of the received message
 */
static void
send_reply_to_client (struct ClientList *client,
                      const struct GNUNET_MessageHeader *message,
                      struct DHT_MessageContext *msg_ctx)
{
  struct GNUNET_DHT_RouteResultMessage *reply;
  struct PendingMessage *pending_message;
  uint16_t msize;
  size_t tsize;
  char *reply_offset;

#if DEBUG_PATH
  char *path_offset;
  unsigned int i;
#endif
#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "`%s:%s': Sending reply to client.\n",
              my_short_id, "DHT");
#endif
  msize = ntohs (message->size);
  tsize =
      sizeof (struct GNUNET_DHT_RouteResultMessage) + msize +
      (msg_ctx->path_history_len * sizeof (struct GNUNET_PeerIdentity));
  if (tsize >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break_op (0);
    return;
  }
  pending_message = GNUNET_malloc (sizeof (struct PendingMessage) + tsize);
  pending_message->msg = (struct GNUNET_MessageHeader *) &pending_message[1];
  reply = (struct GNUNET_DHT_RouteResultMessage *) &pending_message[1];
  reply->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_LOCAL_ROUTE_RESULT);
  reply->header.size = htons (tsize);
  reply->outgoing_path_length = htonl (msg_ctx->path_history_len);
  reply->unique_id = GNUNET_htonll (msg_ctx->unique_id);
  memcpy (&reply->key, &msg_ctx->key, sizeof (GNUNET_HashCode));
  reply_offset = (char *) &reply[1];
  memcpy (&reply[1], message, msize);
  if (msg_ctx->path_history_len > 0)
  {
    reply_offset += msize;
    memcpy (reply_offset, msg_ctx->path_history,
            msg_ctx->path_history_len * sizeof (struct GNUNET_PeerIdentity));
  }
#if DEBUG_PATH
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Returning message with outgoing path length %d\n",
              msg_ctx->path_history_len);
  for (i = 0; i < msg_ctx->path_history_len; i++)
  {
    path_offset =
        &msg_ctx->path_history[i * sizeof (struct GNUNET_PeerIdentity)];
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Found peer %d:%s\n", i,
                GNUNET_i2s ((struct GNUNET_PeerIdentity *) path_offset));
  }
#endif
  add_pending_message (client, pending_message);
}

/**
 * Consider whether or not we would like to have this peer added to
 * our routing table.  Check whether bucket for this peer is full,
 * if so return negative; if not return positive.  Since peers are
 * only added on CORE level connect, this doesn't actually add the
 * peer to the routing table.
 *
 * @param peer the peer we are considering adding
 *
 * @return GNUNET_YES if we want this peer, GNUNET_NO if not (bucket
 *         already full)
 */
static int
consider_peer (struct GNUNET_PeerIdentity *peer)
{
  int bucket;

  if ((GNUNET_YES ==
       GNUNET_CONTAINER_multihashmap_contains (all_known_peers,
                                               &peer->hashPubKey)) ||
      (0 == memcmp (&my_identity, peer, sizeof (struct GNUNET_PeerIdentity))))
    return GNUNET_NO;           /* We already know this peer (are connected even!) */
  bucket = find_current_bucket (&peer->hashPubKey);

  if ((k_buckets[bucket].peers_size < bucket_size) ||
      ((bucket == lowest_bucket) && (lowest_bucket > 0)))
    return GNUNET_YES;

  return GNUNET_NO;
}


/**
 * Task used to remove forwarding entries, either
 * after timeout, when full, or on shutdown.
 *
 * @param cls the entry to remove
 * @param tc context, reason, etc.
 */
static void
remove_forward_entry (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct DHTRouteSource *source_info = cls;
  struct DHTQueryRecord *record;

  source_info = GNUNET_CONTAINER_heap_remove_node (source_info->hnode);
  record = source_info->record;
  GNUNET_CONTAINER_DLL_remove (record->head, record->tail, source_info);

  if (record->head == NULL)     /* No more entries in DLL */
  {
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multihashmap_remove (forward_list.hashmap,
                                                         &record->key, record));
    GNUNET_free (record);
  }
  if (source_info->find_peers_responded != NULL)
    GNUNET_CONTAINER_bloomfilter_free (source_info->find_peers_responded);
  GNUNET_free (source_info);
}

/**
 * Main function that handles whether or not to route a result
 * message to other peers, or to send to our local client.
 *
 * @param msg the result message to be routed
 * @param msg_ctx context of the message we are routing
 *
 * @return the number of peers the message was routed to,
 *         GNUNET_SYSERR on failure
 */
static int
route_result_message (struct GNUNET_MessageHeader *msg,
                      struct DHT_MessageContext *msg_ctx)
{
  struct GNUNET_PeerIdentity new_peer;
  struct DHTQueryRecord *record;
  struct DHTRouteSource *pos;
  struct PeerInfo *peer_info;
  const struct GNUNET_MessageHeader *hello_msg;

#if DEBUG_DHT > 1
  unsigned int i;
#endif

  increment_stats (STAT_RESULTS);
  /**
   * If a find peer result message is received and contains a valid
   * HELLO for another peer, offer it to the transport service.
   */
  if (ntohs (msg->type) == GNUNET_MESSAGE_TYPE_DHT_FIND_PEER_RESULT)
  {
    if (ntohs (msg->size) <= sizeof (struct GNUNET_MessageHeader))
      GNUNET_break_op (0);

    hello_msg = &msg[1];
    if ((ntohs (hello_msg->type) != GNUNET_MESSAGE_TYPE_HELLO) ||
        (GNUNET_SYSERR ==
         GNUNET_HELLO_get_id ((const struct GNUNET_HELLO_Message *) hello_msg,
                              &new_peer)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "%s:%s Received non-HELLO message type in find peer result message!\n",
                  my_short_id, "DHT");
      GNUNET_break_op (0);
      return GNUNET_NO;
    }
    else                        /* We have a valid hello, and peer id stored in new_peer */
    {
      find_peer_context.count++;
      increment_stats (STAT_FIND_PEER_REPLY);
      if (GNUNET_YES == consider_peer (&new_peer))
      {
        increment_stats (STAT_HELLOS_PROVIDED);
        GNUNET_TRANSPORT_offer_hello (transport_handle, hello_msg, NULL, NULL);
        GNUNET_CORE_peer_request_connect (coreAPI, &new_peer, NULL, NULL);
      }
    }
  }

  if (malicious_dropper == GNUNET_YES)
    record = NULL;
  else
    record =
        GNUNET_CONTAINER_multihashmap_get (forward_list.hashmap, &msg_ctx->key);

  if (record == NULL)           /* No record of this message! */
  {
#if DEBUG_DHT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "`%s:%s': Have no record of response key %s uid %llu\n",
                my_short_id, "DHT", GNUNET_h2s (&msg_ctx->key),
                msg_ctx->unique_id);
#endif
#if DEBUG_DHT_ROUTING
    if ((debug_routes_extended) && (dhtlog_handle != NULL))
    {
      dhtlog_handle->insert_route (NULL, msg_ctx->unique_id, DHTLOG_RESULT,
                                   msg_ctx->hop_count, GNUNET_SYSERR,
                                   &my_identity, &msg_ctx->key, msg_ctx->peer,
                                   NULL);
    }
#endif
    if (msg_ctx->bloom != NULL)
    {
      GNUNET_CONTAINER_bloomfilter_free (msg_ctx->bloom);
      msg_ctx->bloom = NULL;
    }
    return 0;
  }

  pos = record->head;
  while (pos != NULL)
  {
#if STRICT_FORWARDING
    if (ntohs (msg->type) == GNUNET_MESSAGE_TYPE_DHT_FIND_PEER_RESULT)  /* If we have already forwarded this peer id, don't do it again! */
    {
      if (GNUNET_YES ==
          GNUNET_CONTAINER_bloomfilter_test (pos->find_peers_responded,
                                             &new_peer.hashPubKey))
      {
        increment_stats ("# find peer responses NOT forwarded (bloom match)");
        pos = pos->next;
        continue;
      }
      else
        GNUNET_CONTAINER_bloomfilter_add (pos->find_peers_responded,
                                          &new_peer.hashPubKey);
    }
#endif

    if (0 == memcmp (&pos->source, &my_identity, sizeof (struct GNUNET_PeerIdentity)))  /* Local client (or DHT) initiated request! */
    {
#if DEBUG_DHT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "`%s:%s': Sending response key %s uid %llu to client\n",
                  my_short_id, "DHT", GNUNET_h2s (&msg_ctx->key),
                  msg_ctx->unique_id);
#endif
#if DEBUG_DHT_ROUTING
      if ((debug_routes_extended) && (dhtlog_handle != NULL))
      {
        dhtlog_handle->insert_route (NULL, msg_ctx->unique_id, DHTLOG_RESULT,
                                     msg_ctx->hop_count, GNUNET_YES,
                                     &my_identity, &msg_ctx->key, msg_ctx->peer,
                                     NULL);
      }
#endif
      increment_stats (STAT_RESULTS_TO_CLIENT);
      if (ntohs (msg->type) == GNUNET_MESSAGE_TYPE_DHT_GET_RESULT)
        increment_stats (STAT_GET_REPLY);
#if DEBUG_DHT > 1
      for (i = 0; i < msg_ctx->path_history_len; i++)
      {
        char *path_offset;

        path_offset =
            &msg_ctx->path_history[i * sizeof (struct GNUNET_PeerIdentity)];
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "(before client) Key %s Found peer %d:%s\n",
                    GNUNET_h2s (&msg_ctx->key), i,
                    GNUNET_i2s ((struct GNUNET_PeerIdentity *) path_offset));
      }
#endif
      send_reply_to_client (pos->client, msg, msg_ctx);
    }
    else                        /* Send to peer */
    {
      peer_info = find_peer_by_id (&pos->source);
      if (peer_info == NULL)    /* Didn't find the peer in our routing table, perhaps peer disconnected! */
      {
        pos = pos->next;
        continue;
      }

      if (msg_ctx->bloom == NULL)
        msg_ctx->bloom =
            GNUNET_CONTAINER_bloomfilter_init (NULL, DHT_BLOOM_SIZE,
                                               DHT_BLOOM_K);
      GNUNET_CONTAINER_bloomfilter_add (msg_ctx->bloom,
                                        &my_identity.hashPubKey);
      if ((GNUNET_NO ==
           GNUNET_CONTAINER_bloomfilter_test (msg_ctx->bloom,
                                              &peer_info->id.hashPubKey)))
      {
#if DEBUG_DHT
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "`%s:%s': Forwarding response key %s uid %llu to peer %s\n",
                    my_short_id, "DHT", GNUNET_h2s (&msg_ctx->key),
                    msg_ctx->unique_id, GNUNET_i2s (&peer_info->id));
#endif
#if DEBUG_DHT_ROUTING
        if ((debug_routes_extended) && (dhtlog_handle != NULL))
        {
          dhtlog_handle->insert_route (NULL, msg_ctx->unique_id, DHTLOG_RESULT,
                                       msg_ctx->hop_count, GNUNET_NO,
                                       &my_identity, &msg_ctx->key,
                                       msg_ctx->peer, &pos->source);
        }
#endif
        forward_result_message (msg, peer_info, msg_ctx);
        /* Try removing forward entries after sending once, only allows ONE response per request */
        if (pos->delete_task != GNUNET_SCHEDULER_NO_TASK)
        {
          GNUNET_SCHEDULER_cancel (pos->delete_task);
          pos->delete_task =
              GNUNET_SCHEDULER_add_now (&remove_forward_entry, pos);
        }
      }
      else
      {
#if DEBUG_DHT
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "`%s:%s': NOT Forwarding response (bloom match) key %s uid %llu to peer %s\n",
                    my_short_id, "DHT", GNUNET_h2s (&msg_ctx->key),
                    msg_ctx->unique_id, GNUNET_i2s (&peer_info->id));
#endif
      }
    }
    pos = pos->next;
  }
  if (msg_ctx->bloom != NULL)
  {
    GNUNET_CONTAINER_bloomfilter_free (msg_ctx->bloom);
    msg_ctx->bloom = NULL;
  }
  return 0;
}


/**
 * Iterator for local get request results,
 *
 * @param cls closure for iterator, a DatacacheGetContext
 * @param exp when does this value expire?
 * @param key the key this data is stored under
 * @param size the size of the data identified by key
 * @param data the actual data
 * @param type the type of the data
 *
 * @return GNUNET_OK to continue iteration, anything else
 * to stop iteration.
 */
static int
datacache_get_iterator (void *cls, struct GNUNET_TIME_Absolute exp,
                        const GNUNET_HashCode * key, size_t size,
                        const char *data, enum GNUNET_BLOCK_Type type)
{
  struct DHT_MessageContext *msg_ctx = cls;
  struct DHT_MessageContext new_msg_ctx;
  struct GNUNET_DHT_GetResultMessage *get_result;
  enum GNUNET_BLOCK_EvaluationResult eval;
  const struct DHTPutEntry *put_entry;
  int get_size;
  char *path_offset;

#if DEBUG_PATH
  unsigned int i;
#endif

#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s:%s': Received `%s' response from datacache\n", my_short_id,
              "DHT", "GET");
#endif

  put_entry = (const struct DHTPutEntry *) data;

  if (size !=
      sizeof (struct DHTPutEntry) + put_entry->data_size +
      (put_entry->path_length * sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Path + data size doesn't add up for data inserted into datacache!\nData size %d, path length %d, expected %d, got %d\n",
                put_entry->data_size, put_entry->path_length,
                sizeof (struct DHTPutEntry) + put_entry->data_size +
                (put_entry->path_length * sizeof (struct GNUNET_PeerIdentity)),
                size);
    msg_ctx->do_forward = GNUNET_NO;
    return GNUNET_OK;
  }

  eval =
      GNUNET_BLOCK_evaluate (block_context, type, key, &msg_ctx->reply_bf,
                             msg_ctx->reply_bf_mutator, msg_ctx->xquery,
                             msg_ctx->xquery_size, &put_entry[1],
                             put_entry->data_size);

  switch (eval)
  {
  case GNUNET_BLOCK_EVALUATION_OK_LAST:
    msg_ctx->do_forward = GNUNET_NO;
  case GNUNET_BLOCK_EVALUATION_OK_MORE:
    memcpy (&new_msg_ctx, msg_ctx, sizeof (struct DHT_MessageContext));
    if (GNUNET_DHT_RO_RECORD_ROUTE ==
        (msg_ctx->msg_options & GNUNET_DHT_RO_RECORD_ROUTE))
    {
      new_msg_ctx.msg_options = GNUNET_DHT_RO_RECORD_ROUTE;
#if DEBUG_PATH
      for (i = 0; i < new_msg_ctx.path_history_len; i++)
      {
        path_offset =
            &new_msg_ctx.path_history[i * sizeof (struct GNUNET_PeerIdentity)];
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "(get_iterator) Key %s Found peer %d:%s\n",
                    GNUNET_h2s (&msg_ctx->key), i,
                    GNUNET_i2s ((struct GNUNET_PeerIdentity *) path_offset));
      }
#endif
    }

    get_size =
        sizeof (struct GNUNET_DHT_GetResultMessage) + put_entry->data_size +
        (put_entry->path_length * sizeof (struct GNUNET_PeerIdentity));
    get_result = GNUNET_malloc (get_size);
    get_result->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_GET_RESULT);
    get_result->header.size = htons (get_size);
    get_result->expiration = GNUNET_TIME_absolute_hton (exp);
    get_result->type = htons (type);
    get_result->put_path_length = htons (put_entry->path_length);
    path_offset = (char *) &put_entry[1];
    path_offset += put_entry->data_size;
#if DEBUG_PATH
    for (i = 0; i < put_entry->path_length; i++)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "(get_iterator PUT path) Key %s Found peer %d:%s\n",
                  GNUNET_h2s (&msg_ctx->key), i,
                  GNUNET_i2s ((struct GNUNET_PeerIdentity *)
                              &path_offset[i *
                                           sizeof (struct
                                                   GNUNET_PeerIdentity)]));
    }
#endif
    /* Copy the actual data and the path_history to the end of the get result */
    memcpy (&get_result[1], &put_entry[1],
            put_entry->data_size +
            (put_entry->path_length * sizeof (struct GNUNET_PeerIdentity)));
    new_msg_ctx.peer = &my_identity;
    new_msg_ctx.bloom = NULL;
    new_msg_ctx.hop_count = 0;
    new_msg_ctx.importance = DHT_DEFAULT_P2P_IMPORTANCE + 2;   /* Make result routing a higher priority */
    new_msg_ctx.timeout = DHT_DEFAULT_P2P_TIMEOUT;
    increment_stats (STAT_GET_RESPONSE_START);
    route_result_message (&get_result->header, &new_msg_ctx);
    GNUNET_free (get_result);
    break;
  case GNUNET_BLOCK_EVALUATION_OK_DUPLICATE:
#if DEBUG_DHT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "`%s:%s': Duplicate block error\n",
                my_short_id, "DHT");
#endif
    break;
  case GNUNET_BLOCK_EVALUATION_RESULT_INVALID:
#if DEBUG_DHT
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "`%s:%s': Invalid request error\n",
                my_short_id, "DHT");
#endif
    break;
  case GNUNET_BLOCK_EVALUATION_REQUEST_VALID:
#if DEBUG_DHT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "`%s:%s': Valid request, no results.\n", my_short_id, "DHT");
#endif
    GNUNET_break (0);
    break;
  case GNUNET_BLOCK_EVALUATION_REQUEST_INVALID:
    GNUNET_break_op (0);
    msg_ctx->do_forward = GNUNET_NO;
    break;
  case GNUNET_BLOCK_EVALUATION_TYPE_NOT_SUPPORTED:
#if DEBUG_DHT
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "`%s:%s': Unsupported block type (%u) in response!\n",
                my_short_id, "DHT", type);
#endif
    /* msg_ctx->do_forward = GNUNET_NO;  // not sure... */
    break;
  }
  return GNUNET_OK;
}


/**
 * Main function that handles whether or not to route a message to other
 * peers.
 *
 * @param msg the message to be routed
 * @param msg_ctx the context containing all pertinent information about the message
 */
static void
route_message (const struct GNUNET_MessageHeader *msg,
               struct DHT_MessageContext *msg_ctx);


/**
 * Server handler for all dht get requests, look for data,
 * if found, send response either to clients or other peers.
 *
 * @param msg the actual get message
 * @param msg_ctx struct containing pertinent information about the get request
 *
 * @return number of items found for GET request
 */
static unsigned int
handle_dht_get (const struct GNUNET_MessageHeader *msg,
                struct DHT_MessageContext *msg_ctx)
{
  const struct GNUNET_DHT_GetMessage *get_msg;
  uint16_t msize;
  uint16_t bf_size;
  unsigned int results;
  const char *end;
  enum GNUNET_BLOCK_Type type;

  msize = ntohs (msg->size);
  if (msize < sizeof (struct GNUNET_DHT_GetMessage))
  {
    GNUNET_break (0);
    return 0;
  }
  get_msg = (const struct GNUNET_DHT_GetMessage *) msg;
  bf_size = ntohs (get_msg->bf_size);
  msg_ctx->xquery_size = ntohs (get_msg->xquery_size);
  msg_ctx->reply_bf_mutator = get_msg->bf_mutator;
  if (msize !=
      sizeof (struct GNUNET_DHT_GetMessage) + bf_size + msg_ctx->xquery_size)
  {
    GNUNET_break_op (0);
    return 0;
  }
  end = (const char *) &get_msg[1];
  if (msg_ctx->xquery_size == 0)
  {
    msg_ctx->xquery = NULL;
  }
  else
  {
    msg_ctx->xquery = (const void *) end;
    end += msg_ctx->xquery_size;
  }
  if (bf_size == 0)
  {
    msg_ctx->reply_bf = NULL;
  }
  else
  {
    msg_ctx->reply_bf =
        GNUNET_CONTAINER_bloomfilter_init (end, bf_size,
                                           GNUNET_DHT_GET_BLOOMFILTER_K);
  }
  type = (enum GNUNET_BLOCK_Type) ntohl (get_msg->type);
#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s:%s': Received `%s' request, message type %u, key %s, uid %llu\n",
              my_short_id, "DHT", "GET", type, GNUNET_h2s (&msg_ctx->key),
              msg_ctx->unique_id);
#endif
  increment_stats (STAT_GETS);
  results = 0;
#if HAVE_MALICIOUS
  if (type == GNUNET_BLOCK_DHT_MALICIOUS_MESSAGE_TYPE)
  {
    GNUNET_CONTAINER_bloomfilter_free (msg_ctx->reply_bf);
    return results;
  }
#endif
  msg_ctx->do_forward = GNUNET_YES;
  if (datacache != NULL)
    results =
        GNUNET_DATACACHE_get (datacache, &msg_ctx->key, type,
                              &datacache_get_iterator, msg_ctx);
#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s:%s': Found %d results for `%s' request uid %llu\n",
              my_short_id, "DHT", results, "GET", msg_ctx->unique_id);
#endif
  if (results >= 1)
  {
#if DEBUG_DHT_ROUTING
    if ((debug_routes) && (dhtlog_handle != NULL))
    {
      dhtlog_handle->insert_query (NULL, msg_ctx->unique_id, DHTLOG_GET,
                                   msg_ctx->hop_count, GNUNET_YES, &my_identity,
                                   &msg_ctx->key);
    }

    if ((debug_routes_extended) && (dhtlog_handle != NULL))
    {
      dhtlog_handle->insert_route (NULL, msg_ctx->unique_id, DHTLOG_ROUTE,
                                   msg_ctx->hop_count, GNUNET_YES, &my_identity,
                                   &msg_ctx->key, msg_ctx->peer, NULL);
    }
#endif
  }
  else
  {
    /* check query valid */
    if (GNUNET_BLOCK_EVALUATION_REQUEST_INVALID ==
        GNUNET_BLOCK_evaluate (block_context, type, &msg_ctx->key,
                               &msg_ctx->reply_bf, msg_ctx->reply_bf_mutator,
                               msg_ctx->xquery, msg_ctx->xquery_size, NULL, 0))
    {
      GNUNET_break_op (0);
      msg_ctx->do_forward = GNUNET_NO;
    }
  }

  if (msg_ctx->hop_count == 0)  /* Locally initiated request */
  {
#if DEBUG_DHT_ROUTING
    if ((debug_routes) && (dhtlog_handle != NULL))
    {
      dhtlog_handle->insert_query (NULL, msg_ctx->unique_id, DHTLOG_GET,
                                   msg_ctx->hop_count, GNUNET_NO, &my_identity,
                                   &msg_ctx->key);
    }
#endif
  }
  if (msg_ctx->do_forward == GNUNET_YES)
    route_message (msg, msg_ctx);
  GNUNET_CONTAINER_bloomfilter_free (msg_ctx->reply_bf);
  return results;
}


static void
remove_recent_find_peer (void *cls,
                         const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_HashCode *key = cls;

  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove
                 (recent_find_peer_requests, key, NULL));
  GNUNET_free (key);
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

#if RESTRICT_FIND_PEER

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
#endif

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
  new_msg_ctx->peer = &my_identity;
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
#if DEBUG_DHT_ROUTING
  if ((debug_routes) && (dhtlog_handle != NULL))
  {
    dhtlog_handle->insert_query (NULL, msg_ctx->unique_id, DHTLOG_FIND_PEER,
                                 msg_ctx->hop_count, GNUNET_YES, &my_identity,
                                 &msg_ctx->key);
  }
#endif
  GNUNET_free_non_null (other_hello);
  GNUNET_free (find_peer_result);
  route_message (find_msg, msg_ctx);
}


/**
 * Server handler for initiating local dht put requests
 *
 * @param msg the actual put message
 * @param msg_ctx struct containing pertinent information about the request
 */
static void
handle_dht_put (const struct GNUNET_MessageHeader *msg,
                struct DHT_MessageContext *msg_ctx)
{
  const struct GNUNET_DHT_PutMessage *put_msg;
  struct DHTPutEntry *put_entry;
  unsigned int put_size;
  char *path_offset;
  enum GNUNET_BLOCK_Type put_type;
  size_t data_size;
  int ret;
  GNUNET_HashCode key;
  struct DHTQueryRecord *record;

  GNUNET_assert (ntohs (msg->size) >= sizeof (struct GNUNET_DHT_PutMessage));

  put_msg = (const struct GNUNET_DHT_PutMessage *) msg;
  put_type = (enum GNUNET_BLOCK_Type) ntohl (put_msg->type);
#if HAVE_MALICIOUS
  if (put_type == GNUNET_BLOCK_DHT_MALICIOUS_MESSAGE_TYPE)
  {
#if DEBUG_DHT_ROUTING
    if ((debug_routes_extended) && (dhtlog_handle != NULL))
    {
          /** Log routes that die due to high load! */
      dhtlog_handle->insert_route (NULL, msg_ctx->unique_id, DHTLOG_ROUTE,
                                   msg_ctx->hop_count, GNUNET_SYSERR,
                                   &my_identity, &msg_ctx->key, msg_ctx->peer,
                                   NULL);
    }
#endif
    return;
  }
#endif
  data_size =
      ntohs (put_msg->header.size) - sizeof (struct GNUNET_DHT_PutMessage);
  ret =
      GNUNET_BLOCK_get_key (block_context, put_type, &put_msg[1], data_size,
                            &key);
  if (GNUNET_NO == ret)
  {
#if DEBUG_DHT_ROUTING
    if ((debug_routes_extended) && (dhtlog_handle != NULL))
    {
      dhtlog_handle->insert_route (NULL, msg_ctx->unique_id, DHTLOG_ROUTE,
                                   msg_ctx->hop_count, GNUNET_SYSERR,
                                   &my_identity, &msg_ctx->key, msg_ctx->peer,
                                   NULL);
    }
#endif
    /* invalid reply */
    GNUNET_break_op (0);
    return;
  }
  if ((GNUNET_YES == ret) &&
      (0 != memcmp (&key, &msg_ctx->key, sizeof (GNUNET_HashCode))))
  {
#if DEBUG_DHT_ROUTING
    if ((debug_routes_extended) && (dhtlog_handle != NULL))
    {
      dhtlog_handle->insert_route (NULL, msg_ctx->unique_id, DHTLOG_ROUTE,
                                   msg_ctx->hop_count, GNUNET_SYSERR,
                                   &my_identity, &msg_ctx->key, msg_ctx->peer,
                                   NULL);
    }
#endif
    /* invalid wrapper: key mismatch! */
    GNUNET_break_op (0);
    return;
  }
  /* ret == GNUNET_SYSERR means that there is no known relationship between
   * data and the key, so we cannot check it */
#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s:%s': Received `%s' request (inserting data!), message type %d, key %s, uid %llu\n",
              my_short_id, "DHT", "PUT", put_type, GNUNET_h2s (&msg_ctx->key),
              msg_ctx->unique_id);
#endif
#if DEBUG_DHT_ROUTING
  if (msg_ctx->hop_count == 0)  /* Locally initiated request */
  {
    if ((debug_routes) && (dhtlog_handle != NULL))
    {
      dhtlog_handle->insert_query (NULL, msg_ctx->unique_id, DHTLOG_PUT,
                                   msg_ctx->hop_count, GNUNET_NO, &my_identity,
                                   &msg_ctx->key);
    }
  }
#endif

  record = GNUNET_CONTAINER_multihashmap_get(forward_list.hashmap,
                                             &msg_ctx->key);
  if (NULL != record)
  {
    struct DHTRouteSource *pos;
    struct GNUNET_DHT_GetResultMessage *get_result;
    struct DHT_MessageContext new_msg_ctx;
    size_t get_size;

    pos = record->head;
    while (pos != NULL)
    {
      /* TODO: do only for local started requests? or also for remote peers? */
      /* TODO: include this in statistics? under what? */
      /* TODO: reverse order of path_history? */
      if (NULL == pos->client)
      {
        pos = pos->next;
        continue;
      }

      memcpy (&new_msg_ctx, msg_ctx, sizeof (struct DHT_MessageContext));
      if (GNUNET_DHT_RO_RECORD_ROUTE ==
          (msg_ctx->msg_options & GNUNET_DHT_RO_RECORD_ROUTE))
      {
        new_msg_ctx.msg_options = GNUNET_DHT_RO_RECORD_ROUTE;
#if DEBUG_PATH
        for (i = 0; i < new_msg_ctx.path_history_len; i++)
        {
          path_offset =
              &new_msg_ctx.path_history[i * sizeof (struct GNUNET_PeerIdentity)];
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "(put for active get) Key %s Found peer %d:%s\n",
                      GNUNET_h2s (&msg_ctx->key), i,
                      GNUNET_i2s ((struct GNUNET_PeerIdentity *) path_offset));
        }
#endif
      }

      get_size =
          sizeof (struct GNUNET_DHT_GetResultMessage) + data_size +
          (msg_ctx->path_history_len * sizeof (struct GNUNET_PeerIdentity));
      get_result = GNUNET_malloc (get_size);
      get_result->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_GET_RESULT);
      get_result->header.size = htons (get_size);
      get_result->expiration = put_msg->expiration;
      get_result->type = put_msg->type;
      get_result->put_path_length = htons (msg_ctx->path_history_len);

      /* Copy the actual data and the path_history to the end of the get result */
      memcpy (&get_result[1], &put_msg[1], data_size);
      path_offset = (char *) &get_result[1];
      path_offset += data_size;
      memcpy (path_offset, msg_ctx->path_history,
              msg_ctx->path_history_len * sizeof (struct GNUNET_PeerIdentity));
      new_msg_ctx.peer = &my_identity;
      new_msg_ctx.bloom = NULL;
      new_msg_ctx.hop_count = 0;
      /* Make result routing a higher priority */
      new_msg_ctx.importance = DHT_DEFAULT_P2P_IMPORTANCE + 2;
      new_msg_ctx.timeout = DHT_DEFAULT_P2P_TIMEOUT;
      new_msg_ctx.unique_id = pos->uid;
      send_reply_to_client(pos->client, &get_result->header, &new_msg_ctx);
      GNUNET_free (get_result);
      pos = pos->next;
    }
  }

  if (msg_ctx->closest != GNUNET_YES)
  {
    route_message (msg, msg_ctx);
    return;
  }

#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s:%s': Received `%s' request (inserting data!), message type %d, key %s, uid %llu\n",
              my_short_id, "DHT", "PUT", put_type, GNUNET_h2s (&msg_ctx->key),
              msg_ctx->unique_id);
#endif

#if DEBUG_DHT_ROUTING
  if ((debug_routes_extended) && (dhtlog_handle != NULL))
  {
    dhtlog_handle->insert_route (NULL, msg_ctx->unique_id, DHTLOG_ROUTE,
                                 msg_ctx->hop_count, GNUNET_YES, &my_identity,
                                 &msg_ctx->key, msg_ctx->peer, NULL);
  }

  if ((debug_routes) && (dhtlog_handle != NULL))
  {
    dhtlog_handle->insert_query (NULL, msg_ctx->unique_id, DHTLOG_PUT,
                                 msg_ctx->hop_count, GNUNET_YES, &my_identity,
                                 &msg_ctx->key);
  }
#endif

  increment_stats (STAT_PUTS_INSERTED);
  if (datacache != NULL)
  {
    /* Put size is actual data size plus struct overhead plus path length (if any) */
    put_size =
        data_size + sizeof (struct DHTPutEntry) +
        (msg_ctx->path_history_len * sizeof (struct GNUNET_PeerIdentity));
    put_entry = GNUNET_malloc (put_size);
    put_entry->data_size = data_size;
    put_entry->path_length = msg_ctx->path_history_len;
    /* Copy data to end of put entry */
    memcpy (&put_entry[1], &put_msg[1], data_size);
    if (msg_ctx->path_history_len > 0)
    {
      /* Copy path after data */
      path_offset = (char *) &put_entry[1];
      path_offset += data_size;
      memcpy (path_offset, msg_ctx->path_history,
              msg_ctx->path_history_len * sizeof (struct GNUNET_PeerIdentity));
    }

    ret =
        GNUNET_DATACACHE_put (datacache, &msg_ctx->key, put_size,
                              (const char *) put_entry, put_type,
                              GNUNET_TIME_absolute_ntoh (put_msg->expiration));
    GNUNET_free (put_entry);
  }
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "`%s:%s': %s request received, but have no datacache!\n",
                my_short_id, "DHT", "PUT");

  if (stop_on_closest == GNUNET_NO)
    route_message (msg, msg_ctx);
}


/**
 * To how many peers should we (on average)
 * forward the request to obtain the desired
 * target_replication count (on average).
 *
 * returns: target_replication / (est. hops) + (target_replication * hop_count)
 * where est. hops is typically 2 * the routing table depth
 *
 * @param hop_count number of hops the message has traversed
 * @param target_replication the number of total paths desired
 *
 * @return Some number of peers to forward the message to
 */
static unsigned int
get_forward_count (unsigned int hop_count, size_t target_replication)
{
  uint32_t random_value;
  unsigned int forward_count;
  float target_value;

  /**
   * If we are behaving in strict kademlia mode, send multiple initial requests,
   * but then only send to 1 or 0 peers based strictly on the number of hops.
   */
  if (strict_kademlia == GNUNET_YES)
  {
    if (hop_count == 0)
      return kademlia_replication;
    if (hop_count < log_of_network_size_estimate * 2.0)
      return 1;
    return 0;
  }

  if (hop_count > log_of_network_size_estimate * 2.0)
  {
    if (GNUNET_YES == paper_forwarding)
    {
      /* Once we have reached our ideal number of hops, don't stop forwarding! */
      return 1;
    }
#if DEBUG_DHT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Hop count too high (est %f, lowest %d), NOT Forwarding request\n",
                log_of_network_size_estimate * 2.0, lowest_bucket);
#endif
    return 0;
  }

  if (GNUNET_YES == paper_forwarding)
  {
    /* FIXME: re-run replication trials with this formula */
    target_value =
        1 + (target_replication - 1.0) / (log_of_network_size_estimate +
                                          ((float) (target_replication - 1.0) *
                                           hop_count));
    /* Set forward count to floor of target_value */
    forward_count = (unsigned int) target_value;
    /* Subtract forward_count (floor) from target_value (yields value between 0 and 1) */
    target_value = target_value - forward_count;
    random_value =
        GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_STRONG, UINT32_MAX);

    if (random_value < (target_value * UINT32_MAX))
      forward_count += 1;
  }
  else
  {
    random_value = 0;
    forward_count = 1;
    target_value =
        target_replication / (log_of_network_size_estimate +
                              ((float) target_replication * hop_count));
    if (target_value > 1)
    {
      /* Set forward count to floor of target_value */
      forward_count = (unsigned int) target_value;
      /* Subtract forward_count (floor) from target_value (yields value between 0 and 1) */
      target_value = target_value - forward_count;
    }
    else
      random_value =
          GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_STRONG, UINT32_MAX);

    if (random_value < (target_value * UINT32_MAX))
      forward_count += 1;
  }

  return forward_count;
}


/**
 * Check whether my identity is closer than any known peers.
 * If a non-null bloomfilter is given, check if this is the closest
 * peer that hasn't already been routed to.
 *
 * @param target hash code to check closeness to
 * @param bloom bloomfilter, exclude these entries from the decision
 * @return GNUNET_YES if node location is closest,
 *         GNUNET_NO otherwise.
 */
static int
am_closest_peer (const GNUNET_HashCode * target,
                 struct GNUNET_CONTAINER_BloomFilter *bloom)
{
  int bits;
  int other_bits;
  int bucket_num;
  int count;
  struct PeerInfo *pos;
  unsigned int my_distance;

  if (0 == memcmp (&my_identity.hashPubKey, target, sizeof (GNUNET_HashCode)))
    return GNUNET_YES;

  bucket_num = find_current_bucket (target);

  bits = GNUNET_CRYPTO_hash_matching_bits (&my_identity.hashPubKey, target);
  my_distance = distance (&my_identity.hashPubKey, target);
  pos = k_buckets[bucket_num].head;
  count = 0;
  while ((pos != NULL) && (count < bucket_size))
  {
    if ((bloom != NULL) &&
        (GNUNET_YES ==
         GNUNET_CONTAINER_bloomfilter_test (bloom, &pos->id.hashPubKey)))
    {
      pos = pos->next;
      continue;                 /* Skip already checked entries */
    }

    other_bits = GNUNET_CRYPTO_hash_matching_bits (&pos->id.hashPubKey, target);
    if (other_bits > bits)
      return GNUNET_NO;
    else if (other_bits == bits)        /* We match the same number of bits */
    {
      if (strict_kademlia != GNUNET_YES)        /* Return that we at as close as any other peer */
        return GNUNET_YES;
      if (distance (&pos->id.hashPubKey, target) < my_distance) /* Check all known peers, only return if we are the true closest */
        return GNUNET_NO;
    }
    pos = pos->next;
  }

  /* No peers closer, we are the closest! */
  return GNUNET_YES;
}


/**
 * Select a peer from the routing table that would be a good routing
 * destination for sending a message for "target".  The resulting peer
 * must not be in the set of blocked peers.<p>
 *
 * Note that we should not ALWAYS select the closest peer to the
 * target, peers further away from the target should be chosen with
 * exponentially declining probability.
 *
 * @param target the key we are selecting a peer to route to
 * @param bloom a bloomfilter containing entries this request has seen already
 * @param hops how many hops has this message traversed thus far
 *
 * @return Peer to route to, or NULL on error
 */
static struct PeerInfo *
select_peer (const GNUNET_HashCode * target,
             struct GNUNET_CONTAINER_BloomFilter *bloom, unsigned int hops)
{
  unsigned int bc;
  unsigned int count;
  unsigned int selected;
  struct PeerInfo *pos;
  unsigned int distance;
  unsigned int largest_distance;
  struct PeerInfo *chosen;

  /** If we are doing kademlia routing (saves some cycles) */
  if ((strict_kademlia == GNUNET_YES) || (hops >= log_of_network_size_estimate))
  {
    /* greedy selection (closest peer that is not in bloomfilter) */
    largest_distance = 0;
    chosen = NULL;
    for (bc = lowest_bucket; bc < MAX_BUCKETS; bc++)
    {
      pos = k_buckets[bc].head;
      count = 0;
      while ((pos != NULL) && (count < bucket_size))
      {
        /* If we are doing strict Kademlia routing, then checking the bloomfilter is basically cheating! */
        if (GNUNET_NO ==
            GNUNET_CONTAINER_bloomfilter_test (bloom, &pos->id.hashPubKey))
        {
          distance = inverse_distance (target, &pos->id.hashPubKey);
          if (distance > largest_distance)
          {
            chosen = pos;
            largest_distance = distance;
          }
        }
        count++;
        pos = pos->next;
      }
    }
    if ((largest_distance > 0) && (chosen != NULL))
    {
      GNUNET_CONTAINER_bloomfilter_add (bloom, &chosen->id.hashPubKey);
      return chosen;
    }
    return NULL;                /* no peer available or we are the closest */
  }


  /* select "random" peer */
  /* count number of peers that are available and not filtered */
  count = 0;
  for (bc = lowest_bucket; bc < MAX_BUCKETS; bc++)
  {
    pos = k_buckets[bc].head;
    while ((pos != NULL) && (count < bucket_size))
    {
      if (GNUNET_YES ==
          GNUNET_CONTAINER_bloomfilter_test (bloom, &pos->id.hashPubKey))
      {
        pos = pos->next;
        continue;               /* Ignore bloomfiltered peers */
      }
      count++;
      pos = pos->next;
    }
  }
  if (count == 0)               /* No peers to select from! */
  {
    increment_stats ("# failed to select peer");
    return NULL;
  }
  /* Now actually choose a peer */
  selected = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, count);
  count = 0;
  for (bc = lowest_bucket; bc < MAX_BUCKETS; bc++)
  {
    pos = k_buckets[bc].head;
    while ((pos != NULL) && (count < bucket_size))
    {
      if (GNUNET_YES ==
          GNUNET_CONTAINER_bloomfilter_test (bloom, &pos->id.hashPubKey))
      {
        pos = pos->next;
        continue;               /* Ignore bloomfiltered peers */
      }
      if (0 == selected--)
        return pos;
      pos = pos->next;
    }
  }
  GNUNET_break (0);
  return NULL;
}


/**
 * Task used to remove recent entries, either
 * after timeout, when full, or on shutdown.
 *
 * @param cls the entry to remove
 * @param tc context, reason, etc.
 */
static void
remove_recent (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct RecentRequest *req = cls;
  static GNUNET_HashCode hash;

  GNUNET_assert (req != NULL);
  hash_from_uid (req->uid, &hash);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (recent.hashmap, &hash,
                                                       req));
  GNUNET_CONTAINER_heap_remove_node (req->heap_node);
  GNUNET_CONTAINER_bloomfilter_free (req->bloom);
  GNUNET_free (req);

  /*
   * if ( (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0) && (0 == GNUNET_CONTAINER_multihashmap_size(recent.hashmap)) && (0 == GNUNET_CONTAINER_heap_get_size(recent.minHeap)))
   * {
   * GNUNET_CONTAINER_multihashmap_destroy(recent.hashmap);
   * GNUNET_CONTAINER_heap_destroy(recent.minHeap);
   * }
   */
}

/**
 * Remember this routing request so that if a reply is
 * received we can either forward it to the correct peer
 * or return the result locally.
 *
 * @param msg_ctx Context of the route request
 *
 * @return GNUNET_YES if this response was cached, GNUNET_NO if not
 */
static int
cache_response (struct DHT_MessageContext *msg_ctx)
{
  struct DHTQueryRecord *record;
  struct DHTRouteSource *source_info;
  struct DHTRouteSource *pos;
  struct GNUNET_TIME_Absolute now;
  unsigned int current_size;

  current_size = GNUNET_CONTAINER_multihashmap_size (forward_list.hashmap);

#if DELETE_WHEN_FULL
  while (current_size >= MAX_OUTSTANDING_FORWARDS)
  {
    source_info = GNUNET_CONTAINER_heap_remove_root (forward_list.minHeap);
    GNUNET_assert (source_info != NULL);
    record = source_info->record;
    GNUNET_CONTAINER_DLL_remove (record->head, record->tail, source_info);
    if (record->head == NULL)   /* No more entries in DLL */
    {
      GNUNET_assert (GNUNET_YES ==
                     GNUNET_CONTAINER_multihashmap_remove (forward_list.hashmap,
                                                           &record->key,
                                                           record));
      GNUNET_free (record);
    }
    if (source_info->delete_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (source_info->delete_task);
      source_info->delete_task = GNUNET_SCHEDULER_NO_TASK;
    }
    if (source_info->find_peers_responded != NULL)
      GNUNET_CONTAINER_bloomfilter_free (source_info->find_peers_responded);
    GNUNET_free (source_info);
    current_size = GNUNET_CONTAINER_multihashmap_size (forward_list.hashmap);
  }
#endif
  /** Non-local request and have too many outstanding forwards, discard! */
  if ((current_size >= MAX_OUTSTANDING_FORWARDS) && (msg_ctx->client == NULL))
    return GNUNET_NO;

  now = GNUNET_TIME_absolute_get ();
  record =
      GNUNET_CONTAINER_multihashmap_get (forward_list.hashmap, &msg_ctx->key);
  if (record != NULL)           /* Already know this request! */
  {
    pos = record->head;
    while (pos != NULL)
    {
      if ((NULL != msg_ctx->peer) &&
          (0 ==
           memcmp (msg_ctx->peer, &pos->source,
                   sizeof (struct GNUNET_PeerIdentity))))
        break;                  /* Already have this peer in reply list! */
      pos = pos->next;
    }
    if ((pos != NULL) && (pos->client == msg_ctx->client))      /* Seen this already */
    {
      GNUNET_CONTAINER_heap_update_cost (forward_list.minHeap, pos->hnode,
                                         now.abs_value);
      return GNUNET_NO;
    }
  }
  else
  {
    record = GNUNET_malloc (sizeof (struct DHTQueryRecord));
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multihashmap_put (forward_list.hashmap,
                                                      &msg_ctx->key, record,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
    memcpy (&record->key, &msg_ctx->key, sizeof (GNUNET_HashCode));
  }

  source_info = GNUNET_malloc (sizeof (struct DHTRouteSource));
  source_info->record = record;
  source_info->delete_task =
      GNUNET_SCHEDULER_add_delayed (DHT_FORWARD_TIMEOUT, &remove_forward_entry,
                                    source_info);
  source_info->find_peers_responded =
      GNUNET_CONTAINER_bloomfilter_init (NULL, DHT_BLOOM_SIZE, DHT_BLOOM_K);
  source_info->source = *msg_ctx->peer;
  GNUNET_CONTAINER_DLL_insert_after (record->head, record->tail, record->tail,
                                     source_info);
  if (msg_ctx->client != NULL)  /* For local request, set timeout so high it effectively never gets pushed out */
  {
    source_info->client = msg_ctx->client;
    now = GNUNET_TIME_absolute_get_forever ();
  }
  source_info->hnode =
      GNUNET_CONTAINER_heap_insert (forward_list.minHeap, source_info,
                                    now.abs_value);
  source_info->uid = msg_ctx->unique_id;
#if DEBUG_DHT > 1
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s:%s': Created new forward source info for %s uid %llu\n",
              my_short_id, "DHT", GNUNET_h2s (&msg_ctx->key),
              msg_ctx->unique_id);
#endif
  return GNUNET_YES;
}


/**
 * Main function that handles whether or not to route a message to other
 * peers.
 *
 * @param msg the message to be routed
 * @param msg_ctx the context containing all pertinent information about the message
 */
static void
route_message (const struct GNUNET_MessageHeader *msg,
               struct DHT_MessageContext *msg_ctx)
{
  int i;
  struct PeerInfo *selected;

#if DEBUG_DHT_ROUTING > 1
  struct PeerInfo *nearest;
#endif
  unsigned int target_forward_count;
  unsigned int forward_count;
  struct RecentRequest *recent_req;
  GNUNET_HashCode unique_hash;
  char *stat_forward_count;
  char *temp_stat_str;

#if DEBUG_DHT_ROUTING
  int ret;
#endif

  if (malicious_dropper == GNUNET_YES)
  {
#if DEBUG_DHT_ROUTING
    if ((debug_routes_extended) && (dhtlog_handle != NULL))
    {
      dhtlog_handle->insert_route (NULL, msg_ctx->unique_id, DHTLOG_ROUTE,
                                   msg_ctx->hop_count, GNUNET_SYSERR,
                                   &my_identity, &msg_ctx->key, msg_ctx->peer,
                                   NULL);
    }
#endif
    if (msg_ctx->bloom != NULL)
    {
      GNUNET_CONTAINER_bloomfilter_free (msg_ctx->bloom);
      msg_ctx->bloom = NULL;
    }
    return;
  }

  increment_stats (STAT_ROUTES);
  target_forward_count =
      get_forward_count (msg_ctx->hop_count, msg_ctx->replication);
  GNUNET_asprintf (&stat_forward_count, "# forward counts of %d",
                   target_forward_count);
  increment_stats (stat_forward_count);
  GNUNET_free (stat_forward_count);
  if (msg_ctx->bloom == NULL)
    msg_ctx->bloom =
        GNUNET_CONTAINER_bloomfilter_init (NULL, DHT_BLOOM_SIZE, DHT_BLOOM_K);

  if ((stop_on_closest == GNUNET_YES) && (msg_ctx->closest == GNUNET_YES) &&
      (ntohs (msg->type) == GNUNET_MESSAGE_TYPE_DHT_PUT))
    target_forward_count = 0;

  /**
   * NOTICE:  In Kademlia, a find peer request goes no further if the peer doesn't return
   * any closer peers (which is being checked for below).  Since we are doing recursive
   * routing we have no choice but to stop forwarding in this case.  This means that at
   * any given step the request may NOT be forwarded to alpha peers (because routes will
   * stop and the parallel route will not be aware of it).  Of course, assuming that we
   * have fulfilled the Kademlia requirements for routing table fullness this will never
   * ever ever be a problem.
   *
   * However, is this fair?
   *
   * Since we use these requests to build our routing tables (and we build them in the
   * testing driver) we will ignore this restriction for FIND_PEER messages so that
   * routing tables still get constructed.
   */
  if ((GNUNET_YES == strict_kademlia) && (msg_ctx->closest == GNUNET_YES) &&
      (msg_ctx->hop_count > 0) &&
      (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_DHT_FIND_PEER))
    target_forward_count = 0;


  GNUNET_CONTAINER_bloomfilter_add (msg_ctx->bloom, &my_identity.hashPubKey);
  hash_from_uid (msg_ctx->unique_id, &unique_hash);
  if (GNUNET_YES ==
      GNUNET_CONTAINER_multihashmap_contains (recent.hashmap, &unique_hash))
  {
    recent_req =
        GNUNET_CONTAINER_multihashmap_get (recent.hashmap, &unique_hash);
    GNUNET_assert (recent_req != NULL);
    if (0 != memcmp (&recent_req->key, &msg_ctx->key, sizeof (GNUNET_HashCode)))
      increment_stats (STAT_DUPLICATE_UID);
    else
    {
      increment_stats (STAT_RECENT_SEEN);
      GNUNET_CONTAINER_bloomfilter_or2 (msg_ctx->bloom, recent_req->bloom,
                                        DHT_BLOOM_SIZE);
    }
  }
  else
  {
    recent_req = GNUNET_malloc (sizeof (struct RecentRequest));
    recent_req->uid = msg_ctx->unique_id;
    memcpy (&recent_req->key, &msg_ctx->key, sizeof (GNUNET_HashCode));
    recent_req->remove_task =
        GNUNET_SCHEDULER_add_delayed (DEFAULT_RECENT_REMOVAL, &remove_recent,
                                      recent_req);
    recent_req->heap_node =
        GNUNET_CONTAINER_heap_insert (recent.minHeap, recent_req,
                                      GNUNET_TIME_absolute_get ().abs_value);
    recent_req->bloom =
        GNUNET_CONTAINER_bloomfilter_init (NULL, DHT_BLOOM_SIZE, DHT_BLOOM_K);
    GNUNET_CONTAINER_multihashmap_put (recent.hashmap, &unique_hash, recent_req,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  }

  if (GNUNET_CONTAINER_multihashmap_size (recent.hashmap) > DHT_MAX_RECENT)
  {
    recent_req = GNUNET_CONTAINER_heap_peek (recent.minHeap);
    GNUNET_assert (recent_req != NULL);
    GNUNET_SCHEDULER_cancel (recent_req->remove_task);
    recent_req->remove_task =
        GNUNET_SCHEDULER_add_now (&remove_recent, recent_req);
  }

  forward_count = 0;
  for (i = 0; i < target_forward_count; i++)
  {
    selected = select_peer (&msg_ctx->key, msg_ctx->bloom, msg_ctx->hop_count);

    if (selected != NULL)
    {
      forward_count++;
      if (GNUNET_CRYPTO_hash_matching_bits
          (&selected->id.hashPubKey,
           &msg_ctx->key) >=
          GNUNET_CRYPTO_hash_matching_bits (&my_identity.hashPubKey,
                                            &msg_ctx->key))
        GNUNET_asprintf (&temp_stat_str,
                         "# requests routed to close(r) peer hop %u",
                         msg_ctx->hop_count);
      else
        GNUNET_asprintf (&temp_stat_str,
                         "# requests routed to less close peer hop %u",
                         msg_ctx->hop_count);
      if (temp_stat_str != NULL)
      {
        increment_stats (temp_stat_str);
        GNUNET_free (temp_stat_str);
      }
      GNUNET_CONTAINER_bloomfilter_add (msg_ctx->bloom,
                                        &selected->id.hashPubKey);
#if DEBUG_DHT_ROUTING > 1
      nearest = find_closest_peer (&msg_ctx->key);
      nearest_buf = GNUNET_strdup (GNUNET_i2s (&nearest->id));
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "`%s:%s': Forwarding request key %s uid %llu to peer %s (closest %s, bits %d, distance %u)\n",
                  my_short_id, "DHT", GNUNET_h2s (&msg_ctx->key),
                  msg_ctx->unique_id, GNUNET_i2s (&selected->id), nearest_buf,
                  GNUNET_CRYPTO_hash_matching_bits (&nearest->id.hashPubKey,
                                                    msg_ctx->key),
                  distance (&nearest->id.hashPubKey, msg_ctx->key));
      GNUNET_free (nearest_buf);
#endif
#if DEBUG_DHT_ROUTING
      if ((debug_routes_extended) && (dhtlog_handle != NULL))
      {
        dhtlog_handle->insert_route (NULL, msg_ctx->unique_id, DHTLOG_ROUTE,
                                     msg_ctx->hop_count, GNUNET_NO,
                                     &my_identity, &msg_ctx->key, msg_ctx->peer,
                                     &selected->id);
      }
#endif
      forward_message (msg, selected, msg_ctx);
    }
  }

  if (msg_ctx->bloom != NULL)
  {
    GNUNET_CONTAINER_bloomfilter_or2 (recent_req->bloom, msg_ctx->bloom,
                                      DHT_BLOOM_SIZE);
    GNUNET_CONTAINER_bloomfilter_free (msg_ctx->bloom);
    msg_ctx->bloom = NULL;
  }

#if DEBUG_DHT_ROUTING
  if (forward_count == 0)
    ret = GNUNET_SYSERR;
  else
    ret = GNUNET_NO;

  if ((debug_routes_extended) && (dhtlog_handle != NULL))
  {
    dhtlog_handle->insert_route (NULL, msg_ctx->unique_id, DHTLOG_ROUTE,
                                 msg_ctx->hop_count, ret, &my_identity,
                                 &msg_ctx->key, msg_ctx->peer, NULL);
  }
#endif
}


/**
 * Main function that handles whether or not to route a message to other
 * peers.
 *
 * @param msg the message to be routed
 * @param msg_ctx the context containing all pertinent information about the message
 */
static void
demultiplex_message (const struct GNUNET_MessageHeader *msg,
                     struct DHT_MessageContext *msg_ctx)
{
  /* FIXME: Should we use closest excluding those we won't route to (the bloomfilter problem)? */
  msg_ctx->closest = am_closest_peer (&msg_ctx->key, msg_ctx->bloom);

  switch (ntohs (msg->type))
  {
  case GNUNET_MESSAGE_TYPE_DHT_GET:    /* Add to hashmap of requests seen, search for data (always) */
    cache_response (msg_ctx);
    handle_dht_get (msg, msg_ctx);
    break;
  case GNUNET_MESSAGE_TYPE_DHT_PUT:    /* Check if closest, if so insert data. */
    increment_stats (STAT_PUTS);
    handle_dht_put (msg, msg_ctx);
    break;
  case GNUNET_MESSAGE_TYPE_DHT_FIND_PEER:      /* Check if closest and not started by us, check options, add to requests seen */
    increment_stats (STAT_FIND_PEER);
    if (((msg_ctx->hop_count > 0) &&
         (0 !=
          memcmp (msg_ctx->peer, &my_identity,
                  sizeof (struct GNUNET_PeerIdentity)))) ||
        (msg_ctx->client != NULL))
    {
      cache_response (msg_ctx);
      if ((msg_ctx->closest == GNUNET_YES) ||
          (msg_ctx->msg_options == GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE))
        handle_dht_find_peer (msg, msg_ctx);
    }
    else
      route_message (msg, msg_ctx);
#if DEBUG_DHT_ROUTING
    if (msg_ctx->hop_count == 0)        /* Locally initiated request */
    {
      if ((debug_routes) && (dhtlog_handle != NULL))
      {
        dhtlog_handle->insert_dhtkey (NULL, &msg_ctx->key);
        dhtlog_handle->insert_query (NULL, msg_ctx->unique_id, DHTLOG_FIND_PEER,
                                     msg_ctx->hop_count, GNUNET_NO,
                                     &my_identity, &msg_ctx->key);
      }
    }
#endif
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "`%s': Message type (%d) not handled, forwarding anyway!\n",
                "DHT", ntohs (msg->type));
    route_message (msg, msg_ctx);
  }
}


/**
 * Iterator over hash map entries.
 *
 * @param cls client to search for in source routes
 * @param key current key code (ignored)
 * @param value value in the hash map, a DHTQueryRecord
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
static int
find_client_records (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct ClientList *client = cls;
  struct DHTQueryRecord *record = value;
  struct DHTRouteSource *pos;

  pos = record->head;
  while (pos != NULL)
  {
    if (pos->client == client)
      break;
    pos = pos->next;
  }
  if (pos != NULL)
  {
    GNUNET_CONTAINER_DLL_remove (record->head, record->tail, pos);
    GNUNET_CONTAINER_heap_remove_node (pos->hnode);
    if (pos->delete_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (pos->delete_task);
      pos->delete_task = GNUNET_SCHEDULER_NO_TASK;
    }
    if (pos->find_peers_responded != NULL)
      GNUNET_CONTAINER_bloomfilter_free (pos->find_peers_responded);
    GNUNET_free (pos);
  }
  if (record->head == NULL)     /* No more entries in DLL */
  {
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multihashmap_remove (forward_list.hashmap,
                                                         &record->key, record));
    GNUNET_free (record);
  }
  return GNUNET_YES;
}

/**
 * Functions with this signature are called whenever a client
 * is disconnected on the network level.
 *
 * @param cls closure (NULL for dht)
 * @param client identification of the client; NULL
 *        for the last call when the server is destroyed
 */
static void
handle_client_disconnect (void *cls, struct GNUNET_SERVER_Client *client)
{
  struct ClientList *pos = client_list;
  struct ClientList *prev;
  struct ClientList *found;
  struct PendingMessage *reply;

  prev = NULL;
  found = NULL;
  while (pos != NULL)
  {
    if (pos->client_handle == client)
    {
      if (prev != NULL)
        prev->next = pos->next;
      else
        client_list = pos->next;
      found = pos;
      break;
    }
    prev = pos;
    pos = pos->next;
  }

  if (found != NULL)
  {
    if (found->transmit_handle != NULL)
      GNUNET_CONNECTION_notify_transmit_ready_cancel (found->transmit_handle);

    while (NULL != (reply = found->pending_head))
    {
      GNUNET_CONTAINER_DLL_remove (found->pending_head, found->pending_tail,
                                   reply);
      GNUNET_free (reply);
    }
    GNUNET_CONTAINER_multihashmap_iterate (forward_list.hashmap,
                                           &find_client_records, found);
    GNUNET_free (found);
  }
}

/**
 * Find a client if it exists, add it otherwise.
 *
 * @param client the server handle to the client
 *
 * @return the client if found, a new client otherwise
 */
static struct ClientList *
find_active_client (struct GNUNET_SERVER_Client *client)
{
  struct ClientList *pos = client_list;
  struct ClientList *ret;

  while (pos != NULL)
  {
    if (pos->client_handle == client)
      return pos;
    pos = pos->next;
  }

  ret = GNUNET_malloc (sizeof (struct ClientList));
  ret->client_handle = client;
  ret->next = client_list;
  client_list = ret;

  return ret;
}

#if HAVE_MALICIOUS
/**
 * Task to send a malicious put message across the network.
 *
 * @param cls closure for this task
 * @param tc the context under which the task is running
 */
static void
malicious_put_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static struct GNUNET_DHT_PutMessage put_message;
  static struct DHT_MessageContext msg_ctx;
  static GNUNET_HashCode key;
  uint32_t random_key;

  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;
  put_message.header.size = htons (sizeof (struct GNUNET_DHT_PutMessage));
  put_message.header.type = htons (GNUNET_MESSAGE_TYPE_DHT_PUT);
  put_message.type = htonl (GNUNET_BLOCK_DHT_MALICIOUS_MESSAGE_TYPE);
  put_message.expiration =
      GNUNET_TIME_absolute_hton (GNUNET_TIME_absolute_get_forever ());
  memset (&msg_ctx, 0, sizeof (struct DHT_MessageContext));
  random_key =
      GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, UINT32_MAX);
  GNUNET_CRYPTO_hash (&random_key, sizeof (uint32_t), &key);
  memcpy (&msg_ctx.key, &key, sizeof (GNUNET_HashCode));
  msg_ctx.unique_id =
      GNUNET_ntohll (GNUNET_CRYPTO_random_u64
                     (GNUNET_CRYPTO_QUALITY_WEAK, UINT64_MAX));
  msg_ctx.replication = ntohl (DHT_DEFAULT_FIND_PEER_REPLICATION);
  msg_ctx.msg_options = ntohl (0);
  msg_ctx.network_size = log_of_network_size_estimate;
  msg_ctx.peer = &my_identity;
  msg_ctx.importance = DHT_DEFAULT_P2P_IMPORTANCE;
  msg_ctx.timeout = DHT_DEFAULT_P2P_TIMEOUT;
#if DEBUG_DHT_ROUTING
  if (dhtlog_handle != NULL)
    dhtlog_handle->insert_dhtkey (NULL, &key);
#endif
  increment_stats (STAT_PUT_START);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s:%s Sending malicious PUT message with hash %s\n", my_short_id,
              "DHT", GNUNET_h2s (&key));
  demultiplex_message (&put_message.header, &msg_ctx);
  GNUNET_SCHEDULER_add_delayed (malicious_put_frequency, &malicious_put_task,
                                NULL);
}


/**
 * Task to send a malicious put message across the network.
 *
 * @param cls closure for this task
 * @param tc the context under which the task is running
 */
static void
malicious_get_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static struct GNUNET_DHT_GetMessage get_message;
  struct DHT_MessageContext msg_ctx;
  static GNUNET_HashCode key;
  uint32_t random_key;

  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;

  get_message.header.size = htons (sizeof (struct GNUNET_DHT_GetMessage));
  get_message.header.type = htons (GNUNET_MESSAGE_TYPE_DHT_GET);
  get_message.type = htonl (GNUNET_BLOCK_DHT_MALICIOUS_MESSAGE_TYPE);
  memset (&msg_ctx, 0, sizeof (struct DHT_MessageContext));
  random_key =
      GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, UINT32_MAX);
  GNUNET_CRYPTO_hash (&random_key, sizeof (uint32_t), &key);
  memcpy (&msg_ctx.key, &key, sizeof (GNUNET_HashCode));
  msg_ctx.unique_id =
      GNUNET_ntohll (GNUNET_CRYPTO_random_u64
                     (GNUNET_CRYPTO_QUALITY_WEAK, UINT64_MAX));
  msg_ctx.replication = ntohl (DHT_DEFAULT_FIND_PEER_REPLICATION);
  msg_ctx.msg_options = ntohl (0);
  msg_ctx.network_size = log_of_network_size_estimate;
  msg_ctx.peer = &my_identity;
  msg_ctx.importance = DHT_DEFAULT_P2P_IMPORTANCE;
  msg_ctx.timeout = DHT_DEFAULT_P2P_TIMEOUT;
#if DEBUG_DHT_ROUTING
  if (dhtlog_handle != NULL)
    dhtlog_handle->insert_dhtkey (NULL, &key);
#endif
  increment_stats (STAT_GET_START);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s:%s Sending malicious GET message with hash %s\n", my_short_id,
              "DHT", GNUNET_h2s (&key));
  demultiplex_message (&get_message.header, &msg_ctx);
  GNUNET_SCHEDULER_add_delayed (malicious_get_frequency, &malicious_get_task,
                                NULL);
}
#endif


/**
 * Iterator over hash map entries.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
static int
add_known_to_bloom (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct GNUNET_CONTAINER_BloomFilter *bloom = cls;

  GNUNET_CONTAINER_bloomfilter_add (bloom, key);
  return GNUNET_YES;
}

/**
 * Task to send a find peer message for our own peer identifier
 * so that we can find the closest peers in the network to ourselves
 * and attempt to connect to them.
 *
 * @param cls closure for this task
 * @param tc the context under which the task is running
 */
static void
send_find_peer_message (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_DHT_FindPeerMessage *find_peer_msg;
  struct DHT_MessageContext msg_ctx;
  struct GNUNET_TIME_Relative next_send_time;
  struct GNUNET_CONTAINER_BloomFilter *temp_bloom;

  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;

  if ((newly_found_peers > bucket_size) && (GNUNET_YES == do_find_peer))        /* If we are finding peers already, no need to send out our request right now! */
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Have %d newly found peers since last find peer message sent!\n",
                newly_found_peers);
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MINUTES,
                                  &send_find_peer_message, NULL);
    newly_found_peers = 0;
    return;
  }

  increment_stats (STAT_FIND_PEER_START);
#if FIND_PEER_WITH_HELLO
  find_peer_msg =
      GNUNET_malloc (sizeof (struct GNUNET_DHT_FindPeerMessage) +
                     GNUNET_HELLO_size ((struct GNUNET_HELLO_Message *)
                                        my_hello));
  find_peer_msg->header.size =
      htons (sizeof (struct GNUNET_DHT_FindPeerMessage) +
             GNUNET_HELLO_size ((struct GNUNET_HELLO_Message *) my_hello));
  memcpy (&find_peer_msg[1], my_hello,
          GNUNET_HELLO_size ((struct GNUNET_HELLO_Message *) my_hello));
#else
  find_peer_msg = GNUNET_malloc (sizeof (struct GNUNET_DHT_FindPeerMessage));
  find_peer_msg->header.size =
      htons (sizeof (struct GNUNET_DHT_FindPeerMessage));
#endif
  find_peer_msg->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_FIND_PEER);
  temp_bloom =
      GNUNET_CONTAINER_bloomfilter_init (NULL, DHT_BLOOM_SIZE, DHT_BLOOM_K);
  GNUNET_CONTAINER_multihashmap_iterate (all_known_peers, &add_known_to_bloom,
                                         temp_bloom);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_bloomfilter_get_raw_data (temp_bloom,
                                                            find_peer_msg->
                                                            bloomfilter,
                                                            DHT_BLOOM_SIZE));
  GNUNET_CONTAINER_bloomfilter_free (temp_bloom);
  memset (&msg_ctx, 0, sizeof (struct DHT_MessageContext));
  memcpy (&msg_ctx.key, &my_identity.hashPubKey, sizeof (GNUNET_HashCode));
  msg_ctx.unique_id =
      GNUNET_ntohll (GNUNET_CRYPTO_random_u64
                     (GNUNET_CRYPTO_QUALITY_STRONG, UINT64_MAX));
  msg_ctx.replication = DHT_DEFAULT_FIND_PEER_REPLICATION;
  msg_ctx.msg_options = GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE;
  msg_ctx.network_size = log_of_network_size_estimate;
  msg_ctx.peer = &my_identity;
  msg_ctx.importance = DHT_DEFAULT_FIND_PEER_IMPORTANCE;
  msg_ctx.timeout = DHT_DEFAULT_FIND_PEER_TIMEOUT;

  demultiplex_message (&find_peer_msg->header, &msg_ctx);
  GNUNET_free (find_peer_msg);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s:%s': Sent `%s' request to some (?) peers\n", my_short_id,
              "DHT", "FIND PEER");
  if (newly_found_peers < bucket_size)
  {
    next_send_time.rel_value =
        (DHT_MAXIMUM_FIND_PEER_INTERVAL.rel_value / 2) +
        GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_STRONG,
                                  DHT_MAXIMUM_FIND_PEER_INTERVAL.rel_value / 2);
  }
  else
  {
    next_send_time.rel_value =
        DHT_MINIMUM_FIND_PEER_INTERVAL.rel_value +
        GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_STRONG,
                                  DHT_MAXIMUM_FIND_PEER_INTERVAL.rel_value -
                                  DHT_MINIMUM_FIND_PEER_INTERVAL.rel_value);
  }

  GNUNET_assert (next_send_time.rel_value != 0);
  find_peer_context.count = 0;
  newly_found_peers = 0;
  find_peer_context.start = GNUNET_TIME_absolute_get ();
  if (GNUNET_YES == do_find_peer)
  {
    GNUNET_SCHEDULER_add_delayed (next_send_time, &send_find_peer_message,
                                  NULL);
  }
}

/**
 * Handler for any generic DHT messages, calls the appropriate handler
 * depending on message type, sends confirmation if responses aren't otherwise
 * expected.
 *
 * @param cls closure for the service
 * @param client the client we received this message from
 * @param message the actual message received
 */
static void
handle_dht_local_route_request (void *cls, struct GNUNET_SERVER_Client *client,
                                const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_DHT_RouteMessage *dht_msg =
      (const struct GNUNET_DHT_RouteMessage *) message;
  const struct GNUNET_MessageHeader *enc_msg;
  struct DHT_MessageContext msg_ctx;

  enc_msg = (const struct GNUNET_MessageHeader *) &dht_msg[1];
#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s:%s': Received `%s' request from client, message type %d, key %s, uid %llu\n",
              my_short_id, "DHT", "GENERIC", ntohs (message->type),
              GNUNET_h2s (&dht_msg->key), GNUNET_ntohll (dht_msg->unique_id));
#endif
#if DEBUG_DHT_ROUTING
  if (dhtlog_handle != NULL)
    dhtlog_handle->insert_dhtkey (NULL, &dht_msg->key);
#endif

  memset (&msg_ctx, 0, sizeof (struct DHT_MessageContext));
  msg_ctx.client = find_active_client (client);
  memcpy (&msg_ctx.key, &dht_msg->key, sizeof (GNUNET_HashCode));
  msg_ctx.unique_id = GNUNET_ntohll (dht_msg->unique_id);
  msg_ctx.replication = ntohl (dht_msg->desired_replication_level);
  msg_ctx.msg_options = ntohl (dht_msg->options);
  if (GNUNET_DHT_RO_RECORD_ROUTE ==
      (msg_ctx.msg_options & GNUNET_DHT_RO_RECORD_ROUTE))
  {
    msg_ctx.path_history = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity));
    memcpy (msg_ctx.path_history, &my_identity,
            sizeof (struct GNUNET_PeerIdentity));
    msg_ctx.path_history_len = 1;
  }
  msg_ctx.network_size = log_of_network_size_estimate;
  msg_ctx.peer = &my_identity;  /* FIXME: use NULL? Fix doxygen? */
  msg_ctx.importance = DHT_DEFAULT_P2P_IMPORTANCE + 4;  /* Make local routing a higher priority */
  msg_ctx.timeout = DHT_DEFAULT_P2P_TIMEOUT;

  if (ntohs (enc_msg->type) == GNUNET_MESSAGE_TYPE_DHT_GET)
    increment_stats (STAT_GET_START);
  else if (ntohs (enc_msg->type) == GNUNET_MESSAGE_TYPE_DHT_PUT)
    increment_stats (STAT_PUT_START);
  else if (ntohs (enc_msg->type) == GNUNET_MESSAGE_TYPE_DHT_FIND_PEER)
    increment_stats (STAT_FIND_PEER_START);

  if (GNUNET_YES == malicious_dropper)
  {
    if (ntohs (enc_msg->type) == GNUNET_MESSAGE_TYPE_DHT_GET)
    {
#if DEBUG_DHT_ROUTING
      if ((debug_routes) && (dhtlog_handle != NULL))
      {
        dhtlog_handle->insert_query (NULL, msg_ctx.unique_id, DHTLOG_GET,
                                     msg_ctx.hop_count, GNUNET_NO, &my_identity,
                                     &msg_ctx.key);
      }
#endif
    }
    else if (ntohs (enc_msg->type) == GNUNET_MESSAGE_TYPE_DHT_PUT)
    {
#if DEBUG_DHT_ROUTING
      if ((debug_routes) && (dhtlog_handle != NULL))
      {
        dhtlog_handle->insert_query (NULL, msg_ctx.unique_id, DHTLOG_PUT,
                                     msg_ctx.hop_count, GNUNET_NO, &my_identity,
                                     &msg_ctx.key);
      }
#endif
    }
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    GNUNET_free_non_null (msg_ctx.path_history);
    return;
  }

  demultiplex_message (enc_msg, &msg_ctx);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);

}

/**
 * Handler for any locally received DHT control messages,
 * sets malicious flags mostly for now.
 *
 * @param cls closure for the service
 * @param client the client we received this message from
 * @param message the actual message received
 *
 */
static void
handle_dht_control_message (void *cls, struct GNUNET_SERVER_Client *client,
                            const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_DHT_ControlMessage *dht_control_msg =
      (const struct GNUNET_DHT_ControlMessage *) message;

#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s:%s': Received `%s' request from client, command %d\n",
              my_short_id, "DHT", "CONTROL", ntohs (dht_control_msg->command));
#endif

  switch (ntohs (dht_control_msg->command))
  {
  case GNUNET_MESSAGE_TYPE_DHT_FIND_PEER:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending self seeking find peer request!\n");
    GNUNET_SCHEDULER_add_now (&send_find_peer_message, NULL);
    break;
#if HAVE_MALICIOUS
  case GNUNET_MESSAGE_TYPE_DHT_MALICIOUS_GET:
    if (ntohs (dht_control_msg->variable) > 0)
      malicious_get_frequency.rel_value = ntohs (dht_control_msg->variable);
    if (malicious_get_frequency.rel_value == 0)
      malicious_get_frequency = DEFAULT_MALICIOUS_GET_FREQUENCY;
    if (malicious_getter != GNUNET_YES)
      GNUNET_SCHEDULER_add_now (&malicious_get_task, NULL);
    malicious_getter = GNUNET_YES;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s:%s Initiating malicious GET behavior, frequency %llu\n",
                my_short_id, "DHT", malicious_get_frequency.rel_value);
    break;
  case GNUNET_MESSAGE_TYPE_DHT_MALICIOUS_PUT:
    if (ntohs (dht_control_msg->variable) > 0)
      malicious_put_frequency.rel_value = ntohs (dht_control_msg->variable);
    if (malicious_put_frequency.rel_value == 0)
      malicious_put_frequency = DEFAULT_MALICIOUS_PUT_FREQUENCY;
    if (malicious_putter != GNUNET_YES)
      GNUNET_SCHEDULER_add_now (&malicious_put_task, NULL);
    malicious_putter = GNUNET_YES;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s:%s Initiating malicious PUT behavior, frequency %d\n",
                my_short_id, "DHT", malicious_put_frequency);
    break;
  case GNUNET_MESSAGE_TYPE_DHT_MALICIOUS_DROP:
#if DEBUG_DHT_ROUTING
    if ((malicious_dropper != GNUNET_YES) && (dhtlog_handle != NULL))
      dhtlog_handle->set_malicious (&my_identity);
#endif
    malicious_dropper = GNUNET_YES;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s:%s Initiating malicious DROP behavior\n", my_short_id,
                "DHT");
    break;
#endif
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "%s:%s Unknown control command type `%d'!\n", my_short_id,
                "DHT", ntohs (dht_control_msg->command));
    break;
  }

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}

/**
 * Handler for any generic DHT stop messages, calls the appropriate handler
 * depending on message type (if processed locally)
 *
 * @param cls closure for the service
 * @param client the client we received this message from
 * @param message the actual message received
 *
 */
static void
handle_dht_local_route_stop (void *cls, struct GNUNET_SERVER_Client *client,
                             const struct GNUNET_MessageHeader *message)
{

  const struct GNUNET_DHT_StopMessage *dht_stop_msg =
      (const struct GNUNET_DHT_StopMessage *) message;
  struct DHTQueryRecord *record;
  struct DHTRouteSource *pos;

#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s:%s': Received `%s' request from client, uid %llu\n",
              my_short_id, "DHT", "GENERIC STOP",
              GNUNET_ntohll (dht_stop_msg->unique_id));
#endif
  record =
      GNUNET_CONTAINER_multihashmap_get (forward_list.hashmap,
                                         &dht_stop_msg->key);
  if (record != NULL)
  {
    pos = record->head;

    while (pos != NULL)
    {
      /* If the client is non-null (local request) and the client matches the requesting client, remove the entry. */
      if ((pos->client != NULL) && (pos->client->client_handle == client))
      {
        if (pos->delete_task != GNUNET_SCHEDULER_NO_TASK)
          GNUNET_SCHEDULER_cancel (pos->delete_task);
        pos->delete_task =
            GNUNET_SCHEDULER_add_now (&remove_forward_entry, pos);
      }
      pos = pos->next;
    }
  }

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Core handler for p2p route requests.
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @param atsi performance data
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_dht_p2p_route_request (void *cls, const struct GNUNET_PeerIdentity *peer,
                              const struct GNUNET_MessageHeader *message,
                              const struct GNUNET_TRANSPORT_ATS_Information
                              *atsi)
{
#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s:%s': Received P2P request from peer %s\n", my_short_id,
              "DHT", GNUNET_i2s (peer));
#endif
  struct GNUNET_DHT_P2PRouteMessage *incoming =
      (struct GNUNET_DHT_P2PRouteMessage *) message;
  struct GNUNET_MessageHeader *enc_msg =
      (struct GNUNET_MessageHeader *) &incoming[1];
  struct DHT_MessageContext *msg_ctx;
  char *route_path;
  int path_size;

  if (ntohs (enc_msg->size) >= GNUNET_SERVER_MAX_MESSAGE_SIZE - 1)
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }

  if (malicious_dropper == GNUNET_YES)
  {
#if DEBUG_DHT_ROUTING
    if ((debug_routes_extended) && (dhtlog_handle != NULL))
    {
          /** Log routes that die due to high load! */
      dhtlog_handle->insert_route (NULL, GNUNET_ntohll (incoming->unique_id),
                                   DHTLOG_ROUTE, ntohl (incoming->hop_count),
                                   GNUNET_SYSERR, &my_identity, &incoming->key,
                                   peer, NULL);
    }
#endif
    return GNUNET_YES;
  }

  if (get_max_send_delay ().rel_value > MAX_REQUEST_TIME.rel_value)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending of previous replies took too long, backing off!\n");
    increment_stats ("# route requests dropped due to high load");
    decrease_max_send_delay (get_max_send_delay ());
#if DEBUG_DHT_ROUTING
    if ((debug_routes_extended) && (dhtlog_handle != NULL))
    {
        /** Log routes that die due to high load! */
      dhtlog_handle->insert_route (NULL, GNUNET_ntohll (incoming->unique_id),
                                   DHTLOG_ROUTE, ntohl (incoming->hop_count),
                                   GNUNET_SYSERR, &my_identity, &incoming->key,
                                   peer, NULL);
    }
#endif
    return GNUNET_YES;
  }
  msg_ctx = GNUNET_malloc (sizeof (struct DHT_MessageContext));
  msg_ctx->bloom =
      GNUNET_CONTAINER_bloomfilter_init (incoming->bloomfilter, DHT_BLOOM_SIZE,
                                         DHT_BLOOM_K);
  GNUNET_assert (msg_ctx->bloom != NULL);
  msg_ctx->hop_count = ntohl (incoming->hop_count);
  memcpy (&msg_ctx->key, &incoming->key, sizeof (GNUNET_HashCode));
  msg_ctx->replication = ntohl (incoming->desired_replication_level);
  msg_ctx->unique_id = GNUNET_ntohll (incoming->unique_id);
  msg_ctx->msg_options = ntohl (incoming->options);
  if (GNUNET_DHT_RO_RECORD_ROUTE ==
      (msg_ctx->msg_options & GNUNET_DHT_RO_RECORD_ROUTE))
  {
    path_size =
        ntohl (incoming->outgoing_path_length) *
        sizeof (struct GNUNET_PeerIdentity);
    if (ntohs (message->size) !=
        (sizeof (struct GNUNET_DHT_P2PRouteMessage) + ntohs (enc_msg->size) +
         path_size))
    {
      GNUNET_break_op (0);
      GNUNET_free (msg_ctx);
      return GNUNET_YES;
    }
    route_path = (char *) &incoming[1];
    route_path = route_path + ntohs (enc_msg->size);
    msg_ctx->path_history =
        GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity) + path_size);
    memcpy (msg_ctx->path_history, route_path, path_size);
    memcpy (&msg_ctx->path_history[path_size], &my_identity,
            sizeof (struct GNUNET_PeerIdentity));
    msg_ctx->path_history_len = ntohl (incoming->outgoing_path_length) + 1;
  }
  msg_ctx->network_size = ntohl (incoming->network_size);
  msg_ctx->peer = peer;
  msg_ctx->importance = DHT_DEFAULT_P2P_IMPORTANCE;
  msg_ctx->timeout = DHT_DEFAULT_P2P_TIMEOUT;
  demultiplex_message (enc_msg, msg_ctx);
  if (msg_ctx->bloom != NULL)
  {
    GNUNET_CONTAINER_bloomfilter_free (msg_ctx->bloom);
    msg_ctx->bloom = NULL;
  }
  GNUNET_free (msg_ctx);
  return GNUNET_YES;
}


/**
 * Core handler for p2p route results.
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @param atsi performance data
 *
 */
static int
handle_dht_p2p_route_result (void *cls, const struct GNUNET_PeerIdentity *peer,
                             const struct GNUNET_MessageHeader *message,
                             const struct GNUNET_TRANSPORT_ATS_Information
                             *atsi)
{
#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s:%s': Received request from peer %s\n", my_short_id, "DHT",
              GNUNET_i2s (peer));
#endif
  const struct GNUNET_DHT_P2PRouteResultMessage *incoming =
      (const struct GNUNET_DHT_P2PRouteResultMessage *) message;
  struct GNUNET_MessageHeader *enc_msg =
      (struct GNUNET_MessageHeader *) &incoming[1];
  struct DHT_MessageContext msg_ctx;

#if DEBUG_PATH
  char *path_offset;
  unsigned int i;
#endif
  if (ntohs (enc_msg->size) >= GNUNET_SERVER_MAX_MESSAGE_SIZE - 1)
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }

  if (malicious_dropper == GNUNET_YES)
  {
#if DEBUG_DHT_ROUTING
    if ((debug_routes_extended) && (dhtlog_handle != NULL))
    {
          /** Log routes that die due to high load! */
      dhtlog_handle->insert_route (NULL, GNUNET_ntohll (incoming->unique_id),
                                   DHTLOG_ROUTE, ntohl (incoming->hop_count),
                                   GNUNET_SYSERR, &my_identity, &incoming->key,
                                   peer, NULL);
    }
#endif
    return GNUNET_YES;
  }

  memset (&msg_ctx, 0, sizeof (struct DHT_MessageContext));
  memcpy (&msg_ctx.key, &incoming->key, sizeof (GNUNET_HashCode));
  msg_ctx.unique_id = GNUNET_ntohll (incoming->unique_id);
  msg_ctx.msg_options = ntohl (incoming->options);
  msg_ctx.hop_count = ntohl (incoming->hop_count);
  msg_ctx.peer = peer;
  msg_ctx.importance = DHT_DEFAULT_P2P_IMPORTANCE + 2;  /* Make result routing a higher priority */
  msg_ctx.timeout = DHT_DEFAULT_P2P_TIMEOUT;
  if ((GNUNET_DHT_RO_RECORD_ROUTE ==
       (msg_ctx.msg_options & GNUNET_DHT_RO_RECORD_ROUTE)) &&
      (ntohl (incoming->outgoing_path_length) > 0))
  {
    if (ntohs (message->size) -
        sizeof (struct GNUNET_DHT_P2PRouteResultMessage) -
        ntohs (enc_msg->size) !=
        ntohl (incoming->outgoing_path_length) *
        sizeof (struct GNUNET_PeerIdentity))
    {
#if DEBUG_DHT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Return message indicated a path was included, but sizes are wrong: Total size %d, enc size %d, left %d, expected %d\n",
                  ntohs (message->size), ntohs (enc_msg->size),
                  ntohs (message->size) -
                  sizeof (struct GNUNET_DHT_P2PRouteResultMessage) -
                  ntohs (enc_msg->size),
                  ntohl (incoming->outgoing_path_length) *
                  sizeof (struct GNUNET_PeerIdentity));
#endif
      GNUNET_break_op (0);
      return GNUNET_NO;
    }
    msg_ctx.path_history = (char *) &incoming[1];
    msg_ctx.path_history += ntohs (enc_msg->size);
    msg_ctx.path_history_len = ntohl (incoming->outgoing_path_length);
#if DEBUG_PATH
    for (i = 0; i < msg_ctx.path_history_len; i++)
    {
      path_offset =
          &msg_ctx.path_history[i * sizeof (struct GNUNET_PeerIdentity)];
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "(handle_p2p_route_result) Key %s Found peer %d:%s\n",
                  GNUNET_h2s (&msg_ctx.key), i,
                  GNUNET_i2s ((struct GNUNET_PeerIdentity *) path_offset));
    }
#endif
  }
  msg_ctx.bloom =
      GNUNET_CONTAINER_bloomfilter_init (incoming->bloomfilter, DHT_BLOOM_SIZE,
                                         DHT_BLOOM_K);
  GNUNET_assert (msg_ctx.bloom != NULL);
  route_result_message (enc_msg, &msg_ctx);
  return GNUNET_YES;
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
  int bucket_count;
  struct PeerInfo *pos;

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
  if (NULL != nse)
  {
    GNUNET_NSE_disconnect (nse);
    nse = NULL;
  }
  if (coreAPI != NULL)
  {
#if DEBUG_DHT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%s:%s Disconnecting core!\n",
                my_short_id, "DHT");
#endif
    GNUNET_CORE_disconnect (coreAPI);
    coreAPI = NULL;
  }
  for (bucket_count = lowest_bucket; bucket_count < MAX_BUCKETS; bucket_count++)
  {
    while (k_buckets[bucket_count].head != NULL)
    {
      pos = k_buckets[bucket_count].head;
#if DEBUG_DHT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "%s:%s Removing peer %s from bucket %d!\n", my_short_id,
                  "DHT", GNUNET_i2s (&pos->id), bucket_count);
#endif
      delete_peer (pos, bucket_count);
    }
  }
  if (datacache != NULL)
  {
#if DEBUG_DHT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%s:%s Destroying datacache!\n",
                my_short_id, "DHT");
#endif
    GNUNET_DATACACHE_destroy (datacache);
    datacache = NULL;
  }
  if (stats != NULL)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_YES);
    stats = NULL;
  }
  if (dhtlog_handle != NULL)
  {
    GNUNET_DHTLOG_disconnect (dhtlog_handle);
    dhtlog_handle = NULL;
  }
  if (block_context != NULL)
  {
    GNUNET_BLOCK_context_destroy (block_context);
    block_context = NULL;
  }
  GNUNET_free_non_null (my_short_id);
  my_short_id = NULL;
}


/**
 * To be called on core init/fail.
 *
 * @param cls service closure
 * @param server handle to the server for this service
 * @param identity the public identity of this peer
 * @param publicKey the public key of this peer
 */
void
core_init (void *cls, struct GNUNET_CORE_Handle *server,
           const struct GNUNET_PeerIdentity *identity,
           const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *publicKey)
{

  if (server == NULL)
  {
#if DEBUG_DHT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%s: Connection to core FAILED!\n",
                "dht", GNUNET_i2s (identity));
#endif
    GNUNET_SCHEDULER_cancel (cleanup_task);
    GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
    return;
  }
#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Core connection initialized, I am peer: %s\n", "dht",
              GNUNET_i2s (identity));
#endif

  /* Copy our identity so we can use it */
  memcpy (&my_identity, identity, sizeof (struct GNUNET_PeerIdentity));
  if (my_short_id != NULL)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "%s Receive CORE INIT message but have already been initialized! Did CORE fail?\n",
                "DHT SERVICE");
  my_short_id = GNUNET_strdup (GNUNET_i2s (&my_identity));
  if (dhtlog_handle != NULL)
    dhtlog_handle->insert_node (NULL, &my_identity);
}


static struct GNUNET_SERVER_MessageHandler plugin_handlers[] = {
  {&handle_dht_local_route_request, NULL, GNUNET_MESSAGE_TYPE_DHT_LOCAL_ROUTE,
   0},
  {&handle_dht_local_route_stop, NULL,
   GNUNET_MESSAGE_TYPE_DHT_LOCAL_ROUTE_STOP, 0},
  {&handle_dht_control_message, NULL, GNUNET_MESSAGE_TYPE_DHT_CONTROL, 0},
  {NULL, NULL, 0, 0}
};


static struct GNUNET_CORE_MessageHandler core_handlers[] = {
  {&handle_dht_p2p_route_request, GNUNET_MESSAGE_TYPE_DHT_P2P_ROUTE, 0},
  {&handle_dht_p2p_route_result, GNUNET_MESSAGE_TYPE_DHT_P2P_ROUTE_RESULT, 0},
  {NULL, 0, 0}
};


/**
 * Method called whenever a peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param atsi performance data
 */
static void
handle_core_connect (void *cls, const struct GNUNET_PeerIdentity *peer,
                     const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
  struct PeerInfo *ret;
  struct DHTPutEntry *put_entry;
  int peer_bucket;

  /* Check for connect to self message */
  if (0 == memcmp (&my_identity, peer, sizeof (struct GNUNET_PeerIdentity)))
    return;

#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s:%s Receives core connect message for peer %s distance %d!\n",
              my_short_id, "dht", GNUNET_i2s (peer), distance);
#endif

  if (GNUNET_YES ==
      GNUNET_CONTAINER_multihashmap_contains (all_known_peers,
                                              &peer->hashPubKey))
  {
#if DEBUG_DHT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s:%s Received %s message for peer %s, but already have peer in RT!",
                my_short_id, "DHT", "CORE CONNECT", GNUNET_i2s (peer));
#endif
    GNUNET_break (0);
    return;
  }

  if ((datacache != NULL) && (GNUNET_YES == put_peer_identities))
  {
    put_entry =
        GNUNET_malloc (sizeof (struct DHTPutEntry) +
                       sizeof (struct GNUNET_PeerIdentity));
    put_entry->path_length = 0;
    put_entry->data_size = sizeof (struct GNUNET_PeerIdentity);
    memcpy (&put_entry[1], peer, sizeof (struct GNUNET_PeerIdentity));
    GNUNET_DATACACHE_put (datacache, &peer->hashPubKey,
                          sizeof (struct DHTPutEntry) +
                          sizeof (struct GNUNET_PeerIdentity),
                          (char *) put_entry, GNUNET_BLOCK_TYPE_DHT_HELLO,
                          GNUNET_TIME_absolute_get_forever ());
    GNUNET_free (put_entry);
  }
  else if (datacache == NULL)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "DHT has no connection to datacache!\n");

  peer_bucket = find_current_bucket (&peer->hashPubKey);
  GNUNET_assert (peer_bucket >= lowest_bucket);
  GNUNET_assert (peer_bucket < MAX_BUCKETS);
  ret = GNUNET_malloc (sizeof (struct PeerInfo));
#if 0
  ret->latency = latency;
  ret->distance = distance;
#endif
  ret->id = *peer;
  GNUNET_CONTAINER_DLL_insert_after (k_buckets[peer_bucket].head,
                                     k_buckets[peer_bucket].tail,
                                     k_buckets[peer_bucket].tail, ret);
  k_buckets[peer_bucket].peers_size++;
#if DO_UPDATE_PREFERENCE
  if ((GNUNET_CRYPTO_hash_matching_bits
       (&my_identity.hashPubKey, &peer->hashPubKey) > 0) &&
      (k_buckets[peer_bucket].peers_size <= bucket_size))
    ret->preference_task =
        GNUNET_SCHEDULER_add_now (&update_core_preference, ret);
#endif
  if ((k_buckets[lowest_bucket].peers_size) >= bucket_size)
    enable_next_bucket ();
  newly_found_peers++;
  GNUNET_CONTAINER_multihashmap_put (all_known_peers, &peer->hashPubKey, ret,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  increment_stats (STAT_PEERS_KNOWN);

#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s:%s Adding peer to routing list: %s\n", my_short_id, "DHT",
              ret == NULL ? "NOT ADDED" : "PEER ADDED");
#endif
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
  struct PeerInfo *to_remove;
  int current_bucket;

  /* Check for disconnect from self message */
  if (0 == memcmp (&my_identity, peer, sizeof (struct GNUNET_PeerIdentity)))
    return;
#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s:%s: Received peer disconnect message for peer `%s' from %s\n",
              my_short_id, "DHT", GNUNET_i2s (peer), "CORE");
#endif

  if (GNUNET_YES !=
      GNUNET_CONTAINER_multihashmap_contains (all_known_peers,
                                              &peer->hashPubKey))
  {
    GNUNET_break (0);
#if DEBUG_DHT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s:%s: do not have peer `%s' in RT, can't disconnect!\n",
                my_short_id, "DHT", GNUNET_i2s (peer));
#endif
    return;
  }
  increment_stats (STAT_DISCONNECTS);
  GNUNET_assert (GNUNET_CONTAINER_multihashmap_contains
                 (all_known_peers, &peer->hashPubKey));
  to_remove =
      GNUNET_CONTAINER_multihashmap_get (all_known_peers, &peer->hashPubKey);
  GNUNET_assert (to_remove != NULL);
  if (NULL != to_remove->info_ctx)
  {
    GNUNET_CORE_peer_change_preference_cancel (to_remove->info_ctx);
    to_remove->info_ctx = NULL;
  }
  GNUNET_assert (0 ==
                 memcmp (peer, &to_remove->id,
                         sizeof (struct GNUNET_PeerIdentity)));
  current_bucket = find_current_bucket (&to_remove->id.hashPubKey);
  delete_peer (to_remove, current_bucket);
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
  datacache = GNUNET_DATACACHE_create (cfg, "dhtcache");
  GNUNET_SERVER_add_handlers (server, plugin_handlers);
  GNUNET_SERVER_disconnect_notify (server, &handle_client_disconnect, NULL);
  nse = GNUNET_NSE_connect (cfg, &update_network_size_estimate, NULL);
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
  forward_list.hashmap =
      GNUNET_CONTAINER_multihashmap_create (MAX_OUTSTANDING_FORWARDS / 10);
  forward_list.minHeap =
      GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  all_known_peers = GNUNET_CONTAINER_multihashmap_create (MAX_BUCKETS / 8);
  GNUNET_assert (all_known_peers != NULL);
  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "dht_testing",
                                            "mysql_logging"))
  {
    debug_routes = GNUNET_YES;
  }

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "dht", "strict_kademlia"))
  {
    strict_kademlia = GNUNET_YES;
  }

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "dht", "stop_on_closest"))
  {
    stop_on_closest = GNUNET_YES;
  }

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "dht", "stop_found"))
  {
    stop_on_found = GNUNET_YES;
  }

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "dht", "malicious_getter"))
  {
    malicious_getter = GNUNET_YES;
    if (GNUNET_NO ==
        GNUNET_CONFIGURATION_get_value_time (cfg, "DHT",
                                             "MALICIOUS_GET_FREQUENCY",
                                             &malicious_get_frequency))
      malicious_get_frequency = DEFAULT_MALICIOUS_GET_FREQUENCY;
  }

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "dht", "malicious_putter"))
  {
    malicious_putter = GNUNET_YES;
    if (GNUNET_NO ==
        GNUNET_CONFIGURATION_get_value_time (cfg, "DHT",
                                             "MALICIOUS_PUT_FREQUENCY",
                                             &malicious_put_frequency))
      malicious_put_frequency = DEFAULT_MALICIOUS_PUT_FREQUENCY;
  }

  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "DHT", "bucket_size",
                                             &temp_config_num))
  {
    bucket_size = (unsigned int) temp_config_num;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "DHT", "kad_alpha",
                                             &kademlia_replication))
  {
    kademlia_replication = DEFAULT_KADEMLIA_REPLICATION;
  }

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "dht", "malicious_dropper"))
  {
    malicious_dropper = GNUNET_YES;
  }

  if (GNUNET_NO ==
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "dht", "do_find_peer"))
  {
    do_find_peer = GNUNET_NO;
  }
  else
    do_find_peer = GNUNET_YES;

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "dht", "use_real_distance"))
    use_real_distance = GNUNET_YES;

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "dht_testing",
                                            "mysql_logging_extended"))
  {
    debug_routes = GNUNET_YES;
    debug_routes_extended = GNUNET_YES;
  }

#if DEBUG_DHT_ROUTING
  if (GNUNET_YES == debug_routes)
  {
    dhtlog_handle = GNUNET_DHTLOG_connect (cfg);
    if (dhtlog_handle == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Could not connect to mysql logging server, logging will not happen!");
    }
  }
#endif

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "dht", "paper_forwarding"))
    paper_forwarding = GNUNET_YES;

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "dht", "put_peer_identities"))
    put_peer_identities = GNUNET_YES;

  stats = GNUNET_STATISTICS_create ("dht", cfg);

  if (stats != NULL)
  {
    GNUNET_STATISTICS_set (stats, STAT_ROUTES, 0, GNUNET_NO);
    GNUNET_STATISTICS_set (stats, STAT_ROUTE_FORWARDS, 0, GNUNET_NO);
    GNUNET_STATISTICS_set (stats, STAT_ROUTE_FORWARDS_CLOSEST, 0, GNUNET_NO);
    GNUNET_STATISTICS_set (stats, STAT_RESULTS, 0, GNUNET_NO);
    GNUNET_STATISTICS_set (stats, STAT_RESULTS_TO_CLIENT, 0, GNUNET_NO);
    GNUNET_STATISTICS_set (stats, STAT_RESULT_FORWARDS, 0, GNUNET_NO);
    GNUNET_STATISTICS_set (stats, STAT_GETS, 0, GNUNET_NO);
    GNUNET_STATISTICS_set (stats, STAT_PUTS, 0, GNUNET_NO);
    GNUNET_STATISTICS_set (stats, STAT_PUTS_INSERTED, 0, GNUNET_NO);
    GNUNET_STATISTICS_set (stats, STAT_FIND_PEER, 0, GNUNET_NO);
    GNUNET_STATISTICS_set (stats, STAT_FIND_PEER_START, 0, GNUNET_NO);
    GNUNET_STATISTICS_set (stats, STAT_GET_START, 0, GNUNET_NO);
    GNUNET_STATISTICS_set (stats, STAT_PUT_START, 0, GNUNET_NO);
    GNUNET_STATISTICS_set (stats, STAT_FIND_PEER_REPLY, 0, GNUNET_NO);
    GNUNET_STATISTICS_set (stats, STAT_FIND_PEER_ANSWER, 0, GNUNET_NO);
    GNUNET_STATISTICS_set (stats, STAT_BLOOM_FIND_PEER, 0, GNUNET_NO);
    GNUNET_STATISTICS_set (stats, STAT_GET_REPLY, 0, GNUNET_NO);
    GNUNET_STATISTICS_set (stats, STAT_GET_RESPONSE_START, 0, GNUNET_NO);
    GNUNET_STATISTICS_set (stats, STAT_HELLOS_PROVIDED, 0, GNUNET_NO);
    GNUNET_STATISTICS_set (stats, STAT_DISCONNECTS, 0, GNUNET_NO);
  }
  if (GNUNET_YES == do_find_peer)
  {
    next_send_time.rel_value =
        DHT_MINIMUM_FIND_PEER_INTERVAL.rel_value +
        GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_STRONG,
                                  (DHT_MAXIMUM_FIND_PEER_INTERVAL.rel_value /
                                   2) -
                                  DHT_MINIMUM_FIND_PEER_INTERVAL.rel_value);
    find_peer_context.start = GNUNET_TIME_absolute_get ();
    GNUNET_SCHEDULER_add_delayed (next_send_time, &send_find_peer_message,
                                  &find_peer_context);
  }

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
  int ret;

  recent.hashmap = GNUNET_CONTAINER_multihashmap_create (DHT_MAX_RECENT / 2);
  recent.minHeap =
      GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  recent_find_peer_requests =
      GNUNET_CONTAINER_multihashmap_create (MAX_BUCKETS / 8);
  ret =
      (GNUNET_OK ==
       GNUNET_SERVICE_run (argc, argv, "dht", GNUNET_SERVICE_OPTION_NONE, &run,
                           NULL)) ? 0 : 1;
  GNUNET_assert (0 == GNUNET_CONTAINER_multihashmap_size (recent.hashmap));
  GNUNET_CONTAINER_multihashmap_destroy (recent.hashmap);
  recent.hashmap = NULL;
  GNUNET_assert (0 == GNUNET_CONTAINER_heap_get_size (recent.minHeap));
  GNUNET_CONTAINER_heap_destroy (recent.minHeap);
  recent.minHeap = NULL;
  GNUNET_CONTAINER_multihashmap_destroy (recent_find_peer_requests);
  recent_find_peer_requests = NULL;
  return ret;
}

/* end of gnunet-service-dht.c */
