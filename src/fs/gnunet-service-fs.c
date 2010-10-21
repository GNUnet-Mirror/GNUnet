/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file fs/gnunet-service-fs.c
 * @brief gnunet anonymity protocol implementation
 * @author Christian Grothoff
 *
 * TODO:
 * - more statistics
 */
#include "platform.h"
#include <float.h>
#include "gnunet_constants.h"
#include "gnunet_core_service.h"
#include "gnunet_dht_service.h"
#include "gnunet_datastore_service.h"
#include "gnunet_load_lib.h"
#include "gnunet_peer_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_signatures.h"
#include "gnunet_statistics_service.h"
#include "gnunet_util_lib.h"
#include "gnunet-service-fs_indexing.h"
#include "fs.h"

#define DEBUG_FS GNUNET_NO

/**
 * Should we introduce random latency in processing?  Required for proper
 * implementation of GAP, but can be disabled for performance evaluation of
 * the basic routing algorithm.
 *
 * Note that with delays enabled, performance can be significantly lower
 * (several orders of magnitude in 2-peer test runs); if you want to
 * measure throughput of other components, set this to NO.  Also, you
 * might want to consider changing 'RETRY_PROBABILITY_INV' to 1 for
 * a rather wasteful mode of operation (that might still get the highest
 * throughput overall).
 *
 * Performance measurements (for 50 MB file, 2 peers):
 *
 * - Without delays: 3300 kb/s
 * - With    delays:  101 kb/s
 */
#define SUPPORT_DELAYS GNUNET_NO

/**
 * Size for the hash map for DHT requests from the FS
 * service.  Should be about the number of concurrent
 * DHT requests we plan to make.
 */
#define FS_DHT_HT_SIZE 1024

/**
 * At what frequency should our datastore load decrease
 * automatically (since if we don't use it, clearly the
 * load must be going down).
 */
#define DATASTORE_LOAD_AUTODECLINE GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 250)

/**
 * How often do we flush trust values to disk?
 */
#define TRUST_FLUSH_FREQ GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 5)

/**
 * How often do we at most PUT content into the DHT?
 */
#define MAX_DHT_PUT_FREQ GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * Inverse of the probability that we will submit the same query
 * to the same peer again.  If the same peer already got the query
 * repeatedly recently, the probability is multiplied by the inverse
 * of this number each time.  Note that we only try about every TTL_DECREMENT/2
 * plus MAX_CORK_DELAY (so roughly every 3.5s).
 *
 * Note that this factor is a key influence to performance in small
 * networks (especially test networks of 2 peers) because if there is
 * only a single peer with the data, this value will determine how
 * soon we might re-try.  For example, a value of 3 can result in 
 * 1.7 MB/s transfer rates for a 10 MB file when a value of 1 would
 * give us 5 MB/s.  OTOH, obviously re-trying the same peer can be
 * rather inefficient in larger networks, hence picking 1 is in 
 * general not the best choice.
 *
 * Performance measurements (for 50 MB file, 2 peers, no delays):
 *
 * - 1: 3300 kb/s (consistently)
 * - 3: 2046 kb/s, 754 kb/s, 3490 kb/s
 * - 5:  759 kb/s, 968 kb/s, 1160 kb/s
 *
 * Note that this does NOT mean that the value should be 1 since
 * a 2-peer network is far from representative here (and this fails
 * to take into consideration bandwidth wasted by repeatedly 
 * sending queries to peers that don't have the content).  Also,
 * it is expected that higher values lead to more inconsistent
 * measurements since this only affects lost messages towards the
 * end of the download.
 *
 * Finally, we should probably consider changing this and making
 * it dependent on the number of connected peers or a related
 * metric (bad magic constants...).
 */
#define RETRY_PROBABILITY_INV 1

/**
 * What is the maximum delay for a P2P FS message (in our interaction
 * with core)?  FS-internal delays are another story.  The value is
 * chosen based on the 32k block size.  Given that peers typcially
 * have at least 1 kb/s bandwidth, 45s waits give us a chance to
 * transmit one message even to the lowest-bandwidth peers.
 */
#define MAX_TRANSMIT_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 45)

/**
 * Maximum number of requests (from other peers, overall) that we're
 * willing to have pending at any given point in time.  Can be changed
 * via the configuration file (32k is just the default).
 */
static unsigned long long max_pending_requests = (32 * 1024);


/**
 * Information we keep for each pending reply.  The
 * actual message follows at the end of this struct.
 */
struct PendingMessage;

/**
 * Function called upon completion of a transmission.
 *
 * @param cls closure
 * @param pid ID of receiving peer, 0 on transmission error
 */
typedef void (*TransmissionContinuation)(void * cls, 
					 GNUNET_PEER_Id tpid);


/**
 * Information we keep for each pending message (GET/PUT).  The
 * actual message follows at the end of this struct.
 */
struct PendingMessage
{
  /**
   * This is a doubly-linked list of messages to the same peer.
   */
  struct PendingMessage *next;

  /**
   * This is a doubly-linked list of messages to the same peer.
   */
  struct PendingMessage *prev;

  /**
   * Entry in pending message list for this pending message.
   */ 
  struct PendingMessageList *pml;  

  /**
   * Function to call immediately once we have transmitted this
   * message.
   */
  TransmissionContinuation cont;

  /**
   * Closure for cont.
   */
  void *cont_cls;

  /**
   * Do not transmit this pending message until this deadline.
   */
  struct GNUNET_TIME_Absolute delay_until;

  /**
   * Size of the reply; actual reply message follows
   * at the end of this struct.
   */
  size_t msize;
  
  /**
   * How important is this message for us?
   */
  uint32_t priority;
 
};


/**
 * Information about a peer that we are connected to.
 * We track data that is useful for determining which
 * peers should receive our requests.  We also keep
 * a list of messages to transmit to this peer.
 */
struct ConnectedPeer
{

  /**
   * List of the last clients for which this peer successfully
   * answered a query.
   */
  struct GNUNET_SERVER_Client *last_client_replies[CS2P_SUCCESS_LIST_SIZE];

  /**
   * List of the last PIDs for which
   * this peer successfully answered a query;
   * We use 0 to indicate no successful reply.
   */
  GNUNET_PEER_Id last_p2p_replies[P2P_SUCCESS_LIST_SIZE];

  /**
   * Average delay between sending the peer a request and
   * getting a reply (only calculated over the requests for
   * which we actually got a reply).   Calculated
   * as a moving average: new_delay = ((n-1)*last_delay+curr_delay) / n
   */ 
  struct GNUNET_TIME_Relative avg_delay;

  /**
   * Point in time until which this peer does not want us to migrate content
   * to it.
   */
  struct GNUNET_TIME_Absolute migration_blocked;

  /**
   * Time until when we blocked this peer from migrating
   * data to us.
   */
  struct GNUNET_TIME_Absolute last_migration_block;

  /**
   * Transmission times for the last MAX_QUEUE_PER_PEER
   * requests for this peer.  Used as a ring buffer, current
   * offset is stored in 'last_request_times_off'.  If the
   * oldest entry is more recent than the 'avg_delay', we should
   * not send any more requests right now.
   */
  struct GNUNET_TIME_Absolute last_request_times[MAX_QUEUE_PER_PEER];

  /**
   * Handle for an active request for transmission to this
   * peer, or NULL.
   */
  struct GNUNET_CORE_TransmitHandle *cth;

  /**
   * Messages (replies, queries, content migration) we would like to
   * send to this peer in the near future.  Sorted by priority, head.
   */
  struct PendingMessage *pending_messages_head;

  /**
   * Messages (replies, queries, content migration) we would like to
   * send to this peer in the near future.  Sorted by priority, tail.
   */
  struct PendingMessage *pending_messages_tail;

  /**
   * How long does it typically take for us to transmit a message
   * to this peer?  (delay between the request being issued and
   * the callback being invoked).
   */
  struct GNUNET_LOAD_Value *transmission_delay;

  /**
   * Time when the last transmission request was issued.
   */
  struct GNUNET_TIME_Absolute last_transmission_request_start;

  /**
   * ID of delay task for scheduling transmission.
   */
  GNUNET_SCHEDULER_TaskIdentifier delayed_transmission_request_task;

  /**
   * Average priority of successful replies.  Calculated
   * as a moving average: new_avg = ((n-1)*last_avg+curr_prio) / n
   */
  double avg_priority;

  /**
   * Increase in traffic preference still to be submitted
   * to the core service for this peer.
   */
  uint64_t inc_preference;

  /**
   * Trust rating for this peer
   */
  uint32_t trust;

  /**
   * Trust rating for this peer on disk.
   */
  uint32_t disk_trust;

  /**
   * The peer's identity.
   */
  GNUNET_PEER_Id pid;  

  /**
   * Size of the linked list of 'pending_messages'.
   */
  unsigned int pending_requests;

  /**
   * Which offset in "last_p2p_replies" will be updated next?
   * (we go round-robin).
   */
  unsigned int last_p2p_replies_woff;

  /**
   * Which offset in "last_client_replies" will be updated next?
   * (we go round-robin).
   */
  unsigned int last_client_replies_woff;

  /**
   * Current offset into 'last_request_times' ring buffer.
   */
  unsigned int last_request_times_off;

};


/**
 * Information we keep for each pending request.  We should try to
 * keep this struct as small as possible since its memory consumption
 * is key to how many requests we can have pending at once.
 */
struct PendingRequest;


/**
 * Doubly-linked list of requests we are performing
 * on behalf of the same client.
 */
struct ClientRequestList
{

  /**
   * This is a doubly-linked list.
   */
  struct ClientRequestList *next;

  /**
   * This is a doubly-linked list.
   */
  struct ClientRequestList *prev;

  /**
   * Request this entry represents.
   */
  struct PendingRequest *req;

  /**
   * Client list this request belongs to.
   */
  struct ClientList *client_list;

};


/**
 * Replies to be transmitted to the client.  The actual
 * response message is allocated after this struct.
 */
struct ClientResponseMessage
{
  /**
   * This is a doubly-linked list.
   */
  struct ClientResponseMessage *next;

  /**
   * This is a doubly-linked list.
   */
  struct ClientResponseMessage *prev;

  /**
   * Client list entry this response belongs to.
   */
  struct ClientList *client_list;

  /**
   * Number of bytes in the response.
   */
  size_t msize;
};


/**
 * Linked list of clients we are performing requests
 * for right now.
 */
struct ClientList
{
  /**
   * This is a linked list.
   */
  struct ClientList *next;

  /**
   * ID of a client making a request, NULL if this entry is for a
   * peer.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Head of list of requests performed on behalf
   * of this client right now.
   */
  struct ClientRequestList *rl_head;

  /**
   * Tail of list of requests performed on behalf
   * of this client right now.
   */
  struct ClientRequestList *rl_tail;

  /**
   * Head of linked list of responses.
   */
  struct ClientResponseMessage *res_head;

  /**
   * Tail of linked list of responses.
   */
  struct ClientResponseMessage *res_tail;

  /**
   * Context for sending replies.
   */
  struct GNUNET_CONNECTION_TransmitHandle *th;

};


/**
 * Information about a peer that we have forwarded this
 * request to already.  
 */
struct UsedTargetEntry
{
  /**
   * What was the last time we have transmitted this request to this
   * peer?
   */
  struct GNUNET_TIME_Absolute last_request_time;

  /**
   * How often have we transmitted this request to this peer?
   */
  unsigned int num_requests;

  /**
   * PID of the target peer.
   */
  GNUNET_PEER_Id pid;

};





/**
 * Doubly-linked list of messages we are performing
 * due to a pending request.
 */
struct PendingMessageList
{

  /**
   * This is a doubly-linked list of messages on behalf of the same request.
   */
  struct PendingMessageList *next;

  /**
   * This is a doubly-linked list of messages on behalf of the same request.
   */
  struct PendingMessageList *prev;

  /**
   * Message this entry represents.
   */
  struct PendingMessage *pm;

  /**
   * Request this entry belongs to.
   */
  struct PendingRequest *req;

  /**
   * Peer this message is targeted for.
   */
  struct ConnectedPeer *target;

};


/**
 * Information we keep for each pending request.  We should try to
 * keep this struct as small as possible since its memory consumption
 * is key to how many requests we can have pending at once.
 */
struct PendingRequest
{

  /**
   * If this request was made by a client, this is our entry in the
   * client request list; otherwise NULL.
   */
  struct ClientRequestList *client_request_list;

  /**
   * Entry of peer responsible for this entry (if this request
   * was made by a peer).
   */
  struct ConnectedPeer *cp;

  /**
   * If this is a namespace query, pointer to the hash of the public
   * key of the namespace; otherwise NULL.  Pointer will be to the 
   * end of this struct (so no need to free it).
   */
  const GNUNET_HashCode *namespace;

  /**
   * Bloomfilter we use to filter out replies that we don't care about
   * (anymore).  NULL as long as we are interested in all replies.
   */
  struct GNUNET_CONTAINER_BloomFilter *bf;

  /**
   * Context of our GNUNET_CORE_peer_change_preference call.
   */
  struct GNUNET_CORE_InformationRequestContext *irc;

  /**
   * Reference to DHT get operation for this request (or NULL).
   */
  struct GNUNET_DHT_GetHandle *dht_get;

  /**
   * Hash code of all replies that we have seen so far (only valid
   * if client is not NULL since we only track replies like this for
   * our own clients).
   */
  GNUNET_HashCode *replies_seen;

  /**
   * Node in the heap representing this entry; NULL
   * if we have no heap node.
   */
  struct GNUNET_CONTAINER_HeapNode *hnode;

  /**
   * Head of list of messages being performed on behalf of this
   * request.
   */
  struct PendingMessageList *pending_head;

  /**
   * Tail of list of messages being performed on behalf of this
   * request.
   */
  struct PendingMessageList *pending_tail;

  /**
   * When did we first see this request (form this peer), or, if our
   * client is initiating, when did we last initiate a search?
   */
  struct GNUNET_TIME_Absolute start_time;

  /**
   * The query that this request is for.
   */
  GNUNET_HashCode query;

  /**
   * The task responsible for transmitting queries
   * for this request.
   */
  GNUNET_SCHEDULER_TaskIdentifier task;

  /**
   * (Interned) Peer identifier that identifies a preferred target
   * for requests.
   */
  GNUNET_PEER_Id target_pid;

  /**
   * (Interned) Peer identifiers of peers that have already
   * received our query for this content.
   */
  struct UsedTargetEntry *used_targets;
  
  /**
   * Our entry in the queue (non-NULL while we wait for our
   * turn to interact with the local database).
   */
  struct GNUNET_DATASTORE_QueueEntry *qe;

  /**
   * Size of the 'bf' (in bytes).
   */
  size_t bf_size;

  /**
   * Desired anonymity level; only valid for requests from a local client.
   */
  uint32_t anonymity_level;

  /**
   * How many entries in "used_targets" are actually valid?
   */
  unsigned int used_targets_off;

  /**
   * How long is the "used_targets" array?
   */
  unsigned int used_targets_size;

  /**
   * Number of results found for this request.
   */
  unsigned int results_found;

  /**
   * How many entries in "replies_seen" are actually valid?
   */
  unsigned int replies_seen_off;

  /**
   * How long is the "replies_seen" array?
   */
  unsigned int replies_seen_size;
  
  /**
   * Priority with which this request was made.  If one of our clients
   * made the request, then this is the current priority that we are
   * using when initiating the request.  This value is used when
   * we decide to reward other peers with trust for providing a reply.
   */
  uint32_t priority;

  /**
   * Priority points left for us to spend when forwarding this request
   * to other peers.
   */
  uint32_t remaining_priority;

  /**
   * Number to mingle hashes for bloom-filter tests with.
   */
  int32_t mingle;

  /**
   * TTL with which we saw this request (or, if we initiated, TTL that
   * we used for the request).
   */
  int32_t ttl;
  
  /**
   * Type of the content that this request is for.
   */
  enum GNUNET_BLOCK_Type type;

  /**
   * Remove this request after transmission of the current response.
   */
  int8_t do_remove;

  /**
   * GNUNET_YES if we should not forward this request to other peers.
   */
  int8_t local_only;

  /**
   * GNUNET_YES if we should not forward this request to other peers.
   */
  int8_t forward_only;

};


/**
 * Block that is ready for migration to other peers.  Actual data is at the end of the block.
 */
struct MigrationReadyBlock
{

  /**
   * This is a doubly-linked list.
   */
  struct MigrationReadyBlock *next;

  /**
   * This is a doubly-linked list.
   */
  struct MigrationReadyBlock *prev;

  /**
   * Query for the block.
   */
  GNUNET_HashCode query;

  /**
   * When does this block expire? 
   */
  struct GNUNET_TIME_Absolute expiration;

  /**
   * Peers we would consider forwarding this
   * block to.  Zero for empty entries.
   */
  GNUNET_PEER_Id target_list[MIGRATION_LIST_SIZE];

  /**
   * Size of the block.
   */
  size_t size;

  /**
   *  Number of targets already used.
   */
  unsigned int used_targets;

  /**
   * Type of the block.
   */
  enum GNUNET_BLOCK_Type type;
};


/**
 * Our connection to the datastore.
 */
static struct GNUNET_DATASTORE_Handle *dsh;

/**
 * Our block context.
 */
static struct GNUNET_BLOCK_Context *block_ctx;

/**
 * Our block configuration.
 */
static struct GNUNET_CONFIGURATION_Handle *block_cfg;

/**
 * Our scheduler.
 */
static struct GNUNET_SCHEDULER_Handle *sched;

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Map of peer identifiers to "struct ConnectedPeer" (for that peer).
 */
static struct GNUNET_CONTAINER_MultiHashMap *connected_peers;

/**
 * Map of peer identifiers to "struct PendingRequest" (for that peer).
 */
static struct GNUNET_CONTAINER_MultiHashMap *peer_request_map;

/**
 * Map of query identifiers to "struct PendingRequest" (for that query).
 */
static struct GNUNET_CONTAINER_MultiHashMap *query_request_map;

/**
 * Heap with the request that will expire next at the top.  Contains
 * pointers of type "struct PendingRequest*"; these will *also* be
 * aliased from the "requests_by_peer" data structures and the
 * "requests_by_query" table.  Note that requests from our clients
 * don't expire and are thus NOT in the "requests_by_expiration"
 * (or the "requests_by_peer" tables).
 */
static struct GNUNET_CONTAINER_Heap *requests_by_expiration_heap;

/**
 * Handle for reporting statistics.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Linked list of clients we are currently processing requests for.
 */
static struct ClientList *client_list;

/**
 * Pointer to handle to the core service (points to NULL until we've
 * connected to it).
 */
static struct GNUNET_CORE_Handle *core;

/**
 * Head of linked list of blocks that can be migrated.
 */
static struct MigrationReadyBlock *mig_head;

/**
 * Tail of linked list of blocks that can be migrated.
 */
static struct MigrationReadyBlock *mig_tail;

/**
 * Request to datastore for migration (or NULL).
 */
static struct GNUNET_DATASTORE_QueueEntry *mig_qe;

/**
 * Request to datastore for DHT PUTs (or NULL).
 */
static struct GNUNET_DATASTORE_QueueEntry *dht_qe;

/**
 * Type we will request for the next DHT PUT round from the datastore.
 */
static enum GNUNET_BLOCK_Type dht_put_type = GNUNET_BLOCK_TYPE_FS_KBLOCK;

/**
 * Where do we store trust information?
 */
static char *trustDirectory;

/**
 * ID of task that collects blocks for migration.
 */
static GNUNET_SCHEDULER_TaskIdentifier mig_task;

/**
 * ID of task that collects blocks for DHT PUTs.
 */
static GNUNET_SCHEDULER_TaskIdentifier dht_task;

/**
 * What is the maximum frequency at which we are allowed to
 * poll the datastore for migration content?
 */
static struct GNUNET_TIME_Relative min_migration_delay;

/**
 * Handle for DHT operations.
 */
static struct GNUNET_DHT_Handle *dht_handle;

/**
 * Size of the doubly-linked list of migration blocks.
 */
static unsigned int mig_size;

/**
 * Are we allowed to migrate content to this peer.
 */
static int active_migration;

/**
 * How many entires with zero anonymity do we currently estimate
 * to have in the database?
 */
static unsigned int zero_anonymity_count_estimate;

/**
 * Typical priorities we're seeing from other peers right now.  Since
 * most priorities will be zero, this value is the weighted average of
 * non-zero priorities seen "recently".  In order to ensure that new
 * values do not dramatically change the ratio, values are first
 * "capped" to a reasonable range (+N of the current value) and then
 * averaged into the existing value by a ratio of 1:N.  Hence
 * receiving the largest possible priority can still only raise our
 * "current_priorities" by at most 1.
 */
static double current_priorities;

/**
 * Datastore 'GET' load tracking.
 */
static struct GNUNET_LOAD_Value *datastore_get_load;

/**
 * Datastore 'PUT' load tracking.
 */
static struct GNUNET_LOAD_Value *datastore_put_load;

/**
 * How long do requests typically stay in the routing table?
 */
static struct GNUNET_LOAD_Value *rt_entry_lifetime;

/**
 * We've just now completed a datastore request.  Update our
 * datastore load calculations.
 *
 * @param start time when the datastore request was issued
 */
static void
update_datastore_delays (struct GNUNET_TIME_Absolute start)
{
  struct GNUNET_TIME_Relative delay;

  delay = GNUNET_TIME_absolute_get_duration (start);
  GNUNET_LOAD_update (datastore_get_load,
		      delay.value);
}


/**
 * Get the filename under which we would store the GNUNET_HELLO_Message
 * for the given host and protocol.
 * @return filename of the form DIRECTORY/HOSTID
 */
static char *
get_trust_filename (const struct GNUNET_PeerIdentity *id)
{
  struct GNUNET_CRYPTO_HashAsciiEncoded fil;
  char *fn;

  GNUNET_CRYPTO_hash_to_enc (&id->hashPubKey, &fil);
  GNUNET_asprintf (&fn, "%s%s%s", trustDirectory, DIR_SEPARATOR_STR, &fil);
  return fn;
}



/**
 * Transmit messages by copying it to the target buffer
 * "buf".  "buf" will be NULL and "size" zero if the socket was closed
 * for writing in the meantime.  In that case, do nothing
 * (the disconnect or shutdown handler will take care of the rest).
 * If we were able to transmit messages and there are still more
 * pending, ask core again for further calls to this function.
 *
 * @param cls closure, pointer to the 'struct ConnectedPeer*'
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_to_peer (void *cls,
		  size_t size, void *buf);


/* ******************* clean up functions ************************ */

/**
 * Delete the given migration block.
 *
 * @param mb block to delete
 */
static void
delete_migration_block (struct MigrationReadyBlock *mb)
{
  GNUNET_CONTAINER_DLL_remove (mig_head,
			       mig_tail,
			       mb);
  GNUNET_PEER_decrement_rcs (mb->target_list,
			     MIGRATION_LIST_SIZE);
  mig_size--;
  GNUNET_free (mb);
}


/**
 * Compare the distance of two peers to a key.
 *
 * @param key key
 * @param p1 first peer
 * @param p2 second peer
 * @return GNUNET_YES if P1 is closer to key than P2
 */
static int
is_closer (const GNUNET_HashCode *key,
	   const struct GNUNET_PeerIdentity *p1,
	   const struct GNUNET_PeerIdentity *p2)
{
  return GNUNET_CRYPTO_hash_xorcmp (&p1->hashPubKey,
				    &p2->hashPubKey,
				    key);
}


/**
 * Consider migrating content to a given peer.
 *
 * @param cls 'struct MigrationReadyBlock*' to select
 *            targets for (or NULL for none)
 * @param key ID of the peer 
 * @param value 'struct ConnectedPeer' of the peer
 * @return GNUNET_YES (always continue iteration)
 */
static int
consider_migration (void *cls,
		    const GNUNET_HashCode *key,
		    void *value)
{
  struct MigrationReadyBlock *mb = cls;
  struct ConnectedPeer *cp = value;
  struct MigrationReadyBlock *pos;
  struct GNUNET_PeerIdentity cppid;
  struct GNUNET_PeerIdentity otherpid;
  struct GNUNET_PeerIdentity worstpid;
  size_t msize;
  unsigned int i;
  unsigned int repl;
  
  /* consider 'cp' as a migration target for mb */
  if (GNUNET_TIME_absolute_get_remaining (cp->migration_blocked).value > 0)
    return GNUNET_YES; /* peer has requested no migration! */
  if (mb != NULL)
    {
      GNUNET_PEER_resolve (cp->pid,
			   &cppid);
      repl = MIGRATION_LIST_SIZE;
      for (i=0;i<MIGRATION_LIST_SIZE;i++)
	{
	  if (mb->target_list[i] == 0)
	    {
	      mb->target_list[i] = cp->pid;
	      GNUNET_PEER_change_rc (mb->target_list[i], 1);
	      repl = MIGRATION_LIST_SIZE;
	      break;
	    }
	  GNUNET_PEER_resolve (mb->target_list[i],
			       &otherpid);
	  if ( (repl == MIGRATION_LIST_SIZE) &&
	       is_closer (&mb->query,
			  &cppid,
			  &otherpid)) 
	    {
	      repl = i;
	      worstpid = otherpid;
	    }
	  else if ( (repl != MIGRATION_LIST_SIZE) &&
		    (is_closer (&mb->query,
				&worstpid,
				&otherpid) ) )
	    {
	      repl = i;
	      worstpid = otherpid;
	    }	    
	}
      if (repl != MIGRATION_LIST_SIZE) 
	{
	  GNUNET_PEER_change_rc (mb->target_list[repl], -1);
	  mb->target_list[repl] = cp->pid;
	  GNUNET_PEER_change_rc (mb->target_list[repl], 1);
	}
    }

  /* consider scheduling transmission to cp for content migration */
  if (cp->cth != NULL)        
    return GNUNET_YES; 
  msize = 0;
  pos = mig_head;
  while (pos != NULL)
    {
      for (i=0;i<MIGRATION_LIST_SIZE;i++)
	{
	  if (cp->pid == pos->target_list[i])
	    {
	      if (msize == 0)
		msize = pos->size;
	      else
		msize = GNUNET_MIN (msize,
				    pos->size);
	      break;
	    }
	}
      pos = pos->next;
    }
  if (msize == 0)
    return GNUNET_YES; /* no content available */
#if DEBUG_FS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Trying to migrate at least %u bytes to peer `%s'\n",
	      msize,
	      GNUNET_h2s (key));
#endif
  if (cp->delayed_transmission_request_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (sched, cp->delayed_transmission_request_task);
      cp->delayed_transmission_request_task = GNUNET_SCHEDULER_NO_TASK;
    }
  cp->cth 
    = GNUNET_CORE_notify_transmit_ready (core,
					 0, GNUNET_TIME_UNIT_FOREVER_REL,
					 (const struct GNUNET_PeerIdentity*) key,
					 msize + sizeof (struct PutMessage),
					 &transmit_to_peer,
					 cp);
  return GNUNET_YES;
}


/**
 * Task that is run periodically to obtain blocks for content
 * migration
 * 
 * @param cls unused
 * @param tc scheduler context (also unused)
 */
static void
gather_migration_blocks (void *cls,
			 const struct GNUNET_SCHEDULER_TaskContext *tc);




/**
 * Task that is run periodically to obtain blocks for DHT PUTs.
 * 
 * @param cls type of blocks to gather
 * @param tc scheduler context (unused)
 */
static void
gather_dht_put_blocks (void *cls,
		       const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * If the migration task is not currently running, consider
 * (re)scheduling it with the appropriate delay.
 */
static void
consider_migration_gathering ()
{
  struct GNUNET_TIME_Relative delay;

  if (dsh == NULL)
    return;
  if (mig_qe != NULL)
    return;
  if (mig_task != GNUNET_SCHEDULER_NO_TASK)
    return;
  delay = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
					 mig_size);
  delay = GNUNET_TIME_relative_divide (delay,
				       MAX_MIGRATION_QUEUE);
  delay = GNUNET_TIME_relative_max (delay,
				    min_migration_delay);
  mig_task = GNUNET_SCHEDULER_add_delayed (sched,
					   delay,
					   &gather_migration_blocks,
					   NULL);
}


/**
 * If the DHT PUT gathering task is not currently running, consider
 * (re)scheduling it with the appropriate delay.
 */
static void
consider_dht_put_gathering (void *cls)
{
  struct GNUNET_TIME_Relative delay;

  if (dsh == NULL)
    return;
  if (dht_qe != NULL)
    return;
  if (dht_task != GNUNET_SCHEDULER_NO_TASK)
    return;
  if (zero_anonymity_count_estimate > 0)
    {
      delay = GNUNET_TIME_relative_divide (GNUNET_DHT_DEFAULT_REPUBLISH_FREQUENCY,
					   zero_anonymity_count_estimate);
      delay = GNUNET_TIME_relative_min (delay,
					MAX_DHT_PUT_FREQ);
    }
  else
    {
      /* if we have NO zero-anonymity content yet, wait 5 minutes for some to
	 (hopefully) appear */
      delay = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 5);
    }
  dht_task = GNUNET_SCHEDULER_add_delayed (sched,
					   delay,
					   &gather_dht_put_blocks,
					   cls);
}


/**
 * Process content offered for migration.
 *
 * @param cls closure
 * @param key key for the content
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum;
 *        maybe 0 if no unique identifier is available
 */
static void
process_migration_content (void *cls,
			   const GNUNET_HashCode * key,
			   size_t size,
			   const void *data,
			   enum GNUNET_BLOCK_Type type,
			   uint32_t priority,
			   uint32_t anonymity,
			   struct GNUNET_TIME_Absolute
			   expiration, uint64_t uid)
{
  struct MigrationReadyBlock *mb;
  
  if (key == NULL)
    {
      mig_qe = NULL;
      if (mig_size < MAX_MIGRATION_QUEUE)  
	consider_migration_gathering ();
      return;
    }
  if (type == GNUNET_BLOCK_TYPE_FS_ONDEMAND)
    {
      if (GNUNET_OK !=
	  GNUNET_FS_handle_on_demand_block (key, size, data,
					    type, priority, anonymity,
					    expiration, uid, 
					    &process_migration_content,
					    NULL))
	{
	  GNUNET_DATASTORE_get_next (dsh, GNUNET_YES);
	}
      return;
    }
#if DEBUG_FS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Retrieved block `%s' of type %u for migration\n",
	      GNUNET_h2s (key),
	      type);
#endif
  mb = GNUNET_malloc (sizeof (struct MigrationReadyBlock) + size);
  mb->query = *key;
  mb->expiration = expiration;
  mb->size = size;
  mb->type = type;
  memcpy (&mb[1], data, size);
  GNUNET_CONTAINER_DLL_insert_after (mig_head,
				     mig_tail,
				     mig_tail,
				     mb);
  mig_size++;
  GNUNET_CONTAINER_multihashmap_iterate (connected_peers,
					 &consider_migration,
					 mb);
  GNUNET_DATASTORE_get_next (dsh, GNUNET_YES);
}


/**
 * Function called upon completion of the DHT PUT operation.
 */
static void
dht_put_continuation (void *cls,
		      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_DATASTORE_get_next (dsh, GNUNET_YES);
}


/**
 * Store content in DHT.
 *
 * @param cls closure
 * @param key key for the content
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum;
 *        maybe 0 if no unique identifier is available
 */
static void
process_dht_put_content (void *cls,
			 const GNUNET_HashCode * key,
			 size_t size,
			 const void *data,
			 enum GNUNET_BLOCK_Type type,
			 uint32_t priority,
			 uint32_t anonymity,
			 struct GNUNET_TIME_Absolute
			 expiration, uint64_t uid)
{ 
  static unsigned int counter;
  static GNUNET_HashCode last_vhash;
  static GNUNET_HashCode vhash;

  if (key == NULL)
    {
      dht_qe = NULL;
      consider_dht_put_gathering (cls);
      return;
    }
  /* slightly funky code to estimate the total number of values with zero
     anonymity from the maximum observed length of a monotonically increasing 
     sequence of hashes over the contents */
  GNUNET_CRYPTO_hash (data, size, &vhash);
  if (GNUNET_CRYPTO_hash_cmp (&vhash, &last_vhash) <= 0)
    {
      if (zero_anonymity_count_estimate > 0)
	zero_anonymity_count_estimate /= 2;
      counter = 0;
    }
  last_vhash = vhash;
  if (counter < 31)
    counter++;
  if (zero_anonymity_count_estimate < (1 << counter))
    zero_anonymity_count_estimate = (1 << counter);
#if DEBUG_FS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Retrieved block `%s' of type %u for DHT PUT\n",
	      GNUNET_h2s (key),
	      type);
#endif
  GNUNET_DHT_put (dht_handle,
		  key,
		  GNUNET_DHT_RO_NONE,
		  type,
		  size,
		  data,
		  expiration,
		  GNUNET_TIME_UNIT_FOREVER_REL,
		  &dht_put_continuation,
		  cls);
}


/**
 * Task that is run periodically to obtain blocks for content
 * migration
 * 
 * @param cls unused
 * @param tc scheduler context (also unused)
 */
static void
gather_migration_blocks (void *cls,
			 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  mig_task = GNUNET_SCHEDULER_NO_TASK;
  if (dsh != NULL)
    {
      mig_qe = GNUNET_DATASTORE_get_random (dsh, 0, UINT_MAX,
					    GNUNET_TIME_UNIT_FOREVER_REL,
					    &process_migration_content, NULL);
      GNUNET_assert (mig_qe != NULL);
    }
}


/**
 * Task that is run periodically to obtain blocks for DHT PUTs.
 * 
 * @param cls type of blocks to gather
 * @param tc scheduler context (unused)
 */
static void
gather_dht_put_blocks (void *cls,
		       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  dht_task = GNUNET_SCHEDULER_NO_TASK;
  if (dsh != NULL)
    {
      if (dht_put_type == GNUNET_BLOCK_TYPE_FS_ONDEMAND)
	dht_put_type = GNUNET_BLOCK_TYPE_FS_KBLOCK;
      dht_qe = GNUNET_DATASTORE_get_zero_anonymity (dsh, 0, UINT_MAX,
						    GNUNET_TIME_UNIT_FOREVER_REL,
						    dht_put_type++,
						    &process_dht_put_content, NULL);
      GNUNET_assert (dht_qe != NULL);
    }
}


/**
 * We're done with a particular message list entry.
 * Free all associated resources.
 * 
 * @param pml entry to destroy
 */
static void
destroy_pending_message_list_entry (struct PendingMessageList *pml)
{
  GNUNET_CONTAINER_DLL_remove (pml->req->pending_head,
			       pml->req->pending_tail,
			       pml);
  GNUNET_CONTAINER_DLL_remove (pml->target->pending_messages_head,
			       pml->target->pending_messages_tail,
			       pml->pm);
  pml->target->pending_requests--;
  GNUNET_free (pml->pm);
  GNUNET_free (pml);
}


/**
 * Destroy the given pending message (and call the respective
 * continuation).
 *
 * @param pm message to destroy
 * @param tpid id of peer that the message was delivered to, or 0 for none
 */
static void
destroy_pending_message (struct PendingMessage *pm,
			 GNUNET_PEER_Id tpid)
{
  struct PendingMessageList *pml = pm->pml;
  TransmissionContinuation cont;
  void *cont_cls;

  cont = pm->cont;
  cont_cls = pm->cont_cls;
  if (pml != NULL)
    {
      GNUNET_assert (pml->pm == pm);
      GNUNET_assert ( (tpid == 0) || (tpid == pml->target->pid) );
      destroy_pending_message_list_entry (pml);
    }
  else
    {
      GNUNET_free (pm);
    }
  if (cont != NULL)
    cont (cont_cls, tpid);  
}


/**
 * We're done processing a particular request.
 * Free all associated resources.
 *
 * @param pr request to destroy
 */
static void
destroy_pending_request (struct PendingRequest *pr)
{
  struct GNUNET_PeerIdentity pid;
  unsigned int i;

  if (pr->hnode != NULL)
    {
      GNUNET_CONTAINER_heap_remove_node (requests_by_expiration_heap,
					 pr->hnode);
      pr->hnode = NULL;
    }
  if (NULL == pr->client_request_list)
    {
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# P2P searches active"),
				-1,
				GNUNET_NO);
    }
  else
    {
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# client searches active"),
				-1,
				GNUNET_NO);
    }
  if (GNUNET_YES == 
      GNUNET_CONTAINER_multihashmap_remove (query_request_map,
					    &pr->query,
					    pr))
    {
      GNUNET_LOAD_update (rt_entry_lifetime,
			  GNUNET_TIME_absolute_get_duration (pr->start_time).value);
    }
  if (pr->qe != NULL)
     {
      GNUNET_DATASTORE_cancel (pr->qe);
      pr->qe = NULL;
    }
  if (pr->dht_get != NULL)
    {
      GNUNET_DHT_get_stop (pr->dht_get);
      pr->dht_get = NULL;
    }
  if (pr->client_request_list != NULL)
    {
      GNUNET_CONTAINER_DLL_remove (pr->client_request_list->client_list->rl_head,
				   pr->client_request_list->client_list->rl_tail,
				   pr->client_request_list);
      GNUNET_free (pr->client_request_list);
      pr->client_request_list = NULL;
    }
  if (pr->cp != NULL)
    {
      GNUNET_PEER_resolve (pr->cp->pid,
			   &pid);
      (void) GNUNET_CONTAINER_multihashmap_remove (peer_request_map,
						   &pid.hashPubKey,
						   pr);
      pr->cp = NULL;
    }
  if (pr->bf != NULL)
    {
      GNUNET_CONTAINER_bloomfilter_free (pr->bf);					 
      pr->bf = NULL;
    }
  if (pr->irc != NULL)
    {
      GNUNET_CORE_peer_change_preference_cancel (pr->irc);
      pr->irc = NULL;
    }
  if (pr->replies_seen != NULL)
    {
      GNUNET_free (pr->replies_seen);
      pr->replies_seen = NULL;
    }
  if (pr->task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (sched,
			       pr->task);
      pr->task = GNUNET_SCHEDULER_NO_TASK;
    }
  while (NULL != pr->pending_head)    
    destroy_pending_message_list_entry (pr->pending_head);
  GNUNET_PEER_change_rc (pr->target_pid, -1);
  if (pr->used_targets != NULL)
    {
      for (i=0;i<pr->used_targets_off;i++)
	GNUNET_PEER_change_rc (pr->used_targets[i].pid, -1);
      GNUNET_free (pr->used_targets);
      pr->used_targets_off = 0;
      pr->used_targets_size = 0;
      pr->used_targets = NULL;
    }
  GNUNET_free (pr);
}


/**
 * Method called whenever a given peer connects.
 *
 * @param cls closure, not used
 * @param peer peer identity this notification is about
 * @param latency reported latency of the connection with 'other'
 * @param distance reported distance (DV) to 'other' 
 */
static void 
peer_connect_handler (void *cls,
		      const struct
		      GNUNET_PeerIdentity * peer,
		      struct GNUNET_TIME_Relative latency,
		      uint32_t distance)
{
  struct ConnectedPeer *cp;
  struct MigrationReadyBlock *pos;
  char *fn;
  uint32_t trust;
  
  cp = GNUNET_malloc (sizeof (struct ConnectedPeer));
  cp->transmission_delay = GNUNET_LOAD_value_init (latency);
  cp->pid = GNUNET_PEER_intern (peer);

  fn = get_trust_filename (peer);
  if ((GNUNET_DISK_file_test (fn) == GNUNET_YES) &&
      (sizeof (trust) == GNUNET_DISK_fn_read (fn, &trust, sizeof (trust))))
    cp->disk_trust = cp->trust = ntohl (trust);
  GNUNET_free (fn);

  GNUNET_break (GNUNET_OK ==
		GNUNET_CONTAINER_multihashmap_put (connected_peers,
						   &peer->hashPubKey,
						   cp,
						   GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));

  pos = mig_head;
  while (NULL != pos)
    {
      (void) consider_migration (pos, &peer->hashPubKey, cp);
      pos = pos->next;
    }
}


/**
 * Method called whenever a given peer has a status change.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param latency reported latency of the connection with 'other'
 * @param distance reported distance (DV) to 'other' 
 * @param bandwidth_in available amount of inbound bandwidth
 * @param bandwidth_out available amount of outbound bandwidth
 * @param timeout absolute time when this peer will time out
 *        unless we see some further activity from it
 */
static void
peer_status_handler (void *cls,
		     const struct
		     GNUNET_PeerIdentity * peer,
		     struct GNUNET_TIME_Relative latency,
		     uint32_t distance,
		     struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
		     struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
		     struct GNUNET_TIME_Absolute timeout)
{
  struct ConnectedPeer *cp;

  cp = GNUNET_CONTAINER_multihashmap_get (connected_peers,
					  &peer->hashPubKey);
  GNUNET_assert (cp != NULL);
  GNUNET_LOAD_value_set_decline (cp->transmission_delay,
				 latency);  
}



/**
 * Increase the host credit by a value.
 *
 * @param host which peer to change the trust value on
 * @param value is the int value by which the
 *  host credit is to be increased or decreased
 * @returns the actual change in trust (positive or negative)
 */
static int
change_host_trust (struct ConnectedPeer *host, int value)
{
  unsigned int old_trust;

  if (value == 0)
    return 0;
  GNUNET_assert (host != NULL);
  old_trust = host->trust;
  if (value > 0)
    {
      if (host->trust + value < host->trust)
        {
          value = UINT32_MAX - host->trust;
          host->trust = UINT32_MAX;
        }
      else
        host->trust += value;
    }
  else
    {
      if (host->trust < -value)
        {
          value = -host->trust;
          host->trust = 0;
        }
      else
        host->trust += value;
    }
  return value;
}


/**
 * Write host-trust information to a file - flush the buffer entry!
 */
static int
flush_trust (void *cls,
	     const GNUNET_HashCode *key,
	     void *value)
{
  struct ConnectedPeer *host = value;
  char *fn;
  uint32_t trust;
  struct GNUNET_PeerIdentity pid;

  if (host->trust == host->disk_trust)
    return GNUNET_OK;                     /* unchanged */
  GNUNET_PEER_resolve (host->pid,
		       &pid);
  fn = get_trust_filename (&pid);
  if (host->trust == 0)
    {
      if ((0 != UNLINK (fn)) && (errno != ENOENT))
        GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING |
                                  GNUNET_ERROR_TYPE_BULK, "unlink", fn);
    }
  else
    {
      trust = htonl (host->trust);
      if (sizeof(uint32_t) == GNUNET_DISK_fn_write (fn, &trust, 
						    sizeof(uint32_t),
						    GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE
						    | GNUNET_DISK_PERM_GROUP_READ | GNUNET_DISK_PERM_OTHER_READ))
        host->disk_trust = host->trust;
    }
  GNUNET_free (fn);
  return GNUNET_OK;
}

/**
 * Call this method periodically to scan data/hosts for new hosts.
 */
static void
cron_flush_trust (void *cls,
		  const struct GNUNET_SCHEDULER_TaskContext *tc)
{

  if (NULL == connected_peers)
    return;
  GNUNET_CONTAINER_multihashmap_iterate (connected_peers,
					 &flush_trust,
					 NULL);
  if (NULL == tc)
    return;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  GNUNET_SCHEDULER_add_delayed (tc->sched,
				TRUST_FLUSH_FREQ, &cron_flush_trust, NULL);
}


/**
 * Free (each) request made by the peer.
 *
 * @param cls closure, points to peer that the request belongs to
 * @param key current key code
 * @param value value in the hash map
 * @return GNUNET_YES (we should continue to iterate)
 */
static int
destroy_request (void *cls,
		 const GNUNET_HashCode * key,
		 void *value)
{
  const struct GNUNET_PeerIdentity * peer = cls;
  struct PendingRequest *pr = value;
  
  GNUNET_break (GNUNET_YES ==
		GNUNET_CONTAINER_multihashmap_remove (peer_request_map,
						      &peer->hashPubKey,
						      pr));
  destroy_pending_request (pr);
  return GNUNET_YES;
}


/**
 * Method called whenever a peer disconnects.
 *
 * @param cls closure, not used
 * @param peer peer identity this notification is about
 */
static void
peer_disconnect_handler (void *cls,
			 const struct
			 GNUNET_PeerIdentity * peer)
{
  struct ConnectedPeer *cp;
  struct PendingMessage *pm;
  unsigned int i;
  struct MigrationReadyBlock *pos;
  struct MigrationReadyBlock *next;

  GNUNET_CONTAINER_multihashmap_get_multiple (peer_request_map,
					      &peer->hashPubKey,
					      &destroy_request,
					      (void*) peer);
  cp = GNUNET_CONTAINER_multihashmap_get (connected_peers,
					  &peer->hashPubKey);
  if (cp == NULL)
    return;
  for (i=0;i<CS2P_SUCCESS_LIST_SIZE;i++)
    {
      if (NULL != cp->last_client_replies[i])
	{
	  GNUNET_SERVER_client_drop (cp->last_client_replies[i]);
	  cp->last_client_replies[i] = NULL;
	}
    }
  GNUNET_break (GNUNET_YES ==
		GNUNET_CONTAINER_multihashmap_remove (connected_peers,
						      &peer->hashPubKey,
						      cp));
  /* remove this peer from migration considerations; schedule
     alternatives */
  next = mig_head;
  while (NULL != (pos = next))
    {
      next = pos->next;
      for (i=0;i<MIGRATION_LIST_SIZE;i++)
	{
	  if (pos->target_list[i] == cp->pid)
	    {
	      GNUNET_PEER_change_rc (pos->target_list[i], -1);
	      pos->target_list[i] = 0;
            }
         }
      if (pos->used_targets >= GNUNET_CONTAINER_multihashmap_size (connected_peers))
	{
	  delete_migration_block (pos);
	  consider_migration_gathering ();
          continue;
	}
      GNUNET_CONTAINER_multihashmap_iterate (connected_peers,
					     &consider_migration,
					     pos);
    }
  GNUNET_PEER_change_rc (cp->pid, -1);
  GNUNET_PEER_decrement_rcs (cp->last_p2p_replies, P2P_SUCCESS_LIST_SIZE);
  if (NULL != cp->cth)
    {
      GNUNET_CORE_notify_transmit_ready_cancel (cp->cth);
      cp->cth = NULL;
    }
  if (cp->delayed_transmission_request_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (sched, cp->delayed_transmission_request_task);
      cp->delayed_transmission_request_task = GNUNET_SCHEDULER_NO_TASK;
    }
  while (NULL != (pm = cp->pending_messages_head))
    destroy_pending_message (pm, 0 /* delivery failed */);
  GNUNET_LOAD_value_free (cp->transmission_delay);
  GNUNET_break (0 == cp->pending_requests);
  GNUNET_free (cp);
}


/**
 * Iterator over hash map entries that removes all occurences
 * of the given 'client' from the 'last_client_replies' of the
 * given connected peer.
 *
 * @param cls closure, the 'struct GNUNET_SERVER_Client*' to remove
 * @param key current key code (unused)
 * @param value value in the hash map (the 'struct ConnectedPeer*' to change)
 * @return GNUNET_YES (we should continue to iterate)
 */
static int
remove_client_from_last_client_replies (void *cls,
					const GNUNET_HashCode * key,
					void *value)
{
  struct GNUNET_SERVER_Client *client = cls;
  struct ConnectedPeer *cp = value;
  unsigned int i;

  for (i=0;i<CS2P_SUCCESS_LIST_SIZE;i++)
    {
      if (cp->last_client_replies[i] == client)
	{
	  GNUNET_SERVER_client_drop (cp->last_client_replies[i]);
	  cp->last_client_replies[i] = NULL;
	}
    }  
  return GNUNET_YES;
}


/**
 * A client disconnected.  Remove all of its pending queries.
 *
 * @param cls closure, NULL
 * @param client identification of the client
 */
static void
handle_client_disconnect (void *cls,
			  struct GNUNET_SERVER_Client
			  * client)
{
  struct ClientList *pos;
  struct ClientList *prev;
  struct ClientRequestList *rcl;
  struct ClientResponseMessage *creply;

  if (client == NULL)
    return;
  prev = NULL;
  pos = client_list;
  while ( (NULL != pos) &&
	  (pos->client != client) )
    {
      prev = pos;
      pos = pos->next;
    }
  if (pos == NULL)
    return; /* no requests pending for this client */
  while (NULL != (rcl = pos->rl_head))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  "Destroying pending request `%s' on disconnect\n",
		  GNUNET_h2s (&rcl->req->query));
      destroy_pending_request (rcl->req);
    }
  if (prev == NULL)
    client_list = pos->next;
  else
    prev->next = pos->next;
  if (pos->th != NULL)
    {
      GNUNET_CONNECTION_notify_transmit_ready_cancel (pos->th);
      pos->th = NULL;
    }
  while (NULL != (creply = pos->res_head))
    {
      GNUNET_CONTAINER_DLL_remove (pos->res_head,
				   pos->res_tail,
				   creply);
      GNUNET_free (creply);
    }    
  GNUNET_SERVER_client_drop (pos->client);
  GNUNET_free (pos);
  GNUNET_CONTAINER_multihashmap_iterate (connected_peers,
					 &remove_client_from_last_client_replies,
					 client);
}


/**
 * Iterator to free peer entries.
 *
 * @param cls closure, unused
 * @param key current key code
 * @param value value in the hash map (peer entry)
 * @return GNUNET_YES (we should continue to iterate)
 */
static int 
clean_peer (void *cls,
	    const GNUNET_HashCode * key,
	    void *value)
{
  peer_disconnect_handler (NULL, (const struct GNUNET_PeerIdentity*) key);
  return GNUNET_YES;
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
  if (mig_qe != NULL)
    {
      GNUNET_DATASTORE_cancel (mig_qe);
      mig_qe = NULL;
    }
  if (dht_qe != NULL)
    {
      GNUNET_DATASTORE_cancel (dht_qe);
      dht_qe = NULL;
    }
  if (GNUNET_SCHEDULER_NO_TASK != mig_task)
    {
      GNUNET_SCHEDULER_cancel (sched, mig_task);
      mig_task = GNUNET_SCHEDULER_NO_TASK;
    }
  if (GNUNET_SCHEDULER_NO_TASK != dht_task)
    {
      GNUNET_SCHEDULER_cancel (sched, dht_task);
      dht_task = GNUNET_SCHEDULER_NO_TASK;
    }
  while (client_list != NULL)
    handle_client_disconnect (NULL,
			      client_list->client);
  cron_flush_trust (NULL, NULL);
  GNUNET_CONTAINER_multihashmap_iterate (connected_peers,
					 &clean_peer,
					 NULL);
  GNUNET_break (0 == GNUNET_CONTAINER_heap_get_size (requests_by_expiration_heap));
  GNUNET_CONTAINER_heap_destroy (requests_by_expiration_heap);
  requests_by_expiration_heap = 0;
  GNUNET_CONTAINER_multihashmap_destroy (connected_peers);
  connected_peers = NULL;
  GNUNET_break (0 == GNUNET_CONTAINER_multihashmap_size (query_request_map));
  GNUNET_CONTAINER_multihashmap_destroy (query_request_map);
  query_request_map = NULL;
  GNUNET_LOAD_value_free (rt_entry_lifetime);
  rt_entry_lifetime = NULL;
  GNUNET_break (0 == GNUNET_CONTAINER_multihashmap_size (peer_request_map));
  GNUNET_CONTAINER_multihashmap_destroy (peer_request_map);
  peer_request_map = NULL;
  GNUNET_assert (NULL != core);
  GNUNET_CORE_disconnect (core);
  core = NULL;
  if (stats != NULL)
    {
      GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
      stats = NULL;
    }
  if (dsh != NULL)
    {
      GNUNET_DATASTORE_disconnect (dsh,
				   GNUNET_NO);
      dsh = NULL;
    }
  while (mig_head != NULL)
    delete_migration_block (mig_head);
  GNUNET_assert (0 == mig_size);
  GNUNET_DHT_disconnect (dht_handle);
  dht_handle = NULL;
  GNUNET_LOAD_value_free (datastore_get_load);
  datastore_get_load = NULL;
  GNUNET_LOAD_value_free (datastore_put_load);
  datastore_put_load = NULL;
  GNUNET_BLOCK_context_destroy (block_ctx);
  block_ctx = NULL;
  GNUNET_CONFIGURATION_destroy (block_cfg);
  block_cfg = NULL;
  sched = NULL;
  cfg = NULL;  
  GNUNET_free_non_null (trustDirectory);
  trustDirectory = NULL;
}


/* ******************* Utility functions  ******************** */


/**
 * We've had to delay a request for transmission to core, but now
 * we should be ready.  Run it.
 *
 * @param cls the 'struct ConnectedPeer' for which a request was delayed
 * @param tc task context (unused)
 */
static void
delayed_transmission_request (void *cls,
			      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ConnectedPeer *cp = cls;
  struct GNUNET_PeerIdentity pid;
  struct PendingMessage *pm;

  pm = cp->pending_messages_head;
  cp->delayed_transmission_request_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_assert (cp->cth == NULL);
  if (pm == NULL)
    return;
  GNUNET_PEER_resolve (cp->pid,
		       &pid);
  cp->last_transmission_request_start = GNUNET_TIME_absolute_get ();
  cp->cth = GNUNET_CORE_notify_transmit_ready (core,
					       pm->priority,
					       GNUNET_CONSTANTS_SERVICE_TIMEOUT,
					       &pid,
					       pm->msize,
					       &transmit_to_peer,
					       cp);
}


/**
 * Transmit messages by copying it to the target buffer
 * "buf".  "buf" will be NULL and "size" zero if the socket was closed
 * for writing in the meantime.  In that case, do nothing
 * (the disconnect or shutdown handler will take care of the rest).
 * If we were able to transmit messages and there are still more
 * pending, ask core again for further calls to this function.
 *
 * @param cls closure, pointer to the 'struct ConnectedPeer*'
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_to_peer (void *cls,
		  size_t size, void *buf)
{
  struct ConnectedPeer *cp = cls;
  char *cbuf = buf;
  struct PendingMessage *pm;
  struct PendingMessage *next_pm;
  struct GNUNET_TIME_Absolute now;
  struct GNUNET_TIME_Relative min_delay;
  struct MigrationReadyBlock *mb;
  struct MigrationReadyBlock *next;
  struct PutMessage migm;
  size_t msize;
  unsigned int i;
  struct GNUNET_PeerIdentity pid;
 
  cp->cth = NULL;
  if (NULL == buf)
    {
#if DEBUG_FS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Dropping message, core too busy.\n");
#endif
      GNUNET_LOAD_update (cp->transmission_delay,
			  UINT64_MAX);
      return 0;
    }  
  GNUNET_LOAD_update (cp->transmission_delay,
		      GNUNET_TIME_absolute_get_duration (cp->last_transmission_request_start).value);
  now = GNUNET_TIME_absolute_get ();
  msize = 0;
  min_delay = GNUNET_TIME_UNIT_FOREVER_REL;
  next_pm = cp->pending_messages_head;
  while ( (NULL != (pm = next_pm) ) &&
	  (pm->msize <= size) )
    {
      next_pm = pm->next;
      if (pm->delay_until.value > now.value)
	{
	  min_delay = GNUNET_TIME_relative_min (min_delay,
						GNUNET_TIME_absolute_get_remaining (pm->delay_until));
	  continue;
	}
      memcpy (&cbuf[msize], &pm[1], pm->msize);
      msize += pm->msize;
      size -= pm->msize;
      if (NULL == pm->pml)
	{
	  GNUNET_CONTAINER_DLL_remove (cp->pending_messages_head,
				       cp->pending_messages_tail,
				       pm);
	  cp->pending_requests--;
	}
      destroy_pending_message (pm, cp->pid);
    }
  if (pm != NULL)
    min_delay = GNUNET_TIME_UNIT_ZERO;
  if (NULL != cp->pending_messages_head)
    {     
      GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == cp->delayed_transmission_request_task);
      cp->delayed_transmission_request_task
	= GNUNET_SCHEDULER_add_delayed (sched,
					min_delay,
					&delayed_transmission_request,
					cp);
    }
  if (pm == NULL)
    {      
      GNUNET_PEER_resolve (cp->pid,
			   &pid);
      next = mig_head;
      while (NULL != (mb = next))
	{
	  next = mb->next;
	  for (i=0;i<MIGRATION_LIST_SIZE;i++)
	    {
	      if ( (cp->pid == mb->target_list[i]) &&
		   (mb->size + sizeof (migm) <= size) )
		{
		  GNUNET_PEER_change_rc (mb->target_list[i], -1);
		  mb->target_list[i] = 0;
		  mb->used_targets++;
		  memset (&migm, 0, sizeof (migm));
		  migm.header.size = htons (sizeof (migm) + mb->size);
		  migm.header.type = htons (GNUNET_MESSAGE_TYPE_FS_PUT);
		  migm.type = htonl (mb->type);
		  migm.expiration = GNUNET_TIME_absolute_hton (mb->expiration);
		  memcpy (&cbuf[msize], &migm, sizeof (migm));
		  msize += sizeof (migm);
		  size -= sizeof (migm);
		  memcpy (&cbuf[msize], &mb[1], mb->size);
		  msize += mb->size;
		  size -= mb->size;
#if DEBUG_FS
		  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			      "Pushing migration block `%s' (%u bytes) to `%s'\n",
			      GNUNET_h2s (&mb->query),
			      (unsigned int) mb->size,
			      GNUNET_i2s (&pid));
#endif	  
		  break;
		}
	      else
		{
#if DEBUG_FS
		  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			      "Migration block `%s' (%u bytes) is not on migration list for peer `%s'\n",
			      GNUNET_h2s (&mb->query),
			      (unsigned int) mb->size,
			      GNUNET_i2s (&pid));
#endif	  
		}
	    }
	  if ( (mb->used_targets >= MIGRATION_TARGET_COUNT) ||
	       (mb->used_targets >= GNUNET_CONTAINER_multihashmap_size (connected_peers)) )
	    {
	      delete_migration_block (mb);
	      consider_migration_gathering ();
	    }
	}
      consider_migration (NULL, 
			  &pid.hashPubKey,
			  cp);
    }
#if DEBUG_FS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Transmitting %u bytes to peer with PID %u\n",
	      (unsigned int) msize,
	      (unsigned int) cp->pid);
#endif
  return msize;
}


/**
 * Add a message to the set of pending messages for the given peer.
 *
 * @param cp peer to send message to
 * @param pm message to queue
 * @param pr request on which behalf this message is being queued
 */
static void
add_to_pending_messages_for_peer (struct ConnectedPeer *cp,
				  struct PendingMessage *pm,
				  struct PendingRequest *pr)
{
  struct PendingMessage *pos;
  struct PendingMessageList *pml;
  struct GNUNET_PeerIdentity pid;

  GNUNET_assert (pm->next == NULL);
  GNUNET_assert (pm->pml == NULL);    
  if (pr != NULL)
    {
      pml = GNUNET_malloc (sizeof (struct PendingMessageList));
      pml->req = pr;
      pml->target = cp;
      pml->pm = pm;
      pm->pml = pml;  
      GNUNET_CONTAINER_DLL_insert (pr->pending_head,
				   pr->pending_tail,
				   pml);
    }
  pos = cp->pending_messages_head;
  while ( (pos != NULL) &&
	  (pm->priority < pos->priority) )
    pos = pos->next;    
  GNUNET_CONTAINER_DLL_insert_after (cp->pending_messages_head,
				     cp->pending_messages_tail,
				     pos,
				     pm);
  cp->pending_requests++;
  if (cp->pending_requests > MAX_QUEUE_PER_PEER)
    {
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# P2P searches discarded (queue length bound)"),
				1,
				GNUNET_NO);
      destroy_pending_message (cp->pending_messages_tail, 0);  
    }
  GNUNET_PEER_resolve (cp->pid, &pid);
  if (NULL != cp->cth)
    {
      GNUNET_CORE_notify_transmit_ready_cancel (cp->cth);
      cp->cth = NULL;
    }
  if (cp->delayed_transmission_request_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (sched, cp->delayed_transmission_request_task);
      cp->delayed_transmission_request_task = GNUNET_SCHEDULER_NO_TASK;
    }
  /* need to schedule transmission */
  cp->last_transmission_request_start = GNUNET_TIME_absolute_get ();
  cp->cth = GNUNET_CORE_notify_transmit_ready (core,
					       cp->pending_messages_head->priority,
					       MAX_TRANSMIT_DELAY,
					       &pid,
					       cp->pending_messages_head->msize,
					       &transmit_to_peer,
					       cp);
  if (cp->cth == NULL)
    {
#if DEBUG_FS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Failed to schedule transmission with core!\n");
#endif
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# CORE transmission failures"),
				1,
				GNUNET_NO);
    }
}


/**
 * Test if the DATABASE (GET) load on this peer is too high
 * to even consider processing the query at
 * all.  
 * 
 * @return GNUNET_YES if the load is too high to do anything (load high)
 *         GNUNET_NO to process normally (load normal)
 *         GNUNET_SYSERR to process for free (load low)
 */
static int
test_get_load_too_high (uint32_t priority)
{
  double ld;

  ld = GNUNET_LOAD_get_load (datastore_get_load);
  if (ld < 1)
    return GNUNET_SYSERR;    
  if (ld <= priority)    
    return GNUNET_NO;    
  return GNUNET_YES;
}




/**
 * Test if the DATABASE (PUT) load on this peer is too high
 * to even consider processing the query at
 * all.  
 * 
 * @return GNUNET_YES if the load is too high to do anything (load high)
 *         GNUNET_NO to process normally (load normal or low)
 */
static int
test_put_load_too_high (uint32_t priority)
{
  double ld;

  if (GNUNET_LOAD_get_average (datastore_put_load) < 50)
    return GNUNET_NO; /* very fast */
  ld = GNUNET_LOAD_get_load (datastore_put_load);
  if (ld < 2.0 * (1 + priority))
    return GNUNET_NO;
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# storage requests dropped due to high load"),
			    1,
			    GNUNET_NO);
  return GNUNET_YES;
}


/* ******************* Pending Request Refresh Task ******************** */



/**
 * We use a random delay to make the timing of requests less
 * predictable.  This function returns such a random delay.  We add a base
 * delay of MAX_CORK_DELAY (1s).
 *
 * FIXME: make schedule dependent on the specifics of the request?
 * Or bandwidth and number of connected peers and load?
 *
 * @return random delay to use for some request, between 1s and 1000+TTL_DECREMENT ms
 */
static struct GNUNET_TIME_Relative
get_processing_delay ()
{
  return 
    GNUNET_TIME_relative_add (GNUNET_CONSTANTS_MAX_CORK_DELAY,
			      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS,
							     GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
										       TTL_DECREMENT)));
}


/**
 * We're processing a GET request from another peer and have decided
 * to forward it to other peers.  This function is called periodically
 * and should forward the request to other peers until we have all
 * possible replies.  If we have transmitted the *only* reply to
 * the initiator we should destroy the pending request.  If we have
 * many replies in the queue to the initiator, we should delay sending
 * out more queries until the reply queue has shrunk some.
 *
 * @param cls our "struct ProcessGetContext *"
 * @param tc unused
 */
static void
forward_request_task (void *cls,
		      const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Function called after we either failed or succeeded
 * at transmitting a query to a peer.  
 *
 * @param cls the requests "struct PendingRequest*"
 * @param tpid ID of receiving peer, 0 on transmission error
 */
static void
transmit_query_continuation (void *cls,
			     GNUNET_PEER_Id tpid)
{
  struct PendingRequest *pr = cls;
  unsigned int i;

  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# queries scheduled for forwarding"),
			    -1,
			    GNUNET_NO);
  if (tpid == 0)   
    {
#if DEBUG_FS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Transmission of request failed, will try again later.\n");
#endif
      if (pr->task == GNUNET_SCHEDULER_NO_TASK)
	pr->task = GNUNET_SCHEDULER_add_delayed (sched,
						 get_processing_delay (),
						 &forward_request_task,
						 pr); 
      return;    
    }
#if DEBUG_FS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Transmitted query `%s'\n",
	      GNUNET_h2s (&pr->query));
#endif
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# queries forwarded"),
			    1,
			    GNUNET_NO);
  for (i=0;i<pr->used_targets_off;i++)
    if (pr->used_targets[i].pid == tpid)
      break; /* found match! */    
  if (i == pr->used_targets_off)
    {
      /* need to create new entry */
      if (pr->used_targets_off == pr->used_targets_size)
	GNUNET_array_grow (pr->used_targets,
			   pr->used_targets_size,
			   pr->used_targets_size * 2 + 2);
      GNUNET_PEER_change_rc (tpid, 1);
      pr->used_targets[pr->used_targets_off].pid = tpid;
      pr->used_targets[pr->used_targets_off].num_requests = 0;
      i = pr->used_targets_off++;
    }
  pr->used_targets[i].last_request_time = GNUNET_TIME_absolute_get ();
  pr->used_targets[i].num_requests++;
  if (pr->task == GNUNET_SCHEDULER_NO_TASK)
    pr->task = GNUNET_SCHEDULER_add_delayed (sched,
					     get_processing_delay (),
					     &forward_request_task,
					     pr);
}


/**
 * How many bytes should a bloomfilter be if we have already seen
 * entry_count responses?  Note that BLOOMFILTER_K gives us the number
 * of bits set per entry.  Furthermore, we should not re-size the
 * filter too often (to keep it cheap).
 *
 * Since other peers will also add entries but not resize the filter,
 * we should generally pick a slightly larger size than what the
 * strict math would suggest.
 *
 * @return must be a power of two and smaller or equal to 2^15.
 */
static size_t
compute_bloomfilter_size (unsigned int entry_count)
{
  size_t size;
  unsigned int ideal = (entry_count * BLOOMFILTER_K) / 4;
  uint16_t max = 1 << 15;

  if (entry_count > max)
    return max;
  size = 8;
  while ((size < max) && (size < ideal))
    size *= 2;
  if (size > max)
    return max;
  return size;
}


/**
 * Recalculate our bloom filter for filtering replies.  This function
 * will create a new bloom filter from scratch, so it should only be
 * called if we have no bloomfilter at all (and hence can create a
 * fresh one of minimal size without problems) OR if our peer is the
 * initiator (in which case we may resize to larger than mimimum size).
 *
 * @param pr request for which the BF is to be recomputed
 */
static void
refresh_bloomfilter (struct PendingRequest *pr)
{
  unsigned int i;
  size_t nsize;
  GNUNET_HashCode mhash;

  nsize = compute_bloomfilter_size (pr->replies_seen_off);
  if (nsize == pr->bf_size)
    return; /* size not changed */
  if (pr->bf != NULL)
    GNUNET_CONTAINER_bloomfilter_free (pr->bf);
  pr->bf_size = nsize;
  pr->mingle = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, -1);
  pr->bf = GNUNET_CONTAINER_bloomfilter_init (NULL, 
					      pr->bf_size,
					      BLOOMFILTER_K);
  for (i=0;i<pr->replies_seen_off;i++)
    {
      GNUNET_BLOCK_mingle_hash (&pr->replies_seen[i],
				pr->mingle,
				&mhash);
      GNUNET_CONTAINER_bloomfilter_add (pr->bf, &mhash);
    }
}


/**
 * Function called after we've tried to reserve a certain amount of
 * bandwidth for a reply.  Check if we succeeded and if so send our
 * query.
 *
 * @param cls the requests "struct PendingRequest*"
 * @param peer identifies the peer
 * @param bpm_in set to the current bandwidth limit (receiving) for this peer
 * @param bpm_out set to the current bandwidth limit (sending) for this peer
 * @param amount set to the amount that was actually reserved or unreserved
 * @param preference current traffic preference for the given peer
 */
static void
target_reservation_cb (void *cls,
		       const struct
		       GNUNET_PeerIdentity * peer,
		       struct GNUNET_BANDWIDTH_Value32NBO bpm_in,
		       struct GNUNET_BANDWIDTH_Value32NBO bpm_out,
		       int amount,
		       uint64_t preference)
{
  struct PendingRequest *pr = cls;
  struct ConnectedPeer *cp;
  struct PendingMessage *pm;
  struct GetMessage *gm;
  GNUNET_HashCode *ext;
  char *bfdata;
  size_t msize;
  unsigned int k;
  int no_route;
  uint32_t bm;
  unsigned int i;

  pr->irc = NULL;
  if (peer == NULL)
    {
      /* error in communication with core, try again later */
      if (pr->task == GNUNET_SCHEDULER_NO_TASK)
	pr->task = GNUNET_SCHEDULER_add_delayed (sched,
						 get_processing_delay (),
						 &forward_request_task,
						 pr);
      return;
    }
  /* (3) transmit, update ttl/priority */
  cp = GNUNET_CONTAINER_multihashmap_get (connected_peers,
					  &peer->hashPubKey);
  if (cp == NULL)
    {
      /* Peer must have just left */
#if DEBUG_FS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Selected peer disconnected!\n");
#endif
      if (pr->task == GNUNET_SCHEDULER_NO_TASK)
	pr->task = GNUNET_SCHEDULER_add_delayed (sched,
						 get_processing_delay (),
						 &forward_request_task,
						 pr);
      return;
    }
  no_route = GNUNET_NO;
  if (amount == 0)
    {
      if (pr->cp == NULL)
	{
#if DEBUG_FS > 1
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Failed to reserve bandwidth for reply (got %d/%u bytes only)!\n",
		      amount,
		      DBLOCK_SIZE);
#endif
	  GNUNET_STATISTICS_update (stats,
				    gettext_noop ("# reply bandwidth reservation requests failed"),
				    1,
				    GNUNET_NO);
	  if (pr->task == GNUNET_SCHEDULER_NO_TASK)
	    pr->task = GNUNET_SCHEDULER_add_delayed (sched,
						     get_processing_delay (),
						     &forward_request_task,
						     pr);
	  return;  /* this target round failed */
	}
      no_route = GNUNET_YES;
    }
  
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# queries scheduled for forwarding"),
			    1,
			    GNUNET_NO);
  for (i=0;i<pr->used_targets_off;i++)
    if (pr->used_targets[i].pid == cp->pid) 
      {
	GNUNET_STATISTICS_update (stats,
				  gettext_noop ("# queries retransmitted to same target"),
				  1,
				  GNUNET_NO);
	break;
      } 

  /* build message and insert message into priority queue */
#if DEBUG_FS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Forwarding request `%s' to `%4s'!\n",
	      GNUNET_h2s (&pr->query),
	      GNUNET_i2s (peer));
#endif
  k = 0;
  bm = 0;
  if (GNUNET_YES == no_route)
    {
      bm |= GET_MESSAGE_BIT_RETURN_TO;
      k++;      
    }
  if (pr->namespace != NULL)
    {
      bm |= GET_MESSAGE_BIT_SKS_NAMESPACE;
      k++;
    }
  if (pr->target_pid != 0)
    {
      bm |= GET_MESSAGE_BIT_TRANSMIT_TO;
      k++;
    }
  msize = sizeof (struct GetMessage) + pr->bf_size + k * sizeof(GNUNET_HashCode);
  GNUNET_assert (msize < GNUNET_SERVER_MAX_MESSAGE_SIZE);
  pm = GNUNET_malloc (sizeof (struct PendingMessage) + msize);
  pm->msize = msize;
  gm = (struct GetMessage*) &pm[1];
  gm->header.type = htons (GNUNET_MESSAGE_TYPE_FS_GET);
  gm->header.size = htons (msize);
  gm->type = htonl (pr->type);
  pr->remaining_priority /= 2;
  gm->priority = htonl (pr->remaining_priority);
  gm->ttl = htonl (pr->ttl);
  gm->filter_mutator = htonl(pr->mingle); 
  gm->hash_bitmap = htonl (bm);
  gm->query = pr->query;
  ext = (GNUNET_HashCode*) &gm[1];
  k = 0;
  if (GNUNET_YES == no_route)
    GNUNET_PEER_resolve (pr->cp->pid, (struct GNUNET_PeerIdentity*) &ext[k++]);
  if (pr->namespace != NULL)
    memcpy (&ext[k++], pr->namespace, sizeof (GNUNET_HashCode));
  if (pr->target_pid != 0)
    GNUNET_PEER_resolve (pr->target_pid, (struct GNUNET_PeerIdentity*) &ext[k++]);
  bfdata = (char *) &ext[k];
  if (pr->bf != NULL)
    GNUNET_CONTAINER_bloomfilter_get_raw_data (pr->bf,
					       bfdata,
					       pr->bf_size);
  pm->cont = &transmit_query_continuation;
  pm->cont_cls = pr;
  cp->last_request_times[(cp->last_request_times_off++) % MAX_QUEUE_PER_PEER] = GNUNET_TIME_absolute_get ();
  add_to_pending_messages_for_peer (cp, pm, pr);
}


/**
 * Closure used for "target_peer_select_cb".
 */
struct PeerSelectionContext 
{
  /**
   * The request for which we are selecting
   * peers.
   */
  struct PendingRequest *pr;

  /**
   * Current "prime" target.
   */
  struct GNUNET_PeerIdentity target;

  /**
   * How much do we like this target?
   */
  double target_score;

};


/**
 * Function called for each connected peer to determine
 * which one(s) would make good targets for forwarding.
 *
 * @param cls closure (struct PeerSelectionContext)
 * @param key current key code (peer identity)
 * @param value value in the hash map (struct ConnectedPeer)
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
static int
target_peer_select_cb (void *cls,
		       const GNUNET_HashCode * key,
		       void *value)
{
  struct PeerSelectionContext *psc = cls;
  struct ConnectedPeer *cp = value;
  struct PendingRequest *pr = psc->pr;
  struct GNUNET_TIME_Relative delay;
  double score;
  unsigned int i;
  unsigned int pc;

  /* 1) check that this peer is not the initiator */
  if (cp == pr->cp)
    {
#if DEBUG_FS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Skipping initiator in forwarding selection\n");
#endif
      return GNUNET_YES; /* skip */	   
    }

  /* 2) check if we have already (recently) forwarded to this peer */
  /* 2a) this particular request */
  pc = 0;
  for (i=0;i<pr->used_targets_off;i++)
    if (pr->used_targets[i].pid == cp->pid) 
      {
	pc = pr->used_targets[i].num_requests;
	GNUNET_assert (pc > 0);
	if (0 != GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
					   RETRY_PROBABILITY_INV * pc))
	  {
#if DEBUG_FS
	    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			"NOT re-trying query that was previously transmitted %u times\n",
			(unsigned int) pc);
#endif
	    return GNUNET_YES; /* skip */
	  }
	break;
      }
#if DEBUG_FS
  if (0 < pc)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  "Re-trying query that was previously transmitted %u times to this peer\n",
		  (unsigned int) pc);
    }
#endif
  /* 2b) many other requests to this peer */
  delay = GNUNET_TIME_absolute_get_duration (cp->last_request_times[cp->last_request_times_off % MAX_QUEUE_PER_PEER]);
  if (delay.value <= cp->avg_delay.value)
    {
#if DEBUG_FS
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  "NOT sending query since we send %u others to this peer in the last %llums\n",
		  MAX_QUEUE_PER_PEER,
		  cp->avg_delay.value);
#endif
      return GNUNET_YES; /* skip */      
    }

  /* 3) calculate how much we'd like to forward to this peer,
     starting with a random value that is strong enough
     to at least give any peer a chance sometimes 
     (compared to the other factors that come later) */
  /* 3a) count successful (recent) routes from cp for same source */
  if (pr->cp != NULL)
    {
      score = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
					P2P_SUCCESS_LIST_SIZE);
      for (i=0;i<P2P_SUCCESS_LIST_SIZE;i++)
	if (cp->last_p2p_replies[i] == pr->cp->pid)
	  score += 1.0; /* likely successful based on hot path */
    }
  else
    {
      score = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
					CS2P_SUCCESS_LIST_SIZE);
      for (i=0;i<CS2P_SUCCESS_LIST_SIZE;i++)
	if (cp->last_client_replies[i] == pr->client_request_list->client_list->client)
	  score += 1.0; /* likely successful based on hot path */
    }
  /* 3b) include latency */
  if (cp->avg_delay.value < 4 * TTL_DECREMENT)
    score += 1.0; /* likely fast based on latency */
  /* 3c) include priorities */
  if (cp->avg_priority <= pr->remaining_priority / 2.0)
    score += 1.0; /* likely successful based on priorities */
  /* 3d) penalize for queue size */  
  score -= (2.0 * cp->pending_requests / (double) MAX_QUEUE_PER_PEER); 
  /* 3e) include peer proximity */
  score -= (2.0 * (GNUNET_CRYPTO_hash_distance_u32 (key,
						    &pr->query)) / (double) UINT32_MAX);
  /* 4) super-bonus for being the known target */
  if (pr->target_pid == cp->pid)
    score += 100.0;
  /* store best-fit in closure */
#if DEBUG_FS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Peer `%s' gets score %f for forwarding query, max is %f\n",
	      GNUNET_h2s (key),
	      score,
	      psc->target_score);
#endif  
  score++; /* avoid zero */
  if (score > psc->target_score)
    {
      psc->target_score = score;
      psc->target.hashPubKey = *key; 
    }
  return GNUNET_YES;
}
  

/**
 * The priority level imposes a bound on the maximum
 * value for the ttl that can be requested.
 *
 * @param ttl_in requested ttl
 * @param prio given priority
 * @return ttl_in if ttl_in is below the limit,
 *         otherwise the ttl-limit for the given priority
 */
static int32_t
bound_ttl (int32_t ttl_in, uint32_t prio)
{
  unsigned long long allowed;

  if (ttl_in <= 0)
    return ttl_in;
  allowed = ((unsigned long long) prio) * TTL_DECREMENT / 1000; 
  if (ttl_in > allowed)      
    {
      if (allowed >= (1 << 30))
        return 1 << 30;
      return allowed;
    }
  return ttl_in;
}


/**
 * Iterator called on each result obtained for a DHT
 * operation that expects a reply
 *
 * @param cls closure
 * @param exp when will this value expire
 * @param key key of the result
 * @param get_path NULL-terminated array of pointers
 *                 to the peers on reverse GET path (or NULL if not recorded)
 * @param put_path NULL-terminated array of pointers
 *                 to the peers on the PUT path (or NULL if not recorded)
 * @param type type of the result
 * @param size number of bytes in data
 * @param data pointer to the result data
 */
static void
process_dht_reply (void *cls,
		   struct GNUNET_TIME_Absolute exp,
		   const GNUNET_HashCode * key,
		   const struct GNUNET_PeerIdentity * const *get_path,
		   const struct GNUNET_PeerIdentity * const *put_path,
		   enum GNUNET_BLOCK_Type type,
		   size_t size,
		   const void *data);


/**
 * We're processing a GET request and have decided
 * to forward it to other peers.  This function is called periodically
 * and should forward the request to other peers until we have all
 * possible replies.  If we have transmitted the *only* reply to
 * the initiator we should destroy the pending request.  If we have
 * many replies in the queue to the initiator, we should delay sending
 * out more queries until the reply queue has shrunk some.
 *
 * @param cls our "struct ProcessGetContext *"
 * @param tc unused
 */
static void
forward_request_task (void *cls,
		     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PendingRequest *pr = cls;
  struct PeerSelectionContext psc;
  struct ConnectedPeer *cp; 
  struct GNUNET_TIME_Relative delay;

  pr->task = GNUNET_SCHEDULER_NO_TASK;
  if (pr->irc != NULL)
    {
#if DEBUG_FS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Forwarding of query `%s' not attempted due to pending local lookup!\n",
		  GNUNET_h2s (&pr->query));
#endif
      return; /* already pending */
    }
  if (GNUNET_YES == pr->local_only)
    return; /* configured to not do P2P search */
  /* (0) try DHT */
  if ( (0 == pr->anonymity_level) &&
       (GNUNET_YES != pr->forward_only) &&
       (pr->type != GNUNET_BLOCK_TYPE_FS_DBLOCK) &&
       (pr->type != GNUNET_BLOCK_TYPE_FS_IBLOCK) )
    {
      pr->dht_get = GNUNET_DHT_get_start (dht_handle,
					  GNUNET_TIME_UNIT_FOREVER_REL,
					  pr->type,
					  &pr->query,
					  GNUNET_DHT_RO_NONE,
					  pr->bf,
					  pr->mingle,
					  pr->namespace,
					  (pr->namespace != NULL) ? sizeof (GNUNET_HashCode) : 0,
					  &process_dht_reply,
					  pr);
    }
  /* (1) select target */
  psc.pr = pr;
  psc.target_score = -DBL_MAX;
  GNUNET_CONTAINER_multihashmap_iterate (connected_peers,
					 &target_peer_select_cb,
					 &psc);  
  if (psc.target_score == -DBL_MAX)
    {
      delay = get_processing_delay ();
#if DEBUG_FS 
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "No peer selected for forwarding of query `%s', will try again in %llu ms!\n",
		  GNUNET_h2s (&pr->query),
		  delay.value);
#endif
      pr->task = GNUNET_SCHEDULER_add_delayed (sched,
					       delay,
					       &forward_request_task,
					       pr);
      return; /* nobody selected */
    }
  /* (3) update TTL/priority */
  if (pr->client_request_list != NULL)
    {
      /* FIXME: use better algorithm!? */
      if (0 == GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
					 4))
	pr->priority++;
      /* bound priority we use by priorities we see from other peers
	 rounded up (must round up so that we can see non-zero
	 priorities, but round up as little as possible to make it
	 plausible that we forwarded another peers request) */
      if (pr->priority > current_priorities + 1.0)
	pr->priority = (uint32_t) current_priorities + 1.0;
      pr->ttl = bound_ttl (pr->ttl + TTL_DECREMENT * 2,
			   pr->priority);
#if DEBUG_FS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Trying query `%s' with priority %u and TTL %d.\n",
		  GNUNET_h2s (&pr->query),
		  pr->priority,
		  pr->ttl);
#endif
    }

  /* (3) reserve reply bandwidth */
  if (GNUNET_NO == pr->forward_only)
    {
      cp = GNUNET_CONTAINER_multihashmap_get (connected_peers,
					      &psc.target.hashPubKey);
      GNUNET_assert (NULL != cp);
      pr->irc = GNUNET_CORE_peer_change_preference (sched, cfg,
						    &psc.target,
						    GNUNET_CONSTANTS_SERVICE_TIMEOUT, 
						    GNUNET_BANDWIDTH_value_init (UINT32_MAX),
						    DBLOCK_SIZE * 2, 
						    cp->inc_preference,
						    &target_reservation_cb,
						    pr);
      cp->inc_preference = 0;
    }
  else
    {
      /* force forwarding */
      static struct GNUNET_BANDWIDTH_Value32NBO zerobw;
      target_reservation_cb (pr, &psc.target,
			     zerobw, zerobw, 0, 0.0);
    }
}


/* **************************** P2P PUT Handling ************************ */


/**
 * Function called after we either failed or succeeded
 * at transmitting a reply to a peer.  
 *
 * @param cls the requests "struct PendingRequest*"
 * @param tpid ID of receiving peer, 0 on transmission error
 */
static void
transmit_reply_continuation (void *cls,
			     GNUNET_PEER_Id tpid)
{
  struct PendingRequest *pr = cls;
  
  switch (pr->type)
    {
    case GNUNET_BLOCK_TYPE_FS_DBLOCK:
    case GNUNET_BLOCK_TYPE_FS_IBLOCK:
      /* only one reply expected, done with the request! */
      destroy_pending_request (pr);
      break;
    case GNUNET_BLOCK_TYPE_ANY:
    case GNUNET_BLOCK_TYPE_FS_KBLOCK:
    case GNUNET_BLOCK_TYPE_FS_SBLOCK:
      break;
    default:
      GNUNET_break (0);
      break;
    }
}


/**
 * Transmit the given message by copying it to the target buffer
 * "buf".  "buf" will be NULL and "size" zero if the socket was closed
 * for writing in the meantime.  In that case, do nothing
 * (the disconnect or shutdown handler will take care of the rest).
 * If we were able to transmit messages and there are still more
 * pending, ask core again for further calls to this function.
 *
 * @param cls closure, pointer to the 'struct ClientList*'
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_to_client (void *cls,
		  size_t size, void *buf)
{
  struct ClientList *cl = cls;
  char *cbuf = buf;
  struct ClientResponseMessage *creply;
  size_t msize;
  
  cl->th = NULL;
  if (NULL == buf)
    {
#if DEBUG_FS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Not sending reply, client communication problem.\n");
#endif
      return 0;
    }
  msize = 0;
  while ( (NULL != (creply = cl->res_head) ) &&
	  (creply->msize <= size) )
    {
      memcpy (&cbuf[msize], &creply[1], creply->msize);
      msize += creply->msize;
      size -= creply->msize;
      GNUNET_CONTAINER_DLL_remove (cl->res_head,
				   cl->res_tail,
				   creply);
      GNUNET_free (creply);
    }
  if (NULL != creply)
    cl->th = GNUNET_SERVER_notify_transmit_ready (cl->client,
						  creply->msize,
						  GNUNET_TIME_UNIT_FOREVER_REL,
						  &transmit_to_client,
						  cl);
#if DEBUG_FS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Transmitted %u bytes to client\n",
	      (unsigned int) msize);
#endif
  return msize;
}


/**
 * Closure for "process_reply" function.
 */
struct ProcessReplyClosure
{
  /**
   * The data for the reply.
   */
  const void *data;

  /**
   * Who gave us this reply? NULL for local host (or DHT)
   */
  struct ConnectedPeer *sender;

  /**
   * When the reply expires.
   */
  struct GNUNET_TIME_Absolute expiration;

  /**
   * Size of data.
   */
  size_t size;

  /**
   * Type of the block.
   */
  enum GNUNET_BLOCK_Type type;

  /**
   * How much was this reply worth to us?
   */
  uint32_t priority;

  /**
   * Evaluation result (returned).
   */
  enum GNUNET_BLOCK_EvaluationResult eval;

  /**
   * Did we finish processing the associated request?
   */ 
  int finished;

  /**
   * Did we find a matching request?
   */
  int request_found;
};


/**
 * We have received a reply; handle it!
 *
 * @param cls response (struct ProcessReplyClosure)
 * @param key our query
 * @param value value in the hash map (info about the query)
 * @return GNUNET_YES (we should continue to iterate)
 */
static int
process_reply (void *cls,
	       const GNUNET_HashCode * key,
	       void *value)
{
  struct ProcessReplyClosure *prq = cls;
  struct PendingRequest *pr = value;
  struct PendingMessage *reply;
  struct ClientResponseMessage *creply;
  struct ClientList *cl;
  struct PutMessage *pm;
  struct ConnectedPeer *cp;
  struct GNUNET_TIME_Relative cur_delay;
#if SUPPORT_DELAYS  
struct GNUNET_TIME_Relative art_delay;
#endif
  size_t msize;
  unsigned int i;

#if DEBUG_FS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Matched result (type %u) for query `%s' with pending request\n",
	      (unsigned int) prq->type,
	      GNUNET_h2s (key));
#endif  
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# replies received and matched"),
			    1,
			    GNUNET_NO);
  if (prq->sender != NULL)
    {
      for (i=0;i<pr->used_targets_off;i++)
	if (pr->used_targets[i].pid == prq->sender->pid)
	  break;
      if (i < pr->used_targets_off)
	{
	  cur_delay = GNUNET_TIME_absolute_get_duration (pr->used_targets[i].last_request_time);      
	  prq->sender->avg_delay.value
	    = (prq->sender->avg_delay.value * 
	       (RUNAVG_DELAY_N - 1) + cur_delay.value) / RUNAVG_DELAY_N; 
	  prq->sender->avg_priority
	    = (prq->sender->avg_priority * 
	       (RUNAVG_DELAY_N - 1) + pr->priority) / (double) RUNAVG_DELAY_N;
	}
      if (pr->cp != NULL)
	{
	  GNUNET_PEER_change_rc (prq->sender->last_p2p_replies
				 [prq->sender->last_p2p_replies_woff % P2P_SUCCESS_LIST_SIZE], 
				 -1);
	  GNUNET_PEER_change_rc (pr->cp->pid, 1);
	  prq->sender->last_p2p_replies
	    [(prq->sender->last_p2p_replies_woff++) % P2P_SUCCESS_LIST_SIZE]
	    = pr->cp->pid;
	}
      else
	{
	  if (NULL != prq->sender->last_client_replies
	      [(prq->sender->last_client_replies_woff) % CS2P_SUCCESS_LIST_SIZE])
	    GNUNET_SERVER_client_drop (prq->sender->last_client_replies
				       [(prq->sender->last_client_replies_woff) % CS2P_SUCCESS_LIST_SIZE]);
	  prq->sender->last_client_replies
	    [(prq->sender->last_client_replies_woff++) % CS2P_SUCCESS_LIST_SIZE]
	    = pr->client_request_list->client_list->client;
	  GNUNET_SERVER_client_keep (pr->client_request_list->client_list->client);
	}
    }
  prq->eval = GNUNET_BLOCK_evaluate (block_ctx,
				     prq->type,
				     key,
				     &pr->bf,
				     pr->mingle,
				     pr->namespace, (pr->namespace != NULL) ? sizeof (GNUNET_HashCode) : 0,
				     prq->data,
				     prq->size);
  switch (prq->eval)
    {
    case GNUNET_BLOCK_EVALUATION_OK_MORE:
      break;
    case GNUNET_BLOCK_EVALUATION_OK_LAST:
      while (NULL != pr->pending_head)
	destroy_pending_message_list_entry (pr->pending_head);
      if (pr->qe != NULL)
	{
	  if (pr->client_request_list != NULL)
	    GNUNET_SERVER_receive_done (pr->client_request_list->client_list->client, 
					GNUNET_YES);
	  GNUNET_DATASTORE_cancel (pr->qe);
	  pr->qe = NULL;
	}
      pr->do_remove = GNUNET_YES;
      if (pr->task != GNUNET_SCHEDULER_NO_TASK)
	{
	  GNUNET_SCHEDULER_cancel (sched,
				   pr->task);
	  pr->task = GNUNET_SCHEDULER_NO_TASK;
	}
      GNUNET_break (GNUNET_YES ==
		    GNUNET_CONTAINER_multihashmap_remove (query_request_map,
							  key,
							  pr));
      GNUNET_LOAD_update (rt_entry_lifetime,
			  GNUNET_TIME_absolute_get_duration (pr->start_time).value);
      break;
    case GNUNET_BLOCK_EVALUATION_OK_DUPLICATE:
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# duplicate replies discarded (bloomfilter)"),
				1,
				GNUNET_NO);
#if DEBUG_FS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Duplicate response `%s', discarding.\n",
		  GNUNET_h2s (&mhash));
#endif
      return GNUNET_YES; /* duplicate */
    case GNUNET_BLOCK_EVALUATION_RESULT_INVALID:
      return GNUNET_YES; /* wrong namespace */	
    case GNUNET_BLOCK_EVALUATION_REQUEST_VALID:
      GNUNET_break (0);
      return GNUNET_YES;
    case GNUNET_BLOCK_EVALUATION_REQUEST_INVALID:
      GNUNET_break (0);
      return GNUNET_YES;
    case GNUNET_BLOCK_EVALUATION_TYPE_NOT_SUPPORTED:
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Unsupported block type %u\n"),
		  prq->type);
      return GNUNET_NO;
    }
  if (pr->client_request_list != NULL)
    {
      if (pr->replies_seen_size == pr->replies_seen_off)
	GNUNET_array_grow (pr->replies_seen,
			   pr->replies_seen_size,
			   pr->replies_seen_size * 2 + 4);	
      GNUNET_CRYPTO_hash (prq->data,
			  prq->size,
			  &pr->replies_seen[pr->replies_seen_off++]);	      
      refresh_bloomfilter (pr);
    }
  if (NULL == prq->sender)
    {
#if DEBUG_FS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Found result for query `%s' in local datastore\n",
		  GNUNET_h2s (key));
#endif
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# results found locally"),
				1,
				GNUNET_NO);      
    }
  prq->priority += pr->remaining_priority;
  pr->remaining_priority = 0;
  pr->results_found++;
  prq->request_found = GNUNET_YES;
  if (NULL != pr->client_request_list)
    {
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# replies received for local clients"),
				1,
				GNUNET_NO);
      cl = pr->client_request_list->client_list;
      msize = sizeof (struct PutMessage) + prq->size;
      creply = GNUNET_malloc (msize + sizeof (struct ClientResponseMessage));
      creply->msize = msize;
      creply->client_list = cl;
      GNUNET_CONTAINER_DLL_insert_after (cl->res_head,
					 cl->res_tail,
					 cl->res_tail,
					 creply);      
      pm = (struct PutMessage*) &creply[1];
      pm->header.type = htons (GNUNET_MESSAGE_TYPE_FS_PUT);
      pm->header.size = htons (msize);
      pm->type = htonl (prq->type);
      pm->expiration = GNUNET_TIME_absolute_hton (prq->expiration);
      memcpy (&pm[1], prq->data, prq->size);      
      if (NULL == cl->th)
	{
#if DEBUG_FS
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Transmitting result for query `%s' to client\n",
		      GNUNET_h2s (key));
#endif  
	  cl->th = GNUNET_SERVER_notify_transmit_ready (cl->client,
							msize,
							GNUNET_TIME_UNIT_FOREVER_REL,
							&transmit_to_client,
							cl);
	}
      GNUNET_break (cl->th != NULL);
      if (pr->do_remove)		
	{
	  prq->finished = GNUNET_YES;
	  destroy_pending_request (pr);	 	
	}
    }
  else
    {
      cp = pr->cp;
#if DEBUG_FS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Transmitting result for query `%s' to other peer (PID=%u)\n",
		  GNUNET_h2s (key),
		  (unsigned int) cp->pid);
#endif  
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# replies received for other peers"),
				1,
				GNUNET_NO);
      msize = sizeof (struct PutMessage) + prq->size;
      reply = GNUNET_malloc (msize + sizeof (struct PendingMessage));
      reply->cont = &transmit_reply_continuation;
      reply->cont_cls = pr;
#if SUPPORT_DELAYS
      art_delay = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS,
						 GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
									   TTL_DECREMENT));
      reply->delay_until 
	= GNUNET_TIME_relative_to_absolute (art_delay);
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("cummulative artificial delay introduced (ms)"),
				art_delay.value,
				GNUNET_NO);
#endif
      reply->msize = msize;
      reply->priority = UINT32_MAX; /* send replies first! */
      pm = (struct PutMessage*) &reply[1];
      pm->header.type = htons (GNUNET_MESSAGE_TYPE_FS_PUT);
      pm->header.size = htons (msize);
      pm->type = htonl (prq->type);
      pm->expiration = GNUNET_TIME_absolute_hton (prq->expiration);
      memcpy (&pm[1], prq->data, prq->size);
      add_to_pending_messages_for_peer (cp, reply, pr);
    }
  return GNUNET_YES;
}


/**
 * Iterator called on each result obtained for a DHT
 * operation that expects a reply
 *
 * @param cls closure
 * @param exp when will this value expire
 * @param key key of the result
 * @param get_path NULL-terminated array of pointers
 *                 to the peers on reverse GET path (or NULL if not recorded)
 * @param put_path NULL-terminated array of pointers
 *                 to the peers on the PUT path (or NULL if not recorded)
 * @param type type of the result
 * @param size number of bytes in data
 * @param data pointer to the result data
 */
static void
process_dht_reply (void *cls,
		   struct GNUNET_TIME_Absolute exp,
		   const GNUNET_HashCode * key,
		   const struct GNUNET_PeerIdentity * const *get_path,
		   const struct GNUNET_PeerIdentity * const *put_path,
		   enum GNUNET_BLOCK_Type type,
		   size_t size,
		   const void *data)
{
  struct PendingRequest *pr = cls;
  struct ProcessReplyClosure prq;

  memset (&prq, 0, sizeof (prq));
  prq.data = data;
  prq.expiration = exp;
  prq.size = size;  
  prq.type = type;
  process_reply (&prq, key, pr);
}



/**
 * Continuation called to notify client about result of the
 * operation.
 *
 * @param cls closure
 * @param success GNUNET_SYSERR on failure
 * @param msg NULL on success, otherwise an error message
 */
static void 
put_migration_continuation (void *cls,
			    int success,
			    const char *msg)
{
  struct GNUNET_TIME_Absolute *start = cls;
  struct GNUNET_TIME_Relative delay;
  
  delay = GNUNET_TIME_absolute_get_duration (*start);
  GNUNET_free (start);
  GNUNET_LOAD_update (datastore_put_load,
		      delay.value);
  if (GNUNET_OK == success)
    return;
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# datastore 'put' failures"),
			    1,
			    GNUNET_NO);
}


/**
 * Handle P2P "PUT" message.
 *
 * @param cls closure, always NULL
 * @param other the other peer involved (sender or receiver, NULL
 *        for loopback messages where we are both sender and receiver)
 * @param message the actual message
 * @param latency reported latency of the connection with 'other'
 * @param distance reported distance (DV) to 'other' 
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_p2p_put (void *cls,
		const struct GNUNET_PeerIdentity *other,
		const struct GNUNET_MessageHeader *message,
		struct GNUNET_TIME_Relative latency,
		uint32_t distance)
{
  const struct PutMessage *put;
  uint16_t msize;
  size_t dsize;
  enum GNUNET_BLOCK_Type type;
  struct GNUNET_TIME_Absolute expiration;
  GNUNET_HashCode query;
  struct ProcessReplyClosure prq;
  struct GNUNET_TIME_Absolute *start;
  struct GNUNET_TIME_Relative block_time;  
  double putl;
  struct ConnectedPeer *cp; 
  struct PendingMessage *pm;
  struct MigrationStopMessage *msm;

  msize = ntohs (message->size);
  if (msize < sizeof (struct PutMessage))
    {
      GNUNET_break_op(0);
      return GNUNET_SYSERR;
    }
  put = (const struct PutMessage*) message;
  dsize = msize - sizeof (struct PutMessage);
  type = ntohl (put->type);
  expiration = GNUNET_TIME_absolute_ntoh (put->expiration);

  if (type == GNUNET_BLOCK_TYPE_FS_ONDEMAND)
    return GNUNET_SYSERR;
  if (GNUNET_OK !=
      GNUNET_BLOCK_get_key (block_ctx,
			    type,
			    &put[1],
			    dsize,
			    &query))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
#if DEBUG_FS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received result for query `%s' from peer `%4s'\n",
	      GNUNET_h2s (&query),
	      GNUNET_i2s (other));
#endif
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# replies received (overall)"),
			    1,
			    GNUNET_NO);
  /* now, lookup 'query' */
  prq.data = (const void*) &put[1];
  if (other != NULL)
    prq.sender = GNUNET_CONTAINER_multihashmap_get (connected_peers,
						    &other->hashPubKey);
  else
    prq.sender = NULL;
  prq.size = dsize;
  prq.type = type;
  prq.expiration = expiration;
  prq.priority = 0;
  prq.finished = GNUNET_NO;
  prq.request_found = GNUNET_NO;
  GNUNET_CONTAINER_multihashmap_get_multiple (query_request_map,
					      &query,
					      &process_reply,
					      &prq);
  if (prq.sender != NULL)
    {
      prq.sender->inc_preference += CONTENT_BANDWIDTH_VALUE + 1000 * prq.priority;
      prq.sender->trust += prq.priority;
    }
  if ( (GNUNET_YES == active_migration) &&
       (GNUNET_NO == test_put_load_too_high (prq.priority)) )
    {      
#if DEBUG_FS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Replicating result for query `%s' with priority %u\n",
		  GNUNET_h2s (&query),
		  prq.priority);
#endif
      start = GNUNET_malloc (sizeof (struct GNUNET_TIME_Absolute));
      *start = GNUNET_TIME_absolute_get ();
      GNUNET_DATASTORE_put (dsh,
			    0, &query, dsize, &put[1],
			    type, prq.priority, 1 /* anonymity */, 
			    expiration, 
			    1 + prq.priority, MAX_DATASTORE_QUEUE,
			    GNUNET_CONSTANTS_SERVICE_TIMEOUT,
			    &put_migration_continuation, 
			    start);
    }
  putl = GNUNET_LOAD_get_load (datastore_put_load);
  if ( (GNUNET_NO == prq.request_found) &&
       ( (GNUNET_YES != active_migration) ||
       	 (putl > 2.5 * (1 + prq.priority)) ) )
    {
      cp = GNUNET_CONTAINER_multihashmap_get (connected_peers,
					      &other->hashPubKey);
      if (GNUNET_TIME_absolute_get_duration (cp->last_migration_block).value < 5000)
	return GNUNET_OK; /* already blocked */
      /* We're too busy; send MigrationStop message! */
      if (GNUNET_YES != active_migration) 
	putl = 1.0 + GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 5);
      block_time = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS,
						  5000 + GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
										   (unsigned int) (60000 * putl * putl)));
      
      cp->last_migration_block = GNUNET_TIME_relative_to_absolute (block_time);
      pm = GNUNET_malloc (sizeof (struct PendingMessage) + 
			  sizeof (struct MigrationStopMessage));
      pm->msize = sizeof (struct MigrationStopMessage);
      pm->priority = UINT32_MAX;
      msm = (struct MigrationStopMessage*) &pm[1];
      msm->header.size = htons (sizeof (struct MigrationStopMessage));
      msm->header.type = htons (GNUNET_MESSAGE_TYPE_FS_MIGRATION_STOP);
      msm->duration = GNUNET_TIME_relative_hton (block_time);
      add_to_pending_messages_for_peer (cp,
					pm,
					NULL);
    }
  return GNUNET_OK;
}


/**
 * Handle P2P "MIGRATION_STOP" message.
 *
 * @param cls closure, always NULL
 * @param other the other peer involved (sender or receiver, NULL
 *        for loopback messages where we are both sender and receiver)
 * @param message the actual message
 * @param latency reported latency of the connection with 'other'
 * @param distance reported distance (DV) to 'other' 
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_p2p_migration_stop (void *cls,
			   const struct GNUNET_PeerIdentity *other,
			   const struct GNUNET_MessageHeader *message,
			   struct GNUNET_TIME_Relative latency,
			   uint32_t distance)
{
  struct ConnectedPeer *cp; 
  const struct MigrationStopMessage *msm;

  msm = (const struct MigrationStopMessage*) message;
  cp = GNUNET_CONTAINER_multihashmap_get (connected_peers,
					  &other->hashPubKey);
  if (cp == NULL)
    {
      GNUNET_break (0);
      return GNUNET_OK;
    }
  cp->migration_blocked = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_relative_ntoh (msm->duration));
  return GNUNET_OK;
}



/* **************************** P2P GET Handling ************************ */


/**
 * Closure for 'check_duplicate_request_{peer,client}'.
 */
struct CheckDuplicateRequestClosure
{
  /**
   * The new request we should check if it already exists.
   */
  const struct PendingRequest *pr;

  /**
   * Existing request found by the checker, NULL if none.
   */
  struct PendingRequest *have;
};


/**
 * Iterator over entries in the 'query_request_map' that
 * tries to see if we have the same request pending from
 * the same client already.
 *
 * @param cls closure (our 'struct CheckDuplicateRequestClosure')
 * @param key current key code (query, ignored, must match)
 * @param value value in the hash map (a 'struct PendingRequest' 
 *              that already exists)
 * @return GNUNET_YES if we should continue to
 *         iterate (no match yet)
 *         GNUNET_NO if not (match found).
 */
static int
check_duplicate_request_client (void *cls,
				const GNUNET_HashCode * key,
				void *value)
{
  struct CheckDuplicateRequestClosure *cdc = cls;
  struct PendingRequest *have = value;

  if (have->client_request_list == NULL)
    return GNUNET_YES;
  if ( (cdc->pr->client_request_list->client_list->client == have->client_request_list->client_list->client) &&
       (cdc->pr != have) )
    {
      cdc->have = have;
      return GNUNET_NO;
    }
  return GNUNET_YES;
}


/**
 * We're processing (local) results for a search request
 * from another peer.  Pass applicable results to the
 * peer and if we are done either clean up (operation
 * complete) or forward to other peers (more results possible).
 *
 * @param cls our closure (struct LocalGetContext)
 * @param key key for the content
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum;
 *        maybe 0 if no unique identifier is available
 */
static void
process_local_reply (void *cls,
		     const GNUNET_HashCode * key,
		     size_t size,
		     const void *data,
		     enum GNUNET_BLOCK_Type type,
		     uint32_t priority,
		     uint32_t anonymity,
		     struct GNUNET_TIME_Absolute
		     expiration, 
		     uint64_t uid)
{
  struct PendingRequest *pr = cls;
  struct ProcessReplyClosure prq;
  struct CheckDuplicateRequestClosure cdrc;
  GNUNET_HashCode query;
  unsigned int old_rf;
  
  if (NULL == key)
    {
#if DEBUG_FS > 1
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Done processing local replies, forwarding request to other peers.\n");
#endif
      pr->qe = NULL;
      if (pr->client_request_list != NULL)
	{
	  GNUNET_SERVER_receive_done (pr->client_request_list->client_list->client, 
				      GNUNET_YES);
	  /* Figure out if this is a duplicate request and possibly
	     merge 'struct PendingRequest' entries */
	  cdrc.have = NULL;
	  cdrc.pr = pr;
	  GNUNET_CONTAINER_multihashmap_get_multiple (query_request_map,
						      &pr->query,
						      &check_duplicate_request_client,
						      &cdrc);
	  if (cdrc.have != NULL)
	    {
#if DEBUG_FS
	      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			  "Received request for block `%s' twice from client, will only request once.\n",
			  GNUNET_h2s (&pr->query));
#endif
	      
	      destroy_pending_request (pr);
	      return;
	    }
	}
      if (pr->local_only == GNUNET_YES)
	{
	  destroy_pending_request (pr);
	  return;
	}
      /* no more results */
      if (pr->task == GNUNET_SCHEDULER_NO_TASK)
	pr->task = GNUNET_SCHEDULER_add_now (sched,
					     &forward_request_task,
					     pr);      
      return;
    }
#if DEBUG_FS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "New local response to `%s' of type %u.\n",
	      GNUNET_h2s (key),
	      type);
#endif
  if (type == GNUNET_BLOCK_TYPE_FS_ONDEMAND)
    {
#if DEBUG_FS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Found ONDEMAND block, performing on-demand encoding\n");
#endif
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# on-demand blocks matched requests"),
				1,
				GNUNET_NO);
      if (GNUNET_OK != 
	  GNUNET_FS_handle_on_demand_block (key, size, data, type, priority, 
					    anonymity, expiration, uid, 
					    &process_local_reply,
					    pr))
      if (pr->qe != NULL)
	{
	  GNUNET_DATASTORE_get_next (dsh, GNUNET_YES);
	}
      return;
    }
  old_rf = pr->results_found;
  memset (&prq, 0, sizeof (prq));
  prq.data = data;
  prq.expiration = expiration;
  prq.size = size;  
  if (GNUNET_OK != 
      GNUNET_BLOCK_get_key (block_ctx,
			    type,
			    data,
			    size,
			    &query))
    {
      GNUNET_break (0);
      GNUNET_DATASTORE_remove (dsh,
			       key,
			       size, data,
			       -1, -1, 
			       GNUNET_TIME_UNIT_FOREVER_REL,
			       NULL, NULL);
      GNUNET_DATASTORE_get_next (dsh, GNUNET_YES);
      return;
    }
  prq.type = type;
  prq.priority = priority;  
  prq.finished = GNUNET_NO;
  prq.request_found = GNUNET_NO;
  if ( (old_rf == 0) &&
       (pr->results_found == 0) )
    update_datastore_delays (pr->start_time);
  process_reply (&prq, key, pr);
  if (prq.finished == GNUNET_YES)
    return;
  if (pr->qe == NULL)
    return; /* done here */
  if (prq.eval == GNUNET_BLOCK_EVALUATION_OK_LAST)
    {
      pr->local_only = GNUNET_YES; /* do not forward */
      GNUNET_DATASTORE_get_next (dsh, GNUNET_NO);
      return;
    }
  if ( (pr->client_request_list == NULL) &&
       ( (GNUNET_YES == test_get_load_too_high (0)) ||
	 (pr->results_found > 5 + 2 * pr->priority) ) )
    {
#if DEBUG_FS > 2
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Load too high, done with request\n");
#endif
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# processing result set cut short due to load"),
				1,
				GNUNET_NO);
      GNUNET_DATASTORE_get_next (dsh, GNUNET_NO);
      return;
    }
  GNUNET_DATASTORE_get_next (dsh, GNUNET_YES);
}


/**
 * We've received a request with the specified priority.  Bound it
 * according to how much we trust the given peer.
 * 
 * @param prio_in requested priority
 * @param cp the peer making the request
 * @return effective priority
 */
static int32_t
bound_priority (uint32_t prio_in,
		struct ConnectedPeer *cp)
{
#define N ((double)128.0)
  uint32_t ret;
  double rret;
  int ld;

  ld = test_get_load_too_high (0);
  if (ld == GNUNET_SYSERR)
    {
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# requests done for free (low load)"),
				1,
				GNUNET_NO);
      return 0; /* excess resources */
    }
  ret = change_host_trust (cp, prio_in);
  if (ret > 0)
    {
      if (ret > current_priorities + N)
	rret = current_priorities + N;
      else
	rret = ret;
      current_priorities 
	= (current_priorities * (N-1) + rret)/N;
    }
  if ( (ld == GNUNET_YES) && (ret > 0) )
    {
      /* try with charging */
      ld = test_get_load_too_high (ret);
    }
  if (ld == GNUNET_YES)
    {
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# request dropped, priority insufficient"),
				1,
				GNUNET_NO);
      /* undo charge */
      if (ret != 0)
	change_host_trust (cp, -ret);
      return -1; /* not enough resources */
    }
  else
    {
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# requests done for a price (normal load)"),
				1,
				GNUNET_NO);
    }
#undef N
  return ret;
}


/**
 * Iterator over entries in the 'query_request_map' that
 * tries to see if we have the same request pending from
 * the same peer already.
 *
 * @param cls closure (our 'struct CheckDuplicateRequestClosure')
 * @param key current key code (query, ignored, must match)
 * @param value value in the hash map (a 'struct PendingRequest' 
 *              that already exists)
 * @return GNUNET_YES if we should continue to
 *         iterate (no match yet)
 *         GNUNET_NO if not (match found).
 */
static int
check_duplicate_request_peer (void *cls,
			      const GNUNET_HashCode * key,
			      void *value)
{
  struct CheckDuplicateRequestClosure *cdc = cls;
  struct PendingRequest *have = value;

  if (cdc->pr->target_pid == have->target_pid)
    {
      cdc->have = have;
      return GNUNET_NO;
    }
  return GNUNET_YES;
}


/**
 * Handle P2P "GET" request.
 *
 * @param cls closure, always NULL
 * @param other the other peer involved (sender or receiver, NULL
 *        for loopback messages where we are both sender and receiver)
 * @param message the actual message
 * @param latency reported latency of the connection with 'other'
 * @param distance reported distance (DV) to 'other' 
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_p2p_get (void *cls,
		const struct GNUNET_PeerIdentity *other,
		const struct GNUNET_MessageHeader *message,
		struct GNUNET_TIME_Relative latency,
		uint32_t distance)
{
  struct PendingRequest *pr;
  struct ConnectedPeer *cp;
  struct ConnectedPeer *cps;
  struct CheckDuplicateRequestClosure cdc;
  struct GNUNET_TIME_Relative timeout;
  uint16_t msize;
  const struct GetMessage *gm;
  unsigned int bits;
  const GNUNET_HashCode *opt;
  uint32_t bm;
  size_t bfsize;
  uint32_t ttl_decrement;
  int32_t priority;
  enum GNUNET_BLOCK_Type type;
  int have_ns;

  msize = ntohs(message->size);
  if (msize < sizeof (struct GetMessage))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  gm = (const struct GetMessage*) message;
#if DEBUG_FS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received request for `%s'\n",
	      GNUNET_h2s (&gm->query));
#endif
  type = ntohl (gm->type);
  bm = ntohl (gm->hash_bitmap);
  bits = 0;
  while (bm > 0)
    {
      if (1 == (bm & 1))
	bits++;
      bm >>= 1;
    }
  if (msize < sizeof (struct GetMessage) + bits * sizeof (GNUNET_HashCode))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }  
  opt = (const GNUNET_HashCode*) &gm[1];
  bfsize = msize - sizeof (struct GetMessage) + bits * sizeof (GNUNET_HashCode);
  bm = ntohl (gm->hash_bitmap);
  bits = 0;
  cps = GNUNET_CONTAINER_multihashmap_get (connected_peers,
					   &other->hashPubKey);
  if (NULL == cps)
    {
      /* peer must have just disconnected */
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# requests dropped due to initiator not being connected"),
				1,
				GNUNET_NO);
      return GNUNET_SYSERR;
    }
  if (0 != (bm & GET_MESSAGE_BIT_RETURN_TO))
    cp = GNUNET_CONTAINER_multihashmap_get (connected_peers,
					    &opt[bits++]);
  else
    cp = cps;
  if (cp == NULL)
    {
#if DEBUG_FS
      if (0 != (bm & GET_MESSAGE_BIT_RETURN_TO))
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		    "Failed to find RETURN-TO peer `%4s' in connection set. Dropping query.\n",
		    GNUNET_i2s ((const struct GNUNET_PeerIdentity*) &opt[bits-1]));
      
      else
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		    "Failed to find peer `%4s' in connection set. Dropping query.\n",
		    GNUNET_i2s (other));
#endif
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# requests dropped due to missing reverse route"),
				1,
				GNUNET_NO);
     /* FIXME: try connect? */
      return GNUNET_OK;
    }
  /* note that we can really only check load here since otherwise
     peers could find out that we are overloaded by not being
     disconnected after sending us a malformed query... */
  priority = bound_priority (ntohl (gm->priority), cps);
  if (priority < 0)
    {
#if DEBUG_FS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Dropping query from `%s', this peer is too busy.\n",
		  GNUNET_i2s (other));
#endif
      return GNUNET_OK;
    }
#if DEBUG_FS 
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received request for `%s' of type %u from peer `%4s' with flags %u\n",
	      GNUNET_h2s (&gm->query),
	      (unsigned int) type,
	      GNUNET_i2s (other),
	      (unsigned int) bm);
#endif
  have_ns = (0 != (bm & GET_MESSAGE_BIT_SKS_NAMESPACE));
  pr = GNUNET_malloc (sizeof (struct PendingRequest) + 
		      (have_ns ? sizeof(GNUNET_HashCode) : 0));
  if (have_ns)
    {
      pr->namespace = (GNUNET_HashCode*) &pr[1];
      memcpy (&pr[1], &opt[bits++], sizeof (GNUNET_HashCode));
    }
  if ( (GNUNET_LOAD_get_load (cp->transmission_delay) > 3 * (1 + priority)) ||
       (GNUNET_LOAD_get_average (cp->transmission_delay) > 
	GNUNET_CONSTANTS_MAX_CORK_DELAY.value * 2 + GNUNET_LOAD_get_average (rt_entry_lifetime)) )
    {
      /* don't have BW to send to peer, or would likely take longer than we have for it,
	 so at best indirect the query */
      priority = 0;
      pr->forward_only = GNUNET_YES;
    }
  pr->type = type;
  pr->mingle = ntohl (gm->filter_mutator);
  if (0 != (bm & GET_MESSAGE_BIT_TRANSMIT_TO))
    pr->target_pid = GNUNET_PEER_intern ((const struct GNUNET_PeerIdentity*) &opt[bits++]);
  pr->anonymity_level = 1;
  pr->priority = (uint32_t) priority;
  pr->ttl = bound_ttl (ntohl (gm->ttl), pr->priority);
  pr->query = gm->query;
  /* decrement ttl (always) */
  ttl_decrement = 2 * TTL_DECREMENT +
    GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
			      TTL_DECREMENT);
  if ( (pr->ttl < 0) &&
       (((int32_t)(pr->ttl - ttl_decrement)) > 0) )
    {
#if DEBUG_FS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Dropping query from `%s' due to TTL underflow (%d - %u).\n",
		  GNUNET_i2s (other),
		  pr->ttl,
		  ttl_decrement);
#endif
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# requests dropped due TTL underflow"),
				1,
				GNUNET_NO);
      /* integer underflow => drop (should be very rare)! */      
      GNUNET_free (pr);
      return GNUNET_OK;
    } 
  pr->ttl -= ttl_decrement;
  pr->start_time = GNUNET_TIME_absolute_get ();

  /* get bloom filter */
  if (bfsize > 0)
    {
      pr->bf = GNUNET_CONTAINER_bloomfilter_init ((const char*) &opt[bits],
						  bfsize,
						  BLOOMFILTER_K);
      pr->bf_size = bfsize;
    }
  cdc.have = NULL;
  cdc.pr = pr;
  GNUNET_CONTAINER_multihashmap_get_multiple (query_request_map,
					      &gm->query,
					      &check_duplicate_request_peer,
					      &cdc);
  if (cdc.have != NULL)
    {
      if (cdc.have->start_time.value + cdc.have->ttl >=
	  pr->start_time.value + pr->ttl)
	{
	  /* existing request has higher TTL, drop new one! */
	  cdc.have->priority += pr->priority;
	  destroy_pending_request (pr);
#if DEBUG_FS
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Have existing request with higher TTL, dropping new request.\n",
		      GNUNET_i2s (other));
#endif
	  GNUNET_STATISTICS_update (stats,
				    gettext_noop ("# requests dropped due to higher-TTL request"),
				    1,
				    GNUNET_NO);
	  return GNUNET_OK;
	}
      else
	{
	  /* existing request has lower TTL, drop old one! */
	  pr->priority += cdc.have->priority;
	  /* Possible optimization: if we have applicable pending
	     replies in 'cdc.have', we might want to move those over
	     (this is a really rare special-case, so it is not clear
	     that this would be worth it) */
	  destroy_pending_request (cdc.have);
	  /* keep processing 'pr'! */
	}
    }

  pr->cp = cp;
  GNUNET_break (GNUNET_OK ==
		GNUNET_CONTAINER_multihashmap_put (query_request_map,
						   &gm->query,
						   pr,
						   GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
  GNUNET_break (GNUNET_OK ==
		GNUNET_CONTAINER_multihashmap_put (peer_request_map,
						   &other->hashPubKey,
						   pr,
						   GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
  
  pr->hnode = GNUNET_CONTAINER_heap_insert (requests_by_expiration_heap,
					    pr,
					    pr->start_time.value + pr->ttl);

  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# P2P searches received"),
			    1,
			    GNUNET_NO);
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# P2P searches active"),
			    1,
			    GNUNET_NO);

  /* calculate change in traffic preference */
  cps->inc_preference += pr->priority * 1000 + QUERY_BANDWIDTH_VALUE;
  /* process locally */
  if (type == GNUNET_BLOCK_TYPE_FS_DBLOCK)
    type = GNUNET_BLOCK_TYPE_ANY; /* to get on-demand as well */
  timeout = GNUNET_TIME_relative_multiply (BASIC_DATASTORE_REQUEST_DELAY,
					   (pr->priority + 1)); 
  if (GNUNET_YES != pr->forward_only)
    {
#if DEBUG_FS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Handing request for `%s' to datastore\n",
		  GNUNET_h2s (&gm->query));
#endif
      pr->qe = GNUNET_DATASTORE_get (dsh,
				     &gm->query,
				     type,			       
				     pr->priority + 1,
				     MAX_DATASTORE_QUEUE,				 
				     timeout,
				     &process_local_reply,
				     pr);
      if (NULL == pr->qe)
	{
	  GNUNET_STATISTICS_update (stats,
				    gettext_noop ("# requests dropped by datastore (queue length limit)"),
				    1,
				    GNUNET_NO);
	}
    }
  else
    {
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# requests forwarded due to high load"),
				1,
				GNUNET_NO);
    }

  /* Are multiple results possible (and did we look locally)?  If so, start processing remotely now! */
  switch (pr->type)
    {
    case GNUNET_BLOCK_TYPE_FS_DBLOCK:
    case GNUNET_BLOCK_TYPE_FS_IBLOCK:
      /* only one result, wait for datastore */
      if (GNUNET_YES != pr->forward_only)
	{
	  GNUNET_STATISTICS_update (stats,
				    gettext_noop ("# requests not instantly forwarded (waiting for datastore)"),
				    1,
				    GNUNET_NO);
 	  break;
	}
    default:
      if (pr->task == GNUNET_SCHEDULER_NO_TASK)
	pr->task = GNUNET_SCHEDULER_add_now (sched,
					     &forward_request_task,
					     pr);
    }

  /* make sure we don't track too many requests */
  if (GNUNET_CONTAINER_heap_get_size (requests_by_expiration_heap) > max_pending_requests)
    {
      pr = GNUNET_CONTAINER_heap_peek (requests_by_expiration_heap);
      GNUNET_assert (pr != NULL);
      destroy_pending_request (pr);
    }
  return GNUNET_OK;
}


/* **************************** CS GET Handling ************************ */


/**
 * Handle START_SEARCH-message (search request from client).
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_start_search (void *cls,
		     struct GNUNET_SERVER_Client *client,
		     const struct GNUNET_MessageHeader *message)
{
  static GNUNET_HashCode all_zeros;
  const struct SearchMessage *sm;
  struct ClientList *cl;
  struct ClientRequestList *crl;
  struct PendingRequest *pr;
  uint16_t msize;
  unsigned int sc;
  enum GNUNET_BLOCK_Type type;

  msize = ntohs (message->size);
  if ( (msize < sizeof (struct SearchMessage)) ||
       (0 != (msize - sizeof (struct SearchMessage)) % sizeof (GNUNET_HashCode)) )
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client,
				  GNUNET_SYSERR);
      return;
    }
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# client searches received"),
			    1,
			    GNUNET_NO);
  sc = (msize - sizeof (struct SearchMessage)) / sizeof (GNUNET_HashCode);
  sm = (const struct SearchMessage*) message;
  type = ntohl (sm->type);
#if DEBUG_FS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received request for `%s' of type %u from local client\n",
	      GNUNET_h2s (&sm->query),
	      (unsigned int) type);
#endif
  cl = client_list;
  while ( (cl != NULL) &&
	  (cl->client != client) )
    cl = cl->next;
  if (cl == NULL)
    {
      cl = GNUNET_malloc (sizeof (struct ClientList));
      cl->client = client;
      GNUNET_SERVER_client_keep (client);
      cl->next = client_list;
      client_list = cl;
    }
  /* detect duplicate KBLOCK requests */
  if ( (type == GNUNET_BLOCK_TYPE_FS_KBLOCK) ||
       (type == GNUNET_BLOCK_TYPE_FS_NBLOCK) ||
       (type == GNUNET_BLOCK_TYPE_ANY) )
    {
      crl = cl->rl_head;
      while ( (crl != NULL) &&
	      ( (0 != memcmp (&crl->req->query,
			      &sm->query,
			      sizeof (GNUNET_HashCode))) ||
		(crl->req->type != type) ) )
	crl = crl->next;
      if (crl != NULL) 	
	{ 
#if DEBUG_FS
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Have existing request, merging content-seen lists.\n");
#endif
	  pr = crl->req;
	  /* Duplicate request (used to send long list of
	     known/blocked results); merge 'pr->replies_seen'
	     and update bloom filter */
	  GNUNET_array_grow (pr->replies_seen,
			     pr->replies_seen_size,
			     pr->replies_seen_off + sc);
	  memcpy (&pr->replies_seen[pr->replies_seen_off],
		  &sm[1],
		  sc * sizeof (GNUNET_HashCode));
	  pr->replies_seen_off += sc;
	  refresh_bloomfilter (pr);
	  GNUNET_STATISTICS_update (stats,
				    gettext_noop ("# client searches updated (merged content seen list)"),
				    1,
				    GNUNET_NO);
	  GNUNET_SERVER_receive_done (client,
				      GNUNET_OK);
	  return;
	}
    }
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# client searches active"),
			    1,
			    GNUNET_NO);
  pr = GNUNET_malloc (sizeof (struct PendingRequest) + 
		      ((type == GNUNET_BLOCK_TYPE_FS_SBLOCK) ? sizeof(GNUNET_HashCode) : 0));
  crl = GNUNET_malloc (sizeof (struct ClientRequestList));
  memset (crl, 0, sizeof (struct ClientRequestList));
  crl->client_list = cl;
  GNUNET_CONTAINER_DLL_insert (cl->rl_head,
			       cl->rl_tail,
			       crl);  
  crl->req = pr;
  pr->type = type;
  pr->client_request_list = crl;
  GNUNET_array_grow (pr->replies_seen,
		     pr->replies_seen_size,
		     sc);
  memcpy (pr->replies_seen,
	  &sm[1],
	  sc * sizeof (GNUNET_HashCode));
  pr->replies_seen_off = sc;
  pr->anonymity_level = ntohl (sm->anonymity_level); 
  pr->start_time = GNUNET_TIME_absolute_get ();
  refresh_bloomfilter (pr);
  pr->query = sm->query;
  if (0 == (1 & ntohl (sm->options)))
    pr->local_only = GNUNET_NO;
  else
    pr->local_only = GNUNET_YES;
  switch (type)
    {
    case GNUNET_BLOCK_TYPE_FS_DBLOCK:
    case GNUNET_BLOCK_TYPE_FS_IBLOCK:
      if (0 != memcmp (&sm->target,
		       &all_zeros,
		       sizeof (GNUNET_HashCode)))
	pr->target_pid = GNUNET_PEER_intern ((const struct GNUNET_PeerIdentity*) &sm->target);
      break;
    case GNUNET_BLOCK_TYPE_FS_SBLOCK:
      pr->namespace = (GNUNET_HashCode*) &pr[1];
      memcpy (&pr[1], &sm->target, sizeof (GNUNET_HashCode));
      break;
    default:
      break;
    }
  GNUNET_break (GNUNET_OK ==
		GNUNET_CONTAINER_multihashmap_put (query_request_map,
						   &sm->query,
						   pr,
						   GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
  if (type == GNUNET_BLOCK_TYPE_FS_DBLOCK)
    type = GNUNET_BLOCK_TYPE_ANY; /* get on-demand blocks too! */
  pr->qe = GNUNET_DATASTORE_get (dsh,
				 &sm->query,
				 type,
				 -3, -1,
				 GNUNET_CONSTANTS_SERVICE_TIMEOUT,			       
				 &process_local_reply,
				 pr);
}


/* **************************** Startup ************************ */

/**
 * Process fs requests.
 *
 * @param s scheduler to use
 * @param server the initialized server
 * @param c configuration to use
 */
static int
main_init (struct GNUNET_SCHEDULER_Handle *s,
	   struct GNUNET_SERVER_Handle *server,
	   const struct GNUNET_CONFIGURATION_Handle *c)
{
  static const struct GNUNET_CORE_MessageHandler p2p_handlers[] =
    {
      { &handle_p2p_get, 
	GNUNET_MESSAGE_TYPE_FS_GET, 0 },
      { &handle_p2p_put, 
	GNUNET_MESSAGE_TYPE_FS_PUT, 0 },
      { &handle_p2p_migration_stop, 
	GNUNET_MESSAGE_TYPE_FS_MIGRATION_STOP,
	sizeof (struct MigrationStopMessage) },
      { NULL, 0, 0 }
    };
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&GNUNET_FS_handle_index_start, NULL, 
     GNUNET_MESSAGE_TYPE_FS_INDEX_START, 0},
    {&GNUNET_FS_handle_index_list_get, NULL, 
     GNUNET_MESSAGE_TYPE_FS_INDEX_LIST_GET, sizeof(struct GNUNET_MessageHeader) },
    {&GNUNET_FS_handle_unindex, NULL, GNUNET_MESSAGE_TYPE_FS_UNINDEX, 
     sizeof (struct UnindexMessage) },
    {&handle_start_search, NULL, GNUNET_MESSAGE_TYPE_FS_START_SEARCH, 
     0 },
    {NULL, NULL, 0, 0}
  };
  unsigned long long enc = 128;

  sched = s;
  cfg = c;
  stats = GNUNET_STATISTICS_create (sched, "fs", cfg);
  min_migration_delay = GNUNET_TIME_UNIT_SECONDS;
  if ( (GNUNET_OK !=
	GNUNET_CONFIGURATION_get_value_number (cfg,
					       "fs",
					       "MAX_PENDING_REQUESTS",
					       &max_pending_requests)) ||
       (GNUNET_OK !=
	GNUNET_CONFIGURATION_get_value_number (cfg,
					       "fs",
					       "EXPECTED_NEIGHBOUR_COUNT",
					       &enc)) ||
       (GNUNET_OK != 
	GNUNET_CONFIGURATION_get_value_time (cfg,
					     "fs",
					     "MIN_MIGRATION_DELAY",
					     &min_migration_delay)) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  _("Configuration fails to specify certain parameters, assuming default values."));
    }
  connected_peers = GNUNET_CONTAINER_multihashmap_create (enc); 
  query_request_map = GNUNET_CONTAINER_multihashmap_create (max_pending_requests);
  rt_entry_lifetime = GNUNET_LOAD_value_init (GNUNET_TIME_UNIT_FOREVER_REL);
  peer_request_map = GNUNET_CONTAINER_multihashmap_create (enc);
  requests_by_expiration_heap = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN); 
  core = GNUNET_CORE_connect (sched,
			      cfg,
			      GNUNET_TIME_UNIT_FOREVER_REL,
			      NULL,
			      NULL,
			      &peer_connect_handler,
			      &peer_disconnect_handler,
			      &peer_status_handler,
			      NULL, GNUNET_NO,
			      NULL, GNUNET_NO,
			      p2p_handlers);
  if (NULL == core)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Failed to connect to `%s' service.\n"),
		  "core");
      GNUNET_CONTAINER_multihashmap_destroy (connected_peers);
      connected_peers = NULL;
      GNUNET_CONTAINER_multihashmap_destroy (query_request_map);
      query_request_map = NULL;
      GNUNET_LOAD_value_free (rt_entry_lifetime);
      rt_entry_lifetime = NULL;
      GNUNET_CONTAINER_heap_destroy (requests_by_expiration_heap);
      requests_by_expiration_heap = NULL;
      GNUNET_CONTAINER_multihashmap_destroy (peer_request_map);
      peer_request_map = NULL;
      if (dsh != NULL)
	{
	  GNUNET_DATASTORE_disconnect (dsh, GNUNET_NO);
	  dsh = NULL;
	}
      return GNUNET_SYSERR;
    }
  /* FIXME: distinguish between sending and storing in options? */
  if (active_migration) 
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  _("Content migration is enabled, will start to gather data\n"));
      consider_migration_gathering ();
    }
  consider_dht_put_gathering (NULL);
  GNUNET_SERVER_disconnect_notify (server, 
				   &handle_client_disconnect,
				   NULL);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_filename (cfg,
                                                          "fs",
                                                          "TRUST",
                                                          &trustDirectory));
  GNUNET_DISK_directory_create (trustDirectory);
  GNUNET_SCHEDULER_add_with_priority (sched,
				      GNUNET_SCHEDULER_PRIORITY_HIGH,
				      &cron_flush_trust, NULL);


  GNUNET_SERVER_add_handlers (server, handlers);
  GNUNET_SCHEDULER_add_delayed (sched,
				GNUNET_TIME_UNIT_FOREVER_REL,
				&shutdown_task,
				NULL);
  return GNUNET_OK;
}


/**
 * Process fs requests.
 *
 * @param cls closure
 * @param sched scheduler to use
 * @param server the initialized server
 * @param cfg configuration to use
 */
static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *sched,
     struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  active_migration = GNUNET_CONFIGURATION_get_value_yesno (cfg,
							   "FS",
							   "ACTIVEMIGRATION");
  dsh = GNUNET_DATASTORE_connect (cfg,
				  sched);
  if (dsh == NULL)
    {
      GNUNET_SCHEDULER_shutdown (sched);
      return;
    }
  datastore_get_load = GNUNET_LOAD_value_init (DATASTORE_LOAD_AUTODECLINE);
  datastore_put_load = GNUNET_LOAD_value_init (DATASTORE_LOAD_AUTODECLINE);
  block_cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_CONFIGURATION_set_value_string (block_cfg,
					 "block",
					 "PLUGINS",
					 "fs");
  block_ctx = GNUNET_BLOCK_context_create (block_cfg);
  GNUNET_assert (NULL != block_ctx);
  dht_handle = GNUNET_DHT_connect (sched,
				   cfg,
				   FS_DHT_HT_SIZE);
  if ( (GNUNET_OK != GNUNET_FS_indexing_init (sched, cfg, dsh)) ||
       (GNUNET_OK != main_init (sched, server, cfg)) )
    {    
      GNUNET_SCHEDULER_shutdown (sched);
      GNUNET_DATASTORE_disconnect (dsh, GNUNET_NO);
      dsh = NULL;
      GNUNET_DHT_disconnect (dht_handle);
      dht_handle = NULL;
      GNUNET_BLOCK_context_destroy (block_ctx);
      block_ctx = NULL;
      GNUNET_CONFIGURATION_destroy (block_cfg);
      block_cfg = NULL;
      GNUNET_LOAD_value_free (datastore_get_load);
      datastore_get_load = NULL;
      GNUNET_LOAD_value_free (datastore_put_load);
      datastore_put_load = NULL;
      return;   
    }
}


/**
 * The main function for the fs service.
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
                              "fs",
			      GNUNET_SERVICE_OPTION_NONE,
			      &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-fs.c */
