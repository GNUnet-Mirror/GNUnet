/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2011, 2016 GNUnet e.V.

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file dht/gnunet-service-dht_clients.c
 * @brief GNUnet DHT service's client management code
 * @author Christian Grothoff
 * @author Nathan Evans
 */

#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_statistics_service.h"
#include "gnunet-service-dht.h"
#include "gnunet-service-dht_datacache.h"
#include "gnunet-service-dht_neighbours.h"
#include "dht.h"


/**
 * Should routing details be logged to stderr (for debugging)?
 */
#define LOG_TRAFFIC(kind,...) GNUNET_log_from (kind, "dht-traffic",__VA_ARGS__)

#define LOG(kind,...) GNUNET_log_from (kind, "dht-clients",__VA_ARGS__)


/**
 * Struct containing information about a client,
 * handle to connect to it, and any pending messages
 * that need to be sent to it.
 */
struct ClientHandle;


/**
 * Entry in the local forwarding map for a client's GET request.
 */
struct ClientQueryRecord
{

  /**
   * The key this request was about
   */
  struct GNUNET_HashCode key;

  /**
   * Kept in a DLL with @e client.
   */
  struct ClientQueryRecord *next;

  /**
   * Kept in a DLL with @e client.
   */
  struct ClientQueryRecord *prev;

  /**
   * Client responsible for the request.
   */
  struct ClientHandle *ch;

  /**
   * Extended query (see gnunet_block_lib.h), allocated at the end of this struct.
   */
  const void *xquery;

  /**
   * Replies we have already seen for this request.
   */
  struct GNUNET_HashCode *seen_replies;

  /**
   * Pointer to this nodes heap location in the retry-heap (for fast removal)
   */
  struct GNUNET_CONTAINER_HeapNode *hnode;

  /**
   * What's the delay between re-try operations that we currently use for this
   * request?
   */
  struct GNUNET_TIME_Relative retry_frequency;

  /**
   * What's the next time we should re-try this request?
   */
  struct GNUNET_TIME_Absolute retry_time;

  /**
   * The unique identifier of this request
   */
  uint64_t unique_id;

  /**
   * Number of bytes in xquery.
   */
  size_t xquery_size;

  /**
   * Number of entries in 'seen_replies'.
   */
  unsigned int seen_replies_count;

  /**
   * Desired replication level
   */
  uint32_t replication;

  /**
   * Any message options for this request
   */
  uint32_t msg_options;

  /**
   * The type for the data for the GET request.
   */
  enum GNUNET_BLOCK_Type type;

};


/**
 * Struct containing paremeters of monitoring requests.
 */
struct ClientMonitorRecord
{

  /**
   * Next element in DLL.
   */
  struct ClientMonitorRecord *next;

  /**
   * Previous element in DLL.
   */
  struct ClientMonitorRecord *prev;

  /**
   * Type of blocks that are of interest
   */
  enum GNUNET_BLOCK_Type type;

  /**
   * Key of data of interest, NULL for all.
   */
  struct GNUNET_HashCode *key;

  /**
   * Flag whether to notify about GET messages.
   */
  int16_t get;

  /**
   * Flag whether to notify about GET_REPONSE messages.
   */
  int16_t get_resp;

  /**
   * Flag whether to notify about PUT messages.
   */
  uint16_t put;

  /**
   * Client to notify of these requests.
   */
  struct ClientHandle *ch;
};


/**
 * Struct containing information about a client,
 * handle to connect to it, and any pending messages
 * that need to be sent to it.
 */
struct ClientHandle
{
  /**
   * Linked list of active queries of this client.
   */
  struct ClientQueryRecord *cqr_head;

  /**
   * Linked list of active queries of this client.
   */
  struct ClientQueryRecord *cqr_tail;

  /**
   * The handle to this client
   */
  struct GNUNET_SERVICE_Client *client;

  /**
   * The message queue to this client
   */
  struct GNUNET_MQ_Handle *mq;

};


/**
 * List of active monitoring requests.
 */
static struct ClientMonitorRecord *monitor_head;

/**
 * List of active monitoring requests.
 */
static struct ClientMonitorRecord *monitor_tail;

/**
 * Hashmap for fast key based lookup, maps keys to `struct ClientQueryRecord` entries.
 */
static struct GNUNET_CONTAINER_MultiHashMap *forward_map;

/**
 * Heap with all of our client's request, sorted by retry time (earliest on top).
 */
static struct GNUNET_CONTAINER_Heap *retry_heap;

/**
 * Task that re-transmits requests (using retry_heap).
 */
static struct GNUNET_SCHEDULER_Task *retry_task;


/**
 * Free data structures associated with the given query.
 *
 * @param record record to remove
 */
static void
remove_client_record (struct ClientQueryRecord *record)
{
  struct ClientHandle *ch = record->ch;

  GNUNET_CONTAINER_DLL_remove (ch->cqr_head,
                               ch->cqr_tail,
                               record);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (forward_map,
                                                       &record->key,
                                                       record));
  if (NULL != record->hnode)
    GNUNET_CONTAINER_heap_remove_node (record->hnode);
  GNUNET_array_grow (record->seen_replies,
                     record->seen_replies_count,
                     0);
  GNUNET_free (record);
}


/**
 * Functions with this signature are called whenever a local client is
 * connects to us.
 *
 * @param cls closure (NULL for dht)
 * @param client identification of the client
 * @param mq message queue for talking to @a client
 * @return our `struct ClientHandle` for @a client
 */
static void *
client_connect_cb (void *cls,
                   struct GNUNET_SERVICE_Client *client,
                   struct GNUNET_MQ_Handle *mq)
{
  struct ClientHandle *ch;

  ch = GNUNET_new (struct ClientHandle);
  ch->client = client;
  ch->mq = mq;
  return ch;
}


/**
 * Functions with this signature are called whenever a client
 * is disconnected on the network level.
 *
 * @param cls closure (NULL for dht)
 * @param client identification of the client
 * @param app_ctx our `struct ClientHandle` for @a client
 */
static void
client_disconnect_cb (void *cls,
                      struct GNUNET_SERVICE_Client *client,
                      void *app_ctx)
{
  struct ClientHandle *ch = app_ctx;
  struct ClientQueryRecord *cqr;
  struct ClientMonitorRecord *monitor;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Local client %p disconnects\n",
	      ch);
  monitor = monitor_head;
  while (NULL != monitor)
  {
    if (monitor->ch == ch)
    {
      struct ClientMonitorRecord *next;

      next = monitor->next;
      GNUNET_free_non_null (monitor->key);
      GNUNET_CONTAINER_DLL_remove (monitor_head,
                                   monitor_tail,
                                   monitor);
      GNUNET_free (monitor);
      monitor = next;
    }
    else
    {
      monitor = monitor->next;
    }
  }
  while (NULL != (cqr = ch->cqr_head))
    remove_client_record (cqr);
  GNUNET_free (ch);
}


/**
 * Route the given request via the DHT.  This includes updating
 * the bloom filter and retransmission times, building the P2P
 * message and initiating the routing operation.
 */
static void
transmit_request (struct ClientQueryRecord *cqr)
{
  int32_t reply_bf_mutator;
  struct GNUNET_CONTAINER_BloomFilter *reply_bf;
  struct GNUNET_CONTAINER_BloomFilter *peer_bf;

  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# GET requests from clients injected"),
                            1,
                            GNUNET_NO);
  reply_bf_mutator =
      (int32_t) GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                          UINT32_MAX);
  reply_bf
    = GNUNET_BLOCK_construct_bloomfilter (reply_bf_mutator,
                                          cqr->seen_replies,
                                          cqr->seen_replies_count);
  peer_bf
    = GNUNET_CONTAINER_bloomfilter_init (NULL,
                                         DHT_BLOOM_SIZE,
                                         GNUNET_CONSTANTS_BLOOMFILTER_K);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Initiating GET for %s, replication %u, already have %u replies\n",
       GNUNET_h2s (&cqr->key),
       cqr->replication,
       cqr->seen_replies_count);
  GDS_NEIGHBOURS_handle_get (cqr->type,
                             cqr->msg_options,
                             cqr->replication,
                             0 /* hop count */ ,
                             &cqr->key,
                             cqr->xquery,
                             cqr->xquery_size,
                             reply_bf,
                             reply_bf_mutator,
                             peer_bf);
  GNUNET_CONTAINER_bloomfilter_free (reply_bf);
  GNUNET_CONTAINER_bloomfilter_free (peer_bf);

  /* exponential back-off for retries.
   * max GNUNET_TIME_STD_EXPONENTIAL_BACKOFF_THRESHOLD (15 min) */
  cqr->retry_frequency = GNUNET_TIME_STD_BACKOFF (cqr->retry_frequency);
  cqr->retry_time = GNUNET_TIME_relative_to_absolute (cqr->retry_frequency);
}


/**
 * Task that looks at the #retry_heap and transmits all of the requests
 * on the heap that are ready for transmission.  Then re-schedules
 * itself (unless the heap is empty).
 *
 * @param cls unused
 */
static void
transmit_next_request_task (void *cls)
{
  struct ClientQueryRecord *cqr;
  struct GNUNET_TIME_Relative delay;

  retry_task = NULL;
  while (NULL != (cqr = GNUNET_CONTAINER_heap_remove_root (retry_heap)))
  {
    cqr->hnode = NULL;
    delay = GNUNET_TIME_absolute_get_remaining (cqr->retry_time);
    if (delay.rel_value_us > 0)
    {
      cqr->hnode =
          GNUNET_CONTAINER_heap_insert (retry_heap,
                                        cqr,
                                        cqr->retry_time.abs_value_us);
      retry_task =
          GNUNET_SCHEDULER_add_delayed (delay,
                                        &transmit_next_request_task,
                                        NULL);
      return;
    }
    transmit_request (cqr);
    cqr->hnode
      = GNUNET_CONTAINER_heap_insert (retry_heap, cqr,
                                      cqr->retry_time.abs_value_us);
  }
}


/**
 * Check DHT PUT messages from the client.
 *
 * @param cls the client we received this message from
 * @param dht_msg the actual message received
 * @return #GNUNET_OK (always)
 */
static int
check_dht_local_put (void *cls,
                      const struct GNUNET_DHT_ClientPutMessage *dht_msg)
{
  /* always well-formed */
  return GNUNET_OK;
}


/**
 * Handler for PUT messages.
 *
 * @param cls the client we received this message from
 * @param dht_msg the actual message received
 */
static void
handle_dht_local_put (void *cls,
                      const struct GNUNET_DHT_ClientPutMessage *dht_msg)
{
  struct ClientHandle *ch = cls;
  struct GNUNET_CONTAINER_BloomFilter *peer_bf;
  uint16_t size;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_DHT_ClientPutConfirmationMessage *conf;

  size = ntohs (dht_msg->header.size);
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# PUT requests received from clients"),
                            1,
                            GNUNET_NO);
  LOG_TRAFFIC (GNUNET_ERROR_TYPE_DEBUG,
               "CLIENT-PUT %s\n",
               GNUNET_h2s_full (&dht_msg->key));
  /* give to local clients */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Handling local PUT of %u-bytes for query %s\n",
       size - sizeof (struct GNUNET_DHT_ClientPutMessage),
       GNUNET_h2s (&dht_msg->key));
  GDS_CLIENTS_handle_reply (GNUNET_TIME_absolute_ntoh (dht_msg->expiration),
                            &dht_msg->key,
                            0,
                            NULL,
                            0,
                            NULL,
                            ntohl (dht_msg->type),
                            size - sizeof (struct GNUNET_DHT_ClientPutMessage),
                            &dht_msg[1]);
  /* store locally */
  GDS_DATACACHE_handle_put (GNUNET_TIME_absolute_ntoh (dht_msg->expiration),
                            &dht_msg->key,
                            0,
                            NULL,
                            ntohl (dht_msg->type),
                            size - sizeof (struct GNUNET_DHT_ClientPutMessage),
                            &dht_msg[1]);
  /* route to other peers */
  peer_bf
    = GNUNET_CONTAINER_bloomfilter_init (NULL,
                                         DHT_BLOOM_SIZE,
                                         GNUNET_CONSTANTS_BLOOMFILTER_K);
  GDS_NEIGHBOURS_handle_put (ntohl (dht_msg->type),
                             ntohl (dht_msg->options),
                             ntohl (dht_msg->desired_replication_level),
                             GNUNET_TIME_absolute_ntoh (dht_msg->expiration),
                             0 /* hop count */ ,
                             peer_bf,
                             &dht_msg->key,
                             0,
                             NULL,
                             &dht_msg[1],
                             size - sizeof (struct GNUNET_DHT_ClientPutMessage));
  GDS_CLIENTS_process_put (ntohl (dht_msg->options),
                           ntohl (dht_msg->type),
                           0,
                           ntohl (dht_msg->desired_replication_level),
                           1,
                           GDS_NEIGHBOURS_get_id(),
                           GNUNET_TIME_absolute_ntoh (dht_msg->expiration),
                           &dht_msg->key,
                           &dht_msg[1],
                           size - sizeof (struct GNUNET_DHT_ClientPutMessage));
  GNUNET_CONTAINER_bloomfilter_free (peer_bf);
  env = GNUNET_MQ_msg (conf,
                       GNUNET_MESSAGE_TYPE_DHT_CLIENT_PUT_OK);
  conf->reserved = htonl (0);
  conf->unique_id = dht_msg->unique_id;
  GNUNET_MQ_send (ch->mq,
                  env);
  GNUNET_SERVICE_client_continue (ch->client);
}


/**
 * Check DHT GET messages from the client.
 *
 * @param cls the client we received this message from
 * @param message the actual message received
 * @return #GNUNET_OK (always)
 */
static int
check_dht_local_get (void *cls,
                      const struct GNUNET_DHT_ClientGetMessage *get)
{
  /* always well-formed */
  return GNUNET_OK;
}


/**
 * Handler for DHT GET messages from the client.
 *
 * @param cls the client we received this message from
 * @param message the actual message received
 */
static void
handle_dht_local_get (void *cls,
                      const struct GNUNET_DHT_ClientGetMessage *get)
{
  struct ClientHandle *ch = cls;
  struct ClientQueryRecord *cqr;
  size_t xquery_size;
  const char *xquery;
  uint16_t size;

  size = ntohs (get->header.size);
  xquery_size = size - sizeof (struct GNUNET_DHT_ClientGetMessage);
  xquery = (const char *) &get[1];
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop
                            ("# GET requests received from clients"), 1,
                            GNUNET_NO);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received GET request for %s from local client %p, xq: %.*s\n",
       GNUNET_h2s (&get->key),
       ch->client,
       xquery_size,
       xquery);
  LOG_TRAFFIC (GNUNET_ERROR_TYPE_DEBUG,
               "CLIENT-GET %s\n",
               GNUNET_h2s_full (&get->key));

  cqr = GNUNET_malloc (sizeof (struct ClientQueryRecord) + xquery_size);
  cqr->key = get->key;
  cqr->ch = ch;
  cqr->xquery = (void *) &cqr[1];
  GNUNET_memcpy (&cqr[1], xquery, xquery_size);
  cqr->hnode = GNUNET_CONTAINER_heap_insert (retry_heap, cqr, 0);
  cqr->retry_frequency = GNUNET_TIME_UNIT_SECONDS;
  cqr->retry_time = GNUNET_TIME_absolute_get ();
  cqr->unique_id = get->unique_id;
  cqr->xquery_size = xquery_size;
  cqr->replication = ntohl (get->desired_replication_level);
  cqr->msg_options = ntohl (get->options);
  cqr->type = ntohl (get->type);
  GNUNET_CONTAINER_DLL_insert (ch->cqr_head,
                               ch->cqr_tail,
                               cqr);
  GNUNET_CONTAINER_multihashmap_put (forward_map,
                                     &cqr->key,
                                     cqr,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  GDS_CLIENTS_process_get (ntohl (get->options),
                           ntohl (get->type),
                           0,
                           ntohl (get->desired_replication_level),
                           1,
                           GDS_NEIGHBOURS_get_id(),
                           &get->key);
  /* start remote requests */
  if (NULL != retry_task)
    GNUNET_SCHEDULER_cancel (retry_task);
  retry_task = GNUNET_SCHEDULER_add_now (&transmit_next_request_task,
					 NULL);
  /* perform local lookup */
  GDS_DATACACHE_handle_get (&get->key,
			    cqr->type,
			    cqr->xquery,
			    xquery_size,
                            NULL,
			    0);
  GNUNET_SERVICE_client_continue (ch->client);
}


/**
 * Closure for #find_by_unique_id().
 */
struct FindByUniqueIdContext
{
  /**
   * Where to store the result, if found.
   */
  struct ClientQueryRecord *cqr;

  uint64_t unique_id;
};


/**
 * Function called for each existing DHT record for the given
 * query.  Checks if it matches the UID given in the closure
 * and if so returns the entry as a result.
 *
 * @param cls the search context
 * @param key query for the lookup (not used)
 * @param value the `struct ClientQueryRecord`
 * @return #GNUNET_YES to continue iteration (result not yet found)
 */
static int
find_by_unique_id (void *cls,
		   const struct GNUNET_HashCode *key,
		   void *value)
{
  struct FindByUniqueIdContext *fui_ctx = cls;
  struct ClientQueryRecord *cqr = value;

  if (cqr->unique_id != fui_ctx->unique_id)
    return GNUNET_YES;
  fui_ctx->cqr = cqr;
  return GNUNET_NO;
}


/**
 * Check "GET result seen" messages from the client.
 *
 * @param cls the client we received this message from
 * @param message the actual message received
 * @return #GNUNET_OK if @a seen is well-formed
 */
static int
check_dht_local_get_result_seen (void *cls,
                                 const struct GNUNET_DHT_ClientGetResultSeenMessage *seen)
{
  uint16_t size;
  unsigned int hash_count;

  size = ntohs (seen->header.size);
  hash_count = (size - sizeof (struct GNUNET_DHT_ClientGetResultSeenMessage)) / sizeof (struct GNUNET_HashCode);
  if (size != sizeof (struct GNUNET_DHT_ClientGetResultSeenMessage) + hash_count * sizeof (struct GNUNET_HashCode))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handler for "GET result seen" messages from the client.
 *
 * @param cls the client we received this message from
 * @param message the actual message received
 */
static void
handle_dht_local_get_result_seen (void *cls,
				  const struct GNUNET_DHT_ClientGetResultSeenMessage *seen)
{
  struct ClientHandle *ch = cls;
  uint16_t size;
  unsigned int hash_count;
  unsigned int old_count;
  const struct GNUNET_HashCode *hc;
  struct FindByUniqueIdContext fui_ctx;
  struct ClientQueryRecord *cqr;

  size = ntohs (seen->header.size);
  hash_count = (size - sizeof (struct GNUNET_DHT_ClientGetResultSeenMessage)) / sizeof (struct GNUNET_HashCode);
  hc = (const struct GNUNET_HashCode*) &seen[1];
  fui_ctx.unique_id = seen->unique_id;
  fui_ctx.cqr = NULL;
  GNUNET_CONTAINER_multihashmap_get_multiple (forward_map,
					      &seen->key,
					      &find_by_unique_id,
					      &fui_ctx);
  if (NULL == (cqr = fui_ctx.cqr))
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (ch->client);
    return;
  }
  /* finally, update 'seen' list */
  old_count = cqr->seen_replies_count;
  GNUNET_array_grow (cqr->seen_replies,
		     cqr->seen_replies_count,
		     cqr->seen_replies_count + hash_count);
  GNUNET_memcpy (&cqr->seen_replies[old_count],
                 hc,
                 sizeof (struct GNUNET_HashCode) * hash_count);
}


/**
 * Closure for #remove_by_unique_id().
 */
struct RemoveByUniqueIdContext
{
  /**
   * Client that issued the removal request.
   */
  struct ClientHandle *ch;

  /**
   * Unique ID of the request.
   */
  uint64_t unique_id;
};


/**
 * Iterator over hash map entries that frees all entries
 * that match the given client and unique ID.
 *
 * @param cls unique ID and client to search for in source routes
 * @param key current key code
 * @param value value in the hash map, a ClientQueryRecord
 * @return #GNUNET_YES (we should continue to iterate)
 */
static int
remove_by_unique_id (void *cls,
                     const struct GNUNET_HashCode *key,
                     void *value)
{
  const struct RemoveByUniqueIdContext *ctx = cls;
  struct ClientQueryRecord *cqr = value;

  if (cqr->unique_id != ctx->unique_id)
    return GNUNET_YES;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Removing client %p's record for key %s (by unique id)\n",
              ctx->ch->client,
              GNUNET_h2s (key));
  remove_client_record (cqr);
  return GNUNET_YES;
}


/**
 * Handler for any generic DHT stop messages, calls the appropriate handler
 * depending on message type (if processed locally)
 *
 * @param cls client we received this message from
 * @param message the actual message received
 *
 */
static void
handle_dht_local_get_stop (void *cls,
                           const struct GNUNET_DHT_ClientGetStopMessage *dht_stop_msg)
{
  struct ClientHandle *ch = cls;
  struct RemoveByUniqueIdContext ctx;

  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop
                            ("# GET STOP requests received from clients"), 1,
                            GNUNET_NO);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received GET STOP request for %s from local client %p\n",
       GNUNET_h2s (&dht_stop_msg->key),
       ch->client);
  ctx.ch = ch;
  ctx.unique_id = dht_stop_msg->unique_id;
  GNUNET_CONTAINER_multihashmap_get_multiple (forward_map,
                                              &dht_stop_msg->key,
                                              &remove_by_unique_id,
                                              &ctx);
  GNUNET_SERVICE_client_continue (ch->client);
}


/**
 * Handler for monitor start messages
 *
 * @param cls the client we received this message from
 * @param msg the actual message received
 *
 */
static void
handle_dht_local_monitor (void *cls,
                          const struct GNUNET_DHT_MonitorStartStopMessage *msg)
{
  struct ClientHandle *ch = cls;
  struct ClientMonitorRecord *r;

  r = GNUNET_new (struct ClientMonitorRecord);
  r->ch = ch;
  r->type = ntohl (msg->type);
  r->get = ntohs (msg->get);
  r->get_resp = ntohs (msg->get_resp);
  r->put = ntohs (msg->put);
  if (0 == ntohs (msg->filter_key))
  {
    r->key = NULL;
  }
  else
  {
    r->key = GNUNET_new (struct GNUNET_HashCode);
    GNUNET_memcpy (r->key,
                   &msg->key,
                   sizeof (struct GNUNET_HashCode));
  }
  GNUNET_CONTAINER_DLL_insert (monitor_head,
                               monitor_tail,
                               r);
  GNUNET_SERVICE_client_continue (ch->client);
}


/**
 * Handler for monitor stop messages
 *
 * @param cls the client we received this message from
 * @param msg the actual message received
 */
static void
handle_dht_local_monitor_stop (void *cls,
                               const struct GNUNET_DHT_MonitorStartStopMessage *msg)
{
  struct ClientHandle *ch = cls;
  struct ClientMonitorRecord *r;
  int keys_match;

  GNUNET_SERVICE_client_continue (ch->client);
  for (r = monitor_head; NULL != r; r = r->next)
  {
    if (NULL == r->key)
    {
      keys_match = (0 == ntohs(msg->filter_key));
    }
    else
    {
      keys_match = ( (0 != ntohs(msg->filter_key)) &&
                     (! memcmp (r->key,
                                &msg->key,
                                sizeof(struct GNUNET_HashCode))) );
    }
    if ( (ch == r->ch) &&
         (ntohl(msg->type) == r->type) &&
         (r->get == msg->get) &&
         (r->get_resp == msg->get_resp) &&
         (r->put == msg->put) &&
         keys_match )
    {
      GNUNET_CONTAINER_DLL_remove (monitor_head,
                                   monitor_tail,
                                   r);
      GNUNET_free_non_null (r->key);
      GNUNET_free (r);
      return; /* Delete only ONE entry */
    }
  }
}


/**
 * Closure for #forward_reply()
 */
struct ForwardReplyContext
{

  /**
   * Expiration time of the reply.
   */
  struct GNUNET_TIME_Absolute expiration;

  /**
   * GET path taken.
   */
  const struct GNUNET_PeerIdentity *get_path;

  /**
   * PUT path taken.
   */
  const struct GNUNET_PeerIdentity *put_path;

  /**
   * Embedded payload.
   */
  const void *data;

  /**
   * Number of bytes in data.
   */
  size_t data_size;

  /**
   * Number of entries in @e get_path.
   */
  unsigned int get_path_length;

  /**
   * Number of entries in @e put_path.
   */
  unsigned int put_path_length;

  /**
   * Type of the data.
   */
  enum GNUNET_BLOCK_Type type;

};


/**
 * Iterator over hash map entries that send a given reply to
 * each of the matching clients.  With some tricky recycling
 * of the buffer.
 *
 * @param cls the 'struct ForwardReplyContext'
 * @param key current key
 * @param value value in the hash map, a ClientQueryRecord
 * @return #GNUNET_YES (we should continue to iterate),
 *         if the result is mal-formed, #GNUNET_NO
 */
static int
forward_reply (void *cls,
               const struct GNUNET_HashCode *key,
               void *value)
{
  struct ForwardReplyContext *frc = cls;
  struct ClientQueryRecord *record = value;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_DHT_ClientResultMessage *reply;
  enum GNUNET_BLOCK_EvaluationResult eval;
  int do_free;
  struct GNUNET_HashCode ch;
  struct GNUNET_PeerIdentity *paths;

  LOG_TRAFFIC (GNUNET_ERROR_TYPE_DEBUG,
	       "CLIENT-RESULT %s\n",
               GNUNET_h2s_full (key));
  if ( (record->type != GNUNET_BLOCK_TYPE_ANY) &&
       (record->type != frc->type))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Record type missmatch, not passing request for key %s to local client\n",
         GNUNET_h2s (key));
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop
                              ("# Key match, type mismatches in REPLY to CLIENT"),
                              1, GNUNET_NO);
    return GNUNET_YES;          /* type mismatch */
  }
  GNUNET_CRYPTO_hash (frc->data, frc->data_size, &ch);
  for (unsigned int i = 0; i < record->seen_replies_count; i++)
    if (0 == memcmp (&record->seen_replies[i],
                     &ch,
                     sizeof (struct GNUNET_HashCode)))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Duplicate reply, not passing request for key %s to local client\n",
           GNUNET_h2s (key));
      GNUNET_STATISTICS_update (GDS_stats,
                                gettext_noop
                                ("# Duplicate REPLIES to CLIENT request dropped"),
                                1, GNUNET_NO);
      return GNUNET_YES;        /* duplicate */
    }
  eval
    = GNUNET_BLOCK_evaluate (GDS_block_context,
                             record->type,
                             GNUNET_BLOCK_EO_NONE,
                             key,
                             NULL,
                             0,
                             record->xquery,
                             record->xquery_size,
                             frc->data,
                             frc->data_size);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Evaluation result is %d for key %s for local client's query\n",
       (int) eval,
       GNUNET_h2s (key));
  switch (eval)
  {
  case GNUNET_BLOCK_EVALUATION_OK_LAST:
    do_free = GNUNET_YES;
    break;
  case GNUNET_BLOCK_EVALUATION_OK_MORE:
    GNUNET_array_append (record->seen_replies,
                         record->seen_replies_count,
                         ch);
    do_free = GNUNET_NO;
    break;
  case GNUNET_BLOCK_EVALUATION_OK_DUPLICATE:
    /* should be impossible to encounter here */
    GNUNET_break (0);
    return GNUNET_YES;
  case GNUNET_BLOCK_EVALUATION_RESULT_INVALID:
    GNUNET_break_op (0);
    return GNUNET_NO;
  case GNUNET_BLOCK_EVALUATION_REQUEST_VALID:
    GNUNET_break (0);
    return GNUNET_NO;
  case GNUNET_BLOCK_EVALUATION_REQUEST_INVALID:
    GNUNET_break (0);
    return GNUNET_NO;
  case GNUNET_BLOCK_EVALUATION_RESULT_IRRELEVANT:
    return GNUNET_YES;
  case GNUNET_BLOCK_EVALUATION_TYPE_NOT_SUPPORTED:
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Unsupported block type (%u) in request!\n"), record->type);
    return GNUNET_NO;
  default:
    GNUNET_break (0);
    return GNUNET_NO;
  }
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# RESULTS queued for clients"),
                            1,
                            GNUNET_NO);
  env = GNUNET_MQ_msg_extra (reply,
                             frc->data_size +
                             (frc->get_path_length + frc->put_path_length) * sizeof (struct GNUNET_PeerIdentity),
                             GNUNET_MESSAGE_TYPE_DHT_CLIENT_RESULT);
  reply->type = htonl (frc->type);
  reply->get_path_length = htonl (frc->get_path_length);
  reply->put_path_length = htonl (frc->put_path_length);
  reply->unique_id = record->unique_id;
  reply->expiration = GNUNET_TIME_absolute_hton (frc->expiration);
  reply->key = *key;
  paths = (struct GNUNET_PeerIdentity *) &reply[1];
  GNUNET_memcpy (paths,
                 frc->put_path,
                 sizeof (struct GNUNET_PeerIdentity) * frc->put_path_length);
  GNUNET_memcpy (&paths[frc->put_path_length],
                 frc->get_path,
                 sizeof (struct GNUNET_PeerIdentity) * frc->get_path_length);
  GNUNET_memcpy (&paths[frc->get_path_length + frc->put_path_length],
                 frc->data,
                 frc->data_size);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending reply to query %s for client %p\n",
       GNUNET_h2s (key),
       record->ch->client);
  GNUNET_MQ_send (record->ch->mq,
                  env);
  if (GNUNET_YES == do_free)
    remove_client_record (record);
  return GNUNET_YES;
}


/**
 * Handle a reply we've received from another peer.  If the reply
 * matches any of our pending queries, forward it to the respective
 * client(s).
 *
 * @param expiration when will the reply expire
 * @param key the query this reply is for
 * @param get_path_length number of peers in @a get_path
 * @param get_path path the reply took on get
 * @param put_path_length number of peers in @a put_path
 * @param put_path path the reply took on put
 * @param type type of the reply
 * @param data_size number of bytes in @a data
 * @param data application payload data
 */
void
GDS_CLIENTS_handle_reply (struct GNUNET_TIME_Absolute expiration,
                          const struct GNUNET_HashCode *key,
                          unsigned int get_path_length,
                          const struct GNUNET_PeerIdentity *get_path,
                          unsigned int put_path_length,
                          const struct GNUNET_PeerIdentity *put_path,
                          enum GNUNET_BLOCK_Type type,
                          size_t data_size,
                          const void *data)
{
  struct ForwardReplyContext frc;
  size_t msize;

  msize = sizeof (struct GNUNET_DHT_ClientResultMessage) + data_size +
    (get_path_length + put_path_length) * sizeof (struct GNUNET_PeerIdentity);
  if (msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }
  if (NULL == GNUNET_CONTAINER_multihashmap_get (forward_map,
                                                 key))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "No matching client for reply for key %s\n",
         GNUNET_h2s (key));
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop ("# REPLIES ignored for CLIENTS (no match)"),
                              1,
                              GNUNET_NO);
    return;                     /* no matching request, fast exit! */
  }
  frc.expiration = expiration;
  frc.get_path = get_path;
  frc.put_path = put_path;
  frc.data = data;
  frc.data_size = data_size;
  frc.get_path_length = get_path_length;
  frc.put_path_length = put_path_length;
  frc.type = type;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Forwarding reply for key %s to client\n",
       GNUNET_h2s (key));
  GNUNET_CONTAINER_multihashmap_get_multiple (forward_map,
                                              key,
                                              &forward_reply,
                                              &frc);

}


/**
 * Check if some client is monitoring GET messages and notify
 * them in that case.
 *
 * @param options Options, for instance RecordRoute, DemultiplexEverywhere.
 * @param type The type of data in the request.
 * @param hop_count Hop count so far.
 * @param path_length number of entries in path (or 0 if not recorded).
 * @param path peers on the GET path (or NULL if not recorded).
 * @param desired_replication_level Desired replication level.
 * @param key Key of the requested data.
 */
void
GDS_CLIENTS_process_get (uint32_t options,
                         enum GNUNET_BLOCK_Type type,
                         uint32_t hop_count,
                         uint32_t desired_replication_level,
                         unsigned int path_length,
                         const struct GNUNET_PeerIdentity *path,
                         const struct GNUNET_HashCode * key)
{
  struct ClientMonitorRecord *m;
  struct ClientHandle **cl;
  unsigned int cl_size;

  cl = NULL;
  cl_size = 0;
  for (m = monitor_head; NULL != m; m = m->next)
  {
    if ( ( (GNUNET_BLOCK_TYPE_ANY == m->type) ||
           (m->type == type) ) &&
         ( (NULL == m->key) ||
           (0 == memcmp (key,
                         m->key,
                         sizeof(struct GNUNET_HashCode))) ) )
    {
      struct GNUNET_MQ_Envelope *env;
      struct GNUNET_DHT_MonitorGetMessage *mmsg;
      struct GNUNET_PeerIdentity *msg_path;
      size_t msize;
      unsigned int i;

      /* Don't send duplicates */
      for (i = 0; i < cl_size; i++)
        if (cl[i] == m->ch)
          break;
      if (i < cl_size)
        continue;
      GNUNET_array_append (cl,
                           cl_size,
                           m->ch);

      msize = path_length * sizeof (struct GNUNET_PeerIdentity);
      env = GNUNET_MQ_msg_extra (mmsg,
                                 msize,
                                 GNUNET_MESSAGE_TYPE_DHT_MONITOR_GET);
      mmsg->options = htonl(options);
      mmsg->type = htonl(type);
      mmsg->hop_count = htonl(hop_count);
      mmsg->desired_replication_level = htonl(desired_replication_level);
      mmsg->get_path_length = htonl(path_length);
      mmsg->key = *key;
      msg_path = (struct GNUNET_PeerIdentity *) &mmsg[1];
      GNUNET_memcpy (msg_path,
                     path,
                     path_length * sizeof (struct GNUNET_PeerIdentity));
      GNUNET_MQ_send (m->ch->mq,
                      env);
    }
  }
  GNUNET_free_non_null (cl);
}


/**
 * Check if some client is monitoring GET RESP messages and notify
 * them in that case.
 *
 * @param type The type of data in the result.
 * @param get_path Peers on GET path (or NULL if not recorded).
 * @param get_path_length number of entries in get_path.
 * @param put_path peers on the PUT path (or NULL if not recorded).
 * @param put_path_length number of entries in get_path.
 * @param exp Expiration time of the data.
 * @param key Key of the data.
 * @param data Pointer to the result data.
 * @param size Number of bytes in @a data.
 */
void
GDS_CLIENTS_process_get_resp (enum GNUNET_BLOCK_Type type,
                              const struct GNUNET_PeerIdentity *get_path,
                              unsigned int get_path_length,
                              const struct GNUNET_PeerIdentity *put_path,
                              unsigned int put_path_length,
                              struct GNUNET_TIME_Absolute exp,
                              const struct GNUNET_HashCode * key,
                              const void *data,
                              size_t size)
{
  struct ClientMonitorRecord *m;
  struct ClientHandle **cl;
  unsigned int cl_size;

  cl = NULL;
  cl_size = 0;
  for (m = monitor_head; NULL != m; m = m->next)
  {
    if ((GNUNET_BLOCK_TYPE_ANY == m->type || m->type == type) &&
        (NULL == m->key ||
         memcmp (key, m->key, sizeof(struct GNUNET_HashCode)) == 0))
    {
      struct GNUNET_MQ_Envelope *env;
      struct GNUNET_DHT_MonitorGetRespMessage *mmsg;
      struct GNUNET_PeerIdentity *path;
      size_t msize;
      unsigned int i;

      /* Don't send duplicates */
      for (i = 0; i < cl_size; i++)
        if (cl[i] == m->ch)
          break;
      if (i < cl_size)
        continue;
      GNUNET_array_append (cl,
                           cl_size,
                           m->ch);

      msize = size;
      msize += (get_path_length + put_path_length)
               * sizeof (struct GNUNET_PeerIdentity);
      env = GNUNET_MQ_msg_extra (mmsg,
                                 msize,
                                 GNUNET_MESSAGE_TYPE_DHT_MONITOR_GET_RESP);
      mmsg->type = htonl(type);
      mmsg->put_path_length = htonl(put_path_length);
      mmsg->get_path_length = htonl(get_path_length);
      mmsg->expiration_time = GNUNET_TIME_absolute_hton(exp);
      mmsg->key = *key;
      path = (struct GNUNET_PeerIdentity *) &mmsg[1];
      GNUNET_memcpy (path,
                     put_path,
                     put_path_length * sizeof (struct GNUNET_PeerIdentity));
      GNUNET_memcpy (path,
                     get_path,
                     get_path_length * sizeof (struct GNUNET_PeerIdentity));
      GNUNET_memcpy (&path[get_path_length],
                     data,
                     size);
      GNUNET_MQ_send (m->ch->mq,
                      env);
    }
  }
  GNUNET_free_non_null (cl);
}


/**
 * Check if some client is monitoring PUT messages and notify
 * them in that case.
 *
 * @param options Options, for instance RecordRoute, DemultiplexEverywhere.
 * @param type The type of data in the request.
 * @param hop_count Hop count so far.
 * @param path_length number of entries in path (or 0 if not recorded).
 * @param path peers on the PUT path (or NULL if not recorded).
 * @param desired_replication_level Desired replication level.
 * @param exp Expiration time of the data.
 * @param key Key under which data is to be stored.
 * @param data Pointer to the data carried.
 * @param size Number of bytes in data.
 */
void
GDS_CLIENTS_process_put (uint32_t options,
                         enum GNUNET_BLOCK_Type type,
                         uint32_t hop_count,
                         uint32_t desired_replication_level,
                         unsigned int path_length,
                         const struct GNUNET_PeerIdentity *path,
                         struct GNUNET_TIME_Absolute exp,
                         const struct GNUNET_HashCode *key,
                         const void *data,
                         size_t size)
{
  struct ClientMonitorRecord *m;
  struct ClientHandle **cl;
  unsigned int cl_size;

  cl = NULL;
  cl_size = 0;
  for (m = monitor_head; NULL != m; m = m->next)
  {
    if ((GNUNET_BLOCK_TYPE_ANY == m->type || m->type == type) &&
        (NULL == m->key ||
         memcmp (key, m->key, sizeof(struct GNUNET_HashCode)) == 0))
    {
      struct GNUNET_MQ_Envelope *env;
      struct GNUNET_DHT_MonitorPutMessage *mmsg;
      struct GNUNET_PeerIdentity *msg_path;
      size_t msize;
      unsigned int i;

      /* Don't send duplicates */
      for (i = 0; i < cl_size; i++)
        if (cl[i] == m->ch)
          break;
      if (i < cl_size)
        continue;
      GNUNET_array_append (cl,
                           cl_size,
                           m->ch);

      msize = size;
      msize += path_length * sizeof (struct GNUNET_PeerIdentity);
      env = GNUNET_MQ_msg_extra (mmsg,
                                 msize,
                                 GNUNET_MESSAGE_TYPE_DHT_MONITOR_PUT);
      mmsg->options = htonl(options);
      mmsg->type = htonl(type);
      mmsg->hop_count = htonl(hop_count);
      mmsg->desired_replication_level = htonl (desired_replication_level);
      mmsg->put_path_length = htonl (path_length);
      mmsg->key = *key;
      mmsg->expiration_time = GNUNET_TIME_absolute_hton (exp);
      msg_path = (struct GNUNET_PeerIdentity *) &mmsg[1];
      GNUNET_memcpy (msg_path,
                     path,
                     path_length * sizeof (struct GNUNET_PeerIdentity));
      GNUNET_memcpy (&msg_path[path_length],
                     data,
                     size);
      GNUNET_MQ_send (m->ch->mq,
                      env);
    }
  }
  GNUNET_free_non_null (cl);
}


/**
 * Initialize client subsystem.
 *
 * @param server the initialized server
 */
static void
GDS_CLIENTS_init ()
{
  forward_map
    = GNUNET_CONTAINER_multihashmap_create (1024,
                                            GNUNET_YES);
  retry_heap
    = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
}


/**
 * Shutdown client subsystem.
 */
static void
GDS_CLIENTS_stop ()
{
  if (NULL != retry_task)
  {
    GNUNET_SCHEDULER_cancel (retry_task);
    retry_task = NULL;
  }
}


/**
 * Define "main" method using service macro.
 *
 * @param run name of the initializaton method for the service
 */
#define GDS_DHT_SERVICE_INIT(run)   \
 GNUNET_SERVICE_MAIN \
  ("dht", \
  GNUNET_SERVICE_OPTION_NONE, \
  run, \
  &client_connect_cb, \
  &client_disconnect_cb, \
  NULL, \
  GNUNET_MQ_hd_var_size (dht_local_put, \
                         GNUNET_MESSAGE_TYPE_DHT_CLIENT_PUT, \
                         struct GNUNET_DHT_ClientPutMessage, \
                         NULL), \
  GNUNET_MQ_hd_var_size (dht_local_get, \
                         GNUNET_MESSAGE_TYPE_DHT_CLIENT_GET, \
                         struct GNUNET_DHT_ClientGetMessage, \
                         NULL), \
  GNUNET_MQ_hd_fixed_size (dht_local_get_stop, \
                          GNUNET_MESSAGE_TYPE_DHT_CLIENT_GET_STOP, \
                          struct GNUNET_DHT_ClientGetStopMessage, \
                          NULL), \
  GNUNET_MQ_hd_fixed_size (dht_local_monitor, \
                           GNUNET_MESSAGE_TYPE_DHT_MONITOR_START, \
                           struct GNUNET_DHT_MonitorStartStopMessage, \
                           NULL), \
  GNUNET_MQ_hd_fixed_size (dht_local_monitor_stop, \
                           GNUNET_MESSAGE_TYPE_DHT_MONITOR_STOP, \
                           struct GNUNET_DHT_MonitorStartStopMessage, \
                           NULL), \
  GNUNET_MQ_hd_var_size (dht_local_get_result_seen, \
                         GNUNET_MESSAGE_TYPE_DHT_CLIENT_GET_RESULTS_KNOWN, \
                         struct GNUNET_DHT_ClientGetResultSeenMessage , \
                         NULL), \
  GNUNET_MQ_handler_end ())


/**
 * MINIMIZE heap size (way below 128k) since this process doesn't need much.
 */
void __attribute__ ((destructor))
GDS_CLIENTS_done ()
{
  if (NULL != retry_heap)
  {
    GNUNET_assert (0 == GNUNET_CONTAINER_heap_get_size (retry_heap));
    GNUNET_CONTAINER_heap_destroy (retry_heap);
    retry_heap = NULL;
  }
  if (NULL != forward_map)
  {
    GNUNET_assert (0 == GNUNET_CONTAINER_multihashmap_size (forward_map));
    GNUNET_CONTAINER_multihashmap_destroy (forward_map);
    forward_map = NULL;
  }
}

/* end of gnunet-service-dht_clients.c */
