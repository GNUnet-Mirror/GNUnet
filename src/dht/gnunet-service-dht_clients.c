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
#include "gnunet-service-dht_clients.h"
#include "gnunet-service-dht_datacache.h"
#include "gnunet-service-dht_neighbours.h"
#include "dht.h"


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
   * Actual message to be sent, allocated at the end of the struct:
   * // msg = (cast) &pm[1]; 
   * // memcpy (&pm[1], data, len);
   */
  const struct GNUNET_MessageHeader *msg;

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
   * Linked list of active clients
   */
  struct ClientList *prev;

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
 * Entry in the DHT routing table for a client's GET request.
 */
struct ClientQueryRecord
{

  /**
   * The key this request was about
   */
  GNUNET_HashCode key;

  /**
   * Client responsible for the request.
   */
  struct ClientList *client;

  /**
   * Extended query (see gnunet_block_lib.h), allocated at the end of this struct.
   */
  const void *xquery;

  /**
   * Replies we have already seen for this request.
   */
  GNUNET_HashCode *seen_replies;

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
 * List of active clients.
 */
static struct ClientList *client_head;

/**
 * List of active clients.
 */
static struct ClientList *client_tail;

/**
 * Hashmap for fast key based lookup, maps keys to 'struct ClientQueryRecord' entries.
 */
static struct GNUNET_CONTAINER_MultiHashMap *forward_map;

/**
 * Heap with all of our client's request, sorted by retry time (earliest on top).
 */
static struct GNUNET_CONTAINER_Heap *retry_heap;

/**
 * Task that re-transmits requests (using retry_heap).
 */
static GNUNET_SCHEDULER_TaskIdentifier retry_task;


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
  struct ClientList *pos = client_head;
  struct ClientList *ret;

  while (pos != NULL)
  {
    if (pos->client_handle == client)
      return pos;
    pos = pos->next;
  }
  ret = GNUNET_malloc (sizeof (struct ClientList));
  ret->client_handle = client;
  GNUNET_CONTAINER_DLL_insert (client_head,
			       client_tail,
			       ret);
  return ret;
}


/**
 * Iterator over hash map entries that frees all entries 
 * associated with the given client.
 *
 * @param cls client to search for in source routes
 * @param key current key code (ignored)
 * @param value value in the hash map, a ClientQueryRecord
 * @return GNUNET_YES (we should continue to iterate)
 */
static int
remove_client_records (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct ClientList *client = cls;
  struct ClientQueryRecord *record = value;

  if (record->client != client)
    return GNUNET_YES;
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multihashmap_remove (forward_map,
						       key, record));
  if (NULL != record->hnode)
    GNUNET_CONTAINER_heap_remove_node (record->hnode);
  GNUNET_array_grow (record->seen_replies,
		     record->seen_replies_count,
		     0);
  GNUNET_free (record);
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
handle_client_disconnect (void *cls, 
			  struct GNUNET_SERVER_Client *client)
{
  struct ClientList *pos;
  struct PendingMessage *reply;

  pos = find_active_client (client);
  GNUNET_CONTAINER_DLL_remove (client_head,
			       client_tail,
			       pos);
  if (pos->transmit_handle != NULL)
    GNUNET_CONNECTION_notify_transmit_ready_cancel (pos->transmit_handle);
  while (NULL != (reply = pos->pending_head))
    {
      GNUNET_CONTAINER_DLL_remove (pos->pending_head, pos->pending_tail,
                                   reply);
      GNUNET_free (reply);
    }
  GNUNET_CONTAINER_multihashmap_iterate (forward_map,
					 &remove_client_records, pos);
  GNUNET_free (pos);
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
                            gettext_noop ("# GET requests from clients injected"), 1,
                            GNUNET_NO);
  reply_bf_mutator = (int32_t) GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
							 UINT32_MAX);
  reply_bf = GNUNET_BLOCK_construct_bloomfilter (reply_bf_mutator,
						 cqr->seen_replies,
						 cqr->seen_replies_count);
  peer_bf = GNUNET_CONTAINER_bloomfilter_init (NULL,
					       DHT_BLOOM_SIZE,
					       GNUNET_CONSTANTS_BLOOMFILTER_K);
  GDS_NEIGHBOURS_handle_get (cqr->type,
			     cqr->msg_options,
			     cqr->replication,
			     0 /* hop count */,
			     &cqr->key,
			     cqr->xquery,
			     cqr->xquery_size,
			     reply_bf,
			     reply_bf_mutator,
			     peer_bf);
  GNUNET_CONTAINER_bloomfilter_free (reply_bf);
  GNUNET_CONTAINER_bloomfilter_free (peer_bf);

  /* exponential back-off for retries, max 1h */
  cqr->retry_frequency = 
    GNUNET_TIME_relative_max (GNUNET_TIME_UNIT_HOURS,
			      GNUNET_TIME_relative_multiply (cqr->retry_frequency, 2));
  cqr->retry_time = GNUNET_TIME_relative_to_absolute (cqr->retry_frequency);
}


/**
 * Task that looks at the 'retry_heap' and transmits all of the requests
 * on the heap that are ready for transmission.  Then re-schedules
 * itself (unless the heap is empty).
 *
 * @param cls unused
 * @param tc scheduler context
 */
static void
transmit_next_request_task (void *cls,
			    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ClientQueryRecord *cqr;
  struct GNUNET_TIME_Relative delay;

  retry_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  while (NULL != (cqr = GNUNET_CONTAINER_heap_remove_root (retry_heap)))
    {
      cqr->hnode = NULL;
      delay = GNUNET_TIME_absolute_get_remaining (cqr->retry_time);
      if (delay.rel_value > 0)
	{
	  cqr->hnode = GNUNET_CONTAINER_heap_insert (retry_heap, cqr,
						     cqr->retry_time.abs_value);
	  retry_task = GNUNET_SCHEDULER_add_delayed (delay,
						     &transmit_next_request_task,
						     NULL);
	  return;
	}
      transmit_request (cqr);
    }
}


/**
 * Handler for PUT messages.
 *
 * @param cls closure for the service
 * @param client the client we received this message from
 * @param message the actual message received
 */
static void
handle_dht_local_put (void *cls, struct GNUNET_SERVER_Client *client,
		      const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_DHT_ClientPutMessage *dht_msg;
  struct GNUNET_CONTAINER_BloomFilter *peer_bf;
  uint16_t size;
  
  size = ntohs (message->size);
  if (size < sizeof (struct GNUNET_DHT_ClientPutMessage))
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# PUT requests received from clients"), 1,
                            GNUNET_NO);
  dht_msg = (const struct GNUNET_DHT_ClientPutMessage *) message;
  /* give to local clients */
  GDS_CLIENTS_handle_reply (GNUNET_TIME_absolute_ntoh (dht_msg->expiration),
			   &dht_msg->key,
			   0, NULL,
			   0, NULL,
			   ntohl (dht_msg->type),
			   size - sizeof (struct GNUNET_DHT_ClientPutMessage),
			   &dht_msg[1]);
  /* store locally */
  GDS_DATACACHE_handle_put (GNUNET_TIME_absolute_ntoh (dht_msg->expiration),
			    &dht_msg->key,
			    0, NULL,
			    ntohl (dht_msg->type),
			    size - sizeof (struct GNUNET_DHT_ClientPutMessage),
			    &dht_msg[1]);
  /* route to other peers */
  peer_bf = GNUNET_CONTAINER_bloomfilter_init (NULL,
					       DHT_BLOOM_SIZE,
					       GNUNET_CONSTANTS_BLOOMFILTER_K);
  GDS_NEIGHBOURS_handle_put (ntohl (dht_msg->type),
			     ntohl (dht_msg->options),
			     ntohl (dht_msg->desired_replication_level),
			     GNUNET_TIME_absolute_ntoh (dht_msg->expiration),
			     0 /* hop count */,
			     peer_bf,
			     &dht_msg->key,
			     0, NULL,
			     &dht_msg[1],
			     size - sizeof (struct GNUNET_DHT_ClientPutMessage));
  GNUNET_CONTAINER_bloomfilter_free (peer_bf);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
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
handle_dht_local_get (void *cls, struct GNUNET_SERVER_Client *client,
		      const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_DHT_ClientGetMessage *get;
  struct ClientQueryRecord *cqr;
  size_t xquery_size;
  const char* xquery;
  uint16_t size;

  size = ntohs (message->size);
  if (size < sizeof (struct GNUNET_DHT_ClientGetMessage))
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  xquery_size = size - sizeof (struct GNUNET_DHT_ClientGetMessage);
  get = (const struct GNUNET_DHT_ClientGetMessage *) message;
  xquery = (const char*) &get[1];
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# GET requests received from clients"), 1,
                            GNUNET_NO);
  
  cqr = GNUNET_malloc (sizeof (struct ClientQueryRecord) + xquery_size);
  cqr->key = get->key;
  cqr->client = find_active_client (client);
  cqr->xquery = (void*) &cqr[1];
  memcpy (&cqr[1], xquery, xquery_size);
  cqr->hnode = GNUNET_CONTAINER_heap_insert (retry_heap, cqr, 0); 
  cqr->retry_frequency = GNUNET_TIME_UNIT_MILLISECONDS;
  cqr->retry_time = GNUNET_TIME_absolute_get ();
  cqr->unique_id = get->unique_id;
  cqr->xquery_size = xquery_size;
  cqr->replication = ntohl (get->desired_replication_level);
  cqr->msg_options = ntohl (get->options);
  cqr->type = ntohl (get->type);  
  GNUNET_CONTAINER_multihashmap_put (forward_map, &get->key, cqr,
				     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  /* start remote requests */
  if (GNUNET_SCHEDULER_NO_TASK != retry_task)
    GNUNET_SCHEDULER_cancel (retry_task);
  retry_task = GNUNET_SCHEDULER_add_now (&transmit_next_request_task, NULL);
  /* perform local lookup */
  GDS_DATACACHE_handle_get (&get->key,
			    cqr->type,
			    cqr->xquery,
			    xquery_size,
			    NULL, 0);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Closure for 'remove_by_unique_id'.
 */
struct RemoveByUniqueIdContext
{
  /**
   * Client that issued the removal request.
   */
  struct ClientList *client;

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
 * @return GNUNET_YES (we should continue to iterate)
 */
static int
remove_by_unique_id (void *cls, const GNUNET_HashCode * key, void *value)
{
  const struct RemoveByUniqueIdContext *ctx = cls;
  struct ClientQueryRecord *record = value;

  if (record->unique_id != ctx->unique_id)
    return GNUNET_YES;
  return remove_client_records (ctx->client, key, record);
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
handle_dht_local_get_stop (void *cls, struct GNUNET_SERVER_Client *client,
			   const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_DHT_ClientGetStopMessage *dht_stop_msg =
    (const struct GNUNET_DHT_ClientGetStopMessage *) message;
  struct RemoveByUniqueIdContext ctx;
  
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# GET STOP requests received from clients"), 1,
                            GNUNET_NO);
  ctx.client = find_active_client (client);
  ctx.unique_id = dht_stop_msg->unique_id;
  GNUNET_CONTAINER_multihashmap_get_multiple (forward_map,
					      &dht_stop_msg->key,
					      &remove_by_unique_id,
					      &ctx);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Task run to check for messages that need to be sent to a client.
 *
 * @param client a ClientList, containing the client and any messages to be sent to it
 */
static void
process_pending_messages (struct ClientList *client);


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
send_reply_to_client (void *cls, size_t size, void *buf)
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
  return off;
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
                                           &send_reply_to_client, client);
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
  GNUNET_CONTAINER_DLL_insert_tail (client->pending_head, client->pending_tail,
				    pending_message);
  process_pending_messages (client);
}


/**
 * Closure for 'forward_reply'
 */
struct ForwardReplyContext
{

  /**
   * Actual message to send to matching clients. 
   */
  struct PendingMessage *pm;

  /**
   * Embedded payload.
   */
  const void *data;

  /**
   * Type of the data.
   */
  enum GNUNET_BLOCK_Type type;

  /**
   * Number of bytes in data.
   */
  size_t data_size;

  /**
   * Do we need to copy 'pm' because it was already used?
   */
  int do_copy;

};


/**
 * Iterator over hash map entries that send a given reply to
 * each of the matching clients.  With some tricky recycling
 * of the buffer.
 *
 * @param cls the 'struct ForwardReplyContext'
 * @param key current key
 * @param value value in the hash map, a ClientQueryRecord
 * @return GNUNET_YES (we should continue to iterate),
 *         if the result is mal-formed, GNUNET_NO
 */
static int
forward_reply (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct ForwardReplyContext *frc = cls;
  struct ClientQueryRecord *record = value;
  struct PendingMessage *pm;
  struct GNUNET_DHT_ClientResultMessage *reply;
  enum GNUNET_BLOCK_EvaluationResult eval;
  int do_free;
  GNUNET_HashCode ch;
  unsigned int i;
  
  if ( (record->type != GNUNET_BLOCK_TYPE_ANY) &&
       (record->type != frc->type) )
    {
      GNUNET_STATISTICS_update (GDS_stats,
				gettext_noop ("# Key match, type mismatches in REPLY to CLIENT"), 1,
				GNUNET_NO);
      return GNUNET_YES; /* type mismatch */
    }
  GNUNET_CRYPTO_hash (frc->data,
		      frc->data_size,
		      &ch);
  for (i=0;i<record->seen_replies_count;i++)
    if (0 == memcmp (&record->seen_replies[i],
		     &ch,
		     sizeof (GNUNET_HashCode)))
      {
	GNUNET_STATISTICS_update (GDS_stats,
				  gettext_noop ("# Duplicate REPLIES to CLIENT request dropped"), 1,
				  GNUNET_NO);
	return GNUNET_YES; /* duplicate */             
      }
  eval =
    GNUNET_BLOCK_evaluate (GDS_block_context, 
			   record->type, key, 
			   NULL, 0,
			   record->xquery,
			   record->xquery_size, 
			   frc->data,
			   frc->data_size);
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
  case GNUNET_BLOCK_EVALUATION_TYPE_NOT_SUPPORTED:
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Unsupported block type (%u) in request!\n"),
                record->type);
    return GNUNET_NO;
  default:
    GNUNET_break (0);
    return GNUNET_NO;
  }
  if (GNUNET_NO == frc->do_copy)
    {
      /* first time, we can use the original data */
      pm = frc->pm; 
      frc->do_copy = GNUNET_YES;
    }
  else
    {
      /* two clients waiting for same reply, must copy for queueing */
      pm = GNUNET_malloc (sizeof (struct PendingMessage) +
			  ntohs (frc->pm->msg->size));
      memcpy (pm, frc->pm, 
	      sizeof (struct PendingMessage) + ntohs (frc->pm->msg->size));
      pm->next = pm->prev = NULL;
    }
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# RESULTS queued for clients"), 1,
                            GNUNET_NO);
  reply = (struct GNUNET_DHT_ClientResultMessage*) &pm[1];  
  reply->unique_id = record->unique_id;
  add_pending_message (record->client, pm);
  if (GNUNET_YES == do_free)
    remove_client_records (record->client, key, record);
  return GNUNET_YES;
}


/**
 * Handle a reply we've received from another peer.  If the reply
 * matches any of our pending queries, forward it to the respective
 * client(s).
 *
 * @param expiration when will the reply expire
 * @param key the query this reply is for
 * @param get_path_length number of peers in 'get_path'
 * @param get_path path the reply took on get
 * @param put_path_length number of peers in 'put_path'
 * @param put_path path the reply took on put
 * @param type type of the reply
 * @param data_size number of bytes in 'data'
 * @param data application payload data
 */
void
GDS_CLIENTS_handle_reply (struct GNUNET_TIME_Absolute expiration,
			 const GNUNET_HashCode *key,
			 unsigned int get_path_length,
			 const struct GNUNET_PeerIdentity *get_path,
			 unsigned int put_path_length,
			 const struct GNUNET_PeerIdentity *put_path,
			 enum GNUNET_BLOCK_Type type,
			 size_t data_size,
			 const void *data)
{
  struct ForwardReplyContext frc;
  struct PendingMessage *pm;
  struct GNUNET_DHT_ClientResultMessage *reply;
  struct GNUNET_PeerIdentity *paths;
  size_t msize;

  if (NULL ==
      GNUNET_CONTAINER_multihashmap_get (forward_map, key))
  {
    GNUNET_STATISTICS_update (GDS_stats,
			      gettext_noop ("# REPLIES ignored for CLIENTS (no match)"), 1,
			      GNUNET_NO);
    return; /* no matching request, fast exit! */
  }
  msize = sizeof(struct GNUNET_DHT_ClientResultMessage) + data_size + 
    (get_path_length + put_path_length) * sizeof (struct GNUNET_PeerIdentity);
  if (msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Could not pass reply to client, message too big!\n"));
      return;
    }
  pm = (struct PendingMessage *) GNUNET_malloc (msize + sizeof (struct PendingMessage));
  reply = (struct GNUNET_DHT_ClientResultMessage*) &pm[1];
  pm->msg = &reply->header;
  reply->header.size = htons ((uint16_t) msize);
  reply->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_CLIENT_RESULT);
  reply->type = htonl (type);
  reply->get_path_length = htonl (get_path_length);
  reply->put_path_length = htonl (put_path_length);
  reply->unique_id = 0; /* filled in later */
  reply->expiration = GNUNET_TIME_absolute_hton (expiration);
  reply->key = *key;
  paths = (struct GNUNET_PeerIdentity*) &reply[1];
  memcpy (paths, get_path, 
	  sizeof (struct GNUNET_PeerIdentity) * get_path_length);
  memcpy (&paths[get_path_length], 
	  put_path, sizeof (struct GNUNET_PeerIdentity) * put_path_length);
  memcpy (&paths[get_path_length + put_path_length],
	  data, 
	  data_size);
  frc.do_copy = GNUNET_NO;
  frc.pm = pm;
  frc.data = data;
  frc.data_size = data_size;
  frc.type = type;
  GNUNET_CONTAINER_multihashmap_get_multiple (forward_map, key,
					      &forward_reply,
					      &frc);
  if (GNUNET_NO == frc.do_copy)
    {
      /* did not match any of the requests, free! */
      GNUNET_free (pm);
    }
}


/**
 * Initialize client subsystem.
 *
 * @param server the initialized server
 */
void 
GDS_CLIENTS_init (struct GNUNET_SERVER_Handle *server)
{
  static struct GNUNET_SERVER_MessageHandler plugin_handlers[] = {
    {&handle_dht_local_put, NULL, 
     GNUNET_MESSAGE_TYPE_DHT_CLIENT_PUT, 0},
    {&handle_dht_local_get, NULL, 
     GNUNET_MESSAGE_TYPE_DHT_CLIENT_GET, 0},
    {&handle_dht_local_get_stop, NULL,
     GNUNET_MESSAGE_TYPE_DHT_CLIENT_GET_STOP, 
     sizeof (struct GNUNET_DHT_ClientGetStopMessage) },
    {NULL, NULL, 0, 0}
  };
  forward_map = GNUNET_CONTAINER_multihashmap_create (1024);
  retry_heap = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  GNUNET_SERVER_add_handlers (server, plugin_handlers);
  GNUNET_SERVER_disconnect_notify (server, &handle_client_disconnect, NULL);
}


/**
 * Shutdown client subsystem.
 */
void
GDS_CLIENTS_done ()
{
  GNUNET_assert (client_head == NULL);
  GNUNET_assert (client_tail == NULL);
  if (GNUNET_SCHEDULER_NO_TASK != retry_task)
    {
      GNUNET_SCHEDULER_cancel (retry_task);
      retry_task = GNUNET_SCHEDULER_NO_TASK;
    }
  GNUNET_assert (0 == GNUNET_CONTAINER_heap_get_size (retry_heap));
  GNUNET_CONTAINER_heap_destroy (retry_heap);
  retry_heap = NULL;
  GNUNET_assert (0 == GNUNET_CONTAINER_multihashmap_size (forward_map));
  GNUNET_CONTAINER_multihashmap_destroy (forward_map);
  forward_map = NULL;
}

/* end of gnunet-service-dht_clients.c */

