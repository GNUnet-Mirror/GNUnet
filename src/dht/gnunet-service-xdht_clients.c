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
#include "gnunet-service-xdht.h"
#include "gnunet-service-xdht_clients.h"
#include "gnunet-service-xdht_datacache.h"
#include "gnunet-service-xdht_neighbours.h"
#include "dht.h"


/**
 * Should routing details be logged to stderr (for debugging)?
 */
#define LOG_TRAFFIC(kind,...) GNUNET_log_from (kind, "dht-traffic",__VA_ARGS__)

#define LOG(kind,...) GNUNET_log_from (kind, "dht-clients",__VA_ARGS__)

#if ENABLE_MALICIOUS
/**
 * Should this peer act malicious?
 */
extern unsigned int malicious;
#endif

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
  struct GNUNET_SERVER_TransmitHandle *transmit_handle;

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
 * Entry in the local forwarding map for a client's GET request.
 */
struct ClientQueryRecord
{

  /**
   * The key this request was about
   */
  struct GNUNET_HashCode key;

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
  struct ClientMonitorRecord    *next;

  /**
   * Previous element in DLL.
   */
  struct ClientMonitorRecord    *prev;

  /**
   * Type of blocks that are of interest
   */
  enum GNUNET_BLOCK_Type        type;

  /**
   * Key of data of interest, NULL for all.
   */
  struct GNUNET_HashCode         *key;

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
  struct ClientList             *client;
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
static GNUNET_SCHEDULER_TaskIdentifier retry_task;


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
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Client %p disconnected, pending messages will be discarded\n",
                client->client_handle);
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
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Transmitting %u bytes to client %p\n",
                msize, client->client_handle);
    off += msize;
  }
  process_pending_messages (client);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Transmitted %u/%u bytes to client %p\n",
              (unsigned int) off, (unsigned int) size, client->client_handle);
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
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Not asking for transmission to %p now: %s\n",
                client->client_handle,
                client->pending_head ==
                NULL ? "no more messages" : "request already pending");
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Asking for transmission of %u bytes to client %p\n",
              ntohs (client->pending_head->msg->size), client->client_handle);
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
  ret = GNUNET_new (struct ClientList);
  ret->client_handle = client;
  GNUNET_CONTAINER_DLL_insert (client_head, client_tail, ret);
  return ret;
}


/**
 * Iterator over hash map entries that frees all entries
 * associated with the given client.
 *
 * @param cls client to search for in source routes
 * @param key current key code (ignored)
 * @param value value in the hash map, a ClientQueryRecord
 * @return #GNUNET_YES (we should continue to iterate)
 */
static int
remove_client_records (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  struct ClientList *client = cls;
  struct ClientQueryRecord *record = value;

  if (record->client != client)
    return GNUNET_YES;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Removing client %p's record for key %s\n", client,
              GNUNET_h2s (key));
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (forward_map, key,
                                                       record));
  if (NULL != record->hnode)
    GNUNET_CONTAINER_heap_remove_node (record->hnode);
  GNUNET_array_grow (record->seen_replies, record->seen_replies_count, 0);
  GNUNET_free (record);
  return GNUNET_YES;
}


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
forward_reply (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  struct ForwardReplyContext *frc = cls;
  struct ClientQueryRecord *record = value;
  struct PendingMessage *pm;
  struct GNUNET_DHT_ClientResultMessage *reply;
  enum GNUNET_BLOCK_EvaluationResult eval;
  int do_free;
  struct GNUNET_HashCode ch;
  unsigned int i;

  LOG_TRAFFIC (GNUNET_ERROR_TYPE_DEBUG,
	       "R5N CLIENT-RESULT %s\n",
               GNUNET_h2s_full (key));
  if ((record->type != GNUNET_BLOCK_TYPE_ANY) && (record->type != frc->type))
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
  for (i = 0; i < record->seen_replies_count; i++)
    if (0 == memcmp (&record->seen_replies[i], &ch, sizeof (struct GNUNET_HashCode)))
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
  eval =
      GNUNET_BLOCK_evaluate (GDS_block_context, record->type, key, NULL, 0,
                             record->xquery, record->xquery_size, frc->data,
                             frc->data_size);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Evaluation result is %d for key %s for local client's query\n",
       (int) eval, GNUNET_h2s (key));
  switch (eval)
  {
  case GNUNET_BLOCK_EVALUATION_OK_LAST:
    do_free = GNUNET_YES;
    break;
  case GNUNET_BLOCK_EVALUATION_OK_MORE:
    GNUNET_array_append (record->seen_replies, record->seen_replies_count, ch);
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
    pm->msg = (struct GNUNET_MessageHeader *) &pm[1];
  }
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# RESULTS queued for clients"), 1,
                            GNUNET_NO);
  reply = (struct GNUNET_DHT_ClientResultMessage *) &pm[1];
  reply->unique_id = record->unique_id;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Queueing reply to query %s for client %p\n",
       GNUNET_h2s (key),
       record->client->client_handle);
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
                          enum GNUNET_BLOCK_Type type, size_t data_size,
                          const void *data)
{
  struct ForwardReplyContext frc;
  struct PendingMessage *pm;
  struct GNUNET_DHT_ClientResultMessage *reply;
  struct GNUNET_PeerIdentity *paths;
  size_t msize;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "reply for key %s\n",
       GNUNET_h2s (key));

  if (NULL == GNUNET_CONTAINER_multihashmap_get (forward_map, key))
  {
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop
                              ("# REPLIES ignored for CLIENTS (no match)"), 1,
                              GNUNET_NO);
    return;                     /* no matching request, fast exit! */
  }
  msize =
      sizeof (struct GNUNET_DHT_ClientResultMessage) + data_size +
      (get_path_length + put_path_length) * sizeof (struct GNUNET_PeerIdentity);
  if (msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Could not pass reply to client, message too big!\n"));
    return;
  }
  pm = GNUNET_malloc (msize + sizeof (struct PendingMessage));
  reply = (struct GNUNET_DHT_ClientResultMessage *) &pm[1];
  pm->msg = &reply->header;
  reply->header.size = htons ((uint16_t) msize);
  reply->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_CLIENT_RESULT);
  reply->type = htonl (type);
  reply->get_path_length = htonl (get_path_length);
  reply->put_path_length = htonl (put_path_length);
  reply->unique_id = 0;         /* filled in later */
  reply->expiration = GNUNET_TIME_absolute_hton (expiration);
  reply->key = *key;
  paths = (struct GNUNET_PeerIdentity *) &reply[1];
  memcpy (paths, put_path,
          sizeof (struct GNUNET_PeerIdentity) * put_path_length);
  memcpy (&paths[put_path_length], get_path,
          sizeof (struct GNUNET_PeerIdentity) * get_path_length);
  memcpy (&paths[get_path_length + put_path_length], data, data_size);
  frc.do_copy = GNUNET_NO;
  frc.pm = pm;
  frc.data = data;
  frc.data_size = data_size;
  frc.type = type;
  GNUNET_CONTAINER_multihashmap_get_multiple (forward_map, key, &forward_reply,
                                              &frc);

  if (GNUNET_NO == frc.do_copy)
  {
    /* did not match any of the requests, free! */
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop
                              ("# REPLIES ignored for CLIENTS (no match)"), 1,
                              GNUNET_NO);
    GNUNET_free (pm);
  }
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
  struct ClientList **cl;
  unsigned int cl_size;

  cl = NULL;
  cl_size = 0;
  for (m = monitor_head; NULL != m; m = m->next)
  {
    if ((GNUNET_BLOCK_TYPE_ANY == m->type || m->type == type) &&
        (NULL == m->key ||
         memcmp (key, m->key, sizeof(struct GNUNET_HashCode)) == 0))
    {
      struct PendingMessage *pm;
      struct GNUNET_DHT_MonitorGetMessage *mmsg;
      struct GNUNET_PeerIdentity *msg_path;
      size_t msize;
      unsigned int i;

      /* Don't send duplicates */
      for (i = 0; i < cl_size; i++)
        if (cl[i] == m->client)
          break;
      if (i < cl_size)
        continue;
      GNUNET_array_append (cl, cl_size, m->client);

      msize = path_length * sizeof (struct GNUNET_PeerIdentity);
      msize += sizeof (struct GNUNET_DHT_MonitorGetMessage);
      msize += sizeof (struct PendingMessage);
      pm = GNUNET_malloc (msize);
      mmsg = (struct GNUNET_DHT_MonitorGetMessage *) &pm[1];
      pm->msg = &mmsg->header;
      mmsg->header.size = htons (msize - sizeof (struct PendingMessage));
      mmsg->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_MONITOR_GET);
      mmsg->options = htonl(options);
      mmsg->type = htonl(type);
      mmsg->hop_count = htonl(hop_count);
      mmsg->desired_replication_level = htonl(desired_replication_level);
      mmsg->get_path_length = htonl(path_length);
      memcpy (&mmsg->key, key, sizeof (struct GNUNET_HashCode));
      msg_path = (struct GNUNET_PeerIdentity *) &mmsg[1];
      if (path_length > 0)
        memcpy (msg_path, path,
                path_length * sizeof (struct GNUNET_PeerIdentity));
      add_pending_message (m->client, pm);
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
                         const struct GNUNET_HashCode * key,
                         const void *data,
                         size_t size)
{
  struct ClientMonitorRecord *m;
  struct ClientList **cl;
  unsigned int cl_size;

  cl = NULL;
  cl_size = 0;
  for (m = monitor_head; NULL != m; m = m->next)
  {
    if ((GNUNET_BLOCK_TYPE_ANY == m->type || m->type == type) &&
        (NULL == m->key ||
         memcmp (key, m->key, sizeof(struct GNUNET_HashCode)) == 0))
    {
      struct PendingMessage *pm;
      struct GNUNET_DHT_MonitorPutMessage *mmsg;
      struct GNUNET_PeerIdentity *msg_path;
      size_t msize;
      unsigned int i;

      /* Don't send duplicates */
      for (i = 0; i < cl_size; i++)
        if (cl[i] == m->client)
          break;
      if (i < cl_size)
        continue;
      GNUNET_array_append (cl, cl_size, m->client);

      msize = size;
      msize += path_length * sizeof (struct GNUNET_PeerIdentity);
      msize += sizeof (struct GNUNET_DHT_MonitorPutMessage);
      msize += sizeof (struct PendingMessage);
      pm = GNUNET_malloc (msize);
      mmsg = (struct GNUNET_DHT_MonitorPutMessage *) &pm[1];
      pm->msg = (struct GNUNET_MessageHeader *) mmsg;
      mmsg->header.size = htons (msize - sizeof (struct PendingMessage));
      mmsg->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_MONITOR_PUT);
      mmsg->options = htonl(options);
      mmsg->type = htonl(type);
      mmsg->hop_count = htonl(hop_count);
      mmsg->desired_replication_level = htonl(desired_replication_level);
      mmsg->put_path_length = htonl(path_length);
      msg_path = (struct GNUNET_PeerIdentity *) &mmsg[1];
      if (path_length > 0)
      {
        memcpy (msg_path, path,
                path_length * sizeof (struct GNUNET_PeerIdentity));
      }
      mmsg->expiration_time = GNUNET_TIME_absolute_hton(exp);
      memcpy (&mmsg->key, key, sizeof (struct GNUNET_HashCode));
      if (size > 0)
        memcpy (&msg_path[path_length], data, size);
      add_pending_message (m->client, pm);
    }
  }
  GNUNET_free_non_null (cl);
}


/**
 * Route the given request via the DHT.  
 */
static void
transmit_request (struct ClientQueryRecord *cqr)
{
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop
                            ("# GET requests from clients injected"), 1,
                            GNUNET_NO);
  
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Initiating GET for %s, replication %u, already have %u replies\n",
       GNUNET_h2s (&cqr->key),
       cqr->replication,
       cqr->seen_replies_count);
  GDS_NEIGHBOURS_send_get (&cqr->key, cqr->type, cqr->msg_options, 
                           cqr->replication, NULL, NULL , NULL,
                           0, 0, NULL);
  
  /* exponential back-off for retries.
   * max GNUNET_TIME_STD_EXPONENTIAL_BACKOFF_THRESHOLD (15 min) */
  cqr->retry_frequency = GNUNET_TIME_STD_BACKOFF (cqr->retry_frequency);
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
    if (delay.rel_value_us > 0)
    {
      cqr->hnode =
          GNUNET_CONTAINER_heap_insert (retry_heap, cqr,
                                        cqr->retry_time.abs_value_us);
      retry_task =
          GNUNET_SCHEDULER_add_delayed (delay, &transmit_next_request_task,
                                        NULL);
      return;
    }
    transmit_request (cqr);
    cqr->hnode =
        GNUNET_CONTAINER_heap_insert (retry_heap, cqr,
                                      cqr->retry_time.abs_value_us);
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
  const struct GNUNET_DHT_ClientPutMessage *put_msg;
  struct PendingMessage *pm;
  struct GNUNET_DHT_ClientPutConfirmationMessage *conf;
  uint16_t size;

  size = ntohs (message->size);
  if (size < sizeof (struct GNUNET_DHT_ClientPutMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop
                            ("# PUT requests received from clients"), 1,
                            GNUNET_NO);
  put_msg = (const struct GNUNET_DHT_ClientPutMessage *) message;
  LOG_TRAFFIC (GNUNET_ERROR_TYPE_DEBUG, "X-VINE DHT CLIENT-PUT %s\n",
               GNUNET_h2s_full (&put_msg->key));
  /* give to local clients */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Handling local PUT of %u-bytes for query %s\n",
       size - sizeof (struct GNUNET_DHT_ClientPutMessage),
       GNUNET_h2s (&put_msg->key));
  
  GDS_CLIENTS_handle_reply (GNUNET_TIME_absolute_ntoh (put_msg->expiration),
                            &put_msg->key, 0, NULL, 0, NULL,
                            ntohl (put_msg->type),
                            size - sizeof (struct GNUNET_DHT_ClientPutMessage),
                            &put_msg[1]);
  /* FIXME: Should we store locally? */
  GDS_DATACACHE_handle_put (GNUNET_TIME_absolute_ntoh (put_msg->expiration),
                            &put_msg->key, 0, NULL, ntohl (put_msg->type),
                            size - sizeof (struct GNUNET_DHT_ClientPutMessage),
                            &put_msg[1]);
 
  struct GNUNET_PeerIdentity my_identity =  GDS_NEIGHBOURS_get_my_id();
  GDS_NEIGHBOURS_send_put (&put_msg->key, 
                           ntohl (put_msg->type), ntohl (put_msg->options),
                           ntohl (put_msg->desired_replication_level), NULL,
                           NULL, NULL, 0, 0, NULL,
                           GNUNET_TIME_absolute_ntoh (put_msg->expiration),
                           &put_msg[1],
                           size - sizeof (struct GNUNET_DHT_ClientPutMessage));
  

  GDS_CLIENTS_process_put (ntohl (put_msg->options),
                           ntohl (put_msg->type),
                           0,
                           ntohl (put_msg->desired_replication_level),
                           1,
                           &my_identity,
                           GNUNET_TIME_absolute_ntoh (put_msg->expiration),
                           &put_msg->key,
                           &put_msg[1],
                           size - sizeof (struct GNUNET_DHT_ClientPutMessage));
  
  pm = GNUNET_malloc (sizeof (struct PendingMessage) +
		      sizeof (struct GNUNET_DHT_ClientPutConfirmationMessage));
  conf = (struct GNUNET_DHT_ClientPutConfirmationMessage *) &pm[1];
  conf->header.size = htons (sizeof (struct GNUNET_DHT_ClientPutConfirmationMessage));
  conf->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_CLIENT_PUT_OK);
  conf->reserved = htonl (0);
  conf->unique_id = put_msg->unique_id;
  pm->msg = &conf->header;
  add_pending_message (find_active_client (client), pm);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handler for DHT GET messages from the client.
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
  const char *xquery;
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
  xquery = (const char *) &get[1];
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop
                            ("# GET requests received from clients"), 1,
                            GNUNET_NO);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received GET request for %s from local client %p, xq: %.*s\n",
       GNUNET_h2s (&get->key), client, xquery_size, xquery);

  LOG_TRAFFIC (GNUNET_ERROR_TYPE_DEBUG, "X-VINE CLIENT-GET %s\n",
               GNUNET_h2s_full (&get->key));


  cqr = GNUNET_malloc (sizeof (struct ClientQueryRecord) + xquery_size);
  cqr->key = get->key;
  cqr->client = find_active_client (client);
  cqr->xquery = (void *) &cqr[1];
  memcpy (&cqr[1], xquery, xquery_size);
  cqr->hnode = GNUNET_CONTAINER_heap_insert (retry_heap, cqr, 0);
  cqr->retry_frequency = GNUNET_TIME_UNIT_SECONDS;
  cqr->retry_time = GNUNET_TIME_absolute_get ();
  cqr->unique_id = get->unique_id;
  cqr->xquery_size = xquery_size;
  cqr->replication = ntohl (get->desired_replication_level);
  cqr->msg_options = ntohl (get->options);
  cqr->type = ntohl (get->type);
  // FIXME use cqr->key, set multihashmap create to GNUNET_YES
  GNUNET_CONTAINER_multihashmap_put (forward_map, &get->key, cqr,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  
  struct GNUNET_PeerIdentity my_identity;
  my_identity = GDS_NEIGHBOURS_get_my_id();
  GDS_CLIENTS_process_get (ntohl (get->options),
                           ntohl (get->type),
                           0,
                           ntohl (get->desired_replication_level),
                           1,
                           &my_identity,
                           &get->key);
  /* start remote requests */
  if (GNUNET_SCHEDULER_NO_TASK != retry_task)
    GNUNET_SCHEDULER_cancel (retry_task);
  retry_task = GNUNET_SCHEDULER_add_now (&transmit_next_request_task, NULL);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Closure for 'find_by_unique_id'.
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
 * @param value the 'struct ClientQueryRecord'
 * @return GNUNET_YES to continue iteration (result not yet found)
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
 * Handler for "GET result seen" messages from the client.
 *
 * @param cls closure for the service
 * @param client the client we received this message from
 * @param message the actual message received
 */
static void
handle_dht_local_get_result_seen (void *cls, struct GNUNET_SERVER_Client *client,
				  const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_DHT_ClientGetResultSeenMessage *seen;
  uint16_t size;
  unsigned int hash_count;
  unsigned int old_count;
  const struct GNUNET_HashCode *hc;
  struct FindByUniqueIdContext fui_ctx;
  struct ClientQueryRecord *cqr;

  size = ntohs (message->size);
  if (size < sizeof (struct GNUNET_DHT_ClientGetResultSeenMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  seen = (const struct GNUNET_DHT_ClientGetResultSeenMessage *) message;
  hash_count = (size - sizeof (struct GNUNET_DHT_ClientGetResultSeenMessage)) / sizeof (struct GNUNET_HashCode);
  if (size != sizeof (struct GNUNET_DHT_ClientGetResultSeenMessage) + hash_count * sizeof (struct GNUNET_HashCode))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
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
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  /* finally, update 'seen' list */
  old_count = cqr->seen_replies_count;
  GNUNET_array_grow (cqr->seen_replies,
		     cqr->seen_replies_count,
		     cqr->seen_replies_count + hash_count);
  memcpy (&cqr->seen_replies[old_count],
	  hc,
	  sizeof (struct GNUNET_HashCode) * hash_count);
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
remove_by_unique_id (void *cls, const struct GNUNET_HashCode * key, void *value)
{
  const struct RemoveByUniqueIdContext *ctx = cls;
  struct ClientQueryRecord *record = value;

  if (record->unique_id != ctx->unique_id)
    return GNUNET_YES;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Removing client %p's record for key %s (by unique id)\n",
              ctx->client->client_handle, GNUNET_h2s (key));
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
                            gettext_noop
                            ("# GET STOP requests received from clients"), 1,
                            GNUNET_NO);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received GET STOP request for %s from local client %p\n",
       client, GNUNET_h2s (&dht_stop_msg->key));
  ctx.client = find_active_client (client);
  ctx.unique_id = dht_stop_msg->unique_id;
  GNUNET_CONTAINER_multihashmap_get_multiple (forward_map, &dht_stop_msg->key,
                                              &remove_by_unique_id, &ctx);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handler for monitor start messages
 *
 * @param cls closure for the service
 * @param client the client we received this message from
 * @param message the actual message received
 *
 */
static void
handle_dht_local_monitor (void *cls, struct GNUNET_SERVER_Client *client,
                          const struct GNUNET_MessageHeader *message)
{
  struct ClientMonitorRecord *r;
  const struct GNUNET_DHT_MonitorStartStopMessage *msg;

  msg = (struct GNUNET_DHT_MonitorStartStopMessage *) message;
  r = GNUNET_new (struct ClientMonitorRecord);

  r->client = find_active_client(client);
  r->type = ntohl(msg->type);
  r->get = ntohs(msg->get);
  r->get_resp = ntohs(msg->get_resp);
  r->put = ntohs(msg->put);
  if (0 == ntohs(msg->filter_key))
      r->key = NULL;
  else
  {
    r->key = GNUNET_new (struct GNUNET_HashCode);
    memcpy (r->key, &msg->key, sizeof (struct GNUNET_HashCode));
  }
  GNUNET_CONTAINER_DLL_insert (monitor_head, monitor_tail, r);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handler for monitor stop messages
 *
 * @param cls closure for the service
 * @param client the client we received this message from
 * @param message the actual message received
 *
 */
static void
handle_dht_local_monitor_stop (void *cls, struct GNUNET_SERVER_Client *client,
                               const struct GNUNET_MessageHeader *message)
{
  struct ClientMonitorRecord *r;
  const struct GNUNET_DHT_MonitorStartStopMessage *msg;
  int keys_match;

  msg = (struct GNUNET_DHT_MonitorStartStopMessage *) message;
  r = monitor_head;

  while (NULL != r)
  {
    if (NULL == r->key)
        keys_match = (0 == ntohs(msg->filter_key));
    else
    {
        keys_match = (0 != ntohs(msg->filter_key)
                      && !memcmp(r->key, &msg->key, sizeof(struct GNUNET_HashCode)));
    }
    if (find_active_client(client) == r->client
        && ntohl(msg->type) == r->type
        && r->get == msg->get
        && r->get_resp == msg->get_resp
        && r->put == msg->put
        && keys_match
        )
    {
        GNUNET_CONTAINER_DLL_remove (monitor_head, monitor_tail, r);
        GNUNET_free_non_null (r->key);
        GNUNET_free (r);
        GNUNET_SERVER_receive_done (client, GNUNET_OK);
        return; /* Delete only ONE entry */
    }
    r = r->next;
  }

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


#if ENABLE_MALICIOUS
/**
 * Handler for monitor stop messages
 *
 * @param cls closure for the service
 * @param client the client we received this message from
 * @param message the actual message received
 *
 */
static void
handle_dht_act_malicious (void *cls, struct GNUNET_SERVER_Client *client,
                          const struct GNUNET_MessageHeader *message)
{
  /* FIXME: parse message and set malicious */
  malicious = 1;
}
#endif


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
  struct ClientMonitorRecord *monitor;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Local client %p disconnects\n",
	      client);
  pos = find_active_client (client);
  GNUNET_CONTAINER_DLL_remove (client_head, client_tail, pos);
  if (pos->transmit_handle != NULL)
    GNUNET_SERVER_notify_transmit_ready_cancel (pos->transmit_handle);
  while (NULL != (reply = pos->pending_head))
  {
    GNUNET_CONTAINER_DLL_remove (pos->pending_head, pos->pending_tail, reply);
    GNUNET_free (reply);
  }
  monitor = monitor_head;
  while (NULL != monitor)
  {
    if (monitor->client == pos)
    {
      struct ClientMonitorRecord *next;

      GNUNET_free_non_null (monitor->key);
      next = monitor->next;
      GNUNET_CONTAINER_DLL_remove (monitor_head, monitor_tail, monitor);
      GNUNET_free (monitor);
      monitor = next;
    }
    else
      monitor = monitor->next;
  }
  GNUNET_CONTAINER_multihashmap_iterate (forward_map, &remove_client_records,
                                         pos);
  GNUNET_free (pos);
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
     sizeof (struct GNUNET_DHT_ClientGetStopMessage)},
    {&handle_dht_local_monitor, NULL,
     GNUNET_MESSAGE_TYPE_DHT_MONITOR_START,
     sizeof (struct GNUNET_DHT_MonitorStartStopMessage)},
    {&handle_dht_local_monitor_stop, NULL,
     GNUNET_MESSAGE_TYPE_DHT_MONITOR_STOP,
     sizeof (struct GNUNET_DHT_MonitorStartStopMessage)},
    {&handle_dht_local_get_result_seen, NULL,
     GNUNET_MESSAGE_TYPE_DHT_CLIENT_GET_RESULTS_KNOWN, 0},
    #if ENABLE_MALICIOUS
    {&handle_dht_act_malicious, NULL,
     GNUNET_MESSAGE_TYPE_DHT_ACT_MALICIOUS,
     sizeof (struct GNUNET_DHT_ActMaliciousMessage)},
    #endif
    {NULL, NULL, 0, 0}
  };
  forward_map = GNUNET_CONTAINER_multihashmap_create (1024, GNUNET_NO);
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
