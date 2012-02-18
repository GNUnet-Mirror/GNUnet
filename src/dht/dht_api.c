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
 * @file dht/dht_api.c
 * @brief library to access the DHT service
 * @author Christian Grothoff
 * @author Nathan Evans
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_arm_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_dht_service.h"
#include "dht.h"

#define LOG(kind,...) GNUNET_log_from (kind, "dht-api",__VA_ARGS__)

/**
 * Entry in our list of messages to be (re-)transmitted.
 */
struct PendingMessage
{
  /**
   * This is a doubly-linked list.
   */
  struct PendingMessage *prev;

  /**
   * This is a doubly-linked list.
   */
  struct PendingMessage *next;

  /**
   * Message that is pending, allocated at the end
   * of this struct.
   */
  const struct GNUNET_MessageHeader *msg;

  /**
   * Handle to the DHT API context.
   */
  struct GNUNET_DHT_Handle *handle;

  /**
   * Continuation to call when the request has been
   * transmitted (for the first time) to the service; can be NULL.
   */
  GNUNET_SCHEDULER_Task cont;

  /**
   * Closure for 'cont'.
   */
  void *cont_cls;

  /**
   * Timeout task for this message
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * Unique ID for this request
   */
  uint64_t unique_id;

  /**
   * Free the saved message once sent, set to GNUNET_YES for messages
   * that do not receive responses; GNUNET_NO if this pending message
   * is aliased from a 'struct GNUNET_DHT_RouteHandle' and will be freed
   * from there.
   */
  int free_on_send;

  /**
   * GNUNET_YES if this message is in our pending queue right now.
   */
  int in_pending_queue;

};


/**
 * Handle to a GET request
 */
struct GNUNET_DHT_GetHandle
{

  /**
   * Iterator to call on data receipt
   */
  GNUNET_DHT_GetIterator iter;

  /**
   * Closure for the iterator callback
   */
  void *iter_cls;

  /**
   * Main handle to this DHT api
   */
  struct GNUNET_DHT_Handle *dht_handle;

  /**
   * The actual message sent for this request,
   * used for retransmitting requests on service
   * failure/reconnect.  Freed on route_stop.
   */
  struct PendingMessage *message;

  /**
   * Key that this get request is for
   */
  GNUNET_HashCode key;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint64_t unique_id;

};


/**
 * Handle to a monitoring request.
 */
struct GNUNET_DHT_MonitorHandle
{
  /**
   * DLL.
   */
  struct GNUNET_DHT_MonitorHandle *next;

  /**
   * DLL.
   */
  struct GNUNET_DHT_MonitorHandle *prev;
  
  /**
   * Main handle to this DHT api.
   */
  struct GNUNET_DHT_Handle *dht_handle;

  /**
   * Type of block looked for.
   */
  enum GNUNET_BLOCK_Type type;

  /**
   * Key being looked for, NULL == all.
   */
  GNUNET_HashCode *key;

  /**
   * Callback for each received message of interest.
   */
  GNUNET_DHT_MonitorCB cb;

  /**
   * Closure for cb.
   */
  void *cb_cls;
  
};


/**
 * Connection to the DHT service.
 */
struct GNUNET_DHT_Handle
{

  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Socket (if available).
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Currently pending transmission request (or NULL).
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * Head of linked list of messages we would like to transmit.
   */
  struct PendingMessage *pending_head;

  /**
   * Tail of linked list of messages we would like to transmit.
   */
  struct PendingMessage *pending_tail;

  /**
   * Head of linked list of messages we would like to monitor. 
   */
  struct GNUNET_DHT_MonitorHandle *monitor_head;

  /**
   * Tail of linked list of messages we would like to monitor.
   */
  struct GNUNET_DHT_MonitorHandle *monitor_tail;

  /**
   * Hash map containing the current outstanding unique requests
   * (values are of type 'struct GNUNET_DHT_RouteHandle').
   */
  struct GNUNET_CONTAINER_MultiHashMap *active_requests;

  /**
   * Task for trying to reconnect.
   */
  GNUNET_SCHEDULER_TaskIdentifier reconnect_task;

  /**
   * How quickly should we retry?  Used for exponential back-off on
   * connect-errors.
   */
  struct GNUNET_TIME_Relative retry_time;

  /**
   * Generator for unique ids.
   */
  uint64_t uid_gen;

  /**
   * Did we start our receive loop yet?
   */
  int in_receive;
};


/**
 * Handler for messages received from the DHT service
 * a demultiplexer which handles numerous message types
 *
 */
static void
service_message_handler (void *cls, const struct GNUNET_MessageHeader *msg);


/**
 * Try to (re)connect to the DHT service.
 *
 * @return GNUNET_YES on success, GNUNET_NO on failure.
 */
static int
try_connect (struct GNUNET_DHT_Handle *handle)
{
  if (handle->client != NULL)
    return GNUNET_OK;
  handle->in_receive = GNUNET_NO;
  handle->client = GNUNET_CLIENT_connect ("dht", handle->cfg);
  if (handle->client == NULL)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("Failed to connect to the DHT service!\n"));
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Add the request corresponding to the given route handle
 * to the pending queue (if it is not already in there).
 *
 * @param cls the 'struct GNUNET_DHT_Handle*'
 * @param key key for the request (not used)
 * @param value the 'struct GNUNET_DHT_GetHandle*'
 * @return GNUNET_YES (always)
 */
static int
add_request_to_pending (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct GNUNET_DHT_Handle *handle = cls;
  struct GNUNET_DHT_GetHandle *rh = value;

  if (GNUNET_NO == rh->message->in_pending_queue)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Retransmitting request related to %s to DHT %p\n", GNUNET_h2s (key),
         handle);
    GNUNET_CONTAINER_DLL_insert (handle->pending_head, handle->pending_tail,
                                 rh->message);
    rh->message->in_pending_queue = GNUNET_YES;
  }
  return GNUNET_YES;
}


/**
 * Try to send messages from list of messages to send
 * @param handle DHT_Handle
 */
static void
process_pending_messages (struct GNUNET_DHT_Handle *handle);


/**
 * Try reconnecting to the dht service.
 *
 * @param cls GNUNET_DHT_Handle
 * @param tc scheduler context
 */
static void
try_reconnect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_DHT_Handle *handle = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Reconnecting with DHT %p\n", handle);
  handle->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  if (handle->retry_time.rel_value < GNUNET_CONSTANTS_SERVICE_RETRY.rel_value)
    handle->retry_time = GNUNET_CONSTANTS_SERVICE_RETRY;
  else
    handle->retry_time = GNUNET_TIME_relative_multiply (handle->retry_time, 2);
  if (handle->retry_time.rel_value > GNUNET_CONSTANTS_SERVICE_TIMEOUT.rel_value)
    handle->retry_time = GNUNET_CONSTANTS_SERVICE_TIMEOUT;
  handle->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  if (GNUNET_YES != try_connect (handle))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "dht reconnect failed(!)\n");
    return;
  }
  GNUNET_CONTAINER_multihashmap_iterate (handle->active_requests,
                                         &add_request_to_pending, handle);
  process_pending_messages (handle);
}


/**
 * Try reconnecting to the DHT service.
 *
 * @param handle handle to dht to (possibly) disconnect and reconnect
 */
static void
do_disconnect (struct GNUNET_DHT_Handle *handle)
{
  if (handle->client == NULL)
    return;
  GNUNET_assert (handle->reconnect_task == GNUNET_SCHEDULER_NO_TASK);
  if (NULL != handle->th)
    GNUNET_CLIENT_notify_transmit_ready_cancel (handle->th);
  handle->th = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Disconnecting from DHT service, will try to reconnect in %llu ms\n",
              (unsigned long long) handle->retry_time.rel_value);
  GNUNET_CLIENT_disconnect (handle->client, GNUNET_NO);
  handle->client = NULL;
  handle->reconnect_task =
      GNUNET_SCHEDULER_add_delayed (handle->retry_time, &try_reconnect, handle);
}


/**
 * Transmit the next pending message, called by notify_transmit_ready
 */
static size_t
transmit_pending (void *cls, size_t size, void *buf);


/**
 * Try to send messages from list of messages to send
 */
static void
process_pending_messages (struct GNUNET_DHT_Handle *handle)
{
  struct PendingMessage *head;

  if (handle->client == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "process_pending_messages called, but client is null, reconnecting\n");
    do_disconnect (handle);
    return;
  }
  if (handle->th != NULL)
    return;
  if (NULL == (head = handle->pending_head))
    return;
  handle->th =
      GNUNET_CLIENT_notify_transmit_ready (handle->client,
                                           ntohs (head->msg->size),
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           GNUNET_YES, &transmit_pending,
                                           handle);
  if (NULL != handle->th)
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "notify_transmit_ready returned NULL, reconnecting\n");
  do_disconnect (handle);
}


/**
 * Transmit the next pending message, called by notify_transmit_ready
 */
static size_t
transmit_pending (void *cls, size_t size, void *buf)
{
  struct GNUNET_DHT_Handle *handle = cls;
  struct PendingMessage *head;
  size_t tsize;

  handle->th = NULL;
  if (buf == NULL)
  {    
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Transmission to DHT service failed!  Reconnecting!\n");
    do_disconnect (handle);
    return 0;
  }
  if (NULL == (head = handle->pending_head))
    return 0;

  tsize = ntohs (head->msg->size);
  if (size < tsize)
  {
    process_pending_messages (handle);
    return 0;
  }
  memcpy (buf, head->msg, tsize);
  GNUNET_CONTAINER_DLL_remove (handle->pending_head, handle->pending_tail,
                               head);
  head->in_pending_queue = GNUNET_NO;
  if (head->timeout_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (head->timeout_task);
    head->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != head->cont)
  {
    head->cont (head->cont_cls, NULL);
    head->cont = NULL;
    head->cont_cls = NULL;
  }
  if (GNUNET_YES == head->free_on_send)
    GNUNET_free (head);
  process_pending_messages (handle);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Forwarded request of %u bytes to DHT service\n", (unsigned int) tsize);
  if (GNUNET_NO == handle->in_receive)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Starting to process replies from DHT\n");
    handle->in_receive = GNUNET_YES;
    GNUNET_CLIENT_receive (handle->client, &service_message_handler, handle,
                           GNUNET_TIME_UNIT_FOREVER_REL);
  }
  return tsize;
}


/**
 * Process a given reply that might match the given
 * request.
 *
 * @param cls the 'struct GNUNET_DHT_ClientResultMessage'
 * @param key query of the request
 * @param value the 'struct GNUNET_DHT_RouteHandle' of a request matching the same key
 * @return GNUNET_YES to continue to iterate over all results,
 *         GNUNET_NO if the reply is malformed
 */
static int
process_reply (void *cls, const GNUNET_HashCode * key, void *value)
{
  const struct GNUNET_DHT_ClientResultMessage *dht_msg = cls;
  struct GNUNET_DHT_GetHandle *get_handle = value;
  const struct GNUNET_PeerIdentity *put_path;
  const struct GNUNET_PeerIdentity *get_path;
  uint32_t put_path_length;
  uint32_t get_path_length;
  size_t data_length;
  size_t msize;
  size_t meta_length;
  const void *data;

  if (dht_msg->unique_id != get_handle->unique_id)
  {
    /* UID mismatch */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Ignoring reply for %s: UID mismatch: %llu/%llu\n", GNUNET_h2s (key),
         dht_msg->unique_id, get_handle->unique_id);
    return GNUNET_YES;
  }
  msize = ntohs (dht_msg->header.size);
  put_path_length = ntohl (dht_msg->put_path_length);
  get_path_length = ntohl (dht_msg->get_path_length);
  meta_length =
      sizeof (struct GNUNET_DHT_ClientResultMessage) +
      sizeof (struct GNUNET_PeerIdentity) * (get_path_length + put_path_length);
  if ((msize < meta_length) ||
      (get_path_length >
       GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)) ||
      (put_path_length >
       GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break (0);
    return GNUNET_NO;
  }
  data_length = msize - meta_length;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Giving %u byte reply for %s to application\n",
       (unsigned int) data_length, GNUNET_h2s (key));
  put_path = (const struct GNUNET_PeerIdentity *) &dht_msg[1];
  get_path = &put_path[put_path_length];
  data = &get_path[get_path_length];
  get_handle->iter (get_handle->iter_cls,
                    GNUNET_TIME_absolute_ntoh (dht_msg->expiration), key,
                    get_path, get_path_length, put_path, put_path_length,
                    ntohl (dht_msg->type), data_length, data);
  return GNUNET_YES;
}


/**
 * Process a monitoring message from the service.
 *
 * @param handle The DHT handle.
 * @param msg Message from the service.
 * 
 * @return GNUNET_OK if everything went fine,
 *         GNUNET_SYSERR if the message is malformed.
 */
static int
process_monitor_message (struct GNUNET_DHT_Handle *handle,
                         const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_DHT_MonitorMessage *m;
  struct GNUNET_DHT_MonitorHandle *h;
  size_t msize;

  if (ntohs (msg->type) < GNUNET_MESSAGE_TYPE_DHT_MONITOR_GET ||
      ntohs (msg->type) > GNUNET_MESSAGE_TYPE_DHT_MONITOR_PUT)
    return GNUNET_SYSERR;
  msize = ntohs (msg->size);
  if (msize < sizeof (struct GNUNET_DHT_MonitorMessage))
    return GNUNET_SYSERR;

  m = (struct GNUNET_DHT_MonitorMessage *) msg;
  h = handle->monitor_head;
  while (NULL != h)
  {
    if (h->type == ntohl(m->type) &&
      (NULL == h->key ||
       memcmp (h->key, &m->key, sizeof (GNUNET_HashCode)) == 0))
    {
      struct GNUNET_PeerIdentity *path;
      uint32_t getl;
      uint32_t putl;

      path = (struct GNUNET_PeerIdentity *) &m[1];
      getl = ntohl (m->get_path_length);
      putl = ntohl (m->put_path_length);
      h->cb (h->cb_cls, ntohs(msg->type),
             GNUNET_TIME_absolute_ntoh(m->expiration),
             &m->key,
             &path[getl], putl, path, getl,
             ntohl (m->desired_replication_level),
             ntohl (m->options), ntohl (m->type),
             (void *) &path[getl + putl],
             ntohs (msg->size) -
             sizeof (struct GNUNET_DHT_MonitorMessage) -
             sizeof (struct GNUNET_PeerIdentity) * (putl + getl));
    }
    h = h->next;
  }

  return GNUNET_OK;
}

/**
 * Handler for messages received from the DHT service
 * a demultiplexer which handles numerous message types
 *
 * @param cls the 'struct GNUNET_DHT_Handle'
 * @param msg the incoming message
 */
static void
service_message_handler (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_DHT_Handle *handle = cls;
  const struct GNUNET_DHT_ClientResultMessage *dht_msg;

  if (msg == NULL)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Error receiving data from DHT service, reconnecting\n");
    do_disconnect (handle);
    return;
  }
  if (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_DHT_CLIENT_RESULT)
  {
    if (process_monitor_message (handle, msg) == GNUNET_OK)
    {
      GNUNET_CLIENT_receive (handle->client, &service_message_handler, handle,
                             GNUNET_TIME_UNIT_FOREVER_REL);
      return;
    }
    GNUNET_break (0);
    do_disconnect (handle);
    return;
  }
  if (ntohs (msg->size) < sizeof (struct GNUNET_DHT_ClientResultMessage))
  {
    GNUNET_break (0);
    do_disconnect (handle);
    return;
  }
  dht_msg = (const struct GNUNET_DHT_ClientResultMessage *) msg;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Received reply for `%s' from DHT service %p\n",
       GNUNET_h2s (&dht_msg->key), handle);
  GNUNET_CONTAINER_multihashmap_get_multiple (handle->active_requests,
                                              &dht_msg->key, &process_reply,
                                              (void *) dht_msg);
  GNUNET_CLIENT_receive (handle->client, &service_message_handler, handle,
                         GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Initialize the connection with the DHT service.
 *
 * @param cfg configuration to use
 * @param ht_len size of the internal hash table to use for
 *               processing multiple GET/FIND requests in parallel
 *
 * @return handle to the DHT service, or NULL on error
 */
struct GNUNET_DHT_Handle *
GNUNET_DHT_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                    unsigned int ht_len)
{
  struct GNUNET_DHT_Handle *handle;

  handle = GNUNET_malloc (sizeof (struct GNUNET_DHT_Handle));
  handle->cfg = cfg;
  handle->uid_gen =
      GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK, UINT64_MAX);
  handle->active_requests = GNUNET_CONTAINER_multihashmap_create (ht_len);
  if (GNUNET_NO == try_connect (handle))
  {
    GNUNET_DHT_disconnect (handle);
    return NULL;
  }
  return handle;
}


/**
 * Shutdown connection with the DHT service.
 *
 * @param handle handle of the DHT connection to stop
 */
void
GNUNET_DHT_disconnect (struct GNUNET_DHT_Handle *handle)
{
  struct PendingMessage *pm;

  GNUNET_assert (handle != NULL);
  GNUNET_assert (0 ==
                 GNUNET_CONTAINER_multihashmap_size (handle->active_requests));
  if (handle->th != NULL)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (handle->th);
    handle->th = NULL;
  }
  while (NULL != (pm = handle->pending_head))
  {
    GNUNET_assert (GNUNET_YES == pm->in_pending_queue);
    GNUNET_CONTAINER_DLL_remove (handle->pending_head, handle->pending_tail,
                                 pm);
    pm->in_pending_queue = GNUNET_NO;
    GNUNET_assert (GNUNET_YES == pm->free_on_send);
    if (GNUNET_SCHEDULER_NO_TASK != pm->timeout_task)
      GNUNET_SCHEDULER_cancel (pm->timeout_task);
    if (NULL != pm->cont)
      pm->cont (pm->cont_cls, NULL);
    GNUNET_free (pm);
  }
  if (handle->client != NULL)
  {
    GNUNET_CLIENT_disconnect (handle->client, GNUNET_YES);
    handle->client = NULL;
  }
  if (handle->reconnect_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (handle->reconnect_task);
  GNUNET_CONTAINER_multihashmap_destroy (handle->active_requests);
  GNUNET_free (handle);
}


/**
 * Timeout for the transmission of a fire&forget-request.  Clean it up.
 *
 * @param cls the 'struct PendingMessage'
 * @param tc scheduler context
 */
static void
timeout_put_request (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PendingMessage *pending = cls;
  struct GNUNET_DHT_Handle *handle;

  handle = pending->handle;
  GNUNET_assert (GNUNET_YES == pending->in_pending_queue);
  GNUNET_CONTAINER_DLL_remove (handle->pending_head, handle->pending_tail,
                               pending);
  pending->in_pending_queue = GNUNET_NO;
  if (pending->cont != NULL)
    pending->cont (pending->cont_cls, tc);
  GNUNET_free (pending);
}


/**
 * Perform a PUT operation storing data in the DHT.
 *
 * @param handle handle to DHT service
 * @param key the key to store under
 * @param desired_replication_level estimate of how many
 *                nearest peers this request should reach
 * @param options routing options for this message
 * @param type type of the value
 * @param size number of bytes in data; must be less than 64k
 * @param data the data to store
 * @param exp desired expiration time for the value
 * @param timeout how long to wait for transmission of this request
 * @param cont continuation to call when done (transmitting request to service)
 * @param cont_cls closure for cont
 */
void
GNUNET_DHT_put (struct GNUNET_DHT_Handle *handle, const GNUNET_HashCode * key,
                uint32_t desired_replication_level,
                enum GNUNET_DHT_RouteOption options,
                enum GNUNET_BLOCK_Type type, size_t size, const char *data,
                struct GNUNET_TIME_Absolute exp,
                struct GNUNET_TIME_Relative timeout, GNUNET_SCHEDULER_Task cont,
                void *cont_cls)
{
  struct GNUNET_DHT_ClientPutMessage *put_msg;
  size_t msize;
  struct PendingMessage *pending;

  msize = sizeof (struct GNUNET_DHT_ClientPutMessage) + size;
  if ((msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE) ||
      (size >= GNUNET_SERVER_MAX_MESSAGE_SIZE))
  {
    GNUNET_break (0);
    if (NULL != cont)
      cont (cont_cls, NULL);
    return;
  }
  pending = GNUNET_malloc (sizeof (struct PendingMessage) + msize);
  put_msg = (struct GNUNET_DHT_ClientPutMessage *) &pending[1];
  pending->msg = &put_msg->header;
  pending->handle = handle;
  pending->cont = cont;
  pending->cont_cls = cont_cls;
  pending->free_on_send = GNUNET_YES;
  pending->timeout_task =
      GNUNET_SCHEDULER_add_delayed (timeout, &timeout_put_request, pending);
  put_msg->header.size = htons (msize);
  put_msg->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_CLIENT_PUT);
  put_msg->type = htonl (type);
  put_msg->options = htonl ((uint32_t) options);
  put_msg->desired_replication_level = htonl (desired_replication_level);
  put_msg->expiration = GNUNET_TIME_absolute_hton (exp);
  put_msg->key = *key;
  memcpy (&put_msg[1], data, size);
  GNUNET_CONTAINER_DLL_insert (handle->pending_head, handle->pending_tail,
                               pending);
  pending->in_pending_queue = GNUNET_YES;
  process_pending_messages (handle);
}


/**
 * Perform an asynchronous GET operation on the DHT identified. See
 * also "GNUNET_BLOCK_evaluate".
 *
 * @param handle handle to the DHT service
 * @param timeout how long to wait for transmission of this request to the service
 * @param type expected type of the response object
 * @param key the key to look up
 * @param desired_replication_level estimate of how many
                  nearest peers this request should reach
 * @param options routing options for this message
 * @param xquery extended query data (can be NULL, depending on type)
 * @param xquery_size number of bytes in xquery
 * @param iter function to call on each result
 * @param iter_cls closure for iter
 * @return handle to stop the async get
 */
struct GNUNET_DHT_GetHandle *
GNUNET_DHT_get_start (struct GNUNET_DHT_Handle *handle,
                      struct GNUNET_TIME_Relative timeout,
                      enum GNUNET_BLOCK_Type type, const GNUNET_HashCode * key,
                      uint32_t desired_replication_level,
                      enum GNUNET_DHT_RouteOption options, const void *xquery,
                      size_t xquery_size, GNUNET_DHT_GetIterator iter,
                      void *iter_cls)
{
  struct GNUNET_DHT_ClientGetMessage *get_msg;
  struct GNUNET_DHT_GetHandle *get_handle;
  size_t msize;
  struct PendingMessage *pending;

  msize = sizeof (struct GNUNET_DHT_ClientGetMessage) + xquery_size;
  if ((msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE) ||
      (xquery_size >= GNUNET_SERVER_MAX_MESSAGE_SIZE))
  {
    GNUNET_break (0);
    return NULL;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Sending query for %s to DHT %p\n",
       GNUNET_h2s (key), handle);
  pending = GNUNET_malloc (sizeof (struct PendingMessage) + msize);
  get_msg = (struct GNUNET_DHT_ClientGetMessage *) &pending[1];
  pending->msg = &get_msg->header;
  pending->handle = handle;
  pending->free_on_send = GNUNET_NO;
  get_msg->header.size = htons (msize);
  get_msg->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_CLIENT_GET);
  get_msg->options = htonl ((uint32_t) options);
  get_msg->desired_replication_level = htonl (desired_replication_level);
  get_msg->type = htonl (type);
  get_msg->key = *key;
  handle->uid_gen++;
  get_msg->unique_id = handle->uid_gen;
  memcpy (&get_msg[1], xquery, xquery_size);
  GNUNET_CONTAINER_DLL_insert (handle->pending_head, handle->pending_tail,
                               pending);
  pending->in_pending_queue = GNUNET_YES;
  get_handle = GNUNET_malloc (sizeof (struct GNUNET_DHT_GetHandle));
  get_handle->iter = iter;
  get_handle->iter_cls = iter_cls;
  get_handle->message = pending;
  get_handle->unique_id = get_msg->unique_id;
  GNUNET_CONTAINER_multihashmap_put (handle->active_requests, key, get_handle,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  process_pending_messages (handle);
  return get_handle;
}


/**
 * Stop async DHT-get.
 *
 * @param get_handle handle to the GET operation to stop
 */
void
GNUNET_DHT_get_stop (struct GNUNET_DHT_GetHandle *get_handle)
{
  struct GNUNET_DHT_Handle *handle;
  const struct GNUNET_DHT_ClientGetMessage *get_msg;
  struct GNUNET_DHT_ClientGetStopMessage *stop_msg;
  struct PendingMessage *pending;

  handle = get_handle->message->handle;
  get_msg =
      (const struct GNUNET_DHT_ClientGetMessage *) get_handle->message->msg;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Sending STOP for %s to DHT via %p\n",
       GNUNET_h2s (&get_msg->key), handle);
  /* generate STOP */
  pending =
      GNUNET_malloc (sizeof (struct PendingMessage) +
                     sizeof (struct GNUNET_DHT_ClientGetStopMessage));
  stop_msg = (struct GNUNET_DHT_ClientGetStopMessage *) &pending[1];
  pending->msg = &stop_msg->header;
  pending->handle = handle;
  pending->free_on_send = GNUNET_YES;
  stop_msg->header.size =
      htons (sizeof (struct GNUNET_DHT_ClientGetStopMessage));
  stop_msg->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_CLIENT_GET_STOP);
  stop_msg->reserved = htonl (0);
  stop_msg->unique_id = get_msg->unique_id;
  stop_msg->key = get_msg->key;
  GNUNET_CONTAINER_DLL_insert (handle->pending_head, handle->pending_tail,
                               pending);
  pending->in_pending_queue = GNUNET_YES;

  /* remove 'GET' from active status */
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (handle->active_requests,
                                                       &get_msg->key,
                                                       get_handle));
  if (GNUNET_YES == get_handle->message->in_pending_queue)
  {
    GNUNET_CONTAINER_DLL_remove (handle->pending_head, handle->pending_tail,
                                 get_handle->message);
    get_handle->message->in_pending_queue = GNUNET_NO;
  }
  GNUNET_free (get_handle->message);
  GNUNET_free (get_handle);

  process_pending_messages (handle);
}


/**
 * Start monitoring the local DHT service.
 *
 * @param handle Handle to the DHT service.
 * @param type Type of blocks that are of interest.
 * @param key Key of data of interest, NULL for all.
 * @param cb Callback to process all monitored data.
 * @param cb_cls Closure for cb.
 *
 * @return Handle to stop monitoring.
 */
struct GNUNET_DHT_MonitorHandle *
GNUNET_DHT_monitor_start (struct GNUNET_DHT_Handle *handle,
                          enum GNUNET_BLOCK_Type type,
                          const GNUNET_HashCode *key,
                          GNUNET_DHT_MonitorCB cb,
                          void *cb_cls)
{
  struct GNUNET_DHT_MonitorHandle *h;
  struct GNUNET_DHT_MonitorMessage *m;
  struct PendingMessage *pending;

  h = GNUNET_malloc (sizeof (struct GNUNET_DHT_MonitorHandle));
  GNUNET_CONTAINER_DLL_insert(handle->monitor_head, handle->monitor_tail, h);

  GNUNET_assert (NULL != cb);
  h->cb = cb;
  h->cb_cls = cb_cls;
  h->type = type;
  h->dht_handle = handle;
  if (NULL != key)
  {
    h->key = GNUNET_malloc (sizeof(GNUNET_HashCode));
    memcpy (h->key, key, sizeof(GNUNET_HashCode));
  }

  pending = GNUNET_malloc (sizeof (struct GNUNET_DHT_MonitorMessage) +
                           sizeof (struct PendingMessage));
  m = (struct GNUNET_DHT_MonitorMessage *) &pending[1];
  pending->msg = &m->header;
  pending->handle = handle;
  pending->free_on_send = GNUNET_YES;
  m->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_MONITOR_GET);
  m->header.size = htons (sizeof (struct GNUNET_DHT_MonitorMessage));
  m->type = htonl(type);
  if (NULL != key)
    memcpy (&m->key, key, sizeof(GNUNET_HashCode));
  GNUNET_CONTAINER_DLL_insert (handle->pending_head, handle->pending_tail,
                               pending);
  pending->in_pending_queue = GNUNET_YES;
  process_pending_messages (handle);

  return h;
}


/**
 * Stop monitoring.
 *
 * @param handle The handle to the monitor request returned by monitor_start.
 *
 * On return get_handle will no longer be valid, caller must not use again!!!
 */
void
GNUNET_DHT_monitor_stop (struct GNUNET_DHT_MonitorHandle *handle)
{
  GNUNET_free_non_null (handle->key);
  GNUNET_CONTAINER_DLL_remove (handle->dht_handle->monitor_head,
                               handle->dht_handle->monitor_tail,
                               handle);
  GNUNET_free (handle);
}



/* end of dht_api.c */
