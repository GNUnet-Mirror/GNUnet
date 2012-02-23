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
 * TODO: Do we really need a client API?
 *
 * @file gns/gns_api.c
 * @brief library to access the GNS service
 * @author Martin Schanzenbach
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_arm_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_dht_service.h"
#include "gns.h"
#include "gnunet_gns_service.h"

#define DEBUG_GNS_API GNUNET_EXTRA_LOGGING

#define LOG(kind,...) GNUNET_log_from (kind, "gns-api",__VA_ARGS__)

/* TODO into gnunet_protocols */
#define GNUNET_MESSAGE_TYPE_GNS_CLIENT_LOOKUP 23
#define GNUNET_MESSAGE_TYPE_GNS_CLIENT_RESULT 24

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
   * Handle to the GNS API context.
   */
  struct GNUNET_GNS_Handle *handle;

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
 * Handle to a Lookup request
 */
struct GNUNET_GNS_LookupHandle
{

  /**
   * Iterator to call on data receipt
   */
  GNUNET_GNS_LookupIterator iter;

  /**
   * Closure for the iterator callback
   */
  void *iter_cls;

  /**
   * Main handle to this GNS api
   */
  struct GNUNET_GNS_Handle *gns_handle;

  /**
   * Key that this get request is for
   */
  GNUNET_HashCode key;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint64_t unique_id;

  struct PendingMessage *message;

};

/**
 * Connection to the GNS service.
 */
struct GNUNET_GNS_Handle
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
   * Hash map containing the current outstanding unique requests.
   */
  struct GNUNET_CONTAINER_MultiHashMap *active_requests;

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
 * Try to send messages from list of messages to send
 * @param handle GNS_Handle
 */
static void
process_pending_messages (struct GNUNET_GNS_Handle *handle);

/**
 * Try to (re)connect to the GNS service.
 *
 * @return GNUNET_YES on success, GNUNET_NO on failure.
 */
static int
try_connect (struct GNUNET_GNS_Handle *handle)
{
  if (handle->client != NULL)
    return GNUNET_OK;
  handle->in_receive = GNUNET_NO;
  handle->client = GNUNET_CLIENT_connect ("gns", handle->cfg);
  if (handle->client == NULL)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("Failed to connect to the GNS service!\n"));
    return GNUNET_NO;
  }
  return GNUNET_YES;
}

/**
 * Add the request corresponding to the given handle
 * to the pending queue (if it is not already in there).
 *
 * @param cls the 'struct GNUNET_GNS_Handle*'
 * @param key key for the request (not used)
 * @param value the 'struct GNUNET_GNS_LookupHandle*'
 * @return GNUNET_YES (always)
 */
static int
add_request_to_pending (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct GNUNET_GNS_Handle *handle = cls;
  struct GNUNET_GNS_LookupHandle *rh = value;

  if (GNUNET_NO == rh->message->in_pending_queue)
  {
#if DEBUG_DHT
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Retransmitting request related to %s to GNS %p\n", GNUNET_h2s(key),
         handle);
#endif
    GNUNET_CONTAINER_DLL_insert (handle->pending_head, handle->pending_tail,
                                 rh->message);
    rh->message->in_pending_queue = GNUNET_YES;
  }
  return GNUNET_YES;
}

/**
 * Try reconnecting to the GNS service.
 *
 * @param cls GNUNET_GNS_Handle
 * @param tc scheduler context
 */
static void
try_reconnect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_GNS_Handle *handle = cls;

#if DEBUG_GNS
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Reconnecting with GNS %p\n", handle);
#endif
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
#if DEBUG_GNS
    LOG (GNUNET_ERROR_TYPE_DEBUG, "GNS reconnect failed(!)\n");
#endif
    return;
  }
  GNUNET_CONTAINER_multihashmap_iterate (handle->active_requests,
                                         &add_request_to_pending, handle);
  process_pending_messages (handle);
}


/**
 * Try reconnecting to the GNS service.
 *
 * @param handle handle to gns to (possibly) disconnect and reconnect
 */
static void
do_disconnect (struct GNUNET_GNS_Handle *handle)
{
  if (handle->client == NULL)
    return;
  GNUNET_assert (handle->reconnect_task == GNUNET_SCHEDULER_NO_TASK);
  if (NULL != handle->th)
    GNUNET_CLIENT_notify_transmit_ready_cancel (handle->th);
  handle->th = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Disconnecting from GNS service, will try to reconnect in %llu ms\n",
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
 * Handler for messages received from the GNS service
 *
 * @param cls the 'struct GNUNET_GNS_Handle'
 * @param msg the incoming message
 */
static void
message_handler (void *cls, const struct GNUNET_MessageHeader *msg);

/**
 * Try to send messages from list of messages to send
 */
static void
process_pending_messages (struct GNUNET_GNS_Handle *handle)
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
  struct GNUNET_GNS_Handle *handle = cls;
  struct PendingMessage *head;
  size_t tsize;

  handle->th = NULL;
  if (buf == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
         "Transmission to GNS service failed!  Reconnecting!\n");
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
  if (GNUNET_YES == head->free_on_send)
    GNUNET_free (head);
  process_pending_messages (handle);
#if DEBUG_GNS
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Forwarded request of %u bytes to GNS service\n", (unsigned int) tsize);
#endif
  if (GNUNET_NO == handle->in_receive)
  {
#if DEBUG_GNS
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Starting to process replies from GNS\n");
#endif
    handle->in_receive = GNUNET_YES;
    GNUNET_CLIENT_receive (handle->client, &message_handler, handle,
                           GNUNET_TIME_UNIT_FOREVER_REL);
  }
  return tsize;
}

/**
 * Process a given reply that might match the given
 * request.
 *
 * @param cls the 'struct GNUNET_GNS_ClientResultMessage'
 * @param key query of the request
 * @param value the 'struct GNUNET_GNS_LookupHandle' of a request matching the same key
 * @return GNUNET_YES to continue to iterate over all results,
 *         GNUNET_NO if the reply is malformed
 */
static int
process_reply (void *cls, const GNUNET_HashCode * key, void *value)
{
  const struct GNUNET_GNS_ClientResultMessage *gns_msg = cls;
  struct GNUNET_GNS_LookupHandle *lookup_handle = value;
  const char *name = (const char*) &lookup_handle[1];
  const struct GNUNET_NAMESTORE_RecordData *records;
  uint32_t num_records;
  size_t meta_length;
  size_t msize;

  if (gns_msg->unique_id != lookup_handle->unique_id)
  {
    /* UID mismatch */
#if DEBUG_GNS
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Ignoring reply for %s: UID mismatch: %llu/%llu\n", GNUNET_h2s (key),
         gns_msg->unique_id, lookup_handle->unique_id);
#endif
    return GNUNET_YES;
  }
  msize = ntohs (gns_msg->header.size);
  num_records = ntohl (gns_msg->num_records);
  meta_length =
    sizeof (struct GNUNET_GNS_ClientResultMessage) +
    sizeof (struct GNUNET_NAMESTORE_RecordData) * (num_records);
  if ((msize < meta_length) ||
      (num_records >
       GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_NAMESTORE_RecordData)))
  {
    GNUNET_break (0);
    return GNUNET_NO;
  }
#if DEBUG_GNS
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Giving %u byte reply for %s to application\n",
       (unsigned int) (msize - meta_length), GNUNET_h2s (key));
#endif
  records = (const struct GNUNET_NAMESTORE_RecordData *) &gns_msg[1];
  lookup_handle->iter (lookup_handle->iter_cls, name, records, num_records);
  return GNUNET_YES;
}


/**
 * Handler for messages received from the GNS service
 *
 * @param cls the 'struct GNUNET_GNS_Handle'
 * @param msg the incoming message
 */
static void
message_handler (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_GNS_Handle *handle = cls;
  const struct GNUNET_GNS_ClientResultMessage *gns_msg;

  if (msg == NULL)
  {
#if DEBUG_GNS
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Error receiving data from GNS service, reconnecting\n");
#endif
    do_disconnect (handle);
    return;
  }
  if (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_GNS_CLIENT_RESULT)
  {
    GNUNET_break (0);
    do_disconnect (handle);
    return;
  }
  if (ntohs (msg->size) < sizeof (struct GNUNET_GNS_ClientResultMessage))
  {
    GNUNET_break (0);
    do_disconnect (handle);
    return;
  }
  gns_msg = (const struct GNUNET_GNS_ClientResultMessage *) msg;
#if DEBUG_GNS
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Received reply for `%s' from GNS service %p\n",
       &gns_msg->name, handle);
#endif
  /* TODO uniquely identify requests... maybe hash(name) or uid */
  GNUNET_CONTAINER_multihashmap_get_multiple (handle->active_requests,
                                              &gns_msg->key, &process_reply,
                                              (void *) gns_msg);
  GNUNET_CLIENT_receive (handle->client, &message_handler, handle,
                         GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Initialize the connection with the GNS service.
 *
 * @param cfg configuration to use
 * @param ht_len size of the internal hash table to use for parallel requests
 * @return handle to the GNS service, or NULL on error
 */
struct GNUNET_GNS_Handle *
GNUNET_GNS_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                    unsigned int ht_len)
{
  struct GNUNET_GNS_Handle *handle;

  handle = GNUNET_malloc (sizeof (struct GNUNET_GNS_Handle));
  handle->cfg = cfg;
  handle->uid_gen =
      GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK, UINT64_MAX);
  handle->active_requests = GNUNET_CONTAINER_multihashmap_create (ht_len);
  if (GNUNET_NO == try_connect (handle))
  {
    GNUNET_GNS_disconnect (handle);
    return NULL;
  }
  return handle;
}


/**
 * Shutdown connection with the GNS service.
 *
 * @param handle handle of the GNS connection to stop
 */
void
GNUNET_GNS_disconnect (struct GNUNET_GNS_Handle *handle)
{
  /* disco from GNS */
}


/**
 * Perform an asynchronous Lookup operation on the GNS.
 * TODO:
 *    - Still not sure what we query for... "names" it is for now
 *    - Do we need such sophisticated message queueing like dht? simplify?
 *
 * @param handle handle to the GNS service
 * @param timeout how long to wait for transmission of this request to the service
 * @param name the name to look up
 * @param iter function to call on each result
 * @param iter_cls closure for iter
 * @return handle to stop the async get
 */
struct GNUNET_GNS_LookupHandle *
GNUNET_GNS_lookup_start (struct GNUNET_GNS_Handle *handle,
                         struct GNUNET_TIME_Relative timeout,
                         const char * name,
                         enum GNUNET_GNS_RecordType type,
                         GNUNET_GNS_LookupIterator iter,
                         void *iter_cls)
{
  /* IPC to look for local entries, start dht lookup, return lookup_handle */
  struct GNUNET_GNS_ClientLookupMessage *lookup_msg;
  struct GNUNET_GNS_LookupHandle *lookup_handle;
  GNUNET_HashCode key;
  size_t msize;
  struct PendingMessage *pending;

  if (NULL == name)
  {
    return NULL;
  }

  GNUNET_CRYPTO_hash (name, strlen(name), &key);

  msize = sizeof (struct GNUNET_GNS_ClientLookupMessage) + strlen(name);
#if DEBUG_GNS
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Starting lookup for %s in GNS %p\n",
       name, handle);
#endif
  pending = GNUNET_malloc (sizeof (struct PendingMessage) + msize);
  lookup_msg = (struct GNUNET_GNS_ClientLookupMessage *) &pending[1];
  pending->msg = &lookup_msg->header;
  pending->handle = handle;
  pending->free_on_send = GNUNET_NO;
  lookup_msg->header.size = htons (msize);
  lookup_msg->header.type = htons (GNUNET_MESSAGE_TYPE_GNS_CLIENT_LOOKUP);
  lookup_msg->key = key;
  memcpy(&lookup_msg[1], name, strlen(name));
  handle->uid_gen++;
  lookup_msg->unique_id = handle->uid_gen;
  GNUNET_CONTAINER_DLL_insert (handle->pending_head, handle->pending_tail,
                               pending);
  pending->in_pending_queue = GNUNET_YES;
  lookup_handle = GNUNET_malloc (sizeof (struct GNUNET_GNS_LookupHandle));
  lookup_handle->iter = iter;
  lookup_handle->iter_cls = iter_cls;
  lookup_handle->message = pending;
  lookup_handle->unique_id = lookup_msg->unique_id;
  GNUNET_CONTAINER_multihashmap_put (handle->active_requests, &lookup_msg->key,
                                     lookup_handle,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  process_pending_messages (handle);
  return lookup_handle;
}


/**
 * Stop async GNS lookup.
 *
 * @param lookup_handle handle to the GNS lookup operation to stop
 */
void
GNUNET_GNS_lookup_stop (struct GNUNET_GNS_LookupHandle *lookup_handle)
{
  /* TODO Stop dht lookups */
}


/* end of gns_api.c */
