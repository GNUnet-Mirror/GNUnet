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
#include "gnunet_bandwidth_lib.h"
#include "gnunet_client_lib.h"
#include "gnunet_constants.h"
#include "gnunet_container_lib.h"
#include "gnunet_arm_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_server_lib.h"
#include "gnunet_time_lib.h"
#include "gnunet_dht_service.h"
#include "dht.h"

#define DEBUG_DHT_API GNUNET_NO

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
 * Handle to a route request
 */
struct GNUNET_DHT_RouteHandle
{

  /**
   * Iterator to call on data receipt
   */
  GNUNET_DHT_ReplyProcessor iter;

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
   * Unique identifier for this request (for key collisions). FIXME: redundant!?
   */
  uint64_t uid;

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

};


/**
 * Transmit the next pending message, called by notify_transmit_ready
 */
static size_t
transmit_pending (void *cls, size_t size, void *buf);


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
  handle->client = GNUNET_CLIENT_connect ("dht", handle->cfg);
  if (handle->client == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failed to connect to the DHT service!\n"));
    return GNUNET_NO;
  }
#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting to process replies from DHT\n");
#endif
  GNUNET_CLIENT_receive (handle->client, &service_message_handler, handle,
                         GNUNET_TIME_UNIT_FOREVER_REL);
  return GNUNET_YES;
}


/**
 * Add the request corresponding to the given route handle
 * to the pending queue (if it is not already in there).
 *
 * @param cls the 'struct GNUNET_DHT_Handle*'
 * @param key key for the request (not used)
 * @param value the 'struct GNUNET_DHT_RouteHandle*'
 * @return GNUNET_YES (always)
 */
static int
add_request_to_pending (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct GNUNET_DHT_Handle *handle = cls;
  struct GNUNET_DHT_RouteHandle *rh = value;

  if (GNUNET_NO == rh->message->in_pending_queue)
  {
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

  handle->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  if (handle->retry_time.rel_value < GNUNET_CONSTANTS_SERVICE_RETRY.rel_value)
    handle->retry_time = GNUNET_CONSTANTS_SERVICE_RETRY;
  else
    handle->retry_time = GNUNET_TIME_relative_multiply (handle->retry_time, 2);
  if (handle->retry_time.rel_value > GNUNET_CONSTANTS_SERVICE_TIMEOUT.rel_value)
    handle->retry_time = GNUNET_CONSTANTS_SERVICE_TIMEOUT;
  handle->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  handle->client = GNUNET_CLIENT_connect ("dht", handle->cfg);
  if (handle->client == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "dht reconnect failed(!)\n");
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
  GNUNET_CLIENT_disconnect (handle->client, GNUNET_NO);
  handle->client = NULL;
  handle->reconnect_task =
      GNUNET_SCHEDULER_add_delayed (handle->retry_time, &try_reconnect, handle);
}


/**
 * Try to send messages from list of messages to send
 */
static void
process_pending_messages (struct GNUNET_DHT_Handle *handle)
{
  struct PendingMessage *head;

  if (handle->client == NULL)
  {
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
  if (NULL == handle->th)
  {
    do_disconnect (handle);
    return;
  }
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
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
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
  if (head->timeout_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (head->timeout_task);
    head->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != head->cont)
  {
    GNUNET_SCHEDULER_add_continuation (head->cont, head->cont_cls,
                                       GNUNET_SCHEDULER_REASON_PREREQ_DONE);
    head->cont = NULL;
    head->cont_cls = NULL;
  }
  head->in_pending_queue = GNUNET_NO;
  if (GNUNET_YES == head->free_on_send)
    GNUNET_free (head);
  process_pending_messages (handle);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Forwarded request of %u bytes to DHT service\n",
              (unsigned int) tsize);
  return tsize;
}


/**
 * Process a given reply that might match the given
 * request.
 */
static int
process_reply (void *cls, const GNUNET_HashCode * key, void *value)
{
  const struct GNUNET_DHT_RouteResultMessage *dht_msg = cls;
  struct GNUNET_DHT_RouteHandle *rh = value;
  const struct GNUNET_MessageHeader *enc_msg;
  size_t enc_size;
  uint64_t uid;
  const struct GNUNET_PeerIdentity **outgoing_path;
  const struct GNUNET_PeerIdentity *pos;
  uint32_t outgoing_path_length;
  unsigned int i;
  char *path_offset;

  uid = GNUNET_ntohll (dht_msg->unique_id);
  if (uid != rh->uid)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Reply UID did not match request UID\n");
    return GNUNET_YES;
  }
  enc_msg = (const struct GNUNET_MessageHeader *) &dht_msg[1];
  enc_size = ntohs (enc_msg->size);
  if (enc_size < sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break (0);
    return GNUNET_NO;
  }
  path_offset = (char *) &dht_msg[1];
  path_offset += enc_size;
  pos = (const struct GNUNET_PeerIdentity *) path_offset;
  outgoing_path_length = ntohl (dht_msg->outgoing_path_length);
  if (outgoing_path_length * sizeof (struct GNUNET_PeerIdentity) >
      ntohs (dht_msg->header.size) - enc_size)
  {
    GNUNET_break (0);
    return GNUNET_NO;
  }

  if (outgoing_path_length > 0)
  {
    outgoing_path =
        GNUNET_malloc ((outgoing_path_length +
                        1) * sizeof (struct GNUNET_PeerIdentity *));
    for (i = 0; i < outgoing_path_length; i++)
    {
      outgoing_path[i] = pos;
      pos++;
    }
    outgoing_path[outgoing_path_length] = NULL;
  }
  else
    outgoing_path = NULL;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Processing reply.\n");
  rh->iter (rh->iter_cls, &rh->key, outgoing_path, enc_msg);
  GNUNET_free_non_null (outgoing_path);
  return GNUNET_YES;
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
  const struct GNUNET_DHT_RouteResultMessage *dht_msg;

  if (msg == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Error receiving data from DHT service, reconnecting\n");
    do_disconnect (handle);
    return;
  }
  if (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_DHT_LOCAL_ROUTE_RESULT)
  {
    GNUNET_break (0);
    do_disconnect (handle);
    return;
  }
  if (ntohs (msg->size) < sizeof (struct GNUNET_DHT_RouteResultMessage))
  {
    GNUNET_break (0);
    do_disconnect (handle);
    return;
  }
  dht_msg = (const struct GNUNET_DHT_RouteResultMessage *) msg;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Comparing reply `%s' against %u pending requests.\n",
              GNUNET_h2s (&dht_msg->key),
              GNUNET_CONTAINER_multihashmap_size (handle->active_requests));
  GNUNET_CONTAINER_multihashmap_get_multiple (handle->active_requests,
                                              &dht_msg->key, &process_reply,
                                              (void *) dht_msg);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Continuing to process replies from DHT\n");
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
    GNUNET_CONTAINER_DLL_remove (handle->pending_head, handle->pending_tail,
                                 pm);
    GNUNET_assert (GNUNET_YES == pm->free_on_send);
    if (GNUNET_SCHEDULER_NO_TASK != pm->timeout_task)
      GNUNET_SCHEDULER_cancel (pm->timeout_task);
    if (NULL != pm->cont)
      GNUNET_SCHEDULER_add_continuation (pm->cont, pm->cont_cls,
                                         GNUNET_SCHEDULER_REASON_TIMEOUT);
    pm->in_pending_queue = GNUNET_NO;
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




/* ***** Special low-level API providing generic routing abstraction ***** */


/**
 * Timeout for the transmission of a fire&forget-request.  Clean it up.
 *
 * @param cls the 'struct PendingMessage'
 * @param tc scheduler context
 */
static void
timeout_route_request (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PendingMessage *pending = cls;
  struct GNUNET_DHT_Handle *handle;

  if (pending->free_on_send != GNUNET_YES)
  {
    /* timeouts should only apply to fire & forget requests! */
    GNUNET_break (0);
    return;
  }
  handle = pending->handle;
  GNUNET_CONTAINER_DLL_remove (handle->pending_head, handle->pending_tail,
                               pending);
  if (pending->cont != NULL)
    pending->cont (pending->cont_cls, tc);
  GNUNET_free (pending);
}


/**
 * Initiate a generic DHT route operation.
 *
 * @param handle handle to the DHT service
 * @param key the key to look up
 * @param desired_replication_level how many peers should ultimately receive
 *                this message (advisory only, target may be too high for the
 *                given DHT or not hit exactly).
 * @param options options for routing
 * @param enc send the encapsulated message to a peer close to the key
 * @param iter function to call on each result, NULL if no replies are expected
 * @param iter_cls closure for iter
 * @param timeout when to abort with an error if we fail to get
 *                a confirmation for the request (when necessary) or how long
 *                to wait for tramission to the service; only applies
 *                if 'iter' is NULL
 * @param cont continuation to call when the request has been transmitted
 *             the first time to the service
 * @param cont_cls closure for cont
 * @return handle to stop the request, NULL if the request is "fire and forget"
 */
struct GNUNET_DHT_RouteHandle *
GNUNET_DHT_route_start (struct GNUNET_DHT_Handle *handle,
                        const GNUNET_HashCode * key,
                        uint32_t desired_replication_level,
                        enum GNUNET_DHT_RouteOption options,
                        const struct GNUNET_MessageHeader *enc,
                        struct GNUNET_TIME_Relative timeout,
                        GNUNET_DHT_ReplyProcessor iter, void *iter_cls,
                        GNUNET_SCHEDULER_Task cont, void *cont_cls)
{
  struct PendingMessage *pending;
  struct GNUNET_DHT_RouteMessage *message;
  struct GNUNET_DHT_RouteHandle *route_handle;
  uint16_t msize;
  uint16_t esize;

  esize = ntohs (enc->size);
  if (sizeof (struct GNUNET_DHT_RouteMessage) + esize >=
      GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return NULL;
  }
  msize = sizeof (struct GNUNET_DHT_RouteMessage) + esize;
  pending = GNUNET_malloc (sizeof (struct PendingMessage) + msize);
  message = (struct GNUNET_DHT_RouteMessage *) &pending[1];
  pending->msg = &message->header;
  pending->handle = handle;
  pending->cont = cont;
  pending->cont_cls = cont_cls;

  message->header.size = htons (msize);
  message->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_LOCAL_ROUTE);
  message->options = htonl ((uint32_t) options);
  message->desired_replication_level = htonl (desired_replication_level);
  message->reserved = 0;
  message->key = *key;
  handle->uid_gen++;
  message->unique_id = GNUNET_htonll (handle->uid_gen);
  memcpy (&message[1], enc, esize);

  if (iter != NULL)
  {
    route_handle = GNUNET_malloc (sizeof (struct GNUNET_DHT_RouteHandle));
    route_handle->key = *key;
    route_handle->iter = iter;
    route_handle->iter_cls = iter_cls;
    route_handle->dht_handle = handle;
    route_handle->uid = handle->uid_gen;
    route_handle->message = pending;
    GNUNET_CONTAINER_multihashmap_put (handle->active_requests, key,
                                       route_handle,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  }
  else
  {
    route_handle = NULL;
    pending->free_on_send = GNUNET_YES;
    pending->timeout_task =
        GNUNET_SCHEDULER_add_delayed (timeout, &timeout_route_request, pending);
  }
  GNUNET_CONTAINER_DLL_insert (handle->pending_head, handle->pending_tail,
                               pending);
  pending->in_pending_queue = GNUNET_YES;
  process_pending_messages (handle);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "DHT route start request processed, returning %p\n",
              route_handle);
  return route_handle;
}


/**
 * Stop a previously issued routing request
 *
 * @param route_handle handle to the request to stop
 */
void
GNUNET_DHT_route_stop (struct GNUNET_DHT_RouteHandle *route_handle)
{
  struct GNUNET_DHT_Handle *handle;
  struct PendingMessage *pending;
  struct GNUNET_DHT_StopMessage *message;
  size_t msize;

  handle = route_handle->dht_handle;
  if (GNUNET_NO == route_handle->message->in_pending_queue)
  {
    /* need to send stop message */
    msize = sizeof (struct GNUNET_DHT_StopMessage);
    pending = GNUNET_malloc (sizeof (struct PendingMessage) + msize);
    message = (struct GNUNET_DHT_StopMessage *) &pending[1];
    pending->msg = &message->header;
    message->header.size = htons (msize);
    message->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_LOCAL_ROUTE_STOP);
    message->reserved = 0;
    message->unique_id = GNUNET_htonll (route_handle->uid);
    message->key = route_handle->key;
    pending->handle = handle;
    pending->free_on_send = GNUNET_YES;
    pending->in_pending_queue = GNUNET_YES;
    GNUNET_CONTAINER_DLL_insert (handle->pending_head, handle->pending_tail,
                                 pending);
    process_pending_messages (handle);
  }
  else
  {
    /* simply remove pending request from message queue before
     * transmission, no need to transmit STOP request! */
    GNUNET_CONTAINER_DLL_remove (handle->pending_head, handle->pending_tail,
                                 route_handle->message);
  }
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove
                 (route_handle->dht_handle->active_requests, &route_handle->key,
                  route_handle));
  GNUNET_free (route_handle->message);
  GNUNET_free (route_handle);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "DHT route stop request processed\n");
}



/* ***** Special API for controlling DHT routing maintenance ******* */


/**
 * Send a control message to the DHT.
 *
 * @param handle handle to the DHT service
 * @param command command
 * @param variable variable to the command
 * @param cont continuation to call when done (transmitting request to service)
 * @param cont_cls closure for cont
 */
static void
send_control_message (struct GNUNET_DHT_Handle *handle, uint16_t command,
                      uint16_t variable, GNUNET_SCHEDULER_Task cont,
                      void *cont_cls)
{
  struct GNUNET_DHT_ControlMessage *msg;
  struct PendingMessage *pending;

  pending =
      GNUNET_malloc (sizeof (struct PendingMessage) +
                     sizeof (struct GNUNET_DHT_ControlMessage));
  msg = (struct GNUNET_DHT_ControlMessage *) &pending[1];
  pending->msg = &msg->header;
  msg->header.size = htons (sizeof (struct GNUNET_DHT_ControlMessage));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_CONTROL);
  msg->command = htons (command);
  msg->variable = htons (variable);
  pending->free_on_send = GNUNET_YES;
  pending->cont = cont;
  pending->cont_cls = cont_cls;
  pending->in_pending_queue = GNUNET_YES;
  GNUNET_CONTAINER_DLL_insert (handle->pending_head, handle->pending_tail,
                               pending);
  process_pending_messages (handle);
}


/**
 * Send a message to the DHT telling it to issue a single find
 * peer request using the peers unique identifier as key.  This
 * is used to fill the routing table, and is normally controlled
 * by the DHT itself.  However, for testing and perhaps more
 * close control over the DHT, this can be explicitly managed.
 *
 * @param handle handle to the DHT service
 * @param cont continuation to call when done (transmitting request to service)
 * @param cont_cls closure for cont
 */
void
GNUNET_DHT_find_peers (struct GNUNET_DHT_Handle *handle,
                       GNUNET_SCHEDULER_Task cont, void *cont_cls)
{
  send_control_message (handle, GNUNET_MESSAGE_TYPE_DHT_FIND_PEER, 0, cont,
                        cont_cls);
}



#if HAVE_MALICIOUS

/**
 * Send a message to the DHT telling it to start issuing random GET
 * requests every 'frequency' milliseconds.
 *
 * @param handle handle to the DHT service
 * @param frequency delay between sending malicious messages
 * @param cont continuation to call when done (transmitting request to service)
 * @param cont_cls closure for cont
 */
void
GNUNET_DHT_set_malicious_getter (struct GNUNET_DHT_Handle *handle,
                                 struct GNUNET_TIME_Relative frequency,
                                 GNUNET_SCHEDULER_Task cont, void *cont_cls)
{
  if (frequency.rel_value > UINT16_MAX)
  {
    GNUNET_break (0);
    return;
  }
  send_control_message (handle, GNUNET_MESSAGE_TYPE_DHT_MALICIOUS_GET,
                        frequency.rel_value, cont, cont_cls);
}

/**
 * Send a message to the DHT telling it to start issuing random PUT
 * requests every 'frequency' milliseconds.
 *
 * @param handle handle to the DHT service
 * @param frequency delay between sending malicious messages
 * @param cont continuation to call when done (transmitting request to service)
 * @param cont_cls closure for cont
 */
void
GNUNET_DHT_set_malicious_putter (struct GNUNET_DHT_Handle *handle,
                                 struct GNUNET_TIME_Relative frequency,
                                 GNUNET_SCHEDULER_Task cont, void *cont_cls)
{
  if (frequency.rel_value > UINT16_MAX)
  {
    GNUNET_break (0);
    return;
  }

  send_control_message (handle, GNUNET_MESSAGE_TYPE_DHT_MALICIOUS_PUT,
                        frequency.rel_value, cont, cont_cls);
}


/**
 * Send a message to the DHT telling it to start dropping
 * all requests received.
 *
 * @param handle handle to the DHT service
 * @param cont continuation to call when done (transmitting request to service)
 * @param cont_cls closure for cont
 *
 */
void
GNUNET_DHT_set_malicious_dropper (struct GNUNET_DHT_Handle *handle,
                                  GNUNET_SCHEDULER_Task cont, void *cont_cls)
{
  send_control_message (handle, GNUNET_MESSAGE_TYPE_DHT_MALICIOUS_DROP, 0, cont,
                        cont_cls);
}

#endif

/* end of dht_api.c */
