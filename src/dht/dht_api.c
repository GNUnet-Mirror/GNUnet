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
 *
 * TODO: retransmission of pending requests maybe happens now, at least
 *       the code is in place to do so.  Need to add checks when api calls
 *       happen to check if retransmission is in progress, and if so set
 *       the single pending message for transmission once the list of
 *       retries are done.
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

struct PendingMessage
{
  /**
   * Message that is pending
   */
  struct GNUNET_MessageHeader *msg;

  /**
   * Timeout for this message
   */
  struct GNUNET_TIME_Relative timeout;

  /**
   * Continuation to call on message send
   * or message receipt confirmation
   */
  GNUNET_SCHEDULER_Task cont;

  /**
   * Continuation closure
   */
  void *cont_cls;

  /**
   * Unique ID for this request
   */
  uint64_t unique_id;

  /**
   * Free the saved message once sent, set
   * to GNUNET_YES for messages that don't
   * receive responses!
   */
  int free_on_send;

};

struct PendingMessageList
{
  /**
   * This is a singly linked list.
   */
  struct PendingMessageList *next;

  /**
   * The pending message.
   */
  struct PendingMessage *message;
};

struct GNUNET_DHT_GetContext
{
  /**
   * Iterator to call on data receipt
   */
  GNUNET_DHT_GetIterator iter;

  /**
   * Closure for the iterator callback
   */
  void *iter_cls;

};

struct GNUNET_DHT_FindPeerContext
{
  /**
   * Iterator to call on data receipt
   */
  GNUNET_DHT_FindPeerProcessor proc;

  /**
   * Closure for the iterator callback
   */
  void *proc_cls;

};

/**
 * Handle to a route request
 */
struct GNUNET_DHT_RouteHandle
{

  /**
   * Unique identifier for this request (for key collisions)
   */
  uint64_t uid;

  /**
   * Key that this get request is for
   */
  GNUNET_HashCode key;

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
  struct GNUNET_DHT_RouteMessage *message;
};


/**
 * Handle to control a get operation.
 */
struct GNUNET_DHT_GetHandle
{
  /**
   * Handle to the actual route operation for the get
   */
  struct GNUNET_DHT_RouteHandle *route_handle;

  /**
   * The context of the get request
   */
  struct GNUNET_DHT_GetContext get_context;
};


/**
 * Handle to control a find peer operation.
 */
struct GNUNET_DHT_FindPeerHandle
{
  /**
     * Handle to the actual route operation for the request
     */
  struct GNUNET_DHT_RouteHandle *route_handle;

    /**
     * The context of the find peer request
     */
  struct GNUNET_DHT_FindPeerContext find_peer_context;
};


enum DHT_Retransmit_Stage
{
  /**
   * The API is not retransmitting anything at this time.
   */
  DHT_NOT_RETRANSMITTING,

  /**
   * The API is retransmitting, and nothing has been single
   * queued for sending.
   */
  DHT_RETRANSMITTING,

  /**
   * The API is retransmitting, and a single message has been
   * queued for transmission once finished.
   */
  DHT_RETRANSMITTING_MESSAGE_QUEUED
};


/**
 * Connection to the DHT service.
 */
struct GNUNET_DHT_Handle
{
  /**
   * Our scheduler.
   */
  struct GNUNET_SCHEDULER_Handle *sched;

  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Socket (if available).
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Currently pending transmission request.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * Message we are currently sending, only allow
   * a single message to be queued.  If not unique
   * (typically a put request), await a confirmation
   * from the service that the message was received.
   * If unique, just fire and forget.
   */
  struct PendingMessage *current;

  /**
   * Hash map containing the current outstanding unique requests
   */
  struct GNUNET_CONTAINER_MultiHashMap *outstanding_requests;

  /**
   * Generator for unique ids.
   */
  uint64_t uid_gen;

  /**
   * Are we currently retransmitting requests?  If so queue a _single_
   * new request when received.
   */
  enum DHT_Retransmit_Stage retransmit_stage;

  /**
   * Linked list of retranmissions, to be used in the event
   * of a dht service disconnect/reconnect.
   */
  struct PendingMessageList *retransmissions;

  /**
   * A single pending message allowed to be scheduled
   * during retransmission phase.
   */
  struct PendingMessage *retransmission_buffer;
};


/**
 * Convert unique ID to hash code.
 *
 * @param uid unique ID to convert
 * @param hash set to uid (extended with zeros)
 */
static void
hash_from_uid (uint64_t uid,
	       GNUNET_HashCode *hash)
{
  memset (hash, 0, sizeof(GNUNET_HashCode));
  *((uint64_t*)hash) = uid;
}

#if RETRANSMIT
/**
 * Iterator callback to retransmit each outstanding request
 * because the connection to the DHT service went down (and
 * came back).
 *
 *
 */
static int retransmit_iterator (void *cls,
                                const GNUNET_HashCode * key,
                                void *value)
{
  struct GNUNET_DHT_RouteHandle *route_handle = value;
  struct PendingMessageList *pending_message_list;

  pending_message_list = GNUNET_malloc(sizeof(struct PendingMessageList) + sizeof(struct PendingMessage));
  pending_message_list->message = (struct PendingMessage *)&pending_message_list[1];
  pending_message_list->message->msg = &route_handle->message->header;
  pending_message_list->message->timeout = GNUNET_TIME_relative_get_forever();
  pending_message_list->message->cont = NULL;
  pending_message_list->message->cont_cls = NULL;
  pending_message_list->message->unique_id = route_handle->uid;
  /* Add the new pending message to the front of the retransmission list */
  pending_message_list->next = route_handle->dht_handle->retransmissions;
  route_handle->dht_handle->retransmissions = pending_message_list;

  return GNUNET_OK;
}
#endif

/**
 * Try to (re)connect to the dht service.
 *
 * @return GNUNET_YES on success, GNUNET_NO on failure.
 */
static int
try_connect (struct GNUNET_DHT_Handle *handle)
{
  if (handle->client != NULL)
    return GNUNET_OK;
  handle->client = GNUNET_CLIENT_connect (handle->sched, "dht", handle->cfg);
  if (handle->client != NULL)
    return GNUNET_YES;
#if DEBUG_STATISTICS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _("Failed to connect to the dht service!\n"));
#endif
  return GNUNET_NO;
}

/**
 * Send complete (or failed), call continuation if we have one.
 */
static void
finish (struct GNUNET_DHT_Handle *handle, int code)
{
  struct PendingMessage *pos = handle->current;
  GNUNET_HashCode uid_hash;
#if DEBUG_DHT_API
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "`%s': Finish called!\n", "DHT API");
#endif
  GNUNET_assert (pos != NULL);
  hash_from_uid (pos->unique_id, &uid_hash);
  if (pos->cont != NULL)
    {
      if (code == GNUNET_SYSERR)
        GNUNET_SCHEDULER_add_continuation (handle->sched, pos->cont,
                                           pos->cont_cls,
                                           GNUNET_SCHEDULER_REASON_TIMEOUT);
      else
        GNUNET_SCHEDULER_add_continuation (handle->sched, pos->cont,
                                           pos->cont_cls,
                                           GNUNET_SCHEDULER_REASON_PREREQ_DONE);
    }

  GNUNET_assert(handle->th == NULL);
  if (pos->free_on_send == GNUNET_YES)
    GNUNET_free(pos->msg);
  GNUNET_free (pos);
  handle->current = NULL;
}

/**
 * Transmit the next pending message, called by notify_transmit_ready
 */
static size_t
transmit_pending (void *cls, size_t size, void *buf)
{
  struct GNUNET_DHT_Handle *handle = cls;
  size_t tsize;

#if DEBUG_DHT_API
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': In transmit_pending\n", "DHT API");
#endif
  handle->th = NULL;

  if (buf == NULL)
    {
#if DEBUG_DHT_API
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "`%s': In transmit_pending buf is NULL\n", "DHT API");
#endif
      finish (handle, GNUNET_SYSERR);
      return 0;
    }

  if (handle->current != NULL)
    {
      tsize = ntohs (handle->current->msg->size);
      if (size >= tsize)
        {
#if DEBUG_DHT_API
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "`%s': Sending message size %d\n", "DHT API", tsize);
#endif
          memcpy (buf, handle->current->msg, tsize);
          finish (handle, GNUNET_OK);
          return tsize;
        }
      else
        {
          return 0;
        }
    }
  /* Have no pending request */
  return 0;
}

/**
 * Try to send messages from list of messages to send
 */
static void
process_pending_message (struct GNUNET_DHT_Handle *handle)
{

  if (handle->current == NULL)
    return;                     /* action already pending */
  if (GNUNET_YES != try_connect (handle))
    {
      handle->th = NULL;
      finish (handle, GNUNET_SYSERR);
      return;
    }

  if (NULL ==
      (handle->th = GNUNET_CLIENT_notify_transmit_ready (handle->client,
                                                         ntohs (handle->
                                                                current->msg->
                                                                size),
                                                         handle->current->
                                                         timeout, GNUNET_YES,
                                                         &transmit_pending,
                                                         handle)))
    {
#if DEBUG_DHT_API
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Failed to transmit request to dht service.\n");
#endif
      finish (handle, GNUNET_SYSERR);
      return;
    }
#if DEBUG_DHT_API
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Scheduled sending message of size %d to service\n",
              "DHT API", ntohs (handle->current->msg->size));
#endif
}

/**
 * Send complete (or failed), call continuation if we have one.
 * Forward declaration.
 */
static void
finish_retransmission (struct GNUNET_DHT_Handle *handle, int code);

/* Forward declaration */
static size_t
transmit_pending_retransmission (void *cls, size_t size, void *buf);

/**
 * Try to send messages from list of messages to send
 */
static void
process_pending_retransmissions (struct GNUNET_DHT_Handle *handle)
{

  if (handle->current == NULL)
    return;                     /* action already pending */
  if (GNUNET_YES != try_connect (handle))
    {
      finish_retransmission (handle, GNUNET_SYSERR);
      return;
    }

  if (NULL ==
      (handle->th = GNUNET_CLIENT_notify_transmit_ready (handle->client,
                                                         ntohs (handle->
                                                                current->msg->
                                                                size),
                                                         handle->current->
                                                         timeout, GNUNET_YES,
                                                         &transmit_pending_retransmission,
                                                         handle)))
    {
#if DEBUG_DHT_API
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Failed to transmit request to dht service.\n");
#endif
      finish_retransmission (handle, GNUNET_SYSERR);
      return;
    }
#if DEBUG_DHT_API
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Scheduled sending message of size %d to service\n",
              "DHT API", ntohs (handle->current->msg->size));
#endif
}

/**
 * Send complete (or failed), call continuation if we have one.
 */
static void
finish_retransmission (struct GNUNET_DHT_Handle *handle, int code)
{
  struct PendingMessage *pos = handle->current;
  struct PendingMessageList *pending_list;
#if DEBUG_DHT_API
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "`%s': Finish (retransmission) called!\n", "DHT API");
#endif
  GNUNET_assert (pos == handle->retransmissions->message);
  pending_list = handle->retransmissions;
  handle->retransmissions = handle->retransmissions->next;
  GNUNET_free (pending_list);

  if (handle->retransmissions == NULL)
    {
      handle->retransmit_stage = DHT_NOT_RETRANSMITTING;
    }

  if (handle->retransmissions != NULL)
    {
      handle->current = handle->retransmissions->message;
      process_pending_retransmissions(handle);
    }
  else if (handle->retransmission_buffer != NULL)
    {
      handle->current = handle->retransmission_buffer;
      process_pending_message(handle);
    }
}

/**
 * Handler for messages received from the DHT service
 * a demultiplexer which handles numerous message types
 *
 */
void
service_message_handler (void *cls,
                         const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_DHT_Handle *handle = cls;
  struct GNUNET_DHT_RouteResultMessage *dht_msg;
  struct GNUNET_MessageHeader *enc_msg;
  struct GNUNET_DHT_RouteHandle *route_handle;
  uint64_t uid;
  GNUNET_HashCode uid_hash;
  size_t enc_size;

  if (msg == NULL)
    {
#if DEBUG_DHT_API
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "`%s': Received NULL from server, connection down!\n",
                  "DHT API");
#endif
      GNUNET_CLIENT_disconnect (handle->client, GNUNET_YES);
      handle->client = GNUNET_CLIENT_connect (handle->sched, 
                                              "dht",
                                              handle->cfg);
      if (handle->current != NULL)
        {
          handle->th = NULL;
          finish(handle, GNUNET_SYSERR); /* If there was a current message, kill it! */
        }
#if RETRANSMIT
      if ((handle->retransmit_stage != DHT_RETRANSMITTING) && (GNUNET_CONTAINER_multihashmap_iterate(handle->outstanding_requests, &retransmit_iterator, handle) > 0))
        {
          handle->retransmit_stage = DHT_RETRANSMITTING;
          handle->current = handle->retransmissions->message;
          process_pending_retransmissions(handle);
        }
#endif
      return;
    }

  switch (ntohs (msg->type))
    {
    case GNUNET_MESSAGE_TYPE_DHT_LOCAL_ROUTE_RESULT:
      {
        dht_msg = (struct GNUNET_DHT_RouteResultMessage *) msg;
        uid = GNUNET_ntohll (dht_msg->unique_id);
#if DEBUG_DHT_API
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "`%s': Received response to message (uid %llu)\n",
                    "DHT API", uid);
#endif

        hash_from_uid (uid, &uid_hash);
        route_handle =
          GNUNET_CONTAINER_multihashmap_get (handle->outstanding_requests,
                                             &uid_hash);
        if (route_handle == NULL)   /* We have no recollection of this request */
          {
#if DEBUG_DHT_API
            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                        "`%s': Received response to message (uid %llu), but have no recollection of it!\n",
                        "DHT API", uid);
#endif
          }
        else
          {
            enc_size =
              ntohs (dht_msg->header.size) -
              sizeof (struct GNUNET_DHT_RouteResultMessage);
            GNUNET_assert (enc_size > 0);
            enc_msg = (struct GNUNET_MessageHeader *) &dht_msg[1];
            route_handle->iter (route_handle->iter_cls, enc_msg);
          }

        break;
      }
    default:
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    "`%s': Received unknown message type %d\n", "DHT API",
                    ntohs (msg->type));
      }
    }
  GNUNET_CLIENT_receive (handle->client,
                         &service_message_handler,
                         handle, GNUNET_TIME_UNIT_FOREVER_REL);

}


/**
 * Initialize the connection with the DHT service.
 *
 * @param sched scheduler to use
 * @param cfg configuration to use
 * @param ht_len size of the internal hash table to use for
 *               processing multiple GET/FIND requests in parallel
 *
 * @return handle to the DHT service, or NULL on error
 */
struct GNUNET_DHT_Handle *
GNUNET_DHT_connect (struct GNUNET_SCHEDULER_Handle *sched,
                    const struct GNUNET_CONFIGURATION_Handle *cfg,
                    unsigned int ht_len)
{
  struct GNUNET_DHT_Handle *handle;

  handle = GNUNET_malloc (sizeof (struct GNUNET_DHT_Handle));
  handle->cfg = cfg;
  handle->sched = sched;
  handle->client = GNUNET_CLIENT_connect (sched, "dht", cfg);
  handle->uid_gen = GNUNET_CRYPTO_random_u64(GNUNET_CRYPTO_QUALITY_WEAK, -1);
  if (handle->client == NULL)
    {
      GNUNET_free (handle);
      return NULL;
    }
  handle->outstanding_requests =
    GNUNET_CONTAINER_multihashmap_create (ht_len);
#if DEBUG_DHT_API
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Connection to service in progress\n", "DHT API");
#endif
  GNUNET_CLIENT_receive (handle->client,
                         &service_message_handler,
                         handle, GNUNET_TIME_UNIT_FOREVER_REL);
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
#if DEBUG_DHT_API
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Called GNUNET_DHT_disconnect\n", "DHT API");
#endif
  GNUNET_assert (handle != NULL);
  if (handle->th != NULL)       /* We have a live transmit request */
    {
      GNUNET_CLIENT_notify_transmit_ready_cancel (handle->th);
      handle->th = NULL;
    }
  if (handle->current != NULL)  /* We are trying to send something now, clean it up */
    GNUNET_free (handle->current);

  if (handle->client != NULL)   /* Finally, disconnect from the service */
    {
      GNUNET_CLIENT_disconnect (handle->client, GNUNET_NO);
      handle->client = NULL;
    }

  GNUNET_assert(GNUNET_CONTAINER_multihashmap_size(handle->outstanding_requests) == 0);
  GNUNET_CONTAINER_multihashmap_destroy(handle->outstanding_requests);
  GNUNET_free (handle);
}


/**
 * Transmit the next pending message, called by notify_transmit_ready
 */
static size_t
transmit_pending_retransmission (void *cls, size_t size, void *buf)
{
  struct GNUNET_DHT_Handle *handle = cls;
  size_t tsize;

#if DEBUG_DHT_API
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': In transmit_pending\n", "DHT API");
#endif
  if (buf == NULL)
    {
#if DEBUG_DHT_API
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "`%s': In transmit_pending buf is NULL\n", "DHT API");
#endif
      finish_retransmission (handle, GNUNET_SYSERR);
      return 0;
    }

  handle->th = NULL;

  if (handle->current != NULL)
    {
      tsize = ntohs (handle->current->msg->size);
      if (size >= tsize)
        {
#if DEBUG_DHT_API
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "`%s': Sending message size %d\n", "DHT API", tsize);
#endif
          memcpy (buf, handle->current->msg, tsize);
          finish_retransmission (handle, GNUNET_OK);
          return tsize;
        }
      else
        {
          return 0;
        }
    }
  /* Have no pending request */
  return 0;
}


/**
 * Iterator called on each result obtained from a generic route
 * operation
 */
void
get_reply_iterator (void *cls, const struct GNUNET_MessageHeader *reply)
{
  struct GNUNET_DHT_GetHandle *get_handle = cls;
  struct GNUNET_DHT_GetResultMessage *result;
  size_t data_size;
  char *result_data;

  if (ntohs (reply->type) != GNUNET_MESSAGE_TYPE_DHT_GET_RESULT)
    return;

  GNUNET_assert (ntohs (reply->size) >=
                 sizeof (struct GNUNET_DHT_GetResultMessage));
  result = (struct GNUNET_DHT_GetResultMessage *) reply;
  data_size = ntohs (reply->size) - sizeof(struct GNUNET_DHT_GetResultMessage);

  result_data = (char *) &result[1];    /* Set data pointer to end of message */

  get_handle->get_context.iter (get_handle->get_context.iter_cls,
                                GNUNET_TIME_absolute_ntoh (result->expiration), &get_handle->route_handle->key,
                                ntohs (result->type), data_size, result_data);
}


/**
 * Iterator called on each result obtained from a generic route
 * operation
 */
void
find_peer_reply_iterator (void *cls, const struct GNUNET_MessageHeader *reply)
{
  struct GNUNET_DHT_FindPeerHandle *find_peer_handle = cls;
  struct GNUNET_MessageHeader *hello;

  if (ntohs (reply->type) != GNUNET_MESSAGE_TYPE_DHT_FIND_PEER_RESULT)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Received wrong type of response to a find peer request...\n");
      return;
    }


  GNUNET_assert (ntohs (reply->size) >=
                 sizeof (struct GNUNET_MessageHeader));
  hello = (struct GNUNET_MessageHeader *)&reply[1];

  if (ntohs(hello->type) != GNUNET_MESSAGE_TYPE_HELLO)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Encapsulated message of type %d, is not a `%s' message!\n", ntohs(hello->type), "HELLO");
      return;
    }
  find_peer_handle->find_peer_context.proc (find_peer_handle->
                                            find_peer_context.proc_cls,
                                            (struct GNUNET_HELLO_Message *)hello);
}

/**
 * Send a message to the DHT telling it to start issuing random GET
 * requests every 'frequency' milliseconds.
 *
 * @param handle handle to the DHT service
 * @param frequency delay (in milliseconds) between sending malicious messages
 * @param cont continuation to call once the message is sent
 * @param cont_cls closure for continuation
 *
 * @return GNUNET_YES if the control message was sent, GNUNET_NO if not
 */
int GNUNET_DHT_set_malicious_getter (struct GNUNET_DHT_Handle *handle, int frequency, GNUNET_SCHEDULER_Task cont, void *cont_cls)
{
  struct GNUNET_DHT_ControlMessage *msg;
  struct PendingMessage *pending;

  if ((handle->current != NULL) && (handle->retransmit_stage != DHT_RETRANSMITTING))
    return GNUNET_NO;

  msg = GNUNET_malloc(sizeof(struct GNUNET_DHT_ControlMessage));
  msg->header.size = htons(sizeof(struct GNUNET_DHT_ControlMessage));
  msg->header.type = htons(GNUNET_MESSAGE_TYPE_DHT_CONTROL);
  msg->command = htons(GNUNET_MESSAGE_TYPE_DHT_MALICIOUS_GET);
  msg->variable = htons(frequency);

  pending = GNUNET_malloc (sizeof (struct PendingMessage));
  pending->msg = &msg->header;
  pending->timeout = GNUNET_TIME_relative_get_forever();
  pending->free_on_send = GNUNET_YES;
  pending->cont = cont;
  pending->cont_cls = cont_cls;
  pending->unique_id = 0;

  if (handle->current == NULL)
    {
      handle->current = pending;
      process_pending_message (handle);
    }
  else
  {
    handle->retransmit_stage = DHT_RETRANSMITTING_MESSAGE_QUEUED;
    handle->retransmission_buffer = pending;
  }

  return GNUNET_YES;
}

/**
 * Send a message to the DHT telling it to issue a single find
 * peer request using the peers unique identifier as key.  This
 * is used to fill the routing table, and is normally controlled
 * by the DHT itself.  However, for testing and perhaps more
 * close control over the DHT, this can be explicitly managed.
 *
 * @param handle handle to the DHT service
 * @param cont continuation to call once the message is sent
 * @param cont_cls closure for continuation
 *
 * @return GNUNET_YES if the control message was sent, GNUNET_NO if not
 */
int GNUNET_DHT_find_peers (struct GNUNET_DHT_Handle *handle,
                           GNUNET_SCHEDULER_Task cont, void *cont_cls)
{
  struct GNUNET_DHT_ControlMessage *msg;
  struct PendingMessage *pending;

  if ((handle->current != NULL) && (handle->retransmit_stage != DHT_RETRANSMITTING))
    return GNUNET_NO;

  msg = GNUNET_malloc(sizeof(struct GNUNET_DHT_ControlMessage));
  msg->header.size = htons(sizeof(struct GNUNET_DHT_ControlMessage));
  msg->header.type = htons(GNUNET_MESSAGE_TYPE_DHT_CONTROL);
  msg->command = htons(GNUNET_MESSAGE_TYPE_DHT_FIND_PEER);

  pending = GNUNET_malloc (sizeof (struct PendingMessage));
  pending->msg = &msg->header;
  pending->timeout = GNUNET_TIME_relative_get_forever();
  pending->free_on_send = GNUNET_YES;
  pending->cont = cont;
  pending->cont_cls = cont_cls;
  pending->unique_id = 0;

  if (handle->current == NULL)
    {
      handle->current = pending;
      process_pending_message (handle);
    }
  else
  {
    handle->retransmit_stage = DHT_RETRANSMITTING_MESSAGE_QUEUED;
    handle->retransmission_buffer = pending;
  }

  return GNUNET_YES;
}

/**
 * Send a message to the DHT telling it to start issuing random PUT
 * requests every 'frequency' milliseconds.
 *
 * @param handle handle to the DHT service
 * @param frequency delay (in milliseconds) between sending malicious messages
 * @param cont continuation to call once the message is sent
 * @param cont_cls closure for continuation
 *
 * @return GNUNET_YES if the control message was sent, GNUNET_NO if not
 */
int GNUNET_DHT_set_malicious_putter (struct GNUNET_DHT_Handle *handle, int frequency, GNUNET_SCHEDULER_Task cont, void *cont_cls)
{
  struct GNUNET_DHT_ControlMessage *msg;
  struct PendingMessage *pending;

  if ((handle->current != NULL) && (handle->retransmit_stage != DHT_RETRANSMITTING))
    return GNUNET_NO;

  msg = GNUNET_malloc(sizeof(struct GNUNET_DHT_ControlMessage));
  msg->header.size = htons(sizeof(struct GNUNET_DHT_ControlMessage));
  msg->header.type = htons(GNUNET_MESSAGE_TYPE_DHT_CONTROL);
  msg->command = htons(GNUNET_MESSAGE_TYPE_DHT_MALICIOUS_PUT);
  msg->variable = htons(frequency);

  pending = GNUNET_malloc (sizeof (struct PendingMessage));
  pending->msg = &msg->header;
  pending->timeout = GNUNET_TIME_relative_get_forever();
  pending->free_on_send = GNUNET_YES;
  pending->cont = cont;
  pending->cont_cls = cont_cls;
  pending->unique_id = 0;

  if (handle->current == NULL)
    {
      handle->current = pending;
      process_pending_message (handle);
    }
  else
  {
    handle->retransmit_stage = DHT_RETRANSMITTING_MESSAGE_QUEUED;
    handle->retransmission_buffer = pending;
  }

  return GNUNET_YES;
}

/**
 * Send a message to the DHT telling it to start dropping
 * all requests received.
 *
 * @param handle handle to the DHT service
 * @param cont continuation to call once the message is sent
 * @param cont_cls closure for continuation
 *
 * @return GNUNET_YES if the control message was sent, GNUNET_NO if not
 */
int GNUNET_DHT_set_malicious_dropper (struct GNUNET_DHT_Handle *handle, GNUNET_SCHEDULER_Task cont, void *cont_cls)
{
  struct GNUNET_DHT_ControlMessage *msg;
  struct PendingMessage *pending;

  if ((handle->current != NULL) && (handle->retransmit_stage != DHT_RETRANSMITTING))
    return GNUNET_NO;

  msg = GNUNET_malloc(sizeof(struct GNUNET_DHT_ControlMessage));
  msg->header.size = htons(sizeof(struct GNUNET_DHT_ControlMessage));
  msg->header.type = htons(GNUNET_MESSAGE_TYPE_DHT_CONTROL);
  msg->command = htons(GNUNET_MESSAGE_TYPE_DHT_MALICIOUS_DROP);
  msg->variable = htons(0);

  pending = GNUNET_malloc (sizeof (struct PendingMessage));
  pending->msg = &msg->header;
  pending->timeout = GNUNET_TIME_relative_get_forever();
  pending->free_on_send = GNUNET_YES;
  pending->cont = cont;
  pending->cont_cls = cont_cls;
  pending->unique_id = 0;

  if (handle->current == NULL)
    {
      handle->current = pending;
      process_pending_message (handle);
    }
  else
  {
    handle->retransmit_stage = DHT_RETRANSMITTING_MESSAGE_QUEUED;
    handle->retransmission_buffer = pending;
  }

  return GNUNET_YES;
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
 *                to wait for tramission to the service
 * @param cont continuation to call when done;
 *             reason will be TIMEOUT on error,
 *             reason will be PREREQ_DONE on success
 * @param cont_cls closure for cont
 *
 * @return handle to stop the request, NULL if the request is "fire and forget"
 */
struct GNUNET_DHT_RouteHandle *
GNUNET_DHT_route_start (struct GNUNET_DHT_Handle *handle,
                        const GNUNET_HashCode * key,
                        unsigned int desired_replication_level,
                        enum GNUNET_DHT_RouteOption options,
                        const struct GNUNET_MessageHeader *enc,
                        struct GNUNET_TIME_Relative timeout,
                        GNUNET_DHT_ReplyProcessor iter,
                        void *iter_cls,
                        GNUNET_SCHEDULER_Task cont, void *cont_cls)
{
  struct GNUNET_DHT_RouteHandle *route_handle;
  struct PendingMessage *pending;
  struct GNUNET_DHT_RouteMessage *message;
  uint16_t msize;
  GNUNET_HashCode uid_key;

  if ((handle->current != NULL) && (handle->retransmit_stage != DHT_RETRANSMITTING))
    return NULL;

  if (sizeof (struct GNUNET_DHT_RouteMessage) + ntohs (enc->size) >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
    {
      GNUNET_break (0);
      return NULL;
    }

  route_handle = GNUNET_malloc (sizeof (struct GNUNET_DHT_RouteHandle));
  memcpy (&route_handle->key, key, sizeof (GNUNET_HashCode));
  route_handle->iter = iter;
  route_handle->iter_cls = iter_cls;
  route_handle->dht_handle = handle;
  route_handle->uid = handle->uid_gen++;
  if (iter != NULL)
    {
      hash_from_uid (route_handle->uid, &uid_key);
      GNUNET_CONTAINER_multihashmap_put (handle->outstanding_requests,
                                         &uid_key, route_handle,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
    }

#if DEBUG_DHT_API
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "`%s': Unique ID is %llu\n", "DHT API", route_handle->uid);
#endif

  msize = sizeof (struct GNUNET_DHT_RouteMessage) + ntohs (enc->size);
  message = GNUNET_malloc (msize);
  message->header.size = htons (msize);
  message->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_LOCAL_ROUTE);
  memcpy (&message->key, key, sizeof (GNUNET_HashCode));
  message->options = htonl (options);
  message->desired_replication_level = htonl (desired_replication_level);
  message->unique_id = GNUNET_htonll (route_handle->uid);
  memcpy (&message[1], enc, ntohs (enc->size));
  pending = GNUNET_malloc (sizeof (struct PendingMessage));
  pending->msg = &message->header;
  pending->timeout = timeout;
  if (iter == NULL)
    pending->free_on_send = GNUNET_YES;
  pending->cont = cont;
  pending->cont_cls = cont_cls;
  pending->unique_id = route_handle->uid;
  if (handle->current == NULL)
    {
      handle->current = pending;
      process_pending_message (handle);
    }
  else
  {
    handle->retransmit_stage = DHT_RETRANSMITTING_MESSAGE_QUEUED;
    handle->retransmission_buffer = pending;
  }

  route_handle->message = message;
  return route_handle;
}


/**
 * Perform an asynchronous GET operation on the DHT identified.
 *
 * @param handle handle to the DHT service
 * @param timeout how long to wait for transmission of this request to the service
 * @param type expected type of the response object
 * @param key the key to look up
 * @param iter function to call on each result
 * @param iter_cls closure for iter
 * @param cont continuation to call once message sent
 * @param cont_cls closure for continuation
 *
 * @return handle to stop the async get
 */
struct GNUNET_DHT_GetHandle *
GNUNET_DHT_get_start (struct GNUNET_DHT_Handle *handle,
                      struct GNUNET_TIME_Relative timeout,
                      uint32_t type,
                      const GNUNET_HashCode * key,
                      GNUNET_DHT_GetIterator iter,
                      void *iter_cls,
                      GNUNET_SCHEDULER_Task cont, void *cont_cls)
{
  struct GNUNET_DHT_GetHandle *get_handle;
  struct GNUNET_DHT_GetMessage get_msg;

  if ((handle->current != NULL) && (handle->retransmit_stage != DHT_RETRANSMITTING)) /* Can't send right now, we have a pending message... */
    return NULL;

  get_handle = GNUNET_malloc (sizeof (struct GNUNET_DHT_GetHandle));
  get_handle->get_context.iter = iter;
  get_handle->get_context.iter_cls = iter_cls;

#if DEBUG_DHT_API
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Inserting pending get request with key %s\n", "DHT API",
              GNUNET_h2s (key));
#endif

  get_msg.header.type = htons (GNUNET_MESSAGE_TYPE_DHT_GET);
  get_msg.header.size = htons (sizeof (struct GNUNET_DHT_GetMessage));
  get_msg.type = htons (type);

  get_handle->route_handle =
    GNUNET_DHT_route_start (handle, key, DEFAULT_GET_REPLICATION, 0, &get_msg.header, timeout,
                            &get_reply_iterator, get_handle, cont, cont_cls);

  return get_handle;
}


/**
 * Stop a previously issued routing request
 *
 * @param route_handle handle to the request to stop
 * @param cont continuation to call once this message is sent to the service or times out
 * @param cont_cls closure for the continuation
 */
void
GNUNET_DHT_route_stop (struct GNUNET_DHT_RouteHandle *route_handle,
                       GNUNET_SCHEDULER_Task cont, void *cont_cls)
{
  struct PendingMessage *pending;
  struct GNUNET_DHT_StopMessage *message;
  size_t msize;
  GNUNET_HashCode uid_key;

  msize = sizeof (struct GNUNET_DHT_StopMessage);
  message = GNUNET_malloc (msize);
  message->header.size = htons (msize);
  message->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_LOCAL_ROUTE_STOP);
#if DEBUG_DHT_API
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Remove outstanding request for uid %llu\n", "DHT API",
              route_handle->uid);
#endif
  message->unique_id = GNUNET_htonll (route_handle->uid);
  memcpy(&message->key, &route_handle->key, sizeof(GNUNET_HashCode));
  pending = GNUNET_malloc (sizeof (struct PendingMessage));
  pending->msg = (struct GNUNET_MessageHeader *) message;
  pending->timeout = GNUNET_TIME_relative_get_forever();
  pending->cont = cont;
  pending->cont_cls = cont_cls;
  pending->free_on_send = GNUNET_YES;
  pending->unique_id = 0; /* When finished is called, free pending->msg */

  if (route_handle->dht_handle->current == NULL)
    {
      route_handle->dht_handle->current = pending;
      process_pending_message (route_handle->dht_handle);
    }
  else if (route_handle->dht_handle->retransmit_stage == DHT_RETRANSMITTING)
    {
      route_handle->dht_handle->retransmit_stage = DHT_RETRANSMITTING_MESSAGE_QUEUED;
      route_handle->dht_handle->retransmission_buffer = pending;
    }
  else
    {
      GNUNET_free(pending);
      GNUNET_break(0);
    }

  hash_from_uid (route_handle->uid, &uid_key);
  GNUNET_assert (GNUNET_CONTAINER_multihashmap_remove
		 (route_handle->dht_handle->outstanding_requests, &uid_key,
		  route_handle) == GNUNET_YES);

  GNUNET_free(route_handle->message);
  GNUNET_free(route_handle);
}


/**
 * Stop async DHT-get.
 *
 * @param get_handle handle to the GET operation to stop
 * @param cont continuation to call once this message is sent to the service or times out
 * @param cont_cls closure for the continuation
 */
void
GNUNET_DHT_get_stop (struct GNUNET_DHT_GetHandle *get_handle,
                     GNUNET_SCHEDULER_Task cont, void *cont_cls)
{
  if ((get_handle->route_handle->dht_handle->current != NULL) &&
      (get_handle->route_handle->dht_handle->retransmit_stage != DHT_RETRANSMITTING))
    {
      if (cont != NULL)
        {
          GNUNET_SCHEDULER_add_continuation (get_handle->route_handle->dht_handle->sched, cont, cont_cls,
                                             GNUNET_SCHEDULER_REASON_TIMEOUT);
        }
      return;
    }

#if DEBUG_DHT_API
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Removing pending get request with key %s, uid %llu\n",
              "DHT API", GNUNET_h2s (&get_handle->route_handle->key),
              get_handle->route_handle->uid);
#endif
  GNUNET_DHT_route_stop (get_handle->route_handle, cont, cont_cls);
  GNUNET_free (get_handle);
}


/**
 * Perform an asynchronous FIND PEER operation on the DHT.
 *
 * @param handle handle to the DHT service
 * @param timeout timeout for this request to be sent to the
 *        service
 * @param options routing options for this message
 * @param key the key to look up
 * @param proc function to call on each result
 * @param proc_cls closure for proc
 * @param cont continuation to call once message sent
 * @param cont_cls closure for continuation
 *
 * @return handle to stop the async get, NULL on error
 */
struct GNUNET_DHT_FindPeerHandle *
GNUNET_DHT_find_peer_start (struct GNUNET_DHT_Handle *handle,
                            struct GNUNET_TIME_Relative timeout,
                            enum GNUNET_DHT_RouteOption options,
                            const GNUNET_HashCode * key,
                            GNUNET_DHT_FindPeerProcessor proc,
                            void *proc_cls,
                            GNUNET_SCHEDULER_Task cont,
                            void *cont_cls)
{
  struct GNUNET_DHT_FindPeerHandle *find_peer_handle;
  struct GNUNET_DHT_FindPeerMessage find_peer_msg;

  if ((handle->current != NULL) && (handle->retransmit_stage != DHT_RETRANSMITTING))  /* Can't send right now, we have a pending message... */
    return NULL;

  find_peer_handle =
    GNUNET_malloc (sizeof (struct GNUNET_DHT_FindPeerHandle));
  find_peer_handle->find_peer_context.proc = proc;
  find_peer_handle->find_peer_context.proc_cls = proc_cls;

#if DEBUG_DHT_API
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Inserting pending `%s' request with key %s\n", "DHT API",
              "FIND PEER", GNUNET_h2s (key));
#endif

  find_peer_msg.header.size = htons(sizeof(struct GNUNET_DHT_FindPeerMessage));
  find_peer_msg.header.type = htons(GNUNET_MESSAGE_TYPE_DHT_FIND_PEER);
  find_peer_handle->route_handle =
    GNUNET_DHT_route_start (handle, key, 0, options, &find_peer_msg.header,
                            timeout, &find_peer_reply_iterator,
                            find_peer_handle, cont, cont_cls);
  return find_peer_handle;
}

/**
 * Stop async find peer.  Frees associated resources.
 *
 * @param find_peer_handle GET operation to stop.
 * @param cont continuation to call once this message is sent to the service or times out
 * @param cont_cls closure for the continuation
 */
void
GNUNET_DHT_find_peer_stop (struct GNUNET_DHT_FindPeerHandle *find_peer_handle,
                           GNUNET_SCHEDULER_Task cont, void *cont_cls)
{
  if ((find_peer_handle->route_handle->dht_handle->current != NULL) &&
      (find_peer_handle->route_handle->dht_handle->retransmit_stage != DHT_RETRANSMITTING))
    {
      if (cont != NULL)
        {
          GNUNET_SCHEDULER_add_continuation (find_peer_handle->route_handle->dht_handle->sched, cont, cont_cls,
                                             GNUNET_SCHEDULER_REASON_TIMEOUT);
        }
      return;
    }

#if DEBUG_DHT_API
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Removing pending `%s' request with key %s, uid %llu\n",
              "DHT API", "FIND PEER",
              GNUNET_h2s (&find_peer_handle->route_handle->key),
              find_peer_handle->route_handle->uid);
#endif
  GNUNET_DHT_route_stop (find_peer_handle->route_handle, cont, cont_cls);
  GNUNET_free (find_peer_handle);

}


/**
 * Perform a PUT operation storing data in the DHT.
 *
 * @param handle handle to DHT service
 * @param key the key to store under
 * @param type type of the value
 * @param size number of bytes in data; must be less than 64k
 * @param data the data to store
 * @param exp desired expiration time for the value
 * @param timeout how long to wait for transmission of this request
 * @param cont continuation to call when done;
 *             reason will be TIMEOUT on error,
 *             reason will be PREREQ_DONE on success
 * @param cont_cls closure for cont
 *
 * @return GNUNET_YES if put message is queued for transmission
 */
void
GNUNET_DHT_put (struct GNUNET_DHT_Handle *handle,
                const GNUNET_HashCode * key,
                uint32_t type,
                uint32_t size,
                const char *data,
                struct GNUNET_TIME_Absolute exp,
                struct GNUNET_TIME_Relative timeout,
                GNUNET_SCHEDULER_Task cont, void *cont_cls)
{
  struct GNUNET_DHT_PutMessage *put_msg;
  struct GNUNET_DHT_RouteHandle *put_route;
  size_t msize;

  if ((handle->current != NULL) && (handle->retransmit_stage != DHT_RETRANSMITTING))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "handle->current is not null!\n");
      if (cont != NULL)
        {
          GNUNET_SCHEDULER_add_continuation (handle->sched, cont, cont_cls,
                                             GNUNET_SCHEDULER_REASON_TIMEOUT);
        }
      return;
    }

#if DEBUG_DHT_API
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Inserting pending put request with key %s\n", "DHT API",
              GNUNET_h2s (key));
#endif

  msize = sizeof (struct GNUNET_DHT_PutMessage) + size;
  put_msg = GNUNET_malloc (msize);
  put_msg->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_PUT);
  put_msg->header.size = htons (msize);
  put_msg->type = htons (type);
  put_msg->data_size = htons (size);
  put_msg->expiration = GNUNET_TIME_absolute_hton(exp);
  memcpy (&put_msg[1], data, size);

  put_route = GNUNET_DHT_route_start (handle, key, DEFAULT_PUT_REPLICATION, 0, &put_msg->header, timeout, NULL,
                                      NULL, cont, cont_cls);

  if (put_route == NULL) /* Route start failed! */
    {
      GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "route start for PUT failed!\n");
      if (cont != NULL)
        {
          GNUNET_SCHEDULER_add_continuation (handle->sched, cont, cont_cls,
                                             GNUNET_SCHEDULER_REASON_TIMEOUT);
        }
    }
  else
    {
      GNUNET_free(put_route);
    }

  GNUNET_free (put_msg);
}
