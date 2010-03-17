/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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

#define DEBUG_DHT_API GNUNET_YES

struct PendingMessages
{
  /**
   * Linked list of pending messages
   */
  struct PendingMessages *next;

  /**
   * Message that is pending
   */
  struct GNUNET_MessageHeader *msg;

  /**
   * Timeout for this message
   */
  struct GNUNET_TIME_Relative timeout;

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
   * List of the currently pending messages for the DHT service.
   */
  struct PendingMessages *pending_list;

  /**
   * Message we are currently sending.
   */
  struct PendingMessages *current;

  /**
   * Hash map containing the current outstanding get requests
   */
  struct GNUNET_CONTAINER_MultiHashMap *outstanding_get_requests;

  /**
   * Hash map containing the current outstanding put requests, awaiting
   * a response
   */
  struct GNUNET_CONTAINER_MultiHashMap *outstanding_put_requests;

  /**
   * Kill off the connection and any pending messages.
   */
  int do_destroy;

};

static struct GNUNET_TIME_Relative default_request_timeout;

/* Forward declaration */
static void process_pending_message(struct GNUNET_DHT_Handle *handle);

/**
 * Handler for messages received from the DHT service
 * a demultiplexer which handles numerous message types
 *
 */
void service_message_handler (void *cls,
                              const struct GNUNET_MessageHeader *msg)
{

  /* TODO: find out message type, handle callbacks for different types of messages.
   * Should be a put acknowledgment, get data or find node result. */
}


/**
 * Initialize the connection with the DHT service.
 *
 * @param cfg configuration to use
 * @param sched scheduler to use
 * @param ht_len size of the internal hash table to use for
 *               processing multiple GET/FIND requests in parallel
 * @return NULL on error
 */
struct GNUNET_DHT_Handle *
GNUNET_DHT_connect (struct GNUNET_SCHEDULER_Handle *sched,
                    const struct GNUNET_CONFIGURATION_Handle *cfg,
                    unsigned int ht_len)
{
  struct GNUNET_DHT_Handle *handle;

  handle = GNUNET_malloc(sizeof(struct GNUNET_DHT_Handle));

  default_request_timeout = GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 5);
  handle->cfg = cfg;
  handle->sched = sched;
  handle->pending_list = NULL;
  handle->current = NULL;
  handle->do_destroy = GNUNET_NO;
  handle->th = NULL;

  handle->client = GNUNET_CLIENT_connect(sched, "dht", cfg);
  handle->outstanding_get_requests = GNUNET_CONTAINER_multihashmap_create(100); /* FIXME: better number */
  handle->outstanding_put_requests = GNUNET_CONTAINER_multihashmap_create(100); /* FIXME: better number */
  if (handle->client == NULL)
    return NULL;
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
 * @param h connection to shut down
 */
void
GNUNET_DHT_disconnect (struct GNUNET_DHT_Handle *handle)
{
  struct PendingMessages *pos;
#if DEBUG_DHT_API
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Called GNUNET_DHT_disconnect\n", "DHT API");
#endif
  GNUNET_assert(handle != NULL);

  if (handle->th != NULL) /* We have a live transmit request in the Aether */
    {
      GNUNET_CLIENT_notify_transmit_ready_cancel (handle->th);
      handle->th = NULL;
    }
  if (handle->current != NULL) /* We are trying to send something now, clean it up */
    GNUNET_free(handle->current);

  while (NULL != (pos = handle->pending_list)) /* Remove all pending sends from the list */
    {
      handle->pending_list = pos->next;
      GNUNET_free(pos);
    }
  if (handle->client != NULL) /* Finally, disconnect from the service */
    {
      GNUNET_CLIENT_disconnect (handle->client, GNUNET_NO);
      handle->client = NULL;
    }

  GNUNET_free (handle);
}


/**
 * Handle to control a GET operation.
 */
struct GNUNET_DHT_GetHandle
{

  /**
   * Key that this get request is for
   */
  GNUNET_HashCode key;

  /**
   * Type of data get request was for
   */
  uint32_t type;

  /**
   * Iterator to call on data receipt
   */
  GNUNET_DHT_Iterator iter;

  /**
   * Closure for the iterator callback
   */
  void *iter_cls;

  /**
   * Main handle to this DHT api
   */
  struct GNUNET_DHT_Handle *dht_handle;
};

/**
 * Handle for a PUT request, holds callback
 */
struct GNUNET_DHT_PutHandle
{
  /**
   * Key that this get request is for
   */
  GNUNET_HashCode key;

  /**
   * Type of data get request was for
   */
  uint32_t type;

  /**
   * Continuation to call on put send
   */
  GNUNET_SCHEDULER_Task cont;

  /**
   * Send continuation cls
   */
  void *cont_cls;
};

/**
 * Send complete (or failed), schedule next (or don't)
 */
static void
finish (struct GNUNET_DHT_Handle *handle, int code)
{
  /* TODO: if code is not GNUNET_OK, do something! */
  struct PendingMessages *pos = handle->current;
  struct GNUNET_DHT_GetMessage *get;
  struct GNUNET_DHT_PutMessage *put;

  GNUNET_assert(pos != NULL);

  switch (ntohs(pos->msg->type))
  {
    case GNUNET_MESSAGE_TYPE_DHT_GET:
      get = (struct GNUNET_DHT_GetMessage *)pos->msg;
      GNUNET_free(get);
      break;
    case GNUNET_MESSAGE_TYPE_DHT_PUT:
      put = (struct GNUNET_DHT_PutMessage *)pos->msg;
      GNUNET_free(put);
      break;
    default:
      GNUNET_break(0);
  }

  handle->current = NULL;

  if (code != GNUNET_SYSERR)
    process_pending_message (handle);

  GNUNET_free(pos);
}

/**
 * Transmit the next pending message, called by notify_transmit_ready
 */
static size_t
transmit_pending (void *cls, size_t size, void *buf)
{
  struct GNUNET_DHT_Handle *handle = cls;
  size_t tsize;

  if (buf == NULL)
    {
#if DEBUG_DHT_API
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "`%s': In transmit_pending buf is NULL\n", "DHT API");
#endif
      /* FIXME: free associated resources or summat */
      finish(handle, GNUNET_SYSERR);
      return 0;
    }

  handle->th = NULL;

  if (handle->current != NULL)
  {
    tsize = ntohs(handle->current->msg->size);
    if (size >= tsize)
    {
#if DEBUG_DHT_API
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "`%s': Sending message size %d\n", "DHT API", tsize);
#endif
      memcpy(buf, handle->current->msg, tsize);
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
 * Try to (re)connect to the dht service.
 *
 * @return GNUNET_YES on success, GNUNET_NO on failure.
 */
static int
try_connect (struct GNUNET_DHT_Handle *ret)
{
  if (ret->client != NULL)
    return GNUNET_OK;
  ret->client = GNUNET_CLIENT_connect (ret->sched, "dht", ret->cfg);
  if (ret->client != NULL)
    return GNUNET_YES;
#if DEBUG_STATISTICS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _("Failed to connect to the dht service!\n"));
#endif
  return GNUNET_NO;
}


/**
 * Try to send messages from list of messages to send
 */
static void process_pending_message(struct GNUNET_DHT_Handle *handle)
{

  if (handle->current != NULL)
    return;                     /* action already pending */
  if (GNUNET_YES != try_connect (handle))
    {
      finish (handle, GNUNET_SYSERR);
      return;
    }

  /* TODO: set do_destroy somewhere's, see what needs to happen in that case! */
  if (handle->do_destroy)
    {
      //GNUNET_DHT_disconnect (handle); /* FIXME: replace with proper disconnect stuffs */
    }

  /* schedule next action */
  handle->current = handle->pending_list;
  if (NULL == handle->current)
    {
      return;
    }
  handle->pending_list = handle->pending_list->next;
  handle->current->next = NULL;

  if (NULL ==
      (handle->th = GNUNET_CLIENT_notify_transmit_ready (handle->client,
                                                    ntohs(handle->current->msg->size),
                                                    handle->current->timeout,
                                                    GNUNET_YES,
                                                    &transmit_pending, handle)))
    {
#if DEBUG_DHT_API
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Failed to transmit request to dht service.\n");
#endif
      finish (handle, GNUNET_SYSERR);
    }
#if DEBUG_DHT_API
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Scheduled sending message of size %d to service\n", "DHT API", ntohs(handle->current->msg->size));
#endif
}

/**
 * Add a pending message to the linked list of messages which need to be sent
 *
 * @param handle handle to the specified DHT api
 * @param msg the message to add to the list
 */
static void add_pending(struct GNUNET_DHT_Handle *handle, struct GNUNET_MessageHeader *msg)
{
  struct PendingMessages *new_message;
  struct PendingMessages *pos;
  struct PendingMessages *last;

  new_message = GNUNET_malloc(sizeof(struct PendingMessages));
  new_message->msg = msg;
  new_message->timeout = default_request_timeout;

  if (handle->pending_list != NULL)
    {
      pos = handle->pending_list;
      while(pos != NULL)
        {
          last = pos;
          pos = pos->next;
        }
      new_message->next = last->next; /* Should always be null */
      last->next = new_message;
    }
  else
    {
      new_message->next = handle->pending_list; /* Will always be null */
      handle->pending_list = new_message;
    }

  process_pending_message(handle);
}

/**
 * Perform an asynchronous GET operation on the DHT identified.
 *
 * @param h handle to the DHT service
 * @param type expected type of the response object
 * @param key the key to look up
 * @param iter function to call on each result
 * @param iter_cls closure for iter
 * @return handle to stop the async get
 */
struct GNUNET_DHT_GetHandle *
GNUNET_DHT_get_start (struct GNUNET_DHT_Handle *handle,
                      uint32_t type,
                      const GNUNET_HashCode * key,
                      GNUNET_DHT_Iterator iter,
                      void *iter_cls)
{
  struct GNUNET_DHT_GetMessage *get_msg;
  struct GNUNET_DHT_GetHandle *get_handle;

  get_handle = GNUNET_CONTAINER_multihashmap_get(handle->outstanding_get_requests, key);

  if (get_handle != NULL)
    {
      /*
       * A get has been previously sent, return existing handle.
       * FIXME: should we re-transmit the request to the DHT service?
       */
      return get_handle;
    }

  get_handle = GNUNET_malloc(sizeof(struct GNUNET_DHT_GetHandle));
  get_handle->type = type;
  memcpy(&get_handle->key, key, sizeof(GNUNET_HashCode));
  get_handle->iter = iter;
  get_handle->iter_cls = iter_cls;

#if DEBUG_DHT_API
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Inserting pending get request with key %s\n", "DHT API", GNUNET_h2s(key));
#endif
  GNUNET_CONTAINER_multihashmap_put(handle->outstanding_get_requests, key, get_handle, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);

  get_msg = GNUNET_malloc(sizeof(struct GNUNET_DHT_GetMessage));
  get_msg->header.type = htons(GNUNET_MESSAGE_TYPE_DHT_GET);
  get_msg->header.size = htons(sizeof(struct GNUNET_DHT_GetMessage));
  get_msg->type = htonl(type);
  memcpy(&get_msg->key, key, sizeof(GNUNET_HashCode));

  add_pending(handle, &get_msg->header);

  return get_handle;
}


/**
 * Stop async DHT-get.  Frees associated resources.
 *
 * @param record GET operation to stop.
 */
void
GNUNET_DHT_get_stop (struct GNUNET_DHT_GetHandle *get_handle)
{
  struct GNUNET_DHT_GetMessage *get_msg;
  struct GNUNET_DHT_Handle *handle;

  if (handle->do_destroy == GNUNET_NO)
    {
      get_msg = GNUNET_malloc(sizeof(struct GNUNET_DHT_GetMessage));
      get_msg->header.type = htons(GNUNET_MESSAGE_TYPE_DHT_GET_STOP);
      get_msg->header.size = htons(sizeof(struct GNUNET_DHT_GetMessage));
      get_msg->type = htonl(get_handle->type);
      memcpy(&get_msg->key, &get_handle->key, sizeof(GNUNET_HashCode));

      add_pending(handle, &get_msg->header);
    }
#if DEBUG_DHT_API
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Removing pending get request with key %s\n", "DHT API", GNUNET_h2s(&get_handle->key));
#endif
  GNUNET_assert(GNUNET_CONTAINER_multihashmap_remove(handle->outstanding_get_requests, &get_handle->key, get_handle) == GNUNET_YES);
  GNUNET_free(get_handle);
}


/**
 * Perform a PUT operation storing data in the DHT.
 *
 * @param h handle to DHT service
 * @param key the key to store under
 * @param type type of the value
 * @param size number of bytes in data; must be less than 64k
 * @param data the data to store
 * @param exp desired expiration time for the value
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
                GNUNET_SCHEDULER_Task cont,
                void *cont_cls)
{
  struct GNUNET_DHT_PutMessage *put_msg;
  struct GNUNET_DHT_PutHandle *put_handle;
  size_t msize;

  put_handle = GNUNET_CONTAINER_multihashmap_get(handle->outstanding_put_requests, key);

  if (put_handle != NULL)
    {
      /*
       * A put has been previously queued, but not yet sent.
       * FIXME: change the continuation function and callback or something?
       */
      return;
    }

  put_handle = GNUNET_malloc(sizeof(struct GNUNET_DHT_PutHandle));
  put_handle->type = type;
  memcpy(&put_handle->key, key, sizeof(GNUNET_HashCode));

#if DEBUG_DHT_API
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Inserting pending put request with key %s\n", "DHT API", GNUNET_h2s(key));
#endif

  GNUNET_CONTAINER_multihashmap_put(handle->outstanding_put_requests, key, put_handle, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);

  msize = sizeof(struct GNUNET_DHT_PutMessage) + size;
  put_msg = GNUNET_malloc(msize);
  put_msg->header.type = htons(GNUNET_MESSAGE_TYPE_DHT_PUT);
  put_msg->header.size = htons(msize);
  put_msg->type = htonl(type);
  memcpy(&put_msg->key, key, sizeof(GNUNET_HashCode));
  memcpy(&put_msg[1], data, size);

  add_pending(handle, &put_msg->header);

  return;
}
