/*
     This file is part of GNUnet.
     (C) 2013-2014 Christian Grothoff (and other contributing authors)

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
 * @file peerstore/peerstore_api.c
 * @brief API for peerstore
 * @author Omar Tarabai
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "peerstore.h"
#include "peerstore_common.h"

#define LOG(kind,...) GNUNET_log_from (kind, "peerstore-api",__VA_ARGS__)

/******************************************************************************/
/************************      DATA STRUCTURES     ****************************/
/******************************************************************************/

/**
 * Handle to the PEERSTORE service.
 */
struct GNUNET_PEERSTORE_Handle
{

  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Connection to the service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Message queue
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Head of active STORE requests.
   */
  struct GNUNET_PEERSTORE_StoreContext *store_head;

  /**
   * Tail of active STORE requests.
   */
  struct GNUNET_PEERSTORE_StoreContext *store_tail;

  /**
   * Head of active ITERATE requests.
   */
  struct GNUNET_PEERSTORE_IterateContext *iterate_head;

  /**
   * Tail of active ITERATE requests.
   */
  struct GNUNET_PEERSTORE_IterateContext *iterate_tail;

  /**
   * Hashmap of watch requests
   */
  struct GNUNET_CONTAINER_MultiHashMap *watches;

  /**
   * Are we in the process of disconnecting but need to sync first?
   */
  int disconnecting;

};

/**
 * Context for a store request
 */
struct GNUNET_PEERSTORE_StoreContext
{
  /**
   * Kept in a DLL.
   */
  struct GNUNET_PEERSTORE_StoreContext *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_PEERSTORE_StoreContext *prev;

  /**
   * Handle to the PEERSTORE service.
   */
  struct GNUNET_PEERSTORE_Handle *h;

  /**
   * Continuation called with service response
   */
  GNUNET_PEERSTORE_Continuation cont;

  /**
   * Closure for @e cont
   */
  void *cont_cls;

  /**
   * Which subsystem does the store?
   */
  char *sub_system;

  /**
   * Key for the store operation.
   */
  char *key;

  /**
   * Contains @e size bytes.
   */
  void *value;

  /**
   * MQ Envelope with store request message
   */
  struct GNUNET_MQ_Envelope *ev;

  /**
   * Peer the store is for.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Number of bytes in @e value.
   */
  size_t size;

  /**
   * When does the value expire?
   */
  struct GNUNET_TIME_Absolute expiry;

  /**
   * Options for the store operation.
   */
  enum GNUNET_PEERSTORE_StoreOption options;

};

/**
 * Context for a iterate request
 */
struct GNUNET_PEERSTORE_IterateContext
{
  /**
   * Kept in a DLL.
   */
  struct GNUNET_PEERSTORE_IterateContext *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_PEERSTORE_IterateContext *prev;

  /**
   * Handle to the PEERSTORE service.
   */
  struct GNUNET_PEERSTORE_Handle *h;

  /**
   * Which subsystem does the store?
   */
  char *sub_system;

  /**
   * Peer the store is for.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Key for the store operation.
   */
  char *key;

  /**
   * Operation timeout
   */
  struct GNUNET_TIME_Relative timeout;

  /**
   * MQ Envelope with iterate request message
   */
  struct GNUNET_MQ_Envelope *ev;

  /**
   * Callback with each matching record
   */
  GNUNET_PEERSTORE_Processor callback;

  /**
   * Closure for @e callback
   */
  void *callback_cls;

  /**
   * #GNUNET_YES / #GNUNET_NO
   * Iterate request has been sent and we are still expecting records
   */
  int iterating;

  /**
   * Task identifier for the function called
   * on iterate request timeout
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

};

/**
 * Context for a watch request
 */
struct GNUNET_PEERSTORE_WatchContext
{
  /**
   * Kept in a DLL.
   */
  struct GNUNET_PEERSTORE_WatchContext *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_PEERSTORE_WatchContext *prev;

  /**
   * Handle to the PEERSTORE service.
   */
  struct GNUNET_PEERSTORE_Handle *h;

  /**
   * MQ Envelope with watch request message
   */
  struct GNUNET_MQ_Envelope *ev;

  /**
   * Callback with each record received
   */
  GNUNET_PEERSTORE_Processor callback;

  /**
   * Closure for @e callback
   */
  void *callback_cls;

  /**
   * Hash of the combined key
   */
  struct GNUNET_HashCode keyhash;

  /**
   * #GNUNET_YES / #GNUNET_NO
   * if sent, cannot be canceled
   */
  int request_sent;

};

/******************************************************************************/
/*******************             DECLARATIONS             *********************/
/******************************************************************************/

/**
 * When a response for iterate request is received
 *
 * @param cls a 'struct GNUNET_PEERSTORE_Handle *'
 * @param msg message received, NULL on timeout or fatal error
 */
static void
handle_iterate_result (void *cls, const struct GNUNET_MessageHeader *msg);

/**
 * When a watch record is received
 *
 * @param cls a 'struct GNUNET_PEERSTORE_Handle *'
 * @param msg message received, NULL on timeout or fatal error
 */
static void
handle_watch_result (void *cls, const struct GNUNET_MessageHeader *msg);

/**
 * Close the existing connection to PEERSTORE and reconnect.
 *
 * @param h handle to the service
 */
static void
reconnect (struct GNUNET_PEERSTORE_Handle *h);

/**
 * Callback after MQ envelope is sent
 *
 * @param cls a 'struct GNUNET_PEERSTORE_WatchContext *'
 */
static void
watch_request_sent (void *cls)
{
  struct GNUNET_PEERSTORE_WatchContext *wc = cls;

  wc->request_sent = GNUNET_YES;
  wc->ev = NULL;
}


/**
 * Callback after MQ envelope is sent
 *
 * @param cls a `struct GNUNET_PEERSTORE_IterateContext *`
 */
static void
iterate_request_sent (void *cls)
{
  struct GNUNET_PEERSTORE_IterateContext *ic = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Iterate request sent to service.\n");
  ic->iterating = GNUNET_YES;
  ic->ev = NULL;
}


/**
 * Callback after MQ envelope is sent
 *
 * @param cls a `struct GNUNET_PEERSTORE_StoreContext *`
 */
static void
store_request_sent (void *cls)
{
  struct GNUNET_PEERSTORE_StoreContext *sc = cls;
  GNUNET_PEERSTORE_Continuation cont;
  void *cont_cls;

  sc->ev = NULL;
  cont = sc->cont;
  cont_cls = sc->cont_cls;
  GNUNET_PEERSTORE_store_cancel (sc);
  if (NULL != cont)
    cont (cont_cls, GNUNET_OK);
}


/**
 * MQ message handlers
 */
static const struct GNUNET_MQ_MessageHandler mq_handlers[] = {
  {&handle_iterate_result, GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATE_RECORD, 0},
  {&handle_iterate_result, GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATE_END,
   sizeof (struct GNUNET_MessageHeader)},
  {&handle_watch_result, GNUNET_MESSAGE_TYPE_PEERSTORE_WATCH_RECORD, 0},
  GNUNET_MQ_HANDLERS_END
};

/******************************************************************************/
/*******************         CONNECTION FUNCTIONS         *********************/
/******************************************************************************/

static void
handle_client_error (void *cls, enum GNUNET_MQ_Error error)
{
  struct GNUNET_PEERSTORE_Handle *h = cls;

  LOG (GNUNET_ERROR_TYPE_ERROR,
       _("Received an error notification from MQ of type: %d\n"), error);
  reconnect (h);
}


/**
 * Iterator over previous watches to resend them
 */
static int
rewatch_it (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct GNUNET_PEERSTORE_Handle *h = cls;
  struct GNUNET_PEERSTORE_WatchContext *wc = value;
  struct StoreKeyHashMessage *hm;

  if (GNUNET_YES == wc->request_sent)
  {                             /* Envelope gone, create new one. */
    wc->ev = GNUNET_MQ_msg (hm, GNUNET_MESSAGE_TYPE_PEERSTORE_WATCH);
    hm->keyhash = wc->keyhash;
    wc->request_sent = GNUNET_NO;
  }
  GNUNET_MQ_notify_sent (wc->ev, &watch_request_sent, wc);
  GNUNET_MQ_send (h->mq, wc->ev);
  return GNUNET_YES;
}


/**
 * Called when the iterate request is timedout
 *
 * @param cls a `struct GNUNET_PEERSTORE_IterateContext *`
 * @param tc Scheduler task context (unused)
 */
static void
iterate_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_PEERSTORE_IterateContext *ic = cls;
  GNUNET_PEERSTORE_Processor callback;
  void *callback_cls;

  ic->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  callback = ic->callback;
  callback_cls = ic->callback_cls;
  GNUNET_PEERSTORE_iterate_cancel (ic);
  if (NULL != callback)
    callback (callback_cls, NULL, _("timeout"));
}


/**
 * Close the existing connection to PEERSTORE and reconnect.
 *
 * @param h handle to the service
 */
static void
reconnect (struct GNUNET_PEERSTORE_Handle *h)
{
  struct GNUNET_PEERSTORE_IterateContext *ic;
  struct GNUNET_PEERSTORE_IterateContext *ic_tmp;
  GNUNET_PEERSTORE_Processor icb;
  void *icb_cls;
  struct GNUNET_PEERSTORE_StoreContext *sc;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Reconnecting...\n");
  for (sc = h->store_head; NULL != sc; sc = sc->next)
  {
    if (NULL != sc->ev)
    {
      GNUNET_MQ_send_cancel (sc->ev);
      sc->ev = NULL;
    }
  }
  ic = h->iterate_head;
  while (NULL != ic)
  {
    if (GNUNET_YES == ic->iterating)
    {
      icb = ic->callback;
      icb_cls = ic->callback_cls;
      ic->iterating = GNUNET_NO;
      ic_tmp = ic;
      ic = ic->next;
      GNUNET_PEERSTORE_iterate_cancel (ic_tmp);
      if (NULL != icb)
        icb (icb_cls, NULL, _("Iteration canceled due to reconnection."));
    }
    else
    {
      if (GNUNET_SCHEDULER_NO_TASK != ic->timeout_task)
      {
        GNUNET_SCHEDULER_cancel (ic->timeout_task);
        ic->timeout_task = GNUNET_SCHEDULER_NO_TASK;
      }
      if (NULL != ic->ev)
      {
        GNUNET_MQ_send_cancel (ic->ev);
        ic->ev = NULL;
      }
      ic = ic->next;
    }
  }
  if (NULL != h->mq)
  {
    GNUNET_MQ_destroy (h->mq);
    h->mq = NULL;
  }
  if (NULL != h->client)
  {
    GNUNET_CLIENT_disconnect (h->client);
    h->client = NULL;
  }
  h->client = GNUNET_CLIENT_connect ("peerstore", h->cfg);
  GNUNET_assert (NULL != h->client);
  h->mq =
      GNUNET_MQ_queue_for_connection_client (h->client, mq_handlers,
                                             &handle_client_error, h);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Resending pending requests after reconnect.\n");
  if (NULL != h->watches)
    GNUNET_CONTAINER_multihashmap_iterate (h->watches, &rewatch_it, h);
  for (ic = h->iterate_head; NULL != ic; ic = ic->next)
  {
    ic->ev =
        PEERSTORE_create_record_mq_envelope (ic->sub_system, &ic->peer, ic->key,
                                             NULL, 0, NULL, 0,
                                             GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATE);
    GNUNET_MQ_notify_sent (ic->ev, &iterate_request_sent, ic);
    GNUNET_MQ_send (h->mq, ic->ev);
    ic->timeout_task =
        GNUNET_SCHEDULER_add_delayed (ic->timeout, &iterate_timeout, ic);
  }
  for (sc = h->store_head; NULL != sc; sc = sc->next)
  {
    sc->ev =
        PEERSTORE_create_record_mq_envelope (sc->sub_system, &sc->peer, sc->key,
                                             sc->value, sc->size, &sc->expiry,
                                             sc->options,
                                             GNUNET_MESSAGE_TYPE_PEERSTORE_STORE);
    GNUNET_MQ_notify_sent (sc->ev, &store_request_sent, sc);
    GNUNET_MQ_send (h->mq, sc->ev);
  }
}


/**
 * Iterator over watch requests to cancel them.
 *
 * @param cls unsused
 * @param key key to the watch request
 * @param value watch context
 * @return #GNUNET_YES to continue iteration
 */
static int
destroy_watch (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct GNUNET_PEERSTORE_WatchContext *wc = value;

  GNUNET_PEERSTORE_watch_cancel (wc);
  return GNUNET_YES;
}


/**
 * Kill the connection to the service. This can be delayed in case of pending
 * STORE requests and the user explicitly asked to sync first. Otherwise it is
 * performed instantly.
 *
 * @param h Handle to the service.
 */
static void
do_disconnect (struct GNUNET_PEERSTORE_Handle *h)
{
  if (NULL != h->mq)
  {
    GNUNET_MQ_destroy (h->mq);
    h->mq = NULL;
  }
  if (NULL != h->client)
  {
    GNUNET_CLIENT_disconnect (h->client);
    h->client = NULL;
  }
  GNUNET_free (h);
}


/**
 * Connect to the PEERSTORE service.
 *
 * @param cfg configuration to use
 * @return NULL on error
 */
struct GNUNET_PEERSTORE_Handle *
GNUNET_PEERSTORE_connect (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_PEERSTORE_Handle *h;

  h = GNUNET_new (struct GNUNET_PEERSTORE_Handle);

  h->client = GNUNET_CLIENT_connect ("peerstore", cfg);
  if (NULL == h->client)
  {
    GNUNET_free (h);
    return NULL;
  }
  h->cfg = cfg;
  h->disconnecting = GNUNET_NO;
  h->mq =
      GNUNET_MQ_queue_for_connection_client (h->client, mq_handlers,
                                             &handle_client_error, h);
  if (NULL == h->mq)
  {
    GNUNET_CLIENT_disconnect (h->client);
    GNUNET_free (h);
    return NULL;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "New connection created\n");
  return h;
}


/**
 * Disconnect from the PEERSTORE service. Any pending ITERATE and WATCH requests
 * will be canceled.
 * Any pending STORE requests will depend on @e snyc_first flag.
 *
 * @param h handle to disconnect
 * @param sync_first send any pending STORE requests before disconnecting
 */
void
GNUNET_PEERSTORE_disconnect (struct GNUNET_PEERSTORE_Handle *h, int sync_first)
{
  struct GNUNET_PEERSTORE_IterateContext *ic;
  struct GNUNET_PEERSTORE_IterateContext *ic_iter;
  struct GNUNET_PEERSTORE_StoreContext *sc;
  struct GNUNET_PEERSTORE_StoreContext *sc_iter;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Disconnecting.\n");
  if (NULL != h->watches)
  {
    GNUNET_CONTAINER_multihashmap_iterate (h->watches, &destroy_watch, NULL);
    GNUNET_CONTAINER_multihashmap_destroy (h->watches);
    h->watches = NULL;
  }
  ic_iter = h->iterate_head;
  while (NULL != ic_iter)
  {
    GNUNET_break (0);
    ic = ic_iter;
    ic_iter = ic_iter->next;
    GNUNET_PEERSTORE_iterate_cancel (ic);
  }
  if (NULL != h->store_head)
  {
    if (GNUNET_YES == sync_first)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Delaying disconnection due to pending store requests.\n");
      h->disconnecting = GNUNET_YES;
      return;
    }
    sc_iter = h->store_head;
    while (NULL != sc_iter)
    {
      sc = sc_iter;
      sc_iter = sc_iter->next;
      GNUNET_PEERSTORE_store_cancel (sc);
    }
  }
  do_disconnect (h);
}


/******************************************************************************/
/*******************            STORE FUNCTIONS           *********************/
/******************************************************************************/


/**
 * Cancel a store request
 *
 * @param sc Store request context
 */
void
GNUNET_PEERSTORE_store_cancel (struct GNUNET_PEERSTORE_StoreContext *sc)
{
  struct GNUNET_PEERSTORE_Handle *h = sc->h;

  if (NULL != sc->ev)
  {
    GNUNET_MQ_send_cancel (sc->ev);
    sc->ev = NULL;
  }
  GNUNET_CONTAINER_DLL_remove (sc->h->store_head, sc->h->store_tail, sc);
  GNUNET_free (sc->sub_system);
  GNUNET_free (sc->value);
  GNUNET_free (sc->key);
  GNUNET_free (sc);
  if ((GNUNET_YES == h->disconnecting) && (NULL == h->store_head))
    do_disconnect (h);
}


/**
 * Store a new entry in the PEERSTORE.
 * Note that stored entries can be lost in some cases
 * such as power failure.
 *
 * @param h Handle to the PEERSTORE service
 * @param sub_system name of the sub system
 * @param peer Peer Identity
 * @param key entry key
 * @param value entry value BLOB
 * @param size size of @e value
 * @param expiry absolute time after which the entry is (possibly) deleted
 * @param options options specific to the storage operation
 * @param cont Continuation function after the store request is sent
 * @param cont_cls Closure for @a cont
 */
struct GNUNET_PEERSTORE_StoreContext *
GNUNET_PEERSTORE_store (struct GNUNET_PEERSTORE_Handle *h,
                        const char *sub_system,
                        const struct GNUNET_PeerIdentity *peer, const char *key,
                        const void *value, size_t size,
                        struct GNUNET_TIME_Absolute expiry,
                        enum GNUNET_PEERSTORE_StoreOption options,
                        GNUNET_PEERSTORE_Continuation cont, void *cont_cls)
{
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_PEERSTORE_StoreContext *sc;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Storing value (size: %lu) for subsytem `%s', peer `%s', key `%s'\n",
       size, sub_system, GNUNET_i2s (peer), key);
  ev = PEERSTORE_create_record_mq_envelope (sub_system, peer, key, value, size,
                                            &expiry, options,
                                            GNUNET_MESSAGE_TYPE_PEERSTORE_STORE);
  sc = GNUNET_new (struct GNUNET_PEERSTORE_StoreContext);

  sc->sub_system = GNUNET_strdup (sub_system);
  sc->peer = *peer;
  sc->key = GNUNET_strdup (key);
  sc->value = GNUNET_memdup (value, size);
  sc->size = size;
  sc->expiry = expiry;
  sc->options = options;
  sc->cont = cont;
  sc->cont_cls = cont_cls;
  sc->h = h;

  GNUNET_CONTAINER_DLL_insert_tail (h->store_head, h->store_tail, sc);
  GNUNET_MQ_notify_sent (ev, &store_request_sent, sc);
  GNUNET_MQ_send (h->mq, ev);
  return sc;

}


/******************************************************************************/
/*******************           ITERATE FUNCTIONS          *********************/
/******************************************************************************/

/**
 * When a response for iterate request is received
 *
 * @param cls a `struct GNUNET_PEERSTORE_Handle *`
 * @param msg message received, NULL on timeout or fatal error
 */
static void
handle_iterate_result (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_PEERSTORE_Handle *h = cls;
  struct GNUNET_PEERSTORE_IterateContext *ic;
  GNUNET_PEERSTORE_Processor callback;
  void *callback_cls;
  uint16_t msg_type;
  struct GNUNET_PEERSTORE_Record *record;
  int continue_iter;

  ic = h->iterate_head;
  if (NULL == ic)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Unexpected iteration response, this should not happen.\n"));
    reconnect (h);
    return;
  }
  callback = ic->callback;
  callback_cls = ic->callback_cls;
  if (NULL == msg)              /* Connection error */
  {
    if (NULL != callback)
      callback (callback_cls, NULL,
                _("Error communicating with `PEERSTORE' service."));
    reconnect (h);
    return;
  }
  msg_type = ntohs (msg->type);
  if (GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATE_END == msg_type)
  {
    ic->iterating = GNUNET_NO;
    GNUNET_PEERSTORE_iterate_cancel (ic);
    if (NULL != callback)
      callback (callback_cls, NULL, NULL);
    return;
  }
  if (NULL != callback)
  {
    record = PEERSTORE_parse_record_message (msg);
    if (NULL == record)
      continue_iter =
          callback (callback_cls, NULL,
                    _("Received a malformed response from service."));
    else
    {
      continue_iter = callback (callback_cls, record, NULL);
      PEERSTORE_destroy_record (record);
    }
    if (GNUNET_NO == continue_iter)
      ic->callback = NULL;
  }
}


/**
 * Cancel an iterate request
 * Please do not call after the iterate request is done
 *
 * @param ic Iterate request context as returned by GNUNET_PEERSTORE_iterate()
 */
void
GNUNET_PEERSTORE_iterate_cancel (struct GNUNET_PEERSTORE_IterateContext *ic)
{
  if (GNUNET_SCHEDULER_NO_TASK != ic->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (ic->timeout_task);
    ic->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (GNUNET_NO == ic->iterating)
  {
    if (NULL != ic->ev)
    {
      GNUNET_MQ_send_cancel (ic->ev);
      ic->ev = NULL;
    }
    GNUNET_CONTAINER_DLL_remove (ic->h->iterate_head, ic->h->iterate_tail, ic);
    GNUNET_free (ic->sub_system);
    if (NULL != ic->key)
      GNUNET_free (ic->key);
    GNUNET_free (ic);
  }
  else
    ic->callback = NULL;
}


/**
 * Iterate over records matching supplied key information
 *
 * @param h handle to the PEERSTORE service
 * @param sub_system name of sub system
 * @param peer Peer identity (can be NULL)
 * @param key entry key string (can be NULL)
 * @param timeout time after which the iterate request is canceled
 * @param callback function called with each matching record, all NULL's on end
 * @param callback_cls closure for @a callback
 * @return Handle to iteration request
 */
struct GNUNET_PEERSTORE_IterateContext *
GNUNET_PEERSTORE_iterate (struct GNUNET_PEERSTORE_Handle *h,
                          const char *sub_system,
                          const struct GNUNET_PeerIdentity *peer,
                          const char *key, struct GNUNET_TIME_Relative timeout,
                          GNUNET_PEERSTORE_Processor callback,
                          void *callback_cls)
{
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_PEERSTORE_IterateContext *ic;

  ev = PEERSTORE_create_record_mq_envelope (sub_system, peer, key, NULL, 0,
                                            NULL, 0,
                                            GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATE);
  ic = GNUNET_new (struct GNUNET_PEERSTORE_IterateContext);

  ic->callback = callback;
  ic->callback_cls = callback_cls;
  ic->ev = ev;
  ic->h = h;
  ic->sub_system = GNUNET_strdup (sub_system);
  if (NULL != peer)
    ic->peer = *peer;
  if (NULL != key)
    ic->key = GNUNET_strdup (key);
  ic->timeout = timeout;
  ic->iterating = GNUNET_NO;
  GNUNET_CONTAINER_DLL_insert_tail (h->iterate_head, h->iterate_tail, ic);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending an iterate request for sub system `%s'\n", sub_system);
  GNUNET_MQ_notify_sent (ev, &iterate_request_sent, ic);
  GNUNET_MQ_send (h->mq, ev);
  ic->timeout_task =
      GNUNET_SCHEDULER_add_delayed (timeout, &iterate_timeout, ic);
  return ic;
}


/******************************************************************************/
/*******************            WATCH FUNCTIONS           *********************/
/******************************************************************************/

/**
 * When a watch record is received
 *
 * @param cls a `struct GNUNET_PEERSTORE_Handle *`
 * @param msg message received, NULL on timeout or fatal error
 */
static void
handle_watch_result (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_PEERSTORE_Handle *h = cls;
  struct GNUNET_PEERSTORE_Record *record;
  struct GNUNET_HashCode keyhash;
  struct GNUNET_PEERSTORE_WatchContext *wc;

  if (NULL == msg)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _
         ("Problem receiving a watch response, no way to determine which request.\n"));
    reconnect (h);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Received a watch record from service.\n");
  record = PEERSTORE_parse_record_message (msg);
  PEERSTORE_hash_key (record->sub_system, record->peer, record->key, &keyhash);
  wc = GNUNET_CONTAINER_multihashmap_get (h->watches, &keyhash);
  if (NULL == wc)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Received a watch result for a non existing watch.\n"));
    PEERSTORE_destroy_record (record);
    reconnect (h);
    return;
  }
  if (NULL != wc->callback)
    wc->callback (wc->callback_cls, record, NULL);
  PEERSTORE_destroy_record (record);
}


/**
 * Cancel a watch request
 *
 * @param wc handle to the watch request
 */
void
GNUNET_PEERSTORE_watch_cancel (struct GNUNET_PEERSTORE_WatchContext *wc)
{
  struct GNUNET_PEERSTORE_Handle *h = wc->h;
  struct GNUNET_MQ_Envelope *ev;
  struct StoreKeyHashMessage *hm;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Canceling watch.\n");
  if (GNUNET_YES == wc->request_sent)   /* If request already sent to service, send a cancel request. */
  {
    ev = GNUNET_MQ_msg (hm, GNUNET_MESSAGE_TYPE_PEERSTORE_WATCH_CANCEL);
    hm->keyhash = wc->keyhash;
    GNUNET_MQ_send (h->mq, ev);
    wc->callback = NULL;
    wc->callback_cls = NULL;
  }
  if (NULL != wc->ev)
  {
    GNUNET_MQ_send_cancel (wc->ev);
    wc->ev = NULL;
  }
  GNUNET_CONTAINER_multihashmap_remove (h->watches, &wc->keyhash, wc);
  GNUNET_free (wc);

}


/**
 * Request watching a given key
 * User will be notified with any new values added to key
 *
 * @param h handle to the PEERSTORE service
 * @param sub_system name of sub system
 * @param peer Peer identity
 * @param key entry key string
 * @param callback function called with each new value
 * @param callback_cls closure for @a callback
 * @return Handle to watch request
 */
struct GNUNET_PEERSTORE_WatchContext *
GNUNET_PEERSTORE_watch (struct GNUNET_PEERSTORE_Handle *h,
                        const char *sub_system,
                        const struct GNUNET_PeerIdentity *peer, const char *key,
                        GNUNET_PEERSTORE_Processor callback, void *callback_cls)
{
  struct GNUNET_MQ_Envelope *ev;
  struct StoreKeyHashMessage *hm;
  struct GNUNET_PEERSTORE_WatchContext *wc;

  GNUNET_assert (NULL != sub_system);
  GNUNET_assert (NULL != peer);
  GNUNET_assert (NULL != key);
  ev = GNUNET_MQ_msg (hm, GNUNET_MESSAGE_TYPE_PEERSTORE_WATCH);
  PEERSTORE_hash_key (sub_system, peer, key, &hm->keyhash);
  wc = GNUNET_new (struct GNUNET_PEERSTORE_WatchContext);

  wc->callback = callback;
  wc->callback_cls = callback_cls;
  wc->ev = ev;
  wc->h = h;
  wc->request_sent = GNUNET_NO;
  wc->keyhash = hm->keyhash;
  if (NULL == h->watches)
    h->watches = GNUNET_CONTAINER_multihashmap_create (5, GNUNET_NO);
  GNUNET_CONTAINER_multihashmap_put (h->watches, &wc->keyhash, wc,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending a watch request for ss `%s', peer `%s', key `%s'.\n",
       sub_system, GNUNET_i2s (peer), key);
  GNUNET_MQ_notify_sent (ev, &watch_request_sent, wc);
  GNUNET_MQ_send (h->mq, ev);
  return wc;
}

/* end of peerstore_api.c */
