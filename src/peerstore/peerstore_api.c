/*
     This file is part of GNUnet.
     Copyright (C) 2013-2016 GNUnet e.V.

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
   * Callback with each matching record
   */
  GNUNET_PEERSTORE_Processor callback;

  /**
   * Closure for @e callback
   */
  void *callback_cls;

  /**
   * #GNUNET_YES if we are currently processing records.
   */
  int iterating;

  /**
   * Task identifier for the function called
   * on iterate request timeout
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

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

};

/******************************************************************************/
/*******************             DECLARATIONS             *********************/
/******************************************************************************/

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
 * @param cls a `struct GNUNET_PEERSTORE_StoreContext *`
 */
static void
store_request_sent (void *cls)
{
  struct GNUNET_PEERSTORE_StoreContext *sc = cls;
  GNUNET_PEERSTORE_Continuation cont;
  void *cont_cls;

  cont = sc->cont;
  cont_cls = sc->cont_cls;
  GNUNET_PEERSTORE_store_cancel (sc);
  if (NULL != cont)
    cont (cont_cls, GNUNET_OK);
}


/******************************************************************************/
/*******************         CONNECTION FUNCTIONS         *********************/
/******************************************************************************/

static void
handle_client_error (void *cls,
                     enum GNUNET_MQ_Error error)
{
  struct GNUNET_PEERSTORE_Handle *h = cls;

  LOG (GNUNET_ERROR_TYPE_ERROR,
       _("Received an error notification from MQ of type: %d\n"),
       error);
  reconnect (h);
}


/**
 * Iterator over previous watches to resend them
 *
 * @param cls the `struct GNUNET_PEERSTORE_Handle`
 * @param key key for the watch
 * @param value the `struct GNUNET_PEERSTORE_WatchContext *`
 * @return #GNUNET_YES (continue to iterate)
 */
static int
rewatch_it (void *cls,
	    const struct GNUNET_HashCode *key,
	    void *value)
{
  struct GNUNET_PEERSTORE_Handle *h = cls;
  struct GNUNET_PEERSTORE_WatchContext *wc = value;
  struct StoreKeyHashMessage *hm;
  struct GNUNET_MQ_Envelope *ev;

  ev = GNUNET_MQ_msg (hm, GNUNET_MESSAGE_TYPE_PEERSTORE_WATCH);
  hm->keyhash = wc->keyhash;
  GNUNET_MQ_send (h->mq, ev);
  return GNUNET_YES;
}


/**
 * Called when the iterate request is timedout
 *
 * @param cls a `struct GNUNET_PEERSTORE_IterateContext *`
 */
static void
iterate_timeout (void *cls)
{
  struct GNUNET_PEERSTORE_IterateContext *ic = cls;
  GNUNET_PEERSTORE_Processor callback;
  void *callback_cls;

  ic->timeout_task = NULL;
  callback = ic->callback;
  callback_cls = ic->callback_cls;
  GNUNET_PEERSTORE_iterate_cancel (ic);
  if (NULL != callback)
    callback (callback_cls, NULL, _("timeout"));
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
destroy_watch (void *cls,
               const struct GNUNET_HashCode *key,
               void *value)
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
  h->cfg = cfg;
  h->disconnecting = GNUNET_NO;
  reconnect (h);
  if (NULL == h->mq)
  {
    GNUNET_free (h);
    return NULL;
  }
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
GNUNET_PEERSTORE_disconnect (struct GNUNET_PEERSTORE_Handle *h,
                             int sync_first)
{
  struct GNUNET_PEERSTORE_IterateContext *ic;
  struct GNUNET_PEERSTORE_StoreContext *sc;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Disconnecting.\n");
  if (NULL != h->watches)
  {
    GNUNET_CONTAINER_multihashmap_iterate (h->watches, &destroy_watch, NULL);
    GNUNET_CONTAINER_multihashmap_destroy (h->watches);
    h->watches = NULL;
  }
  while (NULL != (ic = h->iterate_head))
  {
    GNUNET_break (0);
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
    while (NULL != (sc = h->store_head))
      GNUNET_PEERSTORE_store_cancel (sc);
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
                        const struct GNUNET_PeerIdentity *peer,
                        const char *key,
                        const void *value, size_t size,
                        struct GNUNET_TIME_Absolute expiry,
                        enum GNUNET_PEERSTORE_StoreOption options,
                        GNUNET_PEERSTORE_Continuation cont,
                        void *cont_cls)
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
 * @param msg message received
 */
static void
handle_iterate_end (void *cls,
                    const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_PEERSTORE_Handle *h = cls;
  struct GNUNET_PEERSTORE_IterateContext *ic;
  GNUNET_PEERSTORE_Processor callback;
  void *callback_cls;

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
  ic->iterating = GNUNET_NO;
  GNUNET_PEERSTORE_iterate_cancel (ic);
  if (NULL != callback)
    callback (callback_cls, NULL, NULL);
}


/**
 * When a response for iterate request is received, check the
 * message is well-formed.
 *
 * @param cls a `struct GNUNET_PEERSTORE_Handle *`
 * @param msg message received
 */
static int
check_iterate_result (void *cls,
                      const struct GNUNET_MessageHeader *msg)
{
  /* we defer validation to #handle_iterate_result */
  return GNUNET_OK;
}


/**
 * When a response for iterate request is received
 *
 * @param cls a `struct GNUNET_PEERSTORE_Handle *`
 * @param msg message received
 */
static void
handle_iterate_result (void *cls,
                       const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_PEERSTORE_Handle *h = cls;
  struct GNUNET_PEERSTORE_IterateContext *ic;
  GNUNET_PEERSTORE_Processor callback;
  void *callback_cls;
  struct GNUNET_PEERSTORE_Record *record;

  ic = h->iterate_head;
  if (NULL == ic)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Unexpected iteration response, this should not happen.\n"));
    reconnect (h);
    return;
  }
  ic->iterating = GNUNET_YES;
  callback = ic->callback;
  callback_cls = ic->callback_cls;
  if (NULL == callback)
    return;
  record = PEERSTORE_parse_record_message (msg);
  if (NULL == record)
  {
    callback (callback_cls,
              NULL,
              _("Received a malformed response from service."));
  }
  else
  {
    callback (callback_cls,
              record,
              NULL);
    PEERSTORE_destroy_record (record);
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
  if (NULL != ic->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (ic->timeout_task);
    ic->timeout_task = NULL;
  }
  if (GNUNET_NO == ic->iterating)
  {
    GNUNET_CONTAINER_DLL_remove (ic->h->iterate_head,
                                 ic->h->iterate_tail,
                                 ic);
    GNUNET_free (ic->sub_system);
    GNUNET_free_non_null (ic->key);
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
                          const char *key,
                          struct GNUNET_TIME_Relative timeout,
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
  ic->h = h;
  ic->sub_system = GNUNET_strdup (sub_system);
  if (NULL != peer)
    ic->peer = *peer;
  if (NULL != key)
    ic->key = GNUNET_strdup (key);
  ic->timeout = timeout;
  GNUNET_CONTAINER_DLL_insert_tail (h->iterate_head,
                                    h->iterate_tail,
                                    ic);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending an iterate request for sub system `%s'\n",
       sub_system);
  GNUNET_MQ_send (h->mq, ev);
  ic->timeout_task =
      GNUNET_SCHEDULER_add_delayed (timeout,
                                    &iterate_timeout,
                                    ic);
  return ic;
}


/******************************************************************************/
/*******************            WATCH FUNCTIONS           *********************/
/******************************************************************************/

/**
 * When a watch record is received, validate it is well-formed.
 *
 * @param cls a `struct GNUNET_PEERSTORE_Handle *`
 * @param msg message received
 */
static int
check_watch_record (void *cls,
                    const struct GNUNET_MessageHeader *msg)
{
  /* we defer validation to #handle_watch_result */
  return GNUNET_OK;
}


/**
 * When a watch record is received, process it.
 *
 * @param cls a `struct GNUNET_PEERSTORE_Handle *`
 * @param msg message received
 */
static void
handle_watch_record (void *cls,
                     const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_PEERSTORE_Handle *h = cls;
  struct GNUNET_PEERSTORE_Record *record;
  struct GNUNET_HashCode keyhash;
  struct GNUNET_PEERSTORE_WatchContext *wc;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received a watch record from service.\n");
  record = PEERSTORE_parse_record_message (msg);
  if (NULL == record)
  {
    reconnect (h);
    return;
  }
  PEERSTORE_hash_key (record->sub_system,
                      record->peer,
                      record->key,
                      &keyhash);
  // FIXME: what if there are multiple watches for the same key?
  wc = GNUNET_CONTAINER_multihashmap_get (h->watches,
                                          &keyhash);
  if (NULL == wc)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Received a watch result for a non existing watch.\n"));
    PEERSTORE_destroy_record (record);
    reconnect (h);
    return;
  }
  if (NULL != wc->callback)
    wc->callback (wc->callback_cls,
                  record,
                  NULL);
  PEERSTORE_destroy_record (record);
}


/**
 * Close the existing connection to PEERSTORE and reconnect.
 *
 * @param h handle to the service
 */
static void
reconnect (struct GNUNET_PEERSTORE_Handle *h)
{
  GNUNET_MQ_hd_fixed_size (iterate_end,
                           GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATE_END,
                           struct GNUNET_MessageHeader);
  GNUNET_MQ_hd_var_size (iterate_result,
                         GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATE_RECORD,
                         struct GNUNET_MessageHeader);
  GNUNET_MQ_hd_var_size (watch_record,
                         GNUNET_MESSAGE_TYPE_PEERSTORE_WATCH_RECORD,
                         struct GNUNET_MessageHeader);
  struct GNUNET_MQ_MessageHandler mq_handlers[] = {
    make_iterate_end_handler (h),
    make_iterate_result_handler (h),
    make_watch_record_handler (h),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_PEERSTORE_IterateContext *ic;
  struct GNUNET_PEERSTORE_IterateContext *next;
  GNUNET_PEERSTORE_Processor icb;
  void *icb_cls;
  struct GNUNET_PEERSTORE_StoreContext *sc;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_CLIENT_Connection *client;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Reconnecting...\n");
  for (ic = h->iterate_head; NULL != ic; ic = next)
  {
    next = ic->next;
    if (GNUNET_YES == ic->iterating)
    {
      icb = ic->callback;
      icb_cls = ic->callback_cls;
      GNUNET_PEERSTORE_iterate_cancel (ic);
      if (NULL != icb)
        icb (icb_cls,
             NULL,
             "Iteration canceled due to reconnection");
    }
  }
  if (NULL != h->mq)
  {
    GNUNET_MQ_destroy (h->mq);
    h->mq = NULL;
  }
  client = GNUNET_CLIENT_connect ("peerstore",
                                  h->cfg);
  if (NULL == client)
    return;
  h->mq = GNUNET_MQ_queue_for_connection_client (client,
                                                 mq_handlers,
                                                 &handle_client_error, h);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Resending pending requests after reconnect.\n");
  if (NULL != h->watches)
    GNUNET_CONTAINER_multihashmap_iterate (h->watches,
                                           &rewatch_it,
                                           h);
  for (ic = h->iterate_head; NULL != ic; ic = ic->next)
  {
    ev = PEERSTORE_create_record_mq_envelope (ic->sub_system,
                                              &ic->peer,
                                              ic->key,
                                              NULL, 0,
                                              NULL, 0,
                                              GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATE);
    GNUNET_MQ_send (h->mq, ev);
    ic->timeout_task
      = GNUNET_SCHEDULER_add_delayed (ic->timeout,
                                      &iterate_timeout,
                                      ic);
  }
  for (sc = h->store_head; NULL != sc; sc = sc->next)
  {
    ev = PEERSTORE_create_record_mq_envelope (sc->sub_system,
                                              &sc->peer,
                                              sc->key,
                                              sc->value,
                                              sc->size,
                                              &sc->expiry,
                                              sc->options,
                                              GNUNET_MESSAGE_TYPE_PEERSTORE_STORE);
    GNUNET_MQ_notify_sent (ev,
                           &store_request_sent,
                           sc);
    GNUNET_MQ_send (h->mq,
                    ev);
  }
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

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Canceling watch.\n");
  ev = GNUNET_MQ_msg (hm,
                      GNUNET_MESSAGE_TYPE_PEERSTORE_WATCH_CANCEL);
  hm->keyhash = wc->keyhash;
  GNUNET_MQ_send (h->mq, ev);
  GNUNET_CONTAINER_multihashmap_remove (h->watches,
                                        &wc->keyhash,
                                        wc);
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
                        const struct GNUNET_PeerIdentity *peer,
                        const char *key,
                        GNUNET_PEERSTORE_Processor callback,
                        void *callback_cls)
{
  struct GNUNET_MQ_Envelope *ev;
  struct StoreKeyHashMessage *hm;
  struct GNUNET_PEERSTORE_WatchContext *wc;

  ev = GNUNET_MQ_msg (hm,
                      GNUNET_MESSAGE_TYPE_PEERSTORE_WATCH);
  PEERSTORE_hash_key (sub_system,
                      peer,
                      key,
                      &hm->keyhash);
  wc = GNUNET_new (struct GNUNET_PEERSTORE_WatchContext);
  wc->callback = callback;
  wc->callback_cls = callback_cls;
  wc->h = h;
  wc->keyhash = hm->keyhash;
  if (NULL == h->watches)
    h->watches = GNUNET_CONTAINER_multihashmap_create (5, GNUNET_NO);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap_put (h->watches,
                                                    &wc->keyhash,
                                                    wc,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending a watch request for ss `%s', peer `%s', key `%s'.\n",
       sub_system,
       GNUNET_i2s (peer),
       key);
  GNUNET_MQ_send (h->mq, ev);
  return wc;
}

/* end of peerstore_api.c */
