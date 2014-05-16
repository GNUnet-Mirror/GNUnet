/*
     This file is part of GNUnet.
     (C) 

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
   * MQ Envelope with store request message
   */
  struct GNUNET_MQ_Envelope *ev;

  /**
   * Continuation called with service response
   */
  GNUNET_PEERSTORE_Continuation cont;

  /**
   * Closure for 'cont'
   */
  void *cont_cls;

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
 * When a response for store request is received
 *
 * @param cls a 'struct GNUNET_PEERSTORE_StoreContext *'
 * @param msg message received, NULL on timeout or fatal error
 */
void handle_store_result (void *cls, const struct GNUNET_MessageHeader *msg);

static void
reconnect (struct GNUNET_PEERSTORE_Handle *h);

/**
 * MQ message handlers
 */
static const struct GNUNET_MQ_MessageHandler mq_handlers[] = {
    {&handle_store_result, GNUNET_MESSAGE_TYPE_PEERSTORE_STORE_RESULT_OK, sizeof(struct GNUNET_MessageHeader)},
    {&handle_store_result, GNUNET_MESSAGE_TYPE_PEERSTORE_STORE_RESULT_FAIL, sizeof(struct GNUNET_MessageHeader)},
    GNUNET_MQ_HANDLERS_END
};

/******************************************************************************/
/*******************         CONNECTION FUNCTIONS         *********************/
/******************************************************************************/

static void
handle_client_error (void *cls, enum GNUNET_MQ_Error error)
{
  struct GNUNET_PEERSTORE_Handle *h = cls;

  GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Received an error notification from MQ of type: %d\n", error);
  reconnect(h);
}

/**
 * Close the existing connection to PEERSTORE and reconnect.
 *
 * @param h handle to the service
 */
static void
reconnect (struct GNUNET_PEERSTORE_Handle *h)
{

  LOG(GNUNET_ERROR_TYPE_DEBUG, "Reconnecting...\n");
  if (NULL != h->mq)
  {
    GNUNET_MQ_destroy(h->mq);
    h->mq = NULL;
  }
  if (NULL != h->client)
  {
    GNUNET_CLIENT_disconnect (h->client);
    h->client = NULL;
  }
  h->client = GNUNET_CLIENT_connect ("peerstore", h->cfg);
  h->mq = GNUNET_MQ_queue_for_connection_client(h->client,
      mq_handlers,
      &handle_client_error,
      h);

}

/**
 * Connect to the PEERSTORE service.
 *
 * @return NULL on error
 */
struct GNUNET_PEERSTORE_Handle *
GNUNET_PEERSTORE_connect (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_PEERSTORE_Handle *h;

  h = GNUNET_new (struct GNUNET_PEERSTORE_Handle);
  h->client = GNUNET_CLIENT_connect ("peerstore", cfg);
  if(NULL == h->client)
  {
    GNUNET_free(h);
    return NULL;
  }
  h->cfg = cfg;
  h->mq = GNUNET_MQ_queue_for_connection_client(h->client,
      mq_handlers,
      &handle_client_error,
      h);
  if(NULL == h->mq)
  {
    GNUNET_free(h);
    return NULL;
  }
  LOG(GNUNET_ERROR_TYPE_DEBUG, "New connection created\n");
  return h;
}

/**
 * Disconnect from the PEERSTORE service
 * Do not call in case of pending requests
 *
 * @param h handle to disconnect
 */
void
GNUNET_PEERSTORE_disconnect(struct GNUNET_PEERSTORE_Handle *h)
{
  if(NULL != h->mq)
  {
    GNUNET_MQ_destroy(h->mq);
    h->mq = NULL;
  }
  if (NULL != h->client)
  {
    GNUNET_CLIENT_disconnect (h->client);
    h->client = NULL;
  }
  GNUNET_free(h);
  LOG(GNUNET_ERROR_TYPE_DEBUG, "Disconnected, BYE!\n");
}


/******************************************************************************/
/*******************            STORE FUNCTIONS           *********************/
/******************************************************************************/

/**
 * When a response for store request is received
 *
 * @param cls a 'struct GNUNET_PEERSTORE_StoreContext *'
 * @param msg message received, NULL on timeout or fatal error
 */
void handle_store_result (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_PEERSTORE_Handle *h = cls;
  struct GNUNET_PEERSTORE_StoreContext *sc;
  uint16_t msg_type;
  GNUNET_PEERSTORE_Continuation cont;
  void *cont_cls;

  sc = h->store_head;
  if(NULL == sc)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Unexpected store response, this should not happen.\n");
    reconnect(h);
    return;
  }
  cont = sc->cont;
  cont_cls = sc->cont_cls;
  GNUNET_CONTAINER_DLL_remove(h->store_head, h->store_tail, sc);
  GNUNET_free(sc);
  if(NULL == msg) /* Connection error */
  {
    if(NULL != cont)
      cont(cont_cls, GNUNET_SYSERR);
    reconnect(h);
    return;
  }
  if(NULL != cont) /* Run continuation */
  {
    msg_type = ntohs(msg->type);
    if(GNUNET_MESSAGE_TYPE_PEERSTORE_STORE_RESULT_OK == msg_type)
      cont(cont_cls, GNUNET_OK);
    else if(GNUNET_MESSAGE_TYPE_PEERSTORE_STORE_RESULT_FAIL == msg_type)
      cont(cont_cls, GNUNET_SYSERR);
  }

}

/**
 * Callback after MQ envelope is sent
 *
 * @param cls a 'struct GNUNET_PEERSTORE_StoreContext *'
 */
void store_request_sent (void *cls)
{
  struct GNUNET_PEERSTORE_StoreContext *sc = cls;

  sc->request_sent = GNUNET_YES;
}

/**
 * Cancel a store request
 *
 * @param sc Store request context
 */
void
GNUNET_PEERSTORE_store_cancel (struct GNUNET_PEERSTORE_StoreContext *sc)
{
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
          "Canceling store request.\n");
  if(GNUNET_NO == sc->request_sent)
  {
    if(NULL != sc->ev)
      GNUNET_MQ_discard(sc->ev);
    GNUNET_CONTAINER_DLL_remove(sc->h->store_head, sc->h->store_tail, sc);
    GNUNET_free(sc);
  }
  else
  { /* request already sent, will have to wait for response */
    sc->cont = NULL;
  }

}

/**
 * Store a new entry in the PEERSTORE
 *
 * @param h Handle to the PEERSTORE service
 * @param sub_system name of the sub system
 * @param peer Peer Identity
 * @param key entry key
 * @param value entry value BLOB
 * @param size size of 'value'
 * @param expiry absolute time after which the entry is (possibly) deleted
 * @param cont Continuation function after the store request is processed
 * @param cont_cls Closure for 'cont'
 */
struct GNUNET_PEERSTORE_StoreContext *
GNUNET_PEERSTORE_store (struct GNUNET_PEERSTORE_Handle *h,
    const char *sub_system,
    const struct GNUNET_PeerIdentity *peer,
    const char *key,
    const void *value,
    size_t size,
    struct GNUNET_TIME_Absolute expiry,
    GNUNET_PEERSTORE_Continuation cont,
    void *cont_cls)
{
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_PEERSTORE_StoreContext *sc;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Storing value (size: %lu) for subsytem `%s', peer `%s', key `%s'\n",
      size, sub_system, GNUNET_i2s (peer), key);
  ev = PEERSTORE_create_record_mq_envelope(sub_system,
      peer,
      key,
      value,
      size,
      expiry,
      GNUNET_MESSAGE_TYPE_PEERSTORE_STORE);
  GNUNET_MQ_send(h->mq, ev);
  GNUNET_MQ_notify_sent(ev, &store_request_sent, ev);
  sc = GNUNET_new(struct GNUNET_PEERSTORE_StoreContext);
  sc->ev = ev;
  sc->cont = cont;
  sc->cont_cls = cont_cls;
  sc->h = h;
  sc->request_sent = GNUNET_NO;
  GNUNET_CONTAINER_DLL_insert(h->store_head, h->store_tail, sc);
  return sc;

}

/* end of peerstore_api.c */
