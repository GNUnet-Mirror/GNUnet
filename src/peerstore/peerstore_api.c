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

};

/**
 * Context for a store request
 */
struct GNUNET_PEERSTORE_StoreContext
{

  /**
   * Handle to the PEERSTORE service.
   */
  struct GNUNET_PEERSTORE_Handle *h;

  /**
   * Continuation called with service response
   */
  GNUNET_PEERSTORE_Continuation cont;

  /**
   * Closure for 'cont'
   */
  void *cont_cls;

};

/******************************************************************************/
/*******************         CONNECTION FUNCTIONS         *********************/
/******************************************************************************/

/**
 * Close the existing connection to PEERSTORE and reconnect.
 *
 * @param h handle to the service
 */
static void
reconnect (struct GNUNET_PEERSTORE_Handle *h)
{

  LOG(GNUNET_ERROR_TYPE_DEBUG, "Reconnecting...\n");
  if (NULL != h->client)
  {
    GNUNET_CLIENT_disconnect (h->client);
    h->client = NULL;
  }
  h->client = GNUNET_CLIENT_connect ("peerstore", h->cfg);

}

/**
 * Connect to the PEERSTORE service.
 *
 * @return NULL on error
 */
struct GNUNET_PEERSTORE_Handle *
GNUNET_PEERSTORE_connect (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_CLIENT_Connection *client;
  struct GNUNET_PEERSTORE_Handle *h;

  client = GNUNET_CLIENT_connect ("peerstore", cfg);
  if(NULL == client)
    return NULL;
  h = GNUNET_new (struct GNUNET_PEERSTORE_Handle);
  h->client = client;
  h->cfg = cfg;
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
  if (NULL != h->client)
  {
    GNUNET_CLIENT_disconnect (h->client);
    h->client = NULL;
  }
  GNUNET_free(h);
  LOG(GNUNET_ERROR_TYPE_DEBUG, "Disconnected, BYE!\n");
}


/******************************************************************************/
/*******************             ADD FUNCTIONS            *********************/
/******************************************************************************/

/**
 * When a response for store request is received
 *
 * @param cls a 'struct GNUNET_PEERSTORE_StoreContext *'
 * @param msg message received, NULL on timeout or fatal error
 */
void store_response_receiver (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_PEERSTORE_StoreContext *sc = cls;
  uint16_t msg_type;

  if(NULL == sc->cont)
    return;
  if(NULL == msg)
  {
    sc->cont(sc->cont_cls, GNUNET_SYSERR);
    reconnect(sc->h);
    return;
  }
  msg_type = ntohs(msg->type);
  if(GNUNET_MESSAGE_TYPE_PEERSTORE_STORE_RESULT_OK == msg_type)
    sc->cont(sc->cont_cls, GNUNET_OK);
  else if(GNUNET_MESSAGE_TYPE_PEERSTORE_STORE_RESULT_FAIL == msg_type)
    sc->cont(sc->cont_cls, GNUNET_SYSERR);
  else
  {
    LOG(GNUNET_ERROR_TYPE_ERROR, "Invalid response from `PEERSTORE' service.\n");
    sc->cont(sc->cont_cls, GNUNET_SYSERR);
  }

}

/**
 * Cancel a store request
 *
 * @param sc Store request context
 */
void
GNUNET_PEERSTORE_store_cancel (struct GNUNET_PEERSTORE_StoreContext *sc)
{
  sc->cont = NULL;
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
  struct GNUNET_PEERSTORE_StoreContext *sc;
  struct StoreRecordMessage *srm;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Storing value (size: %lu) for subsytem `%s', peer `%s', key `%s'\n",
      size, sub_system, GNUNET_i2s (peer), key);
  sc = GNUNET_new(struct GNUNET_PEERSTORE_StoreContext);
  sc->cont = cont;
  sc->cont_cls = cont_cls;
  sc->h = h;
  srm = PEERSTORE_create_record_message(sub_system,
      peer,
      key,
      value,
      size,
      expiry,
      GNUNET_MESSAGE_TYPE_PEERSTORE_STORE);
  GNUNET_CLIENT_transmit_and_get_response(h->client,
      (const struct GNUNET_MessageHeader *)srm,
      GNUNET_TIME_UNIT_FOREVER_REL,
      GNUNET_YES,
      &store_response_receiver,
      sc);
  return sc;

}

/* end of peerstore_api.c */
