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
   * Head of transmission queue.
   */
  struct GNUNET_PEERSTORE_RequestContext *rc_head;

  /**
   * Tail of transmission queue.
   */
  struct GNUNET_PEERSTORE_RequestContext *rc_tail;

  /**
   * Handle for the current transmission request, or NULL if none is pending.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * Head of store requests DLL.
   */
  struct GNUNET_PEERSTORE_StoreContext *sc_head;

  /**
   * Tail of store requests DLL.
   */
  struct GNUNET_PEERSTORE_StoreContext *sc_tail;

  /**
   * ID for a reconnect task.
   */
  GNUNET_SCHEDULER_TaskIdentifier r_task;

  /**
   * Are we now receiving?
   */
  int in_receive;

};

/**
 * Entry in the transmission queue to PEERSTORE service.
 *
 */
struct GNUNET_PEERSTORE_RequestContext
{
  /**
   * This is a linked list.
   */
  struct GNUNET_PEERSTORE_RequestContext *next;

  /**
   * This is a linked list.
   */
  struct GNUNET_PEERSTORE_RequestContext *prev;

  /**
   * Handle to the PEERSTORE service.
   */
  struct GNUNET_PEERSTORE_Handle *h;

  /**
   * Function to call after request has been transmitted, or NULL.
   */
  GNUNET_PEERSTORE_Continuation cont;

  /**
   * Closure for 'cont'.
   */
  void *cont_cls;

  /**
   * Number of bytes of the request message (follows after this struct).
   */
  size_t size;

};

/**
 * Context for a store request
 *
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
   * Our entry in the transmission queue.
   */
  struct GNUNET_PEERSTORE_RequestContext *rc;

  /**
   * Function to call with store operation result
   */
  GNUNET_PEERSTORE_Continuation cont;

  /**
   * Closure for 'cont'.
   */
  void *cont_cls;

  /**
   * Set to GNUNET_YES if we are currently receiving replies from the
   * service.
   */
  int request_transmitted;

};

/******************************************************************************/
/***********************         DECLARATIONS         *************************/
/******************************************************************************/

/**
 * Close the existing connection to PEERSTORE and reconnect.
 *
 * @param h handle to the service
 */
static void
reconnect (struct GNUNET_PEERSTORE_Handle *h);

/**
 * Check if we have a request pending in the transmission queue and are
 * able to transmit it right now.  If so, schedule transmission.
 *
 * @param h handle to the service
 */
static void
trigger_transmit (struct GNUNET_PEERSTORE_Handle *h);

/******************************************************************************/
/*******************         CONNECTION FUNCTIONS         *********************/
/******************************************************************************/

/**
 * Task scheduled to re-try connecting to the peerstore service.
 *
 * @param cls the 'struct GNUNET_PEERSTORE_Handle'
 * @param tc scheduler context
 */
static void
reconnect_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_PEERSTORE_Handle *h = cls;

  h->r_task = GNUNET_SCHEDULER_NO_TASK;
  reconnect (h);
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
  return h;
}

/**
 * Disconnect from the PEERSTORE service
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
  GNUNET_free (h);
}

/**
 * Close the existing connection to PEERSTORE and reconnect.
 *
 * @param h handle to the service
 */
static void
reconnect (struct GNUNET_PEERSTORE_Handle *h)
{
  if (GNUNET_SCHEDULER_NO_TASK != h->r_task)
  {
    GNUNET_SCHEDULER_cancel (h->r_task);
    h->r_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != h->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->th);
    h->th = NULL;
  }
  if (NULL != h->client)
  {
    GNUNET_CLIENT_disconnect (h->client);
    h->client = NULL;
  }
  h->client = GNUNET_CLIENT_connect ("peerstore", h->cfg);
  if (NULL == h->client)
  {
    h->r_task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &reconnect_task,
                                      h);
    return;
  }
  trigger_transmit (h);
}

/**
 * Transmit the request at the head of the transmission queue
 * and trigger continuation (if any).
 *
 * @param cls the 'struct GNUNET_PEERSTORE_Handle' (with the queue)
 * @param size size of the buffer (0 on error)
 * @param buf where to copy the message
 * @return number of bytes copied to buf
 */
static size_t
do_transmit (void *cls, size_t size, void *buf)
{
  struct GNUNET_PEERSTORE_Handle *h = cls;
  struct GNUNET_PEERSTORE_RequestContext *rc = h->rc_head;
  size_t ret;

  h->th = NULL;
  if (NULL == rc)
    return 0; /* request was canceled in the meantime */
  if (NULL == buf)
  {
    /* peerstore service died */
    LOG (GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
         "Failed to transmit message to `%s' service.\n", "PEERSTORE");
    GNUNET_CONTAINER_DLL_remove (h->rc_head, h->rc_tail, rc);
    reconnect (h);
    if (NULL != rc->cont)
      rc->cont (rc->cont_cls, _("failed to transmit request (service down?)"));
    GNUNET_free (rc);
    return 0;
  }
  ret = rc->size;
  if (size < ret)
  {
    /* change in head of queue (i.e. cancel + add), try again */
    trigger_transmit (h);
    return 0;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Transmitting request of size %u to `%s' service.\n", ret, "PEERSTORE");
  memcpy (buf, &rc[1], ret);
  GNUNET_CONTAINER_DLL_remove (h->rc_head, h->rc_tail, rc);
  trigger_transmit (h);
  if (NULL != rc->cont)
    rc->cont (rc->cont_cls, NULL);
  GNUNET_free (rc);
  return ret;
}

/**
 * Check if we have a request pending in the transmission queue and are
 * able to transmit it right now.  If so, schedule transmission.
 *
 * @param h handle to the service
 */
static void
trigger_transmit (struct GNUNET_PEERSTORE_Handle *h)
{
  struct GNUNET_PEERSTORE_RequestContext *rc;

  if (NULL == (rc = h->rc_head))
    return; /* no requests queued */
  if (NULL != h->th)
    return; /* request already pending */
  if (NULL == h->client)
  {
    /* disconnected, try to reconnect */
    reconnect (h);
    return;
  }
  h->th =
    GNUNET_CLIENT_notify_transmit_ready (h->client, rc->size,
           GNUNET_TIME_UNIT_FOREVER_REL,
           GNUNET_YES,
           &do_transmit, h);
}

/******************************************************************************/
/*******************           GENERAL FUNCTIONS          *********************/
/******************************************************************************/

/**
 * Function called with server response message
 * after a store operation is request
 *
 * @param cls a 'struct GNUNET_PEERSTORE_StoreContext'
 * @param msg message received, NULL on timeout or fatal error
 */
static void
peerstore_handler (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_PEERSTORE_Handle *h = cls;
  struct GNUNET_PEERSTORE_StoreContext *sc;
  struct StoreResponseMessage *srm;
  uint16_t response_type;
  uint16_t response_size;
  char *emsg;
  GNUNET_PEERSTORE_Continuation cont;
  void *cont_cls;

  h->in_receive = GNUNET_NO;
  if(NULL == msg)
  {
    reconnect(h);
    return;
  }
  response_type = ntohs(msg->type);
  response_size = ntohs(msg->size);
  LOG(GNUNET_ERROR_TYPE_DEBUG, "Received a response of type %lu from server\n", response_type);
  switch(response_type)
  {
  case GNUNET_MESSAGE_TYPE_PEERSTORE_STORE_RESULT:
    GNUNET_assert(response_size >= sizeof(struct GNUNET_MessageHeader) + sizeof(struct StoreResponseMessage));
    sc = h->sc_head;
    if(NULL == sc)
    {
      LOG(GNUNET_ERROR_TYPE_ERROR, "Received a response to a non-existent store request\n");
      return;
    }
    cont = sc->cont;
    cont_cls = sc->cont_cls;
    GNUNET_PEERSTORE_store_cancel(sc);
    trigger_transmit (h);
    if (NULL != h->sc_head)
    {
      h->in_receive = GNUNET_YES;
      GNUNET_CLIENT_receive (h->client,
          &peerstore_handler,
          h,
          GNUNET_TIME_UNIT_FOREVER_REL);
    }
    if(NULL != cont)
    {
      srm = (struct StoreResponseMessage *)&msg[1];
      emsg = NULL;
      if(GNUNET_NO == ntohs(srm->success))
      {
        LOG(GNUNET_ERROR_TYPE_DEBUG, "Calling user callback with message: %s\n", emsg);
        emsg = GNUNET_malloc(ntohs(srm->emsg_size));
        memcpy(emsg, &srm[1], ntohs(srm->emsg_size));
      }
      LOG(GNUNET_ERROR_TYPE_DEBUG, "Calling user callback without a message\n");
      cont(cont_cls, emsg);
    }
    break;
  }

}

/******************************************************************************/
/*******************             ADD FUNCTIONS            *********************/
/******************************************************************************/

/**
 * Cancel a store request
 *
 * @param sc Store request context
 */
void
GNUNET_PEERSTORE_store_cancel (struct GNUNET_PEERSTORE_StoreContext *sc)
{
  struct GNUNET_PEERSTORE_Handle *h;

  h = sc->h;
  sc->cont = NULL;
  if (GNUNET_YES == sc->request_transmitted)
    return;                     /* need to finish processing */
  GNUNET_CONTAINER_DLL_remove (h->sc_head,
             h->sc_tail,
             sc);
  if (NULL != sc->rc)
  {
    GNUNET_CONTAINER_DLL_remove (h->rc_head, h->rc_tail, sc->rc);
    GNUNET_free (sc->rc);
  }
  GNUNET_free (sc);
}

/**
 * Called after store request is sent
 * Waits for response from service
 *
 * @param cls a 'struct GNUNET_PEERSTORE_StoreContext'
 * @parma emsg error message (or NULL)
 */
void store_receive_result(void *cls, const char *emsg)
{
  struct GNUNET_PEERSTORE_StoreContext *sc = cls;
  struct GNUNET_PEERSTORE_Handle *h = sc->h;

  sc->rc = NULL;
  if(NULL != emsg)
  {
    GNUNET_PEERSTORE_store_cancel (sc);
    reconnect (h);
    if (NULL != sc->cont)
      sc->cont (sc->cont_cls, emsg);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Waiting for response from `%s' service.\n",
         "PEERSTORE");
  sc->request_transmitted = GNUNET_YES;
  if (GNUNET_NO == h->in_receive)
  {
    h->in_receive = GNUNET_YES;
    GNUNET_CLIENT_receive (h->client,
        &peerstore_handler,
        h,
        GNUNET_TIME_UNIT_FOREVER_REL);
  }
}

/**
 * Store a new entry in the PEERSTORE
 *
 * @param h Handle to the PEERSTORE service
 * @param peer Peer Identity
 * @param sub_system name of the sub system
 * @param value entry value BLOB
 * @param size size of 'value'
 * @param lifetime relative time after which the entry is (possibly) deleted
 * @param cont Continuation function after the store request is processed
 * @param cont_cls Closure for 'cont'
 */
struct GNUNET_PEERSTORE_StoreContext *
GNUNET_PEERSTORE_store (struct GNUNET_PEERSTORE_Handle *h,
    const struct GNUNET_PeerIdentity *peer,
    const char *sub_system,
    const void *value,
    size_t size,
    struct GNUNET_TIME_Relative lifetime,
    GNUNET_PEERSTORE_Continuation cont,
    void *cont_cls)
{
  struct GNUNET_PEERSTORE_RequestContext *rc;
  struct StoreRequestMessage *entry;
  struct GNUNET_PEERSTORE_StoreContext *sc;
  char *ss;
  void *val;
  size_t sub_system_size;
  size_t request_size;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Storing value (size: %lu) for subsytem `%s' and peer `%s'\n",
      size, sub_system, GNUNET_i2s (peer));
  sub_system_size = strlen(sub_system);
  request_size = sizeof(struct StoreRequestMessage) + sub_system_size + size;
  rc = GNUNET_malloc(sizeof(struct GNUNET_PEERSTORE_RequestContext) + request_size);
  rc->h = h;
  rc->size = request_size;
  entry = (struct StoreRequestMessage *)&rc[1];
  entry->header.size = htons(request_size);
  entry->header.type = htons(GNUNET_MESSAGE_TYPE_PEERSTORE_STORE);
  entry->peer = *peer;
  entry->sub_system_size = htons(sub_system_size);
  entry->value_size = htons(size);
  entry->lifetime = lifetime;
  ss = (char *)&entry[1];
  memcpy(ss, sub_system, sub_system_size);
  val = ss + sub_system_size;
  memcpy(val, value, size);
  sc = GNUNET_new(struct GNUNET_PEERSTORE_StoreContext);
  sc->cont = cont;
  sc->cont_cls = cont_cls;
  sc->h = h;
  sc->rc = rc;
  rc->cont = &store_receive_result;
  rc->cont_cls = sc;
  GNUNET_CONTAINER_DLL_insert_tail(h->rc_head, h->rc_tail, rc);
  GNUNET_CONTAINER_DLL_insert_tail(h->sc_head, h->sc_tail, sc);
  trigger_transmit (h);
  return sc;

}


/* end of peerstore_api.c */
