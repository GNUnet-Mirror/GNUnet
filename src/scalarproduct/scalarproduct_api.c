/*
     This file is part of GNUnet.
     (C) 2013 Christian Grothoff (and other contributing authors)

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
 * @file scalarproduct/scalarproduct_api.c
 * @brief API for the scalarproduct
 * @author Christian Fuchs
 * @author Gaurav Kukreja
 * 
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_scalarproduct_service.h"
#include "gnunet_protocols.h"
#include "scalarproduct.h"

#define LOG(kind,...) GNUNET_log_from (kind, "scalarproduct-api",__VA_ARGS__)

/**************************************************************
 ***  Datatype Declarations                          **********
 **************************************************************/

/**
 * Entry in the request queue per client
 */
struct GNUNET_SCALARPRODUCT_ComputationHandle
{
  /**
   * This is a linked list.
   */
  struct GNUNET_SCALARPRODUCT_ComputationHandle *next;

  /**
   * This is a linked list.
   */
  struct GNUNET_SCALARPRODUCT_ComputationHandle *prev;
  
  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Current connection to the scalarproduct service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Handle for statistics.
   */
  struct GNUNET_STATISTICS_Handle *stats;

  /**
   * The shared session key identifying this computation
   */
  struct GNUNET_HashCode * key;
    
  /**
   * Current transmit handle.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * Size of the message
   */
  uint16_t message_size;

  /**
   * Message to be sent to the scalarproduct service
   */
  struct GNUNET_SCALARPRODUCT_client_request * msg;

  union
  {
    /**
     * Function to call after transmission of the request.
     */
    GNUNET_SCALARPRODUCT_ContinuationWithStatus cont_status;

    /**
     * Function to call after transmission of the request.
     */
    GNUNET_SCALARPRODUCT_DatumProcessor cont_datum;
  };

  /**
   * Closure for 'cont'.
   */
  void *cont_cls;

  /**
   * Response Processor for response from the service. This function calls the
   * continuation function provided by the client.
   */
  GNUNET_SCALARPRODUCT_ResponseMessageHandler response_proc;
};

/**************************************************************
 ***  Global Variables                               **********
 **************************************************************/
/**
 * Head of the active sessions queue
 */
struct GNUNET_SCALARPRODUCT_ComputationHandle *head;
/**
 * Tail of the active sessions queue
 */
struct GNUNET_SCALARPRODUCT_ComputationHandle *tail;

/**************************************************************
 ***  Function Declarations                          **********
 **************************************************************/

/**
 * Called when a response is received from the service. After basic check
 * handler in qe->response_proc is called. This functions handles the response
 * to the client which used the API.
 * 
 * @param cls Pointer to the Master Context
 * @param msg Pointer to the data received in response
 */
static void
receive_cb (void *cls, const struct GNUNET_MessageHeader *msg);

/**
 * Transmits the request to the VectorProduct Sevice
 * 
 * @param cls Closure
 * @param size Size of the buffer
 * @param buf Pointer to the buffer
 * 
 * @return Size of the message sent
 */
static size_t transmit_request (void *cls, size_t size,
                                void *buf);

/**************************************************************
 ***  Static Function Declarations                   **********
 **************************************************************/

/**
 * Handles the RESULT received in reply of prepare_response from the 
 * service
 * 
 * @param cls Handle to the Master Context
 * @param msg Pointer to the response received
 */
static void
process_status_message (void *cls,
                        const struct GNUNET_MessageHeader *msg,
                        enum GNUNET_SCALARPRODUCT_ResponseStatus status)
{
  struct GNUNET_SCALARPRODUCT_ComputationHandle *qe = cls;

  GNUNET_assert (qe != NULL);

  if (qe->cont_status != NULL)
    qe->cont_status (qe->cont_cls, &qe->msg->key, status);
}


/**
 * Handles the RESULT received in reply of prepare_response from the 
 * service
 * 
 * @param cls Handle to the Master Context
 * @param msg Pointer to the response received
 */
static void
process_result_message (void *cls,
                        const struct GNUNET_MessageHeader *msg,
                        enum GNUNET_SCALARPRODUCT_ResponseStatus status)
{
  struct GNUNET_SCALARPRODUCT_ComputationHandle *qe = cls;

  GNUNET_assert (qe != NULL);

  if (msg == NULL && qe->cont_datum != NULL)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Timeout reached or session terminated.\n");
    }
  if (qe->cont_datum != NULL)
    {
      qe->cont_datum (qe->cont_cls, &qe->msg->key, &qe->msg->peer, status, (struct GNUNET_SCALARPRODUCT_client_response *) msg);
    }
}


/**
 * Called when a response is received from the service. After basic check
 * handler in qe->response_proc is called. This functions handles the response
 * to the client which used the API.
 * 
 * @param cls Pointer to the Master Context
 * @param msg Pointer to the data received in response
 */
static void
receive_cb (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_SCALARPRODUCT_ComputationHandle *h = cls;
  struct GNUNET_SCALARPRODUCT_ComputationHandle *qe;
  int16_t was_transmitted;
  struct GNUNET_SCALARPRODUCT_client_response *message =
          (struct GNUNET_SCALARPRODUCT_client_response *) msg;

  h->in_receive = GNUNET_NO;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Received reply from VectorProduct\n");

  if (NULL == (qe = free_queue_head_entry (h)))
    {
      /**
       * The queue head will be NULL if the client disconnected,
       * * In case of Alice, client disconnected after sending request, before receiving response
       * * In case of Bob, client disconnected after preparing response, before getting request from Alice.
       */
      process_queue (h);
      return;
    }

  if (h->client == NULL)
    {
      // GKUKREJA : handle this correctly
      /**
       * The queue head will be NULL if the client disconnected,
       * * In case of Alice, client disconnected after sending request, before receiving response
       * * In case of Bob, client disconnected after preparing response, before getting request from Alice.
       */
      process_queue (h);
      return;
    }

  was_transmitted = qe->was_transmitted;
  // Control will only come here, when the request was transmitted to service,
  // and service responded.
  GNUNET_assert (was_transmitted == GNUNET_YES);

  if (msg == NULL)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING, "Service responded with NULL!\n");
      qe->response_proc (qe, NULL, GNUNET_SCALARPRODUCT_Status_Failure);
    }
  else if ((ntohs (msg->type) != GNUNET_MESSAGE_TYPE_SCALARPRODUCT_SERVICE_TO_CLIENT))
    {
      LOG (GNUNET_ERROR_TYPE_WARNING, "Invalid Message Received\n");
      qe->response_proc (qe, msg, GNUNET_SCALARPRODUCT_Status_InvalidResponse);
    }
  else if (ntohl (message->product_length) == 0)
    {
      // response for the responder client, successful
      GNUNET_STATISTICS_update (h->stats,
                                gettext_noop ("# SUC responder result messages received"), 1,
                                GNUNET_NO);

      LOG (GNUNET_ERROR_TYPE_DEBUG, "Received message from service without product attached.\n");
      qe->response_proc (qe, msg, GNUNET_SCALARPRODUCT_Status_Success);
    }
  else if (ntohl (message->product_length) > 0)
    {
      // response for the requester client, successful
      GNUNET_STATISTICS_update (h->stats,
                                gettext_noop ("# SUC requester result messages received"), 1,
                                GNUNET_NO);

      LOG (GNUNET_ERROR_TYPE_DEBUG, "Received message from requester service for requester client.\n");
      qe->response_proc (qe, msg, GNUNET_SCALARPRODUCT_Status_Success);
    }

  GNUNET_free (qe);
  process_queue (h);
}


/**
 * Transmits the request to the VectorProduct Sevice
 * 
 * @param cls Closure
 * @param size Size of the buffer
 * @param buf Pointer to the buffer
 * 
 * @return Size of the message sent
 */
static size_t
transmit_request (void *cls, size_t size,
                  void *buf)
{
  struct GNUNET_SCALARPRODUCT_ComputationHandle *qe = cls;
  size_t msize;
  
  if (buf == NULL)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Failed to transmit request to SCALARPRODUCT.\n");
      GNUNET_STATISTICS_update (qe->stats,
                                gettext_noop ("# transmission request failures"),
                                1, GNUNET_NO);
      GNUNET_SCALARPRODUCT_disconnect (qe);
      return 0;
    }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Transmitting %u byte request to SCALARPRODUCT\n",
       msize);

  memcpy (buf, qe->msg, size);
  GNUNET_free (qe->msg);
  qe->was_transmitted = GNUNET_YES;

  qe->th = NULL;

  GNUNET_CLIENT_receive (h->client, &receive_cb, h,
                         GNUNET_TIME_UNIT_FOREVER_REL);

#if INSANE_STATISTICS
  GNUNET_STATISTICS_update (h->stats,
                            gettext_noop ("# bytes sent to scalarproduct"), 1,
                            GNUNET_NO);
#endif
  return size;
}


/**************************************************************
 ***  API                                            **********
 **************************************************************/


/**
 * Used by Bob's client to cooperate with Alice, 
 * 
 * @param h handle to the master context
 * @param key Session key - unique to the requesting client
 * @param elements Array of elements of the vector
 * @param element_count Number of elements in the vector
 * @param cont Callback function
 * @param cont_cls Closure for the callback function
 */
struct GNUNET_SCALARPRODUCT_ComputationHandle *
GNUNET_SCALARPRODUCT_response (const struct GNUNET_CONFIGURATION_Handle *cfg,
                               const struct GNUNET_HashCode * key,
                               const int32_t * elements,
                               uint32_t element_count,
                               GNUNET_SCALARPRODUCT_ContinuationWithStatus cont,
                               void *cont_cls)
{
  struct GNUNET_SCALARPRODUCT_ComputationHandle *h;
  struct GNUNET_SCALARPRODUCT_client_request *msg;
  int32_t * vector;
  uint16_t size;
  uint64_t i;
  
  GNUNET_assert(key);
  GNUNET_assert(elements);
  GNUNET_assert(cont);
  GNUNET_assert(element_count > 1);
  GNUNET_assert (GNUNET_SERVER_MAX_MESSAGE_SIZE >= sizeof (struct GNUNET_SCALARPRODUCT_client_request)
                                                   + element_count * sizeof (int32_t));
  h = GNUNET_new (struct GNUNET_SCALARPRODUCT_ComputationHandle);
  h->client = GNUNET_CLIENT_connect ("scalarproduct", cfg);
  if (!h->client)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _ ("Failed to connect to the scalarproduct service\n"));
      GNUNET_free(h);
      return NULL;
    }
  h->stats = GNUNET_STATISTICS_create ("scalarproduct-api", cfg);
  if (!h->th){
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _("Failed to send a message to the statistics service\n"));
      GNUNET_CLIENT_disconnect(h->client);
      GNUNET_free(h);
      return NULL;
  }
  
  size = sizeof (struct GNUNET_SCALARPRODUCT_client_request) + element_count * sizeof (int32_t);
  
  h->cont_datum = cont;
  h->cont_cls = cont_cls;
  h->response_proc = &process_result_message;
  h->cfg = cfg;
  h->msg = GNUNET_malloc (size);
  memcpy (&h->key, key, sizeof (struct GNUNET_HashCode));
  
  msg = (struct GNUNET_SCALARPRODUCT_client_request*) h->msg;
  msg->header.size = htons (size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_TO_ALICE);
  msg->element_count = htonl (element_count);
  
  vector = (int32_t*) &msg[1];
  // copy each element over to the message
  for (i = 0; i < element_count; i++)
    vector[i] = htonl(elements[i]);

  memcpy (&msg->key, key, sizeof (struct GNUNET_HashCode));
  
  h->th = GNUNET_CLIENT_notify_transmit_ready (h->client, size,
                                               GNUNET_TIME_UNIT_FOREVER_REL,
                                               GNUNET_YES, // retry is OK in the initial stage
                                               &transmit_request, h);
  if (!h->th)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _ ("Failed to send a message to the scalarproduct service\n"));
      GNUNET_STATISTICS_destroy(h->GNUNET_YES);
      GNUNET_CLIENT_disconnect(h->client);
      GNUNET_free(h->msg);
      GNUNET_free(h);
      return NULL;
    }
  GNUNET_CONTAINER_DLL_insert (head, tail, h);
  return h;
}


/**
 * Request by Alice's client for computing a scalar product
 * 
 * @param h handle to the master context
 * @param key Session key - unique to the requesting client
 * @param peer PeerID of the other peer
 * @param elements Array of elements of the vector
 * @param element_count Number of elements in the vector
 * @param mask Array of the mask
 * @param mask_bytes number of bytes in the mask
 * @param cont Callback function
 * @param cont_cls Closure for the callback function
 */
struct GNUNET_SCALARPRODUCT_ComputationHandle *
GNUNET_SCALARPRODUCT_request (const struct GNUNET_CONFIGURATION_Handle *cfg,
                              const struct GNUNET_HashCode * key,
                              const struct GNUNET_PeerIdentity *peer,
                              const int32_t * elements,
                              uint32_t element_count,
                              const unsigned char * mask,
                              uint32_t mask_bytes,
                              GNUNET_SCALARPRODUCT_DatumProcessor cont,
                              void *cont_cls)
{
  struct GNUNET_SCALARPRODUCT_ComputationHandle *h;
  struct GNUNET_SCALARPRODUCT_client_request *msg;
  int32_t * vector;
  uint16_t size;
  uint64_t i;
  
  GNUNET_assert (GNUNET_SERVER_MAX_MESSAGE_SIZE >= sizeof (struct GNUNET_SCALARPRODUCT_client_request)
                                                   + element_count * sizeof (int32_t)
                                                   + mask_length);
  
  h = GNUNET_new (struct GNUNET_SCALARPRODUCT_ComputationHandle);
  h->client = GNUNET_CLIENT_connect ("scalarproduct", cfg);
  if (!h->client)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _ ("Failed to connect to the scalarproduct service\n"));
      GNUNET_free(h);
      return NULL;
    }
  h->stats = GNUNET_STATISTICS_create ("scalarproduct-api", cfg);
  if (!h->th){
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _("Failed to send a message to the statistics service\n"));
      GNUNET_CLIENT_disconnect(h->client);
      GNUNET_free(h);
      return NULL;
  }
  
  size = sizeof (struct GNUNET_SCALARPRODUCT_client_request) + element_count * sizeof (int32_t) + mask_length;
  
  h->cont_datum = cont;
  h->cont_cls = cont_cls;
  h->response_proc = &process_status_message;
  h->cfg = cfg;
  h->msg = GNUNET_malloc (size);
  memcpy (&h->key, key, sizeof (struct GNUNET_HashCode));
  
  msg = (struct GNUNET_SCALARPRODUCT_client_request*) h->msg;
  msg->header.size = htons (size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_TO_ALICE);
  msg->element_count = htons (element_count);
  msg->mask_length = htons (mask_length);
  
  vector = (int32_t*) &msg[1];
  // copy each element over to the message
  for (i = 0; i < element_count; i++)
    vector[i] = htonl(elements[i]);

  memcpy (&msg->peer, peer, sizeof (struct GNUNET_PeerIdentity));
  memcpy (&msg->key, key, sizeof (struct GNUNET_HashCode));
  memcpy (&vector[element_count], mask, mask_length);
  
  h->th = GNUNET_CLIENT_notify_transmit_ready (h->client, size,
                                               GNUNET_TIME_UNIT_FOREVER_REL,
                                               GNUNET_YES, // retry is OK in the initial stage
                                               &transmit_request, h);
  if (!h->th)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _ ("Failed to send a message to the scalarproduct service\n"));
      GNUNET_STATISTICS_destroy(h->GNUNET_YES);
      GNUNET_CLIENT_disconnect(h->client);
      GNUNET_free(h->msg);
      GNUNET_free(h);
      return NULL;
    }
  GNUNET_CONTAINER_DLL_insert (head, tail, h);
  return h;
}

/**
 * Disconnect from the scalarproduct service.
 * 
 * @param h handle to the scalarproduct
 */
void
GNUNET_SCALARPRODUCT_disconnect (struct GNUNET_SCALARPRODUCT_ComputationHandle * h)
{
  struct GNUNET_SCALARPRODUCT_ComputationHandle * qe;

  LOG (GNUNET_ERROR_TYPE_INFO,
       "Disconnecting from VectorProduct\n");

  for (qe = head; head != NULL; qe = head)
    {
      GNUNET_CONTAINER_DLL_remove (head, tail, qe);
      if (NULL == qe->th)
        GNUNET_CLIENT_notify_transmit_ready_cancel(qe->th);
      GNUNET_CLIENT_disconnect (h->client);
      GNUNET_STATISTICS_destroy (h->stats, GNUNET_YES);
      qe->response_proc (qe, NULL, GNUNET_SCALARPRODUCT_Status_ServiceDisconnected);
      GNUNET_free(qe->msg);
      GNUNET_free(qe);
    }
}

/* end of ext_api.c */
