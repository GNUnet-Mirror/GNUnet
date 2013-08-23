/*
     This file is part of GNUnet.
     (C) 2013 Christian Grothoff (and other contributing authors)

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

#define LOG(kind,...) GNUNET_log_from (kind, "scalarproduct-api",__VA_ARGS__)

/**************************************************************
 ***  Datatype Declarations                          **********
 **************************************************************/

/**
 * Entry in the request queue per client
 */
struct GNUNET_SCALARPRODUCT_QueueEntry
{
  /**
   * This is a linked list.
   */
  struct GNUNET_SCALARPRODUCT_QueueEntry *next;

  /**
   * This is a linked list.
   */
  struct GNUNET_SCALARPRODUCT_QueueEntry *prev;

  /**
   * Handle to the master context.
   */
  struct GNUNET_SCALARPRODUCT_Handle *h;

  /**
   * Size of the message
   */
  uint16_t message_size;

  /**
   * Message to be sent to the scalarproduct service
   */
  struct GNUNET_SCALARPRODUCT_client_request* msg;

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
   * Has this message been transmitted to the service?
   * Only ever GNUNET_YES for the head of the queue.
   * Note that the overall struct should end at a
   * multiple of 64 bits.
   */
  int16_t was_transmitted;

  /**
   * Timeout for the current operation.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Task for timeout signaling.
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * Response Processor for response from the service. This function calls the
   * continuation function provided by the client.
   */
  GNUNET_SCALARPRODUCT_ResponseMessageHandler response_proc;
};

/**************************************************************
 ***  Function Declarations                          **********
 **************************************************************/

/**
 * Creates a new entry at the tail of the DLL
 * 
 * @param h handle to the master context
 * 
 * @return pointer to the entry
 */
static struct GNUNET_SCALARPRODUCT_QueueEntry *
make_queue_entry (struct GNUNET_SCALARPRODUCT_Handle *h);

/**
 * Removes the head entry from the queue
 * 
 * @param h Handle to the master context
 */
static struct GNUNET_SCALARPRODUCT_QueueEntry *
free_queue_head_entry (struct GNUNET_SCALARPRODUCT_Handle * h);

/**
 * Triggered when timeout occurs for a request in queue
 * 
 * @param cls The pointer to the QueueEntry
 * @param tc Task Context
 */
static void
timeout_queue_entry (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

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

/**
 * Issues transmit request for the new entries in the queue
 * 
 * @param h handle to the master context
 */
static void
process_queue (struct GNUNET_SCALARPRODUCT_Handle *h);

/**************************************************************
 ***  Static Function Declarations                   **********
 **************************************************************/


/**
 * Creates a new entry at the tail of the DLL
 * 
 * @param h handle to the master context
 * 
 * @return pointer to the entry
 */
static struct GNUNET_SCALARPRODUCT_QueueEntry *
make_queue_entry (struct GNUNET_SCALARPRODUCT_Handle *h)
{
  struct GNUNET_SCALARPRODUCT_QueueEntry *qe;

  qe = GNUNET_new (struct GNUNET_SCALARPRODUCT_QueueEntry);

  // if queue empty
  if (NULL == h->queue_head && NULL == h->queue_tail)
    {
      qe->next = NULL;
      qe->prev = NULL;
      h->queue_head = qe;
      h->queue_tail = qe;
    }
  else
    {
      qe->prev = h->queue_tail;
      h->queue_tail->next = qe;
      h->queue_tail = qe;
    }

  return qe;
}


/**
 * Removes the head entry from the queue
 * 
 * @param h Handle to the master context
 */
static struct GNUNET_SCALARPRODUCT_QueueEntry *
free_queue_head_entry (struct GNUNET_SCALARPRODUCT_Handle * h)
{
  struct GNUNET_SCALARPRODUCT_QueueEntry * qe = NULL;

  GNUNET_assert (NULL != h);
  if (NULL == h->queue_head && NULL == h->queue_tail)
    {
      // The queue is empty. Just return.
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Queue was empty when free_queue_head_entry was called.\n");
    }
  else if (h->queue_head == h->queue_tail) //only one entry
    {
      qe = h->queue_head;
      qe->next = NULL;
      qe->prev = NULL;
      h->queue_head = NULL;
      h->queue_tail = NULL;
    }
  else
    {
      qe = h->queue_head;
      h->queue_head = h->queue_head->next;
      h->queue_head->prev = NULL;
      qe->next = NULL;
      qe->prev = NULL;
    }
  return qe;
}


/**
 * Triggered when timeout occurs for a request in queue
 * 
 * @param cls The pointer to the QueueEntry
 * @param tc Task Context
 */
static void
timeout_queue_entry (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_SCALARPRODUCT_QueueEntry * qe = cls;

  // Update Statistics
  GNUNET_STATISTICS_update (qe->h->stats,
                            gettext_noop ("# queue entry timeouts"), 1,
                            GNUNET_NO);

  // Clear the timeout_task
  qe->timeout_task = GNUNET_SCHEDULER_NO_TASK;

  // transmit_request is supposed to cancel timeout task.
  // If message was not transmitted, there is definitely an error.
  GNUNET_assert (GNUNET_NO == qe->was_transmitted);

  LOG (GNUNET_ERROR_TYPE_INFO, "Timeout of request in datastore queue\n");

  // remove the queue_entry for the queue
  GNUNET_CONTAINER_DLL_remove (qe->h->queue_head, qe->h->queue_tail, qe);
  qe->response_proc (qe, NULL, GNUNET_SCALARPRODUCT_Status_Timeout);
}


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
  struct GNUNET_SCALARPRODUCT_QueueEntry *qe = cls;

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
  struct GNUNET_SCALARPRODUCT_QueueEntry *qe = cls;

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
  struct GNUNET_SCALARPRODUCT_Handle *h = cls;
  struct GNUNET_SCALARPRODUCT_QueueEntry *qe;
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
  struct GNUNET_SCALARPRODUCT_Handle *h = cls;
  struct GNUNET_SCALARPRODUCT_QueueEntry *qe;
  size_t msize;
  
  if (NULL == (qe = h->queue_head))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Queue head is NULL!\n\n");
      return 0;
    }

  GNUNET_SCHEDULER_cancel (qe->timeout_task);
  qe->timeout_task = GNUNET_SCHEDULER_NO_TASK;

  h->th = NULL;
  if (NULL == (qe = h->queue_head))
    return 0; /* no entry in queue */
  if (buf == NULL)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Failed to transmit request to SCALARPRODUCT.\n");
      GNUNET_STATISTICS_update (h->stats,
                                gettext_noop ("# transmission request failures"),
                                1, GNUNET_NO);
      GNUNET_SCALARPRODUCT_disconnect (h);
      return 0;
    }
  if (size < (msize = qe->message_size))
    {
      process_queue (h);
      return 0;
    }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Transmitting %u byte request to SCALARPRODUCT\n",
       msize);

  memcpy (buf, qe->msg, size);
  GNUNET_free (qe->msg);
  qe->was_transmitted = GNUNET_YES;

  GNUNET_assert (GNUNET_NO == h->in_receive);
  h->in_receive = GNUNET_YES;

  GNUNET_CLIENT_receive (h->client, &receive_cb, h,
                         GNUNET_TIME_UNIT_FOREVER_REL);

#if INSANE_STATISTICS
  GNUNET_STATISTICS_update (h->stats,
                            gettext_noop ("# bytes sent to scalarproduct"), 1,
                            GNUNET_NO);
#endif
  return size;
}


/**
 * Issues transmit request for the new entries in the queue
 * 
 * @param h handle to the master context
 */
static void
process_queue (struct GNUNET_SCALARPRODUCT_Handle *h)
{
  struct GNUNET_SCALARPRODUCT_QueueEntry *qe;
  
  if (NULL == (qe = h->queue_head))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Queue empty\n");
      return; /* no entry in queue */
    }
  if (qe->was_transmitted == GNUNET_YES)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Head request already transmitted\n");
      return; /* waiting for replies */
    }
  if (h->th != NULL)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Pending transmission request\n");
      return; /* request pending */
    }
  if (h->client == NULL)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Not connected\n");
      return; /* waiting for reconnect */
    }
  if (GNUNET_YES == h->in_receive)
    {
      /* wait for response to previous query */
      return;
    }

  h->th =
          GNUNET_CLIENT_notify_transmit_ready (h->client, qe->message_size,
                                               GNUNET_TIME_UNIT_FOREVER_REL,
                                               GNUNET_YES,
                                               &transmit_request, h);

  if (h->th == NULL)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _ ("Failed to send a message to the scalarproduct service\n"));
      return;
    }

  GNUNET_assert (GNUNET_NO == h->in_receive);
  GNUNET_break (NULL != h->th);
}



/**************************************************************
 ***  API                                            **********
 **************************************************************/


/**
 * Called by the responder client to prepare response
 * 
 * @param h handle to the master context
 * @param key Session key - unique to the requesting client
 * @param element_count Number of elements in the vector
 * @param mask_length number of bytes in the mask
 * @param elements Array of elements of the vector
 * @param mask Array of the mask
 * @param timeout Relative timeout for the operation
 * @param cont Callback function
 * @param cont_cls Closure for the callback function
 */
struct GNUNET_SCALARPRODUCT_QueueEntry *
GNUNET_SCALARPRODUCT_prepare_response (struct GNUNET_SCALARPRODUCT_Handle *h,
                                       const struct GNUNET_HashCode * key,
                                       uint16_t element_count,
                                       int32_t * elements,
                                       struct GNUNET_TIME_Relative timeout,
                                       GNUNET_SCALARPRODUCT_ContinuationWithStatus cont,
                                       void *cont_cls)
{
  struct GNUNET_SCALARPRODUCT_QueueEntry *qe = make_queue_entry (h);
  int32_t * vector;
  uint16_t size;
  unsigned int i;
  
  GNUNET_assert (GNUNET_SERVER_MAX_MESSAGE_SIZE >= sizeof (struct GNUNET_SCALARPRODUCT_client_request)
                 +element_count * sizeof (int32_t));
  size = sizeof (struct GNUNET_SCALARPRODUCT_client_request) +element_count * sizeof (int32_t);

  qe->message_size = size;
  qe->msg = GNUNET_malloc (size);
  qe->msg->header.size = htons (size);
  qe->msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_TO_BOB);
  qe->msg->element_count = htons (element_count);
  qe->msg->mask_length = htons (0);
  memcpy (&qe->msg->key, key, sizeof (struct GNUNET_HashCode));
  qe->cont_status = cont;
  qe->cont_cls = cont_cls;
  qe->was_transmitted = GNUNET_NO;
  qe->timeout_task = GNUNET_SCHEDULER_add_delayed (timeout, &timeout_queue_entry, qe);
  qe->response_proc = &process_status_message;
  qe->timeout = GNUNET_TIME_relative_to_absolute (timeout);

  vector = (int32_t *) & qe->msg[1];
  // copy each element over to the message
  for (i = 0; i < element_count; i++)
    vector[i] = htonl (elements[i]);

  process_queue (h);
  return qe;
}


/**
 * Request the Scalar Product Evaluation
 * 
 * @param h handle to the master context
 * @param key Session key - unique to the requesting client
 * @param peer PeerID of the other peer
 * @param element_count Number of elements in the vector
 * @param mask_length number of bytes in the mask
 * @param elements Array of elements of the vector
 * @param mask Array of the mask
 * @param timeout Relative timeout for the operation
 * @param cont Callback function
 * @param cont_cls Closure for the callback function
 */
struct GNUNET_SCALARPRODUCT_QueueEntry *
GNUNET_SCALARPRODUCT_request (struct GNUNET_SCALARPRODUCT_Handle *h,
                              const struct GNUNET_HashCode * key,
                              const struct GNUNET_PeerIdentity * peer,
                              uint16_t element_count,
                              uint16_t mask_length,
                              int32_t * elements,
                              const unsigned char * mask,
                              struct GNUNET_TIME_Relative timeout,
                              GNUNET_SCALARPRODUCT_DatumProcessor cont,
                              void *cont_cls)
{
  struct GNUNET_SCALARPRODUCT_QueueEntry *qe = make_queue_entry (h);
  int32_t * vector;
  uint16_t size;
  unsigned int i;
  
  GNUNET_assert (GNUNET_SERVER_MAX_MESSAGE_SIZE >= sizeof (struct GNUNET_SCALARPRODUCT_client_request)
                 +element_count * sizeof (int32_t)
                 + mask_length);
  size = sizeof (struct GNUNET_SCALARPRODUCT_client_request) +element_count * sizeof (int32_t) + mask_length;

  qe->message_size = size;
  qe->msg = GNUNET_malloc (size);
  qe->msg->header.size = htons (size);
  qe->msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_TO_ALICE);
  memcpy (&qe->msg->peer, peer, sizeof (struct GNUNET_PeerIdentity));
  qe->msg->element_count = htons (element_count);
  qe->msg->mask_length = htons (mask_length);
  memcpy (&qe->msg->key, key, sizeof (struct GNUNET_HashCode));
  qe->cont_datum = cont;
  qe->cont_cls = cont_cls;
  qe->was_transmitted = GNUNET_NO;
  qe->timeout_task = GNUNET_SCHEDULER_add_delayed (timeout, &timeout_queue_entry, qe);
  qe->response_proc = &process_result_message;
  qe->timeout = GNUNET_TIME_relative_to_absolute (timeout);

  vector = (int32_t*) & qe->msg[1];
  // copy each element over to the message
  for (i = 0; i < element_count; i++)
    vector[i] = htonl (elements[i]);

  // fill in the mask
  memcpy (&vector[element_count], mask, mask_length);

  process_queue (h);
  return qe;
}


/**
 * Connect to the scalarproduct service.
 *
 * @param cfg configuration to use
 * @return handle to use to access the service
 */
struct GNUNET_SCALARPRODUCT_Handle *
GNUNET_SCALARPRODUCT_connect (const struct GNUNET_CONFIGURATION_Handle * cfg)
{
  struct GNUNET_CLIENT_Connection *client;
  struct GNUNET_SCALARPRODUCT_Handle *h;

  client = GNUNET_CLIENT_connect ("scalarproduct", cfg);

  if (NULL == client)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _ ("Failed to connect to the scalarproduct service\n"));
      return NULL;
    }

  h = GNUNET_malloc (sizeof (struct GNUNET_SCALARPRODUCT_Handle) +
                     GNUNET_SERVER_MAX_MESSAGE_SIZE - 1);
  h->client = client;
  h->cfg = cfg;
  h->stats = GNUNET_STATISTICS_create ("scalarproduct-api", cfg);
  return h;
}


/**
 * Disconnect from the scalarproduct service.
 * 
 * @param h handle to the scalarproduct
 */
void
GNUNET_SCALARPRODUCT_disconnect (struct GNUNET_SCALARPRODUCT_Handle * h)
{
  struct GNUNET_SCALARPRODUCT_QueueEntry * qe;

  LOG (GNUNET_ERROR_TYPE_INFO,
       "Disconnecting from VectorProduct\n");

  while (NULL != h->queue_head)
    {
      GNUNET_assert (NULL != (qe = free_queue_head_entry (h)));
      qe->response_proc (qe, NULL, GNUNET_SCALARPRODUCT_Status_ServiceDisconnected);
    }

  if (h->client != NULL)
    {
      GNUNET_CLIENT_disconnect (h->client);
      h->client = NULL;
    }

  GNUNET_STATISTICS_destroy (h->stats, GNUNET_NO);
  h->stats = NULL;
}

/* end of ext_api.c */
