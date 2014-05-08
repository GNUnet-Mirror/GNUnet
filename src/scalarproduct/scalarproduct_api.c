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
 * the abstraction function for our internal callback
 */
typedef void (*GNUNET_SCALARPRODUCT_ResponseMessageHandler) (void *cls,
                                                             const struct GNUNET_MessageHeader *msg,
                                                             enum GNUNET_SCALARPRODUCT_ResponseStatus status);

/**
 * A handle returned for each computation
 */
struct GNUNET_SCALARPRODUCT_ComputationHandle
{
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
  struct GNUNET_HashCode key;

  /**
   * Current transmit handle.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * count of all elements we offer for computation
   */
  uint32_t element_count_total;

  /**
   * count of the transfered elements we offer for computation
   */
  uint32_t element_count_transfered;
  
  /**
   * the client's elements which 
   */
  struct GNUNET_SCALARPRODUCT_Element * elements;
  
  /**
   * Message to be sent to the scalarproduct service
   */
  void * msg;

  /**
   * The client's msg handler callback
   */
  union
  {
  /**
   * Function to call after transmission of the request (Bob).
   */
  GNUNET_SCALARPRODUCT_ContinuationWithStatus cont_status;

  /**
   * Function to call after transmission of the request (Alice).
   */
  GNUNET_SCALARPRODUCT_DatumProcessor cont_datum;
  };

  /**
   * Closure for 'cont'.
   */
  void *cont_cls;

  /**
   * API internal callback for results and failures to be forwarded to the client
   */
  GNUNET_SCALARPRODUCT_ResponseMessageHandler response_proc;
  
  /**
   * 
   */
  GNUNET_SCHEDULER_TaskIdentifier cont_multipart;
};

/**************************************************************
 ***  Forward Function Declarations                          **********
 **************************************************************/

void
GNUNET_SCALARPRODUCT_cancel (struct GNUNET_SCALARPRODUCT_ComputationHandle * h);

static size_t do_send_message (void *cls, size_t size, void *buf);
/**************************************************************
 ***  Static Function Declarations                   **********
 **************************************************************/


/**
 * Handles the STATUS received from the service for a response, does not contain a payload
 *
 * @param cls our Handle
 * @param msg Pointer to the response received
 * @param status the condition the request was terminated with (eg: disconnect)
 */
static void
process_status_message (void *cls,
                        const struct GNUNET_MessageHeader *msg,
                        enum GNUNET_SCALARPRODUCT_ResponseStatus status)
{
  struct GNUNET_SCALARPRODUCT_ComputationHandle *qe = cls;

  qe->cont_status (qe->cont_cls, status);
}


/**
 * Handles the RESULT received from the service for a request, should contain a result MPI value
 *
 * @param cls our Handle
 * @param msg Pointer to the response received
 * @param status the condition the request was terminated with (eg: disconnect)
 */
static void
process_result_message (void *cls,
                        const struct GNUNET_MessageHeader *msg,
                        enum GNUNET_SCALARPRODUCT_ResponseStatus status)
{
  struct GNUNET_SCALARPRODUCT_ComputationHandle *qe = cls;
  const struct GNUNET_SCALARPRODUCT_client_response *message =
          (const struct GNUNET_SCALARPRODUCT_client_response *) msg;
  gcry_mpi_t result = NULL;
  gcry_error_t rc;

  if (GNUNET_SCALARPRODUCT_Status_Success == status)
    {
      size_t product_len = ntohl (message->product_length);
      result = gcry_mpi_new (0);

      if (0 < product_len)
        {
          gcry_mpi_t num;
          size_t read = 0;

          if (0 != (rc = gcry_mpi_scan (&num, GCRYMPI_FMT_STD, &message[1], product_len, &read)))
            {
              LOG_GCRY(GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_scan", rc);
              gcry_mpi_release (result);
              result = NULL;
              status = GNUNET_SCALARPRODUCT_Status_InvalidResponse;
            }
          else
            {
              if (0 < message->range)
                gcry_mpi_add (result, result, num);
              else if (0 > message->range)
                gcry_mpi_sub (result, result, num);
              gcry_mpi_release (num);
            }
        }
    }
  qe->cont_datum (qe->cont_cls, status, result);
}


/**
 * Called when a response is received from the service. After basic check, the
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
  const struct GNUNET_SCALARPRODUCT_client_response *message =
          (const struct GNUNET_SCALARPRODUCT_client_response *) msg;
  enum GNUNET_SCALARPRODUCT_ResponseStatus status = GNUNET_SCALARPRODUCT_Status_InvalidResponse;

  if (NULL == msg)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING, "Disconnected by Service.\n");
      status = GNUNET_SCALARPRODUCT_Status_ServiceDisconnected;
    }
  else if ((GNUNET_SYSERR != message->status) && (0 < message->product_length ))
    {
      // response for the responder client, successful
      GNUNET_STATISTICS_update (h->stats,
                                gettext_noop ("# SUC responder result messages received"), 1,
                                GNUNET_NO);

      status = GNUNET_SCALARPRODUCT_Status_Success;
    }
  else if (message->status == GNUNET_SYSERR){
      // service signaled an error
      status = GNUNET_SCALARPRODUCT_Status_Failure;
  }
  
  if (h->cont_status != NULL)
    h->response_proc (h, msg, status);

  GNUNET_free (h);
}


static void
send_multipart (void * cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  struct GNUNET_SCALARPRODUCT_ComputationHandle *h = (struct GNUNET_SCALARPRODUCT_ComputationHandle *) cls;
  struct GNUNET_SCALARPRODUCT_computation_message_multipart *msg;
  uint32_t size;
  uint32_t todo;

  h->cont_multipart = GNUNET_SCHEDULER_NO_TASK;

  todo = h->element_count_total - h->element_count_transfered;
  size = sizeof (struct GNUNET_SCALARPRODUCT_computation_message_multipart) +todo * sizeof (struct GNUNET_SCALARPRODUCT_Element);
  if (GNUNET_SERVER_MAX_MESSAGE_SIZE <= size) {
    //create a multipart msg, first we calculate a new msg size for the head msg
    todo = (GNUNET_SERVER_MAX_MESSAGE_SIZE - 1 - sizeof (struct GNUNET_SCALARPRODUCT_computation_message_multipart)) / sizeof (struct GNUNET_SCALARPRODUCT_Element);
    size = sizeof (struct GNUNET_SCALARPRODUCT_computation_message_multipart) +todo * sizeof (struct GNUNET_SCALARPRODUCT_Element);
  }

  msg = (struct GNUNET_SCALARPRODUCT_computation_message_multipart*) GNUNET_malloc (size);
  h->msg = msg;
  msg->header.size = htons (size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_MUTLIPART);
  msg->element_count_contained = htonl (todo);

  memcpy (&msg[1], &h->elements[h->element_count_transfered], todo);
  h->element_count_transfered += todo;

  h->th = GNUNET_CLIENT_notify_transmit_ready (h->client, size,
                                               GNUNET_TIME_UNIT_FOREVER_REL,
                                               GNUNET_YES, // retry is OK in the initial stage
                                               &do_send_message, h);

  if (!h->th) {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _ ("Failed to send a multipart message to the scalarproduct service\n"));
    GNUNET_STATISTICS_update (h->stats,
                              gettext_noop ("# transmission request failures"),
                              1, GNUNET_NO);
    GNUNET_STATISTICS_destroy (h->stats, GNUNET_YES);
    GNUNET_CLIENT_disconnect (h->client);
    GNUNET_free (h->msg);
    h->msg = NULL;
    if (h->cont_status != NULL)
      h->response_proc (h, NULL, GNUNET_SCALARPRODUCT_Status_Failure);

    GNUNET_SCALARPRODUCT_cancel (cls);
  }
}

/**
 * Transmits the request to the VectorProduct Service
 *
 * @param cls Closure
 * @param size Size of the buffer
 * @param buf Pointer to the buffer
 *
 * @return Size of the message sent
 */
static size_t
do_send_message (void *cls, size_t size,
                 void *buf)
{
  struct GNUNET_SCALARPRODUCT_ComputationHandle *h = cls;

  if (NULL == buf) {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Failed to transmit request to SCALARPRODUCT.\n");
    GNUNET_STATISTICS_update (h->stats,
                              gettext_noop ("# transmission request failures"),
                              1, GNUNET_NO);

    // notify caller about the error, done here.
    if (h->cont_status != NULL)
      h->response_proc (h, NULL, GNUNET_SCALARPRODUCT_Status_Failure);

    GNUNET_SCALARPRODUCT_cancel (cls);
    return 0;
  }
  memcpy (buf, h->msg, size);

  GNUNET_free (h->msg);
  h->msg = NULL;
  h->th = NULL;

#if INSANE_STATISTICS
  GNUNET_STATISTICS_update (h->stats,
                            gettext_noop ("# bytes sent to scalarproduct"), 1,
                            GNUNET_NO);
#endif

  /* done sending */
  if (h->element_count_total == h->element_count_transfered) {
    GNUNET_CLIENT_receive (h->client, &receive_cb, h,
                           GNUNET_TIME_UNIT_FOREVER_REL);
    return size;
  }
  
  h->cont_multipart = GNUNET_SCHEDULER_add_now (&send_multipart, h);
  
  return size;
}


/**************************************************************
 ***  API                                            **********
 **************************************************************/


/**
 * Used by Bob's client to cooperate with Alice,
 *
 * @param cfg the gnunet configuration handle
 * @param key Session key unique to the requesting client
 * @param elements Array of elements of the vector
 * @param element_count Number of elements in the vector
 * @param cont Callback function
 * @param cont_cls Closure for the callback function
 *
 * @return a new handle for this computation
 */
struct GNUNET_SCALARPRODUCT_ComputationHandle *
GNUNET_SCALARPRODUCT_accept_computation (const struct GNUNET_CONFIGURATION_Handle * cfg,
                               const struct GNUNET_HashCode * session_key,
                               const struct GNUNET_SCALARPRODUCT_Element * elements,
                               uint32_t element_count,
                               GNUNET_SCALARPRODUCT_ContinuationWithStatus cont,
                               void * cont_cls)
{
  struct GNUNET_SCALARPRODUCT_ComputationHandle *h;
  struct GNUNET_SCALARPRODUCT_computation_message *msg;
  uint32_t size;
  uint16_t possible;

  GNUNET_assert (GNUNET_SERVER_MAX_MESSAGE_SIZE >= sizeof (struct GNUNET_SCALARPRODUCT_computation_message)
                 + element_count * sizeof (int32_t));
  h = GNUNET_new (struct GNUNET_SCALARPRODUCT_ComputationHandle);
  h->client = GNUNET_CLIENT_connect ("scalarproduct", cfg);
  if (!h->client)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _ ("Failed to connect to the scalarproduct service\n"));
      GNUNET_free (h);
      return NULL;
    }
  h->stats = GNUNET_STATISTICS_create ("scalarproduct-api", cfg);
  if (!h->stats)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _ ("Failed to send a message to the statistics service\n"));
      GNUNET_CLIENT_disconnect (h->client);
      GNUNET_free (h);
      return NULL;
    }

  h->element_count_total = element_count;
  size = sizeof (struct GNUNET_SCALARPRODUCT_computation_message) + element_count * sizeof (struct GNUNET_SCALARPRODUCT_Element);
  if (GNUNET_SERVER_MAX_MESSAGE_SIZE > size) {
    possible = element_count;
    h->element_count_transfered = element_count;
  }
  else {
    //create a multipart msg, first we calculate a new msg size for the head msg
    possible = (GNUNET_SERVER_MAX_MESSAGE_SIZE - 1 - sizeof (struct GNUNET_SCALARPRODUCT_computation_message)) / sizeof (struct GNUNET_SCALARPRODUCT_Element);
    h->element_count_transfered = possible;
    size = sizeof (struct GNUNET_SCALARPRODUCT_computation_message) + possible*sizeof (struct GNUNET_SCALARPRODUCT_Element);
    h->elements = (struct GNUNET_SCALARPRODUCT_Element*) 
            GNUNET_malloc (sizeof(struct GNUNET_SCALARPRODUCT_Element) * element_count);
    memcpy (h->elements, elements, sizeof (struct GNUNET_SCALARPRODUCT_Element)*element_count);
  }

  h->cont_status = cont;
  h->cont_cls = cont_cls;
  h->response_proc = &process_status_message;
  h->cfg = cfg;
  memcpy (&h->key, session_key, sizeof (struct GNUNET_HashCode));

  msg = (struct GNUNET_SCALARPRODUCT_computation_message*) GNUNET_malloc (size);
  h->msg = msg;
  msg->header.size = htons (size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_TO_BOB);
  msg->element_count_total = htonl (element_count);
  msg->element_count_contained = htonl (possible);

  memcpy (&msg->session_key, session_key, sizeof (struct GNUNET_HashCode));
  memcpy (&msg[1], elements, possible);

  h->th = GNUNET_CLIENT_notify_transmit_ready (h->client, size,
                                               GNUNET_TIME_UNIT_FOREVER_REL,
                                               GNUNET_YES, // retry is OK in the initial stage
                                               &do_send_message, h);
  if (!h->th)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _ ("Failed to send a message to the scalarproduct service\n"));
      GNUNET_STATISTICS_update (h->stats,
                              gettext_noop ("# transmission request failures"),
                              1, GNUNET_NO);
      GNUNET_STATISTICS_destroy (h->stats, GNUNET_YES);
      GNUNET_CLIENT_disconnect (h->client);
      GNUNET_free (h->msg);
      GNUNET_free_non_null (h->elements);
      GNUNET_free (h);
      return NULL;
    }
  return h;
}


/**
 * Request by Alice's client for computing a scalar product
 *
 * @param cfg the gnunet configuration handle
 * @param session_key Session key should be unique to the requesting client
 * @param peer PeerID of the other peer
 * @param elements Array of elements of the vector
 * @param element_count Number of elements in the vector
 * @param cont Callback function
 * @param cont_cls Closure for the callback function
 *
 * @return a new handle for this computation
 */
struct GNUNET_SCALARPRODUCT_ComputationHandle *
GNUNET_SCALARPRODUCT_start_computation (const struct GNUNET_CONFIGURATION_Handle * cfg,
                              const struct GNUNET_HashCode * session_key,
                              const struct GNUNET_PeerIdentity *peer,
                              const struct GNUNET_SCALARPRODUCT_Element * elements,
                              uint32_t element_count,
                              GNUNET_SCALARPRODUCT_DatumProcessor cont,
                              void * cont_cls)
{
  struct GNUNET_SCALARPRODUCT_ComputationHandle *h;
  struct GNUNET_SCALARPRODUCT_computation_message *msg;
  uint32_t size;
  uint16_t possible;

  h = GNUNET_new (struct GNUNET_SCALARPRODUCT_ComputationHandle);
  h->client = GNUNET_CLIENT_connect ("scalarproduct", cfg);
  if (!h->client)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _ ("Failed to connect to the scalarproduct service\n"));
      GNUNET_free (h);
      return NULL;
    }
  h->stats = GNUNET_STATISTICS_create ("scalarproduct-api", cfg);
  if (!h->stats)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _ ("Failed to send a message to the statistics service\n"));
      GNUNET_CLIENT_disconnect (h->client);
      GNUNET_free (h);
      return NULL;
    }

  h->element_count_total = element_count;
  size = sizeof (struct GNUNET_SCALARPRODUCT_computation_message) + element_count * sizeof (struct GNUNET_SCALARPRODUCT_Element);
  if (GNUNET_SERVER_MAX_MESSAGE_SIZE > size) {
    possible = element_count;
    h->element_count_transfered = element_count;
  }
  else {
    //create a multipart msg, first we calculate a new msg size for the head msg
    possible = (GNUNET_SERVER_MAX_MESSAGE_SIZE - 1 - sizeof (struct GNUNET_SCALARPRODUCT_computation_message)) / sizeof (struct GNUNET_SCALARPRODUCT_Element);
    h->element_count_transfered = possible;
    size = sizeof (struct GNUNET_SCALARPRODUCT_computation_message) + possible*sizeof (struct GNUNET_SCALARPRODUCT_Element);
    h->elements = (struct GNUNET_SCALARPRODUCT_Element*) 
            GNUNET_malloc (sizeof(struct GNUNET_SCALARPRODUCT_Element) * element_count);
    memcpy (h->elements, elements, sizeof (struct GNUNET_SCALARPRODUCT_Element)*element_count);
  }
  
  h->cont_datum = cont;
  h->cont_cls = cont_cls;
  h->response_proc = &process_result_message;
  h->cfg = cfg;
  memcpy (&h->key, session_key, sizeof (struct GNUNET_HashCode));

  msg = (struct GNUNET_SCALARPRODUCT_computation_message*) GNUNET_malloc (size);
  h->msg = msg;
  msg->header.size = htons (size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_TO_ALICE);
  msg->element_count_total = htonl (element_count);
  msg->element_count_contained = htonl (possible);

  memcpy (&msg->peer, peer, sizeof (struct GNUNET_PeerIdentity));
  memcpy (&msg->session_key, session_key, sizeof (struct GNUNET_HashCode));
  memcpy (&msg[1], elements, possible);

  h->th = GNUNET_CLIENT_notify_transmit_ready (h->client, size,
                                               GNUNET_TIME_UNIT_FOREVER_REL,
                                               GNUNET_YES, // retry is OK in the initial stage
                                               &do_send_message, h);
  if (!h->th)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _ ("Failed to send a message to the scalarproduct service\n"));
      GNUNET_STATISTICS_update (h->stats,
                              gettext_noop ("# transmission request failures"),
                              1, GNUNET_NO);
      GNUNET_STATISTICS_destroy (h->stats, GNUNET_YES);
      GNUNET_CLIENT_disconnect (h->client);
      GNUNET_free (h->msg);
      GNUNET_free_non_null (h->elements);
      GNUNET_free (h);
      return NULL;
    }
  return h;
}

/**
 * Cancel an ongoing computation or revoke our collaboration offer.
 * Closes the connection to the service
 *
 * @param h computation handle to terminate
 */
void
GNUNET_SCALARPRODUCT_cancel (struct GNUNET_SCALARPRODUCT_ComputationHandle * h)
{
  if (NULL != h->th)
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->th);
  if (GNUNET_SCHEDULER_NO_TASK != h->cont_multipart)
    GNUNET_SCHEDULER_cancel (h->cont_multipart);
  GNUNET_free_non_null (h->elements);
  GNUNET_free_non_null (h->msg);
  GNUNET_CLIENT_disconnect (h->client);
  GNUNET_STATISTICS_destroy (h->stats, GNUNET_YES);
  GNUNET_free (h);
}


/* end of scalarproduct_api.c */
