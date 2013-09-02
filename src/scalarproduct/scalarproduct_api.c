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
static struct GNUNET_SCALARPRODUCT_ComputationHandle *head;
/**
 * Tail of the active sessions queue
 */
static struct GNUNET_SCALARPRODUCT_ComputationHandle *tail;

/**************************************************************
 ***  Function Declarations                          **********
 **************************************************************/

void
GNUNET_SCALARPRODUCT_cancel (struct GNUNET_SCALARPRODUCT_ComputationHandle * h);

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

  qe->cont_status (qe->cont_cls, status);
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
  const struct GNUNET_SCALARPRODUCT_client_response *message =
          (const struct GNUNET_SCALARPRODUCT_client_response *) msg;
  gcry_mpi_t result = NULL;

  if (GNUNET_SCALARPRODUCT_Status_Success == status
      && qe->cont_datum != NULL)
    {
      size_t product_len = ntohl (message->product_length);
      result = gcry_mpi_new (0);

      if (0 < product_len)
        {
          gcry_mpi_t num;
          size_t read = 0;

          if (0 != gcry_mpi_scan (&num, GCRYMPI_FMT_USG, &msg[1], product_len, &read))
            {
              LOG (GNUNET_ERROR_TYPE_ERROR, "Could not convert to mpi to value!\n");
              gcry_mpi_release (result);
              result = NULL;
              status = GNUNET_SCALARPRODUCT_Status_InvalidResponse;
            }
          else
            {
              if (message->range > 0)
                gcry_mpi_add (result, result, num);
              else
                gcry_mpi_sub (result, result, num);
              gcry_mpi_release (num);
            }
        }
    }
  qe->cont_datum (qe->cont_cls, status, result);
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
  struct GNUNET_SCALARPRODUCT_ComputationHandle *qe = cls;
  const struct GNUNET_SCALARPRODUCT_client_response *message =
          (const struct GNUNET_SCALARPRODUCT_client_response *) msg;
  enum GNUNET_SCALARPRODUCT_ResponseStatus status = GNUNET_SCALARPRODUCT_Status_InvalidResponse;

  if (NULL == msg)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING, "Disconnected by Service.\n");
      status = GNUNET_SCALARPRODUCT_Status_ServiceDisconnected;
    }
  else if (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_SERVICE_TO_CLIENT != ntohs (msg->type))
    {
      LOG (GNUNET_ERROR_TYPE_WARNING, "Invalid message type received\n");
    }
  else if (0 < ntohl (message->product_length) || (0 == message->range))
    {
      // response for the responder client, successful
      GNUNET_STATISTICS_update (qe->stats,
                                gettext_noop ("# SUC responder result messages received"), 1,
                                GNUNET_NO);

      status = GNUNET_SCALARPRODUCT_Status_Success;
    }

  if (qe->cont_datum != NULL)
    qe->response_proc (qe, msg, status);

  GNUNET_free (qe);
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

  if (NULL == buf)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Failed to transmit request to SCALARPRODUCT.\n");
      GNUNET_STATISTICS_update (qe->stats,
                                gettext_noop ("# transmission request failures"),
                                1, GNUNET_NO);

      // notify caller about the error, done here.
      if (qe->cont_datum != NULL)
        qe->response_proc (qe, NULL, GNUNET_SCALARPRODUCT_Status_Failure);
      GNUNET_SCALARPRODUCT_cancel (cls);
      return 0;
    }
  memcpy (buf, qe->msg, size);

  GNUNET_free (qe->msg);
  qe->msg = NULL;
  qe->th = NULL;

  GNUNET_CLIENT_receive (qe->client, &receive_cb, qe,
                         GNUNET_TIME_UNIT_FOREVER_REL);

#if INSANE_STATISTICS
  GNUNET_STATISTICS_update (qe->stats,
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

  GNUNET_assert (key);
  GNUNET_assert (elements);
  GNUNET_assert (cont);
  GNUNET_assert (element_count > 1);
  GNUNET_assert (GNUNET_SERVER_MAX_MESSAGE_SIZE >= sizeof (struct GNUNET_SCALARPRODUCT_client_request)
                 +element_count * sizeof (int32_t));
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
  if (!h->th)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _ ("Failed to send a message to the statistics service\n"));
      GNUNET_CLIENT_disconnect (h->client);
      GNUNET_free (h);
      return NULL;
    }

  size = sizeof (struct GNUNET_SCALARPRODUCT_client_request) +element_count * sizeof (int32_t);

  h->cont_status = cont;
  h->cont_cls = cont_cls;
  h->response_proc = &process_result_message;
  h->cfg = cfg;
  h->msg = GNUNET_malloc (size);
  memcpy (&h->key, key, sizeof (struct GNUNET_HashCode));

  msg = (struct GNUNET_SCALARPRODUCT_client_request*) h->msg;
  msg->header.size = htons (size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_TO_ALICE);
  msg->element_count = htonl (element_count);

  vector = (int32_t*) & msg[1];
  // copy each element over to the message
  for (i = 0; i < element_count; i++)
    vector[i] = htonl (elements[i]);

  memcpy (&msg->key, key, sizeof (struct GNUNET_HashCode));

  h->th = GNUNET_CLIENT_notify_transmit_ready (h->client, size,
                                               GNUNET_TIME_UNIT_FOREVER_REL,
                                               GNUNET_YES, // retry is OK in the initial stage
                                               &transmit_request, h);
  if (!h->th)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _ ("Failed to send a message to the scalarproduct service\n"));
      GNUNET_STATISTICS_destroy (h->stats, GNUNET_YES);
      GNUNET_CLIENT_disconnect (h->client);
      GNUNET_free (h->msg);
      GNUNET_free (h);
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
                 +element_count * sizeof (int32_t)
                 + mask_bytes);

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
  if (!h->th)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _ ("Failed to send a message to the statistics service\n"));
      GNUNET_CLIENT_disconnect (h->client);
      GNUNET_free (h);
      return NULL;
    }

  size = sizeof (struct GNUNET_SCALARPRODUCT_client_request) +element_count * sizeof (int32_t) + mask_bytes;

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
  msg->mask_length = htons (mask_bytes);

  vector = (int32_t*) & msg[1];
  // copy each element over to the message
  for (i = 0; i < element_count; i++)
    vector[i] = htonl (elements[i]);

  memcpy (&msg->peer, peer, sizeof (struct GNUNET_PeerIdentity));
  memcpy (&msg->key, key, sizeof (struct GNUNET_HashCode));
  memcpy (&vector[element_count], mask, mask_bytes);

  h->th = GNUNET_CLIENT_notify_transmit_ready (h->client, size,
                                               GNUNET_TIME_UNIT_FOREVER_REL,
                                               GNUNET_YES, // retry is OK in the initial stage
                                               &transmit_request, h);
  if (!h->th)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _ ("Failed to send a message to the scalarproduct service\n"));
      GNUNET_STATISTICS_destroy (h->stats, GNUNET_YES);
      GNUNET_CLIENT_disconnect (h->client);
      GNUNET_free (h->msg);
      GNUNET_free (h);
      return NULL;
    }
  GNUNET_CONTAINER_DLL_insert (head, tail, h);
  return h;
}


/**
 * Disconnect from the scalarproduct service.
 * 
 * @param h a computation handle to cancel
 */
void
GNUNET_SCALARPRODUCT_cancel (struct GNUNET_SCALARPRODUCT_ComputationHandle * h)
{
  struct GNUNET_SCALARPRODUCT_ComputationHandle * qe;

  for (qe = head; head != NULL; qe = head)
    {
      if (qe == h)
        {
          GNUNET_CONTAINER_DLL_remove (head, tail, qe);
          LOG (GNUNET_ERROR_TYPE_INFO,
               "Disconnecting from VectorProduct\n");
          if (NULL == qe->th)
            GNUNET_CLIENT_notify_transmit_ready_cancel (qe->th);
          GNUNET_CLIENT_disconnect (h->client);
          GNUNET_STATISTICS_destroy (h->stats, GNUNET_YES);
          GNUNET_free (qe->msg);
          GNUNET_free (qe);
          break;
        }
    }
}

/* end of ext_api.c */
