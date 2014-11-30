/*
     This file is part of GNUnet.
     (C) 2013, 2014 Christian Grothoff (and other contributing authors)

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
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_scalarproduct_service.h"
#include "gnunet_protocols.h"
#include "scalarproduct.h"

#define LOG(kind,...) GNUNET_log_from (kind, "scalarproduct-api",__VA_ARGS__)


/**
 * The abstraction function for our internal callback
 *
 * @param h computation handle
 * @param msg response we got, NULL on errors
 * @param status processing status code
 */
typedef void
(*GNUNET_SCALARPRODUCT_ResponseMessageHandler) (struct GNUNET_SCALARPRODUCT_ComputationHandle *h,
                                                const struct ClientResponseMessage *msg,
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
   * The shared session key identifying this computation
   */
  struct GNUNET_HashCode key;

  /**
   * Current transmit handle.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * count of all @e elements we offer for computation
   */
  uint32_t element_count_total;

  /**
   * count of the transfered @e elements we offer for computation
   */
  uint32_t element_count_transfered;

  /**
   * the client's elements which
   */
  struct GNUNET_SCALARPRODUCT_Element *elements;

  /**
   * Message to be sent to the scalarproduct service
   */
  struct GNUNET_MessageHeader *msg;

  /**
   * Function to call after transmission of the request (Bob).
   */
  GNUNET_SCALARPRODUCT_ContinuationWithStatus cont_status;

  /**
   * Function to call after transmission of the request (Alice).
   */
  GNUNET_SCALARPRODUCT_DatumProcessor cont_datum;

  /**
   * Closure for @e cont_status or @e cont_datum.
   */
  void *cont_cls;

  /**
   * API internal callback for results and failures to be forwarded to
   * the client.
   */
  GNUNET_SCALARPRODUCT_ResponseMessageHandler response_proc;

};


/**
 * Handles the STATUS received from the service for a response, does
 * not contain a payload.
 *
 * @param h our Handle
 * @param msg Pointer to the response received
 * @param status the condition the request was terminated with (eg: disconnect)
 */
static void
process_status_message (struct GNUNET_SCALARPRODUCT_ComputationHandle *h,
                        const struct ClientResponseMessage *msg,
                        enum GNUNET_SCALARPRODUCT_ResponseStatus status)
{
  if (NULL != h->cont_status)
    h->cont_status (h->cont_cls,
                    status);
  GNUNET_SCALARPRODUCT_cancel (h);
}


/**
 * Handles the RESULT received from the service for a request, should
 * contain a result MPI value
 *
 * @param h our Handle
 * @param msg Pointer to the response received
 * @param status the condition the request was terminated with (eg: disconnect)
 */
static void
process_result_message (struct GNUNET_SCALARPRODUCT_ComputationHandle *h,
                        const struct ClientResponseMessage *msg,
                        enum GNUNET_SCALARPRODUCT_ResponseStatus status)
{
  size_t product_len = ntohl (msg->product_length);
  gcry_mpi_t result = NULL;
  gcry_error_t rc;
  gcry_mpi_t num;
  size_t rsize;

  if ( (GNUNET_SCALARPRODUCT_Status_Success == status) &&
       ( (NULL == msg) ||
         ( (ntohs (msg->header.size) - sizeof (struct ClientResponseMessage)
            != product_len) ) ) )
  {
    GNUNET_break (0);
    status = GNUNET_SCALARPRODUCT_Status_InvalidResponse;
  }
  if (GNUNET_SCALARPRODUCT_Status_Success == status)
  {
    result = gcry_mpi_new (0);

    if (0 < product_len)
    {
      rsize = 0;
      if (0 != (rc = gcry_mpi_scan (&num, GCRYMPI_FMT_STD,
                                    &msg[1],
                                    product_len,
                                    &rsize)))
      {
        LOG_GCRY (GNUNET_ERROR_TYPE_ERROR,
                  "gcry_mpi_scan",
                  rc);
        gcry_mpi_release (result);
        result = NULL;
        status = GNUNET_SCALARPRODUCT_Status_InvalidResponse;
      }
      else
      {
        if (0 < ntohl (msg->range))
          gcry_mpi_add (result, result, num);
        else if (0 > ntohl (msg->range))
          gcry_mpi_sub (result, result, num);
        gcry_mpi_release (num);
      }
    }
  }
  h->cont_datum (h->cont_cls,
                 status,
                 result);
  if (NULL != result)
    gcry_mpi_release (result);
  GNUNET_SCALARPRODUCT_cancel (h);
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
receive_cb (void *cls,
            const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_SCALARPRODUCT_ComputationHandle *h = cls;
  const struct ClientResponseMessage *message;

  if (NULL == msg)
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         "Disconnected from SCALARPRODUCT service.\n");
    h->response_proc (h,
                      NULL,
                      GNUNET_SCALARPRODUCT_Status_ServiceDisconnected);
    return;
  }
  if (ntohs (msg->size) != sizeof (struct ClientResponseMessage))
  {
    GNUNET_break (0);
    h->response_proc (h,
                      NULL,
                      GNUNET_SCALARPRODUCT_Status_InvalidResponse);
    return;
  }
  message = (const struct ClientResponseMessage *) msg;
  if (GNUNET_SYSERR == ntohl (message->status))
  {
    h->response_proc (h,
                      NULL,
                      GNUNET_SCALARPRODUCT_Status_Failure);
    return;
  }
  h->response_proc (h,
                    message,
                    GNUNET_SCALARPRODUCT_Status_Success);
}


/**
 * Transmits the request to the SCALARPRODUCT service
 *
 * @param cls Closure with the `struct GNUNET_SCALARPRODUCT_ComputationHandle`
 * @param size Size of the buffer @a buf
 * @param buf Pointer to the buffer
 * @return Size of the message sent
 */
static size_t
do_send_message (void *cls,
                 size_t size,
                 void *buf)
{
  struct GNUNET_SCALARPRODUCT_ComputationHandle *h = cls;
  struct ComputationMultipartMessage *msg;
  size_t ret;
  uint32_t nsize;
  uint32_t todo;

  h->th = NULL;
  if (NULL == buf)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Failed to transmit request to SCALARPRODUCT.\n");
    /* notify caller about the error, done here */
    h->response_proc (h, NULL,
                      GNUNET_SCALARPRODUCT_Status_Failure);
    return 0;
  }
  ret = ntohs (h->msg->size);
  memcpy (buf, h->msg, ret);
  GNUNET_free (h->msg);
  h->msg = NULL;

  /* done sending? */
  if (h->element_count_total == h->element_count_transfered)
  {
    GNUNET_CLIENT_receive (h->client,
                           &receive_cb, h,
                           GNUNET_TIME_UNIT_FOREVER_REL);
    return ret;
  }

  todo = h->element_count_total - h->element_count_transfered;
  nsize = sizeof (struct ComputationMultipartMessage)
    + todo * sizeof (struct GNUNET_SCALARPRODUCT_Element);
  if (GNUNET_SERVER_MAX_MESSAGE_SIZE <= size)
  {
    /* cannot do all of them, limit to what is possible in one message */
    todo = (GNUNET_SERVER_MAX_MESSAGE_SIZE - 1 - sizeof (struct ComputationMultipartMessage))
      / sizeof (struct GNUNET_SCALARPRODUCT_Element);
    nsize = sizeof (struct ComputationMultipartMessage)
      + todo * sizeof (struct GNUNET_SCALARPRODUCT_Element);
  }

  msg = GNUNET_malloc (nsize);
  h->msg = &msg->header;
  msg->header.size = htons (nsize);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_MUTLIPART);
  msg->element_count_contained = htonl (todo);
  memcpy (&msg[1],
          &h->elements[h->element_count_transfered],
          todo * sizeof (struct GNUNET_SCALARPRODUCT_Element));
  h->element_count_transfered += todo;
  h->th = GNUNET_CLIENT_notify_transmit_ready (h->client, nsize,
                                               GNUNET_TIME_UNIT_FOREVER_REL,
                                               GNUNET_NO,
                                               &do_send_message, h);
  GNUNET_assert (NULL != h->th);
  return ret;
}


/**
 * Used by Bob's client to cooperate with Alice,
 *
 * @param cfg the gnunet configuration handle
 * @param key Session key unique to the requesting client
 * @param elements Array of elements of the vector
 * @param element_count Number of elements in the @a elements vector
 * @param cont Callback function
 * @param cont_cls Closure for @a cont
 * @return a new handle for this computation
 */
struct GNUNET_SCALARPRODUCT_ComputationHandle *
GNUNET_SCALARPRODUCT_accept_computation (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                         const struct GNUNET_HashCode *session_key,
                                         const struct GNUNET_SCALARPRODUCT_Element *elements,
                                         uint32_t element_count,
                                         GNUNET_SCALARPRODUCT_ContinuationWithStatus cont,
                                         void *cont_cls)
{
  struct GNUNET_SCALARPRODUCT_ComputationHandle *h;
  struct ComputationMessage *msg;
  uint32_t size;
  uint16_t possible;

  h = GNUNET_new (struct GNUNET_SCALARPRODUCT_ComputationHandle);
  h->cont_status = cont;
  h->cont_cls = cont_cls;
  h->response_proc = &process_status_message;
  h->cfg = cfg;
  h->key = *session_key;
  h->client = GNUNET_CLIENT_connect ("scalarproduct", cfg);
  h->element_count_total = element_count;
  if (NULL == h->client)
  {
    /* scalarproduct configuration error */
    GNUNET_break (0);
    GNUNET_free (h);
    return NULL;
  }
  size = sizeof (struct ComputationMessage)
    + element_count * sizeof (struct GNUNET_SCALARPRODUCT_Element);
  if (GNUNET_SERVER_MAX_MESSAGE_SIZE > size)
  {
    possible = element_count;
    h->element_count_transfered = element_count;
  }
  else
  {
    /* create a multipart msg, first we calculate a new msg size for the head msg */
    possible = (GNUNET_SERVER_MAX_MESSAGE_SIZE - 1 - sizeof (struct ComputationMessage))
      / sizeof (struct GNUNET_SCALARPRODUCT_Element);
    h->element_count_transfered = possible;
    size = sizeof (struct ComputationMessage)
      + possible * sizeof (struct GNUNET_SCALARPRODUCT_Element);
    h->elements = GNUNET_malloc (sizeof(struct GNUNET_SCALARPRODUCT_Element) * element_count);
    memcpy (h->elements,
            elements,
            sizeof (struct GNUNET_SCALARPRODUCT_Element) * element_count);
  }

  msg = GNUNET_malloc (size);
  h->msg = &msg->header;
  msg->header.size = htons (size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_TO_BOB);
  msg->element_count_total = htonl (element_count);
  msg->element_count_contained = htonl (possible);
  msg->session_key = *session_key;
  memcpy (&msg[1],
          elements,
          possible * sizeof (struct GNUNET_SCALARPRODUCT_Element));
  h->th = GNUNET_CLIENT_notify_transmit_ready (h->client, size,
                                               GNUNET_TIME_UNIT_FOREVER_REL,
                                               GNUNET_YES, /* retry is OK in the initial stage */
                                               &do_send_message, h);
  GNUNET_assert (NULL != h->th);
  return h;
}


/**
 * Request by Alice's client for computing a scalar product
 *
 * @param cfg the gnunet configuration handle
 * @param session_key Session key should be unique to the requesting client
 * @param peer PeerID of the other peer
 * @param elements Array of elements of the vector
 * @param element_count Number of elements in the @a elements vector
 * @param cont Callback function
 * @param cont_cls Closure for @a cont
 * @return a new handle for this computation
 */
struct GNUNET_SCALARPRODUCT_ComputationHandle *
GNUNET_SCALARPRODUCT_start_computation (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                        const struct GNUNET_HashCode *session_key,
                                        const struct GNUNET_PeerIdentity *peer,
                                        const struct GNUNET_SCALARPRODUCT_Element *elements,
                                        uint32_t element_count,
                                        GNUNET_SCALARPRODUCT_DatumProcessor cont,
                                        void *cont_cls)
{
  struct GNUNET_SCALARPRODUCT_ComputationHandle *h;
  struct ComputationMessage *msg;
  uint32_t size;
  uint32_t possible;

  h = GNUNET_new (struct GNUNET_SCALARPRODUCT_ComputationHandle);
  h->client = GNUNET_CLIENT_connect ("scalarproduct", cfg);
  if (NULL == h->client)
  {
    /* missconfigured scalarproduct service */
    GNUNET_break (0);
    GNUNET_free (h);
    return NULL;
  }
  h->element_count_total = element_count;
  h->cont_datum = cont;
  h->cont_cls = cont_cls;
  h->response_proc = &process_result_message;
  h->cfg = cfg;
  h->key = *session_key;
  size = sizeof (struct ComputationMessage)
    + element_count * sizeof (struct GNUNET_SCALARPRODUCT_Element);
  if (GNUNET_SERVER_MAX_MESSAGE_SIZE > size)
  {
    possible = element_count;
    h->element_count_transfered = element_count;
  }
  else
  {
    /* create a multipart msg, first we calculate a new msg size for the head msg */
    possible = (GNUNET_SERVER_MAX_MESSAGE_SIZE - 1 - sizeof (struct ComputationMessage))
      / sizeof (struct GNUNET_SCALARPRODUCT_Element);
    h->element_count_transfered = possible;
    size = sizeof (struct ComputationMessage)
      + possible * sizeof (struct GNUNET_SCALARPRODUCT_Element);
    h->elements = GNUNET_malloc (sizeof(struct GNUNET_SCALARPRODUCT_Element) * element_count);
    memcpy (h->elements,
            elements,
            sizeof (struct GNUNET_SCALARPRODUCT_Element) * element_count);
  }

  msg = GNUNET_malloc (size);
  h->msg = &msg->header;
  msg->header.size = htons (size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_TO_ALICE);
  msg->element_count_total = htonl (element_count);
  msg->element_count_contained = htonl (possible);
  msg->reserved = htonl (0);
  msg->peer = *peer;
  msg->session_key = *session_key;
  memcpy (&msg[1],
          elements,
          sizeof (struct GNUNET_SCALARPRODUCT_Element) * possible);
  h->th = GNUNET_CLIENT_notify_transmit_ready (h->client, size,
                                               GNUNET_TIME_UNIT_FOREVER_REL,
                                               GNUNET_YES, /* retry is OK in the initial stage */
                                               &do_send_message, h);
  GNUNET_assert (NULL != h->th);
  return h;
}


/**
 * Cancel an ongoing computation or revoke our collaboration offer.
 * Closes the connection to the service
 *
 * @param h computation handle to terminate
 */
void
GNUNET_SCALARPRODUCT_cancel (struct GNUNET_SCALARPRODUCT_ComputationHandle *h)
{
  if (NULL != h->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->th);
    h->th = NULL;
  }
  GNUNET_free_non_null (h->elements);
  GNUNET_free_non_null (h->msg);
  if (NULL != h->client)
  {
    GNUNET_CLIENT_disconnect (h->client);
    h->client = NULL;
  }
  GNUNET_free (h);
}


/* end of scalarproduct_api.c */
