/*
     This file is part of GNUnet.
     Copyright (C) 2013, 2014, 2016 GNUnet e.V.

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
  struct GNUNET_MQ_Handle *mq;

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

  /**
   * The shared session key identifying this computation
   */
  struct GNUNET_HashCode key;

};


/**
 * Called when a response is received from the service. Perform basic
 * check that the message is well-formed.
 *
 * @param cls Pointer to the Master Context
 * @param message Pointer to the data received in response
 * @return #GNUNET_OK if @a message is well-formed
 */
static int
check_response (void *cls,
                 const struct ClientResponseMessage *message)
{
  if (ntohs (message->header.size) !=
      ntohl (message->product_length) + sizeof (struct ClientResponseMessage))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handles the STATUS received from the service for a response, does
 * not contain a payload.  Called when we participate as "Bob" via
 * #GNUNET_SCALARPRODUCT_accept_computation().
 *
 * @param h our Handle
 * @param msg the response received
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
 * Called when a response is received from the service. After basic
 * check, the handler in `h->response_proc` is called. This functions
 * handles the response to the client which used the API.
 *
 * @param cls Pointer to the Master Context
 * @param msg Pointer to the data received in response
 */
static void
handle_response (void *cls,
                 const struct ClientResponseMessage *message)
{
  struct GNUNET_SCALARPRODUCT_ComputationHandle *h = cls;
  enum GNUNET_SCALARPRODUCT_ResponseStatus status;

  status = (enum GNUNET_SCALARPRODUCT_ResponseStatus) ntohl (message->status);
  h->response_proc (h,
                    message,
                    status);
}


/**
 * Check if the keys for all given elements are unique.
 *
 * @param elements elements to check
 * @param element_count size of the @a elements array
 * @return #GNUNET_OK if all keys are unique
 */
static int
check_unique (const struct GNUNET_SCALARPRODUCT_Element *elements,
              uint32_t element_count)
{
  struct GNUNET_CONTAINER_MultiHashMap *map;
  uint32_t i;
  int ok;

  ok = GNUNET_OK;
  map = GNUNET_CONTAINER_multihashmap_create (2 * element_count,
                                              GNUNET_YES);
  for (i=0;i<element_count;i++)
    if (GNUNET_OK !=
        GNUNET_CONTAINER_multihashmap_put (map,
                                           &elements[i].key,
                                           map,
                                           GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Keys given to SCALARPRODUCT not unique!\n"));
      ok = GNUNET_SYSERR;
    }
  GNUNET_CONTAINER_multihashmap_destroy (map);
  return ok;
}


/**
 * We encountered an error communicating with the set service while
 * performing a set operation. Report to the application.
 *
 * @param cls the `struct GNUNET_SCALARPRODUCT_ComputationHandle`
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_SCALARPRODUCT_ComputationHandle *h = cls;

  LOG (GNUNET_ERROR_TYPE_INFO,
       "Disconnected from SCALARPRODUCT service.\n");
  h->response_proc (h,
                    NULL,
                    GNUNET_SCALARPRODUCT_STATUS_DISCONNECTED);
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
  GNUNET_MQ_hd_var_size (response,
			 GNUNET_MESSAGE_TYPE_SCALARPRODUCT_RESULT,
			 struct ClientResponseMessage);
  struct GNUNET_SCALARPRODUCT_ComputationHandle *h
    = GNUNET_new (struct GNUNET_SCALARPRODUCT_ComputationHandle);
  struct GNUNET_MQ_MessageHandler handlers[] = {
    make_response_handler (h),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MQ_Envelope *env;
  struct BobComputationMessage *msg;
  struct ComputationBobCryptodataMultipartMessage *mmsg;
  uint32_t size;
  uint16_t possible;
  uint16_t todo;
  uint32_t element_count_transfered;


  if (GNUNET_SYSERR == check_unique (elements,
                                     element_count))
    return NULL;
  h->cont_status = cont;
  h->cont_cls = cont_cls;
  h->response_proc = &process_status_message;
  h->cfg = cfg;
  h->key = *session_key;
  h->mq = GNUNET_CLIENT_connecT (cfg,
                                 "scalarproduct-bob",
                                 handlers,
                                 &mq_error_handler,
                                 h);
  if (NULL == h->mq)
  {
    /* scalarproduct configuration error */
    GNUNET_break (0);
    GNUNET_free (h);
    return NULL;
  }
  possible = (GNUNET_SERVER_MAX_MESSAGE_SIZE - 1 - sizeof (struct BobComputationMessage))
    / sizeof (struct GNUNET_SCALARPRODUCT_Element);
  todo = GNUNET_MIN (possible,
                     element_count);
  size = todo * sizeof (struct GNUNET_SCALARPRODUCT_Element);
  env = GNUNET_MQ_msg_extra (msg,
                             size,
                             GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_TO_BOB);
  msg->element_count_total = htonl (element_count);
  msg->element_count_contained = htonl (todo);
  msg->session_key = *session_key;
  memcpy (&msg[1],
          elements,
          size);
  element_count_transfered = todo;
  GNUNET_MQ_send (h->mq,
                  env);
  possible = (GNUNET_SERVER_MAX_MESSAGE_SIZE - 1 - sizeof (*mmsg))
    / sizeof (struct GNUNET_SCALARPRODUCT_Element);
  while (element_count_transfered < element_count)
  {
    todo = GNUNET_MIN (possible,
                       element_count - element_count_transfered);
    size = todo * sizeof (struct GNUNET_SCALARPRODUCT_Element);
    env = GNUNET_MQ_msg_extra (mmsg,
                               size,
                               GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_MUTLIPART_BOB);
    mmsg->element_count_contained = htonl (todo);
    memcpy (&mmsg[1],
            &elements[element_count_transfered],
            size);
    element_count_transfered += todo;
    GNUNET_MQ_send (h->mq,
                    env);
  }
  return h;
}


/**
 * Handles the RESULT received from the service for a request, should
 * contain a result MPI value.  Called when we participate as "Alice" via
 * #GNUNET_SCALARPRODUCT_start_computation().
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
  uint32_t product_len;
  gcry_mpi_t result = NULL;
  gcry_error_t rc;
  gcry_mpi_t num;
  size_t rsize;

  if (GNUNET_SCALARPRODUCT_STATUS_SUCCESS == status)
  {
    result = gcry_mpi_new (0);

    product_len = ntohl (msg->product_length);
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
        status = GNUNET_SCALARPRODUCT_STATUS_INVALID_RESPONSE;
      }
      else
      {
        if (0 < (int32_t) ntohl (msg->range))
          gcry_mpi_add (result, result, num);
        else
          gcry_mpi_sub (result, result, num);
        gcry_mpi_release (num);
      }
    }
  }
  if (NULL != h->cont_datum)
    h->cont_datum (h->cont_cls,
                   status,
                   result);
  if (NULL != result)
    gcry_mpi_release (result);
  GNUNET_SCALARPRODUCT_cancel (h);
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
  GNUNET_MQ_hd_var_size (response,
			 GNUNET_MESSAGE_TYPE_SCALARPRODUCT_RESULT,
			 struct ClientResponseMessage);
  struct GNUNET_SCALARPRODUCT_ComputationHandle *h
    = GNUNET_new (struct GNUNET_SCALARPRODUCT_ComputationHandle);
  struct GNUNET_MQ_MessageHandler handlers[] = {
    make_response_handler (h),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MQ_Envelope *env;
  struct AliceComputationMessage *msg;
  struct ComputationBobCryptodataMultipartMessage *mmsg;
  uint32_t size;
  uint16_t possible;
  uint16_t todo;
  uint32_t element_count_transfered;

  if (GNUNET_SYSERR == check_unique (elements,
                                     element_count))
    return NULL;
  h->mq = GNUNET_CLIENT_connecT (cfg,
                                 "scalarproduct-alice",
                                 handlers,
                                 &mq_error_handler,
                                 h);
  if (NULL == h->mq)
  {
    /* missconfigured scalarproduct service */
    GNUNET_break (0);
    GNUNET_free (h);
    return NULL;
  }
  h->cont_datum = cont;
  h->cont_cls = cont_cls;
  h->response_proc = &process_result_message;
  h->cfg = cfg;
  h->key = *session_key;

  possible = (GNUNET_SERVER_MAX_MESSAGE_SIZE - 1 - sizeof (struct AliceComputationMessage))
      / sizeof (struct GNUNET_SCALARPRODUCT_Element);
  todo = GNUNET_MIN (possible,
                     element_count);
  size = todo * sizeof (struct GNUNET_SCALARPRODUCT_Element);
  env = GNUNET_MQ_msg_extra (msg,
                             size,
                             GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_TO_ALICE);
  msg->element_count_total = htonl (element_count);
  msg->element_count_contained = htonl (todo);
  msg->reserved = htonl (0);
  msg->peer = *peer;
  msg->session_key = *session_key;
  memcpy (&msg[1],
          elements,
          size);
  GNUNET_MQ_send (h->mq,
                  env);
  element_count_transfered = todo;
  possible = (GNUNET_SERVER_MAX_MESSAGE_SIZE - 1 - sizeof (*mmsg))
    / sizeof (struct GNUNET_SCALARPRODUCT_Element);
  while (element_count_transfered < element_count)
  {
    todo = GNUNET_MIN (possible,
                       element_count - element_count_transfered);
    size = todo * sizeof (struct GNUNET_SCALARPRODUCT_Element);
    env = GNUNET_MQ_msg_extra (mmsg,
                               size,
                               GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_MUTLIPART_ALICE);
    mmsg->element_count_contained = htonl (todo);
    memcpy (&mmsg[1],
            &elements[element_count_transfered],
            size);
    element_count_transfered += todo;
    GNUNET_MQ_send (h->mq,
                    env);
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
GNUNET_SCALARPRODUCT_cancel (struct GNUNET_SCALARPRODUCT_ComputationHandle *h)
{
  if (NULL != h->mq)
  {
    GNUNET_MQ_destroy (h->mq);
    h->mq = NULL;
  }
  GNUNET_free (h);
}


/* end of scalarproduct_api.c */
