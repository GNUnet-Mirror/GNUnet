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
 * @file include/gnunet_vectorproduct_service.h
 * @brief API to the vectorproduct service
 * @author Christian M. Fuchs
 * @author Gaurav Kukreja
 */
#ifndef GNUNET_VECTORPRODUCT_SERVICE_H
#define GNUNET_VECTORPRODUCT_SERVICE_H
#define GCRYPT_NO_DEPRECATED
// including gcrypt crashes netbeans after the next restart...
#include <gcrypt.h>

#ifdef __cplusplus
extern "C" {
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Version of the vectorproduct API.
 */
#define GNUNET_VECTORPRODUCT_VERSION 0x00000042

/**
 * Message type passed from client to service 
 * to initiate a request or responder role
 */
struct GNUNET_VECTORPRODUCT_client_request {
  /**
   * GNUNET message header
   */
  struct GNUNET_MessageHeader header;

  /**
   * how many elements the vector in payload contains
   */
  uint16_t element_count GNUNET_PACKED; 

  /**
   * how many bytes the mask has
   */
  uint16_t mask_length GNUNET_PACKED;
  
  /**
   * the transaction/session key used to identify a session
   */
  struct GNUNET_HashCode key;

  /**
   * the identity of a remote peer we want to communicate with
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * followed by long vector[element_count] | [unsigned char mask[mask_bytes]]
   */
};

/**
 * Message type passed from service client
 * to finalize a session as requester or responder
 */
struct GNUNET_VECTORPRODUCT_client_response {
  /**
   * GNUNET message header
   */
  struct GNUNET_MessageHeader header;

  /**
   * 0 if no product attached
   */
  uint32_t product_length GNUNET_PACKED;

  /**
   * the transaction/session key used to identify a session
   */
  struct GNUNET_HashCode key;

  /**
   * the identity of a remote peer we want to communicate with
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * followed by product of length product_length (or nothing)
   */
};

enum GNUNET_VECTORPRODUCT_ResponseStatus {
  GNUNET_VECTORPRODUCT_Status_Success = 0,
  GNUNET_VECTORPRODUCT_Status_Failure,
  GNUNET_VECTORPRODUCT_Status_Timeout,
  GNUNET_VECTORPRODUCT_Status_InvalidResponse,
  GNUNET_VECTORPRODUCT_Status_ServiceDisconnected
};

struct GNUNET_VECTORPRODUCT_Handle {
  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Current connection to the vectorproduct service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Handle for statistics.
   */
  struct GNUNET_STATISTICS_Handle *stats;

  /**
   * Current head of priority queue.
   */
  struct GNUNET_VECTORPRODUCT_QueueEntry *queue_head;

  /**
   * Current tail of priority queue.
   */
  struct GNUNET_VECTORPRODUCT_QueueEntry *queue_tail;

  /**
   * Are we currently trying to receive from the service?
   */
  int in_receive;

  /**
   * Current transmit handle.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * TODO: What else should/could go here?
   */
};

typedef void (*GNUNET_VECTORPRODUCT_ResponseMessageHandler) (void *cls,
        const struct GNUNET_MessageHeader *msg,
        enum GNUNET_VECTORPRODUCT_ResponseStatus status);

/**
 * Continuation called to notify client about result of the
 * operation.
 *
 * @param cls closure
 * @param success GNUNET_SYSERR on failure (including timeout/queue drop)
 *                GNUNET_NO if content was already there
 *                GNUNET_YES (or other positive value) on success
 * @param msg NULL on success, otherwise an error message
 */
typedef void (*GNUNET_VECTORPRODUCT_ContinuationWithStatus) (void *cls,
        const struct GNUNET_HashCode * key,
        enum GNUNET_VECTORPRODUCT_ResponseStatus status);
/**
 * Process a datum that was stored in the vectorproduct.
 * 
 * @param cls closure
 * @param key Sessioon key
 * @param peer PeerID of the peer with whom the scalar product was calculated.
 * @param status Status of the request
 * @param size Size of the received message
 * @param data Pointer to the data
 * @param type Type of data
 */
typedef void (*GNUNET_VECTORPRODUCT_DatumProcessor) (void *cls,
        const struct GNUNET_HashCode * key,
        const struct GNUNET_PeerIdentity * peer,
        enum GNUNET_VECTORPRODUCT_ResponseStatus status,
        const struct GNUNET_VECTORPRODUCT_client_response *msg);

/**
 * Request the Scalar Product Evaluation
 * 
 * @param h handle to the master context
 * @param key Session key - unique to the requesting client
 * @param peer PeerID of the other peer
 * @param element_count Number of elements in the vector
 * @param mask_bytes number of bytes in the mask
 * @param elements Array of elements of the vector
 * @param mask Array of the mask
 * @param timeout Relative timeout for the operation
 * @param cont Callback function
 * @param cont_cls Closure for the callback function
 */
struct GNUNET_VECTORPRODUCT_QueueEntry *
GNUNET_VECTORPRODUCT_request(struct GNUNET_VECTORPRODUCT_Handle *h,
        const struct GNUNET_HashCode * key,
        const struct GNUNET_PeerIdentity *peer,
        uint16_t element_count,
        uint16_t mask_bytes,
        int32_t * elements, const unsigned char * mask,
        struct GNUNET_TIME_Relative timeout,
        GNUNET_VECTORPRODUCT_DatumProcessor cont,
        void *cont_cls);

/**
 * Called by the responder client to prepare response
 * 
 * @param h handle to the master context
 * @param key Session key - unique to the requesting client
 * @param element_count Number of elements in the vector
 * @param mask_bytes number of bytes in the mask
 * @param elements Array of elements of the vector
 * @param mask Array of the mask
 * @param timeout Relative timeout for the operation
 * @param cont Callback function
 * @param cont_cls Closure for the callback function
 */
struct GNUNET_VECTORPRODUCT_QueueEntry *
GNUNET_VECTORPRODUCT_prepare_response(struct GNUNET_VECTORPRODUCT_Handle *h,
        const struct GNUNET_HashCode * key,
        uint16_t element_count,
        int32_t* elements,
        struct GNUNET_TIME_Relative timeout,
        GNUNET_VECTORPRODUCT_ContinuationWithStatus cont,
        void *cont_cls);

/**
 * Connect to the vectorproduct service.
 *
 * @param cfg configuration to use
 * @return handle to use to access the service
 */
struct GNUNET_VECTORPRODUCT_Handle *
GNUNET_VECTORPRODUCT_connect(const struct GNUNET_CONFIGURATION_Handle * cfg);

/**
 * Disconnect from the vectorproduct service.
 * 
 * @param h handle to the vectorproduct
 */
void
GNUNET_VECTORPRODUCT_disconnect(struct GNUNET_VECTORPRODUCT_Handle * h);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
