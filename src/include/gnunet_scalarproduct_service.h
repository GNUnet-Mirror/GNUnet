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
 * @file include/gnunet_scalarproduct_service.h
 * @brief API to the scalarproduct service
 * @author Christian M. Fuchs
 * @author Gaurav Kukreja
 */
#ifndef GNUNET_SCALARPRODUCT_SERVICE_H
#define GNUNET_SCALARPRODUCT_SERVICE_H
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
 * Version of the scalarproduct API.
 */
#define GNUNET_SCALARPRODUCT_VERSION 0x00000042

/**
 * Message type passed from client to service 
 * to initiate a request or responder role
 */
struct GNUNET_SCALARPRODUCT_client_request
{
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
struct GNUNET_SCALARPRODUCT_client_response
{
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
   * Workaround for libgcrypt: -1 if negative, 0 if zero, else 1
   */
  int8_t range;

  /**
   * followed by product of length product_length (or nothing)
   */
};

enum GNUNET_SCALARPRODUCT_ResponseStatus
{
  GNUNET_SCALARPRODUCT_Status_Success = 0,
  GNUNET_SCALARPRODUCT_Status_Failure,
  GNUNET_SCALARPRODUCT_Status_Timeout,
  GNUNET_SCALARPRODUCT_Status_InvalidResponse,
  GNUNET_SCALARPRODUCT_Status_ServiceDisconnected
};

struct GNUNET_SCALARPRODUCT_Handle
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
   * Current transmit handle.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;
  
  /**
   * Handle to the master context.
   */
  struct GNUNET_SCALARPRODUCT_Handle *h;
  
  /**
   * The shared session key identifying this computation
   */
  struct GNUNET_HashCode * key;
  
  /**
   * The message to be transmitted
   */
  void * msg;

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

typedef void (*GNUNET_SCALARPRODUCT_ResponseMessageHandler) (void *cls,
                                                             const struct GNUNET_MessageHeader *msg,
                                                             enum GNUNET_SCALARPRODUCT_ResponseStatus status);

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
typedef void (*GNUNET_SCALARPRODUCT_ContinuationWithStatus) (void *cls,
                                                             enum GNUNET_SCALARPRODUCT_ResponseStatus status);
/**
 * Process a datum that was stored in the scalarproduct.
 * 
 * @param cls closure
 * @param key Sessioon key
 * @param peer PeerID of the peer with whom the scalar product was calculated.
 * @param status Status of the request
 * @param size Size of the received message
 * @param data Pointer to the data
 * @param type Type of data
 */
typedef void (*GNUNET_SCALARPRODUCT_DatumProcessor) (void *cls,
                                                     enum GNUNET_SCALARPRODUCT_ResponseStatus status,
                                                     gcry_mpi_t result);

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
struct GNUNET_SCALARPRODUCT_Handle *
GNUNET_SCALARPRODUCT_request (const struct GNUNET_CONFIGURATION_Handle *h,
                              const struct GNUNET_HashCode * key,
                              const struct GNUNET_PeerIdentity *peer,
                              const int32_t * elements,
                              uint32_t element_count,
                              const unsigned char * mask,
                              uint32_t mask_bytes,
                              GNUNET_SCALARPRODUCT_DatumProcessor cont,
                              void *cont_cls);

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
struct GNUNET_SCALARPRODUCT_Handle *
GNUNET_SCALARPRODUCT_response (const struct GNUNET_CONFIGURATION_Handle *h,
                               const struct GNUNET_HashCode * key,
                               const int32_t * elements,
                               uint32_t element_count,
                               GNUNET_SCALARPRODUCT_ContinuationWithStatus cont,
                               void *cont_cls);
/**
 * Cancel an ongoing computation or revoke our collaboration offer.
 * Closes the connection to the service
 * 
 * @param h handel to terminate
 */
void 
GNUNET_SCALARPRODUCT_cancel (const struct GNUNET_SCALARPRODUCT_Handle *h);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
