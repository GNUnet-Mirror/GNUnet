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
 * @file include/gnunet_scalarproduct_service.h
 * @brief API to the scalarproduct service
 * @author Christian M. Fuchs
 * @author Gaurav Kukreja
 */
#ifndef GNUNET_SCALARPRODUCT_SERVICE_H
#define GNUNET_SCALARPRODUCT_SERVICE_H
#define GCRYPT_NO_DEPRECATED
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
#define GNUNET_SCALARPRODUCT_VERSION 0x00000044

/**
 * Result status values for the computation.
 */
enum GNUNET_SCALARPRODUCT_ResponseStatus
{

  /**
   * Operation is still active (never returned, used internally).
   */
  GNUNET_SCALARPRODUCT_STATUS_ACTIVE = 0,

  /**
   * The computation was successful.
   */
  GNUNET_SCALARPRODUCT_STATUS_SUCCESS,

  /**
   * We encountered some error.
   */
  GNUNET_SCALARPRODUCT_STATUS_FAILURE,

  /**
   * We got an invalid response.
   */
  GNUNET_SCALARPRODUCT_STATUS_INVALID_RESPONSE,

  /**
   * We got disconnected from the SCALARPRODUCT service.
   */
  GNUNET_SCALARPRODUCT_STATUS_DISCONNECTED
};


/**
 * Opaque declaration of the SP-Handle
 */
struct GNUNET_SCALARPRODUCT_Handle;


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * An element key-value pair for scalarproduct
 */
struct GNUNET_SCALARPRODUCT_Element
{
  /**
   * Key used to identify matching pairs of values to multiply.
   */
  struct GNUNET_HashCode key;

  /**
   * Value to multiply in scalar product, in NBO.
   */
  int64_t value GNUNET_PACKED;
};

GNUNET_NETWORK_STRUCT_END


/**
 * Continuation called to notify client about result of the
 * operation.
 *
 * @param cls closure
 * @param status Status of the request
 */
typedef void
(*GNUNET_SCALARPRODUCT_ContinuationWithStatus) (void *cls,
                                                enum GNUNET_SCALARPRODUCT_ResponseStatus status);


/**
 * Process a datum that was stored in the scalarproduct.
 *
 * @param cls closure
 * @param status Status of the request
 * @param result result of the computation
 */
typedef void
(*GNUNET_SCALARPRODUCT_DatumProcessor) (void *cls,
                                        enum GNUNET_SCALARPRODUCT_ResponseStatus status,
                                        gcry_mpi_t result);


/**
 * Entry in the request queue per client
 */
struct GNUNET_SCALARPRODUCT_ComputationHandle;


/**
 * Request by Alice's client for computing a scalar product
 *
 * @param cfg the gnunet configuration handle
 * @param session_key Session key should be unique to the requesting client
 * @param peer PeerID of the other peer
 * @param elements Array of elements of the vector
 * @param element_count Number of elements in the @a elements vector
 * @param cont Callback function
 * @param cont_cls Closure for the @a cont callback function
 * @return a new handle for this computation
 */
struct GNUNET_SCALARPRODUCT_ComputationHandle *
GNUNET_SCALARPRODUCT_start_computation (const struct GNUNET_CONFIGURATION_Handle *cfg,
                              const struct GNUNET_HashCode *session_key,
                              const struct GNUNET_PeerIdentity *peer,
                              const struct GNUNET_SCALARPRODUCT_Element *elements,
                              uint32_t element_count,
                              GNUNET_SCALARPRODUCT_DatumProcessor cont,
                              void *cont_cls);


/**
 * Used by Bob's client to cooperate with Alice,
 *
 * @param cfg the gnunet configuration handle
 * @param session_key Session key unique to the requesting client
 * @param elements Array of elements of the vector
 * @param element_count Number of elements in the @a elements vector
 * @param cont Callback function
 * @param cont_cls Closure for the @a cont callback function
 * @return a new handle for this computation
 */
struct GNUNET_SCALARPRODUCT_ComputationHandle *
GNUNET_SCALARPRODUCT_accept_computation (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                         const struct GNUNET_HashCode *key,
                                         const struct GNUNET_SCALARPRODUCT_Element *elements,
                                         uint32_t element_count,
                                         GNUNET_SCALARPRODUCT_ContinuationWithStatus cont,
                                         void *cont_cls);


/**
 * Cancel an ongoing computation or revoke our collaboration offer.
 * Closes the connection to the service
 *
 * @param h computation handle to terminate
 */
void
GNUNET_SCALARPRODUCT_cancel (struct GNUNET_SCALARPRODUCT_ComputationHandle *h);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
