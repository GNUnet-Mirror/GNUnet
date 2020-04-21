/*
      This file is part of GNUnet
      Copyright (C) 2013 GNUnet e.V.

      GNUnet is free software: you can redistribute it and/or modify it
      under the terms of the GNU Affero General Public License as published
      by the Free Software Foundation, either version 3 of the License,
      or (at your option) any later version.

      GNUnet is distributed in the hope that it will be useful, but
      WITHOUT ANY WARRANTY; without even the implied warranty of
      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
      Affero General Public License for more details.

      You should have received a copy of the GNU Affero General Public License
      along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

#ifndef GNUNET_REVOCATION_SERVICE_H_
#define GNUNET_REVOCATION_SERVICE_H_

/**
 * @author Christian Grothoff
 *
 * @file
 * API to perform and access key revocations
 *
 * @defgroup revocation  Revocation service
 * Perform and access key revocations.
 *
 * @see [Documentation](https://gnunet.org/revocation-subsystem)
 *
 * @{
 */

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"

/**
 * Version of the key revocation API.
 */
#define GNUNET_REVOCATION_VERSION 0x00000000

/**
 * The proof-of-work narrowing factor.
 * The number of PoWs that are calculates as part of revocation.
 */
#define POW_COUNT 32


GNUNET_NETWORK_STRUCT_BEGIN

struct GNUNET_REVOCATION_Pow
{
  /**
   * The timestamp of the revocation
   */
  struct GNUNET_TIME_AbsoluteNBO timestamp;

  /**
   * The TTL of this revocation (purely informational)
   */
  struct GNUNET_TIME_RelativeNBO ttl;

  /**
   * The PoWs
   */
  uint64_t pow[POW_COUNT] GNUNET_PACKED;

  /**
   * The signature
   */
  struct GNUNET_CRYPTO_EcdsaSignature signature;

  /**
   * The revoked public key
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey key;
};


/**
 * The signature object we use for the PoW
 */
struct GNUNET_REVOCATION_SignaturePurpose
{
  /**
   * The signature purpose
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * The revoked public key
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey key;

  /**
   * The timestamp of the revocation
   */
  struct GNUNET_TIME_AbsoluteNBO timestamp;
};

GNUNET_NETWORK_STRUCT_END


/**
 * Handle to a running proof-of-work calculation.
 */
struct GNUNET_REVOCATION_PowCalculationHandle;

/**
 * Handle for the key revocation query.
 */
struct GNUNET_REVOCATION_Query;

/**
 * Callback to call with the result of a key revocation query.
 *
 * @param cls closure
 * @param is_valid #GNUNET_NO of the key is/was revoked,
 *                 #GNUNET_YES if the key is still valid,
 *                 #GNUNET_SYSERR if we had trouble querying the service
 *
 */
typedef void (*GNUNET_REVOCATION_Callback) (void *cls,
                                            enum GNUNET_GenericReturnValue
                                            is_valid);


/**
 * Check if a key was revoked.
 *
 * @param cfg the configuration to use
 * @param key key to check for revocation
 * @param func funtion to call with the result of the check
 * @param func_cls closure to pass to @a func
 * @return handle to use in #GNUNET_REVOCATION_query_cancel to stop REVOCATION from invoking the callback
 */
struct GNUNET_REVOCATION_Query *
GNUNET_REVOCATION_query (const struct GNUNET_CONFIGURATION_Handle *cfg,
                         const struct GNUNET_CRYPTO_EcdsaPublicKey *key,
                         GNUNET_REVOCATION_Callback func, void *func_cls);


/**
 * Cancel key revocation check.
 *
 * @param q query to cancel
 */
void
GNUNET_REVOCATION_query_cancel (struct GNUNET_REVOCATION_Query *q);


/**
 * Handle for the key revocation operation.
 */
struct GNUNET_REVOCATION_Handle;


/**
 * Perform key revocation.
 *
 * @param cfg the configuration to use
 * @param pow proof of work to use (should have been created by
 *            iteratively calling #GNUNET_REVOCATION_pow_round)
 * @param func function to call with the result of the check
 *             (called with `is_valid` being #GNUNET_NO if
 *              the revocation worked).
 * @param func_cls closure to pass to @a func
 * @return handle to use in #GNUNET_REVOCATION_revoke_cancel to stop REVOCATION from invoking the callback
 */
struct GNUNET_REVOCATION_Handle *
GNUNET_REVOCATION_revoke (const struct GNUNET_CONFIGURATION_Handle *cfg,
                          const struct GNUNET_REVOCATION_Pow *pow,
                          GNUNET_REVOCATION_Callback func, void *func_cls);


/**
 * Cancel key revocation.
 *
 * @param h operation to cancel
 */
void
GNUNET_REVOCATION_revoke_cancel (struct GNUNET_REVOCATION_Handle *h);


/**
 * Check if the given proof-of-work is valid.
 *
 * @param pow proof of work
 * @param matching_bits how many bits must match (configuration)
 * @param epoch_duration length of single epoch in configuration
 * @return #GNUNET_YES if the @a pow is acceptable, #GNUNET_NO if not
 */
enum GNUNET_GenericReturnValue
GNUNET_REVOCATION_check_pow (const struct GNUNET_REVOCATION_Pow *pow,
                             unsigned int matching_bits,
                             struct GNUNET_TIME_Relative epoch_duration);


/**
 * Initializes a fresh PoW computation.
 *
 * @param key the key to calculate the PoW for.
 * @param pow the pow object to work with in the calculation.
 */
void
GNUNET_REVOCATION_pow_init (const struct GNUNET_CRYPTO_EcdsaPrivateKey *key,
                            struct GNUNET_REVOCATION_Pow *pow);


/**
 * Starts a proof-of-work calculation given the pow object as well as
 * target epochs and difficulty.
 *
 * @param pow the PoW to based calculations on.
 * @param epochs the number of epochs for which the PoW must be valid.
 * @param difficulty the base difficulty of the PoW.
 * @return a handle for use in PoW rounds
 */
struct GNUNET_REVOCATION_PowCalculationHandle*
GNUNET_REVOCATION_pow_start (struct GNUNET_REVOCATION_Pow *pow,
                             int epochs,
                             unsigned int difficulty);


/**
 * Calculate a single round in the key revocation PoW.
 *
 * @param pc handle to the PoW, initially called with NULL.
 * @return GNUNET_YES if the @a pow is acceptable, GNUNET_NO if not
 */
enum GNUNET_GenericReturnValue
GNUNET_REVOCATION_pow_round (struct GNUNET_REVOCATION_PowCalculationHandle *pc);


/**
 * Stop a PoW calculation
 *
 * @param pc the calculation to clean up
 * @return #GNUNET_YES if pow valid, #GNUNET_NO if pow was set but is not
 * valid
 */
void
GNUNET_REVOCATION_pow_stop (struct GNUNET_REVOCATION_PowCalculationHandle *pc);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif /* GNUNET_REVOCATION_SERVICE_H_ */

/** @} */ /* end of group revocation */
