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
					    int is_valid);


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
 * @param key public key of the key to revoke
 * @param sig signature to use on the revocation (should have been
 *            created using #GNUNET_REVOCATION_sign_revocation).
 * @param pow proof of work to use (should have been created by
 *            iteratively calling #GNUNET_REVOCATION_check_pow)
 * @param func funtion to call with the result of the check
 *             (called with `is_valid` being #GNUNET_NO if
 *              the revocation worked).
 * @param func_cls closure to pass to @a func
 * @return handle to use in #GNUNET_REVOCATION_revoke_cancel to stop REVOCATION from invoking the callback
 */
struct GNUNET_REVOCATION_Handle *
GNUNET_REVOCATION_revoke (const struct GNUNET_CONFIGURATION_Handle *cfg,
			  const struct GNUNET_CRYPTO_EcdsaPublicKey *key,
			  const struct GNUNET_CRYPTO_EcdsaSignature *sig,
			  uint64_t pow,
			  GNUNET_REVOCATION_Callback func, void *func_cls);


/**
 * Cancel key revocation.
 *
 * @param h operation to cancel
 */
void
GNUNET_REVOCATION_revoke_cancel (struct GNUNET_REVOCATION_Handle *h);


/**
 * Check if the given proof-of-work value
 * would be acceptable for revoking the given key.
 *
 * @param key key to check for
 * @param pow proof of work value
 * @param matching_bits how many bits must match (configuration)
 * @return #GNUNET_YES if the @a pow is acceptable, #GNUNET_NO if not
 */
int
GNUNET_REVOCATION_check_pow (const struct GNUNET_CRYPTO_EcdsaPublicKey *key,
			     uint64_t pow,
			     unsigned int matching_bits);


/**
 * Create a revocation signature.
 *
 * @param key private key of the key to revoke
 * @param sig where to write the revocation signature
 */
void
GNUNET_REVOCATION_sign_revocation (const struct GNUNET_CRYPTO_EcdsaPrivateKey *key,
				   struct GNUNET_CRYPTO_EcdsaSignature *sig);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif /* GNUNET_REVOCATION_SERVICE_H_ */

/** @} */ /* end of group revocation */
