/*
      This file is part of GNUnet
      (C) 2013 Christian Grothoff (and other contributing authors)

      GNUnet is free software; you can redistribute it and/or modify
      it under the terms of the GNU General Public Licerevocation as published
      by the Free Software Foundation; either version 3, or (at your
      option) any later version.

      GNUnet is distributed in the hope that it will be useful, but
      WITHOUT ANY WARRANTY; without even the implied warranty of
      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
      General Public Licerevocation for more details.

      You should have received a copy of the GNU General Public Licerevocation
      along with GNUnet; see the file COPYING.  If not, write to the
      Free Software Foundation, Inc., 59 Temple Place - Suite 330,
      Boston, MA 02111-1307, USA.
 */
/**
 * @file revocation/revocation_api.c
 * @brief API to perform and access key revocations
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_revocation_service.h"
#include "gnunet_signatures.h"
#include "gnunet_protocols.h"
#include "revocation.h"


/**
 * Handle for the key revocation query.
 */
struct GNUNET_REVOCATION_Query
{

  /**
   * Connection to the service.
   */
  struct GNUNET_CLIENT_Connection *client;
  
  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Key to check.
   */
  struct GNUNET_CRYPTO_EccPublicSignKey key;

  /**
   * Function to call with the result.
   */
  GNUNET_REVOCATION_Callback func;

  /**
   * Closure for @e func.
   */
  void *func_cls;
};


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
			 const struct GNUNET_CRYPTO_EccPublicSignKey *key,
			 GNUNET_REVOCATION_Callback func, void *func_cls)
{
  struct GNUNET_REVOCATION_Query *q;

  q = GNUNET_new (struct GNUNET_REVOCATION_Query);
  q->client = GNUNET_CLIENT_connect ("revocation", cfg);
  q->cfg = cfg;
  q->key = *key;
  q->func = func;
  q->func_cls = func_cls;
  GNUNET_break (0);
  return q;
}


/**
 * Cancel key revocation check.
 *
 * @param q query to cancel
 */
void
GNUNET_REVOCATION_query_cancel (struct GNUNET_REVOCATION_Query *q)
{
  GNUNET_CLIENT_disconnect (q->client);
  GNUNET_free (q);
}


/**
 * Handle for the key revocation operation.
 */
struct GNUNET_REVOCATION_Handle
{
  
  /**
   * Connection to the service.
   */
  struct GNUNET_CLIENT_Connection *client;
  
  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Key to revoke.
   */
  struct GNUNET_CRYPTO_EccPublicSignKey key;

  /**
   * Signature showing that we have the right to revoke.
   */
  struct GNUNET_CRYPTO_EccSignature sig;

  /**
   * Proof of work showing that we spent enough resources to broadcast revocation.
   */
  uint64_t pow;

  /**
   * Function to call once we are done.
   */
  GNUNET_REVOCATION_Callback func;

  /**
   * Closure for @e func.
   */
  void *func_cls;

};


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
 * @return handle to use in #GNUNET_REVOCATION_cancel to stop REVOCATION from invoking the callback
 */
struct GNUNET_REVOCATION_Handle *
GNUNET_REVOCATION_revoke (const struct GNUNET_CONFIGURATION_Handle *cfg,
			  const struct GNUNET_CRYPTO_EccPublicSignKey *key,
			  const struct GNUNET_CRYPTO_EccSignature *sig,
			  uint64_t pow,
			  GNUNET_REVOCATION_Callback func, void *func_cls)
{
  struct GNUNET_REVOCATION_Handle *h;

  h = GNUNET_new (struct GNUNET_REVOCATION_Handle);
  h->client = GNUNET_CLIENT_connect ("revocation", cfg);
  h->cfg = cfg;
  h->key = *key;
  h->sig = *sig;
  h->pow = pow;
  h->func = func;
  h->func_cls = func_cls;
  GNUNET_break (0);
  return h;
}


/**
 * Cancel key revocation.
 *
 * @param h operation to cancel
 */
void
GNUNET_REVOCATION_revoke_cancel (struct GNUNET_REVOCATION_Handle *h)
{
  GNUNET_CLIENT_disconnect (h->client);
  GNUNET_free (h);
}


/**
 * Check if the given proof-of-work value
 * would be acceptable for revoking the given key.
 *
 * @param key key to check for
 * @param pow proof of work value
 * @return #GNUNET_YES if the @a pow is acceptable, #GNUNET_NO if not
 */
int
GNUNET_REVOCATION_check_pow (const struct GNUNET_CRYPTO_EccPublicSignKey *key,
			     uint64_t pow)
{
  GNUNET_break (0);
  return GNUNET_NO;
}


/**
 * Create a revocation signature.
 *
 * @param key private key of the key to revoke
 * @param sig where to write the revocation signature
 */
void
GNUNET_REVOCATION_sign_revocation (const struct GNUNET_CRYPTO_EccPrivateKey *key,
				   struct GNUNET_CRYPTO_EccSignature *sig)
{
  struct GNUNET_REVOCATION_RevokeMessage rm;

  rm.purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_REVOCATION);
  rm.purpose.size = htonl (sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) +
			   sizeof (struct GNUNET_CRYPTO_EccPublicSignKey));
  GNUNET_CRYPTO_ecc_key_get_public_for_signature (key, &rm.public_key);
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CRYPTO_ecc_sign (key,
					 &rm.purpose,
					 sig));
}


/* end of revocation_api.c */

