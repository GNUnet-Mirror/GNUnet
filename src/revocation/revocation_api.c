/*
      This file is part of GNUnet
      Copyright (C) 2013, 2016 GNUnet e.V.

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
      Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
      Boston, MA 02110-1301, USA.
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
#include <gcrypt.h>


/**
 * Handle for the key revocation query.
 */
struct GNUNET_REVOCATION_Query
{

  /**
   * Message queue to the service.
   */
  struct GNUNET_MQ_Handle *mq;

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
 * Generic error handler, called with the appropriate
 * error code and the same closure specified at the creation of
 * the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_NSE_Handle *`
 * @param error error code
 */
static void
query_mq_error_handler (void *cls,
                        enum GNUNET_MQ_Error error)
{
  struct GNUNET_REVOCATION_Query *q = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Revocation query MQ error\n");
  q->func (q->func_cls,
           GNUNET_SYSERR);
  GNUNET_REVOCATION_query_cancel (q);
}


/**
 * Handle response to our revocation query.
 *
 * @param cls our `struct GNUNET_REVOCATION_Query` handle
 * @param qrm response we got
 */
static void
handle_revocation_query_response (void *cls,
                                  const struct QueryResponseMessage *qrm)
{
  struct GNUNET_REVOCATION_Query *q = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Revocation query result: %d\n",
              ntohl (qrm->is_valid));
  q->func (q->func_cls,
           ntohl (qrm->is_valid));
  GNUNET_REVOCATION_query_cancel (q);
}


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
			 GNUNET_REVOCATION_Callback func,
                         void *func_cls)
{
  struct GNUNET_REVOCATION_Query *q
    = GNUNET_new (struct GNUNET_REVOCATION_Query);
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_fixed_size (revocation_query_response,
                             GNUNET_MESSAGE_TYPE_REVOCATION_QUERY_RESPONSE,
                             struct QueryResponseMessage,
                             q),
    GNUNET_MQ_handler_end ()
  };
  struct QueryMessage *qm;
  struct GNUNET_MQ_Envelope *env;

  q->mq = GNUNET_CLIENT_connecT (cfg,
                                 "revocation",
                                 handlers,
                                 &query_mq_error_handler,
                                 q);
  if (NULL == q->mq)
  {
    GNUNET_free (q);
    return NULL;
  }
  q->func = func;
  q->func_cls = func_cls;
  env = GNUNET_MQ_msg (qm,
                       GNUNET_MESSAGE_TYPE_REVOCATION_QUERY);
  qm->reserved = htonl (0);
  qm->key = *key;
  GNUNET_MQ_send (q->mq,
                  env);
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
  if (NULL != q->mq)
  {
    GNUNET_MQ_destroy (q->mq);
    q->mq = NULL;
  }
  GNUNET_free (q);
}


/**
 * Handle for the key revocation operation.
 */
struct GNUNET_REVOCATION_Handle
{

  /**
   * Message queue to the service.
   */
  struct GNUNET_MQ_Handle *mq;

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
 * Generic error handler, called with the appropriate
 * error code and the same closure specified at the creation of
 * the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_NSE_Handle *`
 * @param error error code
 */
static void
revocation_mq_error_handler (void *cls,
                             enum GNUNET_MQ_Error error)
{
  struct GNUNET_REVOCATION_Handle *h = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Revocation MQ error\n");
  h->func (h->func_cls,
           GNUNET_SYSERR);
  GNUNET_REVOCATION_revoke_cancel (h);
}


/**
 * Handle response to our revocation query.
 *
 * @param cls our `struct GNUNET_REVOCATION_Handle` handle
 * @param rrm response we got
 */
static void
handle_revocation_response (void *cls,
                            const struct RevocationResponseMessage *rrm)
{
  struct GNUNET_REVOCATION_Handle *h = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Revocation transmission result: %d\n",
              ntohl (rrm->is_valid));
  h->func (h->func_cls,
           ntohl (rrm->is_valid));
  GNUNET_REVOCATION_revoke_cancel (h);
}


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
			  GNUNET_REVOCATION_Callback func,
                          void *func_cls)
{
  struct GNUNET_REVOCATION_Handle *h
    = GNUNET_new (struct GNUNET_REVOCATION_Handle);
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_fixed_size (revocation_response,
                             GNUNET_MESSAGE_TYPE_REVOCATION_REVOKE_RESPONSE,
                             struct RevocationResponseMessage,
                             h),
    GNUNET_MQ_handler_end ()
  };
  unsigned long long matching_bits;
  struct RevokeMessage *rm;
  struct GNUNET_MQ_Envelope *env;

  if ( (GNUNET_OK ==
        GNUNET_CONFIGURATION_get_value_number (cfg,
                                               "REVOCATION",
                                               "WORKBITS",
                                               &matching_bits)) &&
       (GNUNET_YES !=
        GNUNET_REVOCATION_check_pow (key,
                                     pow,
                                     (unsigned int) matching_bits)) )
  {
    GNUNET_break (0);
    GNUNET_free (h);
    return NULL;
  }

  h->mq = GNUNET_CLIENT_connecT (cfg,
                                 "revocation",
                                 handlers,
                                 &revocation_mq_error_handler,
                                 h);
  if (NULL == h->mq)
  {
    GNUNET_free (h);
    return NULL;
  }
  h->func = func;
  h->func_cls = func_cls;
  env = GNUNET_MQ_msg (rm,
                       GNUNET_MESSAGE_TYPE_REVOCATION_REVOKE);
  rm->reserved = htonl (0);
  rm->proof_of_work = pow;
  rm->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_REVOCATION);
  rm->purpose.size = htonl (sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) +
                            sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));
  rm->public_key = *key;
  rm->signature = *sig;
  GNUNET_MQ_send (h->mq,
                  env);
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
  if (NULL != h->mq)
  {
    GNUNET_MQ_destroy (h->mq);
    h->mq = NULL;
  }
  GNUNET_free (h);
}


/**
 * Calculate the 'proof-of-work' hash (an expensive hash).
 *
 * @param buf data to hash
 * @param buf_len number of bytes in @a buf
 * @param result where to write the resulting hash
 */
static void
pow_hash (const void *buf,
	  size_t buf_len,
	  struct GNUNET_HashCode *result)
{
  GNUNET_break (0 ==
		gcry_kdf_derive (buf, buf_len,
				 GCRY_KDF_SCRYPT,
				 1 /* subalgo */,
				 "gnunet-revocation-proof-of-work",
				 strlen ("gnunet-revocation-proof-of-work"),
				 2 /* iterations; keep cost of individual op small */,
				 sizeof (struct GNUNET_HashCode), result));
}


/**
 * Count the leading zeroes in hash.
 *
 * @param hash to count leading zeros in
 * @return the number of leading zero bits.
 */
static unsigned int
count_leading_zeroes (const struct GNUNET_HashCode *hash)
{
  unsigned int hash_count;

  hash_count = 0;
  while ((0 == GNUNET_CRYPTO_hash_get_bit (hash, hash_count)))
    hash_count++;
  return hash_count;
}


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
			     unsigned int matching_bits)
{
  char buf[sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey) +
           sizeof (pow)] GNUNET_ALIGN;
  struct GNUNET_HashCode result;

  GNUNET_memcpy (buf, &pow, sizeof (pow));
  GNUNET_memcpy (&buf[sizeof (pow)], key,
          sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));
  pow_hash (buf, sizeof (buf), &result);
  return (count_leading_zeroes (&result) >=
          matching_bits) ? GNUNET_YES : GNUNET_NO;
}


/**
 * Create a revocation signature.
 *
 * @param key private key of the key to revoke
 * @param sig where to write the revocation signature
 */
void
GNUNET_REVOCATION_sign_revocation (const struct GNUNET_CRYPTO_EcdsaPrivateKey *key,
				   struct GNUNET_CRYPTO_EcdsaSignature *sig)
{
  struct RevokeMessage rm;

  rm.purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_REVOCATION);
  rm.purpose.size = htonl (sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) +
			   sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));
  GNUNET_CRYPTO_ecdsa_key_get_public (key, &rm.public_key);
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CRYPTO_ecdsa_sign (key,
					 &rm.purpose,
					 sig));
}


/* end of revocation_api.c */
