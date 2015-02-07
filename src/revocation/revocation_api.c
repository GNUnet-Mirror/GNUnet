/*
      This file is part of GNUnet
      Copyright (C) 2013 Christian Grothoff (and other contributing authors)

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
#include <gcrypt.h>


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
  struct GNUNET_CRYPTO_EcdsaPublicKey key;

  /**
   * Function to call with the result.
   */
  GNUNET_REVOCATION_Callback func;

  /**
   * Closure for @e func.
   */
  void *func_cls;

  /**
   * Transmission handle to the service.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

};


/**
 * Handle response to our revocation query.
 *
 * @param cls our `struct GNUNET_REVOCATION_Query` handle
 * @param msg response we got, NULL on disconnect
 */
static void
handle_revocation_query_response (void *cls,
                                  const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_REVOCATION_Query *q = cls;
  const struct QueryResponseMessage *qrm;

  if ( (NULL == msg) ||
       (sizeof (struct QueryResponseMessage) != ntohs (msg->size)) ||
       (GNUNET_MESSAGE_TYPE_REVOCATION_QUERY_RESPONSE != ntohs (msg->type)) )
  {
    GNUNET_break (NULL == msg);
    q->func (q->func_cls, GNUNET_SYSERR);
    GNUNET_REVOCATION_query_cancel (q);
    return;
  }
  qrm = (const struct QueryResponseMessage *) msg;
  q->func (q->func_cls, ntohl (qrm->is_valid));
  GNUNET_REVOCATION_query_cancel (q);
}


/**
 * Transmit our revocation query to the service.
 *
 * @param cls our `struct GNUNET_REVOCATION_Query` handle
 * @param size number of bytes available in @a buf
 * @param buf where to copy the query
 * @return number of bytes copied to @a buf
 */
static size_t
send_revocation_query (void *cls,
                       size_t size,
                       void *buf)
{
  struct GNUNET_REVOCATION_Query *q = cls;
  struct QueryMessage qm;

  q->th = NULL;
  if ( (NULL == buf) ||
       (sizeof (struct QueryMessage) > size) )
  {
    GNUNET_break (0);
    q->func (q->func_cls, GNUNET_SYSERR);
    GNUNET_REVOCATION_query_cancel (q);
    return 0;
  }
  qm.header.size = htons (sizeof (struct QueryMessage));
  qm.header.type = htons (GNUNET_MESSAGE_TYPE_REVOCATION_QUERY);
  qm.reserved = htonl (0);
  qm.key = q->key;
  memcpy (buf, &qm, sizeof (struct QueryMessage));
  GNUNET_CLIENT_receive (q->client,
                         &handle_revocation_query_response,
                         q,
                         GNUNET_TIME_UNIT_FOREVER_REL);
  return sizeof (struct QueryMessage);
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
			 GNUNET_REVOCATION_Callback func, void *func_cls)
{
  struct GNUNET_REVOCATION_Query *q;

  q = GNUNET_new (struct GNUNET_REVOCATION_Query);
  q->client = GNUNET_CLIENT_connect ("revocation", cfg);
  if (NULL == q->client)
  {
    GNUNET_break (0);
    GNUNET_free (q);
    return NULL;
  }
  q->cfg = cfg;
  q->key = *key;
  q->func = func;
  q->func_cls = func_cls;
  q->th = GNUNET_CLIENT_notify_transmit_ready (q->client,
                                               sizeof (struct QueryMessage),
                                               GNUNET_TIME_UNIT_FOREVER_REL,
                                               GNUNET_YES,
                                               &send_revocation_query,
                                               q);
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
  if (NULL != q->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (q->th);
    q->th = NULL;
  }
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
  struct GNUNET_CRYPTO_EcdsaPublicKey key;

  /**
   * Signature showing that we have the right to revoke.
   */
  struct GNUNET_CRYPTO_EcdsaSignature sig;

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

  /**
   * Transmission handle to the service.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

};


/**
 * Handle response to our revocation query.
 *
 * @param cls our `struct GNUNET_REVOCATION_Handle` handle
 * @param msg response we got, NULL on disconnect
 */
static void
handle_revocation_response (void *cls,
                            const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_REVOCATION_Handle *h = cls;
  const struct RevocationResponseMessage *rrm;

  if ( (NULL == msg) ||
       (sizeof (struct RevocationResponseMessage) != ntohs (msg->size)) ||
       (GNUNET_MESSAGE_TYPE_REVOCATION_REVOKE_RESPONSE != ntohs (msg->type)) )
  {
    GNUNET_break (NULL == msg);
    h->func (h->func_cls, GNUNET_SYSERR);
    GNUNET_REVOCATION_revoke_cancel (h);
    return;
  }
  rrm = (const struct RevocationResponseMessage *) msg;
  h->func (h->func_cls, ntohl (rrm->is_valid));
  GNUNET_REVOCATION_revoke_cancel (h);

}


/**
 * Transmit our revocation to the service.
 *
 * @param cls our `struct GNUNET_REVOCATION_Handle` handle
 * @param size number of bytes available in @a buf
 * @param buf where to copy the query
 * @return number of bytes copied to @a buf
 */
static size_t
send_revoke (void *cls,
             size_t size,
             void *buf)
{
  struct GNUNET_REVOCATION_Handle *h = cls;
  struct RevokeMessage rm;

  h->th = NULL;
  if ( (NULL == buf) ||
       (sizeof (struct RevokeMessage) > size) )
  {
    GNUNET_break (0);
    h->func (h->func_cls, GNUNET_SYSERR);
    GNUNET_REVOCATION_revoke_cancel (h);
    return 0;
  }
  rm.header.size = htons (sizeof (struct RevokeMessage));
  rm.header.type = htons (GNUNET_MESSAGE_TYPE_REVOCATION_REVOKE);
  rm.reserved = htonl (0);
  rm.proof_of_work = h->pow;
  rm.purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_REVOCATION);
  rm.purpose.size = htonl (sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) +
                           sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey));
  rm.public_key = h->key;
  rm.signature = h->sig;
  memcpy (buf, &rm, sizeof (struct RevokeMessage));
  GNUNET_CLIENT_receive (h->client,
                         &handle_revocation_response,
                         h,
                         GNUNET_TIME_UNIT_FOREVER_REL);
  return sizeof (struct RevokeMessage);
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
			  GNUNET_REVOCATION_Callback func, void *func_cls)
{
  struct GNUNET_REVOCATION_Handle *h;
  unsigned long long matching_bits;

  if ( (GNUNET_OK ==
        GNUNET_CONFIGURATION_get_value_number (cfg,
                                               "REVOCATION",
                                               "WORKBITS",
                                               &matching_bits)) &&
       (GNUNET_YES !=
        GNUNET_REVOCATION_check_pow (key, pow,
                                     (unsigned int) matching_bits)) )
  {
    GNUNET_break (0);
    return NULL;
  }
  h = GNUNET_new (struct GNUNET_REVOCATION_Handle);
  h->client = GNUNET_CLIENT_connect ("revocation", cfg);
  h->cfg = cfg;
  h->key = *key;
  h->sig = *sig;
  h->pow = pow;
  h->func = func;
  h->func_cls = func_cls;
  h->th = GNUNET_CLIENT_notify_transmit_ready (h->client,
                                               sizeof (struct RevokeMessage),
                                               GNUNET_TIME_UNIT_FOREVER_REL,
                                               GNUNET_YES,
                                               &send_revoke,
                                               h);
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
  if (NULL != h->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->th);
    h->th = NULL;
  }
  GNUNET_CLIENT_disconnect (h->client);
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

  memcpy (buf, &pow, sizeof (pow));
  memcpy (&buf[sizeof (pow)], key,
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

