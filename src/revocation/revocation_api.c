/*
      This file is part of GNUnet
      Copyright (C) 2013, 2016 GNUnet e.V.

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
#include <inttypes.h>

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
 * Helper struct that holds a found pow nonce
 * and the corresponding number of leading zeroes.
 */
struct BestPow
{
  /**
   * PoW nonce
   */
  uint64_t pow;

  /**
   * Corresponding zero bits in hash
   */
  unsigned int bits;
};


/**
 * The handle to a PoW calculation.
 * Used in iterative PoW rounds.
 */
struct GNUNET_REVOCATION_PowCalculationHandle
{
  /**
   * Current set of found PoWs
   */
  struct BestPow best[POW_COUNT];

  /**
   * The final PoW result data structure.
   */
  struct GNUNET_REVOCATION_PowP *pow;

  /**
   * The current nonce to try
   */
  uint64_t current_pow;

  /**
   * Epochs how long the PoW should be valid.
   * This is added on top of the difficulty in the PoW.
   */
  unsigned int epochs;

  /**
   * The difficulty (leading zeros) to achieve.
   */
  unsigned int difficulty;

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
              (uint32_t) ntohl (qrm->is_valid));
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

  q->mq = GNUNET_CLIENT_connect (cfg,
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
              (uint32_t) ntohl (rrm->is_valid));
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
 * @param ts  revocation timestamp
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
                          const struct GNUNET_REVOCATION_PowP *pow,
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
  struct GNUNET_TIME_Relative epoch_duration;
  struct RevokeMessage *rm;
  struct GNUNET_MQ_Envelope *env;

  if ((GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_number (cfg,
                                              "REVOCATION",
                                              "WORKBITS",
                                              &matching_bits)))
  {
    GNUNET_break (0);
    GNUNET_free (h);
    return NULL;
  }
  if ((GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_time (cfg,
                                            "REVOCATION",
                                            "EPOCH_DURATION",
                                            &epoch_duration)))
  {
    GNUNET_break (0);
    GNUNET_free (h);
    return NULL;
  }
  if (GNUNET_YES != GNUNET_REVOCATION_check_pow (pow,
                                                 (unsigned int) matching_bits,
                                                 epoch_duration))
  {
    GNUNET_break (0);
    GNUNET_free (h);
    return NULL;
  }


  h->mq = GNUNET_CLIENT_connect (cfg,
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
  rm->proof_of_work = *pow;
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
  while ((0 == GNUNET_CRYPTO_hash_get_bit_ltr (hash, hash_count)))
    hash_count++;
  return hash_count;
}


/**
 * Calculate the average zeros in the pows.
 *
 * @param ph the PowHandle
 * @return the average number of zeroes.
 */
static unsigned int
calculate_score (const struct GNUNET_REVOCATION_PowCalculationHandle *ph)
{
  double sum = 0.0;
  for (unsigned int j = 0; j<POW_COUNT; j++)
    sum += ph->best[j].bits;
  double avg = sum / POW_COUNT;
  return avg;
}


/**
 * Check if the given proof-of-work is valid.
 *
 * @param pow proof of work
 * @param matching_bits how many bits must match (configuration)
 * @param epoch_duration length of single epoch in configuration
 * @return #GNUNET_YES if the @a pow is acceptable, #GNUNET_NO if not
 */
enum GNUNET_GenericReturnValue
GNUNET_REVOCATION_check_pow (const struct GNUNET_REVOCATION_PowP *pow,
                             unsigned int difficulty,
                             struct GNUNET_TIME_Relative epoch_duration)
{
  char buf[sizeof(struct GNUNET_CRYPTO_EcdsaPublicKey)
           + sizeof (struct GNUNET_TIME_AbsoluteNBO)
           + sizeof (uint64_t)] GNUNET_ALIGN;
  struct GNUNET_REVOCATION_SignaturePurposePS spurp;
  struct GNUNET_HashCode result;
  struct GNUNET_TIME_Absolute ts;
  struct GNUNET_TIME_Absolute exp;
  struct GNUNET_TIME_Relative ttl;
  struct GNUNET_TIME_Relative buffer;
  unsigned int score = 0;
  unsigned int tmp_score = 0;
  unsigned int epochs;
  uint64_t pow_val;

  /**
   * Check if signature valid
   */
  spurp.key = pow->key;
  spurp.timestamp = pow->timestamp;
  spurp.purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_REVOCATION);
  spurp.purpose.size = htonl (sizeof(struct GNUNET_CRYPTO_EccSignaturePurpose)
                              + sizeof(struct GNUNET_CRYPTO_EcdsaPublicKey)
                              + sizeof (struct GNUNET_TIME_AbsoluteNBO));
  if (GNUNET_OK !=
      GNUNET_CRYPTO_ecdsa_verify_ (GNUNET_SIGNATURE_PURPOSE_REVOCATION,
                                   &spurp.purpose,
                                   &pow->signature,
                                   &pow->key))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Proof of work signature invalid!\n");
    return GNUNET_NO;
  }

  /**
   * First, check if PoW set is strictly monotically increasing
   */
  for (unsigned int i = 0; i < POW_COUNT-1; i++)
  {
    if (GNUNET_ntohll (pow->pow[i]) >= GNUNET_ntohll (pow->pow[i+1]))
      return GNUNET_NO;
  }
  GNUNET_memcpy (&buf[sizeof(uint64_t)],
                 &pow->timestamp,
                 sizeof (uint64_t));
  GNUNET_memcpy (&buf[sizeof(uint64_t) * 2],
                 &pow->key,
                 sizeof(struct GNUNET_CRYPTO_EcdsaPublicKey));
  for (unsigned int i = 0; i < POW_COUNT; i++)
  {
    pow_val = GNUNET_ntohll (pow->pow[i]);
    GNUNET_memcpy (buf, &pow->pow[i], sizeof(uint64_t));
    GNUNET_CRYPTO_pow_hash ("GnsRevocationPow",
                            buf,
                            sizeof(buf),
                            &result);
    tmp_score = count_leading_zeroes (&result);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Score %u with %" PRIu64 " (#%u)\n",
                tmp_score, pow_val, i);

    score += tmp_score;

  }
  score = score / POW_COUNT;
  if (score < difficulty)
    return GNUNET_NO;
  epochs = score - difficulty;

  /**
   * Check expiration
   */
  ts = GNUNET_TIME_absolute_ntoh (pow->timestamp);
  ttl = GNUNET_TIME_relative_multiply (epoch_duration,
                                       epochs);
  /**
   * Extend by 10% for unsynchronized clocks
   */
  buffer = GNUNET_TIME_relative_divide (epoch_duration,
                                        10);
  exp = GNUNET_TIME_absolute_add (ts, ttl);
  exp = GNUNET_TIME_absolute_add (exp,
                                  buffer);

  if (0 != GNUNET_TIME_absolute_get_remaining (ts).rel_value_us)
    return GNUNET_NO; /* Not yet valid. */
  /* Revert to actual start time */
  ts = GNUNET_TIME_absolute_add (ts,
                                 buffer);

  if (0 == GNUNET_TIME_absolute_get_remaining (exp).rel_value_us)
    return GNUNET_NO; /* expired */
  return GNUNET_YES;
}


/**
 * Initializes a fresh PoW computation.
 *
 * @param key the key to calculate the PoW for.
 * @param[out] pow starting point for PoW calculation (not yet valid)
 */
void
GNUNET_REVOCATION_pow_init (const struct GNUNET_CRYPTO_EcdsaPrivateKey *key,
                            struct GNUNET_REVOCATION_PowP *pow)
{
  struct GNUNET_TIME_Absolute ts = GNUNET_TIME_absolute_get ();
  struct GNUNET_REVOCATION_SignaturePurposePS rp;

  /**
   * Predate the validity period to prevent rejections due to
   * unsynchronized clocks
   */
  ts = GNUNET_TIME_absolute_subtract (ts,
                                      GNUNET_TIME_UNIT_WEEKS);

  pow->timestamp = GNUNET_TIME_absolute_hton (ts);
  rp.timestamp = pow->timestamp;
  rp.purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_REVOCATION);
  rp.purpose.size = htonl (sizeof(struct GNUNET_CRYPTO_EccSignaturePurpose)
                           + sizeof(struct GNUNET_CRYPTO_EcdsaPublicKey)
                           + sizeof (struct GNUNET_TIME_AbsoluteNBO));
  GNUNET_CRYPTO_ecdsa_key_get_public (key, &pow->key);
  rp.key = pow->key;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_ecdsa_sign_ (key,
                                            &rp.purpose,
                                            &pow->signature));
}


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
GNUNET_REVOCATION_pow_start (struct GNUNET_REVOCATION_PowP *pow,
                             int epochs,
                             unsigned int difficulty)
{
  struct GNUNET_REVOCATION_PowCalculationHandle *pc;
  struct GNUNET_TIME_Relative ttl;


  pc = GNUNET_new (struct GNUNET_REVOCATION_PowCalculationHandle);
  pc->pow = pow;
  ttl = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_YEARS,
                                       epochs);
  pc->pow->ttl = GNUNET_TIME_relative_hton (ttl);
  pc->current_pow = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                              UINT64_MAX);
  pc->difficulty = difficulty;
  pc->epochs = epochs;
  return pc;
}

/**
 * Comparison function for quicksort
 *
 * @param a left element
 * @param b right element
 * @return a-b
 */
static int
cmp_pow_value (const void *a, const void *b)
{
  return ( GNUNET_ntohll(*(uint64_t*)a) - GNUNET_ntohll(*(uint64_t*)b));
}

/**
 * Calculate a key revocation valid for broadcasting for a number
 * of epochs.
 *
 * @param pc handle to the PoW, initially called with NULL.
 * @param epochs number of epochs for which the revocation must be valid.
 * @param pow current pow value to try
 * @param difficulty current base difficulty to achieve
 * @return #GNUNET_YES if the @a pow is acceptable, #GNUNET_NO if not
 */
enum GNUNET_GenericReturnValue
GNUNET_REVOCATION_pow_round (struct GNUNET_REVOCATION_PowCalculationHandle *pc)
{
  char buf[sizeof(struct GNUNET_CRYPTO_EcdsaPublicKey)
           + sizeof (uint64_t)
           + sizeof (uint64_t)] GNUNET_ALIGN;
  struct GNUNET_HashCode result;
  unsigned int zeros;
  int ret;
  uint64_t pow_nbo;

  pc->current_pow++;

  /**
   * Do not try duplicates
   */
  for (unsigned int i = 0; i < POW_COUNT; i++)
    if (pc->current_pow == pc->best[i].pow)
      return GNUNET_NO;
  pow_nbo = GNUNET_htonll (pc->current_pow);
  GNUNET_memcpy (buf, &pow_nbo, sizeof(uint64_t));
  GNUNET_memcpy (&buf[sizeof(uint64_t)],
                 &pc->pow->timestamp,
                 sizeof (uint64_t));
  GNUNET_memcpy (&buf[sizeof(uint64_t) * 2],
                 &pc->pow->key,
                 sizeof(struct GNUNET_CRYPTO_EcdsaPublicKey));
  GNUNET_CRYPTO_pow_hash ("GnsRevocationPow",
                          buf,
                          sizeof(buf),
                          &result);
  zeros = count_leading_zeroes (&result);
  for (unsigned int i = 0; i < POW_COUNT; i++)
  {
    if (pc->best[i].bits < zeros)
    {
      pc->best[i].bits = zeros;
      pc->best[i].pow = pc->current_pow;
      pc->pow->pow[i] = pow_nbo;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "New best score %u with %" PRIu64 " (#%u)\n",
                  zeros, pc->current_pow, i);

      break;
    }
  }
  ret = calculate_score (pc) >= pc->difficulty + pc->epochs ? GNUNET_YES :
        GNUNET_NO;
  if (GNUNET_YES == ret)
  {
    /* Sort POWs) */
    qsort (pc->pow->pow, POW_COUNT, sizeof (uint64_t), &cmp_pow_value);
  }
  return ret;
}


/**
 * Stop a PoW calculation
 *
 * @param pc the calculation to clean up
 * @return #GNUNET_YES if pow valid, #GNUNET_NO if pow was set but is not
 * valid
 */
void
GNUNET_REVOCATION_pow_stop (struct GNUNET_REVOCATION_PowCalculationHandle *pc)
{
  GNUNET_free (pc);
}


/* end of revocation_api.c */
