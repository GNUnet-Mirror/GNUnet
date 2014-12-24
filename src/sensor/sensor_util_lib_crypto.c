/*
     This file is part of GNUnet.
     (C)

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
 * @file sensor/sensor_util_lib_crypto.c
 * @brief senor utilities - crpyto related functions
 * @author Omar Tarabai
 */
#include <inttypes.h>
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_sensor_util_lib.h"
#include "gnunet_signatures.h"

#define LOG(kind,...) GNUNET_log_from (kind, "sensor-util-crypto",__VA_ARGS__)

/**
 * Context of an operation performed by #GNUNET_SENSOR_crypto_pow_sign()
 */
struct GNUNET_SENSOR_crypto_pow_context
{

  /**
   * Proof-of-work value
   */
  uint64_t pow;

  /**
   * Private key to be used for signing
   */
  struct GNUNET_CRYPTO_EddsaPrivateKey private_key;

  /**
   * Number of leading zeros required in the result hash
   */
  int matching_bits;

  /**
   * Callback function to call with the result
   */
  GNUNET_SENSOR_UTIL_pow_callback callback;

  /**
   * Closure for callback
   */
  void *callback_cls;

  /**
   * Task that calculates the proof-of-work
   */
  struct GNUNET_SCHEDULER_Task * calculate_pow_task;

  /**
   * Size of msg (allocated after this struct)
   */
  size_t msg_size;

  /**
   * Timestamp of the message
   */
  struct GNUNET_TIME_Absolute timestamp;

  /**
   * Public key of the peer sending this message
   */
  struct GNUNET_CRYPTO_EddsaPublicKey public_key;

};


/**
 * Calculate the scrypt hash
 */
static void
pow_hash (const void *buf, size_t buf_len, struct GNUNET_HashCode *result)
{
  GNUNET_break (0 ==
                gcry_kdf_derive (buf, buf_len, GCRY_KDF_SCRYPT,
                                 1 /* subalgo */ ,
                                 "gnunet-sensor-util-proof-of-work",
                                 strlen ("gnunet-sensor-util-proof-of-work"), 2
                                 /* iterations; keep cost of individual op small */
                                 , sizeof (struct GNUNET_HashCode), result));
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
 * Check if the given proof-of-work is valid
 */
static int
check_pow (void *msg, size_t msg_size, uint64_t pow, int matching_bits)
{
  char buf[msg_size + sizeof (pow)] GNUNET_ALIGN;
  struct GNUNET_HashCode result;

  memcpy (buf, &pow, sizeof (pow));
  memcpy (&buf[sizeof (pow)], msg, msg_size);
  pow_hash (buf, sizeof (buf), &result);
  return (count_leading_zeroes (&result) >=
          matching_bits) ? GNUNET_YES : GNUNET_NO;
}


/**
 * Task that checks if pow is correct, otherwise increments and reschedules itself
 */
static void
calculate_pow (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_SENSOR_crypto_pow_context *cx = cls;
  struct GNUNET_SENSOR_crypto_pow_block *result_block;
  GNUNET_SENSOR_UTIL_pow_callback callback;
  void *callback_cls;
  int sign_result;

  if (0 == cx->pow % 1000)
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Checking pow %" PRIu64 ".\n", cx->pow);
  if (GNUNET_YES ==
      check_pow (&cx->timestamp,
                 sizeof (struct GNUNET_CRYPTO_EddsaPublicKey) +
                 sizeof (struct GNUNET_TIME_Absolute) + cx->msg_size, cx->pow,
                 cx->matching_bits))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Found pow %" PRIu64 ".\n", cx->pow);
    cx->calculate_pow_task = NULL;
    result_block =
        GNUNET_malloc (sizeof (struct GNUNET_SENSOR_crypto_pow_block) +
                       cx->msg_size);
    result_block->msg_size = cx->msg_size;
    result_block->pow = cx->pow;
    result_block->timestamp = cx->timestamp;
    result_block->public_key = cx->public_key;
    result_block->purpose.purpose =
        htonl (GNUNET_SIGNATURE_PURPOSE_SENSOR_ANOMALY_REPORT);
    result_block->purpose.size =
        htonl (sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) +
               sizeof (struct GNUNET_TIME_Absolute) +
               sizeof (struct GNUNET_CRYPTO_EddsaPublicKey) + cx->msg_size);
    memcpy (&result_block[1], &cx[1], cx->msg_size);
    sign_result =
        GNUNET_CRYPTO_eddsa_sign (&cx->private_key, &result_block->purpose,
                                  &result_block->signature);
    callback = cx->callback;
    callback_cls = cx->callback_cls;
    GNUNET_SENSOR_crypto_pow_sign_cancel (cx);
    if (NULL != callback)
      callback (callback_cls, (GNUNET_OK == sign_result) ? result_block : NULL);
    GNUNET_free (result_block);
    return;
  }
  cx->pow++;
  cx->calculate_pow_task = GNUNET_SCHEDULER_add_now (&calculate_pow, cx);
}


/**
 * Cancel an operation started by #GNUNET_SENSOR_crypto_pow_sign().
 * Call only before callback function passed to #GNUNET_SENSOR_crypto_pow_sign()
 * is called with the result.
 */
void
GNUNET_SENSOR_crypto_pow_sign_cancel (struct GNUNET_SENSOR_crypto_pow_context
                                      *cx)
{
  if (NULL != cx->calculate_pow_task)
  {
    GNUNET_SCHEDULER_cancel (cx->calculate_pow_task);
    cx->calculate_pow_task = NULL;
  }
  GNUNET_free (cx);
  cx = NULL;
}


/**
 * Calculate proof-of-work and sign a message.
 * The result of all operations will be returned via the callback passed to this
 * function. Note that the payload (msg) is copied to the result block.
 *
 * @param msg Message to calculate pow and sign
 * @param msg_size size of msg
 * @param timestamp Timestamp to add to the message to protect against replay attacks
 * @param public_key Public key of the origin peer, to protect against redirect attacks
 * @param private_key Private key of the origin peer to sign the result
 * @param matching_bits Number of leading zeros required in the result hash
 * @param callback Callback function to call with the result
 * @param callback_cls Closure for callback
 * @return Operation context
 */
struct GNUNET_SENSOR_crypto_pow_context *
GNUNET_SENSOR_crypto_pow_sign (void *msg, size_t msg_size,
                               struct GNUNET_TIME_Absolute *timestamp,
                               struct GNUNET_CRYPTO_EddsaPublicKey *public_key,
                               struct GNUNET_CRYPTO_EddsaPrivateKey
                               *private_key, int matching_bits,
                               GNUNET_SENSOR_UTIL_pow_callback callback,
                               void *callback_cls)
{
  struct GNUNET_SENSOR_crypto_pow_context *cx;

  cx = GNUNET_malloc (sizeof (struct GNUNET_SENSOR_crypto_pow_context) +
                      msg_size);

  cx->timestamp = *timestamp;
  cx->public_key = *public_key;
  cx->msg_size = msg_size;
  memcpy (&cx[1], msg, msg_size);
  cx->pow = 0;
  cx->private_key = *private_key;
  cx->matching_bits = matching_bits;
  cx->callback = callback;
  cx->callback_cls = callback_cls;
  cx->calculate_pow_task = GNUNET_SCHEDULER_add_now (&calculate_pow, cx);
  return cx;
}


/**
 * Verify that proof-of-work and signature in the given block are valid.
 * If all valid, a pointer to the payload within the block is set and the size
 * of the payload is returned.
 *
 * **VERY IMPORTANT** : You will still need to verify the timestamp yourself.
 *
 * @param block The block received and needs to be verified
 * @param matching_bits Number of leading zeros in the hash used to verify pow
 * @param public_key Public key of the peer that sent this block
 * @param payload Where to store the pointer to the payload
 * @return Size of the payload, 0 on error
 */
size_t
GNUNET_SENSOR_crypto_verify_pow_sign (struct GNUNET_SENSOR_crypto_pow_block *
                                      block, int matching_bits,
                                      struct GNUNET_CRYPTO_EddsaPublicKey *
                                      public_key, void **payload)
{
  /* Check public key */
  if (0 !=
      memcmp (public_key, &block->public_key,
              sizeof (struct GNUNET_CRYPTO_EddsaPublicKey)))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "Public key mismatch.\n");
    return 0;
  }
  /* Check signature */
  if (GNUNET_OK !=
      GNUNET_CRYPTO_eddsa_verify
      (GNUNET_SIGNATURE_PURPOSE_SENSOR_ANOMALY_REPORT, &block->purpose,
       &block->signature, public_key))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "Invalid signature.\n");
    return 0;
  }
  /* Check pow */
  if (GNUNET_NO ==
      check_pow (&block->timestamp,
                 sizeof (struct GNUNET_TIME_Absolute) +
                 sizeof (struct GNUNET_CRYPTO_EddsaPublicKey) + block->msg_size,
                 block->pow, matching_bits))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "Invalid proof-of-work.\n");
    return 0;
  }
  *payload = &block[1];
  return block->msg_size;
}
