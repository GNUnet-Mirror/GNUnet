/*
     This file is part of GNUnet.
     Copyright (C) 2001-2013 Christian Grothoff (and other contributing authors)

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
 * @file util/crypto_hash.c
 * @brief SHA-512 #GNUNET_CRYPTO_hash() related functions
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include <gcrypt.h>

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

#define LOG_STRERROR_FILE(kind,syscall,filename) GNUNET_log_from_strerror_file (kind, "util", syscall, filename)

/**
 * Hash block of given size.
 *
 * @param block the data to #GNUNET_CRYPTO_hash, length is given as a second argument
 * @param size the length of the data to #GNUNET_CRYPTO_hash in @a block
 * @param ret pointer to where to write the hashcode
 */
void
GNUNET_CRYPTO_hash (const void *block,
                    size_t size,
                    struct GNUNET_HashCode *ret)
{
  gcry_md_hash_buffer (GCRY_MD_SHA512, ret, block, size);
}


/* ***************** binary-ASCII encoding *************** */


/**
 * Convert GNUNET_CRYPTO_hash to ASCII encoding.  The ASCII encoding is rather
 * GNUnet specific.  It was chosen such that it only uses characters
 * in [0-9A-V], can be produced without complex arithmetics and uses a
 * small number of characters.  The GNUnet encoding uses 103
 * characters plus a null terminator.
 *
 * @param block the hash code
 * @param result where to store the encoding (struct GNUNET_CRYPTO_HashAsciiEncoded can be
 *  safely cast to char*, a '\\0' termination is set).
 */
void
GNUNET_CRYPTO_hash_to_enc (const struct GNUNET_HashCode *block,
                           struct GNUNET_CRYPTO_HashAsciiEncoded *result)
{
  char *np;

  np = GNUNET_STRINGS_data_to_string ((const unsigned char *) block,
				      sizeof (struct GNUNET_HashCode),
				      (char*) result,
				      sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded) - 1);
  GNUNET_assert (NULL != np);
  *np = '\0';
}


/**
 * Convert ASCII encoding back to hash code.
 *
 * @param enc the encoding
 * @param enclen number of characters in @a enc (without 0-terminator, which can be missing)
 * @param result where to store the hash code
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if result has the wrong encoding
 */
int
GNUNET_CRYPTO_hash_from_string2 (const char *enc,
                                 size_t enclen,
                                 struct GNUNET_HashCode *result)
{
  char upper_enc[enclen];
  char *up_ptr = upper_enc;

  GNUNET_STRINGS_utf8_toupper (enc, up_ptr);

  return GNUNET_STRINGS_string_to_data (upper_enc, enclen,
					(unsigned char*) result,
					sizeof (struct GNUNET_HashCode));
}


/**
 * @ingroup hash
 *
 * Compute the distance between 2 hashcodes.  The computation must be
 * fast, not involve bits[0] or bits[4] (they're used elsewhere), and be
 * somewhat consistent. And of course, the result should be a positive
 * number.
 *
 * @param a some hash code
 * @param b some hash code
 * @return a positive number which is a measure for
 *  hashcode proximity.
 */
unsigned int
GNUNET_CRYPTO_hash_distance_u32 (const struct GNUNET_HashCode *a,
                                 const struct GNUNET_HashCode *b)
{
  unsigned int x1 = (a->bits[1] - b->bits[1]) >> 16;
  unsigned int x2 = (b->bits[1] - a->bits[1]) >> 16;

  return (x1 * x2);
}


/**
 * Create a random hash code.
 *
 * @param mode desired quality level
 * @param result hash code that is randomized
 */
void
GNUNET_CRYPTO_hash_create_random (enum GNUNET_CRYPTO_Quality mode,
                                  struct GNUNET_HashCode *result)
{
  int i;

  for (i = (sizeof (struct GNUNET_HashCode) / sizeof (uint32_t)) - 1; i >= 0; i--)
    result->bits[i] = GNUNET_CRYPTO_random_u32 (mode, UINT32_MAX);
}


/**
 * compute result(delta) = b - a
 *
 * @param a some hash code
 * @param b some hash code
 * @param result set to b - a
 */
void
GNUNET_CRYPTO_hash_difference (const struct GNUNET_HashCode *a,
                               const struct GNUNET_HashCode *b,
                               struct GNUNET_HashCode *result)
{
  int i;

  for (i = (sizeof (struct GNUNET_HashCode) / sizeof (unsigned int)) - 1; i >= 0; i--)
    result->bits[i] = b->bits[i] - a->bits[i];
}


/**
 * compute result(b) = a + delta
 *
 * @param a some hash code
 * @param delta some hash code
 * @param result set to a + delta
 */
void
GNUNET_CRYPTO_hash_sum (const struct GNUNET_HashCode * a,
                        const struct GNUNET_HashCode * delta, struct GNUNET_HashCode * result)
{
  int i;

  for (i = (sizeof (struct GNUNET_HashCode) / sizeof (unsigned int)) - 1; i >= 0; i--)
    result->bits[i] = delta->bits[i] + a->bits[i];
}


/**
 * compute result = a ^ b
 *
 * @param a some hash code
 * @param b some hash code
 * @param result set to a ^ b
 */
void
GNUNET_CRYPTO_hash_xor (const struct GNUNET_HashCode *a,
                        const struct GNUNET_HashCode *b,
                        struct GNUNET_HashCode *result)
{
  int i;

  for (i = (sizeof (struct GNUNET_HashCode) / sizeof (unsigned int)) - 1; i >= 0; i--)
    result->bits[i] = a->bits[i] ^ b->bits[i];
}


/**
 * Convert a hashcode into a key.
 *
 * @param hc hash code that serves to generate the key
 * @param skey set to a valid session key
 * @param iv set to a valid initialization vector
 */
void
GNUNET_CRYPTO_hash_to_aes_key (const struct GNUNET_HashCode *hc,
                               struct GNUNET_CRYPTO_SymmetricSessionKey *skey,
                               struct GNUNET_CRYPTO_SymmetricInitializationVector *iv)
{
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CRYPTO_kdf (skey, sizeof (struct GNUNET_CRYPTO_SymmetricSessionKey),
                                    "Hash key derivation", strlen ("Hash key derivation"),
                                    hc, sizeof (struct GNUNET_HashCode),
                                    NULL, 0));
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CRYPTO_kdf (iv, sizeof (struct GNUNET_CRYPTO_SymmetricInitializationVector),
                                    "Initialization vector derivation", strlen ("Initialization vector derivation"),
                                    hc, sizeof (struct GNUNET_HashCode),
                                    NULL, 0));
}


/**
 * Obtain a bit from a hashcode.
 * @param code the GNUNET_CRYPTO_hash to index bit-wise
 * @param bit index into the hashcode, [0...511]
 * @return Bit \a bit from hashcode \a code, -1 for invalid index
 */
int
GNUNET_CRYPTO_hash_get_bit (const struct GNUNET_HashCode * code, unsigned int bit)
{
  GNUNET_assert (bit < 8 * sizeof (struct GNUNET_HashCode));
  return (((unsigned char *) code)[bit >> 3] & (1 << (bit & 7))) > 0;
}


/**
 * Determine how many low order bits match in two
 * `struct GNUNET_HashCode`s.  i.e. - 010011 and 011111 share
 * the first two lowest order bits, and therefore the
 * return value is two (NOT XOR distance, nor how many
 * bits match absolutely!).
 *
 * @param first the first hashcode
 * @param second the hashcode to compare first to
 *
 * @return the number of bits that match
 */
unsigned int
GNUNET_CRYPTO_hash_matching_bits (const struct GNUNET_HashCode * first,
                                  const struct GNUNET_HashCode * second)
{
  unsigned int i;

  for (i = 0; i < sizeof (struct GNUNET_HashCode) * 8; i++)
    if (GNUNET_CRYPTO_hash_get_bit (first, i) !=
        GNUNET_CRYPTO_hash_get_bit (second, i))
      return i;
  return sizeof (struct GNUNET_HashCode) * 8;
}


/**
 * Compare function for HashCodes, producing a total ordering
 * of all hashcodes.
 *
 * @param h1 some hash code
 * @param h2 some hash code
 * @return 1 if h1 > h2, -1 if h1 < h2 and 0 if h1 == h2.
 */
int
GNUNET_CRYPTO_hash_cmp (const struct GNUNET_HashCode *h1,
                        const struct GNUNET_HashCode *h2)
{
  unsigned int *i1;
  unsigned int *i2;
  int i;

  i1 = (unsigned int *) h1;
  i2 = (unsigned int *) h2;
  for (i = (sizeof (struct GNUNET_HashCode) / sizeof (unsigned int)) - 1; i >= 0; i--)
  {
    if (i1[i] > i2[i])
      return 1;
    if (i1[i] < i2[i])
      return -1;
  }
  return 0;
}


/**
 * Find out which of the two `struct GNUNET_HashCode`s is closer to target
 * in the XOR metric (Kademlia).
 *
 * @param h1 some hash code
 * @param h2 some hash code
 * @param target some hash code
 * @return -1 if h1 is closer, 1 if h2 is closer and 0 if h1==h2.
 */
int
GNUNET_CRYPTO_hash_xorcmp (const struct GNUNET_HashCode *h1,
                           const struct GNUNET_HashCode *h2,
                           const struct GNUNET_HashCode *target)
{
  int i;
  unsigned int d1;
  unsigned int d2;

  for (i = sizeof (struct GNUNET_HashCode) / sizeof (unsigned int) - 1; i >= 0; i--)
  {
    d1 = ((unsigned int *) h1)[i] ^ ((unsigned int *) target)[i];
    d2 = ((unsigned int *) h2)[i] ^ ((unsigned int *) target)[i];
    if (d1 > d2)
      return 1;
    else if (d1 < d2)
      return -1;
  }
  return 0;
}


/**
 * @brief Derive an authentication key
 * @param key authentication key
 * @param rkey root key
 * @param salt salt
 * @param salt_len size of the @a salt
 * @param ... pair of void * & size_t for context chunks, terminated by NULL
 */
void
GNUNET_CRYPTO_hmac_derive_key (struct GNUNET_CRYPTO_AuthKey *key,
                               const struct GNUNET_CRYPTO_SymmetricSessionKey *rkey,
                               const void *salt, size_t salt_len, ...)
{
  va_list argp;

  va_start (argp, salt_len);
  GNUNET_CRYPTO_hmac_derive_key_v (key, rkey, salt, salt_len, argp);
  va_end (argp);
}


/**
 * @brief Derive an authentication key
 * @param key authentication key
 * @param rkey root key
 * @param salt salt
 * @param salt_len size of the @a salt
 * @param argp pair of void * & size_t for context chunks, terminated by NULL
 */
void
GNUNET_CRYPTO_hmac_derive_key_v (struct GNUNET_CRYPTO_AuthKey *key,
                                 const struct GNUNET_CRYPTO_SymmetricSessionKey *rkey,
                                 const void *salt, size_t salt_len,
                                 va_list argp)
{
  GNUNET_CRYPTO_kdf_v (key->key, sizeof (key->key),
                       salt, salt_len,
                       rkey, sizeof (struct GNUNET_CRYPTO_SymmetricSessionKey),
                       argp);
}


/**
 * Calculate HMAC of a message (RFC 2104)
 *
 * @param key secret key
 * @param plaintext input plaintext
 * @param plaintext_len length of @a plaintext
 * @param hmac where to store the hmac
 */
void
GNUNET_CRYPTO_hmac (const struct GNUNET_CRYPTO_AuthKey *key,
                    const void *plaintext, size_t plaintext_len,
                    struct GNUNET_HashCode *hmac)
{
  static int once;
  static gcry_md_hd_t md;
  const unsigned char *mc;

  if (! once)
  {
    once = 1;
    GNUNET_assert (GPG_ERR_NO_ERROR ==
                   gcry_md_open (&md, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC));
  }
  else
  {
    gcry_md_reset (md);
  }
  gcry_md_setkey (md, key->key, sizeof (key->key));
  gcry_md_write (md, plaintext, plaintext_len);
  mc = gcry_md_read (md, GCRY_MD_SHA512);
  GNUNET_assert (NULL != mc);
  memcpy (hmac->bits, mc, sizeof (hmac->bits));
}


/**
 * Context for cummulative hashing.
 */
struct GNUNET_HashContext
{
  /**
   * Internal state of the hash function.
   */
  gcry_md_hd_t hd;
};


/**
 * Start incremental hashing operation.
 *
 * @return context for incremental hash computation
 */
struct GNUNET_HashContext *
GNUNET_CRYPTO_hash_context_start ()
{
  struct GNUNET_HashContext *hc;

  hc = GNUNET_new (struct GNUNET_HashContext);
  GNUNET_assert (0 ==
                 gcry_md_open (&hc->hd,
                               GCRY_MD_SHA512,
                               0));
  return hc;
}


/**
 * Add data to be hashed.
 *
 * @param hc cummulative hash context
 * @param buf data to add
 * @param size number of bytes in @a buf
 */
void
GNUNET_CRYPTO_hash_context_read (struct GNUNET_HashContext *hc,
                         const void *buf,
                         size_t size)
{
  gcry_md_write (hc->hd, buf, size);
}


/**
 * Finish the hash computation.
 *
 * @param hc hash context to use
 * @param r_hash where to write the latest / final hash code
 */
void
GNUNET_CRYPTO_hash_context_finish (struct GNUNET_HashContext *hc,
                           struct GNUNET_HashCode *r_hash)
{
  const void *res = gcry_md_read (hc->hd, 0);

  GNUNET_assert (NULL != res);
  if (NULL != r_hash)
    memcpy (r_hash,
            res,
            sizeof (struct GNUNET_HashCode));
  GNUNET_CRYPTO_hash_context_abort (hc);
}


/**
 * Abort hashing, do not bother calculating final result.
 *
 * @param hc hash context to destroy
 */
void
GNUNET_CRYPTO_hash_context_abort (struct GNUNET_HashContext *hc)
{
  gcry_md_close (hc->hd);
  GNUNET_free (hc);
}


/* end of crypto_hash.c */
