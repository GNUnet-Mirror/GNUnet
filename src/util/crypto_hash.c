/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.

     SHA-512 code by Jean-Luc Cooke <jlcooke@certainkey.com>

     Copyright (c) Jean-Luc Cooke <jlcooke@certainkey.com>
     Copyright (c) Andrew McDonald <andrew@mcdonald.org.uk>
     Copyright (c) 2003 Kyle McMartin <kyle@debian.org>
*/

/**
 * @file util/crypto_hash.c
 * @brief SHA-512 GNUNET_CRYPTO_hash related functions
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_disk_lib.h"
#include <gcrypt.h>

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

#define LOG_STRERROR_FILE(kind,syscall,filename) GNUNET_log_from_strerror_file (kind, "util", syscall, filename)

/**
 * Hash block of given size.
 *
 * @param block the data to GNUNET_CRYPTO_hash, length is given as a second argument
 * @param size the length of the data to GNUNET_CRYPTO_hash
 * @param ret pointer to where to write the hashcode
 */
void
GNUNET_CRYPTO_hash (const void *block, size_t size, GNUNET_HashCode * ret)
{
  gcry_md_hash_buffer (GCRY_MD_SHA512, ret, block, size);
}


/**
 * Context used when hashing a file.
 */
struct GNUNET_CRYPTO_FileHashContext
{

  /**
   * Function to call upon completion.
   */
  GNUNET_CRYPTO_HashCompletedCallback callback;

  /**
   * Closure for callback.
   */
  void *callback_cls;

  /**
   * IO buffer.
   */
  unsigned char *buffer;

  /**
   * Name of the file we are hashing.
   */
  char *filename;

  /**
   * File descriptor.
   */
  struct GNUNET_DISK_FileHandle *fh;

  /**
   * Cummulated hash.
   */
  gcry_md_hd_t md;

  /**
   * Size of the file.
   */
  uint64_t fsize;

  /**
   * Current offset.
   */
  uint64_t offset;

  /**
   * Current task for hashing.
   */
  GNUNET_SCHEDULER_TaskIdentifier task;

  /**
   * Priority we use.
   */
  enum GNUNET_SCHEDULER_Priority priority;

  /**
   * Blocksize.
   */
  size_t bsize;

};


/**
 * Report result of hash computation to callback
 * and free associated resources.
 */
static void
file_hash_finish (struct GNUNET_CRYPTO_FileHashContext *fhc,
                  const GNUNET_HashCode * res)
{
  fhc->callback (fhc->callback_cls, res);
  GNUNET_free (fhc->filename);
  if (!GNUNET_DISK_handle_invalid (fhc->fh))
    GNUNET_break (GNUNET_OK == GNUNET_DISK_file_close (fhc->fh));
  gcry_md_close (fhc->md);
  GNUNET_free (fhc);            /* also frees fhc->buffer */
}


/**
 * File hashing task.
 *
 * @param cls closure
 * @param tc context
 */
static void
file_hash_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CRYPTO_FileHashContext *fhc = cls;
  GNUNET_HashCode *res;
  size_t delta;

  fhc->task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_assert (fhc->offset <= fhc->fsize);
  delta = fhc->bsize;
  if (fhc->fsize - fhc->offset < delta)
    delta = fhc->fsize - fhc->offset;
  if (delta != GNUNET_DISK_file_read (fhc->fh, fhc->buffer, delta))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "read", fhc->filename);
    file_hash_finish (fhc, NULL);
    return;
  }
  gcry_md_write (fhc->md, fhc->buffer, delta);
  fhc->offset += delta;
  if (fhc->offset == fhc->fsize)
  {
    res = (GNUNET_HashCode *) gcry_md_read (fhc->md, GCRY_MD_SHA512);
    file_hash_finish (fhc, res);
    return;
  }
  fhc->task = GNUNET_SCHEDULER_add_with_priority (fhc->priority,
						  &file_hash_task, fhc);
}


/**
 * Compute the hash of an entire file.
 *
 * @param priority scheduling priority to use
 * @param filename name of file to hash
 * @param blocksize number of bytes to process in one task
 * @param callback function to call upon completion
 * @param callback_cls closure for callback
 * @return NULL on (immediate) errror
 */
struct GNUNET_CRYPTO_FileHashContext *
GNUNET_CRYPTO_hash_file (enum GNUNET_SCHEDULER_Priority priority,
                         const char *filename, size_t blocksize,
                         GNUNET_CRYPTO_HashCompletedCallback callback,
                         void *callback_cls)
{
  struct GNUNET_CRYPTO_FileHashContext *fhc;

  GNUNET_assert (blocksize > 0);
  fhc =
      GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_FileHashContext) + blocksize);
  fhc->callback = callback;
  fhc->callback_cls = callback_cls;
  fhc->buffer = (unsigned char *) &fhc[1];
  fhc->filename = GNUNET_strdup (filename);
  if (GPG_ERR_NO_ERROR != gcry_md_open (&fhc->md, GCRY_MD_SHA512, 0))
  {
    GNUNET_break (0);
    GNUNET_free (fhc);
    return NULL;
  }
  fhc->bsize = blocksize;
  if (GNUNET_OK != GNUNET_DISK_file_size (filename, &fhc->fsize, GNUNET_NO))
  {
    GNUNET_free (fhc->filename);
    GNUNET_free (fhc);
    return NULL;
  }
  fhc->fh =
      GNUNET_DISK_file_open (filename, GNUNET_DISK_OPEN_READ,
                             GNUNET_DISK_PERM_NONE);
  if (!fhc->fh)
  {
    GNUNET_free (fhc->filename);
    GNUNET_free (fhc);
    return NULL;
  }
  fhc->priority = priority;
  fhc->task =
      GNUNET_SCHEDULER_add_with_priority (priority, &file_hash_task, fhc);
  return fhc;
}


/**
 * Cancel a file hashing operation.
 *
 * @param fhc operation to cancel (callback must not yet have been invoked)
 */
void
GNUNET_CRYPTO_hash_file_cancel (struct GNUNET_CRYPTO_FileHashContext *fhc)
{
  GNUNET_SCHEDULER_cancel (fhc->task);
  GNUNET_free (fhc->filename);
  GNUNET_break (GNUNET_OK == GNUNET_DISK_file_close (fhc->fh));
  GNUNET_free (fhc);
}



/* ***************** binary-ASCII encoding *************** */

/**
 * Get the numeric value corresponding to a character.
 *
 * @param a a character
 * @return corresponding numeric value
 */
static unsigned int
getValue__ (unsigned char a)
{
  if ((a >= '0') && (a <= '9'))
    return a - '0';
  if ((a >= 'A') && (a <= 'V'))
    return (a - 'A' + 10);
  return -1;
}


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
GNUNET_CRYPTO_hash_to_enc (const GNUNET_HashCode * block,
                           struct GNUNET_CRYPTO_HashAsciiEncoded *result)
{
  /**
   * 32 characters for encoding (GNUNET_CRYPTO_hash => 32 characters)
   */
  static char *encTable__ = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
  unsigned int wpos;
  unsigned int rpos;
  unsigned int bits;
  unsigned int vbit;

  GNUNET_assert (block != NULL);
  GNUNET_assert (result != NULL);
  vbit = 0;
  wpos = 0;
  rpos = 0;
  bits = 0;
  while ((rpos < sizeof (GNUNET_HashCode)) || (vbit > 0))
  {
    if ((rpos < sizeof (GNUNET_HashCode)) && (vbit < 5))
    {
      bits = (bits << 8) | ((unsigned char *) block)[rpos++];   /* eat 8 more bits */
      vbit += 8;
    }
    if (vbit < 5)
    {
      bits <<= (5 - vbit);      /* zero-padding */
      GNUNET_assert (vbit == 2);        /* padding by 3: 512+3 mod 5 == 0 */
      vbit = 5;
    }
    GNUNET_assert (wpos < sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded) - 1);
    result->encoding[wpos++] = encTable__[(bits >> (vbit - 5)) & 31];
    vbit -= 5;
  }
  GNUNET_assert (wpos == sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded) - 1);
  GNUNET_assert (vbit == 0);
  result->encoding[wpos] = '\0';
}


/**
 * Convert ASCII encoding back to GNUNET_CRYPTO_hash
 *
 * @param enc the encoding
 * @param enclen number of characters in 'enc' (without 0-terminator, which can be missing)
 * @param result where to store the GNUNET_CRYPTO_hash code
 * @return GNUNET_OK on success, GNUNET_SYSERR if result has the wrong encoding
 */
int
GNUNET_CRYPTO_hash_from_string2 (const char *enc, size_t enclen,
                                GNUNET_HashCode * result)
{
  unsigned int rpos;
  unsigned int wpos;
  unsigned int bits;
  unsigned int vbit;
  int ret;

  if (enclen != sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded) - 1)
    return GNUNET_SYSERR;

  vbit = 2;                     /* padding! */
  wpos = sizeof (GNUNET_HashCode);
  rpos = sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded) - 1;
  bits = (ret = getValue__ (enc[--rpos])) >> 3;
  if (-1 == ret)
    return GNUNET_SYSERR;
  while (wpos > 0)
  {
    GNUNET_assert (rpos > 0);
    bits = ((ret = getValue__ (enc[--rpos])) << vbit) | bits;
    if (-1 == ret)
      return GNUNET_SYSERR;
    vbit += 5;
    if (vbit >= 8)
    {
      ((unsigned char *) result)[--wpos] = (unsigned char) bits;
      bits >>= 8;
      vbit -= 8;
    }
  }
  GNUNET_assert (rpos == 0);
  GNUNET_assert (vbit == 0);
  return GNUNET_OK;
}


/**
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
GNUNET_CRYPTO_hash_distance_u32 (const GNUNET_HashCode * a,
                                 const GNUNET_HashCode * b)
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
                                  GNUNET_HashCode * result)
{
  int i;

  for (i = (sizeof (GNUNET_HashCode) / sizeof (uint32_t)) - 1; i >= 0; i--)
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
GNUNET_CRYPTO_hash_difference (const GNUNET_HashCode * a,
                               const GNUNET_HashCode * b,
                               GNUNET_HashCode * result)
{
  int i;

  for (i = (sizeof (GNUNET_HashCode) / sizeof (unsigned int)) - 1; i >= 0; i--)
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
GNUNET_CRYPTO_hash_sum (const GNUNET_HashCode * a,
                        const GNUNET_HashCode * delta, GNUNET_HashCode * result)
{
  int i;

  for (i = (sizeof (GNUNET_HashCode) / sizeof (unsigned int)) - 1; i >= 0; i--)
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
GNUNET_CRYPTO_hash_xor (const GNUNET_HashCode * a, const GNUNET_HashCode * b,
                        GNUNET_HashCode * result)
{
  int i;

  for (i = (sizeof (GNUNET_HashCode) / sizeof (unsigned int)) - 1; i >= 0; i--)
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
GNUNET_CRYPTO_hash_to_aes_key (const GNUNET_HashCode * hc,
                               struct GNUNET_CRYPTO_AesSessionKey *skey,
                               struct GNUNET_CRYPTO_AesInitializationVector *iv)
{
  GNUNET_assert (sizeof (GNUNET_HashCode) >=
                 GNUNET_CRYPTO_AES_KEY_LENGTH +
                 sizeof (struct GNUNET_CRYPTO_AesInitializationVector));
  memcpy (skey, hc, GNUNET_CRYPTO_AES_KEY_LENGTH);
  skey->crc32 =
      htonl (GNUNET_CRYPTO_crc32_n (skey, GNUNET_CRYPTO_AES_KEY_LENGTH));
  memcpy (iv, &((char *) hc)[GNUNET_CRYPTO_AES_KEY_LENGTH],
          sizeof (struct GNUNET_CRYPTO_AesInitializationVector));
}


/**
 * Obtain a bit from a hashcode.
 * @param code the GNUNET_CRYPTO_hash to index bit-wise
 * @param bit index into the hashcode, [0...511]
 * @return Bit \a bit from hashcode \a code, -1 for invalid index
 */
int
GNUNET_CRYPTO_hash_get_bit (const GNUNET_HashCode * code, unsigned int bit)
{
  GNUNET_assert (bit < 8 * sizeof (GNUNET_HashCode));
  return (((unsigned char *) code)[bit >> 3] & (1 << (bit & 7))) > 0;
}


/**
 * Determine how many low order bits match in two
 * GNUNET_HashCodes.  i.e. - 010011 and 011111 share
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
GNUNET_CRYPTO_hash_matching_bits (const GNUNET_HashCode * first,
                                  const GNUNET_HashCode * second)
{
  unsigned int i;

  for (i = 0; i < sizeof (GNUNET_HashCode) * 8; i++)
    if (GNUNET_CRYPTO_hash_get_bit (first, i) !=
        GNUNET_CRYPTO_hash_get_bit (second, i))
      return i;
  return sizeof (GNUNET_HashCode) * 8;
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
GNUNET_CRYPTO_hash_cmp (const GNUNET_HashCode * h1, const GNUNET_HashCode * h2)
{
  unsigned int *i1;
  unsigned int *i2;
  int i;

  i1 = (unsigned int *) h1;
  i2 = (unsigned int *) h2;
  for (i = (sizeof (GNUNET_HashCode) / sizeof (unsigned int)) - 1; i >= 0; i--)
  {
    if (i1[i] > i2[i])
      return 1;
    if (i1[i] < i2[i])
      return -1;
  }
  return 0;
}


/**
 * Find out which of the two GNUNET_CRYPTO_hash codes is closer to target
 * in the XOR metric (Kademlia).
 *
 * @param h1 some hash code
 * @param h2 some hash code
 * @param target some hash code
 * @return -1 if h1 is closer, 1 if h2 is closer and 0 if h1==h2.
 */
int
GNUNET_CRYPTO_hash_xorcmp (const GNUNET_HashCode * h1,
                           const GNUNET_HashCode * h2,
                           const GNUNET_HashCode * target)
{
  int i;
  unsigned int d1;
  unsigned int d2;

  for (i = sizeof (GNUNET_HashCode) / sizeof (unsigned int) - 1; i >= 0; i--)
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
 * @param salt_len size of the salt
 * @param ... pair of void * & size_t for context chunks, terminated by NULL
 */
void
GNUNET_CRYPTO_hmac_derive_key (struct GNUNET_CRYPTO_AuthKey *key,
                               const struct GNUNET_CRYPTO_AesSessionKey *rkey,
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
 * @param salt_len size of the salt
 * @param argp pair of void * & size_t for context chunks, terminated by NULL
 */
void
GNUNET_CRYPTO_hmac_derive_key_v (struct GNUNET_CRYPTO_AuthKey *key,
                                 const struct GNUNET_CRYPTO_AesSessionKey *rkey,
                                 const void *salt, size_t salt_len,
                                 va_list argp)
{
  GNUNET_CRYPTO_kdf_v (key->key, sizeof (key->key), salt, salt_len, rkey->key,
                       sizeof (rkey->key), argp);
}


/**
 * Calculate HMAC of a message (RFC 2104)
 *
 * @param key secret key
 * @param plaintext input plaintext
 * @param plaintext_len length of plaintext
 * @param hmac where to store the hmac
 */
void
GNUNET_CRYPTO_hmac (const struct GNUNET_CRYPTO_AuthKey *key,
                    const void *plaintext, size_t plaintext_len,
                    GNUNET_HashCode * hmac)
{
  gcry_md_hd_t md;
  const unsigned char *mc;

  GNUNET_assert (GPG_ERR_NO_ERROR ==
                 gcry_md_open (&md, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC));
  gcry_md_setkey (md, key->key, sizeof (key->key));
  gcry_md_write (md, plaintext, plaintext_len);
  mc = gcry_md_read (md, GCRY_MD_SHA512);
  if (mc != NULL)
    memcpy (hmac->bits, mc, sizeof (hmac->bits));
  gcry_md_close (md);
}


/* end of crypto_hash.c */
