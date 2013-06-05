/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2012 Christian Grothoff (and other contributing authors)

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
*/

/**
 * @file include/gnunet_crypto_lib.h
 * @brief cryptographic primitives for GNUnet
 *
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author Gerd Knorr <kraxel@bytesex.org>
 * @author Ioana Patrascu
 * @author Tzvetan Horozov
 */

#ifndef GNUNET_CRYPTO_LIB_H
#define GNUNET_CRYPTO_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_common.h"
#include "gnunet_scheduler_lib.h"

/**
 * Desired quality level for cryptographic operations.
 */
enum GNUNET_CRYPTO_Quality
{
  /**
   * No good quality of the operation is needed (i.e.,
   * random numbers can be pseudo-random).
   */
  GNUNET_CRYPTO_QUALITY_WEAK,

  /**
   * High-quality operations are desired.
   */
  GNUNET_CRYPTO_QUALITY_STRONG,

  /**
   * Randomness for IVs etc. is required.
   */
  GNUNET_CRYPTO_QUALITY_NONCE
};


/**
 * @brief length of the sessionkey in bytes (256 BIT sessionkey)
 */
#define GNUNET_CRYPTO_AES_KEY_LENGTH (256/8)

/**
 * @brief Length of RSA encrypted data (2048 bit)
 *
 * We currently do not handle encryption of data
 * that can not be done in a single call to the
 * RSA methods (read: large chunks of data).
 * We should never need that, as we can use
 * the GNUNET_CRYPTO_hash for larger pieces of data for signing,
 * and for encryption, we only need to encode sessionkeys!
 */
#define GNUNET_CRYPTO_RSA_DATA_ENCODING_LENGTH 256

/**
 * Length of an RSA KEY (n,e,len), 2048 bit (=256 octests) key n, 2 byte e
 */
#define GNUNET_CRYPTO_RSA_KEY_LENGTH 258

/**
 * Length of a hash value
 */
#define GNUNET_CRYPTO_HASH_LENGTH (512/8)

/**
 * Maximum length of an ECC signature.
 * Note: round up to multiple of 8 minus 2 for alignment.
 */
#define GNUNET_CRYPTO_ECC_SIGNATURE_DATA_ENCODING_LENGTH 126

/**
 * Maximum length of the public key (q-point, Q = dP) when encoded.
 */
#define GNUNET_CRYPTO_ECC_MAX_PUBLIC_KEY_LENGTH 76 


/**
 * The private information of an RSA key pair.
 */
struct GNUNET_CRYPTO_RsaPrivateKey;

/**
 * The private information of an ECC private key.
 */
struct GNUNET_CRYPTO_EccPrivateKey;


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * GNUnet mandates a certain format for the encoding
 * of private RSA key information that is provided
 * by the RSA implementations.  This format is used
 * to serialize a private RSA key (typically when
 * writing it to disk).
 */
struct GNUNET_CRYPTO_RsaPrivateKeyBinaryEncoded
{
  /**
   * Total size of the structure, in bytes, in big-endian!
   */
  uint16_t len GNUNET_PACKED;
  uint16_t sizen GNUNET_PACKED; /*  in big-endian! */
  uint16_t sizee GNUNET_PACKED; /*  in big-endian! */
  uint16_t sized GNUNET_PACKED; /*  in big-endian! */
  uint16_t sizep GNUNET_PACKED; /*  in big-endian! */
  uint16_t sizeq GNUNET_PACKED; /*  in big-endian! */
  uint16_t sizedmp1 GNUNET_PACKED;      /*  in big-endian! */
  uint16_t sizedmq1 GNUNET_PACKED;      /*  in big-endian! */
  /* followed by the actual values */
};
GNUNET_NETWORK_STRUCT_END


/**
 * @brief 0-terminated ASCII encoding of a struct GNUNET_HashCode.
 */
struct GNUNET_CRYPTO_HashAsciiEncoded
{
  unsigned char encoding[104];
};


/**
 * @brief 0-terminated ASCII encoding of a 'struct GNUNET_ShortHashCode'.
 */
struct GNUNET_CRYPTO_ShortHashAsciiEncoded
{
  unsigned char short_encoding[53];
};



/**
 * @brief an RSA signature
 */
struct GNUNET_CRYPTO_RsaSignature
{
  unsigned char sig[GNUNET_CRYPTO_RSA_DATA_ENCODING_LENGTH];
};


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * @brief header of what an RSA signature signs
 *        this must be followed by "size - 8" bytes of
 *        the actual signed data
 */
struct GNUNET_CRYPTO_RsaSignaturePurpose
{
  /**
   * How many bytes does this signature sign?
   * (including this purpose header); in network
   * byte order (!).
   */
  uint32_t size GNUNET_PACKED;

  /**
   * What does this signature vouch for?  This
   * must contain a GNUNET_SIGNATURE_PURPOSE_XXX
   * constant (from gnunet_signatures.h).  In
   * network byte order!
   */
  uint32_t purpose GNUNET_PACKED;

};


/**
 * @brief A public key.
 */
struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded
{
  /**
   * In big-endian, must be GNUNET_CRYPTO_RSA_KEY_LENGTH+4
   */
  uint16_t len GNUNET_PACKED;

  /**
   * Size of n in key; in big-endian!
   */
  uint16_t sizen GNUNET_PACKED;

  /**
   * The key itself, contains n followed by e.
   */
  unsigned char key[GNUNET_CRYPTO_RSA_KEY_LENGTH];

  /**
   * Padding (must be 0)
   */
  uint16_t padding GNUNET_PACKED;
};


/**
 * RSA Encrypted data.
 */
struct GNUNET_CRYPTO_RsaEncryptedData
{
  unsigned char encoding[GNUNET_CRYPTO_RSA_DATA_ENCODING_LENGTH];
};


/**
 * @brief header of what an ECC signature signs
 *        this must be followed by "size - 8" bytes of
 *        the actual signed data
 */
struct GNUNET_CRYPTO_EccSignaturePurpose
{
  /**
   * How many bytes does this signature sign?
   * (including this purpose header); in network
   * byte order (!).
   */
  uint32_t size GNUNET_PACKED;

  /**
   * What does this signature vouch for?  This
   * must contain a GNUNET_SIGNATURE_PURPOSE_XXX
   * constant (from gnunet_signatures.h).  In
   * network byte order!
   */
  uint32_t purpose GNUNET_PACKED;

};


/**
 * @brief an ECC signature
 */
struct GNUNET_CRYPTO_EccSignature
{
  /**
   * Overall size of the signature data.
   */
  uint16_t size;

  /**
   * S-expression, padded with zeros.
   */
  char sexpr[GNUNET_CRYPTO_ECC_SIGNATURE_DATA_ENCODING_LENGTH];
};


/**
 * Public ECC key (always for NIST P-521) encoded in a format suitable
 * for network transmission as created using 'gcry_sexp_sprint'.
 */
struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded 
{
  /**
   * Size of the encoding, in network byte order.
   */
  uint16_t size;

  /**
   * Actual length of the q-point binary encoding.
   */
  uint16_t len;

  /**
   * 0-padded q-point in binary encoding (GCRYPT_MPI_FMT_USG).
   */
  unsigned char key[GNUNET_CRYPTO_ECC_MAX_PUBLIC_KEY_LENGTH];
};


/**
 * Private ECC key encoded for transmission (with length prefix).
 */
struct GNUNET_CRYPTO_EccPrivateKeyBinaryEncoded
{
  /**
   * Overall size of the private key in network byte order.
   */
  uint16_t size;

  /* followd by S-expression, opaque to applications */

  /* FIXME: consider defining padding to make this a fixed-size struct */

};


/**
 * @brief type for session keys
 */
struct GNUNET_CRYPTO_AesSessionKey
{
  /**
   * Actual key.
   */
  unsigned char key[GNUNET_CRYPTO_AES_KEY_LENGTH];

};
GNUNET_NETWORK_STRUCT_END

/**
 * @brief IV for sym cipher
 *
 * NOTE: must be smaller (!) in size than the
 * struct GNUNET_HashCode.
 */
struct GNUNET_CRYPTO_AesInitializationVector
{
  unsigned char iv[GNUNET_CRYPTO_AES_KEY_LENGTH / 2];
};


/**
 * @brief type for (message) authentication keys
 */
struct GNUNET_CRYPTO_AuthKey
{
  unsigned char key[GNUNET_CRYPTO_HASH_LENGTH];
};


/* **************** Functions and Macros ************* */

/**
 * Seed a weak random generator. Only GNUNET_CRYPTO_QUALITY_WEAK-mode generator
 * can be seeded.
 *
 * @param seed the seed to use
 */
void
GNUNET_CRYPTO_seed_weak_random (int32_t seed);


/**
 * Perform an incremental step in a CRC16 (for TCP/IP) calculation.
 *
 * @param sum current sum, initially 0
 * @param buf buffer to calculate CRC over (must be 16-bit aligned)
 * @param len number of bytes in hdr, must be multiple of 2
 * @return updated crc sum (must be subjected to GNUNET_CRYPTO_crc16_finish to get actual crc16)
 */
uint32_t
GNUNET_CRYPTO_crc16_step (uint32_t sum, const void *buf, size_t len);


/**
 * Convert results from GNUNET_CRYPTO_crc16_step to final crc16.
 *
 * @param sum cummulative sum
 * @return crc16 value
 */
uint16_t
GNUNET_CRYPTO_crc16_finish (uint32_t sum);


/**
 * Calculate the checksum of a buffer in one step.
 *
 * @param buf buffer to  calculate CRC over (must be 16-bit aligned)
 * @param len number of bytes in hdr, must be multiple of 2
 * @return crc16 value
 */
uint16_t
GNUNET_CRYPTO_crc16_n (const void *buf, size_t len);


/**
 * Compute the CRC32 checksum for the first len
 * bytes of the buffer.
 *
 * @param buf the data over which we're taking the CRC
 * @param len the length of the buffer in bytes
 * @return the resulting CRC32 checksum
 */
int32_t
GNUNET_CRYPTO_crc32_n (const void *buf, size_t len);


/**
 * Produce a random value.
 *
 * @param mode desired quality of the random number
 * @param i the upper limit (exclusive) for the random number
 * @return a random value in the interval [0,i) (exclusive).
 */
uint32_t
GNUNET_CRYPTO_random_u32 (enum GNUNET_CRYPTO_Quality mode, uint32_t i);


/**
 * Random on unsigned 64-bit values.
 *
 * @param mode desired quality of the random number
 * @param max value returned will be in range [0,max) (exclusive)
 * @return random 64-bit number
 */
uint64_t
GNUNET_CRYPTO_random_u64 (enum GNUNET_CRYPTO_Quality mode, uint64_t max);


/**
 * Get an array with a random permutation of the
 * numbers 0...n-1.
 * @param mode GNUNET_CRYPTO_QUALITY_STRONG if the strong (but expensive) PRNG should be used, GNUNET_CRYPTO_QUALITY_WEAK otherwise
 * @param n the size of the array
 * @return the permutation array (allocated from heap)
 */
unsigned int *
GNUNET_CRYPTO_random_permute (enum GNUNET_CRYPTO_Quality mode, unsigned int n);


/**
 * Create a new Session key.
 *
 * @param key key to initialize
 */
void
GNUNET_CRYPTO_aes_create_session_key (struct GNUNET_CRYPTO_AesSessionKey *key);


/**
 * Encrypt a block with the public key of another
 * host that uses the same cyper.
 *
 * @param block the block to encrypt
 * @param len the size of the block
 * @param sessionkey the key used to encrypt
 * @param iv the initialization vector to use, use INITVALUE
 *        for streams.
 * @return the size of the encrypted block, -1 for errors
 */
ssize_t
GNUNET_CRYPTO_aes_encrypt (const void *block, size_t len,
                           const struct GNUNET_CRYPTO_AesSessionKey *sessionkey,
                           const struct GNUNET_CRYPTO_AesInitializationVector
                           *iv, void *result);


/**
 * Decrypt a given block with the sessionkey.
 *
 * @param block the data to decrypt, encoded as returned by encrypt
 * @param size how big is the block?
 * @param sessionkey the key used to decrypt
 * @param iv the initialization vector to use
 * @param result address to store the result at
 * @return -1 on failure, size of decrypted block on success
 */
ssize_t
GNUNET_CRYPTO_aes_decrypt (const void *block, size_t size,
                           const struct GNUNET_CRYPTO_AesSessionKey *sessionkey,
                           const struct GNUNET_CRYPTO_AesInitializationVector
                           *iv, void *result);


/**
 * @brief Derive an IV
 * @param iv initialization vector
 * @param skey session key
 * @param salt salt for the derivation
 * @param salt_len size of the salt
 * @param ... pairs of void * & size_t for context chunks, terminated by NULL
 */
void
GNUNET_CRYPTO_aes_derive_iv (struct GNUNET_CRYPTO_AesInitializationVector *iv,
                             const struct GNUNET_CRYPTO_AesSessionKey *skey,
                             const void *salt, size_t salt_len, ...);


/**
 * @brief Derive an IV
 * @param iv initialization vector
 * @param skey session key
 * @param salt salt for the derivation
 * @param salt_len size of the salt
 * @param argp pairs of void * & size_t for context chunks, terminated by NULL
 */
void
GNUNET_CRYPTO_aes_derive_iv_v (struct GNUNET_CRYPTO_AesInitializationVector *iv,
                               const struct GNUNET_CRYPTO_AesSessionKey *skey,
                               const void *salt, size_t salt_len, va_list argp);


/**
 * Convert hash to ASCII encoding.
 * @param block the hash code
 * @param result where to store the encoding (struct GNUNET_CRYPTO_HashAsciiEncoded can be
 *  safely cast to char*, a '\\0' termination is set).
 */
void
GNUNET_CRYPTO_hash_to_enc (const struct GNUNET_HashCode * block,
                           struct GNUNET_CRYPTO_HashAsciiEncoded *result);


/**
 * Convert short hash to ASCII encoding.
 *
 * @param block the hash code
 * @param result where to store the encoding (struct GNUNET_CRYPTO_ShortHashAsciiEncoded can be
 *  safely cast to char*, a '\\0' termination is set).
 */
void
GNUNET_CRYPTO_short_hash_to_enc (const struct GNUNET_CRYPTO_ShortHashCode * block,
				 struct GNUNET_CRYPTO_ShortHashAsciiEncoded *result);


/**
 * Convert ASCII encoding back to a 'struct GNUNET_HashCode'
 *
 * @param enc the encoding
 * @param enclen number of characters in 'enc' (without 0-terminator, which can be missing)
 * @param result where to store the GNUNET_CRYPTO_hash code
 * @return GNUNET_OK on success, GNUNET_SYSERR if result has the wrong encoding
 */
int
GNUNET_CRYPTO_hash_from_string2 (const char *enc, size_t enclen,
                                 struct GNUNET_HashCode * result);


/**
 * Convert ASCII encoding back to a 'struct GNUNET_CRYPTO_ShortHash'
 *
 * @param enc the encoding
 * @param enclen number of characters in 'enc' (without 0-terminator, which can be missing)
 * @param result where to store the GNUNET_CRYPTO_hash code
 * @return GNUNET_OK on success, GNUNET_SYSERR if result has the wrong encoding
 */
int
GNUNET_CRYPTO_short_hash_from_string2 (const char *enc, size_t enclen,
				       struct GNUNET_CRYPTO_ShortHashCode * result);


/**
 * Convert ASCII encoding back to struct GNUNET_HashCode
 *
 * @param enc the encoding
 * @param result where to store the hash code
 * @return GNUNET_OK on success, GNUNET_SYSERR if result has the wrong encoding
 */
#define GNUNET_CRYPTO_hash_from_string(enc, result) \
  GNUNET_CRYPTO_hash_from_string2 (enc, strlen(enc), result)


/**
 * Convert ASCII encoding back to a 'struct GNUNET_CRYPTO_ShortHash'
 *
 * @param enc the encoding
 * @param result where to store the GNUNET_CRYPTO_ShortHash 
 * @return GNUNET_OK on success, GNUNET_SYSERR if result has the wrong encoding
 */
#define GNUNET_CRYPTO_short_hash_from_string(enc, result) \
  GNUNET_CRYPTO_short_hash_from_string2 (enc, strlen(enc), result)


/**
 * Compare function for ShortHashCodes, producing a total ordering
 * of all hashcodes.
 *
 * @param h1 some hash code
 * @param h2 some hash code
 * @return 1 if h1 > h2, -1 if h1 < h2 and 0 if h1 == h2.
 */
int
GNUNET_CRYPTO_short_hash_cmp (const struct GNUNET_CRYPTO_ShortHashCode * h1,
                              const struct GNUNET_CRYPTO_ShortHashCode * h2);

/**
 * Compute the distance between 2 hashcodes.
 * The computation must be fast, not involve
 * a.a or a.e (they're used elsewhere), and
 * be somewhat consistent. And of course, the
 * result should be a positive number.
 *
 * @param a some hash code
 * @param b some hash code
 * @return number between 0 and UINT32_MAX
 */
uint32_t
GNUNET_CRYPTO_hash_distance_u32 (const struct GNUNET_HashCode * a,
                                 const struct GNUNET_HashCode * b);


/**
 * Compute hash of a given block.
 *
 * @param block the data to hash
 * @param size size of the block
 * @param ret pointer to where to write the hashcode
 */
void
GNUNET_CRYPTO_hash (const void *block, size_t size, struct GNUNET_HashCode * ret);


/**
 * Compute short (256-bit) hash of a given block.
 *
 * @param block the data to hash
 * @param size size of the block
 * @param ret pointer to where to write the hashcode
 */
void
GNUNET_CRYPTO_short_hash (const void *block, size_t size, 
			  struct GNUNET_CRYPTO_ShortHashCode * ret);


/**
 * Double short (256-bit) hash to create a long hash.
 *
 * @param sh short hash to double
 * @param dh where to store the (doubled) long hash (not really a hash)
 */
void
GNUNET_CRYPTO_short_hash_double (const struct GNUNET_CRYPTO_ShortHashCode *sh,
				 struct GNUNET_HashCode *dh);


/**
 * Truncate doubled short hash back to a short hash.
 *
 * @param dh doubled short hash to reduce again
 * @param sh where to store the short hash
 * @return GNUNET_OK on success, GNUNET_SYSERR if this was not a
 *         doubled short hash
 */
int
GNUNET_CRYPTO_short_hash_from_truncation (const struct GNUNET_HashCode *dh,
					  struct GNUNET_CRYPTO_ShortHashCode *sh);


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
                    struct GNUNET_HashCode * hmac);


/**
 * Function called once the hash computation over the
 * specified file has completed.
 *
 * @param cls closure
 * @param res resulting hash, NULL on error
 */
typedef void (*GNUNET_CRYPTO_HashCompletedCallback) (void *cls,
                                                     const struct GNUNET_HashCode *
                                                     res);


/**
 * Handle to file hashing operation.
 */
struct GNUNET_CRYPTO_FileHashContext;

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
                         void *callback_cls);


/**
 * Cancel a file hashing operation.
 *
 * @param fhc operation to cancel (callback must not yet have been invoked)
 */
void
GNUNET_CRYPTO_hash_file_cancel (struct GNUNET_CRYPTO_FileHashContext *fhc);


/**
 * Create a random hash code.
 *
 * @param mode desired quality level
 * @param result hash code that is randomized
 */
void
GNUNET_CRYPTO_hash_create_random (enum GNUNET_CRYPTO_Quality mode,
                                  struct GNUNET_HashCode * result);


/**
 * compute result(delta) = b - a
 *
 * @param a some hash code
 * @param b some hash code
 * @param result set to b - a
 */
void
GNUNET_CRYPTO_hash_difference (const struct GNUNET_HashCode * a,
                               const struct GNUNET_HashCode * b,
                               struct GNUNET_HashCode * result);


/**
 * compute result(b) = a + delta
 *
 * @param a some hash code
 * @param delta some hash code
 * @param result set to a + delta
 */
void
GNUNET_CRYPTO_hash_sum (const struct GNUNET_HashCode * a,
                        const struct GNUNET_HashCode * delta,
                        struct GNUNET_HashCode * result);


/**
 * compute result = a ^ b
 *
 * @param a some hash code
 * @param b some hash code
 * @param result set to a ^ b
 */
void
GNUNET_CRYPTO_hash_xor (const struct GNUNET_HashCode * a, const struct GNUNET_HashCode * b,
                        struct GNUNET_HashCode * result);


/**
 * Convert a hashcode into a key.
 *
 * @param hc hash code that serves to generate the key
 * @param skey set to a valid session key
 * @param iv set to a valid initialization vector
 */
void
GNUNET_CRYPTO_hash_to_aes_key (const struct GNUNET_HashCode * hc,
                               struct GNUNET_CRYPTO_AesSessionKey *skey,
                               struct GNUNET_CRYPTO_AesInitializationVector
                               *iv);


/**
 * Obtain a bit from a hashcode.
 *
 * @param code the GNUNET_CRYPTO_hash to index bit-wise
 * @param bit index into the hashcode, [0...159]
 * @return Bit \a bit from hashcode \a code, -1 for invalid index
 */
int
GNUNET_CRYPTO_hash_get_bit (const struct GNUNET_HashCode * code, unsigned int bit);

/**
 * Determine how many low order bits match in two
 * struct GNUNET_HashCodes.  i.e. - 010011 and 011111 share
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
                                  const struct GNUNET_HashCode * second);


/**
 * Compare function for HashCodes, producing a total ordering
 * of all hashcodes.
 *
 * @param h1 some hash code
 * @param h2 some hash code
 * @return 1 if h1 > h2, -1 if h1 < h2 and 0 if h1 == h2.
 */
int
GNUNET_CRYPTO_hash_cmp (const struct GNUNET_HashCode * h1, const struct GNUNET_HashCode * h2);


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
GNUNET_CRYPTO_hash_xorcmp (const struct GNUNET_HashCode * h1,
                           const struct GNUNET_HashCode * h2,
                           const struct GNUNET_HashCode * target);


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
                                 va_list argp);


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
                               const void *salt, size_t salt_len, ...);

/**
 * @brief Derive key
 * @param result buffer for the derived key, allocated by caller
 * @param out_len desired length of the derived key
 * @param xtr_algo hash algorithm for the extraction phase, GCRY_MD_...
 * @param prf_algo hash algorithm for the expansion phase, GCRY_MD_...
 * @param xts salt
 * @param xts_len length of xts
 * @param skm source key material
 * @param skm_len length of skm
 * @param ... pair of void * & size_t for context chunks, terminated by NULL
 * @return GNUNET_YES on success
 */
int
GNUNET_CRYPTO_hkdf (void *result, size_t out_len, int xtr_algo, int prf_algo,
                    const void *xts, size_t xts_len, const void *skm,
                    size_t skm_len, ...);


/**
 * @brief Derive key
 * @param result buffer for the derived key, allocated by caller
 * @param out_len desired length of the derived key
 * @param xtr_algo hash algorithm for the extraction phase, GCRY_MD_...
 * @param prf_algo hash algorithm for the expansion phase, GCRY_MD_...
 * @param xts salt
 * @param xts_len length of xts
 * @param skm source key material
 * @param skm_len length of skm
 * @param argp va_list of void * & size_t pairs for context chunks
 * @return GNUNET_YES on success
 */
int
GNUNET_CRYPTO_hkdf_v (void *result, size_t out_len, int xtr_algo, int prf_algo,
                      const void *xts, size_t xts_len, const void *skm,
                      size_t skm_len, va_list argp);


/**
 * @brief Derive key
 * @param result buffer for the derived key, allocated by caller
 * @param out_len desired length of the derived key
 * @param xts salt
 * @param xts_len length of xts
 * @param skm source key material
 * @param skm_len length of skm
 * @param argp va_list of void * & size_t pairs for context chunks
 * @return GNUNET_YES on success
 */
int
GNUNET_CRYPTO_kdf_v (void *result, size_t out_len, const void *xts,
                     size_t xts_len, const void *skm, size_t skm_len,
                     va_list argp);


/**
 * @brief Derive key
 * @param result buffer for the derived key, allocated by caller
 * @param out_len desired length of the derived key
 * @param xts salt
 * @param xts_len length of xts
 * @param skm source key material
 * @param skm_len length of skm
 * @param ... void * & size_t pairs for context chunks
 * @return GNUNET_YES on success
 */
int
GNUNET_CRYPTO_kdf (void *result, size_t out_len, const void *xts,
                   size_t xts_len, const void *skm, size_t skm_len, ...);


/**
 * Convert a public key to a string.
 *
 * @param pub key to convert
 * @return string representing  'pub'
 */
char *
GNUNET_CRYPTO_rsa_public_key_to_string (const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *pub);


/**
 * Convert a string representing a public key to a public key.
 *
 * @param enc encoded public key
 * @param enclen number of bytes in enc (without 0-terminator)
 * @param pub where to store the public key
 * @return GNUNET_OK on success
 */
int
GNUNET_CRYPTO_rsa_public_key_from_string (const char *enc, 
					  size_t enclen,
					  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *pub);


/**
 * Encode the private key in a format suitable for
 * storing it into a file.
 * @return encoding of the private key
 */
struct GNUNET_CRYPTO_RsaPrivateKeyBinaryEncoded *
GNUNET_CRYPTO_rsa_encode_key (const struct GNUNET_CRYPTO_RsaPrivateKey *hostkey);


/**
 * Decode the private key from the data-format back
 * to the "normal", internal format.
 *
 * @param buf the buffer where the private key data is stored
 * @param len the length of the data in 'buffer'
 * @return NULL on error
 */
struct GNUNET_CRYPTO_RsaPrivateKey *
GNUNET_CRYPTO_rsa_decode_key (const char *buf, uint16_t len);


/**
 * Create a new private key by reading it from a file.  If the
 * files does not exist, create a new key and write it to the
 * file.  Caller must free return value. Note that this function
 * can not guarantee that another process might not be trying
 * the same operation on the same file at the same time.
 * If the contents of the file
 * are invalid the old file is deleted and a fresh key is
 * created.
 *
 * @param filename name of file to use for storage
 * @return new private key, NULL on error (for example,
 *   permission denied)
 * @deprecated use 'GNUNET_CRYPTO_rsa_key_create_start' instead
 */
struct GNUNET_CRYPTO_RsaPrivateKey *
GNUNET_CRYPTO_rsa_key_create_from_file (const char *filename);


/**
 * Open existing private key file and read it.  If the
 * file does not exist, or the contents of the file are
 * invalid, the function fails
 * Caller must free returned value.
 *
 * @return a private key, NULL on error (for example,
 *         permission denied) or when file does not exist or contains invalid
 *         data.
 */
struct GNUNET_CRYPTO_RsaPrivateKey *
GNUNET_CRYPTO_rsa_key_create_from_existing_file (const char *filename);


/**
 * Handle to cancel private key generation.
 */
struct GNUNET_CRYPTO_RsaKeyGenerationContext;


/**
 * Function called upon completion of 'GNUNET_CRYPTO_rsa_key_create_async'.
 *
 * @param cls closure
 * @param pk NULL on error, otherwise the private key (which must be free'd by the callee)
 * @param emsg NULL on success, otherwise an error message
 */
typedef void (*GNUNET_CRYPTO_RsaKeyCallback)(void *cls,
					     struct GNUNET_CRYPTO_RsaPrivateKey *pk,
					     const char *emsg);


/**
 * Create a new private key by reading it from a file.  If the files
 * does not exist, create a new key and write it to the file.  If the
 * contents of the file are invalid the old file is deleted and a
 * fresh key is created.
 *
 * @param filename name of file to use for storage
 * @param cont function to call when done (or on errors)
 * @param cont_cls closure for 'cont'
 * @return handle to abort operation, NULL on fatal errors (cont will not be called if NULL is returned)
 */
struct GNUNET_CRYPTO_RsaKeyGenerationContext *
GNUNET_CRYPTO_rsa_key_create_start (const char *filename,
				    GNUNET_CRYPTO_RsaKeyCallback cont,
				    void *cont_cls);


/**
 * Abort RSA key generation.
 *
 * @param gc key generation context to abort
 */
void
GNUNET_CRYPTO_rsa_key_create_stop (struct GNUNET_CRYPTO_RsaKeyGenerationContext *gc);


/**
 * Setup a hostkey file for a peer given the name of the
 * configuration file (!).  This function is used so that
 * at a later point code can be certain that reading a
 * hostkey is fast (for example in time-dependent testcases).
 *
 * @param cfg_name name of the configuration file to use
 */
void
GNUNET_CRYPTO_rsa_setup_hostkey (const char *cfg_name);


/**
 * Deterministically (!) create a private key using only the
 * given HashCode as input to the PRNG.
 *
 * @param hc "random" input to PRNG
 * @return some private key purely dependent on input
 */
struct GNUNET_CRYPTO_RsaPrivateKey *
GNUNET_CRYPTO_rsa_key_create_from_hash (const struct GNUNET_HashCode *hc);


/**
 * Free memory occupied by the private key.
 *
 * @param key pointer to the memory to free
 */
void
GNUNET_CRYPTO_rsa_key_free (struct GNUNET_CRYPTO_RsaPrivateKey *key);


/**
 * Extract the public key of the host.
 *
 * @param priv the private key
 * @param pub where to write the public key
 */
void
GNUNET_CRYPTO_rsa_key_get_public (const struct GNUNET_CRYPTO_RsaPrivateKey
                                  *priv,
                                  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded
                                  *pub);


/**
 * Get hash of the public key that corresponds to a private key.
 *
 * @param key RSA private key
 * @param id buffer for hash of the public key
 */
void
GNUNET_CRYPTO_rsa_get_public_key_hash (struct GNUNET_CRYPTO_RsaPrivateKey *key,
				       struct GNUNET_HashCode *id);


/**
 * Encrypt a block with the public key of another host that uses the
 * same cyper.
 *
 * @param block the block to encrypt
 * @param size the size of block
 * @param publicKey the encoded public key used to encrypt
 * @param target where to store the encrypted block
 * @return GNUNET_SYSERR on error, GNUNET_OK if ok
 */
int
GNUNET_CRYPTO_rsa_encrypt (const void *block, size_t size,
                           const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded
                           *publicKey,
                           struct GNUNET_CRYPTO_RsaEncryptedData *target);


/**
 * Decrypt a given block with the hostkey.
 *
 * @param key the key to use
 * @param block the data to decrypt, encoded as returned by encrypt, not consumed
 * @param result pointer to a location where the result can be stored
 * @param max how many bytes of a result are expected? Must be exact.
 * @return the size of the decrypted block (that is, size) or -1 on error
 */
ssize_t
GNUNET_CRYPTO_rsa_decrypt (const struct GNUNET_CRYPTO_RsaPrivateKey *key,
                           const struct GNUNET_CRYPTO_RsaEncryptedData *block,
                           void *result, size_t max);


/**
 * Sign a given block.
 *
 * @param key private key to use for the signing
 * @param purpose what to sign (size, purpose)
 * @param sig where to write the signature
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
int
GNUNET_CRYPTO_rsa_sign (const struct GNUNET_CRYPTO_RsaPrivateKey *key,
                        const struct GNUNET_CRYPTO_RsaSignaturePurpose *purpose,
                        struct GNUNET_CRYPTO_RsaSignature *sig);


/**
 * Verify signature.  Note that the caller MUST have already
 * checked that "validate->size" bytes are actually available.
 *
 * @param purpose what is the purpose that validate should have?
 * @param validate block to validate (size, purpose, data)
 * @param sig signature that is being validated
 * @param publicKey public key of the signer
 * @return GNUNET_OK if ok, GNUNET_SYSERR if invalid
 */
int
GNUNET_CRYPTO_rsa_verify (uint32_t purpose,
                          const struct GNUNET_CRYPTO_RsaSignaturePurpose
                          *validate,
                          const struct GNUNET_CRYPTO_RsaSignature *sig,
                          const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded
                          *publicKey);



/**
 * Function called upon completion of 'GNUNET_CRYPTO_ecc_key_create_async'.
 *
 * @param cls closure
 * @param pk NULL on error, otherwise the private key (which must be free'd by the callee)
 * @param emsg NULL on success, otherwise an error message
 */
typedef void (*GNUNET_CRYPTO_EccKeyCallback)(void *cls,
					     struct GNUNET_CRYPTO_EccPrivateKey *pk,
					     const char *emsg);


/**
 * Free memory occupied by ECC key
 *
 * @param privatekey pointer to the memory to free
 */
void
GNUNET_CRYPTO_ecc_key_free (struct GNUNET_CRYPTO_EccPrivateKey *privatekey);


/**
 * Extract the public key for the given private key.
 *
 * @param priv the private key
 * @param pub where to write the public key
 */
void
GNUNET_CRYPTO_ecc_key_get_public (const struct GNUNET_CRYPTO_EccPrivateKey *priv,
                                  struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded *pub);

/**
 * Convert a public key to a string.
 *
 * @param pub key to convert
 * @return string representing  'pub'
 */
char *
GNUNET_CRYPTO_ecc_public_key_to_string (const struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded *pub);


/**
 * Convert a string representing a public key to a public key.
 *
 * @param enc encoded public key
 * @param enclen number of bytes in enc (without 0-terminator)
 * @param pub where to store the public key
 * @return GNUNET_OK on success
 */
int
GNUNET_CRYPTO_ecc_public_key_from_string (const char *enc, 
					  size_t enclen,
					  struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded *pub);


/**
 * Encode the private key in a format suitable for
 * storing it into a file.
 *
 * @param key key to encode
 * @return encoding of the private key.
 *    The first 4 bytes give the size of the array, as usual.
 */
struct GNUNET_CRYPTO_EccPrivateKeyBinaryEncoded *
GNUNET_CRYPTO_ecc_encode_key (const struct GNUNET_CRYPTO_EccPrivateKey *key);


/**
 * Decode the private key from the file-format back
 * to the "normal", internal format.
 *
 * @param buf the buffer where the private key data is stored
 * @param len the length of the data in 'buffer'
 * @param validate GNUNET_YES to validate that the key is well-formed,
 *                 GNUNET_NO if the key comes from a totally trusted source 
 *                 and validation is considered too expensive
 * @return NULL on error
 */
struct GNUNET_CRYPTO_EccPrivateKey *
GNUNET_CRYPTO_ecc_decode_key (const char *buf, 
			      size_t len,
			      int validate);


/**
 * Create a new private key by reading it from a file.  If the
 * files does not exist, create a new key and write it to the
 * file.  Caller must free return value.  Note that this function
 * can not guarantee that another process might not be trying
 * the same operation on the same file at the same time.
 * If the contents of the file
 * are invalid the old file is deleted and a fresh key is
 * created.
 *
 * @return new private key, NULL on error (for example,
 *   permission denied)
 */
struct GNUNET_CRYPTO_EccPrivateKey *
GNUNET_CRYPTO_ecc_key_create_from_file (const char *filename);


/**
 * Handle to cancel private key generation and state for the
 * key generation operation.
 */
struct GNUNET_CRYPTO_EccKeyGenerationContext;

/**
 * Create a new private key. Caller must free return value.  Blocking version
 * (blocks to gather entropy).
 *
 * @return fresh private key
 */
struct GNUNET_CRYPTO_EccPrivateKey *
GNUNET_CRYPTO_ecc_key_create (void);


/**
 * Create a new private key by reading it from a file.  If the files
 * does not exist, create a new key and write it to the file.  If the
 * contents of the file are invalid the old file is deleted and a
 * fresh key is created.
 *
 * @param filename name of file to use for storage
 * @param cont function to call when done (or on errors)
 * @param cont_cls closure for 'cont'
 * @return handle to abort operation, NULL on fatal errors (cont will not be called if NULL is returned)
 */
struct GNUNET_CRYPTO_EccKeyGenerationContext *
GNUNET_CRYPTO_ecc_key_create_start (const char *filename,
				    GNUNET_CRYPTO_EccKeyCallback cont,
				    void *cont_cls);


/**
 * Abort ECC key generation.
 *
 * @param gc key generation context to abort
 */
void
GNUNET_CRYPTO_ecc_key_create_stop (struct GNUNET_CRYPTO_EccKeyGenerationContext *gc);

/**
 * Setup a hostkey file for a peer given the name of the
 * configuration file (!).  This function is used so that
 * at a later point code can be certain that reading a
 * hostkey is fast (for example in time-dependent testcases).
 *
 * @param cfg_name name of the configuration file to use
 */
void
GNUNET_CRYPTO_ecc_setup_hostkey (const char *cfg_name);


/**
 * Retrieve the identity of the host's peer.
 *
 * @param cfg configuration to use
 * @param dst pointer to where to write the peer identity
 * @return GNUNET_OK on success, GNUNET_SYSERR if the identity
 *         could not be retrieved
 */
int
GNUNET_CRYPTO_get_host_identity (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                 struct GNUNET_PeerIdentity *dst);


/**
 * Derive key material from a public and a private ECC key.
 *
 * @param key private key to use for the ECDH (x)
 * @param pub public key to use for the ECDY (yG)
 * @param key_material where to write the key material (xyG)
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
int
GNUNET_CRYPTO_ecc_ecdh (const struct GNUNET_CRYPTO_EccPrivateKey *key,
                        const struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded *pub,
                        struct GNUNET_HashCode *key_material);


/**
 * Sign a given block.
 *
 * @param key private key to use for the signing
 * @param purpose what to sign (size, purpose)
 * @param sig where to write the signature
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
int
GNUNET_CRYPTO_ecc_sign (const struct GNUNET_CRYPTO_EccPrivateKey *key,
                        const struct GNUNET_CRYPTO_EccSignaturePurpose *purpose,
                        struct GNUNET_CRYPTO_EccSignature *sig);


/**
 * Verify signature.
 *
 * @param purpose what is the purpose that the signature should have?
 * @param validate block to validate (size, purpose, data)
 * @param sig signature that is being validated
 * @param publicKey public key of the signer
 * @returns GNUNET_OK if ok, GNUNET_SYSERR if invalid
 */
int
GNUNET_CRYPTO_ecc_verify (uint32_t purpose,
                          const struct GNUNET_CRYPTO_EccSignaturePurpose
                          *validate,
                          const struct GNUNET_CRYPTO_EccSignature *sig,
                          const struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded
                          *publicKey);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_CRYPTO_LIB_H */
#endif
/* end of gnunet_crypto_lib.h */
