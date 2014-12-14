/*
     This file is part of GNUnet.
     (C) 2001-2013 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_crypto_lib.h
 * @brief cryptographic primitives for GNUnet
 *
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author Gerd Knorr <kraxel@bytesex.org>
 * @author Ioana Patrascu
 * @author Tzvetan Horozov
 *
 * @defgroup crypto Cryptographic operations
 * @defgroup hash Hashing and operations on hashes
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

/**
 * @brief A 512-bit hashcode
 */
struct GNUNET_HashCode;

/**
 * The identity of the host (wraps the signing key of the peer).
 */
struct GNUNET_PeerIdentity;

#include "gnunet_common.h"
#include "gnunet_scheduler_lib.h"
#include <gcrypt.h>


/**
 * @brief A 512-bit hashcode
 */
struct GNUNET_HashCode
{
  uint32_t bits[512 / 8 / sizeof (uint32_t)];   /* = 16 */
};


/**
 * Maximum length of an ECC signature.
 * Note: round up to multiple of 8 minus 2 for alignment.
 */
#define GNUNET_CRYPTO_ECC_SIGNATURE_DATA_ENCODING_LENGTH 126


/**
 * Desired quality level for random numbers.
 * @ingroup crypto
 */
enum GNUNET_CRYPTO_Quality
{
  /**
   * No good quality of the operation is needed (i.e.,
   * random numbers can be pseudo-random).
   * @ingroup crypto
   */
  GNUNET_CRYPTO_QUALITY_WEAK,

  /**
   * High-quality operations are desired.
   * @ingroup crypto
   */
  GNUNET_CRYPTO_QUALITY_STRONG,

  /**
   * Randomness for IVs etc. is required.
   * @ingroup crypto
   */
  GNUNET_CRYPTO_QUALITY_NONCE
};


/**
 * @brief length of the sessionkey in bytes (256 BIT sessionkey)
 */
#define GNUNET_CRYPTO_AES_KEY_LENGTH (256/8)

/**
 * Length of a hash value
 */
#define GNUNET_CRYPTO_HASH_LENGTH (512/8)

/**
 * How many characters (without 0-terminator) are our ASCII-encoded
 * public keys (ECDSA/EDDSA/ECDHE).
 */
#define GNUNET_CRYPTO_PKEY_ASCII_LENGTH 52

/**
 * @brief 0-terminated ASCII encoding of a struct GNUNET_HashCode.
 */
struct GNUNET_CRYPTO_HashAsciiEncoded
{
  unsigned char encoding[104];
};


GNUNET_NETWORK_STRUCT_BEGIN


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
 * @brief an ECC signature using EdDSA.
 * See https://gnunet.org/ed25519
 */
struct GNUNET_CRYPTO_EddsaSignature
{

  /**
   * R value.
   */
  unsigned char r[256 / 8];

  /**
   * S value.
   */
  unsigned char s[256 / 8];

};



/**
 * @brief an ECC signature using ECDSA
 */
struct GNUNET_CRYPTO_EcdsaSignature
{

  /**
   * R value.
   */
  unsigned char r[256 / 8];

  /**
   * S value.
   */
  unsigned char s[256 / 8];

};


/**
 * Public ECC key (always for Curve25519) encoded in a format suitable
 * for network transmission and EdDSA signatures.
 */
struct GNUNET_CRYPTO_EddsaPublicKey
{
  /**
   * Q consists of an x- and a y-value, each mod p (256 bits), given
   * here in affine coordinates and Ed25519 standard compact format.
   */
  unsigned char q_y[256 / 8];

};


/**
 * Public ECC key (always for Curve25519) encoded in a format suitable
 * for network transmission and ECDSA signatures.
 */
struct GNUNET_CRYPTO_EcdsaPublicKey
{
  /**
   * Q consists of an x- and a y-value, each mod p (256 bits), given
   * here in affine coordinates and Ed25519 standard compact format.
   */
  unsigned char q_y[256 / 8];

};


/**
 * The identity of the host (wraps the signing key of the peer).
 */
struct GNUNET_PeerIdentity
{
  struct GNUNET_CRYPTO_EddsaPublicKey public_key;
};


/**
 * Public ECC key (always for Curve25519) encoded in a format suitable
 * for network transmission and encryption (ECDH),
 * See http://cr.yp.to/ecdh.html
 */
struct GNUNET_CRYPTO_EcdhePublicKey
{
  /**
   * Q consists of an x- and a y-value, each mod p (256 bits), given
   * here in affine coordinates and Ed25519 standard compact format.
   */
  unsigned char q_y[256 / 8];
};


/**
 * Private ECC key encoded for transmission.  To be used only for ECDH
 * key exchange (ECDHE to be precise).
 */
struct GNUNET_CRYPTO_EcdhePrivateKey
{
  /**
   * d is a value mod n, where n has at most 256 bits.
   */
  unsigned char d[256 / 8];

};

/**
 * Private ECC key encoded for transmission.  To be used only for ECDSA
 * signatures.
 */
struct GNUNET_CRYPTO_EcdsaPrivateKey
{
  /**
   * d is a value mod n, where n has at most 256 bits.
   */
  unsigned char d[256 / 8];

};

/**
 * Private ECC key encoded for transmission.  To be used only for EdDSA
 * signatures.
 */
struct GNUNET_CRYPTO_EddsaPrivateKey
{
  /**
   * d is a value mod n, where n has at most 256 bits.
   */
  unsigned char d[256 / 8];

};


/**
 * @brief type for session keys
 */
struct GNUNET_CRYPTO_SymmetricSessionKey
{
  /**
   * Actual key for AES.
   */
  unsigned char aes_key[GNUNET_CRYPTO_AES_KEY_LENGTH];

  /**
   * Actual key for TwoFish.
   */
  unsigned char twofish_key[GNUNET_CRYPTO_AES_KEY_LENGTH];

};

GNUNET_NETWORK_STRUCT_END

/**
 * @brief IV for sym cipher
 *
 * NOTE: must be smaller (!) in size than the
 * `struct GNUNET_HashCode`.
 */
struct GNUNET_CRYPTO_SymmetricInitializationVector
{
  unsigned char aes_iv[GNUNET_CRYPTO_AES_KEY_LENGTH / 2];

  unsigned char twofish_iv[GNUNET_CRYPTO_AES_KEY_LENGTH / 2];
};


/**
 * @brief type for (message) authentication keys
 */
struct GNUNET_CRYPTO_AuthKey
{
  unsigned char key[GNUNET_CRYPTO_HASH_LENGTH];
};


/**
 * Size of paillier plain texts and public keys.
 * Private keys and ciphertexts are twice this size.
 */
#define GNUNET_CRYPTO_PAILLIER_BITS 2048


/**
 * Paillier public key.
 */
struct GNUNET_CRYPTO_PaillierPublicKey
{
  /**
   * N value.
   */
  unsigned char n[GNUNET_CRYPTO_PAILLIER_BITS / 8];
};


/**
 * Paillier public key.
 */
struct GNUNET_CRYPTO_PaillierPrivateKey
{
  /**
   * Lambda-component of the private key.
   */
  unsigned char lambda[GNUNET_CRYPTO_PAILLIER_BITS / 8];
  /**
   * Mu-component of the private key.
   */
  unsigned char mu[GNUNET_CRYPTO_PAILLIER_BITS / 8];
};


/**
 * Paillier ciphertext.
 */
struct GNUNET_CRYPTO_PaillierCiphertext
{
  /**
   * Guaranteed minimum number of homomorphic operations with this ciphertext,
   * in network byte order (NBO).
   */
  int32_t remaining_ops GNUNET_PACKED;

  /**
   * The bits of the ciphertext.
   */
  unsigned char bits[GNUNET_CRYPTO_PAILLIER_BITS * 2 / 8];
};


/* **************** Functions and Macros ************* */

/**
 * @ingroup crypto
 * Seed a weak random generator. Only #GNUNET_CRYPTO_QUALITY_WEAK-mode generator
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
 * @param len number of bytes in @a buf, must be multiple of 2
 * @return updated crc sum (must be subjected to #GNUNET_CRYPTO_crc16_finish to get actual crc16)
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
 * @ingroup hash
 * Calculate the checksum of a buffer in one step.
 *
 * @param buf buffer to calculate CRC over (must be 16-bit aligned)
 * @param len number of bytes in @a buf, must be multiple of 2
 * @return crc16 value
 */
uint16_t
GNUNET_CRYPTO_crc16_n (const void *buf, size_t len);


/**
 * @ingroup hash
 * Compute the CRC32 checksum for the first len
 * bytes of the buffer.
 *
 * @param buf the data over which we're taking the CRC
 * @param len the length of the buffer @a buf in bytes
 * @return the resulting CRC32 checksum
 */
int32_t
GNUNET_CRYPTO_crc32_n (const void *buf, size_t len);


/**
 * @ingroup crypto
 * Fill block with a random values.
 *
 * @param mode desired quality of the random number
 * @param buffer the buffer to fill
 * @param length buffer length
 */
void
GNUNET_CRYPTO_random_block (enum GNUNET_CRYPTO_Quality mode, void *buffer, size_t length);

/**
 * @ingroup crypto
 * Produce a random value.
 *
 * @param mode desired quality of the random number
 * @param i the upper limit (exclusive) for the random number
 * @return a random value in the interval [0,@a i) (exclusive).
 */
uint32_t
GNUNET_CRYPTO_random_u32 (enum GNUNET_CRYPTO_Quality mode, uint32_t i);


/**
 * @ingroup crypto
 * Random on unsigned 64-bit values.
 *
 * @param mode desired quality of the random number
 * @param max value returned will be in range [0,@a max) (exclusive)
 * @return random 64-bit number
 */
uint64_t
GNUNET_CRYPTO_random_u64 (enum GNUNET_CRYPTO_Quality mode, uint64_t max);


/**
 * @ingroup crypto
 * Get an array with a random permutation of the
 * numbers 0...n-1.
 * @param mode #GNUNET_CRYPTO_QUALITY_STRONG if the strong (but expensive) PRNG should be used,
 *             #GNUNET_CRYPTO_QUALITY_WEAK or #GNUNET_CRYPTO_QUALITY_NONCE otherwise
 * @param n the size of the array
 * @return the permutation array (allocated from heap)
 */
unsigned int *
GNUNET_CRYPTO_random_permute (enum GNUNET_CRYPTO_Quality mode, unsigned int n);


/**
 * @ingroup crypto
 * Create a new random session key.
 *
 * @param key key to initialize
 */
void
GNUNET_CRYPTO_symmetric_create_session_key (struct GNUNET_CRYPTO_SymmetricSessionKey *key);


/**
 * @ingroup crypto
 * Encrypt a block using a symmetric sessionkey.
 *
 * @param block the block to encrypt
 * @param size the size of the @a block
 * @param sessionkey the key used to encrypt
 * @param iv the initialization vector to use, use INITVALUE
 *        for streams.
 * @return the size of the encrypted block, -1 for errors
 */
ssize_t
GNUNET_CRYPTO_symmetric_encrypt (const void *block, size_t size,
                                 const struct GNUNET_CRYPTO_SymmetricSessionKey *sessionkey,
                                 const struct GNUNET_CRYPTO_SymmetricInitializationVector *iv,
                                 void *result);


/**
 * @ingroup crypto
 * Decrypt a given block using a symmetric sessionkey.
 *
 * @param block the data to decrypt, encoded as returned by encrypt
 * @param size how big is the block?
 * @param sessionkey the key used to decrypt
 * @param iv the initialization vector to use
 * @param result address to store the result at
 * @return -1 on failure, size of decrypted block on success
 */
ssize_t
GNUNET_CRYPTO_symmetric_decrypt (const void *block, size_t size,
                                 const struct GNUNET_CRYPTO_SymmetricSessionKey *sessionkey,
                                 const struct GNUNET_CRYPTO_SymmetricInitializationVector *iv,
                                 void *result);


/**
 * @ingroup crypto
 * @brief Derive an IV
 * @param iv initialization vector
 * @param skey session key
 * @param salt salt for the derivation
 * @param salt_len size of the @a salt
 * @param ... pairs of void * & size_t for context chunks, terminated by NULL
 */
void
GNUNET_CRYPTO_symmetric_derive_iv (struct GNUNET_CRYPTO_SymmetricInitializationVector *iv,
                                   const struct GNUNET_CRYPTO_SymmetricSessionKey *skey,
                                   const void *salt,
                                   size_t salt_len, ...);


/**
 * @brief Derive an IV
 * @param iv initialization vector
 * @param skey session key
 * @param salt salt for the derivation
 * @param salt_len size of the @a salt
 * @param argp pairs of void * & size_t for context chunks, terminated by NULL
 */
void
GNUNET_CRYPTO_symmetric_derive_iv_v (struct GNUNET_CRYPTO_SymmetricInitializationVector *iv,
                                     const struct GNUNET_CRYPTO_SymmetricSessionKey *skey,
                                     const void *salt,
                                     size_t salt_len,
                                     va_list argp);


/**
 * @ingroup hash
 * Convert hash to ASCII encoding.
 * @param block the hash code
 * @param result where to store the encoding (struct GNUNET_CRYPTO_HashAsciiEncoded can be
 *  safely cast to char*, a '\\0' termination is set).
 */
void
GNUNET_CRYPTO_hash_to_enc (const struct GNUNET_HashCode * block,
                           struct GNUNET_CRYPTO_HashAsciiEncoded *result);


/**
 * @ingroup hash
 * Convert ASCII encoding back to a 'struct GNUNET_HashCode'
 *
 * @param enc the encoding
 * @param enclen number of characters in @a enc (without 0-terminator, which can be missing)
 * @param result where to store the hash code
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if result has the wrong encoding
 */
int
GNUNET_CRYPTO_hash_from_string2 (const char *enc, size_t enclen,
                                 struct GNUNET_HashCode *result);


/**
 * @ingroup hash
 * Convert ASCII encoding back to `struct GNUNET_HashCode`
 *
 * @param enc the encoding
 * @param result where to store the hash code
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if result has the wrong encoding
 */
#define GNUNET_CRYPTO_hash_from_string(enc, result) \
  GNUNET_CRYPTO_hash_from_string2 (enc, strlen(enc), result)


/**
 * @ingroup hash
 *
 * Compute the distance between 2 hashcodes.  The
 * computation must be fast, not involve @a a[0] or @a a[4] (they're used
 * elsewhere), and be somewhat consistent. And of course, the result
 * should be a positive number.
 *
 * @param a some hash code
 * @param b some hash code
 * @return number between 0 and UINT32_MAX
 */
uint32_t
GNUNET_CRYPTO_hash_distance_u32 (const struct GNUNET_HashCode *a,
                                 const struct GNUNET_HashCode *b);


/**
 * @ingroup hash
 * Compute hash of a given block.
 *
 * @param block the data to hash
 * @param size size of the @a block
 * @param ret pointer to where to write the hashcode
 */
void
GNUNET_CRYPTO_hash (const void *block, size_t size, struct GNUNET_HashCode * ret);


/**
 * @ingroup hash
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
                    struct GNUNET_HashCode * hmac);


/**
 * Function called once the hash computation over the
 * specified file has completed.
 *
 * @param cls closure
 * @param res resulting hash, NULL on error
 */
typedef void (*GNUNET_CRYPTO_HashCompletedCallback) (void *cls,
                                                     const struct GNUNET_HashCode *res);


/**
 * Handle to file hashing operation.
 */
struct GNUNET_CRYPTO_FileHashContext;


/**
 * @ingroup hash
 * Compute the hash of an entire file.
 *
 * @param priority scheduling priority to use
 * @param filename name of file to hash
 * @param blocksize number of bytes to process in one task
 * @param callback function to call upon completion
 * @param callback_cls closure for @a callback
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
 * @ingroup hash
 * Create a random hash code.
 *
 * @param mode desired quality level
 * @param result hash code that is randomized
 */
void
GNUNET_CRYPTO_hash_create_random (enum GNUNET_CRYPTO_Quality mode,
                                  struct GNUNET_HashCode *result);


/**
 * @ingroup hash
 * compute @a result = @a b - @a a
 *
 * @param a some hash code
 * @param b some hash code
 * @param result set to @a b - @a a
 */
void
GNUNET_CRYPTO_hash_difference (const struct GNUNET_HashCode *a,
                               const struct GNUNET_HashCode *b,
                               struct GNUNET_HashCode *result);


/**
 * @ingroup hash
 * compute @a result = @a a + @a delta
 *
 * @param a some hash code
 * @param delta some hash code
 * @param result set to @a a + @a delta
 */
void
GNUNET_CRYPTO_hash_sum (const struct GNUNET_HashCode *a,
                        const struct GNUNET_HashCode *delta,
                        struct GNUNET_HashCode *result);


/**
 * @ingroup hash
 * compute result = a ^ b
 *
 * @param a some hash code
 * @param b some hash code
 * @param result set to @a a ^ @a b
 */
void
GNUNET_CRYPTO_hash_xor (const struct GNUNET_HashCode *a,
                        const struct GNUNET_HashCode *b,
                        struct GNUNET_HashCode *result);


/**
 * @ingroup hash
 * Convert a hashcode into a key.
 *
 * @param hc hash code that serves to generate the key
 * @param skey set to a valid session key
 * @param iv set to a valid initialization vector
 */
void
GNUNET_CRYPTO_hash_to_aes_key (const struct GNUNET_HashCode * hc,
                               struct GNUNET_CRYPTO_SymmetricSessionKey *skey,
                               struct GNUNET_CRYPTO_SymmetricInitializationVector *iv);


/**
 * @ingroup hash
 * Obtain a bit from a hashcode.
 *
 * @param code the `struct GNUNET_HashCode` to index bit-wise
 * @param bit index into the hashcode, [0...159]
 * @return Bit \a bit from hashcode \a code, -1 for invalid index
 */
int
GNUNET_CRYPTO_hash_get_bit (const struct GNUNET_HashCode *code,
			    unsigned int bit);


/**
 * @ingroup hash
 * Determine how many low order bits match in two
 * `struct GNUNET_HashCodes`.  i.e. - 010011 and 011111 share
 * the first two lowest order bits, and therefore the
 * return value is two (NOT XOR distance, nor how many
 * bits match absolutely!).
 *
 * @param first the first hashcode
 * @param second the hashcode to compare first to
 * @return the number of bits that match
 */
unsigned int
GNUNET_CRYPTO_hash_matching_bits (const struct GNUNET_HashCode *first,
                                  const struct GNUNET_HashCode *second);


/**
 * @ingroup hash
 * Compare function for HashCodes, producing a total ordering
 * of all hashcodes.
 *
 * @param h1 some hash code
 * @param h2 some hash code
 * @return 1 if @a h1 > @a h2, -1 if @a h1 < @a h2 and 0 if @a h1 == @a h2.
 */
int
GNUNET_CRYPTO_hash_cmp (const struct GNUNET_HashCode *h1,
                        const struct GNUNET_HashCode *h2);


/**
 * @ingroup hash
 * Find out which of the two GNUNET_CRYPTO_hash codes is closer to target
 * in the XOR metric (Kademlia).
 *
 * @param h1 some hash code
 * @param h2 some hash code
 * @param target some hash code
 * @return -1 if @a h1 is closer, 1 if @a h2 is closer and 0 if @a h1== @a h2.
 */
int
GNUNET_CRYPTO_hash_xorcmp (const struct GNUNET_HashCode *h1,
                           const struct GNUNET_HashCode *h2,
                           const struct GNUNET_HashCode *target);


/**
 * @ingroup hash
 * @brief Derive an authentication key
 * @param key authentication key
 * @param rkey root key
 * @param salt salt
 * @param salt_len size of the salt
 * @param argp pair of void * & size_t for context chunks, terminated by NULL
 */
void
GNUNET_CRYPTO_hmac_derive_key_v (struct GNUNET_CRYPTO_AuthKey *key,
                                 const struct GNUNET_CRYPTO_SymmetricSessionKey *rkey,
                                 const void *salt, size_t salt_len,
                                 va_list argp);


/**
 * @ingroup hash
 * @brief Derive an authentication key
 * @param key authentication key
 * @param rkey root key
 * @param salt salt
 * @param salt_len size of the salt
 * @param ... pair of void * & size_t for context chunks, terminated by NULL
 */
void
GNUNET_CRYPTO_hmac_derive_key (struct GNUNET_CRYPTO_AuthKey *key,
                               const struct GNUNET_CRYPTO_SymmetricSessionKey *rkey,
                               const void *salt, size_t salt_len, ...);


/**
 * @ingroup hash
 * @brief Derive key
 * @param result buffer for the derived key, allocated by caller
 * @param out_len desired length of the derived key
 * @param xtr_algo hash algorithm for the extraction phase, GCRY_MD_...
 * @param prf_algo hash algorithm for the expansion phase, GCRY_MD_...
 * @param xts salt
 * @param xts_len length of @a xts
 * @param skm source key material
 * @param skm_len length of @a skm
 * @param ... pair of void * & size_t for context chunks, terminated by NULL
 * @return #GNUNET_YES on success
 */
int
GNUNET_CRYPTO_hkdf (void *result, size_t out_len, int xtr_algo, int prf_algo,
                    const void *xts, size_t xts_len, const void *skm,
                    size_t skm_len, ...);


/**
 * @ingroup hash
 * @brief Derive key
 * @param result buffer for the derived key, allocated by caller
 * @param out_len desired length of the derived key
 * @param xtr_algo hash algorithm for the extraction phase, GCRY_MD_...
 * @param prf_algo hash algorithm for the expansion phase, GCRY_MD_...
 * @param xts salt
 * @param xts_len length of @a xts
 * @param skm source key material
 * @param skm_len length of @a skm
 * @param argp va_list of void * & size_t pairs for context chunks
 * @return #GNUNET_YES on success
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
 * @param xts_len length of @a xts
 * @param skm source key material
 * @param skm_len length of @a skm
 * @param argp va_list of void * & size_t pairs for context chunks
 * @return #GNUNET_YES on success
 */
int
GNUNET_CRYPTO_kdf_v (void *result, size_t out_len, const void *xts,
                     size_t xts_len, const void *skm, size_t skm_len,
                     va_list argp);


/**
 * @ingroup hash
 * @brief Derive key
 * @param result buffer for the derived key, allocated by caller
 * @param out_len desired length of the derived key
 * @param xts salt
 * @param xts_len length of @a xts
 * @param skm source key material
 * @param skm_len length of @a skm
 * @param ... void * & size_t pairs for context chunks
 * @return #GNUNET_YES on success
 */
int
GNUNET_CRYPTO_kdf (void *result, size_t out_len, const void *xts,
                   size_t xts_len, const void *skm, size_t skm_len, ...);


/**
 * @ingroup crypto
 * Extract the public key for the given private key.
 *
 * @param priv the private key
 * @param pub where to write the public key
 */
void
GNUNET_CRYPTO_ecdsa_key_get_public (const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv,
                                    struct GNUNET_CRYPTO_EcdsaPublicKey *pub);

/**
 * @ingroup crypto
 * Extract the public key for the given private key.
 *
 * @param priv the private key
 * @param pub where to write the public key
 */
void
GNUNET_CRYPTO_eddsa_key_get_public (const struct GNUNET_CRYPTO_EddsaPrivateKey *priv,
                                    struct GNUNET_CRYPTO_EddsaPublicKey *pub);


/**
 * @ingroup crypto
 * Extract the public key for the given private key.
 *
 * @param priv the private key
 * @param pub where to write the public key
 */
void
GNUNET_CRYPTO_ecdhe_key_get_public (const struct GNUNET_CRYPTO_EcdhePrivateKey *priv,
                                    struct GNUNET_CRYPTO_EcdhePublicKey *pub);


/**
 * Convert a public key to a string.
 *
 * @param pub key to convert
 * @return string representing @a pub
 */
char *
GNUNET_CRYPTO_ecdsa_public_key_to_string (const struct GNUNET_CRYPTO_EcdsaPublicKey *pub);


/**
 * Convert a public key to a string.
 *
 * @param pub key to convert
 * @return string representing @a pub
 */
char *
GNUNET_CRYPTO_eddsa_public_key_to_string (const struct GNUNET_CRYPTO_EddsaPublicKey *pub);


/**
 * Convert a string representing a public key to a public key.
 *
 * @param enc encoded public key
 * @param enclen number of bytes in @a enc (without 0-terminator)
 * @param pub where to store the public key
 * @return #GNUNET_OK on success
 */
int
GNUNET_CRYPTO_ecdsa_public_key_from_string (const char *enc,
                                            size_t enclen,
                                            struct GNUNET_CRYPTO_EcdsaPublicKey *pub);


/**
 * Convert a string representing a public key to a public key.
 *
 * @param enc encoded public key
 * @param enclen number of bytes in @a enc (without 0-terminator)
 * @param pub where to store the public key
 * @return #GNUNET_OK on success
 */
int
GNUNET_CRYPTO_eddsa_public_key_from_string (const char *enc,
                                            size_t enclen,
                                            struct GNUNET_CRYPTO_EddsaPublicKey *pub);


/**
 * @ingroup crypto
 * Create a new private key by reading it from a file.  If the
 * files does not exist, create a new key and write it to the
 * file.  Caller must free return value.  Note that this function
 * can not guarantee that another process might not be trying
 * the same operation on the same file at the same time.
 * If the contents of the file
 * are invalid the old file is deleted and a fresh key is
 * created.
 *
 * @param filename name of file to use to store the key
 * @return new private key, NULL on error (for example,
 *   permission denied); free using #GNUNET_free
 */
struct GNUNET_CRYPTO_EcdsaPrivateKey *
GNUNET_CRYPTO_ecdsa_key_create_from_file (const char *filename);


/**
 * @ingroup crypto
 * Create a new private key by reading it from a file.  If the
 * files does not exist, create a new key and write it to the
 * file.  Caller must free return value.  Note that this function
 * can not guarantee that another process might not be trying
 * the same operation on the same file at the same time.
 * If the contents of the file
 * are invalid the old file is deleted and a fresh key is
 * created.
 *
 * @param filename name of file to use to store the key
 * @return new private key, NULL on error (for example,
 *   permission denied); free using #GNUNET_free
 */
struct GNUNET_CRYPTO_EddsaPrivateKey *
GNUNET_CRYPTO_eddsa_key_create_from_file (const char *filename);

struct GNUNET_CONFIGURATION_Handle;


/**
 * @ingroup crypto
 * Create a new private key by reading our peer's key from
 * the file specified in the configuration.
 *
 * @param cfg the configuration to use
 * @return new private key, NULL on error (for example,
 *   permission denied); free using #GNUNET_free
 */
struct GNUNET_CRYPTO_EddsaPrivateKey *
GNUNET_CRYPTO_eddsa_key_create_from_configuration (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * @ingroup crypto
 * Create a new private key. Caller must free return value.
 *
 * @return fresh private key; free using #GNUNET_free
 */
struct GNUNET_CRYPTO_EcdsaPrivateKey *
GNUNET_CRYPTO_ecdsa_key_create (void);


/**
 * @ingroup crypto
 * Create a new private key. Caller must free return value.
 *
 * @return fresh private key; free using #GNUNET_free
 */
struct GNUNET_CRYPTO_EddsaPrivateKey *
GNUNET_CRYPTO_eddsa_key_create (void);


/**
 * @ingroup crypto
 * Create a new private key. Caller must free return value.
 *
 * @return fresh private key; free using #GNUNET_free
 */
struct GNUNET_CRYPTO_EcdhePrivateKey *
GNUNET_CRYPTO_ecdhe_key_create (void);


/**
 * @ingroup crypto
 * Clear memory that was used to store a private key.
 *
 * @param pk location of the key
 */
void
GNUNET_CRYPTO_eddsa_key_clear (struct GNUNET_CRYPTO_EddsaPrivateKey *pk);


/**
 * @ingroup crypto
 * Clear memory that was used to store a private key.
 *
 * @param pk location of the key
 */
void
GNUNET_CRYPTO_ecdsa_key_clear (struct GNUNET_CRYPTO_EcdsaPrivateKey *pk);

/**
 * @ingroup crypto
 * Clear memory that was used to store a private key.
 *
 * @param pk location of the key
 */
void
GNUNET_CRYPTO_ecdhe_key_clear (struct GNUNET_CRYPTO_EcdhePrivateKey *pk);


/**
 * @ingroup crypto
 * Get the shared private key we use for anonymous users.
 *
 * @return "anonymous" private key; do not free
 */
const struct GNUNET_CRYPTO_EcdsaPrivateKey *
GNUNET_CRYPTO_ecdsa_key_get_anonymous (void);


/**
 * @ingroup crypto
 * Setup a hostkey file for a peer given the name of the
 * configuration file (!).  This function is used so that
 * at a later point code can be certain that reading a
 * hostkey is fast (for example in time-dependent testcases).
*
 * @param cfg_name name of the configuration file to use
 */
void
GNUNET_CRYPTO_eddsa_setup_hostkey (const char *cfg_name);


/**
 * @ingroup crypto
 * Retrieve the identity of the host's peer.
 *
 * @param cfg configuration to use
 * @param dst pointer to where to write the peer identity
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the identity
 *         could not be retrieved
 */
int
GNUNET_CRYPTO_get_peer_identity (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                 struct GNUNET_PeerIdentity *dst);


/**
 * Compare two Peer Identities.
 *
 * @param first first peer identity
 * @param second second peer identity
 * @return bigger than 0 if first > second,
 *         0 if they are the same
 *         smaller than 0 if second > first
 */
int
GNUNET_CRYPTO_cmp_peer_identity (const struct GNUNET_PeerIdentity *first,
                                 const struct GNUNET_PeerIdentity *second);


/**
 * @ingroup crypto
 * Derive key material from a public and a private ECC key.
 *
 * @param priv private key to use for the ECDH (x)
 * @param pub public key to use for the ECDH (yG)
 * @param key_material where to write the key material (xyG)
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
int
GNUNET_CRYPTO_ecc_ecdh (const struct GNUNET_CRYPTO_EcdhePrivateKey *priv,
                        const struct GNUNET_CRYPTO_EcdhePublicKey *pub,
                        struct GNUNET_HashCode *key_material);


/**
 * @ingroup crypto
 * EdDSA sign a given block.
 *
 * @param priv private key to use for the signing
 * @param purpose what to sign (size, purpose)
 * @param sig where to write the signature
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
int
GNUNET_CRYPTO_eddsa_sign (const struct GNUNET_CRYPTO_EddsaPrivateKey *priv,
                          const struct GNUNET_CRYPTO_EccSignaturePurpose *purpose,
                          struct GNUNET_CRYPTO_EddsaSignature *sig);


/**
 * @ingroup crypto
 * ECDSA Sign a given block.
 *
 * @param priv private key to use for the signing
 * @param purpose what to sign (size, purpose)
 * @param sig where to write the signature
 * @return #GNUNET_SYSERR on error, #GNUNET_OK on success
 */
int
GNUNET_CRYPTO_ecdsa_sign (const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv,
                          const struct GNUNET_CRYPTO_EccSignaturePurpose *purpose,
                          struct GNUNET_CRYPTO_EcdsaSignature *sig);

/**
 * @ingroup crypto
 * Verify EdDSA signature.
 *
 * @param purpose what is the purpose that the signature should have?
 * @param validate block to validate (size, purpose, data)
 * @param sig signature that is being validated
 * @param pub public key of the signer
 * @returns #GNUNET_OK if ok, #GNUNET_SYSERR if invalid
 */
int
GNUNET_CRYPTO_eddsa_verify (uint32_t purpose,
                            const struct GNUNET_CRYPTO_EccSignaturePurpose *validate,
                            const struct GNUNET_CRYPTO_EddsaSignature *sig,
                            const struct GNUNET_CRYPTO_EddsaPublicKey *pub);



/**
 * @ingroup crypto
 * Verify ECDSA signature.
 *
 * @param purpose what is the purpose that the signature should have?
 * @param validate block to validate (size, purpose, data)
 * @param sig signature that is being validated
 * @param pub public key of the signer
 * @returns #GNUNET_OK if ok, #GNUNET_SYSERR if invalid
 */
int
GNUNET_CRYPTO_ecdsa_verify (uint32_t purpose,
                            const struct GNUNET_CRYPTO_EccSignaturePurpose *validate,
                            const struct GNUNET_CRYPTO_EcdsaSignature *sig,
                            const struct GNUNET_CRYPTO_EcdsaPublicKey *pub);


/**
 * @ingroup crypto
 * Derive a private key from a given private key and a label.
 * Essentially calculates a private key 'h = H(l,P) * d mod n'
 * where n is the size of the ECC group and P is the public
 * key associated with the private key 'd'.
 *
 * @param priv original private key
 * @param label label to use for key deriviation
 * @param context additional context to use for HKDF of 'h';
 *        typically the name of the subsystem/application
 * @return derived private key
 */
struct GNUNET_CRYPTO_EcdsaPrivateKey *
GNUNET_CRYPTO_ecdsa_private_key_derive (const struct GNUNET_CRYPTO_EcdsaPrivateKey *priv,
                                        const char *label,
                                        const char *context);


/**
 * @ingroup crypto
 * Derive a public key from a given public key and a label.
 * Essentially calculates a public key 'V = H(l,P) * P'.
 *
 * @param pub original public key
 * @param label label to use for key deriviation
 * @param context additional context to use for HKDF of 'h'.
 *        typically the name of the subsystem/application
 * @param result where to write the derived public key
 */
void
GNUNET_CRYPTO_ecdsa_public_key_derive (const struct GNUNET_CRYPTO_EcdsaPublicKey *pub,
                                       const char *label,
                                       const char *context,
                                       struct GNUNET_CRYPTO_EcdsaPublicKey *result);


/**
 * Output the given MPI value to the given buffer in network
 * byte order.  The MPI @a val may not be negative.
 *
 * @param buf where to output to
 * @param size number of bytes in @a buf
 * @param val value to write to @a buf
 */
void
GNUNET_CRYPTO_mpi_print_unsigned (void *buf,
                                  size_t size,
                                  gcry_mpi_t val);


/**
 * Convert data buffer into MPI value.
 * The buffer is interpreted as network
 * byte order, unsigned integer.
 *
 * @param result where to store MPI value (allocated)
 * @param data raw data (GCRYMPI_FMT_USG)
 * @param size number of bytes in @a data
 */
void
GNUNET_CRYPTO_mpi_scan_unsigned (gcry_mpi_t *result,
                                 const void *data,
                                 size_t size);


/**
 * Create a freshly generated paillier public key.
 *
 * @param[out] public_key Where to store the public key?
 * @param[out] private_key Where to store the private key?
 */
void
GNUNET_CRYPTO_paillier_create (struct GNUNET_CRYPTO_PaillierPublicKey *public_key,
                               struct GNUNET_CRYPTO_PaillierPrivateKey *private_key);


/**
 * Encrypt a plaintext with a paillier public key.
 *
 * @param public_key Public key to use.
 * @param m Plaintext to encrypt.
 * @param desired_ops How many homomorphic ops the caller intends to use
 * @param[out] ciphertext Encrytion of @a plaintext with @a public_key.
 * @return guaranteed number of supported homomorphic operations >= 1,
 *         or desired_ops, in case that is lower,
 *         or -1 if less than one homomorphic operation is possible
 */
int
GNUNET_CRYPTO_paillier_encrypt (const struct GNUNET_CRYPTO_PaillierPublicKey *public_key,
                                const gcry_mpi_t m,
                                int desired_ops,
                                struct GNUNET_CRYPTO_PaillierCiphertext *ciphertext);


/**
 * Decrypt a paillier ciphertext with a private key.
 *
 * @param private_key Private key to use for decryption.
 * @param public_key Public key to use for decryption.
 * @param ciphertext Ciphertext to decrypt.
 * @param[out] m Decryption of @a ciphertext with @private_key.
 */
void
GNUNET_CRYPTO_paillier_decrypt (const struct GNUNET_CRYPTO_PaillierPrivateKey *private_key,
                                const struct GNUNET_CRYPTO_PaillierPublicKey *public_key,
                                const struct GNUNET_CRYPTO_PaillierCiphertext *ciphertext,
                                gcry_mpi_t m);


/**
 * Compute a ciphertext that represents the sum of the plaintext in @a x1 and @a x2
 *
 * Note that this operation can only be done a finite number of times
 * before an overflow occurs.
 *
 * @param public_key Public key to use for encryption.
 * @param c1 Paillier cipher text.
 * @param c2 Paillier cipher text.
 * @param[out] result Result of the homomorphic operation.
 * @return #GNUNET_OK if the result could be computed,
 *         #GNUNET_SYSERR if no more homomorphic operations are remaining.
 */
int
GNUNET_CRYPTO_paillier_hom_add (const struct GNUNET_CRYPTO_PaillierPublicKey *public_key,
                                const struct GNUNET_CRYPTO_PaillierCiphertext *c1,
                                const struct GNUNET_CRYPTO_PaillierCiphertext *c2,
                                struct GNUNET_CRYPTO_PaillierCiphertext *result);


/**
 * Get the number of remaining supported homomorphic operations.
 *
 * @param c Paillier cipher text.
 * @return the number of remaining homomorphic operations
 */
int
GNUNET_CRYPTO_paillier_hom_get_remaining (const struct GNUNET_CRYPTO_PaillierCiphertext *c);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_CRYPTO_LIB_H */
#endif
/* end of gnunet_crypto_lib.h */
