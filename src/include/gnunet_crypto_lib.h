/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007 Christian Grothoff (and other contributing authors)

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


enum GNUNET_CRYPTO_Quality
{
  GNUNET_CRYPTO_QUALITY_WEAK,
  GNUNET_CRYPTO_QUALITY_STRONG
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
 * Length of an RSA KEY (d,e,len), 2048 bit (=256 octests) key d, 2 byte e
 */
#define GNUNET_CRYPTO_RSA_KEY_LENGTH 258


/**
 * The private information of an RSA key pair.
 */
struct GNUNET_CRYPTO_RsaPrivateKey;


/**
 * @brief 0-terminated ASCII encoding of a GNUNET_HashCode.
 */
struct GNUNET_CRYPTO_HashAsciiEncoded
{
  unsigned char encoding[104];
};



/**
 * @brief an RSA signature
 */
struct GNUNET_CRYPTO_RsaSignature
{
  unsigned char sig[GNUNET_CRYPTO_RSA_DATA_ENCODING_LENGTH];
};


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
 * @brief type for session keys
 */
struct GNUNET_CRYPTO_AesSessionKey
{
  /**
   * Actual key.
   */
  unsigned char key[GNUNET_CRYPTO_AES_KEY_LENGTH];

  /**
   * checksum!
   */
  uint32_t crc32 GNUNET_PACKED;
};


/**
 * @brief IV for sym cipher
 *
 * NOTE: must be smaller (!) in size than the
 * GNUNET_HashCode.
 */
struct GNUNET_CRYPTO_AesInitializationVector
{
  unsigned char iv[GNUNET_CRYPTO_AES_KEY_LENGTH / 2];
};


/* **************** Functions and Macros ************* */


/**
 * Compute the CRC32 checksum for the first len
 * bytes of the buffer.
 *
 * @param buf the data over which we're taking the CRC
 * @param len the length of the buffer in bytes
 * @return the resulting CRC32 checksum
 */
int GNUNET_CRYPTO_crc32_n (const void *buf, unsigned int len);


/**
 * Produce a random value.
 *
 * @param i the upper limit (exclusive) for the random number
 * @return a random value in the interval [0,i[.
 */
unsigned int GNUNET_CRYPTO_random_u32 (enum GNUNET_CRYPTO_Quality,
                                       unsigned int i);


/**
 * Random on unsigned 64-bit values.  We break them down into signed
 * 32-bit values and reassemble the 64-bit random value bit-wise.
 */
unsigned long long GNUNET_CRYPTO_random_u64 (enum GNUNET_CRYPTO_Quality mode,
                                             unsigned long long u);


/**
 * Get an array with a random permutation of the
 * numbers 0...n-1.
 * @param mode GNUNET_CRYPTO_QUALITY_STRONG if the strong (but expensive) PRNG should be used, GNUNET_CRYPTO_QUALITY_WEAK otherwise
 * @param n the size of the array
 * @return the permutation array (allocated from heap)
 */
unsigned int *GNUNET_CRYPTO_random_permute (enum GNUNET_CRYPTO_Quality mode,
                                            unsigned int n);


/**
 * Create a new Session key.
 */
void GNUNET_CRYPTO_aes_create_session_key (struct GNUNET_CRYPTO_AesSessionKey
                                           *key);


/**
 * Check that a new session key is well-formed.
 *
 * @return GNUNET_OK if the key is valid
 */
int GNUNET_CRYPTO_aes_check_session_key (const struct
                                         GNUNET_CRYPTO_AesSessionKey *key);


/**
 * Encrypt a block with the public key of another
 * host that uses the same cyper.
 *
 * @param block the block to encrypt
 * @param len the size of the block
 * @param sessionkey the key used to encrypt
 * @param iv the initialization vector to use, use INITVALUE
 *        for streams.
 * @returns the size of the encrypted block, -1 for errors
 */
int GNUNET_CRYPTO_aes_encrypt (const void *block,
                               uint16_t len,
                               const struct GNUNET_CRYPTO_AesSessionKey
                               *sessionkey,
                               const struct
                               GNUNET_CRYPTO_AesInitializationVector *iv,
                               void *result);


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
int GNUNET_CRYPTO_aes_decrypt (const void *block, uint16_t size,
                               const struct GNUNET_CRYPTO_AesSessionKey *sessionkey, 
                               const struct GNUNET_CRYPTO_AesInitializationVector *iv,
                               void *result);


/**
 * Convert GNUNET_CRYPTO_hash to ASCII encoding.
 * @param block the GNUNET_CRYPTO_hash code
 * @param result where to store the encoding (struct GNUNET_CRYPTO_HashAsciiEncoded can be
 *  safely cast to char*, a '\0' termination is set).
 */
void GNUNET_CRYPTO_hash_to_enc (const GNUNET_HashCode * block,
                                struct GNUNET_CRYPTO_HashAsciiEncoded
                                *result);


/**
 * Convert ASCII encoding back to GNUNET_CRYPTO_hash
 * @param enc the encoding
 * @param result where to store the GNUNET_CRYPTO_hash code
 * @return GNUNET_OK on success, GNUNET_SYSERR if result has the wrong encoding
 */
int GNUNET_CRYPTO_hash_from_string (const char *enc,
                                    GNUNET_HashCode * result);


/**
 * Compute the distance between 2 hashcodes.
 * The computation must be fast, not involve
 * a.a or a.e (they're used elsewhere), and
 * be somewhat consistent. And of course, the
 * result should be a positive number.
 * @return number between 0 and 65536
 */
unsigned int GNUNET_CRYPTO_hash_distance_u32 (const GNUNET_HashCode * a,
                                              const GNUNET_HashCode * b);


/**
 * Hash block of given size.
 * @param block the data to GNUNET_CRYPTO_hash, length is given as a second argument
 * @param ret pointer to where to write the hashcode
 */
void GNUNET_CRYPTO_hash (const void *block, unsigned int size,
                         GNUNET_HashCode * ret);


/**
 * Function called once the hash computation over the
 * specified file has completed.
 *
 * @param cls closure
 * @param res resulting hash, NULL on error
 */
typedef void (*GNUNET_CRYPTO_HashCompletedCallback) (void *cls,
                                                     const GNUNET_HashCode *
                                                     res);


/**
 * Compute the hash of an entire file.
 *
 * @param sched scheduler to use
 * @param priority scheduling priority to use
 * @param run_on_shutdown should we complete even on shutdown?
 * @param filename name of file to hash
 * @param blocksize number of bytes to process in one task
 * @param callback function to call upon completion
 * @param callback_cls closure for callback
 */
void GNUNET_CRYPTO_hash_file (struct GNUNET_SCHEDULER_Handle *sched,
                              enum GNUNET_SCHEDULER_Priority priority,
                              int run_on_shutdown,
                              const char *filename,
                              size_t blocksize,
                              GNUNET_CRYPTO_HashCompletedCallback callback,
                              void *callback_cls);


/**
 * Create a random hash code.
 */
void GNUNET_CRYPTO_hash_create_random (GNUNET_HashCode * result);


/**
 * compute result(delta) = b - a
 */
void GNUNET_CRYPTO_hash_difference (const GNUNET_HashCode * a,
                                    const GNUNET_HashCode * b,
                                    GNUNET_HashCode * result);


/**
 * compute result(b) = a + delta
 */
void GNUNET_CRYPTO_hash_sum (const GNUNET_HashCode * a,
                             const GNUNET_HashCode * delta,
                             GNUNET_HashCode * result);


/**
 * compute result = a ^ b
 */
void GNUNET_CRYPTO_hash_xor (const GNUNET_HashCode * a,
                             const GNUNET_HashCode * b,
                             GNUNET_HashCode * result);


/**
 * Convert a hashcode into a key.
 */
void GNUNET_CRYPTO_hash_to_aes_key (const GNUNET_HashCode * hc,
                                    struct GNUNET_CRYPTO_AesSessionKey *skey,
                                    struct
                                    GNUNET_CRYPTO_AesInitializationVector
                                    *iv);


/**
 * Obtain a bit from a hashcode.
 * @param code the GNUNET_CRYPTO_hash to index bit-wise
 * @param bit index into the hashcode, [0...159]
 * @return Bit \a bit from hashcode \a code, -1 for invalid index
 */
int GNUNET_CRYPTO_hash_get_bit (const GNUNET_HashCode * code,
                                unsigned int bit);


/**
 * Compare function for HashCodes, producing a total ordering
 * of all hashcodes.
 * @return 1 if h1 > h2, -1 if h1 < h2 and 0 if h1 == h2.
 */
int GNUNET_CRYPTO_hash_cmp (const GNUNET_HashCode * h1,
                            const GNUNET_HashCode * h2);


/**
 * Find out which of the two GNUNET_CRYPTO_hash codes is closer to target
 * in the XOR metric (Kademlia).
 * @return -1 if h1 is closer, 1 if h2 is closer and 0 if h1==h2.
 */
int GNUNET_CRYPTO_hash_xorcmp (const GNUNET_HashCode * h1,
                               const GNUNET_HashCode * h2,
                               const GNUNET_HashCode * target);


/**
 * Create a new private key. Caller must free return value.
 */
struct GNUNET_CRYPTO_RsaPrivateKey *GNUNET_CRYPTO_rsa_key_create (void);


/**
 * Create a new private key by reading it from a file.  If the
 * files does not exist, create a new key and write it to the
 * file.  Caller must free return value. Note that this function
 * can not guarantee that another process might not be trying
 * the same operation on the same file at the same time.  The
 * caller must somehow know that the file either already exists
 * with a valid key OR be sure that no other process is calling
 * this function at the same time.  If the contents of the file
 * are invalid the old file is deleted and a fresh key is
 * created.
 *
 * @return new private key, NULL on error (for example,
 *   permission denied)
 */
struct GNUNET_CRYPTO_RsaPrivateKey
  *GNUNET_CRYPTO_rsa_key_create_from_file (const char *filename);


/**
 * Deterministically (!) create a private key using only the
 * given HashCode as input to the PRNG.
 */
struct GNUNET_CRYPTO_RsaPrivateKey
  *GNUNET_CRYPTO_rsa_key_create_from_hash (const GNUNET_HashCode * input);


/**
 * Free memory occupied by the private key.
 * @param hostkey pointer to the memory to free
 */
void GNUNET_CRYPTO_rsa_key_free (struct GNUNET_CRYPTO_RsaPrivateKey *hostkey);


/**
 * Extract the public key of the host.
 * @param result where to write the result.
 */
void GNUNET_CRYPTO_rsa_key_get_public (const struct
                                       GNUNET_CRYPTO_RsaPrivateKey *hostkey,
                                       struct
                                       GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded
                                       *result);


/**
 * Encrypt a block with the public key of another host that uses the
 * same cyper.
 *
 * @param block the block to encrypt
 * @param size the size of block
 * @param publicKey the encoded public key used to encrypt
 * @param target where to store the encrypted block
 * @returns GNUNET_SYSERR on error, GNUNET_OK if ok
 */
int GNUNET_CRYPTO_rsa_encrypt (const void *block,
                               uint16_t size,
                               const struct
                               GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded
                               *publicKey,
                               struct GNUNET_CRYPTO_RsaEncryptedData *target);


/**
 * Decrypt a given block with the hostkey.
 *
 * @param key the key to use
 * @param block the data to decrypt, encoded as returned by encrypt, not consumed
 * @param result pointer to a location where the result can be stored
 * @param size how many bytes of a result are expected? Must be exact.
 * @returns the size of the decrypted block (that is, size) or -1 on error
 */
int GNUNET_CRYPTO_rsa_decrypt (const struct GNUNET_CRYPTO_RsaPrivateKey *key,
                               const struct GNUNET_CRYPTO_RsaEncryptedData
                               *block, void *result, uint16_t size);


/**
 * Sign a given block.
 *
 * @param key private key to use for the signing
 * @param purpose what to sign (size, purpose)
 * @param result where to write the signature
 * @return GNUNET_SYSERR on error, GNUNET_OK on success
 */
int GNUNET_CRYPTO_rsa_sign (const struct GNUNET_CRYPTO_RsaPrivateKey *key,
                            const struct GNUNET_CRYPTO_RsaSignaturePurpose
                            *purpose,
                            struct GNUNET_CRYPTO_RsaSignature *result);


/**
 * Verify signature.  Note that the caller MUST have already
 * checked that "validate->size" bytes are actually available.
 *
 * @param purpose what is the purpose that validate should have?
 * @param validate block to validate (size, purpose, data)
 * @param sig signature that is being validated
 * @param publicKey public key of the signer
 * @returns GNUNET_OK if ok, GNUNET_SYSERR if invalid
 */
int GNUNET_CRYPTO_rsa_verify (uint32_t purpose,
                              const struct GNUNET_CRYPTO_RsaSignaturePurpose
                              *validate,
                              const struct GNUNET_CRYPTO_RsaSignature *sig,
                              const struct
                              GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded
                              *publicKey);



/**
 * This function should only be called in testcases
 * where strong entropy gathering is not desired
 * (for example, for hostkey generation).
 */
void GNUNET_CRYPTO_random_disable_entropy_gathering (void);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_CRYPTO_LIB_H */
#endif
/* end of gnunet_crypto_lib.h */
