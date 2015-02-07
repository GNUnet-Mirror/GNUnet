/*
     This file is part of GNUnet.
     Copyright (C) 2001, 2002, 2003, 2004, 2005, 2006, 2013 Christian Grothoff (and other contributing authors)

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
 * @file util/crypto_symmetric.c
 * @brief Symmetric encryption services; combined cipher AES+TWOFISH (256-bit each)
 * @author Christian Grothoff
 * @author Ioana Patrascu
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include <gcrypt.h>

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

/**
 * Create a new SessionKey (for symmetric encryption).
 *
 * @param key session key to initialize
 */
void
GNUNET_CRYPTO_symmetric_create_session_key (struct GNUNET_CRYPTO_SymmetricSessionKey *key)
{
  gcry_randomize (key->aes_key,
                  GNUNET_CRYPTO_AES_KEY_LENGTH,
                  GCRY_STRONG_RANDOM);
  gcry_randomize (key->twofish_key,
                  GNUNET_CRYPTO_AES_KEY_LENGTH,
                  GCRY_STRONG_RANDOM);
}


/**
 * Initialize AES cipher.
 *
 * @param handle handle to initialize
 * @param sessionkey session key to use
 * @param iv initialization vector to use
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
setup_cipher_aes (gcry_cipher_hd_t *handle,
                  const struct GNUNET_CRYPTO_SymmetricSessionKey *sessionkey,
                  const struct GNUNET_CRYPTO_SymmetricInitializationVector *iv)
{
  int rc;

  GNUNET_assert (0 ==
                 gcry_cipher_open (handle, GCRY_CIPHER_AES256,
                                   GCRY_CIPHER_MODE_CFB, 0));
  rc = gcry_cipher_setkey (*handle,
                           sessionkey->aes_key,
                           sizeof (sessionkey->aes_key));
  GNUNET_assert ((0 == rc) || ((char) rc == GPG_ERR_WEAK_KEY));
  rc = gcry_cipher_setiv (*handle,
                          iv->aes_iv,
                          sizeof (iv->aes_iv));
  GNUNET_assert ((0 == rc) || ((char) rc == GPG_ERR_WEAK_KEY));
  return GNUNET_OK;
}


/**
 * Initialize TWOFISH cipher.
 *
 * @param handle handle to initialize
 * @param sessionkey session key to use
 * @param iv initialization vector to use
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
setup_cipher_twofish (gcry_cipher_hd_t *handle,
                      const struct GNUNET_CRYPTO_SymmetricSessionKey *sessionkey,
                      const struct GNUNET_CRYPTO_SymmetricInitializationVector *iv)
{
  int rc;

  GNUNET_assert (0 ==
                 gcry_cipher_open (handle, GCRY_CIPHER_TWOFISH,
                                   GCRY_CIPHER_MODE_CFB, 0));
  rc = gcry_cipher_setkey (*handle,
                           sessionkey->twofish_key,
                           sizeof (sessionkey->twofish_key));
  GNUNET_assert ((0 == rc) || ((char) rc == GPG_ERR_WEAK_KEY));
  rc = gcry_cipher_setiv (*handle,
                          iv->twofish_iv,
                          sizeof (iv->twofish_iv));
  GNUNET_assert ((0 == rc) || ((char) rc == GPG_ERR_WEAK_KEY));
  return GNUNET_OK;
}


/**
 * Encrypt a block with a symmetric session key.
 *
 * @param block the block to encrypt
 * @param size the size of the @a block
 * @param sessionkey the key used to encrypt
 * @param iv the initialization vector to use, use INITVALUE for streams
 * @param result the output parameter in which to store the encrypted result
 *               can be the same or overlap with @c block
 * @returns the size of the encrypted block, -1 for errors.
 *          Due to the use of CFB and therefore an effective stream cipher,
 *          this size should be the same as @c len.
 */
ssize_t
GNUNET_CRYPTO_symmetric_encrypt (const void *block,
                                 size_t size,
                                 const struct GNUNET_CRYPTO_SymmetricSessionKey *sessionkey,
                                 const struct GNUNET_CRYPTO_SymmetricInitializationVector *iv,
                                 void *result)
{
  gcry_cipher_hd_t handle;
  char tmp[size];

  if (GNUNET_OK != setup_cipher_aes (&handle, sessionkey, iv))
    return -1;
  GNUNET_assert (0 == gcry_cipher_encrypt (handle, tmp, size, block, size));
  gcry_cipher_close (handle);
  if (GNUNET_OK != setup_cipher_twofish (&handle, sessionkey, iv))
    return -1;
  GNUNET_assert (0 == gcry_cipher_encrypt (handle, result, size, tmp, size));
  gcry_cipher_close (handle);
  memset (tmp, 0, sizeof (tmp));
  return size;
}


/**
 * Decrypt a given block with the session key.
 *
 * @param block the data to decrypt, encoded as returned by encrypt
 * @param size the size of the @a block to decrypt
 * @param sessionkey the key used to decrypt
 * @param iv the initialization vector to use, use INITVALUE for streams
 * @param result address to store the result at
 *               can be the same or overlap with @c block
 * @return -1 on failure, size of decrypted block on success.
 *         Due to the use of CFB and therefore an effective stream cipher,
 *         this size should be the same as @c size.
 */
ssize_t
GNUNET_CRYPTO_symmetric_decrypt (const void *block, size_t size,
                                 const struct GNUNET_CRYPTO_SymmetricSessionKey *sessionkey,
                                 const struct GNUNET_CRYPTO_SymmetricInitializationVector *iv,
                                 void *result)
{
  gcry_cipher_hd_t handle;
  char tmp[size];

  if (GNUNET_OK != setup_cipher_twofish (&handle, sessionkey, iv))
    return -1;
  GNUNET_assert (0 == gcry_cipher_decrypt (handle, tmp, size, block, size));
  gcry_cipher_close (handle);
  if (GNUNET_OK != setup_cipher_aes (&handle, sessionkey, iv))
    return -1;
  GNUNET_assert (0 == gcry_cipher_decrypt (handle, result, size, tmp, size));
  gcry_cipher_close (handle);
  memset (tmp, 0, sizeof (tmp));
  return size;
}


/**
 * @brief Derive an IV
 *
 * @param iv initialization vector
 * @param skey session key
 * @param salt salt for the derivation
 * @param salt_len size of the @a salt
 * @param ... pairs of void * & size_t for context chunks, terminated by NULL
 */
void
GNUNET_CRYPTO_symmetric_derive_iv (struct GNUNET_CRYPTO_SymmetricInitializationVector *iv,
                             const struct GNUNET_CRYPTO_SymmetricSessionKey *skey,
                             const void *salt, size_t salt_len, ...)
{
  va_list argp;

  va_start (argp, salt_len);
  GNUNET_CRYPTO_symmetric_derive_iv_v (iv, skey, salt, salt_len, argp);
  va_end (argp);
}


/**
 * @brief Derive an IV
 *
 * @param iv initialization vector
 * @param skey session key
 * @param salt salt for the derivation
 * @param salt_len size of the salt
 * @param argp pairs of void * & size_t for context chunks, terminated by NULL
 */
void
GNUNET_CRYPTO_symmetric_derive_iv_v (struct GNUNET_CRYPTO_SymmetricInitializationVector *iv,
                               const struct GNUNET_CRYPTO_SymmetricSessionKey *skey,
                               const void *salt, size_t salt_len, va_list argp)
{
  char aes_salt[salt_len + 4];
  char twofish_salt[salt_len + 4];

  memcpy (aes_salt, salt, salt_len);
  memcpy (&aes_salt[salt_len], "AES!", 4);
  memcpy (twofish_salt, salt, salt_len);
  memcpy (&twofish_salt[salt_len], "FISH", 4);
  GNUNET_CRYPTO_kdf_v (iv->aes_iv, sizeof (iv->aes_iv),
                       aes_salt, salt_len + 4,
                       skey->aes_key, sizeof (skey->aes_key),
                       argp);
  GNUNET_CRYPTO_kdf_v (iv->twofish_iv, sizeof (iv->twofish_iv),
                       twofish_salt, salt_len + 4,
                       skey->twofish_key, sizeof (skey->twofish_key),
                       argp);
}

/* end of crypto_aes.c */
