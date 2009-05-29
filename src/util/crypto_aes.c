/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @file util/crypto_aes.c
 * @brief Symmetric encryption services.
 * @author Christian Grothoff
 * @author Ioana Patrascu
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_crypto_lib.h"
#include <gcrypt.h>

/**
 * Create a new SessionKey (for AES-256).
 */
void
GNUNET_CRYPTO_aes_create_session_key (struct GNUNET_CRYPTO_AesSessionKey *key)
{
  gcry_randomize (&key->key[0], GNUNET_CRYPTO_AES_KEY_LENGTH,
                  GCRY_STRONG_RANDOM);
  key->crc32 =
    htonl (GNUNET_CRYPTO_crc32_n (key, GNUNET_CRYPTO_AES_KEY_LENGTH));
}

/**
 * Check that a new session key is well-formed.
 *
 * @return GNUNET_OK if the key is valid
 */
int
GNUNET_CRYPTO_aes_check_session_key (const struct GNUNET_CRYPTO_AesSessionKey
                                     *key)
{
  uint32_t crc;

  crc = GNUNET_CRYPTO_crc32_n (key, GNUNET_CRYPTO_AES_KEY_LENGTH);
  if (ntohl (key->crc32) == crc)
    return GNUNET_OK;
  GNUNET_break (0);
  return GNUNET_SYSERR;
}


/**
 * Encrypt a block with the public key of another
 * host that uses the same cyper.
 * @param block the block to encrypt
 * @param len the size of the block
 * @param sessionkey the key used to encrypt
 * @param iv the initialization vector to use, use INITVALUE
 *        for streams.
 * @param result the output parameter in which to store the encrypted result
 * @returns the size of the encrypted block, -1 for errors
 */
int
GNUNET_CRYPTO_aes_encrypt (const void *block,
                           uint16_t len,
                           const struct GNUNET_CRYPTO_AesSessionKey
                           *sessionkey,
                           const struct GNUNET_CRYPTO_AesInitializationVector
                           *iv, void *result)
{
  gcry_cipher_hd_t handle;
  int rc;

  if (sessionkey->crc32 !=
      htonl (GNUNET_CRYPTO_crc32_n
             (sessionkey, GNUNET_CRYPTO_AES_KEY_LENGTH)))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
  GNUNET_assert (0 == gcry_cipher_open (&handle,
                                        GCRY_CIPHER_AES256,
                                        GCRY_CIPHER_MODE_CFB, 0));
  rc = gcry_cipher_setkey (handle, sessionkey, GNUNET_CRYPTO_AES_KEY_LENGTH);
  GNUNET_assert ((0 == rc) || ((char) rc == GPG_ERR_WEAK_KEY));
  rc =
    gcry_cipher_setiv (handle, iv,
                       sizeof (struct GNUNET_CRYPTO_AesInitializationVector));
  GNUNET_assert ((0 == rc) || ((char) rc == GPG_ERR_WEAK_KEY));
  GNUNET_assert (0 == gcry_cipher_encrypt (handle, result, len, block, len));
  gcry_cipher_close (handle);
  return len;
}

/**
 * Decrypt a given block with the sessionkey.
 * @param sessionkey the key used to decrypt
 * @param block the data to decrypt, encoded as returned by encrypt
 * @param size the size of the block to decrypt
 * @param iv the initialization vector to use, use INITVALUE
 *        for streams.
 * @param result address to store the result at
 * @return -1 on failure, size of decrypted block on success
 */
int
GNUNET_CRYPTO_aes_decrypt (const struct GNUNET_CRYPTO_AesSessionKey
                           *sessionkey, const void *block, uint16_t size,
                           const struct GNUNET_CRYPTO_AesInitializationVector
                           *iv, void *result)
{
  gcry_cipher_hd_t handle;
  int rc;

  if (sessionkey->crc32 !=
      htonl (GNUNET_CRYPTO_crc32_n
             (sessionkey, GNUNET_CRYPTO_AES_KEY_LENGTH)))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
  GNUNET_assert (0 == gcry_cipher_open (&handle,
                                        GCRY_CIPHER_AES256,
                                        GCRY_CIPHER_MODE_CFB, 0));
  rc = gcry_cipher_setkey (handle, sessionkey, GNUNET_CRYPTO_AES_KEY_LENGTH);
  GNUNET_assert ((0 == rc) || ((char) rc == GPG_ERR_WEAK_KEY));
  rc =
    gcry_cipher_setiv (handle, iv,
                       sizeof (struct GNUNET_CRYPTO_AesInitializationVector));
  GNUNET_assert ((0 == rc) || ((char) rc == GPG_ERR_WEAK_KEY));
  GNUNET_assert (0 ==
                 gcry_cipher_decrypt (handle, result, size, block, size));
  gcry_cipher_close (handle);
  return size;
}

/* end of crypto_aes.c */
