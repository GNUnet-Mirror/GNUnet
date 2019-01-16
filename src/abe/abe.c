/*
     This file is part of GNUnet.  Copyright (C) 2001-2018 Christian Grothoff
     (and other contributing authors)

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
 * @file abe/abe.c
 * @brief functions for Attribute-Based Encryption
 * @author Martin Schanzenbach
 */


#include "platform.h"
#include <pbc/pbc.h>
#include <gabe.h>

#include "gnunet_crypto_lib.h"
#include "gnunet_abe_lib.h"

struct GNUNET_ABE_AbeMasterKey
{
  gabe_pub_t* pub;
  gabe_msk_t* msk;
};

struct GNUNET_ABE_AbeKey
{
  gabe_pub_t* pub;
  gabe_prv_t* prv;
};

static int
init_aes( element_t k, int enc,
          gcry_cipher_hd_t* handle,
          struct GNUNET_CRYPTO_SymmetricSessionKey *key,
          unsigned char* iv)
{
  int rc;
  int key_len;
  unsigned char* key_buf;

  key_len = element_length_in_bytes(k) < 33 ? 3 : element_length_in_bytes(k);
  key_buf = (unsigned char*) malloc(key_len);
  element_to_bytes(key_buf, k);

  GNUNET_memcpy (key->aes_key, key_buf, GNUNET_CRYPTO_AES_KEY_LENGTH);
  GNUNET_assert (0 ==
                 gcry_cipher_open (handle, GCRY_CIPHER_AES256,
                                   GCRY_CIPHER_MODE_CFB, 0));
  rc = gcry_cipher_setkey (*handle,
                           key->aes_key,
                           sizeof (key->aes_key));
  GNUNET_assert ((0 == rc) || ((char) rc == GPG_ERR_WEAK_KEY));
  memset (iv, 0, 16); //TODO make reasonable
  rc = gcry_cipher_setiv (*handle,
                          iv,
                          16);
  GNUNET_assert ((0 == rc) || ((char) rc == GPG_ERR_WEAK_KEY));

  free(key_buf);
  return rc;
}

static int
aes_128_cbc_encrypt( char* pt,
                     int size,
                     element_t k,
                     char **ct )
{
  gcry_cipher_hd_t handle;
  struct GNUNET_CRYPTO_SymmetricSessionKey skey;
  unsigned char iv[16];
  char* buf;
  int padding;
  int buf_size;
  uint8_t len[4];
  init_aes(k, 1, &handle, &skey, iv);

  /* TODO make less crufty */

  /* stuff in real length (big endian) before padding */
  len[0] = (size & 0xff000000)>>24;
  len[1] = (size & 0xff0000)>>16;
  len[2] = (size & 0xff00)>>8;
  len[3] = (size & 0xff)>>0;
  padding = 16 - ((4+size) % 16);
  buf_size = 4 + size + padding;
  buf = GNUNET_malloc (buf_size);
  GNUNET_memcpy (buf, len, 4);
  GNUNET_memcpy (buf+4, pt, size);
  *ct = GNUNET_malloc (buf_size);

  GNUNET_assert (0 == gcry_cipher_encrypt (handle, *ct, buf_size, buf, buf_size));
  gcry_cipher_close (handle);
  //AES_cbc_encrypt(pt->data, ct->data, pt->len, &key, iv, AES_ENCRYPT);
  GNUNET_free (buf);
  return buf_size;
}

static int
aes_128_cbc_decrypt( char* ct,
                     int size,
                     element_t k,
                     char **pt )
{
  struct GNUNET_CRYPTO_SymmetricSessionKey skey;
  gcry_cipher_hd_t handle;
  unsigned char iv[16];
  char* tmp;
  uint32_t len;

  init_aes(k, 1, &handle, &skey, iv);

  tmp = GNUNET_malloc (size);

  //AES_cbc_encrypt(ct->data, pt->data, ct->len, &key, iv, AES_DECRYPT);
  GNUNET_assert (0 == gcry_cipher_decrypt (handle, tmp, size, ct, size));
  gcry_cipher_close (handle);
  /* TODO make less crufty */

  /* get real length */
  len = 0;
  len = len
    | ((tmp[0])<<24) | ((tmp[1])<<16)
    | ((tmp[2])<<8)  | ((tmp[3])<<0);
  /* truncate any garbage from the padding */
  *pt = GNUNET_malloc (len);
  GNUNET_memcpy (*pt, tmp+4, len);
  GNUNET_free (tmp);
  return len;
}

/**
 * @ingroup abe
 * Create a new CP-ABE master key. Caller must free return value.
 *
 * @return fresh private key; free using #GNUNET_ABE_cpabe_delete_master_key
 */
struct GNUNET_ABE_AbeMasterKey*
GNUNET_ABE_cpabe_create_master_key (void)
{
  struct GNUNET_ABE_AbeMasterKey* key;
  key = GNUNET_new (struct GNUNET_ABE_AbeMasterKey);
  gabe_setup(&key->pub, &key->msk);
  GNUNET_assert (NULL != key->pub);
  GNUNET_assert (NULL != key->msk);
  return key;
}

/**
 * @ingroup abe
 * Delete a CP-ABE master key.
 *
 * @param key the master key
 * @return fresh private key; free using #GNUNET_free
 */
void
GNUNET_ABE_cpabe_delete_master_key (struct GNUNET_ABE_AbeMasterKey *key)
{
  gabe_msk_free (key->msk);
  gabe_pub_free (key->pub);
  //GNUNET_free (key->msk);
  //gabe_msk_free (key->msk); //For some reason free of pub implicit?
  GNUNET_free (key);
}

/**
 * @ingroup abe
 * Create a new CP-ABE key. Caller must free return value.
 *
 * @param key the master key
 * @param attrs the attributes to append to the key
 * @return fresh private key; free using #GNUNET_ABE_cpabe_delete_key
 */
struct GNUNET_ABE_AbeKey*
GNUNET_ABE_cpabe_create_key (struct GNUNET_ABE_AbeMasterKey *key,
                             char **attrs)
{
  struct GNUNET_ABE_AbeKey *prv_key;
  int size;
  char *tmp;

  prv_key = GNUNET_new (struct GNUNET_ABE_AbeKey);
  prv_key->prv = gabe_keygen(key->pub, key->msk, attrs);
  size = gabe_pub_serialize(key->pub, &tmp);
  prv_key->pub = gabe_pub_unserialize(tmp, size);
  GNUNET_free (tmp);
  GNUNET_assert (NULL != prv_key->prv);
  return prv_key;
}

/**
 * @ingroup abe
 * Delete a CP-ABE key.
 *
 * @param key the key to delete
 * @param delete_pub GNUNE_YES if the public key should also be freed (bug in gabe)
 * @return fresh private key; free using #GNUNET_free
 */
void
GNUNET_ABE_cpabe_delete_key (struct GNUNET_ABE_AbeKey *key,
                                int delete_pub)
{
  //Memory management in gabe is buggy
  gabe_prv_free (key->prv);
  if (GNUNET_YES == delete_pub)
    gabe_pub_free (key->pub);
  GNUNET_free (key);
}

static ssize_t
write_cpabe (void **result,
             uint32_t file_len,
             char* cph_buf,
             int cph_buf_len,
             char* aes_buf,
             int aes_buf_len)
{
  char *ptr;
  uint32_t *len;

  *result = GNUNET_malloc (12 + cph_buf_len + aes_buf_len);
  ptr = *result;
  len = (uint32_t*) ptr;
  *len = htonl (file_len);
  ptr += 4;
  len = (uint32_t*) ptr;
  *len = htonl (aes_buf_len);
  ptr += 4;
  GNUNET_memcpy (ptr, aes_buf, aes_buf_len);
  ptr += aes_buf_len;
  len = (uint32_t*) ptr;
  *len = htonl (cph_buf_len);
  ptr += 4;
  GNUNET_memcpy (ptr, cph_buf, cph_buf_len);
  return 12 + cph_buf_len + aes_buf_len;
}

static ssize_t
read_cpabe (const void *data,
            char** cph_buf,
            int *cph_buf_len,
            char** aes_buf,
            int *aes_buf_len)
{
  int buf_len;
  char *ptr;
  uint32_t *len;

  ptr = (char*)data;
  len = (uint32_t*)ptr;
  buf_len = ntohl (*len);
  ptr += 4;
  len = (uint32_t*)ptr;
  *aes_buf_len = ntohl (*len);
  ptr += 4;
  *aes_buf = GNUNET_malloc (*aes_buf_len);
  GNUNET_memcpy(*aes_buf, ptr, *aes_buf_len);
  ptr += *aes_buf_len;
  len = (uint32_t*)ptr;
  *cph_buf_len = ntohl (*len);
  ptr += 4;
  *cph_buf = GNUNET_malloc (*cph_buf_len);
  GNUNET_memcpy(*cph_buf, ptr, *cph_buf_len);

  return buf_len;
}

/**
 * @ingroup abe
 * Encrypt a block using  sessionkey.
 *
 * @param block the block to encrypt
 * @param size the size of the @a block
 * @param policy the ABE policy
 * @param key the key used to encrypt
 * @param result the result buffer. Will be allocated. Free using #GNUNET_free
 * @return the size of the encrypted block, -1 for errors
 */
ssize_t
GNUNET_ABE_cpabe_encrypt (const void *block,
                             size_t size,
                             const char *policy,
                             const struct GNUNET_ABE_AbeMasterKey *key,
                             void **result)
{
  gabe_cph_t* cph;
  char* plt;
  char* cph_buf;
  char* aes_buf;
  element_t m;
  int cph_buf_len;
  int aes_buf_len;
  ssize_t result_len;

  if( !(cph = gabe_enc(key->pub, m, (char*)policy)) )
    return GNUNET_SYSERR;
  cph_buf_len = gabe_cph_serialize(cph,
                                &cph_buf);
  gabe_cph_free(cph);
  GNUNET_free (cph);
  plt = GNUNET_memdup (block, size);
  aes_buf_len = aes_128_cbc_encrypt(plt, size, m, &aes_buf);
  GNUNET_free (plt);
  element_clear(m);
  result_len = write_cpabe(result, size, cph_buf, cph_buf_len, aes_buf, aes_buf_len);
  GNUNET_free(cph_buf);
  GNUNET_free(aes_buf);
  return result_len;
}

/**
 * @ingroup abe
 * Decrypt a block using the ABE key.
 *
 * @param block the block to encrypt
 * @param size the size of the @a block
 * @param key the key used to decrypt
 * @param result the result buffer. Will be allocated. Free using #GNUNET_free
 * @return the size of the encrypted block, -1 for errors
 */
ssize_t
GNUNET_ABE_cpabe_decrypt (const void *block,
                             size_t size,
                             const struct GNUNET_ABE_AbeKey *key,
                             void **result)
{
  char* aes_buf;
  char* cph_buf;
  gabe_cph_t* cph;
  element_t m;
  int cph_buf_size;
  int aes_buf_size;
  int plt_len;

  read_cpabe(block, &cph_buf, &cph_buf_size, &aes_buf, &aes_buf_size);
  cph = gabe_cph_unserialize(key->pub, cph_buf, cph_buf_size);
  if( !gabe_dec(key->pub, key->prv, cph, m) ) {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s\n", gabe_error());
    GNUNET_free (aes_buf);
    GNUNET_free (cph_buf);
    gabe_cph_free(cph);
    GNUNET_free (cph);
    element_clear (m);
    return GNUNET_SYSERR;
  }
  gabe_cph_free(cph);
  GNUNET_free (cph);
  plt_len = aes_128_cbc_decrypt(aes_buf, aes_buf_size, m, (char**)result);
  GNUNET_free (cph_buf);
  GNUNET_free (aes_buf);
  element_clear (m);
  //freeing is buggy in gabe
  //gabe_prv_free (prv);
  //gabe_pub_free (pub);
  return plt_len;
}

/**
 * @ingroup abe
 * Serialize an ABE key.
 *
 * @param key the key to serialize
 * @param result the result buffer. Will be allocated. Free using #GNUNET_free
 * @return the size of the encrypted block, -1 for errors
 */
ssize_t
GNUNET_ABE_cpabe_serialize_key (const struct GNUNET_ABE_AbeKey *key,
                                   void **result)
{
  ssize_t len;
  char *pub;
  char *prv;
  int pub_len;
  int prv_len;

  pub_len = gabe_pub_serialize (key->pub, &pub);
  prv_len = gabe_prv_serialize (key->prv, &prv);

  len = pub_len + prv_len + 12;
  write_cpabe (result, len, pub, pub_len, prv, prv_len);

  GNUNET_free (pub);
  GNUNET_free (prv);

  return len;
}

/**
 * @ingroup abe
 * Deserialize a serialized ABE key.
 *
 * @param data the data to deserialize
 * @param len the length of the data.
 * @return the ABE key. NULL of unsuccessful
 */
struct GNUNET_ABE_AbeKey*
GNUNET_ABE_cpabe_deserialize_key (const void *data,
                                     size_t len)
{
  struct GNUNET_ABE_AbeKey *key;
  char *pub;
  char *prv;
  int prv_len;
  int pub_len;

  key = GNUNET_new (struct GNUNET_ABE_AbeKey);
  read_cpabe (data,
              &pub,
              &pub_len,
              &prv,
              &prv_len);
  key->pub = gabe_pub_unserialize (pub, pub_len);
  key->prv = gabe_prv_unserialize (key->pub, prv, prv_len);

  GNUNET_free (pub);
  GNUNET_free (prv);
  return key;
}

/**
 * @ingroup abe
 * Serialize an ABE master key.
 *
 * @param key the key to serialize
 * @param result the result buffer. Will be allocated. Free using #GNUNET_free
 * @return the size of the encrypted block, -1 for errors
 */
ssize_t
GNUNET_ABE_cpabe_serialize_master_key (const struct GNUNET_ABE_AbeMasterKey *key,
                                          void **result)
{
  ssize_t len;
  char *pub;
  char *msk;
  int pub_len;
  int msk_len;

  pub_len = gabe_pub_serialize (key->pub, &pub);
  msk_len = gabe_msk_serialize (key->msk, &msk);

  len = pub_len + msk_len + 12;
  write_cpabe (result, len, pub, pub_len, msk, msk_len);

  GNUNET_free (pub);
  GNUNET_free (msk);

  return len;
}

/**
 * @ingroup abe
 * Deserialize an ABE master key.
 *
 * @param data the data to deserialize
 * @param len the length of the data.
 * @return the ABE key. NULL of unsuccessful
 */
struct GNUNET_ABE_AbeMasterKey*
GNUNET_ABE_cpabe_deserialize_master_key (const void *data,
                                            size_t len)
{
  struct GNUNET_ABE_AbeMasterKey *key;
  char *msk;
  char *pub;
  int msk_len;
  int pub_len;

  key = GNUNET_new (struct GNUNET_ABE_AbeMasterKey);
  read_cpabe (data,
              &pub,
              &pub_len,
              &msk,
              &msk_len);
  key->pub = gabe_pub_unserialize (pub, pub_len);
  key->msk = gabe_msk_unserialize (key->pub, msk, msk_len);

  GNUNET_free (pub);
  GNUNET_free (msk);

  return key;
}
