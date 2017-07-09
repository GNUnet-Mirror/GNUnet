/*
     This file is part of GNUnet.  Copyright (C) 2001-2014 Christian Grothoff
     (and other contributing authors)

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.

*/

/**
 * @file util/crypto_random.c
 * @brief functions to gather random numbers
 * @author Christian Grothoff
 */


#include "platform.h"
#include <glib.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <pbc/pbc.h>
#include <bswabe.h>

#include "gnunet_crypto_lib.h"

struct GNUNET_CRYPTO_AbeMasterKey
{
  GByteArray* pub;

  GByteArray* msk;
};

struct GNUNET_CRYPTO_AbeKey
{
  GByteArray* pub;
  GByteArray* prv;
};

static void
init_aes( element_t k, int enc, AES_KEY* key, unsigned char* iv )
{
  int key_len;
  unsigned char* key_buf;

  key_len = element_length_in_bytes(k) < 17 ? 17 : element_length_in_bytes(k);
  key_buf = (unsigned char*) malloc(key_len);
  element_to_bytes(key_buf, k);

  if( enc )
    AES_set_encrypt_key(key_buf + 1, 128, key);
  else
    AES_set_decrypt_key(key_buf + 1, 128, key);
  free(key_buf);

  memset(iv, 0, 16);
}

static GByteArray*
aes_128_cbc_encrypt( GByteArray* pt, element_t k )
{
  AES_KEY key;
  unsigned char iv[16];
  GByteArray* ct;
  guint8 len[4];
  guint8 zero;

  init_aes(k, 1, &key, iv);

  /* TODO make less crufty */

  /* stuff in real length (big endian) before padding */
  len[0] = (pt->len & 0xff000000)>>24;
  len[1] = (pt->len & 0xff0000)>>16;
  len[2] = (pt->len & 0xff00)>>8;
  len[3] = (pt->len & 0xff)>>0;
  g_byte_array_prepend(pt, len, 4);

  /* pad out to multiple of 128 bit (16 byte) blocks */
  zero = 0;
  while( pt->len % 16 )
    g_byte_array_append(pt, &zero, 1);

  ct = g_byte_array_new();
  g_byte_array_set_size(ct, pt->len);

  AES_cbc_encrypt(pt->data, ct->data, pt->len, &key, iv, AES_ENCRYPT);

  return ct;
}

static GByteArray*
aes_128_cbc_decrypt( GByteArray* ct, element_t k )
{
  AES_KEY key;
  unsigned char iv[16];
  GByteArray* pt;
  unsigned int len;

  init_aes(k, 0, &key, iv);

  pt = g_byte_array_new();
  g_byte_array_set_size(pt, ct->len);

  AES_cbc_encrypt(ct->data, pt->data, ct->len, &key, iv, AES_DECRYPT);

  /* TODO make less crufty */
  
  /* get real length */
  len = 0;
  len = len
    | ((pt->data[0])<<24) | ((pt->data[1])<<16)
    | ((pt->data[2])<<8)  | ((pt->data[3])<<0);
  g_byte_array_remove_index(pt, 0);
  g_byte_array_remove_index(pt, 0);
  g_byte_array_remove_index(pt, 0);
  g_byte_array_remove_index(pt, 0);

  /* truncate any garbage from the padding */
  g_byte_array_set_size(pt, len);

  return pt;
}

struct GNUNET_CRYPTO_AbeMasterKey*
GNUNET_CRYPTO_cpabe_create_master_key (void)
{
  struct GNUNET_CRYPTO_AbeMasterKey* key;
  bswabe_msk_t* msk;
  bswabe_pub_t* pub;
  bswabe_setup(&pub, &msk);
  key = GNUNET_new (struct GNUNET_CRYPTO_AbeMasterKey);
  key->pub = bswabe_pub_serialize(pub);
  key->msk = bswabe_msk_serialize(msk);
  GNUNET_assert (NULL != key->pub);
  GNUNET_assert (NULL != key->msk);
  return key;
}

void
GNUNET_CRYPTO_cpabe_delete_master_key (struct GNUNET_CRYPTO_AbeMasterKey *key)
{
  g_byte_array_unref (key->msk);
  g_byte_array_unref (key->pub);
  GNUNET_free (key);
}

struct GNUNET_CRYPTO_AbeKey*
GNUNET_CRYPTO_cpabe_create_key (struct GNUNET_CRYPTO_AbeMasterKey *key,
                             char **attrs)
{
  struct GNUNET_CRYPTO_AbeKey *prv_key;
  bswabe_pub_t* pub;
  bswabe_msk_t* msk;
  bswabe_prv_t* prv;
  gsize len;

  pub = bswabe_pub_unserialize(key->pub, 0);
  msk = bswabe_msk_unserialize(pub, key->msk, 0);
  prv = bswabe_keygen(pub, msk, attrs);
  prv_key = GNUNET_new (struct GNUNET_CRYPTO_AbeKey);
  prv_key->prv = bswabe_prv_serialize(prv);
  
  len = key->pub->len;
  printf ("Keylen %lu\n", len);
  prv_key->pub = bswabe_pub_serialize (pub);
  GNUNET_assert (NULL != prv_key->prv);
  return prv_key;
}

void
GNUNET_CRYPTO_cpabe_delete_key (struct GNUNET_CRYPTO_AbeKey *key)
{
  g_byte_array_unref (key->prv);
  g_byte_array_unref (key->pub);
  GNUNET_free (key);
}

ssize_t
write_cpabe (void **result, GByteArray* cph_buf,
             uint32_t file_len, GByteArray* aes_buf)
{
  char *ptr;
  uint32_t *len;
  
  *result = GNUNET_malloc (12 + cph_buf->len + aes_buf->len);
  ptr = *result;
  len = (uint32_t*) ptr;
  *len = htonl (file_len);
  ptr += 4;
  len = (uint32_t*) ptr;
  *len = htonl (aes_buf->len);
  ptr += 4;
  memcpy (ptr, aes_buf->data, aes_buf->len);
  ptr += aes_buf->len;
  len = (uint32_t*) ptr;
  *len = htonl (cph_buf->len);
  ptr += 4;
  memcpy (ptr, cph_buf->data, cph_buf->len);
  return 12 + cph_buf->len + aes_buf->len;
}

ssize_t
read_cpabe (const void *data, GByteArray** cph_buf, GByteArray** aes_buf)
{
  int buf_len;
  int tmp_len;
  char *ptr;
  uint32_t *len;

  *cph_buf = g_byte_array_new();
  *aes_buf = g_byte_array_new();
  ptr = (char*)data;
  len = (uint32_t*)ptr;
  buf_len = ntohl (*len);
  ptr += 4;
  len = (uint32_t*)ptr;
  tmp_len = ntohl (*len);
  ptr += 4;
  g_byte_array_set_size(*aes_buf, tmp_len);
  memcpy((*aes_buf)->data, ptr, tmp_len);
  ptr += tmp_len;
  len = (uint32_t*)ptr;
  tmp_len = ntohl (*len);
  ptr += 4;
  g_byte_array_set_size(*cph_buf, tmp_len);
  memcpy((*cph_buf)->data, ptr, tmp_len);

  return buf_len;
}

ssize_t
GNUNET_CRYPTO_cpabe_encrypt (const void *block,
                             size_t size,
                             char *policy,
                             const struct GNUNET_CRYPTO_AbeMasterKey *key,
                             void **result)
{
  bswabe_pub_t* pub;
  bswabe_cph_t* cph;
  GByteArray* plt;
  GByteArray* cph_buf;
  GByteArray* aes_buf;
  guint8 *data;
  element_t m;
  size_t payload_len;
  ssize_t result_len;
  pub = bswabe_pub_unserialize(key->pub, 0);
  if( !(cph = bswabe_enc(pub, m, policy)) )
    return GNUNET_SYSERR;
  cph_buf = bswabe_cph_serialize(cph);
  bswabe_cph_free(cph);
  data = g_memdup (block, size);
  plt = g_byte_array_new_take (data, size);
  payload_len = plt->len;
  aes_buf = aes_128_cbc_encrypt(plt, m);
  g_byte_array_free(plt, 1);
  element_clear(m);
  result_len = write_cpabe(result, cph_buf, payload_len, aes_buf);
  g_byte_array_free(cph_buf, 1);
  g_byte_array_free(aes_buf, 1);
  return result_len;
}

ssize_t
GNUNET_CRYPTO_cpabe_decrypt (const void *block,
                       size_t size,
                       const struct GNUNET_CRYPTO_AbeKey *key,
                       void **result)
{
  bswabe_pub_t* pub;
  bswabe_prv_t* prv;
  GByteArray* aes_buf;
  GByteArray* plt;
  GByteArray* cph_buf;
  bswabe_cph_t* cph;
  element_t m;
  ssize_t pt_size;

  pub = bswabe_pub_unserialize(key->pub, 0);
  prv = bswabe_prv_unserialize(pub, key->prv, 0);
  pt_size = read_cpabe(block, &cph_buf, &aes_buf);
  cph = bswabe_cph_unserialize(pub, cph_buf, 0);
  if( !bswabe_dec(pub, prv, cph, m) ) {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "%s\n", bswabe_error());
    return GNUNET_SYSERR;
  }
  bswabe_cph_free(cph);
  plt = aes_128_cbc_decrypt(aes_buf, m);
  g_byte_array_set_size(plt, size);
  g_byte_array_free(aes_buf, 1);
  *result = GNUNET_malloc (plt->len);
  GNUNET_memcpy (*result, plt->data, plt->len);
  
  return pt_size;
}

ssize_t
GNUNET_CRYPTO_cpabe_serialize_key (const struct GNUNET_CRYPTO_AbeKey *key,
                                   void **result)
{
  ssize_t len;

  len = key->pub->len + key->prv->len + 12;
  write_cpabe (result, key->pub, len, key->prv);

  return len;
}

struct GNUNET_CRYPTO_AbeKey*
GNUNET_CRYPTO_cpabe_deserialize_key (const void *data,
                                     size_t len)
{
  struct GNUNET_CRYPTO_AbeKey *key;

  key = GNUNET_new (struct GNUNET_CRYPTO_AbeKey);
  read_cpabe (data, &key->pub, &key->prv);

  return key;
}

ssize_t
GNUNET_CRYPTO_cpabe_serialize_master_key (const struct GNUNET_CRYPTO_AbeMasterKey *key,
                                          void **result)
{
  ssize_t len;

  len = key->pub->len + key->msk->len + 12;
  write_cpabe (result, key->pub, len, key->msk);

  return len;
}

struct GNUNET_CRYPTO_AbeMasterKey*
GNUNET_CRYPTO_cpabe_deserialize_master_key (const void *data,
                                            size_t len)
{
  struct GNUNET_CRYPTO_AbeMasterKey *key;

  key = GNUNET_new (struct GNUNET_CRYPTO_AbeMasterKey);
  read_cpabe (data, &key->pub, &key->msk);

  return key;
}
