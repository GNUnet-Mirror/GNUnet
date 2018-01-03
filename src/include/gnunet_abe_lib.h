/*
     This file is part of GNUnet.
     Copyright (C) 2001-2018 GNUnet e.V.

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
 * @file include/gnunet_crypto_lib.h
 * @brief cryptographic primitives for GNUnet
 *
 * @author Martin Schanzenbach
 *
 * @defgroup abe  ABE Crypto library: Attribute-Based Encryption operations
 *
 */
#ifndef GNUNET_ABE_LIB_H
#define GNUNET_ABE_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_common.h"
#include <gcrypt.h>

/**
 * @brief type for ABE master keys
 */
struct GNUNET_CRYPTO_AbeMasterKey;

/**
 * @brief type for ABE keys
 */
struct GNUNET_CRYPTO_AbeKey;



/**
 * @ingroup abe
 * Create a new CP-ABE master key. Caller must free return value.
 *
 * @return fresh private key; free using #GNUNET_free
 */
struct GNUNET_ABE_AbeMasterKey *
GNUNET_ABE_cpabe_create_master_key (void);
void
GNUNET_ABE_cpabe_delete_master_key (struct GNUNET_ABE_AbeMasterKey *key);

/**
 * @ingroup abe
 * Create a new CP-ABE key. Caller must free return value.
 *
 * @return fresh private key; free using #GNUNET_free
 */
struct GNUNET_ABE_AbeKey *
GNUNET_ABE_cpabe_create_key (struct GNUNET_ABE_AbeMasterKey *msk,
                                char **attrs);
void
GNUNET_ABE_cpabe_delete_key (struct GNUNET_ABE_AbeKey *key,
                                int delete_pub);


/**
 * @ingroup abe
 * Encrypt a block using  sessionkey.
 *
 * @param block the block to encrypt
 * @param size the size of the @a block
 * @param sessionkey the key used to encrypt
 * @param iv the initialization vector to use, use INITVALUE
 *        for streams.
 * @return the size of the encrypted block, -1 for errors
 */
ssize_t
GNUNET_ABE_cpabe_encrypt (const void *block,
                             size_t size,
                             const char *policy,
                             const struct GNUNET_ABE_AbeMasterKey *key,
                             void **result);

/**
 * @ingroup abe
 * Encrypt a block using  sessionkey.
 *
 * @param block the block to encrypt
 * @param size the size of the @a block
 * @param sessionkey the key used to encrypt
 * @param iv the initialization vector to use, use INITVALUE
 *        for streams.
 * @return the size of the encrypted block, -1 for errors
 */
ssize_t
GNUNET_ABE_cpabe_decrypt (const void *block,
                             size_t size,
                             const struct GNUNET_ABE_AbeKey *key,
                             void **result);

ssize_t
GNUNET_ABE_cpabe_serialize_key (const struct GNUNET_ABE_AbeKey *key,
                                   void **result);

struct GNUNET_ABE_AbeKey*
GNUNET_ABE_cpabe_deserialize_key (const void *data,
                                     size_t len);

ssize_t
GNUNET_ABE_cpabe_serialize_master_key (const struct GNUNET_ABE_AbeMasterKey *key,
                                          void **result);

struct GNUNET_ABE_AbeMasterKey*
GNUNET_ABE_cpabe_deserialize_master_key (const void *data,
                                            size_t len);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_ABE_LIB_H */
#endif
/* end of gnunet_abe_lib.h */
