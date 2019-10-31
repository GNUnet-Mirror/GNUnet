/*
     This file is part of GNUnet.
     Copyright (C) 2001-2018 GNUnet e.V.

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
 * @file include/gnunet_abe_lib.h
 * @brief Attribute-Based Encryption primitives for GNUnet
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
 * @return fresh private key; free using #GNUNET_ABE_cpabe_delete_master_key
 */
struct GNUNET_ABE_AbeMasterKey *
GNUNET_ABE_cpabe_create_master_key (void);

/**
 * @ingroup abe
 * Delete a CP-ABE master key.
 *
 * @param key the master key
 * @return fresh private key; free using #GNUNET_free
 */
void
GNUNET_ABE_cpabe_delete_master_key (struct GNUNET_ABE_AbeMasterKey *key);

/**
 * @ingroup abe
 * Create a new CP-ABE key. Caller must free return value.
 *
 * @param key the master key
 * @param attrs the attributes to append to the key
 * @return fresh private key; free using #GNUNET_ABE_cpabe_delete_key
 */
struct GNUNET_ABE_AbeKey *
GNUNET_ABE_cpabe_create_key (struct GNUNET_ABE_AbeMasterKey *key,
                             char **attrs);

/**
 * @ingroup abe
 * Delete a CP-ABE key.
 *
 * @param key the key to delete
 * @param delete_pub GNUNET_YES if the public key should also be freed (bug in gabe)
 * @return fresh private key; free using #GNUNET_free
 */
void
GNUNET_ABE_cpabe_delete_key (struct GNUNET_ABE_AbeKey *key,
                             int delete_pub);


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
                          void **result);

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
                          void **result);

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
                                void **result);

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
                                  size_t len);

/**
 * @ingroup abe
 * Serialize an ABE master key.
 *
 * @param key the key to serialize
 * @param result the result buffer. Will be allocated. Free using #GNUNET_free
 * @return the size of the encrypted block, -1 for errors
 */
ssize_t
GNUNET_ABE_cpabe_serialize_master_key (const struct
                                       GNUNET_ABE_AbeMasterKey *key,
                                       void **result);

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
