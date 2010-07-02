/*
     This file is part of GNUnet.
     (C) 2010 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_block_lib.h
 * @brief library for data block manipulation
 * @author Christian Grothoff
 */
#ifndef GNUNET_BLOCK_LIB_H
#define GNUNET_BLOCK_LIB_H

#include "gnunet_util_lib.h"
#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Blocks in the datastore and the datacache must have a unique type.
 */
enum GNUNET_BLOCK_Type 
  {
    /**
     * Any type of block, used as a wildcard when searching.  Should
     * never be attached to a specific block.
     */
    GNUNET_BLOCK_TYPE_ANY = 0,

    /**
     * Data block (leaf) in the CHK tree.
     */
    GNUNET_BLOCK_TYPE_DBLOCK = 1,

    /**
     * Inner block in the CHK tree.
     */
    GNUNET_BLOCK_TYPE_IBLOCK = 2,

    /**
     * Type of a block representing a keyword search result.
     */
    GNUNET_BLOCK_TYPE_KBLOCK = 3,

    /**
     * Type of a block that is used to advertise content in a namespace.
     */
    GNUNET_BLOCK_TYPE_SBLOCK = 4,

    /**
     * Type of a block representing a block to be encoded on demand from disk.
     * Should never appear on the network directly.
     */
    GNUNET_BLOCK_TYPE_ONDEMAND = 5,

    /**
     * Type of a block that is used to advertise a namespace.  
     */
    GNUNET_BLOCK_TYPE_NBLOCK = 6

  };


/**
 * @brief keyword block (advertising data under a keyword)
 */
struct KBlock
{

  /**
   * GNUNET_RSA_Signature using RSA-key generated from search keyword.
   */
  struct GNUNET_CRYPTO_RsaSignature signature;

  /**
   * What is being signed and why?
   */
  struct GNUNET_CRYPTO_RsaSignaturePurpose purpose;

  /**
   * Key generated (!) from the H(keyword) as the seed!
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded keyspace;

  /* 0-terminated URI here */

  /* variable-size Meta-Data follows here */

};


/**
 * @brief namespace content block (advertising data under an identifier in a namespace)
 */
struct SBlock
{

  /**
   * GNUNET_RSA_Signature using RSA-key of the namespace
   */
  struct GNUNET_CRYPTO_RsaSignature signature;

  /**
   * What is being signed and why?
   */
  struct GNUNET_CRYPTO_RsaSignaturePurpose purpose;

  /**
   * Hash of the hash of the human-readable identifier used for
   * this entry (the hash of the human-readable identifier is
   * used as the key for decryption; the xor of this identifier
   * and the hash of the "keyspace" is the datastore-query hash).
   */
  GNUNET_HashCode identifier;

  /**
   * Public key of the namespace.
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded subspace;

  /* 0-terminated update-identifier here */

  /* 0-terminated URI here (except for NBlocks) */

  /* variable-size Meta-Data follows here */

};


/**
 * @brief namespace advertisement block (advertising root of a namespace)
 */
struct NBlock
{

  /**
   * GNUNET_RSA_Signature using RSA-key generated from search keyword.
   */
  struct GNUNET_CRYPTO_RsaSignature ksk_signature;

  /**
   * What is being signed and why?
   */
  struct GNUNET_CRYPTO_RsaSignaturePurpose ksk_purpose;

  /**
   * Key generated (!) from the H(keyword) as the seed!
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded keyspace;

  /**
   * GNUNET_RSA_Signature using RSA-key of the namespace
   */
  struct GNUNET_CRYPTO_RsaSignature ns_signature;

  /**
   * What is being signed and why?
   */
  struct GNUNET_CRYPTO_RsaSignaturePurpose ns_purpose;

  /**
   * Public key of the namespace.
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded subspace;

  /* from here on, data is encrypted with H(keyword) */

  /* 0-terminated root identifier here */

  /* variable-size Meta-Data follows here */

};


/**
 * @brief index block (indexing a DBlock that 
 *        can be obtained directly from reading
 *        the plaintext file)
 */
struct OnDemandBlock
{
  /**
   * Hash code of the entire content of the
   * file that was indexed (used to uniquely
   * identify the plaintext file).
   */
  GNUNET_HashCode file_id;

  /**
   * At which offset should we be able to find
   * this on-demand encoded block? (in NBO)
   */
  uint64_t offset GNUNET_PACKED;

};


/**
 * Check if the given block is well-formed (and of the given type).
 *
 * @param type type of the block
 * @param block the block data (or at least "size" bytes claiming to be one)
 * @param size size of "kb" in bytes; check that it is large enough
 * @param query where to store the query that this block answers
 * @return GNUNET_OK if this is actually a well-formed KBlock
 *         GNUNET_NO if we could not determine the query,
 *         GNUNET_SYSERR if the block is malformed
 */
int
GNUNET_BLOCK_check_block (enum GNUNET_BLOCK_Type type,
			  const void *block,
			  size_t size,
			  GNUNET_HashCode *query);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_BLOCK_LIB_H */
#endif
/* end of gnunet_block_lib.h */
