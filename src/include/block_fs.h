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
 * @file include/block_fs.h
 * @brief fs block formats (shared between fs and block)
 * @author Christian Grothoff
 */
#ifndef BLOCK_FS_H
#define BLOCK_FS_H

#include "gnunet_util_lib.h"

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


GNUNET_NETWORK_STRUCT_BEGIN

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
GNUNET_NETWORK_STRUCT_END

#endif
