/*
     This file is part of GNUnet.
     Copyright (C) 2011-2013 Christian Grothoff (and other contributing authors)

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
 * @file namecache/namecache.h
 * @brief common internal definitions for namecache service
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#ifndef NAMECACHE_H
#define NAMECACHE_H

/**
 * Maximum length of any name, including 0-termination.
 */
#define MAX_NAME_LEN 256

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Generic namecache message with op id
 */
struct GNUNET_NAMECACHE_Header
{
  /**
   * header.type will be GNUNET_MESSAGE_TYPE_NAMECACHE_*
   * header.size will be message size
   */
  struct GNUNET_MessageHeader header;

  /**
   * Request ID in NBO
   */
  uint32_t r_id GNUNET_PACKED;
};


/**
 * Lookup a block in the namecache
 */
struct LookupBlockMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_NAMECACHE_LOOKUP_BLOCK
   */
  struct GNUNET_NAMECACHE_Header gns_header;

  /**
   * The query.
   */
  struct GNUNET_HashCode query GNUNET_PACKED;

};


/**
 * Lookup response
 */
struct LookupBlockResponseMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_NAMECACHE_LOOKUP_BLOCK_RESPONSE
   */
  struct GNUNET_NAMECACHE_Header gns_header;

  /**
   * Expiration time
   */
  struct GNUNET_TIME_AbsoluteNBO expire;

  /**
   * Signature.
   */
  struct GNUNET_CRYPTO_EcdsaSignature signature;

  /**
   * Derived public key.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey derived_key;

  /* follwed by encrypted block data */
};


/**
 * Cache a record in the namecache.
 */
struct BlockCacheMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_NAMECACHE_BLOCK_CACHE
   */
  struct GNUNET_NAMECACHE_Header gns_header;

  /**
   * Expiration time
   */
  struct GNUNET_TIME_AbsoluteNBO expire;

  /**
   * Signature.
   */
  struct GNUNET_CRYPTO_EcdsaSignature signature;

  /**
   * Derived public key.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey derived_key;

  /* follwed by encrypted block data */
};


/**
 * Response to a request to cache a block.
 */
struct BlockCacheResponseMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_NAMECACHE_BLOCK_CACHE_RESPONSE
   */
  struct GNUNET_NAMECACHE_Header gns_header;

  /**
   * #GNUNET_OK on success, #GNUNET_SYSERR error
   */
  int32_t op_result GNUNET_PACKED;
};


GNUNET_NETWORK_STRUCT_END


/* end of namecache.h */
#endif
