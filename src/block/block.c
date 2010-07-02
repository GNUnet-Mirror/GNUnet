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
 * @file block/block.c
 * @brief library for data block manipulation
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_signatures.h"
#include "gnunet_block_lib.h"

/**
 * Check if the given KBlock is well-formed.
 *
 * @param kb the kblock data (or at least "dsize" bytes claiming to be one)
 * @param dsize size of "kb" in bytes; check for < sizeof(struct KBlock)!
 * @param query where to store the query that this block answers
 * @return GNUNET_OK if this is actually a well-formed KBlock
 */
static int
check_kblock (const struct KBlock *kb,
	      size_t dsize,
	      GNUNET_HashCode *query)
{
  if (dsize < sizeof (struct KBlock))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  if (dsize - sizeof (struct KBlock) !=
      ntohl (kb->purpose.size) 
      - sizeof (struct GNUNET_CRYPTO_RsaSignaturePurpose) 
      - sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded) ) 
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  if (GNUNET_OK !=
      GNUNET_CRYPTO_rsa_verify (GNUNET_SIGNATURE_PURPOSE_FS_KBLOCK,
				&kb->purpose,
				&kb->signature,
				&kb->keyspace)) 
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  if (query != NULL)
    GNUNET_CRYPTO_hash (&kb->keyspace,
			sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
			query);
  return GNUNET_OK;
}


/**
 * Check if the given NBlock is well-formed.
 *
 * @param nb the nblock data (or at least "dsize" bytes claiming to be one)
 * @param dsize size of "nb" in bytes; check for < sizeof(struct NBlock)!
 * @param query where to store the query that this block answers
 * @return GNUNET_OK if this is actually a well-formed NBlock
 */
static int
check_nblock (const struct NBlock *nb,
	      size_t dsize,
	      GNUNET_HashCode *query)
{
  if (dsize < sizeof (struct NBlock))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  if (dsize - sizeof (struct NBlock) !=
      ntohl (nb->ns_purpose.size) 
      - sizeof (struct GNUNET_CRYPTO_RsaSignaturePurpose) 
      - sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded) ) 
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  if (dsize !=
      ntohl (nb->ksk_purpose.size) + sizeof (struct GNUNET_CRYPTO_RsaSignature))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  if (GNUNET_OK !=
      GNUNET_CRYPTO_rsa_verify (GNUNET_SIGNATURE_PURPOSE_FS_NBLOCK_KSIG,
				&nb->ksk_purpose,
				&nb->ksk_signature,
				&nb->keyspace)) 
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  if (GNUNET_OK !=
      GNUNET_CRYPTO_rsa_verify (GNUNET_SIGNATURE_PURPOSE_FS_NBLOCK,
				&nb->ns_purpose,
				&nb->ns_signature,
				&nb->subspace)) 
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  if (query != NULL)
    GNUNET_CRYPTO_hash (&nb->keyspace,
			sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
			query);
  return GNUNET_OK;
}


/**
 * Check if the given SBlock is well-formed.
 *
 * @param sb the sblock data (or at least "dsize" bytes claiming to be one)
 * @param dsize size of "kb" in bytes; check for < sizeof(struct SBlock)!
 * @param query where to store the query that this block answers
 * @return GNUNET_OK if this is actually a well-formed SBlock
 */
static int
check_sblock (const struct SBlock *sb,
	      size_t dsize,
	      GNUNET_HashCode *query)
{
  if (dsize < sizeof (struct SBlock))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  if (dsize !=
      ntohl (sb->purpose.size) + sizeof (struct GNUNET_CRYPTO_RsaSignature))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  if (GNUNET_OK !=
      GNUNET_CRYPTO_rsa_verify (GNUNET_SIGNATURE_PURPOSE_FS_SBLOCK,
				&sb->purpose,
				&sb->signature,
				&sb->subspace)) 
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  if (query != NULL)
    *query = sb->identifier;
  return GNUNET_OK;
}


/**
 * Check if the given block is well-formed (and of the given type).
 *
 * @param type type of the block
 * @param block the block data (or at least "size" bytes claiming to be one)
 * @param size size of "kb" in bytes; check that it is large enough
 * @param query where to store the query that this block answers
 * @return GNUNET_OK if this is actually a well-formed block,
 *         GNUNET_NO if we could not determine the query,
 *         GNUNET_SYSERR if the block is malformed
 */
int
GNUNET_BLOCK_check_block (enum GNUNET_BLOCK_Type type,
			  const void *block,
			  size_t size,
			  GNUNET_HashCode *query)
{
  /* first, validate! */
  switch (type)
    {
    case GNUNET_BLOCK_TYPE_DBLOCK:
    case GNUNET_BLOCK_TYPE_IBLOCK:
      GNUNET_CRYPTO_hash (block, size, query);
      break;
    case GNUNET_BLOCK_TYPE_KBLOCK:
      if (GNUNET_OK !=
	  check_kblock (block,
			size,
			query))
	return GNUNET_SYSERR;
      break;
    case GNUNET_BLOCK_TYPE_SBLOCK:
      if (GNUNET_OK !=
	  check_sblock (block,
			size,
			query))
	return GNUNET_SYSERR;
      break;
    case GNUNET_BLOCK_TYPE_NBLOCK:
      if (GNUNET_OK !=
	  check_nblock (block,
			size,
			query))
	return GNUNET_SYSERR;
      return GNUNET_OK;
    case GNUNET_BLOCK_TYPE_ONDEMAND:
      if (size != sizeof (struct OnDemandBlock))
	return GNUNET_SYSERR;
      memset (query, 0, sizeof (GNUNET_HashCode));      
      return GNUNET_NO;
    default:
      /* unknown block type */
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}


/* end of block.c */
