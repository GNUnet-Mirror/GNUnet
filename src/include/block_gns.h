/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file include/block_gns.h
 * @brief fs block formats (shared between fs and block)
 * @author Martin Schanzenbach
 */
#ifndef BLOCK_GNS_H
#define BLOCK_GNS_H

#include "gnunet_util_lib.h"

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * @brief a simgle record inside a record block
 */
struct GNSRecordBlock
{
  /**
   * the record type
   */
  uint32_t type GNUNET_PACKED;

  /**
   * expiration time of the record
   */
  struct GNUNET_TIME_AbsoluteNBO expiration;

  /**
   * length of the data
   */
  uint32_t data_length GNUNET_PACKED;
  
  /* record flags */
  uint32_t flags GNUNET_PACKED;

  //Class of the record?

  /* followed by the record data */
};

/**
 * @brief a record block for a given name of a single authority
 */
struct GNSNameRecordBlock
{

  /**
   * GNUNET_RSA_Signature using RSA-key generated from the records.
   */
  struct GNUNET_CRYPTO_RsaSignature signature;

  /**
   * What is being signed and why?
   */
  struct GNUNET_CRYPTO_RsaSignaturePurpose purpose;

  /**
   * The public key of the authority
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded public_key;

  /* number of records that follow */
  uint32_t rd_count GNUNET_PACKED;

  /* 0-terminated name here */

  /* variable-size GNSRecordBlocks follows here */


};

GNUNET_NETWORK_STRUCT_END
#endif
