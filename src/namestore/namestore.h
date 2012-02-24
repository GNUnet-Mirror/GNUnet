/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file namestore/namestore.h
 * @brief common internal definitions for namestore service
 * @author Matthias Wachs
 */
#ifndef NAMESTORE_H
#define NAMESTORE_H

/*
 * Collect message types here, move to protocols later
 */
#define GNUNET_MESSAGE_TYPE_NAMESTORE_LOOKUP_NAME 431
#define GNUNET_MESSAGE_TYPE_NAMESTORE_LOOKUP_NAME_RESPONSE 432

GNUNET_NETWORK_STRUCT_BEGIN
/**
 * Connect to namestore service
 */
struct StartMessage
{

  /**
   * Type will be GNUNET_MESSAGE_TYPE_NAMESTORE_START
   */
  struct GNUNET_MessageHeader header;

};
GNUNET_NETWORK_STRUCT_END


GNUNET_NETWORK_STRUCT_BEGIN
/**
 * Generic namestore message with op id
 */
struct GenericMessage
{
  /**
   * Type will be GNUNET_MESSAGE_TYPE_NAMESTORE_*
   */
  struct GNUNET_MessageHeader header;

  /**
   * Operation ID in NBO
   */
  uint32_t op_id;
};
GNUNET_NETWORK_STRUCT_END



GNUNET_NETWORK_STRUCT_BEGIN
/**
 * Connect to namestore service
 */
struct LookupNameMessage
{
  /**
   * Type will be GNUNET_MESSAGE_TYPE_NAMESTORE_LOOKUP_NAME
   */
  struct GNUNET_MessageHeader header;

  /**
   * Operation ID in NBO
   */
  uint32_t op_id;

  /* The zone */
  GNUNET_HashCode zone;

  /* Requested record type */
  uint32_t record_type;

  /* Requested record type */
  uint32_t name_len;
};
GNUNET_NETWORK_STRUCT_END



GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Lookup response
 * Memory layout:
 * [struct LookupNameResponseMessage][struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded][char *name][rc_count * struct GNUNET_NAMESTORE_RecordData][struct GNUNET_CRYPTO_RsaSignature]
 */

struct LookupNameResponseMessage
{
  /**
   * Type will be GNUNET_MESSAGE_TYPE_NAMESTORE_LOOKUP_NAME_RESPONSE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Operation ID in NBO
   */
  uint32_t op_id;

  struct GNUNET_TIME_AbsoluteNBO expire;

  uint16_t name_len;

  uint16_t contains_sig;

  /* Requested record type */
  uint32_t rc_count;
};


GNUNET_NETWORK_STRUCT_END


/* end of namestore.h */
#endif
