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

/**
 * Maximum length of any name, including 0-termination.
 */
#define MAX_NAME_LEN 256

GNUNET_NETWORK_STRUCT_BEGIN


/**
 * A GNS record serialized for network transmission.
 *
 * Layout is [struct GNUNET_NAMESTORE_NetworkRecord][char[data_size] data]
 */
struct GNUNET_NAMESTORE_NetworkRecord
{
  /**
   * Expiration time for the DNS record.
   */
  struct GNUNET_TIME_AbsoluteNBO expiration;

  /**
   * Number of bytes in 'data'.
   */
  uint32_t data_size;

  /**
   * Type of the GNS/DNS record.
   */
  uint32_t record_type;

  /**
   * Flags for the record.
   */
  uint32_t flags;
};



/**
 * Connect to namestore service.  FIXME: UNNECESSARY.
 */
struct StartMessage
{

  /**
   * Type will be GNUNET_MESSAGE_TYPE_NAMESTORE_START
   */
  struct GNUNET_MessageHeader header;

};


/**
 * Generic namestore message with op id
 */
struct GNUNET_NAMESTORE_Header
{
  /**
   * header.type will be GNUNET_MESSAGE_TYPE_NAMESTORE_*
   * header.size will be message size
   */
  struct GNUNET_MessageHeader header;

  /**
   * Request ID in NBO
   */
  uint32_t r_id;
};


/**
 * Lookup a name in the namestore
 */
struct LookupNameMessage
{
  struct GNUNET_NAMESTORE_Header gns_header;

  /**
   * The zone 
   */
  struct GNUNET_CRYPTO_ShortHashCode zone;

  /**
   * Requested record type 
   */
  uint32_t record_type;

  /**
   * Length of the name
   */
  uint32_t name_len;

  /* 0-terminated name here */
};


/**
 * Lookup response
 */
struct LookupNameResponseMessage
{
  /**
   * Type will be GNUNET_MESSAGE_TYPE_NAMESTORE_LOOKUP_NAME_RESPONSE
   */
  struct GNUNET_NAMESTORE_Header gns_header;

  /**
   * Expiration time
   */
  struct GNUNET_TIME_AbsoluteNBO expire;


  /**
   * Name length
   */
  uint16_t name_len;

  /**
   * Bytes of serialized record data
   */
  uint16_t rd_len;

  /**
   * Number of records contained
   */
  uint16_t rd_count;

  /**
   * Is the signature valid
   * GNUNET_YES or GNUNET_NO
   */
  int16_t contains_sig;

  /**
   * All zeros if 'contains_sig' is GNUNET_NO.
   */
  struct GNUNET_CRYPTO_EccSignature signature;

  /**
   * The public key for the name
   */
  struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded public_key;

  /* 0-terminated name and serialized record data */
  /* rd_len bytes serialized record data */
};


/**
 * Put a record to the namestore
 */
struct RecordPutMessage
{
  /**
   * Type will be GNUNET_MESSAGE_TYPE_NAMESTORE_LOOKUP_RECORD_PUT
   */
  struct GNUNET_NAMESTORE_Header gns_header;

  /**
   * Expiration time
   */
  struct GNUNET_TIME_AbsoluteNBO expire;

  /**
   * Name length
   */
  uint16_t name_len;

  /**
   * Length of serialized record data
   */
  uint16_t rd_len;

  /**
   * Number of records contained 
   */
  uint16_t rd_count;

  /**
   * always zero (for alignment)
   */
  uint16_t reserved;

  /**
   * The signature
   */
  struct GNUNET_CRYPTO_EccSignature signature;

  /**
   * The public key
   */
  struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded public_key;

  /* name (0-terminated) followed by "rd_count" serialized records */

};


/**
 * Put a record to the namestore response
 */
struct RecordPutResponseMessage
{
  /**
   * Type will be GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_PUT_RESPONSE
   */
  struct GNUNET_NAMESTORE_Header gns_header;

  /**
   * result:
   * GNUNET_SYSERR on failure
   * GNUNET_OK on success
   */
  int32_t op_result;
};


/**
 * Create a record and put it to the namestore
 * Memory layout:
 */
struct RecordCreateMessage
{
  /**
   * Type will be GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_CREATE
   */
  struct GNUNET_NAMESTORE_Header gns_header;

  struct GNUNET_TIME_AbsoluteNBO expire;

  /**
   * Name length
   */
  uint16_t name_len;

  /**
   * Length of serialized record data
   */
  uint16_t rd_len;

  /**
   * Record count 
   */
  uint16_t rd_count;

  /**
   * private key length 
   */
  uint16_t pkey_len;

  /* followed by:
   * GNUNET_CRYPTO_EccPrivateKeyBinaryEncoded private key with length pkey_len
   * name with length name_len
   * serialized record data with length rd_len
   * */
};


/**
 * Create a record to the namestore response
 */
struct RecordCreateResponseMessage
{
  /**
   * Type will be GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_CREATE_RESPONSE
   */
  struct GNUNET_NAMESTORE_Header gns_header;

  /**
   *  name length: GNUNET_NO already exists, GNUNET_YES on success, GNUNET_SYSERR error
   */
  int32_t op_result;
};


/**
 * Lookup a name for a zone hash
 */
struct ZoneToNameMessage
{
  /**
   * Type will be GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME
   */
  struct GNUNET_NAMESTORE_Header gns_header;

  /**
   * The hash of public key of the zone to look up in 
   */
  struct GNUNET_CRYPTO_ShortHashCode zone;

  /**
   * The  hash of the public key of the target zone  
   */
  struct GNUNET_CRYPTO_ShortHashCode value_zone;
};

/**
 * Respone for zone to name lookup
 */
struct ZoneToNameResponseMessage
{
  /**
   * Type will be GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME_RESPONSE
   */
  struct GNUNET_NAMESTORE_Header gns_header;

  /**
   * Record block expiration
   */
  struct GNUNET_TIME_AbsoluteNBO expire;

  /**
   * Length of the name
   */
  uint16_t name_len;

  /**
   * Length of serialized record data
   */
  uint16_t rd_len;

  /**
   * Number of records contained
   */
  uint16_t rd_count;

  /* result in NBO: GNUNET_OK on success, GNUNET_NO if there were no results, GNUNET_SYSERR on error */
  int16_t res;

  /**
   * Signature
   */
  struct GNUNET_CRYPTO_EccSignature signature;

  /**
   * Publik key
   */
  struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded zone_key;

};


/**
 * Start monitoring a zone.
 */
struct ZoneMonitorStartMessage
{
  /**
   * Type will be GNUNET_MESSAGE_TYPE_NAMESTORE_MONITOR_START
   */
  struct GNUNET_NAMESTORE_Header gns_header;

  /**
   * Zone hash
   */
  struct GNUNET_CRYPTO_ShortHashCode zone;

  /**
   * All zones. GNUNET_YES to monitor all zones,
   * GNUNET_NO to only monitor 'zone'.  In NBO.
   */
  uint32_t all_zones GNUNET_PACKED;

};


/**
 * Start a zone iteration for the given zone
 */
struct ZoneIterationStartMessage
{
  /**
   * Type will be GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_START
   */
  struct GNUNET_NAMESTORE_Header gns_header;

  /**
   * Zone hash
   */
  struct GNUNET_CRYPTO_ShortHashCode zone;

  /**
   * Which flags must be included
   */
  uint16_t must_have_flags;

  /**
   * Which flags must not be included
   */
  uint16_t must_not_have_flags;
};


/**
 * Ask for next result of zone iteration for the given operation
 */
struct ZoneIterationNextMessage
{
  /**
   * Type will be GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_NEXT
   */
  struct GNUNET_NAMESTORE_Header gns_header;
};


/**
 * Stop zone iteration for the given operation
 */
struct ZoneIterationStopMessage
{
  /**
   * Type will be GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_STOP
   */
  struct GNUNET_NAMESTORE_Header gns_header;
};


/**
 * Next result of zone iteration for the given operation
 * // FIXME: use 'struct LookupResponseMessage' instead? (identical except
 * for having 'contains_sig' instead of 'reserved', but fully compatible otherwise).
 */
struct ZoneIterationResponseMessage
{
  /**
   * Type will be GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_RESPONSE
   */
  struct GNUNET_NAMESTORE_Header gns_header;

  struct GNUNET_TIME_AbsoluteNBO expire;

  uint16_t name_len;

  /**
   * Record data length 
   */
  uint16_t rd_len;

  /**
   * Number of records contained 
   */
  uint16_t rd_count;

  /**
   * always zero (for alignment)
   */
  uint16_t reserved;

  /**
   * All zeros if 'contains_sig' is GNUNET_NO.
   */
  struct GNUNET_CRYPTO_EccSignature signature;

  /**
   * The public key
   */
  struct GNUNET_CRYPTO_EccPublicKeyBinaryEncoded public_key;

};




GNUNET_NETWORK_STRUCT_END


/* end of namestore.h */
#endif
