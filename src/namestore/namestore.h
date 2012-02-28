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
#define GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_PUT 433
#define GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_PUT_RESPONSE 434
#define GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_CREATE 435
#define GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_CREATE_RESPONSE 436
#define GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_REMOVE 437
#define GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_REMOVE_RESPONSE 438

#define GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_START 439
#define GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_RESPONSE 440
#define GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_NEXT 441
#define GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_STOP 442

size_t
GNUNET_NAMESTORE_records_serialize (char ** dest,
                             unsigned int rd_count,
                             const struct GNUNET_NAMESTORE_RecordData *rd);

int
GNUNET_NAMESTORE_records_deserialize ( struct GNUNET_NAMESTORE_RecordData **dest, char *src, size_t len);

/**
 * A GNS record serialized for network transmission.
 * layout is [struct GNUNET_NAMESTORE_NetworkRecord][char[data_size] data]
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


/**
 * Connect to namestore service
 */
GNUNET_NETWORK_STRUCT_BEGIN
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


/**
 * Lookup response
 * Memory layout:
 * [struct LookupNameResponseMessage][struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded][char *name][rc_count * struct GNUNET_NAMESTORE_RecordData][struct GNUNET_CRYPTO_RsaSignature]
 */
GNUNET_NETWORK_STRUCT_BEGIN
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


/**
 * Put a record to the namestore
 * Memory layout:
 * [struct RecordPutMessage][struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded][char *name][rc_count * struct GNUNET_NAMESTORE_RecordData]
 */
GNUNET_NETWORK_STRUCT_BEGIN
struct RecordPutMessage
{
  /**
   * Type will be GNUNET_MESSAGE_TYPE_NAMESTORE_LOOKUP_RECORD_PUT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Operation ID in NBO
   */
  uint32_t op_id;

  /* Contenct starts here */

  /* name length */
  uint16_t name_len;

  /* Length of serialized rd data */
  uint16_t rd_len;

  struct GNUNET_TIME_AbsoluteNBO expire;

  struct GNUNET_CRYPTO_RsaSignature signature;
};
GNUNET_NETWORK_STRUCT_END

/**
 * Put a record to the namestore response
 */
GNUNET_NETWORK_STRUCT_BEGIN
struct RecordPutResponseMessage
{
  /**
   * Type will be GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_PUT_RESPONSE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Operation ID in NBO
   */
  uint32_t op_id;

  /* Contenct starts here */

  /**
   *  name length: GNUNET_NO (0) on error, GNUNET_OK (1) on success
   */
  uint16_t op_result;
};
GNUNET_NETWORK_STRUCT_END


/**
 * Put a record to the namestore
 * Memory layout:
 * [struct RecordPutMessage][struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded][char *name][rc_count * struct GNUNET_NAMESTORE_RecordData]
 */
GNUNET_NETWORK_STRUCT_BEGIN
struct RecordCreateMessage
{
  /**
   * Type will be GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_CREATE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Operation ID in NBO
   */
  uint32_t op_id;

  /* Contenct starts here */

  /* name length */
  uint16_t name_len;

  struct GNUNET_CRYPTO_RsaSignature signature;
};
GNUNET_NETWORK_STRUCT_END


/**
 * Create a record to the namestore response
 * Memory layout:
 */
GNUNET_NETWORK_STRUCT_BEGIN
struct RecordCreateResponseMessage
{
  /**
   * Type will be GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_CREATE_RESPONSE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Operation ID in NBO
   */
  uint32_t op_id;

  /* Contenct starts here */

  /**
   *  name length: GNUNET_NO (0) on error, GNUNET_OK (1) on success
   */
  uint16_t op_result;
};
GNUNET_NETWORK_STRUCT_END

/**
 * Remove a record from the namestore
 * Memory layout:
 * [struct RecordRemoveMessage][char *name][struct GNUNET_NAMESTORE_RecordData]
 */
GNUNET_NETWORK_STRUCT_BEGIN
struct RecordRemoveMessage
{
  /**
   * Type will be GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_REMOVE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Operation ID in NBO
   */
  uint32_t op_id;

  /* Contenct starts here */

  /* name length */
  uint16_t name_len;

  struct GNUNET_CRYPTO_RsaSignature signature;
};
GNUNET_NETWORK_STRUCT_END


/**
 * Remove a record from the namestore response
 */
GNUNET_NETWORK_STRUCT_BEGIN
struct RecordRemoveResponseMessage
{
  /**
   * Type will be GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_REMOVE_RESPONSE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Operation ID in NBO
   */
  uint32_t op_id;

  /* Contenct starts here */

  /**
   *  name length: GNUNET_NO (0) on error, GNUNET_OK (1) on success
   */
  uint16_t op_result;
};
GNUNET_NETWORK_STRUCT_END


/**
 * Start a zone iteration for the given zone
 */
GNUNET_NETWORK_STRUCT_BEGIN
struct ZoneIterationStartMessage
{
  /**
   * Type will be GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_START
   */
  struct GNUNET_MessageHeader header;

  /**
   * Operation ID in NBO
   */
  uint32_t op_id;

  /* Contenct starts here */

  uint16_t must_have_flags;
  uint16_t must_not_have_flags;

  GNUNET_HashCode zone;
};
GNUNET_NETWORK_STRUCT_END

/**
 * Ask for next result of zone iteration for the given operation
 */
GNUNET_NETWORK_STRUCT_BEGIN
struct ZoneIterationNextMessage
{
  /**
   * Type will be GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_NEXT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Operation ID in NBO
   */
  uint32_t op_id;
};
GNUNET_NETWORK_STRUCT_END


/**
 * Stop zone iteration for the given operation
 */
GNUNET_NETWORK_STRUCT_BEGIN
struct ZoneIterationStopMessage
{
  /**
   * Type will be GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_STOP
   */
  struct GNUNET_MessageHeader header;

  /**
   * Operation ID in NBO
   */
  uint32_t op_id;
};
GNUNET_NETWORK_STRUCT_END

/**
 * Ask for next result of zone iteration for the given operation
 */
GNUNET_NETWORK_STRUCT_BEGIN
struct ZoneIterationResponseMessage
{
  /**
   * Type will be GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_RESPONSE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Operation ID in NBO
   */
  uint32_t op_id;
};
GNUNET_NETWORK_STRUCT_END


/* end of namestore.h */
#endif
