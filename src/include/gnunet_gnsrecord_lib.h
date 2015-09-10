/*
     This file is part of GNUnet
     Copyright (C) 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_gnsrecord_lib.h
 * @brief API that can be used to manipulate GNS record data
 * @author Christian Grothoff
 */
#ifndef GNUNET_GNSRECORD_LIB_H
#define GNUNET_GNSRECORD_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Maximum size of a value that can be stored in a GNS block.
 */
#define GNUNET_GNSRECORD_MAX_BLOCK_SIZE (63 * 1024)


/**
 * Record type indicating any record/'*'
 */
#define GNUNET_GNSRECORD_TYPE_ANY 0

/**
 * Record type for GNS zone transfer ("PKEY").
 */
#define GNUNET_GNSRECORD_TYPE_PKEY 65536

/**
 * Record type for GNS nick names ("NICK").
 */
#define GNUNET_GNSRECORD_TYPE_NICK 65537

/**
 * Record type for GNS legacy hostnames ("LEHO").
 */
#define GNUNET_GNSRECORD_TYPE_LEHO 65538

/**
 * Record type for VPN resolution
 */
#define GNUNET_GNSRECORD_TYPE_VPN 65539

/**
 * Record type for delegation to DNS.
 */
#define GNUNET_GNSRECORD_TYPE_GNS2DNS 65540

/**
 * Record type for a boxed record (see TLSA/SRV handling in GNS).
 */
#define GNUNET_GNSRECORD_TYPE_BOX 65541

/**
 * Record type for a social place.
 */
#define GNUNET_GNSRECORD_TYPE_PLACE 65542

/**
 * Record type for a phone (of CONVERSATION).
 */
#define GNUNET_GNSRECORD_TYPE_PHONE 65543

/**
 * Record type for identity attributes (of IDENTITY).
 */
#define GNUNET_GNSRECORD_TYPE_ID_ATTR 65544

/**
 * Record type for an identity token (of IDENTITY).
 */
#define GNUNET_GNSRECORD_TYPE_ID_TOKEN 65545




/**
 * Flags that can be set for a record.
 */
enum GNUNET_GNSRECORD_Flags
{

  /**
   * No special options.
   */
  GNUNET_GNSRECORD_RF_NONE = 0,

  /**
   * This is a private record of this peer and it should
   * thus not be handed out to other peers.
   */
  GNUNET_GNSRECORD_RF_PRIVATE = 2,

  /**
   * This flag is currently unused; former RF_PENDING flag
   *
   * GNUNET_GNSRECORD_RF_UNUSED = 4,
   */

  /**
   * This expiration time of the record is a relative
   * time (not an absolute time).
   */
  GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION = 8,

  /**
   * This record should not be used unless all (other) records with an absolute
   * expiration time have expired.
   */
  GNUNET_GNSRECORD_RF_SHADOW_RECORD = 16

  /**
   * When comparing flags for record equality for removal,
   * which flags should must match (in addition to the type,
   * name, expiration value and data of the record)?  All flags
   * that are not listed here will be ignored for this purpose.
   * (for example, we don't expect that users will remember to
   * pass the '--private' option when removing a record from
   * the namestore, hence we don't require this particular option
   * to match upon removal).  See also
   * #GNUNET_GNSRECORD_records_cmp.
   */
#define GNUNET_GNSRECORD_RF_RCMP_FLAGS (GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION)
};


/**
 * A GNS record.
 */
struct GNUNET_GNSRECORD_Data
{

  /**
   * Binary value stored in the DNS record.  Note: "data" must never
   * be individually 'malloc'ed, but instead always points into some
   * existing data area.
   */
  const void *data;

  /**
   * Expiration time for the DNS record.  Can be relative
   * or absolute, depending on @e flags.  Measured in the same
   * unit as GNUnet time (microseconds).
   */
  uint64_t expiration_time;

  /**
   * Number of bytes in @e data.
   */
  size_t data_size;

  /**
   * Type of the GNS/DNS record.
   */
  uint32_t record_type;

  /**
   * Flags for the record.
   */
  enum GNUNET_GNSRECORD_Flags flags;
};


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Data stored in a PLACE record.
 */
struct GNUNET_GNSRECORD_PlaceData
{
  /**
   * Public key of the place.
   */
  struct GNUNET_CRYPTO_EddsaPublicKey place_key;

  /**
   * Peer identity of the origin.
   */
  struct GNUNET_PeerIdentity origin;

  /**
   * Number of relays that follow.
   */
  uint32_t relay_count GNUNET_PACKED;

  /* Followed by struct GNUNET_PeerIdentity relays[relay_count] */
};


/**
 * Information we have in an encrypted block with record data (i.e. in the DHT).
 */
struct GNUNET_GNSRECORD_Block
{

  /**
   * Signature of the block.
   */
  struct GNUNET_CRYPTO_EcdsaSignature signature;

  /**
   * Derived key used for signing; hash of this is the query.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey derived_key;

  /**
   * Number of bytes signed; also specifies the number of bytes
   * of encrypted data that follow.
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * Expiration time of the block.
   */
  struct GNUNET_TIME_AbsoluteNBO expiration_time;

  /* followed by encrypted data */
};


/**
 * Record type used to box up SRV and TLSA records.  For example, a
 * TLSA record for "_https._tcp.foo.gnu" will be stored under
 * "foo.gnu" as a BOX record with service 443 (https) and protocol 6
 * (tcp) and record_type "TLSA".  When a BOX record is received, GNS
 * unboxes it if the name contained "_SERVICE._PROTO", otherwise GNS
 * leaves it untouched.  This is done to ensure that TLSA (and SRV)
 * records do not require a separate network request, thus making TLSA
 * records inseparable from the "main" A/AAAA/VPN/etc. records.
 */
struct GNUNET_GNSRECORD_BoxRecord
{

  /**
   * Protocol of the boxed record (6 = TCP, 17 = UDP, etc.).
   * Yes, in IP protocols are usually limited to 8 bits. In NBO.
   */
  uint16_t protocol GNUNET_PACKED;

  /**
   * Service of the boxed record (aka port number), in NBO.
   */
  uint16_t service GNUNET_PACKED;

  /**
   * GNS record type of the boxed record. In NBO.
   */
  uint32_t record_type GNUNET_PACKED;

  /* followed by the 'original' record */

};


GNUNET_NETWORK_STRUCT_END


/**
 * Process a records that were decrypted from a block.
 *
 * @param cls closure
 * @param rd_count number of entries in @a rd array
 * @param rd array of records with data to store
 */
typedef void (*GNUNET_GNSRECORD_RecordCallback) (void *cls,
						 unsigned int rd_count,
						 const struct GNUNET_GNSRECORD_Data *rd);



/* ***************** API related to GNSRECORD plugins ************** */

/**
 * Convert the binary value @a data of a record of
 * type @a type to a human-readable string.
 *
 * @param type type of the record
 * @param data value in binary encoding
 * @param data_size number of bytes in @a data
 * @return NULL on error, otherwise human-readable representation of the value
 */
char *
GNUNET_GNSRECORD_value_to_string (uint32_t type,
				  const void *data,
				  size_t data_size);


/**
 * Convert human-readable version of the value @a s of a record
 * of type @a type to the respective binary representation.
 *
 * @param type type of the record
 * @param s human-readable string
 * @param data set to value in binary encoding (will be allocated)
 * @param data_size set to number of bytes in @a data
 * @return #GNUNET_OK on success
 */
int
GNUNET_GNSRECORD_string_to_value (uint32_t type,
				  const char *s,
				  void **data,
				  size_t *data_size);


/**
 * Convert a type name (i.e. "AAAA") to the corresponding number.
 *
 * @param dns_typename name to convert
 * @return corresponding number, UINT32_MAX on error
 */
uint32_t
GNUNET_GNSRECORD_typename_to_number (const char *dns_typename);


/**
 * Convert a type number (i.e. 1) to the corresponding type string (i.e. "A")
 *
 * @param type number of a type to convert
 * @return corresponding typestring, NULL on error
 */
const char *
GNUNET_GNSRECORD_number_to_typename (uint32_t type);


/* convenience APIs for serializing / deserializing GNS records */

/**
 * Calculate how many bytes we will need to serialize the given
 * records.
 *
 * @param rd_count number of records in the @a rd array
 * @param rd array of #GNUNET_GNSRECORD_Data with @a rd_count elements
 * @return the required size to serialize
 */
size_t
GNUNET_GNSRECORD_records_get_size (unsigned int rd_count,
				   const struct GNUNET_GNSRECORD_Data *rd);


/**
 * Serialize the given records to the given destination buffer.
 *
 * @param rd_count number of records in the @a rd array
 * @param rd array of #GNUNET_GNSRECORD_Data with @a rd_count elements
 * @param dest_size size of the destination array @a dst
 * @param dest where to write the result
 * @return the size of serialized records, -1 if records do not fit
 */
ssize_t
GNUNET_GNSRECORD_records_serialize (unsigned int rd_count,
				    const struct GNUNET_GNSRECORD_Data *rd,
				    size_t dest_size,
				    char *dest);


/**
 * Deserialize the given records to the given destination.
 *
 * @param len size of the serialized record data
 * @param src the serialized record data
 * @param rd_count number of records in the @a dest array
 * @param dest where to put the data
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_GNSRECORD_records_deserialize (size_t len,
				      const char *src,
				      unsigned int rd_count,
				      struct GNUNET_GNSRECORD_Data *dest);


/* ******* general APIs relating to blocks, records and labels ******** */



/**
 * Test if a given record is expired.
 *
 * @param rd record to test
 * @return #GNUNET_YES if the record is expired,
 *         #GNUNET_NO if not
 */
int
GNUNET_GNSRECORD_is_expired (const struct GNUNET_GNSRECORD_Data *rd);


/**
 * Convert a UTF-8 string to UTF-8 lowercase
 * @param src source string
 * @return converted result
 */
char *
GNUNET_GNSRECORD_string_to_lowercase (const char *src);


/**
 * Convert a zone to a string (for printing debug messages).
 * This is one of the very few calls in the entire API that is
 * NOT reentrant!
 *
 * @param z public key of a zone
 * @return string form; will be overwritten by next call to #GNUNET_GNSRECORD_z2s.
 */
const char *
GNUNET_GNSRECORD_z2s (const struct GNUNET_CRYPTO_EcdsaPublicKey *z);


/**
 * Convert public key to the respective absolute domain name in the
 * ".zkey" pTLD.
 * This is one of the very few calls in the entire API that is
 * NOT reentrant!
 *
 * @param pkey a public key with a point on the eliptic curve
 * @return string "X.zkey" where X is the coordinates of the public
 *         key in an encoding suitable for DNS labels.
 */
const char *
GNUNET_GNSRECORD_pkey_to_zkey (const struct GNUNET_CRYPTO_EcdsaPublicKey *pkey);


/**
 * Convert an absolute domain name in the ".zkey" pTLD to the
 * respective public key.
 *
 * @param zkey string "X.zkey" where X is the public
 *         key in an encoding suitable for DNS labels.
 * @param pkey set to a public key on the eliptic curve
 * @return #GNUNET_SYSERR if @a zkey has the wrong syntax
 */
int
GNUNET_GNSRECORD_zkey_to_pkey (const char *zkey,
			       struct GNUNET_CRYPTO_EcdsaPublicKey *pkey);


/**
 * Calculate the DHT query for a given @a label in a given @a zone.
 *
 * @param zone private key of the zone
 * @param label label of the record
 * @param query hash to use for the query
 */
void
GNUNET_GNSRECORD_query_from_private_key (const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
					 const char *label,
					 struct GNUNET_HashCode *query);


/**
 * Calculate the DHT query for a given @a label in a given @a zone.
 *
 * @param pub public key of the zone
 * @param label label of the record
 * @param query hash to use for the query
 */
void
GNUNET_GNSRECORD_query_from_public_key (const struct GNUNET_CRYPTO_EcdsaPublicKey *pub,
					const char *label,
					struct GNUNET_HashCode *query);


/**
 * Sign name and records
 *
 * @param key the private key
 * @param expire block expiration
 * @param label the name for the records
 * @param rd record data
 * @param rd_count number of records in @a rd
 */
struct GNUNET_GNSRECORD_Block *
GNUNET_GNSRECORD_block_create (const struct GNUNET_CRYPTO_EcdsaPrivateKey *key,
			       struct GNUNET_TIME_Absolute expire,
			       const char *label,
			       const struct GNUNET_GNSRECORD_Data *rd,
			       unsigned int rd_count);


/**
 * Check if a signature is valid.  This API is used by the GNS Block
 * to validate signatures received from the network.
 *
 * @param block block to verify
 * @return #GNUNET_OK if the signature is valid
 */
int
GNUNET_GNSRECORD_block_verify (const struct GNUNET_GNSRECORD_Block *block);


/**
 * Decrypt block.
 *
 * @param block block to decrypt
 * @param zone_key public key of the zone
 * @param label the name for the records
 * @param proc function to call with the result
 * @param proc_cls closure for @a proc
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the block was
 *        not well-formed
 */
int
GNUNET_GNSRECORD_block_decrypt (const struct GNUNET_GNSRECORD_Block *block,
				const struct GNUNET_CRYPTO_EcdsaPublicKey *zone_key,
				const char *label,
				GNUNET_GNSRECORD_RecordCallback proc,
				void *proc_cls);


/**
 * Compares if two records are equal
 *
 * @param a a record
 * @param b another record
 * @return #GNUNET_YES if the records are equal, or #GNUNET_NO if not.
 */
int
GNUNET_GNSRECORD_records_cmp (const struct GNUNET_GNSRECORD_Data *a,
                              const struct GNUNET_GNSRECORD_Data *b);


/**
 * Returns the expiration time of the given block of records. The block
 * expiration time is the expiration time of the record with smallest
 * expiration time.
 *
 * @param rd_count number of records given in @a rd
 * @param rd array of records
 * @return absolute expiration time
 */
struct GNUNET_TIME_Absolute
GNUNET_GNSRECORD_record_get_expiration_time (unsigned int rd_count,
					     const struct GNUNET_GNSRECORD_Data *rd);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
