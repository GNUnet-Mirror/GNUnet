
/*
     This file is part of GNUnet
     (C) 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_namestore_service.h
 * @brief API that can be used to store naming information on a GNUnet node;
 *        Naming information can either be records for which this peer/user
 *        is authoritative, or blocks which are cached, encrypted naming
 *        data from other peers.
 * @author Christian Grothoff
 */
#ifndef GNUNET_NAMESTORE_SERVICE_H
#define GNUNET_NAMESTORE_SERVICE_H

#include "gnunet_util_lib.h"
#include "gnunet_block_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Record type indicating any record/'*'
 */
#define GNUNET_NAMESTORE_TYPE_ANY 0

/**
 * Record type for GNS zone transfer ("PKEY").
 */
#define GNUNET_NAMESTORE_TYPE_PKEY 65536

/**
 * Record type for GNS zone transfer ("PSEU").
 */
#define GNUNET_NAMESTORE_TYPE_PSEU 65537

/**
 * Record type for GNS legacy hostnames ("LEHO").
 */
#define GNUNET_NAMESTORE_TYPE_LEHO 65538

/**
 * Record type for VPN resolution
 */
#define GNUNET_NAMESTORE_TYPE_VPN 65539

/**
 * Record type for delegation to DNS.
 */
#define GNUNET_NAMESTORE_TYPE_GNS2DNS 65540

/**
 * Record type for a social place.
 */
#define GNUNET_NAMESTORE_TYPE_PLACE 65541

/**
 * Record type for a phone (of CONVERSATION).
 */
#define GNUNET_NAMESTORE_TYPE_PHONE 65542


/**
 * Entry in the queue.
 */
struct GNUNET_NAMESTORE_QueueEntry;

/**
 * Handle to the namestore service.
 */
struct GNUNET_NAMESTORE_Handle;

/**
 * Handle to the namestore zone iterator.
 */
struct GNUNET_NAMESTORE_ZoneIterator;

/**
 * Maximum size of a value that can be stored in the namestore.
 */
#define GNUNET_NAMESTORE_MAX_VALUE_SIZE (63 * 1024)


/**
 * Connect to the namestore service.
 *
 * @param cfg configuration to use
 * @return handle to use to access the service
 */
struct GNUNET_NAMESTORE_Handle *
GNUNET_NAMESTORE_connect (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Disconnect from the namestore service (and free associated
 * resources).  Must not be called from within operation callbacks of
 * the API.
 *
 * @param h handle to the namestore
 */
void
GNUNET_NAMESTORE_disconnect (struct GNUNET_NAMESTORE_Handle *h);


/**
 * Continuation called to notify client about result of the
 * operation.
 *
 * @param cls closure
 * @param success #GNUNET_SYSERR on failure (including timeout/queue drop/failure to validate)
 *                #GNUNET_NO if content was already there or not found
 *                #GNUNET_YES (or other positive value) on success
 * @param emsg NULL on success, otherwise an error message
 */
typedef void (*GNUNET_NAMESTORE_ContinuationWithStatus) (void *cls,
                                                         int32_t success,
                                                         const char *emsg);


/**
 * Flags that can be set for a record.
 */
enum GNUNET_NAMESTORE_RecordFlags
{
  
  /**
   * No special options.
   */
  GNUNET_NAMESTORE_RF_NONE = 0,

  /**
   * This is a private record of this peer and it should
   * thus not be handed out to other peers.
   */
  GNUNET_NAMESTORE_RF_PRIVATE = 2,

  /**
   * This record was added automatically by the system
   * and is pending user confimation.
   */
  GNUNET_NAMESTORE_RF_PENDING = 4,

  /**
   * This expiration time of the record is a relative
   * time (not an absolute time).
   */
  GNUNET_NAMESTORE_RF_RELATIVE_EXPIRATION = 8,

  /**
   * This record should not be used unless all (other) records with an absolute
   * expiration time have expired.
   */
  GNUNET_NAMESTORE_RF_SHADOW_RECORD = 16

  /**
   * When comparing flags for record equality for removal,
   * which flags should must match (in addition to the type,
   * name, expiration value and data of the record)?  All flags
   * that are not listed here will be ignored for this purpose.
   * (for example, we don't expect that users will remember to
   * pass the '--private' option when removing a record from
   * the namestore, hence we don't require this particular option
   * to match upon removal).  See also
   * #GNUNET_NAMESTORE_records_cmp.
   */
#define GNUNET_NAMESTORE_RF_RCMP_FLAGS (GNUNET_NAMESTORE_RF_RELATIVE_EXPIRATION)
};


/**
 * A GNS record.
 */
struct GNUNET_NAMESTORE_RecordData
{

  /**
   * Binary value stored in the DNS record.  Note: "data" must never
   * be individually 'malloc'ed, but instead always points into some
   * existing data area.
   */
  const void *data;

  /**
   * Expiration time for the DNS record.  Can be relative
   * or absolute, depending on 'flags'.  Measured in the same
   * unit as GNUnet time (microseconds).
   */
  uint64_t expiration_time;

  /**
   * Number of bytes in 'data'.
   */
  size_t data_size;

  /**
   * Type of the GNS/DNS record.
   */
  uint32_t record_type;

  /**
   * Flags for the record.
   */
  enum GNUNET_NAMESTORE_RecordFlags flags;
};



GNUNET_NETWORK_STRUCT_BEGIN


/**
 * Information we have in an encrypted block with record data (i.e. in the DHT).
 */
struct GNUNET_NAMESTORE_Block
{

  /**
   * Signature of the block.
   */
  struct GNUNET_CRYPTO_EccSignature signature;

  /**
   * Derived key used for signing; hash of this is the query.
   */
  struct GNUNET_CRYPTO_EccPublicSignKey derived_key;

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



GNUNET_NETWORK_STRUCT_END

/**
 * Store an item in the namestore.  If the item is already present,
 * it is replaced with the new record.  
 *
 * @param h handle to the namestore
 * @param block block to store
 * @param cont continuation to call when done
 * @param cont_cls closure for @a cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_block_cache (struct GNUNET_NAMESTORE_Handle *h,
			      const struct GNUNET_NAMESTORE_Block *block,
			      GNUNET_NAMESTORE_ContinuationWithStatus cont,
			      void *cont_cls);


/**
 * Store an item in the namestore.  If the item is already present,
 * it is replaced with the new record.  Use an empty array to
 * remove all records under the given name.
 *
 * @param h handle to the namestore
 * @param pkey private key of the zone
 * @param label name that is being mapped (at most 255 characters long)
 * @param rd_count number of records in the 'rd' array
 * @param rd array of records with data to store
 * @param cont continuation to call when done
 * @param cont_cls closure for @a cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_records_store (struct GNUNET_NAMESTORE_Handle *h,
				const struct GNUNET_CRYPTO_EccPrivateKey *pkey,
				const char *label,
				unsigned int rd_count,
				const struct GNUNET_NAMESTORE_RecordData *rd,
				GNUNET_NAMESTORE_ContinuationWithStatus cont,
				void *cont_cls);


/**
 * Process a record that was stored in the namestore.
 *
 * @param cls closure
 * @param block block that was stored in the namestore
 */
typedef void (*GNUNET_NAMESTORE_BlockProcessor) (void *cls,
						 const struct GNUNET_NAMESTORE_Block *block);


/**
 * Get a result for a particular key from the namestore.  The processor
 * will only be called once.  
 *
 * @param h handle to the namestore
 * @param derived_hash hash of zone key combined with name to lookup
 *        then at the end once with NULL
 * @param proc function to call on the matching block, or with
 *        NULL if there is no matching block
 * @param proc_cls closure for @a proc
 * @return a handle that can be used to cancel
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_lookup_block (struct GNUNET_NAMESTORE_Handle *h, 
			       const struct GNUNET_HashCode *derived_hash,
			       GNUNET_NAMESTORE_BlockProcessor proc, void *proc_cls);


/**
 * Process a record that was stored in the namestore.
 *
 * @param cls closure
 * @param zone private key of the zone; NULL on disconnect
 * @param label label of the records; NULL on disconnect
 * @param rd_count number of entries in @a rd array, 0 if label was deleted
 * @param rd array of records with data to store
 */
typedef void (*GNUNET_NAMESTORE_RecordMonitor) (void *cls,
						const struct GNUNET_CRYPTO_EccPrivateKey *zone,
						const char *label,
						unsigned int rd_count,
						const struct GNUNET_NAMESTORE_RecordData *rd);


/**
 * Look for an existing PKEY delegation record for a given public key.
 * Returns at most one result to the processor.
 *
 * @param h handle to the namestore
 * @param zone public key of the zone to look up in, never NULL
 * @param value_zone public key of the target zone (value), never NULL
 * @param proc function to call on the matching records, or with
 *        NULL (rd_count == 0) if there are no matching records
 * @param proc_cls closure for @a proc
 * @return a handle that can be used to
 *         cancel
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_zone_to_name (struct GNUNET_NAMESTORE_Handle *h, 
			       const struct GNUNET_CRYPTO_EccPrivateKey *zone,
			       const struct GNUNET_CRYPTO_EccPublicSignKey *value_zone,
			       GNUNET_NAMESTORE_RecordMonitor proc, void *proc_cls);


/**
 * Process a records that were decrypted from a block.
 *
 * @param cls closure
 * @param rd_count number of entries in @a rd array
 * @param rd array of records with data to store
 */
typedef void (*GNUNET_NAMESTORE_RecordCallback) (void *cls,
						 unsigned int rd_count,
						 const struct GNUNET_NAMESTORE_RecordData *rd);


/**
 * Cancel a namestore operation.  The final callback from the
 * operation must not have been done yet.  Must be called on any
 * namestore operation that has not yet completed prior to calling
 * #GNUNET_NAMESTORE_disconnect.
 *
 * @param qe operation to cancel
 */
void
GNUNET_NAMESTORE_cancel (struct GNUNET_NAMESTORE_QueueEntry *qe);


/**
 * Starts a new zone iteration (used to periodically PUT all of our
 * records into our DHT). This MUST lock the struct GNUNET_NAMESTORE_Handle
 * for any other calls than #GNUNET_NAMESTORE_zone_iterator_next and
 * #GNUNET_NAMESTORE_zone_iteration_stop. @a proc will be called once
 * immediately, and then again after
 * #GNUNET_NAMESTORE_zone_iterator_next is invoked.
 *
 * @param h handle to the namestore
 * @param zone zone to access, NULL for all zones
 * @param proc function to call on each name from the zone; it
 *        will be called repeatedly with a value (if available)
 *        and always once at the end with a name of NULL.
 * @param proc_cls closure for @a proc
 * @return an iterator handle to use for iteration
 */
struct GNUNET_NAMESTORE_ZoneIterator *
GNUNET_NAMESTORE_zone_iteration_start (struct GNUNET_NAMESTORE_Handle *h,
				       const struct GNUNET_CRYPTO_EccPrivateKey *zone,
				       GNUNET_NAMESTORE_RecordMonitor proc,
				       void *proc_cls);


/**
 * Calls the record processor specified in #GNUNET_NAMESTORE_zone_iteration_start
 * for the next record.
 *
 * @param it the iterator
 */
void
GNUNET_NAMESTORE_zone_iterator_next (struct GNUNET_NAMESTORE_ZoneIterator *it);


/**
 * Stops iteration and releases the namestore handle for further calls.  Must
 * be called on any iteration that has not yet completed prior to calling
 * #GNUNET_NAMESTORE_disconnect.
 *
 * @param it the iterator
 */
void
GNUNET_NAMESTORE_zone_iteration_stop (struct GNUNET_NAMESTORE_ZoneIterator *it);


/**
 * Handle for a monitoring activity.
 */
struct GNUNET_NAMESTORE_ZoneMonitor;


/**
 * Function called once the monitor has caught up with the current 
 * state of the database.  Will be called AGAIN after each disconnect
 * (record monitor called with 'NULL' for zone_key) once we're again
 * in sync.
 *
 * @param cls closure
 */
typedef void (*GNUNET_NAMESTORE_RecordsSynchronizedCallback)(void *cls);


/**
 * Begin monitoring a zone for changes.  Will first call the @a monitor function
 * on all existing records in the selected zone(s), then calls @a sync_cb,
 * and then calls the @a monitor whenever a record changes.  If the namestore
 * disconnects, the @a monitor function is called with a disconnect event; if
 * the connection is re-established, the process begins from the start (all
 * existing records, sync, then updates).
 *
 * @param cfg configuration to use to connect to namestore
 * @param zone zone to monitor
 * @param monitor function to call on zone changes
 * @param sync_cb function called when we're in sync with the namestore
 * @param cls closure for @a monitor and @a sync_cb
 * @return handle to stop monitoring
 */
struct GNUNET_NAMESTORE_ZoneMonitor *
GNUNET_NAMESTORE_zone_monitor_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
				     const struct GNUNET_CRYPTO_EccPrivateKey *zone,
				     GNUNET_NAMESTORE_RecordMonitor monitor,
				     GNUNET_NAMESTORE_RecordsSynchronizedCallback sync_cb,
				     void *cls);


/**
 * Stop monitoring a zone for changes.
 *
 * @param zm handle to the monitor activity to stop
 */
void
GNUNET_NAMESTORE_zone_monitor_stop (struct GNUNET_NAMESTORE_ZoneMonitor *zm);


/* convenience APIs for serializing / deserializing GNS records */

/**
 * Calculate how many bytes we will need to serialize the given
 * records.
 *
 * @param rd_count number of records in the @a rd array
 * @param rd array of #GNUNET_NAMESTORE_RecordData with @a rd_count elements
 * @return the required size to serialize
 */
size_t
GNUNET_NAMESTORE_records_get_size (unsigned int rd_count,
				   const struct GNUNET_NAMESTORE_RecordData *rd);


/**
 * Serialize the given records to the given destination buffer.
 *
 * @param rd_count number of records in the @a rd array
 * @param rd array of #GNUNET_NAMESTORE_RecordData with @a rd_count elements
 * @param dest_size size of the destination array @a dst
 * @param dest where to write the result
 * @return the size of serialized records, -1 if records do not fit
 */
ssize_t
GNUNET_NAMESTORE_records_serialize (unsigned int rd_count,
				    const struct GNUNET_NAMESTORE_RecordData *rd,
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
GNUNET_NAMESTORE_records_deserialize (size_t len,
				      const char *src,
				      unsigned int rd_count,
				      struct GNUNET_NAMESTORE_RecordData *dest);


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
GNUNET_NAMESTORE_value_to_string (uint32_t type,
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
GNUNET_NAMESTORE_string_to_value (uint32_t type,
				  const char *s,
				  void **data,
				  size_t *data_size);


/**
 * Convert a type name (i.e. "AAAA") to the corresponding number.
 *
 * @param typename name to convert
 * @return corresponding number, UINT32_MAX on error
 */
uint32_t
GNUNET_NAMESTORE_typename_to_number (const char *dns_typename);


/**
 * Convert a type number (i.e. 1) to the corresponding type string (i.e. "A")
 *
 * @param type number of a type to convert
 * @return corresponding typestring, NULL on error
 */
const char *
GNUNET_NAMESTORE_number_to_typename (uint32_t type);


/**
 * Test if a given record is expired.
 * 
 * @param rd record to test
 * @return #GNUNET_YES if the record is expired,
 *         #GNUNET_NO if not
 */
int
GNUNET_NAMESTORE_is_expired (const struct GNUNET_NAMESTORE_RecordData *rd);


/**
 * Convert a UTF-8 string to UTF-8 lowercase
 * @param src source string
 * @return converted result
 */
char *
GNUNET_NAMESTORE_normalize_string (const char *src);


/**
 * Convert a zone to a string (for printing debug messages).
 * This is one of the very few calls in the entire API that is
 * NOT reentrant!
 *
 * @param z public key of a zone
 * @return string form; will be overwritten by next call to #GNUNET_NAMESTORE_z2s.
 */
const char *
GNUNET_NAMESTORE_z2s (const struct GNUNET_CRYPTO_EccPublicSignKey *z);


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
GNUNET_NAMESTORE_pkey_to_zkey (const struct GNUNET_CRYPTO_EccPublicSignKey *pkey);


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
GNUNET_NAMESTORE_zkey_to_pkey (const char *zkey,
			       struct GNUNET_CRYPTO_EccPublicSignKey *pkey);


/**
 * Calculate the DHT query for a given @a label in a given @a zone.
 * 
 * @param zone private key of the zone
 * @param label label of the record
 * @param query hash to use for the query
 */
void
GNUNET_NAMESTORE_query_from_private_key (const struct GNUNET_CRYPTO_EccPrivateKey *zone,
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
GNUNET_NAMESTORE_query_from_public_key (const struct GNUNET_CRYPTO_EccPublicSignKey *pub,
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
struct GNUNET_NAMESTORE_Block *
GNUNET_NAMESTORE_block_create (const struct GNUNET_CRYPTO_EccPrivateKey *key,
			       struct GNUNET_TIME_Absolute expire,
			       const char *label,
			       const struct GNUNET_NAMESTORE_RecordData *rd,
			       unsigned int rd_count);


/**
 * Check if a signature is valid.  This API is used by the GNS Block
 * to validate signatures received from the network.
 *
 * @param block block to verify
 * @return #GNUNET_OK if the signature is valid
 */
int
GNUNET_NAMESTORE_block_verify (const struct GNUNET_NAMESTORE_Block *block);


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
GNUNET_NAMESTORE_block_decrypt (const struct GNUNET_NAMESTORE_Block *block,
				const struct GNUNET_CRYPTO_EccPublicSignKey *zone_key,
				const char *label,
				GNUNET_NAMESTORE_RecordCallback proc,
				void *proc_cls);


/**
 * Compares if two records are equal
 *
 * @param a a record
 * @param b another record 
 * @return #GNUNET_YES if the records are equal, or #GNUNET_NO if not.
 */
int
GNUNET_NAMESTORE_records_cmp (const struct GNUNET_NAMESTORE_RecordData *a,
                              const struct GNUNET_NAMESTORE_RecordData *b);


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
GNUNET_NAMESTORE_record_get_expiration_time (unsigned int rd_count, 
					     const struct GNUNET_NAMESTORE_RecordData *rd);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* end of gnunet_namestore_service.h */
#endif
