/*
     This file is part of GNUnet
     (C) 2012 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @author Christian Grothoff
 *
 * Other functions we might want:
 * - enumerate all known zones
 * - convenience function to gather record and the full affilliated stree
 *   in one shot
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
 * resources).
 *
 * @param h handle to the namestore
 * @param drop set to GNUNET_YES to delete all data in namestore (!)
 */
void
GNUNET_NAMESTORE_disconnect (struct GNUNET_NAMESTORE_Handle *h, int drop);


/**
 * Continuation called to notify client about result of the
 * operation.
 *
 * @param cls closure
 * @param success GNUNET_SYSERR on failure (including timeout/queue drop/failure to validate)
 *                GNUNET_NO if content was already there or not found
 *                GNUNET_YES (or other positive value) on success
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
   * This peer is the authority for this record; it must thus
   * not be deleted (other records can be deleted if we run
   * out of space).
   */
  GNUNET_NAMESTORE_RF_AUTHORITY = 1,

  /**
   * This is a private record of this peer and it should
   * thus not be handed out to other peers.
   */
  GNUNET_NAMESTORE_RF_PRIVATE = 2,

  /**
   * This record was added by the system
   * and is pending user confimation
   */
  GNUNET_NAMESTORE_RF_PENDING = 4

};


/**
 * A GNS record.
 */
struct GNUNET_NAMESTORE_RecordData
{

  /**
   * Binary value stored in the DNS record.
   */
  const void *data;

  /**
   * Expiration time for the DNS record.
   */
  struct GNUNET_TIME_Absolute expiration;

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


/**
 * Store an item in the namestore.  If the item is already present,
 * the expiration time is updated to the max of the existing time and
 * the new time.  This API is used when we cache signatures from other
 * authorities.
 *
 * @param h handle to the namestore
 * @param zone_key public key of the zone
 * @param name name that is being mapped (at most 255 characters long)
 * @param freshness when does the corresponding block in the DHT expire (until
 *               when should we never do a DHT lookup for the same name again)?
 * @param rd_count number of entries in 'rd' array
 * @param rd array of records with data to store
 * @param signature signature for all the records in the zone under the given name
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_record_put (struct GNUNET_NAMESTORE_Handle *h,
			     const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
			     const char *name,
			     struct GNUNET_TIME_Absolute freshness,
			     unsigned int rd_count,
			     const struct GNUNET_NAMESTORE_RecordData *rd,
			     const struct GNUNET_CRYPTO_RsaSignature *signature,
			     GNUNET_NAMESTORE_ContinuationWithStatus cont,
			     void *cont_cls);


/**
 * Check if a signature is valid.  This API is used by the GNS Block
 * to validate signatures received from the network.
 *
 * @param public_key public key of the zone
 * @param expire block expiration
 * @param name name that is being mapped (at most 255 characters long)
 * @param rd_count number of entries in 'rd' array
 * @param rd array of records with data to store
 * @param signature signature for all the records in the zone under the given name
 * @return GNUNET_OK if the signature is valid
 */
int
GNUNET_NAMESTORE_verify_signature (const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *public_key,
                                   const struct GNUNET_TIME_Absolute freshness,
                                   const char *name,
                                   unsigned int rd_count,
                                   const struct GNUNET_NAMESTORE_RecordData *rd,
                                   const struct GNUNET_CRYPTO_RsaSignature *signature);


/**
 * Store an item in the namestore.  If the item is already present,
 * the expiration time is updated to the max of the existing time and
 * the new time.  This API is used by the authority of a zone.
 *
 * @param h handle to the namestore
 * @param pkey private key of the zone
 * @param name name that is being mapped (at most 255 characters long)
 * @param rd record data to store
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_record_create (struct GNUNET_NAMESTORE_Handle *h,
                                const struct GNUNET_CRYPTO_RsaPrivateKey *pkey,
                                const char *name,
                                const struct GNUNET_NAMESTORE_RecordData *rd,
                                GNUNET_NAMESTORE_ContinuationWithStatus cont,
                                void *cont_cls);


/**
 * Explicitly remove some content from the database.  The
 * "cont"inuation will be called with status "GNUNET_OK" if content
 * was removed, "GNUNET_NO" if no matching entry was found and
 * "GNUNET_SYSERR" on all other types of errors.
 * This API is used by the authority of a zone.
 *
 * @param h handle to the namestore
 * @param pkey private key of the zone
 * @param name name that is being mapped (at most 255 characters long)
 * @param rd record data, remove specific record,  NULL to remove the name and all records
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_record_remove (struct GNUNET_NAMESTORE_Handle *h,
				const struct GNUNET_CRYPTO_RsaPrivateKey *pkey,
				const char *name,
				const struct GNUNET_NAMESTORE_RecordData *rd,
				GNUNET_NAMESTORE_ContinuationWithStatus cont,
				void *cont_cls);


/**
 * Process a record that was stored in the namestore.
 *
 * @param cls closure
 * @param zone_key public key of the zone
 * @param expire when does the corresponding block in the DHT expire (until
 *               when should we never do a DHT lookup for the same name again)?; 
 *               GNUNET_TIME_UNIT_ZERO_ABS if there are no records of any type in the namestore,
 *               or the expiration time of the block in the namestore (even if there are zero
 *               records matching the desired record type)
 * @param name name that is being mapped (at most 255 characters long)
 * @param rd_count number of entries in 'rd' array
 * @param rd array of records with data to store
 * @param signature signature of the record block, NULL if signature is unavailable (i.e. 
 *        because the user queried for a particular record type only)
 */
typedef void (*GNUNET_NAMESTORE_RecordProcessor) (void *cls,
						  const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
						  struct GNUNET_TIME_Absolute freshness,			    
						  const char *name,
						  unsigned int rd_len,
						  const struct GNUNET_NAMESTORE_RecordData *rd,
						  const struct GNUNET_CRYPTO_RsaSignature *signature);


/**
 * Get a result for a particular key from the namestore.  The processor
 * will only be called once.  
 *
 * @param h handle to the namestore
 * @param zone zone to look up a record from
 * @param name name to look up
 * @param record_type desired record type, 0 for all
 * @param proc function to call on the matching records, or with
 *        NULL (rd_count == 0) if there are no matching records
 * @param proc_cls closure for proc
 * @return a handle that can be used to
 *         cancel
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_lookup_record (struct GNUNET_NAMESTORE_Handle *h, 
			      const struct GNUNET_CRYPTO_ShortHashCode *zone,
			      const char *name,
			      uint32_t record_type,
			      GNUNET_NAMESTORE_RecordProcessor proc, void *proc_cls);


/**
 * Look for an existing PKEY delegation record for a given public key.
 * Returns at most one result to the processor.
 *
 * @param h handle to the namestore
 * @param zone hash of public key of the zone to look up in, never NULL
 * @param value_zone hash of the public key of the target zone (value), never NULL
 * @param proc function to call on the matching records, or with
 *        NULL (rd_count == 0) if there are no matching records
 * @param proc_cls closure for proc
 * @return a handle that can be used to
 *         cancel
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_zone_to_name (struct GNUNET_NAMESTORE_Handle *h, 
			       const struct GNUNET_CRYPTO_ShortHashCode *zone,
			       const struct GNUNET_CRYPTO_ShortHashCode *value_zone,
			       GNUNET_NAMESTORE_RecordProcessor proc, void *proc_cls);



/**
 * Starts a new zone iteration (used to periodically PUT all of our
 * records into our DHT). "proc" will be called once
 * immediately, and then again after
 * "GNUNET_NAMESTORE_zone_iterator_next" is invoked.
 *
 * @param h handle to the namestore
 * @param zone zone to access, NULL for all zones
 * @param must_have_flags flags that must be set for the record to be returned
 * @param must_not_have_flags flags that must NOT be set for the record to be returned
 * @param proc function to call on each name from the zone; it
 *        will be called repeatedly with a value (if available)
 *        and always once at the end with a name of NULL.
 * @param proc_cls closure for proc
 * @return an iterator handle to use for iteration
 */
struct GNUNET_NAMESTORE_ZoneIterator *
GNUNET_NAMESTORE_zone_iteration_start (struct GNUNET_NAMESTORE_Handle *h,
				       const struct GNUNET_CRYPTO_ShortHashCode *zone,
				       enum GNUNET_NAMESTORE_RecordFlags must_have_flags,
				       enum GNUNET_NAMESTORE_RecordFlags must_not_have_flags,
				       GNUNET_NAMESTORE_RecordProcessor proc,
				       void *proc_cls);


/**
 * Calls the record processor specified in GNUNET_NAMESTORE_zone_iteration_start
 * for the next record.
 *
 * @param it the iterator
 */
void
GNUNET_NAMESTORE_zone_iterator_next (struct GNUNET_NAMESTORE_ZoneIterator *it);


/**
 * Stops iteration and releases the namestore handle for further calls.
 *
 * @param it the iterator
 */
void
GNUNET_NAMESTORE_zone_iteration_stop (struct GNUNET_NAMESTORE_ZoneIterator *it);


/**
 * Cancel a namestore operation.  The final callback from the
 * operation must not have been done yet.
 *
 * @param qe operation to cancel
 */
void
GNUNET_NAMESTORE_cancel (struct GNUNET_NAMESTORE_QueueEntry *qe);



/* convenience APIs for serializing / deserializing GNS records */

/**
 * Calculate how many bytes we will need to serialize the given
 * records.
 *
 * @param rd_count number of records in the rd array
 * @param rd array of GNUNET_NAMESTORE_RecordData with rd_count elements
 *
 * @return the required size to serialize
 *
 */
size_t
GNUNET_NAMESTORE_records_get_size (unsigned int rd_count,
				   const struct GNUNET_NAMESTORE_RecordData *rd);

/**
 * Serialize the given records to the given destination buffer.
 *
 * @param rd_count number of records in the rd array
 * @param rd array of GNUNET_NAMESTORE_RecordData with rd_count elements
 * @param dest_size size of the destination array
 * @param dest where to write the result
 *
 * @return the size of serialized records
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
 * @param rd_count number of records in the rd array
 * @param dest where to put the data
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_NAMESTORE_records_deserialize (size_t len,
				      const char *src,
				      unsigned int rd_count,
				      struct GNUNET_NAMESTORE_RecordData *dest);


/**
 * Checks if a name is wellformed
 *
 * @param name the name to check
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_NAMESTORE_check_name (const char * name);

/**
 * Convert the 'value' of a record to a string.
 *
 * @param type type of the record
 * @param data value in binary encoding
 * @param data_size number of bytes in data
 * @return NULL on error, otherwise human-readable representation of the value
 */
char *
GNUNET_NAMESTORE_value_to_string (uint32_t type,
				  const void *data,
				  size_t data_size);


/**
 * Convert human-readable version of a 'value' of a record to the binary
 * representation.
 *
 * @param type type of the record
 * @param s human-readable string
 * @param data set to value in binary encoding (will be allocated)
 * @param data_size set to number of bytes in data
 * @return GNUNET_OK on success
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
GNUNET_NAMESTORE_typename_to_number (const char *typename);


/**
 * Convert a type number (i.e. 1) to the corresponding type string (i.e. "A")
 *
 * @param type number of a type to convert
 * @return corresponding typestring, NULL on error
 */
const char *
GNUNET_NAMESTORE_number_to_typename (uint32_t type);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* end of gnunet_namestore_service.h */
#endif
