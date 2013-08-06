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
 * @author Christian Grothoff
 *
 * Other functions we might want:
 * - enumerate all known zones
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
 * Record type for zone revocation
 */
#define GNUNET_NAMESTORE_TYPE_REV 65540

/**
 * Record type for a social place.
 */
#define GNUNET_NAMESTORE_TYPE_PLACE 65541

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
 */
void
GNUNET_NAMESTORE_disconnect (struct GNUNET_NAMESTORE_Handle *h);


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
   * 'GNUNET_NAMESTORE_records_cmp'.
   */
#define GNUNET_NAMESTORE_RF_RCMP_FLAGS (GNUNET_NAMESTORE_RF_RELATIVE_EXPIRATION)
};


/**
 * A GNS record.
 */
struct GNUNET_NAMESTORE_RecordData
{

  /**
   * Binary value stored in the DNS record.
   * FIXME: goofy API: sometimes 'data' is individually
   * 'malloc'ed, sometimes it points into some existing
   * data area (so sometimes this should be a 'void *',
   * sometimes a 'const void *').  This is unclean.
   */
  const void *data;

  /**
   * Expiration time for the DNS record.  Can be relative
   * or absolute, depending on 'flags'.
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


/**
 * Store an item in the namestore.  If the item is already present,
 * it is replaced with the new record.  Use an empty array to
 * remove all records under the given name.
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
			     const struct GNUNET_CRYPTO_EccPublicKey *zone_key,
			     const char *name,
			     struct GNUNET_TIME_Absolute freshness,
			     unsigned int rd_count,
			     const struct GNUNET_NAMESTORE_RecordData *rd,
			     const struct GNUNET_CRYPTO_EccSignature *signature,
			     GNUNET_NAMESTORE_ContinuationWithStatus cont,
			     void *cont_cls);


/**
 * Check if a signature is valid.  This API is used by the GNS Block
 * to validate signatures received from the network.
 *
 * @param public_key public key of the zone
 * @param freshness time set for block expiration
 * @param name name that is being mapped (at most 255 characters long)
 * @param rd_count number of entries in 'rd' array
 * @param rd array of records with data to store
 * @param signature signature for all the records in the zone under the given name
 * @return GNUNET_OK if the signature is valid
 */
int
GNUNET_NAMESTORE_verify_signature (const struct GNUNET_CRYPTO_EccPublicKey *public_key,
                                   const struct GNUNET_TIME_Absolute freshness,
                                   const char *name,
                                   unsigned int rd_count,
                                   const struct GNUNET_NAMESTORE_RecordData *rd,
                                   const struct GNUNET_CRYPTO_EccSignature *signature);


/**
 * Store an item in the namestore.  If the item is already present,
 * it is replaced with the new record.  Use an empty array to
 * remove all records under the given name.
 *
 * @param h handle to the namestore
 * @param pkey private key of the zone
 * @param name name that is being mapped (at most 255 characters long)
 * @param rd_count number of records in the 'rd' array
 * @param rd array of records with data to store
 * @param cont continuation to call when done
 * @param cont_cls closure for 'cont'
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_record_put_by_authority (struct GNUNET_NAMESTORE_Handle *h,
					  const struct GNUNET_CRYPTO_EccPrivateKey *pkey,
					  const char *name,
					  unsigned int rd_count,
					  const struct GNUNET_NAMESTORE_RecordData *rd,
					  GNUNET_NAMESTORE_ContinuationWithStatus cont,
					  void *cont_cls);


/**
 * Process a record that was stored in the namestore.
 *
 * @param cls closure
 * @param zone_key public key of the zone
 * @param freshness when does the corresponding block in the DHT expire (until
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
						  const struct GNUNET_CRYPTO_EccPublicKey *zone_key,
						  struct GNUNET_TIME_Absolute freshness,			    
						  const char *name,
						  unsigned int rd_count,
						  const struct GNUNET_NAMESTORE_RecordData *rd,
						  const struct GNUNET_CRYPTO_EccSignature *signature);


/**
 * Get a result for a particular key from the namestore.  The processor
 * will only be called once.  When using this functions, relative expiration
 * times will be converted to absolute expiration times and a signature
 * will be created if we are the authority.  The record data and signature
 * passed to 'proc' is thus always suitable for passing on to other peers
 * (if we are the authority).  If the record type is NOT set to 'ANY' and
 * if we are NOT the authority, then non-matching records may be omitted
 * from the result and no valid signature can be created; in this case,
 * 'signature' will be NULL and the result cannot be given to other peers.
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
 * Cancel a namestore operation.  The final callback from the
 * operation must not have been done yet.  Must be called on any
 * namestore operation that has not yet completed prior to calling
 * 'GNUNET_NAMESTORE_disconnect'.
 *
 * @param qe operation to cancel
 */
void
GNUNET_NAMESTORE_cancel (struct GNUNET_NAMESTORE_QueueEntry *qe);


/**
 * Starts a new zone iteration (used to periodically PUT all of our
 * records into our DHT). "proc" will be called once immediately, and
 * then again after "GNUNET_NAMESTORE_zone_iterator_next" is invoked.
 *
 * By specifying a 'zone' of NULL and setting 'GNUNET_NAMESTORE_RF_AUTHORITY'
 * in 'must_have_flags', we can iterate over all records for which we are
 * the authority (the 'authority' flag will NOT be set in the returned
 * records anyway).  
 *
 * The 'GNUNET_NAMESTORE_RF_RELATIVE_EXPIRATION'
 * bit in 'must_have_flags' has a special meaning:
 *
 * 0) If the bit is clear, all relative expriation times are converted to
 *    absolute expiration times.  This is useful for performing DHT PUT
 *    operations (and zone transfers) of our zone.  The generated signatures
 *    will be valid for other peers.
 * 1) if it is set, it means that relative expiration times should be
 *    preserved when returned (this is useful for the zone editor user 
 *    interface).  No signatures will be created in this case, as 
 *    signatures must not cover records with relative expiration times.
 *
 * Note that not all queries against this interface are equally performant
 * as for some combinations no efficient index may exist.
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
 * Stops iteration and releases the namestore handle for further calls.  Must
 * be called on any iteration that has not yet completed prior to calling
 * 'GNUNET_NAMESTORE_disconnect'.
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
 * Function called whenever the records for a given name changed.
 *
 * @param cls closure
 * @param zone_key NULL if the communication with the namestore broke down
 *                    (and thus all entries should be 'cleared' until the communication
 *                     can be re-established, at which point the monitor will 
 *                     re-add all records that are (still) in the namestore after
 *                     the reconnect); if this value is NULL, all other arguments
 *                     will also be 0/NULL.
 * @param freshness when does the corresponding block in the DHT expire (until
 *               when should we never do a DHT lookup for the same name again)?; 
 *               GNUNET_TIME_UNIT_ZERO_ABS if there are no records of any type in the namestore,
 *               or the expiration time of the block in the namestore (even if there are zero
 *               records matching the desired record type)
 * @param name name that is being mapped (at most 255 characters long)
 * @param rd_count number of entries in 'rd' array
 * @param rd array of records with data to store
 * @param signature signature of the record block
 */
typedef void (*GNUNET_NAMESTORE_RecordMonitor)(void *cls,
					       const struct GNUNET_CRYPTO_EccPublicKey *zone_key,
					       struct GNUNET_TIME_Absolute freshness,			    
					       const char *name,
					       unsigned int rd_len,
					       const struct GNUNET_NAMESTORE_RecordData *rd,
					       const struct GNUNET_CRYPTO_EccSignature *signature);


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
 * Begin monitoring a zone for changes.  Will first call the 'monitor' function
 * on all existing records in the selected zone(s), then calls 'sync_cb',
 * and then calls the 'monitor' whenever a record changes.  If the namestore
 * disconnects, the 'monitor' function is called with a disconnect event; if
 * the connection is re-established, the process begins from the start (all
 * existing records, sync, then updates).
 *
 * Note that the 'signature' in the 'monitor' callback will always be
 * NULL (as signatures are usually not valuable to monitoring clients,
 * the service does not bother to generate a valid signature for
 * monitoring).
 *
 * @param cfg configuration to use to connect to namestore
 * @param zone zone to monitor, NULL for all zones
 * @param monitor function to call on zone changes
 * @param sync_cb function called when we're in sync with the namestore
 * @param cls closure for 'monitor' and 'sync_cb'
 * @return handle to stop monitoring
 */
struct GNUNET_NAMESTORE_ZoneMonitor *
GNUNET_NAMESTORE_zone_monitor_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
				     const struct GNUNET_CRYPTO_ShortHashCode *zone,
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


/**
 * Test if a given record is expired.
 * 
 * @param rd record to test
 * @return GNUNET_YES if the record is expired,
 *         GNUNET_NO if not
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
 * Convert a short hash to a string (for printing debug messages).
 * This is one of the very few calls in the entire API that is
 * NOT reentrant!
 *
 * @param hc the short hash code
 * @return string form; will be overwritten by next call to GNUNET_h2s.
 */
const char *
GNUNET_NAMESTORE_short_h2s (const struct GNUNET_CRYPTO_ShortHashCode * hc);


/**
 * Sign name and records
 *
 * @param key the private key
 * @param expire block expiration
 * @param name the name
 * @param rd record data
 * @param rd_count number of records
 *
 * @return the signature
 */
struct GNUNET_CRYPTO_EccSignature *
GNUNET_NAMESTORE_create_signature (const struct GNUNET_CRYPTO_EccPrivateKey *key,
				   struct GNUNET_TIME_Absolute expire,
				   const char *name,
				   const struct GNUNET_NAMESTORE_RecordData *rd,
				   unsigned int rd_count);


/**
 * Compares if two records are equal
 *
 * @param a Record a
 * @param b Record b
 *
 * @return GNUNET_YES or GNUNET_NO
 */
int
GNUNET_NAMESTORE_records_cmp (const struct GNUNET_NAMESTORE_RecordData *a,
                              const struct GNUNET_NAMESTORE_RecordData *b);




#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* end of gnunet_namestore_service.h */
#endif
