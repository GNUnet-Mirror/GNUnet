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
 *                GNUNET_NO if content was already there
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
  GNUNET_NAMESTORE_RF_PRIVATE = 2

};


/**
 * Get the hash of a record
 *
 * @param zone hash of the public key of the zone
 * @param name name that is being mapped (at most 255 characters long)
 * @param record_type type of the record (A, AAAA, PKEY, etc.)
 * @param expiration expiration time for the content
 * @param flags flags for the content
 * @param data_size number of bytes in data
 * @param data value, semantics depend on 'record_type' (see RFCs for DNS and 
 *             GNS specification for GNS extensions)
 * @param record_hash hash of the record (set)
 */
void
GNUNET_NAMESTORE_record_hash (struct GNUNET_NAMESTORE_Handle *h,
			      const GNUNET_HashCode *zone,
			      const char *name,
			      uint32_t record_type,
			      struct GNUNET_TIME_Absolute expiration,
			      enum GNUNET_NAMESTORE_RecordFlags flags,
			      size_t data_size,
			      const void *data, 
			      GNUNET_HashCode *record_hash);


/**
 * Store an item in the namestore.  If the item is already present,
 * the expiration time is updated to the max of the existing time and
 * the new time.
 *
 * @param h handle to the namestore
 * @param zone hash of the public key of the zone
 * @param name name that is being mapped (at most 255 characters long)
 * @param record_type type of the record (A, AAAA, PKEY, etc.)
 * @param expiration expiration time for the content
 * @param flags flags for the content
 * @param data_size number of bytes in data
 * @param data value, semantics depend on 'record_type' (see RFCs for DNS and 
 *             GNS specification for GNS extensions)
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_record_put (struct GNUNET_NAMESTORE_Handle *h,
			     const GNUNET_HashCode *zone,
			     const char *name,
			     uint32_t record_type,
			     struct GNUNET_TIME_Absolute expiration,
			     enum GNUNET_NAMESTORE_RecordFlags flags,
			     size_t data_size,
			     const void *data, 
			     GNUNET_NAMESTORE_ContinuationWithStatus cont,
			     void *cont_cls);

/**
 * Store a signature for 'name' in the namestore.
 * Used by non-authorities to store signatures for cached name records.
 *
 * @param h handle to the namestore
 * @param zone hash of the public key of the zone
 * @param name name that is being mapped (at most 255 characters long)
 * @param sig the signature
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_signature_put (struct GNUNET_NAMESTORE_Handle *h,
                                const GNUNET_HashCode *zone,
                                const char *name,
                                struct GNUNET_CRYPTO_RsaSignature sig,
                                GNUNET_NAMESTORE_ContinuationWithStatus cont,
                                void *cont_cls);


/**
 * Explicitly remove some content from the database.  The
 * "cont"inuation will be called with status "GNUNET_OK" if content
 * was removed, "GNUNET_NO" if no matching entry was found and
 * "GNUNET_SYSERR" on all other types of errors.
 *
 * @param h handle to the namestore
 * @param zone hash of the public key of the zone
 * @param name name that is being mapped (at most 255 characters long)
 * @param record_type type of the record (A, AAAA, PKEY, etc.)
 * @param size number of bytes in data
 * @param data content stored
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_record_remove (struct GNUNET_NAMESTORE_Handle *h,
				const GNUNET_HashCode *zone, 
				const char *name,
				uint32_t record_type,
				size_t size,
				const void *data, 
				GNUNET_NAMESTORE_ContinuationWithStatus cont,
				void *cont_cls);


/**
 * Process a record that was stored in the namestore.
 *
 * @param cls closure
 * @param zone hash of the public key of the zone
 * @param name name that is being mapped (at most 255 characters long)
 * @param record_type type of the record (A, AAAA, PKEY, etc.)
 * @param expiration expiration time for the content
 * @param flags flags for the content
 * @param size number of bytes in data
 * @param data content stored
 */
typedef void (*GNUNET_NAMESTORE_RecordProcessor) (void *cls,
                                                 const GNUNET_HashCode *zone,
						 const char *name,
						 uint32_t record_type,
						 struct GNUNET_TIME_Absolute expiration,
						 enum GNUNET_NAMESTORE_RecordFlags flags,
						 size_t size, const void *data);

/**
 * Process a signature for a given name
 *
 * @param cls closure
 * @param zone hash of the public key of the zone
 * @param name name of the records that were signed
 * @param sig the signature
 */
typedef void (*GNUNET_NAMESTORE_SignatureProcessor) (void *cls,
                                         const GNUNET_HashCode *zone,
                                         const char *name,
                                         struct GNUNET_CRYPTO_RsaSignature sig);



/**
 * Get a result for a particular key from the namestore.  The processor
 * will only be called once.
 *
 * @param h handle to the namestore
 * @param zone zone to look up a record from
 * @param name name to look up
 * @param record_type desired record type
 * @param proc function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param proc_cls closure for proc
 * @return a handle that can be used to
 *         cancel
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_lookup_record (struct GNUNET_NAMESTORE_Handle *h, 
			      const GNUNET_HashCode *zone,
			      const char *name,
			      uint32_t record_type,
			      GNUNET_NAMESTORE_RecordProcessor proc, void *proc_cls);


/**
 * Obtain latest/current signature of a zone's name.  The processor
 * will only be called once.
 *
 * @param h handle to the namestore
 * @param zone zone to look up a signature from
 * @param the common name of the records the signature is for
 * @param proc function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param proc_cls closure for proc
 * @return a handle that can be used to
 *         cancel
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_lookup_signature (struct GNUNET_NAMESTORE_Handle *h, 
				   const GNUNET_HashCode *zone,
           const char* name,
				   GNUNET_NAMESTORE_SignatureProcessor proc, void *proc_cls);


/**
 * Get all records of a zone.
 *
 * @param h handle to the namestore
 * @param zone zone to access
 * @param proc function to call on a random value; it
 *        will be called repeatedly with a value (if available)
 *        and always once at the end with a zone and name of NULL.
 * @param proc_cls closure for proc
 * @return a handle that can be used to
 *         cancel
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_zone_transfer (struct GNUNET_NAMESTORE_Handle *h,
				const GNUNET_HashCode *zone,
				GNUNET_NAMESTORE_RecordProcessor proc,
				void *proc_cls);


/**
 * Starts a new zone iteration. This MUST lock the GNUNET_NAMESTORE_Handle
 * for any other calls than 
 * GNUNET_NAMESTORE_zone_iterator_next
 * and
 * GNUNET_NAMESTORE_zone_iteration_stop
 *
 * @param h handle to the namestore
 * @param zone zone to access
 * @param proc function to call on a random value; it
 *        will be called repeatedly with a value (if available)
 *        and always once at the end with a zone and name of NULL.
 * @param proc_cls closure for proc
 * @return an iterator handle to use for iteration
 */
struct GNUNET_NAMESTORE_ZoneIterator *
GNUNET_NAMESTORE_zone_iteration_start(struct GNUNET_NAMESTORE_Handle *h,
                                      const GNUNET_HashCode *zone,
                                      GNUNET_NAMESTORE_RecordProcessor proc,
                                      void *proc_cls);

/**
 * Calls the record processor specified in GNUNET_NAMESTORE_zone_iteration_start
 * for the next record.
 *
 * @param it the iterator
 * @return 0 if no more records are available to iterate
 */
int
GNUNET_NAMESTORE_zone_iterator_next(struct GNUNET_NAMESTORE_ZoneIterator *it);

/**
 * Stops iteration and releases the namestore handle for further calls.
 *
 * @param it the iterator
 */
void
GNUNET_NAMESTORE_zone_iteration_stop(struct GNUNET_NAMESTORE_ZoneIterator *it);


/**
 * Cancel a namestore operation.  The final callback from the
 * operation must not have been done yet.
 *
 * @param qe operation to cancel
 */
void
GNUNET_NAMESTORE_cancel (struct GNUNET_NAMESTORE_QueueEntry *qe);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* end of gnunet_namestore_service.h */
#endif
