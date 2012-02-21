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
 * Disconnect from the namestore service (and free
 * associated resources).
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
 * We formally store records in a B-tree for signing.  This struct
 * identifies the location of a record in the B-tree.
 */
struct GNUNET_NAMESTORE_SignatureLocation
{
  /**
   * Offset in the B-tree.
   */
  uint64_t offset;

  /**
   * Depth in the B-tree.
   */
  uint32_t depth;

  /**
   * Revision of the B-tree.
   */
  uint32_t revision;
};


/**
 * Continuation called to notify client about result of the
 * signing operation.
 *
 * @param cls closure
 * @param sig where the signature is now located in the S-tree
 */
typedef void (*GNUNET_NAMESTORE_ContinuationWithSignature) (void *cls,
							    const struct GNUNET_NAMESTORE_SignatureLocation *sig);





/**
 * Get the hash of a record (what will be signed in the Stree for
 * the record).
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
 * Sign a record.  This function is used by the authority of the zone
 * to add a record.
 *
 * @param h handle to the namestore
 * @param zone_privkey private key of the zone
 * @param record_hash hash of the record to be signed
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_stree_extend (struct GNUNET_NAMESTORE_Handle *h,
			       const struct GNUNET_CRYPTO_RsaPrivateKey *zone_privkey,
			       const GNUNET_HashCode *record_hash,
			       GNUNET_NAMESTORE_ContinuationWithSignature cont,
			       void *cont_cls);


/**
 * Rebalance the signature tree of our zone.  This function should
 * be called "rarely" to rebalance the tree.
 *
 * @param h handle to the namestore
 * @param zone_privkey private key for the zone to rebalance
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_stree_rebalance (struct GNUNET_NAMESTORE_Handle *h,
				  const struct GNUNET_CRYPTO_RsaPrivateKey *zone_privkey,
				  GNUNET_NAMESTORE_ContinuationWithStatus cont,
				  void *cont_cls);


/**
 * Provide the root of a signature tree.  This function is 
 * used by non-authorities as the first operation when 
 * adding a foreign zone.
 *
 * @param h handle to the namestore
 * @param zone_key public key of the zone
 * @param signature signature of the top-level entry of the zone
 * @param revision revision number of the zone
 * @param top_hash top-level hash of the zone
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_stree_start (struct GNUNET_NAMESTORE_Handle *h,
			      const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
			      const struct GNUNET_CRYPTO_RsaSignature *signature,
			      uint32_t revision,
			      const GNUNET_HashCode *top_hash,
			      GNUNET_NAMESTORE_ContinuationWithSignature cont,
			      void *cont_cls);


/**
 * Store part of a signature B-tree in the namestore.  This function
 * is used by non-authorities to cache parts of a zone's signature tree.
 * Note that the tree must be build top-down.  This function must check
 * that the nodes being added are valid, and if not refuse the operation.
 *
 * @param h handle to the namestore
 * @param zone_key public key of the zone
 * @param loc location in the B-tree
 * @param ploc parent's location in the B-tree (must have depth = loc.depth - 1)
 * @param num_entries number of entries at this node in the B-tree
 * @param entries the 'num_entries' entries to store (hashes over the
 *                records)
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_stree_put (struct GNUNET_NAMESTORE_Handle *h,
			    const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
			    const struct GNUNET_NAMESTORE_SignatureLocation *loc,
			    const struct GNUNET_NAMESTORE_SignatureLocation *ploc,
			    unsigned int num_entries,
			    const GNUNET_HashCode *entries,
			    GNUNET_NAMESTORE_ContinuationWithStatus cont,
			    void *cont_cls);


/**
 * Store current zone signature in the namestore.  This function
 * is used by non-authorities to cache the top of a zone's signature tree.
 * Note that the tree must be build top-down, so this function is called
 * first for a given zone and revision.
 *
 * @param h handle to the namestore
 * @param zone_key public key of the zone
 * @param loc identifies the top of the B-tree (depth and revision)
 * @param time time of the signature creation
 * @param top_sig signature at the top
 * @param root_hash top level hash code in the Merkle-tree / stree
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @return handle to abort the request
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_signature_put (struct GNUNET_NAMESTORE_Handle *h,
				const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
				const struct GNUNET_NAMESTORE_SignatureLocation *loc,
				struct GNUNET_TIME_Absolute time,
				const struct GNUNET_CRYPTO_RsaSignature *top_sig,
				const GNUNET_HashCode *root_hash,
				GNUNET_NAMESTORE_ContinuationWithStatus cont,
				void *cont_cls);


/**
 * Store an item in the namestore.  If the item is already present,
 * the expiration time is updated to the max of the existing time and
 * the new time.  The operation must fail if there is no matching
 * entry in the signature tree.
 *
 * @param h handle to the namestore
 * @param zone hash of the public key of the zone
 * @param name name that is being mapped (at most 255 characters long)
 * @param record_type type of the record (A, AAAA, PKEY, etc.)
 * @param expiration expiration time for the content
 * @param flags flags for the content
 * @param sig_loc where is the information about the signature for this record stored?
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
			     const struct GNUNET_NAMESTORE_SignatureLocation *sig_loc,
			     size_t data_size,
			     const void *data, 
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
 * @param sig_loc where is the information about the signature for this record stored?
 * @param size number of bytes in data
 * @param data content stored
 */
typedef void (*GNUNET_NAMESTORE_RecordProcessor) (void *cls,
                                                 const GNUNET_HashCode *zone,
						 const char *name,
						 uint32_t record_type,
						 struct GNUNET_TIME_Absolute expiration,
						 enum GNUNET_NAMESTORE_RecordFlags flags,
						 const struct GNUNET_NAMESTORE_SignatureLocation *sig_loc,
						 size_t size, const void *data);


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
GNUNET_NAMESTORE_lookup_name (struct GNUNET_NAMESTORE_Handle *h, 
			      const GNUNET_HashCode *zone,
			      const char *name,
			      uint32_t record_type,
			      GNUNET_NAMESTORE_RecordProcessor proc, void *proc_cls);



/**
 * Get the hash of a subtree in the STree (what will be signed in the parent
 * location). FIXME naming conflict!
 *
 * @param zone hash of the public key of the zone
 * @param loc where we are in the signature tree
 * @param num_entries number of entries being stored here
 * @param entries the entries themselves
 * @param st_hash hash of the stree node (set)
 */
void
GNUNET_NAMESTORE_record_hash_dup (struct GNUNET_NAMESTORE_Handle *h,
			      const GNUNET_HashCode *zone,
			      const struct GNUNET_NAMESTORE_SignatureLocation *loc,
			      unsigned int num_entries,
			      const GNUNET_HashCode *entries,
			      GNUNET_HashCode *st_hash);


/**
 * Process a Stree node that was stored in the namestore.
 *
 * @param cls closure
 * @param zone hash of the public key of the zone
 * @param loc where we are in the signature tree
 * @param ploc location of our parent in the signature tree
 * @param num_entries number of entries being stored here
 * @param entries the entries themselves
 */
typedef void (*GNUNET_NAMESTORE_StreeProcessor) (void *cls,
                                                 const GNUNET_HashCode *zone,
						 const struct GNUNET_NAMESTORE_SignatureLocation *loc,
						 const struct GNUNET_NAMESTORE_SignatureLocation *ploc,
						 unsigned int num_entries,
						 const GNUNET_HashCode *entries);


/**
 * Obtain part of a signature B-tree.  The processor
 * will only be called once.
 *
 * @param h handle to the namestore
 * @param zone zone to look up a record from
 * @param sig_loc location to look up
 * @param proc function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param proc_cls closure for proc
 * @return a handle that can be used to
 *         cancel
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_lookup_stree (struct GNUNET_NAMESTORE_Handle *h, 
			       const GNUNET_HashCode *zone,
			       const struct GNUNET_NAMESTORE_SignatureLocation *sig_loc,
			       GNUNET_NAMESTORE_StreeProcessor proc, void *proc_cls);

/**
 * Process zone signature information that was stored in the namestore.
 *
 * @param cls closure
 * @param zone hash of the public key of the zone
 * @param loc where we are in the signature tree (identifies top)
 * @param top_sig signature at the root
 * @param time timestamp of the signature
 * @param top_hash hash at the top of the tree
 */
typedef void (*GNUNET_NAMESTORE_SignatureProcessor) (void *cls,
						     const GNUNET_HashCode *zone,
						     const struct GNUNET_NAMESTORE_SignatureLocation *loc,
						     const struct GNUNET_CRYPTO_RsaSignature *top_sig,
						     struct GNUNET_TIME_Absolute time,
						     const GNUNET_HashCode *top_hash);


/**
 * Obtain latest/current signature of a zone.  The processor
 * will only be called once.
 *
 * @param h handle to the namestore
 * @param zone zone to look up a record from
 * @param proc function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param proc_cls closure for proc
 * @return a handle that can be used to
 *         cancel
 */
struct GNUNET_NAMESTORE_QueueEntry *
GNUNET_NAMESTORE_lookup_stree (struct GNUNET_NAMESTORE_Handle *h, 
			       const GNUNET_HashCode *zone,
			       GNUNET_NAMESTORE_StreeProcessor proc, void *proc_cls);


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
