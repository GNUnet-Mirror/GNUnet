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
 * @file include/gnunet_namestore_plugin.h
 * @brief plugin API for the namestore database backend
 * @author Christian Grothoff
 *
 * Other functions we might want:
 * - enumerate all known zones
 */
#ifndef GNUNET_NAMESTORE_PLUGIN_H
#define GNUNET_NAMESTORE_PLUGIN_H

#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_namestore_service.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Function called by for each matching record.
 *
 * @param cls closure
 * @param zone hash of the public key of the zone
 * @param loc location of the signature for this record
 * @param name name that is being mapped (at most 255 characters long)
 * @param record_type type of the record (A, AAAA, PKEY, etc.)
 * @param expiration expiration time for the content
 * @param flags flags for the content
 * @param data_size number of bytes in data
 * @param data value, semantics depend on 'record_type' (see RFCs for DNS and 
 *             GNS specification for GNS extensions) 
 */
typedef void (*GNUNET_NAMESTORE_RecordIterator) (void *cls,
						 const GNUNET_HashCode *zone,
						 const struct GNUNET_NAMESTORE_SignatureLocation *loc,
						 const char *name,
						 uint32_t record_type,
						 struct GNUNET_TIME_Absolute expiration,
						 enum GNUNET_NAMESTORE_RecordFlags flags,
						 size_t data_size,
						 const void *data);


/**
 * Function called with the matching node.
 *
 * @param cls closure
 * @param zone hash of public key of the zone
 * @param loc location in the B-tree
 * @param ploc parent's location in the B-tree (must have depth = loc.depth - 1), NULL for root
 * @param num_entries number of entries at this node in the B-tree
 * @param entries the 'num_entries' entries to store (hashes over the
 *                records)
 */
typedef void (*GNUNET_NAMESTORE_NodeCallback) (void *cls,
					       const GNUNET_HashCode *zone,
					       const struct GNUNET_NAMESTORE_SignatureLocation *loc,
					       const struct GNUNET_NAMESTORE_SignatureLocation *ploc,
					       unsigned int num_entries,
					       const GNUNET_HashCode *entries);


/**
 * Function called with the matching signature.
 *
 * @param cls closure
 * @param zone public key of the zone
 * @param loc location of the root in the B-tree (depth, revision)
 * @param top_sig signature signing the zone
 * @param zone_time time the signature was created
 * @param root_hash top level hash that is being signed
 */
typedef void (*GNUNET_NAMESTORE_SignatureCallback) (void *cls,
						    const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
						    const struct GNUNET_NAMESTORE_SignatureLocation *loc,
						    const struct GNUNET_CRYPTO_RsaSignature *top_sig,
						    struct GNUNET_TIME_Absolute zone_time,
						    const GNUNET_HashCode *root_hash);


/**
 * @brief struct returned by the initialization function of the plugin
 */
struct GNUNET_NAMESTORE_PluginFunctions
{

  /**
   * Closure to pass to all plugin functions.
   */
  void *cls;

  /**
   * Store a record in the datastore.
   *
   * @param cls closure (internal context for the plugin)
   * @param zone hash of the public key of the zone
   * @param name name that is being mapped (at most 255 characters long)
   * @param record_type type of the record (A, AAAA, PKEY, etc.)
   * @param loc location of the signature for the record
   * @param expiration expiration time for the content
   * @param flags flags for the content
   * @param data_size number of bytes in data
   * @param data value, semantics depend on 'record_type' (see RFCs for DNS and 
   *             GNS specification for GNS extensions)
   * @return GNUNET_OK on success
   */
  int (*put_record) (void *cls, 
		     const GNUNET_HashCode *zone,
		     const char *name,
		     uint32_t record_type,
		     const struct GNUNET_NAMESTORE_SignatureLocation *loc,
		     struct GNUNET_TIME_Absolute expiration,
		     enum GNUNET_NAMESTORE_RecordFlags flags,
		     size_t data_size,
		     const void *data);


  /**
   * Store a Merkle tree node in the datastore.
   *
   * @param cls closure (internal context for the plugin)
   * @param zone hash of public key of the zone
   * @param loc location in the B-tree
   * @param ploc parent's location in the B-tree (must have depth = loc.depth + 1) and the
   *             revision must also match loc's revision; NULL for root
   * @param num_entries number of entries at this node in the B-tree
   * @param entries the 'num_entries' entries to store (hashes over the
   *                records)
   * @return GNUNET_OK on success
   */
  int (*put_node) (void *cls, 
		   const GNUNET_HashCode *zone,
		   const struct GNUNET_NAMESTORE_SignatureLocation *loc,
		   const struct GNUNET_NAMESTORE_SignatureLocation *ploc,
		   unsigned int num_entries,
		   const GNUNET_HashCode *entries);
  

  /**
   * Store a zone signature in the datastore.  If a signature for the zone with a
   * lower depth exists, the old signature is removed.  If a signature for an
   * older revision of the zone exists, this will delete all records, nodes
   * and signatures for the older revision of the zone.
   *
   * @param cls closure (internal context for the plugin)
   * @param zone_key public key of the zone
   * @param loc location in the B-tree (top of the tree, offset 0, depth at 'maximum')
   * @param top_sig signature at the top
   * @param root_hash top level hash that is signed
   * @param zone_time time the zone was signed
   * @return GNUNET_OK on success
   */
  int (*put_signature) (void *cls, 
			const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
			const struct GNUNET_NAMESTORE_SignatureLocation *loc,
			const struct GNUNET_CRYPTO_RsaSignature *top_sig,
			const GNUNET_HashCode *root_hash,
			struct GNUNET_TIME_Absolute zone_time);
  
  
  /**
   * Iterate over the results for a particular key and zone in the
   * datastore.  Will only query the latest revision known for the
   * zone (as adding a new zone revision will cause the plugin to
   * delete all records from previous revisions).
   *
   * @param cls closure (internal context for the plugin)
   * @param zone hash of public key of the zone
   * @param name_hash hash of name, NULL to iterate over all records of the zone
   * @param iter maybe NULL (to just count)
   * @param iter_cls closure for iter
   * @return the number of results found
   */
  unsigned int (*iterate_records) (void *cls, 
				   const GNUNET_HashCode *zone,
				   const GNUNET_HashCode *name_hash,
				   GNUNET_NAMESTORE_RecordIterator iter, void *iter_cls);

 
  /**
   * Get a particular node from the signature tree.
   *
   * @param cls closure (internal context for the plugin)
   * @param zone hash of public key of the zone
   * @param loc location of the node in the signature tree
   * @param cb function to call with the result
   * @param cb_cls closure for cont
   */
  void (*get_node) (void *cls, 
		    const GNUNET_HashCode *zone,
		    const struct GNUNET_NAMESTORE_SignatureLocation *loc,
		    GNUNET_NAMESTORE_NodeCallback cb, void *cb_cls);


  /**
   * Get the current signature for a zone.
   *
   * @param cls closure (internal context for the plugin)
   * @param zone hash of public key of the zone
   * @param cb function to call with the result
   * @param cb_cls closure for cont
   */
  void (*get_signature) (void *cls, 
			 const GNUNET_HashCode *zone,
			 GNUNET_NAMESTORE_SignatureCallback cb, void *cb_cls);


  /**
   * Delete an entire zone (all revisions, all records, all nodes,
   * all signatures).  Not used in normal operation.
   *
   * @param cls closure (internal context for the plugin)
   * @param zone zone to delete
   */
  void (*delete_zone) (void *cls,
		       const GNUNET_HashCode *zone);


};


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* end of gnunet_namestore_plugin.h */
#endif
