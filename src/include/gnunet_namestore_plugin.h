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
 * @param zone_key public key of the zone
 * @param expire when does the corresponding block in the DHT expire (until
 *               when should we never do a DHT lookup for the same name again)?
 * @param name name that is being mapped (at most 255 characters long)
 * @param rd_count number of entries in 'rd' array
 * @param rd array of records with data to store
 * @param signature signature of the record block, NULL if signature is unavailable (i.e. 
 *        because the user queried for a particular record type only)
 */
typedef void (*GNUNET_NAMESTORE_RecordIterator) (void *cls,
						 const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
						 struct GNUNET_TIME_Absolute expire,
						 const char *name,
						 unsigned int rd_count,
						 const struct GNUNET_NAMESTORE_RecordData *rd,
						 const struct GNUNET_CRYPTO_RsaSignature *signature);


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
   * Store a record in the datastore.  Removes any existing record in the
   * same zone with the same name.
   *
   * @param cls closure (internal context for the plugin)
   * @param zone_key public key of the zone
   * @param expire when does the corresponding block in the DHT expire (until
   *               when should we never do a DHT lookup for the same name again)?
   * @param name name that is being mapped (at most 255 characters long)
   * @param rd_count number of entries in 'rd' array
   * @param rd array of records with data to store
   * @param signature signature of the record block, NULL if signature is unavailable (i.e. 
   *        because the user queried for a particular record type only)
   * @return GNUNET_OK on success
   */
  int (*put_records) (void *cls, 
		      const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *zone_key,
		      struct GNUNET_TIME_Absolute expire,
		      const char *name,
		      unsigned int rd_count,
		      const struct GNUNET_NAMESTORE_RecordData *rd,
		      const struct GNUNET_CRYPTO_RsaSignature *signature);


  /**
   * Removes any existing record in the given zone with the same name.
   *
   * @param cls closure (internal context for the plugin)
   * @param zone hash of the public key of the zone
   * @param name name to remove (at most 255 characters long)
   * @return GNUNET_OK on success
   */
  int (*remove_records) (void *cls, 
			 const GNUNET_HashCode *zone,
			 const char *name);


  /**
   * Iterate over the results for a particular key and zone in the
   * datastore.  Will return at most one result to the iterator.
   *
   * @param cls closure (internal context for the plugin)
   * @param zone hash of public key of the zone, NULL to iterate over all zones
   * @param name_hash hash of name, NULL to iterate over all records of the zone
   * @param offset offset in the list of all matching records
   * @param iter function to call with the result
   * @param iter_cls closure for iter
   * @return GNUNET_OK on success, GNUNET_NO if there were no results, GNUNET_SYSERR on error
   */
  int (*iterate_records) (void *cls, 
			  const GNUNET_HashCode *zone,
			  const GNUNET_HashCode *name_hash,
			  uint64_t offset,
			  GNUNET_NAMESTORE_RecordIterator iter, void *iter_cls);


  /**
   * Delete an entire zone (all records).  Not used in normal operation.
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
