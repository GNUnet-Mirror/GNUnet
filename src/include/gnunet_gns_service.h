/*
      This file is part of GNUnet
      Copyright (C) 2012-2014, 2017 GNUnet e.V.

      GNUnet is free software: you can redistribute it and/or modify it
      under the terms of the GNU Affero General Public License as published
      by the Free Software Foundation, either version 3 of the License,
      or (at your option) any later version.

      GNUnet is distributed in the hope that it will be useful, but
      WITHOUT ANY WARRANTY; without even the implied warranty of
      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
      Affero General Public License for more details.
     
      You should have received a copy of the GNU Affero General Public License
      along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @author Martin Schanzenbach
 *
 * @file
 * API to the GNS service
 *
 * @defgroup gns  GNS service
 * GNU Name System
 *
 * @see [Documentation](https://gnunet.org/gns-implementation)
 *
 * @{
 */
#ifndef GNUNET_GNS_SERVICE_H
#define GNUNET_GNS_SERVICE_H

#include "gnunet_util_lib.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_namestore_service.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * String we use to indicate an empty label (top-level
 * entry in the zone).  DNS uses "@", so do we.
 */
#define GNUNET_GNS_EMPTY_LABEL_AT "@"

/**
 * Connection to the GNS service.
 */
struct GNUNET_GNS_Handle;

/**
 * Handle to control a lookup operation.
 */
struct GNUNET_GNS_LookupRequest;

/**
 * Handle to control a lookup operation where the
 * TLD is resolved to a zone as part of the lookup operation.
 */
struct GNUNET_GNS_LookupWithTldRequest;


/**
 * Initialize the connection with the GNS service.
 *
 * @param cfg configuration to use
 * @return handle to the GNS service, or NULL on error
 */
struct GNUNET_GNS_Handle *
GNUNET_GNS_connect (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Shutdown connection with the GNS service.
 *
 * @param handle connection to shut down
 */
void
GNUNET_GNS_disconnect (struct GNUNET_GNS_Handle *handle);


/**
 * Iterator called on obtained result for a GNS lookup.
 *
 * @param cls closure
 * @param rd_count number of records in @a rd
 * @param rd the records in reply
 */
typedef void
(*GNUNET_GNS_LookupResultProcessor) (void *cls,
                                     uint32_t rd_count,
                                     const struct GNUNET_GNSRECORD_Data *rd);


/**
 * Options for the GNS lookup.
 */
enum GNUNET_GNS_LocalOptions
{
  /**
   * Defaults, look in cache, then in DHT.
   */
  GNUNET_GNS_LO_DEFAULT = 0,

  /**
   * Never look in the DHT, keep request to local cache.
   */
  GNUNET_GNS_LO_NO_DHT = 1,

  /**
   * For the rightmost label, only look in the cache (it
   * is our local namestore), for the others, the DHT is OK.
   */
  GNUNET_GNS_LO_LOCAL_MASTER = 2

};


/**
 * Perform an asynchronous lookup operation on the GNS.
 *
 * @param handle handle to the GNS service
 * @param name the name to look up
 * @param zone zone to look in
 * @param type the GNS record type to look for
 * @param options local options for the lookup
 * @param proc function to call on result
 * @param proc_cls closure for @a proc
 * @return handle to the queued request
 */
struct GNUNET_GNS_LookupRequest *
GNUNET_GNS_lookup (struct GNUNET_GNS_Handle *handle,
		   const char *name,
		   const struct GNUNET_CRYPTO_EcdsaPublicKey *zone,
		   uint32_t type,
		   enum GNUNET_GNS_LocalOptions options,
		   GNUNET_GNS_LookupResultProcessor proc,
		   void *proc_cls);


/**
 * Cancel pending lookup request
 *
 * @param lr the lookup request to cancel
 * @return closure from the lookup result processor
 */
void *
GNUNET_GNS_lookup_cancel (struct GNUNET_GNS_LookupRequest *lr);


/**
 * Iterator called on obtained result for a GNS lookup
 * where "not GNS" is a valid answer.
 *
 * @param cls closure
 * @param gns_tld #GNUNET_YES if a GNS lookup was attempted,
 *                #GNUNET_NO if the TLD is not configured for GNS
 * @param rd_count number of records in @a rd
 * @param rd the records in the reply
 */
typedef void
(*GNUNET_GNS_LookupResultProcessor2) (void *cls,
				      int gns_tld,
				      uint32_t rd_count,
				      const struct GNUNET_GNSRECORD_Data *rd);


/**
 * Perform an asynchronous lookup operation on the GNS,
 * determining the zone using the TLD of the given name
 * and the current configuration to resolve TLDs to zones.
 *
 * @param handle handle to the GNS service
 * @param name the name to look up, including TLD
 * @param type the record type to look up
 * @param options local options for the lookup
 * @param proc processor to call on result
 * @param proc_cls closure for @a proc
 * @return handle to the get request
 */
struct GNUNET_GNS_LookupWithTldRequest*
GNUNET_GNS_lookup_with_tld (struct GNUNET_GNS_Handle *handle,
			    const char *name,
			    uint32_t type,
			    enum GNUNET_GNS_LocalOptions options,
			    GNUNET_GNS_LookupResultProcessor2 proc,
			    void *proc_cls);


/**
 * Cancel pending lookup request
 *
 * @param ltr the lookup request to cancel
 * @return closure from the lookup result processor
 */
void *
GNUNET_GNS_lookup_with_tld_cancel (struct GNUNET_GNS_LookupWithTldRequest *ltr);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/** @} */  /* end of group */
