/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013 Christian Grothoff (and other contributing authors)

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
 * @file gns/gnunet-service-gns_resolver.h
 * @brief GNUnet GNS service
 * @author Martin Schanzenbach
 */
#ifndef GNS_RESOLVER_H
#define GNS_RESOLVER_H
#include "gns.h"
#include "gnunet_dht_service.h"
#include "gnunet_gns_service.h"
#include "gnunet_namecache_service.h"

/**
 * Initialize the resolver subsystem.
 * MUST be called before #GNS_resolver_lookup.
 *
 * @param nc the namecache handle
 * @param dht handle to the dht
 * @param c configuration handle
 * @param max_bg_queries maximum amount of background queries
 */
void
GNS_resolver_init (struct GNUNET_NAMECACHE_Handle *nc,
		   struct GNUNET_DHT_Handle *dht,
		   const struct GNUNET_CONFIGURATION_Handle *c,
		   unsigned long long max_bg_queries);


/**
 * Cleanup resolver: Terminate pending lookups
 */
void
GNS_resolver_done (void);


/**
 * Handle for an active request.
 */
struct GNS_ResolverHandle;


/**
 * Function called with results for a GNS resolution.
 *
 * @param cls closure
 * @param rd_count number of records in @a rd
 * @param rd records returned for the lookup
 */
typedef void (*GNS_ResultProcessor)(void *cls,
				    uint32_t rd_count,
				    const struct GNUNET_GNSRECORD_Data *rd);


/**
 * Lookup of a record in a specific zone
 * calls RecordLookupProcessor on result or timeout
 *
 * @param zone the zone to perform the lookup in
 * @param record_type the record type to look up
 * @param name the name to look up
 * @param shorten_key optional private key for authority caching, can be NULL
 * @param options options set to control local lookup
 * @param proc the processor to call
 * @param proc_cls the closure to pass to @a proc
 * @return handle to cancel operation
 */
struct GNS_ResolverHandle *
GNS_resolver_lookup (const struct GNUNET_CRYPTO_EcdsaPublicKey *zone,
		     uint32_t record_type,
		     const char *name,
		     const struct GNUNET_CRYPTO_EcdsaPrivateKey *shorten_key,
		     enum GNUNET_GNS_LocalOptions options,
		     GNS_ResultProcessor proc,
		     void *proc_cls);


/**
 * Cancel active resolution (i.e. client disconnected).
 *
 * @param rh resolution to abort
 */
void
GNS_resolver_lookup_cancel (struct GNS_ResolverHandle *rh);




/**
 * Generic function to check for TLDs.  Checks if "name" ends in ".tld"
 *
 * @param name the name to check
 * @param tld the tld to check
 * @return #GNUNET_YES or #GNUNET_NO
 */
int
is_tld (const char *name,
	const char *tld);



/**
 * Checks for gnu/zkey
 */
#define is_gnu_tld(name) is_tld(name, GNUNET_GNS_TLD)
#define is_zkey_tld(name) is_tld(name, GNUNET_GNS_TLD_ZKEY)


#endif
