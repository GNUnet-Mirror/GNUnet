/*
      This file is part of GNUnet
      (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_gns_service.h
 * @brief API to the GNS service
 * @author Martin Schanzenbach
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
 * String we use to indicate the local master zone or a
 * root entry in the current zone.
 */
#define GNUNET_GNS_MASTERZONE_STR "+"

/**
 * Connection to the GNS service.
 */
struct GNUNET_GNS_Handle;

/**
 * Handle to control a lookup operation.
 */
struct GNUNET_GNS_LookupRequest;

/**
 * Handle to control a shorten operation.
 */
struct GNUNET_GNS_ShortenRequest;

/**
 * Handle to control a get authority operation
 */
struct GNUNET_GNS_GetAuthRequest;

/**
 * Record types
 * Based on GNUNET_DNSPARSER_TYPEs (standard DNS)
 */
enum GNUNET_GNS_RecordType
{
  /**
   * A 'struct in_addr'
   */
  GNUNET_GNS_RECORD_A          = GNUNET_DNSPARSER_TYPE_A,

  /**
   * A 'char *'
   */
  GNUNET_GNS_RECORD_NS         = GNUNET_DNSPARSER_TYPE_NS,

  /**
   * A 'char *'
   */
  GNUNET_GNS_RECORD_CNAME      = GNUNET_DNSPARSER_TYPE_CNAME,

  /**
   * A 'struct soa_data'
   */
  GNUNET_GNS_RECORD_SOA        = GNUNET_DNSPARSER_TYPE_SOA,

  /**
   * A 'struct srv_data'
   */
  GNUNET_GNS_RECORD_SRV        = GNUNET_DNSPARSER_TYPE_SRV,

  /**
   * A 'char *'
   */
  GNUNET_GNS_RECORD_PTR        = GNUNET_DNSPARSER_TYPE_PTR,

  /**
   * A 'uint16_t' and a 'char *'
   */
  GNUNET_GNS_RECORD_MX         = GNUNET_DNSPARSER_TYPE_MX,

  /**
   * A 'char *'
   */
  GNUNET_GNS_RECORD_TXT        = GNUNET_DNSPARSER_TYPE_TXT,

  /**
   * A 'struct in6_addr'
   */
  GNUNET_GNS_RECORD_AAAA       = GNUNET_DNSPARSER_TYPE_AAAA,

  /* GNS specific */
  /**
   * A 'struct GNUNET_CRYPTO_ShortHashCode'
   */
  GNUNET_GNS_RECORD_PKEY = GNUNET_NAMESTORE_TYPE_PKEY,

  /**
   * A 'char *'
   */
  GNUNET_GNS_RECORD_PSEU = GNUNET_NAMESTORE_TYPE_PSEU,
  GNUNET_GNS_RECORD_ANY  = GNUNET_NAMESTORE_TYPE_ANY,

  /**
   * A 'char *'
   */
  GNUNET_GNS_RECORD_LEHO = GNUNET_NAMESTORE_TYPE_LEHO,

  /**
   * A 'struct vpn_data'
   */
  GNUNET_GNS_RECORD_VPN  = GNUNET_NAMESTORE_TYPE_VPN,

  /**
   * Revocation, no data.
   */
  GNUNET_GNS_RECORD_REV  = GNUNET_NAMESTORE_TYPE_REV
};


/**
 * Initialize the connection with the GNS service.
 *
 * @param cfg configuration to use
 *
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


/* *************** Standard API: lookup ******************* */

/**
 * Iterator called on obtained result for a GNS
 * lookup
 *
 * @param cls closure
 * @param rd_count number of records
 * @param rd the records in reply
 */
typedef void (*GNUNET_GNS_LookupResultProcessor) (void *cls,
						  uint32_t rd_count,
						  const struct GNUNET_NAMESTORE_RecordData *rd);



/**
 * Perform an asynchronous lookup operation on the GNS
 * in the default zone.
 *
 * @param handle handle to the GNS service
 * @param name the name to look up
 * @param type the GNUNET_GNS_RecordType to look for
 * @param only_cached GNUNET_NO to only check locally not DHT for performance
 * @param shorten_key the private key of the shorten zone (can be NULL)
 * @param proc function to call on result
 * @param proc_cls closure for processor
 *
 * @return handle to the queued request
 */
struct GNUNET_GNS_LookupRequest*
GNUNET_GNS_lookup (struct GNUNET_GNS_Handle *handle,
		   const char * name,
		   enum GNUNET_GNS_RecordType type,
		   int only_cached,
		   struct GNUNET_CRYPTO_EccPrivateKey *shorten_key,
		   GNUNET_GNS_LookupResultProcessor proc,
		   void *proc_cls);


/**
 * Perform an asynchronous lookup operation on the GNS
 * in the zone specified by 'zone'.
 *
 * @param handle handle to the GNS service
 * @param name the name to look up
 * @param zone the zone to start the resolution in
 * @param type the GNUNET_GNS_RecordType to look for
 * @param only_cached GNUNET_YES to only check locally not DHT for performance
 * @param shorten_key the private key of the shorten zone (can be NULL)
 * @param proc function to call on result
 * @param proc_cls closure for processor
 *
 * @return handle to the queued request
 */
struct GNUNET_GNS_LookupRequest*
GNUNET_GNS_lookup_zone (struct GNUNET_GNS_Handle *handle,
			const char * name,
			struct GNUNET_CRYPTO_ShortHashCode *zone,
			enum GNUNET_GNS_RecordType type,
			int only_cached,
			struct GNUNET_CRYPTO_EccPrivateKey *shorten_key,
			GNUNET_GNS_LookupResultProcessor proc,
			void *proc_cls);


/**
 * Cancel pending lookup request
 *
 * @param lr the lookup request to cancel
 */
void
GNUNET_GNS_cancel_lookup_request (struct GNUNET_GNS_LookupRequest *lr);

/* *************** Standard API: shorten ******************* */


/**
 * Processor called on for a name shortening result
 * called only once
 *
 * @param cls closure
 * @param short_name the shortened name or NULL if no result / error
 */
typedef void (*GNUNET_GNS_ShortenResultProcessor) (void *cls,
						   const char* short_name);


/**
 * Perform a name shortening operation on the GNS.
 *
 * @param handle handle to the GNS service
 * @param name the name to look up
 * @param private_zone the public zone of the private zone
 * @param shorten_zone the public zone of the shorten zone
 * @param proc function to call on result
 * @param proc_cls closure for processor
 * @return handle to the operation
 */
struct GNUNET_GNS_ShortenRequest*
GNUNET_GNS_shorten (struct GNUNET_GNS_Handle *handle,
                    const char * name,
                    struct GNUNET_CRYPTO_ShortHashCode *private_zone,
                    struct GNUNET_CRYPTO_ShortHashCode *shorten_zone,
                    GNUNET_GNS_ShortenResultProcessor proc,
                    void *proc_cls);


/**
 * Perform a name shortening operation on the GNS.
 *
 * @param handle handle to the GNS service
 * @param name the name to look up
 * @param private_zone the public zone of the private zone
 * @param shorten_zone the public zone of the shorten zone
 * @param zone the zone to start the resolution in
 * @param proc function to call on result
 * @param proc_cls closure for processor
 * @return handle to the operation
 */
struct GNUNET_GNS_ShortenRequest*
GNUNET_GNS_shorten_zone (struct GNUNET_GNS_Handle *handle,
                         const char * name,
                         struct GNUNET_CRYPTO_ShortHashCode *private_zone,
                         struct GNUNET_CRYPTO_ShortHashCode *shorten_zone,
                         struct GNUNET_CRYPTO_ShortHashCode *zone,
                         GNUNET_GNS_ShortenResultProcessor proc,
                         void *proc_cls);


/**
 * Cancel pending shorten request
 *
 * @param sr the lookup request to cancel
 */
void
GNUNET_GNS_cancel_shorten_request (struct GNUNET_GNS_ShortenRequest *sr);


/* *************** Standard API: get authority ******************* */


/**
 * Processor called on for a name shortening result
 * called only once
 *
 * @param cls closure
 * @param auth_name the name of the auhtority or NULL
 */
typedef void (*GNUNET_GNS_GetAuthResultProcessor) (void *cls,
						   const char* short_name);


/**
 * Perform an authority lookup for a given name.
 *
 * @param handle handle to the GNS service
 * @param name the name to look up authority for
 * @param proc function to call on result
 * @param proc_cls closure for processor
 * @return handle to the operation
 */
struct GNUNET_GNS_GetAuthRequest*
GNUNET_GNS_get_authority (struct GNUNET_GNS_Handle *handle,
			  const char *name,
			  GNUNET_GNS_GetAuthResultProcessor proc,
			  void *proc_cls);


/**
 * Cancel pending get auth request
 *
 * @param gar the lookup request to cancel
 */
void
GNUNET_GNS_cancel_get_auth_request (struct GNUNET_GNS_GetAuthRequest *gar);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


#endif
/* gnunet_gns_service.h */
