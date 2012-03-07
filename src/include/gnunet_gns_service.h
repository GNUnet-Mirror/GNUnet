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
 *
 * TODO:
 * - decide what goes into storage API and what into GNS-service API
 * - decide where to pass/expose/check keys / signatures
 * - are GNS private keys per peer or per user?
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
 * Connection to the GNS service.
 */
struct GNUNET_GNS_Handle;

/**
 * Handle to control a get operation.
 */
struct GNUNET_GNS_LookupHandle;

/**
 * Handle to control a shorten operation
 */

/**
 * Record types
 * Based on GNUNET_DNSPARSER_TYPEs (standard DNS)
 */
enum GNUNET_GNS_RecordType
{
  /* Standard DNS */
  GNUNET_GNS_RECORD_TYPE_A = GNUNET_DNSPARSER_TYPE_A,
  GNUNET_GNS_RECORD_TYPE_NS = GNUNET_DNSPARSER_TYPE_NS,
  GNUNET_GNS_RECORD_TYPE_CNAME = GNUNET_DNSPARSER_TYPE_CNAME,
  GNUNET_GNS_RECORD_TYPE_SOA = GNUNET_DNSPARSER_TYPE_SOA,
  GNUNET_GNS_RECORD_TYPE_PTR = GNUNET_DNSPARSER_TYPE_PTR,
  GNUNET_GNS_RECORD_MX = GNUNET_DNSPARSER_TYPE_MX,
  GNUNET_GNS_RECORD_TXT = GNUNET_DNSPARSER_TYPE_TXT,
  GNUNET_GNS_RECORD_AAAA = GNUNET_DNSPARSER_TYPE_AAAA,

  /* GNS specific */
  GNUNET_GNS_RECORD_PKEY = GNUNET_NAMESTORE_TYPE_PKEY,
  GNUNET_GNS_RECORD_PSEU = GNUNET_NAMESTORE_TYPE_PSEU
};

/**
 * Initialize the connection with the GNS service.
 *
 * @param cfg configuration to use
 * @param ht_len size of the internal hash table to use for parallel requests
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
 * Iterator called on each result obtained for a GNS
 * lookup
 *
 * @param cls closure
 * @param name "name" of the original lookup
 * @param rd_count number of records
 * @param rd the records in reply
 */
typedef void (*GNUNET_GNS_LookupIterator) (void *cls,
                                        const char * name,
                                        uint32_t rd_count,
                                        const struct GNUNET_NAMESTORE_RecordData *rd);



/**
 * Perform an asynchronous lookup operation on the GNS.
 *
 * @param handle handle to the GNS service
 * @param name the name to look up
 * @param type the GNUNET_GNS_RecordType to look for
 * @param iter function to call on each result
 * @param iter_cls closure for iter
 *
 * @return handle to stop the async lookup
 */
struct GNUNET_GNS_LookupHandle *
GNUNET_GNS_lookup_start (struct GNUNET_GNS_Handle *handle,
                         const char * name,
                         enum GNUNET_GNS_RecordType type,
                         GNUNET_GNS_LookupIterator iter,
                         void *iter_cls);


/**
 * Stop async GNS lookup.  Frees associated resources.
 *
 * @param lookup_handle lookup operation to stop.
 *
 * On return lookup_handle will no longer be valid, caller
 * must not use again!!!
 */
void
GNUNET_GNS_lookup_stop (struct GNUNET_GNS_LookupHandle *lookup_handle);

/* *************** Standard API: shorten ******************* */


/**
 * Processor called on for a name shortening result
 * called only once
 *
 * @param cls closure
 * @param name "name" of the original lookup
 * @param short_name the shortened name or NULL if no result
 */
typedef void (*GNUNET_GNS_ShortenResultProcessor) (void *cls,
                                        const char * name,
                                        const char* short_name);


/**
 * Perform a shorten operation on name using the GNS.
 *
 * @param handle handle to the GNS service
 * @param name the name to shorten
 * @param proc processor to call on result
 * @param iter_cls closure for processor
 *
 * @return handle to the shorten operation
 */
struct GNUNET_GNS_ShortenHandle *
GNUNET_GNS_shorten (struct GNUNET_GNS_Handle *handle,
                         const char * name,
                         GNUNET_GNS_ShortenResultProcessor proc,
                         void *iter_cls);
#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


#endif
/* gnunet_gns_service.h */
