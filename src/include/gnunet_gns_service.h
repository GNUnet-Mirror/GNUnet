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
 * A single GNS record.
 */
struct GNUNET_GNS_Record;

/**
 * Records types
 */
enum GNUNET_GNS_RecordType
{
  // FIXME: should be based on GNUNET_DNSPARSER_TYPE's (standard DNS),
  // and then maybe our extensions in the area > 255?
  GNUNET_GNS_RECORD_A,
  GNUNET_GNS_RECORD_AAAA,
  GNUNET_GNS_RECORD_MX,
  GNUNET_GNS_RECORD_PKEY
};

/**
 * Initialize the connection with the GNS service.
 *
 * @param cfg configuration to use
 * @param ht_len size of the internal hash table to use for parallel lookups
 * @return NULL on error
 */
struct GNUNET_GNS_Handle *
GNUNET_GNS_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                    unsigned int ht_len);


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
 * operation that expects a reply TODO: eh?
 *
 *
 * @param cls closure
 * @param name "name" of the original lookup
 * @param record the records in reply
 * // FIXME: shouldn't this then be an array of pointers? - not sure as of yet
 * @param num_records the number of records in reply
 */
typedef void (*GNUNET_GNS_LookupIterator) (void *cls,
                                        const char * name,
                                        const struct GNUNET_GNS_Record *record,
                                        unsigned int num_records);



/**
 * Perform an asynchronous lookup operation on the GNS.
 *
 * @param handle handle to the GNS service
 * @param timeout how long to wait for transmission of this request to the service
 * // FIXME: what happens afterwards?
 * @param type expected type of the response object
 * @param name the name to look up
 * @param type the GNUNET_GNS_RecordType to look for
 * @param iter function to call on each result
 * @param iter_cls closure for iter
 *
 * @return handle to stop the async get
 */
struct GNUNET_GNS_LookupHandle *
GNUNET_GNS_lookup_start (struct GNUNET_GNS_Handle *handle,
                         struct GNUNET_TIME_Relative timeout,
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


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


#endif
/* gnunet_gns_service.h */
