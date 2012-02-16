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
GNUNET_GNS_connect (const struct GNUNET_CONFIGURATION_Handle *cfg
                    unsigned int ht_len);


/**
 * Shutdown connection with the GNS service.
 *
 * @param handle connection to shut down
 */
void
GNUNET_GNS_disconnect (struct GNUNET_GNS_Handle *handle);


/* *************** Standard API: add and lookup ******************* */

/**
 * Perform an add operation storing records in the GNS.
 *
 * FIXME: Yes, we need this kind of API, but should it not be with the
 * NameDataStore, rather than the GNS-service?
 *
 * @param handle handle to GNS service
 * @param name the key to store under
 * // FIXME: need to be precise here what 'name' is. Does it
   // include '.gnunet'?  What happens if we specify 'a.b.c.gnunet'
   //  but 'b.c.gnunet' has been delegated? (error?)  
 * @param desired_replication_level estimate of how many
 *                nearest peers this request should reach
 * @param options routing options for this message
   // FIXME: which are? where is the arg?
   // FIXME: we should probably distinguish between 'private' and 'public'
   //        records;
 * @param type type of the value
 * @param size number of bytes in data; must be less than 64k
 * @param data the data to store
   // FIXME: what is the exact format of data?
 * @param exp desired expiration time for the value
 * @param timeout how long to wait for transmission of this request
 * @param cont continuation to call when done (transmitting request to service)
 * @param cont_cls closure for cont
 * // FIXME: where are the continuations?
 */
void
GNUNET_GNS_add_record (struct GNUNET_GNS_Handle *handle,
                       const char* name,
                       enum GNUNET_GNS_RecordType type,
                       size_t size, const char *data,
                       struct GNUNET_TIME_Absolute exp,
                       struct GNUNET_TIME_Relative timeout);


/**
 * Iterator called on each result obtained for a GNS
 * operation that expects a reply TODO: eh?
 *
 *
 * @param cls closure
 * @param exp when will this value expire
 * @param key key of the result
 * // how does the key relate to the name exactly? Why not give the name?
 * @param record the records in reply
 * // FIXME: shouldn't this then be an array of pointers?
 * @param num_records the number of records in reply
 * @param type type of the result
 * // FIXME: not in signature
 */
typedef void (*GNUNET_GNS_LookupIterator) (void *cls,
                                        const GNUNET_HashCode * key,
                                        const struct GNUNET_GNS_Record *record,
                                        unsigned int num_records);



/**
 * Perform an asynchronous lookup operation on the GNS.
 *
 * @param handle handle to the GNS service
 * @param timeout how long to wait for transmission of this request to the service
 * // FIXME: what happens afterwards?
 * @param type expected type of the response object
 * @param key the key to look up
 * // FIXME: key, name, what format?
 * @param desired_replication_level estimate of how many
                  nearest peers this request should reach
 * @param options routing options for this message
 * //FIXME: missmatch between documented and actual options...
 * @param xquery extended query data (can be NULL, depending on type)
 * @param xquery_size number of bytes in xquery
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
