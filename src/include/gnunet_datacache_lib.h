/*
     This file is part of GNUnet
     (C) 2006, 2009 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_datacache_lib.h
 * @brief datacache is a simple, transient hash table
 *        of bounded size with content expiration.
 *        In contrast to the sqstore there is
 *        no prioritization, deletion or iteration.
 *        All of the data is discarded when the peer shuts down!
 * @author Christian Grothoff
 */

#ifndef GNUNET_DATACACHE_LIB_H
#define GNUNET_DATACACHE_LIB_H

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
 * Handle to the cache.
 */
struct GNUNET_DATACACHE_Handle;


/**
 * Create a data cache.
 *
 * @param cfg configuration to use
 * @param section section in the configuration that contains our options
 * @return handle to use to access the service
 */
struct GNUNET_DATACACHE_Handle *
GNUNET_DATACACHE_create (const struct GNUNET_CONFIGURATION_Handle *cfg,
                         const char *section);


/**
 * Destroy a data cache (and free associated resources).
 *
 * @param h handle to the datastore
 */
void
GNUNET_DATACACHE_destroy (struct GNUNET_DATACACHE_Handle *h);


/**
 * An iterator over a set of items stored in the datacache.
 *
 * @param cls closure
 * @param exp when will the content expire?
 * @param key key for the content
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @return GNUNET_OK to continue iterating, GNUNET_SYSERR to abort
 */
typedef int (*GNUNET_DATACACHE_Iterator) (void *cls,
                                          struct GNUNET_TIME_Absolute exp,
                                          const GNUNET_HashCode * key,
                                          size_t size, const char *data,
                                          enum GNUNET_BLOCK_Type type);


/**
 * Store an item in the datacache.
 *
 * @param h handle to the datacache
 * @param key key to store data under
 * @param size number of bytes in data
 * @param data data to store
 * @param type type of the value
 * @param discard_time when to discard the value in any case
 * @return GNUNET_OK on success, GNUNET_SYSERR on error (full, etc.)
 */
int
GNUNET_DATACACHE_put (struct GNUNET_DATACACHE_Handle *h,
                      const GNUNET_HashCode * key, size_t size,
                      const char *data, enum GNUNET_BLOCK_Type type,
                      struct GNUNET_TIME_Absolute discard_time);


/**
 * Iterate over the results for a particular key
 * in the datacache.
 *
 * @param h handle to the datacache
 * @param key what to look up
 * @param type entries of which type are relevant?
 * @param iter maybe NULL (to just count)
 * @param iter_cls closure for iter
 * @return the number of results found
 */
unsigned int
GNUNET_DATACACHE_get (struct GNUNET_DATACACHE_Handle *h,
                      const GNUNET_HashCode * key, enum GNUNET_BLOCK_Type type,
                      GNUNET_DATACACHE_Iterator iter, void *iter_cls);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* end of gnunet_datacache_lib.h */
#endif
