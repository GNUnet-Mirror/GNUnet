/*
     This file is part of GNUnet
     Copyright (C) 2012, 2013 GNUnet e.V.

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

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @author Christian Grothoff
 *
 * @file
 * Plugin API for the namecache database backend
 *
 * @defgroup namecache-plugin  Name Cache service plugin API
 * Plugin API for the namecache database backend.
 *
 * @see [Documentation](https://gnunet.org/namecache-plugin-api)
 *
 * @{
 */
#ifndef GNUNET_NAMECACHE_PLUGIN_H
#define GNUNET_NAMECACHE_PLUGIN_H

#include "gnunet_util_lib.h"
#include "gnunet_namecache_service.h"
#include "gnunet_namestore_service.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Function called for matching blocks.
 *
 * @param cls closure
 * @param block lookup result
 */
typedef void (*GNUNET_NAMECACHE_BlockCallback) (void *cls,
                                                const struct
                                                GNUNET_GNSRECORD_Block *block);


/**
 * @brief struct returned by the initialization function of the plugin
 */
struct GNUNET_NAMECACHE_PluginFunctions
{
  /**
   * Closure to pass to all plugin functions.
   */
  void *cls;

  /**
   * Cache a block in the datastore. Overwrites existing blocks
   * for the same zone and label.
   *
   * @param cls closure (internal context for the plugin)
   * @param block block to cache
   * @return #GNUNET_OK on success, else #GNUNET_SYSERR
   */
  int (*cache_block) (void *cls,
                      const struct GNUNET_GNSRECORD_Block *block);


  /**
   * Get the block for a particular zone and label in the
   * datastore.  Will return at most one result to the iterator.
   *
   * @param cls closure (internal context for the plugin)
   * @param query hash of public key derived from the zone and the label
   * @param iter function to call with the result
   * @param iter_cls closure for @a iter
   * @return #GNUNET_OK on success, #GNUNET_NO if there were no results, #GNUNET_SYSERR on error
   */
  int (*lookup_block) (void *cls,
                       const struct GNUNET_HashCode *query,
                       GNUNET_NAMECACHE_BlockCallback iter, void *iter_cls);
};


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/** @} */  /* end of group */
