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
 * @author Omar Tarabai
 *
 * @file
 * Plugin API for the peerstore database backend
 *
 * @defgroup peerstore-plugin  Peer Store service plugin API
 * Plugin API for the peerstore database backend
 * @{
 */
#ifndef GNUNET_PEERSTORE_PLUGIN_H
#define GNUNET_PEERSTORE_PLUGIN_H

#include "gnunet_util_lib.h"
#include "gnunet_peerstore_service.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * @brief struct returned by the initialization function of the plugin
 */
struct GNUNET_PEERSTORE_PluginFunctions
{

  /**
   * Closure to pass to all plugin functions.
   */
  void *cls;

  /**
   * Store a record in the peerstore.
   * Key is the combination of sub system and peer identity.
   * One key can store multiple values.
   *
   * @param cls closure (internal context for the plugin)
   * @param sub_system name of the GNUnet sub system responsible
   * @param peer peer identity
   * @param value value to be stored
   * @param size size of value to be stored
   * @param expiry absolute time after which the record is (possibly) deleted
   * @param options options related to the store operation
   * @param cont continuation called when record is stored
   * @param cont_cls continuation closure
   * @return #GNUNET_OK on success, else #GNUNET_SYSERR and cont is not called
   */
  int
  (*store_record) (void *cls,
                   const char *sub_system,
                   const struct GNUNET_PeerIdentity *peer,
                   const char *key,
                   const void *value,
                   size_t size,
                   struct GNUNET_TIME_Absolute expiry,
                   enum GNUNET_PEERSTORE_StoreOption options,
                   GNUNET_PEERSTORE_Continuation cont,
                   void *cont_cls);

  /**
   * Iterate over the records given an optional peer id
   * and/or key.
   *
   * @param cls closure (internal context for the plugin)
   * @param sub_system name of sub system
   * @param peer Peer identity (can be NULL)
   * @param key entry key string (can be NULL)
   * @param iter function to call asynchronously with the results, terminated
   * by a NULL result
   * @param iter_cls closure for @a iter
   * @return #GNUNET_OK on success, #GNUNET_SYSERR on error and iter is not
   * called
   */
  int
  (*iterate_records) (void *cls,
                      const char *sub_system,
                      const struct GNUNET_PeerIdentity *peer,
                      const char *key,
                      GNUNET_PEERSTORE_Processor iter,
                      void *iter_cls);

  /**
   * Delete expired records (expiry < now)
   *
   * @param cls closure (internal context for the plugin)
   * @param now time to use as reference
   * @param cont continuation called with the number of records expired
   * @param cont_cls continuation closure
   * @return #GNUNET_OK on success, #GNUNET_SYSERR on error and cont is not
   * called
   */
  int
  (*expire_records) (void *cls,
                     struct GNUNET_TIME_Absolute now,
                     GNUNET_PEERSTORE_Continuation cont,
                     void *cont_cls);

};


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/** @} */  /* end of group */
