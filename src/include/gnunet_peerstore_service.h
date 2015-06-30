/*
      This file is part of GNUnet
      Copyright (C)

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
      Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
      Boston, MA 02110-1301, USA.
 */

/**
 * @file include/gnunet_peerstore_service.h
 * @brief API to the peerstore service
 * @author Omar Tarabai
 */
#ifndef GNUNET_PEERSTORE_SERVICE_H
#define GNUNET_PEERSTORE_SERVICE_H

#include "platform.h"
#include "gnunet_util_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Options for storing values in PEERSTORE
 */
enum GNUNET_PEERSTORE_StoreOption
{

  /**
   * Possibly store multiple values under given key.
   */
  GNUNET_PEERSTORE_STOREOPTION_MULTIPLE = 0,

  /**
   * Delete any previous values for the given key before
   * storing the given value.
   */
  GNUNET_PEERSTORE_STOREOPTION_REPLACE = 1

};

/**
 * Handle to the peerstore service.
 */
struct GNUNET_PEERSTORE_Handle;

/**
 * Context for a store request
 */
struct GNUNET_PEERSTORE_StoreContext;

/**
 * Single PEERSTORE record
 */
struct GNUNET_PEERSTORE_Record
{

  /**
   * Responsible sub system string
   */
  char *sub_system;

  /**
   * Peer Identity
   */
  struct GNUNET_PeerIdentity *peer;

  /**
   * Record key string
   */
  char *key;

  /**
   * Record value BLOB
   */
  void *value;

  /**
   * Size of @e value BLOB
   */
  size_t value_size;

  /**
   * Expiry time of entry
   */
  struct GNUNET_TIME_Absolute *expiry;

  /**
   * Client from which this record originated
   */
  struct GNUNET_SERVER_Client *client;
};


/**
 * Continuation called with a status result.
 *
 * @param cls closure
 * @param success #GNUNET_OK or #GNUNET_SYSERR
 */
typedef void
(*GNUNET_PEERSTORE_Continuation)(void *cls, int success);

/**
 * Function called by PEERSTORE for each matching record.
 *
 * @param cls closure
 * @param record peerstore record information
 * @param emsg error message, or NULL if no errors
 * @return #GNUNET_YES to continue iterating, #GNUNET_NO to stop
 */
typedef int
(*GNUNET_PEERSTORE_Processor) (void *cls,
                               const struct GNUNET_PEERSTORE_Record *record,
                               const char *emsg);

/**
 * Connect to the PEERSTORE service.
 *
 * @return NULL on error
 */
struct GNUNET_PEERSTORE_Handle *
GNUNET_PEERSTORE_connect (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Disconnect from the PEERSTORE service. Any pending ITERATE and WATCH requests
 * will be canceled.
 * Any pending STORE requests will depend on @e snyc_first flag.
 *
 * @param h handle to disconnect
 * @param sync_first send any pending STORE requests before disconnecting
 */
void
GNUNET_PEERSTORE_disconnect (struct GNUNET_PEERSTORE_Handle *h,
                             int sync_first);


/**
 * Store a new entry in the PEERSTORE.
 * Note that stored entries can be lost in some cases
 * such as power failure.
 *
 * @param h Handle to the PEERSTORE service
 * @param sub_system name of the sub system
 * @param peer Peer Identity
 * @param key entry key
 * @param value entry value BLOB
 * @param size size of @e value
 * @param expiry absolute time after which the entry is (possibly) deleted
 * @param options options specific to the storage operation
 * @param cont Continuation function after the store request is sent
 * @param cont_cls Closure for @a cont
 */
struct GNUNET_PEERSTORE_StoreContext *
GNUNET_PEERSTORE_store (struct GNUNET_PEERSTORE_Handle *h,
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
 * Cancel a store request
 *
 * @param sc Store request context
 */
void
GNUNET_PEERSTORE_store_cancel (struct GNUNET_PEERSTORE_StoreContext *sc);


/**
 * Iterate over records matching supplied key information
 *
 * @param h handle to the PEERSTORE service
 * @param sub_system name of sub system
 * @param peer Peer identity (can be NULL)
 * @param key entry key string (can be NULL)
 * @param timeout time after which the iterate request is canceled
 * @param callback function called with each matching record, all NULL's on end
 * @param callback_cls closure for @a callback
 */
struct GNUNET_PEERSTORE_IterateContext *
GNUNET_PEERSTORE_iterate (struct GNUNET_PEERSTORE_Handle *h,
                          const char *sub_system,
                          const struct GNUNET_PeerIdentity *peer,
                          const char *key,
                          struct GNUNET_TIME_Relative timeout,
                          GNUNET_PEERSTORE_Processor callback,
                          void *callback_cls);


/**
 * Cancel an iterate request
 * Please do not call after the iterate request is done
 *
 * @param ic Iterate request context as returned by GNUNET_PEERSTORE_iterate()
 */
void
GNUNET_PEERSTORE_iterate_cancel (struct GNUNET_PEERSTORE_IterateContext *ic);


/**
 * Request watching a given key
 * User will be notified with any new values added to key.
 *
 * @param h handle to the PEERSTORE service
 * @param sub_system name of sub system
 * @param peer Peer identity
 * @param key entry key string
 * @param callback function called with each new value
 * @param callback_cls closure for @a callback
 * @return Handle to watch request
 */
struct GNUNET_PEERSTORE_WatchContext *
GNUNET_PEERSTORE_watch (struct GNUNET_PEERSTORE_Handle *h,
                        const char *sub_system,
                        const struct GNUNET_PeerIdentity *peer,
                        const char *key,
                        GNUNET_PEERSTORE_Processor callback,
                        void *callback_cls);


/**
 * Cancel a watch request
 *
 * @param wc handle to the watch request
 */
void
GNUNET_PEERSTORE_watch_cancel (struct GNUNET_PEERSTORE_WatchContext *wc);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
