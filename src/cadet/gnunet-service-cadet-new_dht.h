/*
     This file is part of GNUnet.
     Copyright (C) 2013, 2017 GNUnet e.V.

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
 * @file cadet/gnunet-service-cadet_dht.h
 * @brief cadet service; dealing with DHT requests and results
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 *
 * All functions in this file should use the prefix GCD (Gnunet Cadet Dht)
 */
#ifndef GNUNET_SERVICE_CADET_DHT_H
#define GNUNET_SERVICE_CADET_DHT_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "platform.h"
#include "gnunet_util_lib.h"

/**
 * Handle for DHT search operation.
 */
struct GCD_search_handle;


/**
 * Callback called on each path found over the DHT.
 *
 * @param cls Closure.
 * @param path An unchecked, unoptimized path to the target node.
 *             After callback will no longer be valid!
 */
typedef void
(*GCD_search_callback) (void *cls,
                        const struct CadetPeerPath *path);


/**
 * Initialize the DHT subsystem.
 *
 * @param c Configuration.
 */
void
GCD_init (const struct GNUNET_CONFIGURATION_Handle *c);

/**
 * Shut down the DHT subsystem.
 */
void
GCD_shutdown (void);


/**
 * Search DHT for paths to @a peeR_id
 *
 * @param peer_id peer to search for
 * @param callback function to call with results
 * @param callback_cls closure for @a callback
 * @return handle to abort search
 */
struct GCD_search_handle *
GCD_search (const struct GNUNET_PeerIdentity *peer_id,
            GCD_search_callback callback,
            void *callback_cls);


/**
 * Stop DHT search started with #GCD_search().
 *
 * @param h handle to search to stop
 */
void
GCD_search_stop (struct GCD_search_handle *h);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_CADET_SERVICE_DHT_H */
#endif
/* end of gnunet-service-cadet_dht.h */
