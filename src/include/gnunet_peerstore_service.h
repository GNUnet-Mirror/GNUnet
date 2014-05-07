/*
      This file is part of GNUnet
      (C) 

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
 * Handle to the peerstore service.
 */
struct GNUNET_PEERSTORE_Handle;

/**
 * Context for add requests
 */
struct GNUNET_PEERSTORE_AddContext;

/**
 * Continuation called with a status result.
 *
 * @param cls closure
 * @param emsg error message, NULL on success
 */
typedef void (*GNUNET_PEERSTORE_Continuation)(void *cls, const char *emsg);

/**
 * Connect to the PEERSTORE service.
 *
 * @return NULL on error
 */
struct GNUNET_PEERSTORE_Handle *
GNUNET_PEERSTORE_connect (const struct GNUNET_CONFIGURATION_Handle *cfg);

/**
 * Disconnect from the PEERSTORE service
 *
 * @param h handle to disconnect
 */
void
GNUNET_PEERSTORE_disconnect(struct GNUNET_PEERSTORE_Handle *h);

/**
 * Store a new entry in the PEERSTORE
 *
 * @param h Handle to the PEERSTORE service
 * @param peer Peer Identity
 * @param sub_system name of the sub system
 * @param value entry value BLOB
 * @param size size of 'value'
 * @param lifetime relative time after which the entry is (possibly) deleted
 * @param cont Continuation function after the store request is processed
 * @param cont_cls Closure for 'cont'
 */
struct GNUNET_PEERSTORE_StoreContext *
GNUNET_PEERSTORE_store (struct GNUNET_PEERSTORE_Handle *h,
    const struct GNUNET_PeerIdentity *peer,
    const char *sub_system,
    const void *value,
    size_t size,
    struct GNUNET_TIME_Relative lifetime,
    GNUNET_PEERSTORE_Continuation cont,
    void *cont_cls);

/**
 * Cancel a store request
 *
 * @param sc Store request context
 */
void
GNUNET_PEERSTORE_store_cancel (struct GNUNET_PEERSTORE_StoreContext *sc);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
