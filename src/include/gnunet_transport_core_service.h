/*
     This file is part of GNUnet.
     Copyright (C) 2009-2016 GNUnet e.V.

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
 * @author Christian Grothoff
 *
 * @file
 * API of the transport service towards the CORE service.
 *
 * @defgroup transport TRANSPORT service
 * Communication with other peers
 *
 * @see [Documentation](https://gnunet.org/transport-service)
 *
 * @{
 */
#ifndef GNUNET_TRANSPORT_CORE_SERVICE_H
#define GNUNET_TRANSPORT_CORE_SERVICE_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"

/**
 * Version number of the transport API.
 */
#define GNUNET_TRANSPORT_CORE_VERSION 0x00000000


/**
 * Opaque handle to the service.
 */
struct GNUNET_TRANSPORT_CoreHandle;


/**
 * Function called to notify transport users that another
 * peer connected to us.
 *
 * @param cls closure
 * @param peer the identity of the peer that connected; this
 *        pointer will remain valid until the disconnect, hence
 *        applications do not necessarily have to make a copy 
 *        of the value if they only need it until disconnect
 * @param mq message queue to use to transmit to @a peer
 * @return closure to use in MQ handlers
 */
typedef void *
(*GNUNET_TRANSPORT_NotifyConnecT) (void *cls,
                                   const struct GNUNET_PeerIdentity *peer,
                                   struct GNUNET_MQ_Handle *mq);


/**
 * Function called to notify transport users that another peer
 * disconnected from us.  The message queue that was given to the
 * connect notification will be destroyed and must not be used
 * henceforth.
 *
 * @param cls closure from #GNUNET_TRANSPORT_core_connect
 * @param peer the peer that disconnected
 * @param handlers_cls closure of the handlers, was returned from the
 *                    connect notification callback
 */
typedef void
(*GNUNET_TRANSPORT_NotifyDisconnecT) (void *cls,
                                      const struct GNUNET_PeerIdentity *peer,
                                      void *handler_cls);


/**
 * Function called if we have "excess" bandwidth to a peer.
 * The notification will happen the first time we have excess
 * bandwidth, and then only again after the client has performed
 * some transmission to the peer.
 *
 * Excess bandwidth is defined as being allowed (by ATS) to send
 * more data, and us reaching the limit of the capacity build-up
 * (which, if we go past it, means we don't use available bandwidth).
 * See also the "max carry" in `struct GNUNET_BANDWIDTH_Tracker`.
 *
 * @param cls the closure
 * @param neighbour peer that we have excess bandwidth to
 * @param handlers_cls closure of the handlers, was returned from the
 *                    connect notification callback
 */
typedef void
(*GNUNET_TRANSPORT_NotifyExcessBandwidtH)(void *cls,
                                          const struct GNUNET_PeerIdentity *neighbour,
                                          void *handlers_cls);



/**
 * Connect to the transport service.  Note that the connection may
 * complete (or fail) asynchronously.
 *
 * @param cfg configuration to use
 * @param self our own identity (API should check that it matches
 *             the identity found by transport), or NULL (no check)
 * @param handlers array of message handlers; note that the
 *                 closures provided will be ignored and replaced
 *                 with the respective return value from @a nc
 * @param handlers array with handlers to call when we receive messages, or NULL
 * @param cls closure for the @a nc, @a nd and @a neb callbacks
 * @param nc function to call on connect events, or NULL
 * @param nd function to call on disconnect events, or NULL
 * @param neb function to call if we have excess bandwidth to a peer, or NULL
 * @return NULL on error
 */
struct GNUNET_TRANSPORT_CoreHandle *
GNUNET_TRANSPORT_core_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                               const struct GNUNET_PeerIdentity *self,
                               const struct GNUNET_MQ_MessageHandler *handlers,
                               void *cls,
                               GNUNET_TRANSPORT_NotifyConnecT nc,
                               GNUNET_TRANSPORT_NotifyDisconnecT nd,
                               GNUNET_TRANSPORT_NotifyExcessBandwidtH neb);


/**
 * Disconnect from the transport service.
 *
 * @param handle handle returned from connect
 */
void
GNUNET_TRANSPORT_core_disconnect (struct GNUNET_TRANSPORT_CoreHandle *handle);


/**
 * Checks if a given peer is connected to us and get the message queue.
 *
 * @param handle connection to transport service
 * @param peer the peer to check
 * @return NULL if disconnected, otherwise message queue for @a peer
 */
struct GNUNET_MQ_Handle *
GNUNET_TRANSPORT_core_get_mq (struct GNUNET_TRANSPORT_CoreHandle *handle,
                              const struct GNUNET_PeerIdentity *peer);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_TRANSPORT_CORE_SERVICE_H */
#endif

/** @} */  /* end of group */

/* end of gnunet_transport_core_service.h */
