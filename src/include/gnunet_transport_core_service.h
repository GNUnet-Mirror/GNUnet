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
 * Function called by the transport for each received message.
 *
 * @param cls closure
 * @param peer (claimed) identity of the other peer
 * @param message the message
 */
typedef void
(*GNUNET_TRANSPORT_ReceiveCallback) (void *cls,
                                     const struct GNUNET_PeerIdentity *peer,
                                     const struct GNUNET_MessageHeader *message);


/**
 * Opaque handle to the service.
 */
struct GNUNET_TRANSPORT_Handle;


/**
 * Function called to notify CORE service that another
 * @a peer connected to us.
 *
 * @param cls closure
 * @param peer the peer that connected, never NULL
 * @param mq message queue for sending messages to this peer
 */
typedef void
(*GNUNET_TRANSPORT_NotifyConnect) (void *cls,
                                   const struct GNUNET_PeerIdentity *peer,
                                   struct GNUNET_MQ_Handle *mq);


/**
 * Function called to notify CORE service that another
 * @a peer disconnected from us.  The associated message
 * queue must not be used henceforth.
 *
 * @param cls closure
 * @param peer the peer that disconnected, never NULL
 */
typedef void
(*GNUNET_TRANSPORT_NotifyDisconnect) (void *cls,
                                      const struct GNUNET_PeerIdentity *peer);


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
 */
typedef void
(*GNUNET_TRANSPORT_NotifyExcessBandwidth)(void *cls,
                                          const struct GNUNET_PeerIdentity *neighbour);


/**
 * Connect to the transport service.
 *
 * @param cfg configuration to use
 * @param self our own identity (if API should check that it matches
 *             the identity found by transport), or NULL (no check)
 * @param cls closure for the callbacks
 * @param rec_handlers NULL-terminated array of handlers for incoming
 *                     messages, or NULL
 * @param nc function to call on connect events, or NULL
 * @param nd function to call on disconnect events, or NULL
 * @param neb function to call if we have excess bandwidth to a peer
 * @return NULL on error
 */
struct GNUNET_TRANSPORT_Handle *
GNUNET_TRANSPORT_core_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                               const struct GNUNET_PeerIdentity *self,
                               void *cls,
                               GNUNET_MQ_MessageHandler *rec_handlers,
                               GNUNET_TRANSPORT_NotifyConnect nc,
                               GNUNET_TRANSPORT_NotifyDisconnect nd,
                               GNUNET_TRANSPORT_NotifyExcessBandwidth neb);


/**
 * Disconnect from the transport service.
 *
 * @param handle handle returned from connect
 */
void
GNUNET_TRANSPORT_disconnect (struct GNUNET_TRANSPORT_Handle *handle);


/**
 * Checks if a given peer is connected to us. Convenience
 * API in case a client does not track connect/disconnect
 * events internally.
 *
 * @param handle connection to transport service
 * @param peer the peer to check
 * @return #GNUNET_YES (connected) or #GNUNET_NO (disconnected)
 */
int
GNUNET_TRANSPORT_check_peer_connected (struct GNUNET_TRANSPORT_Handle *handle,
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
