/*
     This file is part of GNUnet.
     Copyright (C) 2013, 2016 GNUnet e.V.

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
 * DV service API (should only be used by the DV plugin)
 *
 * @defgroup dv  DV service
 * Distance Vector routing
 *
 * The DV service API should only be used by the DV plugin.
 * @{
 */
#ifndef GNUNET_SERVICE_DV_H
#define GNUNET_SERVICE_DV_H

#include "gnunet_util_lib.h"
#include "gnunet_ats_service.h"

/**
 * Signature of a function to be called if DV
 * starts to be able to talk to a peer.
 *
 * @param cls closure
 * @param peer newly connected peer
 * @param distance distance to the peer
 * @param network the peer is located in
 */
typedef void
(*GNUNET_DV_ConnectCallback)(void *cls,
                             const struct GNUNET_PeerIdentity *peer,
                             uint32_t distance,
                             enum GNUNET_ATS_Network_Type network);


/**
 * Signature of a function to be called if DV
 * distance to a peer is changed.
 *
 * @param cls closure
 * @param peer connected peer
 * @param distance new distance to the peer
 * @param network this network will be used to reach the next hop
 */
typedef void
(*GNUNET_DV_DistanceChangedCallback)(void *cls,
                                     const struct GNUNET_PeerIdentity *peer,
                                     uint32_t distance,
                                     enum GNUNET_ATS_Network_Type network);


/**
 * Signature of a function to be called if DV
 * is no longer able to talk to a peer.
 *
 * @param cls closure
 * @param peer peer that disconnected
 */
typedef void
(*GNUNET_DV_DisconnectCallback)(void *cls,
                                const struct GNUNET_PeerIdentity *peer);


/**
 * Signature of a function to be called if DV
 * receives a message for this peer.
 *
 * @param cls closure
 * @param sender sender of the message
 * @param distance how far did the message travel
 * @param msg actual message payload
 */
typedef void
(*GNUNET_DV_MessageReceivedCallback)(void *cls,
                                     const struct GNUNET_PeerIdentity *sender,
                                     uint32_t distance,
                                     const struct GNUNET_MessageHeader *msg);


/**
 * Signature of a function called once the delivery of a
 * message has been successful.
 *
 * @param cls closure
 */
typedef void
(*GNUNET_DV_MessageSentCallback)(void *cls);


/**
 * Handle to the DV service.
 */
struct GNUNET_DV_ServiceHandle;


/**
 * Connect to the DV service.
 *
 * @param cfg configuration
 * @param cls closure for callbacks
 * @param connect_cb function to call on connects
 * @param distance_cb function to call if distances change
 * @param disconnect_cb function to call on disconnects
 * @param message_cb function to call if we receive messages
 * @return handle to access the service
 */
struct GNUNET_DV_ServiceHandle *
GNUNET_DV_service_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
			   void *cls,
			   GNUNET_DV_ConnectCallback connect_cb,
			   GNUNET_DV_DistanceChangedCallback distance_cb,
			   GNUNET_DV_DisconnectCallback disconnect_cb,
			   GNUNET_DV_MessageReceivedCallback message_cb);


/**
 * Disconnect from DV service.
 *
 * @param sh service handle
 */
void
GNUNET_DV_service_disconnect (struct GNUNET_DV_ServiceHandle *sh);


/**
 * Handle for a send operation.
 */
struct GNUNET_DV_TransmitHandle;


/**
 * Send a message via DV service.
 *
 * @param sh service handle
 * @param target intended recpient
 * @param msg message payload
 * @return handle to cancel the operation
 */
void
GNUNET_DV_send (struct GNUNET_DV_ServiceHandle *sh,
		const struct GNUNET_PeerIdentity *target,
		const struct GNUNET_MessageHeader *msg);


#endif

/** @} */  /* end of group */
