/*
     This file is part of GNUnet.
     (C) 2001 - 2011 Christian Grothoff (and other contributing authors)

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
 * @author Bartlomiej Polot
 * @file mesh/mesh.h
 *
 * TODO:
 * - soft stateing (keep-alive (CHANGE?) / timeout / disconnect) -- not a message issue
 * - error reporting (CREATE/CHANGE/ADD/DEL?) -- new message!
 * - partial disconnect reporting -- same as error reporting?
 * - add vs create? change vs. keep-alive? same msg or different ones? -- thinking...
 * - speed requirement specification (change?) in mesh API -- API call
 *
 * - API messages!
 */


#ifndef MESH_H_
#define MESH_H_
#include <stdint.h>
#include "gnunet_common.h"

/**
 * Message for mesh path management
 */
struct GNUNET_MESH_ManipulatePath
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_PATH_[CREATE|CHANGE|ADD|DEL]
     *
     * Size: sizeof(struct GNUNET_MESH_ManipulatePath) + path_length * sizeof (struct GNUNET_PeerIdentity)
     */
    struct GNUNET_MessageHeader header;

    /**
     * Id of the tunnel this path belongs to, unique in conjunction with the origin.
     */
    uint32_t tid GNUNET_PACKED;

    /**
     * Information about speed requirements.  If the tunnel cannot sustain the 
     * minimum bandwidth, packets are to be dropped.
     */
    uint32_t speed_min GNUNET_PACKED;

    /**
     * path_length structs defining the *whole* path from the origin [0] to the
     * final destination [path_length-1].
     */
  // struct GNUNET_PeerIdentity peers[path_length];
};

/**
 * Message for mesh data traffic to all tunnel targets.
 */
struct GNUNET_MESH_OriginMulticast
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_DATA_MULTICAST
     */
    struct GNUNET_MessageHeader header;

    /**
     * TID of the tunnel
     */
    uint32_t tid GNUNET_PACKED;

    /**
     * OID of the tunnel
     */
    struct GNUNET_PeerIdentity oid;

    /**
     * FIXME: Some form of authentication
     */
    // uint32_t token;

    /**
     * Payload follows
     */
};


/**
 * Message for mesh data traffic to a particular destination from origin.
 */
struct GNUNET_MESH_DataMessageFromOrigin
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_DATA_MESSAGE_FROM_ORIGIN
     */
    struct GNUNET_MessageHeader header;

    /**
     * TID of the tunnel
     */
    uint32_t tid GNUNET_PACKED;

    /**
     * OID of the tunnel
     */
    struct GNUNET_PeerIdentity oid;

    /**
     * Destination.
     */
    struct GNUNET_PeerIdentity destination;

    /**
     * FIXME: Some form of authentication
     */
    // uint32_t token;

    /**
     * Payload follows
     */
};


/**
 * Message for mesh data traffic from a tunnel participant to origin.
 */
struct GNUNET_MESH_DataMessageToOrigin
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_DATA_MESSAGE_TO_ORIGIN
     */
    struct GNUNET_MessageHeader header;

    /**
     * TID of the tunnel
     */
    uint32_t tid GNUNET_PACKED;

    /**
     * OID of the tunnel
     */
    struct GNUNET_PeerIdentity oid;

    /**
     * Sender of the message.
     */
    struct GNUNET_PeerIdentity sender;

    /**
     * FIXME: Some form of authentication
     */
    // uint32_t token;

    /**
     * Payload follows
     */
};

/**
 * Message for mesh flow control
 */
struct GNUNET_MESH_SpeedNotify
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_DATA_SPEED_NOTIFY
     */
    struct GNUNET_MessageHeader header;

    /**
     * TID of the tunnel
     */
    uint32_t tid GNUNET_PACKED;

    /**
     * OID of the tunnel
     */
    struct GNUNET_PeerIdentity oid;

    /**
     * Slowest link down the path (above minimum speed requirement).
     */
    uint32_t speed_min;

};

#endif
