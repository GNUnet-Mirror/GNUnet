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
 */


#ifndef MESH_H_
#define MESH_H_
#include <stdint.h>

/**
 * Message for mesh path management
 */
struct GNUNET_MESH_ManipulatePath
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_PATH_[CREATE|CHANGE|ADD]
     */
    struct GNUNET_MessageHeader header;

    /**
     * Id of the tunnel this path belongs to
     */
    uint32_t tid;

    /**
     * Information about speed requirements
     */
    uint32_t speed_min;
    uint32_t speed_max;

    /**
     * Number of hops in the path given below
     */
    uint16_t path_length;

    /**
     * path_length structs defining the *whole* path
     */
    struct GNUNET_PeerIdentity peers[];
};

/**
 * Message for mesh data traffic
 */
struct GNUNET_MESH_Data
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_DATA_[GO|BACK]
     */
    struct GNUNET_MessageHeader header;

    /**
     * OID of the tunnel
     */
    struct GNUNET_PeerIdentity oid;

    /**
     * TID of the tunnel
     */
    uint32_t tid;

    /**
     * Size of payload
     * FIXME uint16 enough?
     */
    uint16_t size;

    /**
     * Payload
     */
    uint8_t data[];
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
     * OID of the tunnel
     */
    struct GNUNET_PeerIdentity oid;

    /**
     * TID of the tunnel
     */
    uint32_t tid;

    /**
     * Slowest link down the path
     */
    uint32_t speed_min;

    /**
     * Fastest link down the path
     */
    uint32_t speed_max;
};

#endif