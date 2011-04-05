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

#include <gnunet_mesh_service.h>
#include "gnunet_common.h"

/******************************************************************************/
/********************      MESH NETWORK MESSAGES     **************************/
/******************************************************************************/
/* API CALL                         MESSAGE USED
 * --------                         ------------
 * connect                          GNUNET_MESH_Connect
 * disconnect                       Server_disconnect
 *
 * peer_request_connect_any         GNUNET_MESH_ConnectPeer
 * peer_request_connect_all         GNUNET_MESH_ConnectPeer
 * peer_request_connect_add         GNUNET_MESH_ConnectPeer
 * peer_request_connect_del         GNUNET_MESH_ConnectPeer
 * peer_request_connect_by_type     GNUNET_MESH_ConnectPeerByType
 * peer_request_connect_cancel      GNUNET_MESH_Control
 *
 * notify_transmit_ready            GNUNET_MESH_Control
 * notify_transmit_ready_cancel     None
 */

struct GNUNET_MESH_Connect {
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT
     *
     * Size: sizeof(struct GNUNET_MESH_Connect) + messages_subscribed * sizeof (message_type)
     */
    struct GNUNET_MessageHeader header;

    /* uint16_t messages_subscribed[] */
};

struct GNUNET_MESH_ConnectPeer {
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT_PEER_[ANY|ALL|ADD|DEL]
     * 
     * Size: sizeof(struct GNUNET_MESH_ConnectPeer) + npeers * sizeof (struct GNUNET_PeerIdentity)
     */
    struct GNUNET_MessageHeader header;

    /* struct GNUNET_PeerIdentity peers[] */
};

struct GNUNET_MESH_ConnectPeerByType {
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT_PEER_BY_TYPE
     */
    struct GNUNET_MessageHeader header;

    /* Type specification */
    GNUNET_MESH_ApplicationType type;
};

struct GNUNET_MESH_Control {
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT_PEER_CANCEL
     *       GNUNET_MESSAGE_TYPE_MESH_LOCAL_TRANSMIT_READY
     */
    struct GNUNET_MessageHeader header;

    uint32_t tunnel_id GNUNET_PACKED;
    uint32_t variable GNUNET_PACKED; /* Size of data / connection ID */
};

struct GNUNET_MESH_TunnelEvent {
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_[CREATED\DESTROYED]
     */
    struct GNUNET_MessageHeader header;

    uint32_t tunnel_id GNUNET_PACKED;
    uint32_t reason GNUNET_PACKED; /* incoming, connect, timeout, disconnect */
};

struct GNUNET_MESH_Data {
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_LOCAL_DATA
     *
     * Size: sizeof(struct GNUNET_MESH_Data) + sizeof (data)
     */
    struct GNUNET_MessageHeader header;

    uint32_t tunnel_id GNUNET_PACKED;

    struct GNUNET_PeerIdentity destination;

    /* uint8_t data[] */
};

struct GNUNET_MESH_DataBroadcast {
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_LOCAL_DATA_BROADCAST
     *
     * Size: sizeof(struct GNUNET_MESH_DataBroadcast) + sizeof (data)
     */
    struct GNUNET_MessageHeader header;

    uint32_t tunnel_id GNUNET_PACKED;

    /* uint8_t data[] */
};

#endif
