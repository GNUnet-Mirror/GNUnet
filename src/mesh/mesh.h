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
 * disconnect                       None (network level disconnect)
 *
 * tunnel_create                    GNUNET_MESH_TunnelMessage
 * tunnel_destroy                   GNUNET_MESH_TunnelMessage
 *
 * peer_request_connect_add         GNUNET_MESH_ConnectPeer
 * peer_request_connect_del         GNUNET_MESH_ConnectPeer
 * peer_request_connect_by_type     GNUNET_MESH_ConnectPeerByType
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


/**
 *
 */
struct GNUNET_MESH_TunnelMessage {
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_[CREATE|DESTROY]
     */
    struct GNUNET_MessageHeader header;

  /**
   * ID of a tunnel controlled by this client.
   */
    uint32_t tunnel_id GNUNET_PACKED;
};


struct GNUNET_MESH_PeerControl {

  /**
   * Type: GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT_PEER_[ADD|DEL] (client to service, client created tunnel)
   * Type: GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_NOTIFY[CONNECT|DISCONNECT] (service to client)
   * 
   * Size: sizeof(struct GNUNET_MESH_PeerControl) 
   */
  struct GNUNET_MessageHeader header;

  /**
   * ID of a tunnel controlled by this client.
   */
    uint32_t tunnel_id GNUNET_PACKED;
  
  /**
   * Peer to connect/disconnect.
   */
  struct GNUNET_PeerIdentity peer;
};




struct GNUNET_MESH_ConnectPeerByType {
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT_PEER_BY_TYPE
     */
    struct GNUNET_MessageHeader header;

  /**
   * ID of a tunnel controlled by this client.
   */
    uint32_t tunnel_id GNUNET_PACKED;
 
  /**
   * Type specification 
   */
    GNUNET_MESH_ApplicationType type;
};


struct GNUNET_MESH_RequestTransmitReady {
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_LOCAL_REQUEST_TRANSMIT_READY
     */
    struct GNUNET_MessageHeader header;

  /**
   * ID of a tunnel controlled by this client.
   */
    uint32_t tunnel_id GNUNET_PACKED;

  /**
   * Size of message we would like to transmit to this tunnel
   */
    uint32_t msg_size GNUNET_PACKED; 
};

struct GNUNET_MESH_NotifyTransmitReady {
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_LOCAL_NOTIFY_TRANSMIT_READY
     */
    struct GNUNET_MessageHeader header;

  /**
   * ID of a tunnel controlled by this client.
   */
    uint32_t tunnel_id GNUNET_PACKED;

  /**
   * Size of message we can now transmit to this tunnel
   */
    uint32_t msg_size GNUNET_PACKED; 
};


struct GNUNET_MESH_Data {
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_LOCAL_DATA (client to service, or service to client)
     *
     * Size: sizeof(struct GNUNET_MESH_Data) + sizeof (data)
     */
    struct GNUNET_MessageHeader header;

  /**
   * ID of a tunnel controlled by this client.
   */
    uint32_t tunnel_id GNUNET_PACKED;

  /**
   * Source or destination of the message (depending on direction).
   */
    struct GNUNET_PeerIdentity destination;

    /* uint8_t data[] */
};


struct GNUNET_MESH_DataBroadcast {
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_LOCAL_DATA_BROADCAST (client to service only, client created tunnel)
     *
     * Size: sizeof(struct GNUNET_MESH_DataBroadcast) + sizeof (data)
     */
    struct GNUNET_MessageHeader header;

  /**
   * ID of a tunnel controlled by this client.
   */
    uint32_t tunnel_id GNUNET_PACKED;

    /* uint8_t data[] */
};


#endif
