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

#include <gnunet_mesh_service_new.h>
#include "gnunet_common.h"

/******************************************************************************/
/********************        MESH LOCAL MESSAGES      *************************/
/******************************************************************************/
/*  Any API call should be documented in the folowing table under API CALL.
 *  Also, any message type should be documented in the following table, with the
 * associated event.
 * 
 * API CALL (GNUNET_MESH_*)             MESSAGE USED
 * ------------------------             ------------
 * connect                              GNUNET_MESH_ClientConnect
 * disconnect                           None (network level disconnect)
 *
 * tunnel_create                        GNUNET_MESH_TunnelMessage
 * tunnel_destroy                       GNUNET_MESH_TunnelMessage
 *
 * peer_request_connect_add             GNUNET_MESH_PeerControl
 * peer_request_connect_del             GNUNET_MESH_PeerControl
 * peer_request_connect_by_type         GNUNET_MESH_ConnectPeerByType
 *
 * notify_transmit_ready                GNUNET_MESH_TransmitReady
 * notify_transmit_ready_cancel         None (clear of internal data structures)
 * 
 * 
 * 
 * EVENT                                MESSAGE USED
 * -----                                ------------
 * notify_transmit_ready reply          GNUNET_MESH_TransmitReady
 * notify_transmit_ready data           GNUNET_MESH_Data OR
 *                                      GNUNET_MESH_DataBroadcast
 * new incoming tunnel                  GNUNET_MESH_PeerControl
 * peer connects to a tunnel            GNUNET_MESH_PeerControl
 * peer disconnects from a tunnel       GNUNET_MESH_PeerControl
 */

/******************************************************************************/
/**************************       CONSTANTS      ******************************/
/******************************************************************************/

#define GNUNET_MESH_LOCAL_TUNNEL_ID_MARK 0x80000000


/******************************************************************************/
/**************************        MESSAGES      ******************************/
/******************************************************************************/

/**
 * Message for a client to register to the service
 */
struct GNUNET_MESH_ClientConnect {
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT
     *
     * Size: sizeof(struct GNUNET_MESH_ClientConnect) +
     *       sizeof(uint16_t) * types +
     *       sizeof(MESH_ApplicationType) * applications
     */
    struct GNUNET_MessageHeader header;
    uint16_t                    types           GNUNET_PACKED;
    uint16_t                    applications    GNUNET_PACKED;
    /* uint16_t                 list_types[types]           */
    /* uint16_t                 list_apps[applications]     */
};


/**
 * Type for tunnel numbering.
 * - Local tunnel numbers are >= 0x80000000
 * - Global tunnel numbers are < 0x80000000
 */
typedef uint32_t MESH_TunnelNumber;

/**
 * Message for a client to create and destroy tunnels.
 */
struct GNUNET_MESH_TunnelMessage {
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_[CREATE|DESTROY]
     *
     * Size: sizeof(struct GNUNET_MESH_TunnelMessage)
     */
    struct GNUNET_MessageHeader header;

    /**
     * ID of a tunnel controlled by this client.
     */
    MESH_TunnelNumber           tunnel_id GNUNET_PACKED;
};

/**
 * Message for:
 * - request adding and deleting peers from a tunnel
 * - notify the client that peers have connected:
 *   -- requested
 *   -- unrequested (new incoming tunnels)
 * - notify the client that peers have disconnected
 */
struct GNUNET_MESH_PeerControl {

  /**
   * Type: GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT_PEER_[ADD|DEL]
   *       (client to service, client created tunnel)
   *       GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_[CONNECTED|DISCONNECTED]
   *       (service to client)
   * 
   * Size: sizeof(struct GNUNET_MESH_PeerControl) 
   */
  struct GNUNET_MessageHeader   header;

  /**
   * ID of a tunnel controlled by this client.
   */
   MESH_TunnelNumber            tunnel_id GNUNET_PACKED;
  
  /**
   * Peer to connect/disconnect.
   */
  struct GNUNET_PeerIdentity    peer;
};


/**
 * Message for connecting to peers offering a certain service.
 */
struct GNUNET_MESH_ConnectPeerByType {
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT_PEER_BY_TYPE
     */
    struct GNUNET_MessageHeader header;

  /**
   * ID of a tunnel controlled by this client.
   */
   MESH_TunnelNumber            tunnel_id GNUNET_PACKED;
 
  /**
   * Type specification 
   */
    GNUNET_MESH_ApplicationType type GNUNET_PACKED;
};


/**
 *  Message for notifying the service that the client wants to send data or
 * notifying a client that the service is ready to accept data.
 */
struct GNUNET_MESH_TransmitReady {
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_LOCAL_REQUEST_TRANSMIT_READY
     *       GNUNET_MESSAGE_TYPE_MESH_LOCAL_NOTIFY_TRANSMIT_READY
     */
    struct GNUNET_MessageHeader header;

    /**
     * ID of a tunnel controlled by this client.
     */
    MESH_TunnelNumber           tunnel_id GNUNET_PACKED;

    /**
     * Size of message we would like to transmit to this tunnel
     */
    uint32_t                    msg_size GNUNET_PACKED; 
};


/**
 * Message to encapsulate data transmitted to/from the service
 */
struct GNUNET_MESH_Data {
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_LOCAL_DATA
     *       (client to service, or service to client)
     * Size: sizeof(struct GNUNET_MESH_Data) + sizeof (data)
     */
    struct GNUNET_MessageHeader header;

    /**
     * ID of a tunnel controlled by this client.
     */
    MESH_TunnelNumber           tunnel_id GNUNET_PACKED;

    /**
     * Source or destination of the message (depending on direction).
     */
    struct GNUNET_PeerIdentity  peer_id;

    /* uint8_t data[] */
};

/**
 * Message to encapsulate broadcast data transmitted to the service
 */
struct GNUNET_MESH_DataBroadcast {
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_LOCAL_DATA_BROADCAST
     *       (client to service only, client created tunnel)
     * Size: sizeof(struct GNUNET_MESH_DataBroadcast) + sizeof (data)
     */
    struct GNUNET_MessageHeader header;

    /**
     * ID of a tunnel controlled by this client.
     */
    MESH_TunnelNumber           tunnel_id GNUNET_PACKED;

    /* uint8_t data[] */
};


#endif
