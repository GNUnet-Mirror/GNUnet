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

#define MESH_DEBUG              GNUNET_YES


#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_peer_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_protocols.h"
#include <gnunet_mesh_service.h>

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
 * notify_transmit_ready                *GNUNET_MESH_TransmitReady?*
 * notify_transmit_ready_cancel         None (clear of internal data structures)
 *
 *
 *
 * EVENT                                MESSAGE USED
 * -----                                ------------
 * data                                 GNUNET_MESH_Data OR
 *                                      GNUNET_MESH_DataBroadcast
 * new incoming tunnel                  GNUNET_MESH_PeerControl
 * peer connects to a tunnel            GNUNET_MESH_PeerControl
 * peer disconnects from a tunnel       GNUNET_MESH_PeerControl
 */

/******************************************************************************/
/**************************       CONSTANTS      ******************************/
/******************************************************************************/

#define GNUNET_MESH_LOCAL_TUNNEL_ID_CLI 0x80000000
#define GNUNET_MESH_LOCAL_TUNNEL_ID_SERV 0xB0000000

#define CORE_QUEUE_SIZE         10
#define LOCAL_QUEUE_SIZE        100

/******************************************************************************/
/**************************        MESSAGES      ******************************/
/******************************************************************************/

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Message for a client to register to the service
 */
struct GNUNET_MESH_ClientConnect
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT
     *
     * Size: sizeof(struct GNUNET_MESH_ClientConnect) +
     *       sizeof(MESH_ApplicationType) * applications +
     *       sizeof(uint16_t) * types
     */
  struct GNUNET_MessageHeader header;
  uint16_t applications GNUNET_PACKED;
  uint16_t types GNUNET_PACKED;
  /* uint16_t                 list_apps[applications]     */
  /* uint16_t                 list_types[types]           */
};


/**
 * Type for tunnel numbering.
 * - Local tunnel numbers given by the service (incoming) are >= 0xB0000000
 * - Local tunnel numbers given by the client (created) are >= 0x80000000
 * - Global tunnel numbers are < 0x80000000
 */
typedef uint32_t MESH_TunnelNumber;

/**
 * Message for a client to create and destroy tunnels.
 */
struct GNUNET_MESH_TunnelMessage
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_[CREATE|DESTROY]
     *
     * Size: sizeof(struct GNUNET_MESH_TunnelMessage)
     */
  struct GNUNET_MessageHeader header;

    /**
     * ID of a tunnel controlled by this client.
     */
  MESH_TunnelNumber tunnel_id GNUNET_PACKED;
};


/**
 * Message for the service to let a client know about created tunnels.
 */
struct GNUNET_MESH_TunnelNotification
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_CREATE
     *
     * Size: sizeof(struct GNUNET_MESH_TunnelMessage)
     */
  struct GNUNET_MessageHeader header;

    /**
     * ID of a tunnel controlled by this client.
     */
  MESH_TunnelNumber tunnel_id GNUNET_PACKED;

    /**
     * Peer at the other end, if any
     */
  struct GNUNET_PeerIdentity peer;
};

/**
 * Message for:
 * - request adding and deleting peers from a tunnel
 * - notify the client that peers have connected:
 *   -- requested
 *   -- unrequested (new incoming tunnels)
 * - notify the client that peers have disconnected
 */
struct GNUNET_MESH_PeerControl
{

  /**
   * Type: GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT_PEER_[ADD|DEL]
   *       (client to service, client created tunnel)
   *       GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_[CONNECTED|DISCONNECTED]
   *       (service to client)
   *
   * Size: sizeof(struct GNUNET_MESH_PeerControl)
   */
  struct GNUNET_MessageHeader header;

  /**
   * ID of a tunnel controlled by this client.
   */
  MESH_TunnelNumber tunnel_id GNUNET_PACKED;

  /**
   * Peer to connect/disconnect.
   */
  struct GNUNET_PeerIdentity peer;
};


/**
 * Message for connecting to peers offering a certain service.
 */
struct GNUNET_MESH_ConnectPeerByType
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT_PEER_BY_TYPE |
     *       GNUNET_MESSAGE_TYPE_MESH_LOCAL_DISCONNECT_PEER_BY_TYPE
     */
  struct GNUNET_MessageHeader header;

  /**
   * ID of a tunnel controlled by this client.
   */
  MESH_TunnelNumber tunnel_id GNUNET_PACKED;

  /**
   * Type specification
   */
  GNUNET_MESH_ApplicationType type GNUNET_PACKED;
};
GNUNET_NETWORK_STRUCT_END

/******************************************************************************/
/************************        ENUMERATIONS      ****************************/
/******************************************************************************/

/**
 * All the states a peer participating in a tunnel can be in.
 */
enum MeshPeerState
{
    /**
     * Uninitialized status, should never appear in operation.
     */
  MESH_PEER_INVALID,

    /**
     * Peer is the root and owner of the tree
     */
  MESH_PEER_ROOT,

    /**
     * Peer only retransmits traffic, is not a final destination
     */
  MESH_PEER_RELAY,

    /**
     * Path to the peer not known yet
     */
  MESH_PEER_SEARCHING,

    /**
     * Request sent, not yet answered.
     */
  MESH_PEER_WAITING,

    /**
     * Peer connected and ready to accept data
     */
  MESH_PEER_READY,

    /**
     * Peer connected previosly but not responding
     */
  MESH_PEER_RECONNECTING
};



#endif
