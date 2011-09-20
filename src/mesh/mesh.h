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
#include <gnunet_mesh_service_new.h>

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
 * - Local tunnel numbers are >= 0x80000000
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


/******************************************************************************/
/************************        ENUMERATIONS      ****************************/
/******************************************************************************/

/**
 * All the states a peer participating in a tunnel can be in.
 */
enum MeshPeerState
{
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


/******************************************************************************/
/************************      DATA STRUCTURES     ****************************/
/******************************************************************************/

/**
 * Information regarding a possible path to reach a single peer
 */
struct MeshPeerPath
{

    /**
     * Linked list
     */
  struct MeshPeerPath *next;
  struct MeshPeerPath *prev;

    /**
     * List of all the peers that form the path from origin to target.
     */
  GNUNET_PEER_Id *peers;

    /**
     * Number of peers (hops) in the path
     */
  unsigned int length;

};


/**
 * Node of path tree for a tunnel
 */
struct MeshTunnelPathNode
{
  /**
   * Tunnel this node belongs to (and therefore tree)
   */
  struct MeshTunnel *t;

  /**
   * Peer this node describes
   */
  GNUNET_PEER_Id peer;

  /**
   * Parent node in the tree
   */
  struct MeshTunnelPathNode *parent;

  /**
   * Array of children
   */
  struct MeshTunnelPathNode *children;

  /**
   * Number of children
   */
  unsigned int nchildren;

    /**
     * Status of the peer in the tunnel
     */
  enum MeshPeerState status;
};


/**
 * Tree to reach all peers in the tunnel
 */
struct MeshTunnelPath
{
  /**
   * How often to refresh the path
   */
  struct GNUNET_TIME_Relative refresh;

  /**
   * Tunnel this path belongs to
   */
  struct MeshTunnel *t;

  /**
   * Root node of peer tree
   */
  struct MeshTunnelPathNode *root;

  /**
   * Node that represents our position in the tree (for non local tunnels)
   */
  struct MeshTunnelPathNode *me;

  /**
   * Cache of all peers and the first hop to them.
   * Indexed by Peer_Identity, contains a pointer to the PeerIdentity
   * of 1st hop.
   */
  struct GNUNET_CONTAINER_MultiHashMap *first_hops;

};


/** FWD declaration */
struct MeshPeerInfo;

/**
 * Struct containing all info possibly needed to build a package when called
 * back by core.
 */
struct MeshDataDescriptor
{
    /** ID of the tunnel this packet travels in */
  struct MESH_TunnelID *origin;

    /** Ultimate destination of the packet */
  GNUNET_PEER_Id destination;

    /** Number of identical messages sent to different hops (multicast) */
  unsigned int copies;

    /** Size of the data */
  size_t size;

    /** Client that asked for the transmission, if any */
  struct GNUNET_SERVER_Client *client;

    /** Who was is message being sent to */
  struct MeshPeerInfo *peer;

    /** Which handler was used to request the transmission */
  unsigned int handler_n;

  /* Data at the end */
};


/**
 * Struct containing all information regarding a given peer
 */
struct MeshPeerInfo
{
    /**
     * ID of the peer
     */
  GNUNET_PEER_Id id;

    /**
     * Last time we heard from this peer
     */
  struct GNUNET_TIME_Absolute last_contact;

    /**
     * Number of attempts to reconnect so far
     */
  int n_reconnect_attempts;

    /**
     * Paths to reach the peer, ordered by ascending hop count
     */
  struct MeshPeerPath *path_head;

    /**
     * Paths to reach the peer, ordered by ascending hop count
     */
  struct MeshPeerPath *path_tail;

    /**
     * Handle to stop the DHT search for a path to this peer
     */
  struct GNUNET_DHT_GetHandle *dhtget;

    /**
     * Handles to stop queued transmissions for this peer
     */
  struct GNUNET_CORE_TransmitHandle *core_transmit[CORE_QUEUE_SIZE];

    /**
     * Pointer to info stuctures used as cls for queued transmissions
     */
  struct MeshDataDescriptor *infos[CORE_QUEUE_SIZE];

    /**
     * Array of tunnels this peer participates in
     * (most probably a small amount, therefore not a hashmap)
     * When the path to the peer changes, notify these tunnels to let them
     * re-adjust their path trees.
     */
  struct MeshTunnel **tunnels;

    /**
     * Number of tunnels above
     */
  unsigned int ntunnels;
};


/**
 * Data scheduled to transmit (to local client or remote peer)
 */
struct MeshQueue
{
    /**
     * Double linked list
     */
  struct MeshQueue *next;
  struct MeshQueue *prev;

    /**
     * Target of the data (NULL if target is client)
     */
  struct MeshPeerInfo *peer;

    /**
     * Client to send the data to (NULL if target is peer)
     */
  struct MeshClient *client;

    /**
     * Size of the message to transmit
     */
  unsigned int size;

    /**
     * How old is the data?
     */
  struct GNUNET_TIME_Absolute timestamp;

    /**
     * Data itself
     */
  struct GNUNET_MessageHeader *data;
};

/**
 * Globally unique tunnel identification (owner + number)
 * DO NOT USE OVER THE NETWORK
 */
struct MESH_TunnelID
{
    /**
     * Node that owns the tunnel
     */
  GNUNET_PEER_Id oid;

    /**
     * Tunnel number to differentiate all the tunnels owned by the node oid
     * ( tid < GNUNET_MESH_LOCAL_TUNNEL_ID_CLI )
     */
  MESH_TunnelNumber tid;
};


struct MeshClient;              /* FWD declaration */

/**
 * Struct containing all information regarding a tunnel
 * For an intermediate node the improtant info used will be:
 * - id        Tunnel unique identification
 * - paths[0]  To know where to send it next
 * - metainfo: ready, speeds, accounting
 */
struct MeshTunnel
{
    /**
     * Tunnel ID
     */
  struct MESH_TunnelID id;

    /**
     * Local tunnel number ( >= GNUNET_MESH_LOCAL_TUNNEL_ID_CLI or 0 )
     */
  MESH_TunnelNumber local_tid;

    /**
     * Last time the tunnel was used
     */
  struct GNUNET_TIME_Absolute timestamp;

    /**
     * Peers in the tunnel, indexed by PeerIdentity -> (MeshPeerInfo)
     */
  struct GNUNET_CONTAINER_MultiHashMap *peers;

    /**
     * Number of peers that are connected and potentially ready to receive data
     */
  unsigned int peers_ready;

    /**
     * Number of peers that have been added to the tunnel
     */
  unsigned int peers_total;

    /**
     * Client owner of the tunnel, if any
     */
  struct MeshClient *client;

    /**
     * Messages ready to transmit
     */
  struct MeshQueue *queue_head;
  struct MeshQueue *queue_tail;

  /**
   * Tunnel paths
   */
  struct MeshTunnelPath *tree;

  /**
   * Task to keep the used paths alive
   */
  GNUNET_SCHEDULER_TaskIdentifier path_refresh_task;
};


/**
 * Info needed to work with tunnel paths and peers
 */
struct MeshPathInfo
{
  /**
   * Tunnel
   */
  struct MeshTunnel *t;

  /**
   * Destination peer
   */
  struct MeshPeerInfo *peer;

  /**
   * Path itself
   */
  struct MeshPeerPath *path;
};


/**
 * Struct containing information about a client of the service
 */
struct MeshClient
{
    /**
     * Linked list
     */
  struct MeshClient *next;
  struct MeshClient *prev;

    /**
     * Tunnels that belong to this client, indexed by local id
     */
  struct GNUNET_CONTAINER_MultiHashMap *tunnels;

    /**
     * Handle to communicate with the client
     */
  struct GNUNET_SERVER_Client *handle;

    /**
     * Applications that this client has claimed to provide
     */
  struct GNUNET_CONTAINER_MultiHashMap *apps;

    /**
     * Messages that this client has declared interest in
     */
  struct GNUNET_CONTAINER_MultiHashMap *types;

    /**
     * Used to search peers offering a service
     */
  struct GNUNET_DHT_GetHandle *dht_get_type;

#if MESH_DEBUG
    /**
     * ID of the client, for debug messages
     */
  unsigned int id;
#endif

};

#endif
