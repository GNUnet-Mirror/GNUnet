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

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include <stdint.h>

#define MESH_DEBUG              GNUNET_YES

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_peer_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_protocols.h"
#include <gnunet_mesh_service.h>

/******************************************************************************/
/**************************       CONSTANTS      ******************************/
/******************************************************************************/

#define GNUNET_MESH_LOCAL_CHANNEL_ID_CLI        0x80000000
#define GNUNET_MESH_LOCAL_CHANNEL_ID_SERV       0xB0000000

#define HIGH_PID                                0xFFFF0000
#define LOW_PID                                 0x0000FFFF

#define PID_OVERFLOW(pid, max) (pid > HIGH_PID && max < LOW_PID)

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
  /* uint32_t                 list_ports[]           */
};


/**
 * Type for channel numbering.
 * - Local channel numbers given by the service (incoming) are >= 0xB0000000
 * - Local channel numbers given by the client (created) are >= 0x80000000
 * - Global channel numbers are < 0x80000000
 */
typedef uint32_t MESH_ChannelNumber;


/**
 * Hash to be used in Mesh communication. Only 256 bits needed,
 * instead of the 512 from @c GNUNET_HashCode.
 *
 */
struct GNUNET_MeshHash
{
  unsigned char bits[256 / 8];
};


/**
 * Message for a client to create and destroy channels.
 */
struct GNUNET_MESH_ChannelMessage
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_[CREATE|DESTROY]
     *
     * Size: sizeof(struct GNUNET_MESH_ChannelMessage)
     */
  struct GNUNET_MessageHeader header;

    /**
     * ID of a channel controlled by this client.
     */
  MESH_ChannelNumber channel_id GNUNET_PACKED;

    /**
     * Channel's peer
     */
  struct GNUNET_PeerIdentity peer;

    /**
     * Port of the channel.
     */
  uint32_t port GNUNET_PACKED;

    /**
     * Options.
     */
  uint32_t opt GNUNET_PACKED;
};


/**
 * Message for mesh data traffic.
 */
struct GNUNET_MESH_LocalData
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_LOCAL_DATA
     */
  struct GNUNET_MessageHeader header;

    /**
     * ID of the channel
     */
  uint32_t id GNUNET_PACKED;

    /**
     * Payload follows
     */
};


/**
 * Message to allow the client send more data to the service
 * (always service -> client).
 */
struct GNUNET_MESH_LocalAck
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_LOCAL_ACK
     */
  struct GNUNET_MessageHeader header;

    /**
     * ID of the channel allowed to send more data.
     */
  MESH_ChannelNumber channel_id GNUNET_PACKED;

};


/**
 * Message to inform the client about channels in the service.
 */
struct GNUNET_MESH_LocalInfo
{
  /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_LOCAL_INFO[_TUNNEL,_PEER]
   */
  struct GNUNET_MessageHeader header;

  /**
   * ID of the channel allowed to send more data.
   */
  MESH_ChannelNumber channel_id GNUNET_PACKED;

  /**
   * ID of the owner of the channel (can be local peer).
   */
//   struct GNUNET_PeerIdentity owner;

  /**
   * ID of the destination of the channel (can be local peer).
   */
  struct GNUNET_PeerIdentity peer;
};


/**
 * Message to inform the client about one of the peers in the service.
 */
struct GNUNET_MESH_LocalInfoPeer
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_MESH_LOCAL_INFO_PEER[S]
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of paths.
   */
  uint16_t paths GNUNET_PACKED;

  /**
   * Do we have a tunnel toward this peer?
   */
  int16_t tunnel GNUNET_PACKED;

  /**
   * ID of the destination of the tunnel (can be local peer).
   */
  struct GNUNET_PeerIdentity destination;

  /* If type == PEER (no 'S'): GNUNET_PeerIdentity paths[]
   * (each path ends in destination) */
};

/**
 * Message to inform the client about one of the tunnels in the service.
 */
struct GNUNET_MESH_LocalInfoTunnel
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_MESH_LOCAL_INFO_TUNNEL[S]
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of channels.
   */
  uint32_t channels GNUNET_PACKED;

  /**
   * ID of the destination of the tunnel (can be local peer).
   */
  struct GNUNET_PeerIdentity destination;

  /**
   * Number of connections.
   */
  uint32_t connections GNUNET_PACKED;

  /**
   * Encryption state.
   */
  uint16_t estate GNUNET_PACKED;

  /**
   * Connection state.
   */
  uint16_t cstate GNUNET_PACKED;

  /* If TUNNEL (no 'S'): GNUNET_PeerIdentity connection_ids[connections] */
  /* If TUNNEL (no 'S'): uint32_t channel_ids[channels] */
};


GNUNET_NETWORK_STRUCT_END



/**
 * @brief Translate a fwd variable into a string representation, for logging.
 *
 * @param fwd Is FWD? (#GNUNET_YES or #GNUNET_NO)
 *
 * @return String representing FWD or BCK.
 */
char *
GM_f2s (int fwd);


/**
 * Check if one pid is bigger than other, accounting for overflow.
 *
 * @param bigger Argument that should be bigger.
 * @param smaller Argument that should be smaller.
 *
 * @return True if bigger (arg1) has a higher value than smaller (arg 2).
 */
int
GM_is_pid_bigger (uint32_t bigger, uint32_t smaller);


/**
 * Get the higher ACK value out of two values, taking in account overflow.
 *
 * @param a First ACK value.
 * @param b Second ACK value.
 *
 * @return Highest ACK value from the two.
 */
uint32_t
GM_max_pid (uint32_t a, uint32_t b);


/**
 * Get the lower ACK value out of two values, taking in account overflow.
 *
 * @param a First ACK value.
 * @param b Second ACK value.
 *
 * @return Lowest ACK value from the two.
 */
uint32_t
GM_min_pid (uint32_t a, uint32_t b);


/**
 * Convert a 256 bit MeshHash into a 512 HashCode to use in GNUNET_h2s,
 * multihashmap, and other HashCode-based functions.
 *
 * @param id A 256 bit hash to expand.
 *
 * @return A HashCode containing the original 256 bit hash right-padded with 0.
 */
const struct GNUNET_HashCode *
GM_h2hc (const struct GNUNET_MeshHash *id);

/**
 * Convert a message type into a string to help debug
 * Generated with:
 * FIND:        "#define ([^ ]+)[ ]*([0-9]+)"
 * REPLACE:     "    case \2: return "\1"; break;"
 *
 * @param m Message type.
 *
 * @return Human readable string description.
 */
const char *
GM_m2s (uint16_t m);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
