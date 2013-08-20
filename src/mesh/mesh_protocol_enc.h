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
 * @file mesh/mesh_protocol_enc.h
 */

#ifndef MESH_PROTOCOL_ENC_H_
#define MESH_PROTOCOL_ENC_H_

#include "platform.h"
#include "gnunet_util_lib.h"
#include "mesh_enc.h"

#ifdef __cplusplus

struct GNUNET_MESH_TunnelMessage;
extern "C"
{
#if 0
  /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/******************************************************************************/
/********************      MESH NETWORK MESSAGES     **************************/
/******************************************************************************/

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Message for mesh connection creation.
 * TODO onionify path, add random tunnel ID
 */
struct GNUNET_MESH_ConnectionCreate
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_CONNECTION_CREATE
     *
     * Size: sizeof(struct GNUNET_MESH_ManipulatePath) +
     *              path_length * sizeof (struct GNUNET_PeerIdentity)
     */
  struct GNUNET_MessageHeader header;

    /**
     * ID of the connection
     */
  struct GNUNET_HashCode cid;

    /**
     * path_length structs defining the *whole* path from the origin [0] to the
     * final destination [path_length-1].
     */
  /* struct GNUNET_PeerIdentity peers[path_length]; */
};

/**
 * Message for ack'ing a connection
 */
struct GNUNET_MESH_ConnectionACK
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_CONNECTION_ACK
     */
  struct GNUNET_MessageHeader header;

    /**
     * Always 0.
     */
  uint32_t reserved GNUNET_PACKED;

    /**
     * ID of the connection.
     */
  struct GNUNET_HashCode cid;

  /* TODO: signature */
};

/**
 * Tunnel(ed) message.
 */
struct GNUNET_MESH_Encrypted
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_MESH_{FWD,BCK}
   */
  struct GNUNET_MessageHeader header;

  /**
   * ID of the packet (hop by hop).
   */
  uint32_t pid GNUNET_PACKED;

  /**
   * ID of the connection.
   */
  struct GNUNET_HashCode cid;

  /**
   * Initialization Vector for payload encryption.
   */
  uint64_t iv;

  /**
   * Number of hops to live.
   */
  uint32_t ttl GNUNET_PACKED;
 
  /**
   * Always 0.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Encrypted content follows.
   */
};

struct GNUNET_MESH_ChannelCreate
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_MESH_CHANNEL_CREATE
   */
  struct GNUNET_MessageHeader header;

  /**
   * ID of the channel
   */
  MESH_ChannelNumber chid GNUNET_PACKED;

  /**
   * Destination port.
   */
  uint32_t port GNUNET_PACKED;

  /**
   * Channel options.
   */
  uint32_t opt GNUNET_PACKED;
};

struct GNUNET_MESH_ChannelManage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_MESH_CHANNEL_{ACK|DESTROY}
   */
  struct GNUNET_MessageHeader header;

  /**
   * ID of the channel
   */
  MESH_ChannelNumber chid GNUNET_PACKED;
};

/**
 * Message for mesh data traffic.
 */
struct GNUNET_MESH_Data
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_UNICAST,
     *       GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN
     */
  struct GNUNET_MessageHeader header;

    /**
     * Unique ID of the payload message
     */
  uint32_t mid GNUNET_PACKED;

    /**
     * ID of the channel
     */
  MESH_ChannelNumber chid GNUNET_PACKED;

    /**
     * Payload follows
     */
};


/**
 * Message to acknowledge end-to-end data.
 */
struct GNUNET_MESH_DataACK
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_MESH_DATA_ACK
   */
  struct GNUNET_MessageHeader header;

  /**
   * ID of the channel
   */
  MESH_ChannelNumber chid GNUNET_PACKED;

  /**
   * Bitfield of already-received newer messages
   * pid +  1 @ LSB
   * pid + 64 @ MSB
   */
  uint64_t futures GNUNET_PACKED;

  /**
   * Last message ID received.
   */
  uint32_t mid GNUNET_PACKED;
};


/**
 * Message to acknowledge mesh encrypted traffic.
 */
struct GNUNET_MESH_ACK
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_ACK
     */
  struct GNUNET_MessageHeader header;

    /**
     * Maximum packet ID authorized.
     */
  uint32_t ack GNUNET_PACKED;

    /**
     * ID of the connection.
     */
  struct GNUNET_HashCode cid;
};


/**
 * Message to query a peer about its Flow Control status regarding a tunnel.
 */
struct GNUNET_MESH_Poll
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_MESH_POLL
   */
  struct GNUNET_MessageHeader header;

  /**
   * Last packet sent.
   */
  uint32_t pid GNUNET_PACKED;

    /**
     * ID of the connection.
     */
  struct GNUNET_HashCode cid;

};


/**
 * Message for notifying a disconnection in a path
 */
struct GNUNET_MESH_ConnectionBroken
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_CONNECTION_BROKEN
     */
  struct GNUNET_MessageHeader header;

    /**
     * Always 0.
     */
  uint32_t reserved GNUNET_PACKED;

    /**
     * ID of the connection.
     */
  struct GNUNET_HashCode cid;

    /**
     * ID of the endpoint
     */
  struct GNUNET_PeerIdentity peer1;

    /**
     * ID of the endpoint
     */
  struct GNUNET_PeerIdentity peer2;

  /* TODO: signature */
};


/**
 * Message to destroy a connection.
 */
struct GNUNET_MESH_ConnectionDestroy
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_CONNECTION_DESTROY
     */
  struct GNUNET_MessageHeader header;

    /**
     * Always 0.
     */
  uint32_t reserved GNUNET_PACKED;

    /**
     * ID of the connection.
     */
  struct GNUNET_HashCode cid;

  /* TODO: signature */
};


/**
 * Message to keep a connection alive.
 */
struct GNUNET_MESH_ConnectionKeepAlive
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_MESH_(FWD|BCK)_KEEPALIVE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always 0.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * ID of the connection.
   */
  struct GNUNET_HashCode cid;
};



GNUNET_NETWORK_STRUCT_END

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef MESH_PROTOCOL_H */
#endif
/* end of mesh_protocol.h */
