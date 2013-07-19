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
 * @file mesh/mesh_protocol.h
 */

#ifndef MESH_PROTOCOL_H_
#define MESH_PROTOCOL_H_

#ifdef __cplusplus
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
 * Message for mesh path creation.
 */
struct GNUNET_MESH_CreateTunnel
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_PATH_CREATE
     *
     * Size: sizeof(struct GNUNET_MESH_ManipulatePath) +
     *       path_length * sizeof (struct GNUNET_PeerIdentity)
     */
  struct GNUNET_MessageHeader header;

    /**
     * Global id of the tunnel this path belongs to,
     * unique in conjunction with the origin.
     */
  uint32_t tid GNUNET_PACKED;

    /**
     * Tunnel options (GNUNET_MESH_OPTION_*).
     */
  uint32_t opt GNUNET_PACKED;

    /**
     * Destination port.
     */
  uint32_t port GNUNET_PACKED;

    /**
     * FIXME do not add the first hop
     * path_length structs defining the *whole* path from the origin [0] to the
     * final destination [path_length-1].
     */
  /* struct GNUNET_PeerIdentity peers[path_length]; */
};

/**
 * Message for mesh path destruction.
 */
struct GNUNET_MESH_DestroyTunnel
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_MESH_PATH_DESTROY
   *
   * Size: sizeof(struct GNUNET_MESH_ManipulatePath) +
   *       path_length * sizeof (struct GNUNET_PeerIdentity)
   */
  struct GNUNET_MessageHeader header;
  
  /**
   * Global id of the tunnel this path belongs to,
   * unique in conjunction with the origin.
   */
  uint32_t tid GNUNET_PACKED;
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
     * TID of the tunnel
     */
  uint32_t tid GNUNET_PACKED;

    /**
     * Number of hops to live
     */
  uint32_t ttl GNUNET_PACKED;

    /**
     * ID of the packet
     */
  uint32_t pid GNUNET_PACKED;

    /**
     * OID of the tunnel
     */
  struct GNUNET_PeerIdentity oid;

  /**
   * Unique ID of the payload message
   */
  uint32_t mid GNUNET_PACKED;

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
   * TID of the tunnel
   */
  uint32_t tid GNUNET_PACKED;

  /**
   * OID of the tunnel
   */
  struct GNUNET_PeerIdentity oid;

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
 * Message to acknowledge mesh data traffic.
 */
struct GNUNET_MESH_ACK
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_ACK
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
     * Maximum packet ID authorized.
     */
  uint32_t pid GNUNET_PACKED;
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
   * TID of the tunnel
   */
  uint32_t tid GNUNET_PACKED;

  /**
   * OID of the tunnel
   */
  struct GNUNET_PeerIdentity oid;

  /**
   * Last packet sent.
   */
  uint32_t pid GNUNET_PACKED;
};

/**
 * Message for ack'ing a path
 */
struct GNUNET_MESH_PathACK
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_PATH_ACK
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
     * ID of the endpoint
     */
  struct GNUNET_PeerIdentity peer_id;

    /**
     * Initial ACK value for payload.
     */
  uint32_t ack GNUNET_PACKED;

  /* TODO: signature */
};


/**
 * Message for notifying a disconnection in a path
 */
struct GNUNET_MESH_PathBroken
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_PATH_BROKEN
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
 * Message to destroy a tunnel
 */
struct GNUNET_MESH_TunnelDestroy
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_TUNNEL_DESTROY
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

  /* TODO: signature */
};


/**
 * Message to destroy a tunnel
 */
struct GNUNET_MESH_TunnelKeepAlive
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_MESH_PATH_(FWD|BCK)_KEEPALIVE
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
