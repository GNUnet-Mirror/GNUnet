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
 * Message for mesh path management
 */
struct GNUNET_MESH_ManipulatePath
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_PATH_[CREATE|CHANGE|ADD|DEL]
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
     * path_length structs defining the *whole* path from the origin [0] to the
     * final destination [path_length-1].
     */
  /* struct GNUNET_PeerIdentity peers[path_length]; */
};

/**
 * Message for mesh data traffic to all tunnel targets.
 */
struct GNUNET_MESH_Multicast
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_MULTICAST
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
     * Unique ID of the packet
     */
  uint32_t mid GNUNET_PACKED;

    /**
     * OID of the tunnel
     */
  struct GNUNET_PeerIdentity oid;

    /**
     * Payload follows
     */
};


/**
 * Message for mesh data traffic to a particular destination from origin.
 */
struct GNUNET_MESH_Unicast
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_UNICAST
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
     * Payload follows
     */
};


/**
 * Message for mesh data traffic from a tunnel participant to origin.
 */
struct GNUNET_MESH_ToOrigin
{
    /**
     * Type: GNUNET_MESSAGE_TYPE_MESH_TO_ORIGIN
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
     * Payload follows
     */
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
GNUNET_NETWORK_STRUCT_END

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef MES_PROTOCOL_H */
#endif
/* end of mesh_protocol.h */
