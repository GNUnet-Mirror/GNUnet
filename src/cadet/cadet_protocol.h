/*
     This file is part of GNUnet.
     Copyright (C) 2001 - 2011 GNUnet e.V.

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @author Bartlomiej Polot
 * @file cadet/cadet_protocol.h
 */

#ifndef CADET_PROTOCOL_H_
#define CADET_PROTOCOL_H_

#include "platform.h"
#include "gnunet_util_lib.h"
#include "cadet.h"

#ifdef __cplusplus

struct GNUNET_CADET_TunnelMessage;
extern "C"
{
#if 0
  /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/******************************************************************************/
/********************      CADET NETWORK MESSAGES     **************************/
/******************************************************************************/

GNUNET_NETWORK_STRUCT_BEGIN


/******************************************************************************/
/*****************************   CONNECTION  **********************************/
/******************************************************************************/


/**
 * Message for cadet connection creation.
 */
struct GNUNET_CADET_ConnectionCreateMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE
   *
   * Size: sizeof (struct GNUNET_CADET_ConnectionCreateMessage) +
   *       path_length * sizeof (struct GNUNET_PeerIdentity)
   */
  struct GNUNET_MessageHeader header;

  /**
   * For alignment.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * ID of the connection
   */
  struct GNUNET_CADET_ConnectionTunnelIdentifier cid;

  /**
   * path_length structs defining the *whole* path from the origin [0] to the
   * final destination [path_length-1].
   */
  /* struct GNUNET_PeerIdentity peers[path_length]; */
};


/**
 * Message for ack'ing a connection
 */
struct GNUNET_CADET_ConnectionCreateMessageAckMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE_ACK
   */
  struct GNUNET_MessageHeader header;

  /**
   * For alignment.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * ID of the connection.
   */
  struct GNUNET_CADET_ConnectionTunnelIdentifier cid;

};


/**
 * Message for notifying a disconnection in a path
 */
struct GNUNET_CADET_ConnectionBrokenMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_CADET_CONNECTION_BROKEN
   */
  struct GNUNET_MessageHeader header;

  /**
   * For alignment.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * ID of the connection.
   */
  struct GNUNET_CADET_ConnectionTunnelIdentifier cid;

  /**
   * ID of the endpoint
   */
  struct GNUNET_PeerIdentity peer1;

  /**
   * ID of the endpoint
   */
  struct GNUNET_PeerIdentity peer2;
};


/**
 * Message to destroy a connection.
 */
struct GNUNET_CADET_ConnectionDestroyMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_CADET_CONNECTION_DESTROY
   */
  struct GNUNET_MessageHeader header;

  /**
   * For alignment.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * ID of the connection.
   */
  struct GNUNET_CADET_ConnectionTunnelIdentifier cid;
};


/**
 * Message to acknowledge cadet encrypted traffic.
 */
struct GNUNET_CADET_ConnectionEncryptedAckMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_CADET_ENCRYPTED_HOP_BY_HOP_ACK
   */
  struct GNUNET_MessageHeader header;

  /**
   * Maximum packet ID authorized.
   */
  uint32_t ack GNUNET_PACKED;

  /**
   * ID of the connection.
   */
  struct GNUNET_CADET_ConnectionTunnelIdentifier cid;
};


/**
 * Message to query a peer about its Flow Control status regarding a tunnel.
 */
struct GNUNET_CADET_ConnectionHopByHopPollMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_CADET_CONNECTION_HOP_BY_HOP_POLL
   */
  struct GNUNET_MessageHeader header;

  /**
   * Last packet sent.
   */
  uint32_t pid GNUNET_PACKED;

  /**
   * ID of the connection.
   */
  struct GNUNET_CADET_ConnectionTunnelIdentifier cid;

};



/******************************************************************************/
/*******************************   TUNNEL   ***********************************/
/******************************************************************************/

/**
 * Flags to be used in GNUNET_CADET_KX.
 */
enum GNUNET_CADET_KX_Flags {

  /**
   * Should the peer reply with its KX details?
   */
  GNUNET_CADET_KX_FLAG_NONE = 0,

  /**
   * The peer should reply with its KX details?
   */
  GNUNET_CADET_KX_FLAG_FORCE_REPLY = 1
};


/**
 * Message for a Key eXchange for a tunnel.
 */
struct GNUNET_CADET_TunnelKeyExchangeMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_CADET_TUNNEL_KX.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Flags for the key exchange in NBO, based on
   * `enum GNUNET_CADET_KX_Flags`.
   */
  uint32_t flags GNUNET_PACKED;

  /**
   * ID of the connection.
   */
  struct GNUNET_CADET_ConnectionTunnelIdentifier cid;

  /**
   * Sender's ephemeral public ECC key encoded in a
   * format suitable for network transmission, as created
   * using 'gcry_sexp_sprint'.
   */
  struct GNUNET_CRYPTO_EcdhePublicKey ephemeral_key;

  /**
   * Sender's next ephemeral public ECC key encoded in a
   * format suitable for network transmission, as created
   * using 'gcry_sexp_sprint'.
   */
  struct GNUNET_CRYPTO_EcdhePublicKey ratchet_key;
};


/**
 * Axolotl tunnel message.
 */
struct GNUNET_CADET_ConnectionEncryptedMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_CONNECTION_ENCRYPTED
   */
  struct GNUNET_MessageHeader header;

  /**
   * ID of the packet (hop by hop).
   */
  uint32_t pid GNUNET_PACKED;

  /**
   * ID of the connection.
   */
  struct GNUNET_CADET_ConnectionTunnelIdentifier cid;

  /**
   * MAC of the encrypted message, used to verify message integrity.
   * Everything after this value  will be encrypted with the header key
   * and authenticated.
   */
  struct GNUNET_ShortHashCode hmac;

  /**************** AX_HEADER start ****************/

  /**
   * Number of messages sent with the current ratchet key.
   */
  uint32_t Ns GNUNET_PACKED;

  /**
   * Number of messages sent with the previous ratchet key.
   */
  uint32_t PNs GNUNET_PACKED;

  /**
   * Current ratchet key.
   */
  struct GNUNET_CRYPTO_EcdhePublicKey DHRs;

  /**************** AX_HEADER  end  ****************/

  /**
   * Encrypted content follows.
   */
};



/******************************************************************************/
/*******************************   CHANNEL  ***********************************/
/******************************************************************************/

#ifndef NEW_CADET

/**
 * Message to create a Channel.
 */
struct GNUNET_CADET_ChannelCreateMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_CADET_CHANNEL_CREATE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Channel options.
   */
  uint32_t opt GNUNET_PACKED;

  /**
   * Destination port.
   */
  struct GNUNET_HashCode port;

  /**
   * ID of the channel
   */
  struct GNUNET_CADET_ChannelNumber chid;
};

#endif

/**
 * Message to manage a Channel (ACK, NACK, Destroy).
 */
struct GNUNET_CADET_ChannelManageMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_CADET_CHANNEL_{ACK|NACK|DESTROY}
   */
  struct GNUNET_MessageHeader header;

  /**
   * ID of the channel
   */
  struct GNUNET_CADET_ChannelNumber chid;
};


#ifndef NEW_CADET

/**
 * Message for cadet data traffic.
 */
struct GNUNET_CADET_ChannelDataMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_CADET_UNICAST,
   *       #GNUNET_MESSAGE_TYPE_CADET_TO_ORIGIN
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique ID of the payload message
   */
  uint32_t mid GNUNET_PACKED;

  /**
   * ID of the channel
   */
  struct GNUNET_CADET_ChannelNumber chid;

  /**
   * Payload follows
   */
};


/**
 * Message to acknowledge end-to-end data.
 */
struct GNUNET_CADET_ChannelDataAckMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_CADET_CHANNEL_DATA_ACK
   */
  struct GNUNET_MessageHeader header;

  /**
   * ID of the channel
   */
  struct GNUNET_CADET_ChannelNumber chid;

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

#endif

GNUNET_NETWORK_STRUCT_END

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef CADET_PROTOCOL_H */
#endif
/* end of cadet_protocol.h */
