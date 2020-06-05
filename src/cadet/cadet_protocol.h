/*
     This file is part of GNUnet.
     Copyright (C) 2007 - 2017 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file cadet/cadet_protocol.h
 * @brief P2P messages used by CADET
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 */

#ifndef CADET_PROTOCOL_H_
#define CADET_PROTOCOL_H_

/**
 * At best, enable when debugging #5328!
 */
#define DEBUG_KX 0
#if DEBUG_KX
#warning NEVER run this in production! KX debugging is on!
#endif

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
   * Connection options in network byte order.
   * #GNUNET_CADET_OPTION_DEFAULT for buffered;
   * #GNUNET_CADET_OPTION_NOBUFFER for unbuffered.
   * Other flags are ignored and should not be set at this level.
   */
  uint32_t options GNUNET_PACKED;

  /**
   * This flag indicates the peer sending the connection create 
   * meassage likes to trigger a KX handshake.
   */
  int has_monotime;
  
  /**
   *  This monotonic time is set, if a peer likes to trigger a KX, but is not
   *  the peer that should start the KX. (xrs,t3ss)
   */
  struct GNUNET_TIME_AbsoluteNBO monotime;

  /**
   *  We sign the monotime. The receiving peer can check the signature, to verify
   *  the sending peer.
   */
  struct GNUNET_CRYPTO_EddsaSignature monotime_sig;

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
struct GNUNET_CADET_ConnectionCreateAckMessage
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
   * Type: #GNUNET_MESSAGE_TYPE_CADET_CONNECTION_BROKEN.
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


/******************************************************************************/
/*******************************   TUNNEL   ***********************************/
/******************************************************************************/

/**
 * Unique identifier (counter) for an encrypted message in a channel.
 * Used to match #GNUNET_MESSAGE_TYPE_CADET_CONNECTION_HOP_BY_HOP_ENCRYPTED_ACK
 * and  #GNUNET_MESSAGE_TYPE_CADET_TUNNEL_ENCRYPTED_POLL messages
 * against the respective  #GNUNET_MESSAGE_TYPE_CADET_TUNNEL_ENCRYPTED
 * messages.
 */
struct CadetEncryptedMessageIdentifier
{
  /**
   * This number is incremented by one per message. It may wrap around.
   * In network byte order.
   */
  uint32_t pid GNUNET_PACKED;
};


/**
 * Flags to be used in GNUNET_CADET_KX.
 */
enum GNUNET_CADET_KX_Flags
{
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
   * Type: #GNUNET_MESSAGE_TYPE_CADET_TUNNEL_KX or
   * #GNUNET_MESSAGE_TYPE_CADET_TUNNEL_KX_AUTH as part
   * of `struct GNUNET_CADET_TunnelKeyExchangeAuthMessage`.
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

#if DEBUG_KX
  /**
   * Sender's ephemeral public ECC key encoded in a
   * format suitable for network transmission, as created
   * using 'gcry_sexp_sprint'.
   */
  struct GNUNET_CRYPTO_EcdhePrivateKey ephemeral_key_XXX; // for debugging KX-crypto!

  /**
   * Sender's ephemeral public ECC key encoded in a
   * format suitable for network transmission, as created
   * using 'gcry_sexp_sprint'.
   */
  struct GNUNET_CRYPTO_EddsaPrivateKey private_key_XXX; // for debugging KX-crypto!
#endif

  /**
   * Sender's next ephemeral public ECC key encoded in a
   * format suitable for network transmission, as created
   * using 'gcry_sexp_sprint'.
   */
  struct GNUNET_CRYPTO_EcdhePublicKey ratchet_key;
};


/**
 * Message for a Key eXchange for a tunnel, with authentication.
 * Used as a response to the initial KX as well as for rekeying.
 */
struct GNUNET_CADET_TunnelKeyExchangeAuthMessage
{
  /**
   * Message header with key material.
   */
  struct GNUNET_CADET_TunnelKeyExchangeMessage kx;

#if DEBUG_KX
  /**
   * Received ephemeral public ECC key encoded in a
   * format suitable for network transmission, as created
   * using 'gcry_sexp_sprint'.
   */
  struct GNUNET_CRYPTO_EcdhePublicKey r_ephemeral_key_XXX; // for debugging KX-crypto!
#endif

  /**
   * KDF-proof that sender could compute the 3-DH, used in lieu of a
   * signature or payload data.
   */
  struct GNUNET_HashCode auth;
};


/**
 * Encrypted axolotl header with numbers that identify which
 * keys in which ratchet are to be used to decrypt the body.
 */
struct GNUNET_CADET_AxHeader
{
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
};


/**
 * Axolotl-encrypted tunnel message with application payload.
 */
struct GNUNET_CADET_TunnelEncryptedMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_CADET_TUNNEL_ENCRYPTED
   */
  struct GNUNET_MessageHeader header;

  /**
   * Reserved, for alignment.
   */
  uint32_t reserved GNUNET_PACKED;

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

  /**
   * Axolotl-header that specifies which keys to use in which ratchet
   * to decrypt the body that follows.
   */
  struct GNUNET_CADET_AxHeader ax_header;

  /**
   * Encrypted content follows.
   */
};


/******************************************************************************/
/*******************************   CHANNEL  ***********************************/
/******************************************************************************/


/**
 * Message to create a Channel.
 */
struct GNUNET_CADET_ChannelOpenMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_CADET_CHANNEL_OPEN
   */
  struct GNUNET_MessageHeader header;

  /**
   * Channel options.
   */
  uint32_t opt GNUNET_PACKED;

  /**
   * Hash of destination port and listener.
   */
  struct GNUNET_HashCode h_port;

  /**
   * ID of the channel within the tunnel.
   */
  struct GNUNET_CADET_ChannelTunnelNumber ctn;
};


/**
 * Message to acknowledge opening a channel of type
 * #GNUNET_MESSAGE_TYPE_CADET_CHANNEL_OPEN_ACK.
 */
struct GNUNET_CADET_ChannelOpenAckMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_CADET_CHANNEL_OPEN_ACK
   */
  struct GNUNET_MessageHeader header;

  /**
   * For alignment.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * ID of the channel
   */
  struct GNUNET_CADET_ChannelTunnelNumber ctn;

  /**
   * Port number of the channel, used to prove to the
   * initiator that the receiver knows the port.
   */
  struct GNUNET_HashCode port;
};


/**
 * Message to destroy a channel of type
 * #GNUNET_MESSAGE_TYPE_CADET_CHANNEL_DESTROY.
 */
struct GNUNET_CADET_ChannelDestroyMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_CADET_CHANNEL_DESTROY
   */
  struct GNUNET_MessageHeader header;

  /**
   * For alignment.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * ID of the channel
   */
  struct GNUNET_CADET_ChannelTunnelNumber ctn;
};


/**
 * Number used to uniquely identify messages in a CADET Channel.
 */
struct ChannelMessageIdentifier
{
  /**
   * Unique ID of the message, cycles around, in NBO.
   */
  uint32_t mid GNUNET_PACKED;
};


/**
 * Message for cadet data traffic.
 */
struct GNUNET_CADET_ChannelAppDataMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_CADET_CHANNEL_APP_DATA.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique ID of the payload message.
   */
  struct ChannelMessageIdentifier mid;

  /**
   * ID of the channel
   */
  struct GNUNET_CADET_ChannelTunnelNumber ctn;

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
   * Type: #GNUNET_MESSAGE_TYPE_CADET_CHANNEL_APP_DATA_ACK
   */
  struct GNUNET_MessageHeader header;

  /**
   * ID of the channel
   */
  struct GNUNET_CADET_ChannelTunnelNumber ctn;

  /**
   * Bitfield of already-received newer messages.  Note that bit 0
   * corresponds to @e mid + 1.
   *
   * pid +  0 @ LSB
   * pid + 63 @ MSB
   */
  uint64_t futures GNUNET_PACKED;

  /**
   * Next message ID expected.
   */
  struct ChannelMessageIdentifier mid;
};


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
