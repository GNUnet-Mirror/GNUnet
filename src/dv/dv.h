/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2009 Christian Grothoff (and other contributing authors)

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
 * @author Christian Grothoff
 * @author NOT Nathan Evans
 * @file dv/dv.h
 */
#ifndef DV_H
#define DV_H

#include "gnunet_common.h"

#define DEBUG_DV_GOSSIP GNUNET_EXTRA_LOGGING
#define DEBUG_DV_GOSSIP_SEND GNUNET_EXTRA_LOGGING
#define DEBUG_DV_GOSSIP_RECEIPT GNUNET_EXTRA_LOGGING
#define DEBUG_DV_MESSAGES GNUNET_EXTRA_LOGGING
#define DEBUG_DV GNUNET_EXTRA_LOGGING
#define DEBUG_DV_PEER_NUMBERS GNUNET_EXTRA_LOGGING
#define DEBUG_MESSAGE_DROP GNUNET_EXTRA_LOGGING

typedef void (*GNUNET_DV_MessageReceivedHandler) (void *cls,
                                                  struct GNUNET_PeerIdentity *
                                                  sender, char *msg,
                                                  size_t msg_len,
                                                  uint32_t distance,
                                                  char *sender_address,
                                                  size_t sender_address_len);

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * DV Message, contains a message that was received
 * via DV for this peer! Internal.
 *
 * Sender address is copied to the end of this struct,
 * followed by the actual message received.
 */
struct GNUNET_DV_MessageReceived
{
  /**
   * Type:  GNUNET_MESSAGE_TYPE_TRANSPORT_DV_MESSAGE
   */
  struct GNUNET_MessageHeader header;

  /**
   * The sender of the message
   */
  struct GNUNET_PeerIdentity sender;

  /**
   * The length of the message that was sent (appended to this end of struct)
   */
  uint32_t msg_len;

  /**
   * The distance to the peer that we received the message from
   */
  uint32_t distance;

};


/**
 * DV Message, indicates that we have learned of a new DV level peer.
 * Internal.
 *
 * Sender address is copied to the end of this struct.
 */
struct GNUNET_DV_ConnectMessage
{
  /**
   * Type:  GNUNET_MESSAGE_TYPE_TRANSPORT_DV_MESSAGE
   */
  struct GNUNET_MessageHeader header;

  /**
   * The sender of the message
   */
  struct GNUNET_PeerIdentity *sender;

  /**
   * The message that was sent
   */
  struct GNUNET_MessageHeader *msg;

  /**
   * The distance to the peer that we received the message from
   */
  uint32_t distance;

  /**
   * Length of the sender address, appended to end of this message
   */
  uint32_t sender_address_len;

};

/**
 * Message to return result from a send attempt.
 * Internal.
 */
struct GNUNET_DV_SendResultMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DV_SEND_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique ID for attempted sent message.
   */
  uint32_t uid;

  /**
   * Result of attempted send, 0 for send okay,
   * 1 for failure of any reason.
   */
  uint32_t result;
};

/**
 * Message to send a message over DV via a specific peer.
 * Internal.
 */
struct GNUNET_DV_SendMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DV_SEND
   */
  struct GNUNET_MessageHeader header;

  /**
   * Intended final recipient of this message
   */
  struct GNUNET_PeerIdentity target;

  /**
   * Message priority
   */
  uint32_t priority;

  /**
   * Unique ID for this message, for confirm callback.
   */
  uint32_t uid;

  /**
   * How long can we delay sending?
   */
  struct GNUNET_TIME_Relative timeout;

  /**
   * Size of the address (appended to end of struct)
   */
  uint32_t addrlen;

  /**
   * The message(s) to be sent.
   */
  char *msgbuf;

  /*
   * Sender, appended to end of struct tells via whom
   * to send this message.
   */

};

/**
 * Message that gets sent between nodes updating dv infos
 */
typedef struct
{
  /* Message Header */
  struct GNUNET_MessageHeader header;

  /**
   * Cost from received from node to neighbor node, takes distance into account
   */
  uint32_t cost GNUNET_PACKED;

  /**
   * Identity of neighbor we learned information about
   */
  struct GNUNET_PeerIdentity neighbor;

  /**
   * PublicKey of neighbor.
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pkey;

  /**
   * Neighbor ID to use when sending to this peer
   */
  uint32_t neighbor_id GNUNET_PACKED;

} p2p_dv_MESSAGE_NeighborInfo;

/**
 * Message that gets sent between nodes carrying information
 */
typedef struct
{
  struct GNUNET_MessageHeader header;

  /**
   * Unique ID for this message.  Will be zero unless
   * message tracking is desired.
   */
  uint32_t uid GNUNET_PACKED;

  /**
   * Identity of peer that ultimately sent the message.
   * Should be looked up in the set of 'neighbor_id's of
   * the referring peer.
   */
  uint32_t sender GNUNET_PACKED;

  /**
   * Identity of neighbor this message is going to.  Should
   * be looked up in the set of our own identifiers for
   * neighbors!
   */
  uint32_t recipient GNUNET_PACKED;

} p2p_dv_MESSAGE_Data;

/**
 * Message that gets sent between nodes indicating a peer
 * was disconnected.
 */
typedef struct
{
  struct GNUNET_MessageHeader header;

  /**
   * Identity of neighbor that was disconnected.
   */
  uint32_t peer_id GNUNET_PACKED;

} p2p_dv_MESSAGE_Disconnect;
GNUNET_NETWORK_STRUCT_END

struct GNUNET_DV_Handle *
GNUNET_DV_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                   GNUNET_DV_MessageReceivedHandler receive_handler,
                   void *receive_handler_cls);

/**
 * Disconnect from the DV service
 *
 * @param handle the current handle to the service to disconnect
 */
void
GNUNET_DV_disconnect (struct GNUNET_DV_Handle *handle);

#endif
