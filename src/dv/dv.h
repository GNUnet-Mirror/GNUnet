/*
     This file is part of GNUnet.
     Copyright (C) 2013 GNUnet e.V.

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
 * @author Christian Grothoff
 * @file dv/dv.h
 * @brief IPC messages between DV service and DV plugin
 */
#ifndef DV_H
#define DV_H

#include "gnunet_common.h"

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * DV service tells plugin about a DV-connection being
 * now available.
 */
struct GNUNET_DV_ConnectMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DV_CONNECT
   */
  struct GNUNET_MessageHeader header;

  /**
   * The distance to the peer that we are now connected to
   */
  uint32_t distance GNUNET_PACKED;

  /**
   * The other peer (at the given distance).
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * The network the peer is in
   */
  uint32_t network GNUNET_PACKED;

};


/**
 * DV service tells plugin about a DV-connection being
 * no longer available.
 *
 * Sender address is copied to the end of this struct,
 * followed by the actual message received.
 */
struct GNUNET_DV_DisconnectMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DV_DISCONNECT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * The peer that is no longer available.
   */
  struct GNUNET_PeerIdentity peer;

};


/**
 * DV Message, contains a message that was received via DV for this
 * peer.  Send from the DV service to the DV plugin.
 *
 * Sender address is copied to the end of this struct,
 * followed by the actual message received.
 */
struct GNUNET_DV_ReceivedMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DV_RECV
   */
  struct GNUNET_MessageHeader header;

  /**
   * The distance to the peer that we received the message from
   */
  uint32_t distance GNUNET_PACKED;

  /**
   * The (actual) sender of the message
   */
  struct GNUNET_PeerIdentity sender;

  /* payload follows */
};


/**
 * Message from plugin to DV service, requesting a
 * message to be routed.
 */
struct GNUNET_DV_SendMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DV_SEND
   */
  struct GNUNET_MessageHeader header;

  /**
   * Reserved for alignment. 0.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * The (actual) target of the message
   */
  struct GNUNET_PeerIdentity target;

};


/**
 * Message from service to DV plugin, saying that our
 * distance to another peer changed.
 */
struct GNUNET_DV_DistanceUpdateMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DV_DISTANCE_CHANGED.
   */
  struct GNUNET_MessageHeader header;

  /**
   * What is the new distance?
   */
  uint32_t distance GNUNET_PACKED;

  /**
   * The peer for which the distance changed.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * The network the peer is in
   */
  uint32_t network GNUNET_PACKED;

};


GNUNET_NETWORK_STRUCT_END

#endif
