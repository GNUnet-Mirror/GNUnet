/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file transport/transport.h
 * @brief common internal definitions for transport service
 * @author Christian Grothoff
 */
#include "gnunet_crypto_lib.h"
#include "gnunet_time_lib.h"
#include "gnunet_transport_service.h"

#define DEBUG_TRANSPORT GNUNET_YES

/**
 * For how long do we allow unused bandwidth
 * from the past to carry over into the future? (in ms)
 */
#define MAX_BANDWIDTH_CARRY 5000

/**
 * How often do we (at most) do a full quota
 * recalculation? (in ms)
 */
#define MIN_QUOTA_REFRESH_TIME 2000

/**
 * Message from the transport service to the library
 * informing about neighbors.
 */
struct ConnectInfoMessage
{

  /**
   * Type will be GNUNET_MESSAGE_TYPE_TRANSPORT_CONNECT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Current quota for outbound traffic in bytes/ms.
   * (should be equal to system default)
   */
  uint32_t quota_out GNUNET_PACKED;

  /**
   * Latency estimate.
   */
  struct GNUNET_TIME_RelativeNBO latency;

  /**
   * Identity of the new neighbour.
   */
  struct GNUNET_PeerIdentity id;

};


/**
 * Message from the transport service to the library
 * informing about disconnects.
 */
struct DisconnectInfoMessage
{

  /**
   * Type will be GNUNET_MESSAGE_TYPE_TRANSPORT_DISCONNECT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Reserved, always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Who got disconnected?
   */
  struct GNUNET_PeerIdentity peer;

};


/**
 * Message used to set a particular bandwidth quota.  Send
 * TO the service to set an incoming quota, send FROM the
 * service to update an outgoing quota.
 */
struct QuotaSetMessage
{

  /**
   * Type will be GNUNET_MESSAGE_TYPE_TRANSPORT_NEIGHBOUR_INFO
   */
  struct GNUNET_MessageHeader header;

  /**
   * Quota in bytes per ms, 0 to drop everything;
   * in network byte order.
   */
  uint32_t quota_in GNUNET_PACKED;

  /**
   * About which peer are we talking here?
   */
  struct GNUNET_PeerIdentity peer;

};


/**
 * Message used to ask the transport service to connect
 * to a particular peer.
 */
struct TryConnectMessage
{

  /**
   * Type will be GNUNET_MESSAGE_TYPE_TRANSPORT_TRY_CONNECT.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * About which peer are we talking here?
  */
  struct GNUNET_PeerIdentity peer;

};

/**
 * Message used to notify the transport API about a message
 * received from the network.  The actual message follows.
 */
struct InboundMessage
{

  /**
   * Type will be GNUNET_MESSAGE_TYPE_TRANSPORT_RECV
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Latency estimate.
   */
  struct GNUNET_TIME_RelativeNBO latency;

  /**
   * Which peer sent the message?
   */
  struct GNUNET_PeerIdentity peer;

};


/**
 * Message used to notify the transport API that it can
 * send another message to the transport service.
 */
struct SendOkMessage
{

  /**
   * Type will be GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_OK
   */
  struct GNUNET_MessageHeader header;

  /**
   * GNUNET_OK if the transmission succeeded,
   * GNUNET_SYSERR if it failed (i.e. network disconnect);
   * in either case, it is now OK for this client to
   * send us another message for the given peer.
   */
  uint32_t success GNUNET_PACKED;

  /**
   * Which peer can send more now?
   */
  struct GNUNET_PeerIdentity peer;

};


/**
 * Message used to notify the transport service about a message
 * to be transmitted to another peer.  The actual message follows.
 */
struct OutboundMessage
{

  /**
   * Type will be GNUNET_MESSAGE_TYPE_TRANSPORT_SEND
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Which peer should receive the message?
   */
  struct GNUNET_PeerIdentity peer;

};






/* end of transport.h */
