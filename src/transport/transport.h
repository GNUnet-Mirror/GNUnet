/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file transport/transport.h
 * @brief common internal definitions for transport service
 * @author Christian Grothoff
 */
#ifndef TRANSPORT_H
#define TRANSPORT_H

#include "gnunet_crypto_lib.h"
#include "gnunet_time_lib.h"
#include "gnunet_transport_service.h"
#include "gnunet_constants.h"

#define DEBUG_TRANSPORT GNUNET_EXTRA_LOGGING

#define DEBUG_TRANSPORT_TIMEOUT GNUNET_EXTRA_LOGGING

#define DEBUG_TRANSPORT_DISCONNECT GNUNET_EXTRA_LOGGING

#define DEBUG_TRANSPORT_API GNUNET_EXTRA_LOGGING

/**
 * For how long do we allow unused bandwidth
 * from the past to carry over into the future? (in seconds)
 */
#define MAX_BANDWIDTH_CARRY_S GNUNET_CONSTANTS_MAX_BANDWIDTH_CARRY_S

/**
 * How often do we (at most) do a full quota
 * recalculation? (in ms)
 */
#define MIN_QUOTA_REFRESH_TIME 2000

/**
 * Maximum frequency for re-evaluating latencies for all transport addresses.
 */
#define LATENCY_EVALUATION_MAX_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 1)

/**
 * Maximum frequency for re-evaluating latencies for connected addresses.
 */
#define CONNECTED_LATENCY_EVALUATION_MAX_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 1)

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Message from the transport service to the library
 * asking to check if both processes agree about this
 * peers identity.
 */
struct StartMessage
{

  /**
   * Type will be GNUNET_MESSAGE_TYPE_TRANSPORT_START
   */
  struct GNUNET_MessageHeader header;

  /**
   * 0: no options
   * 1: The 'self' field should be checked
   * 2: this client is interested in payload traffic
   */
  uint32_t options;

  /**
   * Identity we think we have.  If it does not match, the
   * receiver should print out an error message and disconnect.
   */
  struct GNUNET_PeerIdentity self;

};


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
   * Number of ATS key-value pairs that follow this struct
   * (excluding the 0-terminator).
   */
  uint32_t ats_count GNUNET_PACKED;

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
 * Message type for sending a request connect message
 * to the transport service.  Must be done before transport
 * api will allow messages to be queued/sent to transport
 * service for transmission to a peer.
 */
struct TransportRequestConnectMessage
{
  /**
   *  Message header
   */
  struct GNUNET_MessageHeader header;

  /**
   * For alignment.
   */
  uint32_t reserved;

  /**
   * Identity of the peer we would like to connect to.
   */
  struct GNUNET_PeerIdentity peer;
};

/**
 * Message used to set a particular bandwidth quota.  Sent TO the
 * service to set an incoming quota, sent FROM the service to update
 * an outgoing quota.
 */
struct QuotaSetMessage
{

  /**
   * Type will be GNUNET_MESSAGE_TYPE_TRANSPORT_SET_QUOTA
   */
  struct GNUNET_MessageHeader header;

  /**
   * Quota.
   */
  struct GNUNET_BANDWIDTH_Value32NBO quota;

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
   * Number of ATS key-value pairs that follow this struct
   * (excluding the 0-terminator).
   */
  uint32_t ats_count GNUNET_PACKED;

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
   * Latency estimate.
   */
  struct GNUNET_TIME_RelativeNBO latency;

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
   * Message priority.
   */
  uint32_t priority GNUNET_PACKED;

  /**
   * Allowed delay.
   */
  struct GNUNET_TIME_RelativeNBO timeout;

  /**
   * Which peer should receive the message?
   */
  struct GNUNET_PeerIdentity peer;

};


/**
 * Message from the library to the transport service
 * asking for converting a transport address to a
 * human-readable UTF-8 string.
 */
struct AddressLookupMessage
{

  /**
   * Type will be GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_LOOKUP
   */
  struct GNUNET_MessageHeader header;

  /**
   * Should the conversion use numeric IP addresses (otherwise
   * a reverse DNS lookup is OK -- if applicable).
   */
  int16_t numeric_only GNUNET_PACKED;

  /**
   * Length of the (binary) address in bytes, in big-endian.
   */
  uint16_t addrlen GNUNET_PACKED;

  /**
   * timeout to give up.
   */
  struct GNUNET_TIME_RelativeNBO timeout;

  /* followed by 'addrlen' bytes of the actual address, then
   * followed by the 0-terminated name of the transport */
};


/**
 * Message from the library to the transport service
 * asking for human readable addresses known for a peer.
 */
struct PeerAddressLookupMessage
{
  /**
   * Type will be GNUNET_MESSAGE_TYPE_TRANSPORT_PEER_ADDRESS_LOOKUP
   */
  struct GNUNET_MessageHeader header;

  /**
   * For alignment.
   */
  uint32_t reserved;

  /**
   * timeout to give up.  FIXME: remove in the future.
   */
  struct GNUNET_TIME_RelativeNBO timeout;

  /**
   * The identity of the peer to look up.
   */
  struct GNUNET_PeerIdentity peer;
};


/**
 * Message from the library to the transport service
 * asking for binary addresses known for a peer.
 */
struct AddressIterateMessage
{
  /**
   * Type will be GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_ITERATE
   */
  struct GNUNET_MessageHeader header;

  /**
   * One shot call or continous replies?
   */
  uint32_t one_shot;

  /**
   * timeout to give up.  FIXME: remove in the future
   */
  struct GNUNET_TIME_AbsoluteNBO timeout;

  /**
   * The identity of the peer to look up.
   */
  struct GNUNET_PeerIdentity peer;

};


/**
 * Message from the transport service to the library
 * containing binary addresses known for a peer.
 * Memory layout:
 * [AddressIterateResponseMessage][address[addrlen]][transportname[pluginlen]]
 */
struct AddressIterateResponseMessage
{
  /**
   * Type will be GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_ITERATE_RESPONSE
   */
  struct GNUNET_MessageHeader header;

  /**
   * For alignment.
   */
  uint32_t reserved;

    /**
   * Peer identity
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * address length
   */
  uint32_t addrlen GNUNET_PACKED;

  /**
   * length of the plugin name
   */
  uint32_t pluginlen GNUNET_PACKED;

};


/**
 * Change in blacklisting (either request or notification,
 * depending on which direction it is going).
 */
struct BlacklistMessage
{

  /**
   * Type will be GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST_QUERY or
   * GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST_REPLY.
   */
  struct GNUNET_MessageHeader header;

  /**
   * 0 for the query, GNUNET_OK (allowed) or GNUNET_SYSERR (disallowed)
   * for the response.
   */
  uint32_t is_allowed GNUNET_PACKED;

  /**
   * Which peer is being blacklisted or queried?
   */
  struct GNUNET_PeerIdentity peer;

};
GNUNET_NETWORK_STRUCT_END

/* end of transport.h */
#endif
