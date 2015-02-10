/*
     This file is part of GNUnet.
     Copyright (C) 2009-2014 Christian Grothoff (and other contributing authors)

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
 * What's the maximum number of sockets transport uses for validation and
 * neighbors
 */
#define DEFAULT_MAX_FDS 256

/**
 * Maximum frequency for re-evaluating latencies for all transport addresses.
 */
#define LATENCY_EVALUATION_MAX_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 1)

/**
 * Maximum frequency for re-evaluating latencies for connected addresses.
 */
#define CONNECTED_LATENCY_EVALUATION_MAX_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 1)

/**
 * Similiar to GNUNET_TRANSPORT_NotifyDisconnect but in and out quotas are
 * included here. These values are not required outside transport_api
 *
 * @param cls closure
 * @param peer the peer that connected
 * @param bandwidth_in inbound bandwidth in NBO
 * @param bandwidth_out outbound bandwidth in NBO
 *
 */
typedef void
(*NotifyConnect) (void *cls,
                  const struct GNUNET_PeerIdentity *peer,
                  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
                  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out);


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Message from the transport service to the library
 * asking to check if both processes agree about this
 * peers identity.
 */
struct StartMessage
{

  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_START
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
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_CONNECT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Identity of the new neighbour.
   */
  struct GNUNET_PeerIdentity id;

  /**
   * Current inbound quota for this peer
   */
  struct GNUNET_BANDWIDTH_Value32NBO quota_in;

  /**
   * Current outbound quota for this peer
   */
  struct GNUNET_BANDWIDTH_Value32NBO quota_out;
};


/**
 * Message from the transport service to the library
 * informing about disconnects.
 */
struct DisconnectInfoMessage
{

  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_DISCONNECT
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
   *  Message header with type #GNUNET_MESSAGE_TYPE_TRANSPORT_REQUEST_CONNECT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Reserved (0).
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Identity of the peer we would like to connect to.
   */
  struct GNUNET_PeerIdentity peer;
};


/**
 * Message type for sending a request connection to
 * a peer to be torn down.
 */
struct TransportRequestDisconnectMessage
{
  /**
   *  Message header with type #GNUNET_MESSAGE_TYPE_TRANSPORT_REQUEST_DISCONNECT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Reserved (0).
   */
  uint32_t reserved GNUNET_PACKED;

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
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_SET_QUOTA
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
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_RECV
   */
  struct GNUNET_MessageHeader header;

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
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_OK
   */
  struct GNUNET_MessageHeader header;

  /**
   * #GNUNET_OK if the transmission succeeded,
   * #GNUNET_SYSERR if it failed (i.e. network disconnect);
   * in either case, it is now OK for this client to
   * send us another message for the given peer.
   */
  uint32_t success GNUNET_PACKED;

  /**
   * Size of message sent
   */
  uint32_t bytes_msg GNUNET_PACKED;

  /**
   * Size of message sent over wire
   * Includes plugin and protocol specific overhead
   */
  uint32_t bytes_physical GNUNET_PACKED;

  /**
   * Which peer can send more now?
   */
  struct GNUNET_PeerIdentity peer;

};

/**
 * Message used to notify the transport API about an address to string
 * conversion. Message is followed by the string with the humand-readable
 * address.  For each lookup, multiple results may be returned.  The
 * last message must have a @e res of #GNUNET_OK and an @e addr_len
 * of zero.
 */
struct AddressToStringResultMessage
{

  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_TO_STRING_REPLY
   */
  struct GNUNET_MessageHeader header;

  /**
   * #GNUNET_OK if the conversion succeeded,
   * #GNUNET_SYSERR if it failed
   */
  uint32_t res GNUNET_PACKED;

  /**
   * Length of the following string, zero if @e is #GNUNET_SYSERR
   */
  uint32_t addr_len GNUNET_PACKED;
};


/**
 * Message used to notify the transport service about a message
 * to be transmitted to another peer.  The actual message follows.
 */
struct OutboundMessage
{

  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_SEND
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;

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
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_TO_STRING
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
   * timeout to give up (for DNS resolution timeout mostly)
   */
  struct GNUNET_TIME_RelativeNBO timeout;

  /* followed by @e addrlen bytes of the actual address, then
   * followed by the 0-terminated name of the transport */
};


/**
 * Message from the transport service to the library containing information
 * about a peer. Information contained are:
 * - current address used to communicate with this peer
 * - state
 * - state timeout
 *
 * Memory layout:
 * [AddressIterateResponseMessage][address[addrlen]][transportname[pluginlen]]
 */
struct ValidationIterateResponseMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_VALIDATION_RESPONSE
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
   * Local info about the address
   */
  uint32_t local_address_info GNUNET_PACKED;

  /**
   * Address length
   */
  uint32_t addrlen GNUNET_PACKED;

  /**
   * Length of the plugin name
   */
  uint32_t pluginlen GNUNET_PACKED;

  /**
   * State
   */
  uint32_t state GNUNET_PACKED;

  /**
   * At what time did we successfully validate the address last.
   * Will be NEVER if the address failed validation.
   */
  struct GNUNET_TIME_AbsoluteNBO last_validation;

  /**
   * Until when is the address believed to be valid.
   * Will be ZERO if the address is not belived to be valid.
   */
  struct GNUNET_TIME_AbsoluteNBO valid_until;

  /**
   * When will we next try to validate the address (typically
   * done before @e valid_until happens).
   */
  struct GNUNET_TIME_AbsoluteNBO next_validation;
};

/**
 * Message from the library to the transport service
 * asking for binary addresses known for a peer.
 */
struct ValidationMonitorMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_VALIDATION_REQUEST
   */
  struct GNUNET_MessageHeader header;

  /**
   * One shot call or continous replies?
   */
  uint32_t one_shot GNUNET_PACKED;

  /**
   * The identity of the peer to look up.
   */
  struct GNUNET_PeerIdentity peer;

};


/**
 * Message from the library to the transport service
 * asking for binary addresses known for a peer.
 */
struct PeerMonitorMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PEER_REQUEST
   */
  struct GNUNET_MessageHeader header;

  /**
   * One shot call or continous replies?
   */
  uint32_t one_shot GNUNET_PACKED;

  /**
   * The identity of the peer to look up.
   */
  struct GNUNET_PeerIdentity peer;

};


/**
 * Message from the library to the transport service
 * asking for binary addresses known for a peer.
 */
struct TrafficMetricMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_TRAFFIC_METRIC
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * The identity of the peer to look up.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Fake properties to generate.
   */
  struct GNUNET_ATS_PropertiesNBO properties;

  /**
   * Fake delay to add on inbound traffic.
   */
  struct GNUNET_TIME_RelativeNBO delay_in;

  /**
   * Fake delay to add on outbound traffic.
   */
  struct GNUNET_TIME_RelativeNBO delay_out;
};


/**
 * Message from the transport service to the library containing information
 * about a peer. Information contained are:
 * - current address used to communicate with this peer
 * - state
 * - state timeout
 *
 * Memory layout:
 * [AddressIterateResponseMessage][address[addrlen]][transportname[pluginlen]]
 */
struct PeerIterateResponseMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PEER_RESPONSE
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
   * Timeout for the state this peer is in
   */
  struct GNUNET_TIME_AbsoluteNBO state_timeout;

  /**
   * Local info about the address
   */
  uint32_t local_address_info GNUNET_PACKED;

  /**
   * State this peer is in as an `enum GNUNET_TRANSPORT_PeerState`
   */
  uint32_t state GNUNET_PACKED;

  /**
   * Address length
   */
  uint32_t addrlen GNUNET_PACKED;

  /**
   * Length of the plugin name
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
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST_QUERY or
   * #GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST_REPLY.
   */
  struct GNUNET_MessageHeader header;

  /**
   * 0 for the query, #GNUNET_OK (allowed) or #GNUNET_SYSERR (disallowed)
   * for the response.
   */
  uint32_t is_allowed GNUNET_PACKED;

  /**
   * Which peer is being blacklisted or queried?
   */
  struct GNUNET_PeerIdentity peer;

};


/**
 * Transport-level connection status update.
 */
struct TransportPluginMonitorMessage
{

  /**
   * Type will be #GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PLUGIN_EVENT.
   */
  struct GNUNET_MessageHeader header;

  /**
   * An `enum GNUNET_TRANSPORT_SessionState` in NBO.
   */
  uint16_t session_state GNUNET_PACKED;

  /**
   * #GNUNET_YES if this is an inbound connection,
   * #GNUNET_NO if this is an outbound connection,
   * #GNUNET_SYSERR if connections of this plugin
   *             are so fundamentally bidirectional
   *             that they have no 'initiator'
   * Value given in NBO.
   */
  int16_t is_inbound GNUNET_PACKED;

  /**
   * Number of messages waiting transmission.
   */
  uint32_t msgs_pending GNUNET_PACKED;

  /**
   * Number of bytes waiting for transmission.
   */
  uint32_t bytes_pending GNUNET_PACKED;

  /**
   * When will this transport plugin session time out?
   */
  struct GNUNET_TIME_AbsoluteNBO timeout;

  /**
   * Until how long is this plugin currently blocked from reading?
   */
  struct GNUNET_TIME_AbsoluteNBO delay;

  /**
   * Which peer is this connection for?
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Unique identifier for the session.
   */
  uint64_t session_id;

  /**
   * Length of the plugin name in bytes, including 0-termination.
   */
  uint16_t plugin_name_len GNUNET_PACKED;

  /**
   * Length of the plugin address in bytes.
   */
  uint16_t plugin_address_len GNUNET_PACKED;

  /* followed by 0-terminated plugin name and
     @e plugin_address_len bytes of plugin address */

};


GNUNET_NETWORK_STRUCT_END

/* end of transport.h */
#endif
