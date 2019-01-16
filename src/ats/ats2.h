/*
     This file is part of GNUnet.
     Copyright (C) 2010-2015 GNUnet e.V.

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
 * @file ats/ats2.h
 * @brief automatic transport selection messages
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#ifndef ATS2_H
#define ATS2_H

#include "gnunet_util_lib.h"
#include "gnunet_ats_transport_service.h"


GNUNET_NETWORK_STRUCT_BEGIN


/**
 * ATS performance characteristics for an address.
 */
struct PropertiesNBO
{

  /**
   * Delay.  Time between when the time packet is sent and the packet
   * arrives.  FOREVER if we did not (successfully) measure yet.
   */
  struct GNUNET_TIME_RelativeNBO delay;

  /**
   * Confirmed successful payload on this connection from this peer to
   * the other peer. In NBO.
   *
   * Unit: [bytes/second]
   */
  uint32_t goodput_out;

  /**
   * Confirmed useful payload on this connection to this peer from
   * the other peer. In NBO.
   *
   * Unit: [bytes/second]
   */
  uint32_t goodput_in;

  /**
   * Actual traffic on this connection from this peer to the other peer.
   * Includes transport overhead. In NBO.
   *
   * Unit: [bytes/second]
   */
  uint32_t utilization_out;

  /**
   * Actual traffic on this connection from the other peer to this peer.
   * Includes transport overhead. In NBO.
   *
   * Unit: [bytes/second]
   */
  uint32_t utilization_in;

  /**
   * Distance on network layer (required for distance-vector routing)
   * in hops.  Zero for direct connections (i.e. plain TCP/UDP). In NBO.
   */
  uint32_t distance;

  /**
   * MTU of the network layer, UINT32_MAX for no MTU (stream).
   *
   * Unit: [bytes]. In NBO.
   */
  uint32_t mtu;

  /**
   * Which network scope does the respective address belong to?
   * A `enum GNUNET_NetworkType nt` in NBO.
   */
  uint32_t nt;

  /**
   * What characteristics does this communicator have?
   * A `enum GNUNET_TRANSPORT_CommunicatorCharacteristics` in NBO.
   */
  uint32_t cc;

};


/**
 * Application client to ATS service: we would like to have
 * address suggestions for this peer.
 */
struct ExpressPreferenceMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_ATS_SUGGEST or
   * #GNUNET_MESSAGE_TYPE_ATS_SUGGEST_CANCEL to stop
   * suggestions.
   */
  struct GNUNET_MessageHeader header;

  /**
   * What type of performance preference does the client have?
   * A `enum GNUNET_MQ_PreferenceKind` in NBO.
   */
  uint32_t pk GNUNET_PACKED;

  /**
   * Peer to get address suggestions for.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * How much bandwidth in bytes/second does the application expect?
   */
  struct GNUNET_BANDWIDTH_Value32NBO bw;

};


/**
 * Transport client to ATS service: here is another session you can use.
 */
struct SessionAddMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_ATS_SESSION_ADD or
   * #GNUNET_MESSAGE_TYPE_ATS_SESSION_ADD_INBOUND_ONLY
   */
  struct GNUNET_MessageHeader header;

  /**
   * Internal number this client will henceforth use to
   * refer to this session.
   */
  uint32_t session_id GNUNET_PACKED;

  /**
   * Identity of the peer that this session is for.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Performance properties of the session.
   */
  struct PropertiesNBO properties;

  /* followed by:
   * - char * address (including '\0'-termination).
   */

};


/**
 * Message used to notify ATS that the performance
 * characteristics for an session have changed.
 */
struct SessionUpdateMessage
{
  /**
   * Message of type #GNUNET_MESSAGE_TYPE_ATS_SESSION_UPDATE.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Internal number this client uses to refer to this session.
   */
  uint32_t session_id GNUNET_PACKED;

  /**
   * Which peer is this about? (Technically redundant, as the
   * @e session_id should be sufficient, but enables ATS service
   * to find the session faster).
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Performance properties of the session.
   */
  struct PropertiesNBO properties;

};


/**
 * Message sent by ATS client to ATS service when an session
 * was destroyed and must thus henceforth no longer be considered
 * for scheduling.
 */
struct SessionDelMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_ATS_SESSION_DEL.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Internal number this client uses to refer to this session.
   */
  uint32_t session_id GNUNET_PACKED;

  /**
   * Which peer is this about? (Technically redundant, as the
   * @e session_id should be sufficient, but enables ATS service
   * to find the session faster).
   */
  struct GNUNET_PeerIdentity peer;

};


/**
 * ATS Service allocates resources to an session
 * identified by the given @e session_id for the given @e peer with
 * the given @e bandwidth_in and @e bandwidth_out limits from now on.
 */
struct SessionAllocationMessage
{
  /**
   * A message of type #GNUNET_MESSAGE_TYPE_ATS_SESSION_ALLOCATION.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Internal number this client uses to refer to the session this
   * suggestion is about.
   */
  uint32_t session_id GNUNET_PACKED;

  /**
   * Which peer is this about? (Technically redundant, as the
   * @e session_id should be sufficient, but may enable client
   * to find the session faster and/or check consistency).
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * How much bandwidth we are allowed for sending.
   */
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out;

  /**
   * How much bandwidth we are allowed for receiving.
   */
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in;

};


/**
 * ATS Service suggests to the transport service to try the address
 * for the given @e peer.
 */
struct AddressSuggestionMessage
{
  /**
   * A message of type #GNUNET_MESSAGE_TYPE_ATS_ADDRESS_SUGGESTION.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Which peer is this about? (Technically redundant, as the
   * @e session_id should be sufficient, but may enable client
   * to find the session faster and/or check consistency).
   */
  struct GNUNET_PeerIdentity peer;

  /* Followed by 0-terminated address */
};


GNUNET_NETWORK_STRUCT_END



#endif
