/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file core/core.h
 * @brief common internal definitions for core service
 * @author Christian Grothoff
 */
#ifndef CORE_H
#define CORE_H

#include "gnunet_bandwidth_lib.h"
#include "gnunet_transport_service.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_time_lib.h"

/**
 * General core debugging.
 */
#define DEBUG_CORE GNUNET_EXTRA_LOGGING

/**
 * Definition of bits in the InitMessage's options field that specify
 * which events this client cares about.  Note that inbound messages
 * for handlers that were specifically registered are always
 * transmitted to the client.
 */
#define GNUNET_CORE_OPTION_NOTHING             0
#define GNUNET_CORE_OPTION_SEND_STATUS_CHANGE  4
#define GNUNET_CORE_OPTION_SEND_FULL_INBOUND   8
#define GNUNET_CORE_OPTION_SEND_HDR_INBOUND   16
#define GNUNET_CORE_OPTION_SEND_FULL_OUTBOUND 32
#define GNUNET_CORE_OPTION_SEND_HDR_OUTBOUND  64


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Message transmitted core clients to gnunet-service-core
 * to start the interaction.  This header is followed by
 * uint16_t type values specifying which messages this
 * client is interested in.
 */
struct InitMessage
{

  /**
   * Header with type GNUNET_MESSAGE_TYPE_CORE_INIT.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Options, see GNUNET_CORE_OPTION_ values.
   */
  uint32_t options GNUNET_PACKED;

};


/**
 * Message transmitted by the gnunet-service-core process
 * to its clients in response to an INIT message.
 */
struct InitReplyMessage
{

  /**
   * Header with type GNUNET_MESSAGE_TYPE_CORE_INIT_REPLY
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Public key of the local peer.
   */
  struct GNUNET_PeerIdentity my_identity;

};


/**
 * Message sent by the service to clients to notify them
 * about a peer connecting.
 */
struct ConnectNotifyMessage
{
  /**
   * Header with type GNUNET_MESSAGE_TYPE_CORE_NOTIFY_CONNECT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of ATS key-value pairs that follow this struct
   * (excluding the 0-terminator).
   */
  uint32_t ats_count GNUNET_PACKED;

  /**
   * Identity of the connecting peer.
   */
  struct GNUNET_PeerIdentity peer;

};


/**
 * Message sent by the service to clients to notify them
 * about a peer changing status.
 */
struct PeerStatusNotifyMessage
{
  /**
   * Header with type GNUNET_MESSAGE_TYPE_CORE_NOTIFY_PEER_STATUS
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of ATS key-value pairs that follow this struct
   * (excluding the 0-terminator).
   */
  uint32_t ats_count GNUNET_PACKED;

  /**
   * When the peer would time out (unless we see activity)
   */
  struct GNUNET_TIME_AbsoluteNBO timeout;

  /**
   * Available bandwidth from the peer.
   */
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in;

  /**
   * Available bandwidth to the peer.
   */
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out;

  /**
   * Identity of the peer.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * First of the ATS information blocks (we must have at least
   * one due to the 0-termination requirement).
   */
  struct GNUNET_ATS_Information ats;

};


/**
 * Message sent by the service to clients to notify them
 * about a peer disconnecting.
 */
struct DisconnectNotifyMessage
{
  /**
   * Header with type GNUNET_MESSAGE_TYPE_CORE_NOTIFY_DISCONNECT.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Identity of the connecting peer.
   */
  struct GNUNET_PeerIdentity peer;

};


/**
 * Message sent by the service to clients to notify them about
 * messages being received or transmitted.  This overall message is
 * followed by the real message, or just the header of the real
 * message (depending on the client's preferences).  The receiver can
 * tell if he got the full message or only a partial message by
 * looking at the size field in the header of NotifyTrafficMessage and
 * checking it with the size field in the message that follows.
 */
struct NotifyTrafficMessage
{
  /**
   * Header with type GNUNET_MESSAGE_TYPE_CORE_NOTIFY_INBOUND
   * or GNUNET_MESSAGE_TYPE_CORE_NOTIFY_OUTBOUND.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of ATS key-value pairs that follow this struct
   * (excluding the 0-terminator).
   */
  uint32_t ats_count GNUNET_PACKED;

  /**
   * Identity of the receiver or sender.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * First of the ATS information blocks (we must have at least
   * one due to the 0-termination requirement).
   */
  struct GNUNET_ATS_Information ats;

};


/**
 * Client notifying core about the maximum-priority
 * message it has in the queue for a particular target.
 */
struct SendMessageRequest
{
  /**
   * Header with type GNUNET_MESSAGE_TYPE_CORE_SEND_REQUEST
   */
  struct GNUNET_MessageHeader header;

  /**
   * How important is this message?
   */
  uint32_t priority GNUNET_PACKED;

  /**
   * By what time would the sender really like to see this
   * message transmitted?
   */
  struct GNUNET_TIME_AbsoluteNBO deadline;

  /**
   * Identity of the intended target.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * How large is the client's message queue for this peer?
   */
  uint32_t queue_size GNUNET_PACKED;

  /**
   * How large is the message?
   */
  uint16_t size GNUNET_PACKED;

  /**
   * Counter for this peer to match SMRs to replies.
   */
  uint16_t smr_id GNUNET_PACKED;

};


/**
 * Core notifying client that it is allowed to now
 * transmit a message to the given target
 * (response to GNUNET_MESSAGE_TYPE_CORE_SEND_REQUEST).
 */
struct SendMessageReady
{
  /**
   * Header with type GNUNET_MESSAGE_TYPE_CORE_SEND_READY
   */
  struct GNUNET_MessageHeader header;

  /**
   * How many bytes are allowed for transmission?
   * Guaranteed to be at least as big as the requested size,
   * or ZERO if the request is rejected (will timeout,
   * peer disconnected, queue full, etc.).
   */
  uint16_t size GNUNET_PACKED;

  /**
   * smr_id from the request.
   */
  uint16_t smr_id GNUNET_PACKED;

  /**
   * Identity of the intended target.
   */
  struct GNUNET_PeerIdentity peer;

};


/**
 * Client asking core to transmit a particular message to a particular
 * target (response to GNUNET_MESSAGE_TYPE_CORE_SEND_READY).
 */
struct SendMessage
{
  /**
   * Header with type GNUNET_MESSAGE_TYPE_CORE_SEND
   */
  struct GNUNET_MessageHeader header;

  /**
   * How important is this message?
   */
  uint32_t priority GNUNET_PACKED;

  /**
   * By what time would the sender really like to see this
   * message transmitted?
   */
  struct GNUNET_TIME_AbsoluteNBO deadline;

  /**
   * Identity of the receiver or sender.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * GNUNET_YES if corking is allowed, GNUNET_NO if not.
   */
  uint32_t cork GNUNET_PACKED;

  /**
   * Always 0.
   */
  uint64_t reserved GNUNET_PACKED;

};


/**
 * Client asking core to connect to a particular target.  There is no
 * response from the core to this type of request (however, if an
 * actual connection is created or destroyed, be it because of this
 * type request or not, the core generally needs to notify the
 * clients).
 */
struct ConnectMessage
{
  /**
   * Header with type GNUNET_MESSAGE_TYPE_REQUEST_CONNECT or
   * GNUNET_MESSAGE_TYPE_REQUEST_DISCONNECT.
   */
  struct GNUNET_MessageHeader header;

  /**
   * For alignment.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Identity of the other peer.
   */
  struct GNUNET_PeerIdentity peer;

};
GNUNET_NETWORK_STRUCT_END
#endif
/* end of core.h */
