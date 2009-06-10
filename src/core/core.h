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
 * @file core/core.h
 * @brief common internal definitions for core service
 * @author Christian Grothoff
 */
#include "gnunet_crypto_lib.h"
#include "gnunet_time_lib.h"

/**
 * General core debugging.
 */
#define DEBUG_CORE GNUNET_NO

/**
 * Debugging interaction core-clients.
 */
#define DEBUG_CORE_CLIENT GNUNET_NO

/**
 * Definition of bits in the InitMessage's options field that specify
 * which events this client cares about.  Note that inbound messages
 * for handlers that were specifically registered are always
 * transmitted to the client.
 */
#define GNUNET_CORE_OPTION_NOTHING             0
#define GNUNET_CORE_OPTION_SEND_CONNECT        1
#define GNUNET_CORE_OPTION_SEND_DISCONNECT     2
#define GNUNET_CORE_OPTION_SEND_BFC            4
#define GNUNET_CORE_OPTION_SEND_FULL_INBOUND   8
#define GNUNET_CORE_OPTION_SEND_HDR_INBOUND   16
#define GNUNET_CORE_OPTION_SEND_FULL_OUTBOUND 32
#define GNUNET_CORE_OPTION_SEND_HDR_OUTBOUND  64


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
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded publicKey;

};


/**
 * Message sent by the service to clients to notify them
 * about a peer connecting or disconnecting.
 */
struct ConnectNotifyMessage
{
  /**
   * Header with type GNUNET_MESSAGE_TYPE_CORE_NOTIFY_CONNECT
   * or GNUNET_MESSAGE_TYPE_CORE_NOTIFY_DISCONNECT.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Available bandwidth to this peer; zero for disconnect.
   * [TODO: currently set to hard-coded constant and hence
   * not really useful, right?]
   */
  uint32_t bpm_available GNUNET_PACKED;

  /**
   * Identity of the connecting peer.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Time of our last interaction with the peer; close
   * to "now" for connect messages.
   * [TODO: is this useful?]
   */
  struct GNUNET_TIME_AbsoluteNBO last_activity;

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
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Identity of the receiver or sender.
   */
  struct GNUNET_PeerIdentity peer;

};


/**
 * Message sent to the core asking for configuration
 * information and possibly preference changes.
 */
struct RequestConfigureMessage
{
  /**
   * Header with type GNUNET_MESSAGE_TYPE_CORE_REQUEST_CONFIGURE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Limit the number of bytes of outbound traffic to this
   * peer to at most the specified amount (naturally, the
   * amount is also limited by the receiving peer).
   */
  uint32_t limit_outbound_bpm GNUNET_PACKED;

  /**
   * Number of bytes of inbound traffic to reserve, can
   * be negative (to unreserve).  NBO.
   */
  int32_t reserve_inbound GNUNET_PACKED;

  /**
   * Increment the current traffic preference for the given peer by
   * the specified amont.  The traffic preference is used to determine
   * the share of bandwidth this peer will typcially be assigned.
   */
  uint64_t preference_change GNUNET_PACKED;

  /**
   * Identity of the peer being configured.
   */
  struct GNUNET_PeerIdentity peer;

};


/**
 * Response from the core to a "RequestConfigureMessage"
 * providing traffic status information for a peer.
 */
struct ConfigurationInfoMessage
{
  /**
   * Header with type GNUNET_MESSAGE_TYPE_CORE_CONFIGURATION_INFO
   */
  struct GNUNET_MessageHeader header;

  /**
   * Amount of traffic (inbound number of bytes) that was reserved in
   * response to the configuration change request.  Negative for
   * "unreserved" bytes.
   */
  int32_t reserved_amount GNUNET_PACKED;

  /**
   * Available bandwidth in (in bytes per minute) for this peer.
   * 0 if we have been disconnected.
   */
  uint32_t bpm_in GNUNET_PACKED;

  /**
   * Available bandwidth out (in bytes per minute) for this peer,
   * 0 if we have been disconnected.
   */
  uint32_t bpm_out GNUNET_PACKED;

  /**
   * Latest transport latency estimate for the peer.
   * FOREVER if we have been disconnected.
   */
  struct GNUNET_TIME_RelativeNBO latency;

  /**
   * Current traffic preference for the peer.
   * 0 if we have been disconnected.
   */
  double preference;

  /**
   * Identity of the receiver or sender.
   */
  struct GNUNET_PeerIdentity peer;

};


/**
 * Core asking a client to generate traffic for a particular
 * target.
 */
struct SolicitTrafficMessage
{
  /**
   * Header with type GNUNET_MESSAGE_TYPE_CORE_SOLICIT_TRAFFIC
   * or GNUNET_MESSAGE_TYPE_CORE_RECV_OK
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of bytes of traffic being solicited.
   */
  uint32_t solicit_size GNUNET_PACKED;

  /**
   * Identity of the receiver or sender.
   */
  struct GNUNET_PeerIdentity peer;

};


/**
 * Client asking core to transmit a particular message to
 * a particular target.  Does NOT have to be solicited.
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

};


/* end of core.h */
