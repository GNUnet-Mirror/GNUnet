/*
     This file is part of GNUnet.
     (C) 2010-2015 Christian Grothoff (and other contributing authors)

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
 * @file ats/ats.h
 * @brief automatic transport selection messages
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#ifndef ATS_H
#define ATS_H

#include "gnunet_util_lib.h"

/**
 * Flag used to indicate which type of client is connecting
 * to the ATS service.
 */
enum StartFlag
{

  /**
   * This is a scheduling client (aka transport service)
   */
  START_FLAG_SCHEDULING = 0,

  /**
   * Performance monitoring client that wants to learn about
   * changes in performance characteristics.
   */
  START_FLAG_PERFORMANCE_WITH_PIC = 1,

  /**
   * Performance monitoring client that does NOT want to learn
   * about changes in performance characteristics.
   */
  START_FLAG_PERFORMANCE_NO_PIC = 2,

  /**
   * Connection suggestion handle.
   */
  START_FLAG_CONNECTION_SUGGESTION = 3
};


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * First message any client sends to ATS, used to self-identify
 * (what type of client this is).
 */
struct ClientStartMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_ATS_START.
   */
  struct GNUNET_MessageHeader header;

  /**
   * NBO value of an `enum StartFlag`.
   */
  uint32_t start_flag GNUNET_PACKED;
};


/**
 * Scheduling client to ATS service: we would like to have
 * address suggestions for this peer.
 */
struct RequestAddressMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_ATS_REQUEST_ADDRESS or
   * #GNUNET_MESSAGE_TYPE_ATS_REQUEST_ADDRESS_CANCEL to stop
   * suggestions.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Peer to get address suggestions for.
   */
  struct GNUNET_PeerIdentity peer;
};


/**
 * Scheduling client to ATS service: reset backoff for
 * address suggestions to this peer.
 */
struct ResetBackoffMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_ATS_RESET_BACKOFF.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Peer to reset backoff for.
   */
  struct GNUNET_PeerIdentity peer;
};


/**
 * ATS client to ATS service: here is another address you can use.
 */
struct AddressAddMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_ATS_ADDRESS_ADD.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Length of the `struct GNUNET_ATS_Information` array that follows this struct.
   */
  uint32_t ats_count GNUNET_PACKED;

  /**
   * Identity of the peer that this address is for.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Number of bytes in the address that follows this struct.
   */
  uint16_t address_length GNUNET_PACKED;

  /**
   * Number of bytes in the plugin name that follows this struct.
   */
  uint16_t plugin_name_length GNUNET_PACKED;

  /**
   * Internal number this client will henceforth use to
   * refer to this address.
   */
  uint32_t session_id GNUNET_PACKED;

  /**
   * Local-only information of the address, see
   * `enum GNUNET_HELLO_AddressInfo`.
   */
  uint32_t address_local_info GNUNET_PACKED;

  /* followed by:
   * - struct GNUNET_ATS_Information [ats_count];
   * - char address[address_length]
   * - char plugin_name[plugin_name_length] (including '\0'-termination).
   */

};


/**
 * Message used to notify ATS that the performance
 * characteristics for an address have changed.
 */
struct AddressUpdateMessage
{
  /**
   * Message of type #GNUNET_MESSAGE_TYPE_ATS_ADDRESS_UPDATE.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Length of the `struct GNUNET_ATS_Information` array that follows.
   */
  uint32_t ats_count GNUNET_PACKED;

  /**
   * Which peer is this about? (Technically redundant, as the
   * @e session_id should be sufficient, but enables ATS service
   * to find the session faster).
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Internal number this client uses to refer to this address.
   */
  uint32_t session_id GNUNET_PACKED;

  /* followed by:
   * - struct GNUNET_ATS_Information [ats_count];
   */

};


/**
 * Message sent from ATS client to ATS service to notify
 * it if we started (or stopped) using an address.
 */
struct AddressUseMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_ATS_ADDRESS_IN_USE.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Internal number this client uses to refer to this address.
   */
  uint32_t session_id GNUNET_PACKED;

  /**
   * Which peer is this about? (Technically redundant, as the
   * @e session_id should be sufficient, but enables ATS service
   * to find the session faster).
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * #GNUNET_YES or #GNUNET_NO.
   */
  uint32_t in_use GNUNET_PACKED;

};


/**
 * Message sent by ATS client to ATS service when an address
 * was destroyed and must thus henceforth no longer be considered
 * for scheduling.
 */
struct AddressDestroyedMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_ATS_ADDRESS_DESTROYED.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Internal number this client uses to refer to this address.
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
 * Message sent by ATS service to client to confirm that it is done
 * using the given session ID.
 */
struct SessionReleaseMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_ATS_SESSION_RELEASE.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number the client used to identify the session.
   */
  uint32_t session_id GNUNET_PACKED;

  /**
   * Which peer is this about? (Technically redundant, as the
   * @e session_id should be sufficient, but may enable client
   * to find the session faster).
   */
  struct GNUNET_PeerIdentity peer;
};



/**
 * ATS Service suggests to the transport service to use the address
 * identified by the given @e session_id for the given @e peer with
 * the given @e bandwidth_in and @e bandwidth_out limits from now on.
 */
struct AddressSuggestionMessage
{
  /**
   * A message of type #GNUNET_MESSAGE_TYPE_ATS_ADDRESS_SUGGESTION.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Internal number this client uses to refer to the address this
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




struct PeerInformationMessage
{
  struct GNUNET_MessageHeader header;

  uint32_t ats_count GNUNET_PACKED;

  uint32_t address_active GNUNET_PACKED;

  uint32_t id GNUNET_PACKED;

  struct GNUNET_PeerIdentity peer;

  uint16_t address_length GNUNET_PACKED;

  uint16_t plugin_name_length GNUNET_PACKED;

  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out;

  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in;

  /* followed by:
   * - struct GNUNET_ATS_Information [ats_count];
   * - char address[address_length]
   * - char plugin_name[plugin_name_length] (including '\0'-termination).
   */

};


/**
 * Client to service: please give us an overview of the addresses.
 */
struct AddressListRequestMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_ATS_ADDRESSLIST_REQUEST
   */
  struct GNUNET_MessageHeader header;

  /**
   * ID used to match replies to this request.
   */
  uint32_t id GNUNET_PACKED;

  /**
   * Which peer do we care about? All zeros for all.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * #GNUNET_YES to get information about all addresses,
   * #GNUNET_NO to only return addresses that are in use.
   */
  int32_t all GNUNET_PACKED;

};


struct ReservationRequestMessage
{
  struct GNUNET_MessageHeader header;

  int32_t amount GNUNET_PACKED;

  struct GNUNET_PeerIdentity peer;
};



struct ReservationResultMessage
{
  struct GNUNET_MessageHeader header;

  int32_t amount GNUNET_PACKED;

  struct GNUNET_PeerIdentity peer;

  struct GNUNET_TIME_RelativeNBO res_delay;
};

struct PreferenceInformation
{

  uint32_t preference_kind GNUNET_PACKED;

  float preference_value GNUNET_PACKED;

};


struct ChangePreferenceMessage
{
  struct GNUNET_MessageHeader header;

  uint32_t num_preferences GNUNET_PACKED;

  struct GNUNET_PeerIdentity peer;

  /* followed by 'num_preferences'
   * struct PreferenceInformation values */
};


/**
 * Message containing application feedback for a peer
 */
struct FeedbackPreferenceMessage
{
  struct GNUNET_MessageHeader header;

  /**
   * Number of feedback values included
   */
  uint32_t num_feedback GNUNET_PACKED;

  /**
   * Relative time describing for which time interval this feedback is
   */
  struct GNUNET_TIME_RelativeNBO scope;

  /**
   * Peer this feedback is for
   */
  struct GNUNET_PeerIdentity peer;

  /* followed by 'num_feedback'
   * struct PreferenceInformation values */
};

GNUNET_NETWORK_STRUCT_END



#endif
