/*
     This file is part of GNUnet.
     (C) 2010,2011 Christian Grothoff (and other contributing authors)

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


enum StartFlag
{

  START_FLAG_SCHEDULING = 0,

  START_FLAG_PERFORMANCE_WITH_PIC = 1,

  START_FLAG_PERFORMANCE_NO_PIC = 2
};

GNUNET_NETWORK_STRUCT_BEGIN

struct ClientStartMessage
{
  struct GNUNET_MessageHeader header;

  /**
   * NBO value of an 'enum StartFlag'.
   */
  uint32_t start_flag GNUNET_PACKED;
};


struct RequestAddressMessage
{
  struct GNUNET_MessageHeader header;

  uint32_t reserved GNUNET_PACKED;

  struct GNUNET_PeerIdentity peer;
};

struct ResetBackoffMessage
{
  struct GNUNET_MessageHeader header;

  uint32_t reserved GNUNET_PACKED;

  struct GNUNET_PeerIdentity peer;
};


struct AddressUpdateMessage
{
  struct GNUNET_MessageHeader header;

  uint32_t ats_count GNUNET_PACKED;

  struct GNUNET_PeerIdentity peer;

  uint16_t address_length GNUNET_PACKED;

  uint16_t plugin_name_length GNUNET_PACKED;

  uint32_t session_id GNUNET_PACKED;

  /* followed by:
   * - struct GNUNET_ATS_Information [ats_count];
   * - char address[address_length]
   * - char plugin_name[plugin_name_length] (including '\0'-termination).
   */

};

struct AddressUseMessage
{
  struct GNUNET_MessageHeader header;

  struct GNUNET_PeerIdentity peer;

  uint16_t in_use GNUNET_PACKED;

  uint16_t address_length GNUNET_PACKED;

  uint16_t plugin_name_length GNUNET_PACKED;

  uint32_t session_id GNUNET_PACKED;

  /* followed by:
   * - char address[address_length]
   * - char plugin_name[plugin_name_length] (including '\0'-termination).
   */

};


struct AddressDestroyedMessage
{
  struct GNUNET_MessageHeader header;

  uint32_t reserved GNUNET_PACKED;

  struct GNUNET_PeerIdentity peer;

  uint16_t address_length GNUNET_PACKED;

  uint16_t plugin_name_length GNUNET_PACKED;

  uint32_t session_id GNUNET_PACKED;

  /* followed by:
   * - char address[address_length]
   * - char plugin_name[plugin_name_length] (including '\0'-termination).
   */

};


struct AddressSuggestionMessage
{
  struct GNUNET_MessageHeader header;

  uint32_t ats_count GNUNET_PACKED;

  struct GNUNET_PeerIdentity peer;

  uint16_t address_length GNUNET_PACKED;

  uint16_t plugin_name_length GNUNET_PACKED;

  uint32_t session_id GNUNET_PACKED;

  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out;

  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in;

  /* followed by:
   * - struct GNUNET_ATS_Information [ats_count];
   * - char address[address_length]
   * - char plugin_name[plugin_name_length] (including '\0'-termination).
   */

};


struct PeerInformationMessage
{
  struct GNUNET_MessageHeader header;

  uint32_t ats_count GNUNET_PACKED;

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


struct ReservationRequestMessage
{
  struct GNUNET_MessageHeader header;

  int32_t amount GNUNET_PACKED;

  struct GNUNET_PeerIdentity peer;
};


/**
 * Message sent by ATS service to client to confirm that it is done
 * using the given session ID.
 */
struct SessionReleaseMessage
{
  struct GNUNET_MessageHeader header;

  uint32_t session_id GNUNET_PACKED;

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
GNUNET_NETWORK_STRUCT_END



#endif
