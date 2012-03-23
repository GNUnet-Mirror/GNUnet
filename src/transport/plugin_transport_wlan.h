/*
 This file is part of GNUnet
 (C) 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file transport/plugin_transport_wlan.h
 * @brief header for transport plugin and the helper for wlan
 * @author David Brodski
 */
#ifndef PLUGIN_TRANSPORT_WLAN
#define PLUGIN_TRANSPORT_WLAN

#include <stdint.h>
#include "gnunet_common.h"

/**
 * Number fo bytes in a mac address.
 */
#define MAC_ADDR_SIZE 6

/**
 * Value for "Management" in the 'frame_control' field of the
 * struct GNUNET_TRANSPORT_WLAN_Ieee80211Frame.  
 */
#define IEEE80211_FC0_TYPE_MGT                  0x00

/**
 * Value for "Control" in the 'frame_control' field of the
 * struct GNUNET_TRANSPORT_WLAN_Ieee80211Frame.
 */
#define IEEE80211_FC0_TYPE_CTL                  0x04

/**
 * Value for DATA in the 'frame_control' field of the
 * struct GNUNET_TRANSPORT_WLAN_Ieee80211Frame.
 */
#define IEEE80211_FC0_TYPE_DATA                 0x08


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * A MAC Address.
 */
struct GNUNET_TRANSPORT_WLAN_MacAddress
{
  uint8_t mac[MAC_ADDR_SIZE];
};

/**
 * Format of a WLAN Control Message.
 */
struct GNUNET_TRANSPORT_WLAN_HelperControlMessage
{
  /**
   * Message header.  Type is
   * GNUNET_MESSAGE_TYPE_WLAN_HELPER_CONTROL
   */
  struct GNUNET_MessageHeader hdr;

  /**
   * MAC Address of the local WLAN interface.
   */
  struct GNUNET_TRANSPORT_WLAN_MacAddress mac;
};


/**
 * generic definitions for IEEE 802.11 frames
 */
struct GNUNET_TRANSPORT_WLAN_Ieee80211Frame
{
  /**
   * 802.11 Frame Control field.  A bitmask.  The overall field is a
   * 16-bit mask of the respecitve fields.  The lowest two bits should
   * be 0, then comes the "type" (2 bits, see IEEE80211_FC0_TYPE_*
   * constants), followed by 4-bit subtype (all zeros for ad-hoc),
   * followed by various flags (to DS, from DS, more frag, retry,
   * power management, more data, WEP, strict), all of which we also
   * keep at zero.
   */
  uint16_t frame_control GNUNET_PACKED;

  /**
   * Microseconds to reserve link (duration), 0 by default
   */
  uint16_t duration GNUNET_PACKED;

  /**
   * Address 1: destination address in ad-hoc mode or AP, BSSID if station,
   */
  struct GNUNET_TRANSPORT_WLAN_MacAddress addr1;

  /**
   * Address 2: source address if in ad-hoc-mode or station, BSSID if AP
   */
  struct GNUNET_TRANSPORT_WLAN_MacAddress addr2;

  /**
   * Address 3: BSSID in ad-hoc mode, Destination if station, source if AP
   */
  struct GNUNET_TRANSPORT_WLAN_MacAddress addr3;

  /**
   * 802.11 sequence control field; contains fragment number an sequence
   * number (we set this to all zeros).
   */
  uint16_t sequence_control GNUNET_PACKED;

  /**
   * Link layer control (LLC).  Set to a GNUnet-specific value.
   */
  u_int8_t llc[4];

  /* payload */

} GNUNET_PACKED;



/**
 * Message from the plugin to the WLAN helper: send the given message with the
 * given connection parameters.
 */
struct GNUNET_TRANSPORT_WLAN_RadiotapSendMessage
{

  /**
   * Type is 'GNUNET_MESSAGE_TYPE_WLAN_DATA_TO_HELPER'.
   */
  struct GNUNET_MessageHeader header;

  /**
   * wlan send rate
   */
  uint8_t rate;

  /**
   * Antenna; the first antenna is 0.
   */
  uint8_t antenna;

  /**
   * Transmit power expressed as unitless distance from max power set at factory calibration.
   * 0 is max power. Monotonically nondecreasing with lower power levels.
   */
  uint16_t tx_power GNUNET_PACKED;

  /**
   * IEEE Frame to transmit (the sender MAC address will be overwritten by the helper as it does not
   * trust the plugin to set it correctly).
   */
  struct GNUNET_TRANSPORT_WLAN_Ieee80211Frame frame;

  /* actual payload follows */
};


/**
 * Message from the WLAN helper to the plugin: we have received the given message with the
 * given performance characteristics.
 */
/**
 * struct to represent infos gathered form the radiotap fields, see RadiotapHeader for more Infos
 */
struct GNUNET_TRANSPORT_WLAN_RadiotapReceiveMessage
{

  /**
   * Type is 'GNUNET_MESSAGE_TYPE_WLAN_DATA_FROM_HELPER'.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Information about which of the fields below are actually valid.
   * 0 for none.  FIXME: not properly initialized so far (always zero).
   */
  uint32_t ri_present GNUNET_PACKED;

  /**
   * IEEE80211_RADIOTAP_TSFT, 0 if unknown.
   */
  uint64_t ri_mactime GNUNET_PACKED;

  /**
   * from radiotap
   * either IEEE80211_RADIOTAP_DBM_ANTSIGNAL
   * or IEEE80211_RADIOTAP_DB_ANTSIGNAL, 0 if unknown.
   */
  int32_t ri_power GNUNET_PACKED;

  /**
   * either IEEE80211_RADIOTAP_DBM_ANTNOISE
   * or IEEE80211_RADIOTAP_DB_ANTNOISE, 0 if unknown.
   */
  int32_t ri_noise GNUNET_PACKED;

  /**
   * IEEE80211_RADIOTAP_CHANNEL, 0 if unknown.
   */
  uint32_t ri_channel GNUNET_PACKED;

  /**
   * Frequency we use.  0 if unknown.
   */
  uint32_t ri_freq GNUNET_PACKED;

  /**
   * IEEE80211_RADIOTAP_RATE * 50000, 0 if unknown.
   */
  uint32_t ri_rate GNUNET_PACKED;

  /**
   * IEEE80211_RADIOTAP_ANTENNA, 0 if unknown.
   */
  uint32_t ri_antenna GNUNET_PACKED;

  /**
   * IEEE Frame.
   */
  struct GNUNET_TRANSPORT_WLAN_Ieee80211Frame frame;

  /* followed by payload */
};

GNUNET_NETWORK_STRUCT_END

/**
 * GNUnet bssid
 */
static const struct GNUNET_TRANSPORT_WLAN_MacAddress mac_bssid_gnunet = {
  {0x13, 0x22, 0x33, 0x44, 0x55, 0x66}
};


/**
 * Broadcast MAC
 */
static const struct GNUNET_TRANSPORT_WLAN_MacAddress bc_all_mac = {
  {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
};

#endif
