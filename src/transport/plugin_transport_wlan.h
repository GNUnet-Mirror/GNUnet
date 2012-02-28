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


struct Radiotap_Send
{
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
  uint16_t tx_power;
};


/**
 * struct to represent infos gathered form the radiotap fields, see RadiotapHeader for more Infos
 */
struct Radiotap_rx
{
  /**
   * FIXME: not initialized properly so far. (supposed to contain
   * information about which of the fields below are actually valid).
   */
  uint32_t ri_present;

  /**
   * IEEE80211_RADIOTAP_TSFT
   */
  uint64_t ri_mactime;

  /**
   * from radiotap
   * either IEEE80211_RADIOTAP_DBM_ANTSIGNAL
   * or IEEE80211_RADIOTAP_DB_ANTSIGNAL
   */
  int32_t ri_power;

  /**
   * either IEEE80211_RADIOTAP_DBM_ANTNOISE
   * or IEEE80211_RADIOTAP_DB_ANTNOISE
   */
  int32_t ri_noise;

  /**
   * IEEE80211_RADIOTAP_CHANNEL
   */
  uint32_t ri_channel;

  /**
   * Frequency we use.  FIXME: not properly initialized so far!
   */
  uint32_t ri_freq;

  /**
   * IEEE80211_RADIOTAP_RATE * 50000
   */
  uint32_t ri_rate;

  /**
   * IEEE80211_RADIOTAP_ANTENNA
   */
  uint32_t ri_antenna;
};



#endif
