/*
     This file is part of GNUnet
     (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009 Christian Grothoff (and other contributing authors)

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



struct MacAddress
{
  u_int8_t mac[6];
};

struct Wlan_Helper_Control_Message
{
  struct GNUNET_MessageHeader hdr;
  struct MacAddress mac ;
};



/* Wlan IEEE80211 header default */
//Informations (in German) http://www.umtslink.at/content/WLAN_macheader-196.html
static const uint8_t u8aIeeeHeader[] = 
  {
    0x08, 0x01, // Frame Control 0x08= 00001000 -> | b1,2 = 0 -> Version 0;
                //      b3,4 = 10 -> Data; b5-8 = 0 -> Normal Data
		//	0x01 = 00000001 -> | b1 = 1 to DS; b2 = 0 not from DS;
    0x00, 0x00, // Duration/ID
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // mac1 - in this case receiver
    0x13, 0x22, 0x33, 0x44, 0x55, 0x66, // mac2 - in this case sender
    0x13, 0x22, 0x33, 0x44, 0x55, 0x66, // mac3 - in this case bssid
    0x10, 0x86, //Sequence Control
  };

// gnunet bssid
static const char mac_bssid[] =
  { 0x13, 0x22, 0x33, 0x44, 0x55, 0x66 };

// broadcast mac
static const char bc_all_mac[] =
   { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };


/* this is the template radiotap header we send packets out with */

static const uint8_t u8aRadiotapHeader[] = 
  {
    0x00, 0x00, // <-- radiotap version
    0x19, 0x00, // <- radiotap header length
    0x6f, 0x08, 0x00, 0x00, // <-- bitmap
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <-- timestamp
    0x00, // <-- flags (Offset +0x10)
    0x6c, // <-- rate (0ffset +0x11)
    0x71, 0x09, 0xc0, 0x00, // <-- channel
    0xde, // <-- antsignal
    0x00, // <-- antnoise
    0x01, // <-- antenna
};

struct Radiotap_Send
{
  /**
     * wlan send rate
     */
    uint8_t rate;

    /**
     * antenna
     */
    uint8_t antenna;

    /**
     * Transmit power expressed as unitless distance from max power set at factory calibration.
     * 0 is max power. Monotonically nondecreasing with lower power levels.
     */

    uint16_t tx_power;
};

struct rx_info {
        uint64_t ri_mactime;
        int32_t ri_power;
        int32_t ri_noise;
        uint32_t ri_channel;
        uint32_t ri_freq;
        uint32_t ri_rate;
        uint32_t ri_antenna;
};

/**
 * Radiotap Header
 */
struct RadiotapHeader
{
  /**
   * radiotap version
   */
  u_int8_t version;

  u_int8_t pad_version;
  
  /**
   * radiotap header length
   */
  uint16_t length GNUNET_PACKED;
  
  /**
   * bitmap, fields present
   */
  uint32_t bitmap GNUNET_PACKED;
  
  /**
   * timestamp
   */
  uint64_t timestamp GNUNET_PACKED;
  
  /**
   * radiotap flags
   */
  uint8_t flags;
  
  /**
   * wlan send rate
   */
  uint8_t rate;
  
  // FIXME: unaligned here, is this OK?
  /**
   * Wlan channel
   */
  uint32_t channel GNUNET_PACKED;
  
  /**
   * antsignal
   */
  uint8_t antsignal;
  
  /**
   * antnoise
   */
  uint8_t antnoise;
  
  /**
   * antenna
   */
  uint8_t antenna;
};

#endif
