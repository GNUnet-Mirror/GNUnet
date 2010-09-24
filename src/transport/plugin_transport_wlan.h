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

#include "gnunet_common.h"

typedef unsigned int uint32_t;
typedef unsigned short uint16_t;

/* Wlan IEEE80211 header default */
static const uint8_t u8aIeeeHeader[] = 
  {
    0x08, 0x01, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x13, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x13, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x10, 0x86,
  };

/**
 * Wlan header
 */

struct IeeeHeader
{
  /**
   * Wlan flags
   */
  uint32_t flags;
  
  /**
   * first mac
   */
  uint8_t mac1[6];
  
  /**
   * second mac
   */
  uint8_t mac2[6];
  
  /**
   * third mac
   */
  uint8_t mac3[6];
  
  /**
   * Wlan flags2
   */
  uint16_t flags2;
};

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

/**
 * Radiotap Header
 */
struct RadiotapHeader
{
  /**
   * radiotap version
   */
  uint16_t version GNUNET_PACKED;
  
  /**
   * radiotap header length
   */
  uint16_t length GNUNET_PACKED;
  
  /**
   * bitmap
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

