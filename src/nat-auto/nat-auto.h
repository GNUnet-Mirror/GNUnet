/*
     This file is part of GNUnet.
     Copyright (C) 2011, 2016, 2017 GNUnet e.V.

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file src/nat-auto/nat-auto.h
 * @brief Messages for interaction with gnunet-nat-auto-service
 * @author Christian Grothoff
 *
 */
#ifndef NAT_AUTO_H
#define NAT_AUTO_H
#include "gnunet_util_lib.h"



GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Request to test NAT traversal, sent to the gnunet-nat-server
 * (not the service!).
 */
struct GNUNET_NAT_AUTO_TestMessage
{
  /**
   * Header with type #GNUNET_MESSAGE_TYPE_NAT_TEST
   */
  struct GNUNET_MessageHeader header;

  /**
   * IPv4 target IP address
   */
  uint32_t dst_ipv4;

  /**
   * Port to use, 0 to send dummy ICMP response.
   */
  uint16_t dport;

  /**
   * Data to send OR advertised-port (in NBO) to use for dummy ICMP.
   */
  uint16_t data;

  /**
   * #GNUNET_YES for TCP, #GNUNET_NO for UDP.
   */
  int32_t is_tcp;

};


/**
 * Client requesting automatic configuration.
 */
struct GNUNET_NAT_AUTO_AutoconfigRequestMessage
{
  /**
   * Header with type #GNUNET_MESSAGE_TYPE_NAT_REQUEST_AUTO_CFG
   */
  struct GNUNET_MessageHeader header;

  /* Followed by configuration (diff, serialized, compressed) */
  
};


/**
 * Service responding with proposed configuration.
 */
struct GNUNET_NAT_AUTO_AutoconfigResultMessage
{
  /**
   * Header with type #GNUNET_MESSAGE_TYPE_NAT_AUTO_CFG_RESULT
   */
  struct GNUNET_MessageHeader header;
  
  /**
   * An `enum GNUNET_NAT_StatusCode` in NBO.
   */
  int32_t status_code GNUNET_PACKED;

  /**
   * An `enum GNUNET_NAT_Type` in NBO.
   */
  int32_t type GNUNET_PACKED;

  /* Followed by configuration (diff, serialized, compressed) */
};


GNUNET_NETWORK_STRUCT_END

#endif
