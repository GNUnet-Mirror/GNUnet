/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file src/nat/nat.h
 * @brief Messages for interaction with gnunet-nat-server
 * @author Christian Grothoff
 *
 */
#ifndef NAT_H
#define NAT_H
#include "gnunet_util_lib.h"

#define DEBUG_NAT GNUNET_EXTRA_LOGGING

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Request to test NAT traversal.
 */
struct GNUNET_NAT_TestMessage
{
  /**
   * Header with type "GNUNET_MESSAGE_TYPE_NAT_TEST"
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
   * GNUNET_YES for TCP, GNUNET_NO for UDP.
   */
  int32_t is_tcp;

};
GNUNET_NETWORK_STRUCT_END

#endif
