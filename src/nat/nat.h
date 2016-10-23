/*
     This file is part of GNUnet.
     Copyright (C) 2011 GNUnet e.V.

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
 * @file src/nat/nat.h
 * @brief Messages for interaction with gnunet-nat-server and gnunet-nat-service
 * @author Christian Grothoff
 *
 */
#ifndef NAT_H
#define NAT_H
#include "gnunet_util_lib.h"


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Request to test NAT traversal, sent to the gnunet-nat-server
 * (not the service!).
 */
struct GNUNET_NAT_TestMessage
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
 *
 */
struct GNUNET_NAT_RegisterMessage
{
  /**
   * Header with type #GNUNET_MESSAGE_TYPE_NAT_REGISTER
   */
  struct GNUNET_MessageHeader header;
};


/**
 *
 */
struct GNUNET_NAT_HandleStunMessage
{
  /**
   * Header with type #GNUNET_MESSAGE_TYPE_NAT_HANDLE_STUN
   */
  struct GNUNET_MessageHeader header;
};


/**
 *
 */
struct GNUNET_NAT_RequestConnectionReversalMessage
{
  /**
   * Header with type #GNUNET_MESSAGE_TYPE_NAT_REQUEST_CONNECTION_REVERSAL
   */
  struct GNUNET_MessageHeader header;
};


/**
 *
 */
struct GNUNET_NAT_ConnectionReversalRequestedMessage
{
  /**
   * Header with type #GNUNET_MESSAGE_TYPE_NAT_CONNECTION_REVERSAL_REQUESTED
   */
  struct GNUNET_MessageHeader header;
};


/**
 *
 */
struct GNUNET_NAT_AddressChangeNotificationMessage
{
  /**
   * Header with type #GNUNET_MESSAGE_TYPE_NAT_ADDRESS_CHANGE
   */
  struct GNUNET_MessageHeader header;
};


/**
 *
 */
struct GNUNET_NAT_Ipv4ChangeNotificationMessage
{
  /**
   * Header with type #GNUNET_MESSAGE_TYPE_NAT_IPV4_CHANGE
   */
  struct GNUNET_MessageHeader header;
};


/**
 *
 */
struct GNUNET_NAT_RequestTestMessage
{
  /**
   * Header with type #GNUNET_MESSAGE_TYPE_NAT_REQUEST_TEST
   */
  struct GNUNET_MessageHeader header;
};


/**
 *
 */
struct GNUNET_NAT_TestResultMessage
{
  /**
   * Header with type #GNUNET_MESSAGE_TYPE_NAT_TEST_RESULT
   */
  struct GNUNET_MessageHeader header;
};


/**
 *
 */
struct GNUNET_NAT_AutoconfigRequestMessage
{
  /**
   * Header with type #GNUNET_MESSAGE_TYPE_NAT_REQUEST_AUTO_CFG
   */
  struct GNUNET_MessageHeader header;
};


/**
 *
 */
struct GNUNET_NAT_AutoconfigResultMessage
{
  /**
   * Header with type #GNUNET_MESSAGE_TYPE_NAT_AUTO_CFG_RESULT
   */
  struct GNUNET_MessageHeader header;
};


GNUNET_NETWORK_STRUCT_END

#endif
