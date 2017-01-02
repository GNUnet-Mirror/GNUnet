/*
     This file is part of GNUnet.
     Copyright (C) 2011, 2016 GNUnet e.V.

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
 * Flags specifying the events this client would be
 * interested in being told about.
 */
enum GNUNET_NAT_RegisterFlags
{
  /**
   * This client does not want any notifications.
   */
  GNUNET_NAT_RF_NONE = 0,

  /**
   * This client wants to be informed about changes to our
   * applicable addresses.
   */
  GNUNET_NAT_RF_ADDRESSES = 1,

  /**
   * This client supports address reversal.
   */
  GNUNET_NAT_RF_REVERSAL = 2
};


/**
 * Message sent by a client to register with its addresses.
 */
struct GNUNET_NAT_RegisterMessage
{
  /**
   * Header with type #GNUNET_MESSAGE_TYPE_NAT_REGISTER
   */
  struct GNUNET_MessageHeader header;

  /**
   * An `enum GNUNET_NAT_RegisterFlags`.
   */
  uint8_t flags;

  /**
   * Client's IPPROTO, e.g. IPPROTO_UDP or IPPROTO_TCP.
   */
  uint8_t proto;

  /**
   * Number of bytes in the string that follow which
   * specify the hostname and port of a manually punched
   * hole for this client.
   */
  uint16_t hole_external_len GNUNET_PACKED;

  /**
   * Number of addresses that this service is bound to that follow.
   * Given as an array of "struct sockaddr" entries, the size of
   * each entry being determined by the "sa_family" at the beginning.
   */
  uint16_t num_addrs GNUNET_PACKED;

  /* Followed by @e num_addrs addresses of type 'struct
     sockaddr' */

  /* Followed by @e hole_external_len bytes giving a hostname
     and port */
  
};


/**
 * Client telling the service to (possibly) handle a STUN message.
 */
struct GNUNET_NAT_HandleStunMessage
{
  /**
   * Header with type #GNUNET_MESSAGE_TYPE_NAT_HANDLE_STUN
   */
  struct GNUNET_MessageHeader header;

  /**
   * Size of the sender address included, in NBO.
   */
  uint16_t sender_addr_size;

  /**
   * Number of bytes of payload included, in NBO.
   */
  uint16_t payload_size;

  /* followed by a `struct sockaddr` of @e sender_addr_size bytes */

  /* followed by payload with @e payload_size bytes */
};


/**
 * Client asking the service to initiate connection reversal.
 */
struct GNUNET_NAT_RequestConnectionReversalMessage
{
  /**
   * Header with type #GNUNET_MESSAGE_TYPE_NAT_REQUEST_CONNECTION_REVERSAL
   */
  struct GNUNET_MessageHeader header;

  /**
   * Size of the local address included, in NBO.
   */
  uint16_t local_addr_size;

  /**
   * Size of the remote address included, in NBO.
   */
  uint16_t remote_addr_size;

  /* followed by a `struct sockaddr` of @e local_addr_size bytes */

  /* followed by a `struct sockaddr` of @e remote_addr_size bytes */

};


/**
 * Service telling a client that connection reversal was requested.
 */
struct GNUNET_NAT_ConnectionReversalRequestedMessage
{
  /**
   * Header with type #GNUNET_MESSAGE_TYPE_NAT_CONNECTION_REVERSAL_REQUESTED
   */
  struct GNUNET_MessageHeader header;

  /* followed by a `struct sockaddr_in` */
  
};


/**
 * Service notifying the client about changes in the set of 
 * addresses it has.
 */
struct GNUNET_NAT_AddressChangeNotificationMessage
{
  /**
   * Header with type #GNUNET_MESSAGE_TYPE_NAT_ADDRESS_CHANGE
   */
  struct GNUNET_MessageHeader header;

  /**
   * #GNUNET_YES to add, #GNUNET_NO to remove the address from the list.
   */ 
  int32_t add_remove GNUNET_PACKED;

  /**
   * Type of the address, an `enum GNUNET_NAT_AddressClass` in NBO.
   */
  uint32_t addr_class GNUNET_PACKED;
  /* followed by a `struct sockaddr` */
  
};


/**
 * Client requesting automatic configuration.
 */
struct GNUNET_NAT_AutoconfigRequestMessage
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
struct GNUNET_NAT_AutoconfigResultMessage
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
