/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff

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
 * @file exit/exit.h
 * @brief format for mesh messages exchanged between VPN service and exit daemon
 * @author Christian Grothoff
 */
#ifndef EXIT_H
#define EXIT_H

#include "gnunet_util_lib.h"

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Message send via mesh to an exit daemon to initiate forwarding of
 * TCP data to a local service.
 */
struct GNUNET_EXIT_TcpServiceStartMessage
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_VPN_TCP_TO_SERVICE_START
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always 0.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Identification for the desired service.
   */
  GNUNET_HashCode service_descriptor GNUNET_PACKED;

  /**
   * Skeleton of the TCP header to send.  Port numbers are to
   * be replaced and the checksum may be updated as necessary.
   */
  struct GNUNET_TUN_TcpHeader tcp_header;

  /* followed by TCP payload */
};


/**
 * Message send via mesh to an exit daemon to initiate forwarding of
 * TCP data to the Internet.
 */
struct GNUNET_EXIT_TcpInternetStartMessage
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_VPN_TCP_TO_INTERNET_START
   */
  struct GNUNET_MessageHeader header;

  /**
   * Address family, AF_INET or AF_INET6, in network byte order.
   */
  int32_t af GNUNET_PACKED;

  /**
   * Skeleton of the TCP header to send.  Port numbers are to
   * be replaced and the checksum may be updated as necessary.
   */
  struct GNUNET_TUN_TcpHeader tcp_header;

  /* followed by IP address of the destination; either
     'struct in_addr' or 'struct in6_addr', depending on af */

  /* followed by TCP payload */
};


/**
 * Message send via mesh between VPN and entry and an exit daemon to 
 * transmit TCP data between the VPN entry and an exit session.  This
 * format is used for both Internet-exits and service-exits and
 * in both directions (VPN to exit and exit to VPN).
 */
struct GNUNET_EXIT_TcpDataMessage
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_VPN_TCP_DATA
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always 0.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Skeleton of the TCP header to send.  Port numbers are to
   * be replaced and the checksum may be updated as necessary.  (The destination port number should not be changed, as it contains the desired destination port.)
   */
  struct GNUNET_TUN_TcpHeader tcp_header;

  /* followed by TCP payload */
};


/**
 * Message send via mesh to an exit daemon to send
 * UDP data to a local service.
 */
struct GNUNET_EXIT_UdpServiceMessage
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_VPN_UDP_TO_SERVICE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Source port to use for the UDP request (0 to use a random port).  In NBO.
   */
  uint16_t source_port GNUNET_PACKED;

  /**
   * Destination port to use for the UDP request.  In NBO.
   */   
  uint16_t destination_port GNUNET_PACKED;

  /**
   * Identification for the desired service.
   */
  GNUNET_HashCode service_descriptor GNUNET_PACKED;

  /* followed by UDP payload */
};


/**
 * Message send via mesh to an exit daemon to forward
 * UDP data to the Internet.
 */
struct GNUNET_EXIT_UdpInternetMessage
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_VPN_UDP_TO_INTERNET
   */
  struct GNUNET_MessageHeader header;

  /**
   * Address family, AF_INET or AF_INET6, in network byte order.
   */
  int32_t af GNUNET_PACKED;

  /**
   * Source port to use for the UDP request (0 to use a random port).  In NBO.
   */
  uint16_t source_port GNUNET_PACKED;

  /**
   * Destination port to use for the UDP request.  In NBO.
   */   
  uint16_t destination_port GNUNET_PACKED;

  /* followed by IP address of the destination; either
     'struct in_addr' or 'struct in6_addr', depending on af */

  /* followed by UDP payload */
};


/**
 * Message send from exit daemon back to the UDP entry point
 * (used for both Internet and Service exit replies).
 */
struct GNUNET_EXIT_UdpReplyMessage
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_VPN_UDP_REPLY
   */
  struct GNUNET_MessageHeader header;

  /**
   * Source port to use for the UDP reply (0 to use the same
   * port as for the original request).  In NBO.
   */
  uint16_t source_port GNUNET_PACKED;

  /**
   * Destination port to use for the UDP reply (0 to use the same
   * port as for the original request).  In NBO.
   */   
  uint16_t destination_port GNUNET_PACKED;

  /* followed by UDP payload */
};


/**
 * Message send via mesh to an exit daemon to send
 * ICMP data to a local service.
 */
struct GNUNET_EXIT_IcmpServiceMessage
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_VPN_ICMP_TO_SERVICE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Address family, AF_INET or AF_INET6, in network byte order.  This
   * AF value determines if the 'icmp_header' is ICMPv4 or ICMPv6.
   * The receiver (exit) may still have to translate (PT) to the services'
   * ICMP version (if possible).
   */
  int32_t af GNUNET_PACKED;

  /**
   * Identification for the desired service.
   */
  GNUNET_HashCode service_descriptor GNUNET_PACKED;

  /**
   * ICMP header to use.
   */
  struct GNUNET_TUN_IcmpHeader icmp_header;

  /* followed by ICMP payload; however, for certain ICMP message
     types where the payload is the original IP packet, the payload
     is omitted as it is useless for the receiver (who will need
     to create some fake payload manually)  */
};


/**
 * Message send via mesh to an exit daemon to forward
 * ICMP data to the Internet.
 */
struct GNUNET_EXIT_IcmpInternetMessage
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_VPN_ICMP_TO_INTERNET
   */
  struct GNUNET_MessageHeader header;

  /**
   * Address family, AF_INET or AF_INET6, in network byte order.
   * Determines both the ICMP version used in the 'icmp_header' and
   * the IP address format that is used for the target IP.  If
   * PT is necessary, the sender has already done it.
   */
  int32_t af GNUNET_PACKED;

  /**
   * ICMP header to use.  Must match the target 'af' given
   * above.
   */
  struct GNUNET_TUN_IcmpHeader icmp_header;

  /* followed by IP address of the destination; either
     'struct in_addr' or 'struct in6_addr', depending on af */

  /* followed by ICMP payload; however, for certain ICMP message
     types where the payload is the original IP packet, the payload
     is omitted as it is useless for the receiver (who will need
     to create some fake payload manually)   */
};


/**
 * Message send via mesh to the vpn service to send
 * ICMP data to the VPN's TUN interface.
 */
struct GNUNET_EXIT_IcmpToVPNMessage
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_VPN_ICMP_TO_VPN
   */
  struct GNUNET_MessageHeader header;

  /**
   * Address family, AF_INET or AF_INET6, in network byte order.
   * Useful to determine if this is an ICMPv4 or ICMPv6 header.
   */
  int32_t af GNUNET_PACKED;

  /**
   * ICMP header to use.  ICMPv4 or ICMPv6, depending on 'af'.
   */
  struct GNUNET_TUN_IcmpHeader icmp_header;

  /* followed by ICMP payload; however, for certain ICMP message
     types where the payload is the original IP packet, the payload
     is omitted as it is useless for the receiver (who will need
     to create some fake payload manually) */
};


GNUNET_NETWORK_STRUCT_END

#endif
