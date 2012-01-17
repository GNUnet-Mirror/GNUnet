/*
     This file is part of GNUnet.
     (C) 2010, 2011, 2012 Christian Grothoff

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
 * @file include/gnunet_tun_lib.h
 * @brief standard TCP/IP network structs and IP checksum calculations for TUN interaction
 * @author Philipp Toelke
 * @author Christian Grothoff
 */
#ifndef GNUNET_TUN_LIB_H
#define GNUNET_TUN_LIB_H

#include "gnunet_util_lib.h"


/* see http://www.iana.org/assignments/ethernet-numbers */
#ifndef ETH_P_IPV4
/**
 * Number for IPv4
 */
#define ETH_P_IPV4 0x0800
#endif

#ifndef ETH_P_IPV6
/**
 * Number for IPv6
 */
#define ETH_P_IPV6 0x86DD
#endif


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Header from Linux TUN interface.
 */ 
struct GNUNET_TUN_Layer2PacketHeader
{
  /**
   * Some flags (unused).
   */ 
  uint16_t flags;

  /**
   * Here we get an ETH_P_-number.
   */
  uint16_t proto;
};


/**
 * Standard IPv4 header.
 */
struct GNUNET_TUN_IPv4Header
{
  unsigned header_length:4 GNUNET_PACKED;
  unsigned version:4 GNUNET_PACKED;
  uint8_t diff_serv;
  uint16_t total_length GNUNET_PACKED;
  uint16_t identification GNUNET_PACKED;
  unsigned flags:3 GNUNET_PACKED;
  unsigned fragmentation_offset:13 GNUNET_PACKED;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t checksum GNUNET_PACKED;
  struct in_addr source_address GNUNET_PACKED;
  struct in_addr destination_address GNUNET_PACKED;
};


/**
 * Standard IPv6 header.
 */
struct GNUNET_TUN_IPv6Header
{
  unsigned traffic_class_h:4 GNUNET_PACKED;
  unsigned version:4 GNUNET_PACKED;
  unsigned traffic_class_l:4 GNUNET_PACKED;
  unsigned flow_label:20 GNUNET_PACKED;
  uint16_t payload_length GNUNET_PACKED;
  uint8_t next_header;
  uint8_t hop_limit;
  struct in6_addr source_address GNUNET_PACKED;
  struct in6_addr destination_address GNUNET_PACKED;
};


/**
 * TCP packet header (FIXME: rename!)
 */
struct GNUNET_TUN_TcpHeader
{
  unsigned spt:16 GNUNET_PACKED;
  unsigned dpt:16 GNUNET_PACKED;
  unsigned seq:32 GNUNET_PACKED;
  unsigned ack:32 GNUNET_PACKED;
  unsigned off:4 GNUNET_PACKED;
  unsigned rsv:4 GNUNET_PACKED;
  unsigned flg:8 GNUNET_PACKED;
  unsigned wsz:16 GNUNET_PACKED;
  unsigned crc:16 GNUNET_PACKED;
  unsigned urg:16 GNUNET_PACKED;
};


/**
 * UDP packet header  (FIXME: rename!)
 */
struct GNUNET_TUN_UdpHeader
{
  uint16_t spt GNUNET_PACKED;
  uint16_t dpt GNUNET_PACKED;
  uint16_t len GNUNET_PACKED;
  uint16_t crc GNUNET_PACKED;
};


/**
 * DNS header.
 */
struct GNUNET_TUN_DnsHeader
{
  uint16_t id GNUNET_PACKED;
  uint16_t flags GNUNET_PACKED;
  uint16_t qdcount GNUNET_PACKED;
  uint16_t ancount GNUNET_PACKED;
  uint16_t nscount GNUNET_PACKED;
  uint16_t arcount GNUNET_PACKED;
};

GNUNET_NETWORK_STRUCT_END


/**
 * Initialize an IPv4 header.
 *
 * @param ip header to initialize
 * @param protocol protocol to use (i.e. IPPROTO_UDP)
 * @param payload_length number of bytes of payload that follow (excluding IPv4 header)
 * @param src source IP address to use
 * @param dst destination IP address to use
 */
void
GNUNET_TUN_initialize_ipv4_header (struct GNUNET_TUN_IPv4Header *ip,
				   uint8_t protocol,
				   uint16_t payload_length,
				   const struct in_addr *src,
				   const struct in_addr *dst);


/**
 * Initialize an IPv6 header.
 *
 * @param ip header to initialize
 * @param protocol protocol to use (i.e. IPPROTO_UDP)
 * @param payload_length number of bytes of payload that follow (excluding IPv4 header)
 * @param src source IP address to use
 * @param dst destination IP address to use
 */
void
GNUNET_TUN_initialize_ipv6_header (struct GNUNET_TUN_IPv6Header *ip,
				   uint8_t protocol,
				   uint16_t payload_length,
				   const struct in6_addr *src,
				   const struct in6_addr *dst);


#endif
