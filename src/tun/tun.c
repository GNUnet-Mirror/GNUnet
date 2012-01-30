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
 * @file tun/tun.c
 * @brief standard IP calculations for TUN interaction
 * @author Philipp Toelke
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_tun_lib.h"

/**
 * IP TTL we use for packets that we assemble (8 bit unsigned integer)
 */
#define FRESH_TTL 64


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
				   const struct in_addr *dst)
{
  GNUNET_assert (20 == sizeof (struct GNUNET_TUN_IPv4Header));
  GNUNET_assert (payload_length <= UINT16_MAX - sizeof (struct GNUNET_TUN_IPv4Header));
  memset (ip, 0, sizeof (struct GNUNET_TUN_IPv4Header));
  ip->header_length =  sizeof (struct GNUNET_TUN_IPv4Header) / 4;
  ip->version = 4;
  ip->total_length = htons (sizeof (struct GNUNET_TUN_IPv4Header) + payload_length);
  ip->identification = (uint16_t) GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 
							    65536);
  ip->ttl = FRESH_TTL;
  ip->protocol = protocol;
  ip->source_address = *src;
  ip->destination_address = *dst;
  ip->checksum = GNUNET_CRYPTO_crc16_n (ip, sizeof (struct GNUNET_TUN_IPv4Header));
}


/**
 * Initialize an IPv6 header.
 *
 * @param ip header to initialize
 * @param protocol protocol to use (i.e. IPPROTO_UDP), technically "next_header" for IPv6
 * @param payload_length number of bytes of payload that follow (excluding IPv4 header)
 * @param src source IP address to use
 * @param dst destination IP address to use
 */
void
GNUNET_TUN_initialize_ipv6_header (struct GNUNET_TUN_IPv6Header *ip,
				   uint8_t protocol,
				   uint16_t payload_length,
				   const struct in6_addr *src,
				   const struct in6_addr *dst)
{
  GNUNET_assert (40 == sizeof (struct GNUNET_TUN_IPv6Header));
  GNUNET_assert (payload_length <= UINT16_MAX - sizeof (struct GNUNET_TUN_IPv6Header));
  memset (ip, 0, sizeof (struct GNUNET_TUN_IPv6Header));
  ip->version = 6;
  ip->next_header = protocol;
  ip->payload_length = htons ((uint16_t) payload_length);
  ip->hop_limit = FRESH_TTL;
  ip->destination_address = *dst;
  ip->source_address = *src;  
}


/**
 * Calculate IPv4 TCP checksum.
 *
 * @param ip ipv4 header fully initialized
 * @param tcp TCP header (initialized except for CRC)
 * @param payload the TCP payload
 * @param payload_length number of bytes of TCP payload
 */
void
GNUNET_TUN_calculate_tcp4_checksum (const struct GNUNET_TUN_IPv4Header *ip,
				    struct GNUNET_TUN_TcpHeader *tcp,
				    const void *payload,
				    uint16_t payload_length)
{
  uint32_t sum;
  uint16_t tmp;

  GNUNET_assert (20 == sizeof (struct GNUNET_TUN_TcpHeader));
  GNUNET_assert (payload_length + sizeof (struct GNUNET_TUN_IPv4Header) + sizeof (struct GNUNET_TUN_TcpHeader) ==
		 ntohs (ip->total_length));
  GNUNET_assert (IPPROTO_TCP == ip->protocol);

  tcp->crc = 0;
  sum = GNUNET_CRYPTO_crc16_step (0, 
				  &ip->source_address,
				  sizeof (struct in_addr) * 2);
  tmp = htons (IPPROTO_TCP);
  sum = GNUNET_CRYPTO_crc16_step (sum, &tmp, sizeof (uint16_t));
  tmp = htons (payload_length + sizeof (struct GNUNET_TUN_TcpHeader));
  sum = GNUNET_CRYPTO_crc16_step (sum, &tmp, sizeof (uint16_t));
  sum = GNUNET_CRYPTO_crc16_step (sum, tcp, sizeof (struct GNUNET_TUN_TcpHeader));
  sum = GNUNET_CRYPTO_crc16_step (sum, payload, payload_length);
  tcp->crc = GNUNET_CRYPTO_crc16_finish (sum);
}


/**
 * Calculate IPv6 TCP checksum.
 *
 * @param ip ipv6 header fully initialized
 * @param tcp header (initialized except for CRC)
 * @param payload the TCP payload
 * @param payload_length number of bytes of TCP payload
 */
void
GNUNET_TUN_calculate_tcp6_checksum (const struct GNUNET_TUN_IPv6Header *ip,
				    struct GNUNET_TUN_TcpHeader *tcp,
				    const void *payload,
				    uint16_t payload_length)
{
  uint32_t sum;
  uint32_t tmp;

  GNUNET_assert (20 == sizeof (struct GNUNET_TUN_TcpHeader));
  GNUNET_assert (payload_length + sizeof (struct GNUNET_TUN_TcpHeader) ==
		 ntohs (ip->payload_length));
  GNUNET_assert (IPPROTO_TCP == ip->next_header);
  tcp->crc = 0;
  sum = GNUNET_CRYPTO_crc16_step (0, &ip->source_address, 2 * sizeof (struct in6_addr));
  tmp = htonl (sizeof (struct GNUNET_TUN_TcpHeader) + payload_length);
  sum = GNUNET_CRYPTO_crc16_step (sum, &tmp, sizeof (uint32_t));
  tmp = htonl (IPPROTO_TCP);
  sum = GNUNET_CRYPTO_crc16_step (sum, &tmp, sizeof (uint32_t));
  sum = GNUNET_CRYPTO_crc16_step (sum, tcp,
				  sizeof (struct GNUNET_TUN_TcpHeader));
  sum = GNUNET_CRYPTO_crc16_step (sum, payload, payload_length);
  tcp->crc = GNUNET_CRYPTO_crc16_finish (sum);
}


/**
 * Calculate IPv4 UDP checksum.
 *
 * @param ip ipv4 header fully initialized
 * @param udp UDP header (initialized except for CRC)
 * @param payload the UDP payload
 * @param payload_length number of bytes of UDP payload
 */
void
GNUNET_TUN_calculate_udp4_checksum (const struct GNUNET_TUN_IPv4Header *ip,
				    struct GNUNET_TUN_UdpHeader *udp,
				    const void *payload,
				    uint16_t payload_length)
{
  uint32_t sum;
  uint16_t tmp;

  GNUNET_assert (8 == sizeof (struct GNUNET_TUN_UdpHeader));
  GNUNET_assert (payload_length + sizeof (struct GNUNET_TUN_IPv4Header) + sizeof (struct GNUNET_TUN_UdpHeader) ==
		 ntohs (ip->total_length));
  GNUNET_assert (IPPROTO_UDP == ip->protocol);

  udp->crc = 0; /* technically optional, but we calculate it anyway, just to be sure */
  sum = GNUNET_CRYPTO_crc16_step (0, 
				  &ip->source_address,
				  sizeof (struct in_addr) * 2);
  tmp = htons (IPPROTO_UDP);
  sum = GNUNET_CRYPTO_crc16_step (sum, 
				  &tmp, 
				  sizeof (uint16_t));
  tmp = htons (sizeof (struct GNUNET_TUN_UdpHeader) + payload_length);
  sum = GNUNET_CRYPTO_crc16_step (sum, 
				  &tmp, 
				  sizeof (uint16_t));
  sum = GNUNET_CRYPTO_crc16_step (sum, 
				  udp, 
				  sizeof (struct GNUNET_TUN_UdpHeader));
  sum = GNUNET_CRYPTO_crc16_step (sum, 
				  payload,
				  payload_length);
  udp->crc = GNUNET_CRYPTO_crc16_finish (sum);
}


/**
 * Calculate IPv6 UDP checksum.
 *
 * @param ip ipv6 header fully initialized
 * @param udp UDP header (initialized except for CRC)
 * @param payload the UDP payload
 * @param payload_length number of bytes of UDP payload
 */
void
GNUNET_TUN_calculate_udp6_checksum (const struct GNUNET_TUN_IPv6Header *ip,
				    struct GNUNET_TUN_UdpHeader *udp,
				    const void *payload,
				    uint16_t payload_length)
{
  uint32_t sum;
  uint32_t tmp;

  GNUNET_assert (payload_length + sizeof (struct GNUNET_TUN_UdpHeader) ==
		 ntohs (ip->payload_length));
  GNUNET_assert (payload_length + sizeof (struct GNUNET_TUN_UdpHeader) ==
		 ntohs (udp->len));
  GNUNET_assert (IPPROTO_UDP == ip->next_header);

  udp->crc = 0;
  sum = GNUNET_CRYPTO_crc16_step (0,
				  &ip->source_address,
				  sizeof (struct in6_addr) * 2);
  tmp = htons (sizeof (struct GNUNET_TUN_UdpHeader) + payload_length); /* aka udp->len */
  sum = GNUNET_CRYPTO_crc16_step (sum, &tmp, sizeof (uint32_t));
  tmp = htons (ip->next_header);
  sum = GNUNET_CRYPTO_crc16_step (sum, &tmp, sizeof (uint32_t));
  sum = GNUNET_CRYPTO_crc16_step (sum, udp, sizeof (struct GNUNET_TUN_UdpHeader));
  sum = GNUNET_CRYPTO_crc16_step (sum, payload, payload_length);
  udp->crc = GNUNET_CRYPTO_crc16_finish (sum);
}


/**
 * Calculate ICMP checksum.
 *
 * @param icmp IMCP header (initialized except for CRC)
 * @param payload the ICMP payload
 * @param payload_length number of bytes of ICMP payload
 */
void
GNUNET_TUN_calculate_icmp_checksum (struct GNUNET_TUN_IcmpHeader *icmp,
				    const void *payload,
				    uint16_t payload_length)
{
  uint32_t sum;

  GNUNET_assert (8 == sizeof (struct GNUNET_TUN_IcmpHeader));
  icmp->crc = 0;
  sum = GNUNET_CRYPTO_crc16_step (0,
				  icmp,
				  sizeof (struct GNUNET_TUN_IcmpHeader));
  sum = GNUNET_CRYPTO_crc16_step (sum, payload, payload_length);
  icmp->crc = GNUNET_CRYPTO_crc16_finish (sum);
}


/* end of tun.c */
