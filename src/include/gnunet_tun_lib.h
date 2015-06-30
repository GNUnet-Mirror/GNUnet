/*
     This file is part of GNUnet.
     Copyright (C) 2010-2013 Christian Grothoff

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


/**
 * Maximum regex string length for use with #GNUNET_TUN_ipv4toregexsearch.
 *
 * 8 bytes for IPv4, 4 bytes for port, 1 byte for "4", 2 bytes for "-",
 * one byte for 0-termination.
 */
#define GNUNET_TUN_IPV4_REGEXLEN 16


/**
 * Maximum regex string length for use with #GNUNET_TUN_ipv6toregexsearch
 *
 * 32 bytes for IPv4, 4 bytes for port, 1 byte for "4", 2 bytes for "-",
 * one byte for 0-termination.
 */
#define GNUNET_TUN_IPV6_REGEXLEN 40


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Header from Linux TUN interface.
 */
struct GNUNET_TUN_Layer2PacketHeader
{
  /**
   * Some flags (unused).
   */
  uint16_t flags GNUNET_PACKED;

  /**
   * Here we get an ETH_P_-number.
   */
  uint16_t proto GNUNET_PACKED;
};


/**
 * Standard IPv4 header.
 */
struct GNUNET_TUN_IPv4Header
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
  unsigned int header_length:4 GNUNET_PACKED;
  unsigned int version:4 GNUNET_PACKED;
#elif __BYTE_ORDER == __BIG_ENDIAN
  unsigned int version:4 GNUNET_PACKED;
  unsigned int header_length:4 GNUNET_PACKED;
#else
  #error byteorder undefined
#endif
  uint8_t diff_serv;

  /**
   * Length of the packet, including this header.
   */
  uint16_t total_length GNUNET_PACKED;

  /**
   * Unique random ID for matching up fragments.
   */
  uint16_t identification GNUNET_PACKED;

  unsigned int flags:3 GNUNET_PACKED;

  unsigned int fragmentation_offset:13 GNUNET_PACKED;

  /**
   * How many more hops can this packet be forwarded?
   */
  uint8_t ttl;

  /**
   * L4-protocol, for example, IPPROTO_UDP or IPPROTO_TCP.
   */
  uint8_t protocol;

  /**
   * Checksum.
   */
  uint16_t checksum GNUNET_PACKED;

  /**
   * Origin of the packet.
   */
  struct in_addr source_address GNUNET_PACKED;

  /**
   * Destination of the packet.
   */
  struct in_addr destination_address GNUNET_PACKED;
} GNUNET_GCC_STRUCT_LAYOUT;


/**
 * Standard IPv6 header.
 */
struct GNUNET_TUN_IPv6Header
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
  unsigned int traffic_class_h:4 GNUNET_PACKED;
  unsigned int version:4 GNUNET_PACKED;
  unsigned int traffic_class_l:4 GNUNET_PACKED;
  unsigned int flow_label:20 GNUNET_PACKED;
#elif __BYTE_ORDER == __BIG_ENDIAN
  unsigned int version:4 GNUNET_PACKED;
  unsigned int traffic_class:8 GNUNET_PACKED;
  unsigned int flow_label:20 GNUNET_PACKED;
#else
  #error byteorder undefined
#endif
  /**
   * Length of the payload, excluding this header.
   */
  uint16_t payload_length GNUNET_PACKED;

  /**
   * For example, IPPROTO_UDP or IPPROTO_TCP.
   */
  uint8_t next_header;

  /**
   * How many more hops can this packet be forwarded?
   */
  uint8_t hop_limit;

  /**
   * Origin of the packet.
   */
  struct in6_addr source_address GNUNET_PACKED;

  /**
   * Destination of the packet.
   */
  struct in6_addr destination_address GNUNET_PACKED;
} GNUNET_GCC_STRUCT_LAYOUT;


/**
 * TCP flags.
 */
#define GNUNET_TUN_TCP_FLAGS_FIN 1
#define GNUNET_TUN_TCP_FLAGS_SYN 2
#define GNUNET_TUN_TCP_FLAGS_RST 4
#define GNUNET_TUN_TCP_FLAGS_PSH 8
#define GNUNET_TUN_TCP_FLAGS_ACK 16
#define GNUNET_TUN_TCP_FLAGS_URG 32
#define GNUNET_TUN_TCP_FLAGS_ECE 64
#define GNUNET_TUN_TCP_FLAGS_CWR 128

/**
 * TCP packet header.
 */
struct GNUNET_TUN_TcpHeader
{
  /**
   * Source port (in NBO).
   */
  uint16_t source_port GNUNET_PACKED;

  /**
   * Destination port (in NBO).
   */
  uint16_t destination_port GNUNET_PACKED;

  /**
   * Sequence number.
   */
  uint32_t seq GNUNET_PACKED;

  /**
   * Acknowledgement number.
   */
  uint32_t ack GNUNET_PACKED;
#if __BYTE_ORDER == __LITTLE_ENDIAN
  /**
   * Reserved.  Must be zero.
   */
  unsigned int reserved : 4 GNUNET_PACKED;
  /**
   * Number of 32-bit words in TCP header.
   */
  unsigned int off : 4 GNUNET_PACKED;
#elif __BYTE_ORDER == __BIG_ENDIAN
  /**
   * Number of 32-bit words in TCP header.
   */
  unsigned int off : 4 GNUNET_PACKED;
  /**
   * Reserved.  Must be zero.
   */
  unsigned int reserved : 4 GNUNET_PACKED;
#else
  #error byteorder undefined
#endif

  /**
   * Flags (SYN, FIN, ACK, etc.)
   */
  uint8_t flags;

  /**
   * Window size.
   */
  uint16_t window_size GNUNET_PACKED;

  /**
   * Checksum.
   */
  uint16_t crc GNUNET_PACKED;

  /**
   * Urgent pointer.
   */
  uint16_t urgent_pointer GNUNET_PACKED;
} GNUNET_GCC_STRUCT_LAYOUT;


/**
 * UDP packet header.
 */
struct GNUNET_TUN_UdpHeader
{
  /**
   * Source port (in NBO).
   */
  uint16_t source_port GNUNET_PACKED;

  /**
   * Destination port (in NBO).
   */
  uint16_t destination_port GNUNET_PACKED;

  /**
   * Number of bytes of payload.
   */
  uint16_t len GNUNET_PACKED;

  /**
   * Checksum.
   */
  uint16_t crc GNUNET_PACKED;
};



/**
 * A few common DNS classes (ok, only one is common, but I list a
 * couple more to make it clear what we're talking about here).
 */
#define GNUNET_TUN_DNS_CLASS_INTERNET 1
#define GNUNET_TUN_DNS_CLASS_CHAOS 3
#define GNUNET_TUN_DNS_CLASS_HESIOD 4

#define GNUNET_TUN_DNS_OPCODE_QUERY 0
#define GNUNET_TUN_DNS_OPCODE_INVERSE_QUERY 1
#define GNUNET_TUN_DNS_OPCODE_STATUS 2


/**
 * RFC 1035 codes.
 */
#define GNUNET_TUN_DNS_RETURN_CODE_NO_ERROR 0
#define GNUNET_TUN_DNS_RETURN_CODE_FORMAT_ERROR 1
#define GNUNET_TUN_DNS_RETURN_CODE_SERVER_FAILURE 2
#define GNUNET_TUN_DNS_RETURN_CODE_NAME_ERROR 3
#define GNUNET_TUN_DNS_RETURN_CODE_NOT_IMPLEMENTED 4
#define GNUNET_TUN_DNS_RETURN_CODE_REFUSED 5

/**
 * RFC 2136 codes
 */
#define GNUNET_TUN_DNS_RETURN_CODE_YXDOMAIN 6
#define GNUNET_TUN_DNS_RETURN_CODE_YXRRSET 7
#define GNUNET_TUN_DNS_RETURN_CODE_NXRRSET 8
#define GNUNET_TUN_DNS_RETURN_CODE_NOT_AUTH 9
#define GNUNET_TUN_DNS_RETURN_CODE_NOT_ZONE 10


/**
 * DNS flags (largely RFC 1035 / RFC 2136).
 */
struct GNUNET_TUN_DnsFlags
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
  /**
   * Set to 1 if recursion is desired (client -> server)
   */
  unsigned int recursion_desired    : 1 GNUNET_PACKED;

  /**
   * Set to 1 if message is truncated
   */
  unsigned int message_truncated    : 1 GNUNET_PACKED;

  /**
   * Set to 1 if this is an authoritative answer
   */
  unsigned int authoritative_answer : 1 GNUNET_PACKED;

  /**
   * See GNUNET_TUN_DNS_OPCODE_ defines.
   */
  unsigned int opcode               : 4 GNUNET_PACKED;

  /**
   * query:0, response:1
   */
  unsigned int query_or_response    : 1 GNUNET_PACKED;

  /**
   * See GNUNET_TUN_DNS_RETURN_CODE_ defines.
   */
  unsigned int return_code          : 4 GNUNET_PACKED;

  /**
   * See RFC 4035.
   */
  unsigned int checking_disabled    : 1 GNUNET_PACKED;

  /**
   * Response has been cryptographically verified, RFC 4035.
   */
  unsigned int authenticated_data   : 1 GNUNET_PACKED;

  /**
   * Always zero.
   */
  unsigned int zero                 : 1 GNUNET_PACKED;

  /**
   * Set to 1 if recursion is available (server -> client)
   */
  unsigned int recursion_available  : 1 GNUNET_PACKED;
#elif __BYTE_ORDER == __BIG_ENDIAN

  /**
   * query:0, response:1
   */
  unsigned int query_or_response    : 1 GNUNET_PACKED;

  /**
   * See GNUNET_TUN_DNS_OPCODE_ defines.
   */
  unsigned int opcode               : 4 GNUNET_PACKED;

  /**
   * Set to 1 if this is an authoritative answer
   */
  unsigned int authoritative_answer : 1 GNUNET_PACKED;

  /**
   * Set to 1 if message is truncated
   */
  unsigned int message_truncated    : 1 GNUNET_PACKED;

  /**
   * Set to 1 if recursion is desired (client -> server)
   */
  unsigned int recursion_desired    : 1 GNUNET_PACKED;


  /**
   * Set to 1 if recursion is available (server -> client)
   */
  unsigned int recursion_available  : 1 GNUNET_PACKED;

  /**
   * Always zero.
   */
  unsigned int zero                 : 1 GNUNET_PACKED;

  /**
   * Response has been cryptographically verified, RFC 4035.
   */
  unsigned int authenticated_data   : 1 GNUNET_PACKED;

  /**
   * See RFC 4035.
   */
  unsigned int checking_disabled    : 1 GNUNET_PACKED;

  /**
   * See GNUNET_TUN_DNS_RETURN_CODE_ defines.
   */
  unsigned int return_code          : 4 GNUNET_PACKED;
#else
  #error byteorder undefined
#endif

} GNUNET_GCC_STRUCT_LAYOUT;



/**
 * DNS header.
 */
struct GNUNET_TUN_DnsHeader
{
  /**
   * Unique identifier for the request/response.
   */
  uint16_t id GNUNET_PACKED;

  /**
   * Flags.
   */
  struct GNUNET_TUN_DnsFlags flags;

  /**
   * Number of queries.
   */
  uint16_t query_count GNUNET_PACKED;

  /**
   * Number of answers.
   */
  uint16_t answer_rcount GNUNET_PACKED;

  /**
   * Number of authoritative answers.
   */
  uint16_t authority_rcount GNUNET_PACKED;

  /**
   * Number of additional records.
   */
  uint16_t additional_rcount GNUNET_PACKED;
};


/**
 * Payload of DNS SOA record (header).
 */
struct GNUNET_TUN_DnsSoaRecord
{
  /**
   * The version number of the original copy of the zone.   (NBO)
   */
  uint32_t serial GNUNET_PACKED;

  /**
   * Time interval before the zone should be refreshed. (NBO)
   */
  uint32_t refresh GNUNET_PACKED;

  /**
   * Time interval that should elapse before a failed refresh should
   * be retried. (NBO)
   */
  uint32_t retry GNUNET_PACKED;

  /**
   * Time value that specifies the upper limit on the time interval
   * that can elapse before the zone is no longer authoritative. (NBO)
   */
  uint32_t expire GNUNET_PACKED;

  /**
   * The bit minimum TTL field that should be exported with any RR
   * from this zone. (NBO)
   */
  uint32_t minimum GNUNET_PACKED;
};


/**
 * Payload of DNS SRV record (header).
 */
struct GNUNET_TUN_DnsSrvRecord
{

  /**
   * Preference for this entry (lower value is higher preference).  Clients
   * will contact hosts from the lowest-priority group first and fall back
   * to higher priorities if the low-priority entries are unavailable. (NBO)
   */
  uint16_t prio GNUNET_PACKED;

  /**
   * Relative weight for records with the same priority.  Clients will use
   * the hosts of the same (lowest) priority with a probability proportional
   * to the weight given. (NBO)
   */
  uint16_t weight GNUNET_PACKED;

  /**
   * TCP or UDP port of the service. (NBO)
   */
  uint16_t port GNUNET_PACKED;

  /* followed by 'target' name */
};


/**
 * Payload of DNS CERT record.
 */
struct GNUNET_TUN_DnsCertRecord
{

  /**
   * Certificate type
   */
  uint16_t cert_type;

  /**
   * Certificate KeyTag
   */
  uint16_t cert_tag;

  /**
   * Algorithm
   */
  uint8_t algorithm;

  /* Followed by the certificate */
};


/**
 * Payload of DNSSEC TLSA record.
 * http://datatracker.ietf.org/doc/draft-ietf-dane-protocol/
 */
struct GNUNET_TUN_DnsTlsaRecord
{

  /**
   * Certificate usage
   * 0: CA cert
   * 1: Entity cert
   * 2: Trust anchor
   * 3: domain-issued cert
   */
  uint8_t usage;

  /**
   * Selector
   * What part will be matched against the cert
   * presented by server
   * 0: Full cert (in binary)
   * 1: Full cert (in DER)
   */
  uint8_t selector;

  /**
   * Matching type (of selected content)
   * 0: exact match
   * 1: SHA-256 hash
   * 2: SHA-512 hash
   */
  uint8_t matching_type;

  /**
   * followed by certificate association data
   * The "certificate association data" to be matched.
   * These bytes are either raw data (that is, the full certificate or
   * its SubjectPublicKeyInfo, depending on the selector) for matching
   * type 0, or the hash of the raw data for matching types 1 and 2.
   * The data refers to the certificate in the association, not to the
   * TLS ASN.1 Certificate object.
   *
   * The data is represented as a string of hex chars
   */
};


/**
 * Payload of GNS VPN record
 */
struct GNUNET_TUN_GnsVpnRecord
{
  /**
   * The peer to contact
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * The protocol to use
   */
  uint16_t proto;

  /* followed by the servicename */
};


/**
 * DNS query prefix.
 */
struct GNUNET_TUN_DnsQueryLine
{
  /**
   * Desired type (GNUNET_DNSPARSER_TYPE_XXX). (NBO)
   */
  uint16_t type GNUNET_PACKED;

  /**
   * Desired class (usually GNUNET_TUN_DNS_CLASS_INTERNET). (NBO)
   */
  uint16_t dns_traffic_class GNUNET_PACKED;
};


/**
 * General DNS record prefix.
 */
struct GNUNET_TUN_DnsRecordLine
{
  /**
   * Record type (GNUNET_DNSPARSER_TYPE_XXX). (NBO)
   */
  uint16_t type GNUNET_PACKED;

  /**
   * Record class (usually GNUNET_TUN_DNS_CLASS_INTERNET). (NBO)
   */
  uint16_t dns_traffic_class GNUNET_PACKED;

  /**
   * Expiration for the record (in seconds). (NBO)
   */
  uint32_t ttl GNUNET_PACKED;

  /**
   * Number of bytes of data that follow. (NBO)
   */
  uint16_t data_len GNUNET_PACKED;
};


#define	GNUNET_TUN_ICMPTYPE_ECHO_REPLY 0
#define	GNUNET_TUN_ICMPTYPE_DESTINATION_UNREACHABLE 3
#define	GNUNET_TUN_ICMPTYPE_SOURCE_QUENCH 4
#define	GNUNET_TUN_ICMPTYPE_REDIRECT_MESSAGE 5
#define	GNUNET_TUN_ICMPTYPE_ECHO_REQUEST 8
#define	GNUNET_TUN_ICMPTYPE_ROUTER_ADVERTISEMENT 9
#define	GNUNET_TUN_ICMPTYPE_ROUTER_SOLICITATION 10
#define	GNUNET_TUN_ICMPTYPE_TIME_EXCEEDED 11

#define	GNUNET_TUN_ICMPTYPE6_DESTINATION_UNREACHABLE 1
#define	GNUNET_TUN_ICMPTYPE6_PACKET_TOO_BIG 2
#define	GNUNET_TUN_ICMPTYPE6_TIME_EXCEEDED 3
#define	GNUNET_TUN_ICMPTYPE6_PARAMETER_PROBLEM 4
#define	GNUNET_TUN_ICMPTYPE6_ECHO_REQUEST 128
#define	GNUNET_TUN_ICMPTYPE6_ECHO_REPLY 129


/**
 * ICMP header.
 */
struct GNUNET_TUN_IcmpHeader
{
  uint8_t type;
  uint8_t code;
  uint16_t crc GNUNET_PACKED;

  union
  {
    /**
     * ICMP Echo (request/reply)
     */
    struct
    {
      uint16_t	identifier GNUNET_PACKED;
      uint16_t	sequence_number GNUNET_PACKED;
    } echo;

    /**
     * ICMP Destination Unreachable (RFC 1191)
     */
    struct ih_pmtu
    {
      uint16_t empty GNUNET_PACKED;
      uint16_t next_hop_mtu GNUNET_PACKED;
      /* followed by original IP header + first 8 bytes of original IP datagram */
    } destination_unreachable;

    /**
     * ICMP Redirect
     */
    struct in_addr redirect_gateway_address GNUNET_PACKED;

    /**
     * MTU for packets that are too big (IPv6).
     */
    uint32_t packet_too_big_mtu GNUNET_PACKED;

  } quench;

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

/**
 * Calculate IPv4 TCP checksum.
 *
 * @param ip ipv4 header fully initialized
 * @param tcp TCP header (initialized except for CRC)
 * @param payload the TCP payload
 * @param payload_length number of bytes of TCP @a payload
 */
void
GNUNET_TUN_calculate_tcp4_checksum (const struct GNUNET_TUN_IPv4Header *ip,
				    struct GNUNET_TUN_TcpHeader *tcp,
				    const void *payload,
				    uint16_t payload_length);

/**
 * Calculate IPv6 TCP checksum.
 *
 * @param ip ipv6 header fully initialized
 * @param tcp TCP header (initialized except for CRC)
 * @param payload the TCP payload
 * @param payload_length number of bytes of TCP payload
 */
void
GNUNET_TUN_calculate_tcp6_checksum (const struct GNUNET_TUN_IPv6Header *ip,
				    struct GNUNET_TUN_TcpHeader *tcp,
				    const void *payload,
				    uint16_t payload_length);

/**
 * Calculate IPv4 UDP checksum.
 *
 * @param ip ipv4 header fully initialized
 * @param udp UDP header (initialized except for CRC)
 * @param payload the UDP payload
 * @param payload_length number of bytes of UDP @a payload
 */
void
GNUNET_TUN_calculate_udp4_checksum (const struct GNUNET_TUN_IPv4Header *ip,
				    struct GNUNET_TUN_UdpHeader *udp,
				    const void *payload,
				    uint16_t payload_length);


/**
 * Calculate IPv6 UDP checksum.
 *
 * @param ip ipv6 header fully initialized
 * @param udp UDP header (initialized except for CRC)
 * @param payload the UDP payload
 * @param payload_length number of bytes of @a payload
 */
void
GNUNET_TUN_calculate_udp6_checksum (const struct GNUNET_TUN_IPv6Header *ip,
				    struct GNUNET_TUN_UdpHeader *udp,
				    const void *payload,
				    uint16_t payload_length);


/**
 * Calculate ICMP checksum.
 *
 * @param icmp IMCP header (initialized except for CRC)
 * @param payload the ICMP payload
 * @param payload_length number of bytes of @a payload
 */
void
GNUNET_TUN_calculate_icmp_checksum (struct GNUNET_TUN_IcmpHeader *icmp,
				    const void *payload,
				    uint16_t payload_length);


/**
 * Create a regex in @a rxstr from the given @a ip and @a port.
 *
 * @param ip IPv4 representation.
 * @param port destination port
 * @param rxstr generated regex, must be at least #GNUNET_TUN_IPV4_REGEXLEN
 *              bytes long.
 */
void
GNUNET_TUN_ipv4toregexsearch (const struct in_addr *ip,
                              uint16_t port,
                              char *rxstr);


/**
 * Create a regex in @a rxstr from the given @a ipv6 and @a port.
 *
 * @param ipv6 IPv6 representation.
 * @param port destination port
 * @param rxstr generated regex, must be at least #GNUNET_TUN_IPV6_REGEXLEN
 *              bytes long.
 */
void
GNUNET_TUN_ipv6toregexsearch (const struct in6_addr *ipv6,
                              uint16_t port,
                              char *rxstr);


/**
 * Convert an exit policy to a regular expression.  The exit policy
 * specifies a set of subnets this peer is willing to serve as an
 * exit for; the resulting regular expression will match the
 * IPv6 address strings as returned by #GNUNET_TUN_ipv6toregexsearch.
 *
 * @param policy exit policy specification
 * @return regular expression, NULL on error
 */
char *
GNUNET_TUN_ipv6policy2regex (const char *policy);


/**
 * Convert an exit policy to a regular expression.  The exit policy
 * specifies a set of subnets this peer is willing to serve as an
 * exit for; the resulting regular expression will match the
 * IPv4 address strings as returned by #GNUNET_TUN_ipv4toregexsearch.
 *
 * @param policy exit policy specification
 * @return regular expression, NULL on error
 */
char *
GNUNET_TUN_ipv4policy2regex (const char *policy);


/**
 * Hash the service name of a hosted service to the
 * hash code that is used to identify the service on
 * the network.
 *
 * @param service_name a string
 * @param hc corresponding hash
 */
void
GNUNET_TUN_service_name_to_hash (const char *service_name,
                                 struct GNUNET_HashCode *hc);

#endif
