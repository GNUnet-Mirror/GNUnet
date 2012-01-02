/*
      This file is part of GNUnet
      (C) 2010, 2011, 2012 Christian Grothoff (and other contributing authors)

      GNUnet is free software; you can redistribute it and/or modify
      it under the terms of the GNU General Public License as published
      by the Free Software Foundation; either version 2, or (at your
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
 * @file include/gnunet_dns_service.h
 * @brief API to access the DNS service.  Not finished at all,
 *        currently only contains the structs for the IPC, which
 *        don't even belong here (legacy code in transition)
 * @author Philipp Toelke
 * 
 * TODO:
 * - replace (most?) structs with nice function (prototypes) that take
 *   the appropriate arguments to pass the data
 * - clean up API implementation itself (nicer reconnect, etc.)
 */
#ifndef GNUNET_DNS_SERVICE_H
#define GNUNET_DNS_SERVICE_H

#include "gnunet_common.h"
#include "gnunet_util_lib.h"


/**
 * Subtypes of DNS answers.
 */
enum GNUNET_DNS_ANSWER_Subtype
{
  /**
   * Answers of this type contain a dns-packet that just has to be transmitted
   */
  GNUNET_DNS_ANSWER_TYPE_IP,

  /**
   * Answers of this type contain an incomplete dns-packet. The IP-Address
   * is all 0s. The addroffset points to it.
   */
  GNUNET_DNS_ANSWER_TYPE_SERVICE,

  /**
   * Answers of this type contain an incomplete dns-packet as answer to a
   * PTR-Query. The resolved name is not allocated. The addroffset points to it.
   */
  GNUNET_DNS_ANSWER_TYPE_REV,
  
  /**
   * Answers of this type contains an IP6-Address but traffic to this IP should
   * be routed through the GNUNet.
   */
  GNUNET_DNS_ANSWER_TYPE_REMOTE_AAAA,
  
  /**
   * Answers of this type contains an IP4-Address but traffic to this IP should
   * be routed through the GNUNet.
   */
  GNUNET_DNS_ANSWER_TYPE_REMOTE_A

};


GNUNET_NETWORK_STRUCT_BEGIN
struct GNUNET_vpn_service_descriptor
{
  GNUNET_HashCode peer GNUNET_PACKED;
  GNUNET_HashCode service_descriptor GNUNET_PACKED;
  uint64_t ports GNUNET_PACKED;
  uint32_t service_type GNUNET_PACKED;
};


struct answer_packet
{
  /* General data */
  struct GNUNET_MessageHeader hdr;
  enum GNUNET_DNS_ANSWER_Subtype subtype GNUNET_PACKED;

  char from[16];
  char to[16];
  char addrlen;
  unsigned dst_port:16 GNUNET_PACKED;
  /* -- */

  /* Data for GNUNET_DNS_ANSWER_TYPE_SERVICE */
  struct GNUNET_vpn_service_descriptor service_descr;
  /* -- */

  /* Data for GNUNET_DNS_ANSWER_TYPE_REV */
  /* The offsett in octets from the beginning of the struct to the field
   * in data where the IP-Address has to go. */
  uint16_t addroffset GNUNET_PACKED;
  /* -- */

  /* Data for GNUNET_DNS_ANSWER_TYPE_REMOTE */
  /* either 4 or 16 */
  char addrsize;
  unsigned char addr[16];
  /* -- */

  unsigned char data[1];
};
GNUNET_NETWORK_STRUCT_END


struct answer_packet_list
{
  struct answer_packet_list *next GNUNET_PACKED;
  struct answer_packet_list *prev GNUNET_PACKED;
  struct GNUNET_SERVER_Client *client;
  struct answer_packet pkt;
};


/**
 * Type of a function to be called by the DNS API whenever
 * a DNS reply is obtained.
 *
 * @param cls closure
 * @param pkt reply that we got
 */
typedef void (*GNUNET_DNS_ResponseCallback)(void *cls,
					    const struct answer_packet *pkt);


/**
 * Opaque DNS handle
 */
struct GNUNET_DNS_Handle;


/**
 * Connect to the service-dns
 *
 * @param cfg configuration to use
 * @param cb function to call with DNS replies
 * @param cb_cls closure to pass to cb
 * @return DNS handle 
 */
struct GNUNET_DNS_Handle *
GNUNET_DNS_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
		    GNUNET_DNS_ResponseCallback cb,
		    void *cb_cls);


/**
 * Signal the DNS service that it needs to re-initialize the DNS
 * hijacking (the network setup has changed significantly).
 *
 * @param h DNS handle
 */
void
GNUNET_DNS_restart_hijack (struct GNUNET_DNS_Handle *h);


/**
 * Process a DNS request sent to an IPv4 resolver.  Pass it
 * to the DNS service for resolution.
 *
 * @param h DNS handle
 * @param dst_ip destination IPv4 address
 * @param src_ip source IPv4 address (usually local machine)
 * @param src_port source port (to be used for reply)
 * @param udp_packet_len length of the UDP payload in bytes
 * @param udp_packet UDP payload
 */
void
GNUNET_DNS_queue_request_v4 (struct GNUNET_DNS_Handle *h,
			     const struct in_addr *dst_ip,
			     const struct in_addr *src_ip,
			     uint16_t src_port,
			     size_t udp_packet_len,
			     const char *udp_packet);

/**
 * Process a DNS request sent to an IPv6 resolver.  Pass it
 * to the DNS service for resolution.
 *
 * @param h DNS handle
 * @param dst_ip destination IPv6 address
 * @param src_ip source IPv6 address (usually local machine)
 * @param src_port source port (to be used for reply)
 * @param udp_packet_len length of the UDP payload in bytes
 * @param udp_packet UDP payload
 */
void
GNUNET_DNS_queue_request_v6 (struct GNUNET_DNS_Handle *h,
			     const struct in6_addr *dst_ip,
			     const struct in6_addr *src_ip,
			     uint16_t src_port,
			     size_t udp_packet_len,
			     const char *udp_packet);

/**
 * Disconnect from the DNS service.
 *
 * @param h DNS handle
 */
void
GNUNET_DNS_disconnect (struct GNUNET_DNS_Handle *h);

#endif
