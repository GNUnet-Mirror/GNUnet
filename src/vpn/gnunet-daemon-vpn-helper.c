/*
     This file is part of GNUnet.
     (C) 2010 Christian Grothoff

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
 * @file vpn/gnunet-daemon-vpn-helper.c
 * @brief
 * @author Philipp Toelke
 */
#include <platform.h>
#include <gnunet_common.h>
#include <gnunet_client_lib.h>
#include <gnunet_os_lib.h>
#include <gnunet_mesh_service.h>
#include <gnunet_protocols.h>
#include <gnunet_server_lib.h>
#include <gnunet_container_lib.h>
#include <block_dns.h>
#include <gnunet_configuration_lib.h>

#include "gnunet-daemon-vpn-dns.h"
#include "gnunet-daemon-vpn.h"
#include "gnunet-daemon-vpn-helper.h"
#include "gnunet-service-dns-p.h"
#include "gnunet-vpn-packet.h"
#include "gnunet-vpn-checksum.h"

struct GNUNET_VPN_HELPER_Handle *helper_handle;

/**
 * Start the helper-process
 *
 * If cls != NULL it is assumed that this function is called as a result of a dying
 * helper. cls is then taken as handle to the old helper and is cleaned up.
 * {{{
 */
void
start_helper_and_schedule(void *cls,
			  const struct GNUNET_SCHEDULER_TaskContext *tc) {
    if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
      return;

    if (cls != NULL)
      cleanup_helper(cls);
    cls = NULL;

    char* ifname;
    char* ipv6addr;
    char* ipv6prefix;
    char* ipv4addr;
    char* ipv4mask;

    if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string(cfg, "vpn", "IFNAME", &ifname))
      {
	GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "No entry 'IFNAME' in configuration!\n");
	exit(1);
      }

    if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string(cfg, "vpn", "IPV6ADDR", &ipv6addr))
      {
	GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "No entry 'IPV6ADDR' in configuration!\n");
	exit(1);
      }

    if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string(cfg, "vpn", "IPV6PREFIX", &ipv6prefix))
      {
	GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "No entry 'IPV6PREFIX' in configuration!\n");
	exit(1);
      }

    if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string(cfg, "vpn", "IPV4ADDR", &ipv4addr))
      {
	GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "No entry 'IPV4ADDR' in configuration!\n");
	exit(1);
      }

    if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string(cfg, "vpn", "IPV4MASK", &ipv4mask))
      {
	GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "No entry 'IPV4MASK' in configuration!\n");
	exit(1);
      }

    /* Start the helper
     * Messages get passed to the function message_token
     * When the helper dies, this function will be called again with the
     * helper_handle as cls.
     */
    helper_handle = start_helper(ifname,
				 ipv6addr,
				 ipv6prefix,
				 ipv4addr,
				 ipv4mask,
				 "vpn-gnunet",
				 start_helper_and_schedule,
				 message_token,
				 NULL,
				 NULL);

    GNUNET_free(ipv6addr);
    GNUNET_free(ipv6prefix);
    GNUNET_free(ipv4addr);
    GNUNET_free(ipv4mask);
    GNUNET_free(ifname);

    /* Tell the dns-service to rehijack the dns-port
     * The routing-table gets flushed if an interface disappears.
     */
    restart_hijack = 1;
    GNUNET_CLIENT_notify_transmit_ready(dns_connection, sizeof(struct GNUNET_MessageHeader), GNUNET_TIME_UNIT_FOREVER_REL, GNUNET_YES, &send_query, NULL);
}
/*}}}*/

/**
 * Send an dns-answer-packet to the helper
 */
void
helper_write(void* cls, const struct GNUNET_SCHEDULER_TaskContext* tsdkctx) {
    if (tsdkctx->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN)
      return;

    struct answer_packet_list* ans = answer_proc_head;
    size_t len = ntohs(ans->pkt.hdr.size);

    GNUNET_assert(ans->pkt.subtype == GNUNET_DNS_ANSWER_TYPE_IP);

    GNUNET_assert (20 == sizeof (struct ip_hdr));
    GNUNET_assert (8 == sizeof (struct udp_pkt));
    size_t data_len = len - sizeof(struct answer_packet) + 1;
    size_t net_len = sizeof(struct ip_hdr) + sizeof(struct udp_dns) + data_len;
    size_t pkt_len = sizeof(struct GNUNET_MessageHeader) + sizeof(struct pkt_tun) + net_len;

    struct ip_udp_dns* pkt = alloca(pkt_len);
    GNUNET_assert(pkt != NULL);
    memset(pkt, 0, pkt_len);

    /* set the gnunet-header */
    pkt->shdr.size = htons(pkt_len);
    pkt->shdr.type = htons(GNUNET_MESSAGE_TYPE_VPN_HELPER);

    /* set the tun-header (no flags and ethertype of IPv4) */
    pkt->tun.flags = 0;
    pkt->tun.type = htons(0x0800);

    /* set the ip-header */
    pkt->ip_hdr.version = 4;
    pkt->ip_hdr.hdr_lngth = 5;
    pkt->ip_hdr.diff_serv = 0;
    pkt->ip_hdr.tot_lngth = htons(net_len);
    pkt->ip_hdr.ident = 0;
    pkt->ip_hdr.flags = 0;
    pkt->ip_hdr.frag_off = 0;
    pkt->ip_hdr.ttl = 255;
    pkt->ip_hdr.proto = 0x11; /* UDP */
    pkt->ip_hdr.chks = 0; /* Will be calculated later*/
    pkt->ip_hdr.sadr = ans->pkt.from;
    pkt->ip_hdr.dadr = ans->pkt.to;

    pkt->ip_hdr.chks = calculate_ip_checksum((uint16_t*)&pkt->ip_hdr, 5*4);

    /* set the udp-header */
    pkt->udp_dns.udp_hdr.spt = htons(53);
    pkt->udp_dns.udp_hdr.dpt = ans->pkt.dst_port;
    pkt->udp_dns.udp_hdr.len = htons(net_len - sizeof(struct ip_hdr));
    pkt->udp_dns.udp_hdr.crc = 0; /* Optional for IPv4 */

    memcpy(&pkt->udp_dns.data, ans->pkt.data, data_len);

    GNUNET_CONTAINER_DLL_remove (answer_proc_head, answer_proc_tail, ans);
    GNUNET_free(ans);

    /* FIXME */ GNUNET_DISK_file_write(helper_handle->fh_to_helper, pkt, pkt_len);

    /* if more packets are available, reschedule */
    if (answer_proc_head != NULL)
      GNUNET_SCHEDULER_add_write_file (GNUNET_TIME_UNIT_FOREVER_REL,
				       helper_handle->fh_to_helper,
				       &helper_write,
				       NULL);
}
/**
 * Receive packets from the helper-process
 */
void
message_token(void *cls,
	      void *client,
	      const struct GNUNET_MessageHeader *message) {
    GNUNET_assert(ntohs(message->type) == GNUNET_MESSAGE_TYPE_VPN_HELPER);

    struct tun_pkt *pkt_tun = (struct tun_pkt*) message;

    /* ethertype is ipv6 */
    if (ntohs(pkt_tun->tun.type) == 0x86dd)
      {
	struct ip6_pkt *pkt6 = (struct ip6_pkt*) message;
	GNUNET_assert(pkt6->ip6_hdr.version == 6);
	struct ip6_tcp *pkt6_tcp;
	struct ip6_udp *pkt6_udp;
	struct ip6_icmp *pkt6_icmp;
	GNUNET_HashCode* key;

	switch(pkt6->ip6_hdr.nxthdr)
	  {
	  case 0x06:
	    pkt6_tcp = (struct ip6_tcp*)pkt6;
	    break;
	  case 0x11:
	    pkt6_udp = (struct ip6_udp*)pkt6;
	    if ((key = address_mapping_exists(pkt6->ip6_hdr.dadr)) != NULL)
	      {
		struct map_entry* me = GNUNET_CONTAINER_multihashmap_get(hashmap, key);
		GNUNET_assert(me != NULL);
		GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Mapping exists; type: %d; UDP is %d; port: %x/%x!\n", me->desc.service_type, htonl(GNUNET_DNS_SERVICE_TYPE_UDP), pkt6_udp->udp_hdr.dpt, me->desc.ports);
		GNUNET_free(key);
		if (me->desc.service_type & htonl(GNUNET_DNS_SERVICE_TYPE_UDP) &&
		    (port_in_ports(me->desc.ports, pkt6_udp->udp_hdr.dpt) ||
		     port_in_ports(me->additional_ports, pkt6_udp->udp_hdr.dpt)))
		  {
		    size_t size = sizeof(struct GNUNET_MESH_Tunnel*) + sizeof(struct GNUNET_MessageHeader) + sizeof(GNUNET_HashCode) + ntohs(pkt6_udp->udp_hdr.len);
		    struct GNUNET_MESH_Tunnel **cls = GNUNET_malloc(size);
		    struct GNUNET_MessageHeader *hdr = (struct GNUNET_MessageHeader*)(cls+1);
		    GNUNET_HashCode* hc = (GNUNET_HashCode*)(hdr + 1);

		    memcpy(hc, &me->desc.service_descriptor, sizeof(GNUNET_HashCode));
		    memcpy(hc+1, &pkt6_udp->udp_hdr, ntohs(pkt6_udp->udp_hdr.len));

		    if (me->tunnel == NULL)
		      {
			*cls = GNUNET_MESH_peer_request_connect_all(mesh_handle,
								    GNUNET_TIME_UNIT_FOREVER_REL,
								    1,
								    (struct GNUNET_PeerIdentity*)&me->desc.peer,
								    send_udp_to_peer,
								    NULL,
								    cls);
			me->tunnel = *cls;
		      }
		    else
		      {
			*cls = me->tunnel;
			send_udp_to_peer(cls, (struct GNUNET_PeerIdentity*)1, NULL);
		      }
		    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Queued to send to peer %x\n", *((unsigned int*)&me->desc.peer));
		  }
	      }
	    break;
	  case 0x3a:
	    /* ICMPv6 */
	    pkt6_icmp = (struct ip6_icmp*)pkt6;
	    /* If this packet is an icmp-echo-request and a mapping exists, answer */
	    if (pkt6_icmp->icmp_hdr.type == 0x80 && (key = address_mapping_exists(pkt6->ip6_hdr.dadr)) != NULL)
	      {
		GNUNET_free(key);
		pkt6_icmp = GNUNET_malloc(ntohs(pkt6->shdr.size));
		memcpy(pkt6_icmp, pkt6, ntohs(pkt6->shdr.size));
		GNUNET_SCHEDULER_add_now(&send_icmp_response, pkt6_icmp);
	      }
	    break;
	  }
      }
    /* ethertype is ipv4 */
    else if (ntohs(pkt_tun->tun.type) == 0x0800)
      {
	struct ip_pkt *pkt = (struct ip_pkt*) message;
	struct ip_udp *udp = (struct ip_udp*) message;
	GNUNET_assert(pkt->ip_hdr.version == 4);

	/* Send dns-packets to the service-dns */
	if (pkt->ip_hdr.proto == 0x11 && ntohs(udp->udp_hdr.dpt) == 53 )
	  {
	    /* 9 = 8 for the udp-header + 1 for the unsigned char data[1]; */
	    size_t len = sizeof(struct query_packet) + ntohs(udp->udp_hdr.len) - 9;

	    struct query_packet_list* query = GNUNET_malloc(len + 2*sizeof(struct query_packet_list*));
	    query->pkt.hdr.type = htons(GNUNET_MESSAGE_TYPE_LOCAL_QUERY_DNS);
	    query->pkt.hdr.size = htons(len);
	    query->pkt.orig_to = pkt->ip_hdr.dadr;
	    query->pkt.orig_from = pkt->ip_hdr.sadr;
	    query->pkt.src_port = udp->udp_hdr.spt;
	    memcpy(query->pkt.data, udp->data, ntohs(udp->udp_hdr.len) - 8);

	    GNUNET_CONTAINER_DLL_insert_after(head, tail, tail, query);

	    GNUNET_assert(head != NULL);

	    if (dns_connection != NULL)
	      GNUNET_CLIENT_notify_transmit_ready(dns_connection,
						  len,
						  GNUNET_TIME_UNIT_FOREVER_REL,
						  GNUNET_YES,
						  &send_query,
						  NULL);
	  }
      }
}

void write_to_helper(void* buf, size_t len)
{
  (void)GNUNET_DISK_file_write(helper_handle->fh_to_helper, buf, len);
}

void schedule_helper_write(struct GNUNET_TIME_Relative time, void* cls)
{
  GNUNET_SCHEDULER_add_write_file (time, helper_handle->fh_to_helper, &helper_write, cls);
}
