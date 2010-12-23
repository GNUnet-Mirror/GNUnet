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
 * @file vpn/gnunet-daemon-vpn.c
 * @brief 
 * @author Philipp Toelke
 */
#include "platform.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet-vpn-helper-p.h"
#include "gnunet-vpn-packet.h"
#include "gnunet-vpn-pretty-print.h"
#include "gnunet_common.h"
#include "gnunet_protocols.h"
#include "gnunet_server_lib.h"
#include "gnunet-service-dns-p.h"
#include "gnunet_core_service.h"
#include "gnunet_client_lib.h"
#include "gnunet_container_lib.h"
#include "block_dns.h"
#include "gnunet_constants.h"

/**
 * Final status code.
 */
static int ret;

/**
 * The configuration to use
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * PipeHandle to receive data from the helper
 */
static struct GNUNET_DISK_PipeHandle* helper_in;

/**
 * PipeHandle to send data to the helper
 */
static struct GNUNET_DISK_PipeHandle* helper_out;

/**
 * FileHandle to receive data from the helper
 */
static const struct GNUNET_DISK_FileHandle* fh_from_helper;

/**
 * FileHandle to send data to the helper
 */
static const struct GNUNET_DISK_FileHandle* fh_to_helper;

/**
 * The Message-Tokenizer that tokenizes the messages comming from the helper
 */
static struct GNUNET_SERVER_MessageStreamTokenizer* mst;

/**
 * The connection to the service-dns
 */
static struct GNUNET_CLIENT_Connection *dns_connection;

/**
 * A flag to show that the service-dns has to rehijack the outbound dns-packets
 *
 * This gets set when the helper restarts as the routing-tables are flushed when
 * the interface vanishes.
 */
static unsigned char restart_hijack;

/**
 * The process id of the helper
 */
static struct GNUNET_OS_Process *helper_proc;

/**
 * a list of outgoing dns-query-packets
 */
static struct query_packet_list *head;

/**
 * The last element of the list of outgoing dns-query-packets
 */
static struct query_packet_list *tail;

/**
 * A list of processed dns-responses.
 *
 * "processed" means that the packet is complete and can be sent out via udp
 * directly
 */
static struct answer_packet_list *answer_proc_head;

/**
 * The last element of the list of processed dns-responses.
 */
static struct answer_packet_list *answer_proc_tail;

/**
 * The hashmap containing the mappings from ipv6-addresses to gnunet-descriptors
 */
static struct GNUNET_CONTAINER_MultiHashMap* hashmap;

/**
 * This hashmap contains the mapping from peer, service-descriptor,
 * source-port and destination-port to a socket
 */
static struct GNUNET_CONTAINER_MultiHashMap *udp_connections;

/**
 * The handle to core
 */
static struct GNUNET_CORE_Handle *core_handle;

struct map_entry {
    struct GNUNET_vpn_service_descriptor desc;
    uint16_t namelen;
    uint64_t additional_ports;
    /**
     * In DNS-Format!
     */
    char name[1];
};

static void helper_read(void* cls, const struct GNUNET_SCHEDULER_TaskContext* tsdkctx);
static void dns_answer_handler(void* cls, const struct GNUNET_MessageHeader *msg);

/**
 * Callback called by notify_transmit_ready; sends dns-queries or rehijack-messages
 * to the service-dns
 * {{{
 */
static size_t
send_query(void* cls, size_t size, void* buf) {
    size_t len;
    /*
     * Send the rehijack-message
     */
    if (restart_hijack == 1)
      {
	restart_hijack = 0;
	/*
	 * The message is just a header
	 */
	GNUNET_assert(sizeof(struct GNUNET_MessageHeader) <= size);
	struct GNUNET_MessageHeader* hdr = buf;
	len = sizeof(struct GNUNET_MessageHeader);
	hdr->size = htons(len);
	hdr->type = htons(GNUNET_MESSAGE_TYPE_REHIJACK);
      }
    else
      {
	struct query_packet_list* query = head;
	len = ntohs(query->pkt.hdr.size);

	GNUNET_assert(len <= size);

	memcpy(buf, &query->pkt.hdr, len);

	GNUNET_CONTAINER_DLL_remove (head, tail, query);

	GNUNET_free(query);
      }

    /*
     * Check whether more data is to be sent
     */
    if (head != NULL)
      {
	GNUNET_CLIENT_notify_transmit_ready(dns_connection, ntohs(head->pkt.hdr.size), GNUNET_TIME_UNIT_FOREVER_REL, GNUNET_YES, &send_query, NULL);
      }
    else if (restart_hijack == 1)
      {
	GNUNET_CLIENT_notify_transmit_ready(dns_connection, sizeof(struct GNUNET_MessageHeader), GNUNET_TIME_UNIT_FOREVER_REL, GNUNET_YES, &send_query, NULL);
      }

    return len;
}
/* }}} */

/**
 * Function scheduled as very last function, cleans up after us
 *{{{
 */
static void
cleanup(void* cls, const struct GNUNET_SCHEDULER_TaskContext* tskctx) {
    GNUNET_assert (0 != (tskctx->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN));

    /* stop the helper */
    if (helper_proc != NULL)
      {
	GNUNET_OS_process_kill (helper_proc, SIGTERM);
	GNUNET_OS_process_wait (helper_proc);
	GNUNET_OS_process_close (helper_proc);
	helper_proc = NULL;
      }

    /* close the connection to the service-dns */
    if (dns_connection != NULL)
      {
	GNUNET_CLIENT_disconnect (dns_connection, GNUNET_NO);
	dns_connection = NULL;
      }

    if (core_handle != NULL)
      {
	GNUNET_CORE_disconnect(core_handle);
	core_handle = NULL;
      }
}
/*}}}*/

/**
 * Start the helper-process
 * {{{
 */
static void
start_helper_and_schedule(void *cls,
			  const struct GNUNET_SCHEDULER_TaskContext *tc) {
    if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
      return;

    helper_in = GNUNET_DISK_pipe (GNUNET_YES, GNUNET_YES, GNUNET_NO);
    helper_out = GNUNET_DISK_pipe (GNUNET_YES, GNUNET_NO, GNUNET_YES);

    if (helper_in == NULL || helper_out == NULL) return;

    helper_proc = GNUNET_OS_start_process(helper_in, helper_out, "gnunet-helper-vpn", "gnunet-helper-vpn", NULL);

    fh_from_helper = GNUNET_DISK_pipe_handle (helper_out, GNUNET_DISK_PIPE_END_READ);
    fh_to_helper = GNUNET_DISK_pipe_handle (helper_in, GNUNET_DISK_PIPE_END_WRITE);

    GNUNET_DISK_pipe_close_end(helper_out, GNUNET_DISK_PIPE_END_WRITE);
    GNUNET_DISK_pipe_close_end(helper_in, GNUNET_DISK_PIPE_END_READ);

    /* Tell the dns-service to rehijack the dns-port
     * The routing-table gets flushed if an interface disappears.
     */
    restart_hijack = 1;
    GNUNET_CLIENT_notify_transmit_ready(dns_connection, sizeof(struct GNUNET_MessageHeader), GNUNET_TIME_UNIT_FOREVER_REL, GNUNET_YES, &send_query, NULL);

    GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL, fh_from_helper, &helper_read, NULL);
}
/*}}}*/

/**
 * Restart the helper-process
 * {{{
 */
static void
restart_helper(void* cls, const struct GNUNET_SCHEDULER_TaskContext* tskctx) {
    // Kill the helper
    GNUNET_OS_process_kill (helper_proc, SIGKILL);
    GNUNET_OS_process_wait (helper_proc);
    GNUNET_OS_process_close (helper_proc);
    helper_proc = NULL;

    GNUNET_DISK_pipe_close(helper_in);
    GNUNET_DISK_pipe_close(helper_out);

    /* Restart the helper */
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, start_helper_and_schedule, NULL);
}
/*}}}*/

/**
 * Read from the helper-process
 * {{{
 */
static void
helper_read(void* cls, const struct GNUNET_SCHEDULER_TaskContext* tsdkctx) {
    /* no message can be bigger then 64k */
    char buf[65535];

    if (tsdkctx->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN)
      return;

    int t = GNUNET_DISK_file_read(fh_from_helper, &buf, 65535);

    /* On read-error, restart the helper */
    if (t<=0) {
	GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Read error for header from vpn-helper: %m\n");
	GNUNET_SCHEDULER_add_now(restart_helper, cls);
	return;
    }

    /* FIXME */ GNUNET_SERVER_mst_receive(mst, NULL, buf, t, 0, 0);

    GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL, fh_from_helper, &helper_read, NULL);
}
/*}}}*/

static uint32_t calculate_checksum_update(uint32_t sum, uint16_t *hdr, short len) {
    for(; len >= 2; len -= 2)
      sum += *(hdr++);
    if (len == 1)
      sum += *((unsigned char*)hdr);
    return sum;
}

static uint16_t calculate_checksum_end(uint32_t sum) {
    while (sum >> 16)
      sum = (sum >> 16) + (sum & 0xFFFF);

    return ~sum;
}

/**
 * Calculate the checksum of an IPv4-Header
 */
static uint16_t
calculate_ip_checksum(uint16_t* hdr, short len) {
    uint32_t sum = calculate_checksum_update(0, hdr, len);
    return calculate_checksum_end(sum);
}

/**
 * Send an dns-answer-packet to the helper
 */
static void
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

    /* FIXME */ GNUNET_DISK_file_write(fh_to_helper, pkt, pkt_len);

    /* if more packets are available, reschedule */
    if (answer_proc_head != NULL)
      GNUNET_SCHEDULER_add_write_file (GNUNET_TIME_UNIT_FOREVER_REL,
				       fh_to_helper,
				       &helper_write,
				       NULL);
}

/**
 * @return the hash of the IP-Address if a mapping exists, NULL otherwise
 */
static GNUNET_HashCode*
address_mapping_exists(unsigned char addr[]) {
    GNUNET_HashCode* key = GNUNET_malloc(sizeof(GNUNET_HashCode));
    unsigned char* k = (unsigned char*)key;
    memset(key, 0, sizeof(GNUNET_HashCode));
    unsigned int i;
    for (i = 0; i < 16; i++)
	k[15-i] = addr[i];

    if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains(hashmap, key))
      return key;
    else
      {
	GNUNET_free(key);
	return NULL;
      }
}

static void
send_icmp_response(void* cls, const struct GNUNET_SCHEDULER_TaskContext *tc) {
    struct ip6_icmp* request = cls;

    struct ip6_icmp* response = alloca(ntohs(request->shdr.size));
    memset(response, 0, ntohs(request->shdr.size));

    response->shdr.size = request->shdr.size;
    response->shdr.type = htons(GNUNET_MESSAGE_TYPE_VPN_HELPER);

    response->tun.flags = 0;
    response->tun.type = htons(0x86dd);

    response->ip6_hdr.hoplmt = 255;
    response->ip6_hdr.paylgth = request->ip6_hdr.paylgth;
    response->ip6_hdr.nxthdr = 0x3a;
    response->ip6_hdr.version = 6;
    memcpy(&response->ip6_hdr.sadr, &request->ip6_hdr.dadr, 16);
    memcpy(&response->ip6_hdr.dadr, &request->ip6_hdr.sadr, 16);

    response->icmp_hdr.code = 0;
    response->icmp_hdr.type = 0x81;

    /* Magic, more Magic! */
    response->icmp_hdr.chks = request->icmp_hdr.chks - 0x1;

    /* Copy the rest of the packet */
    memcpy(response+1, request+1, ntohs(request->shdr.size) - sizeof(struct ip6_icmp));

    /* FIXME */ GNUNET_DISK_file_write(fh_to_helper, response, ntohs(response->shdr.size));

    GNUNET_free(request);
}

/**
 * cls is the pointer to a GNUNET_MessageHeader that is
 * followed by the service-descriptor and the udp-packet that should be sent;
 */
static size_t
handle_udp (void *cls, size_t size, void *buf)
{
  struct GNUNET_PeerIdentity *peer = cls;
  struct GNUNET_MessageHeader *hdr =
    (struct GNUNET_MessageHeader *) (peer + 1);
  GNUNET_HashCode *hc = (GNUNET_HashCode *) (hdr + 1);
  struct udp_pkt *udp = (struct udp_pkt *) (hc + 1);
  hdr->size = htons (sizeof (struct GNUNET_MessageHeader) +
		     sizeof (GNUNET_HashCode) + ntohs (udp->len));
  hdr->type = ntohs (GNUNET_MESSAGE_TYPE_SERVICE_UDP);
  GNUNET_assert (size >= ntohs (hdr->size));
  memcpy (buf, hdr, ntohs (hdr->size));
  size = ntohs(hdr->size);
  GNUNET_free (cls);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sent!\n");
  return size;
}

static unsigned int
port_in_ports (uint64_t ports, uint16_t port)
{
  uint16_t *ps = (uint16_t *) & ports;
  return ps[0] == port || ps[1] == port || ps[2] == port || ps[3] == port;
}

void
send_udp (void *cls, 
	  int success)
{
  struct GNUNET_PeerIdentity *peer = cls;
  struct GNUNET_MessageHeader *hdr =
    (struct GNUNET_MessageHeader *) (peer + 1);
  GNUNET_HashCode *hc = (GNUNET_HashCode *) (hdr + 1);
  struct udp_pkt *udp = (struct udp_pkt *) (hc + 1);
  GNUNET_CORE_notify_transmit_ready (core_handle,
				     42,
				     GNUNET_TIME_relative_divide(GNUNET_CONSTANTS_MAX_CORK_DELAY, 2),
				     peer,
				     htons (sizeof
					    (struct GNUNET_MessageHeader) +
					    sizeof (GNUNET_HashCode) +
					    ntohs (udp->len)), handle_udp,
				     cls);
}

/**
 * Receive packets from the helper-process
 */
static void
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
	    pkt_printf_ip6tcp(pkt6_tcp);
	    break;
	  case 0x11:
	    pkt6_udp = (struct ip6_udp*)pkt6;
	    if ((key = address_mapping_exists(pkt6->ip6_hdr.dadr)) != NULL)
	      {
		struct map_entry* me = GNUNET_CONTAINER_multihashmap_get(hashmap, key);
		GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Mapping exists; type: %d; UDP is %d; port: %x/%x!\n", me->desc.service_type, htonl(GNUNET_DNS_SERVICE_TYPE_UDP), pkt6_udp->udp_hdr.dpt, me->desc.ports);
		GNUNET_free(key);
		if (me->desc.service_type & htonl(GNUNET_DNS_SERVICE_TYPE_UDP) &&
		    (port_in_ports(me->desc.ports, pkt6_udp->udp_hdr.dpt) ||
		     port_in_ports(me->additional_ports, pkt6_udp->udp_hdr.dpt)))
		  {
		    size_t size = sizeof(struct GNUNET_PeerIdentity) + sizeof(struct GNUNET_MessageHeader) + sizeof(GNUNET_HashCode) + ntohs(pkt6_udp->udp_hdr.len);
		    struct GNUNET_PeerIdentity *cls = GNUNET_malloc(size);
		    struct GNUNET_MessageHeader *hdr = (struct GNUNET_MessageHeader*)(cls+1);
		    GNUNET_HashCode* hc = (GNUNET_HashCode*)(hdr + 1);
		    memcpy(cls, &me->desc.peer, sizeof(struct GNUNET_PeerIdentity));
		    memcpy(hc, &me->desc.service_descriptor, sizeof(GNUNET_HashCode));
		    memcpy(hc+1, &pkt6_udp->udp_hdr, ntohs(pkt6_udp->udp_hdr.len));
		    GNUNET_CORE_peer_request_connect(core_handle,
					GNUNET_TIME_UNIT_FOREVER_REL,
					(struct GNUNET_PeerIdentity*)&me->desc.peer,
					send_udp,
					cls);
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

/**
 * Connect to the service-dns
 */
static void
connect_to_service_dns (void *cls,
			const struct GNUNET_SCHEDULER_TaskContext *tc) {
    if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
      return;
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Connecting to service-dns\n");
    GNUNET_assert (dns_connection == NULL);
    dns_connection = GNUNET_CLIENT_connect ("dns", cfg);
    GNUNET_CLIENT_receive(dns_connection, &dns_answer_handler, NULL, GNUNET_TIME_UNIT_FOREVER_REL);

    /* If a packet is already in the list, schedule to send it */
    if (head != NULL)
      GNUNET_CLIENT_notify_transmit_ready(dns_connection,
					  ntohs(head->pkt.hdr.size),
					  GNUNET_TIME_UNIT_FOREVER_REL,
					  GNUNET_YES,
					  &send_query,
					  NULL);
    else if (restart_hijack == 1)
      {
	GNUNET_CLIENT_notify_transmit_ready(dns_connection, sizeof(struct GNUNET_MessageHeader), GNUNET_TIME_UNIT_FOREVER_REL, GNUNET_YES, &send_query, NULL);
      }
}

/**
 * Create a new Address from an answer-packet
 * {{{
 */
void
new_ip6addr(char* buf, const GNUNET_HashCode *peer, const GNUNET_HashCode *service_desc) {
	memcpy(buf+14, (int[]){htons(0x3412)}, 2);
	memcpy(buf+8, service_desc, 6);
	memcpy(buf, peer, 8);
}
/*}}}*/

/**
 * This gets scheduled with cls pointing to an answer_packet and does everything
 * needed in order to send it to the helper.
 *
 * At the moment this means "inventing" and IPv6-Address for .gnunet-services and
 * doing nothing for "real" services.
 */
static void
process_answer(void* cls, const struct GNUNET_SCHEDULER_TaskContext* tc) {
    struct answer_packet* pkt = cls;
    struct answer_packet_list* list;

    /* This answer is about a .gnunet-service
     *
     * It contains an almost complete DNS-Response, we have to fill in the ip
     * at the offset pkt->addroffset
     */
    //FIXME htons?
    if (pkt->subtype == GNUNET_DNS_ANSWER_TYPE_SERVICE)
      {
	pkt->subtype = GNUNET_DNS_ANSWER_TYPE_IP;

	GNUNET_HashCode key;
	memset(&key, 0, sizeof(GNUNET_HashCode));
	new_ip6addr((char*)&key, &pkt->service_descr.peer, &pkt->service_descr.service_descriptor);

	uint16_t namelen = strlen((char*)pkt->data+12)+1;

	struct map_entry* value = GNUNET_malloc(sizeof(struct GNUNET_vpn_service_descriptor) + 2 + 8 + namelen);

	value->namelen = namelen;
	memcpy(value->name, pkt->data+12, namelen);

	memcpy(&value->desc, &pkt->service_descr, sizeof(struct GNUNET_vpn_service_descriptor));

	value->additional_ports = 0;

	if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put(hashmap,
							   &key,
							   value,
							   GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
	  {
	    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Could not store to hashmap\n");
	  }

	/*
	 * Copy the newly generated backward ip-address to the packet
	 */
	char* c = ((char*)pkt)+ntohs(pkt->addroffset);
	char* k = (char*)&key;
	unsigned int i;
	for (i = 0; i < 16; i++)
	    c[15-i] = k[i];

	list = GNUNET_malloc(htons(pkt->hdr.size) + 2*sizeof(struct answer_packet_list*));

	memcpy(&list->pkt, pkt, htons(pkt->hdr.size));

      }
    else if (pkt->subtype == GNUNET_DNS_ANSWER_TYPE_REV)
      {
	GNUNET_HashCode key;
	memset(&key, 0, sizeof key);
	unsigned char* k = (unsigned char*)&key;
	unsigned char* s = pkt->data+12;
	int i = 0;
	/* Whoever designed the reverse IPv6-lookup is batshit insane */
	for (i = 0; i < 16; i++)
	  {
	    unsigned char c1 = s[(4*i)+1];
	    unsigned char c2 = s[(4*i)+3];
	    if (c1 <= '9')
	      k[i] = c1 - '0';
	    else
	      k[i] = c1 - 87; /* 87 is the difference between 'a' and 10 */
	    if (c2 <= '9')
	      k[i] += 16*(c2 - '0');
	    else
	      k[i] += 16*(c2 - 87);
	  }

	struct map_entry* map_entry = GNUNET_CONTAINER_multihashmap_get(hashmap, &key);
	unsigned short offset = ntohs(pkt->addroffset);

	if (map_entry == NULL)
	  {
	    GNUNET_free(pkt);
	    return;
	  }

        unsigned short namelen = htons(map_entry->namelen);
	char* name = map_entry->name;

	list = GNUNET_malloc(2*sizeof(struct answer_packet_list*) + offset + 2 + ntohs(namelen));

	struct answer_packet* rpkt = &list->pkt;

	memcpy(rpkt, pkt, offset);

	rpkt->subtype = GNUNET_DNS_ANSWER_TYPE_IP;
	rpkt->hdr.size = ntohs(offset + 2 + ntohs(namelen));

	memcpy(((char*)rpkt)+offset, &namelen, 2);
	memcpy(((char*)rpkt)+offset+2, name, ntohs(namelen));

      }
    else if (pkt->subtype == GNUNET_DNS_ANSWER_TYPE_IP)
      {
	list = GNUNET_malloc(htons(pkt->hdr.size) + 2*sizeof(struct answer_packet_list*));
	memcpy(&list->pkt, pkt, htons(pkt->hdr.size));
      }
    else
      {
	GNUNET_break(0);
	GNUNET_free(pkt);
	return;
      }

    GNUNET_free(pkt);

    GNUNET_CONTAINER_DLL_insert_after(answer_proc_head, answer_proc_tail, answer_proc_tail, list);

    GNUNET_SCHEDULER_add_write_file (GNUNET_TIME_UNIT_FOREVER_REL, fh_to_helper, &helper_write, NULL);

    return;
}

/**
 * This receives packets from the service-dns and schedules process_answer to
 * handle it
 */
static void
dns_answer_handler(void* cls, const struct GNUNET_MessageHeader *msg) {
    /* the service disconnected, reconnect after short wait */
    if (msg == NULL)
      {
	GNUNET_CLIENT_disconnect(dns_connection, GNUNET_NO);
	dns_connection = NULL;
	GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
				      &connect_to_service_dns,
				      NULL);
	return;
      }

    /* the service did something strange, reconnect immediately */
    if (msg->type != htons(GNUNET_MESSAGE_TYPE_LOCAL_RESPONSE_DNS))
      {
	GNUNET_break (0);
	GNUNET_CLIENT_disconnect(dns_connection, GNUNET_NO);
	dns_connection = NULL;
	GNUNET_SCHEDULER_add_now (&connect_to_service_dns,
				  NULL);
	return;
      }
    void *pkt = GNUNET_malloc(ntohs(msg->size));

    memcpy(pkt, msg, ntohs(msg->size));

    GNUNET_SCHEDULER_add_now(process_answer, pkt);
    GNUNET_CLIENT_receive(dns_connection, &dns_answer_handler, NULL, GNUNET_TIME_UNIT_FOREVER_REL);
}

struct udp_state
{
  struct GNUNET_PeerIdentity peer;
  GNUNET_HashCode desc;
  short spt;
  short dpt;
};

struct send_cls
{
  struct GNUNET_NETWORK_Handle *sock;
  struct udp_state state;
};

static size_t
send_udp_service (void *cls, size_t size, void *buf)
{
  struct GNUNET_MessageHeader *hdr = cls;
  GNUNET_assert(size >= ntohs(hdr->size));

  memcpy(buf, cls, ntohs(hdr->size));
  size_t ret = ntohs(hdr->size);
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Sending %d bytes back!\n", ntohs(hdr->size));
  GNUNET_free(cls);
  return ret;
}

void
receive_from_network (void *cls,
		      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN)
    {
      GNUNET_free(cls);
      return;
    }
  struct send_cls *data = cls;

  char buf[1400];

  struct sockaddr_in addr_in;
  socklen_t addr_len = sizeof(struct sockaddr_in);
  ssize_t len = GNUNET_NETWORK_socket_recvfrom (data->sock, buf, 1400, (struct sockaddr*)&addr_in, &addr_len);

  if (len < 0) {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Problem reading from socket: %m\n");
    goto out;
  }

  size_t len_udp = len + sizeof (struct udp_pkt);
  size_t len_pkt = len_udp + sizeof (struct GNUNET_MessageHeader) + sizeof(GNUNET_HashCode);
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Sending data back: data: %d; udp: %d, pkt:%d\n", len, len_udp, len_pkt);

  struct GNUNET_MessageHeader *hdr = GNUNET_malloc (len_pkt);
  GNUNET_HashCode *desc = (GNUNET_HashCode *) (hdr + 1);
  struct udp_pkt *pkt = (struct udp_pkt *) (desc + 1);

  hdr->size = htons (len_pkt);
  hdr->type = htons (GNUNET_MESSAGE_TYPE_SERVICE_UDP_BACK);

  pkt->dpt = htons(data->state.spt);
  pkt->spt = addr_in.sin_port;
  pkt->len = htons (len_udp);
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "UDP from %d to %d\n", ntohs(pkt->spt), ntohs(pkt->dpt));
  /* The chksm can only be computed knowing the ip-addresses */

  memcpy (desc, &data->state.desc, sizeof (GNUNET_HashCode));
  memcpy (pkt + 1, buf, len);

  GNUNET_CORE_notify_transmit_ready (core_handle, 42,
				     GNUNET_TIME_relative_divide(GNUNET_CONSTANTS_MAX_CORK_DELAY, 2),
				     &data->state.peer, len_pkt,
				     send_udp_service, hdr);

out:
  GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL, data->sock,
				 receive_from_network, cls);
}

void
send_to_network (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN)
    return;
  struct send_cls *data = cls;
  struct udp_pkt *pkt = (struct udp_pkt *) (data + 1);

  struct sockaddr_in a4;
  memset(&a4, 0, sizeof(struct sockaddr_in));
  a4.sin_family = AF_INET;
  a4.sin_port = htons(data->state.dpt);
  memcpy(&a4.sin_addr.s_addr, (char[]){127, 0, 0, 1}, 4);

  GNUNET_NETWORK_socket_sendto (data->sock, pkt + 1,
				ntohs (pkt->len) - sizeof (struct udp_pkt),
				(struct sockaddr*)&a4, sizeof a4);

  GNUNET_free(cls);

}

static void
add_additional_port (struct map_entry *me, uint16_t port)
{
  uint16_t *ps = (uint16_t *) & me->additional_ports;
  unsigned int i;
  for (i = 0; i < 4; i++)
    {
      if (ps[i] == 0)
	{
	  ps[i] = port;
	  break;
	}
    }
}

static int
receive_udp_back (void *cls, const struct GNUNET_PeerIdentity *other,
	     const struct GNUNET_MessageHeader *message,
	     const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
  GNUNET_HashCode *desc = (GNUNET_HashCode *) (message + 1);
  struct udp_pkt *pkt = (struct udp_pkt *) (desc + 1);
  char addr[16];
  new_ip6addr(addr, &other->hashPubKey, desc);

  size_t size = sizeof(struct ip6_udp) + ntohs(pkt->len) - 1 - sizeof(struct udp_pkt);

  struct ip6_udp* pkt6 = alloca(size);

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Relaying calc:%d gnu:%d udp:%d bytes!\n", size, ntohs(message->size), ntohs(pkt->len));

  pkt6->shdr.type = htons(GNUNET_MESSAGE_TYPE_VPN_HELPER);
  pkt6->shdr.size = htons(size);

  pkt6->tun.flags = 0;
  pkt6->tun.type = htons(0x86dd);

  pkt6->ip6_hdr.version = 6;
  pkt6->ip6_hdr.tclass_h = 0;
  pkt6->ip6_hdr.tclass_l = 0;
  pkt6->ip6_hdr.flowlbl = 0;
  pkt6->ip6_hdr.paylgth = pkt->len;
  pkt6->ip6_hdr.nxthdr = 0x11;
  pkt6->ip6_hdr.hoplmt = 0xff;

  unsigned int i;
  for (i = 0; i < 16; i++)
    pkt6->ip6_hdr.sadr[15-i] = addr[i];

  memcpy(pkt6->ip6_hdr.dadr, (unsigned char[]){0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 16);

  memcpy(&pkt6->udp_hdr, pkt, ntohs(pkt->len));

  GNUNET_HashCode* key = address_mapping_exists(pkt6->ip6_hdr.sadr);
  GNUNET_assert (key != NULL);

  struct map_entry *me = GNUNET_CONTAINER_multihashmap_get(hashmap, key);

  GNUNET_free(key);

  GNUNET_assert (me != NULL);
  GNUNET_assert (me->desc.service_type & htonl(GNUNET_DNS_SERVICE_TYPE_UDP));
  if (!port_in_ports(me->desc.ports, pkt6->udp_hdr.spt) ||
      !port_in_ports(me->additional_ports, pkt6->udp_hdr.spt)) {
      add_additional_port(me, pkt6->udp_hdr.spt);
  }

  pkt6->udp_hdr.crc = 0;
  uint32_t sum = 0;
  sum = calculate_checksum_update(sum, (uint16_t*)&pkt6->ip6_hdr.sadr, 16);
  sum = calculate_checksum_update(sum, (uint16_t*)&pkt6->ip6_hdr.dadr, 16);
  uint32_t tmp = (pkt6->udp_hdr.len & 0xffff);
  sum = calculate_checksum_update(sum, (uint16_t*)&tmp, 4);
  tmp = htons(((pkt6->ip6_hdr.nxthdr & 0x00ff)));
  sum = calculate_checksum_update(sum, (uint16_t*)&tmp, 4);

  sum = calculate_checksum_update(sum, (uint16_t*)&pkt6->udp_hdr, ntohs(pkt->len));
  pkt6->udp_hdr.crc = calculate_checksum_end(sum);


  /* FIXME */ GNUNET_DISK_file_write(fh_to_helper, pkt6, size);

  return GNUNET_OK;
}

static int
receive_udp_service (void *cls, const struct GNUNET_PeerIdentity *other,
		     const struct GNUNET_MessageHeader *message,
		     const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received UDP-Packet from peer %s\n",
	      GNUNET_i2s (other));
  GNUNET_HashCode *desc = (GNUNET_HashCode *) (message + 1);
  struct udp_pkt *pkt = (struct udp_pkt *) (desc + 1);

  /* FIXME -> check acl etc */
  GNUNET_assert (ntohs (pkt->len) ==
		 ntohs (message->size) -
		 sizeof (struct GNUNET_MessageHeader) -
		 sizeof (GNUNET_HashCode));

  size_t state_size = sizeof (struct udp_state);
  size_t cls_size = sizeof (struct send_cls) + ntohs (pkt->len);
  struct send_cls *send = GNUNET_malloc (cls_size);
  struct udp_state *state = &send->state;
  unsigned int new = GNUNET_NO;

  memcpy (&state->peer, other, sizeof (struct GNUNET_PeerIdentity));
  memcpy (&state->desc, desc, sizeof (GNUNET_HashCode));
  state->spt = ntohs (pkt->spt);

  /* Hash without the dpt, so that eg tftp works */
  state->dpt = 0;

  memcpy (send + 1, pkt, ntohs (pkt->len));

  GNUNET_HashCode hash;
  GNUNET_CRYPTO_hash (state, state_size, &hash);

  state->dpt = ntohs (pkt->dpt);

  struct GNUNET_NETWORK_Handle *sock =
    GNUNET_CONTAINER_multihashmap_get (udp_connections, &hash);

  if (sock == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Creating new Socket!\n");
      sock = GNUNET_NETWORK_socket_create (AF_INET, SOCK_DGRAM, 0);
      new = GNUNET_YES;
    }

  send->sock = sock;

  GNUNET_CONTAINER_multihashmap_put (udp_connections, &hash, sock,
				     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);


  if (new)
    {
      struct send_cls *recv = GNUNET_malloc (sizeof (struct send_cls));
      memcpy (recv, send, sizeof (struct send_cls));
      GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL, sock,
				     receive_from_network, recv);
    }

  GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL, sock,
				  send_to_network, send);

  return GNUNET_OK;
}

/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg_ configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg_) {
    const static struct GNUNET_CORE_MessageHandler handlers[] = {
	  {receive_udp_service, GNUNET_MESSAGE_TYPE_SERVICE_UDP, 0},
	  {receive_udp_back, GNUNET_MESSAGE_TYPE_SERVICE_UDP_BACK, 0},
	  {NULL, 0, 0}
    };
    core_handle = GNUNET_CORE_connect(cfg_,
				      42,
				      NULL,
				      NULL,
				      NULL,
				      NULL,
				      NULL,
				      NULL,
				      0,
				      NULL,
				      0,
				      handlers);
    mst = GNUNET_SERVER_mst_create(&message_token, NULL);
    cfg = cfg_;
    restart_hijack = 0;
    hashmap = GNUNET_CONTAINER_multihashmap_create(65536);
    udp_connections = GNUNET_CONTAINER_multihashmap_create(65536);
    GNUNET_SCHEDULER_add_now (connect_to_service_dns, NULL);
    GNUNET_SCHEDULER_add_now (start_helper_and_schedule, NULL);
    GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_UNIT_FOREVER_REL, &cleanup, cls);
}

/**
 * The main function to obtain template from gnunetd.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv) {
    static const struct GNUNET_GETOPT_CommandLineOption options[] = {
	GNUNET_GETOPT_OPTION_END
    };

    return (GNUNET_OK ==
	    GNUNET_PROGRAM_run (argc,
				argv,
				"gnunet-daemon-vpn",
				gettext_noop ("help text"),
				options, &run, NULL)) ? ret : 1;
}

/* end of gnunet-daemon-vpn.c */
