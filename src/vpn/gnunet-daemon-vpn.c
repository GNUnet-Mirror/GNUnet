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
#include "gnunet-vpn-packet.h"
#include "gnunet-vpn-pretty-print.h"
#include "gnunet_common.h"
#include "gnunet_protocols.h"
#include <gnunet_mesh_service.h>
#include "gnunet_client_lib.h"
#include "gnunet_container_lib.h"
#include "gnunet_constants.h"
#include <block_dns.h>
#include "gnunet-daemon-vpn-helper.h"
#include "gnunet-daemon-vpn-dns.h"
#include "gnunet-daemon-vpn.h"
#include "gnunet-vpn-checksum.h"

const struct GNUNET_CONFIGURATION_Handle *cfg;
struct GNUNET_MESH_Handle *mesh_handle;
struct GNUNET_CONTAINER_MultiHashMap* hashmap;

/**
 * Final status code.
 */
static int ret;

/**
 * This hashmap contains the mapping from peer, service-descriptor,
 * source-port and destination-port to a socket
 */
static struct GNUNET_CONTAINER_MultiHashMap *udp_connections;

/**
 * Function scheduled as very last function, cleans up after us
 *{{{
 */
static void
cleanup(void* cls, const struct GNUNET_SCHEDULER_TaskContext* tskctx) {
    GNUNET_assert (0 != (tskctx->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN));

    /* stop the helper */
    cleanup_helper(helper_handle);

    /* close the connection to the service-dns */
    if (dns_connection != NULL)
      {
	GNUNET_CLIENT_disconnect (dns_connection, GNUNET_NO);
	dns_connection = NULL;
      }

    if (mesh_handle != NULL)
      {
	GNUNET_MESH_disconnect(mesh_handle);
	mesh_handle = NULL;
      }
}
/*}}}*/

/**
 * @return the hash of the IP-Address if a mapping exists, NULL otherwise
 */
GNUNET_HashCode*
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

void
send_icmp_response(void* cls, const struct GNUNET_SCHEDULER_TaskContext *tc) {
    struct ip6_icmp* request = cls;

    struct ip6_icmp* response = alloca(ntohs(request->shdr.size));
    GNUNET_assert(response != NULL);
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

    write_to_helper(response, ntohs(response->shdr.size));

    GNUNET_free(request);
}

/**
 * cls is the pointer to a GNUNET_MessageHeader that is
 * followed by the service-descriptor and the udp-packet that should be sent;
 */
static size_t
send_udp_to_peer_notify_callback (void *cls, size_t size, void *buf)
{
  struct GNUNET_MESH_Tunnel **tunnel = cls;
  struct GNUNET_MessageHeader *hdr =
    (struct GNUNET_MessageHeader *) (tunnel + 1);
  GNUNET_HashCode *hc = (GNUNET_HashCode *) (hdr + 1);
  struct udp_pkt *udp = (struct udp_pkt *) (hc + 1);
  hdr->size = htons (sizeof (struct GNUNET_MessageHeader) +
		     sizeof (GNUNET_HashCode) + ntohs (udp->len));
  hdr->type = ntohs (GNUNET_MESSAGE_TYPE_SERVICE_UDP);
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "send_udp_to_peer_notify_callback: buf = %x; size = %u;\n", buf, size);
  GNUNET_assert (size >= ntohs (hdr->size));
  memcpy (buf, hdr, ntohs (hdr->size));
  size = ntohs(hdr->size);
  GNUNET_free (cls);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sent!\n");
  return size;
}

unsigned int
port_in_ports (uint64_t ports, uint16_t port)
{
  uint16_t *ps = (uint16_t *) & ports;
  return ps[0] == port || ps[1] == port || ps[2] == port || ps[3] == port;
}

void
send_udp_to_peer (void *cls, 
		  const struct GNUNET_PeerIdentity *peer,
		  const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
  if (peer == NULL) return;
  struct GNUNET_MESH_Tunnel **tunnel = cls;
  struct GNUNET_MessageHeader *hdr =
    (struct GNUNET_MessageHeader *) (tunnel + 1);
  GNUNET_HashCode *hc = (GNUNET_HashCode *) (hdr + 1);
  struct udp_pkt *udp = (struct udp_pkt *) (hc + 1);
  GNUNET_MESH_notify_transmit_ready (*tunnel,
				     GNUNET_NO,
				     42,
				     GNUNET_TIME_relative_divide(GNUNET_CONSTANTS_MAX_CORK_DELAY, 2),
				     htons (sizeof
					    (struct GNUNET_MessageHeader) +
					    sizeof (GNUNET_HashCode) +
					    ntohs (udp->len)),
				     send_udp_to_peer_notify_callback,
				     cls);
}

/**
 * Create a new Address from an answer-packet
 */
void
new_ip6addr(unsigned char* buf, const GNUNET_HashCode *peer, const GNUNET_HashCode *service_desc) { /* {{{ */
    char* ipv6addr;
    unsigned long long ipv6prefix;
    GNUNET_assert(GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(cfg, "vpn", "IPV6ADDR", &ipv6addr));
    GNUNET_assert(GNUNET_OK == GNUNET_CONFIGURATION_get_value_number(cfg, "vpn", "IPV6PREFIX", &ipv6prefix));
    GNUNET_assert(ipv6prefix < 127);
    ipv6prefix = (ipv6prefix + 7)/8;

    inet_pton (AF_INET6, ipv6addr, buf);
    GNUNET_free(ipv6addr);

    int peer_length = 16 - ipv6prefix - 6;
    if (peer_length <= 0)
      peer_length = 0;

    int service_length = 16 - ipv6prefix - peer_length;
    if (service_length <= 0)
      service_length = 0;

    memcpy(buf+ipv6prefix, service_desc, service_length);
    memcpy(buf+ipv6prefix+service_length, peer, peer_length);
}
/*}}}*/

/**
 * This gets scheduled with cls pointing to an answer_packet and does everything
 * needed in order to send it to the helper.
 *
 * At the moment this means "inventing" and IPv6-Address for .gnunet-services and
 * doing nothing for "real" services.
 */
void
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

	unsigned char* c = ((unsigned char*)pkt)+ntohs(pkt->addroffset);
	unsigned char* k = (unsigned char*)&key;
	new_ip6addr(c, &pkt->service_descr.peer, &pkt->service_descr.service_descriptor);
	/*
	 * Copy the newly generated ip-address to the key backwarts (as only the first part is hashed)
	 */
	unsigned int i;
	for (i = 0; i < 16; i++)
	    k[15-i] = c[i];

	uint16_t namelen = strlen((char*)pkt->data+12)+1;

	struct map_entry* value = GNUNET_malloc(sizeof(struct map_entry) + namelen);
	char* name = (char*)(value +1);

	value->namelen = namelen;
	memcpy(name, pkt->data+12, namelen);

	memcpy(&value->desc, &pkt->service_descr, sizeof(struct GNUNET_vpn_service_descriptor));

	value->additional_ports = 0;

        if (GNUNET_NO ==
            GNUNET_CONTAINER_multihashmap_contains (hashmap, &key))
          GNUNET_CONTAINER_multihashmap_put (hashmap, &key, value,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
        else
          GNUNET_free(value);


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
	uint16_t offset = ntohs(pkt->addroffset);

	if (map_entry == NULL)
	  {
	    GNUNET_free(pkt);
	    return;
	  }

        unsigned short namelen = htons(map_entry->namelen);
	char* name = (char*)(map_entry + 1);

	list = GNUNET_malloc(2*sizeof(struct answer_packet_list*) + offset + 2 + ntohs(namelen));

	struct answer_packet* rpkt = &list->pkt;

	/* The offset points to the first byte belonging to the address */
	memcpy(rpkt, pkt, offset - 1);

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

    schedule_helper_write(GNUNET_TIME_UNIT_FOREVER_REL, NULL);

    return;
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
receive_udp_back (void *cls, struct GNUNET_MESH_Tunnel* tunnel,
		  void **tunnel_ctx,
		  const struct GNUNET_MessageHeader *message,
		  const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
  GNUNET_HashCode *desc = (GNUNET_HashCode *) (message + 1);
  struct udp_pkt *pkt = (struct udp_pkt *) (desc + 1);
  const struct GNUNET_PeerIdentity* other = GNUNET_MESH_get_peer(tunnel);

  size_t size = sizeof(struct ip6_udp) + ntohs(pkt->len) - 1 - sizeof(struct udp_pkt);

  struct ip6_udp* pkt6 = alloca(size);

  GNUNET_assert(pkt6 != NULL);

  new_ip6addr(pkt6->ip6_hdr.sadr, &other->hashPubKey, desc);

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

  {
    char* ipv6addr;
    GNUNET_assert(GNUNET_OK == GNUNET_CONFIGURATION_get_value_string(cfg, "vpn", "IPV6ADDR", &ipv6addr));
    inet_pton (AF_INET6, ipv6addr, pkt6->ip6_hdr.dadr);
    GNUNET_free(ipv6addr);
  }
  memcpy(&pkt6->udp_hdr, pkt, ntohs(pkt->len));

  GNUNET_HashCode* key = address_mapping_exists(pkt6->ip6_hdr.sadr);
  GNUNET_assert (key != NULL);

  struct map_entry *me = GNUNET_CONTAINER_multihashmap_get(hashmap, key);

  GNUNET_free(key);

  GNUNET_assert (me != NULL);
  GNUNET_assert (me->desc.service_type & htonl(GNUNET_DNS_SERVICE_TYPE_UDP));
  if (!port_in_ports(me->desc.ports, pkt6->udp_hdr.spt) &&
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

  write_to_helper(pkt6, size);

  return GNUNET_OK;
}

void init_mesh (void* cls, struct GNUNET_MESH_Handle* server, const struct GNUNET_PeerIdentity* my_identity, const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *pubkey) {
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Connected to MESH, I am %x\n", *((unsigned long*)my_identity));
}

void connect_mesh (void* cls, const struct GNUNET_PeerIdentity* peer, const struct GNUNET_TRANSPORT_ATS_Information *atsi) {
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Connected to peer %x\n", *((unsigned long*)peer));
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
     const struct GNUNET_CONFIGURATION_Handle *cfg_)
{
    const static struct GNUNET_MESH_MessageHandler handlers[] = {
	  {receive_udp_back, GNUNET_MESSAGE_TYPE_SERVICE_UDP_BACK, 0},
	  {NULL, 0, 0}
    };
    mesh_handle = GNUNET_MESH_connect(cfg_,
				      NULL,
				      NULL,
				      handlers);
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

