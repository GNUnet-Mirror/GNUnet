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
#include "gnunet_common.h"
#include "gnunet_protocols.h"
#include "gnunet_applications.h"
#include <gnunet_mesh_service.h>
#include "gnunet_client_lib.h"
#include "gnunet_container_lib.h"
#include "gnunet_constants.h"
#include <block_dns.h>
#include "gnunet_dns_service.h"
#include "gnunet-daemon-vpn.h"


const struct GNUNET_CONFIGURATION_Handle *cfg;
struct GNUNET_MESH_Handle *mesh_handle;
struct GNUNET_CONTAINER_MultiHashMap *hashmap;
static struct GNUNET_CONTAINER_Heap *heap;

/**
 * The handle to the helper
 */
static struct GNUNET_HELPER_Handle *helper_handle;

/**
 * Arguments to the exit helper.
 */
static char *vpn_argv[7];

struct GNUNET_DNS_Handle *dns_handle;

struct answer_packet_list *answer_proc_head;

struct answer_packet_list *answer_proc_tail;


struct tunnel_notify_queue
{
  struct tunnel_notify_queue *next;
  struct tunnel_notify_queue *prev;
  size_t len;
  void *cls;
};

/**
 * If there are at least this many address-mappings, old ones will be removed
 */
static long long unsigned int max_mappings = 200;

/**
 * Final status code.
 */
static int ret;

/**
 * This hashmap contains the mapping from peer, service-descriptor,
 * source-port and destination-port to a socket
 */
static struct GNUNET_CONTAINER_MultiHashMap *udp_connections;

GNUNET_SCHEDULER_TaskIdentifier conn_task;

GNUNET_SCHEDULER_TaskIdentifier shs_task;


/**
 * The tunnels that will be used to send tcp- and udp-packets
 */
static struct GNUNET_MESH_Tunnel *tcp_tunnel;
static struct GNUNET_MESH_Tunnel *udp_tunnel;



/**
 * Sets a bit active in a bitArray.
 *
 * @param bitArray memory area to set the bit in
 * @param bitIdx which bit to set
 */
static void
setBit (char *bitArray, unsigned int bitIdx)
{
  size_t arraySlot;
  unsigned int targetBit;

  arraySlot = bitIdx / 8;
  targetBit = (1L << (bitIdx % 8));
  bitArray[arraySlot] |= targetBit;
}


/**
 * Checks if a bit is active in the bitArray
 *
 * @param bitArray memory area to set the bit in
 * @param bitIdx which bit to test
 * @return GNUNET_YES if the bit is set, GNUNET_NO if not.
 */
int
testBit (char *bitArray, unsigned int bitIdx)
{
  size_t slot;
  unsigned int targetBit;

  slot = bitIdx / 8;
  targetBit = (1L << (bitIdx % 8));
  if (bitArray[slot] & targetBit)
    return GNUNET_YES;
  else
    return GNUNET_NO;
}


/**
 * Function scheduled as very last function, cleans up after us
 *{{{
 */
static void
cleanup (void *cls GNUNET_UNUSED,
         const struct GNUNET_SCHEDULER_TaskContext *tskctx)
{
  unsigned int i;

  GNUNET_assert (0 != (tskctx->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN));
  /* close the connection to the service-dns */
  GNUNET_DNS_disconnect (dns_handle);
  if (mesh_handle != NULL)
  {
    GNUNET_MESH_disconnect (mesh_handle);
    mesh_handle = NULL;
  }
  if (helper_handle != NULL)
  {
    GNUNET_HELPER_stop (helper_handle);
    helper_handle = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != shs_task)
  {
    GNUNET_SCHEDULER_cancel (shs_task);
    shs_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (GNUNET_SCHEDULER_NO_TASK != conn_task)
  {
    GNUNET_SCHEDULER_cancel (conn_task);
    conn_task = GNUNET_SCHEDULER_NO_TASK;
  }
  for (i=0;i<5;i++)
    GNUNET_free_non_null (vpn_argv[i]);
}

/*}}}*/

/**
 * @return the hash of the IP-Address if a mapping exists, NULL otherwise
 */
GNUNET_HashCode *
address6_mapping_exists (struct in6_addr *v6addr)
{
  unsigned char *addr = (unsigned char*) v6addr;
  GNUNET_HashCode *key = GNUNET_malloc (sizeof (GNUNET_HashCode));
  unsigned char *k = (unsigned char *) key;

  memset (key, 0, sizeof (GNUNET_HashCode));
  unsigned int i;

  for (i = 0; i < 16; i++)
    k[15 - i] = addr[i];

  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (hashmap, key))
    return key;
  else
  {
    GNUNET_free (key);
    return NULL;
  }
}

/**
 * @return the hash of the IP-Address if a mapping exists, NULL otherwise
 */
GNUNET_HashCode *
address4_mapping_exists (uint32_t addr)
{
  GNUNET_HashCode *key = GNUNET_malloc (sizeof (GNUNET_HashCode));

  memset (key, 0, sizeof (GNUNET_HashCode));
  unsigned char *c = (unsigned char *) &addr;
  unsigned char *k = (unsigned char *) key;
  unsigned int i;

  for (i = 0; i < 4; i++)
    k[3 - i] = c[i];

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "a4_m_e: getting with key %08x, addr is %08x, %d.%d.%d.%d\n",
              *((uint32_t *) (key)), addr, c[0], c[1], c[2], c[3]);

  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (hashmap, key))
    return key;
  else
  {
    GNUNET_free (key);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Mapping not found!\n");
    return NULL;
  }
}


static void *
initialize_tunnel_state (int addrlen, struct GNUNET_MESH_TransmitHandle *th)
{
  struct tunnel_state *ts = GNUNET_malloc (sizeof *ts);

  ts->addrlen = addrlen;
  ts->th = th;
  return ts;
}

/**
 * Send an dns-answer-packet to the helper
 */
void
helper_write (void *cls GNUNET_UNUSED,
              int status)
{
  struct answer_packet_list *ans = answer_proc_head;

  if (NULL == ans)
    return;
  if (GNUNET_SYSERR == status)
    return;

  size_t len = ntohs (ans->pkt.hdr.size);

  GNUNET_assert (ans->pkt.subtype == GNUNET_DNS_ANSWER_TYPE_IP);

  GNUNET_assert (20 == sizeof (struct ip_hdr));
  GNUNET_assert (8 == sizeof (struct udp_pkt));

  size_t data_len = len - sizeof (struct answer_packet) + 1;

  size_t pkt_len;

  if (ans->pkt.addrlen == 16)
  {
    size_t net_len =
        sizeof (struct ip6_hdr) + sizeof (struct udp_dns) + data_len;
    pkt_len =
        sizeof (struct GNUNET_MessageHeader) + sizeof (struct pkt_tun) +
        net_len;

    struct ip6_udp_dns *pkt = alloca (pkt_len);

    GNUNET_assert (pkt != NULL);
    memset (pkt, 0, pkt_len);

    /* set the gnunet-header */
    pkt->shdr.size = htons (pkt_len);
    pkt->shdr.type = htons (GNUNET_MESSAGE_TYPE_VPN_HELPER);

    /* set the tun-header (no flags and ethertype of IPv4) */
    pkt->tun.flags = 0;
    pkt->tun.type = htons (0x86dd);

    memcpy (&pkt->ip6_hdr.sadr, ans->pkt.from, 16);
    memcpy (&pkt->ip6_hdr.dadr, ans->pkt.to, 16);

    /* set the udp-header */
    pkt->udp_dns.udp_hdr.spt = htons (53);
    pkt->udp_dns.udp_hdr.dpt = ans->pkt.dst_port;
    pkt->udp_dns.udp_hdr.len = htons (net_len - sizeof (struct ip6_hdr));
    pkt->udp_dns.udp_hdr.crc = 0;
    uint32_t sum = 0;

    sum = GNUNET_CRYPTO_crc16_step (sum, (uint16_t *) & pkt->ip6_hdr.sadr, 16);
    sum = GNUNET_CRYPTO_crc16_step (sum, (uint16_t *) & pkt->ip6_hdr.dadr, 16);
    uint32_t tmp = (pkt->udp_dns.udp_hdr.len & 0xffff);

    sum = GNUNET_CRYPTO_crc16_step (sum, (uint16_t *) & tmp, 4);
    tmp = htons (((pkt->ip6_hdr.nxthdr & 0x00ff)));
    sum = GNUNET_CRYPTO_crc16_step (sum, (uint16_t *) & tmp, 4);

    sum =
        GNUNET_CRYPTO_crc16_step (sum, (uint16_t *) & pkt->udp_dns.udp_hdr,
                                   ntohs (net_len - sizeof (struct ip6_hdr)));
    pkt->udp_dns.udp_hdr.crc = GNUNET_CRYPTO_crc16_finish (sum);

    pkt->ip6_hdr.version = 6;
    pkt->ip6_hdr.paylgth = net_len - sizeof (struct ip6_hdr);
    pkt->ip6_hdr.nxthdr = IPPROTO_UDP;
    pkt->ip6_hdr.hoplmt = 0xff;

    memcpy (&pkt->udp_dns.data, ans->pkt.data, data_len);
    (void) GNUNET_HELPER_send (helper_handle,
			       &pkt->shdr,
			       GNUNET_YES,
			       &helper_write, NULL);
  }
  else if (ans->pkt.addrlen == 4)
  {
    size_t net_len =
        sizeof (struct ip_hdr) + sizeof (struct udp_dns) + data_len;
    pkt_len =
        sizeof (struct GNUNET_MessageHeader) + sizeof (struct pkt_tun) +
        net_len;

    struct ip_udp_dns *pkt = alloca (pkt_len);

    GNUNET_assert (pkt != NULL);
    memset (pkt, 0, pkt_len);

    /* set the gnunet-header */
    pkt->shdr.size = htons (pkt_len);
    pkt->shdr.type = htons (GNUNET_MESSAGE_TYPE_VPN_HELPER);

    /* set the tun-header (no flags and ethertype of IPv4) */
    pkt->tun.flags = 0;
    pkt->tun.type = htons (0x0800);

    /* set the ip-header */
    pkt->ip_hdr.version = 4;
    pkt->ip_hdr.hdr_lngth = 5;
    pkt->ip_hdr.diff_serv = 0;
    pkt->ip_hdr.tot_lngth = htons (net_len);
    pkt->ip_hdr.ident = 0;
    pkt->ip_hdr.flags = 0;
    pkt->ip_hdr.frag_off = 0;
    pkt->ip_hdr.ttl = 255;
    pkt->ip_hdr.proto = IPPROTO_UDP;
    pkt->ip_hdr.chks = 0;       /* Will be calculated later */

    memcpy (&pkt->ip_hdr.sadr, ans->pkt.from, 4);
    memcpy (&pkt->ip_hdr.dadr, ans->pkt.to, 4);

    pkt->ip_hdr.chks =
        GNUNET_CRYPTO_crc16_n ((uint16_t *) & pkt->ip_hdr, 5 * 4);

    /* set the udp-header */
    pkt->udp_dns.udp_hdr.spt = htons (53);
    pkt->udp_dns.udp_hdr.dpt = ans->pkt.dst_port;
    pkt->udp_dns.udp_hdr.len = htons (net_len - sizeof (struct ip_hdr));
    pkt->udp_dns.udp_hdr.crc = 0;       /* Optional for IPv4 */

    memcpy (&pkt->udp_dns.data, ans->pkt.data, data_len);
    (void) GNUNET_HELPER_send (helper_handle,
			       &pkt->shdr,
			       GNUNET_YES,
			       &helper_write, NULL);

  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Wrong addrlen = %d\n",
                ans->pkt.addrlen);
    GNUNET_assert (0);
    return;                     /* convince compiler that we're done here */
  }

  GNUNET_CONTAINER_DLL_remove (answer_proc_head, answer_proc_tail, ans);
  GNUNET_free (ans);

}

/**
 * Receive packets from the helper-process
 */
void
message_token (void *cls GNUNET_UNUSED, void *client GNUNET_UNUSED,
               const struct GNUNET_MessageHeader *message)
{
  GNUNET_assert (ntohs (message->type) == GNUNET_MESSAGE_TYPE_VPN_HELPER);

  struct tun_pkt *pkt_tun = (struct tun_pkt *) message;
  GNUNET_HashCode *key;

  /* ethertype is ipv6 */
  if (ntohs (pkt_tun->tun.type) == 0x86dd)
  {
    struct ip6_pkt *pkt6 = (struct ip6_pkt *) message;

    GNUNET_assert (pkt6->ip6_hdr.version == 6);
    struct ip6_tcp *pkt6_tcp;
    struct ip6_udp *pkt6_udp;
    struct ip6_icmp *pkt6_icmp;

    pkt6_udp = NULL;            /* make compiler happy */
    switch (pkt6->ip6_hdr.nxthdr)
    {
    case IPPROTO_UDP:
      pkt6_udp = (struct ip6_udp *) pkt6;
      /* Send dns-packets to the service-dns */
      if (ntohs (pkt6_udp->udp_hdr.dpt) == 53)
      {
        /* 9 = 8 for the udp-header + 1 for the unsigned char data[1]; */
	GNUNET_DNS_queue_request_v6 (dns_handle,
				     &pkt6->ip6_hdr.dadr,
				     &pkt6->ip6_hdr.sadr,
				     ntohs (pkt6_udp->udp_hdr.spt),
				     ntohs (pkt6_udp->udp_hdr.len) - 8,
				     (const void*) pkt6_udp->data);

        break;
      }
      /* fall through */
    case IPPROTO_TCP:
      pkt6_tcp = (struct ip6_tcp *) pkt6;

      if ((key = address6_mapping_exists (&pkt6->ip6_hdr.dadr)) != NULL)
      {
        struct map_entry *me = GNUNET_CONTAINER_multihashmap_get (hashmap, key);

        GNUNET_assert (me != NULL);
        GNUNET_free (key);

        size_t size =
            sizeof (struct GNUNET_MESH_Tunnel *) +
            sizeof (struct GNUNET_MessageHeader) + sizeof (GNUNET_HashCode) +
            ntohs (pkt6->ip6_hdr.paylgth);

        struct GNUNET_MESH_Tunnel **cls = GNUNET_malloc (size);
        struct GNUNET_MessageHeader *hdr =
            (struct GNUNET_MessageHeader *) (cls + 1);
        GNUNET_HashCode *hc = (GNUNET_HashCode *) (hdr + 1);

        hdr->size =
            htons (sizeof (struct GNUNET_MessageHeader) +
                   sizeof (GNUNET_HashCode) + ntohs (pkt6->ip6_hdr.paylgth));

        GNUNET_MESH_ApplicationType app_type = 0;       /* fix compiler uninitialized warning... */

        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "me->addrlen is %d\n",
                    me->addrlen);
        if (me->addrlen == 0)
        {
          /* This is a mapping to a gnunet-service */
          memcpy (hc, &me->desc.service_descriptor, sizeof (GNUNET_HashCode));

          if (IPPROTO_UDP == pkt6->ip6_hdr.nxthdr &&
              (me->desc.service_type & htonl (GNUNET_DNS_SERVICE_TYPE_UDP)) &&
              (port_in_ports (me->desc.ports, pkt6_udp->udp_hdr.dpt) ||
               testBit (me->additional_ports, ntohs (pkt6_udp->udp_hdr.dpt))))
          {
            hdr->type = htons (GNUNET_MESSAGE_TYPE_VPN_SERVICE_UDP);

            memcpy (hc + 1, &pkt6_udp->udp_hdr, ntohs (pkt6_udp->udp_hdr.len));

          }
          else if (IPPROTO_TCP == pkt6->ip6_hdr.nxthdr &&
                   (me->desc.service_type & htonl (GNUNET_DNS_SERVICE_TYPE_TCP))
                   && (port_in_ports (me->desc.ports, pkt6_tcp->tcp_hdr.dpt)))
          {
            hdr->type = htons (GNUNET_MESSAGE_TYPE_VPN_SERVICE_TCP);

            memcpy (hc + 1, &pkt6_tcp->tcp_hdr, ntohs (pkt6->ip6_hdr.paylgth));

          }
          else
          {
            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "pip: %d\n",
                        port_in_ports (me->desc.ports, pkt6_tcp->tcp_hdr.dpt));
            GNUNET_assert (0);
          }
          if (me->tunnel == NULL && NULL != cls)
          {
            *cls =
                GNUNET_MESH_tunnel_create (mesh_handle,
                                           initialize_tunnel_state (16, NULL),
                                           &send_pkt_to_peer, NULL, cls);

            GNUNET_MESH_peer_request_connect_add (*cls,
                                                  (struct GNUNET_PeerIdentity *)
                                                  &me->desc.peer);
            me->tunnel = *cls;
          }
          else if (NULL != cls)
          {
            *cls = me->tunnel;
            send_pkt_to_peer (cls, (struct GNUNET_PeerIdentity *) 1, NULL);
            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                        "Queued to send IPv6 to peer %x, type %d\n",
                        *((unsigned int *) &me->desc.peer), ntohs (hdr->type));
          }
        }
        else
        {
          /* This is a mapping to a "real" address */
          struct remote_addr *s = (struct remote_addr *) hc;

          s->addrlen = me->addrlen;
          memcpy (s->addr, me->addr, me->addrlen);
          s->proto = pkt6->ip6_hdr.nxthdr;
          if (s->proto == IPPROTO_UDP)
          {
            hdr->type = htons (GNUNET_MESSAGE_TYPE_VPN_REMOTE_UDP);
            memcpy (hc + 1, &pkt6_udp->udp_hdr, ntohs (pkt6_udp->udp_hdr.len));
            app_type = GNUNET_APPLICATION_TYPE_INTERNET_UDP_GATEWAY;
            if (NULL != udp_tunnel)
              me->tunnel = udp_tunnel;
          }
          else if (s->proto == IPPROTO_TCP)
          {
            hdr->type = htons (GNUNET_MESSAGE_TYPE_VPN_REMOTE_TCP);
            memcpy (hc + 1, &pkt6_tcp->tcp_hdr, ntohs (pkt6->ip6_hdr.paylgth));
            app_type = GNUNET_APPLICATION_TYPE_INTERNET_TCP_GATEWAY;
            if (NULL != tcp_tunnel)
              me->tunnel = tcp_tunnel;
          }
          else
          {
            GNUNET_assert (0);
          }
          if (me->tunnel == NULL && NULL != cls)
          {
            *cls =
                GNUNET_MESH_tunnel_create (mesh_handle,
                                           initialize_tunnel_state (16, NULL),
                                           &send_pkt_to_peer, NULL, cls);

            GNUNET_MESH_peer_request_connect_by_type (*cls, app_type);
            me->tunnel = *cls;
            if (GNUNET_APPLICATION_TYPE_INTERNET_UDP_GATEWAY == app_type)
              udp_tunnel = *cls;
            else if (GNUNET_APPLICATION_TYPE_INTERNET_TCP_GATEWAY == app_type)
              tcp_tunnel = *cls;
          }
          else if (NULL != cls)
          {
            *cls = me->tunnel;
            send_pkt_to_peer (cls, (struct GNUNET_PeerIdentity *) 1, NULL);
          }
        }
      }
      else
      {
	char pbuf[INET6_ADDRSTRLEN];
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Packet to %s, which has no mapping\n",
		    inet_ntop (AF_INET6,
			       &pkt6->ip6_hdr.dadr,
			       pbuf,
			       sizeof (pbuf)));
      }
      break;
    case 0x3a:
      /* ICMPv6 */
      pkt6_icmp = (struct ip6_icmp *) pkt6;
      /* If this packet is an icmp-echo-request and a mapping exists, answer */
      if (pkt6_icmp->icmp_hdr.type == 0x80 &&
          (key = address6_mapping_exists (&pkt6->ip6_hdr.dadr)) != NULL)
      {
        GNUNET_free (key);
        pkt6_icmp = GNUNET_malloc (ntohs (pkt6->shdr.size));
        memcpy (pkt6_icmp, pkt6, ntohs (pkt6->shdr.size));
        GNUNET_SCHEDULER_add_now (&send_icmp6_response, pkt6_icmp);
      }
      break;
    }
  }
  /* ethertype is ipv4 */
  else if (ntohs (pkt_tun->tun.type) == 0x0800)
  {
    struct ip_pkt *pkt = (struct ip_pkt *) message;
    struct ip_udp *udp = (struct ip_udp *) message;
    struct ip_tcp *pkt_tcp;
    struct ip_udp *pkt_udp;
    struct ip_icmp *pkt_icmp;

    GNUNET_assert (pkt->ip_hdr.version == 4);

    /* Send dns-packets to the service-dns */
    if (pkt->ip_hdr.proto == IPPROTO_UDP && ntohs (udp->udp_hdr.dpt) == 53)
    {
      GNUNET_DNS_queue_request_v4 (dns_handle,
				   &pkt->ip_hdr.dadr,
				   &pkt->ip_hdr.sadr,
				   ntohs (udp->udp_hdr.spt),
				   ntohs (udp->udp_hdr.len) - 8,
				   (const void*) udp->data);
    }
    else
    {
      uint32_t dadr = pkt->ip_hdr.dadr.s_addr;
      unsigned char *c = (unsigned char *) &dadr;

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Packet to %d.%d.%d.%d, proto %x\n",
                  c[0], c[1], c[2], c[3], pkt->ip_hdr.proto);
      switch (pkt->ip_hdr.proto)
      {
      case IPPROTO_TCP:
      case IPPROTO_UDP:
        pkt_tcp = (struct ip_tcp *) pkt;
        pkt_udp = (struct ip_udp *) pkt;

        if ((key = address4_mapping_exists (dadr)) != NULL)
        {
          struct map_entry *me =
              GNUNET_CONTAINER_multihashmap_get (hashmap, key);
          GNUNET_assert (me != NULL);
          GNUNET_free (key);

          size_t size =
              sizeof (struct GNUNET_MESH_Tunnel *) +
              sizeof (struct GNUNET_MessageHeader) + sizeof (GNUNET_HashCode) +
              ntohs (pkt->ip_hdr.tot_lngth) - 4 * pkt->ip_hdr.hdr_lngth;

          struct GNUNET_MESH_Tunnel **cls = GNUNET_malloc (size);
          struct GNUNET_MessageHeader *hdr =
              (struct GNUNET_MessageHeader *) (cls + 1);
          GNUNET_HashCode *hc = (GNUNET_HashCode *) (hdr + 1);

          hdr->size =
              htons (sizeof (struct GNUNET_MessageHeader) +
                     sizeof (GNUNET_HashCode) + ntohs (pkt->ip_hdr.tot_lngth) -
                     4 * pkt->ip_hdr.hdr_lngth);

          GNUNET_MESH_ApplicationType app_type = 0; /* make compiler happy */

          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "me->addrlen is %d\n",
                      me->addrlen);
          if (me->addrlen == 0)
          {
            /* This is a mapping to a gnunet-service */
            memcpy (hc, &me->desc.service_descriptor, sizeof (GNUNET_HashCode));

            if ((IPPROTO_UDP == pkt->ip_hdr.proto) &&
                (me->desc.service_type & htonl (GNUNET_DNS_SERVICE_TYPE_UDP)) &&
                (port_in_ports (me->desc.ports, pkt_udp->udp_hdr.dpt) ||
                 testBit (me->additional_ports, ntohs (pkt_udp->udp_hdr.dpt))))
            {
              hdr->type = htons (GNUNET_MESSAGE_TYPE_VPN_SERVICE_UDP);

              memcpy (hc + 1, &pkt_udp->udp_hdr, ntohs (pkt_udp->udp_hdr.len));

            }
            else if ((IPPROTO_TCP == pkt->ip_hdr.proto) &&
                     (me->
                      desc.service_type & htonl (GNUNET_DNS_SERVICE_TYPE_TCP))
                     && (port_in_ports (me->desc.ports, pkt_tcp->tcp_hdr.dpt)))
            {
              hdr->type = htons (GNUNET_MESSAGE_TYPE_VPN_SERVICE_TCP);

              memcpy (hc + 1, &pkt_tcp->tcp_hdr,
                      ntohs (pkt->ip_hdr.tot_lngth) -
                      4 * pkt->ip_hdr.hdr_lngth);

            }
            if (me->tunnel == NULL && NULL != cls)
            {
              *cls =
                  GNUNET_MESH_tunnel_create (mesh_handle,
                                             initialize_tunnel_state (4, NULL),
                                             send_pkt_to_peer, NULL, cls);
              GNUNET_MESH_peer_request_connect_add (*cls,
                                                    (struct GNUNET_PeerIdentity
                                                     *) &me->desc.peer);
              me->tunnel = *cls;
            }
            else if (NULL != cls)
            {
              *cls = me->tunnel;
              send_pkt_to_peer (cls, (struct GNUNET_PeerIdentity *) 1, NULL);
              GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                          "Queued to send IPv4 to peer %x, type %d\n",
                          *((unsigned int *) &me->desc.peer),
                          ntohs (hdr->type));
            }
          }
          else
          {
            /* This is a mapping to a "real" address */
            struct remote_addr *s = (struct remote_addr *) hc;

            s->addrlen = me->addrlen;
            memcpy (s->addr, me->addr, me->addrlen);
            s->proto = pkt->ip_hdr.proto;
            if (s->proto == IPPROTO_UDP)
            {
              hdr->type = htons (GNUNET_MESSAGE_TYPE_VPN_REMOTE_UDP);
              memcpy (hc + 1, &pkt_udp->udp_hdr, ntohs (pkt_udp->udp_hdr.len));
              app_type = GNUNET_APPLICATION_TYPE_INTERNET_UDP_GATEWAY;
            }
            else if (s->proto == IPPROTO_TCP)
            {
              hdr->type = htons (GNUNET_MESSAGE_TYPE_VPN_REMOTE_TCP);
              memcpy (hc + 1, &pkt_tcp->tcp_hdr,
                      ntohs (pkt->ip_hdr.tot_lngth) -
                      4 * pkt->ip_hdr.hdr_lngth);
              app_type = GNUNET_APPLICATION_TYPE_INTERNET_TCP_GATEWAY;
            }
            else
              GNUNET_assert (0);
            if (me->tunnel == NULL && NULL != cls)
            {
              *cls =
                  GNUNET_MESH_tunnel_create (mesh_handle,
                                             initialize_tunnel_state (4, NULL),
                                             send_pkt_to_peer, NULL, cls);

              GNUNET_MESH_peer_request_connect_by_type (*cls, app_type);
              me->tunnel = *cls;
            }
            else if (NULL != cls)
            {
              *cls = me->tunnel;
              send_pkt_to_peer (cls, (struct GNUNET_PeerIdentity *) 1, NULL);
            }
          }
        }
        else
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Packet to %x which has no mapping\n", dadr);
        }
        break;
      case 0x01:
        /* ICMP */
        pkt_icmp = (struct ip_icmp *) pkt;
        if (pkt_icmp->icmp_hdr.type == 0x8 &&
            (key = address4_mapping_exists (dadr)) != NULL)
        {
          GNUNET_free (key);
          pkt_icmp = GNUNET_malloc (ntohs (pkt->shdr.size));
          memcpy (pkt_icmp, pkt, ntohs (pkt->shdr.size));
          GNUNET_SCHEDULER_add_now (&send_icmp4_response, pkt_icmp);
        }
        break;
      }
    }
  }
}



static void
collect_mappings (void *cls GNUNET_UNUSED,
                  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;

  struct map_entry *me = GNUNET_CONTAINER_heap_remove_root (heap);

  /* This is free()ed memory! */
  me->heap_node = NULL;

  /* FIXME! GNUNET_MESH_close_tunnel(me->tunnel); */

  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (hashmap, &me->hash, me));

  GNUNET_free (me);
}

void
send_icmp4_response (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;

  struct ip_icmp *request = cls;

  struct ip_icmp *response = alloca (ntohs (request->shdr.size));

  GNUNET_assert (response != NULL);
  memset (response, 0, ntohs (request->shdr.size));

  response->shdr.size = request->shdr.size;
  response->shdr.type = htons (GNUNET_MESSAGE_TYPE_VPN_HELPER);

  response->tun.flags = 0;
  response->tun.type = htons (0x0800);

  response->ip_hdr.hdr_lngth = 5;
  response->ip_hdr.version = 4;
  response->ip_hdr.proto = 0x01;
  response->ip_hdr.dadr = request->ip_hdr.sadr;
  response->ip_hdr.sadr = request->ip_hdr.dadr;
  response->ip_hdr.tot_lngth = request->ip_hdr.tot_lngth;

  response->ip_hdr.chks =
      GNUNET_CRYPTO_crc16_n ((uint16_t *) & response->ip_hdr, 20);

  response->icmp_hdr.code = 0;
  response->icmp_hdr.type = 0x0;

  /* Magic, more Magic! */
  response->icmp_hdr.chks = request->icmp_hdr.chks + 0x8;

  /* Copy the rest of the packet */
  memcpy (response + 1, request + 1,
          ntohs (request->shdr.size) - sizeof (struct ip_icmp));

  (void) GNUNET_HELPER_send (helper_handle,
			     &response->shdr,
			     GNUNET_YES,
			     NULL, NULL);
  GNUNET_free (request);
}

void
send_icmp6_response (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;

  struct ip6_icmp *request = cls;

  struct ip6_icmp *response = alloca (ntohs (request->shdr.size));

  GNUNET_assert (response != NULL);
  memset (response, 0, ntohs (request->shdr.size));

  response->shdr.size = request->shdr.size;
  response->shdr.type = htons (GNUNET_MESSAGE_TYPE_VPN_HELPER);

  response->tun.flags = 0;
  response->tun.type = htons (0x86dd);

  response->ip6_hdr.hoplmt = 255;
  response->ip6_hdr.paylgth = request->ip6_hdr.paylgth;
  response->ip6_hdr.nxthdr = 0x3a;
  response->ip6_hdr.version = 6;
  memcpy (&response->ip6_hdr.sadr, &request->ip6_hdr.dadr, 16);
  memcpy (&response->ip6_hdr.dadr, &request->ip6_hdr.sadr, 16);

  response->icmp_hdr.code = 0;
  response->icmp_hdr.type = 0x81;

  /* Magic, more Magic! */
  response->icmp_hdr.chks = request->icmp_hdr.chks - 0x1;

  /* Copy the rest of the packet */
  memcpy (response + 1, request + 1,
          ntohs (request->shdr.size) - sizeof (struct ip6_icmp));

  (void) GNUNET_HELPER_send (helper_handle,
			     &response->shdr,
			     GNUNET_YES,
			     NULL, NULL);
  GNUNET_free (request);
}

/**
 * cls is the pointer to a GNUNET_MessageHeader that is
 * followed by the service-descriptor and the packet that should be sent;
 */
static size_t
send_pkt_to_peer_notify_callback (void *cls, size_t size, void *buf)
{
  struct GNUNET_MESH_Tunnel **tunnel = cls;

  struct tunnel_state *ts = GNUNET_MESH_tunnel_get_data (*tunnel);

  ts->th = NULL;

  if (NULL != buf)
  {
    struct GNUNET_MessageHeader *hdr =
        (struct GNUNET_MessageHeader *) (tunnel + 1);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "send_pkt_to_peer_notify_callback: buf = %x; size = %u;\n", buf,
                size);
    GNUNET_assert (size >= ntohs (hdr->size));
    memcpy (buf, hdr, ntohs (hdr->size));
    size = ntohs (hdr->size);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sent!\n");
  }
  else
    size = 0;

  if (NULL != ts->head)
  {
    struct tunnel_notify_queue *element = ts->head;

    GNUNET_CONTAINER_DLL_remove (ts->head, ts->tail, element);

    ts->th =
        GNUNET_MESH_notify_transmit_ready (*tunnel, GNUNET_NO, 42,
                                           GNUNET_TIME_relative_divide
                                           (GNUNET_CONSTANTS_MAX_CORK_DELAY, 2),
                                           (const struct GNUNET_PeerIdentity *)
                                           NULL, element->len,
                                           send_pkt_to_peer_notify_callback,
                                           element->cls);

    /* save the handle */
    GNUNET_free (element);
  }
  GNUNET_free (cls);

  return size;
}

unsigned int
port_in_ports (uint64_t ports, uint16_t port)
{
  uint16_t *ps = (uint16_t *) & ports;

  return ports == 0 || ps[0] == port || ps[1] == port || ps[2] == port ||
      ps[3] == port;
}

void
send_pkt_to_peer (void *cls, const struct GNUNET_PeerIdentity *peer,
                  const struct GNUNET_ATS_Information *atsi GNUNET_UNUSED)
{
  /* peer == NULL means that all peers in this request are connected */
  if (peer == NULL)
    return;
  struct GNUNET_MESH_Tunnel **tunnel = cls;
  struct GNUNET_MessageHeader *hdr =
      (struct GNUNET_MessageHeader *) (tunnel + 1);

  GNUNET_assert (NULL != tunnel);
  GNUNET_assert (NULL != *tunnel);

  struct tunnel_state *ts = GNUNET_MESH_tunnel_get_data (*tunnel);

  if (NULL == ts->th)
  {
    ts->th =
        GNUNET_MESH_notify_transmit_ready (*tunnel, GNUNET_NO, 42,
                                           GNUNET_TIME_relative_divide
                                           (GNUNET_CONSTANTS_MAX_CORK_DELAY, 2),
                                           (const struct GNUNET_PeerIdentity *)
                                           NULL, ntohs (hdr->size),
                                           send_pkt_to_peer_notify_callback,
                                           cls);
  }
  else
  {
    struct tunnel_notify_queue *element = GNUNET_malloc (sizeof *element);

    element->cls = cls;
    element->len = ntohs (hdr->size);

    GNUNET_CONTAINER_DLL_insert_tail (ts->head, ts->tail, element);
  }
}

/**
 * Create a new Address from an answer-packet
 */
void
new_ip6addr (struct in6_addr *v6addr,
	     const GNUNET_HashCode * peer,
             const GNUNET_HashCode * service_desc)
{                               /* {{{ */
  unsigned char *buf = (unsigned char*) v6addr;
  char *ipv6addr;
  unsigned long long ipv6prefix;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_string (cfg, "vpn", "IPV6ADDR",
                                                        &ipv6addr));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_number (cfg, "vpn",
                                                        "IPV6PREFIX",
                                                        &ipv6prefix));
  GNUNET_assert (ipv6prefix < 127);
  ipv6prefix = (ipv6prefix + 7) / 8;

  inet_pton (AF_INET6, ipv6addr, buf);
  GNUNET_free (ipv6addr);

  int peer_length = 16 - ipv6prefix - 6;

  if (peer_length <= 0)
    peer_length = 0;

  int service_length = 16 - ipv6prefix - peer_length;

  if (service_length <= 0)
    service_length = 0;

  memcpy (buf + ipv6prefix, service_desc, service_length);
  memcpy (buf + ipv6prefix + service_length, peer, peer_length);
}

/*}}}*/


/**
 * Create a new Address from an answer-packet
 */
void
new_ip6addr_remote (struct in6_addr *v6addr,
		    unsigned char *addr, char addrlen)
{                               /* {{{ */
  unsigned char *buf = (unsigned char*) v6addr;
  char *ipv6addr;
  unsigned long long ipv6prefix;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_string (cfg, "vpn", "IPV6ADDR",
                                                        &ipv6addr));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_number (cfg, "vpn",
                                                        "IPV6PREFIX",
                                                        &ipv6prefix));
  GNUNET_assert (ipv6prefix < 127);
  ipv6prefix = (ipv6prefix + 7) / 8;

  inet_pton (AF_INET6, ipv6addr, buf);
  GNUNET_free (ipv6addr);

  int local_length = 16 - ipv6prefix;

  memcpy (buf + ipv6prefix, addr, GNUNET_MIN (addrlen, local_length));
}

/*}}}*/

/**
 * Create a new Address from an answer-packet
 */
void
new_ip4addr_remote (unsigned char *buf, unsigned char *addr, char addrlen)
{                               /* {{{ */
  char *ipv4addr;
  char *ipv4mask;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_string (cfg, "vpn", "IPV4ADDR",
                                                        &ipv4addr));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_string (cfg, "vpn", "IPV4MASK",
                                                        &ipv4mask));
  uint32_t mask;

  inet_pton (AF_INET, ipv4addr, buf);
  int r = inet_pton (AF_INET, ipv4mask, &mask);

  mask = htonl (mask);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "inet_pton: %d; %m; mask: %08x\n", r,
              mask);

  GNUNET_free (ipv4addr);

  int c;

  if (mask)
  {
    mask = (mask ^ (mask - 1)) >> 1;
    for (c = 0; mask; c++)
    {
      mask >>= 1;
    }
  }
  else
  {
    c = CHAR_BIT * sizeof (mask);
  }

  c = 32 - c;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "The mask %s has %d leading 1s.\n",
              ipv4mask, c);

  GNUNET_free (ipv4mask);

  if (c % 8 == 0)
    c = c / 8;
  else
    GNUNET_assert (0);

  memcpy (buf + c, addr, GNUNET_MIN (addrlen, 4 - c));
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
process_answer (void *cls, 
		const struct answer_packet *pkt)
{
  struct answer_packet_list *list;

  /* This answer is about a .gnunet-service
   *
   * It contains an almost complete DNS-Response, we have to fill in the ip
   * at the offset pkt->addroffset
   */
  if (pkt->subtype == GNUNET_DNS_ANSWER_TYPE_SERVICE)
  {

    GNUNET_HashCode key;

    memset (&key, 0, sizeof (GNUNET_HashCode));

    list =
        GNUNET_malloc (htons (pkt->hdr.size) +
                       sizeof (struct answer_packet_list) -
                       sizeof (struct answer_packet));
    memcpy (&list->pkt, pkt, htons (pkt->hdr.size));

    unsigned char *c = ((unsigned char *) &list->pkt) + ntohs (pkt->addroffset);
    unsigned char *k = (unsigned char *) &key;

    new_ip6addr ((struct in6_addr*) c, 
		 &pkt->service_descr.peer,
                 &pkt->service_descr.service_descriptor);
    /*
     * Copy the newly generated ip-address to the key backwarts (as only the first part is hashed)
     */
    unsigned int i;

    for (i = 0; i < 16; i++)
      k[15 - i] = c[i];

    uint16_t namelen = strlen ((char *) pkt->data + 12) + 1;

    struct map_entry *value =
        GNUNET_malloc (sizeof (struct map_entry) + namelen);
    char *name = (char *) (value + 1);

    value->namelen = namelen;
    memcpy (name, pkt->data + 12, namelen);

    memcpy (&value->desc, &pkt->service_descr,
            sizeof (struct GNUNET_vpn_service_descriptor));

    memset (value->additional_ports, 0, 8192);

    memcpy (&value->hash, &key, sizeof (GNUNET_HashCode));

    if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains (hashmap, &key))
    {
      GNUNET_CONTAINER_multihashmap_put (hashmap, &key, value,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);

      value->heap_node =
          GNUNET_CONTAINER_heap_insert (heap, value,
                                        GNUNET_TIME_absolute_get ().abs_value);
      if (GNUNET_CONTAINER_heap_get_size (heap) > max_mappings)
        GNUNET_SCHEDULER_add_now (collect_mappings, NULL);
    }
    else
      GNUNET_free (value);


    list->pkt.subtype = GNUNET_DNS_ANSWER_TYPE_IP;


  }
  else if (pkt->subtype == GNUNET_DNS_ANSWER_TYPE_REV)
  {
    GNUNET_HashCode key;

    memset (&key, 0, sizeof key);
    unsigned char *k = (unsigned char *) &key;
    const unsigned char *s = pkt->data + 12;
    int i = 0;

    /* Whoever designed the reverse IPv6-lookup is batshit insane */
    for (i = 0; i < 16; i++)
    {
      unsigned char c1 = s[(4 * i) + 1];
      unsigned char c2 = s[(4 * i) + 3];

      if (c1 <= '9')
        k[i] = c1 - '0';
      else
        k[i] = c1 - 87;         /* 87 is the difference between 'a' and 10 */
      if (c2 <= '9')
        k[i] += 16 * (c2 - '0');
      else
        k[i] += 16 * (c2 - 87);
    }

    struct map_entry *map_entry =
        GNUNET_CONTAINER_multihashmap_get (hashmap, &key);
    uint16_t offset = ntohs (pkt->addroffset);

    if (map_entry == NULL)
      return;

    GNUNET_CONTAINER_heap_update_cost (heap, map_entry->heap_node,
                                       GNUNET_TIME_absolute_get ().abs_value);


    unsigned short namelen = htons (map_entry->namelen);
    char *name = (char *) (map_entry + 1);

    list =
        GNUNET_malloc (sizeof (struct answer_packet_list) -
                       sizeof (struct answer_packet) + offset + 2 +
                       ntohs (namelen));

    struct answer_packet *rpkt = &list->pkt;

    /* The offset points to the first byte belonging to the address */
    memcpy (rpkt, pkt, offset - 1);

    rpkt->subtype = GNUNET_DNS_ANSWER_TYPE_IP;
    rpkt->hdr.size = ntohs (offset + 2 + ntohs (namelen));

    memcpy (((char *) rpkt) + offset, &namelen, 2);
    memcpy (((char *) rpkt) + offset + 2, name, ntohs (namelen));

  }
  else if (pkt->subtype == GNUNET_DNS_ANSWER_TYPE_IP)
  {
    list =
        GNUNET_malloc (htons (pkt->hdr.size) +
                       sizeof (struct answer_packet_list) -
                       sizeof (struct answer_packet));
    memcpy (&list->pkt, pkt, htons (pkt->hdr.size));
  }
  else if (pkt->subtype == GNUNET_DNS_ANSWER_TYPE_REMOTE_AAAA)
  {

    GNUNET_HashCode key;

    memset (&key, 0, sizeof (GNUNET_HashCode));

    list =
        GNUNET_malloc (htons (pkt->hdr.size) +
                       sizeof (struct answer_packet_list) -
                       sizeof (struct answer_packet));

    memcpy (&list->pkt, pkt, htons (pkt->hdr.size));
    list->pkt.subtype = GNUNET_DNS_ANSWER_TYPE_IP;

    unsigned char *c = ((unsigned char *) &list->pkt) + ntohs (list->pkt.addroffset);

    new_ip6addr_remote ((struct in6_addr*) c,
			list->pkt.addr, list->pkt.addrsize);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "New mapping to %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
                c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8], c[9],
                c[10], c[11], c[12], c[13], c[14], c[15]);
    unsigned char *k = (unsigned char *) &key;

    /*
     * Copy the newly generated ip-address to the key backwards (as only the first part is used in the hash-table)
     */
    unsigned int i;

    for (i = 0; i < 16; i++)
      k[15 - i] = c[i];

    uint16_t namelen = strlen ((char *) pkt->data + 12) + 1;

    struct map_entry *value =
        GNUNET_malloc (sizeof (struct map_entry) + namelen);
    char *name = (char *) (value + 1);

    value->namelen = namelen;
    memcpy (name, pkt->data + 12, namelen);

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Setting addrlen to %d\n",
                pkt->addrsize);
    value->addrlen = pkt->addrsize;
    memcpy (&value->addr, &pkt->addr, pkt->addrsize);
    memset (value->additional_ports, 0, 8192);

    memcpy (&value->hash, &key, sizeof (GNUNET_HashCode));

    if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains (hashmap, &key))
    {
      GNUNET_CONTAINER_multihashmap_put (hashmap, &key, value,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
      value->heap_node =
          GNUNET_CONTAINER_heap_insert (heap, value,
                                        GNUNET_TIME_absolute_get ().abs_value);
      if (GNUNET_CONTAINER_heap_get_size (heap) > max_mappings)
        GNUNET_SCHEDULER_add_now (collect_mappings, NULL);
    }
    else
      GNUNET_free (value);


  }
  else if (pkt->subtype == GNUNET_DNS_ANSWER_TYPE_REMOTE_A)
  {
    list =
        GNUNET_malloc (htons (pkt->hdr.size) +
                       sizeof (struct answer_packet_list) -
                       sizeof (struct answer_packet));

    memcpy (&list->pkt, pkt, htons (pkt->hdr.size));
    list->pkt.subtype = GNUNET_DNS_ANSWER_TYPE_IP;

    GNUNET_HashCode key;

    memset (&key, 0, sizeof (GNUNET_HashCode));

    unsigned char *c = ((unsigned char *) &list->pkt) + ntohs (pkt->addroffset);

    new_ip4addr_remote (c, list->pkt.addr, pkt->addrsize);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "New mapping to %d.%d.%d.%d\n", c[0],
                c[1], c[2], c[3]);
    unsigned char *k = (unsigned char *) &key;

    /*
     * Copy the newly generated ip-address to the key backwards (as only the first part is used in the hash-table)
     */
    unsigned int i;

    for (i = 0; i < 4; i++)
      k[3 - i] = c[i];

    uint16_t namelen = strlen ((char *) pkt->data + 12) + 1;

    struct map_entry *value =
        GNUNET_malloc (sizeof (struct map_entry) + namelen);
    char *name = (char *) (value + 1);

    value->namelen = namelen;
    memcpy (name, pkt->data + 12, namelen);

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Setting addrlen to %d\n",
                pkt->addrsize);
    value->addrlen = pkt->addrsize;
    memcpy (&value->addr, &pkt->addr, pkt->addrsize);
    memset (value->additional_ports, 0, 8192);

    memcpy (&value->hash, &key, sizeof (GNUNET_HashCode));

    if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains (hashmap, &key))
    {
      GNUNET_CONTAINER_multihashmap_put (hashmap, &key, value,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
      value->heap_node =
          GNUNET_CONTAINER_heap_insert (heap, value,
                                        GNUNET_TIME_absolute_get ().abs_value);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Mapping is saved in the hashmap with key %08x.\n",
                  *((uint32_t *) (&key)));
      if (GNUNET_CONTAINER_heap_get_size (heap) > max_mappings)
        GNUNET_SCHEDULER_add_now (collect_mappings, NULL);
    }
    else
      GNUNET_free (value);

  }
  else
  {
    GNUNET_break (0);
    return;
  }

  GNUNET_CONTAINER_DLL_insert_after (answer_proc_head, answer_proc_tail,
                                     answer_proc_tail, list);

}


/**
 * @brief Add the port to the list of additional ports in the map_entry
 *
 * @param me the map_entry
 * @param port the port in host-byte-order
 */
static void
add_additional_port (struct map_entry *me, uint16_t port)
{
  setBit (me->additional_ports, port);
}

static int
receive_udp_back (void *cls GNUNET_UNUSED, struct GNUNET_MESH_Tunnel *tunnel,
                  void **tunnel_ctx, const struct GNUNET_PeerIdentity *sender,
                  const struct GNUNET_MessageHeader *message,
                  const struct GNUNET_ATS_Information *atsi GNUNET_UNUSED)
{
  GNUNET_HashCode *desc = (GNUNET_HashCode *) (message + 1);
  struct remote_addr *s = (struct remote_addr *) desc;
  struct udp_pkt *pkt = (struct udp_pkt *) (desc + 1);
  const struct GNUNET_PeerIdentity *other = sender;
  struct tunnel_state *ts = *tunnel_ctx;

  if (16 == ts->addrlen)
  {
    size_t size =
        sizeof (struct ip6_udp) + ntohs (pkt->len) - 1 -
        sizeof (struct udp_pkt);

    struct ip6_udp *pkt6 = alloca (size);

    GNUNET_assert (pkt6 != NULL);

    if (ntohs (message->type) == GNUNET_MESSAGE_TYPE_VPN_SERVICE_UDP_BACK)
      new_ip6addr (&pkt6->ip6_hdr.sadr, &other->hashPubKey, desc);
    else
      new_ip6addr_remote (&pkt6->ip6_hdr.sadr, s->addr, s->addrlen);

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Relaying calc:%d gnu:%d udp:%d bytes!\n", size,
                ntohs (message->size), ntohs (pkt->len));

    pkt6->shdr.type = htons (GNUNET_MESSAGE_TYPE_VPN_HELPER);
    pkt6->shdr.size = htons (size);

    pkt6->tun.flags = 0;
    pkt6->tun.type = htons (0x86dd);

    pkt6->ip6_hdr.version = 6;
    pkt6->ip6_hdr.tclass_h = 0;
    pkt6->ip6_hdr.tclass_l = 0;
    pkt6->ip6_hdr.flowlbl = 0;
    pkt6->ip6_hdr.paylgth = pkt->len;
    pkt6->ip6_hdr.nxthdr = IPPROTO_UDP;
    pkt6->ip6_hdr.hoplmt = 0xff;

    {
      char *ipv6addr;

      GNUNET_assert (GNUNET_OK ==
                     GNUNET_CONFIGURATION_get_value_string (cfg, "vpn",
                                                            "IPV6ADDR",
                                                            &ipv6addr));
      inet_pton (AF_INET6, ipv6addr, &pkt6->ip6_hdr.dadr);
      GNUNET_free (ipv6addr);
    }
    memcpy (&pkt6->udp_hdr, pkt, ntohs (pkt->len));

    GNUNET_HashCode *key = address6_mapping_exists (&pkt6->ip6_hdr.sadr);

    GNUNET_assert (key != NULL);

    struct map_entry *me = GNUNET_CONTAINER_multihashmap_get (hashmap, key);

    GNUNET_CONTAINER_heap_update_cost (heap, me->heap_node,
                                       GNUNET_TIME_absolute_get ().abs_value);

    GNUNET_free (key);

    GNUNET_assert (me != NULL);
    if (ntohs (message->type) == GNUNET_MESSAGE_TYPE_VPN_SERVICE_UDP_BACK)
    {
      GNUNET_assert (me->desc.
                     service_type & htonl (GNUNET_DNS_SERVICE_TYPE_UDP));
      if (!port_in_ports (me->desc.ports, pkt6->udp_hdr.spt) &&
          !testBit (me->additional_ports, ntohs (pkt6->udp_hdr.spt)))
      {
        add_additional_port (me, ntohs (pkt6->udp_hdr.spt));
      }
    }

    pkt6->udp_hdr.crc = 0;
    uint32_t sum = 0;

    sum =
        GNUNET_CRYPTO_crc16_step (sum, (uint16_t *) & pkt6->ip6_hdr.sadr, 16);
    sum =
        GNUNET_CRYPTO_crc16_step (sum, (uint16_t *) & pkt6->ip6_hdr.dadr, 16);
    uint32_t tmp = (pkt6->udp_hdr.len & 0xffff);

    sum = GNUNET_CRYPTO_crc16_step (sum, (uint16_t *) & tmp, 4);
    tmp = htons (((pkt6->ip6_hdr.nxthdr & 0x00ff)));
    sum = GNUNET_CRYPTO_crc16_step (sum, (uint16_t *) & tmp, 4);

    sum =
        GNUNET_CRYPTO_crc16_step (sum, (uint16_t *) & pkt6->udp_hdr,
                                   ntohs (pkt->len));
    pkt6->udp_hdr.crc = GNUNET_CRYPTO_crc16_finish (sum);
    
    (void) GNUNET_HELPER_send (helper_handle,
			       &pkt6->shdr,
			       GNUNET_YES,
			       NULL, NULL);
  }
  else
  {
    size_t size =
        sizeof (struct ip_udp) + ntohs (pkt->len) - 1 - sizeof (struct udp_pkt);

    struct ip_udp *pkt4 = alloca (size);

    GNUNET_assert (pkt4 != NULL);

    GNUNET_assert (ntohs (message->type) ==
                   GNUNET_MESSAGE_TYPE_VPN_REMOTE_UDP_BACK);
    uint32_t sadr;

    new_ip4addr_remote ((unsigned char *) &sadr, s->addr, s->addrlen);
    pkt4->ip_hdr.sadr.s_addr = sadr;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Relaying calc:%d gnu:%d udp:%d bytes!\n", size,
                ntohs (message->size), ntohs (pkt->len));

    pkt4->shdr.type = htons (GNUNET_MESSAGE_TYPE_VPN_HELPER);
    pkt4->shdr.size = htons (size);

    pkt4->tun.flags = 0;
    pkt4->tun.type = htons (0x0800);

    pkt4->ip_hdr.version = 4;
    pkt4->ip_hdr.hdr_lngth = 5;
    pkt4->ip_hdr.diff_serv = 0;
    pkt4->ip_hdr.tot_lngth = htons (20 + ntohs (pkt->len));
    pkt4->ip_hdr.ident = 0;
    pkt4->ip_hdr.flags = 0;
    pkt4->ip_hdr.frag_off = 0;
    pkt4->ip_hdr.ttl = 255;
    pkt4->ip_hdr.proto = IPPROTO_UDP;
    pkt4->ip_hdr.chks = 0;      /* Will be calculated later */

    {
      char *ipv4addr;
      uint32_t dadr;

      GNUNET_assert (GNUNET_OK ==
                     GNUNET_CONFIGURATION_get_value_string (cfg, "vpn",
                                                            "IPV4ADDR",
                                                            &ipv4addr));
      inet_pton (AF_INET, ipv4addr, &dadr);
      GNUNET_free (ipv4addr);
      pkt4->ip_hdr.dadr.s_addr = dadr;
    }
    memcpy (&pkt4->udp_hdr, pkt, ntohs (pkt->len));

    GNUNET_HashCode *key = address4_mapping_exists (pkt4->ip_hdr.sadr.s_addr);

    GNUNET_assert (key != NULL);

    struct map_entry *me = GNUNET_CONTAINER_multihashmap_get (hashmap, key);

    GNUNET_CONTAINER_heap_update_cost (heap, me->heap_node,
                                       GNUNET_TIME_absolute_get ().abs_value);

    GNUNET_free (key);

    GNUNET_assert (me != NULL);

    pkt4->udp_hdr.crc = 0;      /* Optional for IPv4 */

    pkt4->ip_hdr.chks =
        GNUNET_CRYPTO_crc16_n ((uint16_t *) & pkt4->ip_hdr, 5 * 4);

    (void) GNUNET_HELPER_send (helper_handle,
			       &pkt4->shdr,
			       GNUNET_YES,
			       NULL, NULL);
  }

  return GNUNET_OK;
}

static int
receive_tcp_back (void *cls GNUNET_UNUSED, struct GNUNET_MESH_Tunnel *tunnel,
                  void **tunnel_ctx,
                  const struct GNUNET_PeerIdentity *sender GNUNET_UNUSED,
                  const struct GNUNET_MessageHeader *message,
                  const struct GNUNET_ATS_Information *atsi GNUNET_UNUSED)
{
  GNUNET_HashCode *desc = (GNUNET_HashCode *) (message + 1);
  struct remote_addr *s = (struct remote_addr *) desc;
  struct tcp_pkt *pkt = (struct tcp_pkt *) (desc + 1);
  const struct GNUNET_PeerIdentity *other = sender;
  struct tunnel_state *ts = *tunnel_ctx;

  size_t pktlen =
      ntohs (message->size) - sizeof (struct GNUNET_MessageHeader) -
      sizeof (GNUNET_HashCode);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received TCP-Packet back, addrlen = %d\n", s->addrlen);

  if (ntohs (message->type) == GNUNET_MESSAGE_TYPE_VPN_SERVICE_TCP_BACK ||
      ts->addrlen == 16)
  {
    size_t size = pktlen + sizeof (struct ip6_tcp) - 1;

    struct ip6_tcp *pkt6 = alloca (size);

    memset (pkt6, 0, size);

    GNUNET_assert (pkt6 != NULL);

    if (ntohs (message->type) == GNUNET_MESSAGE_TYPE_VPN_SERVICE_TCP_BACK)
      new_ip6addr (&pkt6->ip6_hdr.sadr, &other->hashPubKey, desc);
    else
      new_ip6addr_remote (&pkt6->ip6_hdr.sadr, s->addr, s->addrlen);

    pkt6->shdr.type = htons (GNUNET_MESSAGE_TYPE_VPN_HELPER);
    pkt6->shdr.size = htons (size);

    pkt6->tun.flags = 0;
    pkt6->tun.type = htons (0x86dd);

    pkt6->ip6_hdr.version = 6;
    pkt6->ip6_hdr.tclass_h = 0;
    pkt6->ip6_hdr.tclass_l = 0;
    pkt6->ip6_hdr.flowlbl = 0;
    pkt6->ip6_hdr.paylgth = htons (pktlen);
    pkt6->ip6_hdr.nxthdr = IPPROTO_TCP;
    pkt6->ip6_hdr.hoplmt = 0xff;

    {
      char *ipv6addr;

      GNUNET_assert (GNUNET_OK ==
                     GNUNET_CONFIGURATION_get_value_string (cfg, "vpn",
                                                            "IPV6ADDR",
                                                            &ipv6addr));
      inet_pton (AF_INET6, ipv6addr, &pkt6->ip6_hdr.dadr);
      GNUNET_free (ipv6addr);
    }
    memcpy (&pkt6->tcp_hdr, pkt, pktlen);

    GNUNET_HashCode *key = address6_mapping_exists (&pkt6->ip6_hdr.sadr);

    GNUNET_assert (key != NULL);

    struct map_entry *me = GNUNET_CONTAINER_multihashmap_get (hashmap, key);

    GNUNET_CONTAINER_heap_update_cost (heap, me->heap_node,
                                       GNUNET_TIME_absolute_get ().abs_value);

    GNUNET_free (key);

    GNUNET_assert (me != NULL);
    if (ntohs (message->type) == GNUNET_MESSAGE_TYPE_VPN_SERVICE_UDP_BACK)
      GNUNET_assert (me->desc.
                     service_type & htonl (GNUNET_DNS_SERVICE_TYPE_TCP));

    pkt6->tcp_hdr.crc = 0;
    uint32_t sum = 0;
    uint32_t tmp;

    sum =
        GNUNET_CRYPTO_crc16_step (sum, (uint16_t *) & pkt6->ip6_hdr.sadr, 16);
    sum =
        GNUNET_CRYPTO_crc16_step (sum, (uint16_t *) & pkt6->ip6_hdr.dadr, 16);
    tmp = htonl (pktlen);
    sum = GNUNET_CRYPTO_crc16_step (sum, (uint16_t *) & tmp, 4);
    tmp = htonl (((pkt6->ip6_hdr.nxthdr & 0x000000ff)));
    sum = GNUNET_CRYPTO_crc16_step (sum, (uint16_t *) & tmp, 4);

    sum =
        GNUNET_CRYPTO_crc16_step (sum, (uint16_t *) & pkt6->tcp_hdr,
                                   ntohs (pkt6->ip6_hdr.paylgth));
    pkt6->tcp_hdr.crc = GNUNET_CRYPTO_crc16_finish (sum);

    (void) GNUNET_HELPER_send (helper_handle,
			       &pkt6->shdr,
			       GNUNET_YES,
			       NULL, NULL);
  }
  else
  {
    size_t size = pktlen + sizeof (struct ip_tcp) - 1;

    struct ip_tcp *pkt4 = alloca (size);

    GNUNET_assert (pkt4 != NULL);
    memset (pkt4, 0, size);

    GNUNET_assert (ntohs (message->type) ==
                   GNUNET_MESSAGE_TYPE_VPN_REMOTE_TCP_BACK);
    uint32_t sadr;

    new_ip4addr_remote ((unsigned char *) &sadr, s->addr, s->addrlen);
    pkt4->ip_hdr.sadr.s_addr = sadr;

    pkt4->shdr.type = htons (GNUNET_MESSAGE_TYPE_VPN_HELPER);
    pkt4->shdr.size = htons (size);

    pkt4->tun.flags = 0;
    pkt4->tun.type = htons (0x0800);

    pkt4->ip_hdr.version = 4;
    pkt4->ip_hdr.hdr_lngth = 5;
    pkt4->ip_hdr.diff_serv = 0;
    pkt4->ip_hdr.tot_lngth = htons (20 + pktlen);
    pkt4->ip_hdr.ident = 0;
    pkt4->ip_hdr.flags = 0;
    pkt4->ip_hdr.frag_off = 0;
    pkt4->ip_hdr.ttl = 255;
    pkt4->ip_hdr.proto = IPPROTO_TCP;
    pkt4->ip_hdr.chks = 0;      /* Will be calculated later */

    {
      char *ipv4addr;
      uint32_t dadr;

      GNUNET_assert (GNUNET_OK ==
                     GNUNET_CONFIGURATION_get_value_string (cfg, "vpn",
                                                            "IPV4ADDR",
                                                            &ipv4addr));
      inet_pton (AF_INET, ipv4addr, &dadr);
      GNUNET_free (ipv4addr);
      pkt4->ip_hdr.dadr.s_addr = dadr;
    }

    memcpy (&pkt4->tcp_hdr, pkt, pktlen);

    GNUNET_HashCode *key = address4_mapping_exists (pkt4->ip_hdr.sadr.s_addr);

    GNUNET_assert (key != NULL);

    struct map_entry *me = GNUNET_CONTAINER_multihashmap_get (hashmap, key);

    GNUNET_CONTAINER_heap_update_cost (heap, me->heap_node,
                                       GNUNET_TIME_absolute_get ().abs_value);

    GNUNET_free (key);

    GNUNET_assert (me != NULL);
    pkt4->tcp_hdr.crc = 0;
    uint32_t sum = 0;
    uint32_t tmp;

    sum = GNUNET_CRYPTO_crc16_step (sum, (uint16_t *) &pkt4->ip_hdr.sadr, 4);
    sum = GNUNET_CRYPTO_crc16_step (sum, (uint16_t *) &pkt4->ip_hdr.dadr, 4);

    tmp = (0x06 << 16) | (0xffff & pktlen);     // 0x06 for TCP?

    tmp = htonl (tmp);

    sum = GNUNET_CRYPTO_crc16_step (sum, (uint16_t *) & tmp, 4);

    sum = GNUNET_CRYPTO_crc16_step (sum, (uint16_t *) & pkt4->tcp_hdr, pktlen);
    pkt4->tcp_hdr.crc = GNUNET_CRYPTO_crc16_finish (sum);

    pkt4->ip_hdr.chks =
        GNUNET_CRYPTO_crc16_n ((uint16_t *) & pkt4->ip_hdr, 5 * 4);

    (void) GNUNET_HELPER_send (helper_handle,
			       &pkt4->shdr,
			       GNUNET_YES,
			       NULL, NULL);

  }

  return GNUNET_OK;
}

static void *
new_tunnel (void *cls, struct GNUNET_MESH_Tunnel *tunnel,
            const struct GNUNET_PeerIdentity *initiator,
            const struct GNUNET_ATS_Information *atsi)
{
  /* Why should anyone open an inbound tunnel to vpn? */
  GNUNET_break (0);
  return NULL;
}

static void
cleaner (void *cls, const struct GNUNET_MESH_Tunnel *tunnel, void *tunnel_ctx)
{
  /* Why should anyone open an inbound tunnel to vpn? */
  GNUNET_break (0);
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
run (void *cls, char *const *args GNUNET_UNUSED,
     const char *cfgfile GNUNET_UNUSED,
     const struct GNUNET_CONFIGURATION_Handle *cfg_)
{
  static const struct GNUNET_MESH_MessageHandler handlers[] = {
    {receive_udp_back, GNUNET_MESSAGE_TYPE_VPN_SERVICE_UDP_BACK, 0},
    {receive_tcp_back, GNUNET_MESSAGE_TYPE_VPN_SERVICE_TCP_BACK, 0},
    {receive_udp_back, GNUNET_MESSAGE_TYPE_VPN_REMOTE_UDP_BACK, 0},
    {receive_tcp_back, GNUNET_MESSAGE_TYPE_VPN_REMOTE_TCP_BACK, 0},
    {NULL, 0, 0}
  };
  static const GNUNET_MESH_ApplicationType types[] = {
    GNUNET_APPLICATION_TYPE_END
  };
  char *ifname;
  char *ipv6addr;
  char *ipv6prefix;
  char *ipv4addr;
  char *ipv4mask;

  mesh_handle =
      GNUNET_MESH_connect (cfg_, 42, NULL, new_tunnel, cleaner, handlers,
                           types);
  cfg = cfg_;
  hashmap = GNUNET_CONTAINER_multihashmap_create (65536);
  heap = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  GNUNET_CONFIGURATION_get_value_number (cfg, "vpn", "MAX_MAPPINGg",
                                         &max_mappings);
  udp_connections = GNUNET_CONTAINER_multihashmap_create (65536);
  dns_handle = GNUNET_DNS_connect (cfg,
				   &process_answer,
				   NULL);
  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "vpn", "IFNAME", &ifname))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No entry 'IFNAME' in configuration!\n");
    exit (1);
  }

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "vpn", "IPV6ADDR", &ipv6addr))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No entry 'IPV6ADDR' in configuration!\n");
    exit (1);
  }

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "vpn", "IPV6PREFIX",
                                             &ipv6prefix))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No entry 'IPV6PREFIX' in configuration!\n");
    exit (1);
  }

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "vpn", "IPV4ADDR", &ipv4addr))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No entry 'IPV4ADDR' in configuration!\n");
    exit (1);
  }

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "vpn", "IPV4MASK", &ipv4mask))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No entry 'IPV4MASK' in configuration!\n");
    exit (1);
  }

  vpn_argv[0] = GNUNET_strdup ("vpn-gnunet");
  vpn_argv[1] = ifname;
  vpn_argv[2] = ipv6addr;
  vpn_argv[3] = ipv6prefix;
  vpn_argv[4] = ipv4addr;
  vpn_argv[5] = ipv4mask;
  vpn_argv[6] = NULL;
  
  helper_handle = GNUNET_HELPER_start ("gnunet-helper-vpn", vpn_argv,
				       &message_token, NULL);
  GNUNET_DNS_restart_hijack (dns_handle);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &cleanup, cls);
}

/**
 * The main function to obtain template from gnunetd.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "vpn", gettext_noop ("help text"),
                              options, &run, NULL)) ? ret : 1;
}

/* end of gnunet-daemon-vpn.c */
