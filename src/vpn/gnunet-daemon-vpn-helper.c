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
#include <gnunet_applications.h>

#include "gnunet-daemon-vpn-dns.h"
#include "gnunet-daemon-vpn.h"
#include "gnunet-daemon-vpn-helper.h"
#include "gnunet-service-dns-p.h"
#include "gnunet-vpn-packet.h"
#include "gnunet-vpn-checksum.h"
#include "gnunet-helper-vpn-api.h"

struct GNUNET_VPN_HELPER_Handle *helper_handle;

extern struct GNUNET_CLIENT_TransmitHandle* dns_transmit_handle;

/**
 * The tunnels that will be used to send tcp- and udp-packets
 */
static struct GNUNET_MESH_Tunnel *tcp_tunnel;
static struct GNUNET_MESH_Tunnel *udp_tunnel;

/**
 * Start the helper-process
 *
 * If cls != NULL it is assumed that this function is called as a result of a dying
 * helper. cls is then taken as handle to the old helper and is cleaned up.
 * {{{
 */
void
start_helper_and_schedule (void *cls,
                           const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  shs_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  if (cls != NULL)
    cleanup_helper (cls);
  cls = NULL;

  char *ifname;
  char *ipv6addr;
  char *ipv6prefix;
  char *ipv4addr;
  char *ipv4mask;

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

  /* Start the helper
   * Messages get passed to the function message_token
   * When the helper dies, this function will be called again with the
   * helper_handle as cls.
   */
  helper_handle =
      start_helper (ifname, ipv6addr, ipv6prefix, ipv4addr, ipv4mask,
                    "vpn-gnunet", start_helper_and_schedule, message_token,
                    NULL);

  GNUNET_free (ipv6addr);
  GNUNET_free (ipv6prefix);
  GNUNET_free (ipv4addr);
  GNUNET_free (ipv4mask);
  GNUNET_free (ifname);

  /* Tell the dns-service to rehijack the dns-port
   * The routing-table gets flushed if an interface disappears.
   */
  restart_hijack = 1;
  if (NULL != dns_connection && dns_transmit_handle == NULL)
    dns_transmit_handle = GNUNET_CLIENT_notify_transmit_ready (dns_connection,
                                         sizeof (struct GNUNET_MessageHeader),
                                         GNUNET_TIME_UNIT_FOREVER_REL,
                                         GNUNET_YES, &send_query, NULL);

  GNUNET_SCHEDULER_add_write_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                   helper_handle->fh_to_helper, &helper_write,
                                   NULL);
}

/*}}}*/

static void*
initialize_tunnel_state(int addrlen, struct GNUNET_MESH_TransmitHandle* th)
{
  struct tunnel_state* ts = GNUNET_malloc(sizeof *ts);
  ts->addrlen = addrlen;
  ts->th = th;
  return ts;
}

/**
 * Send an dns-answer-packet to the helper
 */
void
helper_write (void *cls
              __attribute__ ((unused)),
              const struct GNUNET_SCHEDULER_TaskContext *tsdkctx)
{
  if (tsdkctx->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN)
    return;

  struct answer_packet_list *ans = answer_proc_head;

  if (NULL == ans)
    return;

  size_t len = ntohs (ans->pkt.hdr.size);

  GNUNET_assert (ans->pkt.subtype == GNUNET_DNS_ANSWER_TYPE_IP);

  GNUNET_assert (20 == sizeof (struct ip_hdr));
  GNUNET_assert (8 == sizeof (struct udp_pkt));

  size_t data_len = len - sizeof (struct answer_packet) + 1;

  void* buf;
  size_t pkt_len;

  if (ans->pkt.addrlen == 16)
    {
      size_t net_len = sizeof (struct ip6_hdr) + sizeof (struct udp_dns) + data_len;
      pkt_len =
        sizeof (struct GNUNET_MessageHeader) + sizeof (struct pkt_tun) + net_len;

      struct ip6_udp_dns *pkt = alloca (pkt_len);

      GNUNET_assert (pkt != NULL);
      memset (pkt, 0, pkt_len);

      /* set the gnunet-header */
      pkt->shdr.size = htons (pkt_len);
      pkt->shdr.type = htons (GNUNET_MESSAGE_TYPE_VPN_HELPER);

      /* set the tun-header (no flags and ethertype of IPv4) */
      pkt->tun.flags = 0;
      pkt->tun.type = htons (0x86dd);

      memcpy(&pkt->ip6_hdr.sadr, ans->pkt.from, 16);
      memcpy(&pkt->ip6_hdr.dadr, ans->pkt.to, 16);

      /* set the udp-header */
      pkt->udp_dns.udp_hdr.spt = htons (53);
      pkt->udp_dns.udp_hdr.dpt = ans->pkt.dst_port;
      pkt->udp_dns.udp_hdr.len = htons (net_len - sizeof (struct ip6_hdr));
      pkt->udp_dns.udp_hdr.crc = 0;
      uint32_t sum = 0;

      sum =
        calculate_checksum_update (sum, (uint16_t *) & pkt->ip6_hdr.sadr, 16);
      sum =
        calculate_checksum_update (sum, (uint16_t *) & pkt->ip6_hdr.dadr, 16);
      uint32_t tmp = (pkt->udp_dns.udp_hdr.len & 0xffff);

      sum = calculate_checksum_update (sum, (uint16_t *) & tmp, 4);
      tmp = htons (((pkt->ip6_hdr.nxthdr & 0x00ff)));
      sum = calculate_checksum_update (sum, (uint16_t *) & tmp, 4);

      sum =
        calculate_checksum_update (sum, (uint16_t *) & pkt->udp_dns.udp_hdr,
                                   ntohs (net_len - sizeof(struct ip6_hdr)));
      pkt->udp_dns.udp_hdr.crc = calculate_checksum_end (sum);

      pkt->ip6_hdr.version = 6;
      pkt->ip6_hdr.paylgth = net_len - sizeof (struct ip6_hdr);
      pkt->ip6_hdr.nxthdr = IPPROTO_UDP;
      pkt->ip6_hdr.hoplmt = 0xff;

      memcpy (&pkt->udp_dns.data, ans->pkt.data, data_len);
      buf = pkt;
    }
  else if (ans->pkt.addrlen == 4)
    {
      size_t net_len = sizeof (struct ip_hdr) + sizeof (struct udp_dns) + data_len;
      pkt_len =
        sizeof (struct GNUNET_MessageHeader) + sizeof (struct pkt_tun) + net_len;

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
      pkt->ip_hdr.chks = 0;         /* Will be calculated later */

      memcpy(&pkt->ip_hdr.sadr, ans->pkt.from, 4);
      memcpy(&pkt->ip_hdr.dadr, ans->pkt.to, 4);

      pkt->ip_hdr.chks = calculate_ip_checksum ((uint16_t *) & pkt->ip_hdr, 5 * 4);

      /* set the udp-header */
      pkt->udp_dns.udp_hdr.spt = htons (53);
      pkt->udp_dns.udp_hdr.dpt = ans->pkt.dst_port;
      pkt->udp_dns.udp_hdr.len = htons (net_len - sizeof (struct ip_hdr));
      pkt->udp_dns.udp_hdr.crc = 0; /* Optional for IPv4 */

      memcpy (&pkt->udp_dns.data, ans->pkt.data, data_len);
      buf = pkt;
    }
  else
    {
      GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Wrong addrlen = %d\n", ans->pkt.addrlen);
      GNUNET_assert(0);
    }

  GNUNET_CONTAINER_DLL_remove (answer_proc_head, answer_proc_tail, ans);
  GNUNET_free (ans);

  if (GNUNET_DISK_file_write (helper_handle->fh_to_helper, buf, pkt_len) < 0)
  {
    cleanup_helper (helper_handle);
    GNUNET_SCHEDULER_add_now (start_helper_and_schedule, NULL);
    return;
  }

  /* if more packets are available, reschedule */
  if (answer_proc_head != NULL)
    GNUNET_SCHEDULER_add_write_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                     helper_handle->fh_to_helper, &helper_write,
                                     NULL);
}

/**
 * Receive packets from the helper-process
 */
void
message_token (void *cls __attribute__ ((unused)), void *client
               __attribute__ ((unused)),
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

    pkt6_udp = NULL; /* make compiler happy */
    switch (pkt6->ip6_hdr.nxthdr)
    {
    case IPPROTO_UDP:
      pkt6_udp = (struct ip6_udp *) pkt6;
      /* Send dns-packets to the service-dns */
      if (ntohs (pkt6_udp->udp_hdr.dpt) == 53)
        {
          /* 9 = 8 for the udp-header + 1 for the unsigned char data[1]; */
          size_t len = sizeof (struct query_packet) + ntohs (pkt6_udp->udp_hdr.len) - 9;

          struct query_packet_list *query =
            GNUNET_malloc (len + 2 * sizeof (struct query_packet_list *));
          query->pkt.hdr.type = htons (GNUNET_MESSAGE_TYPE_VPN_DNS_LOCAL_QUERY_DNS);
          query->pkt.hdr.size = htons (len);
          memcpy(query->pkt.orig_to, &pkt6->ip6_hdr.dadr, 16);
          memcpy(query->pkt.orig_from, &pkt6->ip6_hdr.sadr, 16);
          query->pkt.addrlen = 16;
          query->pkt.src_port = pkt6_udp->udp_hdr.spt;
          memcpy (query->pkt.data, pkt6_udp->data, ntohs (pkt6_udp->udp_hdr.len) - 8);

          GNUNET_CONTAINER_DLL_insert_after (head, tail, tail, query);

          GNUNET_assert (head != NULL);

          if (dns_connection != NULL && dns_transmit_handle == NULL)
            dns_transmit_handle = GNUNET_CLIENT_notify_transmit_ready (dns_connection, len,
                                                                       GNUNET_TIME_UNIT_FOREVER_REL,
                                                                       GNUNET_YES, &send_query, NULL);
          break;
        } 
      /* fall through */
    case IPPROTO_TCP:
      pkt6_tcp = (struct ip6_tcp *) pkt6;

      if ((key = address6_mapping_exists (pkt6->ip6_hdr.dadr)) != NULL)
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

        GNUNET_MESH_ApplicationType app_type;

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
            GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "pip: %d\n", port_in_ports(me->desc.ports, pkt6_tcp->tcp_hdr.dpt));
              GNUNET_assert(0);
          }
          if (me->tunnel == NULL && NULL != cls)
          {
            *cls =
              GNUNET_MESH_tunnel_create(mesh_handle, initialize_tunnel_state(16, NULL),
                                        &send_pkt_to_peer, NULL, cls);

            GNUNET_MESH_peer_request_connect_add (*cls,
                                                      (struct
                                                       GNUNET_PeerIdentity *)
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
              GNUNET_MESH_tunnel_create(mesh_handle, initialize_tunnel_state(16, NULL),
                                        &send_pkt_to_peer, NULL, cls);

            GNUNET_MESH_peer_request_connect_by_type (*cls,
                                                      app_type);
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
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Packet to %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x, which has no mapping\n",
                    pkt6->ip6_hdr.dadr[0], pkt6->ip6_hdr.dadr[1],
                    pkt6->ip6_hdr.dadr[2], pkt6->ip6_hdr.dadr[3],
                    pkt6->ip6_hdr.dadr[4], pkt6->ip6_hdr.dadr[5],
                    pkt6->ip6_hdr.dadr[6], pkt6->ip6_hdr.dadr[7],
                    pkt6->ip6_hdr.dadr[8], pkt6->ip6_hdr.dadr[9],
                    pkt6->ip6_hdr.dadr[10], pkt6->ip6_hdr.dadr[11],
                    pkt6->ip6_hdr.dadr[12], pkt6->ip6_hdr.dadr[13],
                    pkt6->ip6_hdr.dadr[14], pkt6->ip6_hdr.dadr[15]);
      }
      break;
    case 0x3a:
      /* ICMPv6 */
      pkt6_icmp = (struct ip6_icmp *) pkt6;
      /* If this packet is an icmp-echo-request and a mapping exists, answer */
      if (pkt6_icmp->icmp_hdr.type == 0x80 &&
          (key = address6_mapping_exists (pkt6->ip6_hdr.dadr)) != NULL)
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
      /* 9 = 8 for the udp-header + 1 for the unsigned char data[1]; */
      size_t len = sizeof (struct query_packet) + ntohs (udp->udp_hdr.len) - 9;

      struct query_packet_list *query =
          GNUNET_malloc (len + 2 * sizeof (struct query_packet_list *));
      query->pkt.hdr.type = htons (GNUNET_MESSAGE_TYPE_VPN_DNS_LOCAL_QUERY_DNS);
      query->pkt.hdr.size = htons (len);
      memcpy(query->pkt.orig_to, &pkt->ip_hdr.dadr, 4);
      memcpy(query->pkt.orig_from, &pkt->ip_hdr.sadr, 4);
      query->pkt.addrlen = 4;
      query->pkt.src_port = udp->udp_hdr.spt;
      memcpy (query->pkt.data, udp->data, ntohs (udp->udp_hdr.len) - 8);

      GNUNET_CONTAINER_DLL_insert_after (head, tail, tail, query);

      GNUNET_assert (head != NULL);

      if (dns_connection != NULL && dns_transmit_handle == NULL)
        dns_transmit_handle = GNUNET_CLIENT_notify_transmit_ready (dns_connection, len,
                                                                   GNUNET_TIME_UNIT_FOREVER_REL,
                                                                   GNUNET_YES, &send_query, NULL);
    }
    else
    {
      uint32_t dadr = pkt->ip_hdr.dadr;
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

          GNUNET_MESH_ApplicationType app_type;

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
              *cls = GNUNET_MESH_tunnel_create(mesh_handle,
                                               initialize_tunnel_state(4, NULL),
                                               send_pkt_to_peer, NULL, cls);
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
            } else
	      GNUNET_assert (0);
            if (me->tunnel == NULL && NULL != cls)
            {
              *cls =
                GNUNET_MESH_tunnel_create(mesh_handle, initialize_tunnel_state(4, NULL),
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

void
write_to_helper (void *buf, size_t len)
{
  (void) GNUNET_DISK_file_write (helper_handle->fh_to_helper, buf, len);
}

void
schedule_helper_write (struct GNUNET_TIME_Relative time, void *cls)
{
  if (GNUNET_SCHEDULER_NO_TASK != shs_task)
    return;
  GNUNET_SCHEDULER_add_write_file (time, helper_handle->fh_to_helper,
                                   &helper_write, cls);
}
