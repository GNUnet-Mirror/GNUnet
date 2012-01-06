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
 * @file vpn/gnunet-service-vpn.c
 * @brief service that opens a virtual interface and allows its clients
 *        to allocate IPs on the virtual interface and to then redirect
 *        IP traffic received on those IPs via the GNUnet mesh 
 * @author Philipp Toelke
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet-vpn-packet.h"
#include "gnunet_common.h"
#include "gnunet_protocols.h"
#include "gnunet_applications.h"
#include "gnunet_mesh_service.h"
#include "gnunet_constants.h"



struct map_entry
{
    /** The description of the service (used for service) */
  GNUNET_HashCode desc;

    /** The real address of the service (used for remote) */
  char addrlen;
  char addr[16];

  struct GNUNET_MESH_Tunnel *tunnel;
  uint16_t namelen;
  char additional_ports[8192];

  struct GNUNET_CONTAINER_HeapNode *heap_node;
  GNUNET_HashCode hash;

};


struct remote_addr
{
  char addrlen;
  unsigned char addr[16];
  char proto;
};


struct tunnel_notify_queue
{
  struct tunnel_notify_queue *next;
  struct tunnel_notify_queue *prev;
  size_t len;
  void *cls;
};


struct tunnel_state
{
  struct GNUNET_MESH_TransmitHandle *th;
  struct tunnel_notify_queue *head, *tail;

  int addrlen;
};



/**
 * Configuration we use.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to the mesh service.
 */
static struct GNUNET_MESH_Handle *mesh_handle;

/**
 * FIXME
 */
static struct GNUNET_CONTAINER_MultiHashMap *hashmap;

/**
 * FIXME
 */
static struct GNUNET_CONTAINER_Heap *heap;

/**
 * The handle to the VPN helper process "gnunet-helper-vpn".
 */
static struct GNUNET_HELPER_Handle *helper_handle;

/**
 * Arguments to the exit helper.
 */
static char *vpn_argv[7];

/**
 * If there are at least this many address-mappings, old ones will be removed
 */
static unsigned long long max_mappings;


/**
 * @return the hash of the IP-Address if a mapping exists, NULL otherwise
 */
static GNUNET_HashCode *
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
static GNUNET_HashCode *
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


static void
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


static void
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


static void
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
 * Receive packets from the helper-process
 */
static void
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
          *hc = me->desc;

          if (me->tunnel == NULL && NULL != cls)
          {
            *cls =
                GNUNET_MESH_tunnel_create (mesh_handle,
                                           initialize_tunnel_state (16, NULL),
                                           &send_pkt_to_peer, NULL, cls);

            GNUNET_MESH_peer_request_connect_add (*cls,
                                                  (struct GNUNET_PeerIdentity *)
                                                  &me->desc);
            me->tunnel = *cls;
          }
          else if (NULL != cls)
          {
            *cls = me->tunnel;
            send_pkt_to_peer (cls, (struct GNUNET_PeerIdentity *) 1, NULL);
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
          }
          else if (s->proto == IPPROTO_TCP)
          {
            hdr->type = htons (GNUNET_MESSAGE_TYPE_VPN_REMOTE_TCP);
            memcpy (hc + 1, &pkt6_tcp->tcp_hdr, ntohs (pkt6->ip6_hdr.paylgth));
            app_type = GNUNET_APPLICATION_TYPE_INTERNET_TCP_GATEWAY;
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
    //struct ip_udp *udp = (struct ip_udp *) message;
    struct ip_tcp *pkt_tcp;
    struct ip_udp *pkt_udp;
    struct ip_icmp *pkt_icmp;

    GNUNET_assert (pkt->ip_hdr.version == 4);

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
            *hc = me->desc;

            if (me->tunnel == NULL && NULL != cls)
            {
              *cls =
                  GNUNET_MESH_tunnel_create (mesh_handle,
                                             initialize_tunnel_state (4, NULL),
                                             send_pkt_to_peer, NULL, cls);
              GNUNET_MESH_peer_request_connect_add (*cls,
                                                    (struct GNUNET_PeerIdentity
                                                     *) &me->desc);
              me->tunnel = *cls;
            }
            else if (NULL != cls)
            {
              *cls = me->tunnel;
              send_pkt_to_peer (cls, (struct GNUNET_PeerIdentity *) 1, NULL);
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





/**
 * Create a new Address from an answer-packet
 */
static void
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
static void
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
static void
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
 * FIXME: document.
 */ 
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


/**
 * FIXME: document.
 */ 
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


/**
 * FIXME: document.
 */ 
static void *
new_tunnel (void *cls, struct GNUNET_MESH_Tunnel *tunnel,
            const struct GNUNET_PeerIdentity *initiator,
            const struct GNUNET_ATS_Information *atsi)
{
  /* Why should anyone open an inbound tunnel to vpn? */
  GNUNET_break (0);
  return NULL;
}


/**
 * FIXME: document.
 */ 
static void
tunnel_cleaner (void *cls, const struct GNUNET_MESH_Tunnel *tunnel, void *tunnel_ctx)
{
  /* Why should anyone open an inbound tunnel to vpn? */
  /* FIXME: is this not also called for outbound tunnels that go down!? */
  GNUNET_break (0);
}


/**
 * Function scheduled as very last function, cleans up after us
 */
static void
cleanup (void *cls GNUNET_UNUSED,
         const struct GNUNET_SCHEDULER_TaskContext *tskctx)
{
  unsigned int i;

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
  for (i=0;i<5;i++)
    GNUNET_free_non_null (vpn_argv[i]);
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param server the initialized server
 * @param cfg_ configuration
 */
static void
run (void *cls,
     struct GNUNET_SERVER_Handle *server,
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
  char *ipv6prefix_s;
  char *ipv4addr;
  char *ipv4mask;
  struct in_addr v4;
  struct in6_addr v6;
  unsigned long long ipv6prefix;

  cfg = cfg_;
  hashmap = GNUNET_CONTAINER_multihashmap_create (65536);
  heap = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "vpn", "MAX_MAPPING",
					     &max_mappings))
    max_mappings = 200;

  vpn_argv[0] = GNUNET_strdup ("vpn-gnunet");
  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "vpn", "IFNAME", &ifname))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No entry 'IFNAME' in configuration!\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  vpn_argv[1] = ifname;
  if ( (GNUNET_SYSERR ==
	GNUNET_CONFIGURATION_get_value_string (cfg, "vpn", "IPV6ADDR",
					       &ipv6addr) ||
	(1 != inet_pton (AF_INET6, ipv6addr, &v6))) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No valid entry 'IPV6ADDR' in configuration!\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  vpn_argv[2] = ipv6addr;
  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "vpn", "IPV6PREFIX",
                                             &ipv6prefix_s))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No entry 'IPV6PREFIX' in configuration!\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  vpn_argv[3] = ipv6prefix_s;
  if ( (GNUNET_OK !=
	GNUNET_CONFIGURATION_get_value_number (cfg, "vpn",
					       "IPV6PREFIX",
					       &ipv6prefix)) ||
       (ipv6prefix >= 127) )
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  if ( (GNUNET_SYSERR ==
	GNUNET_CONFIGURATION_get_value_string (cfg, "vpn", "IPV4ADDR",
					       &ipv4addr) ||
	(1 != inet_pton (AF_INET, ipv4addr, &v4))) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No valid entry for 'IPV4ADDR' in configuration!\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  vpn_argv[4] = ipv4addr;
  if ( (GNUNET_SYSERR ==
	GNUNET_CONFIGURATION_get_value_string (cfg, "vpn", "IPV4MASK",
					       &ipv4mask) ||
	(1 != inet_pton (AF_INET, ipv4mask, &v4))) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No valid entry 'IPV4MASK' in configuration!\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  vpn_argv[5] = ipv4mask;
  vpn_argv[6] = NULL;

  mesh_handle =
    GNUNET_MESH_connect (cfg_, 42 /* queue length */, NULL, 
			 &new_tunnel, 
			 &tunnel_cleaner, 
			 handlers,
			 types);
  helper_handle = GNUNET_HELPER_start ("gnunet-helper-vpn", vpn_argv,
				       &message_token, NULL);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &cleanup, cls);
}


/**
 * The main function of the VPN service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv, "vpn", 
			      GNUNET_SERVICE_OPTION_NONE,
                              &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-vpn.c */
