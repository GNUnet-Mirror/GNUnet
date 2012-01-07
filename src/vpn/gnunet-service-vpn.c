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
 * @author Christian Grothoff
 *
 * TODO:
 * - add back ICMP support (especially needed for IPv6)o
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_common.h"
#include "gnunet_protocols.h"
#include "gnunet_applications.h"
#include "gnunet_mesh_service.h"
#include "gnunet_constants.h"
#include "tcpip_tun.h"




/**
 * Information we track for each IP address to determine which tunnel
 * to send the traffic over to the destination.
 */
struct map_entry
{
  /**
   * Information about the tunnel to use; the associated tunnel
   * state gives information about the respective local IP that
   * this tunnel is used with.  
   */
  struct tunnel_state *ts;

  /**
   * Entry for this entry in the heap.
   */
  struct GNUNET_CONTAINER_HeapNode *heap_node;

  /**
   * GNUNET_NO if this is a tunnel to an Internet-exit,
   * GNUNET_YES if this tunnel is to a service.
   */
  int is_service;
  
  /**
   * Address family used (AF_INET or AF_INET6).
   */
  int af;

  /**
   * Details about the connection (depending on is_service).
   */
  union
  {

    /**
     * The description of the service (only used for service tunnels).
     */
    GNUNET_HashCode desc;

    /**
     * IP address of the ultimate destination (only used for exit tunnels).
     */
    union
    {
      /**
       * Address if af is AF_INET.
       */
      struct in_addr v4;

      /**
       * Address if af is AF_INET6.
       */
      struct in6_addr v6;
    } ip;

  } destination_details;

    
};


/**
 * A messages we have in queue for a particular tunnel.
 */
struct tunnel_notify_queue
{
  /**
   * This is a doubly-linked list.
   */
  struct tunnel_notify_queue *next;

  /**
   * This is a doubly-linked list.
   */
  struct tunnel_notify_queue *prev;
  
  /**
   * Number of bytes in 'msg'.
   */
  size_t len;

  /**
   * Message to transmit, allocated at the end of this struct.
   */
  const void *msg;
};


/**
 * State we keep for each of our tunnels.
 */
struct tunnel_state
{
  /**
   * Active transmission handle, NULL for none.
   */
  struct GNUNET_MESH_TransmitHandle *th;

  /**
   * Head of list of messages scheduled for transmission.
   */
  struct tunnel_notify_queue *head;

  /**
   * Tail of list of messages scheduled for transmission.
   */
  struct tunnel_notify_queue *tail;

  /**
   * Tunnel for which this is the state.
   */
  struct GNUNET_MESH_Tunnel *tunnel;

  /**
   * Address family used on our side of this tunnel
   * (AF_INET or AF_INET6).
   */
  int af;

  /**
   * IP address of the source on our end.
   */
  union
  {
    /**
     * Address if af is AF_INET.
     */
    struct in_addr v4;
    
    /**
     * Address if af is AF_INET6.
     */
    struct in6_addr v6;

  } source_ip;

  /**
   * Source port used by the sender.
   */
  uint16_t source_port;

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
 * Map from IP address to connection information (mostly with 
 * the respective MESH tunnel handle).
 */
static struct GNUNET_CONTAINER_MultiHashMap *hashmap;

/**
 * Min-Heap sorted by activity time to expire old mappings.
 */
static struct GNUNET_CONTAINER_Heap *heap;

/**
 * The handle to the VPN helper process "gnunet-helper-vpn".
 */
static struct GNUNET_HELPER_Handle *helper_handle;

/**
 * Arguments to the vpn helper.
 */
static char *vpn_argv[7];

/**
 * If there are more than this number of address-mappings, old ones
 * will be removed
 */
static unsigned long long max_mappings;


/**
 * Compute the key under which we would store an entry in the
 * map for the given IP address.
 *
 * @param af address family (AF_INET or AF_INET6)
 * @param address IP address, struct in_addr or struct in6_addr
 * @param key where to store the key
 */
static void
get_key_from_ip (int af,
		 const void *address,
		 GNUNET_HashCode *key)
{
  switch (af)
  {
  case AF_INET:
    GNUNET_CRYPTO_hash (address,
			sizeof (struct in_addr),
			key);
    break;
  case AF_INET6:
    GNUNET_CRYPTO_hash (address,
			sizeof (struct in6_addr),
			key);
    break;
  default:
    GNUNET_assert (0);
    break;
  }
}


/**
 * Send a message from the message queue via mesh.
 *
 * @param cls the 'struct tunnel_state' with the message queue
 * @param size number of bytes available in buf
 * @param buf where to copy the message
 * @return number of bytes copied to buf
 */
static size_t
send_to_peer_notify_callback (void *cls, size_t size, void *buf)
{
  struct tunnel_state *ts = cls;
  struct tunnel_notify_queue *tnq;
  size_t ret;

  ts->th = NULL;
  if (NULL == buf)
    return 0;
  tnq = ts->head;
  GNUNET_assert (NULL != tnq);
  GNUNET_assert (size >= tnq->len);
  GNUNET_CONTAINER_DLL_remove (ts->head,
			       ts->tail,
			       tnq);
  memcpy (buf, tnq->msg, tnq->len);
  ret = tnq->len;
  GNUNET_free (tnq);
  if (NULL != (tnq = ts->head))
    ts->th = GNUNET_MESH_notify_transmit_ready (ts->tunnel, 
						GNUNET_NO /* cork */, 
						42 /* priority */,
						GNUNET_TIME_UNIT_FOREVER_REL,
						NULL, 
						tnq->len,
						&send_to_peer_notify_callback,
						ts);
  return ret;
}


/**
 * Add the given message to the given tunnel and
 * trigger the transmission process.
 *
 * @param tnq message to queue
 * @param ts tunnel to queue the message for
 */
/* static */ void
send_to_to_tunnel (struct tunnel_notify_queue *tnq,
		   struct tunnel_state *ts)
{
  GNUNET_CONTAINER_DLL_insert_tail (ts->head,
				    ts->tail,
				    tnq);
  if (NULL == ts->th)
    ts->th = GNUNET_MESH_notify_transmit_ready (ts->tunnel, 
						GNUNET_NO /* cork */,
						42 /* priority */,
						GNUNET_TIME_UNIT_FOREVER_REL,
						NULL, 
						tnq->len,
						&send_to_peer_notify_callback,
						ts);
}


/**
 * Route a packet via mesh to the given destination.  Note that
 * the source IP may NOT be the one that the tunnel state
 * of the given destination is associated with.  If the tunnel
 * state is unassociated or identical, it should be used; if
 * not, a fresh tunnel YUCK...
 *
 * @param destination description of the destination
 * @param af address family on this end (AF_INET or AF_INET6)
 * @param protocol IPPROTO_TCP or IPPROTO_UDP
 * @param source_ip source IP used by the sender (struct in_addr or struct in6_addr)
 * @param payload payload of the packet after the IP header
 * @param payload_length number of bytes in payload
 */
static void
route_packet (struct map_entry *destination,
	      int af,
	      uint8_t protocol,
	      const void *source_ip,
	      const void *payload,
	      size_t payload_length)
{
#if 0
  // FIXME...

      switch (pkt6->nxthdr)
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
#endif
}



/**
 * Receive packets from the helper-process, identify the
 * correct tunnel and forward them on.
 *
 * @param cls closure, NULL
 * @param client NULL
 * @param message message we got from the client (VPN tunnel interface)
 */
static void
message_token (void *cls GNUNET_UNUSED, void *client GNUNET_UNUSED,
               const struct GNUNET_MessageHeader *message)
{
  const struct tun_header *tun;
  size_t mlen;
  GNUNET_HashCode key;
  struct map_entry *me;

  mlen = ntohs (message->size);
  if ( (ntohs (message->type) != GNUNET_MESSAGE_TYPE_VPN_HELPER) ||
       (mlen < sizeof (struct GNUNET_MessageHeader) + sizeof (struct tun_header)) )
  {
    GNUNET_break (0);
    return;
  }
  tun = (const struct tun_header *) &message[1];
  mlen -= (sizeof (struct GNUNET_MessageHeader) + sizeof (struct tun_header));
  switch (ntohs (tun->proto))
  {
  case ETH_P_IPV6:
    {
      const struct ip6_header *pkt6;
      
      if (mlen < sizeof (struct ip6_header))
      {
	/* blame kernel */
	GNUNET_break (0);
	return;
      }
      pkt6 = (const struct ip6_header *) &tun[1];
      get_key_from_ip (AF_INET6,
		       &pkt6->destination_address,
		       &key);
      me = GNUNET_CONTAINER_multihashmap_get (hashmap, &key);
      /* FIXME: do we need to guard against hash collision? */
      if (NULL == me)
      {
	char buf[INET6_ADDRSTRLEN];
	
	GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		    _("Packet received for unmapped destination `%s' (dropping it)\n"),
		    inet_ntop (AF_INET6,
			       &pkt6->destination_address,
			       buf,
			       sizeof (buf)));
	return;
      }
      route_packet (me,
		    AF_INET6,
		    pkt6->next_header,
		    &pkt6->source_address,		    
		    &pkt6[1],
		    mlen - sizeof (struct ip6_header));
    }
    break;
  case ETH_P_IPV4:
    {
      struct ip4_header *pkt4;

      if (mlen < sizeof (struct ip4_header))
      {
	/* blame kernel */
	GNUNET_break (0);
	return;
      }
      pkt4 = (struct ip4_header *) &tun[1];
      get_key_from_ip (AF_INET,
		       &pkt4->destination_address,
		       &key);
      me = GNUNET_CONTAINER_multihashmap_get (hashmap, &key);
      /* FIXME: do we need to guard against hash collision? */
      if (NULL == me)
      {
	char buf[INET_ADDRSTRLEN];
	
	GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		    _("Packet received for unmapped destination `%s' (dropping it)\n"),
		    inet_ntop (AF_INET,
			       &pkt4->destination_address,
			       buf,
			       sizeof (buf)));
	return;
      }
      if (pkt4->header_length * 4 != sizeof (struct ip4_header))
      {
	GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		    _("Received IPv4 packet with options (dropping it)\n"));		    
	return;
      }
      route_packet (me,
		    AF_INET,
		    pkt4->protocol,
		    &pkt4->source_address,		    
		    &pkt4[1],
		    mlen - sizeof (struct ip4_header));
    }
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		_("Received packet of unknown protocol %d from TUN (dropping it)\n"),
		(unsigned int) ntohs (tun->proto));
    break;
  }
}


#if 0


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

#endif



/**
 * FIXME: document.
 */ 
static int
receive_udp_back (void *cls GNUNET_UNUSED, struct GNUNET_MESH_Tunnel *tunnel,
                  void **tunnel_ctx, const struct GNUNET_PeerIdentity *sender,
                  const struct GNUNET_MessageHeader *message,
                  const struct GNUNET_ATS_Information *atsi GNUNET_UNUSED)
{
#if 0
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
#endif
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
#if 0
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
#endif
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
