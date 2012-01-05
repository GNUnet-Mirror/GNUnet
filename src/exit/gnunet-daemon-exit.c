/*
     This file is part of GNUnet.
     (C) 2010, 2012 Christian Grothoff

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
 * @file exit/gnunet-daemon-exit.c
 * @brief tool to allow IP traffic exit from the GNUnet mesh to the Internet
 * @author Philipp Toelke
 * @author Christian Grothoff
 */
#include <platform.h>
#include <gnunet_common.h>
#include <gnunet_program_lib.h>
#include <gnunet_protocols.h>
#include <gnunet_applications.h>
#include <gnunet_mesh_service.h>
#include <gnunet_constants.h>
#include <string.h>


/* see http://www.iana.org/assignments/ethernet-numbers */
#ifndef ETH_P_IPV4
#define ETH_P_IPV4 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif


GNUNET_NETWORK_STRUCT_BEGIN
/**
 * Header from Linux TUN interface.
 */ 
struct tun_header
{
  /**
   * Some flags (unused).
   */ 
  uint16_t flags;

  /**
   * Here we get an ETH_P_-number.
   */
  uint16_t proto;
};

/**
 * Standard IPv4 header.
 */
struct ip4_header
{
  unsigned header_length:4 GNUNET_PACKED;
  unsigned version:4 GNUNET_PACKED;
  uint8_t diff_serv;
  uint16_t total_length GNUNET_PACKED;
  uint16_t identification GNUNET_PACKED;
  unsigned flags:3 GNUNET_PACKED;
  unsigned fragmentation_offset:13 GNUNET_PACKED;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t checksum GNUNET_PACKED;
  struct in_addr source_address GNUNET_PACKED;
  struct in_addr destination_address GNUNET_PACKED;
};

/**
 * Standard IPv6 header.
 */
struct ip6_header
{
  unsigned traffic_class_h:4 GNUNET_PACKED;
  unsigned version:4 GNUNET_PACKED;
  unsigned traffic_class_l:4 GNUNET_PACKED;
  unsigned flow_label:20 GNUNET_PACKED;
  uint16_t payload_length GNUNET_PACKED;
  uint8_t next_header;
  uint8_t hop_limit;
  struct in6_addr source_address GNUNET_PACKED;
  struct in6_addr destination_address GNUNET_PACKED;
};

#define TCP_FLAG_SYN 2

struct tcp_packet
{
  unsigned spt:16 GNUNET_PACKED;
  unsigned dpt:16 GNUNET_PACKED;
  unsigned seq:32 GNUNET_PACKED;
  unsigned ack:32 GNUNET_PACKED;
  unsigned off:4 GNUNET_PACKED;
  unsigned rsv:4 GNUNET_PACKED;
  unsigned flg:8 GNUNET_PACKED;
  unsigned wsz:16 GNUNET_PACKED;
  unsigned crc:16 GNUNET_PACKED;
  unsigned urg:16 GNUNET_PACKED;
};

/**
 * UDP packet header.
 */
struct udp_packet
{
  uint16_t spt GNUNET_PACKED;
  uint16_t dpt GNUNET_PACKED;
  uint16_t len GNUNET_PACKED;
  uint16_t crc GNUNET_PACKED;
};

/**
 * DNS header.
 */
struct dns_header
{
  uint16_t id GNUNET_PACKED;
  uint16_t flags GNUNET_PACKED;
  uint16_t qdcount GNUNET_PACKED;
  uint16_t ancount GNUNET_PACKED;
  uint16_t nscount GNUNET_PACKED;
  uint16_t arcount GNUNET_PACKED;
};
GNUNET_NETWORK_STRUCT_END

/**
 * Information about a remote address.
 */
struct remote_addr
{
  /**
   * AF_INET or AF_INET6.
   */
  int af;

  /**
   * Remote address information.
   */
  union
  {
    /**
     * Address, if af is AF_INET.
     */
    struct in_addr ipv4;

    /**
     * Address, if af is AF_INET6.
     */
    struct in6_addr ipv6;
  } address;

  /**
   * Remote port, in host byte order!
   */
  uint16_t port;
  
  /**
   * IPPROTO_TCP or IPPROTO_UDP;
   */
  uint8_t proto;

};

/**
 * This struct is saved into the services-hashmap
 */
struct redirect_service
{

  /**
   * Remote address to use for the service.
   */
  struct remote_addr address;

  /**
   * Descriptor for this service (also key of this entry in the service hash map).
   */
  GNUNET_HashCode desc;

  /**
   * Port I am listening on within GNUnet for this service, in host byte order.
   */
  uint16_t my_port;

};

/**
 * Information we use to track a connection.
 */
struct redirect_info 
{

  /**
   * Address information for the other party.
   */
  struct remote_addr remote_address;

  /**
   * The source-port of this connection, in host byte order
   */
  uint16_t source_port;

};

/**
 * This struct is saved into {tcp,udp}_connections;
 */
struct redirect_state
{
  /**
   * Mesh tunnel that is used for this connection.
   */
  struct GNUNET_MESH_Tunnel *tunnel;

  /**
   * Heap node for this state in the connections_heap.
   */
  struct GNUNET_CONTAINER_HeapNode *heap_node;

  /**
   * Key this state has in the connections_map.
   */
  GNUNET_HashCode state_key;

  /**
   * Associated service record, or NULL for no service.
   */
  struct redirect_service *serv;

  /**
   * Source port we use for this connection.  FIXME: needed? used?
   */
  uint16_t source_port__;

};

/**
 * Queue of messages to a tunnel.
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
   * Payload to send via the tunnel.
   */
  const void *payload;

  /**
   * Number of bytes in 'cls'.
   */
  size_t len;
};


/**
 * Information we track per mesh tunnel.
 */
struct tunnel_state
{
  struct tunnel_notify_queue *head;
  struct tunnel_notify_queue *tail;
  struct GNUNET_MESH_TransmitHandle *th;
  struct GNUNET_MESH_Tunnel *tunnel;
};


/**
 * The handle to the configuration used throughout the process
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * The handle to the helper
 */
static struct GNUNET_HELPER_Handle *helper_handle;

/**
 * Arguments to the exit helper.
 */
static char *exit_argv[7];

/**
 * IPv6 prefix (0..127) from configuration file.
 */
static unsigned long long ipv6prefix;

/**
 * Final status code.
 */
static int ret;

/**
 * The handle to mesh
 */
static struct GNUNET_MESH_Handle *mesh_handle;

/**
 * This hashmaps contains the mapping from peer, service-descriptor,
 * source-port and destination-port to a struct redirect_state
 */
static struct GNUNET_CONTAINER_MultiHashMap *connections_map;

/**
 * Heap so we can quickly find "old" connections.
 */
static struct GNUNET_CONTAINER_Heap *connections_heap;

/**
 * If there are at least this many connections, old ones will be removed
 */
static long long unsigned int max_connections = 200;

/**
 * This hashmaps saves interesting things about the configured UDP services
 */
static struct GNUNET_CONTAINER_MultiHashMap *udp_services;

/**
 * This hashmaps saves interesting things about the configured TCP services
 */
static struct GNUNET_CONTAINER_MultiHashMap *tcp_services;


/**
 * Given IP information about a connection, calculate the respective
 * hash we would use for the 'connections_map'.
 *
 * @param hash resulting hash
 * @param ri information about the connection
 */
static void
hash_redirect_info (GNUNET_HashCode * hash, 
		    const struct redirect_info *ri)
{
  char *off;

  memset (hash, 0, sizeof (GNUNET_HashCode));
  /* the GNUnet hashmap only uses the first sizeof(unsigned int) of the hash */
  off = (char*) hash;
  switch (ri->remote_address.af)
  {
  case AF_INET:
    memcpy (off, &ri->remote_address.address.ipv4, sizeof (struct in_addr));
    off += sizeof (struct in_addr);
    break;
  case AF_INET6:
    memcpy (off, &ri->remote_address.address.ipv6, sizeof (struct in6_addr));
    off += sizeof (struct in_addr);
    break;
  default:
    GNUNET_assert (0);
  }
  memcpy (off, &ri->remote_address.port, sizeof (uint16_t));
  memcpy (off, &ri->remote_address.proto, sizeof (uint8_t));
  memcpy (off, &ri->source_port, sizeof (uint8_t));
}


/**
 * Given a service descriptor and a destination port, find the
 * respective service entry.
 *
 * @param service_map map of services (TCP or UDP)
 * @param desc service descriptor
 * @param dpt destination port
 * @return NULL if we are not aware of such a service
 */
struct redirect_service *
find_service (struct GNUNET_CONTAINER_MultiHashMap *service_map,
	      const GNUNET_HashCode *desc,
	      uint16_t dpt)
{
  char key[sizeof (GNUNET_HashCode) + sizeof (uint16_t)];

  memcpy (&key[0], &dpt, sizeof (uint16_t));
  memcpy (&key[sizeof(uint16_t)], desc, sizeof (GNUNET_HashCode));
  return GNUNET_CONTAINER_multihashmap_get (service_map,
					    (GNUNET_HashCode *) key);
}


/**
 * Free memory associated with a service record.
 *
 * @param cls unused
 * @param key service descriptor
 * @param value service record to free
 * @return GNUNET_OK
 */
static int
free_service_record (void *cls,
		     const GNUNET_HashCode *key,
		     void *value)
{
  struct redirect_service *service = value;

  GNUNET_free (service);
  return GNUNET_OK;
}


/**
 * Given a service descriptor and a destination port, find the
 * respective service entry.
 *
 * @param service_map map of services (TCP or UDP)
 * @param name name of the service 
 * @param dpt destination port
 * @param service service information record to store (service->desc will be set).
 */
static void
store_service (struct GNUNET_CONTAINER_MultiHashMap *service_map,
	       const char *name,
	       uint16_t dpt,
	       struct redirect_service *service)
{
  char key[sizeof (GNUNET_HashCode) + sizeof (uint16_t)];
  GNUNET_HashCode desc;

  GNUNET_CRYPTO_hash (name, strlen (name) + 1, &desc);
  service->desc = desc;
  memcpy (&key[0], &dpt, sizeof (uint16_t));
  memcpy (&key[sizeof(uint16_t)], &desc, sizeof (GNUNET_HashCode));
  if (GNUNET_OK !=
      GNUNET_CONTAINER_multihashmap_put (service_map,
					 (GNUNET_HashCode *) key,
					 service,
					 GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
  {
    free_service_record (NULL, (GNUNET_HashCode *) key, service);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Got duplicate service records for `%s:%u'\n"),
		name,
		(unsigned int) dpt);
  }
}


/**
 * MESH is ready to receive a message for the tunnel.  Transmit it.
 *
 * @param cls the 'struct tunnel_state'.
 * @param size number of bytes available in buf
 * @param buf where to copy the message
 * @return number of bytes copied to buf
 */
static size_t
send_to_peer_notify_callback (void *cls, size_t size, void *buf)
{
  struct tunnel_state *s = cls;
  struct GNUNET_MESH_Tunnel *tunnel = s->tunnel;
  struct tunnel_notify_queue *tnq;

  s->th = NULL;
  tnq = s->head;
  GNUNET_assert (size >= tnq->len);
  memcpy (buf, tnq->payload, tnq->len);
  size = tnq->len;
  GNUNET_CONTAINER_DLL_remove (s->head, 
			       s->tail,
			       tnq);  
  GNUNET_free (tnq);
  if (NULL != (tnq = s->head))
    s->th = GNUNET_MESH_notify_transmit_ready (tunnel, 
					       GNUNET_NO /* corking */, 
					       0 /* priority */,
					       GNUNET_TIME_UNIT_FOREVER_REL,
					       NULL,
					       tnq->len,
					       &send_to_peer_notify_callback,
					       s);
  return size;
}


/**
 * Send the given packet via the mesh tunnel.
 *
 * @param mesh_tunnel destination
 * @param payload message to transmit
 * @param payload_length number of bytes in payload
 * @param desc descriptor to add 
 * @param mtype message type to use
 */
static void
send_packet_to_mesh_tunnel (struct GNUNET_MESH_Tunnel *mesh_tunnel,
			    const void *payload,
			    size_t payload_length,
			    const GNUNET_HashCode *desc,
			    uint16_t mtype)
{
  struct tunnel_state *s;
  struct tunnel_notify_queue *tnq;
  struct GNUNET_MessageHeader *msg;
  size_t len;
  GNUNET_HashCode *dp;

  len = sizeof (struct GNUNET_MessageHeader) + sizeof (GNUNET_HashCode) + payload_length;
  if (len >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }
  tnq = GNUNET_malloc (sizeof (struct tunnel_notify_queue) + len);
  tnq->payload = &tnq[1];
  tnq->len = len;
  msg = (struct GNUNET_MessageHeader *) &tnq[1];
  msg->size = htons ((uint16_t) len);
  msg->type = htons (mtype);
  dp = (GNUNET_HashCode *) &msg[1];
  *dp = *desc;
  memcpy (&dp[1], payload, payload_length);
  s = GNUNET_MESH_tunnel_get_data (mesh_tunnel);
  GNUNET_assert (NULL != s);
  GNUNET_CONTAINER_DLL_insert_tail (s->head, s->tail, tnq);
  if (NULL == s->th)
    s->th = GNUNET_MESH_notify_transmit_ready (mesh_tunnel, GNUNET_NO /* cork */, 0 /* priority */,
					       GNUNET_TIME_UNIT_FOREVER_REL,
					       NULL, len,
					       &send_to_peer_notify_callback,
					       s);
}


/**
 * Get our connection tracking state.  Warns if it does not exists,
 * refreshes the timestamp if it does exist.
 *
 * @param af address family
 * @param protocol IPPROTO_UDP or IPPROTO_TCP
 * @param destination_ip target IP
 * @param destination_port target port
 * @param source_port source port
 * @return NULL if we have no tracking information for this tuple
 */
static struct redirect_state *
get_redirect_state (int af,
		    int protocol,
		    const void *destination_ip,
		    uint16_t destination_port,
		    uint16_t source_port)
{
  struct redirect_info ri;
  GNUNET_HashCode state_key;
  struct redirect_state *state;

  ri.remote_address.af = af;
  if (af == AF_INET)
    ri.remote_address.address.ipv4 = *((struct in_addr*) destination_ip);
  else
    ri.remote_address.address.ipv6 = * ((struct in6_addr*) destination_ip);
  ri.remote_address.port = destination_port;
  ri.remote_address.proto = IPPROTO_UDP;
  ri.source_port = source_port;

  hash_redirect_info (&state_key, &ri);
  state = GNUNET_CONTAINER_multihashmap_get (connections_map, &state_key);
  if (NULL == state)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		_("Packet dropped, have no matching connection information\n"));
    return NULL;
  }
  /* Mark this connection as freshly used */
  GNUNET_CONTAINER_heap_update_cost (connections_heap, 
				     state->heap_node,
                                     GNUNET_TIME_absolute_get ().abs_value);
  return state;
}


/**
 * @brief Handles an UDP packet received from the helper.
 *
 * @param udp A pointer to the Packet
 * @param pktlen number of bytes in 'udp'
 * @param destination_ip destination IP-address
 * @param af address family (AFINET or AF_INET6)
 */
static void
udp_from_helper (const struct udp_packet *udp, 
		 size_t pktlen,
		 const void *destination_ip, int af)
{
  struct redirect_state *state;
  struct GNUNET_MESH_Tunnel *tunnel;
  GNUNET_HashCode desc;

  if (pktlen < sizeof (struct udp_packet))
  {
    /* blame kernel */
    GNUNET_break (0);
    return;
  }
  if (pktlen != ntohs (udp->len))
  {
    /* blame kernel */
    GNUNET_break (0);
    return;
  }
  state = get_redirect_state (af, IPPROTO_UDP,
			      destination_ip,
			      ntohs (udp->dpt), 
			      ntohs (udp->spt));
  if (NULL == state)
    return;
  tunnel = state->tunnel;

  // FIXME...
#if 0
  if (state->type == SERVICE)
  {
    /* check if spt == serv.remote if yes: set spt = serv.myport ("nat") */
    if (ntohs (udp->spt) == state->serv->remote_port)
    {
      udp->spt = htons (state->serv->my_port);
    }
    else
    {
      /* otherwise the answer came from a different port (tftp does this)
       * add this new port to the list of all services, so that the packets
       * coming back from the client to this new port will be routed correctly
       */
      struct redirect_service *serv =
          GNUNET_malloc (sizeof (struct redirect_service));
      memcpy (serv, state->serv, sizeof (struct redirect_service));
      serv->my_port = ntohs (udp->spt);
      serv->remote_port = ntohs (udp->spt);
      uint16_t *desc = alloca (sizeof (GNUNET_HashCode) + 2);

      memcpy ((GNUNET_HashCode *) (desc + 1), &state->desc,
              sizeof (GNUNET_HashCode));
      *desc = ntohs (udp->spt);
      GNUNET_assert (GNUNET_OK ==
                     GNUNET_CONTAINER_multihashmap_put (udp_services,
                                                        (GNUNET_HashCode *)
                                                        desc, serv,
                                                        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));

      state->serv = serv;
    }
  }
  
  if (state->type == SERVICE)
    memcpy (&desc, &state->desc, sizeof (GNUNET_HashCode));
  else
    memcpy (&desc, &state->remote, sizeof (struct remote_addr));
#else
  memset (&desc, 0, sizeof (desc));
#endif

  /* send udp-packet back */
  send_packet_to_mesh_tunnel (tunnel,
			      udp, pktlen,
			      &desc,
			      state->serv != NULL
			      ? GNUNET_MESSAGE_TYPE_VPN_SERVICE_UDP_BACK 
			      : GNUNET_MESSAGE_TYPE_VPN_REMOTE_UDP_BACK);
}


/**
 * @brief Handles a TCP packet received from the helper.
 *
 * @param tcp A pointer to the Packet
 * @param pktlen the length of the packet, including its header
 * @param destination_ip destination IP-address
 * @param af address family (AFINET or AF_INET6)
 */
static void
tcp_from_helper (const struct tcp_packet *tcp, 
		 size_t pktlen,
		 const void *destination_ip, int af)
{
  struct redirect_state *state;
  struct GNUNET_MESH_Tunnel *tunnel;
  GNUNET_HashCode desc;

  if (pktlen < sizeof (struct tcp_packet))
  {
    /* blame kernel */
    GNUNET_break (0);
    return;
  }
  state = get_redirect_state (af, IPPROTO_TCP,
			      destination_ip, 
			      ntohs (tcp->dpt),
			      ntohs (tcp->spt));
  if (NULL == state)
    return;
  tunnel = state->tunnel;

  // FIXME...
#if 0
  if (state->type == SERVICE)
  {
    /* check if spt == serv.remote if yes: set spt = serv.myport ("nat") */
    if (ntohs (tcp->spt) == state->serv->remote_port)
    {
      tcp->spt = htons (state->serv->my_port);
    }
    else
    {
      // This is an illegal packet.
      return;
    }
  }

  /* send tcp-packet back */
  if (state->type == SERVICE)
    memcpy (&desc, &state->desc, sizeof (GNUNET_HashCode));
  else
    memcpy (&desc, &state->remote, sizeof (struct remote_addr));
#else
  memset (&desc, 0, sizeof (desc));
#endif
  

  send_packet_to_mesh_tunnel (tunnel,
			      tcp, pktlen,
			      &desc,
			      state->serv != NULL
			      ? GNUNET_MESSAGE_TYPE_VPN_SERVICE_TCP_BACK 
			      : GNUNET_MESSAGE_TYPE_VPN_REMOTE_TCP_BACK);
}


/**
 * Receive packets from the helper-process
 *
 * @param cls unused
 * @param client unsued
 * @param message message received from helper
 */
static void
message_token (void *cls GNUNET_UNUSED, void *client GNUNET_UNUSED,
               const struct GNUNET_MessageHeader *message)
{
  const struct tun_header *pkt_tun;
  size_t size;

  if (ntohs (message->type) != GNUNET_MESSAGE_TYPE_VPN_HELPER)
  {
    GNUNET_break (0);
    return;
  }
  size = ntohs (message->size);
  if (size < sizeof (struct tun_header) + sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break (0);
    return;
  }
  pkt_tun = (const struct tun_header *) &message[1];
  size -= sizeof (struct tun_header) + sizeof (struct GNUNET_MessageHeader);
  switch (ntohs (pkt_tun->proto))
  {
  case ETH_P_IPV6:
    {
      const struct ip6_header *pkt6;

      if (size < sizeof (struct ip6_header))
      {
	/* Kernel to blame? */
	GNUNET_break (0);
	return;
      }
      pkt6 = (struct ip6_header *) &pkt_tun[1];
      if (size != ntohs (pkt6->payload_length))
      {
	/* Kernel to blame? */
	GNUNET_break (0);
	return;
      }
      size -= sizeof (struct ip6_header);
      switch (pkt6->next_header)
      {
      case IPPROTO_UDP:
	udp_from_helper ( (const struct udp_packet *) &pkt6[1], size,
			  &pkt6->destination_address, 
			  AF_INET6);
	break;
      case IPPROTO_TCP:
	tcp_from_helper ((const struct tcp_packet *) &pkt6[1], size,
			 &pkt6->destination_address, 
			 AF_INET6);
	break;
      default:
	GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		    _("IPv6 packet with unsupported next header received.  Ignored.\n"));
	return;
      }
    }
    break;
  case ETH_P_IPV4:
    {
      const struct ip4_header *pkt4;

      if (size < sizeof (struct ip4_header))
      {
	/* Kernel to blame? */
	GNUNET_break (0);
	return;
      }
      pkt4 = (const struct ip4_header *) &pkt_tun[1];
      if (size != ntohs (pkt4->total_length))
      {
	/* Kernel to blame? */
	GNUNET_break (0);
	return;
      }
      if (pkt4->header_length * 4 != sizeof (struct ip4_header))
      {
	GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		    _("IPv4 packet options received.  Ignored.\n"));
	return;
      }
      size -= sizeof (struct ip4_header);
      switch (pkt4->protocol)
      {
      case IPPROTO_UDP:
	udp_from_helper ((const struct udp_packet *) &pkt4[1], size,
			 &pkt4->destination_address, AF_INET);
	break;
      case IPPROTO_TCP:
	tcp_from_helper ((const struct tcp_packet *) &pkt4[1], size,
			 &pkt4->destination_address, AF_INET);
	break;
      default:
	GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		    _("IPv4 packet with unsupported next header received.  Ignored.\n"));
	return;
      }
    }
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Packet from unknown protocol %u received.  Ignored.\n"),
		ntohs (pkt_tun->proto));
    break;
  }
}




void
prepare_ipv4_packet (size_t len, uint16_t pktlen, void *payload,
                     uint8_t protocol, void *ipaddress, void *tunnel,
                     struct redirect_info *state, struct ip4_header *pkt4)
{
  const char *ipv4addr = exit_argv[4];
  const char *ipv4mask = exit_argv[5];
  uint32_t tmp;
  uint32_t tmp2;

  GNUNET_assert (1 == inet_pton (AF_INET, ipv4addr, &tmp));
  GNUNET_assert (1 == inet_pton (AF_INET, ipv4mask, &tmp2));
  memcpy (&pkt4[1], payload, pktlen);
  pkt4->version = 4;
  pkt4->header_length = sizeof (struct ip4_header) / 4;
  pkt4->diff_serv = 0;
  pkt4->total_length = htons (sizeof (struct ip4_header) + pktlen);
  pkt4->identification = 0; // FIXME!
  pkt4->flags = 0;
  pkt4->fragmentation_offset = 0;
  pkt4->ttl = 255;
  pkt4->protocol = protocol;
  pkt4->checksum = 0;        /* Will be calculated later */

  memcpy (&pkt4->destination_address, ipaddress, sizeof (struct in_addr));

  /* Generate a new src-address  -- FIXME: not always, right!? */

  /* This should be a noop */
  tmp = tmp & tmp2;
  tmp |= ntohl (*((uint32_t *) tunnel)) & (~tmp2);

  pkt4->source_address.s_addr = tmp;
  pkt4->checksum = GNUNET_CRYPTO_crc16_n (pkt4, sizeof (struct ip4_header));

  // FIXME:  memcpy (&state->addr, &tmp, 4);

  switch (protocol)
  {
  case IPPROTO_UDP:
    {
      struct udp_packet *pkt4_udp = (struct udp_packet *) &pkt4[1];
      // FIXME: state->pt = pkt4_udp->spt;
      pkt4_udp->crc = 0;  /* Optional for IPv4 */
    }
    break;
  case IPPROTO_TCP:
    {
      struct tcp_packet *pkt4_tcp = (struct tcp_packet *) &pkt4[1];
      
      // FIXME: state->pt = pkt4_tcp->spt;
      pkt4_tcp->crc = 0;
      uint32_t sum = 0;
      sum = GNUNET_CRYPTO_crc16_step (sum, 
				      &pkt4->source_address,
				      sizeof (struct in_addr) * 2);
      tmp = (protocol << 16) | (0xffff & pktlen);
      tmp = htonl (tmp);
      sum = GNUNET_CRYPTO_crc16_step (sum, & tmp, 4);
      sum = GNUNET_CRYPTO_crc16_step (sum, & pkt4_tcp, pktlen);
      pkt4_tcp->crc = GNUNET_CRYPTO_crc16_finish (sum);
    }
    break;
  default:
    GNUNET_assert (0);
  }
}


void
prepare_ipv6_packet (size_t len, uint16_t pktlen, void *payload,
                     uint16_t protocol, void *ipaddress, void *tunnel,
                     struct redirect_info *state, struct ip6_header *pkt6)
{
  const char *ipv6addr = exit_argv[2];
  uint32_t tmp;


  memcpy (&pkt6[1], payload, pktlen);

  pkt6->version = 6;
  pkt6->next_header = protocol;
  pkt6->payload_length = htons (pktlen);
  pkt6->hop_limit = 64;

  memcpy (&pkt6->destination_address, ipaddress, sizeof (struct in6_addr));

  /* Generate a new src-address
   * This takes as much from the address of the tunnel as fits into
   * the host-mask*/

  unsigned long long ipv6prefix_r = (ipv6prefix + 7) / 8;

  inet_pton (AF_INET6, ipv6addr, &pkt6->source_address);

  if (ipv6prefix_r < (16 - sizeof (void *)))
    ipv6prefix_r = 16 - sizeof (void *);

  unsigned int offset = ipv6prefix_r - (16 - sizeof (void *));

  memcpy ((((char *) &pkt6->source_address)) + ipv6prefix_r,
          ((char *) &tunnel) + offset, 16 - ipv6prefix_r);

  /* copy the needed information into the state */
  // FIXME: memcpy (&state->addr, &pkt6->source_address, 16);

  switch (protocol)
  {
  case IPPROTO_UDP:
    {
      struct udp_packet *pkt6_udp = (struct udp_packet *) &pkt6[1];
      
      // FIXME: state->pt = pkt6_udp->spt;      
      pkt6_udp->crc = 0;
      uint32_t sum = 0;
      sum =
        GNUNET_CRYPTO_crc16_step (sum, & pkt6->source_address,
				  16 * 2);
      tmp = (htons (pktlen) & 0xffff);
      sum = GNUNET_CRYPTO_crc16_step (sum, & tmp, 4);
      tmp = htons (pkt6->next_header & 0x00ff);
      sum = GNUNET_CRYPTO_crc16_step (sum, & tmp, 4);
      sum =
        GNUNET_CRYPTO_crc16_step (sum, pkt6_udp,
				  ntohs (pkt6_udp->len));
      pkt6_udp->crc = GNUNET_CRYPTO_crc16_finish (sum);
    }
    break;
  case IPPROTO_TCP:
    {
      struct tcp_packet *pkt6_tcp = (struct tcp_packet *) pkt6;
      
      // FIXME: state->pt = pkt6_tcp->spt;
      pkt6_tcp->crc = 0;
      uint32_t sum = 0;
      
      sum =
        GNUNET_CRYPTO_crc16_step (sum, & pkt6->source_address, 16 * 2);
      tmp = htonl (pktlen);
      sum = GNUNET_CRYPTO_crc16_step (sum, & tmp, 4);
      tmp = htonl (((pkt6->next_header & 0x000000ff)));
      sum = GNUNET_CRYPTO_crc16_step (sum, & tmp, 4);
      
      sum =
        GNUNET_CRYPTO_crc16_step (sum,  pkt6_tcp,
				  ntohs (pkt6->payload_length));
      pkt6_tcp->crc = GNUNET_CRYPTO_crc16_finish (sum);
    }
    break;
  default:
    GNUNET_assert (0);
    break;
  }
}


/**
 * We've just experienced a connection in use.  Track it, or if it is
 * already tracked, update the tracking.
 *
 * @param u_i IP-level connection tracking state
 * @param tunnel associated mesh tunnel
 * @param desc service descriptor (or NULL)
 * @param serv service information
 */
void
update_state_map (const struct redirect_info *ri,
		  struct GNUNET_MESH_Tunnel *tunnel,
		  const GNUNET_HashCode *desc,
		  struct redirect_service *serv)
{
  struct redirect_state *state;
  GNUNET_HashCode state_key;

  hash_redirect_info (&state_key,
		      ri);
  state = GNUNET_CONTAINER_multihashmap_get (connections_map, &state_key);
  if (NULL == state)
  {
    state = GNUNET_malloc (sizeof (struct redirect_state));
    state->tunnel = tunnel;
    state->state_key = state_key;
    state->serv = serv;
    // FIXME? if (NULL != desc) state->desc = *desc;
    // FIXME? state->redirect_info = *ri;
    GNUNET_assert (GNUNET_OK ==
		   GNUNET_CONTAINER_multihashmap_put (connections_map, &state_key, state,
						      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
    state->heap_node =
      GNUNET_CONTAINER_heap_insert (connections_heap,
				    state,
				    GNUNET_TIME_absolute_get ().abs_value);
  }
  else
  {
    if (state->tunnel != tunnel) 
    {
      /* Stats / warning: two tunnels got exactly the same connection state!? */
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Two different mesh tunnels got the same connection state. Oops.\n"));
      return;
    }
    GNUNET_CONTAINER_heap_update_cost (connections_heap,
				       state->heap_node,
				       GNUNET_TIME_absolute_get ().abs_value);
  }
  while (GNUNET_CONTAINER_heap_get_size (connections_heap) > max_connections)
  {
    state = GNUNET_CONTAINER_heap_remove_root (connections_heap);
    state->heap_node = NULL;
    GNUNET_MESH_tunnel_destroy (state->tunnel);
    GNUNET_assert (GNUNET_OK ==
		   GNUNET_CONTAINER_multihashmap_remove (connections_map,
							 &state->state_key, 
							 state));
    GNUNET_free (state);
  }
}

		  


/**
 * The messages are one GNUNET_HashCode for the service followed by a struct tcp_packet
 */
static int
receive_tcp_service (void *unused GNUNET_UNUSED, struct GNUNET_MESH_Tunnel *tunnel,
                     void **tunnel_ctx GNUNET_UNUSED,
                     const struct GNUNET_PeerIdentity *sender GNUNET_UNUSED,
                     const struct GNUNET_MessageHeader *message,
                     const struct GNUNET_ATS_Information *atsi GNUNET_UNUSED)
{
#if 0
  const GNUNET_HashCode *desc = (const GNUNET_HashCode *) &message[1];
  const struct tcp_packet *pkt = (const struct tcp_packet *) &desc[1];
  uint16_t pkt_len = ntohs (message->size);
  struct redirect_service *serv;
  struct redirect_info u_i;
  GNUNET_HashCode state_key;

  /* check that we got at least a valid header */
  if (pkt_len < sizeof (struct GNUNET_MessageHeader) + sizeof (GNUNET_HashCode) + sizeof (struct tcp_packet))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  pkt_len -= (sizeof (struct GNUNET_MessageHeader) + sizeof (GNUNET_HashCode));

  if (NULL == (serv = find_service (tcp_services, desc, ntohs (pkt->dpt))))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
		_("No service found for %s on port %d!\n"),
		"TCP",
                ntohs (pkt->dpt));
    return GNUNET_YES;
  }
  pkt->dpt = htons (serv->remote_port);

  /* At this point it would be possible to check against some kind of ACL. */

  switch (serv->version)
    {
    case 4:
      {
	size_t len =
	  sizeof (struct GNUNET_MessageHeader) + sizeof (struct tun_header) +
	  sizeof (struct ip4_header) + pkt_len;       
	char buf[len];
	struct tun_header *hdr;
	struct GNUNET_MessageHeader *mhdr;
	
	memset (buf, 0, len);
	mhdr = (struct GNUNET_MessageHeader*) buf;
	hdr = (struct tun_header *) &mhdr[1];
	mhdr->type = htons (GNUNET_MESSAGE_TYPE_VPN_HELPER);
	mhdr->size = htons (len);
	hdr->flags = 0;
	hdr->proto = htons (0x0800);
	prepare_ipv4_packet (len, pkt_len, pkt, IPPROTO_TCP, &serv->v4.ip4address,
			     tunnel, &u_i, (struct ip4_header *) &hdr[1]);
	/* FIXME: here, flow-control with mesh would be nice to have... */
	(void) GNUNET_HELPER_send (helper_handle,
				   mhdr,
				   GNUNET_YES,
				   NULL, NULL);
	break;
      }
    case 6:
      {
	size_t len =
	  sizeof (struct GNUNET_MessageHeader) + sizeof (struct tun_header) +
	  sizeof (struct ip6_header) + pkt_len;
	char buf[len];
	struct tun_header *hdr;
	struct GNUNET_MessageHeader *mhdr;
	
	memset (buf, 0, len);
	mhdr = (struct GNUNET_MessageHeader*) buf;
	hdr = (struct tun_header *) &mhdr[1];
	mhdr->type = htons (GNUNET_MESSAGE_TYPE_VPN_HELPER);
	mhdr->size = htons (len);
	hdr->flags = 0;
	hdr->proto = htons (0x86dd);
	prepare_ipv6_packet (len, pkt_len, pkt, IPPROTO_TCP, &serv->v6.ip6address,
			     tunnel, &u_i, (struct ip6_header *) buf);
	    /* FIXME: here, flow-control with mesh would be nice to have... */
	(void) GNUNET_HELPER_send (helper_handle,
				   (const struct GNUNET_MessageHeader*) buf,
				   GNUNET_YES,
				   NULL, NULL);

	break;
      }
    default:
      GNUNET_assert (0);
      break;
    }


  update_state_map (&u_i, desc, tunnel, serv);
#endif
  return GNUNET_YES;
}


static int
receive_tcp_remote (void *cls GNUNET_UNUSED, struct GNUNET_MESH_Tunnel *tunnel,
                    void **tunnel_ctx GNUNET_UNUSED,
                    const struct GNUNET_PeerIdentity *sender GNUNET_UNUSED,
                    const struct GNUNET_MessageHeader *message,
                    const struct GNUNET_ATS_Information *atsi GNUNET_UNUSED)
{
  // FIXME
#if 0
  GNUNET_HashCode *desc = (GNUNET_HashCode *) (message + 1);
  struct tcp_packet *pkt = (struct tcp_packet *) (desc + 1);
  struct remote_addr *s = (struct remote_addr *) desc;
  char *buf;
  size_t len;
  uint16_t pkt_len =
      ntohs (message->size) - sizeof (struct GNUNET_MessageHeader) -
      sizeof (GNUNET_HashCode);

  struct redirect_state *state = GNUNET_malloc (sizeof (struct redirect_state));

  state->tunnel = tunnel;
  state->type = REMOTE;
  state->hashmap = tcp_connections;
  memcpy (&state->remote, s, sizeof (struct remote_addr));

  hash_redirect_info (&state->hash, &state->redirect_info, s->addrlen);

  if (GNUNET_NO ==
      GNUNET_CONTAINER_multihashmap_contains (tcp_connections, &state->hash))
  {
    GNUNET_CONTAINER_multihashmap_put (tcp_connections, &state->hash, state,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);

    state->heap_node =
        GNUNET_CONTAINER_heap_insert (tcp_connections_heap, state,
                                      GNUNET_TIME_absolute_get ().abs_value);

    if (GNUNET_CONTAINER_heap_get_size (tcp_connections_heap) >
        max_tcp_connections)
      GNUNET_SCHEDULER_add_now (collect_connections, tcp_connections_heap);
  }
  else
    GNUNET_free (state);



  len =
      sizeof (struct GNUNET_MessageHeader) + sizeof (struct pkt_tun) +
      sizeof (struct ip6_hdr) + pkt_len;
  buf = alloca (len);

  memset (buf, 0, len);

  switch (s->addrlen)
  {
  case 4:
    prepare_ipv4_packet (len, pkt_len, pkt, IPPROTO_TCP, &s->addr, tunnel,
                         state, (struct ip4_header *) buf);
    break;
  case 16:
    prepare_ipv6_packet (len, pkt_len, pkt, IPPROTO_TCP, &s->addr, tunnel,
                         state, (struct ip6_header *) buf);
    break;
  default:
    GNUNET_free (state);
    return GNUNET_SYSERR;
  }

  /* FIXME: here, flow-control with mesh would be nice to have... */
  (void) GNUNET_HELPER_send (helper_handle,
			     (const struct GNUNET_MessageHeader*) buf,
			     GNUNET_YES,
			     NULL, NULL);

#endif
  return GNUNET_YES;
}

static int
receive_udp_remote (void *cls GNUNET_UNUSED, struct GNUNET_MESH_Tunnel *tunnel,
                    void **tunnel_ctx GNUNET_UNUSED,
                    const struct GNUNET_PeerIdentity *sender GNUNET_UNUSED,
                    const struct GNUNET_MessageHeader *message,
                    const struct GNUNET_ATS_Information *atsi GNUNET_UNUSED)
{
  // FIXME
#if 0
  GNUNET_HashCode *desc = (GNUNET_HashCode *) (message + 1);
  struct udp_packet *pkt = (struct udp_packet *) (desc + 1);
  struct remote_addr *s = (struct remote_addr *) desc;
  char *buf;
  size_t len;

  GNUNET_assert (ntohs (pkt->len) ==
                 ntohs (message->size) - sizeof (struct GNUNET_MessageHeader) -
                 sizeof (GNUNET_HashCode));

  /* Prepare the state.
   * This will be saved in the hashmap, so that the receiving procedure knows
   * through which tunnel this connection has to be routed.
   */
  struct redirect_state *state = GNUNET_malloc (sizeof (struct redirect_state));

  state->tunnel = tunnel;
  state->hashmap = udp_connections;
  state->type = REMOTE;
  memcpy (&state->remote, s, sizeof (struct remote_addr));

  len =
      sizeof (struct GNUNET_MessageHeader) + sizeof (struct pkt_tun) +
      sizeof (struct ip6_hdr) + ntohs (pkt->len);
  buf = alloca (len);

  memset (buf, 0, len);

  switch (s->addrlen)
  {
  case 4:
    prepare_ipv4_packet (len, ntohs (pkt->len), pkt, IPPROTO_UDP, &s->addr,
                         tunnel, state, (struct ip4_header *) buf);
    break;
  case 16:
    prepare_ipv6_packet (len, ntohs (pkt->len), pkt, IPPROTO_UDP, &s->addr,
                         tunnel, state, (struct ip6_header *) buf);
    break;
  default:
    GNUNET_assert (0);
    break;
  }

  hash_redirect_info (&state->hash, &state->redirect_info, s->addrlen);

  (void) GNUNET_HELPER_send (helper_handle,
			     (const struct GNUNET_MessageHeader*) buf,
			     GNUNET_YES,
			     NULL, NULL);


  if (GNUNET_NO ==
      GNUNET_CONTAINER_multihashmap_contains (udp_connections, &state->hash))
  {
    GNUNET_CONTAINER_multihashmap_put (udp_connections, &state->hash, state,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);

    state->heap_node =
        GNUNET_CONTAINER_heap_insert (udp_connections_heap, state,
                                      GNUNET_TIME_absolute_get ().abs_value);

    if (GNUNET_CONTAINER_heap_get_size (udp_connections_heap) >
        max_udp_connections)
      GNUNET_SCHEDULER_add_now (collect_connections, udp_connections_heap);
  }
  else
    GNUNET_free (state);
#endif
  return GNUNET_YES;
}

/**
 * The messages are one GNUNET_HashCode for the service, followed by a struct udp_packet
 */
static int
receive_udp_service (void *cls GNUNET_UNUSED, struct GNUNET_MESH_Tunnel *tunnel,
                     void **tunnel_ctx,
                     const struct GNUNET_PeerIdentity *sender GNUNET_UNUSED,
                     const struct GNUNET_MessageHeader *message,
                     const struct GNUNET_ATS_Information *atsi GNUNET_UNUSED)
{
  // FIXME
#if 0
  GNUNET_HashCode *desc = (GNUNET_HashCode *) (message + 1);
  struct udp_packet *pkt = (struct udp_packet *) (desc + 1);
  uint16_t pkt_len = ntohs (message->size);
  struct redirect_service *serv;

  /* check that we got at least a valid header */
  if (pkt_len < sizeof (struct GNUNET_MessageHeader) + sizeof (GNUNET_HashCode) + sizeof (struct udp_packet))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  pkt_len -= (sizeof (struct GNUNET_MessageHeader) + sizeof (GNUNET_HashCode));

  GNUNET_assert (ntohs (pkt->len) ==
                 ntohs (message->size) - sizeof (struct GNUNET_MessageHeader) -
                 sizeof (GNUNET_HashCode));

  if (NULL == (serv = find_service (udp_services, desc, ntohs (pkt->dpt))))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
		_("No service found for %s on port %d!\n"),
		"UDP",
                ntohs (pkt->dpt));
    return GNUNET_YES;
  }
  pkt->dpt = htons (serv->remote_port);

  /*
   * At this point it would be possible to check against some kind of ACL.
   */

  char *buf;
  size_t len;

  /* Prepare the state.
   * This will be saved in the hashmap, so that the receiving procedure knows
   * through which tunnel this connection has to be routed.
   */
  struct redirect_state *state = GNUNET_malloc (sizeof (struct redirect_state));

  state->tunnel = tunnel;
  state->serv = serv;
  state->type = SERVICE;
  state->hashmap = udp_connections;
  memcpy (&state->desc, desc, sizeof (GNUNET_HashCode));

  len =
      sizeof (struct GNUNET_MessageHeader) + sizeof (struct pkt_tun) +
      sizeof (struct ip6_hdr) + ntohs (pkt->len);
  buf = alloca (len);

  memset (buf, 0, len);

  switch (serv->version)
  {
  case 4:
    prepare_ipv4_packet (len, ntohs (pkt->len), pkt, IPPROTO_UDP,
                         &serv->v4.ip4address, tunnel, state,
                         (struct ip4_header *) buf);
    break;
  case 6:
    prepare_ipv6_packet (len, ntohs (pkt->len), pkt, IPPROTO_UDP,
                         &serv->v6.ip6address, tunnel, state,
                         (struct ip6_header *) buf);

    break;
  default:
    GNUNET_assert (0);
    break;
  }

  hash_redirect_info (&state->hash, &state->redirect_info,
                      serv->version == 4 ? 4 : 16);

  if (GNUNET_NO ==
      GNUNET_CONTAINER_multihashmap_contains (udp_connections, &state->hash))
  {
    GNUNET_CONTAINER_multihashmap_put (udp_connections, &state->hash, state,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);

    state->heap_node =
        GNUNET_CONTAINER_heap_insert (udp_connections_heap, state,
                                      GNUNET_TIME_absolute_get ().abs_value);

    if (GNUNET_CONTAINER_heap_get_size (udp_connections_heap) >
        max_udp_connections)
      GNUNET_SCHEDULER_add_now (collect_connections, udp_connections_heap);
  }
  else
    GNUNET_free (state);

  (void) GNUNET_HELPER_send (helper_handle,
			     (const struct GNUNET_MessageHeader*) buf,
			     GNUNET_YES,
			     NULL, NULL);
#endif
  return GNUNET_YES;
}







/**
 * Callback from GNUNET_MESH for new tunnels.
 *
 * @param cls closure
 * @param tunnel new handle to the tunnel
 * @param initiator peer that started the tunnel
 * @param atsi performance information for the tunnel
 * @return initial tunnel context for the tunnel
 */
static void *
new_tunnel (void *cls GNUNET_UNUSED, struct GNUNET_MESH_Tunnel *tunnel,
            const struct GNUNET_PeerIdentity *initiator GNUNET_UNUSED,
            const struct GNUNET_ATS_Information *ats GNUNET_UNUSED)
{
  struct tunnel_state *s = GNUNET_malloc (sizeof (struct tunnel_state));
  
  s->tunnel = tunnel;
  return s;
}


/**
 * Function called by mesh whenever an inbound tunnel is destroyed.
 * Should clean up any associated state.
 *
 * @param cls closure (set from GNUNET_MESH_connect)
 * @param tunnel connection to the other end (henceforth invalid)
 * @param tunnel_ctx place where local state associated
 *                   with the tunnel is stored
 */
static void
clean_tunnel (void *cls GNUNET_UNUSED, const struct GNUNET_MESH_Tunnel *tunnel,
              void *tunnel_ctx)
{
  struct tunnel_state *s = tunnel_ctx;
  struct tunnel_notify_queue *tnq;

  while (NULL != (tnq = s->head))
  {
    GNUNET_CONTAINER_DLL_remove (s->head,
				 s->tail,
				 tnq);
    GNUNET_free (tnq);
  }
  if (NULL != s->th)
  {
    GNUNET_MESH_notify_transmit_ready_cancel (s->th);
    s->th = NULL;
  }
  GNUNET_free (s);
}


/**
 * Function that frees everything from a hashmap
 *
 * @param cls unused
 * @param hash key
 * @param value value to free
 */
static int
free_iterate (void *cls GNUNET_UNUSED,
              const GNUNET_HashCode * hash GNUNET_UNUSED, void *value)
{
  GNUNET_free (value);
  return GNUNET_YES;
}


/**
 * Function scheduled as very last function, cleans up after us
 */
static void
cleanup (void *cls GNUNET_UNUSED,
         const struct GNUNET_SCHEDULER_TaskContext *tskctx)
{
  unsigned int i;

  if (helper_handle != NULL)
  {
    GNUNET_HELPER_stop (helper_handle);
    helper_handle = NULL;
  }
  if (mesh_handle != NULL)
  {
    GNUNET_MESH_disconnect (mesh_handle);
    mesh_handle = NULL;
  }
  if (NULL != connections_map)
  {
    GNUNET_CONTAINER_multihashmap_iterate (connections_map, &free_iterate, NULL);
    GNUNET_CONTAINER_multihashmap_destroy (connections_map);
    connections_map = NULL;
  }
  if (NULL != connections_heap)
  {
    GNUNET_CONTAINER_heap_destroy (connections_heap);
    connections_heap = NULL;
  }
  if (NULL != tcp_services)
  {
    GNUNET_CONTAINER_multihashmap_iterate (tcp_services, &free_service_record, NULL);
    GNUNET_CONTAINER_multihashmap_destroy (tcp_services);
    tcp_services = NULL;
  }
  if (NULL != udp_services)
  {
    GNUNET_CONTAINER_multihashmap_iterate (udp_services, &free_service_record, NULL);
    GNUNET_CONTAINER_multihashmap_destroy (udp_services);
    udp_services = NULL;
  }
  for (i=0;i<5;i++)
    GNUNET_free_non_null (exit_argv[i]);
}


/**
 * Add services to the service map.
 *
 * @param proto IPPROTO_TCP or IPPROTO_UDP
 * @param cpy copy of the service descriptor (can be mutilated)
 * @param name DNS name of the service
 */
static void
add_services (int proto,
	      char *cpy,
	      const char *name)
{
  char *redirect;
  char *hostname;
  char *hostport;
  struct redirect_service *serv;

  for (redirect = strtok (cpy, " "); redirect != NULL;
       redirect = strtok (NULL, " "))
  {
    if (NULL == (hostname = strstr (redirect, ":")))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  "option `%s' for domain `%s' is not formatted correctly!\n",
		  redirect,
		  name);
      continue;
    }
    hostname[0] = '\0';
    hostname++;
    if (NULL == (hostport = strstr (hostname, ":")))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  "option `%s' for domain `%s' is not formatted correctly!\n",
		  redirect,
		  name);
      continue;
    }
    hostport[0] = '\0';
    hostport++;
    
    int local_port = atoi (redirect);
    int remote_port = atoi (hostport);
    
    if (!((local_port > 0) && (local_port < 65536)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  "`%s' is not a valid port number (for domain `%s')!", redirect,
		  name);
      continue;
    }
    if (!((remote_port > 0) && (remote_port < 65536)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  "`%s' is not a valid port number (for domain `%s')!", hostport,
		  name);
      continue;
    }

    serv = GNUNET_malloc (sizeof (struct redirect_service));
    serv->my_port = (uint16_t) local_port;
    serv->address.port = remote_port;
    if (0 == strcmp ("localhost4", hostname))
    {
      const char *ip4addr = exit_argv[4];

      serv->address.af = AF_INET;      
      GNUNET_assert (1 != inet_pton (AF_INET, ip4addr, &serv->address.address.ipv4));
    }
    else if (0 == strcmp ("localhost6", hostname))
    {
      const char *ip6addr = exit_argv[2];

      serv->address.af = AF_INET6;
      GNUNET_assert (1 == inet_pton (AF_INET6, ip6addr, &serv->address.address.ipv6));
    }
    else
    {
      struct addrinfo *res;      
      int ret;

      ret = getaddrinfo (hostname, NULL, NULL, &res);      
      if ( (ret != 0) || (res == NULL) )
      {
	GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		    _("No addresses found for hostname `%s' of service `%s'!\n"),
		    hostname,
		    name);
	GNUNET_free (serv);
	continue;
      }
      
      serv->address.af = res->ai_family;
      switch (res->ai_family)
      {
	case AF_INET:
	  serv->address.address.ipv4 = ((struct sockaddr_in *) res->ai_addr)->sin_addr;
	  break;
	case AF_INET6:
	  serv->address.address.ipv6 = ((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
	  break;
      default:
	freeaddrinfo (res);
	GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		    _("No IP addresses found for hostname `%s' of service `%s'!\n"),
		    hostname,
		    name);
	GNUNET_free (serv);
	continue;
      }
      freeaddrinfo (res);
    }
    store_service ((IPPROTO_UDP == proto) ? udp_services : tcp_services,
		   name,
		   local_port,
		   serv);
  }
}


/**
 * Reads the configuration servicecfg and populates udp_services
 *
 * @param cls unused
 * @param section name of section in config, equal to hostname
 */
static void
read_service_conf (void *cls GNUNET_UNUSED, const char *section)
{
  char *cpy;

  if ((strlen (section) < 8) ||
      (0 != strcmp (".gnunet.", section + (strlen (section) - 8))))
    return;
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_string (cfg, section, "UDP_REDIRECTS",
					     &cpy))
  {
    add_services (IPPROTO_UDP, cpy, section);
    GNUNET_free (cpy);
  }
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_string (cfg, section, "TCP_REDIRECTS",
					     &cpy))
  {
    add_services (IPPROTO_TCP, cpy, section);
    GNUNET_free (cpy);
  }
}


/**
 * @brief Main function that will be run by the scheduler.
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
  static struct GNUNET_MESH_MessageHandler handlers[] = {
    {&receive_udp_service, GNUNET_MESSAGE_TYPE_VPN_SERVICE_UDP, 0},
    {&receive_tcp_service, GNUNET_MESSAGE_TYPE_VPN_SERVICE_TCP, 0},
    {NULL, 0, 0},
    {NULL, 0, 0},
    {NULL, 0, 0}
  };

  static GNUNET_MESH_ApplicationType apptypes[] = {
    GNUNET_APPLICATION_TYPE_END,
    GNUNET_APPLICATION_TYPE_END,
    GNUNET_APPLICATION_TYPE_END
  };
  unsigned int handler_idx;
  unsigned int app_idx;
  int udp;
  int tcp;
  char *ifname;
  char *ipv6addr;
  char *ipv6prefix_s;
  char *ipv4addr;
  char *ipv4mask;
  struct in_addr v4;
  struct in6_addr v6;

  cfg = cfg_;
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &cleanup, cls);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "exit", "MAX_CONNECTIONS",
                                             &max_connections))
    max_connections = 1024;
  exit_argv[0] = GNUNET_strdup ("exit-gnunet");
  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "exit", "IFNAME", &ifname))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No entry 'IFNAME' in configuration!\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  exit_argv[1] = ifname;
  if ( (GNUNET_SYSERR ==
	GNUNET_CONFIGURATION_get_value_string (cfg, "exit", "IPV6ADDR",
					       &ipv6addr) ||
	(1 != inet_pton (AF_INET6, ipv6addr, &v6))) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No valid entry 'IPV6ADDR' in configuration!\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  exit_argv[2] = ipv6addr;
  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "exit", "IPV6PREFIX",
                                             &ipv6prefix_s))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No entry 'IPV6PREFIX' in configuration!\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  exit_argv[3] = ipv6prefix_s;
  if ( (GNUNET_OK !=
	GNUNET_CONFIGURATION_get_value_number (cfg, "exit",
					       "IPV6PREFIX",
					       &ipv6prefix)) ||
       (ipv6prefix >= 127) )
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  if ( (GNUNET_SYSERR ==
	GNUNET_CONFIGURATION_get_value_string (cfg, "exit", "IPV4ADDR",
					       &ipv4addr) ||
	(1 != inet_pton (AF_INET, ipv4addr, &v4))) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No valid entry for 'IPV4ADDR' in configuration!\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  exit_argv[4] = ipv4addr;
  if ( (GNUNET_SYSERR ==
	GNUNET_CONFIGURATION_get_value_string (cfg, "exit", "IPV4MASK",
					       &ipv4mask) ||
	(1 != inet_pton (AF_INET, ipv4mask, &v4))) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No valid entry 'IPV4MASK' in configuration!\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  exit_argv[5] = ipv4mask;
  exit_argv[6] = NULL;

  app_idx = 0;
  handler_idx = 2;
  udp = GNUNET_CONFIGURATION_get_value_yesno (cfg, "exit", "ENABLE_UDP");
  tcp = GNUNET_CONFIGURATION_get_value_yesno (cfg, "exit", "ENABLE_TCP");
  if (GNUNET_YES == udp)
  {
    handlers[handler_idx].callback = &receive_udp_remote;
    handlers[handler_idx].expected_size = 0;
    handlers[handler_idx].type = GNUNET_MESSAGE_TYPE_VPN_REMOTE_UDP;
    apptypes[app_idx] = GNUNET_APPLICATION_TYPE_INTERNET_UDP_GATEWAY;
    handler_idx++;
    app_idx++;
  }

  if (GNUNET_YES == tcp)
  {
    handlers[handler_idx].callback = &receive_tcp_remote;
    handlers[handler_idx].expected_size = 0;
    handlers[handler_idx].type = GNUNET_MESSAGE_TYPE_VPN_REMOTE_TCP;
    apptypes[app_idx] = GNUNET_APPLICATION_TYPE_INTERNET_TCP_GATEWAY;
    handler_idx++;
    app_idx++;
  }
  udp_services = GNUNET_CONTAINER_multihashmap_create (65536);
  tcp_services = GNUNET_CONTAINER_multihashmap_create (65536);
  GNUNET_CONFIGURATION_iterate_sections (cfg, &read_service_conf, NULL);

  connections_map = GNUNET_CONTAINER_multihashmap_create (65536);
  connections_heap = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  mesh_handle 
    = GNUNET_MESH_connect (cfg, 42 /* queue size */, NULL, 
			   &new_tunnel, 
			   &clean_tunnel, handlers,
                           apptypes);
  if (NULL == mesh_handle)
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  helper_handle = GNUNET_HELPER_start ("gnunet-helper-vpn", 
				       exit_argv,
				       &message_token, NULL);
}


/**
 * The main function
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
          GNUNET_PROGRAM_run (argc, argv, "gnunet-daemon-exit",
                              gettext_noop
                              ("Daemon to run to provide an IP exit node for the VPN"),
                              options, &run, NULL)) ? ret : 1;
}


/* end of gnunet-daemon-exit.c */
