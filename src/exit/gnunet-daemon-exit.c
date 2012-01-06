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
 *
 * TODO:
 * - setup_fresh_address is not implemented
 * - need proper message headers for mesh P2P messages
 * - factor out crc computations from DNS/EXIT into shared library?
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
 * Information about an address.
 */
struct SocketAddress
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
   * IPPROTO_TCP or IPPROTO_UDP;
   */
  uint8_t proto;

  /**
   * Remote port, in host byte order!
   */
  uint16_t port;

};

/**
 * This struct is saved into the services-hashmap to represent
 * a service this peer is specifically offering an exit for
 * (for a specific domain name).
 */
struct LocalService
{

  /**
   * Remote address to use for the service.
   */
  struct SocketAddress address;

  /**
   * DNS name of the service.
   */
  char *name;

  /**
   * Port I am listening on within GNUnet for this service, in host
   * byte order.  (as we may redirect ports).
   */
  uint16_t my_port;

};

/**
 * Information we use to track a connection (the classical 6-tuple of
 * IP-version, protocol, source-IP, destination-IP, source-port and
 * destinatin-port.
 */
struct RedirectInformation 
{

  /**
   * Address information for the other party (equivalent of the
   * arguments one would give to "connect").
   */
  struct SocketAddress remote_address;

  /**
   * Address information we used locally (AF and proto must match
   * "remote_address").  Equivalent of the arguments one would give to
   * "bind".
   */
  struct SocketAddress local_address;

  /* 
     Note 1: additional information might be added here in the
     future to support protocols that require special handling,
     such as ftp/tftp 

     Note 2: we might also sometimes not match on all components
     of the tuple, to support protocols where things do not always
     fully map.
  */
};


/**
 * Queue of messages to a tunnel.
 */
struct TunnelMessageQueue
{
  /**
   * This is a doubly-linked list.
   */
  struct TunnelMessageQueue *next;

  /**
   * This is a doubly-linked list.
   */
  struct TunnelMessageQueue *prev;

  /**
   * Payload to send via the tunnel.
   */
  const void *payload;

  /**
   * Number of bytes in 'payload'.
   */
  size_t len;
};


/**
 * This struct is saved into connections_map to allow finding the
 * right tunnel given an IP packet from TUN.  It is also associated
 * with the tunnel's closure so we can find it again for the next
 * message from the tunnel.
 */
struct TunnelState
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
  struct LocalService *serv;

  /**
   * Head of DLL of messages for this tunnel.
   */
  struct TunnelMessageQueue *head;

  /**
   * Tail of DLL of messages for this tunnel.
   */
  struct TunnelMessageQueue *tail;

  /**
   * Active tunnel transmission request (or NULL).
   */
  struct GNUNET_MESH_TransmitHandle *th;

  /**
   * Primary redirection information for this connection.
   */
  struct RedirectInformation ri;

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
 * The handle to mesh
 */
static struct GNUNET_MESH_Handle *mesh_handle;

/**
 * This hashmaps contains the mapping from peer, service-descriptor,
 * source-port and destination-port to a struct TunnelState
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
hash_redirect_info (GNUNET_HashCode *hash, 
		    const struct RedirectInformation *ri)
{
  char *off;

  memset (hash, 0, sizeof (GNUNET_HashCode));
  /* the GNUnet hashmap only uses the first sizeof(unsigned int) of the hash,
     so we put the IP address in there (and hope for few collisions) */
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
  off += sizeof (uint16_t);
  switch (ri->local_address.af)
  {
  case AF_INET:
    memcpy (off, &ri->local_address.address.ipv4, sizeof (struct in_addr));
    off += sizeof (struct in_addr);
    break;
  case AF_INET6:
    memcpy (off, &ri->local_address.address.ipv6, sizeof (struct in6_addr));
    off += sizeof (struct in_addr);
    break;
  default:
    GNUNET_assert (0);
  }
  memcpy (off, &ri->local_address.port, sizeof (uint16_t));
  off += sizeof (uint16_t);
  memcpy (off, &ri->remote_address.proto, sizeof (uint8_t));
  off += sizeof (uint8_t);
}


/**
 * Get our connection tracking state.  Warns if it does not exists,
 * refreshes the timestamp if it does exist.
 *
 * @param af address family
 * @param protocol IPPROTO_UDP or IPPROTO_TCP
 * @param destination_ip target IP
 * @param destination_port target port
 * @param local_ip local IP
 * @param local_port local port
 * @param state_key set to hash's state if non-NULL
 * @return NULL if we have no tracking information for this tuple
 */
static struct TunnelState *
get_redirect_state (int af,
		    int protocol,		    
		    const void *destination_ip,
		    uint16_t destination_port,
		    const void *local_ip,
		    uint16_t local_port,
		    GNUNET_HashCode *state_key)
{
  struct RedirectInformation ri;
  GNUNET_HashCode key;
  struct TunnelState *state;

  ri.remote_address.af = af;
  if (af == AF_INET)
    ri.remote_address.address.ipv4 = *((struct in_addr*) destination_ip);
  else
    ri.remote_address.address.ipv6 = * ((struct in6_addr*) destination_ip);
  ri.remote_address.port = destination_port;
  ri.remote_address.proto = protocol;
  ri.local_address.af = af;
  if (af == AF_INET)
    ri.local_address.address.ipv4 = *((struct in_addr*) local_ip);
  else
    ri.local_address.address.ipv6 = * ((struct in6_addr*) local_ip);
  ri.local_address.port = local_port;
  ri.local_address.proto = protocol;
  hash_redirect_info (&key, &ri);
  if (NULL != state_key)
    *state_key = key;
  state = GNUNET_CONTAINER_multihashmap_get (connections_map, &key);
  if (NULL == state)
    return NULL;
  /* Mark this connection as freshly used */
  if (NULL == state_key)
    GNUNET_CONTAINER_heap_update_cost (connections_heap, 
				       state->heap_node,
				       GNUNET_TIME_absolute_get ().abs_value);
  return state;
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
static struct LocalService *
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
  struct LocalService *service = value;

  GNUNET_free_non_null (service->name);
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
 * @param service service information record to store (service->name will be set).
 */
static void
store_service (struct GNUNET_CONTAINER_MultiHashMap *service_map,
	       const char *name,
	       uint16_t dpt,
	       struct LocalService *service)
{
  char key[sizeof (GNUNET_HashCode) + sizeof (uint16_t)];
  GNUNET_HashCode desc;

  GNUNET_CRYPTO_hash (name, strlen (name) + 1, &desc);
  service->name = GNUNET_strdup (name);
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
 * @param cls the 'struct TunnelState'.
 * @param size number of bytes available in buf
 * @param buf where to copy the message
 * @return number of bytes copied to buf
 */
static size_t
send_to_peer_notify_callback (void *cls, size_t size, void *buf)
{
  struct TunnelState *s = cls;
  struct GNUNET_MESH_Tunnel *tunnel = s->tunnel;
  struct TunnelMessageQueue *tnq;

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
 * @param desc descriptor to add before payload (optional)
 * @param mtype message type to use
 */
static void
send_packet_to_mesh_tunnel (struct GNUNET_MESH_Tunnel *mesh_tunnel,
			    const void *payload,
			    size_t payload_length,
			    const GNUNET_HashCode *desc,
			    uint16_t mtype)
{
  struct TunnelState *s;
  struct TunnelMessageQueue *tnq;
  struct GNUNET_MessageHeader *msg;
  size_t len;
  GNUNET_HashCode *dp;

  len = sizeof (struct GNUNET_MessageHeader) + sizeof (GNUNET_HashCode) + payload_length;
  if (len >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }
  tnq = GNUNET_malloc (sizeof (struct TunnelMessageQueue) + len);
  tnq->payload = &tnq[1];
  tnq->len = len;
  msg = (struct GNUNET_MessageHeader *) &tnq[1];
  msg->size = htons ((uint16_t) len);
  msg->type = htons (mtype);
  if (NULL != desc)
  {
    dp = (GNUNET_HashCode *) &msg[1];
    *dp = *desc;  
    memcpy (&dp[1], payload, payload_length);
  }
  else
  {
    memcpy (&msg[1], payload, payload_length);
  }
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
 * @brief Handles an UDP packet received from the helper.
 *
 * @param udp A pointer to the Packet
 * @param pktlen number of bytes in 'udp'
 * @param af address family (AFINET or AF_INET6)
 * @param destination_ip destination IP-address of the IP packet (should 
 *                       be our local address)
 * @param source_ip original source IP-address of the IP packet (should
 *                       be the original destination address)
 */
static void
udp_from_helper (const struct udp_packet *udp, 
		 size_t pktlen,
		 int af,
		 const void *destination_ip, 
		 const void *source_ip)
{
  struct TunnelState *state;

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
			      source_ip,
			      ntohs (udp->spt),
			      destination_ip,
			      ntohs (udp->dpt),
			      NULL);
  if (NULL == state)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		_("Packet dropped, have no matching connection information\n"));
    return;
  }
  send_packet_to_mesh_tunnel (state->tunnel,
			      &udp[1], pktlen - sizeof (struct udp_packet),
			      NULL,
			      state->serv != NULL
			      ? GNUNET_MESSAGE_TYPE_VPN_SERVICE_UDP_BACK 
			      : GNUNET_MESSAGE_TYPE_VPN_REMOTE_UDP_BACK);
}


/**
 * @brief Handles a TCP packet received from the helper.
 *
 * @param tcp A pointer to the Packet
 * @param pktlen the length of the packet, including its header
 * @param af address family (AFINET or AF_INET6)
 * @param destination_ip destination IP-address of the IP packet (should 
 *                       be our local address)
 * @param source_ip original source IP-address of the IP packet (should
 *                       be the original destination address)
 */
static void
tcp_from_helper (const struct tcp_packet *tcp, 
		 size_t pktlen,
		 int af,
		 const void *destination_ip,
		 const void *source_ip)
{
  struct TunnelState *state;
  char buf[pktlen];
  struct tcp_packet *mtcp;

  if (pktlen < sizeof (struct tcp_packet))
  {
    /* blame kernel */
    GNUNET_break (0);
    return;
  }
  state = get_redirect_state (af, IPPROTO_TCP,
			      source_ip, 
			      ntohs (tcp->spt),
			      destination_ip,
			      ntohs (tcp->dpt),
			      NULL);
  if (NULL == state)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		_("Packet dropped, have no matching connection information\n"));
    
    return;
  }
  /* mug port numbers and crc to avoid information leakage;
     sender will need to lookup the correct values anyway */
  memcpy (buf, tcp, pktlen);  
  mtcp = (struct tcp_packet *) buf;
  mtcp->spt = 0;
  mtcp->dpt = 0;
  mtcp->crc = 0;
  send_packet_to_mesh_tunnel (state->tunnel,
			      mtcp, pktlen,
			      NULL,
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
	udp_from_helper ((const struct udp_packet *) &pkt6[1], size,
			 AF_INET6,
			 &pkt6->destination_address, 
			 &pkt6->source_address);
	break;
      case IPPROTO_TCP:
	tcp_from_helper ((const struct tcp_packet *) &pkt6[1], size,
			 AF_INET6,
			 &pkt6->destination_address, 
			 &pkt6->source_address);
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
			 AF_INET,
			 &pkt4->destination_address, 
			 &pkt4->source_address);
      case IPPROTO_TCP:
	tcp_from_helper ((const struct tcp_packet *) &pkt4[1], size,
			 AF_INET,
			 &pkt4->destination_address, 
			 &pkt4->source_address);
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


/**
 * We need to create a (unique) fresh local address (IP+port).
 * Fill one in.
 *
 * @param af desired address family
 * @param proto desired protocol (IPPROTO_UDP or IPPROTO_TCP)
 * @param local_address address to initialize
 */
static void
setup_fresh_address (int af,
		     int proto,
		     struct SocketAddress *local_address)
{
  switch (af)
  {
  case AF_INET:
    {
      const char *ipv4addr = exit_argv[4];
      const char *ipv4mask = exit_argv[5];
      uint32_t tmp;
      uint32_t tmp2;
      
      GNUNET_assert (1 == inet_pton (AF_INET, ipv4addr, &tmp));
      GNUNET_assert (1 == inet_pton (AF_INET, ipv4mask, &tmp2));
      // FIXME
      /* This should be a noop */
      tmp = tmp & tmp2;
      tmp |= ntohl (*((uint32_t *) /*tunnel*/ 42)) & (~tmp2);
      
      // pkt4->source_address.s_addr = tmp;
    }
    break;
  case AF_INET6:
    {
      const char *ipv6addr = exit_argv[2];
      /* Generate a new src-address
       * This takes as much from the address of the tunnel as fits into
       * the host-mask*/
      unsigned long long ipv6prefix_r = (ipv6prefix + 7) / 8;
      inet_pton (AF_INET6, ipv6addr, &local_address->address.ipv6);
      if (ipv6prefix_r < (16 - sizeof (void *)))
	ipv6prefix_r = 16 - sizeof (void *);
      
      unsigned int offset = ipv6prefix_r - (16 - sizeof (void *));
      // memcpy ((((char *) &pkt6->source_address)) + ipv6prefix_r, ((char *) &tunnel) + offset, 16 - ipv6prefix_r);
      offset++;
    }
    break;
  default:
    GNUNET_assert (0);
  }  
}


/**
 * We are starting a fresh connection (TCP or UDP) and need
 * to pick a source port and IP address (within the correct
 * range and address family) to associate replies with the
 * connection / correct mesh tunnel.  This function generates
 * a "fresh" source IP and source port number for a connection
 * After picking a good source address, this function sets up
 * the state in the 'connections_map' and 'connections_heap'
 * to allow finding the state when needed later.  The function
 * also makes sure that we remain within memory limits by
 * cleaning up 'old' states.
 *
 * @param state skeleton state to setup a record for; should
 *              'state->ri.remote_address' filled in so that
 *              this code can determine which AF/protocol is
 *              going to be used (the 'tunnel' should also
 *              already be set); after calling this function,
 *              heap_node and the local_address will be
 *              also initialized (heap_node != NULL can be
 *              used to test if a state has been fully setup).
 */
static void
setup_state_record (struct TunnelState *state)
{
  GNUNET_HashCode key;
  struct TunnelState *s;

  /* generate fresh, unique address */
  do
  {
    setup_fresh_address (state->serv->address.af,
			 state->serv->address.proto,
			 &state->ri.local_address);
  } while (NULL != get_redirect_state (state->ri.remote_address.af,
				       IPPROTO_UDP,
				       &state->ri.remote_address.address,
				       state->ri.remote_address.port,
				       &state->ri.local_address.address,
				       state->ri.local_address.port,
				       &key));
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CONTAINER_multihashmap_put (connections_map, 
						    &key, state,
						    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  state->heap_node = GNUNET_CONTAINER_heap_insert (connections_heap,
						   state,
						   GNUNET_TIME_absolute_get ().abs_value);   
  while (GNUNET_CONTAINER_heap_get_size (connections_heap) > max_connections)
  {
    s = GNUNET_CONTAINER_heap_remove_root (connections_heap);
    GNUNET_assert (state != s);
    s->heap_node = NULL;
    GNUNET_MESH_tunnel_destroy (s->tunnel);
    GNUNET_assert (GNUNET_OK ==
		   GNUNET_CONTAINER_multihashmap_remove (connections_map,
							 &s->state_key, 
							 s));
    GNUNET_free (s);
  }
}


/**
 * Prepare an IPv4 packet for transmission via the TUN interface.
 * Initializes the IP header and calculates checksums (IP+UDP/TCP).
 * For UDP, the UDP header will be fully created, whereas for TCP
 * only the ports and checksum will be filled in.  So for TCP,
 * a skeleton TCP header must be part of the provided payload.
 *
 * @param payload payload of the packet (starting with UDP payload or
 *                TCP header, depending on protocol)
 * @param payload_length number of bytes in 'payload'
 * @param protocol IPPROTO_UDP or IPPROTO_TCP
 * @param src_address source address to use (IP and port)
 * @param dst_address destination address to use (IP and port)
 * @param pkt6 where to write the assembled packet; must
 *        contain enough space for the IP header, UDP/TCP header
 *        AND the payload
 */
static void
prepare_ipv4_packet (const void *payload, size_t payload_length,
		     int protocol,
		     const struct SocketAddress *src_address,
		     const struct SocketAddress *dst_address,
		     struct ip4_header *pkt4)
{
  size_t len;

  len = payload_length;
  switch (protocol)
  {
  case IPPROTO_UDP:
    len += sizeof (struct udp_packet);
    break;
  case IPPROTO_TCP:
    /* tcp_header (with port/crc not set) must be part of payload! */
    if (len < sizeof (struct tcp_packet))
    {
      GNUNET_break (0);
      return;
    }
    break;
  default:
    GNUNET_break (0);
    return;
  }
  if (len + sizeof (struct ip4_header) > UINT16_MAX)
  {
    GNUNET_break (0);
    return;
  }

  pkt4->version = 4;
  pkt4->header_length = sizeof (struct ip4_header) / 4;
  pkt4->diff_serv = 0;
  pkt4->total_length = htons ((uint16_t) (sizeof (struct ip4_header) + len));
  pkt4->identification = (uint16_t) GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 
							      65536);
  pkt4->flags = 0;
  pkt4->fragmentation_offset = 0;
  pkt4->ttl = 255;
  pkt4->protocol = protocol;
  pkt4->checksum = 0;
  pkt4->destination_address = dst_address->address.ipv4;
  pkt4->source_address = src_address->address.ipv4;
  pkt4->checksum = GNUNET_CRYPTO_crc16_n (pkt4, sizeof (struct ip4_header));

  switch (protocol)
  {
  case IPPROTO_UDP:
    {
      struct udp_packet *pkt4_udp = (struct udp_packet *) &pkt4[1];

      pkt4_udp->spt = htons (src_address->port);
      pkt4_udp->dpt = htons (dst_address->port);
      pkt4_udp->crc = 0;  /* Optional for IPv4 */
      pkt4_udp->len = htons ((uint16_t) payload_length);
      memcpy (&pkt4_udp[1], payload, payload_length);
    }
    break;
  case IPPROTO_TCP:
    {
      struct tcp_packet *pkt4_tcp = (struct tcp_packet *) &pkt4[1];
      
      memcpy (pkt4_tcp, payload, payload_length);
      pkt4_tcp->spt = htons (src_address->port);
      pkt4_tcp->dpt = htons (dst_address->port);
      pkt4_tcp->crc = 0;
      uint32_t sum = 0;
      sum = GNUNET_CRYPTO_crc16_step (sum, 
				      &pkt4->source_address,
				      sizeof (struct in_addr) * 2);
      uint32_t tmp = htonl ((protocol << 16) | (0xffff & len));
      sum = GNUNET_CRYPTO_crc16_step (sum, & tmp, sizeof (uint32_t));
      sum = GNUNET_CRYPTO_crc16_step (sum, & pkt4_tcp, len);
      pkt4_tcp->crc = GNUNET_CRYPTO_crc16_finish (sum);
    }
    break;
  default:
    GNUNET_assert (0);
  }
}


/**
 * Prepare an IPv6 packet for transmission via the TUN interface.
 * Initializes the IP header and calculates checksums (IP+UDP/TCP).
 * For UDP, the UDP header will be fully created, whereas for TCP
 * only the ports and checksum will be filled in.  So for TCP,
 * a skeleton TCP header must be part of the provided payload.
 *
 * @param payload payload of the packet (starting with UDP payload or
 *                TCP header, depending on protocol)
 * @param payload_length number of bytes in 'payload'
 * @param protocol IPPROTO_UDP or IPPROTO_TCP
 * @param src_address source address to use (IP and port)
 * @param dst_address destination address to use (IP and port)
 * @param pkt6 where to write the assembled packet; must
 *        contain enough space for the IP header, UDP/TCP header
 *        AND the payload
 */
static void
prepare_ipv6_packet (const void *payload, size_t payload_length,
		     int protocol,
		     const struct SocketAddress *src_address,
		     const struct SocketAddress *dst_address,
		     struct ip6_header *pkt6)
{
  size_t len;

  len = payload_length;
  switch (protocol)
  {
  case IPPROTO_UDP:
    len += sizeof (struct udp_packet);
    break;
  case IPPROTO_TCP:
    /* tcp_header (with port/crc not set) must be part of payload! */
    if (len < sizeof (struct tcp_packet))
    {
      GNUNET_break (0);
      return;
    }
    break;
  default:
    GNUNET_break (0);
    return;
  }
  if (len > UINT16_MAX)
  {
    GNUNET_break (0);
    return;
  }

  pkt6->version = 6;
  pkt6->next_header = protocol;
  pkt6->payload_length = htons ((uint16_t) (len + sizeof (struct ip6_header)));
  pkt6->hop_limit = 255;
  pkt6->destination_address = dst_address->address.ipv6;
  pkt6->source_address = src_address->address.ipv6;

  switch (protocol)
  {
  case IPPROTO_UDP:
    {
      struct udp_packet *pkt6_udp = (struct udp_packet *) &pkt6[1];

      memcpy (&pkt6[1], payload, payload_length);
      pkt6_udp->crc = 0;
      pkt6_udp->spt = htons (src_address->port);
      pkt6_udp->dpt = htons (dst_address->port);
      pkt6_udp->len = htons ((uint16_t) payload_length);

      uint32_t sum = 0;
      sum = GNUNET_CRYPTO_crc16_step (sum,
				      &pkt6->source_address,
				      sizeof (struct in6_addr) * 2);
      uint32_t tmp = htons (len);
      sum = GNUNET_CRYPTO_crc16_step (sum, &tmp, sizeof (uint32_t));
      tmp = htonl (pkt6->next_header);
      sum = GNUNET_CRYPTO_crc16_step (sum, &tmp, sizeof (uint32_t));
      sum = GNUNET_CRYPTO_crc16_step (sum, pkt6_udp, len);
      pkt6_udp->crc = GNUNET_CRYPTO_crc16_finish (sum);
    }
    break;
  case IPPROTO_TCP:
    {
      struct tcp_packet *pkt6_tcp = (struct tcp_packet *) pkt6;
      
      memcpy (pkt6_tcp, payload, payload_length);
      pkt6_tcp->crc = 0;
      pkt6_tcp->spt = htons (src_address->port);
      pkt6_tcp->dpt = htons (dst_address->port);

      uint32_t sum = 0;
      sum = GNUNET_CRYPTO_crc16_step (sum, &pkt6->source_address, 
				      sizeof (struct in6_addr) * 2);
      uint32_t tmp = htonl (len);
      sum = GNUNET_CRYPTO_crc16_step (sum, &tmp, sizeof (uint32_t));
      tmp = htonl (pkt6->next_header);
      sum = GNUNET_CRYPTO_crc16_step (sum, &tmp, sizeof (uint32_t));      
      sum = GNUNET_CRYPTO_crc16_step (sum,  pkt6_tcp, len);
      pkt6_tcp->crc = GNUNET_CRYPTO_crc16_finish (sum);
    }
    break;
  default:
    GNUNET_assert (0);
    break;
  }
}


/**
 * Send a TCP packet via the TUN interface.
 *
 * @param destination_address IP and port to use for the TCP packet's destination
 * @param source_address IP and port to use for the TCP packet's source
 * @param payload payload of the IP header (includes TCP header)
 * @param payload_length number of bytes in 'payload'
 */
static void
send_tcp_packet_via_tun (const struct SocketAddress *destination_address,
			 const struct SocketAddress *source_address,
			 const void *payload, size_t payload_length)
{
  size_t len;

  len = sizeof (struct GNUNET_MessageHeader) + sizeof (struct tun_header);
  switch (source_address->af)
  {
  case AF_INET:
    len += sizeof (struct ip4_header);
    break;
  case AF_INET6:
    len += sizeof (struct ip6_header);
    break;
  default:
    GNUNET_break (0);
    return;
  }
  len += payload_length;
  if (len >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }
  {
    char buf[len];
    struct GNUNET_MessageHeader *hdr;
    struct tun_header *tun;
    
    hdr= (struct GNUNET_MessageHeader *) buf;
    hdr->type = htons (42);
    hdr->size = htons (len);
    tun = (struct tun_header*) &hdr[1];
    tun->flags = htons (0);
    switch (source_address->af)
    {
    case AF_INET:
      {
	struct ip4_header * ipv4 = (struct ip4_header*) &tun[1];
	
	tun->proto = htons (ETH_P_IPV4);
	prepare_ipv4_packet (payload, payload_length, IPPROTO_TCP,
			     source_address,
			     destination_address,
			     ipv4);
      }
      break;
    case AF_INET6:
      {
	struct ip6_header * ipv6 = (struct ip6_header*) &tun[1];
	
	tun->proto = htons (ETH_P_IPV6);
	prepare_ipv6_packet (payload, payload_length, IPPROTO_TCP,
			     source_address,
			     destination_address,
			     ipv6);
      }
      break;	
    default:
      GNUNET_assert (0);
      break;
    }
    (void) GNUNET_HELPER_send (helper_handle,
			       (const struct GNUNET_MessageHeader*) buf,
			       GNUNET_YES,
			       NULL, NULL);
  }
}


/**
 * Process a request via mesh to send a request to a UDP service
 * offered by this system.
 *
 * The messages are one GNUNET_HashCode for the service followed by a struct tcp_packet
 * (FIXME: this is not great).
 *
 * @param cls closure, NULL
 * @param tunnel connection to the other end
 * @param tunnel_ctx pointer to our 'struct TunnelState *'
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
receive_tcp_service (void *unused GNUNET_UNUSED, struct GNUNET_MESH_Tunnel *tunnel,
                     void **tunnel_ctx GNUNET_UNUSED,
                     const struct GNUNET_PeerIdentity *sender GNUNET_UNUSED,
                     const struct GNUNET_MessageHeader *message,
                     const struct GNUNET_ATS_Information *atsi GNUNET_UNUSED)
{
  struct TunnelState *state = *tunnel_ctx;
  // FIXME: write proper request struct (we don't need the descriptor EACH time here!)
  const GNUNET_HashCode *desc = (const GNUNET_HashCode *) &message[1];
  const struct tcp_packet *pkt = (const struct tcp_packet *) &desc[1];
  uint16_t pkt_len = ntohs (message->size);


  /* check that we got at least a valid header */
  if (pkt_len < sizeof (struct GNUNET_MessageHeader) + sizeof (GNUNET_HashCode) + sizeof (struct tcp_packet))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  pkt_len -= (sizeof (struct GNUNET_MessageHeader) + sizeof (GNUNET_HashCode));

  if (NULL == state->serv) 
  {
    /* setup fresh connection */
    GNUNET_assert (NULL == state->heap_node);
    if (NULL == (state->serv = find_service (tcp_services, desc, ntohs (pkt->dpt))))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
		  _("No service found for %s on port %d!\n"),
		  "TCP",
		  ntohs (pkt->dpt));
      GNUNET_MESH_tunnel_destroy (state->tunnel);
      return GNUNET_YES;
    }
    state->ri.remote_address = state->serv->address;    
    setup_state_record (state);
  }
  send_tcp_packet_via_tun (&state->ri.remote_address,
			   &state->ri.local_address,
			   pkt, pkt_len);
  return GNUNET_YES;
}


/**
 * Process a request to forward TCP data to the Internet via this peer.
 *
 * @param cls closure, NULL
 * @param tunnel connection to the other end
 * @param tunnel_ctx pointer to our 'struct TunnelState *'
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
receive_tcp_remote (void *cls GNUNET_UNUSED, struct GNUNET_MESH_Tunnel *tunnel,
                    void **tunnel_ctx GNUNET_UNUSED,
                    const struct GNUNET_PeerIdentity *sender GNUNET_UNUSED,
                    const struct GNUNET_MessageHeader *message,
                    const struct GNUNET_ATS_Information *atsi GNUNET_UNUSED)
{
  struct TunnelState *state = *tunnel_ctx;
  // FIXME: write proper request struct (!)
  const GNUNET_HashCode *desc = (const GNUNET_HashCode *) &message[1];
  const struct tcp_packet *pkt = (const struct tcp_packet *) &desc[1];
  const struct SocketAddress *s = (const struct SocketAddress *) desc;
  uint16_t pkt_len = ntohs (message->size);

  if (pkt_len < sizeof (struct GNUNET_MessageHeader) + sizeof (GNUNET_HashCode) + sizeof (struct tcp_packet))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  pkt_len -= (sizeof (struct GNUNET_MessageHeader) + sizeof (GNUNET_HashCode));

  if (NULL == state->heap_node)
  {
    /* first packet, setup record */
    state->ri.remote_address = *s;
    setup_state_record (state);
  }

  send_tcp_packet_via_tun (&state->ri.remote_address,
			   &state->ri.local_address,
			   pkt, pkt_len);
  return GNUNET_YES;
}


/**
 * Send a UDP packet via the TUN interface.
 *
 * @param destination_address IP and port to use for the UDP packet's destination
 * @param source_address IP and port to use for the UDP packet's source
 * @param payload payload of the UDP packet (does NOT include UDP header)
 * @param payload_length number of bytes of data in payload
 */
static void
send_udp_packet_via_tun (const struct SocketAddress *destination_address,
			 const struct SocketAddress *source_address,
			 const void *payload, size_t payload_length)
{
  size_t len;

  len = sizeof (struct GNUNET_MessageHeader) + sizeof (struct tun_header);
  switch (source_address->af)
  {
  case AF_INET:
    len += sizeof (struct ip4_header);
    break;
  case AF_INET6:
    len += sizeof (struct ip6_header);
    break;
  default:
    GNUNET_break (0);
    return;
  }
  len += sizeof (struct udp_packet);
  len += payload_length;
  if (len >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }
  {
    char buf[len];
    struct GNUNET_MessageHeader *hdr;
    struct tun_header *tun;
    
    hdr= (struct GNUNET_MessageHeader *) buf;
    hdr->type = htons (42);
    hdr->size = htons (len);
    tun = (struct tun_header*) &hdr[1];
    tun->flags = htons (0);
    switch (source_address->af)
    {
    case AF_INET:
      {
	struct ip4_header * ipv4 = (struct ip4_header*) &tun[1];
	
	tun->proto = htons (ETH_P_IPV4);
	prepare_ipv4_packet (payload, payload_length, IPPROTO_UDP,
			     source_address,
			     destination_address,
			     ipv4);
      }
      break;
    case AF_INET6:
      {
	struct ip6_header * ipv6 = (struct ip6_header*) &tun[1];
	
	tun->proto = htons (ETH_P_IPV6);
	prepare_ipv6_packet (payload, payload_length, IPPROTO_UDP,
			     source_address,
			     destination_address,
			     ipv6);
      }
      break;	
    default:
      GNUNET_assert (0);
      break;
    }
    (void) GNUNET_HELPER_send (helper_handle,
			       (const struct GNUNET_MessageHeader*) buf,
			       GNUNET_YES,
			       NULL, NULL);
  }
}


/**
 * Process a request to forward UDP data to the Internet via this peer.
 *
 * @param cls closure, NULL
 * @param tunnel connection to the other end
 * @param tunnel_ctx pointer to our 'struct TunnelState *'
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
receive_udp_remote (void *cls GNUNET_UNUSED, struct GNUNET_MESH_Tunnel *tunnel,
                    void **tunnel_ctx GNUNET_UNUSED,
                    const struct GNUNET_PeerIdentity *sender GNUNET_UNUSED,
                    const struct GNUNET_MessageHeader *message,
                    const struct GNUNET_ATS_Information *atsi GNUNET_UNUSED)
{
  struct TunnelState *state = *tunnel_ctx;
  // FIXME: write proper request struct (!)
  const GNUNET_HashCode *desc = (const GNUNET_HashCode *) &message[1];
  const struct udp_packet *pkt = (const struct udp_packet *) &desc[1];
  const struct SocketAddress *s = (const struct SocketAddress *) desc;
  uint16_t pkt_len = ntohs (message->size);

  if (pkt_len < sizeof (struct GNUNET_MessageHeader) + sizeof (GNUNET_HashCode) + sizeof (struct udp_packet))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  pkt_len -= (sizeof (struct GNUNET_MessageHeader) + sizeof (GNUNET_HashCode));

  if (NULL == state->heap_node)
  {
    /* first packet, setup record */
    state->ri.remote_address = *s;
    setup_state_record (state);
  }

  send_udp_packet_via_tun (&state->ri.remote_address,
			   &state->ri.local_address,
			   &pkt[1], pkt_len - sizeof (struct udp_packet));
  return GNUNET_YES;
}


/**
 * Process a request via mesh to send a request to a UDP service
 * offered by this system.
 *
 * @param cls closure, NULL
 * @param tunnel connection to the other end
 * @param tunnel_ctx pointer to our 'struct TunnelState *'
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
receive_udp_service (void *cls GNUNET_UNUSED, struct GNUNET_MESH_Tunnel *tunnel,
                     void **tunnel_ctx,
                     const struct GNUNET_PeerIdentity *sender GNUNET_UNUSED,
                     const struct GNUNET_MessageHeader *message,
                     const struct GNUNET_ATS_Information *atsi GNUNET_UNUSED)
{
  struct TunnelState *state = *tunnel_ctx;
  // FIXME: write proper request struct (we don't need UDP except dpt either!)
  const GNUNET_HashCode *desc = (const GNUNET_HashCode *) &message[1];
  const struct udp_packet *pkt = (const struct udp_packet *) &desc[1];
  uint16_t pkt_len = ntohs (message->size);


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

  if (NULL == state->serv) 
  {
    /* setup fresh connection */
    GNUNET_assert (NULL == state->heap_node);
    if (NULL == (state->serv = find_service (udp_services, desc, ntohs (pkt->dpt))))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
		  _("No service found for %s on port %d!\n"),
		  "UDP",
		  ntohs (pkt->dpt));
      GNUNET_MESH_tunnel_destroy (state->tunnel);
      return GNUNET_YES;
    }
    state->ri.remote_address = state->serv->address;    
    setup_state_record (state);
  }
  send_udp_packet_via_tun (&state->ri.remote_address,
			   &state->ri.local_address,
			   &pkt[1], pkt_len - sizeof (struct udp_packet));
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
  struct TunnelState *s = GNUNET_malloc (sizeof (struct TunnelState));
  
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
  struct TunnelState *s = tunnel_ctx;
  struct TunnelMessageQueue *tnq;

  while (NULL != (tnq = s->head))
  {
    GNUNET_CONTAINER_DLL_remove (s->head,
				 s->tail,
				 tnq);
    GNUNET_free (tnq);
  }
  if (s->heap_node != NULL)
  {
    GNUNET_assert (GNUNET_YES ==
		   GNUNET_CONTAINER_multihashmap_remove (connections_map,
							 &s->state_key,
							 s));
    GNUNET_CONTAINER_heap_remove_node (s->heap_node);
    s->heap_node = NULL;
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
  struct LocalService *serv;

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

    serv = GNUNET_malloc (sizeof (struct LocalService));
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
                              options, &run, NULL)) ? 0 : 1;
}


/* end of gnunet-daemon-exit.c */
