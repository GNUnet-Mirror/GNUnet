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
 * - create secondary mesh tunnels if needed / check overall tunnel creation/management code!
 * => test!
 * - better message queue management (bounded state, drop oldest/RED?)
 * - improve support for deciding which tunnels to keep and which ones to destroy
 * - add back ICMP support (especially needed for IPv6)
 * - consider moving IP-header building / checksumming code into shared library
 *   with dns/exit/vpn (libgnunettun_tcpip?)
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_common.h"
#include "gnunet_protocols.h"
#include "gnunet_applications.h"
#include "gnunet_mesh_service.h"
#include "gnunet_constants.h"
#include "tcpip_tun.h"
#include "vpn.h"
#include "exit.h"

/**
 * Information we track for each IP address to determine which tunnel
 * to send the traffic over to the destination.
 */
struct DestinationEntry
{
  /**
   * Information about the tunnel to use, NULL if no tunnel
   * is available right now.
   */
  struct GNUNET_MESH_Tunnel *tunnel;

  /**
   * Entry for this entry in the destination_heap.
   */
  struct GNUNET_CONTAINER_HeapNode *heap_node;

  /**
   * GNUNET_NO if this is a tunnel to an Internet-exit,
   * GNUNET_YES if this tunnel is to a service.
   */
  int is_service;

  /**
   * Details about the connection (depending on is_service).
   */
  union
  {

    struct
    {
      /**
       * The description of the service (only used for service tunnels).
       */
      GNUNET_HashCode service_descriptor;

      /**
       * Peer offering the service.
       */
      struct GNUNET_PeerIdentity target;

    } service_destination;

    struct 
    {
  
      /**
       * Address family used (AF_INET or AF_INET6).
       */
      int af;
      
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

    } exit_destination;

  } details;
    
};


/**
 * A messages we have in queue for a particular tunnel.
 */
struct TunnelMessageQueueEntry
{
  /**
   * This is a doubly-linked list.
   */
  struct TunnelMessageQueueEntry *next;

  /**
   * This is a doubly-linked list.
   */
  struct TunnelMessageQueueEntry *prev;
  
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
struct TunnelState
{
  /**
   * Active transmission handle, NULL for none.
   */
  struct GNUNET_MESH_TransmitHandle *th;

  /**
   * Entry for this entry in the tunnel_heap, NULL as long as this
   * tunnel state is not fully bound.
   */
  struct GNUNET_CONTAINER_HeapNode *heap_node;

  /**
   * Head of list of messages scheduled for transmission.
   */
  struct TunnelMessageQueueEntry *head;

  /**
   * Tail of list of messages scheduled for transmission.
   */
  struct TunnelMessageQueueEntry *tail;

  /**
   * Client that needs to be notified about the tunnel being
   * up as soon as a peer is connected; NULL for none.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * ID of the client request that caused us to setup this entry.
   */ 
  uint64_t request_id;

  /**
   * Destination to which this tunnel leads.  Note that
   * this struct is NOT in the destination_map (but a
   * local copy) and that the 'heap_node' should always
   * be NULL.
   */
  struct DestinationEntry destination;

  /**
   * GNUNET_NO if this is a tunnel to an Internet-exit,
   * GNUNET_YES if this tunnel is to a service.
   */
  int is_service;

  /**
   * Addess family used for this tunnel on the local TUN interface.
   */
  int af;

  /**
   * IP address of the source on our end, initially uninitialized.
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
   * Destination IP address used by the source on our end (this is the IP
   * that we pick freely within the VPN's tunnel IP range).
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

  } destination_ip;

  /**
   * Source port used by the sender on our end; 0 for uninitialized.
   */
  uint16_t source_port;

  /**
   * Destination port used by the sender on our end; 0 for uninitialized.
   */
  uint16_t destination_port;

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
 * Map from IP address to destination information (possibly with a
 * MESH tunnel handle for fast setup).
 */
static struct GNUNET_CONTAINER_MultiHashMap *destination_map;

/**
 * Min-Heap sorted by activity time to expire old mappings.
 */
static struct GNUNET_CONTAINER_Heap *destination_heap;

/**
 * Map from source and destination address (IP+port) to connection
 * information (mostly with the respective MESH tunnel handle).
 */
static struct GNUNET_CONTAINER_MultiHashMap *tunnel_map;

/**
 * Min-Heap sorted by activity time to expire old mappings.
 */
static struct GNUNET_CONTAINER_Heap *tunnel_heap;

/**
 * The handle to the VPN helper process "gnunet-helper-vpn".
 */
static struct GNUNET_HELPER_Handle *helper_handle;

/**
 * Arguments to the vpn helper.
 */
static char *vpn_argv[7];

/**
 * Length of the prefix of the VPN's IPv6 network.
 */
static unsigned long long ipv6prefix;

/**
 * Notification context for sending replies to clients.
 */
static struct GNUNET_SERVER_NotificationContext *nc;

/**
 * If there are more than this number of address-mappings, old ones
 * will be removed
 */
static unsigned long long max_destination_mappings;

/**
 * If there are more than this number of open tunnels, old ones
 * will be removed
 */
static unsigned long long max_tunnel_mappings;


/**
 * Compute the key under which we would store an entry in the
 * destination_map for the given IP address.
 *
 * @param af address family (AF_INET or AF_INET6)
 * @param address IP address, struct in_addr or struct in6_addr
 * @param key where to store the key
 */
static void
get_destination_key_from_ip (int af,
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
 * Compute the key under which we would store an entry in the
 * tunnel_map for the given socket address pair.
 *
 * @param af address family (AF_INET or AF_INET6)
 * @param protocol IPPROTO_TCP or IPPROTO_UDP
 * @param source_ip sender's source IP, struct in_addr or struct in6_addr
 * @param source_port sender's source port
 * @param destination_ip sender's destination IP, struct in_addr or struct in6_addr
 * @param destination_port sender's destination port
 * @param key where to store the key
 */
static void
get_tunnel_key_from_ips (int af,
			 uint8_t protocol,
			 const void *source_ip,
			 uint16_t source_port,
			 const void *destination_ip,
			 uint16_t destination_port,
			 GNUNET_HashCode *key)
{
  char *off;

  memset (key, 0, sizeof (GNUNET_HashCode));
  /* the GNUnet hashmap only uses the first sizeof(unsigned int) of the hash,
     so we put the ports in there (and hope for few collisions) */
  off = (char*) key;
  memcpy (off, &source_port, sizeof (uint16_t));
  off += sizeof (uint16_t);
  memcpy (off, &destination_port, sizeof (uint16_t));
  off += sizeof (uint16_t);
  switch (af)
  {
  case AF_INET:
    memcpy (off, source_ip, sizeof (struct in_addr));
    off += sizeof (struct in_addr);
    memcpy (off, destination_ip, sizeof (struct in_addr));
    off += sizeof (struct in_addr);
    break;
  case AF_INET6:
    memcpy (off, source_ip, sizeof (struct in6_addr));
    off += sizeof (struct in6_addr);
    memcpy (off, destination_ip, sizeof (struct in6_addr));
    off += sizeof (struct in6_addr);
    break;
  default:
    GNUNET_assert (0);
    break;
  }
  memcpy (off, &protocol, sizeof (uint8_t));
  off += sizeof (uint8_t);  
}


/**
 * Notify the client about the result of its request.
 *
 * @param client client to notify
 * @param request_id original request ID to include in response
 * @param result_af resulting address family
 * @param addr resulting IP address
 */
static void
send_client_reply (struct GNUNET_SERVER_Client *client,
		   uint64_t request_id,
		   int result_af,
		   const void *addr)
{
  char buf[sizeof (struct RedirectToIpResponseMessage) + sizeof (struct in6_addr)];
  struct RedirectToIpResponseMessage *res;
  size_t rlen;

  switch (result_af)
  {
  case AF_INET:
    rlen = sizeof (struct in_addr);    
    break;
  case AF_INET6:
    rlen = sizeof (struct in6_addr);
    break;
  case AF_UNSPEC:
    rlen = 0;
    break;
  default:
    GNUNET_assert (0);
    return;
  }
  res = (struct RedirectToIpResponseMessage *) buf;
  res->header.size = htons (sizeof (struct RedirectToIpResponseMessage) + rlen);
  res->header.type = htons (GNUNET_MESSAGE_TYPE_VPN_CLIENT_USE_IP);
  res->result_af = htonl (result_af);
  res->request_id = request_id;
  memcpy (&res[1], addr, rlen);
  GNUNET_SERVER_notification_context_add (nc, client);
  GNUNET_SERVER_notification_context_unicast (nc,
					      client,
					      &res->header,
					      GNUNET_NO);
}


/**
 * Method called whenever a peer has disconnected from the tunnel.
 *
 * @param cls closure
 * @param peer peer identity the tunnel stopped working with
 */
static void
tunnel_peer_disconnect_handler (void *cls,
				const struct
				GNUNET_PeerIdentity * peer)
{
  /* FIXME: should we do anything here? 
   - stop transmitting to the tunnel (start queueing?)
   - possibly destroy the tunnel entirely (unless service tunnel?) 
  */
}


/**
 * Method called whenever a peer has connected to the tunnel.  Notifies
 * the waiting client that the tunnel is now up.
 *
 * @param cls closure
 * @param peer peer identity the tunnel was created to, NULL on timeout
 * @param atsi performance data for the connection
 */
static void
tunnel_peer_connect_handler (void *cls,
			     const struct GNUNET_PeerIdentity
			     * peer,
			     const struct
			     GNUNET_ATS_Information * atsi)
{
  struct TunnelState *ts = cls;

  if (NULL == ts->client)
    return; /* nothing to do */
  send_client_reply (ts->client,
		     ts->request_id,
		     ts->af,
		     &ts->destination_ip);
  GNUNET_SERVER_client_drop (ts->client);
  ts->client = NULL;
}


/**
 * Send a message from the message queue via mesh.
 *
 * @param cls the 'struct TunnelState' with the message queue
 * @param size number of bytes available in buf
 * @param buf where to copy the message
 * @return number of bytes copied to buf
 */
static size_t
send_to_peer_notify_callback (void *cls, size_t size, void *buf)
{
  struct TunnelState *ts = cls;
  struct TunnelMessageQueueEntry *tnq;
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
    ts->th = GNUNET_MESH_notify_transmit_ready (ts->destination.tunnel, 
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
static void
send_to_tunnel (struct TunnelMessageQueueEntry *tnq,
		struct TunnelState *ts)
{
  GNUNET_CONTAINER_DLL_insert_tail (ts->head,
				    ts->tail,
				    tnq);
  if (NULL == ts->th)
    ts->th = GNUNET_MESH_notify_transmit_ready (ts->destination.tunnel, 
						GNUNET_NO /* cork */,
						42 /* priority */,
						GNUNET_TIME_UNIT_FOREVER_REL,
						NULL, 
						tnq->len,
						&send_to_peer_notify_callback,
						ts);
}


/**
 * Route a packet via mesh to the given destination.  
 *
 * @param destination description of the destination
 * @param af address family on this end (AF_INET or AF_INET6)
 * @param protocol IPPROTO_TCP or IPPROTO_UDP
 * @param source_ip source IP used by the sender (struct in_addr or struct in6_addr)
 * @param destination_ip destination IP used by the sender (struct in_addr or struct in6_addr)
 * @param payload payload of the packet after the IP header
 * @param payload_length number of bytes in payload
 */
static void
route_packet (struct DestinationEntry *destination,
	      int af,
	      uint8_t protocol,
	      const void *source_ip,
	      const void *destination_ip,
	      const void *payload,
	      size_t payload_length)
{
  GNUNET_HashCode key;
  struct TunnelState *ts;
  struct TunnelMessageQueueEntry *tnq;
  size_t alen;
  size_t mlen;
  GNUNET_MESH_ApplicationType app_type;
  int is_new;
  const struct udp_packet *udp;
  const struct tcp_packet *tcp;
    
  switch (protocol)
  {
  case IPPROTO_UDP:
    {
      if (payload_length < sizeof (struct udp_packet))
      {
	/* blame kernel? */
	GNUNET_break (0);
	return;
      }
      udp = payload;
      get_tunnel_key_from_ips (af,
			       IPPROTO_UDP,
			       source_ip,
			       ntohs (udp->spt),
			       destination_ip,
			       ntohs (udp->dpt),
			       &key);
    }
    break;
  case IPPROTO_TCP:
    {
      if (payload_length < sizeof (struct tcp_packet))
      {
	/* blame kernel? */
	GNUNET_break (0);
	return;
      }
      tcp = payload;
      get_tunnel_key_from_ips (af,
			       IPPROTO_TCP,
			       source_ip,
			       ntohs (tcp->spt),
			       destination_ip,
			       ntohs (tcp->dpt),
			       &key);
    }
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		_("Protocol %u not supported, dropping\n"),
		(unsigned int) protocol);
    return;
  }

  if (! destination->is_service)
  {  
    switch (destination->details.exit_destination.af)
    {
    case AF_INET:
      alen = sizeof (struct in_addr);
      app_type = GNUNET_APPLICATION_TYPE_IPV4_GATEWAY; 
     break;
    case AF_INET6:
      alen = sizeof (struct in6_addr);
      app_type = GNUNET_APPLICATION_TYPE_IPV6_GATEWAY; 
      break;
    default:
      alen = 0;
      GNUNET_assert (0);
    }
  }
  else
  {
    /* make compiler happy */
    alen = 0;
    app_type = 0;
  }

  // FIXME: something is horrifically wrong here about
  // how we lookup 'ts', match it and how we decide about
  // creating new tunnels!
  /* find tunnel */
  is_new = GNUNET_NO;
  ts = GNUNET_CONTAINER_multihashmap_get (tunnel_map,
					  &key);
  if (NULL == ts)
  {
    /* create new tunnel */
    is_new = GNUNET_YES;
    ts = GNUNET_malloc (sizeof (struct TunnelState));
    ts->destination.tunnel = GNUNET_MESH_tunnel_create (mesh_handle,
							ts,
							&tunnel_peer_connect_handler,
							&tunnel_peer_disconnect_handler, 
							ts);
    if (destination->is_service)
      GNUNET_MESH_peer_request_connect_add (ts->destination.tunnel,
					    &destination->details.service_destination.target);
    else
      GNUNET_MESH_peer_request_connect_by_type (ts->destination.tunnel,
						app_type);
  }
  
  /* send via tunnel */
  switch (protocol)
  {
  case IPPROTO_UDP:
    if (destination->is_service)
    {
      struct GNUNET_EXIT_UdpServiceMessage *usm;

      mlen = sizeof (struct GNUNET_EXIT_UdpServiceMessage) + 
	payload_length - sizeof (struct udp_packet);
      if (mlen >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
      {
	GNUNET_break (0);
	return;
      }
      tnq = GNUNET_malloc (sizeof (struct TunnelMessageQueueEntry) + mlen);
      usm = (struct GNUNET_EXIT_UdpServiceMessage *) &tnq[1];
      usm->header.size = htons ((uint16_t) mlen);
      usm->header.type = htons (GNUNET_MESSAGE_TYPE_VPN_UDP_TO_SERVICE);
      /* if the source port is below 32000, we assume it has a special
	 meaning; if not, we pick a random port (this is a heuristic) */
      usm->source_port = (ntohs (udp->spt) < 32000) ? udp->spt : 0;
      usm->destination_port = udp->dpt;
      usm->service_descriptor = destination->details.service_destination.service_descriptor;
      memcpy (&usm[1],
	      &udp[1],
	      payload_length - sizeof (struct udp_packet));
    }
    else
    {
      struct GNUNET_EXIT_UdpInternetMessage *uim;
      struct in_addr *ip4dst;
      struct in6_addr *ip6dst;
      void *payload;

      mlen = sizeof (struct GNUNET_EXIT_UdpInternetMessage) + 
	alen + payload_length - sizeof (struct udp_packet);
      if (mlen >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
      {
	GNUNET_break (0);
	return;
      }
      tnq = GNUNET_malloc (sizeof (struct TunnelMessageQueueEntry) + 
			   mlen);
      uim = (struct GNUNET_EXIT_UdpInternetMessage *) &tnq[1];
      uim->header.size = htons ((uint16_t) mlen);
      uim->header.type = htons (GNUNET_MESSAGE_TYPE_VPN_UDP_TO_INTERNET); 
      uim->af = htonl (destination->details.exit_destination.af);
      uim->source_port = (ntohs (udp->spt) < 32000) ? udp->spt : 0;
      uim->destination_port = udp->dpt;
      switch (destination->details.exit_destination.af)
      {
      case AF_INET:
	ip4dst = (struct in_addr *) &uim[1];
	*ip4dst = destination->details.exit_destination.ip.v4;
	payload = &ip4dst[1];
	break;
      case AF_INET6:
	ip6dst = (struct in6_addr *) &uim[1];
	*ip6dst = destination->details.exit_destination.ip.v6;
	payload = &ip6dst[1];
	break;
      default:
	GNUNET_assert (0);
      }
      memcpy (payload,
	      &udp[1],
	      payload_length - sizeof (struct udp_packet));
    }
    break;
  case IPPROTO_TCP:
    if (is_new)
    {
      if (destination->is_service)
      {
	struct GNUNET_EXIT_TcpServiceStartMessage *tsm;

	mlen = sizeof (struct GNUNET_EXIT_TcpServiceStartMessage) + 
	  payload_length - sizeof (struct tcp_packet);
	if (mlen >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
	{
	  GNUNET_break (0);
	  return;
	}
 	tnq = GNUNET_malloc (sizeof (struct TunnelMessageQueueEntry) + mlen);
	tsm = (struct  GNUNET_EXIT_TcpServiceStartMessage *) &tnq[1];
	tsm->header.size = htons ((uint16_t) mlen);
	tsm->header.type = htons (GNUNET_MESSAGE_TYPE_VPN_TCP_TO_SERVICE_START);
	tsm->reserved = htonl (0);
	tsm->service_descriptor = destination->details.service_destination.service_descriptor;
	tsm->tcp_header = *tcp;
	memcpy (&tsm[1],
		&tcp[1],
		payload_length - sizeof (struct tcp_packet));
      }
      else
      {
	struct GNUNET_EXIT_TcpInternetStartMessage *tim;
	struct in_addr *ip4dst;
	struct in6_addr *ip6dst;
	void *payload;

	mlen = sizeof (struct GNUNET_EXIT_TcpInternetStartMessage) + 
	  alen + payload_length - sizeof (struct tcp_packet);
	if (mlen >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
	{
	  GNUNET_break (0);
	  return;
	}
 	tnq = GNUNET_malloc (sizeof (struct TunnelMessageQueueEntry) + mlen);
	tim = (struct  GNUNET_EXIT_TcpInternetStartMessage *) &tnq[1];
	tim->header.size = htons ((uint16_t) mlen);
	tim->header.type = htons (GNUNET_MESSAGE_TYPE_VPN_TCP_TO_INTERNET_START);
	tim->af = htonl (destination->details.exit_destination.af);	
	tim->tcp_header = *tcp;
	switch (destination->details.exit_destination.af)
	{
	case AF_INET:
	  ip4dst = (struct in_addr *) &tim[1];
	  *ip4dst = destination->details.exit_destination.ip.v4;
	  payload = &ip4dst[1];
	  break;
	case AF_INET6:
	  ip6dst = (struct in6_addr *) &tim[1];
	  *ip6dst = destination->details.exit_destination.ip.v6;
	  payload = &ip6dst[1];
	  break;
	default:
	  GNUNET_assert (0);
	}
	memcpy (payload,
		&tcp[1],
		payload_length - sizeof (struct tcp_packet));
      }
    }
    else
    {
      struct GNUNET_EXIT_TcpDataMessage *tdm;

      mlen = sizeof (struct GNUNET_EXIT_TcpDataMessage) + 
	alen + payload_length - sizeof (struct tcp_packet);
      if (mlen >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
      {
	GNUNET_break (0);
	return;
      }
      tnq = GNUNET_malloc (sizeof (struct TunnelMessageQueueEntry) + mlen);
      tdm = (struct  GNUNET_EXIT_TcpDataMessage *) &tnq[1];
      tdm->header.size = htons ((uint16_t) mlen);
      tdm->header.type = htons (GNUNET_MESSAGE_TYPE_VPN_TCP_DATA);
      tdm->reserved = htonl (0);
      tdm->tcp_header = *tcp;
      memcpy (&tdm[1],
	      &tcp[1],
	      payload_length - sizeof (struct tcp_packet));
     }
    break;
  default:
    /* not supported above, how can we get here !? */
    GNUNET_assert (0);
    break;
  }
  send_to_tunnel (tnq, ts);
}


/**
 * Receive packets from the helper-process (someone send to the local
 * virtual tunnel interface).  Find the destination mapping, and if it
 * exists, identify the correct MESH tunnel (or possibly create it)
 * and forward the packet.
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
  struct DestinationEntry *de;

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
      get_destination_key_from_ip (AF_INET6,
				   &pkt6->destination_address,
				   &key);
      de = GNUNET_CONTAINER_multihashmap_get (destination_map, &key);
      /* FIXME: do we need to guard against hash collision? */
      if (NULL == de)
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
      route_packet (de,
		    AF_INET6,
		    pkt6->next_header,
		    &pkt6->source_address,		    
		    &pkt6->destination_address,		    
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
      get_destination_key_from_ip (AF_INET,
				   &pkt4->destination_address,
				   &key);
      de = GNUNET_CONTAINER_multihashmap_get (destination_map, &key);
      /* FIXME: do we need to guard against hash collision? */
      if (NULL == de)
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
      route_packet (de,
		    AF_INET,
		    pkt4->protocol,
		    &pkt4->source_address,		    
		    &pkt4->destination_address,		    
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


/**
 * We got a UDP packet back from the MESH tunnel.  Pass it on to the
 * local virtual interface via the helper.
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
receive_udp_back (void *cls GNUNET_UNUSED, struct GNUNET_MESH_Tunnel *tunnel,
                  void **tunnel_ctx, const struct GNUNET_PeerIdentity *sender,
                  const struct GNUNET_MessageHeader *message,
                  const struct GNUNET_ATS_Information *atsi GNUNET_UNUSED)
{
  struct TunnelState *ts = *tunnel_ctx;
  const struct GNUNET_EXIT_UdpReplyMessage *reply;
  size_t mlen;

  mlen = ntohs (message->size);
  if (mlen < sizeof (struct GNUNET_EXIT_UdpReplyMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (NULL == ts->heap_node)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  reply = (const struct GNUNET_EXIT_UdpReplyMessage *) message;
  mlen -= sizeof (struct GNUNET_EXIT_UdpReplyMessage);
  switch (ts->af)
  {
  case AF_INET:
    {
      size_t size = sizeof (struct ip4_header) 
	+ sizeof (struct udp_packet) 
	+ sizeof (struct GNUNET_MessageHeader) +
	sizeof (struct tun_header) +
	mlen;
      {
	char buf[size];
	struct GNUNET_MessageHeader *msg = (struct GNUNET_MessageHeader *) buf;
	struct tun_header *tun = (struct tun_header*) &msg[1];
	struct ip4_header *ipv4 = (struct ip4_header *) &tun[1];
	struct udp_packet *udp = (struct udp_packet *) &ipv4[1];
	msg->type = htons (GNUNET_MESSAGE_TYPE_VPN_HELPER);
	msg->size = htons (size);
	tun->flags = htons (0);
	tun->proto = htons (ETH_P_IPV4);
	ipv4->version = 4;
	ipv4->header_length = sizeof (struct ip4_header) / 4;
	ipv4->diff_serv = 0;
	ipv4->total_length = htons (sizeof (struct ip4_header) +
				    sizeof (struct udp_packet) +
				    mlen);
	ipv4->identification = (uint16_t) GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 
								    UINT16_MAX + 1);
	ipv4->flags = 0;
	ipv4->fragmentation_offset = 0;
	ipv4->ttl = 255;
	ipv4->protocol = IPPROTO_UDP;
	ipv4->checksum = 0; 
	ipv4->source_address = ts->destination_ip.v4;
	ipv4->destination_address = ts->source_ip.v4;
	ipv4->checksum =
	  GNUNET_CRYPTO_crc16_n (ipv4, sizeof (struct ip4_header));
	if (0 == ntohs (reply->source_port))
	  udp->spt = htons (ts->destination_port);
	else
	  udp->spt = reply->source_port;
	if (0 == ntohs (reply->destination_port))
	  udp->dpt = htons (ts->source_port);
	else
	  udp->dpt = reply->destination_port;
	udp->len = htons (mlen + sizeof (struct udp_packet));
	udp->crc = 0; // FIXME: optional, but we might want to calculate this one anyway
	memcpy (&udp[1],
		&reply[1],
		mlen);
	(void) GNUNET_HELPER_send (helper_handle,
				   msg,
				   GNUNET_YES,
				   NULL, NULL);
      }
    }
    break;
  case AF_INET6:
    {
      size_t size = sizeof (struct ip6_header) 
	+ sizeof (struct udp_packet) 
	+ sizeof (struct GNUNET_MessageHeader) +
	sizeof (struct tun_header) +
	mlen;
      {
	char buf[size];
	struct GNUNET_MessageHeader *msg = (struct GNUNET_MessageHeader *) buf;
	struct tun_header *tun = (struct tun_header*) &msg[1];
	struct ip6_header *ipv6 = (struct ip6_header *) &tun[1];
	struct udp_packet *udp = (struct udp_packet *) &ipv6[1];
	msg->type = htons (GNUNET_MESSAGE_TYPE_VPN_HELPER);
	msg->size = htons (size);
	tun->flags = htons (0);
	tun->proto = htons (ETH_P_IPV6);
	ipv6->traffic_class_h = 0;
	ipv6->version = 6;
	ipv6->traffic_class_l = 0;
	ipv6->flow_label = 0;
	ipv6->payload_length = htons (sizeof (struct udp_packet) + sizeof (struct ip6_header) + mlen);
	ipv6->next_header = IPPROTO_UDP;
	ipv6->hop_limit = 255;
	ipv6->source_address = ts->destination_ip.v6;
	ipv6->destination_address = ts->source_ip.v6;
	if (0 == ntohs (reply->source_port))
	  udp->spt = htons (ts->destination_port);
	else
	  udp->spt = reply->source_port;
	if (0 == ntohs (reply->destination_port))
	  udp->dpt = htons (ts->source_port);
	else
	  udp->dpt = reply->destination_port;
	udp->len = htons (mlen + sizeof (struct udp_packet));
	udp->crc = 0;
	memcpy (&udp[1],
		&reply[1],
		mlen);
	{
	  uint32_t sum = 0;
	  sum =
	    GNUNET_CRYPTO_crc16_step (sum, &ipv6->source_address, 
				      sizeof (struct in6_addr) * 2);
	  uint32_t tmp = udp->len;
	  sum = GNUNET_CRYPTO_crc16_step (sum, &tmp, sizeof (uint32_t));
	  tmp = htons (IPPROTO_UDP);
	  sum = GNUNET_CRYPTO_crc16_step (sum, &tmp, sizeof (uint32_t));
	  sum = GNUNET_CRYPTO_crc16_step (sum, 
					  udp,
					  ntohs (udp->len));
	  udp->crc = GNUNET_CRYPTO_crc16_finish (sum);
	}
	(void) GNUNET_HELPER_send (helper_handle,
				   msg,
				   GNUNET_YES,
				   NULL, NULL);
      }
    }
    break;
  default:
    GNUNET_assert (0);
  }
#if 0
  // FIXME: refresh entry to avoid expiration...
  struct map_entry *me = GNUNET_CONTAINER_multihashmap_get (hashmap, key);
  
  GNUNET_CONTAINER_heap_update_cost (heap, me->heap_node,
				     GNUNET_TIME_absolute_get ().abs_value);
  
#endif
  return GNUNET_OK;
}


/**
 * We got a TCP packet back from the MESH tunnel.  Pass it on to the
 * local virtual interface via the helper.
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
receive_tcp_back (void *cls GNUNET_UNUSED, struct GNUNET_MESH_Tunnel *tunnel,
                  void **tunnel_ctx,
                  const struct GNUNET_PeerIdentity *sender GNUNET_UNUSED,
                  const struct GNUNET_MessageHeader *message,
                  const struct GNUNET_ATS_Information *atsi GNUNET_UNUSED)
{
  struct TunnelState *ts = *tunnel_ctx;
  const struct GNUNET_EXIT_TcpDataMessage *data;
  size_t mlen;

  mlen = ntohs (message->size);
  if (mlen < sizeof (struct GNUNET_EXIT_TcpDataMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (NULL == ts->heap_node)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  data = (const struct GNUNET_EXIT_TcpDataMessage *) message;
  mlen -= sizeof (struct GNUNET_EXIT_TcpDataMessage);
  switch (ts->af)
  {
  case AF_INET:
    {
      size_t size = sizeof (struct ip4_header) 
	+ sizeof (struct tcp_packet) 
	+ sizeof (struct GNUNET_MessageHeader) +
	sizeof (struct tun_header) +
	mlen;
      {
	char buf[size];
	struct GNUNET_MessageHeader *msg = (struct GNUNET_MessageHeader *) buf;
	struct tun_header *tun = (struct tun_header*) &msg[1];
	struct ip4_header *ipv4 = (struct ip4_header *) &tun[1];
	struct tcp_packet *tcp = (struct tcp_packet *) &ipv4[1];
	msg->type = htons (GNUNET_MESSAGE_TYPE_VPN_HELPER);
	msg->size = htons (size);
	tun->flags = htons (0);
	tun->proto = htons (ETH_P_IPV4);
	ipv4->version = 4;
	ipv4->header_length = sizeof (struct ip4_header) / 4;
	ipv4->diff_serv = 0;
	ipv4->total_length = htons (sizeof (struct ip4_header) +
				    sizeof (struct tcp_packet) +
				    mlen);
	ipv4->identification = (uint16_t) GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 
								    UINT16_MAX + 1);
	ipv4->flags = 0;
	ipv4->fragmentation_offset = 0;
	ipv4->ttl = 255;
	ipv4->protocol = IPPROTO_TCP;
	ipv4->checksum = 0; 
	ipv4->source_address = ts->destination_ip.v4;
	ipv4->destination_address = ts->source_ip.v4;
	ipv4->checksum =
	  GNUNET_CRYPTO_crc16_n (ipv4, sizeof (struct ip4_header));
	*tcp = data->tcp_header;
	tcp->spt = htons (ts->destination_port);
	tcp->dpt = htons (ts->source_port);
	tcp->crc = 0;
	memcpy (&tcp[1],
		&data[1],
		mlen);
	{
	  uint32_t sum = 0;
	  uint32_t tmp;
	  
	  sum = GNUNET_CRYPTO_crc16_step (sum, 
					  &ipv4->source_address,
					  2 * sizeof (struct in_addr));	  
	  tmp = htonl ((IPPROTO_TCP << 16) | (mlen + sizeof (struct tcp_packet)));
	  sum = GNUNET_CRYPTO_crc16_step (sum, &tmp, sizeof (uint32_t));
	  sum = GNUNET_CRYPTO_crc16_step (sum, tcp, mlen + sizeof (struct tcp_packet));
	  tcp->crc = GNUNET_CRYPTO_crc16_finish (sum);
	}
	(void) GNUNET_HELPER_send (helper_handle,
				   msg,
				   GNUNET_YES,
				   NULL, NULL);
      }
    }
    break;
  case AF_INET6:
    {
      size_t size = sizeof (struct ip6_header) 
	+ sizeof (struct tcp_packet) 
	+ sizeof (struct GNUNET_MessageHeader) +
	sizeof (struct tun_header) +
	mlen;
      {
	char buf[size];
	struct GNUNET_MessageHeader *msg = (struct GNUNET_MessageHeader *) buf;
	struct tun_header *tun = (struct tun_header*) &msg[1];
	struct ip6_header *ipv6 = (struct ip6_header *) &tun[1];
	struct tcp_packet *tcp = (struct tcp_packet *) &ipv6[1];
	msg->type = htons (GNUNET_MESSAGE_TYPE_VPN_HELPER);
	msg->size = htons (size);
	tun->flags = htons (0);
	tun->proto = htons (ETH_P_IPV6);
	ipv6->traffic_class_h = 0;
	ipv6->version = 6;
	ipv6->traffic_class_l = 0;
	ipv6->flow_label = 0;
	ipv6->payload_length = htons (sizeof (struct tcp_packet) + sizeof (struct ip6_header) + mlen);
	ipv6->next_header = IPPROTO_TCP;
	ipv6->hop_limit = 255;
	ipv6->source_address = ts->destination_ip.v6;
	ipv6->destination_address = ts->source_ip.v6;
	tcp->spt = htons (ts->destination_port);
	tcp->dpt = htons (ts->source_port);
	tcp->crc = 0;
	{
	  uint32_t sum = 0;
	  uint32_t tmp;

	  sum = GNUNET_CRYPTO_crc16_step (sum, &ipv6->source_address, 2 * sizeof (struct in6_addr));
	  tmp = htonl (sizeof (struct tcp_packet) + mlen);
	  sum = GNUNET_CRYPTO_crc16_step (sum, &tmp, sizeof (uint32_t));
	  tmp = htonl (IPPROTO_TCP);
	  sum = GNUNET_CRYPTO_crc16_step (sum, &tmp, sizeof (uint32_t));
	  sum = GNUNET_CRYPTO_crc16_step (sum, tcp,
					  sizeof (struct tcp_packet) + mlen);
	  tcp->crc = GNUNET_CRYPTO_crc16_finish (sum);
	}
	(void) GNUNET_HELPER_send (helper_handle,
				   msg,
				   GNUNET_YES,
				   NULL, NULL);
      }
    }
    break;
  }

#if 0
  // FIXME: refresh entry to avoid expiration...
  struct map_entry *me = GNUNET_CONTAINER_multihashmap_get (hashmap, key);
  
  GNUNET_CONTAINER_heap_update_cost (heap, me->heap_node,
				     GNUNET_TIME_absolute_get ().abs_value);
  
#endif
  return GNUNET_OK;
}


/**
 * Allocate an IPv4 address from the range of the tunnel
 * for a new redirection.
 *
 * @param v4 where to store the address
 * @return GNUNET_OK on success,
 *         GNUNET_SYSERR on error
 */
static int
allocate_v4_address (struct in_addr *v4)
{
  const char *ipv4addr = vpn_argv[4];
  const char *ipv4mask = vpn_argv[5];
  struct in_addr addr;
  struct in_addr mask;
  struct in_addr rnd;
  GNUNET_HashCode key;
  unsigned int tries;

  GNUNET_assert (1 == inet_pton (AF_INET, ipv4addr, &addr));
  GNUNET_assert (1 == inet_pton (AF_INET, ipv4mask, &mask));           
  /* Given 192.168.0.1/255.255.0.0, we want a mask 
     of '192.168.255.255', thus:  */
  mask.s_addr = addr.s_addr | ~mask.s_addr;  
  tries = 0;
  do
    {
      tries++;
      if (tries > 16)
      {
	GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		    _("Failed to find unallocated IPv4 address in VPN's range\n"));
	return GNUNET_SYSERR;
      }
      /* Pick random IPv4 address within the subnet, except 'addr' or 'mask' itself */
      rnd.s_addr = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 
					     UINT32_MAX);	
      v4->s_addr = (addr.s_addr | rnd.s_addr) & mask.s_addr;          
      get_destination_key_from_ip (AF_INET,
				   v4,
				   &key);
    }
  while ( (GNUNET_YES ==
	   GNUNET_CONTAINER_multihashmap_contains (destination_map,
						   &key)) ||
	  (v4->s_addr == addr.s_addr) ||
	  (v4->s_addr == mask.s_addr) );
  return GNUNET_OK;
}


/**
 * Allocate an IPv6 address from the range of the tunnel
 * for a new redirection.
 *
 * @param v6 where to store the address
 * @return GNUNET_OK on success,
 *         GNUNET_SYSERR on error
 */
static int
allocate_v6_address (struct in6_addr *v6)
{
  const char *ipv6addr = vpn_argv[2];
  struct in6_addr addr;
  struct in6_addr mask;
  struct in6_addr rnd;
  int i;
  GNUNET_HashCode key;
  unsigned int tries;

  GNUNET_assert (1 == inet_pton (AF_INET6, ipv6addr, &addr));
  GNUNET_assert (ipv6prefix < 128);
  /* Given ABCD::/96, we want a mask of 'ABCD::FFFF:FFFF,
     thus: */
  mask = addr;
  for (i=127;i>=128-ipv6prefix;i--)
    mask.s6_addr[i / 8] |= (1 << (i % 8));
  
  /* Pick random IPv6 address within the subnet, except 'addr' or 'mask' itself */
  tries = 0;
  do
    {
      tries++;
      if (tries > 16)
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		      _("Failed to find unallocated IPv6 address in VPN's range\n"));
	  return GNUNET_SYSERR;

	}
      for (i=0;i<16;i++)
	{
	  rnd.s6_addr[i] = (unsigned char) GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 
								     256);
	  v6->s6_addr[i]
	    = (addr.s6_addr[i] | rnd.s6_addr[i]) & mask.s6_addr[i];
	}
      get_destination_key_from_ip (AF_INET6,
				   v6,
				   &key);
    }
  while ( (GNUNET_YES ==
	   GNUNET_CONTAINER_multihashmap_contains (destination_map,
						   &key)) ||
	  (0 == memcmp (v6,
			&addr,
			sizeof (struct in6_addr))) ||
	  (0 == memcmp (v6,
			&mask,
			sizeof (struct in6_addr))) );
  return GNUNET_OK;
}


/**
 * A client asks us to setup a redirection via some exit
 * node to a particular IP.  Setup the redirection and
 * give the client the allocated IP.
 *
 * @param cls unused
 * @param client requesting client
 * @param message redirection request (a 'struct RedirectToIpRequestMessage')
 */
static void
service_redirect_to_ip (void *cls GNUNET_UNUSED, struct GNUNET_SERVER_Client *client,
			const struct GNUNET_MessageHeader *message)
{
  size_t mlen;
  size_t alen;
  const struct RedirectToIpRequestMessage *msg;
  int addr_af;
  int result_af;
  struct in_addr v4;
  struct in6_addr v6;
  void *addr;
  struct DestinationEntry *de;
  GNUNET_HashCode key;
  struct TunnelState *ts;
  GNUNET_MESH_ApplicationType app_type;
  
  /* validate and parse request */
  mlen = ntohs (message->size);
  if (mlen < sizeof (struct RedirectToIpRequestMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  alen = mlen - sizeof (struct RedirectToIpRequestMessage);
  msg = (const struct RedirectToIpRequestMessage *) message;
  addr_af = (int) htonl (msg->addr_af);
  switch (addr_af)
  {
  case AF_INET:
    if (alen != sizeof (struct in_addr))
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;      
    }
    app_type = GNUNET_APPLICATION_TYPE_IPV4_GATEWAY; 
    break;
  case AF_INET6:
    if (alen != sizeof (struct in6_addr))
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;      
    }
    app_type = GNUNET_APPLICATION_TYPE_IPV6_GATEWAY; 
    break;
  default:
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;      
  }

  /* allocate response IP */
  addr = NULL;
  result_af = (int) htonl (msg->result_af);
  switch (result_af)
  {
  case AF_INET:
    if (GNUNET_OK !=
	allocate_v4_address (&v4))
      result_af = AF_UNSPEC;
    else
      addr = &v4;
    break;
  case AF_INET6:
    if (GNUNET_OK !=
	allocate_v6_address (&v6))
      result_af = AF_UNSPEC;
    else
      addr = &v6;
    break;
  case AF_UNSPEC:
    if (GNUNET_OK ==
	allocate_v4_address (&v4))
    {
      addr = &v4;
      result_af = AF_INET;
    }
    else if (GNUNET_OK ==
	allocate_v6_address (&v6))
    {
      addr = &v6;
      result_af = AF_INET6;
    }
    break;
  default:
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;      
  }
  if ( (result_af == AF_UNSPEC) ||
       (GNUNET_NO == ntohl (msg->nac)) )
  {
    /* send reply "instantly" */
    send_client_reply (client,
		       msg->request_id,
		       result_af,
		       addr);
  }
  if (result_af == AF_UNSPEC)
  {
    /* failure, we're done */
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  
  /* setup destination record */
  de = GNUNET_malloc (sizeof (struct DestinationEntry));
  de->is_service = GNUNET_NO;
  de->details.exit_destination.af = addr_af;
  memcpy (&de->details.exit_destination.ip,
	  &msg[1],
	  alen);
  get_destination_key_from_ip (result_af,
			       addr,
			       &key);
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CONTAINER_multihashmap_put (destination_map,
						    &key,
						    de,
						    GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
  de->heap_node = GNUNET_CONTAINER_heap_insert (destination_heap,
						de,
						GNUNET_TIME_absolute_ntoh (msg->expiration_time).abs_value);
  /* setup tunnel to destination */
  ts = GNUNET_malloc (sizeof (struct TunnelState));
  if (GNUNET_NO != ntohl (msg->nac))
  {
    ts->request_id = msg->request_id;
    ts->client = client;
    GNUNET_SERVER_client_keep (client);
  }
  ts->destination = *de;
  ts->destination.heap_node = NULL;
  ts->is_service = GNUNET_NO;
  ts->af = result_af;
  if (result_af == AF_INET) 
    ts->destination_ip.v4 = v4;
  else
    ts->destination_ip.v6 = v6;
  de->tunnel = GNUNET_MESH_tunnel_create (mesh_handle,
					  ts,
					  &tunnel_peer_connect_handler,
					  &tunnel_peer_disconnect_handler,
					  ts);
  GNUNET_MESH_peer_request_connect_by_type (de->tunnel,
					    app_type);  
  /* we're done */
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * A client asks us to setup a redirection to a particular peer
 * offering a service.  Setup the redirection and give the client the
 * allocated IP.
 *
 * @param cls unused
 * @param client requesting client
 * @param message redirection request (a 'struct RedirectToPeerRequestMessage')
 */
static void
service_redirect_to_service (void *cls GNUNET_UNUSED, struct GNUNET_SERVER_Client *client,
			     const struct GNUNET_MessageHeader *message)
{
  const struct RedirectToServiceRequestMessage *msg;
  int result_af;
  struct in_addr v4;
  struct in6_addr v6;
  void *addr;
  struct DestinationEntry *de;
  GNUNET_HashCode key;
  struct TunnelState *ts;
  
  /*  parse request */
  msg = (const struct RedirectToServiceRequestMessage *) message;

  /* allocate response IP */
  addr = NULL;
  result_af = (int) htonl (msg->result_af);
  switch (result_af)
  {
  case AF_INET:
    if (GNUNET_OK !=
	allocate_v4_address (&v4))
      result_af = AF_UNSPEC;
    else
      addr = &v4;
    break;
  case AF_INET6:
    if (GNUNET_OK !=
	allocate_v6_address (&v6))
      result_af = AF_UNSPEC;
    else
      addr = &v6;
    break;
  case AF_UNSPEC:
    if (GNUNET_OK ==
	allocate_v4_address (&v4))
    {
      addr = &v4;
      result_af = AF_INET;
    }
    else if (GNUNET_OK ==
	allocate_v6_address (&v6))
    {
      addr = &v6;
      result_af = AF_INET6;
    }
    break;
  default:
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;      
  }
  if ( (result_af == AF_UNSPEC) ||
       (GNUNET_NO == ntohl (msg->nac)) )
  {
    /* send reply "instantly" */
    send_client_reply (client,
		       msg->request_id,
		       result_af,
		       addr);
  }
  if (result_af == AF_UNSPEC)
  {
    /* failure, we're done */
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  
  /* setup destination record */
  de = GNUNET_malloc (sizeof (struct DestinationEntry));
  de->is_service = GNUNET_YES;
  de->details.service_destination.service_descriptor = msg->service_descriptor;
  de->details.service_destination.target = msg->target;
  get_destination_key_from_ip (result_af,
			       addr,
			       &key);
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CONTAINER_multihashmap_put (destination_map,
						    &key,
						    de,
						    GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
  de->heap_node = GNUNET_CONTAINER_heap_insert (destination_heap,
						de,
						GNUNET_TIME_absolute_ntoh (msg->expiration_time).abs_value);

  /* setup tunnel to destination */
  ts = GNUNET_malloc (sizeof (struct TunnelState));
  if (GNUNET_NO != ntohl (msg->nac))
  {
    ts->request_id = msg->request_id;
    ts->client = client;
    GNUNET_SERVER_client_keep (client);
  }
  ts->destination = *de;
  ts->destination.heap_node = NULL;
  ts->is_service = GNUNET_YES;
  ts->af = result_af;
  if (result_af == AF_INET) 
    ts->destination_ip.v4 = v4;
  else
    ts->destination_ip.v6 = v6;
  de->tunnel = GNUNET_MESH_tunnel_create (mesh_handle,
					  ts,
					  &tunnel_peer_connect_handler,
					  &tunnel_peer_disconnect_handler,
					  ts);
  GNUNET_MESH_peer_request_connect_add (de->tunnel,
					&msg->target);  
  /* we're done */
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}



/**
 * Function called for inbound tunnels.  As we don't offer
 * any mesh services, this function should never be called.
 *
 * @param cls closure
 * @param tunnel new handle to the tunnel
 * @param initiator peer that started the tunnel
 * @param atsi performance information for the tunnel
 * @return initial tunnel context for the tunnel
 *         (can be NULL -- that's not an error)
 */ 
static void *
inbound_tunnel_cb (void *cls, struct GNUNET_MESH_Tunnel *tunnel,
		   const struct GNUNET_PeerIdentity *initiator,
		   const struct GNUNET_ATS_Information *atsi)
{
  /* Why should anyone open an inbound tunnel to vpn? */
  GNUNET_break (0);
  return NULL;
}


/**
 * Function called whenever an inbound tunnel is destroyed.  Should clean up
 * any associated state.
 *
 * @param cls closure (set from GNUNET_MESH_connect)
 * @param tunnel connection to the other end (henceforth invalid)
 * @param tunnel_ctx place where local state associated
 *                   with the tunnel is stored
 */ 
static void
tunnel_cleaner (void *cls, const struct GNUNET_MESH_Tunnel *tunnel, void *tunnel_ctx)
{
  /* FIXME: is this function called for outbound tunnels that go down?
     Should we clean up something here? */
  GNUNET_break (0);
}


/**
 * Free memory occupied by an entry in the destination map.
 *
 * @param cls unused
 * @param key unused
 * @param value a 'struct DestinationEntry *'
 * @return GNUNET_OK (continue to iterate)
 */
static int
cleanup_destination (void *cls,
		     const GNUNET_HashCode *key,
		     void *value)
{
  struct DestinationEntry *de = value;

  if (NULL != de->tunnel)
  {
    GNUNET_MESH_tunnel_destroy (de->tunnel);
    de->tunnel = NULL;
  }
  if (NULL != de->heap_node)
  {
    GNUNET_CONTAINER_heap_remove_node (de->heap_node);
    de->heap_node = NULL;
  }
  GNUNET_free (de);
  return GNUNET_OK;
}


/**
 * Free memory occupied by an entry in the tunnel map.
 *
 * @param cls unused
 * @param key unused
 * @param value a 'struct TunnelState *'
 * @return GNUNET_OK (continue to iterate)
 */
static int
cleanup_tunnel (void *cls,
		const GNUNET_HashCode *key,
		void *value)
{
  struct TunnelState *ts = value;
  struct TunnelMessageQueueEntry *tnq;

  while (NULL != (tnq = ts->head))
  {
    GNUNET_CONTAINER_DLL_remove (ts->head,
				 ts->tail,
				 tnq);
    GNUNET_free (tnq);
  }
  if (NULL != ts->client)
  {
    GNUNET_SERVER_client_drop (ts->client);
    ts->client = NULL;
  }
  if (NULL != ts->th)
  {
    GNUNET_MESH_notify_transmit_ready_cancel (ts->th);
    ts->th = NULL;
  }
  if (NULL != ts->destination.tunnel)
  {
    GNUNET_MESH_tunnel_destroy (ts->destination.tunnel);
    ts->destination.tunnel = NULL;
  }
  if (NULL != ts->heap_node)
  {
    GNUNET_CONTAINER_heap_remove_node (ts->heap_node);
    ts->heap_node = NULL;
  }
  // FIXME...
  GNUNET_free (ts);
  return GNUNET_OK;
}


/**
 * Function scheduled as very last function, cleans up after us
 *
 * @param cls unused
 * @param tc unused
 */
static void
cleanup (void *cls GNUNET_UNUSED,
         const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  unsigned int i;

  if (NULL != destination_map)
  {  
    GNUNET_CONTAINER_multihashmap_iterate (destination_map,
					   &cleanup_destination,
					   NULL);
    GNUNET_CONTAINER_multihashmap_destroy (destination_map);
    destination_map = NULL;
  }
  if (NULL != destination_heap)
  {
    GNUNET_CONTAINER_heap_destroy (destination_heap);
    destination_heap = NULL;
  }
  if (NULL != tunnel_map)
  {  
    GNUNET_CONTAINER_multihashmap_iterate (tunnel_map,
					   &cleanup_tunnel,
					   NULL);
    GNUNET_CONTAINER_multihashmap_destroy (tunnel_map);
    tunnel_map = NULL;
  }
  if (NULL != tunnel_heap)
  {
    GNUNET_CONTAINER_heap_destroy (tunnel_heap);
    tunnel_heap = NULL;
  }
  if (NULL != mesh_handle)
  {
    GNUNET_MESH_disconnect (mesh_handle);
    mesh_handle = NULL;
  }
  if (NULL != helper_handle)
    {
    GNUNET_HELPER_stop (helper_handle);
    helper_handle = NULL;
  }
  if (NULL != nc)
  {
    GNUNET_SERVER_notification_context_destroy (nc);
    nc = NULL;
  }
  for (i=0;i<5;i++)
    GNUNET_free_non_null (vpn_argv[i]);
}


/**
 * A client disconnected, clean up all references to it.
 *
 * @param cls the client that disconnected
 * @param key unused
 * @param value a 'struct TunnelState *'
 * @return GNUNET_OK (continue to iterate)
 */
static int
cleanup_tunnel_client (void *cls,
		       const GNUNET_HashCode *key,
		       void *value)
{
  struct GNUNET_SERVER_Client *client = cls;
  struct TunnelState *ts = value;

  if (client == ts->client)
  {
    GNUNET_SERVER_client_drop (ts->client);
    ts->client = NULL;
  }
  return GNUNET_OK;
}

  
/**
 * A client has disconnected from us.  If we are currently building
 * a tunnel for it, cancel the operation.
 *
 * @param cls unused
 * @param client handle to the client that disconnected
 */
static void
client_disconnect (void *cls, struct GNUNET_SERVER_Client *client)
{
  // FIXME: check that all truly all 'struct TunnelState's 
  // with clients are always in the tunnel map!
  GNUNET_CONTAINER_multihashmap_iterate (tunnel_map,
					 &cleanup_tunnel_client,
					 client);
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
  static const struct GNUNET_SERVER_MessageHandler service_handlers[] = {
    /* callback, cls, type, size */
    {&service_redirect_to_ip, NULL, GNUNET_MESSAGE_TYPE_VPN_CLIENT_REDIRECT_TO_IP, 0},
    {&service_redirect_to_service, NULL, 
     GNUNET_MESSAGE_TYPE_VPN_CLIENT_REDIRECT_TO_SERVICE, 
     sizeof (struct RedirectToServiceRequestMessage) },
    {NULL, NULL, 0, 0}
  };
  static const struct GNUNET_MESH_MessageHandler mesh_handlers[] = {
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

  cfg = cfg_;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "vpn", "MAX_MAPPING",
					     &max_destination_mappings))
    max_destination_mappings = 200;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "vpn", "MAX_TUNNELS",
					     &max_tunnel_mappings))
    max_tunnel_mappings = 200;

  destination_map = GNUNET_CONTAINER_multihashmap_create (max_destination_mappings * 2);
  destination_heap = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  tunnel_map = GNUNET_CONTAINER_multihashmap_create (max_tunnel_mappings * 2);
  tunnel_heap = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);


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
			 &inbound_tunnel_cb, 
			 &tunnel_cleaner, 
			 mesh_handlers,
			 types);
  helper_handle = GNUNET_HELPER_start ("gnunet-helper-vpn", vpn_argv,
				       &message_token, NULL);
  nc = GNUNET_SERVER_notification_context_create (server, 1);
  GNUNET_SERVER_add_handlers (server, service_handlers);
  GNUNET_SERVER_disconnect_notify (server, &client_disconnect, NULL);
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
