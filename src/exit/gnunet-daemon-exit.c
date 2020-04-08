/*
     This file is part of GNUnet.
     Copyright (C) 2010-2013, 2017 Christian Grothoff

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file exit/gnunet-daemon-exit.c
 * @brief tool to allow IP traffic exit from the GNUnet cadet to the Internet
 * @author Philipp Toelke
 * @author Christian Grothoff
 *
 * TODO:
 * - test
 *
 * Design:
 * - which code should advertise services? the service model is right
 *   now a bit odd, especially as this code DOES the exit and knows
 *   the DNS "name", but OTOH this is clearly NOT the place to advertise
 *   the service's existence; maybe the daemon should turn into a
 *   service with an API to add local-exit services dynamically?
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_applications.h"
#include "gnunet_dht_service.h"
#include "gnunet_cadet_service.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_dnsstub_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_constants.h"
#include "gnunet_signatures.h"
#include "gnunet_tun_lib.h"
#include "gnunet_regex_service.h"
#include "exit.h"
#include "block_dns.h"


/**
 * Maximum path compression length for cadet regex announcing for IPv4 address
 * based regex.
 */
#define REGEX_MAX_PATH_LEN_IPV4 4

/**
 * Maximum path compression length for cadet regex announcing for IPv6 address
 * based regex.
 */
#define REGEX_MAX_PATH_LEN_IPV6 8

/**
 * How frequently do we re-announce the regex for the exit?
 */
#define REGEX_REFRESH_FREQUENCY GNUNET_TIME_relative_multiply ( \
    GNUNET_TIME_UNIT_MINUTES, 30)

/**
 * How frequently do we re-announce the DNS exit in the DHT?
 */
#define DHT_PUT_FREQUENCY GNUNET_TIME_relative_multiply ( \
    GNUNET_TIME_UNIT_MINUTES, 15)

/**
 * How long do we typically sign the DNS exit advertisement for?
 */
#define DNS_ADVERTISEMENT_TIMEOUT GNUNET_TIME_relative_multiply ( \
    GNUNET_TIME_UNIT_HOURS, 3)


/**
 * Generic logging shorthand
 */
#define LOG(kind, ...)                          \
  GNUNET_log_from (kind, "exit", __VA_ARGS__);


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
   * Descriptor for the service (CADET port).
   */
  struct GNUNET_HashCode descriptor;

  /**
   * DNS name of the service.
   */
  char *name;

  /**
   * Open port with CADET.
   */
  struct GNUNET_CADET_Port *port;

  /**
   * #GNUNET_YES if this is a UDP service, otherwise TCP.
   */
  int16_t is_udp;
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
 * This struct is saved into #connections_map to allow finding the
 * right channel given an IP packet from TUN.  It is also associated
 * with the channel's closure so we can find it again for the next
 * message from the channel.
 */
struct ChannelState
{
  /**
   * Cadet channel that is used for this connection.
   */
  struct GNUNET_CADET_Channel *channel;

  /**
   * Who is the other end of this channel.
   * FIXME is this needed? Only used for debugging messages
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * #GNUNET_NO if this is a channel for TCP/UDP,
   * #GNUNET_YES if this is a channel for DNS,
   * #GNUNET_SYSERR if the channel is not yet initialized.
   */
  int is_dns;

  union
  {
    struct
    {
      /**
       * Heap node for this state in the connections_heap.
       */
      struct GNUNET_CONTAINER_HeapNode *heap_node;

      /**
       * Key this state has in the #connections_map.
       */
      struct GNUNET_HashCode state_key;

      /**
       * Associated service record, or NULL for no service.
       */
      struct LocalService *serv;

      /**
       * Primary redirection information for this connection.
       */
      struct RedirectInformation ri;
    } tcp_udp;

    struct
    {
      /**
       * Socket we are using to transmit this request (must match if we receive
       * a response).
       */
      struct GNUNET_DNSSTUB_RequestSocket *rs;

      /**
       * Original DNS request ID as used by the client.
       */
      uint16_t original_id;

      /**
       * DNS request ID that we used for forwarding.
       */
      uint16_t my_id;
    } dns;
  } specifics;
};


/**
 * Return value from 'main'.
 */
static int global_ret;

/**
 * Handle to our regex announcement for IPv4.
 */
static struct GNUNET_REGEX_Announcement *regex4;

/**
 * Handle to our regex announcement for IPv4.
 */
static struct GNUNET_REGEX_Announcement *regex6;

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
static char *exit_argv[8];

/**
 * IPv6 address of our TUN interface.
 */
static struct in6_addr exit_ipv6addr;

/**
 * IPv6 prefix (0..127) from configuration file.
 */
static unsigned long long ipv6prefix;

/**
 * IPv4 address of our TUN interface.
 */
static struct in_addr exit_ipv4addr;

/**
 * IPv4 netmask of our TUN interface.
 */
static struct in_addr exit_ipv4mask;

/**
 * Statistics.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * The handle to cadet
 */
static struct GNUNET_CADET_Handle *cadet_handle;

/**
 * This hashmaps contains the mapping from peer, service-descriptor,
 * source-port and destination-port to a struct ChannelState
 */
static struct GNUNET_CONTAINER_MultiHashMap *connections_map;

/**
 * Heap so we can quickly find "old" connections.
 */
static struct GNUNET_CONTAINER_Heap *connections_heap;

/**
 * If there are at least this many connections, old ones will be removed
 */
static unsigned long long max_connections;

/**
 * This hashmaps saves interesting things about the configured services
 */
static struct GNUNET_CONTAINER_MultiHashMap *services;

/**
 * Array of all open DNS requests from channels.
 */
static struct ChannelState *channels[UINT16_MAX + 1];

/**
 * Handle to the DNS Stub resolver.
 */
static struct GNUNET_DNSSTUB_Context *dnsstub;

/**
 * Handle for ongoing DHT PUT operations to advertise exit service.
 */
static struct GNUNET_DHT_PutHandle *dht_put;

/**
 * Handle to the DHT.
 */
static struct GNUNET_DHT_Handle *dht;

/**
 * Task for doing DHT PUTs to advertise exit service.
 */
static struct GNUNET_SCHEDULER_Task *dht_task;

/**
 * Advertisement message we put into the DHT to advertise us
 * as a DNS exit.
 */
static struct GNUNET_DNS_Advertisement dns_advertisement;

/**
 * Key we store the DNS advertismenet under.
 */
static struct GNUNET_HashCode dht_put_key;

/**
 * Private key for this peer.
 */
static struct GNUNET_CRYPTO_EddsaPrivateKey *peer_key;

/**
 * Port for DNS exit.
 */
static struct GNUNET_CADET_Port *dns_port;

/**
 * Port for IPv4 exit.
 */
static struct GNUNET_CADET_Port *cadet_port4;

/**
 * Port for IPv6 exit.
 */
static struct GNUNET_CADET_Port *cadet_port6;

/**
 * Are we an IPv4-exit?
 */
static int ipv4_exit;

/**
 * Are we an IPv6-exit?
 */
static int ipv6_exit;

/**
 * Do we support IPv4 at all on the TUN interface?
 */
static int ipv4_enabled;

/**
 * Do we support IPv6 at all on the TUN interface?
 */
static int ipv6_enabled;


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Message with a DNS response.
 */
struct DnsResponseMessage
{
  /**
   * GNUnet header, of type #GNUNET_MESSAGE_TYPE_VPN_DNS_FROM_INTERNET
   */
  struct GNUNET_MessageHeader header;

  /**
   * DNS header.
   */
  struct GNUNET_TUN_DnsHeader dns;

  /* Followed by more DNS payload */
};

GNUNET_NETWORK_STRUCT_END


/**
 * Callback called from DNSSTUB resolver when a resolution
 * succeeded.
 *
 * @param cls NULL
 * @param dns the response itself
 * @param r number of bytes in @a dns
 */
static void
process_dns_result (void *cls,
                    const struct GNUNET_TUN_DnsHeader *dns,
                    size_t r)
{
  struct ChannelState *ts;
  struct GNUNET_MQ_Envelope *env;
  struct DnsResponseMessage *resp;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Processing DNS result from stub resolver\n");
  GNUNET_assert (NULL == cls);
  if (NULL == dns)
    return;
  /* Handle case that this is a reply to a request from a CADET DNS channel */
  ts = channels[dns->id];
  if (NULL == ts)
    return;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Got a response from the stub resolver for DNS request received via CADET!\n");
  channels[dns->id] = NULL;
  env = GNUNET_MQ_msg_extra (resp,
                             r - sizeof(struct GNUNET_TUN_DnsHeader),
                             GNUNET_MESSAGE_TYPE_VPN_DNS_FROM_INTERNET);
  GNUNET_memcpy (&resp->dns,
                 dns,
                 r);
  resp->dns.id = ts->specifics.dns.original_id;
  GNUNET_MQ_send (GNUNET_CADET_get_mq (ts->channel),
                  env);
}


/**
 * Check a request via cadet to perform a DNS query.
 *
 * @param cls our `struct ChannelState *`
 * @param msg the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
check_dns_request (void *cls,
                   const struct DnsResponseMessage *msg)
{
  struct ChannelState *ts = cls;

  if (NULL == dnsstub)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (GNUNET_NO == ts->is_dns)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Process a request via cadet to perform a DNS query.
 *
 * @param cls our `struct ChannelState *`
 * @param msg the actual message
 */
static void
handle_dns_request (void *cls,
                    const struct DnsResponseMessage *msg)
{
  struct ChannelState *ts = cls;
  size_t mlen = ntohs (msg->header.size);
  size_t dlen = mlen - sizeof(struct GNUNET_MessageHeader);
  char buf[dlen] GNUNET_ALIGN;
  struct GNUNET_TUN_DnsHeader *dout;

  if (GNUNET_SYSERR == ts->is_dns)
  {
    /* channel is DNS from now on */
    ts->is_dns = GNUNET_YES;
  }
  ts->specifics.dns.original_id = msg->dns.id;
  if (channels[ts->specifics.dns.my_id] == ts)
    channels[ts->specifics.dns.my_id] = NULL;
  ts->specifics.dns.my_id = (uint16_t) GNUNET_CRYPTO_random_u32 (
    GNUNET_CRYPTO_QUALITY_WEAK,
    UINT16_MAX
    + 1);
  channels[ts->specifics.dns.my_id] = ts;
  GNUNET_memcpy (buf,
                 &msg->dns,
                 dlen);
  dout = (struct GNUNET_TUN_DnsHeader *) buf;
  dout->id = ts->specifics.dns.my_id;
  ts->specifics.dns.rs = GNUNET_DNSSTUB_resolve (dnsstub,
                                                 buf,
                                                 dlen,
                                                 &process_dns_result,
                                                 NULL);
  if (NULL == ts->specifics.dns.rs)
  {
    GNUNET_break_op (0);
    return;
  }
  GNUNET_CADET_receive_done (ts->channel);
}


/**
 * Given IP information about a connection, calculate the respective
 * hash we would use for the #connections_map.
 *
 * @param hash resulting hash
 * @param ri information about the connection
 */
static void
hash_redirect_info (struct GNUNET_HashCode *hash,
                    const struct RedirectInformation *ri)
{
  char *off;

  memset (hash,
          0,
          sizeof(struct GNUNET_HashCode));
  /* the GNUnet hashmap only uses the first sizeof(unsigned int) of the hash,
     so we put the IP address in there (and hope for few collisions) */
  off = (char *) hash;
  switch (ri->remote_address.af)
  {
  case AF_INET:
    GNUNET_memcpy (off,
                   &ri->remote_address.address.ipv4,
                   sizeof(struct in_addr));
    off += sizeof(struct in_addr);
    break;

  case AF_INET6:
    GNUNET_memcpy (off,
                   &ri->remote_address.address.ipv6,
                   sizeof(struct in6_addr));
    off += sizeof(struct in_addr);
    break;

  default:
    GNUNET_assert (0);
  }
  GNUNET_memcpy (off,
                 &ri->remote_address.port,
                 sizeof(uint16_t));
  off += sizeof(uint16_t);
  switch (ri->local_address.af)
  {
  case AF_INET:
    GNUNET_memcpy (off,
                   &ri->local_address.address.ipv4,
                   sizeof(struct in_addr));
    off += sizeof(struct in_addr);
    break;

  case AF_INET6:
    GNUNET_memcpy (off,
                   &ri->local_address.address.ipv6,
                   sizeof(struct in6_addr));
    off += sizeof(struct in_addr);
    break;

  default:
    GNUNET_assert (0);
  }
  GNUNET_memcpy (off,
                 &ri->local_address.port,
                 sizeof(uint16_t));
  off += sizeof(uint16_t);
  GNUNET_memcpy (off,
                 &ri->remote_address.proto,
                 sizeof(uint8_t));
  /* off += sizeof (uint8_t); */
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
static struct ChannelState *
get_redirect_state (int af,
                    int protocol,
                    const void *destination_ip,
                    uint16_t destination_port,
                    const void *local_ip,
                    uint16_t local_port,
                    struct GNUNET_HashCode *state_key)
{
  struct RedirectInformation ri;
  struct GNUNET_HashCode key;
  struct ChannelState *state;

  if (((af == AF_INET) && (protocol == IPPROTO_ICMP)) ||
      ((af == AF_INET6) && (protocol == IPPROTO_ICMPV6)))
  {
    /* ignore ports */
    destination_port = 0;
    local_port = 0;
  }
  ri.remote_address.af = af;
  if (af == AF_INET)
    ri.remote_address.address.ipv4 = *((struct in_addr*) destination_ip);
  else
    ri.remote_address.address.ipv6 = *((struct in6_addr*) destination_ip);
  ri.remote_address.port = destination_port;
  ri.remote_address.proto = protocol;
  ri.local_address.af = af;
  if (af == AF_INET)
    ri.local_address.address.ipv4 = *((struct in_addr*) local_ip);
  else
    ri.local_address.address.ipv6 = *((struct in6_addr*) local_ip);
  ri.local_address.port = local_port;
  ri.local_address.proto = protocol;
  hash_redirect_info (&key,
                      &ri);
  if (NULL != state_key)
    *state_key = key;
  state = GNUNET_CONTAINER_multihashmap_get (connections_map,
                                             &key);
  if (NULL == state)
    return NULL;
  /* Mark this connection as freshly used */
  if (NULL == state_key)
    GNUNET_CONTAINER_heap_update_cost (state->specifics.tcp_udp.heap_node,
                                       GNUNET_TIME_absolute_get ().abs_value_us);
  return state;
}


/**
 * Check a request via cadet to send a request to a TCP service
 * offered by this system.
 *
 * @param cls our `struct ChannelState *`
 * @param start the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
check_tcp_service (void *cls,
                   const struct GNUNET_EXIT_TcpServiceStartMessage *start)
{
  struct ChannelState *state = cls;

  if (NULL == state)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (GNUNET_YES == state->is_dns)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (NULL == state->specifics.tcp_udp.serv)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (NULL != state->specifics.tcp_udp.heap_node)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (start->tcp_header.off * 4 < sizeof(struct GNUNET_TUN_TcpHeader))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
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
 * @param payload_length number of bytes in @a payload
 * @param protocol IPPROTO_UDP or IPPROTO_TCP
 * @param tcp_header skeleton of the TCP header, NULL for UDP
 * @param src_address source address to use (IP and port)
 * @param dst_address destination address to use (IP and port)
 * @param pkt4 where to write the assembled packet; must
 *        contain enough space for the IP header, UDP/TCP header
 *        AND the payload
 */
static void
prepare_ipv4_packet (const void *payload,
                     size_t payload_length,
                     int protocol,
                     const struct GNUNET_TUN_TcpHeader *tcp_header,
                     const struct SocketAddress *src_address,
                     const struct SocketAddress *dst_address,
                     struct GNUNET_TUN_IPv4Header *pkt4)
{
  size_t len;

  len = payload_length;
  switch (protocol)
  {
  case IPPROTO_UDP:
    len += sizeof(struct GNUNET_TUN_UdpHeader);
    break;

  case IPPROTO_TCP:
    len += sizeof(struct GNUNET_TUN_TcpHeader);
    GNUNET_assert (NULL != tcp_header);
    break;

  default:
    GNUNET_break (0);
    return;
  }
  if (len + sizeof(struct GNUNET_TUN_IPv4Header) > UINT16_MAX)
  {
    GNUNET_break (0);
    return;
  }

  GNUNET_TUN_initialize_ipv4_header (pkt4,
                                     protocol,
                                     len,
                                     &src_address->address.ipv4,
                                     &dst_address->address.ipv4);
  switch (protocol)
  {
  case IPPROTO_UDP:
    {
      struct GNUNET_TUN_UdpHeader *pkt4_udp = (struct
                                               GNUNET_TUN_UdpHeader *) &pkt4[1];

      pkt4_udp->source_port = htons (src_address->port);
      pkt4_udp->destination_port = htons (dst_address->port);
      pkt4_udp->len = htons ((uint16_t) payload_length);
      GNUNET_TUN_calculate_udp4_checksum (pkt4,
                                          pkt4_udp,
                                          payload,
                                          payload_length);
      GNUNET_memcpy (&pkt4_udp[1],
                     payload,
                     payload_length);
    }
    break;

  case IPPROTO_TCP:
    {
      struct GNUNET_TUN_TcpHeader *pkt4_tcp = (struct
                                               GNUNET_TUN_TcpHeader *) &pkt4[1];

      *pkt4_tcp = *tcp_header;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Sending TCP packet from port %u to port %u\n",
                  src_address->port,
                  dst_address->port);
      pkt4_tcp->source_port = htons (src_address->port);
      pkt4_tcp->destination_port = htons (dst_address->port);
      GNUNET_TUN_calculate_tcp4_checksum (pkt4,
                                          pkt4_tcp,
                                          payload,
                                          payload_length);
      GNUNET_memcpy (&pkt4_tcp[1],
                     payload,
                     payload_length);
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
 * @param payload_length number of bytes in @a payload
 * @param protocol IPPROTO_UDP or IPPROTO_TCP
 * @param tcp_header skeleton TCP header data to send, NULL for UDP
 * @param src_address source address to use (IP and port)
 * @param dst_address destination address to use (IP and port)
 * @param pkt6 where to write the assembled packet; must
 *        contain enough space for the IP header, UDP/TCP header
 *        AND the payload
 */
static void
prepare_ipv6_packet (const void *payload,
                     size_t payload_length,
                     int protocol,
                     const struct GNUNET_TUN_TcpHeader *tcp_header,
                     const struct SocketAddress *src_address,
                     const struct SocketAddress *dst_address,
                     struct GNUNET_TUN_IPv6Header *pkt6)
{
  size_t len;

  len = payload_length;
  switch (protocol)
  {
  case IPPROTO_UDP:
    len += sizeof(struct GNUNET_TUN_UdpHeader);
    break;

  case IPPROTO_TCP:
    len += sizeof(struct GNUNET_TUN_TcpHeader);
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

  GNUNET_TUN_initialize_ipv6_header (pkt6,
                                     protocol,
                                     len,
                                     &src_address->address.ipv6,
                                     &dst_address->address.ipv6);

  switch (protocol)
  {
  case IPPROTO_UDP:
    {
      struct GNUNET_TUN_UdpHeader *pkt6_udp = (struct
                                               GNUNET_TUN_UdpHeader *) &pkt6[1];

      pkt6_udp->source_port = htons (src_address->port);
      pkt6_udp->destination_port = htons (dst_address->port);
      pkt6_udp->len = htons ((uint16_t) payload_length);
      GNUNET_TUN_calculate_udp6_checksum (pkt6,
                                          pkt6_udp,
                                          payload,
                                          payload_length);
      GNUNET_memcpy (&pkt6_udp[1],
                     payload,
                     payload_length);
    }
    break;

  case IPPROTO_TCP:
    {
      struct GNUNET_TUN_TcpHeader *pkt6_tcp = (struct
                                               GNUNET_TUN_TcpHeader *) &pkt6[1];

      /* GNUNET_memcpy first here as some TCP header fields are initialized this way! */
      *pkt6_tcp = *tcp_header;
      pkt6_tcp->source_port = htons (src_address->port);
      pkt6_tcp->destination_port = htons (dst_address->port);
      GNUNET_TUN_calculate_tcp6_checksum (pkt6,
                                          pkt6_tcp,
                                          payload,
                                          payload_length);
      GNUNET_memcpy (&pkt6_tcp[1],
                     payload,
                     payload_length);
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
 * @param tcp_header header template to use
 * @param payload payload of the TCP packet
 * @param payload_length number of bytes in @a payload
 */
static void
send_tcp_packet_via_tun (const struct SocketAddress *destination_address,
                         const struct SocketAddress *source_address,
                         const struct GNUNET_TUN_TcpHeader *tcp_header,
                         const void *payload,
                         size_t payload_length)
{
  size_t len;

  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# TCP packets sent via TUN"),
                            1,
                            GNUNET_NO);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending packet with %u bytes TCP payload via TUN\n",
              (unsigned int) payload_length);
  len = sizeof(struct GNUNET_MessageHeader) + sizeof(struct
                                                     GNUNET_TUN_Layer2PacketHeader);
  switch (source_address->af)
  {
  case AF_INET:
    len += sizeof(struct GNUNET_TUN_IPv4Header);
    break;

  case AF_INET6:
    len += sizeof(struct GNUNET_TUN_IPv6Header);
    break;

  default:
    GNUNET_break (0);
    return;
  }
  len += sizeof(struct GNUNET_TUN_TcpHeader);
  len += payload_length;
  if (len >= GNUNET_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }
  {
    char buf[len] GNUNET_ALIGN;
    struct GNUNET_MessageHeader *hdr;
    struct GNUNET_TUN_Layer2PacketHeader *tun;

    hdr = (struct GNUNET_MessageHeader *) buf;
    hdr->type = htons (GNUNET_MESSAGE_TYPE_VPN_HELPER);
    hdr->size = htons (len);
    tun = (struct GNUNET_TUN_Layer2PacketHeader*) &hdr[1];
    tun->flags = htons (0);
    switch (source_address->af)
    {
    case AF_INET:
      {
        struct GNUNET_TUN_IPv4Header *ipv4
          = (struct GNUNET_TUN_IPv4Header*) &tun[1];

        tun->proto = htons (ETH_P_IPV4);
        prepare_ipv4_packet (payload,
                             payload_length,
                             IPPROTO_TCP,
                             tcp_header,
                             source_address,
                             destination_address,
                             ipv4);
      }
      break;

    case AF_INET6:
      {
        struct GNUNET_TUN_IPv6Header *ipv6
          = (struct GNUNET_TUN_IPv6Header*) &tun[1];

        tun->proto = htons (ETH_P_IPV6);
        prepare_ipv6_packet (payload,
                             payload_length,
                             IPPROTO_TCP,
                             tcp_header,
                             source_address,
                             destination_address,
                             ipv6);
      }
      break;

    default:
      GNUNET_assert (0);
      break;
    }
    if (NULL != helper_handle)
      (void) GNUNET_HELPER_send (helper_handle,
                                 (const struct GNUNET_MessageHeader*) buf,
                                 GNUNET_YES,
                                 NULL,
                                 NULL);
  }
}


/**
 * Send an ICMP packet via the TUN interface.
 *
 * @param destination_address IP to use for the ICMP packet's destination
 * @param source_address IP to use for the ICMP packet's source
 * @param icmp_header ICMP header to send
 * @param payload payload of the ICMP packet (does NOT include ICMP header)
 * @param payload_length number of bytes of data in @a payload
 */
static void
send_icmp_packet_via_tun (const struct SocketAddress *destination_address,
                          const struct SocketAddress *source_address,
                          const struct GNUNET_TUN_IcmpHeader *icmp_header,
                          const void *payload, size_t payload_length)
{
  size_t len;
  struct GNUNET_TUN_IcmpHeader *icmp;

  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# ICMP packets sent via TUN"),
                            1, GNUNET_NO);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending packet with %u bytes ICMP payload via TUN\n",
              (unsigned int) payload_length);
  len = sizeof(struct GNUNET_MessageHeader) + sizeof(struct
                                                     GNUNET_TUN_Layer2PacketHeader);
  switch (destination_address->af)
  {
  case AF_INET:
    len += sizeof(struct GNUNET_TUN_IPv4Header);
    break;

  case AF_INET6:
    len += sizeof(struct GNUNET_TUN_IPv6Header);
    break;

  default:
    GNUNET_break (0);
    return;
  }
  len += sizeof(struct GNUNET_TUN_IcmpHeader);
  len += payload_length;
  if (len >= GNUNET_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }
  {
    char buf[len] GNUNET_ALIGN;
    struct GNUNET_MessageHeader *hdr;
    struct GNUNET_TUN_Layer2PacketHeader *tun;

    hdr = (struct GNUNET_MessageHeader *) buf;
    hdr->type = htons (GNUNET_MESSAGE_TYPE_VPN_HELPER);
    hdr->size = htons (len);
    tun = (struct GNUNET_TUN_Layer2PacketHeader*) &hdr[1];
    tun->flags = htons (0);
    switch (source_address->af)
    {
    case AF_INET:
      {
        struct GNUNET_TUN_IPv4Header *ipv4 = (struct
                                              GNUNET_TUN_IPv4Header*) &tun[1];

        tun->proto = htons (ETH_P_IPV4);
        GNUNET_TUN_initialize_ipv4_header (ipv4,
                                           IPPROTO_ICMP,
                                           sizeof(struct
                                                  GNUNET_TUN_IcmpHeader)
                                           + payload_length,
                                           &source_address->address.ipv4,
                                           &destination_address->address.ipv4);
        icmp = (struct GNUNET_TUN_IcmpHeader*) &ipv4[1];
      }
      break;

    case AF_INET6:
      {
        struct GNUNET_TUN_IPv6Header *ipv6 = (struct
                                              GNUNET_TUN_IPv6Header*) &tun[1];

        tun->proto = htons (ETH_P_IPV6);
        GNUNET_TUN_initialize_ipv6_header (ipv6,
                                           IPPROTO_ICMPV6,
                                           sizeof(struct
                                                  GNUNET_TUN_IcmpHeader)
                                           + payload_length,
                                           &source_address->address.ipv6,
                                           &destination_address->address.ipv6);
        icmp = (struct GNUNET_TUN_IcmpHeader*) &ipv6[1];
      }
      break;

    default:
      GNUNET_assert (0);
      break;
    }
    *icmp = *icmp_header;
    GNUNET_memcpy (&icmp[1],
                   payload,
                   payload_length);
    GNUNET_TUN_calculate_icmp_checksum (icmp,
                                        payload,
                                        payload_length);
    if (NULL != helper_handle)
      (void) GNUNET_HELPER_send (helper_handle,
                                 (const struct GNUNET_MessageHeader*) buf,
                                 GNUNET_YES,
                                 NULL, NULL);
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
                     uint8_t proto,
                     struct SocketAddress *local_address)
{
  local_address->af = af;
  local_address->proto = (uint8_t) proto;
  /* default "local" port range is often 32768--61000,
     so we pick a random value in that range */
  if (((af == AF_INET) && (proto == IPPROTO_ICMP)) ||
      ((af == AF_INET6) && (proto == IPPROTO_ICMPV6)))
    local_address->port = 0;
  else
    local_address->port
      = (uint16_t) 32768 + GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                                     28232);
  switch (af)
  {
  case AF_INET:
    {
      struct in_addr addr;
      struct in_addr mask;
      struct in_addr rnd;

      addr = exit_ipv4addr;
      mask = exit_ipv4mask;
      if (0 == ~mask.s_addr)
      {
        /* only one valid IP anyway */
        local_address->address.ipv4 = addr;
        return;
      }
      /* Given 192.168.0.1/255.255.0.0, we want a mask
         of '192.168.255.255', thus:  */
      mask.s_addr = addr.s_addr | ~mask.s_addr;
      /* Pick random IPv4 address within the subnet, except 'addr' or 'mask' itself */
      do
      {
        rnd.s_addr = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                               UINT32_MAX);
        local_address->address.ipv4.s_addr = (addr.s_addr | rnd.s_addr)
                                             & mask.s_addr;
      }
      while ((local_address->address.ipv4.s_addr == addr.s_addr) ||
             (local_address->address.ipv4.s_addr == mask.s_addr));
    }
    break;

  case AF_INET6:
    {
      struct in6_addr addr;
      struct in6_addr mask;
      struct in6_addr rnd;
      int i;

      addr = exit_ipv6addr;
      GNUNET_assert (ipv6prefix < 128);
      if (ipv6prefix == 127)
      {
        /* only one valid IP anyway */
        local_address->address.ipv6 = addr;
        return;
      }
      /* Given ABCD::/96, we want a mask of 'ABCD::FFFF:FFFF,
         thus: */
      mask = addr;
      for (i = 127; i >= ipv6prefix; i--)
        mask.s6_addr[i / 8] |= (1 << (i % 8));

      /* Pick random IPv6 address within the subnet, except 'addr' or 'mask' itself */
      do
      {
        for (i = 0; i < 16; i++)
        {
          rnd.s6_addr[i] = (unsigned char) GNUNET_CRYPTO_random_u32 (
            GNUNET_CRYPTO_QUALITY_WEAK,
            256);
          local_address->address.ipv6.s6_addr[i]
            = (addr.s6_addr[i] | rnd.s6_addr[i]) & mask.s6_addr[i];
        }
      }
      while ((0 == GNUNET_memcmp (&local_address->address.ipv6,
                                  &addr)) ||
             (0 == GNUNET_memcmp (&local_address->address.ipv6,
                                  &mask)));
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
 * connection / correct cadet channel.  This function generates
 * a "fresh" source IP and source port number for a connection
 * After picking a good source address, this function sets up
 * the state in the 'connections_map' and 'connections_heap'
 * to allow finding the state when needed later.  The function
 * also makes sure that we remain within memory limits by
 * cleaning up 'old' states.
 *
 * @param state skeleton state to setup a record for; should
 *              'state->specifics.tcp_udp.ri.remote_address' filled in so that
 *              this code can determine which AF/protocol is
 *              going to be used (the 'channel' should also
 *              already be set); after calling this function,
 *              heap_node and the local_address will be
 *              also initialized (heap_node != NULL can be
 *              used to test if a state has been fully setup).
 */
static void
setup_state_record (struct ChannelState *state)
{
  struct GNUNET_HashCode key;
  struct ChannelState *s;

  /* generate fresh, unique address */
  do
  {
    if (NULL == state->specifics.tcp_udp.serv)
      setup_fresh_address (state->specifics.tcp_udp.ri.remote_address.af,
                           state->specifics.tcp_udp.ri.remote_address.proto,
                           &state->specifics.tcp_udp.ri.local_address);
    else
      setup_fresh_address (state->specifics.tcp_udp.serv->address.af,
                           state->specifics.tcp_udp.serv->address.proto,
                           &state->specifics.tcp_udp.ri.local_address);
  }
  while (NULL !=
         get_redirect_state (state->specifics.tcp_udp.ri.remote_address.af,
                             state->specifics.tcp_udp.ri.remote_address.proto,
                             &state->specifics.tcp_udp.ri.remote_address.address,
                             state->specifics.tcp_udp.ri.remote_address.port,
                             &state->specifics.tcp_udp.ri.local_address.address,
                             state->specifics.tcp_udp.ri.local_address.port,
                             &key));
  {
    char buf[INET6_ADDRSTRLEN];
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Picked local address %s:%u for new connection\n",
                inet_ntop (state->specifics.tcp_udp.ri.local_address.af,
                           &state->specifics.tcp_udp.ri.local_address.address,
                           buf,
                           sizeof(buf)),
                (unsigned int) state->specifics.tcp_udp.ri.local_address.port);
  }
  state->specifics.tcp_udp.state_key = key;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap_put (connections_map,
                                                    &key, state,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  state->specifics.tcp_udp.heap_node
    = GNUNET_CONTAINER_heap_insert (connections_heap,
                                    state,
                                    GNUNET_TIME_absolute_get ().abs_value_us);
  while (GNUNET_CONTAINER_heap_get_size (connections_heap) > max_connections)
  {
    s = GNUNET_CONTAINER_heap_remove_root (connections_heap);
    GNUNET_assert (state != s);
    s->specifics.tcp_udp.heap_node = NULL;
    GNUNET_CADET_channel_destroy (s->channel);
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multihashmap_remove (connections_map,
                                                         &s->specifics.tcp_udp.
                                                         state_key,
                                                         s));
    GNUNET_free (s);
  }
}


/**
 * Send a UDP packet via the TUN interface.
 *
 * @param destination_address IP and port to use for the UDP packet's destination
 * @param source_address IP and port to use for the UDP packet's source
 * @param payload payload of the UDP packet (does NOT include UDP header)
 * @param payload_length number of bytes of data in @a payload
 */
static void
send_udp_packet_via_tun (const struct SocketAddress *destination_address,
                         const struct SocketAddress *source_address,
                         const void *payload, size_t payload_length)
{
  size_t len;

  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# UDP packets sent via TUN"),
                            1, GNUNET_NO);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending packet with %u bytes UDP payload via TUN\n",
              (unsigned int) payload_length);
  len = sizeof(struct GNUNET_MessageHeader) + sizeof(struct
                                                     GNUNET_TUN_Layer2PacketHeader);
  switch (source_address->af)
  {
  case AF_INET:
    len += sizeof(struct GNUNET_TUN_IPv4Header);
    break;

  case AF_INET6:
    len += sizeof(struct GNUNET_TUN_IPv6Header);
    break;

  default:
    GNUNET_break (0);
    return;
  }
  len += sizeof(struct GNUNET_TUN_UdpHeader);
  len += payload_length;
  if (len >= GNUNET_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }
  {
    char buf[len] GNUNET_ALIGN;
    struct GNUNET_MessageHeader *hdr;
    struct GNUNET_TUN_Layer2PacketHeader *tun;

    hdr = (struct GNUNET_MessageHeader *) buf;
    hdr->type = htons (GNUNET_MESSAGE_TYPE_VPN_HELPER);
    hdr->size = htons (len);
    tun = (struct GNUNET_TUN_Layer2PacketHeader*) &hdr[1];
    tun->flags = htons (0);
    switch (source_address->af)
    {
    case AF_INET:
      {
        struct GNUNET_TUN_IPv4Header *ipv4 = (struct
                                              GNUNET_TUN_IPv4Header*) &tun[1];

        tun->proto = htons (ETH_P_IPV4);
        prepare_ipv4_packet (payload,
                             payload_length,
                             IPPROTO_UDP,
                             NULL,
                             source_address,
                             destination_address,
                             ipv4);
      }
      break;

    case AF_INET6:
      {
        struct GNUNET_TUN_IPv6Header *ipv6 = (struct
                                              GNUNET_TUN_IPv6Header*) &tun[1];

        tun->proto = htons (ETH_P_IPV6);
        prepare_ipv6_packet (payload,
                             payload_length,
                             IPPROTO_UDP,
                             NULL,
                             source_address,
                             destination_address,
                             ipv6);
      }
      break;

    default:
      GNUNET_assert (0);
      break;
    }
    if (NULL != helper_handle)
      (void) GNUNET_HELPER_send (helper_handle,
                                 (const struct GNUNET_MessageHeader*) buf,
                                 GNUNET_YES,
                                 NULL, NULL);
  }
}


/**
 * Check a request to forward UDP data to the Internet via this peer.
 *
 * @param cls our `struct ChannelState *`
 * @param msg the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
check_udp_remote (void *cls,
                  const struct GNUNET_EXIT_UdpInternetMessage *msg)
{
  struct ChannelState *state = cls;

  if (GNUNET_YES == state->is_dns)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Process a request to forward UDP data to the Internet via this peer.
 *
 * @param cls our `struct ChannelState *`
 * @param msg the actual message
 */
static void
handle_udp_remote (void *cls,
                   const struct GNUNET_EXIT_UdpInternetMessage *msg)
{
  struct ChannelState *state = cls;
  uint16_t pkt_len = ntohs (msg->header.size) - sizeof(struct
                                                       GNUNET_EXIT_UdpInternetMessage);
  const struct in_addr *v4;
  const struct in6_addr *v6;
  const void *payload;
  int af;

  if (GNUNET_SYSERR == state->is_dns)
  {
    /* channel is UDP/TCP from now on */
    state->is_dns = GNUNET_NO;
  }
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# Bytes received from CADET"),
                            pkt_len, GNUNET_NO);
  GNUNET_STATISTICS_update (stats,
                            gettext_noop (
                              "# UDP IP-exit requests received via cadet"),
                            1, GNUNET_NO);
  af = (int) ntohl (msg->af);
  state->specifics.tcp_udp.ri.remote_address.af = af;
  switch (af)
  {
  case AF_INET:
    if (pkt_len < sizeof(struct in_addr))
    {
      GNUNET_break_op (0);
      return;
    }
    if (! ipv4_exit)
    {
      GNUNET_break_op (0);
      return;
    }
    v4 = (const struct in_addr*) &msg[1];
    payload = &v4[1];
    pkt_len -= sizeof(struct in_addr);
    state->specifics.tcp_udp.ri.remote_address.address.ipv4 = *v4;
    break;

  case AF_INET6:
    if (pkt_len < sizeof(struct in6_addr))
    {
      GNUNET_break_op (0);
      return;
    }
    if (! ipv6_exit)
    {
      GNUNET_break_op (0);
      return;
    }
    v6 = (const struct in6_addr*) &msg[1];
    payload = &v6[1];
    pkt_len -= sizeof(struct in6_addr);
    state->specifics.tcp_udp.ri.remote_address.address.ipv6 = *v6;
    break;

  default:
    GNUNET_break_op (0);
    return;
  }
  {
    char buf[INET6_ADDRSTRLEN];
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received data from %s for forwarding to UDP %s:%u\n",
                GNUNET_i2s (&state->peer),
                inet_ntop (af,
                           &state->specifics.tcp_udp.ri.remote_address.address,
                           buf, sizeof(buf)),
                (unsigned int) ntohs (msg->destination_port));
  }
  state->specifics.tcp_udp.ri.remote_address.proto = IPPROTO_UDP;
  state->specifics.tcp_udp.ri.remote_address.port = msg->destination_port;
  if (NULL == state->specifics.tcp_udp.heap_node)
    setup_state_record (state);
  if (0 != ntohs (msg->source_port))
    state->specifics.tcp_udp.ri.local_address.port = msg->source_port;
  send_udp_packet_via_tun (&state->specifics.tcp_udp.ri.remote_address,
                           &state->specifics.tcp_udp.ri.local_address,
                           payload,
                           pkt_len);
  GNUNET_CADET_receive_done (state->channel);
}


/**
 * Check a request via cadet to send a request to a UDP service
 * offered by this system.
 *
 * @param cls our `struct ChannelState *`
 * @param msg the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
check_udp_service (void *cls,
                   const struct GNUNET_EXIT_UdpServiceMessage *msg)
{
  struct ChannelState *state = cls;

  if (NULL == state->specifics.tcp_udp.serv)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Process a request via cadet to send a request to a UDP service
 * offered by this system.
 *
 * @param cls our `struct ChannelState *`
 * @param msg the actual message
 */
static void
handle_udp_service (void *cls,
                    const struct GNUNET_EXIT_UdpServiceMessage *msg)
{
  struct ChannelState *state = cls;
  uint16_t pkt_len = ntohs (msg->header.size) - sizeof(struct
                                                       GNUNET_EXIT_UdpServiceMessage);

  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# Bytes received from CADET"),
                            pkt_len, GNUNET_NO);
  GNUNET_STATISTICS_update (stats,
                            gettext_noop (
                              "# UDP service requests received via cadet"),
                            1, GNUNET_NO);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received data from %s for forwarding to UDP service %s on port %u\n",
       GNUNET_i2s (&state->peer),
       GNUNET_h2s (&state->specifics.tcp_udp.serv->descriptor),
       (unsigned int) ntohs (msg->destination_port));
  setup_state_record (state);
  if (0 != ntohs (msg->source_port))
    state->specifics.tcp_udp.ri.local_address.port = msg->source_port;
  send_udp_packet_via_tun (&state->specifics.tcp_udp.ri.remote_address,
                           &state->specifics.tcp_udp.ri.local_address,
                           &msg[1],
                           pkt_len);
  GNUNET_CADET_receive_done (state->channel);
}


/**
 * Process a request via cadet to send a request to a TCP service
 * offered by this system.
 *
 * @param cls our `struct ChannelState *`
 * @param start the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static void
handle_tcp_service (void *cls,
                    const struct GNUNET_EXIT_TcpServiceStartMessage *start)
{
  struct ChannelState *state = cls;
  uint16_t pkt_len = ntohs (start->header.size) - sizeof(struct
                                                         GNUNET_EXIT_TcpServiceStartMessage);

  if (GNUNET_SYSERR == state->is_dns)
  {
    /* channel is UDP/TCP from now on */
    state->is_dns = GNUNET_NO;
  }
  GNUNET_STATISTICS_update (stats,
                            gettext_noop (
                              "# TCP service creation requests received via cadet"),
                            1,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# Bytes received from CADET"),
                            pkt_len,
                            GNUNET_NO);
  GNUNET_break_op (ntohl (start->reserved) == 0);
  /* setup fresh connection */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received data from %s for forwarding to TCP service %s on port %u\n",
              GNUNET_i2s (&state->peer),
              GNUNET_h2s (&state->specifics.tcp_udp.serv->descriptor),
              (unsigned int) ntohs (start->tcp_header.destination_port));
  setup_state_record (state);
  send_tcp_packet_via_tun (&state->specifics.tcp_udp.ri.remote_address,
                           &state->specifics.tcp_udp.ri.local_address,
                           &start->tcp_header,
                           &start[1],
                           pkt_len);
  GNUNET_CADET_receive_done (state->channel);
}


/**
 * Check a request to forward TCP data to the Internet via this peer.
 *
 * @param cls our `struct ChannelState *`
 * @param start the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
check_tcp_remote (void *cls,
                  const struct GNUNET_EXIT_TcpInternetStartMessage *start)
{
  struct ChannelState *state = cls;

  if (NULL == state)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (GNUNET_YES == state->is_dns)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if ((NULL != state->specifics.tcp_udp.serv) ||
      (NULL != state->specifics.tcp_udp.heap_node))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (start->tcp_header.off * 4 < sizeof(struct GNUNET_TUN_TcpHeader))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Process a request to forward TCP data to the Internet via this peer.
 *
 * @param cls our `struct ChannelState *`
 * @param start the actual message
 */
static void
handle_tcp_remote (void *cls,
                   const struct GNUNET_EXIT_TcpInternetStartMessage *start)
{
  struct ChannelState *state = cls;
  uint16_t pkt_len = ntohs (start->header.size) - sizeof(struct
                                                         GNUNET_EXIT_TcpInternetStartMessage);
  const struct in_addr *v4;
  const struct in6_addr *v6;
  const void *payload;
  int af;

  if (GNUNET_SYSERR == state->is_dns)
  {
    /* channel is UDP/TCP from now on */
    state->is_dns = GNUNET_NO;
  }
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# Bytes received from CADET"),
                            pkt_len, GNUNET_NO);
  GNUNET_STATISTICS_update (stats,
                            gettext_noop (
                              "# TCP IP-exit creation requests received via cadet"),
                            1, GNUNET_NO);
  af = (int) ntohl (start->af);
  state->specifics.tcp_udp.ri.remote_address.af = af;
  switch (af)
  {
  case AF_INET:
    if (pkt_len < sizeof(struct in_addr))
    {
      GNUNET_break_op (0);
      return;
    }
    if (! ipv4_exit)
    {
      GNUNET_break_op (0);
      return;
    }
    v4 = (const struct in_addr*) &start[1];
    payload = &v4[1];
    pkt_len -= sizeof(struct in_addr);
    state->specifics.tcp_udp.ri.remote_address.address.ipv4 = *v4;
    break;

  case AF_INET6:
    if (pkt_len < sizeof(struct in6_addr))
    {
      GNUNET_break_op (0);
      return;
    }
    if (! ipv6_exit)
    {
      GNUNET_break_op (0);
      return;
    }
    v6 = (const struct in6_addr*) &start[1];
    payload = &v6[1];
    pkt_len -= sizeof(struct in6_addr);
    state->specifics.tcp_udp.ri.remote_address.address.ipv6 = *v6;
    break;

  default:
    GNUNET_break_op (0);
    return;
  }
  {
    char buf[INET6_ADDRSTRLEN];
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received payload from %s for existing TCP stream to %s:%u\n",
                GNUNET_i2s (&state->peer),
                inet_ntop (af,
                           &state->specifics.tcp_udp.ri.remote_address.address,
                           buf, sizeof(buf)),
                (unsigned int) ntohs (start->tcp_header.destination_port));
  }
  state->specifics.tcp_udp.ri.remote_address.proto = IPPROTO_TCP;
  state->specifics.tcp_udp.ri.remote_address.port = ntohs (
    start->tcp_header.destination_port);
  setup_state_record (state);
  send_tcp_packet_via_tun (&state->specifics.tcp_udp.ri.remote_address,
                           &state->specifics.tcp_udp.ri.local_address,
                           &start->tcp_header,
                           payload,
                           pkt_len);
  GNUNET_CADET_receive_done (state->channel);
}


/**
 * Check a request to forward TCP data on an established
 * connection via this peer.
 *
 * @param cls our `struct ChannelState *`
 * @param message the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
check_tcp_data (void *cls,
                const struct GNUNET_EXIT_TcpDataMessage *data)
{
  struct ChannelState *state = cls;

  if ((NULL == state) ||
      (NULL == state->specifics.tcp_udp.heap_node))
  {
    /* connection should have been up! */
    GNUNET_STATISTICS_update (stats,
                              gettext_noop (
                                "# TCP DATA requests dropped (no session)"),
                              1, GNUNET_NO);
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (data->tcp_header.off * 4 < sizeof(struct GNUNET_TUN_TcpHeader))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (GNUNET_YES == state->is_dns)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Process a request to forward TCP data on an established
 * connection via this peer.
 *
 * @param cls our `struct ChannelState *`
 * @param message the actual message
 */
static void
handle_tcp_data (void *cls,
                 const struct GNUNET_EXIT_TcpDataMessage *data)
{
  struct ChannelState *state = cls;
  uint16_t pkt_len = ntohs (data->header.size) - sizeof(struct
                                                        GNUNET_EXIT_TcpDataMessage);

  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# Bytes received from CADET"),
                            pkt_len, GNUNET_NO);
  GNUNET_STATISTICS_update (stats,
                            gettext_noop (
                              "# TCP data requests received via cadet"),
                            1, GNUNET_NO);
  if (GNUNET_SYSERR == state->is_dns)
  {
    /* channel is UDP/TCP from now on */
    state->is_dns = GNUNET_NO;
  }

  GNUNET_break_op (ntohl (data->reserved) == 0);
  {
    char buf[INET6_ADDRSTRLEN];
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received additional %u bytes of data from %s for TCP stream to %s:%u\n",
                pkt_len,
                GNUNET_i2s (&state->peer),
                inet_ntop (state->specifics.tcp_udp.ri.remote_address.af,
                           &state->specifics.tcp_udp.ri.remote_address.address,
                           buf, sizeof(buf)),
                (unsigned int) state->specifics.tcp_udp.ri.remote_address.port);
  }

  send_tcp_packet_via_tun (&state->specifics.tcp_udp.ri.remote_address,
                           &state->specifics.tcp_udp.ri.local_address,
                           &data->tcp_header,
                           &data[1], pkt_len);
  GNUNET_CADET_receive_done (state->channel);
}


/**
 * Synthesize a plausible ICMP payload for an ICMPv4 error
 * response on the given channel.
 *
 * @param state channel information
 * @param ipp IPv6 header to fill in (ICMP payload)
 * @param udp "UDP" header to fill in (ICMP payload); might actually
 *            also be the first 8 bytes of the TCP header
 */
static void
make_up_icmpv4_payload (struct ChannelState *state,
                        struct GNUNET_TUN_IPv4Header *ipp,
                        struct GNUNET_TUN_UdpHeader *udp)
{
  GNUNET_TUN_initialize_ipv4_header (ipp,
                                     state->specifics.tcp_udp.ri.remote_address.
                                     proto,
                                     sizeof(struct GNUNET_TUN_TcpHeader),
                                     &state->specifics.tcp_udp.ri.remote_address
                                     .address.ipv4,
                                     &state->specifics.tcp_udp.ri.local_address.
                                     address.ipv4);
  udp->source_port = htons (state->specifics.tcp_udp.ri.remote_address.port);
  udp->destination_port = htons (
    state->specifics.tcp_udp.ri.local_address.port);
  udp->len = htons (0);
  udp->crc = htons (0);
}


/**
 * Synthesize a plausible ICMP payload for an ICMPv6 error
 * response on the given channel.
 *
 * @param state channel information
 * @param ipp IPv6 header to fill in (ICMP payload)
 * @param udp "UDP" header to fill in (ICMP payload); might actually
 *            also be the first 8 bytes of the TCP header
 */
static void
make_up_icmpv6_payload (struct ChannelState *state,
                        struct GNUNET_TUN_IPv6Header *ipp,
                        struct GNUNET_TUN_UdpHeader *udp)
{
  GNUNET_TUN_initialize_ipv6_header (ipp,
                                     state->specifics.tcp_udp.ri.remote_address.
                                     proto,
                                     sizeof(struct GNUNET_TUN_TcpHeader),
                                     &state->specifics.tcp_udp.ri.remote_address
                                     .address.ipv6,
                                     &state->specifics.tcp_udp.ri.local_address.
                                     address.ipv6);
  udp->source_port = htons (state->specifics.tcp_udp.ri.remote_address.port);
  udp->destination_port = htons (
    state->specifics.tcp_udp.ri.local_address.port);
  udp->len = htons (0);
  udp->crc = htons (0);
}


/**
 * Check a request to forward ICMP data to the Internet via this peer.
 *
 * @param cls our `struct ChannelState *`
 * @param msg the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
check_icmp_remote (void *cls,
                   const struct GNUNET_EXIT_IcmpInternetMessage *msg)
{
  struct ChannelState *state = cls;

  if (GNUNET_YES == state->is_dns)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Process a request to forward ICMP data to the Internet via this peer.
 *
 * @param cls our `struct ChannelState *`
 * @param msg the actual message
 */
static void
handle_icmp_remote (void *cls,
                    const struct GNUNET_EXIT_IcmpInternetMessage *msg)
{
  struct ChannelState *state = cls;
  uint16_t pkt_len = ntohs (msg->header.size) - sizeof(struct
                                                       GNUNET_EXIT_IcmpInternetMessage);
  const struct in_addr *v4;
  const struct in6_addr *v6;
  const void *payload;
  char buf[sizeof(struct GNUNET_TUN_IPv6Header) + 8] GNUNET_ALIGN;
  int af;

  if (GNUNET_SYSERR == state->is_dns)
  {
    /* channel is UDP/TCP from now on */
    state->is_dns = GNUNET_NO;
  }
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# Bytes received from CADET"),
                            pkt_len, GNUNET_NO);
  GNUNET_STATISTICS_update (stats,
                            gettext_noop (
                              "# ICMP IP-exit requests received via cadet"),
                            1, GNUNET_NO);

  af = (int) ntohl (msg->af);
  if ((NULL != state->specifics.tcp_udp.heap_node) &&
      (af != state->specifics.tcp_udp.ri.remote_address.af))
  {
    /* other peer switched AF on this channel; not allowed */
    GNUNET_break_op (0);
    return;
  }

  switch (af)
  {
  case AF_INET:
    if (pkt_len < sizeof(struct in_addr))
    {
      GNUNET_break_op (0);
      return;
    }
    if (! ipv4_exit)
    {
      GNUNET_break_op (0);
      return;
    }
    v4 = (const struct in_addr*) &msg[1];
    payload = &v4[1];
    pkt_len -= sizeof(struct in_addr);
    state->specifics.tcp_udp.ri.remote_address.address.ipv4 = *v4;
    if (NULL == state->specifics.tcp_udp.heap_node)
    {
      state->specifics.tcp_udp.ri.remote_address.af = af;
      state->specifics.tcp_udp.ri.remote_address.proto = IPPROTO_ICMP;
      setup_state_record (state);
    }
    /* check that ICMP type is something we want to support
       and possibly make up payload! */
    switch (msg->icmp_header.type)
    {
    case GNUNET_TUN_ICMPTYPE_ECHO_REPLY:
    case GNUNET_TUN_ICMPTYPE_ECHO_REQUEST:
      break;

    case GNUNET_TUN_ICMPTYPE_DESTINATION_UNREACHABLE:
    case GNUNET_TUN_ICMPTYPE_SOURCE_QUENCH:
    case GNUNET_TUN_ICMPTYPE_TIME_EXCEEDED:
      if (0 != pkt_len)
      {
        GNUNET_break_op (0);
        return;
      }
      /* make up payload */
      {
        struct GNUNET_TUN_IPv4Header *ipp = (struct
                                             GNUNET_TUN_IPv4Header *) buf;
        struct GNUNET_TUN_UdpHeader *udp = (struct
                                            GNUNET_TUN_UdpHeader *) &ipp[1];

        GNUNET_assert (8 == sizeof(struct GNUNET_TUN_UdpHeader));
        pkt_len = sizeof(struct GNUNET_TUN_IPv4Header) + 8;
        make_up_icmpv4_payload (state,
                                ipp,
                                udp);
        payload = ipp;
      }
      break;

    default:
      GNUNET_break_op (0);
      GNUNET_STATISTICS_update (stats,
                                gettext_noop (
                                  "# ICMPv4 packets dropped (type not allowed)"),
                                1, GNUNET_NO);
      return;
    }
    /* end AF_INET */
    break;

  case AF_INET6:
    if (pkt_len < sizeof(struct in6_addr))
    {
      GNUNET_break_op (0);
      return;
    }
    if (! ipv6_exit)
    {
      GNUNET_break_op (0);
      return;
    }
    v6 = (const struct in6_addr*) &msg[1];
    payload = &v6[1];
    pkt_len -= sizeof(struct in6_addr);
    state->specifics.tcp_udp.ri.remote_address.address.ipv6 = *v6;
    if (NULL == state->specifics.tcp_udp.heap_node)
    {
      state->specifics.tcp_udp.ri.remote_address.af = af;
      state->specifics.tcp_udp.ri.remote_address.proto = IPPROTO_ICMPV6;
      setup_state_record (state);
    }
    /* check that ICMP type is something we want to support
       and possibly make up payload! */
    switch (msg->icmp_header.type)
    {
    case GNUNET_TUN_ICMPTYPE6_ECHO_REPLY:
    case GNUNET_TUN_ICMPTYPE6_ECHO_REQUEST:
      break;

    case GNUNET_TUN_ICMPTYPE6_DESTINATION_UNREACHABLE:
    case GNUNET_TUN_ICMPTYPE6_PACKET_TOO_BIG:
    case GNUNET_TUN_ICMPTYPE6_TIME_EXCEEDED:
    case GNUNET_TUN_ICMPTYPE6_PARAMETER_PROBLEM:
      if (0 != pkt_len)
      {
        GNUNET_break_op (0);
        return;
      }
      /* make up payload */
      {
        struct GNUNET_TUN_IPv6Header *ipp = (struct
                                             GNUNET_TUN_IPv6Header *) buf;
        struct GNUNET_TUN_UdpHeader *udp = (struct
                                            GNUNET_TUN_UdpHeader *) &ipp[1];

        GNUNET_assert (8 == sizeof(struct GNUNET_TUN_UdpHeader));
        pkt_len = sizeof(struct GNUNET_TUN_IPv6Header) + 8;
        make_up_icmpv6_payload (state,
                                ipp,
                                udp);
        payload = ipp;
      }
      break;

    default:
      GNUNET_break_op (0);
      GNUNET_STATISTICS_update (stats,
                                gettext_noop (
                                  "# ICMPv6 packets dropped (type not allowed)"),
                                1, GNUNET_NO);
      return;
    }
    /* end AF_INET6 */
    break;

  default:
    /* bad AF */
    GNUNET_break_op (0);
    return;
  }

  {
    char buf[INET6_ADDRSTRLEN];
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received ICMP data from %s for forwarding to %s\n",
                GNUNET_i2s (&state->peer),
                inet_ntop (af,
                           &state->specifics.tcp_udp.ri.remote_address.address,
                           buf, sizeof(buf)));
  }
  send_icmp_packet_via_tun (&state->specifics.tcp_udp.ri.remote_address,
                            &state->specifics.tcp_udp.ri.local_address,
                            &msg->icmp_header,
                            payload, pkt_len);
  GNUNET_CADET_receive_done (state->channel);
}


/**
 * Setup ICMP payload for ICMP error messages. Called
 * for both IPv4 and IPv6 addresses.
 *
 * @param state context for creating the IP Packet
 * @param buf where to create the payload, has at least
 *       sizeof (struct GNUNET_TUN_IPv6Header) + 8 bytes
 * @return number of bytes of payload we created in buf
 */
static uint16_t
make_up_icmp_service_payload (struct ChannelState *state,
                              char *buf)
{
  switch (state->specifics.tcp_udp.serv->address.af)
  {
  case AF_INET:
    {
      struct GNUNET_TUN_IPv4Header *ipv4;
      struct GNUNET_TUN_UdpHeader *udp;

      ipv4 = (struct GNUNET_TUN_IPv4Header *) buf;
      udp = (struct GNUNET_TUN_UdpHeader *) &ipv4[1];
      make_up_icmpv4_payload (state,
                              ipv4,
                              udp);
      GNUNET_assert (8 == sizeof(struct GNUNET_TUN_UdpHeader));
      return sizeof(struct GNUNET_TUN_IPv4Header) + 8;
    }
    break;

  case AF_INET6:
    {
      struct GNUNET_TUN_IPv6Header *ipv6;
      struct GNUNET_TUN_UdpHeader *udp;

      ipv6 = (struct GNUNET_TUN_IPv6Header *) buf;
      udp = (struct GNUNET_TUN_UdpHeader *) &ipv6[1];
      make_up_icmpv6_payload (state,
                              ipv6,
                              udp);
      GNUNET_assert (8 == sizeof(struct GNUNET_TUN_UdpHeader));
      return sizeof(struct GNUNET_TUN_IPv6Header) + 8;
    }
    break;

  default:
    GNUNET_break (0);
  }
  return 0;
}


/**
 * Check a request via cadet to send ICMP data to a service
 * offered by this system.
 *
 * @param cls our `struct ChannelState *`
 * @param msg the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
check_icmp_service (void *cls,
                    const struct GNUNET_EXIT_IcmpServiceMessage *msg)
{
  struct ChannelState *state = cls;

  if (GNUNET_YES == state->is_dns)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (NULL == state->specifics.tcp_udp.serv)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Process a request via cadet to send ICMP data to a service
 * offered by this system.
 *
 * @param cls our `struct ChannelState *`
 * @param msg the actual message
 */
static void
handle_icmp_service (void *cls,
                     const struct GNUNET_EXIT_IcmpServiceMessage *msg)
{
  struct ChannelState *state = cls;
  uint16_t pkt_len = ntohs (msg->header.size) - sizeof(struct
                                                       GNUNET_EXIT_IcmpServiceMessage);
  struct GNUNET_TUN_IcmpHeader icmp;
  char buf[sizeof(struct GNUNET_TUN_IPv6Header) + 8] GNUNET_ALIGN;
  const void *payload;

  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# Bytes received from CADET"),
                            pkt_len, GNUNET_NO);
  GNUNET_STATISTICS_update (stats,
                            gettext_noop (
                              "# ICMP service requests received via cadet"),
                            1, GNUNET_NO);
  /* check that we got at least a valid header */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received data from %s for forwarding to ICMP service %s\n",
              GNUNET_i2s (&state->peer),
              GNUNET_h2s (&state->specifics.tcp_udp.serv->descriptor));
  icmp = msg->icmp_header;
  payload = &msg[1];
  state->specifics.tcp_udp.ri.remote_address
    = state->specifics.tcp_udp.serv->address;
  setup_state_record (state);

  /* check that ICMP type is something we want to support,
     perform ICMP PT if needed ans possibly make up payload */
  switch (msg->af)
  {
  case AF_INET:
    switch (msg->icmp_header.type)
    {
    case GNUNET_TUN_ICMPTYPE_ECHO_REPLY:
      if (state->specifics.tcp_udp.serv->address.af == AF_INET6)
        icmp.type = GNUNET_TUN_ICMPTYPE6_ECHO_REPLY;
      break;

    case GNUNET_TUN_ICMPTYPE_ECHO_REQUEST:
      if (state->specifics.tcp_udp.serv->address.af == AF_INET6)
        icmp.type = GNUNET_TUN_ICMPTYPE6_ECHO_REQUEST;
      break;

    case GNUNET_TUN_ICMPTYPE_DESTINATION_UNREACHABLE:
      if (state->specifics.tcp_udp.serv->address.af == AF_INET6)
        icmp.type = GNUNET_TUN_ICMPTYPE6_DESTINATION_UNREACHABLE;
      if (0 != pkt_len)
      {
        GNUNET_break_op (0);
        return;
      }
      payload = buf;
      pkt_len = make_up_icmp_service_payload (state, buf);
      break;

    case GNUNET_TUN_ICMPTYPE_TIME_EXCEEDED:
      if (state->specifics.tcp_udp.serv->address.af == AF_INET6)
        icmp.type = GNUNET_TUN_ICMPTYPE6_TIME_EXCEEDED;
      if (0 != pkt_len)
      {
        GNUNET_break_op (0);
        return;
      }
      payload = buf;
      pkt_len = make_up_icmp_service_payload (state, buf);
      break;

    case GNUNET_TUN_ICMPTYPE_SOURCE_QUENCH:
      if (state->specifics.tcp_udp.serv->address.af == AF_INET6)
      {
        GNUNET_STATISTICS_update (stats,
                                  gettext_noop (
                                    "# ICMPv4 packets dropped (impossible PT to v6)"),
                                  1, GNUNET_NO);
        return;
      }
      if (0 != pkt_len)
      {
        GNUNET_break_op (0);
        return;
      }
      payload = buf;
      pkt_len = make_up_icmp_service_payload (state, buf);
      break;

    default:
      GNUNET_break_op (0);
      GNUNET_STATISTICS_update (stats,
                                gettext_noop (
                                  "# ICMPv4 packets dropped (type not allowed)"),
                                1, GNUNET_NO);
      return;
    }
    /* end of AF_INET */
    break;

  case AF_INET6:
    switch (msg->icmp_header.type)
    {
    case GNUNET_TUN_ICMPTYPE6_ECHO_REPLY:
      if (state->specifics.tcp_udp.serv->address.af == AF_INET)
        icmp.type = GNUNET_TUN_ICMPTYPE_ECHO_REPLY;
      break;

    case GNUNET_TUN_ICMPTYPE6_ECHO_REQUEST:
      if (state->specifics.tcp_udp.serv->address.af == AF_INET)
        icmp.type = GNUNET_TUN_ICMPTYPE_ECHO_REQUEST;
      break;

    case GNUNET_TUN_ICMPTYPE6_DESTINATION_UNREACHABLE:
      if (state->specifics.tcp_udp.serv->address.af == AF_INET)
        icmp.type = GNUNET_TUN_ICMPTYPE_DESTINATION_UNREACHABLE;
      if (0 != pkt_len)
      {
        GNUNET_break_op (0);
        return;
      }
      payload = buf;
      pkt_len = make_up_icmp_service_payload (state, buf);
      break;

    case GNUNET_TUN_ICMPTYPE6_TIME_EXCEEDED:
      if (state->specifics.tcp_udp.serv->address.af == AF_INET)
        icmp.type = GNUNET_TUN_ICMPTYPE_TIME_EXCEEDED;
      if (0 != pkt_len)
      {
        GNUNET_break_op (0);
        return;
      }
      payload = buf;
      pkt_len = make_up_icmp_service_payload (state, buf);
      break;

    case GNUNET_TUN_ICMPTYPE6_PACKET_TOO_BIG:
    case GNUNET_TUN_ICMPTYPE6_PARAMETER_PROBLEM:
      if (state->specifics.tcp_udp.serv->address.af == AF_INET)
      {
        GNUNET_STATISTICS_update (stats,
                                  gettext_noop (
                                    "# ICMPv6 packets dropped (impossible PT to v4)"),
                                  1, GNUNET_NO);
        return;
      }
      if (0 != pkt_len)
      {
        GNUNET_break_op (0);
        return;
      }
      payload = buf;
      pkt_len = make_up_icmp_service_payload (state, buf);
      break;

    default:
      GNUNET_break_op (0);
      GNUNET_STATISTICS_update (stats,
                                gettext_noop (
                                  "# ICMPv6 packets dropped (type not allowed)"),
                                1, GNUNET_NO);
      return;
    }
    /* end of AF_INET6 */
    break;

  default:
    GNUNET_break_op (0);
    return;
  }

  send_icmp_packet_via_tun (&state->specifics.tcp_udp.ri.remote_address,
                            &state->specifics.tcp_udp.ri.local_address,
                            &icmp,
                            payload,
                            pkt_len);
  GNUNET_CADET_receive_done (state->channel);
}


/**
 * Free memory associated with a service record.
 *
 * @param cls unused
 * @param key service descriptor
 * @param value service record to free
 * @return #GNUNET_OK
 */
static int
free_service_record (void *cls,
                     const struct GNUNET_HashCode *key,
                     void *value)
{
  struct LocalService *service = value;

  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (services,
                                                       key,
                                                       service));
  GNUNET_CADET_close_port (service->port);
  GNUNET_free_non_null (service->name);
  GNUNET_free (service);
  return GNUNET_OK;
}


/**
 * Callback from CADET for new channels.
 *
 * @param cls closure
 * @param channel new handle to the channel
 * @param initiator peer that started the channel
 * @return initial channel context for the channel
 */
static void *
new_service_channel (void *cls,
                     struct GNUNET_CADET_Channel *channel,
                     const struct GNUNET_PeerIdentity *initiator)
{
  struct LocalService *ls = cls;
  struct ChannelState *s = GNUNET_new (struct ChannelState);

  s->peer = *initiator;
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# Inbound CADET channels created"),
                            1,
                            GNUNET_NO);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received inbound channel from `%s'\n",
              GNUNET_i2s (initiator));
  s->channel = channel;
  s->specifics.tcp_udp.serv = ls;
  s->specifics.tcp_udp.ri.remote_address = ls->address;
  return s;
}


/**
 * Function called by cadet whenever an inbound channel is destroyed.
 * Should clean up any associated state.
 *
 * @param cls our `struct ChannelState *`
 * @param channel connection to the other end (henceforth invalid)
 */
static void
clean_channel (void *cls,
               const struct GNUNET_CADET_Channel *channel)
{
  struct ChannelState *s = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Channel destroyed\n");
  if (GNUNET_SYSERR == s->is_dns)
  {
    GNUNET_free (s);
    return;
  }
  if (GNUNET_YES == s->is_dns)
  {
    if (channels[s->specifics.dns.my_id] == s)
      channels[s->specifics.dns.my_id] = NULL;
  }
  else
  {
    if (NULL != s->specifics.tcp_udp.heap_node)
    {
      GNUNET_assert (GNUNET_YES ==
                     GNUNET_CONTAINER_multihashmap_remove (connections_map,
                                                           &s->specifics.tcp_udp
                                                           .state_key,
                                                           s));
      GNUNET_CONTAINER_heap_remove_node (s->specifics.tcp_udp.heap_node);
      s->specifics.tcp_udp.heap_node = NULL;
    }
  }
  GNUNET_free (s);
}


/**
 * Given a service descriptor and a destination port, find the
 * respective service entry.
 *
 * @param proto IPPROTO_TCP or IPPROTO_UDP
 * @param name name of the service
 * @param destination_port destination port
 * @param service service information record to store (service->name will be set).
 */
static void
store_service (int proto,
               const char *name,
               uint16_t destination_port,
               struct LocalService *service)
{
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (icmp_service,
                           GNUNET_MESSAGE_TYPE_VPN_ICMP_TO_SERVICE,
                           struct GNUNET_EXIT_IcmpServiceMessage,
                           service),
    GNUNET_MQ_hd_var_size (udp_service,
                           GNUNET_MESSAGE_TYPE_VPN_UDP_TO_SERVICE,
                           struct GNUNET_EXIT_UdpServiceMessage,
                           service),
    GNUNET_MQ_hd_var_size (tcp_service,
                           GNUNET_MESSAGE_TYPE_VPN_TCP_TO_SERVICE_START,
                           struct GNUNET_EXIT_TcpServiceStartMessage,
                           service),
    GNUNET_MQ_hd_var_size (tcp_data,
                           GNUNET_MESSAGE_TYPE_VPN_TCP_DATA_TO_EXIT,
                           struct GNUNET_EXIT_TcpDataMessage,
                           service),
    GNUNET_MQ_handler_end ()
  };

  struct GNUNET_HashCode cadet_port;

  service->name = GNUNET_strdup (name);
  GNUNET_TUN_service_name_to_hash (name,
                                   &service->descriptor);
  GNUNET_TUN_compute_service_cadet_port (&service->descriptor,
                                         destination_port,
                                         &cadet_port);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Opening CADET port %s for SERVICE exit %s on port %u\n",
              GNUNET_h2s (&cadet_port),
              name,
              (unsigned int) destination_port);
  service->port = GNUNET_CADET_open_port (cadet_handle,
                                          &cadet_port,
                                          &new_service_channel,
                                          service,
                                          NULL,
                                          &clean_channel,
                                          handlers);
  service->is_udp = (IPPROTO_UDP == proto);
  if (GNUNET_OK !=
      GNUNET_CONTAINER_multihashmap_put (services,
                                         &cadet_port,
                                         service,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
  {
    GNUNET_CADET_close_port (service->port);
    GNUNET_free_non_null (service->name);
    GNUNET_free (service);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("Got duplicate service records for `%s:%u'\n"),
                name,
                (unsigned int) destination_port);
  }
}


/**
 * Send the given packet via the cadet channel.
 *
 * @param s channel destination
 * @param env message to queue
 */
static void
send_packet_to_cadet_channel (struct ChannelState *s,
                              struct GNUNET_MQ_Envelope *env)
{
  GNUNET_assert (NULL != s);
  GNUNET_STATISTICS_update (stats,
                            gettext_noop (
                              "# Messages transmitted via cadet channels"),
                            1,
                            GNUNET_NO);
  GNUNET_MQ_send (GNUNET_CADET_get_mq (s->channel),
                  env);
}


/**
 * @brief Handles an ICMP packet received from the helper.
 *
 * @param icmp A pointer to the Packet
 * @param pktlen number of bytes in @a icmp
 * @param af address family (AFINET or AF_INET6)
 * @param destination_ip destination IP-address of the IP packet (should
 *                       be our local address)
 * @param source_ip original source IP-address of the IP packet (should
 *                       be the original destination address)
 */
static void
icmp_from_helper (const struct GNUNET_TUN_IcmpHeader *icmp,
                  size_t pktlen,
                  int af,
                  const void *destination_ip,
                  const void *source_ip)
{
  struct ChannelState *state;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_EXIT_IcmpToVPNMessage *i2v;
  const struct GNUNET_TUN_IPv4Header *ipv4;
  const struct GNUNET_TUN_IPv6Header *ipv6;
  const struct GNUNET_TUN_UdpHeader *udp;
  uint16_t source_port;
  uint16_t destination_port;
  uint8_t protocol;

  {
    char sbuf[INET6_ADDRSTRLEN];
    char dbuf[INET6_ADDRSTRLEN];
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received ICMP packet going from %s to %s\n",
                inet_ntop (af,
                           source_ip,
                           sbuf, sizeof(sbuf)),
                inet_ntop (af,
                           destination_ip,
                           dbuf, sizeof(dbuf)));
  }

  if (pktlen < sizeof(struct GNUNET_TUN_IcmpHeader))
  {
    /* blame kernel */
    GNUNET_break (0);
    return;
  }

  /* Find out if this is an ICMP packet in response to an existing
     TCP/UDP packet and if so, figure out ports / protocol of the
     existing session from the IP data in the ICMP payload */
  source_port = 0;
  destination_port = 0;
  switch (af)
  {
  case AF_INET:
    protocol = IPPROTO_ICMP;
    switch (icmp->type)
    {
    case GNUNET_TUN_ICMPTYPE_ECHO_REPLY:
    case GNUNET_TUN_ICMPTYPE_ECHO_REQUEST:
      break;

    case GNUNET_TUN_ICMPTYPE_DESTINATION_UNREACHABLE:
    case GNUNET_TUN_ICMPTYPE_SOURCE_QUENCH:
    case GNUNET_TUN_ICMPTYPE_TIME_EXCEEDED:
      if (pktlen <
          sizeof(struct GNUNET_TUN_IcmpHeader)
          + sizeof(struct GNUNET_TUN_IPv4Header) + 8)
      {
        /* blame kernel */
        GNUNET_break (0);
        return;
      }
      ipv4 = (const struct GNUNET_TUN_IPv4Header *) &icmp[1];
      protocol = ipv4->protocol;
      /* could be TCP or UDP, but both have the ports in the right
         place, so that doesn't matter here */
      udp = (const struct GNUNET_TUN_UdpHeader *) &ipv4[1];
      /* swap ports, as they are from the original message */
      destination_port = ntohs (udp->source_port);
      source_port = ntohs (udp->destination_port);
      /* throw away ICMP payload, won't be useful for the other side anyway */
      pktlen = sizeof(struct GNUNET_TUN_IcmpHeader);
      break;

    default:
      GNUNET_STATISTICS_update (stats,
                                gettext_noop (
                                  "# ICMPv4 packets dropped (type not allowed)"),
                                1, GNUNET_NO);
      return;
    }
    break;

  case AF_INET6:
    protocol = IPPROTO_ICMPV6;
    switch (icmp->type)
    {
    case GNUNET_TUN_ICMPTYPE6_DESTINATION_UNREACHABLE:
    case GNUNET_TUN_ICMPTYPE6_PACKET_TOO_BIG:
    case GNUNET_TUN_ICMPTYPE6_TIME_EXCEEDED:
    case GNUNET_TUN_ICMPTYPE6_PARAMETER_PROBLEM:
      if (pktlen <
          sizeof(struct GNUNET_TUN_IcmpHeader)
          + sizeof(struct GNUNET_TUN_IPv6Header) + 8)
      {
        /* blame kernel */
        GNUNET_break (0);
        return;
      }
      ipv6 = (const struct GNUNET_TUN_IPv6Header *) &icmp[1];
      protocol = ipv6->next_header;
      /* could be TCP or UDP, but both have the ports in the right
         place, so that doesn't matter here */
      udp = (const struct GNUNET_TUN_UdpHeader *) &ipv6[1];
      /* swap ports, as they are from the original message */
      destination_port = ntohs (udp->source_port);
      source_port = ntohs (udp->destination_port);
      /* throw away ICMP payload, won't be useful for the other side anyway */
      pktlen = sizeof(struct GNUNET_TUN_IcmpHeader);
      break;

    case GNUNET_TUN_ICMPTYPE6_ECHO_REQUEST:
    case GNUNET_TUN_ICMPTYPE6_ECHO_REPLY:
      break;

    default:
      GNUNET_STATISTICS_update (stats,
                                gettext_noop (
                                  "# ICMPv6 packets dropped (type not allowed)"),
                                1, GNUNET_NO);
      return;
    }
    break;

  default:
    GNUNET_assert (0);
  }
  switch (protocol)
  {
  case IPPROTO_ICMP:
    state = get_redirect_state (af,
                                IPPROTO_ICMP,
                                source_ip,
                                0,
                                destination_ip,
                                0,
                                NULL);
    break;

  case IPPROTO_ICMPV6:
    state = get_redirect_state (af,
                                IPPROTO_ICMPV6,
                                source_ip,
                                0,
                                destination_ip,
                                0,
                                NULL);
    break;

  case IPPROTO_UDP:
    state = get_redirect_state (af,
                                IPPROTO_UDP,
                                source_ip,
                                source_port,
                                destination_ip,
                                destination_port,
                                NULL);
    break;

  case IPPROTO_TCP:
    state = get_redirect_state (af,
                                IPPROTO_TCP,
                                source_ip,
                                source_port,
                                destination_ip,
                                destination_port,
                                NULL);
    break;

  default:
    GNUNET_STATISTICS_update (stats,
                              gettext_noop (
                                "# ICMP packets dropped (not allowed)"),
                              1,
                              GNUNET_NO);
    return;
  }
  if (NULL == state)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _ (
                  "ICMP Packet dropped, have no matching connection information\n"));
    return;
  }
  env = GNUNET_MQ_msg_extra (i2v,
                             pktlen - sizeof(struct GNUNET_TUN_IcmpHeader),
                             GNUNET_MESSAGE_TYPE_VPN_ICMP_TO_VPN);
  i2v->af = htonl (af);
  GNUNET_memcpy (&i2v->icmp_header,
                 icmp,
                 pktlen);
  send_packet_to_cadet_channel (state,
                                env);
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
udp_from_helper (const struct GNUNET_TUN_UdpHeader *udp,
                 size_t pktlen,
                 int af,
                 const void *destination_ip,
                 const void *source_ip)
{
  struct ChannelState *state;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_EXIT_UdpReplyMessage *urm;

  {
    char sbuf[INET6_ADDRSTRLEN];
    char dbuf[INET6_ADDRSTRLEN];

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received UDP packet going from %s:%u to %s:%u\n",
                inet_ntop (af,
                           source_ip,
                           sbuf, sizeof(sbuf)),
                (unsigned int) ntohs (udp->source_port),
                inet_ntop (af,
                           destination_ip,
                           dbuf, sizeof(dbuf)),
                (unsigned int) ntohs (udp->destination_port));
  }

  if (pktlen < sizeof(struct GNUNET_TUN_UdpHeader))
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
  state = get_redirect_state (af,
                              IPPROTO_UDP,
                              source_ip,
                              ntohs (udp->source_port),
                              destination_ip,
                              ntohs (udp->destination_port),
                              NULL);
  if (NULL == state)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _ (
                  "UDP Packet dropped, have no matching connection information\n"));
    return;
  }
  env = GNUNET_MQ_msg_extra (urm,
                             pktlen - sizeof(struct GNUNET_TUN_UdpHeader),
                             GNUNET_MESSAGE_TYPE_VPN_UDP_REPLY);
  urm->source_port = htons (0);
  urm->destination_port = htons (0);
  GNUNET_memcpy (&urm[1],
                 &udp[1],
                 pktlen - sizeof(struct GNUNET_TUN_UdpHeader));
  send_packet_to_cadet_channel (state,
                                env);
}


/**
 * @brief Handles a TCP packet received from the helper.
 *
 * @param tcp A pointer to the Packet
 * @param pktlen the length of the packet, including its TCP header
 * @param af address family (AFINET or AF_INET6)
 * @param destination_ip destination IP-address of the IP packet (should
 *                       be our local address)
 * @param source_ip original source IP-address of the IP packet (should
 *                       be the original destination address)
 */
static void
tcp_from_helper (const struct GNUNET_TUN_TcpHeader *tcp,
                 size_t pktlen,
                 int af,
                 const void *destination_ip,
                 const void *source_ip)
{
  struct ChannelState *state;
  char buf[pktlen] GNUNET_ALIGN;
  struct GNUNET_TUN_TcpHeader *mtcp;
  struct GNUNET_EXIT_TcpDataMessage *tdm;
  struct GNUNET_MQ_Envelope *env;
  size_t mlen;

  {
    char sbuf[INET6_ADDRSTRLEN];
    char dbuf[INET6_ADDRSTRLEN];
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received TCP packet with %u bytes going from %s:%u to %s:%u\n",
                (unsigned int) (pktlen - sizeof(struct GNUNET_TUN_TcpHeader)),
                inet_ntop (af,
                           source_ip,
                           sbuf, sizeof(sbuf)),
                (unsigned int) ntohs (tcp->source_port),
                inet_ntop (af,
                           destination_ip,
                           dbuf, sizeof(dbuf)),
                (unsigned int) ntohs (tcp->destination_port));
  }

  if (pktlen < sizeof(struct GNUNET_TUN_TcpHeader))
  {
    /* blame kernel */
    GNUNET_break (0);
    return;
  }
  state = get_redirect_state (af,
                              IPPROTO_TCP,
                              source_ip,
                              ntohs (tcp->source_port),
                              destination_ip,
                              ntohs (tcp->destination_port),
                              NULL);
  if (NULL == state)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _ (
                  "TCP Packet dropped, have no matching connection information\n"));

    return;
  }
  /* mug port numbers and crc to avoid information leakage;
     sender will need to lookup the correct values anyway */
  GNUNET_memcpy (buf, tcp, pktlen);
  mtcp = (struct GNUNET_TUN_TcpHeader *) buf;
  mtcp->source_port = 0;
  mtcp->destination_port = 0;
  mtcp->crc = 0;

  mlen = sizeof(struct GNUNET_EXIT_TcpDataMessage) + (pktlen - sizeof(struct
                                                                      GNUNET_TUN_TcpHeader));
  if (mlen >= GNUNET_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }
  env = GNUNET_MQ_msg_extra (tdm,
                             pktlen - sizeof(struct GNUNET_TUN_TcpHeader),
                             GNUNET_MESSAGE_TYPE_VPN_TCP_DATA_TO_VPN);
  tdm->reserved = htonl (0);
  GNUNET_memcpy (&tdm->tcp_header,
                 buf,
                 pktlen);
  send_packet_to_cadet_channel (state,
                                env);
}


/**
 * Receive packets from the helper-process
 *
 * @param cls unused
 * @param message message received from helper
 */
static int
message_token (void *cls GNUNET_UNUSED,
               const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TUN_Layer2PacketHeader *pkt_tun;
  size_t size;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got %u-byte message of type %u from gnunet-helper-exit\n",
              ntohs (message->size),
              ntohs (message->type));
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# Packets received from TUN"),
                            1, GNUNET_NO);
  if (ntohs (message->type) != GNUNET_MESSAGE_TYPE_VPN_HELPER)
  {
    GNUNET_break (0);
    return GNUNET_OK;
  }
  size = ntohs (message->size);
  if (size < sizeof(struct GNUNET_TUN_Layer2PacketHeader) + sizeof(struct
                                                                   GNUNET_MessageHeader))
  {
    GNUNET_break (0);
    return GNUNET_OK;
  }
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# Bytes received from TUN"),
                            size, GNUNET_NO);
  pkt_tun = (const struct GNUNET_TUN_Layer2PacketHeader *) &message[1];
  size -= sizeof(struct GNUNET_TUN_Layer2PacketHeader) + sizeof(struct
                                                                GNUNET_MessageHeader);
  switch (ntohs (pkt_tun->proto))
  {
  case ETH_P_IPV4:
    {
      const struct GNUNET_TUN_IPv4Header *pkt4;

      if (size < sizeof(struct GNUNET_TUN_IPv4Header))
      {
        /* Kernel to blame? */
        GNUNET_break (0);
        return GNUNET_OK;
      }
      pkt4 = (const struct GNUNET_TUN_IPv4Header *) &pkt_tun[1];
      if (size != ntohs (pkt4->total_length))
      {
        /* Kernel to blame? */
        GNUNET_break (0);
        return GNUNET_OK;
      }
      if (pkt4->header_length * 4 != sizeof(struct GNUNET_TUN_IPv4Header))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    _ ("IPv4 packet options received.  Ignored.\n"));
        return GNUNET_OK;
      }

      size -= sizeof(struct GNUNET_TUN_IPv4Header);
      switch (pkt4->protocol)
      {
      case IPPROTO_UDP:
        udp_from_helper ((const struct GNUNET_TUN_UdpHeader *) &pkt4[1], size,
                         AF_INET,
                         &pkt4->destination_address,
                         &pkt4->source_address);
        break;

      case IPPROTO_TCP:
        tcp_from_helper ((const struct GNUNET_TUN_TcpHeader *) &pkt4[1], size,
                         AF_INET,
                         &pkt4->destination_address,
                         &pkt4->source_address);
        break;

      case IPPROTO_ICMP:
        icmp_from_helper ((const struct GNUNET_TUN_IcmpHeader *) &pkt4[1], size,
                          AF_INET,
                          &pkt4->destination_address,
                          &pkt4->source_address);
        break;

      default:
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    _ (
                      "IPv4 packet with unsupported next header %u received.  Ignored.\n"),
                    (int) pkt4->protocol);
        return GNUNET_OK;
      }
    }
    break;

  case ETH_P_IPV6:
    {
      const struct GNUNET_TUN_IPv6Header *pkt6;

      if (size < sizeof(struct GNUNET_TUN_IPv6Header))
      {
        /* Kernel to blame? */
        GNUNET_break (0);
        return GNUNET_OK;
      }
      pkt6 = (struct GNUNET_TUN_IPv6Header *) &pkt_tun[1];
      if (size != ntohs (pkt6->payload_length) + sizeof(struct
                                                        GNUNET_TUN_IPv6Header))
      {
        /* Kernel to blame? */
        GNUNET_break (0);
        return GNUNET_OK;
      }
      size -= sizeof(struct GNUNET_TUN_IPv6Header);
      switch (pkt6->next_header)
      {
      case IPPROTO_UDP:
        udp_from_helper ((const struct GNUNET_TUN_UdpHeader *) &pkt6[1], size,
                         AF_INET6,
                         &pkt6->destination_address,
                         &pkt6->source_address);
        break;

      case IPPROTO_TCP:
        tcp_from_helper ((const struct GNUNET_TUN_TcpHeader *) &pkt6[1], size,
                         AF_INET6,
                         &pkt6->destination_address,
                         &pkt6->source_address);
        break;

      case IPPROTO_ICMPV6:
        icmp_from_helper ((const struct GNUNET_TUN_IcmpHeader *) &pkt6[1], size,
                          AF_INET6,
                          &pkt6->destination_address,
                          &pkt6->source_address);
        break;

      default:
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    _ (
                      "IPv6 packet with unsupported next header %d received.  Ignored.\n"),
                    pkt6->next_header);
        return GNUNET_OK;
      }
    }
    break;

  default:
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("Packet from unknown protocol %u received.  Ignored.\n"),
                ntohs (pkt_tun->proto));
    break;
  }
  return GNUNET_OK;
}


/**
 * Callback from CADET for new channels.
 *
 * @param cls closure
 * @param channel new handle to the channel
 * @param initiator peer that started the channel
 * @return initial channel context for the channel
 */
static void *
new_channel (void *cls,
             struct GNUNET_CADET_Channel *channel,
             const struct GNUNET_PeerIdentity *initiator)
{
  struct ChannelState *s = GNUNET_new (struct ChannelState);

  s->is_dns = GNUNET_SYSERR;
  s->peer = *initiator;
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# Inbound CADET channels created"),
                            1,
                            GNUNET_NO);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received inbound channel from `%s'\n",
              GNUNET_i2s (initiator));
  s->channel = channel;
  return s;
}


/**
 * Function that frees everything from a hashmap
 *
 * @param cls unused
 * @param hash key
 * @param value value to free
 */
static int
free_iterate (void *cls,
              const struct GNUNET_HashCode *hash,
              void *value)
{
  GNUNET_free (value);
  return GNUNET_YES;
}


/**
 * Function scheduled as very last function if the service
 * disabled itself because the helper is not installed
 * properly.  Does nothing, except for keeping the
 * service process alive by virtue of being scheduled.
 *
 * @param cls NULL
 * @param tc scheduler context
 */
static void
dummy_task (void *cls)
{
  /* just terminate */
}


/**
 * Function scheduled as very last function, cleans up after us
 *
 * @param cls NULL
 */
static void
cleanup (void *cls)
{
  unsigned int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Exit service is shutting down now\n");

  if (NULL != helper_handle)
  {
    GNUNET_HELPER_stop (helper_handle, GNUNET_NO);
    helper_handle = NULL;
  }
  if (NULL != regex4)
  {
    GNUNET_REGEX_announce_cancel (regex4);
    regex4 = NULL;
  }
  if (NULL != regex6)
  {
    GNUNET_REGEX_announce_cancel (regex6);
    regex6 = NULL;
  }
  if (NULL != services)
  {
    GNUNET_CONTAINER_multihashmap_iterate (services,
                                           &free_service_record,
                                           NULL);
    GNUNET_CONTAINER_multihashmap_destroy (services);
  }
  if (NULL != dns_port)
  {
    GNUNET_CADET_close_port (dns_port);
    dns_port = NULL;
  }
  if (NULL != cadet_port4)
  {
    GNUNET_CADET_close_port (cadet_port4);
    cadet_port4 = NULL;
  }
  if (NULL != cadet_port6)
  {
    GNUNET_CADET_close_port (cadet_port6);
    cadet_port6 = NULL;
  }
  if (NULL != cadet_handle)
  {
    GNUNET_CADET_disconnect (cadet_handle);
    cadet_handle = NULL;
  }
  if (NULL != connections_map)
  {
    GNUNET_CONTAINER_multihashmap_iterate (connections_map,
                                           &free_iterate,
                                           NULL);
    GNUNET_CONTAINER_multihashmap_destroy (connections_map);
    connections_map = NULL;
  }
  if (NULL != connections_heap)
  {
    GNUNET_CONTAINER_heap_destroy (connections_heap);
    connections_heap = NULL;
  }
  if (NULL != dnsstub)
  {
    GNUNET_DNSSTUB_stop (dnsstub);
    dnsstub = NULL;
  }
  if (NULL != peer_key)
  {
    GNUNET_free (peer_key);
    peer_key = NULL;
  }
  if (NULL != dht_task)
  {
    GNUNET_SCHEDULER_cancel (dht_task);
    dht_task = NULL;
  }
  if (NULL != dht_put)
  {
    GNUNET_DHT_put_cancel (dht_put);
    dht_put = NULL;
  }
  if (NULL != dht)
  {
    GNUNET_DHT_disconnect (dht);
    dht = NULL;
  }
  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats,
                               GNUNET_NO);
    stats = NULL;
  }
  for (i = 0; i < 8; i++)
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
  char *n;
  size_t slen;

  slen = strlen (name);
  GNUNET_assert (slen >= 8);
  n = GNUNET_strndup (name, slen - 8 /* remove .gnunet. */);

  for (redirect = strtok (cpy, " ;"); redirect != NULL;
       redirect = strtok (NULL, " ;"))
  {
    if (NULL == (hostname = strstr (redirect, ":")))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _ (
                    "Option `%s' for domain `%s' is not formatted correctly!\n"),
                  redirect,
                  name);
      continue;
    }
    hostname[0] = '\0';
    hostname++;
    if (NULL == (hostport = strstr (hostname, ":")))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _ (
                    "Option `%s' for domain `%s' is not formatted correctly!\n"),
                  redirect,
                  name);
      continue;
    }
    hostport[0] = '\0';
    hostport++;

    int local_port = atoi (redirect);
    int remote_port = atoi (hostport);

    if (! ((local_port > 0) && (local_port < 65536)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _ ("`%s' is not a valid port number (for domain `%s')!"),
                  redirect,
                  name);
      continue;
    }
    if (! ((remote_port > 0) && (remote_port < 65536)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _ ("`%s' is not a valid port number (for domain `%s')!"),
                  hostport,
                  name);
      continue;
    }

    serv = GNUNET_new (struct LocalService);
    serv->address.proto = proto;
    serv->address.port = remote_port;
    if (0 == strcmp ("localhost4",
                     hostname))
    {
      const char *ip4addr = exit_argv[5];

      serv->address.af = AF_INET;
      GNUNET_assert (1 == inet_pton (AF_INET,
                                     ip4addr,
                                     &serv->address.address.ipv4));
    }
    else if (0 == strcmp ("localhost6",
                          hostname))
    {
      const char *ip6addr = exit_argv[3];

      serv->address.af = AF_INET6;
      GNUNET_assert (1 == inet_pton (AF_INET6,
                                     ip6addr,
                                     &serv->address.address.ipv6));
    }
    else
    {
      struct addrinfo *res;
      int ret;

      ret = getaddrinfo (hostname,
                         NULL,
                         NULL,
                         &res);
      if ((0 != ret) || (NULL == res))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    _ (
                      "No addresses found for hostname `%s' of service `%s'!\n"),
                    hostname,
                    n);
        GNUNET_free (serv);
        continue;
      }

      serv->address.af = res->ai_family;
      switch (res->ai_family)
      {
      case AF_INET:
        if (! ipv4_enabled)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                      _ (
                        "Service `%s' configured for IPv4, but IPv4 is disabled!\n"),
                      n);
          freeaddrinfo (res);
          GNUNET_free (serv);
          continue;
        }
        serv->address.address.ipv4
          = ((struct sockaddr_in *) res->ai_addr)->sin_addr;
        break;

      case AF_INET6:
        if (! ipv6_enabled)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                      _ (
                        "Service `%s' configured for IPv4, but IPv4 is disabled!\n"),
                      n);
          freeaddrinfo (res);
          GNUNET_free (serv);
          continue;
        }
        serv->address.address.ipv6
          = ((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
        break;

      default:
        freeaddrinfo (res);
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    _ (
                      "No IP addresses found for hostname `%s' of service `%s'!\n"),
                    hostname,
                    n);
        GNUNET_free (serv);
        continue;
      }
      freeaddrinfo (res);
    }
    store_service (proto,
                   n,
                   local_port,
                   serv);
  }
  GNUNET_free (n);
}


/**
 * Reads the configuration and populates #udp_services and #tcp_services
 *
 * @param cls unused
 * @param section name of section in config
 */
static void
read_service_conf (void *cls,
                   const char *section)
{
  char *cpy;

  if ((strlen (section) < 8) ||
      (0 != strcmp (".gnunet.", section + (strlen (section) - 8))))
    return;
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             section,
                                             "UDP_REDIRECTS",
                                             &cpy))
  {
    add_services (IPPROTO_UDP,
                  cpy,
                  section);
    GNUNET_free (cpy);
  }
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             section,
                                             "TCP_REDIRECTS",
                                             &cpy))
  {
    add_services (IPPROTO_TCP,
                  cpy,
                  section);
    GNUNET_free (cpy);
  }
}


/**
 * We are running a DNS exit service, advertise it in the
 * DHT.  This task is run periodically to do the DHT PUT.
 *
 * @param cls closure
 */
static void
do_dht_put (void *cls);


/**
 * Function called when the DHT PUT operation is complete.
 * Schedules the next PUT.
 *
 * @param cls closure, NULL
 */
static void
dht_put_cont (void *cls)
{
  dht_put = NULL;
}


/**
 * We are running a DNS exit service, advertise it in the
 * DHT.  This task is run periodically to do the DHT PUT.
 *
 * @param cls closure
 */
static void
do_dht_put (void *cls)
{
  struct GNUNET_TIME_Absolute expiration;

  dht_task = GNUNET_SCHEDULER_add_delayed (DHT_PUT_FREQUENCY,
                                           &do_dht_put,
                                           NULL);
  expiration = GNUNET_TIME_absolute_ntoh (dns_advertisement.expiration_time);
  if (GNUNET_TIME_absolute_get_remaining (expiration).rel_value_us <
      GNUNET_TIME_UNIT_HOURS.rel_value_us)
  {
    /* refresh advertisement */
    expiration = GNUNET_TIME_relative_to_absolute (DNS_ADVERTISEMENT_TIMEOUT);
    dns_advertisement.expiration_time = GNUNET_TIME_absolute_hton (expiration);
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CRYPTO_eddsa_sign_ (peer_key,
                                              &dns_advertisement.purpose,
                                              &dns_advertisement.signature));
  }
  if (NULL != dht_put)
    GNUNET_DHT_put_cancel (dht_put);
  dht_put = GNUNET_DHT_put (dht,
                            &dht_put_key,
                            1 /* replication */,
                            GNUNET_DHT_RO_NONE,
                            GNUNET_BLOCK_TYPE_DNS,
                            sizeof(struct GNUNET_DNS_Advertisement),
                            &dns_advertisement,
                            expiration,
                            &dht_put_cont,
                            NULL);
}


/**
 * Figure out which IP versions we should support (and which
 * are supported by the OS) according to our configuration.
 */
static void
parse_ip_options ()
{
  ipv4_exit = GNUNET_CONFIGURATION_get_value_yesno (cfg,
                                                    "exit",
                                                    "EXIT_IPV4");
  ipv6_exit = GNUNET_CONFIGURATION_get_value_yesno (cfg,
                                                    "exit",
                                                    "EXIT_IPV6");
  ipv4_enabled = GNUNET_CONFIGURATION_get_value_yesno (cfg,
                                                       "exit",
                                                       "ENABLE_IPV4");
  ipv6_enabled = GNUNET_CONFIGURATION_get_value_yesno (cfg,
                                                       "exit",
                                                       "ENABLE_IPV6");
  if ((ipv4_exit || ipv4_enabled) &&
      (GNUNET_OK != GNUNET_NETWORK_test_pf (PF_INET)) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ (
                  "This system does not support IPv4, will disable IPv4 functions despite them being enabled in the configuration\n"));
    ipv4_exit = GNUNET_NO;
    ipv4_enabled = GNUNET_NO;
  }
  if ((ipv6_exit || ipv6_enabled) &&
      (GNUNET_OK != GNUNET_NETWORK_test_pf (PF_INET6)) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ (
                  "This system does not support IPv6, will disable IPv6 functions despite them being enabled in the configuration\n"));
    ipv6_exit = GNUNET_NO;
    ipv6_enabled = GNUNET_NO;
  }
  if (ipv4_exit && (! ipv4_enabled))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ (
                  "Cannot enable IPv4 exit but disable IPv4 on TUN interface, will use ENABLE_IPv4=YES\n"));
    ipv4_enabled = GNUNET_YES;
  }
  if (ipv6_exit && (! ipv6_enabled))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ (
                  "Cannot enable IPv6 exit but disable IPv6 on TUN interface, will use ENABLE_IPv6=YES\n"));
    ipv6_enabled = GNUNET_YES;
  }
}


/**
 * Helper function to open the CADET port for DNS exits and to
 * advertise the DNS exit (if applicable).
 */
static void
advertise_dns_exit ()
{
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (dns_request,
                           GNUNET_MESSAGE_TYPE_VPN_DNS_TO_INTERNET,
                           struct DnsResponseMessage,
                           NULL),
    GNUNET_MQ_handler_end ()
  };
  char *dns_exit;
  struct GNUNET_HashCode port;

  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_get_value_yesno (cfg,
                                            "exit",
                                            "EXIT_DNS"))
    return;
  GNUNET_assert (NULL != (dnsstub = GNUNET_DNSSTUB_start (128)));
  dns_exit = NULL;
  /* TODO: support using multiple DNS resolvers */
  if ((GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_string (cfg,
                                              "exit",
                                              "DNS_RESOLVER",
                                              &dns_exit)) ||
      (GNUNET_OK !=
       GNUNET_DNSSTUB_add_dns_ip (dnsstub,
                                  dns_exit)))
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                               "dns",
                               "DNS_RESOLVER",
                               _ ("need a valid IPv4 or IPv6 address\n"));
    GNUNET_free_non_null (dns_exit);
    return;
  }
  /* open port */
  GNUNET_CRYPTO_hash (GNUNET_APPLICATION_PORT_INTERNET_RESOLVER,
                      strlen (GNUNET_APPLICATION_PORT_INTERNET_RESOLVER),
                      &port);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Opening CADET port %s for DNS exit service\n",
              GNUNET_h2s (&port));
  dns_port = GNUNET_CADET_open_port (cadet_handle,
                                     &port,
                                     &new_channel,
                                     NULL,
                                     NULL,
                                     &clean_channel,
                                     handlers);
  /* advertise exit */
  dht = GNUNET_DHT_connect (cfg,
                            1);
  peer_key = GNUNET_CRYPTO_eddsa_key_create_from_configuration (cfg);
  GNUNET_CRYPTO_eddsa_key_get_public (peer_key,
                                      &dns_advertisement.peer.public_key);
  dns_advertisement.purpose.size = htonl (sizeof(struct
                                                 GNUNET_DNS_Advertisement)
                                          - sizeof(struct
                                                   GNUNET_CRYPTO_EddsaSignature));
  dns_advertisement.purpose.purpose = htonl (
    GNUNET_SIGNATURE_PURPOSE_DNS_RECORD);
  GNUNET_CRYPTO_hash ("dns",
                      strlen ("dns"),
                      &dht_put_key);
  dht_task = GNUNET_SCHEDULER_add_now (&do_dht_put,
                                       NULL);
  GNUNET_free (dns_exit);
}


/**
 * Initialize #exit_argv.
 *
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if we should shutdown
 */
static int
setup_exit_helper_args ()
{
  char *exit_ifname;
  char *tun_ifname;
  char *ipv6addr;
  char *ipv6prefix_s;
  char *ipv4addr;
  char *ipv4mask;

  exit_argv[0] = GNUNET_strdup ("exit-gnunet");
  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             "exit",
                                             "TUN_IFNAME",
                                             &tun_ifname))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "EXIT",
                               "TUN_IFNAME");
    return GNUNET_SYSERR;
  }
  exit_argv[1] = tun_ifname;
  if (ipv4_enabled)
  {
    if (GNUNET_SYSERR ==
        GNUNET_CONFIGURATION_get_value_string (cfg,
                                               "exit",
                                               "EXIT_IFNAME",
                                               &exit_ifname))
    {
      GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                                 "EXIT",
                                 "EXIT_IFNAME");
      return GNUNET_SYSERR;
    }
    exit_argv[2] = exit_ifname;
  }
  else
  {
    exit_argv[2] = GNUNET_strdup ("-");
  }

  if (GNUNET_YES == ipv6_enabled)
  {
    ipv6addr = NULL;
    if (((GNUNET_SYSERR ==
          GNUNET_CONFIGURATION_get_value_string (cfg,
                                                 "exit",
                                                 "IPV6ADDR",
                                                 &ipv6addr)) ||
         (1 != inet_pton (AF_INET6,
                          ipv6addr,
                          &exit_ipv6addr))))
    {
      GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                                 "EXIT",
                                 "IPV6ADDR");
      GNUNET_free_non_null (ipv6addr);
      return GNUNET_SYSERR;
    }
    exit_argv[3] = ipv6addr;
    if (GNUNET_SYSERR ==
        GNUNET_CONFIGURATION_get_value_string (cfg,
                                               "exit",
                                               "IPV6PREFIX",
                                               &ipv6prefix_s))
    {
      GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                                 "EXIT",
                                 "IPV6PREFIX");
      return GNUNET_SYSERR;
    }
    exit_argv[4] = ipv6prefix_s;
    if ((GNUNET_OK !=
         GNUNET_CONFIGURATION_get_value_number (cfg,
                                                "exit",
                                                "IPV6PREFIX",
                                                &ipv6prefix)) ||
        (ipv6prefix >= 127))
    {
      GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                                 "EXIT",
                                 "IPV6PREFIX",
                                 _ ("Must be a number"));
      return GNUNET_SYSERR;
    }
  }
  else
  {
    /* IPv6 explicitly disabled */
    exit_argv[3] = GNUNET_strdup ("-");
    exit_argv[4] = GNUNET_strdup ("-");
  }
  if (GNUNET_YES == ipv4_enabled)
  {
    ipv4addr = NULL;
    if (((GNUNET_SYSERR ==
          GNUNET_CONFIGURATION_get_value_string (cfg,
                                                 "exit",
                                                 "IPV4ADDR",
                                                 &ipv4addr)) ||
         (1 != inet_pton (AF_INET,
                          ipv4addr,
                          &exit_ipv4addr))))
    {
      GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                                 "EXIT",
                                 "IPV4ADDR");
      GNUNET_free_non_null (ipv4addr);
      return GNUNET_SYSERR;
    }
    exit_argv[5] = ipv4addr;
    ipv4mask = NULL;
    if (((GNUNET_SYSERR ==
          GNUNET_CONFIGURATION_get_value_string (cfg,
                                                 "exit",
                                                 "IPV4MASK",
                                                 &ipv4mask)) ||
         (1 != inet_pton (AF_INET,
                          ipv4mask,
                          &exit_ipv4mask))))
    {
      GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                                 "EXIT",
                                 "IPV4MASK");
      GNUNET_free_non_null (ipv4mask);
      return GNUNET_SYSERR;
    }
    exit_argv[6] = ipv4mask;
  }
  else
  {
    /* IPv4 explicitly disabled */
    exit_argv[5] = GNUNET_strdup ("-");
    exit_argv[6] = GNUNET_strdup ("-");
  }
  exit_argv[7] = NULL;
  return GNUNET_OK;
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
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg_)
{
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (icmp_remote,
                           GNUNET_MESSAGE_TYPE_VPN_ICMP_TO_INTERNET,
                           struct GNUNET_EXIT_IcmpInternetMessage,
                           NULL),
    GNUNET_MQ_hd_var_size (udp_remote,
                           GNUNET_MESSAGE_TYPE_VPN_UDP_TO_INTERNET,
                           struct GNUNET_EXIT_UdpInternetMessage,
                           NULL),
    GNUNET_MQ_hd_var_size (tcp_remote,
                           GNUNET_MESSAGE_TYPE_VPN_TCP_TO_INTERNET_START,
                           struct GNUNET_EXIT_TcpInternetStartMessage,
                           NULL),
    GNUNET_MQ_hd_var_size (tcp_data,
                           GNUNET_MESSAGE_TYPE_VPN_TCP_DATA_TO_EXIT,
                           struct GNUNET_EXIT_TcpDataMessage,
                           NULL),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_HashCode port;
  char *policy;
  char *binary;
  char *regex;
  char *prefixed_regex;

  cfg = cfg_;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg,
                                             "exit",
                                             "MAX_CONNECTIONS",
                                             &max_connections))
    max_connections = 1024;
  parse_ip_options ();
  binary = GNUNET_OS_get_suid_binary_path (cfg, "gnunet-helper-exit");
  if ((ipv4_exit) || (ipv6_exit))
  {
    if (GNUNET_YES !=
        GNUNET_OS_check_helper_binary (binary,
                                       GNUNET_YES,
                                       "gnunet-vpn - - - 169.1.3.7 255.255.255.0"))  // no nat, ipv4 only
    {
      GNUNET_free (binary);
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _ (
                    "`%s' is not SUID or the path is invalid, EXIT will not work\n"),
                  "gnunet-helper-exit");
      GNUNET_SCHEDULER_add_shutdown (&dummy_task,
                                     NULL);
      global_ret = 1;
      return;
    }
  }
  if (! (ipv4_enabled || ipv6_enabled))
  {
    GNUNET_free (binary);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("No useful service enabled.  Exiting.\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  GNUNET_SCHEDULER_add_shutdown (&cleanup,
                                 NULL);
  stats = GNUNET_STATISTICS_create ("exit",
                                    cfg);
  cadet_handle = GNUNET_CADET_connect (cfg);
  if (NULL == cadet_handle)
  {
    GNUNET_free (binary);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  advertise_dns_exit ();
  if (GNUNET_OK !=
      setup_exit_helper_args ())
  {
    GNUNET_free (binary);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  services = GNUNET_CONTAINER_multihashmap_create (65536,
                                                   GNUNET_NO);
  connections_map = GNUNET_CONTAINER_multihashmap_create (65536,
                                                          GNUNET_NO);
  connections_heap = GNUNET_CONTAINER_heap_create (
    GNUNET_CONTAINER_HEAP_ORDER_MIN);
  GNUNET_CONFIGURATION_iterate_sections (cfg,
                                         &read_service_conf,
                                         NULL);

  /* Cadet handle acquired, now open ports and announce regular
     expressions matching our exit */
  if ((GNUNET_YES == ipv4_enabled) &&
      (GNUNET_YES == ipv4_exit))
  {
    GNUNET_CRYPTO_hash (GNUNET_APPLICATION_PORT_IPV4_GATEWAY,
                        strlen (GNUNET_APPLICATION_PORT_IPV4_GATEWAY),
                        &port);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Opening CADET port %s for IPv4 gateway service\n",
                GNUNET_h2s (&port));
    cadet_port4 = GNUNET_CADET_open_port (cadet_handle,
                                          &port,
                                          &new_channel,
                                          NULL,
                                          NULL,
                                          &clean_channel,
                                          handlers);
    policy = NULL;
    if (GNUNET_OK !=
        GNUNET_CONFIGURATION_get_value_string (cfg,
                                               "exit",
                                               "EXIT_RANGE_IPV4_POLICY",
                                               &policy))
      regex = NULL;
    else
      regex = GNUNET_TUN_ipv4policy2regex (policy);
    GNUNET_free_non_null (policy);
    if (NULL != regex)
    {
      (void) GNUNET_asprintf (&prefixed_regex,
                              "%s%s",
                              GNUNET_APPLICATION_TYPE_EXIT_REGEX_PREFIX,
                              regex);
      regex4 = GNUNET_REGEX_announce (cfg,
                                      prefixed_regex,
                                      REGEX_REFRESH_FREQUENCY,
                                      REGEX_MAX_PATH_LEN_IPV4);
      GNUNET_free (regex);
      GNUNET_free (prefixed_regex);
    }
  }

  if ((GNUNET_YES == ipv6_enabled) && (GNUNET_YES == ipv6_exit))
  {
    GNUNET_CRYPTO_hash (GNUNET_APPLICATION_PORT_IPV6_GATEWAY,
                        strlen (GNUNET_APPLICATION_PORT_IPV6_GATEWAY),
                        &port);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Opening CADET port %s for IPv6 gateway service\n",
                GNUNET_h2s (&port));
    cadet_port6 = GNUNET_CADET_open_port (cadet_handle,
                                          &port,
                                          &new_channel,
                                          NULL,
                                          NULL,
                                          &clean_channel,
                                          handlers);
    policy = NULL;
    if (GNUNET_OK !=
        GNUNET_CONFIGURATION_get_value_string (cfg,
                                               "exit",
                                               "EXIT_RANGE_IPV6_POLICY",
                                               &policy))
      regex = NULL;
    else
      regex = GNUNET_TUN_ipv6policy2regex (policy);
    GNUNET_free_non_null (policy);
    if (NULL != regex)
    {
      (void) GNUNET_asprintf (&prefixed_regex,
                              "%s%s",
                              GNUNET_APPLICATION_TYPE_EXIT_REGEX_PREFIX,
                              regex);
      regex6 = GNUNET_REGEX_announce (cfg,
                                      prefixed_regex,
                                      REGEX_REFRESH_FREQUENCY,
                                      REGEX_MAX_PATH_LEN_IPV6);
      GNUNET_free (regex);
      GNUNET_free (prefixed_regex);
    }
  }
  helper_handle = GNUNET_HELPER_start (GNUNET_NO,
                                       binary,
                                       exit_argv,
                                       &message_token,
                                       NULL,
                                       NULL);
  GNUNET_free (binary);
}


/**
 * The main function
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc,
      char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK !=
      GNUNET_STRINGS_get_utf8_args (argc,
                                    argv,
                                    &argc,
                                    &argv))
    return 2;

  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc,
                              argv,
                              "gnunet-daemon-exit",
                              gettext_noop (
                                "Daemon to run to provide an IP exit node for the VPN"),
                              options,
                              &run,
                              NULL)) ? global_ret : 1;
}


/* end of gnunet-daemon-exit.c */
