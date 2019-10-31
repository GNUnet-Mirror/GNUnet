/*
     This file is part of GNUnet.
     Copyright (C) 2010, 2011, 2012, 2016, 2017 Christian Grothoff

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
 * @file vpn/gnunet-service-vpn.c
 * @brief service that opens a virtual interface and allows its clients
 *        to allocate IPs on the virtual interface and to then redirect
 *        IP traffic received on those IPs via the GNUnet cadet
 * @author Philipp Toelke
 * @author Christian Grothoff
 *
 * TODO:
 * - keep multiple peers/cadet channels ready as alternative exits /
 *   detect & recover from channel-to-exit failure gracefully
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_common.h"
#include "gnunet_protocols.h"
#include "gnunet_applications.h"
#include "gnunet_cadet_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet_constants.h"
#include "gnunet_tun_lib.h"
#include "gnunet_regex_service.h"
#include "vpn.h"
#include "exit.h"


/**
 * Maximum number of messages we allow in the queue for cadet.
 */
#define MAX_MESSAGE_QUEUE_SIZE 4


/**
 * State we keep for each of our channels.
 */
struct ChannelState;

/**
 * Information we track for each IP address to determine which channel
 * to send the traffic over to the destination.
 */
struct DestinationEntry;

/**
 * List of channels we keep for each destination port for a given
 * destination entry.
 */
struct DestinationChannel
{
  /**
   * Kept in a DLL.
   */
  struct DestinationChannel *next;

  /**
   * Kept in a DLL.
   */
  struct DestinationChannel *prev;

  /**
   * Destination entry list this `struct DestinationChannel` belongs with.
   */
  struct DestinationEntry *destination;

  /**
   * Destination port this channel state is used for.
   */
  uint16_t destination_port;
};


/**
 * Information we track for each IP address to determine which channel
 * to send the traffic over to the destination.
 */
struct DestinationEntry
{
  /**
   * Key under which this entry is in the 'destination_map' (only valid
   * if 'heap_node != NULL').
   */
  struct GNUNET_HashCode key;

  /**
   * Head of DLL of channels associated with this destination.
   */
  struct DestinationChannel *dt_head;

  /**
   * Tail of DLL of channels associated with this destination.
   */
  struct DestinationChannel *dt_tail;

  /**
   * Entry for this entry in the destination_heap.
   */
  struct GNUNET_CONTAINER_HeapNode *heap_node;

  /**
   * #GNUNET_NO if this is a channel to an Internet-exit,
   * #GNUNET_YES if this channel is to a service.
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
       * The description of the service (only used for service channels).
       */
      struct GNUNET_HashCode service_descriptor;

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
       * IP address of the ultimate destination (only used for exit channels).
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
 * A messages we have in queue for a particular channel.
 */
struct ChannelMessageQueueEntry
{
  /**
   * This is a doubly-linked list.
   */
  struct ChannelMessageQueueEntry *next;

  /**
   * This is a doubly-linked list.
   */
  struct ChannelMessageQueueEntry *prev;

  /**
   * Number of bytes in @e msg.
   */
  size_t len;

  /**
   * Message to transmit, allocated at the end of this struct.
   */
  const void *msg;
};


/**
 * State we keep for each of our channels.
 */
struct ChannelState
{
  /**
   * Information about the channel to use, NULL if no channel
   * is available right now.
   */
  struct GNUNET_CADET_Channel *channel;

  /**
   * Active query with REGEX to locate exit.
   */
  struct GNUNET_REGEX_Search *search;

  /**
   * Entry for this entry in the channel_heap, NULL as long as this
   * channel state is not fully bound.
   */
  struct GNUNET_CONTAINER_HeapNode *heap_node;

  /**
   * Head of list of messages scheduled for transmission.
   */
  struct ChannelMessageQueueEntry *tmq_head;

  /**
   * Tail of list of messages scheduled for transmission.
   */
  struct ChannelMessageQueueEntry *tmq_tail;

  /**
   * Destination to which this channel leads.  Note that
   * this struct is NOT in the destination_map (but a
   * local copy) and that the 'heap_node' should always
   * be NULL.
   */
  struct DestinationEntry destination;

  /**
   * Addess family used for this channel on the local TUN interface.
   */
  int af;

  /**
   * Is this channel new (#GNUNET_NO), or did we exchange messages with the
   * other side already (#GNUNET_YES)?
   */
  int is_established;

  /**
   * Length of the doubly linked 'tmq_head/tmq_tail' list.
   */
  unsigned int tmq_length;

  /**
   * IPPROTO_TCP or IPPROTO_UDP once bound.
   */
  uint8_t protocol;

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
   * that we pick freely within the VPN's channel IP range).
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
 * Return value from #main().
 */
static int global_ret;

/**
 * Configuration we use.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to the cadet service.
 */
static struct GNUNET_CADET_Handle *cadet_handle;

/**
 * Map from IP address to destination information (possibly with a
 * CADET channel handle for fast setup).
 */
static struct GNUNET_CONTAINER_MultiHashMap *destination_map;

/**
 * Min-Heap sorted by activity time to expire old mappings.
 */
static struct GNUNET_CONTAINER_Heap *destination_heap;

/**
 * Map from source and destination address (IP+port) to connection
 * information (mostly with the respective CADET channel handle).
 */
static struct GNUNET_CONTAINER_MultiHashMap *channel_map;

/**
 * Min-Heap sorted by activity time to expire old mappings; values are
 * of type 'struct ChannelState'.
 */
static struct GNUNET_CONTAINER_Heap *channel_heap;

/**
 * Statistics.
 */
static struct GNUNET_STATISTICS_Handle *stats;

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
 * If there are more than this number of address-mappings, old ones
 * will be removed
 */
static unsigned long long max_destination_mappings;

/**
 * If there are more than this number of open channels, old ones
 * will be removed
 */
static unsigned long long max_channel_mappings;


/**
 * Compute the key under which we would store an entry in the
 * #destination_map for the given IP address.
 *
 * @param af address family (AF_INET or AF_INET6)
 * @param address IP address, struct in_addr or struct in6_addr
 * @param key where to store the key
 */
static void
get_destination_key_from_ip (int af,
                             const void *address,
                             struct GNUNET_HashCode *key)
{
  switch (af)
  {
  case AF_INET:
    GNUNET_CRYPTO_hash (address, sizeof(struct in_addr), key);
    break;

  case AF_INET6:
    GNUNET_CRYPTO_hash (address, sizeof(struct in6_addr), key);
    break;

  default:
    GNUNET_assert (0);
    break;
  }
}


/**
 * Compute the key under which we would store an entry in the
 * channel_map for the given socket address pair.
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
get_channel_key_from_ips (int af,
                          uint8_t protocol,
                          const void *source_ip,
                          uint16_t source_port,
                          const void *destination_ip,
                          uint16_t destination_port,
                          struct GNUNET_HashCode *key)
{
  char *off;

  memset (key, 0, sizeof(struct GNUNET_HashCode));
  /* the GNUnet hashmap only uses the first sizeof(unsigned int) of the hash,
     so we put the ports in there (and hope for few collisions) */
  off = (char *) key;
  GNUNET_memcpy (off, &source_port, sizeof(uint16_t));
  off += sizeof(uint16_t);
  GNUNET_memcpy (off, &destination_port, sizeof(uint16_t));
  off += sizeof(uint16_t);
  switch (af)
  {
  case AF_INET:
    GNUNET_memcpy (off, source_ip, sizeof(struct in_addr));
    off += sizeof(struct in_addr);
    GNUNET_memcpy (off, destination_ip, sizeof(struct in_addr));
    off += sizeof(struct in_addr);
    break;

  case AF_INET6:
    GNUNET_memcpy (off, source_ip, sizeof(struct in6_addr));
    off += sizeof(struct in6_addr);
    GNUNET_memcpy (off, destination_ip, sizeof(struct in6_addr));
    off += sizeof(struct in6_addr);
    break;

  default:
    GNUNET_assert (0);
    break;
  }
  GNUNET_memcpy (off, &protocol, sizeof(uint8_t));
  /* off += sizeof (uint8_t);  */
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
send_client_reply (struct GNUNET_SERVICE_Client *client,
                   uint64_t request_id,
                   int result_af,
                   const void *addr)
{
  struct GNUNET_MQ_Envelope *env;
  struct RedirectToIpResponseMessage *res;
  size_t rlen;

  switch (result_af)
  {
  case AF_INET:
    rlen = sizeof(struct in_addr);
    break;

  case AF_INET6:
    rlen = sizeof(struct in6_addr);
    break;

  case AF_UNSPEC:
    rlen = 0;
    break;

  default:
    GNUNET_assert (0);
    return;
  }
  env = GNUNET_MQ_msg_extra (res, rlen, GNUNET_MESSAGE_TYPE_VPN_CLIENT_USE_IP);
  res->result_af = htonl (result_af);
  res->request_id = request_id;
  GNUNET_memcpy (&res[1], addr, rlen);
  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (client), env);
}


/**
 * Free resources associated with a channel state.
 *
 * @param ts state to free
 */
static void
free_channel_state (struct ChannelState *ts)
{
  struct GNUNET_HashCode key;
  struct ChannelMessageQueueEntry *tnq;
  struct GNUNET_CADET_Channel *channel;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Cleaning up channel state\n");
  if (NULL != (channel = ts->channel))
  {
    ts->channel = NULL;
    GNUNET_CADET_channel_destroy (channel);
    return;
  }
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# Active channels"),
                            -1,
                            GNUNET_NO);
  while (NULL != (tnq = ts->tmq_head))
  {
    GNUNET_CONTAINER_DLL_remove (ts->tmq_head, ts->tmq_tail, tnq);
    ts->tmq_length--;
    GNUNET_free (tnq);
  }
  GNUNET_assert (0 == ts->tmq_length);
  GNUNET_assert (NULL == ts->destination.heap_node);
  if (NULL != ts->search)
  {
    GNUNET_REGEX_search_cancel (ts->search);
    ts->search = NULL;
  }
  if (NULL != ts->heap_node)
  {
    GNUNET_CONTAINER_heap_remove_node (ts->heap_node);
    ts->heap_node = NULL;
    get_channel_key_from_ips (ts->af,
                              ts->protocol,
                              &ts->source_ip,
                              ts->source_port,
                              &ts->destination_ip,
                              ts->destination_port,
                              &key);
    GNUNET_assert (
      GNUNET_YES ==
      GNUNET_CONTAINER_multihashmap_remove (channel_map, &key, ts));
  }
  GNUNET_free (ts);
}


/**
 * Add the given message to the given channel and trigger the
 * transmission process.
 *
 * @param ts channel to queue the message for
 * @param env message to queue
 */
static void
send_to_channel (struct ChannelState *ts, struct GNUNET_MQ_Envelope *env)
{
  struct GNUNET_MQ_Handle *mq;

  GNUNET_assert (NULL != ts->channel);
  mq = GNUNET_CADET_get_mq (ts->channel);
  GNUNET_MQ_env_set_options (env,
                             GNUNET_MQ_PRIO_BEST_EFFORT
                             | GNUNET_MQ_PREF_OUT_OF_ORDER);
  GNUNET_MQ_send (mq, env);
  if (GNUNET_MQ_get_length (mq) > MAX_MESSAGE_QUEUE_SIZE)
  {
    env = GNUNET_MQ_unsent_head (mq);
    GNUNET_assert (NULL != env);
    GNUNET_STATISTICS_update (stats,
                              gettext_noop (
                                "# Messages dropped in cadet queue (overflow)"),
                              1,
                              GNUNET_NO);
    GNUNET_MQ_discard (env);
  }
}


/**
 * Output destination of a channel for diagnostics.
 *
 * @param de destination to process
 * @return diagnostic string describing destination
 */
static const char *
print_channel_destination (const struct DestinationEntry *de)
{
  static char dest[256];

  if (de->is_service)
  {
    GNUNET_snprintf (dest,
                     sizeof(dest),
                     "HS: %s-%s",
                     GNUNET_i2s (&de->details.service_destination.target),
                     GNUNET_h2s (
                       &de->details.service_destination.service_descriptor));
  }
  else
  {
    inet_ntop (de->details.exit_destination.af,
               &de->details.exit_destination.ip,
               dest,
               sizeof(dest));
  }
  return dest;
}


/**
 * Function called whenever a channel is destroyed.  Should clean up
 * any associated state.
 *
 * @param cls our `struct ChannelState`
 * @param channel connection to the other end (henceforth invalid)
 */
static void
channel_cleaner (void *cls, const struct GNUNET_CADET_Channel *channel)
{
  struct ChannelState *ts = cls;

  ts->channel =
    NULL; /* we must not call GNUNET_CADET_channel_destroy() anymore */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "CADET notified us about death of channel to `%s'\n",
              print_channel_destination (&ts->destination));
  free_channel_state (ts);
}


/**
 * Synthesize a plausible ICMP payload for an ICMP error
 * response on the given channel.
 *
 * @param ts channel information
 * @param ipp IPv4 header to fill in (ICMP payload)
 * @param udp "UDP" header to fill in (ICMP payload); might actually
 *            also be the first 8 bytes of the TCP header
 */
static void
make_up_icmpv4_payload (struct ChannelState *ts,
                        struct GNUNET_TUN_IPv4Header *ipp,
                        struct GNUNET_TUN_UdpHeader *udp)
{
  GNUNET_TUN_initialize_ipv4_header (ipp,
                                     ts->protocol,
                                     sizeof(struct GNUNET_TUN_TcpHeader),
                                     &ts->source_ip.v4,
                                     &ts->destination_ip.v4);
  udp->source_port = htons (ts->source_port);
  udp->destination_port = htons (ts->destination_port);
  udp->len = htons (0);
  udp->crc = htons (0);
}


/**
 * Synthesize a plausible ICMP payload for an ICMP error
 * response on the given channel.
 *
 * @param ts channel information
 * @param ipp IPv6 header to fill in (ICMP payload)
 * @param udp "UDP" header to fill in (ICMP payload); might actually
 *            also be the first 8 bytes of the TCP header
 */
static void
make_up_icmpv6_payload (struct ChannelState *ts,
                        struct GNUNET_TUN_IPv6Header *ipp,
                        struct GNUNET_TUN_UdpHeader *udp)
{
  GNUNET_TUN_initialize_ipv6_header (ipp,
                                     ts->protocol,
                                     sizeof(struct GNUNET_TUN_TcpHeader),
                                     &ts->source_ip.v6,
                                     &ts->destination_ip.v6);
  udp->source_port = htons (ts->source_port);
  udp->destination_port = htons (ts->destination_port);
  udp->len = htons (0);
  udp->crc = htons (0);
}


/**
 * We got an ICMP packet back from the CADET channel.  Check it is OK.
 *
 * @param cls our `struct ChannelState *`
 * @param message the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
check_icmp_back (void *cls, const struct GNUNET_EXIT_IcmpToVPNMessage *i2v)
{
  struct ChannelState *ts = cls;

  if (NULL == ts->heap_node)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (AF_UNSPEC == ts->af)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * We got an ICMP packet back from the CADET channel.  Pass it on to the
 * local virtual interface via the helper.
 *
 * @param cls our `struct ChannelState *`
 * @param message the actual message
 */
static void
handle_icmp_back (void *cls, const struct GNUNET_EXIT_IcmpToVPNMessage *i2v)
{
  struct ChannelState *ts = cls;
  size_t mlen;

  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# ICMP packets received from cadet"),
                            1,
                            GNUNET_NO);
  mlen =
    ntohs (i2v->header.size) - sizeof(struct GNUNET_EXIT_IcmpToVPNMessage);
  {
    char sbuf[INET6_ADDRSTRLEN];
    char dbuf[INET6_ADDRSTRLEN];

    GNUNET_log (
      GNUNET_ERROR_TYPE_DEBUG,
      "Received ICMP packet from cadet, sending %u bytes from %s -> %s via TUN\n",
      (unsigned int) mlen,
      inet_ntop (ts->af, &ts->destination_ip, sbuf, sizeof(sbuf)),
      inet_ntop (ts->af, &ts->source_ip, dbuf, sizeof(dbuf)));
  }
  switch (ts->af)
  {
  case AF_INET: {
      size_t size = sizeof(struct GNUNET_TUN_IPv4Header)
                    + sizeof(struct GNUNET_TUN_IcmpHeader)
                    + sizeof(struct GNUNET_MessageHeader)
                    + sizeof(struct GNUNET_TUN_Layer2PacketHeader) + mlen;
      {
        /* reserve some extra space in case we have an ICMP type here where
             we will need to make up the payload ourselves */
        char buf[size + sizeof(struct GNUNET_TUN_IPv4Header) + 8] GNUNET_ALIGN;
        struct GNUNET_MessageHeader *msg = (struct GNUNET_MessageHeader *) buf;
        struct GNUNET_TUN_Layer2PacketHeader *tun =
          (struct GNUNET_TUN_Layer2PacketHeader *) &msg[1];
        struct GNUNET_TUN_IPv4Header *ipv4 =
          (struct GNUNET_TUN_IPv4Header *) &tun[1];
        struct GNUNET_TUN_IcmpHeader *icmp =
          (struct GNUNET_TUN_IcmpHeader *) &ipv4[1];
        msg->type = htons (GNUNET_MESSAGE_TYPE_VPN_HELPER);
        tun->flags = htons (0);
        tun->proto = htons (ETH_P_IPV4);
        GNUNET_TUN_initialize_ipv4_header (ipv4,
                                           IPPROTO_ICMP,
                                           sizeof(struct GNUNET_TUN_IcmpHeader)
                                           + mlen,
                                           &ts->destination_ip.v4,
                                           &ts->source_ip.v4);
        *icmp = i2v->icmp_header;
        GNUNET_memcpy (&icmp[1], &i2v[1], mlen);
        /* For some ICMP types, we need to adjust (make up) the payload here.
             Also, depending on the AF used on the other side, we have to
             do ICMP PT (translate ICMP types) */
        switch (ntohl (i2v->af))
        {
        case AF_INET:
          switch (icmp->type)
          {
          case GNUNET_TUN_ICMPTYPE_ECHO_REPLY:
          case GNUNET_TUN_ICMPTYPE_ECHO_REQUEST:
            break;

          case GNUNET_TUN_ICMPTYPE_DESTINATION_UNREACHABLE:
          case GNUNET_TUN_ICMPTYPE_SOURCE_QUENCH:
          case GNUNET_TUN_ICMPTYPE_TIME_EXCEEDED: {
              struct GNUNET_TUN_IPv4Header *ipp =
                (struct GNUNET_TUN_IPv4Header *) &icmp[1];
              struct GNUNET_TUN_UdpHeader *udp =
                (struct GNUNET_TUN_UdpHeader *) &ipp[1];

              if (mlen != 0)
              {
                /* sender did not strip ICMP payload? */
                GNUNET_break_op (0);
                return;
              }
              size += sizeof(struct GNUNET_TUN_IPv4Header) + 8;
              GNUNET_assert (8 == sizeof(struct GNUNET_TUN_UdpHeader));
              make_up_icmpv4_payload (ts, ipp, udp);
            }
            break;

          default:
            GNUNET_break_op (0);
            GNUNET_STATISTICS_update (
              stats,
              gettext_noop ("# ICMPv4 packets dropped (type not allowed)"),
              1,
              GNUNET_NO);
            return;
          }
          /* end AF_INET */
          break;

        case AF_INET6:
          /* ICMP PT 6-to-4 and possibly making up payloads */
          switch (icmp->type)
          {
          case GNUNET_TUN_ICMPTYPE6_DESTINATION_UNREACHABLE:
            icmp->type = GNUNET_TUN_ICMPTYPE_DESTINATION_UNREACHABLE;
            {
              struct GNUNET_TUN_IPv4Header *ipp =
                (struct GNUNET_TUN_IPv4Header *) &icmp[1];
              struct GNUNET_TUN_UdpHeader *udp =
                (struct GNUNET_TUN_UdpHeader *) &ipp[1];

              if (mlen != 0)
              {
                /* sender did not strip ICMP payload? */
                GNUNET_break_op (0);
                return;
              }
              size += sizeof(struct GNUNET_TUN_IPv4Header) + 8;
              GNUNET_assert (8 == sizeof(struct GNUNET_TUN_UdpHeader));
              make_up_icmpv4_payload (ts, ipp, udp);
            }
            break;

          case GNUNET_TUN_ICMPTYPE6_TIME_EXCEEDED:
            icmp->type = GNUNET_TUN_ICMPTYPE_TIME_EXCEEDED;
            {
              struct GNUNET_TUN_IPv4Header *ipp =
                (struct GNUNET_TUN_IPv4Header *) &icmp[1];
              struct GNUNET_TUN_UdpHeader *udp =
                (struct GNUNET_TUN_UdpHeader *) &ipp[1];

              if (mlen != 0)
              {
                /* sender did not strip ICMP payload? */
                GNUNET_break_op (0);
                return;
              }
              size += sizeof(struct GNUNET_TUN_IPv4Header) + 8;
              GNUNET_assert (8 == sizeof(struct GNUNET_TUN_UdpHeader));
              make_up_icmpv4_payload (ts, ipp, udp);
            }
            break;

          case GNUNET_TUN_ICMPTYPE6_PACKET_TOO_BIG:
          case GNUNET_TUN_ICMPTYPE6_PARAMETER_PROBLEM:
            GNUNET_STATISTICS_update (
              stats,
              gettext_noop ("# ICMPv6 packets dropped (impossible PT to v4)"),
              1,
              GNUNET_NO);
            return;

          case GNUNET_TUN_ICMPTYPE6_ECHO_REQUEST:
            icmp->type = GNUNET_TUN_ICMPTYPE_ECHO_REQUEST;
            break;

          case GNUNET_TUN_ICMPTYPE6_ECHO_REPLY:
            icmp->type = GNUNET_TUN_ICMPTYPE_ECHO_REPLY;
            break;

          default:
            GNUNET_break_op (0);
            GNUNET_STATISTICS_update (
              stats,
              gettext_noop ("# ICMPv6 packets dropped (type not allowed)"),
              1,
              GNUNET_NO);
            return;
          }
          /* end AF_INET6 */
          break;

        default:
          GNUNET_break_op (0);
          return;
        }
        msg->size = htons (size);
        GNUNET_TUN_calculate_icmp_checksum (icmp, &i2v[1], mlen);
        (void) GNUNET_HELPER_send (helper_handle, msg, GNUNET_YES, NULL, NULL);
      }
    }
    break;

  case AF_INET6: {
      size_t size = sizeof(struct GNUNET_TUN_IPv6Header)
                    + sizeof(struct GNUNET_TUN_IcmpHeader)
                    + sizeof(struct GNUNET_MessageHeader)
                    + sizeof(struct GNUNET_TUN_Layer2PacketHeader) + mlen;
      {
        char buf[size + sizeof(struct GNUNET_TUN_IPv6Header) + 8] GNUNET_ALIGN;
        struct GNUNET_MessageHeader *msg = (struct GNUNET_MessageHeader *) buf;
        struct GNUNET_TUN_Layer2PacketHeader *tun =
          (struct GNUNET_TUN_Layer2PacketHeader *) &msg[1];
        struct GNUNET_TUN_IPv6Header *ipv6 =
          (struct GNUNET_TUN_IPv6Header *) &tun[1];
        struct GNUNET_TUN_IcmpHeader *icmp =
          (struct GNUNET_TUN_IcmpHeader *) &ipv6[1];
        msg->type = htons (GNUNET_MESSAGE_TYPE_VPN_HELPER);
        tun->flags = htons (0);
        tun->proto = htons (ETH_P_IPV6);
        GNUNET_TUN_initialize_ipv6_header (ipv6,
                                           IPPROTO_ICMPV6,
                                           sizeof(struct GNUNET_TUN_IcmpHeader)
                                           + mlen,
                                           &ts->destination_ip.v6,
                                           &ts->source_ip.v6);
        *icmp = i2v->icmp_header;
        GNUNET_memcpy (&icmp[1], &i2v[1], mlen);

        /* For some ICMP types, we need to adjust (make up) the payload here.
             Also, depending on the AF used on the other side, we have to
             do ICMP PT (translate ICMP types) */
        switch (ntohl (i2v->af))
        {
        case AF_INET:
          /* ICMP PT 4-to-6 and possibly making up payloads */
          switch (icmp->type)
          {
          case GNUNET_TUN_ICMPTYPE_ECHO_REPLY:
            icmp->type = GNUNET_TUN_ICMPTYPE6_ECHO_REPLY;
            break;

          case GNUNET_TUN_ICMPTYPE_ECHO_REQUEST:
            icmp->type = GNUNET_TUN_ICMPTYPE6_ECHO_REQUEST;
            break;

          case GNUNET_TUN_ICMPTYPE_DESTINATION_UNREACHABLE:
            icmp->type = GNUNET_TUN_ICMPTYPE6_DESTINATION_UNREACHABLE;
            {
              struct GNUNET_TUN_IPv6Header *ipp =
                (struct GNUNET_TUN_IPv6Header *) &icmp[1];
              struct GNUNET_TUN_UdpHeader *udp =
                (struct GNUNET_TUN_UdpHeader *) &ipp[1];

              if (mlen != 0)
              {
                /* sender did not strip ICMP payload? */
                GNUNET_break_op (0);
                return;
              }
              size += sizeof(struct GNUNET_TUN_IPv6Header) + 8;
              GNUNET_assert (8 == sizeof(struct GNUNET_TUN_UdpHeader));
              make_up_icmpv6_payload (ts, ipp, udp);
            }
            break;

          case GNUNET_TUN_ICMPTYPE_TIME_EXCEEDED:
            icmp->type = GNUNET_TUN_ICMPTYPE6_TIME_EXCEEDED;
            {
              struct GNUNET_TUN_IPv6Header *ipp =
                (struct GNUNET_TUN_IPv6Header *) &icmp[1];
              struct GNUNET_TUN_UdpHeader *udp =
                (struct GNUNET_TUN_UdpHeader *) &ipp[1];

              if (mlen != 0)
              {
                /* sender did not strip ICMP payload? */
                GNUNET_break_op (0);
                return;
              }
              size += sizeof(struct GNUNET_TUN_IPv6Header) + 8;
              GNUNET_assert (8 == sizeof(struct GNUNET_TUN_UdpHeader));
              make_up_icmpv6_payload (ts, ipp, udp);
            }
            break;

          case GNUNET_TUN_ICMPTYPE_SOURCE_QUENCH:
            GNUNET_STATISTICS_update (
              stats,
              gettext_noop ("# ICMPv4 packets dropped (impossible PT to v6)"),
              1,
              GNUNET_NO);
            return;

          default:
            GNUNET_break_op (0);
            GNUNET_STATISTICS_update (
              stats,
              gettext_noop ("# ICMPv4 packets dropped (type not allowed)"),
              1,
              GNUNET_NO);
            return;
          }
          /* end AF_INET */
          break;

        case AF_INET6:
          switch (icmp->type)
          {
          case GNUNET_TUN_ICMPTYPE6_DESTINATION_UNREACHABLE:
          case GNUNET_TUN_ICMPTYPE6_TIME_EXCEEDED:
          case GNUNET_TUN_ICMPTYPE6_PACKET_TOO_BIG:
          case GNUNET_TUN_ICMPTYPE6_PARAMETER_PROBLEM: {
              struct GNUNET_TUN_IPv6Header *ipp =
                (struct GNUNET_TUN_IPv6Header *) &icmp[1];
              struct GNUNET_TUN_UdpHeader *udp =
                (struct GNUNET_TUN_UdpHeader *) &ipp[1];

              if (mlen != 0)
              {
                /* sender did not strip ICMP payload? */
                GNUNET_break_op (0);
                return;
              }
              size += sizeof(struct GNUNET_TUN_IPv6Header) + 8;
              GNUNET_assert (8 == sizeof(struct GNUNET_TUN_UdpHeader));
              make_up_icmpv6_payload (ts, ipp, udp);
            }
            break;

          case GNUNET_TUN_ICMPTYPE6_ECHO_REQUEST:
            break;

          default:
            GNUNET_break_op (0);
            GNUNET_STATISTICS_update (
              stats,
              gettext_noop ("# ICMPv6 packets dropped (type not allowed)"),
              1,
              GNUNET_NO);
            return;
          }
          /* end AF_INET6 */
          break;

        default:
          GNUNET_break_op (0);
          return;
        }
        msg->size = htons (size);
        GNUNET_TUN_calculate_icmp_checksum (icmp, &i2v[1], mlen);
        (void) GNUNET_HELPER_send (helper_handle, msg, GNUNET_YES, NULL, NULL);
      }
    }
    break;

  default:
    GNUNET_assert (0);
  }
  GNUNET_CONTAINER_heap_update_cost (ts->heap_node,
                                     GNUNET_TIME_absolute_get ().abs_value_us);
  GNUNET_CADET_receive_done (ts->channel);
}


/**
 * We got a UDP packet back from the CADET channel.  Check that it is OK.
 *
 * @param cls our `struct ChannelState *`
 * @param reply the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
check_udp_back (void *cls, const struct GNUNET_EXIT_UdpReplyMessage *reply)
{
  struct ChannelState *ts = cls;

  if (NULL == ts->heap_node)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (AF_UNSPEC == ts->af)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * We got a UDP packet back from the CADET channel.  Pass it on to the
 * local virtual interface via the helper.
 *
 * @param cls our `struct ChannelState *`
 * @param reply the actual message
 */
static void
handle_udp_back (void *cls, const struct GNUNET_EXIT_UdpReplyMessage *reply)
{
  struct ChannelState *ts = cls;
  size_t mlen;

  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# UDP packets received from cadet"),
                            1,
                            GNUNET_NO);
  mlen =
    ntohs (reply->header.size) - sizeof(struct GNUNET_EXIT_UdpReplyMessage);
  {
    char sbuf[INET6_ADDRSTRLEN];
    char dbuf[INET6_ADDRSTRLEN];

    GNUNET_log (
      GNUNET_ERROR_TYPE_DEBUG,
      "Received UDP reply from cadet, sending %u bytes from [%s]:%u -> [%s]:%u via TUN\n",
      (unsigned int) mlen,
      inet_ntop (ts->af, &ts->destination_ip, sbuf, sizeof(sbuf)),
      ts->destination_port,
      inet_ntop (ts->af, &ts->source_ip, dbuf, sizeof(dbuf)),
      ts->source_port);
  }
  switch (ts->af)
  {
  case AF_INET: {
      size_t size = sizeof(struct GNUNET_TUN_IPv4Header)
                    + sizeof(struct GNUNET_TUN_UdpHeader)
                    + sizeof(struct GNUNET_MessageHeader)
                    + sizeof(struct GNUNET_TUN_Layer2PacketHeader) + mlen;
      {
        char buf[size] GNUNET_ALIGN;
        struct GNUNET_MessageHeader *msg = (struct GNUNET_MessageHeader *) buf;
        struct GNUNET_TUN_Layer2PacketHeader *tun =
          (struct GNUNET_TUN_Layer2PacketHeader *) &msg[1];
        struct GNUNET_TUN_IPv4Header *ipv4 =
          (struct GNUNET_TUN_IPv4Header *) &tun[1];
        struct GNUNET_TUN_UdpHeader *udp =
          (struct GNUNET_TUN_UdpHeader *) &ipv4[1];
        msg->type = htons (GNUNET_MESSAGE_TYPE_VPN_HELPER);
        msg->size = htons (size);
        tun->flags = htons (0);
        tun->proto = htons (ETH_P_IPV4);
        GNUNET_TUN_initialize_ipv4_header (ipv4,
                                           IPPROTO_UDP,
                                           sizeof(struct GNUNET_TUN_UdpHeader)
                                           + mlen,
                                           &ts->destination_ip.v4,
                                           &ts->source_ip.v4);
        if (0 == ntohs (reply->source_port))
          udp->source_port = htons (ts->destination_port);
        else
          udp->source_port = reply->source_port;
        if (0 == ntohs (reply->destination_port))
          udp->destination_port = htons (ts->source_port);
        else
          udp->destination_port = reply->destination_port;
        udp->len = htons (mlen + sizeof(struct GNUNET_TUN_UdpHeader));
        GNUNET_TUN_calculate_udp4_checksum (ipv4, udp, &reply[1], mlen);
        GNUNET_memcpy (&udp[1], &reply[1], mlen);
        (void) GNUNET_HELPER_send (helper_handle, msg, GNUNET_YES, NULL, NULL);
      }
    }
    break;

  case AF_INET6: {
      size_t size = sizeof(struct GNUNET_TUN_IPv6Header)
                    + sizeof(struct GNUNET_TUN_UdpHeader)
                    + sizeof(struct GNUNET_MessageHeader)
                    + sizeof(struct GNUNET_TUN_Layer2PacketHeader) + mlen;
      {
        char buf[size] GNUNET_ALIGN;
        struct GNUNET_MessageHeader *msg = (struct GNUNET_MessageHeader *) buf;
        struct GNUNET_TUN_Layer2PacketHeader *tun =
          (struct GNUNET_TUN_Layer2PacketHeader *) &msg[1];
        struct GNUNET_TUN_IPv6Header *ipv6 =
          (struct GNUNET_TUN_IPv6Header *) &tun[1];
        struct GNUNET_TUN_UdpHeader *udp =
          (struct GNUNET_TUN_UdpHeader *) &ipv6[1];
        msg->type = htons (GNUNET_MESSAGE_TYPE_VPN_HELPER);
        msg->size = htons (size);
        tun->flags = htons (0);
        tun->proto = htons (ETH_P_IPV6);
        GNUNET_TUN_initialize_ipv6_header (ipv6,
                                           IPPROTO_UDP,
                                           sizeof(struct GNUNET_TUN_UdpHeader)
                                           + mlen,
                                           &ts->destination_ip.v6,
                                           &ts->source_ip.v6);
        if (0 == ntohs (reply->source_port))
          udp->source_port = htons (ts->destination_port);
        else
          udp->source_port = reply->source_port;
        if (0 == ntohs (reply->destination_port))
          udp->destination_port = htons (ts->source_port);
        else
          udp->destination_port = reply->destination_port;
        udp->len = htons (mlen + sizeof(struct GNUNET_TUN_UdpHeader));
        GNUNET_TUN_calculate_udp6_checksum (ipv6, udp, &reply[1], mlen);
        GNUNET_memcpy (&udp[1], &reply[1], mlen);
        (void) GNUNET_HELPER_send (helper_handle, msg, GNUNET_YES, NULL, NULL);
      }
    }
    break;

  default:
    GNUNET_assert (0);
  }
  GNUNET_CONTAINER_heap_update_cost (ts->heap_node,
                                     GNUNET_TIME_absolute_get ().abs_value_us);
  GNUNET_CADET_receive_done (ts->channel);
}


/**
 * We got a TCP packet back from the CADET channel.  Check it is OK.
 *
 * @param cls our `struct ChannelState *`
 * @param data the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
check_tcp_back (void *cls, const struct GNUNET_EXIT_TcpDataMessage *data)
{
  struct ChannelState *ts = cls;

  if (NULL == ts->heap_node)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (data->tcp_header.off * 4 < sizeof(struct GNUNET_TUN_TcpHeader))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * We got a TCP packet back from the CADET channel.  Pass it on to the
 * local virtual interface via the helper.
 *
 * @param cls our `struct ChannelState *`
 * @param data the actual message
 */
static void
handle_tcp_back (void *cls, const struct GNUNET_EXIT_TcpDataMessage *data)
{
  struct ChannelState *ts = cls;
  size_t mlen;

  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# TCP packets received from cadet"),
                            1,
                            GNUNET_NO);
  mlen = ntohs (data->header.size) - sizeof(struct GNUNET_EXIT_TcpDataMessage);
  {
    char sbuf[INET6_ADDRSTRLEN];
    char dbuf[INET6_ADDRSTRLEN];

    GNUNET_log (
      GNUNET_ERROR_TYPE_DEBUG,
      "Received TCP reply from cadet, sending %u bytes from [%s]:%u -> [%s]:%u via TUN\n",
      (unsigned int) mlen,
      inet_ntop (ts->af, &ts->destination_ip, sbuf, sizeof(sbuf)),
      ts->destination_port,
      inet_ntop (ts->af, &ts->source_ip, dbuf, sizeof(dbuf)),
      ts->source_port);
  }
  switch (ts->af)
  {
  case AF_INET: {
      size_t size = sizeof(struct GNUNET_TUN_IPv4Header)
                    + sizeof(struct GNUNET_TUN_TcpHeader)
                    + sizeof(struct GNUNET_MessageHeader)
                    + sizeof(struct GNUNET_TUN_Layer2PacketHeader) + mlen;
      {
        char buf[size] GNUNET_ALIGN;
        struct GNUNET_MessageHeader *msg = (struct GNUNET_MessageHeader *) buf;
        struct GNUNET_TUN_Layer2PacketHeader *tun =
          (struct GNUNET_TUN_Layer2PacketHeader *) &msg[1];
        struct GNUNET_TUN_IPv4Header *ipv4 =
          (struct GNUNET_TUN_IPv4Header *) &tun[1];
        struct GNUNET_TUN_TcpHeader *tcp =
          (struct GNUNET_TUN_TcpHeader *) &ipv4[1];
        msg->type = htons (GNUNET_MESSAGE_TYPE_VPN_HELPER);
        msg->size = htons (size);
        tun->flags = htons (0);
        tun->proto = htons (ETH_P_IPV4);
        GNUNET_TUN_initialize_ipv4_header (ipv4,
                                           IPPROTO_TCP,
                                           sizeof(struct GNUNET_TUN_TcpHeader)
                                           + mlen,
                                           &ts->destination_ip.v4,
                                           &ts->source_ip.v4);
        *tcp = data->tcp_header;
        tcp->source_port = htons (ts->destination_port);
        tcp->destination_port = htons (ts->source_port);
        GNUNET_TUN_calculate_tcp4_checksum (ipv4, tcp, &data[1], mlen);
        GNUNET_memcpy (&tcp[1], &data[1], mlen);
        (void) GNUNET_HELPER_send (helper_handle, msg, GNUNET_YES, NULL, NULL);
      }
    }
    break;

  case AF_INET6: {
      size_t size = sizeof(struct GNUNET_TUN_IPv6Header)
                    + sizeof(struct GNUNET_TUN_TcpHeader)
                    + sizeof(struct GNUNET_MessageHeader)
                    + sizeof(struct GNUNET_TUN_Layer2PacketHeader) + mlen;
      {
        char buf[size] GNUNET_ALIGN;
        struct GNUNET_MessageHeader *msg = (struct GNUNET_MessageHeader *) buf;
        struct GNUNET_TUN_Layer2PacketHeader *tun =
          (struct GNUNET_TUN_Layer2PacketHeader *) &msg[1];
        struct GNUNET_TUN_IPv6Header *ipv6 =
          (struct GNUNET_TUN_IPv6Header *) &tun[1];
        struct GNUNET_TUN_TcpHeader *tcp =
          (struct GNUNET_TUN_TcpHeader *) &ipv6[1];
        msg->type = htons (GNUNET_MESSAGE_TYPE_VPN_HELPER);
        msg->size = htons (size);
        tun->flags = htons (0);
        tun->proto = htons (ETH_P_IPV6);
        GNUNET_TUN_initialize_ipv6_header (ipv6,
                                           IPPROTO_TCP,
                                           sizeof(struct GNUNET_TUN_TcpHeader)
                                           + mlen,
                                           &ts->destination_ip.v6,
                                           &ts->source_ip.v6);
        *tcp = data->tcp_header;
        tcp->source_port = htons (ts->destination_port);
        tcp->destination_port = htons (ts->source_port);
        GNUNET_TUN_calculate_tcp6_checksum (ipv6, tcp, &data[1], mlen);
        GNUNET_memcpy (&tcp[1], &data[1], mlen);
        (void) GNUNET_HELPER_send (helper_handle, msg, GNUNET_YES, NULL, NULL);
      }
    }
    break;
  }
  GNUNET_CONTAINER_heap_update_cost (ts->heap_node,
                                     GNUNET_TIME_absolute_get ().abs_value_us);
  GNUNET_CADET_receive_done (ts->channel);
}


/**
 * Create a channel for @a ts to @a target at @a port
 *
 * @param ts channel state to create the channel for
 * @param target peer to connect to
 * @param port destination port
 * @return the channel handle
 */
static struct GNUNET_CADET_Channel *
create_channel (struct ChannelState *ts,
                const struct GNUNET_PeerIdentity *target,
                const struct GNUNET_HashCode *port)
{
  struct GNUNET_MQ_MessageHandler cadet_handlers[] =
  { GNUNET_MQ_hd_var_size (udp_back,
                           GNUNET_MESSAGE_TYPE_VPN_UDP_REPLY,
                           struct GNUNET_EXIT_UdpReplyMessage,
                           ts),
    GNUNET_MQ_hd_var_size (tcp_back,
                           GNUNET_MESSAGE_TYPE_VPN_TCP_DATA_TO_VPN,
                           struct GNUNET_EXIT_TcpDataMessage,
                           ts),
    GNUNET_MQ_hd_var_size (icmp_back,
                           GNUNET_MESSAGE_TYPE_VPN_ICMP_TO_VPN,
                           struct GNUNET_EXIT_IcmpToVPNMessage,
                           ts),
    GNUNET_MQ_handler_end () };

  return GNUNET_CADET_channel_create (cadet_handle,
                                      ts,
                                      target,
                                      port,
                                      NULL,
                                      &channel_cleaner,
                                      cadet_handlers);
}


/**
 * Regex has found a potential exit peer for us; consider using it.
 *
 * @param cls the `struct ChannelState`
 * @param id Peer providing a regex that matches the string.
 * @param get_path Path of the get request.
 * @param get_path_length Lenght of @a get_path.
 * @param put_path Path of the put request.
 * @param put_path_length Length of the @a put_path.
 */
static void
handle_regex_result (void *cls,
                     const struct GNUNET_PeerIdentity *id,
                     const struct GNUNET_PeerIdentity *get_path,
                     unsigned int get_path_length,
                     const struct GNUNET_PeerIdentity *put_path,
                     unsigned int put_path_length)
{
  struct ChannelState *ts = cls;
  struct GNUNET_HashCode port;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Exit %s found for destination %s!\n",
              GNUNET_i2s (id),
              print_channel_destination (&ts->destination));
  GNUNET_REGEX_search_cancel (ts->search);
  ts->search = NULL;
  switch (ts->af)
  {
  case AF_INET:
    /* these must match the strings used in gnunet-daemon-exit */
    GNUNET_CRYPTO_hash (GNUNET_APPLICATION_PORT_IPV4_GATEWAY,
                        strlen (GNUNET_APPLICATION_PORT_IPV4_GATEWAY),
                        &port);
    break;

  case AF_INET6:
    /* these must match the strings used in gnunet-daemon-exit */
    GNUNET_CRYPTO_hash (GNUNET_APPLICATION_PORT_IPV6_GATEWAY,
                        strlen (GNUNET_APPLICATION_PORT_IPV6_GATEWAY),
                        &port);
    break;

  default:
    GNUNET_break (0);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Creating tunnel to %s for destination %s!\n",
              GNUNET_i2s (id),
              print_channel_destination (&ts->destination));
  ts->channel = create_channel (ts, id, &port);
}


/**
 * Initialize the given destination entry's cadet channel.
 *
 * @param dt destination channel for which we need to setup a channel
 * @param client_af address family of the address returned to the client
 * @return channel state of the channel that was created
 */
static struct ChannelState *
create_channel_to_destination (struct DestinationChannel *dt, int client_af)
{
  struct ChannelState *ts;

  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# Cadet channels created"),
                            1,
                            GNUNET_NO);
  ts = GNUNET_new (struct ChannelState);
  ts->af = client_af;
  ts->destination = *dt->destination;
  ts->destination.heap_node = NULL; /* copy is NOT in destination heap */
  ts->destination_port = dt->destination_port;
  if (dt->destination->is_service)
  {
    struct GNUNET_HashCode cadet_port;

    GNUNET_TUN_compute_service_cadet_port (&ts->destination.details
                                           .service_destination
                                           .service_descriptor,
                                           ts->destination_port,
                                           &cadet_port);
    ts->channel =
      create_channel (ts,
                      &dt->destination->details.service_destination.target,
                      &cadet_port);

    if (NULL == ts->channel)
    {
      GNUNET_break (0);
      GNUNET_free (ts);
      return NULL;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Creating channel to peer %s offering service %s on port %u\n",
                GNUNET_i2s (
                  &dt->destination->details.service_destination.target),
                GNUNET_h2s (&ts->destination.details.service_destination
                            .service_descriptor),
                (unsigned int) ts->destination_port);
  }
  else
  {
    char *policy;

    switch (dt->destination->details.exit_destination.af)
    {
    case AF_INET: {
        char address[GNUNET_TUN_IPV4_REGEXLEN];

        GNUNET_TUN_ipv4toregexsearch (&dt->destination->details.exit_destination
                                      .ip.v4,
                                      dt->destination_port,
                                      address);
        GNUNET_asprintf (&policy,
                         "%s%s",
                         GNUNET_APPLICATION_TYPE_EXIT_REGEX_PREFIX,
                         address);
        break;
      }

    case AF_INET6: {
        char address[GNUNET_TUN_IPV6_REGEXLEN];

        GNUNET_TUN_ipv6toregexsearch (&dt->destination->details.exit_destination
                                      .ip.v6,
                                      dt->destination_port,
                                      address);
        GNUNET_asprintf (&policy,
                         "%s%s",
                         GNUNET_APPLICATION_TYPE_EXIT_REGEX_PREFIX,
                         address);
        break;
      }

    default:
      GNUNET_assert (0);
      break;
    }

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Requesting connect by string: %s\n",
                policy);
    ts->search = GNUNET_REGEX_search (cfg, policy, &handle_regex_result, ts);
    GNUNET_free (policy);
  }
  return ts;
}


/**
 * We have too many active channels.  Clean up the oldest channel.
 *
 * @param except channel that must NOT be cleaned up, even if it is the oldest
 */
static void
expire_channel (struct ChannelState *except)
{
  struct ChannelState *ts;

  ts = GNUNET_CONTAINER_heap_peek (channel_heap);
  GNUNET_assert (NULL != ts);
  if (except == ts)
    return; /* can't do this */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Tearing down expired channel to %s\n",
              print_channel_destination (&except->destination));
  free_channel_state (ts);
}


/**
 * Route a packet via cadet to the given destination.
 *
 * @param destination description of the destination
 * @param af address family on this end (AF_INET or AF_INET6)
 * @param protocol IPPROTO_TCP or IPPROTO_UDP or IPPROTO_ICMP or IPPROTO_ICMPV6
 * @param source_ip source IP used by the sender (struct in_addr or struct in6_addr)
 * @param destination_ip destination IP used by the sender (struct in_addr or struct in6_addr)
 * @param payload payload of the packet after the IP header
 * @param payload_length number of bytes in @a payload
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
  struct GNUNET_HashCode key;
  struct ChannelState *ts;
  size_t alen;
  size_t mlen;
  struct GNUNET_MQ_Envelope *env;
  const struct GNUNET_TUN_UdpHeader *udp;
  const struct GNUNET_TUN_TcpHeader *tcp;
  const struct GNUNET_TUN_IcmpHeader *icmp;
  struct DestinationChannel *dt;
  uint16_t source_port;
  uint16_t destination_port;

  switch (protocol)
  {
  case IPPROTO_UDP: {
      if (payload_length < sizeof(struct GNUNET_TUN_UdpHeader))
      {
        /* blame kernel? */
        GNUNET_break (0);
        return;
      }
      tcp = NULL; /* make compiler happy */
      icmp = NULL; /* make compiler happy */
      udp = payload;
      if (udp->len < sizeof(struct GNUNET_TUN_UdpHeader))
      {
        GNUNET_break_op (0);
        return;
      }
      source_port = ntohs (udp->source_port);
      destination_port = ntohs (udp->destination_port);
      get_channel_key_from_ips (af,
                                IPPROTO_UDP,
                                source_ip,
                                source_port,
                                destination_ip,
                                destination_port,
                                &key);
    }
    break;

  case IPPROTO_TCP: {
      if (payload_length < sizeof(struct GNUNET_TUN_TcpHeader))
      {
        /* blame kernel? */
        GNUNET_break (0);
        return;
      }
      udp = NULL; /* make compiler happy */
      icmp = NULL; /* make compiler happy */
      tcp = payload;
      if (tcp->off * 4 < sizeof(struct GNUNET_TUN_TcpHeader))
      {
        GNUNET_break_op (0);
        return;
      }
      source_port = ntohs (tcp->source_port);
      destination_port = ntohs (tcp->destination_port);
      get_channel_key_from_ips (af,
                                IPPROTO_TCP,
                                source_ip,
                                source_port,
                                destination_ip,
                                destination_port,
                                &key);
    }
    break;

  case IPPROTO_ICMP:
  case IPPROTO_ICMPV6: {
      if ((AF_INET == af) ^ (protocol == IPPROTO_ICMP))
      {
        GNUNET_break (0);
        return;
      }
      if (payload_length < sizeof(struct GNUNET_TUN_IcmpHeader))
      {
        /* blame kernel? */
        GNUNET_break (0);
        return;
      }
      tcp = NULL; /* make compiler happy */
      udp = NULL; /* make compiler happy */
      icmp = payload;
      source_port = 0;
      destination_port = 0;
      get_channel_key_from_ips (af,
                                protocol,
                                source_ip,
                                0,
                                destination_ip,
                                0,
                                &key);
    }
    break;

  default:
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _ ("Protocol %u not supported, dropping\n"),
                (unsigned int) protocol);
    return;
  }
  alen = 0;
  if (! destination->is_service)
  {
    switch (destination->details.exit_destination.af)
    {
    case AF_INET:
      alen = sizeof(struct in_addr);
      break;

    case AF_INET6:
      alen = sizeof(struct in6_addr);
      break;

    default:
      GNUNET_assert (0);
    }

    {
      char sbuf[INET6_ADDRSTRLEN];
      char dbuf[INET6_ADDRSTRLEN];
      char xbuf[INET6_ADDRSTRLEN];

      GNUNET_log (
        GNUNET_ERROR_TYPE_DEBUG,
        "Routing %s packet from [%s]:%u -> [%s]:%u to destination [%s]:%u\n",
        (protocol == IPPROTO_TCP) ? "TCP" : "UDP",
        inet_ntop (af, source_ip, sbuf, sizeof(sbuf)),
        source_port,
        inet_ntop (af, destination_ip, dbuf, sizeof(dbuf)),
        destination_port,
        inet_ntop (destination->details.exit_destination.af,
                   &destination->details.exit_destination.ip,
                   xbuf,
                   sizeof(xbuf)),
        destination_port);
    }
    for (dt = destination->dt_head; NULL != dt; dt = dt->next)
      if (dt->destination_port == destination_port)
        break;
  }
  else
  {
    {
      char sbuf[INET6_ADDRSTRLEN];
      char dbuf[INET6_ADDRSTRLEN];

      GNUNET_log (
        GNUNET_ERROR_TYPE_DEBUG,
        "Routing %s packet from [%s]:%u -> [%s]:%u to service %s at peer %s\n",
        (protocol == IPPROTO_TCP) ? "TCP" : "UDP",
        inet_ntop (af, source_ip, sbuf, sizeof(sbuf)),
        source_port,
        inet_ntop (af, destination_ip, dbuf, sizeof(dbuf)),
        destination_port,
        GNUNET_h2s (
          &destination->details.service_destination.service_descriptor),
        GNUNET_i2s (&destination->details.service_destination.target));
    }
    for (dt = destination->dt_head; NULL != dt; dt = dt->next)
      if (dt->destination_port == destination_port)
        break;
  }
  if (NULL == dt)
  {
    dt = GNUNET_new (struct DestinationChannel);
    dt->destination = destination;
    GNUNET_CONTAINER_DLL_insert (destination->dt_head,
                                 destination->dt_tail,
                                 dt);
    dt->destination_port = destination_port;
  }

  /* see if we have an existing channel for this destination */
  ts = GNUNET_CONTAINER_multihashmap_get (channel_map, &key);
  if (NULL == ts)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Creating new channel for key %s\n",
                GNUNET_h2s (&key));
    /* need to either use the existing channel from the destination (if still
       available) or create a fresh one */
    ts = create_channel_to_destination (dt, af);
    if (NULL == ts)
      return;
    /* now bind existing "unbound" channel to our IP/port tuple */
    ts->protocol = protocol;
    ts->af = af;
    if (AF_INET == af)
    {
      ts->source_ip.v4 = *(const struct in_addr *) source_ip;
      ts->destination_ip.v4 = *(const struct in_addr *) destination_ip;
    }
    else
    {
      ts->source_ip.v6 = *(const struct in6_addr *) source_ip;
      ts->destination_ip.v6 = *(const struct in6_addr *) destination_ip;
    }
    ts->source_port = source_port;
    ts->destination_port = destination_port;
    ts->heap_node =
      GNUNET_CONTAINER_heap_insert (channel_heap,
                                    ts,
                                    GNUNET_TIME_absolute_get ().abs_value_us);
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multihashmap_put (
                     channel_map,
                     &key,
                     ts,
                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
    GNUNET_STATISTICS_update (stats,
                              gettext_noop ("# Active channels"),
                              1,
                              GNUNET_NO);
    while (GNUNET_CONTAINER_multihashmap_size (channel_map) >
           max_channel_mappings)
      expire_channel (ts);
  }
  else
  {
    GNUNET_CONTAINER_heap_update_cost (ts->heap_node,
                                       GNUNET_TIME_absolute_get ()
                                       .abs_value_us);
  }
  if (NULL == ts->channel)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Packet dropped, channel to %s not yet ready (%s)\n",
                print_channel_destination (&ts->destination),
                (NULL == ts->search) ? "EXIT search failed"
                : "EXIT search active");
    GNUNET_STATISTICS_update (stats,
                              gettext_noop (
                                "# Packets dropped (channel not yet online)"),
                              1,
                              GNUNET_NO);
    return;
  }

  /* send via channel */
  switch (protocol)
  {
  case IPPROTO_UDP:
    if (destination->is_service)
    {
      struct GNUNET_EXIT_UdpServiceMessage *usm;

      mlen = sizeof(struct GNUNET_EXIT_UdpServiceMessage) + payload_length
             - sizeof(struct GNUNET_TUN_UdpHeader);
      if (mlen >= GNUNET_MAX_MESSAGE_SIZE)
      {
        GNUNET_break (0);
        return;
      }
      env = GNUNET_MQ_msg_extra (usm,
                                 payload_length
                                 - sizeof(struct GNUNET_TUN_UdpHeader),
                                 GNUNET_MESSAGE_TYPE_VPN_UDP_TO_SERVICE);
      /* if the source port is below 32000, we assume it has a special
         meaning; if not, we pick a random port (this is a heuristic) */
      usm->source_port =
        (ntohs (udp->source_port) < 32000) ? udp->source_port : 0;
      usm->destination_port = udp->destination_port;
      GNUNET_memcpy (&usm[1],
                     &udp[1],
                     payload_length - sizeof(struct GNUNET_TUN_UdpHeader));
    }
    else
    {
      struct GNUNET_EXIT_UdpInternetMessage *uim;
      struct in_addr *ip4dst;
      struct in6_addr *ip6dst;
      void *payload;

      mlen = sizeof(struct GNUNET_EXIT_UdpInternetMessage) + alen
             + payload_length - sizeof(struct GNUNET_TUN_UdpHeader);
      if (mlen >= GNUNET_MAX_MESSAGE_SIZE)
      {
        GNUNET_break (0);
        return;
      }
      env = GNUNET_MQ_msg_extra (uim,
                                 payload_length + alen
                                 - sizeof(struct GNUNET_TUN_UdpHeader),
                                 GNUNET_MESSAGE_TYPE_VPN_UDP_TO_INTERNET);
      uim->af = htonl (destination->details.exit_destination.af);
      uim->source_port =
        (ntohs (udp->source_port) < 32000) ? udp->source_port : 0;
      uim->destination_port = udp->destination_port;
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
      GNUNET_memcpy (payload,
                     &udp[1],
                     payload_length - sizeof(struct GNUNET_TUN_UdpHeader));
    }
    break;

  case IPPROTO_TCP:
    if (GNUNET_NO == ts->is_established)
    {
      if (destination->is_service)
      {
        struct GNUNET_EXIT_TcpServiceStartMessage *tsm;

        mlen = sizeof(struct GNUNET_EXIT_TcpServiceStartMessage)
               + payload_length - sizeof(struct GNUNET_TUN_TcpHeader);
        if (mlen >= GNUNET_MAX_MESSAGE_SIZE)
        {
          GNUNET_break (0);
          return;
        }
        env =
          GNUNET_MQ_msg_extra (tsm,
                               payload_length
                               - sizeof(struct GNUNET_TUN_TcpHeader),
                               GNUNET_MESSAGE_TYPE_VPN_TCP_TO_SERVICE_START);
        tsm->reserved = htonl (0);
        tsm->tcp_header = *tcp;
        GNUNET_memcpy (&tsm[1],
                       &tcp[1],
                       payload_length - sizeof(struct GNUNET_TUN_TcpHeader));
      }
      else
      {
        struct GNUNET_EXIT_TcpInternetStartMessage *tim;
        struct in_addr *ip4dst;
        struct in6_addr *ip6dst;
        void *payload;

        mlen = sizeof(struct GNUNET_EXIT_TcpInternetStartMessage) + alen
               + payload_length - sizeof(struct GNUNET_TUN_TcpHeader);
        if (mlen >= GNUNET_MAX_MESSAGE_SIZE)
        {
          GNUNET_break (0);
          return;
        }
        env =
          GNUNET_MQ_msg_extra (tim,
                               payload_length + alen
                               - sizeof(struct GNUNET_TUN_TcpHeader),
                               GNUNET_MESSAGE_TYPE_VPN_TCP_TO_INTERNET_START);
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
        GNUNET_memcpy (payload,
                       &tcp[1],
                       payload_length - sizeof(struct GNUNET_TUN_TcpHeader));
      }
    }
    else
    {
      struct GNUNET_EXIT_TcpDataMessage *tdm;

      mlen = sizeof(struct GNUNET_EXIT_TcpDataMessage) + payload_length
             - sizeof(struct GNUNET_TUN_TcpHeader);
      if (mlen >= GNUNET_MAX_MESSAGE_SIZE)
      {
        GNUNET_break (0);
        return;
      }
      env = GNUNET_MQ_msg_extra (tdm,
                                 payload_length
                                 - sizeof(struct GNUNET_TUN_TcpHeader),
                                 GNUNET_MESSAGE_TYPE_VPN_TCP_DATA_TO_EXIT);
      tdm->reserved = htonl (0);
      tdm->tcp_header = *tcp;
      GNUNET_memcpy (&tdm[1],
                     &tcp[1],
                     payload_length - sizeof(struct GNUNET_TUN_TcpHeader));
    }
    break;

  case IPPROTO_ICMP:
  case IPPROTO_ICMPV6:
    if (destination->is_service)
    {
      struct GNUNET_EXIT_IcmpServiceMessage *ism;

      /* ICMP protocol translation will be done by the receiver (as we don't know
         the target AF); however, we still need to possibly discard the payload
         depending on the ICMP type */
      switch (af)
      {
      case AF_INET:
        switch (icmp->type)
        {
        case GNUNET_TUN_ICMPTYPE_ECHO_REPLY:
        case GNUNET_TUN_ICMPTYPE_ECHO_REQUEST:
          break;

        case GNUNET_TUN_ICMPTYPE_DESTINATION_UNREACHABLE:
        case GNUNET_TUN_ICMPTYPE_SOURCE_QUENCH:
        case GNUNET_TUN_ICMPTYPE_TIME_EXCEEDED:
          /* throw away ICMP payload, won't be useful for the other side anyway */
          payload_length = sizeof(struct GNUNET_TUN_IcmpHeader);
          break;

        default:
          GNUNET_STATISTICS_update (stats,
                                    gettext_noop (
                                      "# ICMPv4 packets dropped (not allowed)"),
                                    1,
                                    GNUNET_NO);
          return;
        }
        /* end of AF_INET */
        break;

      case AF_INET6:
        switch (icmp->type)
        {
        case GNUNET_TUN_ICMPTYPE6_DESTINATION_UNREACHABLE:
        case GNUNET_TUN_ICMPTYPE6_PACKET_TOO_BIG:
        case GNUNET_TUN_ICMPTYPE6_TIME_EXCEEDED:
        case GNUNET_TUN_ICMPTYPE6_PARAMETER_PROBLEM:
          /* throw away ICMP payload, won't be useful for the other side anyway */
          payload_length = sizeof(struct GNUNET_TUN_IcmpHeader);
          break;

        case GNUNET_TUN_ICMPTYPE6_ECHO_REQUEST:
        case GNUNET_TUN_ICMPTYPE6_ECHO_REPLY:
          break;

        default:
          GNUNET_STATISTICS_update (stats,
                                    gettext_noop (
                                      "# ICMPv6 packets dropped (not allowed)"),
                                    1,
                                    GNUNET_NO);
          return;
        }
        /* end of AF_INET6 */
        break;

      default:
        GNUNET_assert (0);
        break;
      }

      /* update length calculations, as payload_length may have changed */
      mlen = sizeof(struct GNUNET_EXIT_IcmpServiceMessage) + alen
             + payload_length - sizeof(struct GNUNET_TUN_IcmpHeader);
      if (mlen >= GNUNET_MAX_MESSAGE_SIZE)
      {
        GNUNET_break (0);
        return;
      }

      env = GNUNET_MQ_msg_extra (ism,
                                 payload_length
                                 - sizeof(struct GNUNET_TUN_IcmpHeader),
                                 GNUNET_MESSAGE_TYPE_VPN_ICMP_TO_SERVICE);
      ism->af = htonl (af);    /* need to tell destination ICMP protocol family! */
      ism->icmp_header = *icmp;
      GNUNET_memcpy (&ism[1],
                     &icmp[1],
                     payload_length - sizeof(struct GNUNET_TUN_IcmpHeader));
    }
    else
    {
      struct GNUNET_EXIT_IcmpInternetMessage *iim;
      struct in_addr *ip4dst;
      struct in6_addr *ip6dst;
      void *payload;
      uint8_t new_type;

      new_type = icmp->type;
      /* Perform ICMP protocol-translation (depending on destination AF and source AF)
         and throw away ICMP payload depending on ICMP message type */
      switch (af)
      {
      case AF_INET:
        switch (icmp->type)
        {
        case GNUNET_TUN_ICMPTYPE_ECHO_REPLY:
          if (destination->details.exit_destination.af == AF_INET6)
            new_type = GNUNET_TUN_ICMPTYPE6_ECHO_REPLY;
          break;

        case GNUNET_TUN_ICMPTYPE_ECHO_REQUEST:
          if (destination->details.exit_destination.af == AF_INET6)
            new_type = GNUNET_TUN_ICMPTYPE6_ECHO_REQUEST;
          break;

        case GNUNET_TUN_ICMPTYPE_DESTINATION_UNREACHABLE:
          if (destination->details.exit_destination.af == AF_INET6)
            new_type = GNUNET_TUN_ICMPTYPE6_DESTINATION_UNREACHABLE;
          /* throw away IP-payload, exit will have to make it up anyway */
          payload_length = sizeof(struct GNUNET_TUN_IcmpHeader);
          break;

        case GNUNET_TUN_ICMPTYPE_TIME_EXCEEDED:
          if (destination->details.exit_destination.af == AF_INET6)
            new_type = GNUNET_TUN_ICMPTYPE6_TIME_EXCEEDED;
          /* throw away IP-payload, exit will have to make it up anyway */
          payload_length = sizeof(struct GNUNET_TUN_IcmpHeader);
          break;

        case GNUNET_TUN_ICMPTYPE_SOURCE_QUENCH:
          if (destination->details.exit_destination.af == AF_INET6)
          {
            GNUNET_STATISTICS_update (
              stats,
              gettext_noop ("# ICMPv4 packets dropped (impossible PT to v6)"),
              1,
              GNUNET_NO);
            return;
          }
          /* throw away IP-payload, exit will have to make it up anyway */
          payload_length = sizeof(struct GNUNET_TUN_IcmpHeader);
          break;

        default:
          GNUNET_STATISTICS_update (
            stats,
            gettext_noop ("# ICMPv4 packets dropped (type not allowed)"),
            1,
            GNUNET_NO);
          return;
        }
        /* end of AF_INET */
        break;

      case AF_INET6:
        switch (icmp->type)
        {
        case GNUNET_TUN_ICMPTYPE6_DESTINATION_UNREACHABLE:
          if (destination->details.exit_destination.af == AF_INET)
            new_type = GNUNET_TUN_ICMPTYPE_DESTINATION_UNREACHABLE;
          /* throw away IP-payload, exit will have to make it up anyway */
          payload_length = sizeof(struct GNUNET_TUN_IcmpHeader);
          break;

        case GNUNET_TUN_ICMPTYPE6_TIME_EXCEEDED:
          if (destination->details.exit_destination.af == AF_INET)
            new_type = GNUNET_TUN_ICMPTYPE_TIME_EXCEEDED;
          /* throw away IP-payload, exit will have to make it up anyway */
          payload_length = sizeof(struct GNUNET_TUN_IcmpHeader);
          break;

        case GNUNET_TUN_ICMPTYPE6_PACKET_TOO_BIG:
          if (destination->details.exit_destination.af == AF_INET)
          {
            GNUNET_STATISTICS_update (
              stats,
              gettext_noop ("# ICMPv6 packets dropped (impossible PT to v4)"),
              1,
              GNUNET_NO);
            return;
          }
          /* throw away IP-payload, exit will have to make it up anyway */
          payload_length = sizeof(struct GNUNET_TUN_IcmpHeader);
          break;

        case GNUNET_TUN_ICMPTYPE6_PARAMETER_PROBLEM:
          if (destination->details.exit_destination.af == AF_INET)
          {
            GNUNET_STATISTICS_update (
              stats,
              gettext_noop ("# ICMPv6 packets dropped (impossible PT to v4)"),
              1,
              GNUNET_NO);
            return;
          }
          /* throw away IP-payload, exit will have to make it up anyway */
          payload_length = sizeof(struct GNUNET_TUN_IcmpHeader);
          break;

        case GNUNET_TUN_ICMPTYPE6_ECHO_REQUEST:
          if (destination->details.exit_destination.af == AF_INET)
            new_type = GNUNET_TUN_ICMPTYPE_ECHO_REQUEST;
          break;

        case GNUNET_TUN_ICMPTYPE6_ECHO_REPLY:
          if (destination->details.exit_destination.af == AF_INET)
            new_type = GNUNET_TUN_ICMPTYPE_ECHO_REPLY;
          break;

        default:
          GNUNET_STATISTICS_update (
            stats,
            gettext_noop ("# ICMPv6 packets dropped (type not allowed)"),
            1,
            GNUNET_NO);
          return;
        }
        /* end of AF_INET6 */
        break;

      default:
        GNUNET_assert (0);
      }

      /* update length calculations, as payload_length may have changed */
      mlen = sizeof(struct GNUNET_EXIT_IcmpInternetMessage) + alen
             + payload_length - sizeof(struct GNUNET_TUN_IcmpHeader);
      if (mlen >= GNUNET_MAX_MESSAGE_SIZE)
      {
        GNUNET_break (0);
        return;
      }
      env = GNUNET_MQ_msg_extra (iim,
                                 alen + payload_length
                                 - sizeof(struct GNUNET_TUN_IcmpHeader),
                                 GNUNET_MESSAGE_TYPE_VPN_ICMP_TO_INTERNET);
      iim->icmp_header = *icmp;
      iim->icmp_header.type = new_type;
      iim->af = htonl (destination->details.exit_destination.af);
      switch (destination->details.exit_destination.af)
      {
      case AF_INET:
        ip4dst = (struct in_addr *) &iim[1];
        *ip4dst = destination->details.exit_destination.ip.v4;
        payload = &ip4dst[1];
        break;

      case AF_INET6:
        ip6dst = (struct in6_addr *) &iim[1];
        *ip6dst = destination->details.exit_destination.ip.v6;
        payload = &ip6dst[1];
        break;

      default:
        GNUNET_assert (0);
      }
      GNUNET_memcpy (payload,
                     &icmp[1],
                     payload_length - sizeof(struct GNUNET_TUN_IcmpHeader));
    }
    break;

  default:
    /* not supported above, how can we get here !? */
    GNUNET_assert (0);
    break;
  }
  ts->is_established = GNUNET_YES;
  send_to_channel (ts, env);
}


/**
 * Receive packets from the helper-process (someone send to the local
 * virtual channel interface).  Find the destination mapping, and if it
 * exists, identify the correct CADET channel (or possibly create it)
 * and forward the packet.
 *
 * @param cls closure, NULL
 * @param message message we got from the client (VPN channel interface)
 * @return #GNUNET_OK on success,
 *    #GNUNET_NO to stop further processing (no error)
 *    #GNUNET_SYSERR to stop further processing with error
 */
static int
message_token (void *cls, const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TUN_Layer2PacketHeader *tun;
  size_t mlen;
  struct GNUNET_HashCode key;
  struct DestinationEntry *de;

  GNUNET_STATISTICS_update (stats,
                            gettext_noop (
                              "# Packets received from TUN interface"),
                            1,
                            GNUNET_NO);
  mlen = ntohs (message->size);
  if ((ntohs (message->type) != GNUNET_MESSAGE_TYPE_VPN_HELPER) ||
      (mlen < sizeof(struct GNUNET_MessageHeader)
       + sizeof(struct GNUNET_TUN_Layer2PacketHeader)))
  {
    GNUNET_break (0);
    return GNUNET_OK;
  }
  tun = (const struct GNUNET_TUN_Layer2PacketHeader *) &message[1];
  mlen -= (sizeof(struct GNUNET_MessageHeader)
           + sizeof(struct GNUNET_TUN_Layer2PacketHeader));
  switch (ntohs (tun->proto))
  {
  case ETH_P_IPV6: {
      const struct GNUNET_TUN_IPv6Header *pkt6;

      if (mlen < sizeof(struct GNUNET_TUN_IPv6Header))
      {
        /* blame kernel */
        GNUNET_break (0);
        return GNUNET_OK;
      }
      pkt6 = (const struct GNUNET_TUN_IPv6Header *) &tun[1];
      get_destination_key_from_ip (AF_INET6, &pkt6->destination_address, &key);
      de = GNUNET_CONTAINER_multihashmap_get (destination_map, &key);
      if (NULL == de)
      {
        char buf[INET6_ADDRSTRLEN];

        GNUNET_log (
          GNUNET_ERROR_TYPE_INFO,
          _ ("Packet received for unmapped destination `%s' (dropping it)\n"),
          inet_ntop (AF_INET6, &pkt6->destination_address, buf, sizeof(buf)));
        return GNUNET_OK;
      }
      route_packet (de,
                    AF_INET6,
                    pkt6->next_header,
                    &pkt6->source_address,
                    &pkt6->destination_address,
                    &pkt6[1],
                    mlen - sizeof(struct GNUNET_TUN_IPv6Header));
    }
    break;

  case ETH_P_IPV4: {
      struct GNUNET_TUN_IPv4Header *pkt4;

      if (mlen < sizeof(struct GNUNET_TUN_IPv4Header))
      {
        /* blame kernel */
        GNUNET_break (0);
        return GNUNET_OK;
      }
      pkt4 = (struct GNUNET_TUN_IPv4Header *) &tun[1];
      get_destination_key_from_ip (AF_INET, &pkt4->destination_address, &key);
      de = GNUNET_CONTAINER_multihashmap_get (destination_map, &key);
      if (NULL == de)
      {
        char buf[INET_ADDRSTRLEN];

        GNUNET_log (
          GNUNET_ERROR_TYPE_INFO,
          _ ("Packet received for unmapped destination `%s' (dropping it)\n"),
          inet_ntop (AF_INET, &pkt4->destination_address, buf, sizeof(buf)));
        return GNUNET_OK;
      }
      if (pkt4->header_length * 4 != sizeof(struct GNUNET_TUN_IPv4Header))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                    _ ("Received IPv4 packet with options (dropping it)\n"));
        return GNUNET_OK;
      }
      route_packet (de,
                    AF_INET,
                    pkt4->protocol,
                    &pkt4->source_address,
                    &pkt4->destination_address,
                    &pkt4[1],
                    mlen - sizeof(struct GNUNET_TUN_IPv4Header));
    }
    break;

  default:
    GNUNET_log (
      GNUNET_ERROR_TYPE_INFO,
      _ ("Received packet of unknown protocol %d from TUN (dropping it)\n"),
      (unsigned int) ntohs (tun->proto));
    break;
  }
  return GNUNET_OK;
}


/**
 * Allocate an IPv4 address from the range of the channel
 * for a new redirection.
 *
 * @param v4 where to store the address
 * @return #GNUNET_OK on success,
 *         #GNUNET_SYSERR on error
 */
static int
allocate_v4_address (struct in_addr *v4)
{
  const char *ipv4addr = vpn_argv[4];
  const char *ipv4mask = vpn_argv[5];
  struct in_addr addr;
  struct in_addr mask;
  struct in_addr rnd;
  struct GNUNET_HashCode key;
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
                  _ (
                    "Failed to find unallocated IPv4 address in VPN's range\n"));
      return GNUNET_SYSERR;
    }
    /* Pick random IPv4 address within the subnet, except 'addr' or 'mask' itself */
    rnd.s_addr =
      GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, UINT32_MAX);
    v4->s_addr = (addr.s_addr | rnd.s_addr) & mask.s_addr;
    get_destination_key_from_ip (AF_INET, v4, &key);
  }
  while ((GNUNET_YES ==
          GNUNET_CONTAINER_multihashmap_contains (destination_map, &key)) ||
         (v4->s_addr == addr.s_addr) || (v4->s_addr == mask.s_addr));
  return GNUNET_OK;
}


/**
 * Allocate an IPv6 address from the range of the channel
 * for a new redirection.
 *
 * @param v6 where to store the address
 * @return #GNUNET_OK on success,
 *         #GNUNET_SYSERR on error
 */
static int
allocate_v6_address (struct in6_addr *v6)
{
  const char *ipv6addr = vpn_argv[2];
  struct in6_addr addr;
  struct in6_addr mask;
  struct in6_addr rnd;
  int i;
  struct GNUNET_HashCode key;
  unsigned int tries;

  GNUNET_assert (1 == inet_pton (AF_INET6, ipv6addr, &addr));
  GNUNET_assert (ipv6prefix < 128);
  /* Given ABCD::/96, we want a mask of 'ABCD::FFFF:FFFF,
     thus: */
  mask = addr;
  for (i = 127; i >= ipv6prefix; i--)
    mask.s6_addr[i / 8] |= (1 << (i % 8));

  /* Pick random IPv6 address within the subnet, except 'addr' or 'mask' itself */
  tries = 0;
  do
  {
    tries++;
    if (tries > 16)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _ (
                    "Failed to find unallocated IPv6 address in VPN's range\n"));
      return GNUNET_SYSERR;
    }
    for (i = 0; i < 16; i++)
    {
      rnd.s6_addr[i] =
        (unsigned char) GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                                  256);
      v6->s6_addr[i] = (addr.s6_addr[i] | rnd.s6_addr[i]) & mask.s6_addr[i];
    }
    get_destination_key_from_ip (AF_INET6, v6, &key);
  }
  while ((GNUNET_YES ==
          GNUNET_CONTAINER_multihashmap_contains (destination_map, &key)) ||
         (0 == GNUNET_memcmp (v6, &addr)) ||
         (0 == GNUNET_memcmp (v6, &mask)));
  return GNUNET_OK;
}


/**
 * Free resources occupied by a destination entry.
 *
 * @param de entry to free
 */
static void
free_destination_entry (struct DestinationEntry *de)
{
  struct DestinationChannel *dt;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Cleaning up destination entry `%s'\n",
              print_channel_destination (de));
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# Active destinations"),
                            -1,
                            GNUNET_NO);
  while (NULL != (dt = de->dt_head))
  {
    GNUNET_CONTAINER_DLL_remove (de->dt_head, de->dt_tail, dt);
    GNUNET_free (dt);
  }
  if (NULL != de->heap_node)
  {
    GNUNET_CONTAINER_heap_remove_node (de->heap_node);
    de->heap_node = NULL;
    GNUNET_assert (
      GNUNET_YES ==
      GNUNET_CONTAINER_multihashmap_remove (destination_map, &de->key, de));
  }
  GNUNET_free (de);
}


/**
 * We have too many active destinations.  Clean up the oldest destination.
 *
 * @param except destination that must NOT be cleaned up, even if it is the oldest
 */
static void
expire_destination (struct DestinationEntry *except)
{
  struct DestinationEntry *de;

  de = GNUNET_CONTAINER_heap_peek (destination_heap);
  GNUNET_assert (NULL != de);
  if (except == de)
    return; /* can't do this */
  free_destination_entry (de);
}


/**
 * Allocate an IP address for the response.
 *
 * @param result_af desired address family; set to the actual
 *        address family; can initially be AF_UNSPEC if there
 *        is no preference; will be set to AF_UNSPEC if the
 *        allocation failed
 * @param addr set to either v4 or v6 depending on which
 *         storage location was used; set to NULL if allocation failed
 * @param v4 storage space for an IPv4 address
 * @param v6 storage space for an IPv6 address
 * @return #GNUNET_OK normally, #GNUNET_SYSERR if `* result_af` was
 *         an unsupported address family (not AF_INET, AF_INET6 or AF_UNSPEC)
 */
static int
allocate_response_ip (int *result_af,
                      void **addr,
                      struct in_addr *v4,
                      struct in6_addr *v6)
{
  *addr = NULL;
  switch (*result_af)
  {
  case AF_INET:
    if (GNUNET_OK != allocate_v4_address (v4))
      *result_af = AF_UNSPEC;
    else
      *addr = v4;
    break;

  case AF_INET6:
    if (GNUNET_OK != allocate_v6_address (v6))
      *result_af = AF_UNSPEC;
    else
      *addr = v6;
    break;

  case AF_UNSPEC:
    if (GNUNET_OK == allocate_v4_address (v4))
    {
      *addr = v4;
      *result_af = AF_INET;
    }
    else if (GNUNET_OK == allocate_v6_address (v6))
    {
      *addr = v6;
      *result_af = AF_INET6;
    }
    break;

  default:
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * A client asks us to setup a redirection via some exit node to a
 * particular IP.  Check if @a msg is well-formed.
 * allocated IP.
 *
 * @param cls client requesting client
 * @param msg redirection request
 * @return #GNUNET_OK if @a msg is well-formed
 */
static int
check_client_redirect_to_ip (void *cls,
                             const struct RedirectToIpRequestMessage *msg)
{
  size_t alen;
  int addr_af;

  alen = ntohs (msg->header.size) - sizeof(struct RedirectToIpRequestMessage);
  addr_af = (int) htonl (msg->addr_af);
  switch (addr_af)
  {
  case AF_INET:
    if (alen != sizeof(struct in_addr))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    break;

  case AF_INET6:
    if (alen != sizeof(struct in6_addr))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    break;

  default:
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * A client asks us to setup a redirection via some exit node to a
 * particular IP.  Setup the redirection and give the client the
 * allocated IP.
 *
 * @param cls client requesting client
 * @param msg redirection request
 */
static void
handle_client_redirect_to_ip (void *cls,
                              const struct RedirectToIpRequestMessage *msg)
{
  struct GNUNET_SERVICE_Client *client = cls;
  size_t alen;
  int addr_af;
  int result_af;
  struct in_addr v4;
  struct in6_addr v6;
  void *addr;
  struct DestinationEntry *de;
  struct GNUNET_HashCode key;

  alen = ntohs (msg->header.size) - sizeof(struct RedirectToIpRequestMessage);
  addr_af = (int) htonl (msg->addr_af);
  /* allocate response IP */
  result_af = (int) htonl (msg->result_af);
  if (GNUNET_OK != allocate_response_ip (&result_af, &addr, &v4, &v6))
  {
    GNUNET_SERVICE_client_drop (client);
    return;
  }
  /* send reply with our IP address */
  send_client_reply (client, msg->request_id, result_af, addr);
  if (result_af == AF_UNSPEC)
  {
    /* failure, we're done */
    GNUNET_SERVICE_client_continue (client);
    return;
  }

  {
    char sbuf[INET6_ADDRSTRLEN];
    char dbuf[INET6_ADDRSTRLEN];

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Allocated address %s for redirection via exit to %s\n",
                inet_ntop (result_af, addr, sbuf, sizeof(sbuf)),
                inet_ntop (addr_af, &msg[1], dbuf, sizeof(dbuf)));
  }

  /* setup destination record */
  de = GNUNET_new (struct DestinationEntry);
  de->is_service = GNUNET_NO;
  de->details.exit_destination.af = addr_af;
  GNUNET_memcpy (&de->details.exit_destination.ip, &msg[1], alen);
  get_destination_key_from_ip (result_af, addr, &key);
  de->key = key;
  GNUNET_assert (GNUNET_OK == GNUNET_CONTAINER_multihashmap_put (
                   destination_map,
                   &key,
                   de,
                   GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
  de->heap_node = GNUNET_CONTAINER_heap_insert (destination_heap,
                                                de,
                                                GNUNET_TIME_absolute_ntoh (
                                                  msg->expiration_time)
                                                .abs_value_us);
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# Active destinations"),
                            1,
                            GNUNET_NO);
  while (GNUNET_CONTAINER_multihashmap_size (destination_map) >
         max_destination_mappings)
    expire_destination (de);
  GNUNET_SERVICE_client_continue (client);
}


/**
 * A client asks us to setup a redirection to a particular peer
 * offering a service.  Setup the redirection and give the client the
 * allocated IP.
 *
 * @param cls requesting client
 * @param msg redirection request
 */
static void
handle_client_redirect_to_service (
  void *cls,
  const struct RedirectToServiceRequestMessage *msg)
{
  struct GNUNET_SERVICE_Client *client = cls;
  int result_af;
  struct in_addr v4;
  struct in6_addr v6;
  void *addr;
  struct DestinationEntry *de;
  struct GNUNET_HashCode key;
  struct DestinationChannel *dt;

  /* allocate response IP */
  result_af = (int) htonl (msg->result_af);
  if (GNUNET_OK != allocate_response_ip (&result_af, &addr, &v4, &v6))
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (client);
    return;
  }
  send_client_reply (client, msg->request_id, result_af, addr);
  if (result_af == AF_UNSPEC)
  {
    /* failure, we're done */
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Failed to allocate IP address for new destination\n"));
    GNUNET_SERVICE_client_continue (client);
    return;
  }

  {
    char sbuf[INET6_ADDRSTRLEN];

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Allocated address %s for redirection to service %s on peer %s\n",
                inet_ntop (result_af, addr, sbuf, sizeof(sbuf)),
                GNUNET_h2s (&msg->service_descriptor),
                GNUNET_i2s (&msg->target));
  }

  /* setup destination record */
  de = GNUNET_new (struct DestinationEntry);
  de->is_service = GNUNET_YES;
  de->details.service_destination.target = msg->target;
  de->details.service_destination.service_descriptor = msg->service_descriptor;
  get_destination_key_from_ip (result_af, addr, &key);
  de->key = key;
  GNUNET_assert (GNUNET_OK == GNUNET_CONTAINER_multihashmap_put (
                   destination_map,
                   &key,
                   de,
                   GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
  de->heap_node = GNUNET_CONTAINER_heap_insert (destination_heap,
                                                de,
                                                GNUNET_TIME_absolute_ntoh (
                                                  msg->expiration_time)
                                                .abs_value_us);
  while (GNUNET_CONTAINER_multihashmap_size (destination_map) >
         max_destination_mappings)
    expire_destination (de);

  dt = GNUNET_new (struct DestinationChannel);
  dt->destination = de;
  GNUNET_CONTAINER_DLL_insert (de->dt_head, de->dt_tail, dt);
  /* we're done */
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Free memory occupied by an entry in the destination map.
 *
 * @param cls unused
 * @param key unused
 * @param value a `struct DestinationEntry *`
 * @return #GNUNET_OK (continue to iterate)
 */
static int
cleanup_destination (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct DestinationEntry *de = value;

  free_destination_entry (de);
  return GNUNET_OK;
}


/**
 * Free memory occupied by an entry in the channel map.
 *
 * @param cls unused
 * @param key unused
 * @param value a `struct ChannelState *`
 * @return #GNUNET_OK (continue to iterate)
 */
static int
cleanup_channel (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct ChannelState *ts = value;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Tearing down channel to `%s' during cleanup\n",
              print_channel_destination (&ts->destination));
  free_channel_state (ts);
  return GNUNET_OK;
}


/**
 * Function scheduled as very last function, cleans up after us
 *
 * @param cls unused
 */
static void
cleanup (void *cls)
{
  unsigned int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "VPN is shutting down\n");
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
  if (NULL != channel_map)
  {
    GNUNET_CONTAINER_multihashmap_iterate (channel_map, &cleanup_channel, NULL);
    GNUNET_CONTAINER_multihashmap_destroy (channel_map);
    channel_map = NULL;
  }
  if (NULL != channel_heap)
  {
    GNUNET_CONTAINER_heap_destroy (channel_heap);
    channel_heap = NULL;
  }
  if (NULL != cadet_handle)
  {
    GNUNET_CADET_disconnect (cadet_handle);
    cadet_handle = NULL;
  }
  if (NULL != helper_handle)
  {
    GNUNET_HELPER_kill (helper_handle, GNUNET_NO);
    GNUNET_HELPER_wait (helper_handle);
    helper_handle = NULL;
  }
  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
    stats = NULL;
  }
  for (i = 0; i < 5; i++)
    GNUNET_free_non_null (vpn_argv[i]);
}


/**
 * Callback called when a client connects to the service.
 *
 * @param cls closure for the service
 * @param c the new client that connected to the service
 * @param mq the message queue used to send messages to the client
 * @return @a c
 */
static void *
client_connect_cb (void *cls,
                   struct GNUNET_SERVICE_Client *c,
                   struct GNUNET_MQ_Handle *mq)
{
  return c;
}


/**
 * Callback called when a client disconnected from the service
 *
 * @param cls closure for the service
 * @param c the client that disconnected
 * @param internal_cls should be equal to @a c
 */
static void
client_disconnect_cb (void *cls,
                      struct GNUNET_SERVICE_Client *c,
                      void *internal_cls)
{
  GNUNET_assert (c == internal_cls);
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param cfg_ configuration
 * @param service the initialized service
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg_,
     struct GNUNET_SERVICE_Handle *service)
{
  char *ifname;
  char *ipv6addr;
  char *ipv6prefix_s;
  char *ipv4addr;
  char *ipv4mask;
  struct in_addr v4;
  struct in6_addr v6;
  char *binary;

  binary = GNUNET_OS_get_libexec_binary_path ("gnunet-helper-vpn");

  if (GNUNET_YES !=
      GNUNET_OS_check_helper_binary (
        binary,
        GNUNET_YES,
        "-d gnunet-vpn - - 169.1.3.3.7 255.255.255.0")) // ipv4 only please!
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "`%s' is not SUID, refusing to run.\n",
                "gnunet-helper-vpn");
    GNUNET_free (binary);
    global_ret = 1;
    /* we won't "really" exit here, as the 'service' is still running;
       however, as no handlers are registered, the service won't do
       anything either */
    return;
  }
  GNUNET_free (binary);
  cfg = cfg_;
  stats = GNUNET_STATISTICS_create ("vpn", cfg);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg,
                                             "VPN",
                                             "MAX_MAPPING",
                                             &max_destination_mappings))
    max_destination_mappings = 200;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg,
                                             "VPN",
                                             "MAX_TUNNELS",
                                             &max_channel_mappings))
    max_channel_mappings = 200;

  destination_map =
    GNUNET_CONTAINER_multihashmap_create (max_destination_mappings * 2,
                                          GNUNET_NO);
  destination_heap =
    GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  channel_map =
    GNUNET_CONTAINER_multihashmap_create (max_channel_mappings * 2, GNUNET_NO);
  channel_heap = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);


  vpn_argv[0] = GNUNET_strdup ("vpn-gnunet");
  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "VPN", "IFNAME", &ifname))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR, "VPN", "IFNAME");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  vpn_argv[1] = ifname;
  ipv6addr = NULL;
  if (GNUNET_OK == GNUNET_NETWORK_test_pf (PF_INET6))
  {
    if (((GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string (cfg,
                                                                  "VPN",
                                                                  "IPV6ADDR",
                                                                  &ipv6addr)) ||
         (1 != inet_pton (AF_INET6, ipv6addr, &v6))))
    {
      GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                                 "VPN",
                                 "IPV6ADDR",
                                 _ ("Must specify valid IPv6 address"));
      GNUNET_SCHEDULER_shutdown ();
      GNUNET_free_non_null (ipv6addr);
      return;
    }
    vpn_argv[2] = ipv6addr;
    ipv6prefix_s = NULL;
    if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string (cfg,
                                                                "VPN",
                                                                "IPV6PREFIX",
                                                                &ipv6prefix_s))
    {
      GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR, "VPN", "IPV6PREFIX");
      GNUNET_SCHEDULER_shutdown ();
      GNUNET_free_non_null (ipv6prefix_s);
      return;
    }
    vpn_argv[3] = ipv6prefix_s;
    if ((GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (cfg,
                                                             "VPN",
                                                             "IPV6PREFIX",
                                                             &ipv6prefix)) ||
        (ipv6prefix >= 127))
    {
      GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                                 "VPN",
                                 "IPV4MASK",
                                 _ ("Must specify valid IPv6 mask"));
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _ (
                  "IPv6 support disabled as this system does not support IPv6\n"));
    vpn_argv[2] = GNUNET_strdup ("-");
    vpn_argv[3] = GNUNET_strdup ("-");
  }
  if (GNUNET_OK == GNUNET_NETWORK_test_pf (PF_INET))
  {
    ipv4addr = NULL;
    if (((GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string (cfg,
                                                                  "vpn",
                                                                  "IPV4ADDR",
                                                                  &ipv4addr)) ||
         (1 != inet_pton (AF_INET, ipv4addr, &v4))))
    {
      GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                                 "VPN",
                                 "IPV4ADDR",
                                 _ ("Must specify valid IPv4 address"));
      GNUNET_SCHEDULER_shutdown ();
      GNUNET_free_non_null (ipv4addr);
      return;
    }
    vpn_argv[4] = ipv4addr;
    ipv4mask = NULL;
    if (((GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string (cfg,
                                                                  "vpn",
                                                                  "IPV4MASK",
                                                                  &ipv4mask)) ||
         (1 != inet_pton (AF_INET, ipv4mask, &v4))))
    {
      GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                                 "VPN",
                                 "IPV4MASK",
                                 _ ("Must specify valid IPv4 mask"));
      GNUNET_SCHEDULER_shutdown ();
      GNUNET_free_non_null (ipv4mask);
      return;
    }
    vpn_argv[5] = ipv4mask;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _ (
                  "IPv4 support disabled as this system does not support IPv4\n"));
    vpn_argv[4] = GNUNET_strdup ("-");
    vpn_argv[5] = GNUNET_strdup ("-");
  }
  vpn_argv[6] = NULL;

  cadet_handle = GNUNET_CADET_connect (cfg_);
  // FIXME never opens ports???
  helper_handle = GNUNET_HELPER_start (GNUNET_NO,
                                       "gnunet-helper-vpn",
                                       vpn_argv,
                                       &message_token,
                                       NULL,
                                       NULL);
  GNUNET_SCHEDULER_add_shutdown (&cleanup, NULL);
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN (
  "vpn",
  GNUNET_SERVICE_OPTION_NONE,
  &run,
  &client_connect_cb,
  &client_disconnect_cb,
  NULL,
  GNUNET_MQ_hd_var_size (client_redirect_to_ip,
                         GNUNET_MESSAGE_TYPE_VPN_CLIENT_REDIRECT_TO_IP,
                         struct RedirectToIpRequestMessage,
                         NULL),
  GNUNET_MQ_hd_fixed_size (client_redirect_to_service,
                           GNUNET_MESSAGE_TYPE_VPN_CLIENT_REDIRECT_TO_SERVICE,
                           struct RedirectToServiceRequestMessage,
                           NULL),
  GNUNET_MQ_handler_end ());


/* end of gnunet-service-vpn.c */
