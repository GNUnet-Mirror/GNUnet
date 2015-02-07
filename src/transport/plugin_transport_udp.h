/*
     This file is part of GNUnet
     Copyright (C) 2010-2014 Christian Grothoff (and other contributing authors)

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
 * @file transport/plugin_transport_udp.h
 * @brief Implementation of the UDP transport protocol
 * @author Christian Grothoff
 * @author Nathan Evans
 * @author Matthias Wachs
 */
#ifndef PLUGIN_TRANSPORT_UDP_H
#define PLUGIN_TRANSPORT_UDP_H

#include "platform.h"
#include "gnunet_hello_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_fragmentation_lib.h"
#include "gnunet_nat_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_resolver_service.h"
#include "gnunet_signatures.h"
#include "gnunet_constants.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_transport_plugin.h"
#include "transport.h"

#define LOG(kind,...) GNUNET_log_from (kind, "transport-udp", __VA_ARGS__)

#define PLUGIN_NAME "udp"

#define DEBUG_UDP GNUNET_NO

#define DEBUG_UDP_BROADCASTING GNUNET_NO

/**
 * MTU for fragmentation subsystem.  Should be conservative since
 * all communicating peers MUST work with this MTU.
 */
#define UDP_MTU 1400


GNUNET_NETWORK_STRUCT_BEGIN
/**
 * Network format for IPv4 addresses.
 */
struct IPv4UdpAddress
{
  /**
   * Optional options and flags for this address
   */
  uint32_t options GNUNET_PACKED;

  /**
   * IPv4 address, in network byte order.
   */
  uint32_t ipv4_addr GNUNET_PACKED;

  /**
   * Port number, in network byte order.
   */
  uint16_t u4_port GNUNET_PACKED;
};


/**
 * Network format for IPv6 addresses.
 */
struct IPv6UdpAddress
{
  /**
   * Optional options and flags for this address
   */
  uint32_t options GNUNET_PACKED;

  /**
   * IPv6 address.
   */
  struct in6_addr ipv6_addr GNUNET_PACKED;

  /**
   * Port number, in network byte order.
   */
  uint16_t u6_port GNUNET_PACKED;
};
GNUNET_NETWORK_STRUCT_END

/**
 * Either an IPv4 or IPv6 UDP address.  Note that without a "length",
 * one cannot tell which one of the two types this address represents.
 */
union UdpAddress
{
  /**
   * IPv4 case.
   */
  struct IPv4UdpAddress v4;

  /**
   * IPv6 case.
   */
  struct IPv6UdpAddress v6;
};


/**
 * UDP Message-Packet header (after defragmentation).
 */
struct UDPMessage
{
  /**
   * Message header.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero for now.
   */
  uint32_t reserved;

  /**
   * What is the identity of the sender
   */
  struct GNUNET_PeerIdentity sender;

};

struct UDP_MessageWrapper;

struct PrettyPrinterContext;


/**
 * Encapsulation of all of the state of the plugin.
 */
struct Plugin
{

  /**
   * Our environment.
   */
  struct GNUNET_TRANSPORT_PluginEnvironment *env;

  /**
   * Session of peers with whom we are currently connected,
   * map of peer identity to `struct Session *`.
   */
  struct GNUNET_CONTAINER_MultiPeerMap *sessions;

  /**
   * Heap with all of our defragmentation activities.
   */
  struct GNUNET_CONTAINER_Heap *defrag_ctxs;

  /**
   * ID of select task for IPv4
   */
  struct GNUNET_SCHEDULER_Task *select_task;

  /**
   * ID of select task for IPv6
   */
  struct GNUNET_SCHEDULER_Task *select_task_v6;

  /**
   * Tokenizer for inbound messages.
   */
  struct GNUNET_SERVER_MessageStreamTokenizer *mst;

  /**
   * Bandwidth tracker to limit global UDP traffic.
   */
  struct GNUNET_BANDWIDTH_Tracker tracker;

  /**
   * Address we were told to bind to exclusively (IPv4).
   */
  char *bind4_address;

  /**
   * Address we were told to bind to exclusively (IPv6).
   */
  char *bind6_address;

  /**
   * Handle to NAT traversal support.
   */
  struct GNUNET_NAT_Handle *nat;

  /**
   * FD Read set
   */
  struct GNUNET_NETWORK_FDSet *rs_v4;

  /**
   * FD Write set
   */
  struct GNUNET_NETWORK_FDSet *ws_v4;

  /**
   * The read socket for IPv4
   */
  struct GNUNET_NETWORK_Handle *sockv4;

  /**
   * FD Read set
   */
  struct GNUNET_NETWORK_FDSet *rs_v6;

  /**
   * FD Write set
   */
  struct GNUNET_NETWORK_FDSet *ws_v6;

  /**
   * The read socket for IPv6
   */
  struct GNUNET_NETWORK_Handle *sockv6;

  /**
   * Tokenizer for inbound messages.
   */
  struct GNUNET_SERVER_MessageStreamTokenizer *broadcast_mst;

  /**
   * Head of DLL of broadcast addresses
   */
  struct BroadcastAddress *broadcast_tail;

  /**
   * Tail of DLL of broadcast addresses
   */
  struct BroadcastAddress *broadcast_head;

  /**
   * Head of messages in IPv4 queue.
   */
  struct UDP_MessageWrapper *ipv4_queue_head;

  /**
   * Tail of messages in IPv4 queue.
   */
  struct UDP_MessageWrapper *ipv4_queue_tail;

  /**
   * Head of messages in IPv6 queue.
   */
  struct UDP_MessageWrapper *ipv6_queue_head;

  /**
   * Tail of messages in IPv6 queue.
   */
  struct UDP_MessageWrapper *ipv6_queue_tail;

  /**
   * Running pretty printers: head
   */
  struct PrettyPrinterContext *ppc_dll_head;

  /**
   * Running pretty printers: tail
   */
  struct PrettyPrinterContext *ppc_dll_tail;

  /**
   * Function to call about session status changes.
   */
  GNUNET_TRANSPORT_SessionInfoCallback sic;

  /**
   * Closure for @e sic.
   */
  void *sic_cls;

  /**
   * IPv6 multicast address
   */
  struct sockaddr_in6 ipv6_multicast_address;

  /**
   * Broadcast interval
   */
  struct GNUNET_TIME_Relative broadcast_interval;

  /**
   * Bytes currently in buffer
   */
  int64_t bytes_in_buffer;

  /**
   * Address options
   */
  uint32_t myoptions;

  /**
   * Is IPv6 enabled: #GNUNET_YES or #GNUNET_NO
   */
  int enable_ipv6;

  /**
   * Is IPv4 enabled: #GNUNET_YES or #GNUNET_NO
   */
  int enable_ipv4;

  /**
   * Is broadcasting enabled: #GNUNET_YES or #GNUNET_NO
   */
  int enable_broadcasting;

  /**
   * Is receiving broadcasts enabled: #GNUNET_YES or #GNUNET_NO
   */
  int enable_broadcasting_receiving;

  /**
   * Port we broadcasting on.
   */
  uint16_t broadcast_port;

  /**
   * Port we listen on.
   */
  uint16_t port;

  /**
   * Port we advertise on.
   */
  uint16_t aport;

};


const char *
udp_address_to_string (void *cls,
                       const void *addr,
                       size_t addrlen);


/**
 * We received a broadcast message.  Process it and all subsequent
 * messages in the same packet.
 *
 * @param plugin the UDP plugin
 * @param buf the buffer with the message(s)
 * @param size number of bytes in @a buf
 * @param udp_addr address of the sender
 * @param udp_addr_len number of bytes in @a udp_addr
 * @param network_type network type of the sender's address
 */
void
udp_broadcast_receive (struct Plugin *plugin,
                       const char *buf,
                       ssize_t size,
                       const union UdpAddress *udp_addr,
                       size_t udp_addr_len,
                       enum GNUNET_ATS_Network_Type network_type);


void
setup_broadcast (struct Plugin *plugin,
                 struct sockaddr_in6 *server_addrv6,
                 struct sockaddr_in *server_addrv4);


void
stop_broadcast (struct Plugin *plugin);

/*#ifndef PLUGIN_TRANSPORT_UDP_H*/
#endif
/* end of plugin_transport_udp.h */
