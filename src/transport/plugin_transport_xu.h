/*
     This file is part of GNUnet
     Copyright (C) 2010-2014 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
*/

/**
 * @file transport/plugin_transport_xu.h
 * @brief Implementation of the XU transport protocol
 * @author Christian Grothoff
 * @author Nathan Evans
 * @author Matthias Wachs
 */
#ifndef PLUGIN_TRANSPORT_XU_H
#define PLUGIN_TRANSPORT_XU_H

#include "platform.h"
#include "gnunet_hello_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_fragmentation_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_resolver_service.h"
#include "gnunet_signatures.h"
#include "gnunet_constants.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_transport_plugin.h"
#include "transport.h"

#define LOG(kind,...) GNUNET_log_from (kind, "transport-xu", __VA_ARGS__)

#define PLUGIN_NAME "xu"

#define DEBUG_XU GNUNET_NO

#define DEBUG_XU_BROADCASTING GNUNET_NO

/**
 * MTU for fragmentation subsystem.  Should be conservative since
 * all communicating peers MUST work with this MTU.
 */
#define XU_MTU 1400


GNUNET_NETWORK_STRUCT_BEGIN
/**
 * Network format for IPv4 addresses.
 */
struct IPv4XuAddress
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
struct IPv6XuAddress
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
 * Either an IPv4 or IPv6 XU address.  Note that without a "length",
 * one cannot tell which one of the two types this address represents.
 */
union XuAddress
{
  /**
   * IPv4 case.
   */
  struct IPv4XuAddress v4;

  /**
   * IPv6 case.
   */
  struct IPv6XuAddress v6;
};


/**
 * Information we track for each message in the queue.
 */
struct XU_MessageWrapper;


/**
 * Closure for #append_port().
 */
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
   * map of peer identity to `struct GNUNET_ATS_Session *`.
   */
  struct GNUNET_CONTAINER_MultiPeerMap *sessions;

  /**
   * ID of select task for IPv4
   */
  struct GNUNET_SCHEDULER_Task *select_task_v4;

  /**
   * ID of select task for IPv6
   */
  struct GNUNET_SCHEDULER_Task *select_task_v6;

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
   * Handle to NAT traversal support.
   */
  struct GNUNET_NAT_STUN_Handle *stun;

  /**
   * The read socket for IPv4
   */
  struct GNUNET_NETWORK_Handle *sockv4;

  /**
   * The read socket for IPv6
   */
  struct GNUNET_NETWORK_Handle *sockv6;

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
   * Port we listen on.
   */
  uint16_t port;

  /**
   * Port we advertise on.
   */
  uint16_t aport;

};


/**
 * Function called for a quick conversion of the binary address to
 * a numeric address.  Note that the caller must not free the
 * address and that the next call to this function is allowed
 * to override the address again.
 *
 * @param cls closure
 * @param addr binary address (a `union XuAddress`)
 * @param addrlen length of the @a addr
 * @return string representing the same address
 */
const char *
xu_address_to_string (void *cls,
                       const void *addr,
                       size_t addrlen);


/*#ifndef PLUGIN_TRANSPORT_XU_H*/
#endif
/* end of plugin_transport_xu.h */
