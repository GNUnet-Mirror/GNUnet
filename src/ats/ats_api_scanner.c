/*
     This file is part of GNUnet.
     Copyright (C) 2010-2015 Christian Grothoff (and other contributing authors)

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
 * @file ats/ats_api_scanner.c
 * @brief LAN interface scanning to determine IPs in LAN
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_ats_service.h"

/**
 * How frequently do we scan the interfaces for changes to the addresses?
 */
#define INTERFACE_PROCESSING_INTERVAL GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 2)


/**
 * Convert a `enum GNUNET_ATS_Network_Type` to a string
 *
 * @param net the network type
 * @return a string or NULL if invalid
 */
const char *
GNUNET_ATS_print_network_type (enum GNUNET_ATS_Network_Type net)
{
  switch (net)
    {
    case GNUNET_ATS_NET_UNSPECIFIED:
      return "UNSPECIFIED";
    case GNUNET_ATS_NET_LOOPBACK:
      return "LOOPBACK";
    case GNUNET_ATS_NET_LAN:
      return "LAN";
    case GNUNET_ATS_NET_WAN:
      return "WAN";
    case GNUNET_ATS_NET_WLAN:
      return "WLAN";
    case GNUNET_ATS_NET_BT:
      return "BLUETOOTH";
    default:
      return NULL;
    }
}


/**
 * Convert a ATS property to a string
 *
 * @param type the property type
 * @return a string or NULL if invalid
 */
const char *
GNUNET_ATS_print_property_type (enum GNUNET_ATS_Property type)
{
  switch (type)
  {
  case GNUNET_ATS_ARRAY_TERMINATOR:
    return "TERMINATOR";
  case GNUNET_ATS_UTILIZATION_OUT:
    return "UTILIZATION_UP";
  case GNUNET_ATS_UTILIZATION_IN:
    return "UTILIZATION_DOWN";
  case GNUNET_ATS_NETWORK_TYPE:
    return "NETWORK_TYPE";
  case GNUNET_ATS_QUALITY_NET_DELAY:
    return "DELAY";
  case GNUNET_ATS_QUALITY_NET_DISTANCE:
    return "DISTANCE";
  default:
    GNUNET_break (0);
    return NULL;
  }
}


/**
 * We keep a list of our local networks so we can answer
 * LAN vs. WAN questions.  Note: WLAN is not detected yet.
 * (maybe we can do that heuristically based on interface
 * name in the future?).
 */
struct ATS_Network
{
  /**
   * Kept in a DLL.
   */
  struct ATS_Network *next;

  /**
   * Kept in a DLL.
   */
  struct ATS_Network *prev;

  /**
   * Network address.
   */
  struct sockaddr *network;

  /**
   * Netmask to determine what is in the LAN.
   */
  struct sockaddr *netmask;

  /**
   * How long are @e network and @e netmask?
   */
  socklen_t length;
};


/**
 * Handle to the interface scanner.
 */
struct GNUNET_ATS_InterfaceScanner
{

  /**
   * Head of LAN networks list.
   */
  struct ATS_Network *net_head;

  /**
   * Tail of LAN networks list.
   */
  struct ATS_Network *net_tail;

  /**
   * Task for periodically refreshing our LAN network list.
   */
  struct GNUNET_SCHEDULER_Task *interface_task;

};


/**
 * Delete all entries from the current network list.
 *
 * @param is scanner to clean up
 */
static void
delete_networks (struct GNUNET_ATS_InterfaceScanner *is)
{
  struct ATS_Network *cur;

  while (NULL != (cur = is->net_head))
  {
    GNUNET_CONTAINER_DLL_remove (is->net_head,
                                 is->net_tail,
                                 cur);
    GNUNET_free (cur);
  }
}


/**
 * Function invoked for each interface found.  Adds the interface's
 * network addresses to the respective DLL, so we can distinguish
 * between LAN and WAN.
 *
 * @param cls closure with the `struct GNUNET_ATS_InterfaceScanner`
 * @param name name of the interface (can be NULL for unknown)
 * @param isDefault is this presumably the default interface
 * @param addr address of this interface (can be NULL for unknown or unassigned)
 * @param broadcast_addr the broadcast address (can be NULL for unknown or unassigned)
 * @param netmask the network mask (can be NULL for unknown or unassigned)
 * @param addrlen length of the address
 * @return #GNUNET_OK to continue iteration
 */
static int
interface_proc (void *cls,
                const char *name,
                int isDefault,
                const struct sockaddr *addr,
                const struct sockaddr *broadcast_addr,
                const struct sockaddr *netmask,
                socklen_t addrlen)
{
  struct GNUNET_ATS_InterfaceScanner *is = cls;
  /* Calculate network */
  struct ATS_Network *net = NULL;

  /* Skipping IPv4 loopback addresses since we have special check  */
  if  (addr->sa_family == AF_INET)
  {
    const struct sockaddr_in *a4 = (const struct sockaddr_in *) addr;

    if ((a4->sin_addr.s_addr & htonl(0xff000000)) == htonl (0x7f000000))
       return GNUNET_OK;
  }
  /* Skipping IPv6 loopback addresses since we have special check  */
  if  (addr->sa_family == AF_INET6)
  {
    const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *) addr;
    if (IN6_IS_ADDR_LOOPBACK (&a6->sin6_addr))
      return GNUNET_OK;
  }

  if (addr->sa_family == AF_INET)
  {
    const struct sockaddr_in *addr4 = (const struct sockaddr_in *) addr;
    const struct sockaddr_in *netmask4 = (const struct sockaddr_in *) netmask;
    struct sockaddr_in *tmp;
    struct sockaddr_in network4;

    net = GNUNET_malloc (sizeof (struct ATS_Network) + 2 * sizeof (struct sockaddr_in));
    tmp = (struct sockaddr_in *) &net[1];
    net->network = (struct sockaddr *) &tmp[0];
    net->netmask = (struct sockaddr *) &tmp[1];
    net->length = addrlen;

    memset (&network4, 0, sizeof (network4));
    network4.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
    network4.sin_len = sizeof (network4);
#endif
    network4.sin_addr.s_addr = (addr4->sin_addr.s_addr & netmask4->sin_addr.s_addr);

    memcpy (net->netmask, netmask4, sizeof (struct sockaddr_in));
    memcpy (net->network, &network4, sizeof (struct sockaddr_in));
  }

  if (addr->sa_family == AF_INET6)
  {
    const struct sockaddr_in6 *addr6 = (const struct sockaddr_in6 *) addr;
    const struct sockaddr_in6 *netmask6 = (const struct sockaddr_in6 *) netmask;
    struct sockaddr_in6 * tmp;
    struct sockaddr_in6 network6;

    net = GNUNET_malloc (sizeof (struct ATS_Network) + 2 * sizeof (struct sockaddr_in6));
    tmp = (struct sockaddr_in6 *) &net[1];
    net->network = (struct sockaddr *) &tmp[0];
    net->netmask = (struct sockaddr *) &tmp[1];
    net->length = addrlen;

    memset (&network6, 0, sizeof (network6));
    network6.sin6_family = AF_INET6;
#if HAVE_SOCKADDR_IN_SIN_LEN
    network6.sin6_len = sizeof (network6);
#endif
    unsigned int c = 0;
    uint32_t *addr_elem = (uint32_t *) &addr6->sin6_addr;
    uint32_t *mask_elem = (uint32_t *) &netmask6->sin6_addr;
    uint32_t *net_elem = (uint32_t *) &network6.sin6_addr;
    for (c = 0; c < 4; c++)
      net_elem[c] = addr_elem[c] & mask_elem[c];

    memcpy (net->netmask, netmask6, sizeof (struct sockaddr_in6));
    memcpy (net->network, &network6, sizeof (struct sockaddr_in6));
  }
  if (NULL == net)
    return GNUNET_OK; /* odd / unsupported address family */

  /* Store in list */
#if VERBOSE_ATS
  char * netmask = GNUNET_strdup (GNUNET_a2s((struct sockaddr *) net->netmask, addrlen));
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "ats-scanner-api",
                   "Adding network `%s', netmask `%s'\n",
                   GNUNET_a2s ((struct sockaddr *) net->network,
                               addrlen),
                   netmask);
  GNUNET_free (netmask);
#endif
  GNUNET_CONTAINER_DLL_insert (is->net_head,
                               is->net_tail,
                               net);

  return GNUNET_OK;
}


/**
 * Periodically get list of network addresses from our interfaces.
 *
 * @param cls closure
 * @param tc Task context
 */
static void
get_addresses (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_ATS_InterfaceScanner *is = cls;

  is->interface_task = NULL;
  delete_networks (is);
  GNUNET_OS_network_interfaces_list (&interface_proc,
                                     is);
  is->interface_task = GNUNET_SCHEDULER_add_delayed (INTERFACE_PROCESSING_INTERVAL,
                                                     &get_addresses,
                                                     is);
}


/**
 * Returns where the address is located: LAN or WAN or ...
 *
 * @param is the interface scanner handle
 * @param addr address
 * @param addrlen address length
 * @return type of the network the address belongs to
 */
enum GNUNET_ATS_Network_Type
GNUNET_ATS_scanner_address_get_type (struct GNUNET_ATS_InterfaceScanner *is,
                                     const struct sockaddr *addr,
                                     socklen_t addrlen)
{
  struct ATS_Network *cur = is->net_head;
  enum GNUNET_ATS_Network_Type type = GNUNET_ATS_NET_UNSPECIFIED;

  switch (addr->sa_family)
    {
    case AF_UNIX:
      type = GNUNET_ATS_NET_LOOPBACK;
      break;
    case AF_INET:
      {
        const struct sockaddr_in *a4 = (const struct sockaddr_in *) addr;

        if ((a4->sin_addr.s_addr & htonl(0xff000000)) == htonl (0x7f000000))
          type = GNUNET_ATS_NET_LOOPBACK;
        break;
      }
    case AF_INET6:
      {
        const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *) addr;

        if (IN6_IS_ADDR_LOOPBACK (&a6->sin6_addr))
          type = GNUNET_ATS_NET_LOOPBACK;
        break;
      }
    default:
      GNUNET_break (0);
      break;
   }

  /* Check local networks */
  while ((NULL != cur) && (GNUNET_ATS_NET_UNSPECIFIED == type))
  {
    if (addrlen != cur->length)
    {
      cur = cur->next;
      continue;
    }
    if (addr->sa_family == AF_INET)
    {
      const struct sockaddr_in *a4 = (const struct sockaddr_in *) addr;
      const struct sockaddr_in *net4 = (const struct sockaddr_in *) cur->network;
      const struct sockaddr_in *mask4 = (const struct sockaddr_in *) cur->netmask;

      if (((a4->sin_addr.s_addr & mask4->sin_addr.s_addr)) == net4->sin_addr.s_addr)
        type = GNUNET_ATS_NET_LAN;
    }
    if (addr->sa_family == AF_INET6)
    {
      const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *) addr;
      const struct sockaddr_in6 *net6 = (const struct sockaddr_in6 *) cur->network;
      const struct sockaddr_in6 *mask6 = (const struct sockaddr_in6 *) cur->netmask;

      int res = GNUNET_YES;
      int c = 0;
      uint32_t *addr_elem = (uint32_t *) &a6->sin6_addr;
      uint32_t *mask_elem = (uint32_t *) &mask6->sin6_addr;
      uint32_t *net_elem = (uint32_t *) &net6->sin6_addr;
      for (c = 0; c < 4; c++)
        if ((addr_elem[c] & mask_elem[c]) != net_elem[c])
          res = GNUNET_NO;

      if (res == GNUNET_YES)
        type = GNUNET_ATS_NET_LAN;
    }
    cur = cur->next;
  }

  /* no local network found for this address, default: WAN */
  if (type == GNUNET_ATS_NET_UNSPECIFIED)
    type = GNUNET_ATS_NET_WAN;
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "ats-scanner-api",
                   "`%s' is in network `%s'\n",
                   GNUNET_a2s (addr,
                               addrlen),
                   GNUNET_ATS_print_network_type (type));
  return type;
}


/**
 * Initialize the interface scanner.
 *
 * @return interface scanner
 */
struct GNUNET_ATS_InterfaceScanner *
GNUNET_ATS_scanner_init ()
{
  struct GNUNET_ATS_InterfaceScanner *is;

  is = GNUNET_new (struct GNUNET_ATS_InterfaceScanner);
  GNUNET_OS_network_interfaces_list (&interface_proc,
                                     is);
  is->interface_task = GNUNET_SCHEDULER_add_delayed (INTERFACE_PROCESSING_INTERVAL,
                                                     &get_addresses,
                                                     is);
  return is;
}


/**
 * Client is done with the interface scanner, release resources.
 *
 * @param is handle to release
 */
void
GNUNET_ATS_scanner_done (struct GNUNET_ATS_InterfaceScanner *is)
{
  if (NULL != is->interface_task)
  {
    GNUNET_SCHEDULER_cancel (is->interface_task);
    is->interface_task = NULL;
  }
  delete_networks (is);
  GNUNET_free (is);
}


/* end of ats_api_scanner.c */
