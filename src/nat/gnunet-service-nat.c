/*
  This file is part of GNUnet.
  Copyright (C) 2016, 2017 GNUnet e.V.

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
 * @file nat/gnunet-service-nat.c
 * @brief network address translation traversal service
 * @author Christian Grothoff
 *
 * The purpose of this service is to enable transports to
 * traverse NAT routers, by providing traversal options and
 * knowledge about the local network topology.
 *
 * TODO:
 * - migrate test cases to new NAT service
 * - add new traceroute-based logic for external IP detection
 *
 * - implement & test STUN processing to classify NAT;
 *   basically, open port & try different methods.
 */
#include "platform.h"
#include <math.h>
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_signatures.h"
#include "gnunet_statistics_service.h"
#include "gnunet_resolver_service.h"
#include "gnunet_nat_service.h"
#include "gnunet-service-nat.h"
#include "gnunet-service-nat_externalip.h"
#include "gnunet-service-nat_stun.h"
#include "gnunet-service-nat_mini.h"
#include "gnunet-service-nat_helper.h"
#include "nat.h"
#include <gcrypt.h>


/**
 * How often should we ask the OS about a list of active
 * network interfaces?
 */
#define SCAN_FREQ GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15)

/**
 * How long do we wait until we forcefully terminate autoconfiguration?
 */
#define AUTOCONFIG_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * How often do we scan for changes in how our external (dyndns) hostname resolves?
 */
#define DYNDNS_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 7)


/**
 * Information we track per client address.
 */
struct ClientAddress
{
  /**
   * Network address used by the client.
   */
  struct sockaddr_storage ss;

  /**
   * Handle to active UPnP request where we asked upnpc to open
   * a port at the NAT.  NULL if we do not have such a request
   * pending.
   */
  struct GNUNET_NAT_MiniHandle *mh;

};


/**
 * List of local addresses this system has.
 */
struct LocalAddressList
{
  /**
   * This is a linked list.
   */
  struct LocalAddressList *next;

  /**
   * Previous entry.
   */
  struct LocalAddressList *prev;

  /**
   * Context for a gnunet-helper-nat-server used to listen
   * for ICMP messages to this client for connection reversal.
   */
  struct HelperContext *hc;

  /**
   * The address itself (i.e. `struct sockaddr_in` or `struct
   * sockaddr_in6`, in the respective byte order).
   */
  struct sockaddr_storage addr;

  /**
   * Address family. (FIXME: redundant, addr.ss_family! Remove!?)
   */
  int af;

  /**
   * #GNUNET_YES if we saw this one in the previous iteration,
   * but not in the current iteration and thus might need to
   * remove it at the end.
   */
  int old;

  /**
   * What type of address is this?
   */
  enum GNUNET_NAT_AddressClass ac;

};


/**
 * Internal data structure we track for each of our clients.
 */
struct ClientHandle
{

  /**
   * Kept in a DLL.
   */
  struct ClientHandle *next;

  /**
   * Kept in a DLL.
   */
  struct ClientHandle *prev;

  /**
   * Underlying handle for this client with the service.
   */
  struct GNUNET_SERVICE_Client *client;

  /**
   * Message queue for communicating with the client.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Array of addresses used by the service.
   */
  struct ClientAddress *caddrs;

  /**
   * External DNS name and port given by user due to manual
   * hole punching.  Special DNS name 'AUTO' is used to indicate
   * desire for automatic determination of the external IP
   * (instead of DNS or manual configuration, i.e. to be used
   * if the IP keeps changing and we have no DynDNS, but we do
   * have a hole punched).
   */
  char *hole_external;

  /**
   * Name of the configuration section this client cares about.
   */
  char *section_name;

  /**
   * Task for periodically re-running the @e ext_dns DNS lookup.
   */
  struct GNUNET_SCHEDULER_Task *ext_dns_task;

  /**
   * Handle for (DYN)DNS lookup of our external IP as given in
   * @e hole_external.
   */
  struct GNUNET_RESOLVER_RequestHandle *ext_dns;

  /**
   * Handle for monitoring external IP changes.
   */
  struct GN_ExternalIPMonitor *external_monitor;

  /**
   * DLL of external IP addresses as given in @e hole_external.
   */
  struct LocalAddressList *ext_addr_head;

  /**
   * DLL of external IP addresses as given in @e hole_external.
   */
  struct LocalAddressList *ext_addr_tail;

  /**
   * Port number we found in @e hole_external.
   */
  uint16_t ext_dns_port;

  /**
   * What does this client care about?
   */
  enum GNUNET_NAT_RegisterFlags flags;

  /**
   * Is any of the @e caddrs in a reserved subnet for NAT?
   */
  int natted_address;

  /**
   * Number of addresses that this service is bound to.
   * Length of the @e caddrs array.
   */
  uint16_t num_caddrs;

  /**
   * Client's IPPROTO, e.g. IPPROTO_UDP or IPPROTO_TCP.
   */
  uint8_t proto;

};


/**
 * External IP address as given to us via some STUN server.
 */
struct StunExternalIP
{
  /**
   * Kept in a DLL.
   */
  struct StunExternalIP *next;

  /**
   * Kept in a DLL.
   */
  struct StunExternalIP *prev;

  /**
   * Task we run to remove this entry when it is stale.
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

  /**
   * Our external IP address as reported by the
   * STUN server.
   */
  struct sockaddr_in external_addr;

  /**
   * Address of the reporting STUN server.  Used to
   * detect when a STUN server changes its opinion
   * to more quickly remove stale results.
   */
  struct sockaddr_storage stun_server_addr;

  /**
   * Number of bytes used in @e stun_server_addr.
   */
  size_t stun_server_addr_len;
};


/**
 * Timeout to use when STUN data is considered stale.
 */
static struct GNUNET_TIME_Relative stun_stale_timeout;

/**
 * How often do we scan for changes in how our external (dyndns) hostname resolves?
 */
static struct GNUNET_TIME_Relative dyndns_frequency;

/**
 * Handle to our current configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to the statistics service.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Task scheduled to periodically scan our network interfaces.
 */
static struct GNUNET_SCHEDULER_Task *scan_task;

/**
 * Head of client DLL.
 */
static struct ClientHandle *ch_head;

/**
 * Tail of client DLL.
 */
static struct ClientHandle *ch_tail;

/**
 * Head of DLL of local addresses.
 */
static struct LocalAddressList *lal_head;

/**
 * Tail of DLL of local addresses.
 */
static struct LocalAddressList *lal_tail;

/**
 * Kept in a DLL.
 */
static struct StunExternalIP *se_head;

/**
 * Kept in a DLL.
 */
static struct StunExternalIP *se_tail;

/**
 * Is UPnP enabled? #GNUNET_YES if enabled, #GNUNET_NO if disabled,
 * #GNUNET_SYSERR if configuration enabled but binary is unavailable.
 */
int enable_upnp;


/**
 * Remove and free an entry from the #lal_head DLL.
 *
 * @param lal entry to free
 */
static void
free_lal (struct LocalAddressList *lal)
{
  GNUNET_CONTAINER_DLL_remove (lal_head,
			       lal_tail,
			       lal);
  if (NULL != lal->hc)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
		"Lost NATed local address %s, stopping NAT server\n",
		GNUNET_a2s ((const struct sockaddr *) &lal->addr,
			    sizeof (struct sockaddr_in)));

    GN_stop_gnunet_nat_server_ (lal->hc);
    lal->hc = NULL;
  }
  GNUNET_free (lal);
}


/**
 * Free the DLL starting at #lal_head.
 */
static void
destroy_lal ()
{
  struct LocalAddressList *lal;

  while (NULL != (lal = lal_head))
    free_lal (lal);
}


/**
 * Check validity of #GNUNET_MESSAGE_TYPE_NAT_REGISTER message from
 * client.
 *
 * @param cls client who sent the message
 * @param message the message received
 * @return #GNUNET_OK if message is well-formed
 */
static int
check_register (void *cls,
		const struct GNUNET_NAT_RegisterMessage *message)
{
  uint16_t num_addrs = ntohs (message->num_addrs);
  const char *off = (const char *) &message[1];
  size_t left = ntohs (message->header.size) - sizeof (*message);

  for (unsigned int i=0;i<num_addrs;i++)
  {
    size_t alen;
    const struct sockaddr *sa = (const struct sockaddr *) off;

    if (sizeof (sa_family_t) > left)
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    switch (sa->sa_family)
    {
    case AF_INET:
      alen = sizeof (struct sockaddr_in);
      break;
    case AF_INET6:
      alen = sizeof (struct sockaddr_in6);
      break;
#if AF_UNIX
    case AF_UNIX:
      alen = sizeof (struct sockaddr_un);
      break;
#endif
    default:
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    if (alen > left)
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    off += alen;
    left -= alen;
  }
  if (left != ntohs (message->str_len))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Check if @a ip is in @a network with @a bits netmask.
 *
 * @param network to test
 * @param ip IP address to test
 * @param bits bitmask for the network
 * @return #GNUNET_YES if @a ip is in @a network
 */
static int
match_ipv4 (const char *network,
	    const struct in_addr *ip,
	    uint8_t bits)
{
  struct in_addr net;

  if (0 == ip->s_addr)
    return GNUNET_YES;
  if (0 == bits)
    return GNUNET_YES;
  GNUNET_assert (1 == inet_pton (AF_INET,
				 network,
				 &net));
  return ! ((ip->s_addr ^ net.s_addr) & htonl (0xFFFFFFFFu << (32 - bits)));
}


/**
 * Check if @a ip is in @a network with @a bits netmask.
 *
 * @param network to test
 * @param ip IP address to test
 * @param bits bitmask for the network
 * @return #GNUNET_YES if @a ip is in @a network
 */
static int
match_ipv6 (const char *network,
	    const struct in6_addr *ip,
	    uint8_t bits)
{
  struct in6_addr net;
  struct in6_addr mask;
  unsigned int off;

  if (0 == bits)
    return GNUNET_YES;
  GNUNET_assert (1 == inet_pton (AF_INET6,
				 network,
				 &net));
  memset (&mask, 0, sizeof (mask));
  if (0 == GNUNET_memcmp (&mask,
		   ip))
    return GNUNET_YES;
  off = 0;
  while (bits > 8)
  {
    mask.s6_addr[off++] = 0xFF;
    bits -= 8;
  }
  while (bits > 0)
  {
    mask.s6_addr[off] = (mask.s6_addr[off] >> 1) + 0x80;
    bits--;
  }
  for (unsigned j = 0; j < sizeof (struct in6_addr) / sizeof (uint32_t); j++)
    if (((((uint32_t *) ip)[j] & ((uint32_t *) &mask)[j])) !=
	(((uint32_t *) &net)[j] & ((int *) &mask)[j]))
      return GNUNET_NO;
  return GNUNET_YES;
}


/**
 * Test if the given IPv4 address is in a known range
 * for private networks.
 *
 * @param ip address to test
 * @return #GNUNET_YES if @a ip is in a NAT range
 */
static int
is_nat_v4 (const struct in_addr *ip)
{
  return
    match_ipv4 ("10.0.0.0", ip, 8) || /* RFC 1918 */
    match_ipv4 ("100.64.0.0", ip, 10) || /* CG-NAT, RFC 6598 */
    match_ipv4 ("192.168.0.0", ip, 12) || /* RFC 1918 */
    match_ipv4 ("169.254.0.0", ip, 16) || /* AUTO, RFC 3927 */
    match_ipv4 ("172.16.0.0", ip, 16);  /* RFC 1918 */
}


/**
 * Test if the given IPv6 address is in a known range
 * for private networks.
 *
 * @param ip address to test
 * @return #GNUNET_YES if @a ip is in a NAT range
 */
static int
is_nat_v6 (const struct in6_addr *ip)
{
  return
    match_ipv6 ("fc00::", ip, 7) || /* RFC 4193 */
    match_ipv6 ("fec0::", ip, 10) || /* RFC 3879 */
    match_ipv6 ("fe80::", ip, 10); /* RFC 4291, link-local */
}


/**
 * Closure for #ifc_proc.
 */
struct IfcProcContext
{

  /**
   * Head of DLL of local addresses.
   */
  struct LocalAddressList *lal_head;

  /**
   * Tail of DLL of local addresses.
   */
  struct LocalAddressList *lal_tail;

};


/**
 * Callback function invoked for each interface found.  Adds them
 * to our new address list.
 *
 * @param cls a `struct IfcProcContext *`
 * @param name name of the interface (can be NULL for unknown)
 * @param isDefault is this presumably the default interface
 * @param addr address of this interface (can be NULL for unknown or unassigned)
 * @param broadcast_addr the broadcast address (can be NULL for unknown or unassigned)
 * @param netmask the network mask (can be NULL for unknown or unassigned)
 * @param addrlen length of the address
 * @return #GNUNET_OK to continue iteration, #GNUNET_SYSERR to abort
 */
static int
ifc_proc (void *cls,
	  const char *name,
	  int isDefault,
	  const struct sockaddr *addr,
	  const struct sockaddr *broadcast_addr,
	  const struct sockaddr *netmask,
	  socklen_t addrlen)
{
  struct IfcProcContext *ifc_ctx = cls;
  struct LocalAddressList *lal;
  size_t alen;
  const struct in_addr *ip4;
  const struct in6_addr *ip6;
  enum GNUNET_NAT_AddressClass ac;

  switch (addr->sa_family)
  {
  case AF_INET:
    alen = sizeof (struct sockaddr_in);
    ip4 = &((const struct sockaddr_in *) addr)->sin_addr;
    if (match_ipv4 ("127.0.0.0", ip4, 8))
      ac = GNUNET_NAT_AC_LOOPBACK;
    else if (is_nat_v4 (ip4))
      ac = GNUNET_NAT_AC_LAN;
    else
      ac = GNUNET_NAT_AC_GLOBAL;
    break;
  case AF_INET6:
    alen = sizeof (struct sockaddr_in6);
    ip6 = &((const struct sockaddr_in6 *) addr)->sin6_addr;
    if (match_ipv6 ("::1", ip6, 128))
      ac = GNUNET_NAT_AC_LOOPBACK;
    else if (is_nat_v6 (ip6))
      ac = GNUNET_NAT_AC_LAN;
    else
      ac = GNUNET_NAT_AC_GLOBAL;
    if ( (ip6->s6_addr[11] == 0xFF) &&
	 (ip6->s6_addr[12] == 0xFE) )
    {
      /* contains a MAC, be extra careful! */
      ac |= GNUNET_NAT_AC_PRIVATE;
    }
    break;
#if AF_UNIX
  case AF_UNIX:
    GNUNET_break (0);
    return GNUNET_OK;
#endif
  default:
    GNUNET_break (0);
    return GNUNET_OK;
  }
  lal = GNUNET_malloc (sizeof (*lal));
  lal->af = addr->sa_family;
  lal->ac = ac;
  GNUNET_memcpy (&lal->addr,
		 addr,
		 alen);
  GNUNET_CONTAINER_DLL_insert (ifc_ctx->lal_head,
			       ifc_ctx->lal_tail,
			       lal);
  return GNUNET_OK;
}


/**
 * Notify client about a change in the list of addresses this peer
 * has.
 *
 * @param ac address class of the entry in the list that changed
 * @param ch client to contact
 * @param add #GNUNET_YES to add, #GNUNET_NO to remove
 * @param addr the address that changed
 * @param addr_len number of bytes in @a addr
 */
static void
notify_client (enum GNUNET_NAT_AddressClass ac,
	       struct ClientHandle *ch,
	       int add,
	       const void *addr,
	       size_t addr_len)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_NAT_AddressChangeNotificationMessage *msg;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Notifying client about %s of IP %s\n",
              add ? "addition" : "removal",
              GNUNET_a2s (addr,
                          addr_len));
  env = GNUNET_MQ_msg_extra (msg,
			     addr_len,
			     GNUNET_MESSAGE_TYPE_NAT_ADDRESS_CHANGE);
  msg->add_remove = htonl (add);
  msg->addr_class = htonl (ac);
  GNUNET_memcpy (&msg[1],
		 addr,
		 addr_len);
  GNUNET_MQ_send (ch->mq,
		  env);
}


/**
 * Check if we should bother to notify this client about this
 * address change, and if so, do it.
 *
 * @param delta the entry in the list that changed
 * @param ch client to check
 * @param add #GNUNET_YES to add, #GNUNET_NO to remove
 */
static void
check_notify_client (struct LocalAddressList *delta,
		     struct ClientHandle *ch,
		     int add)
{
  size_t alen;
  struct sockaddr_in v4;
  struct sockaddr_in6 v6;

  if (0 == (ch->flags & GNUNET_NAT_RF_ADDRESSES))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Not notifying client as it does not care about addresses\n");
    return;
  }
  switch (delta->af)
  {
  case AF_INET:
    alen = sizeof (struct sockaddr_in);
    GNUNET_memcpy (&v4,
		   &delta->addr,
		   alen);

    /* Check for client notifications */
    for (unsigned int i=0;i<ch->num_caddrs;i++)
    {
      const struct sockaddr_in *c4;

      if (AF_INET != ch->caddrs[i].ss.ss_family)
	continue; /* IPv4 not relevant */
      c4 = (const struct sockaddr_in *) &ch->caddrs[i].ss;
      if ( match_ipv4 ("127.0.0.1", &c4->sin_addr, 8) &&
	   (0 != c4->sin_addr.s_addr) &&
	   (! match_ipv4 ("127.0.0.1", &v4.sin_addr, 8)) )
	continue; /* bound to loopback, but this is not loopback */
      if ( (! match_ipv4 ("127.0.0.1", &c4->sin_addr, 8) ) &&
	   match_ipv4 ("127.0.0.1", &v4.sin_addr, 8) )
	continue; /* bound to non-loopback, but this is loopback */
      if ( (0 != (delta->ac & GNUNET_NAT_AC_EXTERN)) &&
           (0 != c4->sin_addr.s_addr) &&
           (! is_nat_v4 (&v4.sin_addr)) )
       continue; /* based on external-IP, but this IP is not
                    from private address range. */
      if ( (0 != GNUNET_memcmp (&v4.sin_addr,
                         &c4->sin_addr)) &&
           (0 != c4->sin_addr.s_addr) &&
           (! is_nat_v4 (&c4->sin_addr)) )
	continue; /* this IP is not from private address range,
		     and IP does not match. */

      /* OK, IP seems relevant, notify client */
      if (0 == htons (v4.sin_port))
        v4.sin_port = c4->sin_port;
      notify_client (delta->ac,
		     ch,
		     add,
		     &v4,
		     alen);
    }
    break;
  case AF_INET6:
    alen = sizeof (struct sockaddr_in6);
    GNUNET_memcpy (&v6,
		   &delta->addr,
		   alen);
    for (unsigned int i=0;i<ch->num_caddrs;i++)
    {
      const struct sockaddr_in6 *c6;

      if (AF_INET6 != ch->caddrs[i].ss.ss_family)
	continue; /* IPv4 not relevant */
      c6 = (const struct sockaddr_in6 *) &ch->caddrs[i].ss;
      if ( match_ipv6 ("::1", &c6->sin6_addr, 128) &&
	   (0 != GNUNET_memcmp (&c6->sin6_addr,
			 &in6addr_any)) &&
	   (! match_ipv6 ("::1", &v6.sin6_addr, 128)) )
	continue; /* bound to loopback, but this is not loopback */
      if ( (! match_ipv6 ("::1", &c6->sin6_addr, 128) ) &&
	   match_ipv6 ("::1", &v6.sin6_addr, 128) )
	continue; /* bound to non-loopback, but this is loopback */
      if ( (0 != (delta->ac & GNUNET_NAT_AC_EXTERN)) &&
           (0 != GNUNET_memcmp (&c6->sin6_addr,
			 &in6addr_any)) &&
	   (! is_nat_v6 (&v6.sin6_addr)) )
	continue; /* based on external-IP, but this IP is not
		     from private address range. */
      if ( (0 != GNUNET_memcmp (&v6.sin6_addr,
			 &c6->sin6_addr)) &&
	   (0 != GNUNET_memcmp (&c6->sin6_addr,
			 &in6addr_any)) &&
	   (! is_nat_v6 (&c6->sin6_addr)) )
	continue; /* this IP is not from private address range,
		     and IP does not match. */
      if ( (match_ipv6 ("fe80::", &c6->sin6_addr, 10)) &&
	   (0 != GNUNET_memcmp (&c6->sin6_addr,
			 &in6addr_any)) &&
	   (0 != GNUNET_memcmp (&v6.sin6_addr,
			 &c6->sin6_addr)) &&
	   (0 == (delta->ac & GNUNET_NAT_AC_EXTERN)) )
	continue; /* client bound to link-local, and the other address
		     does not match and is not an external IP */

      /* OK, IP seems relevant, notify client */
      if (0 == htons (v6.sin6_port))
        v6.sin6_port = c6->sin6_port;
      notify_client (delta->ac,
		     ch,
		     add,
		     &v6,
		     alen);
    }
    break;
  default:
    GNUNET_break (0);
    return;
  }
}


/**
 * Notify all clients about a change in the list
 * of addresses this peer has.
 *
 * @param delta the entry in the list that changed
 * @param add #GNUNET_YES to add, #GNUNET_NO to remove
 */
static void
notify_clients (struct LocalAddressList *delta,
		int add)
{
  for (struct ClientHandle *ch = ch_head;
       NULL != ch;
       ch = ch->next)
    check_notify_client (delta,
			 ch,
			 add);
}


/**
 * Tell relevant client about a change in our external
 * IPv4 address.
 *
 * @param cls client to check if it cares and possibly notify
 * @param v4 the external address that changed
 * @param add #GNUNET_YES to add, #GNUNET_NO to remove
 */
static void
notify_client_external_ipv4_change (void *cls,
				    const struct in_addr *v4,
				    int add)
{
  struct ClientHandle *ch = cls;
  struct sockaddr_in sa;
  int have_v4;

  /* (0) check if this impacts 'hole_external' */
  if ( (NULL != ch->hole_external) &&
       (0 == strcasecmp (ch->hole_external,
			 "AUTO")) )
  {
    struct LocalAddressList lal;
    struct sockaddr_in *s4;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Detected eternal IP, can now back-fill AUTO:%u in hole punching specification of `%s'\n",
                (unsigned int) ch->ext_dns_port,
                ch->section_name);
    memset (&lal, 0, sizeof (lal));
    s4 = (struct sockaddr_in *) &lal.addr;
    s4->sin_family = AF_INET;
    s4->sin_port = htons (ch->ext_dns_port);
    s4->sin_addr = *v4;
    lal.af = AF_INET;
    lal.ac = GNUNET_NAT_AC_GLOBAL | GNUNET_NAT_AC_MANUAL;
    check_notify_client (&lal,
			 ch,
			 add);
  }

  /* (1) check if client cares. */
  if (! ch->natted_address)
    return;
  have_v4 = GNUNET_NO;
  for (unsigned int i=0;i<ch->num_caddrs;i++)
  {
    const struct sockaddr_storage *ss = &ch->caddrs[i].ss;

    if (AF_INET != ss->ss_family)
      continue;
    have_v4 = GNUNET_YES;
    break;
  }
  if (GNUNET_NO == have_v4)
    return; /* IPv6-only */

  /* (2) build address info */
  memset (&sa,
	  0,
	  sizeof (sa));
  sa.sin_family = AF_INET;
  sa.sin_addr = *v4;
  sa.sin_port = htons (0);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Detected eternal IP %s, notifying client of external IP (without port)\n",
              GNUNET_a2s ((const struct sockaddr *) &sa,
                          sizeof (sa)));
  /* (3) notify client of change */
  notify_client (is_nat_v4 (v4)
		 ? GNUNET_NAT_AC_EXTERN | GNUNET_NAT_AC_LAN
		 : GNUNET_NAT_AC_EXTERN | GNUNET_NAT_AC_GLOBAL,
		 ch,
		 add,
		 &sa,
		 sizeof (sa));
}


/**
 * We got a connection reversal request from another peer.
 * Notify applicable clients.
 *
 * @param cls closure with the `struct LocalAddressList`
 * @param ra IP address of the peer who wants us to connect to it
 */
static void
reversal_callback (void *cls,
		   const struct sockaddr_in *ra)
{
  struct LocalAddressList *lal = cls;
  const struct sockaddr_in *l4;

  GNUNET_assert (AF_INET == lal->af);
  l4 = (const struct sockaddr_in *) &lal->addr;
  for (struct ClientHandle *ch = ch_head;
       NULL != ch;
       ch = ch->next)
  {
    struct GNUNET_NAT_ConnectionReversalRequestedMessage *crrm;
    struct GNUNET_MQ_Envelope *env;
    int match;

    /* Check if client is in applicable range for ICMP NAT traversal
       for this local address */
    if (! ch->natted_address)
      continue;
    match = GNUNET_NO;
    for (unsigned int i=0;i<ch->num_caddrs;i++)
    {
      struct ClientAddress *ca = &ch->caddrs[i];
      const struct sockaddr_in *c4;

      if (AF_INET != ca->ss.ss_family)
	continue;
      c4 = (const struct sockaddr_in *) &ca->ss;
      if ( (0 != c4->sin_addr.s_addr) &&
	   (l4->sin_addr.s_addr != c4->sin_addr.s_addr) )
	continue;
      match = GNUNET_YES;
      break;
    }
    if (! match)
      continue;

    /* Notify applicable client about connection reversal request */
    env = GNUNET_MQ_msg_extra (crrm,
			       sizeof (struct sockaddr_in),
			       GNUNET_MESSAGE_TYPE_NAT_CONNECTION_REVERSAL_REQUESTED);
    GNUNET_memcpy (&crrm[1],
		   ra,
		   sizeof (struct sockaddr_in));
    GNUNET_MQ_send (ch->mq,
		    env);
  }
}


/**
 * Task we run periodically to scan for network interfaces.
 *
 * @param cls NULL
 */
static void
run_scan (void *cls)
{
  struct IfcProcContext ifc_ctx;
  int found;
  int have_nat;
  struct LocalAddressList *lnext;

  scan_task = GNUNET_SCHEDULER_add_delayed (SCAN_FREQ,
					    &run_scan,
					    NULL);
  memset (&ifc_ctx,
	  0,
	  sizeof (ifc_ctx));
  GNUNET_OS_network_interfaces_list (&ifc_proc,
				     &ifc_ctx);
  /* remove addresses that disappeared */
  for (struct LocalAddressList *lal = lal_head;
       NULL != lal;
       lal = lnext)
  {
    lnext = lal->next;
    found = GNUNET_NO;
    for (struct LocalAddressList *pos = ifc_ctx.lal_head;
	 NULL != pos;
	 pos = pos->next)
    {
      if ( (pos->af == lal->af) &&
	   (0 == memcmp (&lal->addr,
			 &pos->addr,
			 (AF_INET == lal->af)
			 ? sizeof (struct sockaddr_in)
			 : sizeof (struct sockaddr_in6))) )
      {
	found = GNUNET_YES;
      }
    }
    if (GNUNET_NO == found)
    {
      notify_clients (lal,
		      GNUNET_NO);
      free_lal (lal);
    }
  }

  /* add addresses that appeared */
  have_nat = GNUNET_NO;
  for (struct LocalAddressList *pos = ifc_ctx.lal_head;
       NULL != pos;
       pos = ifc_ctx.lal_head)
  {
    found = GNUNET_NO;
    if (GNUNET_NAT_AC_LAN == (GNUNET_NAT_AC_LAN & pos->ac))
      have_nat = GNUNET_YES;
    for (struct LocalAddressList *lal = lal_head;
	 NULL != lal;
	 lal = lal->next)
    {
      if ( (pos->af == lal->af) &&
	   (0 == memcmp (&lal->addr,
			 &pos->addr,
			 (AF_INET == lal->af)
			 ? sizeof (struct sockaddr_in)
			 : sizeof (struct sockaddr_in6))) )
	found = GNUNET_YES;
    }
    GNUNET_CONTAINER_DLL_remove (ifc_ctx.lal_head,
				 ifc_ctx.lal_tail,
				 pos);
    if (GNUNET_YES == found)
    {
      GNUNET_free (pos);
    }
    else
    {
      notify_clients (pos,
		      GNUNET_YES);
      GNUNET_CONTAINER_DLL_insert (lal_head,
				   lal_tail,
				   pos);
      if ( (AF_INET == pos->af) &&
	   (NULL == pos->hc) &&
	   (0 != (GNUNET_NAT_AC_LAN & pos->ac)) )
      {
	const struct sockaddr_in *s4
	  = (const struct sockaddr_in *) &pos->addr;

	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		    "Found NATed local address %s, starting NAT server\n",
		    GNUNET_a2s ((const struct sockaddr *) &pos->addr,
                                sizeof (*s4)));
	pos->hc = GN_start_gnunet_nat_server_ (&s4->sin_addr,
					       &reversal_callback,
					       pos,
					       cfg);
      }
    }
  }
  GN_nat_status_changed (have_nat);
}


/**
 * Function called whenever our set of external addresses
 * as created by `upnpc` changes.
 *
 * @param cls closure with our `struct ClientHandle *`
 * @param add_remove #GNUNET_YES to mean the new public IP address, #GNUNET_NO to mean
 *     the previous (now invalid) one, #GNUNET_SYSERR indicates an error
 * @param addr either the previous or the new public IP address
 * @param addrlen actual length of the @a addr
 * @param result #GNUNET_NAT_ERROR_SUCCESS on success, otherwise the specific error code
 */
static void
upnp_addr_change_cb (void *cls,
		     int add_remove,
		     const struct sockaddr *addr,
		     socklen_t addrlen,
		     enum GNUNET_NAT_StatusCode result)
{
  struct ClientHandle *ch = cls;
  enum GNUNET_NAT_AddressClass ac;

  switch (result)
  {
  case GNUNET_NAT_ERROR_SUCCESS:
    GNUNET_assert (NULL != addr);
    break;
  case GNUNET_NAT_ERROR_UPNPC_FAILED:
  case GNUNET_NAT_ERROR_UPNPC_TIMEOUT:
  case GNUNET_NAT_ERROR_IPC_FAILURE:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Running upnpc failed: %d\n",
		result);
    return;
  case GNUNET_NAT_ERROR_EXTERNAL_IP_UTILITY_NOT_FOUND:
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		"external-ip binary not found\n");
    return;
  case GNUNET_NAT_ERROR_UPNPC_NOT_FOUND:
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		"upnpc binary not found\n");
    return;
  case GNUNET_NAT_ERROR_EXTERNAL_IP_UTILITY_FAILED:
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		"external-ip binary could not be run\n");
    return;
  case GNUNET_NAT_ERROR_UPNPC_PORTMAP_FAILED:
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		"upnpc failed to create port mapping\n");
    return;
  case GNUNET_NAT_ERROR_EXTERNAL_IP_UTILITY_OUTPUT_INVALID:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Invalid output from upnpc\n");
    return;
  case GNUNET_NAT_ERROR_EXTERNAL_IP_ADDRESS_INVALID:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Invalid address returned by upnpc\n");
    return;
  default:
    GNUNET_break (0); /* should not be possible */
    return;
  }
  switch (addr->sa_family)
  {
  case AF_INET:
    ac = is_nat_v4 (&((const struct sockaddr_in *) addr)->sin_addr)
      ? GNUNET_NAT_AC_LAN
      : GNUNET_NAT_AC_EXTERN;
    break;
  case AF_INET6:
    ac = is_nat_v6 (&((const struct sockaddr_in6 *) addr)->sin6_addr)
      ? GNUNET_NAT_AC_LAN
      : GNUNET_NAT_AC_EXTERN;
    break;
  default:
    GNUNET_break (0);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "upnp external address %s: %s\n",
	      add_remove ? "added" : "removed",
	      GNUNET_a2s (addr,
			  addrlen));
  notify_client (ac,
		 ch,
		 add_remove,
		 addr,
		 addrlen);
}


/**
 * Resolve the `hole_external` name to figure out our
 * external address from a manually punched hole.  The
 * port number has already been parsed, this task is
 * responsible for periodically doing a DNS lookup.
 *
 * @param ch client handle to act upon
 */
static void
dyndns_lookup (void *cls);


/**
 * Our (external) hostname was resolved.  Update lists of
 * current external IPs (note that DNS may return multiple
 * addresses!) and notify client accordingly.
 *
 * @param cls the `struct ClientHandle`
 * @param addr NULL on error, otherwise result of DNS lookup
 * @param addrlen number of bytes in @a addr
 */
static void
process_external_ip (void *cls,
                     const struct sockaddr *addr,
                     socklen_t addrlen)
{
  struct ClientHandle *ch = cls;
  struct LocalAddressList *lal;
  struct sockaddr_storage ss;
  struct sockaddr_in *v4;
  struct sockaddr_in6 *v6;

  if (NULL == addr)
  {
    struct LocalAddressList *laln;

    ch->ext_dns = NULL;
    ch->ext_dns_task
      = GNUNET_SCHEDULER_add_delayed (dyndns_frequency,
				      &dyndns_lookup,
				      ch);
    /* Current iteration is over, remove 'old' IPs now */
    for (lal = ch->ext_addr_head; NULL != lal; lal = laln)
    {
      laln = lal->next;
      if (GNUNET_YES == lal->old)
      {
	GNUNET_CONTAINER_DLL_remove (ch->ext_addr_head,
				     ch->ext_addr_tail,
				     lal);
	check_notify_client (lal,
			     ch,
			     GNUNET_NO);
	GNUNET_free (lal);
      }
    }
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Got IP `%s' for external address `%s'\n",
	      GNUNET_a2s (addr,
			  addrlen),
	      ch->hole_external);

  /* build sockaddr storage with port number */
  memset (&ss,
          0,
          sizeof (ss));
  GNUNET_memcpy (&ss,
                 addr,
                 addrlen);
  switch (addr->sa_family)
  {
  case AF_INET:
    v4 = (struct sockaddr_in *) &ss;
    v4->sin_port = htons (ch->ext_dns_port);
    break;
  case AF_INET6:
    v6 = (struct sockaddr_in6 *) &ss;
    v6->sin6_port = htons (ch->ext_dns_port);
    break;
  default:
    GNUNET_break (0);
    return;
  }
  /* See if 'ss' matches any of our known addresses */
  for (lal = ch->ext_addr_head; NULL != lal; lal = lal->next)
  {
    if (GNUNET_NO == lal->old)
      continue; /* already processed, skip */
    if ( (addr->sa_family == lal->addr.ss_family) &&
	 (0 == memcmp (&ss,
		       &lal->addr,
		       addrlen)) )
    {
      /* Address unchanged, remember so we do not remove */
      lal->old = GNUNET_NO;
      return; /* done here */
    }
  }
  /* notify client, and remember IP for later removal! */
  lal = GNUNET_new (struct LocalAddressList);
  lal->addr = ss;
  lal->af = ss.ss_family;
  lal->ac = GNUNET_NAT_AC_GLOBAL | GNUNET_NAT_AC_MANUAL;
  GNUNET_CONTAINER_DLL_insert (ch->ext_addr_head,
			       ch->ext_addr_tail,
			       lal);
  check_notify_client (lal,
		       ch,
		       GNUNET_YES);
}


/**
 * Resolve the `hole_external` name to figure out our
 * external address from a manually punched hole.  The
 * port number has already been parsed, this task is
 * responsible for periodically doing a DNS lookup.
 *
 * @param ch client handle to act upon
 */
static void
dyndns_lookup (void *cls)
{
  struct ClientHandle *ch = cls;
  struct LocalAddressList *lal;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Performing DNS lookup for punched hole given for `%s' as `%s:%u'\n",
              ch->section_name,
              ch->hole_external,
              (unsigned int) ch->ext_dns_port);
  for (lal = ch->ext_addr_head; NULL != lal; lal = lal->next)
    lal->old = GNUNET_YES;
  ch->ext_dns_task = NULL;
  ch->ext_dns = GNUNET_RESOLVER_ip_get (ch->hole_external,
					AF_UNSPEC,
					GNUNET_TIME_UNIT_MINUTES,
					&process_external_ip,
					ch);
}


/**
 * Resolve the `hole_external` name to figure out our
 * external address from a manually punched hole.  The
 * given name may be "AUTO" in which case we should use
 * the IP address(es) we have from upnpc or other methods.
 * The name can also be an IP address, in which case we
 * do not need to do DNS resolution.  Finally, we also
 * need to parse the port number.
 *
 * @param ch client handle to act upon
 */
static void
lookup_hole_external (struct ClientHandle *ch)
{
  char *port;
  unsigned int pnum;
  struct sockaddr_in *s4;
  struct LocalAddressList *lal;

  port = strrchr (ch->hole_external, ':');
  if (NULL == port)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Malformed punched hole specification `%s' (lacks port)\n"),
		ch->hole_external);
    return;
  }
  if ( (1 != sscanf (port + 1,
		     "%u",
		     &pnum)) ||
       (pnum > 65535) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Invalid port number in punched hole specification `%s' (lacks port)\n"),
		port + 1);
    return;
  }
  ch->ext_dns_port = (uint16_t) pnum;
  *port = '\0';

  lal = GNUNET_new (struct LocalAddressList);
  if ('[' == *ch->hole_external)
  {
    struct sockaddr_in6 *s6 = (struct sockaddr_in6 *) &lal->addr;

    s6->sin6_family = AF_INET6;
    if (']' != (ch->hole_external[strlen(ch->hole_external)-1]))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Malformed punched hole specification `%s' (lacks `]')\n"),
		  ch->hole_external);
      GNUNET_free (lal);
      return;
    }
    ch->hole_external[strlen(ch->hole_external)-1] = '\0';
    if (1 != inet_pton (AF_INET6,
			ch->hole_external + 1,
			&s6->sin6_addr))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Malformed punched hole specification `%s' (IPv6 address invalid)"),
		  ch->hole_external + 1);
      GNUNET_free (lal);
      return;
    }
    s6->sin6_port = htons (ch->ext_dns_port);
    lal->af = AF_INET6;
    lal->ac = GNUNET_NAT_AC_GLOBAL | GNUNET_NAT_AC_MANUAL;
    GNUNET_CONTAINER_DLL_insert (ch->ext_addr_head,
				 ch->ext_addr_tail,
				 lal);
    check_notify_client (lal,
			 ch,
			 GNUNET_YES);
    return;
  }

  s4 = (struct sockaddr_in *) &lal->addr;
  s4->sin_family = AF_INET;
  if (1 == inet_pton (AF_INET,
		      ch->hole_external,
		      &s4->sin_addr))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "IPv4 punched hole given for `%s' via `%s:%u'\n",
                ch->section_name,
                ch->hole_external,
                (unsigned int) ch->ext_dns_port);
    s4->sin_port = htons (ch->ext_dns_port);
    lal->af = AF_INET;
    lal->ac = GNUNET_NAT_AC_GLOBAL | GNUNET_NAT_AC_MANUAL;
    GNUNET_CONTAINER_DLL_insert (ch->ext_addr_head,
				 ch->ext_addr_tail,
				 lal);
    check_notify_client (lal,
			 ch,
			 GNUNET_YES);
    return;
  }
  if (0 == strcasecmp (ch->hole_external,
		       "AUTO"))
  {
    /* handled in #notify_client_external_ipv4_change() */
    GNUNET_free (lal);
    return;
  }
  /* got a DNS name, trigger lookup! */
  GNUNET_free (lal);
  ch->ext_dns_task
    = GNUNET_SCHEDULER_add_now (&dyndns_lookup,
				ch);
}


/**
 * Handler for #GNUNET_MESSAGE_TYPE_NAT_REGISTER message from client.
 * We remember the client for updates upon future NAT events.
 *
 * @param cls client who sent the message
 * @param message the message received
 */
static void
handle_register (void *cls,
		 const struct GNUNET_NAT_RegisterMessage *message)
{
  struct ClientHandle *ch = cls;
  const char *off;
  size_t left;

  if ( (0 != ch->proto) ||
       (NULL != ch->caddrs) )
  {
    /* double registration not allowed */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (ch->client);
    return;
  }
  ch->flags = message->flags;
  ch->proto = message->proto;
  ch->num_caddrs = ntohs (message->num_addrs);
  ch->caddrs = GNUNET_new_array (ch->num_caddrs,
				 struct ClientAddress);
  left = ntohs (message->header.size) - sizeof (*message);
  off = (const char *) &message[1];
  for (unsigned int i=0;i<ch->num_caddrs;i++)
  {
    const struct sockaddr *sa = (const struct sockaddr *) off;
    size_t alen;
    uint16_t port;
    int is_nat;

    if (sizeof (sa_family_t) > left)
    {
      GNUNET_break (0);
      GNUNET_SERVICE_client_drop (ch->client);
      return;
    }
    is_nat = GNUNET_NO;
    switch (sa->sa_family)
    {
    case AF_INET:
      {
        struct sockaddr_in s4;

        GNUNET_memcpy (&s4,
                       off,
                       sizeof (struct sockaddr_in));
	alen = sizeof (struct sockaddr_in);
	if (is_nat_v4 (&s4.sin_addr))
	  is_nat = GNUNET_YES;
	port = ntohs (s4.sin_port);
      }
      break;
    case AF_INET6:
      {
        struct sockaddr_in6 s6;

        GNUNET_memcpy (&s6,
                       off,
                       sizeof (struct sockaddr_in6));
	alen = sizeof (struct sockaddr_in6);
	if (is_nat_v6 (&s6.sin6_addr))
	  is_nat = GNUNET_YES;
	port = ntohs (s6.sin6_port);
      }
      break;
#if AF_UNIX
    case AF_UNIX:
      alen = sizeof (struct sockaddr_un);
      port = 0;
      break;
#endif
    default:
      GNUNET_break (0);
      GNUNET_SERVICE_client_drop (ch->client);
      return;
    }
    /* store address */
    GNUNET_assert (alen <= left);
    GNUNET_assert (alen <= sizeof (struct sockaddr_storage));
    GNUNET_memcpy (&ch->caddrs[i].ss,
		   off,
		   alen);

    /* If applicable, try UPNPC NAT punching */
    if ( (is_nat) &&
	 (enable_upnp) &&
	 ( (IPPROTO_TCP == ch->proto) ||
	   (IPPROTO_UDP == ch->proto) ) )
    {
      ch->natted_address = GNUNET_YES;
      ch->caddrs[i].mh
	= GNUNET_NAT_mini_map_start (port,
				     IPPROTO_TCP == ch->proto,
				     &upnp_addr_change_cb,
				     ch);
    }

    off += alen;
  }

  ch->section_name
    = GNUNET_strndup (off,
		      ntohs (message->str_len));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received REGISTER message from client for subsystem `%s'\n",
              ch->section_name);
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_string (cfg,
					     ch->section_name,
					     "HOLE_EXTERNAL",
					     &ch->hole_external))
    lookup_hole_external (ch);

  /* Actually send IP address list to client */
  for (struct LocalAddressList *lal = lal_head;
       NULL != lal;
       lal = lal->next)
  {
    check_notify_client (lal,
			 ch,
			 GNUNET_YES);
  }
  /* Also consider IPv4 determined by `external-ip` */
  ch->external_monitor
    = GN_external_ipv4_monitor_start (&notify_client_external_ipv4_change,
				      ch);
  GNUNET_SERVICE_client_continue (ch->client);
}


/**
 * Check validity of #GNUNET_MESSAGE_TYPE_NAT_HANDLE_STUN message from
 * client.
 *
 * @param cls client who sent the message
 * @param message the message received
 * @return #GNUNET_OK if message is well-formed
 */
static int
check_stun (void *cls,
	    const struct GNUNET_NAT_HandleStunMessage *message)
{
  size_t sa_len = ntohs (message->sender_addr_size);
  size_t expect = sa_len + ntohs (message->payload_size);

  if (ntohs (message->header.size) - sizeof (*message) != expect)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (sa_len < sizeof (sa_family_t))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Notify all clients about our external IP address
 * as reported by the STUN server.
 *
 * @param ip the external IP
 * @param add #GNUNET_YES to add, #GNUNET_NO to remove
 */
static void
notify_clients_stun_change (const struct sockaddr_in *ip,
			    int add)
{
  for (struct ClientHandle *ch = ch_head;
       NULL != ch;
       ch = ch->next)
  {
    struct sockaddr_in v4;
    struct GNUNET_NAT_AddressChangeNotificationMessage *msg;
    struct GNUNET_MQ_Envelope *env;

    if (! ch->natted_address)
      continue;
    v4 = *ip;
    v4.sin_port = htons (0);
    env = GNUNET_MQ_msg_extra (msg,
			       sizeof (v4),
			       GNUNET_MESSAGE_TYPE_NAT_ADDRESS_CHANGE);
    msg->add_remove = htonl ((int32_t) add);
    msg->addr_class = htonl (GNUNET_NAT_AC_EXTERN |
			     GNUNET_NAT_AC_GLOBAL);
    GNUNET_memcpy (&msg[1],
		   &v4,
		   sizeof (v4));
    GNUNET_MQ_send (ch->mq,
		    env);
  }
}


/**
 * Function to be called when we decide that an
 * external IP address as told to us by a STUN
 * server has gone stale.
 *
 * @param cls the `struct StunExternalIP` to drop
 */
static void
stun_ip_timeout (void *cls)
{
  struct StunExternalIP *se = cls;

  se->timeout_task = NULL;
  notify_clients_stun_change (&se->external_addr,
			      GNUNET_NO);
  GNUNET_CONTAINER_DLL_remove (se_head,
			       se_tail,
			       se);
  GNUNET_free (se);
}


/**
 * Handler for #GNUNET_MESSAGE_TYPE_NAT_HANDLE_STUN message from
 * client.
 *
 * @param cls client who sent the message
 * @param message the message received
 */
static void
handle_stun (void *cls,
	     const struct GNUNET_NAT_HandleStunMessage *message)
{
  struct ClientHandle *ch = cls;
  const char *buf = (const char *) &message[1];
  const struct sockaddr *sa;
  const void *payload;
  size_t sa_len;
  size_t payload_size;
  struct sockaddr_in external_addr;

  sa_len = ntohs (message->sender_addr_size);
  payload_size = ntohs (message->payload_size);
  sa = (const struct sockaddr *) &buf[0];
  payload = (const struct sockaddr *) &buf[sa_len];
  switch (sa->sa_family)
  {
  case AF_INET:
    if (sa_len != sizeof (struct sockaddr_in))
    {
      GNUNET_break (0);
      GNUNET_SERVICE_client_drop (ch->client);
      return;
    }
    break;
  case AF_INET6:
    if (sa_len != sizeof (struct sockaddr_in6))
    {
      GNUNET_break (0);
      GNUNET_SERVICE_client_drop (ch->client);
      return;
    }
    break;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received HANDLE_STUN message from client\n");
  if (GNUNET_OK ==
      GNUNET_NAT_stun_handle_packet_ (payload,
				      payload_size,
				      &external_addr))
  {
    /* We now know that a server at "sa" claims that
       we are visible at IP "external_addr".

       We should (for some fixed period of time) tell
       all of our clients that listen to a NAT'ed address
       that they might want to consider the given 'external_ip'
       as their public IP address (this includes TCP and UDP
       clients, even if only UDP sends STUN requests).

       If we do not get a renewal, the "external_addr" should be
       removed again.  The timeout frequency should be configurable
       (with a sane default), so that the UDP plugin can tell how
       often to re-request STUN.
    */
    struct StunExternalIP *se;

    /* Check if we had a prior response from this STUN server */
    for (se = se_head; NULL != se; se = se->next)
    {
      if ( (se->stun_server_addr_len != sa_len) ||
	   (0 != memcmp (sa,
			 &se->stun_server_addr,
			 sa_len)) )
	continue; /* different STUN server */
      if (0 != GNUNET_memcmp (&external_addr,
		       &se->external_addr))
      {
	/* external IP changed, update! */
	notify_clients_stun_change (&se->external_addr,
				    GNUNET_NO);
	se->external_addr = external_addr;
	notify_clients_stun_change (&se->external_addr,
				    GNUNET_YES);
      }
      /* update timeout */
      GNUNET_SCHEDULER_cancel (se->timeout_task);
      se->timeout_task
	= GNUNET_SCHEDULER_add_delayed (stun_stale_timeout,
					&stun_ip_timeout,
					se);
      return;
    }
    /* STUN server is completely new, create fresh entry */
    se = GNUNET_new (struct StunExternalIP);
    se->external_addr = external_addr;
    GNUNET_memcpy (&se->stun_server_addr,
		   sa,
		   sa_len);
    se->stun_server_addr_len = sa_len;
    se->timeout_task = GNUNET_SCHEDULER_add_delayed (stun_stale_timeout,
						     &stun_ip_timeout,
						     se);
    GNUNET_CONTAINER_DLL_insert (se_head,
				 se_tail,
				 se);
    notify_clients_stun_change (&se->external_addr,
				GNUNET_NO);
  }
  GNUNET_SERVICE_client_continue (ch->client);
}


/**
 * Check validity of
 * #GNUNET_MESSAGE_TYPE_NAT_REQUEST_CONNECTION_REVERSAL message from
 * client.
 *
 * @param cls client who sent the message
 * @param message the message received
 * @return #GNUNET_OK if message is well-formed
 */
static int
check_request_connection_reversal (void *cls,
				   const struct GNUNET_NAT_RequestConnectionReversalMessage *message)
{
  size_t expect;

  expect = ntohs (message->local_addr_size)
    + ntohs (message->remote_addr_size);
  if (ntohs (message->header.size) - sizeof (*message) != expect)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handler for #GNUNET_MESSAGE_TYPE_NAT_REQUEST_CONNECTION_REVERSAL
 * message from client.
 *
 * @param cls client who sent the message
 * @param message the message received
 */
static void
handle_request_connection_reversal (void *cls,
				    const struct GNUNET_NAT_RequestConnectionReversalMessage *message)
{
  struct ClientHandle *ch = cls;
  const char *buf = (const char *) &message[1];
  size_t local_sa_len = ntohs (message->local_addr_size);
  size_t remote_sa_len = ntohs (message->remote_addr_size);
  struct sockaddr_in l4;
  struct sockaddr_in r4;
  int ret;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received REQUEST CONNECTION REVERSAL message from client\n");
  if (local_sa_len != sizeof (struct sockaddr_in))
  {
    GNUNET_break_op (0);
    GNUNET_SERVICE_client_drop (ch->client);
    return;
  }
  if (remote_sa_len != sizeof (struct sockaddr_in))
  {
    GNUNET_break_op (0);
    GNUNET_SERVICE_client_drop (ch->client);
    return;
  }
  GNUNET_memcpy (&l4,
		 buf,
		 sizeof (struct sockaddr_in));
  GNUNET_break_op (AF_INET == l4.sin_family);
  buf += sizeof (struct sockaddr_in);
  GNUNET_memcpy (&r4,
		 buf,
		 sizeof (struct sockaddr_in));
  GNUNET_break_op (AF_INET == r4.sin_family);
  ret = GN_request_connection_reversal (&l4.sin_addr,
					ntohs (l4.sin_port),
					&r4.sin_addr,
					cfg);
  if (GNUNET_OK != ret)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Connection reversal request failed\n"));
  GNUNET_SERVICE_client_continue (ch->client);
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 */
static void
shutdown_task (void *cls)
{
  struct StunExternalIP *se;

  while (NULL != (se = se_head))
  {
    GNUNET_CONTAINER_DLL_remove (se_head,
				 se_tail,
				 se);
    GNUNET_SCHEDULER_cancel (se->timeout_task);
    GNUNET_free (se);
  }
  GN_nat_status_changed (GNUNET_NO);
  if (NULL != scan_task)
  {
    GNUNET_SCHEDULER_cancel (scan_task);
    scan_task = NULL;
  }
  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats,
			       GNUNET_NO);
    stats = NULL;
  }
  destroy_lal ();
}


/**
 * Setup NAT service.
 *
 * @param cls closure
 * @param c configuration to use
 * @param service the initialized service
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_SERVICE_Handle *service)
{
  cfg = c;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (cfg,
					   "NAT",
					   "STUN_STALE",
					   &stun_stale_timeout))
    stun_stale_timeout = GNUNET_TIME_UNIT_HOURS;

  /* Check for UPnP */
  enable_upnp
    = GNUNET_CONFIGURATION_get_value_yesno (cfg,
					    "NAT",
					    "ENABLE_UPNP");
  if (GNUNET_YES == enable_upnp)
  {
    /* check if it works */
    if (GNUNET_SYSERR ==
        GNUNET_OS_check_helper_binary ("upnpc",
				       GNUNET_NO,
				       NULL))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("UPnP enabled in configuration, but UPnP client `upnpc` command not found, disabling UPnP\n"));
      enable_upnp = GNUNET_SYSERR;
    }
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (cfg,
					   "nat",
					   "DYNDNS_FREQUENCY",
                                           &dyndns_frequency))
    dyndns_frequency = DYNDNS_FREQUENCY;

  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
				 NULL);
  stats = GNUNET_STATISTICS_create ("nat",
				    cfg);
  scan_task = GNUNET_SCHEDULER_add_now (&run_scan,
					NULL);
}


/**
 * Callback called when a client connects to the service.
 *
 * @param cls closure for the service
 * @param c the new client that connected to the service
 * @param mq the message queue used to send messages to the client
 * @return a `struct ClientHandle`
 */
static void *
client_connect_cb (void *cls,
		   struct GNUNET_SERVICE_Client *c,
		   struct GNUNET_MQ_Handle *mq)
{
  struct ClientHandle *ch;

  ch = GNUNET_new (struct ClientHandle);
  ch->mq = mq;
  ch->client = c;
  GNUNET_CONTAINER_DLL_insert (ch_head,
			       ch_tail,
			       ch);
  return ch;
}


/**
 * Callback called when a client disconnected from the service
 *
 * @param cls closure for the service
 * @param c the client that disconnected
 * @param internal_cls a `struct ClientHandle *`
 */
static void
client_disconnect_cb (void *cls,
		      struct GNUNET_SERVICE_Client *c,
		      void *internal_cls)
{
  struct ClientHandle *ch = internal_cls;
  struct LocalAddressList *lal;

  GNUNET_CONTAINER_DLL_remove (ch_head,
			       ch_tail,
			       ch);
  for (unsigned int i=0;i<ch->num_caddrs;i++)
  {
    if (NULL != ch->caddrs[i].mh)
    {
      GNUNET_NAT_mini_map_stop (ch->caddrs[i].mh);
      ch->caddrs[i].mh = NULL;
    }
  }
  GNUNET_free_non_null (ch->caddrs);
  while (NULL != (lal = ch->ext_addr_head))
  {
    GNUNET_CONTAINER_DLL_remove (ch->ext_addr_head,
				 ch->ext_addr_tail,
				 lal);
    GNUNET_free (lal);
  }
  if (NULL != ch->ext_dns_task)
  {
    GNUNET_SCHEDULER_cancel (ch->ext_dns_task);
    ch->ext_dns_task = NULL;
  }
  if (NULL != ch->external_monitor)
  {
    GN_external_ipv4_monitor_stop (ch->external_monitor);
    ch->external_monitor = NULL;
  }
  if (NULL != ch->ext_dns)
  {
    GNUNET_RESOLVER_request_cancel (ch->ext_dns);
    ch->ext_dns = NULL;
  }
  GNUNET_free_non_null (ch->hole_external);
  GNUNET_free_non_null (ch->section_name);
  GNUNET_free (ch);
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
("nat",
 GNUNET_SERVICE_OPTION_NONE,
 &run,
 &client_connect_cb,
 &client_disconnect_cb,
 NULL,
 GNUNET_MQ_hd_var_size (register,
			GNUNET_MESSAGE_TYPE_NAT_REGISTER,
			struct GNUNET_NAT_RegisterMessage,
			NULL),
 GNUNET_MQ_hd_var_size (stun,
			GNUNET_MESSAGE_TYPE_NAT_HANDLE_STUN,
			struct GNUNET_NAT_HandleStunMessage,
			NULL),
 GNUNET_MQ_hd_var_size (request_connection_reversal,
			GNUNET_MESSAGE_TYPE_NAT_REQUEST_CONNECTION_REVERSAL,
			struct GNUNET_NAT_RequestConnectionReversalMessage,
			NULL),
 GNUNET_MQ_handler_end ());


#if defined(LINUX) && defined(__GLIBC__)
#include <malloc.h>

/**
 * MINIMIZE heap size (way below 128k) since this process doesn't need much.
 */
void __attribute__ ((constructor))
GNUNET_ARM_memory_init ()
{
  mallopt (M_TRIM_THRESHOLD, 4 * 1024);
  mallopt (M_TOP_PAD, 1 * 1024);
  malloc_trim (0);
}
#endif

/* end of gnunet-service-nat.c */
