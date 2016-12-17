/*
  This file is part of GNUnet.
  Copyright (C) 2016 GNUnet e.V.

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
  Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
  Boston, MA 02110-1301, USA.
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
 * - implement UPnPC/PMP-based NAT traversal
 * - implement autoconfig
 * - implement NEW logic for external IP detection
 */
#include "platform.h"
#include <math.h>
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_signatures.h"
#include "gnunet_statistics_service.h"
#include "gnunet_nat_service.h"
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
 * How long do we wait until we re-try running `external-ip` if the
 * command failed to terminate nicely?
 */
#define EXTERN_IP_RETRY_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 15)

/**
 * How long do we wait until we re-try running `external-ip` if the
 * command failed (but terminated)?
 */
#define EXTERN_IP_RETRY_FAILURE GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 30)

/**
 * How long do we wait until we re-try running `external-ip` if the
 * command succeeded?
 */
#define EXTERN_IP_RETRY_SUCCESS GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 5)


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
  struct sockaddr **addrs;
  
  /**
   * What does this client care about?
   */
  enum GNUNET_NAT_RegisterFlags flags;

  /**
   * Is any of the @e addrs in a reserved subnet for NAT?
   */
  int natted_address;
  
  /**
   * Port we would like as we are configured to use this one for
   * advertising (in addition to the one we are binding to).
   */
  uint16_t adv_port;

  /**
   * Number of addresses that this service is bound to.
   */
  uint16_t num_addrs;
  
  /**
   * Client's IPPROTO, e.g. IPPROTO_UDP or IPPROTO_TCP.
   */
  uint8_t proto;

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
   * The address itself (i.e. `struct sockaddr_in` or `struct
   * sockaddr_in6`, in the respective byte order).
   */
  struct sockaddr_storage addr;

  /**
   * Address family.
   */
  int af;

  /**
   * What type of address is this?
   */
  enum GNUNET_NAT_AddressClass ac;
  
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
 * Context for autoconfiguration operations.
 */
struct AutoconfigContext
{
  /**
   * Kept in a DLL.
   */
  struct AutoconfigContext *prev;

  /**
   * Kept in a DLL.
   */
  struct AutoconfigContext *next;

  /**
   * Which client asked the question.
   */
  struct ClientHandle *ch;

  /**
   * Configuration we are creating.
   */ 
  struct GNUNET_CONFIGURATION_Handle *c;

  /**
   * Original configuration (for diffing).
   */ 
  struct GNUNET_CONFIGURATION_Handle *orig;

  /**
   * Timeout task to force termination.
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

  /**
   * What type of system are we on?
   */
  char *system_type;

  /**
   * Handle to activity to probe for our external IP.
   */
  struct GNUNET_NAT_ExternalHandle *probe_external;

  /**
   * #GNUNET_YES if upnpc should be used,
   * #GNUNET_NO if upnpc should not be used,
   * #GNUNET_SYSERR if we should simply not change the option.
   */
  int enable_upnpc;

  /**
   * Status code to return to the client.
   */
  enum GNUNET_NAT_StatusCode status_code;

  /**
   * NAT type to return to the client.
   */
  enum GNUNET_NAT_Type type;
};


/**
 * DLL of our autoconfiguration operations.
 */
static struct AutoconfigContext *ac_head;

/**
 * DLL of our autoconfiguration operations.
 */
static struct AutoconfigContext *ac_tail;

/**
 * Timeout to use when STUN data is considered stale.
 */
static struct GNUNET_TIME_Relative stun_stale_timeout;

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
static int enable_upnp;

/**
 * Task run to obtain our external IP (if #enable_upnp is set
 * and if we find we have a NATed IP address).
 */
static struct GNUNET_SCHEDULER_Task *probe_external_ip_task;

/**
 * Handle to our operation to run `external-ip`.
 */
static struct GNUNET_NAT_ExternalHandle *probe_external_ip_op;

/**
 * What is our external IP address as claimed by `external-ip`?
 * 0 for unknown.
 */
static struct in_addr mini_external_ipv4;

/**
 * Free the DLL starting at #lal_head.
 */ 
static void
destroy_lal ()
{
  struct LocalAddressList *lal;

  while (NULL != (lal = lal_head))
  {
    GNUNET_CONTAINER_DLL_remove (lal_head,
				 lal_tail,
				 lal);
    GNUNET_free (lal);
  }
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
  if (0 == memcmp (&mask,
		   ip,
		   sizeof (mask)))
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
    return;
  switch (delta->af)
  {
  case AF_INET:
    alen = sizeof (struct sockaddr_in);
    GNUNET_memcpy (&v4,
		   &delta->addr,
		   alen);
    for (unsigned int i=0;i<ch->num_addrs;i++)
    {
      const struct sockaddr_in *c4;
      
      if (AF_INET != ch->addrs[i]->sa_family)
	return; /* IPv4 not relevant */
      c4 = (const struct sockaddr_in *) ch->addrs[i];
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
    for (unsigned int i=0;i<ch->num_addrs;i++)
    {
      const struct sockaddr_in6 *c6;
      
      if (AF_INET6 != ch->addrs[i]->sa_family)
	return; /* IPv4 not relevant */
      c6 = (const struct sockaddr_in6 *) ch->addrs[i];
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
 * @param v4 the external address that changed
 * @param ch client to check if it cares and possibly notify
 * @param add #GNUNET_YES to add, #GNUNET_NO to remove
 */
static void
check_notify_client_external_ipv4_change (const struct in_addr *v4,
					  struct ClientHandle *ch,
					  int add)
{
  struct sockaddr_in sa;

  // FIXME: (1) check if client cares;
  GNUNET_break (0); // FIXME: implement!
  
  /* (2) figure out external port, build sockaddr */
  memset (&sa,
	  0,
	  sizeof (sa));
  sa.sin_family = AF_INET;
  sa.sin_addr = *v4;
  sa.sin_port = 42; // FIXME
  
  /* (3) notify client of change */

  // FIXME: handle case where 'v4' is still in the NAT range
  // (in case of double-NAT!)
  notify_client (GNUNET_NAT_AC_GLOBAL_EXTERN,
		 ch,
		 add,
		 &sa,
		 sizeof (sa));
}


/**
 * Tell relevant clients about a change in our external
 * IPv4 address.
 * 
 * @param add #GNUNET_YES to add, #GNUNET_NO to remove
 * @param v4 the external address that changed
 */
static void
notify_clients_external_ipv4_change (int add,
				     const struct in_addr *v4)
{
  for (struct ClientHandle *ch = ch_head;
       NULL != ch;
       ch = ch->next)
    check_notify_client_external_ipv4_change (v4,
					      ch,
					      add);
}


/**
 * Task used to run `external-ip` to get our external IPv4
 * address and pass it to NATed clients if possible.
 *
 * @param cls NULL
 */
static void
run_external_ip (void *cls);


/**
 * We learn our current external IP address.  If it changed,
 * notify all of our applicable clients. Also re-schedule
 * #run_external_ip with an appropriate timeout.
 * 
 * @param cls NULL
 * @param addr the address, NULL on errors
 * @param result #GNUNET_NAT_ERROR_SUCCESS on success, otherwise the specific error code
 */
static void
handle_external_ip (void *cls,
		    const struct in_addr *addr,
		    enum GNUNET_NAT_StatusCode result)
{
  probe_external_ip_op = NULL;
  GNUNET_SCHEDULER_cancel (probe_external_ip_task);
  probe_external_ip_task
    = GNUNET_SCHEDULER_add_delayed ((NULL == addr)
				    ? EXTERN_IP_RETRY_FAILURE
				    : EXTERN_IP_RETRY_SUCCESS,
				    &run_external_ip,
				    NULL);
  switch (result)
  {
  case GNUNET_NAT_ERROR_SUCCESS:
    if (addr->s_addr == mini_external_ipv4.s_addr)
      return; /* not change */
    if (0 != mini_external_ipv4.s_addr)
      notify_clients_external_ipv4_change (GNUNET_NO,
					   &mini_external_ipv4);
    mini_external_ipv4 = *addr;
    notify_clients_external_ipv4_change (GNUNET_YES,
					 &mini_external_ipv4);
    break;
  default:
    if (0 != mini_external_ipv4.s_addr)
      notify_clients_external_ipv4_change (GNUNET_NO,
					   &mini_external_ipv4);
    mini_external_ipv4.s_addr = 0; 
    break;
  }
}


/**
 * Task used to run `external-ip` to get our external IPv4
 * address and pass it to NATed clients if possible.
 *
 * @param cls NULL
 */
static void
run_external_ip (void *cls)
{
  probe_external_ip_task
    = GNUNET_SCHEDULER_add_delayed (EXTERN_IP_RETRY_TIMEOUT,
				    &run_external_ip,
				    NULL);
  if (NULL != probe_external_ip_op)
  {
    GNUNET_NAT_mini_get_external_ipv4_cancel_ (probe_external_ip_op);
    probe_external_ip_op = NULL;
  }
  probe_external_ip_op
    = GNUNET_NAT_mini_get_external_ipv4_ (&handle_external_ip,
					  NULL);
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
       lal = lal->next)
  {
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
	found = GNUNET_YES;
    }
    if (GNUNET_NO == found)
      notify_clients (lal,
		      GNUNET_NO);
  }

  /* add addresses that appeared */
  have_nat = GNUNET_NO;
  for (struct LocalAddressList *pos = ifc_ctx.lal_head;
       NULL != pos;
       pos = pos->next)
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
    if (GNUNET_NO == found)
      notify_clients (pos,
		      GNUNET_YES);
  }
  if ( (GNUNET_YES == have_nat) &&
       (GNUNET_YES == enable_upnp) &&
       (NULL == probe_external_ip_task) &&
       (NULL == probe_external_ip_op) )
  {
    probe_external_ip_task
      = GNUNET_SCHEDULER_add_now (&run_external_ip,
				  NULL);
  }
  if ( (GNUNET_NO == have_nat) &&
       (GNUNET_YES == enable_upnp) )
  {
    if (NULL != probe_external_ip_task)
    {
      GNUNET_SCHEDULER_cancel (probe_external_ip_task);
      probe_external_ip_task = NULL;
    }
    if (NULL != probe_external_ip_op)
    {
      GNUNET_NAT_mini_get_external_ipv4_cancel_ (probe_external_ip_op);
      probe_external_ip_op = NULL;
    }
  }
  
  destroy_lal ();
  lal_head = ifc_ctx.lal_head;
  lal_tail = ifc_ctx.lal_tail;
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
       (NULL != ch->addrs) )
  {
    /* double registration not allowed */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (ch->client);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received REGISTER message from client\n");
  ch->flags = message->flags;
  ch->proto = message->proto;
  ch->adv_port = ntohs (message->adv_port);
  ch->num_addrs = ntohs (message->num_addrs);
  ch->addrs = GNUNET_new_array (ch->num_addrs,
				struct sockaddr *);
  left = ntohs (message->header.size) - sizeof (*message);
  off = (const char *) &message[1];
  for (unsigned int i=0;i<ch->num_addrs;i++)
  {
    size_t alen;
    const struct sockaddr *sa = (const struct sockaddr *) off;

    if (sizeof (sa_family_t) > left)
    {
      GNUNET_break (0);
      GNUNET_SERVICE_client_drop (ch->client);
      return;
    }
    switch (sa->sa_family)
    {
    case AF_INET:
      {
	const struct sockaddr_in *s4 = (const struct sockaddr_in *) sa;
	
	alen = sizeof (struct sockaddr_in);
	if (is_nat_v4 (&s4->sin_addr))
	  ch->natted_address = GNUNET_YES;
      }
      break;
    case AF_INET6:
      {
	const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *) sa;
	
	alen = sizeof (struct sockaddr_in6);
	if (is_nat_v6 (&s6->sin6_addr))
	  ch->natted_address = GNUNET_YES;
      }
      break;
#if AF_UNIX
    case AF_UNIX:
      alen = sizeof (struct sockaddr_un);
      break;
#endif
    default:
      GNUNET_break (0);
      GNUNET_SERVICE_client_drop (ch->client);
      return;      
    }
    GNUNET_assert (alen <= left);
    ch->addrs[i] = GNUNET_malloc (alen);
    GNUNET_memcpy (ch->addrs[i],
		   sa,
		   alen);    
    off += alen;
  }
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
  if (0 != mini_external_ipv4.s_addr)
  {
    check_notify_client_external_ipv4_change (&mini_external_ipv4,
					      ch,
					      GNUNET_YES);
  }
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
    v4.sin_port = htons (ch->adv_port);
    env = GNUNET_MQ_msg_extra (msg,
			       sizeof (v4),
			       GNUNET_MESSAGE_TYPE_NAT_ADDRESS_CHANGE);
    msg->add_remove = htonl ((int32_t) add);
    msg->addr_class = htonl (GNUNET_NAT_AC_GLOBAL_EXTERN |
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
      if (0 != memcmp (&external_addr,
		       &se->external_addr,
		       sizeof (struct sockaddr_in)))
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
  const struct sockaddr *local_sa = (const struct sockaddr *) &buf[0];
  const struct sockaddr *remote_sa = (const struct sockaddr *) &buf[local_sa_len];
  const struct sockaddr_in *l4 = NULL;
  const struct sockaddr_in *r4;
  int ret;
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received REQUEST CONNECTION REVERSAL message from client\n");
  switch (local_sa->sa_family)
  {
  case AF_INET:
    if (local_sa_len != sizeof (struct sockaddr_in))
    {
      GNUNET_break (0);
      GNUNET_SERVICE_client_drop (ch->client);
      return;
    }
    l4 = (const struct sockaddr_in *) local_sa;    
    break;
  case AF_INET6:
    if (local_sa_len != sizeof (struct sockaddr_in6))
    {
      GNUNET_break (0);
      GNUNET_SERVICE_client_drop (ch->client);
      return;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Connection reversal for IPv6 not supported yet\n"));
    ret = GNUNET_SYSERR;
    break;
  default:
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (ch->client);
    return;
  }
  switch (remote_sa->sa_family)
  {
  case AF_INET:
    if (remote_sa_len != sizeof (struct sockaddr_in))
    {
      GNUNET_break (0);
      GNUNET_SERVICE_client_drop (ch->client);
      return;
    }
    r4 = (const struct sockaddr_in *) remote_sa;
    ret = GN_request_connection_reversal (&l4->sin_addr,
					  ntohs (l4->sin_port),
					  &r4->sin_addr);
    break;
  case AF_INET6:
    if (remote_sa_len != sizeof (struct sockaddr_in6))
    {
      GNUNET_break (0);
      GNUNET_SERVICE_client_drop (ch->client);
      return;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Connection reversal for IPv6 not supported yet\n"));
    ret = GNUNET_SYSERR;
    break;
  default:
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (ch->client);
    return;
  }
  if (GNUNET_OK != ret)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Connection reversal request failed\n"));  
  GNUNET_SERVICE_client_continue (ch->client);
}


/**
 * Check validity of #GNUNET_MESSAGE_TYPE_NAT_REQUEST_AUTO_CFG message
 * from client.
 *
 * @param cls client who sent the message
 * @param message the message received
 * @return #GNUNET_OK if message is well-formed
 */
static int
check_autoconfig_request (void *cls,
			  const struct GNUNET_NAT_AutoconfigRequestMessage *message)
{
  return GNUNET_OK;  /* checked later */
}


/**
 * Stop all pending activities with respect to the @a ac
 *
 * @param ac autoconfiguration to terminate activities for
 */
static void
terminate_ac_activities (struct AutoconfigContext *ac)
{
  if (NULL != ac->probe_external)
  {
    GNUNET_NAT_mini_get_external_ipv4_cancel_ (ac->probe_external);
    ac->probe_external = NULL;
  }
  if (NULL != ac->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (ac->timeout_task);
    ac->timeout_task = NULL;
  }
}


/**
 * Finish handling the autoconfiguration request and send
 * the response to the client.
 *
 * @param cls the `struct AutoconfigContext` to conclude
 */
static void
conclude_autoconfig_request (void *cls)
{
  struct AutoconfigContext *ac = cls;
  struct ClientHandle *ch = ac->ch;
  struct GNUNET_NAT_AutoconfigResultMessage *arm;
  struct GNUNET_MQ_Envelope *env;
  size_t c_size;
  char *buf;
  struct GNUNET_CONFIGURATION_Handle *diff;
  
  ac->timeout_task = NULL;
  terminate_ac_activities (ac);

  /* Send back response */
  diff = GNUNET_CONFIGURATION_get_diff (ac->orig,
					ac->c);
  buf = GNUNET_CONFIGURATION_serialize (diff,
					&c_size);
  GNUNET_CONFIGURATION_destroy (diff);
  env = GNUNET_MQ_msg_extra (arm,
			     c_size,
			     GNUNET_MESSAGE_TYPE_NAT_AUTO_CFG_RESULT);
  arm->status_code = htonl ((uint32_t) ac->status_code);
  arm->type = htonl ((uint32_t) ac->type);
  GNUNET_memcpy (&arm[1],
		 buf,
		 c_size);
  GNUNET_free (buf);
  GNUNET_MQ_send (ch->mq,
		  env);

  /* clean up */
  GNUNET_free (ac->system_type);
  GNUNET_CONFIGURATION_destroy (ac->orig);
  GNUNET_CONFIGURATION_destroy (ac->c);
  GNUNET_CONTAINER_DLL_remove (ac_head,
			       ac_tail,
			       ac);
  GNUNET_free (ac);
  GNUNET_SERVICE_client_continue (ch->client);
}


/**
 * Check if all autoconfiguration operations have concluded,
 * and if they have, send the result back to the client.
 *
 * @param ac autoconfiguation context to check
 */
static void
check_autoconfig_finished (struct AutoconfigContext *ac)
{
  if (NULL != ac->probe_external)
    return;
  GNUNET_SCHEDULER_cancel (ac->timeout_task);
  ac->timeout_task
    = GNUNET_SCHEDULER_add_now (&conclude_autoconfig_request,
				ac);
}


/**
 * Update ENABLE_UPNPC configuration option.
 *
 * @param ac autoconfiguration to update
 */
static void
update_enable_upnpc_option (struct AutoconfigContext *ac)
{
  switch (ac->enable_upnpc)
  {
  case GNUNET_YES:
    GNUNET_CONFIGURATION_set_value_string (ac->c,
					   "NAT",
					   "ENABLE_UPNP",
					   "YES");
    break;
  case GNUNET_NO:
    GNUNET_CONFIGURATION_set_value_string (ac->c,
					   "NAT",
					   "ENABLE_UPNP",
					   "NO");
    break;
  case GNUNET_SYSERR:
    /* We are unsure, do not change option */
    break;
  }
}


/**
 * Handle result from external IP address probe during
 * autoconfiguration.
 *
 * @param cls our `struct AutoconfigContext`
 * @param addr the address, NULL on errors
 * @param result #GNUNET_NAT_ERROR_SUCCESS on success, otherwise the specific error code
 */
static void
auto_external_result_cb (void *cls,
			 const struct in_addr *addr,
			 enum GNUNET_NAT_StatusCode result)
{
  struct AutoconfigContext *ac = cls;

  ac->probe_external = NULL;
  switch (result)
  {
  case GNUNET_NAT_ERROR_SUCCESS:
    ac->enable_upnpc = GNUNET_YES;
    break;
  case GNUNET_NAT_ERROR_EXTERNAL_IP_UTILITY_OUTPUT_INVALID:
  case GNUNET_NAT_ERROR_EXTERNAL_IP_ADDRESS_INVALID:
  case GNUNET_NAT_ERROR_IPC_FAILURE:
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		"Disabling UPNPC: %d\n",
		(int) result);
    ac->enable_upnpc = GNUNET_NO; /* did not work */
    break;
  default:
    GNUNET_break (0); /* unexpected */
    ac->enable_upnpc = GNUNET_SYSERR;
    break;    
  }
  update_enable_upnpc_option (ac);
  check_autoconfig_finished (ac);
}


/**
 * Handler for #GNUNET_MESSAGE_TYPE_NAT_REQUEST_AUTO_CFG message from
 * client.
 *
 * @param cls client who sent the message
 * @param message the message received
 */
static void
handle_autoconfig_request (void *cls,
			   const struct GNUNET_NAT_AutoconfigRequestMessage *message)
{
  struct ClientHandle *ch = cls;
  size_t left = ntohs (message->header.size) - sizeof (*message);
  struct LocalAddressList *lal;
  struct AutoconfigContext *ac;

  ac = GNUNET_new (struct AutoconfigContext);
  ac->status_code = GNUNET_NAT_ERROR_SUCCESS;
  ac->ch = ch;
  ac->c = GNUNET_CONFIGURATION_create ();
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_deserialize (ac->c,
					(const char *) &message[1],
					left,
					GNUNET_NO))
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (ch->client);
    GNUNET_CONFIGURATION_destroy (ac->c);
    GNUNET_free (ac);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received REQUEST_AUTO_CONFIG message from client\n");

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (ac->c,
					     "PEER",
					     "SYSTEM_TYPE",
					     &ac->system_type))
    ac->system_type = GNUNET_strdup ("UNKNOWN");

  GNUNET_CONTAINER_DLL_insert (ac_head,
			       ac_tail,
			       ac);
  ac->orig
    = GNUNET_CONFIGURATION_dup (ac->c);
  ac->timeout_task
    = GNUNET_SCHEDULER_add_delayed (AUTOCONFIG_TIMEOUT,
				    &conclude_autoconfig_request,
				    ac);
  ac->enable_upnpc = GNUNET_SYSERR; /* undecided */
  
  /* Probe for upnpc */
  if (GNUNET_SYSERR ==
      GNUNET_OS_check_helper_binary ("upnpc",
				     GNUNET_NO,
				     NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		_("UPnP client `upnpc` command not found, disabling UPnP\n"));
    ac->enable_upnpc = GNUNET_NO;
  }
  else
  {
    for (lal = lal_head; NULL != lal; lal = lal->next)
      if (GNUNET_NAT_AC_LAN == (lal->ac & GNUNET_NAT_AC_LAN))
	/* we are behind NAT, useful to try upnpc */
	ac->enable_upnpc = GNUNET_YES;
  }
  if (GNUNET_YES == ac->enable_upnpc)
  {
    /* If we are a mobile device, always leave it on as the network
       may change to one that supports UPnP anytime.  If we are
       stationary, check if our network actually supports UPnP, and if
       not, disable it. */
    if ( (0 == strcasecmp (ac->system_type,
			   "INFRASTRUCTURE")) ||
	 (0 == strcasecmp (ac->system_type,
			   "DESKTOP")) )
    {
      /* Check if upnpc gives us an external IP */
      ac->probe_external
	= GNUNET_NAT_mini_get_external_ipv4_ (&auto_external_result_cb,
					      ac);
    }
  }
  if (NULL == ac->probe_external)
    update_enable_upnpc_option (ac);

  /* Finally, check if we are already done */  
  check_autoconfig_finished (ac);
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
  struct AutoconfigContext *ac;

  while (NULL != (ac = ac_head))
  {
    GNUNET_CONTAINER_DLL_remove (ac_head,
				 ac_tail,
				 ac);
    terminate_ac_activities (ac);
    GNUNET_free (ac);
  }
  while (NULL != (se = se_head))
  {
    GNUNET_CONTAINER_DLL_remove (se_head,
				 se_tail,
				 se);
    GNUNET_SCHEDULER_cancel (se->timeout_task);
    GNUNET_free (se);
  }
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

  GNUNET_CONTAINER_DLL_remove (ch_head,
			       ch_tail,
			       ch);
  for (unsigned int i=0;i<ch->num_addrs;i++)
    GNUNET_free_non_null (ch->addrs[i]);
  GNUNET_free_non_null (ch->addrs);
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
 GNUNET_MQ_hd_var_size (autoconfig_request,
			GNUNET_MESSAGE_TYPE_NAT_REQUEST_AUTO_CFG,
			struct GNUNET_NAT_AutoconfigRequestMessage,
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
