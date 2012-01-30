/*
     This file is part of GNUnet
     (C) 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file transport/plugin_transport_udp.c
 * @brief Implementation of the UDP transport protocol
 * @author Christian Grothoff
 * @author Nathan Evans
 * @author Matthias Wachs
 */
#include "platform.h"
#include "plugin_transport_udp_new.h"
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


/**
 * Closure for 'append_port'.
 */
struct PrettyPrinterContext
{
  /**
   * Function to call with the result.
   */
  GNUNET_TRANSPORT_AddressStringCallback asc;

  /**
   * Clsoure for 'asc'.
   */
  void *asc_cls;

  /**
   * Port to add after the IP address.
   */
  uint16_t port;
};


/**
 * Function called for a quick conversion of the binary address to
 * a numeric address.  Note that the caller must not free the
 * address and that the next call to this function is allowed
 * to override the address again.
 *
 * @param cls closure
 * @param addr binary address
 * @param addrlen length of the address
 * @return string representing the same address
 */
const char *
udp_address_to_string (void *cls, const void *addr, size_t addrlen)
{
  static char rbuf[INET6_ADDRSTRLEN + 10];
  char buf[INET6_ADDRSTRLEN];
  const void *sb;
  struct in_addr a4;
  struct in6_addr a6;
  const struct IPv4UdpAddress *t4;
  const struct IPv6UdpAddress *t6;
  int af;
  uint16_t port;

  if (addrlen == sizeof (struct IPv6UdpAddress))
  {
    t6 = addr;
    af = AF_INET6;
    port = ntohs (t6->u6_port);
    memcpy (&a6, &t6->ipv6_addr, sizeof (a6));
    sb = &a6;
  }
  else if (addrlen == sizeof (struct IPv4UdpAddress))
  {
    t4 = addr;
    af = AF_INET;
    port = ntohs (t4->u4_port);
    memcpy (&a4, &t4->ipv4_addr, sizeof (a4));
    sb = &a4;
  }
  else
  {
    GNUNET_break_op (0);
    return NULL;
  }
  inet_ntop (af, sb, buf, INET6_ADDRSTRLEN);
  GNUNET_snprintf (rbuf, sizeof (rbuf), (af == AF_INET6) ? "[%s]:%u" : "%s:%u",
                   buf, port);
  return rbuf;
}


/**
 * Append our port and forward the result.
 *
 * @param cls a 'struct PrettyPrinterContext'
 * @param hostname result from DNS resolver
 */
static void
append_port (void *cls, const char *hostname)
{
  struct PrettyPrinterContext *ppc = cls;
  char *ret;

  if (hostname == NULL)
  {
    ppc->asc (ppc->asc_cls, NULL);
    GNUNET_free (ppc);
    return;
  }
  GNUNET_asprintf (&ret, "%s:%d", hostname, ppc->port);
  ppc->asc (ppc->asc_cls, ret);
  GNUNET_free (ret);
}


/**
 * Convert the transports address to a nice, human-readable
 * format.
 *
 * @param cls closure
 * @param type name of the transport that generated the address
 * @param addr one of the addresses of the host, NULL for the last address
 *        the specific address format depends on the transport
 * @param addrlen length of the address
 * @param numeric should (IP) addresses be displayed in numeric form?
 * @param timeout after how long should we give up?
 * @param asc function to call on each string
 * @param asc_cls closure for asc
 */
static void
udp_plugin_address_pretty_printer (void *cls, const char *type,
                                   const void *addr, size_t addrlen,
                                   int numeric,
                                   struct GNUNET_TIME_Relative timeout,
                                   GNUNET_TRANSPORT_AddressStringCallback asc,
                                   void *asc_cls)
{
  struct PrettyPrinterContext *ppc;
  const void *sb;
  size_t sbs;
  struct sockaddr_in a4;
  struct sockaddr_in6 a6;
  const struct IPv4UdpAddress *u4;
  const struct IPv6UdpAddress *u6;
  uint16_t port;

  if (addrlen == sizeof (struct IPv6UdpAddress))
  {
    u6 = addr;
    memset (&a6, 0, sizeof (a6));
    a6.sin6_family = AF_INET6;
#if HAVE_SOCKADDR_IN_SIN_LEN
    a6.sin6_len = sizeof (a6);
#endif
    a6.sin6_port = u6->u6_port;
    memcpy (&a6.sin6_addr, &u6->ipv6_addr, sizeof (struct in6_addr));
    port = ntohs (u6->u6_port);
    sb = &a6;
    sbs = sizeof (a6);
  }
  else if (addrlen == sizeof (struct IPv4UdpAddress))
  {
    u4 = addr;
    memset (&a4, 0, sizeof (a4));
    a4.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
    a4.sin_len = sizeof (a4);
#endif
    a4.sin_port = u4->u4_port;
    a4.sin_addr.s_addr = u4->ipv4_addr;
    port = ntohs (u4->u4_port);
    sb = &a4;
    sbs = sizeof (a4);
  }
  else
  {
    /* invalid address */
    GNUNET_break_op (0);
    asc (asc_cls, NULL);
    return;
  }
  ppc = GNUNET_malloc (sizeof (struct PrettyPrinterContext));
  ppc->asc = asc;
  ppc->asc_cls = asc_cls;
  ppc->port = port;
  GNUNET_RESOLVER_hostname_get (sb, sbs, !numeric, timeout, &append_port, ppc);
}


/**
 * Check if the given port is plausible (must be either our listen
 * port or our advertised port).  If it is neither, we return
 * GNUNET_SYSERR.
 *
 * @param plugin global variables
 * @param in_port port number to check
 * @return GNUNET_OK if port is either open_port or adv_port
 */
static int
check_port (struct Plugin *plugin, uint16_t in_port)
{
  if ((in_port == plugin->port) || (in_port == plugin->aport))
    return GNUNET_OK;
  return GNUNET_SYSERR;
}



/**
 * Function that will be called to check if a binary address for this
 * plugin is well-formed and corresponds to an address for THIS peer
 * (as per our configuration).  Naturally, if absolutely necessary,
 * plugins can be a bit conservative in their answer, but in general
 * plugins should make sure that the address does not redirect
 * traffic to a 3rd party that might try to man-in-the-middle our
 * traffic.
 *
 * @param cls closure, should be our handle to the Plugin
 * @param addr pointer to the address
 * @param addrlen length of addr
 * @return GNUNET_OK if this is a plausible address for this peer
 *         and transport, GNUNET_SYSERR if not
 *
 */
static int
udp_plugin_check_address (void *cls, const void *addr, size_t addrlen)
{
  struct Plugin *plugin = cls;
  struct IPv4UdpAddress *v4;
  struct IPv6UdpAddress *v6;

  if ((addrlen != sizeof (struct IPv4UdpAddress)) &&
      (addrlen != sizeof (struct IPv6UdpAddress)))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (addrlen == sizeof (struct IPv4UdpAddress))
  {
    v4 = (struct IPv4UdpAddress *) addr;
    if (GNUNET_OK != check_port (plugin, ntohs (v4->u4_port)))
      return GNUNET_SYSERR;
    if (GNUNET_OK !=
        GNUNET_NAT_test_address (plugin->nat, &v4->ipv4_addr,
                                 sizeof (struct in_addr)))
      return GNUNET_SYSERR;
  }
  else
  {
    v6 = (struct IPv6UdpAddress *) addr;
    if (IN6_IS_ADDR_LINKLOCAL (&v6->ipv6_addr))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
    if (GNUNET_OK != check_port (plugin, ntohs (v6->u6_port)))
      return GNUNET_SYSERR;
    if (GNUNET_OK !=
        GNUNET_NAT_test_address (plugin->nat, &v6->ipv6_addr,
                                 sizeof (struct in6_addr)))
      return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Disconnect from a remote node.  Clean up session if we have one for this peer
 *
 * @param cls closure for this call (should be handle to Plugin)
 * @param target the peeridentity of the peer to disconnect
 * @return GNUNET_OK on success, GNUNET_SYSERR if the operation failed
 */
static void
udp_disconnect (void *cls, const struct GNUNET_PeerIdentity *target)
{

}


/**
 * Creates a new outbound session the transport service will use to send data to the
 * peer
 *
 * @param cls the plugin
 * @param address the address
 * @return the session or NULL of max connections exceeded
 */

static struct Session *
udp_plugin_get_session (void *cls,
                  const struct GNUNET_HELLO_Address *address)
{
  struct Session * s = NULL;
  //struct Plugin * plugin = cls;

  return s;
}


/**
 * Function that can be used by the transport service to transmit
 * a message using the plugin.   Note that in the case of a
 * peer disconnecting, the continuation MUST be called
 * prior to the disconnect notification itself.  This function
 * will be called with this peer's HELLO message to initiate
 * a fresh connection to another peer.
 *
 * @param cls closure
 * @param session which session must be used
 * @param msgbuf the message to transmit
 * @param msgbuf_size number of bytes in 'msgbuf'
 * @param priority how important is the message (most plugins will
 *                 ignore message priority and just FIFO)
 * @param to how long to wait at most for the transmission (does not
 *                require plugins to discard the message after the timeout,
 *                just advisory for the desired delay; most plugins will ignore
 *                this as well)
 * @param cont continuation to call once the message has
 *        been transmitted (or if the transport is ready
 *        for the next transmission call; or if the
 *        peer disconnected...); can be NULL
 * @param cont_cls closure for cont
 * @return number of bytes used (on the physical network, with overheads);
 *         -1 on hard errors (i.e. address invalid); 0 is a legal value
 *         and does NOT mean that the message was not transmitted (DV)
 */
static ssize_t
udp_plugin_send (void *cls,
                  struct Session *session,
                  const char *msgbuf, size_t msgbuf_size,
                  unsigned int priority,
                  struct GNUNET_TIME_Relative to,
                  GNUNET_TRANSPORT_TransmitContinuation cont, void *cont_cls)
{

  return 0;

}


/**
 * Our external IP address/port mapping has changed.
 *
 * @param cls closure, the 'struct LocalAddrList'
 * @param add_remove GNUNET_YES to mean the new public IP address, GNUNET_NO to mean
 *     the previous (now invalid) one
 * @param addr either the previous or the new public IP address
 * @param addrlen actual lenght of the address
 */
static void
udp_nat_port_map_callback (void *cls, int add_remove,
                           const struct sockaddr *addr, socklen_t addrlen)
{
  struct Plugin *plugin = cls;
  struct IPv4UdpAddress u4;
  struct IPv6UdpAddress u6;
  void *arg;
  size_t args;

  /* convert 'addr' to our internal format */
  switch (addr->sa_family)
  {
  case AF_INET:
    GNUNET_assert (addrlen == sizeof (struct sockaddr_in));
    u4.ipv4_addr = ((struct sockaddr_in *) addr)->sin_addr.s_addr;
    u4.u4_port = ((struct sockaddr_in *) addr)->sin_port;
    arg = &u4;
    args = sizeof (u4);
    break;
  case AF_INET6:
    GNUNET_assert (addrlen == sizeof (struct sockaddr_in6));
    memcpy (&u6.ipv6_addr, &((struct sockaddr_in6 *) addr)->sin6_addr,
            sizeof (struct in6_addr));
    u6.u6_port = ((struct sockaddr_in6 *) addr)->sin6_port;
    arg = &u6;
    args = sizeof (u6);
    break;
  default:
    GNUNET_break (0);
    return;
  }
  /* modify our published address list */
  plugin->env->notify_address (plugin->env->cls, add_remove, arg, args);
}


static int
setup_sockets (struct Plugin *plugin, struct sockaddr_in6 *serverAddrv6, struct sockaddr_in *serverAddrv4)
{
  int tries;
  int sockets_created = 0;
  struct sockaddr *serverAddr;
  struct sockaddr *addrs[2];
  socklen_t addrlens[2];
  socklen_t addrlen;

  /* Create IPv6 socket */
  if (plugin->enable_ipv6 == GNUNET_YES)
  {
    plugin->sockv6 = GNUNET_NETWORK_socket_create (PF_INET6, SOCK_DGRAM, 0);
    if (NULL == plugin->sockv6)
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "socket");
    }
    else
    {
#if HAVE_SOCKADDR_IN_SIN_LEN
      serverAddrv6.sin6_len = sizeof (serverAddrv6);
#endif
      serverAddrv6->sin6_family = AF_INET6;
      serverAddrv6->sin6_addr = in6addr_any;
      serverAddrv6->sin6_port = htons (plugin->port);
      addrlen = sizeof (struct sockaddr_in6);
      serverAddr = (struct sockaddr *) serverAddrv6;
#if DEBUG_UDP
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Binding to IPv6 port %d\n",
           ntohs (serverAddrv6->sin6_port));
#endif
      tries = 0;
      while (GNUNET_NETWORK_socket_bind (plugin->sockv6, serverAddr, addrlen) !=
             GNUNET_OK)
      {
        serverAddrv6->sin6_port = htons (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_STRONG, 33537) + 32000);        /* Find a good, non-root port */
#if DEBUG_UDP
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "IPv6 Binding failed, trying new port %d\n",
             ntohs (serverAddrv6->sin6_port));
#endif
        tries++;
        if (tries > 10)
        {
          GNUNET_NETWORK_socket_close (plugin->sockv6);
          plugin->sockv6 = NULL;
          break;
        }
      }
      if (plugin->sockv6 != NULL)
      {
#if DEBUG_UDP
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "IPv6 socket created on port %d\n",
             ntohs (serverAddrv6->sin6_port));
#endif
        addrs[sockets_created] = (struct sockaddr *) serverAddrv6;
        addrlens[sockets_created] = sizeof (struct sockaddr_in6);
        sockets_created++;
      }
    }
  }

  /* Create IPv4 socket */
  plugin->sockv4 = GNUNET_NETWORK_socket_create (PF_INET, SOCK_DGRAM, 0);
  if (NULL == plugin->sockv4)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "socket");
  }
  else
  {
#if HAVE_SOCKADDR_IN_SIN_LEN
    serverAddrv4.sin_len = sizeof (serverAddrv4);
#endif
    serverAddrv4->sin_family = AF_INET;
    serverAddrv4->sin_addr.s_addr = INADDR_ANY;
    serverAddrv4->sin_port = htons (plugin->port);
    addrlen = sizeof (struct sockaddr_in);
    serverAddr = (struct sockaddr *) serverAddrv4;

#if DEBUG_UDP
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Binding to IPv4 port %d\n",
         ntohs (serverAddrv4->sin_port));
#endif
    tries = 0;
    while (GNUNET_NETWORK_socket_bind (plugin->sockv4, serverAddr, addrlen) !=
           GNUNET_OK)
    {
      serverAddrv4->sin_port = htons (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_STRONG, 33537) + 32000);   /* Find a good, non-root port */
#if DEBUG_UDP
      LOG (GNUNET_ERROR_TYPE_DEBUG, "IPv4 Binding failed, trying new port %d\n",
           ntohs (serverAddrv4->sin_port));
#endif
      tries++;
      if (tries > 10)
      {
        GNUNET_NETWORK_socket_close (plugin->sockv4);
        plugin->sockv4 = NULL;
        break;
      }
    }
    if (plugin->sockv4 != NULL)
    {
      addrs[sockets_created] = (struct sockaddr *) serverAddrv4;
      addrlens[sockets_created] = sizeof (struct sockaddr_in);
      sockets_created++;
    }
  }

  /* Create file descriptors */
  plugin->rs = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_zero (plugin->rs);
  if (NULL != plugin->sockv4)
    GNUNET_NETWORK_fdset_set (plugin->rs, plugin->sockv4);
  if (NULL != plugin->sockv6)
    GNUNET_NETWORK_fdset_set (plugin->rs, plugin->sockv6);

  if (sockets_created == 0)
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, _("Failed to open UDP sockets\n"));

  plugin->nat = GNUNET_NAT_register (plugin->env->cfg,
                           GNUNET_NO, plugin->port,
                           sockets_created,
                           (const struct sockaddr **) addrs, addrlens,
                           &udp_nat_port_map_callback, NULL, plugin);

  return sockets_created;
}


/**
 * The exported method. Makes the core api available via a global and
 * returns the udp transport API.
 *
 * @param cls our 'struct GNUNET_TRANSPORT_PluginEnvironment'
 * @return our 'struct GNUNET_TRANSPORT_PluginFunctions'
 */
void *
libgnunet_plugin_transport_udp_init (void *cls)
{
  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  struct Plugin *plugin;

  unsigned long long port;
  unsigned long long aport;
  unsigned long long broadcast;
  unsigned long long udp_max_bps;
  unsigned long long enable_v6;
  char * bind4_address;
  char * bind6_address;
  struct GNUNET_TIME_Relative interval;

  struct sockaddr_in serverAddrv4;
  struct sockaddr_in6 serverAddrv6;

  int res;

  /* Get port number */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (env->cfg, "transport-udp", "PORT",
                                             &port))
    port = 2086;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (env->cfg, "transport-udp",
                                             "ADVERTISED_PORT", &aport))
    aport = port;
  if (port > 65535)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("Given `%s' option is out of range: %llu > %u\n"), "PORT", port,
         65535);
    return NULL;
  }

  /* Protocols */
  if ((GNUNET_YES ==
       GNUNET_CONFIGURATION_get_value_yesno (env->cfg, "nat",
                                             "DISABLEV6")))
  {
    enable_v6 = GNUNET_NO;
  }
  else
    enable_v6 = GNUNET_YES;


  /* Addresses */
  memset (&serverAddrv6, 0, sizeof (serverAddrv6));
  memset (&serverAddrv4, 0, sizeof (serverAddrv4));

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_string (env->cfg, "transport-udp",
                                             "BINDTO", &bind4_address))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Binding udp plugin to specific address: `%s'\n",
         bind4_address);
    if (1 != inet_pton (AF_INET, bind4_address, &serverAddrv4.sin_addr))
    {
      GNUNET_free (bind4_address);
      return NULL;
    }
  }

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_string (env->cfg, "transport-udp",
                                             "BINDTO6", &bind6_address))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Binding udp plugin to specific address: `%s'\n",
         bind6_address);
    if (1 !=
        inet_pton (AF_INET6, bind6_address, &serverAddrv6.sin6_addr))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, _("Invalid IPv6 address: `%s'\n"),
           bind6_address);
      GNUNET_free_non_null (bind4_address);
      GNUNET_free (bind6_address);
      return NULL;
    }
  }


  /* Enable neighbour discovery */
  broadcast = GNUNET_CONFIGURATION_get_value_yesno (env->cfg, "transport-udp",
                                            "BROADCAST");
  if (broadcast == GNUNET_SYSERR)
    broadcast = GNUNET_NO;

  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_time (env->cfg, "transport-udp",
                                           "BROADCAST_INTERVAL", &interval))
  {
    interval = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10);
  }

  /* Maximum datarate */
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (env->cfg, "transport-udp",
                                             "MAX_BPS", &udp_max_bps))
  {
    udp_max_bps = 1024 * 1024 * 50;     /* 50 MB/s == infinity for practical purposes */
  }

  plugin = GNUNET_malloc (sizeof (struct Plugin));
  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));

  GNUNET_BANDWIDTH_tracker_init (&plugin->tracker,
                                 GNUNET_BANDWIDTH_value_init ((uint32_t)udp_max_bps), 30);

  plugin->port = port;
  plugin->aport = aport;
  plugin->last_expected_delay = GNUNET_TIME_UNIT_SECONDS;
  plugin->broadcast_interval = interval;
  plugin->enable_ipv6 = enable_v6;
  plugin->env = env;

  api->cls = plugin;
  api->send = NULL;
  api->disconnect = &udp_disconnect;
  api->address_pretty_printer = &udp_plugin_address_pretty_printer;
  api->address_to_string = &udp_address_to_string;
  api->check_address = &udp_plugin_check_address;
  api->get_session = &udp_plugin_get_session;
  api->send_with_session = &udp_plugin_send;

  LOG (GNUNET_ERROR_TYPE_ERROR, "Setting up sockets\n");
  res = setup_sockets (plugin, &serverAddrv6, &serverAddrv4);
  if ((res == 0) || ((plugin->sockv4 == NULL) && (plugin->sockv6 == NULL)))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, "Failed to create network sockets, plugin failed\n");
    GNUNET_free (plugin);
    GNUNET_free (api);
    return NULL;
  }
  LOG (GNUNET_ERROR_TYPE_ERROR, "Starting broadcasting\n");
  //setup_broadcast (plugin, &serverAddrv6, &serverAddrv4);


  GNUNET_free_non_null (bind4_address);
  GNUNET_free_non_null (bind6_address);
  return api;
}


/**
 * The exported method. Makes the core api available via a global and
 * returns the udp transport API.
 *
 * @param cls our 'struct GNUNET_TRANSPORT_PluginEnvironment'
 * @return our 'struct GNUNET_TRANSPORT_PluginFunctions'
 */
void *
libgnunet_plugin_transport_udp_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  /* Closing sockets */
  if (plugin->sockv4 != NULL)
  {
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (plugin->sockv4));
    plugin->sockv4 = NULL;
  }
  if (plugin->sockv6 != NULL)
  {
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (plugin->sockv6));
    plugin->sockv6 = NULL;
  }
  GNUNET_NETWORK_fdset_destroy (plugin->rs);

  GNUNET_NAT_unregister (plugin->nat);
  plugin->nat = NULL;
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}


/* end of plugin_transport_udp.c */
