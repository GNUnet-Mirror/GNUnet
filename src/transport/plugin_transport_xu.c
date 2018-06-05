/*
 This file is part of GNUnet
 Copyright (C) 2010-2017 GNUnet e.V.

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
 * @file transport/plugin_transport_xu.c
 * @brief Implementation of the XU transport protocol
 * @author Christian Grothoff
 * @author Nathan Evans
 * @author Matthias Wachs
 */
#include "platform.h"
#include "plugin_transport_xu.h"
#include "gnunet_hello_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_fragmentation_lib.h"
#include "gnunet_nat_service.h"
#include "gnunet_protocols.h"
#include "gnunet_resolver_service.h"
#include "gnunet_signatures.h"
#include "gnunet_constants.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_transport_plugin.h"
#include "transport.h"

#define LOG(kind,...) GNUNET_log_from (kind, "transport-xu", __VA_ARGS__)

/**
 * After how much inactivity should a XU session time out?
 */
#define XU_SESSION_TIME_OUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)


/**
 * XU Message-Packet header (after defragmentation).
 */
struct XUMessage
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


/**
 * Closure for #append_port().
 */
struct PrettyPrinterContext
{
  /**
   * DLL
   */
  struct PrettyPrinterContext *next;

  /**
   * DLL
   */
  struct PrettyPrinterContext *prev;

  /**
   * Our plugin.
   */
  struct Plugin *plugin;

  /**
   * Resolver handle
   */
  struct GNUNET_RESOLVER_RequestHandle *resolver_handle;

  /**
   * Function to call with the result.
   */
  GNUNET_TRANSPORT_AddressStringCallback asc;

  /**
   * Clsoure for @e asc.
   */
  void *asc_cls;

  /**
   * Timeout task
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

  /**
   * Is this an IPv6 address?
   */
  int ipv6;

  /**
   * Options
   */
  uint32_t options;

  /**
   * Port to add after the IP address.
   */
  uint16_t port;

};


/**
 * Session with another peer.
 */
struct GNUNET_ATS_Session
{
  /**
   * Which peer is this session for?
   */
  struct GNUNET_PeerIdentity target;

  /**
   * Tokenizer for inbound messages.
   */
  struct GNUNET_MessageStreamTokenizer *mst;

  /**
   * Plugin this session belongs to.
   */
  struct Plugin *plugin;

  /**
   * Session timeout task
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

  /**
   * When does this session time out?
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * What time did we last transmit?
   */
  struct GNUNET_TIME_Absolute last_transmit_time;

  /**
   * expected delay for ACKs
   */
  struct GNUNET_TIME_Relative last_expected_ack_delay;

  /**
   * desired delay between XU messages
   */
  struct GNUNET_TIME_Relative last_expected_msg_delay;
  
  /**
   */
  struct GNUNET_TIME_Relative flow_delay_for_other_peer;
  struct GNUNET_TIME_Relative flow_delay_from_other_peer;

  /**
   * Our own address.
   */
  struct GNUNET_HELLO_Address *address;

  /**
   * Number of bytes waiting for transmission to this peer.
   */
  unsigned long long bytes_in_queue;

  /**
   * Number of messages waiting for transmission to this peer.
   */
  unsigned int msgs_in_queue;

  /**
   * Reference counter to indicate that this session is
   * currently being used and must not be destroyed;
   * setting @e in_destroy will destroy it as soon as
   * possible.
   */
  unsigned int rc;

  /**
   * Network type of the address.
   */
  enum GNUNET_ATS_Network_Type scope;

  /**
   * Is this session about to be destroyed (sometimes we cannot
   * destroy a session immediately as below us on the stack
   * there might be code that still uses it; in this case,
   * @e rc is non-zero).
   */
  int in_destroy;
};



/**
 * If a session monitor is attached, notify it about the new
 * session state.
 *
 * @param plugin our plugin
 * @param session session that changed state
 * @param state new state of the session
 */
static void
notify_session_monitor (struct Plugin *plugin,
                        struct GNUNET_ATS_Session *session,
                        enum GNUNET_TRANSPORT_SessionState state)
{
  struct GNUNET_TRANSPORT_SessionInfo info;

  if (NULL == plugin->sic)
    return;
  if (GNUNET_YES == session->in_destroy)
    return; /* already destroyed, just RC>0 left-over actions */
  memset (&info,
          0,
          sizeof (info));
  info.state = state;
  info.is_inbound = GNUNET_SYSERR; /* hard to say */
  info.num_msg_pending = session->msgs_in_queue;
  info.num_bytes_pending = session->bytes_in_queue;
  /* info.receive_delay remains zero as this is not supported by XU
     (cannot selectively not receive from 'some' peer while continuing
     to receive from others) */
  info.session_timeout = session->timeout;
  info.address = session->address;
  plugin->sic (plugin->sic_cls,
               session,
               &info);
}


/**
 * Return information about the given session to the monitor callback.
 *
 * @param cls the `struct Plugin` with the monitor callback (`sic`)
 * @param peer peer we send information about
 * @param value our `struct GNUNET_ATS_Session` to send information about
 * @return #GNUNET_OK (continue to iterate)
 */
static int
send_session_info_iter (void *cls,
                        const struct GNUNET_PeerIdentity *peer,
                        void *value)
{
  struct Plugin *plugin = cls;
  struct GNUNET_ATS_Session *session = value;

  (void) peer;
  notify_session_monitor (plugin,
                          session,
                          GNUNET_TRANSPORT_SS_INIT);
  notify_session_monitor (plugin,
                          session,
                          GNUNET_TRANSPORT_SS_UP);
  return GNUNET_OK;
}


/**
 * Begin monitoring sessions of a plugin.  There can only
 * be one active monitor per plugin (i.e. if there are
 * multiple monitors, the transport service needs to
 * multiplex the generated events over all of them).
 *
 * @param cls closure of the plugin
 * @param sic callback to invoke, NULL to disable monitor;
 *            plugin will being by iterating over all active
 *            sessions immediately and then enter monitor mode
 * @param sic_cls closure for @a sic
 */
static void
xu_plugin_setup_monitor (void *cls,
                          GNUNET_TRANSPORT_SessionInfoCallback sic,
                          void *sic_cls)
{
  struct Plugin *plugin = cls;

  plugin->sic = sic;
  plugin->sic_cls = sic_cls;
  if (NULL != sic)
  {
    GNUNET_CONTAINER_multipeermap_iterate (plugin->sessions,
                                           &send_session_info_iter,
                                           plugin);
    /* signal end of first iteration */
    sic (sic_cls,
         NULL,
         NULL);
  }
}


/* ****************** Little Helpers ****************** */


/**
 * Function to free last resources associated with a session.
 *
 * @param s session to free
 */
static void
free_session (struct GNUNET_ATS_Session *s)
{
  if (NULL != s->address)
  {
    GNUNET_HELLO_address_free (s->address);
    s->address = NULL;
  }
  if (NULL != s->mst)
  {
    GNUNET_MST_destroy (s->mst);
    s->mst = NULL;
  }
  GNUNET_free (s);
}


/**
 * Function that is called to get the keepalive factor.
 * #GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT is divided by this number to
 * calculate the interval between keepalive packets.
 *
 * @param cls closure with the `struct Plugin`
 * @return keepalive factor
 */
static unsigned int
xu_query_keepalive_factor (void *cls)
{
  (void) cls;
  return 15;
}


/**
 * Function obtain the network type for a session
 *
 * @param cls closure (`struct Plugin *`)
 * @param session the session
 * @return the network type
 */
static enum GNUNET_ATS_Network_Type
xu_plugin_get_network (void *cls,
		       struct GNUNET_ATS_Session *session)
{
  (void) cls;
  return session->scope;
}


/**
 * Function obtain the network type for an address.
 *
 * @param cls closure (`struct Plugin *`)
 * @param address the address
 * @return the network type
 */
static enum GNUNET_ATS_Network_Type
xu_plugin_get_network_for_address (void *cls,
				   const struct GNUNET_HELLO_Address *address)
{
  struct Plugin *plugin = cls;
  size_t addrlen;
  struct sockaddr_in a4;
  struct sockaddr_in6 a6;
  const struct IPv4XuAddress *u4;
  const struct IPv6XuAddress *u6;
  const void *sb;
  size_t sbs;

  addrlen = address->address_length;
  if (addrlen == sizeof(struct IPv6XuAddress))
  {
    GNUNET_assert (NULL != address->address); /* make static analysis happy */
    u6 = address->address;
    memset (&a6, 0, sizeof(a6));
#if HAVE_SOCKADDR_IN_SIN_LEN
    a6.sin6_len = sizeof (a6);
#endif
    a6.sin6_family = AF_INET6;
    a6.sin6_port = u6->u6_port;
    GNUNET_memcpy (&a6.sin6_addr, &u6->ipv6_addr, sizeof(struct in6_addr));
    sb = &a6;
    sbs = sizeof(a6);
  }
  else if (addrlen == sizeof(struct IPv4XuAddress))
  {
    GNUNET_assert (NULL != address->address); /* make static analysis happy */
    u4 = address->address;
    memset (&a4, 0, sizeof(a4));
#if HAVE_SOCKADDR_IN_SIN_LEN
    a4.sin_len = sizeof (a4);
#endif
    a4.sin_family = AF_INET;
    a4.sin_port = u4->u4_port;
    a4.sin_addr.s_addr = u4->ipv4_addr;
    sb = &a4;
    sbs = sizeof(a4);
  }
  else
  {
    GNUNET_break (0);
    return GNUNET_ATS_NET_UNSPECIFIED;
  }
  return plugin->env->get_address_type (plugin->env->cls,
                                        sb,
                                        sbs);
}


/* ******************* Event loop ******************** */

/**
 * We have been notified that our readset has something to read.  We don't
 * know which socket needs to be read, so we have to check each one
 * Then reschedule this function to be called again once more is available.
 *
 * @param cls the plugin handle
 */
static void
xu_plugin_select_v4 (void *cls);


/**
 * We have been notified that our readset has something to read.  We don't
 * know which socket needs to be read, so we have to check each one
 * Then reschedule this function to be called again once more is available.
 *
 * @param cls the plugin handle
 */
static void
xu_plugin_select_v6 (void *cls);


/**
 * (re)schedule IPv4-select tasks for this plugin.
 *
 * @param plugin plugin to reschedule
 */
static void
schedule_select_v4 (struct Plugin *plugin)
{
  if ( (GNUNET_YES != plugin->enable_ipv4) ||
       (NULL == plugin->sockv4) )
    return;
  if (NULL != plugin->select_task_v4)
    GNUNET_SCHEDULER_cancel (plugin->select_task_v4);
  plugin->select_task_v4
    = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
				     plugin->sockv4,
				     &xu_plugin_select_v4,
				     plugin);
}


/**
 * (re)schedule IPv6-select tasks for this plugin.
 *
 * @param plugin plugin to reschedule
 */
static void
schedule_select_v6 (struct Plugin *plugin)
{
  if ( (GNUNET_YES != plugin->enable_ipv6) ||
       (NULL == plugin->sockv6) )
    return;
  if (NULL != plugin->select_task_v6)
    GNUNET_SCHEDULER_cancel (plugin->select_task_v6);
  plugin->select_task_v6
    = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
				     plugin->sockv6,
				     &xu_plugin_select_v6,
				     plugin);
}


/* ******************* Address to string and back ***************** */


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
                       size_t addrlen)
{
  static char rbuf[INET6_ADDRSTRLEN + 10];
  char buf[INET6_ADDRSTRLEN];
  const void *sb;
  struct in_addr a4;
  struct in6_addr a6;
  const struct IPv4XuAddress *t4;
  const struct IPv6XuAddress *t6;
  int af;
  uint16_t port;
  uint32_t options;

  (void) cls;
  if (NULL == addr)
  {
    GNUNET_break_op (0);
    return NULL;
  }

  if (addrlen == sizeof(struct IPv6XuAddress))
  {
    t6 = addr;
    af = AF_INET6;
    options = ntohl (t6->options);
    port = ntohs (t6->u6_port);
    a6 = t6->ipv6_addr;
    sb = &a6;
  }
  else if (addrlen == sizeof(struct IPv4XuAddress))
  {
    t4 = addr;
    af = AF_INET;
    options = ntohl (t4->options);
    port = ntohs (t4->u4_port);
    a4.s_addr = t4->ipv4_addr;
    sb = &a4;
  }
  else
  {
    GNUNET_break_op (0);
    return NULL;
  }
  inet_ntop (af,
             sb,
             buf,
             INET6_ADDRSTRLEN);
  GNUNET_snprintf (rbuf,
                   sizeof(rbuf),
                   (af == AF_INET6)
                   ? "%s.%u.[%s]:%u"
                   : "%s.%u.%s:%u",
                   PLUGIN_NAME,
                   options,
                   buf,
                   port);
  return rbuf;
}


/**
 * Function called to convert a string address to a binary address.
 *
 * @param cls closure (`struct Plugin *`)
 * @param addr string address
 * @param addrlen length of the address
 * @param buf location to store the buffer
 * @param added location to store the number of bytes in the buffer.
 *        If the function returns #GNUNET_SYSERR, its contents are undefined.
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
static int
xu_string_to_address (void *cls,
		      const char *addr,
		      uint16_t addrlen,
		      void **buf,
		      size_t *added)
{
  struct sockaddr_storage socket_address;
  char *address;
  char *plugin;
  char *optionstr;
  uint32_t options;

  (void) cls;
  /* Format tcp.options.address:port */
  address = NULL;
  plugin = NULL;
  optionstr = NULL;

  if ((NULL == addr) || (0 == addrlen))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if ('\0' != addr[addrlen - 1])
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (strlen (addr) + 1 != (size_t) addrlen)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  plugin = GNUNET_strdup (addr);
  optionstr = strchr (plugin, '.');
  if (NULL == optionstr)
  {
    GNUNET_break (0);
    GNUNET_free (plugin);
    return GNUNET_SYSERR;
  }
  optionstr[0] = '\0';
  optionstr++;
  options = atol (optionstr);
  address = strchr (optionstr, '.');
  if (NULL == address)
  {
    GNUNET_break (0);
    GNUNET_free (plugin);
    return GNUNET_SYSERR;
  }
  address[0] = '\0';
  address++;

  if (GNUNET_OK !=
      GNUNET_STRINGS_to_address_ip (address,
                                    strlen (address),
                                    &socket_address))
  {
    GNUNET_break (0);
    GNUNET_free (plugin);
    return GNUNET_SYSERR;
  }
  GNUNET_free(plugin);

  switch (socket_address.ss_family)
  {
  case AF_INET:
    {
      struct IPv4XuAddress *u4;
      const struct sockaddr_in *in4 = (const struct sockaddr_in *) &socket_address;

      u4 = GNUNET_new (struct IPv4XuAddress);
      u4->options = htonl (options);
      u4->ipv4_addr = in4->sin_addr.s_addr;
      u4->u4_port = in4->sin_port;
      *buf = u4;
      *added = sizeof (struct IPv4XuAddress);
      return GNUNET_OK;
    }
  case AF_INET6:
    {
      struct IPv6XuAddress *u6;
      const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *) &socket_address;

      u6 = GNUNET_new (struct IPv6XuAddress);
      u6->options = htonl (options);
      u6->ipv6_addr = in6->sin6_addr;
      u6->u6_port = in6->sin6_port;
      *buf = u6;
      *added = sizeof (struct IPv6XuAddress);
      return GNUNET_OK;
    }
  default:
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
}


/**
 * Append our port and forward the result.
 *
 * @param cls a `struct PrettyPrinterContext *`
 * @param hostname result from DNS resolver
 */
static void
append_port (void *cls,
             const char *hostname)
{
  struct PrettyPrinterContext *ppc = cls;
  struct Plugin *plugin = ppc->plugin;
  char *ret;

  if (NULL == hostname)
  {
    /* Final call, done */
    GNUNET_CONTAINER_DLL_remove (plugin->ppc_dll_head,
                                 plugin->ppc_dll_tail,
                                 ppc);
    ppc->resolver_handle = NULL;
    ppc->asc (ppc->asc_cls,
              NULL,
              GNUNET_OK);
    GNUNET_free (ppc);
    return;
  }
  if (GNUNET_YES == ppc->ipv6)
    GNUNET_asprintf (&ret,
                     "%s.%u.[%s]:%d",
                     PLUGIN_NAME,
                     ppc->options,
                     hostname,
                     ppc->port);
  else
    GNUNET_asprintf (&ret,
                     "%s.%u.%s:%d",
                     PLUGIN_NAME,
                     ppc->options,
                     hostname,
                     ppc->port);
  ppc->asc (ppc->asc_cls,
            ret,
            GNUNET_OK);
  GNUNET_free (ret);
}


/**
 * Convert the transports address to a nice, human-readable format.
 *
 * @param cls closure with the `struct Plugin *`
 * @param type name of the transport that generated the address
 * @param addr one of the addresses of the host, NULL for the last address
 *        the specific address format depends on the transport;
 *        a `union XuAddress`
 * @param addrlen length of the address
 * @param numeric should (IP) addresses be displayed in numeric form?
 * @param timeout after how long should we give up?
 * @param asc function to call on each string
 * @param asc_cls closure for @a asc
 */
static void
xu_plugin_address_pretty_printer (void *cls,
                                   const char *type,
                                   const void *addr,
                                   size_t addrlen,
                                   int numeric,
                                   struct GNUNET_TIME_Relative timeout,
                                   GNUNET_TRANSPORT_AddressStringCallback asc,
                                   void *asc_cls)
{
  struct Plugin *plugin = cls;
  struct PrettyPrinterContext *ppc;
  const struct sockaddr *sb;
  size_t sbs;
  struct sockaddr_in a4;
  struct sockaddr_in6 a6;
  const struct IPv4XuAddress *u4;
  const struct IPv6XuAddress *u6;
  uint16_t port;
  uint32_t options;

  (void) type;
  if (addrlen == sizeof(struct IPv6XuAddress))
  {
    u6 = addr;
    memset (&a6,
            0,
            sizeof (a6));
    a6.sin6_family = AF_INET6;
#if HAVE_SOCKADDR_IN_SIN_LEN
    a6.sin6_len = sizeof (a6);
#endif
    a6.sin6_port = u6->u6_port;
    a6.sin6_addr = u6->ipv6_addr;
    port = ntohs (u6->u6_port);
    options = ntohl (u6->options);
    sb = (const struct sockaddr *) &a6;
    sbs = sizeof (a6);
  }
  else if (addrlen == sizeof (struct IPv4XuAddress))
  {
    u4 = addr;
    memset (&a4,
            0,
            sizeof(a4));
    a4.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
    a4.sin_len = sizeof (a4);
#endif
    a4.sin_port = u4->u4_port;
    a4.sin_addr.s_addr = u4->ipv4_addr;
    port = ntohs (u4->u4_port);
    options = ntohl (u4->options);
    sb = (const struct sockaddr *) &a4;
    sbs = sizeof(a4);
  }
  else
  {
    /* invalid address */
    GNUNET_break_op (0);
    asc (asc_cls,
         NULL,
         GNUNET_SYSERR);
    asc (asc_cls,
         NULL,
         GNUNET_OK);
    return;
  }
  ppc = GNUNET_new (struct PrettyPrinterContext);
  ppc->plugin = plugin;
  ppc->asc = asc;
  ppc->asc_cls = asc_cls;
  ppc->port = port;
  ppc->options = options;
  if (addrlen == sizeof (struct IPv6XuAddress))
    ppc->ipv6 = GNUNET_YES;
  else
    ppc->ipv6 = GNUNET_NO;
  GNUNET_CONTAINER_DLL_insert (plugin->ppc_dll_head,
                               plugin->ppc_dll_tail,
                               ppc);
  ppc->resolver_handle
    = GNUNET_RESOLVER_hostname_get (sb,
                                    sbs,
                                    ! numeric,
                                    timeout,
                                    &append_port,
                                    ppc);
}


/**
 * Check if the given port is plausible (must be either our listen
 * port or our advertised port).  If it is neither, we return
 * #GNUNET_SYSERR.
 *
 * @param plugin global variables
 * @param in_port port number to check
 * @return #GNUNET_OK if port is either our open or advertised port
 */
static int
check_port (const struct Plugin *plugin,
            uint16_t in_port)
{
  if ( (plugin->port == in_port) ||
       (plugin->aport == in_port) )
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
 * @param addr pointer to a `union XuAddress`
 * @param addrlen length of @a addr
 * @return #GNUNET_OK if this is a plausible address for this peer
 *         and transport, #GNUNET_SYSERR if not
 */
static int
xu_plugin_check_address (void *cls,
			 const void *addr,
			 size_t addrlen)
{
  struct Plugin *plugin = cls;
  const struct IPv4XuAddress *v4;
  const struct IPv6XuAddress *v6;

  if (sizeof(struct IPv4XuAddress) == addrlen)
  {
    struct sockaddr_in s4;

    v4 = (const struct IPv4XuAddress *) addr;
    if (GNUNET_OK != check_port (plugin,
                                 ntohs (v4->u4_port)))
      return GNUNET_SYSERR;
    memset (&s4, 0, sizeof (s4));
    s4.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
    s4.sin_len = sizeof (s4);
#endif
    s4.sin_port = v4->u4_port;
    s4.sin_addr.s_addr = v4->ipv4_addr;

    if (GNUNET_OK !=
	GNUNET_NAT_test_address (plugin->nat,
				 &s4,
				 sizeof (struct sockaddr_in)))
      return GNUNET_SYSERR;
  }
  else if (sizeof(struct IPv6XuAddress) == addrlen)
  {
    struct sockaddr_in6 s6;

    v6 = (const struct IPv6XuAddress *) addr;
    if (IN6_IS_ADDR_LINKLOCAL (&v6->ipv6_addr))
      return GNUNET_OK; /* plausible, if unlikely... */
    memset (&s6, 0, sizeof (s6));
    s6.sin6_family = AF_INET6;
#if HAVE_SOCKADDR_IN_SIN_LEN
    s6.sin6_len = sizeof (s6);
#endif
    s6.sin6_port = v6->u6_port;
    s6.sin6_addr = v6->ipv6_addr;

    if (GNUNET_OK !=
	GNUNET_NAT_test_address (plugin->nat,
				 &s6,
				 sizeof(struct sockaddr_in6)))
      return GNUNET_SYSERR;
  }
  else
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Our external IP address/port mapping has changed.
 *
 * @param cls closure, the `struct Plugin`
 * @param add_remove #GNUNET_YES to mean the new public IP address,
 *                   #GNUNET_NO to mean the previous (now invalid) one
 * @param ac address class the address belongs to
 * @param addr either the previous or the new public IP address
 * @param addrlen actual length of the @a addr
 */
static void
xu_nat_port_map_callback (void *cls,
                           int add_remove,
			   enum GNUNET_NAT_AddressClass ac,
                           const struct sockaddr *addr,
                           socklen_t addrlen)
{
  struct Plugin *plugin = cls;
  struct GNUNET_HELLO_Address *address;
  struct IPv4XuAddress u4;
  struct IPv6XuAddress u6;
  void *arg;
  size_t args;

  if (GNUNET_NAT_AC_LOOPBACK == ac)
    return;
  if (GNUNET_NAT_AC_LAN == ac)
    return;
  if (GNUNET_NAT_AC_LAN_PRIVATE == ac)
    return;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       (GNUNET_YES == add_remove)
       ? "NAT notification to add address `%s'\n"
       : "NAT notification to remove address `%s'\n",
       GNUNET_a2s (addr,
                   addrlen));
  /* convert 'address' to our internal format */
  switch (addr->sa_family)
  {
  case AF_INET:
    {
      const struct sockaddr_in *i4;

      GNUNET_assert (sizeof(struct sockaddr_in) == addrlen);
      i4 = (const struct sockaddr_in *) addr;
      if (0 == ntohs (i4->sin_port))
        return; /* Port = 0 means unmapped, ignore these for XU. */
      memset (&u4,
              0,
              sizeof(u4));
      u4.options = htonl (plugin->myoptions);
      u4.ipv4_addr = i4->sin_addr.s_addr;
      u4.u4_port = i4->sin_port;
      arg = &u4;
      args = sizeof (struct IPv4XuAddress);
      break;
    }
  case AF_INET6:
    {
      const struct sockaddr_in6 *i6;

      GNUNET_assert (sizeof(struct sockaddr_in6) == addrlen);
      i6 = (const struct sockaddr_in6 *) addr;
      if (0 == ntohs (i6->sin6_port))
        return; /* Port = 0 means unmapped, ignore these for XU. */
      memset (&u6,
              0,
              sizeof(u6));
      u6.options = htonl (plugin->myoptions);
      u6.ipv6_addr = i6->sin6_addr;
      u6.u6_port = i6->sin6_port;
      arg = &u6;
      args = sizeof (struct IPv6XuAddress);
      break;
    }
  default:
    GNUNET_break (0);
    return;
  }
  /* modify our published address list */
  /* TODO: use 'ac' here in the future... */
  address = GNUNET_HELLO_address_allocate (plugin->env->my_identity,
                                           PLUGIN_NAME,
                                           arg,
                                           args,
                                           GNUNET_HELLO_ADDRESS_INFO_NONE);
  plugin->env->notify_address (plugin->env->cls,
                               add_remove,
                               address);
  GNUNET_HELLO_address_free (address);
}


/* ********************* Finding sessions ******************* */


/**
 * Closure for #session_cmp_it().
 */
struct GNUNET_ATS_SessionCompareContext
{
  /**
   * Set to session matching the address.
   */
  struct GNUNET_ATS_Session *res;

  /**
   * Address we are looking for.
   */
  const struct GNUNET_HELLO_Address *address;
};


/**
 * Find a session with a matching address.
 *
 * @param cls the `struct GNUNET_ATS_SessionCompareContext *`
 * @param key peer identity (unused)
 * @param value the `struct GNUNET_ATS_Session *`
 * @return #GNUNET_NO if we found the session, #GNUNET_OK if not
 */
static int
session_cmp_it (void *cls,
                const struct GNUNET_PeerIdentity *key,
                void *value)
{
  struct GNUNET_ATS_SessionCompareContext *cctx = cls;
  struct GNUNET_ATS_Session *s = value;

  (void) key;
  if (0 == GNUNET_HELLO_address_cmp (s->address,
                                     cctx->address))
  {
    GNUNET_assert (GNUNET_NO == s->in_destroy);
    cctx->res = s;
    return GNUNET_NO;
  }
  return GNUNET_OK;
}


/**
 * Locate an existing session the transport service is using to
 * send data to another peer.  Performs some basic sanity checks
 * on the address and then tries to locate a matching session.
 *
 * @param cls the plugin
 * @param address the address we should locate the session by
 * @return the session if it exists, or NULL if it is not found
 */
static struct GNUNET_ATS_Session *
xu_plugin_lookup_session (void *cls,
                           const struct GNUNET_HELLO_Address *address)
{
  struct Plugin *plugin = cls;
  const struct IPv6XuAddress *xu_a6;
  const struct IPv4XuAddress *xu_a4;
  struct GNUNET_ATS_SessionCompareContext cctx;

  if (NULL == address->address)
  {
    GNUNET_break (0);
    return NULL;
  }
  if (sizeof(struct IPv4XuAddress) == address->address_length)
  {
    if (NULL == plugin->sockv4)
      return NULL;
    xu_a4 = (const struct IPv4XuAddress *) address->address;
    if (0 == xu_a4->u4_port)
    {
      GNUNET_break (0);
      return NULL;
    }
  }
  else if (sizeof(struct IPv6XuAddress) == address->address_length)
  {
    if (NULL == plugin->sockv6)
      return NULL;
    xu_a6 = (const struct IPv6XuAddress *) address->address;
    if (0 == xu_a6->u6_port)
    {
      GNUNET_break (0);
      return NULL;
    }
  }
  else
  {
    GNUNET_break (0);
    return NULL;
  }

  /* check if session already exists */
  cctx.address = address;
  cctx.res = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Looking for existing session for peer `%s' with address `%s'\n",
       GNUNET_i2s (&address->peer),
       xu_address_to_string (plugin,
                              address->address,
                              address->address_length));
  GNUNET_CONTAINER_multipeermap_get_multiple (plugin->sessions,
                                              &address->peer,
                                              &session_cmp_it,
                                              &cctx);
  if (NULL == cctx.res)
    return NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Found existing session %p\n",
       cctx.res);
  return cctx.res;
}


/* ********************** Timeout ****************** */


/**
 * Increment session timeout due to activity.
 *
 * @param s session to reschedule timeout activity for
 */
static void
reschedule_session_timeout (struct GNUNET_ATS_Session *s)
{
  if (GNUNET_YES == s->in_destroy)
    return;
  GNUNET_assert (NULL != s->timeout_task);
  s->timeout = GNUNET_TIME_relative_to_absolute (XU_SESSION_TIME_OUT);
}



/**
 * Function that will be called whenever the transport service wants to
 * notify the plugin that a session is still active and in use and
 * therefore the session timeout for this session has to be updated
 *
 * @param cls closure with the `struct Plugin`
 * @param peer which peer was the session for
 * @param session which session is being updated
 */
static void
xu_plugin_update_session_timeout (void *cls,
                                   const struct GNUNET_PeerIdentity *peer,
                                   struct GNUNET_ATS_Session *session)
{
  struct Plugin *plugin = cls;

  if (GNUNET_YES !=
      GNUNET_CONTAINER_multipeermap_contains_value (plugin->sessions,
                                                    peer,
                                                    session))
  {
    GNUNET_break (0);
    return;
  }
  /* Reschedule session timeout */
  reschedule_session_timeout (session);
}


/* ************************* Sending ************************ */


/**
 * We failed to transmit a message via XU. Generate
 * a descriptive error message.
 *
 * @param plugin our plugin
 * @param sa target address we were trying to reach
 * @param slen number of bytes in @a sa
 * @param error the errno value returned from the sendto() call
 */
static void
analyze_send_error (struct Plugin *plugin,
                    const struct sockaddr *sa,
                    socklen_t slen,
                    int error)
{
  enum GNUNET_ATS_Network_Type type;

  type = plugin->env->get_address_type (plugin->env->cls,
                                        sa,
                                        slen);
  if ( ( (GNUNET_ATS_NET_LAN == type) ||
         (GNUNET_ATS_NET_WAN == type) ) &&
       ( (ENETUNREACH == errno) ||
         (ENETDOWN == errno) ) )
  {
    if (slen == sizeof (struct sockaddr_in))
    {
      /* IPv4: "Network unreachable" or "Network down"
       *
       * This indicates we do not have connectivity
       */
      LOG (GNUNET_ERROR_TYPE_WARNING | GNUNET_ERROR_TYPE_BULK,
           _("XU could not transmit message to `%s': "
             "Network seems down, please check your network configuration\n"),
           GNUNET_a2s (sa,
                       slen));
    }
    if (slen == sizeof (struct sockaddr_in6))
    {
      /* IPv6: "Network unreachable" or "Network down"
       *
       * This indicates that this system is IPv6 enabled, but does not
       * have a valid global IPv6 address assigned or we do not have
       * connectivity
       */
      LOG (GNUNET_ERROR_TYPE_WARNING | GNUNET_ERROR_TYPE_BULK,
           _("XU could not transmit IPv6 message! "
             "Please check your network configuration and disable IPv6 if your "
             "connection does not have a global IPv6 address\n"));
    }
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "XU could not transmit message to `%s': `%s'\n",
         GNUNET_a2s (sa,
                     slen),
         STRERROR (error));
  }
}




/**
 * Function that can be used by the transport service to transmit a
 * message using the plugin.  Note that in the case of a peer
 * disconnecting, the continuation MUST be called prior to the
 * disconnect notification itself.  This function will be called with
 * this peer's HELLO message to initiate a fresh connection to another
 * peer.
 *
 * @param cls closure
 * @param s which session must be used
 * @param msgbuf the message to transmit
 * @param msgbuf_size number of bytes in @a msgbuf
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
 * @param cont_cls closure for @a cont
 * @return number of bytes used (on the physical network, with overheads);
 *         -1 on hard errors (i.e. address invalid); 0 is a legal value
 *         and does NOT mean that the message was not transmitted (DV)
 */
static ssize_t
xu_plugin_send (void *cls,
		struct GNUNET_ATS_Session *s,
		const char *msgbuf,
		size_t msgbuf_size,
		unsigned int priority,
		struct GNUNET_TIME_Relative to,
		GNUNET_TRANSPORT_TransmitContinuation cont,
		void *cont_cls)
{
  struct Plugin *plugin = cls;
  size_t xumlen = msgbuf_size + sizeof(struct XUMessage);
  struct XUMessage *xu;
  char mbuf[xumlen] GNUNET_ALIGN;
  ssize_t sent;
  socklen_t slen;
  const struct sockaddr *a;
  const struct IPv4XuAddress *u4;
  struct sockaddr_in a4;
  const struct IPv6XuAddress *u6;
  struct sockaddr_in6 a6;
  struct GNUNET_NETWORK_Handle *sock;

  (void) priority;
  (void) to;
  if ( (sizeof(struct IPv6XuAddress) == s->address->address_length) &&
       (NULL == plugin->sockv6) )
    return GNUNET_SYSERR;
  if ( (sizeof(struct IPv4XuAddress) == s->address->address_length) &&
       (NULL == plugin->sockv4) )
    return GNUNET_SYSERR;
  if (xumlen >= GNUNET_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (GNUNET_YES !=
      GNUNET_CONTAINER_multipeermap_contains_value (plugin->sessions,
                                                    &s->target,
                                                    s))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "XU transmits %u-byte message to `%s' using address `%s'\n",
       xumlen,
       GNUNET_i2s (&s->target),
       xu_address_to_string (plugin,
                              s->address->address,
                              s->address->address_length));
  xu = (struct XUMessage *) mbuf;
  xu->header.size = htons (xumlen);
  xu->header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_XU_MESSAGE);
  xu->reserved = htonl (0);
  xu->sender = *plugin->env->my_identity;
  GNUNET_memcpy (&xu[1],
		 msgbuf,
		 msgbuf_size);
  
  if (sizeof (struct IPv4XuAddress) == s->address->address_length)
  {
    u4 = s->address->address;
    memset (&a4,
	    0,
	    sizeof(a4));
    a4.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
    a4.sin_len = sizeof (a4);
#endif
    a4.sin_port = u4->u4_port;
    a4.sin_addr.s_addr = u4->ipv4_addr;
    a = (const struct sockaddr *) &a4;
    slen = sizeof (a4);
    sock = plugin->sockv4;
  }
  else if (sizeof (struct IPv6XuAddress) == s->address->address_length)
  {
    u6 = s->address->address;
    memset (&a6,
	    0,
	    sizeof(a6));
    a6.sin6_family = AF_INET6;
#if HAVE_SOCKADDR_IN_SIN_LEN
    a6.sin6_len = sizeof (a6);
#endif
    a6.sin6_port = u6->u6_port;
    a6.sin6_addr = u6->ipv6_addr;
    a = (const struct sockaddr *) &a6;
    slen = sizeof (a6);
    sock = plugin->sockv6;
  }
  else
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
    
  sent = GNUNET_NETWORK_socket_sendto (sock,
				       mbuf,
				       xumlen,
				       a,
				       slen);
  s->last_transmit_time
    = GNUNET_TIME_absolute_max (GNUNET_TIME_absolute_get (),
				s->last_transmit_time);
  
  if (GNUNET_SYSERR == sent)
  {
    /* Failure */
    analyze_send_error (plugin,
			a,
			slen,
			errno);
    GNUNET_STATISTICS_update (plugin->env->stats,
			      "# XU, total, bytes, sent, failure",
			      sent,
			      GNUNET_NO);
    GNUNET_STATISTICS_update (plugin->env->stats,
			      "# XU, total, messages, sent, failure",
			      1,
			      GNUNET_NO);
    return GNUNET_SYSERR;
  }
  /* Success */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "XU transmitted %u-byte message to  `%s' `%s' (%d: %s)\n",
       (unsigned int) (msgbuf_size),
       GNUNET_i2s (&s->target),
       GNUNET_a2s (a,
		   slen),
       (int ) sent,
       (sent < 0) ? STRERROR (errno) : "ok");
  GNUNET_STATISTICS_update (plugin->env->stats,
			    "# XU, total, bytes, sent, success",
			    sent,
			    GNUNET_NO);
  GNUNET_STATISTICS_update (plugin->env->stats,
			    "# XU, total, messages, sent, success",
			    1,
			    GNUNET_NO);
  cont (cont_cls,
	&s->target,
	GNUNET_OK,
	msgbuf_size,
	xumlen);
  notify_session_monitor (s->plugin,
                          s,
                          GNUNET_TRANSPORT_SS_UPDATE);
  return xumlen;
}


/* ********************** Receiving ********************** */


/**
 * Functions with this signature are called whenever we need to close
 * a session due to a disconnect or failure to establish a connection.
 *
 * @param cls closure with the `struct Plugin`
 * @param s session to close down
 * @return #GNUNET_OK on success
 */
static int
xu_disconnect_session (void *cls,
                        struct GNUNET_ATS_Session *s)
{
  struct Plugin *plugin = cls;

  GNUNET_assert (GNUNET_YES != s->in_destroy);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Session %p to peer `%s' at address %s ended\n",
       s,
       GNUNET_i2s (&s->target),
       xu_address_to_string (plugin,
                              s->address->address,
                              s->address->address_length));
  if (NULL != s->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (s->timeout_task);
    s->timeout_task = NULL;
  }
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (plugin->sessions,
                                                       &s->target,
                                                       s));
  s->in_destroy = GNUNET_YES;
  notify_session_monitor (s->plugin,
                          s,
                          GNUNET_TRANSPORT_SS_DONE);
  plugin->env->session_end (plugin->env->cls,
                            s->address,
                            s);
  GNUNET_STATISTICS_set (plugin->env->stats,
                         "# XU sessions active",
                         GNUNET_CONTAINER_multipeermap_size (plugin->sessions),
                         GNUNET_NO);
  if (0 == s->rc)
    free_session (s);
  return GNUNET_OK;
}


/**
 * Message tokenizer has broken up an incomming message. Pass it on
 * to the service.
 *
 * @param cls the `struct GNUNET_ATS_Session *`
 * @param hdr the actual message
 * @return #GNUNET_OK (always)
 */
static int
process_inbound_tokenized_messages (void *cls,
                                    const struct GNUNET_MessageHeader *hdr)
{
  struct GNUNET_ATS_Session *session = cls;
  struct Plugin *plugin = session->plugin;

  if (GNUNET_YES == session->in_destroy)
    return GNUNET_OK;
  reschedule_session_timeout (session);
  session->flow_delay_for_other_peer
    = plugin->env->receive (plugin->env->cls,
                            session->address,
                            session,
                            hdr);
  return GNUNET_OK;
}


/**
 * Destroy a session, plugin is being unloaded.
 *
 * @param cls the `struct Plugin`
 * @param key hash of public key of target peer
 * @param value a `struct PeerSession *` to clean up
 * @return #GNUNET_OK (continue to iterate)
 */
static int
disconnect_and_free_it (void *cls,
                        const struct GNUNET_PeerIdentity *key,
                        void *value)
{
  struct Plugin *plugin = cls;

  (void) key;
  xu_disconnect_session (plugin,
			 value);
  return GNUNET_OK;
}


/**
 * Disconnect from a remote node.  Clean up session if we have one for
 * this peer.
 *
 * @param cls closure for this call (should be handle to Plugin)
 * @param target the peeridentity of the peer to disconnect
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the operation failed
 */
static void
xu_disconnect (void *cls,
                const struct GNUNET_PeerIdentity *target)
{
  struct Plugin *plugin = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Disconnecting from peer `%s'\n",
       GNUNET_i2s (target));
  GNUNET_CONTAINER_multipeermap_get_multiple (plugin->sessions,
                                              target,
                                              &disconnect_and_free_it,
                                              plugin);
}


/**
 * Session was idle, so disconnect it.
 *
 * @param cls the `struct GNUNET_ATS_Session` to time out
 */
static void
session_timeout (void *cls)
{
  struct GNUNET_ATS_Session *s = cls;
  struct Plugin *plugin = s->plugin;
  struct GNUNET_TIME_Relative left;

  s->timeout_task = NULL;
  left = GNUNET_TIME_absolute_get_remaining (s->timeout);
  if (left.rel_value_us > 0)
  {
    /* not actually our turn yet, but let's at least update
       the monitor, it may think we're about to die ... */
    notify_session_monitor (s->plugin,
                            s,
                            GNUNET_TRANSPORT_SS_UPDATE);
    s->timeout_task = GNUNET_SCHEDULER_add_delayed (left,
                                                    &session_timeout,
                                                    s);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Session %p was idle for %s, disconnecting\n",
       s,
       GNUNET_STRINGS_relative_time_to_string (XU_SESSION_TIME_OUT,
                                               GNUNET_YES));
  /* call session destroy function */
  xu_disconnect_session (plugin,
                          s);
}


/**
 * Allocate a new session for the given endpoint address.
 * Note that this function does not inform the service
 * of the new session, this is the responsibility of the
 * caller (if needed).
 *
 * @param cls the `struct Plugin`
 * @param address address of the other peer to use
 * @param network_type network type the address belongs to
 * @return NULL on error, otherwise session handle
 */
static struct GNUNET_ATS_Session *
xu_plugin_create_session (void *cls,
                           const struct GNUNET_HELLO_Address *address,
                           enum GNUNET_ATS_Network_Type network_type)
{
  struct Plugin *plugin = cls;
  struct GNUNET_ATS_Session *s;

  s = GNUNET_new (struct GNUNET_ATS_Session);
  s->mst = GNUNET_MST_create (&process_inbound_tokenized_messages,
                              s);
  s->plugin = plugin;
  s->address = GNUNET_HELLO_address_copy (address);
  s->target = address->peer;
  s->last_transmit_time = GNUNET_TIME_absolute_get ();
  s->last_expected_ack_delay = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS,
                                                              250);
  s->last_expected_msg_delay = GNUNET_TIME_UNIT_MILLISECONDS;
  s->flow_delay_from_other_peer = GNUNET_TIME_UNIT_ZERO;
  s->flow_delay_for_other_peer = GNUNET_TIME_UNIT_ZERO;
  s->timeout = GNUNET_TIME_relative_to_absolute (XU_SESSION_TIME_OUT);
  s->timeout_task = GNUNET_SCHEDULER_add_delayed (XU_SESSION_TIME_OUT,
                                                  &session_timeout,
                                                  s);
  s->scope = network_type;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Creating new session %p for peer `%s' address `%s'\n",
       s,
       GNUNET_i2s (&address->peer),
       xu_address_to_string (plugin,
                              address->address,
                              address->address_length));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multipeermap_put (plugin->sessions,
                                                    &s->target,
                                                    s,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
  GNUNET_STATISTICS_set (plugin->env->stats,
                         "# XU sessions active",
                         GNUNET_CONTAINER_multipeermap_size (plugin->sessions),
                         GNUNET_NO);
  notify_session_monitor (plugin,
                          s,
                          GNUNET_TRANSPORT_SS_INIT);
  return s;
}


/**
 * Creates a new outbound session the transport service will use to
 * send data to the peer.
 *
 * @param cls the `struct Plugin *`
 * @param address the address
 * @return the session or NULL of max connections exceeded
 */
static struct GNUNET_ATS_Session *
xu_plugin_get_session (void *cls,
                        const struct GNUNET_HELLO_Address *address)
{
  struct Plugin *plugin = cls;
  struct GNUNET_ATS_Session *s;
  enum GNUNET_ATS_Network_Type network_type = GNUNET_ATS_NET_UNSPECIFIED;
  const struct IPv4XuAddress *xu_v4;
  const struct IPv6XuAddress *xu_v6;

  if (NULL == address)
  {
    GNUNET_break (0);
    return NULL;
  }
  if ( (address->address_length != sizeof(struct IPv4XuAddress)) &&
       (address->address_length != sizeof(struct IPv6XuAddress)) )
  {
    GNUNET_break_op (0);
    return NULL;
  }
  if (NULL != (s = xu_plugin_lookup_session (cls,
                                              address)))
    return s;

  /* need to create new session */
  if (sizeof (struct IPv4XuAddress) == address->address_length)
  {
    struct sockaddr_in v4;

    xu_v4 = (const struct IPv4XuAddress *) address->address;
    memset (&v4, '\0', sizeof (v4));
    v4.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
    v4.sin_len = sizeof (struct sockaddr_in);
#endif
    v4.sin_port = xu_v4->u4_port;
    v4.sin_addr.s_addr = xu_v4->ipv4_addr;
    network_type = plugin->env->get_address_type (plugin->env->cls,
                                                  (const struct sockaddr *) &v4,
                                                  sizeof (v4));
  }
  if (sizeof (struct IPv6XuAddress) == address->address_length)
  {
    struct sockaddr_in6 v6;

    xu_v6 = (const struct IPv6XuAddress *) address->address;
    memset (&v6, '\0', sizeof (v6));
    v6.sin6_family = AF_INET6;
#if HAVE_SOCKADDR_IN_SIN_LEN
    v6.sin6_len = sizeof (struct sockaddr_in6);
#endif
    v6.sin6_port = xu_v6->u6_port;
    v6.sin6_addr = xu_v6->ipv6_addr;
    network_type = plugin->env->get_address_type (plugin->env->cls,
                                                  (const struct sockaddr *) &v6,
                                                  sizeof (v6));
  }
  GNUNET_break (GNUNET_ATS_NET_UNSPECIFIED != network_type);
  return xu_plugin_create_session (cls,
				    address,
				    network_type);
}


/**
 * We've received a XU Message.  Process it (pass contents to main service).
 *
 * @param plugin plugin context
 * @param msg the message
 * @param xu_addr sender address
 * @param xu_addr_len number of bytes in @a xu_addr
 * @param network_type network type the address belongs to
 */
static void
process_xu_message (struct Plugin *plugin,
                     const struct XUMessage *msg,
                     const union XuAddress *xu_addr,
                     size_t xu_addr_len,
                     enum GNUNET_ATS_Network_Type network_type)
{
  struct GNUNET_ATS_Session *s;
  struct GNUNET_HELLO_Address *address;

  GNUNET_break (GNUNET_ATS_NET_UNSPECIFIED != network_type);
  if (0 != ntohl (msg->reserved))
  {
    GNUNET_break_op(0);
    return;
  }
  if (ntohs (msg->header.size)
      < sizeof(struct GNUNET_MessageHeader) + sizeof(struct XUMessage))
  {
    GNUNET_break_op(0);
    return;
  }

  address = GNUNET_HELLO_address_allocate (&msg->sender,
                                           PLUGIN_NAME,
                                           xu_addr,
                                           xu_addr_len,
                                           GNUNET_HELLO_ADDRESS_INFO_NONE);
  if (NULL ==
      (s = xu_plugin_lookup_session (plugin,
                                      address)))
  {
    s = xu_plugin_create_session (plugin,
                                   address,
                                   network_type);
    plugin->env->session_start (plugin->env->cls,
                                address,
                                s,
                                s->scope);
    notify_session_monitor (plugin,
                            s,
                            GNUNET_TRANSPORT_SS_UP);
  }
  GNUNET_free (address);

  s->rc++;
  GNUNET_MST_from_buffer (s->mst,
                          (const char *) &msg[1],
                          ntohs (msg->header.size) - sizeof(struct XUMessage),
                          GNUNET_YES,
                          GNUNET_NO);
  s->rc--;
  if ( (0 == s->rc) &&
       (GNUNET_YES == s->in_destroy) )
    free_session (s);
}


/**
 * Read and process a message from the given socket.
 *
 * @param plugin the overall plugin
 * @param rsock socket to read from
 */
static void
xu_select_read (struct Plugin *plugin,
                 struct GNUNET_NETWORK_Handle *rsock)
{
  socklen_t fromlen;
  struct sockaddr_storage addr;
  char buf[65536] GNUNET_ALIGN;
  ssize_t size;
  const struct GNUNET_MessageHeader *msg;
  struct IPv4XuAddress v4;
  struct IPv6XuAddress v6;
  const struct sockaddr *sa;
  const struct sockaddr_in *sa4;
  const struct sockaddr_in6 *sa6;
  const union XuAddress *int_addr;
  size_t int_addr_len;
  enum GNUNET_ATS_Network_Type network_type;

  fromlen = sizeof (addr);
  memset (&addr,
          0,
          sizeof(addr));
  size = GNUNET_NETWORK_socket_recvfrom (rsock,
                                         buf,
                                         sizeof (buf),
                                         (struct sockaddr *) &addr,
                                         &fromlen);
  sa = (const struct sockaddr *) &addr;
#if MINGW
  /* On SOCK_DGRAM XU sockets recvfrom might fail with a
   * WSAECONNRESET error to indicate that previous sendto() (yes, sendto!)
   * on this socket has failed.
   * Quote from MSDN:
   *   WSAECONNRESET - The virtual circuit was reset by the remote side
   *   executing a hard or abortive close. The application should close
   *   the socket; it is no longer usable. On a XU-datagram socket this
   *   error indicates a previous send operation resulted in an ICMP Port
   *   Unreachable message.
   */
  if ( (-1 == size) &&
       (ECONNRESET == errno) )
    return;
#endif
  if (-1 == size)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "XU failed to receive data: %s\n",
         STRERROR (errno));
    /* Connection failure or something. Not a protocol violation. */
    return;
  }

  /* Check if this is a STUN packet */
  if (GNUNET_NO !=
      GNUNET_NAT_stun_handle_packet (plugin->nat,
				     (const struct sockaddr *) &addr,
				     fromlen,
				     buf,
				     size))
    return; /* was STUN, do not process further */

  if (((size_t) size) < sizeof(struct GNUNET_MessageHeader))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "XU got %u bytes from %s, which is not enough for a GNUnet message header\n",
         (unsigned int ) size,
         GNUNET_a2s (sa,
                     fromlen));
    /* _MAY_ be a connection failure (got partial message) */
    /* But it _MAY_ also be that the other side uses non-GNUnet protocol. */
    GNUNET_break_op (0);
    return;
  }

  msg = (const struct GNUNET_MessageHeader *) buf;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "XU received %u-byte message from `%s' type %u\n",
       (unsigned int) size,
       GNUNET_a2s (sa,
                   fromlen),
       ntohs (msg->type));
  if (size != ntohs (msg->size))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "XU malformed message (size %u) header from %s\n",
         (unsigned int) size,
         GNUNET_a2s (sa,
                     fromlen));
    GNUNET_break_op (0);
    return;
  }
  GNUNET_STATISTICS_update (plugin->env->stats,
                            "# XU, total bytes received",
                            size,
                            GNUNET_NO);
  network_type = plugin->env->get_address_type (plugin->env->cls,
                                                sa,
                                                fromlen);
  switch (sa->sa_family)
  {
  case AF_INET:
    sa4 = (const struct sockaddr_in *) &addr;
    v4.options = 0;
    v4.ipv4_addr = sa4->sin_addr.s_addr;
    v4.u4_port = sa4->sin_port;
    int_addr = (union XuAddress *) &v4;
    int_addr_len = sizeof (v4);
    break;
  case AF_INET6:
    sa6 = (const struct sockaddr_in6 *) &addr;
    v6.options = 0;
    v6.ipv6_addr = sa6->sin6_addr;
    v6.u6_port = sa6->sin6_port;
    int_addr = (union XuAddress *) &v6;
    int_addr_len = sizeof (v6);
    break;
  default:
    GNUNET_break (0);
    return;
  }

  switch (ntohs (msg->type))
  {
  case GNUNET_MESSAGE_TYPE_TRANSPORT_XU_MESSAGE:
    if (ntohs (msg->size) < sizeof(struct XUMessage))
    {
      GNUNET_break_op(0);
      return;
    }
    process_xu_message (plugin,
                         (const struct XUMessage *) msg,
                         int_addr,
                         int_addr_len,
                         network_type);
    return;
  default:
    GNUNET_break_op(0);
    return;
  }
}


/* ***************** Event loop (part 2) *************** */


/**
 * We have been notified that our readset has something to read.  We don't
 * know which socket needs to be read, so we have to check each one
 * Then reschedule this function to be called again once more is available.
 *
 * @param cls the plugin handle
 */
static void
xu_plugin_select_v4 (void *cls)
{
  struct Plugin *plugin = cls;
  const struct GNUNET_SCHEDULER_TaskContext *tc;

  plugin->select_task_v4 = NULL;
  if (NULL == plugin->sockv4)
    return;
  tc = GNUNET_SCHEDULER_get_task_context ();
  if ( (0 != (tc->reason & GNUNET_SCHEDULER_REASON_READ_READY)) &&
       (GNUNET_NETWORK_fdset_isset (tc->read_ready,
				    plugin->sockv4)) )
    xu_select_read (plugin,
                     plugin->sockv4);
  schedule_select_v4 (plugin);
}


/**
 * We have been notified that our readset has something to read.  We don't
 * know which socket needs to be read, so we have to check each one
 * Then reschedule this function to be called again once more is available.
 *
 * @param cls the plugin handle
 */
static void
xu_plugin_select_v6 (void *cls)
{
  struct Plugin *plugin = cls;
  const struct GNUNET_SCHEDULER_TaskContext *tc;

  plugin->select_task_v6 = NULL;
  if (NULL == plugin->sockv6)
    return;
  tc = GNUNET_SCHEDULER_get_task_context ();
  if ( (0 != (tc->reason & GNUNET_SCHEDULER_REASON_READ_READY)) &&
       (GNUNET_NETWORK_fdset_isset (tc->read_ready,
                                    plugin->sockv6)) )
    xu_select_read (plugin,
                     plugin->sockv6);
  schedule_select_v6 (plugin);
}


/* ******************* Initialization *************** */


/**
 * Setup the XU sockets (for IPv4 and IPv6) for the plugin.
 *
 * @param plugin the plugin to initialize
 * @param bind_v6 IPv6 address to bind to (can be NULL, for 'any')
 * @param bind_v4 IPv4 address to bind to (can be NULL, for 'any')
 * @return number of sockets that were successfully bound
 */
static unsigned int
setup_sockets (struct Plugin *plugin,
               const struct sockaddr_in6 *bind_v6,
               const struct sockaddr_in *bind_v4)
{
  int tries;
  unsigned int sockets_created = 0;
  struct sockaddr_in6 server_addrv6;
  struct sockaddr_in server_addrv4;
  const struct sockaddr *server_addr;
  const struct sockaddr *addrs[2];
  socklen_t addrlens[2];
  socklen_t addrlen;
  int eno;

  /* Create IPv6 socket */
  eno = EINVAL;
  if (GNUNET_YES == plugin->enable_ipv6)
  {
    plugin->sockv6 = GNUNET_NETWORK_socket_create (PF_INET6,
                                                   SOCK_DGRAM,
                                                   0);
    if (NULL == plugin->sockv6)
    {
      LOG (GNUNET_ERROR_TYPE_INFO,
           _("Disabling IPv6 since it is not supported on this system!\n"));
      plugin->enable_ipv6 = GNUNET_NO;
    }
    else
    {
      memset (&server_addrv6,
              0,
              sizeof(struct sockaddr_in6));
#if HAVE_SOCKADDR_IN_SIN_LEN
      server_addrv6.sin6_len = sizeof (struct sockaddr_in6);
#endif
      server_addrv6.sin6_family = AF_INET6;
      if (NULL != bind_v6)
        server_addrv6.sin6_addr = bind_v6->sin6_addr;
      else
        server_addrv6.sin6_addr = in6addr_any;

      if (0 == plugin->port) /* autodetect */
        server_addrv6.sin6_port
          = htons (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_STRONG,
                                             33537)
                   + 32000);
      else
        server_addrv6.sin6_port = htons (plugin->port);
      addrlen = sizeof (struct sockaddr_in6);
      server_addr = (const struct sockaddr *) &server_addrv6;

      tries = 0;
      while (tries < 10)
      {
        LOG(GNUNET_ERROR_TYPE_DEBUG,
            "Binding to IPv6 `%s'\n",
            GNUNET_a2s (server_addr,
                        addrlen));
        /* binding */
        if (GNUNET_OK ==
            GNUNET_NETWORK_socket_bind (plugin->sockv6,
                                        server_addr,
                                        addrlen))
          break;
        eno = errno;
        if (0 != plugin->port)
        {
          tries = 10; /* fail immediately */
          break; /* bind failed on specific port */
        }
        /* autodetect */
        server_addrv6.sin6_port
          = htons (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_STRONG,
                                             33537)
                   + 32000);
        tries++;
      }
      if (tries >= 10)
      {
        GNUNET_NETWORK_socket_close (plugin->sockv6);
        plugin->enable_ipv6 = GNUNET_NO;
        plugin->sockv6 = NULL;
      }
      else
      {
        plugin->port = ntohs (server_addrv6.sin6_port);
      }
      if (NULL != plugin->sockv6)
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "IPv6 XU socket created listinging at %s\n",
             GNUNET_a2s (server_addr,
                         addrlen));
        addrs[sockets_created] = server_addr;
        addrlens[sockets_created] = addrlen;
        sockets_created++;
      }
      else
      {
        LOG (GNUNET_ERROR_TYPE_WARNING,
             _("Failed to bind XU socket to %s: %s\n"),
             GNUNET_a2s (server_addr,
                         addrlen),
             STRERROR (eno));
      }
    }
  }

  /* Create IPv4 socket */
  eno = EINVAL;
  plugin->sockv4 = GNUNET_NETWORK_socket_create (PF_INET,
                                                 SOCK_DGRAM,
                                                 0);
  if (NULL == plugin->sockv4)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
                         "socket");
    LOG (GNUNET_ERROR_TYPE_INFO,
         _("Disabling IPv4 since it is not supported on this system!\n"));
    plugin->enable_ipv4 = GNUNET_NO;
  }
  else
  {
    memset (&server_addrv4,
            0,
            sizeof(struct sockaddr_in));
#if HAVE_SOCKADDR_IN_SIN_LEN
    server_addrv4.sin_len = sizeof (struct sockaddr_in);
#endif
    server_addrv4.sin_family = AF_INET;
    if (NULL != bind_v4)
      server_addrv4.sin_addr = bind_v4->sin_addr;
    else
      server_addrv4.sin_addr.s_addr = INADDR_ANY;

    if (0 == plugin->port)
      /* autodetect */
      server_addrv4.sin_port
        = htons (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_STRONG,
                                           33537)
                 + 32000);
    else
      server_addrv4.sin_port = htons (plugin->port);

    addrlen = sizeof (struct sockaddr_in);
    server_addr = (const struct sockaddr *) &server_addrv4;

    tries = 0;
    while (tries < 10)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Binding to IPv4 `%s'\n",
           GNUNET_a2s (server_addr,
                       addrlen));

      /* binding */
      if (GNUNET_OK ==
          GNUNET_NETWORK_socket_bind (plugin->sockv4,
                                      server_addr,
                                      addrlen))
        break;
      eno = errno;
      if (0 != plugin->port)
      {
        tries = 10; /* fail */
        break; /* bind failed on specific port */
      }

      /* autodetect */
      server_addrv4.sin_port
        = htons (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_STRONG,
                                           33537)
                 + 32000);
      tries++;
    }
    if (tries >= 10)
    {
      GNUNET_NETWORK_socket_close (plugin->sockv4);
      plugin->enable_ipv4 = GNUNET_NO;
      plugin->sockv4 = NULL;
    }
    else
    {
      plugin->port = ntohs (server_addrv4.sin_port);
    }

    if (NULL != plugin->sockv4)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "IPv4 socket created on port %s\n",
           GNUNET_a2s (server_addr,
                       addrlen));
      addrs[sockets_created] = server_addr;
      addrlens[sockets_created] = addrlen;
      sockets_created++;
    }
    else
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _("Failed to bind XU socket to %s: %s\n"),
           GNUNET_a2s (server_addr,
                       addrlen),
           STRERROR (eno));
    }
  }

  if (0 == sockets_created)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("Failed to open XU sockets\n"));
    return 0; /* No sockets created, return */
  }
  schedule_select_v4 (plugin);
  schedule_select_v6 (plugin);
  plugin->nat = GNUNET_NAT_register (plugin->env->cfg,
				     "transport-xu",
				     IPPROTO_UDP,
                                     sockets_created,
                                     addrs,
                                     addrlens,
                                     &xu_nat_port_map_callback,
                                     NULL,
                                     plugin);
  return sockets_created;
}


/**
 * The exported method. Makes the core api available via a global and
 * returns the xu transport API.
 *
 * @param cls our `struct GNUNET_TRANSPORT_PluginEnvironment`
 * @return our `struct GNUNET_TRANSPORT_PluginFunctions`
 */
void *
libgnunet_plugin_transport_xu_init (void *cls)
{
  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  struct Plugin *p;
  unsigned long long port;
  unsigned long long aport;
  int enable_v6;
  char *bind4_address;
  char *bind6_address;
  struct sockaddr_in server_addrv4;
  struct sockaddr_in6 server_addrv6;
  unsigned int res;
  int have_bind4;
  int have_bind6;

  if (NULL == env->receive)
  {
    /* run in 'stub' mode (i.e. as part of gnunet-peerinfo), don't fully
     initialze the plugin or the API */
    api = GNUNET_new (struct GNUNET_TRANSPORT_PluginFunctions);
    api->cls = NULL;
    api->address_pretty_printer = &xu_plugin_address_pretty_printer;
    api->address_to_string = &xu_address_to_string;
    api->string_to_address = &xu_string_to_address;
    return api;
  }

  /* Get port number: port == 0 : autodetect a port,
   * > 0 : use this port, not given : 2086 default */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (env->cfg,
                                             "transport-xu",
                                             "PORT",
                                             &port))
    port = 2086;
  if (port > 65535)
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                               "transport-xu",
                               "PORT",
                               _("must be in [0,65535]"));
    return NULL;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (env->cfg,
                                             "transport-xu",
                                             "ADVERTISED_PORT",
                                             &aport))
    aport = port;
  if (aport > 65535)
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                               "transport-xu",
                               "ADVERTISED_PORT",
                               _("must be in [0,65535]"));
    return NULL;
  }

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
                                            "nat",
                                            "DISABLEV6"))
    enable_v6 = GNUNET_NO;
  else
    enable_v6 = GNUNET_YES;

  have_bind4 = GNUNET_NO;
  memset (&server_addrv4,
          0,
          sizeof (server_addrv4));
  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_string (env->cfg,
                                             "transport-xu",
                                             "BINDTO",
                                             &bind4_address))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Binding XU plugin to specific address: `%s'\n",
         bind4_address);
    if (1 != inet_pton (AF_INET,
                        bind4_address,
                        &server_addrv4.sin_addr))
    {
      GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                                 "transport-xu",
                                 "BINDTO",
                                 _("must be valid IPv4 address"));
      GNUNET_free (bind4_address);
      return NULL;
    }
    have_bind4 = GNUNET_YES;
  }
  GNUNET_free_non_null (bind4_address);
  have_bind6 = GNUNET_NO;
  memset (&server_addrv6,
          0,
          sizeof (server_addrv6));
  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_string (env->cfg,
                                             "transport-xu",
                                             "BINDTO6",
                                             &bind6_address))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Binding xu plugin to specific address: `%s'\n",
         bind6_address);
    if (1 != inet_pton (AF_INET6,
                        bind6_address,
                        &server_addrv6.sin6_addr))
    {
      GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                                 "transport-xu",
                                 "BINDTO6",
                                 _("must be valid IPv6 address"));
      GNUNET_free (bind6_address);
      return NULL;
    }
    have_bind6 = GNUNET_YES;
  }
  GNUNET_free_non_null (bind6_address);

  p = GNUNET_new (struct Plugin);
  p->port = port;
  p->aport = aport;
  p->enable_ipv6 = enable_v6;
  p->enable_ipv4 = GNUNET_YES; /* default */
  p->env = env;
  p->sessions = GNUNET_CONTAINER_multipeermap_create (16,
                                                      GNUNET_NO);
  res = setup_sockets (p,
                       (GNUNET_YES == have_bind6) ? &server_addrv6 : NULL,
                       (GNUNET_YES == have_bind4) ? &server_addrv4 : NULL);
  if ( (0 == res) ||
       ( (NULL == p->sockv4) &&
         (NULL == p->sockv6) ) )
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
        _("Failed to create XU network sockets\n"));
    GNUNET_CONTAINER_multipeermap_destroy (p->sessions);
    if (NULL != p->nat)
      GNUNET_NAT_unregister (p->nat);
    GNUNET_free (p);
    return NULL;
  }

  api = GNUNET_new (struct GNUNET_TRANSPORT_PluginFunctions);
  api->cls = p;
  api->disconnect_session = &xu_disconnect_session;
  api->query_keepalive_factor = &xu_query_keepalive_factor;
  api->disconnect_peer = &xu_disconnect;
  api->address_pretty_printer = &xu_plugin_address_pretty_printer;
  api->address_to_string = &xu_address_to_string;
  api->string_to_address = &xu_string_to_address;
  api->check_address = &xu_plugin_check_address;
  api->get_session = &xu_plugin_get_session;
  api->send = &xu_plugin_send;
  api->get_network = &xu_plugin_get_network;
  api->get_network_for_address = &xu_plugin_get_network_for_address;
  api->update_session_timeout = &xu_plugin_update_session_timeout;
  api->setup_monitor = &xu_plugin_setup_monitor;
  return api;
}


/**
 * The exported method. Makes the core api available via a global and
 * returns the xu transport API.
 *
 * @param cls our `struct GNUNET_TRANSPORT_PluginEnvironment`
 * @return NULL
 */
void *
libgnunet_plugin_transport_xu_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;
  struct PrettyPrinterContext *cur;

  if (NULL == plugin)
  {
    GNUNET_free (api);
    return NULL;
  }
  if (NULL != plugin->select_task_v4)
  {
    GNUNET_SCHEDULER_cancel (plugin->select_task_v4);
    plugin->select_task_v4 = NULL;
  }
  if (NULL != plugin->select_task_v6)
  {
    GNUNET_SCHEDULER_cancel (plugin->select_task_v6);
    plugin->select_task_v6 = NULL;
  }
  if (NULL != plugin->sockv4)
  {
    GNUNET_break (GNUNET_OK ==
                  GNUNET_NETWORK_socket_close (plugin->sockv4));
    plugin->sockv4 = NULL;
  }
  if (NULL != plugin->sockv6)
  {
    GNUNET_break (GNUNET_OK ==
                  GNUNET_NETWORK_socket_close (plugin->sockv6));
    plugin->sockv6 = NULL;
  }
  if (NULL != plugin->nat)
  {
    GNUNET_NAT_unregister (plugin->nat);
    plugin->nat = NULL;
  }
  GNUNET_CONTAINER_multipeermap_destroy (plugin->sessions);

  while (NULL != (cur = plugin->ppc_dll_head))
  {
    GNUNET_break (0);
    GNUNET_CONTAINER_DLL_remove (plugin->ppc_dll_head,
                                 plugin->ppc_dll_tail,
                                 cur);
    GNUNET_RESOLVER_request_cancel (cur->resolver_handle);
    if (NULL != cur->timeout_task)
    {
      GNUNET_SCHEDULER_cancel (cur->timeout_task);
      cur->timeout_task = NULL;
    }
    GNUNET_free (cur);
  }
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}

/* end of plugin_transport_xu.c */
