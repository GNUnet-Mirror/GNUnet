/*
     This file is part of GNUnet
     (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file transport/plugin_transport_http.c
 * @brief http transport service plugin
 * @author Matthias Wachs
 */

#include "plugin_transport_http.h"

/**
 * After how long do we expire an address that we
 * learned from another peer if it is not reconfirmed
 * by anyone?
 */
#define LEARNED_ADDRESS_EXPIRATION GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 6)

/**
 * Network format for IPv4 addresses.
 */
struct IPv4HttpAddress
{
  /**
   * IPv4 address, in network byte order.
   */
  uint32_t ipv4_addr GNUNET_PACKED;

  /**
   * Port number, in network byte order.
   */
  uint16_t port GNUNET_PACKED;
};

/**
 * Wrapper to manage IPv4 addresses
 */
struct IPv4HttpAddressWrapper
{
  /**
   * Linked list next
   */
  struct IPv4HttpAddressWrapper *next;

  /**
   * Linked list previous
   */
  struct IPv4HttpAddressWrapper *prev;

  struct IPv4HttpAddress *addr;
};

/**
 * Network format for IPv6 addresses.
 */
struct IPv6HttpAddress
{
  /**
   * IPv6 address.
   */
  struct in6_addr ipv6_addr GNUNET_PACKED;

  /**
   * Port number, in network byte order.
   */
  uint16_t port GNUNET_PACKED;

};

/**
 * Wrapper for IPv4 addresses.
 */
struct IPv6HttpAddressWrapper
{
  /**
   * Linked list next
   */
  struct IPv6HttpAddressWrapper *next;

  /**
   * Linked list previous
   */
  struct IPv6HttpAddressWrapper *prev;

  struct IPv6HttpAddress *addr;
};


/**
 * Context for address to string conversion.
 */
struct PrettyPrinterContext
{
  /**
   * Function to call with the result.
   */
  GNUNET_TRANSPORT_AddressStringCallback asc;

  /**
   * Plugin
   */
  struct Plugin *plugin;

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
 * Encapsulation of all of the state of the plugin.
 */
struct Plugin;



/**
 * Append our port and forward the result.
 *
 * @param cls the 'struct PrettyPrinterContext*'
 * @param hostname hostname part of the address
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
  GNUNET_asprintf (&ret, "%s://%s:%d", ppc->plugin->protocol, hostname,
                   ppc->plugin->port);
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
http_plugin_address_pretty_printer (void *cls, const char *type,
                                    const void *addr, size_t addrlen,
                                    int numeric,
                                    struct GNUNET_TIME_Relative timeout,
                                    GNUNET_TRANSPORT_AddressStringCallback asc,
                                    void *asc_cls)
{
  GNUNET_assert (cls != NULL);
  struct PrettyPrinterContext *ppc;
  const void *sb;
  size_t sbs;
  struct sockaddr_in a4;
  struct sockaddr_in6 a6;
  const struct IPv4HttpAddress *t4;
  const struct IPv6HttpAddress *t6;
  uint16_t port;

  if (addrlen == sizeof (struct IPv6HttpAddress))
  {
    t6 = addr;
    memset (&a6, 0, sizeof (a6));
    a6.sin6_family = AF_INET6;
    a6.sin6_port = t6->port;
    memcpy (&a6.sin6_addr, &t6->ipv6_addr, sizeof (struct in6_addr));
    port = ntohs (t6->port);
    sb = &a6;
    sbs = sizeof (a6);
  }
  else if (addrlen == sizeof (struct IPv4HttpAddress))
  {
    t4 = addr;
    memset (&a4, 0, sizeof (a4));
    a4.sin_family = AF_INET;
    a4.sin_port = t4->port;
    a4.sin_addr.s_addr = t4->ipv4_addr;
    port = ntohs (t4->ipv4_addr);
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
  ppc->plugin = cls;
  GNUNET_RESOLVER_hostname_get (sb, sbs, !numeric, timeout, &append_port, ppc);
}



/**
 * Another peer has suggested an address for this
 * peer and transport plugin.  Check that this could be a valid
 * address.  If so, consider adding it to the list
 * of addresses.
 *
 * @param cls closure
 * @param addr pointer to the address
 * @param addrlen length of addr
 * @return GNUNET_OK if this is a plausible address for this peer
 *         and transport
 */
static int
http_plugin_address_suggested (void *cls, const void *addr, size_t addrlen)
{
  struct Plugin *plugin = cls;
  struct IPv4HttpAddress *v4;
  struct IPv6HttpAddress *v6;
  struct IPv4HttpAddressWrapper *w_tv4 = plugin->ipv4_addr_head;
  struct IPv6HttpAddressWrapper *w_tv6 = plugin->ipv6_addr_head;

  GNUNET_assert (cls != NULL);
  if ((addrlen != sizeof (struct IPv4HttpAddress)) &&
      (addrlen != sizeof (struct IPv6HttpAddress)))
    return GNUNET_SYSERR;
  if (addrlen == sizeof (struct IPv4HttpAddress))
  {
    v4 = (struct IPv4HttpAddress *) addr;
    while (w_tv4 != NULL)
    {
      if (0 ==
          memcmp (&w_tv4->addr->ipv4_addr, &v4->ipv4_addr, sizeof (uint32_t)))
        break;
      w_tv4 = w_tv4->next;
    }
    if (w_tv4 != NULL)
      return GNUNET_OK;
    else
      return GNUNET_SYSERR;
  }
  if (addrlen == sizeof (struct IPv6HttpAddress))
  {
    v6 = (struct IPv6HttpAddress *) addr;
    while (w_tv6 != NULL)
    {
      if (0 ==
          memcmp (&w_tv6->addr->ipv6_addr, &v6->ipv6_addr,
                  sizeof (struct in6_addr)))
        break;
      w_tv6 = w_tv6->next;
    }
    if (w_tv6 != NULL)
      return GNUNET_OK;
    else
      return GNUNET_SYSERR;
  }
  return GNUNET_SYSERR;
}

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
http_plugin_address_to_string (void *cls, const void *addr, size_t addrlen)
{
  struct Plugin *plugin = cls;

  const struct IPv4HttpAddress *t4;
  const struct IPv6HttpAddress *t6;
  struct sockaddr_in a4;
  struct sockaddr_in6 a6;
  char *address;
  static char rbuf[INET6_ADDRSTRLEN + 13];
  uint16_t port;
  int res;

  GNUNET_assert (plugin != NULL);

  if (addrlen == sizeof (struct IPv6HttpAddress))
  {
    address = GNUNET_malloc (INET6_ADDRSTRLEN);
    t6 = addr;
    a6.sin6_addr = t6->ipv6_addr;
    inet_ntop (AF_INET6, &(a6.sin6_addr), address, INET6_ADDRSTRLEN);
    port = ntohs (t6->port);
  }
  else if (addrlen == sizeof (struct IPv4HttpAddress))
  {
    address = GNUNET_malloc (INET_ADDRSTRLEN);
    t4 = addr;
    a4.sin_addr.s_addr = t4->ipv4_addr;
    inet_ntop (AF_INET, &(a4.sin_addr), address, INET_ADDRSTRLEN);
    port = ntohs (t4->port);
  }
  else
  {
    /* invalid address */
    return NULL;
  }

  GNUNET_assert (strlen (address) + 7 < (INET6_ADDRSTRLEN + 13));
  if (addrlen == sizeof (struct IPv6HttpAddress))
    res = GNUNET_snprintf (rbuf, sizeof (rbuf), "%s://[%s]:%u/", plugin->protocol, address, port);
  else if (addrlen == sizeof (struct IPv4HttpAddress))
    res = GNUNET_snprintf (rbuf, sizeof (rbuf), "%s://%s:%u/", plugin->protocol, address, port);

  GNUNET_free (address);
  GNUNET_assert (res != 0);
  return rbuf;
}

struct Session *
lookup_session (struct Plugin *plugin, const struct GNUNET_PeerIdentity *target,
                const void *addr, size_t addrlen, int force_address)
{
  struct Session *s = NULL;
  struct Session *t = NULL;
  int e_peer;
  int e_addr;

  t = plugin->head;
  if (t == NULL)
    return NULL;
  while (t->next != NULL)
  {
    e_peer = GNUNET_NO;
    e_addr = GNUNET_NO;
    if (0 == memcmp (target, &t->target, sizeof (struct GNUNET_PeerIdentity)))
    {
      e_peer = GNUNET_YES;
      if (addrlen == t->addrlen)
      {
        if (0 == memcmp (addr, &t->addr, addrlen))
          e_addr = GNUNET_YES;
      }
    }

    if ((e_peer == GNUNET_YES) && (force_address == GNUNET_NO))
    {
      s = t;
      break;
    }
    else if ((e_peer == GNUNET_YES) && (force_address == GNUNET_YES) &&
             (e_addr == GNUNET_YES))
    {
      s = t;
      break;
    }
    else if ((e_peer == GNUNET_YES) && (force_address == GNUNET_SYSERR))
    {
      s = t;
      break;
    }
    t = t->next;
  }

  return s;
}

void
delete_session (struct Session *s)
{
  GNUNET_free (s->addr);
  GNUNET_free_non_null(s->server_recv);
  GNUNET_free_non_null(s->server_send);
  GNUNET_free (s);
}

struct Session *
create_session (struct Plugin *plugin, const struct GNUNET_PeerIdentity *target,
                const void *addr, size_t addrlen,
                GNUNET_TRANSPORT_TransmitContinuation cont, void *cont_cls)
{
  struct Session *s = NULL;

  s = GNUNET_malloc (sizeof (struct Session));
  memcpy (&s->target, target, sizeof (struct GNUNET_PeerIdentity));
  s->plugin = plugin;
  s->addr = GNUNET_malloc (addrlen);
  memcpy (s->addr, addr, addrlen);
  s->addrlen = addrlen;
  s->transmit_cont = cont;
  s->transmit_cont_cls = cont_cls;
  s->next = NULL;

  return s;
}

void
notify_session_end (void *cls,
                    const struct GNUNET_PeerIdentity *
                    peer, struct Session * s)
{
  struct Plugin *plugin = cls;

  plugin->env->session_end (NULL, peer, s);
  GNUNET_CONTAINER_DLL_remove (plugin->head, plugin->tail, s);
  delete_session (s);
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
 * @param target who should receive this message
 * @param msgbuf the message to transmit
 * @param msgbuf_size number of bytes in 'msgbuf'
 * @param priority how important is the message (most plugins will
 *                 ignore message priority and just FIFO)
 * @param to how long to wait at most for the transmission (does not
 *                require plugins to discard the message after the timeout,
 *                just advisory for the desired delay; most plugins will ignore
 *                this as well)
 * @param session which session must be used (or NULL for "any")
 * @param addr the address to use (can be NULL if the plugin
 *                is "on its own" (i.e. re-use existing TCP connection))
 * @param addrlen length of the address in bytes
 * @param force_address GNUNET_YES if the plugin MUST use the given address,
 *                GNUNET_NO means the plugin may use any other address and
 *                GNUNET_SYSERR means that only reliable existing
 *                bi-directional connections should be used (regardless
 *                of address)
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
http_plugin_send (void *cls, const struct GNUNET_PeerIdentity *target,
                  const char *msgbuf, size_t msgbuf_size, unsigned int priority,
                  struct GNUNET_TIME_Relative to, struct Session *session,
                  const void *addr, size_t addrlen, int force_address,
                  GNUNET_TRANSPORT_TransmitContinuation cont, void *cont_cls)
{
  struct Plugin *plugin = cls;

  GNUNET_assert (plugin != NULL);

  int res = GNUNET_SYSERR;

#if DEBUG_HTTP
  GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, plugin->name,
                   "Sending %u bytes to peer `%s'\n", msgbuf_size,
                   GNUNET_i2s (target));
#endif

  struct Session *s = NULL;

  /* look for existing connection */
  s = lookup_session (plugin, target, addr, addrlen, force_address);

  /* create new outbound connection */
  if (s == NULL)
  {
    if (plugin->max_connections <= plugin->cur_connections)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, plugin->name,
                       "Maximum number of connections reached, "
                       "cannot connect to peer `%s'\n",
                       GNUNET_i2s (target));
      return res;
    }

#if DEBUG_HTTP
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, plugin->name,
                     "Initiiating new connection to peer `%s'\n",
                     GNUNET_i2s (target));
#endif
    s = create_session (plugin, target, addr, addrlen, cont, cont_cls);
    GNUNET_CONTAINER_DLL_insert (plugin->head, plugin->tail, s);
    // initiate new connection
    if (GNUNET_SYSERR == (res = client_connect (s)))
    {
      GNUNET_CONTAINER_DLL_remove (plugin->head, plugin->tail, s);
      delete_session (s);
      return GNUNET_SYSERR;
    }
  }
  else if (s->inbound == GNUNET_NO)
    res = client_send (s, msgbuf, msgbuf_size);
  else if (s->inbound == GNUNET_YES)
    res = server_send (s, msgbuf, msgbuf_size);

  return res;
}


/**
 * Function that can be used to force the plugin to disconnect
 * from the given peer and cancel all previous transmissions
 * (and their continuationc).
 *
 * @param cls closure
 * @param target peer from which to disconnect
 */
static void
http_plugin_disconnect (void *cls, const struct GNUNET_PeerIdentity *target)
{
  struct Plugin *plugin = cls;
  struct Session *next = NULL;
  struct Session *s = plugin->head;

  while (s != NULL)
  {
    next = s->next;
    if (0 == memcmp (target, &s->target, sizeof (struct GNUNET_PeerIdentity)))
    {
      if (s->inbound == GNUNET_NO)
        GNUNET_assert (GNUNET_OK == client_disconnect (s));
      else
        GNUNET_assert (GNUNET_OK == server_disconnect (s));
      GNUNET_CONTAINER_DLL_remove (plugin->head, plugin->tail, s);
      delete_session (s);
    }
    s = next;
  }
}

/**
 * Function called by the NAT subsystem suggesting another peer wants
 * to connect to us via connection reversal.  Try to connect back to the
 * given IP.
 *
 * @param cls closure
 * @param addr address to try
 * @param addrlen number of bytes in addr
 */
static void
nat_connection_reversal (void *cls, const struct sockaddr *addr,
                         socklen_t addrlen)
{

}

static void
nat_add_address (void *cls, int add_remove, const struct sockaddr *addr,
                 socklen_t addrlen)
{
  struct Plugin *plugin = cls;
  struct IPv4HttpAddress *t4 = NULL;
  struct IPv4HttpAddressWrapper *w_t4 = NULL;
  struct IPv6HttpAddress *t6 = NULL;
  struct IPv6HttpAddressWrapper *w_t6 = NULL;
  int af;

  af = addr->sa_family;
  switch (af)
  {
  case AF_INET:
    w_t4 = plugin->ipv4_addr_head;
    while (w_t4 != NULL)
    {
      int res = memcmp (&w_t4->addr->ipv4_addr,
                        &((struct sockaddr_in *) addr)->sin_addr,
                        sizeof (struct in_addr));

      if (0 == res)
        break;
      w_t4 = w_t4->next;
    }
    if (w_t4 == NULL)
    {
      w_t4 = GNUNET_malloc (sizeof (struct IPv4HttpAddressWrapper));
      t4 = GNUNET_malloc (sizeof (struct IPv4HttpAddress));
      memcpy (&t4->ipv4_addr, &((struct sockaddr_in *) addr)->sin_addr,
              sizeof (struct in_addr));
      t4->port = htons (plugin->port);

      w_t4->addr = t4;

      GNUNET_CONTAINER_DLL_insert (plugin->ipv4_addr_head,
                                   plugin->ipv4_addr_tail, w_t4);
    }
    plugin->env->notify_address (plugin->env->cls, add_remove, w_t4->addr,
                                 sizeof (struct IPv4HttpAddress));

    break;
  case AF_INET6:
    w_t6 = plugin->ipv6_addr_head;
    while (w_t6)
    {
      int res = memcmp (&w_t6->addr->ipv6_addr,
                        &((struct sockaddr_in6 *) addr)->sin6_addr,
                        sizeof (struct in6_addr));

      if (0 == res)
        break;
      w_t6 = w_t6->next;
    }
    if (w_t6 == NULL)
    {
      w_t6 = GNUNET_malloc (sizeof (struct IPv6HttpAddressWrapper));
      t6 = GNUNET_malloc (sizeof (struct IPv6HttpAddress));

      memcpy (&t6->ipv6_addr, &((struct sockaddr_in6 *) addr)->sin6_addr,
              sizeof (struct in6_addr));
      t6->port = htons (plugin->port);

      w_t6->addr = t6;

      GNUNET_CONTAINER_DLL_insert (plugin->ipv6_addr_head,
                                   plugin->ipv6_addr_tail, w_t6);
    }
    plugin->env->notify_address (plugin->env->cls, add_remove, w_t6->addr,
                                 sizeof (struct IPv6HttpAddress));
    break;
  default:
    return;
  }

}

static void
nat_remove_address (void *cls, int add_remove, const struct sockaddr *addr,
                    socklen_t addrlen)
{
  struct Plugin *plugin = cls;
  struct IPv4HttpAddressWrapper *w_t4 = NULL;
  struct IPv6HttpAddressWrapper *w_t6 = NULL;
  int af;

  af = addr->sa_family;
  switch (af)
  {
  case AF_INET:
    w_t4 = plugin->ipv4_addr_head;
    while (w_t4 != NULL)
    {
      int res = memcmp (&w_t4->addr->ipv4_addr,
                        &((struct sockaddr_in *) addr)->sin_addr,
                        sizeof (struct in_addr));

      if (0 == res)
        break;
      w_t4 = w_t4->next;
    }
    if (w_t4 == NULL)
      return;
    plugin->env->notify_address (plugin->env->cls, add_remove, w_t4->addr,
                                 sizeof (struct IPv4HttpAddress));

    GNUNET_CONTAINER_DLL_remove (plugin->ipv4_addr_head, plugin->ipv4_addr_tail,
                                 w_t4);
    GNUNET_free (w_t4->addr);
    GNUNET_free (w_t4);
    break;
  case AF_INET6:
    w_t6 = plugin->ipv6_addr_head;
    while (w_t6 != NULL)
    {
      int res = memcmp (&w_t6->addr->ipv6_addr,
                        &((struct sockaddr_in6 *) addr)->sin6_addr,
                        sizeof (struct in6_addr));

      if (0 == res)
        break;
      w_t6 = w_t6->next;
    }
    if (w_t6 == NULL)
      return;
    plugin->env->notify_address (plugin->env->cls, add_remove, w_t6->addr,
                                 sizeof (struct IPv6HttpAddress));

    GNUNET_CONTAINER_DLL_remove (plugin->ipv6_addr_head, plugin->ipv6_addr_tail,
                                 w_t6);
    GNUNET_free (w_t6->addr);
    GNUNET_free (w_t6);
    break;
  default:
    return;
  }

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
nat_port_map_callback (void *cls, int add_remove, const struct sockaddr *addr,
                       socklen_t addrlen)
{
  GNUNET_assert (cls != NULL);
  struct Plugin *plugin = cls;

#if DEBUG_HTTP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "NPMC called %s to address `%s'\n",
                   (add_remove == GNUNET_NO) ? "remove" : "add",
                   GNUNET_a2s (addr, addrlen));
#endif
  /* convert 'addr' to our internal format */
  switch (add_remove)
  {
  case GNUNET_YES:
    nat_add_address (cls, add_remove, addr, addrlen);
    break;
  case GNUNET_NO:
    nat_remove_address (cls, add_remove, addr, addrlen);
    break;
  }
}


static void
start_report_addresses (struct Plugin *plugin)
{
  int res = GNUNET_OK;
  struct sockaddr **addrs;
  socklen_t *addrlens;

  res =
      GNUNET_SERVICE_get_server_addresses (plugin->name, plugin->env->cfg,
                                           &addrs, &addrlens);

  if (res != GNUNET_SYSERR)
  {
    plugin->nat =
        GNUNET_NAT_register (plugin->env->cfg, GNUNET_YES, plugin->port,
                             (unsigned int) res,
                             (const struct sockaddr **) addrs, addrlens,
                             &nat_port_map_callback, &nat_connection_reversal,
                             plugin);
    while (res > 0)
    {
      res--;
      GNUNET_assert (addrs[res] != NULL);
      GNUNET_free (addrs[res]);
    }
    GNUNET_free_non_null (addrs);
    GNUNET_free_non_null (addrlens);
  }
  else
  {
    plugin->nat =
        GNUNET_NAT_register (plugin->env->cfg, GNUNET_YES, 0, 0, NULL, NULL,
                             NULL, &nat_connection_reversal, plugin);
  }
}

static void
stop_report_addresses (struct Plugin *plugin)
{
  /* Stop NAT handle */
  GNUNET_NAT_unregister (plugin->nat);

  /* Clean up addresses */
  struct IPv4HttpAddressWrapper *w_t4;
  struct IPv6HttpAddressWrapper *w_t6;

  while (plugin->ipv4_addr_head != NULL)
  {
    w_t4 = plugin->ipv4_addr_head;
    GNUNET_CONTAINER_DLL_remove (plugin->ipv4_addr_head, plugin->ipv4_addr_tail,
                                 w_t4);
    GNUNET_free (w_t4->addr);
    GNUNET_free (w_t4);
  }

  while (plugin->ipv6_addr_head != NULL)
  {
    w_t6 = plugin->ipv6_addr_head;
    GNUNET_CONTAINER_DLL_remove (plugin->ipv6_addr_head, plugin->ipv6_addr_tail,
                                 w_t6);
    GNUNET_free (w_t6->addr);
    GNUNET_free (w_t6);
  }
}

static int
configure_plugin (struct Plugin *plugin)
{
  int res = GNUNET_OK;

  /* Use IPv4? */
  if (GNUNET_CONFIGURATION_have_value
      (plugin->env->cfg, plugin->name, "USE_IPv4"))
  {
    plugin->ipv4 =
        GNUNET_CONFIGURATION_get_value_yesno (plugin->env->cfg, plugin->name,
                                              "USE_IPv4");
  }
  else
    plugin->ipv4 = GNUNET_YES;

  /* Use IPv6? */
  if (GNUNET_CONFIGURATION_have_value
      (plugin->env->cfg, plugin->name, "USE_IPv6"))
  {
    plugin->ipv6 =
        GNUNET_CONFIGURATION_get_value_yesno (plugin->env->cfg, plugin->name,
                                              "USE_IPv6");
  }
  else
    plugin->ipv6 = GNUNET_YES;

  if ((plugin->ipv4 == GNUNET_NO) && (plugin->ipv6 == GNUNET_NO))
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, plugin->name,
                     _
                     ("Neither IPv4 nor IPv6 are enabled! Fix in configuration\n"),
                     plugin->name);
    res = GNUNET_SYSERR;
  }
  /* Reading port number from config file */
  unsigned long long port;

  if ((GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_number (plugin->env->cfg, plugin->name,
                                              "PORT", &port)) || (port > 65535))
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, plugin->name,
                     _("Port is required! Fix in configuration\n"),
                     plugin->name);
    res = GNUNET_SYSERR;
  }
  plugin->port = port;

  /* Optional parameters */
  unsigned long long maxneigh;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (plugin->env->cfg, plugin->name,
                                             "MAX_CONNECTIONS", &maxneigh))
    maxneigh = 128;
  plugin->max_connections = maxneigh;

  return res;
}

/**
 * Entry point for the plugin.
 */
void *
LIBGNUNET_PLUGIN_TRANSPORT_INIT (void *cls)
{
  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  struct Plugin *plugin;
  int res;

  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->env = env;
  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
  api->cls = plugin;
  api->send = &http_plugin_send;
  api->disconnect = &http_plugin_disconnect;
  api->address_pretty_printer = &http_plugin_address_pretty_printer;
  api->check_address = &http_plugin_address_suggested;
  api->address_to_string = &http_plugin_address_to_string;

#if BUILD_HTTPS
  plugin->name = "transport-https";
  plugin->protocol = "https";
#else
  plugin->name = "transport-http";
  plugin->protocol = "http";
#endif
  /* Configure plugin from configuration */

  res = configure_plugin (plugin);
  if (res == GNUNET_SYSERR)
  {
    GNUNET_free (plugin);
    GNUNET_free (api);
    return NULL;
  }

  /* Start client */
  res = client_start (plugin);
  if (res == GNUNET_SYSERR)
  {
    GNUNET_free (plugin);
    GNUNET_free (api);
    return NULL;
  }

  /* Start server */
  res = server_start (plugin);
  if (res == GNUNET_SYSERR)
  {
    server_stop (plugin);
    client_stop (plugin);

    GNUNET_free (plugin);
    GNUNET_free (api);
    return NULL;
  }

  /* Report addresses to transport service */
  start_report_addresses (plugin);

#if DEBUG_HTTP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "Plugin `%s' loaded\n", plugin->name);
#endif

  return api;
}


/**
 * Exit point from the plugin.
 */
void *
LIBGNUNET_PLUGIN_TRANSPORT_DONE (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;
  struct Session *s = NULL;

  /* Stop reporting addresses to transport service */
  stop_report_addresses (plugin);

  /* cleaning up sessions */
  s = plugin->head;
  while (s != NULL)
  {
    struct Session *t = s->next;
#if DEBUG_HTTP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "Disconnecting `%s' \n", GNUNET_i2s (&s->target));
#endif
    if (s->inbound == GNUNET_NO)
      GNUNET_assert (GNUNET_OK == client_disconnect (s));
    else
      GNUNET_assert (GNUNET_OK == server_disconnect (s));

    GNUNET_CONTAINER_DLL_remove (plugin->head, plugin->tail, s);
    delete_session (s);
    s = t;
  }

#if DEBUG_HTTP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "Stopping server\n");
#endif
  /* Stop server */
  server_stop (plugin);

#if DEBUG_HTTP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "Stopping client\n");
#endif
  /* Stop client */
  client_stop (plugin);


#if DEBUG_HTTP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "Plugin `%s' unloaded\n", plugin->name);
#endif

  GNUNET_free (plugin);
  GNUNET_free (api);

  return NULL;
}

/* end of plugin_transport_http.c */
