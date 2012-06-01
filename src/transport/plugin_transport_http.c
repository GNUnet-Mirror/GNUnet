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

  struct IPv4HttpAddress addr;
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

  struct IPv6HttpAddress addr6;
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

  uint32_t addrlen;

  int numeric;
};


/**
 * Encapsulation of all of the state of the plugin.
 */
struct Plugin;

/**
 * Start session timeout
 */
static void
start_session_timeout (struct Session *s);

/**
 * Increment session timeout due to activity
 */
static void
reschedule_session_timeout (struct Session *s);

/**
 * Cancel timeout
 */
static void
stop_session_timeout (struct Session *s);

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
  static char rbuf[INET6_ADDRSTRLEN + 13];

  if (hostname == NULL)
  {
    ppc->asc (ppc->asc_cls, NULL);
    GNUNET_free (ppc);
    return;
  }

#if !BUILD_HTTPS
  const char *protocol = "http";
#else
  const char *protocol = "https";
#endif
  GNUNET_assert ((strlen (hostname) + 7) < (INET6_ADDRSTRLEN + 13));
  if (ppc->addrlen == sizeof (struct IPv6HttpAddress))
  {
    if (ppc->numeric == GNUNET_YES)
      GNUNET_snprintf (rbuf, sizeof (rbuf), "%s://[%s]:%u/", protocol, hostname, ppc->port);
    else
    {
      if (strchr(hostname, ':') != NULL)
        GNUNET_snprintf (rbuf, sizeof (rbuf), "%s://[%s]:%u/", protocol, hostname, ppc->port);
      else
        GNUNET_snprintf (rbuf, sizeof (rbuf), "%s://%s:%u/", protocol, hostname, ppc->port);
    }
  }
  else if (ppc->addrlen == sizeof (struct IPv4HttpAddress))
    GNUNET_snprintf (rbuf, sizeof (rbuf), "%s://%s:%u/", protocol, hostname, ppc->port);
  ppc->asc (ppc->asc_cls, rbuf);
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
  struct sockaddr_in s4;
  struct sockaddr_in6 s6;
  size_t sbs;
  uint16_t port = 0;

  if ((addrlen == sizeof (struct IPv6HttpAddress))  && (addr != NULL))
  {
    struct IPv6HttpAddress *a6 = (struct IPv6HttpAddress *) addr;
    s6.sin6_family = AF_INET6;
    s6.sin6_addr = a6->ipv6_addr;
    s6.sin6_port = a6->u6_port;
#if HAVE_SOCKADDR_IN_SIN_LEN
    s6.sin6_len = sizeof (struct sockaddr_in6);
#endif
    sb = &s6;
    sbs = sizeof (struct sockaddr_in6);
    port = ntohs (a6->u6_port);

  }
  else if ((addrlen == sizeof (struct IPv4HttpAddress))  && (addr != NULL))
  {
    struct IPv4HttpAddress *a4 = (struct IPv4HttpAddress *) addr;

    s4.sin_family = AF_INET;
    s4.sin_addr.s_addr = a4->ipv4_addr;
    s4.sin_port = a4->u4_port;
#if HAVE_SOCKADDR_IN_SIN_LEN
    s4.sin_len = sizeof (struct sockaddr_in);
#endif
    sb = &s4;
    sbs = sizeof (struct sockaddr_in);
    port = ntohs (a4->u4_port);
  }
  else if (0 == addrlen)
  {
    asc (asc_cls, "<inbound connection>");
    asc (asc_cls, NULL);
    return;
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
  ppc->addrlen = addrlen;
  ppc->numeric = numeric;
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
  struct IPv4HttpAddressWrapper *w_tv4 = plugin->ipv4_addr_head;
  struct IPv6HttpAddressWrapper *w_tv6 = plugin->ipv6_addr_head;

  GNUNET_assert (cls != NULL);
  if ((addrlen != sizeof (struct sockaddr_in)) ||
      (addrlen != sizeof (struct sockaddr_in6)))
    return GNUNET_SYSERR;

  if (addrlen == sizeof (struct IPv4HttpAddress))
  {
    struct IPv4HttpAddress *a4 = (struct IPv4HttpAddress *) addr;

    while (w_tv4 != NULL)
    {
      if ((0 ==
           memcmp (&w_tv4->addr.ipv4_addr, &a4->ipv4_addr,
                   sizeof (struct in_addr))) &&
          (w_tv4->addr.u4_port == a4->u4_port))
        break;
      w_tv4 = w_tv4->next;
    }
    if (w_tv4 != NULL)
      return GNUNET_OK;
    else
      return GNUNET_SYSERR;
  }
  if (addrlen == sizeof (struct sockaddr_in6))
  {
    struct IPv6HttpAddress *a6 = (struct IPv6HttpAddress *) addr;

    while (w_tv6 != NULL)
    {
      if ((0 ==
           memcmp (&w_tv6->addr6.ipv6_addr, &a6->ipv6_addr,
                   sizeof (struct in6_addr))) &&
          (w_tv6->addr6.u6_port == a6->u6_port))
        break;
      w_tv6 = w_tv6->next;
    }
    if (w_tv6 != NULL)
      return GNUNET_OK;
    else
      return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}

struct GNUNET_TIME_Relative
http_plugin_receive (void *cls, const struct GNUNET_PeerIdentity *peer,
                     const struct GNUNET_MessageHeader *message,
                     struct Session *session, const char *sender_address,
                     uint16_t sender_address_len)
{
  struct Session *s = cls;
  struct Plugin *plugin = s->plugin;
  struct GNUNET_TIME_Relative delay;
  struct GNUNET_ATS_Information atsi[2];

  atsi[0].type = htonl (GNUNET_ATS_QUALITY_NET_DISTANCE);
  atsi[0].value = htonl (1);
  atsi[1].type = htonl (GNUNET_ATS_NETWORK_TYPE);
  atsi[1].value = session->ats_address_network_type;
  GNUNET_break (session->ats_address_network_type != ntohl (GNUNET_ATS_NET_UNSPECIFIED));

  reschedule_session_timeout (session);

  delay =
      plugin->env->receive (plugin->env->cls, &s->target, message,
                            (const struct GNUNET_ATS_Information *) &atsi,
                            2, s, s->addr, s->addrlen);
  return delay;
}


/**
 * Function called to convert a string address to
 * a binary address.
 *
 * @param cls closure ('struct Plugin*')
 * @param addr string address
 * @param addrlen length of the address
 * @param buf location to store the buffer
 *        If the function returns GNUNET_SYSERR, its contents are undefined.
 * @param added length of created address
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int 
http_string_to_address (void *cls,
			const char *addr,
			uint16_t addrlen,
			void **buf,
			size_t *added)
{
#if !BUILD_HTTPS
  char *protocol = "http";
#else
  char *protocol = "https";
#endif
  char *addr_str = NULL;
  struct sockaddr_in addr_4;
  struct sockaddr_in6 addr_6;
  struct IPv4HttpAddress * http_4addr;
  struct IPv6HttpAddress * http_6addr;

  if ((NULL == addr) || (addrlen == 0))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  if ('\0' != addr[addrlen - 1])
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  if (strlen (addr) != addrlen - 1)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  /* protocoll + "://" + ":" */
  if (addrlen <= (strlen (protocol) + 4))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                     "Invalid address string `%s' to convert to address\n",
                     addr);
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  if (NULL == (addr_str = strstr(addr, "://")))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
               "Invalid address string `%s' to convert to address\n",
               addr);
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  addr_str = &addr_str[3];

  if (addr_str[strlen(addr_str)-1] == '/')
    addr_str[strlen(addr_str)-1] = '\0';

  if (GNUNET_OK == GNUNET_STRINGS_to_address_ipv4(addr_str, strlen(addr_str), &addr_4))
  {
    http_4addr = GNUNET_malloc (sizeof (struct IPv4HttpAddress));
    http_4addr->u4_port = addr_4.sin_port;
    http_4addr->ipv4_addr = (uint32_t) addr_4.sin_addr.s_addr;
    (*buf) = http_4addr;
    (*added) = sizeof (struct IPv4HttpAddress);
    return GNUNET_OK;
  }
  if (GNUNET_OK == GNUNET_STRINGS_to_address_ipv6(addr_str, strlen(addr_str), &addr_6))
  {
    http_6addr = GNUNET_malloc (sizeof (struct IPv6HttpAddress));
    http_6addr->u6_port = addr_6.sin6_port;
    http_6addr->ipv6_addr = addr_6.sin6_addr;
    (*buf) = http_6addr;
    (*added) = sizeof (struct IPv6HttpAddress);
    return GNUNET_OK;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
	      "Invalid address string `%s' to convert to address\n",
	      addr_str);
  GNUNET_break (0);
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

  struct IPv4HttpAddress *a4;
  struct IPv6HttpAddress *a6;
  char *address;
  static char rbuf[INET6_ADDRSTRLEN + 13];
  uint16_t port;
  int res = 0;

  if (addrlen == sizeof (struct IPv6HttpAddress))
  {
    a6 = (struct IPv6HttpAddress *) addr;
    address = GNUNET_malloc (INET6_ADDRSTRLEN);
    GNUNET_assert (NULL !=
                   inet_ntop (AF_INET6, &a6->ipv6_addr, address,
                              INET6_ADDRSTRLEN));
    port = ntohs (a6->u6_port);
  }
  else if (addrlen == sizeof (struct IPv4HttpAddress))
  {
    a4 = (struct IPv4HttpAddress *) addr;
    address = GNUNET_malloc (INET_ADDRSTRLEN);
    GNUNET_assert (NULL !=
                   inet_ntop (AF_INET, &(a4->ipv4_addr), address,
                              INET_ADDRSTRLEN));
    port = ntohs (a4->u4_port);
  }
  else
  {
    /* invalid address */
    GNUNET_break (0);
    return NULL;
  }
#if !BUILD_HTTPS
  char *protocol = "http";
#else
  char *protocol = "https";
#endif

  GNUNET_assert (strlen (address) + 7 < (INET6_ADDRSTRLEN + 13));
  if (addrlen == sizeof (struct IPv6HttpAddress))
    res =
        GNUNET_snprintf (rbuf, sizeof (rbuf), "%s://[%s]:%u/", protocol,
                         address, port);
  else if (addrlen == sizeof (struct IPv4HttpAddress))
    res =
        GNUNET_snprintf (rbuf, sizeof (rbuf), "%s://%s:%u/", protocol, address,
                         port);

  GNUNET_free (address);
  GNUNET_assert (res != 0);
  return rbuf;
}


struct Session *
lookup_session_old (struct Plugin *plugin, const struct GNUNET_PeerIdentity *target,
                struct Session *session, const void *addr, size_t addrlen,
                int force_address)
{
  struct Session *t;
  int e_peer;
  int e_addr;

  for (t = plugin->head; NULL != t; t = t->next)
  {
#if 0
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, plugin->name,
                     "Comparing peer `%s' address `%s' len %i session %p to \n",
                     GNUNET_i2s (target), GNUNET_a2s (addr, addrlen), addrlen,
                     session);
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, plugin->name,
                     "peer `%s' address `%s' len %i session %p \n\n",
                     GNUNET_i2s (&t->target), GNUNET_a2s (t->addr, t->addrlen),
                     t->addrlen, t);
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, plugin->name, "memcmp %i \n",
                     memcmp (addr, t->addr, addrlen));
#endif
    e_peer = GNUNET_NO;
    e_addr = GNUNET_NO;
    if (0 == memcmp (target, &t->target, sizeof (struct GNUNET_PeerIdentity)))
    {
      e_peer = GNUNET_YES;
      if ( (addrlen == t->addrlen) &&
	   (0 == memcmp (addr, t->addr, addrlen)) )
	e_addr = GNUNET_YES;    
      if ( (t == session) &&
	   (t->addrlen == session->addrlen) &&
	   (0 == memcmp (session->addr, t->addr, t->addrlen)) )
	e_addr = GNUNET_YES;
    }

    if ( ((e_peer == GNUNET_YES) && (force_address == GNUNET_NO)) ||
	 ((e_peer == GNUNET_YES) && (force_address == GNUNET_YES) && (e_addr == GNUNET_YES)) ||
	 ((e_peer == GNUNET_YES) && (force_address == GNUNET_SYSERR)) )
      return t;
  }
  return NULL;
}


struct Session *
lookup_session (struct Plugin *plugin,
                const struct GNUNET_HELLO_Address *address)
{
  struct Session *pos;

  for (pos = plugin->head; NULL != pos; pos = pos->next)
    if ( (0 == memcmp (&address->peer, &pos->target, sizeof (struct GNUNET_PeerIdentity))) &&
	 (address->address_length == pos->addrlen) &&
	 (0 == memcmp (address->address, pos->addr, pos->addrlen)) )
      return pos;
  return NULL;
}


int
exist_session (struct Plugin *plugin, struct Session *s)
{
  struct Session * head;

  GNUNET_assert (NULL != plugin);
  GNUNET_assert (NULL != s);

  for (head = plugin->head; head != NULL; head = head->next)
  {
    if (head == s)
      return GNUNET_YES;
  }
  return GNUNET_NO;
}


void
delete_session (struct Session *s)
{
  stop_session_timeout(s);

  if (s->msg_tk != NULL)
  {
    GNUNET_SERVER_mst_destroy (s->msg_tk);
    s->msg_tk = NULL;
  }
  GNUNET_free (s->addr);
  GNUNET_free_non_null (s->server_recv);
  GNUNET_free_non_null (s->server_send);
  GNUNET_free (s);
}


struct Session *
create_session (struct Plugin *plugin, const struct GNUNET_PeerIdentity *target,
                const void *addr, size_t addrlen)
{
  struct Session *s = NULL;

  GNUNET_assert ((addrlen == sizeof (struct IPv6HttpAddress)) ||
                 (addrlen == sizeof (struct IPv4HttpAddress)));
  s = GNUNET_malloc (sizeof (struct Session));
  memcpy (&s->target, target, sizeof (struct GNUNET_PeerIdentity));
  s->plugin = plugin;
  s->addr = GNUNET_malloc (addrlen);
  memcpy (s->addr, addr, addrlen);
  s->addrlen = addrlen;
  s->ats_address_network_type = htonl (GNUNET_ATS_NET_UNSPECIFIED);
  start_session_timeout(s);
  return s;
}


void
notify_session_end (void *cls, const struct GNUNET_PeerIdentity *peer,
                    struct Session *s)
{
  struct Plugin *plugin = cls;

  plugin->env->session_end (plugin->env->cls, peer, s);
  GNUNET_CONTAINER_DLL_remove (plugin->head, plugin->tail, s);
  delete_session (s);
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
http_get_session (void *cls,
                  const struct GNUNET_HELLO_Address *address)
{
  struct Plugin *plugin = cls;
  struct Session * s = NULL;
  struct GNUNET_ATS_Information ats;
  size_t addrlen;

  GNUNET_assert (plugin != NULL);
  GNUNET_assert (address != NULL);
  GNUNET_assert (address->address != NULL);

  ats.type = htonl (GNUNET_ATS_ARRAY_TERMINATOR);
  ats.value = htonl (GNUNET_ATS_ARRAY_TERMINATOR);

  /* find existing session */
  s = lookup_session (plugin, address);
  if (s != NULL)
    return s;

  if (plugin->max_connections <= plugin->cur_connections)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, plugin->name,
                     "Maximum number of connections reached, "
                     "cannot connect to peer `%s'\n", GNUNET_i2s (&address->peer));
    return NULL;
  }

  /* create new session */
  addrlen = address->address_length;

  GNUNET_assert ((addrlen == sizeof (struct IPv6HttpAddress)) ||
                 (addrlen == sizeof (struct IPv4HttpAddress)));

  s = create_session (plugin, &address->peer, address->address, address->address_length);

  /* Get ATS type */
  if (addrlen == sizeof (struct IPv4HttpAddress))
  {
    struct IPv4HttpAddress *a4 = (struct IPv4HttpAddress *) address->address;
    struct sockaddr_in s4;

    s4.sin_family = AF_INET;
    s4.sin_addr.s_addr = a4->ipv4_addr;
    s4.sin_port = a4->u4_port;
#if HAVE_SOCKADDR_IN_SIN_LEN
    s4.sin_len = sizeof (struct sockaddr_in);
#endif
    ats = plugin->env->get_address_type (plugin->env->cls, (const struct sockaddr *) &s4, sizeof (struct sockaddr_in));
  }
  if (addrlen == sizeof (struct IPv6HttpAddress))
  {
    struct IPv6HttpAddress *a6 = (struct IPv6HttpAddress *) address->address;
    struct sockaddr_in6 s6;

    s6.sin6_family = AF_INET6;
    s6.sin6_addr = a6->ipv6_addr;
    s6.sin6_port = a6->u6_port;
#if HAVE_SOCKADDR_IN_SIN_LEN
    s6.sin6_len = sizeof (struct sockaddr_in6);
#endif
    ats = plugin->env->get_address_type (plugin->env->cls, (const struct sockaddr *) &s6, sizeof (struct sockaddr_in6));
  }
  s->ats_address_network_type = ats.value;

  /* add new session */
  GNUNET_CONTAINER_DLL_insert (plugin->head, plugin->tail, s);
  /* initiate new connection */
  if (GNUNET_SYSERR == client_connect (s))
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, plugin->name,
                     "Cannot connect to peer `%s' address `%s''\n",
                     http_plugin_address_to_string(NULL, s->addr, s->addrlen),
                     GNUNET_i2s (&s->target));
    GNUNET_CONTAINER_DLL_remove (plugin->head, plugin->tail, s);
    delete_session (s);
    return NULL;
  }

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
http_plugin_send (void *cls,
                  struct Session *session,
                  const char *msgbuf, size_t msgbuf_size,
                  unsigned int priority,
                  struct GNUNET_TIME_Relative to,
                  GNUNET_TRANSPORT_TransmitContinuation cont, void *cont_cls)
{
  struct Plugin *plugin = cls;
  struct HTTP_Message *msg;
  struct Session *tmp;
  size_t res = -1;

  GNUNET_assert (plugin != NULL);
  GNUNET_assert (session != NULL);

  /* lookup if session is really existing */
  tmp = plugin->head;
  while (tmp != NULL)
  {
    if ((tmp == session) &&
       (0 == memcmp (&session->target, &tmp->target, sizeof (struct GNUNET_PeerIdentity))) &&
       (session->addrlen == tmp->addrlen) &&
       (0 == memcmp (session->addr, tmp->addr, tmp->addrlen)))
      break;
    tmp = tmp->next;
  }
  if (tmp == NULL)
  {
    GNUNET_break_op (0);
    return res;
  }

  /* create new message and schedule */
  msg = GNUNET_malloc (sizeof (struct HTTP_Message) + msgbuf_size);
  msg->next = NULL;
  msg->size = msgbuf_size;
  msg->pos = 0;
  msg->buf = (char *) &msg[1];
  msg->transmit_cont = cont;
  msg->transmit_cont_cls = cont_cls;
  memcpy (msg->buf, msgbuf, msgbuf_size);

  reschedule_session_timeout (session);

  if (session->inbound == GNUNET_NO)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Using outbound client session %p to send to `%s'\n", session,
                     GNUNET_i2s (&session->target));
    client_send (session, msg);
    res = msgbuf_size;
  }
  if (session->inbound == GNUNET_YES)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Using inbound server %p session to send to `%s'\n", session,
                     GNUNET_i2s (&session->target));
    server_send (session, msg);
    res = msgbuf_size;
  }
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

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "Transport tells me to disconnect `%s'\n",
                   GNUNET_i2s (target));
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

      struct HTTP_Message *msg = s->msg_head;
      struct HTTP_Message *tmp = NULL;

      while (msg != NULL)
      {
        tmp = msg->next;

        GNUNET_CONTAINER_DLL_remove (s->msg_head, s->msg_tail, msg);
        if (msg->transmit_cont != NULL)
        {
          msg->transmit_cont (msg->transmit_cont_cls, target, GNUNET_SYSERR);
        }
        GNUNET_free (msg);
        msg = tmp;
      }

      delete_session (s);
    }
    s = next;
  }
}


static void *
find_address (struct Plugin *plugin, const struct sockaddr *addr, socklen_t addrlen)
{
  int af;
  struct IPv4HttpAddressWrapper *w_t4 = NULL;
  struct IPv6HttpAddressWrapper *w_t6 = NULL;

  af = addr->sa_family;
  switch (af)
  {
  case AF_INET:
    w_t4 = plugin->ipv4_addr_head;
    struct sockaddr_in *a4 = (struct sockaddr_in *) addr;

    while (w_t4 != NULL)
    {
      int res = memcmp (&w_t4->addr.ipv4_addr,
                        &a4->sin_addr,
                        sizeof (struct in_addr));

      if (res == 0)
      {
        if (a4->sin_port != w_t4->addr.u4_port)
          res = -1;
      }

      if (0 == res)
        break;
      w_t4 = w_t4->next;
    }
    return w_t4;
    break;
  case AF_INET6:
    w_t6 = plugin->ipv6_addr_head;
    struct sockaddr_in6 *a6 = (struct sockaddr_in6 *) addr;

    while (w_t6)
    {
      int res = memcmp (&w_t6->addr6.ipv6_addr, &a6->sin6_addr,
                        sizeof (struct in6_addr));

      if (res == 0)
      {
        if (a6->sin6_port != w_t6->addr6.u6_port)
          res = -1;
      }
      if (0 == res)
        break;
      w_t6 = w_t6->next;
    }
    return w_t6;
    break;
  default:
    return NULL;
  }
  return NULL;
}


static void
nat_add_address (void *cls, int add_remove, const struct sockaddr *addr,
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
    w_t4 = find_address (plugin, addr, addrlen);
    if (w_t4 == NULL)
    {
      struct sockaddr_in *a4 = (struct sockaddr_in *) addr;
      w_t4 = GNUNET_malloc (sizeof (struct IPv4HttpAddressWrapper));
      memcpy (&w_t4->addr.ipv4_addr, &a4->sin_addr, sizeof (struct in_addr));
      w_t4->addr.u4_port = a4->sin_port;

      GNUNET_CONTAINER_DLL_insert (plugin->ipv4_addr_head,
                                   plugin->ipv4_addr_tail, w_t4);

    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Notifying transport to add IPv4 address `%s'\n",
                     http_plugin_address_to_string (NULL, &w_t4->addr,
                                                    sizeof (struct
                                                            IPv4HttpAddress)));
    plugin->env->notify_address (plugin->env->cls, add_remove, &w_t4->addr,
                                 sizeof (struct IPv4HttpAddress));
    }
    break;
  case AF_INET6:
    w_t6 = find_address (plugin, addr, addrlen);
    if (w_t6 == NULL)
    {
      w_t6 = GNUNET_malloc (sizeof (struct IPv6HttpAddressWrapper));
      struct sockaddr_in6 *a6 = (struct sockaddr_in6 *) addr;
      memcpy (&w_t6->addr6.ipv6_addr, &a6->sin6_addr, sizeof (struct in6_addr));
      w_t6->addr6.u6_port = a6->sin6_port;

      GNUNET_CONTAINER_DLL_insert (plugin->ipv6_addr_head,
                                   plugin->ipv6_addr_tail, w_t6);

      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Notifying transport to add IPv6 address `%s'\n",
                     http_plugin_address_to_string (NULL, &w_t6->addr6,
                                                    sizeof (struct
                                                            IPv6HttpAddress)));
      plugin->env->notify_address (plugin->env->cls, add_remove, &w_t6->addr6,
                                 sizeof (struct IPv6HttpAddress));
    }
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
    w_t4 = find_address (plugin, addr, addrlen);
    if (w_t4 == NULL)
      return;


    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Notifying transport to remove IPv4 address `%s'\n",
                     http_plugin_address_to_string (NULL, &w_t4->addr,
                                                    sizeof (struct
                                                            IPv4HttpAddress)));
    plugin->env->notify_address (plugin->env->cls, add_remove, &w_t4->addr,
                                 sizeof (struct IPv4HttpAddress));

    GNUNET_CONTAINER_DLL_remove (plugin->ipv4_addr_head, plugin->ipv4_addr_tail,
                                 w_t4);
    GNUNET_free (w_t4);
    break;
  case AF_INET6:
    w_t6 = find_address (plugin, addr, addrlen);
    if (w_t6 == NULL)
      return;

    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Notifying transport to remove IPv6 address `%s'\n",
                     http_plugin_address_to_string (NULL, &w_t6->addr6,
                                                    sizeof (struct
                                                            IPv6HttpAddress)));

    plugin->env->notify_address (plugin->env->cls, add_remove, &w_t6->addr6,
                                 sizeof (struct IPv6HttpAddress));

    GNUNET_CONTAINER_DLL_remove (plugin->ipv6_addr_head, plugin->ipv6_addr_tail,
                                 w_t6);
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

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "NPMC called %s to address `%s'\n",
                   (add_remove == GNUNET_NO) ? "remove" : "add",
                   GNUNET_a2s (addr, addrlen));

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


void
http_check_ipv6 (struct Plugin *plugin)
{
  struct GNUNET_NETWORK_Handle *desc = NULL;

  if (plugin->ipv6 == GNUNET_YES)
  {
    /* probe IPv6 support */
    desc = GNUNET_NETWORK_socket_create (PF_INET6, SOCK_STREAM, 0);
    if (NULL == desc)
    {
      if ((errno == ENOBUFS) || (errno == ENOMEM) || (errno == ENFILE) ||
          (errno == EACCES))
      {
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "socket");
      }
      GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, plugin->name,
                       _
                       ("Disabling IPv6 since it is not supported on this system!\n"));
      plugin->ipv6 = GNUNET_NO;
    }
    else
    {
      GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (desc));
      desc = NULL;
    }

    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Testing IPv6 on this system: %s\n",
                     (plugin->ipv6 == GNUNET_YES) ? "successful" : "failed");
  }
}


int
http_get_addresses (struct Plugin *plugin, const char *serviceName,
                    const struct GNUNET_CONFIGURATION_Handle *cfg,
                    struct sockaddr ***addrs, socklen_t ** addr_lens)
{
  int disablev6;
  unsigned long long port;
  struct addrinfo hints;
  struct addrinfo *res;
  struct addrinfo *pos;
  struct addrinfo *next;
  unsigned int i;
  int resi;
  int ret;
  struct sockaddr **saddrs;
  socklen_t *saddrlens;
  char *hostname;

  *addrs = NULL;
  *addr_lens = NULL;

  disablev6 = !plugin->ipv6;

  port = 0;
  if (GNUNET_CONFIGURATION_have_value (cfg, serviceName, "PORT"))
  {
    GNUNET_break (GNUNET_OK ==
                  GNUNET_CONFIGURATION_get_value_number (cfg, serviceName,
                                                         "PORT", &port));
    if (port > 65535)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _
                  ("Require valid port number for service in configuration!\n"));
      return GNUNET_SYSERR;
    }
  }

  if (GNUNET_CONFIGURATION_have_value (cfg, serviceName, "BINDTO"))
  {
    GNUNET_break (GNUNET_OK ==
                  GNUNET_CONFIGURATION_get_value_string (cfg, serviceName,
                                                         "BINDTO", &hostname));
  }
  else
    hostname = NULL;

  if (hostname != NULL)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Resolving `%s' since that is where `%s' will bind to.\n",
                     hostname, serviceName);
    memset (&hints, 0, sizeof (struct addrinfo));
    if (disablev6)
      hints.ai_family = AF_INET;
    if ((0 != (ret = getaddrinfo (hostname, NULL, &hints, &res))) ||
        (res == NULL))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Failed to resolve `%s': %s\n"),
                  hostname, gai_strerror (ret));
      GNUNET_free (hostname);
      return GNUNET_SYSERR;
    }
    next = res;
    i = 0;
    while (NULL != (pos = next))
    {
      next = pos->ai_next;
      if ((disablev6) && (pos->ai_family == AF_INET6))
        continue;
      i++;
    }
    if (0 == i)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Failed to find %saddress for `%s'.\n"),
                  disablev6 ? "IPv4 " : "", hostname);
      freeaddrinfo (res);
      GNUNET_free (hostname);
      return GNUNET_SYSERR;
    }
    resi = i;
    saddrs = GNUNET_malloc ((resi + 1) * sizeof (struct sockaddr *));
    saddrlens = GNUNET_malloc ((resi + 1) * sizeof (socklen_t));
    i = 0;
    next = res;
    while (NULL != (pos = next))
    {
      next = pos->ai_next;
      if ((disablev6) && (pos->ai_family == AF_INET6))
        continue;
      if ((pos->ai_protocol != IPPROTO_TCP) && (pos->ai_protocol != 0))
        continue;               /* not TCP */
      if ((pos->ai_socktype != SOCK_STREAM) && (pos->ai_socktype != 0))
        continue;               /* huh? */
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                       "Service will bind to `%s'\n", GNUNET_a2s (pos->ai_addr,
                                                                  pos->ai_addrlen));
      if (pos->ai_family == AF_INET)
      {
        GNUNET_assert (pos->ai_addrlen == sizeof (struct sockaddr_in));
        saddrlens[i] = pos->ai_addrlen;
        saddrs[i] = GNUNET_malloc (saddrlens[i]);
        memcpy (saddrs[i], pos->ai_addr, saddrlens[i]);
        ((struct sockaddr_in *) saddrs[i])->sin_port = htons (port);
      }
      else
      {
        GNUNET_assert (pos->ai_family == AF_INET6);
        GNUNET_assert (pos->ai_addrlen == sizeof (struct sockaddr_in6));
        saddrlens[i] = pos->ai_addrlen;
        saddrs[i] = GNUNET_malloc (saddrlens[i]);
        memcpy (saddrs[i], pos->ai_addr, saddrlens[i]);
        ((struct sockaddr_in6 *) saddrs[i])->sin6_port = htons (port);
      }
      i++;
    }
    GNUNET_free (hostname);
    freeaddrinfo (res);
    resi = i;
  }
  else
  {
    /* will bind against everything, just set port */
    if (disablev6)
    {
      /* V4-only */
      resi = 1;
      i = 0;
      saddrs = GNUNET_malloc ((resi + 1) * sizeof (struct sockaddr *));
      saddrlens = GNUNET_malloc ((resi + 1) * sizeof (socklen_t));

      saddrlens[i] = sizeof (struct sockaddr_in);
      saddrs[i] = GNUNET_malloc (saddrlens[i]);
#if HAVE_SOCKADDR_IN_SIN_LEN
      ((struct sockaddr_in *) saddrs[i])->sin_len = saddrlens[i];
#endif
      ((struct sockaddr_in *) saddrs[i])->sin_family = AF_INET;
      ((struct sockaddr_in *) saddrs[i])->sin_port = htons (port);
    }
    else
    {
      /* dual stack */
      resi = 2;
      saddrs = GNUNET_malloc ((resi + 1) * sizeof (struct sockaddr *));
      saddrlens = GNUNET_malloc ((resi + 1) * sizeof (socklen_t));
      i = 0;
      saddrlens[i] = sizeof (struct sockaddr_in6);
      saddrs[i] = GNUNET_malloc (saddrlens[i]);
#if HAVE_SOCKADDR_IN_SIN_LEN
      ((struct sockaddr_in6 *) saddrs[i])->sin6_len = saddrlens[0];
#endif
      ((struct sockaddr_in6 *) saddrs[i])->sin6_family = AF_INET6;
      ((struct sockaddr_in6 *) saddrs[i])->sin6_port = htons (port);
      i++;
      saddrlens[i] = sizeof (struct sockaddr_in);
      saddrs[i] = GNUNET_malloc (saddrlens[i]);
#if HAVE_SOCKADDR_IN_SIN_LEN
      ((struct sockaddr_in *) saddrs[i])->sin_len = saddrlens[1];
#endif
      ((struct sockaddr_in *) saddrs[i])->sin_family = AF_INET;
      ((struct sockaddr_in *) saddrs[i])->sin_port = htons (port);
    }
  }
  *addrs = saddrs;
  *addr_lens = saddrlens;
  return resi;
}

static void
start_report_addresses (struct Plugin *plugin)
{
  int res = GNUNET_OK;
  struct sockaddr **addrs;
  socklen_t *addrlens;

  res =
      http_get_addresses (plugin, plugin->name, plugin->env->cfg, &addrs,
                          &addrlens);
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   _("Found %u addresses to report to NAT service\n"), res);

  if (res != GNUNET_SYSERR)
  {
    plugin->nat =
        GNUNET_NAT_register (plugin->env->cfg, GNUNET_YES, plugin->port,
                             (unsigned int) res,
                             (const struct sockaddr **) addrs, addrlens,
                             &nat_port_map_callback, NULL, plugin);
    while (res > 0)
    {
      res--;
#if 0
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, plugin->name, _("FREEING %s\n"),
                       GNUNET_a2s (addrs[res], addrlens[res]));
#endif
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
                             NULL, NULL, plugin);
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
    GNUNET_free (w_t4);
  }

  while (plugin->ipv6_addr_head != NULL)
  {
    w_t6 = plugin->ipv6_addr_head;
    GNUNET_CONTAINER_DLL_remove (plugin->ipv6_addr_head, plugin->ipv6_addr_tail,
                                 w_t6);
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
    goto fail;
  }
  plugin->port = port;

  plugin->client_only = GNUNET_NO;
  if (plugin->port == 0)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     _("Port 0, client only mode\n"));
    plugin->client_only = GNUNET_YES;
  }

  char *bind4_address = NULL;

  if ((plugin->ipv4 == GNUNET_YES) &&
      (GNUNET_YES ==
       GNUNET_CONFIGURATION_get_value_string (plugin->env->cfg, plugin->name,
                                              "BINDTO", &bind4_address)))
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Binding %s plugin to specific IPv4 address: `%s'\n",
                     plugin->protocol, bind4_address);
    plugin->server_addr_v4 = GNUNET_malloc (sizeof (struct sockaddr_in));
    if (1 !=
        inet_pton (AF_INET, bind4_address, &plugin->server_addr_v4->sin_addr))
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, plugin->name,
                       _
                       ("Specific IPv4 address `%s' for plugin %s in configuration file is invalid! Binding to all addresses!\n"),
                       bind4_address, plugin->protocol);
      GNUNET_free (plugin->server_addr_v4);
      plugin->server_addr_v4 = NULL;
    }
    else
    {
      plugin->server_addr_v4->sin_family = AF_INET;
      plugin->server_addr_v4->sin_port = htons (plugin->port);
    }
    GNUNET_free (bind4_address);
  }


  char *bind6_address = NULL;

  if ((plugin->ipv6 == GNUNET_YES) &&
      (GNUNET_YES ==
       GNUNET_CONFIGURATION_get_value_string (plugin->env->cfg, plugin->name,
                                              "BINDTO6", &bind6_address)))
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Binding %s plugin to specific IPv6 address: `%s'\n",
                     plugin->protocol, bind6_address);
    plugin->server_addr_v6 = GNUNET_malloc (sizeof (struct sockaddr_in6));
    if (1 !=
        inet_pton (AF_INET6, bind6_address, &plugin->server_addr_v6->sin6_addr))
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, plugin->name,
                       _
                       ("Specific IPv6 address `%s' for plugin %s in configuration file is invalid! Binding to all addresses!\n"),
                       bind6_address, plugin->protocol);
      GNUNET_free (plugin->server_addr_v6);
      plugin->server_addr_v6 = NULL;
    }
    else
    {
      plugin->server_addr_v6->sin6_family = AF_INET6;
      plugin->server_addr_v6->sin6_port = htons (plugin->port);
    }
    GNUNET_free (bind6_address);
  }


  /* Optional parameters */
  unsigned long long maxneigh;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (plugin->env->cfg, plugin->name,
                                             "MAX_CONNECTIONS", &maxneigh))
    maxneigh = 128;
  plugin->max_connections = maxneigh;

fail:
  return res;
}


/**
 * Session was idle, so disconnect it
 */
static void
session_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_assert (NULL != cls);
  struct Session *s = cls;

  s->timeout_task = GNUNET_SCHEDULER_NO_TASK;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Session %p was idle for %llu, disconnecting\n",
      s, GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT.rel_value);

  /* call session destroy function */
  if (s->inbound == GNUNET_NO)
    GNUNET_assert (GNUNET_OK == client_disconnect (s));
  else
    GNUNET_assert (GNUNET_OK == server_disconnect (s));

}


/**
 * Start session timeout
 */
static void
start_session_timeout (struct Session *s)
{
  GNUNET_assert (NULL != s);
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == s->timeout_task);

  s->timeout_task =  GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                                                   &session_timeout,
                                                   s);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Timeout for session %p set to %llu\n",
      s, GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT.rel_value);
}


/**
 * Increment session timeout due to activity
 */
static void
reschedule_session_timeout (struct Session *s)
{
  GNUNET_assert (NULL != s);
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK != s->timeout_task);

  GNUNET_SCHEDULER_cancel (s->timeout_task);
  s->timeout_task =  GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                                                   &session_timeout,
                                                   s);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Timeout rescheduled for session %p set to %llu\n",
      s, GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT.rel_value);
}


/**
 * Cancel timeout
 */
static void
stop_session_timeout (struct Session *s)
{
  GNUNET_assert (NULL != s);

  if (GNUNET_SCHEDULER_NO_TASK != s->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (s->timeout_task);
    s->timeout_task = GNUNET_SCHEDULER_NO_TASK;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Timeout rescheduled for session %p canceled\n",
      s, GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT.rel_value);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Timeout for session %p was not active\n",
      s);
  }
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

  if (NULL == env->receive)
  {
    /* run in 'stub' mode (i.e. as part of gnunet-peerinfo), don't fully
       initialze the plugin or the API */
    api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
    api->cls = NULL;
    api->address_pretty_printer = &http_plugin_address_pretty_printer;
    api->address_to_string = &http_plugin_address_to_string;
    api->string_to_address = &http_string_to_address;
    return api;
  }

  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->env = env;
  plugin->outbound_sessions = 0;
  plugin->inbound_sessions = 0;
  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
  api->cls = plugin;
  api->disconnect = &http_plugin_disconnect;
  api->address_pretty_printer = &http_plugin_address_pretty_printer;
  api->check_address = &http_plugin_address_suggested;
  api->address_to_string = &http_plugin_address_to_string;
  api->string_to_address = &http_string_to_address;
  api->get_session = &http_get_session;
  api->send = &http_plugin_send;

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
    GNUNET_free_non_null (plugin->server_addr_v4);
    GNUNET_free_non_null (plugin->server_addr_v6);
    GNUNET_free (plugin);
    GNUNET_free (api);
    return NULL;
  }

  /* checking IPv6 support */
  http_check_ipv6 (plugin);

  /* Start client */
  res = client_start (plugin);
  if (res == GNUNET_SYSERR)
  {
    GNUNET_free_non_null (plugin->server_addr_v4);
    GNUNET_free_non_null (plugin->server_addr_v6);
    GNUNET_free (plugin);
    GNUNET_free (api);
    return NULL;
  }

  /* Start server */
  if (plugin->client_only == GNUNET_NO)
  {
    res = server_start (plugin);
    if (res == GNUNET_SYSERR)
    {
      server_stop (plugin);
      client_stop (plugin);

      GNUNET_free_non_null (plugin->server_addr_v4);
      GNUNET_free_non_null (plugin->server_addr_v6);
      GNUNET_free (plugin);
      GNUNET_free (api);
      return NULL;
    }
  }
  /* Report addresses to transport service */
  start_report_addresses (plugin);

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "Plugin `%s' loaded\n", plugin->name);
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
  struct Session *s;

  if (NULL == plugin)
  {
    GNUNET_free (api);
    return NULL;
  }

  /* Stop reporting addresses to transport service */
  stop_report_addresses (plugin);

  /* cleaning up sessions */
  s = plugin->head;
  while (s != NULL)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Disconnecting `%s' \n", GNUNET_i2s (&s->target));
    if (s->inbound == GNUNET_NO)
      GNUNET_assert (GNUNET_OK == client_disconnect (s));
    else
      GNUNET_assert (GNUNET_OK == server_disconnect (s));
    s = s->next;
  }

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name, "Stopping server\n");
  /* Stop server */
  server_stop (plugin);

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name, "Stopping client\n");
  /* Stop client */
  client_stop (plugin);

  /* deleting up sessions */
  s = plugin->head;
  while (s != NULL)
  {
    struct Session *t = s->next;

    GNUNET_CONTAINER_DLL_remove (plugin->head, plugin->tail, s);

    struct HTTP_Message *msg = s->msg_head;
    struct HTTP_Message *tmp = NULL;

    while (msg != NULL)
    {
      tmp = msg->next;

      GNUNET_CONTAINER_DLL_remove (s->msg_head, s->msg_tail, msg);
      if (msg->transmit_cont != NULL)
      {
        msg->transmit_cont (msg->transmit_cont_cls, &s->target, GNUNET_SYSERR);
      }
      GNUNET_free (msg);
      msg = tmp;
    }

    delete_session (s);
    s = t;
  }

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "Plugin `%s' unloaded\n", plugin->name);
  GNUNET_free_non_null (plugin->server_addr_v4);
  GNUNET_free_non_null (plugin->server_addr_v6);
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}

/* end of plugin_transport_http.c */
