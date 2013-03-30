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
 * Wrapper to manage addresses
 */
struct HttpAddressWrapper
{
  /**
   * Linked list next
   */
  struct HttpAddressWrapper *next;

  /**
   * Linked list previous
   */
  struct HttpAddressWrapper *prev;

  struct HttpAddress *addr;
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
  struct HttpAddress *haddr = (struct HttpAddress *) addr;

  if (addrlen < (sizeof (struct HttpAddress)))
  {
    /* invalid address */
    GNUNET_break_op (0);
    asc (asc_cls, NULL);
    return;
  }
  asc (asc_cls, haddr->addr);
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
  struct HttpAddressWrapper *w = plugin->addr_head;
  struct HttpAddress *haddr = (struct HttpAddress *) addr;

  GNUNET_assert (cls != NULL);

  if (addrlen <= sizeof (struct HttpAddress))
    return GNUNET_SYSERR;

  if (0 == (strcmp (plugin->ext_addr->addr, haddr->addr)))
      return GNUNET_OK;

  while (NULL != w)
  {
      if (0 == (strcmp (w->addr->addr, haddr->addr)))
          return GNUNET_OK;
      w = w->next;
  }
  return GNUNET_SYSERR;
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
  struct GNUNET_ATS_Information atsi;

  atsi.type = htonl (GNUNET_ATS_NETWORK_TYPE);
  atsi.value = session->ats_address_network_type;
  GNUNET_break (session->ats_address_network_type != ntohl (GNUNET_ATS_NET_UNSPECIFIED));

  reschedule_session_timeout (session);

  delay =
      plugin->env->receive (plugin->env->cls, &s->target, message,
                            &atsi,
                            1, s, s->addr, s->addrlen);
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
#if 0
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
#endif
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
  struct HttpAddress *haddr;
  if (addrlen < sizeof (struct HttpAddress))
  {
      /* invalid address */
      GNUNET_break (0);
      return NULL;
  }
  else
  {
      haddr = (struct HttpAddress *) addr;
      GNUNET_assert (NULL != haddr->addr);
      return (const char *) haddr->addr;
  }
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

/**
 * Deleting the session
 * Must not be used afterwards
 */

void
delete_session (struct Session *s)
{
  struct Plugin *plugin = s->plugin;
  stop_session_timeout(s);

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
  struct GNUNET_ATS_Information ats;

  /*
   * ats = plugin->env->get_address_type (plugin->env->cls, (const struct sockaddr *) &s6, sizeof (struct sockaddr_in6));
   */
  if (addrlen < sizeof (struct HttpAddress))
  {
      GNUNET_break (0);
      return NULL;
  }



  s = GNUNET_malloc (sizeof (struct Session));
  memcpy (&s->target, target, sizeof (struct GNUNET_PeerIdentity));
  s->plugin = plugin;
  s->addr = GNUNET_malloc (addrlen);
  memcpy (s->addr, addr, addrlen);
  s->addrlen = addrlen;
  s->ats_address_network_type = ats.value;


  start_session_timeout(s);
  return s;
}


void
notify_session_end (void *cls, const struct GNUNET_PeerIdentity *peer,
                    struct Session *s)
{
  struct Plugin *plugin = cls;

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "Notifying transport about ending session %p (`%s')\n",
                   s,
                   http_plugin_address_to_string(NULL, s->addr,s->addrlen));

  plugin->env->session_end (plugin->env->cls, peer, s);
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
  size_t addrlen;

  GNUNET_assert (plugin != NULL);
  GNUNET_assert (address != NULL);
  GNUNET_assert (address->address != NULL);

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

  GNUNET_assert (addrlen > sizeof (struct HttpAddress));

  s = create_session (plugin, &address->peer, address->address, address->address_length);

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
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                       "Disconnecting %s session %p to `%s'\n",
                       (s->inbound == GNUNET_NO) ? "outbound" : "inbound",
                       s, GNUNET_i2s (target));

      if (s->inbound == GNUNET_NO)
        GNUNET_assert (GNUNET_OK == client_disconnect (s));
      else
        GNUNET_assert (GNUNET_OK == server_disconnect (s));
    }
    s = next;
  }
}


static void *
find_address (struct Plugin *plugin, const struct sockaddr *addr, socklen_t addrlen)
{
  struct HttpAddressWrapper *w = NULL;
  char *saddr;

  GNUNET_asprintf(&saddr, "%s://%s", plugin->protocol, GNUNET_a2s (addr, addrlen));
  w = plugin->addr_head;
  while (NULL != w)
  {
      if (0 == strcmp (saddr, w->addr->addr))
        break;
      w = w->next;
  }

  GNUNET_free (saddr);
  return w;
}




static void
nat_add_address (void *cls, int add_remove, const struct sockaddr *addr,
                 socklen_t addrlen)
{
  struct Plugin *plugin = cls;
  struct HttpAddressWrapper *w = NULL;
  char *saddr;
  size_t haddrlen;

  GNUNET_asprintf(&saddr, "%s://%s", plugin->protocol, GNUNET_a2s (addr, addrlen));

  haddrlen = sizeof (struct HttpAddress) + strlen(saddr) + 1;
  w = GNUNET_malloc (sizeof (struct HttpAddressWrapper));
  w->addr = GNUNET_malloc (haddrlen);
  w->addr->addr = &w->addr[1];
  w->addr->addr_len = htonl (strlen(saddr) + 1);
  memcpy (w->addr->addr, saddr, strlen(saddr) + 1);
  GNUNET_free (saddr);

  GNUNET_CONTAINER_DLL_insert(plugin->addr_head, plugin->addr_tail, w);
  GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, plugin->name,
                   "Notifying transport to add address `%s'\n", w->addr->addr);

  plugin->env->notify_address (plugin->env->cls, add_remove, w->addr, haddrlen, "http");
}


static void
nat_remove_address (void *cls, int add_remove, const struct sockaddr *addr,
                    socklen_t addrlen)
{
  struct Plugin *plugin = cls;
  struct HttpAddressWrapper *w = NULL;
  size_t haddrlen;

  w = find_address (plugin, addr, addrlen);
  if (NULL == w)
    return;

  haddrlen = sizeof (struct HttpAddress) + ntohl (w->addr->addr_len);
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "Notifying transport to remove address `%s'\n", http_plugin_address_to_string(NULL, w->addr, haddrlen));


  GNUNET_CONTAINER_DLL_remove (plugin->addr_head, plugin->addr_tail, w);
  plugin->env->notify_address (plugin->env->cls, add_remove, w->addr,
       sizeof (struct HttpAddress) + ntohl (w->addr->addr_len), "http");
  GNUNET_free (w->addr);
  GNUNET_free (w);
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
  if (0 == port)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, plugin->name,
                     "Starting in listen only mode\n");
    return -1; /* listen only */
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

  if (GNUNET_SYSERR == res)
  {
    plugin->nat = NULL;
    return;
  }

  plugin->nat =
      GNUNET_NAT_register (plugin->env->cfg, GNUNET_YES, plugin->port,
                           (unsigned int) res,
                           (const struct sockaddr **) addrs, addrlens,
                           &nat_port_map_callback, NULL, plugin);
  while (res > 0)
  {
    res--;
    GNUNET_assert (addrs[res] != NULL);
    GNUNET_free (addrs[res]);
  }
  GNUNET_free_non_null (addrs);
  GNUNET_free_non_null (addrlens);
}


static void
stop_report_addresses (struct Plugin *plugin)
{

  /* Stop NAT handle */
  if (NULL != plugin->nat)
    GNUNET_NAT_unregister (plugin->nat);

  /* Clean up addresses */
  struct HttpAddressWrapper *w;

  while (plugin->addr_head != NULL)
  {
    w = plugin->addr_head;
    GNUNET_CONTAINER_DLL_remove (plugin->addr_head, plugin->addr_tail, w);
    GNUNET_free (w->addr);
    GNUNET_free (w);
  }
}

/**
 * Function called when the service shuts down.  Unloads our plugins
 * and cancels pending validations.
 *
 * @param cls closure, unused
 * @param tc task context (unused)
 */
static void
notify_external_hostname (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;
  struct HttpAddress *eaddr;
  char *addr;
  size_t eaddr_len;
  size_t uri_len;

  plugin->notify_ext_task = GNUNET_SCHEDULER_NO_TASK;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  GNUNET_asprintf(&addr, "%s://%s", plugin->protocol, plugin->external_hostname);
  uri_len = strlen (addr) + 1;
  eaddr_len = sizeof (struct HttpAddress) + uri_len;
  eaddr = GNUNET_malloc (eaddr_len);
  eaddr->addr_len = htonl (uri_len);
  eaddr->addr = (void *) &eaddr[1];
  memcpy (&eaddr->addr, addr, uri_len);
  GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, plugin->name,
                   "Notifying transport about external hostname address `%s'\n", addr);

  GNUNET_free (addr);
  plugin->env->notify_address (plugin->env->cls, GNUNET_YES, eaddr, eaddr_len, "http");
  plugin->ext_addr = eaddr;
  plugin->ext_addr_len = eaddr_len;
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

  if (GNUNET_YES == GNUNET_CONFIGURATION_get_value_string (plugin->env->cfg, plugin->name,
                                              "EXTERNAL_HOSTNAME", &plugin->external_hostname))
  {
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                       _("Using external hostname `%s'\n"), plugin->external_hostname);
      plugin->notify_ext_task = GNUNET_SCHEDULER_add_now (&notify_external_hostname, plugin);
  }
  else
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     _("No external hostname configured\n"));


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

#define TESTING GNUNET_NO

#if TESTING
#define TIMEOUT_LOG GNUNET_ERROR_TYPE_ERROR
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)
#else
#define TIMEOUT_LOG GNUNET_ERROR_TYPE_DEBUG
#define TIMEOUT GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT
#endif


/**
 * Session was idle, so disconnect it
 */
static void
session_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_assert (NULL != cls);
  struct Session *s = cls;

  s->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_log (TIMEOUT_LOG,
              "Session %p was idle for %llu ms, disconnecting\n",
              s, (unsigned long long) TIMEOUT.rel_value);

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
 s->timeout_task =  GNUNET_SCHEDULER_add_delayed (TIMEOUT,
                                                  &session_timeout,
                                                  s);
 GNUNET_log (TIMEOUT_LOG,
             "Timeout for session %p set to %llu ms\n",
             s,  (unsigned long long) TIMEOUT.rel_value);
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
 s->timeout_task =  GNUNET_SCHEDULER_add_delayed (TIMEOUT,
                                                  &session_timeout,
                                                  s);
 GNUNET_log (TIMEOUT_LOG,
             "Timeout rescheduled for session %p set to %llu ms\n",
             s, (unsigned long long) TIMEOUT.rel_value);
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
   GNUNET_log (TIMEOUT_LOG,
               "Timeout stopped for session %p\n",
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
  struct Session *next;

  if (NULL == plugin)
  {
    GNUNET_free (api);
    return NULL;
  }

  if (GNUNET_SCHEDULER_NO_TASK != plugin->notify_ext_task)
  {
      GNUNET_SCHEDULER_cancel (plugin->notify_ext_task);
       plugin->notify_ext_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (NULL != plugin->ext_addr)
  {
      plugin->env->notify_address (plugin->env->cls, GNUNET_NO, plugin->ext_addr, plugin->ext_addr_len, "http");
      GNUNET_free (plugin->ext_addr);
  }

  /* Stop reporting addresses to transport service */
  stop_report_addresses (plugin);

  /* cleaning up sessions */
  s = plugin->head;
  while (s != NULL)
  {
    next = s->next;
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Disconnecting `%s' \n", GNUNET_i2s (&s->target));
    if (s->inbound == GNUNET_NO)
      GNUNET_assert (GNUNET_OK == client_disconnect (s));
    else
      GNUNET_assert (GNUNET_OK == server_disconnect (s));
    s = next;
  }

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name, "Stopping server\n");
  /* Stop server */
  server_stop (plugin);

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name, "Stopping client\n");
  /* Stop client */
  client_stop (plugin);

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "Plugin `%s' unloaded\n", plugin->name);
  GNUNET_free_non_null (plugin->server_addr_v4);
  GNUNET_free_non_null (plugin->server_addr_v6);
  GNUNET_free_non_null (plugin->external_hostname);
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}

/* end of plugin_transport_http.c */
