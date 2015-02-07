/*
 This file is part of GNUnet
 Copyright (C) 2002-2013 Christian Grothoff (and other contributing authors)

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
 * @file transport/plugin_transport_http_common.c
 * @brief functionality shared between http(s)client plugins
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_transport_plugin.h"
#include "plugin_transport_http_common.h"
#include "gnunet_resolver_service.h"

static void
http_clean_splitted (struct SplittedHTTPAddress *spa)
{
  if (NULL != spa)
  {
    GNUNET_free_non_null(spa->protocol);
    GNUNET_free_non_null(spa->host);
    GNUNET_free_non_null(spa->path);
    GNUNET_free_non_null(spa);
  }
}


struct SplittedHTTPAddress *
http_split_address (const char * addr)
{
  struct SplittedHTTPAddress *sp;
  char *src = GNUNET_strdup (addr);
  char *protocol_start = NULL;
  char *host_start = NULL;
  char *v6_end = NULL;
  char *port_start = NULL;
  char *path_start = NULL;
  protocol_start = src;

  sp = GNUNET_new (struct SplittedHTTPAddress);
  /* Address string consists of protocol://host[:port]path*/

  host_start = strstr (src, "://");
  if (NULL == host_start)
  {
    GNUNET_free(src);
    GNUNET_free(sp);
    return NULL ;
  }
  host_start[0] = '\0';
  sp->protocol = GNUNET_strdup (protocol_start);

  host_start += strlen ("://");
  if (strlen (host_start) == 0)
  {
    GNUNET_free(src);
    GNUNET_free(sp->protocol);
    GNUNET_free(sp);
    return NULL ;
  }

  /* Find path start */
  path_start = strchr (host_start, '/');
  if (NULL != path_start)
  {
    sp->path = GNUNET_strdup (path_start);
    path_start[0] = '\0';
  }
  else
    sp->path = GNUNET_strdup ("");

  if (strlen (host_start) < 1)
  {
    GNUNET_free(src);
    GNUNET_free(sp->protocol);
    GNUNET_free(sp->path);
    GNUNET_free(sp);
    return NULL ;
  }

  if (NULL != (port_start = strrchr (host_start, ':')))
  {
    /* *We COULD have a port, but also an IPv6 address! */
    if (NULL != (v6_end = strchr (host_start, ']')))
    {
      if (v6_end < port_start)
      {
        /* IPv6 address + port */
        port_start[0] = '\0';
        port_start++;
        sp->port = atoi (port_start);
        if ((0 == sp->port) || (65535 < sp->port))
        {
          GNUNET_free(src);
          GNUNET_free(sp->protocol);
          GNUNET_free(sp->path);
          GNUNET_free(sp);
          return NULL ;
        }
      }
      else
      {
        /* IPv6 address + no port */
        if (0 == strcmp (sp->protocol, "https"))
          sp->port = HTTPS_DEFAULT_PORT;
        else if (0 == strcmp (sp->protocol, "http"))
          sp->port = HTTP_DEFAULT_PORT;
      }
    }
    else
    {
      /* No IPv6 address */
      port_start[0] = '\0';
      port_start++;
      sp->port = atoi (port_start);
      if ((0 == sp->port) || (65535 < sp->port))
      {
        GNUNET_free(src);
        GNUNET_free(sp->protocol);
        GNUNET_free(sp->path);
        GNUNET_free(sp);
        return NULL ;
      }
    }
  }
  else
  {
    /* No ':' as port separator, default port for protocol */
    if (0 == strcmp (sp->protocol, "https"))
      sp->port = HTTPS_DEFAULT_PORT;
    else if (0 == strcmp (sp->protocol, "http"))
      sp->port = HTTP_DEFAULT_PORT;
    else
    {
      GNUNET_break(0);
      GNUNET_free(src);
      GNUNET_free(sp->protocol);
      GNUNET_free(sp->path);
      GNUNET_free(sp);
      return NULL ;
    }
  }
  if (strlen (host_start) > 0)
    sp->host = GNUNET_strdup (host_start);
  else
  {
    GNUNET_break(0);
    GNUNET_free(src);
    GNUNET_free(sp->protocol);
    GNUNET_free(sp->path);
    GNUNET_free(sp);
    return NULL ;
  }
  GNUNET_free(src);
  return sp;
}

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
  struct GNUNET_SCHEDULER_Task * timeout_task;

  /**
   * Splitted Address
   */
  struct SplittedHTTPAddress *saddr;

  /**
   * Plugin String
   */
  char *plugin;

  /**
   * Was conversion successful
   */
  int sucess;

  /**
   * Address options
   */
  uint32_t options;
};

/**
 * Head of PPC list
 */
static struct PrettyPrinterContext *dll_ppc_head;

/**
 * Tail of PPC list
 */
static struct PrettyPrinterContext *dll_ppc_tail;

/**
 * Function called for a quick conversion of the binary address to
 * a numeric address.  Note that the caller must not free the
 * address and that the next call to this function is allowed
 * to override the address again.
 *
 * @param plugin the name of the plugin
 * @param saddr the splitted http address
 * @param options address options
 * @param dnsresult dns name to include in address
 * @return string representing the same address or NULL on error
 */
static const char *
http_common_plugin_dnsresult_to_address (const char *plugin,
    const struct SplittedHTTPAddress *saddr,
    uint32_t options,
    const char *dnsresult)
{
  static char rbuf[1024];
  char *res;

  GNUNET_asprintf (&res, "%s.%u.%s://%s:%u%s", plugin, options, saddr->protocol,
      dnsresult, saddr->port, saddr->path);
  if (strlen (res) + 1 < 500)
  {
    memcpy (rbuf, res, strlen (res) + 1);
    GNUNET_free(res);
    return rbuf;
  }
  GNUNET_break(0);
  GNUNET_free(res);
  return NULL ;
}


static void
http_common_dns_reverse_lookup_cb (void *cls, const char *hostname)
{
  struct PrettyPrinterContext *ppc = cls;

  if (NULL != hostname)
  {
    ppc->asc (ppc->asc_cls,
        http_common_plugin_dnsresult_to_address (ppc->plugin, ppc->saddr, ppc->options,
            hostname), GNUNET_OK);
    ppc->sucess = GNUNET_YES;

  }
  else
  {
    ppc->asc (ppc->asc_cls, NULL,
        (GNUNET_NO == ppc->sucess) ? GNUNET_SYSERR : GNUNET_OK);

    GNUNET_CONTAINER_DLL_remove(dll_ppc_head, dll_ppc_tail, ppc);
    http_clean_splitted (ppc->saddr);
    GNUNET_free(ppc->plugin);
    GNUNET_free(ppc);
  }
}


static int
http_common_dns_reverse_lookup (const struct sockaddr *sockaddr,
                                socklen_t sockaddr_len,
                                const char *type,
                                struct SplittedHTTPAddress *saddr,
                                uint32_t options,
                                struct GNUNET_TIME_Relative timeout,
                                GNUNET_TRANSPORT_AddressStringCallback asc,
                                void *asc_cls)
{
  struct PrettyPrinterContext *ppc;

  ppc = GNUNET_new (struct PrettyPrinterContext);
  ppc->saddr = saddr;
  ppc->asc = asc;
  ppc->asc_cls = asc_cls;
  ppc->plugin = GNUNET_strdup (type);
  ppc->options = options;
  ppc->resolver_handle = GNUNET_RESOLVER_hostname_get (sockaddr,
                                                       sockaddr_len,
                                                       GNUNET_YES,
                                                       timeout,
                                                       &http_common_dns_reverse_lookup_cb,
                                                       ppc);
  if (NULL == ppc->resolver_handle)
  {
    GNUNET_free(ppc->plugin);
    GNUNET_free(ppc);
    return GNUNET_SYSERR;
  }
  GNUNET_CONTAINER_DLL_insert (dll_ppc_head,
                               dll_ppc_tail,
                               ppc);
  return GNUNET_OK;
}


static void
http_common_dns_ip_lookup_cb (void *cls,
                              const struct sockaddr *addr,
                              socklen_t addrlen)
{
  struct PrettyPrinterContext *ppc = cls;

  if (NULL != addr)
  {
    ppc->asc (ppc->asc_cls,
        http_common_plugin_dnsresult_to_address (ppc->plugin, ppc->saddr, ppc->options,
            GNUNET_a2s (addr, addrlen)), GNUNET_OK);
    ppc->sucess = GNUNET_YES;
    ppc->asc (ppc->asc_cls, GNUNET_a2s (addr, addrlen), GNUNET_OK);
  }
  else
  {
    ppc->asc (ppc->asc_cls, NULL,
        (GNUNET_NO == ppc->sucess) ? GNUNET_SYSERR : GNUNET_OK);

    GNUNET_CONTAINER_DLL_remove(dll_ppc_head, dll_ppc_tail, ppc);
    GNUNET_free(ppc->plugin);
    http_clean_splitted (ppc->saddr);
    GNUNET_free(ppc);
  }
}


static int
http_common_dns_ip_lookup (const char *name,
                           const char *type,
                           struct SplittedHTTPAddress *saddr,
                           uint32_t options,
                           struct GNUNET_TIME_Relative timeout,
                           GNUNET_TRANSPORT_AddressStringCallback asc, void *asc_cls)
{
  struct PrettyPrinterContext *ppc;

  ppc = GNUNET_new (struct PrettyPrinterContext);
  ppc->sucess = GNUNET_NO;
  ppc->saddr = saddr;
  ppc->asc = asc;
  ppc->asc_cls = asc_cls;
  ppc->plugin = GNUNET_strdup (type);
  ppc->options = options;
  ppc->resolver_handle = GNUNET_RESOLVER_ip_get (name,
                                                 AF_UNSPEC,
                                                 timeout,
                                                 &http_common_dns_ip_lookup_cb,
                                                 ppc);
  if (NULL == ppc->resolver_handle)
  {
    GNUNET_free(ppc->plugin);
    GNUNET_free(ppc);
    return GNUNET_SYSERR;
  }
  GNUNET_CONTAINER_DLL_insert (dll_ppc_head,
                               dll_ppc_tail,
                               ppc);
  return GNUNET_OK;
}


/**
 * Convert the transports address to a nice, human-readable
 * format.
 *
 * @param cls closure
 * @param type name of the transport that generated the address
 * @param addr one of the addresses of the host, NULL for the last address
 *        the specific address format depends on the transport
 * @param addrlen length of the @a addr
 * @param numeric should (IP) addresses be displayed in numeric form?
 * @param timeout after how long should we give up?
 * @param asc function to call on each string
 * @param asc_cls closure for @a asc
 */
void
http_common_plugin_address_pretty_printer (void *cls, const char *type,
                                           const void *addr,
                                           size_t addrlen,
                                           int numeric,
                                           struct GNUNET_TIME_Relative timeout,
                                           GNUNET_TRANSPORT_AddressStringCallback asc,
                                           void *asc_cls)
{
  const struct HttpAddress *address = addr;
  struct SplittedHTTPAddress *saddr;
  struct sockaddr *sock_addr;
  const char *ret;
  char *addr_str;
  int res;
  int have_ip;

  saddr = NULL;
  sock_addr = NULL;
  if ( (addrlen < sizeof(struct HttpAddress)) ||
       (addrlen != http_common_address_get_size (address)) )
  {
    GNUNET_break(0);
    goto handle_error;
  }

  addr_str = (char *) &address[1];
  if (addr_str[ntohl (address->urlen) - 1] != '\0')
  {
    GNUNET_break(0);
    goto handle_error;
  }

  saddr = http_split_address (addr_str);
  if (NULL == saddr)
  {
    GNUNET_break(0);
    goto handle_error;
  }

  sock_addr = http_common_socket_from_address (addr, addrlen, &res);
  if (GNUNET_SYSERR == res)
  {
    /* Malformed address */
    GNUNET_break (0);
    goto handle_error;
  }
  else if (GNUNET_NO == res)
  {
    /* Could not convert to IP */
    have_ip = GNUNET_NO;
  }
  else if (GNUNET_YES == res)
  {
    /* Converted to IP */
    have_ip = GNUNET_YES;
  }
  else
  {
    /* Must not happen */
    GNUNET_break (0);
    goto handle_error;
  }

  if ( (GNUNET_YES == numeric) &&
       (GNUNET_YES == have_ip) )
  {
    /* No lookup required */
    ret = http_common_plugin_address_to_string (type, address, addrlen);
    asc (asc_cls, ret, (NULL == ret) ? GNUNET_SYSERR : GNUNET_OK);
    asc (asc_cls, NULL, GNUNET_OK);
    http_clean_splitted (saddr);
    GNUNET_free_non_null (sock_addr);
    return;
  }
  if ( (GNUNET_YES == numeric) &&
       (GNUNET_NO == have_ip) )
  {
    /* Forward lookup */
    if (GNUNET_SYSERR ==
        http_common_dns_ip_lookup (saddr->host, type, saddr,
                                   address->options, timeout,
                                   asc, asc_cls))
    {
      GNUNET_break(0);
      goto handle_error;
    }
    /* Wait for resolver callback */
    GNUNET_free_non_null (sock_addr);
    return;
  }
  if ( (GNUNET_NO == numeric) &&
       (GNUNET_YES == have_ip) )
  {
    /* Reverse lookup */
    if (GNUNET_SYSERR ==
        http_common_dns_reverse_lookup (sock_addr,
                                        (AF_INET == sock_addr->sa_family)
                                        ? sizeof(struct sockaddr_in)
                                        : sizeof(struct sockaddr_in6),
                                        type,
                                        saddr,
                                        address->options, timeout,
                                        asc, asc_cls))
    {
      GNUNET_break(0);
      goto handle_error;
    }
    /* Wait for resolver callback */
    GNUNET_free_non_null (sock_addr);
    return;
  }
  if ( (GNUNET_NO == numeric) &&
       (GNUNET_NO == have_ip) )
  {
    /* No lookup required */
    ret = http_common_plugin_address_to_string (type, address, addrlen);
    asc (asc_cls, ret, (NULL == ret) ? GNUNET_SYSERR : GNUNET_OK);
    asc (asc_cls, NULL, GNUNET_OK);
    GNUNET_free_non_null (sock_addr);
    http_clean_splitted (saddr);
    return;
  }
  /* Error (argument supplied not GNUNET_YES or GNUNET_NO) */
  GNUNET_break (0);
  goto handle_error;

 handle_error:
  /* Report error */
  asc (asc_cls, NULL, GNUNET_SYSERR);
  asc (asc_cls, NULL, GNUNET_OK);
  GNUNET_free_non_null (sock_addr);
  if (NULL != saddr)
    http_clean_splitted (saddr);
}


/**
 * FIXME.
 */
const char *
http_common_plugin_address_to_url (void *cls,
                                   const void *addr,
                                   size_t addrlen)
{
  static char rbuf[1024];
  const struct HttpAddress *address = addr;
  const char * addr_str;

  if (NULL == addr)
  {
    GNUNET_break(0);
    return NULL;
  }
  if (0 >= addrlen)
  {
    GNUNET_break(0);
    return NULL;
  }
  if (addrlen != http_common_address_get_size (address))
  {
    GNUNET_break(0);
    return NULL;
  }
  addr_str = (char *) &address[1];
  if (addr_str[ntohl (address->urlen) - 1] != '\0')
    return NULL;

  memcpy (rbuf,
          &address[1],
          ntohl (address->urlen));
  return rbuf;
}


/**
 * Function called for a quick conversion of the binary address to
 * a numeric address.  Note that the caller must not free the
 * address and that the next call to this function is allowed
 * to override the address again.
 *
 * @param plugin the name of the plugin
 * @param addr binary address
 * @param addrlen length of the address
 * @return string representing the same address
 */
const char *
http_common_plugin_address_to_string (const char *plugin,
                                      const void *addr,
                                      size_t addrlen)
{
  static char rbuf[1024];
  const struct HttpAddress *address = addr;
  const char * addr_str;
  char *res;

  GNUNET_assert(NULL != plugin);
  if (NULL == addr)
    return NULL ;
  if (0 == addrlen)
    return NULL ;
  if (addrlen != http_common_address_get_size (address))
    return NULL ;
  addr_str = (char *) &address[1];
  if (addr_str[ntohl (address->urlen) - 1] != '\0')
    return NULL ;
  GNUNET_asprintf (&res, "%s.%u.%s", plugin, ntohl (address->options),
      &address[1]);
  if (strlen (res) + 1 < 500)
  {
    memcpy (rbuf, res, strlen (res) + 1);
    GNUNET_free(res);
    return rbuf;
  }
  GNUNET_break(0);
  GNUNET_free(res);
  return NULL ;
}

/**
 * Function called to convert a string address to
 * a binary address.
 *
 * @param cls closure ('struct Plugin*')
 * @param addr string address
 * @param addrlen length of the @a addr
 * @param buf location to store the buffer
 *        If the function returns #GNUNET_SYSERR, its contents are undefined.
 * @param added length of created address
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
int
http_common_plugin_string_to_address (void *cls,
                                      const char *addr,
                                      uint16_t addrlen,
                                      void **buf,
                                      size_t *added)
{
  struct HttpAddress *a;
  char *address;
  char *plugin;
  char *optionstr;
  size_t urlen;
  uint32_t options;

  /* Format protocol.options.address:port */
  address = NULL;
  plugin = NULL;
  optionstr = NULL;
  if ((NULL == addr) || (addrlen == 0))
  {
    GNUNET_break(0);
    return GNUNET_SYSERR;
  }
  if ('\0' != addr[addrlen - 1])
  {
    GNUNET_break(0);
    return GNUNET_SYSERR;
  }
  if (strlen (addr) != addrlen - 1)
  {
    GNUNET_break(0);
    return GNUNET_SYSERR;
  }
  plugin = GNUNET_strdup (addr);
  optionstr = strchr (plugin, '.');
  if (NULL == optionstr)
  {
    GNUNET_break(0);
    GNUNET_free(plugin);
    return GNUNET_SYSERR;
  }
  optionstr[0] = '\0';
  optionstr++;
  options = atol (optionstr); /* 0 on conversion error, that's ok */
  address = strchr (optionstr, '.');
  if (NULL == address)
  {
    GNUNET_break(0);
    GNUNET_free(plugin);
    return GNUNET_SYSERR;
  }
  address[0] = '\0';
  address++;
  urlen = strlen (address) + 1;

  a = GNUNET_malloc (sizeof (struct HttpAddress) + urlen);
  a->options = htonl (options);
  a->urlen = htonl (urlen);
  memcpy (&a[1], address, urlen);

  (*buf) = a;
  (*added) = sizeof(struct HttpAddress) + urlen;
  GNUNET_free(plugin);
  return GNUNET_OK;
}


/**
 * Create a HTTP address from a socketaddr
 *
 * @param protocol protocol
 * @param addr sockaddr * address
 * @param addrlen length of the address
 * @return the HttpAddress
 */
struct HttpAddress *
http_common_address_from_socket (const char *protocol,
                                 const struct sockaddr *addr,
                                 socklen_t addrlen)
{
  struct HttpAddress *address = NULL;
  char *res;
  size_t len;

  GNUNET_asprintf (&res,
                   "%s://%s",
                   protocol,
                   GNUNET_a2s (addr,
                               addrlen));
  len = strlen (res) + 1;
  address = GNUNET_malloc (sizeof (struct HttpAddress) + len);
  address->options = htonl (HTTP_OPTIONS_NONE);
  address->urlen = htonl (len);
  memcpy (&address[1], res, len);
  GNUNET_free(res);
  return address;
}


/**
 * Create a socketaddr from a HTTP address
 *
 * @param addr a `sockaddr *` address
 * @param addrlen length of the @a addr
 * @param res the result:
 *   #GNUNET_SYSERR, invalid input,
 *   #GNUNET_YES: could convert to ip,
 *   #GNUNET_NO: valid input but could not convert to ip (hostname?)
 * @return the string
 */
struct sockaddr *
http_common_socket_from_address (const void *addr,
                                 size_t addrlen,
                                 int *res)
{
  const struct HttpAddress *ha;
  struct SplittedHTTPAddress * spa;
  struct sockaddr_storage *s;
  char * to_conv;
  size_t urlen;

  (*res) = GNUNET_SYSERR;
  ha = (const struct HttpAddress *) addr;
  if (NULL == addr)
  {
    GNUNET_break (0);
    return NULL;
  }
  if (0 >= addrlen)
  {
    GNUNET_break (0);
    return NULL;
  }
  if (addrlen < sizeof(struct HttpAddress))
  {
    GNUNET_break (0);
    return NULL;
  }
  urlen = ntohl (ha->urlen);
  if (sizeof(struct HttpAddress) + urlen != addrlen)
  {
    /* This is a legacy addresses */
    return NULL;
  }
  if (addrlen < sizeof(struct HttpAddress) + urlen)
  {
    /* This is a legacy addresses */
    return NULL;
  }
  if (((char *) addr)[addrlen - 1] != '\0')
  {
    GNUNET_break (0);
    return NULL;
  }
  spa = http_split_address ((const char *) &ha[1]);
  if (NULL == spa)
  {
    (*res) = GNUNET_SYSERR;
    return NULL;
  }

  s = GNUNET_new (struct sockaddr_storage);
  GNUNET_asprintf (&to_conv, "%s:%u", spa->host, spa->port);
  if (GNUNET_SYSERR
      == GNUNET_STRINGS_to_address_ip (to_conv, strlen (to_conv), s))
  {
    /* could be a hostname */
    GNUNET_free(s);
    (*res) = GNUNET_NO;
    s = NULL;
  }
  else if ((AF_INET != s->ss_family) && (AF_INET6 != s->ss_family))
  {
    GNUNET_free (s);
    (*res) = GNUNET_SYSERR;
    s = NULL;
  }
  else
  {
    (*res) = GNUNET_YES;
  }
  http_clean_splitted (spa);
  GNUNET_free (to_conv);
  return (struct sockaddr *) s;
}


/**
 * Get the length of an address
 *
 * @param addr address
 * @return the size
 */
size_t
http_common_address_get_size (const struct HttpAddress * addr)
{
  return sizeof(struct HttpAddress) + ntohl (addr->urlen);
}


/**
 * Compare addr1 to addr2
 *
 * @param addr1 address1
 * @param addrlen1 address 1 length
 * @param addr2 address2
 * @param addrlen2 address 2 length
 * @return #GNUNET_YES if equal, #GNUNET_NO if not, #GNUNET_SYSERR on error
 */
size_t
http_common_cmp_addresses (const void *addr1, size_t addrlen1,
    const void *addr2, size_t addrlen2)
{
  const char *a1 = addr1;
  const char *a2 = addr2;
  const struct HttpAddress *ha1;
  const struct HttpAddress *ha2;
  ha1 = (const struct HttpAddress *) a1;
  ha2 = (const struct HttpAddress *) a2;

  if (NULL == a1)
    return GNUNET_SYSERR;
  if (0 >= addrlen1)
    return GNUNET_SYSERR;
  if (a1[addrlen1 - 1] != '\0')
    return GNUNET_SYSERR;

  if (NULL == a2)
    return GNUNET_SYSERR;
  if (0 >= addrlen2)
    return GNUNET_SYSERR;
  if (a2[addrlen2 - 1] != '\0')
    return GNUNET_SYSERR;

  if (addrlen1 != addrlen2)
    return GNUNET_NO;
  if (ha1->urlen != ha2->urlen)
    return GNUNET_NO;

  if (0 == strcmp ((const char *) &ha1[1], (const char *) &ha2[1]))
    return GNUNET_YES;
  return GNUNET_NO;
}

/* end of plugin_transport_http_common.c */
