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
 * @file transport/plugin_transport_http_common.c
 * @brief functionality shared by http client and server transport service plugin
 * @author Matthias Wachs
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_transport_plugin.h"

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
void
http_common_plugin_address_pretty_printer (void *cls, const char *type,
                                        const void *addr, size_t addrlen,
                                        int numeric,
                                        struct GNUNET_TIME_Relative timeout,
                                        GNUNET_TRANSPORT_AddressStringCallback
                                        asc, void *asc_cls)
{
  const char *saddr = (const char *) addr;
  if (NULL == saddr)
  {
      asc (asc_cls, NULL);
      return;
  }
  if (0 >= addrlen)
  if (NULL == saddr)
  {
      asc (asc_cls, NULL);
      return;
  }
  if (saddr[addrlen-1] != '\0')
  {
      asc (asc_cls, NULL);
      return;
  }
  asc (asc_cls, saddr);
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
http_common_plugin_address_to_string (void *cls, const void *addr, size_t addrlen)
{
  const char *saddr = (const char *) addr;
  if (NULL == saddr)
      return NULL;
  if (0 >= addrlen)
    return NULL;
  if (saddr[addrlen-1] != '\0')
    return NULL;
  return saddr;
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
http_common_plugin_string_to_address (void *cls,
                        const char *addr,
                        uint16_t addrlen,
                        void **buf,
                        size_t *added)
{
  if (NULL == addr)
      return GNUNET_SYSERR;
  if (0 >= addrlen)
    return GNUNET_SYSERR;
  if (addr[addrlen-1] != '\0')
    return GNUNET_SYSERR;

  (*buf) = strdup (addr);
  (*added) = strlen (addr) + 1;
  return GNUNET_OK;
}

/**
 * Create a HTTP address from a socketaddr
 *
 * @param protocol protocol
 * @param addr sockaddr * address
 * @param addrlen length of the address
 * @return the string
 */
char *
http_common_address_from_socket (const char *protocol, const struct sockaddr *addr, socklen_t addrlen)
{
  char *res;
  GNUNET_asprintf(&res, "%s://%s", protocol, GNUNET_a2s (addr, addrlen));
  return res;
}

/**
 * Create a socketaddr from a HTTP address
 *
 * @param addr sockaddr * address
 * @param addrlen length of the address
 * @param res the result:
 * GNUNET_SYSERR, invalid input,
 * GNUNET_YES: could convert to ip,
 * GNUNET_NO: valid input but could not convert to ip (hostname?)
 * @return the string
 */
struct sockaddr *
http_common_socket_from_address (const void *addr, size_t addrlen, int *res)
{
  struct sockaddr_storage *s;
  char *addrs;
  char *addrs_org;
  char *addrs_end;
  (*res) = GNUNET_SYSERR;

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
  if (((char *) addr)[addrlen-1] != '\0')
    {
      GNUNET_break (0);
      return NULL;
    }

  addrs_org = strdup ((char *) addr);
  addrs = strstr (addrs_org , "://");
  if (NULL == addrs)
  {
    GNUNET_break (0);
    GNUNET_free (addrs_org);
    return NULL;
  }

  if (strlen (addrs) < 3)
  {
    GNUNET_break (0);
    GNUNET_free (addrs_org);
    return NULL;
  }

  addrs += 3;

  addrs_end = strchr (addrs, '/');
  if (NULL != addrs_end)
    addrs[strlen (addrs) - strlen(addrs_end)] = '\0';

  s = GNUNET_malloc (sizeof (struct sockaddr_storage));
  if (GNUNET_SYSERR == GNUNET_STRINGS_to_address_ip (addrs, strlen(addrs), s))
  {
    /* could be a hostname */
    GNUNET_free (s);
    GNUNET_free (addrs_org);
    (*res) = GNUNET_NO;
    return NULL;
  }
  else
  {
    if ((AF_INET != s->ss_family) && (AF_INET6 != s->ss_family))
    {
      GNUNET_break (0);
      GNUNET_free (s);
      GNUNET_free (addrs_org);
      (*res) = GNUNET_SYSERR;
      return NULL;
    }
  }
  (*res) = GNUNET_YES;
  GNUNET_free (addrs_org);
  return (struct sockaddr *) s;
}

/**
 * Get the length of an address
 *
 * @param addr address
 * @return the size
 */
size_t
http_common_address_get_size (const void *addr)
{
 return strlen (addr) + 1;
}

/**
 * Compare addr1 to addr2
 *
 * @param addr1 address1
 * @param addrlen1 address 1 length
 * @param addr2 address2
 * @param addrlen2 address 2 length
 * @return GNUNET_YES if equal, GNUNET_NO if not, GNUNET_SYSERR on error
 */
int
http_common_cmp_addresses (const void *addr1, size_t addrlen1, const void *addr2, size_t addrlen2)
{
  const char *a1 = (const char *) addr1;
  const char *a2 = (const char *) addr2;

  if (NULL == a1)
      return GNUNET_SYSERR;
  if (0 >= addrlen1)
    return GNUNET_SYSERR;
  if (a1[addrlen1-1] != '\0')
    return GNUNET_SYSERR;

  if (NULL == a2)
      return GNUNET_SYSERR;
  if (0 >= addrlen2)
    return GNUNET_SYSERR;
  if (a2[addrlen2-1] != '\0')
    return GNUNET_SYSERR;

  if (addrlen1 != addrlen2)
    return GNUNET_NO;

  if (0 == strcmp (addr1, addr2))
    return GNUNET_YES;
  return GNUNET_NO;
}



/* end of plugin_transport_http_common.c */
