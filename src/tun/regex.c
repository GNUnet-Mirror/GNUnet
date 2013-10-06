/*
     This file is part of GNUnet
     (C) 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @file src/tun/regex.c
 * @brief functions to convert IP networks to regexes
 * @author Maximilian Szengel
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_tun_lib.h"


/**
 * Create a string with binary IP notation for the given 'addr' in 'str'.
 *
 * @param af address family of the given 'addr'.
 * @param addr address that should be converted to a string.
 *             struct in_addr * for IPv4 and struct in6_addr * for IPv6.
 * @param str string that will contain binary notation of 'addr'. Expected
 *            to be at least 33 bytes long for IPv4 and 129 bytes long for IPv6.
 */
static void
iptobinstr (const int af, const void *addr, char *str)
{
  int i;

  switch (af)
  {
    case AF_INET:
    {
      uint32_t b = htonl (((struct in_addr *) addr)->s_addr);

      str[32] = '\0';
          str += 31;
          for (i = 31; i >= 0; i--)
          {
            *str = (b & 1) + '0';
            str--;
            b >>= 1;
          }
              break;
    }
    case AF_INET6:
    {
      struct in6_addr b = *(const struct in6_addr *) addr;

      str[128] = '\0';
            str += 127;
            for (i = 127; i >= 0; i--)
            {
              *str = (b.s6_addr[i / 8] & 1) + '0';
            str--;
            b.s6_addr[i / 8] >>= 1;
            }
                break;
    }
  }
}


/**
 * Get the ipv4 network prefix from the given 'netmask'.
 *
 * @param netmask netmask for which to get the prefix len.
 *
 * @return length of ipv4 prefix for 'netmask'.
 */
static unsigned int
ipv4netmasktoprefixlen (const char *netmask)
{
  struct in_addr a;
  unsigned int len;
  uint32_t t;

  if (1 != inet_pton (AF_INET, netmask, &a))
    return 0;
  len = 32;
  for (t = htonl (~a.s_addr); 0 != t; t >>= 1)
    len--;
  return len;
}


/**
 * Create a regex in 'rxstr' from the given 'ip' and 'netmask'.
 *
 * @param ip IPv4 representation.
 * @param netmask netmask for the ip.
 * @param rxstr generated regex, must be at least GNUNET_REGEX_IPV4_REGEXLEN
 *              bytes long.
 */
void
GNUNET_TUN_ipv4toregexsearch (const struct in_addr *ip, const char *netmask,
			char *rxstr)
{
  unsigned int pfxlen;

  pfxlen = ipv4netmasktoprefixlen (netmask);
  iptobinstr (AF_INET, ip, rxstr);
  rxstr[pfxlen] = '\0';
            if (pfxlen < 32)
              strcat (rxstr, "(0|1)+");
}


/**
 * Create a regex in 'rxstr' from the given 'ipv6' and 'prefixlen'.
 *
 * @param ipv6 IPv6 representation.
 * @param prefixlen length of the ipv6 prefix.
 * @param rxstr generated regex, must be at least GNUNET_REGEX_IPV6_REGEXLEN
 *              bytes long.
 */
void
GNUNET_TUN_ipv6toregexsearch (const struct in6_addr *ipv6, unsigned int prefixlen,
			char *rxstr)
{
  iptobinstr (AF_INET6, ipv6, rxstr);
  rxstr[prefixlen] = '\0';
    if (prefixlen < 128)
      strcat (rxstr, "(0|1)+");
}


/**
 * Convert an exit policy to a regular expression.  The exit policy
 * specifies a set of subnets this peer is willing to serve as an
 * exit for; the resulting regular expression will match the
 * IPv4 address strings as returned by 'GNUNET_TUN_ipv4toregexsearch'.
 *
 * @param policy exit policy specification
 * @return regular expression, NULL on error
 */
char *
GNUNET_TUN_ipv4policy2regex (const char *policy)
{
  // FIXME: do actual policy parsing here, see #2919
  return GNUNET_strdup (policy);
}


/**
 * Convert an exit policy to a regular expression.  The exit policy
 * specifies a set of subnets this peer is willing to serve as an
 * exit for; the resulting regular expression will match the
 * IPv4 address strings as returned by 'GNUNET_TUN_ipv4toregexsearch'.
 *
 * @param policy exit policy specification
 * @return regular expression, NULL on error
 */
char *
GNUNET_TUN_ipv6policy2regex (const char *policy)
{
  // FIXME: do actual policy parsing here, see #2919
  return GNUNET_strdup (policy);
}


/* end of regex.c */
