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
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_tun_lib.h"


/**
 * Create a regex in @a rxstr from the given @a ip and @a netmask.
 *
 * @param ip IPv4 representation.
 * @param port destination port
 * @param rxstr generated regex, must be at least #GNUNET_TUN_IPV4_REGEXLEN
 *              bytes long.
 */
void
GNUNET_TUN_ipv4toregexsearch (const struct in_addr *ip,
                              uint16_t port,
                              char *rxstr)
{
  GNUNET_snprintf (rxstr,
                   GNUNET_TUN_IPV4_REGEXLEN,
                   "4-%04X-%08X",
                   (unsigned int) port,
                   ntohl (ip->s_addr));
}


/**
 * Create a regex in @a rxstr from the given @a ipv6 and @a prefixlen.
 *
 * @param ipv6 IPv6 representation.
 * @param port destination port
 * @param rxstr generated regex, must be at least #GNUNET_TUN_IPV6_REGEXLEN
 *              bytes long.
 */
void
GNUNET_TUN_ipv6toregexsearch (const struct in6_addr *ipv6,
                              uint16_t port,
                              char *rxstr)
{
  const uint32_t *addr;

  addr = (const uint32_t *) ipv6;
  GNUNET_snprintf (rxstr,
                   GNUNET_TUN_IPV6_REGEXLEN,
                   "6-%04X-%08X%08X%08X%08X",
                   (unsigned int) port,
                   ntohl (addr[0]),
                   ntohl (addr[1]),
                   ntohl (addr[2]),
                   ntohl (addr[3]));
}


/**
 * Convert the given 4-bit (!) number to a regex.
 *
 * @param value the value, only the lowest 4 bits will be looked at
 * @param mask which bits in value are wildcards (any value)?
 */
static char *
nibble_to_regex (uint8_t value,
                 uint8_t mask)
{
  char *ret;

  value &= mask;
  switch (mask)
  {
  case 0:
    return GNUNET_strdup ("."); /* wildcard */
  case 8:
    GNUNET_asprintf (&ret,
                     "(%X|%X|%X|%X|%X|%X|%X|%X)",
                     value,
                     value + 1,
                     value + 2,
                     value + 3,
                     value + 4,
                     value + 5,
                     value + 6,
                     value + 7);
    return ret;
  case 12:
    GNUNET_asprintf (&ret,
                     "(%X|%X|%X|%X)",
                     value,
                     value + 1,
                     value + 2,
                     value + 3);
    return ret;
  case 14:
    GNUNET_asprintf (&ret,
                     "(%X|%X)",
                     value,
                     value + 1);
    return ret;
  case 15:
    GNUNET_asprintf (&ret,
                     "%X",
                     value);
    return ret;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Bad mask: %d\n"),
                mask);
    GNUNET_break (0);
    return NULL;
  }
}


/**
 * Convert the given 16-bit number to a regex.
 *
 * @param value the value
 * @param mask which bits in value are wildcards (any value)?
 */
static char *
num_to_regex (uint16_t value,
              uint16_t mask)
{
  const uint8_t *v = (const uint8_t *) &value;
  const uint8_t *m = (const uint8_t *) &mask;
  char *a;
  char *b;
  char *c;
  char *d;
  char *ret;

  a = nibble_to_regex (v[0] >> 4, m[0] >> 4);
  b = nibble_to_regex (v[0] & 15, m[0] & 15);
  c = nibble_to_regex (v[1] >> 4, m[1] >> 4);
  d = nibble_to_regex (v[1] & 15, m[1] & 15);
  ret = NULL;
  if ( (NULL != a) &&
       (NULL != b) &&
       (NULL != c) &&
       (NULL != d) )
    GNUNET_asprintf (&ret,
                     "%s%s%s%s",
                     a, b, c, d);
  GNUNET_free_non_null (a);
  GNUNET_free_non_null (b);
  GNUNET_free_non_null (c);
  GNUNET_free_non_null (d);
  return ret;
}


/**
 * Convert a port policy to a regular expression.  Note: this is a
 * very simplistic implementation, we might want to consider doing
 * something more sophisiticated (resulting in smaller regular
 * expressions) at a later time.
 *
 * @param pp port policy to convert
 * @return NULL on error
 */
static char *
port_to_regex (const struct GNUNET_STRINGS_PortPolicy *pp)
{
  char *reg;
  char *ret;
  char *pos;
  unsigned int i;
  unsigned int cnt;

  if ( (0 == pp->start_port) ||
       ( (1 == pp->start_port) &&
         (0xFFFF == pp->end_port) &&
         (GNUNET_NO == pp->negate_portrange)) )
    return GNUNET_strdup ("....");
  if ( (pp->start_port == pp->end_port) &&
       (GNUNET_NO == pp->negate_portrange))
  {
    GNUNET_asprintf (&ret,
                     "%04X",
                     pp->start_port);
    return ret;
  }
  if (pp->end_port < pp->start_port)
    return NULL;
  cnt = pp->end_port - pp->start_port + 1;
  if (GNUNET_YES == pp->negate_portrange)
    cnt = 0xFFFF - cnt;
  reg = GNUNET_malloc (cnt * 5 + 1);
  pos = reg;
  for (i=1;i<=0xFFFF;i++)
  {
    if ( ( (i >= pp->start_port) && (i <= pp->end_port) ) ^
         (GNUNET_YES == pp->negate_portrange) )
    {
      if (pos == reg)
      {
        GNUNET_snprintf (pos,
                         5,
                         "%04X",
                         i);
      }
      else
      {
        GNUNET_snprintf (pos,
                         6,
                         "|%04X",
                         i);
      }
      pos += strlen (pos);
    }
  }
  GNUNET_asprintf (&ret,
                   "(%s)",
                   reg);
  GNUNET_free (reg);
  return ret;
}


/**
 * Convert an address (IPv4 or IPv6) to a regex.
 *
 * @param addr address
 * @param mask network mask
 * @param len number of bytes in @a addr and @a mask
 * @return NULL on error, otherwise regex for the address
 */
static char *
address_to_regex (const void *addr,
                  const void *mask,
                  size_t len)
{
  const uint16_t *a = addr;
  const uint16_t *m = mask;
  char *ret;
  char *tmp;
  char *reg;
  unsigned int i;

  ret = NULL;
  GNUNET_assert (1 != (len % 2));
  for (i=0;i<len / 2;i++)
  {
    reg = num_to_regex (a[i], m[i]);
    if (NULL == reg)
    {
      GNUNET_free_non_null (ret);
      return NULL;
    }
    if (NULL == ret)
    {
      ret = reg;
    }
    else
    {
      GNUNET_asprintf (&tmp,
                       "%s%s",
                       ret, reg);
      GNUNET_free (ret);
      GNUNET_free (reg);
      ret = tmp;
    }
  }
  return ret;
}


/**
 * Convert a single line of an IPv4 policy to a regular expression.
 *
 * @param v4 line to convert
 * @return NULL on error
 */
static char *
ipv4_to_regex (const struct GNUNET_STRINGS_IPv4NetworkPolicy *v4)
{
  char *reg;
  char *pp;
  char *ret;

  reg = address_to_regex (&v4->network,
                          &v4->netmask,
                          sizeof (struct in_addr));
  if (NULL == reg)
    return NULL;
  pp = port_to_regex (&v4->pp);
  if (NULL == pp)
  {
    GNUNET_free (reg);
    return NULL;
  }
  GNUNET_asprintf (&ret,
                   "4-%s-%s",
                   pp, reg);
  GNUNET_free (pp);
  GNUNET_free (reg);
  return ret;
}


/**
 * Convert a single line of an IPv4 policy to a regular expression.
 *
 * @param v6 line to convert
 * @return NULL on error
 */
static char *
ipv6_to_regex (const struct GNUNET_STRINGS_IPv6NetworkPolicy *v6)
{
  char *reg;
  char *pp;
  char *ret;

  reg = address_to_regex (&v6->network,
                          &v6->netmask,
                          sizeof (struct in6_addr));
  if (NULL == reg)
    return NULL;
  pp = port_to_regex (&v6->pp);
  if (NULL == pp)
  {
    GNUNET_free (reg);
    return NULL;
  }
  GNUNET_asprintf (&ret,
                   "6-%s-%s",
                   pp, reg);
  GNUNET_free (pp);
  GNUNET_free (reg);
  return ret;
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
  struct GNUNET_STRINGS_IPv4NetworkPolicy *np;
  char *reg;
  char *tmp;
  char *line;
  unsigned int i;

  np = GNUNET_STRINGS_parse_ipv4_policy (policy);
  if (NULL == np)
    return NULL;
  reg = NULL;
  for (i=0; (0 == i) || (0 != np[i].network.s_addr); i++)
  {
    line = ipv4_to_regex (&np[i]);
    if (NULL == line)
    {
      GNUNET_free_non_null (reg);
      GNUNET_free (np);
      return NULL;
    }
    if (NULL == reg)
    {
      reg = line;
    }
    else
    {
      GNUNET_asprintf (&tmp,
                       "%s|(%s)",
                       reg, line);
      GNUNET_free (reg);
      GNUNET_free (line);
      reg = tmp;
    }
    if (0 == np[i].network.s_addr)
      break;
  }
  GNUNET_free (np);
  return reg;
}


/**
 * Convert an exit policy to a regular expression.  The exit policy
 * specifies a set of subnets this peer is willing to serve as an
 * exit for; the resulting regular expression will match the
 * IPv6 address strings as returned by #GNUNET_TUN_ipv6toregexsearch().
 *
 * @param policy exit policy specification
 * @return regular expression, NULL on error
 */
char *
GNUNET_TUN_ipv6policy2regex (const char *policy)
{
  struct in6_addr zero;
  struct GNUNET_STRINGS_IPv6NetworkPolicy *np;
  char *reg;
  char *tmp;
  char *line;
  unsigned int i;

  np = GNUNET_STRINGS_parse_ipv6_policy (policy);
  if (NULL == np)
    return NULL;
  reg = NULL;
  memset (&zero, 0, sizeof (struct in6_addr));
  for (i=0; (0 == i) || (0 != memcmp (&zero, &np[i].network, sizeof (struct in6_addr))); i++)
  {
    line = ipv6_to_regex (&np[i]);
    if (NULL == line)
    {
      GNUNET_free_non_null (reg);
      GNUNET_free (np);
      return NULL;
    }
    if (NULL == reg)
    {
      reg = line;
    }
    else
    {
      GNUNET_asprintf (&tmp,
                       "%s|(%s)",
                       reg, line);
      GNUNET_free (reg);
      GNUNET_free (line);
      reg = tmp;
    }
    if (0 == memcmp (&zero, &np[i].network, sizeof (struct in6_addr)))
      break;
  }
  GNUNET_free (np);
  return reg;
}


/* end of regex.c */
