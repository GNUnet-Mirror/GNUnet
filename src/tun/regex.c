/*
     This file is part of GNUnet
     Copyright (C) 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * Do we need to put parents around the given argument?
 *
 * @param arg part of a regular expression
 * @return #GNUNET_YES if we should parens,
 *         #GNUNET_NO if not
 */
static int
needs_parens (const char *arg)
{
  size_t off;
  size_t len;
  unsigned int op;

  op = 0;
  len = strlen (arg);
  for (off=0;off<len;off++)
  {
    switch (arg[off])
    {
    case '(':
      op++;
      break;
    case ')':
      GNUNET_assert (op > 0);
      op--;
      break;
    case '|':
      if (0 == op)
        return GNUNET_YES;
      break;
    default:
      break;
    }
  }
  return GNUNET_NO;
}


/**
 * Compute port policy for the given range of
 * port numbers.
 *
 * @param start starting offset
 * @param end end offset
 * @param step increment level (power of 16)
 * @param pp port policy to convert
 * @return corresponding regex
 */
static char *
compute_policy (unsigned int start,
                unsigned int end,
                unsigned int step,
                const struct GNUNET_STRINGS_PortPolicy *pp)
{
  unsigned int i;
  char before[36]; /* 16 * 2 + 3 dots + 0-terminator */
  char middlel[33]; /* 16 * 2 + 0-terminator */
  char middleh[33]; /* 16 * 2 + 0-terminator */
  char after[36]; /* 16 * 2 + 3 dots + 0-terminator */
  char beforep[36+2]; /* 16 * 2 + 3 dots + 0-terminator + ()*/
  char middlehp[33+2]; /* 16 * 2 + 0-terminator + () */
  char middlelp[33+2]; /* 16 * 2 + 0-terminator + () */
  char afterp[36+2]; /* 16 * 2 + 3 dots + 0-terminator + () */
  char dots[4];
  char buf[3];
  char *middle;
  char *ret;
  unsigned int xstep;
  char *recl;
  char *rech;
  char *reclp;
  char *rechp;
  unsigned int start_port;
  unsigned int end_port;

  GNUNET_assert (GNUNET_YES == pp->negate_portrange);
  start_port = pp->start_port;
  if (1 == start_port)
    start_port = 0;
  end_port = pp->end_port;
  GNUNET_assert ((end - start) / step <= 0xF);
  before[0] = '\0';
  middlel[0] = '\0';
  middleh[0] = '\0';
  after[0] = '\0';
  for (i=start;i<=end;i+=step)
  {
    GNUNET_snprintf (buf,
                     sizeof (buf),
                     "%X|",
                     (i - start) / step);
    if (i / step < start_port / step)
      strcat (before, buf);
    else if (i / step > end_port / step)
      strcat (after, buf);
    else if (i / step == start_port / step)
      strcat (middlel, buf);
    else if (i / step == end_port / step)
      strcat (middleh, buf);
  }
  if (strlen (before) > 0)
    before[strlen (before)-1] = '\0';
  if (strlen (middlel) > 0)
    middlel[strlen (middlel)-1] = '\0';
  if (strlen (middleh) > 0)
    middleh[strlen (middleh)-1] = '\0';
  if (strlen (after) > 0)
    after[strlen (after)-1] = '\0';
  if (needs_parens (before))
    GNUNET_snprintf (beforep,
                     sizeof (beforep),
                     "(%s)",
                     before);
  else
    strcpy (beforep, before);
  if (needs_parens (middlel))
    GNUNET_snprintf (middlelp,
                     sizeof (middlelp),
                     "(%s)",
                     middlel);
  else
    strcpy (middlelp, middlel);
  if (needs_parens (middleh))
    GNUNET_snprintf (middlehp,
                     sizeof (middlehp),
                     "(%s)",
                     middleh);
  else
    strcpy (middlehp, middleh);
  if (needs_parens (after))
    GNUNET_snprintf (afterp,
                     sizeof (afterp),
                     "(%s)",
                     after);
  else
    strcpy (afterp, after);
  dots[0] = '\0';
  for (xstep=step/16;xstep>0;xstep/=16)
    strcat (dots, ".");
  if (step >= 16)
  {
    if (strlen (middlel) > 0)
      recl = compute_policy ((start_port / step) * step,
                             (start_port / step) * step + step - 1,
                             step / 16,
                             pp);
    else
      recl = GNUNET_strdup ("");
    if (strlen (middleh) > 0)
      rech = compute_policy ((end_port / step) * step,
                             (end_port / step) * step + step - 1,
                             step / 16,
                             pp);
    else
      rech = GNUNET_strdup ("");
  }
  else
  {
    recl = GNUNET_strdup ("");
    rech = GNUNET_strdup ("");
    middlel[0] = '\0';
    middlelp[0] = '\0';
    middleh[0] = '\0';
    middlehp[0] = '\0';
  }
  if (needs_parens (recl))
    GNUNET_asprintf (&reclp,
                     "(%s)",
                     recl);
  else
    reclp = GNUNET_strdup (recl);
  if (needs_parens (rech))
    GNUNET_asprintf (&rechp,
                     "(%s)",
                     rech);
  else
    rechp = GNUNET_strdup (rech);

  if ( (strlen (middleh) > 0) &&
       (strlen (rech) > 0) &&
       (strlen (middlel) > 0) &&
       (strlen (recl) > 0) )
  {
    GNUNET_asprintf (&middle,
                     "%s%s|%s%s",
                     middlel,
                     reclp,
                     middleh,
                     rechp);
  }
  else if ( (strlen (middleh) > 0) &&
            (strlen (rech) > 0) )
  {
    GNUNET_asprintf (&middle,
                     "%s%s",
                     middleh,
                     rechp);
  }
  else if ( (strlen (middlel) > 0) &&
            (strlen (recl) > 0) )
  {
    GNUNET_asprintf (&middle,
                     "%s%s",
                     middlel,
                     reclp);
  }
  else
  {
    middle = GNUNET_strdup ("");
  }
  if ( (strlen(before) > 0) &&
       (strlen(after) > 0) )
  {
    if (strlen (dots) > 0)
    {
      if (strlen (middle) > 0)
        GNUNET_asprintf (&ret,
                         "(%s%s|%s|%s%s)",
                         beforep, dots,
                         middle,
                         afterp, dots);
      else
        GNUNET_asprintf (&ret,
                         "(%s|%s)%s",
                         beforep,
                         afterp,
                         dots);
    }
    else
    {
      if (strlen (middle) > 0)
        GNUNET_asprintf (&ret,
                         "(%s|%s|%s)",
                         before,
                         middle,
                         after);
      else if (1 == step)
        GNUNET_asprintf (&ret,
                         "%s|%s",
                         before,
                         after);
      else
        GNUNET_asprintf (&ret,
                         "(%s|%s)",
                         before,
                         after);
    }
  }
  else if (strlen (before) > 0)
  {
    if (strlen (dots) > 0)
    {
      if (strlen (middle) > 0)
        GNUNET_asprintf (&ret,
                         "(%s%s|%s)",
                         beforep, dots,
                         middle);
      else
        GNUNET_asprintf (&ret,
                         "%s%s",
                         beforep, dots);
    }
    else
    {
      if (strlen (middle) > 0)
        GNUNET_asprintf (&ret,
                         "(%s|%s)",
                         before,
                         middle);
      else
        GNUNET_asprintf (&ret,
                         "%s",
                         before);
    }
  }
  else if (strlen (after) > 0)
  {
    if (strlen (dots) > 0)
    {
      if (strlen (middle) > 0)
        GNUNET_asprintf (&ret,
                         "(%s|%s%s)",
                         middle,
                         afterp, dots);
      else
        GNUNET_asprintf (&ret,
                         "%s%s",
                         afterp, dots);
    }
    else
    {
      if (strlen (middle) > 0)
        GNUNET_asprintf (&ret,
                         "%s|%s",
                         middle,
                         after);
      else
        GNUNET_asprintf (&ret,
                         "%s",
                         after);
    }
  }
  else if (strlen (middle) > 0)
  {
    GNUNET_asprintf (&ret,
                     "%s",
                     middle);
  }
  else
  {
    ret = GNUNET_strdup ("");
  }
  GNUNET_free (middle);
  GNUNET_free (reclp);
  GNUNET_free (rechp);
  GNUNET_free (recl);
  GNUNET_free (rech);
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

  if (GNUNET_YES == pp->negate_portrange)
  {
    ret = compute_policy (0, 0xFFFF, 0x1000, pp);
  }
  else
  {
    cnt = pp->end_port - pp->start_port + 1;
    reg = GNUNET_malloc (cnt * 5 + 1);
    pos = reg;
    for (i=1;i<=0xFFFF;i++)
    {
      if ( (i >= pp->start_port) && (i <= pp->end_port) )
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
  }
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


/**
 * Hash the service name of a hosted service to the
 * hash code that is used to identify the service on
 * the network.
 *
 * @param service_name a string
 * @param hc corresponding hash
 */
void
GNUNET_TUN_service_name_to_hash (const char *service_name,
                                 struct GNUNET_HashCode *hc)
{
  GNUNET_CRYPTO_hash (service_name,
                      strlen (service_name),
                      hc);
}


/* end of regex.c */
