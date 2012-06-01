#ifndef NSS_GNS_QUERY_H
#define NSS_GNS_QUERY_H

/**
 * Parts taken from nss-mdns. Original license statement follows
 */

/* $Id$ */

/***
  This file is part of nss-mdns.
 
  nss-mdns is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2 of the
  License, or (at your option) any later version.
 
  nss-mdns is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.
 
  You should have received a copy of the GNU Lesser General Public
  License along with nss-mdns; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
  USA.
***/

#include <inttypes.h>

/* Maximum number of entries to return */
#define MAX_ENTRIES 16

typedef struct {
    uint32_t address;
} ipv4_address_t;

typedef struct {
    uint8_t address[16];
} ipv6_address_t;


struct userdata {
  int count;
  int data_len; /* only valid when doing reverse lookup */
  union  {
      ipv4_address_t ipv4[MAX_ENTRIES];
      ipv6_address_t ipv6[MAX_ENTRIES];
      char *name[MAX_ENTRIES];
  } data;
};

/**
 * Wrapper function that uses gnunet-gns cli tool to resolve
 * an IPv4/6 address.
 *
 * @param af address family
 * @param name the name to resolve
 * @param u the userdata (result struct)
 * @return -1 on error else 0
 */
int gns_resolve_name(int af,
               const char *name,
               struct userdata *userdata);

#endif
