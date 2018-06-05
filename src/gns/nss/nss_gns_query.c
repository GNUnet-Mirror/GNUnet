/*
     This file is part of GNUnet.
     Copyright (C) 2012 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
*/
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "nss_gns_query.h"
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>


/**
 * Wrapper function that uses gnunet-gns cli tool to resolve
 * an IPv4/6 address.
 *
 * @param af address family
 * @param name the name to resolve
 * @param u the userdata (result struct)
 * @return -1 on error else 0
 */
int
gns_resolve_name (int af,
		  const char *name,
		  struct userdata *u)
{
  FILE *p;
  char *cmd;
  char line[128];
  int ret;

  if (AF_INET6 == af)
  {
    if (-1 == asprintf (&cmd,
			"%s -t AAAA -u %s\n",
			"gnunet-gns -r", name))
      return -1;
  }
  else
  {
    if (-1 == asprintf (&cmd,
			"%s %s\n",
			"gnunet-gns -r -u", name))
      return -1;
  }
  if (NULL == (p = popen (cmd, "r")))
  {
    free (cmd);
    return -1;
  }
  while (NULL != fgets (line, sizeof(line), p))
  {
    if (u->count >= MAX_ENTRIES)
      break;
    if (line[strlen(line)-1] == '\n')
    {
      line[strlen(line)-1] = '\0';
      if (AF_INET == af)
      {
	if (inet_pton(af, line, &(u->data.ipv4[u->count])))
        {
	  u->count++;
	  u->data_len += sizeof(ipv4_address_t);
	}
	else
	{
	  pclose (p);
	  free (cmd);
	  return -1;
	}
      }
      else if (AF_INET6 == af)
      {
	if (inet_pton(af, line, &(u->data.ipv6[u->count])))
        {
	  u->count++;
	  u->data_len += sizeof(ipv6_address_t);
	}
	else
        {
	  pclose (p);
	  free (cmd);
	  return -1;
	}
      }
    }
  }
  ret = pclose (p);
  free (cmd);
  if (4 == ret)
    return -2; /* not for GNS */
  if (3 == ret)
    return -3; /* timeout */
  return 0;
}
/* end of nss_gns_query.c */
