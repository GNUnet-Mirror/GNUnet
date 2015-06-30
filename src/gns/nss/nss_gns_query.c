/*
     This file is part of GNUnet.
     Copyright (C) 2012 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
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
  pclose (p);
  free (cmd);
  return 0;
}
/* end of nss_gns_query.c */
