#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "nss_gns_query.h"
#include <arpa/inet.h>


/**
 * Wrapper function that uses gnunet-gns cli tool to resolve
 * an IPv4/6 address.
 *
 * @param af address family
 * @param name the name to resolve
 * @param u the userdata (result struct)
 * @return -1 on error else 0
 */
int gns_resolve_name(int af, const char *name, struct userdata *u)
{
  FILE *p;
  char *cmd;
  char line[128];

  if (af == AF_INET6)
  {
    if (-1 == asprintf(&cmd, "%s -t AAAA -u %s\n", "gnunet-gns -r", name))
      return -1;
  }
  else
  {
    if (-1 == asprintf(&cmd, "%s %s\n", "gnunet-gns -r -u", name))
      return -1;
  }

  p = popen(cmd,"r");

  if (p != NULL )
  {
    while (fgets( line, sizeof(line), p ) != NULL)
    {

      if (u->count >= MAX_ENTRIES)
        break;

      if (line[strlen(line)-1] == '\n')
      {
        line[strlen(line)-1] = '\0';
        if (af == AF_INET)
        {
          inet_pton(af, line, &(u->data.ipv4[u->count++]));
          u->data_len += sizeof(ipv4_address_t);
        }
        else if ((af == AF_INET6))
        {
          inet_pton(af, line, &(u->data.ipv6[u->count++]));
          u->data_len += sizeof(ipv6_address_t);
        }
      }
    }
  }
  fclose(p);
  free(cmd);

  return 0;

}
