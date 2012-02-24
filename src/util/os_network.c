/*
     This file is part of GNUnet.
     (C) 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file util/os_network.c
 * @brief function to determine available network interfaces
 * @author Nils Durner
 * @author Heikki Lindholm
 * @author Jake Dust
 * @author LRN
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_os_lib.h"


#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)
#define LOG_STRERROR_FILE(kind,syscall,filename) GNUNET_log_from_strerror_file (kind, "util", syscall, filename)

/**
 * @brief Enumerate all network interfaces
 *
 * @param proc the callback function
 * @param proc_cls closure for proc
 */
void
GNUNET_OS_network_interfaces_list (GNUNET_OS_NetworkInterfaceProcessor proc,
                                   void *proc_cls)
{
#ifdef MINGW
  int r;
  int i;
  struct EnumNICs3_results *results = NULL;
  int results_count;

  r = EnumNICs3 (&results, &results_count);
  if (r != GNUNET_OK)
    return;

  for (i = 0; i < results_count; i++)
  {
    if (GNUNET_OK !=
        proc (proc_cls, results[i].pretty_name, results[i].is_default,
              (const struct sockaddr *) &results[i].address,
              results[i].
              flags & ENUMNICS3_BCAST_OK ?
              (const struct sockaddr *) &results[i].broadcast : NULL,
              results[i].flags & ENUMNICS3_MASK_OK ?
              (const struct sockaddr *) &results[i].mask : NULL,
              results[i].addr_size))
      break;
  }
  EnumNICs3_free (results);
  return;

#elif HAVE_GETIFADDRS && HAVE_FREEIFADDRS

  struct ifaddrs *ifa_first;
  struct ifaddrs *ifa_ptr;
  socklen_t alen;

  if (getifaddrs (&ifa_first) == 0)
  {
    for (ifa_ptr = ifa_first; ifa_ptr != NULL; ifa_ptr = ifa_ptr->ifa_next)
    {
      if (ifa_ptr->ifa_name != NULL && ifa_ptr->ifa_addr != NULL &&
          (ifa_ptr->ifa_flags & IFF_UP) != 0)
      {
        if ((ifa_ptr->ifa_addr->sa_family != AF_INET) &&
            (ifa_ptr->ifa_addr->sa_family != AF_INET6))
          continue;
        if (ifa_ptr->ifa_addr->sa_family == AF_INET)
          alen = sizeof (struct sockaddr_in);
        else
          alen = sizeof (struct sockaddr_in6);
        if (GNUNET_OK !=
            proc (proc_cls, ifa_ptr->ifa_name,
                  0 == strcmp (ifa_ptr->ifa_name, GNUNET_DEFAULT_INTERFACE),
                  ifa_ptr->ifa_addr, ifa_ptr->ifa_broadaddr,
                  ifa_ptr->ifa_netmask, alen))
          break;
      }
    }
    freeifaddrs (ifa_first);
  }
#else
  int i;
  char line[1024];
  char *replace;
  const char *start;
  char ifc[12];
  char addrstr[128];
  char bcstr[128];
  char netmaskstr[128];
  FILE *f;
  int have_ifc;
  struct sockaddr_in a4;
  struct sockaddr_in6 a6;
  struct in_addr v4;
  struct in6_addr v6;
  struct sockaddr_in bcaddr;
  struct sockaddr_in netmask;
  struct sockaddr_in6 netmask6;
  struct sockaddr *pass_bcaddr;
  struct sockaddr *pass_netmask;
  int prefixlen;

  if (system ("ifconfig -a > /dev/null 2> /dev/null"))
    if (system ("/sbin/ifconfig -a > /dev/null 2> /dev/null") == 0)
      f = popen ("/sbin/ifconfig -a 2> /dev/null", "r");
    else
      f = NULL;
  else
    f = popen ("ifconfig -a 2> /dev/null", "r");
  if (!f)
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING | GNUNET_ERROR_TYPE_BULK,
                       "popen", "ifconfig");
    return;
  }

  have_ifc = GNUNET_NO;
  ifc[11] = '\0';
  while (NULL != fgets (line, sizeof (line), f))
  {
    if (strlen (line) == 0)
    {
      have_ifc = GNUNET_NO;
      continue;
    }
    if (!isspace (line[0]))
    {
      have_ifc = (1 == SSCANF (line, "%11s", ifc)) ? GNUNET_YES : GNUNET_NO;
      /* would end with ':' on OSX, fix it! */
      if (ifc[strlen (ifc) - 1] == ':')
        ifc[strlen (ifc) - 1] = '\0';
      continue;
    }
    if (!have_ifc)
      continue;                 /* strange input, hope for the best */

    /* make parsing of ipv6 addresses easier */
    for (replace = line; *replace != '\0'; replace++)
    {
      if (*replace == '/')
        *replace = ' ';
    }
    prefixlen = -1;

    start = line;
    while (('\0' != *start) && (isspace (*start)))
      start++;

    /* Zero-out stack allocated values */
    memset (addrstr, 0, 128);
    memset (netmaskstr, 0, 128);
    memset (bcstr, 0, 128);
    prefixlen = 0;

    if ( /* Linux */
         (3 == SSCANF (start, "inet addr:%127s Bcast:%127s Mask:%127s", addrstr, bcstr, netmaskstr)) ||
         (2 == SSCANF (start, "inet addr:%127s Mask:%127s", addrstr, netmaskstr)) ||
         (2 == SSCANF (start, "inet6 addr:%127s %d", addrstr, &prefixlen)) ||
         /* Solaris, OS X */
         (1 == SSCANF (start, "inet %127s", addrstr)) ||
         (1 == SSCANF (start, "inet6 %127s", addrstr)))
    {
      /* IPv4 */
      if (1 == inet_pton (AF_INET, addrstr, &v4))
      {
        memset (&a4, 0, sizeof (a4));
        a4.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
        a4.sin_len = (u_char) sizeof (struct sockaddr_in);
#endif
        a4.sin_addr = v4;

        pass_bcaddr = NULL;
        pass_netmask = NULL;
        if (1 == inet_pton (AF_INET, bcstr, &v4))
        {
          memset (&bcaddr, 0, sizeof (bcaddr));
          bcaddr.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
          bcaddr.sin_len = (u_char) sizeof (struct sockaddr_in);
#endif
          bcaddr.sin_addr = v4;
          pass_bcaddr = (struct sockaddr *) &bcaddr;
        }
        if (1 == inet_pton (AF_INET, netmaskstr, &v4))
        {
          memset (&netmask, 0, sizeof (netmask));
          netmask.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
          netmask.sin_len = (u_char) sizeof (struct sockaddr_in);
#endif
          netmask.sin_addr = v4;
          pass_netmask = (struct sockaddr *) &netmask;
        }


        if (GNUNET_OK !=
            proc (proc_cls, ifc, 0 == strcmp (ifc, GNUNET_DEFAULT_INTERFACE),
                  (const struct sockaddr *) &a4,
                  pass_bcaddr, pass_netmask, sizeof (a4)))
          break;
        continue;
      }
      /* IPv6 */
      if (1 == inet_pton (AF_INET6, addrstr, &v6))
      {
        memset (&a6, 0, sizeof (a6));
        a6.sin6_family = AF_INET6;
#if HAVE_SOCKADDR_IN_SIN_LEN
        a6.sin6_len = (u_char) sizeof (struct sockaddr_in6);
#endif
        a6.sin6_addr = v6;

        pass_netmask = NULL;
        if (prefixlen != -1)
        {
          memset (v6.s6_addr, 0, sizeof (v6.s6_addr));
          for (i = 0; i < prefixlen; i++)
          {
            v6.s6_addr[i >> 3] |= 1 << (i & 7);
          }
          memset (&netmask6, 0, sizeof (netmask6));
          netmask6.sin6_family = AF_INET6;
#if HAVE_SOCKADDR_IN_SIN_LEN
          netmask6.sin6_len = (u_char) sizeof (struct sockaddr_in6);
#endif
          netmask6.sin6_addr = v6;

          pass_netmask = (struct sockaddr *) &netmask6;
        }
        
        if (GNUNET_OK !=
            proc (proc_cls, ifc, 0 == strcmp (ifc, GNUNET_DEFAULT_INTERFACE),
                  (const struct sockaddr *) &a6,
                  NULL, pass_netmask, sizeof (a6)))
          break;
        continue;
      }
    }
  }
  pclose (f);
#endif
}


/* end of os_network.c */
