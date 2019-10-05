/*
     This file is part of GNUnet.
     Copyright (C) 2003, 2004, 2005, 2006, 2009 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */
/**
 * @file util/test_os_network.c
 * @brief testcase for util/os_network.c
 */
#include "platform.h"
#include "gnunet_util_lib.h"


/**
 * Check if the address we got is IPv4 or IPv6 loopback (which should
 * be present on all systems at all times); if so, set ok to 0
 * (success).
 */
static int
proc (void *cls,
      const char *name,
      int isDefault,
      const struct sockaddr *addr,
      const struct sockaddr *broadcast_addr,
      const struct sockaddr *netmask,
      socklen_t addrlen)
{
  int *ok = cls;
  char buf[INET6_ADDRSTRLEN];
  const char *protocol;

  if (NULL == addr)
    return GNUNET_OK;
  if (addrlen == sizeof(struct sockaddr_in))
    protocol = "IPv4";
  else
    protocol = "IPv6";
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s Address `%s'\n",
              protocol,
              GNUNET_a2s ((const struct sockaddr *) addr,
                          addrlen));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Netmask `%s'\n",
              GNUNET_a2s ((const struct sockaddr *) netmask,
                          addrlen));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s'\n",
              GNUNET_a2s ((const struct sockaddr *) broadcast_addr,
                          addrlen));
  inet_ntop (addr->sa_family,
             (addr->sa_family ==
              AF_INET) ? (void *) &((struct sockaddr_in *) addr)->sin_addr
             : (void *) &((struct sockaddr_in6 *) addr)->sin6_addr, buf,
             sizeof(buf));
  if ((0 == strcmp ("::1", buf)) || (0 == strcmp ("127.0.0.1", buf)))
    *ok = 0;
  return GNUNET_OK;
}


int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-os-network",
                    "WARNING",
                    NULL);
  ret = 1;
  GNUNET_OS_network_interfaces_list (&proc,
                                     &ret);
  return ret;
}

/* end of test_os_network.c */
