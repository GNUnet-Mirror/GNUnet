/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file nat/test_nat.c
 * @brief Testcase for NAT library
 * @author Milan Bouchet-Valat
 */

/**
 * Testcase for port redirection and public IP address retrieval.
 * This test never fails, because there need to be a NAT box set up for that.
 * So we only get IP address and open the 2086 port using any UPnP and NAT-PMP
 * routers found, wait for 30s, close ports and return.
 * Have a look at the logs and use NMAP to check that it works with your box.
 */


#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_nat_lib.h"

/* Time to wait before stopping NAT, in seconds */
#define TIMEOUT 60

struct addr_cls
{
  struct sockaddr *addr;
  socklen_t addrlen;
};

static void
addr_callback (void *cls, int add_remove,
               const struct sockaddr *addr, socklen_t addrlen)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "External address changed: %s %s\n",
              add_remove == GNUNET_YES ? "added" : "removed",
              GNUNET_a2s (addr, addrlen));
}

static void
stop (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_NAT_Handle *nat = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Stopping NAT and quitting...\n");
  GNUNET_NAT_unregister (nat);
}

/* Return the address of the default interface,
 * or any interface with a valid address if the default is not valid */
static int
process_if (void *cls,
            const char *name,
            int isDefault, const struct sockaddr *addr, socklen_t addrlen)
{
  struct addr_cls *data = cls;

  if (addr && addrlen > 0)
    {
      if (data->addr)
        GNUNET_free (data->addr);
      data->addr = memcpy (GNUNET_malloc (addrlen), addr, addrlen);
      data->addrlen = addrlen;
      if (isDefault)
        return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}

static void
run (void *cls,
     char *const *args,
     const char *cfgfile, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_NAT_Handle *nat;
  struct addr_cls data;
  struct sockaddr *addr;

  GNUNET_log_setup ("test-nat", "DEBUG", NULL);

  data.addr = NULL;
  GNUNET_OS_network_interfaces_list (process_if, &data);
  if (!data.addr)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Could not find a valid interface address!\n");
      exit (GNUNET_SYSERR);
    }

  addr = GNUNET_malloc (data.addrlen);
  memcpy (addr, data.addr, data.addrlen);

  GNUNET_assert (addr->sa_family == AF_INET || addr->sa_family == AF_INET6);
  if (addr->sa_family == AF_INET)
    ((struct sockaddr_in *) addr)->sin_port = htons (2086);
  else
    ((struct sockaddr_in6 *) addr)->sin6_port = htons (2086);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Requesting NAT redirection from address %s...\n",
              GNUNET_a2s (addr, data.addrlen));

  nat = GNUNET_NAT_register (cfg, addr, data.addrlen, addr_callback, NULL);
  GNUNET_free (addr);

  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                (GNUNET_TIME_UNIT_SECONDS, TIMEOUT), stop,
                                nat);
}

int
main (int argc, char *const argv[])
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  char *const argv_prog[] = {
    "test-nat",
    "-c",
    "test-nat.conf",
    "-L",
#if VERBOSE
    "DEBUG",
#else
    "WARNING",
#endif
    NULL
  };

  GNUNET_log_setup ("test-nat",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Testing NAT library, timeout set to %d seconds\n", TIMEOUT);

  GNUNET_PROGRAM_run (5, argv_prog, "test-nat", "nohelp", options, &run, NULL);

  return 0;
}

/* end of test_nat.c */
