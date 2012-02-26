/*
     This file is part of GNUnet.
     (C) 2009, 2011 Christian Grothoff (and other contributing authors)

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
 * Testcase for port redirection and public IP address retrieval.
 * This test never fails, because there need to be a NAT box set up for that.
 * So we only get IP address and open the 2086 port using any NAT traversal
 * method available, wait for 30s, close ports and return.
 * Have a look at the logs and use NMAP to check that it works with your box.
 *
 * @file nat/test_nat.c
 * @brief Testcase for NAT library
 * @author Milan Bouchet-Valat
 * @author Christian Grothoff
 *
 * TODO: actually use ARM to start resolver service to make DNS work!
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_program_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_nat_lib.h"


#define VERBOSE GNUNET_NO


/**
 * Time to wait before stopping NAT, in seconds
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)


/**
 * Function called on each address that the NAT service
 * believes to be valid for the transport.
 */
static void
addr_callback (void *cls, int add_remove, const struct sockaddr *addr,
               socklen_t addrlen)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Address changed: %s `%s' (%u bytes)\n",
              add_remove == GNUNET_YES ? "added" : "removed", GNUNET_a2s (addr,
                                                                          addrlen),
              (unsigned int) addrlen);
}


/**
 * Function that terminates the test.
 */
static void
stop (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_NAT_Handle *nat = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Stopping NAT and quitting...\n");
  GNUNET_NAT_unregister (nat);
}


struct addr_cls
{
  struct sockaddr *addr;
  socklen_t addrlen;
};


/**
 * Return the address of the default interface,
 * or any interface with a valid address if the default is not valid
 *
 * @param cls the 'struct addr_cls'
 * @param name name of the interface
 * @param isDefault do we think this may be our default interface
 * @param addr address of the interface
 * @param addrlen number of bytes in addr
 * @return GNUNET_OK to continue iterating
 */
static int
process_if (void *cls, const char *name, int isDefault,
            const struct sockaddr *addr, const struct sockaddr *broadcast_addr,
            const struct sockaddr *netmask, socklen_t addrlen)
{
  struct addr_cls *data = cls;

  if (addr == NULL)
    return GNUNET_OK;
  GNUNET_free_non_null (data->addr);
  data->addr = GNUNET_malloc (addrlen);
  memcpy (data->addr, addr, addrlen);
  data->addrlen = addrlen;
  if (isDefault)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * Main function run with scheduler.
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_NAT_Handle *nat;
  struct addr_cls data;
  struct sockaddr *addr;

  data.addr = NULL;
  GNUNET_OS_network_interfaces_list (process_if, &data);
  if (NULL == data.addr)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not find a valid interface address!\n");
    exit (GNUNET_SYSERR);
  }
  addr = data.addr;
  GNUNET_assert (addr->sa_family == AF_INET || addr->sa_family == AF_INET6);
  if (addr->sa_family == AF_INET)
    ((struct sockaddr_in *) addr)->sin_port = htons (2086);
  else
    ((struct sockaddr_in6 *) addr)->sin6_port = htons (2086);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Requesting NAT redirection from address %s...\n",
              GNUNET_a2s (addr, data.addrlen));

  nat = GNUNET_NAT_register (cfg, GNUNET_YES /* tcp */ ,
                             2086, 1, (const struct sockaddr **) &addr,
                             &data.addrlen, &addr_callback, NULL, NULL);
  GNUNET_free (addr);
  GNUNET_SCHEDULER_add_delayed (TIMEOUT, &stop, nat);
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
    "test_nat_data.conf",
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
