/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file src/vpn/gnunet-vpn.c
 * @brief Tool to manually request VPN tunnels to be created
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_vpn_service.h"


/**
 * Handle to vpn service.
 */
static struct GNUNET_VPN_Handle *handle;

/**
 * Opaque redirection request handle.
 */
static struct GNUNET_VPN_RedirectionRequest *request;

/**
 * Option -p: destination peer identity for service
 */
static char *peer_id;

/**
 * Option -s: service name (hash to get service descriptor)
 */
static char *service_name;

/**
 * Option -i: target IP
 */
static char *target_ip;

/**
 * Option -4: IPv4 requested.
 */
static int ipv4;

/**
 * Option -6: IPv6 requested.
 */
static int ipv6;

/**
 * Selected level of verbosity.
 */
static int verbosity;

/**
 * Global return value.
 */
static int ret;


/**
 * Shutdown.
 */
static void
do_disconnect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != request)
  {
    GNUNET_VPN_cancel_request (request);
    request = NULL;
  }
  if (NULL != handle)
  {
    GNUNET_VPN_disconnect (handle);
    handle = NULL;
  }
  GNUNET_free_non_null (peer_id);
  GNUNET_free_non_null (service_name);
  GNUNET_free_non_null (target_ip);
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  handle = GNUNET_VPN_connect (cfg);
  
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
				&do_disconnect, NULL);
}


int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'4', "ipv4", NULL,
     gettext_noop ("request that result should be an IPv4 address"),
     0, &GNUNET_GETOPT_set_one, &ipv4},
    {'6', "ipv6", NULL,
     gettext_noop ("request that result should be an IPv6 address"),
     0, &GNUNET_GETOPT_set_one, &ipv6},
    {'i', "ip", "IP",
     gettext_noop ("destination IP for the tunnel"),
     1, &GNUNET_GETOPT_set_string, &target_ip},
    {'p', "peer", "PEERID",
     gettext_noop ("peer offering the service we would like to access"),
     1, &GNUNET_GETOPT_set_string, &peer_id},
    {'s', "service", "NAME",
     gettext_noop ("name of the service we would like to access"),
     1, &GNUNET_GETOPT_set_string, &peer_id},
    GNUNET_GETOPT_OPTION_VERBOSE (&verbosity),
    GNUNET_GETOPT_OPTION_END
  };
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-vpn",
                              gettext_noop
                              ("Setup tunnels via VPN."), options,
                              &run, NULL)) ? ret : 1;
}


/* end of gnunet-vpn.c */
