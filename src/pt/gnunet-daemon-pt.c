/*
     This file is part of GNUnet.
     (C) 2010, 2012 Christian Grothoff

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
 * @file pt/gnunet-daemon-pt.c
 * @brief tool to manipulate DNS and VPN services to perform protocol translation (IPvX over GNUnet)
 * @author Christian Grothoff
 *
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_dns_service.h"
#include "gnunet_vpn_service.h"
#include "gnunet_statistics_service.h"


/**
 * The handle to the configuration used throughout the process
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * The handle to the VPN
 */
static struct GNUNET_VPN_Handle *vpn_handle;

/**
 * Statistics.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * The handle to DNS
 */
static struct GNUNET_DNS_Handle *dns_handle;

/**
 * Are we doing IPv4-pt?
 */
static int ipv4_pt;

/**
 * Are we doing IPv6-pt?
 */
static int ipv6_pt;



/**
 * Signature of a function that is called whenever the DNS service
 * encounters a DNS request and needs to do something with it.  The
 * function has then the chance to generate or modify the response by
 * calling one of the three "GNUNET_DNS_request_*" continuations.
 *
 * When a request is intercepted, this function is called first to
 * give the client a chance to do the complete address resolution;
 * "rdata" will be NULL for this first call for a DNS request, unless
 * some other client has already filled in a response.
 *
 * If multiple clients exist, all of them are called before the global
 * DNS.  The global DNS is only called if all of the clients'
 * functions call GNUNET_DNS_request_forward.  Functions that call
 * GNUNET_DNS_request_forward will be called again before a final
 * response is returned to the application.  If any of the clients'
 * functions call GNUNET_DNS_request_drop, the response is dropped.
 *
 * @param cls closure
 * @param rh request handle to user for reply
 * @param request_length number of bytes in request
 * @param request udp payload of the DNS request
 */
static void 
dns_request_handler (void *cls,
		     struct GNUNET_DNS_RequestHandle *rh,
		     size_t request_length,
		     const char *request)
{
}


/**
 * Function scheduled as very last function, cleans up after us
 */
static void
cleanup (void *cls GNUNET_UNUSED,
         const struct GNUNET_SCHEDULER_TaskContext *tskctx)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Pt service is shutting down now\n");
  if (vpn_handle != NULL)
  {
    GNUNET_VPN_disconnect (vpn_handle);
    vpn_handle = NULL;
  }
  if (dns_handle != NULL)
  {
    GNUNET_DNS_disconnect (dns_handle);
    dns_handle = NULL;
  }
  if (stats != NULL)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_YES);
    stats = NULL;
  }
}


/**
 * @brief Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg_ configuration
 */
static void
run (void *cls, char *const *args GNUNET_UNUSED,
     const char *cfgfile GNUNET_UNUSED,
     const struct GNUNET_CONFIGURATION_Handle *cfg_)
{
  cfg = cfg_;
  stats = GNUNET_STATISTICS_create ("pt", cfg);
  ipv4_pt = GNUNET_CONFIGURATION_get_value_yesno (cfg, "pt", "TUNNEL_IPV4");
  ipv6_pt = GNUNET_CONFIGURATION_get_value_yesno (cfg, "pt", "TUNNEL_IPV6"); 
  if (! (ipv4_pt || ipv6_pt))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("No useful service enabled.  Exiting.\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;    
  }
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &cleanup, cls);
  dns_handle 
    = GNUNET_DNS_connect (cfg, 
			  GNUNET_DNS_FLAG_POST_RESOLUTION,
			  &dns_request_handler, NULL);
  if (NULL == dns_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Failed to connect to %s service.  Exiting.\n"),
		"DNS");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  vpn_handle = GNUNET_VPN_connect (cfg);
  if (NULL == vpn_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Failed to connect to %s service.  Exiting.\n"),
		"VPN");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
}


/**
 * The main function
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-daemon-pt",
                              gettext_noop
                              ("Daemon to run to perform IP protocol translation to GNUnet"),
                              options, &run, NULL)) ? 0 : 1;
}


/* end of gnunet-daemon-pt.c */
