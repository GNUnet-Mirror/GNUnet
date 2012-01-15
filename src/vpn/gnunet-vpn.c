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
 * Option -t: TCP requested.
 */
static int tcp;

/**
 * Option -u: UDP requested.
 */
static int udp;

/**
 * Selected level of verbosity.
 */
static int verbosity;

/**
 * Option '-a':  Notify only once the tunnel is connected?
 */
static int nac;

/**
 * Global return value.
 */
static int ret;

/**
 * Option '-d': duration of the mapping
 */
static unsigned long long duration = 5 * 60;


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
 * Callback invoked from the VPN service once a redirection is
 * available.  Provides the IP address that can now be used to
 * reach the requested destination.
 *
 * @param cls closure
 * @param af address family, AF_INET or AF_INET6; AF_UNSPEC on error;
 *                will match 'result_af' from the request
 * @param address IP address (struct in_addr or struct in_addr6, depending on 'af')
 *                that the VPN allocated for the redirection;
 *                traffic to this IP will now be redirected to the 
 *                specified target peer; NULL on error
 */
static void
allocation_cb (void *cls,
	       int af,
	       const void *address)
{
  char buf[INET6_ADDRSTRLEN];

  request = NULL;
  switch (af)
  {
  case AF_INET6:
  case AF_INET:
    FPRINTF (stdout,
	     "%s\n",
	     inet_ntop (af, address, buf, sizeof (buf)));
    break;
  case AF_UNSPEC:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Error creating tunnel\n"));
    ret = 1;
    break;
  default:
    break;
  }
  GNUNET_SCHEDULER_shutdown ();
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
  int dst_af;
  int req_af;
  struct GNUNET_PeerIdentity peer; 
  GNUNET_HashCode sd;
  const void *addr;
  struct in_addr v4;
  struct in6_addr v6;
  uint8_t protocol;
  struct GNUNET_TIME_Absolute etime;

  etime = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
									   (unsigned int) duration));
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
				&do_disconnect, NULL);
  handle = GNUNET_VPN_connect (cfg);
  if (NULL == handle)
    goto error;
  req_af = AF_UNSPEC;
  if (ipv4)
  {
    if (ipv6)
    {
      FPRINTF (stderr, _("Option `%s' makes no sense with option `%s'.\n"),
               "-4", "-6");
      goto error;
    }
    req_af = AF_INET;
  }
  if (ipv6)
    req_af = AF_INET6;
  
  if (NULL == target_ip)
  {
    if (NULL == service_name)
    {
      FPRINTF (stderr, _("Option `%s' or `%s' is required.\n"),
               "-i", "-s");
      goto error;
    }
    if (NULL == peer_id)
    {
      FPRINTF (stderr, _("Option `%s' is required when using option `%s'.\n"),
               "-p", "-s");
      goto error;
    }
    if (! (tcp | udp) )
    {
      FPRINTF (stderr, _("Option `%s' or `%s' is required when using option `%s'.\n"),
               "-t", "-u", "-s");
      goto error;
    }
    if (tcp & udp)
    {
      FPRINTF (stderr, _("Option `%s' makes no sense with option `%s'.\n"),
               "-t", "-u");
      goto error;
    }
    if (tcp)
      protocol = IPPROTO_TCP;
    if (udp)
      protocol = IPPROTO_UDP;
    if (GNUNET_OK !=
	GNUNET_CRYPTO_hash_from_string (peer_id,
					&peer.hashPubKey))
    {
      FPRINTF (stderr, _("`%s' is not a valid peer identifier.\n"),
               peer_id);
      goto error;
    }    
    GNUNET_CRYPTO_hash (service_name,
			strlen (service_name),
			&sd);
    request = GNUNET_VPN_redirect_to_peer (handle,
					   req_af,
					   protocol,
					   &peer,
					   &sd,
					   nac,
					   etime,
					   &allocation_cb, NULL);
  }
  else
  {
    if (1 != inet_pton (AF_INET6, target_ip, &v6))
    {
      if (1 != inet_pton (AF_INET, target_ip, &v4))
      {
	FPRINTF (stderr, _("`%s' is not a valid IP address.\n"),
		 target_ip);
	goto error;
      }
      else
      {
	dst_af = AF_INET;
	addr = &v4;
      }
    }
    else
    {
      dst_af = AF_INET6;
      addr = &v6;
    }    
    request = GNUNET_VPN_redirect_to_ip (handle,
					 req_af,
					 dst_af,
					 addr,
					 nac,
					 etime,
					 &allocation_cb, NULL);
  }
  return;

 error:
  GNUNET_SCHEDULER_shutdown ();
  ret = 1;
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
    {'a', "after-connect", NULL,
     gettext_noop ("print IP address only after mesh tunnel has been created"),
     0, &GNUNET_GETOPT_set_one, &ipv6},
    {'d', "duration", "SECONDS",
     gettext_noop ("how long should the mapping be valid for new tunnels?"),
     1, &GNUNET_GETOPT_set_ulong, &duration},
    {'i', "ip", "IP",
     gettext_noop ("destination IP for the tunnel"),
     1, &GNUNET_GETOPT_set_string, &target_ip},
    {'p', "peer", "PEERID",
     gettext_noop ("peer offering the service we would like to access"),
     1, &GNUNET_GETOPT_set_string, &peer_id},
    {'s', "service", "NAME",
     gettext_noop ("name of the service we would like to access"),
     1, &GNUNET_GETOPT_set_string, &service_name},
    {'t', "tcp", NULL,
     gettext_noop ("service is offered via TCP"),
     0, &GNUNET_GETOPT_set_one, &tcp},
    {'u', "udp", NULL,
     gettext_noop ("service is offered via UDP"),
     0, &GNUNET_GETOPT_set_one, &udp},

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
