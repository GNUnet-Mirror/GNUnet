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
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_dns_service.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet_vpn_service.h"
#include "gnunet_statistics_service.h"


/**
 * After how long do we time out if we could not get an IP from VPN?
 */
#define TIMEOUT GNUNET_TIME_UNIT_MINUTES


/**
 * How many bytes of payload do we allow at most for a DNS reply?
 * Given that this is pretty much limited to loopback, we can be
 * pretty high (Linux loopback defaults to 16k, most local UDP packets
 * should survive up to 9k (NFS), so 8k should be pretty safe in
 * general).
 */
#define MAX_DNS_SIZE (8 * 1024)


/**
 * Which group of DNS records are we currently processing?
 */
enum RequestGroup
  {
    /**
     * DNS answers
     */
    ANSWERS = 0, 

    /**
     * DNS authority records
     */
    AUTHORITY_RECORDS = 1,

    /**
     * DNS additional records
     */
    ADDITIONAL_RECORDS = 2,

    /**
     * We're done processing.
     */
    END = 3
  };


/**
 * Information tracked per DNS request that we are processing.
 */
struct RequestContext
{
  /**
   * Handle to submit the final result.
   */
  struct GNUNET_DNS_RequestHandle *rh;
  
  /**
   * DNS packet that is being modified.
   */
  struct GNUNET_DNSPARSER_Packet *dns;

  /**
   * Active redirection request with the VPN.
   */
  struct GNUNET_VPN_RedirectionRequest *rr;

  /**
   * Record for which we have an active redirection request.
   */
  struct GNUNET_DNSPARSER_Record *rec;

  /**
   * Offset in the current record group that is being modified.
   */
  unsigned int offset;

  /**
   * Group that is being modified
   */
  enum RequestGroup group;
  
};


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
 * We're done modifying all records in the response.  Submit the reply
 * and free the resources of the rc.
 *
 * @param rc context to process
 */
static void
finish_request (struct RequestContext *rc)
{
  char *buf;
  size_t buf_len;

  if (GNUNET_SYSERR ==
      GNUNET_DNSPARSER_pack (rc->dns,
			     MAX_DNS_SIZE,
			     &buf,
			     &buf_len))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Failed to pack DNS request.  Dropping.\n"));
    GNUNET_DNS_request_drop (rc->rh);
  }
  else
  {
    GNUNET_STATISTICS_update (stats,
			      gettext_noop ("# DNS requests mapped to VPN"),
			      1, GNUNET_NO);
    GNUNET_DNS_request_answer (rc->rh,
			       buf_len, buf);
    GNUNET_free (buf);
  }
  GNUNET_DNSPARSER_free_packet (rc->dns);
  GNUNET_free (rc);
}


/**
 * Process the next record of the given request context.
 * When done, submit the reply and free the resources of
 * the rc.
 *
 * @param rc context to process
 */
static void
submit_request (struct RequestContext *rc);


/**
 * Callback invoked from the VPN service once a redirection is
 * available.  Provides the IP address that can now be used to
 * reach the requested destination.  We substitute the active
 * record and then continue with 'submit_request' to look at
 * the other records.
 *
 * @param cls our 'struct RequestContext'
 * @param af address family, AF_INET or AF_INET6; AF_UNSPEC on error;
 *                will match 'result_af' from the request
 * @param address IP address (struct in_addr or struct in_addr6, depending on 'af')
 *                that the VPN allocated for the redirection;
 *                traffic to this IP will now be redirected to the 
 *                specified target peer; NULL on error
 */
static void
vpn_allocation_callback (void *cls,
			 int af,
			 const void *address)
{
  struct RequestContext *rc = cls;

  rc->rr = NULL;
  if (af == AF_UNSPEC)
  {
    GNUNET_DNS_request_drop (rc->rh);
    GNUNET_DNSPARSER_free_packet (rc->dns);
    GNUNET_free (rc);
    return;
  }
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# DNS records modified"),
			    1, GNUNET_NO);
  switch (rc->rec->type)
  {
  case GNUNET_DNSPARSER_TYPE_A:
    GNUNET_assert (AF_INET == af);
    memcpy (rc->rec->data.raw.data, address, sizeof (struct in_addr));
    break;
  case GNUNET_DNSPARSER_TYPE_AAAA:
    GNUNET_assert (AF_INET6 == af);
    memcpy (rc->rec->data.raw.data, address, sizeof (struct in6_addr));
    break;
  default:
    GNUNET_assert (0);
    return;
  }
  rc->rec = NULL;
  submit_request (rc);
}


/**
 * Modify the given DNS record by asking VPN to create a tunnel
 * to the given address.  When done, continue with submitting
 * other records from the request context ('submit_request' is
 * our continuation).
 *
 * @param rc context to process
 * @param rec record to modify
 */
static void
modify_address (struct RequestContext *rc,
		struct GNUNET_DNSPARSER_Record *rec)
{
  int af;

  switch (rec->type)
  {
  case GNUNET_DNSPARSER_TYPE_A:
    af = AF_INET;
    GNUNET_assert (rec->data.raw.data_len == sizeof (struct in_addr));
    break;
  case GNUNET_DNSPARSER_TYPE_AAAA:
    af = AF_INET6;
    GNUNET_assert (rec->data.raw.data_len == sizeof (struct in6_addr));
    break;
  default:
    GNUNET_assert (0);
    return;
  }
  rc->rec = rec;
  rc->rr = GNUNET_VPN_redirect_to_ip (vpn_handle,
				      af, af,
				      rec->data.raw.data,
				      GNUNET_NO /* nac */,
				      GNUNET_TIME_relative_to_absolute (TIMEOUT),
				      &vpn_allocation_callback,
				      rc);
}


/**
 * Process the next record of the given request context.
 * When done, submit the reply and free the resources of
 * the rc.
 *
 * @param rc context to process
 */
static void
submit_request (struct RequestContext *rc)
{
  struct GNUNET_DNSPARSER_Record *ra;
  unsigned int ra_len;
  unsigned int i;

  while (1)
  {
    switch (rc->group)
    {
    case ANSWERS:
      ra = rc->dns->answers;
      ra_len = rc->dns->num_answers;
      break;
    case AUTHORITY_RECORDS:
      ra = rc->dns->authority_records;
      ra_len = rc->dns->num_authority_records;
      break;
    case ADDITIONAL_RECORDS:
      ra = rc->dns->additional_records;
      ra_len = rc->dns->num_additional_records;
      break;
    case END:
      finish_request (rc);
      return;
    default:
      GNUNET_assert (0);      
    }
    for (i=rc->offset;i<ra_len;i++)
    {
      switch (ra[i].type)
      {
      case GNUNET_DNSPARSER_TYPE_A:
	if (ipv4_pt)
	{
	  rc->offset = i + 1;
	  modify_address (rc, &ra[i]);
	  return;
	}
	break;
      case GNUNET_DNSPARSER_TYPE_AAAA:
	if (ipv6_pt)
	{
	  rc->offset = i + 1;
	  modify_address (rc, &ra[i]);
	  return;
	}
	break;
      }
    }
    rc->group++;
  }
}


/**
 * Test if any of the given records need protocol-translation work.
 *
 * @param ra array of records
 * @param ra_len number of entries in ra
 * @return GNUNET_YES if any of the given records require protocol-translation
 */
static int
work_test (const struct GNUNET_DNSPARSER_Record *ra,
	   unsigned int ra_len)
{
  unsigned int i;

  for (i=0;i<ra_len;i++)
  {
    switch (ra[i].type)
    {
    case GNUNET_DNSPARSER_TYPE_A:
      if (ipv4_pt)
	return GNUNET_YES;
      break;
    case GNUNET_DNSPARSER_TYPE_AAAA:
      if (ipv6_pt)
	return GNUNET_YES;
      break;
    }
  }
  return GNUNET_NO;
}


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
  struct GNUNET_DNSPARSER_Packet *dns;
  struct RequestContext *rc;
  int work;

  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# DNS requests intercepted"),
			    1, GNUNET_NO);
  dns = GNUNET_DNSPARSER_parse (request, request_length);
  if (NULL == dns)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Failed to parse DNS request.  Dropping.\n"));
    GNUNET_DNS_request_drop (rh);
    return;
  }
  work = GNUNET_NO;
  work |= work_test (dns->answers, dns->num_answers);
  work |= work_test (dns->authority_records, dns->num_authority_records);
  work |= work_test (dns->additional_records, dns->num_additional_records);
  if (! work)
  {
    GNUNET_DNS_request_forward (rh);
    return;
  }
  rc = GNUNET_malloc (sizeof (struct RequestContext));
  rc->rh = rh;
  rc->dns = dns;
  rc->offset = 0;
  rc->group = ANSWERS;
  submit_request (rc);
}


/**
 * Function scheduled as very last function, cleans up after us
 */
static void
cleanup (void *cls GNUNET_UNUSED,
         const struct GNUNET_SCHEDULER_TaskContext *tskctx)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Protocol translation daemon is shutting down now\n");
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
