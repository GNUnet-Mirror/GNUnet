/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file src/dns/gnunet-dns-redirector.c
 * @brief Tool to change DNS replies (for testing)
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_dns_service.h"
#include "gnunet_dnsparser_lib.h"

/**
 * Handle to DNS service.
 */
static struct GNUNET_DNS_Handle *handle;

/**
 * New target for A records.
 */
static char *n4;

/**
 * New target for AAAA records.
 */
static char *n6;

/**
 * Global return value (0 success).
 */
static int ret;

/**
 * Selected level of verbosity.
 */
static int verbosity;


/**
 * Modify the given DNS record.
 *
 * @param record record to modify
 */
static void
modify_record (const struct GNUNET_DNSPARSER_Record *record)
{
  char buf[INET6_ADDRSTRLEN];

  switch (record->type)
  {
  case GNUNET_DNSPARSER_TYPE_A:    
    if (record->data.raw.data_len != sizeof (struct in_addr))
      return;
    if (NULL != n4)
    {
      if (verbosity > 1)
	fprintf (stderr, 
		 "Changing A record from `%s' to `%s'\n",
		 inet_ntop (AF_INET, record->data.raw.data, buf, sizeof (buf)),
		 n4);
      GNUNET_assert (1 == inet_pton (AF_INET, n4, record->data.raw.data));
    }
    break;
  case GNUNET_DNSPARSER_TYPE_AAAA:
    if (record->data.raw.data_len != sizeof (struct in6_addr))
      return;
    if (NULL != n6)
    {
      if (verbosity > 1)
	fprintf (stderr, 
		 "Changing AAAA record from `%s' to `%s'\n",
		 inet_ntop (AF_INET6, record->data.raw.data, buf, sizeof (buf)),
		 n6);
      GNUNET_assert (1 == inet_pton (AF_INET6, n6, record->data.raw.data));
    }
    break;
  case GNUNET_DNSPARSER_TYPE_NS:
  case GNUNET_DNSPARSER_TYPE_CNAME:
  case GNUNET_DNSPARSER_TYPE_PTR:
  case GNUNET_DNSPARSER_TYPE_SOA:
  case GNUNET_DNSPARSER_TYPE_MX:
  case GNUNET_DNSPARSER_TYPE_TXT:
    break;
  default:
    break;
  }
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
modify_request (void *cls,
		struct GNUNET_DNS_RequestHandle *rh,
		size_t request_length,
		const char *request)
{
  struct GNUNET_DNSPARSER_Packet *p;
  unsigned int i;
  char *buf;
  size_t len;
  int ret;

  p = GNUNET_DNSPARSER_parse (request, request_length);
  if (NULL == p)
  {
    fprintf (stderr, "Received malformed DNS packet, leaving it untouched\n");
    GNUNET_DNS_request_forward (rh);
    return;
  }
  for (i=0;i<p->num_answers;i++)
    modify_record (&p->answers[i]);
  buf = NULL;
  ret = GNUNET_DNSPARSER_pack (p, 1024, &buf, &len);
  GNUNET_DNSPARSER_free_packet (p);
  if (GNUNET_OK != ret)
  {
    if (GNUNET_NO == ret)
      fprintf (stderr, 
	       "Modified DNS response did not fit, keeping old response\n");
    else
      GNUNET_break (0); /* our modifications should have been sane! */
    GNUNET_DNS_request_forward (rh);
  }
  else
  {
    if (verbosity > 0)
      fprintf (stdout,
	       "Injecting modified DNS response\n");
    GNUNET_DNS_request_answer (rh, len, buf);
  }
  GNUNET_free_non_null (buf);      
}


/**
 * Shutdown.
 */
static void
do_disconnect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != handle)
  {
    GNUNET_DNS_disconnect (handle);
    handle = NULL;
  }
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
  struct in_addr i4;
  struct in6_addr i6;
  if ( (n4 != NULL) &&
       (1 != inet_pton (AF_INET, n4, &i4)) )
  {
    fprintf (stderr,
	     "`%s' is nto a valid IPv4 address!\n",
	     n4);
    return;
  }
  if ( (n6 != NULL) &&
       (1 != inet_pton (AF_INET6, n6, &i6)) )
  {
    fprintf (stderr,
	     "`%s' is nto a valid IPv6 address!\n",
	     n6);
    return;
  }

  handle =
    GNUNET_DNS_connect (cfg, 
			GNUNET_DNS_FLAG_POST_RESOLUTION,
			&modify_request,
			NULL);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
				&do_disconnect, NULL);
}


int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'4', "ipv4", "IPV4",
     gettext_noop ("set A records"),
     1, &GNUNET_GETOPT_set_string, &n4},
    {'6', "ipv4", "IPV6",
     gettext_noop ("set AAAA records"),
     1, &GNUNET_GETOPT_set_string, &n6},
    GNUNET_GETOPT_OPTION_VERBOSE (&verbosity),
    GNUNET_GETOPT_OPTION_END
  };
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-dns-redirector",
                              gettext_noop
                              ("Change DNS replies to point elsewhere."), options,
                              &run, NULL)) ? ret : 1;
}


/* end of gnunet-dns-redirector.c */
