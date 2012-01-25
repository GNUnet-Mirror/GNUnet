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
 * @file src/dns/gnunet-dns-monitor.c
 * @brief Tool to monitor DNS queries
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_dns_service.h"
#include "gnunet_dnsparser_lib.h"

/**
 * Handle to transport service.
 */
static struct GNUNET_DNS_Handle *handle;

/**
 * Option -i.
 */
static int inbound_only;

/**
 * Option -o.
 */
static int outbound_only;

/**
 * Global return value (0 success).
 */
static int ret;

/**
 * Selected level of verbosity.
 */
static int verbosity;


/**
 * Convert numeric DNS record type to a string.
 *
 * @param type type to convert
 * @return type as string, only valid until the next call to this function
 */
static const char *
get_type (uint16_t type)
{
  static char buf[6];
  switch (type)
  {
  case GNUNET_DNSPARSER_TYPE_A: return "A";
  case GNUNET_DNSPARSER_TYPE_NS: return "NS";
  case GNUNET_DNSPARSER_TYPE_CNAME: return "CNAME";
  case GNUNET_DNSPARSER_TYPE_SOA: return "SOA";
  case GNUNET_DNSPARSER_TYPE_PTR: return "PTR";
  case GNUNET_DNSPARSER_TYPE_MX: return "MX";
  case GNUNET_DNSPARSER_TYPE_TXT: return "TXT";
  case GNUNET_DNSPARSER_TYPE_AAAA: return "AAAA";
  }
  GNUNET_snprintf (buf, sizeof (buf), "%u", (unsigned int) type);
  return buf;
}


/**
 * Convert numeric DNS record class to a string.
 *
 * @param class class to convert
 * @return class as string, only valid until the next call to this function
 */
static const char *
get_class (uint16_t class)
{
  static char buf[6];
  switch (class)
  {
  case GNUNET_DNSPARSER_CLASS_INTERNET: return "IN";
  case GNUNET_DNSPARSER_CLASS_CHAOS: return "CHAOS";
  case GNUNET_DNSPARSER_CLASS_HESIOD: return "HESIOD";
  }
  GNUNET_snprintf (buf, sizeof (buf), "%u", (unsigned int) class);
  return buf;
}


/**
 * Output the given DNS query to stdout.
 *
 * @param query query to display.
 */
static void
display_query (const struct GNUNET_DNSPARSER_Query *query)
{
  fprintf (stdout,
	   "\t\t%s %s: %s\n",
	   get_class (query->class),
	   get_type (query->type),
	   query->name);
}


/**
 * Output the given DNS record to stdout.
 *
 * @param record record to display.
 */
static void
display_record (const struct GNUNET_DNSPARSER_Record *record)
{
  const char *format;
  char buf[INET6_ADDRSTRLEN];
  char *tmp;
  
  tmp = NULL;
  switch (record->type)
  {
  case GNUNET_DNSPARSER_TYPE_A:
    if (record->data.raw.data_len != sizeof (struct in_addr))
      format = "<invalid>";
    else
      format = inet_ntop (AF_INET, record->data.raw.data, buf, sizeof (buf));
    break;
  case GNUNET_DNSPARSER_TYPE_AAAA:
    if (record->data.raw.data_len != sizeof (struct in6_addr))
      format = "<invalid>";
    else
      format = inet_ntop (AF_INET6, record->data.raw.data, buf, sizeof (buf));
    break;
  case GNUNET_DNSPARSER_TYPE_NS:
  case GNUNET_DNSPARSER_TYPE_CNAME:
  case GNUNET_DNSPARSER_TYPE_PTR:
    format = record->data.hostname;
    break;
  case GNUNET_DNSPARSER_TYPE_SOA:
    if (record->data.soa == NULL)
      format = "<invalid>";
    else
    {
      GNUNET_asprintf (&tmp,
		       "origin: %s, mail: %s, serial = %u, refresh = %u s, retry = %u s, expire = %u s, minimum = %u s",
		       record->data.soa->mname,
		       record->data.soa->rname,
		       (unsigned int) record->data.soa->serial,
		       (unsigned int) record->data.soa->refresh,
		       (unsigned int) record->data.soa->retry,
		       (unsigned int) record->data.soa->expire,
		       (unsigned int) record->data.soa->minimum_ttl);	       
      format = tmp;
    }
    break;
  case GNUNET_DNSPARSER_TYPE_MX:
    if (record->data.mx == NULL)
      format = "<invalid>";
    else
    {
      GNUNET_asprintf (&tmp,
		       "%u: %s",
		       record->data.mx->preference,
		       record->data.mx->mxhost);
      format = tmp;
    }
    break;
  case GNUNET_DNSPARSER_TYPE_TXT:
    GNUNET_asprintf (&tmp,
		     "%.*s",
		     (unsigned int) record->data.raw.data_len,
		     record->data.raw.data);
    format = tmp;
    break;
  default:
    format = "<payload>";
    break;
  }
  fprintf (stdout,
	   "\t\t%s %s: %s = %s (%u s)\n",
	   get_class (record->class),
	   get_type (record->type),
	   record->name,
	   format,
	   (unsigned int) (GNUNET_TIME_absolute_get_remaining (record->expiration_time).rel_value / 1000));
  GNUNET_free_non_null (tmp);
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
display_request (void *cls,
		 struct GNUNET_DNS_RequestHandle *rh,
		 size_t request_length,
		 const char *request)
{
  static const char *return_codes[] =
    {
      "No error", "Format error", "Server failure", "Name error",
      "Not implemented", "Refused", "YXDomain", "YXRRset",
      "NXRRset", "NOT AUTH", "NOT ZONE", "<invalid>",
      "<invalid>", "<invalid>", "<invalid>", "<invalid>"
    };
  static const char *op_codes[] =
    {
      "Query", "Inverse query", "Status", "<invalid>",
      "<invalid>", "<invalid>", "<invalid>", "<invalid>",
      "<invalid>", "<invalid>", "<invalid>", "<invalid>",
      "<invalid>", "<invalid>", "<invalid>", "<invalid>"
    };
  struct GNUNET_DNSPARSER_Packet *p;
  unsigned int i;

  p = GNUNET_DNSPARSER_parse (request, request_length);
  if (NULL == p)
  {
    fprintf (stderr, "Received malformed DNS packet!\n");
    // FIXME: drop instead?
    GNUNET_DNS_request_forward (rh);
    return;
  }
  fprintf (stdout,
	   "%s with ID: %5u Flags: %s%s%s%s%s%s, Return Code: %s, Opcode: %s\n",
	   p->flags.query_or_response ? "Response" : "Query",
	   p->id,
	   p->flags.recursion_desired ? "RD " : "",
	   p->flags.message_truncated ? "MT " : "",
	   p->flags.authoritative_answer ? "AA " : "",
	   p->flags.checking_disabled ? "CD " : "",
	   p->flags.authenticated_data ? "AD " : "",
	   p->flags.recursion_available ? "RA " : "",
	   return_codes[p->flags.return_code & 15],
	   op_codes[p->flags.opcode & 15]);  
  if (p->num_queries > 0)
    fprintf (stdout,
	     "\tQueries:\n");
  for (i=0;i<p->num_queries;i++)
    display_query (&p->queries[i]);
  
  if (p->num_answers > 0)
    fprintf (stdout,
	     "\tAnswers:\n");
  for (i=0;i<p->num_answers;i++)
    display_record (&p->answers[i]);
  fprintf (stdout, "\n");
  GNUNET_DNSPARSER_free_packet (p);
  GNUNET_DNS_request_forward (rh);
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
  enum GNUNET_DNS_Flags flags;

  flags = GNUNET_DNS_FLAG_REQUEST_MONITOR | GNUNET_DNS_FLAG_RESPONSE_MONITOR;
  if (inbound_only | outbound_only)
    flags = 0;
  if (inbound_only)
    flags |= GNUNET_DNS_FLAG_REQUEST_MONITOR;
  if (outbound_only)
    flags |= GNUNET_DNS_FLAG_RESPONSE_MONITOR;
  handle =
    GNUNET_DNS_connect (cfg, 
			flags,
			&display_request,
			NULL);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
				&do_disconnect, NULL);
}


int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'i', "inbound-only", NULL,
     gettext_noop ("only monitor DNS queries"),
     0, &GNUNET_GETOPT_set_one, &inbound_only},
    {'o', "outbound-only", NULL,
     gettext_noop ("only monitor DNS replies"),
     0, &GNUNET_GETOPT_set_one, &outbound_only},
    GNUNET_GETOPT_OPTION_VERBOSE (&verbosity),
    GNUNET_GETOPT_OPTION_END
  };
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-dns-monitor",
                              gettext_noop
                              ("Monitor DNS queries."), options,
                              &run, NULL)) ? ret : 1;
}


/* end of gnunet-dns-monitor.c */
