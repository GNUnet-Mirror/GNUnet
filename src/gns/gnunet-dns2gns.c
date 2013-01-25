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
 * @file gnunet-dns2gns.c
 * @brief DNS server that translates DNS requests to GNS
 * @author Christian Grothoff
 */
#include "platform.h"
#include <gnunet_util_lib.h>
#include <gnunet_dnsparser_lib.h>
#include <gnunet_gns_service.h>
#include <gnunet_dnsstub_lib.h>
#include "gns.h"

/**
 * Timeout for DNS requests.
 */
#define TIMEOUT GNUNET_TIME_UNIT_MINUTES

/**
 * Default suffix
 */
#define DNS_SUFFIX ".zkey.eu"

/**
 * FCFS suffix
 */
#define FCFS_SUFFIX "fcfs.zkey.eu"

/**
 * Data kept per request.
 */
struct Request
{
  /**
   * Socket to use for sending the reply.
   */
  struct GNUNET_NETWORK_Handle *lsock;

  /**
   * Destination address to use.
   */
  const void *addr;

  /**
   * Initially, this is the DNS request, it will then be
   * converted to the DNS response.
   */
  struct GNUNET_DNSPARSER_Packet *packet;
  
  /**
   * Our GNS request handle.
   */
  struct GNUNET_GNS_LookupRequest *lookup;

  /**
   * Our DNS request handle
   */
  struct GNUNET_DNSSTUB_RequestSocket *dns_lookup;

  /**
   * Task run on timeout or shutdown to clean up without
   * response.
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * Number of bytes in 'addr'.
   */ 
  size_t addr_len;

};


/**
 * Handle to GNS resolver.
 */
struct GNUNET_GNS_Handle *gns;

/**
 * Stub resolver
 */
struct GNUNET_DNSSTUB_Context *dns_stub;

/**
 * Listen socket for IPv4.
 */
static struct GNUNET_NETWORK_Handle *listen_socket4;

/**
 * Listen socket for IPv6.
 */
static struct GNUNET_NETWORK_Handle *listen_socket6;

/**
 * Task for IPv4 socket.
 */
static GNUNET_SCHEDULER_TaskIdentifier t4;

/**
 * Task for IPv6 socket.
 */
static GNUNET_SCHEDULER_TaskIdentifier t6;

/**
 * DNS suffix, suffix of this gateway in DNS; defaults to '.zkey.eu'
 */
static char *dns_suffix;

/**
 * FCFS suffix, suffix of FCFS-authority in DNS; defaults to 'fcfs.zkey.eu'.
 */
static char *fcfs_suffix;

/**
 * IP of DNS server
 */
static char *dns_ip;

/**
 * UDP Port we listen on for inbound DNS requests.
 */
static unsigned int listen_port = 53;


/**
 * Task run on shutdown.  Cleans up everything.
 *
 * @param cls unused
 * @param tc scheduler context
 */
static void
do_shutdown (void *cls,
	     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (GNUNET_SCHEDULER_NO_TASK != t4)
    GNUNET_SCHEDULER_cancel (t4);
  if (GNUNET_SCHEDULER_NO_TASK != t6)
    GNUNET_SCHEDULER_cancel (t6);
  if (NULL != listen_socket4)
  {
    GNUNET_NETWORK_socket_close (listen_socket4);
    listen_socket4 = NULL;
  }
  if (NULL != listen_socket6)
  {
    GNUNET_NETWORK_socket_close (listen_socket6);
    listen_socket6 = NULL;
  }
  GNUNET_GNS_disconnect (gns);
  gns = NULL;
  GNUNET_DNSSTUB_stop (dns_stub);
  dns_stub = NULL;
}


/**
 * Send the response for the given request and clean up.
 *
 * @param request context for the request.
 */
static void
send_response (struct Request *request)
{
  char *buf;
  size_t size;
  
  if (GNUNET_SYSERR ==
      GNUNET_DNSPARSER_pack (request->packet,
			     UINT16_MAX /* is this not too much? */,
			     &buf,
			     &size))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Failed to pack DNS response into UDP packet!\n"));
    }
  else
    {
      if (size !=
	  GNUNET_NETWORK_socket_sendto (request->lsock,
					buf, size,
					request->addr,
					request->addr_len))
	GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "sendto");
      GNUNET_free (buf);
    }
  GNUNET_SCHEDULER_cancel (request->timeout_task);
  GNUNET_DNSPARSER_free_packet (request->packet);
  GNUNET_free (request);
}


/**
 * Task run on timeout.  Cleans up request.
 *
 * @param cls 'struct Request' of the request to clean up
 * @param tc scheduler context
 */
static void
do_timeout (void *cls,
	    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Request *request = cls;

  if (NULL != request->packet)
    GNUNET_DNSPARSER_free_packet (request->packet);
  if (NULL != request->lookup)
    GNUNET_GNS_cancel_lookup_request (request->lookup);
  if (NULL != request->dns_lookup)
    GNUNET_DNSSTUB_resolve_cancel (request->dns_lookup);
  GNUNET_free (request);
}


/**
 * Iterator called on obtained result for a DNS
 * lookup
 *
 * @param cls closure
 * @param rs the request socket
 * @param dns the DNS udp payload
 * @param r size of the DNS payload
 */
static void
dns_result_processor (void *cls,
                  struct GNUNET_DNSSTUB_RequestSocket *rs,
                  const struct GNUNET_TUN_DnsHeader *dns,
                  size_t r)
{
  struct Request *request = cls;

  request->packet = GNUNET_DNSPARSER_parse ((char*)dns, r);
  send_response (request);
}


/**
 * Iterator called on obtained result for a GNS
 * lookup
 *
 * @param cls closure
 * @param rd_count number of records
 * @param rd the records in reply
 */
static void
result_processor (void *cls,
		  uint32_t rd_count,
		  const struct GNUNET_NAMESTORE_RecordData *rd)
{
  struct Request *request = cls;
  struct GNUNET_DNSPARSER_Packet *packet;
  uint32_t i;
  struct GNUNET_DNSPARSER_Record rec;

  request->lookup = NULL;
  packet = request->packet;
  packet->flags.query_or_response = 1;
  packet->flags.return_code = GNUNET_DNSPARSER_RETURN_CODE_NO_ERROR;
  packet->flags.checking_disabled = 0;
  packet->flags.authenticated_data = 1;
  packet->flags.zero = 0;
  packet->flags.recursion_available = 1;
  packet->flags.message_truncated = 0;
  packet->flags.authoritative_answer = 0;
  //packet->flags.opcode = GNUNET_DNSPARSER_OPCODE_STATUS; // ???
  for (i=0;i<rd_count;i++)
    {
      rec.expiration_time.abs_value = rd[i].expiration_time;
      switch (rd[i].record_type)
	{
	case GNUNET_DNSPARSER_TYPE_A:
	  GNUNET_assert (sizeof (struct in_addr) == rd[i].data_size);
	  rec.name = GNUNET_strdup (packet->queries[0].name);
	  rec.class = GNUNET_DNSPARSER_CLASS_INTERNET;
	  rec.type = GNUNET_DNSPARSER_TYPE_A;
	  rec.data.raw.data = GNUNET_malloc (sizeof (struct in_addr));
	  memcpy (rec.data.raw.data,
		  rd[i].data,
		  rd[i].data_size);
	  rec.data.raw.data_len = sizeof (struct in_addr);
	  GNUNET_array_append (packet->answers,
			       packet->num_answers,
			       rec);
	  break;
	case GNUNET_DNSPARSER_TYPE_AAAA:
	  GNUNET_assert (sizeof (struct in6_addr) == rd[i].data_size);
	  rec.name = GNUNET_strdup (packet->queries[0].name);
	  rec.data.raw.data = GNUNET_malloc (sizeof (struct in6_addr));
	  rec.class = GNUNET_DNSPARSER_CLASS_INTERNET;
	  rec.type = GNUNET_DNSPARSER_TYPE_AAAA;
	  memcpy (rec.data.raw.data,
		  rd[i].data,
		  rd[i].data_size);
	  rec.data.raw.data_len = sizeof (struct in6_addr);
	  GNUNET_array_append (packet->answers,
			       packet->num_answers,
			       rec);
	  break;
	case GNUNET_DNSPARSER_TYPE_CNAME:
	  rec.name = GNUNET_strdup (packet->queries[0].name);
	  rec.data.hostname = strdup (rd[i].data);
	  rec.class = GNUNET_DNSPARSER_CLASS_INTERNET;
	  rec.type = GNUNET_DNSPARSER_TYPE_CNAME;
	  memcpy (rec.data.hostname,
		  rd[i].data,
		  rd[i].data_size);
	  GNUNET_array_append (packet->answers,
			       packet->num_answers,
			       rec);
	  break;
	default:
	  /* skip */
	  break;
	}
    }
  send_response (request);
}


/**
 * Handle DNS request.
 *
 * @param lsock socket to use for sending the reply
 * @param addr address to use for sending the reply
 * @param addr_len number of bytes in addr
 * @param udp_msg DNS request payload
 * @param udp_msg_size number of bytes in udp_msg 
 */
static void
handle_request (struct GNUNET_NETWORK_Handle *lsock,
		const void *addr,
		size_t addr_len,
		const char *udp_msg,
		size_t udp_msg_size)
{
  struct Request *request;
  struct GNUNET_DNSPARSER_Packet *packet;
  char *name;
  char *dot;
  char *nname;
  size_t name_len;
  enum GNUNET_GNS_RecordType type;
  int use_gns;
  struct GNUNET_CRYPTO_ShortHashCode zone;

  packet = GNUNET_DNSPARSER_parse (udp_msg, udp_msg_size);
  if (NULL == packet)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Cannot parse DNS request from %s\n"),
		  GNUNET_a2s (addr, addr_len));
      return;
    }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received request for `%s' with flags %u, #answers %d, #auth %d, #additional %d\n",
	      packet->queries[0].name,
	      (unsigned int) packet->flags.query_or_response,
	      (int) packet->num_answers,
	      (int) packet->num_authority_records,
	      (int) packet->num_additional_records);
  if ( (0 != packet->flags.query_or_response) || 
       (0 != packet->num_answers) ||
       (0 != packet->num_authority_records))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Received malformed DNS request from %s\n"),
		  GNUNET_a2s (addr, addr_len));
      GNUNET_DNSPARSER_free_packet (packet);
      return;
    }
  if ( (1 != packet->num_queries) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Received unsupported DNS request from %s\n"),
		  GNUNET_a2s (addr, addr_len));
      GNUNET_DNSPARSER_free_packet (packet);
      return;
    }
  request = GNUNET_malloc (sizeof (struct Request) + addr_len);
  request->lsock = lsock;
  request->packet = packet;
  request->addr = &request[1];
  request->addr_len = addr_len;
  memcpy (&request[1], addr, addr_len);
  request->timeout_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
							&do_timeout,
							request);
  name = GNUNET_strdup (packet->queries[0].name);
  name_len = strlen (name);
  use_gns = GNUNET_NO;
  if ( (name_len > strlen (dns_suffix)) &&
       (0 == strcasecmp (dns_suffix,
			 &name[name_len - strlen (dns_suffix)])) )
    {
      /* Test if '.zkey' was requested */
      name[name_len - strlen (dns_suffix)] = '\0';
      dot = strrchr (name, (int) '.');
      if ( (NULL != dot) &&
	   (GNUNET_OK ==
	    GNUNET_CRYPTO_short_hash_from_string (dot + 1, &zone)) )
      {
	/* valid '.zkey' name */
	GNUNET_asprintf (&nname, 
			 "%s.%s", 
			 name, 
			 GNUNET_GNS_TLD_ZKEY);
	GNUNET_free (name);
	name = nname;
      }
      else
      {	
	/* try '.gads' name */
	GNUNET_asprintf (&nname, 
			 "%s.%s", 
			 name, 
			 GNUNET_GNS_TLD);
	GNUNET_free (name);
	name = nname;
      }
      name_len = strlen (name);
    }
  if ( (name_len >= strlen ((GNUNET_GNS_TLD))) &&
       (0 == strcasecmp (GNUNET_GNS_TLD,
                         &name[name_len - strlen (GNUNET_GNS_TLD)])) )
    use_gns = GNUNET_YES;

  if ( (name_len > strlen (GNUNET_GNS_TLD_ZKEY)) &&
       (0 == strcasecmp (GNUNET_GNS_TLD_ZKEY,
                         &name[name_len - strlen (GNUNET_GNS_TLD_ZKEY)])) )
    use_gns = GNUNET_YES;

  if (GNUNET_YES == use_gns)
  {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		   "Calling GNS\n");
      type = packet->queries[0].type;
      request->lookup = GNUNET_GNS_lookup (gns,
					   name,
					   type,
					   GNUNET_NO,
					   NULL,
					   &result_processor,
					   request);
    }
  else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		   "Calling DNS at %s\n", dns_ip);
      GNUNET_DNSPARSER_free_packet (request->packet);
      request->packet = NULL;
      request->dns_lookup = GNUNET_DNSSTUB_resolve2 (dns_stub,
                                                     udp_msg,
                                                     udp_msg_size,
                                                     &dns_result_processor,
                                                     request);
    }
  GNUNET_free (name);
}


/**
 * Task to read IPv4 DNS packets.
 *
 * @param cls the 'listen_socket4'
 * @param tc scheduler context
 */ 
static void
read_dns4 (void *cls,
	   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct sockaddr_in v4;
  socklen_t addrlen;
  ssize_t size;

  GNUNET_assert (listen_socket4 == cls);
  t4 = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
				      listen_socket4,
				      &read_dns4,
				      listen_socket4);
  if (0 == (GNUNET_SCHEDULER_REASON_READ_READY & tc->reason))
    return; /* shutdown? */
  size = GNUNET_NETWORK_socket_recvfrom_amount (listen_socket4);
  if (0 > size)
    {
      GNUNET_break (0);
      return; /* read error!? */
    }
  {
    char buf[size];
    
    addrlen = sizeof (v4);
    GNUNET_break (size == 
		  GNUNET_NETWORK_socket_recvfrom (listen_socket4,
						  buf,
						  size,
						  (struct sockaddr *) &v4,
						  &addrlen));
    handle_request (listen_socket4, &v4, addrlen,
		    buf, size);
  }
}


/**
 * Task to read IPv6 DNS packets.
 *
 * @param cls the 'listen_socket6'
 * @param tc scheduler context
 */ 
static void
read_dns6 (void *cls,
	   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct sockaddr_in6 v6;
  socklen_t addrlen;
  ssize_t size;

  GNUNET_assert (listen_socket6 == cls);
  t6 = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
				      listen_socket6,
				      &read_dns6,
				      listen_socket6);
  if (0 == (GNUNET_SCHEDULER_REASON_READ_READY & tc->reason))
    return; /* shutdown? */
  size = GNUNET_NETWORK_socket_recvfrom_amount (listen_socket6);
  if (0 > size)
    {
      GNUNET_break (0);
      return; /* read error!? */
    }
  {
    char buf[size];
    
    addrlen = sizeof (v6);
    GNUNET_break (size == 
		  GNUNET_NETWORK_socket_recvfrom (listen_socket6,
						  buf,
						  size,
						  (struct sockaddr *) &v6,
						  &addrlen));
    handle_request (listen_socket6, &v6, addrlen,
		    buf, size);
  }
}


/**
 * Main function that will be run.
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
  if (NULL == dns_ip)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No DNS server specified!\n");
    return;
  }

  if (NULL == dns_suffix)
    dns_suffix = DNS_SUFFIX;
  if (NULL == fcfs_suffix)
    fcfs_suffix = FCFS_SUFFIX;
  if (NULL == (gns = GNUNET_GNS_connect (cfg)))
    return;
  if (NULL == (dns_stub = GNUNET_DNSSTUB_start (dns_ip)))
    {
      GNUNET_GNS_disconnect (gns);
      gns = NULL;
      return;
    }
  listen_socket4 = GNUNET_NETWORK_socket_create (PF_INET,
						 SOCK_DGRAM, 
						 IPPROTO_UDP);
  if (NULL != listen_socket4)
    {
      struct sockaddr_in v4;

      memset (&v4, 0, sizeof (v4));
      v4.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
      v4.sin_len = sizeof (v4);
#endif
      v4.sin_port = htons (listen_port);
      if (GNUNET_OK !=
	  GNUNET_NETWORK_socket_bind (listen_socket4,
				      (struct sockaddr *) &v4,
				      sizeof (v4)))
	{
	  GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "bind");
	  GNUNET_NETWORK_socket_close (listen_socket4);
	  listen_socket4 = NULL;
	}
    }
  listen_socket6 = GNUNET_NETWORK_socket_create (PF_INET6,
						SOCK_DGRAM, 
						IPPROTO_UDP);
  if (NULL != listen_socket6)
    {
      struct sockaddr_in6 v6;

      memset (&v6, 0, sizeof (v6));
      v6.sin6_family = AF_INET6;
#if HAVE_SOCKADDR_IN_SIN_LEN
      v6.sin6_len = sizeof (v6);
#endif
      v6.sin6_port = htons (listen_port);
      if (GNUNET_OK !=
	  GNUNET_NETWORK_socket_bind (listen_socket6,
				      (struct sockaddr *) &v6,
				      sizeof (v6)))
	{
	  GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "bind");
	  GNUNET_NETWORK_socket_close (listen_socket6);
	  listen_socket6 = NULL;
	}
    }
  if ( (NULL == listen_socket4) &&
       (NULL == listen_socket6) )
    {
      GNUNET_GNS_disconnect (gns);
      gns = NULL;
      GNUNET_DNSSTUB_stop (dns_stub);
      dns_stub = NULL;
      return;
    }
  if (NULL != listen_socket4)
    t4 = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
					listen_socket4,
					&read_dns4,
					listen_socket4);
  if (NULL != listen_socket6)
    t6 = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
					listen_socket6,
					&read_dns6,
					listen_socket6);

  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
				&do_shutdown, NULL);
}


/**
 * The main function for the fcfs daemon.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, 
      char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'d', "dns", "IP",
      gettext_noop ("IP of recursive DNS resolver to use (required)"), 1,
      &GNUNET_GETOPT_set_string, &dns_ip},
    {'s', "suffix", "SUFFIX",
      gettext_noop ("Authoritative DNS suffix to use (optional); default: zkey.eu"), 1,
      &GNUNET_GETOPT_set_string, &dns_suffix},
    {'f', "fcfs", "NAME",
      gettext_noop ("Authoritative FCFS suffix to use (optional); default: fcfs.zkey.eu"), 1,
      &GNUNET_GETOPT_set_string, &fcfs_suffix},
    {'p', "port", "UDPPORT",
      gettext_noop ("UDP port to listen on for inbound DNS requests; default: 53"), 1,
      &GNUNET_GETOPT_set_uint, &listen_port},
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv,
						 &argc, &argv))
    return 2;
  GNUNET_log_setup ("gnunet-dns2gns", "WARNING", NULL);
  ret =
      (GNUNET_OK ==
       GNUNET_PROGRAM_run (argc, argv, "gnunet-dns2gns",
                           _("GNUnet DNS-to-GNS proxy (a DNS server)"), 
			   options,
                           &run, NULL)) ? 0 : 1;
  GNUNET_free ((void*) argv);
  return ret;
}

/* end of gnunet-dns2gns.c */
