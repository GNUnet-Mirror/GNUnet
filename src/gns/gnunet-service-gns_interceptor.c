/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013 Christian Grothoff (and other contributing authors)

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
 * @file gns/gnunet-service-gns_interceptor.c
 * @brief GNUnet GNS interceptor logic
 * @author Martin Schanzenbach
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_dns_service.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet-service-gns_resolver.h"
#include "gnunet-service-gns_interceptor.h"
#include "gns.h"


/**
 * Handle to a DNS intercepted
 * reslution request
 */
struct InterceptLookupHandle
{

  /**
   * We keep these in a DLL.
   */
  struct InterceptLookupHandle *next;

  /**
   * We keep these in a DLL.
   */
  struct InterceptLookupHandle *prev;

  /**
   * the request handle to reply to
   */
  struct GNUNET_DNS_RequestHandle *request_handle;

  /**
   * the dns parser packet received
   */
  struct GNUNET_DNSPARSER_Packet *packet;

  /**
   * Handle for the lookup operation.
   */
  struct GNS_ResolverHandle *lookup;

};


/**
 * Our handle to the DNS handler library
 */
static struct GNUNET_DNS_Handle *dns_handle;

/**
 * Key of the zone we start lookups in.
 */
static struct GNUNET_CRYPTO_EcdsaPublicKey zone;

/**
 * Head of the DLL.
 */
static struct InterceptLookupHandle *ilh_head;

/**
 * Tail of the DLL.
 */
static struct InterceptLookupHandle *ilh_tail;


/**
 * Reply to dns request with the result from our lookup.
 *
 * @param cls the closure to the request (an InterceptLookupHandle)
 * @param rd_count the number of records to return
 * @param rd the record data
 */
static void
reply_to_dns (void *cls, uint32_t rd_count,
	      const struct GNUNET_GNSRECORD_Data *rd)
{
  struct InterceptLookupHandle *ilh = cls;
  struct GNUNET_DNSPARSER_Packet *packet = ilh->packet;
  struct GNUNET_DNSPARSER_Query *query = &packet->queries[0];
  uint32_t i;
  size_t len;
  int ret;
  char *buf;
  unsigned int num_answers;
  unsigned int skip_answers;
  unsigned int skip_additional;
  size_t off;

  /* Put records in the DNS packet */
  num_answers = 0;
  for (i=0; i < rd_count; i++)
    if (rd[i].record_type == query->type)
      num_answers++;
  skip_answers = 0;
  skip_additional = 0;

  {
    struct GNUNET_DNSPARSER_Record answer_records[num_answers];
    struct GNUNET_DNSPARSER_Record additional_records[rd_count - num_answers];

    packet->answers = answer_records;
    packet->additional_records = additional_records;
    /* FIXME: need to handle #GNUNET_GNSRECORD_RF_SHADOW_RECORD option
       (by ignoring records where this flag is set if there is any
       other record of that type in the result set) */
    for (i=0; i < rd_count; i++)
    {
      if (rd[i].record_type == query->type)
      {
	answer_records[i - skip_answers].name = query->name;
	answer_records[i - skip_answers].type = rd[i].record_type;
	switch(rd[i].record_type)
	{
	case GNUNET_DNSPARSER_TYPE_NS:
	case GNUNET_DNSPARSER_TYPE_CNAME:
	case GNUNET_DNSPARSER_TYPE_PTR:
	  answer_records[i - skip_answers].data.hostname
	    = GNUNET_DNSPARSER_parse_name (rd[i].data,
					   rd[i].data_size,
					   &off);
	  if ( (off != rd[i].data_size) ||
	       (NULL == answer_records[i].data.hostname) )
	  {
	    GNUNET_break_op (0);
	    skip_answers++;
	  }
	  break;
	case GNUNET_DNSPARSER_TYPE_SOA:
	  answer_records[i - skip_answers].data.soa
	    = GNUNET_DNSPARSER_parse_soa (rd[i].data,
					  rd[i].data_size,
					  &off);
	  if ( (off != rd[i].data_size) ||
	       (NULL == answer_records[i].data.soa) )
	  {
	    GNUNET_break_op (0);
	    skip_answers++;
	  }
	  break;
	case GNUNET_DNSPARSER_TYPE_SRV:
	  /* FIXME: SRV is not yet supported */
	  skip_answers++;
	  break;
	case GNUNET_DNSPARSER_TYPE_MX:
	  answer_records[i - skip_answers].data.mx
	    = GNUNET_DNSPARSER_parse_mx (rd[i].data,
					 rd[i].data_size,
					 &off);
	  if ( (off != rd[i].data_size) ||
	       (NULL == answer_records[i].data.hostname) )
	  {
	    GNUNET_break_op (0);
	    skip_answers++;
	  }
	  break;
	default:
	  answer_records[i - skip_answers].data.raw.data_len = rd[i].data_size;
	  answer_records[i - skip_answers].data.raw.data = (char*)rd[i].data;
	  break;
	}
	GNUNET_break (0 == (rd[i - skip_answers].flags & GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION));
	answer_records[i - skip_answers].expiration_time.abs_value_us = rd[i].expiration_time;
	answer_records[i - skip_answers].dns_traffic_class = GNUNET_TUN_DNS_CLASS_INTERNET;
      }
      else
      {
	additional_records[i - skip_additional].name = query->name;
	additional_records[i - skip_additional].type = rd[i].record_type;
	switch(rd[i].record_type)
	{
	case GNUNET_DNSPARSER_TYPE_NS:
	case GNUNET_DNSPARSER_TYPE_CNAME:
	case GNUNET_DNSPARSER_TYPE_PTR:
	  additional_records[i - skip_additional].data.hostname
	    = GNUNET_DNSPARSER_parse_name (rd[i].data,
					   rd[i].data_size,
					   &off);
	  if ( (off != rd[i].data_size) ||
	       (NULL == additional_records[i].data.hostname) )
	  {
	    GNUNET_break_op (0);
	    skip_additional++;
	  }
	  break;
	case GNUNET_DNSPARSER_TYPE_SOA:
	  additional_records[i - skip_additional].data.soa
	    = GNUNET_DNSPARSER_parse_soa (rd[i].data,
					  rd[i].data_size,
					  &off);
	  if ( (off != rd[i].data_size) ||
	       (NULL == additional_records[i].data.hostname) )
	  {
	    GNUNET_break_op (0);
	    skip_additional++;
	  }
	  break;
	case GNUNET_DNSPARSER_TYPE_MX:
	  additional_records[i - skip_additional].data.mx
	    = GNUNET_DNSPARSER_parse_mx (rd[i].data,
					 rd[i].data_size,
					 &off);
	  if ( (off != rd[i].data_size) ||
	       (NULL == additional_records[i].data.hostname) )
	  {
	    GNUNET_break_op (0);
	    skip_additional++;
	  }
	  break;
	case GNUNET_DNSPARSER_TYPE_SRV:
	  /* FIXME: SRV is not yet supported */
	  skip_answers++;
	  break;
	default:
	  additional_records[i - skip_additional].data.raw.data_len = rd[i].data_size;
	  additional_records[i - skip_additional].data.raw.data = (char*)rd[i].data;
	  break;
	}
	GNUNET_break (0 == (rd[i - skip_additional].flags & GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION));
	additional_records[i - skip_additional].expiration_time.abs_value_us = rd[i].expiration_time;
	additional_records[i - skip_additional].dns_traffic_class = GNUNET_TUN_DNS_CLASS_INTERNET;
      }
    }
    packet->num_answers = num_answers - skip_answers;
    packet->num_additional_records = rd_count - num_answers - skip_additional;
    packet->flags.authoritative_answer = 1;
    if (NULL == rd)
      packet->flags.return_code = GNUNET_TUN_DNS_RETURN_CODE_NAME_ERROR;
    else
      packet->flags.return_code = GNUNET_TUN_DNS_RETURN_CODE_NO_ERROR;
    packet->flags.query_or_response = 1;
    ret = GNUNET_DNSPARSER_pack (packet,
				 1024, /* maximum allowed size for DNS reply */
				 &buf,
				 &len);
    if (GNUNET_OK != ret)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Error converting GNS response to DNS response!\n"));
    }
    else
    {
      GNUNET_DNS_request_answer (ilh->request_handle,
				 len,
				 buf);
      GNUNET_free (buf);
    }
    packet->num_answers = 0;
    packet->answers = NULL;
    packet->num_additional_records = 0;
    packet->additional_records = NULL;
    GNUNET_DNSPARSER_free_packet (packet);
  }
  GNUNET_CONTAINER_DLL_remove (ilh_head, ilh_tail, ilh);
  GNUNET_free (ilh);
}


/**
 * The DNS request handler.  Called for every incoming DNS request.
 *
 * @param cls closure, unused
 * @param rh request handle to user for reply
 * @param request_length number of bytes in @a request
 * @param request UDP payload of the DNS request
 */
static void
handle_dns_request (void *cls,
		    struct GNUNET_DNS_RequestHandle *rh,
		    size_t request_length,
		    const char *request)
{
  struct GNUNET_DNSPARSER_Packet *p;
  struct InterceptLookupHandle *ilh;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Hijacked a DNS request. Processing.\n");
  if (NULL == (p = GNUNET_DNSPARSER_parse (request, request_length)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Received malformed DNS packet, leaving it untouched.\n");
    GNUNET_DNS_request_forward (rh);
    GNUNET_DNSPARSER_free_packet (p);
    return;
  }

  /* Check TLD and decide if we or legacy dns is responsible */
  if (1 != p->num_queries)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Not exactly one query in DNS packet. Forwarding untouched.\n");
    GNUNET_DNS_request_forward (rh);
    GNUNET_DNSPARSER_free_packet(p);
    return;
  }

  /* Check for GNS TLDs. */
  if ( (GNUNET_YES == is_gnu_tld (p->queries[0].name)) ||
       (GNUNET_YES == is_zkey_tld (p->queries[0].name)) ||
       (0 == strcmp (p->queries[0].name, GNUNET_GNS_TLD)) )
  {
    /* Start resolution in GNS */
    ilh = GNUNET_new (struct InterceptLookupHandle);
    GNUNET_CONTAINER_DLL_insert (ilh_head, ilh_tail, ilh);
    ilh->packet = p;
    ilh->request_handle = rh;
    ilh->lookup = GNS_resolver_lookup (&zone,
				       p->queries[0].type,
				       p->queries[0].name,
				       NULL /* FIXME: enable shorten for DNS intercepts? */,
				       GNUNET_NO,
				       &reply_to_dns, ilh);
    return;
  }
  /* This request does not concern us. Forward to real DNS. */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Request for `%s' is forwarded to DNS untouched.\n",
	      p->queries[0].name);
  GNUNET_DNS_request_forward (rh);
  GNUNET_DNSPARSER_free_packet (p);
}


/**
 * Initialized the interceptor
 *
 * @param gnu_zone the zone to work in
 * @param c the configuration
 * @return #GNUNET_OK on success
 */
int
GNS_interceptor_init (const struct GNUNET_CRYPTO_EcdsaPublicKey *gnu_zone,
		      const struct GNUNET_CONFIGURATION_Handle *c)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      "DNS hijacking enabled. Connecting to DNS service.\n");
  zone = *gnu_zone;
  dns_handle = GNUNET_DNS_connect (c,
				   GNUNET_DNS_FLAG_PRE_RESOLUTION,
				   &handle_dns_request,
				   NULL);
  if (NULL == dns_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		_("Failed to connect to the DNS service!\n"));
    return GNUNET_SYSERR;
  }
  return GNUNET_YES;
}


/**
 * Disconnect from interceptor
 */
void
GNS_interceptor_done ()
{
  struct InterceptLookupHandle *ilh;

  while (NULL != (ilh = ilh_head))
  {
    GNUNET_CONTAINER_DLL_remove (ilh_head, ilh_tail, ilh);
    GNS_resolver_lookup_cancel (ilh->lookup);
    GNUNET_DNS_request_drop (ilh->request_handle);
    GNUNET_DNSPARSER_free_packet (ilh->packet);
    GNUNET_free (ilh);
  }
  if (NULL != dns_handle)
  {
    GNUNET_DNS_disconnect (dns_handle);
    dns_handle = NULL;
  }
}

/* end of gnunet-service-gns_interceptor.c */
