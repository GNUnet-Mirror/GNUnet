/*
     This file is part of GNUnet.
     (C) 2009, 2010, 2011 Christian Grothoff (and other contributing authors)

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
 *
 * @file gns/gnunet-service-gns_interceptor.c
 * @brief GNUnet GNS interceptor logic
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_transport_service.h"
#include "gnunet_dns_service.h"
#include "gnunet_dnsparser_lib.h"
#include "gnunet-service-gns_resolver.h"
#include "gns.h"

#define MAX_DNS_LABEL_LENGTH 63

/**
 * Handle to a DNS intercepted
 * reslution request
 */
struct InterceptLookupHandle
{
  /* the request handle to reply to */
  struct GNUNET_DNS_RequestHandle *request_handle;
  
  /* the dns parser packet received */
  struct GNUNET_DNSPARSER_Packet *packet;
  
  /* the query parsed from the packet */
  struct GNUNET_DNSPARSER_Query *query;
};


/**
 * Our handle to the DNS handler library
 */
static struct GNUNET_DNS_Handle *dns_handle;

/**
 * The root zone for this interceptor
 */
static struct GNUNET_CRYPTO_ShortHashCode our_zone;

/**
 * Our priv key
 */
static struct GNUNET_CRYPTO_RsaPrivateKey *our_key;

/**
 * Default timeout
 */
static struct GNUNET_TIME_Relative default_lookup_timeout;

/**
 * Reply to dns request with the result from our lookup.
 *
 * @param cls the closure to the request (an InterceptLookupHandle)
 * @param rd_count the number of records to return
 * @param rd the record data
 */
static void
reply_to_dns(void* cls, uint32_t rd_count,
             const struct GNUNET_NAMESTORE_RecordData *rd)
{
  int i;
  size_t len;
  int ret;
  char *buf;
  struct InterceptLookupHandle* ilh = (struct InterceptLookupHandle*)cls;
  struct GNUNET_DNSPARSER_Packet *packet = ilh->packet;
  unsigned int num_answers = 0;
  
  
  /**
   * Put records in the DNS packet and modify it
   * to a response
   */
  for (i=0; i < rd_count; i++)
  {
    if (rd[i].record_type == ilh->query->type)
      num_answers++;
  }

  struct GNUNET_DNSPARSER_Record answer_records[num_answers];
  struct GNUNET_DNSPARSER_Record additional_records[rd_count-(num_answers)];
  packet->answers = answer_records;
  packet->additional_records = additional_records;

  for (i=0; i < rd_count; i++)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Adding type %d to DNS response\n", rd[i].record_type);
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Name: %s\n", ilh->query->name);
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Record %d/%d\n", i+1, rd_count);
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Record len %d\n", rd[i].data_size);
    
    if (rd[i].record_type == ilh->query->type)
    {
      answer_records[i].name = ilh->query->name;
      answer_records[i].type = rd[i].record_type;
      switch(rd[i].record_type)
      {
       case GNUNET_GNS_RECORD_TYPE_NS:
       case GNUNET_GNS_RECORD_TYPE_CNAME:
       case GNUNET_GNS_RECORD_TYPE_PTR:
         answer_records[i].data.hostname = (char*)rd[i].data;
         break;
       case GNUNET_GNS_RECORD_TYPE_SOA:
         answer_records[i].data.soa =
           (struct GNUNET_DNSPARSER_SoaRecord *)rd[i].data;
         break;
       case GNUNET_GNS_RECORD_MX:
         answer_records[i].data.mx =
           (struct GNUNET_DNSPARSER_MxRecord *)rd[i].data;
         break;
       default:
        answer_records[i].data.raw.data_len = rd[i].data_size;
        answer_records[i].data.raw.data = (char*)rd[i].data;
      }
      answer_records[i].expiration_time = rd[i].expiration;
      answer_records[i].class = GNUNET_DNSPARSER_CLASS_INTERNET;//hmmn
    }
    else
    {
      additional_records[i].name = ilh->query->name;
      additional_records[i].type = rd[i].record_type;
      switch(rd[i].record_type)
      {
       case GNUNET_GNS_RECORD_TYPE_NS:
       case GNUNET_GNS_RECORD_TYPE_CNAME:
       case GNUNET_GNS_RECORD_TYPE_PTR:
         additional_records[i].data.hostname = (char*)rd[i].data;
         break;
       case GNUNET_GNS_RECORD_TYPE_SOA:
         additional_records[i].data.soa =
           (struct GNUNET_DNSPARSER_SoaRecord *)rd[i].data;
         break;
       case GNUNET_GNS_RECORD_MX:
         additional_records[i].data.mx =
           (struct GNUNET_DNSPARSER_MxRecord *)rd[i].data;
         break;
       default:
        additional_records[i].data.raw.data_len = rd[i].data_size;
        additional_records[i].data.raw.data = (char*)rd[i].data;
      }
      additional_records[i].expiration_time = rd[i].expiration;
      additional_records[i].class = GNUNET_DNSPARSER_CLASS_INTERNET;//hmmn
    }
  }
  
  packet->num_answers = num_answers;
  packet->num_additional_records = rd_count-(num_answers);
  
  packet->flags.authoritative_answer = 1;

  if (rd == NULL)
    packet->flags.return_code = GNUNET_DNSPARSER_RETURN_CODE_NAME_ERROR;
  else
    packet->flags.return_code = GNUNET_DNSPARSER_RETURN_CODE_NO_ERROR;
  
  packet->flags.query_or_response = 1;

  
  /**
   * Reply to DNS
   */
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Building DNS response\n");
  ret = GNUNET_DNSPARSER_pack (packet,
                               1024, /* FIXME magic from dns redirector */
                               &buf,
                               &len);
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Built DNS response! (ret=%d,len=%d)\n", ret, len);
  if (ret == GNUNET_OK)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Answering DNS request\n");
    GNUNET_DNS_request_answer(ilh->request_handle,
                              len,
                              buf);

    GNUNET_free(buf);
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Answered DNS request\n");
  }
  else
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
               "Error building DNS response! (ret=%d)", ret);
  }
  
  packet->num_answers = 0;
  packet->answers = NULL;
  packet->num_additional_records = 0;
  packet->additional_records = NULL;
  GNUNET_DNSPARSER_free_packet(packet);
  GNUNET_free(ilh);
}


/**
 * Entry point for name resolution
 * Setup a new query and try to resolve
 *
 * @param request the request handle of the DNS request from a client
 * @param p the DNS query packet we received
 * @param q the DNS query we received parsed from p
 */
static void
start_resolution_for_dns(struct GNUNET_DNS_RequestHandle *request,
                          struct GNUNET_DNSPARSER_Packet *p,
                          struct GNUNET_DNSPARSER_Query *q)
{
  struct InterceptLookupHandle* ilh;
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting resolution for %s (type=%d)!\n",
              q->name, q->type);
  
  ilh = GNUNET_malloc(sizeof(struct InterceptLookupHandle));
  ilh->packet = p;
  ilh->query = q;
  ilh->request_handle = request;
  
  /* Start resolution in our zone */
  gns_resolver_lookup_record(our_zone, our_zone, q->type, q->name,
                             our_key,
                             default_lookup_timeout,
                             &reply_to_dns, ilh);
}



/**
 * The DNS request handler
 * Called for every incoming DNS request.
 *
 * @param cls closure
 * @param rh request handle to user for reply
 * @param request_length number of bytes in request
 * @param request udp payload of the DNS request
 */
static void
handle_dns_request(void *cls,
                   struct GNUNET_DNS_RequestHandle *rh,
                   size_t request_length,
                   const char *request)
{
  struct GNUNET_DNSPARSER_Packet *p;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Hijacked a DNS request...processing\n");
  p = GNUNET_DNSPARSER_parse (request, request_length);
  
  if (NULL == p)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Received malformed DNS packet, leaving it untouched\n");
    GNUNET_DNS_request_forward (rh);
    GNUNET_DNSPARSER_free_packet (p);
    return;
  }
  
  /**
   * Check tld and decide if we or
   * legacy dns is responsible
   *
   * FIXME now in theory there could be more than 1 query in the request
   * but if this is case we get into trouble:
   * either we query the GNS or the DNS. We cannot do both!
   * So I suggest to either only allow a single query per request or
   * only allow GNS or DNS requests.
   * The way it is implemented here now is buggy and will lead to erratic
   * behaviour (if multiple queries are present).
   */
  if (p->num_queries == 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No Queries in DNS packet... forwarding\n");
    GNUNET_DNS_request_forward (rh);
    GNUNET_DNSPARSER_free_packet(p);
    return;
  }

  if (p->num_queries > 1)
  {
    /* Note: We could also look for .gnunet */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                ">1 queriy in DNS packet... odd. We only process #1\n");
  }

  
  /**
   * Check for .gnunet/.zkey
   */
  
  if ((is_gnunet_tld(p->queries[0].name) == GNUNET_YES) ||
      (is_zkey_tld(p->queries[0].name) == GNUNET_YES) ||
      (strcmp(p->queries[0].name, GNUNET_GNS_TLD) == 0))
  {
    start_resolution_for_dns(rh, p, p->queries);
  }
  else
  {
    /**
     * This request does not concern us. Forward to real DNS.
     */
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "Request for %s is forwarded to DNS\n", p->queries[0].name);
    GNUNET_DNS_request_forward (rh);
    GNUNET_DNSPARSER_free_packet (p);
  }

}


/**
 * Initialized the interceptor
 *
 * @param zone the zone to work in
 * @param key the prov key of the zone (can be null, needed for caching)
 * @param c the configuration
 * @return GNUNET_OK on success
 */
int
gns_interceptor_init(struct GNUNET_CRYPTO_ShortHashCode zone,
                     struct GNUNET_CRYPTO_RsaPrivateKey *key,
                     const struct GNUNET_CONFIGURATION_Handle *c)
{
  unsigned long long default_lookup_timeout_secs = 0;

  GNUNET_log(GNUNET_ERROR_TYPE_INFO,
             "DNS hijacking enabled... connecting to service.\n");

  our_zone = zone;
  our_key = key;
  /**
   * Do gnunet dns init here
   */
  dns_handle = GNUNET_DNS_connect(c,
                                  GNUNET_DNS_FLAG_PRE_RESOLUTION,
                                  &handle_dns_request, /* rh */
                                  NULL); /* Closure */

  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_number(c, "gns",
                                            "DEFAULT_LOOKUP_TIMEOUT",
                                            &default_lookup_timeout_secs))
  {
    default_lookup_timeout = GNUNET_TIME_relative_multiply(
                                                  GNUNET_TIME_UNIT_SECONDS,
                                                  default_lookup_timeout_secs);
  }

  if (NULL == dns_handle)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
             "Failed to connect to the dnsservice!\n");
    return GNUNET_SYSERR;
  }

  return GNUNET_YES;
}

/**
 * Disconnect from interceptor
 */
void
gns_interceptor_stop(void)
{
  if (dns_handle)
    GNUNET_DNS_disconnect(dns_handle);
}

/* end of gns_interceptor.c */
