/*
     This file is part of GNUnet
     Copyright (C) 2018 GNUnet e.V.

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/
/**
 * @file src/namestore/gnunet-zoneimport.c
 * @brief import a DNS zone for publication in GNS, incremental
 * @author Christian Grothoff
 */
#include "platform.h"
#include <gnunet_util_lib.h>
#include <gnunet_dnsstub_lib.h>
#include <gnunet_dnsparser_lib.h>
#include <gnunet_gnsrecord_lib.h>
#include <gnunet_namestore_service.h>
#include <gnunet_identity_service.h>


/**
 * Maximum number of queries pending at the same time.
 */
#define THRESH 100

/**
 * TIME_THRESH is in usecs.  How quickly do we submit fresh queries.
 * Used as an additional throttle.
 */
#define TIME_THRESH 10

/**
 * How often do we retry a query before giving up for good?
 */
#define MAX_RETRIES 5


/**
 * Some zones may include authoritative records for other
 * zones, such as foo.com.uk or bar.com.fr.  As for GNS
 * each dot represents a zone cut, we then need to create a
 * zone on-the-fly to capture those records properly.
 */
struct Zone
{

  /**
   * Kept in a DLL.
   */
  struct Zone *next;

  /**
   * Kept in a DLL.
   */
  struct Zone *prev;

  /**
   * Domain of the zone (i.e. "fr" or "com.fr")
   */
  char *domain;

  /**
   * Private key of the zone.
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey key;

};


/**
 * Record for the request to be stored by GNS.
 */
struct Record
{
  /**
   * Kept in a DLL.
   */
  struct Record *next;

  /**
   * Kept in a DLL.
   */
  struct Record *prev;

  /**
   * GNS record.
   */
  struct GNUNET_GNSRECORD_Data grd;

};


/**
 * Request we should make.
 */
struct Request
{
  /**
   * Requests are kept in a heap while waiting to be resolved.
   */
  struct GNUNET_CONTAINER_HeapNode *hn;

  /**
   * Active requests are kept in a DLL.
   */
  struct Request *next;

  /**
   * Active requests are kept in a DLL.
   */
  struct Request *prev;

  /**
   * Head of records that should be published in GNS for
   * this hostname.
   */
  struct Record *rec_head;

  /**
   * Tail of records that should be published in GNS for
   * this hostname.
   */
  struct Record *rec_tail;

  /**
   * Socket used to make the request, NULL if not active.
   */
  struct GNUNET_DNSSTUB_RequestSocket *rs;

  /**
   * Raw DNS query.
   */
  void *raw;

  /**
   * Hostname we are resolving.
   */
  char *hostname;

  /**
   * Label (without TLD) which we are resolving.
   */
  char *label;

  /**
   * Namestore operation pending for this record.
   */
  struct GNUNET_NAMESTORE_QueueEntry *qe;

  /**
   * Zone responsible for this request.
   */
  const struct Zone *zone;

  /**
   * Answer we got back and are currently parsing, or NULL
   * if not active.
   */
  struct GNUNET_DNSPARSER_Packet *p;

  /**
   * At what time does the (earliest) of the returned records
   * for this name expire? At this point, we need to re-fetch
   * the record.
   */
  struct GNUNET_TIME_Absolute expires;

  /**
   * Number of bytes in @e raw.
   */
  size_t raw_len;

  /**
   * When did we last issue this request?
   */
  time_t time;

  /**
   * How often did we issue this query? (And failed, reset
   * to zero once we were successful.)
   */
  int issue_num;

  /**
   * random 16-bit DNS query identifier.
   */
  uint16_t id;
};


/**
 * Handle to the identity service.
 */
static struct GNUNET_IDENTITY_Handle *id;

/**
 * Namestore handle.
 */
static struct GNUNET_NAMESTORE_Handle *ns;

/**
 * Context for DNS resolution.
 */
static struct GNUNET_DNSSTUB_Context *ctx;

/**
 * The number of queries that are outstanding
 */
static unsigned int pending;

/**
 * Number of lookups we performed overall.
 */
static unsigned int lookups;

/**
 * How many hostnames did we reject (malformed).
 */
static unsigned int rejects;

/**
 * Number of lookups that failed.
 */
static unsigned int failures;

/**
 * Number of records we found.
 */
static unsigned int records;

/**
 * #GNUNET_YES if we have more work to be read from `stdin`.
 */
static int stdin_waiting;

/**
 * Heap of all requests to perform, sorted by
 * the time we should next do the request (i.e. by expires).
 */
static struct GNUNET_CONTAINER_Heap *req_heap;

/**
 * Active requests are kept in a DLL.
 */
static struct Request *req_head;

/**
 * Active requests are kept in a DLL.
 */
static struct Request *req_tail;

/**
 * Main task.
 */
static struct GNUNET_SCHEDULER_Task *t;

/**
 * Which DNS server do we use for queries?
 */
static char *dns_server;

/**
 * Head of list of zones we are managing.
 */
static struct Zone *zone_head;

/**
 * Tail of list of zones we are managing.
 */
static struct Zone *zone_tail;


/**
 * Callback for #for_all_records
 *
 * @param cls closure
 * @param rec a DNS record
 */
typedef void
(*RecordProcessor) (void *cls,
		    const struct GNUNET_DNSPARSER_Record *rec);


/**
 * Call @a rp for each record in @a p, regardless of
 * what response section it is in.
 *
 * @param p packet from DNS
 * @param rp function to call
 * @param rp_cls closure for @a rp
 */
static void
for_all_records (const struct GNUNET_DNSPARSER_Packet *p,
		 RecordProcessor rp,
		 void *rp_cls)
{
  for (unsigned int i=0;i<p->num_answers;i++)
  {
    struct GNUNET_DNSPARSER_Record *rs = &p->answers[i];

    rp (rp_cls,
	rs);
  }
  for (unsigned int i=0;i<p->num_authority_records;i++)
  {
    struct GNUNET_DNSPARSER_Record *rs = &p->authority_records[i];

    rp (rp_cls,
	rs);
  }
  for (unsigned int i=0;i<p->num_additional_records;i++)
  {
    struct GNUNET_DNSPARSER_Record *rs = &p->additional_records[i];

    rp (rp_cls,
	rs);
  }
}


/**
 * Free @a req and data structures reachable from it.
 *
 * @param req request to free
 */
static void
free_request (struct Request *req)
{
  struct Record *rec;

  while (NULL != (rec = req->rec_head))
  {
    GNUNET_CONTAINER_DLL_remove (req->rec_head,
				 req->rec_tail,
				 rec);
    GNUNET_free (rec);
  }
  GNUNET_free (req->hostname);
  GNUNET_free (req->label);
  GNUNET_free (req->raw);
  GNUNET_free (req);
}


/**
 * Process as many requests as possible from the queue.
 *
 * @param cls NULL
 */
static void
process_queue (void *cls);


/**
 * Insert @a req into DLL sorted by next fetch time.
 *
 * @param req request to insert into #req_heap
 */
static void
insert_sorted (struct Request *req)
{
  req->hn = GNUNET_CONTAINER_heap_insert (req_heap,
                                          req,
                                          req->expires.abs_value_us);
  if (req == GNUNET_CONTAINER_heap_peek (req_heap))
  {
    if (NULL != t)
      GNUNET_SCHEDULER_cancel (t);
    t = GNUNET_SCHEDULER_add_at (req->expires,
				 &process_queue,
				 NULL);
  }
}


/**
 * Add record to the GNS record set for @a req.
 *
 * @param req the request to expand GNS record set for
 * @param type type to use
 * @param expiration_time when should @a rec expire
 * @param data raw data to store
 * @param data_len number of bytes in @a data
 */
static void
add_record (struct Request *req,
	    uint32_t type,
	    struct GNUNET_TIME_Absolute expiration_time,
	    const void *data,
	    size_t data_len)
{
  struct Record *rec;

  rec = GNUNET_malloc (sizeof (struct Record) + data_len);
  rec->grd.data = &rec[1];
  rec->grd.expiration_time = expiration_time.abs_value_us;
  rec->grd.data_size = data_len;
  rec->grd.record_type = type;
  rec->grd.flags = GNUNET_GNSRECORD_RF_NONE;
  GNUNET_memcpy (&rec[1],
		 data,
		 data_len);
  GNUNET_CONTAINER_DLL_insert (req->rec_head,
			       req->rec_tail,
			       rec);
}


/**
 * Closure for #check_for_glue.
 */
struct GlueClosure
{
  /**
   * Overall request we are processing.
   */
  struct Request *req;

  /**
   * NS name we are looking for glue for.
   */
  const char *ns;

  /**
   * Set to #GNUNET_YES if glue was found.
   */
  int found;
};


/**
 * Try to find glue records for a given NS record.
 *
 * @param cls a `struct GlueClosure *`
 * @param rec record that may contain glue information
 */
static void
check_for_glue (void *cls,
		const struct GNUNET_DNSPARSER_Record *rec)
{
  struct GlueClosure *gc = cls;
  char dst[65536];
  size_t dst_len;
  size_t off;
  char ip[INET6_ADDRSTRLEN+1];
  socklen_t ip_size = (socklen_t) sizeof (ip);

  if (0 != strcasecmp (rec->name,
		       gc->ns))
    return;
  dst_len = sizeof (dst);
  off = 0;
  switch (rec->type)
  {
  case GNUNET_DNSPARSER_TYPE_A:
    if (sizeof (struct in_addr) != rec->data.raw.data_len)
    {
      GNUNET_break (0);
      return;
    }
    if (NULL ==
	inet_ntop (AF_INET,
		   rec->data.raw.data,
		   ip,
		   ip_size))
    {
      GNUNET_break (0);
      return;
    }
    if ( (GNUNET_OK ==
	  GNUNET_DNSPARSER_builder_add_name (dst,
					     dst_len,
					     &off,
					     gc->req->hostname)) &&
	 (GNUNET_OK ==
	  GNUNET_DNSPARSER_builder_add_name (dst,
					     dst_len,
					     &off,
					     ip)) )
    {
      add_record (gc->req,
		  GNUNET_GNSRECORD_TYPE_GNS2DNS,
		  rec->expiration_time,
		  dst,
		  off);
      gc->found = GNUNET_YES;
    }
    break;
  case GNUNET_DNSPARSER_TYPE_AAAA:
    if (sizeof (struct in6_addr) != rec->data.raw.data_len)
    {
      GNUNET_break (0);
      return;
    }
    if (NULL ==
	inet_ntop (AF_INET6,
		   rec->data.raw.data,
		   ip,
		   ip_size))
    {
      GNUNET_break (0);
      return;
    }
    if ( (GNUNET_OK ==
	  GNUNET_DNSPARSER_builder_add_name (dst,
					     dst_len,
					     &off,
					     gc->req->hostname)) &&
	 (GNUNET_OK ==
	  GNUNET_DNSPARSER_builder_add_name (dst,
					     dst_len,
					     &off,
					     ip)) )
    {
      add_record (gc->req,
		  GNUNET_GNSRECORD_TYPE_GNS2DNS,
		  rec->expiration_time,
		  dst,
		  off);
      gc->found = GNUNET_YES;
    }
    break;
  case GNUNET_DNSPARSER_TYPE_CNAME:
    if ( (GNUNET_OK ==
	  GNUNET_DNSPARSER_builder_add_name (dst,
					     dst_len,
					     &off,
					     gc->req->hostname)) &&
	 (GNUNET_OK ==
	  GNUNET_DNSPARSER_builder_add_name (dst,
					     dst_len,
					     &off,
					     rec->data.hostname)) )
    {
      add_record (gc->req,
		  GNUNET_GNSRECORD_TYPE_GNS2DNS,
		  rec->expiration_time,
		  dst,
		  off);
      gc->found = GNUNET_YES;
    }
    break;
  default:
    /* useless, do nothing */
    break;
  }
}


/**
 * We received @a rec for @a req. Remember the answer.
 *
 * @param cls a `struct Request`
 * @param rec response
 */
static void
process_record (void *cls,
                const struct GNUNET_DNSPARSER_Record *rec)
{
  struct Request *req = cls;
  char dst[65536];
  size_t dst_len;
  size_t off;

  dst_len = sizeof (dst);
  off = 0;
  records++;
  if (0 != strcasecmp (rec->name,
		       req->hostname))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"DNS returned record for `%s' of type %u while resolving `%s'\n",
		rec->name,
		(unsigned int) rec->type,
		req->hostname);
    return; /* does not match hostname, might be glue, but
	       not useful for this pass! */
  }
  if (0 ==
      GNUNET_TIME_absolute_get_remaining (rec->expiration_time).rel_value_us)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"DNS returned expired record for `%s'\n",
		req->hostname);
    return; /* record expired */
  }
  switch (rec->type)
  {
  case GNUNET_DNSPARSER_TYPE_NS:
    {
      struct GlueClosure gc;

      /* check for glue */
      gc.req = req;
      gc.ns = rec->data.hostname;
      gc.found = GNUNET_NO;
      for_all_records (req->p,
		       &check_for_glue,
		       &gc);
      if ( (GNUNET_NO == gc.found) &&
	   (GNUNET_OK ==
	    GNUNET_DNSPARSER_builder_add_name (dst,
					       dst_len,
					       &off,
					       req->hostname)) &&
	   (GNUNET_OK ==
	    GNUNET_DNSPARSER_builder_add_name (dst,
					       dst_len,
					       &off,
					       rec->data.hostname)) )
      {
	/* FIXME: actually check if this is out-of-bailiwick,
	   and if not request explicit resolution... */
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		    "Converted OOB (`%s') NS record for `%s'\n",
		    rec->data.hostname,
		    rec->name);
	add_record (req,
		    GNUNET_GNSRECORD_TYPE_GNS2DNS,
		    rec->expiration_time,
		    dst,
		    off);
      }
      else
      {
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		    "Converted NS record for `%s' using glue\n",
		    rec->name);
      }
      break;
    }
  case GNUNET_DNSPARSER_TYPE_CNAME:
    if (GNUNET_OK ==
	GNUNET_DNSPARSER_builder_add_name (dst,
					   dst_len,
					   &off,
					   rec->data.hostname))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Converting CNAME (`%s') record for `%s'\n",
		  rec->data.hostname,
		  rec->name);
      add_record (req,
		  rec->type,
		  rec->expiration_time,
		  dst,
		  off);
    }
    break;
  case GNUNET_DNSPARSER_TYPE_DNAME:
    /* No support for DNAME in GNS yet! FIXME: support later! */
    fprintf (stdout,
             "FIXME: not supported: %s DNAME %s\n",
             rec->name,
             rec->data.hostname);
    break;
  case GNUNET_DNSPARSER_TYPE_MX:
    if (GNUNET_OK ==
	GNUNET_DNSPARSER_builder_add_mx (dst,
					 dst_len,
					 &off,
					 rec->data.mx))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Converting MX (`%s') record for `%s'\n",
		  rec->data.mx->mxhost,
		  rec->name);
      add_record (req,
		  rec->type,
		  rec->expiration_time,
		  dst,
		  off);
    }
    break;
  case GNUNET_DNSPARSER_TYPE_SOA:
    if (GNUNET_OK ==
	GNUNET_DNSPARSER_builder_add_soa (dst,
					  dst_len,
					  &off,
					  rec->data.soa))
    {
      /* NOTE: GNS does not really use SOAs */
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Converting SOA record for `%s'\n",
		  rec->name);
      add_record (req,
		  rec->type,
		  rec->expiration_time,
		  dst,
		  off);
    }
    break;
  case GNUNET_DNSPARSER_TYPE_SRV:
    if (GNUNET_OK ==
	GNUNET_DNSPARSER_builder_add_srv (dst,
					  dst_len,
					  &off,
					  rec->data.srv))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Converting SRV record for `%s'\n",
		  rec->name);
      add_record (req,
		  rec->type,
		  rec->expiration_time,
		  dst,
		  off);
    }
    break;
  case GNUNET_DNSPARSER_TYPE_PTR:
    if (GNUNET_OK ==
	GNUNET_DNSPARSER_builder_add_name (dst,
					   dst_len,
					   &off,
					   rec->data.hostname))
    {
      /* !?: what does a PTR record do in a regular TLD??? */
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Converting PTR record for `%s' (weird)\n",
		  rec->name);
      add_record (req,
		  rec->type,
		  rec->expiration_time,
		  dst,
		  off);
    }
    break;
  case GNUNET_DNSPARSER_TYPE_CERT:
    if (GNUNET_OK ==
	GNUNET_DNSPARSER_builder_add_cert (dst,
					   dst_len,
					   &off,
					   rec->data.cert))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Converting CERT record for `%s'\n",
		  rec->name);
      add_record (req,
		  rec->type,
		  rec->expiration_time,
		  dst,
		  off);
    }
    break;
    /* Rest is 'raw' encoded and just needs to be copied IF
       the hostname matches the requested name; otherwise we
       simply cannot use it. */
  case GNUNET_DNSPARSER_TYPE_A:
  case GNUNET_DNSPARSER_TYPE_AAAA:
  case GNUNET_DNSPARSER_TYPE_TXT:
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Converting record of type %u for `%s'\n",
		(unsigned int) rec->type,
		rec->name);
    add_record (req,
		rec->type,
		rec->expiration_time,
		rec->data.raw.data,
		rec->data.raw.data_len);
    break;
  }
}


/**
 * Continuation called to notify client about result of the
 * operation.
 *
 * @param cls closure with our `struct Request`
 * @param success #GNUNET_SYSERR on failure (including timeout/queue drop/failure to validate)
 *                #GNUNET_NO if content was already there or not found
 *                #GNUNET_YES (or other positive value) on success
 * @param emsg NULL on success, otherwise an error message
 */
static void
store_completed_cb (void *cls,
		    int32_t success,
		    const char *emsg)
{
  static unsigned int pdot;
  struct Request *req = cls;
  struct Record *rec;

  req->qe = NULL;
  pending--;
  if (GNUNET_SYSERR == success)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Failed to store zone data for `%s': %s\n",
		req->hostname,
		emsg);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		"Stored records under `%s'\n",
		req->label);
    pdot++;
    if (0 == pdot % 1000)
      fprintf (stderr, ".");
  }
  /* Free records */
  while (NULL != (rec = req->rec_head))
  {
    GNUNET_CONTAINER_DLL_remove (req->rec_head,
				 req->rec_tail,
				 rec);
    GNUNET_free (rec);
  }
}


/**
 * Function called with the result of a DNS resolution.
 *
 * @param cls closure with the `struct Request`
 * @param dns dns response, never NULL
 * @param dns_len number of bytes in @a dns
 */
static void
process_result (void *cls,
                const struct GNUNET_TUN_DnsHeader *dns,
                size_t dns_len)
{
  struct Request *req = cls;
  struct Record *rec;
  struct GNUNET_DNSPARSER_Packet *p;
  unsigned int rd_count;

  GNUNET_assert (NULL == req->hn);
  if (NULL == dns)
  {
    /* stub gave up */
    GNUNET_CONTAINER_DLL_remove (req_head,
				 req_tail,
				 req);
    pending--;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Stub gave up on DNS reply for `%s'\n",
                req->hostname);
    if (req->issue_num > MAX_RETRIES)
    {
      failures++;
      free_request (req);
      return;
    }
    req->rs = NULL;
    insert_sorted (req);
    return;
  }
  if (req->id != dns->id)
    return;
  GNUNET_CONTAINER_DLL_remove (req_head,
			       req_tail,
			       req);
  GNUNET_DNSSTUB_resolve_cancel (req->rs);
  req->rs = NULL;
  p = GNUNET_DNSPARSER_parse ((const char *) dns,
                              dns_len);
  if (NULL == p)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to parse DNS reply for `%s'\n",
                req->hostname);
    if (req->issue_num > MAX_RETRIES)
    {
      failures++;
      insert_sorted (req);
      pending--;
      return;
    }
    insert_sorted (req);
    pending--;
    return;
  }
  /* import new records */
  req->issue_num = 0; /* success, reset counter! */
  req->p = p;
  for_all_records (p,
		   &process_record,
		   req);
  req->p = NULL;
  GNUNET_DNSPARSER_free_packet (p);
  /* count records found, determine minimum expiration time */
  req->expires = GNUNET_TIME_UNIT_FOREVER_ABS;
  rd_count = 0;
  for (rec = req->rec_head; NULL != rec; rec = rec->next)
  {
    struct GNUNET_TIME_Absolute at;

    at.abs_value_us = rec->grd.expiration_time;
    req->expires = GNUNET_TIME_absolute_min (req->expires,
					     at);
    rd_count++;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      "Obtained %u records for `%s'\n",
	      rd_count,
	      req->hostname);
  /* Instead of going for SOA, simplified for now to look each
     day in case we got an empty response */
  if (0 == rd_count)
    req->expires
      = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_DAYS);
  /* convert records to namestore import format */
  {
    struct GNUNET_GNSRECORD_Data rd[GNUNET_NZL(rd_count)];
    unsigned int off = 0;

    /* convert linked list into array */
    for (rec = req->rec_head; NULL != rec; rec =rec->next)
      rd[off++] = rec->grd;
    req->qe = GNUNET_NAMESTORE_records_store (ns,
					      &req->zone->key,
					      req->label,
					      rd_count,
					      rd,
					      &store_completed_cb,
					      req);
  }
  insert_sorted (req);
}


/**
 * Submit a request to DNS unless we need to slow down because
 * we are at the rate limit.
 *
 * @param req request to submit
 * @return #GNUNET_OK if request was submitted
 *         #GNUNET_NO if request was already submitted
 *         #GNUNET_SYSERR if we are at the rate limit
 */
static int
submit_req (struct Request *req)
{
  static struct GNUNET_TIME_Absolute last_request;
  struct GNUNET_TIME_Absolute now;

  if (NULL != req->qe)
    return GNUNET_NO; /* namestore op still pending */
  if (NULL != req->rs)
  {
    GNUNET_break (0);
    return GNUNET_NO; /* already submitted */
  }
  now = GNUNET_TIME_absolute_get ();
  if ( (now.abs_value_us - last_request.abs_value_us < TIME_THRESH) ||
       (pending >= THRESH) )
    return GNUNET_SYSERR;
  GNUNET_CONTAINER_DLL_insert (req_head,
			       req_tail,
			       req);
  GNUNET_assert (NULL == req->rs);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      "Requesting resolution for `%s'\n",
	      req->hostname);
  req->rs = GNUNET_DNSSTUB_resolve (ctx,
                                    req->raw,
                                    req->raw_len,
                                    &process_result,
                                    req);
  GNUNET_assert (NULL != req->rs);
  req->issue_num++;
  last_request = now;
  lookups++;
  pending++;
  req->time = time (NULL);
  return GNUNET_OK;
}


/**
 * Process as many requests as possible from the queue.
 *
 * @param cls NULL
 */
static void
process_queue (void *cls)
{
  struct Request *req;

  (void) cls;
  t = NULL;
  while (1)
  {
    req = GNUNET_CONTAINER_heap_peek (req_heap);
    if (NULL == req)
      break;
    if (GNUNET_TIME_absolute_get_remaining (req->expires).rel_value_us > 0)
      break;
    if (GNUNET_OK != submit_req (req))
      break;
    GNUNET_assert (req ==
		   GNUNET_CONTAINER_heap_remove_root (req_heap));
    req->hn = NULL;
  }

  req = GNUNET_CONTAINER_heap_peek (req_heap);
  if (NULL == req)
    return;
  if (GNUNET_TIME_absolute_get_remaining (req->expires).rel_value_us > 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		"Waiting until %s for next record (`%s') to expire\n",
		GNUNET_STRINGS_absolute_time_to_string (req->expires),
		req->hostname);
    if (NULL != t)
      GNUNET_SCHEDULER_cancel (t);
    t = GNUNET_SCHEDULER_add_at (req->expires,
				 &process_queue,
				 NULL);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Throttling for 1ms\n");
    if (NULL != t)
      GNUNET_SCHEDULER_cancel (t);
    t = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MILLISECONDS,
				      &process_queue,
				      NULL);
  }
}


/**
 * Clean up and terminate the process.
 *
 * @param cls NULL
 */
static void
do_shutdown (void *cls)
{
  struct Request *req;
  struct Zone *zone;

  (void) cls;
  if (NULL != id)
  {
    GNUNET_IDENTITY_disconnect (id);
    id = NULL;
  }
  if (NULL != t)
  {
    GNUNET_SCHEDULER_cancel (t);
    t = NULL;
  }
  while (NULL != (req = req_head))
  {
    GNUNET_CONTAINER_DLL_remove (req_head,
				 req_tail,
				 req);
    if (NULL != req->qe)
      GNUNET_NAMESTORE_cancel (req->qe);
    free_request (req);
  }
  while (NULL != (req = GNUNET_CONTAINER_heap_remove_root (req_heap)))
  {
    req->hn = NULL;
    if (NULL != req->qe)
      GNUNET_NAMESTORE_cancel (req->qe);
    free_request (req);
  }
  if (NULL != ns)
  {
    GNUNET_NAMESTORE_disconnect (ns);
    ns = NULL;
  }
  if (NULL != ctx)
  {
    GNUNET_DNSSTUB_stop (ctx);
    ctx = NULL;
  }
  if (NULL != req_heap)
  {
    GNUNET_CONTAINER_heap_destroy (req_heap);
    req_heap = NULL;
  }
  while (NULL != (zone = zone_head))
  {
    GNUNET_CONTAINER_DLL_remove (zone_head,
                                 zone_tail,
                                 zone);
    GNUNET_free (zone->domain);
    GNUNET_free (zone);
  }
}


/**
 * Begin processing hostnames from stdin.
 *
 * @param cls NULL
 */
static void
process_stdin (void *cls);


/**
 * If applicable, continue processing from stdin.
 */
static void
continue_stdin ()
{
  if ( (pending < THRESH) &&
       (stdin_waiting) )
  {
    if (NULL != t)
      GNUNET_SCHEDULER_cancel (t);
    t = GNUNET_SCHEDULER_add_now (&process_stdin,
				  NULL);
  }
}


/**
 * Function called if #GNUNET_NAMESTORE_records_lookup() failed.
 * Continues resolution based on assumption namestore has no data.
 *
 * @param cls a `struct Request`
 */
static void
ns_lookup_error_cb (void *cls)
{
  struct Request *req = cls;

  req->qe = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      "Failed to load data from namestore for `%s'\n",
	      req->label);
  insert_sorted (req);
  pending--;
  continue_stdin ();
}


/**
 * Process a record that was stored in the namestore.
 *
 * @param cls a `struct Request *`
 * @param zone private key of the zone
 * @param label label of the records
 * @param rd_count number of entries in @a rd array, 0 if label was deleted
 * @param rd array of records with data to store
 */
static void
ns_lookup_result_cb (void *cls,
		     const struct GNUNET_CRYPTO_EcdsaPrivateKey *zone,
		     const char *label,
		     unsigned int rd_count,
		     const struct GNUNET_GNSRECORD_Data *rd)
{
  struct Request *req = cls;

  req->qe = NULL;
  pending--;
  GNUNET_break (0 == memcmp (zone,
			     &req->zone->key,
			     sizeof (*zone)));
  GNUNET_break (0 == strcasecmp (label,
				 req->label));
  for (unsigned int i=0;i<rd_count;i++)
  {
    struct GNUNET_TIME_Absolute at;

    at.abs_value_us = rd->expiration_time;
    add_record (req,
		rd->record_type,
		at,
		rd->data,
		rd->data_size);
  }
  if (0 == rd_count)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		"Empty record set in namestore for `%s'\n",
		req->label);
  }
  else
  {
    unsigned int pos = 0;

    req->expires = GNUNET_TIME_UNIT_FOREVER_ABS;
    for (struct Record *rec = req->rec_head;
	 NULL != rec;
	 rec = rec->next)
    {
      struct GNUNET_TIME_Absolute at;

      at.abs_value_us = rec->grd.expiration_time;
      req->expires = GNUNET_TIME_absolute_min (req->expires,
					       at);
      pos++;
    }
    if (0 == pos)
      req->expires = GNUNET_TIME_UNIT_ZERO_ABS;
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Hot-start with %u existing records for `%s'\n",
		pos,
                req->label);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Adding `%s' to worklist to start at %s\n",
	      req->hostname,
	      GNUNET_STRINGS_absolute_time_to_string (req->expires));
  insert_sorted (req);
  continue_stdin ();
}


/**
 * Add @a hostname to the list of requests to be made.
 *
 * @param hostname name to resolve
 */
static void
queue (const char *hostname)
{
  struct GNUNET_DNSPARSER_Packet p;
  struct GNUNET_DNSPARSER_Query q;
  struct Request *req;
  char *raw;
  size_t raw_size;
  const char *dot;
  struct Zone *zone;

  if (GNUNET_OK !=
      GNUNET_DNSPARSER_check_name (hostname))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Refusing invalid hostname `%s'\n",
                hostname);
    rejects++;
    continue_stdin ();
    return;
  }
  dot = strchr (hostname,
                (unsigned char) '.');
  if (NULL == dot)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Refusing invalid hostname `%s' (lacks '.')\n",
                hostname);
    rejects++;
    continue_stdin ();
    return;
  }
  for (zone = zone_head; NULL != zone; zone = zone->next)
    if (0 == strcmp (zone->domain,
                     dot + 1))
      break;
  if (NULL == zone)
  {
    rejects++;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Domain name `%s' not in ego list!\n",
                dot + 1);
    continue_stdin ();
    return;
  }
  q.name = (char *) hostname;
  q.type = GNUNET_DNSPARSER_TYPE_NS;
  q.dns_traffic_class = GNUNET_TUN_DNS_CLASS_INTERNET;

  memset (&p,
          0,
          sizeof (p));
  p.num_queries = 1;
  p.queries = &q;
  p.id = (uint16_t) GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
                                              UINT16_MAX);

  if (GNUNET_OK !=
      GNUNET_DNSPARSER_pack (&p,
                             UINT16_MAX,
                             &raw,
                             &raw_size))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to pack query for hostname `%s'\n",
                hostname);
    rejects++;
    continue_stdin ();
    return;
  }

  pending++;
  req = GNUNET_new (struct Request);
  req->zone = zone;
  req->hostname = GNUNET_strdup (hostname);
  req->raw = raw;
  req->raw_len = raw_size;
  req->id = p.id;
  req->label = GNUNET_strndup (hostname,
			       dot - hostname);
  req->qe = GNUNET_NAMESTORE_records_lookup (ns,
					     &req->zone->key,
					     req->label,
					     &ns_lookup_error_cb,
					     req,
					     &ns_lookup_result_cb,
					     req);
}


/**
 * Begin processing hostnames from stdin.
 *
 * @param cls NULL
 */
static void
process_stdin (void *cls)
{
  static unsigned int pdot;
  char hn[256];

  (void) cls;
  t = NULL;
  if (NULL != id)
  {
    GNUNET_IDENTITY_disconnect (id);
    id = NULL;
  }
  if (NULL !=
      fgets (hn,
	     sizeof (hn),
	     stdin))
  {
    if (strlen(hn) > 0)
      hn[strlen(hn)-1] = '\0'; /* eat newline */
    pdot++;
    if (0 == pdot % 1000)
      fprintf (stderr, ".");
    queue (hn);
    return;
  }
  stdin_waiting = GNUNET_NO;
  fprintf (stderr, "\n");
  t = GNUNET_SCHEDULER_add_now (&process_queue,
				NULL);
}


/**
 * Method called to inform about the egos of this peer.
 *
 * When used with #GNUNET_IDENTITY_connect, this function is
 * initially called for all egos and then again whenever a
 * ego's name changes or if it is deleted.  At the end of
 * the initial pass over all egos, the function is once called
 * with 'NULL' for @a ego. That does NOT mean that the callback won't
 * be invoked in the future or that there was an error.
 *
 * When used with #GNUNET_IDENTITY_create or #GNUNET_IDENTITY_get,
 * this function is only called ONCE, and 'NULL' being passed in
 * @a ego does indicate an error (i.e. name is taken or no default
 * value is known).  If @a ego is non-NULL and if '*ctx'
 * is set in those callbacks, the value WILL be passed to a subsequent
 * call to the identity callback of #GNUNET_IDENTITY_connect (if
 * that one was not NULL).
 *
 * When an identity is renamed, this function is called with the
 * (known) @a ego but the NEW @a name.
 *
 * When an identity is deleted, this function is called with the
 * (known) ego and "NULL" for the @a name.  In this case,
 * the @a ego is henceforth invalid (and the @a ctx should also be
 * cleaned up).
 *
 * @param cls closure
 * @param ego ego handle
 * @param ctx context for application to store data for this ego
 *                 (during the lifetime of this process, initially NULL)
 * @param name name assigned by the user for this ego,
 *                   NULL if the user just deleted the ego and it
 *                   must thus no longer be used
 */
static void
identity_cb (void *cls,
	     struct GNUNET_IDENTITY_Ego *ego,
	     void **ctx,
	     const char *name)
{
  (void) cls;
  (void) ctx;
  if (NULL == ego)
  {
    if (NULL != zone_head)
    {
      stdin_waiting = GNUNET_YES;
      t = GNUNET_SCHEDULER_add_now (&process_stdin,
				    NULL);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  "Specified zone not found\n");
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
  }
  if (NULL != name)
  {
    struct Zone *zone;

    zone = GNUNET_new (struct Zone);
    zone->key = *GNUNET_IDENTITY_ego_get_private_key (ego);
    zone->domain = GNUNET_strdup (name);
    GNUNET_CONTAINER_DLL_insert (zone_head,
                                 zone_tail,
                                 zone);
  }
}


/**
 * Process requests from the queue, then if the queue is
 * not empty, try again.
 *
 * @param cls NULL
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  (void) cls;
  (void) args;
  (void) cfgfile;
  req_heap = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  ctx = GNUNET_DNSSTUB_start (256);
  if (NULL == ctx)
  {
    fprintf (stderr,
             "Failed to initialize GNUnet DNS STUB\n");
    return;
  }
  if (NULL == args[1])
  {
    fprintf (stderr,
             "You must provide a list of DNS resolvers on the command line\n");
    return;
  }
  for (unsigned int i=1;NULL != args[i];i++)
  {
    if (GNUNET_OK !=
        GNUNET_DNSSTUB_add_dns_ip (ctx,
                                   args[1]))
    {
      fprintf (stderr,
               "Failed to use `%s' for DNS resolver\n",
               args[i]);
      return;
    }
  }


  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
                                 NULL);
  ns = GNUNET_NAMESTORE_connect (cfg);
  if (NULL == ns)
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  id = GNUNET_IDENTITY_connect (cfg,
				&identity_cb,
				NULL);
}


/**
 * Call with IP address of resolver to query.
 *
 * @param argc should be 2
 * @param argv[1] should contain IP address
 * @return 0 on success
 */
int
main (int argc,
      char *const*argv)
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_mandatory
    (GNUNET_GETOPT_option_string ('s',
				  "server",
				  "IP",
				  "which DNS server should be used",
				  &dns_server)),
    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK !=
      GNUNET_STRINGS_get_utf8_args (argc, argv,
				    &argc, &argv))
    return 2;
  GNUNET_PROGRAM_run (argc,
		      argv,
		      "gnunet-zoneimport",
		      "import DNS zone into namestore",
		      options,
		      &run,
		      NULL);
  GNUNET_free ((void*) argv);
  fprintf (stderr,
           "Rejected %u names, did %u lookups, found %u records, %u lookups failed, %u pending on shutdown\n",
	   rejects,
           lookups,
           records,
           failures,
           pending);
  return 0;
}

/* end of gnunet-zoneimport.c */
