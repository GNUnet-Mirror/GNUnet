/*
     This file is part of GNUnet
     Copyright (C) 2018 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
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
#include <gnunet_statistics_service.h>
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
 * How many DNS requests do we at most issue in rapid series?
 */
#define MAX_SERIES 10

/**
 * How long do we wait at least between series of requests?
 */
#define SERIES_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MICROSECONDS, 10)

/**
 * How long do DNS records have to last at least after being imported?
 */
static struct GNUNET_TIME_Relative minimum_expiration_time;

/**
 * How many requests do we request from NAMESTORE in one batch
 * during our initial iteration?
 */
#define NS_BATCH_SIZE 1024

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
 * Request we should make.  We keep this struct in memory per request,
 * thus optimizing it is crucial for the overall memory consumption of
 * the zone importer.
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
   * Hostname we are resolving, allocated at the end of
   * this struct (optimizing memory consumption by reducing
   * total number of allocations).
   */
  char *hostname;

  /**
   * Namestore operation pending for this record.
   */
  struct GNUNET_NAMESTORE_QueueEntry *qe;

  /**
   * Zone responsible for this request.
   */
  const struct Zone *zone;

  /**
   * At what time does the (earliest) of the returned records
   * for this name expire? At this point, we need to re-fetch
   * the record.
   */
  struct GNUNET_TIME_Absolute expires;

  /**
   * While we are fetching the record, the value is set to the
   * starting time of the DNS operation.  While doing a
   * NAMESTORE store, again set to the start time of the
   * NAMESTORE operation.
   */
  struct GNUNET_TIME_Absolute op_start_time;

  /**
   * How often did we issue this query? (And failed, reset
   * to zero once we were successful.)
   */
  unsigned int issue_num;

  /**
   * random 16-bit DNS query identifier.
   */
  uint16_t id;
};


/**
 * Command-line argument specifying desired size of the hash map with
 * all of our pending names.  Usually, we use an automatically growing
 * map, but this is only OK up to about a million entries.  Above that
 * number, the user must explicitly specify the size at startup.
 */
static unsigned int map_size = 1024;

/**
 * Handle to the identity service.
 */
static struct GNUNET_IDENTITY_Handle *id;

/**
 * Namestore handle.
 */
static struct GNUNET_NAMESTORE_Handle *ns;

/**
 * Handle to the statistics service.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Context for DNS resolution.
 */
static struct GNUNET_DNSSTUB_Context *ctx;

/**
 * The number of DNS queries that are outstanding
 */
static unsigned int pending;

/**
 * The number of NAMESTORE record store operations that are outstanding
 */
static unsigned int pending_rs;

/**
 * Number of lookups we performed overall.
 */
static unsigned int lookups;

/**
 * Number of records we had cached.
 */
static unsigned int cached;

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
 * Number of record sets given to namestore.
 */
static unsigned int record_sets;

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
 * Hash map of requests for which we may still get a response from
 * the namestore.  Set to NULL once the initial namestore iteration
 * is done.
 */
static struct GNUNET_CONTAINER_MultiHashMap *ns_pending;

/**
 * Current zone iteration handle.
 */
static struct GNUNET_NAMESTORE_ZoneIterator *zone_it;

/**
 * Head of list of zones we are managing.
 */
static struct Zone *zone_head;

/**
 * Tail of list of zones we are managing.
 */
static struct Zone *zone_tail;

/**
 * After how many more results must #ns_lookup_result_cb() ask
 * the namestore for more?
 */
static uint64_t ns_iterator_trigger_next;

/**
 * Number of DNS requests counted in latency total.
 */
static uint64_t total_dns_latency_cnt;

/**
 * Sum of DNS latencies observed.
 */
static struct GNUNET_TIME_Relative total_dns_latency;

/**
 * Number of records processed (DNS lookup, no NAMESTORE) in total.
 */
static uint64_t total_reg_proc_dns;

/**
 * Number of records processed (DNS lookup, with NAMESTORE) in total.
 */
static uint64_t total_reg_proc_dns_ns;

/**
 * Start time of the regular processing.
 */
static struct GNUNET_TIME_Absolute start_time_reg_proc;

/**
 * Last time we worked before going idle.
 */
static struct GNUNET_TIME_Absolute sleep_time_reg_proc;

/**
 * Time we slept just waiting for work.
 */
static struct GNUNET_TIME_Relative idle_time;


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
 * Return just the label of the hostname in @a req.
 *
 * @param req request to process hostname of
 * @return statically allocated pointer to the label,
 *         overwritten upon the next request!
 */
static const char *
get_label (struct Request *req)
{
  static char label[64];
  const char *dot;

  dot = strchr (req->hostname,
                (unsigned char) '.');
  if (NULL == dot)
  {
    GNUNET_break (0);
    return NULL;
  }
  if (((size_t) (dot - req->hostname)) >= sizeof (label))
  {
    GNUNET_break (0);
    return NULL;
  }
  GNUNET_memcpy (label,
                 req->hostname,
                 dot - req->hostname);
  label[dot - req->hostname] = '\0';
  return label;
}


/**
 * Build DNS query for @a hostname.
 *
 * @param hostname host to build query for
 * @param raw_size[out] number of bytes in the query
 * @return NULL on error, otherwise pointer to statically (!)
 *         allocated query buffer
 */
static void *
build_dns_query (struct Request *req,
		 size_t *raw_size)
{
  static char raw[512];
  char *rawp;
  struct GNUNET_DNSPARSER_Packet p;
  struct GNUNET_DNSPARSER_Query q;
  int ret;

  q.name = (char *) req->hostname;
  q.type = GNUNET_DNSPARSER_TYPE_NS;
  q.dns_traffic_class = GNUNET_TUN_DNS_CLASS_INTERNET;

  memset (&p,
          0,
          sizeof (p));
  p.num_queries = 1;
  p.queries = &q;
  p.id = req->id;
  ret = GNUNET_DNSPARSER_pack (&p,
                               UINT16_MAX,
                               &rawp,
                               raw_size);
  if (GNUNET_OK != ret)
  {
    if (GNUNET_NO == ret)
      GNUNET_free (rawp);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to pack query for hostname `%s'\n",
                req->hostname);
    rejects++;
    return NULL;
  }
  if (*raw_size > sizeof (raw))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to pack query for hostname `%s'\n",
                req->hostname);
    rejects++;
    GNUNET_break (0);
    GNUNET_free (rawp);
    return NULL;
  }
  GNUNET_memcpy (raw,
                 rawp,
                 *raw_size);
  GNUNET_free (rawp);
  return raw;
}



/**
 * Free records associated with @a req.
 *
 * @param req request to free records of
 */
static void
free_records (struct Request *req)
{
  struct Record *rec;

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
 * Free @a req and data structures reachable from it.
 *
 * @param req request to free
 */
static void
free_request (struct Request *req)
{
  free_records (req);
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
    sleep_time_reg_proc = GNUNET_TIME_absolute_get ();
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
  struct GNUNET_TIME_Absolute expiration_time;
  struct GNUNET_TIME_Relative left;

  if (0 != strcasecmp (rec->name,
		       gc->ns))
    return;
  expiration_time = rec->expiration_time;
  left = GNUNET_TIME_absolute_get_remaining (expiration_time);
  if (0 == left.rel_value_us)
    return; /* ignore expired glue records */
  /* if expiration window is too short, bump it to configured minimum */
  if (left.rel_value_us < minimum_expiration_time.rel_value_us)
    expiration_time = GNUNET_TIME_relative_to_absolute (minimum_expiration_time);
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
		  expiration_time,
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
		  expiration_time,
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
		  expiration_time,
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
 * Closure for #process_record().
 */
struct ProcessRecordContext
{
  /**
   * Answer we got back and are currently parsing, or NULL
   * if not active.
   */
  struct GNUNET_DNSPARSER_Packet *p;

  /**
   * Request we are processing.
   */
  struct Request *req;
};


/**
 * We received @a rec for @a req. Remember the answer.
 *
 * @param cls a `struct ProcessRecordContext`
 * @param rec response
 */
static void
process_record (void *cls,
                const struct GNUNET_DNSPARSER_Record *rec)
{
  struct ProcessRecordContext *prc = cls;
  struct Request *req = prc->req;
  char dst[65536];
  size_t dst_len;
  size_t off;
  struct GNUNET_TIME_Absolute expiration_time;
  struct GNUNET_TIME_Relative left;

  dst_len = sizeof (dst);
  off = 0;
  records++;
  if (0 != strcasecmp (rec->name,
		       req->hostname))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"DNS returned record from zone `%s' of type %u while resolving `%s'\n",
		rec->name,
		(unsigned int) rec->type,
		req->hostname);
    return; /* does not match hostname, might be glue, but
	       not useful for this pass! */
  }
  expiration_time = rec->expiration_time;
  left = GNUNET_TIME_absolute_get_remaining (expiration_time);
  if (0 == left.rel_value_us)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"DNS returned expired record for `%s'\n",
		req->hostname);
    GNUNET_STATISTICS_update (stats,
                              "# expired records obtained from DNS",
                              1,
                              GNUNET_NO);
    return; /* record expired */
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "DNS returned record that expires at %s for `%s'\n",
              GNUNET_STRINGS_absolute_time_to_string (expiration_time),
              req->hostname);
  /* if expiration window is too short, bump it to configured minimum */
  if (left.rel_value_us < minimum_expiration_time.rel_value_us)
    expiration_time = GNUNET_TIME_relative_to_absolute (minimum_expiration_time);
  switch (rec->type)
  {
  case GNUNET_DNSPARSER_TYPE_NS:
    {
      struct GlueClosure gc;

      /* check for glue */
      gc.req = req;
      gc.ns = rec->data.hostname;
      gc.found = GNUNET_NO;
      for_all_records (prc->p,
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
		    expiration_time,
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
		  expiration_time,
		  dst,
		  off);
    }
    break;
  case GNUNET_DNSPARSER_TYPE_DNAME:
    /* No support for DNAME in GNS yet! FIXME: support later! */
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
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
		  expiration_time,
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
		  expiration_time,
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
		  expiration_time,
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
		  expiration_time,
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
		  expiration_time,
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
		expiration_time,
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
  static struct GNUNET_TIME_Absolute last;
  struct Request *req = cls;

  req->qe = NULL;
  if (GNUNET_SYSERR == success)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Failed to store zone data for `%s': %s\n",
		req->hostname,
		emsg);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Stored records under `%s' (%d)\n",
		req->hostname,
                success);
  }
  total_reg_proc_dns_ns++; /* finished regular processing */
  pending_rs--;
  free_records (req);
  /* compute NAMESTORE statistics */
  {
    static uint64_t total_ns_latency_cnt;
    static struct GNUNET_TIME_Relative total_ns_latency;
    struct GNUNET_TIME_Relative ns_latency;

    ns_latency = GNUNET_TIME_absolute_get_duration (req->op_start_time);
    total_ns_latency = GNUNET_TIME_relative_add (total_ns_latency,
                                                 ns_latency);
    if (0 == total_ns_latency_cnt)
      last = GNUNET_TIME_absolute_get ();
    total_ns_latency_cnt++;
    if (0 == (total_ns_latency_cnt % 1000))
    {
      struct GNUNET_TIME_Relative delta;

      delta = GNUNET_TIME_absolute_get_duration (last);
      last = GNUNET_TIME_absolute_get ();
      fprintf (stderr,
	       "Processed 1000 records in %s\n",
	       GNUNET_STRINGS_relative_time_to_string (delta,
						       GNUNET_YES));
      GNUNET_STATISTICS_set (stats,
                             "# average NAMESTORE PUT latency (μs)",
                             total_ns_latency.rel_value_us / total_ns_latency_cnt,
                             GNUNET_NO);
    }
  }
  /* compute and publish overall velocity */
  if (0 == (total_reg_proc_dns_ns % 100) )
  {
    struct GNUNET_TIME_Relative runtime;

    runtime = GNUNET_TIME_absolute_get_duration (start_time_reg_proc);
    runtime = GNUNET_TIME_relative_subtract (runtime,
                                             idle_time);
    runtime = GNUNET_TIME_relative_divide (runtime,
                                           total_reg_proc_dns + total_reg_proc_dns_ns);
    GNUNET_STATISTICS_set (stats,
                           "# Regular processing completed without NAMESTORE",
                           total_reg_proc_dns,
                           GNUNET_NO);
    GNUNET_STATISTICS_set (stats,
                           "# Regular processing completed with NAMESTORE PUT",
                           total_reg_proc_dns_ns,
                           GNUNET_NO);
    GNUNET_STATISTICS_set (stats,
                           "# average request processing latency (μs)",
                           runtime.rel_value_us,
                           GNUNET_NO);
    GNUNET_STATISTICS_set (stats,
                           "# total time spent idle (μs)",
                           idle_time.rel_value_us,
                           GNUNET_NO);
  }

  if (NULL == t)
  {
    sleep_time_reg_proc = GNUNET_TIME_absolute_get ();
    t = GNUNET_SCHEDULER_add_now (&process_queue,
				  NULL);
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
    if (NULL == t)
    {
      sleep_time_reg_proc = GNUNET_TIME_absolute_get ();
      t = GNUNET_SCHEDULER_add_now (&process_queue,
				    NULL);
    }
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Stub gave up on DNS reply for `%s'\n",
                req->hostname);
    GNUNET_STATISTICS_update (stats,
			      "# DNS lookups timed out",
			      1,
			      GNUNET_NO);
    if (req->issue_num > MAX_RETRIES)
    {
      failures++;
      free_request (req);
      GNUNET_STATISTICS_update (stats,
				"# requests given up on",
				1,
				GNUNET_NO);
      return;
    }
    total_reg_proc_dns++;
    req->rs = NULL;
    insert_sorted (req);
    return;
  }
  if (req->id != dns->id)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "DNS ID did not match request, ignoring reply\n");
    GNUNET_STATISTICS_update (stats,
			      "# DNS ID mismatches",
			      1,
			      GNUNET_NO);
    return;
  }
  GNUNET_CONTAINER_DLL_remove (req_head,
			       req_tail,
			       req);
  GNUNET_DNSSTUB_resolve_cancel (req->rs);
  req->rs = NULL;
  pending--;
  p = GNUNET_DNSPARSER_parse ((const char *) dns,
                              dns_len);
  if (NULL == p)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to parse DNS reply for `%s'\n",
                req->hostname);
    GNUNET_STATISTICS_update (stats,
			      "# DNS parser errors",
			      1,
			      GNUNET_NO);
    if (NULL == t)
    {
      sleep_time_reg_proc = GNUNET_TIME_absolute_get ();
      t = GNUNET_SCHEDULER_add_now (&process_queue,
				    NULL);
    }
    if (req->issue_num > MAX_RETRIES)
    {
      failures++;
      free_request (req);
      GNUNET_STATISTICS_update (stats,
				"# requests given up on",
				1,
				GNUNET_NO);
      return;
    }
    insert_sorted (req);
    return;
  }
  /* import new records */
  req->issue_num = 0; /* success, reset counter! */
  {
    struct ProcessRecordContext prc = {
      .req = req,
      .p = p
    };

    for_all_records (p,
		     &process_record,
		     &prc);
  }
  GNUNET_DNSPARSER_free_packet (p);
  /* count records found, determine minimum expiration time */
  req->expires = GNUNET_TIME_UNIT_FOREVER_ABS;
  {
    struct GNUNET_TIME_Relative dns_latency;

    dns_latency = GNUNET_TIME_absolute_get_duration (req->op_start_time);
    total_dns_latency = GNUNET_TIME_relative_add (total_dns_latency,
						  dns_latency);
    total_dns_latency_cnt++;
    if (0 == (total_dns_latency_cnt % 1000))
    {
      GNUNET_STATISTICS_set (stats,
                             "# average DNS lookup latency (μs)",
                             total_dns_latency.rel_value_us / total_dns_latency_cnt,
                             GNUNET_NO);
    }
  }
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
  {
    req->expires
      = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_DAYS);
    GNUNET_STATISTICS_update (stats,
                              "# empty DNS replies (usually NXDOMAIN)",
                              1,
                              GNUNET_NO);
  }
  else
  {
    record_sets++;
  }
  /* convert records to namestore import format */
  {
    struct GNUNET_GNSRECORD_Data rd[GNUNET_NZL(rd_count)];
    unsigned int off = 0;

    /* convert linked list into array */
    for (rec = req->rec_head; NULL != rec; rec =rec->next)
      rd[off++] = rec->grd;
    pending_rs++;
    req->op_start_time = GNUNET_TIME_absolute_get ();
    req->qe = GNUNET_NAMESTORE_records_store (ns,
					      &req->zone->key,
					      get_label (req),
					      rd_count,
					      rd,
					      &store_completed_cb,
					      req);
    GNUNET_assert (NULL != req->qe);
  }
  insert_sorted (req);
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
  unsigned int series;
  void *raw;
  size_t raw_size;
  struct GNUNET_TIME_Relative delay;

  (void) cls;
  delay = GNUNET_TIME_absolute_get_duration (sleep_time_reg_proc);
  idle_time = GNUNET_TIME_relative_add (idle_time,
                                        delay);
  series = 0;
  t = NULL;
  while (pending + pending_rs < THRESH)
  {
    req = GNUNET_CONTAINER_heap_peek (req_heap);
    if (NULL == req)
      break;
    if (NULL != req->qe)
      return; /* namestore op still pending */
    if (NULL != req->rs)
    {
      GNUNET_break (0);
      return; /* already submitted */
    }
    if (GNUNET_TIME_absolute_get_remaining (req->expires).rel_value_us > 0)
      break;
    GNUNET_assert (req ==
		   GNUNET_CONTAINER_heap_remove_root (req_heap));
    req->hn = NULL;
    GNUNET_CONTAINER_DLL_insert (req_head,
                                 req_tail,
                                 req);
    GNUNET_assert (NULL == req->rs);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Requesting resolution for `%s'\n",
                req->hostname);
    raw = build_dns_query (req,
                           &raw_size);
    if (NULL == raw)
    {
      GNUNET_break (0);
      free_request (req);
      continue;
    }
    req->op_start_time = GNUNET_TIME_absolute_get ();
    req->rs = GNUNET_DNSSTUB_resolve (ctx,
                                      raw,
                                      raw_size,
                                      &process_result,
                                      req);
    GNUNET_assert (NULL != req->rs);
    req->issue_num++;
    lookups++;
    pending++;
    series++;
    if (series > MAX_SERIES)
      break;
  }
  if (pending + pending_rs >= THRESH)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Stopped processing queue (%u+%u/%u)]\n",
		pending,
		pending_rs,
		THRESH);
    return; /* wait for replies */
  }
  req = GNUNET_CONTAINER_heap_peek (req_heap);
  if (NULL == req)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Stopped processing queue: empty queue\n");
    return;
  }
  if (GNUNET_TIME_absolute_get_remaining (req->expires).rel_value_us > 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		"Waiting until %s for next record (`%s') to expire\n",
		GNUNET_STRINGS_absolute_time_to_string (req->expires),
		req->hostname);
    if (NULL != t)
      GNUNET_SCHEDULER_cancel (t);
    sleep_time_reg_proc = GNUNET_TIME_absolute_get ();
    t = GNUNET_SCHEDULER_add_at (req->expires,
				 &process_queue,
				 NULL);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Throttling\n");
  if (NULL != t)
    GNUNET_SCHEDULER_cancel (t);
  sleep_time_reg_proc = GNUNET_TIME_absolute_get ();
  t = GNUNET_SCHEDULER_add_delayed (SERIES_DELAY,
                                    &process_queue,
                                    NULL);
}


/**
 * Iterator called during #do_shutdown() to free requests in
 * the #ns_pending map.
 *
 * @param cls NULL
 * @param key unused
 * @param value the `struct Request` to free
 * @return #GNUNET_OK
 */
static int
free_request_it (void *cls,
                 const struct GNUNET_HashCode *key,
                 void *value)
{
  struct Request *req = value;

  (void) cls;
  (void) key;
  free_request (req);
  return GNUNET_OK;
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
  if (NULL != zone_it)
  {
    GNUNET_NAMESTORE_zone_iteration_stop (zone_it);
    zone_it = NULL;
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
  if (NULL != ns_pending)
  {
    GNUNET_CONTAINER_multihashmap_iterate (ns_pending,
                                           &free_request_it,
                                           NULL);
    GNUNET_CONTAINER_multihashmap_destroy (ns_pending);
    ns_pending = NULL;
  }
  while (NULL != (zone = zone_head))
  {
    GNUNET_CONTAINER_DLL_remove (zone_head,
                                 zone_tail,
                                 zone);
    GNUNET_free (zone->domain);
    GNUNET_free (zone);
  }
  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
    stats = NULL;
  }
}


/**
 * Iterate over all of the zones we care about and see which records
 * we may need to re-fetch when.
 *
 * @param cls NULL
 */
static void
iterate_zones (void *cls);


/**
 * Function called if #GNUNET_NAMESTORE_records_lookup() failed.
 * Just logs an error.
 *
 * @param cls a `struct Zone`
 */
static void
ns_lookup_error_cb (void *cls)
{
  struct Zone *zone = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      "Failed to load data from namestore for zone `%s'\n",
	      zone->domain);
  zone_it = NULL;
  ns_iterator_trigger_next = 0;
  iterate_zones (NULL);
}


/**
 * Process a record that was stored in the namestore.
 *
 * @param cls a `struct Zone *`
 * @param key private key of the zone
 * @param label label of the records
 * @param rd_count number of entries in @a rd array, 0 if label was deleted
 * @param rd array of records with data to store
 */
static void
ns_lookup_result_cb (void *cls,
		     const struct GNUNET_CRYPTO_EcdsaPrivateKey *key,
		     const char *label,
		     unsigned int rd_count,
		     const struct GNUNET_GNSRECORD_Data *rd)
{
  struct Zone *zone = cls;
  struct Request *req;
  struct GNUNET_HashCode hc;
  char *fqdn;

  ns_iterator_trigger_next--;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Obtained NAMESTORE reply, %llu left in round\n",
	      (unsigned long long) ns_iterator_trigger_next);
  if (0 == ns_iterator_trigger_next)
  {
    ns_iterator_trigger_next = NS_BATCH_SIZE;
    GNUNET_STATISTICS_update (stats,
                              "# NAMESTORE records requested from cache",
                              ns_iterator_trigger_next,
                              GNUNET_NO);
    GNUNET_NAMESTORE_zone_iterator_next (zone_it,
                                         ns_iterator_trigger_next);
  }
  GNUNET_asprintf (&fqdn,
                   "%s.%s",
                   label,
                   zone->domain);
  GNUNET_CRYPTO_hash (fqdn,
                      strlen (fqdn) + 1,
                      &hc);
  GNUNET_free (fqdn);
  req = GNUNET_CONTAINER_multihashmap_get (ns_pending,
                                           &hc);
  if (NULL == req)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Ignoring record `%s' in zone `%s': not on my list!\n",
                label,
                zone->domain);
    return;
  }
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap_remove (ns_pending,
                                                       &hc,
                                                       req));
  GNUNET_break (0 == memcmp (key,
			     &req->zone->key,
			     sizeof (*key)));
  GNUNET_break (0 == strcasecmp (label,
				 get_label (req)));
  for (unsigned int i=0;i<rd_count;i++)
  {
    struct GNUNET_TIME_Absolute at;

    if (0 != (rd->flags & GNUNET_GNSRECORD_RF_RELATIVE_EXPIRATION))
    {
      struct GNUNET_TIME_Relative rel;

      rel.rel_value_us = rd->expiration_time;
      at = GNUNET_TIME_relative_to_absolute (rel);
    }
    else
    {
      at.abs_value_us = rd->expiration_time;
    }
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
		req->hostname);
  }
  else
  {
    unsigned int pos = 0;

    cached++;
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
                req->hostname);
  }
  free_records (req);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Adding `%s' to worklist to start at %s\n",
	      req->hostname,
	      GNUNET_STRINGS_absolute_time_to_string (req->expires));
  insert_sorted (req);
}


/**
 * Add @a hostname to the list of requests to be made.
 *
 * @param hostname name to resolve
 */
static void
queue (const char *hostname)
{
  struct Request *req;
  const char *dot;
  struct Zone *zone;
  size_t hlen;
  struct GNUNET_HashCode hc;

  if (GNUNET_OK !=
      GNUNET_DNSPARSER_check_name (hostname))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Refusing invalid hostname `%s'\n",
                hostname);
    rejects++;
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
    return;
  }

  hlen = strlen (hostname) + 1;
  req = GNUNET_malloc (sizeof (struct Request) + hlen);
  req->zone = zone;
  req->hostname = (char *) &req[1];
  GNUNET_memcpy (req->hostname,
                 hostname,
                 hlen);
  req->id = (uint16_t) GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
						 UINT16_MAX);
  GNUNET_CRYPTO_hash (req->hostname,
                      hlen,
                      &hc);
  if (GNUNET_OK !=
      GNUNET_CONTAINER_multihashmap_put (ns_pending,
                                         &hc,
                                         req,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Duplicate hostname `%s' ignored\n",
                hostname);
    GNUNET_free (req);
    return;
  }
}


/**
 * We have completed the initial iteration over the namestore's database.
 * This function is called on each of the remaining records in
 * #move_to_queue to #queue() them, as we will simply not find existing
 * records for them any longer.
 *
 * @param cls NULL
 * @param key unused
 * @param value a `struct Request`
 * @return #GNUNET_OK (continue to iterate)
 */
static int
move_to_queue (void *cls,
               const struct GNUNET_HashCode *key,
               void *value)
{
  struct Request *req = value;

  (void) cls;
  (void) key;
  insert_sorted (req);
  return GNUNET_OK;
}


/**
 * Iterate over all of the zones we care about and see which records
 * we may need to re-fetch when.
 *
 * @param cls NULL
 */
static void
iterate_zones (void *cls)
{
  static struct Zone *last;

  (void) cls;
  if (NULL != zone_it)
  {
    zone_it = NULL;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Finished iteration over zone `%s'!\n",
                last->domain);
    /* subtract left-overs from previous iteration */
    GNUNET_STATISTICS_update (stats,
			      "# NAMESTORE records requested from cache",
			      (long long) (- ns_iterator_trigger_next),
			      GNUNET_NO);
    ns_iterator_trigger_next = 0;
  }
  GNUNET_assert (NULL != zone_tail);
  if (zone_tail == last)
  {
    /* Done iterating over relevant zones in NAMESTORE, move
       rest of hash map to work queue as well. */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Finished all NAMESTORE iterations!\n");
    GNUNET_STATISTICS_set (stats,
			   "# Domain names without cached reply",
			   GNUNET_CONTAINER_multihashmap_size (ns_pending),
			   GNUNET_NO);
    GNUNET_CONTAINER_multihashmap_iterate (ns_pending,
                                           &move_to_queue,
                                           NULL);
    GNUNET_CONTAINER_multihashmap_destroy (ns_pending);
    ns_pending = NULL;
    start_time_reg_proc = GNUNET_TIME_absolute_get ();
    total_reg_proc_dns = 0;
    total_reg_proc_dns_ns = 0;
    return;
  }
  if (NULL == last)
    last = zone_head;
  else
    last = last->next;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting iteration over zone `%s'!\n",
              last->domain);
  /* subtract left-overs from previous iteration */
  GNUNET_STATISTICS_update (stats,
			    "# NAMESTORE records requested from cache",
			    1,
			    GNUNET_NO);
  ns_iterator_trigger_next = 1;
  GNUNET_STATISTICS_update (stats,
			    "# zones iterated",
			    1,
			    GNUNET_NO);
  zone_it = GNUNET_NAMESTORE_zone_iteration_start (ns,
                                                   &last->key,
                                                   &ns_lookup_error_cb,
                                                   NULL,
                                                   &ns_lookup_result_cb,
                                                   last,
                                                   &iterate_zones,
                                                   NULL);

}


/**
 * Begin processing hostnames from stdin.
 *
 * @param cls NULL
 */
static void
process_stdin (void *cls)
{
  static struct GNUNET_TIME_Absolute last;
  static uint64_t idot;
  char hn[256];

  (void) cls;
  t = NULL;
  if (NULL != id)
  {
    GNUNET_IDENTITY_disconnect (id);
    id = NULL;
  }
  while (NULL !=
         fgets (hn,
                sizeof (hn),
                stdin))
  {
    if (strlen(hn) > 0)
      hn[strlen(hn)-1] = '\0'; /* eat newline */
    if (0 == idot)
      last = GNUNET_TIME_absolute_get ();
    idot++;
    if (0 == idot % 100000)
    {
      struct GNUNET_TIME_Relative delta;

      delta = GNUNET_TIME_absolute_get_duration (last);
      last = GNUNET_TIME_absolute_get ();
      fprintf (stderr,
	       "Read 100000 domain names in %s\n",
	       GNUNET_STRINGS_relative_time_to_string (delta,
						       GNUNET_YES));
      GNUNET_STATISTICS_set (stats,
			     "# domain names provided",
			     idot,
			     GNUNET_NO);
    }
    queue (hn);
  }
  fprintf (stderr,
           "Done reading %llu domain names\n",
           (unsigned long long) idot);
  GNUNET_STATISTICS_set (stats,
			 "# domain names provided",
			 idot,
			 GNUNET_NO);
  iterate_zones (NULL);
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
      t = GNUNET_SCHEDULER_add_now (&process_stdin,
				    NULL);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  "No zone found\n");
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
  stats = GNUNET_STATISTICS_create ("zoneimport",
				    cfg);
  req_heap = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  ns_pending = GNUNET_CONTAINER_multihashmap_create (map_size,
                                                     GNUNET_NO);
  if (NULL == ns_pending)
  {
    fprintf (stderr,
             "Failed to allocate memory for main hash map\n");
    return;
  }
  ctx = GNUNET_DNSSTUB_start (256);
  if (NULL == ctx)
  {
    fprintf (stderr,
             "Failed to initialize GNUnet DNS STUB\n");
    return;
  }
  if (NULL == args[0])
  {
    fprintf (stderr,
             "You must provide a list of DNS resolvers on the command line\n");
    return;
  }
  for (unsigned int i=0;NULL != args[i];i++)
  {
    if (GNUNET_OK !=
        GNUNET_DNSSTUB_add_dns_ip (ctx,
                                   args[i]))
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
    GNUNET_GETOPT_option_uint ('s',
                               "size",
                               "MAPSIZE",
                               gettext_noop ("size to use for the main hash map"),
                               &map_size),
    GNUNET_GETOPT_option_relative_time ('m',
                                        "minimum-expiration",
                                        "RELATIVETIME",
                                        gettext_noop ("minimum expiration time we assume for imported records"),
                                        &minimum_expiration_time),
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  if (GNUNET_OK !=
      GNUNET_STRINGS_get_utf8_args (argc, argv,
                                    &argc, &argv))
    return 2;
  if (GNUNET_OK !=
      (ret = GNUNET_PROGRAM_run (argc,
                                 argv,
                                 "gnunet-zoneimport",
                                 "import DNS zone into namestore",
                                 options,
                                 &run,
                                 NULL)))
    return ret;
  GNUNET_free ((void*) argv);
  fprintf (stderr,
           "Rejected %u names, had %u cached, did %u lookups, stored %u record sets\n"
           "Found %u records, %u lookups failed, %u/%u pending on shutdown\n",
           rejects,
           cached,
           lookups,
           record_sets,
           records,
           failures,
           pending,
           pending_rs);
  return 0;
}

/* end of gnunet-zoneimport.c */
