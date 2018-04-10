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
#include <gnunet_namestore_plugin.h>


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
   * Requests are kept in a DLL.
   */
  struct Request *next;

  /**
   * Requests are kept in a DLL.
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
   * Number of bytes in @e raw.
   */
  size_t raw_len;

  /**
   * Hostname we are resolving.
   */
  char *hostname;

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
  struct GNUNET_TIME_Absolute expires__;
  
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
 * Namestore plugin.
 */
static struct GNUNET_NAMESTORE_PluginFunctions *ns;

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
 * Number of lookups that failed.
 */
static unsigned int failures;

/**
 * Number of records we found.
 */
static unsigned int records;

/**
 * Head of DLL of all requests to perform, sorted by
 * the time we should next do the request (i.e. by expires).
 */
static struct Request *req_head;

/**
 * Tail of DLL of all requests to perform, sorted by
 * the time we should next do the request (i.e. by expires).
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
 * Name of the database plugin (for loading/unloading).
 */
static char *db_lib_name;


/**
 * Maximum number of queries pending at the same time.
 */
#define THRESH 20

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
		   &rec->data.raw.data,
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
		  rec->type,
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
		   &rec->data.raw.data,
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
		  rec->type,
		  rec->expiration_time,
		  dst,
		  off);
      gc->found = GNUNET_YES;
    }
    break;
  case GNUNET_DNSPARSER_TYPE_CNAME:
    GNUNET_break (0); /* FIXME: implement! */
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
    return; /* does not match hostname, might be glue, but
	       not useful for this pass! */
  if (0 ==
      GNUNET_TIME_absolute_get_remaining (rec->expiration_time).rel_value_us)
    return; /* record expired */
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
	add_record (req,
		    rec->type,
		    rec->expiration_time,
		    dst,
		    off);
      break;
    }
  case GNUNET_DNSPARSER_TYPE_CNAME:
    /* Special logic required, FIXME: support later! */
    fprintf (stdout,
             "%s CNAME %s\n",
             rec->name,
             rec->data.hostname);
    break;
  case GNUNET_DNSPARSER_TYPE_DNAME:
    /* Very special logic required (no support for DNAME
       in GNS yet!), FIXME: support later! */
    fprintf (stdout,
             "FIMXE: %s DNAME %s\n",
             rec->name,
             rec->data.hostname);
    break;
  case GNUNET_DNSPARSER_TYPE_MX:
    if (GNUNET_OK ==
	GNUNET_DNSPARSER_builder_add_mx (dst,
					 dst_len,
					 &off,
					 rec->data.mx))
      add_record (req,
		  rec->type,
		  rec->expiration_time,
		  dst,
		  off);
    break;
  case GNUNET_DNSPARSER_TYPE_SOA:
    if (GNUNET_OK ==
	GNUNET_DNSPARSER_builder_add_soa (dst,
					  dst_len,
					  &off,
					  rec->data.soa))
      add_record (req,
		  rec->type,
		  rec->expiration_time,
		  dst,
		  off);
    break;
  case GNUNET_DNSPARSER_TYPE_SRV:
    if (GNUNET_OK ==
	GNUNET_DNSPARSER_builder_add_srv (dst,
					  dst_len,
					  &off,
					  rec->data.srv))
      add_record (req,
		  rec->type,
		  rec->expiration_time,
		  dst,
		  off);
    break;
  case GNUNET_DNSPARSER_TYPE_PTR:
    if (GNUNET_OK ==
	GNUNET_DNSPARSER_builder_add_name (dst,
					   dst_len,
					   &off,
					   rec->data.hostname))
      add_record (req,
		  rec->type,
		  rec->expiration_time,
		  dst,
		  off);
    break;
  case GNUNET_DNSPARSER_TYPE_CERT:
    if (GNUNET_OK ==
	GNUNET_DNSPARSER_builder_add_cert (dst,
					   dst_len,
					   &off,
					   rec->data.cert))
      add_record (req,
		  rec->type,
		  rec->expiration_time,
		  dst,
		  off);
    break;
    /* Rest is 'raw' encoded and just needs to be copied IF
       the hostname matches the requested name; otherwise we
       simply cannot use it. */
  case GNUNET_DNSPARSER_TYPE_A:
  case GNUNET_DNSPARSER_TYPE_AAAA:
  case GNUNET_DNSPARSER_TYPE_TXT:
  default:
    add_record (req,
		rec->type,
		rec->expiration_time,
		rec->data.raw.data,
		rec->data.raw.data_len);
    break;
  }
}


/**
 * Function called with the result of a DNS resolution.
 *
 * @param cls closure with the `struct Request`
 * @param rs socket that received the response
 * @param dns dns response, never NULL
 * @param dns_len number of bytes in @a dns
 */
static void
process_result (void *cls,
                struct GNUNET_DNSSTUB_RequestSocket *rs,
                const struct GNUNET_TUN_DnsHeader *dns,
                size_t dns_len)
{
  struct Request *req = cls;
  struct GNUNET_DNSPARSER_Packet *p;

  (void) rs;
  if (NULL == dns)
  {
    /* stub gave up */
    pending--;
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Stub gave up on DNS reply for `%s'\n",
                req->hostname);
    GNUNET_CONTAINER_DLL_remove (req_head,
                                 req_tail,
                                 req);
    if (req->issue_num > MAX_RETRIES)
    {
      failures++;
      GNUNET_free (req->hostname);
      GNUNET_free (req->raw);
      GNUNET_free (req);
      return;
    }
    GNUNET_CONTAINER_DLL_insert_tail (req_head,
                                      req_tail,
                                      req);
    req->rs = NULL;
    return;
  }
  if (req->id != dns->id)
    return;
  pending--;
  GNUNET_DNSSTUB_resolve_cancel (req->rs);
  req->rs = NULL;
  GNUNET_CONTAINER_DLL_remove (req_head,
                               req_tail,
                               req);
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
      GNUNET_free (req->hostname);
      GNUNET_free (req->raw);
      GNUNET_free (req);
      return;
    }
    GNUNET_CONTAINER_DLL_insert_tail (req_head,
                                      req_tail,
                                      req);
    return;
  }
  req->p = p;
  for_all_records (p,
		   &process_record,
		   req);
  req->p = NULL;
  // FIXME: update database!
  GNUNET_DNSPARSER_free_packet (p);
  GNUNET_free (req->hostname);
  GNUNET_free (req->raw);
  GNUNET_free (req);
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
  static struct timeval last_request;
  struct timeval now;

  if (NULL != req->rs)
    return GNUNET_NO; /* already submitted */
  gettimeofday (&now,
                NULL);
  if ( ( ( (now.tv_sec - last_request.tv_sec) == 0) &&
         ( (now.tv_usec - last_request.tv_usec) < TIME_THRESH) ) ||
       (pending >= THRESH) )
    return GNUNET_SYSERR;
  GNUNET_assert (NULL == req->rs);
  req->rs = GNUNET_DNSSTUB_resolve2 (ctx,
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
process_queue(void *cls)
{
  (void) cls;
  t = NULL;
  for (struct Request *req = req_head;
       NULL != req;
       req = req->next)
  {
    if (GNUNET_SYSERR == submit_req (req))
      break;
  }
  if (NULL != req_head)
    t = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MILLISECONDS,
                                  &process_queue,
                                  NULL);
  else
    GNUNET_SCHEDULER_shutdown ();
}


/**
 * Clean up and terminate the process.
 *
 * @param cls NULL
 */
static void
do_shutdown (void *cls)
{
  (void) cls;
  if (NULL != t)
  {
    GNUNET_SCHEDULER_cancel (t);
    t = NULL;
  }
  if (NULL != ns)
  {
    GNUNET_break (NULL ==
		  GNUNET_PLUGIN_unload (db_lib_name,
					ns));
    GNUNET_free (db_lib_name);
    db_lib_name = NULL;
  }
  GNUNET_DNSSTUB_stop (ctx);
  ctx = NULL;
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

  if (GNUNET_OK !=
      GNUNET_DNSPARSER_check_name (hostname))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Refusing invalid hostname `%s'\n",
                hostname);
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
    return;
  }

  req = GNUNET_new (struct Request);
  req->hostname = strdup (hostname);
  req->raw = raw;
  req->raw_len = raw_size;
  req->id = p.id;
  /* FIXME: import data from namestore! */

  /* FIXME: insert sorted by record expiration time */
  GNUNET_CONTAINER_DLL_insert_tail (req_head,
                                    req_tail,
                                    req);
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
  char hn[256];
  char *database;

  (void) cls;
  (void) args;
  (void) cfgfile;
  ctx = GNUNET_DNSSTUB_start (dns_server);
  if (NULL == ctx)
  {
    fprintf (stderr,
             "Failed to initialize GNUnet DNS STUB\n");
    return;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             "namestore",
                                             "database",
                                             &database))
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "No database backend configured\n");

  GNUNET_asprintf (&db_lib_name,
                   "libgnunet_plugin_namestore_%s",
                   database);
  ns = GNUNET_PLUGIN_load (db_lib_name,
			   (void *) cfg);
  GNUNET_free (database);
  while (NULL !=
         fgets (hn,
                sizeof (hn),
                stdin))
  {
    if (strlen(hn) > 0)
      hn[strlen(hn)-1] = '\0'; /* eat newline */
    queue (hn);
  }
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
                                 NULL);
  t = GNUNET_SCHEDULER_add_now (&process_queue,
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
           "Did %u lookups, found %u records, %u lookups failed, %u pending on shutdown\n",
           lookups,
           records,
           failures,
           pending);
  return 0;
}

/* end of gnunet-zoneimport.c */
