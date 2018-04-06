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
 * @file src/dns/gnunet-zoneimport.c
 * @brief import a DNS zone for analysis, brute force
 * @author Christian Grothoff
 */
#include "platform.h"
#include <gnunet_util_lib.h>
#include <gnunet_dnsstub_lib.h>
#include <gnunet_dnsparser_lib.h>

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
   * When did we last issue this request?
   */
  time_t time;

  /**
   * How often did we issue this query?
   */
  int issue_num;

  /**
   * random 16-bit DNS query identifier.
   */
  uint16_t id;
};


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
 * Head of DLL of all requests to perform.
 */
static struct Request *req_head;

/**
 * Tail of DLL of all requests to perform.
 */
static struct Request *req_tail;

/**
 * Main task.
 */
static struct GNUNET_SCHEDULER_Task *t;

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
 * We received @a rec for @a req. Remember the answer.
 *
 * @param req request
 * @param rec response
 */
static void
process_record (struct Request *req,
                struct GNUNET_DNSPARSER_Record *rec)
{
  char buf[INET6_ADDRSTRLEN];

  records++;
  switch (rec->type)
  {
  case GNUNET_DNSPARSER_TYPE_A:
    fprintf (stdout,
             "%s A %s\n",
             req->hostname,
             inet_ntop (AF_INET,
                        rec->data.raw.data,
                        buf,
                        sizeof (buf)));
    break;
  case GNUNET_DNSPARSER_TYPE_AAAA:
    fprintf (stdout,
             "%s AAAA %s\n",
             req->hostname,
             inet_ntop (AF_INET6,
                        rec->data.raw.data,
                        buf,
                        sizeof (buf)));
    break;
  case GNUNET_DNSPARSER_TYPE_NS:
    fprintf (stdout,
             "%s NS %s\n",
             req->hostname,
             rec->data.hostname);
    break;
  case GNUNET_DNSPARSER_TYPE_CNAME:
    fprintf (stdout,
             "%s CNAME %s\n",
             req->hostname,
             rec->data.hostname);
    break;
  case GNUNET_DNSPARSER_TYPE_MX:
    fprintf (stdout,
             "%s MX %u %s\n",
             req->hostname,
             (unsigned int) rec->data.mx->preference,
             rec->data.mx->mxhost);
    break;
  default:
    fprintf (stderr,
             "Unsupported type %u\n",
             (unsigned int) rec->type);
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
  for (unsigned int i=0;i<p->num_answers;i++)
  {
    struct GNUNET_DNSPARSER_Record *rs = &p->answers[i];

    process_record (req,
                    rs);
  }
  for (unsigned int i=0;i<p->num_authority_records;i++)
  {
    struct GNUNET_DNSPARSER_Record *rs = &p->authority_records[i];

    process_record (req,
                    rs);
  }
  for (unsigned int i=0;i<p->num_additional_records;i++)
  {
    struct GNUNET_DNSPARSER_Record *rs = &p->additional_records[i];

    process_record (req,
                    rs);
  }
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
  GNUNET_DNSSTUB_stop (ctx);
  ctx = NULL;
}


/**
 * Process requests from the queue, then if the queue is
 * not empty, try again.
 *
 * @param cls NULL
 */
static void
run (void *cls)
{
  (void) cls;

  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
                                 NULL);
  t = GNUNET_SCHEDULER_add_now (&process_queue,
                                NULL);
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
  GNUNET_CONTAINER_DLL_insert_tail (req_head,
                                    req_tail,
                                    req);
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
      char **argv)
{
  char hn[256];

  if (2 != argc)
  {
    fprintf (stderr,
             "Missing required configuration argument\n");
    return -1;
  }
  ctx = GNUNET_DNSSTUB_start (argv[1]);
  if (NULL == ctx)
  {
    fprintf (stderr,
             "Failed to initialize GNUnet DNS STUB\n");
    return 1;
  }
  while (NULL !=
         fgets (hn,
                sizeof (hn),
                stdin))
  {
    if (strlen(hn) > 0)
      hn[strlen(hn)-1] = '\0'; /* eat newline */
    queue (hn);
  }
  GNUNET_SCHEDULER_run (&run,
                        NULL);
  fprintf (stderr,
           "Did %u lookups, found %u records, %u lookups failed, %u pending on shutdown\n",
           lookups,
           records,
           failures,
           pending);
  return 0;
}
