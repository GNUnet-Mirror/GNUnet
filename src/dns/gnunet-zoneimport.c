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

struct Request
{
  struct Request *next;
  struct Request *prev;
  struct GNUNET_DNSSTUB_RequestSocket *rs;
  /**
   * Raw DNS query.
   */
  void *raw;
  /**
   * Number of bytes in @e raw.
   */
  size_t raw_len;

  char *hostname;
  time_t time;
  int issueNum;

  /**
   * random 16-bit DNS query identifier.
   */
  uint16_t id;
};


static struct GNUNET_DNSSTUB_Context *ctx;

// the number of queries that are outstanding
static unsigned int pending;

static unsigned int lookups;

static struct Request *req_head;

static struct Request *req_tail;

// the number of queries that are outstanding
static unsigned int pending;

static unsigned int lookups;

#define THRESH 20

#define MAX_RETRIES 5


// time_thresh is in usecs, but note that adns isn't consistent
// in how long it takes to submit queries, so 40usecs is
// really equivalent to 25,000 queries per second, but clearly it doesn't
// operate in that range. Thus, 10 is just a 'magic' number that we can
// tweak depending on how fast we want to submit queries.
#define TIME_THRESH 10

#define MAX_RETRIES 5


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
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Stub gave up on DNS reply for `%s'\n",
                req->hostname);
    GNUNET_CONTAINER_DLL_remove (req_head,
                                 req_tail,
                                 req);
    GNUNET_CONTAINER_DLL_insert_tail (req_head,
                                      req_tail,
                                      req);
    req->rs = NULL;
    return;
  }
  if (req->id != dns->id)
    return;
  p = GNUNET_DNSPARSER_parse ((const char *) dns,
                              dns_len);
  if (NULL == p)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to parse DNS reply for `%s'\n",
                req->hostname);
    GNUNET_CONTAINER_DLL_remove (req_head,
                                 req_tail,
                                 req);
    GNUNET_CONTAINER_DLL_insert_tail (req_head,
                                      req_tail,
                                      req);
    GNUNET_DNSSTUB_resolve_cancel (req->rs);
    req->rs = NULL;
    return;
  }
  for (unsigned int i=0;i<p->num_answers;i++)
  {
    struct GNUNET_DNSPARSER_Record *rs = &p->answers[i];
    char buf[INET_ADDRSTRLEN];

    switch (rs->type)
    {
    case GNUNET_DNSPARSER_TYPE_A:
      fprintf (stdout,
               "%s %s\n",
               req->hostname,
               inet_ntop (AF_INET,
                          rs->data.raw.data,
                          buf,
                          sizeof (buf)));
      break;
    }
  }
  GNUNET_DNSPARSER_free_packet (p);
  GNUNET_DNSSTUB_resolve_cancel (req->rs);
  req->rs = NULL;
  GNUNET_CONTAINER_DLL_remove (req_head,
                               req_tail,
                               req);
  GNUNET_free (req->hostname);
  GNUNET_free (req->raw);
  GNUNET_free (req);
}


static void
submit_req (struct Request *req)
{
  static struct timeval last_request;
  struct timeval now;

  if (NULL != req->rs)
    return; /* already submitted */
  gettimeofday (&now,
                NULL);
  if ( ( ( (now.tv_sec - last_request.tv_sec) == 0) &&
         ( (now.tv_usec - last_request.tv_usec) < TIME_THRESH) ) ||
       (pending >= THRESH) )
    return;
  GNUNET_assert (NULL == req->rs);
  req->rs = GNUNET_DNSSTUB_resolve2 (ctx,
                                     req->raw,
                                     req->raw_len,
                                     &process_result,
                                     req);
  GNUNET_assert (NULL != req->rs);
  last_request = now;
  lookups++;
  pending++;
  req->time = time (NULL);
}


static void
process_queue()
{
  struct Request *wl = wl = req_head;

  if ( (pending < THRESH) &&
       (NULL != wl) )
  {
    struct Request *req = wl;

    wl = req->next;
    submit_req (req);
  }
}


static void
run (void *cls)
{
  process_queue ();
  if (NULL != req_head)
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MILLISECONDS,
                                  &run,
                                  NULL);
}


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
  q.type = GNUNET_DNSPARSER_TYPE_ANY;
  q.dns_traffic_class = GNUNET_TUN_DNS_CLASS_INTERNET;

  memset (&p, 0, sizeof (p));
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
  GNUNET_DNSSTUB_stop (ctx);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Did %u lookups\n",
              lookups);
  return 0;
}
