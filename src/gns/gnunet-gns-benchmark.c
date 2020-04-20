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
 * @file src/gns/gnunet-gns-benchmark.c
 * @brief issue many queries to GNS and compute performance statistics
 * @author Christian Grothoff
 */
#include "platform.h"
#include <gnunet_util_lib.h>
#include <gnunet_gnsrecord_lib.h>
#include <gnunet_gns_service.h>


/**
 * How long do we wait at least between requests by default?
 */
#define DEF_REQUEST_DELAY GNUNET_TIME_relative_multiply ( \
    GNUNET_TIME_UNIT_MILLISECONDS, 1)

/**
 * How long do we wait until we consider a request failed by default?
 */
#define DEF_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 1)


/**
 * We distinguish between different categories of
 * requests, for which we track statistics separately.
 * However, this process does not change how it acts
 * based on the category.
 */
enum RequestCategory
{
  RC_SHARED = 0,
  RC_PRIVATE = 1,
  /**
   * Must be last and match number of categories.
   */
  RC_MAX = 2
};


/**
 * Request we should make.  We keep this struct in memory per request,
 * thus optimizing it is crucial for the overall memory consumption of
 * the zone importer.
 */
struct Request
{
  /**
   * Active requests are kept in a DLL.
   */
  struct Request *next;

  /**
   * Active requests are kept in a DLL.
   */
  struct Request *prev;

  /**
   * Socket used to make the request, NULL if not active.
   */
  struct GNUNET_GNS_LookupWithTldRequest *lr;

  /**
   * Hostname we are resolving, allocated at the end of
   * this struct (optimizing memory consumption by reducing
   * total number of allocations).
   */
  const char *hostname;

  /**
   * While we are fetching the record, the value is set to the
   * starting time of the GNS operation.
   */
  struct GNUNET_TIME_Absolute op_start_time;

  /**
   * Observed latency, set once we got a reply.
   */
  struct GNUNET_TIME_Relative latency;

  /**
   * Category of the request.
   */
  enum RequestCategory cat;
};


/**
 * GNS handle.
 */
static struct GNUNET_GNS_Handle *gns;

/**
 * Number of lookups we performed overall per category.
 */
static unsigned int lookups[RC_MAX];

/**
 * Number of replies we got per category.
 */
static unsigned int replies[RC_MAX];

/**
 * Number of replies we got per category.
 */
static unsigned int failures[RC_MAX];

/**
 * Sum of the observed latencies of successful queries,
 * per category.
 */
static struct GNUNET_TIME_Relative latency_sum[RC_MAX];

/**
 * Active requests are kept in a DLL.
 */
static struct Request *act_head;

/**
 * Active requests are kept in a DLL.
 */
static struct Request *act_tail;

/**
 * Completed successful requests are kept in a DLL.
 */
static struct Request *succ_head;

/**
 * Completed successful requests are kept in a DLL.
 */
static struct Request *succ_tail;

/**
 * Yet to be started requests are kept in a DLL.
 */
static struct Request *todo_head;

/**
 * Yet to be started requests are kept in a DLL.
 */
static struct Request *todo_tail;

/**
 * Main task.
 */
static struct GNUNET_SCHEDULER_Task *t;

/**
 * Delay between requests.
 */
static struct GNUNET_TIME_Relative request_delay;

/**
 * Timeout for requests.
 */
static struct GNUNET_TIME_Relative timeout;

/**
 * Number of requests we have concurrently active.
 */
static unsigned int active_cnt;

/**
 * Look for GNS2DNS records specifically?
 */
static int g2d;

/**
 * Free @a req and data structures reachable from it.
 *
 * @param req request to free
 */
static void
free_request (struct Request *req)
{
  if (NULL != req->lr)
    GNUNET_GNS_lookup_with_tld_cancel (req->lr);
  GNUNET_free (req);
}


/**
 * Function called with the result of a GNS resolution.
 *
 * @param cls closure with the `struct Request`
 * @param gns_tld #GNUNET_YES if GNS lookup was attempted
 * @param rd_count number of records in @a rd
 * @param rd the records in reply
 */
static void
process_result (void *cls,
                int gns_tld,
                uint32_t rd_count,
                const struct GNUNET_GNSRECORD_Data *rd)
{
  struct Request *req = cls;

  (void) gns_tld;
  (void) rd_count;
  (void) rd;
  active_cnt--;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got response for request `%s'\n",
              req->hostname);
  req->lr = NULL;
  req->latency = GNUNET_TIME_absolute_get_duration (req->op_start_time);
  GNUNET_CONTAINER_DLL_remove (act_head,
                               act_tail,
                               req);
  GNUNET_CONTAINER_DLL_insert (succ_head,
                               succ_tail,
                               req);
  replies[req->cat]++;
  latency_sum[req->cat]
    = GNUNET_TIME_relative_add (latency_sum[req->cat],
                                req->latency);
}


/**
 * Process request from the queue.
 *
 * @param cls NULL
 */
static void
process_queue (void *cls)
{
  struct Request *req;
  struct GNUNET_TIME_Relative duration;

  (void) cls;
  t = NULL;
  /* check for expired requests */
  while (NULL != (req = act_head))
  {
    duration = GNUNET_TIME_absolute_get_duration (req->op_start_time);
    if (duration.rel_value_us < timeout.rel_value_us)
      break;
    GNUNET_CONTAINER_DLL_remove (act_head,
                                 act_tail,
                                 req);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Failing request `%s' due to timeout\n",
                req->hostname);
    failures[req->cat]++;
    active_cnt--;
    free_request (req);
  }
  if (NULL == (req = todo_head))
  {
    struct GNUNET_TIME_Absolute at;

    if (NULL == (req = act_head))
    {
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    at = GNUNET_TIME_absolute_add (req->op_start_time,
                                   timeout);
    t = GNUNET_SCHEDULER_add_at (at,
                                 &process_queue,
                                 NULL);
    return;
  }
  GNUNET_CONTAINER_DLL_remove (todo_head,
                               todo_tail,
                               req);
  GNUNET_CONTAINER_DLL_insert_tail (act_head,
                                    act_tail,
                                    req);
  lookups[req->cat]++;
  active_cnt++;
  req->op_start_time = GNUNET_TIME_absolute_get ();
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting request `%s' (%u in parallel)\n",
              req->hostname,
              active_cnt);
  req->lr = GNUNET_GNS_lookup_with_tld (gns,
                                        req->hostname,
                                        g2d
                                        ? GNUNET_GNSRECORD_TYPE_GNS2DNS
                                        : GNUNET_GNSRECORD_TYPE_ANY,
                                        GNUNET_GNS_LO_DEFAULT,
                                        &process_result,
                                        req);
  t = GNUNET_SCHEDULER_add_delayed (request_delay,
                                    &process_queue,
                                    NULL);
}


/**
 * Compare two requests by latency for qsort().
 *
 * @param c1 pointer to `struct Request *`
 * @param c2 pointer to `struct Request *`
 * @return -1 if c1<c2, 1 if c1>c2, 0 if c1==c2.
 */
static int
compare_req (const void *c1,
             const void *c2)
{
  const struct Request *r1 = *(void **) c1;
  const struct Request *r2 = *(void **) c2;

  if (r1->latency.rel_value_us < r2->latency.rel_value_us)
    return -1;
  if (r1->latency.rel_value_us > r2->latency.rel_value_us)
    return 1;
  return 0;
}


/**
 * Output statistics, then clean up and terminate the process.
 *
 * @param cls NULL
 */
static void
do_shutdown (void *cls)
{
  struct Request *req;
  struct Request **ra[RC_MAX];
  unsigned int rp[RC_MAX];

  (void) cls;
  for (enum RequestCategory rc = 0; rc < RC_MAX; rc++)
  {
    ra[rc] = GNUNET_new_array (replies[rc],
                               struct Request *);
    rp[rc] = 0;
  }
  for (req = succ_head; NULL != req; req = req->next)
  {
    GNUNET_assert (rp[req->cat] < replies[req->cat]);
    ra[req->cat][rp[req->cat]++] = req;
  }
  for (enum RequestCategory rc = 0; rc < RC_MAX; rc++)
  {
    unsigned int off;

    fprintf (stdout,
             "Category %u\n",
             rc);
    fprintf (stdout,
             "\tlookups: %u replies: %u failures: %u\n",
             lookups[rc],
             replies[rc],
             failures[rc]);
    if (0 == rp[rc])
      continue;
    qsort (ra[rc],
           rp[rc],
           sizeof(struct Request *),
           &compare_req);
    latency_sum[rc] = GNUNET_TIME_relative_divide (latency_sum[rc],
                                                   replies[rc]);
    fprintf (stdout,
             "\taverage: %s\n",
             GNUNET_STRINGS_relative_time_to_string (latency_sum[rc],
                                                     GNUNET_YES));
    off = rp[rc] * 50 / 100;
    fprintf (stdout,
             "\tmedian(50): %s\n",
             GNUNET_STRINGS_relative_time_to_string (ra[rc][off]->latency,
                                                     GNUNET_YES));
    off = rp[rc] * 75 / 100;
    fprintf (stdout,
             "\tquantile(75): %s\n",
             GNUNET_STRINGS_relative_time_to_string (ra[rc][off]->latency,
                                                     GNUNET_YES));
    off = rp[rc] * 90 / 100;
    fprintf (stdout,
             "\tquantile(90): %s\n",
             GNUNET_STRINGS_relative_time_to_string (ra[rc][off]->latency,
                                                     GNUNET_YES));
    off = rp[rc] * 99 / 100;
    fprintf (stdout,
             "\tquantile(99): %s\n",
             GNUNET_STRINGS_relative_time_to_string (ra[rc][off]->latency,
                                                     GNUNET_YES));
    GNUNET_free (ra[rc]);
  }
  if (NULL != t)
  {
    GNUNET_SCHEDULER_cancel (t);
    t = NULL;
  }
  while (NULL != (req = act_head))
  {
    GNUNET_CONTAINER_DLL_remove (act_head,
                                 act_tail,
                                 req);
    free_request (req);
  }
  while (NULL != (req = succ_head))
  {
    GNUNET_CONTAINER_DLL_remove (succ_head,
                                 succ_tail,
                                 req);
    free_request (req);
  }
  while (NULL != (req = todo_head))
  {
    GNUNET_CONTAINER_DLL_remove (todo_head,
                                 todo_tail,
                                 req);
    free_request (req);
  }
  if (NULL != gns)
  {
    GNUNET_GNS_disconnect (gns);
    gns = NULL;
  }
}


/**
 * Add @a hostname to the list of requests to be made.
 *
 * @param hostname name to resolve
 * @param cat category of the @a hostname
 */
static void
queue (const char *hostname,
       enum RequestCategory cat)
{
  struct Request *req;
  const char *dot;
  size_t hlen;

  dot = strchr (hostname,
                (unsigned char) '.');
  if (NULL == dot)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Refusing invalid hostname `%s' (lacks '.')\n",
                hostname);
    return;
  }
  hlen = strlen (hostname) + 1;
  req = GNUNET_malloc (sizeof(struct Request) + hlen);
  req->cat = cat;
  req->hostname = (char *) &req[1];
  GNUNET_memcpy (&req[1],
                 hostname,
                 hlen);
  GNUNET_CONTAINER_DLL_insert (todo_head,
                               todo_tail,
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
  static struct GNUNET_TIME_Absolute last;
  static uint64_t idot;
  unsigned int cat;
  char hn[256];
  char in[270];

  (void) cls;
  t = NULL;
  while (NULL !=
         fgets (in,
                sizeof(in),
                stdin))
  {
    if (strlen (in) > 0)
      hn[strlen (in) - 1] = '\0';  /* eat newline */
    if ((2 != sscanf (in,
                      "%u %255s",
                      &cat,
                      hn)) ||
        (cat >= RC_MAX))
    {
      fprintf (stderr,
               "Malformed input line `%s', skipping\n",
               in);
      continue;
    }
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
    }
    queue (hn,
           (enum RequestCategory) cat);
  }
  fprintf (stderr,
           "Done reading %llu domain names\n",
           (unsigned long long) idot);
  t = GNUNET_SCHEDULER_add_now (&process_queue,
                                NULL);
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
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
                                 NULL);
  gns = GNUNET_GNS_connect (cfg);
  if (NULL == gns)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  t = GNUNET_SCHEDULER_add_now (&process_stdin,
                                NULL);
}


/**
 * Call with list of names with numeric category to query.
 *
 * @param argc unused
 * @param argv unused
 * @return 0 on success
 */
int
main (int argc,
      char *const*argv)
{
  int ret = 0;
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_relative_time ('d',
                                        "delay",
                                        "RELATIVETIME",
                                        gettext_noop (
                                          "how long to wait between queries"),
                                        &request_delay),
    GNUNET_GETOPT_option_relative_time ('t',
                                        "timeout",
                                        "RELATIVETIME",
                                        gettext_noop (
                                          "how long to wait for an answer"),
                                        &timeout),
    GNUNET_GETOPT_option_flag ('2',
                               "g2d",
                               gettext_noop (
                                 "look for GNS2DNS records instead of ANY"),
                               &g2d),
    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK !=
      GNUNET_STRINGS_get_utf8_args (argc, argv,
                                    &argc, &argv))
    return 2;
  timeout = DEF_TIMEOUT;
  request_delay = DEF_REQUEST_DELAY;
  if (GNUNET_OK !=
      GNUNET_PROGRAM_run (argc,
                          argv,
                          "gnunet-gns-benchmark",
                          "resolve GNS names and measure performance",
                          options,
                          &run,
                          NULL))
    ret = 1;
  GNUNET_free_nz ((void *) argv);
  return ret;
}


/* end of gnunet-gns-benchmark.c */
