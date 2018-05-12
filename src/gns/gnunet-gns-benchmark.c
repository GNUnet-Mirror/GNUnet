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
#define DEF_REQUEST_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 1)

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
  char *hostname;

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
  /* check for expired requests */
  while (NULL != (req = act_head))
  {
    duration = GNUNET_TIME_absolute_get_duration (req->op_start_time);
    if (duration.rel_value_us < timeout.rel_value_us)
      break;
    GNUNET_CONTAINER_DLL_remove (act_head,
				 act_tail,
				 req);
    failures[req->cat]++;
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
  req->op_start_time = GNUNET_TIME_absolute_get ();
  req->lr = GNUNET_GNS_lookup_with_tld (gns,
					req->hostname,
					GNUNET_GNSRECORD_TYPE_ANY,
					GNUNET_GNS_LO_DEFAULT,
					&process_result,
					req);
  t = GNUNET_SCHEDULER_add_delayed (request_delay,
                                    &process_queue,
                                    NULL);
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

  (void) cls;
  /* FIXME: calculate statistics */
  if (NULL != gns)
  {
    GNUNET_GNS_disconnect (gns);
    gns = NULL;
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
  req = GNUNET_malloc (sizeof (struct Request) + hlen);
  req->cat = cat;
  req->hostname = (char *) &req[1];
  memcpy (req->hostname,
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
  char hn[270];

  (void) cls;
  t = NULL;
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
    if (0 == idot % 10000)
    {
      struct GNUNET_TIME_Relative delta;

      delta = GNUNET_TIME_absolute_get_duration (last);
      last = GNUNET_TIME_absolute_get ();
      fprintf (stderr,
	       "Imported 10000 records in %s\n",
	       GNUNET_STRINGS_relative_time_to_string (delta,
						       GNUNET_YES));
    }
    queue (hn,
	   RC_SHARED); // FIXME: parse input line!
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
                                        gettext_noop ("how long to wait between queries"),
                                        &request_delay),
    GNUNET_GETOPT_option_relative_time ('t',
                                        "timeout",
                                        "RELATIVETIME",
                                        gettext_noop ("how long to wait for an answer"),
                                        &timeout),
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
  GNUNET_free ((void*) argv);
  fprintf (stderr,
           "Statistics here\n");
  return ret;
}

/* end of gnunet-gns-benchmark.c */
