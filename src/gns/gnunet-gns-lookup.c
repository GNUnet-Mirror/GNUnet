/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2004, 2005, 2006, 2007, 2009 Christian Grothoff (and other contributing authors)

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
 * @file gns/gnunet-gns-lookup.c
 * @brief search for records in GNS
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_gns_service.h"

/**
 * The type of the query
 */
static unsigned int query_type;

/**
 * Desired replication level
 */
static unsigned int replication = 5;

/**
 * The key for the query
 */
static char *query_key;

/**
 * User supplied timeout value (in seconds)
 */
static unsigned long long timeout_request = 5;

/**
 * When this request should really die
 */
struct GNUNET_TIME_Absolute absolute_timeout;

/**
 * Be verbose
 */
static int verbose;

/**
 * Handle to the GNS
 */
static struct GNUNET_GNS_Handle *gns_handle;

/**
 * Global handle of the configuration
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle for the lookup request
 */
static struct GNUNET_GNS_LookupHandle *lookup_handle;

/**
 * Global status value
 */
static int ret;


static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (gns_handle != NULL)
  {
    GNUNET_GNS_disconnect (gns_handle);
    gns_handle = NULL;
  }
}


static void
cleanup_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (lookup_handle != NULL)
  {
    GNUNET_GNS_lookup_stop (lookup_handle);
    lookup_handle = NULL;
  }
  GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
}


/**
 * Iterator called on each result obtained for a GNS
 * operation that expects a reply
 *
 * @param cls closure
 * @param name name
 * @param record a record
 * @param num_records number of records
 */
static void
lookup_result_iterator (void *cls,
                        const char * name,
                        const struct GNUNET_GNS_Record *record,
                        unsigned int num_records)
{
  FPRINTF (stdout, "%d results for %s\n", num_records, name);
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param c configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  struct GNUNET_TIME_Relative timeout;

  cfg = c;

  if (query_key == NULL)
  {
    if (verbose)
      FPRINTF (stderr, "%s",  "Must provide key for GNS lookup!\n");
    ret = 1;
    return;
  }

  gns_handle = GNUNET_GNS_connect (cfg, 1);

  if (gns_handle == NULL)
  {
    if (verbose)
      FPRINTF (stderr, "%s",  "Couldn't connect to GNS service!\n");
    ret = 1;
    return;
  }
  else if (verbose)
    FPRINTF (stderr, "%s",  "Connected to GNS service!\n");

  timeout =
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, timeout_request);
  absolute_timeout = GNUNET_TIME_relative_to_absolute (timeout);

  if (verbose)
    FPRINTF (stderr, "Issuing lookup request for %s!\n", query_key);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_absolute_get_remaining
                                (absolute_timeout), &cleanup_task, NULL);
  lookup_handle =
      GNUNET_GNS_lookup_start (gns_handle, timeout, query_key,
                               0/*GNS_RecordType*/,
                               &lookup_result_iterator,
                               NULL);

}


/**
 * gnunet-dht-get command line options
 */
static struct GNUNET_GETOPT_CommandLineOption options[] = {
  {'k', "key", "KEY",
   gettext_noop ("the query key"),
   1, &GNUNET_GETOPT_set_string, &query_key},
  {'r', "replication", "LEVEL",
   gettext_noop ("how many parallel requests (replicas) to create"),
   1, &GNUNET_GETOPT_set_uint, &replication},
  {'t', "type", "TYPE",
   gettext_noop ("the type of data to look for"),
   1, &GNUNET_GETOPT_set_uint, &query_type},
  {'T', "timeout", "TIMEOUT",
   gettext_noop ("how long to execute this query before giving up?"),
   1, &GNUNET_GETOPT_set_ulong, &timeout_request},
  {'V', "verbose", NULL,
   gettext_noop ("be verbose (print progress information)"),
   0, &GNUNET_GETOPT_set_one, &verbose},
  GNUNET_GETOPT_OPTION_END
};


/**
 * Entry point for gnunet-gns-lookup
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-gns-get",
                              gettext_noop
                              ("Issue a request to the GNUnet Naming System, prints results."),
                              options, &run, NULL)) ? ret : 1;
}

/* end of gnunet-gns-lookup.c */
