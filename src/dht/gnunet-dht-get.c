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
 * @file dht/gnunet-dht-get.c
 * @brief search for data in DHT
 * @author Christian Grothoff
 * @author Nathan Evans
 */
#include "platform.h"
#include "gnunet_dht_service.h"

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
 * Handle to the DHT
 */
static struct GNUNET_DHT_Handle *dht_handle;

/**
 * Global handle of the configuration
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle for the get request
 */
static struct GNUNET_DHT_GetHandle *get_handle;

/**
 * Count of results found
 */
static unsigned int result_count;

/**
 * Global status value
 */
static int ret;


static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (dht_handle != NULL)
  {
    GNUNET_DHT_disconnect (dht_handle);
    dht_handle = NULL;
  }
}


static void
cleanup_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (get_handle != NULL)
  {
    GNUNET_DHT_get_stop (get_handle);
    get_handle = NULL;
  }
  GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
}


/**
 * Iterator called on each result obtained for a DHT
 * operation that expects a reply
 *
 * @param cls closure
 * @param exp when will this value expire
 * @param key key of the result
 * @param get_path peers on reply path (or NULL if not recorded)
 * @param get_path_length number of entries in get_path
 * @param put_path peers on the PUT path (or NULL if not recorded)
 * @param put_path_length number of entries in get_path
 * @param type type of the result
 * @param size number of bytes in data
 * @param data pointer to the result data
 */
static void
get_result_iterator (void *cls, struct GNUNET_TIME_Absolute exp,
                     const GNUNET_HashCode * key,
                     const struct GNUNET_PeerIdentity *get_path,
                     unsigned int get_path_length,
                     const struct GNUNET_PeerIdentity *put_path,
                     unsigned int put_path_length, enum GNUNET_BLOCK_Type type,
                     size_t size, const void *data)
{
  FPRINTF (stdout, "Result %d, type %d:\n%.*s\n", result_count, type,
           (unsigned int) size, (char *) data);
  result_count++;
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
  GNUNET_HashCode key;

  cfg = c;

  if (query_key == NULL)
  {
    if (verbose)
      FPRINTF (stderr, "%s",  "Must provide key for DHT GET!\n");
    ret = 1;
    return;
  }

  dht_handle = GNUNET_DHT_connect (cfg, 1);

  if (dht_handle == NULL)
  {
    if (verbose)
      FPRINTF (stderr, "%s",  "Couldn't connect to DHT service!\n");
    ret = 1;
    return;
  }
  else if (verbose)
    FPRINTF (stderr, "%s",  "Connected to DHT service!\n");

  if (query_type == GNUNET_BLOCK_TYPE_ANY)      /* Type of data not set */
    query_type = GNUNET_BLOCK_TYPE_TEST;

  GNUNET_CRYPTO_hash (query_key, strlen (query_key), &key);

  timeout =
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, timeout_request);
  absolute_timeout = GNUNET_TIME_relative_to_absolute (timeout);

  if (verbose)
    FPRINTF (stderr, "Issuing GET request for %s!\n", query_key);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_absolute_get_remaining
                                (absolute_timeout), &cleanup_task, NULL);
  get_handle =
      GNUNET_DHT_get_start (dht_handle, query_type, &key, replication,
                            GNUNET_DHT_RO_NONE, NULL, 0, &get_result_iterator,
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
 * Entry point for gnunet-dht-get
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-dht-get",
                              gettext_noop
                              ("Issue a GET request to the GNUnet DHT, prints results."),
                              options, &run, NULL)) ? ret : 1;
}

/* end of gnunet-dht-get.c */
