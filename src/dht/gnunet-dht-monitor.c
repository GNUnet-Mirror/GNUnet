/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file dht/gnunet-dht-monitor.c
 * @brief search for data in DHT
 * @author Christian Grothoff
 * @author Bartlomiej Polot
 */
#include "platform.h"
#include "gnunet_dht_service.h"

/**
 * The type of the query
 */
static unsigned int block_type;

/**
 * The key to be monitored
 */
static char *query_key;

/**
 * User supplied timeout value (in seconds)
 */
static unsigned long long timeout_request = 5;

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
static struct GNUNET_DHT_MonitorHandle *monitor_handle;

/**
 * Count of messages received
 */
static unsigned int result_count;

/**
 * Global status value
 */
static int ret;


/**
 * Function called on shutdown, disconnects from DHT if necessary.
 *
 * @param cls closure (unused)
 * @param tc Task Context
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (verbose)
    FPRINTF (stderr, "%s",  "Shutting down!\n");
  if (dht_handle != NULL)
  {
    GNUNET_DHT_disconnect (dht_handle);
    dht_handle = NULL;
  }
}


/**
 * Stop monitoring request and start shutdown
 *
 * @param cls closure (unused)
 * @param tc Task Context
 */
static void
cleanup_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (verbose)
    FPRINTF (stderr, "%s",  "Cleaning up!\n");
  if (monitor_handle != NULL)
  {
    GNUNET_DHT_monitor_stop (monitor_handle);
    monitor_handle = NULL;
  }
  GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
}


/**
 * Callback called on each request going through the DHT.
 *
 * @param cls Closure.
 * @param mtype Type of the DHT message monitored.
 * @param exp When will this value expire.
 * @param key Key of the result/request.
 * @param get_path Peers on reply path (or NULL if not recorded).
 * @param get_path_length number of entries in get_path.
 * @param put_path peers on the PUT path (or NULL if not recorded).
 * @param put_path_length number of entries in get_path.
 * @param desired_replication_level Desired replication level.
 * @param options Options of the route (record, demultiplex, etc)
 * @param type Type of the result/request.
 * @param data Pointer to the result data.
 * @param size Number of bytes in data.
 */
void
monitor_callback (void *cls,
                  uint16_t mtype,
                  struct GNUNET_TIME_Absolute exp,
                  const GNUNET_HashCode * key,
                  const struct GNUNET_PeerIdentity *get_path,
                  unsigned int get_path_length,
                  const struct GNUNET_PeerIdentity *put_path,
                  unsigned int put_path_length,
                  uint32_t desired_replication_level,
                  enum GNUNET_DHT_RouteOption options,
                  enum GNUNET_BLOCK_Type type,
                  const void *data,
                  size_t size)
{
  FPRINTF (stdout, "Result %d, type %d:\n%.*s\n",
           result_count,
           type,
           (unsigned int) size,
           (char *) data);
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
  GNUNET_HashCode *key;

  cfg = c;

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

  if (block_type == GNUNET_BLOCK_TYPE_ANY)      /* Type of data not set */
    block_type = GNUNET_BLOCK_TYPE_TEST;

  if (query_key != NULL) {
    key = GNUNET_malloc (sizeof(GNUNET_HashCode));
    GNUNET_CRYPTO_hash (query_key, strlen (query_key), key);
  }
  else
    key = NULL;

  if (0 != timeout_request)
  {
    timeout = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
                                             timeout_request);
    if (verbose)
      FPRINTF (stderr, "Monitoring for %llus\n", timeout_request);
  }
  else
  {
    timeout = GNUNET_TIME_UNIT_FOREVER_REL;
    if (verbose)
      FPRINTF (stderr, "Monitoring indefinitely (close with Ctrl+C)\n");
  }

  GNUNET_SCHEDULER_add_delayed (timeout, &cleanup_task, NULL);
  if (verbose)
    FPRINTF (stderr, "Issuing MONITOR request for %s!\n", query_key);
  monitor_handle = GNUNET_DHT_monitor_start (dht_handle, block_type, key,
                                             &monitor_callback, NULL);
  if (verbose)
    FPRINTF (stderr, "MONITOR started!\n");
  GNUNET_free_non_null (key);

}


/**
 * gnunet-dht-get command line options
 */
static struct GNUNET_GETOPT_CommandLineOption options[] = {
  {'k', "key", "KEY",
   gettext_noop ("the query key"),
   1, &GNUNET_GETOPT_set_string, &query_key},
  {'t', "type", "TYPE",
   gettext_noop ("the type of data to look for"),
   1, &GNUNET_GETOPT_set_uint, &block_type},
  {'T', "timeout", "TIMEOUT",
   gettext_noop ("how long to execute? 0 = forever"),
   1, &GNUNET_GETOPT_set_ulong, &timeout_request},
  {'V', "verbose", NULL,
   gettext_noop ("be verbose (print progress information)"),
   0, &GNUNET_GETOPT_set_one, &verbose},
  GNUNET_GETOPT_OPTION_END
};


/**
 * Entry point for gnunet-dht-monitor
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
                              ("Prints all packets that go through the DHT."),
                              options, &run, NULL)) ? ret : 1;
}

/* end of gnunet-dht-monitor.c */
