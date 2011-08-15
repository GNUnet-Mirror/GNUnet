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
 * @file dht/gnunet-dht-get-peer.c
 * @brief search for peers close to key using the DHT
 * @author Christian Grothoff
 * @author Nathan Evans
 */
#include "platform.h"
#include "gnunet_dht_service.h"
#include "gnunet_hello_lib.h"

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
 * Handle for the request
 */
static struct GNUNET_DHT_FindPeerHandle *find_peer_handle;

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
  fprintf (stderr, _("Found %u peers\n"), result_count);
}


static void
cleanup_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (find_peer_handle != NULL)
  {
    GNUNET_DHT_find_peer_stop (find_peer_handle);
    find_peer_handle = NULL;
  }
  GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
}

/**
 * Iterator called on each result obtained from a find peer
 * operation
 *
 * @param cls closure (NULL)
 * @param hello the response message, a HELLO
 */
static void
find_peer_processor (void *cls, const struct GNUNET_HELLO_Message *hello)
{
  struct GNUNET_PeerIdentity peer;

  if (GNUNET_OK == GNUNET_HELLO_get_id (hello, &peer))
  {
    result_count++;
    if (verbose)
      fprintf (stderr, _("Found peer `%s'\n"), GNUNET_i2s (&peer));
  }
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
      fprintf (stderr, "Must provide key for DHT GET!\n");
    ret = 1;
    return;
  }

  dht_handle = GNUNET_DHT_connect (cfg, 1);

  if (dht_handle == NULL)
  {
    if (verbose)
      fprintf (stderr, "Couldn't connect to DHT service!\n");
    ret = 1;
    return;
  }
  else if (verbose)
    fprintf (stderr, "Connected to DHT service!\n");

  GNUNET_CRYPTO_hash (query_key, strlen (query_key), &key);

  timeout =
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, timeout_request);
  absolute_timeout = GNUNET_TIME_relative_to_absolute (timeout);

  if (verbose)
    fprintf (stderr, "Issuing FIND PEER request for %s!\n", query_key);

  find_peer_handle =
      GNUNET_DHT_find_peer_start (dht_handle, timeout, &key, GNUNET_DHT_RO_NONE,
                                  &find_peer_processor, NULL);
  if (NULL == find_peer_handle)
  {
    GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
    return;
  }
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_absolute_get_remaining
                                (absolute_timeout), &cleanup_task, NULL);
}


/**
 * gnunet-dht-get command line options
 */
static struct GNUNET_GETOPT_CommandLineOption options[] = {
  {'k', "key", "KEY",
   gettext_noop ("the query key"),
   1, &GNUNET_GETOPT_set_string, &query_key},
  {'T', "timeout", "TIMEOUT",
   gettext_noop ("how long to execute this query before giving up?"),
   1, &GNUNET_GETOPT_set_ulong, &timeout_request},
  {'V', "verbose", NULL,
   gettext_noop ("be verbose (print progress information)"),
   0, &GNUNET_GETOPT_set_one, &verbose},
  GNUNET_GETOPT_OPTION_END
};


/**
 * Entry point for gnunet-dht-get-peer
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-dht-get-peer",
                              gettext_noop
                              ("Issue a GET PEER request to the GNUnet DHT, print results."),
                              options, &run, NULL)) ? ret : 1;
}

/* end of gnunet-dht-get-peer */
