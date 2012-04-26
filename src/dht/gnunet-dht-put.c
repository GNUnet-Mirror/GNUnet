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
 * @file dht/gnunet-dht-put.c
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
 * The key for the query
 */
static char *query_key;

/**
 * User supplied timeout value
 */
static unsigned long long timeout_request = 5;

/**
 * User supplied expiration value
 */
static unsigned long long expiration_seconds = 3600;

/**
 * Desired replication level.
 */
static unsigned int replication = 5;

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
 * Global status value
 */
static int ret;

/**
 * The data to insert into the dht
 */
static char *data;

static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != dht_handle)
  {
    GNUNET_DHT_disconnect (dht_handle);
    dht_handle = NULL;
  }
}

/**
 * Signature of the main function of a task.
 *
 * @param cls closure
 * @param success GNUNET_OK if the PUT was transmitted,
 *                GNUNET_NO on timeout,
 *                GNUNET_SYSERR on disconnect from service
 *                after the PUT message was transmitted
 *                (so we don't know if it was received or not)
 */
static void
message_sent_cont (void *cls, int success)
{
  if (verbose)
  {
    switch (success)
    {
    case GNUNET_OK:
      FPRINTF (stderr, "%s",  _("PUT request sent!\n"));
      break;
    case GNUNET_NO:
      FPRINTF (stderr, "%s",  _("Timeout sending PUT request!\n"));
      break;
    case GNUNET_SYSERR:
      FPRINTF (stderr, "%s",  _("PUT request not confirmed!\n"));
      break;
    default:
      GNUNET_break (0);
      break;
    }
  }
  GNUNET_SCHEDULER_add_now (&shutdown_task, NULL);
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
  struct GNUNET_TIME_Absolute expiration;
  GNUNET_HashCode key;

  cfg = c;

  if ((query_key == NULL) || (data == NULL))
  {
    FPRINTF (stderr, "%s",  _("Must provide KEY and DATA for DHT put!\n"));
    ret = 1;
    return;
  }

  dht_handle = GNUNET_DHT_connect (cfg, 1);
  if (dht_handle == NULL)
  {
    FPRINTF (stderr, _("Could not connect to %s service!\n"), "DHT");
    ret = 1;
    return;
  }
  else if (verbose)
    FPRINTF (stderr, _("Connected to %s service!\n"), "DHT");

  if (query_type == GNUNET_BLOCK_TYPE_ANY)      /* Type of data not set */
    query_type = GNUNET_BLOCK_TYPE_TEST;

  GNUNET_CRYPTO_hash (query_key, strlen (query_key), &key);

  timeout =
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, timeout_request);
  expiration =
      GNUNET_TIME_relative_to_absolute (GNUNET_TIME_relative_multiply
                                        (GNUNET_TIME_UNIT_SECONDS,
                                         expiration_seconds));

  if (verbose)
    FPRINTF (stderr, _("Issuing put request for `%s' with data `%s'!\n"),
             query_key, data);
  GNUNET_DHT_put (dht_handle, &key, replication, GNUNET_DHT_RO_NONE, query_type,
                  strlen (data), data, expiration, timeout, &message_sent_cont,
                  NULL);

}


/**
 * gnunet-dht-put command line options
 */
static struct GNUNET_GETOPT_CommandLineOption options[] = {
  {'d', "data", "DATA",
   gettext_noop ("the data to insert under the key"),
   1, &GNUNET_GETOPT_set_string, &data},
  {'e', "expiration", "EXPIRATION",
   gettext_noop ("how long to store this entry in the dht (in seconds)"),
   1, &GNUNET_GETOPT_set_ulong, &expiration_seconds},
  {'k', "key", "KEY",
   gettext_noop ("the query key"),
   1, &GNUNET_GETOPT_set_string, &query_key},
  {'r', "replication", "LEVEL",
   gettext_noop ("how many replicas to create"),
   1, &GNUNET_GETOPT_set_uint, &replication},
  {'t', "type", "TYPE",
   gettext_noop ("the type to insert data as"),
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
 * Entry point for gnunet-dht-put
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-dht-put",
                              gettext_noop
                              ("Issue a PUT request to the GNUnet DHT insert DATA under KEY."),
                              options, &run, NULL)) ? ret : 1;
}

/* end of gnunet-dht-put.c */
