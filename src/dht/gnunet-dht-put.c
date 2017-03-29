/*
     This file is part of GNUnet.
     Copyright (C) 2001, 2002, 2004, 2005, 2006, 2007, 2009, 2017 GNUnet e.V.

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
 * The key used in the DHT
 */
struct GNUNET_HashCode key;

/**
 * The key for the query
 */
static char *query_key;

/**
 * User supplied expiration value
 */
static struct GNUNET_TIME_Relative expiration;

/**
 * Desired replication level.
 */
static unsigned int replication = 5;

/**
 * Be verbose
 */
static unsigned int verbose;

/**
 * Use #GNUNET_DHT_DEMULTIPLEX_EVERYWHERE.
 */
static int demultixplex_everywhere;

/**
 * Use #GNUNET_DHT_RO_RECORD_ROUTE.
 */
static int record_route;

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
shutdown_task (void *cls)
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
 * @param success #GNUNET_OK if the PUT was transmitted,
 *                #GNUNET_NO on timeout,
 *                #GNUNET_SYSERR on disconnect from service
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
      FPRINTF (stderr, "%s `%s'!\n",  _("PUT request sent with key"), GNUNET_h2s_full(&key));
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
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  enum GNUNET_DHT_RouteOption ro;

  cfg = c;
  if ((NULL == query_key) || (NULL == data))
  {
    FPRINTF (stderr, "%s",  _("Must provide KEY and DATA for DHT put!\n"));
    ret = 1;
    return;
  }

  if (NULL == (dht_handle = GNUNET_DHT_connect (cfg, 1)))
  {
    FPRINTF (stderr, _("Could not connect to %s service!\n"), "DHT");
    ret = 1;
    return;
  }
  if (GNUNET_BLOCK_TYPE_ANY == query_type)      /* Type of data not set */
    query_type = GNUNET_BLOCK_TYPE_TEST;

  GNUNET_CRYPTO_hash (query_key, strlen (query_key), &key);

  if (verbose)
    FPRINTF (stderr,
             _("Issuing put request for `%s' with data `%s'!\n"),
             query_key,
             data);
  ro = GNUNET_DHT_RO_NONE;
  if (demultixplex_everywhere)
    ro |= GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE;
  if (record_route)
    ro |= GNUNET_DHT_RO_RECORD_ROUTE;
  GNUNET_DHT_put (dht_handle,
                  &key,
                  replication,
                  ro,
                  query_type,
                  strlen (data),
                  data,
                  GNUNET_TIME_relative_to_absolute (expiration),
                  &message_sent_cont,
                  NULL);
}

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

  struct GNUNET_GETOPT_CommandLineOption options[] = {
  
    GNUNET_GETOPT_option_string ('d',
                                 "data",
                                 "DATA",
                                 gettext_noop ("the data to insert under the key"),
                                 &data),
  
    GNUNET_GETOPT_option_relative_time ('e',
                                            "expiration",
                                            "EXPIRATION",
                                            gettext_noop ("how long to store this entry in the dht (in seconds)"),
                                            &expiration),
  
    GNUNET_GETOPT_option_string ('k',
                                 "key",
                                 "KEY",
                                 gettext_noop ("the query key"),
                                 &query_key),
  
    GNUNET_GETOPT_option_flag ('x',
                                  "demultiplex",
                                  gettext_noop ("use DHT's demultiplex everywhere option"),
                                  &demultixplex_everywhere),
  
    GNUNET_GETOPT_option_uint ('r',
                                   "replication",
                                   "LEVEL",
                                   gettext_noop ("how many replicas to create"),
                                   &replication),
  
    GNUNET_GETOPT_option_flag ('R',
                                  "record",
                                  gettext_noop ("use DHT's record route option"),
                                  &record_route),
  
    GNUNET_GETOPT_option_uint ('t',
                                   "type",
                                   "TYPE",
                                   gettext_noop ("the type to insert data as"),
                                   &query_type),
  
    GNUNET_GETOPT_option_verbose (&verbose),
  
    GNUNET_GETOPT_OPTION_END
  };


  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv,
                                                 &argc, &argv))
    return 2;
  expiration = GNUNET_TIME_UNIT_HOURS;
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc,
                              argv,
                              "gnunet-dht-put",
                              gettext_noop
                              ("Issue a PUT request to the GNUnet DHT insert DATA under KEY."),
                              options,
                              &run,
                              NULL))
    ? ret : 1;
}

/* end of gnunet-dht-put.c */
