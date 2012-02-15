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
 * @file gns/gnunet-gns-add.c
 * @brief search for data in GNS
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_gns_service.h"

/**
 * The type of the record
 */
static unsigned int record_type;

/**
 * The key for the recprd
 */
static char *record_key;

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
 * Handle to the GNS
 */
static struct GNUNET_GNS_Handle *gns_handle;


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
  if (gns_handle != NULL)
  {
    GNUNET_GNS_disconnect (gns_handle);
    gns_handle = NULL;
  }
}

/**
 * Signature of the main function of a task.
 *
 * @param cls closure
 * @param tc context information (why was this task triggered now)
 */
void
message_sent_cont (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (verbose)
    FPRINTF (stderr, "%s",  _("PUT request sent!\n"));
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

  cfg = c;

  if ((record_key == NULL) || (data == NULL))
  {
    FPRINTF (stderr, "%s",  _("Must provide KEY and DATA for GNS record!\n"));
    ret = 1;
    return;
  }

  gns_handle = GNUNET_GNS_connect (cfg, 1);
  if (gns_handle == NULL)
  {
    FPRINTF (stderr, _("Could not connect to %s service!\n"), "GNS");
    ret = 1;
    return;
  }
  else if (verbose)
    FPRINTF (stderr, _("Connected to %s service!\n"), "GNS");

  if (query_type == GNUNET_BLOCK_TYPE_ANY)      /* Type of data not set */
    query_type = GNUNET_BLOCK_TYPE_TEST;

  timeout =
      GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, timeout_request);
  expiration =
      GNUNET_TIME_relative_to_absolute (GNUNET_TIME_relative_multiply
                                        (GNUNET_TIME_UNIT_SECONDS,
                                         expiration_seconds));

  if (verbose)
    FPRINTF (stderr, _("Issuing add request for `%s' with data `%s'!\n"),
             record_key, data);
  GNUNET_GNS_add (gns_handle, &record_key, replication, GNUNET_DHT_RO_NONE, record_type,
                  strlen (data), data, expiration, timeout, &message_sent_cont,
                  NULL);

}


/**
 * gnunet-gns-add command line options
 */
static struct GNUNET_GETOPT_CommandLineOption options[] = {
  {'d', "data", "DATA",
   gettext_noop ("the data to insert under the key"),
   1, &GNUNET_GETOPT_set_string, &data},
  {'e', "expiration", "EXPIRATION",
   gettext_noop ("how long to store this entry in the GNS (in seconds)"),
   1, &GNUNET_GETOPT_set_ulong, &expiration_seconds},
  {'k', "key", "KEY",
   gettext_noop ("the record key"),
   1, &GNUNET_GETOPT_set_string, &record_key},
  {'r', "replication", "LEVEL",
   gettext_noop ("how many replicas to create"),
   1, &GNUNET_GETOPT_set_uint, &replication},
  {'t', "type", "TYPE",
   gettext_noop ("the type to insert record as"),
   1, &GNUNET_GETOPT_set_uint, &record_type},
  {'T', "timeout", "TIMEOUT",
   gettext_noop ("how long to execute this query before giving up?"),
   1, &GNUNET_GETOPT_set_ulong, &timeout_request},
  {'V', "verbose", NULL,
   gettext_noop ("be verbose (print progress information)"),
   0, &GNUNET_GETOPT_set_one, &verbose},
  GNUNET_GETOPT_OPTION_END
};


/**
 * Entry point for gnunet-gns-add
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "gnunet-gns-add",
                              gettext_noop
                              ("Issue an add to the GNUnet NS of DATA under KEY."),
                              options, &run, NULL)) ? ret : 1;
}

/* end of gnunet-gns-put.c */
