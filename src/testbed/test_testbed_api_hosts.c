/*
      This file is part of GNUnet
      (C) 2008--2012 Christian Grothoff (and other contributing authors)

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
 * @file testbed/test_testbed_api_hosts.c
 * @brief tests cases for testbed_api_hosts.c
 * @author Sree Harsha Totakura
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"
#include "testbed_api_hosts.h"


#define TIME_REL_SECS(sec)						\
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, sec)

/**
 * Host we are creating and using
 */
static struct GNUNET_TESTBED_Host *host;

/**
 * An array of hosts which are loaded from a file
 */
static struct GNUNET_TESTBED_Host **hosts;

/**
 * Number of hosts in the above list
 */
static unsigned int num_hosts;

/**
 * Global test status
 */
static int status;

/**
 * Shutdown task identifier
 */
GNUNET_SCHEDULER_TaskIdentifier shutdown_id;

/**
 * The shutdown task
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_TESTBED_host_destroy (host);
  while (0 != num_hosts)
  {
    GNUNET_TESTBED_host_destroy (hosts[num_hosts - 1]);
    num_hosts--;
  }
  GNUNET_free (hosts);
}


/**
 * Main run function.
 *
 * @param cls NULL
 * @param args arguments passed to GNUNET_PROGRAM_run
 * @param cfgfile the path to configuration file
 * @param cfg the configuration file handle
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  host = GNUNET_TESTBED_host_create ("localhost", NULL, 0);
  GNUNET_assert (NULL != host);
  GNUNET_assert (0 != GNUNET_TESTBED_host_get_id_ (host));
  GNUNET_TESTBED_host_destroy (host);
  host = GNUNET_TESTBED_host_create (NULL, NULL, 0);
  GNUNET_assert (NULL != host);
  GNUNET_assert (0 == GNUNET_TESTBED_host_get_id_ (host));
  GNUNET_assert (host == GNUNET_TESTBED_host_lookup_by_id_ (0));
  hosts = NULL;
  num_hosts = GNUNET_TESTBED_hosts_load_from_file ("sample_hosts.txt", &hosts);
  GNUNET_assert (15 == num_hosts);
  GNUNET_assert (NULL != hosts);
  status = GNUNET_YES;
  shutdown_id =
      GNUNET_SCHEDULER_add_delayed (TIME_REL_SECS (2), &do_shutdown, NULL);
}


int
main (int argc, char **argv)
{
  char *const argv2[] = { "test_testbed_api_hosts",
    "-c", "test_testbed_api.conf",
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  status = GNUNET_SYSERR;
  if (GNUNET_OK !=
      GNUNET_PROGRAM_run ((sizeof (argv2) / sizeof (char *)) - 1, argv2,
                          "test_testbed_api_hosts", "nohelp", options, &run,
                          NULL))
    return 1;
  return (GNUNET_OK == status) ? 0 : 1;
}

/* end of test_testbed_api_hosts.c */
