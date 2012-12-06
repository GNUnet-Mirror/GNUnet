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
 * @file fs/gnunet-fs-profiler.c
 * @brief tool to benchmark/profile file-sharing 
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"

/**
 * Final status code.
 */
static int ret;

/**
 * Data file with the hosts for the testbed.
 */
static char *host_filename;

/**
 * Number of peers to run in the experiment.
 */
static unsigned int num_peers;


/**
 * The testbed has been started, now begin the experiment.
 *
 * @param cls configuration handle
 * @param tc scheduler context
 */ 
static void
master_task (void *cls,
	     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  // const struct GNUNET_CONFIGURATION_Handle *cfg = cls;

  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_TESTBED_run (host_filename,
		      cfg,
		      num_peers,
		      0, NULL, NULL,
		      &master_task, (void *) cfg);
}


/**
 * Program to run a file-sharing testbed.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'n', "num-peers", "COUNT",
     gettext_noop ("run the experiment with COUNT peers"),
     1, &GNUNET_GETOPT_set_uint, &num_peers},
    {'t', "testbed", "HOSTFILE",
     gettext_noop ("specifies name of a file with the HOSTS the testbed should use"),
     1, &GNUNET_GETOPT_set_string, &host_filename},

    GNUNET_GETOPT_OPTION_END
  };
  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  ret = (GNUNET_OK ==
	 GNUNET_PROGRAM_run (argc, argv, "gnunet-fs-profiler",
			     gettext_noop ("run a testbed to measure file-sharing performance"), options, &run,
			     NULL)) ? ret : 1;
  GNUNET_free ((void*) argv);
  return ret;
}

/* end of gnunet-fs-profiler.c */
