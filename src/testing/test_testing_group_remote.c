/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file testing/test_testing_group_remote.c
 * @brief testcase for testing remote and local starting and connecting
 *        of hosts from the testing library.  The test_testing_data_remote.conf
 *        file should be modified if this testcase is intended to be used.
 */
#include "platform.h"
#include "gnunet_testing_lib.h"

#define VERBOSE GNUNET_YES


/**
 * How long until we give up on connecting the peers?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 300)

#define DEFAULT_NUM_PEERS 8;

static int ok;

static int peers_left;

static int peers_failed;

static struct GNUNET_TESTING_PeerGroup *pg;

static struct GNUNET_SCHEDULER_Handle *sched;

static unsigned long long num_peers;

static char *hostnames;


static void
my_cb (void *cls,
       const struct GNUNET_PeerIdentity *id,
       const struct GNUNET_CONFIGURATION_Handle *cfg,
       struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  if (emsg != NULL)
    {
      peers_failed++;
    }

  peers_left--;
  if (peers_left == 0)
    {
      GNUNET_TESTING_daemons_stop (pg, TIMEOUT);
      ok = 0;
    }
  else if (failed_peers == peers_left)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Too many peers failed, ending test!\n");
      GNUNET_TESTING_daemons_stop (pg, TIMEOUT);
    }
}


static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *s,
     char *const *args,
     const char *cfgfile, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  sched = s;
  ok = 1;
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting daemons.\n");
#endif

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "testing", "num_peers",
                                             &num_peers))
    num_peers = DEFAULT_NUM_PEERS;

  GNUNET_CONFIGURATION_get_value_string (cfg, "testing", "hosts",
                                         &hostnames);

  peers_left = num_peers;
  pg = GNUNET_TESTING_daemons_start (sched, cfg,
                                     peers_left,
                                     TIMEOUT,
                                     &my_cb, NULL, NULL, NULL, hostnames);
  GNUNET_assert (pg != NULL);
}

static int
check ()
{
  char *const argv[] = { "test-testing",
    "-c",
    "test_testing_data_remote.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
                      argv, "test-testing-group", "nohelp",
                      options, &run, &ok);
  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-testing-group",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();
  /**
   * Still need to remove the base testing directory here,
   * because group starts will create subdirectories under this
   * main dir.  However, we no longer need to sleep, as the
   * shutdown sequence won't return until everything is cleaned
   * up.
   */
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-testing");
  return ret;
}

/* end of test_testing_group.c */
