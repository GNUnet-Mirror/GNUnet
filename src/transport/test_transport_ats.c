/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file testing/test_testing_group.c
 * @brief testcase for functions to connect peers in testing.c
 */
#include "platform.h"
#include "gnunet_testing_lib.h"
#include "gnunet_scheduler_lib.h"

#define VERBOSE GNUNET_YES

#define NUM_PEERS 4

#define DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * How long until we give up on connecting the peers?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 300)

static int ok;

static int peers_left;

static int failed_peers;

static struct GNUNET_TESTING_PeerGroup *pg;

static  GNUNET_SCHEDULER_TaskIdentifier task;


/**
 * Check whether peers successfully shut down.
 */
void
shutdown_callback (void *cls, const char *emsg)
{
  if (emsg != NULL)
    {
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Shutdown of peers failed!\n");
#endif
      if (ok == 0)
        ok = 666;
    }
  else
    {
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "All peers successfully shut down!\n");
#endif
    }
}

static void shutdown_peers()
{
    GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
}

void
delay_task (void *cls,
			  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
	task = GNUNET_SCHEDULER_NO_TASK;
	if ( (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
	    return;

#if VERBOSE
	GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Delay over\n");
#endif
	shutdown_peers ();
}

static void connect_peers()
{
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connecting peers!\n");

    task = GNUNET_SCHEDULER_add_delayed(DELAY, &delay_task, NULL);


    //GNUNET_TESTING_daemons_connect();
	//shutdown_peers();

}

static void
my_cb (void *cls,
       const struct GNUNET_PeerIdentity *id,
       const struct GNUNET_CONFIGURATION_Handle *cfg,
       struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  if (id == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Start callback called with error (too long starting peers), aborting test!\n");
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Error from testing: `%s'\n");
      failed_peers++;
      if (failed_peers == peers_left)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Too many peers failed, ending test!\n");
          ok = 1;
          GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
        }
      return;
    }

  peers_left--;
  if (peers_left == 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "All peers started successfully!\n");
      connect_peers();
      ok = 0;
    }
  else if (failed_peers == peers_left)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Too many peers failed, ending test!\n");
      GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
      ok = 1;
    }
}


static void
run (void *cls,
     char *const *args,
     const char *cfgfile, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  ok = 1;
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting %i peers.\n", NUM_PEERS);
#endif
  peers_left = NUM_PEERS;
  pg = GNUNET_TESTING_daemons_start (cfg,
                                     peers_left, /* Total number of peers */
                                     peers_left, /* Number of outstanding connections */
                                     peers_left, /* Number of parallel ssh connections, or peers being started at once */
                                     TIMEOUT,
                                     NULL, NULL,
                                     &my_cb, NULL, NULL, NULL, NULL);
  GNUNET_assert (pg != NULL);
}

static int
check ()
{
  char *const argv[] = { "test-testing",
    "-c",
    "test_testing_data.conf",
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
