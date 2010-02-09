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
 * @file topology/test_gnunet_service_topology.c
 * @brief testcase for topology maintenance code
 */
#include "platform.h"
#include "gnunet_testing_lib.h"

#define VERBOSE GNUNET_YES

#define NUM_PEERS 2

/**
 * How long until we give up on connecting the peers?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)


static int ok;

static int peers_left;

static int connect_left;

static struct GNUNET_TESTING_PeerGroup *pg;

static struct GNUNET_TESTING_Daemon *first;

static struct GNUNET_TESTING_Daemon *last;

static struct GNUNET_SCHEDULER_Handle *sched;


static void
clean_up_task (void *cls,
		 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_TESTING_daemons_stop (pg);
  ok = 0;     
}


static void 
notify_connect_complete(void *cls,
                        const struct GNUNET_PeerIdentity *first,
                        const struct GNUNET_PeerIdentity *second,
                        const struct GNUNET_CONFIGURATION_Handle *first_cfg,
                        const struct GNUNET_CONFIGURATION_Handle *second_cfg,
                        struct GNUNET_TESTING_Daemon *first_daemon,
                        struct GNUNET_TESTING_Daemon *second_daemon,
                        const char *emsg)
{
  if (NULL != emsg)
    {
      fprintf (stderr,
	       "Failed to connect two peers: %s\n",
	       emsg);
      GNUNET_assert (0);
      return;
    }
  connect_left--;
  if (connect_left == 0)
    {
      /* FIXME: check that topology adds a few more links
	 in addition to those that were seeded */
      /* For now, sleep so we can have the daemon do some work */
      GNUNET_SCHEDULER_add_delayed (sched,
				    GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5),
				    &clean_up_task,
				    NULL);
    }
}


static void my_cb(void *cls,
		   const struct GNUNET_PeerIdentity *id,
		   const struct GNUNET_CONFIGURATION_Handle *cfg,
		   struct GNUNET_TESTING_Daemon *d,
		   const char *emsg)
{
  GNUNET_assert (id != NULL);
  peers_left--;  
  if (first == NULL)
    {
      connect_left = NUM_PEERS;
      first = d;
      last = d;
      return;
    }
  GNUNET_TESTING_daemons_connect (last, d, TIMEOUT,
				  &notify_connect_complete,
				  NULL);
  if (peers_left == 0)
    {
      /* close circle */
      GNUNET_TESTING_daemons_connect (d, first, TIMEOUT,
				      &notify_connect_complete,
				      NULL);
    }
}


static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *s,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  sched = s;
  ok = 1;
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Starting daemons.\n");
#endif
  peers_left = NUM_PEERS;
  pg = GNUNET_TESTING_daemons_start (sched, cfg, 
				     peers_left,
				     &my_cb, NULL, NULL, NULL, NULL);
  GNUNET_assert (pg != NULL);
}

static int
check ()
{
  char *const argv[] = { "test-testing",
    "-c",
    "test_gnunet_service_topology_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
                      argv, "test-gnunet-service-topology", "nohelp",
                      options, &run, &ok);
  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-gnunet-service-topology",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();
  sleep (1); /* FIXME: needed? */
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-topology");
  return ret;
}

/* end of test_gnunet_service_topology.c */
