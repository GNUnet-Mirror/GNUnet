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
 * @file dht/test_dht_twopeer.c
 * @brief base testcase for testing DHT service with
 *        two running peers
 */
#include "platform.h"
#include "gnunet_testing_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_dht_service.h"

/* DEFINES */
#define VERBOSE GNUNET_YES

#define TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 5)

#define DEFAULT_NUM_PEERS 2

/* Structs */
/* ... */

/* Globals */
static char *test_directory;

static unsigned int expected_connections;

static unsigned long long peers_left;

static struct GNUNET_TESTING_PeerGroup *pg;

static struct GNUNET_SCHEDULER_Handle *sched;

static unsigned long long num_peers;

static unsigned int total_connections;

static unsigned int failed_connections;

GNUNET_SCHEDULER_TaskIdentifier die_task;

static int ok;

/**
 * Check whether peers successfully shut down.
 */
void shutdown_callback (void *cls,
                        const char *emsg)
{
  if (emsg != NULL)
    {
      if (ok == 0)
        ok = 2;
    }
}

static void
finish_testing (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  GNUNET_assert (pg != NULL);
  GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
  ok = 0;
}

static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  if (pg != NULL)
    GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
  ok = 1;
}

void
topology_callback (void *cls,
                   const struct GNUNET_PeerIdentity *first,
                   const struct GNUNET_PeerIdentity *second,
                   uint32_t distance,
                   const struct GNUNET_CONFIGURATION_Handle *first_cfg,
                   const struct GNUNET_CONFIGURATION_Handle *second_cfg,
                   struct GNUNET_TESTING_Daemon *first_daemon,
                   struct GNUNET_TESTING_Daemon *second_daemon,
                   const char *emsg)
{
  if (emsg == NULL)
    {
      total_connections++;
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "connected peer %s to peer %s, distance %u\n",
                 first_daemon->shortname,
                 second_daemon->shortname,
                 distance);
#endif
    }
#if VERBOSE
  else
    {
      failed_connections++;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Failed to connect peer %s to peer %s with error :\n%s\n",
                  first_daemon->shortname,
                  second_daemon->shortname, emsg);
    }
#endif

  if (total_connections == expected_connections)
    {
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Created %d total connections, which is our target number!  Starting next phase of testing.\n",
                  total_connections);
#endif
      GNUNET_SCHEDULER_cancel (sched, die_task);
      die_task = GNUNET_SCHEDULER_NO_TASK;
      //GNUNET_SCHEDULER_add_now (sched, &next_phase, NULL);
      GNUNET_SCHEDULER_add_now (sched, &finish_testing, NULL);
    }
  else if (total_connections + failed_connections == expected_connections)
    {
      GNUNET_SCHEDULER_cancel (sched, die_task);
      die_task = GNUNET_SCHEDULER_add_now (sched,
                                               &end_badly, "from topology_callback (too many failed connections)");
    }
  else
    {
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Have %d total connections, %d failed connections, Want %d\n",
                  total_connections, failed_connections, expected_connections);
#endif
    }
}

static void
connect_topology (void *cls, const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  expected_connections = -1;
  if ((pg != NULL) && (peers_left == 0))
    {
      expected_connections = GNUNET_TESTING_connect_topology (pg, GNUNET_TESTING_TOPOLOGY_CLIQUE, GNUNET_TESTING_TOPOLOGY_OPTION_ALL, 0.0);
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Have %d expected connections\n", expected_connections);
#endif
    }

  GNUNET_SCHEDULER_cancel (sched, die_task);
  if (expected_connections == GNUNET_SYSERR)
    {
      die_task = GNUNET_SCHEDULER_add_now (sched,
                                           &end_badly, "from connect topology (bad return)");
    }

  die_task = GNUNET_SCHEDULER_add_delayed (sched,
                                           TIMEOUT,
                                           &end_badly, "from connect topology (timeout)");
}

static void
peers_started_callback (void *cls,
       const struct GNUNET_PeerIdentity *id,
       const struct GNUNET_CONFIGURATION_Handle *cfg,
       struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  if (emsg != NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Failed to start daemon with error: `%s'\n",
                  emsg);
      return;
    }
  GNUNET_assert (id != NULL);
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Started daemon %llu out of %llu\n",
              (num_peers - peers_left) + 1, num_peers);
#endif

  //GNUNET_DHT_connect();
  peers_left--;

  if (peers_left == 0)
    {
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "All %d daemons started, now creating topology!\n",
                  num_peers);
#endif
      GNUNET_SCHEDULER_cancel (sched, die_task);
      /* Set up task in case topology creation doesn't finish
       * within a reasonable amount of time */
      die_task = GNUNET_SCHEDULER_add_delayed (sched,
                                               GNUNET_TIME_relative_multiply
                                               (GNUNET_TIME_UNIT_MINUTES, 5),
                                               &end_badly, "from peers_started_callback");

      GNUNET_SCHEDULER_add_now(sched, &connect_topology, NULL);
      ok = 0;
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

  if (GNUNET_YES != GNUNET_CONFIGURATION_get_value_string(cfg, "paths", "servicehome", &test_directory))
    {
      ok = 404;
      return;
    }

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "testing", "num_peers",
                                             &num_peers))
    num_peers = DEFAULT_NUM_PEERS;

  peers_left = num_peers;

  /* Set up a task to end testing if peer start fails */
  die_task = GNUNET_SCHEDULER_add_delayed (sched,
                                           TIMEOUT,
                                           &end_badly, "didn't start all daemons in reasonable amount of time!!!");

  pg = GNUNET_TESTING_daemons_start (sched, cfg,
                                     num_peers, TIMEOUT, NULL, NULL, &peers_started_callback, NULL,
                                     &topology_callback, NULL, NULL);

}

static int
check ()
{
  int ret;
  char *const argv[] = {"test-dht-twopeer",
    "-c",
    "test_dht_twopeer_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  ret = GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
                      argv, "test-dht-twopeer", "nohelp",
                      options, &run, &ok);
  if (ret != GNUNET_OK)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "`test-dht-twopeer': Failed with error code %d\n", ret);
    }
  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-dht-twopeer",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();
  /**
   * Need to remove base directory, subdirectories taken care
   * of by the testing framework.
   */
  if (GNUNET_DISK_directory_remove (test_directory) != GNUNET_OK)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Failed to remove testing directory %s\n", test_directory);
    }
  return ret;
}

/* end of test_dht_twopeer.c */
