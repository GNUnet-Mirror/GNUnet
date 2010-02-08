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
 * @file testing/test_testing_group.c
 * @brief testcase for functions to connect two peers in testing.c
 */
#include "platform.h"
#include "gnunet_testing_lib.h"

#define VERBOSE GNUNET_NO


/**
 * How long until we give up on connecting the peers?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)

#define DEFAULT_NUM_PEERS 4;

static int ok;

static unsigned long long num_peers;

static int total_connections;

static int peers_left;

static struct GNUNET_TESTING_PeerGroup *pg;

static struct GNUNET_SCHEDULER_Handle *sched;

const struct GNUNET_CONFIGURATION_Handle *main_cfg;

GNUNET_SCHEDULER_TaskIdentifier die_task;


static void
finish_testing ()
{
  GNUNET_assert (pg != NULL);
  GNUNET_TESTING_daemons_stop (pg);
  ok = 0;
}


void
topology_callback (void *cls,
                   const struct GNUNET_PeerIdentity *first,
                   const struct GNUNET_PeerIdentity *second,
                   const struct GNUNET_CONFIGURATION_Handle *first_cfg,
                   const struct GNUNET_CONFIGURATION_Handle *second_cfg,
                   struct GNUNET_TESTING_Daemon *first_daemon,
                   struct GNUNET_TESTING_Daemon *second_daemon,
                   const char *emsg)
{
  /* Keep track of connections here if the client needs to know?
   * Still, we have no real handle to say the i'th peer of the peer group
   * even though we know that X peers exist in i...  But we may want to
   * know about the peer for logging purposes here (I'm sure we will actually
   * so the API may need changed).  Question, should the API expose what
   * a peer group is, or provide convenience/accessor functions? */
  if (emsg == NULL)
    {
      total_connections++;
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "connected peer %s to peer %s\n",
               GNUNET_TESTING_daemon_get_shortname (first_daemon),
               GNUNET_TESTING_daemon_get_shortname (second_daemon));
#endif
    }
#if VERBOSE
  else
    {

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Failed to connect peer %s to peer %s with error %s\n",
               GNUNET_TESTING_daemon_get_shortname (first_daemon),
               GNUNET_TESTING_daemon_get_shortname (second_daemon), emsg);
    }
#endif

  if (total_connections * 2 == num_peers * (num_peers - 1))
    {
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Created %d total connections, which is our target number!  Ending test.\n",
                  total_connections * 2);
#endif
      GNUNET_SCHEDULER_cancel (sched, die_task);
      finish_testing ();
    }
  else
    {
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Have %d total connections, Need %d\n",
                  total_connections * 2, num_peers * (num_peers - 1));
#endif
    }
}


static void
end_badly ()
{
  GNUNET_SCHEDULER_cancel (sched, die_task);
  if (pg != NULL)
    {
      GNUNET_TESTING_daemons_stop (pg);
      ok = 7331;                /* Opposite of leet */
    }
  else
    ok = 401;                   /* Never got peers started */
}


static void
create_topology ()
{
  int expected_connections;     /* Is there any way we can use this to check
                                   how many connections we are expecting to
                                   finish the topology?  It would be nice so
                                   that we could estimate completion time,
                                   but since GNUNET_TESTING_create_topology
                                   goes off and starts connecting we may get
                                   the topology callback before we have
                                   finished and not know how many!  We could
                                   just never touch expected_connections,
                                   and if we get called back when it's still
                                   0 then we know we can't believe it.  I
                                   don't like this though, because it may
                                   technically be possible for all connections
                                   to have been created and the callback
                                   called without us setting
                                   expected_connections!  Other options are
                                   doing a trial connection setup, or
                                   calculating the number of connections.
                                   Problem with calculating is that for random
                                   topologies this isn't reliable.  Problem
                                   with counting is we then iterate over them
                                   twice instead of once.  Probably the best
                                   option though.  Grr, also doing trial
                                   connection set up means we need to call
                                   fake_topology_create and then
                                   real_topology_create which is also ugly.
                                   Then we need to maintain state inside pg as
                                   well, which I was trying to avoid. */

  if ((pg != NULL) && (peers_left == 0))
    {
      /* create_topology will read the topology information from
         the config already contained in the peer group, so should
         we have create_topology called from start peers?  I think
         maybe this way is best so that the client can know both
         when peers are started, and when they are connected.
       */
      expected_connections = GNUNET_TESTING_create_topology (pg);
#if VERBOSE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Have %d expected connections\n", expected_connections);
#endif
    }

  GNUNET_SCHEDULER_cancel (sched, die_task);

  die_task = GNUNET_SCHEDULER_add_delayed (sched,
                                           GNUNET_TIME_relative_multiply
                                           (GNUNET_TIME_UNIT_SECONDS, 20),
                                           &finish_testing, NULL);
}


static void
my_cb (void *cls,
       const struct GNUNET_PeerIdentity *id,
       const struct GNUNET_CONFIGURATION_Handle *cfg,
       struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  GNUNET_assert (id != NULL);
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Started daemon %d out of %d\n",
              (num_peers - peers_left) + 1, num_peers);
#endif
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
                                               &end_badly, NULL);
      create_topology ();
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
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting daemons based on config file %s\n", cfgfile);
#endif
  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "testing", "num_peers",
                                             &num_peers))
    num_peers = DEFAULT_NUM_PEERS;

  main_cfg = cfg;

  peers_left = num_peers;

  /* Set up a task to end testing if peer start fails */
  die_task = GNUNET_SCHEDULER_add_delayed (sched,
                                           GNUNET_TIME_relative_multiply
                                           (GNUNET_TIME_UNIT_MINUTES, 5),
                                           &end_badly, NULL);

  pg = GNUNET_TESTING_daemons_start (sched, cfg,
                                     peers_left, &my_cb, NULL,
                                     &topology_callback, NULL, NULL);

  /*
     if (ret != GNUNET_SYSERR)
     ret = send_test_messages (pg);
   */

}

static int
check ()
{
  char *const argv[] = { "test-testing-topology",
    "-c",
    "test_testing_data_topology_clique.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1,
                      argv, "test-testing-topology", "nohelp",
                      options, &run, &ok);
  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-testing-topology_clique",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();
  sleep (1);
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-testing");
  return ret;
}

/* end of test_testing_group.c */
