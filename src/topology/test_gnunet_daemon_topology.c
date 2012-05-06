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
 * @file topology/test_gnunet_daemon_topology.c
 * @brief testcase for topology maintenance code
 */
#include "platform.h"
#include "gnunet_testing_lib.h"


#define NUM_PEERS 2

/**
 * How long until we give up on connecting the peers?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 600)

#define CONNECT_ATTEMPTS 3


static int ok;

static int peers_left;

static int connect_left;

static struct GNUNET_TESTING_PeerGroup *pg;

static struct GNUNET_TESTING_Daemon *first;

static struct GNUNET_TESTING_Daemon *last;

/**
 * Active connection attempt.
 */
struct GNUNET_TESTING_ConnectContext *cc[NUM_PEERS];

/**
 * Check whether peers successfully shut down.
 */
static void
shutdown_callback (void *cls, const char *emsg)
{
  if (emsg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Shutdown of peers failed!\n");
    if (ok == 0)
      ok = 666;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "All peers successfully shut down!\n");
  }
}


static void
clean_up_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  unsigned int i;

  for (i = 0; i < NUM_PEERS; i++)
  {
    if (NULL != cc[i])
    {
      GNUNET_TESTING_daemons_connect_cancel (cc[i]);
      cc[i] = NULL;
    }
  }
  GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
  ok = 0;
}


static void
notify_connect_complete (void *cls, const struct GNUNET_PeerIdentity *first,
                         const struct GNUNET_PeerIdentity *second,
                         unsigned int distance,
                         const struct GNUNET_CONFIGURATION_Handle *first_cfg,
                         const struct GNUNET_CONFIGURATION_Handle *second_cfg,
                         struct GNUNET_TESTING_Daemon *first_daemon,
                         struct GNUNET_TESTING_Daemon *second_daemon,
                         const char *emsg)
{
  struct GNUNET_TESTING_ConnectContext **cc = cls;
  unsigned int i;

  *cc = NULL;
  if (NULL != emsg)
  {
    FPRINTF (stderr, "Failed to connect two peers: %s\n", emsg);
    for (i = 0; i < NUM_PEERS; i++)
      if (NULL != cc[i])
      {
        GNUNET_TESTING_daemons_connect_cancel (cc[i]);
        cc[i] = NULL;
      }
    GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
    GNUNET_assert (0);
    return;
  }
  connect_left--;
  if (connect_left == 0)
  {
    /* FIXME: check that topology adds a few more links
     * in addition to those that were seeded */
    GNUNET_SCHEDULER_add_now (&clean_up_task, NULL);
  }
}


static void
my_cb (void *cls, const struct GNUNET_PeerIdentity *id,
       const struct GNUNET_CONFIGURATION_Handle *cfg,
       struct GNUNET_TESTING_Daemon *d, const char *emsg)
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
  cc[peers_left] =
      GNUNET_TESTING_daemons_connect (last, d, TIMEOUT, CONNECT_ATTEMPTS,
                                      GNUNET_YES, &notify_connect_complete,
                                      &cc[peers_left]);
  if (peers_left == 0)
  {
    /* close circle */
    cc[NUM_PEERS - 1] =
        GNUNET_TESTING_daemons_connect (d, first, TIMEOUT, CONNECT_ATTEMPTS,
                                        GNUNET_YES, &notify_connect_complete,
                                        &cc[NUM_PEERS - 1]);
  }
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  ok = 1;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting daemons.\n");
  peers_left = NUM_PEERS;
  pg = GNUNET_TESTING_daemons_start (cfg, peers_left, peers_left, peers_left,
                                     TIMEOUT, NULL, NULL, &my_cb, NULL, NULL,
                                     NULL, NULL);
  GNUNET_assert (pg != NULL);
}


static int
check ()
{
  char *const argv[] = {
    "test-gnunet-daemon-topology",
    "-c",
    "test_gnunet_daemon_topology_data.conf",
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv,
                      "test-gnunet-daemon-topology", "nohelp", options, &run,
                      &ok);
  return ok;
}


int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-gnunet-daemon-topology",
                    "WARNING",
                    NULL);
  ret = check ();
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-topology");
  return ret;
}

/* end of test_gnunet_daemon_topology.c */
