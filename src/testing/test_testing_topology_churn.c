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
 * @file testing/test_testing_topology_churn.c
 * @brief base testcase for testing simple churn functionality
 */
#include "platform.h"
#include "gnunet_testing_lib.h"
#include "gnunet_core_service.h"


/**
 * How long until we fail the whole testcase?
 */
#define TEST_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 600)

/**
 * How long until we give up on starting the peers? (Must be longer than the connect timeout!)
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 300)

#define DEFAULT_NUM_PEERS 4

static int ok;

static unsigned long long num_peers;

static unsigned int expected_connections;

static unsigned int expected_failed_connections;

static unsigned long long peers_left;

static struct GNUNET_TESTING_PeerGroup *pg;

const struct GNUNET_CONFIGURATION_Handle *main_cfg;

GNUNET_SCHEDULER_TaskIdentifier die_task;

static char *test_directory;

#define MTYPE 12345

GNUNET_NETWORK_STRUCT_BEGIN

struct GNUNET_TestMessage
{
  /**
   * Header of the message
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this message.
   */
  uint32_t uid;
};
GNUNET_NETWORK_STRUCT_END

/**
 * Check whether peers successfully shut down.
 */
void
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
finish_testing ()
{
  GNUNET_assert (pg != NULL);

  if (die_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (die_task);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Called finish testing, stopping daemons.\n");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Calling daemons_stop\n");
  GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "daemons_stop finished\n");
  ok = 0;
}

static void
end_badly (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  char *msg = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "End badly was called (%s)... stopping daemons.\n", msg);

  if (pg != NULL)
  {
    GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
    ok = 7331;                  /* Opposite of leet */
  }
  else
    ok = 401;                   /* Never got peers started */

}

struct ChurnTestContext
{
  GNUNET_SCHEDULER_Task next_task;

};

static struct ChurnTestContext churn_ctx;

/**
 * Churn callback, report on success or failure of churn operation.
 *
 * @param cls closure
 * @param emsg NULL on success
 */
void
churn_callback (void *cls, const char *emsg)
{
  if (emsg == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Successfully churned peers!\n",
                emsg);
    GNUNET_SCHEDULER_add_now (churn_ctx.next_task, NULL);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Failed to churn peers with error `%s'\n", emsg);
    GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_add_now (&end_badly, NULL);
  }
}


static void
churn_peers_both ()
{
  churn_ctx.next_task = &finish_testing;
  GNUNET_TESTING_daemons_churn (pg, NULL, 1, 1, TIMEOUT, &churn_callback, NULL);
}

static void
churn_peers_off_again ()
{
  churn_ctx.next_task = &churn_peers_both;
  GNUNET_TESTING_daemons_churn (pg, NULL, 2, 0, TIMEOUT, &churn_callback, NULL);
}

static void
churn_peers_on ()
{
  churn_ctx.next_task = &churn_peers_off_again;
  GNUNET_TESTING_daemons_churn (pg, NULL, 0, 2, TIMEOUT, &churn_callback, NULL);
}

static void
churn_peers_off ()
{
  churn_ctx.next_task = &churn_peers_on;
  GNUNET_TESTING_daemons_churn (pg, NULL, 2, 0, TIMEOUT, &churn_callback, NULL);
}

static void
peers_started_callback (void *cls, const struct GNUNET_PeerIdentity *id,
                        const struct GNUNET_CONFIGURATION_Handle *cfg,
                        struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  if (emsg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Failed to start daemon with error: `%s'\n", emsg);
    return;
  }
  GNUNET_assert (id != NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Started daemon %llu out of %llu\n",
              (num_peers - peers_left) + 1, num_peers);
  peers_left--;
  if (peers_left == 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "All %d daemons started, now testing churn!\n", num_peers);
    GNUNET_SCHEDULER_cancel (die_task);
    /* Set up task in case topology creation doesn't finish
     * within a reasonable amount of time */
    die_task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                      (GNUNET_TIME_UNIT_MINUTES, 5), &end_badly,
                                      "from peers_started_callback");
    churn_peers_off ();
    ok = 0;
  }
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  ok = 1;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting daemons based on config file %s\n", cfgfile);
  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "paths", "servicehome",
                                             &test_directory))
  {
    ok = 404;
    return;
  }

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "testing", "num_peers",
                                             &num_peers))
    num_peers = DEFAULT_NUM_PEERS;

  main_cfg = cfg;

  peers_left = num_peers;
  GNUNET_assert (num_peers > 0 && num_peers < (unsigned int) -1);

  /* For this specific test we only really want a CLIQUE topology as the
   * overlay allowed topology, and a RING topology as the underlying connection
   * allowed topology.  So we will expect only num_peers * 2 connections to
   * work, and (num_peers * (num_peers - 1)) - (num_peers * 2) to fail.
   */
  expected_connections = num_peers * (num_peers - 1);
  expected_failed_connections = expected_connections - (num_peers * 2);


  /* Set up a task to end testing if peer start fails */
  die_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_MINUTES, 5), &end_badly,
                                    "didn't start all daemons in reasonable amount of time!!!");

  pg = GNUNET_TESTING_daemons_start (cfg, peers_left, peers_left, peers_left,
                                     TIMEOUT, NULL, NULL,
                                     &peers_started_callback, NULL, NULL, NULL,
                                     NULL);

}

static int
check ()
{
  int ret;

  char *const argv[] = { "test-testing-topology-churn",
    "-c",
    "test_testing_data_topology_churn.conf",
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  ret =
      GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv,
                          "test-testing-topology-churn", "nohelp", options,
                          &run, &ok);
  if (ret != GNUNET_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "`test-testing-topology-churn': Failed with error code %d\n",
                ret);
  }

  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test_testing_topology_churn",
                    "WARNING",
                    NULL);
  ret = check ();

  /**
   * Need to remove base directory, subdirectories taken care
   * of by the testing framework.
   */
  if (test_directory != NULL)
  {
    if (GNUNET_DISK_directory_remove (test_directory) != GNUNET_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Failed to remove testing directory %s\n", test_directory);
    }
  }

  return ret;
}

/* end of test_testing_topology_churn.c */
