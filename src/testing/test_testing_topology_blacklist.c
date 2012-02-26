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
 * @file testing/test_testing_topology_blacklist.c
 * @brief base testcase for testing transport level blacklisting
 */
#include "platform.h"
#include "gnunet_testing_lib.h"
#include "gnunet_core_service.h"

#define VERBOSE GNUNET_NO

/**
 * How long until we fail the whole testcase?
 */
#define TEST_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 600)

/**
 * How long until we give up on starting the peers? (Must be longer than the connect timeout!)
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 300)

#define DEFAULT_NUM_PEERS 4

#define MAX_OUTSTANDING_CONNECTIONS 300

static int ok;

struct GNUNET_TIME_Relative connect_timeout;

static unsigned long long connect_attempts;

static unsigned long long num_peers;

static unsigned int total_connections;

static unsigned int failed_connections;

static unsigned int expected_connections;

static unsigned int expected_failed_connections;

static unsigned long long peers_left;

static struct GNUNET_TESTING_PeerGroup *pg;

const struct GNUNET_CONFIGURATION_Handle *main_cfg;

GNUNET_SCHEDULER_TaskIdentifier die_task;

static char *dotOutFileName;

static FILE *dotOutFile;

static char *blacklist_transports;

static enum GNUNET_TESTING_Topology topology = GNUNET_TESTING_TOPOLOGY_CLIQUE;  /* Overlay should allow all connections */

static enum GNUNET_TESTING_Topology blacklist_topology = GNUNET_TESTING_TOPOLOGY_RING;  /* Blacklist underlay into a ring */

static enum GNUNET_TESTING_Topology connection_topology = GNUNET_TESTING_TOPOLOGY_NONE; /* NONE actually means connect all allowed peers */

static enum GNUNET_TESTING_TopologyOption connect_topology_option = GNUNET_TESTING_TOPOLOGY_OPTION_ALL; /* Try to connect all possible OVERLAY connections */

static double connect_topology_option_modifier = 0.0;

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
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Shutdown of peers failed!\n");
#endif
    if (ok == 0)
      ok = 666;
  }
  else
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "All peers successfully shut down!\n");
#endif
  }
}

static void
finish_testing ()
{
  GNUNET_assert (pg != NULL);

#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Called finish testing, stopping daemons.\n");
#endif
  sleep (1);
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Calling daemons_stop\n");
#endif
  GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "daemons_stop finished\n");
#endif
  if (dotOutFile != NULL)
  {
    FPRINTF (dotOutFile, "%s",  "}");
    FCLOSE (dotOutFile);
  }

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

  if (dotOutFile != NULL)
  {
    FPRINTF (dotOutFile, "%s",  "}");
    FCLOSE (dotOutFile);
  }
}



void
topology_callback (void *cls, const struct GNUNET_PeerIdentity *first,
                   const struct GNUNET_PeerIdentity *second, uint32_t distance,
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
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "connected peer %s to peer %s\n",
                first_daemon->shortname, second_daemon->shortname);
#endif
    if (dotOutFile != NULL)
      FPRINTF (dotOutFile, "\tn%s -- n%s;\n", first_daemon->shortname,
               second_daemon->shortname);
  }

  else
  {
    failed_connections++;
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Failed to connect peer %s to peer %s with error :\n%s\n",
                first_daemon->shortname, second_daemon->shortname, emsg);
#endif
  }


  if (total_connections == expected_connections)
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Created %d total connections, which is our target number (that's bad)!\n",
                total_connections);
#endif

    GNUNET_SCHEDULER_cancel (die_task);
    die_task = GNUNET_SCHEDULER_NO_TASK;
    die_task =
        GNUNET_SCHEDULER_add_now (&end_badly,
                                  "from topology_callback (too many successful connections)");
  }
  else if (total_connections + failed_connections == expected_connections)
  {
    if ((failed_connections == expected_failed_connections) &&
        (total_connections ==
         expected_connections - expected_failed_connections))
    {
      GNUNET_SCHEDULER_cancel (die_task);
      die_task = GNUNET_SCHEDULER_NO_TASK;
      die_task = GNUNET_SCHEDULER_add_now (&finish_testing, NULL);
    }
    else
    {
      GNUNET_SCHEDULER_cancel (die_task);
      die_task =
          GNUNET_SCHEDULER_add_now (&end_badly,
                                    "from topology_callback (wrong number of failed connections)");
    }
  }
  else
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Have %d total connections, %d failed connections, Want %d (failed) and %d (successful)\n",
                total_connections, failed_connections,
                expected_failed_connections,
                expected_connections - expected_failed_connections);
#endif
  }
}

static void
connect_topology ()
{
  expected_connections = -1;
  if ((pg != NULL) && (peers_left == 0))
  {
    expected_connections =
        GNUNET_TESTING_connect_topology (pg, connection_topology,
                                         connect_topology_option,
                                         connect_topology_option_modifier,
                                         connect_timeout, connect_attempts,
                                         NULL, NULL);
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Have %d expected connections\n",
                expected_connections);
#endif
  }

  GNUNET_SCHEDULER_cancel (die_task);
  if (expected_connections == GNUNET_SYSERR)
  {
    die_task =
        GNUNET_SCHEDULER_add_now (&end_badly,
                                  "from connect topology (bad return)");
  }

  die_task =
      GNUNET_SCHEDULER_add_delayed (TEST_TIMEOUT, &end_badly,
                                    "from connect topology (timeout)");
}

static void
create_topology ()
{
  peers_left = num_peers;       /* Reset counter */
  if (GNUNET_TESTING_create_topology
      (pg, topology, blacklist_topology, blacklist_transports) != GNUNET_SYSERR)
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Topology set up, now starting peers!\n");
#endif
    GNUNET_TESTING_daemons_continue_startup (pg);
  }
  else
  {
    GNUNET_SCHEDULER_cancel (die_task);
    die_task =
        GNUNET_SCHEDULER_add_now (&end_badly,
                                  "from create topology (bad return)");
  }
  GNUNET_SCHEDULER_cancel (die_task);
  die_task =
      GNUNET_SCHEDULER_add_delayed (TEST_TIMEOUT, &end_badly,
                                    "from continue startup (timeout)");
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
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Started daemon %llu out of %llu\n",
              (num_peers - peers_left) + 1, num_peers);
#endif
  peers_left--;
  if (peers_left == 0)
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "All %d daemons started, now creating topology!\n", num_peers);
#endif
    GNUNET_SCHEDULER_cancel (die_task);
    /* Set up task in case topology creation doesn't finish
     * within a reasonable amount of time */
    die_task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                      (GNUNET_TIME_UNIT_MINUTES, 5), &end_badly,
                                      "from peers_started_callback");
    connect_topology ();
    ok = 0;
  }
}

/**
 * Callback indicating that the hostkey was created for a peer.
 *
 * @param cls NULL
 * @param id the peer identity
 * @param d the daemon handle (pretty useless at this point, remove?)
 * @param emsg non-null on failure
 */
void
hostkey_callback (void *cls, const struct GNUNET_PeerIdentity *id,
                  struct GNUNET_TESTING_Daemon *d, const char *emsg)
{
  if (emsg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Hostkey callback received error: %s\n", emsg);
  }

#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Hostkey created for peer `%s'\n",
              GNUNET_i2s (id));
#endif
  peers_left--;
  if (peers_left == 0)
  {
#if VERBOSE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "All %d hostkeys created, now creating topology!\n", num_peers);
#endif
    GNUNET_SCHEDULER_cancel (die_task);
    /* Set up task in case topology creation doesn't finish
     * within a reasonable amount of time */
    die_task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                      (GNUNET_TIME_UNIT_MINUTES, 5), &end_badly,
                                      "from hostkey_callback");
    GNUNET_SCHEDULER_add_now (&create_topology, NULL);
    ok = 0;
  }
}

static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  unsigned long long topology_num;
  unsigned long long connect_topology_num;
  unsigned long long blacklist_topology_num;
  unsigned long long connect_topology_option_num;
  char *connect_topology_option_modifier_string;

  ok = 1;

  dotOutFile = FOPEN (dotOutFileName, "w");
  if (dotOutFile != NULL)
  {
    FPRINTF (dotOutFile, "%s",  "strict graph G {\n");
  }

#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting daemons based on config file %s\n", cfgfile);
#endif

  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "paths", "servicehome",
                                             &test_directory))
  {
    ok = 404;
    if (dotOutFile != NULL)
    {
      FCLOSE (dotOutFile);
    }
    return;
  }

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "testing", "topology",
                                             &topology_num))
    topology = topology_num;

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "testing", "connect_topology",
                                             &connect_topology_num))
    connection_topology = connect_topology_num;

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "testing",
                                             "connect_topology_option",
                                             &connect_topology_option_num))
    connect_topology_option = connect_topology_option_num;

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "testing",
                                             "connect_topology_option_modifier",
                                             &connect_topology_option_modifier_string))
  {
    if (sscanf
        (connect_topology_option_modifier_string, "%lf",
         &connect_topology_option_modifier) != 1)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _
                  ("Invalid value `%s' for option `%s' in section `%s': expected float\n"),
                  connect_topology_option_modifier_string,
                  "connect_topology_option_modifier", "TESTING");
      GNUNET_free (connect_topology_option_modifier_string);
      ok = 707;
      if (dotOutFile != NULL)
      {
        FCLOSE (dotOutFile);
      }
      return;
    }
    GNUNET_free (connect_topology_option_modifier_string);
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "testing",
                                             "blacklist_transports",
                                             &blacklist_transports))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "No transports specified for blacklisting in blacklist testcase (this shouldn't happen!)\n");
    ok = 808;
    if (dotOutFile != NULL)
    {
      FCLOSE (dotOutFile);
    }
    return;
  }

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "testing",
                                             "blacklist_topology",
                                             &blacklist_topology_num))
    blacklist_topology = blacklist_topology_num;

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "testing", "num_peers",
                                             &num_peers))
    num_peers = DEFAULT_NUM_PEERS;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (cfg, "testing", "CONNECT_TIMEOUT",
                                           &connect_timeout))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Must provide option %s:%s!\n",
                "testing", "CONNECT_TIMEOUT");
    return;
  }


  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "testing", "connect_attempts",
                                             &connect_attempts))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Must provide option %s:%s!\n",
                "testing", "connect_attempts");
    return;
  }

  main_cfg = cfg;

  GNUNET_assert (num_peers > 0 && num_peers < (unsigned int) -1);
  peers_left = num_peers;

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
                                     TIMEOUT, &hostkey_callback, NULL,
                                     &peers_started_callback, NULL,
                                     &topology_callback, NULL, NULL);

}

static int
check ()
{
  int ret;

  char *const argv[] = { "test-testing-topology-blacklist",
    "-c",
    "test_testing_data_topology_blacklist.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  ret =
      GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv,
                          "test-testing-topology-blacklist", "nohelp", options,
                          &run, &ok);
  if (ret != GNUNET_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "`test-testing-topology-blacklist': Failed with error code %d\n",
                ret);
  }

  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test_testing_topology_blacklist",
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

/* end of test_testing_topology_blacklist.c */
