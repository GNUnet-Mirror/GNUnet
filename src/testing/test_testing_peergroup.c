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
 * @file testing/test_testing_peergroup.c
 * @brief testcase for functions to connect peers in testing_peergroup.c
 */
#include "platform.h"
#include "gnunet_testing_lib.h"

#define VERBOSE GNUNET_NO

#define NUM_PEERS 4

/**
 * How long until we give up on connecting the peers?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 300)

static int ok;

static int peers_left;

static struct GNUNET_TESTING_PeerGroup *pg;

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
    ok = 0;
  }
}


static void
my_cb (void *cls, const char *emsg)
{
  if (emsg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Peergroup callback called with error, aborting test!\n");
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Error from testing: `%s'\n");
    ok = 1;
    GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer Group started successfully, ending test!\n");
  /**
   * If something is to actually be DONE with the testcase, it should
   * be put in here.  Usually there will be a struct declared (or global
   * variables can be used) to keep track of the state, statistics,
   * handles to peers, etc.  The example here is the opaque "TestCaseData"
   * struct that could be passed into a function "additional_code_for_testing"
   * which can be used to perform actions on the peers in the peergroup.
   * Also, the GNUNET_TESTING_daemons_stop call would need to be removed,
   * and only called once all of the testing is complete.
   */

  /**
   * struct TestcaseData *state_closure;
   * GNUNET_SCHEDULER_add_now(&additional_code_for_testing, state_closure);
   */

  GNUNET_TESTING_daemons_stop (pg, TIMEOUT, &shutdown_callback, NULL);
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_CONFIGURATION_Handle *testing_cfg;

  ok = 1;
  testing_cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_assert (GNUNET_OK == GNUNET_CONFIGURATION_load (testing_cfg, cfgfile));
#if VERBOSE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting daemons.\n");
  GNUNET_CONFIGURATION_set_value_string (testing_cfg, "testing",
                                         "use_progressbars", "YES");
#endif
  peers_left = NUM_PEERS;
  pg = GNUNET_TESTING_peergroup_start (testing_cfg, peers_left, TIMEOUT, NULL,
                                       &my_cb, NULL, NULL);
  GNUNET_assert (pg != NULL);
}

static int
check ()
{
  char *const argv[] = { "test-testing-peergroup",
    "-c",
    "test_testing_peergroup_data.conf",
#if VERBOSE
    "-L", "DEBUG",
#endif
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  GNUNET_PROGRAM_run ((sizeof (argv) / sizeof (char *)) - 1, argv,
                      "test-testing-peergroup", "nohelp", options, &run, &ok);
  return ok;
}

int
main (int argc, char *argv[])
{
  int ret;

  GNUNET_log_setup ("test-testing-peergroup",
#if VERBOSE
                    "DEBUG",
#else
                    "WARNING",
#endif
                    NULL);
  ret = check ();
  GNUNET_DISK_directory_remove ("/tmp/test-gnunet-testing");
  return ret;
}

/* end of test_testing_peergroup.c */
