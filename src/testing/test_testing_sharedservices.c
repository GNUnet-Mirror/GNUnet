/*
      This file is part of GNUnet
      Copyright (C) 2008, 2009, 2012 Christian Grothoff (and other contributing authors)

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
 * @file testing/test_testing_sharedservices.c
 * @brief test case for testing service sharing among peers started by testing
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"

#define LOG(kind,...)                           \
  GNUNET_log (kind, __VA_ARGS__)

#define NUM_PEERS 4

/**
 * The status of the test
 */
int status;

/**
 * The testing context
 */
struct TestingContext
{
  /**
   * The testing system
   */
  struct GNUNET_TESTING_System *system;

  /**
   * The peer which has been started by the testing system
   */
  struct GNUNET_TESTING_Peer *peers[NUM_PEERS];

  /**
   * The running configuration of the peer
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;
};


/**
 * Task for shutdown
 *
 * @param cls the testing context
 * @param tc the tast context
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct TestingContext *test_ctx = cls;
  struct GNUNET_TESTING_Peer *peer;
  unsigned int cnt;

  GNUNET_assert (NULL != test_ctx);
  for (cnt = 0; cnt < NUM_PEERS; cnt++)
  {
    peer = test_ctx->peers[cnt];
    if (NULL == peer)
      continue;
    (void) GNUNET_TESTING_peer_stop (peer);
    GNUNET_TESTING_peer_destroy (peer);
  }
  if (NULL != test_ctx->cfg)
    GNUNET_CONFIGURATION_destroy (test_ctx->cfg);
  if (NULL != test_ctx->system)
    GNUNET_TESTING_system_destroy (test_ctx->system, GNUNET_YES);
  GNUNET_free (test_ctx);
}


/**
 * Main point of test execution
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct TestingContext *test_ctx;
  char *emsg;
  struct GNUNET_PeerIdentity id;
  struct GNUNET_TESTING_SharedService ss[] = {
    {"peerinfo", cfg, 2},
    {NULL, NULL, 0}
  };
  struct GNUNET_TESTING_Peer *peer;
  unsigned int cnt;

  test_ctx = GNUNET_new (struct TestingContext);
  test_ctx->system =
      GNUNET_TESTING_system_create ("test-gnunet-testing",
                                    "127.0.0.1", NULL, ss);
  emsg = NULL;
  if (NULL == test_ctx->system)
    goto end;
  test_ctx->cfg = GNUNET_CONFIGURATION_dup (cfg);
  for (cnt = 0; cnt < NUM_PEERS; cnt++)
  {
    peer = GNUNET_TESTING_peer_configure (test_ctx->system,
                                          test_ctx->cfg,
                                          0, &id, &emsg);
    if (NULL == peer)
    {
      if (NULL != emsg)
        printf ("Test failed upon error: %s", emsg);
      goto end;
    }
    if (GNUNET_OK != GNUNET_TESTING_peer_start (peer))
    {
      GNUNET_TESTING_peer_destroy (peer);
      goto end;
    }
    test_ctx->peers[cnt] = peer;
  }
  status = GNUNET_OK;
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                &do_shutdown, test_ctx);
  return;

 end:
  GNUNET_SCHEDULER_add_now (&do_shutdown, test_ctx);
  GNUNET_free_non_null (emsg);
}


int main (int argc, char *argv[])
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  char *const argv2[] = { "test_testing_sharedservices",
    "-c", "test_testing_sharedservices.conf",
    NULL
  };

  status = GNUNET_SYSERR;
  if (GNUNET_OK !=
      GNUNET_PROGRAM_run ((sizeof (argv2) / sizeof (char *)) - 1, argv2,
                          "test_testing_sharedservices",
                          "test case for testing service sharing among peers started by testing",
                          options, &run, NULL))
    return 1;
  return (GNUNET_OK == status) ? 0 : 3;
}

/* end of test_testing_sharedservices.c */
