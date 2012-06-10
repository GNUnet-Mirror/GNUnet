/*
      This file is part of GNUnet
      (C) 2008, 2009, 2012 Christian Grothoff (and other contributing authors)

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
 * @file testing/test_testing_new_peerstartup.c
 * @brief test case for testing peer startup and shutdown using new testing
 *          library 
 * @author Sree Harsha Totakura
 */

#include "platform.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_testing_lib-new.h"

#define LOG(kind,...)                           \
  GNUNET_log (kind, __VA_ARGS__)


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
  struct GNUNET_TESTING_Peer *peer;

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
  
  GNUNET_assert (GNUNET_OK == GNUNET_TESTING_peer_stop (test_ctx->peer));
  GNUNET_TESTING_peer_destroy (test_ctx->peer);
  GNUNET_CONFIGURATION_destroy (test_ctx->cfg);
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
  struct GNUNET_TESTING_System *system;
  struct GNUNET_TESTING_Peer *peer;
  struct GNUNET_CONFIGURATION_Handle *new_cfg;
  struct TestingContext *test_ctx;
  char *emsg;
  struct GNUNET_PeerIdentity id;
    
  system = GNUNET_TESTING_system_create ("test-gnunet-testing",
                                         "127.0.0.1");
  GNUNET_assert (NULL != system);
  new_cfg = GNUNET_CONFIGURATION_dup (cfg);
  emsg = NULL;
  peer = GNUNET_TESTING_peer_configure (system, new_cfg, 0, &id, &emsg);
  GNUNET_assert (NULL != peer);
  GNUNET_assert (NULL == emsg);
  GNUNET_assert (GNUNET_OK == GNUNET_TESTING_peer_start (peer));
  test_ctx = GNUNET_malloc (sizeof (struct TestingContext));
  test_ctx->system = system;
  test_ctx->peer = peer;
  test_ctx->cfg = new_cfg;
  GNUNET_SCHEDULER_add_now (&do_shutdown, test_ctx);
}


int main (int argc, char *argv[])
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK !=
      GNUNET_PROGRAM_run (argc, argv,
                          "test_testing_new_peerstartup",
                          "test case for peerstartup using new testing library",
                          options, &run, NULL))
    return 1;
  return 0;
}

/* end of test_testing_peerstartup.c */
