/*
     This file is part of GNUnet.
     (C) 2014 Christian Grothoff (and other contributing authors)

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
 * @file dht/gnunet_dht_profiler.c
 * @brief Profiler for GNUnet DHT
 * @author Sree Harsha Totakura <sreeharsha@totakura.in> 
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"

/**
 * Number of peers which should perform a PUT out of 100 peers
 */
#define PUT_PROBABILITY 50

/**
 * Configuration
 */
static struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Name of the file with the hosts to run the test over
 */
static char *hosts_file;

/**
 * Number of peers
 */
static unsigned int num_peers;

/**
 * Context to hold data of peer
 */
struct Context
{
  /**
   * Testbed operation acting on this peer
   */
  struct GNUNET_TESTBED_Operation *op;

  /**
   * Delay task
   */
  struct GNUNET_SCHEDULER_TaskIdentifier delay_task;
};


/**
 * Context for the data we put into DHT
 */
struct DataContext
{
  /**
   * next ptr for the DLL
   */
  struct Data *next;

  /**
   * prev ptr for the DLL
   */
  struct Data *prev;

  /**
   * The size of the data
   */
  size_t size;

  /**
   * The data follows here
   */
};


/**
 * An array of contexts.  The size of this array should be equal to @a num_peers
 */
struct Context *a_ctx;


/**
 * Shutdown task.  Cleanup all resources and operations
 *
 * @param cls NULL
 * @param tc scheduler task context
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  unsigned int cnt;
  
  if (NULL != a_ctx)
  {
    for (cnt=0; cnt < num_peers, cnt++)
    {
      if (NULL == a_ctx[cnt].op)
        continue;
      GNUNET_TESTBED_operation_done (a_ctx[cnt].op);
      a_ctx[cnt].op = NULL;
    }
    GNUNET_free (a_ctx);
    a_ctx = NULL;
  }
}


/**
 * Callback called when DHT service on the peer is started
 *
 * @param cls the context
 * @param op the operation that has been finished
 * @param emsg error message in case the operation has failed; will be NULL if
 *          operation has executed successfully.
 */
static void
service_started (void *cls,
                 struct GNUNET_TESTBED_Operation *op,
                 const char *emsg)
{
  struct Context *ctx = cls;

  GNUNET_assert (NULL != ctx);
  GNUNET_assert (NULL != ctx->op);
  GNUNET_TESTBED_operation_done (ctx->op);
  ctx->op = NULL;
  if (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 100)
      >= PUT_PROBABILITY)
    return;
  /* FIXME: connect to the DHT service and wait initwait before starting a PUT */
}


/**
 * Signature of a main function for a testcase.
 *
 * @param cls closure
 * @param h the run handle
 * @param num_peers number of peers in 'peers'
 * @param peers handle to peers run in the testbed
 * @param links_succeeded the number of overlay link connection attempts that
 *          succeeded
 * @param links_failed the number of overlay link
 */
static void
test_run (void *cls,
          struct GNUNET_TESTBED_RunHandle *h,
          unsigned int num_peers, struct GNUNET_TESTBED_Peer **peers,
          unsigned int links_succeeded,
          unsigned int links_failed)
{
  int cnt;

  if (NULL == peers)
  {
    /* exit */
    GNUNET_assert (0);
  }
  a_ctx = GNUNET_malloc (sizeof (struct Context) * num_peers);
  for (cnt = 0; cnt < num_peers, cnt++)
  {
    a_ctx[cnt].op = GNUNET_TESTBED_peer_manage_service (&a_ctx[cnt],
                                                        peers[cnt],
                                                        "dht",
                                                        &service_started,
                                                        &a_ctx[cnt],
                                                        1);
  }
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param config configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *config)
{
  uint64_t event_mask;
  
  if (0 == num_peers)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, _("Exiting as the number of peers is %u\n"),
         num_peers);
    return;
  }
  cfg = GNUNET_CONFIGURATION_dup (config);
  event_mask = 0;
  GNUNET_TESTBED_run (hosts_file, cfg, num_peers, event_mask, NULL,
                      NULL, &test_run, NULL);
  abort_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &do_abort,
                                    NULL);
}


/**
 * Main function.
 *
 * @return 0 on success
 */
int
main (int argc, char *const *argv)
{
  static struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'n', "peers", "COUNT",
     gettext_noop ("number of peers to start"),
     1, &GNUNET_GETOPT_set_uint, &num_peers},
    {'H', "hosts", "FILENAME",
     gettext_noop ("name of the file with the login information for the testbed"),
     1, &GNUNET_GETOPT_set_string, &hosts_file},
    {'d', "initwait", "DELAY",
     gettext_noop ("delay to allow DHT to stabilize after starting the peers"),
     1, &GNUNET_GETOPT_set_relative_time, &init_wait},
    {'w', "wait", "DELAY",
     gettext_noop ("delay between rounds"),
     1, &GNUNET_GETOPT_set_relative_time, &wait_time},
    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;
  if (GNUNET_OK !=
      GNUNET_PROGRAM_run (argc, argv, "dht-profiler",
			  gettext_noop
			  ("Measure quality and performance of the DHT service."),
			  options, &run, NULL))
    ok = 1;
  return ok;
}
