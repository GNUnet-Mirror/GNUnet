/*
     This file is part of GNUnet.
     Copyright (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file dht/dht_test_lib.c
 * @author Christian Grothoff
 * @brief library for writing DHT tests
 */
#include "platform.h"
#include "dht_test_lib.h"

/**
 * Test context for a DHT Test.
 */
struct GNUNET_DHT_TEST_Context
{
  /**
   * Array of running peers.
   */
  struct GNUNET_TESTBED_Peer **peers;

  /**
   * Array of handles to the DHT for each peer.
   */
  struct GNUNET_DHT_Handle **dhts;

  /**
   * Operation associated with the connection to the DHT.
   */
  struct GNUNET_TESTBED_Operation **ops;

  /**
   * Main function of the test to run once all DHTs are available.
   */
  GNUNET_DHT_TEST_AppMain app_main;

  /**
   * Closure for 'app_main'.
   */
  void *app_main_cls;

  /**
   * Number of peers running, size of the arrays above.
   */
  unsigned int num_peers;

};


/**
 * Adapter function called to establish a connection to
 * the DHT service.
 *
 * @param cls closure
 * @param cfg configuration of the peer to connect to; will be available until
 *          GNUNET_TESTBED_operation_done() is called on the operation returned
 *          from GNUNET_TESTBED_service_connect()
 * @return service handle to return in 'op_result', NULL on error
 */
static void *
dht_connect_adapter (void *cls,
		     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  return GNUNET_DHT_connect (cfg, 16);
}


/**
 * Adapter function called to destroy a connection to
 * the DHT service.
 *
 * @param cls closure
 * @param op_result service handle returned from the connect adapter
 */
static void
dht_disconnect_adapter (void *cls,
			void *op_result)
{
  struct GNUNET_DHT_Handle *dht = op_result;

  GNUNET_DHT_disconnect (dht);
}


/**
 * Callback to be called when a service connect operation is completed
 *
 * @param cls the callback closure from functions generating an operation
 * @param op the operation that has been finished
 * @param ca_result the service handle returned from GNUNET_TESTBED_ConnectAdapter()
 * @param emsg error message in case the operation has failed; will be NULL if
 *          operation has executed successfully.
 */
static void
dht_connect_cb (void *cls,
		struct GNUNET_TESTBED_Operation *op,
		void *ca_result,
		const char *emsg)
{
  struct GNUNET_DHT_TEST_Context *ctx = cls;
  unsigned int i;

  if (NULL != emsg)
  {
    fprintf (stderr, "Failed to connect to DHT service: %s\n",
	     emsg);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  for (i=0;i<ctx->num_peers;i++)
    if (op == ctx->ops[i])
      ctx->dhts[i] = ca_result;
  for (i=0;i<ctx->num_peers;i++)
    if (NULL == ctx->dhts[i])
      return; /* still some DHT connections missing */
  /* all DHT connections ready! */
  ctx->app_main (ctx->app_main_cls,
		 ctx,
		 ctx->num_peers,
		 ctx->peers,
		 ctx->dhts);		
}


/**
 * Clean up the testbed.
 *
 * @param ctx handle for the testbed
 */
void
GNUNET_DHT_TEST_cleanup (struct GNUNET_DHT_TEST_Context *ctx)
{
  unsigned int i;

  for (i=0;i<ctx->num_peers;i++)
    GNUNET_TESTBED_operation_done (ctx->ops[i]);
  GNUNET_free (ctx->ops);
  GNUNET_free (ctx->dhts);
  GNUNET_free (ctx);
  GNUNET_SCHEDULER_shutdown ();
}


static void
dht_test_run (void *cls,
             struct GNUNET_TESTBED_RunHandle *h,
	      unsigned int num_peers,
	      struct GNUNET_TESTBED_Peer **peers,
              unsigned int links_succeeded,
              unsigned int links_failed)
{
  struct GNUNET_DHT_TEST_Context *ctx = cls;
  unsigned int i;

  GNUNET_assert (num_peers == ctx->num_peers);
  ctx->peers = peers;
  for (i=0;i<num_peers;i++)
    ctx->ops[i] = GNUNET_TESTBED_service_connect (ctx,
						  peers[i],
						  "dht",
						  &dht_connect_cb,
						  ctx,
						  &dht_connect_adapter,
						  &dht_disconnect_adapter,
						  ctx);
}


/**
 * Run a test using the given name, configuration file and number of
 * peers.
 *
 * @param testname name of the test (for logging)
 * @param cfgname name of the configuration file
 * @param num_peers number of peers to start
 * @param tmain main function to run once the testbed is ready
 * @param tmain_cls closure for 'tmain'
 */
void
GNUNET_DHT_TEST_run (const char *testname,
		     const char *cfgname,
		     unsigned int num_peers,
		     GNUNET_DHT_TEST_AppMain tmain,
		     void *tmain_cls)
{
  struct GNUNET_DHT_TEST_Context *ctx;

  ctx = GNUNET_new (struct GNUNET_DHT_TEST_Context);
  ctx->num_peers = num_peers;
  ctx->ops = GNUNET_malloc (num_peers * sizeof (struct GNUNET_TESTBED_Operation *));
  ctx->dhts = GNUNET_malloc (num_peers * sizeof (struct GNUNET_DHT_Handle *));
  ctx->app_main = tmain;
  ctx->app_main_cls = tmain_cls;
  (void) GNUNET_TESTBED_test_run (testname,
                                  cfgname,
                                  num_peers,
                                  0LL, NULL, NULL,
                                  &dht_test_run, ctx);
}

/* end of dht_test_lib.c */
