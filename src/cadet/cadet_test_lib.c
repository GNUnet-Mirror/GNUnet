/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2017 GNUnet e.V.

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/
/**
 * @file cadet/cadet_test_lib.c
 * @author Bartlomiej Polot
 * @brief library for writing CADET tests
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "cadet_test_lib.h"
#include "gnunet_cadet_service.h"


/**
 * Test context for a CADET Test.
 */
struct GNUNET_CADET_TEST_Context
{
  /**
   * Array of running peers.
   */
  struct GNUNET_TESTBED_Peer **peers;

  /**
   * Array of handles to the CADET for each peer.
   */
  struct GNUNET_CADET_Handle **cadets;

  /**
   * Operation associated with the connection to the CADET.
   */
  struct GNUNET_TESTBED_Operation **ops;

  /**
   * Number of peers running, size of the arrays above.
   */
  unsigned int num_peers;

  /**
   * Main function of the test to run once all CADETs are available.
   */
  GNUNET_CADET_TEST_AppMain app_main;

  /**
   * Closure for 'app_main'.
   */
  void *app_main_cls;

  /**
   * Handler for incoming tunnels.
   */
  GNUNET_CADET_ConnectEventHandler connects;

  /**
   * Function called when the transmit window size changes.
   */
  GNUNET_CADET_WindowSizeEventHandler window_changes;

  /**
   * Cleaner for destroyed incoming tunnels.
   */
  GNUNET_CADET_DisconnectEventHandler disconnects;

  /**
   * Message handlers.
   */
  struct GNUNET_MQ_MessageHandler *handlers;

  /**
   * Application ports.
   */
  const struct GNUNET_HashCode **ports;

  /**
   * Number of ports in #ports.
   */
  unsigned int port_count;

};


/**
 * Context for a cadet adapter callback.
 */
struct GNUNET_CADET_TEST_AdapterContext
{
  /**
   * Peer number for the particular peer.
   */
  unsigned int peer;

  /**
   * Port handlers for open ports.
   */
  struct GNUNET_CADET_Port **ports;
 
  /**
   * General context.
   */
  struct GNUNET_CADET_TEST_Context *ctx;
};


/**
 * Adapter function called to establish a connection to
 * the CADET service.
 *
 * @param cls closure
 * @param cfg configuration of the peer to connect to; will be available until
 *          GNUNET_TESTBED_operation_done() is called on the operation returned
 *          from GNUNET_TESTBED_service_connect()
 * @return service handle to return in 'op_result', NULL on error
 */
static void *
cadet_connect_adapter (void *cls,
                       const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_CADET_TEST_AdapterContext *actx = cls;
  struct GNUNET_CADET_TEST_Context *ctx = actx->ctx;
  struct GNUNET_CADET_Handle *h;
  unsigned int i;

  h = GNUNET_CADET_connect (cfg);
  if (NULL == ctx->ports)
    return h;

  actx->ports = GNUNET_new_array (ctx->port_count, struct GNUNET_CADET_Port *);
  for (i = 0; i < ctx->port_count; i++)
  {
    actx->ports[i] = GNUNET_CADET_open_port (h,
                                             ctx->ports[i],
                                             ctx->connects,
                                             (void *) (long) actx->peer,
                                             ctx->window_changes,
                                             ctx->disconnects,
                                             ctx->handlers);
  }
  return h;
}


/**
 * Adapter function called to destroy a connection to
 * the CADET service.
 *
 * @param cls closure
 * @param op_result service handle returned from the connect adapter
 */
static void
cadet_disconnect_adapter (void *cls,
                         void *op_result)
{
  struct GNUNET_CADET_Handle *cadet = op_result;
  struct GNUNET_CADET_TEST_AdapterContext *actx = cls;

  if (NULL != actx->ports)
  {
    for (int i = 0; i < actx->ctx->port_count; i++)
    {
      GNUNET_CADET_close_port (actx->ports[i]);
      actx->ports[i] = NULL;
    }
    GNUNET_free (actx->ports);
  }
  GNUNET_free (actx);
  GNUNET_CADET_disconnect (cadet);
}


/**
 * Callback to be called when a service connect operation is completed.
 *
 * @param cls The callback closure from functions generating an operation.
 * @param op The operation that has been finished.
 * @param ca_result The service handle returned from
 *                  GNUNET_TESTBED_ConnectAdapter() (cadet handle).
 * @param emsg Error message in case the operation has failed.
 *             NULL if operation has executed successfully.
 */
static void
cadet_connect_cb (void *cls,
                 struct GNUNET_TESTBED_Operation *op,
                 void *ca_result,
                 const char *emsg)
{
  struct GNUNET_CADET_TEST_Context *ctx = cls;
  unsigned int i;

  if (NULL != emsg)
  {
    fprintf (stderr, "Failed to connect to CADET service: %s\n",
             emsg);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  for (i = 0; i < ctx->num_peers; i++)
    if (op == ctx->ops[i])
    {
      ctx->cadets[i] = ca_result;
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "...cadet %u connected\n", i);
    }
  for (i = 0; i < ctx->num_peers; i++)
    if (NULL == ctx->cadets[i])
      return; /* still some CADET connections missing */
  /* all CADET connections ready! */
  ctx->app_main (ctx->app_main_cls,
                 ctx,
                 ctx->num_peers,
                 ctx->peers,
                 ctx->cadets);
}


void
GNUNET_CADET_TEST_cleanup (struct GNUNET_CADET_TEST_Context *ctx)
{
  unsigned int i;

  for (i = 0; i < ctx->num_peers; i++)
  {
    GNUNET_assert (NULL != ctx->ops[i]);
    GNUNET_TESTBED_operation_done (ctx->ops[i]);
    ctx->ops[i] = NULL;
  }
  GNUNET_free (ctx->ops);
  GNUNET_free (ctx->cadets);
  GNUNET_free (ctx);
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Callback run when the testbed is ready (peers running and connected to
 * each other)
 *
 * @param cls Closure (context).
 * @param h the run handle
 * @param num_peers Number of peers that are running.
 * @param peers Handles to each one of the @c num_peers peers.
 * @param links_succeeded the number of overlay link connection attempts that
 *          succeeded
 * @param links_failed the number of overlay link connection attempts that
 *          failed
 */
static void
cadet_test_run (void *cls,
               struct GNUNET_TESTBED_RunHandle *h,
               unsigned int num_peers,
               struct GNUNET_TESTBED_Peer **peers,
               unsigned int links_succeeded,
               unsigned int links_failed)
{
  struct GNUNET_CADET_TEST_Context *ctx = cls;
  unsigned int i;

  if (0 != links_failed)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Some links failed (%u), ending\n",
                links_failed);
    exit (2);
  }

  if  (num_peers != ctx->num_peers)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Peers started %u/%u, ending\n",
                num_peers, ctx->num_peers);
    exit (1);
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Testbed up, %u peers and %u links\n",
              num_peers, links_succeeded);
  ctx->peers = peers;
  for (i = 0; i < num_peers; i++)
  {
    struct GNUNET_CADET_TEST_AdapterContext *newctx;
    newctx = GNUNET_new (struct GNUNET_CADET_TEST_AdapterContext);
    newctx->peer = i;
    newctx->ctx = ctx;
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Connecting to cadet %u\n", i);
    ctx->ops[i] = GNUNET_TESTBED_service_connect (ctx,
                                                  peers[i],
                                                  "cadet",
                                                  &cadet_connect_cb,
                                                  ctx,
                                                  &cadet_connect_adapter,
                                                  &cadet_disconnect_adapter,
                                                  newctx);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "op handle %p\n", ctx->ops[i]);
  }
}


/**
 * Run a test using the given name, configuration file and number of peers.
 * All cadet callbacks will receive the peer number (long) as the closure.
 *
 * @param testname Name of the test (for logging).
 * @param cfgfile Name of the configuration file.
 * @param num_peers Number of peers to start.
 * @param tmain Main function to run once the testbed is ready.
 * @param tmain_cls Closure for @a tmain.
 * @param connects Handler for incoming channels.
 * @param window_changes Handler for the window size change notification.
 * @param disconnects Cleaner for destroyed incoming channels.
 * @param handlers Message handlers.
 * @param ports Ports the peers offer, NULL-terminated.
 */
void
GNUNET_CADET_TEST_ruN (const char *testname,
                       const char *cfgfile,
                       unsigned int num_peers,
                       GNUNET_CADET_TEST_AppMain tmain,
                       void *tmain_cls,
                       GNUNET_CADET_ConnectEventHandler connects,
                       GNUNET_CADET_WindowSizeEventHandler window_changes,
                       GNUNET_CADET_DisconnectEventHandler disconnects,
                       struct GNUNET_MQ_MessageHandler *handlers,
                       const struct GNUNET_HashCode **ports)
{
  struct GNUNET_CADET_TEST_Context *ctx;

  ctx = GNUNET_new (struct GNUNET_CADET_TEST_Context);
  ctx->num_peers = num_peers;
  ctx->ops = GNUNET_new_array (num_peers, struct GNUNET_TESTBED_Operation *);
  ctx->cadets = GNUNET_new_array (num_peers, struct GNUNET_CADET_Handle *);
  ctx->app_main = tmain;
  ctx->app_main_cls = tmain_cls;
  ctx->connects = connects;
  ctx->window_changes = window_changes;
  ctx->disconnects = disconnects;
  ctx->handlers = GNUNET_MQ_copy_handlers (handlers);
  ctx->ports = ports;
  ctx->port_count = 0;
  while (NULL != ctx->ports[ctx->port_count])
    ctx->port_count++;

  GNUNET_TESTBED_test_run (testname,
                           cfgfile,
                           num_peers,
                           0LL, NULL, NULL,
                           &cadet_test_run, ctx);
}

/* end of cadet_test_lib.c */
