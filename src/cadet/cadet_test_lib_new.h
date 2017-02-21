/*
     This file is part of GNUnet.
     Copyright (C) 2012,2017 GNUnet e.V.

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
 * @file cadet/cadet_test_lib.h
 * @author Bartlomiej Polot
 * @brief library for writing CADET tests
 */
#ifndef CADET_TEST_LIB_H
#define CADET_TEST_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_testbed_service.h"
#include "gnunet_cadet_service.h"

/**
 * Test context for a CADET Test.
 */
struct GNUNET_CADET_TEST_Context;


/**
 * Main function of a CADET test.
 *
 * @param cls Closure.
 * @param ctx Argument to give to GNUNET_CADET_TEST_cleanup on test end.
 * @param num_peers Number of peers that are running.
 * @param peers Array of peers.
 * @param cadets Handle to each of the CADETs of the peers.
 */
typedef void (*GNUNET_CADET_TEST_AppMain) (void *cls,
                                          struct GNUNET_CADET_TEST_Context *ctx,
                                          unsigned int num_peers,
                                          struct GNUNET_TESTBED_Peer **peers,
                                          struct GNUNET_CADET_Handle **cadets);


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
                       const struct GNUNET_HashCode **ports);

/**
 * Clean up the testbed.
 *
 * @param ctx handle for the testbed
 */
void
GNUNET_CADET_TEST_cleanup (struct GNUNET_CADET_TEST_Context *ctx);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef CADET_TEST_LIB_H */
#endif
