/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file mesh/mesh2_test_lib.h
 * @author Bartlomiej Polot
 * @brief library for writing MESH tests
 */
#ifndef MESH_TEST_LIB_H
#define MESH_TEST_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_testbed_service.h"
#include "gnunet_mesh2_service.h"

/**
 * Test context for a MESH Test.
 */
struct GNUNET_MESH_TEST_Context;


/**
 * Main function of a MESH test.
 *
 * @param cls Closure.
 * @param ctx Argument to give to GNUNET_MESH_TEST_cleanup on test end.
 * @param num_peers Number of peers that are running.
 * @param peers Array of peers.
 * @param meshes Handle to each of the MESHs of the peers.
 */
typedef void (*GNUNET_MESH_TEST_AppMain) (void *cls,
                                          struct GNUNET_MESH_TEST_Context *ctx,
                                          unsigned int num_peers,
                                          struct GNUNET_TESTBED_Peer **peers,
                                          struct GNUNET_MESH_Handle **meshes);


/**
 * Run a test using the given name, configuration file and number of
 * peers.
 * All mesh callbacks will receive the peer number as the closure.
 *
 * @param testname Name of the test (for logging).
 * @param cfgname Name of the configuration file.
 * @param num_peers Number of peers to start.
 * @param tmain Main function to run once the testbed is ready.
 * @param tmain_cls Closure for 'tmain'.
 * @param new_tunnel Handler for incoming tunnels.
 * @param cleaner Cleaner for destroyed incoming tunnels.
 * @param handlers Message handlers.
 * @param stypes Application types.
 */
void 
GNUNET_MESH_TEST_run (const char *testname,
                      const char *cfgname,
                      unsigned int num_peers,
                      GNUNET_MESH_TEST_AppMain tmain,
                      void *tmain_cls,
                      GNUNET_MESH_InboundTunnelNotificationHandler new_tunnel,
                      GNUNET_MESH_TunnelEndHandler cleaner,
                      struct GNUNET_MESH_MessageHandler* handlers,
                      const GNUNET_MESH_ApplicationType* stypes);


/**
 * Clean up the testbed.
 *
 * @param ctx handle for the testbed
 */
void
GNUNET_MESH_TEST_cleanup (struct GNUNET_MESH_TEST_Context *ctx);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef MESH_TEST_LIB_H */
#endif
