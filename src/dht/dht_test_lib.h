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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/
/**
 * @file dht/dht_test_lib.h
 * @author Christian Grothoff
 * @brief library for writing DHT tests
 */
#ifndef DHT_TEST_LIB_H
#define DHT_TEST_LIB_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_testbed_service.h"
#include "gnunet_dht_service.h"

/**
 * Test context for a DHT Test.
 */
struct GNUNET_DHT_TEST_Context;


/**
 * Main function of a DHT test.
 *
 * @param cls closure
 * @param ctx argument to give to GNUNET_DHT_TEST_cleanup on test end
 * @param num_peers number of peers that are running
 * @param peers array of peers
 * @param dhts handle to each of the DHTs of the peers
 */
typedef void (*GNUNET_DHT_TEST_AppMain) (void *cls,
					 struct GNUNET_DHT_TEST_Context *ctx,
					 unsigned int num_peers,
					 struct GNUNET_TESTBED_Peer **peers,
					 struct GNUNET_DHT_Handle **dhts);


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
		     void *tmain_cls);


/**
 * Clean up the testbed.
 *
 * @param ctx handle for the testbed
 */
void
GNUNET_DHT_TEST_cleanup (struct GNUNET_DHT_TEST_Context *ctx);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef DHT_TEST_LIB_H */
#endif
