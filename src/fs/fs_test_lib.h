/*
     This file is part of GNUnet.
     (C) 2010 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs_test_lib.h
 * @brief library routines for testing FS publishing and downloading
 *        with multiple peers; this code is limited to flat files
 *        and no keywords (those functions can be tested with
 *        single-peer setups; this is for testing routing).
 * @author Christian Grothoff
 */
#ifndef FS_TEST_LIB_H
#define FS_TEST_LIB_H

#include "gnunet_util_lib.h"
#include "gnunet_fs_service.h"

/**
 * Handle for a daemon started for testing FS.
 */
struct GNUNET_FS_TestDaemon;


/**
 * Start daemons for testing.
 *
 * @param template_cfg_file configuration template to use
 * @param timeout if this operation cannot be completed within the
 *                given period, call the continuation with an error code
 * @param total number of daemons to start
 * @param daemons array of 'total' entries to be initialized
 *                (array must already be allocated, will be filled)
 * @param cont function to call when done; note that if 'cont'
 *             is called with reason "TIMEOUT", then starting the
 *             daemons has failed and the client MUST NOT call
 *             'GNUNET_FS_TEST_daemons_stop'!
 * @param cont_cls closure for cont
 */
void
GNUNET_FS_TEST_daemons_start (const char *template_cfg_file,
                              struct GNUNET_TIME_Relative timeout,
                              unsigned int total,
                              struct GNUNET_FS_TestDaemon **daemons,
                              GNUNET_SCHEDULER_Task cont, void *cont_cls);


struct GNUNET_FS_TEST_ConnectContext;


/**
 * Connect two daemons for testing.
 *
 * @param daemon1 first daemon to connect
 * @param daemon2 second first daemon to connect
 * @param timeout if this operation cannot be completed within the
 *                given period, call the continuation with an error code
 * @param cont function to call when done
 * @param cont_cls closure for cont
 */
struct GNUNET_FS_TEST_ConnectContext *
GNUNET_FS_TEST_daemons_connect (struct GNUNET_FS_TestDaemon *daemon1,
                                struct GNUNET_FS_TestDaemon *daemon2,
                                struct GNUNET_TIME_Relative timeout,
                                GNUNET_SCHEDULER_Task cont, void *cont_cls);


/**
 * Cancel connect operation.
 *
 * @param cc operation to cancel
 */
void
GNUNET_FS_TEST_daemons_connect_cancel (struct GNUNET_FS_TEST_ConnectContext
                                       *cc);


/**
 * Obtain peer group used for testing.
 *
 * @param daemons array with the daemons (must contain at least one)
 * @return peer group
 */
struct GNUNET_TESTING_PeerGroup *
GNUNET_FS_TEST_get_group (struct GNUNET_FS_TestDaemon **daemons);



/**
 * Obtain peer configuration used for testing.
 *
 * @param daemons array with the daemons
 * @param off which configuration to get
 * @return peer configuration
 */
const struct GNUNET_CONFIGURATION_Handle *
GNUNET_FS_TEST_get_configuration (struct GNUNET_FS_TestDaemon **daemons,
                                  unsigned int off);

/**
 * Stop daemons used for testing.
 *
 * @param total number of daemons to stop
 * @param daemons array with the daemons (values will be clobbered)
 */
void
GNUNET_FS_TEST_daemons_stop (unsigned int total,
                             struct GNUNET_FS_TestDaemon **daemons);


/**
 * Function signature.
 *
 * @param cls closure (user defined)
 * @param uri a URI, NULL for errors
 */
typedef void (*GNUNET_FS_TEST_UriContinuation) (void *cls,
                                                const struct GNUNET_FS_Uri *
                                                uri);


/**
 * Publish a file at the given daemon.
 *
 * @param daemon where to publish
 * @param timeout if this operation cannot be completed within the
 *                given period, call the continuation with an error code
 * @param anonymity option for publication
 * @param do_index GNUNET_YES for index, GNUNET_NO for insertion,
 *                GNUNET_SYSERR for simulation
 * @param size size of the file to publish
 * @param seed seed to use for file generation
 * @param verbose how verbose to be in reporting
 * @param cont function to call when done
 * @param cont_cls closure for cont
 */
void
GNUNET_FS_TEST_publish (struct GNUNET_FS_TestDaemon *daemon,
                        struct GNUNET_TIME_Relative timeout, uint32_t anonymity,
                        int do_index, uint64_t size, uint32_t seed,
                        unsigned int verbose,
                        GNUNET_FS_TEST_UriContinuation cont, void *cont_cls);


/**
 * Perform test download.
 *
 * @param daemon which peer to download from
 * @param timeout if this operation cannot be completed within the
 *                given period, call the continuation with an error code
 * @param anonymity option for download
 * @param seed used for file validation
 * @param uri URI of file to download (CHK/LOC only)
 * @param verbose how verbose to be in reporting
 * @param cont function to call when done
 * @param cont_cls closure for cont
 */
void
GNUNET_FS_TEST_download (struct GNUNET_FS_TestDaemon *daemon,
                         struct GNUNET_TIME_Relative timeout,
                         uint32_t anonymity, uint32_t seed,
                         const struct GNUNET_FS_Uri *uri, unsigned int verbose,
                         GNUNET_SCHEDULER_Task cont, void *cont_cls);



#endif
