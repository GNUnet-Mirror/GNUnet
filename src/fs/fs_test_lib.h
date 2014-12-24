/*
     This file is part of GNUnet.
     (C) 2010, 2012 Christian Grothoff (and other contributing authors)

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
 * @brief library routines for testing FS publishing and downloading;
 *        this code is limited to flat files
 *        and no keywords (those functions can be tested with
 *        single-peer setups; this is for testing routing).
 * @author Christian Grothoff
 */
#ifndef FS_TEST_LIB_H
#define FS_TEST_LIB_H

#include "gnunet_util_lib.h"
#include "gnunet_fs_service.h"
#include "gnunet_testbed_service.h"


/**
 * Function signature.
 *
 * @param cls closure (user defined)
 * @param uri a URI, NULL for errors
 * @param fn name of the file on disk to be removed upon
 *           completion, or NULL for inserted files (also NULL on error)
 */
typedef void (*GNUNET_FS_TEST_UriContinuation) (void *cls,
                                                const struct GNUNET_FS_Uri *
                                                uri,
						const char *fn);


/**
 * Publish a file at the given daemon.
 *
 * @param peer where to publish
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
GNUNET_FS_TEST_publish (struct GNUNET_TESTBED_Peer *peer,
                        struct GNUNET_TIME_Relative timeout, uint32_t anonymity,
                        int do_index, uint64_t size, uint32_t seed,
                        unsigned int verbose,
                        GNUNET_FS_TEST_UriContinuation cont, void *cont_cls);


/**
 * Perform test download.
 *
 * @param peer which peer to download from
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
GNUNET_FS_TEST_download (struct GNUNET_TESTBED_Peer *peer,
                         struct GNUNET_TIME_Relative timeout,
                         uint32_t anonymity, uint32_t seed,
                         const struct GNUNET_FS_Uri *uri, unsigned int verbose,
                         GNUNET_SCHEDULER_TaskCallback cont, void *cont_cls);



#endif
