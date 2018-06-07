/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2011 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
    
     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file fs/gnunet-service-fs_indexing.h
 * @brief indexing for the file-sharing service
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_FS_INDEXING_H
#define GNUNET_SERVICE_FS_INDEXING_H

#include "gnunet_block_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_datastore_service.h"
#include "gnunet_peer_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_signatures.h"
#include "gnunet_util_lib.h"


/**
 * We've received an on-demand encoded block from the datastore.
 * Attempt to do on-demand encoding and (if successful), call the
 * continuation with the resulting block.  On error, clean up and ask
 * the datastore for more results.
 *
 * @param key key for the content
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param replication replication-level for the content
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum;
 *        maybe 0 if no unique identifier is available
 * @param cont function to call with the actual block (at most once, on success)
 * @param cont_cls closure for @a cont
 * @return #GNUNET_OK on success
 */
int
GNUNET_FS_handle_on_demand_block (const struct GNUNET_HashCode *key,
                                  uint32_t size,
                                  const void *data,
                                  enum GNUNET_BLOCK_Type type,
                                  uint32_t priority,
                                  uint32_t anonymity,
                                  uint32_t replication,
                                  struct GNUNET_TIME_Absolute expiration,
                                  uint64_t uid,
                                  GNUNET_DATASTORE_DatumProcessor cont,
                                  void *cont_cls);


/**
 * Transmit information about indexed files to @a mq.
 *
 * @param mq message queue to send information to
 */
void
GNUNET_FS_indexing_send_list (struct GNUNET_MQ_Handle *mq);


/**
 * Remove a file from the index.
 *
 * @param fid identifier of the file to remove
 * @return #GNUNET_YES if the @a fid was found
 */
int
GNUNET_FS_indexing_do_unindex (const struct GNUNET_HashCode *fid);


/**
 * Add the given file to the list of indexed files.
 *
 * @param filename name of the file
 * @param file_id hash identifier for @a filename
 */
void
GNUNET_FS_add_to_index (const char *filename,
                        const struct GNUNET_HashCode *file_id);


/**
 * Initialize the indexing submodule.
 *
 * @param c configuration to use
 * @param d datastore to use
 * @return GNUNET_OK on success
 */
int
GNUNET_FS_indexing_init (const struct GNUNET_CONFIGURATION_Handle *c,
                         struct GNUNET_DATASTORE_Handle *d);


/**
 * Shutdown the module.
 */
void
GNUNET_FS_indexing_done (void);


#endif
