/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file fs/gnunet-service-fs_lc.h
 * @brief API to handle 'local clients'
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_FS_LC_H
#define GNUNET_SERVICE_FS_LC_H

#include "gnunet-service-fs.h"


/**
 * Look up a local client record or create one if it
 * doesn't exist yet.
 *
 * @param client handle of the client
 * @return handle to local client entry
 */
struct GSF_LocalClient *
GSF_local_client_lookup_ (struct GNUNET_SERVER_Client *client);


/**
 * Handle START_SEARCH-message (search request from local client).
 * Only responsible for creating the request entry itself and setting
 * up reply callback and cancellation on client disconnect.  Does NOT
 * execute the actual request strategy (planning).
 *
 * @param client identification of the client
 * @param message the actual message
 * @param prptr where to store the pending request handle for the request
 * @return GNUNET_YES to start local processing,
 *         GNUNET_NO to not (yet) start local processing,
 *         GNUNET_SYSERR on error
 */
int
GSF_local_client_start_search_handler_ (struct GNUNET_SERVER_Client *client,
                                        const struct GNUNET_MessageHeader
                                        *message,
                                        struct GSF_PendingRequest **prptr);


/**
 * Transmit a message to the given local client as soon as possible.
 * If the client disconnects before transmission, the message is
 * simply discarded.
 *
 * @param lc recipient
 * @param msg message to transmit to client
 */
void
GSF_local_client_transmit_ (struct GSF_LocalClient *lc,
                            const struct GNUNET_MessageHeader *msg);


/**
 * A client disconnected from us.  Tear down the local client record.
 *
 * @param cls unused
 * @param client handle of the client
 */
void
GSF_client_disconnect_handler_ (void *cls, struct GNUNET_SERVER_Client *client);


#endif
/* end of gnunet-service-fs_lc.h */
