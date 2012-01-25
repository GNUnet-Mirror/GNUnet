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
 * @file fs/gnunet-service-fs_pe.h
 * @brief API to manage query plan
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_FS_PE_H
#define GNUNET_SERVICE_FS_PE_H

#include "gnunet-service-fs.h"


/**
 * Create a new query plan entry.
 *
 * @param cp peer with the entry
 * @param pr request with the entry
 */
void
GSF_plan_add_ (struct GSF_ConnectedPeer *cp, struct GSF_PendingRequest *pr);


/**
 * Notify the plan about a peer being no longer available;
 * destroy all entries associated with this peer.
 *
 * @param cp connected peer
 */
void
GSF_plan_notify_peer_disconnect_ (const struct GSF_ConnectedPeer *cp);


/**
 * Notify the plan about a request being done;
 * destroy all entries associated with this request.
 *
 * @param pr request that is done
 */
void
GSF_plan_notify_request_done_ (struct GSF_PendingRequest *pr);

/**
 * Get the last transmission attempt time for the request plan list
 * referenced by 'rpr_head', that was sent to 'sender'
 *
 * @param rpr_head request plan reference list to check.
 * @param sender the peer that we've sent the request to.
 * @param result the timestamp to fill.
 * @return GNUNET_YES if 'result' was changed, GNUNET_NO otherwise.
 */
int
GSF_request_plan_reference_get_last_transmission_ (
    struct GSF_RequestPlanReference *rpr_head, struct GSF_ConnectedPeer *sender,
    struct GNUNET_TIME_Absolute *result);

/**
 * Initialize plan subsystem.
 */
void
GSF_plan_init (void);


/**
 * Shutdown plan subsystem.
 */
void
GSF_plan_done (void);


#endif
/* end of gnunet-service-fs_pe.h */
