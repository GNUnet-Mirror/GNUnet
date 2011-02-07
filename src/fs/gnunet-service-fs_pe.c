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
 * @file fs/gnunet-service-fs_pe.c
 * @brief API to manage query plan
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-fs_pe.h"


/**
 * Create a new query plan entry.
 *
 * @param cp peer with the entry
 * @param pr request with the entry
 * @param weight determines position of the entry in the cp queue,
 *        lower weights are earlier in the queue
 */
void
GSF_plan_add_ (struct GSF_ConnectedPeer *cp,
	       struct GSF_PendingRequest *pr,
	       double weight)
{
 // FIXME
}


/**
 * Notify the plan about a peer being no longer available;
 * destroy all entries associated with this peer.
 *
 * @param cp connected peer 
 */
void
GSF_plan_notify_peer_disconnect_ (struct GSF_ConnectedPeer *cp)
{
 // FIXME
}


/**
 * Notify the plan about a request being done;
 * destroy all entries associated with this request.
 *
 * @param pr request that is done
 */
void
GSF_plan_notify_request_done_ (struct GSF_PendingRequest *pr)
{
 // FIXME
}


/**
 * Get the lowest-weight entry for the respective peer
 * from the plan.  Removes the entry from the plan's queue.
 *
 * @param cp connected peer to query for the next request
 * @return NULL if the queue for this peer is empty
 */
struct GSF_PendingRequest *
GSF_plan_get_ (struct GSF_ConnectedPeer *cp)
{
  return NULL; // FIXME
}


/**
 * Get the size of the request queue for the given peer.
 *
 * @param cp connected peer to query 
 * @return number of entries in this peer's request queue
 */
unsigned int
GSF_plan_size_ (struct GSF_ConnectedPeer *cp)
{
  return 0; // FIXME
}



/* end of gnunet-service-fs_pe.h */
