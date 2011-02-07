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
#include "gnunet-service-fs_cp.h"
#include "gnunet-service-fs_pe.h"

/**
 * Hash map from peer identities to GNUNET_CONTAINER_Heap's with
 * pending requests as entries.
 */
static struct GNUNET_CONTAINER_MultiHashMap *plans;


/**
 * Get the size of the request queue for the given peer.
 *
 * @param cp connected peer to query 
 * @return number of entries in this peer's request queue
 */
static struct GNUNET_CONTAINER_Heap *
get_heap (const struct GSF_ConnectedPeer *cp)
{
  struct GNUNET_CONTAINER_Heap *h;
  struct GNUNET_PeerIdentity id;

  GSF_connected_peer_get_identity_ (cp, &id);
  return GNUNET_CONTAINER_multihashmap_get (plans,
					    &id.hashPubKey);
}


/**
 * Create a new query plan entry.
 *
 * @param cp peer with the entry
 * @param pr request with the entry
 * @param weight determines position of the entry in the cp queue,
 *        lower weights are earlier in the queue
 */
void
GSF_plan_add_ (const struct GSF_ConnectedPeer *cp,
	       struct GSF_PendingRequest *pr,
	       GNUNET_CONTAINER_HeapCostType weight)
{
  struct GNUNET_PeerIdentity id;
  struct GNUNET_CONTAINER_Heap *h;
  struct GSF_PendingRequest *pr;

  GSF_connected_peer_get_identity_ (cp, &id);
  h = GNUNET_CONTAINER_multihashmap_get (plans,
					 &id.hashPubKey);
  if (NULL == h)
    {
      h = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
      GNUNET_CONTAINER_multihashmap_put (plans,
					 &id.hashPubKey,
					 h,
					 GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
    }
  GNUNET_CONTAINER_heap_insert (h,
				pr,
				weight);
}


/**
 * Notify the plan about a peer being no longer available;
 * destroy all entries associated with this peer.
 *
 * @param cp connected peer 
 */
void
GSF_plan_notify_peer_disconnect_ (const struct GSF_ConnectedPeer *cp)
{
  struct GNUNET_PeerIdentity id;
  struct GNUNET_CONTAINER_Heap *h;
  struct GSF_PendingRequest *pr;

  GSF_connected_peer_get_identity_ (cp, &id);
  h = GNUNET_CONTAINER_multihashmap_get (plans,
					 &id.hashPubKey);
  GNUNET_CONTAINER_multihashmap_remove (plans,
					&id.hashPubKey,
					h);
  GNUNET_CONTAINER_heap_destroy (h);
}


/**
 * Closure for 'find_request'.
 */
struct FindRequestClosure
{
  /**
   * Place to store the node that was found (NULL for none).
   */
  struct GNUNET_CONTAINER_HeapNode *node;

  /**
   * Value we're looking for
   */
  const struct GSF_PendingRequest *pr;
};


/**
 * Find a heap node where the value matches the
 * pending request given in the closure.
 *
 * @param cls the 'struct FindRequestClosure'
 * @param node heap structure we're looking for on a match
 * @param element the pending request stored in the heap
 * @param cost weight of the request
 * @return GNUNET_YES to continue looking
 */
static int
find_request (void *cls,
	      struct GNUNET_CONTAINER_HeapNode *node,
	      void *element,
	      GNUNET_CONTAINER_HeapCostType cost)
{
  struct FindRequestClosure *frc = cls;
  struct GSF_PendingRequest *pr = element;

  if (pr == frc->pr)
    {
      frc->node = node;
      return GNUNET_NO;
    }
  return GNUNET_YES;
}


/**
 * Remove the given request from all heaps. * 
 *
 * @param cls 'struct GSF_PendingRequest' to purge
 * @param key identity of the peer we're currently looking at (unused)
 * @param value request heap for the given peer to search for the 'cls'
 * @return GNUNET_OK (continue iteration)
 */
static int
remove_request (void *cls,
		const GNUNET_HashCode *key,
		void *value)
{
  const struct GSF_PendingRequest *pr = cls;
  struct GNUNET_CONTAINER_Heap *h = value;
  struct FindRequestClosure frc;

  frc.pr = pr;
  do
    {
      frc.node = NULL;
      GNUNET_CONTAINER_heap_iterate (h, &find_request, &frc);
      if (frc.node != NULL)
	GNUNET_CONTAINER_heap_remove_node (h, frc.node);
    }
  while (NULL != frc.node);
  return GNUNET_OK;
}


/**
 * Notify the plan about a request being done; destroy all entries
 * associated with this request.  Note that this implementation is
 * currently terribly inefficient (O(n)) and could instead be done in
 * O(1).  But for now, I first want to see it work correctly...
 *
 * @param pr request that is done
 */
void
GSF_plan_notify_request_done_ (const struct GSF_PendingRequest *pr)
{
  GNUNET_CONTAINER_multihashmap_iterate (plans,
					 &remove_request,
					 (void*) pr);
}


/**
 * Get the lowest-weight entry for the respective peer
 * from the plan.  Removes the entry from the plan's queue.
 *
 * @param cp connected peer to query for the next request
 * @return NULL if the queue for this peer is empty
 */
struct GSF_PendingRequest *
GSF_plan_get_ (const struct GSF_ConnectedPeer *cp)
{
  struct GNUNET_CONTAINER_Heap *h;
  struct GSF_PendingRequest *pr;

  h = get_heap (cp);
  if (NULL == h)
    return NULL;
  return GNUNET_CONTAINER_heap_remove_root (h);
}


/**
 * Get the size of the request queue for the given peer.
 *
 * @param cp connected peer to query 
 * @return number of entries in this peer's request queue
 */
unsigned int
GSF_plan_size_ (const struct GSF_ConnectedPeer *cp)
{
  struct GNUNET_CONTAINER_Heap *h;

  h = get_heap (cp);
  if (NULL == h)
    return 0;
  return GNUNET_CONTAINER_heap_get_size (h);
}



/**
 * Initialize plan subsystem.
 */
void
GSF_plan_init ()
{
  plans = GNUNET_CONTAINER_multihashmap_create (256);
}


/**
 * Shutdown plan subsystem.
 */
void
GSF_plan_done ()
{
  GNUNET_assert (0 == 
		 GNUNET_CONTAINER_multihashmap_get_size (plans));
  GNUNET_CONTAINER_multihashmap_destroy (plans);
}



/* end of gnunet-service-fs_pe.h */
