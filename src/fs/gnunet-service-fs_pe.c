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
#include "gnunet-service-fs_pr.h"

/**
 * Transmission plan for a peer.
 */
struct PeerPlan
{
  /**
   * Heap with pending queries, smaller weights mean higher priority.
   */
  struct GNUNET_CONTAINER_Heap *heap;

  /**
   * Current transmission request handle.
   */
  struct GSF_PeerTransmitHandle *pth;

  /**
   * Peer for which this is the plan.
   */
  struct GSF_ConnectedPeer *cp;

  /**
   * Current task for executing the plan.
   */
  GNUNET_SCHEDULER_TaskIdentifier task;
};


/**
 * Hash map from peer identities to PeerPlans.
 */
static struct GNUNET_CONTAINER_MultiHashMap *plans;


/**
 * Figure out when and how to transmit to the given peer.
 *
 * @param cls the 'struct GSF_ConnectedPeer' for transmission
 * @param tc scheduler context
 */
static void
schedule_peer_transmission (void *cls,
			    const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Function called to get a message for transmission.
 *
 * @param cls closure
 * @param buf_size number of bytes available in buf
 * @param buf where to copy the message, NULL on error (peer disconnect)
 * @return number of bytes copied to 'buf', can be 0 (without indicating an error)
 */
static size_t 
transmit_message_callback (void *cls,
			   size_t buf_size,
			   void *buf)
{
  struct PeerPlan *pp = cls;
  struct GSF_PendingRequest *pr;
  size_t msize;

  if (NULL == buf)
    {
      /* failed, try again... */
      pp->task = GNUNET_SCHEDULER_add_now (&schedule_peer_transmission, pp);
      return 0;
    }
  pr = GNUNET_CONTAINER_heap_peek (pp->heap);
  msize = GSF_pending_request_get_message_ (pr, buf_size, buf);
  if (msize > buf_size)
    {
      /* buffer to small (message changed), try again */
      pp->task = GNUNET_SCHEDULER_add_now (&schedule_peer_transmission, pp);
      return 0;
    }
  /* remove from root, add again elsewhere... */
  GNUNET_assert (pr == GNUNET_CONTAINER_heap_remove_root (pp->heap));
  GSF_plan_add_ (pp->cp, pr);
  return msize;
}


/**
 * Figure out when and how to transmit to the given peer.
 *
 * @param cls the 'struct PeerPlan'
 * @param tc scheduler context
 */
static void
schedule_peer_transmission (void *cls,
			    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerPlan *pp = cls;
  struct GSF_PendingRequest *pr;
  size_t msize;
  struct GNUNET_TIME_Relative delay;

  pp->task = GNUNET_SCHEDULER_NO_TASK;
  if (NULL == pp->heap)
    return;
  if (0 == GNUNET_CONTAINER_heap_get_size (pp->heap))
    return;
  GNUNET_assert (NULL == pp->pth);
  pr = GNUNET_CONTAINER_heap_peek (pp->heap);
  if (0) // FIXME: if (re)transmission should wait, wait...
    {
      delay = GNUNET_TIME_UNIT_SECONDS;
      // FIXME
      pp->task = GNUNET_SCHEDULER_add_delayed (delay,
					       &schedule_peer_transmission,
					       pp);
      return;
    }
  msize = GSF_pending_request_get_message_ (pr, 0, NULL);					   
  pp->pth = GSF_peer_transmit_ (pp->cp,
				GNUNET_YES,
				0 /* FIXME: pr->priority? */,
				GNUNET_TIME_UNIT_FOREVER_REL,
				msize,
				&transmit_message_callback,
				pp);
  GNUNET_assert (NULL != pp->pth);
}


/**
 * Create a new query plan entry.
 *
 * @param cp peer with the entry
 * @param pr request with the entry
 */
void
GSF_plan_add_ (const struct GSF_ConnectedPeer *cp,
	       struct GSF_PendingRequest *pr)
{
  struct GNUNET_PeerIdentity id;
  struct PeerPlan *pp;
  GNUNET_CONTAINER_HeapCostType weight;
  
  GSF_connected_peer_get_identity_ (cp, &id);
  pp = GNUNET_CONTAINER_multihashmap_get (plans,
					  &id.hashPubKey);
  if (NULL == pp)
    {
      pp = GNUNET_malloc (sizeof (struct PeerPlan));
      pp->heap = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
      GNUNET_CONTAINER_multihashmap_put (plans,
					 &id.hashPubKey,
					 pp,
					 GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
    }
  weight = 0; // FIXME: calculate real weight!
  GNUNET_CONTAINER_heap_insert (pp->heap,
				pr,
				weight);
  if (pp->pth != NULL)
    {
      if (pr != GNUNET_CONTAINER_heap_peek (pp->heap))
	return;
      GSF_peer_transmit_cancel_ (pp->pth);
      pp->pth = NULL;
    }
  if (GNUNET_SCHEDULER_NO_TASK != pp->task)
    GNUNET_SCHEDULER_cancel (pp->task);
  pp->task = GNUNET_SCHEDULER_add_now (&schedule_peer_transmission,
				       pp);
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
  struct PeerPlan *pp;

  GSF_connected_peer_get_identity_ (cp, &id);
  pp = GNUNET_CONTAINER_multihashmap_get (plans,
					  &id.hashPubKey);
  GNUNET_CONTAINER_multihashmap_remove (plans,
					&id.hashPubKey,
					pp);
  if (NULL != pp->pth)
    GSF_peer_transmit_cancel_ (pp->pth);
  if (GNUNET_SCHEDULER_NO_TASK != pp->task)
    GNUNET_SCHEDULER_cancel (pp->task);
  GNUNET_CONTAINER_heap_destroy (pp->heap);
  GNUNET_free (pp);
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
 * Remove the given request from all heaps. * FIXME: O(n) -- inefficient!
 *
 * @param cls 'struct GSF_PendingRequest' to purge
 * @param key identity of the peer we're currently looking at (unused)
 * @param value PeerPlan for the given peer to search for the 'cls'
 * @return GNUNET_OK (continue iteration)
 */
static int
remove_request (void *cls,
		const GNUNET_HashCode *key,
		void *value)
{
  const struct GSF_PendingRequest *pr = cls;
  struct PeerPlan *pp = value;
  struct GNUNET_CONTAINER_Heap *h = pp->heap;
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
		 GNUNET_CONTAINER_multihashmap_size (plans));
  GNUNET_CONTAINER_multihashmap_destroy (plans);
}



/* end of gnunet-service-fs_pe.h */
