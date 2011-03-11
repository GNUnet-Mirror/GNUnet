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
 * Information we keep per request per peer.  This is a doubly-linked
 * list (with head and tail in the 'struct GSF_PendingRequestData')
 * with one entry in each heap of each 'struct PeerPlan'.  Each
 * entry tracks information relevant for this request and this peer.
 */
struct GSF_RequestPlan
{

  /**
   * This is a doubly-linked list.
   */
  struct GSF_RequestPlan *next;

  /**
   * This is a doubly-linked list.
   */
  struct GSF_RequestPlan *prev;

  /**
   * Heap node associated with this request and this peer.
   */
  struct GNUNET_CONTAINER_HeapNode *hn;

  /**
   * Associated pending request.
   */
  struct GSF_PendingRequest *pr;

  /**
   * Earliest time we'd be happy to transmit this request.
   */
  struct GNUNET_TIME_Absolute earliest_transmission;

  /**
   * Priority for this request for this target.
   */
  uint32_t priority;

};


/**
 * Transmission plan for a peer.
 */
struct PeerPlan
{
  /**
   * Heap with pending queries (struct GSF_RequestPlan), smaller weights mean higher priority.
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
 * Insert the given request plan into the heap with the appropriate weight.
 *
 * @param pp associated peer's plan
 * @param rp request to plan
 */
static void
plan (struct PeerPlan *pp,
      struct GSF_RequestPlan *rp)
{
  GNUNET_CONTAINER_HeapCostType weight;
  struct GSF_PendingRequestData *prd;

  prd = GSF_pending_request_get_data_ (rp->pr);
  weight = 0; // FIXME: calculate real weight!
  // FIXME: calculate 'rp->earliest_transmission'!
  // fIXME: claculate 'rp->priority'! 
  rp->hn = GNUNET_CONTAINER_heap_insert (pp->heap,
					 rp,
					 weight);
}


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
  struct GSF_RequestPlan *rp;
  size_t msize;

  if (NULL == buf)
    {
      /* failed, try again... */
      pp->task = GNUNET_SCHEDULER_add_now (&schedule_peer_transmission, pp);
      return 0;
    }
  rp = GNUNET_CONTAINER_heap_peek (pp->heap);
  msize = GSF_pending_request_get_message_ (rp->pr, buf_size, buf);
  if (msize > buf_size)
    {
      /* buffer to small (message changed), try again */
      pp->task = GNUNET_SCHEDULER_add_now (&schedule_peer_transmission, pp);
      return 0;
    }
  /* remove from root, add again elsewhere... */
  GNUNET_assert (rp == GNUNET_CONTAINER_heap_remove_root (pp->heap));
  rp->hn = NULL;
  plan (pp, rp);
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
  struct GSF_RequestPlan *rp;
  struct GSF_PendingRequestData *prd;
  size_t msize;
  struct GNUNET_TIME_Relative delay;

  pp->task = GNUNET_SCHEDULER_NO_TASK;
  if (NULL == pp->heap)
    return;
  if (0 == GNUNET_CONTAINER_heap_get_size (pp->heap))
    return;
  GNUNET_assert (NULL == pp->pth);
  rp = GNUNET_CONTAINER_heap_peek (pp->heap);
  prd = GSF_pending_request_get_data_ (rp->pr);
  delay = GNUNET_TIME_absolute_get_remaining (rp->earliest_transmission);
  if (delay.rel_value > 0)
    {
      pp->task = GNUNET_SCHEDULER_add_delayed (delay,
					       &schedule_peer_transmission,
					       pp);
      return;
    }
  msize = GSF_pending_request_get_message_ (rp->pr, 0, NULL);					   
  pp->pth = GSF_peer_transmit_ (pp->cp,
				GNUNET_YES,
				rp->priority,
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
  struct GSF_PendingRequestData *prd;
  struct GSF_RequestPlan *rp;
  
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
  prd = GSF_pending_request_get_data_ (pr);
  rp = GNUNET_malloc (sizeof (struct GSF_RequestPlan));
  rp->pr = pr;
  GNUNET_CONTAINER_DLL_insert (prd->rp_head,
			       prd->rp_tail,
			       rp);
  plan (pp, rp);
  if (pp->pth != NULL)
    {
      if (rp != GNUNET_CONTAINER_heap_peek (pp->heap))
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
  struct GSF_RequestPlan *rp;
  struct GSF_PendingRequestData *prd;

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
  while (NULL != (rp = GNUNET_CONTAINER_heap_remove_root (pp->heap)))
    {
      prd = GSF_pending_request_get_data_ (rp->pr);
      GNUNET_CONTAINER_DLL_remove (prd->rp_head,
				   prd->rp_tail,
				   rp);
      GNUNET_free (rp);
    }
  GNUNET_CONTAINER_heap_destroy (pp->heap);
  GNUNET_free (pp);
}


/**
 * Notify the plan about a request being done; destroy all entries
 * associated with this request.
 *
 * @param pr request that is done
 */
void
GSF_plan_notify_request_done_ (const struct GSF_PendingRequest *pr)
{
  struct GSF_RequestPlan *rp;
  struct GSF_PendingRequestData *prd;

  while (NULL != (rp = prd->rp_head))
    {
      prd = GSF_pending_request_get_data_ (rp->pr);
      GNUNET_CONTAINER_heap_remove_node (rp->hn);
      GNUNET_CONTAINER_DLL_remove (prd->rp_head,
				   prd->rp_tail,
				   rp);
      GNUNET_free (rp);
    }
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
