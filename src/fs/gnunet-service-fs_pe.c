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
#include "gnunet-service-fs.h"
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
   * Earliest time we'd be happy to (re)transmit this request.
   */
  struct GNUNET_TIME_Absolute earliest_transmission;

  /**
   * When was the last time we transmitted this request to this peer? 0 for never.
   */
  struct GNUNET_TIME_Absolute last_transmission;

  /**
   * Current priority for this request for this target.
   */
  uint64_t priority;

  /**
   * How often did we transmit this request to this peer?
   */
  unsigned int transmission_counter;

};


/**
 * Transmission plan for a peer.
 */
struct PeerPlan
{
  /**
   * Heap with pending queries (struct GSF_RequestPlan), higher weights mean higher priority.
   */
  struct GNUNET_CONTAINER_Heap *priority_heap;

  /**
   * Heap with pending queries (struct GSF_RequestPlan), by transmission time, lowest first.
   */
  struct GNUNET_CONTAINER_Heap *delay_heap;

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
 * Sum of all transmission counters (equals total delay for all plan entries).
 */
static unsigned long long total_delay;

/**
 * Number of plan entries.
 */
static unsigned long long plan_count;


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
 * Insert the given request plan into the heap with the appropriate weight.
 *
 * @param pp associated peer's plan
 * @param rp request to plan
 */
static void
plan (struct PeerPlan *pp,
      struct GSF_RequestPlan *rp)
{
  struct GSF_PendingRequestData *prd;
  struct GNUNET_TIME_Relative delay;

  GNUNET_STATISTICS_set (GSF_stats,
			 gettext_noop ("# average retransmission delay (ms)"),
			 total_delay * 1000LL / plan_count,
			 GNUNET_NO);
  prd = GSF_pending_request_get_data_ (rp->pr);
  // FIXME: calculate 'rp->earliest_transmission'!
  // FIXME: claculate 'rp->priority'!  
  delay = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
					 rp->transmission_counter);
  rp->earliest_transmission 
    = GNUNET_TIME_relative_to_absolute (delay);
#if DEBUG_FS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Earliest (re)transmission for `%s' in %us\n",
	      GNUNET_h2s (&prd->query),
	      rp->transmission_counter);
#endif 

  GNUNET_assert (rp->hn == NULL);
  if (GNUNET_TIME_absolute_get_remaining (rp->earliest_transmission).rel_value == 0)
    rp->hn = GNUNET_CONTAINER_heap_insert (pp->priority_heap,
					   rp,
					   rp->priority);
  else
    rp->hn = GNUNET_CONTAINER_heap_insert (pp->delay_heap,
					   rp,
					   rp->earliest_transmission.abs_value);
  if (GNUNET_SCHEDULER_NO_TASK != pp->task)
    GNUNET_SCHEDULER_cancel (pp->task);
  pp->task = GNUNET_SCHEDULER_add_now (&schedule_peer_transmission, pp);
}


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

  pp->pth = NULL;
  if (NULL == buf)
    {
      /* failed, try again... */
      pp->task = GNUNET_SCHEDULER_add_now (&schedule_peer_transmission, pp);
      return 0;
    }
  rp = GNUNET_CONTAINER_heap_peek (pp->priority_heap);
  if (NULL == rp)
    {
      pp->task = GNUNET_SCHEDULER_add_now (&schedule_peer_transmission, pp);
      return 0;
    }
  msize = GSF_pending_request_get_message_ (rp->pr, buf_size, buf);
  if (msize > buf_size)
    {
      /* buffer to small (message changed), try again */
      pp->task = GNUNET_SCHEDULER_add_now (&schedule_peer_transmission, pp);
      return 0;
    }
  /* remove from root, add again elsewhere... */
  GNUNET_assert (rp == GNUNET_CONTAINER_heap_remove_root (pp->priority_heap));
  rp->hn = NULL;
  rp->last_transmission = GNUNET_TIME_absolute_get ();
  rp->transmission_counter++;
  total_delay++;
#if DEBUG_FS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Executing plan %p executed %u times, planning retransmission\n",
	      rp,
	      rp->transmission_counter);
#endif    
  plan (pp, rp);
  GNUNET_STATISTICS_update (GSF_stats,
			    gettext_noop ("# queries messages sent to other peers"),
			    1,
			    GNUNET_NO);
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
  size_t msize;

  pp->task = GNUNET_SCHEDULER_NO_TASK;
  if (pp->pth != NULL)
    {
      GSF_peer_transmit_cancel_ (pp->pth);
      pp->pth = NULL;
    }
  /* move ready requests to priority queue */
  while ( (NULL != (rp = GNUNET_CONTAINER_heap_peek (pp->delay_heap))) &&
	  (GNUNET_TIME_absolute_get_remaining (rp->earliest_transmission).rel_value == 0) )
    {
      GNUNET_assert (rp == GNUNET_CONTAINER_heap_remove_root (pp->delay_heap));
      rp->hn = GNUNET_CONTAINER_heap_insert (pp->priority_heap,
					     rp, 
					     rp->priority);					
    }   
  if (0 == GNUNET_CONTAINER_heap_get_size (pp->priority_heap))
    {
      /* priority heap (still) empty, check for delay... */
      rp = GNUNET_CONTAINER_heap_peek (pp->delay_heap);
      if (NULL == rp)
	{
#if DEBUG_FS
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "No active requests for plan %p.\n",
		      pp);
#endif
	  return; /* both queues empty */
	}
#if DEBUG_FS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Sleeping for %llu ms before retrying requests on plan %p.\n",
		  (unsigned long long) GNUNET_TIME_absolute_get_remaining (rp->earliest_transmission).rel_value,
		  pp);
#endif
      pp->task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_absolute_get_remaining (rp->earliest_transmission),
					       &schedule_peer_transmission,
					       pp);
      return;
    }
  /* process from priority heap */
  rp = GNUNET_CONTAINER_heap_peek (pp->priority_heap);
#if DEBUG_FS > 1
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Executing query plan %p\n",
	      rp);
#endif    
  GNUNET_assert (NULL != rp);
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
GSF_plan_add_ (struct GSF_ConnectedPeer *cp,
	       struct GSF_PendingRequest *pr)
{
  struct GNUNET_PeerIdentity id;
  struct PeerPlan *pp;
  struct GSF_PendingRequestData *prd;
  struct GSF_RequestPlan *rp;

  GNUNET_assert (NULL != cp);
  GSF_connected_peer_get_identity_ (cp, &id);
  pp = GNUNET_CONTAINER_multihashmap_get (plans,
					  &id.hashPubKey);
  if (NULL == pp)
    {
      pp = GNUNET_malloc (sizeof (struct PeerPlan));
      pp->priority_heap = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MAX);
      pp->delay_heap = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
      pp->cp = cp;
      GNUNET_CONTAINER_multihashmap_put (plans,
					 &id.hashPubKey,
					 pp,
					 GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
    }
  prd = GSF_pending_request_get_data_ (pr);
  plan_count++;
  GNUNET_STATISTICS_update (GSF_stats,
			    gettext_noop ("# query plan entries"),
			    1,
			    GNUNET_NO);
  rp = GNUNET_malloc (sizeof (struct GSF_RequestPlan));
#if DEBUG_FS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Planning transmission of query `%s' to peer `%s' (%p)\n",
	      GNUNET_h2s (&prd->query),
	      GNUNET_i2s (&id), 
	      rp);
#endif    
  rp->pr = pr;
  GNUNET_CONTAINER_DLL_insert (prd->rp_head,
			       prd->rp_tail,
			       rp);
  plan (pp, rp);
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
  if (NULL == pp)
    return; /* nothing was ever planned for this peer */
  GNUNET_CONTAINER_multihashmap_remove (plans,
					&id.hashPubKey,
					pp);
  if (NULL != pp->pth)
    GSF_peer_transmit_cancel_ (pp->pth);
  if (GNUNET_SCHEDULER_NO_TASK != pp->task)
    {
      GNUNET_SCHEDULER_cancel (pp->task);
      pp->task = GNUNET_SCHEDULER_NO_TASK;
    }
  while (NULL != (rp = GNUNET_CONTAINER_heap_remove_root (pp->priority_heap)))
    {
      prd = GSF_pending_request_get_data_ (rp->pr);
      GNUNET_CONTAINER_DLL_remove (prd->rp_head,
				   prd->rp_tail,
				   rp);
      plan_count--;
      GNUNET_free (rp);
    }
  GNUNET_CONTAINER_heap_destroy (pp->priority_heap);
  while (NULL != (rp = GNUNET_CONTAINER_heap_remove_root (pp->delay_heap)))
    {
      prd = GSF_pending_request_get_data_ (rp->pr);
      GNUNET_CONTAINER_DLL_remove (prd->rp_head,
				   prd->rp_tail,
				   rp);
      plan_count--;
      GNUNET_free (rp);
    }
  GNUNET_STATISTICS_set (GSF_stats,
			 gettext_noop ("# query plan entries"),
			 plan_count,
			 GNUNET_NO);

  GNUNET_CONTAINER_heap_destroy (pp->delay_heap);
  GNUNET_free (pp);
}


/**
 * Notify the plan about a request being done; destroy all entries
 * associated with this request.
 *
 * @param pr request that is done
 */
void
GSF_plan_notify_request_done_ (struct GSF_PendingRequest *pr)
{
  struct GSF_RequestPlan *rp;
  struct GSF_PendingRequestData *prd;

  prd = GSF_pending_request_get_data_ (pr);
  while (NULL != (rp = prd->rp_head))
    {
      GNUNET_CONTAINER_heap_remove_node (rp->hn);
      GNUNET_CONTAINER_DLL_remove (prd->rp_head,
				   prd->rp_tail,
				   rp);
      plan_count--;
      GNUNET_free (rp);
    }
  GNUNET_STATISTICS_set (GSF_stats,
			 gettext_noop ("# query plan entries"),
			 plan_count,
			 GNUNET_NO);  
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
