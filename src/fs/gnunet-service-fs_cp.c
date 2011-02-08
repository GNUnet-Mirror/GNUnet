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
 * @file fs/gnunet-service-fs_cp.c
 * @brief API to handle 'connected peers'
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-fs.h"
#include "gnunet-service-fs_cp.h"

/**
 * How often do we flush trust values to disk?
 */
#define TRUST_FLUSH_FREQ GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 5)



/**
 * Handle to cancel a transmission request.
 */
struct GSF_PeerTransmitHandle
{

  /**
   * Handle for an active request for transmission to this
   * peer, or NULL (if core queue was full).
   */
  struct GNUNET_CORE_TransmitHandle *cth;

  /**
   * Time when this transmission request was issued.
   */
  struct GNUNET_TIME_Absolute transmission_request_start_time;

  /**
   * Timeout for this request.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Task called on timeout, or 0 for none.
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * Function to call to get the actual message.
   */
  GSF_GetMessageCallback gmc;

  /**
   * Peer this request targets.
   */
  struct GSF_ConnectedPeer *cp;

  /**
   * Closure for 'gmc'.
   */
  void *gmc_cls;

  /**
   * Size of the message to be transmitted.
   */
  size_t size;

  /**
   * GNUNET_YES if this is a query, GNUNET_NO for content.
   */
  int is_query;

  /**
   * Priority of this request.
   */
  uint32_t priority;

};


/**
 * A connected peer.
 */
struct GSF_ConnectedPeer 
{

  /**
   * Performance data for this peer.
   */
  struct GSF_PeerPerformanceData ppd;

  /**
   * Time until when we blocked this peer from migrating
   * data to us.
   */
  struct GNUNET_TIME_Absolute last_migration_block;

  /**
   * Messages (replies, queries, content migration) we would like to
   * send to this peer in the near future.  Sorted by priority, head.
   */
  struct GSF_PeerTransmitHandle *pth_head;

  /**
   * Messages (replies, queries, content migration) we would like to
   * send to this peer in the near future.  Sorted by priority, tail.
   */
  struct GSF_PeerTransmitHandle *pth_tail;

  /**
   * Context of our GNUNET_CORE_peer_change_preference call (or NULL).
   * NULL if we have successfully reserved 32k, otherwise non-NULL.
   */
  struct GNUNET_CORE_InformationRequestContext *irc;

  /**
   * ID of delay task for scheduling transmission.
   */
  GNUNET_SCHEDULER_TaskIdentifier delayed_transmission_request_task; // FIXME: unused!

  /**
   * Increase in traffic preference still to be submitted
   * to the core service for this peer.
   */
  uint64_t inc_preference;

  /**
   * Trust rating for this peer
   */
  uint32_t trust;

  /**
   * Trust rating for this peer on disk.
   */
  uint32_t disk_trust;

  /**
   * The peer's identity.
   */
  GNUNET_PEER_Id pid;

  /**
   * Which offset in "last_p2p_replies" will be updated next?
   * (we go round-robin).
   */
  unsigned int last_p2p_replies_woff;

  /**
   * Which offset in "last_client_replies" will be updated next?
   * (we go round-robin).
   */
  unsigned int last_client_replies_woff;

  /**
   * Current offset into 'last_request_times' ring buffer.
   */
  unsigned int last_request_times_off;

};


/**
 * Map from peer identities to 'struct GSF_ConnectPeer' entries.
 */
static struct GNUNET_CONTAINER_MultiHashMap *cp_map;


/**
 * Where do we store trust information?
 */
static char *trustDirectory;


/**
 * Get the filename under which we would store the GNUNET_HELLO_Message
 * for the given host and protocol.
 * @return filename of the form DIRECTORY/HOSTID
 */
static char *
get_trust_filename (const struct GNUNET_PeerIdentity *id)
{
  struct GNUNET_CRYPTO_HashAsciiEncoded fil;
  char *fn;

  GNUNET_CRYPTO_hash_to_enc (&id->hashPubKey, &fil);
  GNUNET_asprintf (&fn, "%s%s%s", trustDirectory, DIR_SEPARATOR_STR, &fil);
  return fn;
}


/**
 * Find latency information in 'atsi'.
 *
 * @param atsi performance data
 * @return connection latency
 */
static struct GNUNET_TIME_Relative
get_latency (const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
  if (atsi == NULL)
    return GNUNET_TIME_UNIT_SECONDS;
  while ( (ntohl (atsi->type) != GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR) &&
	  (ntohl (atsi->type) != GNUNET_TRANSPORT_ATS_QUALITY_NET_DELAY) )
    atsi++;
  if (ntohl (atsi->type) == GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR) 
    {
      GNUNET_break (0);
      /* how can we not have latency data? */
      return GNUNET_TIME_UNIT_SECONDS;
    }
  return GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS,
					ntohl (atsi->value));
}


/**
 * Update the performance information kept for the given peer.
 *
 * @param cp peer record to update
 * @param atsi transport performance data
 */
static void
update_atsi (struct GSF_ConnectedPeer *cp,
	     const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
  struct GNUNET_TIME_Relative latency;

  latency = get_latency (atsi);
  GNUNET_LOAD_value_set_decline (cp->transmission_delay,
				 latency);
  /* LATER: merge atsi into cp's performance data (if we ever care...) */
}


/**
 * Core is ready to transmit to a peer, get the message.
 *
 * @param cls the 'struct GSF_PeerTransmitHandle' of the message
 * @param size number of bytes core is willing to take
 * @param buf where to copy the message
 * @return number of bytes copied to buf
 */
static size_t
peer_transmit_ready_cb (void *cls,
			size_t size,
			void *buf)
{
  struct GSF_PeerTransmitHandle *pth = cls;
  struct GSF_ConnectedPeer *cp;
  size_t ret;

  if (pth->timeout_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (pth->timeout_task);
      pth->timeout_task = GNUNET_SCHEDULER_NO_TASK;
    }
  cp = pth->cp;
  GNUNET_CONTAINER_DLL_remove (cp->pth_head,
			       cp->pth_tail,
			       pth);
  if (pth->is_query)
    {
      cp->ppd.last_request_times[(cp->last_request_times_off++) % MAX_QUEUE_PER_PEER] = GNUNET_TIME_absolute_get ();
      GNUNET_assert (0 < cp->ppd.pending_queries--);    
    }
  else
    {
      GNUNET_assert (0 < cp->ppd.pending_replies--);
    }
  GNUNET_LOAD_update (cp->ppd.transmission_delay,
		      GNUNET_TIME_absolute_get_duration (pth->request_start_time).rel_value);  
  ret = pth->gmc (pth->gmc_cls, 
		  0, NULL);
  GNUNET_free (pth);  
  return ret;
}


/**
 * Function called by core upon success or failure of our bandwidth reservation request.
 *
 * @param cls the 'struct GSF_ConnectedPeer' of the peer for which we made the request
 * @param peer identifies the peer
 * @param bandwidth_out available amount of outbound bandwidth
 * @param amount set to the amount that was actually reserved or unreserved;
 *               either the full requested amount or zero (no partial reservations)
 * @param preference current traffic preference for the given peer
 */
static void
core_reserve_callback (void *cls,
		       const struct GNUNET_PeerIdentity * peer,
		       struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
		       int amount,
		       uint64_t preference)
{
  struct GSF_ConnectedPeer *cp = cls;
  uint64_t ip;

  cp->irc = NULL;
  if (0 == amount)
    {
      /* failed; retry! (how did we get here!?) */
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Failed to reserve bandwidth to peer `%s'\n"),
		  GNUNET_i2s (peer));
      ip = cp->inc_preference;
      cp->inc_preference = 0;
      cp->irc = GNUNET_CORE_peer_change_preference (core,
						    peer,
						    GNUNET_TIME_UNIT_FOREVER_REL,
						    GNUNET_BANDWIDTH_VALUE_MAX,
						    GNUNET_FS_DBLOCK_SIZE,
						    ip,
						    &core_reserve_callback,
						    cp);
      return;
    }
  pth = cp->pth_head;
  if ( (NULL != pth) &&
       (NULL == pth->cth) )
    {
      /* reservation success, try transmission now! */
      pth->cth = GNUNET_CORE_notify_transmit_ready (core,
						    priority,
						    GNUNET_TIME_absolute_get_remaining (pth->timeout),
						    &target,
						    size,
						    &peer_transmit_ready_cb,
						    pth);
    }
}


/**
 * A peer connected to us.  Setup the connected peer
 * records.
 *
 * @param peer identity of peer that connected
 * @param atsi performance data for the connection
 * @return handle to connected peer entry
 */
struct GSF_ConnectedPeer *
GSF_peer_connect_handler_ (const struct GNUNET_PeerIdentity *peer,
			   const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
  struct GSF_ConnectedPeer *cp;
  char *fn;
  uint32_t trust;
  struct GNUNET_TIME_Relative latency;

  cp = GNUNET_malloc (sizeof (struct GSF_ConnectedPeer));
  cp->transmission_delay = GNUNET_LOAD_value_init (latency);
  cp->pid = GNUNET_PEER_intern (peer);
  cp->transmission_delay = GNUNET_LOAD_value_init (0);
  cp->irc = GNUNET_CORE_peer_change_preference (core,
						peer,
						GNUNET_TIME_UNIT_FOREVER_REL,
						GNUNET_BANDWIDTH_VALUE_MAX,
						GNUNET_FS_DBLOCK_SIZE,
						0,
						&core_reserve_callback,
						cp);
  fn = get_trust_filename (peer);
  if ((GNUNET_DISK_file_test (fn) == GNUNET_YES) &&
      (sizeof (trust) == GNUNET_DISK_fn_read (fn, &trust, sizeof (trust))))
    cp->disk_trust = cp->trust = ntohl (trust);
  GNUNET_free (fn);
  GNUNET_break (GNUNET_OK ==
		GNUNET_CONTAINER_multihashmap_put (cp_map,
						   &peer->hashPubKey,
						   cp,
						   GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  update_atsi (cp, atsi);
  GSF_plan_notify_new_peer_ (cp);
  return cp;
}


/**
 * Handle P2P "MIGRATION_STOP" message.
 *
 * @param cls closure, always NULL
 * @param other the other peer involved (sender or receiver, NULL
 *        for loopback messages where we are both sender and receiver)
 * @param message the actual message
 * @param atsi performance information
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
GSF_handle_p2p_migration_stop_ (void *cls,
				const struct GNUNET_PeerIdentity *other,
				const struct GNUNET_MessageHeader *message,
				const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
  struct GSF_ConnectedPeer *cp; 
  const struct MigrationStopMessage *msm;

  msm = (const struct MigrationStopMessage*) message;
  cp = GNUNET_CONTAINER_multihashmap_get (cp_map,
					  &other->hashPubKey);
  if (cp == NULL)
    {
      GNUNET_break (0);
      return GNUNET_OK;
    }
  cp->ppd.migration_blocked = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_relative_ntoh (msm->duration));
  update_atsi (cp, atsi);
  return GNUNET_OK;
}


/**
 * Handle P2P "QUERY" message.
 *
 * @param other the other peer involved (sender or receiver, NULL
 *        for loopback messages where we are both sender and receiver)
 * @param message the actual message
 * @return pending request handle, NULL on error
 */
struct GSF_PendingRequest *
GSF_handle_p2p_query_ (const struct GNUNET_PeerIdentity *other,
		       const struct GNUNET_MessageHeader *message)
{
  // FIXME!
  // parse request
  // setup pending request
  // track pending request to cancel it on peer disconnect (!)
  // return it!
  // (actual planning & execution up to caller!)
  return NULL;
}


/**
 * Function called if there has been a timeout trying to satisfy
 * a transmission request.
 *
 * @param cls the 'struct GSF_PeerTransmitHandle' of the request 
 * @param tc scheduler context
 */
static void
peer_transmit_timeout (void *cls,
		       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GSF_PeerTransmitHandle *pth = cls;
  struct GSF_ConnectedPeer *cp;
  
  pth->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  cp = pth->cp;
  GNUNET_CONTAINER_DLL_remove (cp->pth_head,
			       cp->pth_tail,
			       pth);
  if (pth->is_query)
    GNUNET_assert (0 < cp->ppd.pending_queries--);    
  else
    GNUNET_assert (0 < cp->ppd.pending_replies--);
  GNUNET_LOAD_update (cp->ppd.transmission_delay,
		      UINT64_MAX);
  pth->gmc (pth->gmc_cls, 
	    0, NULL);
  GNUNET_free (pth);
}


/**
 * Transmit a message to the given peer as soon as possible.
 * If the peer disconnects before the transmission can happen,
 * the callback is invoked with a 'NULL' buffer.
 *
 * @param peer target peer
 * @param is_query is this a query (GNUNET_YES) or content (GNUNET_NO)
 * @param priority how important is this request?
 * @param timeout when does this request timeout (call gmc with error)
 * @param size number of bytes we would like to send to the peer
 * @param gmc function to call to get the message
 * @param gmc_cls closure for gmc
 * @return handle to cancel request
 */
struct GSF_PeerTransmitHandle *
GSF_peer_transmit_ (struct GSF_ConnectedPeer *peer,
		    int is_query,
		    uint32_t priority,
		    struct GNUNET_TIME_Relative timeout,
		    size_t size,
		    GSF_GetMessageCallback gmc,
		    void *gmc_cls)
{
  struct GSF_ConnectedPeer *cp;
  struct GSF_PeerTransmitHandle *pth;
  struct GSF_PeerTransmitHandle *pos;
  struct GSF_PeerTransmitHandle *prev;
  struct GNUNET_PeerIdentity target;
  uint64_t ip;
  int is_ready;

  cp = GNUNET_CONTAINER_multihashmap_get (cp_map,
					  &peer->hashPubKey);
  GNUNET_assert (NULL != cp);
  pth = GNUNET_malloc (sizeof (struct GSF_PeerTransmitHandle));
  pth->transmission_request_start_time = GNUNET_TIME_absolute_now ();
  pth->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  pth->gmc = gmc;
  pth->gmc_cls = gmc_cls;
  pth->size = size;
  pth->is_query = is_query;
  pth->priority = priority;
  pth->cp = cp;
  /* insertion sort (by priority, descending) */
  prev = NULL;
  pos = cp->pth_head;
  while ( (pos != NULL) &&
	  (pos->priority > priority) )
    {
      prev = pos;
      pos = pos->next;
    }
  if (prev == NULL)
    GNUNET_CONTAINER_DLL_insert_head (cp->pth_head,
				      cp->pth_tail,
				      pth);
  else
    GNUNET_CONTAINER_DLL_insert_after (cp->pth_head,
				       cp->pth_tail,
				       prev,
				       pth);
  GNUNET_PEER_resolve (cp->pid,
		       &target);
  if (is_query)
    {
      /* query, need reservation */
      if (NULL == cp->irc)
	{
	  /* reservation already done! */
	  is_ready = GNUNET_YES;
	  ip = cp->inc_preference;
	  cp->inc_preference = 0;
	  cp->irc = GNUNET_CORE_peer_change_preference (core,
							peer,
							GNUNET_TIME_UNIT_FOREVER_REL,
							GNUNET_BANDWIDTH_VALUE_MAX,
							GNUNET_FS_DBLOCK_SIZE,
							ip,
							&core_reserve_callback,
							cp);	  
	}
      else
	{
	  /* still waiting for reservation */
	  is_ready = GNUNET_NO;
	}
    }
  else
    {
      /* no reservation needed for content */
      is_ready = GNUNET_YES;
    }
  if (is_ready)
    {
      pth->cth = GNUNET_CORE_notify_transmit_ready (core,
						    priority,
						    timeout,
						    &target,
						    size,
						    &peer_transmit_ready_cb,
						    pth);
      /* pth->cth could be NULL here, that's OK, we'll try again
	 later... */
    }
  if (pth->cth == NULL)
    {
      /* if we're waiting for reservation OR if we could not do notify_transmit_ready,
	 install a timeout task to be on the safe side */
      pth->timeout_task = GNUNET_SCHEDULER_add_delayed (timeout,
							&peer_transmit_timeout,
							pth);
    }
  return pth;
}


/**
 * Cancel an earlier request for transmission.
 *
 * @param pth request to cancel
 */
void
GSF_peer_transmit_cancel_ (struct GSF_PeerTransmitHandle *pth)
{
  struct GSF_PeerTransmitHandle *pth = cls;
  struct GSF_ConnectedPeer *cp;

  if (pth->timeout_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (pth->timeout_task);
      pth->timeout_task = GNUNET_SCHEDULER_NO_TASK;
    }
  if (NULL != pth->cth)
    {
      GNUNET_CORE_notify_transmit_ready_cancel (pth->cth);
      pth->cth = NULL;
    }
  cp = pth->cp;
  GNUNET_CONTAINER_DLL_remove (cp->pth_head,
			       cp->pth_tail,
			       pth);
  if (pth->is_query)
    GNUNET_assert (0 < cp->ppd.pending_queries--);    
  else
    GNUNET_assert (0 < cp->ppd.pending_replies--);
  GNUNET_free (pth);
}


/**
 * Report on receiving a reply; update the performance record of the given peer.
 *
 * @param cp responding peer (will be updated)
 * @param request_time time at which the original query was transmitted
 * @param request_priority priority of the original request
 * @param initiator_client local client on responsible for query (or NULL)
 * @param initiator_peer other peer responsible for query (or NULL)
 */
void
GSF_peer_update_performance_ (struct GSF_ConnectedPeer *cp,
			      struct GNUNET_TIME_Absolute request_time,
			      uint32_t request_priority,
			      const struct GSF_LocalClient *initiator_client,
			      const struct GSF_ConnectedPeer *initiator_peer)
{
  struct GNUNET_TIME_Relative delay;
  unsigned int i;

  delay = GNUNET_TIME_absolute_get_duration (request_time);  
  cp->ppd.avg_reply_delay = (cp->ppd.avg_reply_delay * (RUNAVG_DELAY_N-1) + delay.rel_value) / RUNAVG_DELAY_N;
  cp->ppd.avg_priority = (cp->avg_priority * (RUNAVG_DELAY_N-1) + request_priority) / RUNAVG_DELAY_N;
  if (NULL != initiator_client)
    {
      cp->ppd.last_client_replies[cp->last_client_replies_woff++ % CS2P_SUCCESS_LIST_SIZE] = initiator_client;
    }
  else if (NULL != initiator_peer)
    {
      GNUNET_PEER_change_rc (cp->ppd.last_p2p_replies[cp->last_p2p_replies_woff % P2P_SUCCESS_LIST_SIZE], -1);
      cp->ppd.last_p2p_replies[cp->last_p2p_replies_woff++ % P2P_SUCCESS_LIST_SIZE] = initiator_peer->pid;
      GNUNET_PEER_change_rc (initiator_peer->pid, 1);
    }
  else
    GNUNET_break (0);
}


/**
 * Method called whenever a given peer has a status change.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param bandwidth_in available amount of inbound bandwidth
 * @param bandwidth_out available amount of outbound bandwidth
 * @param timeout absolute time when this peer will time out
 *        unless we see some further activity from it
 * @param atsi status information
 */
void
GSF_peer_status_handler_ (void *cls,
			  const struct GNUNET_PeerIdentity *peer,
			  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in,
			  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
			  struct GNUNET_TIME_Absolute timeout,
			  const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
  struct GSF_ConnectedPeer *cp;

  cp = GNUNET_CONTAINER_multihashmap_get (cp_map,
					  &peer->hashPubKey);
  GNUNET_assert (NULL != cp);
  update_atsi (cp, atsi);
}


/**
 * A peer disconnected from us.  Tear down the connected peer
 * record.
 *
 * @param cls unused
 * @param peer identity of peer that connected
 */
void
GSF_peer_disconnect_handler_ (void *cls,
			      const struct GNUNET_PeerIdentity *peer)
{
  struct GSF_ConnectedPeer *cp;
  struct GSF_PeerTransmitHandle *pth;

  cp = GNUNET_CONTAINER_multihashmap_get (cp_map,
					  &peer->hashPubKey);
  GNUNET_assert (NULL != cp);
  GNUNET_CONTAINER_multihashmap_remove (cp_map,
					&peer->hashPubKey,
					cp);
  if (NULL != cp->irc)
    {
      GNUNET_CORE_peer_change_preference_cancel (cp->irc);
      cp->irc = NULL;
    }
  GSF_plan_notify_peer_disconnect_ (cp);
  GNUNET_LOAD_value_free (cp->ppd.transmission_delay);
  GNUNET_PEER_decrement_rcs (cp->ppd.last_p2p_replies, P2P_SUCCESS_LIST_SIZE);
  while (NULL != (pth = cp->pth_head))
    {
      if (NULL != pth->th)
	{
	  GNUNET_CORE_notify_transmit_ready_cancel (pth->th);
	  pth->th = NULL;
	}
      GNUNET_CONTAINER_DLL_remove (cp->pth_head,
				   cp->pth_tail,
				   pth);
      GNUNET_free (pth);
    }
  GNUNET_PEER_change_rc (cp->pid, -1);
  GNUNET_free (cp);
}


/**
 * Closure for 'call_iterator'.
 */
struct IterationContext
{
  /**
   * Function to call on each entry.
   */
  GSF_ConnectedPeerIterator it;

  /**
   * Closure for 'it'.
   */
  void *it_cls;
};


/**
 * Function that calls the callback for each peer.
 *
 * @param cls the 'struct IterationContext*'
 * @param key identity of the peer
 * @param value the 'struct GSF_ConnectedPeer*'
 * @return GNUNET_YES to continue iteration
 */
static int
call_iterator (void *cls,
	       const GNUNET_HashCode *key,
	       void *value)
{
  struct IterationContext *ic = cls;
  struct GSF_ConnectedPeer *cp = value;
  
  ic->it (ic->it_cls,
	  (const struct GNUNET_PeerIdentity*) key,
	  cp,
	  &cp->ppd);
  return GNUNET_YES;
}


/**
 * Iterate over all connected peers.
 *
 * @param it function to call for each peer
 * @param it_cls closure for it
 */
void
GSF_iterate_connected_peers_ (GSF_ConnectedPeerIterator it,
			      void *it_cls)
{
  struct IterationContext ic;

  ic.it = it;
  ic.it_cls = it_cls;
  GNUNET_CONTAINER_multihashmap_iterate (cp_map,
					 &call_iterator,
					 &ic);
}


/**
 * Obtain the identity of a connected peer.
 *
 * @param cp peer to reserve bandwidth from
 * @param id identity to set (written to)
 */
void
GSF_connected_peer_get_identity_ (const struct GSF_ConnectedPeer *cp,
				  struct GNUNET_PeerIdentity *id)
{
  GNUNET_PEER_resolve (cp->pid,
		       &id);
}


/**
 * Write host-trust information to a file - flush the buffer entry!
 *
 * @param cls closure, not used
 * @param key host identity
 * @param value the 'struct GSF_ConnectedPeer' to flush
 * @return GNUNET_OK to continue iteration
 */
static int
flush_trust (void *cls,
	     const GNUNET_HashCode *key,
	     void *value)
{
  struct GSF_ConnectedPeer *cp = value;
  char *fn;
  uint32_t trust;
  struct GNUNET_PeerIdentity pid;

  if (cp->trust == cp->disk_trust)
    return GNUNET_OK;                     /* unchanged */
  GNUNET_PEER_resolve (cp->pid,
		       &pid);
  fn = get_trust_filename (&pid);
  if (cp->trust == 0)
    {
      if ((0 != UNLINK (fn)) && (errno != ENOENT))
        GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING |
                                  GNUNET_ERROR_TYPE_BULK, "unlink", fn);
    }
  else
    {
      trust = htonl (cp->trust);
      if (sizeof(uint32_t) == GNUNET_DISK_fn_write (fn, &trust, 
						    sizeof(uint32_t),
						    GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE
						    | GNUNET_DISK_PERM_GROUP_READ | GNUNET_DISK_PERM_OTHER_READ))
        cp->disk_trust = cp->trust;
    }
  GNUNET_free (fn);
  return GNUNET_OK;
}


/**
 * Notify core about a preference we have for the given peer
 * (to allocate more resources towards it).  The change will
 * be communicated the next time we reserve bandwidth with
 * core (not instantly).
 *
 * @param cp peer to reserve bandwidth from
 * @param pref preference change
 */
void
GSF_connected_peer_change_preference_ (struct GSF_ConnectedPeer *cp,
				       uint64_t pref)
{
  cp->inc_preference += pref;
}


/**
 * Call this method periodically to flush trust information to disk.
 *
 * @param cls closure, not used
 * @param tc task context, not used
 */
static void
cron_flush_trust (void *cls,
		  const struct GNUNET_SCHEDULER_TaskContext *tc)
{

  if (NULL == cp_map)
    return;
  GNUNET_CONTAINER_multihashmap_iterate (cp_map,
					 &flush_trust,
					 NULL);
  if (NULL == tc)
    return;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  GNUNET_SCHEDULER_add_delayed (TRUST_FLUSH_FREQ, 
				&cron_flush_trust, 
				NULL);
}


/**
 * Initialize peer management subsystem.
 *
 * @param cfg configuration to use
 */
void
GSF_connected_peer_init_ (struct GNUNET_CONFIGURATION_Handle *cfg)
{
  cp_map = GNUNET_CONTAINER_multihashmap_create (128);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_filename (cfg,
                                                          "fs",
                                                          "TRUST",
                                                          &trustDirectory));
  GNUNET_DISK_directory_create (trustDirectory);
  GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_HIGH,
				      &cron_flush_trust, NULL);
}


/**
 * Iterator to free peer entries.
 *
 * @param cls closure, unused
 * @param key current key code
 * @param value value in the hash map (peer entry)
 * @return GNUNET_YES (we should continue to iterate)
 */
static int 
clean_peer (void *cls,
	    const GNUNET_HashCode * key,
	    void *value)
{
  GSF_peer_disconnect_handler_ (NULL, 
				(const struct GNUNET_PeerIdentity*) key);
  return GNUNET_YES;
}


/**
 * Shutdown peer management subsystem.
 */
void
GSF_connected_peer_done_ ()
{
  cron_flush_trust (NULL, NULL);
  GNUNET_CONTAINER_multihashmap_iterate (cp_map,
					 &clean_peer,
					 NULL);
  GNUNET_CONTAINER_multihashmap_destroy (cp_map);
  cp_map = NULL;
  GNUNET_free (trustDirectory);
  trustDirectory = NULL;
}


/**
 * Iterator to remove references to LC entry.
 *
 * @param the 'struct GSF_LocalClient*' to look for
 * @param key current key code
 * @param value value in the hash map (peer entry)
 * @return GNUNET_YES (we should continue to iterate)
 */
static int 
clean_peer (void *cls,
	    const GNUNET_HashCode * key,
	    void *value)
{
  const struct GSF_LocalClient *lc = cls;
  struct GSF_ConnectedPeer *cp = value;
  unsigned int i;

  for (i=0;i<CS2P_SUCCESS_LIST_SIZE;i++)
    if (cp->ppd.last_client_replies[i] == lc)
      cp->ppd.last_client_replies[i] = NULL;
  return GNUNET_YES;
}


/**
 * Notification that a local client disconnected.  Clean up all of our
 * references to the given handle.
 *
 * @param lc handle to the local client (henceforth invalid)
 */
void
GSF_handle_local_client_disconnect_ (const struct GSF_LocalClient *lc)
{
  GNUNET_CONTAINER_multihashmap_iterate (cp_map,
					 &clean_local_client,
					 (void*) lc);
}


/* end of gnunet-service-fs_cp.c */
