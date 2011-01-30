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
   */
  struct GNUNET_CORE_InformationRequestContext *irc;

  /**
   * ID of delay task for scheduling transmission.
   */
  GNUNET_SCHEDULER_TaskIdentifier delayed_transmission_request_task;

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
  // FIXME: merge atsi into cp's performance data!
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


  // FIXME: notify plan & migration about new peer!
  
  return cp;
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

  cp = pth->cp;
  GNUNET_CONTAINER_DLL_remove (cp->pth_head,
			       cp->pth_tail,
			       pth);
  // FIXME: update 'cp' counters!
  ret = pth->gmc (pth->gmc_cls, 
		  0, NULL);
  GNUNET_free (pth);  
  return ret;
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
  // FIXME: update 'cp' counters!
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
  pth->cth = GNUNET_CORE_notify_transmit_ready (core,
						priority,
						timeout,
						&target,
						size,
						&peer_transmit_ready_cb,
						pth);
  /* pth->cth could be NULL here, that's OK, we'll try again
     later... */
  if (pth->cth == NULL)
    pth->timeout_task = GNUNET_SCHEDULER_add_delayed (timeout,
						      &peer_transmit_timeout,
						      pth);
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
  cp = pth->cp;
  GNUNET_CONTAINER_DLL_remove (cp->pth_head,
			       cp->pth_tail,
			       pth);
  // FIXME: update 'cp' counters!
  GNUNET_free (pth);
}


/**
 * Report on receiving a reply; update the performance record of the given peer.
 *
 * @param peer responding peer (will be updated)
 * @param request_time time at which the original query was transmitted
 * @param request_priority priority of the original request
 * @param initiator_client local client on responsible for query (or NULL)
 * @param initiator_peer other peer responsible for query (or NULL)
 */
void
GSF_peer_update_performance_ (struct GSF_ConnectedPeer *peer,
			      GNUNET_TIME_Absolute request_time,
			      uint32_t request_priority,
			      const struct GSF_LocalClient *initiator_client,
			      const struct GSF_ConnectedPeer *initiator_peer)
{
  // FIXME...
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

  cp = GNUNET_CONTAINER_multihashmap_get (cp_map,
					  &peer->hashPubKey);
  GNUNET_assert (NULL != cp);
  GNUNET_CONTAINER_multihashmap_remove (cp_map,
					&peer->hashPubKey,
					cp);
  // FIXME: more cleanup
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
 * Try to reserve bandwidth (to receive data FROM the given peer).
 * This function must only be called ONCE per connected peer at a
 * time; it can be called again after the 'rc' callback was invoked.
 * If the peer disconnects, the request is (silently!) ignored (and
 * the requester is responsible to register for notification about the
 * peer disconnect if any special action needs to be taken in this
 * case).
 *
 * @param cp peer to reserve bandwidth from
 * @param size number of bytes to reserve
 * @param rc function to call upon reservation success or failure
 * @param rc_cls closure for rc
 */
void
GSF_connected_peer_reserve_ (struct GSF_ConnectedPeer *cp,
			     size_t size,
			     GSF_PeerReserveCallback rc,
			     void *rc_cls)
{
  // FIXME: should we allow queueing multiple reservation requests?
  // FIXME: what about cancellation?
  // FIXME: change docu on peer disconnect handling?
  if (NULL != cp->irc)
    {
      rc (rc_cls, cp, GNUNET_NO);
      return;
    }
  // FIXME...
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
  GNUNET_CONTAINER_multihashmap_iterate (cp_peers,
					 &clean_peer,
					 NULL);
  GNUNET_CONTAINER_multihashmap_destroy (cp_map);
  cp_map = NULL;
  GNUNET_free (trustDirectory);
  trustDirectory = NULL;
}



#endif
/* end of gnunet-service-fs_cp.h */
