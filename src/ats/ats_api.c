/*
     This file is part of GNUnet.
     (C) 2010,2011 Christian Grothoff (and other contributing authors)

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
 * @file ats/ats_api.c
 * @brief automatic transport selection API
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_ats_service.h"

// NOTE: this implementation is simply supposed
// to implement a simplistic strategy in-process;
// in the future, we plan to replace it with a real
// service implementation

/**
 * Allocation record for a peer's address.
 */
struct AllocationRecord
{

  /**
   * Public key of the peer.
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded public_key;                                                

  /**
   * Performance information associated with this address (array).
   */
  struct GNUNET_TRANSPORT_ATS_Information *ats;

  /**
   * Name of the plugin
   */
  char *plugin_name;

  /**
   * Address this record represents, allocated at the end of this struct.
   */
  const void *plugin_addr;

  /**
   * Session associated with this record.
   */
  struct Session *session;

  /**
   * Number of bytes in plugin_addr.
   */
  size_t plugin_addr_len;	     

  /**
   * Number of entries in 'ats'.
   */
  uint32_t ats_count;

  /**
   * Bandwidth assigned to this address right now, 0 for none.
   */
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth;

  /**
   * Set to GNUNET_YES if this is the connected address of a connected peer.
   */
  int connected;

};


/**
 * Opaque handle to stop incremental validation address callbacks.
 */
struct GNUNET_ATS_SuggestionContext
{

  /**
   * Function to call with our final suggestion.
   */
  GNUNET_ATS_AddressSuggestionCallback cb;

  /**
   * Closure for 'cb'.
   */
  void *cb_cls;

  /**
   * Global ATS handle.
   */ 
  struct GNUNET_ATS_Handle *atc;

  /**
   * Which peer are we monitoring?
   */   
  struct GNUNET_PeerIdentity target;

};


/**
 * Handle to the ATS subsystem.
 */
struct GNUNET_ATS_Handle
{
  /**
   * Configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Function to call when the allocation changes.
   */
  GNUNET_TRANSPORT_ATS_AllocationNotification alloc_cb;

  /**
   * Closure for 'alloc_cb'.
   */
  void *alloc_cb_cls;

  /**
   * Information about all connected peers.  Maps peer identities
   * to one or more 'struct AllocationRecord' values.
   */
  struct GNUNET_CONTAINER_MultiHashMap *peers;

  /**
   * Map of PeerIdentities to 'struct GNUNET_ATS_SuggestionContext's.
   */
  struct GNUNET_CONTAINER_MultiHashMap *notify_map;


  /**
   * Task scheduled to update our bandwidth assignment.
   */
  GNUNET_SCHEDULER_TaskIdentifier ba_task;

  /**
   * Total bandwidth per configuration.
   */
  unsigned long long total_bps;
};


/**
 * Count number of connected records.
 *
 * @param cls pointer to counter
 * @param key identity of the peer associated with the records
 * @param value a 'struct AllocationRecord' 
 * @return GNUNET_YES (continue iteration)
 */
static int
count_connections (void *cls,
		   const GNUNET_HashCode *key,
		   void *value)
{
  unsigned int *ac = cls;
  struct AllocationRecord *ar = value;
  
  if (GNUNET_YES == ar->connected)
    (*ac)++;
  return GNUNET_YES;
}


/**
 * Closure for 'set_bw_connections'.
 */
struct SetBandwidthContext
{
  /**
   * ATS handle.
   */
  struct GNUNET_ATS_Handle *atc;

  /**
   * Bandwidth to assign.
   */
  struct GNUNET_BANDWIDTH_Value32NBO bw;
};


/**
 * Set bandwidth based on record.
 *
 * @param cls 'struct SetBandwidthContext'
 * @param key identity of the peer associated with the records
 * @param value a 'struct AllocationRecord' 
 * @return GNUNET_YES (continue iteration)
 */
static int
set_bw_connections (void *cls,
		    const GNUNET_HashCode *key,
		    void *value)
{
  struct SetBandwidthContext *sbc = cls;
  struct AllocationRecord *ar = value;
  
  if (GNUNET_YES == ar->connected)
    {
      ar->bandwidth = sbc->bw;
      sbc->atc->alloc_cb (sbc->atc->alloc_cb_cls,
			  (const struct GNUNET_PeerIdentity*) key,
			  ar->plugin_name,
			  ar->session,
			  ar->plugin_addr,
			  ar->plugin_addr_len,
			  ar->bandwidth);
    }
  else if (ntohl(ar->bandwidth.value__) > 0)
    {
      ar->bandwidth = GNUNET_BANDWIDTH_value_init (0);
      sbc->atc->alloc_cb (sbc->atc->alloc_cb_cls,
			  (const struct GNUNET_PeerIdentity*) key,
			  ar->plugin_name,
			  ar->session,
			  ar->plugin_addr,
			  ar->plugin_addr_len,
			  ar->bandwidth);
    }
  return GNUNET_YES;
}


/**
 * Task run to update bandwidth assignments.
 *
 * @param cls the 'struct GNUNET_ATS_Handle'
 * @param tc scheduler context
 */ 
static void
update_bandwidth_task (void *cls,
		       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_ATS_Handle *atc = cls;
  unsigned int ac;
  struct SetBandwidthContext bwc;

  atc->ba_task = GNUNET_SCHEDULER_NO_TASK;
  /* FIXME: update calculations NICELY; what follows is a naive version */
  GNUNET_CONTAINER_multihashmap_iterate (atc->peers,
					 &count_connections,
					 &ac);
  bwc.atc = atc;
  bwc.bw = GNUNET_BANDWIDTH_value_init (atc->total_bps / ac);
  GNUNET_CONTAINER_multihashmap_iterate (atc->peers,
					 &set_bw_connections,
					 &bwc);
}


/**
 * Calculate an updated bandwidth assignment and notify.
 *
 * @param ats handle
 * @param change which allocation record changed?
 */
static void
update_bandwidth_assignment (struct GNUNET_ATS_Handle *atc,
			     struct AllocationRecord *change)
{
  /* FIXME: based on the 'change', update the LP-problem... */
  if (atc->ba_task == GNUNET_SCHEDULER_NO_TASK)
    atc->ba_task = GNUNET_SCHEDULER_add_now (&update_bandwidth_task,
					     atc);
}


/**
 * Function called with feasbile addresses we might want to suggest.
 *
 * @param cls the 'struct GNUNET_ATS_SuggestionContext'
 * @param key identity of the peer
 * @param value a 'struct AllocationRecord' for the peer
 * @return GNUNET_NO if we're done, GNUNET_YES if we did not suggest an address yet
 */
static int
suggest_address (void *cls,
		 const GNUNET_HashCode *key,
		 void *value)
{
  struct GNUNET_ATS_SuggestionContest *asc = cls;
  struct AllocationRecord *ar = value;

  // FIXME...
  return GNUNET_YES;
}


/**
 * We would like to establish a new connection with a peer.
 * ATS should suggest a good address to begin with.
 *
 * @param atc handle
 * @param peer identity of the new peer
 * @param cb function to call with the address
 * @param cb_cls closure for cb
 */
struct GNUNET_ATS_SuggestionContext *
GNUNET_ATS_suggest_address (struct GNUNET_ATS_Handle *atc,
			    const struct GNUNET_PeerIdentity *peer,
			    GNUNET_ATS_AddressSuggestionCallback cb,
			    void *cb_cls)
{
  struct GNUNET_ATS_SuggestionContext *asc;

  asc = GNUNET_malloc (sizeof (struct GNUNET_ATS_SuggestionContext));
  asc->cb = cb;
  asc->cb_cls = cb_cls;
  asc->atc = atc;
  asc->target = *peer;
  GNUNET_CONTAINER_multihashmap_get_multiple (atc->peers,
                                              &peer->hashPubKey,
                                              &suggest_address,
					      asc);
  if (NULL == asc->cb)
    {
      GNUNET_free (asc);
      return NULL;
    }
  GNUNET_CONTAINER_multihashmap_put (atc->notify_map,
				     &peer->hashPubKey,
				     asc,
				     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  return asc;
}


/**
 * Cancel suggestion request.
 *
 * @param asc handle of the request to cancel
 */
void
GNUNET_ATS_suggest_address_cancel (struct GNUNET_ATS_SuggestionContext *asc)
{
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CONTAINER_multihashmap_remove (asc->atc->notify_map,
						       &asc->target.hashPubKey,
						       asc));
  GNUNET_free (asc);
}


/**
 * Initialize the ATS subsystem.
 *
 * @param cfg configuration to use
 * @param alloc_cb notification to call whenever the allocation changed
 * @param alloc_cb_cls closure for 'alloc_cb'
 * @return ats context
 */
struct GNUNET_ATS_Handle *
GNUNET_ATS_init (const struct GNUNET_CONFIGURATION_Handle *cfg,
		 GNUNET_TRANSPORT_ATS_AllocationNotification alloc_cb,
		 void *alloc_cb_cls)
{
  struct GNUNET_ATS_Handle *atc;

  atc = GNUNET_malloc (sizeof (struct GNUNET_ATS_Handle));
  atc->cfg = cfg;
  atc->alloc_cb = alloc_cb;
  atc->alloc_cb_cls = alloc_cb_cls;
  atc->peers = GNUNET_CONTAINER_multihashmap_create (256);
  GNUNET_CONFIGURATION_get_value_number (cfg,
					 "core",
					 "TOTAL_QUOTA_OUT",
					 &atc->total_bps);
  return atc;
}


/**
 * Free an allocation record.
 *
 * @param cls unused
 * @param key identity of the peer associated with the record
 * @param value the 'struct AllocationRecord' to free
 * @return GNUNET_OK (continue to iterate)
 */
static int
destroy_allocation_record (void *cls,
			   const GNUNET_HashCode *key,
			   void *value)
{
  struct AllocationRecord *ar = value;

  GNUNET_array_grow (ar->ats, ar->ats_count, 0);
  GNUNET_free (ar->plugin_name);
  GNUNET_free (ar);
  return GNUNET_OK;
}


/**
 * Shutdown the ATS subsystem.
 *
 * @param atc handle
 */
void
GNUNET_ATS_shutdown (struct GNUNET_ATS_Handle *atc)
{
  if (GNUNET_SCHEDULER_NO_TASK != atc->ba_task)
    {
      GNUNET_SCHEDULER_cancel (atc->ba_task);
      atc->ba_task = GNUNET_SCHEDULER_NO_TASK;
    }
  GNUNET_CONTAINER_multihashmap_iterate (atc->peers,
					 &destroy_allocation_record,
					 NULL);
  GNUNET_CONTAINER_multihashmap_destroy (atc->peers);
  GNUNET_assert (GNUNET_CONTAINER_multihashmap_size (atc->notify_map) == 0);
  GNUNET_CONTAINER_multihashmap_destroy (atc->notify_map);
  atc->notify_map = NULL;
  GNUNET_free (atc);
}


/**
 * Closure for 'update_session'
 */
struct UpdateSessionContext
{
  /**
   * Ats handle.
   */
  struct GNUNET_ATS_Handle *atc;

  /**
   * Allocation record with new information.
   */
  struct AllocationRecord *arnew;
};


/**
 * Update an allocation record, merging with the new information
 *
 * @param cls a new 'struct AllocationRecord'
 * @param key identity of the peer associated with the records
 * @param value the old 'struct AllocationRecord' 
 * @return GNUNET_YES if the records do not match, 
 *         GNUNET_NO if the record do match and 'old' was updated
 */
static int
update_session (void *cls,
		const GNUNET_HashCode *key,
		void *value)
{
  struct UpdateSessionContext *usc = cls;
  struct AllocationRecord *arnew = usc->arnew;
  struct AllocationRecord *arold = value;
  int change;

  if (0 != strcmp (arnew->plugin_name, arold->plugin_name))
    return GNUNET_YES;
  if ( (arnew->session == arold->session) ||
       ( (arold->session == NULL) &&
	 (arold->plugin_addr_len == arnew->plugin_addr_len) &&
	 (0 == memcmp (arold->plugin_addr,
		       arnew->plugin_addr,
		       arnew->plugin_addr_len)) ) )
    {
      change = GNUNET_NO;
      /* records match */
      if (arnew->session != arold->session) 
	{
	  arold->session = arnew->session;
	  change = GNUNET_YES;
	}
      if ( (arnew->connected == GNUNET_YES) &&
	   (arold->connected == GNUNET_NO) )
	{
	  arold->connected = GNUNET_YES;
	  change = GNUNET_YES;
	}
      // FIXME: merge ats arrays of (arold, arnew);
      
      if (GNUNET_YES == change)
	update_bandwidth_assignment (usc->atc, arold);
      return GNUNET_NO;      
    }
  return GNUNET_YES;
}


/**
 * Create an allocation record with the given properties.
 *
 * @param plugin_name name of the currently used transport plugin
 * @param session session in use (if available)
 * @param plugin_addr address in use (if available)
 * @param plugin_addr_len number of bytes in plugin_addr
 * @param ats performance data for the connection
 * @param ats_count number of performance records in 'ats'
 */
static struct AllocationRecord *
create_allocation_record (const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *public_key,
			  const char *plugin_name,
			  struct Session *session,
			  const void *plugin_addr,
			  size_t plugin_addr_len,
			  const struct GNUNET_TRANSPORT_ATS_Information *ats,
			  uint32_t ats_count)
{
  struct AllocationRecord *ar;

  ar = GNUNET_malloc (sizeof (struct AllocationRecord) + plugin_addr_len);
  ar->public_key = *public_key;
  ar->plugin_name = GNUNET_strdup (plugin_name);
  ar->plugin_addr = &ar[1];
  memcpy (&ar[1], plugin_addr, plugin_addr_len);
  ar->session = session;
  ar->plugin_addr_len = plugin_addr_len;
  GNUNET_array_grow (ar->ats,
		     ar->ats_count,
		     ats_count);
  memcpy (ar->ats, 
	  ats, 
	  ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information));
  return ar;
}


/**
 * Mark all matching allocation records as not connected.
 *
 * @param cls 'struct GTS_AtsHandle'
 * @param key identity of the peer associated with the record
 * @param value the 'struct AllocationRecord' to clear the 'connected' flag
 * @return GNUNET_OK (continue to iterate)
 */
static int
disconnect_peer (void *cls,
		 const GNUNET_HashCode *key,
		 void *value)
{
  struct GNUNET_ATS_Handle *atc = cls;
  struct AllocationRecord *ar = value;

  if (GNUNET_YES == ar->connected)
    {
      ar->connected = GNUNET_NO;     
      update_bandwidth_assignment (atc, ar);
    }
  return GNUNET_OK;
}


/**
 * We established a new connection with a peer (for example, because
 * core asked for it or because the other peer connected to us).
 * Calculate bandwidth assignments including the new peer.
 *
 * @param atc handle
 * @param public_key public key of the peer
 * @param peer identity of the new peer
 * @param plugin_name name of the currently used transport plugin
 * @param session session in use (if available)
 * @param plugin_addr address in use (if available)
 * @param plugin_addr_len number of bytes in plugin_addr
 * @param ats performance data for the connection
 * @param ats_count number of performance records in 'ats'
 */
void
GNUNET_ATS_peer_connect (struct GNUNET_ATS_Handle *atc,
			 const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *public_key,
			 const struct GNUNET_PeerIdentity *peer,
			 const char *plugin_name,
			 struct Session *session,
			 const void *plugin_addr,
			 size_t plugin_addr_len,
			 const struct GNUNET_TRANSPORT_ATS_Information *ats,
			 uint32_t ats_count)
{
  struct AllocationRecord *ar;
  struct UpdateSessionContext usc;

  (void) GNUNET_CONTAINER_multihashmap_iterate (atc->peers,
						&disconnect_peer,
						atc);
  ar = create_allocation_record (public_key,
				 plugin_name,
				 session,
				 plugin_addr,
				 plugin_addr_len,
				 ats,
				 ats_count);
  ar->connected = GNUNET_YES;
  usc.atc = atc;
  usc.arnew = ar;
  if (GNUNET_SYSERR ==
      GNUNET_CONTAINER_multihashmap_iterate (atc->peers,
					     &update_session,
					     &usc))
    {     
      destroy_allocation_record (NULL, &peer->hashPubKey, ar);
      return;
    }
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CONTAINER_multihashmap_put (atc->peers,
						    &peer->hashPubKey,
						    ar,
						    GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));   
}


/**
 * We disconnected from the given peer (for example, because ats, core
 * or blacklist asked for it or because the other peer disconnected).
 * Calculate bandwidth assignments without the peer.
 *
 * @param atc handle
 * @param peer identity of the new peer
 */
void
GNUNET_ATS_peer_disconnect (struct GNUNET_ATS_Handle *atc,
			 const struct GNUNET_PeerIdentity *peer)
{
  (void) GNUNET_CONTAINER_multihashmap_get_multiple (atc->peers,
						     &peer->hashPubKey,
						     &disconnect_peer,
						     atc);
}


/**
 * Closure for 'destroy_allocation_record'
 */
struct SessionDestroyContext
{
  /**
   * Ats handle.
   */
  struct GNUNET_ATS_Handle *atc;

  /**
   * Session being destroyed.
   */
  const struct Session *session;
};


/**
 * Free an allocation record matching the given session.
 *
 * @param cls the 'struct SessionDestroyContext'
 * @param key identity of the peer associated with the record
 * @param value the 'struct AllocationRecord' to free
 * @return GNUNET_OK (continue to iterate)
 */
static int
destroy_session (void *cls,
		 const GNUNET_HashCode *key,
		 void *value)
{
  struct SessionDestroyContext *sdc = cls;
  struct AllocationRecord *ar = value;

  if (ar->session != sdc->session)
    return GNUNET_OK;
  ar->session = NULL;
  if (ar->plugin_addr != NULL)
    return GNUNET_OK;
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CONTAINER_multihashmap_remove (sdc->atc->peers,
						       key,
						       ar));
  if (GNUNET_YES == ar->connected);
    {
      /* FIXME: is this supposed to be allowed? What to do then? */
      GNUNET_break (0);
    }
  destroy_allocation_record (NULL, key, ar);
  return GNUNET_OK;
}


/**
 * A session got destroyed, stop including it as a valid address.
 *
 * @param atc handle
 * @param peer identity of the peer
 * @param session session handle that is no longer valid
 */
void
GNUNET_ATS_session_destroyed (struct GNUNET_ATS_Handle *atc,
			      const struct GNUNET_PeerIdentity *peer,
			      const struct Session *session)
{
  struct SessionDestroyContext sdc;

  sdc.atc = atc;
  sdc.session = session;
  (void) GNUNET_CONTAINER_multihashmap_iterate (atc->peers,
						&destroy_session,
						&sdc);
}


/**
 * Notify validation watcher that an entry is now valid
 *
 * @param cls 'struct ValidationEntry' that is now valid
 * @param key peer identity (unused)
 * @param value a 'GST_ValidationIteratorContext' to notify
 * @return GNUNET_YES (continue to iterate)
 */
static int
notify_valid (void *cls,
	      const GNUNET_HashCode *key,
	      void *value)
{
  struct AllocationRecord *ar = cls;
  struct GNUNET_ATS_SuggestionContext *asc = value;

  asc->cb (asc->cb_cls,
	   &ar->public_key,
	   &asc->target,
	   ar->plugin_name,
	   ar->plugin_addr,
	   ar->plugin_addr_len,
	   ar->ats, ar->ats_count);
  return GNUNET_OK;
}


/**
 * We have updated performance statistics for a given address.  Note
 * that this function can be called for addresses that are currently
 * in use as well as addresses that are valid but not actively in use.
 * Furthermore, the peer may not even be connected to us right now (in
 * which case the call may be ignored or the information may be stored
 * for later use).  Update bandwidth assignments.
 *
 * @param atc handle
 * @param public_key public key of the peer
 * @param peer identity of the peer
 * @param valid_until how long is the address valid?
 * @param plugin_name name of the transport plugin
 * @param session session handle (if available)
 * @param plugin_addr address  (if available)
 * @param plugin_addr_len number of bytes in plugin_addr
 * @param ats performance data for the address
 * @param ats_count number of performance records in 'ats'
 */
void
GNUNET_ATS_address_update (struct GNUNET_ATS_Handle *atc,
			   const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *public_key,
			   const struct GNUNET_PeerIdentity *peer,
			   struct GNUNET_TIME_Absolute valid_until,
			   const char *plugin_name,
			   struct Session *session,
			   const void *plugin_addr,
			   size_t plugin_addr_len,
			   const struct GNUNET_TRANSPORT_ATS_Information *ats,
			   uint32_t ats_count)
{
  struct AllocationRecord *ar;
  struct UpdateSessionContext usc;

  ar = create_allocation_record (public_key,
				 plugin_name,				 
				 session,
				 plugin_addr,
				 plugin_addr_len,
				 ats,
				 ats_count);
  usc.atc = atc;
  usc.arnew = ar;    
  if (GNUNET_SYSERR ==
      GNUNET_CONTAINER_multihashmap_iterate (atc->peers,
					     &update_session,
					     &usc))
    {     
      destroy_allocation_record (NULL, &peer->hashPubKey, ar);
      return;
    }
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CONTAINER_multihashmap_put (atc->peers,
						    &peer->hashPubKey,
						    ar,
						    GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE)); 
  GNUNET_CONTAINER_multihashmap_get_multiple (atc->notify_map,
					      &peer->hashPubKey,
					      &notify_valid,
					      ar);
}

/* end of file gnunet-service-transport_ats.c */
