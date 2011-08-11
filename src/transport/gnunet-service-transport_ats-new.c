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
 * @file transport/gnunet-service-transport_ats-new.c
 * @brief automatic transport selection API
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet-service-transport_ats-new.h"


/**
 * Allocation record for a peer's address.
 */
struct AllocationRecord
{

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
 * Handle to the ATS subsystem.
 */
struct GST_AtsHandle
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

};


/**
 * Initialize the ATS subsystem.
 *
 * @param cfg configuration to use
 * @param alloc_cb notification to call whenever the allocation changed
 * @param alloc_cb_cls closure for 'alloc_cb'
 * @return ats context
 */
struct GST_AtsHandle *
GST_ats_init (const struct GNUNET_CONFIGURATION_Handle *cfg,
	      GNUNET_TRANSPORT_ATS_AllocationNotification alloc_cb,
	      void *alloc_cb_cls)
{
  struct GST_AtsHandle *atc;

  atc = GNUNET_malloc (sizeof (struct GST_AtsHandle));
  atc->cfg = cfg;
  atc->alloc_cb = alloc_cb;
  atc->alloc_cb_cls = alloc_cb_cls;
  atc->peers = GNUNET_CONTAINER_multihashmap_create (256);
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
GST_ats_shutdown (struct GST_AtsHandle *atc)
{
  GNUNET_CONTAINER_multihashmap_iterate (atc->peers,
					 &destroy_allocation_record,
					 NULL);
  GNUNET_CONTAINER_multihashmap_destroy (atc->peers);
  GNUNET_free (atc);
}


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
  struct AllocationRecord *arnew = cls;
  struct AllocationRecord *arold = value;

  if (0 != strcmp (arnew->plugin_name, arold->plugin_name))
    return GNUNET_YES;
  if ( (arnew->session == arold->session) ||
       ( (arold->session == NULL) &&
	 (arold->plugin_addr_len == arnew->plugin_addr_len) &&
	 (0 == memcmp (arold->plugin_addr,
		       arnew->plugin_addr,
		       arnew->plugin_addr_len)) ) )
    {
      /* records match */
      arold->session = arnew->session;
      if (arnew->connected == GNUNET_YES)
	arold->connected = GNUNET_YES;
      // FIXME: merge ats arrays of (arold, arnew);
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
create_allocation_record (const char *plugin_name,
			  struct Session *session,
			  const void *plugin_addr,
			  size_t plugin_addr_len,
			  const struct GNUNET_TRANSPORT_ATS_Information *ats,
			  uint32_t ats_count)
{
  struct AllocationRecord *ar;

  ar = GNUNET_malloc (sizeof (struct AllocationRecord) + plugin_addr_len);
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
 * We established a new connection with a peer (for example, because
 * core asked for it or because the other peer connected to us).
 * Calculate bandwidth assignments including the new peer.
 *
 * @param atc handle
 * @param peer identity of the new peer
 * @param plugin_name name of the currently used transport plugin
 * @param session session in use (if available)
 * @param plugin_addr address in use (if available)
 * @param plugin_addr_len number of bytes in plugin_addr
 * @param ats performance data for the connection
 * @param ats_count number of performance records in 'ats'
 */
void
GST_ats_peer_connect (struct GST_AtsHandle *atc,
		      const struct GNUNET_PeerIdentity *peer,
		      const char *plugin_name,
		      struct Session *session,
		      const void *plugin_addr,
		      size_t plugin_addr_len,
		      const struct GNUNET_TRANSPORT_ATS_Information *ats,
		      uint32_t ats_count)
{
  struct AllocationRecord *ar;

  ar = create_allocation_record (plugin_name,
				 session,
				 plugin_addr,
				 plugin_addr_len,
				 ats,
				 ats_count);
  ar->connected = GNUNET_YES;
  if (GNUNET_SYSERR ==
      GNUNET_CONTAINER_multihashmap_iterate (atc->peers,
					     &update_session,
					     ar))
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
 * Mark all matching allocation records as not connected.
 *
 * @param cls unused
 * @param key identity of the peer associated with the record
 * @param value the 'struct AllocationRecord' to clear the 'connected' flag
 * @return GNUNET_OK (continue to iterate)
 */
static int
disconnect_peer (void *cls,
		 const GNUNET_HashCode *key,
		 void *value)
{
  struct AllocationRecord *ar = value;

  ar->connected = GNUNET_NO;
  return GNUNET_OK;
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
GST_ats_peer_disconnect (struct GST_AtsHandle *atc,
			 const struct GNUNET_PeerIdentity *peer)
{
  (void) GNUNET_CONTAINER_multihashmap_iterate (atc->peers,
						&disconnect_peer,
						NULL);
}


/**
 * Closure for 'destroy_allocation_record'
 */
struct SessionDestroyContext
{
  /**
   * Ats handle.
   */
  struct GST_AtsHandle *atc;

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
GST_ats_session_destroyed (struct GST_AtsHandle *atc,
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
 * We have updated performance statistics for a given address.  Note
 * that this function can be called for addresses that are currently
 * in use as well as addresses that are valid but not actively in use.
 * Furthermore, the peer may not even be connected to us right now (in
 * which case the call may be ignored or the information may be stored
 * for later use).  Update bandwidth assignments.
 *
 * @param atc handle
 * @param peer identity of the new peer
 * @param plugin_name name of the transport plugin
 * @param session session handle (if available)
 * @param plugin_addr address  (if available)
 * @param plugin_addr_len number of bytes in plugin_addr
 * @param ats performance data for the address
 * @param ats_count number of performance records in 'ats'
 */
void
GST_ats_address_update (struct GST_AtsHandle *atc,
			const struct GNUNET_PeerIdentity *peer,
			const char *plugin_name,
			struct Session *session,
			const void *plugin_addr,
			size_t plugin_addr_len,
			const struct GNUNET_TRANSPORT_ATS_Information *ats,
			uint32_t ats_count)
{
  struct AllocationRecord *ar;

  ar = create_allocation_record (plugin_name,
				 session,
				 plugin_addr,
				 plugin_addr_len,
				 ats,
				 ats_count);
  
  if (GNUNET_SYSERR ==
      GNUNET_CONTAINER_multihashmap_iterate (atc->peers,
					     &update_session,
					     ar))
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

/* end of file gnunet-service-transport_ats.c */
