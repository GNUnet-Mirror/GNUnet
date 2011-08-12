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
 * @file include/gnunet_ats_service.h
 * @brief automatic transport selection and outbound bandwidth determination
 * @author Christian Grothoff
 * @author Matthias Wachs
 *
 * TODO:
 * - move GNUNET_TRANSPORT_ATS* in here and rename...
 * - extend API to express communication preferences to ATS 
 *   (to be called DIRECTLY from apps, not from transport/core!)
 */
#ifndef GNUNET_ATS_SERVICE_H
#define GNUNET_ATS_SERVICE_H

#include "gnunet_constants.h"
#include "gnunet_util_lib.h"
#include "gnunet_transport_service.h"
#include "gnunet_transport_plugin.h"


/**
 * Handle to the ATS subsystem.
 */
struct GNUNET_ATS_Handle;


/**
 * Signature of a function called by ATS to notify the callee that the
 * assigned bandwidth or address for a given peer was changed.  If the
 * callback is called with address/bandwidth assignments of zero, the
 * ATS disconnect function will still be called once the disconnect 
 * actually happened.
 *
 * @param cls closure
 * @param peer identity of the peer
 * @param plugin_name name of the transport plugin, NULL to disconnect
 * @param session session to use (if available)
 * @param plugin_addr address to use (if available)
 * @param plugin_addr_len number of bytes in addr
 * @param bandwidth assigned outbound bandwidth for the connection
 */
typedef void (*GNUNET_TRANSPORT_ATS_AllocationNotification)(void *cls,
							    const struct GNUNET_PeerIdentity *peer,
							    const char *plugin_name,
							    struct Session *session,
							    const void *plugin_addr,
							    size_t plugin_addr_len,
							    struct GNUNET_BANDWIDTH_Value32NBO bandwidth);


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
		 void *alloc_cb_cls);


/**
 * Shutdown the ATS subsystem.
 *
 * @param atc handle
 */
void
GNUNET_ATS_shutdown (struct GNUNET_ATS_Handle *atc);


/**
 * Signature of a function that takes an address suggestion 
 *
 * @param cls closure
 * @param public_key public key of the peer
 * @param peer identity of the new peer
 * @param plugin_name name of the plugin, NULL if we have no suggestion
 * @param plugin_addr suggested address, NULL if we have no suggestion
 * @param plugin_addr_len number of bytes in plugin_addr
 * @param ats performance data for the address (as far as known)
 * @param ats_count number of performance records in 'ats'
 */
typedef void (*GNUNET_ATS_AddressSuggestionCallback)(void *cls,
						     const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *public_key,
						     const struct GNUNET_PeerIdentity *peer,
						     const char *plugin_name,
						     const void *plugin_addr,
						     size_t plugin_addr_len,
						     const struct GNUNET_TRANSPORT_ATS_Information *ats,
						     uint32_t ats_count);


/**
 * Handle to cancel suggestion request.
 */
struct GNUNET_ATS_SuggestionContext;


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
			    void *cb_cls);


/**
 * Cancel suggestion request.
 *
 * @param asc handle of the request to cancel
 */
void
GNUNET_ATS_suggest_address_cancel (struct GNUNET_ATS_SuggestionContext *asc);


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
			 uint32_t ats_count);


/**
 * We disconnected from the given peer (for example, because ats, core
 * or blacklist asked for it or because the other peer disconnected).
 * Calculate bandwidth assignments without the peer.
 *
 * @param atc handle
 * @param peer identity of the peer
 */
void
GNUNET_ATS_peer_disconnect (struct GNUNET_ATS_Handle *atc,
			    const struct GNUNET_PeerIdentity *peer);


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
			      const struct Session *session);


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
 * @param peer identity of the new peer
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
			   const char *plugin_name,
			   struct Session *session,
			   const void *plugin_addr,
			   size_t plugin_addr_len,
			   const struct GNUNET_TRANSPORT_ATS_Information *ats,
			   uint32_t ats_count);


#endif
/* end of file gnunet-service-transport_ats.h */
