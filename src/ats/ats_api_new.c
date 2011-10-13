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
 */
#include "platform.h"
#include "gnunet_ats_service.h"


/**
 * Handle to the ATS subsystem for bandwidth/transport scheduling information.
 */
struct GNUNET_ATS_SchedulingHandle
{
};


/**
 * Initialize the ATS subsystem.
 *
 * @param cfg configuration to use
 * @param alloc_cb notification to call whenever the allocation changed
 * @param alloc_cb_cls closure for 'alloc_cb'
 * @return ats context
 */
struct GNUNET_ATS_SchedulingHandle *
GNUNET_ATS_scheduling_init (const struct GNUNET_CONFIGURATION_Handle *cfg,
			    GNUNET_ATS_AddressSuggestionCallback alloc_cb,
			    void *alloc_cb_cls)
{
  return NULL;
}


/**
 * Client is done with ATS scheduling, release resources.
 *
 * @param atc handle to release
 */
void
GNUNET_ATS_scheduling_done (struct GNUNET_ATS_SchedulingHandle *atc)
{
}


/**
 * We would like to establish a new connection with a peer.  ATS
 * should suggest a good address to begin with.
 *
 * @param atc handle
 * @param peer identity of the peer we need an address for
 */
void
GNUNET_ATS_suggest_address (struct GNUNET_ATS_SchedulingHandle *atc,
                            const struct GNUNET_PeerIdentity *peer)
{
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
 * @param plugin_addr address  (if available)
 * @param plugin_addr_len number of bytes in plugin_addr
 * @param session session handle (if available)
 * @param ats performance data for the address
 * @param ats_count number of performance records in 'ats'
 */
void
GNUNET_ATS_address_update (struct GNUNET_ATS_SchedulingHandle *atc,
                           const struct GNUNET_PeerIdentity *peer,
                           const char *plugin_name,
                           const void *plugin_addr, size_t plugin_addr_len,
			   struct Session *session,
                           const struct GNUNET_TRANSPORT_ATS_Information *ats,
                           uint32_t ats_count)
{
}


/**
 * A session got destroyed, stop including it as a valid address.
 *
 * @param atc handle
 * @param peer identity of the peer
 * @param plugin_name name of the transport plugin
 * @param plugin_addr address  (if available)
 * @param plugin_addr_len number of bytes in plugin_addr
 * @param session session handle that is no longer valid
 */
void
GNUNET_ATS_address_destroyed (struct GNUNET_ATS_SchedulingHandle *atc,
                              const struct GNUNET_PeerIdentity *peer,
			      const char *plugin_name,
			      const void *plugin_addr, 
			      size_t plugin_addr_len,
                              const struct Session *session)
{
}

/* end of ats_api_new.c */
