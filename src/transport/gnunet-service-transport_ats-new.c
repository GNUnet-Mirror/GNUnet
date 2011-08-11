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
 * Handle to the ATS subsystem.
 */
struct GST_AtsHandle
{
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  GNUNET_TRANSPORT_ATS_AllocationNotification alloc_cb;

  void *alloc_cb_cls;
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
  return atc;
}


/**
 * Shutdown the ATS subsystem.
 *
 * @param atc handle
 */
void
GST_ats_shutdown (struct GST_AtsHandle *atc)
{
  GNUNET_free (atc);
}


/**
 * We established a new connection with a peer (for example, because
 * core asked for it or because the other peer connected to us).
 * Calculate bandwidth assignments including the new peer.
 *
 * @param atc handle
 * @param peer identity of the new peer
 * @param plugin_name name of the currently used transport plugin
 * @param plugin_addr address in use
 * @param plugin_addr_len number of bytes in plugin_addr
 * @param ats performance data for the connection
 * @param ats_count number of performance records in 'ats'
 */
void
GST_ats_peer_connect (struct GST_AtsHandle *atc,
		      const struct GNUNET_PeerIdentity *peer,
		      const char *plugin_name,
		      const void *plugin_addr,
		      size_t plugin_addr_len,
		      const struct GNUNET_TRANSPORT_ATS_Information *ats,
		      uint32_t ats_count)
{
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
 * @param plugin_addr address 
 * @param plugin_addr_len number of bytes in plugin_addr
 * @param ats performance data for the address
 * @param ats_count number of performance records in 'ats'
 */
void
GST_ats_address_update (struct GST_AtsHandle *atc,
			const struct GNUNET_PeerIdentity *peer,
			const char *plugin_name,
			const void *plugin_addr,
			size_t plugin_addr_len,
			const struct GNUNET_TRANSPORT_ATS_Information *ats,
			uint32_t ats_count)
{
}

/* end of file gnunet-service-transport_ats.c */
