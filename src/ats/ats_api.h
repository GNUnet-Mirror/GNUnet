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
 * @file ats/ats_api.h
 * @brief automatic transport selection API common includes
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#ifndef ATS_API_H
#define ATS_API_H

#include "gnunet_util_lib.h"

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
   * Inbound bandwidth assigned to this address right now, 0 for none.
   */
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in;

  /**
   * Outbound bandwidth assigned to this address right now, 0 for none.
   */
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out;

  /**
   * Tracking bandwidth for receiving from this peer.  Used for
   * applications that want to 'reserve' bandwidth for replies.
   */
  struct GNUNET_BANDWIDTH_Tracker available_recv_window;

  /**
   * Set to GNUNET_YES if this is the connected address of a connected peer.
   */
  int connected;

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
   * Total inbound bandwidth per configuration.
   */
  unsigned long long total_bps_in;

  /**
   * Total outbound bandwidth per configuration.
   */
  unsigned long long total_bps_out;
};

#endif
