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
 * @file ats/gnunet-service-ats_addresses.h
 * @brief ats service address management
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_ATS_ADDRESSES_H
#define GNUNET_SERVICE_ATS_ADDRESSES_H

#include "gnunet_util_lib.h"
#include "gnunet_ats_service.h"
#include "gnunet_statistics_service.h"
#include "ats.h"

struct ATS_Address
{
  struct ATS_Address *next;

  struct ATS_Address *prev;

  struct GNUNET_PeerIdentity peer;

  size_t addr_len;

  uint32_t session_id;

  uint32_t ats_count;

  const void *addr;

  char *plugin;

  void *mlp_information;

  struct GNUNET_ATS_Information *ats;

  struct GNUNET_TIME_Relative atsp_latency;

  struct GNUNET_BANDWIDTH_Value32NBO atsp_utilization_in;

  struct GNUNET_BANDWIDTH_Value32NBO atsp_utilization_out;

  uint32_t atsp_distance;

  uint32_t atsp_cost_wan;

  uint32_t atsp_cost_lan;

  uint32_t atsp_cost_wlan;

  uint32_t atsp_network_type;

  struct GNUNET_BANDWIDTH_Value32NBO assigned_bw_in;

  struct GNUNET_BANDWIDTH_Value32NBO assigned_bw_out;

  /**
   * Blocking interval
   */
  struct GNUNET_TIME_Relative block_interval;

  /**
   * Time when address can be suggested again
   */
  struct GNUNET_TIME_Absolute blocked_until;

  /**
   * Is this the active address for this peer?
   */
  int active;

  /**
   * Is this the address for this peer in use?
   */
  int used;
};

/**
 * Initialize address subsystem.
 *
 * @param cfg configuration to use
 * @param stats the statistics handle to use
 */
void
GAS_addresses_init (const struct GNUNET_CONFIGURATION_Handle *cfg,
                    const struct GNUNET_STATISTICS_Handle *stats);


/**
 * Shutdown address subsystem.
 */
void
GAS_addresses_done (void);

void
GAS_addresses_handle_backoff_reset (const struct GNUNET_PeerIdentity *peer);

/**
 * This address is now used or not used anymore
 */
int
GAS_addresses_in_use (const struct GNUNET_PeerIdentity *peer,
                      const char *plugin_name, const void *plugin_addr,
                      size_t plugin_addr_len, uint32_t session_id, int in_use);

void
GAS_addresses_update (const struct GNUNET_PeerIdentity *peer,
                      const char *plugin_name, const void *plugin_addr,
                      size_t plugin_addr_len, uint32_t session_id,
                      const struct GNUNET_ATS_Information *atsi,
                      uint32_t atsi_count);


void
GAS_addresses_destroy (const struct GNUNET_PeerIdentity *peer,
                       const char *plugin_name, const void *plugin_addr,
                       size_t plugin_addr_len, uint32_t session_id);


void
GAS_addresses_destroy_all (void);


// FIXME: this function should likely end up in the LP-subsystem and
// not with 'addresses' in the future...
// Note: this call should trigger an address suggestion
// (GAS_scheduling_transmit_address_suggestion)
void
GAS_addresses_request_address (const struct GNUNET_PeerIdentity *peer);


// FIXME: this function should likely end up in the LP-subsystem and
// not with 'addresses' in the future...
void
GAS_addresses_change_preference (const struct GNUNET_PeerIdentity *peer,
                                 enum GNUNET_ATS_PreferenceKind kind,
                                 float score);


/* FIXME: add performance request API */

#endif

/* end of gnunet-service-ats_addresses.h */
