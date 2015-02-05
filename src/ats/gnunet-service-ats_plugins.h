/*
 This file is part of GNUnet.
 (C) 2011-2014 Christian Grothoff (and other contributing authors)

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
 * @file ats/gnunet-service-ats_plugins.h
 * @brief ats service plugin management
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_ATS_PLUGINS_H
#define GNUNET_SERVICE_ATS_PLUGINS_H

#include "gnunet_util_lib.h"
#include "gnunet_ats_service.h"
#include "gnunet-service-ats.h"
#include "gnunet_statistics_service.h"
#include "ats.h"


/**
 * Available ressource assignment modes
 */
enum ATS_Mode
{
  /**
   * proportional mode:
   *
   * Assign each peer an equal amount of bandwidth (bw)
   *
   * bw_per_peer = bw_total / #active addresses
   */
  MODE_PROPORTIONAL,

  /**
   * MLP mode:
   *
   * Solve ressource assignment as an optimization problem
   * Uses an mixed integer programming solver
   */
  MODE_MLP,

  /**
   * Reinforcement Learning mode:
   *
   * Solve resource assignment using a learning agent
   */
  MODE_RIL
};


/**
 * Initialize address subsystem. The addresses subsystem manages the addresses
 * known and current performance information. It has a solver component
 * responsible for the resource allocation. It tells the solver about changes
 * and receives updates when the solver changes the ressource allocation.
 *
 * @param cfg configuration to use
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error (failed to load
 *         solver plugin)
 */
int
GAS_plugins_init (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Shutdown address subsystem.
 */
void
GAS_plugins_done (void);


/**
 * The preference changed for a peer, update solver.
 *
 * @param peer the peer
 * @param kind the ATS kind
 * @param pref_rel the new relative preference value
 */
void
GAS_normalized_preference_changed (const struct GNUNET_PeerIdentity *peer,
				   enum GNUNET_ATS_PreferenceKind kind,
				   double pref_rel);


/**
 * The relative value for a property changed
 *
 * @param address the peer
 * @param type the ATS type
 * @param prop_rel the new relative preference value
 */
void
GAS_normalized_property_changed (struct ATS_Address *address,
				 uint32_t type,
				 double prop_rel);


void
GAS_plugin_new_address (struct ATS_Address *new_address,
			enum GNUNET_ATS_Network_Type addr_net,
			const struct GNUNET_ATS_Information *atsi,
			uint32_t atsi_count);


void
GAS_plugin_update_address (struct ATS_Address *address,
			   const struct GNUNET_ATS_Information *atsi,
			   uint32_t atsi_count);


void
GAS_plugin_update_preferences (void *client,
			       const struct GNUNET_PeerIdentity *peer,
			       enum GNUNET_ATS_PreferenceKind kind,
			       float score_abs);


void
GAS_plugin_preference_feedback (void *application,
				const struct GNUNET_PeerIdentity *peer,
				const struct GNUNET_TIME_Relative scope,
				enum GNUNET_ATS_PreferenceKind kind,
				float score_abs);


void
GAS_plugin_delete_address (struct ATS_Address *address);


void
GAS_plugin_request_connect_start (const struct GNUNET_PeerIdentity *pid);


void
GAS_plugin_request_connect_stop (const struct GNUNET_PeerIdentity *pid);


void
GAS_plugin_solver_lock (void);


void
GAS_plugin_solver_unlock (void);


#endif
