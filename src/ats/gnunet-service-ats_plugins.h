/*
   This file is part of GNUnet.
   Copyright (C) 2011-2014 GNUnet e.V.

   GNUnet is free software: you can redistribute it and/or modify it
   under the terms of the GNU Affero General Public License as published
   by the Free Software Foundation, either version 3 of the License,
   or (at your option) any later version.

   GNUnet is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file ats/gnunet-service-ats_plugins.h
 * @brief ats service plugin management
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_ATS_PLUGINS_H
#define GNUNET_SERVICE_ATS_PLUGINS_H

#include "gnunet-service-ats_addresses.h"


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
GAS_plugin_init(const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Shutdown address subsystem.
 */
void
GAS_plugin_done(void);


/**
 * The preference changed for a peer, update solver.
 *
 * @param peer the peer
 * @param kind the ATS kind
 * @param pref_rel the new relative preference value
 */
void
GAS_plugin_notify_preference_changed(const struct GNUNET_PeerIdentity *peer,
                                     enum GNUNET_ATS_PreferenceKind kind,
                                     double pref_rel);


/**
 * The relative value for a property changed.
 *
 * @param address the peer
 */
void
GAS_plugin_notify_property_changed(struct ATS_Address *address);


/**
 * Tell the solver that the given address can now be used
 * for talking to the respective peer.
 *
 * @param new_address the new address
 * @param addr_net network scope the address is in
 */
void
GAS_plugin_new_address(struct ATS_Address *new_address);


/**
 * Tell the solver that the given address is no longer valid
 * can cannot be used any longer.
 *
 * @param address address that was deleted
 */
void
GAS_plugin_delete_address(struct ATS_Address *address);


/**
 * Tell the solver that the given client has expressed its
 * appreciation for the past performance of a given connection.
 *
 * @param application client providing the feedback
 * @param peer peer the feedback is about
 * @param scope timeframe the feedback applies to
 * @param kind performance property the feedback relates to
 * @param score_abs degree of the appreciation
 */
void
GAS_plugin_notify_feedback(struct GNUNET_SERVICE_Client *application,
                           const struct GNUNET_PeerIdentity *peer,
                           const struct GNUNET_TIME_Relative scope,
                           enum GNUNET_ATS_PreferenceKind kind,
                           float score_abs);


/**
 * Stop instant solving, there are many state updates
 * happening in bulk right now.
 */
void
GAS_plugin_solver_lock(void);


/**
 * Resume instant solving, we are done with the bulk state updates.
 */
void
GAS_plugin_solver_unlock(void);


/**
 * Notify the plugin that a request to connect to
 * a particular peer was given to us.
 *
 * @param pid identity of peer we now care about
 */
void
GAS_plugin_request_connect_start(const struct GNUNET_PeerIdentity *pid);


/**
 * Notify the plugin that a request to connect to
 * a particular peer was dropped.
 *
 * @param pid identity of peer we care now less about
 */
void
GAS_plugin_request_connect_stop(const struct GNUNET_PeerIdentity *pid);


#endif
