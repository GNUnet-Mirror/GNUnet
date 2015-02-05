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
 * @file ats/gnunet-service-ats_preferences.h
 * @brief FIXME
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_ATS_PREFERENCES_H
#define GNUNET_SERVICE_ATS_PREFERENCES_H

#include "gnunet_util_lib.h"
#include "gnunet_ats_service.h"
#include "gnunet-service-ats.h"
#include "gnunet_statistics_service.h"
#include "ats.h"


#define DEFAULT_ABS_PREFERENCE 0.0

#define DEFAULT_REL_PREFERENCE 0.0


/**
 * A preference client disconnected.
 *
 * @param client the client
 */
void
GAS_preference_client_disconnect (struct GNUNET_SERVER_Client *client);


/**
 * Get the normalized preference values for a specific peer.
 *
 * @param cls ignored
 * @param id the peer
 * @return pointer to the values, can be indexed
 *  with GNUNET_ATS_PreferenceKind, NULL if peer does not exist
 */
const double *
GAS_normalization_get_preferences_by_peer (void *cls,
					   const struct GNUNET_PeerIdentity *id);


/**
 * Get the normalized preference values for a specific client and peer
 *
 * @param client client
 * @param peer the peer
 * @param pref the preference type
 * @return the value
 */
double
GAS_normalization_get_preferences_by_client (const void *client,
                                             const struct GNUNET_PeerIdentity *peer,
                                             enum GNUNET_ATS_PreferenceKind pref);


/**
 * Normalize an updated preference value
 *
 * @param client the client with this preference
 * @param peer the peer to change the preference for
 * @param kind the kind to change the preference
 * @param score_abs the normalized score
 */
void
GAS_normalization_normalize_preference (void *client,
                                        const struct GNUNET_PeerIdentity *peer,
                                        enum GNUNET_ATS_PreferenceKind kind,
                                        float score_abs);


/**
 * A performance client disconnected
 *
 * @param client the disconnecting client
 */
void
GAS_normalization_preference_client_disconnect (void *client);


/**
 * Handle 'preference change' messages from clients.
 *
 * @param cls unused, NULL
 * @param client client that sent the request
 * @param message the request message
 */
void
GAS_handle_preference_change (void *cls,
                              struct GNUNET_SERVER_Client *client,
                              const struct GNUNET_MessageHeader *message);


/**
 * Initialize preferences subsystem.
 */
void
GAS_preference_init (void);


/**
 * Shutdown preferences subsystem.
 */
void
GAS_preference_done (void);


#endif
