/*
 This file is part of GNUnet.
 Copyright (C) 2011-2014 Christian Grothoff (and other contributing authors)

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
 Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 Boston, MA 02110-1301, USA.
 */
/**
 * @file ats/gnunet-service-ats_preferences.h
 * @brief manage preferences expressed by clients
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

/**
 * Default preference value we assume if we know nothing.
 */
#define DEFAULT_ABS_PREFERENCE 0.0

/**
 * Default relative preference value we assume if we know nothing.
 */
#define DEFAULT_REL_PREFERENCE 0.0


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


/**
 * Get the normalized preference values for a specific peer.
 *
 * @param cls ignored
 * @param id the peer
 * @return pointer to the values, can be indexed
 *  with `enum GNUNET_ATS_PreferenceKind`, never NULL
 */
const double *
GAS_preference_get_by_peer (void *cls,
                            const struct GNUNET_PeerIdentity *id);


/**
 * A performance client disconnected
 *
 * @param client the disconnecting client
 */
void
GAS_preference_client_disconnect (struct GNUNET_SERVER_Client *client);


#endif
