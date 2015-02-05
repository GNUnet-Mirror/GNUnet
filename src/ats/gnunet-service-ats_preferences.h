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
 * A preference client disconnected
 *
 * @param client the client; FIXME: type!?
 */
void
GAS_addresses_preference_client_disconnect (void *client);


/**
 * Change the preference for a peer
 *
 * @param client the client sending this request; FIXME: type!?
 * @param peer the peer id
 * @param kind the preference kind to change
 * @param score_abs the new preference score
 */
void
GAS_addresses_preference_change (void *client,
                                 const struct GNUNET_PeerIdentity *peer,
                                 enum GNUNET_ATS_PreferenceKind kind,
                                 float score_abs);


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
 * Application feedback on how good preference requirements are fulfilled
 * for a specific preference in the given time scope [now - scope .. now]
 *
 * An application notifies ATS if (and only if) it has feedback information
 * for a specific property. This value is valid until the feedback score is
 * updated by the application.
 *
 * If the application has no feedback for this preference kind the application
 * will not explicitly call.
 *
 * @param application the application sending this request; FIXME: type?
 * @param peer the peer id
 * @param scope the time interval this valid for: [now - scope .. now]
 * @param kind the preference kind this feedback is intended for
 * @param score_abs the new preference score
 */
void
GAS_addresses_preference_feedback (void *application,
                                   const struct GNUNET_PeerIdentity *peer,
                                   const struct GNUNET_TIME_Relative scope,
                                   enum GNUNET_ATS_PreferenceKind kind,
                                   float score_abs);

/**
 * Handle 'preference feedback' messages from clients.
 *
 * @param cls unused, NULL
 * @param client client that sent the request
 * @param message the request message
 */
void
GAS_handle_preference_feedback (void *cls,
                                struct GNUNET_SERVER_Client *client,
                                const struct GNUNET_MessageHeader *message);



/**
 * Shutdown preferences subsystem.
 */
void
GAS_preference_done (void);


#endif
