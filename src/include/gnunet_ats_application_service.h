/*
   This file is part of GNUnet.
   Copyright (C) 2010-2015, 2018 GNUnet e.V.

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
 * @file
 * Bandwidth allocation API for applications to interact with
 *
 * @author Christian Grothoff
 * @author Matthias Wachs
 *
 * @defgroup ats  ATS service
 * Bandwidth allocation
 *
 * @see [Documentation](https://gnunet.org/ats-subsystem)
 *
 * @{
 */
#ifndef GNUNET_ATS_APPLICATION_SERVICE_H
#define GNUNET_ATS_APPLICATION_SERVICE_H

#include "gnunet_constants.h"
#include "gnunet_util_lib.h"

/**
 * Handle to the ATS subsystem for making suggestions about
 * connections the peer would like to have.
 */
struct GNUNET_ATS_ApplicationHandle;


/**
 * Initialize the ATS application client handle.
 *
 * @param cfg configuration to use
 * @return ats application handle, NULL on error
 */
struct GNUNET_ATS_ApplicationHandle *
GNUNET_ATS_application_init (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Shutdown ATS application client.
 *
 * @param ch handle to destroy
 */
void
GNUNET_ATS_application_done (struct GNUNET_ATS_ApplicationHandle *ch);


/**
 * Handle for suggestion requests.
 */
struct GNUNET_ATS_ApplicationSuggestHandle;


/**
 * An application would like to communicate with a peer.  ATS should
 * allocate bandwith using a suitable address for requiremetns @a pk
 * to transport.
 *
 * @param ch handle
 * @param peer identity of the peer we need an address for
 * @param pk what kind of application will the application require (can be
 *         #GNUNET_MQ_PREFERENCE_NONE, we will still try to connect)
 * @param bw desired bandwith, can be zero (we will still try to connect)
 * @return suggestion handle, NULL if request is already pending
 */
struct GNUNET_ATS_ApplicationSuggestHandle *
GNUNET_ATS_application_suggest (struct GNUNET_ATS_ApplicationHandle *ch,
                                const struct GNUNET_PeerIdentity *peer,
                                enum GNUNET_MQ_PreferenceKind pk,
                                struct GNUNET_BANDWIDTH_Value32NBO bw);


/**
 * We no longer care about communicating with a peer.
 *
 * @param sh handle
 */
void
GNUNET_ATS_application_suggest_cancel (struct
                                       GNUNET_ATS_ApplicationSuggestHandle *sh);

/** @} */  /* end of group */

#endif
/* end of file gnunet_ats_application_service.h */
