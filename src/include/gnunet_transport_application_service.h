/*
 This file is part of GNUnet.
 Copyright (C) 2010-2015, 2018, 2019 GNUnet e.V.

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
 * @defgroup TRANSPORT service
 * Bandwidth allocation
 *
 * @{
 */
#ifndef GNUNET_TRANSPORT_APPLICATION_SERVICE_H
#define GNUNET_TRANSPORT_APPLICATION_SERVICE_H

#include "gnunet_constants.h"
#include "gnunet_util_lib.h"
#include "gnunet_nt_lib.h"

/**
 * Handle to the TRANSPORT subsystem for making suggestions about
 * connections the peer would like to have.
 */
struct GNUNET_TRANSPORT_ApplicationHandle;


/**
 * Initialize the TRANSPORT application client handle.
 *
 * @param cfg configuration to use
 * @return ats application handle, NULL on error
 */
struct GNUNET_TRANSPORT_ApplicationHandle *
GNUNET_TRANSPORT_application_init (
  const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Shutdown TRANSPORT application client.
 *
 * @param ch handle to destroy
 */
void
GNUNET_TRANSPORT_application_done (
  struct GNUNET_TRANSPORT_ApplicationHandle *ch);


/**
 * An application would like TRANSPORT to connect to a peer.
 *
 * @param ch handle
 * @param peer identity of the peer we need an address for
 * @param pk what kind of application will the application require (can be
 *         #GNUNET_MQ_PRIO_BACKGROUND, we will still try to connect)
 * @param bw desired bandwith, can be zero (we will still try to connect)
 * @return suggest handle, NULL if a request is already pending
 */
struct GNUNET_TRANSPORT_ApplicationSuggestHandle *
GNUNET_TRANSPORT_application_suggest (
  struct GNUNET_TRANSPORT_ApplicationHandle *ch,
  const struct GNUNET_PeerIdentity *peer,
  enum GNUNET_MQ_PriorityPreferences pk,
  struct GNUNET_BANDWIDTH_Value32NBO bw);


/**
 * We no longer care about being connected to a peer.
 *
 * @param sh handle to stop
 */
void
GNUNET_TRANSPORT_application_suggest_cancel (
  struct GNUNET_TRANSPORT_ApplicationSuggestHandle *sh);


/**
 * An application (or a communicator) has received a HELLO (or other address
 * data of another peer) and wants TRANSPORT to validate that the address is
 * correct.  The result is NOT returned, in fact TRANSPORT may do nothing
 * (i.e. if it has too many active validations or recently tried this one
 * already).  If the @a addr validates, TRANSPORT will persist the address
 * with PEERSTORE.
 *
 * @param ch handle
 * @param peer identity of the peer we have an address for
 * @param nt network type of @a addr (as claimed by the other peer);
 *        used by TRANSPORT to avoid trying @a addr's that really cannot work
 *        due to network type missmatches
 * @param addr address to validate
 */
void
GNUNET_TRANSPORT_application_validate (
  struct GNUNET_TRANSPORT_ApplicationHandle *ch,
  const struct GNUNET_PeerIdentity *peer,
  enum GNUNET_NetworkType nt,
  const char *addr);

/** @} */ /* end of group */

#endif
/* end of file gnunet_ats_application_service.h */
