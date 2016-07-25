/*
     This file is part of GNUnet.
     Copyright (C) 2009-2014, 2016 GNUnet e.V.

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
 * @author Christian Grothoff
 *
 * @file
 * Low-level P2P IO
 *
 * @defgroup transport  Transport service
 * Low-level P2P IO
 *
 * @see [Documentation](https://gnunet.org/transport-service)
 *
 * @{
 */

#ifndef GNUNET_TRANSPORT_MANIPULATION_SERVICE_H
#define GNUNET_TRANSPORT_MANIPULATION_SERVICE_H


#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"
#include "gnunet_ats_service.h"

/**
 * Version number of the transport API.
 */
#define GNUNET_TRANSPORT_MANIPULATION_VERSION 0x00000003

/**
 * Handle for transport manipulation.
 */
struct GNUNET_TRANSPORT_ManipulationHandle;


/**
 * Connect to the transport service.  Note that the connection may
 * complete (or fail) asynchronously.
 *
 * @param cfg configuration to use
 * @return NULL on error
 */
struct GNUNET_TRANSPORT_ManipulationHandle *
GNUNET_TRANSPORT_manipulation_connect (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Disconnect from the transport service.
 *
 * @param handle handle returned from connect
 */
void
GNUNET_TRANSPORT_manipulation_disconnect (struct GNUNET_TRANSPORT_ManipulationHandle *handle);


/**
 * Set transport metrics for a peer and a direction
 *
 * @param handle transport handle
 * @param peer the peer to set the metric for
 * @param prop the performance metrics to set
 * @param delay_in inbound delay to introduce
 * @param delay_out outbound delay to introduce
 *
 * Note: Delay restrictions in receiving direction will be enforced
 * with one message delay.
 */
void
GNUNET_TRANSPORT_manipulation_set (struct GNUNET_TRANSPORT_ManipulationHandle *handle,
				   const struct GNUNET_PeerIdentity *peer,
				   const struct GNUNET_ATS_Properties *prop,
				   struct GNUNET_TIME_Relative delay_in,
				   struct GNUNET_TIME_Relative delay_out);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_TRANSPORT_MANIPULATION_SERVICE_H */
#endif

/** @} */  /* end of group */

/* end of gnunet_transport_manipulation_service.h */
