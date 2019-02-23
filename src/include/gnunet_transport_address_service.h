/*
     This file is part of GNUnet.
     Copyright (C) 2009-2018 GNUnet e.V.

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
 * @author Christian Grothoff
 *
 * @file
 * Provide addresses to transport for validation
 *
 * @defgroup transport TRANSPORT service
 * Low-level communication with other peers
 *
 * @see [Documentation](https://gnunet.org/transport-service)
 *
 * @{
 */

#ifndef GNUNET_TRANSPORT_ADDRESS_SERVICE_H
#define GNUNET_TRANSPORT_ADDRESS_SERVICE_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"
#include "gnunet_nt_lib.h"

/**
 * Version number of the transport address API.
 */
#define GNUNET_TRANSPORT_ADDRESS_VERSION 0x00000000


/**
 * Opaque handle to the transport service for communicators.
 */
struct GNUNET_TRANSPORT_AddressHandle;


/**
 * Connect to the transport service.
 *
 * @param cfg configuration to use
 * @return NULL on error
 */
struct GNUNET_TRANSPORT_AddressHandle *
GNUNET_TRANSPORT_address_connect (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Disconnect from the transport service.
 *
 * @param ch handle returned from connect
 */
void
GNUNET_TRANSPORT_address_disconnect (struct GNUNET_TRANSPORT_AddressHandle *ch);


/**
 * The client has learned about a possible address for peer @a pid
 * (i.e. via broadcast, multicast, DHT, ...).  The transport service
 * should consider validating it. Note that the plugin is NOT expected
 * to have verified the signature, the transport service must decide
 * whether to check the signature.
 *
 * While the notification is sent to @a ch asynchronously, this API
 * does not return a handle as the delivery of addresses is simply
 * unreliable, and if @a ch is down, the data provided will simply be
 * lost.
 *
 * @param ch communicator handle
 * @param pid peer the address is for
 * @param raw raw address data
 * @param raw_size number of bytes in @a raw
 */
void
GNUNET_TRANSPORT_address_try (struct GNUNET_TRANSPORT_AddressHandle *ch,
                              const struct GNUNET_PeerIdentity *pid,
                              const void *raw,
                              const size_t raw_size);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_TRANSPORT_ADDRESS_SERVICE_H */
#endif

/** @} */  /* end of group */

/* end of gnunet_transport_address_service.h */
