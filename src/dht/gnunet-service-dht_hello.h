/*
     This file is part of GNUnet.
     Copyright (C) 2011 GNUnet e.V.

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
 * @file dht/gnunet-service-dht_hello.h
 * @brief GNUnet DHT integration with peerinfo
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_DHT_HELLO_H
#define GNUNET_SERVICE_DHT_HELLO_H

#include "gnunet_util_lib.h"
#include "gnunet_hello_lib.h"

/**
 * Obtain a peer's HELLO if available
 *
 * @param peer peer to look for a HELLO from
 * @return HELLO for the given peer
 */
const struct GNUNET_HELLO_Message *
GDS_HELLO_get (const struct GNUNET_PeerIdentity *peer);


/**
 * Initialize HELLO subsystem.
 */
void
GDS_HELLO_init (void);


/**
 * Shutdown HELLO subsystem.
 */
void
GDS_HELLO_done (void);

#endif
