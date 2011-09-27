/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
