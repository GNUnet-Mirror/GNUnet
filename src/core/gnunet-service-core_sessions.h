/*
     This file is part of GNUnet.
     (C) 2009, 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file core/gnunet-service-core_neighbours.h
 * @brief code for managing of 'encrypted' sessions (key exchange done) 
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_CORE_SESSIONS_H
#define GNUNET_SERVICE_CORE_SESSIONS_H

#include "gnunet_service_core_kx.h"
#include "gnunet_service_core_sessions.h"


/**
 * End the session with the given peer (we are no longer
 * connected).
 *
 * @param pid identity of peer to kill session with
 */
void
GSC_SESSIONS_end (const struct GNUNET_PeerIdentity *pid);


/**
 * Traffic is being solicited for the given peer.  This means that
 * the message queue on the transport-level is now empty and it
 * is now OK to transmit another (non-control) message.
 *
 * @param pid identity of peer ready to receive data
 */
void
GSC_SESSIONS_solicit (const struct GNUNET_PeerIdentity *pid);


/**
 * Initialize sessions subsystem.
 */
void
GSC_SESSIONS_init (void);


/**
 * Shutdown sessions subsystem.
 */
void
GSC_SESSIONS_done (void);



#endif
