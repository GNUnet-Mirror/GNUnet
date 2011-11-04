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
 * @brief code for managing low-level 'plaintext' connections with transport (key exchange may or may not be done yet)
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_CORE_NEIGHBOURS_H
#define GNUNET_SERVICE_CORE_NEIGHBOURS_H

#include "gnunet_util_lib.h"

/**
 * Transmit the given message to the given target.  Note that a
 * non-control messages should only be transmitted after a
 * 'GSC_SESSION_solicit' call was made (that call is always invoked
 * when the message queue is empty).  Outbound quotas and memory
 * bounds will then be enfoced (as GSC_SESSION_solicit is only called
 * if sufficient banwdith is available).
 *
 * @param target peer that should receive the message (must be connected)
 * @param msg message to transmit
 * @param timeout by when should the transmission be done?
 */
void
GSC_NEIGHBOURS_transmit (const struct GNUNET_PeerIdentity *target,
                         const struct GNUNET_MessageHeader *msg,
                         struct GNUNET_TIME_Relative timeout);


/**
 * Initialize neighbours subsystem.
 */
int
GSC_NEIGHBOURS_init (void);


/**
 * Shutdown neighbours subsystem.
 */
void
GSC_NEIGHBOURS_done (void);


#endif
