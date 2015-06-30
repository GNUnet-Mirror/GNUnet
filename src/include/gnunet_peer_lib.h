/*
     This file is part of GNUnet.
     Copyright (C) 2006, 2009 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_peer_lib.h
 * @brief helper library for interning of peer identifiers
 * @author Christian Grothoff
 */

#ifndef GNUNET_PEER_LIB_H
#define GNUNET_PEER_LIB_H

#include "gnunet_util_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * A GNUNET_PEER_Id is simply a shorter version of a "struct
 * GNUNET_PeerIdentifier" that can be used inside of a GNUnet peer to
 * save memory when the same identifier needs to be used over and over
 * again.
 */
typedef unsigned int GNUNET_PEER_Id;


/**
 * Search for a peer identity. The reference counter is not changed.
 *
 * @param pid identity to find
 * @return the interned identity or 0.
 */
GNUNET_PEER_Id
GNUNET_PEER_search (const struct GNUNET_PeerIdentity *pid);


/**
 * Intern an peer identity.  If the identity is already known, its
 * reference counter will be increased by one.
 *
 * @param pid identity to intern
 * @return the interned identity.
 */
GNUNET_PEER_Id
GNUNET_PEER_intern (const struct GNUNET_PeerIdentity *pid);


/**
 * Change the reference counter of an interned PID.
 *
 * @param id identity to change the RC of
 * @param delta how much to change the RC
 */
void
GNUNET_PEER_change_rc (GNUNET_PEER_Id id, int delta);


/**
 * Decrement multiple RCs of peer identities by one.
 *
 * @param ids array of PIDs to decrement the RCs of
 * @param count size of the @a ids array
 */
void
GNUNET_PEER_decrement_rcs (const GNUNET_PEER_Id *ids,
                           unsigned int count);


/**
 * Convert an interned PID to a normal peer identity.
 *
 * @param id interned PID to convert
 * @param pid where to write the normal peer identity
 */
void
GNUNET_PEER_resolve (GNUNET_PEER_Id id,
                     struct GNUNET_PeerIdentity *pid);


/**
 * Convert an interned PID to a normal peer identity.
 *
 * @param id interned PID to convert
 * @return pointer to peer identity, valid as long @a id is valid
 */
const struct GNUNET_PeerIdentity *
GNUNET_PEER_resolve2 (GNUNET_PEER_Id id);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_PEER_LIB_H */
#endif
/* end of gnunet_peer_lib.h */
