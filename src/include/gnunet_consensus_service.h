/*
      This file is part of GNUnet
      (C) 2012 Christian Grothoff (and other contributing authors)

      GNUnet is free software; you can redistribute it and/or modify
      it under the terms of the GNU General Public License as published
      by the Free Software Foundation; either version 2, or (at your
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
 * @file include/gnunet_consensus_service.h
 * @brief 
 * @author Florian Dold
 */

#ifndef GNUNET_CONSENSUS_SERVICE_H
#define GNUNET_CONSENSUS_SERVICE_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_time_lib.h"


/**
 * Called when a new element was received from another peer.
 *
 * @return GNUNET_YES to keep the new value, GNUNET_NO to discard it
 */
typedef int (*GNUNET_CONSENSUS_NewElementCallback) (void *cls,
                                           struct GNUNET_PeerIdentity *source,
                                           uint8_t *new_data);


/**
 * Called when a conclusion was successful.
 *
 * TODO: A way to get to the set elements at the point of conclusion
 */
typedef void (*GNUNET_CONSENSUS_ConcludeCallback) (void *cls, int success);

/**
 * Opaque handle for the consensus service.
 */
struct GNUNET_CONSENSUS_Handle;


/**
 * Opaque handle for the consensus service.
 */
struct GNUNET_CONSENSUS_ConcludeHandle;


/**
 * Create a consensus session.
 *
 * @param peers zero-terminated list of peers participating in this consensus session
 * @param session_id session identifier
 *                   Allows a group of peers to have more than consensus session.
 * @param element_size size of the elements in the reconciled set in bytes
 * @param new_element callback, called when a new element is added to the set by
 *                    another peer
 * @param cls closure for new_element
 *
 * @return handle to use
 */
struct GNUNET_CONSENSUS_Handle *
GNUNET_CONSENSUS_create (struct GNUNET_PeerIdentity *peers,
                         uint32_t session_id,
                         int element_size,
                         uint8_t **initial_elements,
                         GNUNET_CONSENSUS_NewElementCallback new_element,
                         void *cls);


/**
 * Try to reach a short-term consensus with all other peers in the consensus session.
 *
 * @param consensus consensus session
 * @param timeout timeout after which the conculde callback
 *                will be called with success=GNUNET_NO
 * @param conclude called when the conclusion was successful
 * @param cls closure for the conclude callback
 *
 */
struct GNUNET_CONSENSUS_ConcludeHandle
GNUNET_CONSENSUS_conclude(struct GNUNET_CONSENSUS_Handle *consensus,
                          struct GNUNET_TIME_Relative timeout,
                          GNUNET_CONSENSUS_ConcludeCallback conclude,
                          void *cls);


/**
 * Insert an element in the set being reconsiled.
 *
 * @param handle handle for the consensus session
 * @param element the element to be inserted
 *
 */
void
GNUNET_CONSENSUS_insert(struct GNUNET_CONSENSUS_Handle, uint8_t *element);


/**
 * Destroy a consensus handle (free all state associated with
 * it).
 *
 * @param h consensus handle to destroy
 */
void
GNUNET_CONSENSUS_destroy (struct GNUNET_CONSENSUS_Handle *h);





#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
