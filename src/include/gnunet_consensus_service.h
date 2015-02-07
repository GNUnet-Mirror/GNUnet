/*
      This file is part of GNUnet
      Copyright (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_consensus_service.h
 * @brief multi-peer set reconciliation
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
#include "gnunet_configuration_lib.h"
#include "gnunet_set_service.h"


/**
 * Called when a new element was received from another peer, or an error occured.
 * May deliver duplicate values.
 * Elements given to a consensus operation by the local peer are NOT given
 * to this callback.
 *
 * @param cls closure
 * @param element new element, NULL on error
 */
typedef void (*GNUNET_CONSENSUS_ElementCallback) (void *cls,
                                                  const struct GNUNET_SET_Element *element);



/**
 * Opaque handle for the consensus service.
 */
struct GNUNET_CONSENSUS_Handle;


/**
 * Create a consensus session.  The set being reconciled is initially
 * empty.
 *
 * @param cfg
 * @param num_peers
 * @param peers array of peers participating in this consensus session
 *              Inclusion of the local peer is optional.
 * @param session_id session identifier
 *                   Allows a group of peers to have more than consensus session.
 * @param start start time of the consensus, conclude should be called before
 *              the start time.
 * @param deadline time when the consensus should have concluded
 * @param new_element_cb callback, called when a new element is added to the set by
 *                    another peer. Also called when an error occurs.
 * @param new_element_cls closure for new_element
 * @return handle to use, NULL on error
 */
struct GNUNET_CONSENSUS_Handle *
GNUNET_CONSENSUS_create (const struct GNUNET_CONFIGURATION_Handle *cfg,
                         unsigned int num_peers,
                         const struct GNUNET_PeerIdentity *peers,
                         const struct GNUNET_HashCode *session_id,
                         struct GNUNET_TIME_Absolute start,
                         struct GNUNET_TIME_Absolute deadline,
                         GNUNET_CONSENSUS_ElementCallback new_element_cb,
                         void *new_element_cls);


/**
 * Called when an insertion (transmission to consensus service, which
 * does not imply fully consensus on this element with all other
 * peers) was successful.  May not call GNUNET_CONSENSUS_destroy();
 * schedule a task to call GNUNET_CONSENSUS_destroy() instead (if
 * needed).
 *
 * @param cls
 * @param success #GNUNET_OK on success, #GNUNET_SYSERR if
 *        the insertion and thus the consensus failed for good
 */
typedef void (*GNUNET_CONSENSUS_InsertDoneCallback) (void *cls,
                                                     int success);


/**
 * Insert an element in the set being reconsiled.  Only transmit changes to
 * other peers if GNUNET_CONSENSUS_begin() has been called.
 * Must not be called after GNUNET_CONSENSUS_conclude().
 * May not call GNUNET_CONSENSUS_destroy(); schedule a task to call
 * GNUNET_CONSENSUS_destroy() instead (if needed).
 *
 * @param consensus handle for the consensus session
 * @param element the element to be inserted
 * @param idc function called when we are done with this element and it
 *            is thus allowed to call GNUNET_CONSENSUS_insert() again
 * @param idc_cls closure for @a idc
 */
void
GNUNET_CONSENSUS_insert (struct GNUNET_CONSENSUS_Handle *consensus,
                         const struct GNUNET_SET_Element *element,
                         GNUNET_CONSENSUS_InsertDoneCallback idc,
                         void *idc_cls);



/**
 * Called when a conclusion was successful.
 *
 * @param cls
 */
typedef void (*GNUNET_CONSENSUS_ConcludeCallback) (void *cls);


/**
 * We are finished inserting new elements into the consensus;
 * try to conclude the consensus within a given time window.
 *
 * @param consensus consensus session
 * @param conclude called when the conclusion was successful
 * @param conclude_cls closure for the conclude callback
 */
void
GNUNET_CONSENSUS_conclude (struct GNUNET_CONSENSUS_Handle *consensus,
                           GNUNET_CONSENSUS_ConcludeCallback conclude,
                           void *conclude_cls);


/**
 * Destroy a consensus handle (free all state associated with
 * it, no longer call any of the callbacks).
 *
 * @param consensus handle to destroy
 */
void
GNUNET_CONSENSUS_destroy (struct GNUNET_CONSENSUS_Handle *consensus);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
