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
#include "gnunet_configuration_lib.h"


/**
 * An element of the consensus set.
 */
struct GNUNET_CONSENSUS_Element
{
  /**
   * The actual data of the element.
   */
   const void *data;

   /**
    * Size of the element's data.
    */
   uint16_t size;

   /**
    * Application specific element type
    */
   uint16_t type;
};


/**
 * Called when a new element was received from another peer, or an error occured.
 *
 * Elements given to a consensus operation by the local peer are NOT given
 * to this callback.
 *
 * @param cls closure
 * @param element new element, NULL on error
 */
typedef void (*GNUNET_CONSENSUS_NewElementCallback) (void *cls,
                                                     struct GNUNET_CONSENSUS_Element *element);



/**
 * Opaque handle for the consensus service.
 */
struct GNUNET_CONSENSUS_Handle;


/**
 * Create a consensus session.
 *
 * @param cfg
 * @param num_peers
 * @param peers array of peers participating in this consensus session
 *              Inclusion of the local peer is optional.
 * @param session_id session identifier
 *                   Allows a group of peers to have more than consensus session.
 * @param num_initial_elements number of entries in the 'initial_elements' array
 * @param initial_elements our elements for the consensus (each of 'element_size'
 * @param new_element callback, called when a new element is added to the set by
 *                    another peer
 * @param new_element_cls closure for new_element
 * @return handle to use, NULL on error
 */
struct GNUNET_CONSENSUS_Handle *
GNUNET_CONSENSUS_create (const struct GNUNET_CONFIGURATION_Handle *cfg,
			 unsigned int num_peers,
			 const struct GNUNET_PeerIdentity *peers,
                         const struct GNUNET_HashCode *session_id,
                         /*
			 unsigned int num_initial_elements,
                         const struct GNUNET_CONSENSUS_Element **initial_elements,
                         */
                         GNUNET_CONSENSUS_NewElementCallback new_element,
                         void *new_element_cls);


/**
 * Called when an insertion (transmission to consensus service,
 * which does not imply fully consensus on this element with
 * all other peers) was successful.
 *
 * @param cls
 * @param success GNUNET_OK on success, GNUNET_SYSERR if 
 *        the insertion and thus the consensus failed for good
 */
typedef void (*GNUNET_CONSENSUS_InsertDoneCallback) (void *cls,
						     int success);


/**
 * Insert an element in the set being reconsiled.  Must not be called after
 * "GNUNET_CONSENSUS_conclude".
 *
 * @param consensus handle for the consensus session
 * @param element the element to be inserted
 * @param idc function called when we are done with this element and it 
 *            is thus allowed to call GNUNET_CONSENSUS_insert again
 * @param idc_cls closure for 'idc'
 */
void
GNUNET_CONSENSUS_insert (struct GNUNET_CONSENSUS_Handle *consensus,
			 const struct GNUNET_CONSENSUS_Element *element,
			 GNUNET_CONSENSUS_InsertDoneCallback idc,
			 void *idc_cls);


/**
 * Called when a conclusion was successful.
 *
 * @param cls
 * @param num_peers_in_consensus
 * @param peers_in_consensus
 */
typedef void (*GNUNET_CONSENSUS_ConcludeCallback) (void *cls, 
						   unsigned int num_peers_in_consensus,
						   const struct GNUNET_PeerIdentity *peers_in_consensus);


/**
 * We are finished inserting new elements into the consensus;
 * try to conclude the consensus within a given time window.
 *
 * @param consensus consensus session
 * @param timeout timeout after which the conculde callback
 *                must be called
 * @param conclude called when the conclusion was successful
 * @param conclude_cls closure for the conclude callback
 */
void
GNUNET_CONSENSUS_conclude (struct GNUNET_CONSENSUS_Handle *consensus,
			   struct GNUNET_TIME_Relative timeout,
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
