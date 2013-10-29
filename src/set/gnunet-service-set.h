/*
      This file is part of GNUnet
      (C) 2013 Christian Grothoff (and other contributing authors)

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
 * @file set/gnunet-service-set.h
 * @brief common components for the implementation the different set operations
 * @author Florian Dold
 */

#ifndef GNUNET_SERVICE_SET_H_PRIVATE
#define GNUNET_SERVICE_SET_H_PRIVATE

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_applications.h"
#include "gnunet_core_service.h"
#include "gnunet_mesh_service.h"
#include "gnunet_set_service.h"
#include "set.h"


/**
 * Implementation-specific set state.
 * Used as opaque pointer, and specified further
 * in the respective implementation.
 */
struct SetState;


/**
 * Implementation-specific set operation.
 * Used as opaque pointer, and specified further
 * in the respective implementation.
 */
struct OperationState;


/* forward declarations */
struct Set;
struct TunnelContext;
struct ElementEntry;


/**
 * Detail information about an operation.
 */
struct OperationSpecification
{
  /**
   * The type of the operation.
   */
  enum GNUNET_SET_OperationType operation;

  /**
   * The remove peer we evaluate the operation with
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Application ID for the operation, used to distinguish
   * multiple operations of the same type with the same peer.
   */
  struct GNUNET_HashCode app_id;

  /**
   * Context message, may be NULL.
   */
  struct GNUNET_MessageHeader *context_msg;

  /**
   * Salt to use for the operation.
   */
  uint32_t salt;

  /**
   * ID used to identify responses to a client.
   */
  uint32_t client_request_id;

  /**
   * Set associated with the operation, NULL until the spec has been associated
   * with a set.
   */
  struct Set *set;

  /**
   * When are elements sent to the client, and which elements are sent?
   */
  enum GNUNET_SET_ResultMode result_mode;
};




/**
 * Signature of functions that create the implementation-specific
 * state for a set supporting a specific operation.
 *
 * @return a set state specific to the supported operation
 */
typedef struct SetState *(*CreateImpl) (void);


/**
 * Signature of functions that implement the add/remove functionality
 * for a set supporting a specific operation.
 *
 * @param set implementation-specific set state
 * @param msg element message from the client
 */
typedef void (*AddRemoveImpl) (struct SetState *state, struct ElementEntry *ee);


/**
 * Signature of functions that handle disconnection
 * of the remote peer.
 *
 * @param op the set operation, contains implementation-specific data
 */
typedef void (*PeerDisconnectImpl) (struct OperationState *op);


/**
 * Signature of functions that implement the destruction of the
 * implementation-specific set state.
 *
 * @param state the set state, contains implementation-specific data
 */
typedef void (*DestroySetImpl) (struct SetState *state);


/**
 * Signature of functions that implement the creation of set operations
 * (currently evaluate and accept).
 *
 * @param spec specification of the set operation to be created
 * @param tunnel the tunnel with the other peer
 * @param tc tunnel context
 */
typedef void (*OpCreateImpl) (struct OperationSpecification *spec,
                              struct GNUNET_MESH_Tunnel *tunnel,
                              struct TunnelContext *tc);


/**
 * Signature of functions that implement the message handling for
 * the different set operations.
 *
 * @param op operation state
 * @param msg received message
 * @return GNUNET_OK on success, GNUNET_SYSERR to
 *         destroy the operation and the tunnel
 */
typedef int (*MsgHandlerImpl) (struct OperationState *op,
                               const struct GNUNET_MessageHeader *msg);

typedef void (*CancelImpl) (struct SetState *set,
                            uint32_t request_id);


/**
 * Signature of functions that implement sending all the set's
 * elements to the client.
 *
 * @param set set that should be iterated over
 */
typedef void (*IterateImpl) (struct Set *set);


/**
 * Dispatch table for a specific set operation.
 * Every set operation has to implement the callback
 * in this struct.
 */
struct SetVT
{
  /**
   * Callback for the set creation.
   */
  CreateImpl create;

  /**
   * Callback for element insertion
   */
  AddRemoveImpl add;

  /**
   * Callback for element removal.
   */
  AddRemoveImpl remove;

  /**
   * Callback for accepting a set operation request
   */
  OpCreateImpl accept;

  /**
   * Callback for starting evaluation with a remote peer.
   */
  OpCreateImpl evaluate;

  /**
   * Callback for destruction of the set state.
   */
  DestroySetImpl destroy_set;

  /**
   * Callback for handling operation-specific messages.
   */
  MsgHandlerImpl msg_handler;

  /**
   * Callback for handling the remote peer's
   * disconnect.
   */
  PeerDisconnectImpl peer_disconnect;

  /**
   * Callback for canceling an operation by
   * its ID.
   */
  CancelImpl cancel;

  /**
   * Callback for iterating over all set elements.
   */
  IterateImpl iterate;
};


/**
 * Information about an element element in the set.
 * All elements are stored in a hash-table
 * from their hash-code to their 'struct Element',
 * so that the remove and add operations are reasonably
 * fast.
 */
struct ElementEntry
{
  /**
   * The actual element. The data for the element
   * should be allocated at the end of this struct.
   */
  struct GNUNET_SET_Element element;

  /**
   * Hash of the element.
   * Will be used to derive the different IBF keys
   * for different salts.
   */
  struct GNUNET_HashCode element_hash;

  /**
   * Generation the element was added by the client.
   * Operations of earlier generations will not consider the element.
   */
  unsigned int generation_added;

  /**
   * GNUNET_YES if the element has been removed in some generation.
   */
  int removed;

  /**
   * Generation the element was removed by the client.
   * Operations of later generations will not consider the element.
   * Only valid if is_removed is GNUNET_YES.
   */
  unsigned int generation_removed;

  /**
   * GNUNET_YES if the element is a remote element, and does not belong
   * to the operation's set.
   */
  int remote;
};


/**
 * A set that supports a specific operation
 * with other peers.
 */
struct Set
{
  /**
   * Client that owns the set.
   * Only one client may own a set.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Message queue for the client
   */
  struct GNUNET_MQ_Handle *client_mq;

  /**
   * Type of operation supported for this set
   */
  enum GNUNET_SET_OperationType operation;

  /**
   * Virtual table for this set.
   * Determined by the operation type of this set.
   */
  const struct SetVT *vt;

  /**
   * Sets are held in a doubly linked list.
   */
  struct Set *next;

  /**
   * Sets are held in a doubly linked list.
   */
  struct Set *prev;

  /**
   * Implementation-specific state.
   */
  struct SetState *state;

  /**
   * Current state of iterating elements for the client.
   * NULL if we are not currently iterating.
   */
  struct GNUNET_CONTAINER_MultiHashMapIterator *iter;

  /**
   * Maps 'struct GNUNET_HashCode' to 'struct ElementEntry'.
   */
  struct GNUNET_CONTAINER_MultiHashMap *elements;

  /**
   * Current generation, that is, number of
   * previously executed operations on this set
   */
  unsigned int current_generation;
};


/**
 * Information about a tunnel we are connected to.
 * Used as tunnel context with mesh.
 */
struct TunnelContext
{
  /**
   * V-Table for the operation belonging
   * to the tunnel contest.
   */
  const struct SetVT *vt;

  /**
   * Implementation-specific operation state.
   */
  struct OperationState *op;
};


/**
 * Get the table with implementing functions for
 * set union.
 */
const struct SetVT *
_GSS_union_vt (void);

/**
 * Get the table with implementing functions for
 * set intersection.
 */
const struct SetVT *
_GSS_intersection_vt (void);


#endif
