/*
      This file is part of GNUnet
      Copyright (C) 2013, 2014 Christian Grothoff (and other contributing authors)

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
 * @file set/gnunet-service-set.h
 * @brief common components for the implementation the different set operations
 * @author Florian Dold
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_SET_H_PRIVATE
#define GNUNET_SERVICE_SET_H_PRIVATE

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_applications.h"
#include "gnunet_core_service.h"
#include "gnunet_cadet_service.h"
#include "gnunet_set_service.h"
#include "set.h"


/**
 * Implementation-specific set state.  Used as opaque pointer, and
 * specified further in the respective implementation.
 */
struct SetState;

/**
 * Implementation-specific set operation.  Used as opaque pointer, and
 * specified further in the respective implementation.
 */
struct OperationState;

/**
 * A set that supports a specific operation with other peers.
 */
struct Set;

/**
 * Information about an element element in the set.  All elements are
 * stored in a hash-table from their hash-code to their 'struct
 * Element', so that the remove and add operations are reasonably
 * fast.
 */
struct ElementEntry;

/**
 * Operation context used to execute a set operation.
 */
struct Operation;


/**
 * Detail information about an operation.
 */
struct OperationSpecification
{

  /**
   * The remove peer we evaluate the operation with.
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
   * Set associated with the operation, NULL until the spec has been
   * associated with a set.
   */
  struct Set *set;

  /**
   * Salt to use for the operation.
   */
  uint32_t salt;

  /**
   * Remote peers element count
   */
  uint32_t remote_element_count;

  /**
   * ID used to identify an operation between service and client
   */
  uint32_t client_request_id;

  /**
   * The type of the operation.
   */
  enum GNUNET_SET_OperationType operation;

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
typedef struct SetState *
(*CreateImpl) (void);


/**
 * Signature of functions that implement the add/remove functionality
 * for a set supporting a specific operation.
 *
 * @param set implementation-specific set state
 * @param ee element message from the client
 */
typedef void
(*AddRemoveImpl) (struct SetState *state,
                  struct ElementEntry *ee);


/**
 * Signature of functions that handle disconnection of the remote
 * peer.
 *
 * @param op the set operation, contains implementation-specific data
 */
typedef void
(*PeerDisconnectImpl) (struct Operation *op);


/**
 * Signature of functions that implement the destruction of the
 * implementation-specific set state.
 *
 * @param state the set state, contains implementation-specific data
 */
typedef void
(*DestroySetImpl) (struct SetState *state);


/**
 * Signature of functions that implement accepting a set operation.
 *
 * @param op operation that is created by accepting the operation,
 *        should be initialized by the implementation
 */
typedef void
(*OpAcceptImpl) (struct Operation *op);


/**
 * Signature of functions that implement starting the evaluation of
 * set operations.
 *
 * @param op operation that is created, should be initialized to
 *        begin the evaluation
 * @param opaque_context message to be transmitted to the listener
 *        to convince him to accept, may be NULL
 */
typedef void
(*OpEvaluateImpl) (struct Operation *op,
                   const struct GNUNET_MessageHeader *opaque_context);


/**
 * Signature of functions that implement the message handling for
 * the different set operations.
 *
 * @param op operation state
 * @param msg received message
 * @return #GNUNET_OK on success, #GNUNET_SYSERR to
 *         destroy the operation and the tunnel
 */
typedef int
(*MsgHandlerImpl) (struct Operation *op,
                   const struct GNUNET_MessageHeader *msg);


/**
 * Signature of functions that implement operation cancellation
 *
 * @param op operation state
 */
typedef void
(*CancelImpl) (struct Operation *op);


typedef struct SetState *
(*CopyStateImpl) (struct Set *op);


/**
 * Dispatch table for a specific set operation.  Every set operation
 * has to implement the callback in this struct.
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
  OpAcceptImpl accept;

  /**
   * Callback for starting evaluation with a remote peer.
   */
  OpEvaluateImpl evaluate;

  /**
   * Callback for destruction of the set state.
   */
  DestroySetImpl destroy_set;

  /**
   * Callback for handling operation-specific messages.
   */
  MsgHandlerImpl msg_handler;

  /**
   * Callback for handling the remote peer's disconnect.
   */
  PeerDisconnectImpl peer_disconnect;

  /**
   * Callback for canceling an operation by its ID.
   */
  CancelImpl cancel;

  CopyStateImpl copy_state;
};


/**
 * MutationEvent gives information about changes
 * to an element (removal / addition) in a set content.
 */
struct MutationEvent
{
  /**
   * First generation affected by this mutation event.
   *
   * If @a generation is 0, this mutation event is a list
   * sentinel element.
   */
  unsigned int generation;

  /**
   * If @a added is #GNUNET_YES, then this is a
   * `remove` event, otherwise it is an `add` event.
   */
  int added;
};


/**
 * Information about an element element in the set.  All elements are
 * stored in a hash-table from their hash-code to their `struct
 * Element`, so that the remove and add operations are reasonably
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
   * Hash of the element.  For set union: Will be used to derive the
   * different IBF keys for different salts.
   */
  struct GNUNET_HashCode element_hash;

  /**
   * If @a mutations is not NULL, it contains
   * a list of mutations, ordered by increasing generation.
   * The list is terminated by a sentinel event with `generation`
   * set to 0.
   *
   * If @a mutations is NULL, then this element exists in all generations
   * of the respective set content this element belongs to.
   */
  struct MutationEvent *mutations;

  unsigned int mutations_size;

  /**
   * #GNUNET_YES if the element is a remote element, and does not belong
   * to the operation's set.
   */
  int remote;
};


/**
 * Operation context used to execute a set operation.
 */
struct Operation
{
  /**
   * V-Table for the operation belonging to the tunnel contest.
   *
   * Used for all operation specific operations after receiving the ops request
   */
  const struct SetVT *vt;

  /**
   * Channel to the peer.
   */
  struct GNUNET_CADET_Channel *channel;

  /**
   * Message queue for the channel.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Detail information about the set operation, including the set to
   * use.  When 'spec' is NULL, the operation is not yet entirely
   * initialized.
   */
  struct OperationSpecification *spec;

  /**
   * Operation-specific operation state.  Note that the exact
   * type depends on this being a union or intersection operation
   * (and thus on @e vt).
   */
  struct OperationState *state;

  /**
   * Evaluate operations are held in a linked list.
   */
  struct Operation *next;

  /**
   * Evaluate operations are held in a linked list.
   */
  struct Operation *prev;

  /**
   * The identity of the requesting peer.  Needs to
   * be stored here as the op spec might not have been created yet.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Timeout task, if the incoming peer has not been accepted
   * after the timeout, it will be disconnected.
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

  /**
   * Unique request id for the request from a remote peer, sent to the
   * client, which will accept or reject the request.  Set to '0' iff
   * the request has not been suggested yet.
   */
  uint32_t suggest_id;

  /**
   * #GNUNET_YES if this is not a "real" set operation yet, and we still
   * need to wait for the other peer to give us more details.
   */
  int is_incoming;

  /**
   * Generation in which the operation handle
   * was created.
   */
  unsigned int generation_created;

  /**
   * Incremented whenever (during shutdown) some component still
   * needs to do something with this before the operation is freed.
   * (Used as a reference counter, but only during termination.)
   */
  unsigned int keep;
};


/**
 * SetContent stores the actual set elements,
 * which may be shared by multiple generations derived
 * from one set.
 */
struct SetContent
{
  /**
   * Number of references to the content.
   */
  unsigned int refcount;

  /**
   * Maps `struct GNUNET_HashCode *` to `struct ElementEntry *`.
   */
  struct GNUNET_CONTAINER_MultiHashMap *elements;

  unsigned int latest_generation;
};


struct GenerationRange
{
  /**
   * First generation that is excluded.
   */
  unsigned int start;

  /**
   * Generation after the last excluded generation.
   */
  unsigned int end;
};


/**
 * A set that supports a specific operation with other peers.
 */
struct Set
{

  /**
   * Sets are held in a doubly linked list (in `sets_head` and `sets_tail`).
   */
  struct Set *next;

  /**
   * Sets are held in a doubly linked list.
   */
  struct Set *prev;

  /**
   * Client that owns the set.  Only one client may own a set,
   * and there can only be one set per client.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Message queue for the client.
   */
  struct GNUNET_MQ_Handle *client_mq;

  /**
   * Virtual table for this set.  Determined by the operation type of
   * this set.
   *
   * Used only for Add/remove of elements and when receiving an incoming
   * operation from a remote peer.
   */
  const struct SetVT *vt;

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
   * Evaluate operations are held in a linked list.
   */
  struct Operation *ops_head;

  /**
   * Evaluate operations are held in a linked list.
   */
  struct Operation *ops_tail;

  /**
   * Current generation, that is, number of previously executed
   * operations and lazy copies on the underlying set content.
   */
  unsigned int current_generation;

  /**
   * List of generations we have to exclude, due to lazy copies.
   */
  struct GenerationRange *excluded_generations;

  unsigned int excluded_generations_size;

  /**
   * Type of operation supported for this set
   */
  enum GNUNET_SET_OperationType operation;

  /**
   * Each @e iter is assigned a unique number, so that the client
   * can distinguish iterations.
   */
  uint16_t iteration_id;

  /**
   * Content, possibly shared by multiple sets,
   * and thus reference counted.
   */
  struct SetContent *content;

};


/**
 * Destroy the given operation.  Call the implementation-specific
 * cancel function of the operation.  Disconnects from the remote
 * peer.  Does not disconnect the client, as there may be multiple
 * operations per set.
 *
 * @param op operation to destroy
 * @param gc #GNUNET_YES to perform garbage collection on the set
 */
void
_GSS_operation_destroy (struct Operation *op,
                        int gc);


/**
 * Get the table with implementing functions for set union.
 *
 * @return the operation specific VTable
 */
const struct SetVT *
_GSS_union_vt (void);


/**
 * Get the table with implementing functions for set intersection.
 *
 * @return the operation specific VTable
 */
const struct SetVT *
_GSS_intersection_vt (void);


int
_GSS_is_element_of_set (struct ElementEntry *ee,
                        struct Set *set);

int
_GSS_is_element_of_operation (struct ElementEntry *ee,
                              struct Operation *op);


#endif
