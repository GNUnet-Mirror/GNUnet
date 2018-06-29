/*
      This file is part of GNUnet
      Copyright (C) 2013-2017 GNUnet e.V.

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
 * Signature of functions that create the implementation-specific
 * state for a set supporting a specific operation.
 *
 * @return a set state specific to the supported operation, NULL on error
 */
typedef struct SetState *
(*SetCreateImpl) (void);


/**
 * Signature of functions that implement the add/remove functionality
 * for a set supporting a specific operation.
 *
 * @param set implementation-specific set state
 * @param ee element message from the client
 */
typedef void
(*SetAddRemoveImpl) (struct SetState *state,
                  struct ElementEntry *ee);


/**
 * Make a copy of a set's internal state.
 *
 * @param state set state to copy
 * @return copy of the internal state
 */
typedef struct SetState *
(*SetCopyStateImpl) (struct SetState *state);


/**
 * Signature of functions that implement the destruction of the
 * implementation-specific set state.
 *
 * @param state the set state, contains implementation-specific data
 */
typedef void
(*SetDestroyImpl) (struct SetState *state);


/**
 * Signature of functions that implement accepting a set operation.
 *
 * @param op operation that is created by accepting the operation,
 *        should be initialized by the implementation
 * @return operation-specific state to keep in @a op
 */
typedef struct OperationState *
(*OpAcceptImpl) (struct Operation *op);


/**
 * Signature of functions that implement starting the evaluation of
 * set operations.
 *
 * @param op operation that is created, should be initialized to
 *        begin the evaluation
 * @param opaque_context message to be transmitted to the listener
 *        to convince it to accept, may be NULL
 * @return operation-specific state to keep in @a op
 */
typedef struct OperationState *
(*OpEvaluateImpl) (struct Operation *op,
                   const struct GNUNET_MessageHeader *opaque_context);

/**
 * Signature of functions that implement operation cancelation.
 * This includes notifying the client about the operation's final
 * state.
 *
 * @param op operation state
 */
typedef void
(*OpCancelImpl) (struct Operation *op);


/**
 * Signature of functions called when the CADET channel died.
 *
 * @param op operation state
 */
typedef void
(*OpChannelDeathImpl) (struct Operation *op);



/**
 * Dispatch table for a specific set operation.  Every set operation
 * has to implement the callback in this struct.
 */
struct SetVT
{
  /**
   * Callback for the set creation.
   */
  SetCreateImpl create;

  /**
   * Callback for element insertion
   */
  SetAddRemoveImpl add;

  /**
   * Callback for element removal.
   */
  SetAddRemoveImpl remove;

  /**
   * Callback for making a copy of a set's internal state.
   */
  SetCopyStateImpl copy_state;

  /**
   * Callback for destruction of the set state.
   */
  SetDestroyImpl destroy_set;

  /**
   * Callback for accepting a set operation request
   */
  OpAcceptImpl accept;

  /**
   * Callback for starting evaluation with a remote peer.
   */
  OpEvaluateImpl evaluate;

  /**
   * Callback for canceling an operation.
   */
  OpCancelImpl cancel;

  /**
   * Callback called in case the CADET channel died.
   */
  OpChannelDeathImpl channel_death;

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

  /**
   * Number of elements in the array @a mutations.
   */
  unsigned int mutations_size;

  /**
   * #GNUNET_YES if the element is a remote element, and does not belong
   * to the operation's set.
   */
  int remote;
};


/**
 * A listener is inhabited by a client, and waits for evaluation
 * requests from remote peers.
 */
struct Listener;


/**
 * State we keep per client.
 */
struct ClientState
{
  /**
   * Set, if associated with the client, otherwise NULL.
   */
  struct Set *set;

  /**
   * Listener, if associated with the client, otherwise NULL.
   */
  struct Listener *listener;

  /**
   * Client handle.
   */
  struct GNUNET_SERVICE_Client *client;

  /**
   * Message queue.
   */
  struct GNUNET_MQ_Handle *mq;

};


/**
 * Operation context used to execute a set operation.
 */
struct Operation
{

  /**
   * Kept in a DLL of the listener, if @e listener is non-NULL.
   */
  struct Operation *next;

  /**
   * Kept in a DLL of the listener, if @e listener is non-NULL.
   */
  struct Operation *prev;

  /**
   * Channel to the peer.
   */
  struct GNUNET_CADET_Channel *channel;

  /**
   * Port this operation runs on.
   */
  struct Listener *listener;

  /**
   * Message queue for the channel.
   */
  struct GNUNET_MQ_Handle *mq;

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
   * Operation-specific operation state.  Note that the exact
   * type depends on this being a union or intersection operation
   * (and thus on @e vt).
   */
  struct OperationState *state;

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
   * When are elements sent to the client, and which elements are sent?
   */
  enum GNUNET_SET_ResultMode result_mode;

  /**
   * Always use delta operation instead of sending full sets,
   * even it it's less efficient.
   */
  int force_delta;

  /**
   * Always send full sets, even if delta operations would
   * be more efficient.
   */
  int force_full;

  /**
   * #GNUNET_YES to fail operations where Byzantine faults
   * are suspected
   */
  int byzantine;

  /**
   * Lower bound for the set size, used only when
   * byzantine mode is enabled.
   */
  int byzantine_lower_bound;

  /**
   * Unique request id for the request from a remote peer, sent to the
   * client, which will accept or reject the request.  Set to '0' iff
   * the request has not been suggested yet.
   */
  uint32_t suggest_id;

  /**
   * Generation in which the operation handle
   * was created.
   */
  unsigned int generation_created;

};


/**
 * SetContent stores the actual set elements, which may be shared by
 * multiple generations derived from one set.
 */
struct SetContent
{

  /**
   * Maps `struct GNUNET_HashCode *` to `struct ElementEntry *`.
   */
  struct GNUNET_CONTAINER_MultiHashMap *elements;

  /**
   * Mutations requested by the client that we're
   * unable to execute right now because we're iterating
   * over the underlying hash map of elements.
   */
  struct PendingMutation *pending_mutations_head;

  /**
   * Mutations requested by the client that we're
   * unable to execute right now because we're iterating
   * over the underlying hash map of elements.
   */
  struct PendingMutation *pending_mutations_tail;

  /**
   * Number of references to the content.
   */
  unsigned int refcount;

  /**
   * FIXME: document!
   */
  unsigned int latest_generation;

  /**
   * Number of concurrently active iterators.
   */
  int iterator_count;
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
 * Information about a mutation to apply to a set.
 */
struct PendingMutation
{
  /**
   * Mutations are kept in a DLL.
   */
  struct PendingMutation *prev;

  /**
   * Mutations are kept in a DLL.
   */
  struct PendingMutation *next;

  /**
   * Set this mutation is about.
   */
  struct Set *set;

  /**
   * Message that describes the desired mutation.
   * May only be a #GNUNET_MESSAGE_TYPE_SET_ADD or
   * #GNUNET_MESSAGE_TYPE_SET_REMOVE.
   */
  struct GNUNET_SET_ElementMessage *msg;
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
  struct ClientState *cs;

  /**
   * Content, possibly shared by multiple sets,
   * and thus reference counted.
   */
  struct SetContent *content;

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
   * List of generations we have to exclude, due to lazy copies.
   */
  struct GenerationRange *excluded_generations;

  /**
   * Current generation, that is, number of previously executed
   * operations and lazy copies on the underlying set content.
   */
  unsigned int current_generation;

  /**
   * Number of elements in array @a excluded_generations.
   */
  unsigned int excluded_generations_size;

  /**
   * Type of operation supported for this set
   */
  enum GNUNET_SET_OperationType operation;

  /**
   * Generation we're currently iteration over.
   */
  unsigned int iter_generation;

  /**
   * Each @e iter is assigned a unique number, so that the client
   * can distinguish iterations.
   */
  uint16_t iteration_id;

};


extern struct GNUNET_STATISTICS_Handle *_GSS_statistics;


/**
 * Destroy the given operation.   Used for any operation where both
 * peers were known and that thus actually had a vt and channel.  Must
 * not be used for operations where 'listener' is still set and we do
 * not know the other peer.
 *
 * Call the implementation-specific cancel function of the operation.
 * Disconnects from the remote peer.  Does not disconnect the client,
 * as there may be multiple operations per set.
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


/**
 * Is element @a ee part of the set used by @a op?
 *
 * @param ee element to test
 * @param op operation the defines the set and its generation
 * @return #GNUNET_YES if the element is in the set, #GNUNET_NO if not
 */
int
_GSS_is_element_of_operation (struct ElementEntry *ee,
                              struct Operation *op);


#endif
