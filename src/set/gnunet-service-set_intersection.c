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
 * @file set/gnunet-service-set_intersection.c
 * @brief two-peer set intersection
 * @author Christian Fuchs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet-service-set.h"
#include "strata_estimator.h"
#include "set_protocol.h"
#include <gcrypt.h>

#define BLOOMFILTER_SIZE GNUNET_CRYPTO_HASH_LENGTH
/**
 * Current phase we are in for a intersection operation.
 */
enum IntersectionOperationPhase
{
  /**
   * Alices has suggested an operation to bob, 
   * and is waiting for a bf or session end.
   */
  PHASE_INITIAL,
  /**
   * Bob has accepted the operation, Bob and Alice are now exchanging bfs
   * until one notices the their element count is equal
   */
  PHASE_BF_EXCHANGE,
  /**
   * if both peers have an equal peercount, they enter this state for 
   * one more turn, to see if they actually have agreed on a correct set.
   * if a peer finds the same element count after the next iteration, 
   * it ends the the session
   */
  PHASE_MAYBE_FINISHED,
  /**
   * The protocol is over.
   * Results may still have to be sent to the client.
   */
  PHASE_FINISHED
};


/**
 * State of an evaluate operation
 * with another peer.
 */
struct OperationState
{
  /**
   * The bf we currently receive
   */
  struct GNUNET_CONTAINER_BloomFilter *remote_bf;

  /**
   * BF of the set's element.
   */
  struct GNUNET_CONTAINER_BloomFilter *local_bf;

  /**
   * Current state of the operation.
   */
  enum IntersectionOperationPhase phase;

  /**
   * Generation in which the operation handle
   * was created.
   */
  unsigned int generation_created;
  
  /**
   * Maps element-id-hashes to 'elements in our set'.
   */
  struct GNUNET_CONTAINER_MultiHashMap *my_elements;
  
  /**
   * Current element count contained within contained_elements
   */
  uint32_t my_elements_count;

  /**
   * Iterator for sending elements on the key to element mapping to the client.
   */
  struct GNUNET_CONTAINER_MultiHashMap32Iterator *full_result_iter;
  
  /**
   * Evaluate operations are held in
   * a linked list.
   */
  struct OperationState *next;

   /**
    * Evaluate operations are held in
    * a linked list.
    */
  struct OperationState *prev;

  /**
   * Did we send the client that we are done?
   */
  int client_done_sent;
};


/**
 * Alice's version:
 * 
 * fills the contained-elements hashmap with all relevant 
 * elements and adds their mutated hashes to our local bloomfilter with mutator+1
 * 
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES if we should continue to
 *         iterate,
 *         #GNUNET_NO if not.
 */
static int 
iterator_initialization_by_alice (void *cls,
                                      const struct GNUNET_HashCode *key,
                                      void *value){
  struct ElementEntry *ee = value;
  struct Operation *op = cls;
  struct GNUNET_HashCode mutated_hash;
  
  //only consider this element, if it is valid for us
  if ((op->generation_created >= ee->generation_removed) 
       || (op->generation_created < ee->generation_added))
    return GNUNET_YES;
  
  // not contained according to bob's bloomfilter
  GNUNET_BLOCK_mingle_hash(&ee->element_hash, op->spec->salt, &mutated_hash);
  if (GNUNET_NO == GNUNET_CONTAINER_bloomfilter_test (op->state->remote_bf, 
                                                      &mutated_hash))
    return GNUNET_YES;
  
  op->state->my_elements_count++;  
  GNUNET_CONTAINER_multihashmap_put (op->state->my_elements, 
                                     &ee->element_hash, ee,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  
  // create our own bloomfilter with salt+1
  GNUNET_BLOCK_mingle_hash(&ee->element_hash, op->spec->salt+1, &mutated_hash);
  GNUNET_CONTAINER_bloomfilter_add (op->state->local_bf, 
                                    &mutated_hash);
  
  return GNUNET_YES;
}

/**
 * fills the contained-elements hashmap with all relevant 
 * elements and adds their mutated hashes to our local bloomfilter
 * 
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES if we should continue to
 *         iterate,
 *         #GNUNET_NO if not.
 */
static int 
iterator_initialization (void *cls,
                                      const struct GNUNET_HashCode *key,
                                      void *value){
  struct ElementEntry *ee = value;
  struct Operation *op = cls;
  struct GNUNET_HashCode mutated_hash;
  
  //only consider this element, if it is valid for us
  if ((op->generation_created >= ee->generation_removed) 
       || (op->generation_created < ee->generation_added))
    return GNUNET_YES;
  
  GNUNET_CONTAINER_multihashmap_put (op->state->my_elements, 
                                     &ee->element_hash, ee,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  
  GNUNET_BLOCK_mingle_hash(&ee->element_hash, op->spec->salt, &mutated_hash);
  
  GNUNET_CONTAINER_bloomfilter_add (op->state->local_bf, 
                                    &mutated_hash);
  
  return GNUNET_YES;
}

/**
 * Counts all valid elements in the hashmap 
 * (the ones that are valid in our generation)
 * 
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES if we should continue to
 *         iterate,
 *         #GNUNET_NO if not.
 */
static int 
iterator_element_count (void *cls,
                                      const struct GNUNET_HashCode *key,
                                      void *value){
  struct ElementEntry *ee = value;
  struct Operation *op = cls;
  
  //only consider this element, if it is valid for us
  if ((op->generation_created >= ee->generation_removed) 
       || (op->generation_created < ee->generation_added))
    return GNUNET_YES;
  
  op->state->my_elements_count++;
  
  return GNUNET_YES;
}

/**
 * removes element from a hashmap if it is not contained within the
 * provided remote bloomfilter. Then, fill our new bloomfilter.
 * 
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES if we should continue to
 *         iterate,
 *         #GNUNET_NO if not.
 */
static int
iterator_bf_round (void *cls,
                                      const struct GNUNET_HashCode *key,
                                      void *value){
  struct ElementEntry *ee = value;
  struct Operation *op = cls;
  struct GNUNET_HashCode mutated_hash;
  
  GNUNET_BLOCK_mingle_hash(&ee->element_hash, op->spec->salt, &mutated_hash);
  
  if (GNUNET_NO == GNUNET_CONTAINER_bloomfilter_test (op->state->remote_bf, 
                                     &mutated_hash)){
    op->state->my_elements_count--;
    GNUNET_CONTAINER_multihashmap_remove (op->state->my_elements, 
                                     &ee->element_hash,
                                     ee);
    return GNUNET_YES;
  }
  
  GNUNET_BLOCK_mingle_hash(&ee->element_hash, op->spec->salt+1, &mutated_hash);
  
  GNUNET_CONTAINER_bloomfilter_add (op->state->local_bf, 
                                    &mutated_hash);
  
  return GNUNET_YES;
}

/**
 * Inform the client that the union operation has failed,
 * and proceed to destroy the evaluate operation.
 *
 * @param op the intersection operation to fail
 */
static void
fail_intersection_operation (struct Operation *op)
{
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SET_ResultMessage *msg;

  if (op->state->my_elements)
    GNUNET_CONTAINER_multihashmap_destroy(op->state->my_elements);
  
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "intersection operation failed\n");

  ev = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_SET_RESULT);
  msg->result_status = htons (GNUNET_SET_STATUS_FAILURE);
  msg->request_id = htonl (op->spec->client_request_id);
  msg->element_type = htons (0);
  GNUNET_MQ_send (op->spec->set->client_mq, ev);
  _GSS_operation_destroy (op);
}



/**
 * Inform the peer that this operation is complete.
 *
 * @param eo the intersection operation to fail
 */
static void
send_peer_done (struct Operation *op)
{
  struct GNUNET_MQ_Envelope *ev;

  op->state->phase = PHASE_FINISHED;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Intersection succeeded, sending DONE\n");
  GNUNET_CONTAINER_bloomfilter_free (op->state->local_bf);
  op->state->local_bf = NULL;

  ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_SET_P2P_DONE);
  GNUNET_MQ_send (op->mq, ev);
}

/**
 * Send a request for the evaluate operation to a remote peer
 *
 * @param eo operation with the other peer
 */
static void
send_operation_request (struct Operation *op)
{
  struct GNUNET_MQ_Envelope *ev;
  struct OperationRequestMessage *msg;

  ev = GNUNET_MQ_msg_nested_mh (msg, GNUNET_MESSAGE_TYPE_SET_P2P_OPERATION_REQUEST,
                                op->spec->context_msg);

  if (NULL == ev)
  {
    /* the context message is too large */
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (op->spec->set->client);
    return;
  }
  msg->operation = htonl (GNUNET_SET_OPERATION_INTERSECTION);
  msg->app_id = op->spec->app_id;
  msg->salt = htonl (op->spec->salt);
  msg->element_count = htonl(op->state->my_elements);
  
  GNUNET_MQ_send (op->mq, ev);

  if (NULL != op->spec->context_msg)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "sent op request with context message\n");
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "sent op request without context message\n");

  if (NULL != op->spec->context_msg)
  {
    GNUNET_free (op->spec->context_msg);
    op->spec->context_msg = NULL;
  }

}

/**
 * Handle an BF message from a remote peer.
 *
 * @param cls the intersection operation
 * @param mh the header of the message
 */
static void
handle_p2p_bf (void *cls, const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;
  struct BFMessage *msg = (struct BFMessage *) mh;
  uint32_t old_count;

  old_count = op->state->my_elements_count;
  op->spec->salt = ntohl (msg->sender_mutator);
  
  op->state->remote_bf = GNUNET_CONTAINER_bloomfilter_init (&msg[1],
                                                            BLOOMFILTER_SIZE,
                                                            ntohl (msg->bloomfilter_length));
  op->state->local_bf = GNUNET_CONTAINER_bloomfilter_init (NULL,
                                                           BLOOMFILTER_SIZE,
                                                           GNUNET_CONSTANTS_BLOOMFILTER_K);
  switch (op->state->phase)
  {
  case PHASE_INITIAL:
    // If we are ot our first msg
    op->state->my_elements = GNUNET_CONTAINER_multihashmap_create (op->state->my_elements_count, GNUNET_YES);

    GNUNET_CONTAINER_multihashmap_iterate (op->spec->set->elements,
                                           &iterator_initialization_by_alice,
                                           op);
    break;
  case PHASE_BF_EXCHANGE:
  case PHASE_MAYBE_FINISHED:
    // if we are bob or alice and are continuing operation
    GNUNET_CONTAINER_multihashmap_iterate (op->spec->set->elements,
                                           &iterator_bf_round,
                                           op);
    break;
  default:
    GNUNET_break_op (0);
    fail_intersection_operation(op);
  }
  // the iterators created a new BF with salt+1
  // the peer needs this information for decoding the next BF
  // this behavior can be modified at will later on.
  op->spec->salt++;
  
  GNUNET_CONTAINER_bloomfilter_free (op->state->remote_bf);
  op->state->remote_bf = NULL;
  
  if ((op->state->phase == PHASE_MAYBE_FINISHED) 
       && (old_count == op->state->my_elements_count)){
    // In the last round we though we were finished, we now know this is correct
    send_peer_done(op);
    return;
  }
  
  op->state->phase = PHASE_BF_EXCHANGE;
  // maybe we are finished, but we do one more round to make certain
  // we don't have false positives ...
  if (op->state->my_elements_count == ntohl (msg->sender_element_count))
      op->state->phase = PHASE_MAYBE_FINISHED;

  send_bloomfilter (op);
}


/**
 * Handle an BF message from a remote peer.
 *
 * @param cls the intersection operation
 * @param mh the header of the message
 */
static void
handle_p2p_element_info (void *cls, const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;
  struct BFMessage *msg = (struct BFMessage *) mh;
  uint32_t remote_element_count;

  remote_element_count = ntohl(msg->sender_element_count);
  if ((op->state->phase == PHASE_INITIAL)
      || (op->state->my_elements_count > remote_element_count)){
    GNUNET_break_op (0);
    fail_intersection_operation(op);
  }

  op->state->phase = PHASE_BF_EXCHANGE;
  op->state->my_elements = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);

  op->state->local_bf = GNUNET_CONTAINER_bloomfilter_init (NULL,
                                                           BLOOMFILTER_SIZE,
                                                           GNUNET_CONSTANTS_BLOOMFILTER_K);
  GNUNET_CONTAINER_multihashmap_iterate (op->spec->set->elements,
                                         &iterator_initialization,
                                         op);

  GNUNET_CONTAINER_bloomfilter_free (op->state->remote_bf);
  op->state->remote_bf = NULL;

  if (op->state->my_elements_count == ntohl (msg->sender_element_count))
    op->state->phase = PHASE_MAYBE_FINISHED;

  send_bloomfilter (op);
}


/**
 * Send a bloomfilter to our peer.
 * that the operation is over.
 * After the result done message has been sent to the client,
 * destroy the evaluate operation.
 *
 * @param eo intersection operation
 */
static void
send_bloomfilter (struct Operation *op)
{
  struct GNUNET_MQ_Envelope *ev;
  struct BFMessage *msg;
  uint32_t bf_size;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "sending bf of size %u\n",);

  // send our bloomfilter
  bf_size = GNUNET_CONTAINER_bloomfilter_get_size (op->state->local_bf);

  ev = GNUNET_MQ_msg_extra (msg, bf_size, GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_BF);
  msg->reserved = 0;
  msg->sender_element_count = htonl (op->state->my_elements_count);
  msg->bloomfilter_length = htonl (bf_size);
  msg->sender_mutator = htonl (op->spec->salt);
  GNUNET_assert (GNUNET_SYSERR !=
                 GNUNET_CONTAINER_bloomfilter_get_raw_data (op->state->local_bf,
                                                            &msg->sender_bf_data,
                                                            BLOOMFILTER_SIZE));
  GNUNET_CONTAINER_bloomfilter_free (op->state->local_bf);
  op->state->local_bf = NULL;
  GNUNET_MQ_send (op->mq, ev);
}

/**
 * Send our element to the peer, in case our element count is lower than his
 *
 * @param eo intersection operation
 */
static void
send_element_count (struct Operation *op)
{
  struct GNUNET_MQ_Envelope *ev;
  struct BFMessage *msg;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "sending element count (bf_msg)\n");

  // just send our element count, as the other peer must start
  ev = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_ELEMENT_INFO);
  msg->reserved = 0;
  msg->sender_element_count = htonl (op->state->my_elements_count);
  msg->bloomfilter_length = htonl (0);
  msg->sender_mutator = htonl (0);

  GNUNET_MQ_send (op->mq, ev);
}

/**
 * Send a result message to the client indicating
 * that the operation is over.
 * After the result done message has been sent to the client,
 * destroy the evaluate operation.
 *
 * @param op intersection operation
 */
static void
finish_and_destroy (struct Operation *op)
{
  GNUNET_assert (GNUNET_NO == op->state->client_done_sent);

  if (GNUNET_SET_RESULT_FULL == op->spec->result_mode)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "sending full result set\n");
    op->state->full_result_iter =
        GNUNET_CONTAINER_multihashmap32_iterator_create (op->state->my_elements);
    send_remaining_elements (op);
    return;
  }
  send_client_done_and_destroy (op);
}

/**
 * Handle a done message from a remote peer
 *
 * @param cls the union operation
 * @param mh the message
 */
static void
handle_p2p_done (void *cls, const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;
  struct GNUNET_MQ_Envelope *ev;

  if ((op->state->phase = PHASE_FINISHED) || (op->state->phase = PHASE_MAYBE_FINISHED)){
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "got final DONE\n");
    
    finish_and_destroy (op);
    return;
  }
  
  GNUNET_break_op (0);
  fail_intersection_operation (op);
}


/**
 * Evaluate a union operation with
 * a remote peer.
 *
 * @param op operation to evaluate
 */
static void
intersection_evaluate (struct Operation *op)
{
  op->state = GNUNET_new (struct OperationState);
  /* we started the operation, thus we have to send the operation request */
  op->state->phase = PHASE_INITIAL;
  op->state->my_elements = GNUNET_CONTAINER_multihashmap_create(1, GNUNET_YES);
  GNUNET_CONTAINER_multihashmap_iterate(op->spec->set->elements, 
                                        &iterator_element_count,
                                        op);
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "evaluating intersection operation");
  send_operation_request (op);
}

/**
 * Accept an union operation request from a remote peer.
 * Only initializes the private operation state.
 *
 * @param op operation that will be accepted as a union operation
 */
static void
intersection_accept (struct Operation *op)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "accepting set union operation\n");
  op->state = GNUNET_new (struct OperationState);
  op->state->my_elements = GNUNET_CONTAINER_multihashmap_create(1, GNUNET_YES);
  GNUNET_CONTAINER_multihashmap_iterate(op->spec->set->elements, 
                                        &iterator_element_count,
                                        op);
  // if Alice (the peer) has more elements than Bob (us), she should start
  if (op->spec->element_count < op->state->my_elements_count){
    op->state->phase = PHASE_INITIAL;
    send_element_count(op);
    return;
  }
  // create a new bloomfilter in case we have fewer elements
  op->state->phase = PHASE_BF_EXCHANGE;
  op->state->local_bf = GNUNET_CONTAINER_bloomfilter_init (NULL,
                                                           BLOOMFILTER_SIZE,
                                                           GNUNET_CONSTANTS_BLOOMFILTER_K);
  GNUNET_CONTAINER_multihashmap_iterate (op->spec->set->elements,
                                         &iterator_initialization,
                                         op);
  send_bloomfilter (op);
}


/**
 * Create a new set supporting the intersection operation
 *
 * @return the newly created set
 */
static struct SetState *
intersection_set_create (void)
{
  struct SetState *set_state;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "intersection set created\n");

  set_state = GNUNET_new (struct SetState);
  
  return set_state;
}


/**
 * Add the element from the given element message to the set.
 *
 * @param set_state state of the set want to add to
 * @param ee the element to add to the set
 */
static void
intersection_add (struct SetState *set_state, struct ElementEntry *ee)
{
  //nothing to do here
}


/**
 * Destroy a set that supports the intersection operation
 *
 * @param set_state the set to destroy
 */
static void
intersection_set_destroy (struct SetState *set_state)
{
  GNUNET_free (set_state);
}


/**
 * Remove the element given in the element message from the set.
 *
 * @param set_state state of the set to remove from
 * @param element set element to remove
 */
static void
intersection_remove (struct SetState *set_state, struct ElementEntry *element)
{
  //nothing to do here
}


/**
 * Dispatch messages for a intersection operation.
 *
 * @param eo the state of the intersection evaluate operation
 * @param mh the received message
 * @return GNUNET_SYSERR if the tunnel should be disconnected,
 *         GNUNET_OK otherwise
 */
int
intersection_handle_p2p_message (struct Operation *op,
                                 const struct GNUNET_MessageHeader *mh)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "received p2p message (t: %u, s: %u)\n",
              ntohs (mh->type), ntohs (mh->size));
  switch (ntohs (mh->type))
  {
    /* this message handler is not active until after we received an
     * operation request message, thus the ops request is not handled here
     */
  case GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_ELEMENT_INFO:
    handle_p2p_element_info (op, mh);
    break;
  case GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_BF:
    handle_p2p_bf (op, mh);
    break;
  case GNUNET_MESSAGE_TYPE_SET_P2P_DONE:
    handle_p2p_done (op, mh);
    break;
  default:
    /* something wrong with mesh's message handlers? */
    GNUNET_assert (0);
  }
  return GNUNET_OK;
}

/**
 * Signal to the client that the operation has finished and
 * destroy the operation.
 *
 * @param cls operation to destroy
 */
static void
send_client_done_and_destroy (void *cls)
{
  struct Operation *op = cls;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SET_ResultMessage *rm;
  ev = GNUNET_MQ_msg (rm, GNUNET_MESSAGE_TYPE_SET_RESULT);
  rm->request_id = htonl (op->spec->client_request_id);
  rm->result_status = htons (GNUNET_SET_STATUS_DONE);
  rm->element_type = htons (0);
  GNUNET_MQ_send (op->spec->set->client_mq, ev);
  _GSS_operation_destroy (op);
}
/**
 * Send all elements in the full result iterator.
 *
 * @param cls operation
 */
static void
send_remaining_elements (void *cls)
{
  struct Operation *op = cls;
  struct ElementEntry *remaining; //TODO rework this, key entry does not exist here
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SET_ResultMessage *rm;
  struct GNUNET_SET_Element *element;
  int res;

  res = GNUNET_CONTAINER_multihashmap32_iterator_next (op->state->full_result_iter, NULL, (const void **) &remaining);
  if (GNUNET_NO == res) {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "sending done and destroy because iterator ran out\n");
    send_client_done_and_destroy (op);
    return;
  }
  
  element = &remaining->element;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "sending element (size %u) to client (full set)\n", element->size);
  GNUNET_assert (0 != op->spec->client_request_id);
  
  ev = GNUNET_MQ_msg_extra (rm, element->size, GNUNET_MESSAGE_TYPE_SET_RESULT);
  GNUNET_assert (NULL != ev);
  
  rm->result_status = htons (GNUNET_SET_STATUS_OK);
  rm->request_id = htonl (op->spec->client_request_id);
  rm->element_type = element->type;
  memcpy (&rm[1], element->data, element->size);

  GNUNET_MQ_notify_sent (ev, send_remaining_elements, op);
  GNUNET_MQ_send (op->spec->set->client_mq, ev);
}

/**
 * handler for peer-disconnects, notifies the client about the aborted operation
 * 
 * @param op the destroyed operation
 */
static void
intersection_peer_disconnect (struct Operation *op)
{
  if (PHASE_FINISHED != op->state->phase)
  {
    struct GNUNET_MQ_Envelope *ev;
    struct GNUNET_SET_ResultMessage *msg;

    ev = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_SET_RESULT);
    msg->request_id = htonl (op->spec->client_request_id);
    msg->result_status = htons (GNUNET_SET_STATUS_FAILURE);
    msg->element_type = htons (0);
    GNUNET_MQ_send (op->spec->set->client_mq, ev);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "other peer disconnected prematurely\n");
    _GSS_operation_destroy (op);
    return;
  }
  // else: the session has already been concluded
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "other peer disconnected (finished)\n");
  if (GNUNET_NO == op->state->client_done_sent)
    finish_and_destroy (op);
}


/**
 * Destroy the union operation.  Only things specific to the union operation are destroyed.
 * 
 * @param op union operation to destroy
 */
static void
intersection_op_cancel (struct Operation *op)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "destroying intersection op\n");
  /* check if the op was canceled twice */
  GNUNET_assert (NULL != op->state);
  if (NULL != op->state->remote_bf)
  {
    GNUNET_CONTAINER_bloomfilter_free (op->state->remote_bf);
    op->state->remote_bf = NULL;
  }
  if (NULL != op->state->local_bf)
  {
    GNUNET_CONTAINER_bloomfilter_free (op->state->local_bf);
    op->state->local_bf = NULL;
  }
  if (NULL != op->state->my_elements)
  {
    // no need to free the elements, they are still part of the set
    GNUNET_CONTAINER_multihashmap_destroy (op->state->my_elements);
    op->state->my_elements = NULL;
  }
  GNUNET_free (op->state);
  op->state = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "destroying intersection op done\n");
}

const struct SetVT *
_GSS_intersection_vt ()
{
  static const struct SetVT intersection_vt = {
    .create = &intersection_set_create,
    .msg_handler = &intersection_handle_p2p_message,
    .add = &intersection_add,
    .remove = &intersection_remove,
    .destroy_set = &intersection_set_destroy,
    .evaluate = &intersection_evaluate,
    .accept = &intersection_accept,
    .peer_disconnect = &intersection_peer_disconnect,
    .cancel = &intersection_op_cancel,
  };

  return &intersection_vt;
}
