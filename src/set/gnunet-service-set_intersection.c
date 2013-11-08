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

/**
 * Current phase we are in for a intersection operation.
 */
enum IntersectionOperationPhase
{
  /**
   * We get our tunnel but received no message as of now
   */
  PHASE_EXPECT_INITIAL,
  /**
   * We expect a BF + the number of the other peers elements
   */
  PHASE_BF_EXCHANGE,
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
   * Tunnel to the remote peer.
   */
  struct GNUNET_MESH_Tunnel *tunnel;

  /**
   * Detail information about the set operation,
   * including the set to use.
   */
  struct OperationSpecification *spec;

  /**
   * Message queue for the peer.
   */
  struct GNUNET_MQ_Handle *mq;

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
   * Set state of the set that this operation
   * belongs to.
   */
  struct Set *set;
  
  /**
   * Maps element-id-hashes to 'elements in our set'.
   */
  struct GNUNET_CONTAINER_MultiHashMap *contained_elements;
  
  /**
   * Current element count contained within contained_elements
   */
  uint64_t contained_elements_count;

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
 * Extra state required for efficient set intersection.
 */
struct SetState
{
  /**
   * Evaluate operations are held in
   * a linked list.
   */
  struct OperationState *ops_head;

  /**
   * Evaluate operations are held in
   * a linked list.
   */
  struct OperationState *ops_tail;
};


/**
 * Destroy a intersection operation, and free all resources
 * associated with it.
 *
 * @param eo the intersection operation to destroy
 */
static void
intersection_operation_destroy (struct OperationState *eo)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "destroying intersection op\n");
  GNUNET_CONTAINER_DLL_remove (eo->set->state->ops_head,
                               eo->set->state->ops_tail,
                               eo);
  if (NULL != eo->mq)
  {
    GNUNET_MQ_destroy (eo->mq);
    eo->mq = NULL;
  }
  if (NULL != eo->tunnel)
  {
    struct GNUNET_MESH_Tunnel *t = eo->tunnel;
    eo->tunnel = NULL;
    GNUNET_MESH_tunnel_destroy (t);
  }
  // TODO: destroy set elements?
  if (NULL != eo->spec)
  {
    if (NULL != eo->spec->context_msg)
    {
      GNUNET_free (eo->spec->context_msg);
      eo->spec->context_msg = NULL;
    }
    GNUNET_free (eo->spec);
    eo->spec = NULL;
  }
  GNUNET_free (eo);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "destroying intersection op done\n");

  /* FIXME: do a garbage collection of the set generations */
}


/**
 * Inform the client that the intersection operation has failed,
 * and proceed to destroy the evaluate operation.
 *
 * @param eo the intersection operation to fail
 */
static void
fail_intersection_operation (struct OperationState *eo)
{
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SET_ResultMessage *msg;

  ev = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_SET_RESULT);
  msg->result_status = htons (GNUNET_SET_STATUS_FAILURE);
  msg->request_id = htonl (eo->spec->client_request_id);
  msg->element_type = htons (0);
  GNUNET_MQ_send (eo->spec->set->client_mq, ev);
  intersection_operation_destroy (eo);
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
  struct OperationState *eo = cls;
  struct BFMessage *msg = (struct BFMessage *) mh;
  unsigned int buckets_in_message;

  if (eo->phase == PHASE_EXPECT_INITIAL )
  {
    eo->phase = PHASE_BF_EXCHANGE;
    
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "creating new bf of size %u\n", 1<<msg->order);

    // if (the remote peer has less elements than us)
    //    run our elements through his bloomfilter
    // else if (we have the same elements)
    //    done;
    // 
    // evict elements we can exclude through the bloomfilter
    //
    // create a new bloomfilter over our remaining elements
    // 
    // send our new count and the bloomfilter back
  }
  else if (eo->phase == PHASE_BF_EXCHANGE)
  {

  }

}


/**
 * Send a result message to the client indicating
 * that there is a new element.
 *
 * @param eo intersection operation
 * @param element element to send
 */
static void
send_client_element (struct OperationState *eo,
                     struct GNUNET_SET_Element *element)
{
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SET_ResultMessage *rm;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "sending element (size %u) to client\n", element->size);
  GNUNET_assert (0 != eo->spec->client_request_id);
  ev = GNUNET_MQ_msg_extra (rm, element->size, GNUNET_MESSAGE_TYPE_SET_RESULT);
  if (NULL == ev)
  {
    GNUNET_MQ_discard (ev);
    GNUNET_break (0);
    return;
  }
  rm->result_status = htons (GNUNET_SET_STATUS_OK);
  rm->request_id = htonl (eo->spec->client_request_id);
  rm->element_type = element->type;
  memcpy (&rm[1], element->data, element->size);
  GNUNET_MQ_send (eo->spec->set->client_mq, ev);
}


/**
 * Send a result message to the client indicating
 * that the operation is over.
 * After the result done message has been sent to the client,
 * destroy the evaluate operation.
 *
 * @param eo intersection operation
 */
static void
send_client_done_and_destroy (struct OperationState *eo)
{
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SET_ResultMessage *rm;

  GNUNET_assert (GNUNET_NO == eo->client_done_sent);

  eo->client_done_sent = GNUNET_YES;

  ev = GNUNET_MQ_msg (rm, GNUNET_MESSAGE_TYPE_SET_RESULT);
  rm->request_id = htonl (eo->spec->client_request_id);
  rm->result_status = htons (GNUNET_SET_STATUS_DONE);
  rm->element_type = htons (0);
  GNUNET_MQ_send (eo->spec->set->client_mq, ev);

  intersection_operation_destroy (eo);
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
send_bloomfilter (struct Operation *op){
  //get number of all elements still in the set
  
  // send the bloomfilter
  unsigned int buckets_sent = 0;
  struct BloomFilter *bf;
  //TODO:
  // add all our elements to the bloomfilter
  // create new bloomfilter for all our elements & count elements
  //GNUNET_CONTAINER_multihashmap32_remove
  //eo->local_bf = GNUNET_CONTAINER_multihashmap32_iterate(eo->set->elements, add);
  
  op->state->local_bf;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "sending bf of size %u\n", 1<<ibf_order);

  bf = eo->local_bf;

  while (buckets_sent < (1 << bf_order))
  {
    unsigned int buckets_in_message;
    struct GNUNET_MQ_Envelope *ev;
    struct IBFMessage *msg;

    buckets_in_message = (1 << bf_order) - buckets_sent;
    /* limit to maximum */
    if (buckets_in_message > MAX_BUCKETS_PER_MESSAGE)
      buckets_in_message = MAX_BUCKETS_PER_MESSAGE;

    ev = GNUNET_MQ_msg_extra (msg, buckets_in_message * IBF_BUCKET_SIZE,
                               GNUNET_MESSAGE_TYPE_SET_P2P_BF);
    msg->reserved = 0;
    msg->order = bf_order;
    msg->offset = htons (buckets_sent);
    ibf_write_slice (ibf, buckets_sent,
                     buckets_in_message, &msg[1]);
    buckets_sent += buckets_in_message;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ibf chunk size %u, %u/%u sent\n",
                buckets_in_message, buckets_sent, 1<<ibf_order);
    GNUNET_MQ_send (eo->mq, ev);
  }

  eo->phase = PHASE_BF_EXCHANGE;
}

/**
 * Handle a done message from a remote peer
 *
 * @param cls the intersection operation
 * @param mh the message
 */
static void
handle_p2p_done (void *cls, const struct GNUNET_MessageHeader *mh)
{
  struct OperationState *eo = cls;
  struct GNUNET_MQ_Envelope *ev;

  if (eo->phase == PHASE_EXPECT_ELEMENTS_AND_REQUESTS)
  {
    /* we got all requests, but still have to send our elements as response */

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "got DONE, sending final DONE after elements\n");
    eo->phase = PHASE_FINISHED;
    ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_SET_P2P_DONE);
    GNUNET_MQ_send (eo->mq, ev);
    return;
  }
  if (eo->phase == PHASE_EXPECT_ELEMENTS)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "got final DONE\n");
    eo->phase = PHASE_FINISHED;
    send_client_done_and_destroy (eo);
    return;
  }
  GNUNET_break (0);
  fail_intersection_operation (eo);
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
  op->state->phase = PHASE_BF_EXCHANGE;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "evaluating intersection operation");
  send_operation_request (op);
}


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
intersection_iterator_set_to_contained_alice (void *cls,
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
  
  op->state->contained_elements_count++;  
  GNUNET_CONTAINER_multihashmap_put (op->state->contained_elements, 
                                     &ee->element_hash, ee,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  
  // create our own bloomfilter with salt+1
  GNUNET_BLOCK_mingle_hash(&ee->element_hash, op->spec->salt+1, &mutated_hash);
  GNUNET_CONTAINER_bloomfilter_add (op->state->local_bf, 
                                    &mutated_hash);
  
  return GNUNET_YES;
}

/**
 * Bob's version:
 * 
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
intersection_iterator_set_to_contained_bob (void *cls,
                                      const struct GNUNET_HashCode *key,
                                      void *value){
  struct ElementEntry *ee = value;
  struct Operation *op = cls;
  struct GNUNET_HashCode mutated_hash;
  
  //only consider this element, if it is valid for us
  if ((op->generation_created >= ee->generation_removed) 
       || (op->generation_created < ee->generation_added))
    return GNUNET_YES;
  
  GNUNET_CONTAINER_multihashmap_put (op->state->contained_elements, 
                                     &ee->element_hash, ee,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  
  op->state->contained_elements_count++;
  
  GNUNET_BLOCK_mingle_hash(&ee->element_hash, op->spec->salt, &mutated_hash);
  
  GNUNET_CONTAINER_bloomfilter_add (op->state->local_bf, 
                                    &mutated_hash);
  
  return GNUNET_YES;
}

/**
 * removes element from a hashmap if it is not contained within the
 * provided remote bloomfilter.
 * 
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES if we should continue to
 *         iterate,
 *         #GNUNET_NO if not.
 */
static int
intersection_iterator_element_removal (void *cls,
                                      const struct GNUNET_HashCode *key,
                                      void *value){
  struct ElementEntry *ee = value;
  struct Operation *op = cls;
  struct GNUNET_HashCode mutated_hash;
  
  GNUNET_BLOCK_mingle_hash(&ee->element_hash, op->spec->salt, &mutated_hash);
  
  if (GNUNET_NO == GNUNET_CONTAINER_bloomfilter_test (op->state->remote_bf, 
                                     &mutated_hash)){
    op->state->contained_elements_count--;
    GNUNET_CONTAINER_multihashmap_remove (op->state->contained_elements, 
                                     &ee->element_hash,
                                     ee);
  }
  
  return GNUNET_YES;
}

/**
 * removes element from a hashmap if it is not contained within the
 * provided remote bloomfilter.
 * 
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES if we should continue to
 *         iterate,
 *         #GNUNET_NO if not.
 */
static int
intersection_iterator_create_bf (void *cls,
                                      const struct GNUNET_HashCode *key,
                                      void *value){
  struct ElementEntry *ee = value;
  struct Operation *op = cls;
  struct GNUNET_HashCode mutated_hash;
  
  GNUNET_BLOCK_mingle_hash(&ee->element_hash, op->spec->salt, &mutated_hash);
  
  GNUNET_CONTAINER_bloomfilter_add (op->state->local_bf, 
                                    &mutated_hash);
  
  return GNUNET_YES;
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
  
  op->state->contained_elements = GNUNET_CONTAINER_multihashmap_create(1, GNUNET_YES);
  
  GNUNET_CONTAINER_multihashmap_iterate(op->spec->set->elements, 
                                        &intersection_iterator_set_to_contained_bob,
                                        op);
  
  
  op->state->local_bf = GNUNET_CONTAINER_bloomfilter_init(NULL, sizeof(struct GNUNET_HashCode), GNUNET_CONSTANTS_BLOOMFILTER_K);
  
  if (NULL != op->state->remote_bf){
    // run the set through the remote bloomfilter
    ;
  }
  
  // 
  op->state->local_bf;
  
  /* kick off the operation */
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
intersection_handle_p2p_message (struct OperationState *eo,
                          const struct GNUNET_MessageHeader *mh)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "received p2p message (t: %u, s: %u)\n",
              ntohs (mh->type), ntohs (mh->size));
  switch (ntohs (mh->type))
  {
    /* this message handler is not active until after we received an
     * operation request message, thus the ops request is not handled here
     */
    case GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_BF:
      handle_p2p_bf (eo, mh);
      break;
    case GNUNET_MESSAGE_TYPE_SET_P2P_DONE:
      handle_p2p_done (eo, mh);
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
send_done_and_destroy (void *cls)
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
 * Send a result message to the client indicating
 * that the operation is over.
 * After the result done message has been sent to the client,
 * destroy the evaluate operation.
 *
 * @param op union operation
 */
static void
finish_and_destroy (struct Operation *op)
{
  GNUNET_assert (GNUNET_NO == op->state->client_done_sent);

  if (GNUNET_SET_RESULT_FULL == op->spec->result_mode)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "sending full result set\n");
    GNUNET_assert (NULL == op->state->full_result_iter); 
    op->state->full_result_iter =
        GNUNET_CONTAINER_multihashmap32_iterator_create (op->state->contained_elements);
    return;
  }
  send_done_and_destroy (op);
}


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
  if (NULL != op->state->contained_elements)
  {
    // no need to free the elements, they are still part of the set
    GNUNET_CONTAINER_multihashmap_destroy (op->state->contained_elements);
    op->state->contained_elements = NULL;
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
