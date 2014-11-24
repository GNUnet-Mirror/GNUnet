/*
      This file is part of GNUnet
      (C) 2013, 2014 Christian Grothoff (and other contributing authors)

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
#include "gnunet_block_lib.h"
#include "set_protocol.h"
#include <gcrypt.h>

#define BLOOMFILTER_SIZE GNUNET_CRYPTO_HASH_LENGTH

#define CALCULATE_BF_SIZE(A, B, s, k) \
                          do { \
                            k = ceil(1 + log2((double) (2*B / (double) A)));\
                            if (k<1) k=1; /* k can be calculated as 0 */\
                            s = ceil((double) (A * k / log(2))); \
                          } while (0)

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
   * Iterator for sending elements on the key to element mapping to the client.
   */
  struct GNUNET_CONTAINER_MultiHashMapIterator *full_result_iter;

  /**
   * Evaluate operations are held in a linked list.
   */
  struct OperationState *next;

  /**
   * Evaluate operations are held in a linked list.
   */
  struct OperationState *prev;

  /**
   * for multipart msgs we have to store the bloomfilter-data until we fully sent it.
   */
  char *bf_data;

  /**
   * Maps element-id-hashes to 'elements in our set'.
   */
  struct GNUNET_CONTAINER_MultiHashMap *my_elements;

  /**
   * Current element count contained within @e my_elements
   */
  uint32_t my_element_count;

  /**
   * size of the bloomfilter in @e bf_data.
   */
  uint32_t bf_data_size;

  /**
   * size of the bloomfilter
   */
  uint32_t bf_bits_per_element;

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
   * Number of currently valid elements in the set which have not been removed
   */
  uint32_t current_set_element_count;
};


/**
 * Send a result message to the client indicating
 * we removed an element
 *
 * @param op union operation
 * @param element element to send
 */
static void
send_client_element (struct Operation *op,
                     struct GNUNET_SET_Element *element)
{
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SET_ResultMessage *rm;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "sending removed element (size %u) to client\n",
              element->size);
  GNUNET_assert (0 != op->spec->client_request_id);
  ev = GNUNET_MQ_msg_extra (rm, element->size, GNUNET_MESSAGE_TYPE_SET_RESULT);
  if (NULL == ev)
  {
    GNUNET_MQ_discard (ev);
    GNUNET_break (0);
    return;
  }
  rm->result_status = htons (GNUNET_SET_STATUS_OK);
  rm->request_id = htonl (op->spec->client_request_id);
  rm->element_type = element->type;
  memcpy (&rm[1], element->data, element->size);
  GNUNET_MQ_send (op->spec->set->client_mq, ev);
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
iterator_initialization_by_alice (void *cls,
                                  const struct GNUNET_HashCode *key,
                                  void *value)
{
  struct ElementEntry *ee = value;
  struct Operation *op = cls;
  struct GNUNET_HashCode mutated_hash;

  //only consider this element, if it is valid for us
  if ((op->generation_created < ee->generation_removed)
       && (op->generation_created >= ee->generation_added))
    return GNUNET_YES;

  // not contained according to bob's bloomfilter
  GNUNET_BLOCK_mingle_hash(&ee->element_hash,
                           op->spec->salt,
                           &mutated_hash);
  if (GNUNET_NO == GNUNET_CONTAINER_bloomfilter_test (op->state->remote_bf,
                                                      &mutated_hash)){
    if (GNUNET_SET_RESULT_REMOVED == op->spec->result_mode)
      send_client_element (op, &ee->element);
    return GNUNET_YES;
  }

  op->state->my_element_count++;
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_put (op->state->my_elements,
                                                    &ee->element_hash, ee,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));

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
                         void *value)
{
  struct ElementEntry *ee = value;
  struct Operation *op = cls;

  //only consider this element, if it is valid for us
  if ((op->generation_created < ee->generation_removed)
       && (op->generation_created >= ee->generation_added))
    return GNUNET_YES;

  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_put (op->state->my_elements,
                                                    &ee->element_hash, ee,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
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
iterator_bf_reduce (void *cls,
                   const struct GNUNET_HashCode *key,
                   void *value)
{
  struct ElementEntry *ee = value;
  struct Operation *op = cls;
  struct GNUNET_HashCode mutated_hash;

  GNUNET_BLOCK_mingle_hash(&ee->element_hash, op->spec->salt, &mutated_hash);

  if (GNUNET_NO ==
      GNUNET_CONTAINER_bloomfilter_test (op->state->remote_bf,
                                         &mutated_hash))
  {
    op->state->my_element_count--;
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multihashmap_remove (op->state->my_elements,
                                                         &ee->element_hash,
                                                         ee));
    if (GNUNET_SET_RESULT_REMOVED == op->spec->result_mode)
      send_client_element (op, &ee->element);
  }

  return GNUNET_YES;
}


/**
 * Create a bloomfilter based on the elements given
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES if we should continue to
 *         iterate,
 *         #GNUNET_NO if not.
 */
static int
iterator_bf_create (void *cls,
                    const struct GNUNET_HashCode *key,
                    void *value)
{
  struct ElementEntry *ee = value;
  struct Operation *op = cls;
  struct GNUNET_HashCode mutated_hash;

  GNUNET_BLOCK_mingle_hash (&ee->element_hash,
                            op->spec->salt,
                            &mutated_hash);
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
  {
    GNUNET_CONTAINER_multihashmap_destroy(op->state->my_elements);
    op->state->my_elements = NULL;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "intersection operation failed\n");

  ev = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_SET_RESULT);
  msg->result_status = htons (GNUNET_SET_STATUS_FAILURE);
  msg->request_id = htonl (op->spec->client_request_id);
  msg->element_type = htons (0);
  GNUNET_MQ_send (op->spec->set->client_mq, ev);
  _GSS_operation_destroy (op, GNUNET_YES);
}


/**
 * Send a request for the evaluate operation to a remote peer
 *
 * @param op operation with the other peer
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
  msg->element_count = htonl(op->state->my_element_count);

  GNUNET_MQ_send (op->mq, ev);

  if (NULL != op->spec->context_msg)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "sent op request with context message\n");
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "sent op request without context message\n");

  if (NULL != op->spec->context_msg)
  {
    GNUNET_free (op->spec->context_msg);
    op->spec->context_msg = NULL;
  }
}


static void
send_bloomfilter_multipart (struct Operation *op,
                            uint32_t offset)
{
  struct GNUNET_MQ_Envelope *ev;
  struct BFPart *msg;
  uint32_t chunk_size = (GNUNET_SERVER_MAX_MESSAGE_SIZE - sizeof(struct BFPart));
  uint32_t todo_size = op->state->bf_data_size - offset;

  if (todo_size < chunk_size)
    chunk_size = todo_size;

  ev = GNUNET_MQ_msg_extra (msg,
                            chunk_size,
                            GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_BF_PART);

  msg->chunk_length = htonl (chunk_size);
  msg->chunk_offset = htonl (offset);
  memcpy(&msg[1], &op->state->bf_data[offset], chunk_size);

  GNUNET_MQ_send (op->mq, ev);

  if (op->state->bf_data_size == offset + chunk_size)
  {
    // done
    GNUNET_free(op->state->bf_data);
    op->state->bf_data = NULL;
    return;
  }
  send_bloomfilter_multipart (op, offset + chunk_size);
}


/**
 * Send a bloomfilter to our peer.
 * that the operation is over.
 * After the result done message has been sent to the client,
 * destroy the evaluate operation.
 *
 * @param op intersection operation
 */
static void
send_bloomfilter (struct Operation *op)
{
  struct GNUNET_MQ_Envelope *ev;
  struct BFMessage *msg;
  uint32_t bf_size;
  uint32_t bf_elementbits;
  uint32_t chunk_size;
  struct GNUNET_CONTAINER_BloomFilter * local_bf;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "sending bf of size %u\n");

  CALCULATE_BF_SIZE(op->state->my_element_count,
                    op->spec->remote_element_count,
                    bf_size,
                    bf_elementbits);

  local_bf = GNUNET_CONTAINER_bloomfilter_init (NULL,
                                                bf_size,
                                                bf_elementbits);

  op->spec->salt++;
  GNUNET_CONTAINER_multihashmap_iterate (op->state->my_elements,
                                         &iterator_bf_create,
                                         op);

  // send our bloomfilter
  if (GNUNET_SERVER_MAX_MESSAGE_SIZE > bf_size + sizeof (struct BFMessage))
  {
    // singlepart
    chunk_size = bf_size;
    ev = GNUNET_MQ_msg_extra (msg, chunk_size, GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_BF);
    GNUNET_assert (GNUNET_SYSERR !=
                   GNUNET_CONTAINER_bloomfilter_get_raw_data (local_bf,
                                                              (char*)&msg[1],
                                                              bf_size));
  }
  else
  {
    //multipart
    chunk_size = GNUNET_SERVER_MAX_MESSAGE_SIZE - 1 - sizeof (struct BFMessage);
    ev = GNUNET_MQ_msg_extra (msg, chunk_size, GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_BF);
    op->state->bf_data = (char *) GNUNET_malloc (bf_size);
    GNUNET_assert (GNUNET_SYSERR !=
                   GNUNET_CONTAINER_bloomfilter_get_raw_data (local_bf,
                                                              op->state->bf_data,
                                                              bf_size));
    memcpy (&msg[1], op->state->bf_data, chunk_size);
    op->state->bf_data_size = bf_size;
  }
  GNUNET_CONTAINER_bloomfilter_free (local_bf);

  msg->sender_element_count = htonl (op->state->my_element_count);
  msg->bloomfilter_total_length = htonl (bf_size);
  msg->bloomfilter_length = htonl (chunk_size);
  msg->bits_per_element = htonl (bf_elementbits);
  msg->sender_mutator = htonl (op->spec->salt);

  GNUNET_MQ_send (op->mq, ev);

  if (op->state->bf_data)
    send_bloomfilter_multipart (op, chunk_size);
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
  _GSS_operation_destroy (op, GNUNET_YES);
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

  res = GNUNET_CONTAINER_multihashmap_iterator_next (op->state->full_result_iter,
                                                     NULL,
                                                     (const void **) &remaining);
  if (GNUNET_NO == res)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "sending done and destroy because iterator ran out\n");
    send_client_done_and_destroy (op);
    return;
  }

  element = &remaining->element;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "sending element (size %u) to client (full set)\n",
              element->size);
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
 * Inform the peer that this operation is complete.
 *
 * @param op the intersection operation to fail
 */
static void
send_peer_done (struct Operation *op)
{
  struct GNUNET_MQ_Envelope *ev;

  op->state->phase = PHASE_FINISHED;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Intersection succeeded, sending DONE\n");
  GNUNET_CONTAINER_bloomfilter_free (op->state->local_bf);
  op->state->local_bf = NULL;

  ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_SET_P2P_DONE);
  GNUNET_MQ_send (op->mq, ev);
}


/**
 * Process a Bloomfilter once we got all the chunks
 *
 * @param op the intersection operation
 */
static void
process_bf (struct Operation *op)
{
  uint32_t old_elements;
  uint32_t peer_elements;

  old_elements = op->state->my_element_count;
  peer_elements = op->spec->remote_element_count;
  switch (op->state->phase)
  {
  case PHASE_INITIAL:
    // If we are ot our first msg
    op->state->my_elements = GNUNET_CONTAINER_multihashmap_create (op->state->my_element_count, GNUNET_YES);

    GNUNET_CONTAINER_multihashmap_iterate (op->spec->set->elements,
                                           &iterator_initialization_by_alice,
                                           op);
    break;
  case PHASE_BF_EXCHANGE:
  case PHASE_MAYBE_FINISHED:
    // if we are bob or alice and are continuing operation
    GNUNET_CONTAINER_multihashmap_iterate (op->state->my_elements,
                                           &iterator_bf_reduce,
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

  if ((0 == op->state->my_element_count) // fully disjoint
      || ((op->state->phase == PHASE_MAYBE_FINISHED) // we agree on a shared set of elements
          && (old_elements == op->state->my_element_count)
          && (op->state->my_element_count == peer_elements)))
  {
    // In the last round we though we were finished, we now know this is correct
    send_peer_done (op);
    return;
  }

  op->state->phase = PHASE_BF_EXCHANGE;
  if (op->state->my_element_count == peer_elements)
    // maybe we are finished, but we do one more round to make certain
    // we don't have false positives ...
    op->state->phase = PHASE_MAYBE_FINISHED;

  send_bloomfilter (op);
}


/**
 * Handle an BF multipart message from a remote peer.
 *
 * @param cls the intersection operation
 * @param mh the header of the message
 */
static void
handle_p2p_bf_part (void *cls, const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;
  const struct BFPart *msg = (const struct BFPart *) mh;
  uint32_t chunk_size;
  uint32_t chunk_offset;

  chunk_size = ntohl(msg->chunk_length);
  chunk_offset = ntohl(msg->chunk_offset);

  if ((NULL == op->state->bf_data)
       || (op->state->bf_data_size < chunk_size + chunk_offset))
  {
    // unexpected multipart chunk
    GNUNET_break_op (0);
    fail_intersection_operation(op);
    return;
  }

  memcpy (&op->state->bf_data[chunk_offset], (const char*) &msg[1], chunk_size);

  if (op->state->bf_data_size != chunk_offset + chunk_size)
    // wait for next chunk
    return;

  op->state->remote_bf = GNUNET_CONTAINER_bloomfilter_init ((const char*) &msg[1],
                                                            op->state->bf_data_size,
                                                            op->state->bf_bits_per_element);

  GNUNET_free (op->state->bf_data);
  op->state->bf_data = NULL;

  process_bf (op);
}


/**
 * Handle an BF message from a remote peer.
 *
 * @param cls the intersection operation
 * @param mh the header of the message
 */
static void
handle_p2p_bf (void *cls,
               const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;
  const struct BFMessage *msg = (const struct BFMessage *) mh;
  uint32_t bf_size;
  uint32_t chunk_size;
  uint32_t bf_bits_per_element;

  switch (op->state->phase)
  {
  case PHASE_INITIAL:
  case PHASE_BF_EXCHANGE:
  case PHASE_MAYBE_FINISHED:
    if (NULL == op->state->bf_data)
    {
      // no colliding multipart transaction going on currently
      op->spec->salt = ntohl (msg->sender_mutator);
      bf_size = ntohl (msg->bloomfilter_total_length);
      bf_bits_per_element = ntohl (msg->bits_per_element);
      chunk_size = ntohl (msg->bloomfilter_length);
      op->spec->remote_element_count = ntohl(msg->sender_element_count);
      if (bf_size == chunk_size)
      {
        // single part, done here
        op->state->remote_bf = GNUNET_CONTAINER_bloomfilter_init ((const char*) &msg[1],
                                                                  bf_size,
                                                                  bf_bits_per_element);
        process_bf (op);
        return;
      }

      //first multipart chunk
      op->state->bf_data = GNUNET_malloc (bf_size);
      op->state->bf_data_size = bf_size;
      op->state->bf_bits_per_element = bf_bits_per_element;
      memcpy (op->state->bf_data, (const char*) &msg[1], chunk_size);
      return;
    }
  default:
    GNUNET_break_op (0);
    fail_intersection_operation (op);
  }
}


/**
 * Handle an BF message from a remote peer.
 *
 * @param cls the intersection operation
 * @param mh the header of the message
 */
static void
handle_p2p_element_info (void *cls,
                         const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;
  const struct BFMessage *msg = (const struct BFMessage *) mh;

  op->spec->remote_element_count = ntohl(msg->sender_element_count);
  if ((op->state->phase != PHASE_INITIAL)
      || (op->state->my_element_count > op->spec->remote_element_count)
          || (0 == op->state->my_element_count)
              || (0 == op->spec->remote_element_count))
  {
    GNUNET_break_op (0);
    fail_intersection_operation(op);
    return;
  }

  op->state->phase = PHASE_BF_EXCHANGE;
  op->state->my_elements = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);

  GNUNET_CONTAINER_multihashmap_iterate (op->spec->set->elements,
                                         &iterator_initialization,
                                         op);

  GNUNET_CONTAINER_bloomfilter_free (op->state->remote_bf);
  op->state->remote_bf = NULL;

  if (op->state->my_element_count == ntohl (msg->sender_element_count))
    op->state->phase = PHASE_MAYBE_FINISHED;

  send_bloomfilter (op);
}


/**
 * Send our element count to the peer, in case our element count is lower than his
 *
 * @param op intersection operation
 */
static void
send_element_count (struct Operation *op)
{
  struct GNUNET_MQ_Envelope *ev;
  struct BFMessage *msg;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "sending element count (bf_msg)\n");

  // just send our element count, as the other peer must start
  ev = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_ELEMENT_INFO);
  msg->sender_element_count = htonl (op->state->my_element_count);
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
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "sending full result set\n");
    op->state->full_result_iter =
        GNUNET_CONTAINER_multihashmap_iterator_create (op->state->my_elements);
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
handle_p2p_done (void *cls,
                 const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;

  if ( (op->state->phase = PHASE_FINISHED) ||
       (op->state->phase = PHASE_MAYBE_FINISHED) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "got final DONE\n");

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
  op->state->my_element_count = op->spec->set->state->current_set_element_count;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "evaluating intersection operation");
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "accepting set union operation\n");
  op->state = GNUNET_new (struct OperationState);
  op->state->my_elements = GNUNET_CONTAINER_multihashmap_create(1, GNUNET_YES);
  op->state->my_element_count = op->spec->set->state->current_set_element_count;

  // if Alice (the peer) has more elements than Bob (us), she should start
  if (op->spec->remote_element_count < op->state->my_element_count){
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
intersection_set_create ()
{
  struct SetState *set_state;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "intersection set created\n");
  set_state = GNUNET_new (struct SetState);
  set_state->current_set_element_count = 0;

  return set_state;
}


/**
 * Add the element from the given element message to the set.
 *
 * @param set_state state of the set want to add to
 * @param ee the element to add to the set
 */
static void
intersection_add (struct SetState *set_state,
                  struct ElementEntry *ee)
{
  set_state->current_set_element_count++;
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
intersection_remove (struct SetState *set_state,
                     struct ElementEntry *element)
{
  GNUNET_assert(0 < set_state->current_set_element_count);
  set_state->current_set_element_count--;
}


/**
 * Dispatch messages for a intersection operation.
 *
 * @param op the state of the intersection evaluate operation
 * @param mh the received message
 * @return #GNUNET_SYSERR if the tunnel should be disconnected,
 *         #GNUNET_OK otherwise
 */
static int
intersection_handle_p2p_message (struct Operation *op,
                                 const struct GNUNET_MessageHeader *mh)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "received p2p message (t: %u, s: %u)\n",
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
  case GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_BF_PART:
    handle_p2p_bf_part (op, mh);
    break;
  case GNUNET_MESSAGE_TYPE_SET_P2P_DONE:
    handle_p2p_done (op, mh);
    break;
  default:
    /* something wrong with cadet's message handlers? */
    GNUNET_assert (0);
  }
  return GNUNET_OK;
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
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "other peer disconnected prematurely\n");
    _GSS_operation_destroy (op, GNUNET_YES);
    return;
  }
  // else: the session has already been concluded
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "other peer disconnected (finished)\n");
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "destroying intersection op\n");
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
/*  if (NULL != op->state->my_elements)
  {
    // no need to free the elements, they are still part of the set
    GNUNET_CONTAINER_multihashmap_destroy (op->state->my_elements);
    op->state->my_elements = NULL;
  }*/
  GNUNET_free (op->state);
  op->state = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "destroying intersection op done\n");
}


/**
 * Get the table with implementing functions for set intersection.
 *
 * @return the operation specific VTable
 */
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
