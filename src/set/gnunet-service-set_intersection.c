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
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet-service-set.h"
#include "gnunet_block_lib.h"
#include "gnunet-service-set_protocol.h"
#include <gcrypt.h>


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
   * until one notices the their element hashes are equal.
   */
  PHASE_BF_EXCHANGE,

  /**
   * The protocol is over.  Results may still have to be sent to the
   * client.
   */
  PHASE_FINISHED
};


/**
 * State of an evaluate operation with another peer.
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
   * Remaining elements in the intersection operation.
   * Maps element-id-hashes to 'elements in our set'.
   */
  struct GNUNET_CONTAINER_MultiHashMap *my_elements;

  /**
   * Iterator for sending the final set of @e my_elements to the client.
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
   * For multipart BF transmissions, we have to store the
   * bloomfilter-data until we fully received it.
   */
  char *bf_data;

  /**
   * XOR of the keys of all of the elements (remaining) in my set.
   * Always updated when elements are added or removed to
   * @e my_elements.
   */
  struct GNUNET_HashCode my_xor;

  /**
   * XOR of the keys of all of the elements (remaining) in
   * the other peer's set.  Updated when we receive the
   * other peer's Bloom filter.
   */
  struct GNUNET_HashCode other_xor;

  /**
   * How many bytes of @e bf_data are valid?
   */
  uint32_t bf_data_offset;

  /**
   * Current element count contained within @e my_elements.
   * (May differ briefly during initialization.)
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
   * Salt currently used for BF construction (by us or the other peer,
   * depending on where we are in the code).
   */
  uint32_t salt;

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
 * Merely tracks the total number of elements.
 */
struct SetState
{
  /**
   * Number of currently valid elements in the set which have not been
   * removed.
   */
  uint32_t current_set_element_count;
};


/**
 * If applicable in the current operation mode, send a result message
 * to the client indicating we removed an element.
 *
 * @param op intersection operation
 * @param element element to send
 */
static void
send_client_removed_element (struct Operation *op,
                             struct GNUNET_SET_Element *element)
{
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SET_ResultMessage *rm;

  if (GNUNET_SET_RESULT_REMOVED != op->spec->result_mode)
    return; /* Wrong mode for transmitting removed elements */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending removed element (size %u) to client\n",
              element->size);
  GNUNET_assert (0 != op->spec->client_request_id);
  ev = GNUNET_MQ_msg_extra (rm,
                            element->size,
                            GNUNET_MESSAGE_TYPE_SET_RESULT);
  if (NULL == ev)
  {
    GNUNET_break (0);
    return;
  }
  rm->result_status = htons (GNUNET_SET_STATUS_OK);
  rm->request_id = htonl (op->spec->client_request_id);
  rm->element_type = element->element_type;
  memcpy (&rm[1],
          element->data,
          element->size);
  GNUNET_MQ_send (op->spec->set->client_mq,
                  ev);
}


/**
 * Fills the "my_elements" hashmap with all relevant elements.
 *
 * @param cls the `struct Operation *` we are performing
 * @param key current key code
 * @param value the `struct ElementEntry *` from the hash map
 * @return #GNUNET_YES (we should continue to iterate)
 */
static int
filtered_map_initialization (void *cls,
                             const struct GNUNET_HashCode *key,
                             void *value)
{
  struct Operation *op = cls;
  struct ElementEntry *ee = value;
  struct GNUNET_HashCode mutated_hash;

  if ( (op->generation_created < ee->generation_removed) &&
       (op->generation_created >= ee->generation_added) )
    return GNUNET_YES; /* element not valid in our operation's generation */

  /* Test if element is in Bob's bloomfilter */
  GNUNET_BLOCK_mingle_hash (&ee->element_hash,
                            op->state->salt,
                            &mutated_hash);
  if (GNUNET_NO ==
      GNUNET_CONTAINER_bloomfilter_test (op->state->remote_bf,
                                         &mutated_hash))
  {
    /* remove this element */
    send_client_removed_element (op,
                                 &ee->element);
    return GNUNET_YES;
  }
  op->state->my_element_count++;
  GNUNET_CRYPTO_hash_xor (&op->state->my_xor,
                          &ee->element_hash,
                          &op->state->my_xor);
  GNUNET_break (GNUNET_YES ==
                GNUNET_CONTAINER_multihashmap_put (op->state->my_elements,
                                                   &ee->element_hash,
                                                   ee,
                                                   GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));

  return GNUNET_YES;
}


/**
 * Removes elements from our hashmap if they are not contained within the
 * provided remote bloomfilter.
 *
 * @param cls closure with the `struct Operation *`
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES (we should continue to iterate)
 */
static int
iterator_bf_reduce (void *cls,
                   const struct GNUNET_HashCode *key,
                   void *value)
{
  struct Operation *op = cls;
  struct ElementEntry *ee = value;
  struct GNUNET_HashCode mutated_hash;

  GNUNET_BLOCK_mingle_hash (&ee->element_hash,
                            op->state->salt,
                            &mutated_hash);
  if (GNUNET_NO ==
      GNUNET_CONTAINER_bloomfilter_test (op->state->remote_bf,
                                         &mutated_hash))
  {
    GNUNET_break (0 < op->state->my_element_count);
    op->state->my_element_count--;
    GNUNET_CRYPTO_hash_xor (&op->state->my_xor,
                            &ee->element_hash,
                            &op->state->my_xor);
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multihashmap_remove (op->state->my_elements,
                                                         &ee->element_hash,
                                                         ee));
    send_client_removed_element (op,
                                 &ee->element);
  }
  return GNUNET_YES;
}


/**
 * Create initial bloomfilter based on all the elements given.
 *
 * @param cls the `struct Operation *`
 * @param key current key code
 * @param value the `struct ElementEntry` to process
 * @return #GNUNET_YES (we should continue to iterate)
 */
static int
iterator_bf_create (void *cls,
                    const struct GNUNET_HashCode *key,
                    void *value)
{
  struct Operation *op = cls;
  struct ElementEntry *ee = value;
  struct GNUNET_HashCode mutated_hash;

  GNUNET_BLOCK_mingle_hash (&ee->element_hash,
                            op->state->salt,
                            &mutated_hash);
  GNUNET_CONTAINER_bloomfilter_add (op->state->local_bf,
                                    &mutated_hash);
  return GNUNET_YES;
}


/**
 * Inform the client that the intersection operation has failed,
 * and proceed to destroy the evaluate operation.
 *
 * @param op the intersection operation to fail
 */
static void
fail_intersection_operation (struct Operation *op)
{
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SET_ResultMessage *msg;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Intersection operation failed\n");
  if (NULL != op->state->my_elements)
  {
    GNUNET_CONTAINER_multihashmap_destroy (op->state->my_elements);
    op->state->my_elements = NULL;
  }
  ev = GNUNET_MQ_msg (msg,
                      GNUNET_MESSAGE_TYPE_SET_RESULT);
  msg->result_status = htons (GNUNET_SET_STATUS_FAILURE);
  msg->request_id = htonl (op->spec->client_request_id);
  msg->element_type = htons (0);
  GNUNET_MQ_send (op->spec->set->client_mq,
                  ev);
  _GSS_operation_destroy (op,
                          GNUNET_YES);
}


/**
 * Send a bloomfilter to our peer.  After the result done message has
 * been sent to the client, destroy the evaluate operation.
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
  struct GNUNET_CONTAINER_BloomFilter *local_bf;
  char *bf_data;
  uint32_t offset;

  /* We consider the ratio of the set sizes to determine
     the number of bits per element, as the smaller set
     should use more bits to maximize its set reduction
     potential and minimize overall bandwidth consumption. */
  bf_elementbits = 2 + ceil (log2((double)
                             (op->spec->remote_element_count /
                                   (double) op->state->my_element_count)));
  if (bf_elementbits < 1)
    bf_elementbits = 1; /* make sure k is not 0 */
  /* optimize BF-size to ~50% of bits set */
  bf_size = ceil ((double) (op->state->my_element_count
                            * bf_elementbits / log(2)));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending bf of size %u\n",
              (unsigned int) bf_size);
  local_bf = GNUNET_CONTAINER_bloomfilter_init (NULL,
                                                bf_size,
                                                bf_elementbits);
  op->state->salt = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
                                              UINT32_MAX);
  GNUNET_CONTAINER_multihashmap_iterate (op->state->my_elements,
                                         &iterator_bf_create,
                                         op);

  /* send our Bloom filter */
  chunk_size = 60 * 1024 - sizeof (struct BFMessage);
  if (bf_size <= chunk_size)
  {
    /* singlepart */
    chunk_size = bf_size;
    ev = GNUNET_MQ_msg_extra (msg,
                              chunk_size,
                              GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_BF);
    GNUNET_assert (GNUNET_SYSERR !=
                   GNUNET_CONTAINER_bloomfilter_get_raw_data (local_bf,
                                                              (char*) &msg[1],
                                                              bf_size));
    msg->sender_element_count = htonl (op->state->my_element_count);
    msg->bloomfilter_total_length = htonl (bf_size);
    msg->bits_per_element = htonl (bf_elementbits);
    msg->sender_mutator = htonl (op->state->salt);
    msg->element_xor_hash = op->state->my_xor;
    GNUNET_MQ_send (op->mq, ev);
  }
  else
  {
    /* multipart */
    bf_data = GNUNET_malloc (bf_size);
    GNUNET_assert (GNUNET_SYSERR !=
                   GNUNET_CONTAINER_bloomfilter_get_raw_data (local_bf,
                                                              bf_data,
                                                              bf_size));
    offset = 0;
    while (offset < bf_size)
    {
      if (bf_size - chunk_size < offset)
        chunk_size = bf_size - offset;
      ev = GNUNET_MQ_msg_extra (msg,
                                chunk_size,
                                GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_BF);
      memcpy (&msg[1],
              &bf_data[offset],
              chunk_size);
      offset += chunk_size;
      msg->sender_element_count = htonl (op->state->my_element_count);
      msg->bloomfilter_total_length = htonl (bf_size);
      msg->bits_per_element = htonl (bf_elementbits);
      msg->sender_mutator = htonl (op->state->salt);
      msg->element_xor_hash = op->state->my_xor;
      GNUNET_MQ_send (op->mq, ev);
    }
    GNUNET_free (bf_data);
  }
  GNUNET_CONTAINER_bloomfilter_free (local_bf);
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

  ev = GNUNET_MQ_msg (rm,
                      GNUNET_MESSAGE_TYPE_SET_RESULT);
  rm->request_id = htonl (op->spec->client_request_id);
  rm->result_status = htons (GNUNET_SET_STATUS_DONE);
  rm->element_type = htons (0);
  GNUNET_MQ_send (op->spec->set->client_mq,
                  ev);
  _GSS_operation_destroy (op,
                          GNUNET_YES);
}


/**
 * Send all elements in the full result iterator.
 *
 * @param cls the `struct Operation *`
 */
static void
send_remaining_elements (void *cls)
{
  struct Operation *op = cls;
  const void *nxt;
  const struct ElementEntry *ee;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SET_ResultMessage *rm;
  const struct GNUNET_SET_Element *element;
  int res;

  res = GNUNET_CONTAINER_multihashmap_iterator_next (op->state->full_result_iter,
                                                     NULL,
                                                     &nxt);
  if (GNUNET_NO == res)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending done and destroy because iterator ran out\n");
    send_client_done_and_destroy (op);
    return;
  }
  ee = nxt;
  element = &ee->element;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending element (size %u) to client (full set)\n",
              element->size);
  GNUNET_assert (0 != op->spec->client_request_id);
  ev = GNUNET_MQ_msg_extra (rm,
                            element->size,
                            GNUNET_MESSAGE_TYPE_SET_RESULT);
  GNUNET_assert (NULL != ev);
  rm->result_status = htons (GNUNET_SET_STATUS_OK);
  rm->request_id = htonl (op->spec->client_request_id);
  rm->element_type = element->element_type;
  memcpy (&rm[1],
          element->data,
          element->size);
  GNUNET_MQ_notify_sent (ev,
                         &send_remaining_elements,
                         op);
  GNUNET_MQ_send (op->spec->set->client_mq,
                  ev);
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
  struct IntersectionDoneMessage *idm;

  op->state->phase = PHASE_FINISHED;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Intersection succeeded, sending DONE\n");
  GNUNET_CONTAINER_bloomfilter_free (op->state->local_bf);
  op->state->local_bf = NULL;

  ev = GNUNET_MQ_msg (idm,
                      GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_DONE);
  idm->final_element_count = htonl (op->state->my_element_count);
  idm->element_xor_hash = op->state->my_xor;
  GNUNET_MQ_send (op->mq,
                  ev);
}


/**
 * Process a Bloomfilter once we got all the chunks.
 *
 * @param op the intersection operation
 */
static void
process_bf (struct Operation *op)
{
  switch (op->state->phase)
  {
  case PHASE_INITIAL:
    /* This is the first BF being sent, build our initial map with
       filtering in place */
    op->state->my_elements
      = GNUNET_CONTAINER_multihashmap_create (op->spec->remote_element_count,
                                              GNUNET_YES);
    GNUNET_break (0 == op->state->my_element_count);
    GNUNET_CONTAINER_multihashmap_iterate (op->spec->set->elements,
                                           &filtered_map_initialization,
                                           op);
    break;
  case PHASE_BF_EXCHANGE:
    /* Update our set by reduction */
    GNUNET_CONTAINER_multihashmap_iterate (op->state->my_elements,
                                           &iterator_bf_reduce,
                                           op);
    break;
  case PHASE_FINISHED:
    GNUNET_break_op (0);
    fail_intersection_operation(op);
    return;
  }
  GNUNET_CONTAINER_bloomfilter_free (op->state->remote_bf);
  op->state->remote_bf = NULL;

  if ( (0 == op->state->my_element_count) || /* fully disjoint */
       ( (op->state->my_element_count == op->spec->remote_element_count) &&
         (0 == memcmp (&op->state->my_xor,
                       &op->state->other_xor,
                       sizeof (struct GNUNET_HashCode))) ) )
  {
    /* we are done */
    send_peer_done (op);
    return;
  }
  op->state->phase = PHASE_BF_EXCHANGE;
  send_bloomfilter (op);
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
  const struct BFMessage *msg;
  uint32_t bf_size;
  uint32_t chunk_size;
  uint32_t bf_bits_per_element;
  uint16_t msize;

  msize = htons (mh->size);
  if (msize < sizeof (struct BFMessage))
  {
    GNUNET_break_op (0);
    fail_intersection_operation (op);
    return;
  }
  msg = (const struct BFMessage *) mh;
  switch (op->state->phase)
  {
  case PHASE_INITIAL:
    GNUNET_break_op (0);
    fail_intersection_operation (op);
    break;
  case PHASE_BF_EXCHANGE:
    bf_size = ntohl (msg->bloomfilter_total_length);
    bf_bits_per_element = ntohl (msg->bits_per_element);
    chunk_size = msize - sizeof (struct BFMessage);
    op->state->other_xor = msg->element_xor_hash;
    if (bf_size == chunk_size)
    {
      if (NULL != op->state->bf_data)
      {
        GNUNET_break_op (0);
        fail_intersection_operation (op);
        return;
      }
      /* single part, done here immediately */
      op->state->remote_bf
        = GNUNET_CONTAINER_bloomfilter_init ((const char*) &msg[1],
                                             bf_size,
                                             bf_bits_per_element);
      op->state->salt = ntohl (msg->sender_mutator);
      process_bf (op);
      return;
    }
    /* multipart chunk */
    if (NULL == op->state->bf_data)
    {
      /* first chunk, initialize */
      op->state->bf_data = GNUNET_malloc (bf_size);
      op->state->bf_data_size = bf_size;
      op->state->bf_bits_per_element = bf_bits_per_element;
      op->state->bf_data_offset = 0;
      op->state->salt = ntohl (msg->sender_mutator);
      op->spec->remote_element_count = ntohl (msg->sender_element_count);
    }
    else
    {
      /* increment */
      if ( (op->state->bf_data_size != bf_size) ||
           (op->state->bf_bits_per_element != bf_bits_per_element) ||
           (op->state->bf_data_offset + chunk_size > bf_size) ||
           (op->state->salt != ntohl (msg->sender_mutator)) ||
           (op->spec->remote_element_count != ntohl (msg->sender_element_count)) )
      {
        GNUNET_break_op (0);
        fail_intersection_operation (op);
        return;
      }
    }
    memcpy (&op->state->bf_data[op->state->bf_data_offset],
            (const char*) &msg[1],
            chunk_size);
    op->state->bf_data_offset += chunk_size;
    if (op->state->bf_data_offset == bf_size)
    {
      /* last chunk, run! */
      op->state->remote_bf
        = GNUNET_CONTAINER_bloomfilter_init (op->state->bf_data,
                                             bf_size,
                                             bf_bits_per_element);
      GNUNET_free (op->state->bf_data);
      op->state->bf_data = NULL;
      op->state->bf_data_size = 0;
      process_bf (op);
    }
    break;
  default:
    GNUNET_break_op (0);
    fail_intersection_operation (op);
    break;
  }
}


/**
 * Fills the "my_elements" hashmap with the initial set of
 * (non-deleted) elements from the set of the specification.
 *
 * @param cls closure with the `struct Operation *`
 * @param key current key code for the element
 * @param value value in the hash map with the `struct ElementEntry *`
 * @return #GNUNET_YES (we should continue to iterate)
 */
static int
initialize_map_unfiltered (void *cls,
                           const struct GNUNET_HashCode *key,
                           void *value)
{
  struct ElementEntry *ee = value;
  struct Operation *op = cls;

  if ( (op->generation_created < ee->generation_removed) &&
       (op->generation_created >= ee->generation_added) )
    return GNUNET_YES; /* element not live in operation's generation */
  GNUNET_CRYPTO_hash_xor (&op->state->my_xor,
                          &ee->element_hash,
                          &op->state->my_xor);
  GNUNET_break (GNUNET_YES ==
                GNUNET_CONTAINER_multihashmap_put (op->state->my_elements,
                                                   &ee->element_hash,
                                                   ee,
                                                   GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  return GNUNET_YES;
}


/**
 * Send our element count to the peer, in case our element count is
 * lower than his.
 *
 * @param op intersection operation
 */
static void
send_element_count (struct Operation *op)
{
  struct GNUNET_MQ_Envelope *ev;
  struct IntersectionElementInfoMessage *msg;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending our element count (bf_msg)\n");
  ev = GNUNET_MQ_msg (msg,
                      GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_ELEMENT_INFO);
  msg->sender_element_count = htonl (op->state->my_element_count);
  GNUNET_MQ_send (op->mq, ev);
}


/**
 * We go first, initialize our map with all elements and
 * send the first Bloom filter.
 *
 * @param op operation to start exchange for
 */
static void
begin_bf_exchange (struct Operation *op)
{
  GNUNET_break (PHASE_INITIAL == op->state->phase);
  op->state->phase = PHASE_BF_EXCHANGE;
  op->state->my_elements
    = GNUNET_CONTAINER_multihashmap_create (op->state->my_element_count,
                                            GNUNET_YES);
  GNUNET_CONTAINER_multihashmap_iterate (op->spec->set->elements,
                                         &initialize_map_unfiltered,
                                         op);
  send_bloomfilter (op);
}


/**
 * Handle the initial `struct IntersectionElementInfoMessage` from a
 * remote peer.
 *
 * @param cls the intersection operation
 * @param mh the header of the message
 */
static void
handle_p2p_element_info (void *cls,
                         const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;
  const struct IntersectionElementInfoMessage *msg;

  if (ntohs (mh->size) != sizeof (struct IntersectionElementInfoMessage))
  {
    GNUNET_break_op (0);
    fail_intersection_operation(op);
    return;
  }
  msg = (const struct IntersectionElementInfoMessage *) mh;
  op->spec->remote_element_count = ntohl (msg->sender_element_count);
  if ( (PHASE_INITIAL != op->state->phase) ||
       (op->state->my_element_count > op->spec->remote_element_count) ||
       (0 == op->state->my_element_count) ||
       (0 == op->spec->remote_element_count) )
  {
    GNUNET_break_op (0);
    fail_intersection_operation(op);
    return;
  }
  GNUNET_break (NULL == op->state->remote_bf);
  begin_bf_exchange (op);
}


/**
 * Send a result message to the client indicating that the operation
 * is over.  After the result done message has been sent to the
 * client, destroy the evaluate operation.
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
                "Sending full result set\n");
    op->state->full_result_iter
      = GNUNET_CONTAINER_multihashmap_iterator_create (op->state->my_elements);
    send_remaining_elements (op);
    return;
  }
  send_client_done_and_destroy (op);
}


/**
 * Remove all elements from our hashmap.
 *
 * @param cls closure with the `struct Operation *`
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES (we should continue to iterate)
 */
static int
filter_all (void *cls,
            const struct GNUNET_HashCode *key,
            void *value)
{
  struct Operation *op = cls;
  struct ElementEntry *ee = value;

  GNUNET_break (0 < op->state->my_element_count);
  op->state->my_element_count--;
  GNUNET_CRYPTO_hash_xor (&op->state->my_xor,
                          &ee->element_hash,
                          &op->state->my_xor);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (op->state->my_elements,
                                                       &ee->element_hash,
                                                       ee));
  send_client_removed_element (op,
                               &ee->element);
  return GNUNET_YES;
}


/**
 * Handle a done message from a remote peer
 *
 * @param cls the intersection operation
 * @param mh the message
 */
static void
handle_p2p_done (void *cls,
                 const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;
  const struct IntersectionDoneMessage *idm;

  if (PHASE_BF_EXCHANGE != op->state->phase)
  {
    /* wrong phase to conclude? FIXME: Or should we allow this
       if the other peer has _initially_ already an empty set? */
    GNUNET_break_op (0);
    fail_intersection_operation (op);
    return;
  }
  if (ntohs (mh->size) != sizeof (struct IntersectionDoneMessage))
  {
    GNUNET_break_op (0);
    fail_intersection_operation (op);
    return;
  }
  idm = (const struct IntersectionDoneMessage *) mh;
  if (0 == ntohl (idm->final_element_count))
  {
    /* other peer determined empty set is the intersection,
       remove all elements */
    GNUNET_CONTAINER_multihashmap_iterate (op->state->my_elements,
                                           &filter_all,
                                           op);
  }
  if ( (op->state->my_element_count != ntohl (idm->final_element_count)) ||
       (0 != memcmp (&op->state->my_xor,
                     &idm->element_xor_hash,
                     sizeof (struct GNUNET_HashCode))) )
  {
    /* Other peer thinks we are done, but we disagree on the result! */
    GNUNET_break_op (0);
    fail_intersection_operation (op);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got final DONE\n");
  op->state->phase = PHASE_FINISHED;
  finish_and_destroy (op);
}


/**
 * Initiate a set intersection operation with a remote peer.
 *
 * @param op operation that is created, should be initialized to
 *        begin the evaluation
 * @param opaque_context message to be transmitted to the listener
 *        to convince him to accept, may be NULL
 */
static void
intersection_evaluate (struct Operation *op,
                       const struct GNUNET_MessageHeader *opaque_context)
{
  struct GNUNET_MQ_Envelope *ev;
  struct OperationRequestMessage *msg;

  op->state = GNUNET_new (struct OperationState);
  /* we started the operation, thus we have to send the operation request */
  op->state->phase = PHASE_INITIAL;
  op->state->my_element_count = op->spec->set->state->current_set_element_count;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Initiating intersection operation evaluation");
  ev = GNUNET_MQ_msg_nested_mh (msg,
                                GNUNET_MESSAGE_TYPE_SET_P2P_OPERATION_REQUEST,
                                opaque_context);
  if (NULL == ev)
  {
    /* the context message is too large!? */
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (op->spec->set->client);
    return;
  }
  msg->operation = htonl (GNUNET_SET_OPERATION_INTERSECTION);
  msg->app_id = op->spec->app_id;
  msg->element_count = htonl (op->state->my_element_count);
  GNUNET_MQ_send (op->mq,
                  ev);
  if (NULL != opaque_context)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sent op request with context message\n");
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sent op request without context message\n");
}


/**
 * Accept an intersection operation request from a remote peer.  Only
 * initializes the private operation state.
 *
 * @param op operation that will be accepted as an intersection operation
 */
static void
intersection_accept (struct Operation *op)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Accepting set intersection operation\n");
  op->state = GNUNET_new (struct OperationState);
  op->state->phase = PHASE_INITIAL;
  op->state->my_element_count
    = op->spec->set->state->current_set_element_count;
  op->state->my_elements
    = GNUNET_CONTAINER_multihashmap_create
    (GNUNET_MIN (op->state->my_element_count,
                 op->spec->remote_element_count),
     GNUNET_YES);
  if (op->spec->remote_element_count < op->state->my_element_count)
  {
    /* If the other peer (Alice) has fewer elements than us (Bob),
       we just send the count as Alice should send the first BF */
    send_element_count (op);
    op->state->phase = PHASE_BF_EXCHANGE;
    return;
  }
  /* We have fewer elements, so we start with the BF */
  begin_bf_exchange (op);
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
              "Received p2p message (t: %u, s: %u)\n",
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
  case GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_DONE:
    handle_p2p_done (op, mh);
    break;
  default:
    /* something wrong with cadet's message handlers? */
    GNUNET_assert (0);
  }
  return GNUNET_OK;
}


/**
 * Handler for peer-disconnects, notifies the client about the aborted
 * operation.  If we did not expect anything from the other peer, we
 * gracefully terminate the operation.
 *
 * @param op the destroyed operation
 */
static void
intersection_peer_disconnect (struct Operation *op)
{
  if (PHASE_FINISHED != op->state->phase)
  {
    fail_intersection_operation (op);
    return;
  }
  /* the session has already been concluded */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Other peer disconnected (finished)\n");
  if (GNUNET_NO == op->state->client_done_sent)
    finish_and_destroy (op);
}


/**
 * Destroy the intersection operation.  Only things specific to the
 * intersection operation are destroyed.
 *
 * @param op intersection operation to destroy
 */
static void
intersection_op_cancel (struct Operation *op)
{
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
    GNUNET_CONTAINER_multihashmap_destroy (op->state->my_elements);
    op->state->my_elements = NULL;
  }
  GNUNET_free (op->state);
  op->state = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Destroying intersection op state done\n");
}


/**
 * Create a new set supporting the intersection operation.
 *
 * @return the newly created set
 */
static struct SetState *
intersection_set_create ()
{
  struct SetState *set_state;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Intersection set created\n");
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
  GNUNET_assert (0 < set_state->current_set_element_count);
  set_state->current_set_element_count--;
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
