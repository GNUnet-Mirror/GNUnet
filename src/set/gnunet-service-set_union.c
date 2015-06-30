/*
      This file is part of GNUnet
      Copyright (C) 2013 Christian Grothoff (and other contributing authors)

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
 * @file set/gnunet-service-set_union.c
 * @brief two-peer set operations
 * @author Florian Dold
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet-service-set.h"
#include "ibf.h"
#include "gnunet-service-set_union_strata_estimator.h"
#include "gnunet-service-set_protocol.h"
#include <gcrypt.h>


/**
 * Number of IBFs in a strata estimator.
 */
#define SE_STRATA_COUNT 32
/**
 * Size of the IBFs in the strata estimator.
 */
#define SE_IBF_SIZE 80
/**
 * hash num parameter for the difference digests and strata estimators
 */
#define SE_IBF_HASH_NUM 4

/**
 * Number of buckets that can be transmitted in one message.
 */
#define MAX_BUCKETS_PER_MESSAGE ((1<<15) / IBF_BUCKET_SIZE)

/**
 * The maximum size of an ibf we use is 2^(MAX_IBF_ORDER).
 * Choose this value so that computing the IBF is still cheaper
 * than transmitting all values.
 */
#define MAX_IBF_ORDER (16)

/**
 * Number of buckets used in the ibf per estimated
 * difference.
 */
#define IBF_ALPHA 4


/**
 * Current phase we are in for a union operation.
 */
enum UnionOperationPhase
{
  /**
   * We sent the request message, and expect a strata estimator
   */
  PHASE_EXPECT_SE,

  /**
   * We sent the strata estimator, and expect an IBF. This phase is entered once
   * upon initialization and later via #PHASE_EXPECT_ELEMENTS_AND_REQUESTS.
   *
   * After receiving the complete IBF, we enter #PHASE_EXPECT_ELEMENTS
   */
  PHASE_EXPECT_IBF,

  /**
   * Continuation for multi part IBFs.
   */
  PHASE_EXPECT_IBF_CONT,

  /**
   * We are sending request and elements,
   * and thus only expect elements from the other peer.
   *
   * We are currently decoding an IBF until it can no longer be decoded,
   * we currently send requests and expect elements
   * The remote peer is in #PHASE_EXPECT_ELEMENTS_AND_REQUESTS
   */
  PHASE_EXPECT_ELEMENTS,

  /**
   * We are expecting elements and requests, and send
   * requested elements back to the other peer.
   *
   * We are in this phase if we have SENT an IBF for the remote peer to decode.
   * We expect requests, send elements or could receive an new IBF, which takes
   * us via #PHASE_EXPECT_IBF to phase #PHASE_EXPECT_ELEMENTS
   *
   * The remote peer is thus in:
   * #PHASE_EXPECT_ELEMENTS
   */
  PHASE_EXPECT_ELEMENTS_AND_REQUESTS,

  /**
   * The protocol is over.
   * Results may still have to be sent to the client.
   */
  PHASE_FINISHED
};


/**
 * State of an evaluate operation with another peer.
 */
struct OperationState
{

  /**
   * Copy of the set's strata estimator at the time of
   * creation of this operation
   */
  struct StrataEstimator *se;

  /**
   * The ibf we currently receive
   */
  struct InvertibleBloomFilter *remote_ibf;

  /**
   * IBF of the set's element.
   */
  struct InvertibleBloomFilter *local_ibf;

  /**
   * Maps IBF-Keys (specific to the current salt) to elements.
   * Used as a multihashmap, the keys being the lower 32bit of the IBF-Key.
   * Colliding IBF-Keys are linked.
   */
  struct GNUNET_CONTAINER_MultiHashMap32 *key_to_element;

  /**
   * Iterator for sending elements on the key to element mapping to the client.
   */
  struct GNUNET_CONTAINER_MultiHashMap32Iterator *full_result_iter;

  /**
   * Current state of the operation.
   */
  enum UnionOperationPhase phase;

  /**
   * Did we send the client that we are done?
   */
  int client_done_sent;

  /**
   * Number of ibf buckets received
   */
  unsigned int ibf_buckets_received;

};


/**
 * The key entry is used to associate an ibf key with an element.
 */
struct KeyEntry
{
  /**
   * IBF key for the entry, derived from the current salt.
   */
  struct IBF_Key ibf_key;

  /**
   * The actual element associated with the key.
   */
  struct ElementEntry *element;

  /**
   * Element that collides with this element
   * on the ibf key. All colliding entries must have the same ibf key.
   */
  struct KeyEntry *next_colliding;
};


/**
 * Used as a closure for sending elements
 * with a specific IBF key.
 */
struct SendElementClosure
{
  /**
   * The IBF key whose matching elements should be
   * sent.
   */
  struct IBF_Key ibf_key;

  /**
   * Operation for which the elements
   * should be sent.
   */
  struct Operation *op;
};


/**
 * Extra state required for efficient set union.
 */
struct SetState
{
  /**
   * The strata estimator is only generated once for
   * each set.
   * The IBF keys are derived from the element hashes with
   * salt=0.
   */
  struct StrataEstimator *se;
};


/**
 * Iterator over hash map entries, called to
 * destroy the linked list of colliding ibf key entries.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES if we should continue to iterate,
 *         #GNUNET_NO if not.
 */
static int
destroy_key_to_element_iter (void *cls,
                             uint32_t key,
                             void *value)
{
  struct KeyEntry *k = value;

  while (NULL != k)
  {
    struct KeyEntry *k_tmp = k;

    k = k->next_colliding;
    if (GNUNET_YES == k_tmp->element->remote)
    {
      GNUNET_free (k_tmp->element);
      k_tmp->element = NULL;
    }
    GNUNET_free (k_tmp);
  }
  return GNUNET_YES;
}


/**
 * Destroy the union operation.  Only things specific to the union
 * operation are destroyed.
 *
 * @param op union operation to destroy
 */
static void
union_op_cancel (struct Operation *op)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "destroying union op\n");
  /* check if the op was canceled twice */
  GNUNET_assert (NULL != op->state);
  if (NULL != op->state->remote_ibf)
  {
    ibf_destroy (op->state->remote_ibf);
    op->state->remote_ibf = NULL;
  }
  if (NULL != op->state->local_ibf)
  {
    ibf_destroy (op->state->local_ibf);
    op->state->local_ibf = NULL;
  }
  if (NULL != op->state->se)
  {
    strata_estimator_destroy (op->state->se);
    op->state->se = NULL;
  }
  if (NULL != op->state->key_to_element)
  {
    GNUNET_CONTAINER_multihashmap32_iterate (op->state->key_to_element,
                                             &destroy_key_to_element_iter,
                                             NULL);
    GNUNET_CONTAINER_multihashmap32_destroy (op->state->key_to_element);
    op->state->key_to_element = NULL;
  }
  GNUNET_free (op->state);
  op->state = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "destroying union op done\n");
}


/**
 * Inform the client that the union operation has failed,
 * and proceed to destroy the evaluate operation.
 *
 * @param op the union operation to fail
 */
static void
fail_union_operation (struct Operation *op)
{
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SET_ResultMessage *msg;

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "union operation failed\n");
  ev = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_SET_RESULT);
  msg->result_status = htons (GNUNET_SET_STATUS_FAILURE);
  msg->request_id = htonl (op->spec->client_request_id);
  msg->element_type = htons (0);
  GNUNET_MQ_send (op->spec->set->client_mq, ev);
  _GSS_operation_destroy (op, GNUNET_YES);
}


/**
 * Derive the IBF key from a hash code and
 * a salt.
 *
 * @param src the hash code
 * @param salt salt to use
 * @return the derived IBF key
 */
static struct IBF_Key
get_ibf_key (const struct GNUNET_HashCode *src,
             uint16_t salt)
{
  struct IBF_Key key;

  GNUNET_CRYPTO_hkdf (&key, sizeof (key),
		      GCRY_MD_SHA512, GCRY_MD_SHA256,
                      src, sizeof *src,
		      &salt, sizeof (salt),
		      NULL, 0);
  return key;
}


/**
 * Iterator to create the mapping between ibf keys
 * and element entries.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES if we should continue to iterate,
 *         #GNUNET_NO if not.
 */
static int
op_register_element_iterator (void *cls,
                              uint32_t key,
                              void *value)
{
  struct KeyEntry *const new_k = cls;
  struct KeyEntry *old_k = value;

  GNUNET_assert (NULL != old_k);
  /* check if our ibf key collides with the ibf key in the existing entry */
  if (old_k->ibf_key.key_val == new_k->ibf_key.key_val)
  {
    /* insert the the new key in the collision chain */
    new_k->next_colliding = old_k->next_colliding;
    old_k->next_colliding = new_k;
    /* signal to the caller that we were able to insert into a colliding bucket */
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Iterator to create the mapping between ibf keys
 * and element entries.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES (we should continue to iterate)
 */
static int
op_has_element_iterator (void *cls,
                         uint32_t key,
                         void *value)
{
  struct GNUNET_HashCode *element_hash = cls;
  struct KeyEntry *k = value;

  GNUNET_assert (NULL != k);
  while (NULL != k)
  {
    if (0 == GNUNET_CRYPTO_hash_cmp (&k->element->element_hash,
                                     element_hash))
      return GNUNET_NO;
    k = k->next_colliding;
  }
  return GNUNET_YES;
}


/**
 * Determine whether the given element is already in the operation's element
 * set.
 *
 * @param op operation that should be tested for 'element_hash'
 * @param element_hash hash of the element to look for
 * @return #GNUNET_YES if the element has been found, #GNUNET_NO otherwise
 */
static int
op_has_element (struct Operation *op,
                const struct GNUNET_HashCode *element_hash)
{
  int ret;
  struct IBF_Key ibf_key;

  ibf_key = get_ibf_key (element_hash, op->spec->salt);
  ret = GNUNET_CONTAINER_multihashmap32_get_multiple (op->state->key_to_element,
                                                      (uint32_t) ibf_key.key_val,
                                                      op_has_element_iterator,
                                                      (void *) element_hash);

  /* was the iteration aborted because we found the element? */
  if (GNUNET_SYSERR == ret)
    return GNUNET_YES;
  return GNUNET_NO;
}


/**
 * Insert an element into the union operation's
 * key-to-element mapping. Takes ownership of 'ee'.
 * Note that this does not insert the element in the set,
 * only in the operation's key-element mapping.
 * This is done to speed up re-tried operations, if some elements
 * were transmitted, and then the IBF fails to decode.
 *
 * @param op the union operation
 * @param ee the element entry
 */
static void
op_register_element (struct Operation *op,
                     struct ElementEntry *ee)
{
  int ret;
  struct IBF_Key ibf_key;
  struct KeyEntry *k;

  ibf_key = get_ibf_key (&ee->element_hash, op->spec->salt);
  k = GNUNET_new (struct KeyEntry);
  k->element = ee;
  k->ibf_key = ibf_key;
  ret = GNUNET_CONTAINER_multihashmap32_get_multiple (op->state->key_to_element,
                                                      (uint32_t) ibf_key.key_val,
                                                      op_register_element_iterator,
                                                      k);

  /* was the element inserted into a colliding bucket? */
  if (GNUNET_SYSERR == ret)
    return;
  GNUNET_CONTAINER_multihashmap32_put (op->state->key_to_element,
                                       (uint32_t) ibf_key.key_val,
                                       k,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
}


/**
 * Insert a key into an ibf.
 *
 * @param cls the ibf
 * @param key unused
 * @param value the key entry to get the key from
 */
static int
prepare_ibf_iterator (void *cls,
                      uint32_t key,
                      void *value)
{
  struct InvertibleBloomFilter *ibf = cls;
  struct KeyEntry *ke = value;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "inserting %x into ibf\n",
              ke->ibf_key.key_val);
  ibf_insert (ibf, ke->ibf_key);
  return GNUNET_YES;
}


/**
 * Iterator for initializing the
 * key-to-element mapping of a union operation
 *
 * @param cls the union operation `struct Operation *`
 * @param key unused
 * @param value the `struct ElementEntry *` to insert
 *        into the key-to-element mapping
 * @return #GNUNET_YES (to continue iterating)
 */
static int
init_key_to_element_iterator (void *cls,
                              const struct GNUNET_HashCode *key,
                              void *value)
{
  struct Operation *op = cls;
  struct ElementEntry *e = value;

  /* make sure that the element belongs to the set at the time
   * of creating the operation */
  if ( (e->generation_added > op->generation_created) ||
       ( (GNUNET_YES == e->removed) &&
         (e->generation_removed < op->generation_created)))
    return GNUNET_YES;

  GNUNET_assert (GNUNET_NO == e->remote);

  op_register_element (op, e);
  return GNUNET_YES;
}


/**
 * Create an ibf with the operation's elements
 * of the specified size
 *
 * @param op the union operation
 * @param size size of the ibf to create
 */
static void
prepare_ibf (struct Operation *op,
             uint16_t size)
{
  if (NULL == op->state->key_to_element)
  {
    unsigned int len;

    len = GNUNET_CONTAINER_multihashmap_size (op->spec->set->elements);
    op->state->key_to_element = GNUNET_CONTAINER_multihashmap32_create (len + 1);
    GNUNET_CONTAINER_multihashmap_iterate (op->spec->set->elements,
                                           init_key_to_element_iterator, op);
  }
  if (NULL != op->state->local_ibf)
    ibf_destroy (op->state->local_ibf);
  op->state->local_ibf = ibf_create (size, SE_IBF_HASH_NUM);
  GNUNET_CONTAINER_multihashmap32_iterate (op->state->key_to_element,
                                           &prepare_ibf_iterator,
                                           op->state->local_ibf);
}


/**
 * Send an ibf of appropriate size.
 *
 * @param op the union operation
 * @param ibf_order order of the ibf to send, size=2^order
 */
static void
send_ibf (struct Operation *op,
          uint16_t ibf_order)
{
  unsigned int buckets_sent = 0;
  struct InvertibleBloomFilter *ibf;

  prepare_ibf (op, 1<<ibf_order);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "sending ibf of size %u\n",
              1<<ibf_order);

  ibf = op->state->local_ibf;

  while (buckets_sent < (1 << ibf_order))
  {
    unsigned int buckets_in_message;
    struct GNUNET_MQ_Envelope *ev;
    struct IBFMessage *msg;

    buckets_in_message = (1 << ibf_order) - buckets_sent;
    /* limit to maximum */
    if (buckets_in_message > MAX_BUCKETS_PER_MESSAGE)
      buckets_in_message = MAX_BUCKETS_PER_MESSAGE;

    ev = GNUNET_MQ_msg_extra (msg,
                              buckets_in_message * IBF_BUCKET_SIZE,
                              GNUNET_MESSAGE_TYPE_SET_UNION_P2P_IBF);
    msg->reserved = 0;
    msg->order = ibf_order;
    msg->offset = htons (buckets_sent);
    ibf_write_slice (ibf, buckets_sent,
                     buckets_in_message, &msg[1]);
    buckets_sent += buckets_in_message;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "ibf chunk size %u, %u/%u sent\n",
                buckets_in_message,
                buckets_sent,
                1<<ibf_order);
    GNUNET_MQ_send (op->mq, ev);
  }

  op->state->phase = PHASE_EXPECT_ELEMENTS_AND_REQUESTS;
}


/**
 * Send a strata estimator to the remote peer.
 *
 * @param op the union operation with the remote peer
 */
static void
send_strata_estimator (struct Operation *op)
{
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_MessageHeader *strata_msg;

  ev = GNUNET_MQ_msg_header_extra (strata_msg,
                                   SE_STRATA_COUNT * IBF_BUCKET_SIZE * SE_IBF_SIZE,
                                   GNUNET_MESSAGE_TYPE_SET_UNION_P2P_SE);
  strata_estimator_write (op->state->se, &strata_msg[1]);
  GNUNET_MQ_send (op->mq,
                  ev);
  op->state->phase = PHASE_EXPECT_IBF;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "sent SE, expecting IBF\n");
}


/**
 * Compute the necessary order of an ibf
 * from the size of the symmetric set difference.
 *
 * @param diff the difference
 * @return the required size of the ibf
 */
static unsigned int
get_order_from_difference (unsigned int diff)
{
  unsigned int ibf_order;

  ibf_order = 2;
  while ( (1<<ibf_order) < (IBF_ALPHA * diff) ||
          ((1<<ibf_order) < SE_IBF_HASH_NUM) )
    ibf_order++;
  if (ibf_order > MAX_IBF_ORDER)
    ibf_order = MAX_IBF_ORDER;
  return ibf_order;
}


/**
 * Handle a strata estimator from a remote peer
 *
 * @param cls the union operation
 * @param mh the message
 * @return #GNUNET_SYSERR if the tunnel should be disconnected,
 *         #GNUNET_OK otherwise
 */
static int
handle_p2p_strata_estimator (void *cls,
                             const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;
  struct StrataEstimator *remote_se;
  int diff;

  if (op->state->phase != PHASE_EXPECT_SE)
  {
    fail_union_operation (op);
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (ntohs (mh->size) !=
      SE_STRATA_COUNT * SE_IBF_SIZE * IBF_BUCKET_SIZE +
      sizeof (struct GNUNET_MessageHeader))
  {
    fail_union_operation (op);
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  remote_se = strata_estimator_create (SE_STRATA_COUNT,
                                       SE_IBF_SIZE,
                                       SE_IBF_HASH_NUM);
  strata_estimator_read (&mh[1], remote_se);
  GNUNET_assert (NULL != op->state->se);
  diff = strata_estimator_difference (remote_se,
                                      op->state->se);
  strata_estimator_destroy (remote_se);
  strata_estimator_destroy (op->state->se);
  op->state->se = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "got se diff=%d, using ibf size %d\n",
              diff,
              1<<get_order_from_difference (diff));
  send_ibf (op,
            get_order_from_difference (diff));
  return GNUNET_OK;
}


/**
 * Iterator to send elements to a remote peer
 *
 * @param cls closure with the element key and the union operation
 * @param key ignored
 * @param value the key entry
 */
static int
send_element_iterator (void *cls,
                       uint32_t key,
                       void *value)
{
  struct SendElementClosure *sec = cls;
  struct IBF_Key ibf_key = sec->ibf_key;
  struct Operation *op = sec->op;
  struct KeyEntry *ke = value;

  if (ke->ibf_key.key_val != ibf_key.key_val)
    return GNUNET_YES;
  while (NULL != ke)
  {
    const struct GNUNET_SET_Element *const element = &ke->element->element;
    struct GNUNET_MQ_Envelope *ev;
    struct GNUNET_MessageHeader *mh;

    GNUNET_assert (ke->ibf_key.key_val == ibf_key.key_val);
    ev = GNUNET_MQ_msg_header_extra (mh,
                                     element->size,
                                     GNUNET_MESSAGE_TYPE_SET_P2P_ELEMENTS);
    if (NULL == ev)
    {
      /* element too large */
      GNUNET_break (0);
      continue;
    }
    memcpy (&mh[1],
            element->data,
            element->size);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "sending element (%s) to peer\n",
                GNUNET_h2s (&ke->element->element_hash));
    GNUNET_MQ_send (op->mq, ev);
    ke = ke->next_colliding;
  }
  return GNUNET_NO;
}


/**
 * Send all elements that have the specified IBF key
 * to the remote peer of the union operation
 *
 * @param op union operation
 * @param ibf_key IBF key of interest
 */
static void
send_elements_for_key (struct Operation *op,
                       struct IBF_Key ibf_key)
{
  struct SendElementClosure send_cls;

  send_cls.ibf_key = ibf_key;
  send_cls.op = op;
  (void) GNUNET_CONTAINER_multihashmap32_get_multiple (op->state->key_to_element,
                                                       (uint32_t) ibf_key.key_val,
                                                       &send_element_iterator,
                                                       &send_cls);
}


/**
 * Decode which elements are missing on each side, and
 * send the appropriate elemens and requests
 *
 * @param op union operation
 */
static void
decode_and_send (struct Operation *op)
{
  struct IBF_Key key;
  struct IBF_Key last_key;
  int side;
  unsigned int num_decoded;
  struct InvertibleBloomFilter *diff_ibf;

  GNUNET_assert (PHASE_EXPECT_ELEMENTS == op->state->phase);

  prepare_ibf (op, op->state->remote_ibf->size);
  diff_ibf = ibf_dup (op->state->local_ibf);
  ibf_subtract (diff_ibf, op->state->remote_ibf);

  ibf_destroy (op->state->remote_ibf);
  op->state->remote_ibf = NULL;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "decoding IBF (size=%u)\n",
              diff_ibf->size);

  num_decoded = 0;
  last_key.key_val = 0;

  while (1)
  {
    int res;
    int cycle_detected = GNUNET_NO;

    last_key = key;

    res = ibf_decode (diff_ibf, &side, &key);
    if (res == GNUNET_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "decoded ibf key %lx\n",
                  key.key_val);
      num_decoded += 1;
      if ( (num_decoded > diff_ibf->size) ||
           (num_decoded > 1 && last_key.key_val == key.key_val) )
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "detected cyclic ibf (decoded %u/%u)\n",
                    num_decoded,
                    diff_ibf->size);
        cycle_detected = GNUNET_YES;
      }
    }
    if ( (GNUNET_SYSERR == res) ||
         (GNUNET_YES == cycle_detected) )
    {
      int next_order;
      next_order = 0;
      while (1<<next_order < diff_ibf->size)
        next_order++;
      next_order++;
      if (next_order <= MAX_IBF_ORDER)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		    "decoding failed, sending larger ibf (size %u)\n",
                    1<<next_order);
        send_ibf (op, next_order);
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		    "set union failed: reached ibf limit\n");
      }
      break;
    }
    if (GNUNET_NO == res)
    {
      struct GNUNET_MQ_Envelope *ev;

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "transmitted all values, sending DONE\n");
      ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_SET_UNION_P2P_DONE);
      GNUNET_MQ_send (op->mq, ev);
      break;
    }
    if (1 == side)
    {
      send_elements_for_key (op, key);
    }
    else if (-1 == side)
    {
      struct GNUNET_MQ_Envelope *ev;
      struct GNUNET_MessageHeader *msg;

      /* It may be nice to merge multiple requests, but with cadet's corking it is not worth
       * the effort additional complexity. */
      ev = GNUNET_MQ_msg_header_extra (msg,
                                       sizeof (struct IBF_Key),
                                       GNUNET_MESSAGE_TYPE_SET_P2P_ELEMENT_REQUESTS);

      memcpy (&msg[1],
              &key,
              sizeof (struct IBF_Key));
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "sending element request\n");
      GNUNET_MQ_send (op->mq, ev);
    }
    else
    {
      GNUNET_assert (0);
    }
  }
  ibf_destroy (diff_ibf);
}


/**
 * Handle an IBF message from a remote peer.
 *
 * @param cls the union operation
 * @param mh the header of the message
 * @return #GNUNET_SYSERR if the tunnel should be disconnected,
 *         #GNUNET_OK otherwise
 */
static int
handle_p2p_ibf (void *cls,
                const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;
  const struct IBFMessage *msg;
  unsigned int buckets_in_message;

  if (ntohs (mh->size) < sizeof (struct IBFMessage))
  {
    GNUNET_break_op (0);
    fail_union_operation (op);
    return GNUNET_SYSERR;
  }
  msg = (const struct IBFMessage *) mh;
  if ( (op->state->phase == PHASE_EXPECT_ELEMENTS_AND_REQUESTS) ||
       (op->state->phase == PHASE_EXPECT_IBF) )
  {
    op->state->phase = PHASE_EXPECT_IBF_CONT;
    GNUNET_assert (NULL == op->state->remote_ibf);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Creating new ibf of size %u\n",
                1 << msg->order);
    op->state->remote_ibf = ibf_create (1<<msg->order, SE_IBF_HASH_NUM);
    op->state->ibf_buckets_received = 0;
    if (0 != ntohs (msg->offset))
    {
      GNUNET_break_op (0);
      fail_union_operation (op);
      return GNUNET_SYSERR;
    }
  }
  else if (op->state->phase == PHASE_EXPECT_IBF_CONT)
  {
    if ( (ntohs (msg->offset) != op->state->ibf_buckets_received) ||
         (1<<msg->order != op->state->remote_ibf->size) )
    {
      GNUNET_break_op (0);
      fail_union_operation (op);
      return GNUNET_SYSERR;
    }
  }

  buckets_in_message = (ntohs (msg->header.size) - sizeof *msg) / IBF_BUCKET_SIZE;

  if (0 == buckets_in_message)
  {
    GNUNET_break_op (0);
    fail_union_operation (op);
    return GNUNET_SYSERR;
  }

  if ((ntohs (msg->header.size) - sizeof *msg) != buckets_in_message * IBF_BUCKET_SIZE)
  {
    GNUNET_break_op (0);
    fail_union_operation (op);
    return GNUNET_SYSERR;
  }

  ibf_read_slice (&msg[1],
                  op->state->ibf_buckets_received,
                  buckets_in_message,
                  op->state->remote_ibf);
  op->state->ibf_buckets_received += buckets_in_message;

  if (op->state->ibf_buckets_received == op->state->remote_ibf->size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "received full ibf\n");
    op->state->phase = PHASE_EXPECT_ELEMENTS;
    decode_and_send (op);
  }
  return GNUNET_OK;
}


/**
 * Send a result message to the client indicating
 * that there is a new element.
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
              "sending element (size %u) to client\n",
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
  rm->element_type = element->element_type;
  memcpy (&rm[1], element->data, element->size);
  GNUNET_MQ_send (op->spec->set->client_mq, ev);
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
  _GSS_operation_destroy (op, GNUNET_YES);
  op->keep--;
  if (0 == op->keep)
    GNUNET_free (op);
}


/**
 * Send all remaining elements in the full result iterator.
 *
 * @param cls operation
 */
static void
send_remaining_elements (void *cls)
{
  struct Operation *op = cls;
  struct KeyEntry *ke;
  int res;

  res = GNUNET_CONTAINER_multihashmap32_iterator_next (op->state->full_result_iter,
                                                       NULL,
                                                       (const void **) &ke);
  if (GNUNET_NO == res)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "sending done and destroy because iterator ran out\n");
    send_done_and_destroy (op);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "sending elements from key entry\n");
  while (1)
  {
    struct GNUNET_MQ_Envelope *ev;
    struct GNUNET_SET_ResultMessage *rm;
    struct GNUNET_SET_Element *element;

    element = &ke->element->element;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "sending element (size %u) to client (full set)\n",
                element->size);
    GNUNET_assert (0 != op->spec->client_request_id);
    ev = GNUNET_MQ_msg_extra (rm,
                              element->size,
                              GNUNET_MESSAGE_TYPE_SET_RESULT);
    if (NULL == ev)
    {
      GNUNET_MQ_discard (ev);
      GNUNET_break (0);
      continue;
    }
    rm->result_status = htons (GNUNET_SET_STATUS_OK);
    rm->request_id = htonl (op->spec->client_request_id);
    rm->element_type = element->element_type;
    memcpy (&rm[1], element->data, element->size);
    if (NULL == ke->next_colliding)
    {
      GNUNET_MQ_notify_sent (ev, send_remaining_elements, op);
      GNUNET_MQ_send (op->spec->set->client_mq, ev);
      break;
    }
    GNUNET_MQ_send (op->spec->set->client_mq, ev);
    ke = ke->next_colliding;
  }
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
  op->keep++;
  if (GNUNET_SET_RESULT_FULL == op->spec->result_mode)
  {
    /* prevent that the op is free'd by the tunnel end handler */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "sending full result set\n");
    GNUNET_assert (NULL == op->state->full_result_iter);
    op->state->full_result_iter =
        GNUNET_CONTAINER_multihashmap32_iterator_create (op->state->key_to_element);
    send_remaining_elements (op);
    return;
  }
  send_done_and_destroy (op);
}


/**
 * Handle an element message from a remote peer.
 *
 * @param cls the union operation
 * @param mh the message
 */
static void
handle_p2p_elements (void *cls,
                     const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;
  struct ElementEntry *ee;
  uint16_t element_size;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got element from peer\n");
  if ( (op->state->phase != PHASE_EXPECT_ELEMENTS) &&
       (op->state->phase != PHASE_EXPECT_ELEMENTS_AND_REQUESTS) )
  {
    fail_union_operation (op);
    GNUNET_break_op (0);
    return;
  }
  element_size = ntohs (mh->size) - sizeof (struct GNUNET_MessageHeader);
  ee = GNUNET_malloc (sizeof (struct ElementEntry) + element_size);
  memcpy (&ee[1], &mh[1], element_size);
  ee->element.size = element_size;
  ee->element.data = &ee[1];
  ee->remote = GNUNET_YES;
  GNUNET_CRYPTO_hash (ee->element.data,
                      ee->element.size,
                      &ee->element_hash);

  if (GNUNET_YES == op_has_element (op, &ee->element_hash))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "got existing element from peer\n");
    GNUNET_free (ee);
    return;
  }

  op_register_element (op, ee);
  /* only send results immediately if the client wants it */
  if (GNUNET_SET_RESULT_ADDED == op->spec->result_mode)
    send_client_element (op, &ee->element);
}


/**
 * Handle an element request from a remote peer.
 *
 * @param cls the union operation
 * @param mh the message
 */
static void
handle_p2p_element_requests (void *cls,
                             const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;
  const struct IBF_Key *ibf_key;
  unsigned int num_keys;

  /* look up elements and send them */
  if (op->state->phase != PHASE_EXPECT_ELEMENTS_AND_REQUESTS)
  {
    GNUNET_break_op (0);
    fail_union_operation (op);
    return;
  }
  num_keys = (ntohs (mh->size) - sizeof (struct GNUNET_MessageHeader))
    / sizeof (struct IBF_Key);
  if ((ntohs (mh->size) - sizeof (struct GNUNET_MessageHeader))
      != num_keys * sizeof (struct IBF_Key))
  {
    GNUNET_break_op (0);
    fail_union_operation (op);
    return;
  }

  ibf_key = (const struct IBF_Key *) &mh[1];
  while (0 != num_keys--)
  {
    send_elements_for_key (op, *ibf_key);
    ibf_key++;
  }
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
  struct GNUNET_MQ_Envelope *ev;

  if (op->state->phase == PHASE_EXPECT_ELEMENTS_AND_REQUESTS)
  {
    /* we got all requests, but still have to send our elements as response */

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "got DONE, sending final DONE after elements\n");
    op->state->phase = PHASE_FINISHED;
    ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_SET_UNION_P2P_DONE);
    GNUNET_MQ_send (op->mq, ev);
    return;
  }
  if (op->state->phase == PHASE_EXPECT_ELEMENTS)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "got final DONE\n");
    op->state->phase = PHASE_FINISHED;
    finish_and_destroy (op);
    return;
  }
  GNUNET_break_op (0);
  fail_union_operation (op);
}


/**
 * Initiate operation to evaluate a set union with a remote peer.
 *
 * @param op operation to perform (to be initialized)
 * @param opaque_context message to be transmitted to the listener
 *        to convince him to accept, may be NULL
 */
static void
union_evaluate (struct Operation *op,
                const struct GNUNET_MessageHeader *opaque_context)
{
  struct GNUNET_MQ_Envelope *ev;
  struct OperationRequestMessage *msg;

  op->state = GNUNET_new (struct OperationState);
  /* copy the current generation's strata estimator for this operation */
  op->state->se = strata_estimator_dup (op->spec->set->state->se);
  /* we started the operation, thus we have to send the operation request */
  op->state->phase = PHASE_EXPECT_SE;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Initiating union operation evaluation\n");
  ev = GNUNET_MQ_msg_nested_mh (msg,
                                GNUNET_MESSAGE_TYPE_SET_P2P_OPERATION_REQUEST,
                                opaque_context);
  if (NULL == ev)
  {
    /* the context message is too large */
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (op->spec->set->client);
    return;
  }
  msg->operation = htonl (GNUNET_SET_OPERATION_UNION);
  msg->app_id = op->spec->app_id;
  GNUNET_MQ_send (op->mq,
                  ev);

  if (NULL != opaque_context)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "sent op request with context message\n");
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "sent op request without context message\n");
}


/**
 * Accept an union operation request from a remote peer.
 * Only initializes the private operation state.
 *
 * @param op operation that will be accepted as a union operation
 */
static void
union_accept (struct Operation *op)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "accepting set union operation\n");
  op->state = GNUNET_new (struct OperationState);
  op->state->se = strata_estimator_dup (op->spec->set->state->se);
  /* kick off the operation */
  send_strata_estimator (op);
}


/**
 * Create a new set supporting the union operation
 *
 * We maintain one strata estimator per set and then manipulate it over the
 * lifetime of the set, as recreating a strata estimator would be expensive.
 *
 * @return the newly created set
 */
static struct SetState *
union_set_create (void)
{
  struct SetState *set_state;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "union set created\n");
  set_state = GNUNET_new (struct SetState);
  set_state->se = strata_estimator_create (SE_STRATA_COUNT,
                                           SE_IBF_SIZE, SE_IBF_HASH_NUM);
  return set_state;
}


/**
 * Add the element from the given element message to the set.
 *
 * @param set_state state of the set want to add to
 * @param ee the element to add to the set
 */
static void
union_add (struct SetState *set_state, struct ElementEntry *ee)
{
  strata_estimator_insert (set_state->se,
                           get_ibf_key (&ee->element_hash, 0));
}


/**
 * Remove the element given in the element message from the set.
 * Only marks the element as removed, so that older set operations can still exchange it.
 *
 * @param set_state state of the set to remove from
 * @param ee set element to remove
 */
static void
union_remove (struct SetState *set_state, struct ElementEntry *ee)
{
  strata_estimator_remove (set_state->se,
                           get_ibf_key (&ee->element_hash, 0));
}


/**
 * Destroy a set that supports the union operation.
 *
 * @param set_state the set to destroy
 */
static void
union_set_destroy (struct SetState *set_state)
{
  if (NULL != set_state->se)
  {
    strata_estimator_destroy (set_state->se);
    set_state->se = NULL;
  }
  GNUNET_free (set_state);
}


/**
 * Dispatch messages for a union operation.
 *
 * @param op the state of the union evaluate operation
 * @param mh the received message
 * @return #GNUNET_SYSERR if the tunnel should be disconnected,
 *         #GNUNET_OK otherwise
 */
int
union_handle_p2p_message (struct Operation *op,
                          const struct GNUNET_MessageHeader *mh)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "received p2p message (t: %u, s: %u)\n",
              ntohs (mh->type),
              ntohs (mh->size));
  switch (ntohs (mh->type))
  {
    case GNUNET_MESSAGE_TYPE_SET_UNION_P2P_IBF:
      return handle_p2p_ibf (op, mh);
    case GNUNET_MESSAGE_TYPE_SET_UNION_P2P_SE:
      return handle_p2p_strata_estimator (op, mh);
    case GNUNET_MESSAGE_TYPE_SET_P2P_ELEMENTS:
      handle_p2p_elements (op, mh);
      break;
    case GNUNET_MESSAGE_TYPE_SET_P2P_ELEMENT_REQUESTS:
      handle_p2p_element_requests (op, mh);
      break;
    case GNUNET_MESSAGE_TYPE_SET_UNION_P2P_DONE:
      handle_p2p_done (op, mh);
      break;
    default:
      /* something wrong with cadet's message handlers? */
      GNUNET_assert (0);
  }
  return GNUNET_OK;
}

/**
 * handler for peer-disconnects, notifies the client
 * about the aborted operation in case the op was not concluded
 *
 * @param op the destroyed operation
 */
static void
union_peer_disconnect (struct Operation *op)
{
  if (PHASE_FINISHED != op->state->phase)
  {
    struct GNUNET_MQ_Envelope *ev;
    struct GNUNET_SET_ResultMessage *msg;

    ev = GNUNET_MQ_msg (msg,
                        GNUNET_MESSAGE_TYPE_SET_RESULT);
    msg->request_id = htonl (op->spec->client_request_id);
    msg->result_status = htons (GNUNET_SET_STATUS_FAILURE);
    msg->element_type = htons (0);
    GNUNET_MQ_send (op->spec->set->client_mq,
                    ev);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "other peer disconnected prematurely\n");
    _GSS_operation_destroy (op,
                            GNUNET_YES);
    return;
  }
  // else: the session has already been concluded
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "other peer disconnected (finished)\n");
  if (GNUNET_NO == op->state->client_done_sent)
    finish_and_destroy (op);
}


/**
 * Get the table with implementing functions for
 * set union.
 *
 * @return the operation specific VTable
 */
const struct SetVT *
_GSS_union_vt ()
{
  static const struct SetVT union_vt = {
    .create = &union_set_create,
    .msg_handler = &union_handle_p2p_message,
    .add = &union_add,
    .remove = &union_remove,
    .destroy_set = &union_set_destroy,
    .evaluate = &union_evaluate,
    .accept = &union_accept,
    .peer_disconnect = &union_peer_disconnect,
    .cancel = &union_op_cancel,
  };

  return &union_vt;
}
