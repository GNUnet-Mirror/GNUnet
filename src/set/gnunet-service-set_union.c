/*
      This file is part of GNUnet
      Copyright (C) 2013-2015 Christian Grothoff (and other contributing authors)

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


#define LOG(kind,...) GNUNET_log_from (kind, "set-union",__VA_ARGS__)


/**
 * Number of IBFs in a strata estimator.
 */
#define SE_STRATA_COUNT 32
/**
 * Size of the IBFs in the strata estimator.
 */
#define SE_IBF_SIZE 80
/**
 * The hash num parameter for the difference digests and strata estimators.
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
   * We sent the request message, and expect a strata estimator.
   */
  PHASE_EXPECT_SE,

  /**
   * We sent the strata estimator, and expect an IBF. This phase is entered once
   * upon initialization and later via #PHASE_EXPECT_ELEMENTS_AND_REQUESTS.
   *
   * XXX: could use better wording.
   *
   * After receiving the complete IBF, we enter #PHASE_EXPECT_ELEMENTS
   */
  PHASE_EXPECT_IBF,

  /**
   * Continuation for multi part IBFs.
   */
  PHASE_EXPECT_IBF_CONT,

  /**
   * We are decoding an IBF.
   */
  PHASE_INVENTORY_ACTIVE,

  /**
   * The other peer is decoding the IBF we just sent.
   */
  PHASE_INVENTORY_PASSIVE,

  /**
   * The protocol is almost finished, but we still have to flush our message
   * queue and/or expect some elements.
   */
  PHASE_FINISH_CLOSING,

  /**
   * In the penultimate phase,
   * we wait until all our demands
   * are satisfied.  Then we send a done
   * message, and wait for another done message.*/
  PHASE_FINISH_WAITING,

  /**
   * In the ultimate phase, we wait until
   * our demands are satisfied and then
   * quit (sending another DONE message). */
  PHASE_DONE,
};


/**
 * State of an evaluate operation with another peer.
 */
struct OperationState
{
  /**
   * Copy of the set's strata estimator at the time of
   * creation of this operation.
   */
  struct StrataEstimator *se;

  /**
   * The IBF we currently receive.
   */
  struct InvertibleBloomFilter *remote_ibf;

  /**
   * The IBF with the local set's element.
   */
  struct InvertibleBloomFilter *local_ibf;

  /**
   * Maps IBF-Keys (specific to the current salt) to elements.
   * Used as a multihashmap, the keys being the lower 32bit of the IBF-Key.
   * Colliding IBF-Keys are linked.
   */
  struct GNUNET_CONTAINER_MultiHashMap32 *key_to_element;

  /**
   * Current state of the operation.
   */
  enum UnionOperationPhase phase;

  /**
   * Did we send the client that we are done?
   */
  int client_done_sent;

  /**
   * Number of ibf buckets already received into the @a remote_ibf.
   */
  unsigned int ibf_buckets_received;

  /**
   * Hashes for elements that we have demanded from the other peer.
   */
  struct GNUNET_CONTAINER_MultiHashMap *demanded_hashes;
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
   *
   * Only owned by the union operation if element->operation
   * is #GNUNET_YES.
   */
  struct ElementEntry *element;
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

  GNUNET_assert (NULL != k);
  if (GNUNET_YES == k->element->remote)
  {
    GNUNET_free (k->element);
    k->element = NULL;
  }
  GNUNET_free (k);
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
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "destroying union op\n");
  /* check if the op was canceled twice */
  GNUNET_assert (NULL != op->state);
  if (NULL != op->state->remote_ibf)
  {
    ibf_destroy (op->state->remote_ibf);
    op->state->remote_ibf = NULL;
  }
  if (NULL != op->state->demanded_hashes)
  {
    GNUNET_CONTAINER_multihashmap_destroy (op->state->demanded_hashes);
    op->state->demanded_hashes = NULL;
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
  LOG (GNUNET_ERROR_TYPE_DEBUG,
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

  LOG (GNUNET_ERROR_TYPE_ERROR,
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

  GNUNET_CRYPTO_kdf (&key, sizeof (key),
                     src, sizeof *src,
                     &salt, sizeof (salt),
                     NULL, 0);
  return key;
}


/**
 * Iterator over the mapping from IBF keys to element entries.  Checks if we
 * have an element with a given GNUNET_HashCode.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES if we should search further,
 *         #GNUNET_NO if we've found the element.
 */
static int
op_has_element_iterator (void *cls,
                         uint32_t key,
                         void *value)
{
  struct GNUNET_HashCode *element_hash = cls;
  struct KeyEntry *k = value;

  GNUNET_assert (NULL != k);
  if (0 == GNUNET_CRYPTO_hash_cmp (&k->element->element_hash,
                                   element_hash))
    return GNUNET_NO;
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
 * XXX: clarify ownership, doesn't sound right.
 *
 * @param op the union operation
 * @param ee the element entry
 */
static void
op_register_element (struct Operation *op,
                     struct ElementEntry *ee)
{
  struct IBF_Key ibf_key;
  struct KeyEntry *k;

  ibf_key = get_ibf_key (&ee->element_hash, op->spec->salt);
  k = GNUNET_new (struct KeyEntry);
  k->element = ee;
  k->ibf_key = ibf_key;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap32_put (op->state->key_to_element,
                                                      (uint32_t) ibf_key.key_val,
                                                      k,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
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
  struct Operation *op = cls;
  struct KeyEntry *ke = value;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "[OP %x] inserting %lx (hash %s) into ibf\n",
       (void *) op,
       (unsigned long) ke->ibf_key.key_val,
       GNUNET_h2s (&ke->element->element_hash));
  ibf_insert (op->state->local_ibf, ke->ibf_key);
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
  struct ElementEntry *ee = value;

  /* make sure that the element belongs to the set at the time
   * of creating the operation */
  if (GNUNET_NO == _GSS_is_element_of_operation (ee, op))
    return GNUNET_YES;

  GNUNET_assert (GNUNET_NO == ee->remote);

  op_register_element (op, ee);
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

    len = GNUNET_CONTAINER_multihashmap_size (op->spec->set->content->elements);
    op->state->key_to_element = GNUNET_CONTAINER_multihashmap32_create (len + 1);
    GNUNET_CONTAINER_multihashmap_iterate (op->spec->set->content->elements,
                                           init_key_to_element_iterator, op);
  }
  if (NULL != op->state->local_ibf)
    ibf_destroy (op->state->local_ibf);
  op->state->local_ibf = ibf_create (size, SE_IBF_HASH_NUM);
  GNUNET_CONTAINER_multihashmap32_iterate (op->state->key_to_element,
                                           &prepare_ibf_iterator,
                                           op);
}


/**
 * Send an ibf of appropriate size.
 *
 * Fragments the IBF into multiple messages if necessary.
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

  LOG (GNUNET_ERROR_TYPE_DEBUG,
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
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "ibf chunk size %u, %u/%u sent\n",
         buckets_in_message,
         buckets_sent,
         1<<ibf_order);
    GNUNET_MQ_send (op->mq, ev);
  }

  /* The other peer must decode the IBF, so
   * we're passive. */
  op->state->phase = PHASE_INVENTORY_PASSIVE;
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
  LOG (GNUNET_ERROR_TYPE_DEBUG,
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
  LOG (GNUNET_ERROR_TYPE_DEBUG,
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
send_offers_iterator (void *cls,
                      uint32_t key,
                      void *value)
{
  struct SendElementClosure *sec = cls;
  struct Operation *op = sec->op;
  struct KeyEntry *ke = value;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_MessageHeader *mh;

  /* Detect 32-bit key collision for the 64-bit IBF keys. */
  if (ke->ibf_key.key_val != sec->ibf_key.key_val)
    return GNUNET_YES;

  ev = GNUNET_MQ_msg_header_extra (mh,
                                   sizeof (struct GNUNET_HashCode),
                                   GNUNET_MESSAGE_TYPE_SET_UNION_P2P_OFFER);

  GNUNET_assert (NULL != ev);
  *(struct GNUNET_HashCode *) &mh[1] = ke->element->element_hash;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "[OP %x] sending element offer (%s) to peer\n",
       (void *) op,
       GNUNET_h2s (&ke->element->element_hash));
  GNUNET_MQ_send (op->mq, ev);
  return GNUNET_YES;
}


/**
 * Send offers (in the form of GNUNET_Hash-es) to the remote peer for the given IBF key.
 *
 * @param op union operation
 * @param ibf_key IBF key of interest
 */
static void
send_offers_for_key (struct Operation *op,
                     struct IBF_Key ibf_key)
{
  struct SendElementClosure send_cls;

  send_cls.ibf_key = ibf_key;
  send_cls.op = op;
  (void) GNUNET_CONTAINER_multihashmap32_get_multiple (op->state->key_to_element,
                                                       (uint32_t) ibf_key.key_val,
                                                       &send_offers_iterator,
                                                       &send_cls);
}


/**
 * Decode which elements are missing on each side, and
 * send the appropriate offers and inquiries.
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

  GNUNET_assert (PHASE_INVENTORY_ACTIVE == op->state->phase);

  prepare_ibf (op, op->state->remote_ibf->size);
  diff_ibf = ibf_dup (op->state->local_ibf);
  ibf_subtract (diff_ibf, op->state->remote_ibf);

  ibf_destroy (op->state->remote_ibf);
  op->state->remote_ibf = NULL;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
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
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "decoded ibf key %lx\n",
           (unsigned long) key.key_val);
      num_decoded += 1;
      if ( (num_decoded > diff_ibf->size) ||
           (num_decoded > 1 && last_key.key_val == key.key_val) )
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG,
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
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "decoding failed, sending larger ibf (size %u)\n",
             1<<next_order);
        send_ibf (op, next_order);
      }
      else
      {
        // XXX: Send the whole set, element-by-element
        LOG (GNUNET_ERROR_TYPE_ERROR,
             "set union failed: reached ibf limit\n");
      }
      break;
    }
    if (GNUNET_NO == res)
    {
      struct GNUNET_MQ_Envelope *ev;

      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "transmitted all values, sending DONE\n");
      ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_SET_UNION_P2P_DONE);
      GNUNET_MQ_send (op->mq, ev);
      /* We now wait until we get a DONE message back
       * and then wait for our MQ to be flushed and all our
       * demands be delivered. */
      break;
    }
    if (1 == side)
    {
      send_offers_for_key (op, key);
    }
    else if (-1 == side)
    {
      struct GNUNET_MQ_Envelope *ev;
      struct GNUNET_MessageHeader *msg;

      /* It may be nice to merge multiple requests, but with CADET's corking it is not worth
       * the effort additional complexity. */
      ev = GNUNET_MQ_msg_header_extra (msg,
                                       sizeof (struct IBF_Key),
                                       GNUNET_MESSAGE_TYPE_SET_UNION_P2P_INQUIRY);

      memcpy (&msg[1],
              &key,
              sizeof (struct IBF_Key));
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "sending element inquiry for IBF key %lx\n",
           (unsigned long) key.key_val);
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
 * Reassemble the IBF from multiple pieces, and
 * process the whole IBF once possible.
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
  if ( (op->state->phase == PHASE_INVENTORY_PASSIVE) ||
       (op->state->phase == PHASE_EXPECT_IBF) )
  {
    op->state->phase = PHASE_EXPECT_IBF_CONT;
    GNUNET_assert (NULL == op->state->remote_ibf);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
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
  else
  {
    GNUNET_assert (0);
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

  GNUNET_assert (NULL != op->state->remote_ibf);

  ibf_read_slice (&msg[1],
                  op->state->ibf_buckets_received,
                  buckets_in_message,
                  op->state->remote_ibf);
  op->state->ibf_buckets_received += buckets_in_message;

  if (op->state->ibf_buckets_received == op->state->remote_ibf->size)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "received full ibf\n");
    op->state->phase = PHASE_INVENTORY_ACTIVE;
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
 * @param status status to send with the new element
 */
static void
send_client_element (struct Operation *op,
                     struct GNUNET_SET_Element *element,
                     int status)
{
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SET_ResultMessage *rm;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
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
  rm->result_status = htons (status);
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
  /* Will also call the union-specific cancel function. */
  _GSS_operation_destroy (op, GNUNET_YES);
}


static void
maybe_finish (struct Operation *op)
{
  unsigned int num_demanded;

  num_demanded = GNUNET_CONTAINER_multihashmap_size (op->state->demanded_hashes);

  if (PHASE_FINISH_WAITING == op->state->phase)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "In PHASE_FINISH_WAITING, pending %u demands\n",
         num_demanded);
    if (0 == num_demanded)
    {
      struct GNUNET_MQ_Envelope *ev;

      op->state->phase = PHASE_DONE;
      ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_SET_UNION_P2P_DONE);
      GNUNET_MQ_send (op->mq, ev);

      /* We now wait until the other peer closes the channel
       * after it got all elements from us. */
    }
  }
  if (PHASE_FINISH_CLOSING == op->state->phase)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "In PHASE_FINISH_CLOSING, pending %u demands\n",
         num_demanded);
    if (0 == num_demanded)
    {
      op->state->phase = PHASE_DONE;
      send_done_and_destroy (op);
    }
  }
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
  const struct GNUNET_SET_ElementMessage *emsg;
  uint16_t element_size;

  if (0 == GNUNET_CONTAINER_multihashmap_size (op->state->demanded_hashes))
  {
    GNUNET_break_op (0);
    fail_union_operation (op);
    return;
  }

  if (ntohs (mh->size) < sizeof (struct GNUNET_SET_ElementMessage))
  {
    GNUNET_break_op (0);
    fail_union_operation (op);
    return;
  }

  emsg = (struct GNUNET_SET_ElementMessage *) mh;

  element_size = ntohs (mh->size) - sizeof (struct GNUNET_SET_ElementMessage);
  ee = GNUNET_malloc (sizeof (struct ElementEntry) + element_size);
  memcpy (&ee[1], &emsg[1], element_size);
  ee->element.size = element_size;
  ee->element.data = &ee[1];
  ee->element.element_type = ntohs (emsg->element_type);
  ee->remote = GNUNET_YES;
  GNUNET_CRYPTO_hash (ee->element.data,
                      ee->element.size,
                      &ee->element_hash);

  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_remove (op->state->demanded_hashes, &ee->element_hash, NULL))
  {
    /* We got something we didn't demand, since it's not in our map. */
    GNUNET_break_op (0);
    GNUNET_free (ee);
    fail_union_operation (op);
    return;
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Got element (size %u, hash %s) from peer\n",
       (unsigned int) element_size,
       GNUNET_h2s (&ee->element_hash));

  if (GNUNET_YES == op_has_element (op, &ee->element_hash))
  {
    /* Got repeated element.  Should not happen since
     * we track demands. */
    GNUNET_break (0);
    GNUNET_free (ee);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Registering new element from remote peer\n");
    op_register_element (op, ee);
    /* only send results immediately if the client wants it */
    switch (op->spec->result_mode)
    {
      case GNUNET_SET_RESULT_ADDED:
        send_client_element (op, &ee->element, GNUNET_SET_STATUS_OK);
        break;
      case GNUNET_SET_RESULT_SYMMETRIC:
        send_client_element (op, &ee->element, GNUNET_SET_STATUS_ADD_LOCAL);
        break;
      default:
        /* Result mode not supported, should have been caught earlier. */
        GNUNET_break (0);
        break;
    }
  }

  maybe_finish (op);
}


/**
 * Send offers (for GNUNET_Hash-es) in response
 * to inquiries (for IBF_Key-s).
 *
 * @param cls the union operation
 * @param mh the message
 */
static void
handle_p2p_inquiry (void *cls,
                    const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;
  const struct IBF_Key *ibf_key;
  unsigned int num_keys;

  /* look up elements and send them */
  if (op->state->phase != PHASE_INVENTORY_PASSIVE)
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
    send_offers_for_key (op, *ibf_key);
    ibf_key++;
  }
}



static void
handle_p2p_demand (void *cls,
                    const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;
  struct ElementEntry *ee;
  struct GNUNET_SET_ElementMessage *emsg;
  const struct GNUNET_HashCode *hash;
  unsigned int num_hashes;
  struct GNUNET_MQ_Envelope *ev;

  num_hashes = (ntohs (mh->size) - sizeof (struct GNUNET_MessageHeader))
    / sizeof (struct GNUNET_HashCode);
  if ((ntohs (mh->size) - sizeof (struct GNUNET_MessageHeader))
      != num_hashes * sizeof (struct GNUNET_HashCode))
  {
    GNUNET_break_op (0);
    fail_union_operation (op);
    return;
  }

  for (hash = (const struct GNUNET_HashCode *) &mh[1];
       num_hashes > 0;
       hash++, num_hashes--)
  {
    ee = GNUNET_CONTAINER_multihashmap_get (op->spec->set->content->elements, hash);
    if (NULL == ee)
    {
      /* Demand for non-existing element. */
      GNUNET_break_op (0);
      fail_union_operation (op);
      return;
    }
    if (GNUNET_NO == _GSS_is_element_of_operation (ee, op))
    {
      /* Probably confused lazily copied sets. */
      GNUNET_break_op (0);
      fail_union_operation (op);
      return;
    }
    ev = GNUNET_MQ_msg_extra (emsg, ee->element.size, GNUNET_MESSAGE_TYPE_SET_P2P_ELEMENTS);
    memcpy (&emsg[1], ee->element.data, ee->element.size);
    emsg->reserved = htons (0);
    emsg->element_type = htons (ee->element.element_type);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "[OP %x] Sending demanded element (size %u, hash %s) to peer\n",
         (void *) op,
         (unsigned int) ee->element.size,
         GNUNET_h2s (&ee->element_hash));
    GNUNET_MQ_send (op->mq, ev);

    switch (op->spec->result_mode)
    {
      case GNUNET_SET_RESULT_ADDED:
        /* Nothing to do. */
        break;
      case GNUNET_SET_RESULT_SYMMETRIC:
        send_client_element (op, &ee->element, GNUNET_SET_STATUS_ADD_REMOTE);
        break;
      default:
        /* Result mode not supported, should have been caught earlier. */
        GNUNET_break (0);
        break;
    }
  }
}


/**
 * Handle offers (of GNUNET_HashCode-s) and
 * respond with demands (of GNUNET_HashCode-s).
 *
 * @param cls the union operation
 * @param mh the message
 */
static void
handle_p2p_offer (void *cls,
                    const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;
  const struct GNUNET_HashCode *hash;
  unsigned int num_hashes;

  /* look up elements and send them */
  if ( (op->state->phase != PHASE_INVENTORY_PASSIVE) &&
       (op->state->phase != PHASE_INVENTORY_ACTIVE))
  {
    GNUNET_break_op (0);
    fail_union_operation (op);
    return;
  }
  num_hashes = (ntohs (mh->size) - sizeof (struct GNUNET_MessageHeader))
    / sizeof (struct GNUNET_HashCode);
  if ((ntohs (mh->size) - sizeof (struct GNUNET_MessageHeader))
      != num_hashes * sizeof (struct GNUNET_HashCode))
  {
    GNUNET_break_op (0);
    fail_union_operation (op);
    return;
  }

  for (hash = (const struct GNUNET_HashCode *) &mh[1];
       num_hashes > 0;
       hash++, num_hashes--)
  {
    struct ElementEntry *ee;
    struct GNUNET_MessageHeader *demands;
    struct GNUNET_MQ_Envelope *ev;
    ee = GNUNET_CONTAINER_multihashmap_get (op->spec->set->content->elements, hash);
    if (NULL != ee)
      if (GNUNET_YES == _GSS_is_element_of_operation (ee, op))
        continue;

    if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (op->state->demanded_hashes, hash))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Skipped sending duplicate demand\n");
      continue;
    }

    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multihashmap_put (op->state->demanded_hashes,
                                                      hash,
                                                      NULL,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST));

    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "[OP %x] Requesting element (hash %s)\n",
         (void *) op, GNUNET_h2s (hash));
    ev = GNUNET_MQ_msg_header_extra (demands, sizeof (struct GNUNET_HashCode), GNUNET_MESSAGE_TYPE_SET_UNION_P2P_DEMAND);
    *(struct GNUNET_HashCode *) &demands[1] = *hash;
    GNUNET_MQ_send (op->mq, ev);
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

  if (op->state->phase == PHASE_INVENTORY_PASSIVE)
  {
    /* We got all requests, but still have to send our elements in response. */

    op->state->phase = PHASE_FINISH_WAITING;

    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "got DONE (as passive partner), waiting for our demands to be satisfied\n");
    /* The active peer is done sending offers
     * and inquiries.  This means that all
     * our responses to that (demands and offers)
     * must be in flight (queued or in mesh).
     *
     * We should notify the active peer once
     * all our demands are satisfied, so that the active
     * peer can quit if we gave him everything.
     */
    maybe_finish (op);
    return;
  }
  if (op->state->phase == PHASE_INVENTORY_ACTIVE)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "got DONE (as active partner), waiting to finish\n");
    /* All demands of the other peer are satisfied,
     * and we processed all offers, thus we know
     * exactly what our demands must be.
     *
     * We'll close the channel
     * to the other peer once our demands are met.
     */
    op->state->phase = PHASE_FINISH_CLOSING;
    maybe_finish (op);
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

  GNUNET_assert (NULL == op->state);
  op->state = GNUNET_new (struct OperationState);
  op->state->demanded_hashes = GNUNET_CONTAINER_multihashmap_create (32, GNUNET_NO);
  /* copy the current generation's strata estimator for this operation */
  op->state->se = strata_estimator_dup (op->spec->set->state->se);
  /* we started the operation, thus we have to send the operation request */
  op->state->phase = PHASE_EXPECT_SE;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
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
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "sent op request with context message\n");
  else
    LOG (GNUNET_ERROR_TYPE_DEBUG,
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
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "accepting set union operation\n");
  GNUNET_assert (NULL == op->state);
  op->state = GNUNET_new (struct OperationState);
  op->state->se = strata_estimator_dup (op->spec->set->state->se);
  op->state->demanded_hashes = GNUNET_CONTAINER_multihashmap_create (32, GNUNET_NO);
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

  LOG (GNUNET_ERROR_TYPE_DEBUG,
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
  //LOG (GNUNET_ERROR_TYPE_DEBUG,
  //            "received p2p message (t: %u, s: %u)\n",
  //            ntohs (mh->type),
  //            ntohs (mh->size));
  switch (ntohs (mh->type))
  {
    case GNUNET_MESSAGE_TYPE_SET_UNION_P2P_IBF:
      return handle_p2p_ibf (op, mh);
    case GNUNET_MESSAGE_TYPE_SET_UNION_P2P_SE:
      return handle_p2p_strata_estimator (op, mh);
    case GNUNET_MESSAGE_TYPE_SET_P2P_ELEMENTS:
      handle_p2p_elements (op, mh);
      break;
    case GNUNET_MESSAGE_TYPE_SET_UNION_P2P_INQUIRY:
      handle_p2p_inquiry (op, mh);
      break;
    case GNUNET_MESSAGE_TYPE_SET_UNION_P2P_DONE:
      handle_p2p_done (op, mh);
      break;
    case GNUNET_MESSAGE_TYPE_SET_UNION_P2P_OFFER:
      handle_p2p_offer (op, mh);
      break;
    case GNUNET_MESSAGE_TYPE_SET_UNION_P2P_DEMAND:
      handle_p2p_demand (op, mh);
      break;
    default:
      /* Something wrong with cadet's message handlers? */
      GNUNET_assert (0);
  }
  return GNUNET_OK;
}


/**
 * Handler for peer-disconnects, notifies the client
 * about the aborted operation in case the op was not concluded.
 *
 * @param op the destroyed operation
 */
static void
union_peer_disconnect (struct Operation *op)
{
  if (PHASE_DONE != op->state->phase)
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
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "other peer disconnected prematurely, phase %u\n",
         op->state->phase);
    _GSS_operation_destroy (op,
                            GNUNET_YES);
    return;
  }
  // else: the session has already been concluded
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "other peer disconnected (finished)\n");
  if (GNUNET_NO == op->state->client_done_sent)
    send_done_and_destroy (op);
}


/**
 * Copy union-specific set state.
 *
 * @param set source set for copying the union state
 * @return a copy of the union-specific set state
 */
static struct SetState *
union_copy_state (struct Set *set)
{
  struct SetState *new_state;

  new_state = GNUNET_new (struct SetState);
  GNUNET_assert ( (NULL != set->state) && (NULL != set->state->se) );
  new_state->se = strata_estimator_dup (set->state->se);

  return new_state;
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
    .copy_state = &union_copy_state,
  };

  return &union_vt;
}
