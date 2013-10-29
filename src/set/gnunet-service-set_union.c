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
 * @file set/gnunet-service-set.c
 * @brief two-peer set operations
 * @author Florian Dold
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet-service-set.h"
#include "ibf.h"
#include "strata_estimator.h"
#include "set_protocol.h"
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
   * We sent the strata estimator, and expect an IBF
   */
  PHASE_EXPECT_IBF,
  /**
   * We know what type of IBF the other peer wants to send us,
   * and expect the remaining parts
   */
  PHASE_EXPECT_IBF_CONT,
  /**
   * We are sending request and elements,
   * and thus only expect elements from the other peer.
   */
  PHASE_EXPECT_ELEMENTS,
  /**
   * We are expecting elements and requests, and send
   * requested elements back to the other peer.
   */
  PHASE_EXPECT_ELEMENTS_AND_REQUESTS,
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
   * Number of ibf buckets received
   */
  unsigned int ibf_buckets_received;

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
   * Current state of the operation.
   */
  enum UnionOperationPhase phase;

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
 * The key entry is used to associate an ibf key with
 * an element.
 */
struct KeyEntry
{
  /**
   * IBF key for the entry, derived from the current salt.
   */
  struct IBF_Key ibf_key;

  /**
   * The actual element associated with the key
   */
  struct ElementEntry *element;

  /**
   * Element that collides with this element
   * on the ibf key
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
  struct OperationState *eo;
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
 * Iterator over hash map entries.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
static int
destroy_key_to_element_iter (void *cls,
                             uint32_t key,
                             void *value)
{
  struct KeyEntry *k = value;
  /* destroy the linked list of colliding ibf key entries */
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
 * Destroy a union operation, and free all resources
 * associated with it.
 *
 * @param eo the union operation to destroy
 */
static void
union_operation_destroy (struct OperationState *eo)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "destroying union op\n");
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
  if (NULL != eo->remote_ibf)
  {
    ibf_destroy (eo->remote_ibf);
    eo->remote_ibf = NULL;
  }
  if (NULL != eo->local_ibf)
  {
    ibf_destroy (eo->local_ibf);
    eo->local_ibf = NULL;
  }
  if (NULL != eo->se)
  {
    strata_estimator_destroy (eo->se);
    eo->se = NULL;
  }
  if (NULL != eo->key_to_element)
  {
    GNUNET_CONTAINER_multihashmap32_iterate (eo->key_to_element, destroy_key_to_element_iter, NULL);
    GNUNET_CONTAINER_multihashmap32_destroy (eo->key_to_element);
    eo->key_to_element = NULL;
  }
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "destroying union op done\n");

  /* FIXME: do a garbage collection of the set generations */
}


/**
 * Inform the client that the union operation has failed,
 * and proceed to destroy the evaluate operation.
 *
 * @param eo the union operation to fail
 */
static void
fail_union_operation (struct OperationState *eo)
{
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SET_ResultMessage *msg;

  ev = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_SET_RESULT);
  msg->result_status = htons (GNUNET_SET_STATUS_FAILURE);
  msg->request_id = htonl (eo->spec->client_request_id);
  msg->element_type = htons (0);
  GNUNET_MQ_send (eo->spec->set->client_mq, ev);
  union_operation_destroy (eo);
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
get_ibf_key (struct GNUNET_HashCode *src, uint16_t salt)
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
 * Send a request for the evaluate operation to a remote peer
 *
 * @param eo operation with the other peer
 */
static void
send_operation_request (struct OperationState *eo)
{
  struct GNUNET_MQ_Envelope *ev;
  struct OperationRequestMessage *msg;

  ev = GNUNET_MQ_msg_nested_mh (msg, GNUNET_MESSAGE_TYPE_SET_P2P_OPERATION_REQUEST,
                                eo->spec->context_msg);

  if (NULL == ev)
  {
    /* the context message is too large */
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (eo->spec->set->client);
    return;
  }
  msg->operation = htonl (GNUNET_SET_OPERATION_UNION);
  msg->app_id = eo->spec->app_id;
  msg->salt = htonl (eo->spec->salt);
  GNUNET_MQ_send (eo->mq, ev);

  if (NULL != eo->spec->context_msg)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "sent op request with context message\n");
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "sent op request without context message\n");

  if (NULL != eo->spec->context_msg)
  {
    GNUNET_free (eo->spec->context_msg);
    eo->spec->context_msg = NULL;
  }

}


/**
 * Iterator to create the mapping between ibf keys
 * and element entries.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
static int
op_register_element_iterator (void *cls,
                         uint32_t key,
                         void *value)
{
  struct KeyEntry *const new_k = cls;
  struct KeyEntry *old_k = value;

  GNUNET_assert (NULL != old_k);
  do
  {
    if (old_k->ibf_key.key_val == new_k->ibf_key.key_val)
    {
      new_k->next_colliding = old_k->next_colliding;
      old_k->next_colliding = new_k;
      return GNUNET_NO;
    }
    old_k = old_k->next_colliding;
  } while (NULL != old_k);
  return GNUNET_YES;
}


/**
 * Insert an element into the union operation's
 * key-to-element mapping. Takes ownership of 'ee'.
 * Note that this does not insert the element in the set,
 * only in the operation's key-element mapping.
 * This is done to speed up re-tried operations, if some elements
 * were transmitted, and then the IBF fails to decode.
 *
 * @param eo the union operation
 * @param ee the element entry
 */
static void
op_register_element (struct OperationState *eo, struct ElementEntry *ee)
{
  int ret;
  struct IBF_Key ibf_key;
  struct KeyEntry *k;

  ibf_key = get_ibf_key (&ee->element_hash, eo->spec->salt);
  k = GNUNET_new (struct KeyEntry);
  k->element = ee;
  k->ibf_key = ibf_key;
  ret = GNUNET_CONTAINER_multihashmap32_get_multiple (eo->key_to_element,
                                                      (uint32_t) ibf_key.key_val,
                                                      op_register_element_iterator, k);

  /* was the element inserted into a colliding bucket? */
  if (GNUNET_SYSERR == ret)
    return;

  GNUNET_CONTAINER_multihashmap32_put (eo->key_to_element, (uint32_t) ibf_key.key_val, k,
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "inserting %x into ibf\n", ke->ibf_key.key_val);

  ibf_insert (ibf, ke->ibf_key);
  return GNUNET_YES;
}


/**
 * Iterator for initializing the
 * key-to-element mapping of a union operation
 *
 * @param cls the union operation
 * @param key unised
 * @param value the element entry to insert
 *        into the key-to-element mapping
 * @return GNUNET_YES to continue iterating,
 *         GNUNET_NO to stop
 */
static int
init_key_to_element_iterator (void *cls,
                              const struct GNUNET_HashCode *key,
                              void *value)
{
  struct OperationState *eo = cls;
  struct ElementEntry *e = value;

  /* make sure that the element belongs to the set at the time
   * of creating the operation */
  if ( (e->generation_added > eo->generation_created) ||
       ( (GNUNET_YES == e->removed) &&
         (e->generation_removed < eo->generation_created)))
    return GNUNET_YES;

  GNUNET_assert (GNUNET_NO == e->remote);

  op_register_element (eo, e);
  return GNUNET_YES;
}


/**
 * Create an ibf with the operation's elements
 * of the specified size
 *
 * @param eo the union operation
 * @param size size of the ibf to create
 */
static void
prepare_ibf (struct OperationState *eo, uint16_t size)
{
  if (NULL == eo->key_to_element)
  {
    unsigned int len;
    len = GNUNET_CONTAINER_multihashmap_size (eo->set->elements);
    eo->key_to_element = GNUNET_CONTAINER_multihashmap32_create (len + 1);
    GNUNET_CONTAINER_multihashmap_iterate (eo->set->elements,
                                           init_key_to_element_iterator, eo);
  }
  if (NULL != eo->local_ibf)
    ibf_destroy (eo->local_ibf);
  eo->local_ibf = ibf_create (size, SE_IBF_HASH_NUM);
  GNUNET_CONTAINER_multihashmap32_iterate (eo->key_to_element,
                                           prepare_ibf_iterator, eo->local_ibf);
}


/**
 * Send an ibf of appropriate size.
 *
 * @param eo the union operation
 * @param ibf_order order of the ibf to send, size=2^order
 */
static void
send_ibf (struct OperationState *eo, uint16_t ibf_order)
{
  unsigned int buckets_sent = 0;
  struct InvertibleBloomFilter *ibf;

  prepare_ibf (eo, 1<<ibf_order);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "sending ibf of size %u\n", 1<<ibf_order);

  ibf = eo->local_ibf;

  while (buckets_sent < (1 << ibf_order))
  {
    unsigned int buckets_in_message;
    struct GNUNET_MQ_Envelope *ev;
    struct IBFMessage *msg;

    buckets_in_message = (1 << ibf_order) - buckets_sent;
    /* limit to maximum */
    if (buckets_in_message > MAX_BUCKETS_PER_MESSAGE)
      buckets_in_message = MAX_BUCKETS_PER_MESSAGE;

    ev = GNUNET_MQ_msg_extra (msg, buckets_in_message * IBF_BUCKET_SIZE,
                               GNUNET_MESSAGE_TYPE_SET_P2P_IBF);
    msg->reserved = 0;
    msg->order = ibf_order;
    msg->offset = htons (buckets_sent);
    ibf_write_slice (ibf, buckets_sent,
                     buckets_in_message, &msg[1]);
    buckets_sent += buckets_in_message;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ibf chunk size %u, %u/%u sent\n",
                buckets_in_message, buckets_sent, 1<<ibf_order);
    GNUNET_MQ_send (eo->mq, ev);
  }

  eo->phase = PHASE_EXPECT_ELEMENTS_AND_REQUESTS;
}


/**
 * Send a strata estimator to the remote peer.
 *
 * @param eo the union operation with the remote peer
 */
static void
send_strata_estimator (struct OperationState *eo)
{
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_MessageHeader *strata_msg;

  ev = GNUNET_MQ_msg_header_extra (strata_msg,
                                   SE_STRATA_COUNT * IBF_BUCKET_SIZE * SE_IBF_SIZE,
                                   GNUNET_MESSAGE_TYPE_SET_P2P_SE);
  strata_estimator_write (eo->set->state->se, &strata_msg[1]);
  GNUNET_MQ_send (eo->mq, ev);
  eo->phase = PHASE_EXPECT_IBF;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "sent SE, expecting IBF\n");
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
  while ((1<<ibf_order) < (IBF_ALPHA * diff) || (1<<ibf_order) < SE_IBF_HASH_NUM)
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
 */
static void
handle_p2p_strata_estimator (void *cls, const struct GNUNET_MessageHeader *mh)
{
  struct OperationState *eo = cls;
  struct StrataEstimator *remote_se;
  int diff;

  if (eo->phase != PHASE_EXPECT_SE)
  {
    fail_union_operation (eo);
    GNUNET_break (0);
    return;
  }
  remote_se = strata_estimator_create (SE_STRATA_COUNT, SE_IBF_SIZE,
                                       SE_IBF_HASH_NUM);
  strata_estimator_read (&mh[1], remote_se);
  GNUNET_assert (NULL != eo->se);
  diff = strata_estimator_difference (remote_se, eo->se);
  strata_estimator_destroy (remote_se);
  strata_estimator_destroy (eo->se);
  eo->se = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "got se diff=%d, using ibf size %d\n",
              diff, 1<<get_order_from_difference (diff));
  send_ibf (eo, get_order_from_difference (diff));
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
  struct OperationState *eo = sec->eo;
  struct KeyEntry *ke = value;

  if (ke->ibf_key.key_val != ibf_key.key_val)
    return GNUNET_YES;
  while (NULL != ke)
  {
    const struct GNUNET_SET_Element *const element = &ke->element->element;
    struct GNUNET_MQ_Envelope *ev;
    struct GNUNET_MessageHeader *mh;

    GNUNET_assert (ke->ibf_key.key_val == ibf_key.key_val);
    ev = GNUNET_MQ_msg_header_extra (mh, element->size, GNUNET_MESSAGE_TYPE_SET_P2P_ELEMENTS);
    if (NULL == ev)
    {
      /* element too large */
      GNUNET_break (0);
      continue;
    }
    memcpy (&mh[1], element->data, element->size);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "sending element (%s) to peer\n",
                GNUNET_h2s (&ke->element->element_hash));
    GNUNET_MQ_send (eo->mq, ev);
    ke = ke->next_colliding;
  }
  return GNUNET_NO;
}

/**
 * Send all elements that have the specified IBF key
 * to the remote peer of the union operation
 *
 * @param eo union operation
 * @param ibf_key IBF key of interest
 */
static void
send_elements_for_key (struct OperationState *eo, struct IBF_Key ibf_key)
{
  struct SendElementClosure send_cls;

  send_cls.ibf_key = ibf_key;
  send_cls.eo = eo;
  GNUNET_CONTAINER_multihashmap32_get_multiple (eo->key_to_element, (uint32_t) ibf_key.key_val,
                                                &send_element_iterator, &send_cls);
}


/**
 * Decode which elements are missing on each side, and
 * send the appropriate elemens and requests
 *
 * @param eo union operation
 */
static void
decode_and_send (struct OperationState *eo)
{
  struct IBF_Key key;
  struct IBF_Key last_key;
  int side;
  unsigned int num_decoded;
  struct InvertibleBloomFilter *diff_ibf;

  GNUNET_assert (PHASE_EXPECT_ELEMENTS == eo->phase);

  prepare_ibf (eo, eo->remote_ibf->size);
  diff_ibf = ibf_dup (eo->local_ibf);
  ibf_subtract (diff_ibf, eo->remote_ibf);

  ibf_destroy (eo->remote_ibf);
  eo->remote_ibf = NULL;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "decoding IBF (size=%u)\n", diff_ibf->size);

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
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "decoded ibf key %lx\n",
                  key.key_val);
      num_decoded += 1;
      if (num_decoded > diff_ibf->size || (num_decoded > 1 && last_key.key_val == key.key_val))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "detected cyclic ibf (decoded %u/%u)\n",
                    num_decoded, diff_ibf->size);
        cycle_detected = GNUNET_YES;
      }
    }
    if ((GNUNET_SYSERR == res) || (GNUNET_YES == cycle_detected))
    {
      int next_order;
      next_order = 0;
      while (1<<next_order < diff_ibf->size)
        next_order++;
      next_order++;
      if (next_order <= MAX_IBF_ORDER)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		    "decoding failed, sending larger ibf (size %u)\n",
                    1<<next_order);
        send_ibf (eo, next_order);
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

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "transmitted all values, sending DONE\n");
      ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_SET_P2P_DONE);
      GNUNET_MQ_send (eo->mq, ev);
      break;
    }
    if (1 == side)
    {
      send_elements_for_key (eo, key);
    }
    else if (-1 == side)
    {
      struct GNUNET_MQ_Envelope *ev;
      struct GNUNET_MessageHeader *msg;

      /* FIXME: before sending the request, check if we may just have the element */
      /* FIXME: merge multiple requests */
      /* FIXME: remember somewhere that we already requested the element,
       * so that we don't request it again with the next ibf if decoding fails */
      ev = GNUNET_MQ_msg_header_extra (msg, sizeof (struct IBF_Key),
                                        GNUNET_MESSAGE_TYPE_SET_P2P_ELEMENT_REQUESTS);

      *(struct IBF_Key *) &msg[1] = key;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "sending element request\n");
      GNUNET_MQ_send (eo->mq, ev);
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
 */
static void
handle_p2p_ibf (void *cls, const struct GNUNET_MessageHeader *mh)
{
  struct OperationState *eo = cls;
  struct IBFMessage *msg = (struct IBFMessage *) mh;
  unsigned int buckets_in_message;

  if ( (eo->phase == PHASE_EXPECT_ELEMENTS_AND_REQUESTS) ||
       (eo->phase == PHASE_EXPECT_IBF) )
  {
    eo->phase = PHASE_EXPECT_IBF_CONT;
    GNUNET_assert (NULL == eo->remote_ibf);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "creating new ibf of size %u\n", 1<<msg->order);
    eo->remote_ibf = ibf_create (1<<msg->order, SE_IBF_HASH_NUM);
    eo->ibf_buckets_received = 0;
    if (0 != ntohs (msg->offset))
    {
      GNUNET_break (0);
      fail_union_operation (eo);
      return;
    }
  }
  else if (eo->phase == PHASE_EXPECT_IBF_CONT)
  {
    if ( (ntohs (msg->offset) != eo->ibf_buckets_received) ||
         (1<<msg->order != eo->remote_ibf->size) )
    {
      GNUNET_break (0);
      fail_union_operation (eo);
      return;
    }
  }

  buckets_in_message = (ntohs (msg->header.size) - sizeof *msg) / IBF_BUCKET_SIZE;

  if (0 == buckets_in_message)
  {
    GNUNET_break_op (0);
    fail_union_operation (eo);
    return;
  }

  if ((ntohs (msg->header.size) - sizeof *msg) != buckets_in_message * IBF_BUCKET_SIZE)
  {
    GNUNET_break (0);
    fail_union_operation (eo);
    return;
  }

  ibf_read_slice (&msg[1], eo->ibf_buckets_received, buckets_in_message, eo->remote_ibf);
  eo->ibf_buckets_received += buckets_in_message;

  if (eo->ibf_buckets_received == eo->remote_ibf->size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "received full ibf\n");
    eo->phase = PHASE_EXPECT_ELEMENTS;
    decode_and_send (eo);
  }
}


/**
 * Send a result message to the client indicating
 * that there is a new element.
 *
 * @param eo union operation
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
 * @param eo union operation
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

  union_operation_destroy (eo);
}


/**
 * Handle an element message from a remote peer.
 *
 * @param cls the union operation
 * @param mh the message
 */
static void
handle_p2p_elements (void *cls, const struct GNUNET_MessageHeader *mh)
{
  struct OperationState *eo = cls;
  struct ElementEntry *ee;
  uint16_t element_size;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "got element from peer\n");

  if ( (eo->phase != PHASE_EXPECT_ELEMENTS) &&
       (eo->phase != PHASE_EXPECT_ELEMENTS_AND_REQUESTS) )
  {
    fail_union_operation (eo);
    GNUNET_break (0);
    return;
  }
  element_size = ntohs (mh->size) - sizeof (struct GNUNET_MessageHeader);
  ee = GNUNET_malloc (sizeof *ee + element_size);
  memcpy (&ee[1], &mh[1], element_size);
  ee->element.size = element_size;
  ee->element.data = &ee[1];
  ee->remote = GNUNET_YES;
  GNUNET_CRYPTO_hash (ee->element.data, ee->element.size, &ee->element_hash);

  /* FIXME: see if the element has already been inserted! */

  op_register_element (eo, ee);
  /* only send results immediately if the client wants it */
  if (GNUNET_SET_RESULT_ADDED == eo->spec->result_mode)
    send_client_element (eo, &ee->element);
}


/**
 * Handle an element request from a remote peer.
 *
 * @param cls the union operation
 * @param mh the message
 */
static void
handle_p2p_element_requests (void *cls, const struct GNUNET_MessageHeader *mh)
{
  struct OperationState *eo = cls;
  struct IBF_Key *ibf_key;
  unsigned int num_keys;

  /* look up elements and send them */
  if (eo->phase != PHASE_EXPECT_ELEMENTS_AND_REQUESTS)
  {
    GNUNET_break (0);
    fail_union_operation (eo);
    return;
  }

  num_keys = (ntohs (mh->size) - sizeof *mh) / sizeof (struct IBF_Key);

  if ((ntohs (mh->size) - sizeof *mh) != num_keys * sizeof (struct IBF_Key))
  {
    GNUNET_break (0);
    fail_union_operation (eo);
    return;
  }

  ibf_key = (struct IBF_Key *) &mh[1];
  while (0 != num_keys--)
  {
    send_elements_for_key (eo, *ibf_key);
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
  fail_union_operation (eo);
}


/**
 * Evaluate a union operation with
 * a remote peer.
 *
 * @param spec specification of the operation the evaluate
 * @param tunnel tunnel already connected to the partner peer
 * @param tc tunnel context, passed here so all new incoming
 *        messages are directly going to the union operations
 * @return a handle to the operation
 */
static void
union_evaluate (struct OperationSpecification *spec,
                struct GNUNET_MESH_Tunnel *tunnel,
                struct TunnelContext *tc)
{
  struct OperationState *eo;

  eo = GNUNET_new (struct OperationState);
  tc->vt = _GSS_union_vt ();
  tc->op = eo;
  eo->se = strata_estimator_dup (spec->set->state->se);
  eo->generation_created = spec->set->current_generation++;
  eo->set = spec->set;
  eo->spec = spec;
  eo->tunnel = tunnel;
  eo->tunnel = tunnel;
  eo->mq = GNUNET_MESH_mq_create (tunnel);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "evaluating union operation, (app %s)\n",
              GNUNET_h2s (&eo->spec->app_id));

  /* we started the operation, thus we have to send the operation request */
  eo->phase = PHASE_EXPECT_SE;

  GNUNET_CONTAINER_DLL_insert (eo->set->state->ops_head,
                               eo->set->state->ops_tail,
                               eo);

  send_operation_request (eo);
}


/**
 * Accept an union operation request from a remote peer
 *
 * @param spec all necessary information about the operation
 * @param tunnel open tunnel to the partner's peer
 * @param tc tunnel context, passed here so all new incoming
 *        messages are directly going to the union operations
 * @return operation
 */
static void
union_accept (struct OperationSpecification *spec,
              struct GNUNET_MESH_Tunnel *tunnel,
              struct TunnelContext *tc)
{
  struct OperationState *eo;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "accepting set union operation\n");

  eo = GNUNET_new (struct OperationState);
  tc->vt = _GSS_union_vt ();
  tc->op = eo;
  eo->set = spec->set;
  eo->generation_created = eo->set->current_generation++;
  eo->spec = spec;
  eo->tunnel = tunnel;
  eo->mq = GNUNET_MESH_mq_create (tunnel);
  eo->se = strata_estimator_dup (eo->set->state->se);
  /* transfer ownership of mq and socket from incoming to eo */
  GNUNET_CONTAINER_DLL_insert (eo->set->state->ops_head,
                               eo->set->state->ops_tail,
                               eo);
  /* kick off the operation */
  send_strata_estimator (eo);
}


/**
 * Create a new set supporting the union operation
 *
 * @return the newly created set
 */
static struct SetState *
union_set_create (void)
{
  struct SetState *set_state;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "union set created\n");

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
  strata_estimator_insert (set_state->se, get_ibf_key (&ee->element_hash, 0));
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
  strata_estimator_remove (set_state->se, get_ibf_key (&ee->element_hash, 0));
}


/**
 * Destroy a set that supports the union operation
 *
 * @param set_state the set to destroy
 */
static void
union_set_destroy (struct SetState *set_state)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "destroying union set\n");
  /* important to destroy operations before the rest of the set */
  while (NULL != set_state->ops_head)
    union_operation_destroy (set_state->ops_head);
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
 * @param eo the state of the union evaluate operation
 * @param mh the received message
 * @return GNUNET_SYSERR if the tunnel should be disconnected,
 *         GNUNET_OK otherwise
 */
int
union_handle_p2p_message (struct OperationState *eo,
                          const struct GNUNET_MessageHeader *mh)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "received p2p message (t: %u, s: %u)\n",
              ntohs (mh->type), ntohs (mh->size));
  switch (ntohs (mh->type))
  {
    case GNUNET_MESSAGE_TYPE_SET_P2P_IBF:
      handle_p2p_ibf (eo, mh);
      break;
    case GNUNET_MESSAGE_TYPE_SET_P2P_SE:
      handle_p2p_strata_estimator (eo, mh);
      break;
    case GNUNET_MESSAGE_TYPE_SET_P2P_ELEMENTS:
      handle_p2p_elements (eo, mh);
      break;
    case GNUNET_MESSAGE_TYPE_SET_P2P_ELEMENT_REQUESTS:
      handle_p2p_element_requests (eo, mh);
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


static void
union_peer_disconnect (struct OperationState *op)
{
  /* Are we already disconnected? */
  if (NULL == op->tunnel)
    return;
  op->tunnel = NULL;
  if (NULL != op->mq)
  {
    GNUNET_MQ_destroy (op->mq);
    op->mq = NULL;
  }
  if (PHASE_FINISHED != op->phase)
  {
    struct GNUNET_MQ_Envelope *ev;
    struct GNUNET_SET_ResultMessage *msg;

    ev = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_SET_RESULT);
    msg->request_id = htonl (op->spec->client_request_id);
    msg->result_status = htons (GNUNET_SET_STATUS_FAILURE);
    msg->element_type = htons (0);
    GNUNET_MQ_send (op->spec->set->client_mq, ev);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "other peer disconnected prematurely\n");
    union_operation_destroy (op);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "other peer disconnected (finished)\n");
  if (GNUNET_NO == op->client_done_sent)
    send_client_done_and_destroy (op);
}


static void
union_op_cancel (struct SetState *set_state, uint32_t op_id)
{
  struct OperationState *op_state; 
  int found = GNUNET_NO;
  for (op_state = set_state->ops_head; NULL != op_state; op_state = op_state->next)
  {
    if (op_state->spec->client_request_id == op_id)
    {
      found = GNUNET_YES;
      break;
    }
  }
  if (GNUNET_NO == found)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "canceling non-existing operation\n");
    return;
  }
  union_operation_destroy (op_state);
}


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
