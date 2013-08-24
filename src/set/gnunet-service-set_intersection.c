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
 * @author Christian M. Fuchs
 */


#include "gnunet-service-set.h"
#include "gnunet_container_lib.h"
#include "gnunet_crypto_lib.h"
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
#define SE_IBF_HASH_NUM 3

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
 * Current phase we are in for a union operation
 */
enum IntersectionOperationPhase
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
struct IntersectionEvaluateOperation
{
  /**
   * Local set the operation is evaluated on.
   */
  struct Set *set;

  /**
   * Peer with the remote set
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Application-specific identifier
   */
  struct GNUNET_HashCode app_id;

  /**
   * Context message, given to us
   * by the client, may be NULL.
   */
  struct GNUNET_MessageHeader *context_msg;

  /**
   * Tunnel to the other peer.
   */
  struct GNUNET_MESH_Tunnel *tunnel;

  /**
   * Request ID to multiplex set operations to
   * the client inhabiting the set.
   */
  uint32_t request_id;

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
   */
  struct GNUNET_CONTAINER_MultiHashMap32 *key_to_element;

  /**
   * Current state of the operation.
   */
  enum IntersectionOperationPhase phase;

  /**
   * Salt to use for this operation.
   */
  uint16_t salt;

  /**
   * Generation in which the operation handle
   * was created.
   */
  unsigned int generation_created;
  
  /**
   * Evaluate operations are held in
   * a linked list.
   */
  struct IntersectionEvaluateOperation *next;
  
   /**
   * Evaluate operations are held in
   * a linked list.
   */
  struct IntersectionEvaluateOperation *prev;
};


/**
 * Information about the element in a set.
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
 * Entries in the key-to-element map of the union set.
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
  struct IntersectionEvaluateOperation *eo;
};


/**
 * Extra state required for efficient set union.
 */
struct IntersectionState
{
  /**
   * The strata estimator is only generated once for
   * each set.
   * The IBF keys are derived from the element hashes with
   * salt=0.
   */
  struct StrataEstimator *se;

  /**
   * Maps 'struct GNUNET_HashCode' to 'struct ElementEntry'.
   */
  struct GNUNET_CONTAINER_MultiHashMap *elements;

  /**
   * Evaluate operations are held in
   * a linked list.
   */
  struct IntersectionEvaluateOperation *ops_head;

  /**
   * Evaluate operations are held in
   * a linked list.
   */
  struct IntersectionEvaluateOperation *ops_tail;

  /**
   * Current generation, that is, number of
   * previously executed operations on this set
   */
  unsigned int current_generation;
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
destroy_elements_iterator (void *cls,
                           const struct GNUNET_HashCode * key,
                           void *value)
{
  struct ElementEntry *ee = value;

  GNUNET_free (ee);
  return GNUNET_YES;
}


/**
 * Destroy the elements belonging to a union set.
 *
 * @param us union state that contains the elements
 */
static void
destroy_elements (struct IntersectionState *us)
{
  if (NULL == us->elements)
    return;
  GNUNET_CONTAINER_multihashmap_iterate (us->elements, destroy_elements_iterator, NULL);
  GNUNET_CONTAINER_multihashmap_destroy (us->elements);
  us->elements = NULL;
}



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
  
  while (NULL != k)
  {
    struct KeyEntry *k_tmp = k;
    k = k->next_colliding;
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
void
_GSS_union_operation_destroy (struct UnionEvaluateOperation *eo)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "destroying union op\n");
  
  if (NULL != eo->tunnel)
  {
    GNUNET_MESH_tunnel_destroy (eo->tunnel);
    /* wait for the final destruction by the tunnel cleaner */
    return;
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

  GNUNET_CONTAINER_DLL_remove (eo->set->state.u->ops_head,
                               eo->set->state.u->ops_tail,
                               eo);
  GNUNET_free (eo);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "destroying union op done\n");

  /* FIXME: do a garbage collection of the set generations */
}


/**
 * Inform the client that the union operation has failed,
 * and proceed to destroy the evaluate operation.
 *
 * @param eo the union operation to fail
 */
static void
fail_union_operation (struct UnionEvaluateOperation *eo)
{
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_SET_ResultMessage *msg;

  mqm = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_SET_RESULT);
  msg->result_status = htons (GNUNET_SET_STATUS_FAILURE);
  msg->request_id = htonl (eo->request_id);
  GNUNET_MQ_send (eo->set->client_mq, mqm);
  _GSS_union_operation_destroy (eo);
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
send_operation_request (struct IntersectionEvaluateOperation *eo)
{
  struct GNUNET_MQ_Envelope *mqm;
  struct OperationRequestMessage *msg;

  mqm = GNUNET_MQ_msg_nested_mh (msg, GNUNET_MESSAGE_TYPE_SET_P2P_OPERATION_REQUEST, eo->context_msg);

  if (NULL == mqm)
  {
    /* the context message is too large */
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (eo->set->client);
    return;
  }
  msg->operation = htons (GNUNET_SET_OPERATION_INTERSECTION);
  msg->app_id = eo->app_id;
  GNUNET_MQ_send (eo->tc->mq, mqm);

  if (NULL != eo->context_msg)
  {
    GNUNET_free (eo->context_msg);
    eo->context_msg = NULL;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "sent op request\n");
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
insert_element_iterator (void *cls,
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
 * key-to-element mapping
 *
 * @param eo the union operation
 * @param ee the element entry
 */
static void
insert_element (struct UnionEvaluateOperation *eo, struct ElementEntry *ee)
{
  int ret;
  struct IBF_Key ibf_key;
  struct KeyEntry *k;

  ibf_key = get_ibf_key (&ee->element_hash, eo->salt);
  k = GNUNET_new (struct KeyEntry);
  k->element = ee;
  k->ibf_key = ibf_key;
  ret = GNUNET_CONTAINER_multihashmap32_get_multiple (eo->key_to_element,
                                                      (uint32_t) ibf_key.key_val,
                                                      insert_element_iterator, k);

  /* was the element inserted into a colliding bucket? */
  if (GNUNET_SYSERR == ret)
    return;

  GNUNET_CONTAINER_multihashmap32_put (eo->key_to_element, (uint32_t) ibf_key.key_val, k,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
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
 */
static int
init_key_to_element_iterator (void *cls,
                              const struct GNUNET_HashCode *key,
                              void *value)
{
  struct UnionEvaluateOperation *eo = cls;
  struct ElementEntry *e = value;

  /* make sure that the element belongs to the set at the time
   * of creating the operation */
  if ( (e->generation_added > eo->generation_created) ||
       ( (GNUNET_YES == e->removed) &&
         (e->generation_removed < eo->generation_created)))
    return GNUNET_YES;

  insert_element (eo, e);
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
prepare_ibf (struct UnionEvaluateOperation *eo, uint16_t size)
{
  if (NULL == eo->key_to_element)
  {
    unsigned int len;
    len = GNUNET_CONTAINER_multihashmap_size (eo->set->state.u->elements);
    eo->key_to_element = GNUNET_CONTAINER_multihashmap32_create (len + 1);
    GNUNET_CONTAINER_multihashmap_iterate (eo->set->state.u->elements,
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
send_ibf (struct UnionEvaluateOperation *eo, uint16_t ibf_order)
{
  unsigned int buckets_sent = 0;
  struct InvertibleBloomFilter *ibf;

  prepare_ibf (eo, 1<<ibf_order);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "sending ibf of size %u\n", 1<<ibf_order);

  ibf = eo->local_ibf;

  while (buckets_sent < (1 << ibf_order))
  {
    unsigned int buckets_in_message;
    struct GNUNET_MQ_Envelope *mqm;
    struct IBFMessage *msg;

    buckets_in_message = (1 << ibf_order) - buckets_sent;
    /* limit to maximum */
    if (buckets_in_message > MAX_BUCKETS_PER_MESSAGE)
      buckets_in_message = MAX_BUCKETS_PER_MESSAGE;

    mqm = GNUNET_MQ_msg_extra (msg, buckets_in_message * IBF_BUCKET_SIZE,
                               GNUNET_MESSAGE_TYPE_SET_P2P_IBF);
    msg->order = ibf_order;
    msg->offset = htons (buckets_sent);
    ibf_write_slice (ibf, buckets_sent,
                     buckets_in_message, &msg[1]);
    buckets_sent += buckets_in_message;
    GNUNET_MQ_send (eo->tc->mq, mqm);
  }

  eo->phase = PHASE_EXPECT_ELEMENTS_AND_REQUESTS;
}


/**
 * Send a strata estimator to the remote peer.
 *
 * @param eo the union operation with the remote peer
 */
static void
send_strata_estimator (struct IntersectionEvaluateOperation *eo)
{
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_MessageHeader *strata_msg;

  mqm = GNUNET_MQ_msg_header_extra (strata_msg,
                                    SE_STRATA_COUNT * IBF_BUCKET_SIZE * SE_IBF_SIZE,
                                    GNUNET_MESSAGE_TYPE_SET_P2P_SE);
  strata_estimator_write (eo->set->state.i->se, &strata_msg[1]);
  GNUNET_MQ_send (eo->tc->mq, mqm);
  eo->phase = PHASE_EXPECT_IBF;
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
  while ((1<<ibf_order) < (2 * diff))
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
  struct UnionEvaluateOperation *eo = cls;
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
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "got se, diff=%d\n", diff);
  strata_estimator_destroy (remote_se);
  strata_estimator_destroy (eo->se);
  eo->se = NULL;
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
  struct UnionEvaluateOperation *eo = sec->eo;
  struct KeyEntry *ke = value;

  if (ke->ibf_key.key_val != ibf_key.key_val)
    return GNUNET_YES;
  while (NULL != ke)
  {
    const struct GNUNET_SET_Element *const element = &ke->element->element;
    struct GNUNET_MQ_Envelope *mqm;
    struct GNUNET_MessageHeader *mh;

    GNUNET_assert (ke->ibf_key.key_val == ibf_key.key_val);
    mqm = GNUNET_MQ_msg_header_extra (mh, element->size, GNUNET_MESSAGE_TYPE_SET_P2P_ELEMENTS);
    if (NULL == mqm)
    {
      /* element too large */
      GNUNET_break (0);
      continue;
    }
    memcpy (&mh[1], element->data, element->size);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "sending element to client\n");
    GNUNET_MQ_send (eo->tc->mq, mqm);
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
send_elements_for_key (struct UnionEvaluateOperation *eo, struct IBF_Key ibf_key)
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
decode_and_send (struct UnionEvaluateOperation *eo)
{
  struct IBF_Key key;
  int side;
  struct InvertibleBloomFilter *diff_ibf;

  GNUNET_assert (PHASE_EXPECT_ELEMENTS == eo->phase);

  prepare_ibf (eo, eo->remote_ibf->size);
  diff_ibf = ibf_dup (eo->local_ibf);
  ibf_subtract (diff_ibf, eo->remote_ibf);

  while (1)
  {
    int res;

    res = ibf_decode (diff_ibf, &side, &key);
    if (GNUNET_SYSERR == res)
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
      struct GNUNET_MQ_Envelope *mqm;

      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "transmitted all values, sending DONE\n");
      mqm = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_SET_P2P_DONE);
      GNUNET_MQ_send (eo->tc->mq, mqm);
      break;
    }
    if (1 == side)
    {
      send_elements_for_key (eo, key);
    }
    else
    {
      struct GNUNET_MQ_Envelope *mqm;
      struct GNUNET_MessageHeader *msg;

      /* FIXME: before sending the request, check if we may just have the element */
      /* FIXME: merge multiple requests */
      mqm = GNUNET_MQ_msg_header_extra (msg, sizeof (struct IBF_Key),
                                        GNUNET_MESSAGE_TYPE_SET_P2P_ELEMENT_REQUESTS);
      *(struct IBF_Key *) &msg[1] = key;
      GNUNET_MQ_send (eo->tc->mq, mqm);
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
  struct UnionEvaluateOperation *eo = cls;
  struct IBFMessage *msg = (struct IBFMessage *) mh;
  unsigned int buckets_in_message;

  if ( (eo->phase == PHASE_EXPECT_ELEMENTS_AND_REQUESTS) ||
       (eo->phase == PHASE_EXPECT_IBF) )
  {
    eo->phase = PHASE_EXPECT_IBF_CONT;
    GNUNET_assert (NULL == eo->remote_ibf);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "creating new ibf of order %u\n", 1<<msg->order);
    eo->remote_ibf = ibf_create (1<<msg->order, SE_IBF_HASH_NUM);
    if (0 != ntohs (msg->offset))
    {
      GNUNET_break (0);
      fail_union_operation (eo);
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

    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "received full strata estimator\n");
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
send_client_element (struct UnionEvaluateOperation *eo,
                     struct GNUNET_SET_Element *element)
{
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_SET_ResultMessage *rm;

  GNUNET_assert (0 != eo->request_id);
  mqm = GNUNET_MQ_msg_extra (rm, element->size, GNUNET_MESSAGE_TYPE_SET_RESULT);
  if (NULL == mqm)
  {
    GNUNET_MQ_discard (mqm);
    GNUNET_break (0);
    return;
  }
  rm->result_status = htons (GNUNET_SET_STATUS_OK);
  rm->request_id = htonl (eo->request_id);
  memcpy (&rm[1], element->data, element->size);
  GNUNET_MQ_send (eo->set->client_mq, mqm);
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
send_client_done_and_destroy (struct UnionEvaluateOperation *eo)
{
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_SET_ResultMessage *rm;

  GNUNET_assert (0 != eo->request_id);
  mqm = GNUNET_MQ_msg (rm, GNUNET_MESSAGE_TYPE_SET_RESULT);
  rm->request_id = htonl (eo->request_id);
  rm->result_status = htons (GNUNET_SET_STATUS_DONE);
  GNUNET_MQ_send (eo->set->client_mq, mqm);

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
  struct UnionEvaluateOperation *eo = cls;
  struct ElementEntry *ee;
  uint16_t element_size;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "got element from peer\n");

  if ( (eo->phase != PHASE_EXPECT_ELEMENTS) &&
       (eo->phase != PHASE_EXPECT_ELEMENTS_AND_REQUESTS) )
  {
    fail_union_operation (eo);
    GNUNET_break (0);
    return;
  }
  element_size = ntohs (mh->size) - sizeof (struct GNUNET_MessageHeader);
  ee = GNUNET_malloc (sizeof *eo + element_size);
  memcpy (&ee[1], &mh[1], element_size);
  ee->element.data = &ee[1];
  ee->remote = GNUNET_YES;

  insert_element (eo, ee);
  send_client_element (eo, &ee->element);

  GNUNET_free (ee);
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
  struct UnionEvaluateOperation *eo = cls;
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
 * Callback used for notifications
 *
 * @param cls closure
 */
static void
peer_done_sent_cb (void *cls)
{
  struct UnionEvaluateOperation *eo = cls;

  send_client_done_and_destroy (eo);
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
  struct UnionEvaluateOperation *eo = cls;

  if (eo->phase == PHASE_EXPECT_ELEMENTS_AND_REQUESTS)
  {
    /* we got all requests, but still have to send our elements as response */
    struct GNUNET_MQ_Envelope *mqm;

    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "got DONE, sending final DONE after elements\n");
    eo->phase = PHASE_FINISHED;
    mqm = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_SET_P2P_DONE);
    GNUNET_MQ_notify_sent (mqm, peer_done_sent_cb, eo);
    GNUNET_MQ_send (eo->tc->mq, mqm);
    return;
  }
  if (eo->phase == PHASE_EXPECT_ELEMENTS)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "got final DONE\n");
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
 * @param m the evaluate request message from the client
 * @param set the set to evaluate the operation with
 */
void
_GSS_intersection_evaluate (struct GNUNET_SET_EvaluateMessage *m, struct Set *set)
{
  struct IntersectionEvaluateOperation *eo;
  struct GNUNET_MessageHeader *context_msg;

  eo = GNUNET_new (struct IntersectionEvaluateOperation);
  eo->peer = m->target_peer;
  eo->set = set;
  eo->request_id = htonl (m->request_id);
  GNUNET_assert (0 != eo->request_id);
  eo->se = strata_estimator_dup (set->state.i->se);
  eo->salt = ntohs (m->salt);
  eo->app_id = m->app_id;
  
  context_msg = GNUNET_MQ_extract_nested_mh (m);
  if (NULL != context_msg)
  {
    eo->context_msg = GNUNET_copy_message (context_msg);
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
	      "evaluating intersection operation, (app %s)\n", 
              GNUNET_h2s (&eo->app_id));

  eo->tc = GNUNET_new (struct TunnelContext);
  eo->tc->tunnel = GNUNET_MESH_tunnel_create (mesh, eo->tc, &eo->peer,
                                              GNUNET_APPLICATION_TYPE_SET);
  GNUNET_assert (NULL != eo->tc->tunnel);
  eo->tc->peer = eo->peer;
  eo->tc->mq = GNUNET_MESH_mq_create (eo->tc->tunnel);
  /* we started the operation, thus we have to send the operation request */
  eo->phase = PHASE_EXPECT_SE;

  GNUNET_CONTAINER_DLL_insert (eo->set->state.i->ops_head,
                               eo->set->state.i->ops_tail,
                               eo);

  send_operation_request (eo);
}


/**
 * Accept an union operation request from a remote peer
 *
 * @param m the accept message from the client
 * @param set the set of the client
 * @param incoming information about the requesting remote peer
 */
void
_GSS_intersection_accept (struct GNUNET_SET_AcceptRejectMessage *m, struct Set *set,
                   struct Incoming *incoming)
{
  struct IntersectionEvaluateOperation *eo;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "accepting set union operation\n");

  eo = GNUNET_new (struct IntersectionEvaluateOperation);
  eo->tc = incoming->tc;
  eo->generation_created = set->state.i->current_generation++;
  eo->set = set;
  eo->salt = ntohs (incoming->salt);
  GNUNET_assert (0 != ntohl (m->request_id));
  eo->request_id = ntohl (m->request_id);
  eo->se = strata_estimator_dup (set->state.i->se);
  /* transfer ownership of mq and socket from incoming to eo */
  GNUNET_CONTAINER_DLL_insert (eo->set->state.i->ops_head,
                               eo->set->state.i->ops_tail,
                               eo);
  /* kick off the operation */
  send_strata_estimator (eo);
}


/**
 * Create a new set supporting the intersection operation
 *
 * @return the newly created set
 */
struct Set *
_GSS_intersection_set_create (void)
{
  struct Set *set;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "intersection set created\n");
  
  set = GNUNET_malloc (sizeof (struct Set) + sizeof (struct IntersectionState));
  set->state.i = (struct IntersectionState *) &set[1];
  set->operation = GNUNET_SET_OPERATION_INTERSECTION;
  /* keys of the hash map are stored in the element entrys, thus we do not
   * want the hash map to copy them */
  set->state.i->elements = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);
  set->state.i->se = strata_estimator_create (SE_STRATA_COUNT,
                                              SE_IBF_SIZE, SE_IBF_HASH_NUM);  
  return set;
}


/**
 * Add the element from the given element message to the set.
 *
 * @param m message with the element
 * @param set set to add the element to
 */
void
_GSS_intersection_add (struct GNUNET_SET_ElementMessage *m, struct Set *set)
{
  struct ElementEntry *ee;
  struct ElementEntry *ee_dup;
  uint16_t element_size;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "adding element\n");

  GNUNET_assert (GNUNET_SET_OPERATION_INTERSECTION == set->operation);
  element_size = ntohs (m->header.size) - sizeof *m;
  ee = GNUNET_malloc (element_size + sizeof *ee);
  ee->element.size = element_size;
  memcpy (&ee[1], &m[1], element_size);
  ee->element.data = &ee[1];
  ee->generation_added = set->state.i->current_generation;
  GNUNET_CRYPTO_hash (ee->element.data, element_size, &ee->element_hash);
  ee_dup = GNUNET_CONTAINER_multihashmap_get (set->state.i->elements, &ee->element_hash);
  if (NULL != ee_dup)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "element inserted twice, ignoring\n");
    GNUNET_free (ee);
    return;
  }
  GNUNET_CONTAINER_multihashmap_put (set->state.i->elements, &ee->element_hash, ee,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  strata_estimator_insert (set->state.i->se, get_ibf_key (&ee->element_hash, 0));
}


/**
 * Destroy a set that supports the union operation
 *
 * @param set the set to destroy, must be of type GNUNET_SET_OPERATION_UNION
 */
void
_GSS_union_set_destroy (struct Set *set)
{
  GNUNET_assert (GNUNET_SET_OPERATION_UNION == set->operation);
  if (NULL != set->client)
  {
    GNUNET_SERVER_client_drop (set->client);
    set->client = NULL;
  }
  if (NULL != set->client_mq)
  {
    GNUNET_MQ_destroy (set->client_mq);
    set->client_mq = NULL;
  }

  if (NULL != set->state.u->se)
  {
    strata_estimator_destroy (set->state.u->se);
    set->state.u->se = NULL;
  }

  destroy_elements (set->state.u);

  while (NULL != set->state.u->ops_head)
  {
    _GSS_union_operation_destroy (set->state.u->ops_head);
  }
}

/**
 * Remove the element given in the element message from the set.
 * Only marks the element as removed, so that older set operations can still exchange it.
 *
 * @param m message with the element
 * @param set set to remove the element from
 */
void
_GSS_intersection_remove (struct GNUNET_SET_ElementMessage *m, struct Set *set)
{
  struct GNUNET_HashCode hash;
  struct ElementEntry *ee;

  GNUNET_assert (GNUNET_SET_OPERATION_UNION == set->operation);
  GNUNET_CRYPTO_hash (&m[1], ntohs (m->header.size), &hash);
  ee = GNUNET_CONTAINER_multihashmap_get (set->state.i->elements, &hash);
  if (NULL == ee)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "client tried to remove non-existing element\n");
    return;
  }
  if (GNUNET_YES == ee->removed)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "client tried to remove element twice\n");
    return;
  }
  ee->removed = GNUNET_YES;
  ee->generation_removed = set->state.i->current_generation;
}


/**
 * Dispatch messages for a union operation.
 *
 * @param cls closure
 * @param tunnel mesh tunnel
 * @param tunnel_ctx tunnel context
 * @param mh message to process
 * @return ???
 */
int
_GSS_union_handle_p2p_message (void *cls,
                               struct GNUNET_MESH_Tunnel *tunnel,
                               void **tunnel_ctx,
                               const struct GNUNET_MessageHeader *mh)
{
  struct TunnelContext *tc = *tunnel_ctx;
  struct UnionEvaluateOperation *eo;

  if (CONTEXT_OPERATION_UNION != tc->type)
  {
    /* never kill mesh */
    return GNUNET_OK;
  }

  eo = tc->data;

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
  /* never kill mesh! */
  return GNUNET_OK;
}
