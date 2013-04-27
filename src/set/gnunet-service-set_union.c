/*
      This file is part of GNUnet
      (C) 2013 Christian Grothoff (and other contributing authors)

      GNUnet is free software; you can redistribute it and/or modify
      it under the terms of the GNU General Public License as published
      by the Free Software Foundation; either version 2, or (at your
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


enum UnionOperationState
{
  STATE_EXPECT_SE,
  STATE_EXPECT_IBF,
  STATE_EXPECT_IBF_CONT,
  STATE_EXPECT_ELEMENTS,
  STATE_EXPECT_ELEMENTS_AND_REQUESTS,
  STATE_WAIT_SENT_DONE,
  STATE_FINISHED
};


/**
 * State of an evaluate operation
 * with another peer.
 */
struct UnionEvaluateOperation
{
  /**
   * Local set the operation is evaluated on
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
   * Stream socket connected to the other peer
   */
  struct GNUNET_STREAM_Socket *socket;

  /**
   * Message queue for the peer on the other
   * end
   */
  struct GNUNET_MQ_MessageQueue *mq;

  /**
   * Type of this operation
   */
  enum GNUNET_SET_OperationType operation;

  /**
   * GNUNET_YES if we started the operation,
   * GNUNET_NO if the other peer started it.
   */
  int is_outgoing;

  /**
   * Request id, so we can use one client handle
   * for multiple operations
   */
  uint32_t request_id;

  /* last difference estimate */
  unsigned int diff;

  /**
   * Number of ibf buckets received
   */
  unsigned int ibf_buckets_received;

  /**
   * Current salt in use, zero unless
   * we detected a collision
   */
  uint8_t salt;

  /**
   * order of the ibf we receive
   */
  unsigned int ibf_order;

  struct StrataEstimator *se;

  /**
   * The ibf we currently receive
   */
  struct InvertibleBloomFilter *remote_ibf;

  /**
   * Array of IBFs, some of them pre-allocated
   */
  struct InvertibleBloomFilter *local_ibf;

  /**
   * Elements we received from the other peer.
   */
  struct GNUNET_CONTAINER_MultiHashMap *received_elements;

  /**
   * Maps IBF-Keys (specific to the current salt) to elements.
   */
  struct GNUNET_CONTAINER_MultiHashMap32 *key_to_element;

  /**
   * Current state of the operation
   */
  enum UnionOperationState state;
  
  /**
   * Evaluate operations are held in
   * a linked list.
   */
  struct UnionEvaluateOperation *next;
  
   /**
   * Evaluate operations are held in
   * a linked list.
   */
  struct UnionEvaluateOperation *prev;
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
   * Generation the element was added.
   * Operations of earlier generations will not consider the element.
   */
  int generation_add;

  /**
   * Generation this element was removed.
   * Operations of later generations will not consider the element.
   */
  int generation_remove;

  /**
   * GNUNET_YES if we received the element from a remote peer, and not
   * from the local peer.  Note that if the local client inserts an
   * element *after* we got it from a remote peer, the element is
   * considered local.
   */
  int remote;
};

/**
 * Information about the element used for 
 * a specific union operation.
 */
struct KeyEntry
{
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
 * Extra state required for efficient set union.
 */
struct UnionState
{
  /**
   * The strata estimator is only generated once for
   * each set.
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
  struct UnionEvaluateOperation *ops_head;

  /**
   * Evaluate operations are held in
   * a linked list.
   */
  struct UnionEvaluateOperation *ops_tail;
};


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


static void
send_operation_request (struct UnionEvaluateOperation *eo)
{
  struct GNUNET_MQ_Message *mqm;
  struct OperationRequestMessage *msg;
  int ret;

  mqm = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_SET_P2P_OPERATION_REQUEST);
  ret = GNUNET_MQ_nest (mqm, eo->context_msg);
  if (GNUNET_OK != ret)
  {
    /* the context message is too large */
    _GSS_client_disconnect (eo->set->client);
    GNUNET_MQ_discard (mqm);
    GNUNET_break (0);
    return;
  }
  msg->operation = eo->operation;
  msg->app_id = eo->app_id;
  GNUNET_MQ_send (eo->mq, mqm);

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
      new_k->next_colliding = old_k;
      old_k->next_colliding = new_k;
      return GNUNET_NO;
    }
    old_k = old_k->next_colliding;
  } while (NULL != old_k);
  return GNUNET_YES;
}


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
  ret = GNUNET_CONTAINER_multihashmap32_get_multiple (eo->key_to_element, (uint32_t) ibf_key.key_val,
                                                    insert_element_iterator, k);
  /* was the element inserted into a colliding bucket? */
  if (GNUNET_SYSERR == ret)
  {
    GNUNET_assert (NULL != k->next_colliding);
    return;
  }
  GNUNET_CONTAINER_multihashmap32_put (eo->key_to_element, (uint32_t) ibf_key.key_val, k,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  if (NULL != eo->local_ibf)
    ibf_insert (eo->local_ibf, ibf_key);
}


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

static int
init_key_to_element_iterator (void *cls,
                              const struct GNUNET_HashCode *key,
                              void *value)
{
  struct UnionEvaluateOperation *eo = cls;
  struct ElementEntry *e = value;

  insert_element (eo, e);
  return GNUNET_YES;
}

static void
prepare_ibf (struct UnionEvaluateOperation *eo, uint16_t size)
{
  if (NULL == eo->key_to_element)
  {
    unsigned int len;
    len = GNUNET_CONTAINER_multihashmap_size (eo->set->state.u->elements);
    eo->key_to_element = GNUNET_CONTAINER_multihashmap32_create (len);
    GNUNET_CONTAINER_multihashmap_iterate (eo->set->state.u->elements,
                                             init_key_to_element_iterator, eo);
  }
  if (NULL != eo->local_ibf)
    ibf_destroy (eo->local_ibf);
  eo->local_ibf = ibf_create (size, SE_IBF_HASH_NUM);
  GNUNET_CONTAINER_multihashmap32_iterate (eo->key_to_element, prepare_ibf_iterator, eo->local_ibf);
}


/**
 * Send an ibf of appropriate size.
 *
 * @param cpi the peer
 */
static void
send_ibf (struct UnionEvaluateOperation *eo, uint16_t ibf_order)
{
  unsigned int buckets_sent = 0;
  struct InvertibleBloomFilter *ibf;

  prepare_ibf (eo, ibf_order);

  ibf = eo->local_ibf;

  while (buckets_sent < (1 << ibf_order))
  {
    unsigned int buckets_in_message;
    struct GNUNET_MQ_Message *mqm;
    struct IBFMessage *msg;

    buckets_in_message = (1 << ibf_order) - buckets_sent;
    /* limit to maximum */
    if (buckets_in_message > MAX_BUCKETS_PER_MESSAGE)
      buckets_in_message = MAX_BUCKETS_PER_MESSAGE;

    mqm = GNUNET_MQ_msg_extra (msg, buckets_in_message * IBF_BUCKET_SIZE,
                               GNUNET_MESSAGE_TYPE_SET_P2P_IBF);
    msg->order = htons (ibf_order);
    msg->offset = htons (buckets_sent);
    ibf_write_slice (ibf, buckets_sent,
                     buckets_in_message, &msg[1]);
    buckets_sent += buckets_in_message;
    GNUNET_MQ_send (eo->mq, mqm);
  }

  eo->state = STATE_EXPECT_ELEMENTS_AND_REQUESTS;
}


/**
 * Send a strata estimator.
 *
 * @param cpi the peer
 */
static void
send_strata_estimator (struct UnionEvaluateOperation *eo)
{
  struct GNUNET_MQ_Message *mqm;
  struct GNUNET_MessageHeader *strata_msg;

  mqm = GNUNET_MQ_msg_header_extra (strata_msg,
                                    SE_STRATA_COUNT * IBF_BUCKET_SIZE * SE_IBF_SIZE,
                                    GNUNET_MESSAGE_TYPE_SET_P2P_SE);
  strata_estimator_write (eo->set->state.u->se, &strata_msg[1]);
  GNUNET_MQ_send (eo->mq, mqm);
  eo->state = STATE_EXPECT_IBF;
}


static void
handle_p2p_strata_estimator (void *cls, const struct GNUNET_MessageHeader *mh)
{
  struct UnionEvaluateOperation *eo = cls;
  struct StrataEstimator *remote_se;
  int ibf_order;
  int diff;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "got se\n");

  if (eo->state != STATE_EXPECT_SE)
  {
    /* FIXME: handle */
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
  /* minimum order */
  ibf_order = 2;
  while ((1<<ibf_order) < (2 * diff))
    ibf_order++;
  if (ibf_order > MAX_IBF_ORDER)
    ibf_order = MAX_IBF_ORDER;
  send_ibf (eo, ibf_order);
}


/**
 * FIXME
 *
 * @param
 */
static void
decode (struct UnionEvaluateOperation *eo)
{
  struct IBF_Key key;
  int side;
  struct InvertibleBloomFilter *diff_ibf;

  GNUNET_assert (STATE_EXPECT_ELEMENTS == eo->state);

  prepare_ibf (eo, eo->ibf_order);
  diff_ibf = ibf_dup (eo->local_ibf);
  ibf_subtract (diff_ibf, eo->remote_ibf);

  while (1)
  {
    int res;

    res = ibf_decode (diff_ibf, &side, &key);
    if (GNUNET_SYSERR == res)
    {
      /* decoding failed, we tell the other peer by sending our ibf
       * with a larger order */
      GNUNET_assert (0);
      return;
    }
    if (GNUNET_NO == res)
    {
      struct GNUNET_MQ_Message *mqm;
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "transmitted all values, sending DONE\n");
      mqm = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_SET_P2P_DONE);
      GNUNET_MQ_send (eo->mq, mqm);
      return;
    }
    if (1 == side)
    {
      //struct ElementEntry *e;
      /* we have the element(s), send it to the other peer */
      //GNUNET_CONTAINER_multihashmap32_get_multiple (eo->set->state.u->elements,
      //                                              (uint32_t) key.key_val);
      /* FIXME */
    }
    else
    {
      struct GNUNET_MQ_Message *mqm;
      struct GNUNET_MessageHeader *msg;

      /* FIXME: before sending the request, check if we may just have the element */
      /* FIXME: merge multiple requests */
      mqm = GNUNET_MQ_msg_header_extra (msg, sizeof (struct IBF_Key), GNUNET_MESSAGE_TYPE_SET_P2P_ELEMENT_REQUESTS);
      *(struct IBF_Key *) &msg[1] = key;
      GNUNET_MQ_send (eo->mq, mqm);
    }
  }
}


static void
handle_p2p_ibf (void *cls, const struct GNUNET_MessageHeader *mh)
{
  struct UnionEvaluateOperation *eo = cls;
  struct IBFMessage *msg = (struct IBFMessage *) mh;
  unsigned int buckets_in_message;

  if (eo->state == STATE_EXPECT_ELEMENTS_AND_REQUESTS)
  {
    /* check that the ibf is a new one / first part */
    /* clear outgoing messages */
    GNUNET_assert (0);
  }
  else if (eo->state == STATE_EXPECT_IBF)
  {
    eo->state = STATE_EXPECT_IBF_CONT;
    eo->ibf_order = msg->order;
    GNUNET_assert (NULL == eo->remote_ibf);
    eo->remote_ibf = ibf_create (1<<msg->order, SE_IBF_HASH_NUM);
    if (ntohs (msg->offset) != 0)
    {
      /* FIXME: handle */
      GNUNET_assert (0);
    }
  }
  else if (eo->state == STATE_EXPECT_IBF_CONT)
  {
    if ( (ntohs (msg->offset) != eo->ibf_buckets_received) ||
         (msg->order != eo->ibf_order) )
    {
      /* FIXME: handle */
      GNUNET_assert (0);
    }
  }

  buckets_in_message = (ntohs (msg->header.size) - sizeof *msg) / IBF_BUCKET_SIZE;

  if ((ntohs (msg->header.size) - sizeof *msg) != buckets_in_message * IBF_BUCKET_SIZE)
  {
    /* FIXME: handle, message was malformed */
    GNUNET_assert (0);
  }

  ibf_read_slice (&msg[1], eo->ibf_buckets_received, buckets_in_message, eo->remote_ibf);
  eo->ibf_buckets_received += buckets_in_message;

  if (eo->ibf_buckets_received == (1<<eo->ibf_order))
  {
    eo->state = STATE_EXPECT_ELEMENTS;
    decode (eo);
  }
}


static void
handle_p2p_elements (void *cls, const struct GNUNET_MessageHeader *mh)
{
  struct UnionEvaluateOperation *eo = cls;

  if ( (eo->state != STATE_EXPECT_ELEMENTS) &&
       (eo->state != STATE_EXPECT_ELEMENTS_AND_REQUESTS) )
  {
    /* FIXME: handle */
    GNUNET_break (0);
    return;
  }
}


static void
handle_p2p_element_requests (void *cls, const struct GNUNET_MessageHeader *mh)
{
  struct UnionEvaluateOperation *eo = cls;

  /* look up elements and send them */
  if (eo->state != STATE_EXPECT_ELEMENTS_AND_REQUESTS)
  {
    /* FIXME: handle */
    GNUNET_break (0);
    return;
  }
}


static void
handle_p2p_done (void *cls, const struct GNUNET_MessageHeader *mh)
{
  GNUNET_break (0);
}


static const struct GNUNET_MQ_Handler union_handlers[] = {
  {handle_p2p_elements, GNUNET_MESSAGE_TYPE_SET_P2P_ELEMENTS},
  {handle_p2p_strata_estimator, GNUNET_MESSAGE_TYPE_SET_P2P_SE},
  {handle_p2p_ibf, GNUNET_MESSAGE_TYPE_SET_P2P_IBF},
  {handle_p2p_element_requests, GNUNET_MESSAGE_TYPE_SET_P2P_ELEMENT_REQUESTS},
  {handle_p2p_done, GNUNET_MESSAGE_TYPE_SET_P2P_DONE},
  GNUNET_MQ_HANDLERS_END
};


/**
 * Functions of this type will be called when a stream is established
 * 
 * @param cls the closure from GNUNET_STREAM_open
 * @param socket socket to use to communicate with the
 *        other side (read/write)
 */
static void
stream_open_cb (void *cls,
                struct GNUNET_STREAM_Socket *socket)
{
  struct UnionEvaluateOperation *eo = cls;

  GNUNET_assert (NULL == eo->mq);
  GNUNET_assert (socket == eo->socket);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "open cb successful\n");

  eo->mq = GNUNET_MQ_queue_for_stream_socket (eo->socket,
                                              union_handlers, eo);
  /* we started the operation, thus we have to send the operation request */
  send_operation_request (eo);
  eo->state = STATE_EXPECT_SE;
}
	

void
_GSS_union_evaluate (struct EvaluateMessage *m, struct Set *set)
{
  struct UnionEvaluateOperation *eo;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "evaluating union operation\n");

  eo = GNUNET_new (struct UnionEvaluateOperation);
  eo->peer = m->peer;
  eo->set = set;
  eo->socket = 
      GNUNET_STREAM_open (configuration, &eo->peer, GNUNET_APPLICATION_TYPE_SET,
                          stream_open_cb, eo,
                          GNUNET_STREAM_OPTION_END);
}


void
_GSS_union_accept (struct AcceptMessage *m, struct Set *set,
                   struct Incoming *incoming)
{
  struct UnionEvaluateOperation *eo;

  eo = GNUNET_new (struct UnionEvaluateOperation);
  eo->set = set;
  eo->peer = incoming->peer;
  eo->app_id = incoming->app_id;
  eo->salt = ntohs (incoming->salt);
  eo->request_id = m->request_id;
  eo->set = set;
  eo->mq = incoming->mq;
  /* the peer's socket is now ours, we'll receive all messages */
  GNUNET_MQ_replace_handlers (eo->mq, union_handlers, eo);
  /* kick of the operation */
  send_strata_estimator (eo);
}


struct Set *
_GSS_union_set_create (void)
{
  struct Set *set;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "set created\n");
  
  set = GNUNET_malloc (sizeof (struct Set) + sizeof (struct UnionState));
  set->state.u = (struct UnionState *) &set[1];
  set->operation = GNUNET_SET_OPERATION_UNION;
  set->state.u->se = strata_estimator_create (SE_STRATA_COUNT,
                                              SE_IBF_SIZE, SE_IBF_HASH_NUM);  
  return set;
}



void
_GSS_union_add (struct ElementMessage *m, struct Set *set)
{
  struct ElementEntry *ee;
  struct ElementEntry *ee_dup;
  uint16_t element_size;
  
  element_size = ntohs (m->header.size) - sizeof *m;
  ee = GNUNET_malloc (element_size + sizeof *ee);
  ee->element.size = element_size;
  ee->element.data = &ee[1];
  memcpy (ee->element.data, &m[1], element_size);
  GNUNET_CRYPTO_hash (ee->element.data, element_size, &ee->element_hash);
  ee_dup = GNUNET_CONTAINER_multihashmap_get (set->state.u->elements, &ee->element_hash);
  if (NULL != ee_dup)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "element inserted twice, ignoring\n");
    GNUNET_free (ee);
    return;
  }
  GNUNET_CONTAINER_multihashmap_put (set->state.u->elements, &ee->element_hash, ee,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  strata_estimator_insert (set->state.u->se, get_ibf_key (&ee->element_hash, 0));
}

