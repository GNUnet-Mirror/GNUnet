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
#include "set_protocol.h"
#include "ibf.h"
#include "strata_estimator.h"


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

  /**
   * The ibf we currently receive
   */
  struct InvertibleBloomFilter *ibf_received;

  struct StrataEstimator *se;

  /**
   * Current state of the operation
   */
  enum UnionOperationState state;
};


/**
 * Element entry, stored in the hash maps from
 * partial IBF keys to elements.
 */
struct ElementEntry
{
  /**
   * The actual element
   */
  struct GNUNET_SET_Element *element;

  /**
   * Actual ibf key of the element entry
   */
  struct IBF_Key ibf_key;

  /**
   * Linked list, note that the next element
   * has to have an ibf_key that is lexicographically
   * equal or larger.
   */
  struct ElementEntry *next;

  /**
   * GNUNET_YES if the element was received from
   * the remote peer, and the local peer did not previously
   * have it
   */
  int remote;
};


/**
 * Extra state required for efficient set union.
 */
struct UnionState
{
  /**
   * Strate estimator of the set we currently have,
   * used for estimation of the symmetric difference
   */
  struct StrataEstimator *se;

  /**
   * Array of IBFs, some of them pre-allocated
   */
  struct InvertibleBloomFilter **ibfs;

  /**
   * Maps the first 32 bits of the ibf-key to
   * elements.
   */
  struct GNUNET_CONTAINER_MultiHashMap32 *elements;
};


static void
send_operation_request (struct EvaluateOperation *eo)
{
  struct GNUNET_MQ_Message *mqm;
  struct OperationRequestMessage *msg;

  mqm = GNUNET_MQ_msg_concat (msg, eo->context_msg,
                              GNUNET_MESSAGE_TYPE_SET_P2P_OPERATION_REQUEST);
  if (NULL == mqm)
  {
    /* the context message is too large */
    client_disconnect (eo->set->client);
    GNUNET_break (0);
    return;
  }
  msg->operation = eo->operation;
  msg->app_id = eo->app_id;
  GNUNET_MQ_send (eo->mq, mqm);
}


/**
 * Iterator to insert values into an ibf.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
static int
ibf_insert_iterator (void *cls,
                     uint32_t key,
                     void *value)
{
  struct InvertibleBloomFilter *ibf = cls;
  struct ElementEntry *e = value;
  struct IBF_Key ibf_key;

  GNUNET_assert (NULL != e);
  ibf_key = e->ibf_key;
  ibf_insert (ibf, ibf_key);
  e = e->next;

  while (NULL != e)
  {
    /* only insert keys we haven't seen yet */
    if (0 != memcmp (&e->ibf_key, &ibf_key, sizeof ibf_key))
    {
      ibf_key = e->ibf_key;
      ibf_insert (ibf, ibf_key);
    }
    e = e->next; 
  }

  return GNUNET_YES;
}


/**
 * Create and populate an IBF for the specified peer,
 * if it does not already exist.
 *
 * @param cpi peer to create the ibf for
 */
static struct InvertibleBloomFilter *
prepare_ibf (struct EvaluateOperation *eo, uint16_t order)
{
  struct UnionState *us = eo->set->extra.u;

  GNUNET_assert (order <= MAX_IBF_ORDER);
  if (NULL == us->ibfs)
    us->ibfs = GNUNET_malloc (MAX_IBF_ORDER * sizeof (struct InvertibleBloomFilter *));
  if (NULL == us->ibfs[order])
  {
    us->ibfs[order] = ibf_create (1 << order, SE_IBF_HASH_NUM);
    GNUNET_CONTAINER_multihashmap32_iterate (us->elements, ibf_insert_iterator, us->ibfs[order]);
  }
  return us->ibfs[order];
}


/**
 * Send an ibf of appropriate size.
 *
 * @param cpi the peer
 */
static void
send_ibf (struct EvaluateOperation *eo, uint16_t ibf_order)
{
  unsigned int buckets_sent = 0;
  struct InvertibleBloomFilter *ibf;

  ibf = prepare_ibf (eo, ibf_order);

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

  eo->extra.u->state = STATE_EXPECT_ELEMENTS_AND_REQUESTS;
}


/**
 * Send a strata estimator.
 *
 * @param cpi the peer
 */
static void
send_strata_estimator (struct EvaluateOperation *eo)
{
  struct GNUNET_MQ_Message *mqm;
  struct GNUNET_MessageHeader *strata_msg;

  mqm = GNUNET_MQ_msg_header_extra (strata_msg,
                                    SE_STRATA_COUNT * IBF_BUCKET_SIZE * SE_IBF_SIZE,
                                    GNUNET_MESSAGE_TYPE_SET_P2P_SE);
  strata_estimator_write (eo->set->extra.u->se, &strata_msg[1]);
  GNUNET_MQ_send (eo->mq, mqm);

  eo->extra.u->state = STATE_EXPECT_IBF;
}


static void
handle_p2p_strata_estimator (void *cls, const struct GNUNET_MessageHeader *mh)
{
  struct EvaluateOperation *eo = cls;
  int ibf_order;
  int diff;

  if (eo->extra.u->state != STATE_EXPECT_SE)
  {
    /* FIXME: handle */
    GNUNET_break (0);
    return;
  }
  GNUNET_assert (NULL == eo->extra.u->se);
  eo->extra.u->se = strata_estimator_create (SE_STRATA_COUNT, SE_IBF_SIZE, SE_IBF_HASH_NUM);
  strata_estimator_read (&mh[1], eo->extra.u->se);
  GNUNET_assert (NULL != eo->set->extra.u->se);
  diff = strata_estimator_difference (eo->set->extra.u->se, eo->extra.u->se);
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
decode (struct EvaluateOperation *eo)
{
  struct IBF_Key key;
  int side;
  struct InvertibleBloomFilter *diff_ibf;

  GNUNET_assert (STATE_EXPECT_ELEMENTS == eo->extra.u->state);

  diff_ibf = ibf_dup (prepare_ibf (eo, eo->extra.u->ibf_order));
  ibf_subtract (diff_ibf, eo->extra.u->ibf_received);

  while (1)
  {
    int res;

    res = ibf_decode (diff_ibf, &side, &key);
    if (GNUNET_SYSERR == res)
    {
      /* decoding failed, we tell the other peer by sending our ibf with a larger order */
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
      struct ElementEntry *e;
      /* we have the element(s), send it to the other peer */
      e = GNUNET_CONTAINER_multihashmap32_get (eo->set->extra.u->elements, (uint32_t) key.key_val);
      if (NULL == e)
      {
        /* FIXME */
        GNUNET_assert (0);
        return;
      }
      while (NULL != e)
      {
        /* FIXME: send element */
        e = e->next;
      }
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
  struct EvaluateOperation *eo = cls;
  struct UnionEvaluateOperation *ueo = eo->extra.u;
  struct IBFMessage *msg = (struct IBFMessage *) mh;
  unsigned int buckets_in_message;

  if (ueo->state == STATE_EXPECT_ELEMENTS_AND_REQUESTS)
  {
    /* check that the ibf is a new one / first part */
    /* clear outgoing messages */
    GNUNET_assert (0);
  }
  else if (ueo->state == STATE_EXPECT_IBF)
  {
    ueo->state = STATE_EXPECT_IBF_CONT;
    ueo->ibf_order = msg->order;
    GNUNET_assert (NULL == ueo->ibf_received);
    ueo->ibf_received = ibf_create (1<<msg->order, SE_IBF_HASH_NUM);
    if (ntohs (msg->offset) != 0)
    {
      /* FIXME: handle */
      GNUNET_assert (0);
    }
  }
  else if (ueo->state == STATE_EXPECT_IBF_CONT)
  {
    if ( (ntohs (msg->offset) != ueo->ibf_buckets_received) ||
         (msg->order != ueo->ibf_order) )
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

  ibf_read_slice (&msg[1], ueo->ibf_buckets_received, buckets_in_message, ueo->ibf_received);
  ueo->ibf_buckets_received += buckets_in_message;

  if (ueo->ibf_buckets_received == (1<<ueo->ibf_order))
  {
    ueo->state = STATE_EXPECT_ELEMENTS;
    decode (eo);
  }
}


static void
handle_p2p_elements (void *cls, const struct GNUNET_MessageHeader *mh)
{
  struct EvaluateOperation *eo = cls;

  if ( (eo->extra.u->state != STATE_EXPECT_ELEMENTS) &&
       (eo->extra.u->state != STATE_EXPECT_ELEMENTS_AND_REQUESTS) )
  {
    /* FIXME: handle */
    GNUNET_break (0);
    return;
  }
}


static void
handle_p2p_element_requests (void *cls, const struct GNUNET_MessageHeader *mh)
{
  struct EvaluateOperation *eo = cls;

  /* look up elements and send them */
  if (eo->extra.u->state != STATE_EXPECT_ELEMENTS_AND_REQUESTS)
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
 * @param socket socket to use to communicate with the other side (read/write)
 */
static void
stream_open_cb (void *cls,
                struct GNUNET_STREAM_Socket *socket)
{
  struct EvaluateOperation *eo = cls;

  GNUNET_assert (NULL == eo->mq);
  GNUNET_assert (socket == eo->socket);

  eo->mq = GNUNET_MQ_queue_for_stream_socket (eo->socket, union_handlers, eo);
  send_operation_request (eo);
}
	

void
union_evaluate (struct EvaluateOperation *eo)
{
  GNUNET_assert (GNUNET_SET_OPERATION_UNION == eo->set->operation);
  eo->socket = 
      GNUNET_STREAM_open (configuration, &eo->peer, GNUNET_APPLICATION_TYPE_SET,
                          stream_open_cb, GNUNET_STREAM_OPTION_END);
}


static void
insert_ibf_key_unchecked (struct UnionState *us, struct IBF_Key ibf_key)
{
  int i;

  strata_estimator_insert (us->se, ibf_key);
  for (i = 0; i <= MAX_IBF_ORDER; i++)
  {
    if (NULL == us->ibfs)
      break;
    if (NULL == us->ibfs[i])
      continue;
    ibf_insert (us->ibfs[i], ibf_key);
  }
}


/**
 * Insert an element into the consensus set of the specified session.
 * The element will not be copied, and freed when destroying the session.
 *
 * @param session session for new element
 * @param element element to insert
 */
static void
insert_element (struct Set *set, struct GNUNET_SET_Element *element)
{
  struct UnionState *us = set->extra.u;
  struct GNUNET_HashCode hash;
  struct ElementEntry *e;
  struct ElementEntry *e_old;

  e = GNUNET_new (struct ElementEntry);
  e->element = element;
  GNUNET_CRYPTO_hash (e->element->data, e->element->size, &hash);
  e->ibf_key = ibf_key_from_hashcode (&hash);

  e_old = GNUNET_CONTAINER_multihashmap32_get (us->elements, (uint32_t) e->ibf_key.key_val);
  if (NULL == e_old)
  {
    GNUNET_CONTAINER_multihashmap32_put (us->elements, (uint32_t) e->ibf_key.key_val, e,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
    return;
  }

  while (NULL != e_old)
  {
    int cmp = memcmp (&e->ibf_key, &e_old->ibf_key, sizeof (struct IBF_Key));
    if (cmp < 0)
    {
      if (NULL == e_old->next)
      {
        e_old->next = e;
        insert_ibf_key_unchecked (us, e->ibf_key);
        return;
      }
      e_old = e_old->next;
    }
    else if (cmp == 0)
    {
      e->next = e_old->next;
      e_old->next = e;
      return;
    }
    else
    {
      e->next = e_old;
      insert_ibf_key_unchecked (us, e->ibf_key);
      return;
    }
  } 
}


void
union_accept (struct EvaluateOperation *eo, struct Incoming *incoming)
{
  GNUNET_assert (NULL != incoming->mq); 
  eo->mq = incoming->mq;
  GNUNET_MQ_replace_handlers (eo->mq, union_handlers, eo);

  send_strata_estimator (eo);
}


struct Set *
union_set_create ()
{
  struct Set *set;
  set = GNUNET_malloc (sizeof (struct Set) + sizeof (struct UnionState));
  set->extra.u = (struct UnionState *) &set[1];
  set->operation = GNUNET_SET_OPERATION_UNION;
  set->extra.u->se = strata_estimator_create (SE_STRATA_COUNT, SE_IBF_SIZE, SE_IBF_HASH_NUM);
  return set;
}


void
union_add (struct Set *set, struct ElementMessage *m)
{
  struct GNUNET_SET_Element *element;
  uint16_t element_size;
  element_size = ntohs (m->header.size) - sizeof *m;
  element = GNUNET_malloc (sizeof *element + element_size);
  element->size = element_size;
  element->data = &element[1];
  memcpy (element->data, &m[1], element_size);
  insert_element (set, element);
}

