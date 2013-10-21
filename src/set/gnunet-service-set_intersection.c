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
 * Current phase we are in for a intersection operation.
 */
enum IntersectionOperationPhase
{
  /**
   * We sent the request message, and expect a BF
   */
  PHASE_EXPECT_INITIAL,
  /**
   * We sent the request message, and expect a BF
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
  struct BloomFilter *remote_bf;

  /**
   * BF of the set's element.
   */
  struct BloomFilter *local_bf;

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
 * Extra state required for efficient set intersection.
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
 * Insert an element into the intersection operation's
 * key-to-element mapping. Takes ownership of 'ee'.
 * Note that this does not insert the element in the set,
 * only in the operation's key-element mapping.
 * This is done to speed up re-tried operations, if some elements
 * were transmitted, and then the IBF fails to decode.
 *
 * @param eo the intersection operation
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
 * Iterator for initializing the
 * key-to-element mapping of a intersection operation
 *
 * @param cls the intersection operation
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
 * Handle an IBF message from a remote peer.
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
 * Evaluate a intersection operation with
 * a remote peer.
 *
 * @param spec specification of the operation the evaluate
 * @param tunnel tunnel already connected to the partner peer
 * @param tc tunnel context, passed here so all new incoming
 *        messages are directly going to the intersection operations
 * @return a handle to the operation
 */
static void
intersection_evaluate (struct OperationSpecification *spec,
                struct GNUNET_MESH_Tunnel *tunnel,
                struct TunnelContext *tc)
{
  struct OperationState *eo;

  eo = GNUNET_new (struct OperationState);
  tc->vt = _GSS_intersection_vt ();
  tc->op = eo;
  eo->generation_created = spec->set->current_generation++;
  eo->set = spec->set;
  eo->spec = spec;
  eo->tunnel = tunnel;
  eo->mq = GNUNET_MESH_mq_create (tunnel);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "evaluating intersection operation, (app %s)\n",
              GNUNET_h2s (&eo->spec->app_id));

  /* we started the operation, thus we have to send the operation request */
  eo->phase = PHASE_EXPECT_SE;

  GNUNET_CONTAINER_DLL_insert (eo->set->state->ops_head,
                               eo->set->state->ops_tail,
                               eo);

  send_initial_bloomfilter (eo);
}


/**
 * Accept an intersection operation request from a remote peer
 *
 * @param spec all necessary information about the operation
 * @param tunnel open tunnel to the partner's peer
 * @param tc tunnel context, passed here so all new incoming
 *        messages are directly going to the intersection operations
 * @return operation
 */
static void
intersection_accept (struct OperationSpecification *spec,
              struct GNUNET_MESH_Tunnel *tunnel,
              struct TunnelContext *tc)
{
  struct OperationState *eo;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "accepting set intersection operation\n");

  eo = GNUNET_new (struct OperationState);
  tc->vt = _GSS_intersection_vt ();
  tc->op = eo;
  eo->set = spec->set;
  eo->generation_created = eo->set->current_generation++;
  eo->spec = spec;
  eo->tunnel = tunnel;
  eo->mq = GNUNET_MESH_mq_create (tunnel);
  /* transfer ownership of mq and socket from incoming to eo */
  GNUNET_CONTAINER_DLL_insert (eo->set->state->ops_head,
                               eo->set->state->ops_tail,
                               eo);
  /* kick off the operation */
  send_bloomfilter (eo);
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

  //TODO: actually create that thing
  
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
  //TODO
}


/**
 * Destroy a set that supports the intersection operation
 *
 * @param set_state the set to destroy
 */
static void
intersection_set_destroy (struct SetState *set_state)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "destroying intersection set\n");
  /* important to destroy operations before the rest of the set */
  while (NULL != set_state->ops_head)
    intersection_operation_destroy (set_state->ops_head);
  if (NULL != set_state->se)
  {
    //TODO: actually destroy that thing
    set_state->se = NULL;
  }
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
  //TODO
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
    case GNUNET_MESSAGE_TYPE_SET_P2P_BF:
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


static void
intersection_peer_disconnect (struct OperationState *op)
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
    intersection_operation_destroy (op);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "other peer disconnected (finished)\n");
  if (GNUNET_NO == op->client_done_sent)
    send_client_done_and_destroy (op);
}


static void
intersection_op_cancel (struct SetState *set_state, uint32_t op_id)
{
  /* FIXME: implement */
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
