/*
      This file is part of GNUnet
      Copyright (C) 2013-2017 GNUnet e.V.

      GNUnet is free software: you can redistribute it and/or modify it
      under the terms of the GNU Affero General Public License as published
      by the Free Software Foundation, either version 3 of the License,
      or (at your option) any later version.

      GNUnet is distributed in the hope that it will be useful, but
      WITHOUT ANY WARRANTY; without even the implied warranty of
      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
      Affero General Public License for more details.
     
      You should have received a copy of the GNU Affero General Public License
      along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
/**
 * @file set/gnunet-service-set_union.c
 * @brief two-peer set operations
 * @author Florian Dold
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet-service-set.h"
#include "ibf.h"
#include "gnunet-service-set_union.h"
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
#define MAX_IBF_ORDER (20)

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
   * XXX: repurposed to also expect a "request full set" message, should be renamed
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
   * message, and wait for another done message.
   */
  PHASE_FINISH_WAITING,

  /**
   * In the ultimate phase, we wait until
   * our demands are satisfied and then
   * quit (sending another DONE message).
   */
  PHASE_DONE,

  /**
   * After sending the full set, wait for responses with the elements
   * that the local peer is missing.
   */
  PHASE_FULL_SENDING,
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
   * Maps unsalted IBF-Keys to elements.
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

  /**
   * Salt that we're using for sending IBFs
   */
  uint32_t salt_send;

  /**
   * Salt for the IBF we've received and that we're currently decoding.
   */
  uint32_t salt_receive;

  /**
   * Number of elements we received from the other peer
   * that were not in the local set yet.
   */
  uint32_t received_fresh;

  /**
   * Total number of elements received from the other peer.
   */
  uint32_t received_total;

  /**
   * Initial size of our set, just before
   * the operation started.
   */
  uint64_t initial_size;
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

  /**
   * Did we receive this element?
   * Even if element->is_foreign is false, we might
   * have received the element, so this indicates that
   * the other peer has it.
   */
  int received;
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

  LOG (GNUNET_ERROR_TYPE_WARNING,
       "union operation failed\n");
  ev = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_SET_RESULT);
  msg->result_status = htons (GNUNET_SET_STATUS_FAILURE);
  msg->request_id = htonl (op->client_request_id);
  msg->element_type = htons (0);
  GNUNET_MQ_send (op->set->cs->mq,
                  ev);
  _GSS_operation_destroy (op, GNUNET_YES);
}


/**
 * Derive the IBF key from a hash code and
 * a salt.
 *
 * @param src the hash code
 * @return the derived IBF key
 */
static struct IBF_Key
get_ibf_key (const struct GNUNET_HashCode *src)
{
  struct IBF_Key key;
  uint16_t salt = 0;

  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CRYPTO_kdf (&key, sizeof (key),
				    src, sizeof *src,
				    &salt, sizeof (salt),
				    NULL, 0));
  return key;
}


/**
 * Context for #op_get_element_iterator
 */
struct GetElementContext
{
  /**
   * FIXME.
   */
  struct GNUNET_HashCode hash;

  /**
   * FIXME.
   */
  struct KeyEntry *k;
};


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
op_get_element_iterator (void *cls,
                         uint32_t key,
                         void *value)
{
  struct GetElementContext *ctx = cls;
  struct KeyEntry *k = value;

  GNUNET_assert (NULL != k);
  if (0 == GNUNET_CRYPTO_hash_cmp (&k->element->element_hash,
                                   &ctx->hash))
  {
    ctx->k = k;
    return GNUNET_NO;
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
static struct KeyEntry *
op_get_element (struct Operation *op,
                const struct GNUNET_HashCode *element_hash)
{
  int ret;
  struct IBF_Key ibf_key;
  struct GetElementContext ctx = {{{ 0 }} , 0};

  ctx.hash = *element_hash;

  ibf_key = get_ibf_key (element_hash);
  ret = GNUNET_CONTAINER_multihashmap32_get_multiple (op->state->key_to_element,
                                                      (uint32_t) ibf_key.key_val,
                                                      op_get_element_iterator,
                                                      &ctx);

  /* was the iteration aborted because we found the element? */
  if (GNUNET_SYSERR == ret)
  {
    GNUNET_assert (NULL != ctx.k);
    return ctx.k;
  }
  return NULL;
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
 * @parem received was this element received from the remote peer?
 */
static void
op_register_element (struct Operation *op,
                     struct ElementEntry *ee,
                     int received)
{
  struct IBF_Key ibf_key;
  struct KeyEntry *k;

  ibf_key = get_ibf_key (&ee->element_hash);
  k = GNUNET_new (struct KeyEntry);
  k->element = ee;
  k->ibf_key = ibf_key;
  k->received = received;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap32_put (op->state->key_to_element,
                                                      (uint32_t) ibf_key.key_val,
                                                      k,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
}


/**
 * FIXME.
 */
static void
salt_key (const struct IBF_Key *k_in,
          uint32_t salt,
          struct IBF_Key *k_out)
{
  int s = salt % 64;
  uint64_t x = k_in->key_val;
  /* rotate ibf key */
  x = (x >> s) | (x << (64 - s));
  k_out->key_val = x;
}


/**
 * FIXME.
 */
static void
unsalt_key (const struct IBF_Key *k_in,
            uint32_t salt,
            struct IBF_Key *k_out)
{
  int s = salt % 64;
  uint64_t x = k_in->key_val;
  x = (x << s) | (x >> (64 - s));
  k_out->key_val = x;
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
  struct IBF_Key salted_key;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "[OP %x] inserting %lx (hash %s) into ibf\n",
       (void *) op,
       (unsigned long) ke->ibf_key.key_val,
       GNUNET_h2s (&ke->element->element_hash));
  salt_key (&ke->ibf_key,
            op->state->salt_send,
            &salted_key);
  ibf_insert (op->state->local_ibf, salted_key);
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
  if (GNUNET_NO ==
      _GSS_is_element_of_operation (ee,
                                    op))
    return GNUNET_YES;
  GNUNET_assert (GNUNET_NO == ee->remote);
  op_register_element (op,
                       ee,
                       GNUNET_NO);
  return GNUNET_YES;
}


/**
 * Initialize the IBF key to element mapping local to this set
 * operation.
 *
 * @param op the set union operation
 */
static void
initialize_key_to_element (struct Operation *op)
{
  unsigned int len;

  GNUNET_assert (NULL == op->state->key_to_element);
  len = GNUNET_CONTAINER_multihashmap_size (op->set->content->elements);
  op->state->key_to_element = GNUNET_CONTAINER_multihashmap32_create (len + 1);
  GNUNET_CONTAINER_multihashmap_iterate (op->set->content->elements,
                                         &init_key_to_element_iterator,
                                         op);
}


/**
 * Create an ibf with the operation's elements
 * of the specified size
 *
 * @param op the union operation
 * @param size size of the ibf to create
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
static int
prepare_ibf (struct Operation *op,
             uint32_t size)
{
  GNUNET_assert (NULL != op->state->key_to_element);

  if (NULL != op->state->local_ibf)
    ibf_destroy (op->state->local_ibf);
  op->state->local_ibf = ibf_create (size, SE_IBF_HASH_NUM);
  if (NULL == op->state->local_ibf)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to allocate local IBF\n");
    return GNUNET_SYSERR;
  }
  GNUNET_CONTAINER_multihashmap32_iterate (op->state->key_to_element,
                                           &prepare_ibf_iterator,
                                           op);
  return GNUNET_OK;
}


/**
 * Send an ibf of appropriate size.
 *
 * Fragments the IBF into multiple messages if necessary.
 *
 * @param op the union operation
 * @param ibf_order order of the ibf to send, size=2^order
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
static int
send_ibf (struct Operation *op,
          uint16_t ibf_order)
{
  unsigned int buckets_sent = 0;
  struct InvertibleBloomFilter *ibf;

  if (GNUNET_OK !=
      prepare_ibf (op, 1<<ibf_order))
  {
    /* allocation failed */
    return GNUNET_SYSERR;
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "sending ibf of size %u\n",
       1<<ibf_order);

  {
    char name[64] = { 0 };
    snprintf (name, sizeof (name), "# sent IBF (order %u)", ibf_order);
    GNUNET_STATISTICS_update (_GSS_statistics, name, 1, GNUNET_NO);
  }

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
    msg->reserved1 = 0;
    msg->reserved2 = 0;
    msg->order = ibf_order;
    msg->offset = htonl (buckets_sent);
    msg->salt = htonl (op->state->salt_send);
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
  return GNUNET_OK;
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
  while ( ( (1<<ibf_order) < (IBF_ALPHA * diff) ||
            ((1<<ibf_order) < SE_IBF_HASH_NUM) ) &&
          (ibf_order < MAX_IBF_ORDER) )
    ibf_order++;
  // add one for correction
  return ibf_order + 1;
}


/**
 * Send a set element.
 *
 * @param cls the union operation `struct Operation *`
 * @param key unused
 * @param value the `struct ElementEntry *` to insert
 *        into the key-to-element mapping
 * @return #GNUNET_YES (to continue iterating)
 */
static int
send_full_element_iterator (void *cls,
                       const struct GNUNET_HashCode *key,
                       void *value)
{
  struct Operation *op = cls;
  struct GNUNET_SET_ElementMessage *emsg;
  struct ElementEntry *ee = value;
  struct GNUNET_SET_Element *el = &ee->element;
  struct GNUNET_MQ_Envelope *ev;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending element %s\n",
       GNUNET_h2s (key));
  ev = GNUNET_MQ_msg_extra (emsg,
                            el->size,
                            GNUNET_MESSAGE_TYPE_SET_UNION_P2P_FULL_ELEMENT);
  emsg->element_type = htons (el->element_type);
  GNUNET_memcpy (&emsg[1],
                 el->data,
                 el->size);
  GNUNET_MQ_send (op->mq,
                  ev);
  return GNUNET_YES;
}


/**
 * Switch to full set transmission for @a op.
 *
 * @param op operation to switch to full set transmission.
 */
static void
send_full_set (struct Operation *op)
{
  struct GNUNET_MQ_Envelope *ev;

  op->state->phase = PHASE_FULL_SENDING;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Dedicing to transmit the full set\n");
  /* FIXME: use a more memory-friendly way of doing this with an
     iterator, just as we do in the non-full case! */
  (void) GNUNET_CONTAINER_multihashmap_iterate (op->set->content->elements,
                                                &send_full_element_iterator,
                                                op);
  ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_SET_UNION_P2P_FULL_DONE);
  GNUNET_MQ_send (op->mq,
                  ev);
}


/**
 * Handle a strata estimator from a remote peer
 *
 * @param cls the union operation
 * @param msg the message
 */
int
check_union_p2p_strata_estimator (void *cls,
                                  const struct StrataEstimatorMessage *msg)
{
  struct Operation *op = cls;
  int is_compressed;
  size_t len;

  if (op->state->phase != PHASE_EXPECT_SE)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  is_compressed = (GNUNET_MESSAGE_TYPE_SET_UNION_P2P_SEC == htons (msg->header.type));
  len = ntohs (msg->header.size) - sizeof (struct StrataEstimatorMessage);
  if ( (GNUNET_NO == is_compressed) &&
       (len != SE_STRATA_COUNT * SE_IBF_SIZE * IBF_BUCKET_SIZE) )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle a strata estimator from a remote peer
 *
 * @param cls the union operation
 * @param msg the message
 */
void
handle_union_p2p_strata_estimator (void *cls,
                                   const struct StrataEstimatorMessage *msg)
{
  struct Operation *op = cls;
  struct StrataEstimator *remote_se;
  unsigned int diff;
  uint64_t other_size;
  size_t len;
  int is_compressed;

  is_compressed = (GNUNET_MESSAGE_TYPE_SET_UNION_P2P_SEC == htons (msg->header.type));
  GNUNET_STATISTICS_update (_GSS_statistics,
                            "# bytes of SE received",
                            ntohs (msg->header.size),
                            GNUNET_NO);
  len = ntohs (msg->header.size) - sizeof (struct StrataEstimatorMessage);
  other_size = GNUNET_ntohll (msg->set_size);
  remote_se = strata_estimator_create (SE_STRATA_COUNT,
                                       SE_IBF_SIZE,
                                       SE_IBF_HASH_NUM);
  if (NULL == remote_se)
  {
    /* insufficient resources, fail */
    fail_union_operation (op);
    return;
  }
  if (GNUNET_OK !=
      strata_estimator_read (&msg[1],
                             len,
                             is_compressed,
                             remote_se))
  {
    /* decompression failed */
    strata_estimator_destroy (remote_se);
    fail_union_operation (op);
    return;
  }
  GNUNET_assert (NULL != op->state->se);
  diff = strata_estimator_difference (remote_se,
                                      op->state->se);

  if (diff > 200)
    diff = diff * 3 / 2;

  strata_estimator_destroy (remote_se);
  strata_estimator_destroy (op->state->se);
  op->state->se = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "got se diff=%d, using ibf size %d\n",
       diff,
       1U << get_order_from_difference (diff));

  {
    char *set_debug;

    set_debug = getenv ("GNUNET_SET_BENCHMARK");
    if ( (NULL != set_debug) &&
         (0 == strcmp (set_debug, "1")) )
    {
      FILE *f = fopen ("set.log", "a");
      fprintf (f, "%llu\n", (unsigned long long) diff);
      fclose (f);
    }
  }

  if ( (GNUNET_YES == op->byzantine) &&
       (other_size < op->byzantine_lower_bound) )
  {
    GNUNET_break (0);
    fail_union_operation (op);
    return;
  }

  if ( (GNUNET_YES == op->force_full) ||
       (diff > op->state->initial_size / 4) ||
       (0 == other_size) )
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Deciding to go for full set transmission (diff=%d, own set=%u)\n",
         diff,
         op->state->initial_size);
    GNUNET_STATISTICS_update (_GSS_statistics,
                              "# of full sends",
                              1,
                              GNUNET_NO);
    if ( (op->state->initial_size <= other_size) ||
         (0 == other_size) )
    {
      send_full_set (op);
    }
    else
    {
      struct GNUNET_MQ_Envelope *ev;

      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Telling other peer that we expect its full set\n");
      op->state->phase = PHASE_EXPECT_IBF;
      ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_SET_UNION_P2P_REQUEST_FULL);
      GNUNET_MQ_send (op->mq,
                      ev);
    }
  }
  else
  {
    GNUNET_STATISTICS_update (_GSS_statistics,
                              "# of ibf sends",
                              1,
                              GNUNET_NO);
    if (GNUNET_OK !=
        send_ibf (op,
                  get_order_from_difference (diff)))
    {
      /* Internal error, best we can do is shut the connection */
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Failed to send IBF, closing connection\n");
      fail_union_operation (op);
      return;
    }
  }
  GNUNET_CADET_receive_done (op->channel);
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
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
static int
decode_and_send (struct Operation *op)
{
  struct IBF_Key key;
  struct IBF_Key last_key;
  int side;
  unsigned int num_decoded;
  struct InvertibleBloomFilter *diff_ibf;

  GNUNET_assert (PHASE_INVENTORY_ACTIVE == op->state->phase);

  if (GNUNET_OK !=
      prepare_ibf (op,
                   op->state->remote_ibf->size))
  {
    GNUNET_break (0);
    /* allocation failed */
    return GNUNET_SYSERR;
  }
  diff_ibf = ibf_dup (op->state->local_ibf);
  ibf_subtract (diff_ibf,
                op->state->remote_ibf);

  ibf_destroy (op->state->remote_ibf);
  op->state->remote_ibf = NULL;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "decoding IBF (size=%u)\n",
       diff_ibf->size);

  num_decoded = 0;
  key.key_val = 0; /* just to avoid compiler thinking we use undef'ed variable */

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
           ( (num_decoded > 1) &&
             (last_key.key_val == key.key_val) ) )
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
        GNUNET_STATISTICS_update (_GSS_statistics,
                                  "# of IBF retries",
                                  1,
                                  GNUNET_NO);
        op->state->salt_send++;
        if (GNUNET_OK !=
            send_ibf (op, next_order))
        {
          /* Internal error, best we can do is shut the connection */
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                      "Failed to send IBF, closing connection\n");
          fail_union_operation (op);
          ibf_destroy (diff_ibf);
          return GNUNET_SYSERR;
        }
      }
      else
      {
        GNUNET_STATISTICS_update (_GSS_statistics,
                                  "# of failed union operations (too large)",
                                  1,
                                  GNUNET_NO);
        // XXX: Send the whole set, element-by-element
        LOG (GNUNET_ERROR_TYPE_ERROR,
             "set union failed: reached ibf limit\n");
        fail_union_operation (op);
        ibf_destroy (diff_ibf);
        return GNUNET_SYSERR;
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
      struct IBF_Key unsalted_key;

      unsalt_key (&key,
                  op->state->salt_receive,
                  &unsalted_key);
      send_offers_for_key (op,
                           unsalted_key);
    }
    else if (-1 == side)
    {
      struct GNUNET_MQ_Envelope *ev;
      struct InquiryMessage *msg;

      /* It may be nice to merge multiple requests, but with CADET's corking it is not worth
       * the effort additional complexity. */
      ev = GNUNET_MQ_msg_extra (msg,
                                sizeof (struct IBF_Key),
                                GNUNET_MESSAGE_TYPE_SET_UNION_P2P_INQUIRY);
      msg->salt = htonl (op->state->salt_receive);
      GNUNET_memcpy (&msg[1],
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
  return GNUNET_OK;
}


/**
 * Check an IBF message from a remote peer.
 *
 * Reassemble the IBF from multiple pieces, and
 * process the whole IBF once possible.
 *
 * @param cls the union operation
 * @param msg the header of the message
 * @return #GNUNET_OK if @a msg is well-formed
 */
int
check_union_p2p_ibf (void *cls,
                     const struct IBFMessage *msg)
{
  struct Operation *op = cls;
  unsigned int buckets_in_message;

  if (GNUNET_SET_OPERATION_UNION != op->set->operation)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  buckets_in_message = (ntohs (msg->header.size) - sizeof *msg) / IBF_BUCKET_SIZE;
  if (0 == buckets_in_message)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if ((ntohs (msg->header.size) - sizeof *msg) != buckets_in_message * IBF_BUCKET_SIZE)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (op->state->phase == PHASE_EXPECT_IBF_CONT)
  {
    if (ntohl (msg->offset) != op->state->ibf_buckets_received)
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
    if (1<<msg->order != op->state->remote_ibf->size)
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
    if (ntohl (msg->salt) != op->state->salt_receive)
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  }
  else if ( (op->state->phase != PHASE_INVENTORY_PASSIVE) &&
            (op->state->phase != PHASE_EXPECT_IBF) )
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }

  return GNUNET_OK;
}


/**
 * Handle an IBF message from a remote peer.
 *
 * Reassemble the IBF from multiple pieces, and
 * process the whole IBF once possible.
 *
 * @param cls the union operation
 * @param msg the header of the message
 */
void
handle_union_p2p_ibf (void *cls,
                      const struct IBFMessage *msg)
{
  struct Operation *op = cls;
  unsigned int buckets_in_message;

  buckets_in_message = (ntohs (msg->header.size) - sizeof *msg) / IBF_BUCKET_SIZE;
  if ( (op->state->phase == PHASE_INVENTORY_PASSIVE) ||
       (op->state->phase == PHASE_EXPECT_IBF) )
  {
    op->state->phase = PHASE_EXPECT_IBF_CONT;
    GNUNET_assert (NULL == op->state->remote_ibf);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Creating new ibf of size %u\n",
         1 << msg->order);
    op->state->remote_ibf = ibf_create (1<<msg->order, SE_IBF_HASH_NUM);
    op->state->salt_receive = ntohl (msg->salt);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Receiving new IBF with salt %u\n",
         op->state->salt_receive);
    if (NULL == op->state->remote_ibf)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Failed to parse remote IBF, closing connection\n");
      fail_union_operation (op);
      return;
    }
    op->state->ibf_buckets_received = 0;
    if (0 != ntohl (msg->offset))
    {
      GNUNET_break_op (0);
      fail_union_operation (op);
      return;
    }
  }
  else
  {
    GNUNET_assert (op->state->phase == PHASE_EXPECT_IBF_CONT);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received more of IBF\n");
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
    if (GNUNET_OK !=
        decode_and_send (op))
    {
      /* Internal error, best we can do is shut down */
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Failed to decode IBF, closing connection\n");
      fail_union_operation (op);
      return;
    }
  }
  GNUNET_CADET_receive_done (op->channel);
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
  GNUNET_assert (0 != op->client_request_id);
  ev = GNUNET_MQ_msg_extra (rm, element->size, GNUNET_MESSAGE_TYPE_SET_RESULT);
  if (NULL == ev)
  {
    GNUNET_MQ_discard (ev);
    GNUNET_break (0);
    return;
  }
  rm->result_status = htons (status);
  rm->request_id = htonl (op->client_request_id);
  rm->element_type = htons (element->element_type);
  rm->current_size = GNUNET_htonll (GNUNET_CONTAINER_multihashmap32_size (op->state->key_to_element));
  GNUNET_memcpy (&rm[1],
                 element->data,
                 element->size);
  GNUNET_MQ_send (op->set->cs->mq,
                  ev);
}


/**
 * Destroy remote channel.
 *
 * @param op operation
 */
void destroy_channel (struct Operation *op)
{
  struct GNUNET_CADET_Channel *channel;

  if (NULL != (channel = op->channel))
  {
    /* This will free op; called conditionally as this helper function
       is also called from within the channel disconnect handler. */
    op->channel = NULL;
    GNUNET_CADET_channel_destroy (channel);
  }
}


/**
 * Signal to the client that the operation has finished and
 * destroy the operation.
 *
 * @param cls operation to destroy
 */
static void
send_client_done (void *cls)
{
  struct Operation *op = cls;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SET_ResultMessage *rm;

  if (GNUNET_YES == op->state->client_done_sent) {
    return;
  }

  if (PHASE_DONE != op->state->phase) {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "union operation failed\n");
    ev = GNUNET_MQ_msg (rm, GNUNET_MESSAGE_TYPE_SET_RESULT);
    rm->result_status = htons (GNUNET_SET_STATUS_FAILURE);
    rm->request_id = htonl (op->client_request_id);
    rm->element_type = htons (0);
    GNUNET_MQ_send (op->set->cs->mq,
                    ev);
    return;
  }

  op->state->client_done_sent = GNUNET_YES;

  LOG (GNUNET_ERROR_TYPE_INFO,
       "Signalling client that union operation is done\n");
  ev = GNUNET_MQ_msg (rm,
                      GNUNET_MESSAGE_TYPE_SET_RESULT);
  rm->request_id = htonl (op->client_request_id);
  rm->result_status = htons (GNUNET_SET_STATUS_DONE);
  rm->element_type = htons (0);
  rm->current_size = GNUNET_htonll (GNUNET_CONTAINER_multihashmap32_size (op->state->key_to_element));
  GNUNET_MQ_send (op->set->cs->mq,
                  ev);
}


/**
 * Tests if the operation is finished, and if so notify.
 *
 * @param op operation to check
 */
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
      GNUNET_MQ_send (op->mq,
                      ev);
      /* We now wait until the other peer sends P2P_OVER
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
      send_client_done (op);
      destroy_channel (op);
    }
  }
}


/**
 * Check an element message from a remote peer.
 *
 * @param cls the union operation
 * @param emsg the message
 */
int
check_union_p2p_elements (void *cls,
                          const struct GNUNET_SET_ElementMessage *emsg)
{
  struct Operation *op = cls;

  if (GNUNET_SET_OPERATION_UNION != op->set->operation)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (0 == GNUNET_CONTAINER_multihashmap_size (op->state->demanded_hashes))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle an element message from a remote peer.
 * Sent by the other peer either because we decoded an IBF and placed a demand,
 * or because the other peer switched to full set transmission.
 *
 * @param cls the union operation
 * @param emsg the message
 */
void
handle_union_p2p_elements (void *cls,
                           const struct GNUNET_SET_ElementMessage *emsg)
{
  struct Operation *op = cls;
  struct ElementEntry *ee;
  struct KeyEntry *ke;
  uint16_t element_size;

  element_size = ntohs (emsg->header.size) - sizeof (struct GNUNET_SET_ElementMessage);
  ee = GNUNET_malloc (sizeof (struct ElementEntry) + element_size);
  GNUNET_memcpy (&ee[1],
                 &emsg[1],
                 element_size);
  ee->element.size = element_size;
  ee->element.data = &ee[1];
  ee->element.element_type = ntohs (emsg->element_type);
  ee->remote = GNUNET_YES;
  GNUNET_SET_element_hash (&ee->element,
                           &ee->element_hash);
  if (GNUNET_NO ==
      GNUNET_CONTAINER_multihashmap_remove (op->state->demanded_hashes,
                                            &ee->element_hash,
                                            NULL))
  {
    /* We got something we didn't demand, since it's not in our map. */
    GNUNET_break_op (0);
    fail_union_operation (op);
    return;
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Got element (size %u, hash %s) from peer\n",
       (unsigned int) element_size,
       GNUNET_h2s (&ee->element_hash));

  GNUNET_STATISTICS_update (_GSS_statistics,
                            "# received elements",
                            1,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (_GSS_statistics,
                            "# exchanged elements",
                            1,
                            GNUNET_NO);

  op->state->received_total++;

  ke = op_get_element (op, &ee->element_hash);
  if (NULL != ke)
  {
    /* Got repeated element.  Should not happen since
     * we track demands. */
    GNUNET_STATISTICS_update (_GSS_statistics,
                              "# repeated elements",
                              1,
                              GNUNET_NO);
    ke->received = GNUNET_YES;
    GNUNET_free (ee);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Registering new element from remote peer\n");
    op->state->received_fresh++;
    op_register_element (op, ee, GNUNET_YES);
    /* only send results immediately if the client wants it */
    switch (op->result_mode)
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

  if ( (op->state->received_total > 8) &&
       (op->state->received_fresh < op->state->received_total / 3) )
  {
    /* The other peer gave us lots of old elements, there's something wrong. */
    GNUNET_break_op (0);
    fail_union_operation (op);
    return;
  }
  GNUNET_CADET_receive_done (op->channel);
  maybe_finish (op);
}


/**
 * Check a full element message from a remote peer.
 *
 * @param cls the union operation
 * @param emsg the message
 */
int
check_union_p2p_full_element (void *cls,
                              const struct GNUNET_SET_ElementMessage *emsg)
{
  struct Operation *op = cls;

  if (GNUNET_SET_OPERATION_UNION != op->set->operation)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  // FIXME: check that we expect full elements here?
  return GNUNET_OK;
}


/**
 * Handle an element message from a remote peer.
 *
 * @param cls the union operation
 * @param emsg the message
 */
void
handle_union_p2p_full_element (void *cls,
                               const struct GNUNET_SET_ElementMessage *emsg)
{
  struct Operation *op = cls;
  struct ElementEntry *ee;
  struct KeyEntry *ke;
  uint16_t element_size;

  element_size = ntohs (emsg->header.size) - sizeof (struct GNUNET_SET_ElementMessage);
  ee = GNUNET_malloc (sizeof (struct ElementEntry) + element_size);
  GNUNET_memcpy (&ee[1], &emsg[1], element_size);
  ee->element.size = element_size;
  ee->element.data = &ee[1];
  ee->element.element_type = ntohs (emsg->element_type);
  ee->remote = GNUNET_YES;
  GNUNET_SET_element_hash (&ee->element, &ee->element_hash);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Got element (full diff, size %u, hash %s) from peer\n",
       (unsigned int) element_size,
       GNUNET_h2s (&ee->element_hash));

  GNUNET_STATISTICS_update (_GSS_statistics,
                            "# received elements",
                            1,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (_GSS_statistics,
                            "# exchanged elements",
                            1,
                            GNUNET_NO);

  op->state->received_total++;

  ke = op_get_element (op, &ee->element_hash);
  if (NULL != ke)
  {
    /* Got repeated element.  Should not happen since
     * we track demands. */
    GNUNET_STATISTICS_update (_GSS_statistics,
                              "# repeated elements",
                              1,
                              GNUNET_NO);
    ke->received = GNUNET_YES;
    GNUNET_free (ee);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Registering new element from remote peer\n");
    op->state->received_fresh++;
    op_register_element (op, ee, GNUNET_YES);
    /* only send results immediately if the client wants it */
    switch (op->result_mode)
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

  if ( (GNUNET_YES == op->byzantine) &&
       (op->state->received_total > 384 + op->state->received_fresh * 4) &&
       (op->state->received_fresh < op->state->received_total / 6) )
  {
    /* The other peer gave us lots of old elements, there's something wrong. */
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Other peer sent only %llu/%llu fresh elements, failing operation\n",
         (unsigned long long) op->state->received_fresh,
         (unsigned long long) op->state->received_total);
    GNUNET_break_op (0);
    fail_union_operation (op);
    return;
  }
  GNUNET_CADET_receive_done (op->channel);
}


/**
 * Send offers (for GNUNET_Hash-es) in response
 * to inquiries (for IBF_Key-s).
 *
 * @param cls the union operation
 * @param msg the message
 */
int
check_union_p2p_inquiry (void *cls,
                         const struct InquiryMessage *msg)
{
  struct Operation *op = cls;
  unsigned int num_keys;

  if (GNUNET_SET_OPERATION_UNION != op->set->operation)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (op->state->phase != PHASE_INVENTORY_PASSIVE)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  num_keys = (ntohs (msg->header.size) - sizeof (struct InquiryMessage))
    / sizeof (struct IBF_Key);
  if ((ntohs (msg->header.size) - sizeof (struct InquiryMessage))
      != num_keys * sizeof (struct IBF_Key))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Send offers (for GNUNET_Hash-es) in response
 * to inquiries (for IBF_Key-s).
 *
 * @param cls the union operation
 * @param msg the message
 */
void
handle_union_p2p_inquiry (void *cls,
                          const struct InquiryMessage *msg)
{
  struct Operation *op = cls;
  const struct IBF_Key *ibf_key;
  unsigned int num_keys;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received union inquiry\n");
  num_keys = (ntohs (msg->header.size) - sizeof (struct InquiryMessage))
    / sizeof (struct IBF_Key);
  ibf_key = (const struct IBF_Key *) &msg[1];
  while (0 != num_keys--)
  {
    struct IBF_Key unsalted_key;

    unsalt_key (ibf_key,
                ntohl (msg->salt),
                &unsalted_key);
    send_offers_for_key (op,
                         unsalted_key);
    ibf_key++;
  }
  GNUNET_CADET_receive_done (op->channel);
}


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
send_missing_full_elements_iter (void *cls,
                                 uint32_t key,
                                 void *value)
{
  struct Operation *op = cls;
  struct KeyEntry *ke = value;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SET_ElementMessage *emsg;
  struct ElementEntry *ee = ke->element;

  if (GNUNET_YES == ke->received)
    return GNUNET_YES;
  ev = GNUNET_MQ_msg_extra (emsg,
                            ee->element.size,
                            GNUNET_MESSAGE_TYPE_SET_UNION_P2P_FULL_ELEMENT);
  GNUNET_memcpy (&emsg[1],
                 ee->element.data,
                 ee->element.size);
  emsg->element_type = htons (ee->element.element_type);
  GNUNET_MQ_send (op->mq,
                  ev);
  return GNUNET_YES;
}


/**
 * Handle a request for full set transmission.
 *
 * @parem cls closure, a set union operation
 * @param mh the demand message
 */
void
handle_union_p2p_request_full (void *cls,
                               const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received request for full set transmission\n");
  if (GNUNET_SET_OPERATION_UNION != op->set->operation)
  {
    GNUNET_break_op (0);
    fail_union_operation (op);
    return;
  }
  if (PHASE_EXPECT_IBF != op->state->phase)
  {
    GNUNET_break_op (0);
    fail_union_operation (op);
    return;
  }

  // FIXME: we need to check that our set is larger than the
  // byzantine_lower_bound by some threshold
  send_full_set (op);
  GNUNET_CADET_receive_done (op->channel);
}


/**
 * Handle a "full done" message.
 *
 * @parem cls closure, a set union operation
 * @param mh the demand message
 */
void
handle_union_p2p_full_done (void *cls,
                            const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;

  switch (op->state->phase)
  {
  case PHASE_EXPECT_IBF:
    {
      struct GNUNET_MQ_Envelope *ev;

      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "got FULL DONE, sending elements that other peer is missing\n");

      /* send all the elements that did not come from the remote peer */
      GNUNET_CONTAINER_multihashmap32_iterate (op->state->key_to_element,
                                               &send_missing_full_elements_iter,
                                               op);

      ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_SET_UNION_P2P_FULL_DONE);
      GNUNET_MQ_send (op->mq,
                      ev);
      op->state->phase = PHASE_DONE;
      /* we now wait until the other peer sends us the OVER message*/
    }
    break;
  case PHASE_FULL_SENDING:
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "got FULL DONE, finishing\n");
      /* We sent the full set, and got the response for that.  We're done. */
      op->state->phase = PHASE_DONE;
      GNUNET_CADET_receive_done (op->channel);
      send_client_done (op);
      destroy_channel (op);
      return;
    }
    break;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Handle full done phase is %u\n",
                (unsigned) op->state->phase);
    GNUNET_break_op (0);
    fail_union_operation (op);
    return;
  }
  GNUNET_CADET_receive_done (op->channel);
}


/**
 * Check a demand by the other peer for elements based on a list
 * of `struct GNUNET_HashCode`s.
 *
 * @parem cls closure, a set union operation
 * @param mh the demand message
 * @return #GNUNET_OK if @a mh is well-formed
 */
int
check_union_p2p_demand (void *cls,
                        const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;
  unsigned int num_hashes;

  if (GNUNET_SET_OPERATION_UNION != op->set->operation)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  num_hashes = (ntohs (mh->size) - sizeof (struct GNUNET_MessageHeader))
    / sizeof (struct GNUNET_HashCode);
  if ((ntohs (mh->size) - sizeof (struct GNUNET_MessageHeader))
      != num_hashes * sizeof (struct GNUNET_HashCode))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle a demand by the other peer for elements based on a list
 * of `struct GNUNET_HashCode`s.
 *
 * @parem cls closure, a set union operation
 * @param mh the demand message
 */
void
handle_union_p2p_demand (void *cls,
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
  for (hash = (const struct GNUNET_HashCode *) &mh[1];
       num_hashes > 0;
       hash++, num_hashes--)
  {
    ee = GNUNET_CONTAINER_multihashmap_get (op->set->content->elements,
                                            hash);
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
    GNUNET_memcpy (&emsg[1], ee->element.data, ee->element.size);
    emsg->reserved = htons (0);
    emsg->element_type = htons (ee->element.element_type);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "[OP %x] Sending demanded element (size %u, hash %s) to peer\n",
         (void *) op,
         (unsigned int) ee->element.size,
         GNUNET_h2s (&ee->element_hash));
    GNUNET_MQ_send (op->mq, ev);
    GNUNET_STATISTICS_update (_GSS_statistics,
                              "# exchanged elements",
                              1,
                              GNUNET_NO);

    switch (op->result_mode)
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
  GNUNET_CADET_receive_done (op->channel);
}


/**
 * Check offer (of `struct GNUNET_HashCode`s).
 *
 * @param cls the union operation
 * @param mh the message
 * @return #GNUNET_OK if @a mh is well-formed
 */
int
check_union_p2p_offer (void *cls,
                        const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;
  unsigned int num_hashes;

  if (GNUNET_SET_OPERATION_UNION != op->set->operation)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  /* look up elements and send them */
  if ( (op->state->phase != PHASE_INVENTORY_PASSIVE) &&
       (op->state->phase != PHASE_INVENTORY_ACTIVE))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  num_hashes = (ntohs (mh->size) - sizeof (struct GNUNET_MessageHeader))
    / sizeof (struct GNUNET_HashCode);
  if ((ntohs (mh->size) - sizeof (struct GNUNET_MessageHeader)) !=
      num_hashes * sizeof (struct GNUNET_HashCode))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle offers (of `struct GNUNET_HashCode`s) and
 * respond with demands (of `struct GNUNET_HashCode`s).
 *
 * @param cls the union operation
 * @param mh the message
 */
void
handle_union_p2p_offer (void *cls,
                        const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;
  const struct GNUNET_HashCode *hash;
  unsigned int num_hashes;

  num_hashes = (ntohs (mh->size) - sizeof (struct GNUNET_MessageHeader))
    / sizeof (struct GNUNET_HashCode);
  for (hash = (const struct GNUNET_HashCode *) &mh[1];
       num_hashes > 0;
       hash++, num_hashes--)
  {
    struct ElementEntry *ee;
    struct GNUNET_MessageHeader *demands;
    struct GNUNET_MQ_Envelope *ev;

    ee = GNUNET_CONTAINER_multihashmap_get (op->set->content->elements,
                                            hash);
    if (NULL != ee)
      if (GNUNET_YES == _GSS_is_element_of_operation (ee, op))
        continue;

    if (GNUNET_YES ==
        GNUNET_CONTAINER_multihashmap_contains (op->state->demanded_hashes,
                                                hash))
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
    ev = GNUNET_MQ_msg_header_extra (demands,
                                     sizeof (struct GNUNET_HashCode),
                                     GNUNET_MESSAGE_TYPE_SET_UNION_P2P_DEMAND);
    GNUNET_memcpy (&demands[1],
                   hash,
                   sizeof (struct GNUNET_HashCode));
    GNUNET_MQ_send (op->mq, ev);
  }
  GNUNET_CADET_receive_done (op->channel);
}


/**
 * Handle a done message from a remote peer
 *
 * @param cls the union operation
 * @param mh the message
 */
void
handle_union_p2p_done (void *cls,
                       const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;

  if (GNUNET_SET_OPERATION_UNION != op->set->operation)
  {
    GNUNET_break_op (0);
    fail_union_operation (op);
    return;
  }
  switch (op->state->phase)
  {
  case PHASE_INVENTORY_PASSIVE:
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
     * peer can quit if we gave it everything.
     */
    GNUNET_CADET_receive_done (op->channel);
    maybe_finish (op);
    return;
  case PHASE_INVENTORY_ACTIVE:
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
    GNUNET_CADET_receive_done (op->channel);
    maybe_finish (op);
    return;
  default:
    GNUNET_break_op (0);
    fail_union_operation (op);
    return;
  }
}

/**
 * Handle a over message from a remote peer
 *
 * @param cls the union operation
 * @param mh the message
 */
void
handle_union_p2p_over (void *cls,
                       const struct GNUNET_MessageHeader *mh)
{
  send_client_done (cls);
}


/**
 * Initiate operation to evaluate a set union with a remote peer.
 *
 * @param op operation to perform (to be initialized)
 * @param opaque_context message to be transmitted to the listener
 *        to convince it to accept, may be NULL
 */
static struct OperationState *
union_evaluate (struct Operation *op,
                const struct GNUNET_MessageHeader *opaque_context)
{
  struct OperationState *state;
  struct GNUNET_MQ_Envelope *ev;
  struct OperationRequestMessage *msg;

  ev = GNUNET_MQ_msg_nested_mh (msg,
                                GNUNET_MESSAGE_TYPE_SET_P2P_OPERATION_REQUEST,
                                opaque_context);
  if (NULL == ev)
  {
    /* the context message is too large */
    GNUNET_break (0);
    return NULL;
  }
  state = GNUNET_new (struct OperationState);
  state->demanded_hashes = GNUNET_CONTAINER_multihashmap_create (32,
                                                                 GNUNET_NO);
  /* copy the current generation's strata estimator for this operation */
  state->se = strata_estimator_dup (op->set->state->se);
  /* we started the operation, thus we have to send the operation request */
  state->phase = PHASE_EXPECT_SE;
  state->salt_receive = state->salt_send = 42; // FIXME?????
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Initiating union operation evaluation\n");
  GNUNET_STATISTICS_update (_GSS_statistics,
                            "# of total union operations",
                            1,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (_GSS_statistics,
                            "# of initiated union operations",
                            1,
                            GNUNET_NO);
  msg->operation = htonl (GNUNET_SET_OPERATION_UNION);
  GNUNET_MQ_send (op->mq,
                  ev);

  if (NULL != opaque_context)
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "sent op request with context message\n");
  else
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "sent op request without context message\n");

  op->state = state;
  initialize_key_to_element (op);
  state->initial_size = GNUNET_CONTAINER_multihashmap32_size (state->key_to_element);
  return state;
}


/**
 * Accept an union operation request from a remote peer.
 * Only initializes the private operation state.
 *
 * @param op operation that will be accepted as a union operation
 */
static struct OperationState *
union_accept (struct Operation *op)
{
  struct OperationState *state;
  const struct StrataEstimator *se;
  struct GNUNET_MQ_Envelope *ev;
  struct StrataEstimatorMessage *strata_msg;
  char *buf;
  size_t len;
  uint16_t type;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "accepting set union operation\n");
  GNUNET_STATISTICS_update (_GSS_statistics,
                            "# of accepted union operations",
                            1,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (_GSS_statistics,
                            "# of total union operations",
                            1,
                            GNUNET_NO);

  state = GNUNET_new (struct OperationState);
  state->se = strata_estimator_dup (op->set->state->se);
  state->demanded_hashes = GNUNET_CONTAINER_multihashmap_create (32,
                                                                 GNUNET_NO);
  state->salt_receive = state->salt_send = 42; // FIXME?????
  op->state = state;
  initialize_key_to_element (op);
  state->initial_size = GNUNET_CONTAINER_multihashmap32_size (state->key_to_element);

  /* kick off the operation */
  se = state->se;
  buf = GNUNET_malloc (se->strata_count * IBF_BUCKET_SIZE * se->ibf_size);
  len = strata_estimator_write (se,
                                buf);
  if (len < se->strata_count * IBF_BUCKET_SIZE * se->ibf_size)
    type = GNUNET_MESSAGE_TYPE_SET_UNION_P2P_SEC;
  else
    type = GNUNET_MESSAGE_TYPE_SET_UNION_P2P_SE;
  ev = GNUNET_MQ_msg_extra (strata_msg,
                            len,
                            type);
  GNUNET_memcpy (&strata_msg[1],
                 buf,
                 len);
  GNUNET_free (buf);
  strata_msg->set_size
    = GNUNET_htonll (GNUNET_CONTAINER_multihashmap_size (op->set->content->elements));
  GNUNET_MQ_send (op->mq,
                  ev);
  state->phase = PHASE_EXPECT_IBF;
  return state;
}


/**
 * Create a new set supporting the union operation
 *
 * We maintain one strata estimator per set and then manipulate it over the
 * lifetime of the set, as recreating a strata estimator would be expensive.
 *
 * @return the newly created set, NULL on error
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
  if (NULL == set_state->se)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to allocate strata estimator\n");
    GNUNET_free (set_state);
    return NULL;
  }
  return set_state;
}


/**
 * Add the element from the given element message to the set.
 *
 * @param set_state state of the set want to add to
 * @param ee the element to add to the set
 */
static void
union_add (struct SetState *set_state,
           struct ElementEntry *ee)
{
  strata_estimator_insert (set_state->se,
                           get_ibf_key (&ee->element_hash));
}


/**
 * Remove the element given in the element message from the set.
 * Only marks the element as removed, so that older set operations can still exchange it.
 *
 * @param set_state state of the set to remove from
 * @param ee set element to remove
 */
static void
union_remove (struct SetState *set_state,
              struct ElementEntry *ee)
{
  strata_estimator_remove (set_state->se,
                           get_ibf_key (&ee->element_hash));
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
 * Copy union-specific set state.
 *
 * @param state source state for copying the union state
 * @return a copy of the union-specific set state
 */
static struct SetState *
union_copy_state (struct SetState *state)
{
  struct SetState *new_state;

  GNUNET_assert ( (NULL != state) &&
                  (NULL != state->se) );
  new_state = GNUNET_new (struct SetState);
  new_state->se = strata_estimator_dup (state->se);

  return new_state;
}


/**
 * Handle case where channel went down for an operation.
 *
 * @param op operation that lost the channel
 */
static void
union_channel_death (struct Operation *op)
{
  send_client_done (op);
  _GSS_operation_destroy (op,
                          GNUNET_YES);
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
    .add = &union_add,
    .remove = &union_remove,
    .destroy_set = &union_set_destroy,
    .evaluate = &union_evaluate,
    .accept = &union_accept,
    .cancel = &union_op_cancel,
    .copy_state = &union_copy_state,
    .channel_death = &union_channel_death
  };

  return &union_vt;
}
