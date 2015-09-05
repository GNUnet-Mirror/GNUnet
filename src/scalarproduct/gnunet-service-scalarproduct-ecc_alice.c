/*
     This file is part of GNUnet.
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
 * @file scalarproduct/gnunet-service-scalarproduct-ecc_alice.c
 * @brief scalarproduct service implementation
 * @author Christian M. Fuchs
 * @author Christian Grothoff
 */
#include "platform.h"
#include <limits.h>
#include <gcrypt.h>
#include "gnunet_util_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_cadet_service.h"
#include "gnunet_applications.h"
#include "gnunet_protocols.h"
#include "gnunet_scalarproduct_service.h"
#include "gnunet_set_service.h"
#include "scalarproduct.h"
#include "gnunet-service-scalarproduct-ecc.h"

#define LOG(kind,...) GNUNET_log_from (kind, "scalarproduct-alice", __VA_ARGS__)

/**
 * Maximum allowed result value for the scalarproduct computation.
 * DLOG will fail if the result is bigger.  At 1 million, the
 * precomputation takes about 2s on a fast machine.
 */
#define MAX_RESULT (1024 * 1024)

/**
 * How many values should DLOG store in memory (determines baseline
 * RAM consumption, roughly 100 bytes times the value given here).
 * Should be about SQRT (MAX_RESULT), larger values will make the
 * online computation faster.
 */
#define MAX_RAM (1024)

/**
 * An encrypted element key-value pair.
 */
struct MpiElement
{
  /**
   * Key used to identify matching pairs of values to multiply.
   * Points into an existing data structure, to avoid copying
   * and doubling memory use.
   */
  const struct GNUNET_HashCode *key;

  /**
   * a_i value, not disclosed to Bob.
   */
  gcry_mpi_t value;

};


/**
 * A scalarproduct session which tracks
 * a request form the client to our final response.
 */
struct AliceServiceSession
{

  /**
   * (hopefully) unique transaction ID
   */
  struct GNUNET_HashCode session_id;

  /**
   * Alice or Bob's peerID
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * The client this request is related to.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * The message queue for the client.
   */
  struct GNUNET_MQ_Handle *client_mq;

  /**
   * The message queue for CADET.
   */
  struct GNUNET_MQ_Handle *cadet_mq;

  /**
   * all non-0-value'd elements transmitted to us.
   * Values are of type `struct GNUNET_SCALARPRODUCT_Element *`
   */
  struct GNUNET_CONTAINER_MultiHashMap *intersected_elements;

  /**
   * Set of elements for which will conduction an intersection.
   * the resulting elements are then used for computing the scalar product.
   */
  struct GNUNET_SET_Handle *intersection_set;

  /**
   * Set of elements for which will conduction an intersection.
   * the resulting elements are then used for computing the scalar product.
   */
  struct GNUNET_SET_OperationHandle *intersection_op;

  /**
   * Handle to Alice's Intersection operation listening for Bob
   */
  struct GNUNET_SET_ListenHandle *intersection_listen;

  /**
   * channel-handle associated with our cadet handle
   */
  struct GNUNET_CADET_Channel *channel;

  /**
   * a(Alice), sorted array by key of length @e used_element_count.
   */
  struct MpiElement *sorted_elements;

  /**
   * The computed scalar
   */
  gcry_mpi_t product;

  /**
   * How many elements we were supplied with from the client (total
   * count before intersection).
   */
  uint32_t total;

  /**
   * How many elements actually are used for the scalar product.
   * Size of the arrays in @e r and @e r_prime.  Sometimes also
   * reset to 0 and used as a counter!
   */
  uint32_t used_element_count;

  /**
   * Already transferred elements from client to us.
   * Less or equal than @e total.
   */
  uint32_t client_received_element_count;

  /**
   * State of this session.   In
   * #GNUNET_SCALARPRODUCT_STATUS_ACTIVE while operation is
   * ongoing, afterwards in #GNUNET_SCALARPRODUCT_STATUS_SUCCESS or
   * #GNUNET_SCALARPRODUCT_STATUS_FAILURE.
   */
  enum GNUNET_SCALARPRODUCT_ResponseStatus status;

  /**
   * Flag to prevent recursive calls to #destroy_service_session() from
   * doing harm.
   */
  int in_destroy;

};


/**
 * GNUnet configuration handle
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Context for DLOG operations on a curve.
 */
static struct GNUNET_CRYPTO_EccDlogContext *edc;

/**
 * Alice's private key ('a').
 */
static gcry_mpi_t my_privkey;

/**
 * Inverse of Alice's private key ('a_inv').
 */
static gcry_mpi_t my_privkey_inv;

/**
 * Handle to the CADET service.
 */
static struct GNUNET_CADET_Handle *my_cadet;


/**
 * Iterator called to free elements.
 *
 * @param cls the `struct AliceServiceSession *` (unused)
 * @param key the key (unused)
 * @param value value to free
 * @return #GNUNET_OK (continue to iterate)
 */
static int
free_element_cb (void *cls,
                 const struct GNUNET_HashCode *key,
                 void *value)
{
  struct GNUNET_SCALARPRODUCT_Element *e = value;

  GNUNET_free (e);
  return GNUNET_OK;
}


/**
 * Destroy session state, we are done with it.
 *
 * @param s the session to free elements from
 */
static void
destroy_service_session (struct AliceServiceSession *s)
{
  unsigned int i;

  if (GNUNET_YES == s->in_destroy)
    return;
  s->in_destroy = GNUNET_YES;
  if (NULL != s->client_mq)
  {
    GNUNET_MQ_destroy (s->client_mq);
    s->client_mq = NULL;
  }
  if (NULL != s->cadet_mq)
  {
    GNUNET_MQ_destroy (s->cadet_mq);
    s->cadet_mq = NULL;
  }
  if (NULL != s->client)
  {
    GNUNET_SERVER_client_set_user_context (s->client,
                                           NULL);
    GNUNET_SERVER_client_disconnect (s->client);
    s->client = NULL;
  }
  if (NULL != s->channel)
  {
    GNUNET_CADET_channel_destroy (s->channel);
    s->channel = NULL;
  }
  if (NULL != s->intersected_elements)
  {
    GNUNET_CONTAINER_multihashmap_iterate (s->intersected_elements,
                                           &free_element_cb,
                                           s);
    GNUNET_CONTAINER_multihashmap_destroy (s->intersected_elements);
    s->intersected_elements = NULL;
  }
  if (NULL != s->intersection_listen)
  {
    GNUNET_SET_listen_cancel (s->intersection_listen);
    s->intersection_listen = NULL;
  }
  if (NULL != s->intersection_op)
  {
    GNUNET_SET_operation_cancel (s->intersection_op);
    s->intersection_op = NULL;
  }
  if (NULL != s->intersection_set)
  {
    GNUNET_SET_destroy (s->intersection_set);
    s->intersection_set = NULL;
  }
  if (NULL != s->sorted_elements)
  {
    for (i=0;i<s->used_element_count;i++)
      gcry_mpi_release (s->sorted_elements[i].value);
    GNUNET_free (s->sorted_elements);
    s->sorted_elements = NULL;
  }
  if (NULL != s->product)
  {
    gcry_mpi_release (s->product);
    s->product = NULL;
  }
  GNUNET_free (s);
}


/**
 * Notify the client that the session has failed.  A message gets sent
 * to Alice's client if we encountered any error.
 *
 * @param session the associated client session to fail or succeed
 */
static void
prepare_client_end_notification (struct AliceServiceSession *session)
{
  struct ClientResponseMessage *msg;
  struct GNUNET_MQ_Envelope *e;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending session-end notification with status %d to client for session %s\n",
              session->status,
              GNUNET_h2s (&session->session_id));
  e = GNUNET_MQ_msg (msg,
                     GNUNET_MESSAGE_TYPE_SCALARPRODUCT_RESULT);
  msg->product_length = htonl (0);
  msg->status = htonl (session->status);
  GNUNET_MQ_send (session->client_mq,
                  e);
}


/**
 * Prepare the final (positive) response we will send to Alice's
 * client.
 *
 * @param s the session associated with our client.
 */
static void
transmit_client_response (struct AliceServiceSession *s)
{
  struct ClientResponseMessage *msg;
  struct GNUNET_MQ_Envelope *e;
  unsigned char *product_exported = NULL;
  size_t product_length = 0;
  int32_t range;
  gcry_error_t rc;
  int sign;
  gcry_mpi_t value;

  if (NULL == s->product)
  {
    GNUNET_break (0);
    prepare_client_end_notification (s);
    return;
  }
  value = gcry_mpi_new (0);
  sign = gcry_mpi_cmp_ui (s->product, 0);
  if (0 > sign)
  {
    range = -1;
    gcry_mpi_sub (value,
                  value,
                  s->product);
  }
  else if (0 < sign)
  {
    range = 1;
    gcry_mpi_add (value, value, s->product);
  }
  else
  {
    /* result is exactly zero */
    range = 0;
  }
  gcry_mpi_release (s->product);
  s->product = NULL;

  if ( (0 != range) &&
       (0 != (rc = gcry_mpi_aprint (GCRYMPI_FMT_STD,
                                    &product_exported,
                                    &product_length,
                                    value))))
  {
    LOG_GCRY (GNUNET_ERROR_TYPE_ERROR,
              "gcry_mpi_scan",
              rc);
    prepare_client_end_notification (s);
    return;
  }
  gcry_mpi_release (value);
  e = GNUNET_MQ_msg_extra (msg,
                           product_length,
                           GNUNET_MESSAGE_TYPE_SCALARPRODUCT_RESULT);
  msg->status = htonl (GNUNET_SCALARPRODUCT_STATUS_SUCCESS);
  msg->range = htonl (range);
  msg->product_length = htonl (product_length);
  if (NULL != product_exported)
  {
    memcpy (&msg[1],
            product_exported,
            product_length);
    GNUNET_free (product_exported);
  }
  GNUNET_MQ_send (s->client_mq,
                  e);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sent result to client, session %s has ended!\n",
              GNUNET_h2s (&s->session_id));
}



/**
 * Function called whenever a channel is destroyed.  Should clean up
 * any associated state.
 *
 * It must NOT call #GNUNET_CADET_channel_destroy() on the channel.
 *
 * @param cls closure (set from #GNUNET_CADET_connect())
 * @param channel connection to the other end (henceforth invalid)
 * @param channel_ctx place where local state associated
 *                   with the channel is stored
 */
static void
cb_channel_destruction (void *cls,
                        const struct GNUNET_CADET_Channel *channel,
                        void *channel_ctx)
{
  struct AliceServiceSession *s = channel_ctx;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer disconnected, terminating session %s with peer %s\n",
              GNUNET_h2s (&s->session_id),
              GNUNET_i2s (&s->peer));
  if (NULL != s->cadet_mq)
  {
    GNUNET_MQ_destroy (s->cadet_mq);
    s->cadet_mq = NULL;
  }
  s->channel = NULL;
  if (GNUNET_SCALARPRODUCT_STATUS_ACTIVE == s->status)
  {
    /* We didn't get an answer yet, fail with error */
    s->status = GNUNET_SCALARPRODUCT_STATUS_FAILURE;
    prepare_client_end_notification (s);
  }
}


/**
 * Compute our scalar product, done by Alice
 *
 * @param session the session associated with this computation
 * @param prod_g_i_b_i value from Bob
 * @param prod_h_i_b_i value from Bob
 * @return product as MPI, never NULL
 */
static gcry_mpi_t
compute_scalar_product (struct AliceServiceSession *session,
                        gcry_mpi_point_t prod_g_i_b_i,
                        gcry_mpi_point_t prod_h_i_b_i)
{
  gcry_mpi_point_t g_i_b_i_a_inv;
  gcry_mpi_point_t g_ai_bi;
  int ai_bi;
  gcry_mpi_t ret;

  g_i_b_i_a_inv = GNUNET_CRYPTO_ecc_pmul_mpi (edc,
                                              prod_g_i_b_i,
                                              my_privkey_inv);
  g_ai_bi = GNUNET_CRYPTO_ecc_add (edc,
                                   g_i_b_i_a_inv,
                                   prod_h_i_b_i);
  gcry_mpi_point_release (g_i_b_i_a_inv);
  ai_bi = GNUNET_CRYPTO_ecc_dlog (edc,
                                  g_ai_bi);
  gcry_mpi_point_release (g_ai_bi);
  if (MAX_RESULT == ai_bi)
  {
    /* result too big */
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Scalar product result out of range\n");
    return NULL;
  }
  ret = gcry_mpi_new (0);
  if (ai_bi > 0)
  {
    gcry_mpi_set_ui (ret, ai_bi);
  }
  else
  {
    gcry_mpi_set_ui (ret, - ai_bi);
    gcry_mpi_neg (ret, ret);
  }
  return ret;
}


/**
 * Handle a response we got from another service we wanted to
 * calculate a scalarproduct with.
 *
 * @param cls closure (set from #GNUNET_CADET_connect)
 * @param channel connection to the other end
 * @param channel_ctx place to store local state associated with the channel
 * @param message the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (we are done)
 */
static int
handle_bobs_cryptodata_message (void *cls,
                                struct GNUNET_CADET_Channel *channel,
                                void **channel_ctx,
                                const struct GNUNET_MessageHeader *message)
{
  struct AliceServiceSession *s = *channel_ctx;
  const struct EccBobCryptodataMessage *msg;
  uint32_t contained;
  uint16_t msg_size;
  gcry_mpi_point_t prod_g_i_b_i;
  gcry_mpi_point_t prod_h_i_b_i;

  if (NULL == s)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  msg_size = ntohs (message->size);
  if (sizeof (struct EccBobCryptodataMessage) > msg_size)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  msg = (const struct EccBobCryptodataMessage *) message;
  contained = ntohl (msg->contained_element_count);
  if (2 != contained)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (NULL == s->sorted_elements)
  {
    /* we're not ready yet, how can Bob be? */
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (s->total != s->client_received_element_count)
  {
    /* we're not ready yet, how can Bob be? */
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received %u crypto values from Bob\n",
              (unsigned int) contained);
  GNUNET_CADET_receive_done (s->channel);
  prod_g_i_b_i = GNUNET_CRYPTO_ecc_bin_to_point (edc,
                                                 &msg->prod_g_i_b_i);
  prod_h_i_b_i = GNUNET_CRYPTO_ecc_bin_to_point (edc,
                                                 &msg->prod_h_i_b_i);
  s->product = compute_scalar_product (s,
                                       prod_g_i_b_i,
                                       prod_h_i_b_i);
  gcry_mpi_point_release (prod_g_i_b_i);
  gcry_mpi_point_release (prod_h_i_b_i);
  transmit_client_response (s);
  return GNUNET_OK;
}


/**
 * Iterator to copy over messages from the hash map
 * into an array for sorting.
 *
 * @param cls the `struct AliceServiceSession *`
 * @param key the key (unused)
 * @param value the `struct GNUNET_SCALARPRODUCT_Element *`
 */
static int
copy_element_cb (void *cls,
                 const struct GNUNET_HashCode *key,
                 void *value)
{
  struct AliceServiceSession *s = cls;
  struct GNUNET_SCALARPRODUCT_Element *e = value;
  gcry_mpi_t mval;
  int64_t val;

  mval = gcry_mpi_new (0);
  val = (int64_t) GNUNET_ntohll (e->value);
  if (0 > val)
    gcry_mpi_sub_ui (mval, mval, -val);
  else
    gcry_mpi_add_ui (mval, mval, val);
  s->sorted_elements [s->used_element_count].value = mval;
  s->sorted_elements [s->used_element_count].key = &e->key;
  s->used_element_count++;
  return GNUNET_OK;
}


/**
 * Compare two `struct MpiValue`s by key for sorting.
 *
 * @param a pointer to first `struct MpiValue *`
 * @param b pointer to first `struct MpiValue *`
 * @return -1 for a < b, 0 for a=b, 1 for a > b.
 */
static int
element_cmp (const void *a,
             const void *b)
{
  const struct MpiElement *ma = a;
  const struct MpiElement *mb = b;

  return GNUNET_CRYPTO_hash_cmp (ma->key,
                                 mb->key);
}


/**
 * Maximum number of elements we can put into a single cryptodata
 * message
 */
#define ELEMENT_CAPACITY ((GNUNET_CONSTANTS_MAX_CADET_MESSAGE_SIZE - 1 - sizeof (struct EccAliceCryptodataMessage)) / sizeof (struct GNUNET_CRYPTO_EccPoint))


/**
 * Send the cryptographic data from Alice to Bob.
 * Does nothing if we already transferred all elements.
 *
 * @param s the associated service session
 */
static void
send_alices_cryptodata_message (struct AliceServiceSession *s)
{
  struct EccAliceCryptodataMessage *msg;
  struct GNUNET_MQ_Envelope *e;
  struct GNUNET_CRYPTO_EccPoint *payload;
  gcry_mpi_t r_ia;
  gcry_mpi_t r_ia_ai;
  unsigned int i;
  unsigned int off;
  unsigned int todo_count;

  s->sorted_elements
    = GNUNET_malloc (GNUNET_CONTAINER_multihashmap_size (s->intersected_elements) *
                     sizeof (struct MpiElement));
  s->used_element_count = 0;
  GNUNET_CONTAINER_multihashmap_iterate (s->intersected_elements,
                                         &copy_element_cb,
                                         s);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Finished intersection, %d items remain\n",
       s->used_element_count);
  qsort (s->sorted_elements,
         s->used_element_count,
         sizeof (struct MpiElement),
         &element_cmp);
  off = 0;
  while (off < s->used_element_count)
  {
    todo_count = s->used_element_count - off;
    if (todo_count > ELEMENT_CAPACITY)
      todo_count = ELEMENT_CAPACITY;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending %u/%u crypto values to Bob\n",
                (unsigned int) todo_count,
                (unsigned int) s->used_element_count);

    e = GNUNET_MQ_msg_extra (msg,
                             todo_count * 2 * sizeof (struct GNUNET_CRYPTO_EccPoint),
                             GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ECC_ALICE_CRYPTODATA);
    msg->contained_element_count = htonl (todo_count);
    payload = (struct GNUNET_CRYPTO_EccPoint *) &msg[1];
    r_ia = gcry_mpi_new (0);
    r_ia_ai = gcry_mpi_new (0);
    for (i = off; i < off + todo_count; i++)
    {
      gcry_mpi_t r_i;
      gcry_mpi_point_t g_i;
      gcry_mpi_point_t h_i;

      r_i = GNUNET_CRYPTO_ecc_random_mod_n (edc);
      g_i = GNUNET_CRYPTO_ecc_dexp_mpi (edc,
                                        r_i);
      /* r_ia = r_i * a */
      gcry_mpi_mul (r_ia,
                    r_i,
                    my_privkey);
      gcry_mpi_release (r_i);
      /* r_ia_ai = r_ia + a_i */
      gcry_mpi_add (r_ia_ai,
                    r_ia,
                    s->sorted_elements[i].value);
      h_i = GNUNET_CRYPTO_ecc_dexp_mpi (edc,
                                        r_ia_ai);
      GNUNET_CRYPTO_ecc_point_to_bin (edc,
                                      g_i,
                                      &payload[(i - off) * 2]);
      GNUNET_CRYPTO_ecc_point_to_bin (edc,
                                      h_i,
                                      &payload[(i - off) * 2 + 1]);
      gcry_mpi_point_release (g_i);
      gcry_mpi_point_release (h_i);
    }
    gcry_mpi_release (r_ia);
    gcry_mpi_release (r_ia_ai);
    off += todo_count;
    GNUNET_MQ_send (s->cadet_mq,
                    e);
  }
}


/**
 * Callback for set operation results. Called for each element
 * that should be removed from the result set, and then once
 * to indicate that the set intersection operation is done.
 *
 * @param cls closure with the `struct AliceServiceSession`
 * @param element a result element, only valid if status is #GNUNET_SET_STATUS_OK
 * @param status what has happened with the set intersection?
 */
static void
cb_intersection_element_removed (void *cls,
                                 const struct GNUNET_SET_Element *element,
                                 enum GNUNET_SET_Status status)
{
  struct AliceServiceSession *s = cls;
  struct GNUNET_SCALARPRODUCT_Element *se;

  switch (status)
  {
  case GNUNET_SET_STATUS_OK:
    /* this element has been removed from the set */
    se = GNUNET_CONTAINER_multihashmap_get (s->intersected_elements,
                                            element->data);
    GNUNET_assert (NULL != se);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Intersection removed element with key %s and value %lld\n",
         GNUNET_h2s (&se->key),
         (long long) GNUNET_ntohll (se->value));
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multihashmap_remove (s->intersected_elements,
                                                         element->data,
                                                         se));
    GNUNET_free (se);
    return;
  case GNUNET_SET_STATUS_DONE:
    s->intersection_op = NULL;
    if (NULL != s->intersection_set)
    {
      GNUNET_SET_destroy (s->intersection_set);
      s->intersection_set = NULL;
    }
    send_alices_cryptodata_message (s);
    return;
  case GNUNET_SET_STATUS_HALF_DONE:
    /* unexpected for intersection */
    GNUNET_break (0);
    return;
  case GNUNET_SET_STATUS_FAILURE:
    /* unhandled status code */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Set intersection failed!\n");
    if (NULL != s->intersection_listen)
    {
      GNUNET_SET_listen_cancel (s->intersection_listen);
      s->intersection_listen = NULL;
    }
    s->intersection_op = NULL;
    if (NULL != s->intersection_set)
    {
      GNUNET_SET_destroy (s->intersection_set);
      s->intersection_set = NULL;
    }
    s->status = GNUNET_SCALARPRODUCT_STATUS_FAILURE;
    prepare_client_end_notification (s);
    return;
  default:
    GNUNET_break (0);
    return;
  }
}


/**
 * Called when another peer wants to do a set operation with the
 * local peer. If a listen error occurs, the @a request is NULL.
 *
 * @param cls closure with the `struct AliceServiceSession *`
 * @param other_peer the other peer
 * @param context_msg message with application specific information from
 *        the other peer
 * @param request request from the other peer (never NULL), use GNUNET_SET_accept()
 *        to accept it, otherwise the request will be refused
 *        Note that we can't just return value from the listen callback,
 *        as it is also necessary to specify the set we want to do the
 *        operation with, whith sometimes can be derived from the context
 *        message. It's necessary to specify the timeout.
 */
static void
cb_intersection_request_alice (void *cls,
                               const struct GNUNET_PeerIdentity *other_peer,
                               const struct GNUNET_MessageHeader *context_msg,
                               struct GNUNET_SET_Request *request)
{
  struct AliceServiceSession *s = cls;

  if (0 != memcmp (other_peer,
                   &s->peer,
                   sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break_op (0);
    return;
  }
  s->intersection_op
    = GNUNET_SET_accept (request,
                         GNUNET_SET_RESULT_REMOVED,
                         &cb_intersection_element_removed,
                         s);
  if (NULL == s->intersection_op)
  {
    GNUNET_break (0);
    s->status = GNUNET_SCALARPRODUCT_STATUS_FAILURE;
    prepare_client_end_notification (s);
    return;
  }
  if (GNUNET_OK !=
      GNUNET_SET_commit (s->intersection_op,
                         s->intersection_set))
  {
    GNUNET_break (0);
    s->status = GNUNET_SCALARPRODUCT_STATUS_FAILURE;
    prepare_client_end_notification (s);
    return;
  }
  GNUNET_SET_destroy (s->intersection_set);
  s->intersection_set = NULL;
  GNUNET_SET_listen_cancel (s->intersection_listen);
  s->intersection_listen = NULL;
}


/**
 * Our client has finished sending us its multipart message.
 *
 * @param session the service session context
 */
static void
client_request_complete_alice (struct AliceServiceSession *s)
{
  struct EccServiceRequestMessage *msg;
  struct GNUNET_MQ_Envelope *e;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Creating new channel for session with key %s.\n",
              GNUNET_h2s (&s->session_id));
  s->channel
    = GNUNET_CADET_channel_create (my_cadet,
                                   s,
                                   &s->peer,
                                   GNUNET_APPLICATION_TYPE_SCALARPRODUCT_ECC,
                                   GNUNET_CADET_OPTION_RELIABLE);
  if (NULL == s->channel)
  {
    s->status = GNUNET_SCALARPRODUCT_STATUS_FAILURE;
    prepare_client_end_notification (s);
    return;
  }
  s->cadet_mq = GNUNET_CADET_mq_create (s->channel);
  s->intersection_listen
    = GNUNET_SET_listen (cfg,
                         GNUNET_SET_OPERATION_INTERSECTION,
                         &s->session_id,
                         &cb_intersection_request_alice,
                         s);
  if (NULL == s->intersection_listen)
  {
    s->status = GNUNET_SCALARPRODUCT_STATUS_FAILURE;
    GNUNET_CADET_channel_destroy (s->channel);
    s->channel = NULL;
    prepare_client_end_notification (s);
    return;
  }

  e = GNUNET_MQ_msg (msg,
                     GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ECC_SESSION_INITIALIZATION);
  msg->session_id = s->session_id;
  GNUNET_MQ_send (s->cadet_mq,
                  e);
}


/**
 * We're receiving additional set data. Add it to our
 * set and if we are done, initiate the transaction.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
GSS_handle_alice_client_message_multipart (void *cls,
                                           struct GNUNET_SERVER_Client *client,
                                           const struct GNUNET_MessageHeader *message)
{
  const struct ComputationBobCryptodataMultipartMessage * msg;
  struct AliceServiceSession *s;
  uint32_t contained_count;
  const struct GNUNET_SCALARPRODUCT_Element *elements;
  uint32_t i;
  uint16_t msize;
  struct GNUNET_SET_Element set_elem;
  struct GNUNET_SCALARPRODUCT_Element *elem;

  s = GNUNET_SERVER_client_get_user_context (client,
                                             struct AliceServiceSession);
  if (NULL == s)
  {
    /* session needs to already exist */
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client,
                                GNUNET_SYSERR);
    return;
  }
  msize = ntohs (message->size);
  if (msize < sizeof (struct ComputationBobCryptodataMultipartMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client,
                                GNUNET_SYSERR);
    return;
  }
  msg = (const struct ComputationBobCryptodataMultipartMessage *) message;
  contained_count = ntohl (msg->element_count_contained);

  if ( (msize != (sizeof (struct ComputationBobCryptodataMultipartMessage) +
                  contained_count * sizeof (struct GNUNET_SCALARPRODUCT_Element))) ||
       (0 == contained_count) ||
       (s->total == s->client_received_element_count) ||
       (s->total < s->client_received_element_count + contained_count) )
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client,
                                GNUNET_SYSERR);
    return;
  }
  s->client_received_element_count += contained_count;
  elements = (const struct GNUNET_SCALARPRODUCT_Element *) &msg[1];
  for (i = 0; i < contained_count; i++)
  {
    elem = GNUNET_new (struct GNUNET_SCALARPRODUCT_Element);
    memcpy (elem,
            &elements[i],
            sizeof (struct GNUNET_SCALARPRODUCT_Element));
    if (GNUNET_SYSERR ==
        GNUNET_CONTAINER_multihashmap_put (s->intersected_elements,
                                           &elem->key,
                                           elem,
                                           GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
    {
      GNUNET_break (0);
      GNUNET_free (elem);
      continue;
    }
    set_elem.data = &elem->key;
    set_elem.size = sizeof (elem->key);
    set_elem.element_type = 0;
    GNUNET_SET_add_element (s->intersection_set,
                            &set_elem,
                            NULL, NULL);
    s->used_element_count++;
  }
  GNUNET_SERVER_receive_done (client,
                              GNUNET_OK);
  if (s->total != s->client_received_element_count)
  {
    /* more to come */
    return;
  }
  client_request_complete_alice (s);
}


/**
 * Handler for Alice's client request message.
 * We are doing request-initiation to compute a scalar product with a peer.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
GSS_handle_alice_client_message (void *cls,
                                 struct GNUNET_SERVER_Client *client,
                                 const struct GNUNET_MessageHeader *message)
{
  const struct AliceComputationMessage *msg;
  struct AliceServiceSession *s;
  uint32_t contained_count;
  uint32_t total_count;
  const struct GNUNET_SCALARPRODUCT_Element *elements;
  uint32_t i;
  uint16_t msize;
  struct GNUNET_SET_Element set_elem;
  struct GNUNET_SCALARPRODUCT_Element *elem;

  s = GNUNET_SERVER_client_get_user_context (client,
                                             struct AliceServiceSession);
  if (NULL != s)
  {
    /* only one concurrent session per client connection allowed,
       simplifies logic a lot... */
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  msize = ntohs (message->size);
  if (msize < sizeof (struct AliceComputationMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  msg = (const struct AliceComputationMessage *) message;
  total_count = ntohl (msg->element_count_total);
  contained_count = ntohl (msg->element_count_contained);
  if ( (0 == total_count) ||
       (0 == contained_count) ||
       (msize != (sizeof (struct AliceComputationMessage) +
                  contained_count * sizeof (struct GNUNET_SCALARPRODUCT_Element))) )
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  s = GNUNET_new (struct AliceServiceSession);
  s->peer = msg->peer;
  s->status = GNUNET_SCALARPRODUCT_STATUS_ACTIVE;
  s->client = client;
  s->client_mq = GNUNET_MQ_queue_for_server_client (client);
  s->total = total_count;
  s->client_received_element_count = contained_count;
  s->session_id = msg->session_key;
  elements = (const struct GNUNET_SCALARPRODUCT_Element *) &msg[1];
  s->intersected_elements = GNUNET_CONTAINER_multihashmap_create (s->total,
                                                                  GNUNET_YES);
  s->intersection_set = GNUNET_SET_create (cfg,
                                           GNUNET_SET_OPERATION_INTERSECTION);
  for (i = 0; i < contained_count; i++)
  {
    if (0 == GNUNET_ntohll (elements[i].value))
      continue;
    elem = GNUNET_new (struct GNUNET_SCALARPRODUCT_Element);
    memcpy (elem,
            &elements[i],
            sizeof (struct GNUNET_SCALARPRODUCT_Element));
    if (GNUNET_SYSERR ==
        GNUNET_CONTAINER_multihashmap_put (s->intersected_elements,
                                           &elem->key,
                                           elem,
                                           GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
    {
      /* element with same key encountered twice! */
      GNUNET_break (0);
      GNUNET_free (elem);
      continue;
    }
    set_elem.data = &elem->key;
    set_elem.size = sizeof (elem->key);
    set_elem.element_type = 0;
    GNUNET_SET_add_element (s->intersection_set,
                            &set_elem,
                            NULL, NULL);
    s->used_element_count++;
  }
  GNUNET_SERVER_client_set_user_context (client,
                                         s);
  GNUNET_SERVER_receive_done (client,
                              GNUNET_OK);
  if (s->total != s->client_received_element_count)
  {
    /* wait for multipart msg */
    return;
  }
  client_request_complete_alice (s);
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Shutting down, initiating cleanup.\n");
  // FIXME: we have to cut our connections to CADET first!
  if (NULL != my_cadet)
  {
    GNUNET_CADET_disconnect (my_cadet);
    my_cadet = NULL;
  }
  if (NULL != edc)
  {
    GNUNET_CRYPTO_ecc_dlog_release (edc);
    edc = NULL;
  }
}


/**
 * A client disconnected.
 *
 * Remove the associated session(s), release data structures
 * and cancel pending outgoing transmissions to the client.
 *
 * @param cls closure, NULL
 * @param client identification of the client
 */
static void
handle_client_disconnect (void *cls,
                          struct GNUNET_SERVER_Client *client)
{
  struct AliceServiceSession *s;

  if (NULL == client)
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client %p disconnected from us.\n",
              client);
  s = GNUNET_SERVER_client_get_user_context (client,
                                             struct AliceServiceSession);
  if (NULL == s)
    return;
  s->client = NULL;
  GNUNET_SERVER_client_set_user_context (client,
                                         NULL);
  destroy_service_session (s);
}


/**
 * Initialization of the program and message handlers
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls,
     struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  static const struct GNUNET_CADET_MessageHandler cadet_handlers[] = {
    { &handle_bobs_cryptodata_message,
      GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ECC_BOB_CRYPTODATA,
      0},
    { NULL, 0, 0}
  };
  static const struct GNUNET_SERVER_MessageHandler server_handlers[] = {
    { &GSS_handle_alice_client_message, NULL,
      GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_TO_ALICE,
      0},
    { &GSS_handle_alice_client_message_multipart, NULL,
      GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_MUTLIPART_ALICE,
      0},
    { NULL, NULL, 0, 0}
  };

  cfg = c;
  edc = GNUNET_CRYPTO_ecc_dlog_prepare (MAX_RESULT,
                                        MAX_RAM);
  /* Select a random 'a' value for Alice */
  GNUNET_CRYPTO_ecc_rnd_mpi (edc,
                             &my_privkey,
                             &my_privkey_inv);
  GNUNET_SERVER_add_handlers (server,
                              server_handlers);
  GNUNET_SERVER_disconnect_notify (server,
                                   &handle_client_disconnect,
                                   NULL);
  my_cadet = GNUNET_CADET_connect (cfg, NULL,
                                   NULL /* no incoming supported */,
                                   &cb_channel_destruction,
                                   cadet_handlers,
                                   NULL);
  if (NULL == my_cadet)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Connect to CADET failed\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                &shutdown_task,
                                NULL);

}


/**
 * The main function for the scalarproduct service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc,
      char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv,
                              "scalarproduct-alice",
                              GNUNET_SERVICE_OPTION_NONE,
                              &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-scalarproduct-ecc_alice.c */
