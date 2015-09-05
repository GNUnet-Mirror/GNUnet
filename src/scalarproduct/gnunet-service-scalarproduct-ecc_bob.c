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
 * @file scalarproduct/gnunet-service-scalarproduct-ecc_bob.c
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

#define LOG(kind,...) GNUNET_log_from (kind, "scalarproduct-bob", __VA_ARGS__)


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
   * Value represented (a).
   */
  gcry_mpi_t value;
};


/**
 * An incoming session from CADET.
 */
struct CadetIncomingSession;


/**
 * A scalarproduct session which tracks an offer for a
 * multiplication service by a local client.
 */
struct BobServiceSession
{

  /**
   * (hopefully) unique transaction ID
   */
  struct GNUNET_HashCode session_id;

  /**
   * The client this request is related to.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Client message queue.
   */
  struct GNUNET_MQ_Handle *client_mq;

  /**
   * All non-0-value'd elements transmitted to us.
   */
  struct GNUNET_CONTAINER_MultiHashMap *intersected_elements;

  /**
   * Set of elements for which we will be conducting an intersection.
   * The resulting elements are then used for computing the scalar product.
   */
  struct GNUNET_SET_Handle *intersection_set;

  /**
   * Set of elements for which will conduction an intersection.
   * the resulting elements are then used for computing the scalar product.
   */
  struct GNUNET_SET_OperationHandle *intersection_op;

  /**
   * b(Bob)
   */
  struct MpiElement *sorted_elements;

  /**
   * Product of the g_i^{b_i}
   */
  gcry_mpi_point_t prod_g_i_b_i;

  /**
   * Product of the h_i^{b_i}
   */
  gcry_mpi_point_t prod_h_i_b_i;

  /**
   * Handle for our associated incoming CADET session, or NULL
   * if we have not gotten one yet.
   */
  struct CadetIncomingSession *cadet;

  /**
   * How many elements will be supplied in total from the client.
   */
  uint32_t total;

  /**
   * Already transferred elements (received) for multipart
   * messages from client. Always less than @e total.
   */
  uint32_t client_received_element_count;

  /**
   * How many elements actually are used for the scalar product.
   * Size of the arrays in @e r and @e r_prime.  Also sometimes
   * used as an index into the arrays during construction.
   */
  uint32_t used_element_count;

  /**
   * Counts the number of values received from Alice by us.
   * Always less than @e used_element_count.
   */
  uint32_t cadet_received_element_count;

  /**
   * State of this session.   In
   * #GNUNET_SCALARPRODUCT_STATUS_ACTIVE while operation is
   * ongoing, afterwards in #GNUNET_SCALARPRODUCT_STATUS_SUCCESS or
   * #GNUNET_SCALARPRODUCT_STATUS_FAILURE.
   */
  enum GNUNET_SCALARPRODUCT_ResponseStatus status;

  /**
   * Are we already in #destroy_service_session()?
   */
  int in_destroy;

};


/**
 * An incoming session from CADET.
 */
struct CadetIncomingSession
{

  /**
   * Associated client session, or NULL.
   */
  struct BobServiceSession *s;

  /**
   * The CADET channel.
   */
  struct GNUNET_CADET_Channel *channel;

  /**
   * Originator's peer identity. (Only for diagnostics.)
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * (hopefully) unique transaction ID
   */
  struct GNUNET_HashCode session_id;

  /**
   * The message queue for this channel.
   */
  struct GNUNET_MQ_Handle *cadet_mq;

  /**
   * Has this CADET session been added to the map yet?
   * #GNUNET_YES if so, in which case @e session_id is
   * the key.
   */
  int in_map;

  /**
   * Are we already in #destroy_cadet_session()?
   */
  int in_destroy;

};


/**
 * GNUnet configuration handle
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Map of `struct BobServiceSession`, by session keys.
 */
static struct GNUNET_CONTAINER_MultiHashMap *client_sessions;

/**
 * Map of `struct CadetIncomingSession`, by session keys.
 */
static struct GNUNET_CONTAINER_MultiHashMap *cadet_sessions;

/**
 * Handle to the CADET service.
 */
static struct GNUNET_CADET_Handle *my_cadet;

/**
 * Context for DLOG operations on a curve.
 */
static struct GNUNET_CRYPTO_EccDlogContext *edc;



/**
 * Finds a not terminated client session in the respective map based on
 * session key.
 *
 * @param key the session key we want to search for
 * @return the matching session, or NULL for none
 */
static struct BobServiceSession *
find_matching_client_session (const struct GNUNET_HashCode *key)
{
  return GNUNET_CONTAINER_multihashmap_get (client_sessions,
                                            key);
}


/**
 * Finds a CADET session in the respective map based on session key.
 *
 * @param key the session key we want to search for
 * @return the matching session, or NULL for none
 */
static struct CadetIncomingSession *
find_matching_cadet_session (const struct GNUNET_HashCode *key)
{
  return GNUNET_CONTAINER_multihashmap_get (cadet_sessions,
                                            key);
}


/**
 * Callback used to free the elements in the map.
 *
 * @param cls NULL
 * @param key key of the element
 * @param value the value to free
 */
static int
free_element_cb (void *cls,
                 const struct GNUNET_HashCode *key,
                 void *value)
{
  struct GNUNET_SCALARPRODUCT_Element *element = value;

  GNUNET_free (element);
  return GNUNET_OK;
}


/**
 * Destroy session state, we are done with it.
 *
 * @param session the session to free elements from
 */
static void
destroy_cadet_session (struct CadetIncomingSession *s);


/**
 * Destroy session state, we are done with it.
 *
 * @param session the session to free elements from
 */
static void
destroy_service_session (struct BobServiceSession *s)
{
  struct CadetIncomingSession *in;
  unsigned int i;

  if (GNUNET_YES == s->in_destroy)
    return;
  s->in_destroy = GNUNET_YES;
  if (NULL != (in = s->cadet))
  {
    s->cadet = NULL;
    destroy_cadet_session (in);
  }
  if (NULL != s->client_mq)
  {
    GNUNET_MQ_destroy (s->client_mq);
    s->client_mq = NULL;
  }
  if (NULL != s->client)
  {
    GNUNET_SERVER_client_disconnect (s->client);
    s->client = NULL;
  }
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (client_sessions,
                                                       &s->session_id,
                                                       s));
  if (NULL != s->intersected_elements)
  {
    GNUNET_CONTAINER_multihashmap_iterate (s->intersected_elements,
                                           &free_element_cb,
                                           NULL);
    GNUNET_CONTAINER_multihashmap_destroy (s->intersected_elements);
    s->intersected_elements = NULL;
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
  if (NULL != s->prod_g_i_b_i)
  {
    gcry_mpi_point_release (s->prod_g_i_b_i);
    s->prod_g_i_b_i = NULL;
  }
  if (NULL != s->prod_g_i_b_i)
  {
    gcry_mpi_point_release (s->prod_h_i_b_i);
    s->prod_h_i_b_i = NULL;
  }
  GNUNET_free (s);
}


/**
 * Destroy incoming CADET session state, we are done with it.
 *
 * @param in the session to free elements from
 */
static void
destroy_cadet_session (struct CadetIncomingSession *in)
{
  struct BobServiceSession *s;

  if (GNUNET_YES == in->in_destroy)
    return;
  in->in_destroy = GNUNET_YES;
  if (NULL != (s = in->s))
  {
    in->s = NULL;
    destroy_service_session (s);
  }
  if (GNUNET_YES == in->in_map)
  {
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multihashmap_remove (cadet_sessions,
                                                         &in->session_id,
                                                         in));
    in->in_map = GNUNET_NO;
  }
  if (NULL != in->cadet_mq)
  {
    GNUNET_MQ_destroy (in->cadet_mq);
    in->cadet_mq = NULL;
  }
  if (NULL != in->channel)
  {
    GNUNET_CADET_channel_destroy (in->channel);
    in->channel = NULL;
  }
  GNUNET_free (in);
}


/**
 * Notify the client that the session has succeeded or failed.  This
 * message gets sent to Bob's client if the operation completed or
 * Alice disconnected.
 *
 * @param session the associated client session to fail or succeed
 */
static void
prepare_client_end_notification (struct BobServiceSession *session)
{
  struct ClientResponseMessage *msg;
  struct GNUNET_MQ_Envelope *e;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending session-end notification with status %d to client for session %s\n",
              session->status,
              GNUNET_h2s (&session->session_id));
  e = GNUNET_MQ_msg (msg,
                     GNUNET_MESSAGE_TYPE_SCALARPRODUCT_RESULT);
  msg->range = 0;
  msg->product_length = htonl (0);
  msg->status = htonl (session->status);
  GNUNET_MQ_send (session->client_mq,
                  e);
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
  struct CadetIncomingSession *in = channel_ctx;
  struct BobServiceSession *s;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer disconnected, terminating session %s with peer %s\n",
              GNUNET_h2s (&in->session_id),
              GNUNET_i2s (&in->peer));
  if (NULL != in->cadet_mq)
  {
    GNUNET_MQ_destroy (in->cadet_mq);
    in->cadet_mq = NULL;
  }
  in->channel = NULL;
  if (NULL != (s = in->s))
  {
    if (GNUNET_SCALARPRODUCT_STATUS_ACTIVE == s->status)
    {
      s->status = GNUNET_SCALARPRODUCT_STATUS_FAILURE;
      prepare_client_end_notification (s);
    }
  }
  destroy_cadet_session (in);
}


/**
 * MQ finished giving our last message to CADET, now notify
 * the client that we are finished.
 */
static void
bob_cadet_done_cb (void *cls)
{
  struct BobServiceSession *session = cls;

  session->status = GNUNET_SCALARPRODUCT_STATUS_SUCCESS;
  prepare_client_end_notification (session);
}


/**
 * Bob generates the response message to be sent to Alice.
 *
 * @param s the associated requesting session with Alice
 */
static void
transmit_bobs_cryptodata_message (struct BobServiceSession *s)
{
  struct EccBobCryptodataMessage *msg;
  struct GNUNET_MQ_Envelope *e;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending response to Alice\n");
  e = GNUNET_MQ_msg (msg,
                     GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ECC_BOB_CRYPTODATA);
  msg->contained_element_count = htonl (2);
  if (NULL != s->prod_g_i_b_i)
    GNUNET_CRYPTO_ecc_point_to_bin (edc,
                                    s->prod_g_i_b_i,
                                    &msg->prod_g_i_b_i);
  if (NULL != s->prod_h_i_b_i)
    GNUNET_CRYPTO_ecc_point_to_bin (edc,
                                    s->prod_h_i_b_i,
                                    &msg->prod_h_i_b_i);
  GNUNET_MQ_notify_sent (e,
                         &bob_cadet_done_cb,
                         s);
  GNUNET_MQ_send (s->cadet->cadet_mq,
                  e);
}


/**
 * Iterator to copy over messages from the hash map
 * into an array for sorting.
 *
 * @param cls the `struct BobServiceSession *`
 * @param key the key (unused)
 * @param value the `struct GNUNET_SCALARPRODUCT_Element *`
 * TODO: code duplication with Alice!
 */
static int
copy_element_cb (void *cls,
                 const struct GNUNET_HashCode *key,
                 void *value)
{
  struct BobServiceSession *s = cls;
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
 * TODO: code duplication with Alice!
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
 * Handle a multipart-chunk of a request from another service to
 * calculate a scalarproduct with us.
 *
 * @param cls closure (set from #GNUNET_CADET_connect)
 * @param channel connection to the other end
 * @param channel_ctx place to store local state associated with the @a channel
 * @param message the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_alices_cryptodata_message (void *cls,
                                  struct GNUNET_CADET_Channel *channel,
                                  void **channel_ctx,
                                  const struct GNUNET_MessageHeader *message)
{
  struct CadetIncomingSession *in = *channel_ctx;
  struct BobServiceSession *s;
  const struct EccAliceCryptodataMessage *msg;
  const struct GNUNET_CRYPTO_EccPoint *payload;
  uint32_t contained_elements;
  size_t msg_length;
  uint16_t msize;
  unsigned int max;
  unsigned int i;
  const struct MpiElement *b_i;
  gcry_mpi_point_t tmp;
  gcry_mpi_point_t g_i;
  gcry_mpi_point_t h_i;
  gcry_mpi_point_t g_i_b_i;
  gcry_mpi_point_t h_i_b_i;

  /* sanity checks */
  if (NULL == in)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  s = in->s;
  if (NULL == s)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  /* sort our vector for the computation */
  if (NULL == s->sorted_elements)
  {
    s->sorted_elements
      = GNUNET_malloc (GNUNET_CONTAINER_multihashmap_size (s->intersected_elements) *
                       sizeof (struct MpiElement));
    s->used_element_count = 0;
    GNUNET_CONTAINER_multihashmap_iterate (s->intersected_elements,
                                           &copy_element_cb,
                                           s);
    qsort (s->sorted_elements,
           s->used_element_count,
           sizeof (struct MpiElement),
           &element_cmp);
  }

  /* parse message */
  msize = ntohs (message->size);
  if (msize <= sizeof (struct EccAliceCryptodataMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  msg = (const struct EccAliceCryptodataMessage *) message;
  contained_elements = ntohl (msg->contained_element_count);
  /* Our intersection may still be ongoing, but this is nevertheless
     an upper bound on the required array size */
  max = GNUNET_CONTAINER_multihashmap_size (s->intersected_elements);
  msg_length = sizeof (struct EccAliceCryptodataMessage)
    + contained_elements * sizeof (struct GNUNET_CRYPTO_EccPoint);
  if ( (msize != msg_length) ||
       (0 == contained_elements) ||
       (contained_elements > UINT16_MAX) ||
       (max < contained_elements + s->cadet_received_element_count) )
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received %u crypto values from Alice\n",
              (unsigned int) contained_elements);
  payload = (const struct GNUNET_CRYPTO_EccPoint *) &msg[1];

  for (i=0;i<contained_elements;i++)
  {
    b_i = &s->sorted_elements[i + s->cadet_received_element_count];
    g_i = GNUNET_CRYPTO_ecc_bin_to_point (edc,
                                          &payload[i * 2]);
    g_i_b_i = GNUNET_CRYPTO_ecc_pmul_mpi (edc,
                                          g_i,
                                          b_i->value);
    gcry_mpi_point_release (g_i);
    h_i = GNUNET_CRYPTO_ecc_bin_to_point (edc,
                                          &payload[i * 2 + 1]);
    h_i_b_i = GNUNET_CRYPTO_ecc_pmul_mpi (edc,
                                          h_i,
                                          b_i->value);
    gcry_mpi_point_release (h_i);
    if (0 == i + s->cadet_received_element_count)
    {
      /* first iteration, nothing to add */
      s->prod_g_i_b_i = g_i_b_i;
      s->prod_h_i_b_i = h_i_b_i;
    }
    else
    {
      /* further iterations, cummulate resulting value */
      tmp = GNUNET_CRYPTO_ecc_add (edc,
                                   s->prod_g_i_b_i,
                                   g_i_b_i);
      gcry_mpi_point_release (s->prod_g_i_b_i);
      gcry_mpi_point_release (g_i_b_i);
      s->prod_g_i_b_i = tmp;
      tmp = GNUNET_CRYPTO_ecc_add (edc,
                                   s->prod_h_i_b_i,
                                   h_i_b_i);
      gcry_mpi_point_release (s->prod_h_i_b_i);
      gcry_mpi_point_release (h_i_b_i);
      s->prod_h_i_b_i = tmp;
    }
  }
  s->cadet_received_element_count += contained_elements;
  if ( (s->cadet_received_element_count == max) &&
       (NULL == s->intersection_op) )
  {
    /* intersection has finished also on our side, and
       we got the full set, so we can proceed with the
       CADET response(s) */
    transmit_bobs_cryptodata_message (s);
  }
  GNUNET_CADET_receive_done (s->cadet->channel);
  return GNUNET_OK;
}


/**
 * Callback for set operation results. Called for each element
 * that needs to be removed from the result set.
 *
 * @param cls closure with the `struct BobServiceSession`
 * @param element a result element, only valid if status is #GNUNET_SET_STATUS_OK
 * @param status what has happened with the set intersection?
 */
static void
cb_intersection_element_removed (void *cls,
                                 const struct GNUNET_SET_Element *element,
                                 enum GNUNET_SET_Status status)
{
  struct BobServiceSession *s = cls;
  struct GNUNET_SCALARPRODUCT_Element *se;

  switch (status)
  {
  case GNUNET_SET_STATUS_OK:
    /* this element has been removed from the set */
    se = GNUNET_CONTAINER_multihashmap_get (s->intersected_elements,
                                            element->data);
    GNUNET_assert (NULL != se);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Removed element with key %s and value %lld\n",
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
    GNUNET_break (NULL == s->intersection_set);
    GNUNET_CADET_receive_done (s->cadet->channel);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Finished intersection, %d items remain\n",
         GNUNET_CONTAINER_multihashmap_size (s->intersected_elements));
    if (s->client_received_element_count ==
        GNUNET_CONTAINER_multihashmap_size (s->intersected_elements))
    {
      /* CADET transmission from Alice is also already done,
         start with our own reply */
      transmit_bobs_cryptodata_message (s);
    }
    return;
  case GNUNET_SET_STATUS_HALF_DONE:
    /* unexpected for intersection */
    GNUNET_break (0);
    return;
  case GNUNET_SET_STATUS_FAILURE:
    /* unhandled status code */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Set intersection failed!\n");
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
 * We've paired up a client session with an incoming CADET request.
 * Initiate set intersection work.
 *
 * @param s client session to start intersection for
 */
static void
start_intersection (struct BobServiceSession *s)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got session with key %s and %u elements, starting intersection.\n",
              GNUNET_h2s (&s->session_id),
              (unsigned int) s->total);

  s->intersection_op
    = GNUNET_SET_prepare (&s->cadet->peer,
                          &s->session_id,
                          NULL,
                          GNUNET_SET_RESULT_REMOVED,
                          &cb_intersection_element_removed,
                          s);
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
}


/**
 * Handle a request from Alice to calculate a scalarproduct with us (Bob).
 *
 * @param cls closure (set from #GNUNET_CADET_connect)
 * @param channel connection to the other end
 * @param channel_ctx place to store the `struct CadetIncomingSession *`
 * @param message the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_alices_computation_request (void *cls,
                                   struct GNUNET_CADET_Channel *channel,
                                   void **channel_ctx,
                                   const struct GNUNET_MessageHeader *message)
{
  struct CadetIncomingSession *in = *channel_ctx;
  struct BobServiceSession *s;
  const struct EccServiceRequestMessage *msg;

  msg = (const struct EccServiceRequestMessage *) message;
  if (GNUNET_YES == in->in_map)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (NULL != find_matching_cadet_session (&msg->session_id))
  {
    /* not unique, got one like this already */
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  in->session_id = msg->session_id;
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_put (cadet_sessions,
                                                    &in->session_id,
                                                    in,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  s = find_matching_client_session (&in->session_id);
  if (NULL == s)
  {
    /* no client waiting for this request, wait for client */
    return GNUNET_OK;
  }
  GNUNET_assert (NULL == s->cadet);
  /* pair them up */
  in->s = s;
  s->cadet = in;
  if (s->client_received_element_count == s->total)
    start_intersection (s);
  return GNUNET_OK;
}


/**
 * Function called for inbound channels on Bob's end.  Does some
 * preliminary initialization, more happens after we get Alice's first
 * message.
 *
 * @param cls closure
 * @param channel new handle to the channel
 * @param initiator peer that started the channel
 * @param port unused
 * @param options unused
 * @return session associated with the channel
 */
static void *
cb_channel_incoming (void *cls,
                     struct GNUNET_CADET_Channel *channel,
                     const struct GNUNET_PeerIdentity *initiator,
                     uint32_t port,
                     enum GNUNET_CADET_ChannelOption options)
{
  struct CadetIncomingSession *in;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "New incoming channel from peer %s.\n",
              GNUNET_i2s (initiator));
  in = GNUNET_new (struct CadetIncomingSession);
  in->peer = *initiator;
  in->channel = channel;
  in->cadet_mq = GNUNET_CADET_mq_create (in->channel);
  return in;
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
GSS_handle_bob_client_message_multipart (void *cls,
                                         struct GNUNET_SERVER_Client *client,
                                         const struct GNUNET_MessageHeader *message)
{
  const struct ComputationBobCryptodataMultipartMessage * msg;
  struct BobServiceSession *s;
  uint32_t contained_count;
  const struct GNUNET_SCALARPRODUCT_Element *elements;
  uint32_t i;
  uint16_t msize;
  struct GNUNET_SET_Element set_elem;
  struct GNUNET_SCALARPRODUCT_Element *elem;

  s = GNUNET_SERVER_client_get_user_context (client,
                                             struct BobServiceSession);
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
       (UINT16_MAX < contained_count) ||
       (s->total == s->client_received_element_count) ||
       (s->total < s->client_received_element_count + contained_count) )
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client,
                                GNUNET_SYSERR);
    return;
  }
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
  }
  s->client_received_element_count += contained_count;
  GNUNET_SERVER_receive_done (client,
                              GNUNET_OK);
  if (s->total != s->client_received_element_count)
  {
    /* more to come */
    return;
  }
  if (NULL == s->cadet)
  {
    /* no Alice waiting for this request, wait for Alice */
    return;
  }
  start_intersection (s);
}


/**
 * Handler for Bob's a client request message.  Bob is in the response
 * role, keep the values + session and waiting for a matching session
 * or process a waiting request from Alice.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
GSS_handle_bob_client_message (void *cls,
                               struct GNUNET_SERVER_Client *client,
                               const struct GNUNET_MessageHeader *message)
{
  const struct BobComputationMessage *msg;
  struct BobServiceSession *s;
  struct CadetIncomingSession *in;
  uint32_t contained_count;
  uint32_t total_count;
  const struct GNUNET_SCALARPRODUCT_Element *elements;
  uint32_t i;
  struct GNUNET_SET_Element set_elem;
  struct GNUNET_SCALARPRODUCT_Element *elem;
  uint16_t msize;

  s = GNUNET_SERVER_client_get_user_context (client,
                                             struct BobServiceSession);
  if (NULL != s)
  {
    /* only one concurrent session per client connection allowed,
       simplifies logic a lot... */
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client,
                                GNUNET_SYSERR);
    return;
  }
  msize = ntohs (message->size);
  if (msize < sizeof (struct BobComputationMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client,
                                GNUNET_SYSERR);
    return;
  }
  msg = (const struct BobComputationMessage *) message;
  total_count = ntohl (msg->element_count_total);
  contained_count = ntohl (msg->element_count_contained);
  if ( (0 == total_count) ||
       (0 == contained_count) ||
       (UINT16_MAX < contained_count) ||
       (msize != (sizeof (struct BobComputationMessage) +
                  contained_count * sizeof (struct GNUNET_SCALARPRODUCT_Element))) )
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client,
                                GNUNET_SYSERR);
    return;
  }
  if (NULL != find_matching_client_session (&msg->session_key))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client,
                                GNUNET_SYSERR);
    return;
  }

  s = GNUNET_new (struct BobServiceSession);
  s->status = GNUNET_SCALARPRODUCT_STATUS_ACTIVE;
  s->client = client;
  s->client_mq = GNUNET_MQ_queue_for_server_client (client);
  s->total = total_count;
  s->client_received_element_count = contained_count;
  s->session_id = msg->session_key;
  GNUNET_break (GNUNET_YES ==
                GNUNET_CONTAINER_multihashmap_put (client_sessions,
                                                   &s->session_id,
                                                   s,
                                                   GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
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
                              GNUNET_YES);
  if (s->total != s->client_received_element_count)
  {
    /* multipart msg */
    return;
  }
  in = find_matching_cadet_session (&s->session_id);
  if (NULL == in)
  {
    /* nothing yet, wait for Alice */
    return;
  }
  GNUNET_assert (NULL == in->s);
  /* pair them up */
  in->s = s;
  s->cadet = in;
  start_intersection (s);
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
  GNUNET_CONTAINER_multihashmap_destroy (client_sessions);
  client_sessions = NULL;
  GNUNET_CONTAINER_multihashmap_destroy (cadet_sessions);
  cadet_sessions = NULL;
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
  struct BobServiceSession *s;

  if (NULL == client)
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client disconnected from us.\n",
              client);
  s = GNUNET_SERVER_client_get_user_context (client,
                                             struct BobServiceSession);
  if (NULL == s)
    return;
  s->client = NULL;
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
  static const struct GNUNET_SERVER_MessageHandler server_handlers[] = {
    { &GSS_handle_bob_client_message, NULL,
      GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_TO_BOB,
      0},
    { &GSS_handle_bob_client_message_multipart, NULL,
      GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_MUTLIPART_BOB,
      0},
    { NULL, NULL, 0, 0}
  };
  static const struct GNUNET_CADET_MessageHandler cadet_handlers[] = {
    { &handle_alices_computation_request,
      GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ECC_SESSION_INITIALIZATION,
      sizeof (struct EccServiceRequestMessage) },
    { &handle_alices_cryptodata_message,
      GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ECC_ALICE_CRYPTODATA,
      0},
    { NULL, 0, 0}
  };
  static const uint32_t ports[] = {
    GNUNET_APPLICATION_TYPE_SCALARPRODUCT_ECC,
    0
  };

  cfg = c;
  /* We don't really do DLOG, so we can setup with very minimal resources */
  edc = GNUNET_CRYPTO_ecc_dlog_prepare (4 /* max value */,
                                        2 /* RAM */);

  GNUNET_SERVER_add_handlers (server,
                              server_handlers);
  GNUNET_SERVER_disconnect_notify (server,
                                   &handle_client_disconnect,
                                   NULL);
  client_sessions = GNUNET_CONTAINER_multihashmap_create (128,
                                                          GNUNET_YES);
  cadet_sessions = GNUNET_CONTAINER_multihashmap_create (128,
                                                         GNUNET_YES);
  my_cadet = GNUNET_CADET_connect (cfg, NULL,
                                   &cb_channel_incoming,
                                   &cb_channel_destruction,
                                   cadet_handlers,
                                   ports);
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
                              "scalarproduct-bob",
                              GNUNET_SERVICE_OPTION_NONE,
                              &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-scalarproduct-ecc_bob.c */
