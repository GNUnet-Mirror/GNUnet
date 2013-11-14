/*
     This file is part of GNUnet.
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
 * @file scalarproduct/gnunet-service-scalarproduct.c
 * @brief scalarproduct service implementation
 * @author Christian M. Fuchs
 */
#include <limits.h>
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_mesh_service.h"
#include "gnunet_applications.h"
#include "gnunet_protocols.h"
#include "gnunet_scalarproduct_service.h"
#include "scalarproduct.h"

#define LOG(kind,...) GNUNET_log_from (kind, "scalarproduct", __VA_ARGS__)

///////////////////////////////////////////////////////////////////////////////
//                     Service Structure Definitions
///////////////////////////////////////////////////////////////////////////////


/**
 * state a session can be in
 */
enum SessionState
{
  CLIENT_REQUEST_RECEIVED,
  WAITING_FOR_BOBS_CONNECT,
  CLIENT_RESPONSE_RECEIVED,
  WAITING_FOR_SERVICE_REQUEST,
  WAITING_FOR_MULTIPART_TRANSMISSION,
  WAITING_FOR_SERVICE_RESPONSE,
  SERVICE_REQUEST_RECEIVED,
  SERVICE_RESPONSE_RECEIVED,
  FINALIZED
};


/**
 * role a peer in a session can assume
 */
enum PeerRole
{
  ALICE,
  BOB
};


/**
 * A scalarproduct session which tracks:
 *
 * a request form the client to our final response.
 * or
 * a request from a service to us(service).
 */
struct ServiceSession
{
  /**
   * the role this peer has
   */
  enum PeerRole role;

  /**
   * session information is kept in a DLL
   */
  struct ServiceSession *next;

  /**
   * session information is kept in a DLL
   */
  struct ServiceSession *prev;

  /**
   * (hopefully) unique transaction ID
   */
  struct GNUNET_HashCode key;

  /**
   * state of the session
   */
  enum SessionState state;

  /**
   * Alice or Bob's peerID
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * the client this request is related to
   */
  struct GNUNET_SERVER_Client * client;

  /**
   * The message to send
   */
  struct GNUNET_MessageHeader * msg;

  /**
   * how many elements we were supplied with from the client
   */
  uint32_t total;

  /**
   * how many elements actually are used after applying the mask
   */
  uint32_t used;

  /**
   * already transferred elements (sent/received) for multipart messages, less or equal than used_element_count for
   */
  uint32_t transferred;

  /**
   * index of the last transferred element for multipart messages
   */
  uint32_t last_processed;

  /**
   * how many bytes the mask is long.
   * just for convenience so we don't have to re-re-re calculate it each time
   */
  uint32_t mask_length;

  /**
   * all the vector elements we received
   */
  int32_t * vector;

  /**
   * mask of which elements to check
   */
  unsigned char * mask;

  /**
   * Public key of the remote service, only used by bob
   */
  gcry_sexp_t remote_pubkey;

  /**
   * E(ai)(Bob) or ai(Alice) after applying the mask
   */
  gcry_mpi_t * a;

  /**
   * Bob's permutation p of R
   */
  gcry_mpi_t * r;

  /**
   * Bob's permutation q of R
   */
  gcry_mpi_t * r_prime;

  /**
   * Bob's s
   */
  gcry_mpi_t s;

  /**
   * Bob's s'
   */
  gcry_mpi_t s_prime;

  /**
   * Bobs matching response session from the client
   */
  struct ServiceSession * response;

  /**
   * The computed scalar
   */
  gcry_mpi_t product;

  /**
   * My transmit handle for the current message to a alice/bob
   */
  struct GNUNET_MESH_TransmitHandle * service_transmit_handle;

  /**
   * My transmit handle for the current message to the client
   */
  struct GNUNET_SERVER_TransmitHandle * client_transmit_handle;

  /**
   * channel-handle associated with our mesh handle
   */
  struct GNUNET_MESH_Channel * channel;

  /**
   * Handle to a task that sends a msg to the our client
   */
  GNUNET_SCHEDULER_TaskIdentifier client_notification_task;

  /**
   * Handle to a task that sends a msg to the our peer
   */
  GNUNET_SCHEDULER_TaskIdentifier service_request_task;
};

///////////////////////////////////////////////////////////////////////////////
//                      Forward Delcarations
///////////////////////////////////////////////////////////////////////////////

/**
 * Send a multi part chunk of a service request from alice to bob.
 * This element only contains a part of the elements-vector (session->a[]),
 * mask and public key set have to be contained within the first message
 * 
 * This allows a ~32kbit key length while using 32000 elements or 62000 elements per request.
 * 
 * @param cls the associated service session
 */
static void
prepare_service_request_multipart (void *cls);

/**
 * Send a multi part chunk of a service response from bob to alice.
 * This element only contains the two permutations of R, R'.
 * 
 * @param cls the associated service session
 */
static void
prepare_service_response_multipart (void *cls);


///////////////////////////////////////////////////////////////////////////////
//                      Global Variables
///////////////////////////////////////////////////////////////////////////////


/**
 * Handle to the core service (NULL until we've connected to it).
 */
static struct GNUNET_MESH_Handle *my_mesh;

/**
 * The identity of this host.
 */
static struct GNUNET_PeerIdentity me;

/**
 * Service's own public key represented as string
 */
static unsigned char * my_pubkey_external;

/**
 * Service's own public key represented as string
 */
static uint32_t my_pubkey_external_length = 0;

/**
 * Service's own n
 */
static gcry_mpi_t my_n;

/**
 * Service's own n^2 (kept for performance)
 */
static gcry_mpi_t my_nsquare;

/**
 * Service's own public exponent
 */
static gcry_mpi_t my_g;

/**
 * Service's own private multiplier
 */
static gcry_mpi_t my_mu;

/**
 * Service's own private exponent
 */
static gcry_mpi_t my_lambda;

/**
 * Service's offset for values that could possibly be negative but are plaintext for encryption.
 */
static gcry_mpi_t my_offset;

/**
 * Head of our double linked list for client-requests sent to us.
 * for all of these elements we calculate a scalar product with a remote peer
 * split between service->service and client->service for simplicity
 */
static struct ServiceSession * from_client_head;
/**
 * Tail of our double linked list for client-requests sent to us.
 * for all of these elements we calculate a scalar product with a remote peer
 * split between service->service and client->service for simplicity
 */
static struct ServiceSession * from_client_tail;

/**
 * Head of our double linked list for service-requests sent to us.
 * for all of these elements we help the requesting service in calculating a scalar product
 * split between service->service and client->service for simplicity
 */
static struct ServiceSession * from_service_head;

/**
 * Tail of our double linked list for service-requests sent to us.
 * for all of these elements we help the requesting service in calculating a scalar product
 * split between service->service and client->service for simplicity
 */
static struct ServiceSession * from_service_tail;

/**
 * Certain events (callbacks for server & mesh operations) must not be queued after shutdown.
 */
static int do_shutdown;

///////////////////////////////////////////////////////////////////////////////
//                      Helper Functions
///////////////////////////////////////////////////////////////////////////////


/**
 * Generates an Paillier private/public keyset and extracts the values using libgrcypt only
 */
static void
generate_keyset ()
{
  gcry_sexp_t gen_params;
  gcry_sexp_t key;
  gcry_sexp_t tmp_sexp;
  gcry_mpi_t p;
  gcry_mpi_t q;
  gcry_mpi_t tmp1;
  gcry_mpi_t tmp2;
  gcry_mpi_t gcd;

  size_t erroff = 0;

  // we can still use the RSA keygen for generating p,q,n, but using e is pointless.
  GNUNET_assert (0 == gcry_sexp_build (&gen_params, &erroff,
                                       "(genkey(rsa(nbits %d)(rsa-use-e 3:257)))",
                                       KEYBITS));

  GNUNET_assert (0 == gcry_pk_genkey (&key, gen_params));
  gcry_sexp_release (gen_params);

  // get n and d of our publickey as MPI
  tmp_sexp = gcry_sexp_find_token (key, "n", 0);
  GNUNET_assert (tmp_sexp);
  my_n = gcry_sexp_nth_mpi (tmp_sexp, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release (tmp_sexp);
  tmp_sexp = gcry_sexp_find_token (key, "p", 0);
  GNUNET_assert (tmp_sexp);
  p = gcry_sexp_nth_mpi (tmp_sexp, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release (tmp_sexp);
  tmp_sexp = gcry_sexp_find_token (key, "q", 0);
  GNUNET_assert (tmp_sexp);
  q = gcry_sexp_nth_mpi (tmp_sexp, 1, GCRYMPI_FMT_USG);
  gcry_sexp_release (key);

  tmp1 = gcry_mpi_new (0);
  tmp2 = gcry_mpi_new (0);
  gcd = gcry_mpi_new (0);
  my_g = gcry_mpi_new (0);
  my_mu = gcry_mpi_new (0);
  my_nsquare = gcry_mpi_new (0);
  my_lambda = gcry_mpi_new (0);

  // calculate lambda
  // lambda = frac{(p-1)*(q-1)}{gcd(p-1,q-1)}
  gcry_mpi_sub_ui (tmp1, p, 1);
  gcry_mpi_sub_ui (tmp2, q, 1);
  gcry_mpi_gcd (gcd, tmp1, tmp2);
  gcry_mpi_set (my_lambda, tmp1);
  gcry_mpi_mul (my_lambda, my_lambda, tmp2);
  gcry_mpi_div (my_lambda, NULL, my_lambda, gcd, 0);

  // generate a g
  gcry_mpi_mul (my_nsquare, my_n, my_n);
  do {
    // find a matching g
    do {
      gcry_mpi_randomize (my_g, KEYBITS * 2, GCRY_WEAK_RANDOM);
      // g must be smaller than n^2
      if (0 >= gcry_mpi_cmp (my_g, my_nsquare))
        continue;

      // g must have gcd == 1 with n^2
      gcry_mpi_gcd (gcd, my_g, my_nsquare);
    }
    while (gcry_mpi_cmp_ui (gcd, 1));

    // is this a valid g?
    // if so, gcd(((g^lambda mod n^2)-1 )/n, n) = 1
    gcry_mpi_powm (tmp1, my_g, my_lambda, my_nsquare);
    gcry_mpi_sub_ui (tmp1, tmp1, 1);
    gcry_mpi_div (tmp1, NULL, tmp1, my_n, 0);
    gcry_mpi_gcd (gcd, tmp1, my_n);
  }
  while (gcry_mpi_cmp_ui (gcd, 1));

  // calculate our mu based on g and n.
  // mu = (((g^lambda mod n^2)-1 )/n)^-1 mod n
  gcry_mpi_invm (my_mu, tmp1, my_n);

  GNUNET_assert (0 == gcry_sexp_build (&key, &erroff,
                                       "(public-key (paillier (n %M)(g %M)))",
                                       my_n, my_g));

  // get the length of this sexpression
  my_pubkey_external_length = gcry_sexp_sprint (key,
                                                GCRYSEXP_FMT_CANON,
                                                NULL,
                                                UINT16_MAX);

  GNUNET_assert (my_pubkey_external_length > 0);
  my_pubkey_external = GNUNET_malloc (my_pubkey_external_length);

  // convert the sexpression to canonical format
  gcry_sexp_sprint (key,
                    GCRYSEXP_FMT_CANON,
                    my_pubkey_external,
                    my_pubkey_external_length);

  gcry_sexp_release (key);

  // offset has to be sufficiently small to allow computation of:
  // m1+m2 mod n == (S + a) + (S + b) mod n,
  // if we have more complex operations, this factor needs to be lowered
  my_offset = gcry_mpi_new (KEYBITS / 3);
  gcry_mpi_set_bit (my_offset, KEYBITS / 3);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _ ("Generated key set with key length %d bits.\n"), KEYBITS);
}


/**
 * If target != size, move target bytes to the
 * end of the size-sized buffer and zero out the
 * first target-size bytes.
 *
 * @param buf original buffer
 * @param size number of bytes in the buffer
 * @param target target size of the buffer
 */
static void
adjust (unsigned char *buf, size_t size, size_t target)
{
  if (size < target) {
    memmove (&buf[target - size], buf, size);
    memset (buf, 0, target - size);
  }
}


/**
 * Encrypts an element using the paillier crypto system
 *
 * @param c ciphertext (output)
 * @param m plaintext
 * @param g the public base
 * @param n the module from which which r is chosen (Z*_n)
 * @param n_square the module for encryption, for performance reasons.
 */
static void
encrypt_element (gcry_mpi_t c, gcry_mpi_t m, gcry_mpi_t g, gcry_mpi_t n, gcry_mpi_t n_square)
{
  gcry_mpi_t tmp;

  GNUNET_assert (tmp = gcry_mpi_new (0));

  while (0 >= gcry_mpi_cmp_ui (tmp, 1)) {
    gcry_mpi_randomize (tmp, KEYBITS / 3, GCRY_WEAK_RANDOM);
    // r must be 1 < r < n
  }

  gcry_mpi_powm (c, g, m, n_square);
  gcry_mpi_powm (tmp, tmp, n, n_square);
  gcry_mpi_mulm (c, tmp, c, n_square);

  gcry_mpi_release (tmp);
}


/**
 * decrypts an element using the paillier crypto system
 *
 * @param m plaintext (output)
 * @param c the ciphertext
 * @param mu the modifier to correct encryption
 * @param lambda the private exponent
 * @param n the outer module for decryption
 * @param n_square the inner module for decryption
 */
static void
decrypt_element (gcry_mpi_t m, gcry_mpi_t c, gcry_mpi_t mu, gcry_mpi_t lambda, gcry_mpi_t n, gcry_mpi_t n_square)
{
  gcry_mpi_powm (m, c, lambda, n_square);
  gcry_mpi_sub_ui (m, m, 1);
  gcry_mpi_div (m, NULL, m, n, 0);
  gcry_mpi_mulm (m, m, mu, n);
}


/**
 * computes the square sum over a vector of a given length.
 *
 * @param vector the vector to encrypt
 * @param length the length of the vector
 * @return an MPI value containing the calculated sum, never NULL
 */
static gcry_mpi_t
compute_square_sum (gcry_mpi_t * vector, uint32_t length)
{
  gcry_mpi_t elem;
  gcry_mpi_t sum;
  int32_t i;

  GNUNET_assert (sum = gcry_mpi_new (0));
  GNUNET_assert (elem = gcry_mpi_new (0));

  // calculare E(sum (ai ^ 2), publickey)
  for (i = 0; i < length; i++) {
    gcry_mpi_mul (elem, vector[i], vector[i]);
    gcry_mpi_add (sum, sum, elem);
  }
  gcry_mpi_release (elem);

  return sum;
}


/**
 * Primitive callback for copying over a message, as they
 * usually are too complex to be handled in the callback itself.
 * clears a session-callback, if a session was handed over and the transmit handle was stored
 *
 * @param cls the message object
 * @param size the size of the buffer we got
 * @param buf the buffer to copy the message to
 * @return 0 if we couldn't copy, else the size copied over
 */
static size_t
do_send_message (void *cls, size_t size, void *buf)
{
  struct ServiceSession * session = cls;
  uint16_t type;

  GNUNET_assert (buf);

  if (ntohs (session->msg->size) != size) {
    GNUNET_break (0);
    return 0;
  }

  type = ntohs (session->msg->type);
  memcpy (buf, session->msg, size);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sent a message of type %hu.\n",
              type);
  GNUNET_free (session->msg);
  session->msg = NULL;

  switch (type)
  {
  case GNUNET_MESSAGE_TYPE_SCALARPRODUCT_SERVICE_TO_CLIENT:
    session->state = FINALIZED;
    session->client_transmit_handle = NULL;
    break;

  case GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ALICE_TO_BOB:
  case GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ALICE_TO_BOB_MULTIPART:
    session->service_transmit_handle = NULL;
    if (session->state == WAITING_FOR_MULTIPART_TRANSMISSION)
      prepare_service_request_multipart (session);
    break;

  case GNUNET_MESSAGE_TYPE_SCALARPRODUCT_BOB_TO_ALICE:
  case GNUNET_MESSAGE_TYPE_SCALARPRODUCT_BOB_TO_ALICE_MULTIPART:
    session->service_transmit_handle = NULL;
    if (session->state == WAITING_FOR_MULTIPART_TRANSMISSION)
      prepare_service_response_multipart (session);
    break;

  default:
    GNUNET_assert (0);
  }

  return size;
}


/**
 * initializes a new vector with fresh MPI values (=0) of a given length
 *
 * @param length of the vector to create
 * @return the initialized vector, never NULL
 */
static gcry_mpi_t *
initialize_mpi_vector (uint32_t length)
{
  uint32_t i;
  gcry_mpi_t * output = GNUNET_malloc (sizeof (gcry_mpi_t) * length);

  for (i = 0; i < length; i++)
    GNUNET_assert (NULL != (output[i] = gcry_mpi_new (0)));
  return output;
}


/**
 * permutes an MPI vector according to the given permutation vector
 *
 * @param vector the vector to permuted
 * @param perm the permutation to use
 * @param length the length of the vectors
 * @return the permuted vector (same as input), never NULL
 */
static gcry_mpi_t *
permute_vector (gcry_mpi_t * vector,
                unsigned int * perm,
                uint32_t length)
{
  gcry_mpi_t tmp[length];
  uint32_t i;

  GNUNET_assert (length > 0);

  // backup old layout
  memcpy (tmp, vector, length * sizeof (gcry_mpi_t));

  // permute vector according to given
  for (i = 0; i < length; i++)
    vector[i] = tmp[perm[i]];

  return vector;
}


/**
 * Finds a not terminated client/service session in the
 * given DLL based on session key, element count and state.
 * 
 * @param tail - the tail of the DLL
 * @param key - the key we want to search for
 * @param element_count - the total element count of the dataset (session->total)
 * @param state - a pointer to the state the session should be in, NULL to ignore
 * @param peerid - a pointer to the peer ID of the associated peer, NULL to ignore
 * @return a pointer to a matching session, or NULL
 */
static struct ServiceSession *
find_matching_session (struct ServiceSession * tail,
                       const struct GNUNET_HashCode * key,
                       uint32_t element_count,
                       enum SessionState * state,
                       const struct GNUNET_PeerIdentity * peerid)
{
  struct ServiceSession * curr;

  for (curr = tail; NULL != curr; curr = curr->prev) {
    // if the key matches, and the element_count is same
    if ((!memcmp (&curr->key, key, sizeof (struct GNUNET_HashCode)))
        && (curr->total == element_count)) {
      // if incoming state is NULL OR is same as state of the queued request
      if ((NULL == state) || (curr->state == *state)) {
        // if peerid is NULL OR same as the peer Id in the queued request
        if ((NULL == peerid)
            || (!memcmp (&curr->peer, peerid, sizeof (struct GNUNET_PeerIdentity))))
          // matches and is not an already terminated session
          return curr;
      }
    }
  }

  return NULL;
}

/**
 * Safely frees ALL memory areas referenced by a session.
 * 
 * @param session - the session to free elements from
 */
static void
free_session_variables (struct ServiceSession * session)
{
  unsigned int i;

  if (session->a) {
    for (i = 0; i < session->used; i++)
      if (session->a[i]) gcry_mpi_release (session->a[i]);
    GNUNET_free (session->a);
    session->a = NULL;
  }
  if (session->mask) {
    GNUNET_free (session->mask);
    session->mask = NULL;
  }
  if (session->r) {
    for (i = 0; i < session->used; i++)
      if (session->r[i]) gcry_mpi_release (session->r[i]);
    GNUNET_free (session->r);
    session->r = NULL;
  }
  if (session->r_prime) {
    for (i = 0; i < session->used; i++)
      if (session->r_prime[i]) gcry_mpi_release (session->r_prime[i]);
    GNUNET_free (session->r_prime);
    session->r_prime = NULL;
  }
  if (session->s) {
    gcry_mpi_release (session->s);
    session->s = NULL;
  }

  if (session->s_prime) {
    gcry_mpi_release (session->s_prime);
    session->s_prime = NULL;
  }

  if (session->product) {
    gcry_mpi_release (session->product);
    session->product = NULL;
  }

  if (session->remote_pubkey) {
    gcry_sexp_release (session->remote_pubkey);
    session->remote_pubkey = NULL;
  }

  if (session->vector) {
    GNUNET_free_non_null (session->vector);
    session->s = NULL;
  }
}
///////////////////////////////////////////////////////////////////////////////
//                      Event and Message Handlers
///////////////////////////////////////////////////////////////////////////////


/**
 * A client disconnected.
 *
 * Remove the associated session(s), release data structures
 * and cancel pending outgoing transmissions to the client.
 * if the session has not yet completed, we also cancel Alice's request to Bob.
 *
 * @param cls closure, NULL
 * @param client identification of the client
 */
static void
handle_client_disconnect (void *cls,
                          struct GNUNET_SERVER_Client *client)
{
  struct ServiceSession *session;
  
  if (NULL != client)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _ ("Client (%p) disconnected from us.\n"), client);
  else
    return;

  session = GNUNET_SERVER_client_get_user_context (client, struct ServiceSession);
  if (NULL == session)
    return;
  GNUNET_CONTAINER_DLL_remove (from_client_head, from_client_tail, session);

  if (!(session->role == BOB && session->state == FINALIZED)) {
    //we MUST terminate any client message underway
    if (session->service_transmit_handle && session->channel)
      GNUNET_MESH_notify_transmit_ready_cancel (session->service_transmit_handle);
    if (session->channel && session->state == WAITING_FOR_SERVICE_RESPONSE)
      GNUNET_MESH_channel_destroy (session->channel);
  }
  if (GNUNET_SCHEDULER_NO_TASK != session->client_notification_task) {
    GNUNET_SCHEDULER_cancel (session->client_notification_task);
    session->client_notification_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (GNUNET_SCHEDULER_NO_TASK != session->service_request_task) {
    GNUNET_SCHEDULER_cancel (session->service_request_task);
    session->service_request_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != session->client_transmit_handle) {
    GNUNET_SERVER_notify_transmit_ready_cancel (session->client_transmit_handle);
    session->client_transmit_handle = NULL;
  }
  free_session_variables (session);
  GNUNET_free (session);
}


/**
 * Notify the client that the session has succeeded or failed completely.
 * This message gets sent to
 * * alice's client if bob disconnected or to
 * * bob's client if the operation completed or alice disconnected
 *
 * @param cls the associated client session
 * @param tc the task context handed to us by the scheduler, unused
 */
static void
prepare_client_end_notification (void * cls,
                                 const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  struct ServiceSession * session = cls;
  struct GNUNET_SCALARPRODUCT_client_response * msg;

  session->client_notification_task = GNUNET_SCHEDULER_NO_TASK;

  msg = GNUNET_new (struct GNUNET_SCALARPRODUCT_client_response);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_SERVICE_TO_CLIENT);
  memcpy (&msg->key, &session->key, sizeof (struct GNUNET_HashCode));
  memcpy (&msg->peer, &session->peer, sizeof ( struct GNUNET_PeerIdentity));
  msg->header.size = htons (sizeof (struct GNUNET_SCALARPRODUCT_client_response));
  // signal error if not signalized, positive result-range field but zero length.
  msg->product_length = htonl (0);
  msg->range = (session->state == FINALIZED) ? 0 : -1;

  session->msg = &msg->header;

  //transmit this message to our client
  session->client_transmit_handle =
          GNUNET_SERVER_notify_transmit_ready (session->client,
                                               sizeof (struct GNUNET_SCALARPRODUCT_client_response),
                                               GNUNET_TIME_UNIT_FOREVER_REL,
                                               &do_send_message,
                                               session);

  // if we could not even queue our request, something is wrong
  if (NULL == session->client_transmit_handle) {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, _ ("Could not send message to client (%p)!\n"), session->client);
    // usually gets freed by do_send_message
    session->msg = NULL;
    GNUNET_free (msg);
  }
  else
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, _ ("Sending session-end notification to client (%p) for session %s\n"), &session->client, GNUNET_h2s (&session->key));
  
  free_session_variables (session);
}


/**
 * prepare the response we will send to alice or bobs' clients.
 * in Bobs case the product will be NULL.
 *
 * @param cls the session associated with our client.
 * @param tc the task context handed to us by the scheduler, unused
 */
static void
prepare_client_response (void *cls,
                         const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ServiceSession * session = cls;
  struct GNUNET_SCALARPRODUCT_client_response * msg;
  unsigned char * product_exported = NULL;
  size_t product_length = 0;
  uint32_t msg_length = 0;
  int8_t range = -1;
  gcry_error_t rc;
  int sign;

  session->client_notification_task = GNUNET_SCHEDULER_NO_TASK;

  if (session->product) {
    gcry_mpi_t value = gcry_mpi_new (0);

    sign = gcry_mpi_cmp_ui (session->product, 0);
    // libgcrypt can not handle a print of a negative number
    // if (a->sign) return gcry_error (GPG_ERR_INTERNAL); /* Can't handle it yet. */
    if (0 > sign) {
      gcry_mpi_sub (value, value, session->product);
    }
    else if (0 < sign) {
      range = 1;
      gcry_mpi_add (value, value, session->product);
    }
    else
      range = 0;

    gcry_mpi_release (session->product);
    session->product = NULL;

    // get representation as string
    if (range
        && (0 != (rc = gcry_mpi_aprint (GCRYMPI_FMT_STD,
                                        &product_exported,
                                        &product_length,
                                        value)))) {
      LOG_GCRY (GNUNET_ERROR_TYPE_ERROR, "gcry_mpi_scan", rc);
      product_length = 0;
      range = -1; // signal error with product-length = 0 and range = -1
    }
    gcry_mpi_release (value);
  }

  msg_length = sizeof (struct GNUNET_SCALARPRODUCT_client_response) +product_length;
  msg = GNUNET_malloc (msg_length);
  memcpy (&msg->key, &session->key, sizeof (struct GNUNET_HashCode));
  memcpy (&msg->peer, &session->peer, sizeof ( struct GNUNET_PeerIdentity));
  if (product_exported != NULL) {
    memcpy (&msg[1], product_exported, product_length);
    GNUNET_free (product_exported);
  }
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_SERVICE_TO_CLIENT);
  msg->header.size = htons (msg_length);
  msg->range = range;
  msg->product_length = htonl (product_length);

  session->msg = (struct GNUNET_MessageHeader *) msg;
  //transmit this message to our client
  session->client_transmit_handle =
          GNUNET_SERVER_notify_transmit_ready (session->client,
                                               msg_length,
                                               GNUNET_TIME_UNIT_FOREVER_REL,
                                               &do_send_message,
                                               session);
  if (NULL == session->client_transmit_handle) {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("Could not send message to client (%p)!\n"),
                session->client);
    session->client = NULL;
    // callback was not called!
    GNUNET_free (msg);
    session->msg = NULL;
  }
  else
    // gracefully sent message, just terminate session structure
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _ ("Sent result to client (%p), this session (%s) has ended!\n"),
                session->client,
                GNUNET_h2s (&session->key));
  free_session_variables (session);
}


/**
 * Send a multipart chunk of a service response from bob to alice.
 * This element only contains the two permutations of R, R'.
 * 
 * @param cls the associated service session
 */
static void
prepare_service_response_multipart (void *cls)
{
  struct ServiceSession * session = cls;
  unsigned char * current;
  unsigned char * element_exported;
  struct GNUNET_SCALARPRODUCT_multipart_message * msg;
  unsigned int i;
  uint32_t msg_length;
  uint32_t todo_count;
  size_t element_length = 0; // initialized by gcry_mpi_print, but the compiler doesn't know that

  msg_length = sizeof (struct GNUNET_SCALARPRODUCT_multipart_message);
  todo_count = session->used - session->transferred;

  if (todo_count > MULTIPART_ELEMENT_CAPACITY / 2)
    // send the currently possible maximum chunk, we always transfer both permutations
    todo_count = MULTIPART_ELEMENT_CAPACITY / 2;

  msg_length += todo_count * PAILLIER_ELEMENT_LENGTH * 2;
  msg = GNUNET_malloc (msg_length);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ALICE_TO_BOB_MULTIPART);
  msg->header.size = htons (msg_length);
  msg->multipart_element_count = htonl (todo_count);

  element_exported = GNUNET_malloc (PAILLIER_ELEMENT_LENGTH);
  current = (unsigned char *) &msg[1];
  // convert k[][]
  for (i = session->transferred; i < session->transferred + todo_count; i++) {
    //k[i][p]
    memset (element_exported, 0, PAILLIER_ELEMENT_LENGTH);
    GNUNET_assert (0 == gcry_mpi_print (GCRYMPI_FMT_USG,
                                        element_exported, PAILLIER_ELEMENT_LENGTH,
                                        &element_length,
                                        session->r[i]));
    adjust (element_exported, element_length, PAILLIER_ELEMENT_LENGTH);
    memcpy (current, element_exported, PAILLIER_ELEMENT_LENGTH);
    current += PAILLIER_ELEMENT_LENGTH;
    //k[i][q]
    memset (element_exported, 0, PAILLIER_ELEMENT_LENGTH);
    GNUNET_assert (0 == gcry_mpi_print (GCRYMPI_FMT_USG,
                                        element_exported, PAILLIER_ELEMENT_LENGTH,
                                        &element_length,
                                        session->r_prime[i]));
    adjust (element_exported, element_length, PAILLIER_ELEMENT_LENGTH);
    memcpy (current, element_exported, PAILLIER_ELEMENT_LENGTH);
    current += PAILLIER_ELEMENT_LENGTH;
  }
  GNUNET_free (element_exported);
  for (i = session->transferred; i < session->transferred; i++) {
    gcry_mpi_release (session->r_prime[i]);
    session->r_prime[i] = NULL;
    gcry_mpi_release (session->r[i]);
    session->r[i] = NULL;
  }
  session->transferred += todo_count;
  session->msg = (struct GNUNET_MessageHeader *) msg;
  session->service_transmit_handle =
          GNUNET_MESH_notify_transmit_ready (session->channel,
                                             GNUNET_YES,
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             msg_length,
                                             &do_send_message,
                                             session);
  //disconnect our client
  if (NULL == session->service_transmit_handle) {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _ ("Could not send service-response message via mesh!)\n"));
    session->state = FINALIZED;

    session->response->client_notification_task =
            GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                      session->response);
    return;
  }
  if (session->transferred != session->used)
    // more multiparts
    session->state = WAITING_FOR_MULTIPART_TRANSMISSION;
  else{
    // final part
    session->state = FINALIZED;
    GNUNET_free(session->r);
    GNUNET_free(session->r_prime);
    session->r_prime = NULL;
    session->r = NULL;
  }
}


/**
 * Bob executes:
 * generates the response message to be sent to alice after computing
 * the values (1), (2), S and S'
 *  (1)[]: $E_A(a_{pi(i)}) times E_A(- r_{pi(i)} - b_{pi(i)}) &= E_A(a_{pi(i)} - r_{pi(i)} - b_{pi(i)})$
 *  (2)[]: $E_A(a_{pi'(i)}) times E_A(- r_{pi'(i)}) &= E_A(a_{pi'(i)} - r_{pi'(i)})$
 *      S: $S := E_A(sum (r_i + b_i)^2)$
 *     S': $S' := E_A(sum r_i^2)$
 *
 * @param s         S: $S := E_A(sum (r_i + b_i)^2)$
 * @param s_prime    S': $S' := E_A(sum r_i^2)$
 * @param session  the associated requesting session with alice
 * @return #GNUNET_NO if we could not send our message
 *         #GNUNET_OK if the operation succeeded
 */
static int
prepare_service_response (gcry_mpi_t s,
                          gcry_mpi_t s_prime,
                          struct ServiceSession * session)
{
  struct GNUNET_SCALARPRODUCT_service_response * msg;
  uint32_t msg_length = 0;
  unsigned char * current = NULL;
  unsigned char * element_exported = NULL;
  size_t element_length = 0;
  int i;

  msg_length = sizeof (struct GNUNET_SCALARPRODUCT_service_response)
          + 2 * PAILLIER_ELEMENT_LENGTH; // s, stick

  if (GNUNET_SERVER_MAX_MESSAGE_SIZE > msg_length + 2 * session->used * PAILLIER_ELEMENT_LENGTH) { //kp, kq
    msg_length += +2 * session->used * PAILLIER_ELEMENT_LENGTH;
    session->transferred = session->used;
  }
  else {
    session->transferred = (GNUNET_SERVER_MAX_MESSAGE_SIZE - 1 - msg_length) / (PAILLIER_ELEMENT_LENGTH * 2);
  }

  msg = GNUNET_malloc (msg_length);

  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_BOB_TO_ALICE);
  msg->header.size = htons (msg_length);
  msg->total_element_count = htonl (session->total);
  msg->used_element_count = htonl (session->used);
  msg->contained_element_count = htonl (session->transferred);
  memcpy (&msg->key, &session->key, sizeof (struct GNUNET_HashCode));
  current = (unsigned char *) &msg[1];

  element_exported = GNUNET_malloc (PAILLIER_ELEMENT_LENGTH);
  // 4 times the same logics with slight variations.
  // doesn't really justify having 2 functions for that
  // so i put it into blocks to enhance readability
  // convert s
  memset (element_exported, 0, PAILLIER_ELEMENT_LENGTH);
  GNUNET_assert (0 == gcry_mpi_print (GCRYMPI_FMT_USG,
                                      element_exported, PAILLIER_ELEMENT_LENGTH,
                                      &element_length,
                                      s));
  adjust (element_exported, element_length, PAILLIER_ELEMENT_LENGTH);
  memcpy (current, element_exported, PAILLIER_ELEMENT_LENGTH);
  current += PAILLIER_ELEMENT_LENGTH;

  // convert stick
  memset (element_exported, 0, PAILLIER_ELEMENT_LENGTH);
  GNUNET_assert (0 == gcry_mpi_print (GCRYMPI_FMT_USG,
                                      element_exported, PAILLIER_ELEMENT_LENGTH,
                                      &element_length,
                                      s_prime));
  adjust (element_exported, element_length, PAILLIER_ELEMENT_LENGTH);
  memcpy (current, element_exported, PAILLIER_ELEMENT_LENGTH);
  current += PAILLIER_ELEMENT_LENGTH;

  // convert k[][]
  for (i = 0; i < session->transferred; i++) {
    //k[i][p]
    memset (element_exported, 0, PAILLIER_ELEMENT_LENGTH);
    GNUNET_assert (0 == gcry_mpi_print (GCRYMPI_FMT_USG,
                                        element_exported, PAILLIER_ELEMENT_LENGTH,
                                        &element_length,
                                        session->r[i]));
    adjust (element_exported, element_length, PAILLIER_ELEMENT_LENGTH);
    memcpy (current, element_exported, PAILLIER_ELEMENT_LENGTH);
    current += PAILLIER_ELEMENT_LENGTH;
    //k[i][q]
    memset (element_exported, 0, PAILLIER_ELEMENT_LENGTH);
    GNUNET_assert (0 == gcry_mpi_print (GCRYMPI_FMT_USG,
                                        element_exported, PAILLIER_ELEMENT_LENGTH,
                                        &element_length,
                                        session->r_prime[i]));
    adjust (element_exported, element_length, PAILLIER_ELEMENT_LENGTH);
    memcpy (current, element_exported, PAILLIER_ELEMENT_LENGTH);
    current += PAILLIER_ELEMENT_LENGTH;
  }

  GNUNET_free (element_exported);
  for (i = 0; i < session->transferred; i++) {
    gcry_mpi_release (session->r_prime[i]);
    session->r_prime[i] = NULL;
    gcry_mpi_release (session->r[i]);
    session->r[i] = NULL;
  }
  gcry_mpi_release (s);
  session->s = NULL;
  gcry_mpi_release (s_prime);
  session->s_prime = NULL;

  session->msg = (struct GNUNET_MessageHeader *) msg;
  session->service_transmit_handle =
          GNUNET_MESH_notify_transmit_ready (session->channel,
                                             GNUNET_YES,
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             msg_length,
                                             &do_send_message,
                                             session);
  //disconnect our client
  if (NULL == session->service_transmit_handle) {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _ ("Could not send service-response message via mesh!)\n"));
    session->state = FINALIZED;

    session->response->client_notification_task =
            GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                      session->response);
    return GNUNET_NO;
  }
  if (session->transferred != session->used)
    // multipart
    session->state = WAITING_FOR_MULTIPART_TRANSMISSION;
  else{
    //singlepart
    session->state = FINALIZED;
    GNUNET_free(session->r);
    GNUNET_free(session->r_prime);
    session->r_prime = NULL;
    session->r = NULL;
  }

  return GNUNET_OK;
}


/**
 * executed by bob:
 * compute the values
 *  (1)[]: $E_A(a_{pi(i)}) otimes E_A(- r_{pi(i)} - b_{pi(i)}) &= E_A(a_{pi(i)} - r_{pi(i)} - b_{pi(i)})$
 *  (2)[]: $E_A(a_{pi'(i)}) otimes E_A(- r_{pi'(i)}) &= E_A(a_{pi'(i)} - r_{pi'(i)})$
 *      S: $S := E_A(sum (r_i + b_i)^2)$
 *     S': $S' := E_A(sum r_i^2)$
 *
 * @param request the requesting session + bob's requesting peer
 * @param response the responding session + bob's client handle
 * @return GNUNET_SYSERR if the computation failed
 *         GNUNET_OK if everything went well.
 */
static int
compute_service_response (struct ServiceSession * request,
                          struct ServiceSession * response)
{
  int i;
  int j;
  int ret = GNUNET_SYSERR;
  unsigned int * p;
  unsigned int * q;
  uint32_t count;
  gcry_mpi_t * rand = NULL;
  gcry_mpi_t * r = NULL;
  gcry_mpi_t * r_prime = NULL;
  gcry_mpi_t * b;
  gcry_mpi_t * a_pi;
  gcry_mpi_t * a_pi_prime;
  gcry_mpi_t * b_pi;
  gcry_mpi_t * rand_pi;
  gcry_mpi_t * rand_pi_prime;
  gcry_mpi_t s = NULL;
  gcry_mpi_t s_prime = NULL;
  gcry_mpi_t remote_n = NULL;
  gcry_mpi_t remote_nsquare;
  gcry_mpi_t remote_g = NULL;
  gcry_sexp_t tmp_exp;
  uint32_t value;

  count = request->used;

  b = GNUNET_malloc (sizeof (gcry_mpi_t) * count);
  a_pi = GNUNET_malloc (sizeof (gcry_mpi_t) * count);
  b_pi = GNUNET_malloc (sizeof (gcry_mpi_t) * count);
  a_pi_prime = GNUNET_malloc (sizeof (gcry_mpi_t) * count);
  rand_pi = GNUNET_malloc (sizeof (gcry_mpi_t) * count);
  rand_pi_prime = GNUNET_malloc (sizeof (gcry_mpi_t) * count);

  // convert responder session to from long to mpi
  for (i = 0, j = 0; i < response->total && j < count; i++) {
    if (request->mask[i / 8] & (1 << (i % 8))) {
      value = response->vector[i] >= 0 ? response->vector[i] : -response->vector[i];
      // long to gcry_mpi_t
      if (0 > response->vector[i]) {
        b[j] = gcry_mpi_new (0);
        gcry_mpi_sub_ui (b[j], b[j], value);
      }
      else {
        b[j] = gcry_mpi_set_ui (NULL, value);
      }
      j++;
    }
  }
  GNUNET_free (response->vector);
  response->vector = NULL;

  tmp_exp = gcry_sexp_find_token (request->remote_pubkey, "n", 0);
  if (!tmp_exp) {
    GNUNET_break_op (0);
    gcry_sexp_release (request->remote_pubkey);
    request->remote_pubkey = NULL;
    goto except;
  }
  remote_n = gcry_sexp_nth_mpi (tmp_exp, 1, GCRYMPI_FMT_USG);
  if (!remote_n) {
    GNUNET_break (0);
    gcry_sexp_release (tmp_exp);
    goto except;
  }
  remote_nsquare = gcry_mpi_new (KEYBITS + 1);
  gcry_mpi_mul (remote_nsquare, remote_n, remote_n);
  gcry_sexp_release (tmp_exp);
  tmp_exp = gcry_sexp_find_token (request->remote_pubkey, "g", 0);
  gcry_sexp_release (request->remote_pubkey);
  request->remote_pubkey = NULL;
  if (!tmp_exp) {
    GNUNET_break_op (0);
    gcry_mpi_release (remote_n);
    goto except;
  }
  remote_g = gcry_sexp_nth_mpi (tmp_exp, 1, GCRYMPI_FMT_USG);
  if (!remote_g) {
    GNUNET_break (0);
    gcry_mpi_release (remote_n);
    gcry_sexp_release (tmp_exp);
    goto except;
  }
  gcry_sexp_release (tmp_exp);

  // generate r, p and q
  rand = initialize_mpi_vector (count);
  for (i = 0; i < count; i++) {
    value = (int32_t) GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, UINT32_MAX);

    // long to gcry_mpi_t
    if (value < 0)
      gcry_mpi_sub_ui (rand[i],
                       rand[i],
                       -value);
    else
      rand[i] = gcry_mpi_set_ui (rand[i], value);
  }
  p = GNUNET_CRYPTO_random_permute (GNUNET_CRYPTO_QUALITY_WEAK, count);
  q = GNUNET_CRYPTO_random_permute (GNUNET_CRYPTO_QUALITY_WEAK, count);
  //initialize the result vectors
  r = initialize_mpi_vector (count);
  r_prime = initialize_mpi_vector (count);

  // copy the REFERNCES of a, b and r into aq and bq. we will not change
  // those values, thus we can work with the references
  memcpy (a_pi, request->a, sizeof (gcry_mpi_t) * count);
  memcpy (a_pi_prime, request->a, sizeof (gcry_mpi_t) * count);
  memcpy (b_pi, b, sizeof (gcry_mpi_t) * count);
  memcpy (rand_pi, rand, sizeof (gcry_mpi_t) * count);
  memcpy (rand_pi_prime, rand, sizeof (gcry_mpi_t) * count);

  // generate p and q permutations for a, b and r
  GNUNET_assert (permute_vector (a_pi, p, count));
  GNUNET_assert (permute_vector (b_pi, p, count));
  GNUNET_assert (permute_vector (rand_pi, p, count));
  GNUNET_assert (permute_vector (a_pi_prime, q, count));
  GNUNET_assert (permute_vector (rand_pi_prime, q, count));

  // encrypt the element
  // for the sake of readability I decided to have dedicated permutation
  // vectors, which get rid of all the lookups in p/q.
  // however, ap/aq are not absolutely necessary but are just abstraction
  // Calculate Kp = E(S + a_pi) (+) E(S - r_pi - b_pi)
  for (i = 0; i < count; i++) {
    // E(S - r_pi - b_pi)
    gcry_mpi_sub (r[i], my_offset, rand_pi[i]);
    gcry_mpi_sub (r[i], r[i], b_pi[i]);
    encrypt_element (r[i], r[i], remote_g, remote_n, remote_nsquare);

    // E(S - r_pi - b_pi) * E(S + a_pi) ==  E(2*S + a - r - b)
    gcry_mpi_mulm (r[i], r[i], a_pi[i], remote_nsquare);
  }
  GNUNET_free (a_pi);
  GNUNET_free (b_pi);
  GNUNET_free (rand_pi);

  // Calculate Kq = E(S + a_qi) (+) E(S - r_qi)
  for (i = 0; i < count; i++) {
    // E(S - r_qi)
    gcry_mpi_sub (r_prime[i], my_offset, rand_pi_prime[i]);
    encrypt_element (r_prime[i], r_prime[i], remote_g, remote_n, remote_nsquare);

    // E(S - r_qi) * E(S + a_qi) == E(2*S + a_qi - r_qi)
    gcry_mpi_mulm (r_prime[i], r_prime[i], a_pi_prime[i], remote_nsquare);
  }
  GNUNET_free (a_pi_prime);
  GNUNET_free (rand_pi_prime);

  request->r = r;
  request->r_prime = r_prime;
  request->response = response;

  // Calculate S' =  E(SUM( r_i^2 ))
  s_prime = compute_square_sum (rand, count);
  encrypt_element (s_prime, s_prime, remote_g, remote_n, remote_nsquare);

  // Calculate S = E(SUM( (r_i + b_i)^2 ))
  for (i = 0; i < count; i++) {
    gcry_mpi_add (rand[i], rand[i], b[i]);
  }
  s = compute_square_sum (rand, count);
  encrypt_element (s, s, remote_g, remote_n, remote_nsquare);
  gcry_mpi_release (remote_n);
  gcry_mpi_release (remote_g);
  gcry_mpi_release (remote_nsquare);

  // release r and tmp
  for (i = 0; i < count; i++)
    // rp, rq, aq, ap, bp, bq are released along with a, r, b respectively, (a and b are handled at except:)
    gcry_mpi_release (rand[i]);

  // copy the r[], r_prime[], S and Stick into a new message, prepare_service_response frees these
  if (GNUNET_YES != prepare_service_response (s, s_prime, request))
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, _ ("Failed to communicate with `%s', scalar product calculation aborted.\n"),
                GNUNET_i2s (&request->peer));
  else
    ret = GNUNET_OK;

except:
  for (i = 0; i < count; i++) {
    gcry_mpi_release (b[i]);
    gcry_mpi_release (request->a[i]);
  }

  GNUNET_free (b);
  GNUNET_free (request->a);
  request->a = NULL;

  return ret;
}


/**
 * Send a multi part chunk of a service request from alice to bob.
 * This element only contains a part of the elements-vector (session->a[]),
 * mask and public key set have to be contained within the first message
 * 
 * This allows a ~32kbit key length while using 32000 elements or 62000 elements per request.
 * 
 * @param cls the associated service session
 */
static void
prepare_service_request_multipart (void *cls)
{
  struct ServiceSession * session = cls;
  unsigned char * current;
  unsigned char * element_exported;
  struct GNUNET_SCALARPRODUCT_multipart_message * msg;
  unsigned int i;
  unsigned int j;
  uint32_t msg_length;
  uint32_t todo_count;
  size_t element_length = 0; // initialized by gcry_mpi_print, but the compiler doesn't know that
  gcry_mpi_t a;
  uint32_t value;

  msg_length = sizeof (struct GNUNET_SCALARPRODUCT_multipart_message);
  todo_count = session->used - session->transferred;

  if (todo_count > MULTIPART_ELEMENT_CAPACITY)
    // send the currently possible maximum chunk
    todo_count = MULTIPART_ELEMENT_CAPACITY;

  msg_length += todo_count * PAILLIER_ELEMENT_LENGTH;
  msg = GNUNET_malloc (msg_length);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ALICE_TO_BOB_MULTIPART);
  msg->header.size = htons (msg_length);
  msg->multipart_element_count = htonl (todo_count);

  element_exported = GNUNET_malloc (PAILLIER_ELEMENT_LENGTH);
  a = gcry_mpi_new (KEYBITS * 2);
  current = (unsigned char *) &msg[1];
  // encrypt our vector and generate string representations
  for (i = session->last_processed, j = 0; i < session->total; i++) {
    // is this a used element?
    if (session->mask[i / 8] & 1 << (i % 8)) {
      if (todo_count <= j)
        break; //reached end of this message, can't include more

      memset (element_exported, 0, PAILLIER_ELEMENT_LENGTH);
      value = session->vector[i] >= 0 ? session->vector[i] : -session->vector[i];

      a = gcry_mpi_set_ui (a, 0);
      // long to gcry_mpi_t
      if (session->vector[i] < 0)
        gcry_mpi_sub_ui (a, a, value);
      else
        gcry_mpi_add_ui (a, a, value);

      session->a[session->transferred + j++] = gcry_mpi_set (NULL, a);
      gcry_mpi_add (a, a, my_offset);
      encrypt_element (a, a, my_g, my_n, my_nsquare);

      // get representation as string
      // we always supply some value, so gcry_mpi_print fails only if it can't reserve memory
      GNUNET_assert (!gcry_mpi_print (GCRYMPI_FMT_USG,
                                      element_exported, PAILLIER_ELEMENT_LENGTH,
                                      &element_length,
                                      a));

      // move buffer content to the end of the buffer so it can easily be read by libgcrypt. also this now has fixed size
      adjust (element_exported, element_length, PAILLIER_ELEMENT_LENGTH);

      // copy over to the message
      memcpy (current, element_exported, PAILLIER_ELEMENT_LENGTH);
      current += PAILLIER_ELEMENT_LENGTH;
    }
  }
  gcry_mpi_release (a);
  GNUNET_free (element_exported);
  session->transferred += todo_count;

  session->msg = (struct GNUNET_MessageHeader *) msg;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _ ("Transmitting service request.\n"));

  //transmit via mesh messaging
  session->service_transmit_handle = GNUNET_MESH_notify_transmit_ready (session->channel, GNUNET_YES,
                                                                        GNUNET_TIME_UNIT_FOREVER_REL,
                                                                        msg_length,
                                                                        &do_send_message,
                                                                        session);
  if (!session->service_transmit_handle) {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _ ("Could not send service-request multipart message to channel!\n"));
    GNUNET_free (msg);
    session->msg = NULL;
    session->client_notification_task =
            GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                      session);
    return;
  }
  if (session->transferred != session->used) {
    session->last_processed = i;
  }
  else
    //final part
    session->state = WAITING_FOR_SERVICE_RESPONSE;
}


/**
 * Executed by Alice, fills in a service-request message and sends it to the given peer
 *
 * @param cls the session associated with this request
 * @param tc task context handed over by scheduler, unsued
 */
static void
prepare_service_request (void *cls,
                         const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ServiceSession * session = cls;
  unsigned char * current;
  unsigned char * element_exported;
  struct GNUNET_SCALARPRODUCT_service_request * msg;
  unsigned int i;
  unsigned int j;
  uint32_t msg_length;
  size_t element_length = 0; // initialized by gcry_mpi_print, but the compiler doesn't know that
  gcry_mpi_t a;
  uint32_t value;

  session->service_request_task = GNUNET_SCHEDULER_NO_TASK;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _ ("Successfully created new channel to peer (%s)!\n"), GNUNET_i2s (&session->peer));

  msg_length = sizeof (struct GNUNET_SCALARPRODUCT_service_request)
          +session->mask_length
          + my_pubkey_external_length;

  if (GNUNET_SERVER_MAX_MESSAGE_SIZE > msg_length + session->used * PAILLIER_ELEMENT_LENGTH) {
    msg_length += session->used * PAILLIER_ELEMENT_LENGTH;
    session->transferred = session->used;
  }
  else {
    //create a multipart msg, first we calculate a new msg size for the head msg
    session->transferred = (GNUNET_SERVER_MAX_MESSAGE_SIZE - 1 - msg_length) / PAILLIER_ELEMENT_LENGTH;
  }

  msg = GNUNET_malloc (msg_length);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ALICE_TO_BOB);
  msg->total_element_count = htonl (session->used);
  msg->contained_element_count = htonl (session->transferred);
  memcpy (&msg->key, &session->key, sizeof (struct GNUNET_HashCode));
  msg->mask_length = htonl (session->mask_length);
  msg->pk_length = htonl (my_pubkey_external_length);
  msg->element_count = htonl (session->total);
  msg->header.size = htons (msg_length);

  // fill in the payload
  current = (unsigned char *) &msg[1];
  // copy over the mask
  memcpy (current, session->mask, session->mask_length);
  // copy over our public key
  current += session->mask_length;
  memcpy (current, my_pubkey_external, my_pubkey_external_length);
  current += my_pubkey_external_length;

  // now copy over the element vector
  element_exported = GNUNET_malloc (PAILLIER_ELEMENT_LENGTH);
  session->a = GNUNET_malloc (sizeof (gcry_mpi_t) * session->used);
  a = gcry_mpi_new (KEYBITS * 2);
  // encrypt our vector and generate string representations
  for (i = 0, j = 0; i < session->total; i++) {
    // if this is a used element...
    if (session->mask[i / 8] & 1 << (i % 8)) {
      if (session->transferred <= j)
        break; //reached end of this message, can't include more

      memset (element_exported, 0, PAILLIER_ELEMENT_LENGTH);
      value = session->vector[i] >= 0 ? session->vector[i] : -session->vector[i];

      a = gcry_mpi_set_ui (a, 0);
      // long to gcry_mpi_t
      if (session->vector[i] < 0)
        gcry_mpi_sub_ui (a, a, value);
      else
        gcry_mpi_add_ui (a, a, value);

      session->a[j++] = gcry_mpi_set (NULL, a);
      gcry_mpi_add (a, a, my_offset);
      encrypt_element (a, a, my_g, my_n, my_nsquare);

      // get representation as string
      // we always supply some value, so gcry_mpi_print fails only if it can't reserve memory
      GNUNET_assert (!gcry_mpi_print (GCRYMPI_FMT_USG,
                                      element_exported, PAILLIER_ELEMENT_LENGTH,
                                      &element_length,
                                      a));

      // move buffer content to the end of the buffer so it can easily be read by libgcrypt. also this now has fixed size
      adjust (element_exported, element_length, PAILLIER_ELEMENT_LENGTH);

      // copy over to the message
      memcpy (current, element_exported, PAILLIER_ELEMENT_LENGTH);
      current += PAILLIER_ELEMENT_LENGTH;
    }
  }
  gcry_mpi_release (a);
  GNUNET_free (element_exported);

  session->msg = (struct GNUNET_MessageHeader *) msg;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _ ("Transmitting service request.\n"));

  //transmit via mesh messaging
  session->service_transmit_handle = GNUNET_MESH_notify_transmit_ready (session->channel, GNUNET_YES,
                                                                        GNUNET_TIME_UNIT_FOREVER_REL,
                                                                        msg_length,
                                                                        &do_send_message,
                                                                        session);
  if (!session->service_transmit_handle) {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _ ("Could not send message to channel!\n"));
    GNUNET_free (msg);
    session->msg = NULL;
    session->client_notification_task =
            GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                      session);
    return;
  }
  if (session->transferred != session->used) {
    session->state = WAITING_FOR_MULTIPART_TRANSMISSION;
    session->last_processed = i;
  }
  else
    //singlepart message
    session->state = WAITING_FOR_SERVICE_RESPONSE;
}


/**
 * Handler for a client request message.
 * Can either be type A or B
 *   A: request-initiation to compute a scalar product with a peer
 *   B: response role, keep the values + session and wait for a matching session or process a waiting request
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_client_request (void *cls,
                       struct GNUNET_SERVER_Client *client,
                       const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_SCALARPRODUCT_client_request * msg = (const struct GNUNET_SCALARPRODUCT_client_request *) message;
  struct ServiceSession * session;
  uint32_t element_count;
  uint32_t mask_length;
  uint32_t msg_type;
  int32_t * vector;
  uint32_t i;

  // only one concurrent session per client connection allowed, simplifies logics a lot...
  session = GNUNET_SERVER_client_get_user_context (client, struct ServiceSession);
  if ((NULL != session) && (session->state != FINALIZED)) {
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  else if (NULL != session) {
    // old session is already completed, clean it up
    GNUNET_CONTAINER_DLL_remove (from_client_head, from_client_tail, session);
    free_session_variables (session);
    GNUNET_free (session);
  }

  //we need at least a peer and one message id to compare
  if (sizeof (struct GNUNET_SCALARPRODUCT_client_request) > ntohs (msg->header.size)) {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("Too short message received from client!\n"));
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  msg_type = ntohs (msg->header.type);
  element_count = ntohl (msg->element_count);
  mask_length = ntohl (msg->mask_length);

  //sanity check: is the message as long as the message_count fields suggests?
  if ((ntohs (msg->header.size) != (sizeof (struct GNUNET_SCALARPRODUCT_client_request) +element_count * sizeof (int32_t) + mask_length))
      || (0 == element_count)) {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("Invalid message received from client, session information incorrect!\n"));
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  // do we have a duplicate session here already?
  if (NULL != find_matching_session (from_client_tail,
                                     &msg->key,
                                     element_count,
                                     NULL, NULL)) {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("Duplicate session information received, cannot create new session with key `%s'\n"),
                GNUNET_h2s (&msg->key));
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  session = GNUNET_new (struct ServiceSession);
  session->service_request_task = GNUNET_SCHEDULER_NO_TASK;
  session->client_notification_task = GNUNET_SCHEDULER_NO_TASK;
  session->client = client;
  session->total = element_count;
  session->mask_length = mask_length;
  // get our transaction key
  memcpy (&session->key, &msg->key, sizeof (struct GNUNET_HashCode));
  //allocate memory for vector and encrypted vector
  session->vector = GNUNET_malloc (sizeof (int32_t) * element_count);
  vector = (int32_t *) & msg[1];

  if (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_TO_ALICE == msg_type) {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                _ ("Got client-request-session with key %s, preparing channel to remote service.\n"),
                GNUNET_h2s (&session->key));

    session->role = ALICE;
    // fill in the mask
    session->mask = GNUNET_malloc (mask_length);
    memcpy (session->mask, &vector[element_count], mask_length);

    // copy over the elements
    session->used = 0;
    for (i = 0; i < element_count; i++) {
      session->vector[i] = ntohl (vector[i]);
      if (session->vector[i] == 0)
        session->mask[i / 8] &= ~(1 << (i % 8));
      if (session->mask[i / 8] & (1 << (i % 8)))
        session->used++;
    }

    if (0 == session->used) {
      GNUNET_break_op (0);
      GNUNET_free (session->vector);
      GNUNET_free (session);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
    //session with ourself makes no sense!
    if (!memcmp (&msg->peer, &me, sizeof (struct GNUNET_PeerIdentity))) {
      GNUNET_break (0);
      GNUNET_free (session->vector);
      GNUNET_free (session);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
    // get our peer ID
    memcpy (&session->peer, &msg->peer, sizeof (struct GNUNET_PeerIdentity));
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _ ("Creating new channel for session with key %s.\n"),
                GNUNET_h2s (&session->key));
    session->channel = GNUNET_MESH_channel_create (my_mesh, session,
                                                 &session->peer,
                                                 GNUNET_APPLICATION_TYPE_SCALARPRODUCT,
                                                 GNUNET_NO,
                                                 GNUNET_YES);
    //prepare_service_request, channel_peer_disconnect_handler,
    if (!session->channel) {
      GNUNET_break (0);
      GNUNET_free (session->vector);
      GNUNET_free (session);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
    GNUNET_SERVER_client_set_user_context (client, session);
    GNUNET_CONTAINER_DLL_insert (from_client_head, from_client_tail, session);

    session->state = CLIENT_REQUEST_RECEIVED;
    session->service_request_task =
            GNUNET_SCHEDULER_add_now (&prepare_service_request,
                                      session);

  }
  else {
    struct ServiceSession * requesting_session;
    enum SessionState needed_state = SERVICE_REQUEST_RECEIVED;

    session->role = BOB;
    session->mask = NULL;
    // copy over the elements
    session->used = element_count;
    for (i = 0; i < element_count; i++)
      session->vector[i] = ntohl (vector[i]);
    session->state = CLIENT_RESPONSE_RECEIVED;

    GNUNET_SERVER_client_set_user_context (client, session);
    GNUNET_CONTAINER_DLL_insert (from_client_head, from_client_tail, session);

    //check if service queue contains a matching request
    requesting_session = find_matching_session (from_service_tail,
                                                &session->key,
                                                session->total,
                                                &needed_state, NULL);
    if (NULL != requesting_session) {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, _ ("Got client-responder-session with key %s and a matching service-request-session set, processing.\n"), GNUNET_h2s (&session->key));
      if (GNUNET_OK != compute_service_response (requesting_session, session))
        session->client_notification_task =
              GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                        session);

    }
    else {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, _ ("Got client-responder-session with key %s but NO matching service-request-session set, queuing element for later use.\n"), GNUNET_h2s (&session->key));
      // no matching session exists yet, store the response
      // for later processing by handle_service_request()
    }
  }
  GNUNET_SERVER_receive_done (client, GNUNET_YES);
}


/**
 * Function called for inbound channels.
 *
 * @param cls closure
 * @param channel new handle to the channel
 * @param initiator peer that started the channel
 * @param port unused
 * @return session associated with the channel
 */
static void *
channel_incoming_handler (void *cls,
                         struct GNUNET_MESH_Channel *channel,
                         const struct GNUNET_PeerIdentity *initiator,
                         uint32_t port)
{
  struct ServiceSession * c = GNUNET_new (struct ServiceSession);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _ ("New incoming channel from peer %s.\n"), GNUNET_i2s (initiator));
  
  c->peer = *initiator;
  c->channel = channel;
  c->role = BOB;
  c->state = WAITING_FOR_SERVICE_REQUEST;
  return c;
}


/**
 * Function called whenever a channel is destroyed.  Should clean up
 * any associated state.
 *
 * It must NOT call GNUNET_MESH_channel_destroy on the channel.
 *
 * @param cls closure (set from GNUNET_MESH_connect)
 * @param channel connection to the other end (henceforth invalid)
 * @param channel_ctx place where local state associated
 *                   with the channel is stored
 */
static void
channel_destruction_handler (void *cls,
                            const struct GNUNET_MESH_Channel *channel,
                            void *channel_ctx)
{
  struct ServiceSession * session = channel_ctx;
  struct ServiceSession * client_session;
  struct ServiceSession * curr;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _ ("Peer disconnected, terminating session %s with peer (%s)\n"),
              GNUNET_h2s (&session->key),
              GNUNET_i2s (&session->peer));
  if (ALICE == session->role) {
    // as we have only one peer connected in each session, just remove the session
    
    if ((SERVICE_RESPONSE_RECEIVED > session->state) && (!do_shutdown)) {
      session->channel = NULL;
      // if this happened before we received the answer, we must terminate the session
      session->client_notification_task =
              GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                        session);
    }
  }
  else { //(BOB == session->role) service session
    // remove the session, unless it has already been dequeued, but somehow still active
    // this could bug without the IF in case the queue is empty and the service session was the only one know to the service
    // scenario: disconnect before alice can send her message to bob.
    for (curr = from_service_head; NULL != curr; curr = curr->next)
      if (curr == session) {
        GNUNET_CONTAINER_DLL_remove (from_service_head, from_service_tail, curr);
        break;
      }
    // there is a client waiting for this service session, terminate it, too!
    // i assume the tupel of key and element count is unique. if it was not the rest of the code would not work either.
    client_session = find_matching_session (from_client_tail,
                                            &session->key,
                                            session->total,
                                            NULL, NULL);
    free_session_variables (session);
    GNUNET_free (session);

    // the client has to check if it was waiting for a result
    // or if it was a responder, no point in adding more statefulness
    if (client_session && (!do_shutdown)) {
      client_session->state = FINALIZED;
      client_session->client_notification_task =
              GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                        client_session);
    }
  }
}


/**
 * Compute our scalar product, done by Alice
 *
 * @param session - the session associated with this computation
 * @return product as MPI, never NULL
 */
static gcry_mpi_t
compute_scalar_product (struct ServiceSession * session)
{
  uint32_t count;
  gcry_mpi_t t;
  gcry_mpi_t u;
  gcry_mpi_t u_prime;
  gcry_mpi_t p;
  gcry_mpi_t p_prime;
  gcry_mpi_t tmp;
  unsigned int i;

  count = session->used;
  tmp = gcry_mpi_new (KEYBITS);
  // due to the introduced static offset S, we now also have to remove this
  // from the E(a_pi)(+)E(-b_pi-r_pi) and E(a_qi)(+)E(-r_qi) twice each,
  // the result is E((S + a_pi) + (S -b_pi-r_pi)) and E(S + a_qi + S - r_qi)
  for (i = 0; i < count; i++) {
    decrypt_element (session->r[i], session->r[i], my_mu, my_lambda, my_n, my_nsquare);
    gcry_mpi_sub (session->r[i], session->r[i], my_offset);
    gcry_mpi_sub (session->r[i], session->r[i], my_offset);
    decrypt_element (session->r_prime[i], session->r_prime[i], my_mu, my_lambda, my_n, my_nsquare);
    gcry_mpi_sub (session->r_prime[i], session->r_prime[i], my_offset);
    gcry_mpi_sub (session->r_prime[i], session->r_prime[i], my_offset);
  }

  // calculate t = sum(ai)
  t = compute_square_sum (session->a, count);

  // calculate U
  u = gcry_mpi_new (0);
  tmp = compute_square_sum (session->r, count);
  gcry_mpi_sub (u, u, tmp);
  gcry_mpi_release (tmp);

  //calculate U'
  u_prime = gcry_mpi_new (0);
  tmp = compute_square_sum (session->r_prime, count);
  gcry_mpi_sub (u_prime, u_prime, tmp);

  GNUNET_assert (p = gcry_mpi_new (0));
  GNUNET_assert (p_prime = gcry_mpi_new (0));

  // compute P
  decrypt_element (session->s, session->s, my_mu, my_lambda, my_n, my_nsquare);
  decrypt_element (session->s_prime, session->s_prime, my_mu, my_lambda, my_n, my_nsquare);

  // compute P
  gcry_mpi_add (p, session->s, t);
  gcry_mpi_add (p, p, u);

  // compute P'
  gcry_mpi_add (p_prime, session->s_prime, t);
  gcry_mpi_add (p_prime, p_prime, u_prime);

  gcry_mpi_release (t);
  gcry_mpi_release (u);
  gcry_mpi_release (u_prime);

  // compute product
  gcry_mpi_sub (p, p, p_prime);
  gcry_mpi_release (p_prime);
  tmp = gcry_mpi_set_ui (tmp, 2);
  gcry_mpi_div (p, NULL, p, tmp, 0);

  gcry_mpi_release (tmp);
  for (i = 0; i < count; i++)
    gcry_mpi_release (session->a[i]);
  GNUNET_free (session->a);
  session->a = NULL;

  return p;
}


/**
 * Handle a multipart-chunk of a request from another service to calculate a scalarproduct with us.
 *
 * @param cls closure (set from #GNUNET_MESH_connect)
 * @param channel connection to the other end
 * @param channel_ctx place to store local state associated with the channel
 * @param message the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_service_request_multipart (void *cls,
                                  struct GNUNET_MESH_Channel * channel,
                                  void **channel_ctx,
                                  const struct GNUNET_MessageHeader * message)
{
  struct ServiceSession * session;
  const struct GNUNET_SCALARPRODUCT_multipart_message * msg = (const struct GNUNET_SCALARPRODUCT_multipart_message *) message;
  uint32_t used_elements;
  uint32_t contained_elements = 0;
  uint32_t msg_length;
  unsigned char * current;
  gcry_error_t rc;
  int32_t i = -1;

  // are we in the correct state?
  session = (struct ServiceSession *) * channel_ctx;
  if ((BOB != session->role) || (WAITING_FOR_MULTIPART_TRANSMISSION != session->state)) {
    goto except;
  }
  // shorter than minimum?
  if (ntohs (msg->header.size) <= sizeof (struct GNUNET_SCALARPRODUCT_multipart_message)) {
    goto except;
  }
  used_elements = session->used;
  contained_elements = ntohl (msg->multipart_element_count);
  msg_length = sizeof (struct GNUNET_SCALARPRODUCT_multipart_message)
          +contained_elements * PAILLIER_ELEMENT_LENGTH;
  //sanity check
  if ((ntohs (msg->header.size) != msg_length)
      || (used_elements < contained_elements + session->transferred)) {
    goto except;
  }
  current = (unsigned char *) &msg[1];
  if (contained_elements != 0) {
    // Convert each vector element to MPI_value
    for (i = session->transferred; i < session->transferred + contained_elements; i++) {
      size_t read = 0;
      if (0 != (rc = gcry_mpi_scan (&session->a[i],
                                    GCRYMPI_FMT_USG,
                                    &current[i * PAILLIER_ELEMENT_LENGTH],
                                    PAILLIER_ELEMENT_LENGTH,
                                    &read))) {
        LOG_GCRY (GNUNET_ERROR_TYPE_DEBUG, "gcry_mpi_scan", rc);
        goto except;
      }
    }
    session->transferred += contained_elements;

    if (session->transferred == used_elements) {
      // single part finished
      session->state = SERVICE_REQUEST_RECEIVED;
      if (session->response) {
        GNUNET_log (GNUNET_ERROR_TYPE_INFO, _ ("Got session with key %s and a matching element set, processing.\n"), GNUNET_h2s (&session->key));
        if (GNUNET_OK != compute_service_response (session, session->response)) {
          //something went wrong, remove it again...
          goto except;
        }
      }
      else
        GNUNET_log (GNUNET_ERROR_TYPE_INFO, _ ("Got session with key %s without a matching element set, queueing.\n"), GNUNET_h2s (&session->key));
    }
    else {
      // multipart message
    }
  }

  return GNUNET_OK;
except:
  // and notify our client-session that we could not complete the session
  GNUNET_CONTAINER_DLL_remove (from_service_head, from_service_tail, session);
  if (session->response)
    // we just found the responder session in this queue
    session->response->client_notification_task =
          GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                    session->response);
  free_session_variables (session);
  GNUNET_free (session);
  return GNUNET_SYSERR;
}


/**
 * Handle a request from another service to calculate a scalarproduct with us.
 *
 * @param cls closure (set from #GNUNET_MESH_connect)
 * @param channel connection to the other end
 * @param channel_ctx place to store local state associated with the channel
 * @param message the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_service_request (void *cls,
                        struct GNUNET_MESH_Channel * channel,
                        void **channel_ctx,
                        const struct GNUNET_MessageHeader * message)
{
  struct ServiceSession * session;
  const struct GNUNET_SCALARPRODUCT_service_request * msg = (const struct GNUNET_SCALARPRODUCT_service_request *) message;
  uint32_t mask_length;
  uint32_t pk_length;
  uint32_t used_elements;
  uint32_t contained_elements = 0;
  uint32_t element_count;
  uint32_t msg_length;
  unsigned char * current;
  gcry_error_t rc;
  int32_t i = -1;
  enum SessionState needed_state;

  session = (struct ServiceSession *) * channel_ctx;
  if (WAITING_FOR_SERVICE_REQUEST != session->state) {
    goto invalid_msg;
  }
  // Check if message was sent by me, which would be bad!
  if (!memcmp (&session->peer, &me, sizeof (struct GNUNET_PeerIdentity))) {
    GNUNET_free (session);
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  // shorter than expected?
  if (ntohs (msg->header.size) < sizeof (struct GNUNET_SCALARPRODUCT_service_request)) {
    GNUNET_free (session);
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  mask_length = ntohl (msg->mask_length);
  pk_length = ntohl (msg->pk_length);
  used_elements = ntohl (msg->total_element_count);
  contained_elements = ntohl (msg->contained_element_count);
  element_count = ntohl (msg->element_count);
  msg_length = sizeof (struct GNUNET_SCALARPRODUCT_service_request)
          +mask_length + pk_length + contained_elements * PAILLIER_ELEMENT_LENGTH;

  //sanity check: is the message as long as the message_count fields suggests?
  if ((ntohs (msg->header.size) != msg_length) || (element_count < used_elements) || (used_elements < contained_elements)
      || (used_elements == 0) || (mask_length != (element_count / 8 + (element_count % 8 ? 1 : 0)))
      ) {
    GNUNET_free (session);
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (find_matching_session (from_service_tail,
                             &msg->key,
                             element_count,
                             NULL,
                             NULL)) {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _ ("Got message with duplicate session key (`%s'), ignoring service request.\n"), (const char *) &(msg->key));
    GNUNET_free (session);
    return GNUNET_SYSERR;
  }

  session->total = element_count;
  session->used = used_elements;
  session->transferred = contained_elements;
  session->channel = channel;

  // session key
  memcpy (&session->key, &msg->key, sizeof (struct GNUNET_HashCode));
  current = (unsigned char *) &msg[1];
  //preserve the mask, we will need that later on
  session->mask = GNUNET_malloc (mask_length);
  memcpy (session->mask, current, mask_length);
  //the public key
  current += mask_length;

  //convert the publickey to sexp
  if (0 != (rc = gcry_sexp_new (&session->remote_pubkey, current, pk_length, 1))) {
    LOG_GCRY (GNUNET_ERROR_TYPE_DEBUG, "gcry_sexp_new", rc);
    GNUNET_free (session->mask);
    GNUNET_free (session);
    return GNUNET_SYSERR;
  }
  current += pk_length;
  //check if service queue contains a matching request
  needed_state = CLIENT_RESPONSE_RECEIVED;
  session->response = find_matching_session (from_client_tail,
                                             &session->key,
                                             session->total,
                                             &needed_state, NULL);

  session->a = GNUNET_malloc (sizeof (gcry_mpi_t) * used_elements);
  session->state = WAITING_FOR_MULTIPART_TRANSMISSION;
  GNUNET_CONTAINER_DLL_insert (from_service_head, from_service_tail, session);
  if (contained_elements != 0) {
    // Convert each vector element to MPI_value
    for (i = 0; i < contained_elements; i++) {
      size_t read = 0;
      if (0 != (rc = gcry_mpi_scan (&session->a[i],
                                    GCRYMPI_FMT_USG,
                                    &current[i * PAILLIER_ELEMENT_LENGTH],
                                    PAILLIER_ELEMENT_LENGTH,
                                    &read))) {
        LOG_GCRY (GNUNET_ERROR_TYPE_DEBUG, "gcry_mpi_scan", rc);
        goto invalid_msg;
      }
    }
    if (contained_elements == used_elements) {
      // single part finished
      session->state = SERVICE_REQUEST_RECEIVED;
      if (session->response) {
        GNUNET_log (GNUNET_ERROR_TYPE_INFO, _ ("Got session with key %s and a matching element set, processing.\n"), GNUNET_h2s (&session->key));
        if (GNUNET_OK != compute_service_response (session, session->response)) {
          //something went wrong, remove it again...
          goto invalid_msg;
        }
      }
      else
        GNUNET_log (GNUNET_ERROR_TYPE_INFO, _ ("Got session with key %s without a matching element set, queueing.\n"), GNUNET_h2s (&session->key));
    }
    else {
      // multipart message
    }
  }
  return GNUNET_OK;
invalid_msg:
  GNUNET_break_op (0);
  if ((NULL != session->next) || (NULL != session->prev) || (from_service_head == session))
    GNUNET_CONTAINER_DLL_remove (from_service_head, from_service_tail, session);
  // and notify our client-session that we could not complete the session
  if (session->response)
    // we just found the responder session in this queue
    session->response->client_notification_task =
          GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                    session->response);
  free_session_variables (session);
  return GNUNET_SYSERR;
}


/**
 * Handle a multipart chunk of a response we got from another service we wanted to calculate a scalarproduct with.
 *
 * @param cls closure (set from #GNUNET_MESH_connect)
 * @param channel connection to the other end
 * @param channel_ctx place to store local state associated with the channel
 * @param message the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_service_response_multipart (void *cls,
                                   struct GNUNET_MESH_Channel * channel,
                                   void **channel_ctx,
                                   const struct GNUNET_MessageHeader * message)
{
  struct ServiceSession * session;
  const struct GNUNET_SCALARPRODUCT_multipart_message * msg = (const struct GNUNET_SCALARPRODUCT_multipart_message *) message;
  unsigned char * current;
  size_t read;
  size_t i;
  uint32_t contained = 0;
  size_t msg_size;
  size_t required_size;
  int rc;

  GNUNET_assert (NULL != message);
  // are we in the correct state?
  session = (struct ServiceSession *) * channel_ctx;
  if ((ALICE != session->role) || (WAITING_FOR_MULTIPART_TRANSMISSION != session->state)) {
    goto invalid_msg;
  }
  msg_size = ntohs (msg->header.size);
  required_size = sizeof (struct GNUNET_SCALARPRODUCT_multipart_message) + 2 * PAILLIER_ELEMENT_LENGTH;
  // shorter than minimum?
  if (required_size > msg_size) {
    goto invalid_msg;
  }
  contained = ntohl (msg->multipart_element_count);
  required_size = sizeof (struct GNUNET_SCALARPRODUCT_multipart_message)
          + 2 * contained * PAILLIER_ELEMENT_LENGTH;
  //sanity check: is the message as long as the message_count fields suggests?
  if ((required_size != msg_size) || (session->used < session->transferred + contained)) {
    goto invalid_msg;
  }
  current = (unsigned char *) &msg[1];
  // Convert each k[][perm] to its MPI_value
  for (i = 0; i < contained; i++) {
    if (0 != (rc = gcry_mpi_scan (&session->r[i], GCRYMPI_FMT_USG, current,
                                  PAILLIER_ELEMENT_LENGTH, &read))) {
      LOG_GCRY (GNUNET_ERROR_TYPE_DEBUG, "gcry_mpi_scan", rc);
      goto invalid_msg;
    }
    current += PAILLIER_ELEMENT_LENGTH;
    if (0 != (rc = gcry_mpi_scan (&session->r_prime[i], GCRYMPI_FMT_USG, current,
                                  PAILLIER_ELEMENT_LENGTH, &read))) {
      LOG_GCRY (GNUNET_ERROR_TYPE_DEBUG, "gcry_mpi_scan", rc);
      goto invalid_msg;
    }
    current += PAILLIER_ELEMENT_LENGTH;
  }
  session->transferred += contained;
  if (session->transferred != session->used)
    return GNUNET_OK;
  session->state = SERVICE_RESPONSE_RECEIVED;
  session->product = compute_scalar_product (session); //never NULL
  
invalid_msg:
  GNUNET_break_op (NULL != session->product);

  // send message with product to client
  if (ALICE == session->role){
    session->state = FINALIZED;
    session->channel = NULL;
    session->client_notification_task =
          GNUNET_SCHEDULER_add_now (&prepare_client_response,
                                    session);
  }
  // the channel has done its job, terminate our connection and the channel
  // the peer will be notified that the channel was destroyed via channel_destruction_handler
  // just close the connection, as recommended by Christian
  return GNUNET_SYSERR;
}


/**
 * Handle a response we got from another service we wanted to calculate a scalarproduct with.
 *
 * @param cls closure (set from #GNUNET_MESH_connect)
 * @param channel connection to the other end
 * @param channel_ctx place to store local state associated with the channel
 * @param message the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (we are done)
 */
static int
handle_service_response (void *cls,
                         struct GNUNET_MESH_Channel * channel,
                         void **channel_ctx,
                         const struct GNUNET_MessageHeader * message)
{
  struct ServiceSession * session;
  const struct GNUNET_SCALARPRODUCT_service_response * msg = (const struct GNUNET_SCALARPRODUCT_service_response *) message;
  unsigned char * current;
  size_t read;
  size_t i;
  uint32_t contained = 0;
  size_t msg_size;
  size_t required_size;
  int rc;

  GNUNET_assert (NULL != message);
  session = (struct ServiceSession *) * channel_ctx;
  // are we in the correct state?
  if (WAITING_FOR_SERVICE_RESPONSE != session->state) {
    goto invalid_msg;
  }
  //we need at least a full message without elements attached
  msg_size = ntohs (msg->header.size);
  required_size = sizeof (struct GNUNET_SCALARPRODUCT_service_response) + 2 * PAILLIER_ELEMENT_LENGTH;
  
  if (required_size > msg_size) {
    goto invalid_msg;
  }
  contained = ntohl (msg->contained_element_count);
  required_size = sizeof (struct GNUNET_SCALARPRODUCT_service_response)
          + 2 * contained * PAILLIER_ELEMENT_LENGTH
          + 2 * PAILLIER_ELEMENT_LENGTH;
  //sanity check: is the message as long as the message_count fields suggests?
  if ((msg_size != required_size) || (session->used < contained)) {
    goto invalid_msg;
  }
  session->state = WAITING_FOR_MULTIPART_TRANSMISSION;
  session->transferred = contained;
  //convert s
  current = (unsigned char *) &msg[1];
  if (0 != (rc = gcry_mpi_scan (&session->s, GCRYMPI_FMT_USG, current,
                                PAILLIER_ELEMENT_LENGTH, &read))) {
    LOG_GCRY (GNUNET_ERROR_TYPE_DEBUG, "gcry_mpi_scan", rc);
    goto invalid_msg;
  }
  current += PAILLIER_ELEMENT_LENGTH;
  //convert stick
  if (0 != (rc = gcry_mpi_scan (&session->s_prime, GCRYMPI_FMT_USG, current,
                                PAILLIER_ELEMENT_LENGTH, &read))) {
    LOG_GCRY (GNUNET_ERROR_TYPE_DEBUG, "gcry_mpi_scan", rc);
    goto invalid_msg;
  }
  current += PAILLIER_ELEMENT_LENGTH;
  session->r = GNUNET_malloc (sizeof (gcry_mpi_t) * session->used);
  session->r_prime = GNUNET_malloc (sizeof (gcry_mpi_t) * session->used);
  // Convert each k[][perm] to its MPI_value
  for (i = 0; i < contained; i++) {
    if (0 != (rc = gcry_mpi_scan (&session->r[i], GCRYMPI_FMT_USG, current,
                                  PAILLIER_ELEMENT_LENGTH, &read))) {
      LOG_GCRY (GNUNET_ERROR_TYPE_DEBUG, "gcry_mpi_scan", rc);
      goto invalid_msg;
    }
    current += PAILLIER_ELEMENT_LENGTH;
    if (0 != (rc = gcry_mpi_scan (&session->r_prime[i], GCRYMPI_FMT_USG, current,
                                  PAILLIER_ELEMENT_LENGTH, &read))) {
      LOG_GCRY (GNUNET_ERROR_TYPE_DEBUG, "gcry_mpi_scan", rc);
      goto invalid_msg;
    }
    current += PAILLIER_ELEMENT_LENGTH;
  }
  if (session->transferred != session->used)
    return GNUNET_OK; //wait for the other multipart chunks

  session->state = SERVICE_RESPONSE_RECEIVED;
  session->product = compute_scalar_product (session); //never NULL
  
invalid_msg:
  GNUNET_break_op (NULL != session->product);
  // send message with product to client
  if (ALICE == session->role){
    session->state = FINALIZED;
    session->channel = NULL;
    session->client_notification_task =
          GNUNET_SCHEDULER_add_now (&prepare_client_response,
                                    session);
  }
  // the channel has done its job, terminate our connection and the channel
  // the peer will be notified that the channel was destroyed via channel_destruction_handler
  // just close the connection, as recommended by Christian
  return GNUNET_SYSERR;
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
  struct ServiceSession * session;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _ ("Shutting down, initiating cleanup.\n"));

  do_shutdown = GNUNET_YES;

  // terminate all owned open channels.
  for (session = from_client_head; NULL != session; session = session->next) {
    if ((FINALIZED != session->state) && (NULL != session->channel)) {
      GNUNET_MESH_channel_destroy (session->channel);
      session->channel = NULL;
    }
    if (GNUNET_SCHEDULER_NO_TASK != session->client_notification_task) {
      GNUNET_SCHEDULER_cancel (session->client_notification_task);
      session->client_notification_task = GNUNET_SCHEDULER_NO_TASK;
    }
    if (GNUNET_SCHEDULER_NO_TASK != session->service_request_task) {
      GNUNET_SCHEDULER_cancel (session->service_request_task);
      session->service_request_task = GNUNET_SCHEDULER_NO_TASK;
    }
    if (NULL != session->client) {
      GNUNET_SERVER_client_disconnect (session->client);
      session->client = NULL;
    }
  }
  for (session = from_service_head; NULL != session; session = session->next)
    if (NULL != session->channel) {
      GNUNET_MESH_channel_destroy (session->channel);
      session->channel = NULL;
    }

  if (my_mesh) {
    GNUNET_MESH_disconnect (my_mesh);
    my_mesh = NULL;
  }
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
    {&handle_client_request, NULL, GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_TO_ALICE, 0},
    {&handle_client_request, NULL, GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_TO_BOB, 0},
    {NULL, NULL, 0, 0}
  };
  static const struct GNUNET_MESH_MessageHandler mesh_handlers[] = {
    { &handle_service_request, GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ALICE_TO_BOB, 0},
    { &handle_service_request_multipart, GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ALICE_TO_BOB_MULTIPART, 0},
    { &handle_service_response, GNUNET_MESSAGE_TYPE_SCALARPRODUCT_BOB_TO_ALICE, 0},
    { &handle_service_response_multipart, GNUNET_MESSAGE_TYPE_SCALARPRODUCT_BOB_TO_ALICE_MULTIPART, 0},
    {NULL, 0, 0}
  };
  static const uint32_t ports[] = {
    GNUNET_APPLICATION_TYPE_SCALARPRODUCT,
    0
  };
  //generate private/public key set
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _ ("Generating Paillier-Keyset.\n"));
  generate_keyset ();
  // register server callbacks and disconnect handler
  GNUNET_SERVER_add_handlers (server, server_handlers);
  GNUNET_SERVER_disconnect_notify (server,
                                   &handle_client_disconnect,
                                   NULL);
  GNUNET_break (GNUNET_OK ==
                GNUNET_CRYPTO_get_peer_identity (c,
                                                 &me));
  my_mesh = GNUNET_MESH_connect (c, NULL,
                                 &channel_incoming_handler,
                                 &channel_destruction_handler,
                                 mesh_handlers, ports);
  if (!my_mesh) {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _ ("Connect to MESH failed\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _ ("Mesh initialized\n"));
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
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc, argv,
                              "scalarproduct",
                              GNUNET_SERVICE_OPTION_NONE,
                              &run, NULL)) ? 0 : 1;
}

/* end of gnunet-service-scalarproduct.c */
