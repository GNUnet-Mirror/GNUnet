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
#include "gnunet_scalarproduct.h"


#define LOG(kind,...) GNUNET_log_from (kind, "scalarproduct", __VA_ARGS__)

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' with the message given
 * by gcry_strerror(rc).
 */
#define LOG_GCRY(level, cmd, rc) do { LOG(level, _("`%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, gcry_strerror(rc)); } while(0)

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
static uint16_t my_pubkey_external_length = 0;

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
  gcry_sexp_t gen_parms;
  gcry_sexp_t key;
  gcry_sexp_t tmp_sexp;
  gcry_mpi_t p;
  gcry_mpi_t q;
  gcry_mpi_t tmp1;
  gcry_mpi_t tmp2;
  gcry_mpi_t gcd;

  size_t erroff = 0;

  // we can still use the RSA keygen for generating p,q,n, but using e is pointless.
  GNUNET_assert (0 == gcry_sexp_build (&gen_parms, &erroff,
                                       "(genkey(rsa(nbits %d)(rsa-use-e 3:257)))",
                                       KEYBITS));

  GNUNET_assert (0 == gcry_pk_genkey (&key, gen_parms));
  gcry_sexp_release (gen_parms);

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
  // lambda = \frac{(p-1)*(q-1)}{gcd(p-1,q-1)}
  gcry_mpi_sub_ui (tmp1, p, 1);
  gcry_mpi_sub_ui (tmp2, q, 1);
  gcry_mpi_gcd (gcd, tmp1, tmp2);
  gcry_mpi_set (my_lambda, tmp1);
  gcry_mpi_mul (my_lambda, my_lambda, tmp2);
  gcry_mpi_div (my_lambda, NULL, my_lambda, gcd, 0);

  // generate a g
  gcry_mpi_mul (my_nsquare, my_n, my_n);
  do
    {
      // find a matching g
      do
        {
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
  my_offset = gcry_mpi_new(KEYBITS/3);
  gcry_mpi_set_bit(my_offset, KEYBITS/3);

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
  if (size < target)
    {
      memmove (&buf[target - size], buf, size);
      memset (buf, 0, target - size);
    }
}


/**
 * encrypts an element using the paillier crypto system
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

  while (0 >= gcry_mpi_cmp_ui (tmp, 1))
    {
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
compute_square_sum (gcry_mpi_t * vector, uint16_t length)
{
  gcry_mpi_t elem;
  gcry_mpi_t sum;
  int32_t i;

  GNUNET_assert (sum = gcry_mpi_new (0));
  GNUNET_assert (elem = gcry_mpi_new (0));

  // calculare E(sum (ai ^ 2), publickey)
  for (i = 0; i < length; i++)
    {
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
  struct MessageObject * info = cls;
  struct GNUNET_MessageHeader * msg;
  size_t written = 0;

  GNUNET_assert (info);
  msg = info->msg;
  GNUNET_assert (msg);
  GNUNET_assert (buf);

  if (ntohs (msg->size) == size)
    {
      memcpy (buf, msg, size);
      written = size;
    }

  // reset the transmit handle, if necessary
  if (info->transmit_handle)
    *info->transmit_handle = NULL;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Sent a message of type %hu.\n", 
	      ntohs (msg->type));
  GNUNET_free(msg);
  GNUNET_free(info);
  return written;
}


/**
 * initializes a new vector with fresh MPI values (=0) of a given length
 * 
 * @param length of the vector to create
 * @return the initialized vector, never NULL
 */
static gcry_mpi_t *
initialize_mpi_vector (uint16_t length)
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
 * Populate a vector with random integer values and convert them to 
 * 
 * @param length the length of the vector we must generate
 * @return an array of MPI values with random values
 */
static gcry_mpi_t *
generate_random_vector (uint16_t length)
{
  gcry_mpi_t * random_vector;
  int32_t value;
  uint32_t i;

  random_vector = initialize_mpi_vector (length);
  for (i = 0; i < length; i++)
    {
      value = (int32_t) GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, UINT32_MAX);

      // long to gcry_mpi_t
      if (value < 0)
        gcry_mpi_sub_ui (random_vector[i],
                         random_vector[i],
                         -value);
      else
        random_vector[i] = gcry_mpi_set_ui (random_vector[i], value);
    }

  return random_vector;
}


/**
 * Finds a not terminated client/service session in the 
 * given DLL based on session key, element count and state.
 * 
 * @param tail - the tail of the DLL
 * @param my - the session to compare it to
 * @return a pointer to a matching session, 
 *         else NULL
 */
static struct ServiceSession *
find_matching_session (struct ServiceSession * tail,
                       const struct GNUNET_HashCode * key,
                       uint16_t element_count,
                       enum SessionState * state,
                       const struct GNUNET_PeerIdentity * peerid)
{
  struct ServiceSession * curr;

  for (curr = tail; NULL != curr; curr = curr->prev)
    {
      // if the key matches, and the element_count is same
      if ((!memcmp (&curr->key, key, sizeof (struct GNUNET_HashCode)))
          && (curr->element_count == element_count))
        {
          // if incoming state is NULL OR is same as state of the queued request
          if ((NULL == state) || (curr->state == *state))
            {
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


static void
destroy_tunnel (void *cls,
                const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ServiceSession * session = cls;

  if (session->tunnel)
    {
      GNUNET_MESH_tunnel_destroy (session->tunnel);
      session->tunnel = NULL;
    }
  session->service_transmit_handle = NULL;
  // we need to set this to NULL so there is no problem with double-cancel later on.
}


static void
free_session (struct ServiceSession * session)
{
  unsigned int i;

  if (FINALIZED != session->state)
    {
      if (session->a)
        {
          for (i = 0; i < session->used_element_count; i++)
            gcry_mpi_release (session->a[i]);

          GNUNET_free (session->a);
        }
      if (session->product)
        gcry_mpi_release (session->product);

      if (session->remote_pubkey)
        gcry_sexp_release (session->remote_pubkey);

      GNUNET_free_non_null (session->vector);
    }

  GNUNET_free (session);
}
///////////////////////////////////////////////////////////////////////////////
//                      Event and Message Handlers
///////////////////////////////////////////////////////////////////////////////


/**
 * A client disconnected. 
 * 
 * Remove the associated session(s), release datastructures 
 * and cancel pending outgoing transmissions to the client.
 * if the session has not yet completed, we also cancel Alice's request to Bob.
 *
 * @param cls closure, NULL
 * @param client identification of the client
 */
static void
handle_client_disconnect (void *cls,
                          struct GNUNET_SERVER_Client
                          * client)
{
  struct ServiceSession * elem;
  struct ServiceSession * next;

  // start from the tail, old stuff will be there...
  for (elem = from_client_head; NULL != elem; elem = next)
    {
      next = elem->next;
      if (elem->client != client)
        continue;

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _ ("Client (%p) disconnected from us.\n"), client);
      GNUNET_CONTAINER_DLL_remove (from_client_head, from_client_tail, elem);

      if (!(elem->role == BOB && elem->state == FINALIZED))
        {
          //we MUST terminate any client message underway
          if (elem->service_transmit_handle && elem->tunnel)
            GNUNET_MESH_notify_transmit_ready_cancel (elem->service_transmit_handle);
          if (elem->tunnel && elem->state == WAITING_FOR_RESPONSE_FROM_SERVICE)
            destroy_tunnel (elem, NULL);
        }
      free_session (elem);
    }
}


/**
 * Notify the client that the session has succeeded or failed completely.
 * This message gets sent to 
 * * alice's client if bob disconnected or to
 * * bob's client if the operation completed or alice disconnected
 * 
 * @param client_session the associated client session
 * @return GNUNET_NO, if we could not notify the client
 *         GNUNET_YES if we notified it.
 */
static void
prepare_client_end_notification (void * cls,
                                 const struct GNUNET_SCHEDULER_TaskContext * tc)
{
  struct ServiceSession * session = cls;
  struct GNUNET_SCALARPRODUCT_client_response * msg;
  struct MessageObject * msg_obj;

  msg = GNUNET_new (struct GNUNET_SCALARPRODUCT_client_response);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_SERVICE_TO_CLIENT);
  memcpy (&msg->key, &session->key, sizeof (struct GNUNET_HashCode));
  memcpy (&msg->peer, &session->peer, sizeof ( struct GNUNET_PeerIdentity));
  msg->header.size = htons (sizeof (struct GNUNET_SCALARPRODUCT_client_response));
  // 0 size and the first char in the product is 0, which should never be zero if encoding is used.
  msg->product_length = htonl (0);

  msg_obj = GNUNET_new (struct MessageObject);
  msg_obj->msg = &msg->header;
  msg_obj->transmit_handle = NULL; // do not reset the transmit handle, please

  //transmit this message to our client
  session->client_transmit_handle =
          GNUNET_SERVER_notify_transmit_ready (session->client,
                                               sizeof (struct GNUNET_SCALARPRODUCT_client_response),
                                               GNUNET_TIME_UNIT_FOREVER_REL,
                                               &do_send_message,
                                               msg_obj);


  // if we could not even queue our request, something is wrong
  if ( ! session->client_transmit_handle)
    {

      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, _ ("Could not send message to client (%p)! This is OK if it was disconnected beforehand already.\n"), session->client);
      // usually gets freed by do_send_message
      GNUNET_free (msg_obj);
      GNUNET_free (msg);
    }
  else
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, _ ("Sending session-end notification to client (%p) for session %s\n"), &session->client, GNUNET_h2s (&session->key));
  
  free_session(session);
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
 * @param r    (1)[]: $E_A(a_{pi(i)}) times E_A(- r_{pi(i)} - b_{pi(i)}) &= E_A(a_{pi(i)} - r_{pi(i)} - b_{pi(i)})$
 * @param r_prime    (2)[]: $E_A(a_{pi'(i)}) times E_A(- r_{pi'(i)}) &= E_A(a_{pi'(i)} - r_{pi'(i)})$
 * @param s         S: $S := E_A(sum (r_i + b_i)^2)$
 * @param s_prime    S': $S' := E_A(sum r_i^2)$
 * @param request  the associated requesting session with alice
 * @param response the associated responder session with bob's client
 * @return GNUNET_SYSERR if the function was called with NULL parameters or if there was an error
 *         GNUNET_NO if we could not send our message
 *         GNUNET_OK if the operation succeeded
 */
static int
prepare_service_response (gcry_mpi_t * r,
                          gcry_mpi_t * r_prime,
                          gcry_mpi_t s,
                          gcry_mpi_t s_prime,
                          struct ServiceSession * request,
                          struct ServiceSession * response)
{
  struct GNUNET_SCALARPRODUCT_service_response * msg;
  uint16_t msg_length = 0;
  unsigned char * current = NULL;
  unsigned char * element_exported = NULL;
  size_t element_length = 0;
  int i;

  msg_length = sizeof (struct GNUNET_SCALARPRODUCT_service_response)
          + 2 * request->used_element_count * PAILLIER_ELEMENT_LENGTH // kp, kq
          + 2 * PAILLIER_ELEMENT_LENGTH; // s, stick

  msg = GNUNET_malloc (msg_length);

  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_BOB_TO_ALICE);
  msg->header.size = htons (msg_length);
  msg->element_count = htons (request->element_count);
  msg->used_element_count = htons (request->used_element_count);
  memcpy (&msg->key, &request->key, sizeof (struct GNUNET_HashCode));
  current = (unsigned char *) &msg[1];

  // 4 times the same logics with slight variations.
  // doesn't really justify having 2 functions for that
  // so i put it into blocks to enhance readability 
  // convert s
  {
    element_exported = GNUNET_malloc (PAILLIER_ELEMENT_LENGTH);
    GNUNET_assert (0 == gcry_mpi_print (GCRYMPI_FMT_USG,
                                        element_exported, PAILLIER_ELEMENT_LENGTH,
                                        &element_length,
                                        s));
    adjust (element_exported, element_length, PAILLIER_ELEMENT_LENGTH);
    memcpy (current, element_exported, PAILLIER_ELEMENT_LENGTH);
    GNUNET_free (element_exported);
    current += PAILLIER_ELEMENT_LENGTH;
  }

  // convert stick
  {
    element_exported = GNUNET_malloc (PAILLIER_ELEMENT_LENGTH);
    GNUNET_assert (0 == gcry_mpi_print (GCRYMPI_FMT_USG,
                                        element_exported, PAILLIER_ELEMENT_LENGTH,
                                        &element_length,
                                        s_prime));
    adjust (element_exported, element_length, PAILLIER_ELEMENT_LENGTH);
    memcpy (current, element_exported, PAILLIER_ELEMENT_LENGTH);
    GNUNET_free (element_exported);
    current += PAILLIER_ELEMENT_LENGTH;
  }

  // convert kp[]
  for (i = 0; i < request->used_element_count; i++)
    {
      element_exported = GNUNET_malloc (PAILLIER_ELEMENT_LENGTH);
      GNUNET_assert (0 == gcry_mpi_print (GCRYMPI_FMT_USG,
                                          element_exported, PAILLIER_ELEMENT_LENGTH,
                                          &element_length,
                                          r[i]));
      adjust (element_exported, element_length, PAILLIER_ELEMENT_LENGTH);
      memcpy (current, element_exported, PAILLIER_ELEMENT_LENGTH);
      GNUNET_free (element_exported);
      current += PAILLIER_ELEMENT_LENGTH;
    }


  // convert kq[]
  for (i = 0; i < request->used_element_count; i++)
    {
      element_exported = GNUNET_malloc (PAILLIER_ELEMENT_LENGTH);
      GNUNET_assert (0 == gcry_mpi_print (GCRYMPI_FMT_USG,
                                          element_exported, PAILLIER_ELEMENT_LENGTH,
                                          &element_length,
                                          r_prime[i]));
      adjust (element_exported, element_length, PAILLIER_ELEMENT_LENGTH);
      memcpy (current, element_exported, PAILLIER_ELEMENT_LENGTH);
      GNUNET_free (element_exported);
      current += PAILLIER_ELEMENT_LENGTH;
    }

  if (GNUNET_SERVER_MAX_MESSAGE_SIZE >= msg_length)
    {
      struct MessageObject * msg_obj;

      msg_obj = GNUNET_new (struct MessageObject);
      msg_obj->msg = (struct GNUNET_MessageHeader *) msg;
      msg_obj->transmit_handle = (void *) &request->service_transmit_handle; //and reset the transmit handle
      request->service_transmit_handle =
              GNUNET_MESH_notify_transmit_ready (request->tunnel,
                                                 GNUNET_YES,
                                                 GNUNET_TIME_UNIT_FOREVER_REL,
                                                 &request->peer, //must be specified, we are a slave/participant/non-owner
                                                 msg_length,
                                                 &do_send_message,
                                                 msg_obj);
      // we don't care if it could be send or not. either way, the session is over for us.
      request->state = FINALIZED;
      response->state = FINALIZED;
    }
  else
    {
      // TODO FEATURE: fallback to fragmentation, in case the message is too long
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, _ ("Message too large, fragmentation is currently not supported!)\n"));
    }

  //disconnect our client
  if ( ! request->service_transmit_handle)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _ ("Could not send service-response message via mesh!)\n"));
      GNUNET_CONTAINER_DLL_remove (from_client_head, from_client_tail, response);
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                    &prepare_client_end_notification,
                                    response);
      return GNUNET_NO;
    }
  return GNUNET_OK;
}


/**
 * executed by bob: 
 * compute the values 
 *  (1)[]: $E_A(a_{\pi(i)}) \otimes E_A(- r_{\pi(i)} - b_{\pi(i)}) &= E_A(a_{\pi(i)} - r_{\pi(i)} - b_{\pi(i)})$
 *  (2)[]: $E_A(a_{\pi'(i)}) \otimes E_A(- r_{\pi'(i)}) &= E_A(a_{\pi'(i)} - r_{\pi'(i)})$
 *      S: $S := E_A(\sum (r_i + b_i)^2)$
 *     S': $S' := E_A(\sum r_i^2)$
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
  uint16_t count;
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

  count = request->used_element_count;

  b = GNUNET_malloc (sizeof (gcry_mpi_t) * count);
  a_pi = GNUNET_malloc (sizeof (gcry_mpi_t) * count);
  b_pi = GNUNET_malloc (sizeof (gcry_mpi_t) * count);
  a_pi_prime = GNUNET_malloc (sizeof (gcry_mpi_t) * count);
  rand_pi = GNUNET_malloc (sizeof (gcry_mpi_t) * count);
  rand_pi_prime = GNUNET_malloc (sizeof (gcry_mpi_t) * count);

  // convert responder session to from long to mpi
  for (i = 0, j = 0; i < response->element_count && j < count; i++)
    {
      if (request->mask[i / 8] & (1 << (i % 8)))
        {
          value = response->vector[i] >= 0 ? response->vector[i] : -response->vector[i];
          // long to gcry_mpi_t
          if (0 > response->vector[i])
            {
              b[j] = gcry_mpi_new (0);
              gcry_mpi_sub_ui (b[j], b[j], value);
            }
          else
            {
              b[j] = gcry_mpi_set_ui (NULL, value);
            }
          j++;
        }
    }
  GNUNET_free (response->vector);
  response->vector = NULL;

  tmp_exp = gcry_sexp_find_token (request->remote_pubkey, "n", 0);
  if ( ! tmp_exp)
    {
      GNUNET_break_op (0);
      gcry_sexp_release (request->remote_pubkey);
      request->remote_pubkey = NULL;
      goto except;
    }
  remote_n = gcry_sexp_nth_mpi (tmp_exp, 1, GCRYMPI_FMT_USG);
  if ( ! remote_n)
    {
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
  if ( ! tmp_exp)
    {
      GNUNET_break_op (0);
      gcry_mpi_release (remote_n);
      goto except;
    }
  remote_g = gcry_sexp_nth_mpi (tmp_exp, 1, GCRYMPI_FMT_USG);
  if ( ! remote_g)
    {
      GNUNET_break (0);
      gcry_mpi_release (remote_n);
      gcry_sexp_release (tmp_exp);
      goto except;
    }
  gcry_sexp_release (tmp_exp);

  // generate r, p and q
  rand = generate_random_vector (count);
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
  for (i = 0; i < count; i++)
    {
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
  for (i = 0; i < count; i++)
    {
      // E(S - r_qi)
      gcry_mpi_sub (r_prime[i], my_offset, rand_pi_prime[i]);
      encrypt_element (r_prime[i], r_prime[i], remote_g, remote_n, remote_nsquare);

      // E(S - r_qi) * E(S + a_qi) == E(2*S + a_qi - r_qi)
      gcry_mpi_mulm (r_prime[i], r_prime[i], a_pi_prime[i], remote_nsquare);
    }
  GNUNET_free (a_pi_prime);
  GNUNET_free (rand_pi_prime);

  // Calculate S' =  E(SUM( r_i^2 ))
  s_prime = compute_square_sum (rand, count);
  encrypt_element (s_prime, s_prime, remote_g, remote_n, remote_nsquare);

  // Calculate S = E(SUM( (r_i + b_i)^2 ))
  for (i = 0; i < count; i++)
    {
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

  // copy the Kp[], Kq[], S and Stick into a new message
  if (GNUNET_YES != prepare_service_response (r, r_prime, s, s_prime, request, response))
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Failed to communicate with `%s', scalar product calculation aborted.\n"),
		GNUNET_i2s (&request->peer));
  else
    ret = GNUNET_OK;

  for (i = 0; i < count; i++)
    {
      gcry_mpi_release (r_prime[i]);
      gcry_mpi_release (r[i]);
    }

  gcry_mpi_release (s);
  gcry_mpi_release (s_prime);

except:
  for (i = 0; i < count; i++)
    {
      gcry_mpi_release (b[i]);
      gcry_mpi_release (request->a[i]);
    }

  GNUNET_free (b);
  GNUNET_free (request->a);
  request->a = NULL;

  return ret;
}


/**
 * Executed by Alice, fills in a service-request message and sends it to the given peer
 * 
 * @param session the session associated with this request, then also holds the CORE-handle
 * @return #GNUNET_SYSERR if we could not send the message
 *         #GNUNET_NO if the message was too large
 *         #GNUNET_OK if we sent it
 */
static void
prepare_service_request (void *cls,
                         const struct GNUNET_PeerIdentity * peer,
                         const struct GNUNET_ATS_Information * atsi)
{
  struct ServiceSession * session = cls;
  unsigned char * current;
  struct GNUNET_SCALARPRODUCT_service_request * msg;
  struct MessageObject * msg_obj;
  unsigned int i;
  unsigned int j;
  uint16_t msg_length;
  size_t element_length = 0; //gets initialized by gcry_mpi_print, but the compiler doesn't know that
  gcry_mpi_t a;
  uint32_t value;

  GNUNET_assert (NULL != cls);
  GNUNET_assert (NULL != peer);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _ ("Successfully created new tunnel to peer (%s)!\n"), GNUNET_i2s (peer));

  msg_length = sizeof (struct GNUNET_SCALARPRODUCT_service_request)
          + session->used_element_count * PAILLIER_ELEMENT_LENGTH
          + session->mask_length
          + my_pubkey_external_length;

  if (GNUNET_SERVER_MAX_MESSAGE_SIZE < sizeof (struct GNUNET_SCALARPRODUCT_service_request)
      + session->used_element_count * PAILLIER_ELEMENT_LENGTH
      + session->mask_length
      + my_pubkey_external_length)
    {
      // TODO FEATURE: fallback to fragmentation, in case the message is too long
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, _ ("Message too large, fragmentation is currently not supported!\n"));
      GNUNET_CONTAINER_DLL_remove (from_client_head, from_client_tail, session);
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                    &prepare_client_end_notification,
                                    session);
      return;
    }
  msg = GNUNET_malloc (msg_length);

  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ALICE_TO_BOB);
  memcpy (&msg->key, &session->key, sizeof (struct GNUNET_HashCode));
  msg->mask_length = htons (session->mask_length);
  msg->pk_length = htons (my_pubkey_external_length);
  msg->used_element_count = htons (session->used_element_count);
  msg->element_count = htons (session->element_count);
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
  session->a = GNUNET_malloc (sizeof (gcry_mpi_t) * session->used_element_count);
  a = gcry_mpi_new (KEYBITS * 2);
  // encrypt our vector and generate string representations
  for (i = 0, j = 0; i < session->element_count; i++)
    {
      // if this is a used element...
      if (session->mask[i / 8] & 1 << (i % 8))
        {
          unsigned char * element_exported = GNUNET_malloc (PAILLIER_ELEMENT_LENGTH);
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
          GNUNET_assert ( ! gcry_mpi_print (GCRYMPI_FMT_USG,
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

  msg_obj = GNUNET_new (struct MessageObject);
  msg_obj->msg = (struct GNUNET_MessageHeader *) msg;
  msg_obj->transmit_handle = (void *) &session->service_transmit_handle; //and reset the transmit handle
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Transmitting service request.\n"));

  //transmit via mesh messaging
  session->state = WAITING_FOR_RESPONSE_FROM_SERVICE;
  session->service_transmit_handle = GNUNET_MESH_notify_transmit_ready (session->tunnel, GNUNET_YES,
                                                                        GNUNET_TIME_UNIT_FOREVER_REL,
                                                                        peer, //multicast to all targets, maybe useful in the future
                                                                        msg_length,
                                                                        &do_send_message,
                                                                        msg_obj);
  if ( ! session->service_transmit_handle)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Could not send mutlicast message to tunnel!\n"));
      GNUNET_free (msg_obj);
      GNUNET_free (msg);
      GNUNET_CONTAINER_DLL_remove (from_client_head, from_client_tail, session);
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                    &prepare_client_end_notification,
                                    session);
    }
}


/**
 * Method called whenever a peer has disconnected from the tunnel.
 * Implementations of this callback must NOT call
 * #GNUNET_MESH_tunnel_destroy immediately, but instead schedule those
 * to run in some other task later.  However, calling 
 * #GNUNET_MESH_notify_transmit_ready_cancel is allowed.
 *
 * @param cls closure
 * @param peer peer identity the tunnel stopped working with
 */
static void
tunnel_peer_disconnect_handler (void *cls, const struct GNUNET_PeerIdentity * peer)
{
  // as we have only one peer connected in each session, just remove the session and say good bye
  struct ServiceSession * session = cls;
  struct ServiceSession * curr;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Peer (%s) disconnected from our tunnel!\n",
	      GNUNET_i2s (peer));

  if ((session->role == ALICE) && (FINALIZED != session->state) && ( ! do_shutdown))
    {
      for (curr = from_client_head; NULL != curr; curr = curr->next)
        if (curr == session)
          {
            GNUNET_CONTAINER_DLL_remove (from_client_head, from_client_tail, session);
            break;
          }
      // FIXME: dangling tasks, code duplication, use-after-free, fun...
      GNUNET_SCHEDULER_add_now (&destroy_tunnel,
                                session);
      // if this happened before we received the answer, we must terminate the session
      GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
				session);
    }
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
  uint16_t element_count;
  uint16_t mask_length;
  uint16_t msg_type;
  int32_t * vector;
  uint32_t i;

  GNUNET_assert (message);

  //we need at least a peer and one message id to compare
  if (sizeof (struct GNUNET_SCALARPRODUCT_client_request) > ntohs (msg->header.size))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _ ("Too short message received from client!\n"));
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }

  msg_type = ntohs (msg->header.type);
  element_count = ntohs (msg->element_count);
  mask_length = ntohs (msg->mask_length);

  //sanity check: is the message as long as the message_count fields suggests?
  if (( ntohs (msg->header.size) != (sizeof (struct GNUNET_SCALARPRODUCT_client_request) + element_count * sizeof (int32_t) + mask_length))
      || (0 == element_count))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _ ("Invalid message received from client, session information incorrect!\n"));
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }

  // do we have a duplicate session here already?
  if (NULL != find_matching_session (from_client_tail,
                                     &msg->key,
                                     element_count,
                                     NULL, NULL))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, _ ("Duplicate session information received, cannot create new session with key `%s'\n"), GNUNET_h2s (&msg->key));
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }

  session = GNUNET_new (struct ServiceSession);
  session->client = client;
  session->element_count = element_count;
  session->mask_length = mask_length;
  // get our transaction key
  memcpy (&session->key, &msg->key, sizeof (struct GNUNET_HashCode));
  //allocate memory for vector and encrypted vector
  session->vector = GNUNET_malloc (sizeof (int32_t) * element_count);
  vector = (int32_t *) & msg[1];

  if (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_TO_ALICE == msg_type)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _ ("Got client-request-session with key %s, preparing tunnel to remote service.\n"), GNUNET_h2s (&session->key));

      session->role = ALICE;
      // fill in the mask
      session->mask = GNUNET_malloc (mask_length);
      memcpy (session->mask, &vector[element_count], mask_length);

      // copy over the elements
      session->used_element_count = 0;
      for (i = 0; i < element_count; i++)
        {
          session->vector[i] = ntohl (vector[i]);
          if (session->vector[i] == 0)
            session->mask[i / 8] &= ~(1 << (i % 8));
          if (session->mask[i / 8] & (1 << (i % 8)))
            session->used_element_count++;
        }

      if ( ! session->used_element_count)
        {
          GNUNET_break_op (0);
          GNUNET_free (session->vector);
          GNUNET_free (session->a);
          GNUNET_free (session);
          GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
          return;
        }
      //session with ourself makes no sense!
      if ( ! memcmp (&msg->peer, &me, sizeof (struct GNUNET_PeerIdentity)))
        {
          GNUNET_break (0);
          GNUNET_free (session->vector);
          GNUNET_free (session->a);
          GNUNET_free (session);
          GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
          return;
        }
      // get our peer ID
      memcpy (&session->peer, &msg->peer, sizeof (struct GNUNET_PeerIdentity));
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, _ ("Creating new tunnel to for session with key %s.\n"), GNUNET_h2s (&session->key));
      GNUNET_CONTAINER_DLL_insert (from_client_head, from_client_tail, session);
      session->tunnel = GNUNET_MESH_tunnel_create (my_mesh, session,
                                                   prepare_service_request,
                                                   tunnel_peer_disconnect_handler,
                                                   session);
      if ( ! session->tunnel)
        {
          GNUNET_break (0);
          GNUNET_free (session->vector);
          GNUNET_free (session->a);
          GNUNET_free (session);
          GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
          return;
        }
      GNUNET_MESH_peer_request_connect_add (session->tunnel, &session->peer);
      GNUNET_SERVER_receive_done (client, GNUNET_YES);
      session->state = WAITING_FOR_BOBS_CONNECT;
    }
  else
    {
      struct ServiceSession * requesting_session;
      enum SessionState needed_state = REQUEST_FROM_SERVICE_RECEIVED;

      session->role = BOB;
      session->mask = NULL;
      // copy over the elements
      session->used_element_count = element_count;
      for (i = 0; i < element_count; i++)
        session->vector[i] = ntohl (vector[i]);
      session->state = MESSAGE_FROM_RESPONDING_CLIENT_RECEIVED;
      
      GNUNET_CONTAINER_DLL_insert (from_client_head, from_client_tail, session);
      GNUNET_SERVER_receive_done (client, GNUNET_YES);
      //check if service queue contains a matching request 
      requesting_session = find_matching_session (from_service_tail,
                                                  &session->key,
                                                  session->element_count,
                                                  &needed_state, NULL);
      if (NULL != requesting_session)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_INFO, _ ("Got client-responder-session with key %s and a matching service-request-session set, processing.\n"), GNUNET_h2s (&session->key));
          if (GNUNET_OK != compute_service_response (requesting_session, session))
            {
              GNUNET_CONTAINER_DLL_remove (from_client_head, from_client_tail, session);
              GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                            &prepare_client_end_notification,
                                            session);
            }
        }
      else
        GNUNET_log (GNUNET_ERROR_TYPE_INFO, _ ("Got client-responder-session with key %s but NO matching service-request-session set, queuing element for later use.\n"), GNUNET_h2s (&session->key));
        // no matching session exists yet, store the response
        // for later processing by handle_service_request()
    }
}


/**
 * Function called for inbound tunnels. 
 *
 * @param cls closure
 * @param tunnel new handle to the tunnel
 * @param initiator peer that started the tunnel
 * @param atsi performance information for the tunnel
 * @return initial tunnel context for the tunnel
 *         (can be NULL -- that's not an error)
 */
static void *
tunnel_incoming_handler (void *cls, struct GNUNET_MESH_Tunnel *tunnel,
                         const struct GNUNET_PeerIdentity *initiator,
                         const struct GNUNET_ATS_Information *atsi)
{

  struct ServiceSession * c = GNUNET_new (struct ServiceSession);

  memcpy (&c->peer, initiator, sizeof (struct GNUNET_PeerIdentity));
  c->tunnel = tunnel;
  c->role = BOB;
  return c;
}


/**
 * Function called whenever an inbound tunnel is destroyed.  Should clean up
 * any associated state.
 *
 * @param cls closure (set from #GNUNET_MESH_connect)
 * @param tunnel connection to the other end (henceforth invalid)
 * @param tunnel_ctx place where local state associated
 *                   with the tunnel is stored (our 'struct TunnelState')
 */
static void
tunnel_destruction_handler (void *cls,
                            const struct GNUNET_MESH_Tunnel *tunnel,
                            void *tunnel_ctx)
{
  struct ServiceSession * service_session = tunnel_ctx;
  struct ServiceSession * client_session;
  struct ServiceSession * curr;

  GNUNET_assert (service_session);
  if (!memcmp (&service_session->peer, &me, sizeof (struct GNUNET_PeerIdentity)))
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _ ("Tunnel destroyed, terminating session with peer (%s)\n"), GNUNET_i2s (&service_session->peer));
  // remove the session, unless it has already been dequeued, but somehow still active
  // this could bug without the IF in case the queue is empty and the service session was the only one know to the service
  for (curr = from_service_head; NULL != curr; curr = curr->next)
        if (curr == service_session)
          {
            GNUNET_CONTAINER_DLL_remove (from_service_head, from_service_tail, curr);
            break;
          }
  // there is a client waiting for this service session, terminate it, too!
  // i assume the tupel of key and element count is unique. if it was not the rest of the code would not work either.
  client_session = find_matching_session (from_client_tail,
                                          &service_session->key,
                                          service_session->element_count,
                                          NULL, NULL);
  free_session (service_session);

  // the client has to check if it was waiting for a result 
  // or if it was a responder, no point in adding more statefulness
  if (client_session && ( ! do_shutdown))
    {
      // remove the session, we just found it in the queue, so it must be there
      GNUNET_CONTAINER_DLL_remove (from_client_head, from_client_tail, client_session);
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                    &prepare_client_end_notification,
                                    client_session);
    }
}


/**
 * Compute our scalar product, done by Alice
 * 
 * @param session - the session associated with this computation
 * @param kp - (1) from the protocol definition: 
 *             $E_A(a_{\pi(i)}) \otimes E_A(- r_{\pi(i)} - b_{\pi(i)}) &= E_A(a_{\pi(i)} - r_{\pi(i)} - b_{\pi(i)})$
 * @param kq - (2) from the protocol definition: 
 *             $E_A(a_{\pi'(i)}) \otimes E_A(- r_{\pi'(i)}) &= E_A(a_{\pi'(i)} - r_{\pi'(i)})$
 * @param s - S from the protocol definition: 
 *            $S := E_A(\sum (r_i + b_i)^2)$
 * @param stick - S' from the protocol definition: 
 *                $S' := E_A(\sum r_i^2)$
 * @return product as MPI, never NULL
 */
static gcry_mpi_t
compute_scalar_product (struct ServiceSession * session,
                        gcry_mpi_t * r, gcry_mpi_t * r_prime, gcry_mpi_t s, gcry_mpi_t s_prime)
{
  uint16_t count;
  gcry_mpi_t t;
  gcry_mpi_t u;
  gcry_mpi_t utick;
  gcry_mpi_t p;
  gcry_mpi_t ptick;
  gcry_mpi_t tmp;
  unsigned int i;

  count = session->used_element_count;
  tmp = gcry_mpi_new (KEYBITS);
  // due to the introduced static offset S, we now also have to remove this
  // from the E(a_pi)(+)E(-b_pi-r_pi) and E(a_qi)(+)E(-r_qi) twice each,
  // the result is E((S + a_pi) + (S -b_pi-r_pi)) and E(S + a_qi + S - r_qi)
  for (i = 0; i < count; i++)
    {
      decrypt_element (r[i], r[i], my_mu, my_lambda, my_n, my_nsquare);
      gcry_mpi_sub(r[i],r[i],my_offset);
      gcry_mpi_sub(r[i],r[i],my_offset);
      decrypt_element (r_prime[i], r_prime[i], my_mu, my_lambda, my_n, my_nsquare);
      gcry_mpi_sub(r_prime[i],r_prime[i],my_offset);
      gcry_mpi_sub(r_prime[i],r_prime[i],my_offset);
    }

  // calculate t = sum(ai)
  t = compute_square_sum (session->a, count);

  // calculate U
  u = gcry_mpi_new (0);
  tmp = compute_square_sum (r, count);
  gcry_mpi_sub (u, u, tmp);
  gcry_mpi_release (tmp);

  //calculate U'
  utick = gcry_mpi_new (0);
  tmp = compute_square_sum (r_prime, count);
  gcry_mpi_sub (utick, utick, tmp);

  GNUNET_assert (p = gcry_mpi_new (0));
  GNUNET_assert (ptick = gcry_mpi_new (0));

  // compute P
  decrypt_element (s, s, my_mu, my_lambda, my_n, my_nsquare);
  decrypt_element (s_prime, s_prime, my_mu, my_lambda, my_n, my_nsquare);
  
  // compute P
  gcry_mpi_add (p, s, t);
  gcry_mpi_add (p, p, u);

  // compute P'
  gcry_mpi_add (ptick, s_prime, t);
  gcry_mpi_add (ptick, ptick, utick);

  gcry_mpi_release (t);
  gcry_mpi_release (u);
  gcry_mpi_release (utick);

  // compute product
  gcry_mpi_sub (p, p, ptick);
  gcry_mpi_release (ptick);
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
 * prepare the response we will send to alice or bobs' clients.
 * in Bobs case the product will be NULL. 
 * 
 * @param session  the session associated with our client.
 */
static void
prepare_client_response (void *cls,
                         const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ServiceSession * session = cls;
  struct GNUNET_SCALARPRODUCT_client_response * msg;
  unsigned char * product_exported = NULL;
  size_t product_length = 0;
  uint16_t msg_length = 0;
  struct MessageObject * msg_obj;
  int8_t range = 0;
  int sign;

  if (session->product)
    {
      gcry_mpi_t value = gcry_mpi_new(0);
      
      sign = gcry_mpi_cmp_ui(session->product, 0);
      // libgcrypt can not handle a print of a negative number
      if (0 > sign){
          range = -1;
          gcry_mpi_sub(value, value, session->product);
      }
      else if(0 < sign){
          range = 1;
          gcry_mpi_add(value, value, session->product);
      }
      
      // get representation as string
      // unfortunately libgcrypt is too stupid to implement print-support in
      // signed GCRYMPI_FMT_STD format, and simply asserts in that case.
      // here is the associated sourcecode:
      // if (a->sign) return gcry_error (GPG_ERR_INTERNAL); /* Can't handle it yet. */
      if (range)
          GNUNET_assert ( ! gcry_mpi_aprint (GCRYMPI_FMT_USG, // FIXME: just log (& survive!)
                                             &product_exported,
                                             &product_length,
                                             session->product));
      
      gcry_mpi_release (session->product);
      session->product = NULL;
    }

  msg_length = sizeof (struct GNUNET_SCALARPRODUCT_client_response) + product_length;
  msg = GNUNET_malloc (msg_length);
  memcpy (&msg[1], product_exported, product_length);
  GNUNET_free_non_null (product_exported);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_SERVICE_TO_CLIENT);
  msg->header.size = htons (msg_length);
  msg->range = range;
  memcpy (&msg->key, &session->key, sizeof (struct GNUNET_HashCode));
  memcpy (&msg->peer, &session->peer, sizeof ( struct GNUNET_PeerIdentity));
  msg->product_length = htonl (product_length);
  
  msg_obj = GNUNET_new (struct MessageObject);
  msg_obj->msg = (struct GNUNET_MessageHeader *) msg;
  msg_obj->transmit_handle = NULL; // don't reset the transmit handle

  //transmit this message to our client
  session->client_transmit_handle =  // FIXME: use after free possibility during shutdown
          GNUNET_SERVER_notify_transmit_ready (session->client,
                                               msg_length,
                                               GNUNET_TIME_UNIT_FOREVER_REL,
                                               &do_send_message,
                                               msg_obj);
  if ( ! session->client_transmit_handle)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, _ ("Could not send message to client (%p)! This probably is OK if the client disconnected before us.\n"), session->client);
      session->client = NULL;
      // callback was not called!
      GNUNET_free (msg_obj);
      GNUNET_free (msg);
    }
  else
      // gracefully sent message, just terminate session structure
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, _ ("Sent result to client (%p), this session (%s) has ended!\n"), session->client, GNUNET_h2s (&session->key));
  free_session (session);
}


/**
 * Handle a request from another service to calculate a scalarproduct with us.
 *
 * @param cls closure (set from #GNUNET_MESH_connect)
 * @param tunnel connection to the other end
 * @param tunnel_ctx place to store local state associated with the tunnel
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_service_request (void *cls,
                        struct GNUNET_MESH_Tunnel * tunnel,
                        void **tunnel_ctx,
                        const struct GNUNET_PeerIdentity * sender,
                        const struct GNUNET_MessageHeader * message,
                        const struct GNUNET_ATS_Information * atsi)
{
  struct ServiceSession * session;
  const struct GNUNET_SCALARPRODUCT_service_request * msg = (const struct GNUNET_SCALARPRODUCT_service_request *) message;
  uint16_t mask_length;
  uint16_t pk_length;
  uint16_t used_elements;
  uint16_t element_count;
  uint16_t msg_length;
  unsigned char * current;
  struct ServiceSession * responder_session;
  int32_t i = -1;
  enum SessionState needed_state;

  session = (struct ServiceSession *) * tunnel_ctx;
  // is this tunnel already in use?
  if ( (session->next) || (from_service_head == session))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, _ ("Got a service request over a tunnel that is already in use, ignoring!\n"));
      return GNUNET_SYSERR;
    }
  // Check if message was sent by me, which would be bad!
  if ( ! memcmp (sender, &me, sizeof (struct GNUNET_PeerIdentity)))
    {
      GNUNET_break (0);
      GNUNET_free (session);
      return GNUNET_SYSERR;
    }
  // this protocol can at best be 1:N, but never M:N!
  // Check if the sender is not the peer, I am connected to, which would be bad!
  if (memcmp (sender, &session->peer, sizeof (struct GNUNET_PeerIdentity)))
    {
      GNUNET_break (0);
      GNUNET_free (session);
      return GNUNET_SYSERR;
    }

  //we need at least a peer and one message id to compare
  if (ntohs (msg->header.size) < sizeof (struct GNUNET_SCALARPRODUCT_service_request))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, _ ("Too short message received from peer!\n"));
      GNUNET_free (session);
      return GNUNET_SYSERR;
    }
  mask_length = ntohs (msg->mask_length);
  pk_length = ntohs (msg->pk_length);
  used_elements = ntohs (msg->used_element_count);
  element_count = ntohs (msg->element_count);
  msg_length = sizeof (struct GNUNET_SCALARPRODUCT_service_request)
               + mask_length + pk_length + used_elements * PAILLIER_ELEMENT_LENGTH;

  //sanity check: is the message as long as the message_count fields suggests?
  if ((ntohs (msg->header.size) != msg_length) || (element_count < used_elements)
      || (used_elements == 0) || (mask_length != (element_count / 8 + (element_count % 8 ? 1 : 0)))
      )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, _ ("Invalid message received from peer, message count does not match message length!\n"));
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, _ ("Used elements: %hu\nElement Count: %hu\nExpected Mask Length: %hu\nCalculated Masklength: %d\n"), used_elements, element_count, mask_length, (element_count / 8 + (element_count % 8 ? 1 : 0)));
      GNUNET_free (session);
      return GNUNET_SYSERR;
    }
  if (find_matching_session (from_service_tail,
                             &msg->key,
                             element_count,
                             NULL,
                             sender))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _ ("Got message with duplicate session key (`%s'), ignoring service request.\n"), (const char *) &(msg->key));
      GNUNET_free (session);
      return GNUNET_SYSERR;
    }
  
  memcpy (&session->peer, sender, sizeof (struct GNUNET_PeerIdentity));
  session->state = REQUEST_FROM_SERVICE_RECEIVED;
  session->element_count = ntohs (msg->element_count);
  session->used_element_count = used_elements;
  session->tunnel = tunnel;

  // session key
  memcpy (&session->key, &msg->key, sizeof (struct GNUNET_HashCode));
  current = (unsigned char *) &msg[1];
  //preserve the mask, we will need that later on
  session->mask = GNUNET_malloc (mask_length);
  memcpy (session->mask, current, mask_length);
  //the public key
  current += mask_length;

  //convert the publickey to sexp
  if (gcry_sexp_new (&session->remote_pubkey, current, pk_length, 1))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, _ ("Could not translate remote public key to sexpression!\n"));
      GNUNET_free (session->mask);
      GNUNET_free (session);
      return GNUNET_SYSERR;
    }

  current += pk_length;

  //check if service queue contains a matching request 
  needed_state = MESSAGE_FROM_RESPONDING_CLIENT_RECEIVED;
  responder_session = find_matching_session (from_client_tail,
                                             &session->key,
                                             session->element_count,
                                             &needed_state, NULL);

  session->a = GNUNET_malloc (sizeof (gcry_mpi_t) * used_elements);

  if (GNUNET_SERVER_MAX_MESSAGE_SIZE >= sizeof (struct GNUNET_SCALARPRODUCT_service_request)
      +pk_length
      + mask_length
      + used_elements * PAILLIER_ELEMENT_LENGTH)
    {
      gcry_error_t ret = 0;
      session->a = GNUNET_malloc (sizeof (gcry_mpi_t) * used_elements);
      // Convert each vector element to MPI_value
      for (i = 0; i < used_elements; i++)
        {
          size_t read = 0;

          ret = gcry_mpi_scan (&session->a[i],
                               GCRYMPI_FMT_USG,
                               &current[i * PAILLIER_ELEMENT_LENGTH],
                               PAILLIER_ELEMENT_LENGTH,
                               &read);
          if (ret)
            {
              GNUNET_log (GNUNET_ERROR_TYPE_WARNING, _ ("Could not translate E[a%d] to MPI!\n%s/%s\n"),
                          i, gcry_strsource (ret), gcry_strerror (ret));
              goto except;
            }
        }
      GNUNET_CONTAINER_DLL_insert (from_service_head, from_service_tail, session);
      if (responder_session)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_INFO, _ ("Got session with key %s and a matching element set, processing.\n"), GNUNET_h2s (&session->key));
          if (GNUNET_OK != compute_service_response (session, responder_session))
            {
              //something went wrong, remove it again...
              GNUNET_CONTAINER_DLL_remove (from_service_head, from_service_tail, session);
              goto except;
            }
        }
      else
          GNUNET_log (GNUNET_ERROR_TYPE_INFO, _ ("Got session with key %s without a matching element set, queueing.\n"), GNUNET_h2s (&session->key));
      return GNUNET_OK;
    }
  else
    {
      // TODO FEATURE: fallback to fragmentation, in case the message is too long
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, _ ("Message too large, fragmentation is currently not supported!\n"));
      goto except;
    }
except:
  for (i = 0; i < used_elements; i++)
    if (session->a[i])
      gcry_mpi_release (session->a[i]);
  gcry_sexp_release (session->remote_pubkey);
  session->remote_pubkey = NULL;
  GNUNET_free_non_null (session->a);
  session->a = NULL;
  free_session (session);
  // and notify our client-session that we could not complete the session
  if (responder_session)
    {
      // we just found the responder session in this queue
      GNUNET_CONTAINER_DLL_remove (from_client_head, from_client_tail, responder_session);
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                    &prepare_client_end_notification,
                                    responder_session);
    }
  return GNUNET_SYSERR;
}


/**
 * Handle a response we got from another service we wanted to calculate a scalarproduct with.
 *
 * @param cls closure (set from #GNUNET_MESH_connect)
 * @param tunnel connection to the other end
 * @param tunnel_ctx place to store local state associated with the tunnel
 * @param sender who sent the message
 * @param message the actual message
 * @param atsi performance data for the connection
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_service_response (void *cls,
                         struct GNUNET_MESH_Tunnel * tunnel,
                         void **tunnel_ctx,
                         const struct GNUNET_PeerIdentity * sender,
                         const struct GNUNET_MessageHeader * message,
                         const struct GNUNET_ATS_Information * atsi)
{

  struct ServiceSession * session;
  struct GNUNET_SCALARPRODUCT_service_response * msg = (struct GNUNET_SCALARPRODUCT_service_response *) message;
  unsigned char * current;
  uint16_t count;
  gcry_mpi_t s = NULL;
  gcry_mpi_t s_prime = NULL;
  size_t read;
  size_t i;
  uint16_t used_element_count;
  size_t msg_size;
  gcry_mpi_t * r = NULL;
  gcry_mpi_t * r_prime = NULL;
  int rc;

  GNUNET_assert (NULL != message);
  GNUNET_assert (NULL != sender);
  GNUNET_assert (NULL != tunnel_ctx);
  session = (struct ServiceSession *) * tunnel_ctx;
  GNUNET_assert (NULL != session);
  count = session->used_element_count;
  session->product = NULL;

  if (memcmp (&session->peer, sender, sizeof (struct GNUNET_PeerIdentity)))
    {
      GNUNET_break_op (0);
      goto invalid_msg;
    }
  //we need at least a peer and one message id to compare
  if (sizeof (struct GNUNET_SCALARPRODUCT_service_response) > ntohs (msg->header.size))
    {
      GNUNET_break_op (0);
      goto invalid_msg;
    }
  used_element_count = ntohs (msg->used_element_count);
  msg_size = sizeof (struct GNUNET_SCALARPRODUCT_service_response)
          + 2 * used_element_count * PAILLIER_ELEMENT_LENGTH
          + 2 * PAILLIER_ELEMENT_LENGTH;
  //sanity check: is the message as long as the message_count fields suggests?
  if ((ntohs (msg->header.size) != msg_size) || (count != used_element_count))
    {
      GNUNET_break_op (0);
      goto invalid_msg;
    }

  //convert s
  current = (unsigned char *) &msg[1];
  if (0 != (rc = gcry_mpi_scan (&s, GCRYMPI_FMT_USG, current, 
                     PAILLIER_ELEMENT_LENGTH, &read)))
    {
      LOG_GCRY (GNUNET_ERROR_TYPE_DEBUG, "gcry_mpi_scan", rc);
      GNUNET_break_op (0);
      goto invalid_msg;
    }
  current += PAILLIER_ELEMENT_LENGTH;
  //convert stick
  if (0 != (rc = gcry_mpi_scan (&s_prime, GCRYMPI_FMT_USG, current,
                       PAILLIER_ELEMENT_LENGTH, &read)))
    {
      LOG_GCRY (GNUNET_ERROR_TYPE_DEBUG, "gcry_mpi_scan", rc);
      GNUNET_break_op (0);
      goto invalid_msg;
    }
  current += PAILLIER_ELEMENT_LENGTH;

  r = GNUNET_malloc (sizeof (gcry_mpi_t) * count);
  // Convert each kp[] to its MPI_value
  for (i = 0; i < count; i++)
    {
      if (0 != (rc = gcry_mpi_scan (&r[i], GCRYMPI_FMT_USG, current,
                           PAILLIER_ELEMENT_LENGTH, &read)))
        {
          LOG_GCRY (GNUNET_ERROR_TYPE_DEBUG, "gcry_mpi_scan", rc);
      GNUNET_break_op (0);
          goto invalid_msg;
        }
      current += PAILLIER_ELEMENT_LENGTH;
    }


  r_prime = GNUNET_malloc (sizeof (gcry_mpi_t) * count);
  // Convert each kq[] to its MPI_value
  for (i = 0; i < count; i++)
    {
      if (0 != (rc = gcry_mpi_scan (&r_prime[i], GCRYMPI_FMT_USG, current,
                           PAILLIER_ELEMENT_LENGTH, &read)))
        {
          LOG_GCRY (GNUNET_ERROR_TYPE_DEBUG, "gcry_mpi_scan", rc);
      GNUNET_break_op (0);
          goto invalid_msg;
        }
      current += PAILLIER_ELEMENT_LENGTH;
    }
  
  session->product = compute_scalar_product (session, r, r_prime, s, s_prime);
  
invalid_msg:
  if (s)
    gcry_mpi_release (s);
  if (s_prime)
    gcry_mpi_release (s_prime);
  for (i = 0; r && i < count; i++)
    if (r[i]) gcry_mpi_release (r[i]);
  for (i = 0; r_prime && i < count; i++)
    if (r_prime[i]) gcry_mpi_release (r_prime[i]);
  GNUNET_free_non_null (r);
  GNUNET_free_non_null (r_prime);
  
  session->state = FINALIZED;
  // the tunnel has done its job, terminate our connection and the tunnel
  // the peer will be notified that the tunnel was destroyed via tunnel_destruction_handler
  GNUNET_CONTAINER_DLL_remove (from_client_head, from_client_tail, session);
  GNUNET_SCHEDULER_add_now (&destroy_tunnel, session); // FIXME: use after free!
  // send message with product to client
  /* session->current_task = */ GNUNET_SCHEDULER_add_now (&prepare_client_response, session); // FIXME: dangling task!
  return GNUNET_OK;
  // if success: terminate the session gracefully, else terminate with error
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
  struct ServiceSession * curr;
  struct ServiceSession * next;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _ ("Shutting down, initiating cleanup.\n"));

  do_shutdown = GNUNET_YES;
  // terminate all owned open tunnels.
  for (curr = from_client_head; NULL != curr; curr = next)
    {
      next = curr->next;
      if (FINALIZED != curr->state)
        {
          destroy_tunnel (curr, NULL);
          curr->state = FINALIZED;
        }
    }
  if (my_mesh)
    {
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
    { &handle_service_response, GNUNET_MESSAGE_TYPE_SCALARPRODUCT_BOB_TO_ALICE, 0},
    {NULL, 0, 0}
  };
  static GNUNET_MESH_ApplicationType mesh_types[] = {
    GNUNET_APPLICATION_TYPE_SCALARPRODUCT,
    GNUNET_APPLICATION_TYPE_END
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
		GNUNET_CRYPTO_get_host_identity (c,
						 &me));
  my_mesh = GNUNET_MESH_connect (c, NULL,
                                 &tunnel_incoming_handler,
                                 &tunnel_destruction_handler,
                                 mesh_handlers, mesh_types);
  if (!my_mesh)
    {
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

/* end of gnunet-service-ext.c */
