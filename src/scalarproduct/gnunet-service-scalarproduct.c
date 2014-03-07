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
#include "platform.h"
#include <limits.h>
#include <gcrypt.h>
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
  struct GNUNET_CRYPTO_PaillierPublicKey * remote_pubkey;

  /**
   * ai(Alice) after applying the mask
   */
  gcry_mpi_t * a;

  /**
   * E(ai)(Bob) after applying the mask
   */
  struct GNUNET_CRYPTO_PaillierCiphertext * e_a;

  /**
   * Bob's permutation p of R
   */
  struct GNUNET_CRYPTO_PaillierCiphertext * r;

  /**
   * Bob's permutation q of R
   */
  struct GNUNET_CRYPTO_PaillierCiphertext * r_prime;

  /**
   * Bob's s
   */
  struct GNUNET_CRYPTO_PaillierCiphertext * s;

  /**
   * Bob's s'
   */
  struct GNUNET_CRYPTO_PaillierCiphertext * s_prime;

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
 * Service's own public key
 */
static struct GNUNET_CRYPTO_PaillierPublicKey my_pubkey;

/**
 * Service's own private key
 */
static struct GNUNET_CRYPTO_PaillierPrivateKey my_privkey;

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
  if (session->e_a) {
    GNUNET_free (session->e_a);
    session->e_a = NULL;
  }
  if (session->mask) {
    GNUNET_free (session->mask);
    session->mask = NULL;
  }
  if (session->r) {
    GNUNET_free (session->r);
    session->r = NULL;
  }
  if (session->r_prime) {
    GNUNET_free (session->r_prime);
    session->r_prime = NULL;
  }
  if (session->s) {
    GNUNET_free (session->s);
    session->s = NULL;
  }
  if (session->s_prime) {
    GNUNET_free (session->s_prime);
    session->s_prime = NULL;
  }
  if (session->product) {
    gcry_mpi_release (session->product);
    session->product = NULL;
  }
  if (session->remote_pubkey) {
    GNUNET_free (session->remote_pubkey);
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
  msg->key = session->key;
  msg->peer = session->peer;
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
  struct GNUNET_CRYPTO_PaillierCiphertext * payload;
  struct GNUNET_SCALARPRODUCT_multipart_message * msg;
  unsigned int i;
  unsigned int j;
  uint32_t msg_length;
  uint32_t todo_count;

  msg_length = sizeof (struct GNUNET_SCALARPRODUCT_multipart_message);
  todo_count = session->used - session->transferred;

  if (todo_count > MULTIPART_ELEMENT_CAPACITY / 2)
    // send the currently possible maximum chunk, we always transfer both permutations
    todo_count = MULTIPART_ELEMENT_CAPACITY / 2;

  msg_length += todo_count * sizeof (struct GNUNET_CRYPTO_PaillierCiphertext) * 2;
  msg = GNUNET_malloc (msg_length);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ALICE_TO_BOB_MULTIPART);
  msg->header.size = htons (msg_length);
  msg->multipart_element_count = htonl (todo_count);

  payload = (struct GNUNET_CRYPTO_PaillierCiphertext *) &msg[1];
  for (i = session->transferred, j=0; i < session->transferred + todo_count; i++) {
    //r[i][p] and r[i][q]
    memcpy (&payload[j++], &session->r[i], sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
    memcpy (&payload[j++], &session->r_prime[i], sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
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
  else {
    // final part
    session->state = FINALIZED;
    GNUNET_free (session->r_prime);
    GNUNET_free (session->r);
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
 * @param session  the associated requesting session with alice
 * @return #GNUNET_NO if we could not send our message
 *         #GNUNET_OK if the operation succeeded
 */
static int
prepare_service_response (struct ServiceSession * session)
{
  struct GNUNET_SCALARPRODUCT_service_response * msg;
  uint32_t msg_length = 0;
  struct GNUNET_CRYPTO_PaillierCiphertext * payload;
  int i;

  msg_length = sizeof (struct GNUNET_SCALARPRODUCT_service_response)
          + 2 * sizeof (struct GNUNET_CRYPTO_PaillierCiphertext); // s, stick

  if (GNUNET_SERVER_MAX_MESSAGE_SIZE >
      msg_length + 2 * session->used * sizeof (struct GNUNET_CRYPTO_PaillierCiphertext)) { //r, r'
    msg_length += 2 * session->used * sizeof (struct GNUNET_CRYPTO_PaillierCiphertext);
    session->transferred = session->used;
  }
  else
    session->transferred = (GNUNET_SERVER_MAX_MESSAGE_SIZE - 1 - msg_length) /
    (sizeof (struct GNUNET_CRYPTO_PaillierCiphertext) * 2);

  msg = GNUNET_malloc (msg_length);

  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_BOB_TO_ALICE);
  msg->header.size = htons (msg_length);
  msg->total_element_count = htonl (session->total);
  msg->used_element_count = htonl (session->used);
  msg->contained_element_count = htonl (session->transferred);
  memcpy (&msg->key, &session->key, sizeof (struct GNUNET_HashCode));

  payload = (struct GNUNET_CRYPTO_PaillierCiphertext *) &msg[1];
  memcpy (&payload[0], session->s, sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
  memcpy (&payload[1], session->s_prime, sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
  GNUNET_free (session->s_prime);
  session->s_prime = NULL;
  GNUNET_free (session->s);
  session->s = NULL;
  
  // convert k[][]
  for (i = 0; i < session->transferred; i++) {
    //k[i][p] and k[i][q]
    memcpy (&payload[2 + i*2], &session->r[i], sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
    memcpy (&payload[3 + i*2], &session->r_prime[i], sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
  }

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
  else {
    //singlepart
    session->state = FINALIZED;
    GNUNET_free (session->r);
    session->r = NULL;
    GNUNET_free (session->r_prime);
    session->r_prime = NULL;
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
  gcry_mpi_t tmp;
  gcry_mpi_t * b;
  struct GNUNET_CRYPTO_PaillierCiphertext * a;
  struct GNUNET_CRYPTO_PaillierCiphertext * r;
  struct GNUNET_CRYPTO_PaillierCiphertext * r_prime;
  struct GNUNET_CRYPTO_PaillierCiphertext * s;
  struct GNUNET_CRYPTO_PaillierCiphertext * s_prime;
  uint32_t value;

  count = request->used;
  a = request->e_a;
  b = initialize_mpi_vector (count);
  q = GNUNET_CRYPTO_random_permute (GNUNET_CRYPTO_QUALITY_WEAK, count);
  p = GNUNET_CRYPTO_random_permute (GNUNET_CRYPTO_QUALITY_WEAK, count);
  rand = initialize_mpi_vector (count);
  r = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_PaillierCiphertext) * count);
  r_prime = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_PaillierCiphertext) * count);
  s = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
  s_prime = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));

  // convert responder session to from long to mpi
  for (i = 0, j = 0; i < response->total && j < count; i++) {
    if (request->mask[i / 8] & (1 << (i % 8))) {
      value = response->vector[i] >= 0 ? response->vector[i] : -response->vector[i];
      // long to gcry_mpi_t
      if (0 > response->vector[i])
        gcry_mpi_sub_ui (b[j], b[j], value);
      else
        b[j] = gcry_mpi_set_ui (b[j], value);
      j++;
    }
  }
  GNUNET_free (response->vector);
  response->vector = NULL;

  for (i = 0; i < count; i++) {
    int32_t svalue;

    svalue = (int32_t) GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, UINT32_MAX);

    // long to gcry_mpi_t
    if (svalue < 0)
      gcry_mpi_sub_ui (rand[i],
                       rand[i],
                       -svalue);
    else
      rand[i] = gcry_mpi_set_ui (rand[i], svalue);
  }

  tmp = gcry_mpi_new (0);
  // encrypt the element
  // for the sake of readability I decided to have dedicated permutation
  // vectors, which get rid of all the lookups in p/q.
  // however, ap/aq are not absolutely necessary but are just abstraction
  // Calculate Kp = E(S + a_pi) (+) E(S - r_pi - b_pi)
  for (i = 0; i < count; i++) {
    // E(S - r_pi - b_pi)
    gcry_mpi_sub (tmp, my_offset, rand[p[i]]);
    gcry_mpi_sub (tmp, tmp, b[p[i]]);
    GNUNET_CRYPTO_paillier_encrypt (request->remote_pubkey,
                                    tmp,
                                    2,
                                    &r[i]);

    // E(S - r_pi - b_pi) * E(S + a_pi) ==  E(2*S + a - r - b)
    GNUNET_CRYPTO_paillier_hom_add (request->remote_pubkey,
                                    &r[i],
                                    &a[p[i]],
                                    &r[i]);
  }

  // Calculate Kq = E(S + a_qi) (+) E(S - r_qi)
  for (i = 0; i < count; i++) {
    // E(S - r_qi)
    gcry_mpi_sub (tmp, my_offset, rand[q[i]]);
    GNUNET_assert (2 == GNUNET_CRYPTO_paillier_encrypt (request->remote_pubkey,
                                                        tmp,
                                                        2,
                                                        &r_prime[i]));

    // E(S - r_qi) * E(S + a_qi) == E(2*S + a_qi - r_qi)
    GNUNET_assert (1 == GNUNET_CRYPTO_paillier_hom_add (request->remote_pubkey,
                                                        &r_prime[i],
                                                        &a[q[i]],
                                                        &r_prime[i]));
  }

  // Calculate S' =  E(SUM( r_i^2 ))
  tmp = compute_square_sum (rand, count);
  GNUNET_CRYPTO_paillier_encrypt (request->remote_pubkey,
                                  tmp,
                                  1,
                                  s_prime);

  // Calculate S = E(SUM( (r_i + b_i)^2 ))
  for (i = 0; i < count; i++)
    gcry_mpi_add (rand[i], rand[i], b[i]);
  tmp = compute_square_sum (rand, count);
  GNUNET_CRYPTO_paillier_encrypt (request->remote_pubkey,
                                  tmp,
                                  1,
                                  s);

  request->r = r;
  request->r_prime = r_prime;
  request->s = s;
  request->s_prime = s_prime;
  request->response = response;

  // release rand, b and a
  for (i = 0; i < count; i++) {
    gcry_mpi_release (rand[i]);
    gcry_mpi_release (b[i]);
    gcry_mpi_release (request->a[i]);
  }
  gcry_mpi_release (tmp);
  GNUNET_free (request->a);
  request->a = NULL;
  GNUNET_free (p);
  GNUNET_free (q);
  GNUNET_free (b);
  GNUNET_free (rand);

  // copy the r[], r_prime[], S and Stick into a new message, prepare_service_response frees these
  if (GNUNET_YES != prepare_service_response (request))
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, _ ("Failed to communicate with `%s', scalar product calculation aborted.\n"),
                GNUNET_i2s (&request->peer));
  else
    ret = GNUNET_OK;

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
  struct GNUNET_SCALARPRODUCT_multipart_message * msg;
  struct GNUNET_CRYPTO_PaillierCiphertext * payload;
  unsigned int i;
  unsigned int j;
  uint32_t msg_length;
  uint32_t todo_count;
  gcry_mpi_t a;
  uint32_t value;

  msg_length = sizeof (struct GNUNET_SCALARPRODUCT_multipart_message);
  todo_count = session->used - session->transferred;

  if (todo_count > MULTIPART_ELEMENT_CAPACITY)
    // send the currently possible maximum chunk
    todo_count = MULTIPART_ELEMENT_CAPACITY;

  msg_length += todo_count * sizeof(struct GNUNET_CRYPTO_PaillierCiphertext);
  msg = GNUNET_malloc (msg_length);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ALICE_TO_BOB_MULTIPART);
  msg->header.size = htons (msg_length);
  msg->multipart_element_count = htonl (todo_count);

  a = gcry_mpi_new (0);
  payload = (struct GNUNET_CRYPTO_PaillierCiphertext *) &msg[1];
  // encrypt our vector and generate string representations
  for (i = session->last_processed, j = 0; i < session->total; i++) {
    // is this a used element?
    if (session->mask[i / 8] & 1 << (i % 8)) {
      if (todo_count <= j)
        break; //reached end of this message, can't include more

      value = session->vector[i] >= 0 ? session->vector[i] : -session->vector[i];

      a = gcry_mpi_set_ui (a, 0);
      // long to gcry_mpi_t
      if (session->vector[i] < 0)
        gcry_mpi_sub_ui (a, a, value);
      else
        gcry_mpi_add_ui (a, a, value);

      session->a[session->transferred + j] = gcry_mpi_set (NULL, a);
      gcry_mpi_add (a, a, my_offset);
      GNUNET_CRYPTO_paillier_encrypt (&my_pubkey, a, 3, &payload[j++]);
    }
  }
  gcry_mpi_release (a);
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
  struct GNUNET_SCALARPRODUCT_service_request * msg;
  struct GNUNET_CRYPTO_PaillierCiphertext * payload;
  unsigned int i;
  unsigned int j;
  uint32_t msg_length;
  gcry_mpi_t a;
  uint32_t value;

  session->service_request_task = GNUNET_SCHEDULER_NO_TASK;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _ ("Successfully created new channel to peer (%s)!\n"), GNUNET_i2s (&session->peer));

  msg_length = sizeof (struct GNUNET_SCALARPRODUCT_service_request)
          + session->mask_length
          + sizeof(struct GNUNET_CRYPTO_PaillierPublicKey);

  if (GNUNET_SERVER_MAX_MESSAGE_SIZE > msg_length + session->used * sizeof(struct GNUNET_CRYPTO_PaillierCiphertext)) {
    msg_length += session->used * sizeof(struct GNUNET_CRYPTO_PaillierCiphertext);
    session->transferred = session->used;
  }
  else {
    //create a multipart msg, first we calculate a new msg size for the head msg
    session->transferred = (GNUNET_SERVER_MAX_MESSAGE_SIZE - 1 - msg_length) / sizeof(struct GNUNET_CRYPTO_PaillierCiphertext);
  }

  msg = GNUNET_malloc (msg_length);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ALICE_TO_BOB);
  msg->total_element_count = htonl (session->used);
  msg->contained_element_count = htonl (session->transferred);
  memcpy (&msg->key, &session->key, sizeof (struct GNUNET_HashCode));
  msg->mask_length = htonl (session->mask_length);
  msg->element_count = htonl (session->total);
  msg->header.size = htons (msg_length);

  // fill in the payload
  current = (unsigned char *) &msg[1];
  // copy over the mask
  memcpy (current, session->mask, session->mask_length);
  // copy over our public key
  current += session->mask_length;
  memcpy (current, &my_pubkey, sizeof(struct GNUNET_CRYPTO_PaillierPublicKey));
  current += sizeof(struct GNUNET_CRYPTO_PaillierPublicKey);
  payload = (struct GNUNET_CRYPTO_PaillierCiphertext *) current;

  // now copy over the element vector
  session->a = GNUNET_malloc (sizeof (gcry_mpi_t) * session->used);
  a = gcry_mpi_new (0);
  // encrypt our vector and generate string representations
  for (i = 0, j = 0; i < session->total; i++) {
    // if this is a used element...
    if (session->mask[i / 8] & 1 << (i % 8)) {
      if (session->transferred <= j)
        break; //reached end of this message, can't include more

      value = session->vector[i] >= 0 ? session->vector[i] : -session->vector[i];

      a = gcry_mpi_set_ui (a, 0);
      // long to gcry_mpi_t
      if (session->vector[i] < 0)
        gcry_mpi_sub_ui (a, a, value);
      else
        gcry_mpi_add_ui (a, a, value);

      session->a[j] = gcry_mpi_set (NULL, a);
      gcry_mpi_add (a, a, my_offset);
      GNUNET_CRYPTO_paillier_encrypt (&my_pubkey, a, 3, &payload[j++]);
    }
  }
  gcry_mpi_release (a);

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
                                                   GNUNET_MESH_OPTION_RELIABLE);
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
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _ ("Got client-responder-session with key %s and a matching service-request-session set, processing.\n"),
                  GNUNET_h2s (&session->key));
      if (GNUNET_OK != compute_service_response (requesting_session, session))
        session->client_notification_task =
              GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                        session);

    }
    else {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _ ("Got client-responder-session with key %s but NO matching service-request-session set, queuing element for later use.\n"),
                  GNUNET_h2s (&session->key));
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
 * @param options unused
 *
 * @return session associated with the channel
 */
static void *
channel_incoming_handler (void *cls,
                          struct GNUNET_MESH_Channel *channel,
                          const struct GNUNET_PeerIdentity *initiator,
                          uint32_t port, enum GNUNET_MESH_ChannelOption options)
{
  struct ServiceSession * c = GNUNET_new (struct ServiceSession);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _ ("New incoming channel from peer %s.\n"),
              GNUNET_i2s (initiator));

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
  gcry_mpi_t r[session->used];
  gcry_mpi_t r_prime[session->used];
  gcry_mpi_t s;
  gcry_mpi_t s_prime;
  unsigned int i;

  count = session->used;
  // due to the introduced static offset S, we now also have to remove this
  // from the E(a_pi)(+)E(-b_pi-r_pi) and E(a_qi)(+)E(-r_qi) twice each,
  // the result is E((S + a_pi) + (S -b_pi-r_pi)) and E(S + a_qi + S - r_qi)
  for (i = 0; i < count; i++) {
    GNUNET_CRYPTO_paillier_decrypt (&my_privkey, &my_pubkey,
                                    &session->r[i], r[i]);
    gcry_mpi_sub (r[i], r[i], my_offset);
    gcry_mpi_sub (r[i], r[i], my_offset);
    GNUNET_CRYPTO_paillier_decrypt (&my_privkey, &my_pubkey,
                                    &session->r_prime[i], r_prime[i]);
    gcry_mpi_sub (r_prime[i], r_prime[i], my_offset);
    gcry_mpi_sub (r_prime[i], r_prime[i], my_offset);
  }

  // calculate t = sum(ai)
  t = compute_square_sum (session->a, count);

  // calculate U
  u = gcry_mpi_new (0);
  tmp = compute_square_sum (r, count);
  gcry_mpi_sub (u, u, tmp);
  gcry_mpi_release (tmp);

  //calculate U'
  u_prime = gcry_mpi_new (0);
  tmp = compute_square_sum (r_prime, count);
  gcry_mpi_sub (u_prime, u_prime, tmp);

  GNUNET_assert (p = gcry_mpi_new (0));
  GNUNET_assert (p_prime = gcry_mpi_new (0));
  GNUNET_assert (s = gcry_mpi_new (0));
  GNUNET_assert (s_prime = gcry_mpi_new (0));

  // compute P
  GNUNET_CRYPTO_paillier_decrypt (&my_privkey, &my_pubkey,
                                    session->s, s);
  GNUNET_CRYPTO_paillier_decrypt (&my_privkey, &my_pubkey,
                                    session->s_prime, s_prime);

  // compute P
  gcry_mpi_add (p, s, t);
  gcry_mpi_add (p, p, u);

  // compute P'
  gcry_mpi_add (p_prime, s_prime, t);
  gcry_mpi_add (p_prime, p_prime, u_prime);

  gcry_mpi_release (t);
  gcry_mpi_release (u);
  gcry_mpi_release (u_prime);
  gcry_mpi_release (s);
  gcry_mpi_release (s_prime);

  // compute product
  gcry_mpi_sub (p, p, p_prime);
  gcry_mpi_release (p_prime);
  tmp = gcry_mpi_set_ui (tmp, 2);
  gcry_mpi_div (p, NULL, p, tmp, 0);

  gcry_mpi_release (tmp);
  for (i = 0; i < count; i++){
    gcry_mpi_release (session->a[i]);
    gcry_mpi_release (r[i]);
    gcry_mpi_release (r_prime[i]);
  }
  GNUNET_free (session->a);
  session->a = NULL;
  GNUNET_free (session->s);
  session->s = NULL;
  GNUNET_free (session->s_prime);
  session->s_prime = NULL;
  GNUNET_free (session->r);
  session->r = NULL;
  GNUNET_free (session->r_prime);
  session->r_prime = NULL;

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
  struct GNUNET_CRYPTO_PaillierCiphertext *payload;
  uint32_t used_elements;
  uint32_t contained_elements = 0;
  uint32_t msg_length;

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
          + contained_elements * sizeof(struct GNUNET_CRYPTO_PaillierCiphertext);
  //sanity check
  if ((ntohs (msg->header.size) != msg_length)
      || (used_elements < contained_elements + session->transferred)) {
    goto except;
  }
  payload = (struct GNUNET_CRYPTO_PaillierCiphertext *) &msg[1];
  if (contained_elements != 0) {
    // Convert each vector element to MPI_value
    memcpy(&session->e_a[session->transferred], payload, 
           sizeof(struct GNUNET_CRYPTO_PaillierCiphertext) * contained_elements);
    
    session->transferred += contained_elements;

    if (session->transferred == used_elements) {
      // single part finished
      session->state = SERVICE_REQUEST_RECEIVED;
      if (session->response) {
        GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                    _ ("Got session with key %s and a matching element set, processing.\n"),
                    GNUNET_h2s (&session->key));
        if (GNUNET_OK != compute_service_response (session, session->response)) {
          //something went wrong, remove it again...
          goto except;
        }
      }
      else
        GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                    _ ("Got session with key %s without a matching element set, queueing.\n"),
                    GNUNET_h2s (&session->key));
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
  struct GNUNET_CRYPTO_PaillierCiphertext *payload;
  uint32_t used_elements;
  uint32_t contained_elements = 0;
  uint32_t element_count;
  uint32_t msg_length;
  unsigned char * current;
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
  used_elements = ntohl (msg->total_element_count);
  contained_elements = ntohl (msg->contained_element_count);
  element_count = ntohl (msg->element_count);
  msg_length = sizeof (struct GNUNET_SCALARPRODUCT_service_request)
          + mask_length + sizeof(struct GNUNET_CRYPTO_PaillierPublicKey) 
          + contained_elements * sizeof(struct GNUNET_CRYPTO_PaillierCiphertext);

  //sanity check: is the message as long as the message_count fields suggests?
  if ((ntohs (msg->header.size) != msg_length) ||
      (element_count < used_elements) ||
      (used_elements < contained_elements) ||
      (0 == used_elements) ||
      (mask_length != (element_count / 8 + ((element_count % 8) ? 1 : 0)))) {
    GNUNET_free (session);
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (find_matching_session (from_service_tail,
                             &msg->key,
                             element_count,
                             NULL,
                             NULL)) {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Got message with duplicate session key (`%s'), ignoring service request.\n"),
                (const char *) &(msg->key));
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
  session->remote_pubkey = GNUNET_malloc(sizeof(struct GNUNET_CRYPTO_PaillierPublicKey));
  memcpy(session->remote_pubkey, current, sizeof(struct GNUNET_CRYPTO_PaillierPublicKey));
  current += sizeof(struct GNUNET_CRYPTO_PaillierPublicKey);
  
  payload = (struct GNUNET_CRYPTO_PaillierCiphertext*) current;
  //check if service queue contains a matching request
  needed_state = CLIENT_RESPONSE_RECEIVED;
  session->response = find_matching_session (from_client_tail,
                                             &session->key,
                                             session->total,
                                             &needed_state, NULL);
  session->state = WAITING_FOR_MULTIPART_TRANSMISSION;
  GNUNET_CONTAINER_DLL_insert (from_service_head, from_service_tail, session);
  
  session->e_a = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_PaillierCiphertext) * used_elements);
  if (contained_elements != 0) {
    // Convert each vector element to MPI_value
    memcpy(session->e_a, payload, sizeof (struct GNUNET_CRYPTO_PaillierCiphertext) * used_elements);
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
  struct GNUNET_CRYPTO_PaillierCiphertext * payload;
  size_t i;
  uint32_t contained = 0;
  size_t msg_size;
  size_t required_size;

  GNUNET_assert (NULL != message);
  // are we in the correct state?
  session = (struct ServiceSession *) * channel_ctx;
  if ((ALICE != session->role) || (WAITING_FOR_MULTIPART_TRANSMISSION != session->state)) {
    goto invalid_msg;
  }
  msg_size = ntohs (msg->header.size);
  required_size = sizeof (struct GNUNET_SCALARPRODUCT_multipart_message) 
                  + 2 * sizeof (struct GNUNET_CRYPTO_PaillierCiphertext);
  // shorter than minimum?
  if (required_size > msg_size) {
    goto invalid_msg;
  }
  contained = ntohl (msg->multipart_element_count);
  required_size = sizeof (struct GNUNET_SCALARPRODUCT_multipart_message)
          + 2 * contained * sizeof (struct GNUNET_CRYPTO_PaillierCiphertext);
  //sanity check: is the message as long as the message_count fields suggests?
  if ((required_size != msg_size) || (session->used < session->transferred + contained)) {
    goto invalid_msg;
  }
  payload = (struct GNUNET_CRYPTO_PaillierCiphertext *) &msg[1];
  // Convert each k[][perm] to its MPI_value
  for (i = 0; i < contained; i++) {
    memcpy(&session->r[session->transferred+i], &payload[2*i], sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
    memcpy(&session->r_prime[session->transferred+i], &payload[2*i], sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
  }
  session->transferred += contained;
  if (session->transferred != session->used)
    return GNUNET_OK;
  session->state = SERVICE_RESPONSE_RECEIVED;
  session->product = compute_scalar_product (session); //never NULL

invalid_msg:
  GNUNET_break_op (NULL != session->product); //NULL if we never tried to compute it...

  // send message with product to client
  if (ALICE == session->role) {
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
  struct GNUNET_CRYPTO_PaillierCiphertext * payload;
  size_t i;
  uint32_t contained = 0;
  size_t msg_size;
  size_t required_size;

  GNUNET_assert (NULL != message);
  session = (struct ServiceSession *) * channel_ctx;
  // are we in the correct state?
  if (WAITING_FOR_SERVICE_RESPONSE != session->state) {
    goto invalid_msg;
  }
  //we need at least a full message without elements attached
  msg_size = ntohs (msg->header.size);
  required_size = sizeof (struct GNUNET_SCALARPRODUCT_service_response) + 2 * sizeof (struct GNUNET_CRYPTO_PaillierCiphertext);

  if (required_size > msg_size) {
    goto invalid_msg;
  }
  contained = ntohl (msg->contained_element_count);
  required_size = sizeof (struct GNUNET_SCALARPRODUCT_service_response)
          + 2 * contained * sizeof (struct GNUNET_CRYPTO_PaillierCiphertext)
          + 2 * sizeof (struct GNUNET_CRYPTO_PaillierCiphertext);
  //sanity check: is the message as long as the message_count fields suggests?
  if ((msg_size != required_size) || (session->used < contained)) {
    goto invalid_msg;
  }
  session->state = WAITING_FOR_MULTIPART_TRANSMISSION;
  session->transferred = contained;
  //convert s
  payload = (struct GNUNET_CRYPTO_PaillierCiphertext *) &msg[1];
  
  session->s = GNUNET_malloc(sizeof(struct GNUNET_CRYPTO_PaillierCiphertext));
  session->s_prime = GNUNET_malloc(sizeof(struct GNUNET_CRYPTO_PaillierCiphertext));
  memcpy(session->s,&payload[0],sizeof(struct GNUNET_CRYPTO_PaillierCiphertext));
  memcpy(session->s_prime,&payload[1],sizeof(struct GNUNET_CRYPTO_PaillierCiphertext));
  
  session->r = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_PaillierCiphertext) * session->used);
  session->r_prime = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_PaillierCiphertext) * session->used);
  
  // Convert each k[][perm] to its MPI_value
  for (i = 0; i < contained; i++) {
    memcpy(&session->r[i], &payload[2 + 2*i], sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
    memcpy(&session->r_prime[i], &payload[3 + 2*i], sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
  }
  if (session->transferred != session->used)
    return GNUNET_OK; //wait for the other multipart chunks

  session->state = SERVICE_RESPONSE_RECEIVED;
  session->product = compute_scalar_product (session); //never NULL

invalid_msg:
  GNUNET_break_op (NULL != session->product);
  // send message with product to client
  if (ALICE == session->role) {
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
  GNUNET_CRYPTO_paillier_create (&my_pubkey, &my_privkey);
  
  // offset has to be sufficiently small to allow computation of:
  // m1+m2 mod n == (S + a) + (S + b) mod n,
  // if we have more complex operations, this factor needs to be lowered
  my_offset = gcry_mpi_new (GNUNET_CRYPTO_PAILLIER_BITS / 3);
  gcry_mpi_set_bit (my_offset, GNUNET_CRYPTO_PAILLIER_BITS / 3);
  
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
