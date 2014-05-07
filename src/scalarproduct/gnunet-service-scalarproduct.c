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
#include "gnunet_cadet_service.h"
#include "gnunet_applications.h"
#include "gnunet_protocols.h"
#include "gnunet_scalarproduct_service.h"
#include "gnunet_set_service.h"
#include "scalarproduct.h"

#define LOG(kind,...) GNUNET_log_from (kind, "scalarproduct", __VA_ARGS__)

///////////////////////////////////////////////////////////////////////////////
//                     Service Structure Definitions
///////////////////////////////////////////////////////////////////////////////


/**
 * role a peer in a session can assume
 */
enum PeerRole
{
  ALICE,
  BOB
};

/**
 * DLL for sorting elements
 */
struct SortedValue
{
  /**
   * Sorted Values are kept in a DLL
   */
  struct SortedValue * next;
  
  /**
   * Sorted Values are kept in a DLL
   */
  struct SortedValue * prev;
  
  /**
   * The element's id+integer-value
   */
  struct GNUNET_SCALARPRODUCT_Element * elem;
  
  /**
   * the element's value converted to MPI
   */
  gcry_mpi_t val;
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
  struct GNUNET_HashCode session_id;

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
   * how many elements we used for intersection
   */
  uint32_t intersected_elements_count;

  /**
   * all non-0-value'd elements transmitted to us
   */
  struct GNUNET_CONTAINER_MultiHashMap * intersected_elements;

  /**
   * how many elements actually are used for the scalar product
   */
  uint32_t used_elements_count;

  /**
   * already transferred elements (sent/received) for multipart messages, less or equal than used_element_count for
   */
  uint32_t transferred_element_count;

  /**
   * Set of elements for which will conduction an intersection. 
   * the resulting elements are then used for computing the scalar product.
   */
  struct GNUNET_SET_Handle * intersection_set;

  /**
   * Set of elements for which will conduction an intersection. 
   * the resulting elements are then used for computing the scalar product.
   */
  struct GNUNET_SET_OperationHandle * intersection_op;

  /**
   * Handle to Alice's Intersection operation listening for Bob
   */
  struct GNUNET_SET_ListenHandle * intersection_listen;

  /**
   * Public key of the remote service, only used by bob
   */
  struct GNUNET_CRYPTO_PaillierPublicKey * remote_pubkey;

  /**
   * DLL for sorting elements after intersection
   */
  struct SortedValue * a_head;

  /**
   * a(Alice)
   */
  struct SortedValue * a_tail;

  /**
   * a(Alice)
   */
  gcry_mpi_t * sorted_elements;

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
  struct GNUNET_CADET_TransmitHandle * service_transmit_handle;

  /**
   * My transmit handle for the current message to the client
   */
  struct GNUNET_SERVER_TransmitHandle * client_transmit_handle;

  /**
   * channel-handle associated with our cadet handle
   */
  struct GNUNET_CADET_Channel * channel;

  /**
   * Handle to a task that sends a msg to the our client
   */
  GNUNET_SCHEDULER_TaskIdentifier client_notification_task;
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
prepare_alices_cyrptodata_message_multipart (void *cls);

/**
 * Send a multi part chunk of a service response from bob to alice.
 * This element only contains the two permutations of R, R'.
 *
 * @param cls the associated service session
 */
static void
prepare_bobs_cryptodata_message_multipart (void *cls);


///////////////////////////////////////////////////////////////////////////////
//                      Global Variables
///////////////////////////////////////////////////////////////////////////////


/**
 * Gnunet configuration handle
 */
const struct GNUNET_CONFIGURATION_Handle * cfg;

/**
 * Handle to the core service (NULL until we've connected to it).
 */
static struct GNUNET_CADET_Handle *my_cadet;

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
 * Certain events (callbacks for server & cadet operations) must not be queued after shutdown.
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
 * @param cls the session containing the message object
 * @param size the size of the buffer we got
 * @param buf the buffer to copy the message to
 * @return 0 if we couldn't copy, else the size copied over
 */
static size_t
do_send_message (void *cls, size_t size, void *buf)
{
  struct ServiceSession * s = cls;
  uint16_t type;

  GNUNET_assert (buf);

  if (ntohs (s->msg->size) != size) {
    GNUNET_break (0);
    return 0;
  }

  type = ntohs (s->msg->type);
  memcpy (buf, s->msg, size);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sent a message of type %hu.\n",
              type);
  GNUNET_free (s->msg);
  s->msg = NULL;

  switch (type)
  {
  case GNUNET_MESSAGE_TYPE_SCALARPRODUCT_RESULT:
    s->client_transmit_handle = NULL;
    break;

  case GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ALICE_CRYPTODATA:
  case GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ALICE_CRYPTODATA_MULTIPART:
    s->service_transmit_handle = NULL;
    if (s->used_elements_count != s->transferred_element_count)
      prepare_alices_cyrptodata_message_multipart (s);
    break;

  case GNUNET_MESSAGE_TYPE_SCALARPRODUCT_BOB_CRYPTODATA:
  case GNUNET_MESSAGE_TYPE_SCALARPRODUCT_BOB_CRYPTODATA_MULTIPART:
    s->service_transmit_handle = NULL;
    if (s->used_elements_count != s->transferred_element_count)
      prepare_bobs_cryptodata_message_multipart (s);
    break;

  default:
    GNUNET_assert (0);
  }

  return size;
}


/**
 * Finds a not terminated client/service session in the
 * given DLL based on session key, element count and state.
 *
 * @param tail - the tail of the DLL
 * @param key - the key we want to search for
 * @param element_count - the total element count of the dataset (session->total)
 * @param peerid - a pointer to the peer ID of the associated peer, NULL to ignore
 * @return a pointer to a matching session, or NULL
 */
static struct ServiceSession *
find_matching_session (struct ServiceSession * tail,
                       const struct GNUNET_HashCode * key,
                       uint32_t element_count,
                       const struct GNUNET_PeerIdentity * peerid)
{
  struct ServiceSession * curr;

  for (curr = tail; NULL != curr; curr = curr->prev) {
    // if the key matches, and the element_count is same
    if ((!memcmp (&curr->session_id, key, sizeof (struct GNUNET_HashCode)))
        && (curr->total == element_count)) {
      // if peerid is NULL OR same as the peer Id in the queued request
      if ((NULL == peerid)
          || (!memcmp (&curr->peer, peerid, sizeof (struct GNUNET_PeerIdentity))))
        // matches and is not an already terminated session
        return curr;
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
  while (NULL != session->a_head) {
    struct SortedValue * e = session->a_head;
    GNUNET_free (e->elem);
    gcry_mpi_release (e->val);
    GNUNET_CONTAINER_DLL_remove (session->a_head, session->a_tail, e);
    GNUNET_free (e);
  }
  if (session->e_a) {
    GNUNET_free (session->e_a);
    session->e_a = NULL;
  }
  if (session->remote_pubkey){
    GNUNET_free(session->remote_pubkey);
    session->remote_pubkey=NULL;
  }
  if (session->sorted_elements) {
    GNUNET_free (session->sorted_elements);
    session->sorted_elements = NULL;
  }
  if (session->intersected_elements) {
    GNUNET_CONTAINER_multihashmap_destroy (session->intersected_elements);
    //elements are freed independently in session->a_head/tail
    session->intersected_elements = NULL;
  }
  if (session->intersection_listen) {
    GNUNET_SET_listen_cancel (session->intersection_listen);
    session->intersection_listen = NULL;
  }
  if (session->intersection_op) {
    GNUNET_SET_operation_cancel (session->intersection_op);
    session->intersection_op = NULL;
  }
  if (session->intersection_set) {
    GNUNET_SET_destroy (session->intersection_set);
    session->intersection_set = NULL;
  }
  if (session->channel){
    GNUNET_CADET_channel_destroy(session->channel);
    session->channel = NULL;
  }
  if (session->msg) {
    GNUNET_free (session->msg);
    session->msg = NULL;
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

  if (!(session->role == BOB && 0/*//TODO: if session concluded*/)) {
    //we MUST terminate any client message underway
    if (session->service_transmit_handle && session->channel)
      GNUNET_CADET_notify_transmit_ready_cancel (session->service_transmit_handle);
    if (session->channel && 0/* //TODO: waiting for service response */)
      GNUNET_CADET_channel_destroy (session->channel);
  }
  if (GNUNET_SCHEDULER_NO_TASK != session->client_notification_task) {
    GNUNET_SCHEDULER_cancel (session->client_notification_task);
    session->client_notification_task = GNUNET_SCHEDULER_NO_TASK;
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
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_RESULT);
  memcpy (&msg->key, &session->session_id, sizeof (struct GNUNET_HashCode));
  memcpy (&msg->peer, &session->peer, sizeof ( struct GNUNET_PeerIdentity));
  msg->header.size = htons (sizeof (struct GNUNET_SCALARPRODUCT_client_response));
  // signal error if not signalized, positive result-range field but zero length.
  msg->product_length = htonl (0);
  msg->range = (session /* //TODO: if finalized */) ? 0 : -1;

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
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, _ ("Sending session-end notification to client (%p) for session %s\n"), &session->client, GNUNET_h2s (&session->session_id));

  free_session_variables (session);
}


/**
 * Executed by Alice, fills in a service-request message and sends it to the given peer
 *
 * @param cls the session associated with this request
 */
static void
prepare_alices_cyrptodata_message (void *cls)
{
  struct ServiceSession * session = cls;
  struct GNUNET_SCALARPRODUCT_alices_cryptodata_message * msg;
  struct GNUNET_CRYPTO_PaillierCiphertext * payload;
  unsigned int i;
  uint32_t msg_length;
  gcry_mpi_t a;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _ ("Successfully created new channel to peer (%s)!\n"), GNUNET_i2s (&session->peer));

  msg_length = sizeof (struct GNUNET_SCALARPRODUCT_alices_cryptodata_message)
          +session->used_elements_count * sizeof (struct GNUNET_CRYPTO_PaillierCiphertext);

  if (GNUNET_SERVER_MAX_MESSAGE_SIZE > msg_length) {
    session->transferred_element_count = session->used_elements_count;
  }
  else {
    //create a multipart msg, first we calculate a new msg size for the head msg
    session->transferred_element_count = (GNUNET_SERVER_MAX_MESSAGE_SIZE - 1 - sizeof (struct GNUNET_SCALARPRODUCT_alices_cryptodata_message))
            / sizeof (struct GNUNET_CRYPTO_PaillierCiphertext);
    msg_length = sizeof (struct GNUNET_SCALARPRODUCT_alices_cryptodata_message)
            +session->transferred_element_count * sizeof (struct GNUNET_CRYPTO_PaillierCiphertext);
  }

  msg = GNUNET_malloc (msg_length);
  msg->header.size = htons (msg_length);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ALICE_CRYPTODATA);
  msg->contained_element_count = htonl (session->transferred_element_count);

  // fill in the payload
  payload = (struct GNUNET_CRYPTO_PaillierCiphertext *) &msg[1];

  // now copy over the sorted element vector
  a = gcry_mpi_new (0);
  for (i = 0; i < session->transferred_element_count; i++) {
    gcry_mpi_add (a, session->sorted_elements[i], my_offset);
    GNUNET_CRYPTO_paillier_encrypt (&my_pubkey, a, 3, &payload[i]);
  }
  gcry_mpi_release (a);

  session->msg = (struct GNUNET_MessageHeader *) msg;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _ ("Transmitting service request.\n"));

  //transmit via cadet messaging
  session->service_transmit_handle = GNUNET_CADET_notify_transmit_ready (session->channel, GNUNET_YES,
                                                                        GNUNET_TIME_UNIT_FOREVER_REL,
                                                                        msg_length,
                                                                        &do_send_message,
                                                                        session);
  if (NULL == session->service_transmit_handle) {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _ ("Could not send message to channel!\n"));
    GNUNET_free (msg);
    session->msg = NULL;
    session->client_notification_task =
            GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                      session);
    return;
  }
}


/**
 * Send a multipart chunk of a service response from bob to alice.
 * This element only contains the two permutations of R, R'.
 *
 * @param cls the associated service session
 */
static void
prepare_bobs_cryptodata_message_multipart (void *cls)
{
  struct ServiceSession * session = cls;
  struct GNUNET_CRYPTO_PaillierCiphertext * payload;
  struct GNUNET_SCALARPRODUCT_multipart_message * msg;
  unsigned int i;
  unsigned int j;
  uint32_t msg_length;
  uint32_t todo_count;

  msg_length = sizeof (struct GNUNET_SCALARPRODUCT_multipart_message);
  todo_count = session->used_elements_count - session->transferred_element_count;

  if (todo_count > MULTIPART_ELEMENT_CAPACITY / 2)
    // send the currently possible maximum chunk, we always transfer both permutations
    todo_count = MULTIPART_ELEMENT_CAPACITY / 2;

  msg_length += todo_count * sizeof (struct GNUNET_CRYPTO_PaillierCiphertext) * 2;
  msg = GNUNET_malloc (msg_length);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ALICE_CRYPTODATA_MULTIPART);
  msg->header.size = htons (msg_length);
  msg->contained_element_count = htonl (todo_count);

  payload = (struct GNUNET_CRYPTO_PaillierCiphertext *) &msg[1];
  for (i = session->transferred_element_count, j = 0; i < session->transferred_element_count + todo_count; i++) {
    //r[i][p] and r[i][q]
    memcpy (&payload[j++], &session->r[i], sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
    memcpy (&payload[j++], &session->r_prime[i], sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
  }
  session->transferred_element_count += todo_count;
  session->msg = (struct GNUNET_MessageHeader *) msg;
  session->service_transmit_handle =
          GNUNET_CADET_notify_transmit_ready (session->channel,
                                             GNUNET_YES,
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             msg_length,
                                             &do_send_message,
                                             session);
  //disconnect our client
  if (NULL == session->service_transmit_handle) {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _ ("Could not send service-response message via cadet!)\n"));
    
    GNUNET_free (msg);
    session->msg = NULL;
    GNUNET_CONTAINER_DLL_remove (from_service_head, from_service_tail, session);
    
    session->response->client_notification_task =
            GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                      session->response);
    free_session_variables(session);
    GNUNET_free(session);
    return;
  }
  if (session->transferred_element_count != session->used_elements_count) {
    // more multiparts
  }
  else {
    // final part
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
 */
static void
prepare_bobs_cryptodata_message (void *cls,
                          const struct GNUNET_SCHEDULER_TaskContext
                          * tc)
{
  struct ServiceSession * session = (struct ServiceSession *) cls;
  struct GNUNET_SCALARPRODUCT_service_response * msg;
  uint32_t msg_length = 0;
  struct GNUNET_CRYPTO_PaillierCiphertext * payload;
  int i;

  msg_length = sizeof (struct GNUNET_SCALARPRODUCT_service_response)
          + 2 * sizeof (struct GNUNET_CRYPTO_PaillierCiphertext); // s, stick

  if (GNUNET_SERVER_MAX_MESSAGE_SIZE >
      msg_length + 2 * session->used_elements_count * sizeof (struct GNUNET_CRYPTO_PaillierCiphertext)) { //r, r'
    msg_length += 2 * session->used_elements_count * sizeof (struct GNUNET_CRYPTO_PaillierCiphertext);
    session->transferred_element_count = session->used_elements_count;
  }
  else
    session->transferred_element_count = (GNUNET_SERVER_MAX_MESSAGE_SIZE - 1 - msg_length) /
    (sizeof (struct GNUNET_CRYPTO_PaillierCiphertext) * 2);

  msg = GNUNET_malloc (msg_length);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_BOB_CRYPTODATA);
  msg->header.size = htons (msg_length);
  msg->total_element_count = htonl (session->total);
  msg->used_element_count = htonl (session->used_elements_count);
  msg->contained_element_count = htonl (session->transferred_element_count);
  memcpy (&msg->key, &session->session_id, sizeof (struct GNUNET_HashCode));

  payload = (struct GNUNET_CRYPTO_PaillierCiphertext *) &msg[1];
  memcpy (&payload[0], session->s, sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
  memcpy (&payload[1], session->s_prime, sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
  GNUNET_free (session->s_prime);
  session->s_prime = NULL;
  GNUNET_free (session->s);
  session->s = NULL;

  payload = &payload[2];
  // convert k[][]
  for (i = 0; i < session->transferred_element_count; i++) {
    //k[i][p] and k[i][q]
    memcpy (&payload[i * 2], &session->r[i], sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
    memcpy (&payload[i * 2 + 1], &session->r_prime[i], sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
  }

  session->msg = (struct GNUNET_MessageHeader *) msg;
  session->service_transmit_handle =
          GNUNET_CADET_notify_transmit_ready (session->channel,
                                             GNUNET_YES,
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             msg_length,
                                             &do_send_message,
                                             session);
  //disconnect our client
  if (NULL == session->service_transmit_handle) {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _ ("Could not send service-response message via cadet!)\n"));

    GNUNET_free (msg);
    session->msg = NULL;
    GNUNET_CONTAINER_DLL_remove (from_service_head, from_service_tail, session);
    
    session->response->client_notification_task =
            GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                      session->response);
    free_session_variables(session);
    GNUNET_free(session);
    return;
  }
  if (session->transferred_element_count != session->used_elements_count) {
    // multipart
  }
  else {
    //singlepart
    GNUNET_free (session->r);
    session->r = NULL;
    GNUNET_free (session->r_prime);
    session->r_prime = NULL;
  }
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
 */
static void
compute_service_response (struct ServiceSession * session)
{
  int i;
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

  count = session->used_elements_count;
  a = session->e_a;
  b = session->sorted_elements;
  q = GNUNET_CRYPTO_random_permute (GNUNET_CRYPTO_QUALITY_WEAK, count);
  p = GNUNET_CRYPTO_random_permute (GNUNET_CRYPTO_QUALITY_WEAK, count);

  for (i = 0; i < count; i++)
    GNUNET_assert (NULL != (rand[i] = gcry_mpi_new (0)));
  r = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_PaillierCiphertext) * count);
  r_prime = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_PaillierCiphertext) * count);
  s = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
  s_prime = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));

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
    GNUNET_CRYPTO_paillier_encrypt (session->remote_pubkey,
                                    tmp,
                                    2,
                                    &r[i]);

    // E(S - r_pi - b_pi) * E(S + a_pi) ==  E(2*S + a - r - b)
    GNUNET_CRYPTO_paillier_hom_add (session->remote_pubkey,
                                    &r[i],
                                    &a[p[i]],
                                    &r[i]);
  }

  // Calculate Kq = E(S + a_qi) (+) E(S - r_qi)
  for (i = 0; i < count; i++) {
    // E(S - r_qi)
    gcry_mpi_sub (tmp, my_offset, rand[q[i]]);
    GNUNET_assert (2 == GNUNET_CRYPTO_paillier_encrypt (session->remote_pubkey,
                                                        tmp,
                                                        2,
                                                        &r_prime[i]));

    // E(S - r_qi) * E(S + a_qi) == E(2*S + a_qi - r_qi)
    GNUNET_assert (1 == GNUNET_CRYPTO_paillier_hom_add (session->remote_pubkey,
                                                        &r_prime[i],
                                                        &a[q[i]],
                                                        &r_prime[i]));
  }

  // Calculate S' =  E(SUM( r_i^2 ))
  tmp = compute_square_sum (rand, count);
  GNUNET_CRYPTO_paillier_encrypt (session->remote_pubkey,
                                  tmp,
                                  1,
                                  s_prime);

  // Calculate S = E(SUM( (r_i + b_i)^2 ))
  for (i = 0; i < count; i++)
    gcry_mpi_add (rand[i], rand[i], b[i]);
  tmp = compute_square_sum (rand, count);
  GNUNET_CRYPTO_paillier_encrypt (session->remote_pubkey,
                                  tmp,
                                  1,
                                  s);

  session->r = r;
  session->r_prime = r_prime;
  session->s = s;
  session->s_prime = s_prime;

  // release rand, b and a
  for (i = 0; i < count; i++) {
    gcry_mpi_release (rand[i]);
    gcry_mpi_release (b[i]);
  }
  gcry_mpi_release (tmp);
  GNUNET_free (session->e_a);
  session->e_a = NULL;
  GNUNET_free (p);
  GNUNET_free (q);
  GNUNET_free (b);
  GNUNET_free (rand);

  // copy the r[], r_prime[], S and Stick into a new message, prepare_service_response frees these
  GNUNET_SCHEDULER_add_now (&prepare_bobs_cryptodata_message, session);
}


/**
 * Iterator over all hash map entries in session->intersected_elements.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES if we should continue to
 *         iterate,
 *         #GNUNET_NO if not.
 */
int
cb_insert_element_sorted (void *cls,
                          const struct GNUNET_HashCode *key,
                          void *value)
{
  struct ServiceSession * session = (struct ServiceSession*) cls;
  struct SortedValue * e = GNUNET_new (struct SortedValue);
  struct SortedValue * o = session->a_head;

  e->elem = value;
  e->val = gcry_mpi_new (0);
  if (0 > e->elem->value)
    gcry_mpi_sub_ui (e->val, e->val, abs (e->elem->value));
  else
    gcry_mpi_add_ui (e->val, e->val, e->elem->value);

  // insert as first element with the lowest key
  if (NULL == session->a_head
      || (0 <= GNUNET_CRYPTO_hash_cmp (&session->a_head->elem->key, &e->elem->key))) {
    GNUNET_CONTAINER_DLL_insert (session->a_head, session->a_tail, e);
    return GNUNET_YES;
  }
  // insert as last element with the highest key
  if (0 >= GNUNET_CRYPTO_hash_cmp (&session->a_tail->elem->key, &e->elem->key)) {
    GNUNET_CONTAINER_DLL_insert_tail (session->a_head, session->a_tail, e);
    return GNUNET_YES;
  }
  // insert before the first higher/equal element
  do {
    if (0 <= GNUNET_CRYPTO_hash_cmp (&o->elem->key, &e->elem->key)) {
      GNUNET_CONTAINER_DLL_insert_before (session->a_head, session->a_tail, o, e);
      return GNUNET_YES;
    }
    o = o->next;
  }
  while (NULL != o);
  // broken DLL
  GNUNET_assert (0);
}


/**
 * Callback for set operation results. Called for each element
 * in the result set.
 *
 * @param cls closure
 * @param element a result element, only valid if status is #GNUNET_SET_STATUS_OK
 * @param status see `enum GNUNET_SET_Status`
 */
static void
cb_intersection_element_removed (void *cls,
                                 const struct GNUNET_SET_Element *element,
                                 enum GNUNET_SET_Status status)
{
  struct ServiceSession * session = (struct ServiceSession*) cls;
  struct GNUNET_SCALARPRODUCT_Element * se;
  int i;

  switch (status)
  {
  case GNUNET_SET_STATUS_OK:
    //this element has been removed from the set
    se = GNUNET_CONTAINER_multihashmap_get (session->intersected_elements,
                                            element->data);

    GNUNET_CONTAINER_multihashmap_remove (session->intersected_elements,
                                          element->data,
                                          se);
    session->used_elements_count--;
    return;

  case GNUNET_SET_STATUS_DONE:
    if (2 > session->used_elements_count) {
      // failed! do not leak information about our single remaining element!
      // continue after the loop
      break;
    }

    GNUNET_CONTAINER_multihashmap_iterate (session->intersected_elements,
                                           &cb_insert_element_sorted,
                                           session);

    session->sorted_elements = GNUNET_malloc (session->used_elements_count * sizeof (gcry_mpi_t));
    for (i = 0; NULL != session->a_head; i++) {
      struct SortedValue* a = session->a_head;
      GNUNET_assert (i < session->used_elements_count);
      
      session->sorted_elements[i] = a->val;
      GNUNET_CONTAINER_DLL_remove (session->a_head, session->a_tail, a);
      GNUNET_free (a->elem);
    }
    GNUNET_assert (i == session->used_elements_count);

    if (ALICE == session->role) {
      prepare_alices_cyrptodata_message (session);
      return;
    }
    else if (session->used_elements_count == session->transferred_element_count) {
      compute_service_response (session);
      return;
    }
  default:
    break;
  }

  //failed if we go here
  GNUNET_break (0);

  // and notify our client-session that we could not complete the session
  if (ALICE == session->role) {
    session->client_notification_task =
            GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                      session);
  }
  else {
    GNUNET_CONTAINER_DLL_remove (from_service_head, from_service_tail, session);
    free_session_variables (session);
    session->response->client_notification_task =
            GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                      session->response);
    GNUNET_free(session);
  }
}


/**
 * Called when another peer wants to do a set operation with the
 * local peer. If a listen error occurs, the @a request is NULL.
 *
 * @param cls closure
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
  struct ServiceSession * session = (struct ServiceSession *) cls;

  // check the peer-id, the app-id=session-id is compared by SET
  if (0 != memcmp (&session->peer, &other_peer, sizeof (struct GNUNET_PeerIdentity)))
    return;

  session->intersection_op = GNUNET_SET_accept (request,
                                                GNUNET_SET_RESULT_REMOVED,
                                                cb_intersection_element_removed,
                                                session);

  if (NULL == session->intersection_op) {
    session->response->client_notification_task =
            GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                      session);
    return;
  }
  if (GNUNET_OK != GNUNET_SET_commit (session->intersection_op, session->intersection_set)) {
    session->response->client_notification_task =
            GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                      session);
    return;
  }
  session->intersection_set = NULL;
  session->intersection_listen = NULL;
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
  msg->key = session->session_id;
  msg->peer = session->peer;
  if (product_exported != NULL) {
    memcpy (&msg[1], product_exported, product_length);
    GNUNET_free (product_exported);
  }
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_RESULT);
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
                GNUNET_h2s (&session->session_id));
  free_session_variables (session);
}


/**
 * Executed by Alice, fills in a service-request message and sends it to the given peer
 *
 * @param session the session associated with this request
 */
static void
prepare_alices_computation_request (struct ServiceSession * session)
{
  struct GNUNET_SCALARPRODUCT_service_request * msg;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _ ("Successfully created new channel to peer (%s)!\n"), GNUNET_i2s (&session->peer));

  msg = GNUNET_new (struct GNUNET_SCALARPRODUCT_service_request);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ALICE_CRYPTODATA);
  msg->total_element_count = htonl (session->used_elements_count);
  memcpy (&msg->session_id, &session->session_id, sizeof (struct GNUNET_HashCode));
  msg->header.size = htons (sizeof (struct GNUNET_SCALARPRODUCT_service_request));

  session->msg = (struct GNUNET_MessageHeader *) msg;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _ ("Transmitting service request.\n"));

  //transmit via cadet messaging
  session->service_transmit_handle = GNUNET_CADET_notify_transmit_ready (session->channel, GNUNET_YES,
                                                                        GNUNET_TIME_UNIT_FOREVER_REL,
                                                                        sizeof (struct GNUNET_SCALARPRODUCT_service_request),
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
prepare_alices_cyrptodata_message_multipart (void *cls)
{
  struct ServiceSession * session = cls;
  struct GNUNET_SCALARPRODUCT_multipart_message * msg;
  struct GNUNET_CRYPTO_PaillierCiphertext * payload;
  unsigned int i;
  uint32_t msg_length;
  uint32_t todo_count;
  gcry_mpi_t a;

  msg_length = sizeof (struct GNUNET_SCALARPRODUCT_multipart_message);
  todo_count = session->used_elements_count - session->transferred_element_count;

  if (todo_count > MULTIPART_ELEMENT_CAPACITY)
    // send the currently possible maximum chunk
    todo_count = MULTIPART_ELEMENT_CAPACITY;

  msg_length += todo_count * sizeof (struct GNUNET_CRYPTO_PaillierCiphertext);
  msg = GNUNET_malloc (msg_length);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ALICE_CRYPTODATA_MULTIPART);
  msg->header.size = htons (msg_length);
  msg->contained_element_count = htonl (todo_count);

  payload = (struct GNUNET_CRYPTO_PaillierCiphertext *) &msg[1];

  // now copy over the sorted element vector
  a = gcry_mpi_new (0);
  for (i = session->transferred_element_count; i < todo_count; i++) {
    gcry_mpi_add (a, session->sorted_elements[i], my_offset);
    GNUNET_CRYPTO_paillier_encrypt (&my_pubkey, a, 3, &payload[i - session->transferred_element_count]);
  }
  gcry_mpi_release (a);
  session->transferred_element_count += todo_count;

  session->msg = (struct GNUNET_MessageHeader *) msg;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _ ("Transmitting service request.\n"));

  //transmit via cadet messaging
  session->service_transmit_handle = GNUNET_CADET_notify_transmit_ready (session->channel, GNUNET_YES,
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
}


/**
 * Our client has finished sending us its multipart message.
 * 
 * @param session the service session context
 */
static void
client_request_complete_bob (struct ServiceSession * client_session)
{
  struct ServiceSession * session;

  //check if service queue contains a matching request
  session = find_matching_session (from_service_tail,
                                   &client_session->session_id,
                                   client_session->total, NULL);
  if (NULL != session) {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _ ("Got client-responder-session with key %s and a matching service-request-session set, processing.\n"),
                GNUNET_h2s (&client_session->session_id));

    session->response = client_session;
    session->intersected_elements = client_session->intersected_elements;
    client_session->intersected_elements = NULL;
    session->intersection_set = client_session->intersection_set;
    client_session->intersection_set = NULL;

    session->intersection_op = GNUNET_SET_prepare (&session->peer,
                                                   &session->session_id,
                                                   NULL,
                                                   GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, UINT16_MAX),
                                                   GNUNET_SET_RESULT_REMOVED,
                                                   cb_intersection_element_removed,
                                                   session);

    GNUNET_SET_commit (session->intersection_op, session->intersection_set);
  }
  else {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _ ("Got client-responder-session with key %s but NO matching service-request-session set, queuing element for later use.\n"),
                GNUNET_h2s (&client_session->session_id));
    // no matching session exists yet, store the response
    // for later processing by handle_service_request()
  }
}


/**
 * Our client has finished sending us its multipart message.
 * 
 * @param session the service session context
 */
static void
client_request_complete_alice (struct ServiceSession * session)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _ ("Creating new channel for session with key %s.\n"),
              GNUNET_h2s (&session->session_id));
  session->channel = GNUNET_CADET_channel_create (my_cadet, session,
                                                 &session->peer,
                                                 GNUNET_APPLICATION_TYPE_SCALARPRODUCT,
                                                 GNUNET_CADET_OPTION_RELIABLE);
  if (NULL == session->channel) {
    session->response->client_notification_task =
            GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                      session);
    return;
  }
  session->intersection_listen = GNUNET_SET_listen (cfg,
                                                    GNUNET_SET_OPERATION_INTERSECTION,
                                                    &session->session_id,
                                                    cb_intersection_request_alice,
                                                    session);
  if (NULL == session->intersection_listen) {
    session->response->client_notification_task =
            GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                      session);
    return;
  }
  prepare_alices_computation_request (session);
}


static void
handle_client_message_multipart (void *cls,
                                 struct GNUNET_SERVER_Client *client,
                                 const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_SCALARPRODUCT_computation_message_multipart * msg = (const struct GNUNET_SCALARPRODUCT_computation_message_multipart *) message;
  struct ServiceSession * session;
  uint32_t contained_count;
  struct GNUNET_SCALARPRODUCT_Element * elements;
  uint32_t i;

  // only one concurrent session per client connection allowed, simplifies logics a lot...
  session = GNUNET_SERVER_client_get_user_context (client, struct ServiceSession);
  if (NULL == session) {
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  contained_count = ntohl (msg->element_count_contained);

  //sanity check: is the message as long as the message_count fields suggests?
  if ((ntohs (msg->header.size) != (sizeof (struct GNUNET_SCALARPRODUCT_computation_message_multipart) +contained_count * sizeof (struct GNUNET_SCALARPRODUCT_Element)))
      || (0 == contained_count) || (session->total < session->transferred_element_count + contained_count)) {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  session->transferred_element_count += contained_count;

  elements = (struct GNUNET_SCALARPRODUCT_Element *) & msg[1];
  for (i = 0; i < contained_count; i++) {
    struct GNUNET_SET_Element set_elem;
    struct GNUNET_SCALARPRODUCT_Element * elem;

    if (0 == ntohl (elements[i].value))
      continue;

    elem = GNUNET_new (struct GNUNET_SCALARPRODUCT_Element);
    memcpy (elem, &elements[i], sizeof (struct GNUNET_SCALARPRODUCT_Element));

    if (GNUNET_SYSERR == GNUNET_CONTAINER_multihashmap_put (session->intersected_elements,
                                                            &elem->key,
                                                            elem,
                                                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY)) {
      GNUNET_free (elem);
      continue;
    }
    set_elem.data = &elements[i].key;
    set_elem.size = htons (sizeof (elements[i].key));
    set_elem.type = htons (0); /* do we REALLY need this? */
    GNUNET_SET_add_element (session->intersection_set, &set_elem, NULL, NULL);
    session->used_elements_count++;
  }

  GNUNET_SERVER_receive_done (client, GNUNET_OK);

  if (session->total != session->transferred_element_count)
    // multipart msg
    return;

  if (ALICE == session->role)
    client_request_complete_alice (session);
  else
    client_request_complete_bob (session);
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
handle_client_message (void *cls,
                       struct GNUNET_SERVER_Client *client,
                       const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_SCALARPRODUCT_computation_message * msg = (const struct GNUNET_SCALARPRODUCT_computation_message *) message;
  struct ServiceSession * session;
  uint32_t contained_count;
  uint32_t total_count;
  uint32_t msg_type;
  struct GNUNET_SCALARPRODUCT_Element * elements;
  uint32_t i;

  // only one concurrent session per client connection allowed, simplifies logics a lot...
  session = GNUNET_SERVER_client_get_user_context (client, struct ServiceSession);
  if (NULL != session) {
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  msg_type = ntohs (msg->header.type);
  total_count = ntohl (msg->element_count_total);
  contained_count = ntohl (msg->element_count_contained);

  if ((GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_TO_ALICE == msg_type)
      && (!memcmp (&msg->peer, &me, sizeof (struct GNUNET_PeerIdentity)))) {
    //session with ourself makes no sense!
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  //sanity check: is the message as long as the message_count fields suggests?
  if ((ntohs (msg->header.size) != (sizeof (struct GNUNET_SCALARPRODUCT_computation_message) +contained_count * sizeof (struct GNUNET_SCALARPRODUCT_Element)))
      || (0 == total_count)) {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  // do we have a duplicate session here already?
  if (NULL != find_matching_session (from_client_tail,
                                     &msg->session_key,
                                     total_count, NULL)) {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("Duplicate session information received, can not create new session with key `%s'\n"),
                GNUNET_h2s (&msg->session_key));
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  session = GNUNET_new (struct ServiceSession);
  session->client_notification_task = GNUNET_SCHEDULER_NO_TASK;
  session->client = client;
  session->total = total_count;
  session->transferred_element_count = contained_count;
  // get our transaction key
  memcpy (&session->session_id, &msg->session_key, sizeof (struct GNUNET_HashCode));

  elements = (struct GNUNET_SCALARPRODUCT_Element *) & msg[1];
  session->intersected_elements = GNUNET_CONTAINER_multihashmap_create (session->total, GNUNET_NO);
  session->intersection_set = GNUNET_SET_create (cfg, GNUNET_SET_OPERATION_INTERSECTION);
  for (i = 0; i < contained_count; i++) {
    struct GNUNET_SET_Element set_elem;
    struct GNUNET_SCALARPRODUCT_Element * elem;

    if (0 == ntohl (elements[i].value))
      continue;

    elem = GNUNET_new (struct GNUNET_SCALARPRODUCT_Element);
    memcpy (elem, &elements[i], sizeof (struct GNUNET_SCALARPRODUCT_Element));

    if (GNUNET_SYSERR == GNUNET_CONTAINER_multihashmap_put (session->intersected_elements,
                                                            &elem->key,
                                                            elem,
                                                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY)) {
      GNUNET_free (elem);
      continue;
    }
    set_elem.data = &elements[i].key;
    set_elem.size = htons (sizeof (elements[i].key));
    set_elem.type = htons (0); /* do we REALLY need this? */
    GNUNET_SET_add_element (session->intersection_set, &set_elem, NULL, NULL);
    session->used_elements_count++;
  }

  if (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_TO_ALICE == msg_type) {
    session->role = ALICE;
    memcpy (&session->peer, &msg->peer, sizeof (struct GNUNET_PeerIdentity));
  }
  else {
    session->role = BOB;
  }

  GNUNET_CONTAINER_DLL_insert (from_client_head, from_client_tail, session);
  GNUNET_SERVER_client_set_user_context (client, session);
  GNUNET_SERVER_receive_done (client, GNUNET_YES);

  if (session->total != session->transferred_element_count)
    // multipart msg
    return;

  if (ALICE == session->role)
    client_request_complete_alice (session);
  else
    client_request_complete_bob (session);
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
cb_channel_incoming (void *cls,
                          struct GNUNET_CADET_Channel *channel,
                          const struct GNUNET_PeerIdentity *initiator,
                          uint32_t port, enum GNUNET_CADET_ChannelOption options)
{
  struct ServiceSession * c = GNUNET_new (struct ServiceSession);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _ ("New incoming channel from peer %s.\n"),
              GNUNET_i2s (initiator));

  c->peer = *initiator;
  c->channel = channel;
  c->role = BOB;
  return c;
}


/**
 * Function called whenever a channel is destroyed.  Should clean up
 * any associated state.
 *
 * It must NOT call GNUNET_CADET_channel_destroy on the channel.
 *
 * @param cls closure (set from GNUNET_CADET_connect)
 * @param channel connection to the other end (henceforth invalid)
 * @param channel_ctx place where local state associated
 *                   with the channel is stored
 */
static void
cb_channel_destruction (void *cls,
                             const struct GNUNET_CADET_Channel *channel,
                             void *channel_ctx)
{
  struct ServiceSession * session = channel_ctx;
  struct ServiceSession * client_session;
  struct ServiceSession * curr;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _ ("Peer disconnected, terminating session %s with peer (%s)\n"),
              GNUNET_h2s (&session->session_id),
              GNUNET_i2s (&session->peer));
  if (ALICE == session->role) {
    // as we have only one peer connected in each session, just remove the session

    if ((0/*//TODO: only for complete session*/) && (!do_shutdown)) {
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
                                            &session->session_id,
                                            session->total, NULL);
    free_session_variables (session);
    GNUNET_free (session);

    // the client has to check if it was waiting for a result
    // or if it was a responder, no point in adding more statefulness
    if (client_session && (!do_shutdown)) {
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
  gcry_mpi_t r[session->used_elements_count];
  gcry_mpi_t r_prime[session->used_elements_count];
  gcry_mpi_t s;
  gcry_mpi_t s_prime;
  unsigned int i;

  count = session->used_elements_count;
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
  t = compute_square_sum (session->sorted_elements, count);

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
  for (i = 0; i < count; i++) {
    gcry_mpi_release (session->sorted_elements[i]);
    gcry_mpi_release (r[i]);
    gcry_mpi_release (r_prime[i]);
  }
  GNUNET_free (session->a_head);
  session->a_head = NULL;
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
 * @param cls closure (set from #GNUNET_CADET_connect)
 * @param channel connection to the other end
 * @param channel_ctx place to store local state associated with the channel
 * @param message the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_alices_cyrptodata_message_multipart (void *cls,
                                            struct GNUNET_CADET_Channel * channel,
                                            void **channel_ctx,
                                            const struct GNUNET_MessageHeader * message)
{
  struct ServiceSession * session;
  const struct GNUNET_SCALARPRODUCT_multipart_message * msg = (const struct GNUNET_SCALARPRODUCT_multipart_message *) message;
  struct GNUNET_CRYPTO_PaillierCiphertext *payload;
  uint32_t contained_elements;
  uint32_t msg_length;

  // are we in the correct state?
  session = (struct ServiceSession *) * channel_ctx;
  //we are not bob
  if ((NULL == session->e_a) || //or we did not expect this message yet 
      (session->used_elements_count == session->transferred_element_count)) { //we are not expecting multipart messages
    goto except;
  }
  // shorter than minimum?
  if (ntohs (msg->header.size) <= sizeof (struct GNUNET_SCALARPRODUCT_multipart_message)) {
    goto except;
  }
  contained_elements = ntohl (msg->contained_element_count);
  msg_length = sizeof (struct GNUNET_SCALARPRODUCT_multipart_message)
          +contained_elements * sizeof (struct GNUNET_CRYPTO_PaillierCiphertext);
  //sanity check
  if ((ntohs (msg->header.size) != msg_length)
      || (session->used_elements_count < contained_elements + session->transferred_element_count)
      || (0 == contained_elements)) {
    goto except;
  }
  payload = (struct GNUNET_CRYPTO_PaillierCiphertext *) &msg[1];
  // Convert each vector element to MPI_value
  memcpy (&session->e_a[session->transferred_element_count], payload,
          sizeof (struct GNUNET_CRYPTO_PaillierCiphertext) * contained_elements);

  session->transferred_element_count += contained_elements;

  if (contained_elements == session->used_elements_count) {
    // single part finished
    if (NULL == session->intersection_op)
      // intersection has already finished, so we can proceed
      compute_service_response (session);
  }

  return GNUNET_OK;
except:
  session->channel = NULL;
  // and notify our client-session that we could not complete the session
  free_session_variables (session);
  if (NULL != session->client){
    //Alice
    session->client_notification_task =
          GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                    session);
  }
  else {
    //Bob
    if (NULL != session->response)
    session->response->client_notification_task =
          GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                    session->response);
    GNUNET_CONTAINER_DLL_remove (from_service_head, from_service_tail, session);
    GNUNET_free(session);
  }
  return GNUNET_SYSERR;
}


/**
 * Handle a request from another service to calculate a scalarproduct with us.
 *
 * @param cls closure (set from #GNUNET_CADET_connect)
 * @param channel connection to the other end
 * @param channel_ctx place to store local state associated with the channel
 * @param message the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_alices_cyrptodata_message (void *cls,
                                  struct GNUNET_CADET_Channel * channel,
                                  void **channel_ctx,
                                  const struct GNUNET_MessageHeader * message)
{
  struct ServiceSession * session;
  const struct GNUNET_SCALARPRODUCT_alices_cryptodata_message * msg = (const struct GNUNET_SCALARPRODUCT_alices_cryptodata_message *) message;
  struct GNUNET_CRYPTO_PaillierCiphertext *payload;
  uint32_t contained_elements = 0;
  uint32_t msg_length;

  session = (struct ServiceSession *) * channel_ctx;
  //we are not bob
  if ((BOB != session->role)
      //we are expecting multipart messages instead
      || (NULL != session->e_a)
      //or we did not expect this message yet
      || //intersection OP has not yet finished
      !((NULL != session->intersection_op)
        //intersection OP done
        || (session->response->sorted_elements)
        )) {
    goto invalid_msg;
  }

  // shorter than minimum?
  if (ntohs (msg->header.size) <= sizeof (struct GNUNET_SCALARPRODUCT_multipart_message)) {
    goto invalid_msg;
  }

  contained_elements = ntohl (msg->contained_element_count);
  msg_length = sizeof (struct GNUNET_SCALARPRODUCT_alices_cryptodata_message)
          +contained_elements * sizeof (struct GNUNET_CRYPTO_PaillierCiphertext);

  //sanity check: is the message as long as the message_count fields suggests?
  if ((ntohs (msg->header.size) != msg_length) ||
      (session->used_elements_count < session->transferred_element_count + contained_elements) ||
      (0 == contained_elements)) {
    goto invalid_msg;
  }

  session->transferred_element_count = contained_elements;
  payload = (struct GNUNET_CRYPTO_PaillierCiphertext*) &msg[1];

  session->e_a = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_PaillierCiphertext) * session->used_elements_count);
  memcpy (&session->e_a[0], payload, contained_elements * sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
  if (contained_elements == session->used_elements_count) {
    // single part finished
    if (NULL == session->intersection_op)
      // intersection has already finished, so we can proceed
      compute_service_response (session);
  }
  return GNUNET_OK;
invalid_msg:
  GNUNET_break_op (0);
  session->channel = NULL;
  // and notify our client-session that we could not complete the session
  free_session_variables (session);
  if (NULL != session->client){
    //Alice
    session->client_notification_task =
          GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                    session);
  }
  else {
    //Bob
    if (NULL != session->response)
    session->response->client_notification_task =
          GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                    session->response);
    GNUNET_CONTAINER_DLL_remove (from_service_head, from_service_tail, session);
    GNUNET_free(session);
  }
  return GNUNET_SYSERR;
}


/**
 * Handle a request from another service to calculate a scalarproduct with us.
 *
 * @param cls closure (set from #GNUNET_CADET_connect)
 * @param channel connection to the other end
 * @param channel_ctx place to store local state associated with the channel
 * @param message the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_alices_computation_request (void *cls,
                        struct GNUNET_CADET_Channel * channel,
                        void **channel_ctx,
                        const struct GNUNET_MessageHeader * message)
{
  struct ServiceSession * session;
  struct ServiceSession * client_session;
  const struct GNUNET_SCALARPRODUCT_service_request * msg = (const struct GNUNET_SCALARPRODUCT_service_request *) message;
  uint32_t total_elements;

  session = (struct ServiceSession *) * channel_ctx;
  if (session->total != 0) {
    // must be a fresh session
    goto invalid_msg;
  }
  // Check if message was sent by me, which would be bad!
  if (!memcmp (&session->peer, &me, sizeof (struct GNUNET_PeerIdentity))) {
    GNUNET_free (session);
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  // shorter than expected?
  if (ntohs (msg->header.size) != sizeof (struct GNUNET_SCALARPRODUCT_service_request)) {
    GNUNET_free (session);
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  total_elements = ntohl (msg->total_element_count);

  //sanity check: is the message as long as the message_count fields suggests?
  if (1 > total_elements) {
    GNUNET_free (session);
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (find_matching_session (from_service_tail,
                             &msg->session_id,
                             total_elements,
                             NULL)) {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Got message with duplicate session key (`%s'), ignoring service request.\n"),
                (const char *) &(msg->session_id));
    GNUNET_free (session);
    return GNUNET_SYSERR;
  }

  session->total = total_elements;
  session->channel = channel;

  // session key
  memcpy (&session->session_id, &msg->session_id, sizeof (struct GNUNET_HashCode));

  // public key
  session->remote_pubkey = GNUNET_new (struct GNUNET_CRYPTO_PaillierPublicKey);
  memcpy (session->remote_pubkey, &msg->public_key, sizeof (struct GNUNET_CRYPTO_PaillierPublicKey));

  //check if service queue contains a matching request
  client_session = find_matching_session (from_client_tail,
                                          &session->session_id,
                                          session->total, NULL);

  GNUNET_CONTAINER_DLL_insert (from_service_head, from_service_tail, session);

  if ((NULL != client_session)
      && (client_session->transferred_element_count == client_session->total)) {

    GNUNET_log (GNUNET_ERROR_TYPE_INFO, _ ("Got session with key %s and a matching element set, processing.\n"), GNUNET_h2s (&session->session_id));

    session->response = client_session;
    session->intersected_elements = client_session->intersected_elements;
    client_session->intersected_elements = NULL;
    session->intersection_set = client_session->intersection_set;
    client_session->intersection_set = NULL;

    session->intersection_op = GNUNET_SET_prepare (&session->peer,
                                                   &session->session_id,
                                                   NULL,
                                                   GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, UINT16_MAX),
                                                   GNUNET_SET_RESULT_REMOVED,
                                                   cb_intersection_element_removed,
                                                   session);

    GNUNET_SET_commit (session->intersection_op, session->intersection_set);
  }
  else {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, _ ("Got session with key %s without a matching element set, queueing.\n"), GNUNET_h2s (&session->session_id));
  }

  return GNUNET_OK;
invalid_msg:
  GNUNET_break_op (0);
  session->channel = NULL;
  // and notify our client-session that we could not complete the session
  free_session_variables (session);
  if (NULL != session->client){
    //Alice
    session->client_notification_task =
          GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                    session);
  }
  else {
    //Bob
    if (NULL != session->response)
    session->response->client_notification_task =
          GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                    session->response);
    GNUNET_CONTAINER_DLL_remove (from_service_head, from_service_tail, session);
    GNUNET_free(session);
  }
  return GNUNET_SYSERR;
}


/**
 * Handle a multipart chunk of a response we got from another service we wanted to calculate a scalarproduct with.
 *
 * @param cls closure (set from #GNUNET_CADET_connect)
 * @param channel connection to the other end
 * @param channel_ctx place to store local state associated with the channel
 * @param message the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_bobs_cryptodata_multipart (void *cls,
                                   struct GNUNET_CADET_Channel * channel,
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
  if ((ALICE != session->role) || (NULL == session->sorted_elements)) {
    goto invalid_msg;
  }
  msg_size = ntohs (msg->header.size);
  required_size = sizeof (struct GNUNET_SCALARPRODUCT_multipart_message)
          + 2 * sizeof (struct GNUNET_CRYPTO_PaillierCiphertext);
  // shorter than minimum?
  if (required_size > msg_size) {
    goto invalid_msg;
  }
  contained = ntohl (msg->contained_element_count);
  required_size = sizeof (struct GNUNET_SCALARPRODUCT_multipart_message)
          + 2 * contained * sizeof (struct GNUNET_CRYPTO_PaillierCiphertext);
  //sanity check: is the message as long as the message_count fields suggests?
  if ((required_size != msg_size) || (session->used_elements_count < session->transferred_element_count + contained)) {
    goto invalid_msg;
  }
  payload = (struct GNUNET_CRYPTO_PaillierCiphertext *) &msg[1];
  // Convert each k[][perm] to its MPI_value
  for (i = 0; i < contained; i++) {
    memcpy (&session->r[session->transferred_element_count + i], &payload[2 * i], sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
    memcpy (&session->r_prime[session->transferred_element_count + i], &payload[2 * i], sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
  }
  session->transferred_element_count += contained;
  if (session->transferred_element_count != session->used_elements_count)
    return GNUNET_OK;
  session->product = compute_scalar_product (session); //never NULL

invalid_msg:
  GNUNET_break_op (NULL != session->product);
  session->channel = NULL;
  // send message with product to client
  if (NULL != session->client){
    //Alice
    session->client_notification_task =
          GNUNET_SCHEDULER_add_now (&prepare_client_response,
                                    session);
  }
  else {
    //Bob
    if (NULL != session->response)
    session->response->client_notification_task =
          GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                    session->response);
    GNUNET_CONTAINER_DLL_remove (from_service_head, from_service_tail, session);
    free_session_variables (session);
    GNUNET_free(session);
  }
  // the channel has done its job, terminate our connection and the channel
  // the peer will be notified that the channel was destroyed via channel_destruction_handler
  // just close the connection, as recommended by Christian
  return GNUNET_SYSERR;
}


/**
 * Handle a response we got from another service we wanted to calculate a scalarproduct with.
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
                         struct GNUNET_CADET_Channel * channel,
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
  if (0 /*//TODO: correct state*/) {
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
  if ((msg_size != required_size) || (session->used_elements_count < contained)) {
    goto invalid_msg;
  }
  session->transferred_element_count = contained;
  //convert s
  payload = (struct GNUNET_CRYPTO_PaillierCiphertext *) &msg[1];

  session->s = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
  session->s_prime = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
  memcpy (session->s, &payload[0], sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
  memcpy (session->s_prime, &payload[1], sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));

  session->r = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_PaillierCiphertext) * session->used_elements_count);
  session->r_prime = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_PaillierCiphertext) * session->used_elements_count);

  // Convert each k[][perm] to its MPI_value
  for (i = 0; i < contained; i++) {
    memcpy (&session->r[i], &payload[2 + 2 * i], sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
    memcpy (&session->r_prime[i], &payload[3 + 2 * i], sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
  }
  if (session->transferred_element_count != session->used_elements_count)
    return GNUNET_OK; //wait for the other multipart chunks
  session->product = compute_scalar_product (session); //never NULL

invalid_msg:
  GNUNET_break_op (NULL != session->product);
  session->channel = NULL;
  // send message with product to client
  if (NULL != session->client){
    //Alice
    session->client_notification_task =
          GNUNET_SCHEDULER_add_now (&prepare_client_response,
                                    session);
  }
  else {
    //Bob
    if (NULL != session->response)
    session->response->client_notification_task =
          GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                    session->response);
    GNUNET_CONTAINER_DLL_remove (from_service_head, from_service_tail, session);
    free_session_variables (session);
    GNUNET_free(session);
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
    if ((0/*//TODO: not finalized*/) && (NULL != session->channel)) {
      GNUNET_CADET_channel_destroy (session->channel);
      session->channel = NULL;
    }
    if (GNUNET_SCHEDULER_NO_TASK != session->client_notification_task) {
      GNUNET_SCHEDULER_cancel (session->client_notification_task);
      session->client_notification_task = GNUNET_SCHEDULER_NO_TASK;
    }
    if (NULL != session->client) {
      GNUNET_SERVER_client_disconnect (session->client);
      session->client = NULL;
    }
  }
  for (session = from_service_head; NULL != session; session = session->next)
    if (NULL != session->channel) {
      GNUNET_CADET_channel_destroy (session->channel);
      session->channel = NULL;
    }

  if (my_cadet) {
    GNUNET_CADET_disconnect (my_cadet);
    my_cadet = NULL;
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
    {&handle_client_message, NULL, GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_TO_ALICE, 0},
    {&handle_client_message, NULL, GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_TO_BOB, 0},
    {&handle_client_message_multipart, NULL, GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_MUTLIPART, 0},
    {NULL, NULL, 0, 0}
  };
  static const struct GNUNET_CADET_MessageHandler cadet_handlers[] = {
    { &handle_alices_computation_request, GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ALICE_CRYPTODATA, 0},
    { &handle_alices_cyrptodata_message, GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ALICE_CRYPTODATA, 0},
    { &handle_alices_cyrptodata_message_multipart, GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ALICE_CRYPTODATA_MULTIPART, 0},
    { &handle_bobs_cryptodata_message, GNUNET_MESSAGE_TYPE_SCALARPRODUCT_BOB_CRYPTODATA, 0},
    { &handle_bobs_cryptodata_multipart, GNUNET_MESSAGE_TYPE_SCALARPRODUCT_BOB_CRYPTODATA_MULTIPART, 0},
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
  my_cadet = GNUNET_CADET_connect (c, NULL,
                                 &cb_channel_incoming,
                                 &cb_channel_destruction,
                                 cadet_handlers, ports);
  if (!my_cadet) {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _ ("Connect to CADET failed\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _ ("CADET initialized\n"));
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
