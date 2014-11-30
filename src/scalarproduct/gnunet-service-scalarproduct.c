/*
     This file is part of GNUnet.
     (C) 2013, 2014 Christian Grothoff (and other contributing authors)

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

#define LOG(kind,...) GNUNET_log_from (kind, "scalarproduct", __VA_ARGS__)


/**
 * Maximum count of elements we can put into a multipart message
 */
#define MULTIPART_ELEMENT_CAPACITY ((GNUNET_SERVER_MAX_MESSAGE_SIZE - 1 - sizeof (struct MultipartMessage)) / sizeof (struct GNUNET_CRYPTO_PaillierCiphertext))


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Message type passed from requesting service Alice to responding
 * service Bob to initiate a request and make Bob participate in our
 * protocol
 */
struct ServiceRequestMessage
{
  /**
   * GNUNET message header
   */
  struct GNUNET_MessageHeader header;

  /**
   * the transaction/session key used to identify a session
   */
  struct GNUNET_HashCode session_id;

  /**
   * Alice's public key
   */
  struct GNUNET_CRYPTO_PaillierPublicKey public_key;

};


/**
 * FIXME.
 */
struct AliceCryptodataMessage
{
  /**
   * GNUNET message header
   */
  struct GNUNET_MessageHeader header;

  /**
   * how many elements we appended to this message
   */
  uint32_t contained_element_count GNUNET_PACKED;

  /**
   * struct GNUNET_CRYPTO_PaillierCiphertext[contained_element_count]
   */
};


/**
 * Multipart Message type passed between to supply additional elements
 * for the peer
 */
struct MultipartMessage
{
  /**
   * GNUNET message header
   */
  struct GNUNET_MessageHeader header;

  /**
   * how many elements we supply within this message
   */
  uint32_t contained_element_count GNUNET_PACKED;

  // struct GNUNET_CRYPTO_PaillierCiphertext[multipart_element_count]
};


/**
 * Message type passed from responding service Bob to responding service Alice
 * to complete a request and allow Alice to compute the result
 */
struct ServiceResponseMessage
{
  /**
   * GNUNET message header
   */
  struct GNUNET_MessageHeader header;

  /**
   * how many elements the session input had
   */
  uint32_t total_element_count GNUNET_PACKED;

  /**
   * how many elements were included after the mask was applied
   * including all multipart msgs.
   */
  uint32_t used_element_count GNUNET_PACKED;

  /**
   * how many elements this individual message delivers
   */
  uint32_t contained_element_count GNUNET_PACKED;

  /**
   * the transaction/session key used to identify a session
   */
  struct GNUNET_HashCode key;

  /**
   * followed by s | s' | k[i][perm]
   */
};

GNUNET_NETWORK_STRUCT_END


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
  struct SortedValue *next;

  /**
   * Sorted Values are kept in a DLL
   */
  struct SortedValue *prev;

  /**
   * The element's id+integer-value
   */
  struct GNUNET_SCALARPRODUCT_Element *elem;

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
  struct GNUNET_SERVER_Client *client;

  /**
   * The message to send
   */
  struct GNUNET_MessageHeader *msg;

  /**
   * all non-0-value'd elements transmitted to us
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
   * Public key of the remote service, only used by Bob
   */
  struct GNUNET_CRYPTO_PaillierPublicKey remote_pubkey;

  /**
   * DLL for sorting elements after intersection
   */
  struct SortedValue *a_head;

  /**
   * a(Alice)
   */
  struct SortedValue *a_tail;

  /**
   * a(Alice)
   */
  gcry_mpi_t *sorted_elements;

  /**
   * E(ai)(Bob) after applying the mask
   */
  struct GNUNET_CRYPTO_PaillierCiphertext *e_a;

  /**
   * Bob's permutation p of R
   */
  struct GNUNET_CRYPTO_PaillierCiphertext *r;

  /**
   * Bob's permutation q of R
   */
  struct GNUNET_CRYPTO_PaillierCiphertext *r_prime;

  /**
   * Bob's s
   */
  struct GNUNET_CRYPTO_PaillierCiphertext *s;

  /**
   * Bob's s'
   */
  struct GNUNET_CRYPTO_PaillierCiphertext *s_prime;

  /**
   * Bob's matching response session from the client
   */
  struct ServiceSession *response;

  /**
   * My transmit handle for the current message to a Alice/Bob
   */
  struct GNUNET_CADET_TransmitHandle *service_transmit_handle;

  /**
   * My transmit handle for the current message to the client
   */
  struct GNUNET_SERVER_TransmitHandle *client_transmit_handle;

  /**
   * channel-handle associated with our cadet handle
   */
  struct GNUNET_CADET_Channel *channel;

  /**
   * Handle to a task that sends a msg to the our client
   */
  GNUNET_SCHEDULER_TaskIdentifier client_notification_task;

  /**
   * The computed scalar
   */
  gcry_mpi_t product;

  /**
   * how many elements we were supplied with from the client
   */
  uint32_t total;

  /**
   * how many elements actually are used for the scalar product
   */
  uint32_t used_element_count;

  /**
   * already transferred elements (sent/received) for multipart messages, less or equal than @e used_element_count for
   */
  uint32_t transferred_element_count;

  /**
   * Is this session active (#GNUNET_YES), Concluded (#GNUNET_NO), or had an error (#GNUNET_SYSERR)
   */
  int32_t active;

  /**
   * the role this peer has
   */
  enum PeerRole role;

};


/**
 * GNUnet configuration handle
 */
static const struct GNUNET_CONFIGURATION_Handle * cfg;

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
static struct ServiceSession *from_client_head;

/**
 * Tail of our double linked list for client-requests sent to us.
 * for all of these elements we calculate a scalar product with a remote peer
 * split between service->service and client->service for simplicity
 */
static struct ServiceSession *from_client_tail;

/**
 * Head of our double linked list for service-requests sent to us.
 * for all of these elements we help the requesting service in calculating a scalar product
 * split between service->service and client->service for simplicity
 */
static struct ServiceSession *from_service_head;

/**
 * Tail of our double linked list for service-requests sent to us.
 * for all of these elements we help the requesting service in calculating a scalar product
 * split between service->service and client->service for simplicity
 */
static struct ServiceSession *from_service_tail;

/**
 * Certain events (callbacks for server & cadet operations) must not be queued after shutdown.
 */
static int do_shutdown;


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
 * Send a multi part chunk of a service response from Bob to Alice.
 * This element only contains the two permutations of R, R'.
 *
 * @param cls the associated service session
 */
static void
prepare_bobs_cryptodata_message_multipart (void *cls);


/**
 * computes the square sum over a vector of a given length.
 *
 * @param vector the vector to encrypt
 * @param length the length of the vector
 * @return an MPI value containing the calculated sum, never NULL
 */
static gcry_mpi_t
compute_square_sum (gcry_mpi_t *vector,
                    uint32_t length)
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
 * Safely frees ALL memory areas referenced by a session.
 *
 * @param session - the session to free elements from
 */
static void
free_session_variables (struct ServiceSession *s)
{
  while (NULL != s->a_head)
  {
    struct SortedValue * e = s->a_head;

    GNUNET_free (e->elem);
    gcry_mpi_release (e->val);
    GNUNET_CONTAINER_DLL_remove (s->a_head, s->a_tail, e);
    GNUNET_free (e);
  }
  if (s->e_a)
  {
    GNUNET_free (s->e_a);
    s->e_a = NULL;
  }
  if (s->sorted_elements)
  {
    GNUNET_free (s->sorted_elements);
    s->sorted_elements = NULL;
  }
  if (s->intersected_elements)
  {
    GNUNET_CONTAINER_multihashmap_destroy (s->intersected_elements);
    //elements are freed independently in session->a_head/tail
    s->intersected_elements = NULL;
  }
  if (s->intersection_listen)
  {
    GNUNET_SET_listen_cancel (s->intersection_listen);
    s->intersection_listen = NULL;
  }
  if (s->intersection_op)
  {
    GNUNET_SET_operation_cancel (s->intersection_op);
    s->intersection_op = NULL;
  }
  if (s->intersection_set)
  {
    GNUNET_SET_destroy (s->intersection_set);
    s->intersection_set = NULL;
  }
  if (s->msg)
  {
    GNUNET_free (s->msg);
    s->msg = NULL;
  }
  if (s->r)
  {
    GNUNET_free (s->r);
    s->r = NULL;
  }
  if (s->r_prime)
  {
    GNUNET_free (s->r_prime);
    s->r_prime = NULL;
  }
  if (s->s)
  {
    GNUNET_free (s->s);
    s->s = NULL;
  }
  if (s->s_prime)
  {
    GNUNET_free (s->s_prime);
    s->s_prime = NULL;
  }
  if (s->product)
  {
    gcry_mpi_release (s->product);
    s->product = NULL;
  }
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
cb_transfer_message (void *cls,
                     size_t size,
                     void *buf)
{
  struct ServiceSession * s = cls;
  uint16_t type;

  GNUNET_assert (buf);
  if (ntohs (s->msg->size) != size)
  {
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
    free_session_variables (s);
    break;

  case GNUNET_MESSAGE_TYPE_SCALARPRODUCT_SESSION_INITIALIZATION:
    s->service_transmit_handle = NULL;
    break;

  case GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ALICE_CRYPTODATA:
  case GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ALICE_CRYPTODATA_MULTIPART:
    s->service_transmit_handle = NULL;
    if (s->used_element_count != s->transferred_element_count)
      prepare_alices_cyrptodata_message_multipart (s);
    else
      s->channel = NULL;
    break;

  case GNUNET_MESSAGE_TYPE_SCALARPRODUCT_BOB_CRYPTODATA:
  case GNUNET_MESSAGE_TYPE_SCALARPRODUCT_BOB_CRYPTODATA_MULTIPART:
    s->service_transmit_handle = NULL;
    if (s->used_element_count != s->transferred_element_count)
      prepare_bobs_cryptodata_message_multipart (s);
    else
      s->channel = NULL;
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
 * @param peerid - a pointer to the peer ID of the associated peer, NULL to ignore
 * @return a pointer to a matching session, or NULL
 */
static struct ServiceSession *
find_matching_session (struct ServiceSession * tail,
                       const struct GNUNET_HashCode * key,
                       const struct GNUNET_PeerIdentity * peerid)
{
  struct ServiceSession * s;

  for (s = tail; NULL != s; s = s->prev)
  {
    // if the key matches, and the element_count is same
    if (0 == memcmp (&s->session_id, key, sizeof (struct GNUNET_HashCode)))
    {
      // if peerid is NULL OR same as the peer Id in the queued request
      if ((NULL == peerid)
          || (0 == memcmp (&s->peer, peerid, sizeof (struct GNUNET_PeerIdentity))))
        // matches and is not an already terminated session
        return s;
    }
  }

  return NULL;
}


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
cb_client_disconnect (void *cls,
                      struct GNUNET_SERVER_Client *client)
{
  struct ServiceSession *s;

  if (NULL == client)
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client %p disconnected from us.\n",
              client);
  s = GNUNET_SERVER_client_get_user_context (client, struct ServiceSession);
  if (NULL == s)
    return;
  GNUNET_CONTAINER_DLL_remove (from_client_head,
                               from_client_tail,
                               s);
  if (NULL != s->service_transmit_handle)
  {
    GNUNET_CADET_notify_transmit_ready_cancel (s->service_transmit_handle);
    s->service_transmit_handle = NULL;
  }
  if (NULL != s->channel)
  {
    GNUNET_CADET_channel_destroy (s->channel);
    s->channel = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != s->client_notification_task)
  {
    GNUNET_SCHEDULER_cancel (s->client_notification_task);
    s->client_notification_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != s->client_transmit_handle)
  {
    GNUNET_SERVER_notify_transmit_ready_cancel (s->client_transmit_handle);
    s->client_transmit_handle = NULL;
  }
  free_session_variables (s);
  GNUNET_free (s);
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
  struct ServiceSession * s = cls;
  struct ClientResponseMessage *msg;

  s->client_notification_task = GNUNET_SCHEDULER_NO_TASK;

  msg = GNUNET_new (struct ClientResponseMessage);
  msg->header.size = htons (sizeof (struct ClientResponseMessage));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_RESULT);
  // signal error if not signalized, positive result-range field but zero length.
  msg->product_length = htonl (0);
  msg->status = htonl(s->active);
  s->msg = &msg->header;

  //transmit this message to our client
  s->client_transmit_handle
    = GNUNET_SERVER_notify_transmit_ready (s->client,
                                           sizeof (struct ClientResponseMessage),
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           &cb_transfer_message,
                                           s);

  // if we could not even queue our request, something is wrong
  if (NULL == s->client_transmit_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Could not send message to client (%p)!\n"),
                s->client);
    GNUNET_SERVER_client_disconnect (s->client);
    free_session_variables(s);
    GNUNET_CONTAINER_DLL_remove (from_client_head,
                                 from_client_tail,
                                 s);
    GNUNET_free(s);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Sending session-end notification to client (%p) for session %s\n"),
              s->client,
              GNUNET_h2s (&s->session_id));
}


/**
 * Executed by Alice, fills in a service-request message and sends it to the given peer
 *
 * @param cls the session associated with this request
 */
static void
prepare_alices_cyrptodata_message (void *cls)
{
  struct ServiceSession * s = cls;
  struct AliceCryptodataMessage * msg;
  struct GNUNET_CRYPTO_PaillierCiphertext * payload;
  unsigned int i;
  uint32_t msg_length;
  gcry_mpi_t a;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Successfully created new channel to peer (%s)!\n",
              GNUNET_i2s (&s->peer));

  msg_length = sizeof (struct AliceCryptodataMessage)
          + s->used_element_count * sizeof (struct GNUNET_CRYPTO_PaillierCiphertext);

  if (GNUNET_SERVER_MAX_MESSAGE_SIZE > msg_length)
  {
    s->transferred_element_count = s->used_element_count;
  }
  else
  {
    //create a multipart msg, first we calculate a new msg size for the head msg
    s->transferred_element_count = (GNUNET_SERVER_MAX_MESSAGE_SIZE - 1 - sizeof (struct AliceCryptodataMessage))
            / sizeof (struct GNUNET_CRYPTO_PaillierCiphertext);
    msg_length = sizeof (struct AliceCryptodataMessage)
            +s->transferred_element_count * sizeof (struct GNUNET_CRYPTO_PaillierCiphertext);
  }

  msg = GNUNET_malloc (msg_length);
  msg->header.size = htons (msg_length);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ALICE_CRYPTODATA);
  msg->contained_element_count = htonl (s->transferred_element_count);

  // fill in the payload
  payload = (struct GNUNET_CRYPTO_PaillierCiphertext *) &msg[1];

  // now copy over the sorted element vector
  a = gcry_mpi_new (0);
  for (i = 0; i < s->transferred_element_count; i++)
  {
    gcry_mpi_add (a, s->sorted_elements[i], my_offset);
    GNUNET_CRYPTO_paillier_encrypt (&my_pubkey, a, 3, &payload[i]);
  }
  gcry_mpi_release (a);

  s->msg = (struct GNUNET_MessageHeader *) msg;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmitting service request.\n");

  //transmit via cadet messaging
  s->service_transmit_handle = GNUNET_CADET_notify_transmit_ready (s->channel,
                                                                   GNUNET_YES,
                                                                   GNUNET_TIME_UNIT_FOREVER_REL,
                                                                   msg_length,
                                                                   &cb_transfer_message,
                                                                   s);
  if (NULL == s->service_transmit_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Could not send message to channel!\n"));
    GNUNET_free (msg);
    s->msg = NULL;
    s->active = GNUNET_SYSERR;
    s->client_notification_task =
            GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                      s);
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
  struct ServiceSession * s = cls;
  struct GNUNET_CRYPTO_PaillierCiphertext * payload;
  struct MultipartMessage * msg;
  unsigned int i;
  unsigned int j;
  uint32_t msg_length;
  uint32_t todo_count;

  msg_length = sizeof (struct MultipartMessage);
  todo_count = s->used_element_count - s->transferred_element_count;

  if (todo_count > MULTIPART_ELEMENT_CAPACITY / 2)
    // send the currently possible maximum chunk, we always transfer both permutations
    todo_count = MULTIPART_ELEMENT_CAPACITY / 2;

  msg_length += todo_count * sizeof (struct GNUNET_CRYPTO_PaillierCiphertext) * 2;
  msg = GNUNET_malloc (msg_length);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ALICE_CRYPTODATA_MULTIPART);
  msg->header.size = htons (msg_length);
  msg->contained_element_count = htonl (todo_count);

  payload = (struct GNUNET_CRYPTO_PaillierCiphertext *) &msg[1];
  for (i = s->transferred_element_count, j = 0; i < s->transferred_element_count + todo_count; i++)
  {
    //r[i][p] and r[i][q]
    memcpy (&payload[j++],
            &s->r[i],
            sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
    memcpy (&payload[j++],
            &s->r_prime[i],
            sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
  }
  s->transferred_element_count += todo_count;
  s->msg = (struct GNUNET_MessageHeader *) msg;
  s->service_transmit_handle =
          GNUNET_CADET_notify_transmit_ready (s->channel,
                                             GNUNET_YES,
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             msg_length,
                                             &cb_transfer_message,
                                             s);
  if (NULL == s->service_transmit_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Could not send service-response message via cadet!)\n"));

    GNUNET_free (msg);
    s->msg = NULL;
    GNUNET_CADET_channel_destroy(s->channel);
    s->response->active = GNUNET_SYSERR;

    GNUNET_CONTAINER_DLL_remove (from_service_head,
                                 from_service_tail,
                                 s);

    s->response->client_notification_task
      = GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                  s->response);
    free_session_variables(s);
    GNUNET_free(s);
    return;
  }
  if (s->transferred_element_count == s->used_element_count)
  {
    // final part
    s->active = GNUNET_NO;
    GNUNET_free (s->r_prime);
    GNUNET_free (s->r);
    s->r_prime = NULL;
    s->r = NULL;
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
  struct ServiceSession * s = cls;
  struct ServiceResponseMessage *msg;
  uint32_t msg_length = 0;
  struct GNUNET_CRYPTO_PaillierCiphertext * payload;
  int i;

  msg_length = sizeof (struct ServiceResponseMessage)
          + 2 * sizeof (struct GNUNET_CRYPTO_PaillierCiphertext); // s, stick

  if (GNUNET_SERVER_MAX_MESSAGE_SIZE >
      msg_length + 2 * s->used_element_count * sizeof (struct GNUNET_CRYPTO_PaillierCiphertext))
  { //r, r'
    msg_length += 2 * s->used_element_count * sizeof (struct GNUNET_CRYPTO_PaillierCiphertext);
    s->transferred_element_count = s->used_element_count;
  }
  else
    s->transferred_element_count = (GNUNET_SERVER_MAX_MESSAGE_SIZE - 1 - msg_length) /
    (sizeof (struct GNUNET_CRYPTO_PaillierCiphertext) * 2);

  msg = GNUNET_malloc (msg_length);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_BOB_CRYPTODATA);
  msg->header.size = htons (msg_length);
  msg->total_element_count = htonl (s->total);
  msg->used_element_count = htonl (s->used_element_count);
  msg->contained_element_count = htonl (s->transferred_element_count);
  memcpy (&msg->key, &s->session_id, sizeof (struct GNUNET_HashCode));

  payload = (struct GNUNET_CRYPTO_PaillierCiphertext *) &msg[1];
  memcpy (&payload[0], s->s, sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
  memcpy (&payload[1], s->s_prime, sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
  GNUNET_free (s->s_prime);
  s->s_prime = NULL;
  GNUNET_free (s->s);
  s->s = NULL;

  payload = &payload[2];
  // convert k[][]
  for (i = 0; i < s->transferred_element_count; i++)
  {
    //k[i][p] and k[i][q]
    memcpy (&payload[i * 2],
            &s->r[i],
            sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
    memcpy (&payload[i * 2 + 1],
            &s->r_prime[i],
            sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
  }

  s->msg = (struct GNUNET_MessageHeader *) msg;
  s->service_transmit_handle
    = GNUNET_CADET_notify_transmit_ready (s->channel,
                                          GNUNET_YES,
                                          GNUNET_TIME_UNIT_FOREVER_REL,
                                          msg_length,
                                          &cb_transfer_message,
                                          s);
  if (NULL == s->service_transmit_handle)
  {
    //disconnect our client
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Could not send service-response message via cadet!)\n"));

    GNUNET_free (msg);
    s->msg = NULL;
    GNUNET_CONTAINER_DLL_remove (from_service_head,
                                 from_service_tail,
                                 s);
    GNUNET_CADET_channel_destroy(s->channel);
    s->response->active = GNUNET_SYSERR;

    s->response->client_notification_task =
            GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                      s->response);
    free_session_variables(s);
    GNUNET_free(s);
    return;
  }
  if (s->transferred_element_count != s->used_element_count)
  {
    // multipart
  }
  else
  {
    //singlepart
    s->active = GNUNET_NO;
    GNUNET_free (s->r);
    s->r = NULL;
    GNUNET_free (s->r_prime);
    s->r_prime = NULL;
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
compute_service_response (struct ServiceSession *session)
{
  int i;
  unsigned int * p;
  unsigned int * q;
  uint32_t count;
  gcry_mpi_t *rand;
  gcry_mpi_t tmp;
  gcry_mpi_t * b;
  struct GNUNET_CRYPTO_PaillierCiphertext * a;
  struct GNUNET_CRYPTO_PaillierCiphertext * r;
  struct GNUNET_CRYPTO_PaillierCiphertext * r_prime;
  struct GNUNET_CRYPTO_PaillierCiphertext * s;
  struct GNUNET_CRYPTO_PaillierCiphertext * s_prime;

  count = session->used_element_count;
  a = session->e_a;
  b = session->sorted_elements;
  q = GNUNET_CRYPTO_random_permute (GNUNET_CRYPTO_QUALITY_WEAK, count);
  p = GNUNET_CRYPTO_random_permute (GNUNET_CRYPTO_QUALITY_WEAK, count);
  rand = GNUNET_malloc (sizeof (gcry_mpi_t) * count);
  for (i = 0; i < count; i++)
    GNUNET_assert (NULL != (rand[i] = gcry_mpi_new (0)));
  r = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_PaillierCiphertext) * count);
  r_prime = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_PaillierCiphertext) * count);
  s = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
  s_prime = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));

  for (i = 0; i < count; i++)
  {
    int32_t svalue;

    svalue = (int32_t) GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                                 UINT32_MAX);

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
  for (i = 0; i < count; i++)
  {
    // E(S - r_pi - b_pi)
    gcry_mpi_sub (tmp, my_offset, rand[p[i]]);
    gcry_mpi_sub (tmp, tmp, b[p[i]]);
    GNUNET_CRYPTO_paillier_encrypt (&session->remote_pubkey,
                                    tmp,
                                    2,
                                    &r[i]);

    // E(S - r_pi - b_pi) * E(S + a_pi) ==  E(2*S + a - r - b)
    GNUNET_CRYPTO_paillier_hom_add (&session->remote_pubkey,
                                    &r[i],
                                    &a[p[i]],
                                    &r[i]);
  }

  // Calculate Kq = E(S + a_qi) (+) E(S - r_qi)
  for (i = 0; i < count; i++) {
    // E(S - r_qi)
    gcry_mpi_sub (tmp, my_offset, rand[q[i]]);
    GNUNET_assert (2 == GNUNET_CRYPTO_paillier_encrypt (&session->remote_pubkey,
                                                        tmp,
                                                        2,
                                                        &r_prime[i]));

    // E(S - r_qi) * E(S + a_qi) == E(2*S + a_qi - r_qi)
    GNUNET_assert (1 == GNUNET_CRYPTO_paillier_hom_add (&session->remote_pubkey,
                                                        &r_prime[i],
                                                        &a[q[i]],
                                                        &r_prime[i]));
  }

  // Calculate S' =  E(SUM( r_i^2 ))
  tmp = compute_square_sum (rand, count);
  GNUNET_CRYPTO_paillier_encrypt (&session->remote_pubkey,
                                  tmp,
                                  1,
                                  s_prime);

  // Calculate S = E(SUM( (r_i + b_i)^2 ))
  for (i = 0; i < count; i++)
    gcry_mpi_add (rand[i], rand[i], b[i]);
  tmp = compute_square_sum (rand, count);
  GNUNET_CRYPTO_paillier_encrypt (&session->remote_pubkey,
                                  tmp,
                                  1,
                                  s);

  session->r = r;
  session->r_prime = r_prime;
  session->s = s;
  session->s_prime = s_prime;

  // release rand, b and a
  for (i = 0; i < count; i++)
  {
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
  GNUNET_SCHEDULER_add_now (&prepare_bobs_cryptodata_message, s);
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
static int
cb_insert_element_sorted (void *cls,
                          const struct GNUNET_HashCode *key,
                          void *value)
{
  struct ServiceSession * s = cls;
  struct SortedValue * e = GNUNET_new (struct SortedValue);
  struct SortedValue * o = s->a_head;
  int64_t val;

  e->elem = value;
  e->val = gcry_mpi_new (0);
  val = (int64_t) GNUNET_ntohll (e->elem->value);
  if (0 > val)
    gcry_mpi_sub_ui (e->val, e->val, -val);
  else
    gcry_mpi_add_ui (e->val, e->val, val);

  // insert as first element with the lowest key
  if (NULL == s->a_head
      || (0 <= GNUNET_CRYPTO_hash_cmp (&s->a_head->elem->key,
                                       &e->elem->key)))
  {
    GNUNET_CONTAINER_DLL_insert (s->a_head,
                                 s->a_tail,
                                 e);
    return GNUNET_YES;
  }
  else if (0 > GNUNET_CRYPTO_hash_cmp (&s->a_tail->elem->key,
                                       &e->elem->key))
  {
    // insert as last element with the highest key
    GNUNET_CONTAINER_DLL_insert_tail (s->a_head,
                                      s->a_tail,
                                      e);
    return GNUNET_YES;
  }
  // insert before the first higher/equal element
  do
  {
    if (0 <= GNUNET_CRYPTO_hash_cmp (&o->elem->key,
                                     &e->elem->key))
    {
      GNUNET_CONTAINER_DLL_insert_before (s->a_head,
                                          s->a_tail,
                                          o,
                                          e);
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
  struct ServiceSession * s = cls;
  struct GNUNET_SCALARPRODUCT_Element * se;
  int i;

  switch (status)
  {
  case GNUNET_SET_STATUS_OK:
    //this element has been removed from the set
    se = GNUNET_CONTAINER_multihashmap_get (s->intersected_elements,
                                            element->data);

    GNUNET_CONTAINER_multihashmap_remove (s->intersected_elements,
                                          element->data,
                                          se);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%s: removed element with key %s value %d\n",
         s->role == ALICE ? "ALICE" : "BOB",
         GNUNET_h2s(&se->key),
         se->value);
    return;

  case GNUNET_SET_STATUS_DONE:
    s->intersection_op = NULL;
    s->intersection_set = NULL;

    s->used_element_count
      = GNUNET_CONTAINER_multihashmap_iterate (s->intersected_elements,
                                               &cb_insert_element_sorted,
                                               s);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%s: Finished intersection, %d items remain\n",
         s->role == ALICE ? "ALICE" : "BOB",
         s->used_element_count);
    if (2 > s->used_element_count)
    {
      // failed! do not leak information about our single remaining element!
      // continue after the loop
      break;
    }

    s->sorted_elements = GNUNET_malloc (s->used_element_count * sizeof (gcry_mpi_t));
    for (i = 0; NULL != s->a_head; i++)
    {
      struct SortedValue* a = s->a_head;
      GNUNET_assert (i < s->used_element_count);

      s->sorted_elements[i] = a->val;
      GNUNET_CONTAINER_DLL_remove (s->a_head, s->a_tail, a);
      GNUNET_free (a->elem);
    }
    GNUNET_assert (i == s->used_element_count);

    if (ALICE == s->role) {
      prepare_alices_cyrptodata_message (s);
      return;
    }
    else if (s->used_element_count == s->transferred_element_count)
    {
      compute_service_response (s);
      return;
    }
    break;
  default:
    LOG (GNUNET_ERROR_TYPE_DEBUG, "%s: OOOPS %d", s->role == ALICE ? "ALICE" : "BOB", status);
    if (NULL != s->intersection_listen)
    {
      GNUNET_SET_listen_cancel (s->intersection_listen);
      s->intersection_listen = NULL;
    }

    // the op failed and has already been invalidated by the set service
    break;
  }

  s->intersection_op = NULL;
  s->intersection_set = NULL;

  //failed if we go here
  GNUNET_break_op (0);

  // and notify our client-session that we could not complete the session
  if (ALICE == s->role) {
    s->active = GNUNET_SYSERR;
    s->client_notification_task =
            GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                      s);
  }
  else
  {
    GNUNET_CONTAINER_DLL_remove (from_service_head,
                                 from_service_tail,
                                 s);
    free_session_variables (s);
    s->response->active = GNUNET_SYSERR;
    s->response->client_notification_task =
            GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                      s->response);
    GNUNET_free(s);
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
  struct ServiceSession * s = cls;

  s->intersection_op = GNUNET_SET_accept (request,
                                          GNUNET_SET_RESULT_REMOVED,
                                          cb_intersection_element_removed,
                                          s);
  if (NULL == s->intersection_op)
  {
    s->active = GNUNET_SYSERR;
    s->client_notification_task =
            GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                      s);
    return;
  }
  if (GNUNET_OK != GNUNET_SET_commit (s->intersection_op, s->intersection_set))
  {
    s->active = GNUNET_SYSERR;
    s->client_notification_task =
            GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                      s);
    return;
  }
  s->intersection_set = NULL;
  s->intersection_listen = NULL;
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
  struct ServiceSession * s = cls;
  struct ClientResponseMessage *msg;
  unsigned char * product_exported = NULL;
  size_t product_length = 0;
  uint32_t msg_length = 0;
  int8_t range = -1;
  gcry_error_t rc;
  int sign;

  s->client_notification_task = GNUNET_SCHEDULER_NO_TASK;

  if (s->product)
  {
    gcry_mpi_t value = gcry_mpi_new (0);

    sign = gcry_mpi_cmp_ui (s->product, 0);
    // libgcrypt can not handle a print of a negative number
    // if (a->sign) return gcry_error (GPG_ERR_INTERNAL); /* Can't handle it yet. */
    if (0 > sign)
    {
      gcry_mpi_sub (value, value, s->product);
    }
    else if (0 < sign)
    {
      range = 1;
      gcry_mpi_add (value, value, s->product);
    }
    else
      range = 0;

    gcry_mpi_release (s->product);
    s->product = NULL;

    // get representation as string
    if (range
        && (0 != (rc = gcry_mpi_aprint (GCRYMPI_FMT_STD,
                                        &product_exported,
                                        &product_length,
                                        value))))
    {
      LOG_GCRY (GNUNET_ERROR_TYPE_ERROR,
                "gcry_mpi_scan",
                rc);
      product_length = 0;
      range = -1; // signal error with product-length = 0 and range = -1
    }
    gcry_mpi_release (value);
  }

  msg_length = sizeof (struct ClientResponseMessage) + product_length;
  msg = GNUNET_malloc (msg_length);
  if (NULL != product_exported)
  {
    memcpy (&msg[1],
            product_exported,
            product_length);
    GNUNET_free (product_exported);
  }
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_RESULT);
  msg->header.size = htons (msg_length);
  msg->range = range;
  msg->product_length = htonl (product_length);
  s->msg = (struct GNUNET_MessageHeader *) msg;
  s->client_transmit_handle =
          GNUNET_SERVER_notify_transmit_ready (s->client,
                                               msg_length,
                                               GNUNET_TIME_UNIT_FOREVER_REL,
                                               &cb_transfer_message,
                                               s);
  GNUNET_break (NULL != s->client_transmit_handle);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sent result to client (%p), this session (%s) has ended!\n",
              s->client,
              GNUNET_h2s (&s->session_id));
}


/**
 * Executed by Alice, fills in a service-request message and sends it to the given peer
 *
 * @param session the session associated with this request
 */
static void
prepare_alices_computation_request (struct ServiceSession * s)
{
  struct ServiceRequestMessage * msg;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _("Successfully created new channel to peer (%s)!\n"),
              GNUNET_i2s (&s->peer));

  msg = GNUNET_new (struct ServiceRequestMessage);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_SESSION_INITIALIZATION);
  memcpy (&msg->session_id, &s->session_id, sizeof (struct GNUNET_HashCode));
  msg->header.size = htons (sizeof (struct ServiceRequestMessage));

  s->msg = (struct GNUNET_MessageHeader *) msg;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Transmitting service request.\n"));

  //transmit via cadet messaging
  s->service_transmit_handle
    = GNUNET_CADET_notify_transmit_ready (s->channel, GNUNET_YES,
                                          GNUNET_TIME_UNIT_FOREVER_REL,
                                          sizeof (struct ServiceRequestMessage),
                                          &cb_transfer_message,
                                          s);
  if (! s->service_transmit_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Could not send message to channel!\n"));
    GNUNET_free (msg);
    s->msg = NULL;
    s->active = GNUNET_SYSERR;
    s->client_notification_task =
            GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                      s);
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
  struct ServiceSession * s = cls;
  struct MultipartMessage * msg;
  struct GNUNET_CRYPTO_PaillierCiphertext * payload;
  unsigned int i;
  uint32_t msg_length;
  uint32_t todo_count;
  gcry_mpi_t a;

  msg_length = sizeof (struct MultipartMessage);
  todo_count = s->used_element_count - s->transferred_element_count;

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
  for (i = s->transferred_element_count; i < todo_count; i++)
  {
    gcry_mpi_add (a, s->sorted_elements[i], my_offset);
    GNUNET_CRYPTO_paillier_encrypt (&my_pubkey, a, 3, &payload[i - s->transferred_element_count]);
  }
  gcry_mpi_release (a);
  s->transferred_element_count += todo_count;

  s->msg = (struct GNUNET_MessageHeader *) msg;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Transmitting service request.\n");

  //transmit via cadet messaging
  s->service_transmit_handle
    = GNUNET_CADET_notify_transmit_ready (s->channel,
                                          GNUNET_YES,
                                          GNUNET_TIME_UNIT_FOREVER_REL,
                                          msg_length,
                                          &cb_transfer_message,
                                          s);
  if (!s->service_transmit_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Could not send service-request multipart message to channel!\n"));
    GNUNET_free (msg);
    s->msg = NULL;
    s->active = GNUNET_SYSERR;
    s->client_notification_task
      = GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                  s);
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
  struct ServiceSession * s;

  //check if service queue contains a matching request
  s = find_matching_session (from_service_tail,
                             &client_session->session_id,
                             NULL);
  if (NULL != s)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Got client-responder-session with key %s and a matching service-request-session set, processing.\n",
                GNUNET_h2s (&client_session->session_id));

    s->response = client_session;
    s->intersected_elements = client_session->intersected_elements;
    client_session->intersected_elements = NULL;
    s->intersection_set = client_session->intersection_set;
    client_session->intersection_set = NULL;

    s->intersection_op = GNUNET_SET_prepare (&s->peer,
                                                   &s->session_id,
                                                   NULL,
                                                   GNUNET_SET_RESULT_REMOVED,
                                                   cb_intersection_element_removed,
                                                   s);

    GNUNET_SET_commit (s->intersection_op, s->intersection_set);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Got client-responder-session with key %s but NO matching service-request-session set, queuing element for later use.\n",
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
client_request_complete_alice (struct ServiceSession * s)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _ ("Creating new channel for session with key %s.\n"),
              GNUNET_h2s (&s->session_id));
  s->channel = GNUNET_CADET_channel_create (my_cadet, s,
                                                 &s->peer,
                                                 GNUNET_APPLICATION_TYPE_SCALARPRODUCT,
                                                 GNUNET_CADET_OPTION_RELIABLE);
  if (NULL == s->channel)
  {
    s->active = GNUNET_SYSERR;
    s->client_notification_task =
            GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                      s);
    return;
  }
  s->intersection_listen = GNUNET_SET_listen (cfg,
                                              GNUNET_SET_OPERATION_INTERSECTION,
                                              &s->session_id,
                                              cb_intersection_request_alice,
                                              s);
  if (NULL == s->intersection_listen)
  {
    s->active = GNUNET_SYSERR;
    s->client_notification_task =
            GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                      s);
    return;
  }
  prepare_alices_computation_request (s);
}


static void
handle_client_message_multipart (void *cls,
                                 struct GNUNET_SERVER_Client *client,
                                 const struct GNUNET_MessageHeader *message)
{
  const struct ComputationMultipartMessage * msg;
  struct ServiceSession *s;
  uint32_t contained_count;
  struct GNUNET_SCALARPRODUCT_Element *elements;
  uint32_t i;

  msg = (const struct ComputationMultipartMessage *) message;
  // only one concurrent session per client connection allowed, simplifies logics a lot...
  s = GNUNET_SERVER_client_get_user_context (client, struct ServiceSession);
  if (NULL == s)
  {
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  contained_count = ntohl (msg->element_count_contained);

  //sanity check: is the message as long as the message_count fields suggests?
  if ( (ntohs (msg->header.size) != (sizeof (struct ComputationMultipartMessage) + contained_count * sizeof (struct GNUNET_SCALARPRODUCT_Element))) ||
       (0 == contained_count) ||
       (s->total < s->transferred_element_count + contained_count))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  s->transferred_element_count += contained_count;

  elements = (struct GNUNET_SCALARPRODUCT_Element *) & msg[1];
  for (i = 0; i < contained_count; i++)
  {
    struct GNUNET_SET_Element set_elem;
    struct GNUNET_SCALARPRODUCT_Element * elem;

    if (0 == GNUNET_ntohll (elements[i].value))
      continue;

    elem = GNUNET_new (struct GNUNET_SCALARPRODUCT_Element);
    memcpy (elem, &elements[i], sizeof (struct GNUNET_SCALARPRODUCT_Element));

    if (GNUNET_SYSERR == GNUNET_CONTAINER_multihashmap_put (s->intersected_elements,
                                                            &elem->key,
                                                            elem,
                                                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
    {
      GNUNET_free (elem);
      continue;
    }
    set_elem.data = &elem->key;
    set_elem.size = sizeof (elem->key);
    set_elem.element_type = 0; /* do we REALLY need this? */
    GNUNET_SET_add_element (s->intersection_set, &set_elem, NULL, NULL);
    s->used_element_count++;
  }

  GNUNET_SERVER_receive_done (client, GNUNET_OK);

  if (s->total != s->transferred_element_count)
    // multipart msg
    return;

  if (ALICE == s->role)
    client_request_complete_alice (s);
  else
    client_request_complete_bob (s);
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
  const struct ComputationMessage * msg = (const struct ComputationMessage *) message;
  struct ServiceSession * s;
  uint32_t contained_count;
  uint32_t total_count;
  uint32_t msg_type;
  struct GNUNET_SCALARPRODUCT_Element * elements;
  uint32_t i;

  // only one concurrent session per client connection allowed, simplifies logics a lot...
  s = GNUNET_SERVER_client_get_user_context (client, struct ServiceSession);
  if (NULL != s)
  {
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  msg_type = ntohs (msg->header.type);
  total_count = ntohl (msg->element_count_total);
  contained_count = ntohl (msg->element_count_contained);

  if ((GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_TO_ALICE == msg_type)
      && (!memcmp (&msg->peer, &me, sizeof (struct GNUNET_PeerIdentity))))
  {
    //session with ourself makes no sense!
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  //sanity check: is the message as long as the message_count fields suggests?
  if ((ntohs (msg->header.size) !=
       (sizeof (struct ComputationMessage) + contained_count * sizeof (struct GNUNET_SCALARPRODUCT_Element)))
      || (0 == total_count))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  // do we have a duplicate session here already?
  if (NULL != find_matching_session (from_client_tail,
                                     &msg->session_key,
                                     NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("Duplicate session information received, can not create new session with key `%s'\n"),
                GNUNET_h2s (&msg->session_key));
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  s = GNUNET_new (struct ServiceSession);
  s->active = GNUNET_YES;
  s->client_notification_task = GNUNET_SCHEDULER_NO_TASK;
  s->client = client;
  s->total = total_count;
  s->transferred_element_count = contained_count;
  // get our transaction key
  memcpy (&s->session_id, &msg->session_key, sizeof (struct GNUNET_HashCode));

  elements = (struct GNUNET_SCALARPRODUCT_Element *) & msg[1];
  s->intersected_elements = GNUNET_CONTAINER_multihashmap_create (s->total, GNUNET_NO);
  s->intersection_set = GNUNET_SET_create (cfg, GNUNET_SET_OPERATION_INTERSECTION);
  for (i = 0; i < contained_count; i++)
  {
    struct GNUNET_SET_Element set_elem;
    struct GNUNET_SCALARPRODUCT_Element * elem;

    if (0 == GNUNET_ntohll (elements[i].value))
      continue;

    elem = GNUNET_new (struct GNUNET_SCALARPRODUCT_Element);
    memcpy (elem, &elements[i], sizeof (struct GNUNET_SCALARPRODUCT_Element));

    if (GNUNET_SYSERR ==
        GNUNET_CONTAINER_multihashmap_put (s->intersected_elements,
                                           &elem->key,
                                           elem,
                                           GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
    {
      GNUNET_free (elem);
      continue;
    }
    set_elem.data = &elem->key;
    set_elem.size = sizeof (elem->key);
    set_elem.element_type = 0;
    GNUNET_SET_add_element (s->intersection_set, &set_elem, NULL, NULL);
    s->used_element_count++;
  }

  if (GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_TO_ALICE == msg_type)
  {
    s->role = ALICE;
    memcpy (&s->peer,
            &msg->peer,
            sizeof (struct GNUNET_PeerIdentity));
  }
  else
  {
    s->role = BOB;
  }

  GNUNET_CONTAINER_DLL_insert (from_client_head,
                               from_client_tail,
                               s);
  GNUNET_SERVER_client_set_user_context (client, s);
  GNUNET_SERVER_receive_done (client, GNUNET_YES);

  if (s->total != s->transferred_element_count)
    // multipart msg
    return;

  if (ALICE == s->role)
    client_request_complete_alice (s);
  else
    client_request_complete_bob (s);
}


/**
 * Function called for inbound channels.
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
  struct ServiceSession *s;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _ ("New incoming channel from peer %s.\n"),
              GNUNET_i2s (initiator));
  s = GNUNET_new (struct ServiceSession);
  s->peer = *initiator;
  s->channel = channel;
  s->role = BOB;
  s->active = GNUNET_YES;
  return s;
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
  struct ServiceSession * s = channel_ctx;
  struct ServiceSession * client_session;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer disconnected, terminating session %s with peer (%s)\n",
              GNUNET_h2s (&s->session_id),
              GNUNET_i2s (&s->peer));

  // as we have only one peer connected in each session, just remove the session
  s->channel = NULL;

  if ( (ALICE == s->role) &&
       (GNUNET_YES == s->active) &&
       (! do_shutdown) )
  {
    // if this happened before we received the answer, we must terminate the session
    s->role = GNUNET_SYSERR;
    s->client_notification_task =
            GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                      s);
  }
  else if ((BOB == s->role) && (GNUNET_SYSERR != s->active))
  {
    if ( (s == from_service_head) ||
         ( (NULL != from_service_head) &&
           ( (NULL != s->next) ||
             (NULL != s->a_tail)) ) )
      GNUNET_CONTAINER_DLL_remove (from_service_head,
                                   from_service_tail,
                                   s);

    // there is a client waiting for this service session, terminate it, too!
    // i assume the tupel of key and element count is unique. if it was not the rest of the code would not work either.
    client_session = s->response;
    if ( (NULL != s->response ) &&
         (GNUNET_NO == s->active) &&
         (GNUNET_YES == client_session->active) )
      client_session->active = GNUNET_NO;
    free_session_variables (s);

    // the client has to check if it was waiting for a result
    // or if it was a responder, no point in adding more statefulness
    if ((NULL != s->response ) && (! do_shutdown))
    {
      client_session->client_notification_task
        = GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                    client_session);
    }
    GNUNET_free (s);
  }
}


/**
 * Compute our scalar product, done by Alice
 *
 * @param session - the session associated with this computation
 * @return product as MPI, never NULL
 */
static gcry_mpi_t
compute_scalar_product (struct ServiceSession *session)
{
  uint32_t count;
  gcry_mpi_t t;
  gcry_mpi_t u;
  gcry_mpi_t u_prime;
  gcry_mpi_t p;
  gcry_mpi_t p_prime;
  gcry_mpi_t tmp;
  gcry_mpi_t r[session->used_element_count];
  gcry_mpi_t r_prime[session->used_element_count];
  gcry_mpi_t s;
  gcry_mpi_t s_prime;
  unsigned int i;

  count = session->used_element_count;
  // due to the introduced static offset S, we now also have to remove this
  // from the E(a_pi)(+)E(-b_pi-r_pi) and E(a_qi)(+)E(-r_qi) twice each,
  // the result is E((S + a_pi) + (S -b_pi-r_pi)) and E(S + a_qi + S - r_qi)
  for (i = 0; i < count; i++)
  {
    GNUNET_CRYPTO_paillier_decrypt (&my_privkey,
                                    &my_pubkey,
                                    &session->r[i],
                                    r[i]);
    gcry_mpi_sub (r[i], r[i], my_offset);
    gcry_mpi_sub (r[i], r[i], my_offset);
    GNUNET_CRYPTO_paillier_decrypt (&my_privkey,
                                    &my_pubkey,
                                    &session->r_prime[i],
                                    r_prime[i]);
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
  GNUNET_CRYPTO_paillier_decrypt (&my_privkey,
                                  &my_pubkey,
                                  session->s, s);
  GNUNET_CRYPTO_paillier_decrypt (&my_privkey,
                                  &my_pubkey,
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
  for (i = 0; i < count; i++)
  {
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
 * @param channel_ctx place to store local state associated with the @a channel
 * @param message the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_alices_cyrptodata_message_multipart (void *cls,
                                            struct GNUNET_CADET_Channel *channel,
                                            void **channel_ctx,
                                            const struct GNUNET_MessageHeader *message)
{
  struct ServiceSession * s;
  const struct MultipartMessage * msg = (const struct MultipartMessage *) message;
  struct GNUNET_CRYPTO_PaillierCiphertext *payload;
  uint32_t contained_elements;
  uint32_t msg_length;

  // are we in the correct state?
  s = (struct ServiceSession *) * channel_ctx;
  //we are not bob
  if ((NULL == s->e_a) || //or we did not expect this message yet
      (s->used_element_count == s->transferred_element_count))
  { //we are not expecting multipart messages
    goto except;
  }
  // shorter than minimum?
  if (ntohs (msg->header.size) <= sizeof (struct MultipartMessage))
  {
    goto except;
  }
  contained_elements = ntohl (msg->contained_element_count);
  msg_length = sizeof (struct MultipartMessage)
          +contained_elements * sizeof (struct GNUNET_CRYPTO_PaillierCiphertext);
  //sanity check
  if ((ntohs (msg->header.size) != msg_length)
      || (s->used_element_count < contained_elements + s->transferred_element_count)
      || (0 == contained_elements))
  {
    goto except;
  }
  payload = (struct GNUNET_CRYPTO_PaillierCiphertext *) &msg[1];
  // Convert each vector element to MPI_value
  memcpy (&s->e_a[s->transferred_element_count], payload,
          sizeof (struct GNUNET_CRYPTO_PaillierCiphertext) * contained_elements);

  s->transferred_element_count += contained_elements;

  if (contained_elements == s->used_element_count)
  {
    // single part finished
    if (NULL == s->intersection_op)
      // intersection has already finished, so we can proceed
      compute_service_response (s);
  }

  return GNUNET_OK;
except:
  s->channel = NULL;
  // and notify our client-session that we could not complete the session
  free_session_variables (s);
  if (NULL != s->client)
  {
    //Alice
    s->active = GNUNET_SYSERR;
    s->client_notification_task =
          GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                    s);
  }
  else
  {
    //Bob
    if (NULL != s->response){
      s->response->active = GNUNET_SYSERR;
      s->response->client_notification_task =
            GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                      s->response);
    }
    if ( (s == from_service_head) ||
         ( (NULL != from_service_head) &&
           ( (NULL != s->next) ||
             (NULL != s->a_tail)) ) )
      GNUNET_CONTAINER_DLL_remove (from_service_head,
                                   from_service_tail,
                                   s);
    GNUNET_free (s);
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
                                  struct GNUNET_CADET_Channel *channel,
                                  void **channel_ctx,
                                  const struct GNUNET_MessageHeader *message)
{
  struct ServiceSession * s;
  const struct AliceCryptodataMessage *msg;
  struct GNUNET_CRYPTO_PaillierCiphertext *payload;
  uint32_t contained_elements = 0;
  uint32_t msg_length;

  s = (struct ServiceSession *) * channel_ctx;
  //we are not bob
  if ((BOB != s->role)
      //we are expecting multipart messages instead
      || (NULL != s->e_a)
      //or we did not expect this message yet
      || //intersection OP has not yet finished
      !((NULL != s->intersection_op)
        //intersection OP done
        || (s->response->sorted_elements)
        ))
  {
    goto invalid_msg;
  }

  if (ntohs (message->size) < sizeof (struct AliceCryptodataMessage))
  {
    GNUNET_break_op (0);
    goto invalid_msg;
  }
  msg = (const struct AliceCryptodataMessage *) message;

  contained_elements = ntohl (msg->contained_element_count);
  msg_length = sizeof (struct AliceCryptodataMessage)
          +contained_elements * sizeof (struct GNUNET_CRYPTO_PaillierCiphertext);

  //sanity check: is the message as long as the message_count fields suggests?
  if ((ntohs (msg->header.size) != msg_length) ||
      (s->used_element_count < s->transferred_element_count + contained_elements) ||
      (0 == contained_elements))
  {
    goto invalid_msg;
  }

  s->transferred_element_count = contained_elements;
  payload = (struct GNUNET_CRYPTO_PaillierCiphertext*) &msg[1];

  s->e_a = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_PaillierCiphertext) * s->used_element_count);
  memcpy (&s->e_a[0],
          payload,
          contained_elements * sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
  if (contained_elements == s->used_element_count)
  {
    // single part finished
    if (NULL == s->intersection_op)
      // intersection has already finished, so we can proceed
      compute_service_response (s);
  }
  return GNUNET_OK;

invalid_msg:
  GNUNET_break_op (0);
  s->channel = NULL;
  // and notify our client-session that we could not complete the session
  free_session_variables (s);
  if (NULL != s->client)
  {
    //Alice
    s->active = GNUNET_SYSERR;
    s->client_notification_task =
          GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                    s);
  }
  else
  {
    //Bob
    if (NULL != s->response)
    {
      s->response->active = GNUNET_SYSERR;
      s->response->client_notification_task =
              GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                        s->response);
    }
    if ( (s == from_service_head) ||
         ( (NULL != from_service_head) &&
           ( (NULL != s->next) ||
             (NULL != s->a_tail)) ) )
      GNUNET_CONTAINER_DLL_remove (from_service_head,
                                   from_service_tail,
                                   s);
    GNUNET_free(s);
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
                                   struct GNUNET_CADET_Channel *channel,
                                   void **channel_ctx,
                                   const struct GNUNET_MessageHeader *message)
{
  struct ServiceSession * s;
  struct ServiceSession * client_session;
  const struct ServiceRequestMessage *msg;

  msg = (const struct ServiceRequestMessage *) message;
  s = (struct ServiceSession *) * channel_ctx;
  if ((BOB != s->role) || (0 != s->total))
  {
    // must be a fresh session
    goto invalid_msg;
  }
  // Check if message was sent by me, which would be bad!
  if (0 != memcmp (&s->peer,
                   &me,
                   sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_free (s);
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (find_matching_session (from_service_tail,
                             &msg->session_id,
                             NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Got message with duplicate session key (`%s'), ignoring service request.\n"),
                (const char *) &(msg->session_id));
    GNUNET_free (s);
    return GNUNET_SYSERR;
  }

  s->channel = channel;
  s->session_id = msg->session_id;
  s->remote_pubkey = msg->public_key;

  //check if service queue contains a matching request
  client_session = find_matching_session (from_client_tail,
                                          &s->session_id,
                                          NULL);

  GNUNET_CONTAINER_DLL_insert (from_service_head,
                               from_service_tail,
                               s);

  if ( (NULL != client_session) &&
       (client_session->transferred_element_count == client_session->total) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Got session with key %s and a matching element set, processing.\n",
                GNUNET_h2s (&s->session_id));

    s->response = client_session;
    s->intersected_elements = client_session->intersected_elements;
    client_session->intersected_elements = NULL;
    s->intersection_set = client_session->intersection_set;
    client_session->intersection_set = NULL;

    s->intersection_op
      = GNUNET_SET_prepare (&s->peer,
                            &s->session_id,
                            NULL,
                            GNUNET_SET_RESULT_REMOVED,
                            &cb_intersection_element_removed,
                            s);
    GNUNET_SET_commit (s->intersection_op,
                       s->intersection_set);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Got session with key %s without a matching element set, queueing.\n",
                GNUNET_h2s (&s->session_id));
  }

  return GNUNET_OK;
invalid_msg:
  GNUNET_break_op (0);
  s->channel = NULL;
  // and notify our client-session that we could not complete the session
  free_session_variables (s);
  if (NULL != s->client)
  {
    //Alice
    s->active = GNUNET_SYSERR;
    s->client_notification_task =
          GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                    s);
  }
  else
  {
    //Bob
    if (NULL != s->response) {
      s->response->active = GNUNET_SYSERR;
      s->response->client_notification_task =
              GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                        s->response);
    }
    if ( (s == from_service_head) ||
         ( (NULL != from_service_head) &&
           ( (NULL != s->next) ||
             (NULL != s->a_tail)) ) )
      GNUNET_CONTAINER_DLL_remove (from_service_head,
                                   from_service_tail,
                                   s);
    GNUNET_free(s);
  }
  return GNUNET_SYSERR;
}


/**
 * Handle a multipart chunk of a response we got from another service we wanted to calculate a scalarproduct with.
 *
 * @param cls closure (set from #GNUNET_CADET_connect)
 * @param channel connection to the other end
 * @param channel_ctx place to store local state associated with the @a channel
 * @param message the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_bobs_cryptodata_multipart (void *cls,
                                   struct GNUNET_CADET_Channel *channel,
                                   void **channel_ctx,
                                   const struct GNUNET_MessageHeader *message)
{
  struct ServiceSession * s;
  const struct MultipartMessage *msg;
  struct GNUNET_CRYPTO_PaillierCiphertext * payload;
  size_t i;
  uint32_t contained = 0;
  size_t msg_size;
  size_t required_size;

  GNUNET_assert (NULL != message);
  // are we in the correct state?
  s = (struct ServiceSession *) * channel_ctx;
  if ((ALICE != s->role) || (NULL == s->sorted_elements))
  {
    goto invalid_msg;
  }
  msg_size = ntohs (message->size);
  if (sizeof (struct MultipartMessage) > msg_size)
  {
    GNUNET_break_op (0);
    goto invalid_msg;
  }
  msg = (const struct MultipartMessage *) message;
  contained = ntohl (msg->contained_element_count);
  required_size = sizeof (struct MultipartMessage)
          + 2 * contained * sizeof (struct GNUNET_CRYPTO_PaillierCiphertext);
  //sanity check: is the message as long as the message_count fields suggests?
  if ( (required_size != msg_size) ||
       (s->used_element_count < s->transferred_element_count + contained) )
  {
    goto invalid_msg;
  }
  payload = (struct GNUNET_CRYPTO_PaillierCiphertext *) &msg[1];
  // Convert each k[][perm] to its MPI_value
  for (i = 0; i < contained; i++)
  {
    memcpy (&s->r[s->transferred_element_count + i],
            &payload[2 * i],
            sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
    memcpy (&s->r_prime[s->transferred_element_count + i],
            &payload[2 * i],
            sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
  }
  s->transferred_element_count += contained;
  if (s->transferred_element_count != s->used_element_count)
    return GNUNET_OK;
  s->product = compute_scalar_product (s); //never NULL

invalid_msg:
  GNUNET_break_op (NULL != s->product);
  s->channel = NULL;
  // send message with product to client
  if (NULL != s->client)
  {
    //Alice
    if (NULL != s->product)
      s->active = GNUNET_NO;
    else
      s->active = GNUNET_SYSERR;
    s->client_notification_task =
          GNUNET_SCHEDULER_add_now (&prepare_client_response,
                                    s);
  }
  else
  {
    //Bob
    if (NULL != s->response){
      s->response->active = GNUNET_SYSERR;
      s->response->client_notification_task =
              GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                        s->response);
    }
    if ( (s == from_service_head) ||
         ( (NULL != from_service_head) &&
           ( (NULL != s->next) ||
             (NULL != s->a_tail)) ) )
      GNUNET_CONTAINER_DLL_remove (from_service_head,
                                   from_service_tail,
                                   s);
    free_session_variables (s);
    GNUNET_free(s);
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
                                struct GNUNET_CADET_Channel *channel,
                                void **channel_ctx,
                                const struct GNUNET_MessageHeader *message)
{
  struct ServiceSession *s;
  const struct ServiceResponseMessage *msg;
  struct GNUNET_CRYPTO_PaillierCiphertext * payload;
  size_t i;
  uint32_t contained = 0;
  size_t msg_size;
  size_t required_size;

  GNUNET_assert (NULL != message);
  s = (struct ServiceSession *) * channel_ctx;
  // are we in the correct state?
  if (NULL == s->sorted_elements
      || NULL != s->msg
      || s->used_element_count != s->transferred_element_count)
  {
    goto invalid_msg;
  }
  //we need at least a full message without elements attached
  msg_size = ntohs (message->size);
  if (sizeof (struct ServiceResponseMessage) > msg_size)
  {
    GNUNET_break_op (0);
    goto invalid_msg;
  }
  msg = (const struct ServiceResponseMessage *) message;
  contained = ntohl (msg->contained_element_count);
  required_size = sizeof (struct ServiceResponseMessage)
          + 2 * contained * sizeof (struct GNUNET_CRYPTO_PaillierCiphertext)
          + 2 * sizeof (struct GNUNET_CRYPTO_PaillierCiphertext);
  //sanity check: is the message as long as the message_count fields suggests?
  if ((msg_size != required_size) || (s->used_element_count < contained))
  {
    goto invalid_msg;
  }
  s->transferred_element_count = contained;
  //convert s
  payload = (struct GNUNET_CRYPTO_PaillierCiphertext *) &msg[1];

  s->s = GNUNET_new (struct GNUNET_CRYPTO_PaillierCiphertext);
  s->s_prime = GNUNET_new (struct GNUNET_CRYPTO_PaillierCiphertext);
  memcpy (s->s,
          &payload[0],
          sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
  memcpy (s->s_prime,
          &payload[1],
          sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));

  s->r = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_PaillierCiphertext) * s->used_element_count);
  s->r_prime = GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_PaillierCiphertext) * s->used_element_count);

  payload = &payload[2];
  // Convert each k[][perm] to its MPI_value
  for (i = 0; i < contained; i++)
  {
    memcpy (&s->r[i],
            &payload[2 * i],
            sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
    memcpy (&s->r_prime[i],
            &payload[2 * i + 1],
            sizeof (struct GNUNET_CRYPTO_PaillierCiphertext));
  }
  if (s->transferred_element_count != s->used_element_count)
    return GNUNET_OK; //wait for the other multipart chunks
  s->product = compute_scalar_product (s); //never NULL

invalid_msg:
  GNUNET_break_op (NULL != s->product);
  s->channel = NULL;
  // send message with product to client
  if (NULL != s->client)
  {
    //Alice
    s->client_notification_task =
          GNUNET_SCHEDULER_add_now (&prepare_client_response,
                                    s);
  }
  else
  {
    //Bob
    if (NULL != s->response)
    {
      s->response->active = GNUNET_SYSERR;
      s->response->client_notification_task
        = GNUNET_SCHEDULER_add_now (&prepare_client_end_notification,
                                    s->response);
    }
    if ( (s == from_service_head) ||
         ( (NULL != from_service_head) &&
           ( (NULL != s->next) ||
             (NULL != s->a_tail)) ) )
      GNUNET_CONTAINER_DLL_remove (from_service_head,
                                   from_service_tail,
                                   s);
    free_session_variables (s);
    GNUNET_free(s);
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
  struct ServiceSession * s;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Shutting down, initiating cleanup.\n");

  do_shutdown = GNUNET_YES;

  // terminate all owned open channels.
  for (s = from_client_head; NULL != s; s = s->next)
  {
    if ((GNUNET_NO != s->active) && (NULL != s->channel))
    {
      GNUNET_CADET_channel_destroy (s->channel);
      s->channel = NULL;
    }
    if (GNUNET_SCHEDULER_NO_TASK != s->client_notification_task)
    {
      GNUNET_SCHEDULER_cancel (s->client_notification_task);
      s->client_notification_task = GNUNET_SCHEDULER_NO_TASK;
    }
    if (NULL != s->client)
    {
      GNUNET_SERVER_client_disconnect (s->client);
      s->client = NULL;
    }
  }
  for (s = from_service_head; NULL != s; s = s->next)
    if (NULL != s->channel)
    {
      GNUNET_CADET_channel_destroy (s->channel);
      s->channel = NULL;
    }

  if (my_cadet)
  {
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
    { &handle_client_message, NULL,
      GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_TO_ALICE,
      0},
    { &handle_client_message, NULL,
      GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_TO_BOB,
      0},
    { &handle_client_message_multipart, NULL,
      GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_MUTLIPART,
      0},
    { NULL, NULL, 0, 0}
  };
  static const struct GNUNET_CADET_MessageHandler cadet_handlers[] = {
    { &handle_alices_computation_request,
      GNUNET_MESSAGE_TYPE_SCALARPRODUCT_SESSION_INITIALIZATION,
      sizeof (struct ServiceRequestMessage) },
    { &handle_alices_cyrptodata_message,
      GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ALICE_CRYPTODATA,
      0},
    { &handle_alices_cyrptodata_message_multipart,
      GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ALICE_CRYPTODATA_MULTIPART,
      0},
    { &handle_bobs_cryptodata_message,
      GNUNET_MESSAGE_TYPE_SCALARPRODUCT_BOB_CRYPTODATA,
      0},
    { &handle_bobs_cryptodata_multipart,
      GNUNET_MESSAGE_TYPE_SCALARPRODUCT_BOB_CRYPTODATA_MULTIPART,
      0},
    { NULL, 0, 0}
  };
  static const uint32_t ports[] = {
    GNUNET_APPLICATION_TYPE_SCALARPRODUCT,
    0
  };
  cfg = c;

  //generate private/public key set
  GNUNET_CRYPTO_paillier_create (&my_pubkey,
                                 &my_privkey);

  // offset has to be sufficiently small to allow computation of:
  // m1+m2 mod n == (S + a) + (S + b) mod n,
  // if we have more complex operations, this factor needs to be lowered
  my_offset = gcry_mpi_new (GNUNET_CRYPTO_PAILLIER_BITS / 3);
  gcry_mpi_set_bit (my_offset, GNUNET_CRYPTO_PAILLIER_BITS / 3);

  // register server callbacks and disconnect handler
  GNUNET_SERVER_add_handlers (server, server_handlers);
  GNUNET_SERVER_disconnect_notify (server,
                                   &cb_client_disconnect,
                                   NULL);
  GNUNET_break (GNUNET_OK ==
                GNUNET_CRYPTO_get_peer_identity (cfg,
                                                 &me));
  my_cadet = GNUNET_CADET_connect (cfg, NULL,
                                   &cb_channel_incoming,
                                   &cb_channel_destruction,
                                   cadet_handlers,
                                   ports);
  if (!my_cadet)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Connect to CADET failed\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connection to CADET initialized\n");
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
