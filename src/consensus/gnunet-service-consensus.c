/*
      This file is part of GNUnet
      (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file consensus/gnunet-service-consensus.c
 * @brief 
 * @author Florian Dold
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_protocols.h"
#include "gnunet_applications.h"
#include "gnunet_util_lib.h"
#include "gnunet_consensus_service.h"
#include "gnunet_core_service.h"
#include "gnunet_stream_lib.h"
#include "consensus_protocol.h"
#include "ibf.h"
#include "consensus.h"


/**
 * Number of IBFs in a strata estimator.
 */
#define STRATA_COUNT 32
/**
 * Number of buckets per IBF.
 */
#define STRATA_IBF_BUCKETS 80
/**
 * hash num parameter of the IBF
 */
#define STRATA_HASH_NUM 3
/**
 * Number of strata that can be transmitted in one message.
 */
#define STRATA_PER_MESSAGE ((1<<15) / (IBF_BUCKET_SIZE * STRATA_IBF_BUCKETS))

#define BUCKETS_PER_MESSAGE ((1<<15) / IBF_BUCKET_SIZE)

#define MAX_IBF_ORDER (64)


/* forward declarations */

struct ConsensusSession;
struct IncomingSocket;
struct ConsensusPeerInformation;

static void
send_next (struct ConsensusSession *session);

static void 
write_strata (void *cls, enum GNUNET_STREAM_Status status, size_t size);

static void 
write_ibf (void *cls, enum GNUNET_STREAM_Status status, size_t size);

static void 
write_values (void *cls, enum GNUNET_STREAM_Status status, size_t size);

static int
get_peer_idx (const struct GNUNET_PeerIdentity *peer, const struct ConsensusSession *session);


/**
 * An element that is waiting to be transmitted to a client.
 */
struct PendingElement
{
  /**
   * Pending elements are kept in a DLL.
   */
  struct PendingElement *next;

  /**
   * Pending elements are kept in a DLL.
   */
  struct PendingElement *prev;

  /**
   * The actual element
   */
  struct GNUNET_CONSENSUS_Element *element;

  /* peer this element is coming from */
  struct ConsensusPeerInformation *cpi;
};

struct ConsensusPeerInformation
{
  struct GNUNET_STREAM_Socket *socket;

  /**
   * Is socket's connection established, i.e. can we write to it?
   * Only relevent on outgoing cpi.
   */
  int is_connected;

  /**
   * Type of the peer in the all-to-all rounds,
   * GNUNET_YES if we initiate reconciliation.
   */
  int is_outgoing;

  /**
   * Did we receive/send a consensus hello?
   */
  int hello;

  /**
   * Handle for currently active read
   */
  struct GNUNET_STREAM_ReadHandle *rh;

  /**
   * Handle for currently active read
   */
  struct GNUNET_STREAM_WriteHandle *wh;

  /**
   * How many of the strate in the ibf were
   * sent or received in this round?
   */
  int strata_counter;

  int ibf_order;

  struct InvertibleBloomFilter *outgoing_ibf;

  int outgoing_bucket_counter;

  struct InvertibleBloomFilter *incoming_ibf;

  int incoming_bucket_counter;

  /**
   * NULL or incoming_ibf - outgoing_ibf.
   * Decoded values of side '1' are to be requested from the the peer.
   */
  struct InvertibleBloomFilter *diff_ibf;

  /**
   * Strata estimator of the peer, NULL if our peer
   * initiated the reconciliation.
   */
  struct InvertibleBloomFilter **strata;

  unsigned int diff;

  struct GNUNET_SERVER_MessageStreamTokenizer *mst;

  struct ConsensusSession *session;
};

struct QueuedMessage
{
  struct GNUNET_MessageHeader *msg;

  /**
   * Queued messages are stored in a doubly linked list.
   */
  struct QueuedMessage *next;

  /**
   * Queued messages are stored in a doubly linked list.
   */
  struct QueuedMessage *prev;
};


/**
 * A consensus session consists of one local client and the remote authorities.
 */
struct ConsensusSession
{
  /**
   * Consensus sessions are kept in a DLL.
   */
  struct ConsensusSession *next;

  /**
   * Consensus sessions are kept in a DLL.
   */
  struct ConsensusSession *prev;

  /**
   * Join message. Used to initialize the session later,
   * if the identity of the local peer is not yet known.
   * NULL if the session has been fully initialized.
   */
  struct GNUNET_CONSENSUS_JoinMessage *join_msg;

  /**
  * Global consensus identification, computed
  * from the local id and participating authorities.
  */
  struct GNUNET_HashCode global_id;

  /**
   * Local client in this consensus session.
   * There is only one client per consensus session.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Values in the consensus set of this session,
   * all of them either have been sent by or approved by the client.
   */
  struct GNUNET_CONTAINER_MultiHashMap *values;

  /**
   * Elements that have not been approved (or rejected) by the client yet.
   */
  struct PendingElement *approval_pending_head;

  /**
   * Elements that have not been approved (or rejected) by the client yet.
   */
  struct PendingElement *approval_pending_tail;

  struct QueuedMessage *client_messages_head;

  struct QueuedMessage *client_messages_tail;

  /**
   * Currently active transmit handle for sending to the client
   */
  struct GNUNET_SERVER_TransmitHandle *th;

  /**
   * Once conclude_requested is GNUNET_YES, the client may not
   * insert any more values.
   */
  int conclude_requested;

  /**
   * Minimum number of peers to form a consensus group
   */
  int conclude_group_min;

  /**
   * Current round of the conclusion
   */
  int current_round;

  /**
   * Soft deadline for conclude.
   * Speed up the speed of the consensus at the cost of consensus quality, as
   * the time approached or crosses the deadline.
   */
  struct GNUNET_TIME_Absolute conclude_deadline;

  /**
   * Number of other peers in the consensus
   */
  unsigned int num_peers;

  struct ConsensusPeerInformation *info;

  /**
   * Sorted array of peer identities in this consensus session,
   * includes the local peer.
   */
  struct GNUNET_PeerIdentity *peers;

  /**
   * Index of the local peer in the peers array
   */
  int local_peer_idx;

  /**
   * Task identifier for the round timeout task
   */
  GNUNET_SCHEDULER_TaskIdentifier round_timeout_tid;

  struct InvertibleBloomFilter **strata;

  struct InvertibleBloomFilter **ibfs;
};


/**
 * Sockets from other peers who want to communicate with us.
 * It may not be known yet which consensus session they belong to.
 */
struct IncomingSocket
{
  /**
   * Incoming sockets are kept in a double linked list.
   */
  struct IncomingSocket *next;

  /**
   * Incoming sockets are kept in a double linked list.
   */
  struct IncomingSocket *prev;

  /**
   * The actual socket.
   */
  struct GNUNET_STREAM_Socket *socket;

  /**
   * Handle for currently active read
   */
  struct GNUNET_STREAM_ReadHandle *rh;

  /**
   * Peer that connected to us with the socket.
   */
  struct GNUNET_PeerIdentity *peer;

  /**
   * Message stream tokenizer for this socket.
   */
  struct GNUNET_SERVER_MessageStreamTokenizer *mst;

  /**
   * Peer-in-session this socket belongs to, once known, otherwise NULL.
   */
  struct ConsensusPeerInformation *cpi;
};

static struct IncomingSocket *incoming_sockets_head;
static struct IncomingSocket *incoming_sockets_tail;

/**
 * Linked list of sesstions this peer participates in.
 */
static struct ConsensusSession *sessions_head;

/**
 * Linked list of sesstions this peer participates in.
 */
static struct ConsensusSession *sessions_tail;

/**
 * Configuration of the consensus service.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to the server for this service.
 */
static struct GNUNET_SERVER_Handle *srv;

/**
 * Peer that runs this service.
 */
static struct GNUNET_PeerIdentity *my_peer;

/**
 * Handle to the core service. Only used during service startup, will be NULL after that.
 */
static struct GNUNET_CORE_Handle *core;

/**
 * Listener for sockets from peers that want to reconcile with us.
 */
static struct GNUNET_STREAM_ListenSocket *listener;


static void
queue_client_message (struct ConsensusSession *session, struct GNUNET_MessageHeader *msg)
{
  struct QueuedMessage *qm;
  qm = GNUNET_malloc (sizeof *qm);
  qm->msg = msg;
  GNUNET_CONTAINER_DLL_insert_tail (session->client_messages_head, session->client_messages_tail, qm);
}


static int
estimate_difference (struct InvertibleBloomFilter** strata1,
                     struct InvertibleBloomFilter** strata2)
{
  int i;
  int count;
  count = 0;
  for (i = STRATA_COUNT - 1; i >= 0; i--)
  {
    struct InvertibleBloomFilter *diff;
    int ibf_count;
    int more;
    ibf_count = 0;
    diff = ibf_dup (strata1[i]);
    ibf_subtract (diff, strata2[i]);
    for (;;)
    {
      more = ibf_decode (diff, NULL, NULL);
      if (GNUNET_NO == more)
      {
        count += ibf_count;
        break;
      }
      if (GNUNET_SYSERR == more)
      {
        return count * (1 << (i + 1));
      }
      ibf_count++;
    }
    ibf_destroy (diff);
  }
  return count;
}



/**
 * Functions of this signature are called whenever data is available from the
 * stream.
 *
 * @param cls the closure from GNUNET_STREAM_read
 * @param status the status of the stream at the time this function is called
 * @param data traffic from the other side
 * @param size the number of bytes available in data read; will be 0 on timeout 
 * @return number of bytes of processed from 'data' (any data remaining should be
 *         given to the next time the read processor is called).
 */
static size_t
session_stream_data_processor (void *cls,
                       enum GNUNET_STREAM_Status status,
                       const void *data,
                       size_t size)
{
  struct ConsensusPeerInformation *cpi;
  int ret;

  GNUNET_assert (GNUNET_STREAM_OK == status);

  cpi = cls;

  GNUNET_assert (NULL != cpi->mst);

  ret = GNUNET_SERVER_mst_receive (cpi->mst, cpi, data, size, GNUNET_NO, GNUNET_YES);
  if (GNUNET_SYSERR == ret)
  {
    /* FIXME: handle this correctly */
    GNUNET_assert (0);
  }

  /* read again */
  cpi->rh = GNUNET_STREAM_read (cpi->socket, GNUNET_TIME_UNIT_FOREVER_REL,
                                &session_stream_data_processor, cpi);

  /* we always read all data */
  return size;
}

/**
 * Functions of this signature are called whenever data is available from the
 * stream.
 *
 * @param cls the closure from GNUNET_STREAM_read
 * @param status the status of the stream at the time this function is called
 * @param data traffic from the other side
 * @param size the number of bytes available in data read; will be 0 on timeout 
 * @return number of bytes of processed from 'data' (any data remaining should be
 *         given to the next time the read processor is called).
 */
static size_t
incoming_stream_data_processor (void *cls,
                       enum GNUNET_STREAM_Status status,
                       const void *data,
                       size_t size)
{
  struct IncomingSocket *incoming;
  int ret;

  GNUNET_assert (GNUNET_STREAM_OK == status);

  incoming = cls;

  ret = GNUNET_SERVER_mst_receive (incoming->mst, incoming, data, size, GNUNET_NO, GNUNET_YES);
  if (GNUNET_SYSERR == ret)
  {
    /* FIXME: handle this correctly */
    GNUNET_assert (0);
  }

  /* read again */
  incoming->rh = GNUNET_STREAM_read (incoming->socket, GNUNET_TIME_UNIT_FOREVER_REL,
                                     &incoming_stream_data_processor, incoming);

  /* we always read all data */
  return size;
}


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
ibf_values_iterator (void *cls,
                     const struct GNUNET_HashCode *key,
                     void *value)
{
  struct ConsensusPeerInformation *cpi;
  cpi = cls;
  ibf_insert (cpi->session->ibfs[cpi->ibf_order], key);
  return GNUNET_YES;
}


static void
create_outgoing_ibf (struct ConsensusPeerInformation *cpi)
{
  if (NULL == cpi->session->ibfs[cpi->ibf_order])
  {
    cpi->session->ibfs[cpi->ibf_order] = ibf_create (1 << cpi->ibf_order, STRATA_HASH_NUM, 0);
    GNUNET_CONTAINER_multihashmap_iterate (cpi->session->values, ibf_values_iterator, cpi);
  }
  cpi->outgoing_ibf = ibf_dup (cpi->session->ibfs[cpi->ibf_order]);
}

static int
handle_p2p_strata (struct ConsensusPeerInformation *cpi, const struct StrataMessage *strata_msg)
{
  int i;
  int num_strata;
  struct GNUNET_HashCode *hash_src;
  uint8_t *count_src;

  GNUNET_assert (GNUNET_NO == cpi->is_outgoing);

  if (NULL == cpi->strata)
  {
    cpi->strata = GNUNET_malloc (STRATA_COUNT * sizeof (struct InvertibleBloomFilter *));
    for (i = 0; i < STRATA_COUNT; i++)
      cpi->strata[i] = ibf_create (STRATA_IBF_BUCKETS, STRATA_HASH_NUM, 0);
  }

  num_strata = ntohs (strata_msg->num_strata);

  /* for correct message alignment, copy bucket types seperately */
  hash_src = (struct GNUNET_HashCode *) &strata_msg[1];

  for (i = 0; i < num_strata; i++)
  {
    memcpy (cpi->strata[cpi->strata_counter+i]->hash_sum, hash_src, STRATA_IBF_BUCKETS * sizeof *hash_src);
    hash_src += STRATA_IBF_BUCKETS;
  }

  for (i = 0; i < num_strata; i++)
  {
    memcpy (cpi->strata[cpi->strata_counter+i]->id_sum, hash_src, STRATA_IBF_BUCKETS * sizeof *hash_src);
    hash_src += STRATA_IBF_BUCKETS;
  }

  count_src = (uint8_t *) hash_src;

  for (i = 0; i < num_strata; i++)
  {
    memcpy (cpi->strata[cpi->strata_counter+i]->count, count_src, STRATA_IBF_BUCKETS);
    count_src += STRATA_IBF_BUCKETS;
  }

  GNUNET_assert (count_src == (((uint8_t *) &strata_msg[1]) + STRATA_IBF_BUCKETS * num_strata * IBF_BUCKET_SIZE));

  cpi->strata_counter += num_strata;

  if (STRATA_COUNT == cpi->strata_counter)
  {

    cpi->diff = estimate_difference (cpi->session->strata, cpi->strata);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "received strata, diff=%d\n", cpi->diff);
    cpi->ibf_order = 0;
    while ((1 << cpi->ibf_order) < cpi->diff)
      cpi->ibf_order++;
    if (cpi->ibf_order > MAX_IBF_ORDER)
      cpi->ibf_order = MAX_IBF_ORDER;
    cpi->ibf_order += 2;
    create_outgoing_ibf (cpi);
    write_ibf (cpi, GNUNET_STREAM_OK, 0);
  }

  return GNUNET_YES;
}


static int
handle_p2p_ibf (struct ConsensusPeerInformation *cpi, const struct DifferenceDigest *digest)
{
  struct GNUNET_HashCode *hash_src;
  int num_buckets;
  uint8_t *count_src;

  num_buckets = (ntohs (digest->header.size) - (sizeof *digest)) / IBF_BUCKET_SIZE;

  if (cpi->is_outgoing == GNUNET_YES)
  {
    /* we receive the ibf as an initiator, thus we're interested in the order */
    cpi->ibf_order = digest->order;
    if ((0 == cpi->outgoing_bucket_counter) && (NULL == cpi->wh))
    {
      create_outgoing_ibf (cpi);
      write_ibf (cpi, GNUNET_STREAM_OK, 0);
    }
    /* FIXME: ensure that orders do not differ each time */
  }
  else
  {
    /* FIXME: handle correctly */
    GNUNET_assert (cpi->ibf_order == digest->order);
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "receiving %d buckets at %d of %d\n", num_buckets, cpi->incoming_bucket_counter, (1 << cpi->ibf_order));

  if (cpi->incoming_bucket_counter + num_buckets > (1 << cpi->ibf_order))
  {
    /* TODO: handle this */
    GNUNET_assert (0);
  }

  if (NULL == cpi->incoming_ibf)
    cpi->incoming_ibf = ibf_create (1 << cpi->ibf_order, STRATA_HASH_NUM, 0);

  hash_src = (struct GNUNET_HashCode *) &digest[1];

  memcpy (cpi->incoming_ibf->hash_sum, hash_src, num_buckets * sizeof *hash_src);
  hash_src += num_buckets;

  memcpy (cpi->incoming_ibf->id_sum, hash_src, num_buckets * sizeof *hash_src);
  hash_src += num_buckets;

  count_src = (uint8_t *) hash_src;

  memcpy (cpi->incoming_ibf->count, count_src, num_buckets * sizeof *count_src);

  cpi->incoming_bucket_counter += num_buckets;

  if (cpi->incoming_bucket_counter == (1 << cpi->ibf_order))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "received full ibf\n");
    if ((NULL == cpi->wh) && (cpi->outgoing_bucket_counter == (1 << cpi->ibf_order)))
      write_values (cpi, GNUNET_STREAM_OK, 0);
  }
  return GNUNET_YES;
}


static int
handle_p2p_element (struct ConsensusPeerInformation *cpi, const struct GNUNET_MessageHeader *element_msg)
{
  struct PendingElement *pending_element;
  struct GNUNET_CONSENSUS_Element *element;
  struct GNUNET_CONSENSUS_ElementMessage *client_element_msg;
  size_t size;

  size = ntohs (element_msg->size) - sizeof *element_msg;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "receiving element, size=%d\n", size);

  element = GNUNET_malloc (size + sizeof *element);
  element->size = size;
  memcpy (&element[1], &element_msg[1], size);
  element->data = &element[1];

  pending_element = GNUNET_malloc (sizeof *pending_element);
  pending_element->element = element;
  GNUNET_CONTAINER_DLL_insert_tail (cpi->session->approval_pending_head, cpi->session->approval_pending_tail, pending_element);

  client_element_msg = GNUNET_malloc (size + sizeof *client_element_msg);
  client_element_msg->header.type = htons (GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_RECEIVED_ELEMENT);
  client_element_msg->header.size = htons (size + sizeof *client_element_msg);
  memcpy (&client_element_msg[1], &element[1], size);

  queue_client_message (cpi->session, (struct GNUNET_MessageHeader *) client_element_msg);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "received element\n");

  send_next (cpi->session);
  
  return GNUNET_YES;
}


static int
handle_p2p_hello (struct IncomingSocket *inc, const struct ConsensusHello *hello)
{
  /* FIXME: session might not exist yet */
  struct ConsensusSession *session;
  session = sessions_head;
  while (NULL != session)
  {
    if (0 == GNUNET_CRYPTO_hash_cmp (&session->global_id, &hello->global_id))
    {
      int idx;
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "peer helloed session\n");
      idx = get_peer_idx (inc->peer, session);
      GNUNET_assert (-1 != idx);
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "idx is %d\n", idx);
      inc->cpi = &session->info[idx];
      GNUNET_assert (GNUNET_NO == inc->cpi->is_outgoing);
      inc->cpi->mst = inc->mst;
      inc->cpi->hello = GNUNET_YES;
      inc->cpi->socket = inc->socket;
      return GNUNET_YES;
    }
    session = session->next;
  }
  GNUNET_assert (0);
  return GNUNET_NO;
}


/**
 * Functions with this signature are called whenever a
 * complete message is received by the tokenizer.
 *
 * Do not call GNUNET_SERVER_mst_destroy in callback
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR to stop further processing
 */
static int
mst_session_callback (void *cls, void *client, const struct GNUNET_MessageHeader *message)
{
  struct ConsensusPeerInformation *cpi;
  cpi =  cls;
  switch (ntohs (message->type))
  {
    case GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_DELTA_ESTIMATE:
      return handle_p2p_strata (cpi, (struct StrataMessage *) message);
    case GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_DIFFERENCE_DIGEST:
      return handle_p2p_ibf (cpi, (struct DifferenceDigest *) message);
    case GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_ELEMENTS:
      return handle_p2p_element (cpi, message);
    default:
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "unexpected message type from peer: %u\n", ntohs (message->type));
      /* FIXME: handle correctly */
      GNUNET_assert (0);
  }
  return GNUNET_OK;
}


/**
 * Handle tokenized messages from stream sockets.
 * Delegate them if the socket belongs to a session,
 * handle hello messages otherwise.
 *
 * Do not call GNUNET_SERVER_mst_destroy in callback
 *
 * @param cls closure, unused
 * @param client incoming socket this message comes from
 * @param message the actual message
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR to stop further processing
 */
static int
mst_incoming_callback (void *cls, void *client, const struct GNUNET_MessageHeader *message)
{
  struct IncomingSocket *inc;
  inc = (struct IncomingSocket *) client;
  switch (ntohs( message->type))
  {
    case GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_HELLO:
      return handle_p2p_hello (inc, (struct ConsensusHello *) message);
    default:
      if (NULL != inc->cpi)
        return mst_session_callback (inc->cpi, client, message);
      /* FIXME: disconnect peer properly */
      GNUNET_assert (0);
  }
  return GNUNET_OK;
}


/**
 * Functions of this type are called upon new stream connection from other peers
 * or upon binding error which happen when the app_port given in
 * GNUNET_STREAM_listen() is already taken.
 *
 * @param cls the closure from GNUNET_STREAM_listen
 * @param socket the socket representing the stream; NULL on binding error
 * @param initiator the identity of the peer who wants to establish a stream
 *            with us; NULL on binding error
 * @return GNUNET_OK to keep the socket open, GNUNET_SYSERR to close the
 *             stream (the socket will be invalid after the call)
 */
static int
listen_cb (void *cls,
           struct GNUNET_STREAM_Socket *socket,
           const struct GNUNET_PeerIdentity *initiator)
{
  struct IncomingSocket *incoming;

  GNUNET_assert (NULL != socket);

  incoming = GNUNET_malloc (sizeof *incoming);

  incoming->socket = socket;
  incoming->peer = GNUNET_memdup (initiator, sizeof *initiator);

  incoming->rh = GNUNET_STREAM_read (socket, GNUNET_TIME_UNIT_FOREVER_REL,
                                     &incoming_stream_data_processor, incoming);


  incoming->mst = GNUNET_SERVER_mst_create (mst_incoming_callback, incoming);

  GNUNET_CONTAINER_DLL_insert_tail (incoming_sockets_head, incoming_sockets_tail, incoming);

  return GNUNET_OK;
}


static void
destroy_session (struct ConsensusSession *session)
{
  /* FIXME: more stuff to free! */
  GNUNET_CONTAINER_DLL_remove (sessions_head, sessions_tail, session);
  GNUNET_SERVER_client_drop (session->client);
  GNUNET_free (session);
}


/**
 * Disconnect a client, and destroy all sessions associated with it.
 *
 * @param client the client to disconnect
 */
static void
disconnect_client (struct GNUNET_SERVER_Client *client)
{
  struct ConsensusSession *session;
  GNUNET_SERVER_client_disconnect (client);
  
  /* if the client owns a session, remove it */
  session = sessions_head;
  while (NULL != session)
  {
    if (client == session->client)
    {
      destroy_session (session);
      break;
    }
    session = session->next;
  }
}


/**
 * Compute a global, (hopefully) unique consensus session id,
 * from the local id of the consensus session, and the identities of all participants.
 * Thus, if the local id of two consensus sessions coincide, but are not comprised of
 * exactly the same peers, the global id will be different.
 *
 * @param local_id local id of the consensus session
 * @param peers array of all peers participating in the consensus session
 * @param num_peers number of elements in the peers array
 * @param dst where the result is stored, may not be NULL
 */
static void
compute_global_id (const struct GNUNET_HashCode *local_id,
                   const struct GNUNET_PeerIdentity *peers, int num_peers, 
                   struct GNUNET_HashCode *dst)
{
  int i;
  struct GNUNET_HashCode tmp;

  *dst = *local_id;
  for (i = 0; i < num_peers; ++i)
  {
    GNUNET_CRYPTO_hash_xor (dst, &peers[0].hashPubKey, &tmp);
    *dst = tmp;
    GNUNET_CRYPTO_hash (dst, sizeof (struct GNUNET_PeerIdentity), &tmp);
    *dst = tmp;
  }
}


/**
 * Function called to notify a client about the connection
 * begin ready to queue more data.  "buf" will be
 * NULL and "size" zero if the connection was closed for
 * writing in the meantime.
 *
 * @param cls consensus session
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_queued (void *cls, size_t size,
                 void *buf)
{
  struct ConsensusSession *session;
  struct QueuedMessage *qmsg;
  size_t msg_size;

  session = cls;
  session->th = NULL;


  qmsg = session->client_messages_head;
  GNUNET_CONTAINER_DLL_remove (session->client_messages_head, session->client_messages_tail, qmsg);
  GNUNET_assert (qmsg);

  if (NULL == buf)
  {
    destroy_session (session);
    return 0;
  }

  msg_size = ntohs (qmsg->msg->size);

  GNUNET_assert (size >= msg_size);

  memcpy (buf, qmsg->msg, msg_size);
  GNUNET_free (qmsg->msg);
  GNUNET_free (qmsg);

  send_next (session);

  return msg_size;
}


/**
 * Schedule sending the next message (if there is any) to a client.
 *
 * @param cli the client to send the next message to
 */
static void
send_next (struct ConsensusSession *session)
{

  GNUNET_assert (NULL != session);

  if (NULL != session->th)
    return;

  if (NULL != session->client_messages_head)
  {
    int msize;
    msize = ntohs (session->client_messages_head->msg->size);
    session->th = GNUNET_SERVER_notify_transmit_ready (session->client, msize, 
                                                       GNUNET_TIME_UNIT_FOREVER_REL,
                                                       &transmit_queued, session);
  }
}


/**
 * Although GNUNET_CRYPTO_hash_cmp exisits, it does not have
 * the correct signature to be used with e.g. qsort.
 * We use this function instead.
 *
 * @param h1 some hash code
 * @param h2 some hash code
 * @return 1 if h1 > h2, -1 if h1 < h2 and 0 if h1 == h2.
 */
static int
hash_cmp (const void *a, const void *b)
{
  return GNUNET_CRYPTO_hash_cmp ((struct GNUNET_HashCode *) a, (struct GNUNET_HashCode *) b);
}


/**
 * Search peer in the list of peers in session.
 *
 * @param peer peer to find
 * @param session session with peer
 * @return index of peer, -1 if peer is not in session
 */
static int
get_peer_idx (const struct GNUNET_PeerIdentity *peer, const struct ConsensusSession *session)
{
  const struct GNUNET_PeerIdentity *needle;
  needle = bsearch (peer, session->peers, session->num_peers, sizeof (struct GNUNET_PeerIdentity), &hash_cmp);
  if (NULL == needle)
    return -1;
  return needle - session->peers;
}



static void
hello_cont (void *cls, enum GNUNET_STREAM_Status status, size_t size)
{
  struct ConsensusPeerInformation *cpi;

  cpi = cls;
  cpi->hello = GNUNET_YES;
  
  GNUNET_assert (GNUNET_STREAM_OK == status);

  if (cpi->session->conclude_requested)
  {
    write_strata (cpi, GNUNET_STREAM_OK, 0);  
  }
}


/**
 * Functions of this type will be called when a stream is established
 *
 * @param cls the closure from GNUNET_STREAM_open
 * @param socket socket to use to communicate with the other side (read/write)
 */
static void
open_cb (void *cls, struct GNUNET_STREAM_Socket *socket)
{
  struct ConsensusPeerInformation *cpi;
  struct ConsensusHello *hello;


  cpi = cls;
  cpi->is_connected = GNUNET_YES;

  hello = GNUNET_malloc (sizeof *hello);
  hello->header.size = htons (sizeof *hello);
  hello->header.type = htons (GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_HELLO);
  memcpy (&hello->global_id, &cpi->session->global_id, sizeof (struct GNUNET_HashCode));

  cpi->wh =
      GNUNET_STREAM_write (socket, hello, sizeof *hello, GNUNET_TIME_UNIT_FOREVER_REL, hello_cont, cpi);

  cpi->rh = GNUNET_STREAM_read (socket, GNUNET_TIME_UNIT_FOREVER_REL,
                                &session_stream_data_processor, cpi);

}


static void
initialize_session_info (struct ConsensusSession *session)
{
  int i;
  int last;

  for (i = 0; i < session->num_peers; ++i)
  {
    /* initialize back-references, so consensus peer information can
     * be used as closure */
    session->info[i].session = session;
  }

  last = (session->local_peer_idx + ((session->num_peers - 1) / 2) + 1) % session->num_peers;
  i = (session->local_peer_idx + 1) % session->num_peers;
  while (i != last)
  {
    session->info[i].is_outgoing = GNUNET_YES;
    session->info[i].socket = GNUNET_STREAM_open (cfg, &session->peers[i], GNUNET_APPLICATION_TYPE_CONSENSUS,
                                                  open_cb, &session->info[i], GNUNET_STREAM_OPTION_END);
    session->info[i].mst = GNUNET_SERVER_mst_create (mst_session_callback, &session->info[i]);
    i = (i + 1) % session->num_peers;

    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "peer %d contacts peer %d\n", session->local_peer_idx, i);
  }
  // tie-breaker for even number of peers
  if (((session->num_peers % 2) == 0) && (session->local_peer_idx < last))
  {
    session->info[last].is_outgoing = GNUNET_YES;
    session->info[last].socket = GNUNET_STREAM_open (cfg, &session->peers[last], GNUNET_APPLICATION_TYPE_CONSENSUS,
                                                     open_cb, &session->info[last], GNUNET_STREAM_OPTION_END);
    session->info[last].mst = GNUNET_SERVER_mst_create (mst_session_callback, &session->info[last]);

    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "peer %d contacts peer %d (tiebreaker)\n", session->local_peer_idx, last);
  }
}


/**
 * Create the sorted list of peers for the session,
 * add the local peer if not in the join message.
 */
static void
initialize_session_peer_list (struct ConsensusSession *session)
{
  int local_peer_in_list;
  int listed_peers;
  const struct GNUNET_PeerIdentity *msg_peers;
  unsigned int i;

  GNUNET_assert (NULL != session->join_msg);

  /* peers in the join message, may or may not include the local peer */
  listed_peers = ntohs (session->join_msg->num_peers);
  
  session->num_peers = listed_peers;

  msg_peers = (struct GNUNET_PeerIdentity *) &session->join_msg[1];

  local_peer_in_list = GNUNET_NO;
  for (i = 0; i < listed_peers; i++)
  {
    if (0 == memcmp (&msg_peers[i], my_peer, sizeof (struct GNUNET_PeerIdentity)))
    {
      local_peer_in_list = GNUNET_YES;
      break;
    }
  }

  if (GNUNET_NO == local_peer_in_list)
    session->num_peers++;

  session->peers = GNUNET_malloc (session->num_peers * sizeof (struct GNUNET_PeerIdentity));

  if (GNUNET_NO == local_peer_in_list)
    session->peers[session->num_peers - 1] = *my_peer;

  memcpy (session->peers, msg_peers, listed_peers * sizeof (struct GNUNET_PeerIdentity));
  qsort (session->peers, session->num_peers, sizeof (struct GNUNET_PeerIdentity), &hash_cmp);
}


static void
strata_insert (struct InvertibleBloomFilter **strata, struct GNUNET_HashCode *key)
{
  uint32_t v;
  int i;
  v = key->bits[0];
  /* count trailing '1'-bits of v */
  for (i = 0; v & 1; v>>=1, i++);
  ibf_insert (strata[i], key);
}


/**
 * Initialize the session, continue receiving messages from the owning client
 *
 * @param session the session to initialize
 */
static void
initialize_session (struct ConsensusSession *session)
{
  const struct ConsensusSession *other_session;
  int i;

  GNUNET_assert (NULL != session->join_msg);

  initialize_session_peer_list (session);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "session with %u peers\n", session->num_peers);

  compute_global_id (&session->join_msg->session_id, session->peers, session->num_peers, &session->global_id);

  /* Check if some local client already owns the session. */
  other_session = sessions_head;
  while (NULL != other_session)
  {
    if ((other_session != session) && 
        (0 == GNUNET_CRYPTO_hash_cmp (&session->global_id, &other_session->global_id)))
    {
      /* session already owned by another client */
      GNUNET_break (0);
      disconnect_client (session->client);
      return;
    }
    other_session = other_session->next;
  }

  session->values = GNUNET_CONTAINER_multihashmap_create (256, GNUNET_NO);

  session->local_peer_idx = get_peer_idx (my_peer, session);
  GNUNET_assert (-1 != session->local_peer_idx);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "%d is the local peer\n", session->local_peer_idx);

  session->strata = GNUNET_malloc (STRATA_COUNT * sizeof (struct InvertibleBloomFilter *));
  for (i = 0; i < STRATA_COUNT; i++)
    session->strata[i] = ibf_create (STRATA_IBF_BUCKETS, STRATA_HASH_NUM, 0);

  session->ibfs = GNUNET_malloc (MAX_IBF_ORDER * sizeof (struct InvertibleBloomFilter *));

  session->info = GNUNET_malloc (session->num_peers * sizeof (struct ConsensusPeerInformation));
  initialize_session_info (session);

  GNUNET_free (session->join_msg);
  session->join_msg = NULL;

  GNUNET_SERVER_receive_done (session->client, GNUNET_OK);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "session %s initialized\n", GNUNET_h2s (&session->global_id));
}


/**
 * Called when a client wants to join a consensus session.
 *
 * @param cls unused
 * @param client client that sent the message
 * @param m message sent by the client
 */
static void
client_join (void *cls,
             struct GNUNET_SERVER_Client *client,
             const struct GNUNET_MessageHeader *m)
{
  struct ConsensusSession *session;

  // make sure the client has not already joined a session
  session = sessions_head;
  while (NULL != session)
  {
    if (session->client == client)
    {
      GNUNET_break (0);
      disconnect_client (client);
      return;
    }
    session = session->next;
  }

  session = GNUNET_malloc (sizeof (struct ConsensusSession));
  session->join_msg = (struct GNUNET_CONSENSUS_JoinMessage *) GNUNET_copy_message (m);
  session->client = client;
  GNUNET_SERVER_client_keep (client);

  GNUNET_CONTAINER_DLL_insert (sessions_head, sessions_tail, session);

  // Initialize session later if local peer identity is not known yet.
  if (NULL == my_peer)
  {
    GNUNET_SERVER_disable_receive_done_warning (client);
    return;
  }

  initialize_session (session);
}


/**
 * Called when a client performs an insert operation.
 *
 * @param cls (unused)
 * @param client client handle
 * @param message message sent by the client
 */
void
client_insert (void *cls,
             struct GNUNET_SERVER_Client *client,
             const struct GNUNET_MessageHeader *m)
{
  struct ConsensusSession *session;
  struct GNUNET_CONSENSUS_ElementMessage *msg;
  struct GNUNET_CONSENSUS_Element *element;
  struct GNUNET_HashCode key;
  int element_size;

  session = sessions_head;
  while (NULL != session)
  {
    if (session->client == client)
      break;
  }

  if (NULL == session)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "client tried to insert, but client is not in any session\n");
    GNUNET_SERVER_client_disconnect (client);
    return;
  }

  msg = (struct GNUNET_CONSENSUS_ElementMessage *) m;
  element_size = ntohs (msg->header.size )- sizeof (struct GNUNET_CONSENSUS_ElementMessage);

  element = GNUNET_malloc (sizeof (struct GNUNET_CONSENSUS_Element) + element_size);

  element->type = msg->element_type;
  element->size = element_size;
  memcpy (&element[1], &msg[1], element_size);
  element->data = &element[1];

  GNUNET_assert (NULL != element->data);

  GNUNET_CRYPTO_hash (element, element_size, &key);

  GNUNET_CONTAINER_multihashmap_put (session->values, &key, element,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);

  strata_insert (session->strata, &key);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);

  send_next (session);
}



/**
 * Functions of this signature are called whenever writing operations
 * on a stream are executed
 *
 * @param cls the closure from GNUNET_STREAM_write
 * @param status the status of the stream at the time this function is called;
 *          GNUNET_STREAM_OK if writing to stream was completed successfully;
 *          GNUNET_STREAM_TIMEOUT if the given data is not sent successfully
 *          (this doesn't mean that the data is never sent, the receiver may
 *          have read the data but its ACKs may have been lost);
 *          GNUNET_STREAM_SHUTDOWN if the stream is shutdown for writing in the
 *          mean time; GNUNET_STREAM_SYSERR if the stream is broken and cannot
 *          be processed.
 * @param size the number of bytes written
 */
static void 
write_strata (void *cls, enum GNUNET_STREAM_Status status, size_t size)
{
  struct ConsensusPeerInformation *cpi;
  struct StrataMessage *strata_msg;
  size_t msize;
  int i;
  struct GNUNET_HashCode *hash_dst;
  uint8_t *count_dst;
  int num_strata;

  cpi = cls;
  cpi->wh = NULL;

  GNUNET_assert (GNUNET_YES == cpi->is_outgoing);

  /* FIXME: handle this */
  GNUNET_assert (GNUNET_STREAM_OK == status);

  if (STRATA_COUNT == cpi->strata_counter)
  {
    /* strata have been written, wait for other side's IBF */
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "strata written\n");
    return;
  }

  if ((STRATA_COUNT - cpi->strata_counter) < STRATA_PER_MESSAGE)
    num_strata = (STRATA_COUNT - cpi->strata_counter);
  else
    num_strata = STRATA_PER_MESSAGE;


  msize = (sizeof *strata_msg) + (num_strata * IBF_BUCKET_SIZE * STRATA_IBF_BUCKETS);

  strata_msg = GNUNET_malloc (msize);
  strata_msg->header.size = htons (msize);
  strata_msg->header.type = htons (GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_DELTA_ESTIMATE);
  strata_msg->num_strata = htons (num_strata);

  /* for correct message alignment, copy bucket types seperately */
  hash_dst = (struct GNUNET_HashCode *) &strata_msg[1];

  for (i = 0; i < num_strata; i++)
  {
    memcpy (hash_dst, cpi->session->strata[cpi->strata_counter+i]->hash_sum, STRATA_IBF_BUCKETS * sizeof *hash_dst);
    hash_dst += STRATA_IBF_BUCKETS;
  }

  for (i = 0; i < num_strata; i++)
  {
    memcpy (hash_dst, cpi->session->strata[cpi->strata_counter+i]->id_sum, STRATA_IBF_BUCKETS * sizeof *hash_dst);
    hash_dst += STRATA_IBF_BUCKETS;
  }

  count_dst = (uint8_t *) hash_dst;

  for (i = 0; i < num_strata; i++)
  {
    memcpy (count_dst, cpi->session->strata[cpi->strata_counter+i]->count, STRATA_IBF_BUCKETS);
    count_dst += STRATA_IBF_BUCKETS;
  }

  cpi->strata_counter += num_strata;

  cpi->wh = GNUNET_STREAM_write (cpi->socket, strata_msg, msize, GNUNET_TIME_UNIT_FOREVER_REL,
                                 write_strata, cpi);

  GNUNET_assert (NULL != cpi->wh);
}


/**
 * Functions of this signature are called whenever writing operations
 * on a stream are executed
 *
 * @param cls the closure from GNUNET_STREAM_write
 * @param status the status of the stream at the time this function is called;
 *          GNUNET_STREAM_OK if writing to stream was completed successfully;
 *          GNUNET_STREAM_TIMEOUT if the given data is not sent successfully
 *          (this doesn't mean that the data is never sent, the receiver may
 *          have read the data but its ACKs may have been lost);
 *          GNUNET_STREAM_SHUTDOWN if the stream is shutdown for writing in the
 *          mean time; GNUNET_STREAM_SYSERR if the stream is broken and cannot
 *          be processed.
 * @param size the number of bytes written
 */
static void 
write_ibf (void *cls, enum GNUNET_STREAM_Status status, size_t size)
{
  struct ConsensusPeerInformation *cpi;
  struct DifferenceDigest *digest;
  int msize;
  struct GNUNET_HashCode *hash_dst;
  uint8_t *count_dst;
  int num_buckets;

  cpi = cls;
  cpi->wh = NULL;

  if (cpi->outgoing_bucket_counter == (1 << cpi->ibf_order))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "ibf completely written\n");
    if (cpi->incoming_bucket_counter == (1 << cpi->ibf_order))
      write_values (cpi, GNUNET_STREAM_OK, 0);
    return;
  }

  /* remaining buckets */
  num_buckets = (1 << cpi->ibf_order) - cpi->outgoing_bucket_counter;

  /* limit to maximum */
  if (num_buckets > BUCKETS_PER_MESSAGE)
    num_buckets = BUCKETS_PER_MESSAGE;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "writing ibf buckets at %d/%d\n", cpi->outgoing_bucket_counter, (1<<cpi->ibf_order));

  msize = (sizeof *digest) + (num_buckets * IBF_BUCKET_SIZE);

  digest = GNUNET_malloc (msize);
  digest->header.size = htons (msize);
  digest->header.type = htons (GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_DIFFERENCE_DIGEST);
  digest->order = cpi->ibf_order;

  hash_dst = (struct GNUNET_HashCode *) &digest[1];

  memcpy (hash_dst, cpi->outgoing_ibf->hash_sum, num_buckets * sizeof *hash_dst);
  hash_dst += num_buckets;

  memcpy (hash_dst, cpi->outgoing_ibf->id_sum, num_buckets * sizeof *hash_dst);
  hash_dst += num_buckets;

  count_dst = (uint8_t *) hash_dst;

  memcpy (count_dst, cpi->outgoing_ibf->count, num_buckets * sizeof *count_dst);

  cpi->outgoing_bucket_counter += num_buckets;

  cpi->wh = GNUNET_STREAM_write (cpi->socket, digest, msize, GNUNET_TIME_UNIT_FOREVER_REL,
                                 write_ibf, cpi);

  GNUNET_assert (NULL != cpi->wh);
}


/**
 * Functions of this signature are called whenever writing operations
 * on a stream are executed
 *
 * @param cls the closure from GNUNET_STREAM_write
 * @param status the status of the stream at the time this function is called;
 *          GNUNET_STREAM_OK if writing to stream was completed successfully;
 *          GNUNET_STREAM_TIMEOUT if the given data is not sent successfully
 *          (this doesn't mean that the data is never sent, the receiver may
 *          have read the data but its ACKs may have been lost);
 *          GNUNET_STREAM_SHUTDOWN if the stream is shutdown for writing in the
 *          mean time; GNUNET_STREAM_SYSERR if the stream is broken and cannot
 *          be processed.
 * @param size the number of bytes written
 */
static void 
write_values (void *cls, enum GNUNET_STREAM_Status status, size_t size)
{
  struct ConsensusPeerInformation *cpi;
  struct GNUNET_HashCode key;
  struct GNUNET_CONSENSUS_Element *element;
  struct GNUNET_MessageHeader *element_msg;
  int side;
  int msize;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "transmitting value\n");

  cpi = cls;
  cpi->wh = NULL;

  if (NULL == cpi->diff_ibf)
  {
    GNUNET_assert (NULL != cpi->incoming_ibf);
    GNUNET_assert (NULL != cpi->outgoing_ibf);
    GNUNET_assert (cpi->outgoing_ibf->size == cpi->incoming_ibf->size);
    cpi->diff_ibf = ibf_dup (cpi->incoming_ibf);
    ibf_subtract (cpi->diff_ibf, cpi->outgoing_ibf);
  }

  for (;;)
  {
    int res;
    res = ibf_decode (cpi->diff_ibf, &side, &key);
    if (GNUNET_SYSERR == res)
    {
      /* TODO: handle this correctly, request new ibf */
      GNUNET_break (0);
      return;
    }
    if (GNUNET_NO == res)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "transmitted all values\n");
      return;
    }
    if (-1 == side)
      break;
  }

  element = GNUNET_CONTAINER_multihashmap_get (cpi->session->values, &key);

  if (NULL == element)
  {
    /* FIXME: handle correctly */
    GNUNET_break (0);
    return;
  }

  msize = sizeof (struct GNUNET_MessageHeader) + element->size;

  element_msg = GNUNET_malloc (msize);
  element_msg->size = htons (msize);
  element_msg->type = htons (GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_ELEMENTS);


  GNUNET_assert (NULL != element->data);


  memcpy (&element_msg[1], element->data, element->size);

  cpi->wh = GNUNET_STREAM_write (cpi->socket, element_msg, msize, GNUNET_TIME_UNIT_FOREVER_REL,
                                 write_values, cpi);

  GNUNET_free (element_msg);


  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "transmitted value\n");

  GNUNET_assert (NULL != cpi->wh);
}


/**
 * Called when a client performs the conclude operation.
 *
 * @param cls (unused)
 * @param client client handle
 * @param message message sent by the client
 */
void
client_conclude (void *cls,
             struct GNUNET_SERVER_Client *client,
             const struct GNUNET_MessageHeader *message)
{
  struct ConsensusSession *session;
  int i;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "conclude requested\n");

  session = sessions_head;
  while ((session != NULL) && (session->client != client))
    session = session->next;
  if (NULL == session)
  {
    /* client not found */
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (client);
    return;
  }

  if (GNUNET_YES == session->conclude_requested)
  {
    /* client requested conclude twice */
    GNUNET_break (0);
    disconnect_client (client);
    return;
  }

  session->conclude_requested = GNUNET_YES;

  /* FIXME: write to already connected sockets */

  for (i = 0; i < session->num_peers; i++)
  {
    if ( (GNUNET_YES == session->info[i].is_outgoing) &&
         (GNUNET_YES == session->info[i].hello) )
    {
      /* kick off transmitting strata by calling the write continuation */
      write_strata (&session->info[i], GNUNET_STREAM_OK, 0);
    }
  }

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  send_next (session);
}


/**
 * Called when a client sends an ack
 *
 * @param cls (unused)
 * @param client client handle
 * @param message message sent by the client
 */
void
client_ack (void *cls,
             struct GNUNET_SERVER_Client *client,
             const struct GNUNET_MessageHeader *message)
{
  struct ConsensusSession *session;
  struct GNUNET_CONSENSUS_AckMessage *msg;
  struct PendingElement *pending;
  struct GNUNET_CONSENSUS_Element *element;
  struct GNUNET_HashCode key;

  session = sessions_head;
  while (NULL != session)
  {
    if (session->client == client)
      break;
  }

  if (NULL == session)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "client tried to ack, but client is not in any session\n");
    GNUNET_SERVER_client_disconnect (client);
    return;
  }

  pending = session->approval_pending_head;

  GNUNET_CONTAINER_DLL_remove (session->approval_pending_head, session->approval_pending_tail, pending);

  msg = (struct GNUNET_CONSENSUS_AckMessage *) message;

  if (msg->keep)
  {

    element = pending->element;

    GNUNET_CRYPTO_hash (element, element->size, &key);

    GNUNET_CONTAINER_multihashmap_put (session->values, &key, element,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);

    strata_insert (session->strata, &key);
  }

  /* FIXME: also remove element from strata */

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}

/**
 * Task that disconnects from core.
 *
 * @param cls core handle
 * @param tc context information (why was this task triggered now)
 */
static void
disconnect_core (void *cls,
                 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_CORE_disconnect (core);
  core = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "disconnected from core\n");
}


static void
core_startup (void *cls,
              struct GNUNET_CORE_Handle *core,
              const struct GNUNET_PeerIdentity *peer)
{
  struct ConsensusSession *session;

  my_peer = GNUNET_memdup(peer, sizeof (struct GNUNET_PeerIdentity));
  /* core can't be disconnected directly in the core startup callback, schedule a task to do it! */
  GNUNET_SCHEDULER_add_now (&disconnect_core, core);
  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "connected to core\n");

  session = sessions_head;
  while (NULL != session)
  {
    if (NULL != session->join_msg)
      initialize_session (session);
    session = session->next;
  }
}


/**
 * Called to clean up, after a shutdown has been requested.
 *
 * @param cls closure
 * @param tc context information (why was this task triggered now)
 */
static void
shutdown_task (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{

  /* FIXME: complete; write separate destructors for different data types */

  while (NULL != incoming_sockets_head)
  {
    struct IncomingSocket *socket;
    socket = incoming_sockets_head;
    if (NULL == socket->cpi)
    {
      GNUNET_STREAM_close (socket->socket);
    }
    incoming_sockets_head = incoming_sockets_head->next;
    GNUNET_free (socket);
  }

  while (NULL != sessions_head)
  {
    struct ConsensusSession *session;
    int i;

    session = sessions_head;

    for (i = 0; session->num_peers; i++)
    {
      struct ConsensusPeerInformation *cpi;
      cpi = &session->info[i];
      if ((NULL != cpi) && (NULL != cpi->socket))
      {
        GNUNET_STREAM_close (cpi->socket);
      }
    }

    if (NULL != session->client)
      GNUNET_SERVER_client_disconnect (session->client);

    sessions_head = sessions_head->next;
    GNUNET_free (session);
  }

  if (NULL != core)
  {
    GNUNET_CORE_disconnect (core);
    core = NULL;
  }

  if (NULL != listener)
  {
    GNUNET_STREAM_listen_close (listener);
    listener = NULL;
  } 

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "handled shutdown request\n");
}


/**
 * Start processing consensus requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server, const struct GNUNET_CONFIGURATION_Handle *c)
{
  static const struct GNUNET_CORE_MessageHandler core_handlers[] = {
    {NULL, 0, 0}
  };
  static const struct GNUNET_SERVER_MessageHandler server_handlers[] = {
    {&client_join, NULL, GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_JOIN, 0},
    {&client_insert, NULL, GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_INSERT, 0},
    {&client_conclude, NULL, GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_CONCLUDE,
        sizeof (struct GNUNET_CONSENSUS_ConcludeMessage)},
    {&client_ack, NULL, GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_ACK,
        sizeof (struct GNUNET_CONSENSUS_AckMessage)},
    {NULL, NULL, 0, 0}
  };

  cfg = c;
  srv = server;

  GNUNET_SERVER_add_handlers (server, server_handlers);

  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task, NULL);


  listener = GNUNET_STREAM_listen (cfg, GNUNET_APPLICATION_TYPE_CONSENSUS,
                                   listen_cb, NULL,
                                   GNUNET_STREAM_OPTION_END);


  /* we have to wait for the core_startup callback before proceeding with the consensus service startup */
  core = GNUNET_CORE_connect (c, NULL, &core_startup, NULL, NULL, NULL, GNUNET_NO, NULL, GNUNET_NO, core_handlers);
  GNUNET_assert (NULL != core);

  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "consensus running\n");
}


/**
 * The main function for the consensus service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  int ret;
  ret = GNUNET_SERVICE_run (argc, argv, "consensus", GNUNET_SERVICE_OPTION_NONE, &run, NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "exit\n");
  return (GNUNET_OK == ret) ? 0 : 1;
}

