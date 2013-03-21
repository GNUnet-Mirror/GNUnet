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
 * @brief multi-peer set reconciliation
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
 * hash num parameter for the difference digests and strata estimators
 */
#define STRATA_HASH_NUM 3

/**
 * Number of buckets that can be transmitted in one message.
 */
#define BUCKETS_PER_MESSAGE ((1<<15) / IBF_BUCKET_SIZE)

/**
 * The maximum size of an ibf we use is 2^(MAX_IBF_ORDER).
 * Choose this value so that computing the IBF is still cheaper
 * than transmitting all values.
 */
#define MAX_IBF_ORDER (16)

/**
 * Number exp-rounds.
 */
#define NUM_EXP_ROUNDS (4)


/* forward declarations */

struct ConsensusSession;
struct IncomingSocket;
struct ConsensusPeerInformation;

static void
client_send_next (struct ConsensusSession *session);

static int
get_peer_idx (const struct GNUNET_PeerIdentity *peer, const struct ConsensusSession *session);

static void 
round_over (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

static void
send_ibf (struct ConsensusPeerInformation *cpi);

static void
send_strata_estimator (struct ConsensusPeerInformation *cpi);

static void
decode (struct ConsensusPeerInformation *cpi);

static void 
write_queued (void *cls, enum GNUNET_STREAM_Status status, size_t size);

static void
subround_over (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * An element that is waiting to be transmitted to the client.
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


struct ElementList
{
  struct ElementList *next;
  struct GNUNET_CONSENSUS_Element *element;
  struct GNUNET_HashCode *element_hash;
};


/**
 * Describes the current round a consensus session is in.
 */
enum ConsensusRound
{
  /**
   * Not started the protocol yet.
   */
  CONSENSUS_ROUND_BEGIN=0,
  /**
   * Distribution of elements with the exponential scheme.
   */
  CONSENSUS_ROUND_EXCHANGE,
  /**
   * Exchange which elements each peer has, but not the elements.
   */
  CONSENSUS_ROUND_INVENTORY,
  /**
   * Collect and distribute missing values.
   */
  CONSENSUS_ROUND_STOCK,
  /**
   * Consensus concluded.
   */
  CONSENSUS_ROUND_FINISH
};


/**
 * Information about a peer that is in a consensus session.
 */
struct ConsensusPeerInformation
{
  struct GNUNET_PeerIdentity peer_id;

  /**
   * Socket for communicating with the peer, either created by the local peer,
   * or the remote peer.
   */
  struct GNUNET_STREAM_Socket *socket;

  /**
   * Message tokenizer, for the data received from this peer via the stream socket.
   */
  struct GNUNET_SERVER_MessageStreamTokenizer *mst;

  /**
   * Do we connect to the peer, or does the peer connect to us?
   * Only valid for all-to-all phases
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

  enum {
    /* beginning of round */
    IBF_STATE_NONE=0,
    /* we currently receive an ibf */
    IBF_STATE_RECEIVING,
    /* we currently transmit an ibf */
    IBF_STATE_TRANSMITTING,
    /* we decode a received ibf */
    IBF_STATE_DECODING,
    /* wait for elements and element requests */
    IBF_STATE_ANTICIPATE_DIFF
  } ibf_state ;

  /**
   * What is the order (=log2 size) of the ibf
   * we're currently dealing with?
   * Interpretation depends on ibf_state.
   */
  int ibf_order;

  /**
   * The current IBF for this peer,
   * purpose dependent on ibf_state
   */
  struct InvertibleBloomFilter *ibf;

  /**
   * How many buckets have we transmitted/received? 
   * Interpretatin depends on ibf_state
   */
  int ibf_bucket_counter;

  /**
   * Strata estimator of the peer, NULL if our peer
   * initiated the reconciliation.
   */
  struct StrataEstimator *se;

  /**
   * Element keys that this peer misses, but we have them.
   */
  struct GNUNET_CONTAINER_MultiHashMap *requested_keys;

  /**
   * Element keys that this peer has, but we miss.
   */
  struct GNUNET_CONTAINER_MultiHashMap *reported_keys;

  /**
   * Back-reference to the consensus session,
   * to that ConsensusPeerInformation can be used as a closure
   */
  struct ConsensusSession *session;

  /**
   * Messages queued for the current round.
   */
  struct QueuedMessage *messages_head;

  /**
   * Messages queued for the current round.
   */
  struct QueuedMessage *messages_tail;

  /**
   * True if we are actually replaying the strata message,
   * e.g. currently handling the premature_strata_message.
   */
  int replaying_strata_message;

  /**
   * A strata message that is not actually for the current round,
   * used in the exp-scheme.
   */
  struct StrataMessage *premature_strata_message;

  /**
   * We have finishes the exp-subround with the peer.
   */
  int exp_subround_finished;

  int inventory_synced;

  /**
   * Round this peer seems to be in, according to the last SE we got.
   * Necessary to store this, as we sometimes need to respond to a request from an
   * older round, while we are already in the next round.
   */
  enum ConsensusRound apparent_round;

};

typedef void (*QueuedMessageCallback) (void *msg);

/**
 * A doubly linked list of messages.
 */
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

  QueuedMessageCallback cb;
  
  void *cls;
};


struct StrataEstimator
{
  struct InvertibleBloomFilter **strata;
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
  * from the session id and participating authorities.
  */
  struct GNUNET_HashCode global_id;

  /**
   * Local client in this consensus session.
   * There is only one client per consensus session.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Elements in the consensus set of this session,
   * all of them either have been sent by or approved by the client.
   * Contains ElementList.
   * Used as a unique-key hashmap.
   */
  struct GNUNET_CONTAINER_MultiHashMap *values;

  /**
   * Elements that have not been approved (or rejected) by the client yet.
   */
  struct PendingElement *client_approval_head;

  /**
   * Elements that have not been approved (or rejected) by the client yet.
   */
  struct PendingElement *client_approval_tail;

  /**
   * Messages to be sent to the local client that owns this session
   */
  struct QueuedMessage *client_messages_head;

  /**
   * Messages to be sent to the local client that owns this session
   */
  struct QueuedMessage *client_messages_tail;

  /**
   * Currently active transmit handle for sending to the client
   */
  struct GNUNET_SERVER_TransmitHandle *client_th;

  /**
   * Timeout for all rounds together, single rounds will schedule a timeout task
   * with a fraction of the conclude timeout.
   */
  struct GNUNET_TIME_Relative conclude_timeout;
  
  /**
   * Timeout task identifier for the current round
   */
  GNUNET_SCHEDULER_TaskIdentifier round_timeout_tid;

  /**
   * Number of other peers in the consensus
   */
  unsigned int num_peers;

  /**
   * Information about the other peers,
   * their state, etc.
   */
  struct ConsensusPeerInformation *info;

  /**
   * Index of the local peer in the peers array
   */
  int local_peer_idx;

  /**
   * Strata estimator, computed online
   */
  struct StrataEstimator *se;

  /**
   * Pre-computed IBFs
   */
  struct InvertibleBloomFilter **ibfs;

  /**
   * Current round
   */
  enum ConsensusRound current_round;

  int exp_round;

  int exp_subround;

  /**
   * Permutation of peers for the current round,
   * maps logical index (for current round) to physical index (location in info array)
   */
  int *shuffle;

  /**
   * The partner for the current exp-round
   */
  struct ConsensusPeerInformation* partner_outgoing;

  /**
   * The partner for the current exp-round
   */
  struct ConsensusPeerInformation* partner_incoming;
};


/**
 * Sockets from other peers who want to communicate with us.
 * It may not be known yet which consensus session they belong to.
 * Also, the session might not exist yet locally.
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
  struct GNUNET_PeerIdentity peer_id;

  /**
   * Message stream tokenizer for this socket.
   */
  struct GNUNET_SERVER_MessageStreamTokenizer *mst;

  /**
   * Peer-in-session this socket belongs to, once known, otherwise NULL.
   */
  struct ConsensusPeerInformation *cpi;

  /**
   * Set to the global session id, if the peer sent us a hello-message,
   * but the session does not exist yet.
   */
  struct GNUNET_HashCode *requested_gid;
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


/**
 * Queue a message to be sent to the inhabiting client of a session.
 *
 * @param session session
 * @param msg message we want to queue
 */
static void
queue_client_message (struct ConsensusSession *session, struct GNUNET_MessageHeader *msg)
{
  struct QueuedMessage *qm;
  qm = GNUNET_malloc (sizeof *qm);
  qm->msg = msg;
  GNUNET_CONTAINER_DLL_insert_tail (session->client_messages_head, session->client_messages_tail, qm);
}

/**
 * Queue a message to be sent to another peer
 *
 * @param cpi peer
 * @param msg message we want to queue
 * @param cb callback, called when the message is given to strem
 * @param cls closure for cb
 */
static void
queue_peer_message_with_cls (struct ConsensusPeerInformation *cpi, struct GNUNET_MessageHeader *msg, QueuedMessageCallback cb, void *cls)
{
  struct QueuedMessage *qm;
  qm = GNUNET_malloc (sizeof *qm);
  qm->msg = msg;
  qm->cls = cls;
  qm->cb = cb;
  GNUNET_CONTAINER_DLL_insert_tail (cpi->messages_head, cpi->messages_tail, qm);
  if (cpi->wh == NULL)
    write_queued (cpi, GNUNET_STREAM_OK, 0);
}


/**
 * Queue a message to be sent to another peer
 *
 * @param cpi peer
 * @param msg message we want to queue
 */
static void
queue_peer_message (struct ConsensusPeerInformation *cpi, struct GNUNET_MessageHeader *msg)
{
  queue_peer_message_with_cls (cpi, msg, NULL, NULL);
}


/*
static void
clear_peer_messages (struct ConsensusPeerInformation *cpi)
{
  cpi->messages_head = NULL;
  cpi->messages_tail = NULL;
}
*/


/**
 * Estimate set difference with two strata estimators,
 * i.e. arrays of IBFs.
 * Does not not modify its arguments.
 *
 * @param se1 first strata estimator
 * @param se2 second strata estimator
 * @return the estimated difference
 */
static int
estimate_difference (const struct StrataEstimator *se1,
                     const struct StrataEstimator *se2)
{
  int i;
  int count;
  count = 0;
  for (i = STRATA_COUNT - 1; i >= 0; i--)
  {
    struct InvertibleBloomFilter *diff;
    /* number of keys decoded from the ibf */
    int ibf_count;
    int more;
    ibf_count = 0;
    /* FIXME: implement this without always allocating new IBFs */
    diff = ibf_dup (se1->strata[i]);
    ibf_subtract (diff, se2->strata[i]);
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
        ibf_destroy (diff);
        return count * (1 << (i + 1));
      }
      ibf_count++;
    }
    ibf_destroy (diff);
  }
  return count;
}


/**
 * Called when receiving data from a peer that is member of
 * an inhabited consensus session.
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
 * Called when we receive data from a peer that is not member of
 * a session yet, or the session is not yet inhabited.
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


static void
send_elements (struct ConsensusPeerInformation *cpi, struct ElementList *head)
{
  struct GNUNET_CONSENSUS_Element *element;
  struct GNUNET_MessageHeader *element_msg;
  size_t msize;

  while (NULL != head)
  {
    element = head->element;
    msize = sizeof (struct GNUNET_MessageHeader) + element->size;
    element_msg = GNUNET_malloc (msize);
    element_msg->size = htons (msize);
    switch (cpi->apparent_round)
    {
      case CONSENSUS_ROUND_STOCK:
      case CONSENSUS_ROUND_EXCHANGE:
        element_msg->type = htons (GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_ELEMENTS);
        break;
      case CONSENSUS_ROUND_INVENTORY:
        element_msg->type = htons (GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_ELEMENTS_REPORT);
        break;
      default:
        GNUNET_break (0);
    }
    GNUNET_assert (NULL != element->data);
    memcpy (&element_msg[1], element->data, element->size);
    queue_peer_message (cpi, element_msg);
    head = head->next;
  }
}

/**
 * Iterator to insert values into an ibf.
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
  struct ElementList *head;
  struct IBF_Key ibf_key;
  cpi = cls;
  head = value;
  ibf_key = ibf_key_from_hashcode (head->element_hash);
  GNUNET_assert (ibf_key.key_val == ibf_key_from_hashcode (key).key_val);
  ibf_insert (cpi->session->ibfs[cpi->ibf_order], ibf_key);
  return GNUNET_YES;
}

/**
 * Create and populate an IBF for the specified peer,
 * if it does not already exist.
 *
 * @param cpi peer to create the ibf for
 */
static void
prepare_ibf (struct ConsensusPeerInformation *cpi)
{
  if (NULL == cpi->session->ibfs[cpi->ibf_order])
  {
    cpi->session->ibfs[cpi->ibf_order] = ibf_create (1 << cpi->ibf_order, STRATA_HASH_NUM, 0);
    GNUNET_CONTAINER_multihashmap_iterate (cpi->session->values, ibf_values_iterator, cpi);
  }
}


/**
 * Called when a remote peer wants to inform the local peer
 * that the remote peer misses elements.
 * Elements are not reconciled.
 *
 * @param cpi session
 * @param msg message
 */
static int
handle_p2p_element_report (struct ConsensusPeerInformation *cpi, const struct GNUNET_MessageHeader *msg)
{
  GNUNET_assert (0);
}


static int
exp_subround_finished (const struct ConsensusSession *session)
{
  int not_finished;
  not_finished = 0;
  if ((session->partner_outgoing != NULL) && (session->partner_outgoing->exp_subround_finished == GNUNET_NO))
      not_finished++;
  if ((session->partner_incoming != NULL) && (session->partner_incoming->exp_subround_finished == GNUNET_NO))
      not_finished++;
  if (0 == not_finished)
    return GNUNET_YES;
  return GNUNET_NO;
}

static int
inventory_round_finished (struct ConsensusSession *session)
{
  int i;
  int finished;
  finished = 0;
  for (i = 0; i < session->num_peers; i++)
    if (GNUNET_YES == session->info[i].inventory_synced)
      finished++;
  if (finished >= (session->num_peers / 2))
    return GNUNET_YES;
  return GNUNET_NO;
}



static void
fin_sent_cb (void *cls)
{
  struct ConsensusPeerInformation *cpi;
  cpi = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "P%d: sent FIN\n", cpi->session->local_peer_idx);
  switch (cpi->session->current_round)
  {
    case CONSENSUS_ROUND_EXCHANGE:
    case CONSENSUS_ROUND_STOCK:
      if (cpi->session->current_round != cpi->apparent_round)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_INFO, "P%d: FIN to SYNC from the past\n", cpi->session->local_peer_idx);
        break;
      }
      cpi->exp_subround_finished = GNUNET_YES;
      /* the subround is only really over if *both* partners are done */
      if (GNUNET_YES == exp_subround_finished (cpi->session))
        subround_over (cpi->session, NULL);
      else
        GNUNET_log (GNUNET_ERROR_TYPE_INFO, "P%d: still waiting for more after FIN sent\n", cpi->session->local_peer_idx);
      break;
    case CONSENSUS_ROUND_INVENTORY:
      cpi->inventory_synced = GNUNET_YES;
      if (inventory_round_finished (cpi->session) && cpi->session->current_round == cpi->apparent_round)
        round_over (cpi->session, NULL);
      /* FIXME: maybe go to next round */
      break;
    default:
      GNUNET_break (0);
  }
}


/**
 * Gets called when the other peer wants us to inform that
 * it has decoded our ibf and sent us all elements / requests
 */
static int
handle_p2p_synced (struct ConsensusPeerInformation *cpi, const struct GNUNET_MessageHeader *msg)
{
  struct ConsensusRoundMessage *fin_msg;

  switch (cpi->session->current_round)
  {
    case CONSENSUS_ROUND_INVENTORY:
      cpi->inventory_synced = GNUNET_YES;
    case CONSENSUS_ROUND_STOCK:
    case CONSENSUS_ROUND_EXCHANGE:
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "P%d: got SYNC from P%d\n", cpi->session->local_peer_idx, (int) (cpi - cpi->session->info));
      fin_msg = GNUNET_malloc (sizeof *fin_msg);
      fin_msg->header.type = htons (GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_FIN);
      fin_msg->header.size = htons (sizeof *fin_msg);
      fin_msg->round = cpi->apparent_round;
      /* the subround os over once we kicked off sending the fin msg */
      /* FIXME: assert we are talking to the right peer! */
      queue_peer_message_with_cls (cpi, (struct GNUNET_MessageHeader *) fin_msg, fin_sent_cb, cpi);
      /* FIXME: mark peer as synced */
      break;
    default:
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "unexpected SYNCED message the current round\n");
      break;
  }
  return GNUNET_YES;
}


/**
 * The other peer wants us to inform that he sent us all the elements we requested.
 */
static int
handle_p2p_fin (struct ConsensusPeerInformation *cpi, const struct GNUNET_MessageHeader *msg)
{
  struct ConsensusRoundMessage *round_msg;
  round_msg = (struct ConsensusRoundMessage *) msg;
  /* FIXME: only call subround_over if round is the current one! */
  switch (cpi->session->current_round)
  {
    case CONSENSUS_ROUND_EXCHANGE:
    case CONSENSUS_ROUND_STOCK:
      if (cpi->session->current_round != round_msg->round)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_INFO, "P%d: got FIN from P%d (past round)\n", cpi->session->local_peer_idx, (int) (cpi - cpi->session->info));
        cpi->ibf_state = IBF_STATE_NONE;
        cpi->ibf_bucket_counter = 0;
        break;
      }
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "P%d: got FIN from P%d (exp)\n", cpi->session->local_peer_idx, (int) (cpi - cpi->session->info));
      cpi->exp_subround_finished = GNUNET_YES;
      if (GNUNET_YES == exp_subround_finished (cpi->session))
        subround_over (cpi->session, NULL);
      else
        GNUNET_log (GNUNET_ERROR_TYPE_INFO, "P%d: still waiting for more after got FIN\n", cpi->session->local_peer_idx);
    break;
    case CONSENSUS_ROUND_INVENTORY:
      cpi->inventory_synced = GNUNET_YES;
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "P%d: got FIN from P%d (a2a)\n", cpi->session->local_peer_idx, (int) (cpi - cpi->session->info));
      if (inventory_round_finished (cpi->session))
        round_over (cpi->session, NULL);
      break;
    default:
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "unexpected FIN message the current round\n");
      break;
  }
  return GNUNET_YES;
}


static struct StrataEstimator *
strata_estimator_create ()
{
  struct StrataEstimator *se;
  int i;

  /* fixme: allocate everything in one chunk */

  se = GNUNET_malloc (sizeof (struct StrataEstimator));
  se->strata = GNUNET_malloc (sizeof (struct InvertibleBloomFilter) * STRATA_COUNT);
  for (i = 0; i < STRATA_COUNT; i++)
    se->strata[i] = ibf_create (STRATA_IBF_BUCKETS, STRATA_HASH_NUM, 0);

  return se;
}

static void
strata_estimator_destroy (struct StrataEstimator *se)
{
  int i;
  for (i = 0; i < STRATA_COUNT; i++)
    ibf_destroy (se->strata[i]);
  GNUNET_free (se->strata);
  GNUNET_free (se);
}


static int
is_premature_strata_message (const struct ConsensusSession *session, const struct StrataMessage *strata_msg)
{
  switch (strata_msg->round)
  {
    case CONSENSUS_ROUND_STOCK:
    case CONSENSUS_ROUND_EXCHANGE:
      /* here, we also have to compare subrounds */
      if ( (strata_msg->round != session->current_round) ||
           (strata_msg->exp_round != session->exp_round) ||
           (strata_msg->exp_subround != session->exp_subround))
        return GNUNET_YES;
      break;
    default:
      if (session->current_round != strata_msg->round)
        return GNUNET_YES;
    break;
  }
  return GNUNET_NO;
}


/**
 * Called when a peer sends us its strata estimator.
 * In response, we sent out IBF of appropriate size back.
 *
 * @param cpi session
 * @param strata_msg message
 */
static int
handle_p2p_strata (struct ConsensusPeerInformation *cpi, const struct StrataMessage *strata_msg)
{
  int i; // unsigned?
  unsigned int diff;
  void *buf;
  size_t size;

  if ((cpi->session->current_round == CONSENSUS_ROUND_STOCK) && (strata_msg->round == CONSENSUS_ROUND_INVENTORY))
  {
    /* we still have to handle this request appropriately */
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "P%d: got inventory SE from P%d, we are already further alog\n",
                cpi->session->local_peer_idx, (int) (cpi - cpi->session->info));
  }
  else if (is_premature_strata_message (cpi->session, strata_msg))
  {
    if (GNUNET_NO == cpi->replaying_strata_message)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "P%d: got probably premature SE from P%d, (%d,%d)\n",
                  cpi->session->local_peer_idx, (int) (cpi - cpi->session->info), strata_msg->exp_round, strata_msg->exp_subround);
      cpi->premature_strata_message = (struct StrataMessage *) GNUNET_copy_message ((struct GNUNET_MessageHeader *) strata_msg);
    }
    return GNUNET_YES;
  }

  if (NULL == cpi->se)
    cpi->se = strata_estimator_create ();

  cpi->apparent_round = strata_msg->round;

  size = ntohs (strata_msg->header.size);
  buf = (void *) &strata_msg[1]; // FIXME: do NOT cast away 'const'!
  for (i = 0; i < STRATA_COUNT; i++)
  {
    int res;
    res = ibf_read (&buf, &size, cpi->se->strata[i]);
    GNUNET_assert (GNUNET_OK == res);
  }

  diff = estimate_difference (cpi->session->se, cpi->se);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "P%d: got SE from P%d, diff=%d\n",
              cpi->session->local_peer_idx, (int) (cpi - cpi->session->info), diff);

  switch (cpi->session->current_round)
  {
    case CONSENSUS_ROUND_EXCHANGE:
    case CONSENSUS_ROUND_INVENTORY:
    case CONSENSUS_ROUND_STOCK:
      /* send IBF of the right size */
      cpi->ibf_order = 0;
      while (((1 << cpi->ibf_order) < diff) || STRATA_HASH_NUM > (1 << cpi->ibf_order) )
        cpi->ibf_order++;
      if (cpi->ibf_order > MAX_IBF_ORDER)
        cpi->ibf_order = MAX_IBF_ORDER;
      cpi->ibf_order += 1;
      /* create ibf if not already pre-computed */
      prepare_ibf (cpi);
      if (NULL != cpi->ibf)
        ibf_destroy (cpi->ibf);
      cpi->ibf = ibf_dup (cpi->session->ibfs[cpi->ibf_order]);
      cpi->ibf_state = IBF_STATE_TRANSMITTING;
      cpi->ibf_bucket_counter = 0;
      send_ibf (cpi);
      break;
    default:
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "P%d: got unexpected SE from P%d\n",
                  cpi->session->local_peer_idx, (int) (cpi - cpi->session->info));
      break;
  }
  return GNUNET_YES;
}


static int
handle_p2p_ibf (struct ConsensusPeerInformation *cpi, const struct DifferenceDigest *digest)
{
  int num_buckets;
  void *buf;

  /* FIXME: find out if we're still expecting the same ibf! */

  cpi->apparent_round = cpi->session->current_round;
  // FIXME: check header.size >= sizeof (DD)
  num_buckets = (ntohs (digest->header.size) - (sizeof *digest)) / IBF_BUCKET_SIZE;
  switch (cpi->ibf_state)
  {
    case IBF_STATE_NONE:
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "P%d: receiving IBF from P%d\n", cpi->session->local_peer_idx, (int) (cpi - cpi->session->info));
      cpi->ibf_state = IBF_STATE_RECEIVING;
      cpi->ibf_order = digest->order;
      cpi->ibf_bucket_counter = 0;
      if (NULL != cpi->ibf)
      {
        ibf_destroy (cpi->ibf);
        cpi->ibf = NULL;
      }
      break;
    case IBF_STATE_ANTICIPATE_DIFF:
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "P%d: receiving IBF from P%d (probably out IBF did not decode)\n",
                  cpi->session->local_peer_idx, (int) (cpi - cpi->session->info));
      cpi->ibf_state = IBF_STATE_RECEIVING;
      cpi->ibf_order = digest->order;
      cpi->ibf_bucket_counter = 0;
      if (NULL != cpi->ibf)
      {
        ibf_destroy (cpi->ibf);
        cpi->ibf = NULL;
      }
      break;
    case IBF_STATE_RECEIVING:
      break;
    default:
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "P%d: unexpected IBF from P%d\n", cpi->session->local_peer_idx, (int) (cpi - cpi->session->info));
      return GNUNET_YES;
  }

  if (cpi->ibf_bucket_counter + num_buckets > (1 << cpi->ibf_order))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "P%d: overfull IBF from P%d\n", cpi->session->local_peer_idx, (int) (cpi - cpi->session->info));
    return GNUNET_YES;
  }


  if (NULL == cpi->ibf)
    cpi->ibf = ibf_create (1 << cpi->ibf_order, STRATA_HASH_NUM, 0);

  buf = (void *) &digest[1]; // FIXME: digest is supposed to be READ ONLY!
  ibf_read_slice (&buf, NULL, cpi->ibf_bucket_counter, num_buckets, cpi->ibf);

  cpi->ibf_bucket_counter += num_buckets;

  if (cpi->ibf_bucket_counter == (1 << cpi->ibf_order))
  {
    cpi->ibf_state = IBF_STATE_DECODING;
    cpi->ibf_bucket_counter = 0;
    prepare_ibf (cpi);
    ibf_subtract (cpi->ibf, cpi->session->ibfs[cpi->ibf_order]);
    decode (cpi);
  }
  return GNUNET_YES;
}


/**
 * Handle an element that another peer sent us
 */
static int
handle_p2p_element (struct ConsensusPeerInformation *cpi, const struct GNUNET_MessageHeader *element_msg)
{
  struct PendingElement *pending_element;
  struct GNUNET_CONSENSUS_Element *element;
  struct GNUNET_CONSENSUS_ElementMessage *client_element_msg;
  size_t size;

  switch (cpi->session->current_round)
  {
    case CONSENSUS_ROUND_STOCK:
      /* FIXME: check if we really expect the element */
    case CONSENSUS_ROUND_EXCHANGE:
      break;
    default:
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "got unexpected element, ignoring\n");
      return GNUNET_YES;
  }

  size = ntohs (element_msg->size) - sizeof *element_msg;

  element = GNUNET_malloc (size + sizeof *element);
  element->size = size;
  memcpy (&element[1], &element_msg[1], size);
  element->data = &element[1];

  pending_element = GNUNET_malloc (sizeof *pending_element);
  pending_element->element = element;
  GNUNET_CONTAINER_DLL_insert_tail (cpi->session->client_approval_head, cpi->session->client_approval_tail, pending_element);

  client_element_msg = GNUNET_malloc (size + sizeof *client_element_msg);
  client_element_msg->header.type = htons (GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_RECEIVED_ELEMENT);
  client_element_msg->header.size = htons (size + sizeof *client_element_msg);
  memcpy (&client_element_msg[1], &element[1], size);

  queue_client_message (cpi->session, (struct GNUNET_MessageHeader *) client_element_msg);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "received element, size=%d\n", size);

  client_send_next (cpi->session);
  
  return GNUNET_YES;
}


/**
 * Handle a request for elements.
 * 
 * @param cpi peer that is requesting the element
 * @param msg the element request message
 */
static int
handle_p2p_element_request (struct ConsensusPeerInformation *cpi, const struct ElementRequest *msg)
{
  struct GNUNET_HashCode hashcode;
  struct IBF_Key *ibf_key;
  unsigned int num;

  /* element requests are allowed in every round */

  num = ntohs (msg->header.size) / sizeof (struct IBF_Key);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "handling element request for %u elements\n", num);
  
  ibf_key = (struct IBF_Key *) &msg[1];
  while (num--)
  {
    struct ElementList *head;
    ibf_hashcode_from_key (*ibf_key, &hashcode);
    head = GNUNET_CONTAINER_multihashmap_get (cpi->session->values, &hashcode);
    send_elements (cpi, head);
    ibf_key++;
  }
  return GNUNET_YES;
}

/**
 * If necessary, send a message to the peer, depending on the current
 * round.
 */
static void
embrace_peer (struct ConsensusPeerInformation *cpi)
{
  GNUNET_assert (GNUNET_YES == cpi->hello);
  switch (cpi->session->current_round)
  {
    case CONSENSUS_ROUND_EXCHANGE:
      if (cpi->session->partner_outgoing != cpi)
        break;
      /* fallthrough */
    case CONSENSUS_ROUND_INVENTORY:
      /* fallthrough */
    case CONSENSUS_ROUND_STOCK:
      if (cpi == cpi->session->partner_outgoing)
        send_strata_estimator (cpi);
    default:
      break;
  }
}


/**
 * Handle a HELLO-message, send when another peer wants to join a session where
 * our peer is a member. The session may or may not be inhabited yet.
 */
static int
handle_p2p_hello (struct IncomingSocket *inc, const struct ConsensusHello *hello)
{
  /* FIXME: session might not exist yet. create an uninhabited session and wait for a client */
  struct ConsensusSession *session;
  int idx;

  for (session = sessions_head; NULL != session; session = session->next)
  {
    if (0 != GNUNET_CRYPTO_hash_cmp (&session->global_id, &hello->global_id))
      continue;
    idx = get_peer_idx (&inc->peer_id, session);
    GNUNET_assert (-1 != idx);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "peer %d hello'ed session %d\n", idx);
    inc->cpi = &session->info[idx];
    inc->cpi->mst = inc->mst;
    inc->cpi->hello = GNUNET_YES;
    inc->cpi->socket = inc->socket;
    embrace_peer (inc->cpi);
    return GNUNET_YES;        
  }
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "peer tried to HELLO uninhabited session\n");
  return GNUNET_NO;
}


/**
 * Send a strata estimator.
 *
 * @param cpi the peer
 */
static void
send_strata_estimator (struct ConsensusPeerInformation *cpi)
{
  struct StrataMessage *strata_msg;
  void *buf;
  size_t msize;
  int i;

  cpi->apparent_round = cpi->session->current_round;
  cpi->ibf_state = IBF_STATE_NONE;
  cpi->ibf_bucket_counter = 0;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "P%d: sending SE(%d) to P%d\n",
              cpi->session->local_peer_idx, cpi->session->current_round, (int) (cpi - cpi->session->info));

  msize = (sizeof *strata_msg) + (STRATA_COUNT * IBF_BUCKET_SIZE * STRATA_IBF_BUCKETS);

  strata_msg = GNUNET_malloc (msize);
  strata_msg->header.size = htons (msize);
  strata_msg->header.type = htons (GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_DELTA_ESTIMATE);
  strata_msg->round = cpi->session->current_round;
  strata_msg->exp_round = cpi->session->exp_round;
  strata_msg->exp_subround = cpi->session->exp_subround;
  
  buf = &strata_msg[1];
  for (i = 0; i < STRATA_COUNT; i++)
  {
    ibf_write (cpi->session->se->strata[i], &buf, NULL);
  }

  queue_peer_message (cpi, (struct GNUNET_MessageHeader *) strata_msg);
}


/**
 * Send an IBF of the order specified in cpi.
 *
 * @param cpi the peer
 */
static void
send_ibf (struct ConsensusPeerInformation *cpi)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "P%d: sending IBF to P%d\n",
              cpi->session->local_peer_idx, (int) (cpi - cpi->session->info));

  cpi->ibf_bucket_counter = 0;
  while (cpi->ibf_bucket_counter < (1 << cpi->ibf_order))
  {
    int num_buckets;
    void *buf;
    struct DifferenceDigest *digest;
    int msize;

    num_buckets = (1 << cpi->ibf_order) - cpi->ibf_bucket_counter;
    /* limit to maximum */
    if (num_buckets > BUCKETS_PER_MESSAGE)
      num_buckets = BUCKETS_PER_MESSAGE;

    msize = (sizeof *digest) + (num_buckets * IBF_BUCKET_SIZE);

    digest = GNUNET_malloc (msize);
    digest->header.size = htons (msize);
    digest->header.type = htons (GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_DIFFERENCE_DIGEST);
    digest->order = cpi->ibf_order;
    digest->round = cpi->apparent_round;

    buf = &digest[1];
    ibf_write_slice (cpi->ibf, cpi->ibf_bucket_counter, num_buckets, &buf, NULL);

    queue_peer_message (cpi, (struct GNUNET_MessageHeader *) digest);

    cpi->ibf_bucket_counter += num_buckets;
  }
  cpi->ibf_bucket_counter = 0;
  cpi->ibf_state = IBF_STATE_ANTICIPATE_DIFF;
}


/**
 * Decode the current diff ibf, and send elements/requests/reports/
 *
 * @param cpi partner peer
 */
static void
decode (struct ConsensusPeerInformation *cpi)
{
  struct IBF_Key key;
  struct GNUNET_HashCode hashcode;
  int side;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "P%d: decoding ibf from P%d\n", cpi->session->local_peer_idx, (int) (cpi - cpi->session->info));

  while (1)
  {
    int res;

    res = ibf_decode (cpi->ibf, &side, &key);
    if (GNUNET_SYSERR == res)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "decoding failed, transmitting larger IBF\n");
      /* decoding failed, we tell the other peer by sending our ibf with a larger order */
      cpi->ibf_order++;
      prepare_ibf (cpi);
      cpi->ibf = ibf_dup (cpi->session->ibfs[cpi->ibf_order]);
      cpi->ibf_state = IBF_STATE_TRANSMITTING;
      cpi->ibf_bucket_counter = 0;
      send_ibf (cpi);
      return;
    }
    if (GNUNET_NO == res)
    {
      struct ConsensusRoundMessage *msg;
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "P%d: transmitted all values, sending SYNC\n", cpi->session->local_peer_idx);
      msg = GNUNET_malloc (sizeof *msg);
      msg->header.size = htons (sizeof *msg);
      msg->header.type = htons (GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_SYNCED);
      msg->round = cpi->apparent_round;
      queue_peer_message (cpi, (struct GNUNET_MessageHeader *) msg);
      return;
    }
    if (-1 == side)
    {
      struct ElementList *head;
      /* we have the element(s), send it to the other peer */
      ibf_hashcode_from_key (key, &hashcode);
      head = GNUNET_CONTAINER_multihashmap_get (cpi->session->values, &hashcode);
      send_elements (cpi, head);
    }
    else
    {
      struct ElementRequest *msg;
      size_t msize;
      struct IBF_Key *p;

      msize = (sizeof *msg) + sizeof (struct IBF_Key);
      msg = GNUNET_malloc (msize);
      switch (cpi->apparent_round)
      {
        case CONSENSUS_ROUND_STOCK:
          /* FIXME: check if we really want to request the element */
        case CONSENSUS_ROUND_EXCHANGE:
          msg->header.type = htons (GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_ELEMENTS_REQUEST);
          break;
        case CONSENSUS_ROUND_INVENTORY:
          msg->header.type = htons (GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_ELEMENTS_REPORT);
          break;
        default:
          GNUNET_assert (0);
      }
      msg->header.size = htons (msize);
      p = (struct IBF_Key *) &msg[1];
      *p = key;
      queue_peer_message (cpi, (struct GNUNET_MessageHeader *) msg);
    }
  }
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
    case GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_ELEMENTS_REPORT:
      return handle_p2p_element_report (cpi, message);
    case GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_ELEMENTS_REQUEST:
      return handle_p2p_element_request (cpi, (struct ElementRequest *) message);
    case GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_SYNCED:
      return handle_p2p_synced (cpi, message);
    case GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_FIN:
      return handle_p2p_fin (cpi, message);
    default:
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "ignoring unexpected message type (%u) from peer: %s\n",
                  ntohs (message->type), GNUNET_h2s (&cpi->peer_id.hashPubKey));
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
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "ignoring unexpected message type (%u) from peer: %s (not in session)\n",
                  ntohs (message->type), GNUNET_h2s (&inc->peer_id.hashPubKey));
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
  incoming->peer_id = *initiator;
  incoming->rh = GNUNET_STREAM_read (socket, GNUNET_TIME_UNIT_FOREVER_REL,
                                     &incoming_stream_data_processor, incoming);
  incoming->mst = GNUNET_SERVER_mst_create (mst_incoming_callback, incoming);
  GNUNET_CONTAINER_DLL_insert_tail (incoming_sockets_head, incoming_sockets_tail, incoming);
  return GNUNET_OK;
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
destroy_element_list_iter (void *cls,
                           const struct GNUNET_HashCode * key,
                           void *value)
{
  struct ElementList *el;
  el = value;
  while (NULL != el)
  {
    struct ElementList *el_old;
    el_old = el;
    el = el->next;
    GNUNET_free (el_old->element_hash);
    GNUNET_free (el_old->element);
    GNUNET_free (el_old);
  }
  return GNUNET_YES;
}


/**
 * Destroy a session, free all resources associated with it.
 * 
 * @param session the session to destroy
 */
static void
destroy_session (struct ConsensusSession *session)
{
  int i;

  GNUNET_CONTAINER_DLL_remove (sessions_head, sessions_tail, session);
  GNUNET_SERVER_client_drop (session->client);
  session->client = NULL;
  if (NULL != session->shuffle)
  {
    GNUNET_free (session->shuffle);
    session->shuffle = NULL;
  }
  if (NULL != session->se)
  {
    strata_estimator_destroy (session->se);
    session->se = NULL;
  }
  if (NULL != session->info)
  {
    for (i = 0; i < session->num_peers; i++)
    {
      struct ConsensusPeerInformation *cpi;
      cpi = &session->info[i];
      if ((NULL != cpi) && (NULL != cpi->socket))
      {
        if (NULL != cpi->rh)
        {
          GNUNET_STREAM_read_cancel (cpi->rh);
          cpi->rh = NULL;
        } 
        if (NULL != cpi->wh)
        {
          GNUNET_STREAM_write_cancel (cpi->wh);
          cpi->wh = NULL;
        } 
        GNUNET_STREAM_close (cpi->socket);
        cpi->socket = NULL;
      }
      if (NULL != cpi->se)
      {
        strata_estimator_destroy (cpi->se);
        cpi->se = NULL;
      }
      if (NULL != cpi->ibf)
      {
        ibf_destroy (cpi->ibf);
        cpi->ibf = NULL;
      }
      if (NULL != cpi->mst)
      {
        GNUNET_SERVER_mst_destroy (cpi->mst);
        cpi->mst = NULL;
      }
    }
    GNUNET_free (session->info);
    session->info = NULL;
  }
  if (NULL != session->ibfs)
  {
    for (i = 0; i <= MAX_IBF_ORDER; i++)
    {
      if (NULL != session->ibfs[i])
      {
        ibf_destroy (session->ibfs[i]);
        session->ibfs[i] = NULL;
      }
    }
    GNUNET_free (session->ibfs);
    session->ibfs = NULL;
  }
  if (NULL != session->values)
  {
    GNUNET_CONTAINER_multihashmap_iterate (session->values, destroy_element_list_iter, NULL);
    GNUNET_CONTAINER_multihashmap_destroy (session->values);
    session->values = NULL;
  }
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
 * @param session session to generate the global id for
 * @param session_id local id of the consensus session
 */
static void
compute_global_id (struct ConsensusSession *session, const struct GNUNET_HashCode *session_id)
{
  int i;
  struct GNUNET_HashCode tmp;

  session->global_id = *session_id;
  for (i = 0; i < session->num_peers; ++i)
  {
    GNUNET_CRYPTO_hash_xor (&session->global_id, &session->info[i].peer_id.hashPubKey, &tmp);
    session->global_id = tmp;
    GNUNET_CRYPTO_hash (&session->global_id, sizeof (struct GNUNET_PeerIdentity), &tmp);
    session->global_id = tmp;
  }
}


/**
 * Transmit a queued message to the session's client.
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
  session->client_th = NULL;

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

  client_send_next (session);

  return msg_size;
}


/**
 * Schedule transmitting the next queued message (if any) to the inhabiting client of a session.
 *
 * @param session the consensus session
 */
static void
client_send_next (struct ConsensusSession *session)
{

  GNUNET_assert (NULL != session);

  if (NULL != session->client_th)
    return;

  if (NULL != session->client_messages_head)
  {
    int msize;
    msize = ntohs (session->client_messages_head->msg->size);
    session->client_th = GNUNET_SERVER_notify_transmit_ready (session->client, msize, 
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
hash_cmp (const void *h1, const void *h2)
{
  return GNUNET_CRYPTO_hash_cmp ((struct GNUNET_HashCode *) h1, (struct GNUNET_HashCode *) h2);
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
  int i;
  for (i = 0; i < session->num_peers; i++)
    if (0 == memcmp (peer, &session->info[i].peer_id, sizeof *peer))
      return i;
  return -1;
}


/**
 * Called when stream has finishes writing the hello message
 */
static void
hello_cont (void *cls, enum GNUNET_STREAM_Status status, size_t size)
{
  struct ConsensusPeerInformation *cpi;

  cpi = cls;
  cpi->wh = NULL;
  cpi->hello = GNUNET_YES;
  GNUNET_assert (GNUNET_STREAM_OK == status);
  embrace_peer (cpi);
}


/**
 * Called when we established a stream connection to another peer
 *
 * @param cls cpi of the peer we just connected to
 * @param socket socket to use to communicate with the other side (read/write)
 */
static void
open_cb (void *cls, struct GNUNET_STREAM_Socket *socket)
{
  struct ConsensusPeerInformation *cpi;
  struct ConsensusHello *hello;

  cpi = cls;
  hello = GNUNET_malloc (sizeof *hello);
  hello->header.size = htons (sizeof *hello);
  hello->header.type = htons (GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_HELLO);
  memcpy (&hello->global_id, &cpi->session->global_id, sizeof (struct GNUNET_HashCode));
  GNUNET_assert (NULL == cpi->mst);
  cpi->mst = GNUNET_SERVER_mst_create (mst_session_callback, cpi);
  cpi->wh =
      GNUNET_STREAM_write (socket, hello, sizeof *hello, GNUNET_TIME_UNIT_FOREVER_REL, hello_cont, cpi);
  GNUNET_free (hello);
  cpi->rh = GNUNET_STREAM_read (socket, GNUNET_TIME_UNIT_FOREVER_REL,
                                &session_stream_data_processor, cpi);
}


/**
 * Create the sorted list of peers for the session,
 * add the local peer if not in the join message.
 */
static void
initialize_session_peer_list (struct ConsensusSession *session)
{
  unsigned int local_peer_in_list;
  uint32_t listed_peers;
  const struct GNUNET_PeerIdentity *msg_peers;
  struct GNUNET_PeerIdentity *peers;
  unsigned int i;

  GNUNET_assert (NULL != session->join_msg);

  /* peers in the join message, may or may not include the local peer */
  listed_peers = ntohl (session->join_msg->num_peers);
  
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

  peers = GNUNET_malloc (session->num_peers * sizeof (struct GNUNET_PeerIdentity));

  if (GNUNET_NO == local_peer_in_list)
    peers[session->num_peers - 1] = *my_peer;

  memcpy (peers, msg_peers, listed_peers * sizeof (struct GNUNET_PeerIdentity));
  qsort (peers, session->num_peers, sizeof (struct GNUNET_PeerIdentity), &hash_cmp);

  session->info = GNUNET_malloc (session->num_peers * sizeof (struct ConsensusPeerInformation));

  for (i = 0; i < session->num_peers; ++i)
  {
    /* initialize back-references, so consensus peer information can
     * be used as closure */
    session->info[i].session = session;
    session->info[i].peer_id = peers[i];
  }

  free (peers);
}


static void
strata_estimator_insert (struct StrataEstimator *se, struct GNUNET_HashCode *key)
{
  uint32_t v;
  int i;
  v = key->bits[0];
  /* count trailing '1'-bits of v */
  for (i = 0; v & 1; v>>=1, i++)
    /* empty */;
  ibf_insert (se->strata[i], ibf_key_from_hashcode (key));
}


/**
 * Add incoming peer connections to the session,
 * for peers who have connected to us before the local session has been established
 *
 * @param session ...
 */
static void
add_incoming_peers (struct ConsensusSession *session)
{
  struct IncomingSocket *inc;
  inc = incoming_sockets_head;

  while (NULL != inc)
  {
    if (0 == GNUNET_CRYPTO_hash_cmp (&session->global_id, inc->requested_gid))
    {
      int i;
      for (i = 0; i < session->num_peers; i++)
      {
        struct ConsensusPeerInformation *cpi;
        cpi = &session->info[i];
        if (0 == memcmp (&inc->peer_id, &cpi->peer_id, sizeof (struct GNUNET_PeerIdentity)))
        {
          cpi->socket = inc->socket;
          inc->cpi = cpi;
          inc->cpi->mst = inc->mst;
          inc->cpi->hello = GNUNET_YES;
          break;
        }
      }
    }
    inc = inc->next;
  }
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

  GNUNET_assert (NULL != session->join_msg);
  initialize_session_peer_list (session);
  session->current_round = CONSENSUS_ROUND_BEGIN;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "session with %u peers\n", session->num_peers);
  compute_global_id (session, &session->join_msg->session_id);

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
  session->se = strata_estimator_create ();
  session->ibfs = GNUNET_malloc ((MAX_IBF_ORDER+1) * sizeof (struct InvertibleBloomFilter *));
  GNUNET_free (session->join_msg);
  session->join_msg = NULL;
  add_incoming_peers (session);
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
 * Hash a block of data, producing a replicated ibf hash.
 */
static void
hash_for_ibf (const void *block, size_t size, struct GNUNET_HashCode *ret)
{
  struct IBF_Key ibf_key;
  GNUNET_CRYPTO_hash (block, size, ret);
  ibf_key = ibf_key_from_hashcode (ret);
  ibf_hashcode_from_key (ibf_key, ret);
}


static void
insert_element (struct ConsensusSession *session, struct GNUNET_CONSENSUS_Element *element)
{
  struct GNUNET_HashCode hash;
  struct ElementList *head;

  hash_for_ibf (element->data, element->size, &hash);

  head = GNUNET_CONTAINER_multihashmap_get (session->values, &hash);

  if (NULL == head)
  {
    int i;

    head = GNUNET_malloc (sizeof *head);
    head->element = element;
    head->next = NULL;
    head->element_hash = GNUNET_memdup (&hash, sizeof hash);
    GNUNET_CONTAINER_multihashmap_put (session->values, &hash, head,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
    strata_estimator_insert (session->se, &hash);

    for (i = 0; i <= MAX_IBF_ORDER; i++)
      if (NULL != session->ibfs[i])
        ibf_insert (session->ibfs[i], ibf_key_from_hashcode (&hash));
  }
  else
  {
    struct ElementList *el;
    el = GNUNET_malloc (sizeof *el);
    head->element = element;
    head->next = NULL;
    head->element_hash = GNUNET_memdup (&hash, sizeof hash);
    while (NULL != head->next)
      head = head->next;
    head->next = el;
  }
}


/**
 * Called when a client performs an insert operation.
 *
 * @param cls (unused)
 * @param client client handle
 * @param m message sent by the client
 */
void
client_insert (void *cls,
             struct GNUNET_SERVER_Client *client,
             const struct GNUNET_MessageHeader *m)
{
  struct ConsensusSession *session;
  struct GNUNET_CONSENSUS_ElementMessage *msg;
  struct GNUNET_CONSENSUS_Element *element;
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

  insert_element (session, element);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);

  client_send_next (session);
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
write_queued (void *cls, enum GNUNET_STREAM_Status status, size_t size)
{
  struct ConsensusPeerInformation *cpi;

  GNUNET_assert (GNUNET_STREAM_OK == status);
  cpi = cls;
  cpi->wh = NULL;
  if (NULL != cpi->messages_head)
  {
    struct QueuedMessage *qm;
    qm = cpi->messages_head;
    GNUNET_CONTAINER_DLL_remove (cpi->messages_head, cpi->messages_tail, qm);
    cpi->wh = GNUNET_STREAM_write (cpi->socket, qm->msg, ntohs (qm->msg->size),
                                   GNUNET_TIME_UNIT_FOREVER_REL,
                                   write_queued, cpi);
    if (NULL != qm->cb)
      qm->cb (qm->cls);
    GNUNET_free (qm->msg);
    GNUNET_free (qm);
    GNUNET_assert (NULL != cpi->wh);
  }
}


static void
shuffle (struct ConsensusSession *session)
{
  /* FIXME: implement */
}


/**
 * Find and set the partner_incoming and partner_outgoing of our peer,
 * one of them may not exist in most cases.
 *
 * @param session the consensus session
 */
static void
find_partners (struct ConsensusSession *session)
{
  int mark[session->num_peers];
  int i;
  memset (mark, 0, session->num_peers * sizeof (int));
  session->partner_incoming = session->partner_outgoing = NULL;
  for (i = 0; i < session->num_peers; i++)
  {
    int arc;
    if (0 != mark[i])
      continue;
    arc = (i + (1 << session->exp_subround)) % session->num_peers;
    mark[i] = mark[arc] = 1;
    GNUNET_assert (i != arc);
    if (i == session->local_peer_idx)
    {
      GNUNET_assert (NULL == session->partner_outgoing);
      session->partner_outgoing = &session->info[session->shuffle[arc]];
      session->partner_outgoing->exp_subround_finished = GNUNET_NO;
    }
    if (arc == session->local_peer_idx)
    {
      GNUNET_assert (NULL == session->partner_incoming);
      session->partner_incoming = &session->info[session->shuffle[i]];
      session->partner_incoming->exp_subround_finished = GNUNET_NO;
    }
  }
}


static void
replay_premature_message (struct ConsensusPeerInformation *cpi)
{
  if (NULL != cpi->premature_strata_message)
  {
    struct StrataMessage *sm;

    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "replaying premature SE\n");
    sm = cpi->premature_strata_message;
    cpi->premature_strata_message = NULL;

    cpi->replaying_strata_message = GNUNET_YES;
    handle_p2p_strata (cpi, sm);
    cpi->replaying_strata_message = GNUNET_NO;

    GNUNET_free (sm);
  }
}


/**
 * Do the next subround in the exp-scheme.
 * This function can be invoked as a timeout task, or called manually (tc will be NULL then).
 *
 * @param cls the session
 * @param tc task context, for when this task is invoked by the scheduler,
 *           NULL if invoked for another reason
 */
static void
subround_over (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ConsensusSession *session;
  int i;

  /* don't kick off next subround if we're shutting down */
  if ((NULL != tc) && (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  session = cls;
  /* don't send any messages from the last round */
  /*
  clear_peer_messages (session->partner_outgoing);
  clear_peer_messages (session->partner_incoming);
  for (i = 0; i < session->num_peers; i++)
    clear_peer_messages (&session->info[i]);
  */
  /* cancel timeout */
  if ((NULL == tc) && (session->round_timeout_tid != GNUNET_SCHEDULER_NO_TASK))
    GNUNET_SCHEDULER_cancel (session->round_timeout_tid);
  session->round_timeout_tid = GNUNET_SCHEDULER_NO_TASK;
  /* check if we are done with the log phase, 2-peer consensus only does one log round */
  if ( (session->exp_round == NUM_EXP_ROUNDS) ||
       ((session->num_peers == 2) && (session->exp_round == 1)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "P%d: exp-round over\n", session->local_peer_idx);
    round_over (session, NULL);
    return;
  }
  if (session->exp_round == 0)
  {
    /* initialize everything for the log-rounds */
    session->exp_round = 1;
    session->exp_subround = 0;
    if (NULL == session->shuffle)
      session->shuffle = GNUNET_malloc ((sizeof (int)) * session->num_peers);
    for (i = 0; i < session->num_peers; i++)
      session->shuffle[i] = i;
  }
  else if (session->exp_subround + 1 >= (int) ceil (log2 (session->num_peers)))
  {
    /* subrounds done, start new log-round */
    session->exp_round++;
    session->exp_subround = 0;
    shuffle (session);
  }
  else 
  {
    session->exp_subround++;
  }

  find_partners (session);

#ifdef GNUNET_EXTRA_LOGGING
  {
    int in;
    int out;
    if (session->partner_outgoing == NULL)
      out = -1;
    else
      out = (int) (session->partner_outgoing - session->info);
    if (session->partner_incoming == NULL)
      in = -1;
    else
      in = (int) (session->partner_incoming - session->info);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "P%u: doing exp-round, r=%d, sub=%d, in: %d, out: %d\n", session->local_peer_idx,
                session->exp_round, session->exp_subround, in, out);
  }
#endif /* GNUNET_EXTRA_LOGGING */

  if (NULL != session->partner_incoming)
  {
    session->partner_incoming->ibf_state = IBF_STATE_NONE;
    session->partner_incoming->exp_subround_finished = GNUNET_NO;
    session->partner_incoming->ibf_bucket_counter = 0;

    /* maybe there's an early strata estimator? */
    replay_premature_message (session->partner_incoming);
  }

  if (NULL != session->partner_outgoing)
  {
    session->partner_outgoing->ibf_state = IBF_STATE_NONE;
    session->partner_outgoing->ibf_bucket_counter = 0;
    session->partner_outgoing->exp_subround_finished = GNUNET_NO;

    if (NULL == session->partner_outgoing->socket)
    {
      session->partner_outgoing->socket =
          GNUNET_STREAM_open (cfg, &session->partner_outgoing->peer_id, GNUNET_APPLICATION_TYPE_CONSENSUS,
                              open_cb, session->partner_outgoing,
                              GNUNET_STREAM_OPTION_END);
    }
    else if (GNUNET_YES == session->partner_outgoing->hello)
    {
      send_strata_estimator (session->partner_outgoing);
    }
    /* else: do nothing, the send hello cb will handle this */
  }

  /*
  session->round_timeout_tid = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_divide (session->conclude_timeout, 3 * NUM_EXP_ROUNDS),
                                                                   subround_over, session);
  */
}

static void
contact_peer_a2a (struct ConsensusPeerInformation *cpi)
{
  cpi->is_outgoing = GNUNET_YES;
  if (NULL == cpi->socket)
  {
    cpi->socket = GNUNET_STREAM_open (cfg, &cpi->peer_id, GNUNET_APPLICATION_TYPE_CONSENSUS,
                                      open_cb, cpi, GNUNET_STREAM_OPTION_END);
  }
  else if (GNUNET_YES == cpi->hello)
  {
    send_strata_estimator (cpi);
  }
}

/**
 * Start the inventory round, contact all peers we are supposed to contact.
 *
 * @param session the current session
 */
static void
start_inventory (struct ConsensusSession *session)
{
  int i;
  int last;

  for (i = 0; i < session->num_peers; i++)
  {
    session->info[i].ibf_bucket_counter = 0;
    session->info[i].ibf_state = IBF_STATE_NONE;
    session->info[i].is_outgoing = GNUNET_NO;
  }

  last = (session->local_peer_idx + ((session->num_peers - 1) / 2) + 1) % session->num_peers;
  i = (session->local_peer_idx + 1) % session->num_peers;
  while (i != last)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "P%d contacting P%d in all-to-all\n", session->local_peer_idx, i);
    contact_peer_a2a (&session->info[i]);
    session->info[i].is_outgoing = GNUNET_YES;
    i = (i + 1) % session->num_peers;
  }
  // tie-breaker for even number of peers
  if (((session->num_peers % 2) == 0) && (session->local_peer_idx < last))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "P%d contacting P%d in all-to-all (tie-breaker)\n", session->local_peer_idx, i);
    session->info[last].is_outgoing = GNUNET_YES;
    contact_peer_a2a (&session->info[last]);
  }

  for (i = 0; i < session->num_peers; i++)
  {
    if (GNUNET_NO == session->info[i].is_outgoing)
      replay_premature_message (&session->info[i]);
  }
}

static void
send_client_conclude_done (struct ConsensusSession *session)
{
  struct GNUNET_MessageHeader *msg;
  session->current_round = CONSENSUS_ROUND_FINISH;
  msg = GNUNET_malloc (sizeof *msg);
  msg->type = htons (GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_CONCLUDE_DONE);
  msg->size = htons (sizeof *msg);
  queue_client_message (session, msg);
  client_send_next (session);
}

/**
 * Start the next round.
 * This function can be invoked as a timeout task, or called manually (tc will be NULL then).
 *
 * @param cls the session
 * @param tc task context, for when this task is invoked by the scheduler,
 *           NULL if invoked for another reason
 */
static void 
round_over (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ConsensusSession *session;

  /* don't kick off next round if we're shutting down */
  if ((NULL != tc) && (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  session = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "P%d: round over\n", session->local_peer_idx);

  /*
  for (i = 0; i < session->num_peers; i++)
    clear_peer_messages (&session->info[i]);
  */

  if ((NULL == tc) && (session->round_timeout_tid != GNUNET_SCHEDULER_NO_TASK))
  {
    GNUNET_SCHEDULER_cancel (session->round_timeout_tid);
    session->round_timeout_tid = GNUNET_SCHEDULER_NO_TASK;
  }

  switch (session->current_round)
  {
    case CONSENSUS_ROUND_BEGIN:
      session->current_round = CONSENSUS_ROUND_EXCHANGE;
      session->exp_round = 0;
      subround_over (session, NULL);
      break;
    case CONSENSUS_ROUND_EXCHANGE:
      /* handle two peers specially */
      if (session->num_peers <= 2)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_INFO, "P%d: done\n", session->local_peer_idx);
        send_client_conclude_done (session);
        return;
      }
      session->current_round = CONSENSUS_ROUND_INVENTORY;
      start_inventory (session);
      break;
    case CONSENSUS_ROUND_INVENTORY:
      session->current_round = CONSENSUS_ROUND_STOCK;
      session->exp_round = 0;
      subround_over (session, NULL);
      break;
    case CONSENSUS_ROUND_STOCK:
      session->current_round = CONSENSUS_ROUND_FINISH;
      send_client_conclude_done (session);
      break;
    default:
      GNUNET_assert (0);
  }
}


/**
 * Called when a client performs the conclude operation.
 *
 * @param cls (unused)
 * @param client client handle
 * @param message message sent by the client
 */
static void
client_conclude (void *cls,
                 struct GNUNET_SERVER_Client *client,
                 const struct GNUNET_MessageHeader *message)
{
  struct ConsensusSession *session;
  struct GNUNET_CONSENSUS_ConcludeMessage *cmsg;

  cmsg = (struct GNUNET_CONSENSUS_ConcludeMessage *) message;

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

  if (CONSENSUS_ROUND_BEGIN != session->current_round)
  {
    /* client requested conclude twice */
    GNUNET_break (0);
    /* client may still own a session, destroy it */
    disconnect_client (client);
    return;
  }

  if (session->num_peers <= 1)
  {
    send_client_conclude_done (session);
  }
  else
  {
    session->conclude_timeout = GNUNET_TIME_relative_ntoh (cmsg->timeout);
    /* the 'begin' round is over, start with the next, real round */
    round_over (session, NULL);
  }

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  client_send_next (session);
}


/**
 * Called when a client sends an ack
 *
 * @param cls (unused)
 * @param client client handle
 * @param message message sent by the client
 */
static void
client_ack (void *cls,
             struct GNUNET_SERVER_Client *client,
             const struct GNUNET_MessageHeader *message)
{
  struct ConsensusSession *session;
  struct GNUNET_CONSENSUS_AckMessage *msg;
  struct PendingElement *pending;
  struct GNUNET_CONSENSUS_Element *element;

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

  pending = session->client_approval_head;

  GNUNET_CONTAINER_DLL_remove (session->client_approval_head, session->client_approval_tail, pending);

  msg = (struct GNUNET_CONSENSUS_AckMessage *) message;

  if (msg->keep)
  {
    element = pending->element;
    insert_element (session, element);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "got client ack\n");
  }

  GNUNET_free (pending);

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
  if (core != NULL)
  {
    GNUNET_CORE_disconnect (core);
    core = NULL;
  }
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
    if (NULL != socket->rh)
    {
      GNUNET_STREAM_read_cancel (socket->rh);
      socket->rh = NULL;
    } 
    if (NULL == socket->cpi)
    {
      GNUNET_STREAM_close (socket->socket);
      socket->socket = NULL;
      if (NULL != socket->mst)
      {
        GNUNET_SERVER_mst_destroy (socket->mst);
        socket->mst = NULL;
      }
    }
    incoming_sockets_head = incoming_sockets_head->next;
    GNUNET_free (socket);
  }

  while (NULL != sessions_head)
  {
    struct ConsensusSession *session;
    session = sessions_head->next;
    destroy_session (sessions_head);
    sessions_head = session;
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
  /* core is only used to retrieve the peer identity */
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

