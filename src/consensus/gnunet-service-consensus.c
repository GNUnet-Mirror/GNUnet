/*
      This file is part of GNUnet
      (C) 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @file consensus/gnunet-service-consensus.c
 * @brief multi-peer set reconciliation
 * @author Florian Dold
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_applications.h"
#include "gnunet_set_service.h"
#include "gnunet_consensus_service.h"
#include "consensus_protocol.h"
#include "consensus.h"


/**
 * Log macro that prefixes the local peer and the peer we are in contact with.
 *
 * @param kind log level
 * @param cpi ConsensusPeerInformation of the partner peer
 * @param m log message
 */
#define LOG_PP(kind, cpi, m,...) GNUNET_log (kind, "P%d for P%d: " m, \
   cpi->session->local_peer_idx, (int) (cpi - cpi->session->info),##__VA_ARGS__)


/**
 * Number of exponential rounds, used in the exp and completion round.
 */
#define NUM_EXP_REPETITIONS 4


/* forward declarations */

/* mutual recursion with struct ConsensusSession */
struct ConsensusPeerInformation;

/* mutual recursion with round_over */
static void
subround_over (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


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
   * Collect and distribute missing values.
   */
  CONSENSUS_ROUND_COMPLETION,
  /**
   * Consensus concluded. After timeout and finished communication with client,
   * consensus session will be destroyed.
   */
  CONSENSUS_ROUND_FINISH
};


/**
 * Information about the current round.
 */
struct RoundInfo
{
  /**
   * The current main round.
   */
  enum ConsensusRound round;
  /**
   * The current exp round repetition, valid if
   * the main round is an exp round.
   */
  uint32_t exp_repetition;
  /**
   * The current exp subround, valid if
   * the main round is an exp round.
   */
  uint32_t exp_subround;
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
  * Global consensus identification, computed
  * from the session id and participating authorities.
  */
  struct GNUNET_HashCode global_id;

  /**
   * Client that inhabits the session
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Queued messages to the client.
   */
  struct GNUNET_MQ_Handle *client_mq;

  /**
   * Time when the conclusion of the consensus should begin.
   */
  struct GNUNET_TIME_Absolute conclude_start;

  /**
   * Timeout for all rounds together, single rounds will schedule a timeout task
   * with a fraction of the conclude timeout.
   * Only valid once the current round is not CONSENSUS_ROUND_BEGIN.
   */
  struct GNUNET_TIME_Absolute conclude_deadline;

  /**
   * Timeout task identifier for the current round or subround.
   */
  GNUNET_SCHEDULER_TaskIdentifier round_timeout_tid;

  /**
   * Number of other peers in the consensus.
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
  unsigned int local_peer_idx;

  /**
   * Current round
   */
  enum ConsensusRound current_round;

  /**
   * Permutation of peers for the current round,
   */
  uint32_t *shuffle;

  /**
   * Inverse permutation of peers for the current round,
   */
  uint32_t *shuffle_inv;

  /**
   * Current round of the exponential scheme.
   */
  uint32_t exp_repetition;

  /**
   * Current sub-round of the exponential scheme.
   */
  uint32_t exp_subround;

  /**
   * The partner for the current exp-round.
   * The local peer will initiate the set reconciliation with the
   * outgoing peer.
   */
  struct ConsensusPeerInformation *partner_outgoing;

  /**
   * The partner for the current exp-round
   * The incoming peer will initiate the set reconciliation with
   * the incoming peer.
   */
  struct ConsensusPeerInformation *partner_incoming;

  /**
   * The consensus set of this session.
   */
  struct GNUNET_SET_Handle *element_set;

  /**
   * Listener for requests from other peers.
   * Uses the session's global id as app id.
   */
  struct GNUNET_SET_ListenHandle *set_listener;
};


/**
 * Information about a peer that is in a consensus session.
 */
struct ConsensusPeerInformation
{
  /**
   * Peer identitty of the peer in the consensus session
   */
  struct GNUNET_PeerIdentity peer_id;

  /**
   * Back-reference to the consensus session,
   * to that ConsensusPeerInformation can be used as a closure
   */
  struct ConsensusSession *session;

  /**
   * Have we finished the set operation for this (sub-)round?
   */
  int set_op_finished;

  /**
   * Set operation we are currently executing with this peer.
   */
  struct GNUNET_SET_OperationHandle *set_op;

  /**
   * Set operation we are planning on executing with this peer.
   */
  struct GNUNET_SET_OperationHandle *delayed_set_op;

  /**
   * Info about the round of the delayed set operation.
   */
  struct RoundInfo delayed_round_info;
};


/**
 * Linked list of sessions this peer participates in.
 */
static struct ConsensusSession *sessions_head;

/**
 * Linked list of sessions this peer participates in.
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
static struct GNUNET_PeerIdentity my_peer;


/**
 * Check if the current subround has finished.
 * Must only be called when an exp-round is the current round.
 *
 * @param session session to check for exp-round completion
 * @return GNUNET_YES if the subround has finished,
 *         GNUNET_NO if not
 */
static int
have_exp_subround_finished (const struct ConsensusSession *session)
{
  int not_finished;

  GNUNET_assert (CONSENSUS_ROUND_EXCHANGE == session->current_round);

  not_finished = 0;
  if ( (NULL != session->partner_outgoing) &&
       (GNUNET_NO == session->partner_outgoing->set_op_finished) )
    not_finished++;
  if ( (NULL != session->partner_incoming) &&
       (GNUNET_NO == session->partner_incoming->set_op_finished) )
    not_finished++;
  if (0 == not_finished)
    return GNUNET_YES;
  return GNUNET_NO;
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
  if (NULL != session->element_set)
  {
    GNUNET_SET_destroy (session->element_set);
    session->element_set = NULL;
  }
  if (NULL != session->set_listener)
  {
    GNUNET_SET_listen_cancel (session->set_listener);
    session->set_listener = NULL;
  }
  if (NULL != session->client_mq)
  {
    GNUNET_MQ_destroy (session->client_mq);
    session->client_mq = NULL;
  }
  if (NULL != session->client)
  {
    GNUNET_SERVER_client_disconnect (session->client);
    session->client = NULL;
  }
  if (NULL != session->shuffle)
  {
    GNUNET_free (session->shuffle);
    session->shuffle = NULL;
  }
  if (NULL != session->shuffle_inv)
  {
    GNUNET_free (session->shuffle_inv);
    session->shuffle_inv = NULL;
  }
  if (NULL != session->info)
  {
    for (i = 0; i < session->num_peers; i++)
    {
      struct ConsensusPeerInformation *cpi;
      cpi = &session->info[i];
      if (NULL != cpi->set_op)
      {
        GNUNET_SET_operation_cancel (cpi->set_op);
        cpi->set_op = NULL;
      }
    }
    GNUNET_free (session->info);
    session->info = NULL;
  }
  GNUNET_free (session);
}


/**
 * Iterator for set elements. [FIXME: bad comment]
 *
 * @param cls closure
 * @param element the current element, NULL if all elements have been
 *        iterated over
 * @return #GNUNET_YES to continue iterating, #GNUNET_NO to stop.
 */
static int
send_to_client_iter (void *cls,
                     const struct GNUNET_SET_Element *element)
{
  struct ConsensusSession *session = cls;
  struct GNUNET_MQ_Envelope *ev;

  if (NULL != element)
  {
    struct GNUNET_CONSENSUS_ElementMessage *m;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "P%d: got element for client\n",
                session->local_peer_idx);

    ev = GNUNET_MQ_msg_extra (m, element->size,
                              GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_RECEIVED_ELEMENT);
    m->element_type = htons (element->element_type);
    memcpy (&m[1], element->data, element->size);
    GNUNET_MQ_send (session->client_mq, ev);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "P%d: finished iterating elements for client\n",
                session->local_peer_idx);
    ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_CONCLUDE_DONE);
    GNUNET_MQ_send (session->client_mq, ev);
  }
  return GNUNET_YES;
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
  unsigned int i;
  int res;

  /* don't kick off next round if we're shutting down */
  if ((NULL != tc) && (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  session = cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "P%d: round over\n", session->local_peer_idx);

  if (tc != NULL)
    session->round_timeout_tid = GNUNET_SCHEDULER_NO_TASK;

  if (session->round_timeout_tid != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (session->round_timeout_tid);
    session->round_timeout_tid = GNUNET_SCHEDULER_NO_TASK;
  }

  for (i = 0; i < session->num_peers; i++)
  {
    if (NULL != session->info[i].set_op)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "P%d: canceling stray op with P%d\n",
                  session->local_peer_idx, i);
      GNUNET_SET_operation_cancel (session->info[i].set_op);
      session->info[i].set_op = NULL;
    }
    /* we're in the new round, nothing finished yet */
    session->info[i].set_op_finished = GNUNET_NO;
  }

  switch (session->current_round)
  {
    case CONSENSUS_ROUND_BEGIN:
      session->current_round = CONSENSUS_ROUND_EXCHANGE;
      session->exp_repetition = 0;
      subround_over (session, NULL);
      break;
    case CONSENSUS_ROUND_EXCHANGE:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "P%d: finished, sending elements to client\n",
                  session->local_peer_idx);
      session->current_round = CONSENSUS_ROUND_FINISH;
      res = GNUNET_SET_iterate (session->element_set, send_to_client_iter, session);
      if (GNUNET_SYSERR == res)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "can't iterate set: set invalid\n");
      }
      else if (GNUNET_NO == res)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "can't iterate set: iterator already active\n");
      }
      break;
    default:
      GNUNET_assert (0);
  }
}


/**
 * Create a new permutation for the session's peers in session->shuffle.
 * Uses a Fisher-Yates shuffle with pseudo-randomness coming from
 * both the global session id and the current round index.
 *
 * @param session the session to create the new permutation for
 */
static void
shuffle (struct ConsensusSession *session)
{
  uint32_t i;
  uint32_t randomness[session->num_peers-1];

  if (NULL == session->shuffle)
    session->shuffle = GNUNET_malloc (session->num_peers * sizeof (*session->shuffle));
  if (NULL == session->shuffle_inv)
    session->shuffle_inv = GNUNET_malloc (session->num_peers * sizeof (*session->shuffle_inv));

  GNUNET_CRYPTO_kdf (randomness, sizeof (randomness),
		     &session->exp_repetition, sizeof (uint32_t),
                     &session->global_id, sizeof (struct GNUNET_HashCode),
		     NULL);

  for (i = 0; i < session->num_peers; i++)
    session->shuffle[i] = i;

  for (i = session->num_peers - 1; i > 0; i--)
  {
    uint32_t x;
    uint32_t tmp;
    x = randomness[i-1] % session->num_peers;
    tmp = session->shuffle[x];
    session->shuffle[x] = session->shuffle[i];
    session->shuffle[i] = tmp;
  }

  /* create the inverse */
  for (i = 0; i < session->num_peers; i++)
    session->shuffle_inv[session->shuffle[i]] = i;
}


/**
 * Find and set the partner_incoming and partner_outgoing of our peer,
 * one of them may not exist (and thus set to NULL) if the number of peers
 * in the session is not a power of two.
 *
 * @param session the consensus session
 */
static void
find_partners (struct ConsensusSession *session)
{
  unsigned int arc;
  unsigned int num_ghosts;
  unsigned int largest_arc;
  int partner_idx;

  /* shuffled local index */
  int my_idx = session->shuffle[session->local_peer_idx];

  /* distance to neighboring peer in current subround */
  arc = 1 << session->exp_subround;
  largest_arc = 1;
  while (largest_arc < session->num_peers)
    largest_arc <<= 1;
  num_ghosts = largest_arc - session->num_peers;
  // GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "largest arc: %u\n", largest_arc);
  // GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "arc: %u\n", arc);
  // GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "num ghosts: %u\n", num_ghosts);

  if (0 == (my_idx & arc))
  {
    /* we are outgoing */
    partner_idx = (my_idx + arc) % session->num_peers;
    session->partner_outgoing = &session->info[session->shuffle_inv[partner_idx]];
    GNUNET_assert (GNUNET_NO == session->partner_outgoing->set_op_finished);
    /* are we a 'ghost' of a peer that would exist if
     * the number of peers was a power of two, and thus have to partner
     * with an additional peer?
     */
    if (my_idx < num_ghosts)
    {
      int ghost_partner_idx;
      // GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "my index %d, arc %d, peers %u\n", my_idx, arc, session->num_peers);
      ghost_partner_idx = (my_idx - (int) arc) % (int) session->num_peers;
      /* platform dependent; modulo sometimes returns negative values */
      if (ghost_partner_idx < 0)
        ghost_partner_idx += session->num_peers;
      /* we only need to have a ghost partner if the partner is outgoing */
      if (0 == (ghost_partner_idx & arc))
      {
        // GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ghost partner is %d\n", ghost_partner_idx);
        session->partner_incoming = &session->info[session->shuffle_inv[ghost_partner_idx]];
        GNUNET_assert (GNUNET_NO == session->partner_incoming->set_op_finished);
        return;
      }
    }
    session->partner_incoming = NULL;
    return;
  }
  /* we only have an incoming connection */
  partner_idx = (my_idx - (int) arc) % (int) session->num_peers;
  if (partner_idx < 0)
    partner_idx += session->num_peers;
  session->partner_outgoing = NULL;
  session->partner_incoming = &session->info[session->shuffle_inv[partner_idx]];
  GNUNET_assert (GNUNET_NO == session->partner_incoming->set_op_finished);
}


/**
 * Callback for set operation results. Called for each element
 * in the result set.
 *
 * @param cls closure
 * @param element a result element, only valid if status is GNUNET_SET_STATUS_OK
 * @param status see enum GNUNET_SET_Status
 */
static void
set_result_cb (void *cls,
               const struct GNUNET_SET_Element *element,
               enum GNUNET_SET_Status status)
{
  struct ConsensusPeerInformation *cpi = cls;
  unsigned int remote_idx = cpi - cpi->session->info;
  unsigned int local_idx = cpi->session->local_peer_idx;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "P%u: set result from P%u with status %u\n",
              local_idx, remote_idx, (unsigned int) status);

  GNUNET_assert ((cpi == cpi->session->partner_outgoing) ||
                 (cpi == cpi->session->partner_incoming));

  switch (status)
  {
    case GNUNET_SET_STATUS_OK:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "P%u: set result from P%u: element\n",
                  local_idx, remote_idx);
      break;
    case GNUNET_SET_STATUS_FAILURE:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "P%u: set result from P%u: failure\n",
                  local_idx, remote_idx);
      cpi->set_op = NULL;
      return;
    case GNUNET_SET_STATUS_HALF_DONE:
    case GNUNET_SET_STATUS_DONE:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "P%u: set result from P%u: done\n",
                  local_idx, remote_idx);
      cpi->set_op_finished = GNUNET_YES;
      cpi->set_op = NULL;
      if (have_exp_subround_finished (cpi->session) == GNUNET_YES)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "P%u: all reconciliations of subround done\n",
                    local_idx);
        subround_over (cpi->session, NULL);
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "P%u: waiting for further set results\n",
                    local_idx);
      }
      return;
    default:
      GNUNET_break (0);
      return;
  }

  switch (cpi->session->current_round)
  {
    case CONSENSUS_ROUND_COMPLETION:
    case CONSENSUS_ROUND_EXCHANGE:
      GNUNET_SET_add_element (cpi->session->element_set, element, NULL, NULL);
      break;
    default:
      GNUNET_break (0);
      return;
  }
}


/**
 * Compare the round the session is in with the round of the given context message.
 *
 * @param session a consensus session
 * @param ri a round context message
 * @return 0 if it's the same round, -1 if the session is in an earlier round,
 *         1 if the session is in a later round
 */
static int
rounds_compare (struct ConsensusSession *session,
                struct RoundInfo* ri)
{
  if (session->current_round < ri->round)
    return -1;
  if (session->current_round > ri->round)
    return 1;
  if (session->current_round == CONSENSUS_ROUND_EXCHANGE)
  {
    if (session->exp_repetition < ri->exp_repetition)
      return -1;
    if (session->exp_repetition > ri->exp_repetition)
      return 1;
    if (session->exp_subround < ri->exp_subround)
      return -1;
    if (session->exp_subround > ri->exp_subround)
      return 1;
    return 0;
  }
  /* other rounds have no subrounds / repetitions to compare */
  return 0;
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
  struct GNUNET_TIME_Relative subround_timeout;
  int i;

  /* don't kick off next subround if we're shutting down */
  if ((NULL != tc) && (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  session = cls;

  GNUNET_assert (CONSENSUS_ROUND_EXCHANGE == session->current_round);

  if (tc != NULL)
  {
    session->round_timeout_tid = GNUNET_SCHEDULER_NO_TASK;
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "P%u: consensus subround timed out\n",
                session->local_peer_idx);
  }

  /* cancel timeout */
  if (session->round_timeout_tid != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (session->round_timeout_tid);
    session->round_timeout_tid = GNUNET_SCHEDULER_NO_TASK;
  }

  for (i = 0; i < session->num_peers; i++)
  {
    if (NULL != session->info[i].set_op)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "P%d: canceling stray op with P%d\n",
                  session->local_peer_idx, i);
      GNUNET_SET_operation_cancel (session->info[i].set_op);
      session->info[i].set_op = NULL;
    }
    /* we're in the new round, nothing finished yet */
    session->info[i].set_op_finished = GNUNET_NO;
  }

  if (session->exp_repetition >= NUM_EXP_REPETITIONS)
  {
    round_over (session, NULL);
    return;
  }

  if (session->exp_repetition == 0)
  {
    /* initialize everything for the log-rounds */
    session->exp_repetition = 1;
    session->exp_subround = 0;
    if (NULL == session->shuffle)
      session->shuffle = GNUNET_malloc ((sizeof (int)) * session->num_peers);
    if (NULL == session->shuffle_inv)
      session->shuffle_inv = GNUNET_malloc ((sizeof (int)) * session->num_peers);
    for (i = 0; i < session->num_peers; i++)
      session->shuffle[i] = session->shuffle_inv[i] = i;
  }
  else if (session->exp_subround + 1 >= (int) ceil (log2 (session->num_peers)))
  {
    /* subrounds done, start new log-round */
    session->exp_repetition++;
    session->exp_subround = 0;
    shuffle (session);
  }
  else
  {
    session->exp_subround++;
  }

  subround_timeout =
      GNUNET_TIME_relative_divide (GNUNET_TIME_absolute_get_difference (session->conclude_start, session->conclude_deadline),
                                   2 * NUM_EXP_REPETITIONS * ((int) ceil (log2 (session->num_peers))));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "subround timeout: %u ms\n", subround_timeout.rel_value_us / 1000);

  session->round_timeout_tid = GNUNET_SCHEDULER_add_delayed (subround_timeout, subround_over, session);

  /* determine the incoming and outgoing partner */
  find_partners (session);

  GNUNET_assert (session->partner_outgoing != &session->info[session->local_peer_idx]);
  GNUNET_assert (session->partner_incoming != &session->info[session->local_peer_idx]);

  /* initiate set operation with the outgoing partner */
  if (NULL != session->partner_outgoing)
  {
    struct GNUNET_CONSENSUS_RoundContextMessage *msg;
    msg = GNUNET_new (struct GNUNET_CONSENSUS_RoundContextMessage);
    msg->header.type = htons (GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_ROUND_CONTEXT);
    msg->header.size = htons (sizeof *msg);
    msg->round = htonl (session->current_round);
    msg->exp_repetition = htonl (session->exp_repetition);
    msg->exp_subround = htonl (session->exp_subround);

    if (NULL != session->partner_outgoing->set_op)
    {
      GNUNET_break (0);
      GNUNET_SET_operation_cancel (session->partner_outgoing->set_op);
    }
    session->partner_outgoing->set_op =
        GNUNET_SET_prepare (&session->partner_outgoing->peer_id,
                            &session->global_id,
                            (struct GNUNET_MessageHeader *) msg,
                            GNUNET_SET_RESULT_ADDED,
                            set_result_cb, session->partner_outgoing);
    GNUNET_free (msg);
    if (GNUNET_OK != GNUNET_SET_commit (session->partner_outgoing->set_op, session->element_set))
    {
      GNUNET_break (0);
      session->partner_outgoing->set_op = NULL;
      session->partner_outgoing->set_op_finished = GNUNET_YES;
    }
  }

  /* commit to the delayed set operation */
  if ((NULL != session->partner_incoming) && (NULL != session->partner_incoming->delayed_set_op))
  {
    int cmp = rounds_compare (session, &session->partner_incoming->delayed_round_info);

    if (NULL != session->partner_incoming->set_op)
    {
      GNUNET_break (0);
      GNUNET_SET_operation_cancel (session->partner_incoming->set_op);
      session->partner_incoming->set_op = NULL;
    }
    if (cmp == 0)
    {
      if (GNUNET_OK != GNUNET_SET_commit (session->partner_incoming->delayed_set_op, session->element_set))
      {
        GNUNET_break (0);
      }
      session->partner_incoming->set_op = session->partner_incoming->delayed_set_op;
      session->partner_incoming->delayed_set_op = NULL;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "P%d resumed delayed round with P%d\n",
                  session->local_peer_idx, (int) (session->partner_incoming - session->info));
    }
    else
    {
      /* this should not happen -- a round has been skipped! */
      GNUNET_break_op (0);
    }
  }

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
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "P%u: doing exp-round, r=%d, sub=%d, in: %d, out: %d\n", session->local_peer_idx,
                session->exp_repetition, session->exp_subround, in, out);
  }
#endif /* GNUNET_EXTRA_LOGGING */

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
 * Compute a global, (hopefully) unique consensus session id,
 * from the local id of the consensus session, and the identities of all participants.
 * Thus, if the local id of two consensus sessions coincide, but are not comprised of
 * exactly the same peers, the global id will be different.
 *
 * @param session session to generate the global id for
 * @param session_id local id of the consensus session
 */
static void
compute_global_id (struct ConsensusSession *session,
		   const struct GNUNET_HashCode *session_id)
{
  int i;
  struct GNUNET_HashCode tmp;
  struct GNUNET_HashCode phash;

  /* FIXME: use kdf? */

  session->global_id = *session_id;
  for (i = 0; i < session->num_peers; ++i)
  {
    GNUNET_CRYPTO_hash (&session->info[i].peer_id, sizeof (struct GNUNET_PeerIdentity), &phash);
    GNUNET_CRYPTO_hash_xor (&session->global_id, &phash, &tmp);
    session->global_id = tmp;
    GNUNET_CRYPTO_hash (&session->global_id, sizeof (struct GNUNET_PeerIdentity), &tmp);
    session->global_id = tmp;
  }
}


/**
 * Compare two peer identities.
 *
 * @param h1 some peer identity
 * @param h2 some peer identity
 * @return 1 if h1 > h2, -1 if h1 < h2 and 0 if h1 == h2.
 */
static int
peer_id_cmp (const void *h1, const void *h2)
{
  return memcmp (h1, h2, sizeof (struct GNUNET_PeerIdentity));
}


/**
 * Create the sorted list of peers for the session,
 * add the local peer if not in the join message.
 */
static void
initialize_session_peer_list (struct ConsensusSession *session,
                              struct GNUNET_CONSENSUS_JoinMessage *join_msg)
{
  unsigned int local_peer_in_list;
  uint32_t listed_peers;
  const struct GNUNET_PeerIdentity *msg_peers;
  struct GNUNET_PeerIdentity *peers;
  unsigned int i;

  GNUNET_assert (NULL != join_msg);

  /* peers in the join message, may or may not include the local peer */
  listed_peers = ntohl (join_msg->num_peers);

  session->num_peers = listed_peers;

  msg_peers = (struct GNUNET_PeerIdentity *) &join_msg[1];

  local_peer_in_list = GNUNET_NO;
  for (i = 0; i < listed_peers; i++)
  {
    if (0 == memcmp (&msg_peers[i], &my_peer, sizeof (struct GNUNET_PeerIdentity)))
    {
      local_peer_in_list = GNUNET_YES;
      break;
    }
  }

  if (GNUNET_NO == local_peer_in_list)
    session->num_peers++;

  peers = GNUNET_malloc (session->num_peers * sizeof (struct GNUNET_PeerIdentity));

  if (GNUNET_NO == local_peer_in_list)
    peers[session->num_peers - 1] = my_peer;

  memcpy (peers, msg_peers, listed_peers * sizeof (struct GNUNET_PeerIdentity));
  qsort (peers, session->num_peers, sizeof (struct GNUNET_PeerIdentity), &peer_id_cmp);

  session->info = GNUNET_malloc (session->num_peers * sizeof (struct ConsensusPeerInformation));

  for (i = 0; i < session->num_peers; ++i)
  {
    /* initialize back-references, so consensus peer information can
     * be used as closure */
    session->info[i].session = session;
    session->info[i].peer_id = peers[i];
  }

  GNUNET_free (peers);
}


/**
 * Called when another peer wants to do a set operation with the
 * local peer.
 *
 * @param cls closure
 * @param other_peer the other peer
 * @param context_msg message with application specific information from
 *        the other peer
 * @param request request from the other peer, use GNUNET_SET_accept
 *        to accept it, otherwise the request will be refused
 *        Note that we don't use a return value here, as it is also
 *        necessary to specify the set we want to do the operation with,
 *        whith sometimes can be derived from the context message.
 *        Also necessary to specify the timeout.
 */
static void
set_listen_cb (void *cls,
               const struct GNUNET_PeerIdentity *other_peer,
               const struct GNUNET_MessageHeader *context_msg,
               struct GNUNET_SET_Request *request)
{
  struct ConsensusSession *session = cls;
  struct GNUNET_CONSENSUS_RoundContextMessage *msg = (struct GNUNET_CONSENSUS_RoundContextMessage *) context_msg;
  struct ConsensusPeerInformation *cpi;
  struct GNUNET_SET_OperationHandle *set_op;
  struct RoundInfo round_info;
  int index;
  int cmp;

  if (NULL == context_msg)
  {
    GNUNET_break_op (0);
    return;
  }

  index = get_peer_idx (other_peer, session);

  if (index < 0)
  {
    GNUNET_break_op (0);
    return;
  }

  round_info.round = ntohl (msg->round);
  round_info.exp_repetition = ntohl (msg->exp_repetition);
  round_info.exp_subround = ntohl (msg->exp_subround);

  cpi = &session->info[index];

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "P%d got set request from P%d\n", session->local_peer_idx, index);

  switch (session->current_round)
  {
    case CONSENSUS_ROUND_BEGIN:
      /* we're in the begin round, so requests for the exchange round may
       * come in, they will be delayed for now! */
    case CONSENSUS_ROUND_EXCHANGE:
      cmp = rounds_compare (session, &round_info);
      if (cmp > 0)
      {
        /* the other peer is too late */
        LOG_PP (GNUNET_ERROR_TYPE_DEBUG, cpi, "too late for the current round\n");
        return;
      }
      /* kill old request, if any. this is legal,
       * as the other peer would not make a new request if it would want to
       * complete the old one! */
      if (NULL != cpi->set_op)
      {
        LOG_PP (GNUNET_ERROR_TYPE_INFO, cpi, "got new request from same peer, canceling old one\n");
        GNUNET_SET_operation_cancel (cpi->set_op);
        cpi->set_op = NULL;
      }
      set_op = GNUNET_SET_accept (request, GNUNET_SET_RESULT_ADDED,
                                  set_result_cb, &session->info[index]);
      if (cmp == 0)
      {
        /* we're in exactly the right round for the incoming request */
        if (cpi != cpi->session->partner_incoming)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "P%u: got request from %u (with matching round), "
                      "but incoming partner is %d\n", cpi->session->local_peer_idx, cpi - cpi->session->info,
                      ((NULL == cpi->session->partner_incoming) ? -1 : (cpi->session->partner_incoming - cpi->session->info)));
          GNUNET_SET_operation_cancel (set_op);
          return;
        }
        cpi->set_op = set_op;
        if (GNUNET_OK != GNUNET_SET_commit (set_op, session->element_set))
        {
          GNUNET_break (0);
        }
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "P%d commited to set request from P%d\n", session->local_peer_idx, index);
      }
      else
      {
        /* we still have wait until we have finished the current round,
         * as the other peer's round is larger */
        cpi->delayed_set_op = set_op;
        cpi->delayed_round_info = round_info;
        /* The current setop is finished, as we canceled the current setop above. */
        cpi->set_op_finished = GNUNET_YES;
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "P%d delaying set request from P%d\n", session->local_peer_idx, index);
      }
      break;
    default:
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "P%d got unexpected set request in round %d from P%d\n",
                  session->local_peer_idx, session->current_round, index);
      GNUNET_break_op (0);
      return;
  }
}


/**
 * Initialize the session, continue receiving messages from the owning client
 *
 * @param session the session to initialize
 * @param join_msg the join message from the client
 */
static void
initialize_session (struct ConsensusSession *session,
                    struct GNUNET_CONSENSUS_JoinMessage *join_msg)
{
  struct ConsensusSession *other_session;

  initialize_session_peer_list (session, join_msg);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "session with %u peers\n", session->num_peers);
  compute_global_id (session, &join_msg->session_id);

  /* check if some local client already owns the session.
   * it is only legal to have a session with an existing global id
   * if all other sessions with this global id are finished.*/
  other_session = sessions_head;
  while (NULL != other_session)
  {
    if ((other_session != session) &&
        (0 == GNUNET_CRYPTO_hash_cmp (&session->global_id, &other_session->global_id)))
    {
      if (CONSENSUS_ROUND_FINISH != other_session->current_round)
      {
        GNUNET_break (0);
        destroy_session (session);
        return;
      }
      break;
    }
    other_session = other_session->next;
  }

  session->conclude_deadline = GNUNET_TIME_absolute_ntoh (join_msg->deadline);
  session->conclude_start = GNUNET_TIME_absolute_ntoh (join_msg->start);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "consensus with timeout %ums created\n",
              (GNUNET_TIME_absolute_get_difference (session->conclude_start, session->conclude_deadline)).rel_value_us / 1000);

  session->local_peer_idx = get_peer_idx (&my_peer, session);
  GNUNET_assert (-1 != session->local_peer_idx);
  session->element_set = GNUNET_SET_create (cfg, GNUNET_SET_OPERATION_UNION);
  GNUNET_assert (NULL != session->element_set);
  session->set_listener = GNUNET_SET_listen (cfg, GNUNET_SET_OPERATION_UNION,
                                             &session->global_id,
                                             set_listen_cb, session);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%d is the local peer\n", session->local_peer_idx);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "session %s initialized\n", GNUNET_h2s (&session->global_id));
}


static struct ConsensusSession *
get_session_by_client (struct GNUNET_SERVER_Client *client)
{
  struct ConsensusSession *session;

  session = sessions_head;
  while (NULL != session)
  {
    if (session->client == client)
      return session;
    session = session->next;
  }
  return NULL;
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "join message sent by client\n");

  session = get_session_by_client (client);
  if (NULL != session)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  session = GNUNET_new (struct ConsensusSession);
  session->client = client;
  session->client_mq = GNUNET_MQ_queue_for_server_client (client);
  GNUNET_CONTAINER_DLL_insert (sessions_head, sessions_tail, session);
  initialize_session (session, (struct GNUNET_CONSENSUS_JoinMessage *) m);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "join done\n");
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
  struct GNUNET_SET_Element *element;
  ssize_t element_size;

  session = get_session_by_client (client);

  if (NULL == session)
  {
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (client);
    return;
  }

  if (CONSENSUS_ROUND_BEGIN != session->current_round)
  {
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (client);
    return;
  }

  msg = (struct GNUNET_CONSENSUS_ElementMessage *) m;
  element_size = ntohs (msg->header.size) - sizeof (struct GNUNET_CONSENSUS_ElementMessage);
  if (element_size < 0)
  {
    GNUNET_break (0);
    return;
  }

  element = GNUNET_malloc (sizeof (struct GNUNET_SET_Element) + element_size);
  element->element_type = msg->element_type;
  element->size = element_size;
  memcpy (&element[1], &msg[1], element_size);
  element->data = &element[1];
  GNUNET_SET_add_element (session->element_set, element, NULL, NULL);
  GNUNET_free (element);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);

  // GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "P%u: element added\n", session->local_peer_idx);
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "conclude requested\n");
  session = get_session_by_client (client);
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
    return;
  }
  if (session->num_peers <= 1)
  {
    session->current_round = CONSENSUS_ROUND_FINISH;
    GNUNET_SET_iterate (session->element_set, send_to_client_iter, session);
  }
  else
  {
    /* the 'begin' round is over, start with the next, actual round */
    round_over (session, NULL);
  }

  GNUNET_assert (CONSENSUS_ROUND_BEGIN != session->current_round);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
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
  while (NULL != sessions_head)
    destroy_session (sessions_head);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "handled shutdown request\n");
}


/**
 * Clean up after a client after it is
 * disconnected (either by us or by itself)
 *
 * @param cls closure, unused
 * @param client the client to clean up after
 */
void
handle_client_disconnect (void *cls, struct GNUNET_SERVER_Client *client)
{
  struct ConsensusSession *session;

  session = get_session_by_client (client);
  if (NULL == session)
    return;
  if ((CONSENSUS_ROUND_BEGIN == session->current_round) ||
      (CONSENSUS_ROUND_FINISH == session->current_round))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "client disconnected, destroying session\n");
    destroy_session (session);
  }
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "client disconnected, but waiting for consensus to finish\n");
}


/**
 * Start processing consensus requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  static const struct GNUNET_SERVER_MessageHandler server_handlers[] = {
    {&client_conclude, NULL, GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_CONCLUDE,
        sizeof (struct GNUNET_MessageHeader)},
    {&client_insert, NULL, GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_INSERT, 0},
    {&client_join, NULL, GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_JOIN, 0},
    {NULL, NULL, 0, 0}
  };

  cfg = c;
  srv = server;
  if (GNUNET_OK != GNUNET_CRYPTO_get_peer_identity (cfg, &my_peer))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "could not retrieve host identity\n");
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_SERVER_add_handlers (server, server_handlers);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task, NULL);
  GNUNET_SERVER_disconnect_notify (server, handle_client_disconnect, NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "consensus running\n");
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
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "exit (%d)\n", GNUNET_OK != ret);
  return (GNUNET_OK == ret) ? 0 : 1;
}

