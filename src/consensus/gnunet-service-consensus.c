/*
      This file is part of GNUnet
      Copyright (C) 2012, 2013, 2017 GNUnet e.V.

      GNUnet is free software: you can redistribute it and/or modify it
      under the terms of the GNU Affero General Public License as published
      by the Free Software Foundation, either version 3 of the License,
      or (at your option) any later version.

      GNUnet is distributed in the hope that it will be useful, but
      WITHOUT ANY WARRANTY; without even the implied warranty of
      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
      Affero General Public License for more details.
     
      You should have received a copy of the GNU Affero General Public License
      along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file consensus/gnunet-service-consensus.c
 * @brief multi-peer set reconciliation
 * @author Florian Dold <flo@dold.me>
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_block_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_applications.h"
#include "gnunet_set_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet_consensus_service.h"
#include "consensus_protocol.h"
#include "consensus.h"


enum ReferendumVote
{
  /**
   * Vote that nothing should change.
   * This option is never voted explicitly.
   */
  VOTE_STAY = 0,
  /**
   * Vote that an element should be added.
   */
  VOTE_ADD = 1,
  /**
   * Vote that an element should be removed.
   */
  VOTE_REMOVE = 2,
};


enum EarlyStoppingPhase
{
  EARLY_STOPPING_NONE = 0,
  EARLY_STOPPING_ONE_MORE = 1,
  EARLY_STOPPING_DONE = 2,
};


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Tuple of integers that together
 * identify a task uniquely.
 */
struct TaskKey {
  /**
   * A value from 'enum PhaseKind'.
   */
  uint16_t kind GNUNET_PACKED;

  /**
   * Number of the first peer
   * in canonical order.
   */
  int16_t peer1 GNUNET_PACKED;

  /**
   * Number of the second peer in canonical order.
   */
  int16_t peer2 GNUNET_PACKED;

  /**
   * Repetition of the gradecast phase.
   */
  int16_t repetition GNUNET_PACKED;

  /**
   * Leader in the gradecast phase.
   *
   * Can be different from both peer1 and peer2.
   */
  int16_t leader GNUNET_PACKED;
};



struct SetKey
{
  int set_kind GNUNET_PACKED;
  int k1 GNUNET_PACKED;
  int k2 GNUNET_PACKED;
};


struct SetEntry
{
  struct SetKey key;
  struct GNUNET_SET_Handle *h;
  /**
   * GNUNET_YES if the set resulted
   * from applying a referendum with contested
   * elements.
   */
  int is_contested;
};


struct DiffKey
{
  int diff_kind GNUNET_PACKED;
  int k1 GNUNET_PACKED;
  int k2 GNUNET_PACKED;
};

struct RfnKey
{
  int rfn_kind GNUNET_PACKED;
  int k1 GNUNET_PACKED;
  int k2 GNUNET_PACKED;
};


GNUNET_NETWORK_STRUCT_END

enum PhaseKind
{
  PHASE_KIND_ALL_TO_ALL,
  PHASE_KIND_ALL_TO_ALL_2,
  PHASE_KIND_GRADECAST_LEADER,
  PHASE_KIND_GRADECAST_ECHO,
  PHASE_KIND_GRADECAST_ECHO_GRADE,
  PHASE_KIND_GRADECAST_CONFIRM,
  PHASE_KIND_GRADECAST_CONFIRM_GRADE,
  /**
   * Apply a repetition of the all-to-all
   * gradecast to the current set.
   */
  PHASE_KIND_APPLY_REP,
  PHASE_KIND_FINISH,
};


enum SetKind
{
  SET_KIND_NONE = 0,
  SET_KIND_CURRENT,
  /**
   * Last result set from a gradecast
   */
  SET_KIND_LAST_GRADECAST,
  SET_KIND_LEADER_PROPOSAL,
  SET_KIND_ECHO_RESULT,
};

enum DiffKind
{
  DIFF_KIND_NONE = 0,
  DIFF_KIND_LEADER_PROPOSAL,
  DIFF_KIND_LEADER_CONSENSUS,
  DIFF_KIND_GRADECAST_RESULT,
};

enum RfnKind
{
  RFN_KIND_NONE = 0,
  RFN_KIND_ECHO,
  RFN_KIND_CONFIRM,
  RFN_KIND_GRADECAST_RESULT
};


struct SetOpCls
{
  struct SetKey input_set;

  struct SetKey output_set;
  struct RfnKey output_rfn;
  struct DiffKey output_diff;

  int do_not_remove;

  int transceive_contested;

  struct GNUNET_SET_OperationHandle *op;
};


struct FinishCls
{
  struct SetKey input_set;
};

/**
 * Closure for both @a start_task
 * and @a cancel_task.
 */
union TaskFuncCls
{
  struct SetOpCls setop;
  struct FinishCls finish;
};

struct TaskEntry;

typedef void (*TaskFunc) (struct TaskEntry *task);

/*
 * Node in the consensus task graph.
 */
struct TaskEntry
{
  struct TaskKey key;

  struct Step *step;

  int is_started;

  int is_finished;

  TaskFunc start;
  TaskFunc cancel;

  union TaskFuncCls cls;
};


struct Step
{
  /**
   * All steps of one session are in a
   * linked list for easier deallocation.
   */
  struct Step *prev;

  /**
   * All steps of one session are in a
   * linked list for easier deallocation.
   */
  struct Step *next;

  struct ConsensusSession *session;

  /**
   * Tasks that this step is composed of.
   */
  struct TaskEntry **tasks;
  unsigned int tasks_len;
  unsigned int tasks_cap;

  unsigned int finished_tasks;

  /*
   * Tasks that have this task as dependency.
   *
   * We store pointers to subordinates rather
   * than to prerequisites since it makes
   * tracking the readiness of a task easier.
   */
  struct Step **subordinates;
  unsigned int subordinates_len;
  unsigned int subordinates_cap;

  /**
   * Counter for the prerequisites of
   * this step.
   */
  size_t pending_prereq;

  /*
   * Task that will run this step despite
   * any pending prerequisites.
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

  unsigned int is_running;

  unsigned int is_finished;

  /*
   * Synchrony round of the task.
   * Determines the deadline for the task.
   */
  unsigned int round;

  /**
   * Human-readable name for
   * the task, used for debugging.
   */
  char *debug_name;

  /**
   * When we're doing an early finish, how should this step be
   * treated?
   * If GNUNET_YES, the step will be marked as finished
   * without actually running its tasks.
   * Otherwise, the step will still be run even after
   * an early finish.
   *
   * Note that a task may never be finished early if
   * it is already running.
   */
  int early_finishable;
};


struct RfnElementInfo
{
  const struct GNUNET_SET_Element *element;

  /*
   * GNUNET_YES if the peer votes for the proposal.
   */
  int *votes;

  /**
   * Proposal for this element,
   * can only be VOTE_ADD or VOTE_REMOVE.
   */
  enum ReferendumVote proposal;
};


struct ReferendumEntry
{
  struct RfnKey key;

  /*
   * Elements where there is at least one proposed change.
   *
   * Maps the hash of the GNUNET_SET_Element
   * to 'struct RfnElementInfo'.
   */
  struct GNUNET_CONTAINER_MultiHashMap *rfn_elements;

  unsigned int num_peers;

  /**
   * Stores, for every peer in the session,
   * whether the peer finished the whole referendum.
   *
   * Votes from peers are only counted if they're
   * marked as commited (#GNUNET_YES) in the referendum.
   *
   * Otherwise (#GNUNET_NO), the requested changes are
   * not counted for majority votes or thresholds.
   */
  int *peer_commited;


  /**
   * Contestation state of the peer.  If a peer is contested, the values it
   * contributed are still counted for applying changes, but the grading is
   * affected.
   */
  int *peer_contested;
};


struct DiffElementInfo
{
  const struct GNUNET_SET_Element *element;

  /**
   * Positive weight for 'add', negative
   * weights for 'remove'.
   */
  int weight;
};


/**
 * Weighted diff.
 */
struct DiffEntry
{
  struct DiffKey key;
  struct GNUNET_CONTAINER_MultiHashMap *changes;
};

struct SetHandle
{
  struct SetHandle *prev;
  struct SetHandle *next;

  struct GNUNET_SET_Handle *h;
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

  unsigned int num_client_insert_pending;

  struct GNUNET_CONTAINER_MultiHashMap *setmap;
  struct GNUNET_CONTAINER_MultiHashMap *rfnmap;
  struct GNUNET_CONTAINER_MultiHashMap *diffmap;

  /**
   * Array of peers with length 'num_peers'.
   */
  int *peers_blacklisted;

  /*
   * Mapping from (hashed) TaskKey to TaskEntry.
   *
   * We map the application_id for a round to the task that should be
   * executed, so we don't have to go through all task whenever we get
   * an incoming set op request.
   */
  struct GNUNET_CONTAINER_MultiHashMap *taskmap;

  struct Step *steps_head;
  struct Step *steps_tail;

  int conclude_started;

  int conclude_done;

  /**
  * Global consensus identification, computed
  * from the session id and participating authorities.
  */
  struct GNUNET_HashCode global_id;

  /**
   * Client that inhabits the session
   */
  struct GNUNET_SERVICE_Client *client;

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

  struct GNUNET_PeerIdentity *peers;

  /**
   * Number of other peers in the consensus.
   */
  unsigned int num_peers;

  /**
   * Index of the local peer in the peers array
   */
  unsigned int local_peer_idx;

  /**
   * Listener for requests from other peers.
   * Uses the session's global id as app id.
   */
  struct GNUNET_SET_ListenHandle *set_listener;

  /**
   * State of our early stopping scheme.
   */
  int early_stopping;

  /**
   * Our set size from the first round.
   */
  uint64_t first_size;

  uint64_t *first_sizes_received;

  /**
   * Bounded Eppstein lower bound.
   */
  uint64_t lower_bound;

  struct SetHandle *set_handles_head;
  struct SetHandle *set_handles_tail;
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
 * Peer that runs this service.
 */
static struct GNUNET_PeerIdentity my_peer;

/**
 * Statistics handle.
 */
struct GNUNET_STATISTICS_Handle *statistics;


static void
finish_task (struct TaskEntry *task);


static void
run_ready_steps (struct ConsensusSession *session);


static const char *
phasename (uint16_t phase)
{
  switch (phase)
  {
    case PHASE_KIND_ALL_TO_ALL: return "ALL_TO_ALL";
    case PHASE_KIND_ALL_TO_ALL_2: return "ALL_TO_ALL_2";
    case PHASE_KIND_FINISH: return "FINISH";
    case PHASE_KIND_GRADECAST_LEADER: return "GRADECAST_LEADER";
    case PHASE_KIND_GRADECAST_ECHO: return "GRADECAST_ECHO";
    case PHASE_KIND_GRADECAST_ECHO_GRADE: return "GRADECAST_ECHO_GRADE";
    case PHASE_KIND_GRADECAST_CONFIRM: return "GRADECAST_CONFIRM";
    case PHASE_KIND_GRADECAST_CONFIRM_GRADE: return "GRADECAST_CONFIRM_GRADE";
    case PHASE_KIND_APPLY_REP: return "APPLY_REP";
    default: return "(unknown)";
  }
}


static const char *
setname (uint16_t kind)
{
  switch (kind)
  {
    case SET_KIND_CURRENT: return "CURRENT";
    case SET_KIND_LEADER_PROPOSAL: return "LEADER_PROPOSAL";
    case SET_KIND_NONE: return "NONE";
    default: return "(unknown)";
  }
}

static const char *
rfnname (uint16_t kind)
{
  switch (kind)
  {
    case RFN_KIND_NONE: return "NONE";
    case RFN_KIND_ECHO: return "ECHO";
    case RFN_KIND_CONFIRM: return "CONFIRM";
    default: return "(unknown)";
  }
}

static const char *
diffname (uint16_t kind)
{
  switch (kind)
  {
    case DIFF_KIND_NONE: return "NONE";
    case DIFF_KIND_LEADER_CONSENSUS: return "LEADER_CONSENSUS";
    case DIFF_KIND_GRADECAST_RESULT: return "GRADECAST_RESULT";
    case DIFF_KIND_LEADER_PROPOSAL: return "LEADER_PROPOSAL";
    default: return "(unknown)";
  }
}

#ifdef GNUNET_EXTRA_LOGGING


static const char *
debug_str_element (const struct GNUNET_SET_Element *el)
{
  struct GNUNET_HashCode hash;

  GNUNET_SET_element_hash (el, &hash);

  return GNUNET_h2s (&hash);
}

static const char *
debug_str_task_key (struct TaskKey *tk)
{
  static char buf[256];

  snprintf (buf, sizeof (buf),
            "TaskKey kind=%s, p1=%d, p2=%d, l=%d, rep=%d",
            phasename (tk->kind), tk->peer1, tk->peer2,
            tk->leader, tk->repetition);

  return buf;
}

static const char *
debug_str_diff_key (struct DiffKey *dk)
{
  static char buf[256];

  snprintf (buf, sizeof (buf),
            "DiffKey kind=%s, k1=%d, k2=%d",
            diffname (dk->diff_kind), dk->k1, dk->k2);

  return buf;
}

static const char *
debug_str_set_key (const struct SetKey *sk)
{
  static char buf[256];

  snprintf (buf, sizeof (buf),
            "SetKey kind=%s, k1=%d, k2=%d",
            setname (sk->set_kind), sk->k1, sk->k2);

  return buf;
}


static const char *
debug_str_rfn_key (const struct RfnKey *rk)
{
  static char buf[256];

  snprintf (buf, sizeof (buf),
            "RfnKey kind=%s, k1=%d, k2=%d",
            rfnname (rk->rfn_kind), rk->k1, rk->k2);

  return buf;
}

#endif /* GNUNET_EXTRA_LOGGING */


/**
 * Send the final result set of the consensus to the client, element by
 * element.
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
  struct TaskEntry *task = (struct TaskEntry *) cls;
  struct ConsensusSession *session = task->step->session;
  struct GNUNET_MQ_Envelope *ev;

  if (NULL != element)
  {
    struct GNUNET_CONSENSUS_ElementMessage *m;
    const struct ConsensusElement *ce;

    GNUNET_assert (GNUNET_BLOCK_TYPE_CONSENSUS_ELEMENT == element->element_type);
    ce = element->data;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "marker is %u\n", (unsigned) ce->marker);

    if (0 != ce->marker)
      return GNUNET_YES;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "P%d: sending element %s to client\n",
                session->local_peer_idx,
                debug_str_element (element));

    ev = GNUNET_MQ_msg_extra (m, element->size - sizeof (struct ConsensusElement),
                              GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_RECEIVED_ELEMENT);
    m->element_type = ce->payload_type;
    GNUNET_memcpy (&m[1], &ce[1], element->size - sizeof (struct ConsensusElement));
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


static struct SetEntry *
lookup_set (struct ConsensusSession *session, struct SetKey *key)
{
  struct GNUNET_HashCode hash;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "P%u: looking up set {%s}\n",
              session->local_peer_idx,
              debug_str_set_key (key));

  GNUNET_assert (SET_KIND_NONE != key->set_kind);
  GNUNET_CRYPTO_hash (key, sizeof (struct SetKey), &hash);
  return GNUNET_CONTAINER_multihashmap_get (session->setmap, &hash);
}


static struct DiffEntry *
lookup_diff (struct ConsensusSession *session, struct DiffKey *key)
{
  struct GNUNET_HashCode hash;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "P%u: looking up diff {%s}\n",
              session->local_peer_idx,
              debug_str_diff_key (key));

  GNUNET_assert (DIFF_KIND_NONE != key->diff_kind);
  GNUNET_CRYPTO_hash (key, sizeof (struct DiffKey), &hash);
  return GNUNET_CONTAINER_multihashmap_get (session->diffmap, &hash);
}


static struct ReferendumEntry *
lookup_rfn (struct ConsensusSession *session, struct RfnKey *key)
{
  struct GNUNET_HashCode hash;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "P%u: looking up rfn {%s}\n",
              session->local_peer_idx,
              debug_str_rfn_key (key));

  GNUNET_assert (RFN_KIND_NONE != key->rfn_kind);
  GNUNET_CRYPTO_hash (key, sizeof (struct RfnKey), &hash);
  return GNUNET_CONTAINER_multihashmap_get (session->rfnmap, &hash);
}


static void
diff_insert (struct DiffEntry *diff,
             int weight,
             const struct GNUNET_SET_Element *element)
{
  struct DiffElementInfo *di;
  struct GNUNET_HashCode hash;

  GNUNET_assert ( (1 == weight) || (-1 == weight));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "diff_insert with element size %u\n",
              element->size);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "hashing element\n");

  GNUNET_SET_element_hash (element, &hash);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "hashed element\n");

  di = GNUNET_CONTAINER_multihashmap_get (diff->changes, &hash);

  if (NULL == di)
  {
    di = GNUNET_new (struct DiffElementInfo);
    di->element = GNUNET_SET_element_dup (element);
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multihashmap_put (diff->changes,
                                                      &hash, di,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST));
  }

  di->weight = weight;
}


static void
rfn_commit (struct ReferendumEntry *rfn,
            uint16_t commit_peer)
{
  GNUNET_assert (commit_peer < rfn->num_peers);

  rfn->peer_commited[commit_peer] = GNUNET_YES;
}


static void
rfn_contest (struct ReferendumEntry *rfn,
             uint16_t contested_peer)
{
  GNUNET_assert (contested_peer < rfn->num_peers);

  rfn->peer_contested[contested_peer] = GNUNET_YES;
}


static uint16_t
rfn_noncontested (struct ReferendumEntry *rfn)
{
  uint16_t i;
  uint16_t ret;

  ret = 0;
  for (i = 0; i < rfn->num_peers; i++)
    if ( (GNUNET_YES == rfn->peer_commited[i]) && (GNUNET_NO == rfn->peer_contested[i]) )
      ret++;

  return ret;
}


static void
rfn_vote (struct ReferendumEntry *rfn,
          uint16_t voting_peer,
          enum ReferendumVote vote,
          const struct GNUNET_SET_Element *element)
{
  struct RfnElementInfo *ri;
  struct GNUNET_HashCode hash;

  GNUNET_assert (voting_peer < rfn->num_peers);

  /* Explicit voting only makes sense with VOTE_ADD or VOTE_REMOTE,
     since VOTE_KEEP is implicit in not voting. */
  GNUNET_assert ( (VOTE_ADD == vote) || (VOTE_REMOVE == vote) );

  GNUNET_SET_element_hash (element, &hash);
  ri = GNUNET_CONTAINER_multihashmap_get (rfn->rfn_elements, &hash);

  if (NULL == ri)
  {
    ri = GNUNET_new (struct RfnElementInfo);
    ri->element = GNUNET_SET_element_dup (element);
    ri->votes = GNUNET_new_array (rfn->num_peers, int);
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multihashmap_put (rfn->rfn_elements,
                                                      &hash, ri,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST));
  }

  ri->votes[voting_peer] = GNUNET_YES;
  ri->proposal = vote;
}


static uint16_t
task_other_peer (struct TaskEntry *task)
{
  uint16_t me = task->step->session->local_peer_idx;
  if (task->key.peer1 == me)
    return task->key.peer2;
  return task->key.peer1;
}


static int
cmp_uint64_t (const void *pa, const void *pb)
{
  uint64_t a = *(uint64_t *) pa;
  uint64_t b = *(uint64_t *) pb;

  if (a == b)
    return 0;
  if (a < b)
    return -1;
  return 1;
}


/**
 * Callback for set operation results. Called for each element
 * in the result set.
 *
 * @param cls closure
 * @param element a result element, only valid if status is #GNUNET_SET_STATUS_OK
 * @param current_size current set size
 * @param status see enum GNUNET_SET_Status
 */
static void
set_result_cb (void *cls,
               const struct GNUNET_SET_Element *element,
               uint64_t current_size,
               enum GNUNET_SET_Status status)
{
  struct TaskEntry *task = cls;
  struct ConsensusSession *session = task->step->session;
  struct SetEntry *output_set = NULL;
  struct DiffEntry *output_diff = NULL;
  struct ReferendumEntry *output_rfn = NULL;
  unsigned int other_idx;
  struct SetOpCls *setop;
  const struct ConsensusElement *consensus_element = NULL;

  if (NULL != element)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "P%u: got element of type %u, status %u\n",
                session->local_peer_idx,
                (unsigned) element->element_type,
                (unsigned) status);
    GNUNET_assert (GNUNET_BLOCK_TYPE_CONSENSUS_ELEMENT == element->element_type);
    consensus_element = element->data;
  }

  setop = &task->cls.setop;


  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "P%u: got set result for {%s}, status %u\n",
              session->local_peer_idx,
              debug_str_task_key (&task->key),
              status);

  if (GNUNET_NO == task->is_started)
  {
    GNUNET_break_op (0);
    return;
  }

  if (GNUNET_YES == task->is_finished)
  {
    GNUNET_break_op (0);
    return;
  }

  other_idx = task_other_peer (task);

  if (SET_KIND_NONE != setop->output_set.set_kind)
  {
    output_set = lookup_set (session, &setop->output_set);
    GNUNET_assert (NULL != output_set);
  }

  if (DIFF_KIND_NONE != setop->output_diff.diff_kind)
  {
    output_diff = lookup_diff (session, &setop->output_diff);
    GNUNET_assert (NULL != output_diff);
  }

  if (RFN_KIND_NONE != setop->output_rfn.rfn_kind)
  {
    output_rfn = lookup_rfn (session, &setop->output_rfn);
    GNUNET_assert (NULL != output_rfn);
  }

  if (GNUNET_YES == session->peers_blacklisted[other_idx])
  {
    /* Peer might have been blacklisted
       by a gradecast running in parallel, ignore elements from now */
    if (GNUNET_SET_STATUS_ADD_LOCAL == status)
      return;
    if (GNUNET_SET_STATUS_ADD_REMOTE == status)
      return;
  }

  if ( (NULL != consensus_element) && (0 != consensus_element->marker) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "P%u: got some marker\n",
                  session->local_peer_idx);
    if ( (GNUNET_YES == setop->transceive_contested) &&
         (CONSENSUS_MARKER_CONTESTED == consensus_element->marker) )
    {
      GNUNET_assert (NULL != output_rfn);
      rfn_contest (output_rfn, task_other_peer (task));
      return;
    }

    if (CONSENSUS_MARKER_SIZE == consensus_element->marker)
    {

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "P%u: got size marker\n",
                  session->local_peer_idx);


      struct ConsensusSizeElement *cse = (void *) consensus_element;

      if (cse->sender_index == other_idx)
      {
        if (NULL == session->first_sizes_received)
          session->first_sizes_received = GNUNET_new_array (session->num_peers, uint64_t);
        session->first_sizes_received[other_idx] = GNUNET_ntohll (cse->size);

        uint64_t *copy = GNUNET_memdup (session->first_sizes_received, sizeof (uint64_t) * session->num_peers);
        qsort (copy, session->num_peers, sizeof (uint64_t), cmp_uint64_t);
        session->lower_bound = copy[session->num_peers / 3 + 1];
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "P%u: lower bound %llu\n",
                    session->local_peer_idx,
                    (long long) session->lower_bound);
        GNUNET_free (copy);
      }
      return;
    }

    return;
  }

  switch (status)
  {
    case GNUNET_SET_STATUS_ADD_LOCAL:
      GNUNET_assert (NULL != consensus_element);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Adding element in Task {%s}\n",
                  debug_str_task_key (&task->key));
      if (NULL != output_set)
      {
        // FIXME: record pending adds, use callback
        GNUNET_SET_add_element (output_set->h,
                                element,
                                NULL,
                                NULL);
#ifdef GNUNET_EXTRA_LOGGING
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "P%u: adding element %s into set {%s} of task {%s}\n",
                    session->local_peer_idx,
                    debug_str_element (element),
                    debug_str_set_key (&setop->output_set),
                    debug_str_task_key (&task->key));
#endif
      }
      if (NULL != output_diff)
      {
        diff_insert (output_diff, 1, element);
#ifdef GNUNET_EXTRA_LOGGING
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "P%u: adding element %s into diff {%s} of task {%s}\n",
                    session->local_peer_idx,
                    debug_str_element (element),
                    debug_str_diff_key (&setop->output_diff),
                    debug_str_task_key (&task->key));
#endif
      }
      if (NULL != output_rfn)
      {
        rfn_vote (output_rfn, task_other_peer (task), VOTE_ADD, element);
#ifdef GNUNET_EXTRA_LOGGING
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "P%u: adding element %s into rfn {%s} of task {%s}\n",
                    session->local_peer_idx,
                    debug_str_element (element),
                    debug_str_rfn_key (&setop->output_rfn),
                    debug_str_task_key (&task->key));
#endif
      }
      // XXX: add result to structures in task
      break;
    case GNUNET_SET_STATUS_ADD_REMOTE:
      GNUNET_assert (NULL != consensus_element);
      if (GNUNET_YES == setop->do_not_remove)
        break;
      if (CONSENSUS_MARKER_CONTESTED == consensus_element->marker)
        break;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Removing element in Task {%s}\n",
                  debug_str_task_key (&task->key));
      if (NULL != output_set)
      {
        // FIXME: record pending adds, use callback
        GNUNET_SET_remove_element (output_set->h,
                                   element,
                                   NULL,
                                   NULL);
#ifdef GNUNET_EXTRA_LOGGING
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "P%u: removing element %s from set {%s} of task {%s}\n",
                    session->local_peer_idx,
                    debug_str_element (element),
                    debug_str_set_key (&setop->output_set),
                    debug_str_task_key (&task->key));
#endif
      }
      if (NULL != output_diff)
      {
        diff_insert (output_diff, -1, element);
#ifdef GNUNET_EXTRA_LOGGING
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "P%u: removing element %s from diff {%s} of task {%s}\n",
                    session->local_peer_idx,
                    debug_str_element (element),
                    debug_str_diff_key (&setop->output_diff),
                    debug_str_task_key (&task->key));
#endif
      }
      if (NULL != output_rfn)
      {
        rfn_vote (output_rfn, task_other_peer (task), VOTE_REMOVE, element);
#ifdef GNUNET_EXTRA_LOGGING
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "P%u: removing element %s from rfn {%s} of task {%s}\n",
                    session->local_peer_idx,
                    debug_str_element (element),
                    debug_str_rfn_key (&setop->output_rfn),
                    debug_str_task_key (&task->key));
#endif
      }
      break;
    case GNUNET_SET_STATUS_DONE:
      // XXX: check first if any changes to the underlying
      // set are still pending
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "P%u: Finishing setop in Task {%s} (%u/%u)\n",
                  session->local_peer_idx,
                  debug_str_task_key (&task->key),
                  (unsigned int) task->step->finished_tasks,
                  (unsigned int) task->step->tasks_len);
      if (NULL != output_rfn)
      {
        rfn_commit (output_rfn, task_other_peer (task));
      }
      if (PHASE_KIND_ALL_TO_ALL == task->key.kind)
      {
        session->first_size = current_size;
      }
      finish_task (task);
      break;
    case GNUNET_SET_STATUS_FAILURE:
      // XXX: cleanup
      GNUNET_break_op (0);
      finish_task (task);
      return;
    default:
      /* not reached */
      GNUNET_assert (0);
  }
}

#ifdef EVIL

enum EvilnessType
{
  EVILNESS_NONE,
  EVILNESS_CRAM_ALL,
  EVILNESS_CRAM_LEAD,
  EVILNESS_CRAM_ECHO,
  EVILNESS_SLACK,
  EVILNESS_SLACK_A2A,
};

enum EvilnessSubType
{
  EVILNESS_SUB_NONE,
  EVILNESS_SUB_REPLACEMENT,
  EVILNESS_SUB_NO_REPLACEMENT,
};

struct Evilness
{
  enum EvilnessType type;
  enum EvilnessSubType subtype;
  unsigned int num;
};


static int
parse_evilness_cram_subtype (const char *evil_subtype_str, struct Evilness *evil)
{
  if (0 == strcmp ("replace", evil_subtype_str))
  {
    evil->subtype = EVILNESS_SUB_REPLACEMENT;
  }
  else if (0 == strcmp ("noreplace", evil_subtype_str))
  {
    evil->subtype = EVILNESS_SUB_NO_REPLACEMENT;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Malformed field '%s' in EVIL_SPEC (unknown subtype), behaving like a good peer.\n",
                evil_subtype_str);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


static void
get_evilness (struct ConsensusSession *session, struct Evilness *evil)
{
  char *evil_spec;
  char *field;
  char *evil_type_str = NULL;
  char *evil_subtype_str = NULL;

  GNUNET_assert (NULL != evil);

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (cfg, "consensus", "EVIL_SPEC", &evil_spec))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "P%u: no evilness\n",
                session->local_peer_idx);
    evil->type = EVILNESS_NONE;
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "P%u: got evilness spec\n",
              session->local_peer_idx);

  for (field = strtok (evil_spec, "/");
       NULL != field;
       field = strtok (NULL, "/"))
  {
    unsigned int peer_num;
    unsigned int evil_num;
    int ret;

    evil_type_str = NULL;
    evil_subtype_str = NULL;

    ret = sscanf (field, "%u;%m[a-z-];%m[a-z-];%u", &peer_num, &evil_type_str, &evil_subtype_str, &evil_num);

    if (ret != 4)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Malformed field '%s' in EVIL_SPEC (expected 4 components got %d), behaving like a good peer.\n",
                  field,
                  ret);
      goto not_evil;
    }

    GNUNET_assert (NULL != evil_type_str);
    GNUNET_assert (NULL != evil_subtype_str);

    if (peer_num == session->local_peer_idx)
    {
      if (0 == strcmp ("slack", evil_type_str))
      {
        evil->type = EVILNESS_SLACK;
      }
      if (0 == strcmp ("slack-a2a", evil_type_str))
      {
        evil->type = EVILNESS_SLACK_A2A;
      }
      else if (0 == strcmp ("cram-all", evil_type_str))
      {
        evil->type = EVILNESS_CRAM_ALL;
        evil->num = evil_num;
        if (GNUNET_OK != parse_evilness_cram_subtype (evil_subtype_str, evil))
          goto not_evil;
      }
      else if (0 == strcmp ("cram-lead", evil_type_str))
      {
        evil->type = EVILNESS_CRAM_LEAD;
        evil->num = evil_num;
        if (GNUNET_OK != parse_evilness_cram_subtype (evil_subtype_str, evil))
          goto not_evil;
      }
      else if (0 == strcmp ("cram-echo", evil_type_str))
      {
        evil->type = EVILNESS_CRAM_ECHO;
        evil->num = evil_num;
        if (GNUNET_OK != parse_evilness_cram_subtype (evil_subtype_str, evil))
          goto not_evil;
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Malformed field '%s' in EVIL_SPEC (unknown type), behaving like a good peer.\n",
                    evil_type_str);
        goto not_evil;
      }
      goto cleanup;
    }
    /* No GNUNET_free since memory was allocated by libc */
    free (evil_type_str);
    evil_type_str = NULL;
    evil_subtype_str = NULL;
  }
not_evil:
  evil->type = EVILNESS_NONE;
cleanup:
  GNUNET_free (evil_spec);
  /* no GNUNET_free_non_null since it wasn't
   * allocated with GNUNET_malloc */
  if (NULL != evil_type_str)
    free (evil_type_str);
  if (NULL != evil_subtype_str)
    free (evil_subtype_str);
}

#endif


/**
 * Commit the appropriate set for a
 * task.
 */
static void
commit_set (struct ConsensusSession *session,
            struct TaskEntry *task)
{
  struct SetEntry *set;
  struct SetOpCls *setop = &task->cls.setop;

  GNUNET_assert (NULL != setop->op);
  set = lookup_set (session, &setop->input_set);
  GNUNET_assert (NULL != set);

  if ( (GNUNET_YES == setop->transceive_contested) && (GNUNET_YES == set->is_contested) )
  {
    struct GNUNET_SET_Element element;
    struct ConsensusElement ce = { 0 };
    ce.marker = CONSENSUS_MARKER_CONTESTED;
    element.data = &ce;
    element.size = sizeof (struct ConsensusElement);
    element.element_type = GNUNET_BLOCK_TYPE_CONSENSUS_ELEMENT;
    GNUNET_SET_add_element (set->h, &element, NULL, NULL);
  }

  if (PHASE_KIND_ALL_TO_ALL_2 == task->key.kind)
  {
    struct GNUNET_SET_Element element;
    struct ConsensusSizeElement cse = {
      .size = 0,
      .sender_index = 0
    };
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "inserting size marker\n");
    cse.ce.marker = CONSENSUS_MARKER_SIZE;
    cse.size = GNUNET_htonll (session->first_size);
    cse.sender_index = session->local_peer_idx;
    element.data = &cse;
    element.size = sizeof (struct ConsensusSizeElement);
    element.element_type = GNUNET_BLOCK_TYPE_CONSENSUS_ELEMENT;
    GNUNET_SET_add_element (set->h, &element, NULL, NULL);
  }

#ifdef EVIL
  {
    unsigned int i;
    struct Evilness evil;

    get_evilness (session, &evil);
    if (EVILNESS_NONE != evil.type)
    {
      /* Useful for evaluation */
      GNUNET_STATISTICS_set (statistics,
                             "is evil",
                             1,
                             GNUNET_NO);
    }
    switch (evil.type)
    {
      case EVILNESS_CRAM_ALL:
      case EVILNESS_CRAM_LEAD:
      case EVILNESS_CRAM_ECHO:
        /* We're not cramming elements in the
           all-to-all round, since that would just
           add more elements to the result set, but
           wouldn't test robustness. */
        if (PHASE_KIND_ALL_TO_ALL == task->key.kind)
        {
          GNUNET_SET_commit (setop->op, set->h);
          break;
        }
        if ((EVILNESS_CRAM_LEAD == evil.type) &&
            ((PHASE_KIND_GRADECAST_LEADER != task->key.kind) || SET_KIND_CURRENT != set->key.set_kind))
        {
          GNUNET_SET_commit (setop->op, set->h);
          break;
        }
        if (EVILNESS_CRAM_ECHO == evil.type && (PHASE_KIND_GRADECAST_ECHO != task->key.kind))
        {
          GNUNET_SET_commit (setop->op, set->h);
          break;
        }
        for (i = 0; i < evil.num; i++)
        {
          struct GNUNET_SET_Element element;
          struct ConsensusStuffedElement se = {
            .ce.payload_type = 0,
            .ce.marker = 0,
          };
          element.data = &se;
          element.size = sizeof (struct ConsensusStuffedElement);
          element.element_type = GNUNET_BLOCK_TYPE_CONSENSUS_ELEMENT;

          if (EVILNESS_SUB_REPLACEMENT == evil.subtype)
          {
            /* Always generate a new element. */
            GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_WEAK, &se.rand);
          }
          else if (EVILNESS_SUB_NO_REPLACEMENT == evil.subtype)
          {
            /* Always cram the same elements, derived from counter. */
            GNUNET_CRYPTO_hash (&i, sizeof (i), &se.rand);
          }
          else
          {
            GNUNET_assert (0);
          }
          GNUNET_SET_add_element (set->h, &element, NULL, NULL);
#ifdef GNUNET_EXTRA_LOGGING
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "P%u: evil peer: cramming element %s into set {%s} of task {%s}\n",
                      session->local_peer_idx,
                      debug_str_element (&element),
                      debug_str_set_key (&setop->input_set),
                      debug_str_task_key (&task->key));
#endif
        }
        GNUNET_STATISTICS_update (statistics,
                                  "# stuffed elements",
                                  evil.num,
                                  GNUNET_NO);
        GNUNET_SET_commit (setop->op, set->h);
        break;
      case EVILNESS_SLACK:
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "P%u: evil peer: slacking\n",
                    (unsigned int) session->local_peer_idx);
        /* Do nothing. */
      case EVILNESS_SLACK_A2A:
        if ( (PHASE_KIND_ALL_TO_ALL_2 == task->key.kind ) ||
             (PHASE_KIND_ALL_TO_ALL == task->key.kind) )
        {
          struct GNUNET_SET_Handle *empty_set;
          empty_set = GNUNET_SET_create (cfg, GNUNET_SET_OPERATION_UNION);
          GNUNET_SET_commit (setop->op, empty_set);
          GNUNET_SET_destroy (empty_set);
        }
        else
        {
          GNUNET_SET_commit (setop->op, set->h);
        }
        break;
      case EVILNESS_NONE:
        GNUNET_SET_commit (setop->op, set->h);
        break;
    }
  }
#else
  if (GNUNET_NO == session->peers_blacklisted[task_other_peer (task)])
  {
    GNUNET_SET_commit (setop->op, set->h);
  }
  else
  {
    /* For our testcases, we don't want the blacklisted
       peers to wait. */
    GNUNET_SET_operation_cancel (setop->op);
    setop->op = NULL;
    finish_task (task);
  }
#endif
}


static void
put_diff (struct ConsensusSession *session,
         struct DiffEntry *diff)
{
  struct GNUNET_HashCode hash;

  GNUNET_assert (NULL != diff);

  GNUNET_CRYPTO_hash (&diff->key, sizeof (struct DiffKey), &hash);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap_put (session->diffmap, &hash, diff,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
}

static void
put_set (struct ConsensusSession *session,
         struct SetEntry *set)
{
  struct GNUNET_HashCode hash;

  GNUNET_assert (NULL != set->h);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Putting set %s\n",
              debug_str_set_key (&set->key));

  GNUNET_CRYPTO_hash (&set->key, sizeof (struct SetKey), &hash);
  GNUNET_assert (GNUNET_SYSERR !=
                 GNUNET_CONTAINER_multihashmap_put (session->setmap, &hash, set,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE));
}


static void
put_rfn (struct ConsensusSession *session,
         struct ReferendumEntry *rfn)
{
  struct GNUNET_HashCode hash;

  GNUNET_CRYPTO_hash (&rfn->key, sizeof (struct RfnKey), &hash);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap_put (session->rfnmap, &hash, rfn,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
}



static void
task_cancel_reconcile (struct TaskEntry *task)
{
  /* not implemented yet */
  GNUNET_assert (0);
}


static void
apply_diff_to_rfn (struct DiffEntry *diff,
                   struct ReferendumEntry *rfn,
                   uint16_t voting_peer,
                   uint16_t num_peers)
{
  struct GNUNET_CONTAINER_MultiHashMapIterator *iter;
  struct DiffElementInfo *di;

  iter = GNUNET_CONTAINER_multihashmap_iterator_create (diff->changes);

  while (GNUNET_YES ==
         GNUNET_CONTAINER_multihashmap_iterator_next (iter,
                                                      NULL,
                                                      (const void **) &di))
  {
    if (di->weight > 0)
    {
      rfn_vote (rfn, voting_peer, VOTE_ADD, di->element);
    }
    if (di->weight < 0)
    {
      rfn_vote (rfn, voting_peer, VOTE_REMOVE, di->element);
    }
  }

  GNUNET_CONTAINER_multihashmap_iterator_destroy (iter);
}


struct DiffEntry *
diff_create ()
{
  struct DiffEntry *d = GNUNET_new (struct DiffEntry);

  d->changes = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);

  return d;
}


struct DiffEntry *
diff_compose (struct DiffEntry *diff_1,
              struct DiffEntry *diff_2)
{
  struct DiffEntry *diff_new;
  struct GNUNET_CONTAINER_MultiHashMapIterator *iter;
  struct DiffElementInfo *di;

  diff_new = diff_create ();

  iter = GNUNET_CONTAINER_multihashmap_iterator_create (diff_1->changes);
  while (GNUNET_YES == GNUNET_CONTAINER_multihashmap_iterator_next (iter, NULL, (const void **) &di))
  {
    diff_insert (diff_new, di->weight, di->element);
  }
  GNUNET_CONTAINER_multihashmap_iterator_destroy (iter);

  iter = GNUNET_CONTAINER_multihashmap_iterator_create (diff_2->changes);
  while (GNUNET_YES == GNUNET_CONTAINER_multihashmap_iterator_next (iter, NULL, (const void **) &di))
  {
    diff_insert (diff_new, di->weight, di->element);
  }
  GNUNET_CONTAINER_multihashmap_iterator_destroy (iter);

  return diff_new;
}


struct ReferendumEntry *
rfn_create (uint16_t size)
{
  struct ReferendumEntry *rfn;

  rfn = GNUNET_new (struct ReferendumEntry);
  rfn->rfn_elements = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);
  rfn->peer_commited = GNUNET_new_array (size, int);
  rfn->peer_contested = GNUNET_new_array (size, int);
  rfn->num_peers = size;

  return rfn;
}


#if UNUSED
static void
diff_destroy (struct DiffEntry *diff)
{
  GNUNET_CONTAINER_multihashmap_destroy (diff->changes);
  GNUNET_free (diff);
}
#endif


/**
 * For a given majority, count what the outcome
 * is (add/remove/keep), and give the number
 * of peers that voted for this outcome.
 */
static void
rfn_majority (const struct ReferendumEntry *rfn,
              const struct RfnElementInfo *ri,
              uint16_t *ret_majority,
              enum ReferendumVote *ret_vote)
{
  uint16_t votes_yes = 0;
  uint16_t num_commited = 0;
  uint16_t i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Computing rfn majority for element %s of rfn {%s}\n",
              debug_str_element (ri->element),
              debug_str_rfn_key (&rfn->key));

  for (i = 0; i < rfn->num_peers; i++)
  {
    if (GNUNET_NO == rfn->peer_commited[i])
      continue;
    num_commited++;

    if (GNUNET_YES == ri->votes[i])
      votes_yes++;
  }

  if (votes_yes > (num_commited) / 2)
  {
    *ret_vote = ri->proposal;
    *ret_majority = votes_yes;
  }
  else
  {
    *ret_vote = VOTE_STAY;
    *ret_majority = num_commited - votes_yes;
  }
}


struct SetCopyCls
{
  struct TaskEntry *task;
  struct SetKey dst_set_key;
};


static void
set_copy_cb (void *cls, struct GNUNET_SET_Handle *copy)
{
  struct SetCopyCls *scc = cls;
  struct TaskEntry *task = scc->task;
  struct SetKey dst_set_key = scc->dst_set_key;
  struct SetEntry *set;
  struct SetHandle *sh = GNUNET_new (struct SetHandle);

  sh->h = copy;
  GNUNET_CONTAINER_DLL_insert (task->step->session->set_handles_head,
                               task->step->session->set_handles_tail,
                               sh);

  GNUNET_free (scc);
  set = GNUNET_new (struct SetEntry);
  set->h = copy;
  set->key = dst_set_key;
  put_set (task->step->session, set);

  task->start (task);
}


/**
 * Call the start function of the given
 * task again after we created a copy of the given set.
 */
static void
create_set_copy_for_task (struct TaskEntry *task,
                          struct SetKey *src_set_key,
                          struct SetKey *dst_set_key)
{
  struct SetEntry *src_set;
  struct SetCopyCls *scc = GNUNET_new (struct SetCopyCls);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Copying set {%s} to {%s} for task {%s}\n",
              debug_str_set_key (src_set_key),
              debug_str_set_key (dst_set_key),
              debug_str_task_key (&task->key));

  scc->task = task;
  scc->dst_set_key = *dst_set_key;
  src_set = lookup_set (task->step->session, src_set_key);
  GNUNET_assert (NULL != src_set);
  GNUNET_SET_copy_lazy (src_set->h,
                        set_copy_cb,
                        scc);
}


struct SetMutationProgressCls
{
  int num_pending;
  /**
   * Task to finish once all changes are through.
   */
  struct TaskEntry *task;
};


static void
set_mutation_done (void *cls)
{
  struct SetMutationProgressCls *pc = cls;

  GNUNET_assert (pc->num_pending > 0);

  pc->num_pending--;

  if (0 == pc->num_pending)
  {
    struct TaskEntry *task = pc->task;
    GNUNET_free (pc);
    finish_task (task);
  }
}


static void
try_finish_step_early (struct Step *step)
{
  unsigned int i;

  if (GNUNET_YES == step->is_running)
    return;
  if (GNUNET_YES == step->is_finished)
    return;
  if (GNUNET_NO == step->early_finishable)
    return;

  step->is_finished = GNUNET_YES;

#ifdef GNUNET_EXTRA_LOGGING
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Finishing step `%s' early.\n",
              step->debug_name);
#endif

  for (i = 0; i < step->subordinates_len; i++)
  {
    GNUNET_assert (step->subordinates[i]->pending_prereq > 0);
    step->subordinates[i]->pending_prereq--;
#ifdef GNUNET_EXTRA_LOGGING
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Decreased pending_prereq to %u for step `%s'.\n",
                (unsigned int) step->subordinates[i]->pending_prereq,
                step->subordinates[i]->debug_name);

#endif
    try_finish_step_early (step->subordinates[i]);
  }

  // XXX: maybe schedule as task to avoid recursion?
  run_ready_steps (step->session);
}


static void
finish_step (struct Step *step)
{
  unsigned int i;

  GNUNET_assert (step->finished_tasks == step->tasks_len);
  GNUNET_assert (GNUNET_YES == step->is_running);
  GNUNET_assert (GNUNET_NO == step->is_finished);

#ifdef GNUNET_EXTRA_LOGGING
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "All tasks of step `%s' with %u subordinates finished.\n",
              step->debug_name,
              step->subordinates_len);
#endif

  for (i = 0; i < step->subordinates_len; i++)
  {
    GNUNET_assert (step->subordinates[i]->pending_prereq > 0);
    step->subordinates[i]->pending_prereq--;
#ifdef GNUNET_EXTRA_LOGGING
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Decreased pending_prereq to %u for step `%s'.\n",
                (unsigned int) step->subordinates[i]->pending_prereq,
                step->subordinates[i]->debug_name);

#endif
  }

  step->is_finished = GNUNET_YES;

  // XXX: maybe schedule as task to avoid recursion?
  run_ready_steps (step->session);
}



/**
 * Apply the result from one round of gradecasts (i.e. every peer
 * should have gradecasted) to the peer's current set.
 *
 * @param task the task with context information
 */
static void
task_start_apply_round (struct TaskEntry *task)
{
  struct ConsensusSession *session = task->step->session;
  struct SetKey sk_in;
  struct SetKey sk_out;
  struct RfnKey rk_in;
  struct SetEntry *set_out;
  struct ReferendumEntry *rfn_in;
  struct GNUNET_CONTAINER_MultiHashMapIterator *iter;
  struct RfnElementInfo *ri;
  struct SetMutationProgressCls *progress_cls;
  uint16_t worst_majority = UINT16_MAX;

  sk_in = (struct SetKey) { SET_KIND_CURRENT, task->key.repetition };
  rk_in = (struct RfnKey) { RFN_KIND_GRADECAST_RESULT, task->key.repetition };
  sk_out = (struct SetKey) { SET_KIND_CURRENT, task->key.repetition + 1 };

  set_out = lookup_set (session, &sk_out);
  if (NULL == set_out)
  {
    create_set_copy_for_task (task, &sk_in, &sk_out);
    return;
  }

  rfn_in = lookup_rfn (session, &rk_in);
  GNUNET_assert (NULL != rfn_in);

  progress_cls = GNUNET_new (struct SetMutationProgressCls);
  progress_cls->task = task;

  iter = GNUNET_CONTAINER_multihashmap_iterator_create (rfn_in->rfn_elements);

  while (GNUNET_YES ==
         GNUNET_CONTAINER_multihashmap_iterator_next (iter,
                                                      NULL,
                                                      (const void **) &ri))
  {
    uint16_t majority_num;
    enum ReferendumVote majority_vote;

    rfn_majority (rfn_in, ri, &majority_num, &majority_vote);

    if (worst_majority > majority_num)
      worst_majority = majority_num;

    switch (majority_vote)
    {
      case VOTE_ADD:
        progress_cls->num_pending++;
        GNUNET_assert (GNUNET_OK ==
                       GNUNET_SET_add_element (set_out->h,
                                               ri->element,
                                               &set_mutation_done,
                                               progress_cls));
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "P%u: apply round: adding element %s with %u-majority.\n",
                    session->local_peer_idx,
                    debug_str_element (ri->element), majority_num);
        break;
      case VOTE_REMOVE:
        progress_cls->num_pending++;
        GNUNET_assert (GNUNET_OK ==
                       GNUNET_SET_remove_element (set_out->h,
                                                  ri->element,
                                                  &set_mutation_done,
                                                  progress_cls));
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "P%u: apply round: deleting element %s with %u-majority.\n",
                    session->local_peer_idx,
                    debug_str_element (ri->element), majority_num);
        break;
      case VOTE_STAY:
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "P%u: apply round: keeping element %s with %u-majority.\n",
                    session->local_peer_idx,
                    debug_str_element (ri->element), majority_num);
        // do nothing
        break;
      default:
        GNUNET_assert (0);
        break;
    }
  }

  if (0 == progress_cls->num_pending)
  {
    // call closure right now, no pending ops
    GNUNET_free (progress_cls);
    finish_task (task);
  }

  {
    uint16_t thresh = (session->num_peers / 3) * 2;

    if (worst_majority >= thresh)
    {
      switch (session->early_stopping)
      {
        case EARLY_STOPPING_NONE:
          session->early_stopping = EARLY_STOPPING_ONE_MORE;
          GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                      "P%u: Stopping early (after one more superround)\n",
                      session->local_peer_idx);
          break;
        case EARLY_STOPPING_ONE_MORE:
          GNUNET_log (GNUNET_ERROR_TYPE_INFO, "P%u: finishing steps due to early finish\n",
                      session->local_peer_idx);
          session->early_stopping = EARLY_STOPPING_DONE;
          {
            struct Step *step;
            for (step = session->steps_head; NULL != step; step = step->next)
              try_finish_step_early (step);
          }
          break;
        case EARLY_STOPPING_DONE:
          /* We shouldn't be here anymore after early stopping */
          GNUNET_break (0);
          break;
        default:
          GNUNET_assert (0);
          break;
      }
    }
    else if (EARLY_STOPPING_NONE != session->early_stopping)
    {
      // Our assumption about the number of bad peers
      // has been broken.
      GNUNET_break_op (0);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "P%u: NOT finishing early (majority not good enough)\n",
                  session->local_peer_idx);
    }
  }
  GNUNET_CONTAINER_multihashmap_iterator_destroy (iter);
}


static void
task_start_grade (struct TaskEntry *task)
{
  struct ConsensusSession *session = task->step->session;
  struct ReferendumEntry *output_rfn;
  struct ReferendumEntry *input_rfn;
  struct DiffEntry *input_diff;
  struct RfnKey rfn_key;
  struct DiffKey diff_key;
  struct GNUNET_CONTAINER_MultiHashMapIterator *iter;
  struct RfnElementInfo *ri;
  unsigned int gradecast_confidence = 2;

  rfn_key = (struct RfnKey) { RFN_KIND_GRADECAST_RESULT, task->key.repetition };
  output_rfn = lookup_rfn (session, &rfn_key);
  if (NULL == output_rfn)
  {
    output_rfn = rfn_create (session->num_peers);
    output_rfn->key = rfn_key;
    put_rfn (session, output_rfn);
  }

  diff_key = (struct DiffKey) { DIFF_KIND_LEADER_PROPOSAL, task->key.repetition, task->key.leader };
  input_diff = lookup_diff (session, &diff_key);
  GNUNET_assert (NULL != input_diff);

  rfn_key = (struct RfnKey) { RFN_KIND_ECHO, task->key.repetition, task->key.leader };
  input_rfn = lookup_rfn (session, &rfn_key);
  GNUNET_assert (NULL != input_rfn);

  iter = GNUNET_CONTAINER_multihashmap_iterator_create (input_rfn->rfn_elements);

  apply_diff_to_rfn (input_diff, output_rfn, task->key.leader, session->num_peers);

  while (GNUNET_YES ==
         GNUNET_CONTAINER_multihashmap_iterator_next (iter,
                                                      NULL,
                                                      (const void **) &ri))
  {
    uint16_t majority_num;
    enum ReferendumVote majority_vote;

    // XXX: we need contested votes and non-contested votes here
    rfn_majority (input_rfn, ri, &majority_num, &majority_vote);

    if (majority_num <= session->num_peers / 3)
      majority_vote = VOTE_REMOVE;

    switch (majority_vote)
    {
      case VOTE_STAY:
        break;
      case VOTE_ADD:
        rfn_vote (output_rfn, task->key.leader, VOTE_ADD, ri->element);
        break;
      case VOTE_REMOVE:
        rfn_vote (output_rfn, task->key.leader, VOTE_REMOVE, ri->element);
        break;
      default:
        GNUNET_assert (0);
        break;
    }
  }
  GNUNET_CONTAINER_multihashmap_iterator_destroy (iter);

  {
    uint16_t noncontested;
    noncontested = rfn_noncontested (input_rfn);
    if (noncontested < (session->num_peers / 3) * 2)
    {
      gradecast_confidence = GNUNET_MIN(1, gradecast_confidence);
    }
    if (noncontested < (session->num_peers / 3) + 1)
    {
      gradecast_confidence = 0;
    }
  }

  if (gradecast_confidence >= 1)
    rfn_commit (output_rfn, task->key.leader);

  if (gradecast_confidence <= 1)
    session->peers_blacklisted[task->key.leader] = GNUNET_YES;

  finish_task (task);
}


static void
task_start_reconcile (struct TaskEntry *task)
{
  struct SetEntry *input;
  struct SetOpCls *setop = &task->cls.setop;
  struct ConsensusSession *session = task->step->session;

  input = lookup_set (session, &setop->input_set);
  GNUNET_assert (NULL != input);
  GNUNET_assert (NULL != input->h);

  /* We create the outputs for the operation here
     (rather than in the set operation callback)
     because we want something valid in there, even
     if the other peer doesn't talk to us */

  if (SET_KIND_NONE != setop->output_set.set_kind)
  {
    /* If we don't have an existing output set,
       we clone the input set. */
    if (NULL == lookup_set (session, &setop->output_set))
    {
      create_set_copy_for_task (task, &setop->input_set, &setop->output_set);
      return;
    }
  }

  if (RFN_KIND_NONE != setop->output_rfn.rfn_kind)
  {
    if (NULL == lookup_rfn (session, &setop->output_rfn))
    {
      struct ReferendumEntry *rfn;

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "P%u: output rfn <%s> missing, creating.\n",
                  session->local_peer_idx,
                  debug_str_rfn_key (&setop->output_rfn));

      rfn = rfn_create (session->num_peers);
      rfn->key = setop->output_rfn;
      put_rfn (session, rfn);
    }
  }

  if (DIFF_KIND_NONE != setop->output_diff.diff_kind)
  {
    if (NULL == lookup_diff (session, &setop->output_diff))
    {
      struct DiffEntry *diff;

      diff = diff_create ();
      diff->key = setop->output_diff;
      put_diff (session, diff);
    }
  }

  if ( (task->key.peer1 == session->local_peer_idx) && (task->key.peer2 == session->local_peer_idx) )
  {
    /* XXX: mark the corresponding rfn as commited if necessary */
    finish_task (task);
    return;
  }

  if (task->key.peer1 == session->local_peer_idx)
  {
    struct GNUNET_CONSENSUS_RoundContextMessage rcm;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "P%u: Looking up set {%s} to run remote union\n",
                session->local_peer_idx,
                debug_str_set_key (&setop->input_set));

    rcm.header.type = htons (GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_ROUND_CONTEXT);
    rcm.header.size = htons (sizeof (struct GNUNET_CONSENSUS_RoundContextMessage));

    rcm.kind = htons (task->key.kind);
    rcm.peer1 = htons (task->key.peer1);
    rcm.peer2 = htons (task->key.peer2);
    rcm.leader = htons (task->key.leader);
    rcm.repetition = htons (task->key.repetition);
    rcm.is_contested = htons (0);

    GNUNET_assert (NULL == setop->op);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "P%u: initiating set op with P%u, our set is %s\n",
                session->local_peer_idx, task->key.peer2, debug_str_set_key (&setop->input_set));

    struct GNUNET_SET_Option opts[] = {
      { GNUNET_SET_OPTION_BYZANTINE, { .num = session->lower_bound } },
      { GNUNET_SET_OPTION_END },
    };

    // XXX: maybe this should be done while
    // setting up tasks alreays?
    setop->op = GNUNET_SET_prepare (&session->peers[task->key.peer2],
                                    &session->global_id,
                                    &rcm.header,
                                    GNUNET_SET_RESULT_SYMMETRIC,
                                    opts,
                                    set_result_cb,
                                    task);

    commit_set (session, task);
  }
  else if (task->key.peer2 == session->local_peer_idx)
  {
    /* Wait for the other peer to contact us */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "P%u: waiting set op with P%u\n",
                session->local_peer_idx, task->key.peer1);

    if (NULL != setop->op)
    {
      commit_set (session, task);
    }
  }
  else
  {
    /* We made an error while constructing the task graph. */
    GNUNET_assert (0);
  }
}


static void
task_start_eval_echo (struct TaskEntry *task)
{
  struct GNUNET_CONTAINER_MultiHashMapIterator *iter;
  struct ReferendumEntry *input_rfn;
  struct RfnElementInfo *ri;
  struct SetEntry *output_set;
  struct SetMutationProgressCls *progress_cls;
  struct ConsensusSession *session = task->step->session;
  struct SetKey sk_in;
  struct SetKey sk_out;
  struct RfnKey rk_in;

  sk_in = (struct SetKey) { SET_KIND_LEADER_PROPOSAL, task->key.repetition, task->key.leader };
  sk_out = (struct SetKey) { SET_KIND_ECHO_RESULT, task->key.repetition, task->key.leader };
  output_set = lookup_set (session, &sk_out);
  if (NULL == output_set)
  {
    create_set_copy_for_task (task, &sk_in, &sk_out);
    return;
  }


  {
    // FIXME: should be marked as a shallow copy, so
    // we can destroy everything correctly
    struct SetEntry *last_set = GNUNET_new (struct SetEntry);
    last_set->h = output_set->h;
    last_set->key = (struct SetKey) { SET_KIND_LAST_GRADECAST };
    put_set (session, last_set);
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Evaluating referendum in Task {%s}\n",
              debug_str_task_key (&task->key));

  progress_cls = GNUNET_new (struct SetMutationProgressCls);
  progress_cls->task = task;

  rk_in = (struct RfnKey) { RFN_KIND_ECHO, task->key.repetition, task->key.leader };
  input_rfn = lookup_rfn (session, &rk_in);

  GNUNET_assert (NULL != input_rfn);

  iter = GNUNET_CONTAINER_multihashmap_iterator_create (input_rfn->rfn_elements);
  GNUNET_assert (NULL != iter);

  while (GNUNET_YES ==
         GNUNET_CONTAINER_multihashmap_iterator_next (iter,
                                                      NULL,
                                                      (const void **) &ri))
  {
    enum ReferendumVote majority_vote;
    uint16_t majority_num;

    rfn_majority (input_rfn, ri, &majority_num, &majority_vote);

    if (majority_num < session->num_peers / 3)
    {
      /* It is not the case that all nonfaulty peers
         echoed the same value.  Since we're doing a set reconciliation, we
         can't simply send "nothing" for the value.  Thus we mark our 'confirm'
         reconciliation as contested.  Other peers might not know that the
         leader is faulty, thus we still re-distribute in the confirmation
         round. */
      output_set->is_contested = GNUNET_YES;
    }

    switch (majority_vote)
    {
      case VOTE_ADD:
        progress_cls->num_pending++;
        GNUNET_assert (GNUNET_OK ==
                       GNUNET_SET_add_element (output_set->h,
                                               ri->element,
                                               set_mutation_done,
                                               progress_cls));
        break;
      case VOTE_REMOVE:
        progress_cls->num_pending++;
        GNUNET_assert (GNUNET_OK ==
                       GNUNET_SET_remove_element (output_set->h,
                                                  ri->element,
                                                  set_mutation_done,
                                                  progress_cls));
        break;
      case VOTE_STAY:
        /* Nothing to do. */
        break;
      default:
        /* not reached */
        GNUNET_assert (0);
    }
  }

  GNUNET_CONTAINER_multihashmap_iterator_destroy (iter);

  if (0 == progress_cls->num_pending)
  {
    // call closure right now, no pending ops
    GNUNET_free (progress_cls);
    finish_task (task);
  }
}


static void
task_start_finish (struct TaskEntry *task)
{
  struct SetEntry *final_set;
  struct ConsensusSession *session = task->step->session;

  final_set = lookup_set (session, &task->cls.finish.input_set);

  GNUNET_assert (NULL != final_set);


  GNUNET_SET_iterate (final_set->h,
                      send_to_client_iter,
                      task);
}

static void
start_task (struct ConsensusSession *session, struct TaskEntry *task)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "P%u: starting task {%s}\n", session->local_peer_idx, debug_str_task_key (&task->key));

  GNUNET_assert (GNUNET_NO == task->is_started);
  GNUNET_assert (GNUNET_NO == task->is_finished);
  GNUNET_assert (NULL != task->start);

  task->start (task);

  task->is_started = GNUNET_YES;
}




/*
 * Run all steps of the session that don't any
 * more dependencies.
 */
static void
run_ready_steps (struct ConsensusSession *session)
{
  struct Step *step;

  step = session->steps_head;

  while (NULL != step)
  {
    if ( (GNUNET_NO == step->is_running) && (0 == step->pending_prereq) && (GNUNET_NO == step->is_finished) )
    {
      size_t i;

      GNUNET_assert (0 == step->finished_tasks);

#ifdef GNUNET_EXTRA_LOGGING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "P%u: Running step `%s' of round %d with %d tasks and %d subordinates\n",
                  session->local_peer_idx,
                  step->debug_name,
                  step->round, step->tasks_len, step->subordinates_len);
#endif

      step->is_running = GNUNET_YES;
      for (i = 0; i < step->tasks_len; i++)
        start_task (session, step->tasks[i]);

      /* Sometimes there is no task to trigger finishing the step, so we have to do it here. */
      if ( (step->finished_tasks == step->tasks_len) && (GNUNET_NO == step->is_finished))
        finish_step (step);

      /* Running the next ready steps will be triggered by task completion */
      return;
    }
    step = step->next;
  }

  return;
}



static void
finish_task (struct TaskEntry *task)
{
  GNUNET_assert (GNUNET_NO == task->is_finished);
  task->is_finished = GNUNET_YES;

  task->step->finished_tasks++;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "P%u: Finishing Task {%s} (now %u/%u tasks finished in step)\n",
              task->step->session->local_peer_idx,
              debug_str_task_key (&task->key),
              (unsigned int) task->step->finished_tasks,
              (unsigned int) task->step->tasks_len);

  if (task->step->finished_tasks == task->step->tasks_len)
    finish_step (task->step);
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
    if (0 == memcmp (peer, &session->peers[i], sizeof (struct GNUNET_PeerIdentity)))
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
 * @param local_session_id local id of the consensus session
 */
static void
compute_global_id (struct ConsensusSession *session,
		   const struct GNUNET_HashCode *local_session_id)
{
  const char *salt = "gnunet-service-consensus/session_id";

  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CRYPTO_kdf (&session->global_id,
                                    sizeof (struct GNUNET_HashCode),
                                    salt,
                                    strlen (salt),
                                    session->peers,
                                    session->num_peers * sizeof (struct GNUNET_PeerIdentity),
                                    local_session_id,
                                    sizeof (struct GNUNET_HashCode),
                                    NULL));
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
 *
 * @param session session to initialize
 * @param join_msg join message with the list of peers participating at the end
 */
static void
initialize_session_peer_list (struct ConsensusSession *session,
                              const struct GNUNET_CONSENSUS_JoinMessage *join_msg)
{
  const struct GNUNET_PeerIdentity *msg_peers
    = (const struct GNUNET_PeerIdentity *) &join_msg[1];
  int local_peer_in_list;

  session->num_peers = ntohl (join_msg->num_peers);

  /* Peers in the join message, may or may not include the local peer,
     Add it if it is missing. */
  local_peer_in_list = GNUNET_NO;
  for (unsigned int i = 0; i < session->num_peers; i++)
  {
    if (0 == memcmp (&msg_peers[i],
                     &my_peer,
                     sizeof (struct GNUNET_PeerIdentity)))
    {
      local_peer_in_list = GNUNET_YES;
      break;
    }
  }
  if (GNUNET_NO == local_peer_in_list)
    session->num_peers++;

  session->peers = GNUNET_new_array (session->num_peers,
                                     struct GNUNET_PeerIdentity);
  if (GNUNET_NO == local_peer_in_list)
    session->peers[session->num_peers - 1] = my_peer;

  GNUNET_memcpy (session->peers,
                 msg_peers,
                 ntohl (join_msg->num_peers) * sizeof (struct GNUNET_PeerIdentity));
  qsort (session->peers,
         session->num_peers,
         sizeof (struct GNUNET_PeerIdentity),
         &peer_id_cmp);
}


static struct TaskEntry *
lookup_task (struct ConsensusSession *session,
             struct TaskKey *key)
{
  struct GNUNET_HashCode hash;


  GNUNET_CRYPTO_hash (key, sizeof (struct TaskKey), &hash);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Looking up task hash %s\n",
              GNUNET_h2s (&hash));
  return GNUNET_CONTAINER_multihashmap_get (session->taskmap, &hash);
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
  struct TaskKey tk;
  struct TaskEntry *task;
  struct GNUNET_CONSENSUS_RoundContextMessage *cm;

  if (NULL == context_msg)
  {
    GNUNET_break_op (0);
    return;
  }

  if (GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_ROUND_CONTEXT != ntohs (context_msg->type))
  {
    GNUNET_break_op (0);
    return;
  }

  if (sizeof (struct GNUNET_CONSENSUS_RoundContextMessage) != ntohs (context_msg->size))
  {
    GNUNET_break_op (0);
    return;
  }

  cm = (struct GNUNET_CONSENSUS_RoundContextMessage *) context_msg;

  tk = ((struct TaskKey) {
      .kind = ntohs (cm->kind),
      .peer1 = ntohs (cm->peer1),
      .peer2 = ntohs (cm->peer2),
      .repetition = ntohs (cm->repetition),
      .leader = ntohs (cm->leader),
  });

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "P%u: got req for task %s\n",
              session->local_peer_idx, debug_str_task_key (&tk));

  task = lookup_task (session, &tk);

  if (NULL == task)
  {
    GNUNET_break_op (0);
    return;
  }

  if (GNUNET_YES == task->is_finished)
  {
    GNUNET_break_op (0);
    return;
  }

  if (task->key.peer2 != session->local_peer_idx)
  {
    /* We're being asked, so we must be thne 2nd peer. */
    GNUNET_break_op (0);
    return;
  }

  GNUNET_assert (! ((task->key.peer1 == session->local_peer_idx) &&
                    (task->key.peer2 == session->local_peer_idx)));

  struct GNUNET_SET_Option opts[] = {
    { GNUNET_SET_OPTION_BYZANTINE, { .num = session->lower_bound } },
    { GNUNET_SET_OPTION_END },
  };

  task->cls.setop.op = GNUNET_SET_accept (request,
                                          GNUNET_SET_RESULT_SYMMETRIC,
                                          opts,
                                          set_result_cb,
                                          task);

  /* If the task hasn't been started yet,
     we wait for that until we commit. */

  if (GNUNET_YES == task->is_started)
  {
    commit_set (session, task);
  }
}



static void
put_task (struct GNUNET_CONTAINER_MultiHashMap *taskmap,
          struct TaskEntry *t)
{
  struct GNUNET_HashCode round_hash;
  struct Step *s;

  GNUNET_assert (NULL != t->step);

  t = GNUNET_memdup (t, sizeof (struct TaskEntry));

  s = t->step;

  if (s->tasks_len == s->tasks_cap)
  {
    unsigned int target_size = 3 * (s->tasks_cap + 1) / 2;
    GNUNET_array_grow (s->tasks,
                       s->tasks_cap,
                       target_size);
  }

#ifdef GNUNET_EXTRA_LOGGING
  GNUNET_assert (NULL != s->debug_name);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Putting task <%s> into step `%s'\n",
              debug_str_task_key (&t->key),
              s->debug_name);
#endif

  s->tasks[s->tasks_len] = t;
  s->tasks_len++;

  GNUNET_CRYPTO_hash (&t->key, sizeof (struct TaskKey), &round_hash);
  GNUNET_assert (GNUNET_OK ==
      GNUNET_CONTAINER_multihashmap_put (taskmap, &round_hash, t,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
}


static void
install_step_timeouts (struct ConsensusSession *session)
{
  /* Given the fully constructed task graph
     with rounds for tasks, we can give the tasks timeouts. */

  // unsigned int max_round;

  /* XXX: implement! */
}



/*
 * Arrange two peers in some canonical order.
 */
static void
arrange_peers (uint16_t *p1, uint16_t *p2, uint16_t n)
{
  uint16_t a;
  uint16_t b;

  GNUNET_assert (*p1 < n);
  GNUNET_assert (*p2 < n);

  if (*p1 < *p2)
  {
    a = *p1;
    b = *p2;
  }
  else
  {
    a = *p2;
    b = *p1;
  }

  /* For uniformly random *p1, *p2,
     this condition is true with 50% chance */
  if (((b - a) + n) % n <= n / 2)
  {
    *p1 = a;
    *p2 = b;
  }
  else
  {
    *p1 = b;
    *p2 = a;
  }
}


/**
 * Record @a dep as a dependency of @a step.
 */
static void
step_depend_on (struct Step *step, struct Step *dep)
{
  /* We're not checking for cyclic dependencies,
     but this is a cheap sanity check. */
  GNUNET_assert (step != dep);
  GNUNET_assert (NULL != step);
  GNUNET_assert (NULL != dep);
  GNUNET_assert (dep->round <= step->round);

#ifdef GNUNET_EXTRA_LOGGING
  /* Make sure we have complete debugging information.
     Also checks that we don't screw up too badly
     constructing the task graph. */
  GNUNET_assert (NULL != step->debug_name);
  GNUNET_assert (NULL != dep->debug_name);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Making step `%s' depend on `%s'\n",
              step->debug_name,
              dep->debug_name);
#endif

  if (dep->subordinates_cap == dep->subordinates_len)
  {
    unsigned int target_size = 3 * (dep->subordinates_cap + 1) / 2;
    GNUNET_array_grow (dep->subordinates,
                       dep->subordinates_cap,
                       target_size);
  }

  GNUNET_assert (dep->subordinates_len <= dep->subordinates_cap);

  dep->subordinates[dep->subordinates_len] = step;
  dep->subordinates_len++;

  step->pending_prereq++;
}


static struct Step *
create_step (struct ConsensusSession *session, int round, int early_finishable)
{
  struct Step *step;
  step = GNUNET_new (struct Step);
  step->session = session;
  step->round = round;
  step->early_finishable = early_finishable;
  GNUNET_CONTAINER_DLL_insert_tail (session->steps_head,
                                    session->steps_tail,
                                    step);
  return step;
}


/**
 * Construct the task graph for a single
 * gradecast.
 */
static void
construct_task_graph_gradecast (struct ConsensusSession *session,
                                uint16_t rep,
                                uint16_t lead,
                                struct Step *step_before,
                                struct Step *step_after)
{
  uint16_t n = session->num_peers;
  uint16_t me = session->local_peer_idx;

  uint16_t p1;
  uint16_t p2;

  /* The task we're currently setting up. */
  struct TaskEntry task;

  struct Step *step;
  struct Step *prev_step;

  uint16_t round;

  unsigned int k;

  round = step_before->round + 1;

  /* gcast step 1: leader disseminates */

  step = create_step (session, round, GNUNET_YES);

#ifdef GNUNET_EXTRA_LOGGING
  GNUNET_asprintf (&step->debug_name, "disseminate leader %u rep %u", lead, rep);
#endif
  step_depend_on (step, step_before);

  if (lead == me)
  {
    for (k = 0; k < n; k++)
    {
      if (k == me)
        continue;
      p1 = me;
      p2 = k;
      arrange_peers (&p1, &p2, n);
      task = ((struct TaskEntry) {
        .step = step,
        .start = task_start_reconcile,
        .cancel = task_cancel_reconcile,
        .key = (struct TaskKey) { PHASE_KIND_GRADECAST_LEADER, p1, p2, rep, me },
      });
      task.cls.setop.input_set = (struct SetKey) { SET_KIND_CURRENT, rep };
      put_task (session->taskmap, &task);
    }
    /* We run this task to make sure that the leader
       has the stored the SET_KIND_LEADER set of himself,
       so it can participate in the rest of the gradecast
       without the code having to handle any special cases. */
    task = ((struct TaskEntry) {
      .step = step,
      .key = (struct TaskKey) { PHASE_KIND_GRADECAST_LEADER, me, me, rep, me },
      .start = task_start_reconcile,
      .cancel = task_cancel_reconcile,
    });
    task.cls.setop.input_set = (struct SetKey) { SET_KIND_CURRENT, rep };
    task.cls.setop.output_set = (struct SetKey) { SET_KIND_LEADER_PROPOSAL, rep, me };
    task.cls.setop.output_diff = (struct DiffKey) { DIFF_KIND_LEADER_PROPOSAL, rep, me };
    put_task (session->taskmap, &task);
  }
  else
  {
    p1 = me;
    p2 = lead;
    arrange_peers (&p1, &p2, n);
    task = ((struct TaskEntry) {
      .step = step,
      .key = (struct TaskKey) { PHASE_KIND_GRADECAST_LEADER, p1, p2, rep, lead },
      .start = task_start_reconcile,
      .cancel = task_cancel_reconcile,
    });
    task.cls.setop.input_set = (struct SetKey) { SET_KIND_CURRENT, rep };
    task.cls.setop.output_set = (struct SetKey) { SET_KIND_LEADER_PROPOSAL, rep, lead };
    task.cls.setop.output_diff = (struct DiffKey) { DIFF_KIND_LEADER_PROPOSAL, rep, lead };
    put_task (session->taskmap, &task);
  }

  /* gcast phase 2: echo */
  prev_step = step;
  round += 1;
  step = create_step (session, round, GNUNET_YES);
#ifdef GNUNET_EXTRA_LOGGING
  GNUNET_asprintf (&step->debug_name, "echo leader %u rep %u", lead, rep);
#endif
  step_depend_on (step, prev_step);

  for (k = 0; k < n; k++)
  {
    p1 = k;
    p2 = me;
    arrange_peers (&p1, &p2, n);
    task = ((struct TaskEntry) {
      .step = step,
      .key = (struct TaskKey) { PHASE_KIND_GRADECAST_ECHO, p1, p2, rep, lead },
      .start = task_start_reconcile,
      .cancel = task_cancel_reconcile,
    });
    task.cls.setop.input_set = (struct SetKey) { SET_KIND_LEADER_PROPOSAL, rep, lead };
    task.cls.setop.output_rfn = (struct RfnKey) { RFN_KIND_ECHO, rep, lead };
    put_task (session->taskmap, &task);
  }

  prev_step = step;
  /* Same round, since step only has local tasks */
  step = create_step (session, round, GNUNET_YES);
#ifdef GNUNET_EXTRA_LOGGING
  GNUNET_asprintf (&step->debug_name, "echo grade leader %u rep %u", lead, rep);
#endif
  step_depend_on (step, prev_step);

  arrange_peers (&p1, &p2, n);
  task = ((struct TaskEntry) {
    .key = (struct TaskKey) { PHASE_KIND_GRADECAST_ECHO_GRADE, -1, -1, rep, lead },
    .step = step,
    .start = task_start_eval_echo
  });
  put_task (session->taskmap, &task);

  prev_step = step;
  round += 1;
  step = create_step (session, round, GNUNET_YES);
#ifdef GNUNET_EXTRA_LOGGING
  GNUNET_asprintf (&step->debug_name, "confirm leader %u rep %u", lead, rep);
#endif
  step_depend_on (step, prev_step);

  /* gcast phase 3: confirmation and grading */
  for (k = 0; k < n; k++)
  {
    p1 = k;
    p2 = me;
    arrange_peers (&p1, &p2, n);
    task = ((struct TaskEntry) {
      .step = step,
      .start = task_start_reconcile,
      .cancel = task_cancel_reconcile,
      .key = (struct TaskKey) { PHASE_KIND_GRADECAST_CONFIRM, p1, p2, rep, lead},
    });
    task.cls.setop.input_set = (struct SetKey) { SET_KIND_ECHO_RESULT, rep, lead };
    task.cls.setop.output_rfn = (struct RfnKey) { RFN_KIND_CONFIRM, rep, lead };
    /* If there was at least one element in the echo round that was
       contested (i.e. it had no n-t majority), then we let the other peers
       know, and other peers let us know.  The contested flag for each peer is
       stored in the rfn. */
    task.cls.setop.transceive_contested = GNUNET_YES;
    put_task (session->taskmap, &task);
  }

  prev_step = step;
  /* Same round, since step only has local tasks */
  step = create_step (session, round, GNUNET_YES);
#ifdef GNUNET_EXTRA_LOGGING
  GNUNET_asprintf (&step->debug_name, "confirm grade leader %u rep %u", lead, rep);
#endif
  step_depend_on (step, prev_step);

  task = ((struct TaskEntry) {
    .step = step,
    .key = (struct TaskKey) { PHASE_KIND_GRADECAST_CONFIRM_GRADE, -1, -1, rep, lead },
    .start = task_start_grade,
  });
  put_task (session->taskmap, &task);

  step_depend_on (step_after, step);
}


static void
construct_task_graph (struct ConsensusSession *session)
{
  uint16_t n = session->num_peers;
  uint16_t t = n / 3;

  uint16_t me = session->local_peer_idx;

  /* The task we're currently setting up. */
  struct TaskEntry task;

  /* Current leader */
  unsigned int lead;

  struct Step *step;
  struct Step *prev_step;

  unsigned int round = 0;

  unsigned int i;

  // XXX: introduce first step,
  // where we wait for all insert acks
  // from the set service

  /* faster but brittle all-to-all */

  // XXX: Not implemented yet

  /* all-to-all step */

  step = create_step (session, round, GNUNET_NO);

#ifdef GNUNET_EXTRA_LOGGING
  step->debug_name = GNUNET_strdup ("all to all");
#endif

  for (i = 0; i < n; i++)
  {
    uint16_t p1;
    uint16_t p2;

    p1 = me;
    p2 = i;
    arrange_peers (&p1, &p2, n);
    task = ((struct TaskEntry) {
      .key = (struct TaskKey) { PHASE_KIND_ALL_TO_ALL, p1, p2, -1, -1 },
      .step = step,
      .start = task_start_reconcile,
      .cancel = task_cancel_reconcile,
    });
    task.cls.setop.input_set = (struct SetKey) { SET_KIND_CURRENT, 0 };
    task.cls.setop.output_set = task.cls.setop.input_set;
    task.cls.setop.do_not_remove = GNUNET_YES;
    put_task (session->taskmap, &task);
  }

  round += 1;
  prev_step = step;
  step = create_step (session, round, GNUNET_NO);;
#ifdef GNUNET_EXTRA_LOGGING
  step->debug_name = GNUNET_strdup ("all to all 2");
#endif
  step_depend_on (step, prev_step);


  for (i = 0; i < n; i++)
  {
    uint16_t p1;
    uint16_t p2;

    p1 = me;
    p2 = i;
    arrange_peers (&p1, &p2, n);
    task = ((struct TaskEntry) {
      .key = (struct TaskKey) { PHASE_KIND_ALL_TO_ALL_2, p1, p2, -1, -1 },
      .step = step,
      .start = task_start_reconcile,
      .cancel = task_cancel_reconcile,
    });
    task.cls.setop.input_set = (struct SetKey) { SET_KIND_CURRENT, 0 };
    task.cls.setop.output_set = task.cls.setop.input_set;
    task.cls.setop.do_not_remove = GNUNET_YES;
    put_task (session->taskmap, &task);
  }

  round += 1;

  prev_step = step;
  step = NULL;



  /* Byzantine union */

  /* sequential repetitions of the gradecasts */
  for (i = 0; i < t + 1; i++)
  {
    struct Step *step_rep_start;
    struct Step *step_rep_end;

    /* Every repetition is in a separate round. */
    step_rep_start = create_step (session, round, GNUNET_YES);
#ifdef GNUNET_EXTRA_LOGGING
    GNUNET_asprintf (&step_rep_start->debug_name, "gradecast start rep %u", i);
#endif

    step_depend_on (step_rep_start, prev_step);

    /* gradecast has three rounds */
    round += 3;
    step_rep_end = create_step (session, round, GNUNET_YES);
#ifdef GNUNET_EXTRA_LOGGING
    GNUNET_asprintf (&step_rep_end->debug_name, "gradecast end rep %u", i);
#endif

    /* parallel gradecasts */
    for (lead = 0; lead < n; lead++)
      construct_task_graph_gradecast (session, i, lead, step_rep_start, step_rep_end);

    task = ((struct TaskEntry) {
      .step = step_rep_end,
      .key = (struct TaskKey) { PHASE_KIND_APPLY_REP, -1, -1, i, -1},
      .start = task_start_apply_round,
    });
    put_task (session->taskmap, &task);

    prev_step = step_rep_end;
  }

 /* There is no next gradecast round, thus the final
    start step is the overall end step of the gradecasts */
  round += 1;
  step = create_step (session, round, GNUNET_NO);
#ifdef GNUNET_EXTRA_LOGGING
  GNUNET_asprintf (&step->debug_name, "finish");
#endif
  step_depend_on (step, prev_step);

  task = ((struct TaskEntry) {
    .step = step,
    .key = (struct TaskKey) { PHASE_KIND_FINISH, -1, -1, -1, -1 },
    .start = task_start_finish,
  });
  task.cls.finish.input_set = (struct SetKey) { SET_KIND_LAST_GRADECAST };

  put_task (session->taskmap, &task);
}



/**
 * Check join message.
 *
 * @param cls session of client that sent the message
 * @param m message sent by the client
 * @return #GNUNET_OK if @a m is well-formed
 */
static int
check_client_join (void *cls,
                   const struct GNUNET_CONSENSUS_JoinMessage *m)
{
  uint32_t listed_peers = ntohl (m->num_peers);

  if ( (ntohs (m->header.size) - sizeof (*m)) !=
       listed_peers * sizeof (struct GNUNET_PeerIdentity))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Called when a client wants to join a consensus session.
 *
 * @param cls session of client that sent the message
 * @param m message sent by the client
 */
static void
handle_client_join (void *cls,
                    const struct GNUNET_CONSENSUS_JoinMessage *m)
{
  struct ConsensusSession *session = cls;
  struct ConsensusSession *other_session;

  initialize_session_peer_list (session,
                                m);
  compute_global_id (session,
                     &m->session_id);

  /* Check if some local client already owns the session.
     It is only legal to have a session with an existing global id
     if all other sessions with this global id are finished.*/
  for (other_session = sessions_head;
       NULL != other_session;
       other_session = other_session->next)
  {
    if ( (other_session != session) &&
         (0 == GNUNET_CRYPTO_hash_cmp (&session->global_id,
                                       &other_session->global_id)) )
      break;
  }

  session->conclude_deadline
    = GNUNET_TIME_absolute_ntoh (m->deadline);
  session->conclude_start
    = GNUNET_TIME_absolute_ntoh (m->start);
  session->local_peer_idx = get_peer_idx (&my_peer,
                                          session);
  GNUNET_assert (-1 != session->local_peer_idx);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Joining consensus session %s containing %u peers as %u with timeout %s\n",
              GNUNET_h2s (&m->session_id),
              session->num_peers,
              session->local_peer_idx,
              GNUNET_STRINGS_relative_time_to_string
              (GNUNET_TIME_absolute_get_difference (session->conclude_start,
                                                    session->conclude_deadline),
               GNUNET_YES));

  session->set_listener
    = GNUNET_SET_listen (cfg,
                         GNUNET_SET_OPERATION_UNION,
                         &session->global_id,
                         &set_listen_cb,
                         session);

  session->setmap = GNUNET_CONTAINER_multihashmap_create (1,
                                                          GNUNET_NO);
  session->taskmap = GNUNET_CONTAINER_multihashmap_create (1,
                                                           GNUNET_NO);
  session->diffmap = GNUNET_CONTAINER_multihashmap_create (1,
                                                           GNUNET_NO);
  session->rfnmap = GNUNET_CONTAINER_multihashmap_create (1,
                                                          GNUNET_NO);

  {
    struct SetEntry *client_set;

    client_set = GNUNET_new (struct SetEntry);
    client_set->h = GNUNET_SET_create (cfg,
                                       GNUNET_SET_OPERATION_UNION);
    struct SetHandle *sh = GNUNET_new (struct SetHandle);
    sh->h = client_set->h;
    GNUNET_CONTAINER_DLL_insert (session->set_handles_head,
                                 session->set_handles_tail,
                                 sh);
    client_set->key = ((struct SetKey) { SET_KIND_CURRENT, 0, 0 });
    put_set (session,
             client_set);
  }

  session->peers_blacklisted = GNUNET_new_array (session->num_peers,
                                                 int);

  /* Just construct the task graph,
     but don't run anything until the client calls conclude. */
  construct_task_graph (session);
  GNUNET_SERVICE_client_continue (session->client);
}


static void
client_insert_done (void *cls)
{
  // FIXME: implement
}


/**
 * Called when a client performs an insert operation.
 *
 * @param cls client handle
 * @param msg message sent by the client
 * @return #GNUNET_OK (always well-formed)
 */
static int
check_client_insert (void *cls,
                      const struct GNUNET_CONSENSUS_ElementMessage *msg)
{
  return GNUNET_OK;
}


/**
 * Called when a client performs an insert operation.
 *
 * @param cls client handle
 * @param msg message sent by the client
 */
static void
handle_client_insert (void *cls,
                      const struct GNUNET_CONSENSUS_ElementMessage *msg)
{
  struct ConsensusSession *session = cls;
  ssize_t element_size;
  struct GNUNET_SET_Handle *initial_set;
  struct ConsensusElement *ce;

  if (GNUNET_YES == session->conclude_started)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (session->client);
    return;
  }

  element_size = ntohs (msg->header.size) - sizeof (struct GNUNET_CONSENSUS_ElementMessage);
  ce = GNUNET_malloc (sizeof (struct ConsensusElement) + element_size);
  GNUNET_memcpy (&ce[1], &msg[1], element_size);
  ce->payload_type = msg->element_type;

  struct GNUNET_SET_Element element = {
    .element_type = GNUNET_BLOCK_TYPE_CONSENSUS_ELEMENT,
    .size = sizeof (struct ConsensusElement) + element_size,
    .data = ce,
  };

  {
    struct SetKey key = { SET_KIND_CURRENT, 0, 0 };
    struct SetEntry *entry;

    entry = lookup_set (session,
                        &key);
    GNUNET_assert (NULL != entry);
    initial_set = entry->h;
  }

  session->num_client_insert_pending++;
  GNUNET_SET_add_element (initial_set,
                          &element,
                          &client_insert_done,
                          session);

#ifdef GNUNET_EXTRA_LOGGING
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "P%u: element %s added\n",
                session->local_peer_idx,
                debug_str_element (&element));
  }
#endif
  GNUNET_free (ce);
  GNUNET_SERVICE_client_continue (session->client);
}


/**
 * Called when a client performs the conclude operation.
 *
 * @param cls client handle
 * @param message message sent by the client
 */
static void
handle_client_conclude (void *cls,
                        const struct GNUNET_MessageHeader *message)
{
  struct ConsensusSession *session = cls;

  if (GNUNET_YES == session->conclude_started)
  {
    /* conclude started twice */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (session->client);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "conclude requested\n");
  session->conclude_started = GNUNET_YES;
  install_step_timeouts (session);
  run_ready_steps (session);
  GNUNET_SERVICE_client_continue (session->client);
}


/**
 * Called to clean up, after a shutdown has been requested.
 *
 * @param cls closure
 */
static void
shutdown_task (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "shutting down\n");
  GNUNET_STATISTICS_destroy (statistics,
                             GNUNET_NO);
  statistics = NULL;
}


/**
 * Start processing consensus requests.
 *
 * @param cls closure
 * @param c configuration to use
 * @param service the initialized service
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_SERVICE_Handle *service)
{
  cfg = c;
  if (GNUNET_OK !=
      GNUNET_CRYPTO_get_peer_identity (cfg,
                                       &my_peer))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not retrieve host identity\n");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  statistics = GNUNET_STATISTICS_create ("consensus",
                                         cfg);
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
                                 NULL);
}


/**
 * Callback called when a client connects to the service.
 *
 * @param cls closure for the service
 * @param c the new client that connected to the service
 * @param mq the message queue used to send messages to the client
 * @return @a c
 */
static void *
client_connect_cb (void *cls,
		   struct GNUNET_SERVICE_Client *c,
		   struct GNUNET_MQ_Handle *mq)
{
  struct ConsensusSession *session = GNUNET_new (struct ConsensusSession);

  session->client = c;
  session->client_mq = mq;
  GNUNET_CONTAINER_DLL_insert (sessions_head,
                               sessions_tail,
                               session);
  return session;
}


/**
 * Callback called when a client disconnected from the service
 *
 * @param cls closure for the service
 * @param c the client that disconnected
 * @param internal_cls should be equal to @a c
 */
static void
client_disconnect_cb (void *cls,
		      struct GNUNET_SERVICE_Client *c,
		      void *internal_cls)
{
  struct ConsensusSession *session = internal_cls;

  if (NULL != session->set_listener)
  {
    GNUNET_SET_listen_cancel (session->set_listener);
    session->set_listener = NULL;
  }
  GNUNET_CONTAINER_DLL_remove (sessions_head,
                               sessions_tail,
                               session);

  while (session->set_handles_head)
  {
    struct SetHandle *sh = session->set_handles_head;
    session->set_handles_head = sh->next;
    GNUNET_SET_destroy (sh->h);
    GNUNET_free (sh);
  }
  GNUNET_free (session);
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
("consensus",
 GNUNET_SERVICE_OPTION_NONE,
 &run,
 &client_connect_cb,
 &client_disconnect_cb,
 NULL,
 GNUNET_MQ_hd_fixed_size (client_conclude,
                          GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_CONCLUDE,
                          struct GNUNET_MessageHeader,
                          NULL),
 GNUNET_MQ_hd_var_size (client_insert,
                        GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_INSERT,
                        struct GNUNET_CONSENSUS_ElementMessage,
                        NULL),
 GNUNET_MQ_hd_var_size (client_join,
                        GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_JOIN,
                        struct GNUNET_CONSENSUS_JoinMessage,
                        NULL),
 GNUNET_MQ_handler_end ());

/* end of gnunet-service-consensus.c */
