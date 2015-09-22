/*
      This file is part of GNUnet
      Copyright (C) 2012, 2013 Christian Grothoff (and other contributing authors)

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


enum ReferendumVote
{
  VOTE_NONE = 0,
  VOTE_ADD = 1,
  VOTE_REMOVE = 2,
  VOTE_CONTESTED = 3
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
  PHASE_KIND_GRADECAST_LEADER,
  PHASE_KIND_GRADECAST_ECHO,
  PHASE_KIND_GRADECAST_ECHO_GRADE,
  PHASE_KIND_GRADECAST_CONFIRM,
  PHASE_KIND_GRADECAST_CONFIRM_GRADE,
  PHASE_KIND_GRADECAST_APPLY_RESULT,
  PHASE_KIND_FINISH,
};


enum ActionType
{
  /**
   * Do a set reconciliation with another peer (or via looback).
   */
  ACTION_RECONCILE,
  /**
   * Apply a referendum with a threshold
   * to a set and/or a diff.
   */
  ACTION_EVAL_RFN,
  /**
   * Apply a diff to a set.
   */
  ACTION_APPLY_DIFF,
  ACTION_FINISH,
};

enum SetKind
{
  SET_KIND_NONE = 0,
  SET_KIND_CURRENT,
  SET_KIND_LEADER,
  SET_KIND_ECHO_RESULT,
};

enum DiffKind
{
  DIFF_KIND_NONE = 0,
  DIFF_KIND_LEADER,
  DIFF_KIND_GRADECAST_RESULT,
};

enum RfnKind
{
  RFN_KIND_NONE = 0,
  RFN_KIND_ECHO,
  RFN_KIND_CONFIRM,
};


/*
 * Node in the consensus task graph.
 */
struct TaskEntry
{
  struct TaskKey key;

  struct Step *step;

  int is_running;

  int is_finished;

  enum ActionType action;

  struct SetKey input_set;
  struct DiffKey input_diff;
  struct RfnKey input_rfn;
  struct SetKey output_set;
  struct DiffKey output_diff;
  struct RfnKey output_rfn;

  /**
   * Threshold when evaluating referendums.
   */
  uint16_t threshold;

  /**
   * Operation that is running for this task.
   */
  struct GNUNET_SET_OperationHandle *op;

  struct GNUNET_SET_Handle *commited_set;
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
   * Round that this step should start.
   * If not all prerequisites have run,
   * the task will run anyway.
   */
  unsigned int start_round;

  /*
   * Number of rounds this step occupies.
   *
   * Some steps are more expensive, and thus
   * are allocated more rounds.
   */
  unsigned int num_rounds;

  /**
   * Human-readable name for
   * the task, used for debugging.
   */
  char *debug_name;
};

struct RfnPeerInfo
{
  /* Peers can propose changes,
   * but they are only accepted once
   * the whole set operation is done. */
  int is_commited;
};

struct RfnElementInfo
{
  struct GNUNET_SET_Element *element;

  /*
   * Vote (or VOTE_NONE) from every peer
   * in the session about the element.
   */
  int *votes;
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
};


struct DiffElementInfo
{
  struct GNUNET_SET_Element *element;

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
  int *peers_ignored;

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


static void
finish_task (struct TaskEntry *task);

static void
run_task_remote_union (struct ConsensusSession *session, struct TaskEntry *task);

static void
run_task_eval_rfn (struct ConsensusSession *session, struct TaskEntry *task);

static void
run_task_apply_diff (struct ConsensusSession *session, struct TaskEntry *task);

static void
run_ready_steps (struct ConsensusSession *session);

static const char *
phasename (uint16_t phase)
{
  switch (phase)
  {
    case PHASE_KIND_ALL_TO_ALL: return "ALL_TO_ALL";
    case PHASE_KIND_FINISH: return "FINISH";
    case PHASE_KIND_GRADECAST_LEADER: return "GRADECAST_LEADER";
    case PHASE_KIND_GRADECAST_ECHO: return "GRADECAST_ECHO";
    case PHASE_KIND_GRADECAST_ECHO_GRADE: return "GRADECAST_ECHO_GRADE";
    case PHASE_KIND_GRADECAST_CONFIRM: return "GRADECAST_CONFIRM";
    case PHASE_KIND_GRADECAST_CONFIRM_GRADE: return "GRADECAST_CONFIRM_GRADE";
    case PHASE_KIND_GRADECAST_APPLY_RESULT: return "GRADECAST_APPLY_RESULT";
    default: return "(unknown)";
  }
}


static const char *
setname (uint16_t kind)
{
  switch (kind)
  {
    case SET_KIND_CURRENT: return "CURRENT";
    case SET_KIND_LEADER: return "LEADER";
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
    case DIFF_KIND_LEADER: return "LEADER";
    case DIFF_KIND_GRADECAST_RESULT: return "GRADECAST_RESULT";
    default: return "(unknown)";
  }
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
debug_str_set_key (struct SetKey *sk)
{
  static char buf[256];

  snprintf (buf, sizeof (buf),
            "SetKey kind=%s, k1=%d, k2=%d",
            setname (sk->set_kind), sk->k1, sk->k2);

  return buf;
}


static const char *
debug_str_rfn_key (struct RfnKey *rk)
{
  static char buf[256];

  snprintf (buf, sizeof (buf),
            "RfnKey kind=%s, k1=%d, k2=%d",
            rfnname (rk->rfn_kind), rk->k1, rk->k2);

  return buf;
}


/**
 * Destroy a session, free all resources associated with it.
 *
 * @param session the session to destroy
 */
static void
destroy_session (struct ConsensusSession *session)
{
  GNUNET_CONTAINER_DLL_remove (sessions_head, sessions_tail, session);
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
  GNUNET_free (session);
}


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
 * Callback for set operation results. Called for each element
 * in the result set.
 *
 * @param cls closure
 * @param element a result element, only valid if status is GNUNET_SET_STATUS_OK
 * @param status see enum GNUNET_SET_Status
 */
static void
set_result_cb_loop (void *cls,
               const struct GNUNET_SET_Element *element,
               enum GNUNET_SET_Status status)
{
  /* Nothing to do here.
     This is the callback for looped local set operations, everything is
     handled by the first callback */

  struct TaskEntry *task = cls;
  struct ConsensusSession *session = task->step->session;
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "P%u: skipping looped set result for {%s}, status %u\n",
              session->local_peer_idx,
              debug_str_task_key (&task->key),
              status);
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
  GNUNET_assert (0);
}


static void
rfn_vote (struct ReferendumEntry *rfn,
          uint16_t voting_peer,
          uint16_t num_peers,
          int vote,
          const struct GNUNET_SET_Element *element)
{
  GNUNET_assert (voting_peer < num_peers);
  GNUNET_assert (0);
}

uint16_t
task_other_peer (struct TaskEntry *task)
{
  uint16_t me = task->step->session->local_peer_idx;
  if (task->key.peer1 == me)
    return task->key.peer2;
  return task->key.peer1;
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
  struct TaskEntry *task = cls;
  struct ConsensusSession *session = task->step->session;
  struct SetEntry *output_set = NULL;
  struct DiffEntry *output_diff = NULL;
  struct ReferendumEntry *output_rfn = NULL;
  unsigned int other_idx;
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "P%u: got set result for {%s}, status %u\n",
              session->local_peer_idx,
              debug_str_task_key (&task->key),
              status);

  if (GNUNET_NO == task->is_running)
  {
    GNUNET_break_op (0);
    return;
  }

  if (GNUNET_YES == task->is_finished)
  {
    GNUNET_break_op (0);
    return;
  }

  if (task->key.peer1 == session->local_peer_idx)
    other_idx = task->key.peer2;
  else if (task->key.peer2 == session->local_peer_idx)
    other_idx = task->key.peer1;
  else
  {
    /* error in task graph construction */
    GNUNET_assert (0);
  }

  if (SET_KIND_NONE != task->output_set.set_kind)
    output_set = lookup_set (session, &task->output_set);

  if (DIFF_KIND_NONE != task->output_diff.diff_kind)
    output_diff = lookup_diff (session, &task->output_diff);

  if (RFN_KIND_NONE != task->output_rfn.rfn_kind)
    output_rfn = lookup_rfn (session, &task->output_rfn);

  if (GNUNET_YES == session->peers_ignored[other_idx])
  {
    /* We should have never started or commited to an operation
       with an ignored peer. */
    GNUNET_break (0);
    return;
  }

  switch (status)
  {
    // case GNUNET_SET_STATUS_MISSING_LOCAL:
    case GNUNET_SET_STATUS_OK:
      if (NULL != output_set)
      {
        // FIXME: record pending adds, use callback
        GNUNET_SET_add_element (output_set->h,
                                element,
                                NULL,
                                NULL);

      }
      if (NULL != output_diff)
      {
        diff_insert (output_diff, 1, element);
      }
      if (NULL != output_rfn)
      {
        rfn_vote (output_rfn, task_other_peer (task), session->num_peers, VOTE_ADD, element);
      }
      // XXX: add result to structures in task
      break;
    //case GNUNET_SET_STATUS_MISSING_REMOTE:
    //  // XXX: add result to structures in task
    //  break;
    case GNUNET_SET_STATUS_DONE:
      // XXX: check first if any changes to the underlying
      // set are still pending
      // XXX: commit other peer in referendum
      finish_task (task);
      break;
    case GNUNET_SET_STATUS_FAILURE:
      // XXX: cleanup
      GNUNET_break (0);
      return;
    default:
      /* not reached */
      GNUNET_assert (0);
  }
}



/**
 * Commit the appropriate set for a
 * task.
 */
static void
commit_set (struct ConsensusSession *session,
            struct TaskEntry *task)
{
  struct SetEntry *set;

  GNUNET_assert (NULL != task->op);
  set = lookup_set (session, &task->input_set);
  GNUNET_assert (NULL != set);
  GNUNET_SET_commit (task->op, set->h);
}


static void
put_diff (struct ConsensusSession *session,
         struct DiffEntry *diff)
{
  struct GNUNET_HashCode hash;

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

  GNUNET_CRYPTO_hash (&set->key, sizeof (struct SetKey), &hash);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap_put (session->setmap, &hash, set,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
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
output_cloned_cb (void *cls, struct GNUNET_SET_Handle *copy)
{
  struct TaskEntry *task = (struct TaskEntry *) cls;
  struct ConsensusSession *session = task->step->session;
  struct SetEntry *set = GNUNET_new (struct SetEntry);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "P%u: Received lazy copy, storing output set %s\n",
              session->local_peer_idx, debug_str_set_key (&task->output_set));

  set->key = task->output_set;
  set->h = copy;
  put_set (task->step->session, set);
  run_task_remote_union (task->step->session, task);
}


static void
run_task_remote_union (struct ConsensusSession *session, struct TaskEntry *task)
{
  struct SetEntry *input;

  input = lookup_set (session, &task->input_set);
  GNUNET_assert (NULL != input);
  GNUNET_assert (NULL != input->h);

  /* We create the outputs for the operation here
     (rather than in the set operation callback)
     because we want something valid in there, even
     if the other peer doesn't talk to us */

  if (SET_KIND_NONE != task->output_set.set_kind)
  {
    /* If we don't have an existing output set,
       we clone the input set. */
    if (NULL == lookup_set (session, &task->output_set))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Output set missing, copying from input set\n");
      /* Since the cloning is asynchronous,
         we'll retry the current function once the copy
         has been provided by the SET service. */
      GNUNET_SET_copy_lazy (input->h, output_cloned_cb, task);
      return;
    }
  }

  if (RFN_KIND_NONE != task->output_rfn.rfn_kind)
  {
    if (NULL == lookup_rfn (session, &task->output_rfn))
    {
      struct ReferendumEntry *rfn;

      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "P%u: output rfn <%s> missing, creating.\n",
                  session->local_peer_idx,
                  debug_str_rfn_key (&task->output_rfn));

      rfn = GNUNET_new (struct ReferendumEntry);
      rfn->key = task->output_rfn;
      rfn->rfn_elements = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);
      rfn->peer_commited = GNUNET_new_array (session->num_peers, int);
      put_rfn (session, rfn);
    }
  }

  if (task->key.peer1 == session->local_peer_idx)
  {
    struct GNUNET_CONSENSUS_RoundContextMessage rcm = { 0 };

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "P%u: Looking up set {%s} to run remote union\n",
                session->local_peer_idx,
                debug_str_set_key (&task->input_set));

    rcm.header.type = htons (GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_ROUND_CONTEXT);
    rcm.header.size = htons (sizeof (struct GNUNET_CONSENSUS_RoundContextMessage));

    rcm.kind = htons (task->key.kind);
    rcm.peer1 = htons (task->key.peer1);
    rcm.peer2 = htons (task->key.peer2);
    rcm.leader = htons (task->key.leader);
    rcm.repetition = htons (task->key.repetition);

    GNUNET_assert (NULL == task->op);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "P%u: initiating set op with P%u, our set is %s\n",
                session->local_peer_idx, task->key.peer2, debug_str_set_key (&task->input_set));

    // XXX: maybe this should be done while
    // setting up tasks alreays?
    task->op = GNUNET_SET_prepare (&session->peers[task->key.peer2],
                                   &session->global_id,
                                   &rcm.header,
                                   GNUNET_SET_RESULT_ADDED, /* XXX: will be obsolete soon */
                                   set_result_cb,
                                   task);

    /* Referendums must be materialized as a set before */
    GNUNET_assert (RFN_KIND_NONE == task->input_rfn.rfn_kind);

    if (GNUNET_OK != GNUNET_SET_commit (task->op, input->h))
    {
      GNUNET_break (0);
      /* XXX: cleanup? */
      return;
    }
  }
  else if (task->key.peer2 == session->local_peer_idx)
  {
    /* Wait for the other peer to contact us */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "P%u: waiting set op with P%u\n",
                session->local_peer_idx, task->key.peer1);

    if (NULL != task->op)
    {
      GNUNET_assert (NULL == task->commited_set);
      commit_set (session, task);
    }
  }
  else
  {
    /* We made an error while constructing the task graph. */
    GNUNET_assert (0);
  }
}


static int
rfn_majority (uint16_t num_peers,
              struct ReferendumEntry *rfn,
              struct RfnElementInfo *ri,
              uint16_t threshold)
{
  unsigned int votes_add = 0;
  unsigned int votes_remove = 0;
  unsigned int num_commited = 0;
  unsigned int maj_thresh;
  unsigned int nv;
  unsigned int tv;
  unsigned int i;

  for (i = 0; i < num_peers; i++)
  {
    if (GNUNET_NO == rfn->peer_commited[i])
      continue;
    num_commited++;
    if (ri->votes[i] == VOTE_ADD)
      votes_add++;
    if (ri->votes[i] == VOTE_REMOVE)
      votes_remove++;
  }

  /* Threshold to reach a majority among
     submitted votes, may not be enough for the
     global threshold. */
  maj_thresh = (num_commited + 1) / 2;
  /* Vote are relative to our local set, so it can only be
     either all add or all remove */
  GNUNET_assert ( (0 == votes_add) || (0 == votes_remove) );

  if (votes_add > 0)
  {
    nv = votes_add;
    tv = VOTE_ADD;
  }
  else if (votes_remove > 0)
  {
    nv = votes_remove;
    tv = VOTE_REMOVE;
  }
  else
  {
    nv = 0;
    tv = VOTE_NONE;
  }

  if ( (nv >= maj_thresh) && (nv >= threshold) )
    return tv;

  if ( ((num_commited - nv) >= maj_thresh) && ((num_commited - nv) >= threshold) )
    return VOTE_NONE;

  return VOTE_CONTESTED;
}


struct SetChangeProgressCls
{
  int num_pending;
  struct TaskEntry *task;
};


static void
eval_rfn_done (struct TaskEntry *task)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "P%u: EVAL_REFERENDUM done for task {%s}\n",
              task->step->session->local_peer_idx, debug_str_task_key (&task->key));

  finish_task (task);
}


static void
eval_rfn_progress (void *cls)
{
  struct SetChangeProgressCls *erc = cls;

  GNUNET_assert (erc->num_pending > 0);

  erc->num_pending--;

  if (0 == erc->num_pending)
  {
    struct TaskEntry *task = erc->task;
    GNUNET_free (erc);
    eval_rfn_done (task);
  }
}


static void
eval_rfn_copy_cb (void *cls, struct GNUNET_SET_Handle *copy)
{
  struct TaskEntry *task = (struct TaskEntry *) cls;
  struct ConsensusSession *session = task->step->session;
  struct SetEntry *set;

  set = GNUNET_new (struct SetEntry);
  set->h = copy;
  set->key = task->output_set;

  put_set (session, set);

  run_task_eval_rfn (session, task);
}


/**
 * Take an input set and an input referendum, 
 * apply the referendum with a threshold to the input
 * set and store the result in the output set and/or output diff.
 */
static void
run_task_eval_rfn (struct ConsensusSession *session, struct TaskEntry *task)
{
  struct GNUNET_CONTAINER_MultiHashMapIterator *iter;
  struct ReferendumEntry *input_rfn;
  struct RfnElementInfo *ri;
  struct SetEntry *output_set = NULL;
  struct DiffEntry *output_diff = NULL;
  struct SetChangeProgressCls *progress_cls;

  /* Have at least one output */
  GNUNET_assert ( (task->output_set.set_kind != SET_KIND_NONE) ||
                  (task->output_diff.diff_kind != DIFF_KIND_NONE));

  /* Not allowed as output */
  GNUNET_assert ( (task->output_rfn.rfn_kind == RFN_KIND_NONE));

  if (SET_KIND_NONE != task->output_set.set_kind)
  {
    /* We have a set output, thus the output set must
       exist or copy it from the input set */
    output_set = lookup_set (session, &task->output_set);
    if (NULL == output_set)
    {
      struct SetEntry *input_set;

      input_set = lookup_set (session, &task->input_set);
      GNUNET_assert (NULL != input_set);
      GNUNET_SET_copy_lazy (input_set->h,
                            eval_rfn_copy_cb,
                            task);
      /* We'll be called again, this time with the
         set ready. */
      return;
    }
  }

  if (DIFF_KIND_NONE != task->output_diff.diff_kind)
  {
    output_diff = lookup_diff (session, &task->output_diff);
    if (NULL == output_diff)
    {
      output_diff = GNUNET_new (struct DiffEntry);
      output_diff->key = task->output_diff;
      output_diff->changes = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);
      put_diff (session, output_diff);
    }
  }

  progress_cls = GNUNET_new (struct SetChangeProgressCls);

  input_rfn = lookup_rfn (session, &task->input_rfn);

  GNUNET_assert (NULL != input_rfn);

  iter = GNUNET_CONTAINER_multihashmap_iterator_create (input_rfn->rfn_elements);
  GNUNET_assert (NULL != iter);

  while (GNUNET_YES == GNUNET_CONTAINER_multihashmap_iterator_next (iter, NULL, (const void **) &ri))
  {
    int majority_vote = rfn_majority (session->num_peers, input_rfn, ri, task->threshold);
    switch (majority_vote)
    {
      case VOTE_ADD:
        if (NULL != output_set)
        {
          progress_cls->num_pending++;
          GNUNET_assert (GNUNET_OK ==
                         GNUNET_SET_add_element (output_set->h,
                                     ri->element,
                                     eval_rfn_progress,
                                     progress_cls));
        }
        if (NULL != output_diff)
        {
          diff_insert (output_diff, 1, ri->element);
        }
        break;
      case VOTE_CONTESTED:
        if (NULL != output_set)
          output_set->is_contested = GNUNET_YES;
        /* fallthrough */
      case VOTE_REMOVE:
        if (NULL != output_set)
        {
          progress_cls->num_pending++;
          GNUNET_assert (GNUNET_OK ==
                         GNUNET_SET_remove_element (output_set->h,
                                     ri->element,
                                     eval_rfn_progress,
                                     progress_cls));
        }
        if (NULL != output_diff)
        {
          diff_insert (output_diff, -1, ri->element);
        }
        break;
      case VOTE_NONE:
        /* Nothing to do. */
        break;
      default:
        /* not reached */
        GNUNET_assert (0);
    }
  }
  GNUNET_CONTAINER_multihashmap_iterator_destroy (iter);

  if (progress_cls->num_pending == 0)
  {
    // call closure right now, no pending ops
    GNUNET_free (progress_cls);
    eval_rfn_done (task);
  }
}


static void
apply_diff_copy_cb (void *cls, struct GNUNET_SET_Handle *copy)
{
  struct TaskEntry *task = (struct TaskEntry *) cls;
  struct ConsensusSession *session = task->step->session;
  struct SetEntry *set;

  set = GNUNET_new (struct SetEntry);
  set->h = copy;
  set->key = task->output_set;

  put_set (session, set);

  run_task_apply_diff (session, task);
}


static void
apply_diff_done (struct TaskEntry *task)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "P%u: APPLY_DIFF done for task {%s}\n",
              task->step->session->local_peer_idx, debug_str_task_key (&task->key));
  finish_task (task);
}


static void
apply_diff_progress (void *cls)
{
  struct SetChangeProgressCls *erc = cls;

  GNUNET_assert (erc->num_pending > 0);

  erc->num_pending--;

  if (0 == erc->num_pending)
  {
    struct TaskEntry *task = erc->task;
    GNUNET_free (erc);
    apply_diff_done (task);
  }
}


static void
run_task_apply_diff (struct ConsensusSession *session, struct TaskEntry *task)
{
  struct SetEntry *output_set;
  struct DiffEntry *input_diff;
  struct GNUNET_CONTAINER_MultiHashMapIterator *iter;
  struct DiffElementInfo *di;
  struct SetChangeProgressCls *progress_cls;

  GNUNET_assert (task->output_set.set_kind != SET_KIND_NONE);
  GNUNET_assert (task->input_diff.diff_kind != DIFF_KIND_NONE);

  input_diff = lookup_diff (session, &task->input_diff);

  GNUNET_assert (NULL != input_diff);

  output_set = lookup_set (session, &task->output_set);

  if (NULL == output_set)
  {
      struct SetEntry *input_set;

      input_set = lookup_set (session, &task->input_set);
      GNUNET_assert (NULL != input_set);
      GNUNET_SET_copy_lazy (input_set->h,
                            apply_diff_copy_cb,
                            task);
      /* We'll be called again, this time with the
         set ready. */
      return;
  }

  progress_cls = GNUNET_new (struct SetChangeProgressCls);

  iter = GNUNET_CONTAINER_multihashmap_iterator_create (input_diff->changes);

  while (GNUNET_YES == GNUNET_CONTAINER_multihashmap_iterator_next (iter, NULL, (const void **) &di))
  {
    if (di->weight > 0)
    {
      progress_cls->num_pending++;
      GNUNET_assert (GNUNET_OK ==
                     GNUNET_SET_remove_element (output_set->h,
                                 di->element,
                                 apply_diff_progress,
                                 progress_cls));
    }
    else if (di->weight < 0)
    {
      progress_cls->num_pending++;
      GNUNET_assert (GNUNET_OK ==
                     GNUNET_SET_add_element (output_set->h,
                                 di->element,
                                 apply_diff_progress,
                                 progress_cls));
    }
  }

  GNUNET_CONTAINER_multihashmap_iterator_destroy (iter);

  if (progress_cls->num_pending == 0)
  {
    // call closure right now, no pending ops
    GNUNET_free (progress_cls);
    apply_diff_done (task);
  }
}


static void
run_task_finish (struct ConsensusSession *session, struct TaskEntry *task)
{
  struct SetEntry *final_set;

  final_set = lookup_set (session, &task->input_set);

  GNUNET_assert (NULL != final_set);


  GNUNET_SET_iterate (final_set->h,
                      send_to_client_iter,
                      task);
}

static void
run_task (struct ConsensusSession *session, struct TaskEntry *task)
{
  GNUNET_assert (GNUNET_NO == task->is_running);
  GNUNET_assert (GNUNET_NO == task->is_finished);

  
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "P%u: running task {%s}\n", session->local_peer_idx, debug_str_task_key (&task->key));

  switch (task->action)
  {
    case ACTION_RECONCILE:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "P%u: running ACTION_RECONCILE task\n", session->local_peer_idx);
      run_task_remote_union (session, task);
      break;
    case ACTION_EVAL_RFN:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "P%u: running ACTION_EVAL_RFN task\n", session->local_peer_idx);
      run_task_eval_rfn (session, task);
      break;
    case ACTION_APPLY_DIFF:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "P%u: running ACTION_APPLY_DIFF task\n", session->local_peer_idx);
      run_task_apply_diff (session, task);
      break;
    case ACTION_FINISH:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "P%u: running ACTION_FINISH task\n", session->local_peer_idx);
      run_task_finish (session, task);
      break;
    default:
      /* not reached */
      GNUNET_assert (0);
  }
  task->is_running = GNUNET_YES;
}


static void finish_step (struct Step *step)
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
                step->subordinates[i]->pending_prereq,
                step->subordinates[i]->debug_name);

#endif
  }

  step->is_finished = GNUNET_YES;

  // XXX: maybe schedule as task to avoid recursion?
  run_ready_steps (step->session);
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
    if ( (GNUNET_NO == step->is_running) && (0 == step->pending_prereq) )
    {
      size_t i;

      GNUNET_assert (0 == step->finished_tasks);

#ifdef GNUNET_EXTRA_LOGGING
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "P%u: Running step `%s' of round %d:%d with %d tasks and %d subordinates\n",
                  session->local_peer_idx,
                  step->debug_name,
                  step->start_round, step->num_rounds, step->tasks_len, step->subordinates_len);
#endif

      step->is_running = GNUNET_YES;
      for (i = 0; i < step->tasks_len; i++)
        run_task (session, step->tasks[i]);

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
 */
static void
initialize_session_peer_list (struct ConsensusSession *session,
                              struct GNUNET_CONSENSUS_JoinMessage *join_msg)
{
  unsigned int local_peer_in_list;
  uint32_t listed_peers;
  const struct GNUNET_PeerIdentity *msg_peers;
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

  session->peers = GNUNET_malloc (session->num_peers * sizeof (struct GNUNET_PeerIdentity));

  if (GNUNET_NO == local_peer_in_list)
    session->peers[session->num_peers - 1] = my_peer;

  memcpy (session->peers, msg_peers, listed_peers * sizeof (struct GNUNET_PeerIdentity));
  qsort (session->peers, session->num_peers, sizeof (struct GNUNET_PeerIdentity), &peer_id_cmp);
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
  GNUNET_SET_ResultIterator my_result_cb;

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

  if (ACTION_RECONCILE != task->action)
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

  if (task->key.peer1 == task->key.peer2)
    my_result_cb = set_result_cb_loop;
  else
    my_result_cb = set_result_cb;

  task->op = GNUNET_SET_accept (request,
                                GNUNET_SET_RESULT_ADDED, /* XXX: obsolete soon */
                                my_result_cb,
                                task);
  
  /* If the task hasn't been started yet, 
     we wait for that until we commit. */

  if (GNUNET_YES == task->is_running)
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
 * Record @a dep as a dependency of @step.
 */
static void
step_depend_on (struct Step *step, struct Step *dep)
{
  /* We're not checking for cyclic dependencies,
     but this is a cheap sanity check. */
  GNUNET_assert (step != dep);
  GNUNET_assert (NULL != step);
  GNUNET_assert (NULL != dep);
  // XXX: make rounds work
  //GNUNET_assert (dep->start_round <= step->start_round);

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
create_step (struct ConsensusSession *session, int start_round, int num_rounds)
{
  struct Step *step;
  step = GNUNET_new (struct Step);
  step->session = session;
  step->start_round = start_round;
  step->num_rounds = num_rounds;
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
  uint16_t t = n / 3;

  uint16_t me = session->local_peer_idx;

  uint16_t p1;
  uint16_t p2;

  /* The task we're currently setting up. */
  struct TaskEntry task;

  struct Step *step;
  struct Step *prev_step;

  uint16_t round;

  unsigned int k;

  round = step_before->start_round + step_before->num_rounds;

  /* gcast step 1: leader disseminates */

  step = create_step (session, round, 1);

#ifdef GNUNET_EXTRA_LOGGING
  GNUNET_asprintf (&step->debug_name, "disseminate leader %u rep %u", lead, rep);
#endif
  step_depend_on (step, step_before);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "P%d: Considering leader %d\n", session->local_peer_idx, lead);

  if (lead == me)
  {
    for (k = 0; k < n; k++)
    {
      if (k == me)
        continue;
      p1 = me;
      p2 = k;
      arrange_peers (&p1, &p2, n);
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "P%d: GC LEADER(1): %d %d %d %d\n", session->local_peer_idx, p1, p2, rep, lead);
      task = ((struct TaskEntry) {
        .step = step,
        .action = ACTION_RECONCILE,
        .key = (struct TaskKey) { PHASE_KIND_GRADECAST_LEADER, p1, p2, rep, me },
        .input_set = (struct SetKey) { SET_KIND_CURRENT, rep },
        .output_set = (struct SetKey) { SET_KIND_NONE },
      });
      put_task (session->taskmap, &task);
    }
    /* We run this task to make sure that the leader
       has the stored the SET_KIND_LEADER set of himself,
       so he can participate in the rest of the gradecast
       without the code having to handle any special cases. */
    task = ((struct TaskEntry) {
      .step = step,
      .action = ACTION_RECONCILE,
      .key = (struct TaskKey) { PHASE_KIND_GRADECAST_LEADER, me, me, rep, me },
      .input_set = (struct SetKey) { SET_KIND_CURRENT, rep },
      .output_set = (struct SetKey) { SET_KIND_LEADER, rep, me },
      .output_diff = (struct DiffKey) { DIFF_KIND_LEADER, rep, me },
    });
    put_task (session->taskmap, &task);
  }
  else
  {
    p1 = me;
    p2 = lead;
    arrange_peers (&p1, &p2, n);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, "P%d: GC LEADER(2): %d %d %d %d\n", session->local_peer_idx, p1, p2, rep, lead);
    task = ((struct TaskEntry) {
      .step = step,
      .action = ACTION_RECONCILE,
      .key = (struct TaskKey) { PHASE_KIND_GRADECAST_LEADER, p1, p2, rep, lead},
      .input_set = (struct SetKey) { SET_KIND_CURRENT, rep },
      .output_set = (struct SetKey) { SET_KIND_LEADER, rep, lead },
      .output_diff = (struct DiffKey) { DIFF_KIND_LEADER, rep, lead },
    });
    put_task (session->taskmap, &task);
  }

  /* gcast phase 2: echo */
  prev_step = step;
  step = create_step (session, round, 1);
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
      .action = ACTION_RECONCILE,
      .key = (struct TaskKey) { PHASE_KIND_GRADECAST_ECHO, p1, p2, rep, lead },
      .input_set = (struct SetKey) { SET_KIND_LEADER, rep, lead },
      .output_rfn = (struct RfnKey) { RFN_KIND_ECHO, rep, lead },
    });
    put_task (session->taskmap, &task);
  }

  prev_step = step;
  step = create_step (session, round, 1);
#ifdef GNUNET_EXTRA_LOGGING
  GNUNET_asprintf (&step->debug_name, "echo grade leader %u rep %u", lead, rep);
#endif
  step_depend_on (step, prev_step);

  arrange_peers (&p1, &p2, n);
  task = ((struct TaskEntry) {
    .key = (struct TaskKey) { PHASE_KIND_GRADECAST_ECHO_GRADE, -1, -1, rep, lead },
    .step = step,
    .action = ACTION_EVAL_RFN,
    .input_set = (struct SetKey) { SET_KIND_LEADER, rep, lead },
    .input_rfn = (struct RfnKey) { RFN_KIND_ECHO, rep, lead },
    .output_set = (struct SetKey) { SET_KIND_ECHO_RESULT, rep, lead },
    .threshold = n - t,
  });
  put_task (session->taskmap, &task);

  prev_step = step;
  step = create_step (session, round, 1);
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
      .action = ACTION_RECONCILE,
      .key = (struct TaskKey) { PHASE_KIND_GRADECAST_CONFIRM, p1, p2, rep, lead},
      .input_set = (struct SetKey) { SET_KIND_ECHO_RESULT, rep, lead },
      .output_rfn = (struct RfnKey) { RFN_KIND_CONFIRM, rep, lead },
    });
    put_task (session->taskmap, &task);
  }

  prev_step = step;
  step = create_step (session, round, 1);
#ifdef GNUNET_EXTRA_LOGGING
  GNUNET_asprintf (&step->debug_name, "confirm grade leader %u rep %u", lead, rep);
#endif
  step_depend_on (step, prev_step);

  // evaluate ConfirmationReferendum and
  // apply it to the LeaderReferendum
  task = ((struct TaskEntry) {
    .step = step,
    .key = (struct TaskKey) { PHASE_KIND_GRADECAST_CONFIRM_GRADE, -1, -1, rep, lead },
    .action = ACTION_EVAL_RFN,
    .input_rfn = (struct RfnKey) { RFN_KIND_ECHO, rep, lead },
    .output_diff = (struct DiffKey) { DIFF_KIND_GRADECAST_RESULT, rep },
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

  uint16_t p1;
  uint16_t p2;

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

  step = create_step (session, round, 1);

#ifdef GNUNET_EXTRA_LOGGING
  step->debug_name = GNUNET_strdup ("all to all");
#endif

  for (i = 0; i < n; i++)
  {
    p1 = me;
    p2 = i;
    arrange_peers (&p1, &p2, n);
    task = ((struct TaskEntry) {
      .key = (struct TaskKey) { PHASE_KIND_ALL_TO_ALL, p1, p2, -1, -1 },
      .step = step,
      .action = ACTION_RECONCILE,
      .input_set = (struct SetKey) { SET_KIND_CURRENT, 0 },
      .output_set = (struct SetKey) { SET_KIND_CURRENT, 0 },
    });
    put_task (session->taskmap, &task);
  }

  round++;

  prev_step = step;
  step = NULL;

  /* Byzantine union */

  /* sequential repetitions of the gradecasts */
  for (i = 0; i < t + 1; i++)
  {
    struct Step *step_rep_start;
    struct Step *step_rep_end;

    step_rep_start = create_step (session, round, 1);
#ifdef GNUNET_EXTRA_LOGGING
      GNUNET_asprintf (&step_rep_start->debug_name, "gradecast start rep %u", i);
#endif

    step_depend_on (step_rep_start, prev_step);

    step_rep_end = create_step (session, round, 1);
#ifdef GNUNET_EXTRA_LOGGING
      GNUNET_asprintf (&step_rep_end->debug_name, "gradecast end rep %u", i);
#endif

    /* parallel gradecasts */
    for (lead = 0; lead < n; lead++)
      construct_task_graph_gradecast (session, i, lead, step_rep_start, step_rep_end);

    // TODO: add peers to ignore list,
    //
    // evaluate ConfirmationReferendum and
    // apply it to the LeaderReferendum
    task = ((struct TaskEntry) {
      .step = step_rep_end,
      .key = (struct TaskKey) { PHASE_KIND_GRADECAST_APPLY_RESULT, -1, -1, i, -1},
      .action = ACTION_APPLY_DIFF,
      .input_set = (struct SetKey) { SET_KIND_CURRENT, i },
      .input_diff = (struct DiffKey) { DIFF_KIND_GRADECAST_RESULT, i },
      .output_set = (struct SetKey) { SET_KIND_CURRENT, i + 1 },
    });
    put_task (session->taskmap, &task);

    prev_step = step_rep_end;
  }

 /* There is no next gradecast round, thus the final
    start step is the overall end step of the gradecasts */
  step = create_step (session, round, 1);
#ifdef GNUNET_EXTRA_LOGGING
  GNUNET_asprintf (&step->debug_name, "finish");
#endif
  step_depend_on (step, prev_step);

  task = ((struct TaskEntry) {
    .step = step,
    .key = (struct TaskKey) { PHASE_KIND_FINISH, -1, -1, -1, -1 },
    .input_set = (struct SetKey) { SET_KIND_CURRENT, t + 1 },
    .action = ACTION_FINISH,
  });

  put_task (session->taskmap, &task);
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

  /* Check if some local client already owns the session.
     It is only legal to have a session with an existing global id
     if all other sessions with this global id are finished.*/
  other_session = sessions_head;
  while (NULL != other_session)
  {
    if ((other_session != session) &&
        (0 == GNUNET_CRYPTO_hash_cmp (&session->global_id, &other_session->global_id)))
    {
      //if (CONSENSUS_ROUND_FINISH != other_session->current_round)
      //{
      //  GNUNET_break (0);
      //  destroy_session (session);
      //  return;
      //}
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
  session->set_listener = GNUNET_SET_listen (cfg, GNUNET_SET_OPERATION_UNION,
                                             &session->global_id,
                                             set_listen_cb, session);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%d is the local peer\n", session->local_peer_idx);

  session->setmap = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);
  session->taskmap = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);
  session->diffmap = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);
  session->rfnmap = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);

  {
    struct SetEntry *client_set;
    client_set = GNUNET_new (struct SetEntry);
    client_set->h = GNUNET_SET_create (cfg, GNUNET_SET_OPERATION_UNION);
    client_set->key = ((struct SetKey) { SET_KIND_CURRENT, 0, 0 });
    put_set (session, client_set);
  }

  session->peers_ignored = GNUNET_new_array (session->num_peers, int);

  /* Just construct the task graph,
     but don't run anything until the client calls conclude. */
  construct_task_graph (session);

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


static void
client_insert_done (void *cls)
{
  // FIXME: implement
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
  struct GNUNET_SET_Handle *initial_set;

  session = get_session_by_client (client);

  if (NULL == session)
  {
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (client);
    return;
  }

  if (GNUNET_YES == session->conclude_started)
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
  {
    struct SetKey key = { SET_KIND_CURRENT, 0, 0 };
    struct SetEntry *entry;
    entry = lookup_set (session, &key);
    GNUNET_assert (NULL != entry);
    initial_set = entry->h;
  }
  session->num_client_insert_pending++;
  GNUNET_SET_add_element (initial_set, element, client_insert_done, session);
  GNUNET_free (element);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "P%u: element added\n", session->local_peer_idx);
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

  session = get_session_by_client (client);
  if (NULL == session)
  {
    /* client not found */
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (client);
    return;
  }

  if (GNUNET_YES == session->conclude_started)
  {
    /* conclude started twice */
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (client);
    destroy_session (session);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "conclude requested\n");

  session->conclude_started = GNUNET_YES;

  install_step_timeouts (session);
  run_ready_steps (session);


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
  // FIXME: destroy if we can
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

