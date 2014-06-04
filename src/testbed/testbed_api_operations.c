/*
      This file is part of GNUnet
      (C) 2008--2013 Christian Grothoff (and other contributing authors)

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
 * @file testbed/testbed_api_operations.c
 * @brief functions to manage operation queues
 * @author Christian Grothoff
 * @author Sree Harsha Totakura
 */

#include "platform.h"
#include "testbed_api_operations.h"
#include "testbed_api_sd.h"

/**
 * The number of readings containing past operation's timing information that we
 * keep track of for adaptive queues
 */
#define ADAPTIVE_QUEUE_DEFAULT_HISTORY 40

/**
 * The number of parallel opeartions we start with by default for adaptive
 * queues
 */
#define ADAPTIVE_QUEUE_DEFAULT_MAX_ACTIVE 4

/**
 * An entry in the operation queue
 */
struct QueueEntry
{
  /**
   * The next DLL pointer
   */
  struct QueueEntry *next;

  /**
   * The prev DLL pointer
   */
  struct QueueEntry *prev;

  /**
   * The operation this entry holds
   */
  struct GNUNET_TESTBED_Operation *op;

  /**
   * How many units of resources does the operation need
   */
  unsigned int nres;
};


/**
 * Queue of operations where we can only support a certain
 * number of concurrent operations of a particular type.
 */
struct OperationQueue;


/**
 * A slot to record time taken by an operation
 */
struct TimeSlot
{
  /**
   * DLL next pointer
   */
  struct TimeSlot *next;

  /**
   * DLL prev pointer
   */
  struct TimeSlot *prev;

  /**
   * This operation queue to which this time slot belongs to
   */
  struct OperationQueue *queue;

  /**
   * The operation to which this timeslot is currently allocated to
   */
  struct GNUNET_TESTBED_Operation *op;

  /**
   * Accumulated time
   */
  struct GNUNET_TIME_Relative tsum;

  /**
   * Number of timing values accumulated
   */
  unsigned int nvals;
};


/**
 * Context for operation queues of type OPERATION_QUEUE_TYPE_ADAPTIVE
 */
struct FeedbackCtx
{
  /**
   * Handle for calculating standard deviation
   */
  struct SDHandle *sd;

  /**
   * Head for DLL of time slots which are free to be allocated to operations
   */
  struct TimeSlot *alloc_head;

  /**
   * Tail for DLL of time slots which are free to be allocated to operations
   */
  struct TimeSlot *alloc_tail;

  /**
   * Pointer to the chunk of time slots.  Free all time slots at a time using
   * this pointer.
   */
  struct TimeSlot *tslots_freeptr;

  /**
   * Number of time slots filled so far
   */
  unsigned int tslots_filled;

  /**
   * Bound on the maximum number of operations which can be active
   */
  unsigned int max_active_bound;

  /**
   * Number of operations that have failed
   */
  unsigned int nfailed;
};


/**
 * Queue of operations where we can only support a certain
 * number of concurrent operations of a particular type.
 */
struct OperationQueue
{
  /**
   * DLL head for the wait queue.  Operations which are waiting for this
   * operation queue are put here
   */
  struct QueueEntry *wq_head;

  /**
   * DLL tail for the wait queue.
   */
  struct QueueEntry *wq_tail;

  /**
   * DLL head for the ready queue.  Operations which are in this operation queue
   * and are in ready state are put here
   */
  struct QueueEntry *rq_head;

  /**
   * DLL tail for the ready queue
   */
  struct QueueEntry *rq_tail;

  /**
   * DLL head for the active queue.  Operations which are in this operation
   * queue and are currently active are put here
   */
  struct QueueEntry *aq_head;

  /**
   * DLL tail for the active queue.
   */
  struct QueueEntry *aq_tail;

  /**
   * DLL head for the inactive queue.  Operations which are inactive and can be
   * evicted if the queues it holds are maxed out and another operation begins
   * to wait on them.
   */
  struct QueueEntry *nq_head;

  /**
   * DLL tail for the inactive queue.
   */
  struct QueueEntry *nq_tail;

  /**
   * Feedback context; only relevant for adaptive operation queues.  NULL for
   * fixed operation queues
   */
  struct FeedbackCtx *fctx;

  /**
   * The type of this opeartion queue
   */
  enum OperationQueueType type;

  /**
   * Number of operations that are currently active in this queue.
   */
  unsigned int active;

  /**
   * Max number of operations which can be active at any time in this queue.
   * This value can be changed either by calling
   * GNUNET_TESTBED_operation_queue_reset_max_active_() or by the adaptive
   * algorithm if this operation queue is of type #OPERATION_QUEUE_TYPE_ADAPTIVE
   */
  unsigned int max_active;

  /**
   * The number of resources occupied by failed operations in the current shot.
   * This is only relavant if the operation queue is of type
   * #OPERATION_QUEUE_TYPE_ADAPTIVE
   */
  unsigned int overload;
};


/**
 * Operation state
 */
enum OperationState
{
  /**
   * The operation is just created and is in initial state
   */
  OP_STATE_INIT,

  /**
   * The operation is currently waiting for resources
   */
  OP_STATE_WAITING,

  /**
   * The operation is ready to be started
   */
  OP_STATE_READY,

  /**
   * The operation has started and is active
   */
  OP_STATE_ACTIVE,

  /**
   * The operation is inactive.  It still holds resources on the operation
   * queues.  However, this operation will be evicted when another operation
   * requires resources from the maxed out queues this operation is holding
   * resources from.
   */
  OP_STATE_INACTIVE
};


/**
 * An entry in the ready queue (implemented as DLL)
 */
struct ReadyQueueEntry
{
  /**
   * next ptr for DLL
   */
  struct ReadyQueueEntry *next;

  /**
   * prev ptr for DLL
   */
  struct ReadyQueueEntry *prev;

  /**
   * The operation associated with this entry
   */
  struct GNUNET_TESTBED_Operation *op;
};


/**
 * Opaque handle to an abstract operation to be executed by the testing framework.
 */
struct GNUNET_TESTBED_Operation
{
  /**
   * Function to call when we have the resources to begin the operation.
   */
  OperationStart start;

  /**
   * Function to call to clean up after the operation (which may or may
   * not have been started yet).
   */
  OperationRelease release;

  /**
   * Closure for callbacks.
   */
  void *cb_cls;

  /**
   * Array of operation queues this Operation belongs to.
   */
  struct OperationQueue **queues;

  /**
   * Array of operation queue entries corresponding to this operation in
   * operation queues for this operation
   */
  struct QueueEntry **qentries;

  /**
   * Array of number of resources an operation need from each queue. The numbers
   * in this array should correspond to the queues array
   */
  unsigned int *nres;

  /**
   * Entry corresponding to this operation in ready queue.  Will be NULL if the
   * operation is not marked as READY
   */
  struct ReadyQueueEntry *rq_entry;

  /**
   * Head pointer for DLL of tslots allocated to this operation
   */
  struct TimeSlot *tslots_head;

  /**
   * Tail pointer for DLL of tslots allocated to this operation
   */
  struct TimeSlot *tslots_tail;

  /**
   * The time at which the operation is started
   */
  struct GNUNET_TIME_Absolute tstart;

  /**
   * Number of queues in the operation queues array
   */
  unsigned int nqueues;

  /**
   * The state of the operation
   */
  enum OperationState state;

  /**
   * Is this a failed operation?
   */
  int failed;

};

/**
 * DLL head for the ready queue
 */
struct ReadyQueueEntry *rq_head;

/**
 * DLL tail for the ready queue
 */
struct ReadyQueueEntry *rq_tail;

/**
 * The id of the task to process the ready queue
 */
GNUNET_SCHEDULER_TaskIdentifier process_rq_task_id;


/**
 * Assigns the given operation a time slot from the given operation queue
 *
 * @param op the operation
 * @param queue the operation queue
 * @return the timeslot
 */
static void
assign_timeslot (struct GNUNET_TESTBED_Operation *op,
                 struct OperationQueue *queue)
{
  struct FeedbackCtx *fctx = queue->fctx;
  struct TimeSlot *tslot;

  GNUNET_assert (OPERATION_QUEUE_TYPE_ADAPTIVE == queue->type);
  tslot = fctx->alloc_head;
  GNUNET_assert (NULL != tslot);
  GNUNET_CONTAINER_DLL_remove (fctx->alloc_head, fctx->alloc_tail, tslot);
  GNUNET_CONTAINER_DLL_insert_tail (op->tslots_head, op->tslots_tail, tslot);
  tslot->op = op;
}


/**
 * Removes a queue entry of an operation from one of the operation queues' lists
 * depending on the state of the operation
 *
 * @param op the operation whose entry has to be removed
 * @param index the index of the entry in the operation's array of queue entries
 */
static void
remove_queue_entry (struct GNUNET_TESTBED_Operation *op, unsigned int index)
{
  struct OperationQueue *opq;
  struct QueueEntry *entry;

  opq = op->queues[index];
  entry = op->qentries[index];
  switch (op->state)
  {
  case OP_STATE_INIT:
    GNUNET_assert (0);
    break;
  case OP_STATE_WAITING:
    GNUNET_CONTAINER_DLL_remove (opq->wq_head, opq->wq_tail, entry);
    break;
  case OP_STATE_READY:
    GNUNET_CONTAINER_DLL_remove (opq->rq_head, opq->rq_tail, entry);
    break;
  case OP_STATE_ACTIVE:
    GNUNET_CONTAINER_DLL_remove (opq->aq_head, opq->aq_tail, entry);
    break;
  case OP_STATE_INACTIVE:
    GNUNET_CONTAINER_DLL_remove (opq->nq_head, opq->nq_tail, entry);
    break;
  }
}


/**
 * Changes the state of the operation while moving its associated queue entries
 * in the operation's operation queues
 *
 * @param op the operation whose state has to be changed
 * @param state the state the operation should have.  It cannot be OP_STATE_INIT
 */
static void
change_state (struct GNUNET_TESTBED_Operation *op, enum OperationState state)
{
  struct QueueEntry *entry;
  struct OperationQueue *opq;
  unsigned int cnt;
  unsigned int s;

  GNUNET_assert (OP_STATE_INIT != state);
  GNUNET_assert (NULL != op->queues);
  GNUNET_assert (NULL != op->nres);
  GNUNET_assert ((OP_STATE_INIT == op->state) || (NULL != op->qentries));
  GNUNET_assert (op->state != state);
  for (cnt = 0; cnt < op->nqueues; cnt++)
  {
    if (OP_STATE_INIT == op->state)
    {
      entry = GNUNET_new (struct QueueEntry);
      entry->op = op;
      entry->nres = op->nres[cnt];
      s = cnt;
      GNUNET_array_append (op->qentries, s, entry);
    }
    else
    {
      entry = op->qentries[cnt];
      remove_queue_entry (op, cnt);
    }
    opq = op->queues[cnt];
    switch (state)
    {
    case OP_STATE_INIT:
      GNUNET_assert (0);
      break;
    case OP_STATE_WAITING:
      GNUNET_CONTAINER_DLL_insert_tail (opq->wq_head, opq->wq_tail, entry);
      break;
    case OP_STATE_READY:
      GNUNET_CONTAINER_DLL_insert_tail (opq->rq_head, opq->rq_tail, entry);
      break;
    case OP_STATE_ACTIVE:
      GNUNET_CONTAINER_DLL_insert_tail (opq->aq_head, opq->aq_tail, entry);
      break;
    case OP_STATE_INACTIVE:
      GNUNET_CONTAINER_DLL_insert_tail (opq->nq_head, opq->nq_tail, entry);
      break;
    }
  }
  op->state = state;
}


/**
 * Removes an operation from the ready queue.  Also stops the 'process_rq_task'
 * if the given operation is the last one in the queue.
 *
 * @param op the operation to be removed
 */
static void
rq_remove (struct GNUNET_TESTBED_Operation *op)
{
  GNUNET_assert (NULL != op->rq_entry);
  GNUNET_CONTAINER_DLL_remove (rq_head, rq_tail, op->rq_entry);
  GNUNET_free (op->rq_entry);
  op->rq_entry = NULL;
  if ( (NULL == rq_head) && (GNUNET_SCHEDULER_NO_TASK != process_rq_task_id) )
  {
    GNUNET_SCHEDULER_cancel (process_rq_task_id);
    process_rq_task_id = GNUNET_SCHEDULER_NO_TASK;
  }
}


/**
 * Processes the ready queue by calling the operation start callback of the
 * operation at the head.  The operation is then removed from the queue.  The
 * task is scheduled to run again immediately until no more operations are in
 * the ready queue.
 *
 * @param cls NULL
 * @param tc scheduler task context.  Not used.
 */
static void
process_rq_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TESTBED_Operation *op;
  struct OperationQueue *queue;
  unsigned int cnt;

  process_rq_task_id = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_assert (NULL != rq_head);
  GNUNET_assert (NULL != (op = rq_head->op));
  rq_remove (op);
  if (NULL != rq_head)
    process_rq_task_id = GNUNET_SCHEDULER_add_now (&process_rq_task, NULL);
  change_state (op, OP_STATE_ACTIVE);
  for (cnt = 0; cnt < op->nqueues; cnt++)
  {
    queue = op->queues[cnt];
    if (OPERATION_QUEUE_TYPE_ADAPTIVE == queue->type)
      assign_timeslot (op, queue);
  }
  op->tstart = GNUNET_TIME_absolute_get ();
  if (NULL != op->start)
    op->start (op->cb_cls);
}


/**
 * Adds the operation to the ready queue and starts the 'process_rq_task'
 *
 * @param op the operation to be queued
 */
static void
rq_add (struct GNUNET_TESTBED_Operation *op)
{
  struct ReadyQueueEntry *rq_entry;

  GNUNET_assert (NULL == op->rq_entry);
  rq_entry = GNUNET_new (struct ReadyQueueEntry);
  rq_entry->op = op;
  GNUNET_CONTAINER_DLL_insert_tail (rq_head, rq_tail, rq_entry);
  op->rq_entry = rq_entry;
  if (GNUNET_SCHEDULER_NO_TASK == process_rq_task_id)
    process_rq_task_id = GNUNET_SCHEDULER_add_now (&process_rq_task, NULL);
}


/**
 * Checks if the given operation queue is empty or not
 *
 * @param opq the operation queue
 * @return GNUNET_YES if the given operation queue has no operations; GNUNET_NO
 *           otherwise
 */
static int
is_queue_empty (struct OperationQueue *opq)
{
  if ( (NULL != opq->wq_head)
       || (NULL != opq->rq_head)
       || (NULL != opq->aq_head)
       || (NULL != opq->nq_head) )
    return GNUNET_NO;
  return GNUNET_YES;
}


/**
 * Checks if the given operation queue has enough resources to provide for the
 * operation of the given queue entry.  It also checks if any inactive
 * operations are to be released in order to accommodate the needed resources
 * and returns them as an array.
 *
 * @param opq the operation queue to check for resource accommodation
 * @param entry the operation queue entry whose operation's resources are to be
 *          accommodated
 * @param ops_ pointer to return the array of operations which are to be released
 *          in order to accommodate the new operation.  Can be NULL
 * @param n_ops_ the number of operations in ops_
 * @return GNUNET_YES if the given entry's operation can be accommodated in this
 *           queue. GNUNET_NO if it cannot be accommodated; ops_ and n_ops_ will
 *           be set to NULL and 0 respectively.
 */
static int
decide_capacity (struct OperationQueue *opq,
                 struct QueueEntry *entry,
                 struct GNUNET_TESTBED_Operation ***ops_,
                 unsigned int *n_ops_)
{
  struct QueueEntry **evict_entries;
  struct GNUNET_TESTBED_Operation **ops;
  struct GNUNET_TESTBED_Operation *op;
  unsigned int n_ops;
  unsigned int n_evict_entries;
  unsigned int need;
  unsigned int max;
  int deficit;
  int rval;

  GNUNET_assert (NULL != (op = entry->op));
  GNUNET_assert (0 < (need = entry->nres));
  ops = NULL;
  n_ops = 0;
  evict_entries = NULL;
  n_evict_entries = 0;
  rval = GNUNET_YES;
  if (OPERATION_QUEUE_TYPE_ADAPTIVE == opq->type)
  {
    GNUNET_assert (NULL != opq->fctx);
    GNUNET_assert (opq->max_active >= opq->overload);
    max = opq->max_active - opq->overload;
  }
  else
    max = opq->max_active;
  if (opq->active > max)
  {
    rval = GNUNET_NO;
    goto ret;
  }
  if ((opq->active + need) <= max)
    goto ret;
  deficit = need - (max - opq->active);
  for (entry = opq->nq_head;
       (0 < deficit) && (NULL != entry);
       entry = entry->next)
  {
    GNUNET_array_append (evict_entries, n_evict_entries, entry);
    deficit -= entry->nres;
  }
  if (0 < deficit)
  {
    rval = GNUNET_NO;
    goto ret;
  }
  for (n_ops = 0; n_ops < n_evict_entries;)
  {
    op = evict_entries[n_ops]->op;
    GNUNET_array_append (ops, n_ops, op); /* increments n-ops */
  }

 ret:
  GNUNET_free_non_null (evict_entries);
  if (NULL != ops_)
    *ops_ = ops;
  else
    GNUNET_free (ops);
  if (NULL != n_ops_)
    *n_ops_ = n_ops;
  return rval;
}


/**
 * Merges an array of operations into another, eliminating duplicates.  No
 * ordering is guaranteed.
 *
 * @param old the array into which the merging is done.
 * @param n_old the number of operations in old array
 * @param new the array from which operations are to be merged
 * @param n_new the number of operations in new array
 */
static void
merge_ops (struct GNUNET_TESTBED_Operation ***old,
           unsigned int *n_old,
           struct GNUNET_TESTBED_Operation **new,
           unsigned int n_new)
{
  struct GNUNET_TESTBED_Operation **cur;
  unsigned int i;
  unsigned int j;
  unsigned int n_cur;

  GNUNET_assert (NULL != old);
  n_cur = *n_old;
  cur = *old;
  for (i = 0; i < n_new; i++)
  {
    for (j = 0; j < *n_old; j++)
    {
      if (new[i] == cur[j])
        break;
    }
    if (j < *n_old)
      continue;
    GNUNET_array_append (cur, n_cur, new[j]);
  }
  *old = cur;
  *n_old = n_cur;
}



/**
 * Checks for the readiness of an operation and schedules a operation start task
 *
 * @param op the operation
 */
static int
check_readiness (struct GNUNET_TESTBED_Operation *op)
{
  struct GNUNET_TESTBED_Operation **evict_ops;
  struct GNUNET_TESTBED_Operation **ops;
  unsigned int n_ops;
  unsigned int n_evict_ops;
  unsigned int i;

  GNUNET_assert (NULL == op->rq_entry);
  GNUNET_assert (OP_STATE_WAITING == op->state);
  evict_ops = NULL;
  n_evict_ops = 0;
  for (i = 0; i < op->nqueues; i++)
  {
    ops = NULL;
    n_ops = 0;
    if (GNUNET_NO == decide_capacity (op->queues[i], op->qentries[i],
                                      &ops, &n_ops))
    {
      GNUNET_free_non_null (evict_ops);
      return GNUNET_NO;
    }
    if (NULL == ops)
      continue;
    merge_ops (&evict_ops, &n_evict_ops, ops, n_ops);
    GNUNET_free (ops);
  }
  if (NULL != evict_ops)
  {
    for (i = 0; i < n_evict_ops; i++)
      GNUNET_TESTBED_operation_release_ (evict_ops[i]);
    GNUNET_free (evict_ops);
    evict_ops = NULL;
    /* Evicting the operations should schedule this operation */
    GNUNET_assert (OP_STATE_READY == op->state);
    return GNUNET_YES;
  }
  for (i = 0; i < op->nqueues; i++)
    op->queues[i]->active += op->nres[i];
  change_state (op, OP_STATE_READY);
  rq_add (op);
  return GNUNET_YES;
}


/**
 * Defers a ready to be executed operation back to waiting
 *
 * @param op the operation to defer
 */
static void
defer (struct GNUNET_TESTBED_Operation *op)
{
  unsigned int i;

  GNUNET_assert (OP_STATE_READY == op->state);
  rq_remove (op);
  for (i = 0; i < op->nqueues; i++)
  {
    GNUNET_assert (op->queues[i]->active >= op->nres[i]);
    op->queues[i]->active -= op->nres[i];
  }
  change_state (op, OP_STATE_WAITING);
}


/**
 * Cleanups the array of timeslots of an operation queue.  For each time slot in
 * the array, if it is allocated to an operation, it will be deallocated from
 * the operation
 *
 * @param queue the operation queue
 */
static void
cleanup_tslots (struct OperationQueue *queue)
{
  struct FeedbackCtx *fctx = queue->fctx;
  struct TimeSlot *tslot;
  struct GNUNET_TESTBED_Operation *op;
  unsigned int cnt;

  GNUNET_assert (NULL != fctx);
  for (cnt = 0; cnt < queue->max_active; cnt++)
  {
    tslot = &fctx->tslots_freeptr[cnt];
    op = tslot->op;
    if (NULL == op)
      continue;
    GNUNET_CONTAINER_DLL_remove (op->tslots_head, op->tslots_tail, tslot);
  }
  GNUNET_free_non_null (fctx->tslots_freeptr);
  fctx->tslots_freeptr = NULL;
  fctx->alloc_head = NULL;
  fctx->alloc_tail = NULL;
  fctx->tslots_filled = 0;
}


/**
 * Cleansup the existing timing slots and sets new timing slots in the given
 * queue to accommodate given number of max active operations.
 *
 * @param queue the queue
 * @param n the number of maximum active operations.  If n is greater than the
 *   maximum limit set while creating the queue, then the minimum of these two
 *   will be selected as n
 */
static void
adaptive_queue_set_max_active (struct OperationQueue *queue, unsigned int n)
{
  struct FeedbackCtx *fctx = queue->fctx;
  struct TimeSlot *tslot;
  unsigned int cnt;

  cleanup_tslots (queue);
  n = GNUNET_MIN (n ,fctx->max_active_bound);
  fctx->tslots_freeptr = GNUNET_malloc (n * sizeof (struct TimeSlot));
  fctx->nfailed = 0;
  for (cnt = 0; cnt < n; cnt++)
  {
    tslot = &fctx->tslots_freeptr[cnt];
    tslot->queue = queue;
    GNUNET_CONTAINER_DLL_insert_tail (fctx->alloc_head, fctx->alloc_tail, tslot);
  }
  GNUNET_TESTBED_operation_queue_reset_max_active_ (queue, n);
}


/**
 * Adapts parallelism in an adaptive queue by using the statistical data from
 * the feedback context.
 *
 * @param queue the queue
 */
static void
adapt_parallelism (struct OperationQueue *queue)
{
  struct GNUNET_TIME_Relative avg;
  struct FeedbackCtx *fctx;
  struct TimeSlot *tslot;
  int sd;
  unsigned int nvals;
  unsigned int cnt;
  unsigned int parallelism;

  avg = GNUNET_TIME_UNIT_ZERO;
  nvals = 0;
  fctx = queue->fctx;
  for (cnt = 0; cnt < queue->max_active; cnt++)
  {
    tslot = &fctx->tslots_freeptr[cnt];
    avg = GNUNET_TIME_relative_add (avg, tslot->tsum);
    nvals += tslot->nvals;
  }
  GNUNET_assert (nvals >= queue->max_active);
  GNUNET_assert (fctx->nfailed <= nvals);
  nvals -= fctx->nfailed;
  if (0 == nvals)
  {
    if (1 == queue->max_active)
      adaptive_queue_set_max_active (queue, 1);
    else
      adaptive_queue_set_max_active (queue, queue->max_active / 2);
    return;
  }
  avg = GNUNET_TIME_relative_divide (avg, nvals);
  GNUNET_TESTBED_SD_add_data_ (fctx->sd, (unsigned int) avg.rel_value_us);
  if (GNUNET_SYSERR ==
      GNUNET_TESTBED_SD_deviation_factor_ (fctx->sd,
                                           (unsigned int) avg.rel_value_us,
                                           &sd))
  {
    adaptive_queue_set_max_active (queue, queue->max_active); /* no change */
    return;
  }

  parallelism = 0;
  if (-1 == sd)
    parallelism = queue->max_active + 1;
  if (sd <= -2)
    parallelism = queue->max_active * 2;
  if (1 == sd)
    parallelism = queue->max_active - 1;
  if (2 <= sd)
    parallelism = queue->max_active / 2;
  parallelism = GNUNET_MAX (parallelism, ADAPTIVE_QUEUE_DEFAULT_MAX_ACTIVE);
  adaptive_queue_set_max_active (queue, parallelism);

#if 0
  /* old algorithm */
  if (sd < 0)
    sd = 0;
  GNUNET_assert (0 <= sd);
  //GNUNET_TESTBED_SD_add_data_ (fctx->sd, (unsigned int) avg.rel_value_us);
  if (0 == sd)
  {
    adaptive_queue_set_max_active (queue, queue->max_active * 2);
    return;
  }
  if (1 == sd)
  {
    adaptive_queue_set_max_active (queue, queue->max_active + 1);
    return;
  }
  if (1 == queue->max_active)
  {
    adaptive_queue_set_max_active (queue, 1);
    return;
  }
  if (2 == sd)
  {
    adaptive_queue_set_max_active (queue, queue->max_active - 1);
    return;
  }
  adaptive_queue_set_max_active (queue, queue->max_active / 2);
#endif
}


/**
 * update tslots with the operation's completion time.  Additionally, if
 * updating a timeslot makes all timeslots filled in an adaptive operation
 * queue, call adapt_parallelism() for that queue.
 *
 * @param op the operation
 */
static void
update_tslots (struct GNUNET_TESTBED_Operation *op)
{
  struct OperationQueue *queue;
  struct GNUNET_TIME_Relative t;
  struct TimeSlot *tslot;
  struct FeedbackCtx *fctx;
  unsigned int i;

  t = GNUNET_TIME_absolute_get_duration (op->tstart);
  while (NULL != (tslot = op->tslots_head)) /* update time slots */
  {
    queue = tslot->queue;
    fctx = queue->fctx;
    GNUNET_CONTAINER_DLL_remove (op->tslots_head, op->tslots_tail, tslot);
    tslot->op = NULL;
    GNUNET_CONTAINER_DLL_insert_tail (fctx->alloc_head, fctx->alloc_tail,
                                      tslot);
    if (op->failed)
    {
      fctx->nfailed++;
      for (i = 0; i < op->nqueues; i++)
        if (queue == op->queues[i])
            break;
      GNUNET_assert (i != op->nqueues);
      op->queues[i]->overload += op->nres[i];
    }
    tslot->tsum = GNUNET_TIME_relative_add (tslot->tsum, t);
    if (0 != tslot->nvals++)
      continue;
    fctx->tslots_filled++;
    if (queue->max_active == fctx->tslots_filled)
      adapt_parallelism (queue);
  }
}


/**
 * Create an 'operation' to be performed.
 *
 * @param cls closure for the callbacks
 * @param start function to call to start the operation
 * @param release function to call to close down the operation
 * @return handle to the operation
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_operation_create_ (void *cls, OperationStart start,
                                  OperationRelease release)
{
  struct GNUNET_TESTBED_Operation *op;

  op = GNUNET_new (struct GNUNET_TESTBED_Operation);
  op->start = start;
  op->state = OP_STATE_INIT;
  op->release = release;
  op->cb_cls = cls;
  return op;
}


/**
 * Create an operation queue.
 *
 * @param type the type of operation queue
 * @param max_active maximum number of operations in this
 *        queue that can be active in parallel at the same time
 * @return handle to the queue
 */
struct OperationQueue *
GNUNET_TESTBED_operation_queue_create_ (enum OperationQueueType type,
                                        unsigned int max_active)
{
  struct OperationQueue *queue;
  struct FeedbackCtx *fctx;

  queue = GNUNET_new (struct OperationQueue);
  queue->type = type;
  if (OPERATION_QUEUE_TYPE_FIXED == type)
  {
    queue->max_active = max_active;
  }
  else
  {
    fctx = GNUNET_new (struct FeedbackCtx);
    fctx->max_active_bound = max_active;
    fctx->sd = GNUNET_TESTBED_SD_init_ (ADAPTIVE_QUEUE_DEFAULT_HISTORY);
    queue->fctx = fctx;
    adaptive_queue_set_max_active (queue, ADAPTIVE_QUEUE_DEFAULT_MAX_ACTIVE);
  }
  return queue;
}


/**
 * Destroy an operation queue.  The queue MUST be empty
 * at this time.
 *
 * @param queue queue to destroy
 */
void
GNUNET_TESTBED_operation_queue_destroy_ (struct OperationQueue *queue)
{
  struct FeedbackCtx *fctx;

  GNUNET_break (GNUNET_YES == is_queue_empty (queue));
  if (OPERATION_QUEUE_TYPE_ADAPTIVE == queue->type)
  {
    cleanup_tslots (queue);
    fctx = queue->fctx;
    GNUNET_TESTBED_SD_destroy_ (fctx->sd);
    GNUNET_free (fctx);
  }
  GNUNET_free (queue);
}


/**
 * Destroys the operation queue if it is empty.  If not empty return GNUNET_NO.
 *
 * @param queue the queue to destroy if empty
 * @return GNUNET_YES if the queue is destroyed.  GNUNET_NO if not (because it
 *           is not empty)
 */
int
GNUNET_TESTBED_operation_queue_destroy_empty_ (struct OperationQueue *queue)
{
  if (GNUNET_NO == is_queue_empty (queue))
    return GNUNET_NO;
  GNUNET_TESTBED_operation_queue_destroy_ (queue);
  return GNUNET_YES;
}


/**
 * Rechecks if any of the operations in the given operation queue's waiting list
 * can be made active
 *
 * @param opq the operation queue
 */
static void
recheck_waiting (struct OperationQueue *opq)
{
  struct QueueEntry *entry;
  struct QueueEntry *entry2;

  entry = opq->wq_head;
  while (NULL != entry)
  {
    entry2 = entry->next;
    if (GNUNET_NO == check_readiness (entry->op))
      break;
    entry = entry2;
  }
}


/**
 * Function to reset the maximum number of operations in the given queue. If
 * max_active is lesser than the number of currently active operations, the
 * active operations are not stopped immediately.
 *
 * @param queue the operation queue which has to be modified
 * @param max_active the new maximum number of active operations
 */
void
GNUNET_TESTBED_operation_queue_reset_max_active_ (struct OperationQueue *queue,
                                                  unsigned int max_active)
{
  struct QueueEntry *entry;

  queue->max_active = max_active;
  queue->overload = 0;
  while ( (queue->active > queue->max_active)
          && (NULL != (entry = queue->rq_head)) )
    defer (entry->op);
  recheck_waiting (queue);
}


/**
 * Add an operation to a queue.  An operation can be in multiple queues at
 * once. Once the operation is inserted into all the queues
 * GNUNET_TESTBED_operation_begin_wait_() has to be called to actually start
 * waiting for the operation to become active.
 *
 * @param queue queue to add the operation to
 * @param op operation to add to the queue
 * @param nres the number of units of the resources of queue needed by the
 *          operation. Should be greater than 0.
 */
void
GNUNET_TESTBED_operation_queue_insert2_ (struct OperationQueue *queue,
                                         struct GNUNET_TESTBED_Operation *op,
                                         unsigned int nres)
{
  unsigned int qsize;

  GNUNET_assert (0 < nres);
  qsize = op->nqueues;
  GNUNET_array_append (op->queues, op->nqueues, queue);
  GNUNET_array_append (op->nres, qsize, nres);
  GNUNET_assert (qsize == op->nqueues);
}


/**
 * Add an operation to a queue.  An operation can be in multiple queues at
 * once. Once the operation is inserted into all the queues
 * GNUNET_TESTBED_operation_begin_wait_() has to be called to actually start
 * waiting for the operation to become active. The operation is assumed to take
 * 1 queue resource. Use GNUNET_TESTBED_operation_queue_insert2_() if it
 * requires more than 1
 *
 * @param queue queue to add the operation to
 * @param op operation to add to the queue
 */
void
GNUNET_TESTBED_operation_queue_insert_ (struct OperationQueue *queue,
                                        struct GNUNET_TESTBED_Operation *op)
{
  return GNUNET_TESTBED_operation_queue_insert2_ (queue, op, 1);
}


/**
 * Marks the given operation as waiting on the queues.  Once all queues permit
 * the operation to become active, the operation will be activated.  The actual
 * activation will occur in a separate task (thus allowing multiple queue
 * insertions to be made without having the first one instantly trigger the
 * operation if the first queue has sufficient resources).
 *
 * @param op the operation to marks as waiting
 */
void
GNUNET_TESTBED_operation_begin_wait_ (struct GNUNET_TESTBED_Operation *op)
{
  GNUNET_assert (NULL == op->rq_entry);
  change_state (op, OP_STATE_WAITING);
  (void) check_readiness (op);
}


/**
 * Marks an active operation as inactive - the operation will be kept in a
 * ready-to-be-released state and continues to hold resources until another
 * operation contents for them.
 *
 * @param op the operation to be marked as inactive.  The operation start
 *          callback should have been called before for this operation to mark
 *          it as inactive.
 */
void
GNUNET_TESTBED_operation_inactivate_ (struct GNUNET_TESTBED_Operation *op)
{
  struct OperationQueue **queues;
  size_t ms;
  unsigned int nqueues;
  unsigned int i;

  GNUNET_assert (OP_STATE_ACTIVE == op->state);
  change_state (op, OP_STATE_INACTIVE);
  nqueues = op->nqueues;
  ms = sizeof (struct OperationQueue *) * nqueues;
  queues = GNUNET_malloc (ms);
  /* Cloning is needed as the operation be released by waiting operations and
     hence its nqueues memory ptr will be freed */
  GNUNET_assert (NULL != (queues = memcpy (queues, op->queues, ms)));
  for (i = 0; i < nqueues; i++)
    recheck_waiting (queues[i]);
  GNUNET_free (queues);
}


/**
 * Marks and inactive operation as active.  This fuction should be called to
 * ensure that the oprelease callback will not be called until it is either
 * marked as inactive or released.
 *
 * @param op the operation to be marked as active
 */
void
GNUNET_TESTBED_operation_activate_ (struct GNUNET_TESTBED_Operation *op)
{

  GNUNET_assert (OP_STATE_INACTIVE == op->state);
  change_state (op, OP_STATE_ACTIVE);
}


/**
 * An operation is 'done' (was cancelled or finished); remove
 * it from the queues and release associated resources.
 *
 * @param op operation that finished
 */
void
GNUNET_TESTBED_operation_release_ (struct GNUNET_TESTBED_Operation *op)
{
  struct QueueEntry *entry;
  struct OperationQueue *opq;
  unsigned int i;

  if (OP_STATE_INIT == op->state)
  {
    GNUNET_free (op);
    return;
  }
  if (OP_STATE_READY == op->state)
    rq_remove (op);
  if (OP_STATE_INACTIVE == op->state) /* Activate the operation if inactive */
    GNUNET_TESTBED_operation_activate_ (op);
  if (OP_STATE_ACTIVE == op->state)
    update_tslots (op);
  GNUNET_assert (NULL != op->queues);
  GNUNET_assert (NULL != op->qentries);
  for (i = 0; i < op->nqueues; i++)
  {
    entry = op->qentries[i];
    remove_queue_entry (op, i);
    opq = op->queues[i];
    switch (op->state)
    {
    case OP_STATE_INIT:
    case OP_STATE_INACTIVE:
      GNUNET_assert (0);
      break;
    case OP_STATE_WAITING:
      break;
    case OP_STATE_ACTIVE:
    case OP_STATE_READY:
      GNUNET_assert (0 != opq->active);
      GNUNET_assert (opq->active >= entry->nres);
      opq->active -= entry->nres;
      recheck_waiting (opq);
      break;
    }
    GNUNET_free (entry);
  }
  GNUNET_free_non_null (op->qentries);
  GNUNET_free (op->queues);
  GNUNET_free (op->nres);
  if (NULL != op->release)
    op->release (op->cb_cls);
  GNUNET_free (op);
}


/**
 * Marks an operation as failed
 *
 * @param op the operation to be marked as failed
 */
void
GNUNET_TESTBED_operation_mark_failed (struct GNUNET_TESTBED_Operation *op)
{
  op->failed = GNUNET_YES;
}


/* end of testbed_api_operations.c */
