/*
      This file is part of GNUnet
      (C) 2008--2012 Christian Grothoff (and other contributing authors)

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
 */
#include "platform.h"
#include "testbed_api_operations.h"


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
struct OperationQueue
{
 /**
   * The head of the operation queue
   */
  struct QueueEntry *head;

  /**
   * The tail of the operation queue
   */
  struct QueueEntry *tail;

  /**
   * Number of operations that are currently active in this queue.
   */
  unsigned int active;

  /**
   * Max number of operations which can be active at any time in this queue
   */
  unsigned int max_active;

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
   * The operation has started
   */
  OP_STATE_STARTED
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
   * Number of queues in the operation queues array
   */
  unsigned int nqueues;

  /**
   * The state of the operation
   */
  enum OperationState state;

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

  process_rq_task_id = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_assert (NULL != rq_head);
  GNUNET_assert (NULL != (op = rq_head->op));
  rq_remove (op);
  if (NULL != rq_head)
    process_rq_task_id = GNUNET_SCHEDULER_add_now (&process_rq_task, NULL);
  op->state = OP_STATE_STARTED;
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
  rq_entry = GNUNET_malloc (sizeof (struct ReadyQueueEntry));
  rq_entry->op = op;
  GNUNET_CONTAINER_DLL_insert_tail (rq_head, rq_tail, rq_entry);
  op->rq_entry = rq_entry;
  if (GNUNET_SCHEDULER_NO_TASK == process_rq_task_id)
    process_rq_task_id = GNUNET_SCHEDULER_add_now (&process_rq_task, NULL);
}


/**
 * Checks for the readiness of an operation and schedules a operation start task
 *
 * @param op the operation
 */
static void
check_readiness (struct GNUNET_TESTBED_Operation *op)
{
  unsigned int i;

  GNUNET_assert (NULL == op->rq_entry);
  for (i = 0; i < op->nqueues; i++)
  {
    GNUNET_assert (0 < op->nres[i]);
    if ((op->queues[i]->active + op->nres[i]) > op->queues[i]->max_active)
      return;
  }
  for (i = 0; i < op->nqueues; i++)
    op->queues[i]->active += op->nres[i];
  op->state = OP_STATE_READY;
  rq_add (op);
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
    op->queues[i]->active--;
  op->state = OP_STATE_WAITING;
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

  op = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_Operation));
  op->start = start;
  op->state = OP_STATE_INIT;
  op->release = release;
  op->cb_cls = cls;
  return op;
}


/**
 * Create an operation queue.
 *
 * @param max_active maximum number of operations in this
 *        queue that can be active in parallel at the same time
 * @return handle to the queue
 */
struct OperationQueue *
GNUNET_TESTBED_operation_queue_create_ (unsigned int max_active)
{
  struct OperationQueue *queue;

  queue = GNUNET_malloc (sizeof (struct OperationQueue));
  queue->max_active = max_active;
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
  GNUNET_break (NULL == queue->head);
  GNUNET_break (NULL == queue->tail);
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
  if (NULL != queue->head)
    return GNUNET_NO;
  GNUNET_TESTBED_operation_queue_destroy_ (queue);
  return GNUNET_YES;
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
  entry = queue->head;
  while ((queue->active > queue->max_active) && (NULL != entry))
  {
    if (entry->op->state == OP_STATE_READY)
      defer (entry->op);
    entry = entry->next;
  }

  entry = queue->head;
  while ((NULL != entry) && (queue->active < queue->max_active))
  {
    if (OP_STATE_WAITING == entry->op->state)
      check_readiness (entry->op);
    entry = entry->next;
  }
}


/**
 * Add an operation to a queue.  An operation can be in multiple queues at
 * once. Once the operation is inserted into all the queues
 * GNUNET_TESTBED_operation_begin_wait_() has to be called to actually start
 * waiting for the operation to become active.
 *
 * @param queue queue to add the operation to
 * @param operation operation to add to the queue
 * @param nres the number of units of the resources of queue needed by the
 *          operation. Should be greater than 0.
 */
void
GNUNET_TESTBED_operation_queue_insert2_ (struct OperationQueue *queue,
                                         struct GNUNET_TESTBED_Operation
                                         *operation, unsigned int nres)
{
  struct QueueEntry *entry;
  unsigned int qsize;

  GNUNET_assert (0 < nres);
  entry = GNUNET_malloc (sizeof (struct QueueEntry));
  entry->op = operation;
  entry->nres = nres;
  GNUNET_CONTAINER_DLL_insert_tail (queue->head, queue->tail, entry);
  qsize = operation->nqueues;
  GNUNET_array_append (operation->queues, operation->nqueues, queue);
  GNUNET_array_append (operation->nres, qsize, nres);
  GNUNET_assert (qsize == operation->nqueues);
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
 * @param operation operation to add to the queue
 */
void
GNUNET_TESTBED_operation_queue_insert_ (struct OperationQueue *queue,
                                        struct GNUNET_TESTBED_Operation
                                        *operation)
{
  return GNUNET_TESTBED_operation_queue_insert2_ (queue, operation, 1);
}


/**
 * Marks the given operation as waiting on the queues.  Once all queues permit
 * the operation to become active, the operation will be activated.  The actual
 * activation will occur in a separate task (thus allowing multiple queue
 * insertions to be made without having the first one instantly trigger the
 * operation if the first queue has sufficient resources).
 *
 * @param operation the operation to marks as waiting
 */
void
GNUNET_TESTBED_operation_begin_wait_ (struct GNUNET_TESTBED_Operation
                                      *operation)
{
  GNUNET_assert (NULL == operation->rq_entry);
  operation->state = OP_STATE_WAITING;
  check_readiness (operation);
}


/**
 * Remove an operation from a queue.  This can be because the
 * oeration was active and has completed (and the resources have
 * been released), or because the operation was cancelled and
 * thus scheduling the operation is no longer required.
 *
 * @param queue queue to add the operation to
 * @param operation operation to add to the queue
 */
void
GNUNET_TESTBED_operation_queue_remove_ (struct OperationQueue *queue,
                                        struct GNUNET_TESTBED_Operation
                                        *operation)
{
  struct QueueEntry *entry;
  struct QueueEntry *entry2;

  for (entry = queue->head; NULL != entry; entry = entry->next)
    if (entry->op == operation)
      break;
  GNUNET_assert (NULL != entry);
  GNUNET_assert (0 < entry->nres);
  switch (operation->state)
  {
  case OP_STATE_INIT:
  case OP_STATE_WAITING:
    break;
  case OP_STATE_READY:
  case OP_STATE_STARTED:
    GNUNET_assert (0 != queue->active);
    GNUNET_assert (queue->active >= entry->nres);
    queue->active -= entry->nres;
    break;
  }
  entry2 = entry->next;
  GNUNET_CONTAINER_DLL_remove (queue->head, queue->tail, entry);
  GNUNET_free (entry);
  for (; NULL != entry2; entry2 = entry2->next)
    if (OP_STATE_WAITING == entry2->op->state)
      break;
  if (NULL == entry2)
    return;
  check_readiness (entry2->op);
}


/**
 * An operation is 'done' (was cancelled or finished); remove
 * it from the queues and release associated resources.
 *
 * @param operation operation that finished
 */
void
GNUNET_TESTBED_operation_release_ (struct GNUNET_TESTBED_Operation *operation)
{
  unsigned int i;

  if (OP_STATE_READY == operation->state)
    rq_remove (operation);
  for (i = 0; i < operation->nqueues; i++)
    GNUNET_TESTBED_operation_queue_remove_ (operation->queues[i], operation);
  GNUNET_free (operation->queues);
  GNUNET_free (operation->nres);
  if (NULL != operation->release)
    operation->release (operation->cb_cls);
  GNUNET_free (operation);
}


/* end of testbed_api_operations.c */
