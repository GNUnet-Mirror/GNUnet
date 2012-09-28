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
   * Number of operations that can be concurrently
   * active in this queue.
   */
  unsigned int active;
};


/**
 * Operation state
 */
enum OperationState
{
    /**
     * The operation is currently waiting for resources
     */
  OP_STATE_WAITING,

    /**
     * The operation has started
     */
  OP_STATE_STARTED
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
   * The id of the task which calls OperationStart for this operation
   */
  GNUNET_SCHEDULER_TaskIdentifier start_task_id;

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
 * Task for calling OperationStart on operation
 *
 * @param cls the Operation
 * @param tc the TaskContext from scheduler
 */
static void
call_start (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TESTBED_Operation *op = cls;

  op->start_task_id = GNUNET_SCHEDULER_NO_TASK;
  op->state = OP_STATE_STARTED;
  if (NULL != op->start)
  {
    op->start (op->cb_cls);
  }
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

  if (GNUNET_SCHEDULER_NO_TASK != op->start_task_id)
    return;
  for (i = 0; i < op->nqueues; i++)
  {
    if (0 == op->queues[i]->active)
      return;
  }
  for (i = 0; i < op->nqueues; i++)
  {
    op->queues[i]->active--;
  }
  op->start_task_id = GNUNET_SCHEDULER_add_now (&call_start, op);
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
  op->release = release;
  op->cb_cls = cls;
  op->start_task_id = GNUNET_SCHEDULER_NO_TASK;
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
  queue->active = max_active;
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
 * Add an operation to a queue.  An operation can be in multiple
 * queues at once.  Once all queues permit the operation to become
 * active, the operation will be activated.  The actual activation
 * will occur in a separate task (thus allowing multiple queue
 * insertions to be made without having the first one instantly
 * trigger the operation if the first queue has sufficient
 * resources).
 *
 * @param queue queue to add the operation to
 * @param operation operation to add to the queue
 */
void
GNUNET_TESTBED_operation_queue_insert_ (struct OperationQueue *queue,
                                        struct GNUNET_TESTBED_Operation
                                        *operation)
{
  struct QueueEntry *entry;

  entry = GNUNET_malloc (sizeof (struct QueueEntry));
  entry->op = operation;
  GNUNET_CONTAINER_DLL_insert_tail (queue->head, queue->tail, entry);
  operation->queues =
      GNUNET_realloc (operation->queues,
                      sizeof (struct OperationQueue *) *
                      (++operation->nqueues));
  operation->queues[operation->nqueues - 1] = queue;
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
  if (OP_STATE_STARTED == operation->state)
    queue->active++;
  entry2 = entry->next;
  GNUNET_CONTAINER_DLL_remove (queue->head, queue->tail, entry);
  GNUNET_free (entry);
  for (; NULL != entry2; entry2 = entry2->next)
    if (OP_STATE_STARTED != entry2->op->state)
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

  if (GNUNET_SCHEDULER_NO_TASK != operation->start_task_id)
  {
    GNUNET_SCHEDULER_cancel (operation->start_task_id);
    operation->start_task_id = GNUNET_SCHEDULER_NO_TASK;
  }
  for (i = 0; i < operation->nqueues; i++)
    GNUNET_TESTBED_operation_queue_remove_ (operation->queues[i], operation);
  GNUNET_free (operation->queues);
  if (NULL != operation->release)
    operation->release (operation->cb_cls);
  GNUNET_free (operation);
}


/* end of testbed_api_operations.c */
