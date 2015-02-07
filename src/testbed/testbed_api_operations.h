/*
      This file is part of GNUnet
      Copyright (C) 2008--2013 Christian Grothoff (and other contributing authors)

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
 * @file testbed/testbed_api_operations.h
 * @brief internal API to access the 'operations' subsystem
 * @author Christian Grothoff
 */
#ifndef NEW_TESTING_API_OPERATIONS_H
#define NEW_TESTING_API_OPERATIONS_H

#include "gnunet_testbed_service.h"
#include "gnunet_helper_lib.h"


/**
 * Queue of operations where we can only support a certain
 * number of concurrent operations of a particular type.
 */
struct OperationQueue;


/**
 * The type of operation queue
 */
enum OperationQueueType
{
  /**
   * Operation queue which permits a fixed maximum number of operations to be
   * active at any time
   */
  OPERATION_QUEUE_TYPE_FIXED,

  /**
   * Operation queue which adapts the number of operations to be active based on
   * the operation completion times of previously executed operation in it
   */
  OPERATION_QUEUE_TYPE_ADAPTIVE
};


/**
 * Create an operation queue.
 *
 * @param type the type of operation queue
 * @param max_active maximum number of operations in this queue that can be
 *   active in parallel at the same time.
 * @return handle to the queue
 */
struct OperationQueue *
GNUNET_TESTBED_operation_queue_create_ (enum OperationQueueType type,
                                        unsigned int max_active);


/**
 * Destroy an operation queue.  The queue MUST be empty
 * at this time.
 *
 * @param queue queue to destroy
 */
void
GNUNET_TESTBED_operation_queue_destroy_ (struct OperationQueue *queue);


/**
 * Destroys the operation queue if it is empty.  If not empty return GNUNET_NO.
 *
 * @param queue the queue to destroy if empty
 * @return GNUNET_YES if the queue is destroyed.  GNUNET_NO if not (because it
 *           is not empty)
 */
int
GNUNET_TESTBED_operation_queue_destroy_empty_ (struct OperationQueue *queue);


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
                                                  unsigned int max_active);


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
                                         unsigned int nres);


/**
 * Add an operation to a queue.  An operation can be in multiple queues at
 * once. Once the operation is inserted into all the queues
 * GNUNET_TESTBED_operation_begin_wait_() has to be called to actually start
 * waiting for the operation to become active.
 *
 * @param queue queue to add the operation to
 * @param op operation to add to the queue
 */
void
GNUNET_TESTBED_operation_queue_insert_ (struct OperationQueue *queue,
                                        struct GNUNET_TESTBED_Operation *op);


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
GNUNET_TESTBED_operation_begin_wait_ (struct GNUNET_TESTBED_Operation *op);


/**
 * Function to call to start an operation once all
 * queues the operation is part of declare that the
 * operation can be activated.
 *
 * @param cls the closure from GNUNET_TESTBED_operation_create_()
 */
typedef void (*OperationStart) (void *cls);


/**
 * Function to call to cancel an operation (release all associated
 * resources).  This can be because of a call to
 * "GNUNET_TESTBED_operation_cancel" (before the operation generated
 * an event) or AFTER the operation generated an event due to a call
 * to "GNUNET_TESTBED_operation_done".  Thus it is not guaranteed that
 * a callback to the 'OperationStart' preceeds the call to
 * 'OperationRelease'.  Implementations of this function are expected
 * to clean up whatever state is in 'cls' and release all resources
 * associated with the operation.
 *
 * @param cls the closure from GNUNET_TESTBED_operation_create_()
 */
typedef void (*OperationRelease) (void *cls);


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
                                  OperationRelease release);


/**
 * An operation is 'done' (was cancelled or finished); remove
 * it from the queues and release associated resources.
 *
 * @param op operation that finished
 */
void
GNUNET_TESTBED_operation_release_ (struct GNUNET_TESTBED_Operation *op);


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
GNUNET_TESTBED_operation_inactivate_ (struct GNUNET_TESTBED_Operation *op);


/**
 * Marks and inactive operation as active.  This fuction should be called to
 * ensure that the oprelease callback will not be called until it is either
 * marked as inactive or released.
 *
 * @param op the operation to be marked as active
 */
void
GNUNET_TESTBED_operation_activate_ (struct GNUNET_TESTBED_Operation *op);


/**
 * Marks an operation as failed
 *
 * @param op the operation to be marked as failed
 */
void
GNUNET_TESTBED_operation_mark_failed (struct GNUNET_TESTBED_Operation *op);


#endif
/* end of testbed_api_operations.h */
