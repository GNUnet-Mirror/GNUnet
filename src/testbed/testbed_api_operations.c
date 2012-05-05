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

  // FIXME!

};


/**
 * Queue of operations where we can only support a certain
 * number of concurrent operations of a particular type.
 */
struct OperationQueue
{

  /**
   * Maximum number of operationst that can be concurrently
   * active in this queue.
   */
  unsigned int max_active;

  // FIXME!

};


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
  GNUNET_break (0);
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
					struct GNUNET_TESTBED_Operation *operation)
{
  GNUNET_break (0);
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
					struct GNUNET_TESTBED_Operation *operation)
{
  GNUNET_break (0);
}


/**
 * An operation is 'done' (was cancelled or finished); remove
 * it from the queues and release associated resources.
 *
 * @param operation operation that finished
 */
static void
operation_release (struct GNUNET_TESTBED_Operation *operation)
{
  // call operation->release, remove from queues
  GNUNET_break (0);
}


/**
 * Cancel a pending operation.  Releases all resources
 * of the operation and will ensure that no event
 * is generated for the operation.  Does NOT guarantee
 * that the operation will be fully undone (or that
 * nothing ever happened).  
 * 
 * @param operation operation to cancel
 */
void
GNUNET_TESTBED_operation_cancel (struct GNUNET_TESTBED_Operation *operation)
{
  // test that operation had not yet generated an event
  GNUNET_break (0);
  operation_release (operation);
}


/**
 * Signal that the information from an operation has been fully
 * processed.  This function MUST be called for each event
 * of type 'operation_finished' to fully remove the operation
 * from the operation queue.  After calling this function, the
 * 'op_result' becomes invalid (!).
 * 
 * @param operation operation to signal completion for
 */
void
GNUNET_TESTBED_operation_done (struct GNUNET_TESTBED_Operation *operation)
{
  // test that operation was started and had generated an event
  GNUNET_break (0);
  operation_release (operation);
}



/* end of testbed_api_operations.c */
