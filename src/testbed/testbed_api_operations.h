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
 * Create an operation queue.
 *
 * @param max_active maximum number of operations in this
 *        queue that can be active in parallel at the same time
 * @return handle to the queue
 */
struct OperationQueue *
GNUNET_TESTBED_operation_queue_create_ (unsigned int max_active);


/**
 * Destroy an operation queue.  The queue MUST be empty
 * at this time.
 *
 * @param queue queue to destroy
 */
void
GNUNET_TESTBED_operation_queue_destroy_ (struct OperationQueue *queue);


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
					struct GNUNET_TESTBED_Operation *operation);


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
					struct GNUNET_TESTBED_Operation *operation);



/**
 * Function to call to start an operation once all
 * queues the operation is part of declare that the
 * operation can be activated.
 */
typedef void (*OperationStart)(void *cls);


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
 */
typedef void (*OperationRelease)(void *cls);


/**
 * Create an 'operation' to be performed.
 *
 * @param cls closure for the callbacks
 * @param start function to call to start the operation
 * @param release function to call to close down the operation
 * @param ... FIXME
 * @return handle to the operation
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_operation_create_ (void *cls,
				  OperationStart start,
				  OperationRelease release,
				  ...);


#endif
/* end of testbed_api_operations.h */
