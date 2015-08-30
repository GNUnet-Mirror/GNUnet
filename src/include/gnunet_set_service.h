/*
      This file is part of GNUnet
      Copyright (C) 2013, 2014 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_set_service.h
 * @brief two-peer set operations
 * @author Florian Dold
 * @author Christian Grothoff
 */

#ifndef GNUNET_SET_SERVICE_H
#define GNUNET_SET_SERVICE_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_common.h"
#include "gnunet_time_lib.h"
#include "gnunet_configuration_lib.h"


/**
 * Maximum size of a context message for set operation requests.
 */
#define GNUNET_SET_CONTEXT_MESSAGE_MAX_SIZE ((1<<16) - 1024)


/**
 * Opaque handle to a set.
 */
struct GNUNET_SET_Handle;

/**
 * Opaque handle to a set operation request from another peer.
 */
struct GNUNET_SET_Request;

/**
 * Opaque handle to a listen operation.
 */
struct GNUNET_SET_ListenHandle;

/**
 * Opaque handle to a set operation.
 */
struct GNUNET_SET_OperationHandle;


/**
 * The operation that a set set supports.
 */
enum GNUNET_SET_OperationType
{
  /**
   * A purely local set that does not support any operation.
   */
  GNUNET_SET_OPERATION_NONE,

  /**
   * Set intersection, only return elements that are in both sets.
   */
  GNUNET_SET_OPERATION_INTERSECTION,

  /**
   * Set union, return all elements that are in at least one of the sets.
   */
  GNUNET_SET_OPERATION_UNION
};


/**
 * Status for the result callback
 */
enum GNUNET_SET_Status
{
  /**
   * Everything went ok, we are transmitting an element of the
   * result (in set, or to be removed from set, depending on
   * the `enum GNUNET_SET_ResultMode`).
   */
  GNUNET_SET_STATUS_OK,

  /**
   * The other peer refused to to the operation with us,
   * or something went wrong.
   */
  GNUNET_SET_STATUS_FAILURE,

  /**
   * Success, all elements have been returned (but the other peer
   * might still be receiving some from us, so we are not done).  Only
   * used during UNION operation.
   */
  GNUNET_SET_STATUS_HALF_DONE,

  /**
   * Success, all elements have been sent (and received).
   */
  GNUNET_SET_STATUS_DONE
};


/**
 * The way results are given to the client.
 */
enum GNUNET_SET_ResultMode
{
  /**
   * Client gets every element in the resulting set.
   */
  GNUNET_SET_RESULT_FULL,

  /**
   * Client gets only elements that have been added to the set.
   * Only works with set union.
   */
  GNUNET_SET_RESULT_ADDED,

  /**
   * Client gets only elements that have been removed from the set.
   * Only works with set intersection.
   */
  GNUNET_SET_RESULT_REMOVED
};


/**
 * Element stored in a set.
 */
struct GNUNET_SET_Element
{
  /**
   * Number of bytes in the buffer pointed to by data.
   */
  uint16_t size;

  /**
   * Application-specific element type.
   */
  uint16_t element_type;

  /**
   * Actual data of the element
   */
  const void *data;
};


/**
 * Continuation used for some of the set operations
 *
 * @param cls closure
 */
typedef void (*GNUNET_SET_Continuation) (void *cls);


/**
 * Callback for set operation results. Called for each element
 * in the result set.
 *
 * @param cls closure
 * @param element a result element, only valid if status is #GNUNET_SET_STATUS_OK
 * @param status see `enum GNUNET_SET_Status`
 */
typedef void (*GNUNET_SET_ResultIterator) (void *cls,
                                           const struct GNUNET_SET_Element *element,
                                           enum GNUNET_SET_Status status);

/**
 * Iterator for set elements.
 *
 * @param cls closure
 * @param element the current element, NULL if all elements have been
 *        iterated over
 * @return #GNUNET_YES to continue iterating, #GNUNET_NO to stop.
 */
typedef int (*GNUNET_SET_ElementIterator) (void *cls,
                                           const struct GNUNET_SET_Element *element);


/**
 * Called when another peer wants to do a set operation with the
 * local peer. If a listen error occurs, the @a request is NULL.
 *
 * @param cls closure
 * @param other_peer the other peer
 * @param context_msg message with application specific information from
 *        the other peer
 * @param request request from the other peer (never NULL), use GNUNET_SET_accept()
 *        to accept it, otherwise the request will be refused
 *        Note that we can't just return value from the listen callback,
 *        as it is also necessary to specify the set we want to do the
 *        operation with, whith sometimes can be derived from the context
 *        message. It's necessary to specify the timeout.
 */
typedef void
(*GNUNET_SET_ListenCallback) (void *cls,
                              const struct GNUNET_PeerIdentity *other_peer,
                              const struct GNUNET_MessageHeader *context_msg,
                              struct GNUNET_SET_Request *request);



typedef void
(*GNUNET_SET_CopyReadyCallback) (void *cls,
                                 struct GNUNET_SET_Handle *copy);


/**
 * Create an empty set, supporting the specified operation.
 *
 * @param cfg configuration to use for connecting to the
 *        set service
 * @param op operation supported by the set
 *        Note that the operation has to be specified
 *        beforehand, as certain set operations need to maintain
 *        data structures spefific to the operation
 * @return a handle to the set
 */
struct GNUNET_SET_Handle *
GNUNET_SET_create (const struct GNUNET_CONFIGURATION_Handle *cfg,
                   enum GNUNET_SET_OperationType op);


/**
 * Add an element to the given set.
 * After the element has been added (in the sense of being
 * transmitted to the set service), @a cont will be called.
 * Calls to #GNUNET_SET_add_element can be queued
 *
 * @param set set to add element to
 * @param element element to add to the set
 * @param cont continuation called after the element has been added
 * @param cont_cls closure for @a cont
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the
 *         set is invalid (e.g. the set service crashed)
 */
int
GNUNET_SET_add_element (struct GNUNET_SET_Handle *set,
                        const struct GNUNET_SET_Element *element,
                        GNUNET_SET_Continuation cont,
                        void *cont_cls);


/**
 * Remove an element to the given set.
 * After the element has been removed (in the sense of the
 * request being transmitted to the set service), cont will be called.
 * Calls to remove_element can be queued
 *
 * @param set set to remove element from
 * @param element element to remove from the set
 * @param cont continuation called after the element has been removed
 * @param cont_cls closure for @a cont
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the
 *         set is invalid (e.g. the set service crashed)
 */
int
GNUNET_SET_remove_element (struct GNUNET_SET_Handle *set,
                           const struct GNUNET_SET_Element *element,
                           GNUNET_SET_Continuation cont,
                           void *cont_cls);


void
GNUNET_SET_copy_lazy (struct GNUNET_SET_Handle *set,
                      GNUNET_SET_CopyReadyCallback cb,
                      void *cls);


/**
 * Destroy the set handle, and free all associated resources.
 * Iterations must have completed (or be explicitly canceled)
 * before destroying the corresponding set.  Operations may
 * still be pending when a set is destroyed.
 *
 * @param set set to destroy
 */
void
GNUNET_SET_destroy (struct GNUNET_SET_Handle *set);


/**
 * Prepare a set operation to be evaluated with another peer.
 * The evaluation will not start until the client provides
 * a local set with GNUNET_SET_commit().
 *
 * @param other_peer peer with the other set
 * @param app_id hash for the application using the set
 * @param context_msg additional information for the request
 * @param result_mode specified how results will be returned,
 *        see `enum GNUNET_SET_ResultMode`.
 * @param result_cb called on error or success
 * @param result_cls closure for @a result_cb
 * @return a handle to cancel the operation
 */
struct GNUNET_SET_OperationHandle *
GNUNET_SET_prepare (const struct GNUNET_PeerIdentity *other_peer,
                    const struct GNUNET_HashCode *app_id,
                    const struct GNUNET_MessageHeader *context_msg,
                    enum GNUNET_SET_ResultMode result_mode,
                    GNUNET_SET_ResultIterator result_cb,
                    void *result_cls);


/**
 * Wait for set operation requests for the given application ID.
 * If the connection to the set service is lost, the listener is
 * re-created transparently with exponential backoff.
 *
 * @param cfg configuration to use for connecting to
 *            the set service
 * @param operation operation we want to listen for
 * @param app_id id of the application that handles set operation requests
 * @param listen_cb called for each incoming request matching the operation
 *                  and application id
 * @param listen_cls handle for @a listen_cb
 * @return a handle that can be used to cancel the listen operation
 */
struct GNUNET_SET_ListenHandle *
GNUNET_SET_listen (const struct GNUNET_CONFIGURATION_Handle *cfg,
                   enum GNUNET_SET_OperationType op_type,
                   const struct GNUNET_HashCode *app_id,
                   GNUNET_SET_ListenCallback listen_cb,
                   void *listen_cls);


/**
 * Cancel the given listen operation.  After calling cancel, the
 * listen callback for this listen handle will not be called again.
 *
 * @param lh handle for the listen operation
 */
void
GNUNET_SET_listen_cancel (struct GNUNET_SET_ListenHandle *lh);


/**
 * Accept a request we got via GNUNET_SET_listen().  Must be called during
 * GNUNET_SET_listen(), as the `struct GNUNET_SET_Request` becomes invalid
 * afterwards.
 * Call GNUNET_SET_commit() to provide the local set to use for the operation,
 * and to begin the exchange with the remote peer.
 *
 * @param request request to accept
 * @param result_mode specified how results will be returned,
 *        see `enum GNUNET_SET_ResultMode`.
 * @param result_cb callback for the results
 * @param result_cls closure for @a result_cb
 * @return a handle to cancel the operation
 */
struct GNUNET_SET_OperationHandle *
GNUNET_SET_accept (struct GNUNET_SET_Request *request,
                   enum GNUNET_SET_ResultMode result_mode,
                   GNUNET_SET_ResultIterator result_cb,
                   void *result_cls);


/**
 * Commit a set to be used with a set operation.
 * This function is called once we have fully constructed
 * the set that we want to use for the operation.  At this
 * time, the P2P protocol can then begin to exchange the
 * set information and call the result callback with the
 * result information.
 *
 * @param oh handle to the set operation
 * @param set the set to use for the operation
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the
 *         set is invalid (e.g. the set service crashed)
 */
int
GNUNET_SET_commit (struct GNUNET_SET_OperationHandle *oh,
                   struct GNUNET_SET_Handle *set);


/**
 * Cancel the given set operation.  May not be called after the
 * operation's `GNUNET_SET_ResultIterator` has been called with a
 * status that indicates error, timeout or done.
 *
 * @param oh set operation to cancel
 */
void
GNUNET_SET_operation_cancel (struct GNUNET_SET_OperationHandle *oh);


/**
 * Iterate over all elements in the given set.
 * Note that this operation involves transferring every element of the set
 * from the service to the client, and is thus costly.
 * Only one iteration per set may be active at the same time.
 *
 * @param set the set to iterate over
 * @param iter the iterator to call for each element
 * @param iter_cls closure for @a iter
 * @return #GNUNET_YES if the iteration started successfuly,
 *         #GNUNET_NO if another iteration was still active,
 *         #GNUNET_SYSERR if the set is invalid (e.g. the server crashed, disconnected)
 */
int
GNUNET_SET_iterate (struct GNUNET_SET_Handle *set,
                    GNUNET_SET_ElementIterator iter,
                    void *iter_cls);

/**
 * Stop iteration over all elements in the given set.  Can only
 * be called before the iteration has "naturally" completed its
 * turn.
 *
 * @param set the set to stop iterating over
 */
void
GNUNET_SET_iterate_cancel (struct GNUNET_SET_Handle *set);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
