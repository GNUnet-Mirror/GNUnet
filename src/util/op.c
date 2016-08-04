/*
     This file is part of GNUnet.
     Copyright (C) 2016 GNUnet e.V.

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
 * @file
 * Asynchronous operations; register callbacks for operations and call them when a response arrives.
 *
 * @author Gabor X Toth
 */

#include <inttypes.h>

#include "platform.h"
#include "gnunet_util_lib.h"

#define LOG(kind,...) GNUNET_log_from (kind, "util-op", __VA_ARGS__)

struct OperationListItem
{
  struct OperationListItem *prev;
  struct OperationListItem *next;

  /**
   * Operation ID.
   */
  uint64_t op_id;

  /**
   * Continuation to invoke with the result of an operation.
   */
  GNUNET_ResultCallback result_cb;

  /**
   * Closure for @a result_cb.
   */
  void *cls;

  /**
   * User context.
   */
  void *ctx;
};


/**
 * Operations handle.
 */

struct GNUNET_OP_Handle
{
  /**
   * First operation in the linked list.
   */
  struct OperationListItem *op_head;

  /**
   * Last operation in the linked list.
   */
  struct OperationListItem *op_tail;

  /**
   * Last operation ID used.
   */
  uint64_t last_op_id;
};


/**
 * Create new operations handle.
 */
struct GNUNET_OP_Handle *
GNUNET_OP_create ()
{
  return GNUNET_new (struct GNUNET_OP_Handle);
}


/**
 * Destroy operations handle.
 */
void
GNUNET_OP_destroy (struct GNUNET_OP_Handle *h)
{
  GNUNET_free (h);
}


/**
 * Get a unique operation ID to distinguish between asynchronous requests.
 *
 * @param h
 *        Operations handle.
 *
 * @return Operation ID to use.
 */
uint64_t
GNUNET_OP_get_next_id (struct GNUNET_OP_Handle *h)
{
  return ++h->last_op_id;
}


/**
 * Find operation by ID.
 *
 * @param h
 *        Operations handle.
 * @param op_id
 *        Operation ID to look up.
 *
 * @return Operation, or NULL if not found.
 */
static struct OperationListItem *
op_find (struct GNUNET_OP_Handle *h,
	 uint64_t op_id)
{
  struct OperationListItem *op;

  for (op = h->op_head; NULL != op; op = op->next)
    if (op->op_id == op_id)
      return op;
  return NULL;
}


/**
 * Find operation by ID.
 *
 * @param h
 *        Operations handle.
 * @param op_id
 *        Operation ID to look up.
 * @param[out] result_cb
 *        If an operation was found, its result callback is returned here.
 * @param[out] cls
 *        If an operation was found, its closure is returned here.
 * @param[out] ctx
 *        If an operation was found, its user context is returned here.
 *
 * @return #GNUNET_YES if an operation was found,
 *         #GNUNET_NO  if not found.
 */
int
GNUNET_OP_get (struct GNUNET_OP_Handle *h,
               uint64_t op_id,
               GNUNET_ResultCallback *result_cb,
               void **cls,
               void **ctx)
{
  struct OperationListItem *op = op_find (h, op_id);
  if (NULL != op)
  {
    if (NULL != result_cb)
      *result_cb = op->result_cb;
    if (NULL != cls)
      *cls = op->cls;
    if (NULL != ctx)
      *ctx = op->ctx;
    return GNUNET_YES;
  }
  return GNUNET_NO;
}


/**
 * Add a new operation.
 *
 * @param h
 *        Operations handle.
 * @param result_cb
 *        Function to call with the result of the operation.
 * @param cls
 *        Closure for @a result_cb.
 * @param ctx
 *        User context.
 *
 * @return ID of the new operation.
 */
uint64_t
GNUNET_OP_add (struct GNUNET_OP_Handle *h,
               GNUNET_ResultCallback result_cb,
               void *cls,
               void *ctx)
{
  struct OperationListItem *op;

  op = GNUNET_new (struct OperationListItem);
  op->op_id = GNUNET_OP_get_next_id (h);
  op->result_cb = result_cb;
  op->cls = cls;
  op->ctx = ctx;
  GNUNET_CONTAINER_DLL_insert_tail (h->op_head,
				    h->op_tail,
				    op);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%p Added operation #%" PRIu64 "\n",
       h, op->op_id);
  return op->op_id;
}


/**
 * Remove an operation, and call its result callback (unless it was cancelled).
 *
 *
 * @param h
 *        Operations handle.
 * @param op_id
 *        Operation ID.
 * @param result_code
 *        Result of the operation.
 * @param data
 *        Data result of the operation.
 * @param data_size
 *        Size of @a data.
 * @param[out] ctx
 *        User context.
 * @param cancel
 *        Is the operation cancelled?
 *        #GNUNET_NO  Not cancelled, result callback is called.
 *        #GNUNET_YES Cancelled, result callback is not called.
 *
 * @return #GNUNET_YES if the operation was found and removed,
 *         #GNUNET_NO  if the operation was not found.
 */
static int
op_result (struct GNUNET_OP_Handle *h,
           uint64_t op_id,
	   int64_t result_code,
           const void *data,
	   uint16_t data_size,
           void **ctx,
	   uint8_t cancel)
{
  if (0 == op_id)
    return GNUNET_NO;

  struct OperationListItem *op = op_find (h, op_id);
  if (NULL == op)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Could not find operation #%" PRIu64 "\n", op_id);
    return GNUNET_NO;
  }

  if (NULL != ctx)
    *ctx = op->ctx;

  GNUNET_CONTAINER_DLL_remove (h->op_head,
			       h->op_tail,
			       op);

  if ( (GNUNET_YES != cancel) &&
       (NULL != op->result_cb) )
    op->result_cb (op->cls,
		   result_code, data,
		   data_size);
  GNUNET_free (op);
  return GNUNET_YES;
}


/**
 * Call the result callback of an operation and remove it.
 *
 * @param h
 *        Operations handle.
 * @param op_id
 *        Operation ID.
 * @param result_code
 *        Result of the operation.
 * @param data
 *        Data result of the operation.
 * @param data_size
 *        Size of @a data.
 * @param[out] ctx
 *        User context.
 *
 * @return #GNUNET_YES if the operation was found and removed,
 *         #GNUNET_NO  if the operation was not found.
 */
int
GNUNET_OP_result (struct GNUNET_OP_Handle *h,
                  uint64_t op_id,
                  int64_t result_code,
                  const void *data,
                  uint16_t data_size,
                  void **ctx)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%p Received result for operation #%" PRIu64 ": %" PRId64 " (size: %u)\n",
       h, op_id, result_code, data_size);
  return op_result (h, op_id, result_code, data, data_size, ctx, GNUNET_NO);
}


/**
 * Remove / cancel an operation.
 *
 * @param h
 *        Operations handle.
 * @param op_id
 *        Operation ID.
 *
 * @return #GNUNET_YES if the operation was found and removed,
 *         #GNUNET_NO  if the operation was not found.
 */
int
GNUNET_OP_remove (struct GNUNET_OP_Handle *h,
                  uint64_t op_id)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%p Cancelling operation #%" PRIu64  "\n",
       h, op_id);
  return op_result (h, op_id, 0, NULL, 0, NULL, GNUNET_YES);
}
