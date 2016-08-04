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

#ifndef GNUNET_OP_H
#define GNUNET_OP_H

#include "gnunet_util_lib.h"

/**
 * Operations handle.
 */
struct GNUNET_OP_Handle;


/**
 * Create new operations handle.
 */
struct GNUNET_OP_Handle *
GNUNET_OP_create ();


/**
 * Destroy operations handle.
 */
void
GNUNET_OP_destroy (struct GNUNET_OP_Handle *h);


/**
 * Get a unique operation ID to distinguish between asynchronous requests.
 *
 * @param h
 *        Operations handle.
 *
 * @return Operation ID to use.
 */
uint64_t
GNUNET_OP_get_next_id (struct GNUNET_OP_Handle *h);


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
 *        User context.
 *
 * @return #GNUNET_YES if an operation was found,
 *         #GNUNET_NO  if not found.
 */
int
GNUNET_OP_get (struct GNUNET_OP_Handle *h,
               uint64_t op_id,
               GNUNET_ResultCallback *result_cb,
               void **cls,
               void **ctx);


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
               void *ctx);


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
                  void **ctx);


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
                  uint64_t op_id);


#endif // GNUNET_OP_H
