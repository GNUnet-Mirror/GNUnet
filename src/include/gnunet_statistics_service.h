/*
      This file is part of GNUnet
      Copyright (C) 2009-2013, 2016 GNUnet e.V.

      GNUnet is free software: you can redistribute it and/or modify it
      under the terms of the GNU Affero General Public License as published
      by the Free Software Foundation, either version 3 of the License,
      or (at your option) any later version.

      GNUnet is distributed in the hope that it will be useful, but
      WITHOUT ANY WARRANTY; without even the implied warranty of
      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
      Affero General Public License for more details.

      You should have received a copy of the GNU Affero General Public License
      along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @author Christian Grothoff
 *
 * @file
 * API to create, modify and access statistics.
 *
 * @defgroup statistics  Statistics service
 * Track statistics or provide access to statistics.
 *
 * Create, modify and access statistics about the operation of GNUnet.
 *
 * All statistical values must be of type `unsigned long long`.
 *
 * @see [Documentation](https://gnunet.org/gnunet-statistics-subsystem)
 *
 * @{
 */

#ifndef GNUNET_STATISTICS_SERVICE_H
#define GNUNET_STATISTICS_SERVICE_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"

/**
 * Version of the statistics API.
 */
#define GNUNET_STATISTICS_VERSION 0x00000000

/**
 * Opaque handle for the statistics service.
 */
struct GNUNET_STATISTICS_Handle;

/**
 * Callback function to process statistic values.
 *
 * @param cls closure
 * @param subsystem name of subsystem that created the statistic
 * @param name the name of the datum
 * @param value the current value
 * @param is_persistent #GNUNET_YES if the value is persistent, #GNUNET_NO if not
 * @return #GNUNET_OK to continue, #GNUNET_SYSERR to abort iteration
 */
typedef int
(*GNUNET_STATISTICS_Iterator) (void *cls,
                               const char *subsystem,
                               const char *name,
                               uint64_t value,
                               int is_persistent);


/**
 * Get handle for the statistics service.
 *
 * @param subsystem name of subsystem using the service
 * @param cfg services configuration in use
 * @return handle to use
 */
struct GNUNET_STATISTICS_Handle *
GNUNET_STATISTICS_create (const char *subsystem,
                          const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Destroy a handle (free all state associated with it).
 *
 * @param h statistics handle to destroy
 * @param sync_first set to #GNUNET_YES if pending SET requests should
 *        be completed
 */
void
GNUNET_STATISTICS_destroy (struct GNUNET_STATISTICS_Handle *h,
                           int sync_first);


/**
 * Watch statistics from the peer (be notified whenever they change).
 *
 * @param handle identification of the statistics service
 * @param subsystem limit to the specified subsystem, never NULL
 * @param name name of the statistic value, never NULL
 * @param proc function to call on each value
 * @param proc_cls closure for @a proc
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GNUNET_STATISTICS_watch (struct GNUNET_STATISTICS_Handle *handle,
                         const char *subsystem,
                         const char *name,
                         GNUNET_STATISTICS_Iterator proc,
                         void *proc_cls);


/**
 * Stop watching statistics from the peer.
 *
 * @param handle identification of the statistics service
 * @param subsystem limit to the specified subsystem, never NULL
 * @param name name of the statistic value, never NULL
 * @param proc function to call on each value
 * @param proc_cls closure for @a proc
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error (no such watch)
 */
int
GNUNET_STATISTICS_watch_cancel (struct GNUNET_STATISTICS_Handle *handle,
                                const char *subsystem,
                                const char *name,
                                GNUNET_STATISTICS_Iterator proc,
                                void *proc_cls);


/**
 * Continuation called by #GNUNET_STATISTICS_get() functions.
 *
 * @param cls closure
 * @param success #GNUNET_OK if statistics were
 *        successfully obtained, #GNUNET_SYSERR if not.
 */
typedef void
(*GNUNET_STATISTICS_Callback) (void *cls,
                               int success);


/**
 * Handle that can be used to cancel a statistics 'get' operation.
 */
struct GNUNET_STATISTICS_GetHandle;


/**
 * Get statistic from the peer.
 *
 * @param handle identification of the statistics service
 * @param subsystem limit to the specified subsystem, NULL for all subsystems
 * @param name name of the statistic value, NULL for all values
 * @param cont continuation to call when done (can be NULL)
 *        This callback CANNOT destroy the statistics handle in the same call.
 * @param proc function to call on each value
 * @param cls closure for @a proc and @a cont
 * @return NULL on error
 */
struct GNUNET_STATISTICS_GetHandle *
GNUNET_STATISTICS_get (struct GNUNET_STATISTICS_Handle *handle,
                       const char *subsystem,
                       const char *name,
                       GNUNET_STATISTICS_Callback cont,
                       GNUNET_STATISTICS_Iterator proc,
                       void *cls);


/**
 * Cancel a #GNUNET_STATISTICS_get request.  Must be called before the 'cont'
 * function is called.
 *
 * @param gh handle of the request to cancel
 */
void
GNUNET_STATISTICS_get_cancel (struct GNUNET_STATISTICS_GetHandle *gh);


/**
 * Set statistic value for the peer.  Will always use our
 * subsystem (the argument used when @a handle was created).
 *
 * @param handle identification of the statistics service
 * @param name name of the statistic value
 * @param value new value to set
 * @param make_persistent should the value be kept across restarts?
 */
void
GNUNET_STATISTICS_set (struct GNUNET_STATISTICS_Handle *handle,
                       const char *name,
                       uint64_t value,
                       int make_persistent);


/**
 * Set statistic value for the peer.  Will always use our
 * subsystem (the argument used when @a handle was created).
 *
 * @param handle identification of the statistics service
 * @param name name of the statistic value
 * @param delta change in value (added to existing value)
 * @param make_persistent should the value be kept across restarts?
 */
void
GNUNET_STATISTICS_update (struct GNUNET_STATISTICS_Handle *handle,
                          const char *name,
                          int64_t delta,
                          int make_persistent);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/** @} */ /* end of group statistics */

#endif
