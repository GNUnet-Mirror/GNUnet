/*
      This file is part of GNUnet
      (C) 2009, 2010 Christian Grothoff (and other contributing authors)

      GNUnet is free software; you can redistribute it and/or modify
      it under the terms of the GNU General Public License as published
      by the Free Software Foundation; either version 2, or (at your
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
 * @file include/gnunet_statistics_service.h
 * @brief API to create, modify and access statistics about
 *        the operation of GNUnet; all statistical values
 *        must be of type "unsigned long long".
 * @author Christian Grothoff
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

#include "gnunet_common.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_scheduler_lib.h"

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
 * @param is_persistent GNUNET_YES if the value is persistent, GNUNET_NO if not
 * @return GNUNET_OK to continue, GNUNET_SYSERR to abort iteration
 */
typedef int (*GNUNET_STATISTICS_Iterator) (void *cls, const char *subsystem,
                                           const char *name, uint64_t value,
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
 * Destroy a handle (free all state associated with
 * it).
 *
 * @param h statistics handle to destroy
 * @param sync_first set to GNUNET_YES if pending SET requests should
 *        be completed
 */
void
GNUNET_STATISTICS_destroy (struct GNUNET_STATISTICS_Handle *h, int sync_first);


/**
 * Watch statistics from the peer (be notified whenever they change).
 *
 * @param handle identification of the statistics service
 * @param subsystem limit to the specified subsystem, never NULL
 * @param name name of the statistic value, never NULL
 * @param proc function to call on each value
 * @param proc_cls closure for proc
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_STATISTICS_watch (struct GNUNET_STATISTICS_Handle *handle,
                         const char *subsystem, const char *name,
                         GNUNET_STATISTICS_Iterator proc, void *proc_cls);


/**
 * Stop watching statistics from the peer.
 *
 * @param handle identification of the statistics service
 * @param subsystem limit to the specified subsystem, never NULL
 * @param name name of the statistic value, never NULL
 * @param proc function to call on each value
 * @param proc_cls closure for proc
 * @return GNUNET_OK on success, GNUNET_SYSERR on error (no such watch)
 */
int
GNUNET_STATISTICS_watch_cancel (struct GNUNET_STATISTICS_Handle *handle,
				const char *subsystem, const char *name,
				GNUNET_STATISTICS_Iterator proc, void *proc_cls);


/**
 * Continuation called by the "get_all" and "get" functions.
 *
 * @param cls closure
 * @param success GNUNET_OK if statistics were
 *        successfully obtained, GNUNET_SYSERR if not.
 */
typedef void (*GNUNET_STATISTICS_Callback) (void *cls, int success);


/**
 * Handle that can be used to cancel a statistics 'get' operation.
 */
struct GNUNET_STATISTICS_GetHandle;

/**
 * Get statistic from the peer.
 *
 * @param handle identification of the statistics service
 * @param subsystem limit to the specified subsystem, NULL for our subsystem
 * @param name name of the statistic value, NULL for all values
 * @param timeout after how long should we give up (and call
 *        notify with buf NULL and size 0)?
 * @param cont continuation to call when done (can be NULL)
 *        This callback CANNOT destroy the statistics handle in the same call.
 * @param proc function to call on each value
 * @param cls closure for proc and cont
 * @return NULL on error
 */
struct GNUNET_STATISTICS_GetHandle *
GNUNET_STATISTICS_get (struct GNUNET_STATISTICS_Handle *handle,
                       const char *subsystem, const char *name,
                       struct GNUNET_TIME_Relative timeout,
                       GNUNET_STATISTICS_Callback cont,
                       GNUNET_STATISTICS_Iterator proc, void *cls);


/**
 * Cancel a 'get' request.  Must be called before the 'cont'
 * function is called.
 *
 * @param gh handle of the request to cancel
 */
void
GNUNET_STATISTICS_get_cancel (struct GNUNET_STATISTICS_GetHandle *gh);


/**
 * Set statistic value for the peer.  Will always use our
 * subsystem (the argument used when "handle" was created).
 *
 * @param handle identification of the statistics service
 * @param name name of the statistic value
 * @param value new value to set
 * @param make_persistent should the value be kept across restarts?
 */
void
GNUNET_STATISTICS_set (struct GNUNET_STATISTICS_Handle *handle,
                       const char *name, uint64_t value, int make_persistent);

/**
 * Set statistic value for the peer.  Will always use our
 * subsystem (the argument used when "handle" was created).
 *
 * @param handle identification of the statistics service
 * @param name name of the statistic value
 * @param delta change in value (added to existing value)
 * @param make_persistent should the value be kept across restarts?
 */
void
GNUNET_STATISTICS_update (struct GNUNET_STATISTICS_Handle *handle,
                          const char *name, int64_t delta, int make_persistent);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
