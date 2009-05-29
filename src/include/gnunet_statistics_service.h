/*
      This file is part of GNUnet
      (C) 2009 Christian Grothoff (and other contributing authors)

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
typedef int (*GNUNET_STATISTICS_Iterator) (void *cls,
                                           const char *subsystem,
                                           const char *name,
                                           unsigned long long value,
                                           int is_persistent);

/**
 * Get handle for the statistics service.
 *
 * @param sched scheduler to use
 * @param subsystem name of subsystem using the service
 * @param cfg services configuration in use
 * @return handle to use
 */
struct GNUNET_STATISTICS_Handle
  *GNUNET_STATISTICS_create (struct GNUNET_SCHEDULER_Handle *sched,
                             const char *subsystem,
                             struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Destroy a handle (free all state associated with
 * it).
 */
void GNUNET_STATISTICS_destroy (struct GNUNET_STATISTICS_Handle *handle);


/**
 * Continuation called by the "get_all" and "get" functions.
 *
 * @param cls closure
 * @param success GNUNET_OK if statistics were
 *        successfully obtained, GNUNET_SYSERR if not.
 */
typedef void (*GNUNET_STATISTICS_Callback) (void *cls, int success);

/**
 * Get statistic from the peer.
 *
 * @param handle identification of the statistics service
 * @param subsystem limit to the specified subsystem, NULL for our subsystem
 * @param name name of the statistic value, NULL for all values
 * @param timeout after how long should we give up (and call
 *        notify with buf NULL and size 0)?
 * @param cont continuation to call when done (can be NULL)
 * @param proc function to call on each value
 * @param cls closure for proc and cont
 */
void
GNUNET_STATISTICS_get (struct GNUNET_STATISTICS_Handle *handle,
                       const char *subsystem,
                       const char *name,
                       struct GNUNET_TIME_Relative timeout,
                       GNUNET_STATISTICS_Callback cont,
                       GNUNET_STATISTICS_Iterator proc, void *cls);

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
                       const char *name,
                       unsigned long long value, int make_persistent);

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
                          const char *name,
                          long long delta, int make_persistent);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
