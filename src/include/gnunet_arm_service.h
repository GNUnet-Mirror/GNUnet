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
 * @file include/gnunet_arm_service.h
 * @brief API to access gnunet-arm
 * @author Christian Grothoff
 */

#ifndef GNUNET_ARM_SERVICE_H
#define GNUNET_ARM_SERVICE_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_configuration_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_time_lib.h"

/**
 * Version of the arm API.
 */
#define GNUNET_ARM_VERSION 0x00000000


/**
 * Callback function invoked when operation is complete.
 *
 * @param cls closure
 * @param success GNUNET_YES if we think the service is running
 *                GNUNET_NO if we think the service is stopped
 *                GNUNET_SYSERR if we think ARM was not running or
 *                          if the service status is unknown
 */
typedef void (*GNUNET_ARM_Callback) (void *cls, int success);


/**
 * Start a service.
 *
 * @param service_name name of the service
 * @param cfg configuration to use (needed to contact ARM;
 *        the ARM service may internally use a different
 *        configuration to determine how to start the service).
 * @param sched scheduler to use
 * @param timeout how long to wait before failing for good
 * @param cb callback to invoke when service is ready
 * @param cb_cls closure for callback
 */
void
GNUNET_ARM_start_service (const char *service_name,
                          const struct GNUNET_CONFIGURATION_Handle *cfg,
                          struct GNUNET_SCHEDULER_Handle *sched,
                          struct GNUNET_TIME_Relative timeout,
                          GNUNET_ARM_Callback cb, void *cb_cls);


/**
 * Stop a service.
 *
 * @param service_name name of the service
 * @param cfg configuration to use (needed to contact ARM;
 *        the ARM service may internally use a different
 *        configuration to determine how to start the service).
 * @param sched scheduler to use
 * @param timeout how long to wait before failing for good
 * @param cb callback to invoke when service is ready
 * @param cb_cls closure for callback
 */
void
GNUNET_ARM_stop_service (const char *service_name,
                         const struct GNUNET_CONFIGURATION_Handle *cfg,
                         struct GNUNET_SCHEDULER_Handle *sched,
                         struct GNUNET_TIME_Relative timeout,
                         GNUNET_ARM_Callback cb, void *cb_cls);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
