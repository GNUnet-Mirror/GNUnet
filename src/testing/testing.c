/*
      This file is part of GNUnet
      (C) 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file testing/testing.c
 * @brief convenience API for writing testcases for GNUnet
 *        Many testcases need to start and stop gnunetd,
 *        and this library is supposed to make that easier
 *        for TESTCASES.  Normal programs should always
 *        use functions from gnunet_{util,arm}_lib.h.  This API is
 *        ONLY for writing testcases!
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_arm_service.h"
#include "gnunet_testing_lib.h"

/**
 * Handle for a GNUnet daemon (technically a set of
 * daemons; the handle is really for the master ARM
 * daemon) started by the testing library.
 */
struct GNUNET_TESTING_Daemon
{
};


/**
 * Starts a GNUnet daemon.  GNUnet must be installed on the target
 * system and available in the PATH.  The machine must furthermore be
 * reachable via "ssh" (unless the hostname is "NULL") without the
 * need to enter a password.
 *
 * @param sched scheduler to use 
 * @param cfg configuration to use
 * @param hostname name of the machine where to run GNUnet
 *        (use NULL for localhost).
 * @param cb function to call with the result
 * @param cb_cls closure for cb
 * @return handle to the daemon (actual start will be completed asynchronously)
 */
struct GNUNET_TESTING_Daemon *
GNUNET_TESTING_daemon_start (struct GNUNET_SCHEDULER_Handle *sched,
			     struct GNUNET_CONFIGURATION_Handle *cfg,
			     const char *hostname,
			     GNUNET_TESTING_NotifyDaemonRunning cb,
			     void *cb_cls)
{
  return NULL;
}


/**
 * Stops a GNUnet daemon.
 *
 * @param d the daemon that should be stopped
 * @param cb function called once the daemon was stopped
 * @param cb_cls closure for cb
 */
void GNUNET_TESTING_daemon_stop (struct GNUNET_TESTING_Daemon *d,
				 GNUNET_TESTING_NotifyCompletion cb,
				 void * cb_cls)
{
}


/**
 * Changes the configuration of a GNUnet daemon.
 *
 * @param d the daemon that should be modified
 * @param cfg the new configuration for the daemon
 * @param cb function called once the configuration was changed
 * @param cb_cls closure for cb
 */
void GNUNET_TESTING_daemon_reconfigure (struct GNUNET_TESTING_Daemon *d,
					const struct GNUNET_CONFIGURATION_Handle *cfg,
					GNUNET_TESTING_NotifyCompletion cb,
					void * cb_cls)
{
}


/**
 * Establish a connection between two GNUnet daemons.
 *
 * @param d1 handle for the first daemon
 * @param d2 handle for the second daemon
 * @param timeout how long is the connection attempt
 *        allowed to take?
 * @param cb function to call at the end
 * @param cb_cls closure for cb
 */
void GNUNET_TESTING_daemons_connect (struct GNUNET_TESTING_Daemon *d1,
				     struct GNUNET_TESTING_Daemon *d2,
				     struct GNUNET_TIME_Relative timeout,
				     GNUNET_TESTING_NotifyCompletion cb,
				     void *cb_cls)
{
}


/* end of testing.c */
