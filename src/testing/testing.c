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
 * Starts a GNUnet daemon.
 *
 * @param service_home directory to use as the service home directory
 * @param transports transport services that should be loaded
 * @param applications application services and daemons that should be started
 * @param port_offset offset to add to all ports for all services
 * @param hostname name of the machine where to run GNUnet
 *        (use NULL for localhost).
 * @param cb function to call with the result
 * @param cb_cls closure for cb
 */
void
GNUNET_TESTING_daemon_start (struct GNUNET_SCHEDULER_Handle *sched,
			     struct GNUNET_CONFIGURATION_Handle *cfg,
			     const char *service_home,
			     const char *transports,
			     const char *applications,
			     uint16_t port_offset,
			     const char *hostname,
			     GNUNET_TESTING_NotifyDaemonRunning cb,
			     void *cb_cls)
{
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
 * Establish a connection between two GNUnet daemons.
 *
 * @param d1 handle for the first daemon
 * @param d2 handle for the second daemon
 * @param cb function to call at the end
 * @param cb_cls closure for cb
 */
void GNUNET_TESTING_daemons_connect (struct GNUNET_TESTING_Daemon *d1,
				     struct GNUNET_TESTING_Daemon *d2,
				     GNUNET_TESTING_NotifyCompletion cb,
				     void *cb_cls)
{
}


/**
 * Start count gnunetd processes with the same set of
 * transports and applications.  The port numbers will
 * be computed by adding delta each time (zero
 * times for the first peer).
 *
 * @param total number of daemons to start
 * @param service_home_prefix path to use as the prefix for the home of the services
 * @param transports which transports should all peers use
 * @param applications which applications should be used?
 * @param timeout how long is this allowed to take?
 * @param cb function to call on each daemon that was started
 * @param cb_cls closure for cb
 * @param cbe function to call at the end
 * @param cbe_cls closure for cbe
 * @param hostname where to run the peers; can be NULL (to run
 *        everything on localhost).
 * @param va Additional hosts can be specified using a NULL-terminated list of
 *        varargs, hosts will then be used round-robin from that
 *        list; va only contains anything if hostname != NULL.
 */
void
GNUNET_TESTING_daemons_start_va (struct GNUNET_SCHEDULER_Handle *sched,
				 struct GNUNET_CONFIGURATION_Handle *cfg,
				 unsigned int total,
				 const char *service_home_prefix,
				 const char *transports,
				 const char *applications,
				 GNUNET_TESTING_NotifyDaemonRunning cb,
				 void *cb_cls,
				 GNUNET_TESTING_NotifyCompletion cbe,
				 void *cbe_cls,
				 const char *hostname,
				 va_list va)
{
}


/**
 * Start count gnunetd processes with the same set of
 * transports and applications.  The port numbers will
 * be computed by adding delta each time (zero
 * times for the first peer).
 *
 * @param total number of daemons to start
 * @param service_home_prefix path to use as the prefix for the home of the services
 * @param transports which transports should all peers use
 * @param applications which applications should be used?
 * @param timeout how long is this allowed to take?
 * @param cb function to call on each daemon that was started
 * @param cb_cls closure for cb
 * @param cbe function to call at the end
 * @param cbe_cls closure for cbe
 * @param hostname where to run the peers; can be NULL (to run
 *        everything on localhost). Additional
 *        hosts can be specified using a NULL-terminated list of
 *        varargs, hosts will then be used round-robin from that
 *        list.
 */
void
GNUNET_TESTING_daemons_start (struct GNUNET_SCHEDULER_Handle *sched,
			      struct GNUNET_CONFIGURATION_Handle *cfg,
			      unsigned int total,
			      const char *service_home_prefix,
			      const char *transports,
			      const char *applications,
			      GNUNET_TESTING_NotifyDaemonRunning cb,
			      void *cb_cls,
			      GNUNET_TESTING_NotifyCompletion cbe,
			      void *cbe_cls,
			      const char *hostname,
			      ...)
{
  va_list va;
  
  va_start (va, hostname);
  GNUNET_TESTING_daemons_start_va (sched, cfg,
				   total, service_home_prefix,
				   transports, applications,
				   cb, cb_cls, cbe, cbe_cls, hostname,
				   va);
  va_end (va);
}

/* end of testing.c */
