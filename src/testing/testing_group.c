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
 * @file testing/testing_group.c
 * @brief convenience API for writing testcases for GNUnet
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_arm_service.h"
#include "gnunet_testing_lib.h"


/**
 * Handle to a group of GNUnet peers.
 */
struct GNUNET_TESTING_PeerGroup
{
};


/**
 * Start count gnunetd processes with the same set of transports and
 * applications.  The port numbers (any option called "PORT") will be
 * adjusted to ensure that no two peers running on the same system
 * have the same port(s) in their respective configurations.
 *
 * @param sched scheduler to use 
 * @param cfg configuration template to use
 * @param total number of daemons to start
 * @param cb function to call on each daemon that was started
 * @param cb_cls closure for cb
 * @param hostname where to run the peers; can be NULL (to run
 *        everything on localhost).
 * @param va Additional hosts can be specified using a NULL-terminated list of
 *        varargs, hosts will then be used round-robin from that
 *        list; va only contains anything if hostname != NULL.
 * @return NULL on error, otherwise handle to control peer group
 */
struct GNUNET_TESTING_PeerGroup *
GNUNET_TESTING_daemons_start_va (struct GNUNET_SCHEDULER_Handle *sched,
				 const struct GNUNET_CONFIGURATION_Handle *cfg,
				 unsigned int total,
				 GNUNET_TESTING_NotifyDaemonRunning cb,
				 void *cb_cls,
				 const char *hostname,
				 va_list va)
{
  return NULL;
}


/**
 * Start count gnunetd processes with the same set of
 * transports and applications.  The port numbers will
 * be computed by adding delta each time (zero
 * times for the first peer).
 *
 * @param sched scheduler to use 
 * @param cfg configuration template to use
 * @param total number of daemons to start
 * @param timeout how long is this allowed to take?
 * @param cb function to call on each daemon that was started
 * @param cb_cls closure for cb
 * @param hostname where to run the peers; can be NULL (to run
 *        everything on localhost). Additional
 *        hosts can be specified using a NULL-terminated list of
 *        varargs, hosts will then be used round-robin from that
 *        list.
 * @return NULL on error, otherwise handle to control peer group
 */
struct GNUNET_TESTING_PeerGroup *
GNUNET_TESTING_daemons_start (struct GNUNET_SCHEDULER_Handle *sched,
			      struct GNUNET_CONFIGURATION_Handle *cfg,
			      unsigned int total,
			      GNUNET_TESTING_NotifyDaemonRunning cb,
			      void *cb_cls,
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



/**
 * Shutdown all peers started in the given group.
 * 
 * @param pg handle to the peer group
 */
void
GNUNET_TESTING_daemons_stop (struct GNUNET_TESTING_PeerGroup *pg)

{
}


/* end of testing_group.c */
