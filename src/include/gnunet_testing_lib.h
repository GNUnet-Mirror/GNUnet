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
 * @file include/gnunet_testing_lib.h
 * @brief convenience API for writing testcases for GNUnet
 *        Many testcases need to start and stop gnunetd,
 *        and this library is supposed to make that easier
 *        for TESTCASES.  Normal programs should always
 *        use functions from gnunet_{util,arm}_lib.h.  This API is
 *        ONLY for writing testcases!
 * @author Christian Grothoff
 */

#ifndef GNUNET_TESTING_LIB_H
#define GNUNET_TESTING_LIB_H

#include "gnunet_util_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif



/**
 * Handle for a GNUnet daemon (technically a set of
 * daemons; the handle is really for the master ARM
 * daemon) started by the testing library.
 */
struct GNUNET_TESTING_Daemon;


/**
 * Prototype of a function that will be called whenever
 * a daemon was started by the testing library.
 *
 * @param cls closure
 * @param id identifier for the daemon, NULL on error
 * @param cfg configuration used by this daemon
 * @param d handle for the daemon
 * @param emsg error message (NULL on success)
 */
typedef void (*GNUNET_TESTING_NotifyDaemonRunning)(void *cls,
						   const struct GNUNET_PeerIdentity *id,
						   const struct GNUNET_CONFIGURATION_Handle *cfg,
						   struct GNUNET_TESTING_Daemon *d,
						   const char *emsg);


/**
 * Starts a GNUnet daemon.
 *
 * @param sched scheduler to use 
 * @param cfg configuration to use
 * @param service_home directory to use as the service home directory
 * @param transports transport services that should be loaded
 * @param applications application services and daemons that should be started
 * @param port_offset offset to add to all ports for all services
 * @param hostname name of the machine where to run GNUnet
 *        (use NULL for localhost).
 * @param cb function to call with the result
 * @param cb_cls closure for cb
 * @return handle to the daemon (actual start will be completed asynchronously)
 */
struct GNUNET_TESTING_Daemon *
GNUNET_TESTING_daemon_start (struct GNUNET_SCHEDULER_Handle *sched,
			     struct GNUNET_CONFIGURATION_Handle *cfg,
			     const char *service_home,
			     const char *transports,
			     const char *applications,
			     uint16_t port_offset,
			     const char *hostname,
			     GNUNET_TESTING_NotifyDaemonRunning cb,
			     void *cb_cls);


/**
 * Prototype of a function that will be called when a
 * particular operation was completed the testing library.
 *
 * @param cls closure
 * @param emsg NULL on success
 */
typedef void (*GNUNET_TESTING_NotifyCompletion)(void *cls,
						const char *emsg);


/**
 * Stops a GNUnet daemon.
 *
 * @param d the daemon that should be stopped
 * @param cb function called once the daemon was stopped
 * @param cb_cls closure for cb
 */
void GNUNET_TESTING_daemon_stop (struct GNUNET_TESTING_Daemon *d,
				 GNUNET_TESTING_NotifyCompletion cb,
				 void * cb_cls);


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
					void * cb_cls);



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
				     void *cb_cls);


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
				 const struct GNUNET_CONFIGURATION_Handle *cfg,
				 unsigned int total,
				 GNUNET_TESTING_NotifyDaemonRunning cb,
				 void *cb_cls,
				 GNUNET_TESTING_NotifyCompletion cbe,
				 void *cbe_cls,
				 const char *hostname,
				 va_list va);


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
			      ...);


/**
 * Handle to an entire testbed of GNUnet peers.
 */
struct GNUNET_TESTING_Testbed;

/**
 * Prototype of a function that will be called when 
 * a testbed is being created.
 *
 * @param cls closure
 * @param tb NULL on error
 */
typedef void (*GNUNET_TESTING_NotifyTestbedRunning)(void *cls,
						    struct GNUNET_TESTING_Testbed *tb);


/**
 * Topologies supported for testbeds.
 */
enum GNUNET_TESTING_Topology
{
  /**
   * A clique (everyone connected to everyone else).
   */
  GNUNET_TESTING_TOPOLOGY_CLIQUE,

  /**
   * Small-world network (2d torus plus random links).
   */
  GNUNET_TESTING_TOPOLOGY_SMALL_WORLD,

  /**
   * Ring topology.
   */
  GNUNET_TESTING_TOPOLOGY_RING,

  /**
   * 2-d torus.
   */
  GNUNET_TESTING_TOPOLOGY_2D_TORUS,

  /**
   * Random graph.
   */
  GNUNET_TESTING_TOPOLOGY_ERDOS_RENYI,

  /**
   * All peers are disconnected.
   */
  GNUNET_TESTING_TOPOLOGY_NONE
};



/**
 * Start count GNUnet daemons with a particular
 * topology.
 *
 * @param size number of peers the testbed should have
 * @param topology desired topology (enforced via F2F)
 * @param service_home_prefix path to use as the prefix for the home of the services
 * @param transports which transports should all peers use
 * @param applications which applications should be used?
 * @param timeout how long is this allowed to take?
 * @param cb function to call on each daemon that was started
 * @param cb_cls closure for cb
 * @param cte function to call at the end
 * @param cte_cls closure for cbe
 * @param hostname where to run the peers; can be NULL (to run
 *        everything on localhost). Additional
 *        hosts can be specified using a NULL-terminated list of
 *        varargs, hosts will then be used round-robin from that
 *        list.
 */
void
GNUNET_TESTING_testbed_start (struct GNUNET_SCHEDULER_Handle *sched,
			      struct GNUNET_CONFIGURATION_Handle *cfg,
			      unsigned int size,
			      enum GNUNET_TESTING_Topology topology,
			      const char *service_home_prefix,
			      const char *transports,
			      const char *applications,
			      GNUNET_TESTING_NotifyDaemonRunning cb,
			      void *cb_cls,
			      GNUNET_TESTING_NotifyTestbedRunning cte,
			      void *cte_cls,
			      const char *hostname,
			      ...);




/**
 * Stop all of the daemons started with the start function.
 *
 * @param tb handle for the testbed
 * @param cb function to call at the end
 * @param cb_cls closure for cb
 */
void
GNUNET_TESTING_testbed_stop (struct GNUNET_TESTING_Testbed *tb,
			     GNUNET_TESTING_NotifyCompletion cb,
			     void *cb_cls );



/**
 * Simulate churn in the testbed by stopping some peers (and possibly
 * re-starting others if churn is called multiple times).  This
 * function can only be used to create leave-join churn (peers "never"
 * leave for good).  First "voff" random peers that are currently
 * online will be taken offline; then "von" random peers that are then
 * offline will be put back online.  No notifications will be
 * generated for any of these operations except for the callback upon
 * completion.  Note that the implementation is at liberty to keep
 * the ARM service itself (but none of the other services or daemons)
 * running even though the "peer" is being varied offline.
 *
 * @param tb handle for the testbed
 * @param voff number of peers that should go offline
 * @param von number of peers that should come back online;
 *            must be zero on first call (since "testbed_start"
 *            always starts all of the peers)
 * @param cb function to call at the end
 * @param cb_cls closure for cb
 */
void
GNUNET_TESTING_testbed_churn (struct GNUNET_TESTING_Testbed *tb,
			      unsigned int voff,
			      unsigned int von,
			      GNUNET_TESTING_NotifyCompletion cb,
			      void *cb_cls);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
