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
 * @file testing/testing_testbed.c
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
 * Handle to an entire testbed of GNUnet peers.
 */
struct GNUNET_TESTING_Testbed
{
};


/**
 * Start "count" GNUnet daemons with a particular topology.
 *
 * @param sched scheduler to use 
 * @param cfg configuration template to use
 * @param count number of peers the testbed should have
 * @param topology desired topology (enforced via F2F)
 * @param cb function to call on each daemon that was started
 * @param cb_cls closure for cb
 * @param hostname where to run the peers; can be NULL (to run
 *        everything on localhost). Additional
 *        hosts can be specified using a NULL-terminated list of
 *        varargs, hosts will then be used round-robin from that
 *        list.
 * @return handle to control the testbed
 */
struct GNUNET_TESTING_Testbed *
GNUNET_TESTING_testbed_start (struct GNUNET_SCHEDULER_Handle *sched,
			      const struct GNUNET_CONFIGURATION_Handle *cfg,
			      unsigned int count,
			      enum GNUNET_TESTING_Topology topology,
			      GNUNET_TESTING_NotifyDaemonRunning cb,
			      void *cb_cls,
			      const char *hostname,
			      ...)
{
  GNUNET_break (0);
  return NULL;
}


/**
 * Stop all of the daemons started with the start function.
 *
 * @param tb handle for the testbed
 * @param cb function to call when done
 * @param cb_cls closure for cb
 */
void
GNUNET_TESTING_testbed_stop (struct GNUNET_TESTING_Testbed *tb,
			     GNUNET_TESTING_NotifyCompletion cb,
			     void *cb_cls)
{
  GNUNET_break (0);
}


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
			      void *cb_cls)
{
  GNUNET_break (0);
}


/* end of testing_testbed.c */
