/*
      This file is part of GNUnet
      (C) 2008--2012 Christian Grothoff (and other contributing authors)

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
      Free Software Foundation, Inc., 59 Temple Place - Suite 330,
      Boston, MA 02111-1307, USA.
 */

/**
 * @file testbed/testbed_api_testbed.c
 * @brief high-level testbed management
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_testbed_service.h"


/**
 * Opaque handle to an abstract operation to be executed by the testing framework.
 */
struct GNUNET_TESTBED_Testbed
{
  // FIXME!
};


/**
 * Configure and run a testbed using the given
 * master controller on 'num_hosts' starting
 * 'num_peers' using the given peer configuration.
 *
 * @param controller master controller for the testbed
 *                   (must not be destroyed until after the
 *                    testbed is destroyed).
 * @param num_hosts number of hosts in 'hosts', 0 to only
 *        use 'localhost'
 * @param hosts list of hosts to use for the testbed
 * @param num_peers number of peers to start
 * @param peer_cfg peer configuration template to use
 * @param underlay_topology underlay topology to create
 * @param va topology-specific options
 * @return handle to the testbed
 */
struct GNUNET_TESTBED_Testbed *
GNUNET_TESTBED_create_va (struct GNUNET_TESTBED_Controller *controller,
				  unsigned int num_hosts,
				  struct GNUNET_TESTBED_Host **hosts,
				  unsigned int num_peers,
				  const struct GNUNET_CONFIGURATION_Handle *peer_cfg,
				  enum GNUNET_TESTBED_TopologyOption underlay_topology,
				  va_list va)
{
  GNUNET_break (0);
  return NULL;
}


/**
 * Configure and run a testbed using the given
 * master controller on 'num_hosts' starting
 * 'num_peers' using the given peer configuration.
 *
 * @param controller master controller for the testbed
 *                   (must not be destroyed until after the
 *                    testbed is destroyed).
 * @param num_hosts number of hosts in 'hosts', 0 to only
 *        use 'localhost'
 * @param hosts list of hosts to use for the testbed
 * @param num_peers number of peers to start
 * @param peer_cfg peer configuration template to use
 * @param underlay_topology underlay topology to create
 * @param ... topology-specific options
 */
struct GNUNET_TESTBED_Testbed *
GNUNET_TESTBED_create (struct GNUNET_TESTBED_Controller *controller,
			       unsigned int num_hosts,
			       struct GNUNET_TESTBED_Host **hosts,
			       unsigned int num_peers,
			       const struct GNUNET_CONFIGURATION_Handle *peer_cfg,
			       enum GNUNET_TESTBED_TopologyOption underlay_topology,
			       ...)
{
  GNUNET_break (0);
  return NULL;
}


/**
 * Destroy a testbed.  Stops all running peers and then
 * destroys all peers.  Does NOT destroy the master controller.
 *
 * @param testbed testbed to destroy
 */
void
GNUNET_TESTBED_destroy (struct GNUNET_TESTBED_Testbed *testbed)
{
  GNUNET_break (0);
}



/**
 * Convenience method for running a testbed with
 * a single call.  Underlay and overlay topology
 * are configured using the "UNDERLAY" and "OVERLAY"
 * options in the "[testbed]" section of the configuration\
 * (with possible options given in "UNDERLAY_XXX" and/or
 * "OVERLAY_XXX").
 *
 * The testbed is to be terminated using a call to
 * "GNUNET_SCHEDULER_shutdown".
 *
 * @param host_filename name of the file with the 'hosts', NULL
 *        to run everything on 'localhost'
 * @param cfg configuration to use (for testbed, controller and peers)
 * @param num_peers number of peers to start; FIXME: maybe put that ALSO into cfg?
 * @param event_mask bit mask with set of events to call 'cc' for;
 *                   or-ed values of "1LL" shifted by the
 *                   respective 'enum GNUNET_TESTBED_EventType'
 *                   (i.e.  "(1LL << GNUNET_TESTBED_ET_CONNECT) || ...")
 * @param cc controller callback to invoke on events
 * @param cc_cls closure for cc
 * @param master task to run once the testbed is ready
 * @param master_cls closure for 'task'.
 */
void
GNUNET_TESTBED_run (const char *host_filename,
			    const struct GNUNET_CONFIGURATION_Handle *cfg,
			    unsigned int num_peers,
			    uint64_t event_mask,
			    GNUNET_TESTBED_ControllerCallback cc,
			    void *cc_cls,
			    GNUNET_SCHEDULER_Task master,
			    void *master_cls)
{
  GNUNET_break (0);
}



/* end of testbed_api_testbed.c */
