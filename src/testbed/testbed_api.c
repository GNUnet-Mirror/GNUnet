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
 * @file testbed/testbed_api.c
 * @brief API for accessing the GNUnet testing service.
 *        This library is supposed to make it easier to write
 *        testcases and script large-scale benchmarks.
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_testbed_service.h"
#include "gnunet_core_service.h"
#include "gnunet_constants.h"
#include "gnunet_transport_service.h"
#include "gnunet_hello_lib.h"




/**
 * Start a controller process using the given configuration at the
 * given host.
 *
 * @param cfg configuration to use
 * @param host host to run the controller on, NULL for 'localhost'
 * @param event_mask bit mask with set of events to call 'cc' for;
 *                   or-ed values of "1LL" shifted by the
 *                   respective 'enum GNUNET_TESTBED_EventType'
 *                   (i.e.  "(1LL << GNUNET_TESTBED_ET_CONNECT) | ...")
 * @param cc controller callback to invoke on events
 * @param cc_cls closure for cc
 * @return handle to the controller
 */
struct GNUNET_TESTBED_Controller *
GNUNET_TESTBED_controller_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
				 struct GNUNET_TESTBED_Host *host,
				 uint64_t event_mask,
				 GNUNET_TESTBED_ControllerCallback cc,
				 void *cc_cls)
{
  GNUNET_break (0);
  return NULL;
}


/**
 * Configure shared services at a controller.  Using this function,
 * you can specify that certain services (such as "resolver")
 * should not be run for each peer but instead be shared
 * across N peers on the specified host.  This function
 * must be called before any peers are created at the host.
 * 
 * @param controller controller to configure
 * @param service_name name of the service to share
 * @param num_peers number of peers that should share one instance
 *        of the specified service (1 for no sharing is the default),
 *        use 0 to disable the service
 */
void
GNUNET_TESTBED_controller_configure_sharing (struct GNUNET_TESTBED_Controller *controller,
					     const char *service_name,
					     uint32_t num_peers)
{
  GNUNET_break (0);
}


/**
 * Stop the given controller (also will terminate all peers and
 * controllers dependent on this controller).  This function 
 * blocks until the testbed has been fully terminated (!).
 *
 * @param controller handle to controller to stop
 */
void
GNUNET_TESTBED_controller_stop (struct GNUNET_TESTBED_Controller *controller)
{
  GNUNET_break (0);
}


/**
 * Create a link from a 'master' controller to a slave controller.
 * Whenever the master controller is asked to start a peer at the
 * given 'delegated_host', it will delegate the request to the
 * specified slave controller.  Note that the slave controller runs at
 * the 'slave_host', which may or may not be the same host as the
 * 'delegated_host' (for hierarchical delegations).  The configuration
 * of the slave controller is given and to be used to either create
 * the slave controller or to connect to an existing slave controller
 * process.  'is_subordinate' specifies if the given slave controller
 * should be started and managed by the master controller, or if the
 * slave already has a master and this is just a secondary master that
 * is also allowed to use the existing slave.
 *
 * @param master handle to the master controller who creates the association
 * @param delegated_host requests to which host should be delegated
 * @param slave_host which host is used to run the slave controller 
 * @param slave_cfg configuration to use for the slave controller
 * @param is_subordinate GNUNET_YES if the slave should be started (and stopped)
 *                       by the master controller; GNUNET_NO if we are just
 *                       allowed to use the slave via TCP/IP
 */
void
GNUNET_TESTBED_controller_link (struct GNUNET_TESTBED_Controller *master,
				struct GNUNET_TESTBED_Host *delegated_host,
				struct GNUNET_TESTBED_Host *slave_host,
				const struct GNUNET_CONFIGURATION_Handle *slave_cfg,
				int is_subordinate)
{
  GNUNET_break (0);
}


/**
 * Ask the testbed controller to write the current overlay topology to
 * a file.  Naturally, the file will only contain a snapshot as the
 * topology may evolve all the time.
 *
 * @param controller overlay controller to inspect
 * @param filename name of the file the topology should
 *        be written to.
 */
void
GNUNET_TESTBED_overlay_write_topology_to_file (struct GNUNET_TESTBED_Controller *controller,
					       const char *filename)
{
}



/* end of testbed_api.c */
