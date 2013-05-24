/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file experimentation/gnunet-daemon-experimentation.h
 * @brief experimentation daemon
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_statistics_service.h"


/**
 * Timeout between request and expected response
 */
#define EXP_RESPONSE_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

extern struct GNUNET_STATISTICS_Handle *GSE_stats;

extern struct GNUNET_CONFIGURATION_Handle *GSE_cfg;

extern uint32_t GSE_node_capabilities;

/**
 * Capabilities a node has or an experiment requires
 */
enum GNUNET_EXPERIMENTATION_capabilities
{
	NONE = 0,
	PLUGIN_TCP = 1,
	PLUGIN_UDP = 2,
	PLUGIN_UNIX = 4,
	PLUGIN_HTTP_CLIENT = 8,
	PLUGIN_HTTP_SERVER = 16,
	PLUGIN_HTTPS_CLIENT = 32,
	PLUGIN_HTTPS_SERVER = 64,
	PLUGIN_WLAN = 128,
	HAVE_IPV6 = 256,
	BEHIND_NAT = 512
};


/**
 * A experimentation node
 */
struct Node
{
	/**
	 * Peer id
	 */
	struct GNUNET_PeerIdentity id;

	/**
	 * Task for response timeout
	 */
	GNUNET_SCHEDULER_TaskIdentifier timeout_task;

	/**
	 * Core transmission handle
	 */
	struct GNUNET_CORE_TransmitHandle *cth;

	uint32_t capabilities;
};

/**
 * Experimentation request message
 * Used to detect experimentation capability
 */
struct Experimentation_Request
{
	struct GNUNET_MessageHeader msg;

	uint32_t capabilities;
};

/**
 * Experimentation response message
 * Sent if peer is running the daemon
 */
struct Experimentation_Response
{
	struct GNUNET_MessageHeader msg;

	uint32_t capabilities;
};


/**
 * Start the nodes management
 */
void
GNUNET_EXPERIMENTATION_nodes_start ();


/**
 * Stop the nodes management
 */
void
GNUNET_EXPERIMENTATION_nodes_stop ();


/**
 * Start the detecting capabilities
 */
void
GNUNET_EXPERIMENTATION_capabilities_start ();

/**
 * Stop the detecting capabilities
 */
void
GNUNET_EXPERIMENTATION_capabilities_stop ();


/* end of gnunet-daemon-experimentation.h */
