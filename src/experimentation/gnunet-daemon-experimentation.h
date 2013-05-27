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

/**
 * Default experiment frequency
 */
#define EXP_DEFAULT_EXP_FREQ GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 60)

/**
 * Default experiment duration
 */
#define EXP_DEFAULT_EXP_DUR GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * Statistics handle shared between components
 */
extern struct GNUNET_STATISTICS_Handle *GSE_stats;


/**
 * Configuration handle shared between components
 */
extern struct GNUNET_CONFIGURATION_Handle *GSE_cfg;


/**
 * Capability value shared between components
 */
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
 * Print a single capability value
 *
 * @param cap capability value
 * @return the string to print
 */
const char *
GNUNET_EXPERIMENTATION_capability_to_str (uint32_t cap);


/**
 * Are the capabilities provided?
 *
 * @param have bitstring containing the provided capabilities
 * @param desired bitstring containing the desired capabilities\
 * @return GNUNET_YES or GNUNET_NO
 */
int
GNUNET_EXPERIMENTATION_capabilities_have (uint32_t have, uint32_t desired);


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


/**
 * Start experiments management
 *
 * @return GNUNET_YES or GNUNET_NO
 */
int
GNUNET_EXPERIMENTATION_experiments_issuer_accepted (struct GNUNET_PeerIdentity *issuer_ID);


/**
 * Start experiments management
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_EXPERIMENTATION_experiments_start ();


/**
 * Stop experiments management
 */
void
GNUNET_EXPERIMENTATION_experiments_stop ();


/**
 * Start the scheduler component
 */
void
GNUNET_EXPERIMENTATION_scheduler_start ();


/**
 * Stop the scheduler component
 */
void
GNUNET_EXPERIMENTATION_scheduler_stop ();


/**
 * Start the storage component
 */
void
GNUNET_EXPERIMENTATION_storage_start ();



/**
 * Stop the storage component
 */
void
GNUNET_EXPERIMENTATION_storage_stop ();


/* end of gnunet-daemon-experimentation.h */
