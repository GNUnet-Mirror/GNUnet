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
 * @file testbed/testbed_api_topology.c
 * @brief topology-generation functions
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_testbed_service.h"


/**
 * Configure overall network topology to have a particular shape.
 *
 * @param op_cls closure argument to give with the operation event
 * @param num_peers number of peers in 'peers'
 * @param peers array of 'num_peers' with the peers to configure
 * @param topo desired underlay topology to use
 * @param ap topology-specific options
 * @return handle to the operation, NULL if configuring the topology
 *         is not allowed at this time
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_underlay_configure_topology_va (void *op_cls,
					       unsigned int num_peers,
					       struct GNUNET_TESTBED_Peer **peers,
					       enum GNUNET_TESTBED_TopologyOption topo,
					       va_list ap)
{
  GNUNET_break (0);
  return NULL;
}


/**
 * Configure overall network topology to have a particular shape.
 *
 * @param op_cls closure argument to give with the operation event
 * @param num_peers number of peers in 'peers'
 * @param peers array of 'num_peers' with the peers to configure
 * @param topo desired underlay topology to use
 * @param ... topology-specific options
 * @return handle to the operation, NULL if configuring the topology
 *         is not allowed at this time
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_underlay_configure_topology (void *op_cls,
					    unsigned int num_peers,
					    struct GNUNET_TESTBED_Peer **peers,
					    enum GNUNET_TESTBED_TopologyOption topo,
					    ...)
{
  GNUNET_break (0);
  return NULL;
}


/**
 * All peers must have been started before calling this function.
 * This function then connects the given peers in the P2P overlay
 * using the given topology.
 *
 * @param op_cls closure argument to give with the operation event
 * @param num_peers number of peers in 'peers'
 * @param peers array of 'num_peers' with the peers to configure
 * @param topo desired underlay topology to use
 * @param va topology-specific options
 * @return handle to the operation, NULL if connecting these 
 *         peers is fundamentally not possible at this time (peers
 *         not running or underlay disallows)
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_overlay_configure_topology_va (void *op_cls,
					      unsigned int num_peers,
					      struct GNUNET_TESTBED_Peer *peers,
					      enum GNUNET_TESTBED_TopologyOption topo,
					      va_list va)
{
  GNUNET_break (0);
  return NULL;
}


/**
 * All peers must have been started before calling this function.
 * This function then connects the given peers in the P2P overlay
 * using the given topology.
 *
 * @param op_cls closure argument to give with the operation event
 * @param num_peers number of peers in 'peers'
 * @param peers array of 'num_peers' with the peers to configure
 * @param topo desired underlay topology to use
 * @param ... topology-specific options
 * @return handle to the operation, NULL if connecting these 
 *         peers is fundamentally not possible at this time (peers
 *         not running or underlay disallows)
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_overlay_configure_topology (void *op_cls,
					   unsigned int num_peers,
					   struct GNUNET_TESTBED_Peer *peers,
					   enum GNUNET_TESTBED_TopologyOption topo,
					   ...)
{
  GNUNET_break (0);
  return NULL;
}

/* end of testbed_api_topology.c */
