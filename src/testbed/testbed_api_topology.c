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
#include "testbed_api.h"
#include "testbed_api_peers.h"
#include "testbed_api_operations.h"


/**
 * Representation of an overlay link
 */
struct OverlayLink
{
  /**
   * Peer A
   */
  struct GNUNET_TESTBED_Peer *A;

  /**
   * Peer B
   */
  struct GNUNET_TESTBED_Peer *B;

};


/**
 * Context information for topology operations
 */
struct TopologyContext
{
  /**
   * An array of links
   */
  struct OverlayLink *link_array;
  
};


/**
 * Function called when a overlay connect operation is ready
 *
 * @param cls the closure from GNUNET_TESTBED_operation_create_()
 */
static void
opstart_overlay_configure_topology (void *cls)
{
  GNUNET_break (0);
}


/**
 * Callback which will be called when overlay connect operation is released
 *
 * @param cls the closure from GNUNET_TESTBED_operation_create_()
 */
static void
oprelease_overlay_configure_topology (void *cls)
{
  GNUNET_break (0);
}


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
                                               struct GNUNET_TESTBED_Peer
                                               **peers,
                                               enum
                                               GNUNET_TESTBED_TopologyOption
                                               topo, va_list ap)
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
                                            enum GNUNET_TESTBED_TopologyOption
                                            topo, ...)
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
 *         not running or underlay disallows) or if num_peers is less than 2
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_overlay_configure_topology_va (void *op_cls,
                                              unsigned int num_peers,
                                              struct GNUNET_TESTBED_Peer **peers,
                                              enum GNUNET_TESTBED_TopologyOption
                                              topo, va_list va)
{
  struct OverlayLink *link_array;
  struct GNUNET_TESTBED_Operation *op;
  struct GNUNET_TESTBED_Controller *c;
  unsigned int p;

  if (num_peers < 2)
    return NULL;
  c = peers[0]->controller;
  switch (topo)
  {
  case GNUNET_TESTBED_TOPOLOGY_LINE:
    link_array = GNUNET_malloc (sizeof (struct OverlayLink) * (num_peers - 1));
    for (p=1; p < num_peers; p++)
    {
      link_array[p-1].A = peers[p-1];
      link_array[p-1].B = peers[p];
    }
    break;
  default:
    GNUNET_break (0);
    return NULL;
  }
  op = GNUNET_TESTBED_operation_create_ (link_array,
					 &opstart_overlay_configure_topology,
					 &oprelease_overlay_configure_topology);
  GNUNET_TESTBED_operation_queue_insert_
      (c->opq_parallel_topology_config_operations, op);
  return op;
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
 *         not running or underlay disallows) or if num_peers is less than 2
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_overlay_configure_topology (void *op_cls, unsigned int num_peers,
                                           struct GNUNET_TESTBED_Peer **peers,
                                           enum GNUNET_TESTBED_TopologyOption
                                           topo, ...)
{
  struct GNUNET_TESTBED_Operation *op;
  va_list vargs;

  va_start (vargs, topo);
  op = GNUNET_TESTBED_overlay_configure_topology_va (op_cls, num_peers, peers,
						     topo, vargs);
  va_end (vargs);
  return op;
}

/* end of testbed_api_topology.c */
