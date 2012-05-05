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
 * @file testbed/testbed_api_peers.c
 * @brief management of the knowledge about peers in this library
 *        (we know the peer ID, its host, pending operations, etc.)
 * @author Christian Grothoff
 */
#include "platform.h"
#include "testbed_api_peers.h"


/**
 * Details about a peer; kept in a separate struct to avoid bloating
 * memory consumption everywhere...
 */
struct PeerDetails
{
  /**
   * Configuration of the peer; NULL if we are not sure what the peer's correct
   * configuration actually is; non-NULL if this peer is controlled by this
   * process.
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * If this process has started this peer's ARM process, this is the handle
   * to the 'gnunet-service-arm' process of the peer.
   */
  struct GNUNET_OS_Process *arm;
  
  // ...

};


/**
 * A peer controlled by the testing framework.  A peer runs
 * at a particular host.
 */ 
struct GNUNET_TESTBED_Peer
{
  /**
   * Our controller context (not necessarily the controller
   * that is responsible for starting/running the peer!).
   */
  struct GNUNET_TESTBED_Controller *controller;
			   
  /**
   * Which host does this peer run on?
   */
  struct GNUENT_TESTING_Host *host;

  /**
   * Globally unique ID of the peer.
   */
  uint32_t unique_id;

  /**
   * Internals of the peer for the controlling process; NULL if 
   * this process is not controlling this peer.
   */
  struct PeerDetails *details;

};


/**
 * Lookup a peer by ID.
 * 
 * @param id global peer ID assigned to the peer
 * @return handle to the host, NULL on error
 */
struct GNUNET_TESTBED_Peer *
GNUNET_TESTBED_peer_lookup_by_id_ (uint32_t id)
{
  GNUNET_break (0);
  return NULL;
}


/**
 * Create the given peer at the specified host using the given
 * controller.  If the given controller is not running on the target
 * host, it should find or create a controller at the target host and
 * delegate creating the peer.  Explicit delegation paths can be setup
 * using 'GNUNET_TESTBED_controller_link'.  If no explicit delegation
 * path exists, a direct link with a subordinate controller is setup
 * for the first delegated peer to a particular host; the subordinate
 * controller is then destroyed once the last peer that was delegated
 * to the remote host is stopped.  This function is used in particular
 * if some other controller has already assigned a unique ID to the
 * peer.
 *
 * Creating the peer only creates the handle to manipulate and further
 * configure the peer; use "GNUNET_TESTBED_peer_start" and
 * "GNUNET_TESTBED_peer_stop" to actually start/stop the peer's
 * processes.
 *
 * Note that the given configuration will be adjusted by the
 * controller to avoid port/path conflicts with other peers.
 * The "final" configuration can be obtained using
 * 'GNUNET_TESTBED_peer_get_information'.
 *
 * @param unique_id unique ID for this peer
 * @param controller controller process to use
 * @param host host to run the peer on
 * @param cfg configuration to use for the peer
 * @return handle to the peer (actual startup will happen asynchronously)
 */
struct GNUNET_TESTBED_Peer *
GNUNET_TESTBED_peer_create_with_id_ (uint32_t unique_id,				     
				     struct GNUNET_TESTBED_Controller *controller,				     
				     struct GNUNET_TESTBED_Host *host,
				     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  // FIXME: create locally or delegate...
  GNUNET_break (0);
  return NULL;  
}


/**
 * Create the given peer at the specified host using the given
 * controller.  If the given controller is not running on the target
 * host, it should find or create a controller at the target host and
 * delegate creating the peer.  Explicit delegation paths can be setup
 * using 'GNUNET_TESTBED_controller_link'.  If no explicit delegation
 * path exists, a direct link with a subordinate controller is setup
 * for the first delegated peer to a particular host; the subordinate
 * controller is then destroyed once the last peer that was delegated
 * to the remote host is stopped.
 *
 * Creating the peer only creates the handle to manipulate and further
 * configure the peer; use "GNUNET_TESTBED_peer_start" and
 * "GNUNET_TESTBED_peer_stop" to actually start/stop the peer's
 * processes.
 *
 * Note that the given configuration will be adjusted by the
 * controller to avoid port/path conflicts with other peers.
 * The "final" configuration can be obtained using
 * 'GNUNET_TESTBED_peer_get_information'.
 *
 * @param controller controller process to use
 * @param host host to run the peer on
 * @param cfg configuration to use for the peer
 * @return handle to the peer (actual startup will happen asynchronously)
 */
struct GNUNET_TESTBED_Peer *
GNUNET_TESTBED_peer_create (struct GNUNET_TESTBED_Controller *controller,
			    struct GNUNET_TESTBED_Host *host,
			    const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  static uint32_t id_gen;

  return GNUNET_TESTBED_peer_create_with_id_ (++id_gen,
					      controller,
					      host,
					      cfg);
}


/**
 * Start the given peer.
 *
 * @param peer peer to start
 * @return handle to the operation
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_peer_start (struct GNUNET_TESTBED_Peer *peer)
{
  // FIXME: start locally or delegate...
  GNUNET_break (0);
  return NULL;
}


/**
 * Stop the given peer.  The handle remains valid (use
 * "GNUNET_TESTBED_peer_destroy" to fully clean up the 
 * state of the peer).
 *
 * @param peer peer to stop
 * @return handle to the operation
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_peer_stop (struct GNUNET_TESTBED_Peer *peer)
{
  // FIXME: stop locally or delegate...
  GNUNET_break (0);
  return NULL;
}


/**
 * Request information about a peer.
 *
 * @param peer peer to request information about
 * @param pit desired information
 * @return handle to the operation
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_peer_get_information (struct GNUNET_TESTBED_Peer *peer,
				     enum GNUNET_TESTBED_PeerInformationType pit)
{
  // FIXME: handle locally or delegate...
  GNUNET_break (0);
  return NULL;
}


/**
 * Change peer configuration.  Must only be called while the
 * peer is stopped.  Ports and paths cannot be changed this
 * way.
 *
 * @param peer peer to change configuration for
 * @param cfg new configuration (differences to existing
 *            configuration only)
 * @return handle to the operation
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_peer_update_configuration (struct GNUNET_TESTBED_Peer *peer,
					  const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  // FIXME: handle locally or delegate...
  GNUNET_break (0);
  return NULL;
}


/**
 * Manipulate the P2P underlay topology by configuring a link
 * between two peers.  
 *
 * @param op_cls closure argument to give with the operation event
 * @param p1 first peer
 * @param p2 second peer
 * @param co option to change
 * @param ... option-specific values
 * @return handle to the operation, NULL if configuring the link at this
 *         time is not allowed
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_underlay_configure_link (void *op_cls,
					struct GNUNET_TESTBED_Peer *p1,
					struct GNUNET_TESTBED_Peer *p2,
					enum GNUNET_TESTBED_ConnectOption co, ...)
{
  GNUNET_break (0);
  return NULL;
}



/**
 * Both peers must have been started before calling this function.
 * This function then obtains a HELLO from 'p1', gives it to 'p2'
 * and asks 'p2' to connect to 'p1'.
 *
 * @param op_cls closure argument to give with the operation event
 * @param p1 first peer
 * @param p2 second peer
 * @return handle to the operation, NULL if connecting these two
 *         peers is fundamentally not possible at this time (peers
 *         not running or underlay disallows)
 */
struct GNUNET_TESTBED_Operation *
GNUNET_TESTBED_overlay_connect (void *op_cls,
				struct GNUNET_TESTBED_Peer *p1,
				struct GNUNET_TESTBED_Peer *p2)
{
  GNUNET_break (0);
  return NULL;
}



/* end of testbed_api_peers.c */
