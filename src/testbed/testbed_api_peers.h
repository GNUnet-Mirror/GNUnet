/*
      This file is part of GNUnet
      Copyright (C) 2008--2013 Christian Grothoff (and other contributing authors)

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
 * @file testbed/testbed_api_peers.h
 * @brief internal API to access the 'peers' subsystem
 * @author Christian Grothoff
 * @author Sree Harsha Totakura
 */

#ifndef NEW_TESTING_API_PEERS_H
#define NEW_TESTING_API_PEERS_H

#include "gnunet_testbed_service.h"
#include "gnunet_helper_lib.h"


/**
 * Enumeration of possible states a peer could be in
 */
enum PeerState
{
    /**
     * State to signify that this peer is invalid
     */
  TESTBED_PS_INVALID,

    /**
     * The peer has been created
     */
  TESTBED_PS_CREATED,

    /**
     * The peer is running
     */
  TESTBED_PS_STARTED,

    /**
     * The peer is stopped
     */
  TESTBED_PS_STOPPED,
};


/**
 * A peer controlled by the testing framework.  A peer runs
 * at a particular host.
 */
struct GNUNET_TESTBED_Peer
{
  /**
   * peer list DLL
   */
  struct GNUNET_TESTBED_Peer *next;

  /**
   * peer list DLL
   */
  struct GNUNET_TESTBED_Peer *prev;

  /**
   * Our controller context (not necessarily the controller
   * that is responsible for starting/running the peer!).
   */
  struct GNUNET_TESTBED_Controller *controller;

  /**
   * Which host does this peer run on?
   */
  struct GNUNET_TESTBED_Host *host;

  /**
   * Globally unique ID of the peer.
   */
  uint32_t unique_id;

  /**
   * Peer's state
   */
  enum PeerState state;

  /**
   * Has an underlay model already set for this peer?
   */
  uint8_t underlay_model_exists;
};


/**
 * Data for the OperationType OP_PEER_CREATE
 */
struct PeerCreateData
{
  /**
   * The host where the peer has to be created
   */
  struct GNUNET_TESTBED_Host *host;

  /**
   * The template configuration of the peer
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * The call back to call when we receive peer create success message
   */
  GNUNET_TESTBED_PeerCreateCallback cb;

  /**
   * The closure for the above callback
   */
  void *cls;

  /**
   * The peer structure to return when we get success message
   */
  struct GNUNET_TESTBED_Peer *peer;

};


/**
 * Data for OperationType OP_PEER_START and OP_PEER_STOP
 */
struct PeerEventData
{
  /**
   * The handle of the peer to start
   */
  struct GNUNET_TESTBED_Peer *peer;

  /**
   * The Peer churn callback to call when this operation is completed
   */
  GNUNET_TESTBED_PeerChurnCallback pcc;

  /**
   * Closure for the above callback
   */
  void *pcc_cls;

};


/**
 * Data for the OperationType OP_PEER_DESTROY;
 */
struct PeerDestroyData
{
  /**
   * The peer structure
   */
  struct GNUNET_TESTBED_Peer *peer;

  //PEERDESTROYDATA
};


/**
 * Data for the OperationType OP_PEER_INFO
 */
struct PeerInfoData
{
  /**
   * The peer whose information has been requested
   */
  struct GNUNET_TESTBED_Peer *peer;

  /**
   * The Peer info callback to call when this operation has completed
   */
  GNUNET_TESTBED_PeerInfoCallback cb;

  /**
   * The closure for peer info callback
   */
  void *cb_cls;

  /**
   * The type of peer information requested
   */
  enum GNUNET_TESTBED_PeerInformationType pit;
};


/**
 * Data for the operations of type OP_PEER_RECONFIGURE
 */
struct PeerReconfigureData
{
  /**
   * The peer whose information has been requested
   */
  struct GNUNET_TESTBED_Peer *peer;

  /**
   * The serialized new configuration template
   */
  char *config;

  /**
   * the size of the serialized configuration
   */
  uint16_t cfg_size;
};


/**
 * Data structure for OperationType OP_OVERLAY_CONNECT
 */
struct OverlayConnectData
{

  /**
   * Peer A to connect to peer B
   */
  struct GNUNET_TESTBED_Peer *p1;

  /**
   * Peer B
   */
  struct GNUNET_TESTBED_Peer *p2;

  /**
   * The operation completion callback to call once this operation is done
   */
  GNUNET_TESTBED_OperationCompletionCallback cb;

  /**
   * The closure for the above callback
   */
  void *cb_cls;

  /**
   * OperationContext for forwarded operations generated when peer1's controller doesn't have the
   * configuration of peer2's controller for linking laterally to attemp an
   * overlay connection between peer 1 and peer 2.
   */
  struct OperationContext *sub_opc;

};


struct ManageServiceData {
  GNUNET_TESTBED_OperationCompletionCallback cb;

  void *cb_cls;

  struct GNUNET_TESTBED_Peer *peer;

  char *service_name;

  unsigned int start;

  uint16_t msize;

};


/**
 * Generate PeerGetConfigurationMessage
 *
 * @param peer_id the id of the peer whose information we have to get
 * @param operation_id the ip of the operation that should be represented in
 *          the message
 * @return the PeerGetConfigurationMessage
 */
struct GNUNET_TESTBED_PeerGetConfigurationMessage *
GNUNET_TESTBED_generate_peergetconfig_msg_ (uint32_t peer_id,
                                            uint64_t operation_id);


/**
 * Adds a peer to the peer list
 *
 * @param peer the peer to add to the peer list
 */
void
GNUNET_TESTBED_peer_register_ (struct GNUNET_TESTBED_Peer *peer);


/**
 * Removes a peer from the peer list
 *
 * @param peer the peer to remove
 */
void
GNUNET_TESTBED_peer_deregister_ (struct GNUNET_TESTBED_Peer *peer);


/**
 * Frees all peers
 */
void
GNUNET_TESTBED_cleanup_peers_ (void);

#endif
/* end of testbed_api_peers.h */
