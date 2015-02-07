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
 * @file testbed/testbed.h
 * @brief IPC messages between testing API and service ("controller")
 * @author Christian Grothoff
 */

#ifndef TESTBED_H
#define TESTBED_H

#include "gnunet_util_lib.h"

GNUNET_NETWORK_STRUCT_BEGIN
/**
 * Initial message from a client to a testing control service.
 */
struct GNUNET_TESTBED_InitMessage
{

  /**
   * Type is #GNUNET_MESSAGE_TYPE_TESTBED_INIT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Host ID that the controller is either given (if this is the
   * dominating client) or assumed to have (for peer-connections
   * between controllers).  A controller must check that all
   * connections make consistent claims...
   */
  uint32_t host_id GNUNET_PACKED;

  /**
   * Event mask that specifies which events this client
   * is interested in.  In NBO.
   */
  uint64_t event_mask GNUNET_PACKED;

  /* Followed by 0-terminated hostname of the controller */
};


/**
 * Notify the service about a host that we intend to use.
 */
struct GNUNET_TESTBED_AddHostMessage
{

  /**
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_ADD_HOST
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique ID for the host (in NBO).
   */
  uint32_t host_id GNUNET_PACKED;

  /**
   * SSH port to use, 0 for default (in NBO).
   */
  uint16_t ssh_port GNUNET_PACKED;

  /**
   * Number of bytes in the user name that follows;
   * 0 to use no user name; otherwise 'strlen (username)',
   * excluding 0-termination!
   */
  uint16_t username_length GNUNET_PACKED;

  /**
   * Number of bytes in the host name (excluding 0-termination) that follows the
   * user name; cannot be 0
   */
  uint16_t hostname_length GNUNET_PACKED;

  /**
   * The length of the uncompressed configuration
   */
  uint16_t config_size GNUNET_PACKED;

  /* followed by non 0-terminated user name */

  /* followed by non 0-terminated host name */

  /* followed by gzip compressed configuration to start or connect to a
     controller on this host.  While starting the controller this configration
     is used as a template */

};


/**
 * Confirmation from the service that adding a host
 * worked (or failed).
 * FIXME: Where is this required?
 */
struct GNUNET_TESTBED_HostConfirmedMessage
{

  /**
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_ADD_HOST_SUCCESS
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique ID for the host (in NBO).
   */
  uint32_t host_id GNUNET_PACKED;

  /* followed by the 0-terminated error message (on failure)
   * (typical errors include host-id already in use) */

};


/**
 * Client notifies controller that it should delegate
 * requests for a particular client to a particular
 * sub-controller.
 */
struct GNUNET_TESTBED_ControllerLinkRequest
{

  /**
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_LINK_CONTROLLERS
   */
  struct GNUNET_MessageHeader header;

  /**
   * For which host should requests be delegated? NBO.
   */
  uint32_t delegated_host_id GNUNET_PACKED;

  /**
   * The id of the operation which created this message
   */
  uint64_t operation_id GNUNET_PACKED;

  /**
   * Which host is responsible for managing the delegation? NBO
   */
  uint32_t slave_host_id GNUNET_PACKED;

  /**
   * Set to 1 if the receiving controller is the master controller for
   * the slave host (and thus responsible for starting it?). 0 if not
   */
  uint8_t is_subordinate;

};


/**
 * Response message for ControllerLinkRequest message
 */
struct GNUNET_TESTBED_ControllerLinkResponse
{

  /**
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_LINK_CONTROLLERS_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * The size of the compressed configuration. Can be ZERO if the controller is
   * not started (depends on the ControllerLinkRequest). NBO.
   */
  uint16_t config_size GNUNET_PACKED;

  /**
   * Set to GNUNET_YES to signify SUCCESS; GNUNET_NO to signify failure
   */
  uint16_t success GNUNET_PACKED;

  /**
   * The id of the operation which created this message. NBO
   */
  uint64_t operation_id GNUNET_PACKED;

  /* If controller linking is successful and configuration is present, then here
   * comes the serialized gzip configuration with which the controller is
   * running at the delegate host */

  /* In case of failure, here comes the error message (without \0 termination)*/

};


/**
 * Message sent from client to testing service to
 * create (configure, but not start) a peer.
 */
struct GNUNET_TESTBED_PeerCreateMessage
{

  /**
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_CREATE_PEER
   */
  struct GNUNET_MessageHeader header;

  /**
   * On which host should the peer be started?
   */
  uint32_t host_id GNUNET_PACKED;

  /**
   * Unique operation id
   */
  uint64_t operation_id GNUNET_PACKED;

  /**
   * Unique ID for the peer.
   */
  uint32_t peer_id GNUNET_PACKED;

  /**
   * Size of the uncompressed configuration
   */
  uint16_t config_size GNUNET_PACKED;

  /* followed by serialized peer configuration;
   * gzip'ed configuration file in INI format */

};


/**
 * Message sent from client to testing service to
 * reconfigure a (stopped) a peer.
 */
struct GNUNET_TESTBED_PeerReconfigureMessage
{

  /**
   * Type is #GNUNET_MESSAGE_TYPE_TESTBED_RECONFIGURE_PEER
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique ID for the peer.
   */
  uint32_t peer_id GNUNET_PACKED;

  /**
   * Operation ID that is used to identify this operation.
   */
  uint64_t operation_id GNUNET_PACKED;

  /**
   * The length of the serialized configuration when uncompressed
   */
  uint16_t config_size GNUNET_PACKED;

  /* followed by serialized peer configuration;
   * gzip'ed configuration file in INI format */

};


/**
 * Message sent from client to testing service to
 * start a peer.
 */
struct GNUNET_TESTBED_PeerStartMessage
{

  /**
   * Type is #GNUNET_MESSAGE_TYPE_TESTBED_START_PEER
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique ID for the peer.
   */
  uint32_t peer_id GNUNET_PACKED;

  /**
   * Operation ID that is used to identify this operation.
   */
  uint64_t operation_id GNUNET_PACKED;

};


/**
 * Message sent from client to testing service to
 * stop a peer.
 */
struct GNUNET_TESTBED_PeerStopMessage
{

  /**
   * Type is #GNUNET_MESSAGE_TYPE_TESTBED_STOP_PEER
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique ID for the peer.
   */
  uint32_t peer_id GNUNET_PACKED;

  /**
   * Operation ID that is used to identify this operation.
   */
  uint64_t operation_id GNUNET_PACKED;

};


/**
 * Message sent from client to testing service to
 * destroy a (stopped) peer.
 */
struct GNUNET_TESTBED_PeerDestroyMessage
{

  /**
   * Type is #GNUNET_MESSAGE_TYPE_TESTBED_DESTROY_PEER
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique ID for the peer.
   */
  uint32_t peer_id GNUNET_PACKED;

  /**
   * Operation ID that is used to identify this operation.
   */
  uint64_t operation_id GNUNET_PACKED;

};


/**
 * Message sent from client to testing service to
 * (re)configure a "physical" link between two peers.
 */
struct GNUNET_TESTBED_ConfigureUnderlayLinkMessage
{

  /**
   * Type is #GNUNET_MESSAGE_TYPE_TESTBED_CONFIGURE_UNDERLAY_LINK
   */
  struct GNUNET_MessageHeader header;

  /**
   * 'enum GNUNET_TESTBED_ConnectOption' of the option to change
   */
  int32_t connect_option GNUNET_PACKED;

  /**
   * Unique ID for the first peer.
   */
  uint32_t peer1 GNUNET_PACKED;

  /**
   * Unique ID for the second peer.
   */
  uint32_t peer2 GNUNET_PACKED;

  /**
   * Operation ID that is used to identify this operation.
   */
  uint64_t operation_id GNUNET_PACKED;

  /* followed by option-dependent variable-size values */

};


/**
 * Message sent from client to testing service to
 * connect two peers.
 */
struct GNUNET_TESTBED_OverlayConnectMessage
{

  /**
   * Type is #GNUNET_MESSAGE_TYPE_TESTBED_OVERLAY_CONNECT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique ID for the first peer.
   */
  uint32_t peer1 GNUNET_PACKED;

  /**
   * Operation ID that is used to identify this operation.
   */
  uint64_t operation_id GNUNET_PACKED;

  /**
   * Unique ID for the second peer.
   */
  uint32_t peer2 GNUNET_PACKED;

  /**
   * The ID of the host which runs peer2
   */
  uint32_t peer2_host_id GNUNET_PACKED;

};


/**
 * Message sent from host controller of a peer(A) to the host controller of
 * another peer(B) to request B to connect to A
 */
struct GNUNET_TESTBED_RemoteOverlayConnectMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_TESTBED_REMOTE_OVERLAY_CONNECT
   */
  struct GNUNET_MessageHeader header;

  /**
   * The Unique ID of B
   */
  uint32_t peer GNUNET_PACKED;

  /**
   * The Operation ID that is used to identify this operation
   */
  uint64_t operation_id GNUNET_PACKED;

  /**
   * Identity of A
   */
  struct GNUNET_PeerIdentity peer_identity;

  /**
   * To be followed by the HELLO message of A
   */
  struct GNUNET_MessageHeader hello[0];
  // FIXME: we usually do not use this gcc-hack as some
  // compilers / tools really get messed up by it...

};


/**
 * Event notification from a controller to a client.
 */
struct GNUNET_TESTBED_PeerEventMessage
{

  /**
   * Type is #GNUNET_MESSAGE_TYPE_TESTBED_PEER_EVENT
   */
  struct GNUNET_MessageHeader header;

  /**
   * `enum GNUNET_TESTBED_EventType` (in NBO);
   * either #GNUNET_TESTBED_ET_PEER_START or #GNUNET_TESTBED_ET_PEER_STOP.
   */
  int32_t event_type GNUNET_PACKED;

  /**
   * Host where the peer is running.
   */
  uint32_t host_id GNUNET_PACKED;

  /**
   * Peer that was started or stopped.
   */
  uint32_t peer_id GNUNET_PACKED;

  /**
   * Operation ID that is used to identify this operation.
   */
  uint64_t operation_id GNUNET_PACKED;

};


/**
 * Event notification from a controller to a client.
 */
struct GNUNET_TESTBED_ConnectionEventMessage
{

  /**
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_PEER_CONNECT_EVENT
   */
  struct GNUNET_MessageHeader header;

  /**
   * 'enum GNUNET_TESTBED_EventType' (in NBO);
   * either GNUNET_TESTBED_ET_CONNECT or GNUNET_TESTBED_ET_DISCONNECT.
   */
  int32_t event_type GNUNET_PACKED;

  /**
   * First peer.
   */
  uint32_t peer1 GNUNET_PACKED;

  /**
   * Second peer.
   */
  uint32_t peer2 GNUNET_PACKED;

  /**
   * Operation ID that is used to identify this operation.
   */
  uint64_t operation_id GNUNET_PACKED;

};


/**
 * Event notification from a controller to a client.
 */
struct GNUNET_TESTBED_OperationFailureEventMessage
{

  /**
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_OPERATION_FAIL_EVENT
   */
  struct GNUNET_MessageHeader header;

  /**
   * 'enum GNUNET_TESTBED_EventType' (in NBO);
   * GNUNET_TESTBED_ET_OPERATION_FINISHED.
   */
  int32_t event_type GNUNET_PACKED;

  /**
   * Operation ID of the operation that created this event.
   */
  uint64_t operation_id GNUNET_PACKED;

  /* followed by 0-terminated error message */

};


/**
 * Event notification from a controller to a client.
 */
struct GNUNET_TESTBED_PeerCreateSuccessEventMessage
{

  /**
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_CREATE_PEER_SUCCESS
   */
  struct GNUNET_MessageHeader header;

  /**
   * Peer identity of the peer that was created.
   */
  uint32_t peer_id GNUNET_PACKED;

  /**
   * Operation ID of the operation that created this event.
   */
  uint64_t operation_id GNUNET_PACKED;

};


/**
 * Event notification from a controller to a client for
 * a generic operational success where the operation does
 * not return any data.
 */
struct GNUNET_TESTBED_GenericOperationSuccessEventMessage
{

  /**
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_GENERIC_OPERATION_SUCCESS
   */
  struct GNUNET_MessageHeader header;

  /**
   * 'enum GNUNET_TESTBED_EventType' (in NBO);
   * GNUNET_TESTBED_ET_OPERATION_FINISHED.
   */
  int32_t event_type GNUNET_PACKED;

  /**
   * Operation ID of the operation that created this event.
   */
  uint64_t operation_id GNUNET_PACKED;

};


/**
 * Message sent from client to testing service to
 * obtain the configuration of a peer.
 */
struct GNUNET_TESTBED_PeerGetConfigurationMessage
{

  /**
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_GET_PEER_INFORMATION
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique ID for the peer.
   */
  uint32_t peer_id GNUNET_PACKED;

  /**
   * Operation ID that is used to identify this operation.
   */
  uint64_t operation_id GNUNET_PACKED;

};


/**
 * Peer configuration and identity reply from controller to a client.
 */
struct GNUNET_TESTBED_PeerConfigurationInformationMessage
{

  /**
   * Type is #GNUNET_MESSAGE_TYPE_TESTBED_PEER_INFORMATION
   */
  struct GNUNET_MessageHeader header;

  /**
   * The id of the peer relevant to this information
   */
  uint32_t peer_id GNUNET_PACKED;

  /**
   * Operation ID of the operation that created this event.
   */
  uint64_t operation_id GNUNET_PACKED;

  /**
   * Identity of the peer.
   */
  struct GNUNET_PeerIdentity peer_identity;

  /**
   * The size of configuration when uncompressed
   */
  uint16_t config_size GNUNET_PACKED;

  /* followed by gzip-compressed configuration of the peer */

};


/**
 * Message to request configuration of a slave controller
 */
struct GNUNET_TESTBED_SlaveGetConfigurationMessage
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_GET_SLAVE_CONFIGURATION
   */
  struct GNUNET_MessageHeader header;

  /**
   * The id of the slave host
   */
  uint32_t slave_id GNUNET_PACKED;

  /**
   * Operation ID
   */
  uint64_t operation_id GNUNET_PACKED;

};


/**
 * Reply to #GNUNET_MESSAGE_TYPE_TESTBED_GET_SLAVE_CONFIGURATION message
 */
struct GNUNET_TESTBED_SlaveConfiguration
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_SLAVE_CONFIGURATION
   */
  struct GNUNET_MessageHeader header;

  /**
   * The id of the host where the slave is running
   */
  uint32_t slave_id GNUNET_PACKED;

  /**
   * Operation ID
   */
  uint64_t operation_id GNUNET_PACKED;

  /**
   * The size of the configuration when uncompressed
   */
  uint16_t config_size GNUNET_PACKED;

  /* followed by gzip-compressed configuration of the peer */

};


/**
 * Shutdown peers message
 */
struct GNUNET_TESTBED_ShutdownPeersMessage
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_SHUTDOWN_PEERS
   */
  struct GNUNET_MessageHeader header;

  /**
   * Operation ID
   */
  uint64_t operation_id GNUNET_PACKED;
};


/**
 * Message to start/stop services of a peer
 */
struct GNUNET_TESTBED_ManagePeerServiceMessage
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_SHUTDOWN_PEERS
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique ID of the peer whose service has to be managed.
   */
  uint32_t peer_id GNUNET_PACKED;

  /**
   * Operation ID
   */
  uint64_t operation_id GNUNET_PACKED;

  /**
   * set this to 1 to start the service; 0 to stop the service
   */
  uint8_t start;

  /**
   * The NULL-terminated name of the service to start/stop follows here
   */
};


/**
 * Message to send underlay link model of a peer.  This message will be
 * forwarded to the controller running the peer.
 */
struct GNUNET_TESTBED_UnderlayLinkModelMsg
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_UNDERLAYLINKMODELMSG
   */
  struct GNUNET_MessageHeader header;

  /**
   * The number of peer entries contained in this message
   */
  uint32_t nentries GNUNET_PACKED;

  /**
   * The number of link properties contained in this message
   */
  uint32_t nprops GNUNET_PACKED;

  /**
   * Array of ids of peers to be in the blacklist/whitelist.  Each id is of type
   * uint32_t.  Number of ids should be equal to nentries.
   */

  /**
   * Array of link properties.  Each link property is to be arraged in a
   * sequence of four integers of type uint32_t: peer_id, latency, loss and
   * bandwidth.
   */

};


/**************************************/
/* Barriers IPC messages and protocol */
/**************************************/


/**
 * The environmental variable which when available refers to the configuration
 * file the local testbed controller is using
 */
#define ENV_TESTBED_CONFIG "GNUNET_TESTBED_CONTROLLER_CONFIG"


/**
 * Message to initialise a barrier
 */
struct GNUNET_TESTBED_BarrierInit
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_INIT
   */
  struct GNUNET_MessageHeader header;

  /**
   * The quorum percentage needed for crossing the barrier
   */
  uint8_t quorum;

  /**
   * name of the barrier.  Non NULL-terminated.
   */
  char name[0];
};


/**
 * Message to cancel a barrier
 */
struct GNUNET_TESTBED_BarrierCancel
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_CANCEL
   */
  struct GNUNET_MessageHeader header;

  /**
   * The barrier name.  Non NULL terminated
   */
  char name[0];
};


/**
 * Message for signalling status changes of a barrier
 */
struct GNUNET_TESTBED_BarrierStatusMsg
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_STATUS
   */
  struct GNUNET_MessageHeader header;

  /**
   * status.  Use enumerated values of enum BarrierStatus
   */
  uint16_t status GNUNET_PACKED;

  /**
   * strlen of the barrier name
   */
  uint16_t name_len GNUNET_PACKED;

  /**
   * the barrier name (NULL terminated) concatenated with an error message (NULL
   * terminated) if the status were to indicate an error
   */
  char data[0];
};


/**
 * Message sent from peers to the testbed-barrier service to indicate that they
 * have reached a barrier and are waiting for it to be crossed
 */
struct GNUNET_TESTBED_BarrierWait
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_WAIT
   */
  struct GNUNET_MessageHeader header;

  /**
   * The name of the barrier they have reached.  Non-NULL terminated.
   */
  char name[0];
};


GNUNET_NETWORK_STRUCT_END
#endif
/* end of testbed.h */
