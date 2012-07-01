/*
      This file is part of GNUnet
      (C) 2012 Christian Grothoff (and other contributing authors)

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

#ifndef NEW_TESTING_H
#define NEW_TESTING_H

#include "gnunet_util_lib.h"


/**
 * Initial message from a client to a testing control service.
 */
struct GNUNET_TESTBED_InitMessage
{

  /**
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_INIT
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
};


/**
 * Notify the service about a host that we intend to use.
 */
struct GNUNET_TESTBED_AddHostMessage
{

  /**
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_ADDHOST
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
  uint16_t user_name_length GNUNET_PACKED;

  /* followed by 0-terminated user name */

  /* followed by 0-terminated host name */

};


/**
 * Confirmation from the service that adding a host
 * worked (or failed).
 * FIXME: Where is this required?
 */
struct GNUNET_TESTBED_HostConfirmedMessage
{

  /**
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_ADDHOSTSUCCESS
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique ID for the host (in NBO).
   */
  uint32_t host_id GNUNET_PACKED;

  /* followed by the 0-terminated error message (on failure) 
   (typical errors include failure to login and 
   host-id already in use) */

};


/**
 * Message to testing service: configure service sharing
 * at a host.
 */
struct GNUNET_TESTBED_ConfigureSharedServiceMessage
{

  /**
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_SERVICESHARE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Host that is being configured.
   */
  uint32_t host_id GNUNET_PACKED;

  /**
   * Number of peers that should share a service instance;
   * 1 for no sharing, 0 to forcefully disable the service.
   */
  uint32_t num_peers GNUNET_PACKED;

  /* followed by 0-terminated name of the service */

};


/**
 * Client notifies controller that it should delegate
 * requests for a particular client to a particular
 * sub-controller.
 */
struct GNUNET_TESTBED_ControllerLinkMessage
{

  /**
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_LCONTROLLERS
   */
  struct GNUNET_MessageHeader header;

  /**
   * For which host should requests be delegated? NBO.
   */
  uint32_t delegated_host_id GNUNET_PACKED;

  /**
   * Which host is responsible for managing the delegation? NBO
   */
  uint32_t slave_host_id GNUNET_PACKED;

  /**
   * The size of the uncompressed configuration
   */
  uint16_t config_size GNUNET_PACKED;

  /**
   * Set to 1 if the receiving controller is the master controller for
   * the slave host (and thus responsible for starting it?). 0 if not
   */
  uint8_t is_subordinate;

  /* followed by serialized slave configuration;
     gzip'ed configuration file in INI format */

};


/**
 * Message sent from client to testing service to 
 * create (configure, but not start) a peer.
 */
struct GNUNET_TESTBED_PeerCreateMessage
{

  /**
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_CREATEPEER
   */
  struct GNUNET_MessageHeader header;

  /**
   * On which host should the peer be started?
   */
  uint32_t host_id GNUNET_PACKED;

  /**
   * Unique ID for the peer.
   */
  uint32_t peer_id GNUNET_PACKED;

  /* followed by serialized peer configuration;
     gzip'ed configuration file in INI format */
  
};


/**
 * Message sent from client to testing service to 
 * reconfigure a (stopped) a peer.
 */
struct GNUNET_TESTBED_PeerReconfigureMessage
{

  /**
   * Type is GNUNET_MESSAGE_TYPDE_TESTBED_PEERRECONF
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

  /* followed by serialized peer configuration;
     gzip'ed configuration file in INI format */
  
};


/**
 * Message sent from client to testing service to
 * start a peer.
 */
struct GNUNET_TESTBED_PeerStartMessage
{

  /**
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_STARTPEER
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
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_STOPPEER
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
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_DESTROYPEER
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
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_CONFIGULLINK
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
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_OLCONNECT
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

};


/**
 * Event notification from a controller to a client.
 */
struct GNUNET_TESTBED_PeerEventMessage
{

  /**
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_PEEREVENT
   */
  struct GNUNET_MessageHeader header;

  /**
   * 'enum GNUNET_TESTBED_EventType' (in NBO);
   * either GNUNET_TESTBED_ET_PEER_START or GNUNET_TESTBED_ET_PEER_STOP.
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
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_PEERCONEVENT
   */
  struct GNUNET_MessageHeader header;

  /**
   * 'enum GNUNET_TESTBED_EventType' (in NBO);
   * either GNUNET_TESTBED_ET_PEER_CONNECT or GNUNET_TESTBED_ET_PEER_DISCONNECT.
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
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_OPERATIONEVENT
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
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_PEERCREATESUCCESS
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
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_GENERICOPSUCCESS
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
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_GETPEERCONFIG
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
 * Event notification from a controller to a client.
 */
struct GNUNET_TESTBED_PeerConfigurationInformationMessage
{

  /**
   * Type is GNUNET_MESSAGE_TYPE_TESTBED_PEERCONFIG
   */
  struct GNUNET_MessageHeader header;

  /**
   * Peer number of the peer that was created.
   */
  uint32_t peer_number GNUNET_PACKED;
  
  /**
   * Operation ID of the operation that created this event.
   */
  uint64_t operation_id GNUNET_PACKED;

  /**
   * Identity of the peer.
   */
  struct GNUNET_PeerIdentity peer_id;

  /* followed by gzip-compressed configuration of the peer */

};

#endif
