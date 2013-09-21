/*
     This file is part of GNUnet.
     (C) 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @file multicast/multicast.h
 * @brief multicast IPC messages
 * @author Christian Grothoff
 */
#ifndef MULTICAST_H
#define MULTICAST_H

GNUNET_NETWORK_STRUCT_BEGIN


/**
 * Message sent from the client to the service to notify the service
 * about a join decision.
 */
struct MulticastJoinDecisionMessage
{

  /**
   *
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique ID that identifies the associated join test.
   */
  uint32_t uid;

  /**
   * #GNUNET_YES if the peer was admitted.
   */
  int32_t is_admitted;

  /**
   * Number of relays given.
   */
  uint32_t relay_count;

  /* followed by 'relay_count' peer identities */
  
  /* followed by the join response message */

};


/**
 * Message sent from the client to the service to notify the service
 * about the result of a membership test.
 */
struct MulticastMembershipTestResponseMessage
{

  /**
   *
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique ID that identifies the associated membership test.
   */
  uint32_t uid;

  /**
   * #GNUNET_YES if the peer is a member, #GNUNET_NO if peer was not a member,
   * #GNUNET_SYSERR if we cannot answer the test.
   */
  int32_t is_admitted;

};


/**
 * Message sent from the client to the service to give the service
 * a replayed message.
 */
struct MulticastReplayResponseMessage
{

  /**
   *
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique ID that identifies the associated replay session.
   */
  uint32_t uid;

  /**
   * An `enum GNUNET_MULTICAST_ReplayErrorCode` identifying issues (in NBO).
   */
  int32_t error_code;

  /* followed by replayed message */

};


/**
 * Message sent from the client to the service to notify the service
 * about the end of a replay session.
 */
struct MulticastReplayEndMessage
{

  /**
   *
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique ID that identifies the associated replay session.
   */
  uint32_t uid;

};


/**
 * Message sent from the client to the service to notify the service
 * about the starting of a multicast group with this peers as its origin.
 */
struct MulticastOriginStartMessage
{

  /**
   *
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero.
   */
  uint32_t reserved;

  /**
   * Private, non-ephemeral key for the mutlicast group.
   */
  struct GNUNET_CRYPTO_EccPrivateKey group_key;

  /**
   * Last fragment ID, used to continue counting fragments if we resume operating
   * a group.
   */
  uint64_t last_fragment_id;

};


/**
 * Message sent from the client to the service to broadcast to all group
 * members.
 */
struct MulticastBroadcastMessage
{

  /**
   *
   */
  struct GNUNET_MessageHeader header;

  /**
   * #GNUNET_OK normally, #GNUNET_SYSERR if the origin aborted the
   * transmission.
   */
  int32_t status;

  /**
   * Message ID.
   */
  uint64_t message_id;

  /**
   * Group generation.
   */
  uint64_t group_generation;

  /**
   * Total message size.
   */
  uint64_t total_size;

};


/**
 * Message sent from the client to the service to join a multicast group.
 */
struct MulticastJoinMessage
{

  /**
   *
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of relays we (think) we already know about.
   */
  uint32_t relay_count;

  /**
   * Public non-ephemeral key of the mutlicast group.
   */
  struct GNUNET_CRYPTO_EccPublicSignKey group_key;

  /**
   * Our private key for the group.
   */
  struct GNUNET_CRYPTO_EccPrivateKey member_key;

  /* followed by 'relay_count' `struct GNUNET_PeerIdentity`s */

};



/**
 * Message sent from the client to the service OR the service to the
 * client asking for a message fragment to be replayed.
 */
struct MulticastReplayRequestMessage
{

  /**
   * The message type can be either 
   * #GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_REQUEST or
   * #GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_REQUEST_CANCEL.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Replay request ID.
   */
  uint32_t uid;

  /**
   * ID of the message that is being requested.
   */
  uint64_t message_id;

  /**
   * Offset of the fragment that is being requested.
   */
  uint64_t fragment_offset;

  /**
   * Additional flags for the request.
   */
  uint64_t flags;

};



/**
 * Message sent from the client to the service to unicast to the group origin.
 */
struct MulticastUnicastToOriginMessage
{

  /**
   *
   */
  struct GNUNET_MessageHeader header;

  /**
   * Reserved (always 0).
   */
  uint32_t reserved;

  /**
   * Message ID.
   */
  uint64_t message_id;

  /**
   * Total message size.
   */
  uint64_t total_size;

  /* followed by payload */

};


/**
 * Message sent from the client to the service to
 * cancel unicast to the group origin.
 */
struct MulticastUnicastToOriginCancelMessage
{

  /**
   *
   */
  struct GNUNET_MessageHeader header;

  /**
   * Reserved (always 0).
   */
  uint32_t reserved;

  /**
   * Message ID.
   */
  uint64_t message_id;

};





GNUNET_NETWORK_STRUCT_END

#endif
/* end of multicast.h */
