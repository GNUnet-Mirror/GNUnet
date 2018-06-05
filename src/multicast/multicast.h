/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2013 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
*/

/**
 * @file multicast/multicast.h
 * @brief multicast IPC messages
 * @author Christian Grothoff
 * @author Gabor X Toth
 */
#ifndef MULTICAST_H
#define MULTICAST_H

#include "platform.h"
#include "gnunet_multicast_service.h"

GNUNET_NETWORK_STRUCT_BEGIN


/**
 * Header of a join request sent to the origin or another member.
 */
struct MulticastJoinRequestMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_MULTICAST_JOIN_REQUEST
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero.
   */
  uint32_t reserved;

  /**
   * ECC signature of the rest of the fields of the join request.
   *
   * Signature must match the public key of the joining member.
   */
  struct GNUNET_CRYPTO_EcdsaSignature signature;

  /**
   * Purpose for the signature and size of the signed data.
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * Public key of the target group.
   */
  struct GNUNET_CRYPTO_EddsaPublicKey group_pub_key;

  /**
   * Public key of the joining member.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey member_pub_key;

  /**
   * Peer identity of the joining member.
   */
  struct GNUNET_PeerIdentity peer;

  /* Followed by struct GNUNET_MessageHeader join_message */
};


/**
 * Header of a join decision message sent to a peer requesting join.
 */
struct MulticastJoinDecisionMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_MULTICAST_JOIN_DECISION
   */
  struct GNUNET_MessageHeader header;

  /**
   * #GNUNET_YES    if the peer was admitted
   * #GNUNET_NO     if entry was refused,
   * #GNUNET_SYSERR if the request could not be answered.
   */
  int32_t is_admitted;

  /**
   * Number of relays given.
   */
  uint32_t relay_count;

  /* Followed by relay_count peer identities */

  /* Followed by the join response message */
};


/**
 * Header added to a struct MulticastJoinDecisionMessage
 * when sent between the client and service.
 */
struct MulticastJoinDecisionMessageHeader
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_MULTICAST_JOIN_DECISION
   */
  struct GNUNET_MessageHeader header;

  /**
   * C->S: Peer to send the join decision to.
   * S->C: Peer we received the join decision from.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * C->S: Public key of the member requesting join.
   * S->C: Unused.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey member_pub_key;

  /* Followed by struct MulticastJoinDecisionMessage */
};


/**
 * Message sent from the client to the service to notify the service
 * about the result of a membership test.
 */
struct MulticastMembershipTestResultMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_MULTICAST_MEMBERSHIP_TEST_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique ID that identifies the associated membership test.
   */
  uint32_t uid;

  /**
   * #GNUNET_YES    if the peer is a member
   * #GNUNET_NO     if peer is not a member,
   * #GNUNET_SYSERR if the test could not be answered.
   */
  int32_t is_admitted;
};


/**
 * Message sent from the client to the service OR the service to the
 * client asking for a message fragment to be replayed.
 */
struct MulticastReplayRequestMessage
{

  /**
   * The message type should be
   * #GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_REQUEST.
   */
  struct GNUNET_MessageHeader header;

  /**
   * S->C: Public key of the member requesting replay.
   * C->S: Unused.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey member_pub_key;

  /**
   * ID of the message that is being requested.
   */
  uint64_t fragment_id;

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

  /**
   * Replay request ID.
   */
  uint32_t uid;
};


/**
 * Message sent from the client to the service to give the service
 * a replayed message.
 */
struct MulticastReplayResponseMessage
{

  /**
   * Type: GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_RESPONSE
   *    or GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_RESPONSE_END
   */
  struct GNUNET_MessageHeader header;

  /**
   * ID of the message that is being requested.
   */
  uint64_t fragment_id;

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

  /**
   * An `enum GNUNET_MULTICAST_ReplayErrorCode` identifying issues (in NBO).
   */
  int32_t error_code;

  /* followed by replayed message */
};


/**
 * Message sent from the client to the service to notify the service
 * about the starting of a multicast group with this peers as its origin.
 */
struct MulticastOriginStartMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_MULTICAST_ORIGIN_START
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero.
   */
  uint32_t reserved;

  /**
   * Private, non-ephemeral key for the multicast group.
   */
  struct GNUNET_CRYPTO_EddsaPrivateKey group_key;

  /**
   * Last fragment ID sent to the group, used to continue counting fragments if
   * we resume operating * a group.
   */
  uint64_t max_fragment_id;
};


struct MulticastMemberJoinMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_MULTICAST_MEMBER_JOIN
   */
  struct GNUNET_MessageHeader header;

  uint32_t relay_count GNUNET_PACKED;

  struct GNUNET_CRYPTO_EddsaPublicKey group_pub_key;

  struct GNUNET_CRYPTO_EcdsaPrivateKey member_key;

  struct GNUNET_PeerIdentity origin;

  /* Followed by struct GNUNET_PeerIdentity relays[relay_count] */

  /* Followed by struct GNUNET_MessageHeader join_msg */
};


GNUNET_NETWORK_STRUCT_END

#endif
/* end of multicast.h */
