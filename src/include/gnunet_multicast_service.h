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
 * @file include/gnunet_multicast_service.h
 * @brief multicast service; establish tunnels to distant peers
 * @author Christian Grothoff
 */

#ifndef GNUNET_MULTICAST_SERVICE_H
#define GNUNET_MULTICAST_SERVICE_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"
#include "gnunet_transport_service.h"

/**
 * Version number of GNUnet-multicast API.
 */
#define GNUNET_MULTICAST_VERSION 0x00000000


/**
 * Opaque handle for a multicast group member.
 */
struct GNUNET_MULTICAST_Member;

/**
 * Handle for the origin of a multicast group.
 */
struct GNUNET_MULTICAST_Origin;

/**
 * Group membership policies.
 */
enum GNUNET_MULTICAST_JoinPolicy
{
  /**
   * Anyone can join the group, without announcing his presence; all
   * messages are always public and can be distributed freely.  Joins
   * may be announced, but this is not required.
   */
  GNUNET_MULTICAST_JP_ANONYMOUS = 0,

  /**
   * Origin must approve membership to the group, messages must only be
   * distributed to current group members.  This includes the group
   * state as well as transient messages.
   */
  GNUNET_MULTICAST_JP_PRIVATE = 1

#if IDEAS_FOR_FUTURE
  /**
   * Anyone can freely join the group (no approval required); however,
   * transient messages must only be distributed to current group
   * members, so the origin must still acknowledge that the member
   * joined before transient messages are delivered.  As approval is
   * guaranteed, the presistent group state can de synchronized freely
   * immediately, prior to origin confirmation
   */
  GNUNET_MULTICAST_JP_OPEN = 2
#endif

};


/**
 * Opaque handle to a replay request from the multicast service.
 */
struct GNUNET_MULTICAST_ReplayHandle;


/**
 * Functions with this signature are called whenever the multicast
 * service needs a message to be replayed.  Implementations of this
 * function MUST call 'GNUNET_MULTICAST_replay' ONCE (with a message
 * or an error); however, if the origin is destroyed or the group is
 * left, the replay handle must no longer be used.
 *
 * @param cls closure (set from GNUNET_MULTICAST_origin_start/join)
 * @param message_id which message should be replayed
 * @param rh handle to pass to message transmit function
 */
typedef void (*GNUNET_MULTICAST_ReplayCallback) (void *cls,
						 uint64_t message_id,
						 struct GNUNET_MULTICAST_ReplayHandle *rh);


/**
 * Possible error codes during replay.
 */
enum GNUNET_MULTICAST_ReplayErrorCode
{
  
  /**
   * Everything is fine.
   */ 
  GNUNET_MULTICAST_REC_OK = 0,

  /**
   * Message has been discarded (likely transient message that was too old).
   */ 
  GNUNET_MULTICAST_REC_TRANSIENT_LOST = 1,

  /**
   * Message ID counter was larger than the highest counter this
   * replay function has ever encountered; thus it is likely the
   * origin never sent it and we're at the HEAD of the multicast
   * stream as far as this node is concerned.
   */ 
  GNUNET_MULTICAST_REC_PAST_HEAD = 2,

  /**
   * Internal error (i.e. database error).  Try some other peer.
   */ 
  GNUNET_MULTICAST_REC_INTERNAL_ERROR = 3

};


/**
 * Header of a multicast message.  This format is public as the replay
 * mechanism must replay messages using the same format.
 */
struct GNUNET_MULTICAST_MessageHeader
{

  /**
   * Header for all multicast messages from the origin.
   */
  struct GNUNET_MessageHeader header;

  /**
   * How many hops has this message taken since the origin?
   * (helpful to determine shortest paths to the origin for responses
   *  among honest peers; updated at each hop and thus not signed
   *  and not secure)
   */
  uint32_t hop_counter;

  /**
   * ECC signature of the message.
   */
  struct GNUNET_CRYPTO_EccSignature signature;

  /**
   * Signature of the multicast message.
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * Number of the message, monotonically increasing.
   */
  uint64_t message_id;

  /**
   * Counter that monotonically increases whenever a member
   * leaves the group.
   */
  uint64_t group_generation;

  /**
   * Difference between the current message_id and the message_id of
   * the preceeding non-transient message.  Zero for transient
   * messages, UINT64_MAX for the first message, or any other message
   * creating a full state reset by the origin.  By subtracting
   * 'state_delta' from 'message_id', it is possible to calculate the
   * message ID of the preceeding non-transient message and thus
   * quickly traverse all state changes up to the last full state
   * reset by the origin.  This is useful as it allows joining clients
   * to quickly reassemble the state while skipping over transient
   * messages (and doing so without having to trust intermediaries to
   * do it right, as the indices in the chain are signed).  If the
   * state chain is getting too long, the origin can choose to
   * originate a state message with a state_delta of UINT64_MAX,
   * thereby starting a new chain.  The origin will then have to
   * re-create the full state with state update messages following the
   * state reset message.
   */
  uint64_t state_delta;

  /**
   * Header for the message body.  Three message types are
   * specifically understood by multicast, namely "peer join", "peer
   * leave", and "group terminated".  Multicast will use those
   * messages to update its list of candidates for content
   * distribution.  All other message types are application-specific.
   */
  struct GNUNET_MessageHeader body;

  /* followed by message body */
};


/**
 * Replay a message from the multicast group.
 *
 * @param rh replay handle identifying which replay operation was requested
 * @param msg replayed message, NULL if unknown/error
 * @param ec error code
 */
void
GNUNET_MULTICAST_replay (struct GNUNET_MULTICAST_ReplayHandle *rh,
			 const struct GNUNET_MULTICAST_MessageHeader *msg,
			 enum GNUNET_MULTICAST_ReplayErrorCode ec);


/**
 * Method called whenever another peer wants to join or has left a 
 * multicast group.
 *
 * @param cls closure
 * @param peer identity of the peer that wants to join or leave
 * @param is_joining GNUNET_YES if the peer wants to join, GNUNET_NO if the peer left
 * @return GNUNET_OK if joining is approved, GNUNET_SYSERR if it is disapproved;
 *         GNUNET_NO should be returned for peers leaving 
 */
typedef int (*GNUNET_MULTICAST_MembershipChangeCallback)(void *cls,
							 const struct GNUNET_PeerIdentity *peer,
							 int is_joining);


/**
 * Method called to test if a member was in the group at a particular time.
 *
 * @param cls closure
 * @param peer identity of the peer that we want to test
 * @param message_id message ID for which we want to do the test
 * @param group_generation the generation of the group for which we want to do the test
 * @return GNUNET_YES if peer was a member, GNUNET_NO if peer was not a member,
 *         GNUNET_SYSERR if we cannot answer the membership test
 */
typedef int (*GNUNET_MULTICAST_MembershipTestCallback)(void *cls,
						       const struct GNUNET_PeerIdentity *peer,
						       uint64_t message_id,
						       uint64_t group_generation);


/**
 * Function called whenever a group member has transmitted a message
 * to the origin (other than joining or leaving).
 *
 * @param cls closure (set from GNUNET_MULTICAST_origin_start)
 * @param sender identity of the sender
 * @param response_id unique counter for the response from this sender to this origin
 * @param msg message to the origin
 */
typedef void (*GNUNET_MULTICAST_ResponseCallback) (void *cls,
						   const struct GNUNET_PeerIdentity *sender,
						   uint64_t response_id,
						   const struct GNUNET_MessageHeader *msg);


/**
 * Function called whenever a group member is receiving a message from
 * the origin.
 *
 * @param cls closure (set from GNUNET_MULTICAST_member_join)
 * @param msg message from the origin, NULL if the origin shut down
 *        (or we were kicked out, and we should thus call GNUNET_MULTICAST_member_leave next)
 */
typedef void (*GNUNET_MULTICAST_MessageCallback) (void *cls,
						  const struct GNUNET_MULTICAST_MessageHeader *msg);


/**
 * Start a multicast group.
 *
 * @param cfg configuration to use
 * @param cls closure for the various callbacks that follow
 * @param priv_key ECC key that will be used to sign messages for this
 *                 multicast session; public key is used to identify the
 *                 multicast group; FIXME: we'll likely want to use
 *                 NOT the p521 curve here, but a cheaper one in the future
 * @param join_policy what is the membership policy of the group?
 * @param replay_cb function that can be called to replay a message
 * @param test_cb function multicast can use to test group membership
 * @param join_cb function called to approve / disapprove joining of a peer
 * @param response_cb function called with messages from group members
 * @return handle for the origin, NULL on error 
 */
struct GNUNET_MULTICAST_Origin *
GNUNET_MULTICAST_origin_start (const struct GNUNET_CONFIGURATION_Handle *cfg, 
			       void *cls,
			       struct GNUNET_CRYPTO_EccPrivateKey *priv_key,
			       enum GNUNET_MULTICAST_JoinPolicy join_policy,
			       GNUNET_MULITCAST_ReplayCallback replay_cb,
			       GNUNET_MULITCAST_MembershipTestCallback test_cb,
			       GNUNET_MULTICAST_MembershipChangeCallback join_cb,
			       GNUNET_MULTICAST_ResponseCallback response_cb);


/**
 * Send a message to the multicast group.
 *
 * @param origin handle to the multicast group
 * @param msg_body body of the message to transmit
 */
void
GNUNET_MULTICAST_origin_send_to_all (struct GNUNET_MULTICAST_Origin *origin,
				     const struct GNUNET_MessageHeader *msg_body);


/**
 * End a multicast group.
 *
 * @param origin multicast group to terminate
 */
void
GNUNET_MULTICAST_origin_end (struct GNUNET_MULTICAST_Origin *origin);


/**
 * Join a multicast group.
 *
 * @param cfg configuration to use
 * @param cls closure for callbacks
 * @param pub_key ECC key that identifies the group
 * @param max_known_message_id largest known message ID to the replay service;
 *        all messages with IDs larger than this ID will be replayed if
 *        possible (lower IDs will be considered known and thus only
 *        be replayed upon explicit request)
 * @param max_known_state_message_id largest known message ID with a non-zero
 *                       value for the 'state_delta'; state messages with
 *        larger IDs than this value will be replayed with high priority
 *        (lower IDs will be considered known and thus only
 *        be replayed upon explicit request)
 * @param replay_cb function that can be called to replay messages
 *        this peer already knows from this group; NULL if this
 *        client is unable to support replay
 * @param test_cb function multicast can use to test group membership
 * @param message_cb function to be called for all messages we 
 *        receive from the group, excluding those our replay_cb
 *        already has
 * FIXME: need some argument(s) to identify the joining member (key pair to 
 *        bind user identity/pseudonym to peer identity, application-level
 *        message to origin, etc.)
 * @return handle for the member, NULL on error 
 */
struct GNUNET_MULTICAST_Member *
GNUNET_MULTICAST_member_join (const struct GNUNET_CONFIGURATION_Handle *cfg, 
			      void *cls,
			      struct GNUNET_CRYPTO_EccPublicKey *pub_key,
			      uint64_t max_known_message_id,
			      uint64_t max_known_state_message_id,
			      GNUNET_MULTICAST_ReplayCallback replay_cb,
			      GNUNET_MULITCAST_MembershipTestCallback test_cb,
			      GNUNET_MULTICAST_MessageCallback message_cb);


/**
 * Request a message to be replayed.  Useful if messages below
 * the 'max_known_*_id's given when joining are needed and not
 * known to the client.
 *
 * @param member membership handle
 * @param message_id ID of a message that this client would like to see replayed
 */
void
GNUNET_MULTICAST_member_request_replay (struct GNUNET_MULTICAST_Member *member,
					uint64_t message_id);


/**
 * Leave a mutlicast group.
 *
 * @param member membership handle
 */
void
GNUNET_MULTICAST_member_leave (struct GNUNET_MULTICAST_Member *member);


/**
 * Send a message to the origin of the multicast group.  FIXME: how
 * will we do routing/flow-control of responses?
 * 
 * @param member membership handle
 * @param msg message to send to the origin
 * FIXME: change to notify_transmit_ready-style to wait for ACKs...
 */
void
GNUNET_MULTICAST_member_respond_to_origin (struct GNUNET_MULTICAST_Member *member,
					   const struct GNUNET_MessageHeader *msg);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_MULTICAST_SERVICE_H */
#endif
/* end of gnunet_multicast_service.h */
