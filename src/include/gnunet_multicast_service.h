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
 * @author Gabor X Toth
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
   * Anyone can join the group, without announcing his presence;
   * all messages are always public and can be distributed freely.
   * Joins may be announced, but this is not required.
   */
  GNUNET_MULTICAST_JP_ANONYMOUS = 0,

  /** 
   * Origin must approve membership to the group, messages must only be
   * distributed to current group members.  This includes the group
   * state as well as transient messages.
   */
  GNUNET_MULTICAST_JP_PRIVATE = 1,

#if IDEAS_FOR_FUTURE
  /** 
   * Anyone can freely join the group (no approval required); however,
   * transient messages must only be distributed to current group
   * members, so the origin must still acknowledge that the member
   * joined before transient messages are delivered.  As approval is
   * guaranteed, the presistent group state can be synchronized freely
   * immediately, prior to origin confirmation.
   */
  GNUNET_MULTICAST_JP_OPEN = 2,

  /**
   * Origin must approve membership to the group, but past messages can be
   * freely distributed to members.
   */
  GNUNET_MULTICAST_JP_CLOSED = 3,
#endif

};

enum GNUNET_MULTICAST_MessageFlags
{
  /**
   * First fragment of a message.
   */
  GNUNET_MULTICAST_MESSAGE_FIRST_FRAGMENT = 1 << 0,

  /**
   * Last fragment of a message.
   */
  GNUNET_MULTICAST_MESSAGE_LAST_FRAGMENT = 1 << 1,

  /** 
   * OR'ed flags if message is not fragmented.
   */
  GNUNET_MULTICAST_MESSAGE_NOT_FRAGMENTED
    = GNUNET_MULTICAST_MESSAGE_FIRST_FRAGMENT
    | GNUNET_MULTICAST_MESSAGE_LAST_FRAGMENT
};


GNUNET_NETWORK_STRUCT_BEGIN

/** 
 * Header of a multicast message fragment.
 *
 * This format is public as the replay mechanism must replay message fragments using the
 * same format.  This is needed as we want to integrity-check message fragments within
 * the multicast layer to avoid multicasting mal-formed messages.
 */
struct GNUNET_MULTICAST_MessageHeader
{

  /** 
   * Header for all multicast message fragments from the origin.
   */
  struct GNUNET_MessageHeader header;

  /** 
   * Number of hops this message fragment has taken since the origin.
   *
   * Helpful to determine shortest paths to the origin for responses among
   * honest peers; updated at each hop and thus not signed and not secure.
   */
  uint32_t hop_counter GNUNET_PACKED;

  /** 
   * ECC signature of the message fragment.
   *
   * Signature must match the public key of the multicast group.
   */
  struct GNUNET_CRYPTO_EccSignature signature;

  /** 
   * Signature of the multicast message fragment.
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /** 
   * Number of the message fragment, monotonically increasing.
   */
  uint64_t fragment_id GNUNET_PACKED;

  /** 
   * Number of the message this fragment belongs to.
   */
  uint64_t message_id GNUNET_PACKED;

  /** 
   * Byte offset of this @e fragment of the @e message.
   */
  uint64_t fragment_offset GNUNET_PACKED;

  /** 
   * Counter that monotonically increases whenever a member parts the group.
   *
   * It has significance in case of replay requests: when a member has missed
   * messages and gets a replay request: in this case if the @a group_generation
   * is still the same before and after the missed messages, it means that no
   * @e join or @e part operations happened during the missed messages.
   */
  uint64_t group_generation GNUNET_PACKED;

  /** 
   * Difference between the current @a fragment_id and the @a fragment_id of the
   * preceeding non-transient message.
   * 
   * Zero for transient messages, @c UINT64_MAX for the first message, or any
   * other message creating a full state reset by the origin.  By subtracting
   * @a state_delta from @a fragment_id, it is possible to calculate the message
   * ID of the preceeding non-transient message and thus quickly traverse all
   * state changes up to the last full state reset by the origin.  This is
   * useful as it allows joining clients to quickly reassemble the state while
   * skipping over transient messages (and doing so without having to trust
   * intermediaries to do it right, as the indices in the chain are signed).  If
   * the state chain is getting too long, the origin can choose to originate a
   * state message with a state_delta of UINT64_MAX, thereby starting a new
   * chain.  The origin will then have to re-create the full state with state
   * update messages following the state reset message.
   *
   * Open question: needed in multicast, or just have this in PSYC; still might
   * be useful for selective fetching of messages.  Still, that again should
   * that not be done by PSYC?
   */
  uint64_t state_delta GNUNET_PACKED;

  /**
   * Flags for this message.
   */
  enum GNUNET_MULTICAST_MessageFlags flags GNUNET_PACKED;

  /** 
   * Header for the message body.
   *
   * Three message types are specifically understood by multicast, namely "peer
   * join", "peer part", and "group terminated".  Multicast will use those
   * messages to update its list of candidates for content distribution.  All
   * other message types are application-specific.
   */
  struct GNUNET_MessageHeader body;

  /* Followed by message body. */
};

GNUNET_NETWORK_STRUCT_END

GNUNET_NETWORK_STRUCT_BEGIN

/** 
 * Header of a request from a member to the origin.
 *
 * This format is public as the replay mechanism must replay message fragments using the
 * same format.  This is needed as we want to integrity-check message fragments within
 * the multicast layer to avoid multicasting mal-formed messages.
 */
struct GNUNET_MULTICAST_RequestHeader
{

  /** 
   * Header for all requests from a member to the origin.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Flags for this request.
   */
  enum GNUNET_MULTICAST_MessageFlags flags GNUNET_PACKED;

  /** 
   * Header for the request body.
   *
   * Two request types are specifically understood by multicast, namely "peer
   * join", "peer part".  Multicast will use those messages to update its list
   * of candidates for content distribution.  All other message types are
   * application-specific.
   */
  struct GNUNET_MessageHeader body;

  /* Followed by request body. */
};

GNUNET_NETWORK_STRUCT_END


/** 
 * Handle that identifies a join request.
 *
 * Used to match calls to #GNUNET_MULTICAST_JoinCallback to the
 * corresponding calls to GNUNET_MULTICAST_join_decision().
 */
struct GNUNET_MULTICAST_JoinHandle;

/** 
 * Handle that identifies a part request.
 *
 * Used to match calls to #GNUNET_MULTICAST_PartCallback to the
 * corresponding calls to GNUNET_MULTICAST_part_ack().
 */
struct GNUNET_MULTICAST_PartHandle;


/** 
 * Function to call with the decision made for a join request.
 *
 * Must be called once and only once in response to an invocation of the
 * #GNUNET_MULTICAST_JoinCallback.
 *
 * @param jh Join request handle.
 * @param join_response Message to send in response to the joining peer;
 *        can also be used to redirect the peer to a different group at the
 *        application layer; this response is to be transmitted to the
 *        peer that issued the request even if admission is denied.
 * @param is_admitted #GNUNET_YES if joining is approved,
 *        #GNUNET_NO if it is disapproved
 * @param relay_count Number of relays given.
 * @param relays Array of suggested peers that might be useful relays to use
 *        when joining the multicast group (essentially a list of peers that
 *        are already part of the multicast group and might thus be willing
 *        to help with routing).  If empty, only this local peer (which must
 *        be the multicast origin) is a good candidate for building the
 *        multicast tree.  Note that it is unnecessary to specify our own
 *        peer identity in this array.
 */
void
GNUNET_MULTICAST_join_decision (struct GNUNET_MULTICAST_JoinHandle *jh,
                                const struct GNUNET_MessageHeader *join_response,
                                int is_admitted,
                                unsigned int relay_count,
                                const struct GNUNET_PeerIdentity *relays);


/** 
 * Part acknowledgment.
 *
 * @param ph Part handle.
 */
void
GNUNET_MULTICAST_part_ack (struct GNUNET_MULTICAST_PartHandle *ph);


/** 
 * Method called whenever another peer wants to join the multicast group.
 *
 * Implementations of this function must call GNUNET_MULTICAST_join_decision()
 * with the decision.
 *
 * @param cls Closure.
 * @param peer Identity of the peer that wants to join.
 * @param msg Application-dependent join message from the new user
 *        (might, for example, contain a user,
 *        bind user identity/pseudonym to peer identity, application-level
 *        message to origin, etc.).
 * @param jh Join handle to pass to GNUNET_MULTICAST_join_decison().
 */
typedef void (*GNUNET_MULTICAST_JoinCallback)(void *cls,
                                              const struct GNUNET_PeerIdentity *peer,
                                              const struct GNUNET_MessageHeader *msg,
                                              struct GNUNET_MULTICAST_JoinHandle *jh);


/** 
 * Method called whenever another peer wants to part the multicast group.
 *
 * A part request must always be honoured, and answered with GNUNET_MULTICAST_part_ack();
 *
 * @param cls Closure.
 * @param peer Identity of the peer that wants to part.
 * @param msg Application-dependent part message from the leaving user.
 * @param ph Part handle.
 */
typedef void (*GNUNET_MULTICAST_PartCallback)(void *cls,
                                              const struct GNUNET_PeerIdentity *peer,
                                              const struct GNUNET_MessageHeader *msg,
                                              struct GNUNET_MULTICAST_PartHandle *ph);


/** 
 * Handle to pass back for the answer of a membership test.
 */
struct GNUNET_MULTICAST_MembershipTestHandle;


/** 
 * Call informing multicast about the decision taken for membership test.
 *
 * @param mth Handle that was given for the query.
 * @param decision #GNUNET_YES if peer was a member, #GNUNET_NO if peer was not a member,
 *         #GNUNET_SYSERR if we cannot answer the membership test.
 */
void
GNUNET_MULTICAST_membership_test_answer (struct GNUNET_MULTICAST_MembershipTestHandle *mth,
					 int decision);


/** 
 * Method called to test if a member was in the group at a particular time.
 *
 * It is called when a replay request is received to determine if the requested
 * message can be replayed.
 *
 * @param cls Closure.
 * @param peer Identity of the peer that we want to test.
 * @param fragment_id Message fragment ID for which we want to do the test.
 * @param mth Handle to give to GNUNET_MULTICAST_membership_test_answer().
 */
typedef void (*GNUNET_MULTICAST_MembershipTestCallback)(void *cls,
							const struct GNUNET_PeerIdentity *peer,
							uint64_t fragment_id,
							struct GNUNET_MULTICAST_MembershipTestHandle *mth);


/** 
 * Function called whenever a group member has transmitted a request
 * to the origin (other than joining or leaving).
 *
 * @param cls Closure (set from GNUNET_MULTICAST_origin_start).
 * @param sender Identity of the sender.
 * @param req Request to the origin.
 */
typedef void (*GNUNET_MULTICAST_RequestCallback) (void *cls,
                                                  const struct GNUNET_PeerIdentity *sender,
                                                  const struct GNUNET_MULTICAST_RequestHeader *req);


/** 
 * Function called whenever a group member is receiving a message fragment from
 * the origin.
 *
 * If admission to the group is denied, this function is called once with the
 * response of the @e origin (as given to GNUNET_MULTICAST_join_decision()) and
 * then a second time with NULL to indicate that the connection failed for good.
 *
 * @param cls Closure (set from GNUNET_MULTICAST_member_join())
 * @param msg Message from the origin, NULL if the origin shut down
 *        (or we were kicked out, and we should thus call
 *        GNUNET_MULTICAST_member_part() next)
 */
typedef void (*GNUNET_MULTICAST_MessageCallback) (void *cls,
                                                  const struct GNUNET_MULTICAST_MessageHeader *msg);


/** 
 * Opaque handle to a replay request from the multicast service.
 */
struct GNUNET_MULTICAST_ReplayHandle;


/** 
 * Functions with this signature are called whenever the multicast service needs
 * a message to be replayed.
 *
 * Implementations of this function MUST call GNUNET_MULTICAST_replay() ONCE
 * (with a message or an error); however, if the origin is destroyed or the
 * group is left, the replay handle must no longer be used.
 *
 * @param cls Closure (set from GNUNET_MULTICAST_origin_start()
 *            or GNUNET_MULTICAST_member_join()).
 * @param fragment_id Which message fragment should be replayed.
 * @param rh Handle to pass to message transmit function.
 */
typedef void (*GNUNET_MULTICAST_ReplayCallback) (void *cls,
						 uint64_t fragment_id,
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
   * Message fragment has been discarded (likely transient message that was too old).
   */
  GNUNET_MULTICAST_REC_TRANSIENT_LOST = 1,

  /** 
   * Fragment ID counter was larger than the highest counter this
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
 * Replay a message from the multicast group.
 *
 * @param rh Replay handle identifying which replay operation was requested.
 * @param msg Replayed message fragment, NULL if unknown/error.
 * @param ec Error code.
 */
void
GNUNET_MULTICAST_replay (struct GNUNET_MULTICAST_ReplayHandle *rh,
			 const struct GNUNET_MULTICAST_MessageHeader *msg,
			 enum GNUNET_MULTICAST_ReplayErrorCode ec);


/** 
 * Start a multicast group.
 *
 * Will advertise the origin in the P2P overlay network under the respective
 * public key so that other peer can find this peer to join it.  Peers that
 * issue GNUNET_MULTICAST_member_join() can then transmit a join request to
 * either an existing group member (if the @a join_policy is permissive) or to
 * the origin.  If the joining is approved, the member is cleared for @e replay
 * and will begin to receive messages transmitted to the group.  If joining is
 * disapproved, the failed candidate will be given a response.  Members in the
 * group can send messages to the origin (one at a time).
 *
 * @param cfg Configuration to use.
 * @param cls Closure for the various callbacks that follow.
 * @param priv_key ECC key that will be used to sign messages for this
 *                 multicast session; public key is used to identify the
 *                 multicast group; FIXME: we'll likely want to use
 *                 NOT the p521 curve here, but a cheaper one in the future.
 * @param join_policy What is the membership policy of the group?
 * @param replay_cb Function that can be called to replay a message.
 * @param test_cb Function multicast can use to test group membership.
 * @param join_cb Function called to approve / disapprove joining of a peer.
 * @param part_cb Function called when a member wants to part the group.
 * @param request_cb Function called with messages from group members.
 * @return Handle for the origin, NULL on error.
 */
struct GNUNET_MULTICAST_Origin *
GNUNET_MULTICAST_origin_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
			       void *cls,
			       const struct GNUNET_CRYPTO_EccPrivateKey *priv_key,
			       enum GNUNET_MULTICAST_JoinPolicy join_policy,
			       GNUNET_MULITCAST_ReplayCallback replay_cb,
			       GNUNET_MULITCAST_MembershipTestCallback test_cb,
			       GNUNET_MULTICAST_JoinCallback join_cb,
			       GNUNET_MULTICAST_PartCallback part_cb,
			       GNUNET_MULTICAST_RequestCallback request_cb);


/** 
 * Handle for a request to send a message to all multicast group members
 * (from the origin).
 */
struct GNUNET_MULTICAST_OriginMessageHandle;


/** 
 * Send a message to the multicast group.
 *
 * @param origin Handle to the multicast group.
 * @param size Number of bytes to transmit.
 * @param cb Function to call to get the message.
 * @param cb_cls Closure for @a cb.
 * @return NULL on error (i.e. request already pending).
 */
struct GNUNET_MULTICAST_OriginMessageHandle *
GNUNET_MULTICAST_origin_to_all (struct GNUNET_MULTICAST_Origin *origin,
				size_t size,
				GNUNET_CONNECTION_TransmitReadyNotify cb,
				void *cb_cls);


/** 
 * Cancel request for message transmission to multicast group.
 *
 * @param mh Request to cancel.
 */
void
GNUNET_MULTICAST_origin_to_all_cancel (struct GNUNET_MULTICAST_OriginMessageHandle *mh);


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
 * The entity joining is always the local peer.  Further information about the
 * candidate can be provided in the @a join_req message.  If the join fails, the
 * @a message_cb is invoked with a (failure) response and then with NULL.  If
 * the join succeeds, outstanding (state) messages and ongoing multicast
 * messages will be given to the @a message_cb until the member decides to part
 * the group.  The @a test_cb and @a replay_cb functions may be called at
 * anytime by the multicast service to support relaying messages to other
 * members of the group.
 *
 * @param cfg Configuration to use.
 * @param pub_key ECC key that identifies the group.
 * @param origin Peer identity of the origin.
 * @param max_known_fragment_id Largest known message fragment ID to the replay
          service; all messages with IDs larger than this ID will be replayed if
 *        possible (lower IDs will be considered known and thus only
 *        be replayed upon explicit request).
 * @param max_known_state_fragment_id Largest known message fragment ID with a
          non-zero value for the @e state_delta; state messages with
 *        larger IDs than this value will be replayed with high priority
 *        (lower IDs will be considered known and thus only
 *        be replayed upon explicit request).
 * @param replay_cb Function that can be called to replay messages
 *        this peer already knows from this group; NULL if this
 *        client is unable to support replay.
 * @param test_cb Function multicast can use to test group membership.
 * @param message_cb Function to be called for all message fragments we
 *        receive from the group, excluding those our @a replay_cb
 *        already has.
 * @param cls Closure for callbacks.
 * @param join_req Application-dependent join message to be passed to origin
 *        (might, for example, contain a user
 *        bind user identity/pseudonym to peer identity, application-level
 *        message to origin, etc.).
 * @return Handle for the member, NULL on error.
 */
struct GNUNET_MULTICAST_Member *
GNUNET_MULTICAST_member_join (const struct GNUNET_CONFIGURATION_Handle *cfg,
			      const struct GNUNET_CRYPTO_EccPublicKey *pub_key,
                              const struct GNUNET_PeerIdentity *origin,
			      uint64_t max_known_fragment_id,
			      uint64_t max_known_state_fragment_id,
			      GNUNET_MULTICAST_ReplayCallback replay_cb,
			      GNUNET_MULITCAST_MembershipTestCallback test_cb,
			      GNUNET_MULTICAST_MessageCallback message_cb,
			      void *cls,
			      const struct GNUNET_MessageHeader *join_req);


/** 
 * Handle for a replay request.
 */
struct GNUNET_MULTICAST_MemberReplayHandle;


/** 
 * Request a message to be replayed.
 *
 * Useful if messages below the @e max_known_*_id's given when joining are
 * needed and not known to the client.
 *
 * @param member Membership handle.
 * @param fragment_id ID of a message fragment that this client would like to see replayed.
 * @param message_cb Function to be called for the replayed message.
 * @param message_cb_cls Closure for @a message_cb.
 * @return Replay request handle, NULL on error.
 */
struct GNUNET_MULTICAST_MemberReplayHandle *
GNUNET_MULTICAST_member_request_replay (struct GNUNET_MULTICAST_Member *member,
					uint64_t fragment_id,
					GNUNET_MULTICAST_MessageCallback message_cb,
					void *message_cb_cls);


/** 
 * Cancel a replay request.
 *
 * @param rh Request to cancel.
 */
void
GNUNET_MULTICAST_member_request_replay_cancel (struct GNUNET_MULTICAST_MemberReplayHandle *rh);


/** 
 * Part a multicast group.
 *
 * @param member Membership handle.
 */
void
GNUNET_MULTICAST_member_part (struct GNUNET_MULTICAST_Member *member);


/** 
 * Handle for a message to be delivered from a member to the origin.
 */
struct GNUNET_MULTICAST_MemberRequestHandle;


/** 
 * Send a message to the origin of the multicast group.
 * 
 * @param member Membership handle.
 * @param size Number of bytes we want to send to origin.
 * @param cb Callback to call to get the message.
 * @param cb_cls Closure for @a cb.
 * @return Handle to cancel request, NULL on error (i.e. request already pending).
 */
struct GNUNET_MULTICAST_MemberRequestHandle *
GNUNET_MULTICAST_member_to_origin (struct GNUNET_MULTICAST_Member *member,
				   size_t size,
				   GNUNET_CONNECTION_TransmitReadyNotify cb,
				   void *cb_cls);


/** 
 * Cancel request for message transmission to origin.
 *
 * @param rh Request to cancel.
 */
void
GNUNET_MULTICAST_member_to_origin_cancel (struct GNUNET_MULTICAST_MemberRequestHandle *rh);



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_MULTICAST_SERVICE_H */
#endif
/* end of gnunet_multicast_service.h */
