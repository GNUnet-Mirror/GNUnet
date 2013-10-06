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
 * Maximum size of a multicast message fragment.
 */
#define GNUNET_MULTICAST_FRAGMENT_MAX_SIZE 63 * 1024

/**
 * Opaque handle for a multicast group member.
 */
struct GNUNET_MULTICAST_Member;

/**
 * Handle for the origin of a multicast group.
 */
struct GNUNET_MULTICAST_Origin;


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
   * Helpful to determine shortest paths to the origin among honest peers for
   * unicast requests from members.  Updated at each hop and thus not signed and
   * not secure.
   */
  uint32_t hop_counter GNUNET_PACKED;

  /**
   * ECC signature of the message fragment.
   *
   * Signature must match the public key of the multicast group.
   */
  struct GNUNET_CRYPTO_EccSignature signature;

  /**
   * Purpose for the signature and size of the signed data.
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * Number of the message fragment, monotonically increasing.
   */
  uint64_t fragment_id GNUNET_PACKED;

  /**
   * Byte offset of this @e fragment of the @e message.
   */
  uint64_t fragment_offset GNUNET_PACKED;

  /**
   * Number of the message this fragment belongs to.
   *
   * Set in GNUNET_MULTICAST_origin_to_all().
   */
  uint64_t message_id GNUNET_PACKED;

  /**
   * Counter that monotonically increases whenever a member parts the group.
   *
   * Set in GNUNET_MULTICAST_origin_to_all().
   *
   * It has significance in case of replay requests: when a member has missed
   * messages and gets a replay request: in this case if the @a group_generation
   * is still the same before and after the missed messages, it means that no
   * @e join or @e part operations happened during the missed messages.
   */
  uint64_t group_generation GNUNET_PACKED;

  /**
   * Flags for this message fragment.
   */
  uint32_t flags GNUNET_PACKED;

  /* Followed by message body. */
};

GNUNET_NETWORK_STRUCT_END


/**
 * Handle that identifies a join request.
 *
 * Used to match calls to #GNUNET_MULTICAST_JoinCallback to the
 * corresponding calls to #GNUNET_MULTICAST_join_decision().
 */
struct GNUNET_MULTICAST_JoinHandle;


/**
 * Function to call with the decision made for a join request.
 *
 * Must be called once and only once in response to an invocation of the
 * #GNUNET_MULTICAST_JoinCallback.
 *
 * @param jh Join request handle.
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
 * @param join_response Message to send in response to the joining peer;
 *        can also be used to redirect the peer to a different group at the
 *        application layer; this response is to be transmitted to the
 *        peer that issued the request even if admission is denied.
 */
struct GNUNET_MULTICAST_ReplayHandle *
GNUNET_MULTICAST_join_decision (struct GNUNET_MULTICAST_JoinHandle *jh,
                                int is_admitted,
                                unsigned int relay_count,
                                const struct GNUNET_PeerIdentity *relays,
                                const struct GNUNET_MessageHeader *join_response);


/**
 * Method called whenever another peer wants to join the multicast group.
 *
 * Implementations of this function must call GNUNET_MULTICAST_join_decision()
 * with the decision.
 *
 * @param cls Closure.
 * @param peer Identity of the member that wants to join.
 * @param join_req Application-dependent join message from the new member
 *        (might, for example, contain a user,
 *        bind user identity/pseudonym to peer identity, application-level
 *        message to origin, etc.).
 * @param jh Join handle to pass to GNUNET_MULTICAST_join_decison().
 */
typedef void
(*GNUNET_MULTICAST_JoinCallback) (void *cls,
                                  const struct GNUNET_CRYPTO_EccPublicSignKey *member_key,
                                  const struct GNUNET_MessageHeader *join_req,
                                  struct GNUNET_MULTICAST_JoinHandle *jh);


/**
 * Handle to pass back for the answer of a membership test.
 */
struct GNUNET_MULTICAST_MembershipTestHandle;


/**
 * Call informing multicast about the decision taken for a membership test.
 *
 * @param mth Handle that was given for the query.
 * @param result #GNUNET_YES if peer was a member, #GNUNET_NO if peer was not a member,
 *        #GNUNET_SYSERR if we cannot answer the membership test.
 */
void
GNUNET_MULTICAST_membership_test_result (struct GNUNET_MULTICAST_MembershipTestHandle *mth,
                                         int result);


/**
 * Method called to test if a member was in the group at a particular time.
 *
 * It is called when a replay request is received to determine if the requested
 * message can be replayed.
 *
 * @param cls Closure.
 * @param member_key Identity of the member that we want to test.
 * @param message_id Message ID for which to perform the test.
 * @param group_generation Group generation of the message. It has relevance if
 *        the message consists of multiple fragments with different group
 *        generations.
 * @param mth Handle to give to GNUNET_MULTICAST_membership_test_answer().
 */
typedef void
(*GNUNET_MULTICAST_MembershipTestCallback) (void *cls,
                                            const struct GNUNET_CRYPTO_EccPublicSignKey *member_key,
                                            uint64_t message_id,
                                            uint64_t group_generation,
                                            struct GNUNET_MULTICAST_MembershipTestHandle *mth);


/**
 * Function called whenever a group member has transmitted a request
 * to the origin (other than joining or leaving).
 *
 * FIXME: need to distinguish between origin cancelling a message (some fragments
 * were sent, then the rest 'discarded') and the case where we got disconnected;
 * right now, both would mean 'msg' is NULL, but they could be quite different...
 * So the semantics from the receiver side of
 * GNUNET_MULTICAST_member_to_origin_cancel() are not clear here.   Maybe we
 * should do something with the flags in this case?
 *
 * @param cls Closure (set from GNUNET_MULTICAST_origin_start).
 * @param sender Identity of the sender.
 * @param req Request to the origin.
 * @param flags Flags for the request.
 */
typedef void
(*GNUNET_MULTICAST_RequestCallback) (void *cls,
                                     const struct GNUNET_CRYPTO_EccPublicSignKey *member_key,
                                     const struct GNUNET_MessageHeader *req,
                                     enum GNUNET_MULTICAST_MessageFlags flags);


/**
 * Function called whenever a group member is receiving a message fragment from
 * the origin.
 *
 * If admission to the group is denied, this function is called once with the
 * response of the @e origin (as given to GNUNET_MULTICAST_join_decision()) and
 * then a second time with NULL to indicate that the connection failed for good.
 *
 * FIXME: need to distinguish between origin cancelling a message (some fragments
 * were sent, then the rest 'discarded') and the case where we got disconnected;
 * right now, both would mean 'msg' is NULL, but they could be quite different...
 * So the semantics from the receiver side of
 * GNUNET_MULTICAST_origin_to_all_cancel() are not clear here.
 *
 * @param cls Closure (set from GNUNET_MULTICAST_member_join())
 * @param msg Message from the origin, NULL if the origin shut down
 *        (or we were kicked out, and we should thus call
 *        GNUNET_MULTICAST_member_part() next)
 */
typedef void
(*GNUNET_MULTICAST_MessageCallback) (void *cls,
                                     const struct GNUNET_MessageHeader *msg);


/**
 * Function called with the result of an asynchronous operation.
 *
 * @see GNUNET_MULTICAST_replay_fragment()
 *
 * @param result Result of the operation.
 */
typedef void
(*GNUNET_MULTICAST_ResultCallback) (void *cls,
                                    int result);


/**
 * Opaque handle to a replay request from the multicast service.
 */
struct GNUNET_MULTICAST_ReplayHandle;


/**
 * Functions with this signature are called whenever the multicast service needs
 * a message fragment to be replayed by fragment_id.
 *
 * Implementations of this function MUST call GNUNET_MULTICAST_replay() ONCE
 * (with a message or an error); however, if the origin is destroyed or the
 * group is left, the replay handle must no longer be used.
 *
 * @param cls Closure (set from GNUNET_MULTICAST_origin_start()
 *        or GNUNET_MULTICAST_member_join()).
 * @param member_key The member requesting replay.
 * @param fragment_id Which message fragment should be replayed.
 * @param flags Flags for the replay.
 * @param rh Handle to pass to message transmit function.
 */
typedef void
(*GNUNET_MULTICAST_ReplayFragmentCallback) (void *cls,
                                            const struct GNUNET_CRYPTO_EccPublicSignKey *member_key,
                                            uint64_t fragment_id,
                                            uint64_t flags,
                                            struct GNUNET_MULTICAST_ReplayHandle *rh);

/**
 * Functions with this signature are called whenever the multicast service needs
 * a message fragment to be replayed by message_id and fragment_offset.
 *
 * Implementations of this function MUST call GNUNET_MULTICAST_replay() ONCE
 * (with a message or an error); however, if the origin is destroyed or the
 * group is left, the replay handle must no longer be used.
 *
 * @param cls Closure (set from GNUNET_MULTICAST_origin_start()
 *        or GNUNET_MULTICAST_member_join()).
 * @param member_key The member requesting replay.
 * @param message_id Which message should be replayed.
 * @param fragment_offset Offset of the fragment within of @a message_id to be replayed.
 * @param flags Flags for the replay.
 * @param rh Handle to pass to message transmit function.
 */
typedef void
(*GNUNET_MULTICAST_ReplayMessageCallback) (void *cls,
                                           const struct GNUNET_CRYPTO_EccPublicSignKey *member_key,
                                           uint64_t message_id,
                                           uint64_t fragment_offset,
                                           uint64_t flags,
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
   * Message fragment not found in the message store.
   *
   * Either discarded if it is too old, or not arrived yet if this member has
   * missed some messages.
   */
  GNUNET_MULTICAST_REC_NOT_FOUND = 1,

  /**
   * Fragment ID counter was larger than the highest counter this
   * replay function has ever encountered; thus it is likely the
   * origin never sent it and we're at the HEAD of the multicast
   * stream as far as this node is concerned.
   *
   * FIXME: needed?
   */
  GNUNET_MULTICAST_REC_PAST_HEAD = 2,

  /**
   * Access is denied to the requested fragment, membership test did not pass.
   */
  GNUNET_MULTICAST_REC_ACCESS_DENIED = 3,

  /**
   * Internal error (i.e. database error).  Try some other peer.
   */
  GNUNET_MULTICAST_REC_INTERNAL_ERROR = 4

};


/**
 * Replay a message fragment for the multicast group.
 *
 * @param rh Replay handle identifying which replay operation was requested.
 * @param msg Replayed message fragment, NULL if unknown/error.
 * @param ec Error code.
 */
void
GNUNET_MULTICAST_replay_response (struct GNUNET_MULTICAST_ReplayHandle *rh,
                                  const struct GNUNET_MessageHeader *msg,
                                  enum GNUNET_MULTICAST_ReplayErrorCode ec);


/**
 * Indicate the end of the replay session.
 *
 * Invalidates the replay handle.
 *
 * @param rh Replay session to end.
 */
void
GNUNET_MULTICAST_replay_response_end (struct GNUNET_MULTICAST_ReplayHandle *rh);


/**
 * Function called to provide data for a transmission for a replay.
 *
 * @see GNUNET_MULTICAST_replay2()
 */
typedef int
(*GNUNET_MULTICAST_ReplayTransmitNotify) (void *cls,
                                          size_t *data_size,
                                          void *data);


/**
 * Replay a message for the multicast group.
 *
 * @param rh Replay handle identifying which replay operation was requested.
 * @param notify Function to call to get the message.
 * @param notify_cls Closure for @a notify.
 */
void
GNUNET_MULTICAST_replay_response2 (struct GNUNET_MULTICAST_ReplayHandle *rh,
                                   GNUNET_MULTICAST_ReplayTransmitNotify notify,
                                   void *notify_cls);


/**
 * Start a multicast group.
 *
 * Will advertise the origin in the P2P overlay network under the respective
 * public key so that other peer can find this peer to join it.  Peers that
 * issue GNUNET_MULTICAST_member_join() can then transmit a join request to
 * either an existing group member or to the origin.  If the joining is
 * approved, the member is cleared for @e replay and will begin to receive
 * messages transmitted to the group.  If joining is disapproved, the failed
 * candidate will be given a response.  Members in the group can send messages
 * to the origin (one at a time).
 *
 * @param cfg Configuration to use.
 * @param priv_key ECC key that will be used to sign messages for this
 *        multicast session; public key is used to identify the multicast group;
 * @param next_fragment_id Next fragment ID to continue counting fragments from
 *        when restarting the origin.  1 for a new group.
 * @param join_cb Function called to approve / disapprove joining of a peer.
 * @param mem_test_cb Function multicast can use to test group membership.
 * @param replay_frag_cb Function that can be called to replay a message fragment.
 * @param replay_msg_cb Function that can be called to replay a message.
 * @param request_cb Function called with message fragments from group members.
 * @param message_cb Function called with the message fragments sent to the
 *        network by GNUNET_MULTICAST_origin_to_all().  These message fragments
 *        should be stored for answering replay requests later.
 * @param cls Closure for the various callbacks that follow.
 * @return Handle for the origin, NULL on error.
 */
struct GNUNET_MULTICAST_Origin *
GNUNET_MULTICAST_origin_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
                               const struct GNUNET_CRYPTO_EccPrivateKey *priv_key,
                               uint64_t next_fragment_id,
                               GNUNET_MULTICAST_JoinCallback join_cb,
                               GNUNET_MULTICAST_MembershipTestCallback mem_test_cb,
                               GNUNET_MULTICAST_ReplayFragmentCallback replay_frag_cb,
                               GNUNET_MULTICAST_ReplayMessageCallback replay_msg_cb,
                               GNUNET_MULTICAST_RequestCallback request_cb,
                               GNUNET_MULTICAST_MessageCallback message_cb,
                               void *cls);

/**
 * Function called to provide data for a transmission from the origin to all
 * members.
 *
 * Note that returning #GNUNET_OK or #GNUNET_SYSERR (but not #GNUNET_NO)
 * invalidates the respective transmission handle.
 *
 * @param cls Closure.
 * @param[in,out] data_size Initially set to the number of bytes available in
 *        @a data, should be set to the number of bytes written to data.
 * @param[out] data Where to write the body of the message to give to the
 *         method. The function must copy at most @a data_size bytes to @a data.
 * @return #GNUNET_SYSERR on error (fatal, aborts transmission)
 *         #GNUNET_NO on success, if more data is to be transmitted later.
 *         Should be used if @a data_size was not big enough to take all the
 *         data.  If 0 is returned in @a data_size the transmission is paused,
 *         and can be resumed with GNUNET_MULTICAST_origin_to_all_resume().
 *         #GNUNET_YES if this completes the transmission (all data supplied)
 */
typedef int
(*GNUNET_MULTICAST_OriginTransmitNotify) (void *cls,
                                          size_t *data_size,
                                          void *data);


/**
 * Handle for a request to send a message to all multicast group members
 * (from the origin).
 */
struct GNUNET_MULTICAST_OriginMessageHandle;


/**
 * Send a message to the multicast group.
 *
 * @param origin Handle to the multicast group.
 * @param message_id Application layer ID for the message.  Opaque to multicast.
 * @param group_generation Group generation of the message.  Documented in
 *             GNUNET_MULTICAST_MessageHeader.
 * @param notify Function to call to get the message.
 * @param notify_cls Closure for @a notify.
 * @return NULL on error (i.e. request already pending).
 */
struct GNUNET_MULTICAST_OriginMessageHandle *
GNUNET_MULTICAST_origin_to_all (struct GNUNET_MULTICAST_Origin *origin,
                                uint64_t message_id,
                                uint64_t group_generation,
                                GNUNET_MULTICAST_OriginTransmitNotify notify,
                                void *notify_cls);



/**
 * Resume message transmission to multicast group.
 *
 * @param mh Request to cancel.
 */
void
GNUNET_MULTICAST_origin_to_all_resume (struct GNUNET_MULTICAST_OriginMessageHandle *mh);


/**
 * Cancel request for message transmission to multicast group.
 *
 * @param mh Request to cancel.
 */
void
GNUNET_MULTICAST_origin_to_all_cancel (struct GNUNET_MULTICAST_OriginMessageHandle *mh);


/**
 * Stop a multicast group.
 *
 * @param origin Multicast group to stop.
 */
void
GNUNET_MULTICAST_origin_stop (struct GNUNET_MULTICAST_Origin *origin);


/**
 * Join a multicast group.
 *
 * The entity joining is always the local peer.  Further information about the
 * candidate can be provided in the @a join_request message.  If the join fails, the
 * @a message_cb is invoked with a (failure) response and then with NULL.  If
 * the join succeeds, outstanding (state) messages and ongoing multicast
 * messages will be given to the @a message_cb until the member decides to part
 * the group.  The @a mem_test_cb and @a replay_cb functions may be called at
 * anytime by the multicast service to support relaying messages to other
 * members of the group.
 *
 * @param cfg Configuration to use.
 * @param group_key ECC public key that identifies the group to join.
 * @param member_key ECC key that identifies the member and used to sign
 *        requests sent to the origin.
 * @param origin Peer ID of the origin to send unicast requsets to.  If NULL,
 *        unicast requests are sent back via multiple hops on the reverse path
 *        of multicast messages.
 * @param relay_count Number of peers in the @a relays array.
 * @param relays Peer identities of members of the group, which serve as relays
 *        and can be used to join the group at. and send the @a join_request to.
 *        If empty, the @a join_request is sent directly to the @a origin.
 * @param join_request  Application-dependent join request to be passed to the peer
 *        @a relay (might, for example, contain a user, bind user
 *        identity/pseudonym to peer identity, application-level message to
 *        origin, etc.).
 * @param join_cb Function called to approve / disapprove joining of a peer.
 * @param mem_test_cb Function multicast can use to test group membership.
 * @param replay_frag_cb Function that can be called to replay message fragments
 *        this peer already knows from this group. NULL if this
 *        client is unable to support replay.
 * @param replay_msg_cb Function that can be called to replay message fragments
 *        this peer already knows from this group. NULL if this
 *        client is unable to support replay.
 * @param message_cb Function to be called for all message fragments we
 *        receive from the group, excluding those our @a replay_cb
 *        already has.
 * @param cls Closure for callbacks.
 * @return Handle for the member, NULL on error.
 */
struct GNUNET_MULTICAST_Member *
GNUNET_MULTICAST_member_join (const struct GNUNET_CONFIGURATION_Handle *cfg,
                              const struct GNUNET_CRYPTO_EccPublicSignKey *group_key,
                              const struct GNUNET_CRYPTO_EccPrivateKey *member_key,
                              const struct GNUNET_PeerIdentity *origin,
                              uint32_t relay_count,
                              const struct GNUNET_PeerIdentity *relays,
                              const struct GNUNET_MessageHeader *join_request,
                              GNUNET_MULTICAST_JoinCallback join_cb,
                              GNUNET_MULTICAST_MembershipTestCallback mem_test_cb,
                              GNUNET_MULTICAST_ReplayFragmentCallback replay_frag_cb,
                              GNUNET_MULTICAST_ReplayMessageCallback replay_msg_cb,
                              GNUNET_MULTICAST_MessageCallback message_cb,
                              void *cls);

/**
 * Handle for a replay request.
 */
struct GNUNET_MULTICAST_MemberReplayHandle;


/**
 * Request a fragment to be replayed by fragment ID.
 *
 * Useful if messages below the @e max_known_fragment_id given when joining are
 * needed and not known to the client.
 *
 * @param member Membership handle.
 * @param fragment_id ID of a message fragment that this client would like to
          see replayed.
 * @param flags Additional flags for the replay request.  It is used and defined
 *        by the replay callback.  FIXME: which replay callback? FIXME: use enum?
 *        FIXME: why not pass reply cb here?
 * @return Replay request handle, NULL on error.
 */
struct GNUNET_MULTICAST_MemberReplayHandle *
GNUNET_MULTICAST_member_replay_fragment (struct GNUNET_MULTICAST_Member *member,
                                         uint64_t fragment_id,
                                         uint64_t flags);


/**
 * Request a message fr to be replayed.
 *
 * Useful if messages below the @e max_known_fragment_id given when joining are
 * needed and not known to the client.
 *
 * @param member Membership handle.
 * @param message_id ID of the message this client would like to see replayed.
 * @param fragment_offset Offset of the fragment within the message to replay.
 * @param flags Additional flags for the replay request.  It is used & defined
 *        by the replay callback.
 * @param result_cb Function to be called for the replayed message.
 * @param result_cb_cls Closure for @a result_cb.
 * @return Replay request handle, NULL on error.
 */
struct GNUNET_MULTICAST_MemberReplayHandle *
GNUNET_MULTICAST_member_replay_message (struct GNUNET_MULTICAST_Member *member,
                                        uint64_t message_id,
                                        uint64_t fragment_offset,
                                        uint64_t flags,
                                        GNUNET_MULTICAST_ResultCallback result_cb,
                                        void *result_cb_cls);


/**
 * Cancel a replay request.
 *
 * @param rh Request to cancel.
 */
void
GNUNET_MULTICAST_member_replay_cancel (struct GNUNET_MULTICAST_MemberReplayHandle *rh);


/**
 * Part a multicast group.
 *
 * Disconnects from all group members and invalidates the @a member handle.
 *
 * An application-dependent part message can be transmitted beforehand using
 * #GNUNET_MULTICAST_member_to_origin())
 *
 * @param member Membership handle.
 */
void
GNUNET_MULTICAST_member_part (struct GNUNET_MULTICAST_Member *member);


/**
 * Function called to provide data for a transmission from a member to the origin.
 *
 * Note that returning #GNUNET_OK or #GNUNET_SYSERR (but not #GNUNET_NO)
 * invalidates the respective transmission handle.
 *
 * @param cls Closure.
 * @param[in,out] data_size Initially set to the number of bytes available in
 *        @a data, should be set to the number of bytes written to data.
 * @param[out] data Where to write the body of the message to give to the
 *         method. The function must copy at most @a data_size bytes to @a data.
 * @return #GNUNET_SYSERR on error (fatal, aborts transmission)
 *         #GNUNET_NO on success, if more data is to be transmitted later.
 *         Should be used if @a data_size was not big enough to take all the
 *         data.  If 0 is returned in @a data_size the transmission is paused,
 *         and can be resumed with GNUNET_MULTICAST_member_to_origin_resume().
 *         #GNUNET_YES if this completes the transmission (all data supplied)
 */
typedef int
(*GNUNET_MULTICAST_MemberTransmitNotify) (void *cls,
                                          size_t *data_size,
                                          void *data);


/**
 * Handle for a message to be delivered from a member to the origin.
 */
struct GNUNET_MULTICAST_MemberRequestHandle;


/**
 * Send a message to the origin of the multicast group.
 *
 * @param member Membership handle.
 * @param message_id Application layer ID for the message.  Opaque to multicast.
 * @param notify Callback to call to get the message.
 * @param notify_cls Closure for @a notify.
 * @return Handle to cancel request, NULL on error (i.e. request already pending).
 */
struct GNUNET_MULTICAST_MemberRequestHandle *
GNUNET_MULTICAST_member_to_origin (struct GNUNET_MULTICAST_Member *member,
                                   uint64_t message_id,
                                   GNUNET_MULTICAST_MemberTransmitNotify notify,
                                   void *notify_cls);


/**
 * Resume message transmission to origin.
 *
 * @param rh Request to cancel.
 */
void
GNUNET_MULTICAST_member_to_origin_resume (struct GNUNET_MULTICAST_MemberRequestHandle *rh);


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
