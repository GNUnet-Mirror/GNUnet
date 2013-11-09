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
 * @file multicast/multicast_api.c
 * @brief multicast service; establish tunnels to distant peers
 * @author Christian Grothoff
 * @author Gabor X Toth
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_signatures.h"
#include "gnunet_multicast_service.h"
#include "multicast.h"

#define LOG(kind,...) GNUNET_log_from (kind, "multicast-api",__VA_ARGS__)


/**
 * Handle for a request to send a message to all multicast group members
 * (from the origin).
 */
struct GNUNET_MULTICAST_OriginMessageHandle
{
  GNUNET_MULTICAST_OriginTransmitNotify notify;
  void *notify_cls;
  struct GNUNET_MULTICAST_Origin *origin;

  uint64_t message_id;
  uint64_t group_generation;
  uint64_t fragment_offset;
};


/**
 * Handle for the origin of a multicast group.
 */
struct GNUNET_MULTICAST_Origin
{
  struct GNUNET_CRYPTO_EddsaPrivateKey priv_key;
  struct GNUNET_MULTICAST_OriginMessageHandle msg_handle;

  GNUNET_MULTICAST_JoinCallback join_cb;
  GNUNET_MULTICAST_MembershipTestCallback mem_test_cb;
  GNUNET_MULTICAST_ReplayFragmentCallback replay_frag_cb;
  GNUNET_MULTICAST_ReplayMessageCallback replay_msg_cb;
  GNUNET_MULTICAST_RequestCallback request_cb;
  GNUNET_MULTICAST_MessageCallback message_cb;
  void *cls;

  uint64_t next_fragment_id;
};


/**
 * Handle for a message to be delivered from a member to the origin.
 */
struct GNUNET_MULTICAST_MemberRequestHandle
{
};


/**
 * Opaque handle for a multicast group member.
 */
struct GNUNET_MULTICAST_Member
{
};


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Header of a request from a member to the origin.
 */
struct GNUNET_MULTICAST_RequestHeader
{
  /**
   * Header for all requests from a member to the origin.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Public key of the sending member.
   */
  struct GNUNET_CRYPTO_EddsaPublicKey member_key;

  /**
   * ECC signature of the request fragment.
   *
   * Signature must match the public key of the multicast group.
   */
  struct GNUNET_CRYPTO_EddsaSignature signature;

  /**
   * Purpose for the signature and size of the signed data.
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * Number of the request fragment, monotonically increasing.
   */
  uint64_t fragment_id GNUNET_PACKED;

  /**
   * Byte offset of this @e fragment of the @e request.
   */
  uint64_t fragment_offset GNUNET_PACKED;

  /**
   * Number of the request this fragment belongs to.
   *
   * Set in GNUNET_MULTICAST_origin_to_all().
   */
  uint64_t request_id GNUNET_PACKED;

  /**
   * Flags for this request.
   */
  enum GNUNET_MULTICAST_MessageFlags flags GNUNET_PACKED;

  /* Followed by request body. */
};

/**
 * Header of a join request sent to the origin or another member.
 */
struct GNUNET_MULTICAST_JoinRequest
{
  /**
   * Header for the join request.
   */
  struct GNUNET_MessageHeader header;

  /**
   * ECC signature of the rest of the fields of the join request.
   *
   * Signature must match the public key of the joining member.
   */
  struct GNUNET_CRYPTO_EddsaSignature signature;

  /**
   * Purpose for the signature and size of the signed data.
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * Public key of the target group.
   */
  struct GNUNET_CRYPTO_EddsaPublicKey group_key;

  /**
   * Public key of the joining member.
   */
  struct GNUNET_CRYPTO_EddsaPublicKey member_key;

  /**
   * Peer identity of the joining member.
   */
  struct GNUNET_PeerIdentity member_peer;

  /* Followed by request body. */
};

GNUNET_NETWORK_STRUCT_END


/**
 * Handle that identifies a join request.
 *
 * Used to match calls to #GNUNET_MULTICAST_JoinCallback to the
 * corresponding calls to #GNUNET_MULTICAST_join_decision().
 */
struct GNUNET_MULTICAST_JoinHandle
{
};


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
                                const struct GNUNET_MessageHeader *join_response)
{
  return NULL;
}


/**
 * Handle to pass back for the answer of a membership test.
 */
struct GNUNET_MULTICAST_MembershipTestHandle
{
};


/**
 * Call informing multicast about the decision taken for a membership test.
 *
 * @param mth Handle that was given for the query.
 * @param result #GNUNET_YES if peer was a member, #GNUNET_NO if peer was not a member,
 *        #GNUNET_SYSERR if we cannot answer the membership test.
 */
void
GNUNET_MULTICAST_membership_test_result (struct GNUNET_MULTICAST_MembershipTestHandle *mth,
                                         int result)
{
}


/**
 * Opaque handle to a replay request from the multicast service.
 */
struct GNUNET_MULTICAST_ReplayHandle
{
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
                                  enum GNUNET_MULTICAST_ReplayErrorCode ec)
{
}


/**
 * Indicate the end of the replay session.
 *
 * Invalidates the replay handle.
 *
 * @param rh Replay session to end.
 */
void
GNUNET_MULTICAST_replay_response_end (struct GNUNET_MULTICAST_ReplayHandle *rh)
{
}


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
                                   void *notify_cls)
{
}


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
 *        when restarting the origin.  0 for a new group.
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
                               const struct GNUNET_CRYPTO_EddsaPrivateKey *priv_key,
                               uint64_t next_fragment_id,
                               GNUNET_MULTICAST_JoinCallback join_cb,
                               GNUNET_MULTICAST_MembershipTestCallback mem_test_cb,
                               GNUNET_MULTICAST_ReplayFragmentCallback replay_frag_cb,
                               GNUNET_MULTICAST_ReplayMessageCallback replay_msg_cb,
                               GNUNET_MULTICAST_RequestCallback request_cb,
                               GNUNET_MULTICAST_MessageCallback message_cb,
                               void *cls)
{
  struct GNUNET_MULTICAST_Origin *orig = GNUNET_malloc (sizeof (*orig));
  orig->priv_key = *priv_key;
  orig->next_fragment_id = next_fragment_id;
  orig->join_cb = join_cb;
  orig->mem_test_cb = mem_test_cb;
  orig->replay_frag_cb = replay_frag_cb;
  orig->replay_msg_cb = replay_msg_cb;
  orig->request_cb = request_cb;
  orig->message_cb = message_cb;
  orig->cls = cls;
  return orig;
}


/* FIXME: for now just send back to the client what it sent. */
static void
schedule_origin_to_all (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "schedule_origin_to_all()\n");
  struct GNUNET_MULTICAST_Origin *orig = cls;
  struct GNUNET_MULTICAST_OriginMessageHandle *mh = &orig->msg_handle;

  size_t buf_size = GNUNET_MULTICAST_FRAGMENT_MAX_SIZE;
  struct GNUNET_MULTICAST_MessageHeader *msg
    = GNUNET_malloc (sizeof (*msg) + buf_size);
  int ret = mh->notify (mh->notify_cls, &buf_size, &msg[1]);

  if (! (GNUNET_YES == ret || GNUNET_NO == ret)
      || buf_size > GNUNET_MULTICAST_FRAGMENT_MAX_SIZE)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "MasterTransmitNotify() returned error or invalid message size.\n");
    /* FIXME: handle error */
    return;
  }

  if (GNUNET_NO == ret && 0 == buf_size)
    return; /* Transmission paused. */

  msg->header.type = htons (GNUNET_MESSAGE_TYPE_MULTICAST_MESSAGE);
  msg->header.size = htons (buf_size);
  msg->message_id = mh->message_id;
  msg->group_generation = mh->group_generation;

  /* FIXME: add fragment ID and signature in the service instead of here */
  msg->fragment_id = orig->next_fragment_id++;
  msg->fragment_offset = mh->fragment_offset;
  mh->fragment_offset += buf_size;
  msg->purpose.size = htonl (buf_size
                             - sizeof (msg->header)
                             - sizeof (msg->hop_counter)
                             - sizeof (msg->signature));
  msg->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_MULTICAST_MESSAGE);

  if (GNUNET_OK != GNUNET_CRYPTO_eddsa_sign (&orig->priv_key, &msg->purpose,
                                           &msg->signature))
  {
    /* FIXME: handle error */
    return;
  }

  /* FIXME: send msg to the service and only then call message_cb with the
   *        returned signed message.
   * FIXME: Also send to local members in this group.
   */
  orig->message_cb (orig->cls, (const struct GNUNET_MessageHeader *) msg);

  if (GNUNET_NO == ret)
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_SECONDS, 1),
                                  schedule_origin_to_all, orig);

}

/**
 * Send a message to the multicast group.
 *
 * @param origin Handle to the multicast group.
 * @param message_id Application layer ID for the message.  Opaque to multicast.
 * @param group_generation Group generation of the message.  Documented in
 *             `struct GNUNET_MULTICAST_MessageHeader`.
 * @param notify Function to call to get the message.
 * @param notify_cls Closure for @a notify.
 * @return NULL on error (i.e. request already pending).
 */
struct GNUNET_MULTICAST_OriginMessageHandle *
GNUNET_MULTICAST_origin_to_all (struct GNUNET_MULTICAST_Origin *origin,
                                uint64_t message_id,
                                uint64_t group_generation,
                                GNUNET_MULTICAST_OriginTransmitNotify notify,
                                void *notify_cls)
{
  struct GNUNET_MULTICAST_OriginMessageHandle *mh = &origin->msg_handle;
  mh->origin = origin;
  mh->message_id = message_id;
  mh->group_generation = group_generation;
  mh->notify = notify;
  mh->notify_cls = notify_cls;

  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                (GNUNET_TIME_UNIT_SECONDS, 1),
                                schedule_origin_to_all, origin);
  return &origin->msg_handle;
}


/**
 * Resume message transmission to multicast group.
 *
 * @param mh Request to cancel.
 */
void
GNUNET_MULTICAST_origin_to_all_resume (struct GNUNET_MULTICAST_OriginMessageHandle *mh)
{
  GNUNET_SCHEDULER_add_now (schedule_origin_to_all, mh->origin);
}


/**
 * Cancel request for message transmission to multicast group.
 *
 * @param mh Request to cancel.
 */
void
GNUNET_MULTICAST_origin_to_all_cancel (struct GNUNET_MULTICAST_OriginMessageHandle *mh)
{
}


/**
 * Stop a multicast group.
 *
 * @param origin Multicast group to stop.
 */
void
GNUNET_MULTICAST_origin_stop (struct GNUNET_MULTICAST_Origin *origin)
{
  GNUNET_free (origin);
}


/**
 * Join a multicast group.
 *
 * The entity joining is always the local peer.  Further information about the
 * candidate can be provided in the @a join_request message.  If the join fails, the
 * @a message_cb is invoked with a (failure) response and then with NULL.  If
 * the join succeeds, outstanding (state) messages and ongoing multicast
 * messages will be given to the @a message_cb until the member decides to part
 * the group.  The @a test_cb and @a replay_cb functions may be called at
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
                              const struct GNUNET_CRYPTO_EddsaPublicKey *group_key,
                              const struct GNUNET_CRYPTO_EddsaPrivateKey *member_key,
                              const struct GNUNET_PeerIdentity *origin,
                              uint32_t relay_count,
                              const struct GNUNET_PeerIdentity *relays,
                              const struct GNUNET_MessageHeader *join_request,
                              GNUNET_MULTICAST_JoinCallback join_cb,
                              GNUNET_MULTICAST_MembershipTestCallback mem_test_cb,
                              GNUNET_MULTICAST_ReplayFragmentCallback replay_frag_cb,
                              GNUNET_MULTICAST_ReplayMessageCallback replay_msg_cb,
                              GNUNET_MULTICAST_MessageCallback message_cb,
                              void *cls)
{
  struct GNUNET_MULTICAST_Member *mem = GNUNET_malloc (sizeof (*mem));

  return mem;
}


/**
 * Handle for a replay request.
 */
struct GNUNET_MULTICAST_MemberReplayHandle
{
};


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
                                         uint64_t flags)
{
  return NULL;
}


/**
 * Request a message fragment to be replayed.
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
                                        void *result_cb_cls)
{
  return NULL;
}


/**
 * Cancel a replay request.
 *
 * @param rh Request to cancel.
 */
void
GNUNET_MULTICAST_member_replay_cancel (struct GNUNET_MULTICAST_MemberReplayHandle *rh)
{
}


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
GNUNET_MULTICAST_member_part (struct GNUNET_MULTICAST_Member *member)
{
  GNUNET_free (member);
}


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
                                   void *notify_cls)
{
  return NULL;
}


/**
 * Resume message transmission to origin.
 *
 * @param rh Request to cancel.
 */
void
GNUNET_MULTICAST_member_to_origin_resume (struct GNUNET_MULTICAST_MemberRequestHandle *rh)
{

}


/**
 * Cancel request for message transmission to origin.
 *
 * @param rh Request to cancel.
 */
void
GNUNET_MULTICAST_member_to_origin_cancel (struct GNUNET_MULTICAST_MemberRequestHandle *rh)
{
}


/* end of multicast_api.c */
