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
 * Started origins.
 * Group's pub_key_hash -> struct GNUNET_MULTICAST_Origin
 */
static struct GNUNET_CONTAINER_MultiHashMap *origins;

/**
 * Joined members.
 * group_key_hash -> struct GNUNET_MULTICAST_Member
 */
static struct GNUNET_CONTAINER_MultiHashMap *members;


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


struct GNUNET_MULTICAST_Group
{
  uint8_t is_origin;
};

/**
 * Handle for the origin of a multicast group.
 */
struct GNUNET_MULTICAST_Origin
{
  struct GNUNET_MULTICAST_Group grp;

  struct GNUNET_MULTICAST_OriginMessageHandle msg_handle;
  struct GNUNET_CRYPTO_EddsaPrivateKey priv_key;

  GNUNET_MULTICAST_JoinCallback join_cb;
  GNUNET_MULTICAST_MembershipTestCallback mem_test_cb;
  GNUNET_MULTICAST_ReplayFragmentCallback replay_frag_cb;
  GNUNET_MULTICAST_ReplayMessageCallback replay_msg_cb;
  GNUNET_MULTICAST_RequestCallback request_cb;
  GNUNET_MULTICAST_MessageCallback message_cb;
  void *cls;

  uint64_t next_fragment_id;

  struct GNUNET_CRYPTO_EddsaPublicKey pub_key;
  struct GNUNET_HashCode pub_key_hash;
};


/**
 * Handle for a message to be delivered from a member to the origin.
 */
struct GNUNET_MULTICAST_MemberRequestHandle
{
  GNUNET_MULTICAST_MemberTransmitNotify notify;
  void *notify_cls;
  struct GNUNET_MULTICAST_Member *member;

  uint64_t request_id;
  uint64_t fragment_offset;
};


/**
 * Handle for a multicast group member.
 */
struct GNUNET_MULTICAST_Member
{
  struct GNUNET_MULTICAST_Group grp;

  struct GNUNET_MULTICAST_MemberRequestHandle req_handle;

  struct GNUNET_CRYPTO_EddsaPublicKey group_key;
  struct GNUNET_CRYPTO_EddsaPrivateKey member_key;
  struct GNUNET_PeerIdentity origin;
  struct GNUNET_PeerIdentity relays;
  uint32_t relay_count;
  struct GNUNET_MessageHeader *join_request;
  GNUNET_MULTICAST_JoinCallback join_cb;
  GNUNET_MULTICAST_MembershipTestCallback member_test_cb;
  GNUNET_MULTICAST_ReplayFragmentCallback replay_frag_cb;
  GNUNET_MULTICAST_ReplayMessageCallback replay_msg_cb;
  GNUNET_MULTICAST_MessageCallback message_cb;
  void *cls;

  uint64_t next_fragment_id;
  struct GNUNET_HashCode group_key_hash;
};


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
 * Handle to pass back for the answer of a membership test.
 */
struct GNUNET_MULTICAST_MembershipTestHandle
{
};


/**
 * Opaque handle to a replay request from the multicast service.
 */
struct GNUNET_MULTICAST_ReplayHandle
{
};


/**
 * Handle for a replay request.
 */
struct GNUNET_MULTICAST_MemberReplayHandle
{
};


/**
 * Iterator callback for calling message callbacks for all groups.
 */
static int
message_callback (void *cls, const struct GNUNET_HashCode *chan_key_hash,
                   void *group)
{
  const struct GNUNET_MessageHeader *msg = cls;
  struct GNUNET_MULTICAST_Group *grp = group;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Calling message callback for a message of type %u and size %u.\n",
              ntohs (msg->type), ntohs (msg->size));

  if (GNUNET_YES == grp->is_origin)
  {
    struct GNUNET_MULTICAST_Origin *orig = (struct GNUNET_MULTICAST_Origin *) grp;
    orig->message_cb (orig->cls, msg);
  }
  else
  {
    struct GNUNET_MULTICAST_Member *mem = (struct GNUNET_MULTICAST_Member *) grp;
    mem->message_cb (mem->cls, msg);
  }

  return GNUNET_YES;
}


/**
 * Handle a multicast message from the service.
 *
 * Call message callbacks of all origins and members of the destination group.
 *
 * @param grp Destination group of the message.
 * @param msg The message.
 */
static void
handle_multicast_message (struct GNUNET_MULTICAST_Group *grp,
                          const struct GNUNET_MULTICAST_MessageHeader *msg)
{
  struct GNUNET_HashCode *hash;

  if (GNUNET_YES == grp->is_origin)
  {
    struct GNUNET_MULTICAST_Origin *orig = (struct GNUNET_MULTICAST_Origin *) grp;
    hash = &orig->pub_key_hash;
  }
  else
  {
    struct GNUNET_MULTICAST_Member *mem = (struct GNUNET_MULTICAST_Member *) grp;
    hash = &mem->group_key_hash;
  }

  if (origins != NULL)
    GNUNET_CONTAINER_multihashmap_get_multiple (origins, hash, message_callback,
                                                (void *) msg);
  if (members != NULL)
    GNUNET_CONTAINER_multihashmap_get_multiple (members, hash, message_callback,
                                                (void *) msg);
}


/**
 * Iterator callback for calling request callbacks of origins.
 */
static int
request_callback (void *cls, const struct GNUNET_HashCode *chan_key_hash,
                  void *origin)
{
  const struct GNUNET_MULTICAST_RequestHeader *req = cls;
  struct GNUNET_MULTICAST_Origin *orig = origin;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Calling request callback for a request of type %u and size %u.\n",
              ntohs (req->header.type), ntohs (req->header.size));

  orig->request_cb (orig->cls, &req->member_key,
                    (const struct GNUNET_MessageHeader *) req, 0);
  return GNUNET_YES;
}


/**
 * Handle a multicast request from the service.
 *
 * Call request callbacks of all origins of the destination group.
 *
 * @param grp Destination group of the message.
 * @param msg The message.
 */
static void
handle_multicast_request (const struct GNUNET_HashCode *group_key_hash,
                          const struct GNUNET_MULTICAST_RequestHeader *req)
{
  if (NULL != origins)
    GNUNET_CONTAINER_multihashmap_get_multiple (origins, group_key_hash,
                                                request_callback, (void *) req);
}


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
  orig->grp.is_origin = GNUNET_YES;
  orig->priv_key = *priv_key;
  orig->next_fragment_id = next_fragment_id;
  orig->join_cb = join_cb;
  orig->mem_test_cb = mem_test_cb;
  orig->replay_frag_cb = replay_frag_cb;
  orig->replay_msg_cb = replay_msg_cb;
  orig->request_cb = request_cb;
  orig->message_cb = message_cb;
  orig->cls = cls;

  GNUNET_CRYPTO_eddsa_key_get_public (&orig->priv_key, &orig->pub_key);
  GNUNET_CRYPTO_hash (&orig->pub_key, sizeof (orig->pub_key),
                      &orig->pub_key_hash);

  if (NULL == origins)
    origins = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);

  GNUNET_CONTAINER_multihashmap_put (origins, &orig->pub_key_hash, orig,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);

  /* FIXME: send ORIGIN_START to service */

  return orig;
}


/**
 * Stop a multicast group.
 *
 * @param origin Multicast group to stop.
 */
void
GNUNET_MULTICAST_origin_stop (struct GNUNET_MULTICAST_Origin *orig)
{
  GNUNET_CONTAINER_multihashmap_remove (origins, &orig->pub_key_hash, orig);
  GNUNET_free (orig);
}


/* FIXME: for now just call clients' callbacks
 *        without sending anything to multicast. */
static void
schedule_origin_to_all (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "schedule_origin_to_all()\n");
  struct GNUNET_MULTICAST_Origin *orig = cls;
  struct GNUNET_MULTICAST_OriginMessageHandle *mh = &orig->msg_handle;

  size_t buf_size = GNUNET_MULTICAST_FRAGMENT_MAX_PAYLOAD;
  char buf[GNUNET_MULTICAST_FRAGMENT_MAX_PAYLOAD] = "";
  struct GNUNET_MULTICAST_MessageHeader *msg
    = (struct GNUNET_MULTICAST_MessageHeader *) buf;
  int ret = mh->notify (mh->notify_cls, &buf_size, &msg[1]);

  if (! (GNUNET_YES == ret || GNUNET_NO == ret)
      || GNUNET_MULTICAST_FRAGMENT_MAX_PAYLOAD < buf_size)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "OriginTransmitNotify() returned error or invalid message size.\n");
    /* FIXME: handle error */
    return;
  }

  if (GNUNET_NO == ret && 0 == buf_size)
    return; /* Transmission paused. */

  msg->header.type = htons (GNUNET_MESSAGE_TYPE_MULTICAST_MESSAGE);
  msg->header.size = htons (sizeof (*msg) + buf_size);
  msg->message_id = GNUNET_htonll (mh->message_id);
  msg->group_generation = mh->group_generation;

  /* FIXME: add fragment ID and signature in the service instead of here */
  msg->fragment_id = GNUNET_ntohll (orig->next_fragment_id++);
  msg->fragment_offset = GNUNET_ntohll (mh->fragment_offset);
  mh->fragment_offset += sizeof (*msg) + buf_size;
  msg->purpose.size = htonl (sizeof (*msg) + buf_size
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

  /* FIXME: send msg to the service and only then call handle_multicast_message
   *        with the returned signed message.
   */
  handle_multicast_message (&orig->grp, msg);

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

  /* FIXME: remove delay, it's there only for testing */
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
                              GNUNET_MULTICAST_MembershipTestCallback member_test_cb,
                              GNUNET_MULTICAST_ReplayFragmentCallback replay_frag_cb,
                              GNUNET_MULTICAST_ReplayMessageCallback replay_msg_cb,
                              GNUNET_MULTICAST_MessageCallback message_cb,
                              void *cls)
{
  struct GNUNET_MULTICAST_Member *mem = GNUNET_malloc (sizeof (*mem));
  mem->group_key = *group_key;
  mem->member_key = *member_key;
  mem->origin = *origin;
  mem->relay_count = relay_count;
  mem->relays = *relays;
  mem->join_cb = join_cb;
  mem->member_test_cb = member_test_cb;
  mem->replay_frag_cb = replay_frag_cb;
  mem->message_cb = message_cb;
  mem->cls = cls;

  if (NULL != join_request)
  {
    uint16_t size = ntohs (join_request->size);
    mem->join_request = GNUNET_malloc (size);
    memcpy (mem->join_request, join_request, size);
  }

  GNUNET_CRYPTO_hash (&mem->group_key, sizeof (mem->group_key), &mem->group_key_hash);

  if (NULL == members)
    members = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);

  GNUNET_CONTAINER_multihashmap_put (members, &mem->group_key_hash, mem,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);

  /* FIXME: send MEMBER_JOIN to service */

  return mem;
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
GNUNET_MULTICAST_member_part (struct GNUNET_MULTICAST_Member *mem)
{
  GNUNET_CONTAINER_multihashmap_remove (members, &mem->group_key_hash, mem);
  GNUNET_free (mem);
}


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


/* FIXME: for now just send back to the client what it sent. */
static void
schedule_member_to_origin (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "schedule_member_to_origin()\n");
  struct GNUNET_MULTICAST_Member *mem = cls;
  struct GNUNET_MULTICAST_MemberRequestHandle *rh = &mem->req_handle;

  size_t buf_size = GNUNET_MULTICAST_FRAGMENT_MAX_PAYLOAD;
  char buf[GNUNET_MULTICAST_FRAGMENT_MAX_PAYLOAD] = "";
  struct GNUNET_MULTICAST_RequestHeader *req
    = (struct GNUNET_MULTICAST_RequestHeader *) buf;
  int ret = rh->notify (rh->notify_cls, &buf_size, &req[1]);

  if (! (GNUNET_YES == ret || GNUNET_NO == ret)
      || GNUNET_MULTICAST_FRAGMENT_MAX_PAYLOAD < buf_size)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "MemberTransmitNotify() returned error or invalid message size.\n");
    /* FIXME: handle error */
    return;
  }

  if (GNUNET_NO == ret && 0 == buf_size)
    return; /* Transmission paused. */

  req->header.type = htons (GNUNET_MESSAGE_TYPE_MULTICAST_REQUEST);
  req->header.size = htons (sizeof (*req) + buf_size);
  req->request_id = GNUNET_htonll (rh->request_id);

  /* FIXME: add fragment ID and signature in the service instead of here */
  req->fragment_id = GNUNET_ntohll (mem->next_fragment_id++);
  req->fragment_offset = GNUNET_ntohll (rh->fragment_offset);
  rh->fragment_offset += sizeof (*req) + buf_size;
  req->purpose.size = htonl (sizeof (*req) + buf_size
                             - sizeof (req->header)
                             - sizeof (req->member_key)
                             - sizeof (req->signature));
  req->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_MULTICAST_MESSAGE);

  if (GNUNET_OK != GNUNET_CRYPTO_eddsa_sign (&mem->member_key, &req->purpose,
                                           &req->signature))
  {
    /* FIXME: handle error */
    return;
  }

  /* FIXME: send req to the service and only then call handle_multicast_request
   *        with the returned request.
   */
  handle_multicast_request (&mem->group_key_hash, req);

  if (GNUNET_NO == ret)
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                  (GNUNET_TIME_UNIT_SECONDS, 1),
                                  schedule_member_to_origin, mem);
}


/**
 * Send a message to the origin of the multicast group.
 *
 * @param member Membership handle.
 * @param request_id Application layer ID for the request.  Opaque to multicast.
 * @param notify Callback to call to get the message.
 * @param notify_cls Closure for @a notify.
 * @return Handle to cancel request, NULL on error (i.e. request already pending).
 */
struct GNUNET_MULTICAST_MemberRequestHandle *
GNUNET_MULTICAST_member_to_origin (struct GNUNET_MULTICAST_Member *member,
                                   uint64_t request_id,
                                   GNUNET_MULTICAST_MemberTransmitNotify notify,
                                   void *notify_cls)
{
  struct GNUNET_MULTICAST_MemberRequestHandle *rh = &member->req_handle;
  rh->member = member;
  rh->request_id = request_id;
  rh->notify = notify;
  rh->notify_cls = notify_cls;

  /* FIXME: remove delay, it's there only for testing */
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                (GNUNET_TIME_UNIT_SECONDS, 1),
                                schedule_member_to_origin, member);
  return &member->req_handle;
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
