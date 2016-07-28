/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2013 GNUnet e.V.

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file multicast/multicast_api.c
 * @brief Multicast service; implements multicast groups using CADET connections.
 * @author Christian Grothoff
 * @author Gabor X Toth
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_multicast_service.h"
#include "multicast.h"

#define LOG(kind,...) GNUNET_log_from (kind, "multicast-api",__VA_ARGS__)


/**
 * Handle for a request to send a message to all multicast group members
 * (from the origin).
 */
struct GNUNET_MULTICAST_OriginTransmitHandle
{
  GNUNET_MULTICAST_OriginTransmitNotify notify;
  void *notify_cls;
  struct GNUNET_MULTICAST_Origin *origin;

  uint64_t message_id;
  uint64_t group_generation;
  uint64_t fragment_offset;
};


/**
 * Handle for a message to be delivered from a member to the origin.
 */
struct GNUNET_MULTICAST_MemberTransmitHandle
{
  GNUNET_MULTICAST_MemberTransmitNotify notify;
  void *notify_cls;
  struct GNUNET_MULTICAST_Member *member;

  uint64_t request_id;
  uint64_t fragment_offset;
};


struct GNUNET_MULTICAST_Group
{
  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Client connection to the service.
   */
  struct GNUNET_CLIENT_MANAGER_Connection *client;

  /**
   * Message to send on reconnect.
   */
  struct GNUNET_MessageHeader *connect_msg;

  GNUNET_MULTICAST_JoinRequestCallback join_req_cb;
  GNUNET_MULTICAST_ReplayFragmentCallback replay_frag_cb;
  GNUNET_MULTICAST_ReplayMessageCallback replay_msg_cb;
  GNUNET_MULTICAST_MessageCallback message_cb;
  void *cb_cls;

  /**
   * Function called after disconnected from the service.
   */
  GNUNET_ContinuationCallback disconnect_cb;

  /**
   * Closure for @a disconnect_cb.
   */
  void *disconnect_cls;

  /**
   * Are we currently transmitting a message?
   */
  uint8_t in_transmit;

  /**
   * Number of MULTICAST_FRAGMENT_ACK messages we are still waiting for.
   */
  uint8_t acks_pending;

  /**
   * Is this the origin or a member?
   */
  uint8_t is_origin;

  /**
   * Is this channel in the process of disconnecting from the service?
   * #GNUNET_YES or #GNUNET_NO
   */
  uint8_t is_disconnecting;
};


/**
 * Handle for the origin of a multicast group.
 */
struct GNUNET_MULTICAST_Origin
{
  struct GNUNET_MULTICAST_Group grp;
  struct GNUNET_MULTICAST_OriginTransmitHandle tmit;

  GNUNET_MULTICAST_RequestCallback request_cb;
};


/**
 * Handle for a multicast group member.
 */
struct GNUNET_MULTICAST_Member
{
  struct GNUNET_MULTICAST_Group grp;
  struct GNUNET_MULTICAST_MemberTransmitHandle tmit;

  GNUNET_MULTICAST_JoinDecisionCallback join_dcsn_cb;

  /**
   * Replay fragment -> struct GNUNET_MULTICAST_MemberReplayHandle *
   */
  struct GNUNET_CONTAINER_MultiHashMap *replay_reqs;

  uint64_t next_fragment_id;
};


/**
 * Handle that identifies a join request.
 *
 * Used to match calls to #GNUNET_MULTICAST_JoinRequestCallback to the
 * corresponding calls to #GNUNET_MULTICAST_join_decision().
 */
struct GNUNET_MULTICAST_JoinHandle
{
  struct GNUNET_MULTICAST_Group *group;

  /**
   * Public key of the member requesting join.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey member_pub_key;

  /**
   * Peer identity of the member requesting join.
   */
  struct GNUNET_PeerIdentity peer;
};


/**
 * Opaque handle to a replay request from the multicast service.
 */
struct GNUNET_MULTICAST_ReplayHandle
{
  struct GNUNET_MULTICAST_Group *grp;
  struct MulticastReplayRequestMessage req;
};


/**
 * Handle for a replay request.
 */
struct GNUNET_MULTICAST_MemberReplayHandle
{
};


static void
origin_to_all (struct GNUNET_MULTICAST_Origin *orig);

static void
member_to_origin (struct GNUNET_MULTICAST_Member *mem);


/**
 * Send first message to the service after connecting.
 */
static void
group_send_connect_msg (struct GNUNET_MULTICAST_Group *grp)
{
  uint16_t cmsg_size = ntohs (grp->connect_msg->size);
  struct GNUNET_MessageHeader *cmsg = GNUNET_malloc (cmsg_size);
  GNUNET_memcpy (cmsg, grp->connect_msg, cmsg_size);
  GNUNET_CLIENT_MANAGER_transmit_now (grp->client, cmsg);
  GNUNET_free (cmsg);
}


/**
 * Got disconnected from service.  Reconnect.
 */
static void
group_recv_disconnect (void *cls,
                        struct GNUNET_CLIENT_MANAGER_Connection *client,
                        const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_MULTICAST_Group *
    grp = GNUNET_CLIENT_MANAGER_get_user_context_ (client, sizeof (*grp));
  GNUNET_CLIENT_MANAGER_reconnect (client);
  group_send_connect_msg (grp);
}


/**
 * Receive join request from service.
 */
static void
group_recv_join_request (void *cls,
                          struct GNUNET_CLIENT_MANAGER_Connection *client,
                          const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_MULTICAST_Group *grp;
  const struct MulticastJoinRequestMessage *jreq;
  struct GNUNET_MULTICAST_JoinHandle *jh;
  const struct GNUNET_MessageHeader *jmsg;

  grp = GNUNET_CLIENT_MANAGER_get_user_context_ (client, sizeof (*grp));
  if (NULL == grp)
  {
    GNUNET_break (0);
    return;
  }
  if (NULL == grp->join_req_cb)
    return;
  /* FIXME: this fails to check that 'msg' is well-formed! */
  jreq = (const struct MulticastJoinRequestMessage *) msg;
  if (sizeof (*jreq) + sizeof (*jmsg) <= ntohs (jreq->header.size))
    jmsg = (const struct GNUNET_MessageHeader *) &jreq[1];
  else
    jmsg = NULL;
  jh = GNUNET_malloc (sizeof (*jh));
  jh->group = grp;
  jh->member_pub_key = jreq->member_pub_key;
  jh->peer = jreq->peer;
  grp->join_req_cb (grp->cb_cls, &jreq->member_pub_key, jmsg, jh);
}


/**
 * Receive multicast message from service.
 */
static void
group_recv_message (void *cls,
                    struct GNUNET_CLIENT_MANAGER_Connection *client,
                    const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_MULTICAST_Group *
    grp = GNUNET_CLIENT_MANAGER_get_user_context_ (client, sizeof (*grp));
  struct GNUNET_MULTICAST_MessageHeader *
    mmsg = (struct GNUNET_MULTICAST_MessageHeader *) msg;

  if (GNUNET_YES == grp->is_disconnecting)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Calling message callback with a message of size %u.\n",
              ntohs (mmsg->header.size));

  if (NULL != grp->message_cb)
    grp->message_cb (grp->cb_cls, mmsg);
}


/**
 * Receive message/request fragment acknowledgement from service.
 */
static void
group_recv_fragment_ack (void *cls,
                         struct GNUNET_CLIENT_MANAGER_Connection *client,
                         const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_MULTICAST_Group *
    grp = GNUNET_CLIENT_MANAGER_get_user_context_ (client, sizeof (*grp));

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%p Got fragment ACK. in_transmit=%u, acks_pending=%u\n",
       grp, grp->in_transmit, grp->acks_pending);

  if (0 == grp->acks_pending)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%p Ignoring extraneous fragment ACK.\n", grp);
    return;
  }
  grp->acks_pending--;

  if (GNUNET_YES != grp->in_transmit)
    return;

  if (GNUNET_YES == grp->is_origin)
    origin_to_all ((struct GNUNET_MULTICAST_Origin *) grp);
  else
    member_to_origin ((struct GNUNET_MULTICAST_Member *) grp);
}

/**
 * Origin receives uniquest request from a member.
 */
static void
origin_recv_request (void *cls,
                     struct GNUNET_CLIENT_MANAGER_Connection *client,
                     const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_MULTICAST_Group *grp;
  struct GNUNET_MULTICAST_Origin *
    orig = GNUNET_CLIENT_MANAGER_get_user_context_ (client, sizeof (*grp));
  grp = &orig->grp;
  struct GNUNET_MULTICAST_RequestHeader *
    req = (struct GNUNET_MULTICAST_RequestHeader *) msg;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Calling request callback with a request of size %u.\n",
              ntohs (req->header.size));

  if (NULL != orig->request_cb)
    orig->request_cb (grp->cb_cls, req);
}


/**
 * Receive multicast replay request from service.
 */
static void
group_recv_replay_request (void *cls,
                           struct GNUNET_CLIENT_MANAGER_Connection *client,
                           const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_MULTICAST_Group *
    grp = GNUNET_CLIENT_MANAGER_get_user_context_ (client, sizeof (*grp));
  struct MulticastReplayRequestMessage *
    rep = (struct MulticastReplayRequestMessage *) msg;

  if (GNUNET_YES == grp->is_disconnecting)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got replay request.\n");

  if (0 != rep->fragment_id)
  {
    if (NULL != grp->replay_frag_cb)
    {
      struct GNUNET_MULTICAST_ReplayHandle * rh = GNUNET_malloc (sizeof (*rh));
      rh->grp = grp;
      rh->req = *rep;
      grp->replay_frag_cb (grp->cb_cls, &rep->member_pub_key,
                           GNUNET_ntohll (rep->fragment_id),
                           GNUNET_ntohll (rep->flags), rh);
    }
  }
  else if (0 != rep->message_id)
  {
    if (NULL != grp->replay_msg_cb)
    {
      struct GNUNET_MULTICAST_ReplayHandle * rh = GNUNET_malloc (sizeof (*rh));
      rh->grp = grp;
      rh->req = *rep;
      grp->replay_msg_cb (grp->cb_cls, &rep->member_pub_key,
                          GNUNET_ntohll (rep->message_id),
                          GNUNET_ntohll (rep->fragment_offset),
                          GNUNET_ntohll (rep->flags), rh);
    }
  }
}


/**
 * Receive multicast replay request from service.
 */
static void
member_recv_replay_response (void *cls,
                            struct GNUNET_CLIENT_MANAGER_Connection *client,
                            const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_MULTICAST_Group *grp;
  struct GNUNET_MULTICAST_Member *
    mem = GNUNET_CLIENT_MANAGER_get_user_context_ (client, sizeof (*grp));
  grp = &mem->grp;
  struct MulticastReplayResponseMessage *
    res = (struct MulticastReplayResponseMessage *) msg;

  if (GNUNET_YES == grp->is_disconnecting)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got replay response.\n");
}

/**
 * Member receives join decision.
 */
static void
member_recv_join_decision (void *cls,
                           struct GNUNET_CLIENT_MANAGER_Connection *client,
                           const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_MULTICAST_Group *grp;
  struct GNUNET_MULTICAST_Member *
    mem = GNUNET_CLIENT_MANAGER_get_user_context_ (client, sizeof (*grp));
  grp = &mem->grp;

  const struct MulticastJoinDecisionMessageHeader *
    hdcsn = (const struct MulticastJoinDecisionMessageHeader *) msg;
  const struct MulticastJoinDecisionMessage *
    dcsn = (const struct MulticastJoinDecisionMessage *) &hdcsn[1];

  uint16_t dcsn_size = ntohs (dcsn->header.size);
  int is_admitted = ntohl (dcsn->is_admitted);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%p Member got join decision from multicast: %d\n",
       mem, is_admitted);

  const struct GNUNET_MessageHeader *join_resp = NULL;
  uint16_t join_resp_size = 0;

  uint16_t relay_count = ntohl (dcsn->relay_count);
  const struct GNUNET_PeerIdentity *relays = NULL;
  uint16_t relay_size = relay_count * sizeof (*relays);
  if (0 < relay_count)
  {
    if (dcsn_size < sizeof (*dcsn) + relay_size)
    {
      GNUNET_break_op (0);
      is_admitted = GNUNET_SYSERR;
    }
    else
    {
      relays = (struct GNUNET_PeerIdentity *) &dcsn[1];
    }
  }

  if (sizeof (*dcsn) + relay_size + sizeof (*join_resp) <= dcsn_size)
  {
    join_resp = (const struct GNUNET_MessageHeader *) ((char *) &dcsn[1] + relay_size);
    join_resp_size = ntohs (join_resp->size);
  }
  if (dcsn_size < sizeof (*dcsn) + relay_size + join_resp_size)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received invalid join decision message from multicast: %u < %u + %u + %u\n",
         dcsn_size , sizeof (*dcsn), relay_size, join_resp_size);
    GNUNET_break_op (0);
    is_admitted = GNUNET_SYSERR;
  }

  if (NULL != mem->join_dcsn_cb)
    mem->join_dcsn_cb (grp->cb_cls, is_admitted, &hdcsn->peer,
                       relay_count, relays, join_resp);

  // FIXME:
  //if (GNUNET_YES != is_admitted)
  //  GNUNET_MULTICAST_member_part (mem);
}


/**
 * Message handlers for an origin.
 */
static struct GNUNET_CLIENT_MANAGER_MessageHandler origin_handlers[] =
{
  { group_recv_disconnect, NULL, 0, 0, GNUNET_NO },

  { group_recv_message, NULL,
    GNUNET_MESSAGE_TYPE_MULTICAST_MESSAGE,
    sizeof (struct GNUNET_MULTICAST_MessageHeader), GNUNET_YES },

  { origin_recv_request, NULL,
    GNUNET_MESSAGE_TYPE_MULTICAST_REQUEST,
    sizeof (struct GNUNET_MULTICAST_RequestHeader), GNUNET_YES },

  { group_recv_fragment_ack, NULL,
    GNUNET_MESSAGE_TYPE_MULTICAST_FRAGMENT_ACK,
    sizeof (struct GNUNET_MessageHeader), GNUNET_YES },

  { group_recv_join_request, NULL,
    GNUNET_MESSAGE_TYPE_MULTICAST_JOIN_REQUEST,
    sizeof (struct MulticastJoinRequestMessage), GNUNET_YES },

  { group_recv_replay_request, NULL,
    GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_REQUEST,
    sizeof (struct MulticastReplayRequestMessage), GNUNET_NO },

  { NULL, NULL, 0, 0, GNUNET_NO }
};


/**
 * Message handlers for a member.
 */
static struct GNUNET_CLIENT_MANAGER_MessageHandler member_handlers[] =
{
  { group_recv_disconnect, NULL, 0, 0, GNUNET_NO },

  { group_recv_message, NULL,
    GNUNET_MESSAGE_TYPE_MULTICAST_MESSAGE,
    sizeof (struct GNUNET_MULTICAST_MessageHeader), GNUNET_YES },

  { group_recv_fragment_ack, NULL,
    GNUNET_MESSAGE_TYPE_MULTICAST_FRAGMENT_ACK,
    sizeof (struct GNUNET_MessageHeader), GNUNET_YES },

  { group_recv_join_request, NULL,
    GNUNET_MESSAGE_TYPE_MULTICAST_JOIN_REQUEST,
    sizeof (struct MulticastJoinRequestMessage), GNUNET_YES },

  { member_recv_join_decision, NULL,
    GNUNET_MESSAGE_TYPE_MULTICAST_JOIN_DECISION,
    sizeof (struct MulticastJoinDecisionMessage), GNUNET_YES },

  { group_recv_replay_request, NULL,
    GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_REQUEST,
    sizeof (struct MulticastReplayRequestMessage), GNUNET_NO },

  { member_recv_replay_response, NULL,
    GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_RESPONSE,
    sizeof (struct MulticastReplayRequestMessage), GNUNET_NO },

  { NULL, NULL, 0, 0, GNUNET_NO }
};


static void
group_cleanup (struct GNUNET_MULTICAST_Group *grp)
{
  GNUNET_free (grp->connect_msg);
  if (NULL != grp->disconnect_cb)
    grp->disconnect_cb (grp->disconnect_cls);
}


static void
origin_cleanup (void *cls)
{
  struct GNUNET_MULTICAST_Origin *orig = cls;
  group_cleanup (&orig->grp);
  GNUNET_free (orig);
}


static void
member_cleanup (void *cls)
{
  struct GNUNET_MULTICAST_Member *mem = cls;
  group_cleanup (&mem->grp);
  GNUNET_free (mem);
}


/**
 * Function to call with the decision made for a join request.
 *
 * Must be called once and only once in response to an invocation of the
 * #GNUNET_MULTICAST_JoinRequestCallback.
 *
 * @param join
 *        Join request handle.
 * @param is_admitted
 *        #GNUNET_YES    if the join is approved,
 *        #GNUNET_NO     if it is disapproved,
 *        #GNUNET_SYSERR if we cannot answer the request.
 * @param relay_count
 *        Number of relays given.
 * @param relays
 *        Array of suggested peers that might be useful relays to use
 *        when joining the multicast group (essentially a list of peers that
 *        are already part of the multicast group and might thus be willing
 *        to help with routing).  If empty, only this local peer (which must
 *        be the multicast origin) is a good candidate for building the
 *        multicast tree.  Note that it is unnecessary to specify our own
 *        peer identity in this array.
 * @param join_resp
 *        Message to send in response to the joining peer;
 *        can also be used to redirect the peer to a different group at the
 *        application layer; this response is to be transmitted to the
 *        peer that issued the request even if admission is denied.
 */
struct GNUNET_MULTICAST_ReplayHandle *
GNUNET_MULTICAST_join_decision (struct GNUNET_MULTICAST_JoinHandle *join,
                                int is_admitted,
                                uint16_t relay_count,
                                const struct GNUNET_PeerIdentity *relays,
                                const struct GNUNET_MessageHeader *join_resp)
{
  struct GNUNET_MULTICAST_Group *grp = join->group;
  uint16_t join_resp_size = (NULL != join_resp) ? ntohs (join_resp->size) : 0;
  uint16_t relay_size = relay_count * sizeof (*relays);

  struct MulticastJoinDecisionMessageHeader * hdcsn;
  struct MulticastJoinDecisionMessage *dcsn;
  hdcsn = GNUNET_malloc (sizeof (*hdcsn) + sizeof (*dcsn)
                         + relay_size + join_resp_size);
  hdcsn->header.size = htons (sizeof (*hdcsn) + sizeof (*dcsn)
                              + relay_size + join_resp_size);
  hdcsn->header.type = htons (GNUNET_MESSAGE_TYPE_MULTICAST_JOIN_DECISION);
  hdcsn->member_pub_key = join->member_pub_key;
  hdcsn->peer = join->peer;

  dcsn = (struct MulticastJoinDecisionMessage *) &hdcsn[1];
  dcsn->header.type = htons (GNUNET_MESSAGE_TYPE_MULTICAST_JOIN_DECISION);
  dcsn->header.size = htons (sizeof (*dcsn) + relay_size + join_resp_size);
  dcsn->is_admitted = htonl (is_admitted);
  dcsn->relay_count = htonl (relay_count);
  if (0 < relay_size)
    GNUNET_memcpy (&dcsn[1], relays, relay_size);
  if (0 < join_resp_size)
    GNUNET_memcpy (((char *) &dcsn[1]) + relay_size, join_resp, join_resp_size);

  GNUNET_CLIENT_MANAGER_transmit (grp->client, &hdcsn->header);
  GNUNET_free (hdcsn);
  GNUNET_free (join);
  return NULL;
}


/**
 * Replay a message fragment for the multicast group.
 *
 * @param rh
 *        Replay handle identifying which replay operation was requested.
 * @param msg
 *        Replayed message fragment, NULL if not found / an error occurred.
 * @param ec
 *        Error code.  See enum GNUNET_MULTICAST_ReplayErrorCode
 *        If not #GNUNET_MULTICAST_REC_OK, the replay handle is invalidated.
 */
void
GNUNET_MULTICAST_replay_response (struct GNUNET_MULTICAST_ReplayHandle *rh,
                                  const struct GNUNET_MessageHeader *msg,
                                  enum GNUNET_MULTICAST_ReplayErrorCode ec)
{
  uint8_t msg_size = (NULL != msg) ? ntohs (msg->size) : 0;
  struct MulticastReplayResponseMessage *
    res = GNUNET_malloc (sizeof (*res) + msg_size);
  *res = (struct MulticastReplayResponseMessage) {
    .header = {
      .type = htons (GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_RESPONSE),
      .size = htons (sizeof (*res) + msg_size),
    },
    .fragment_id = rh->req.fragment_id,
    .message_id = rh->req.message_id,
    .fragment_offset = rh->req.fragment_offset,
    .flags = rh->req.flags,
    .error_code = htonl (ec),
  };

  if (GNUNET_MULTICAST_REC_OK == ec)
  {
    GNUNET_assert (NULL != msg);
    GNUNET_memcpy (&res[1], msg, msg_size);
  }

  GNUNET_CLIENT_MANAGER_transmit (rh->grp->client, &res->header);
  GNUNET_free (res);

  if (GNUNET_MULTICAST_REC_OK != ec)
    GNUNET_free (rh);
}


/**
 * Indicate the end of the replay session.
 *
 * Invalidates the replay handle.
 *
 * @param rh
 *        Replay session to end.
 */
void
GNUNET_MULTICAST_replay_response_end (struct GNUNET_MULTICAST_ReplayHandle *rh)
{
  struct MulticastReplayResponseMessage end = {
    .header = {
      .type = htons (GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_RESPONSE_END),
      .size = htons (sizeof (end)),
    },
    .fragment_id = rh->req.fragment_id,
    .message_id = rh->req.message_id,
    .fragment_offset = rh->req.fragment_offset,
    .flags = rh->req.flags,
  };

  GNUNET_CLIENT_MANAGER_transmit (rh->grp->client, &end.header);
  GNUNET_free (rh);
}


/**
 * Replay a message for the multicast group.
 *
 * @param rh
 *        Replay handle identifying which replay operation was requested.
 * @param notify
 *        Function to call to get the message.
 * @param notify_cls
 *        Closure for @a notify.
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
 * @param cfg
 *        Configuration to use.
 * @param priv_key
 *        ECC key that will be used to sign messages for this
 *        multicast session; public key is used to identify the multicast group;
 * @param max_fragment_id
 *        Maximum fragment ID already sent to the group.
 *        0 for a new group.
 * @param join_request_cb
 *        Function called to approve / disapprove joining of a peer.
 * @param replay_frag_cb
 *        Function that can be called to replay a message fragment.
 * @param replay_msg_cb
 *        Function that can be called to replay a message.
 * @param request_cb
 *        Function called with message fragments from group members.
 * @param message_cb
 *        Function called with the message fragments sent to the
 *        network by GNUNET_MULTICAST_origin_to_all().  These message fragments
 *        should be stored for answering replay requests later.
 * @param cls
 *        Closure for the various callbacks that follow.
 *
 * @return Handle for the origin, NULL on error.
 */
struct GNUNET_MULTICAST_Origin *
GNUNET_MULTICAST_origin_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
                               const struct GNUNET_CRYPTO_EddsaPrivateKey *priv_key,
                               uint64_t max_fragment_id,
                               GNUNET_MULTICAST_JoinRequestCallback join_request_cb,
                               GNUNET_MULTICAST_ReplayFragmentCallback replay_frag_cb,
                               GNUNET_MULTICAST_ReplayMessageCallback replay_msg_cb,
                               GNUNET_MULTICAST_RequestCallback request_cb,
                               GNUNET_MULTICAST_MessageCallback message_cb,
                               void *cls)
{
  struct GNUNET_MULTICAST_Origin *orig = GNUNET_malloc (sizeof (*orig));
  struct GNUNET_MULTICAST_Group *grp = &orig->grp;
  struct MulticastOriginStartMessage *start = GNUNET_malloc (sizeof (*start));

  start->header.type = htons (GNUNET_MESSAGE_TYPE_MULTICAST_ORIGIN_START);
  start->header.size = htons (sizeof (*start));
  start->max_fragment_id = max_fragment_id;
  GNUNET_memcpy (&start->group_key, priv_key, sizeof (*priv_key));

  grp->connect_msg = (struct GNUNET_MessageHeader *) start;
  grp->is_origin = GNUNET_YES;
  grp->cfg = cfg;

  grp->cb_cls = cls;
  grp->join_req_cb = join_request_cb;
  grp->replay_frag_cb = replay_frag_cb;
  grp->replay_msg_cb = replay_msg_cb;
  grp->message_cb = message_cb;

  orig->request_cb = request_cb;

  grp->client = GNUNET_CLIENT_MANAGER_connect (cfg, "multicast", origin_handlers);
  GNUNET_CLIENT_MANAGER_set_user_context_ (grp->client, orig, sizeof (*grp));
  group_send_connect_msg (grp);

  return orig;
}


/**
 * Stop a multicast group.
 *
 * @param origin
 *        Multicast group to stop.
 */
void
GNUNET_MULTICAST_origin_stop (struct GNUNET_MULTICAST_Origin *orig,
                              GNUNET_ContinuationCallback stop_cb,
                              void *stop_cls)
{
  struct GNUNET_MULTICAST_Group *grp = &orig->grp;

  grp->is_disconnecting = GNUNET_YES;
  grp->disconnect_cb = stop_cb;
  grp->disconnect_cls = stop_cls;

  GNUNET_CLIENT_MANAGER_disconnect (orig->grp.client, GNUNET_YES,
                                    &origin_cleanup, orig);
}


static void
origin_to_all (struct GNUNET_MULTICAST_Origin *orig)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "%p origin_to_all()\n", orig);
  struct GNUNET_MULTICAST_Group *grp = &orig->grp;
  struct GNUNET_MULTICAST_OriginTransmitHandle *tmit = &orig->tmit;
  GNUNET_assert (GNUNET_YES == grp->in_transmit);

  size_t buf_size = GNUNET_MULTICAST_FRAGMENT_MAX_SIZE;
  struct GNUNET_MULTICAST_MessageHeader *msg = GNUNET_malloc (buf_size);
  int ret = tmit->notify (tmit->notify_cls, &buf_size, &msg[1]);

  if (! (GNUNET_YES == ret || GNUNET_NO == ret)
      || GNUNET_MULTICAST_FRAGMENT_MAX_SIZE < buf_size)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "%p OriginTransmitNotify() returned error or invalid message size.\n",
         orig);
    /* FIXME: handle error */
    GNUNET_free (msg);
    return;
  }

  if (GNUNET_NO == ret && 0 == buf_size)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%p OriginTransmitNotify() - transmission paused.\n", orig);
    GNUNET_free (msg);
    return; /* Transmission paused. */
  }

  msg->header.type = htons (GNUNET_MESSAGE_TYPE_MULTICAST_MESSAGE);
  msg->header.size = htons (sizeof (*msg) + buf_size);
  msg->message_id = GNUNET_htonll (tmit->message_id);
  msg->group_generation = tmit->group_generation;
  msg->fragment_offset = GNUNET_htonll (tmit->fragment_offset);
  tmit->fragment_offset += sizeof (*msg) + buf_size;

  grp->acks_pending++;
  GNUNET_CLIENT_MANAGER_transmit (grp->client, &msg->header);
  GNUNET_free (msg);

  if (GNUNET_YES == ret)
    grp->in_transmit = GNUNET_NO;
}


/**
 * Send a message to the multicast group.
 *
 * @param orig
 *        Handle to the multicast group.
 * @param message_id
 *        Application layer ID for the message.  Opaque to multicast.
 * @param group_generation
 *        Group generation of the message.
 *        Documented in struct GNUNET_MULTICAST_MessageHeader.
 * @param notify
 *        Function to call to get the message.
 * @param notify_cls
 *        Closure for @a notify.
 *
 * @return Message handle on success,
 *         NULL on error (i.e. another request is already pending).
 */
struct GNUNET_MULTICAST_OriginTransmitHandle *
GNUNET_MULTICAST_origin_to_all (struct GNUNET_MULTICAST_Origin *orig,
                                uint64_t message_id,
                                uint64_t group_generation,
                                GNUNET_MULTICAST_OriginTransmitNotify notify,
                                void *notify_cls)
{
  struct GNUNET_MULTICAST_Group *grp = &orig->grp;
  if (GNUNET_YES == grp->in_transmit)
    return NULL;
  grp->in_transmit = GNUNET_YES;

  struct GNUNET_MULTICAST_OriginTransmitHandle *tmit = &orig->tmit;
  tmit->origin = orig;
  tmit->message_id = message_id;
  tmit->fragment_offset = 0;
  tmit->group_generation = group_generation;
  tmit->notify = notify;
  tmit->notify_cls = notify_cls;

  origin_to_all (orig);
  return tmit;
}


/**
 * Resume message transmission to multicast group.
 *
 * @param th
 *        Transmission to cancel.
 */
void
GNUNET_MULTICAST_origin_to_all_resume (struct GNUNET_MULTICAST_OriginTransmitHandle *th)
{
  struct GNUNET_MULTICAST_Group *grp = &th->origin->grp;
  if (0 != grp->acks_pending || GNUNET_YES != grp->in_transmit)
    return;
  origin_to_all (th->origin);
}


/**
 * Cancel request for message transmission to multicast group.
 *
 * @param th
 *        Transmission to cancel.
 */
void
GNUNET_MULTICAST_origin_to_all_cancel (struct GNUNET_MULTICAST_OriginTransmitHandle *th)
{
  th->origin->grp.in_transmit = GNUNET_NO;
}


/**
 * Join a multicast group.
 *
 * The entity joining is always the local peer.  Further information about the
 * candidate can be provided in the @a join_request message.  If the join fails, the
 * @a message_cb is invoked with a (failure) response and then with NULL.  If
 * the join succeeds, outstanding (state) messages and ongoing multicast
 * messages will be given to the @a message_cb until the member decides to part
 * the group.  The @a replay_cb function may be called at any time by the
 * multicast service to support relaying messages to other members of the group.
 *
 * @param cfg
 *        Configuration to use.
 * @param group_key
 *        ECC public key that identifies the group to join.
 * @param member_key
 *        ECC key that identifies the member
 *        and used to sign requests sent to the origin.
 * @param origin
 *        Peer ID of the origin to send unicast requsets to.  If NULL,
 *        unicast requests are sent back via multiple hops on the reverse path
 *        of multicast messages.
 * @param relay_count
 *        Number of peers in the @a relays array.
 * @param relays
 *        Peer identities of members of the group, which serve as relays
 *        and can be used to join the group at. and send the @a join_request to.
 *        If empty, the @a join_request is sent directly to the @a origin.
 * @param join_msg
 *        Application-dependent join message to be passed to the peer @a origin.
 * @param join_request_cb
 *        Function called to approve / disapprove joining of a peer.
 * @param join_decision_cb
 *        Function called to inform about the join decision.
 * @param replay_frag_cb
 *        Function that can be called to replay message fragments
 *        this peer already knows from this group. NULL if this
 *        client is unable to support replay.
 * @param replay_msg_cb
 *        Function that can be called to replay message fragments
 *        this peer already knows from this group. NULL if this
 *        client is unable to support replay.
 * @param message_cb
 *        Function to be called for all message fragments we
 *        receive from the group, excluding those our @a replay_cb
 *        already has.
 * @param cls
 *        Closure for callbacks.
 *
 * @return Handle for the member, NULL on error.
 */
struct GNUNET_MULTICAST_Member *
GNUNET_MULTICAST_member_join (const struct GNUNET_CONFIGURATION_Handle *cfg,
                              const struct GNUNET_CRYPTO_EddsaPublicKey *group_pub_key,
                              const struct GNUNET_CRYPTO_EcdsaPrivateKey *member_key,
                              const struct GNUNET_PeerIdentity *origin,
                              uint16_t relay_count,
                              const struct GNUNET_PeerIdentity *relays,
                              const struct GNUNET_MessageHeader *join_msg,
                              GNUNET_MULTICAST_JoinRequestCallback join_request_cb,
                              GNUNET_MULTICAST_JoinDecisionCallback join_decision_cb,
                              GNUNET_MULTICAST_ReplayFragmentCallback replay_frag_cb,
                              GNUNET_MULTICAST_ReplayMessageCallback replay_msg_cb,
                              GNUNET_MULTICAST_MessageCallback message_cb,
                              void *cls)
{
  struct GNUNET_MULTICAST_Member *mem = GNUNET_malloc (sizeof (*mem));
  struct GNUNET_MULTICAST_Group *grp = &mem->grp;

  uint16_t relay_size = relay_count * sizeof (*relays);
  uint16_t join_msg_size = (NULL != join_msg) ? ntohs (join_msg->size) : 0;
  struct MulticastMemberJoinMessage *
    join = GNUNET_malloc (sizeof (*join) + relay_size + join_msg_size);
  join->header.size = htons (sizeof (*join) + relay_size + join_msg_size);
  join->header.type = htons (GNUNET_MESSAGE_TYPE_MULTICAST_MEMBER_JOIN);
  join->group_pub_key = *group_pub_key;
  join->member_key = *member_key;
  join->origin = *origin;
  join->relay_count = ntohl (relay_count);
  if (0 < relay_size)
    GNUNET_memcpy (&join[1], relays, relay_size);
  if (0 < join_msg_size)
    GNUNET_memcpy (((char *) &join[1]) + relay_size, join_msg, join_msg_size);

  grp->connect_msg = (struct GNUNET_MessageHeader *) join;
  grp->is_origin = GNUNET_NO;
  grp->cfg = cfg;

  mem->join_dcsn_cb = join_decision_cb;
  grp->join_req_cb = join_request_cb;
  grp->replay_frag_cb = replay_frag_cb;
  grp->replay_msg_cb = replay_msg_cb;
  grp->message_cb = message_cb;
  grp->cb_cls = cls;

  grp->client = GNUNET_CLIENT_MANAGER_connect (cfg, "multicast", member_handlers);
  GNUNET_CLIENT_MANAGER_set_user_context_ (grp->client, mem, sizeof (*grp));
  group_send_connect_msg (grp);

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
 * @param member
 *        Membership handle.
 */
void
GNUNET_MULTICAST_member_part (struct GNUNET_MULTICAST_Member *mem,
                              GNUNET_ContinuationCallback part_cb,
                              void *part_cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%p Member parting.\n", mem);
  struct GNUNET_MULTICAST_Group *grp = &mem->grp;

  grp->is_disconnecting = GNUNET_YES;
  grp->disconnect_cb = part_cb;
  grp->disconnect_cls = part_cls;

  mem->join_dcsn_cb = NULL;
  grp->join_req_cb = NULL;
  grp->message_cb = NULL;
  grp->replay_msg_cb = NULL;
  grp->replay_frag_cb = NULL;

  GNUNET_CLIENT_MANAGER_disconnect (mem->grp.client, GNUNET_YES,
                                    member_cleanup, mem);
}


void
member_replay_request (struct GNUNET_MULTICAST_Member *mem,
                       uint64_t fragment_id,
                       uint64_t message_id,
                       uint64_t fragment_offset,
                       uint64_t flags)
{
  struct MulticastReplayRequestMessage rep = {
    .header = {
      .type = htons (GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_REQUEST),
      .size = htons (sizeof (rep)),
    },
    .fragment_id = GNUNET_htonll (fragment_id),
    .message_id = GNUNET_htonll (message_id),
    .fragment_offset = GNUNET_htonll (fragment_offset),
    .flags = GNUNET_htonll (flags),
  };
  GNUNET_CLIENT_MANAGER_transmit (mem->grp.client, &rep.header);
}


/**
 * Request a fragment to be replayed by fragment ID.
 *
 * Useful if messages below the @e max_known_fragment_id given when joining are
 * needed and not known to the client.
 *
 * @param member
 *        Membership handle.
 * @param fragment_id
 *        ID of a message fragment that this client would like to see replayed.
 * @param flags
 *        Additional flags for the replay request.
 *        It is used and defined by GNUNET_MULTICAST_ReplayFragmentCallback
 *
 * @return Replay request handle.
 */
struct GNUNET_MULTICAST_MemberReplayHandle *
GNUNET_MULTICAST_member_replay_fragment (struct GNUNET_MULTICAST_Member *mem,
                                         uint64_t fragment_id,
                                         uint64_t flags)
{
  member_replay_request (mem, fragment_id, 0, 0, flags);
  // FIXME: return something useful
  return NULL;
}


/**
 * Request a message fragment to be replayed.
 *
 * Useful if messages below the @e max_known_fragment_id given when joining are
 * needed and not known to the client.
 *
 * @param member
 *        Membership handle.
 * @param message_id
 *        ID of the message this client would like to see replayed.
 * @param fragment_offset
 *        Offset of the fragment within the message to replay.
 * @param flags
 *        Additional flags for the replay request.
 *        It is used & defined by GNUNET_MULTICAST_ReplayMessageCallback
 *
 * @return Replay request handle, NULL on error.
 */
struct GNUNET_MULTICAST_MemberReplayHandle *
GNUNET_MULTICAST_member_replay_message (struct GNUNET_MULTICAST_Member *mem,
                                        uint64_t message_id,
                                        uint64_t fragment_offset,
                                        uint64_t flags)
{
  member_replay_request (mem, 0, message_id, fragment_offset, flags);
  // FIXME: return something useful
  return NULL;
}


static void
member_to_origin (struct GNUNET_MULTICAST_Member *mem)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "member_to_origin()\n");
  struct GNUNET_MULTICAST_Group *grp = &mem->grp;
  struct GNUNET_MULTICAST_MemberTransmitHandle *tmit = &mem->tmit;
  GNUNET_assert (GNUNET_YES == grp->in_transmit);

  size_t buf_size = GNUNET_MULTICAST_FRAGMENT_MAX_SIZE;
  struct GNUNET_MULTICAST_RequestHeader *req = GNUNET_malloc (buf_size);
  int ret = tmit->notify (tmit->notify_cls, &buf_size, &req[1]);

  if (! (GNUNET_YES == ret || GNUNET_NO == ret)
      || GNUNET_MULTICAST_FRAGMENT_MAX_SIZE < buf_size)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "MemberTransmitNotify() returned error or invalid message size. "
         "ret=%d, buf_size=%u\n", ret, buf_size);
    /* FIXME: handle error */
    GNUNET_free (req);
    return;
  }

  if (GNUNET_NO == ret && 0 == buf_size)
  {
    /* Transmission paused. */
    GNUNET_free (req);
    return;
  }

  req->header.type = htons (GNUNET_MESSAGE_TYPE_MULTICAST_REQUEST);
  req->header.size = htons (sizeof (*req) + buf_size);
  req->request_id = GNUNET_htonll (tmit->request_id);
  req->fragment_offset = GNUNET_ntohll (tmit->fragment_offset);
  tmit->fragment_offset += sizeof (*req) + buf_size;

  GNUNET_CLIENT_MANAGER_transmit (grp->client, &req->header);
  GNUNET_free (req);

  if (GNUNET_YES == ret)
    grp->in_transmit = GNUNET_NO;
}


/**
 * Send a message to the origin of the multicast group.
 *
 * @param mem
 *        Membership handle.
 * @param request_id
 *        Application layer ID for the request.  Opaque to multicast.
 * @param notify
 *        Callback to call to get the message.
 * @param notify_cls
 *        Closure for @a notify.
 *
 * @return Handle to cancel request, NULL on error (i.e. request already pending).
 */
struct GNUNET_MULTICAST_MemberTransmitHandle *
GNUNET_MULTICAST_member_to_origin (struct GNUNET_MULTICAST_Member *mem,
                                   uint64_t request_id,
                                   GNUNET_MULTICAST_MemberTransmitNotify notify,
                                   void *notify_cls)
{
  if (GNUNET_YES == mem->grp.in_transmit)
    return NULL;
  mem->grp.in_transmit = GNUNET_YES;

  struct GNUNET_MULTICAST_MemberTransmitHandle *tmit = &mem->tmit;
  tmit->member = mem;
  tmit->request_id = request_id;
  tmit->fragment_offset = 0;
  tmit->notify = notify;
  tmit->notify_cls = notify_cls;

  member_to_origin (mem);
  return tmit;
}


/**
 * Resume message transmission to origin.
 *
 * @param th
 *        Transmission to cancel.
 */
void
GNUNET_MULTICAST_member_to_origin_resume (struct GNUNET_MULTICAST_MemberTransmitHandle *th)
{
  struct GNUNET_MULTICAST_Group *grp = &th->member->grp;
  if (0 != grp->acks_pending || GNUNET_YES != grp->in_transmit)
    return;
  member_to_origin (th->member);
}


/**
 * Cancel request for message transmission to origin.
 *
 * @param th
 *        Transmission to cancel.
 */
void
GNUNET_MULTICAST_member_to_origin_cancel (struct GNUNET_MULTICAST_MemberTransmitHandle *th)
{
  th->member->grp.in_transmit = GNUNET_NO;
}


/* end of multicast_api.c */
