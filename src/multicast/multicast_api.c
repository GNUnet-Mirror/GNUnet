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
  struct GNUNET_MQ_Handle *mq;

  /**
   * Message to send on connect.
   */
  struct GNUNET_MQ_Envelope *connect_env;

  /**
   * Time to wait until we try to reconnect on failure.
   */
  struct GNUNET_TIME_Relative reconnect_delay;

  /**
   * Task for reconnecting when the listener fails.
   */
  struct GNUNET_SCHEDULER_Task *reconnect_task;

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
 * Check join request message.
 */
static int
check_group_join_request (void *cls,
                          const struct MulticastJoinRequestMessage *jreq)
{
  uint16_t size = ntohs (jreq->header.size);

  if (sizeof (*jreq) == size)
    return GNUNET_OK;

  if (sizeof (*jreq) + sizeof (struct GNUNET_MessageHeader) <= size)
    return GNUNET_OK;

  return GNUNET_SYSERR;
}


/**
 * Receive join request from service.
 */
static void
handle_group_join_request (void *cls,
                           const struct MulticastJoinRequestMessage *jreq)
{
  struct GNUNET_MULTICAST_Group *grp = cls;
  struct GNUNET_MULTICAST_JoinHandle *jh;
  const struct GNUNET_MessageHeader *jmsg = NULL;

  if (NULL == grp)
  {
    GNUNET_break (0);
    return;
  }
  if (NULL == grp->join_req_cb)
    return;

  if (sizeof (*jreq) + sizeof (*jmsg) <= ntohs (jreq->header.size))
    jmsg = (const struct GNUNET_MessageHeader *) &jreq[1];

  jh = GNUNET_malloc (sizeof (*jh));
  jh->group = grp;
  jh->member_pub_key = jreq->member_pub_key;
  jh->peer = jreq->peer;
  grp->join_req_cb (grp->cb_cls, &jreq->member_pub_key, jmsg, jh);

  grp->reconnect_delay = GNUNET_TIME_UNIT_MILLISECONDS;
}


/**
 * Check multicast message.
 */
static int
check_group_message (void *cls,
                     const struct GNUNET_MULTICAST_MessageHeader *mmsg)
{
  return GNUNET_OK;
}


/**
 * Receive multicast message from service.
 */
static void
handle_group_message (void *cls,
                      const struct GNUNET_MULTICAST_MessageHeader *mmsg)
{
  struct GNUNET_MULTICAST_Group *grp = cls;

  if (GNUNET_YES == grp->is_disconnecting)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Calling message callback with a message of size %u.\n",
              ntohs (mmsg->header.size));

  if (NULL != grp->message_cb)
    grp->message_cb (grp->cb_cls, mmsg);

  grp->reconnect_delay = GNUNET_TIME_UNIT_MILLISECONDS;
}


/**
 * Receive message/request fragment acknowledgement from service.
 */
static void
handle_group_fragment_ack (void *cls,
                           const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_MULTICAST_Group *grp = cls;

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

  grp->reconnect_delay = GNUNET_TIME_UNIT_MILLISECONDS;
}


/**
 * Check unicast request.
 */
static int
check_origin_request (void *cls,
                      const struct GNUNET_MULTICAST_RequestHeader *req)
{
  return GNUNET_OK;
}


/**
 * Origin receives unicast request from a member.
 */
static void
handle_origin_request (void *cls,
                       const struct GNUNET_MULTICAST_RequestHeader *req)
{
  struct GNUNET_MULTICAST_Group *grp;
  struct GNUNET_MULTICAST_Origin *orig = cls;
  grp = &orig->grp;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Calling request callback with a request of size %u.\n",
              ntohs (req->header.size));

  if (NULL != orig->request_cb)
    orig->request_cb (grp->cb_cls, req);

  grp->reconnect_delay = GNUNET_TIME_UNIT_MILLISECONDS;
}


/**
 * Receive multicast replay request from service.
 */
static void
handle_group_replay_request (void *cls,
                             const struct MulticastReplayRequestMessage *rep)

{
  struct GNUNET_MULTICAST_Group *grp = cls;

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

  grp->reconnect_delay = GNUNET_TIME_UNIT_MILLISECONDS;
}


/**
 * Check replay response.
 */
static int
check_member_replay_response (void *cls,
                              const struct MulticastReplayResponseMessage *res)
{
  uint16_t size = ntohs (res->header.size);

  if (sizeof (*res) == size)
    return GNUNET_OK;

  if (sizeof (*res) + sizeof (struct GNUNET_MULTICAST_MessageHeader) <= size)
    return GNUNET_OK;

  return GNUNET_SYSERR;
}


/**
 * Receive replay response from service.
 */
static void
handle_member_replay_response (void *cls,
                               const struct MulticastReplayResponseMessage *res)
{
  struct GNUNET_MULTICAST_Group *grp;
  struct GNUNET_MULTICAST_Member *mem = cls;
  grp = &mem->grp;

  if (GNUNET_YES == grp->is_disconnecting)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Got replay response.\n");

  // FIXME: return result
}


/**
 * Check join decision.
 */
static int
check_member_join_decision (void *cls,
                            const struct MulticastJoinDecisionMessageHeader *hdcsn)
{
  return GNUNET_OK; // checked in handle below
}


/**
 * Member receives join decision.
 */
static void
handle_member_join_decision (void *cls,
                             const struct MulticastJoinDecisionMessageHeader *hdcsn)
{
  struct GNUNET_MULTICAST_Group *grp;
  struct GNUNET_MULTICAST_Member *mem = cls;
  grp = &mem->grp;

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

  grp->reconnect_delay = GNUNET_TIME_UNIT_MILLISECONDS;
}


static void
group_cleanup (struct GNUNET_MULTICAST_Group *grp)
{
  if (NULL != grp->connect_env)
  {
    GNUNET_MQ_discard (grp->connect_env);
    grp->connect_env = NULL;
  }
  if (NULL != grp->mq)
  {
    GNUNET_MQ_destroy (grp->mq);
    grp->mq = NULL;
  }
  if (NULL != grp->disconnect_cb)
  {
    grp->disconnect_cb (grp->disconnect_cls);
    grp->disconnect_cb = NULL;
  }
  GNUNET_free (grp);
}


static void
group_disconnect (struct GNUNET_MULTICAST_Group *grp,
                  GNUNET_ContinuationCallback cb,
                  void *cls)
{
  grp->is_disconnecting = GNUNET_YES;
  grp->disconnect_cb = cb;
  grp->disconnect_cls = cls;

  if (NULL != grp->mq)
  {
    struct GNUNET_MQ_Envelope *last = GNUNET_MQ_get_last_envelope (grp->mq);
    if (NULL != last)
    {
      GNUNET_MQ_notify_sent (last,
                             (GNUNET_MQ_NotifyCallback) group_cleanup, grp);
    }
    else
    {
      group_cleanup (grp);
    }
  }
  else
  {
    group_cleanup (grp);
  }
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

  struct MulticastJoinDecisionMessageHeader *hdcsn;
  struct MulticastJoinDecisionMessage *dcsn;
  struct GNUNET_MQ_Envelope *
    env = GNUNET_MQ_msg_extra (hdcsn, sizeof (*dcsn) + relay_size + join_resp_size,
                               GNUNET_MESSAGE_TYPE_MULTICAST_JOIN_DECISION);
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

  GNUNET_MQ_send (grp->mq, env);
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
  struct MulticastReplayResponseMessage *res;
  struct GNUNET_MQ_Envelope *
    env = GNUNET_MQ_msg_extra (res, msg_size,
                               GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_RESPONSE);
  res->fragment_id = rh->req.fragment_id;
  res->message_id = rh->req.message_id;
  res->fragment_offset = rh->req.fragment_offset;
  res->flags = rh->req.flags;
  res->error_code = htonl (ec);

  if (GNUNET_MULTICAST_REC_OK == ec)
  {
    GNUNET_assert (NULL != msg);
    GNUNET_memcpy (&res[1], msg, msg_size);
  }

  GNUNET_MQ_send (rh->grp->mq, env);

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
  struct MulticastReplayResponseMessage *end;
  struct GNUNET_MQ_Envelope *
    env = GNUNET_MQ_msg (end, GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_RESPONSE_END);

  end->fragment_id = rh->req.fragment_id;
  end->message_id = rh->req.message_id;
  end->fragment_offset = rh->req.fragment_offset;
  end->flags = rh->req.flags;

  GNUNET_MQ_send (rh->grp->mq, env);
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


static void
origin_connect (struct GNUNET_MULTICAST_Origin *orig);


static void
origin_reconnect (void *cls)
{
  origin_connect (cls);
}


/**
 * Origin client disconnected from service.
 *
 * Reconnect after backoff period.
 */
static void
origin_disconnected (void *cls, enum GNUNET_MQ_Error error)
{
  struct GNUNET_MULTICAST_Origin *orig = cls;
  struct GNUNET_MULTICAST_Group *grp = &orig->grp;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Origin client disconnected (%d), re-connecting\n",
       (int) error);
  if (NULL != grp->mq)
  {
    GNUNET_MQ_destroy (grp->mq);
    grp->mq = NULL;
  }

  grp->reconnect_task = GNUNET_SCHEDULER_add_delayed (grp->reconnect_delay,
                                                      origin_reconnect,
                                                      orig);
  grp->reconnect_delay = GNUNET_TIME_STD_BACKOFF (grp->reconnect_delay);
}


/**
 * Connect to service as origin.
 */
static void
origin_connect (struct GNUNET_MULTICAST_Origin *orig)
{
  struct GNUNET_MULTICAST_Group *grp = &orig->grp;

  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (group_message,
                           GNUNET_MESSAGE_TYPE_MULTICAST_MESSAGE,
                           struct GNUNET_MULTICAST_MessageHeader,
                           grp),
    GNUNET_MQ_hd_var_size (origin_request,
                           GNUNET_MESSAGE_TYPE_MULTICAST_REQUEST,
                           struct GNUNET_MULTICAST_RequestHeader,
                           orig),
    GNUNET_MQ_hd_fixed_size (group_fragment_ack,
                             GNUNET_MESSAGE_TYPE_MULTICAST_FRAGMENT_ACK,
                             struct GNUNET_MessageHeader,
                             grp),
    GNUNET_MQ_hd_var_size (group_join_request,
                           GNUNET_MESSAGE_TYPE_MULTICAST_JOIN_REQUEST,
                           struct MulticastJoinRequestMessage,
                           grp),
    GNUNET_MQ_hd_fixed_size (group_replay_request,
                             GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_REQUEST,
                             struct MulticastReplayRequestMessage,
                             grp),
    GNUNET_MQ_handler_end ()
  };

  grp->mq = GNUNET_CLIENT_connect (grp->cfg, "multicast",
                                   handlers, origin_disconnected, orig);
  GNUNET_assert (NULL != grp->mq);
  GNUNET_MQ_send_copy (grp->mq, grp->connect_env);
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

  struct MulticastOriginStartMessage *start;
  grp->connect_env = GNUNET_MQ_msg (start,
                                    GNUNET_MESSAGE_TYPE_MULTICAST_ORIGIN_START);
  start->max_fragment_id = max_fragment_id;
  start->group_key = *priv_key;

  grp->cfg = cfg;
  grp->is_origin = GNUNET_YES;
  grp->reconnect_delay = GNUNET_TIME_UNIT_MILLISECONDS;

  grp->cb_cls = cls;
  grp->join_req_cb = join_request_cb;
  grp->replay_frag_cb = replay_frag_cb;
  grp->replay_msg_cb = replay_msg_cb;
  grp->message_cb = message_cb;

  orig->request_cb = request_cb;

  origin_connect (orig);
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

  group_disconnect (grp, stop_cb, stop_cls);
}


static void
origin_to_all (struct GNUNET_MULTICAST_Origin *orig)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "%p origin_to_all()\n", orig);
  struct GNUNET_MULTICAST_Group *grp = &orig->grp;
  struct GNUNET_MULTICAST_OriginTransmitHandle *tmit = &orig->tmit;
  GNUNET_assert (GNUNET_YES == grp->in_transmit);

  size_t buf_size = GNUNET_MULTICAST_FRAGMENT_MAX_SIZE;
  struct GNUNET_MULTICAST_MessageHeader *msg;
  struct GNUNET_MQ_Envelope *
    env = GNUNET_MQ_msg_extra (msg, buf_size - sizeof(*msg),
                               GNUNET_MESSAGE_TYPE_MULTICAST_MESSAGE);

  int ret = tmit->notify (tmit->notify_cls, &buf_size, &msg[1]);

  if (! (GNUNET_YES == ret || GNUNET_NO == ret)
      || GNUNET_MULTICAST_FRAGMENT_MAX_SIZE < buf_size)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "%p OriginTransmitNotify() returned error or invalid message size.\n",
         orig);
    /* FIXME: handle error */
    GNUNET_MQ_discard (env);
    return;
  }

  if (GNUNET_NO == ret && 0 == buf_size)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%p OriginTransmitNotify() - transmission paused.\n", orig);
    GNUNET_MQ_discard (env);
    return; /* Transmission paused. */
  }

  msg->header.size = htons (sizeof (*msg) + buf_size);
  msg->message_id = GNUNET_htonll (tmit->message_id);
  msg->group_generation = tmit->group_generation;
  msg->fragment_offset = GNUNET_htonll (tmit->fragment_offset);
  tmit->fragment_offset += sizeof (*msg) + buf_size;

  grp->acks_pending++;
  GNUNET_MQ_send (grp->mq, env);

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


static void
member_connect (struct GNUNET_MULTICAST_Member *mem);


static void
member_reconnect (void *cls)
{
  member_connect (cls);
}


/**
 * Member client disconnected from service.
 *
 * Reconnect after backoff period.
 */
static void
member_disconnected (void *cls, enum GNUNET_MQ_Error error)
{
  struct GNUNET_MULTICAST_Member *mem = cls;
  struct GNUNET_MULTICAST_Group *grp = &mem->grp;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Member client disconnected (%d), re-connecting\n",
       (int) error);
  GNUNET_MQ_destroy (grp->mq);
  grp->mq = NULL;

  grp->reconnect_task = GNUNET_SCHEDULER_add_delayed (grp->reconnect_delay,
                                                      member_reconnect,
                                                      mem);
  grp->reconnect_delay = GNUNET_TIME_STD_BACKOFF (grp->reconnect_delay);
}


/**
 * Connect to service as member.
 */
static void
member_connect (struct GNUNET_MULTICAST_Member *mem)
{
  struct GNUNET_MULTICAST_Group *grp = &mem->grp;

  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (group_message,
                           GNUNET_MESSAGE_TYPE_MULTICAST_MESSAGE,
                           struct GNUNET_MULTICAST_MessageHeader,
                           grp),
    GNUNET_MQ_hd_fixed_size (group_fragment_ack,
                             GNUNET_MESSAGE_TYPE_MULTICAST_FRAGMENT_ACK,
                             struct GNUNET_MessageHeader,
                             grp),
    GNUNET_MQ_hd_var_size (group_join_request,
                           GNUNET_MESSAGE_TYPE_MULTICAST_JOIN_REQUEST,
                           struct MulticastJoinRequestMessage,
                           grp),
    GNUNET_MQ_hd_var_size (member_join_decision,
                           GNUNET_MESSAGE_TYPE_MULTICAST_JOIN_DECISION,
                           struct MulticastJoinDecisionMessageHeader,
                           mem),
    GNUNET_MQ_hd_fixed_size (group_replay_request,
                             GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_REQUEST,
                             struct MulticastReplayRequestMessage,
                             grp),
    GNUNET_MQ_hd_var_size (member_replay_response,
                           GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_RESPONSE,
                           struct MulticastReplayResponseMessage,
                           mem),
    GNUNET_MQ_handler_end ()
  };

  grp->mq = GNUNET_CLIENT_connect (grp->cfg, "multicast",
                                   handlers, member_disconnected, mem);
  GNUNET_assert (NULL != grp->mq);
  GNUNET_MQ_send_copy (grp->mq, grp->connect_env);
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
  struct MulticastMemberJoinMessage *join;
  grp->connect_env = GNUNET_MQ_msg_extra (join, relay_size + join_msg_size,
                                          GNUNET_MESSAGE_TYPE_MULTICAST_MEMBER_JOIN);
  join->group_pub_key = *group_pub_key;
  join->member_key = *member_key;
  join->origin = *origin;
  join->relay_count = ntohl (relay_count);
  if (0 < relay_size)
    GNUNET_memcpy (&join[1], relays, relay_size);
  if (0 < join_msg_size)
    GNUNET_memcpy (((char *) &join[1]) + relay_size, join_msg, join_msg_size);

  grp->cfg = cfg;
  grp->is_origin = GNUNET_NO;
  grp->reconnect_delay = GNUNET_TIME_UNIT_MILLISECONDS;

  mem->join_dcsn_cb = join_decision_cb;
  grp->join_req_cb = join_request_cb;
  grp->replay_frag_cb = replay_frag_cb;
  grp->replay_msg_cb = replay_msg_cb;
  grp->message_cb = message_cb;
  grp->cb_cls = cls;

  member_connect (mem);
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

  mem->join_dcsn_cb = NULL;
  grp->join_req_cb = NULL;
  grp->message_cb = NULL;
  grp->replay_msg_cb = NULL;
  grp->replay_frag_cb = NULL;

  group_disconnect (grp, part_cb, part_cls);
}


void
member_replay_request (struct GNUNET_MULTICAST_Member *mem,
                       uint64_t fragment_id,
                       uint64_t message_id,
                       uint64_t fragment_offset,
                       uint64_t flags)
{
  struct MulticastReplayRequestMessage *rep;
  struct GNUNET_MQ_Envelope *
    env = GNUNET_MQ_msg (rep, GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_REQUEST);

  rep->fragment_id = GNUNET_htonll (fragment_id);
  rep->message_id = GNUNET_htonll (message_id);
  rep->fragment_offset = GNUNET_htonll (fragment_offset);
  rep->flags = GNUNET_htonll (flags);

  GNUNET_MQ_send (mem->grp.mq, env);
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
  struct GNUNET_MULTICAST_RequestHeader *req;
  struct GNUNET_MQ_Envelope *
    env = GNUNET_MQ_msg_extra (req, buf_size - sizeof(*req),
                               GNUNET_MESSAGE_TYPE_MULTICAST_REQUEST);

  int ret = tmit->notify (tmit->notify_cls, &buf_size, &req[1]);

  if (! (GNUNET_YES == ret || GNUNET_NO == ret)
      || GNUNET_MULTICAST_FRAGMENT_MAX_SIZE < buf_size)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "MemberTransmitNotify() returned error or invalid message size. "
         "ret=%d, buf_size=%u\n", ret, buf_size);
    /* FIXME: handle error */
    GNUNET_MQ_discard (env);
    return;
  }

  if (GNUNET_NO == ret && 0 == buf_size)
  {
    /* Transmission paused. */
    GNUNET_MQ_discard (env);
    return;
  }

  req->header.size = htons (sizeof (*req) + buf_size);
  req->request_id = GNUNET_htonll (tmit->request_id);
  req->fragment_offset = GNUNET_ntohll (tmit->fragment_offset);
  tmit->fragment_offset += sizeof (*req) + buf_size;

  GNUNET_MQ_send (grp->mq, env);

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
