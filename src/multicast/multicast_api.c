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


struct MessageQueue
{
  struct MessageQueue *prev;
  struct MessageQueue *next;
};


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
   * Socket (if available).
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Currently pending transmission request, or NULL for none.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * Head of operations to transmit.
   */
  struct MessageQueue *tmit_head;

  /**
   * Tail of operations to transmit.
   */
  struct MessageQueue *tmit_tail;

  /**
   * Message being transmitted to the Multicast service.
   */
  struct MessageQueue *tmit_msg;

  /**
   * Message to send on reconnect.
   */
  struct GNUNET_MessageHeader *reconnect_msg;

  /**
   * Task doing exponential back-off trying to reconnect.
   */
  GNUNET_SCHEDULER_TaskIdentifier reconnect_task;

  /**
   * Time for next connect retry.
   */
  struct GNUNET_TIME_Relative reconnect_delay;

  struct GNUNET_CRYPTO_EddsaPublicKey pub_key;
  struct GNUNET_HashCode pub_key_hash;

  GNUNET_MULTICAST_JoinCallback join_cb;
  GNUNET_MULTICAST_MembershipTestCallback member_test_cb;
  GNUNET_MULTICAST_ReplayFragmentCallback replay_frag_cb;
  GNUNET_MULTICAST_ReplayMessageCallback replay_msg_cb;
  GNUNET_MULTICAST_MessageCallback message_cb;
  void *cb_cls;

  /**
   * Are we polling for incoming messages right now?
   */
  uint8_t in_receive;

  /**
   * Are we currently transmitting a message?
   */
  uint8_t in_transmit;

  /**
   * Is this the origin or a member?
   */
  uint8_t is_origin;
};


/**
 * Handle for the origin of a multicast group.
 */
struct GNUNET_MULTICAST_Origin
{
  struct GNUNET_MULTICAST_Group grp;
  struct GNUNET_MULTICAST_OriginTransmitHandle tmit;
  struct GNUNET_CRYPTO_EddsaPrivateKey priv_key;

  GNUNET_MULTICAST_RequestCallback request_cb;
};


/**
 * Handle for a multicast group member.
 */
struct GNUNET_MULTICAST_Member
{
  struct GNUNET_MULTICAST_Group grp;
  struct GNUNET_MULTICAST_MemberTransmitHandle tmit;

  struct GNUNET_CRYPTO_EddsaPrivateKey priv_key;
  struct GNUNET_PeerIdentity origin;
  struct GNUNET_PeerIdentity relays;
  uint32_t relay_count;

  struct GNUNET_MessageHeader *join_request;

  uint64_t next_fragment_id;
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


static void
reconnect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


static void
reschedule_connect (struct GNUNET_MULTICAST_Group *grp);


/**
 * Schedule transmission of the next message from our queue.
 *
 * @param grp PSYC channel handle
 */
static void
transmit_next (struct GNUNET_MULTICAST_Group *grp);


static void
message_handler (void *cls, const struct GNUNET_MessageHeader *msg);


/**
 * Reschedule a connect attempt to the service.
 *
 * @param c channel to reconnect
 */
static void
reschedule_connect (struct GNUNET_MULTICAST_Group *grp)
{
  GNUNET_assert (grp->reconnect_task == GNUNET_SCHEDULER_NO_TASK);

  if (NULL != grp->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (grp->th);
    grp->th = NULL;
  }
  if (NULL != grp->client)
  {
    GNUNET_CLIENT_disconnect (grp->client);
    grp->client = NULL;
  }
  grp->in_receive = GNUNET_NO;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Scheduling task to reconnect to Multicast service in %s.\n",
       GNUNET_STRINGS_relative_time_to_string (grp->reconnect_delay, GNUNET_YES));
  grp->reconnect_task =
      GNUNET_SCHEDULER_add_delayed (grp->reconnect_delay, &reconnect, grp);
  grp->reconnect_delay = GNUNET_TIME_STD_BACKOFF (grp->reconnect_delay);
}


/**
 * Reset stored data related to the last received message.
 */
static void
recv_reset (struct GNUNET_MULTICAST_Group *grp)
{
}


static void
recv_error (struct GNUNET_MULTICAST_Group *grp)
{
  if (NULL != grp->message_cb)
    grp->message_cb (grp->cb_cls, NULL);

  recv_reset (grp);
}


/**
 * Transmit next message to service.
 *
 * @param cls	The struct GNUNET_MULTICAST_Group.
 * @param size	Number of bytes available in @a buf.
 * @param buf	Where to copy the message.
 *
 * @return Number of bytes copied to @a buf.
 */
static size_t
send_next_message (void *cls, size_t size, void *buf)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "send_next_message()\n");
  struct GNUNET_MULTICAST_Group *grp = cls;
  struct MessageQueue *mq = grp->tmit_head;
  if (NULL == mq)
    return 0;
  struct GNUNET_MessageHeader *qmsg = (struct GNUNET_MessageHeader *) &mq[1];
  size_t ret = ntohs (qmsg->size);
  grp->th = NULL;
  if (ret > size)
  {
    reschedule_connect (grp);
    return 0;
  }
  memcpy (buf, qmsg, ret);

  GNUNET_CONTAINER_DLL_remove (grp->tmit_head, grp->tmit_tail, mq);
  GNUNET_free (mq);

  if (NULL != grp->tmit_head)
    transmit_next (grp);

  if (GNUNET_NO == grp->in_receive)
  {
    grp->in_receive = GNUNET_YES;
    GNUNET_CLIENT_receive (grp->client, &message_handler, grp,
                           GNUNET_TIME_UNIT_FOREVER_REL);
  }
  return ret;
}


/**
 * Schedule transmission of the next message from our queue.
 *
 * @param grp  Multicast group handle.
 */
static void
transmit_next (struct GNUNET_MULTICAST_Group *grp)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "transmit_next()\n");
  if (NULL != grp->th || NULL == grp->client)
    return;

  struct MessageQueue *mq = grp->tmit_head;
  if (NULL == mq)
    return;
  struct GNUNET_MessageHeader *qmsg = (struct GNUNET_MessageHeader *) &mq[1];

  grp->th = GNUNET_CLIENT_notify_transmit_ready (grp->client,
                                                 ntohs (qmsg->size),
                                                 GNUNET_TIME_UNIT_FOREVER_REL,
                                                 GNUNET_NO,
                                                 &send_next_message,
                                                 grp);
}


/**
 * Try again to connect to the Multicast service.
 *
 * @param cls Channel handle.
 * @param tc Scheduler context.
 */
static void
reconnect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_MULTICAST_Group *grp = cls;

  recv_reset (grp);
  grp->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connecting to Multicast service.\n");
  GNUNET_assert (NULL == grp->client);
  grp->client = GNUNET_CLIENT_connect ("multicast", grp->cfg);
  GNUNET_assert (NULL != grp->client);
  uint16_t reconn_size = ntohs (grp->reconnect_msg->size);

  if (NULL == grp->tmit_head ||
      0 != memcmp (&grp->tmit_head[1], grp->reconnect_msg, reconn_size))
  {
    struct MessageQueue *mq = GNUNET_malloc (sizeof (*mq) + reconn_size);
    memcpy (&mq[1], grp->reconnect_msg, reconn_size);
    GNUNET_CONTAINER_DLL_insert (grp->tmit_head, grp->tmit_tail, mq);
  }
  transmit_next (grp);
}


/**
 * Disconnect from the Multicast service.
 *
 * @param g  Group handle to disconnect.
 */
static void
disconnect (void *g)
{
  struct GNUNET_MULTICAST_Group *grp = g;

  GNUNET_assert (NULL != grp);
  if (grp->tmit_head != grp->tmit_tail)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Disconnecting while there are still outstanding messages!\n");
    GNUNET_break (0);
  }
  if (grp->reconnect_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (grp->reconnect_task);
    grp->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != grp->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (grp->th);
    grp->th = NULL;
  }
  if (NULL != grp->client)
  {
    GNUNET_CLIENT_disconnect (grp->client);
    grp->client = NULL;
  }
  if (NULL != grp->reconnect_msg)
  {
    GNUNET_free (grp->reconnect_msg);
    grp->reconnect_msg = NULL;
  }
}


/**
 * Iterator callback for calling message callbacks for all groups.
 */
static int
message_callback (void *cls, const struct GNUNET_HashCode *pub_key_hash,
                  void *group)
{
  const struct GNUNET_MessageHeader *msg = cls;
  struct GNUNET_MULTICAST_Group *grp = group;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Calling message callback with a message "
              "of type %u and size %u.\n",
              ntohs (msg->type), ntohs (msg->size));

  if (NULL != grp->message_cb)
    grp->message_cb (grp->cb_cls, msg);

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
  if (origins != NULL)
    GNUNET_CONTAINER_multihashmap_get_multiple (origins, &grp->pub_key_hash,
                                                message_callback, (void *) msg);
  if (members != NULL)
    GNUNET_CONTAINER_multihashmap_get_multiple (members, &grp->pub_key_hash,
                                                message_callback, (void *) msg);
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

  orig->request_cb (orig->grp.cb_cls, &req->member_key,
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
handle_multicast_request (struct GNUNET_MULTICAST_Group *grp,
                          const struct GNUNET_MULTICAST_RequestHeader *req)
{
  if (NULL != origins)
    GNUNET_CONTAINER_multihashmap_get_multiple (origins, &grp->pub_key_hash,
                                                request_callback, (void *) req);
}


/**
 * Function called when we receive a message from the service.
 *
 * @param cls	struct GNUNET_MULTICAST_Group
 * @param msg	Message received, NULL on timeout or fatal error.
 */
static void
message_handler (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_MULTICAST_Group *grp = cls;

  if (NULL == msg)
  {
    // timeout / disconnected from service, reconnect
    reschedule_connect (grp);
    return;
  }

  uint16_t size_eq = 0;
  uint16_t size_min = 0;
  uint16_t size = ntohs (msg->size);
  uint16_t type = ntohs (msg->type);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received message of type %d and size %u from Multicast service\n",
       type, size);

  switch (type)
  {
  case GNUNET_MESSAGE_TYPE_MULTICAST_MESSAGE:
    size_min = sizeof (struct GNUNET_MULTICAST_MessageHeader);
    break;

  case GNUNET_MESSAGE_TYPE_MULTICAST_REQUEST:
    size_min = sizeof (struct GNUNET_MULTICAST_RequestHeader);
    break;

  default:
    GNUNET_break_op (0);
    return;
  }

  if (! ((0 < size_eq && size == size_eq)
         || (0 < size_min && size_min <= size)))
  {
    GNUNET_break_op (0);
    return;
  }

  switch (type)
  {
  case GNUNET_MESSAGE_TYPE_MULTICAST_MESSAGE:
    handle_multicast_message (grp, (struct GNUNET_MULTICAST_MessageHeader *) msg);
    break;

  case GNUNET_MESSAGE_TYPE_MULTICAST_REQUEST:
    if (GNUNET_YES != grp->is_origin)
    {
      GNUNET_break (0);
      break;
    }

    handle_multicast_request (grp, (struct GNUNET_MULTICAST_RequestHeader *) msg);
    break;

  default:
    GNUNET_break_op (0);
    return;
  }

  if (NULL != grp->client)
  {
    GNUNET_CLIENT_receive (grp->client, &message_handler, grp,
                           GNUNET_TIME_UNIT_FOREVER_REL);
  }
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
 * @param cfg  Configuration to use.
 * @param priv_key  ECC key that will be used to sign messages for this
 *        multicast session; public key is used to identify the multicast group;
 * @param max_fragment_id  Maximum fragment ID already sent to the group.
 *        0 for a new group.
 * @param join_cb  Function called to approve / disapprove joining of a peer.
 * @param member_test_cb  Function multicast can use to test group membership.
 * @param replay_frag_cb  Function that can be called to replay a message fragment.
 * @param replay_msg_cb  Function that can be called to replay a message.
 * @param request_cb  Function called with message fragments from group members.
 * @param message_cb  Function called with the message fragments sent to the
 *        network by GNUNET_MULTICAST_origin_to_all().  These message fragments
 *        should be stored for answering replay requests later.
 * @param cls  Closure for the various callbacks that follow.
 *
 * @return Handle for the origin, NULL on error.
 */
struct GNUNET_MULTICAST_Origin *
GNUNET_MULTICAST_origin_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
                               const struct GNUNET_CRYPTO_EddsaPrivateKey *priv_key,
                               uint64_t max_fragment_id,
                               GNUNET_MULTICAST_JoinCallback join_cb,
                               GNUNET_MULTICAST_MembershipTestCallback member_test_cb,
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
  memcpy (&start->group_key, priv_key, sizeof (*priv_key));

  grp->reconnect_msg = (struct GNUNET_MessageHeader *) start;
  grp->is_origin = GNUNET_YES;
  grp->cfg = cfg;

  grp->cb_cls = cls;
  grp->join_cb = join_cb;
  grp->member_test_cb = member_test_cb;
  grp->replay_frag_cb = replay_frag_cb;
  grp->replay_msg_cb = replay_msg_cb;
  grp->message_cb = message_cb;

  orig->request_cb = request_cb;
  orig->priv_key = *priv_key;

  GNUNET_CRYPTO_eddsa_key_get_public (&orig->priv_key, &grp->pub_key);
  GNUNET_CRYPTO_hash (&grp->pub_key, sizeof (grp->pub_key),
                      &grp->pub_key_hash);

  if (NULL == origins)
    origins = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);

  GNUNET_CONTAINER_multihashmap_put (origins, &grp->pub_key_hash, orig,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);

  grp->reconnect_delay = GNUNET_TIME_UNIT_ZERO;
  grp->reconnect_task = GNUNET_SCHEDULER_add_now (&reconnect, grp);

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
  disconnect (&orig->grp);
  GNUNET_CONTAINER_multihashmap_remove (origins, &orig->grp.pub_key_hash, orig);
  GNUNET_free (orig);
}


static void
origin_to_all (struct GNUNET_MULTICAST_Origin *orig)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "origin_to_all()\n");
  struct GNUNET_MULTICAST_Group *grp = &orig->grp;
  struct GNUNET_MULTICAST_OriginTransmitHandle *tmit = &orig->tmit;

  size_t buf_size = GNUNET_MULTICAST_FRAGMENT_MAX_SIZE;
  struct MessageQueue *mq = GNUNET_malloc (sizeof (*mq) + buf_size);
  GNUNET_CONTAINER_DLL_insert_tail (grp->tmit_head, grp->tmit_tail, mq);

  struct GNUNET_MULTICAST_MessageHeader *
    msg = (struct GNUNET_MULTICAST_MessageHeader *) &mq[1];
  int ret = tmit->notify (tmit->notify_cls, &buf_size, &msg[1]);

  if (! (GNUNET_YES == ret || GNUNET_NO == ret)
      || GNUNET_MULTICAST_FRAGMENT_MAX_PAYLOAD < buf_size)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "OriginTransmitNotify() returned error or invalid message size.\n");
    /* FIXME: handle error */
    GNUNET_free (mq);
    return;
  }

  if (GNUNET_NO == ret && 0 == buf_size)
  {
    GNUNET_free (mq);
    return; /* Transmission paused. */
  }

  msg->header.type = htons (GNUNET_MESSAGE_TYPE_MULTICAST_MESSAGE);
  msg->header.size = htons (sizeof (*msg) + buf_size);
  msg->message_id = GNUNET_htonll (tmit->message_id);
  msg->group_generation = tmit->group_generation;
  msg->fragment_offset = GNUNET_htonll (tmit->fragment_offset);
  tmit->fragment_offset += sizeof (*msg) + buf_size;

  transmit_next (grp);
}


/**
 * Send a message to the multicast group.
 *
 * @param orig  Handle to the multicast group.
 * @param message_id  Application layer ID for the message.  Opaque to multicast.
 * @param group_generation  Group generation of the message.
 *                          Documented in struct GNUNET_MULTICAST_MessageHeader.
 * @param notify  Function to call to get the message.
 * @param notify_cls  Closure for @a notify.
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
  struct GNUNET_MULTICAST_OriginTransmitHandle *tmit = &orig->tmit;
  tmit->origin = orig;
  tmit->message_id = message_id;
  tmit->group_generation = group_generation;
  tmit->notify = notify;
  tmit->notify_cls = notify_cls;

  origin_to_all (orig);
  return tmit;
}


/**
 * Resume message transmission to multicast group.
 *
 * @param th  Transmission to cancel.
 */
void
GNUNET_MULTICAST_origin_to_all_resume (struct GNUNET_MULTICAST_OriginTransmitHandle *th)
{
  origin_to_all (th->origin);
}


/**
 * Cancel request for message transmission to multicast group.
 *
 * @param th  Transmission to cancel.
 */
void
GNUNET_MULTICAST_origin_to_all_cancel (struct GNUNET_MULTICAST_OriginTransmitHandle *th)
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
 * @param join_req  Application-dependent join request to be passed to the peer
 *        @a relay (might, for example, contain a user, bind user
 *        identity/pseudonym to peer identity, application-level message to
 *        origin, etc.).
 * @param join_cb Function called to approve / disapprove joining of a peer.
 * @param member_test_cb Function multicast can use to test group membership.
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
                              const struct GNUNET_MessageHeader *join_req,
                              GNUNET_MULTICAST_JoinCallback join_cb,
                              GNUNET_MULTICAST_MembershipTestCallback member_test_cb,
                              GNUNET_MULTICAST_ReplayFragmentCallback replay_frag_cb,
                              GNUNET_MULTICAST_ReplayMessageCallback replay_msg_cb,
                              GNUNET_MULTICAST_MessageCallback message_cb,
                              void *cls)
{
  struct GNUNET_MULTICAST_Member *mem = GNUNET_malloc (sizeof (*mem));
  struct GNUNET_MULTICAST_Group *grp = &mem->grp;

  uint16_t relay_size = relay_count * sizeof (*relays);
  uint16_t join_req_size = (NULL != join_req) ? ntohs (join_req->size) : 0;
  struct MulticastMemberJoinMessage *
    join = GNUNET_malloc (sizeof (*join) + relay_size + join_req_size);
  join->header.type = htons (GNUNET_MESSAGE_TYPE_MULTICAST_MEMBER_JOIN);
  join->header.size = htons (sizeof (*join) + relay_size + join_req_size);
  join->group_key = *group_key;
  join->member_key = *member_key;
  join->origin = *origin;
  memcpy (&join[1], relays, relay_size);
  memcpy (((char *) &join[1]) + relay_size, join_req, join_req_size);

  grp->reconnect_msg = (struct GNUNET_MessageHeader *) join;
  grp->is_origin = GNUNET_NO;
  grp->cfg = cfg;
  grp->pub_key = *group_key;

  grp->join_cb = join_cb;
  grp->member_test_cb = member_test_cb;
  grp->replay_frag_cb = replay_frag_cb;
  grp->message_cb = message_cb;
  grp->cb_cls = cls;

  mem->origin = *origin;
  mem->relay_count = relay_count;
  mem->relays = *relays;
  mem->priv_key = *member_key;

  GNUNET_CRYPTO_eddsa_key_get_public (&mem->priv_key, &grp->pub_key);
  GNUNET_CRYPTO_hash (&grp->pub_key, sizeof (grp->pub_key), &grp->pub_key_hash);

  if (NULL == members)
    members = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);

  GNUNET_CONTAINER_multihashmap_put (members, &grp->pub_key_hash, mem,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);

  grp->reconnect_delay = GNUNET_TIME_UNIT_ZERO;
  grp->reconnect_task = GNUNET_SCHEDULER_add_now (&reconnect, grp);

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
  disconnect (&mem->grp);
  GNUNET_CONTAINER_multihashmap_remove (members, &mem->grp.pub_key_hash, mem);
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


static void
member_to_origin (struct GNUNET_MULTICAST_Member *mem)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "member_to_origin()\n");
  struct GNUNET_MULTICAST_Group *grp = &mem->grp;
  struct GNUNET_MULTICAST_MemberTransmitHandle *tmit = &mem->tmit;

  size_t buf_size = GNUNET_MULTICAST_FRAGMENT_MAX_PAYLOAD;
  struct MessageQueue *mq = GNUNET_malloc (sizeof (*mq) + buf_size);
  GNUNET_CONTAINER_DLL_insert_tail (grp->tmit_head, grp->tmit_tail, mq);

  struct GNUNET_MULTICAST_RequestHeader *
    req = (struct GNUNET_MULTICAST_RequestHeader *) &mq[1];
  int ret = tmit->notify (tmit->notify_cls, &buf_size, &req[1]);

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
  req->request_id = GNUNET_htonll (tmit->request_id);
  req->fragment_offset = GNUNET_ntohll (tmit->fragment_offset);
  tmit->fragment_offset += sizeof (*req) + buf_size;

  transmit_next (grp);
}


/**
 * Send a message to the origin of the multicast group.
 *
 * @param mem Membership handle.
 * @param request_id Application layer ID for the request.  Opaque to multicast.
 * @param notify Callback to call to get the message.
 * @param notify_cls Closure for @a notify.
 * @return Handle to cancel request, NULL on error (i.e. request already pending).
 */
struct GNUNET_MULTICAST_MemberTransmitHandle *
GNUNET_MULTICAST_member_to_origin (struct GNUNET_MULTICAST_Member *mem,
                                   uint64_t request_id,
                                   GNUNET_MULTICAST_MemberTransmitNotify notify,
                                   void *notify_cls)
{
  struct GNUNET_MULTICAST_MemberTransmitHandle *tmit = &mem->tmit;
  tmit->member = mem;
  tmit->request_id = request_id;
  tmit->notify = notify;
  tmit->notify_cls = notify_cls;

  member_to_origin (mem);
  return tmit;
}


/**
 * Resume message transmission to origin.
 *
 * @param th  Transmission to cancel.
 */
void
GNUNET_MULTICAST_member_to_origin_resume (struct GNUNET_MULTICAST_MemberTransmitHandle *th)
{

}


/**
 * Cancel request for message transmission to origin.
 *
 * @param th  Transmission to cancel.
 */
void
GNUNET_MULTICAST_member_to_origin_cancel (struct GNUNET_MULTICAST_MemberTransmitHandle *th)
{
}


/* end of multicast_api.c */
