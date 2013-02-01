/*
  This file is part of GNUnet.
  (C) 2012 Christian Grothoff (and other contributing authors)

  GNUnet is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published
  by the Free Software Foundation; either version 2, or (at your
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
 * @file testbed/gnunet-service-testbed_oc.c
 * @brief code for handling overlay connect operations
 * @author Sree Harsha Totakura
 */

#include "gnunet-service-testbed.h"

/**
 * Redefine LOG with a changed log component string
 */
#ifdef LOG
#undef LOG
#endif
#define LOG(kind,...)                                   \
  GNUNET_log_from (kind, "testbed-OC", __VA_ARGS__)


/**
 * Context information for requesting TRANSPORT to connect to a peer
 */
struct TryConnectContext
{
  /**
   * The identity of the peer to which the transport has to attempt a connection
   */
  struct GNUNET_PeerIdentity *pid;

  /**
   * The transport handle obtained from cache. Do NOT close/disconnect.
   */
  struct GNUNET_TRANSPORT_Handle *th_;

  /**
   * The GetCacheHandle for the p1th transport handle
   */
  struct GSTCacheGetHandle *cgh_th;

  /**
   * the try connect handle
   */
  struct GNUNET_TRANSPORT_TryConnectHandle *tch;

  /**
   * The task handle
   */
  GNUNET_SCHEDULER_TaskIdentifier task;

  /**
   * The id of the operation which is resposible for this context
   */
  uint64_t op_id;

  /**
   * The number of times we attempted to connect
   */
  unsigned int retries;

};


/**
 * Context information for connecting 2 peers in overlay.
 */
struct OverlayConnectContext
{
  /**
   * The next pointer for maintaining a DLL of all OverlayConnectContexts
   */
  struct OverlayConnectContext *next;

  /**
   * The prev pointer for maintaining a DLL of all OverlayConnectContexts
   */
  struct OverlayConnectContext *prev;

  /**
   * The client which has requested for overlay connection. This is used to send
   * either a success of failure message
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * the first peer which is to expect an overlay connection from the second peer.
   */
  struct Peer *peer;

  /**
   * Transport handle of the first peer obtained from cache to get its HELLO. Do
   * NOT close/disconnect.
   */
  struct GNUNET_TRANSPORT_Handle *p1th_;

  /**
   * The CacheGetHandle for the p1th transport handle
   */
  struct GSTCacheGetHandle *cgh_p1th;

  /**
   * The GetCacheHandle for registering callback to notify CORE level peer
   * connects and to get our identity.
   */
  struct GSTCacheGetHandle *cgh_ch;

  /**
   * HELLO of the first peer.  This should be sent to the second peer.
   */
  struct GNUNET_MessageHeader *hello;

  /**
   * Get GetHelloHandle to acquire a HELLO of the first peer
   */
  struct GNUNET_TRANSPORT_GetHelloHandle *ghh;

  /**
   * The handle for offering the HELLO of the first peer to the second
   * peer. This is only used if the second peer is a local peer.
   */
  struct GNUNET_TRANSPORT_OfferHelloHandle *ohh;

  /**
   * The error message we send if this overlay connect operation has timed out
   */
  char *emsg;

  /**
   * Operation context for the suboperation we start to get the identity of the
   * second peer if it is a remote peer
   */
  struct OperationContext *opc;

  /**
   * Controller of peer 2; NULL if the peer is a local peer
   */
  struct GNUNET_TESTBED_Controller *peer2_controller;

  /**
   * The transport TryConnectContext. This will be NULL if the second peer is a
   * remote peer
   */
  struct TryConnectContext tcc;

  /**
   * The peer identity of the first peer
   */
  struct GNUNET_PeerIdentity peer_identity;

  /**
   * The peer identity of the other peer
   */
  struct GNUNET_PeerIdentity other_peer_identity;

  /**
   * The id of the operation responsible for creating this context
   */
  uint64_t op_id;

  /**
   * The id of the task for sending HELLO of peer 2 to peer 1 and ask peer 1 to
   * connect to peer 2
   */
  GNUNET_SCHEDULER_TaskIdentifier send_hello_task;

  /**
   * The id of the overlay connect timeout task
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * The id of the cleanup task
   */
  GNUNET_SCHEDULER_TaskIdentifier cleanup_task;

  /**
   * The id of peer A
   */
  uint32_t peer_id;

  /**
   * The id of peer B
   */
  uint32_t other_peer_id;

};


/**
 * Context information for remote overlay connect operations.  Remote overlay
 * connections are used when peers A and B reside on different hosts.  In these
 * operations the host controller for peer B is asked by the host controller of
 * peer A to make peer B connect to peer A by sending the controller of peer B
 * the HELLO of peer A.
 */
struct RemoteOverlayConnectCtx
{
  /**
   * the next pointer for DLL
   */
  struct RemoteOverlayConnectCtx *next;

  /**
   * the prev pointer for DLL
   */
  struct RemoteOverlayConnectCtx *prev;

  /**
   * The peer handle of peer B
   */
  struct Peer *peer;

  /**
   * Peer A's HELLO
   */
  struct GNUNET_MessageHeader *hello;

  /**
   * The handle for offering HELLO
   */
  struct GNUNET_TRANSPORT_OfferHelloHandle *ohh;

  /**
   * The transport try connect context
   */
  struct TryConnectContext tcc;

  /**
   * The peer identity of peer A
   */
  struct GNUNET_PeerIdentity a_id;

  /**
   * Task for offering HELLO of A to B and doing try_connect
   */
  GNUNET_SCHEDULER_TaskIdentifier attempt_connect_task_id;

  /**
   * Task to timeout RequestOverlayConnect
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_rocc_task_id;

  /**
   * The id of the operation responsible for creating this context
   */
  uint64_t op_id;
};


/**
 * DLL head for OverlayConnectContext DLL - to be used to clean up during shutdown
 */
static struct OverlayConnectContext *occq_head;

/**
 * DLL tail for OverlayConnectContext DLL
 */
static struct OverlayConnectContext *occq_tail;

/**
 * DLL head for RequectOverlayConnectContext DLL - to be used to clean up during
 * shutdown
 */
static struct RemoteOverlayConnectCtx *roccq_head;

/**
 * DLL tail for RequectOverlayConnectContext DLL
 */
static struct RemoteOverlayConnectCtx *roccq_tail;


/**
 * Cleans up ForwardedOverlayConnectContext
 *
 * @param focc the ForwardedOverlayConnectContext to cleanup
 */
void
GST_cleanup_focc (struct ForwardedOverlayConnectContext *focc)
{
  GNUNET_free_non_null (focc->orig_msg);
  GNUNET_free (focc);
}


/**
 * Timeout task for cancelling a forwarded overlay connect connect
 *
 * @param cls the ForwardedOverlayConnectContext
 * @param tc the task context from the scheduler
 */
static void
forwarded_overlay_connect_timeout (void *cls,
                                   const struct GNUNET_SCHEDULER_TaskContext
                                   *tc)
{
  struct ForwardedOperationContext *fopc = cls;
  struct RegisteredHostContext *rhc;
  struct ForwardedOverlayConnectContext *focc;

  rhc = fopc->cls;
  focc = rhc->focc_dll_head;
  GNUNET_CONTAINER_DLL_remove (rhc->focc_dll_head, rhc->focc_dll_tail, focc);
  GST_cleanup_focc (focc);
  LOG_DEBUG ("Overlay linking between peers %u and %u failed\n", focc->peer1,
             focc->peer2);
  GST_forwarded_operation_timeout (cls, tc);
  if (NULL != rhc->focc_dll_head)
    GST_process_next_focc (rhc);
}


/**
 * Callback to be called when forwarded overlay connection operation has a reply
 * from the sub-controller successfull. We have to relay the reply msg back to
 * the client
 *
 * @param cls ForwardedOperationContext
 * @param msg the peer create success message
 */
static void
forwarded_overlay_connect_listener (void *cls,
                                    const struct GNUNET_MessageHeader *msg)
{
  struct ForwardedOperationContext *fopc = cls;
  struct RegisteredHostContext *rhc;
  struct ForwardedOverlayConnectContext *focc;

  rhc = fopc->cls;
  GST_forwarded_operation_reply_relay (cls, msg);
  focc = rhc->focc_dll_head;
  GNUNET_CONTAINER_DLL_remove (rhc->focc_dll_head, rhc->focc_dll_tail, focc);
  GST_cleanup_focc (focc);
  if (NULL != rhc->focc_dll_head)
    GST_process_next_focc (rhc);
}


/**
 * Processes a forwarded overlay connect context in the queue of the given RegisteredHostContext
 *
 * @param rhc the RegisteredHostContext
 */
void
GST_process_next_focc (struct RegisteredHostContext *rhc)
{
  struct ForwardedOperationContext *fopc;
  struct ForwardedOverlayConnectContext *focc;

  focc = rhc->focc_dll_head;
  GNUNET_assert (NULL != focc);
  GNUNET_assert (RHC_OL_CONNECT == rhc->state);
  fopc = GNUNET_malloc (sizeof (struct ForwardedOperationContext));
  GNUNET_SERVER_client_keep (rhc->client);
  fopc->client = rhc->client;
  fopc->operation_id = focc->operation_id;
  fopc->cls = rhc;
  fopc->type = OP_OVERLAY_CONNECT;
  fopc->opc =
      GNUNET_TESTBED_forward_operation_msg_ (rhc->gateway->controller,
                                             focc->operation_id, focc->orig_msg,
                                             &forwarded_overlay_connect_listener,
                                             fopc);
  GNUNET_free (focc->orig_msg);
  focc->orig_msg = NULL;
  fopc->timeout_task =
      GNUNET_SCHEDULER_add_delayed (TIMEOUT, &forwarded_overlay_connect_timeout,
                                    fopc);
  GNUNET_CONTAINER_DLL_insert_tail (fopcq_head, fopcq_tail, fopc);
}


/**
 * Cleanup overlay connect context structure
 *
 * @param occ the overlay connect context
 */
static void
cleanup_occ (struct OverlayConnectContext *occ)
{
  LOG_DEBUG ("0x%llx: Cleaning up occ\n", occ->op_id);
  GNUNET_free_non_null (occ->emsg);
  GNUNET_free_non_null (occ->hello);
  GNUNET_SERVER_client_drop (occ->client);
  if (NULL != occ->opc)
    GNUNET_TESTBED_forward_operation_msg_cancel_ (occ->opc);
  if (GNUNET_SCHEDULER_NO_TASK != occ->send_hello_task)
    GNUNET_SCHEDULER_cancel (occ->send_hello_task);
  if (GNUNET_SCHEDULER_NO_TASK != occ->cleanup_task)
    GNUNET_SCHEDULER_cancel (occ->cleanup_task);
  if (GNUNET_SCHEDULER_NO_TASK != occ->timeout_task)
    GNUNET_SCHEDULER_cancel (occ->timeout_task);
  if (NULL != occ->cgh_ch)
  {
    GST_cache_get_handle_done (occ->cgh_ch);
    occ->peer->reference_cnt--;
  }
  if (NULL != occ->ghh)
    GNUNET_TRANSPORT_get_hello_cancel (occ->ghh);
  if (NULL != occ->ohh)
    GNUNET_TRANSPORT_offer_hello_cancel (occ->ohh);
  if (GNUNET_SCHEDULER_NO_TASK != occ->tcc.task)
    GNUNET_SCHEDULER_cancel (occ->tcc.task);
  if (NULL != occ->tcc.tch)
    GNUNET_TRANSPORT_try_connect_cancel (occ->tcc.tch);
  if (NULL != occ->cgh_p1th)
  {
    GST_cache_get_handle_done (occ->cgh_p1th);
    occ->peer->reference_cnt--;
  }
  if (NULL != occ->tcc.cgh_th)
  {
    GST_cache_get_handle_done (occ->tcc.cgh_th);
    GST_peer_list[occ->other_peer_id]->reference_cnt--;
  }
  if ((GNUNET_YES == occ->peer->destroy_flag) &&
      (0 == occ->peer->reference_cnt))
    GST_destroy_peer (occ->peer);
  if ((NULL == occ->peer2_controller) &&
      (GNUNET_YES == GST_peer_list[occ->other_peer_id]->destroy_flag) &&
      (0 == GST_peer_list[occ->other_peer_id]->reference_cnt))
    GST_destroy_peer (GST_peer_list[occ->other_peer_id]);
  GNUNET_CONTAINER_DLL_remove (occq_head, occq_tail, occ);
  GNUNET_free (occ);
}


/**
 * Task for cleaing up overlay connect context structure
 *
 * @param cls the overlay connect context
 * @param tc the task context
 */
static void
do_cleanup_occ (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct OverlayConnectContext *occ = cls;

  occ->cleanup_task = GNUNET_SCHEDULER_NO_TASK;
  cleanup_occ (occ);
}


/**
 * Task which will be run when overlay connect request has been timed out
 *
 * @param cls the OverlayConnectContext
 * @param tc the TaskContext
 */
static void
timeout_overlay_connect (void *cls,
                         const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct OverlayConnectContext *occ = cls;

  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK != occ->timeout_task);
  occ->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  LOG (GNUNET_ERROR_TYPE_WARNING,
       "0x%llx: Timeout while connecting peers %u and %u\n", occ->op_id,
       occ->peer_id, occ->other_peer_id);
  GST_send_operation_fail_msg (occ->client, occ->op_id, occ->emsg);
  cleanup_occ (occ);
}


static void
send_overlay_connect_success_msg (struct OverlayConnectContext *occ)
{
  struct GNUNET_TESTBED_ConnectionEventMessage *msg;

  LOG_DEBUG ("0x%llx: Peers connected - Sending overlay connect success\n",
             occ->op_id);
  msg = GNUNET_malloc (sizeof (struct GNUNET_TESTBED_ConnectionEventMessage));
  msg->header.size =
      htons (sizeof (struct GNUNET_TESTBED_ConnectionEventMessage));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_PEER_CONNECT_EVENT);
  msg->event_type = htonl (GNUNET_TESTBED_ET_CONNECT);
  msg->peer1 = htonl (occ->peer_id);
  msg->peer2 = htonl (occ->other_peer_id);
  msg->operation_id = GNUNET_htonll (occ->op_id);
  GST_queue_message (occ->client, &msg->header);
}


/**
 * Function called to notify transport users that another
 * peer connected to us.
 *
 * @param cls closure
 * @param new_peer the peer that connected
 */
static void
overlay_connect_notify (void *cls, const struct GNUNET_PeerIdentity *new_peer)
{
  struct OverlayConnectContext *occ = cls;
  char *new_peer_str;
  char *other_peer_str;

  //LOG_DEBUG ("Overlay connect notify\n");
  if (0 ==
      memcmp (new_peer, &occ->peer_identity,
              sizeof (struct GNUNET_PeerIdentity)))
    return;
  new_peer_str = GNUNET_strdup (GNUNET_i2s (new_peer));
  other_peer_str = GNUNET_strdup (GNUNET_i2s (&occ->other_peer_identity));
  if (0 !=
      memcmp (new_peer, &occ->other_peer_identity,
              sizeof (struct GNUNET_PeerIdentity)))
  {
    /* LOG_DEBUG ("Unexpected peer %4s connected when expecting peer %4s\n", */
    /*         new_peer_str, other_peer_str); */
    GNUNET_free (new_peer_str);
    GNUNET_free (other_peer_str);
    return;
  }
  GNUNET_free (new_peer_str);
  LOG_DEBUG ("0x%llx: Peer %4s connected to peer %4s\n", occ->op_id,
             other_peer_str, GNUNET_i2s (&occ->peer_identity));
  GNUNET_free (other_peer_str);
  if (GNUNET_SCHEDULER_NO_TASK != occ->send_hello_task)
  {
    GNUNET_SCHEDULER_cancel (occ->send_hello_task);
    occ->send_hello_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK != occ->timeout_task);
  GNUNET_SCHEDULER_cancel (occ->timeout_task);
  occ->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  if (GNUNET_SCHEDULER_NO_TASK != occ->tcc.task)
  {
    GNUNET_SCHEDULER_cancel (occ->tcc.task);
    occ->tcc.task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_free_non_null (occ->emsg);
  occ->emsg = NULL;
  send_overlay_connect_success_msg (occ);
  occ->cleanup_task = GNUNET_SCHEDULER_add_now (&do_cleanup_occ, occ);
  //cleanup_occ (occ);
}


/**
 * Task to ask transport of a peer to connect to another peer
 *
 * @param cls the TryConnectContext
 * @param tc the scheduler task context
 */
static void
try_connect_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Callback to be called with result of the try connect request.
 *
 * @param cls the overlay connect context
 * @param result GNUNET_OK if message was transmitted to transport service
 *               GNUNET_SYSERR if message was not transmitted to transport service
 */
static void
try_connect_cb (void *cls, const int result)
{
  struct TryConnectContext *tcc = cls;

  tcc->tch = NULL;
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == tcc->task);
  tcc->task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_MILLISECONDS,
                                     500 + pow (2, ++tcc->retries)),
                                    &try_connect_task, tcc);
}


/**
 * Task to ask transport of a peer to connect to another peer
 *
 * @param cls the TryConnectContext
 * @param tc the scheduler task context
 */
static void
try_connect_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct TryConnectContext *tcc = cls;

  tcc->task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    return;
  GNUNET_assert (NULL == tcc->tch);
  GNUNET_assert (NULL != tcc->pid);
  GNUNET_assert (NULL != tcc->th_);
  GNUNET_assert (NULL != tcc->cgh_th);
  LOG_DEBUG ("0x%llx: Trail %u to connect to peer %s\n", tcc->op_id,
             tcc->retries, GNUNET_i2s (tcc->pid));
  tcc->tch =
      GNUNET_TRANSPORT_try_connect (tcc->th_, tcc->pid, &try_connect_cb, tcc);
}


/**
 * Task to offer HELLO of peer 1 to peer 2 and try to make peer 2 to connect to
 * peer 1.
 *
 * @param cls the OverlayConnectContext
 * @param tc the TaskContext from scheduler
 */
static void
send_hello (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Task that is run when hello has been sent
 *
 * @param cls the overlay connect context
 * @param tc the scheduler task context; if tc->reason =
 *          GNUNET_SCHEDULER_REASON_TIMEOUT then sending HELLO failed; if
 *          GNUNET_SCHEDULER_REASON_READ_READY is succeeded
 */
static void
occ_hello_sent_cb (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct OverlayConnectContext *occ = cls;

  occ->ohh = NULL;
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == occ->send_hello_task);
  if (GNUNET_SCHEDULER_REASON_TIMEOUT == tc->reason)
  {
    GNUNET_free_non_null (occ->emsg);
    GNUNET_asprintf (&occ->emsg,
                     "0x%llx: Timeout while offering HELLO to other peer",
                     occ->op_id);
    occ->send_hello_task = GNUNET_SCHEDULER_add_now (&send_hello, occ);
    return;
  }
  if (GNUNET_SCHEDULER_REASON_READ_READY != tc->reason)
    return;
  GNUNET_free_non_null (occ->emsg);
  GNUNET_asprintf (&occ->emsg, "0x%llx: Timeout while try connect", occ->op_id);
  occ->tcc.pid = &occ->peer_identity;
  occ->tcc.op_id = occ->op_id;
  occ->tcc.task = GNUNET_SCHEDULER_add_now (&try_connect_task, &occ->tcc);
}


/**
 * Task to offer HELLO of peer 1 to peer 2 and try to make peer 2 to connect to
 * peer 1.
 *
 * @param cls the OverlayConnectContext
 * @param tc the TaskContext from scheduler
 */
static void
send_hello (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct OverlayConnectContext *occ = cls;
  char *other_peer_str;

  occ->send_hello_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  GNUNET_assert (NULL != occ->hello);
  other_peer_str = GNUNET_strdup (GNUNET_i2s (&occ->other_peer_identity));
  if (NULL != occ->peer2_controller)
  {
    struct GNUNET_TESTBED_RemoteOverlayConnectMessage *msg;
    uint16_t msize;
    uint16_t hello_size;

    LOG_DEBUG ("0x%llx: Offering HELLO of %s (size: %u) to %s via Remote "
               "Overlay Request\n", occ->op_id,
               GNUNET_i2s (&occ->peer_identity), ntohs (occ->hello->size),
               other_peer_str);
    hello_size = ntohs (occ->hello->size);
    msize =
        sizeof (struct GNUNET_TESTBED_RemoteOverlayConnectMessage) + hello_size;
    msg = GNUNET_malloc (msize);
    msg->header.type =
        htons (GNUNET_MESSAGE_TYPE_TESTBED_REMOTE_OVERLAY_CONNECT);
    msg->header.size = htons (msize);
    msg->peer = htonl (occ->other_peer_id);
    msg->operation_id = GNUNET_htonll (occ->op_id);
    (void) memcpy (&msg->peer_identity, &occ->peer_identity,
                   sizeof (struct GNUNET_PeerIdentity));
    memcpy (msg->hello, occ->hello, hello_size);
    GNUNET_TESTBED_queue_message_ (occ->peer2_controller, &msg->header);
  }
  else
  {
    LOG_DEBUG ("0x%llx: Offering HELLO of %s to %s\n", occ->op_id,
               GNUNET_i2s (&occ->peer_identity), other_peer_str);
    occ->ohh =
        GNUNET_TRANSPORT_offer_hello (occ->tcc.th_, occ->hello,
                                      occ_hello_sent_cb, occ);
    if (NULL == occ->ohh)
    {
      GNUNET_break (0);
      occ->send_hello_task =
          GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                        (GNUNET_TIME_UNIT_MILLISECONDS,
                                         100 +
                                         GNUNET_CRYPTO_random_u32
                                         (GNUNET_CRYPTO_QUALITY_WEAK, 500)),
                                        &send_hello, occ);
    }
  }
  GNUNET_free (other_peer_str);
}


/**
 * Callback from cache with needed handles set
 *
 * @param cls the closure passed to GST_cache_get_handle_transport()
 * @param ch the handle to CORE. Can be NULL if it is not requested
 * @param th the handle to TRANSPORT. Can be NULL if it is not requested
 * @param ignore_ peer identity which is ignored in this callback
 */
static void
p2_transport_connect_cache_callback (void *cls, struct GNUNET_CORE_Handle *ch,
                                     struct GNUNET_TRANSPORT_Handle *th,
                                     const struct GNUNET_PeerIdentity *ignore_)
{
  struct OverlayConnectContext *occ = cls;

  if (NULL == th)
  {
    GNUNET_asprintf (&occ->emsg, "0x%llx: Cannot connect to TRANSPORT of %s",
                     occ->op_id, GNUNET_i2s (&occ->other_peer_identity));
    GNUNET_SCHEDULER_cancel (occ->timeout_task);
    occ->timeout_task =
        GNUNET_SCHEDULER_add_now (&timeout_overlay_connect, occ);
    return;
  }
  occ->tcc.th_ = th;
  GNUNET_asprintf (&occ->emsg, "0x%llx: Timeout while offering HELLO to %s",
                   occ->op_id, GNUNET_i2s (&occ->other_peer_identity));
  occ->send_hello_task = GNUNET_SCHEDULER_add_now (&send_hello, occ);
}


/**
 * Connects to the transport of the other peer if it is a local peer and
 * schedules the send hello task
 *
 * @param occ the overlay connect context
 */
static void
p2_transport_connect (struct OverlayConnectContext *occ)
{
  GNUNET_assert (NULL == occ->emsg);
  GNUNET_assert (NULL != occ->hello);
  GNUNET_assert (NULL == occ->ghh);
  GNUNET_assert (NULL == occ->p1th_);
  GNUNET_assert (NULL == occ->cgh_p1th);
  if (NULL == occ->peer2_controller)
  {
    GST_peer_list[occ->other_peer_id]->reference_cnt++;
    occ->tcc.cgh_th =
        GST_cache_get_handle_transport (occ->other_peer_id,
                                        GST_peer_list[occ->other_peer_id]->
                                        details.local.cfg,
                                        &p2_transport_connect_cache_callback,
                                        occ, NULL, NULL, NULL);
    return;
  }
  GNUNET_asprintf (&occ->emsg, "0x%llx: Timeout while offering HELLO to %s",
                   occ->op_id, GNUNET_i2s (&occ->other_peer_identity));
  occ->send_hello_task = GNUNET_SCHEDULER_add_now (&send_hello, occ);
}


/**
 * Test for checking whether HELLO message is empty
 *
 * @param cls empty flag to set
 * @param address the HELLO
 * @param expiration expiration of the HELLO
 * @return
 */
static int
test_address (void *cls, const struct GNUNET_HELLO_Address *address,
              struct GNUNET_TIME_Absolute expiration)
{
  int *empty = cls;

  *empty = GNUNET_NO;
  return GNUNET_OK;
}


/**
 * Function called whenever there is an update to the HELLO of peers in the
 * OverlayConnectClosure. If we have a valid HELLO, we connect to the peer 2's
 * transport and offer peer 1's HELLO and ask peer 2 to connect to peer 1
 *
 * @param cls closure
 * @param hello our updated HELLO
 */
static void
hello_update_cb (void *cls, const struct GNUNET_MessageHeader *hello)
{
  struct OverlayConnectContext *occ = cls;
  int empty;
  uint16_t msize;

  msize = ntohs (hello->size);
  empty = GNUNET_YES;
  (void) GNUNET_HELLO_iterate_addresses ((const struct GNUNET_HELLO_Message *)
                                         hello, GNUNET_NO, &test_address,
                                         &empty);
  if (GNUNET_YES == empty)
  {
    LOG_DEBUG ("0x%llx: HELLO of %s is empty\n", occ->op_id,
               GNUNET_i2s (&occ->peer_identity));
    return;
  }
  LOG_DEBUG ("0x%llx: Received HELLO of %s\n", occ->op_id,
             GNUNET_i2s (&occ->peer_identity));
  occ->hello = GNUNET_malloc (msize);
  GST_cache_add_hello (occ->peer_id, hello);
  memcpy (occ->hello, hello, msize);
  GNUNET_TRANSPORT_get_hello_cancel (occ->ghh);
  occ->ghh = NULL;
  GST_cache_get_handle_done (occ->cgh_p1th);
  occ->peer->reference_cnt--;
  occ->cgh_p1th = NULL;
  occ->p1th_ = NULL;
  GNUNET_free_non_null (occ->emsg);
  occ->emsg = NULL;
  p2_transport_connect (occ);
}


/**
 * Callback from cache with needed handles set
 *
 * @param cls the closure passed to GST_cache_get_handle_transport()
 * @param ch the handle to CORE. Can be NULL if it is not requested
 * @param th the handle to TRANSPORT. Can be NULL if it is not requested
 * @param ignore_ peer identity which is ignored in this callback
 */
static void
p1_transport_connect_cache_callback (void *cls, struct GNUNET_CORE_Handle *ch,
                                     struct GNUNET_TRANSPORT_Handle *th,
                                     const struct GNUNET_PeerIdentity *ignore_)
{
  struct OverlayConnectContext *occ = cls;

  GNUNET_free_non_null (occ->emsg);
  occ->emsg = NULL;
  if (NULL == th)
  {
    GNUNET_asprintf (&occ->emsg, "0x%llx: Cannot connect to TRANSPORT of %s",
                     occ->op_id, GNUNET_i2s (&occ->peer_identity));
    GNUNET_SCHEDULER_cancel (occ->timeout_task);
    occ->timeout_task =
        GNUNET_SCHEDULER_add_now (&timeout_overlay_connect, occ);
    return;
  }
  GNUNET_assert (NULL == occ->p1th_);
  GNUNET_assert (NULL != occ->cgh_p1th);
  occ->p1th_ = th;
  GNUNET_asprintf (&occ->emsg,
                   "0x%llx: Timeout while acquiring HELLO of peer %4s",
                   occ->op_id, GNUNET_i2s (&occ->peer_identity));
  occ->ghh = GNUNET_TRANSPORT_get_hello (occ->p1th_, &hello_update_cb, occ);
}


/**
 * Callback from cache with needed handles set
 *
 * @param cls the closure passed to GST_cache_get_handle_transport()
 * @param ch the handle to CORE. Can be NULL if it is not requested
 * @param th the handle to TRANSPORT. Can be NULL if it is not requested
 * @param my_identity the identity of our peer
 */
static void
occ_cache_get_handle_core_cb (void *cls, struct GNUNET_CORE_Handle *ch,
                              struct GNUNET_TRANSPORT_Handle *th,
                              const struct GNUNET_PeerIdentity *my_identity)
{
  struct OverlayConnectContext *occ = cls;
  const struct GNUNET_MessageHeader *hello;

  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK != occ->timeout_task);
  GNUNET_free_non_null (occ->emsg);
  if ((NULL == ch) || (NULL == my_identity))
  {
    (void) GNUNET_asprintf (&occ->emsg,
                            "0x%llx: Failed to connect to CORE of peer with"
                            "id: %u", occ->op_id, occ->peer_id);
    GNUNET_SCHEDULER_cancel (occ->timeout_task);
    occ->timeout_task =
        GNUNET_SCHEDULER_add_now (&timeout_overlay_connect, occ);
    return;
  }
  //occ->ch_ = ch;
  occ->emsg = NULL;
  if (GNUNET_YES ==
      GNUNET_CORE_is_peer_connected_sync (ch, &occ->other_peer_identity))
  {
    LOG_DEBUG ("0x%llx: Target peer already connected\n", occ->op_id);
    GNUNET_SCHEDULER_cancel (occ->timeout_task);
    occ->timeout_task = GNUNET_SCHEDULER_NO_TASK;
    send_overlay_connect_success_msg (occ);
    occ->cleanup_task = GNUNET_SCHEDULER_add_now (&do_cleanup_occ, occ);
    return;
  }
  memcpy (&occ->peer_identity, my_identity,
          sizeof (struct GNUNET_PeerIdentity));
  LOG_DEBUG ("0x%llx: Acquiring HELLO of peer %s\n", occ->op_id,
             GNUNET_i2s (&occ->peer_identity));
  /* Lookup for HELLO in hello cache */
  if (NULL != (hello = GST_cache_lookup_hello (occ->peer_id)))
  {
    LOG_DEBUG ("0x%llx: HELLO of peer %s found in cache\n", occ->op_id,
               GNUNET_i2s (&occ->peer_identity));
    occ->hello = GNUNET_copy_message (hello);
    p2_transport_connect (occ);
    return;
  }
  GNUNET_asprintf (&occ->emsg,
                   "0x%llx: Timeout while acquiring TRANSPORT of %s from cache",
                   occ->op_id, GNUNET_i2s (&occ->peer_identity));
  occ->peer->reference_cnt++;
  occ->cgh_p1th =
      GST_cache_get_handle_transport (occ->peer_id,
                                      occ->peer->details.local.cfg,
                                      p1_transport_connect_cache_callback, occ,
                                      NULL, NULL, NULL);
  return;
}


/**
 * Callback to be called when forwarded get peer config operation as part of
 * overlay connect is successfull. Connection to Peer 1's core is made and is
 * checked for new connection from peer 2
 *
 * @param cls ForwardedOperationContext
 * @param msg the peer create success message
 */
static void
overlay_connect_get_config (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct OverlayConnectContext *occ = cls;
  const struct GNUNET_TESTBED_PeerConfigurationInformationMessage *cmsg;

  occ->opc = NULL;
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK != occ->timeout_task);
  if (GNUNET_MESSAGE_TYPE_TESTBED_PEER_CONFIGURATION != ntohs (msg->type))
  {
    GNUNET_SCHEDULER_cancel (occ->timeout_task);
    occ->timeout_task =
        GNUNET_SCHEDULER_add_now (&timeout_overlay_connect, occ);
  }
  cmsg =
      (const struct GNUNET_TESTBED_PeerConfigurationInformationMessage *) msg;
  memcpy (&occ->other_peer_identity, &cmsg->peer_identity,
          sizeof (struct GNUNET_PeerIdentity));
  GNUNET_free_non_null (occ->emsg);
  GNUNET_asprintf (&occ->emsg,
                   "0x%llx: Timeout while connecting to CORE of peer with "
                   "id: %u", occ->op_id, occ->peer_id);
  occ->peer->reference_cnt++;
  occ->cgh_ch =
      GST_cache_get_handle_core (occ->peer_id, occ->peer->details.local.cfg,
                                 occ_cache_get_handle_core_cb, occ,
                                 &occ->other_peer_identity,
                                 &overlay_connect_notify, occ);
  return;
}


/**
 * Callback which will be called to after a host registration succeeded or failed
 *
 * @param cls the RegisteredHostContext
 * @param emsg the error message; NULL if host registration is successful
 */
static void
registeredhost_registration_completion (void *cls, const char *emsg)
{
  struct RegisteredHostContext *rhc = cls;
  struct GNUNET_CONFIGURATION_Handle *cfg;
  uint32_t peer2_host_id;

  /* if (NULL != rhc->focc_dll_head) */
  /*   TESTBED_process_next_focc (rhc); */
  peer2_host_id = GNUNET_TESTBED_host_get_id_ (rhc->reg_host);
  GNUNET_assert (RHC_INIT == rhc->state);
  GNUNET_assert (NULL == rhc->sub_op);
  if ((NULL == rhc->gateway2) || ((peer2_host_id < GST_slave_list_size) /* Check if we have the needed config */
                                  && (NULL != GST_slave_list[peer2_host_id])))
  {
    rhc->state = RHC_LINK;
    cfg =
        (NULL ==
         rhc->gateway2) ? our_config : GST_slave_list[peer2_host_id]->cfg;
    rhc->sub_op =
        GNUNET_TESTBED_controller_link (rhc, rhc->gateway->controller,
                                        rhc->reg_host, rhc->host, cfg,
                                        GNUNET_NO);
    return;
  }
  rhc->state = RHC_GET_CFG;
  rhc->sub_op =
      GNUNET_TESTBED_get_slave_config (rhc, rhc->gateway2->controller,
                                       rhc->reg_host);
}


/**
 * Iterator to match a registered host context
 *
 * @param cls pointer 2 pointer of RegisteredHostContext
 * @param key current key code
 * @param value value in the hash map
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
static int
reghost_match_iterator (void *cls, const struct GNUNET_HashCode *key,
                        void *value)
{
  struct RegisteredHostContext **rh = cls;
  struct RegisteredHostContext *rh_val = value;

  if ((rh_val->host == (*rh)->host) && (rh_val->reg_host == (*rh)->reg_host))
  {
    GNUNET_free (*rh);
    *rh = rh_val;
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Function to generate the hashcode corresponding to a RegisteredHostContext
 *
 * @param reg_host the host which is being registered in RegisteredHostContext
 * @param host the host of the controller which has to connect to the above rhost
 * @return the hashcode
 */
static struct GNUNET_HashCode
hash_hosts (struct GNUNET_TESTBED_Host *reg_host,
            struct GNUNET_TESTBED_Host *host)
{
  struct GNUNET_HashCode hash;
  uint32_t host_ids[2];

  host_ids[0] = GNUNET_TESTBED_host_get_id_ (reg_host);
  host_ids[1] = GNUNET_TESTBED_host_get_id_ (host);
  GNUNET_CRYPTO_hash (host_ids, sizeof (host_ids), &hash);
  return hash;
}


/**
 * Handler for GNUNET_MESSAGE_TYPE_TESTBED_OLCONNECT messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
void
GST_handle_overlay_connect (void *cls, struct GNUNET_SERVER_Client *client,
                            const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TESTBED_OverlayConnectMessage *msg;
  struct Peer *peer;
  struct OverlayConnectContext *occ;
  struct GNUNET_TESTBED_Controller *peer2_controller;
  uint64_t operation_id;
  uint32_t p1;
  uint32_t p2;
  uint32_t peer2_host_id;

  if (sizeof (struct GNUNET_TESTBED_OverlayConnectMessage) !=
      ntohs (message->size))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  msg = (const struct GNUNET_TESTBED_OverlayConnectMessage *) message;
  p1 = ntohl (msg->peer1);
  p2 = ntohl (msg->peer2);
  if ((p1 >= GST_peer_list_size) || (NULL == GST_peer_list[p1]))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  peer = GST_peer_list[p1];
  peer2_host_id = ntohl (msg->peer2_host_id);
  operation_id = GNUNET_ntohll (msg->operation_id);
  LOG_DEBUG
      ("Received overlay connect for peers %u and %u with op id: 0x%llx\n", p1,
       p2, operation_id);
  if (GNUNET_YES == peer->is_remote)
  {
    struct ForwardedOperationContext *fopc;
    struct Route *route_to_peer2_host;
    struct Route *route_to_peer1_host;

    LOG_DEBUG ("0x%llx: Forwarding overlay connect\n", operation_id);
    route_to_peer2_host = NULL;
    route_to_peer1_host = NULL;
    route_to_peer2_host = GST_find_dest_route (peer2_host_id);
    if ((NULL != route_to_peer2_host) ||
        (peer2_host_id == GST_context->host_id))
    {
      /* Peer 2 either below us OR with us */
      route_to_peer1_host =
          GST_find_dest_route (GST_peer_list[p1]->details.
                               remote.remote_host_id);
      /* Because we get this message only if we know where peer 1 is */
      GNUNET_assert (NULL != route_to_peer1_host);
      if ((peer2_host_id == GST_context->host_id) ||
          (route_to_peer2_host->dest != route_to_peer1_host->dest))
      {
        /* Peer2 is either with us OR peer1 and peer2 can be reached through
         * different gateways */
        struct GNUNET_HashCode hash;
        struct RegisteredHostContext *rhc;
        int skip_focc;

        rhc = GNUNET_malloc (sizeof (struct RegisteredHostContext));
        if (NULL != route_to_peer2_host)
          rhc->reg_host = GST_host_list[route_to_peer2_host->dest];
        else
          rhc->reg_host = GST_host_list[GST_context->host_id];
        rhc->host = GST_host_list[route_to_peer1_host->dest];
        GNUNET_assert (NULL != rhc->reg_host);
        GNUNET_assert (NULL != rhc->host);
        rhc->gateway = peer->details.remote.slave;
        rhc->gateway2 =
            (NULL ==
             route_to_peer2_host) ? NULL :
            GST_slave_list[route_to_peer2_host->dest];
        rhc->state = RHC_INIT;
        GNUNET_SERVER_client_keep (client);
        rhc->client = client;
        hash = hash_hosts (rhc->reg_host, rhc->host);
        skip_focc = GNUNET_NO;
        if ((GNUNET_NO ==
             GNUNET_CONTAINER_multihashmap_contains (peer->details.
                                                     remote.slave->reghost_map,
                                                     &hash)) ||
            (GNUNET_SYSERR !=
             GNUNET_CONTAINER_multihashmap_get_multiple (peer->details.remote.
                                                         slave->reghost_map,
                                                         &hash,
                                                         reghost_match_iterator,
                                                         &rhc)))
        {
          /* create and add a new registerd host context */
          /* add the focc to its queue */
          GNUNET_CONTAINER_multihashmap_put (peer->details.remote.
                                             slave->reghost_map, &hash, rhc,
                                             GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
          GNUNET_assert (NULL != GST_host_list[peer2_host_id]);
          GST_queue_host_registration (peer->details.remote.slave,
                                       registeredhost_registration_completion,
                                       rhc, GST_host_list[peer2_host_id]);
        }
        else
        {
          /* rhc is now set to the existing one from the hash map by
           * reghost_match_iterator() */
          /* if queue is empty then ignore creating focc and proceed with
           * normal forwarding */
          if (RHC_OL_CONNECT == rhc->state)
            skip_focc = GNUNET_YES;
        }
        if (GNUNET_NO == skip_focc)
        {
          struct ForwardedOverlayConnectContext *focc;

          focc = GNUNET_malloc (sizeof (struct ForwardedOverlayConnectContext));
          focc->peer1 = p1;
          focc->peer2 = p2;
          focc->peer2_host_id = peer2_host_id;
          focc->orig_msg = GNUNET_copy_message (message);
          focc->operation_id = operation_id;
          GNUNET_CONTAINER_DLL_insert_tail (rhc->focc_dll_head,
                                            rhc->focc_dll_tail, focc);
          GNUNET_SERVER_receive_done (client, GNUNET_OK);
          return;
        }
      }
    }
    fopc = GNUNET_malloc (sizeof (struct ForwardedOperationContext));
    GNUNET_SERVER_client_keep (client);
    fopc->client = client;
    fopc->operation_id = operation_id;
    fopc->type = OP_OVERLAY_CONNECT;
    fopc->opc =
        GNUNET_TESTBED_forward_operation_msg_ (peer->details.remote.
                                               slave->controller, operation_id,
                                               message,
                                               &GST_forwarded_operation_reply_relay,
                                               fopc);
    fopc->timeout_task =
        GNUNET_SCHEDULER_add_delayed (TIMEOUT, &GST_forwarded_operation_timeout,
                                      fopc);
    GNUNET_CONTAINER_DLL_insert_tail (fopcq_head, fopcq_tail, fopc);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  peer2_controller = NULL;
  if ((p2 >= GST_peer_list_size) || (NULL == GST_peer_list[p2]))
  {
    if ((peer2_host_id >= GST_slave_list_size) ||
        (NULL == GST_slave_list[peer2_host_id]))
    {
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "0x%llx: Configuration of peer2's controller missing for connecting peers"
           "%u and %u\n", operation_id, p1, p2);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
    peer2_controller = GST_slave_list[peer2_host_id]->controller;
    if (NULL == peer2_controller)
    {
      GNUNET_break (0);         /* What's going on? */
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  }
  else
  {
    if (GNUNET_YES == GST_peer_list[p2]->is_remote)
      peer2_controller = GST_peer_list[p2]->details.remote.slave->controller;
  }
  occ = GNUNET_malloc (sizeof (struct OverlayConnectContext));
  GNUNET_CONTAINER_DLL_insert_tail (occq_head, occq_tail, occ);
  GNUNET_SERVER_client_keep (client);
  occ->client = client;
  occ->peer_id = p1;
  occ->other_peer_id = p2;
  occ->peer = GST_peer_list[p1];
  occ->op_id = GNUNET_ntohll (msg->operation_id);
  occ->peer2_controller = peer2_controller;
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == occ->timeout_task);
  occ->timeout_task =
      GNUNET_SCHEDULER_add_delayed (TIMEOUT, &timeout_overlay_connect, occ);
  /* Get the identity of the second peer */
  if (NULL != occ->peer2_controller)
  {
    struct GNUNET_TESTBED_PeerGetConfigurationMessage cmsg;

    cmsg.header.size =
        htons (sizeof (struct GNUNET_TESTBED_PeerGetConfigurationMessage));
    cmsg.header.type =
        htons (GNUNET_MESSAGE_TYPE_TESTBED_GET_PEER_CONFIGURATION);
    cmsg.peer_id = msg->peer2;
    cmsg.operation_id = msg->operation_id;
    occ->opc =
        GNUNET_TESTBED_forward_operation_msg_ (occ->peer2_controller,
                                               occ->op_id, &cmsg.header,
                                               &overlay_connect_get_config,
                                               occ);
    GNUNET_asprintf (&occ->emsg,
                     "0x%llx: Timeout while getting peer identity of peer "
                     "with id: %u", occ->op_id, occ->other_peer_id);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  GNUNET_TESTING_peer_get_identity (GST_peer_list[occ->other_peer_id]->
                                    details.local.peer,
                                    &occ->other_peer_identity);
  GNUNET_asprintf (&occ->emsg,
                   "0x%llx: Timeout while connecting to CORE of peer with "
                   "id: %u", occ->op_id, occ->peer_id);
  occ->peer->reference_cnt++;
  occ->cgh_ch =
      GST_cache_get_handle_core (occ->peer_id, occ->peer->details.local.cfg,
                                 occ_cache_get_handle_core_cb, occ,
                                 &occ->other_peer_identity,
                                 &overlay_connect_notify, occ);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Function to cleanup RemoteOverlayConnectCtx and any associated tasks
 * with it
 *
 * @param rocc the RemoteOverlayConnectCtx
 */
static void
cleanup_rocc (struct RemoteOverlayConnectCtx *rocc)
{
  LOG_DEBUG ("0x%llx: Cleaning up rocc\n", rocc->op_id);
  if (GNUNET_SCHEDULER_NO_TASK != rocc->attempt_connect_task_id)
    GNUNET_SCHEDULER_cancel (rocc->attempt_connect_task_id);
  if (GNUNET_SCHEDULER_NO_TASK != rocc->timeout_rocc_task_id)
    GNUNET_SCHEDULER_cancel (rocc->timeout_rocc_task_id);
  if (NULL != rocc->ohh)
    GNUNET_TRANSPORT_offer_hello_cancel (rocc->ohh);
  if (NULL != rocc->tcc.tch)
    GNUNET_TRANSPORT_try_connect_cancel (rocc->tcc.tch);
  if (GNUNET_SCHEDULER_NO_TASK != rocc->tcc.task)
    GNUNET_SCHEDULER_cancel (rocc->tcc.task);
  //GNUNET_TRANSPORT_disconnect (rocc->tcc.th_);
  GST_cache_get_handle_done (rocc->tcc.cgh_th);
  rocc->peer->reference_cnt--;
  if ((GNUNET_YES == rocc->peer->destroy_flag) &&
      (0 == rocc->peer->reference_cnt))
    GST_destroy_peer (rocc->peer);
  GNUNET_free_non_null (rocc->hello);
  GNUNET_CONTAINER_DLL_remove (roccq_head, roccq_tail, rocc);
  GNUNET_free (rocc);
}


/**
 * Task to timeout rocc and cleanit up
 *
 * @param cls the RemoteOverlayConnectCtx
 * @param tc the TaskContext from scheduler
 */
static void
timeout_rocc_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct RemoteOverlayConnectCtx *rocc = cls;

  GNUNET_assert (rocc->timeout_rocc_task_id != GNUNET_SCHEDULER_NO_TASK);
  rocc->timeout_rocc_task_id = GNUNET_SCHEDULER_NO_TASK;
  LOG_DEBUG ("0x%llx: rocc timed out\n", rocc->op_id);
  cleanup_rocc (rocc);
}


/**
 * Function called to notify transport users that another
 * peer connected to us.
 *
 * @param cls closure
 * @param new_peer the peer that connected
 * @param ats performance data
 * @param ats_count number of entries in ats (excluding 0-termination)
 */
static void
cache_transport_peer_connect_notify (void *cls,
                                     const struct GNUNET_PeerIdentity *new_peer)
{
  struct RemoteOverlayConnectCtx *rocc = cls;

  LOG_DEBUG ("0x%llx: Request Overlay connect notify\n", rocc->op_id);
  GNUNET_assert (0 ==
                 memcmp (new_peer, &rocc->a_id,
                         sizeof (struct GNUNET_PeerIdentity)));
  LOG_DEBUG ("0x%llx: Peer %4s connected\n", rocc->op_id,
             GNUNET_i2s (&rocc->a_id));
  cleanup_rocc (rocc);
}


/**
 * Task to offer the HELLO message to the peer and ask it to connect to the peer
 * whose identity is in RemoteOverlayConnectCtx
 *
 * @param cls the RemoteOverlayConnectCtx
 * @param tc the TaskContext from scheduler
 */
static void
attempt_connect_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Task that is run when hello has been sent
 *
 * @param cls the overlay connect context
 * @param tc the scheduler task context; if tc->reason =
 *          GNUNET_SCHEDULER_REASON_TIMEOUT then sending HELLO failed; if
 *          GNUNET_SCHEDULER_REASON_READ_READY is succeeded
 */
static void
rocc_hello_sent_cb (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct RemoteOverlayConnectCtx *rocc = cls;

  rocc->ohh = NULL;
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == rocc->attempt_connect_task_id);
  LOG_DEBUG ("0x%llx: HELLO of peer %4s sent to local peer with id: %u\n",
             rocc->op_id, GNUNET_i2s (&rocc->a_id), rocc->peer->id);
  if (GNUNET_SCHEDULER_REASON_TIMEOUT == tc->reason)
  {
    GNUNET_break (0);
    rocc->attempt_connect_task_id =
        GNUNET_SCHEDULER_add_now (&attempt_connect_task, rocc);
    return;
  }
  if (GNUNET_SCHEDULER_REASON_READ_READY != tc->reason)
    return;
  rocc->tcc.task = GNUNET_SCHEDULER_add_now (&try_connect_task, &rocc->tcc);
}


/**
 * Task to offer the HELLO message to the peer and ask it to connect to the peer
 * whose identity is in RemoteOverlayConnectCtx
 *
 * @param cls the RemoteOverlayConnectCtx
 * @param tc the TaskContext from scheduler
 */
static void
attempt_connect_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct RemoteOverlayConnectCtx *rocc = cls;

  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK != rocc->attempt_connect_task_id);
  rocc->attempt_connect_task_id = GNUNET_SCHEDULER_NO_TASK;
  LOG_DEBUG ("0x%llx: Offering HELLO of peer %4s to local peer with id: %u\n",
             rocc->op_id, GNUNET_i2s (&rocc->a_id), rocc->peer->id);
  rocc->ohh =
      GNUNET_TRANSPORT_offer_hello (rocc->tcc.th_, rocc->hello,
                                    rocc_hello_sent_cb, rocc);
  if (NULL == rocc->ohh)
    rocc->attempt_connect_task_id =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                      (GNUNET_TIME_UNIT_MILLISECONDS,
                                       100 +
                                       GNUNET_CRYPTO_random_u32
                                       (GNUNET_CRYPTO_QUALITY_WEAK, 500)),
                                      &attempt_connect_task, rocc);
}


/**
 * Callback from cache with needed handles set
 *
 * @param cls the closure passed to GST_cache_get_handle_transport()
 * @param ch the handle to CORE. Can be NULL if it is not requested
 * @param th the handle to TRANSPORT. Can be NULL if it is not requested
 * @param ignore_ peer identity which is ignored in this callback
 */
static void
rocc_cache_get_handle_transport_cb (void *cls, struct GNUNET_CORE_Handle *ch,
                                    struct GNUNET_TRANSPORT_Handle *th,
                                    const struct GNUNET_PeerIdentity *ignore_)
{
  struct RemoteOverlayConnectCtx *rocc = cls;

  if (NULL == th)
  {
    rocc->timeout_rocc_task_id =
        GNUNET_SCHEDULER_add_now (&timeout_rocc_task, rocc);
    return;
  }
  rocc->tcc.th_ = th;
  rocc->tcc.pid = &rocc->a_id;
  if (GNUNET_YES ==
      GNUNET_TRANSPORT_check_neighbour_connected (rocc->tcc.th_, rocc->tcc.pid))
  {
    LOG_DEBUG ("0x%llx: Target peer %4s already connected to local peer: %u\n",
               rocc->op_id, GNUNET_i2s (&rocc->a_id), rocc->peer->id);
    cleanup_rocc (rocc);
    return;
  }
  rocc->attempt_connect_task_id =
      GNUNET_SCHEDULER_add_now (&attempt_connect_task, rocc);
}


/**
 * Handler for GNUNET_MESSAGE_TYPE_TESTBED_REQUESTCONNECT messages
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
void
GST_handle_remote_overlay_connect (void *cls,
                                   struct GNUNET_SERVER_Client *client,
                                   const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TESTBED_RemoteOverlayConnectMessage *msg;
  struct RemoteOverlayConnectCtx *rocc;
  struct Peer *peer;
  uint32_t peer_id;
  uint16_t msize;
  uint16_t hsize;

  msize = ntohs (message->size);
  if (sizeof (struct GNUNET_TESTBED_RemoteOverlayConnectMessage) >= msize)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  msg = (const struct GNUNET_TESTBED_RemoteOverlayConnectMessage *) message;
  if ((NULL == msg->hello) ||
      (GNUNET_MESSAGE_TYPE_HELLO != ntohs (msg->hello->type)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  hsize = ntohs (msg->hello->size);
  if ((sizeof (struct GNUNET_TESTBED_RemoteOverlayConnectMessage) + hsize) !=
      msize)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  peer_id = ntohl (msg->peer);
  if ((peer_id >= GST_peer_list_size) ||
      (NULL == (peer = GST_peer_list[peer_id])))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  if (GNUNET_YES == peer->is_remote)
  {
    struct GNUNET_MessageHeader *msg2;

    msg2 = GNUNET_copy_message (message);
    GNUNET_TESTBED_queue_message_ (peer->details.remote.slave->controller,
                                   msg2);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  rocc = GNUNET_malloc (sizeof (struct RemoteOverlayConnectCtx));
  rocc->op_id = GNUNET_ntohll (msg->operation_id);
  GNUNET_CONTAINER_DLL_insert_tail (roccq_head, roccq_tail, rocc);
  memcpy (&rocc->a_id, &msg->peer_identity,
          sizeof (struct GNUNET_PeerIdentity));
  LOG_DEBUG ("Received request for overlay connection with op_id: 0x%llx "
             "from local peer %u to peer %4s with hello size: %u\n",
             rocc->op_id, peer_id, GNUNET_i2s (&rocc->a_id), hsize);
  rocc->peer = peer;
  rocc->peer->reference_cnt++;
  rocc->hello = GNUNET_malloc (hsize);
  memcpy (rocc->hello, msg->hello, hsize);
  rocc->tcc.cgh_th =
      GST_cache_get_handle_transport (peer_id, rocc->peer->details.local.cfg,
                                      &rocc_cache_get_handle_transport_cb, rocc,
                                      &rocc->a_id,
                                      &cache_transport_peer_connect_notify,
                                      rocc);
  rocc->timeout_rocc_task_id =
      GNUNET_SCHEDULER_add_delayed (TIMEOUT, &timeout_rocc_task, rocc);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Clears all pending overlay connect contexts in queue
 */
void
GST_free_occq ()
{
  struct OverlayConnectContext *occ;

  while (NULL != (occ = occq_head))
    cleanup_occ (occ);
}


/**
 * Clears all pending remote overlay connect contexts in queue
 */
void
GST_free_roccq ()
{
  struct RemoteOverlayConnectCtx *rocc;

  while (NULL != (rocc = roccq_head))
    cleanup_rocc (rocc);
}
