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
 * @file set/set_api.c
 * @brief api for the set service
 * @author Florian Dold
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_client_lib.h"
#include "gnunet_set_service.h"
#include "set.h"


#define LOG(kind,...) GNUNET_log_from (kind, "set-api",__VA_ARGS__)


/**
 * Opaque handle to a set.
 */
struct GNUNET_SET_Handle
{
  struct GNUNET_CLIENT_Connection *client;
  struct GNUNET_MQ_Handle *mq;
  unsigned int messages_since_ack;
};

/**
 * Opaque handle to a set operation request from another peer.
 */
struct GNUNET_SET_Request
{
  uint32_t accept_id;
  int accepted;
};

struct GNUNET_SET_OperationHandle
{
  GNUNET_SET_ResultIterator result_cb;
  void *result_cls;

  /**
   * Local set used for the operation,
   * NULL if no set has been provided by conclude yet.
   */
  struct GNUNET_SET_Handle *set;

  /**
   * Request ID to identify the operation within the set.
   */
  uint32_t request_id;

  /**
   * Message sent to the server on calling conclude,
   * NULL if conclude has been called.
   */
  struct GNUNET_MQ_Envelope *conclude_mqm;

  /**
   * Address of the request if in the conclude message,
   * used to patch the request id into the message when the set is known.
   */
  uint32_t *request_id_addr;
};


/**
 * Opaque handle to a listen operation.
 */
struct GNUNET_SET_ListenHandle
{
  struct GNUNET_CLIENT_Connection *client;
  struct GNUNET_MQ_Handle* mq;
  GNUNET_SET_ListenCallback listen_cb;
  void *listen_cls;
};


/**
 * Handle result message for a set operation.
 *
 * @param cls the set
 * @param mh the message
 */
static void
handle_result (void *cls, const struct GNUNET_MessageHeader *mh)
{
  struct GNUNET_SET_ResultMessage *msg = (struct GNUNET_SET_ResultMessage *) mh;
  struct GNUNET_SET_Handle *set = cls;
  struct GNUNET_SET_OperationHandle *oh;
  struct GNUNET_SET_Element e;


  GNUNET_assert (NULL != set);
  GNUNET_assert (NULL != set->mq);

  if (set->messages_since_ack >= GNUNET_SET_ACK_WINDOW/2)
  {
    struct GNUNET_MQ_Envelope *mqm;
    mqm = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_SET_ACK);
    GNUNET_MQ_send (set->mq, mqm);
  }
  oh = GNUNET_MQ_assoc_get (set->mq, ntohl (msg->request_id));
  GNUNET_assert (NULL != oh);
  /* status is not STATUS_OK => there's no attached element,
   * and this is the last result message we get */
  if (htons (msg->result_status) != GNUNET_SET_STATUS_OK)
  {
    GNUNET_MQ_assoc_remove (set->mq, ntohl (msg->request_id));
    if (NULL != oh->result_cb)
      oh->result_cb (oh->result_cls, NULL, htons (msg->result_status));
    GNUNET_free (oh);
    return;
  }

  e.data = &msg[1];
  e.size = ntohs (mh->size) - sizeof (struct GNUNET_SET_ResultMessage);
  e.type = msg->element_type;
  if (NULL != oh->result_cb)
    oh->result_cb (oh->result_cls, &e, htons (msg->result_status));
}

/**
 * Handle request message for a listen operation
 *
 * @param cls the listen handle
 * @param mh the message
 */
static void
handle_request (void *cls, const struct GNUNET_MessageHeader *mh)
{
  struct GNUNET_SET_RequestMessage *msg = (struct GNUNET_SET_RequestMessage *) mh;
  struct GNUNET_SET_ListenHandle *lh = cls;
  struct GNUNET_SET_Request *req;
  struct GNUNET_MessageHeader *context_msg;

  LOG (GNUNET_ERROR_TYPE_INFO, "processing request\n");
  req = GNUNET_new (struct GNUNET_SET_Request);
  req->accept_id = ntohl (msg->accept_id);
  context_msg = GNUNET_MQ_extract_nested_mh (msg);
  /* calling GNUNET_SET_accept in the listen cb will set req->accepted */
  lh->listen_cb (lh->listen_cls, &msg->peer_id, context_msg, req);

  if (GNUNET_NO == req->accepted)
  {
    struct GNUNET_MQ_Envelope *mqm;
    struct GNUNET_SET_AcceptRejectMessage *amsg;

    mqm = GNUNET_MQ_msg (amsg, GNUNET_MESSAGE_TYPE_SET_REJECT);
    /* no request id, as we refused */
    amsg->request_id = htonl (0);
    amsg->accept_reject_id = msg->accept_id;
    GNUNET_MQ_send (lh->mq, mqm);
    GNUNET_free (req);
    LOG (GNUNET_ERROR_TYPE_INFO, "rejecting request\n");
  }

  LOG (GNUNET_ERROR_TYPE_INFO, "processed op request from service\n");

  /* the accept-case is handled in GNUNET_SET_accept,
   * as we have the accept message available there */
}


/**
 * Create an empty set, supporting the specified operation.
 *
 * @param cfg configuration to use for connecting to the
 *        set service
 * @param op operation supported by the set
 *        Note that the operation has to be specified
 *        beforehand, as certain set operations need to maintain
 *        data structures spefific to the operation
 * @return a handle to the set
 */
struct GNUNET_SET_Handle *
GNUNET_SET_create (const struct GNUNET_CONFIGURATION_Handle *cfg,
                   enum GNUNET_SET_OperationType op)
{
  struct GNUNET_SET_Handle *set;
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_SET_CreateMessage *msg;
  static const struct GNUNET_MQ_MessageHandler mq_handlers[] = {
    {handle_result, GNUNET_MESSAGE_TYPE_SET_RESULT},
    GNUNET_MQ_HANDLERS_END
  };

  set = GNUNET_new (struct GNUNET_SET_Handle);
  set->client = GNUNET_CLIENT_connect ("set", cfg);
  LOG (GNUNET_ERROR_TYPE_INFO, "set client created\n");
  GNUNET_assert (NULL != set->client);
  set->mq = GNUNET_MQ_queue_for_connection_client (set->client, mq_handlers, set);
  GNUNET_assert (NULL != set->mq);
  mqm = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_SET_CREATE);
  msg->operation = htons (op);
  GNUNET_MQ_send (set->mq, mqm);
  return set;
}


/**
 * Add an element to the given set.
 * After the element has been added (in the sense of being
 * transmitted to the set service), cont will be called.
 * Calls to add_element can be queued
 *
 * @param set set to add element to
 * @param element element to add to the set
 * @param cont continuation called after the element has been added
 * @param cont_cls closure for cont
 */
void
GNUNET_SET_add_element (struct GNUNET_SET_Handle *set,
                        const struct GNUNET_SET_Element *element,
                        GNUNET_SET_Continuation cont,
                        void *cont_cls)
{
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_SET_ElementMessage *msg;

  mqm = GNUNET_MQ_msg_extra (msg, element->size, GNUNET_MESSAGE_TYPE_SET_ADD);
  msg->element_type = element->type;
  memcpy (&msg[1], element->data, element->size);
  GNUNET_MQ_notify_sent (mqm, cont, cont_cls);
  GNUNET_MQ_send (set->mq, mqm);
}


/**
 * Remove an element to the given set.
 * After the element has been removed (in the sense of the
 * request being transmitted to the set service), cont will be called.
 * Calls to remove_element can be queued
 *
 * @param set set to remove element from
 * @param element element to remove from the set
 * @param cont continuation called after the element has been removed
 * @param cont_cls closure for cont
 */
void
GNUNET_SET_remove_element (struct GNUNET_SET_Handle *set,
                           const struct GNUNET_SET_Element *element,
                           GNUNET_SET_Continuation cont,
                           void *cont_cls)
{
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_SET_ElementMessage *msg;

  mqm = GNUNET_MQ_msg_extra (msg, element->size, GNUNET_MESSAGE_TYPE_SET_REMOVE);
  msg->element_type = element->type;
  memcpy (&msg[1], element->data, element->size);
  GNUNET_MQ_notify_sent (mqm, cont, cont_cls);
  GNUNET_MQ_send (set->mq, mqm);
}


/**
 * Destroy the set handle, and free all associated resources.
 */
void
GNUNET_SET_destroy (struct GNUNET_SET_Handle *set)
{
  GNUNET_CLIENT_disconnect (set->client);
  set->client = NULL;
  GNUNET_MQ_destroy (set->mq);
  set->mq = NULL;
}


/**
 * Prepare a set operation to be evaluated with another peer.
 * The evaluation will not start until the client provides
 * a local set with GNUNET_SET_commit.
 *
 * @param other_peer peer with the other set
 * @param app_id hash for the application using the set
 * @param context_msg additional information for the request
 * @param salt salt used for the set operation; sometimes set operations
 *        fail due to hash collisions, using a different salt for each operation
 *        makes it harder for an attacker to exploit this
 * @param result_mode specified how results will be returned,
 *        see 'GNUNET_SET_ResultMode'.
 * @param result_cb called on error or success
 * @param result_cls closure for result_cb
 * @return a handle to cancel the operation
 */
struct GNUNET_SET_OperationHandle *
GNUNET_SET_prepare (const struct GNUNET_PeerIdentity *other_peer,
                    const struct GNUNET_HashCode *app_id,
                    const struct GNUNET_MessageHeader *context_msg,
                    uint16_t salt,
                    enum GNUNET_SET_ResultMode result_mode,
                    GNUNET_SET_ResultIterator result_cb,
                    void *result_cls)
{
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_SET_OperationHandle *oh;
  struct GNUNET_SET_EvaluateMessage *msg;

  oh = GNUNET_new (struct GNUNET_SET_OperationHandle);
  oh->result_cb = result_cb;
  oh->result_cls = result_cls;

  mqm = GNUNET_MQ_msg_nested_mh (msg, GNUNET_MESSAGE_TYPE_SET_EVALUATE, context_msg);

  msg->app_id = *app_id;
  msg->target_peer = *other_peer;
  msg->salt = salt;
  msg->reserved = 0;
  oh->conclude_mqm = mqm;
  oh->request_id_addr = &msg->request_id;

  return oh;
}


/**
 * Wait for set operation requests for the given application id
 * 
 * @param cfg configuration to use for connecting to
 *            the set service
 * @param operation operation we want to listen for
 * @param app_id id of the application that handles set operation requests
 * @param listen_cb called for each incoming request matching the operation
 *                  and application id
 * @param listen_cls handle for listen_cb
 * @return a handle that can be used to cancel the listen operation
 */
struct GNUNET_SET_ListenHandle *
GNUNET_SET_listen (const struct GNUNET_CONFIGURATION_Handle *cfg,
                   enum GNUNET_SET_OperationType operation,
                   const struct GNUNET_HashCode *app_id,
                   GNUNET_SET_ListenCallback listen_cb,
                   void *listen_cls)
{
  struct GNUNET_SET_ListenHandle *lh;
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_SET_ListenMessage *msg;
  static const struct GNUNET_MQ_MessageHandler mq_handlers[] = {
    {handle_request, GNUNET_MESSAGE_TYPE_SET_REQUEST},
    GNUNET_MQ_HANDLERS_END
  };

  lh = GNUNET_new (struct GNUNET_SET_ListenHandle);
  lh->client = GNUNET_CLIENT_connect ("set", cfg);
  lh->listen_cb = listen_cb;
  lh->listen_cls = listen_cls;
  GNUNET_assert (NULL != lh->client);
  lh->mq = GNUNET_MQ_queue_for_connection_client (lh->client, mq_handlers, lh);
  mqm = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_SET_LISTEN);
  msg->operation = htons (operation);
  msg->app_id = *app_id;
  GNUNET_MQ_send (lh->mq, mqm);

  return lh;
}


/**
 * Cancel the given listen operation.
 *
 * @param lh handle for the listen operation
 */
void
GNUNET_SET_listen_cancel (struct GNUNET_SET_ListenHandle *lh)
{
  GNUNET_CLIENT_disconnect (lh->client);
  GNUNET_MQ_destroy (lh->mq);
  GNUNET_free (lh);
}


/**
 * Accept a request we got via GNUNET_SET_listen.  Must be called during
 * GNUNET_SET_listen, as the 'struct GNUNET_SET_Request' becomes invalid
 * afterwards.
 * Call GNUNET_SET_conclude to provide the local set to use for the operation,
 * and to begin the exchange with the remote peer. 
 *
 * @param request request to accept
 * @param result_mode specified how results will be returned,
 *        see 'GNUNET_SET_ResultMode'.
 * @param result_cb callback for the results
 * @param cls closure for result_cb
 * @return a handle to cancel the operation
 */
struct GNUNET_SET_OperationHandle *
GNUNET_SET_accept (struct GNUNET_SET_Request *request,
                   enum GNUNET_SET_ResultMode result_mode,
                   GNUNET_SET_ResultIterator result_cb,
                   void *cls)
{
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_SET_OperationHandle *oh;
  struct GNUNET_SET_AcceptRejectMessage *msg;

  GNUNET_assert (GNUNET_NO == request->accepted);
  request->accepted = GNUNET_YES;

  oh = GNUNET_new (struct GNUNET_SET_OperationHandle);
  oh->result_cb = result_cb;
  oh->result_cls = cls;

  mqm = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_SET_ACCEPT);
  msg->accept_reject_id = htonl (request->accept_id);

  oh->conclude_mqm = mqm;
  oh->request_id_addr = &msg->request_id;

  return oh;
}


/**
 * Cancel the given set operation.
 *
 * @param oh set operation to cancel
 */
void
GNUNET_SET_operation_cancel (struct GNUNET_SET_OperationHandle *oh)
{
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_SET_OperationHandle *h_assoc;

  if (NULL != oh->set)
  {
    h_assoc = GNUNET_MQ_assoc_remove (oh->set->mq, oh->request_id);
    GNUNET_assert (h_assoc == oh);
    mqm = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_SET_CANCEL);
    GNUNET_MQ_send (oh->set->mq, mqm);
  }

  if (NULL != oh->conclude_mqm)
    GNUNET_MQ_discard (oh->conclude_mqm);

  GNUNET_free (oh);
}


/**
 * Commit a set to be used with a set operation.
 * This function is called once we have fully constructed
 * the set that we want to use for the operation.  At this
 * time, the P2P protocol can then begin to exchange the
 * set information and call the result callback with the
 * result information.
 *
 * @param oh handle to the set operation 
 * @param set the set to use for the operation
 */
void
GNUNET_SET_commit (struct GNUNET_SET_OperationHandle *oh,
		     struct GNUNET_SET_Handle *set)
{
  GNUNET_assert (NULL == oh->set);
  GNUNET_assert (NULL != oh->conclude_mqm);
  oh->set = set;
  oh->request_id = GNUNET_MQ_assoc_add (oh->set->mq, oh);
  *oh->request_id_addr = htonl (oh->request_id);
  GNUNET_MQ_send (oh->set->mq, oh->conclude_mqm);
  oh->conclude_mqm = NULL;
  oh->request_id_addr = NULL;
}

