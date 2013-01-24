/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file consensus/consensus_api.c
 * @brief 
 * @author Florian Dold
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_client_lib.h"
#include "gnunet_consensus_service.h"
#include "consensus.h"


#define LOG(kind,...) GNUNET_log_from (kind, "consensus-api",__VA_ARGS__)

/**
 * Actions that can be queued.
 */
struct QueuedMessage
{
  /**
   * Queued messages are stored in a doubly linked list.
   */
  struct QueuedMessage *next;

  /**
   * Queued messages are stored in a doubly linked list.
   */
  struct QueuedMessage *prev;

  /**
   * The actual queued message.
   */
  struct GNUNET_MessageHeader *msg;

  /**
   * Will be called after transmit, if not NULL
   */
  GNUNET_CONSENSUS_InsertDoneCallback idc;

  /**
   * Closure for idc
   */
  void *idc_cls;
};


/**
 * Handle for the service.
 */
struct GNUNET_CONSENSUS_Handle
{
  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Client connected to the consensus service, may be NULL if not connected.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Callback for new elements. Not called for elements added locally.
   */
  GNUNET_CONSENSUS_ElementCallback new_element_cb;

  /**
   * Closure for new_element_cb
   */
  void *new_element_cls;

  /**
   * The (local) session identifier for the consensus session.
   */
  struct GNUNET_HashCode session_id;

  /**
   * Number of peers in the consensus. Optionally includes the local peer.
   */
  int num_peers;

  /**
   * Peer identities of peers participating in the consensus, includes the local peer.
   */
  struct GNUNET_PeerIdentity **peers;

  /**
   * Currently active transmit request.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * GNUNES_YES iff the join message has been sent to the service.
   */
  int joined;

  /**
   * Closure for the insert done callback.
   */
  void *idc_cls;

  /**
   * Called when the conclude operation finishes or fails.
   */
  GNUNET_CONSENSUS_ConcludeCallback conclude_cb;

  /**
   * Closure for the conclude callback.
   */
  void *conclude_cls;

  /**
   * Deadline for the conclude operation.
   */
  struct GNUNET_TIME_Absolute conclude_deadline;

  unsigned int conclude_min_size;

  struct QueuedMessage *messages_head;
  struct QueuedMessage *messages_tail;
};



/**
 * Schedule transmitting the next message.
 *
 * @param consensus consensus handle
 */
static void
send_next (struct GNUNET_CONSENSUS_Handle *consensus);


/**
 * Function called to notify a client about the connection
 * begin ready to queue more data.  "buf" will be
 * NULL and "size" zero if the connection was closed for
 * writing in the meantime.
 *
 * @param cls closure
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_queued (void *cls, size_t size,
                 void *buf)
{
  struct GNUNET_CONSENSUS_Handle *consensus;
  struct QueuedMessage *qmsg;
  size_t msg_size;

  consensus = (struct GNUNET_CONSENSUS_Handle *) cls;
  consensus->th = NULL;

  qmsg = consensus->messages_head;
  GNUNET_CONTAINER_DLL_remove (consensus->messages_head, consensus->messages_tail, qmsg);

  if (NULL == buf)
  {
    if (NULL != qmsg->idc)
    {
      qmsg->idc (qmsg->idc_cls, GNUNET_YES);
    }
    return 0;
  }

  msg_size = ntohs (qmsg->msg->size);

  GNUNET_assert (size >= msg_size);

  memcpy (buf, qmsg->msg, msg_size);
  if (NULL != qmsg->idc)
  {
    qmsg->idc (qmsg->idc_cls, GNUNET_YES);
  }

  /* FIXME: free the messages */

  send_next (consensus);

  return msg_size;
}


/**
 * Schedule transmitting the next message.
 *
 * @param consensus consensus handle
 */
static void
send_next (struct GNUNET_CONSENSUS_Handle *consensus)
{
  if (NULL != consensus->th)
    return;

  if (NULL != consensus->messages_head)
  {
    consensus->th = 
        GNUNET_CLIENT_notify_transmit_ready (consensus->client, ntohs (consensus->messages_head->msg->size),
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             GNUNET_NO, &transmit_queued, consensus);
  }
}

static void
queue_message (struct GNUNET_CONSENSUS_Handle *consensus, struct GNUNET_MessageHeader *msg)
{
  struct QueuedMessage *qm;
  qm = GNUNET_malloc (sizeof *qm);
  qm->msg = msg;
  GNUNET_CONTAINER_DLL_insert_tail (consensus->messages_head, consensus->messages_tail, qm);
}


/**
 * Called when the server has sent is a new element
 * 
 * @param consensus consensus handle
 * @param msg element message
 */
static void
handle_new_element (struct GNUNET_CONSENSUS_Handle *consensus,
                   struct GNUNET_CONSENSUS_ElementMessage *msg)
{
  struct GNUNET_CONSENSUS_Element element;
  struct GNUNET_CONSENSUS_AckMessage *ack_msg;
  int ret;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "received new element\n");

  element.type = msg->element_type;
  element.size = ntohs (msg->header.size) - sizeof (struct GNUNET_CONSENSUS_ElementMessage);
  element.data = &msg[1];

  ret = consensus->new_element_cb (consensus->new_element_cls, &element);

  ack_msg = GNUNET_malloc (sizeof *ack_msg);
  ack_msg->header.size = htons (sizeof *ack_msg);
  ack_msg->header.type = htons (GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_ACK);
  ack_msg->keep = ret;

  queue_message (consensus, (struct GNUNET_MessageHeader *) ack_msg);

  send_next (consensus);
}


/**
 * Called when the server has announced
 * that the conclusion is over.
 * 
 * @param consensus consensus handle
 * @param msg conclude done message
 */
static void
handle_conclude_done (struct GNUNET_CONSENSUS_Handle *consensus,
                     struct GNUNET_CONSENSUS_ConcludeDoneMessage *msg)
{
  GNUNET_assert (NULL != consensus->conclude_cb);
  consensus->conclude_cb (consensus->conclude_cls, NULL);
  consensus->conclude_cb = NULL;
}



/**
 * Type of a function to call when we receive a message
 * from the service.
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
static void
message_handler (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_CONSENSUS_Handle *consensus = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "received message from consensus service\n");

  if (msg == NULL)
  {
    /* Error, timeout, death */
    LOG (GNUNET_ERROR_TYPE_ERROR, "error receiving\n");
    GNUNET_CLIENT_disconnect (consensus->client);
    consensus->client = NULL;
    consensus->new_element_cb (NULL, NULL);
    return;
  }

  switch (ntohs (msg->type))
  {
    case GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_RECEIVED_ELEMENT:
      handle_new_element (consensus, (struct GNUNET_CONSENSUS_ElementMessage *) msg);
      break;
    case GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_CONCLUDE_DONE:
      handle_conclude_done (consensus, (struct GNUNET_CONSENSUS_ConcludeDoneMessage *) msg);
      break;
    default:
      GNUNET_break (0);
  }
  GNUNET_CLIENT_receive (consensus->client, &message_handler, consensus,
                         GNUNET_TIME_UNIT_FOREVER_REL);
}

/**
 * Function called to notify a client about the connection
 * begin ready to queue more data.  "buf" will be
 * NULL and "size" zero if the connection was closed for
 * writing in the meantime.
 *
 * @param cls closure
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_join (void *cls, size_t size, void *buf)
{
  struct GNUNET_CONSENSUS_JoinMessage *msg;
  struct GNUNET_CONSENSUS_Handle *consensus;
  int msize;

  GNUNET_assert (NULL != buf);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "transmitting join message\n");

  consensus = cls;
  consensus->th = NULL;
  consensus->joined = 1;

  msg = buf;

  msize = sizeof (struct GNUNET_CONSENSUS_JoinMessage) +
      consensus->num_peers * sizeof (struct GNUNET_PeerIdentity);

  msg->header.type = htons (GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_JOIN);
  msg->header.size = htons (msize);
  msg->session_id = consensus->session_id;
  msg->num_peers = htons (consensus->num_peers);
  if (0 != msg->num_peers)
    memcpy(&msg[1],
           consensus->peers,
           consensus->num_peers * sizeof (struct GNUNET_PeerIdentity));

  send_next (consensus);

  GNUNET_CLIENT_receive (consensus->client, &message_handler, consensus,
                         GNUNET_TIME_UNIT_FOREVER_REL);
  
  return msize;
}

/**
 * Create a consensus session.
 *
 * @param cfg configuration to use for connecting to the consensus service
 * @param num_peers number of peers in the peers array
 * @param peers array of peers participating in this consensus session
 *              Inclusion of the local peer is optional.
 * @param session_id session identifier
 *                   Allows a group of peers to have more than consensus session.
 * @param new_element_cb callback, called when a new element is added to the set by
 *                    another peer
 * @param new_element_cls closure for new_element
 * @return handle to use, NULL on error
 */
struct GNUNET_CONSENSUS_Handle *
GNUNET_CONSENSUS_create (const struct GNUNET_CONFIGURATION_Handle *cfg,
			 unsigned int num_peers,
			 const struct GNUNET_PeerIdentity *peers,
                         const struct GNUNET_HashCode *session_id,
                         GNUNET_CONSENSUS_ElementCallback new_element_cb,
                         void *new_element_cls)
{
  struct GNUNET_CONSENSUS_Handle *consensus;
  size_t join_message_size;

  consensus = GNUNET_malloc (sizeof (struct GNUNET_CONSENSUS_Handle));
  consensus->cfg = cfg;
  consensus->new_element_cb = new_element_cb;
  consensus->new_element_cls = new_element_cls;
  consensus->num_peers = num_peers;
  consensus->session_id = *session_id;

  if (0 == num_peers)
    consensus->peers = NULL;
  else if (num_peers > 0)
    consensus->peers =
        GNUNET_memdup (peers, num_peers * sizeof (struct GNUNET_PeerIdentity));

  consensus->client = GNUNET_CLIENT_connect ("consensus", cfg);

  GNUNET_assert (consensus->client != NULL);

  join_message_size = (sizeof (struct GNUNET_CONSENSUS_JoinMessage)) +
      (num_peers * sizeof (struct GNUNET_PeerIdentity));

  consensus->th =
      GNUNET_CLIENT_notify_transmit_ready (consensus->client,
                                           join_message_size,
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           GNUNET_NO, &transmit_join, consensus);


  GNUNET_assert (consensus->th != NULL);
  return consensus;
}



/**
 * Insert an element in the set being reconsiled.  Must not be called after
 * "GNUNET_CONSENSUS_conclude".
 *
 * @param consensus handle for the consensus session
 * @param element the element to be inserted
 * @param idc function called when we are done with this element and it 
 *            is thus allowed to call GNUNET_CONSENSUS_insert again
 * @param idc_cls closure for 'idc'
 */
void
GNUNET_CONSENSUS_insert (struct GNUNET_CONSENSUS_Handle *consensus,
			 const struct GNUNET_CONSENSUS_Element *element,
			 GNUNET_CONSENSUS_InsertDoneCallback idc,
			 void *idc_cls)
{
  struct QueuedMessage *qmsg;
  struct GNUNET_CONSENSUS_ElementMessage *element_msg;
  size_t element_msg_size;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "inserting, size=%llu\n", element->size);

  element_msg_size = (sizeof (struct GNUNET_CONSENSUS_ElementMessage) +
                               element->size);

  element_msg = GNUNET_malloc (element_msg_size);
  element_msg->header.type = htons (GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_INSERT);
  element_msg->header.size = htons (element_msg_size);
  memcpy (&element_msg[1], element->data, element->size);

  qmsg = GNUNET_malloc (sizeof (struct QueuedMessage));
  qmsg->msg = (struct GNUNET_MessageHeader *) element_msg;
  qmsg->idc = idc;
  qmsg->idc_cls = idc_cls;

  GNUNET_CONTAINER_DLL_insert_tail (consensus->messages_head, consensus->messages_tail, qmsg);

  send_next (consensus);
}


/**
 * We are done with inserting new elements into the consensus;
 * try to conclude the consensus within a given time window.
 * After conclude has been called, no further elements may be
 * inserted by the client.
 *
 * @param consensus consensus session
 * @param timeout timeout after which the conculde callback
 *                must be called
 * @param conclude called when the conclusion was successful
 * @param conclude_cls closure for the conclude callback
 */
void
GNUNET_CONSENSUS_conclude (struct GNUNET_CONSENSUS_Handle *consensus,
			   struct GNUNET_TIME_Relative timeout,
			   unsigned int min_group_size_in_consensus,
			   GNUNET_CONSENSUS_ConcludeCallback conclude,
			   void *conclude_cls)
{
  struct QueuedMessage *qmsg;
  struct GNUNET_CONSENSUS_ConcludeMessage *conclude_msg;

  GNUNET_assert (NULL != conclude);
  GNUNET_assert (NULL == consensus->conclude_cb);

  consensus->conclude_cls = conclude_cls;
  consensus->conclude_cb = conclude;

  conclude_msg = GNUNET_malloc (sizeof (struct GNUNET_CONSENSUS_ConcludeMessage));
  conclude_msg->header.type = htons (GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_CONCLUDE);
  conclude_msg->header.size = htons (sizeof (struct GNUNET_CONSENSUS_ConcludeMessage));
  conclude_msg->timeout = GNUNET_TIME_relative_hton (timeout);
  conclude_msg->min_group_size = min_group_size_in_consensus;

  qmsg = GNUNET_malloc (sizeof (struct QueuedMessage));
  qmsg->msg = (struct GNUNET_MessageHeader *) conclude_msg;

  GNUNET_CONTAINER_DLL_insert_tail (consensus->messages_head, consensus->messages_tail, qmsg);

  send_next (consensus);
}


/**
 * Destroy a consensus handle (free all state associated with
 * it, no longer call any of the callbacks).
 *
 * @param consensus handle to destroy
 */
void
GNUNET_CONSENSUS_destroy (struct GNUNET_CONSENSUS_Handle *consensus)
{
  if (consensus->client != NULL)
  {
    GNUNET_CLIENT_disconnect (consensus->client);
    consensus->client = NULL;
  }
  if (NULL != consensus->peers)
    GNUNET_free (consensus->peers);
  GNUNET_free (consensus);
}

