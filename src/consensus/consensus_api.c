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
#include "gnunet_protocols.h"
#include "gnunet_client_lib.h"
#include "gnunet_consensus_service.h"
#include "consensus.h"


#define LOG(kind,...) GNUNET_log_from (kind, "consensus-api",__VA_ARGS__)


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
   * Socket (if available).
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Callback for new elements. Not called for elements added locally.
   */
  GNUNET_CONSENSUS_NewElementCallback new_element_cb;

  /**
   * Closure for new_element_cb
   */
  void *new_element_cls;

  /**
   * Session identifier for the consensus session.
   */
  struct GNUNET_HashCode session_id;

  /**
   * Number of peers in the consensus. Optionally includes the local peer.
   */
  int num_peers;

  /**
   * Peer identities of peers in the consensus. Optionally includes the local peer.
   */
  struct GNUNET_PeerIdentity *peers;

  /**
   * Currently active transmit request.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * GNUNES_YES iff the join message has been sent to the service.
   */
  int joined;

  /**
   * Called when the current insertion operation finishes.
   * NULL if there is no insert operation active.
   */
  GNUNET_CONSENSUS_InsertDoneCallback idc;

  /**
   * Closure for the insert done callback.
   */
  void *idc_cls;

  /**
   * An element that was requested to be inserted.
   */
  struct GNUNET_CONSENSUS_Element *insert_element;

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
};


static void
handle_new_element(struct GNUNET_CONSENSUS_Handle *consensus,
                   struct GNUNET_CONSENSUS_ElementMessage *msg)
{
  struct GNUNET_CONSENSUS_Element element;
  element.type = msg->element_type;
  element.size = msg->header.size - sizeof (struct GNUNET_CONSENSUS_ElementMessage);
  element.data = &msg[1];
  consensus->new_element_cb (consensus->new_element_cls, &element);
}

static void
handle_conclude_done(struct GNUNET_CONSENSUS_Handle *consensus,
                     struct GNUNET_CONSENSUS_ConcludeDoneMessage *msg)
{
  GNUNET_assert (NULL != consensus->conclude_cb);
  consensus->conclude_cb(consensus->conclude_cls,
                         msg->num_peers,
                         (struct GNUNET_PeerIdentity *) &msg[1]);
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

  LOG (GNUNET_ERROR_TYPE_INFO, "received message from consensus service\n");

  if (msg == NULL)
  {
    /* Error, timeout, death */
    LOG (GNUNET_ERROR_TYPE_ERROR, "error receiving\n");
    GNUNET_CLIENT_disconnect (consensus->client);
    consensus->client = NULL;
    consensus->new_element_cb (NULL, NULL);
    if (NULL != consensus->idc)
    {
      consensus->idc(consensus->idc_cls, GNUNET_NO);
      consensus->idc = NULL;
      consensus->idc_cls = NULL;
    }
    return;
  }

  switch (ntohs(msg->type))
  {
    case GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_RECEIVED_ELEMENT:
      handle_new_element (consensus, (struct GNUNET_CONSENSUS_ElementMessage *) msg);
      break;
    case GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_CONCLUDE_DONE:
      handle_conclude_done (consensus, (struct GNUNET_CONSENSUS_ConcludeDoneMessage *) msg);
      break;
    default:
      LOG(GNUNET_ERROR_TYPE_WARNING, "did not understand message type sent by service, ignoring");
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
transmit_insert (void *cls, size_t size, void *buf)
{
  struct GNUNET_CONSENSUS_ElementMessage *msg;
  struct GNUNET_CONSENSUS_Handle *consensus;
  GNUNET_CONSENSUS_InsertDoneCallback idc;
  int msize;
  void *idc_cls;

  GNUNET_assert (NULL != buf);

  consensus = cls;

  GNUNET_assert (NULL != consensus->insert_element);

  consensus->th = NULL;

  msg = buf;

  msize = sizeof (struct GNUNET_CONSENSUS_ElementMessage) +
      consensus->insert_element->size;

  msg->header.type = htons (GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_INSERT);
  msg->header.size = htons (msize);
  memcpy (&msg[1],
          consensus->insert_element->data,
          consensus->insert_element->size);


  idc = consensus->idc;
  consensus->idc = NULL;
  idc_cls = consensus->idc_cls;
  consensus->idc_cls = NULL;
  idc (idc_cls, GNUNET_YES);

  return msize;
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
  memcpy(&msg[1],
         consensus->peers,
         consensus->num_peers * sizeof (struct GNUNET_PeerIdentity));

  if (consensus->insert_element != NULL)
  {
    consensus->th =
        GNUNET_CLIENT_notify_transmit_ready (consensus->client,
                                             msize,
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             GNUNET_NO, &transmit_insert, consensus);
  }

  GNUNET_CLIENT_receive (consensus->client, &message_handler, consensus,
                         GNUNET_TIME_UNIT_FOREVER_REL);
  
  return msize;
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
transmit_conclude (void *cls, size_t size, void *buf)
{
  struct GNUNET_CONSENSUS_ConcludeMessage *msg;
  struct GNUNET_CONSENSUS_Handle *consensus;
  int msize;

  GNUNET_assert (NULL != buf);

  consensus = cls;
  consensus->th = NULL;

  msg = buf;

  msize = sizeof (struct GNUNET_CONSENSUS_ConcludeMessage);

  msg->header.type = htons (GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_CONCLUDE);
  msg->header.size = htons (msize);
  msg->timeout =
      GNUNET_TIME_relative_hton (GNUNET_TIME_absolute_get_remaining(consensus->conclude_deadline));

  return msize;
}


/**
 * Function called to notify a client about the connection
 * begin ready to queue more data.  "buf" will be
 * NULL and "size" zero if the connection was closed for
 * writing in the meantime.
 *
 * @param cls the consensus handle
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_begin (void *cls, size_t size, void *buf)
{
  struct GNUNET_MessageHeader *msg;
  struct GNUNET_CONSENSUS_Handle *consensus;
  int msize;

  GNUNET_assert (NULL != buf);

  consensus = cls;
  consensus->th = NULL;

  msg = buf;

  msize = sizeof (struct GNUNET_MessageHeader);

  msg->type = htons (GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_BEGIN);
  msg->size = htons (msize);

  return msize;
}


/**
 * Create a consensus session.
 *
 * @param cfg
 * @param num_peers
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
                         GNUNET_CONSENSUS_NewElementCallback new_element_cb,
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
  {
    consensus->peers = NULL;
  }
  else if (num_peers > 0)
  {
    consensus->peers = GNUNET_memdup (peers, num_peers * sizeof (struct GNUNET_PeerIdentity));
  }
  else
  {
    GNUNET_break (0);
  }

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

  GNUNET_assert (NULL == consensus->idc);
  GNUNET_assert (NULL == consensus->insert_element);

  consensus->idc = idc;
  consensus->idc_cls = idc_cls;
  consensus->insert_element = GNUNET_memdup(element, sizeof (struct GNUNET_CONSENSUS_Element) + element->size);

  if (consensus->joined == 0)
  {
    GNUNET_assert (NULL != consensus->th);
    return;
  }

  GNUNET_assert (NULL == consensus->th);

  consensus->th =
      GNUNET_CLIENT_notify_transmit_ready (consensus->client,
                                           element->size + sizeof (struct GNUNET_CONSENSUS_ElementMessage),
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           GNUNET_NO, &transmit_insert, consensus);
}


/**
 * Begin reconciling elements with other peers.
 *
 * @param consensus handle for the consensus session
 */
void
GNUNET_CONSENSUS_begin (struct GNUNET_CONSENSUS_Handle *consensus)
{
  GNUNET_assert (NULL == consensus->idc);
  GNUNET_assert (NULL == consensus->insert_element);

  consensus->th =
      GNUNET_CLIENT_notify_transmit_ready (consensus->client,
                                           sizeof (struct GNUNET_MessageHeader),
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           GNUNET_NO, &transmit_begin, consensus);
}


/**
 * We are finished inserting new elements into the consensus;
 * try to conclude the consensus within a given time window.
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
			   GNUNET_CONSENSUS_ConcludeCallback conclude,
			   void *conclude_cls)
{
  GNUNET_assert (NULL == consensus->th);
  GNUNET_assert (NULL == consensus->conclude_cb);

  consensus->conclude_cls = conclude_cls;
  consensus->conclude_cb = conclude;
  consensus->conclude_deadline = GNUNET_TIME_relative_to_absolute(timeout);

  consensus->th =
      GNUNET_CLIENT_notify_transmit_ready (consensus->client,
                                           sizeof (struct GNUNET_CONSENSUS_ConcludeMessage),
                                           timeout,
                                           GNUNET_NO, &transmit_conclude, consensus);
  if (NULL == consensus->th)
  {
    conclude(conclude_cls, 0, NULL);
  }
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
  GNUNET_free (consensus->peers);
  GNUNET_free (consensus);
}

