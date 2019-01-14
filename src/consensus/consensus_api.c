/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2016 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
    
     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
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
 * Handle for the service.
 */
struct GNUNET_CONSENSUS_Handle
{
  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Callback for new elements. Not called for elements added locally.
   */
  GNUNET_CONSENSUS_ElementCallback new_element_cb;

  /**
   * Closure for @e new_element_cb
   */
  void *new_element_cls;

  /**
   * The (local) session identifier for the consensus session.
   */
  struct GNUNET_HashCode session_id;

  /**
   * #GNUNET_YES iff the join message has been sent to the service.
   */
  int joined;

  /**
   * Called when the conclude operation finishes or fails.
   */
  GNUNET_CONSENSUS_ConcludeCallback conclude_cb;

  /**
   * Closure for the @e conclude_cb callback.
   */
  void *conclude_cls;

  /**
   * Deadline for the conclude operation.
   */
  struct GNUNET_TIME_Absolute conclude_deadline;

  /**
   * Message queue for the client.
   */
  struct GNUNET_MQ_Handle *mq;
};


/**
 * FIXME: this should not bee necessary when the API
 * issue has been fixed
 */
struct InsertDoneInfo
{
  GNUNET_CONSENSUS_InsertDoneCallback idc;
  void *cls;
};


/**
 * Called when the server has sent is a new element
 *
 * @param cls consensus handle
 * @param msg element message
 */
static int
check_new_element (void *cls,
                   const struct GNUNET_CONSENSUS_ElementMessage *msg)
{
  /* any size is fine, elements are variable-size */
  return GNUNET_OK;
}


/**
 * Called when the server has sent is a new element
 *
 * @param cls consensus handle
 * @param msg element message
 */
static void
handle_new_element (void *cls,
                    const struct GNUNET_CONSENSUS_ElementMessage *msg)
{
  struct GNUNET_CONSENSUS_Handle *consensus = cls;
  struct GNUNET_SET_Element element;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "received new element\n");
  element.element_type = msg->element_type;
  element.size = ntohs (msg->header.size) - sizeof (struct GNUNET_CONSENSUS_ElementMessage);
  element.data = &msg[1];
  consensus->new_element_cb (consensus->new_element_cls,
                             &element);
}


/**
 * Called when the server has announced
 * that the conclusion is over.
 *
 * @param cls consensus handle
 * @param msg conclude done message
 */
static void
handle_conclude_done (void *cls,
		      const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_CONSENSUS_Handle *consensus = cls;
  GNUNET_CONSENSUS_ConcludeCallback cc;

  GNUNET_MQ_destroy (consensus->mq);
  consensus->mq = NULL;
  GNUNET_assert (NULL != (cc = consensus->conclude_cb));
  consensus->conclude_cb = NULL;
  cc (consensus->conclude_cls);
}


/**
 * Generic error handler, called with the appropriate
 * error code and the same closure specified at the creation of
 * the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure, same closure as for the message handlers
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  LOG (GNUNET_ERROR_TYPE_WARNING,
       "consensus service disconnected us\n");
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
 * @param start start time of the consensus, conclude should be called before
 *              the start time.
 * @param deadline time when the consensus should have concluded
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
                         struct GNUNET_TIME_Absolute start,
                         struct GNUNET_TIME_Absolute deadline,
                         GNUNET_CONSENSUS_ElementCallback new_element_cb,
                         void *new_element_cls)
{
  struct GNUNET_CONSENSUS_Handle *consensus
    = GNUNET_new (struct GNUNET_CONSENSUS_Handle);
  struct GNUNET_MQ_MessageHandler mq_handlers[] = {
    GNUNET_MQ_hd_var_size (new_element,
                           GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_RECEIVED_ELEMENT,
                           struct GNUNET_CONSENSUS_ElementMessage,
                           consensus),
    GNUNET_MQ_hd_fixed_size (conclude_done,
                             GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_CONCLUDE_DONE,
                             struct GNUNET_MessageHeader,
                             consensus),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_CONSENSUS_JoinMessage *join_msg;
  struct GNUNET_MQ_Envelope *ev;

  consensus->cfg = cfg;
  consensus->new_element_cb = new_element_cb;
  consensus->new_element_cls = new_element_cls;
  consensus->session_id = *session_id;
  consensus->mq = GNUNET_CLIENT_connect (cfg,
                                         "consensus",
                                         mq_handlers,
                                         &mq_error_handler,
                                         consensus);
  if (NULL == consensus->mq)
  {
    GNUNET_free (consensus);
    return NULL;
  }
  ev = GNUNET_MQ_msg_extra (join_msg,
                            (num_peers * sizeof (struct GNUNET_PeerIdentity)),
                            GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_JOIN);

  join_msg->session_id = consensus->session_id;
  join_msg->start = GNUNET_TIME_absolute_hton (start);
  join_msg->deadline = GNUNET_TIME_absolute_hton (deadline);
  join_msg->num_peers = htonl (num_peers);
  GNUNET_memcpy(&join_msg[1],
	 peers,
	 num_peers * sizeof (struct GNUNET_PeerIdentity));

  GNUNET_MQ_send (consensus->mq, ev);
  return consensus;
}


static void
idc_adapter (void *cls)
{
  struct InsertDoneInfo *i = cls;
  i->idc (i->cls, GNUNET_OK);
  GNUNET_free (i);
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
			 const struct GNUNET_SET_Element *element,
			 GNUNET_CONSENSUS_InsertDoneCallback idc,
			 void *idc_cls)
{
  struct GNUNET_CONSENSUS_ElementMessage *element_msg;
  struct GNUNET_MQ_Envelope *ev;
  struct InsertDoneInfo *i;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "inserting, size=%llu\n", element->size);

  ev = GNUNET_MQ_msg_extra (element_msg, element->size,
                            GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_INSERT);

  GNUNET_memcpy (&element_msg[1], element->data, element->size);

  if (NULL != idc)
  {
    i = GNUNET_new (struct InsertDoneInfo);
    i->idc = idc;
    i->cls = idc_cls;
    GNUNET_MQ_notify_sent (ev, idc_adapter, i);
  }
  GNUNET_MQ_send (consensus->mq, ev);
}


/**
 * We are done with inserting new elements into the consensus;
 * try to conclude the consensus within a given time window.
 * After conclude has been called, no further elements may be
 * inserted by the client.
 *
 * @param consensus consensus session
 * @param deadline deadline after which the conculde callback
 *                must be called
 * @param conclude called when the conclusion was successful
 * @param conclude_cls closure for the conclude callback
 */
void
GNUNET_CONSENSUS_conclude (struct GNUNET_CONSENSUS_Handle *consensus,
			   GNUNET_CONSENSUS_ConcludeCallback conclude,
			   void *conclude_cls)
{
  struct GNUNET_MQ_Envelope *ev;

  GNUNET_assert (NULL != conclude);
  GNUNET_assert (NULL == consensus->conclude_cb);

  consensus->conclude_cls = conclude_cls;
  consensus->conclude_cb = conclude;

  ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_CONCLUDE);
  GNUNET_MQ_send (consensus->mq, ev);
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
  if (NULL != consensus->mq)
  {
    GNUNET_MQ_destroy (consensus->mq);
    consensus->mq = NULL;
  }
  GNUNET_free (consensus);
}

/* end of consensus_api.c */
