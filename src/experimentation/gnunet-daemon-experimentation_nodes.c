/*
     This file is part of GNUnet.
     (C) 2012-2013 Christian Grothoff (and other contributing authors)

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
 * @file experimentation/gnunet-daemon-experimentation_nodes.c
 * @brief experimentation daemon: node management
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet-daemon-experimentation.h"


#define FAST_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * Core handle
 */
static struct GNUNET_CORE_Handle *ch;

/**
 * Peer's own identity
 */
static struct GNUNET_PeerIdentity me;

/**
 * Nodes with a pending request
 */
static struct GNUNET_CONTAINER_MultiPeerMap *nodes_requested;

/**
 * Active experimentation nodes
 */
static struct GNUNET_CONTAINER_MultiPeerMap *nodes_active;

/**
 * Inactive experimentation nodes
 * To be excluded from future requests
 */
static struct GNUNET_CONTAINER_MultiPeerMap *nodes_inactive;


struct NodeComCtx
{
  struct NodeComCtx *prev;
  struct NodeComCtx *next;

  struct Node *n;
  struct Experiment *e;

  size_t size;
  GNUNET_CONNECTION_TransmitReadyNotify notify;
  void *notify_cls;
};


/**
 * Update statistics
 *
 * @param m peermap to update values from
 */
static void
update_stats (struct GNUNET_CONTAINER_MultiPeerMap *m)
{
  GNUNET_assert (NULL != m);
  GNUNET_assert (NULL != GED_stats);

  if (m == nodes_active)
  {
    GNUNET_STATISTICS_set (GED_stats, "# nodes active",
			   GNUNET_CONTAINER_multipeermap_size(m), GNUNET_NO);
  }
  else if (m == nodes_inactive)
  {
    GNUNET_STATISTICS_set (GED_stats, "# nodes inactive",
			   GNUNET_CONTAINER_multipeermap_size(m), GNUNET_NO);
  }
  else if (m == nodes_requested)
  {
    GNUNET_STATISTICS_set (GED_stats, "# nodes requested",
			   GNUNET_CONTAINER_multipeermap_size(m), GNUNET_NO);
  }
  else
    GNUNET_break (0);
}


/**
 * Clean up node
 *
 * @param cls the peermap to clean up
 * @param key key of the current node
 * @param value related node object
 * @return always #GNUNET_OK
 */
static int
cleanup_node (void *cls,
	      const struct GNUNET_PeerIdentity * key,
	      void *value)
{
  struct Node *n;
  struct NodeComCtx *e_cur;
  struct NodeComCtx *e_next;
  struct GNUNET_CONTAINER_MultiPeerMap *cur = cls;

  n = value;
  if (GNUNET_SCHEDULER_NO_TASK != n->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (n->timeout_task);
    n->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (NULL != n->cth)
  {
    GNUNET_CORE_notify_transmit_ready_cancel (n->cth);
    n->cth = NULL;
  }
  e_next = n->e_req_head;
  while (NULL != (e_cur = e_next))
  {
    e_next = e_cur->next;
    GNUNET_CONTAINER_DLL_remove (n->e_req_head, n->e_req_tail, e_cur);
    GNUNET_free (e_cur);
  }
  GNUNET_break (0 == GNUNET_CONTAINER_multipeermap_remove (cur, key, value));
  GNUNET_free (value);
  return GNUNET_OK;
}


/**
 * Check if id passed is my id
 *
 * @param id the id to check
 * @return GNUNET_YES or GNUNET_NO
 */
static int
is_me (const struct GNUNET_PeerIdentity *id)
{
  if (0 == memcmp (&me, id, sizeof (me)))
    return GNUNET_YES;
  else
    return GNUNET_NO;
}


/**
 * Core startup callback
 *
 * @param cls unused
 * @param my_identity my id
 */
static void
core_startup_handler (void *cls,
                      const struct GNUNET_PeerIdentity *my_identity)
{
  me = *my_identity;
}


static void
schedule_transmisson (struct NodeComCtx *e_ctx);


static size_t
transmit_read_wrapper (void *cls, size_t bufsize, void *buf)
{
  struct NodeComCtx *e_ctx = cls;
  struct NodeComCtx *next;

  size_t res = e_ctx->notify (e_ctx->notify_cls, bufsize, buf);
  e_ctx->n->cth = NULL;

  GNUNET_CONTAINER_DLL_remove (e_ctx->n->e_req_head, e_ctx->n->e_req_tail, e_ctx);
  next = e_ctx->n->e_req_head;
  GNUNET_free (e_ctx);

  if (NULL != next)
  {
    /* Schedule next message */
    schedule_transmisson (next);
  }
  return res;
}


static void
schedule_transmisson (struct NodeComCtx *e_ctx)
{
  if (NULL != e_ctx->n->cth)
    return;

  e_ctx->n->cth = GNUNET_CORE_notify_transmit_ready (ch, GNUNET_NO, 0, FAST_TIMEOUT,
						     &e_ctx->n->id, e_ctx->size,
						     transmit_read_wrapper, e_ctx);
  if (NULL == e_ctx->n->cth)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Cannot send message to peer `%s' for experiment `%s'\n"),
		GNUNET_i2s(&e_ctx->n->id), e_ctx->e->name);
    GNUNET_free (e_ctx);
  }
}


/**
 * Remove experimentation request due to timeout
 *
 * @param cls the related node
 * @param tc scheduler's task context
 */
static void
remove_request (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Node *n = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Removing request for peer %s due to timeout\n",
	      GNUNET_i2s (&n->id));
  if (GNUNET_YES == GNUNET_CONTAINER_multipeermap_contains (nodes_requested, &n->id))
  {
    GNUNET_break (0 == GNUNET_CONTAINER_multipeermap_remove (nodes_requested, &n->id, n));
    update_stats (nodes_requested);
    GNUNET_CONTAINER_multipeermap_put (nodes_inactive, &n->id, n,
				       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
    update_stats (nodes_inactive);
  }
  n->timeout_task = GNUNET_SCHEDULER_NO_TASK;
}


static int
append_public_key (void *cls,
		   const struct GNUNET_HashCode *key,
		   void *value)
{
  struct GNUNET_CRYPTO_EccPublicSignKey **issuers = cls;
  struct Issuer *issuer = value;

  *issuers[0] = issuer->pubkey;
  *issuers = &((*issuers)[1]);
  return GNUNET_OK;
}


/**
 * Core's transmit notify callback to send request
 *
 * @param cls the related node
 * @param bufsize buffer size
 * @param buf the buffer to copy to
 * @return bytes passed
 */
static size_t
send_experimentation_request_cb (void *cls, size_t bufsize, void *buf)
{
  struct Node *n = cls;
  struct Experimentation_Request msg;
  unsigned int my_issuer_count = GNUNET_CONTAINER_multihashmap_size (valid_issuers);
  size_t msg_size = sizeof (msg);
  size_t ri_size = sizeof (struct GNUNET_CRYPTO_EccPublicSignKey) * my_issuer_count;
  size_t total_size = msg_size + ri_size;
  struct GNUNET_CRYPTO_EccPublicSignKey *issuers;
	
  n->cth = NULL;
  if (NULL == buf)
  {
    /* client disconnected */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Client disconnected\n");
    if (GNUNET_SCHEDULER_NO_TASK != n->timeout_task)
    		GNUNET_SCHEDULER_cancel (n->timeout_task);
    GNUNET_SCHEDULER_add_now (&remove_request, n);
    return 0;
  }
  GNUNET_assert (bufsize >= total_size);
  msg.msg.size = htons (total_size);
  msg.msg.type = htons (GNUNET_MESSAGE_TYPE_EXPERIMENTATION_REQUEST);
  msg.capabilities = htonl (GSE_node_capabilities);
  msg.issuer_count = htonl (my_issuer_count);
  memcpy (buf, &msg, msg_size);
  issuers = (struct GNUNET_CRYPTO_EccPublicSignKey *) buf + msg_size;
  GNUNET_CONTAINER_multihashmap_iterate (valid_issuers,
					 &append_public_key,
					 &issuers);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _("Sending experimentation request to peer %s\n"),
	      GNUNET_i2s (&n->id));
  return total_size;
}


/**
 * Send request to peer to start add him to to the set of experimentation nodes
 *
 * @param peer the peer to send to
 */
static void
send_experimentation_request (const struct GNUNET_PeerIdentity *peer)
{
  struct Node *n;
  struct NodeComCtx *e_ctx;
  size_t size;
  size_t c_issuers;

  c_issuers = GNUNET_CONTAINER_multihashmap_size (valid_issuers);
  size = sizeof (struct Experimentation_Request) +
    c_issuers * sizeof (struct GNUNET_CRYPTO_EccPublicSignKey);
  n = GNUNET_new (struct Node);
  n->id = *peer;
  n->timeout_task = GNUNET_SCHEDULER_add_delayed (EXP_RESPONSE_TIMEOUT, &remove_request, n);
  n->capabilities = NONE;

  e_ctx = GNUNET_new (struct NodeComCtx);
  e_ctx->n = n;
  e_ctx->e = NULL;
  e_ctx->size = size;
  e_ctx->notify = &send_experimentation_request_cb;
  e_ctx->notify_cls = n;
  GNUNET_CONTAINER_DLL_insert_tail(n->e_req_head, n->e_req_tail, e_ctx);
  schedule_transmisson (e_ctx);

  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CONTAINER_multipeermap_put (nodes_requested,
						    peer, n,
						    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST));
  update_stats (nodes_requested);
}


/**
 * Core's transmit notify callback to send response
 *
 * @param cls the related node
 * @param bufsize buffer size
 * @param buf the buffer to copy to
 * @return bytes passed
 */
static size_t
send_response_cb (void *cls, size_t bufsize, void *buf)
{
  struct Node *n = cls;
  struct Experimentation_Response msg;
  size_t c_issuers = GNUNET_CONTAINER_multihashmap_size (valid_issuers);
  size_t ri_size = c_issuers * sizeof (struct GNUNET_CRYPTO_EccPublicSignKey);
  size_t msg_size = sizeof (msg);
  size_t total_size = msg_size + ri_size;
  struct GNUNET_CRYPTO_EccPublicSignKey *issuers;

  n->cth = NULL;
  if (buf == NULL)
  {
    /* client disconnected */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Client disconnected\n");
    return 0;
  }
  GNUNET_assert (bufsize >= total_size);

  msg.msg.size = htons (total_size);
  msg.msg.type = htons (GNUNET_MESSAGE_TYPE_EXPERIMENTATION_RESPONSE);
  msg.capabilities = htonl (GSE_node_capabilities);
  msg.issuer_count = htonl (c_issuers);
  memcpy (buf, &msg, msg_size);
  issuers = (struct GNUNET_CRYPTO_EccPublicSignKey *) buf + msg_size;
  GNUNET_CONTAINER_multihashmap_iterate (valid_issuers,
					 &append_public_key,
					 &issuers);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Sending response to peer %s\n",
	      GNUNET_i2s (&n->id));
  return total_size;
}


static void
get_experiments_cb (struct Node *n, struct Experiment *e)
{
  static int counter = 0;
  if (NULL == e)
    return; /* Done */

  /* Tell the scheduler to add a node with an experiment */
  GED_scheduler_add (n, e, GNUNET_YES);
  counter ++;
}


struct Node *
get_node (const struct GNUNET_PeerIdentity *id)
{
  struct Node * res;
  struct Node * tmp;

  res = NULL;
  tmp = NULL;
  tmp = GNUNET_CONTAINER_multipeermap_get (nodes_active, id);
  if (res == NULL)
    res = tmp;

  tmp = GNUNET_CONTAINER_multipeermap_get (nodes_inactive, id);
  if (res == NULL)
    res = tmp;
  else
    GNUNET_break (0); /* Multiple instances */

  tmp = GNUNET_CONTAINER_multipeermap_get (nodes_requested, id);
  if (res == NULL)
    res = tmp;
  else
    GNUNET_break (0); /* Multiple instances */

  return res;
}


/**
 * Set a specific node as active
 *
 * @param n the node
 */
static void
node_make_active (struct Node *n)
{
  int c1;

  GNUNET_CONTAINER_multipeermap_put (nodes_active,
				     &n->id, n, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  update_stats (nodes_active);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _("Added peer `%s' as active node\n"),
	      GNUNET_i2s (&n->id));
  /* Request experiments for this node to start them */
  for (c1 = 0; c1 < n->issuer_count; c1++)
  {
    GED_experiments_get (n, &n->issuer_id[c1], &get_experiments_cb);
  }
}


/**
 * Handle a request and send a response
 *
 * @param peer the source
 * @param message the message
 */
static void
handle_request (const struct GNUNET_PeerIdentity *peer,
		const struct GNUNET_MessageHeader *message)
{
  struct Node *n;
  struct NodeComCtx *e_ctx;
  const struct Experimentation_Request *rm = (const struct Experimentation_Request *) message;
  const struct GNUNET_CRYPTO_EccPublicSignKey *rmi = (const struct GNUNET_CRYPTO_EccPublicSignKey *) &rm[1];
  unsigned int my_issuer_count = GNUNET_CONTAINER_multihashmap_size (valid_issuers);
  int c1;
  int c2;
  uint32_t ic;
  uint32_t ic_accepted;
  int make_active;

  if (ntohs (message->size) < sizeof (struct Experimentation_Request))
  {
    GNUNET_break (0);
    return;
  }
  ic = ntohl (rm->issuer_count);
  if (ntohs (message->size) !=
      sizeof (struct Experimentation_Request) + ic * sizeof (struct GNUNET_CRYPTO_EccPublicSignKey))
  {
    GNUNET_break (0);
    return;
  }

  make_active = GNUNET_NO;
  if (NULL != (n = GNUNET_CONTAINER_multipeermap_get (nodes_active, peer)))
  {
    /* Nothing to do */
  }
  else if (NULL != (n = GNUNET_CONTAINER_multipeermap_get (nodes_requested, peer)))
  {
    GNUNET_assert (GNUNET_OK == GNUNET_CONTAINER_multipeermap_remove (nodes_requested, peer, n));
    if (GNUNET_SCHEDULER_NO_TASK != n->timeout_task)
      {
	GNUNET_SCHEDULER_cancel (n->timeout_task);
	n->timeout_task = GNUNET_SCHEDULER_NO_TASK;
      }
    update_stats (nodes_requested);
    make_active = GNUNET_YES;
  }
  else if (NULL != (n = GNUNET_CONTAINER_multipeermap_get (nodes_inactive, peer)))
  {
    GNUNET_break (0 == GNUNET_CONTAINER_multipeermap_remove (nodes_inactive, peer, n));
    update_stats (nodes_inactive);
    make_active = GNUNET_YES;
  }
  else
  {
    /* Create new node */
    n = GNUNET_new (struct Node);
    n->id = *peer;
    n->capabilities = NONE;
    make_active = GNUNET_YES;
  }

  /* Update node */
  n->capabilities = ntohl (rm->capabilities);

  /* Filter accepted issuer */
  ic_accepted = 0;
  for (c1 = 0; c1 < ic; c1++)
  {
    if (GNUNET_YES == GED_experiments_issuer_accepted(&rmi[c1]))
      ic_accepted ++;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Request from peer `%s' with %u issuers, we accepted %u issuer \n",
	      GNUNET_i2s (peer), ic, ic_accepted);
  GNUNET_free_non_null (n->issuer_id);
  n->issuer_id = GNUNET_malloc (ic_accepted * sizeof (struct GNUNET_CRYPTO_EccPublicSignKey));
  c2 = 0;
  for (c1 = 0; c1 < ic; c1++)
  {
    if (GNUNET_YES == GED_experiments_issuer_accepted (&rmi[c1]))
    {
      n->issuer_id[c2] = rmi[c1];
      c2 ++;
    }
  }
  n->issuer_count = ic_accepted;

  if (GNUNET_YES == make_active)
    node_make_active (n);

  /* Send response */
  e_ctx = GNUNET_new (struct NodeComCtx);
  e_ctx->n = n;
  e_ctx->e = NULL;
  e_ctx->size = sizeof (struct Experimentation_Response) +
    my_issuer_count * sizeof (struct GNUNET_CRYPTO_EccPublicSignKey);
  e_ctx->notify = &send_response_cb;
  e_ctx->notify_cls = n;

  GNUNET_CONTAINER_DLL_insert_tail(n->e_req_head, n->e_req_tail, e_ctx);
  schedule_transmisson (e_ctx);
}


/**
 * Handle a response
 *
 * @param peer the source
 * @param message the message
 */
static void handle_response (const struct GNUNET_PeerIdentity *peer,
			     const struct GNUNET_MessageHeader *message)
{
  struct Node *n;
  const struct Experimentation_Response *rm = (const struct Experimentation_Response *) message;
  const struct GNUNET_CRYPTO_EccPublicSignKey *rmi = (const struct GNUNET_CRYPTO_EccPublicSignKey *) &rm[1];
  uint32_t ic;
  uint32_t ic_accepted;
  int make_active;
  unsigned int c1;
  unsigned int c2;

  if (ntohs (message->size) < sizeof (struct Experimentation_Response))
    {
      GNUNET_break (0);
      return;
    }
  ic = ntohl (rm->issuer_count);
  if (ntohs (message->size) != sizeof (struct Experimentation_Response) + ic * sizeof (struct GNUNET_CRYPTO_EccPublicSignKey))
  {
    GNUNET_break (0);
    return;
  }

  make_active = GNUNET_NO;
  if (NULL != (n = GNUNET_CONTAINER_multipeermap_get (nodes_active, peer)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Received %s from %s peer `%s'\n",
		"RESPONSE", "active", GNUNET_i2s (peer));
  }
  else if (NULL != (n = GNUNET_CONTAINER_multipeermap_get (nodes_requested, peer)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received %s from %s peer `%s'\n",
		"RESPONSE", "requested", GNUNET_i2s (peer));
    GNUNET_assert (GNUNET_OK ==  GNUNET_CONTAINER_multipeermap_remove (nodes_requested, peer, n));
    if (GNUNET_SCHEDULER_NO_TASK != n->timeout_task)
    {
      GNUNET_SCHEDULER_cancel (n->timeout_task);
      n->timeout_task = GNUNET_SCHEDULER_NO_TASK;
    }
    update_stats (nodes_requested);
    make_active = GNUNET_YES;
  }
  else if (NULL != (n = GNUNET_CONTAINER_multipeermap_get (nodes_inactive, peer)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Received %s from peer `%s'\n",
		"RESPONSE", "inactive", GNUNET_i2s (peer));
    GNUNET_break (0 == GNUNET_CONTAINER_multipeermap_remove (nodes_inactive, peer, n));
    update_stats (nodes_inactive);
    make_active = GNUNET_YES;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received %s from %s peer `%s'\n",
		"RESPONSE", "unknown", GNUNET_i2s (peer));
    return;
  }

  /* Update */
  n->capabilities = ntohl (rm->capabilities);

  /* Filter accepted issuer */
  ic_accepted = 0;
  for (c1 = 0; c1 < ic; c1++)
  {
    if (GNUNET_YES == GED_experiments_issuer_accepted(&rmi[c1]))
      ic_accepted ++;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Response from peer `%s' with %u issuers, we accepted %u issuer \n",
	      GNUNET_i2s (peer), ic, ic_accepted);
  GNUNET_free_non_null (n->issuer_id);
  n->issuer_id = GNUNET_malloc (ic_accepted * sizeof (struct GNUNET_PeerIdentity));
  c2 = 0;
  for (c1 = 0; c1 < ic; c1++)
  {
    if (GNUNET_YES == GED_experiments_issuer_accepted(&rmi[c1]))
    {
      n->issuer_id[c2] = rmi[c1];
      c2 ++;
    }
  }
  n->issuer_count = ic_accepted;

  if (GNUNET_YES == make_active)
    node_make_active (n);
}


/**
 * Handle a response
 *
 * @param peer the source
 * @param message the message
 */
static void
handle_start (const struct GNUNET_PeerIdentity *peer,
	      const struct GNUNET_MessageHeader *message)
{
  uint16_t size;
  uint32_t name_len;
  const struct GED_start_message *msg;
  const char *name;
  struct Node *n;
  struct Experiment *e;

  if (NULL == peer)
  {
    GNUNET_break (0);
    return;
  }
  if (NULL == message)
  {
    GNUNET_break (0);
    return;
  }

  size = ntohs (message->size);
  if (size < sizeof (struct GED_start_message))
  {
    GNUNET_break (0);
    return;
  }
  msg = (const struct GED_start_message *) message;
  name_len = ntohl (msg->len_name);
  if (size != sizeof (struct GED_start_message) + name_len)
  {
    GNUNET_break (0);
    return;
  }

  n = get_node (peer);
  if (NULL == n)
  {
    GNUNET_break (0);
    return;
  }
  name = (const char *) &msg[1];
  if (name[name_len-1] != '\0')
  {
    GNUNET_break (0);
    return;
  }
  if (name_len != strlen (name) + 1)
  {
    GNUNET_break (0);
    return;
  }
  e = GED_experiments_find (&msg->issuer, name, GNUNET_TIME_absolute_ntoh(msg->version_nbo));
  if (NULL == e)
  {
    GNUNET_break (0);
    return;
  }
  GED_scheduler_handle_start (n, e);
}


/**
 * Handle a response
 *
 * @param peer the source
 * @param message the message
 */
static void
handle_start_ack (const struct GNUNET_PeerIdentity *peer,
		  const struct GNUNET_MessageHeader *message)
{
  uint16_t size;
  uint32_t name_len;
  const struct GED_start_ack_message *msg;
  const char *name;
  struct Node *n;
  struct Experiment *e;

  if (NULL == peer)
  {
    GNUNET_break (0);
    return;
  }
  if (NULL == message)
  {
    GNUNET_break (0);
    return;
  }

  size = ntohs (message->size);
  if (size < sizeof (struct GED_start_ack_message))
  {
    GNUNET_break (0);
    return;
  }
  msg = (const struct GED_start_ack_message *) message;
  name_len = ntohl (msg->len_name);
  if (size != sizeof (struct GED_start_message) + name_len)
  {
    GNUNET_break (0);
    return;
  }

  n = get_node (peer);
  if (NULL == n)
  {
    GNUNET_break (0);
    return;
  }
  name = (const char *) &msg[1];
  if (name[name_len-1] != '\0')
  {
    GNUNET_break (0);
    return;
  }
  if (name_len != strlen (name) + 1)
  {
    GNUNET_break (0);
    return;
  }

  e = GED_experiments_find (&msg->issuer, name, GNUNET_TIME_absolute_ntoh(msg->version_nbo));
  if (NULL == e)
  {
    GNUNET_break (0);
    return;
  }
  GED_scheduler_handle_start_ack (n, e);
}


/**
 * Handle a response
 *
 * @param peer the source
 * @param message the message
 */
static void
handle_stop (const struct GNUNET_PeerIdentity *peer,
	     const struct GNUNET_MessageHeader *message)
{
	uint16_t size;
	uint32_t name_len;
	const struct GED_stop_message *msg;
	const char *name;
	struct Node *n;
	struct Experiment *e;

	if (NULL == peer)
	{
		GNUNET_break (0);
		return;
	}
	if (NULL == message)
	{
		GNUNET_break (0);
		return;
	}

	size = ntohs (message->size);
	if (size < sizeof (struct GED_stop_message))
	{
		GNUNET_break (0);
		return;
	}
	msg = (const struct GED_stop_message *) message;
	name_len = ntohl (msg->len_name);
	if (size != sizeof (struct GED_start_message) + name_len)
	{
		GNUNET_break (0);
		return;
	}

	n = get_node (peer);
	if (NULL == n)
	{
		GNUNET_break (0);
		return;
	}
	name = (const char *) &msg[1];
	if (name[name_len-1] != '\0')
	{
		GNUNET_break (0);
		return;
	}

	if (name_len != strlen (name) + 1)
	{
		GNUNET_break (0);
		return;
	}

	e = GED_experiments_find (&msg->issuer, name, GNUNET_TIME_absolute_ntoh(msg->version_nbo));
	if (NULL == e)
	{
		GNUNET_break (0);
		return;
	}
	GED_scheduler_handle_stop (n, e);
}


/**
 * Method called whenever a given peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
core_connect_handler (void *cls,
		      const struct GNUNET_PeerIdentity *peer)
{
  if (GNUNET_YES == is_me(peer))
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Connected to peer %s\n"),
	      GNUNET_i2s (peer));

  if (GNUNET_YES == GNUNET_CONTAINER_multipeermap_contains (nodes_requested, peer))
    return; /* We already sent a request */

  if (GNUNET_YES == GNUNET_CONTAINER_multipeermap_contains (nodes_active, peer))
    return; /* This peer is known as active  */

  if (GNUNET_YES == GNUNET_CONTAINER_multipeermap_contains (nodes_inactive, peer))
    return; /* This peer is known as inactive  */

  send_experimentation_request (peer);
}


/**
 * Method called whenever a given peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
core_disconnect_handler (void *cls,
			 const struct GNUNET_PeerIdentity * peer)
{
	struct Node *n;
	if (GNUNET_YES == is_me(peer))
		return;

	GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Disconnected from peer %s\n"),
			GNUNET_i2s (peer));

	if (NULL != (n = GNUNET_CONTAINER_multipeermap_get (nodes_requested, peer)))
		cleanup_node (nodes_requested, peer, n);

	if (NULL != (n = GNUNET_CONTAINER_multipeermap_get (nodes_active, peer)))
		cleanup_node (nodes_active, peer, n);

	if (NULL != (n = GNUNET_CONTAINER_multipeermap_get (nodes_inactive, peer)))
		cleanup_node (nodes_inactive, peer, n);
}


/**
 * Handle a request and send a response
 *
 * @param cls unused
 * @param other the sender
 * @param message the message
 * @return GNUNET_OK to keep connection, GNUNET_SYSERR on error
 */
static int
core_receive_handler (void *cls,
		      const struct GNUNET_PeerIdentity *other,
		      const struct GNUNET_MessageHeader *message)
{
	if (ntohs (message->size) < sizeof (struct GNUNET_MessageHeader))
	{
			GNUNET_break (0);
			return GNUNET_SYSERR;
	}

	switch (ntohs (message->type)) {
		case GNUNET_MESSAGE_TYPE_EXPERIMENTATION_REQUEST:
			handle_request (other, message);
			break;
		case GNUNET_MESSAGE_TYPE_EXPERIMENTATION_RESPONSE:
			handle_response (other, message);
			break;
		case GNUNET_MESSAGE_TYPE_EXPERIMENTATION_START:
			handle_start (other, message);
			break;
		case GNUNET_MESSAGE_TYPE_EXPERIMENTATION_START_ACK:
			handle_start_ack (other, message);
			break;
		case GNUNET_MESSAGE_TYPE_EXPERIMENTATION_STOP:
			handle_stop (other, message);
			break;
		default:
			break;
	}

	return GNUNET_OK;
}


static size_t
node_experiment_start_cb (void *cls, size_t bufsize, void *buf)
{
	struct NodeComCtx *e_ctx = cls;
	struct GED_start_message *msg;
	size_t name_len;
	size_t size;

	if (NULL == buf)
		return 0;

	name_len = strlen(e_ctx->e->name) + 1;
	size = sizeof (struct GED_start_message) + name_len;

	msg = GNUNET_malloc (size);
	msg->header.size = htons (size);
	msg->header.type = htons (GNUNET_MESSAGE_TYPE_EXPERIMENTATION_START);
	msg->issuer = e_ctx->e->issuer;
	msg->version_nbo = GNUNET_TIME_absolute_hton(e_ctx->e->version);
	msg->len_name = htonl (name_len);
	memcpy (&msg[1], e_ctx->e->name, name_len);

	memcpy (buf, msg, size);
	GNUNET_free (msg);
	return size;
}


static size_t
node_experiment_start_ack_cb (void *cls, size_t bufsize, void *buf)
{
	struct NodeComCtx *e_ctx = cls;
	struct GED_start_ack_message *msg;
	size_t name_len;
	size_t size;
	if (NULL == buf)
		return 0;

	name_len = strlen(e_ctx->e->name) + 1;
	size = sizeof (struct GED_start_ack_message) + name_len;

	msg = GNUNET_malloc (size);
	msg->header.size = htons (size);
	msg->header.type = htons (GNUNET_MESSAGE_TYPE_EXPERIMENTATION_START_ACK);
	msg->issuer = e_ctx->e->issuer;
	msg->version_nbo = GNUNET_TIME_absolute_hton(e_ctx->e->version);
	msg->len_name = htonl (name_len);
	memcpy (&msg[1], e_ctx->e->name, name_len);

	memcpy (buf, msg, size);
	GNUNET_free (msg);
	return size;
}




/**
 * Confirm a experiment START with a node
 *
 * @return GNUNET_NO if core was busy with sending, GNUNET_OK otherwise
 */
int
GED_nodes_send_start_ack (struct Node *n, struct Experiment *e)
{
	struct NodeComCtx *e_ctx;

	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			"Sending %s for experiment request to peer `%s' for experiment `%s'\n",
			"START_ACK" ,GNUNET_i2s(&n->id), e->name);

	e_ctx = GNUNET_malloc (sizeof (struct NodeComCtx));
	e_ctx->n = n;
	e_ctx->e = e;
	e_ctx->size = sizeof (struct GED_start_ack_message) + strlen (e->name) + 1;
	e_ctx->notify = &node_experiment_start_ack_cb;
	e_ctx->notify_cls = e_ctx;

	GNUNET_CONTAINER_DLL_insert_tail (n->e_req_head, n->e_req_tail, e_ctx);
	schedule_transmisson (e_ctx);
	return GNUNET_OK;
}


/**
 * Request a experiment to start with a node
 *
 * @return GNUNET_NO if core was busy with sending, GNUNET_OK otherwise
 */
int
GED_nodes_send_start (struct Node *n, struct Experiment *e)
{
	struct NodeComCtx *e_ctx;

	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			"Sending %s for experiment request to peer `%s' for experiment `%s'\n",
			"START", GNUNET_i2s(&n->id), e->name);

	e_ctx = GNUNET_malloc (sizeof (struct NodeComCtx));
	e_ctx->n = n;
	e_ctx->e = e;
	e_ctx->size = sizeof (struct GED_start_message) + strlen (e->name) + 1;
	e_ctx->notify = &node_experiment_start_cb;
	e_ctx->notify_cls = e_ctx;

	GNUNET_CONTAINER_DLL_insert_tail (n->e_req_head, n->e_req_tail, e_ctx);
	schedule_transmisson (e_ctx);
	return GNUNET_OK;
}


/**
 * Start the nodes management
 */
void
GED_nodes_start ()
{
	/* Connecting to core service to find partners */
	ch = GNUNET_CORE_connect (GED_cfg, NULL,
														&core_startup_handler,
														&core_connect_handler,
													 	&core_disconnect_handler,
														&core_receive_handler,
														GNUNET_NO, NULL, GNUNET_NO, NULL);
	if (NULL == ch)
	{
			GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Failed to connect to CORE service!\n"));
			return;
	}

	nodes_requested = GNUNET_CONTAINER_multipeermap_create (10, GNUNET_NO);
	nodes_active = GNUNET_CONTAINER_multipeermap_create (10, GNUNET_NO);
	nodes_inactive = GNUNET_CONTAINER_multipeermap_create (10, GNUNET_NO);
}


/**
 * Stop the nodes management
 */
void
GED_nodes_stop ()
{
  if (NULL != ch)
  {
  		GNUNET_CORE_disconnect (ch);
  		ch = NULL;
  }

  if (NULL != nodes_requested)
  {
  		GNUNET_CONTAINER_multipeermap_iterate (nodes_requested,
  																					 &cleanup_node,
  																					 nodes_requested);
  		update_stats (nodes_requested);
  		GNUNET_CONTAINER_multipeermap_destroy (nodes_requested);
  		nodes_requested = NULL;
  }

  if (NULL != nodes_active)
  {
  		GNUNET_CONTAINER_multipeermap_iterate (nodes_active,
  																					 &cleanup_node,
  																					 nodes_active);
  		update_stats (nodes_active);
  		GNUNET_CONTAINER_multipeermap_destroy (nodes_active);
  		nodes_active = NULL;
  }

  if (NULL != nodes_inactive)
  {
  		GNUNET_CONTAINER_multipeermap_iterate (nodes_inactive,
  																					 &cleanup_node,
  																					 nodes_inactive);
  		update_stats (nodes_inactive);
  		GNUNET_CONTAINER_multipeermap_destroy (nodes_inactive);
  		nodes_inactive = NULL;
  }
}

/* end of gnunet-daemon-experimentation_nodes.c */
