/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
#include "gnunet_getopt_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet-daemon-experimentation.h"


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
struct GNUNET_CONTAINER_MultiHashMap *nodes_requested;


/**
 * Active experimentation nodes
 */
struct GNUNET_CONTAINER_MultiHashMap *nodes_active;


/**
 * Inactive experimentation nodes
 * To be excluded from future requests
 */
struct GNUNET_CONTAINER_MultiHashMap *nodes_inactive;


/**
 * Update statistics
 *
 * @param m hashmap to update values from
 */
static void update_stats (struct GNUNET_CONTAINER_MultiHashMap *m)
{
	GNUNET_assert (NULL != m);
	GNUNET_assert (NULL != GSE_stats);

	if (m == nodes_active)
	{
			GNUNET_STATISTICS_set (GSE_stats, "# nodes active",
					GNUNET_CONTAINER_multihashmap_size(m), GNUNET_NO);
	}
	else if (m == nodes_inactive)
	{
			GNUNET_STATISTICS_set (GSE_stats, "# nodes inactive",
					GNUNET_CONTAINER_multihashmap_size(m), GNUNET_NO);
	}
	else if (m == nodes_requested)
	{
			GNUNET_STATISTICS_set (GSE_stats, "# nodes requested",
					GNUNET_CONTAINER_multihashmap_size(m), GNUNET_NO);
	}
	else
		GNUNET_break (0);

}


/**
 * Clean up nodes
 *
 * @param cls the hashmap to clean up
 * @param key key of the current node
 * @param value related node object
 * @return always GNUNET_OK
 */
static int
cleanup_nodes (void *cls,
							 const struct GNUNET_HashCode * key,
							 void *value)
{
	struct Node *n;
	struct GNUNET_CONTAINER_MultiHashMap *cur = cls;

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
	GNUNET_free_non_null (n->issuer_id);

	GNUNET_CONTAINER_multihashmap_remove (cur, key, value);
	GNUNET_free (value);
	return GNUNET_OK;
}


/**
 * Check if id passed is my id
 *
 * @param id the id to check
 * @return GNUNET_YES or GNUNET_NO
 */
static int is_me (const struct GNUNET_PeerIdentity *id)
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
 * @param server core service's server handle
 * @param my_identity my id
 */
static void
core_startup_handler (void *cls,
											struct GNUNET_CORE_Handle *server,
                      const struct GNUNET_PeerIdentity *my_identity)
{
	me = *my_identity;
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

	GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Removing request for peer %s due to timeout\n"),
			GNUNET_i2s (&n->id));

	if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (nodes_requested, &n->id.hashPubKey))
	{
			GNUNET_CONTAINER_multihashmap_remove (nodes_requested, &n->id.hashPubKey, n);
			update_stats (nodes_requested);
			GNUNET_CONTAINER_multihashmap_put (nodes_inactive, &n->id.hashPubKey, n,
					GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
			update_stats (nodes_inactive);
	}

	n->timeout_task = GNUNET_SCHEDULER_NO_TASK;
	if (NULL != n->cth)
	{
		GNUNET_CORE_notify_transmit_ready_cancel (n->cth);
		n->cth = NULL;
	}
}


/**
 * Core's transmit notify callback to send request
 *
 * @param cls the related node
 * @param bufsize buffer size
 * @param buf the buffer to copy to
 * @return bytes passed
 */
size_t send_experimentation_request_cb (void *cls, size_t bufsize, void *buf)
{
	struct Node *n = cls;
	struct Experimentation_Request msg;
	size_t msg_size = sizeof (msg);
	size_t ri_size = sizeof (struct Experimentation_Issuer) * GSE_my_issuer_count;
	size_t total_size = msg_size + ri_size;

	memset (buf, '0', bufsize);
	n->cth = NULL;
  if (buf == NULL)
  {
    /* client disconnected */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Client disconnected\n");
    if (GNUNET_SCHEDULER_NO_TASK != n->timeout_task)
    		GNUNET_SCHEDULER_cancel (n->timeout_task);
    GNUNET_SCHEDULER_add_now (&remove_request, n);
    return 0;
  }
  GNUNET_assert (bufsize >= total_size);

	msg.msg.size = htons (total_size);
	msg.msg.type = htons (GNUNET_MESSAGE_TYPE_EXPERIMENTATION_REQUEST);
	msg.capabilities = htonl (GSE_node_capabilities);
	msg.issuer_count = htonl (GSE_my_issuer_count);
	memcpy (buf, &msg, msg_size);
	memcpy (&((char *) buf)[msg_size], GSE_my_issuer, ri_size);

	GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Sending request to peer %s\n"),
			GNUNET_i2s (&n->id));
	return total_size;
}


/**
 * Send request to peer to start add him to to the set of experimentation nodes
 *
 * @param peer the peer to send to
 */
static void send_experimentation_request (const struct GNUNET_PeerIdentity *peer)
{
	struct Node *n;
	size_t size;
	size_t c_issuers;

	c_issuers = GSE_my_issuer_count;

	size = sizeof (struct Experimentation_Request) +
				 c_issuers * sizeof (struct Experimentation_Issuer);
	n = GNUNET_malloc (sizeof (struct Node));
	n->id = *peer;
	n->timeout_task = GNUNET_SCHEDULER_add_delayed (EXP_RESPONSE_TIMEOUT, &remove_request, n);
	n->capabilities = NONE;
	n->cth = GNUNET_CORE_notify_transmit_ready(ch, GNUNET_NO, 0,
								GNUNET_TIME_relative_get_forever_(),
								peer, size, send_experimentation_request_cb, n);

	GNUNET_assert (GNUNET_OK == GNUNET_CONTAINER_multihashmap_put (nodes_requested,
			&peer->hashPubKey, n, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST));
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
size_t send_response_cb (void *cls, size_t bufsize, void *buf)
{
	struct Node *n = cls;
	struct Experimentation_Response msg;
	size_t ri_size = GSE_my_issuer_count * sizeof (struct Experimentation_Issuer);
	size_t msg_size = sizeof (msg);
	size_t total_size = msg_size + ri_size;

	n->cth = NULL;
  if (buf == NULL)
  {
    /* client disconnected */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Client disconnected\n");
    return 0;
  }
  GNUNET_assert (bufsize >= total_size);

	msg.msg.size = htons (total_size);
	msg.msg.type = htons (GNUNET_MESSAGE_TYPE_EXPERIMENTATION_RESPONSE);
	msg.capabilities = htonl (GSE_node_capabilities);
	msg.issuer_count = htonl (GSE_my_issuer_count);
	memcpy (buf, &msg, msg_size);
	memcpy (&((char *) buf)[msg_size], GSE_my_issuer, ri_size);

	GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Sending response to peer %s\n"),
			GNUNET_i2s (&n->id));
	return total_size;
}


static void
get_experiments_cb (struct Node *n, struct Experiment *e)
{
	static int counter = 0;
	if (NULL == e)
	{
			GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Added %u experiments for peer %s\n"),
					counter, GNUNET_i2s (&n->id));
			return;
	}

	GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Starting experiment `%s' with peer %s\n"),
			e->name,
			GNUNET_i2s (&n->id));

	/* Tell the scheduler to add a node with an experiment */
	GED_scheduler_add (n, e);
	counter ++;
}

/**
 * Set a specific node as active
 *
 * @param n the node
 */
static void node_make_active (struct Node *n)
{
	int c1;
  GNUNET_CONTAINER_multihashmap_put (nodes_active,
			&n->id.hashPubKey, n, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
	update_stats (nodes_active);
	GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Added peer `%s' as active node\n"),
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
static void handle_request (const struct GNUNET_PeerIdentity *peer,
														const struct GNUNET_MessageHeader *message)
{
	struct Node *n;
	struct Experimentation_Request *rm = (struct Experimentation_Request *) message;
	struct Experimentation_Issuer *rmi = (struct Experimentation_Issuer *) &rm[1];
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
	if (ntohs (message->size) != sizeof (struct Experimentation_Request) + ic * sizeof (struct Experimentation_Issuer))
	{
		GNUNET_break (0);
		return;
	}

	make_active = GNUNET_NO;
	if (NULL != (n = GNUNET_CONTAINER_multihashmap_get (nodes_active, &peer->hashPubKey)))
	{
			/* Nothing to do */
	}
	else if (NULL != (n = GNUNET_CONTAINER_multihashmap_get (nodes_requested, &peer->hashPubKey)))
	{
			GNUNET_CONTAINER_multihashmap_remove (nodes_requested, &peer->hashPubKey, n);
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
			update_stats (nodes_requested);
			make_active = GNUNET_YES;
	}
	else if (NULL != (n = GNUNET_CONTAINER_multihashmap_get (nodes_inactive, &peer->hashPubKey)))
	{
			GNUNET_CONTAINER_multihashmap_remove (nodes_inactive, &peer->hashPubKey, n);
			update_stats (nodes_inactive);
			make_active = GNUNET_YES;
	}
	else
	{
			/* Create new node */
			n = GNUNET_malloc (sizeof (struct Node));
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
		if (GNUNET_YES == GED_experiments_issuer_accepted(&rmi[c1].issuer_id))
			ic_accepted ++;
	}
	GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Request from peer `%s' with %u issuers, we accepted %u issuer \n"),
			GNUNET_i2s (peer), ic, ic_accepted);
	GNUNET_free_non_null (n->issuer_id);
	n->issuer_id = GNUNET_malloc (ic_accepted * sizeof (struct GNUNET_PeerIdentity));
	c2 = 0;
	for (c1 = 0; c1 < ic; c1++)
	{
			if (GNUNET_YES == GED_experiments_issuer_accepted(&rmi[c1].issuer_id))
			{
				n->issuer_id[c2] = rmi[c1].issuer_id;
				c2 ++;
			}
	}
	n->issuer_count = ic_accepted;

	if (GNUNET_YES == make_active)
		node_make_active (n);

	/* Send response */
	n->cth = GNUNET_CORE_notify_transmit_ready (ch, GNUNET_NO, 0,
								GNUNET_TIME_relative_get_forever_(),
								peer,
								sizeof (struct Experimentation_Response) +
								GSE_my_issuer_count * sizeof (struct Experimentation_Issuer),
								send_response_cb, n);
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
	struct Experimentation_Response *rm = (struct Experimentation_Response *) message;
	struct Experimentation_Issuer *rmi = (struct Experimentation_Issuer *) &rm[1];
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
	if (ntohs (message->size) != sizeof (struct Experimentation_Response) + ic * sizeof (struct Experimentation_Issuer))
	{
		GNUNET_break (0);
		return;
	}

	make_active = GNUNET_NO;
	if (NULL != (n = GNUNET_CONTAINER_multihashmap_get (nodes_active, &peer->hashPubKey)))
	{
			GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Received %s from %s peer `%s'\n"),
					"RESPONSE", "active", GNUNET_i2s (peer));
	}
	else if (NULL != (n = GNUNET_CONTAINER_multihashmap_get (nodes_requested, &peer->hashPubKey)))
	{
			GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Received %s from %s peer `%s'\n"),
					"RESPONSE", "requested", GNUNET_i2s (peer));
			GNUNET_CONTAINER_multihashmap_remove (nodes_requested, &peer->hashPubKey, n);
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
			update_stats (nodes_requested);
			make_active = GNUNET_YES;
	}
	else if (NULL != (n = GNUNET_CONTAINER_multihashmap_get (nodes_inactive, &peer->hashPubKey)))
	{
			GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Received %s from peer `%s'\n"),
					"RESPONSE", "inactive", GNUNET_i2s (peer));
			GNUNET_CONTAINER_multihashmap_remove (nodes_inactive, &peer->hashPubKey, n);
			update_stats (nodes_inactive);
			make_active = GNUNET_YES;
	}
	else
	{
			GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Received %s from %s peer `%s'\n"),
					"RESPONSE", "unknown", GNUNET_i2s (peer));
			return;
	}

	/* Update */
	n->capabilities = ntohl (rm->capabilities);

	/* Filter accepted issuer */
	ic_accepted = 0;
	for (c1 = 0; c1 < ic; c1++)
	{
		if (GNUNET_YES == GED_experiments_issuer_accepted(&rmi[c1].issuer_id))
			ic_accepted ++;
	}
	GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Response from peer `%s' with %u issuers, we accepted %u issuer \n"),
			GNUNET_i2s (peer), ic, ic_accepted);
	GNUNET_free_non_null (n->issuer_id);
	n->issuer_id = GNUNET_malloc (ic_accepted * sizeof (struct GNUNET_PeerIdentity));
	c2 = 0;
	for (c1 = 0; c1 < ic; c1++)
	{
			if (GNUNET_YES == GED_experiments_issuer_accepted(&rmi[c1].issuer_id))
			{
				n->issuer_id[c2] = rmi[c1].issuer_id;
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
static void handle_start (const struct GNUNET_PeerIdentity *peer,
														 const struct GNUNET_MessageHeader *message)
{
	GED_scheduler_handle_start (NULL, NULL);
}

/**
 * Handle a response
 *
 * @param peer the source
 * @param message the message
 */
static void handle_start_ack (const struct GNUNET_PeerIdentity *peer,
														 const struct GNUNET_MessageHeader *message)
{
	GED_scheduler_handle_start_ack (NULL, NULL);
}

/**
 * Handle a response
 *
 * @param peer the source
 * @param message the message
 */
static void handle_stop (const struct GNUNET_PeerIdentity *peer,
														 const struct GNUNET_MessageHeader *message)
{
	GED_scheduler_handle_stop (NULL, NULL);
}

/**
 * Method called whenever a given peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
void core_connect_handler (void *cls,
                           const struct GNUNET_PeerIdentity *peer)
{
	if (GNUNET_YES == is_me(peer))
		return;

	GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Connected to peer %s\n"),
			GNUNET_i2s (peer));

	if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (nodes_requested, &peer->hashPubKey))
		return; /* We already sent a request */

	if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (nodes_active, &peer->hashPubKey))
		return; /* This peer is known as active  */

	if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (nodes_inactive, &peer->hashPubKey))
		return; /* This peer is known as inactive  */

	send_experimentation_request (peer);

}


/**
 * Method called whenever a given peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
void core_disconnect_handler (void *cls,
                           const struct GNUNET_PeerIdentity * peer)
{
	if (GNUNET_YES == is_me(peer))
		return;

	GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Disconnected from peer %s\n"),
			GNUNET_i2s (peer));

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

#define FAST_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

struct GNUNET_EXPERIMENTATION_start_message
{
	struct GNUNET_MessageHeader header;
};

struct ExperimentStartCtx
{
	struct ExperimentStartCtx *prev;
	struct ExperimentStartCtx *next;

	struct Node *n;
	struct Experiment *e;
};

size_t node_experiment_start_cb (void *cls, size_t bufsize, void *buf)
{
	struct ExperimentStartCtx *e_ctx = cls;
	struct GNUNET_EXPERIMENTATION_start_message msg;

	GNUNET_CONTAINER_DLL_remove (e_ctx->n->e_req_head, e_ctx->n->e_req_tail, e_ctx);
	e_ctx->n->cth = NULL;
	if (NULL == buf)
	{
		GNUNET_free (e_ctx);
		return 0;
	}

	size_t size = sizeof (struct GNUNET_EXPERIMENTATION_start_message);
	msg.header.size = htons (size);
	msg.header.type = htons (GNUNET_MESSAGE_TYPE_EXPERIMENTATION_START);

	memcpy (buf, &msg, size);
	GNUNET_free (e_ctx);
	return size;
}

int
GED_nodes_rts (struct Node *n)
{
	if (NULL == n->cth)
		return GNUNET_YES;
	else
		return GNUNET_NO;

}

/**
 * Request a experiment to start with a node
 *
 * @return GNUNET_NO if core was busy with sending, GNUNET_OK otherwise
 */
int
GED_nodes_request_start (struct Node *n, struct Experiment *e)
{
	struct ExperimentStartCtx *e_ctx;

	if (NULL != n->cth)
	{
		GNUNET_break (0); /* should call rts before */
		return GNUNET_NO;
	}

	GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Sending experiment start request to peer `%s' for experiment `%s'\n"),
			GNUNET_i2s(&n->id), e->name);

	e_ctx = GNUNET_malloc (sizeof (struct ExperimentStartCtx));
	e_ctx->n = n;
	e_ctx->e = e;
	n->cth = GNUNET_CORE_notify_transmit_ready (ch, GNUNET_NO, 0, FAST_TIMEOUT, &n->id,
			sizeof (struct GNUNET_EXPERIMENTATION_start_message),
			&node_experiment_start_cb, e_ctx);
	if (NULL == n->cth)
	{
		GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Cannot send experiment start request to peer `%s' for experiment `%s'\n"),
				GNUNET_i2s(&n->id), e->name);
		GNUNET_free (e_ctx);
	}
	GNUNET_CONTAINER_DLL_insert (n->e_req_head, n->e_req_tail, e_ctx);

	return GNUNET_OK;
}


/**
 * Start the nodes management
 */
void
GED_nodes_start ()
{
	/* Connecting to core service to find partners */
	ch = GNUNET_CORE_connect (GSE_cfg, NULL,
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

	nodes_requested = GNUNET_CONTAINER_multihashmap_create (10, GNUNET_NO);
	nodes_active = GNUNET_CONTAINER_multihashmap_create (10, GNUNET_NO);
	nodes_inactive = GNUNET_CONTAINER_multihashmap_create (10, GNUNET_NO);
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
  		GNUNET_CONTAINER_multihashmap_iterate (nodes_requested,
  																					 &cleanup_nodes,
  																					 nodes_requested);
  		update_stats (nodes_requested);
  		GNUNET_CONTAINER_multihashmap_destroy (nodes_requested);
  		nodes_requested = NULL;
  }

  if (NULL != nodes_active)
  {
  		GNUNET_CONTAINER_multihashmap_iterate (nodes_active,
  																					 &cleanup_nodes,
  																					 nodes_active);
  		update_stats (nodes_active);
  		GNUNET_CONTAINER_multihashmap_destroy (nodes_active);
  		nodes_active = NULL;
  }

  if (NULL != nodes_inactive)
  {
  		GNUNET_CONTAINER_multihashmap_iterate (nodes_inactive,
  																					 &cleanup_nodes,
  																					 nodes_inactive);
  		update_stats (nodes_inactive);
  		GNUNET_CONTAINER_multihashmap_destroy (nodes_inactive);
  		nodes_inactive = NULL;
  }
}

/* end of gnunet-daemon-experimentation_nodes.c */
