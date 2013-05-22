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
 * @file experimentation/gnunet-daemon-experimentation.c
 * @brief experimentation daemon
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_statistics_service.h"

#define EXP_RESPONSE_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 2)

static struct GNUNET_CORE_Handle *ch;

static struct GNUNET_PeerIdentity me;

static struct GNUNET_STATISTICS_Handle *stats;

/**
 * A experimentation node
 */
struct Node
{
	struct GNUNET_PeerIdentity id;

	GNUNET_SCHEDULER_TaskIdentifier timeout_task;

	struct GNUNET_CORE_TransmitHandle *cth;
};


struct Experimentation_Request
{
	struct GNUNET_MessageHeader msg;
};

struct Experimentation_Response
{
	struct GNUNET_MessageHeader msg;
};


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


static void update_stats (struct GNUNET_CONTAINER_MultiHashMap *m)
{
	GNUNET_assert (NULL != m);
	GNUNET_assert (NULL != stats);

	if (m == nodes_active)
	{
			GNUNET_STATISTICS_set (stats, "# nodes active",
					GNUNET_CONTAINER_multihashmap_size(m), GNUNET_NO);
	}
	else if (m == nodes_inactive)
	{
			GNUNET_STATISTICS_set (stats, "# nodes inactive",
					GNUNET_CONTAINER_multihashmap_size(m), GNUNET_NO);
	}
	else if (m == nodes_requested)
	{
			GNUNET_STATISTICS_set (stats, "# nodes requested",
					GNUNET_CONTAINER_multihashmap_size(m), GNUNET_NO);
	}
	else
		GNUNET_break (0);

}

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


	GNUNET_CONTAINER_multihashmap_remove (cur, key, value);
	GNUNET_free (value);
	return GNUNET_OK;
}

/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
cleanup_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Experimentation daemon shutting down ...\n"));
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

  if (NULL != stats)
  {
  		GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
  		stats = NULL;
  }
}

static int is_me (const struct GNUNET_PeerIdentity *id)
{
	if (0 == memcmp (&me, id, sizeof (me)))
		return GNUNET_YES;
	else
		return GNUNET_NO;
}

static void
core_startup_handler (void *cls,
											struct GNUNET_CORE_Handle * server,
                      const struct GNUNET_PeerIdentity *my_identity)
{
	me = *my_identity;
}

static void
remove_request (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
	struct Node *n = cls;

	GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Removing request for peer %s due to timeout\n"),
			GNUNET_i2s (&n->id));

	if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains (nodes_requested, &n->id.hashPubKey))
			GNUNET_break (0);
	else
	{
			GNUNET_CONTAINER_multihashmap_remove (nodes_requested, &n->id.hashPubKey, n);
			update_stats (nodes_requested);
			GNUNET_CONTAINER_multihashmap_put (nodes_inactive, &n->id.hashPubKey, n,
					GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
			update_stats (nodes_inactive);
			n->timeout_task = GNUNET_SCHEDULER_NO_TASK;
			if (NULL != n->cth)
			{
				GNUNET_CORE_notify_transmit_ready_cancel (n->cth);
				n->cth = NULL;
			}
	}
}

size_t send_request_cb (void *cls, size_t bufsize, void *buf)
{
	struct Node *n = cls;
	struct Experimentation_Request msg;
	size_t size = sizeof (msg);

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
  GNUNET_assert (bufsize >= size);

	msg.msg.size = htons (size);
	msg.msg.type = htons (GNUNET_MESSAGE_TYPE_EXPERIMENTATION_REQUEST);
	memcpy (buf, &msg, size);

	GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Sending request to peer %s\n"),
			GNUNET_i2s (&n->id));
	return size;
}

static void send_request (const struct GNUNET_PeerIdentity *peer)
{
	struct Node *n;
	size_t size;

	size = sizeof (struct Experimentation_Request);
	n = GNUNET_malloc (sizeof (struct Node));
	n->id = *peer;
	n->timeout_task = GNUNET_SCHEDULER_add_delayed (EXP_RESPONSE_TIMEOUT, &remove_request, n);
	n->cth = GNUNET_CORE_notify_transmit_ready(ch, GNUNET_NO, 0,
								GNUNET_TIME_relative_get_forever_(),
								peer, size, send_request_cb, n);

	GNUNET_assert (GNUNET_OK == GNUNET_CONTAINER_multihashmap_put (nodes_requested,
			&peer->hashPubKey, n, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST));

	update_stats (nodes_requested);
}

size_t send_response_cb (void *cls, size_t bufsize, void *buf)
{
	struct Node *n = cls;
	struct Experimentation_Response msg;
	size_t size = sizeof (msg);

	n->cth = NULL;
  if (buf == NULL)
  {
    /* client disconnected */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Client disconnected\n");
    return 0;
  }
  GNUNET_assert (bufsize >= size);

	msg.msg.size = htons (size);
	msg.msg.type = htons (GNUNET_MESSAGE_TYPE_EXPERIMENTATION_RESPONSE);
	memcpy (buf, &msg, size);

	GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Sending response to peer %s\n"),
			GNUNET_i2s (&n->id));
	return size;
}

static void handle_request (const struct GNUNET_PeerIdentity *peer)
{
	struct Node *n;

	if (NULL != (n = GNUNET_CONTAINER_multihashmap_get (nodes_active, &peer->hashPubKey)))
	{
			GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Received %s from peer `%s'\n"),
					"REQUEST", "active", GNUNET_i2s (peer));
	}
	else if (NULL != (n = GNUNET_CONTAINER_multihashmap_get (nodes_requested, &peer->hashPubKey)))
	{
			GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Received %s from %s peer `%s'\n"),
					"REQUEST", "requested", GNUNET_i2s (peer));
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
		  GNUNET_CONTAINER_multihashmap_put (nodes_active,
					&peer->hashPubKey, n, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
			update_stats (nodes_active);
	}
	else if (NULL != (n = GNUNET_CONTAINER_multihashmap_get (nodes_inactive, &peer->hashPubKey)))
	{
			GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Received %s from peer `%s'\n"),
					"REQUEST", "inactive", GNUNET_i2s (peer));
			GNUNET_CONTAINER_multihashmap_remove (nodes_inactive, &peer->hashPubKey, n);
			update_stats (nodes_inactive);
		  GNUNET_CONTAINER_multihashmap_put (nodes_active,
					&peer->hashPubKey, n, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
			update_stats (nodes_active);
	}

	else
	{
			/* Create new node */
			n = GNUNET_malloc (sizeof (struct Node));
			n->id = *peer;
			GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Received %s from %s peer `%s'\n"),
					"REQUEST", "new", GNUNET_i2s (peer));
		  GNUNET_CONTAINER_multihashmap_put (nodes_active,
					&peer->hashPubKey, n, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
			update_stats (nodes_active);
	}

	n->cth = GNUNET_CORE_notify_transmit_ready(ch, GNUNET_NO, 0,
								GNUNET_TIME_relative_get_forever_(),
								peer, sizeof (struct Experimentation_Response),
								send_response_cb, n);

}

static void handle_response (const struct GNUNET_PeerIdentity *peer)
{

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

	send_request (peer);

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
			handle_request (other);

			break;
		case GNUNET_MESSAGE_TYPE_EXPERIMENTATION_RESPONSE:
			GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Received %s from peer `%s'\n"),
					"RESPONSE", GNUNET_i2s (other));
			handle_response (other);
			break;
		default:
			break;
	}

	return GNUNET_OK;
}



/**
 * The main function for the experimentation daemon.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
	GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Experimentation daemon starting ...\n"));

	stats = GNUNET_STATISTICS_create ("experimentation", cfg);
	if (NULL == stats)
	{
		GNUNET_log (GNUNET_ERROR_TYPE_WARNING, _("Failed to create statistics!\n"));
		return;
	}

	/* Connecting to core service to find partners */
	ch = GNUNET_CORE_connect (cfg, NULL,
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

  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &cleanup_task,
                                NULL);

}


/**
 * The main function for the experimentation daemon.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };

  return (GNUNET_OK ==
          GNUNET_PROGRAM_run (argc, argv, "experimentation",
          										_("GNUnet hostlist server and client"), options,
                              &run, NULL)) ? 0 : 1;
}

/* end of gnunet-daemon-experimentation.c */
