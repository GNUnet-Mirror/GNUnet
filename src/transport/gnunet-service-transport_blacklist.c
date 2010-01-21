/*
     This file is part of GNUnet.
     (C) 2010 Christian Grothoff (and other contributing authors)

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
 * @file transport/gnunet-service-transport_blacklist.c
 * @brief low-level P2P messaging
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_service_lib.h"
#include "transport.h"
#include "gnunet-service-transport_blacklist.h"


/**
 * Information kept for each blacklisted peer.
 */
struct BlacklistEntry
{
  /**
   * How long until this entry times out?
   */
  struct GNUNET_TIME_Absolute until;

  /**
   * Task scheduled to run the moment the time does run out.
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;
};


/**
 * Entry in list of notifications still to transmit to
 * a client.
 */
struct PendingNotificationList 
{

  /**
   * This is a linked list.
   */
  struct PendingNotificationList *next;

  /**
   * Identity of the peer to send notification about.
   */
  struct GNUNET_PeerIdentity peer;

};


/**
 * List of clients to notify whenever the blacklist changes.
 */
struct BlacklistNotificationList
{

  /**
   * This is a linked list.
   */
  struct BlacklistNotificationList *next;

  /**
   * Client to notify.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Pending request for transmission to client, or NULL.
   */ 
  struct GNUNET_CONNECTION_TransmitHandle *req;

  /**
   * Blacklist entries that still need to be submitted.
   */
  struct PendingNotificationList *pending;
  
};


/**
 * Map of blacklisted peers (maps from peer identities
 * to 'struct BlacklistEntry*' values).
 */
static struct GNUNET_CONTAINER_MultiHashMap *blacklist;

/**
 * Linked list of clients to notify whenever the blacklist changes.
 */
static struct BlacklistNotificationList *blacklist_notifiers;

/**
 * Our scheduler.
 */
static struct GNUNET_SCHEDULER_Handle *sched;


/**
 * Free the entries in the blacklist hash map.
 *
 * @param cls closure, unused
 * @param key current key code
 * @param value value in the hash map
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
static int
free_blacklist_entry (void *cls,
		      const GNUNET_HashCode *key,
		      void *value)
{
  struct BlacklistEntry *be = value;

  GNUNET_SCHEDULER_cancel (sched,
			   be->timeout_task);
  GNUNET_free (be);
  return GNUNET_YES;
}


static void 
shutdown_task (void *cls,
	       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_CONTAINER_multihashmap_iterate (blacklist,
					 &free_blacklist_entry,
					 NULL);
  GNUNET_CONTAINER_multihashmap_destroy (blacklist);
}


/**
 * Handle a request to blacklist a peer.
 *
 * @param cls closure (always NULL)
 * @param client identification of the client
 * @param message the actual message
 */
void
GNUNET_TRANSPORT_handle_blacklist (void *cls,
				   struct GNUNET_SERVER_Client *client,
				   const struct GNUNET_MessageHeader *message)
{
}


/**
 * Handle a request for notification of blacklist changes.
 *
 * @param cls closure (always NULL)
 * @param client identification of the client
 * @param message the actual message
 */
void
GNUNET_TRANSPORT_handle_blacklist_notify (void *cls,
					  struct GNUNET_SERVER_Client *client,
					  const struct GNUNET_MessageHeader *message)
{
}


/**
 * Is the given peer currently blacklisted?
 *
 * @param id identity of the peer
 * @return GNUNET_YES if the peer is blacklisted, GNUNET_NO if not
 */
int
GNUNET_TRANSPORT_blacklist_check (const struct GNUNET_PeerIdentity *id)
{
  return GNUNET_CONTAINER_multihashmap_contains (blacklist, &id->hashPubKey);
}


/**
 * Initialize the blacklisting subsystem.
 *
 * @param s scheduler to use
 */
void 
GNUNET_TRANSPORT_blacklist_init (struct GNUNET_SCHEDULER_Handle *s)
{
  sched = s;
  blacklist = GNUNET_CONTAINER_multihashmap_create (4);
  GNUNET_SCHEDULER_add_delayed (sched,
				GNUNET_TIME_UNIT_FOREVER_REL,
				&shutdown_task,
				NULL);
}

/* end of gnunet-service-transport_blacklist.c */
