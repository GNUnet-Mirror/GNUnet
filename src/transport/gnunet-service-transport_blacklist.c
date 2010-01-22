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
#include "gnunet_util_lib.h"
#include "gnunet_service_lib.h"
#include "transport.h"
#include "gnunet-service-transport_blacklist.h"


/**
 * Information kept for each blacklisted peer.
 */
struct BlacklistEntry
{
  /**
   * Identity of the peer being blacklisted by this entry.
   * (also equivalent to the key)  
   */
  struct GNUNET_PeerIdentity peer;

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
 * Map of blacklisted peers (maps from peer identities
 * to 'struct BlacklistEntry*' values).
 */
static struct GNUNET_CONTAINER_MultiHashMap *blacklist;

/**
 * Notifications for blacklisting.
 */
static struct GNUNET_SERVER_NotificationContext *blacklist_notifiers;

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
 * @return GNUNET_YES (continue to iterate)
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


/**
 * Task run when we are shutting down.  Cleans up.
 *
 * @param cls closure (unused)
 * @param tc scheduler context (unused)
 */
static void 
shutdown_task (void *cls,
	       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_CONTAINER_multihashmap_iterate (blacklist,
					 &free_blacklist_entry,
					 NULL);
  GNUNET_CONTAINER_multihashmap_destroy (blacklist);
  blacklist = NULL;
  GNUNET_SERVER_notification_context_destroy (blacklist_notifiers);
  blacklist_notifiers = NULL;
}


/**
 * Task run when a blacklist entry times out.
 *
 * @param cls closure (the 'struct BlacklistEntry*')
 * @param tc scheduler context (unused)
 */
static void
timeout_task (void *cls,
	      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct BlacklistEntry *be = cls;
  struct BlacklistMessage msg;
  
  be->timeout_task = GNUNET_SCHEDULER_NO_TASK; 
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST);
  msg.header.size = htons (sizeof (struct BlacklistMessage));
  msg.reserved = htonl (0);
  msg.peer = be->peer;
  msg.until = GNUNET_TIME_absolute_hton (GNUNET_TIME_UNIT_ZERO_ABS);
  GNUNET_assert (GNUNET_YES == GNUNET_CONTAINER_multihashmap_remove (blacklist,
								     &be->peer.hashPubKey,
								     be));
  GNUNET_free (be);
  GNUNET_SERVER_notification_context_broadcast (blacklist_notifiers,
						&msg.header,
						GNUNET_NO);
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
  struct BlacklistEntry *be;
  const struct BlacklistMessage *msg = (const struct BlacklistMessage*) message;

  be = GNUNET_CONTAINER_multihashmap_get (blacklist,
					  &be->peer.hashPubKey);
  if (be != NULL)
    {
      GNUNET_SCHEDULER_cancel (sched,
			       be->timeout_task);
    }
  else
    {
      be = GNUNET_malloc (sizeof (struct BlacklistEntry));
      be->peer = msg->peer;
      GNUNET_CONTAINER_multihashmap_put (blacklist,
					 &be->peer.hashPubKey,
					 be,
					 GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
    }
  be->until = GNUNET_TIME_absolute_ntoh (msg->until);
  be->timeout_task = GNUNET_SCHEDULER_add_delayed (sched,
						   GNUNET_TIME_absolute_get_remaining (be->until),
						   &timeout_task,
						   be);
  GNUNET_SERVER_notification_context_broadcast (blacklist_notifiers,
						&msg->header,
						GNUNET_NO);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Notify the given client about all entries in the blacklist.
 *
 * @param cls closure, refers to the 'struct GNUNET_SERVER_Client' to notify
 * @param key current key code (peer identity, not used)
 * @param value value in the hash map, the 'struct BlacklistEntry*'
 * @return GNUNET_YES (continue to iterate)
 */
static int
notify_blacklist_entry (void *cls,
			const GNUNET_HashCode *key,
			void *value)
{
  struct GNUNET_SERVER_Client *client = cls;
  struct BlacklistEntry *be = value;
  struct BlacklistMessage msg;

  msg.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST);
  msg.header.size = htons (sizeof (struct BlacklistMessage));
  msg.reserved = htonl (0);
  msg.peer = be->peer;
  msg.until = GNUNET_TIME_absolute_hton (be->until);
  GNUNET_SERVER_notification_context_unicast (blacklist_notifiers,
					      client,
					      &msg.header,
					      GNUNET_NO);
  return GNUNET_YES;
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
  GNUNET_SERVER_notification_context_add (blacklist_notifiers, client);
  GNUNET_CONTAINER_multihashmap_iterate (blacklist,
					 &notify_blacklist_entry,
					 client);
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
GNUNET_TRANSPORT_blacklist_init (struct GNUNET_SERVER_Handle *server,
				 struct GNUNET_SCHEDULER_Handle *s)
{
  sched = s;
  blacklist = GNUNET_CONTAINER_multihashmap_create (4);
  GNUNET_SCHEDULER_add_delayed (sched,
				GNUNET_TIME_UNIT_FOREVER_REL,
				&shutdown_task,
				NULL);
  blacklist_notifiers = GNUNET_SERVER_notification_context_create (server, 0);
}


/* end of gnunet-service-transport_blacklist.c */
