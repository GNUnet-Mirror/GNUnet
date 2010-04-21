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
 * Handle a request to start a blacklist.
 *
 * @param cls closure (always NULL)
 * @param client identification of the client
 * @param message the actual message
 */
void
GNUNET_TRANSPORT_handle_blacklist_init (void *cls,
					struct GNUNET_SERVER_Client *client,
					const struct GNUNET_MessageHeader *message)
{
  struct Blacklisters *bl;

  bl = GNUNET_malloc (sizeof (struct Blacklisters));
  bl->client = client;
  GNUNET_SERVER_client_keep (client);
  GNUNET_CONTAINER_DLL_insert (bl_head, bl_tail, bl);
  /* FIXME: confirm that all existing connections are OK! */
}


/**
 * Handle a request to blacklist a peer.
 *
 * @param cls closure (always NULL)
 * @param client identification of the client
 * @param message the actual message
 */
void
GNUNET_TRANSPORT_handle_blacklist_reply (void *cls,
					 struct GNUNET_SERVER_Client *client,
					 const struct GNUNET_MessageHeader *message)
{
  struct Blacklisters *bl;
  const struct BlacklistMessage *msg = (const struct BlacklistMessage*) message;

  bl = bl_head;
  while ( (bl != NULL) &&
	  (bl->client != client) )
    bl = bl->next;
  if (bl == NULL)
    {
      GNUNET_SERVER_client_done (client, GNUNET_SYSERR);
      return;
    }
  if (ntohl (msg->is_allowed) == GNUNET_SYSERR)
    {    
      be = GNUNET_malloc (sizeof (struct BlacklistEntry));
      be->peer = msg->peer;
      be->client = client;
      GNUNET_CONTAINER_multihashmap_put (blacklist,
					 &msg->peer.hashPubKey,
					 be,
					 GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
    }
  /* FIXME: trigger continuation... */
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
  if (GNUNET_CONTAINER_multihashmap_contains (blacklist, &id->hashPubKey))    
    return GNUNET_YES;
  
}


/**
 * Initialize the blacklisting subsystem.
 *
 * @param server server of the transport service
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
}


/* end of gnunet-service-transport_blacklist.c */
