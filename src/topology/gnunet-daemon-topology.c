/*
     This file is part of GNUnet.
     (C) 2007, 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file topology/gnunet-daemon-topology.c
 * @brief code for bootstrapping via topology servers
 * @author Christian Grothoff
 */

#include <stdlib.h>
#include "platform.h"
#include "gnunet_core_service.h"
#include "gnunet_protocols.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_util_lib.h"


#define DEBUG_TOPOLOGY GNUNET_NO

/**
 * For how long do we blacklist a peer after a failed
 * connection attempt?
 */
#define BLACKLIST_AFTER_ATTEMPT GNUNET_TIME_UNIT_HOURS

/**
 * For how long do we blacklist a friend after a failed
 * connection attempt?
 */
#define BLACKLIST_AFTER_ATTEMPT_FRIEND GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 15)

/**
 * How frequently are we allowed to ask PEERINFO for more
 * HELLO's to advertise (at most)?
 */
#define MIN_HELLO_GATHER_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 27)

/**
 * How often do we at most advertise the same HELLO to the same peer?
 * Also used to remove HELLOs of peers that PEERINFO no longer lists
 * from our cache.
 */
#define HELLO_ADVERTISEMENT_MIN_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 12)


/**
 * List of neighbours, friends and blacklisted peers.
 */
struct PeerList
{

  /**
   * This is a linked list.
   */
  struct PeerList *next;

  /**
   * Is this peer listed here because he is a friend?
   */
  int is_friend;

  /**
   * Are we connected to this peer right now?
   */
  int is_connected;

  /**
   * Until what time should we not try to connect again
   * to this peer?
   */
  struct GNUNET_TIME_Absolute blacklisted_until;

  /**
   * Last time we transmitted a HELLO to this peer?
   */
  struct GNUNET_TIME_Absolute last_hello_sent;

  /**
   * ID of the peer.
   */
  struct GNUNET_PeerIdentity id;

};


/**
 * List of HELLOs we may consider for advertising.
 */
struct HelloList
{
  /**
   * This is a linked list.
   */
  struct HelloList *next;

  /**
   * Pointer to the HELLO message.  Memory allocated as part
   * of the "struct HelloList" --- do not free!
   */
  struct GNUNET_HELLO_Message *msg;

  /**
   * Bloom filter used to mark which peers already got
   * this HELLO.
   */
  struct GNUNET_CONTAINER_BloomFilter *filter;

  /**
   * What peer is this HELLO for?
   */
  struct GNUNET_PeerIdentity id;

  /**
   * When should we remove this entry from the linked list (either
   * resetting the filter or possibly eliminating it for good because
   * we no longer consider the peer to be participating in the
   * network)?
   */
  struct GNUNET_TIME_Absolute expiration;
};


/**
 * Linked list of HELLOs for advertising.
 */
static struct HelloList *hellos;

/**
 * Our scheduler.
 */
static struct GNUNET_SCHEDULER_Handle * sched;

/**
 * Our configuration.
 */
static struct GNUNET_CONFIGURATION_Handle * cfg;

/**
 * Handle to the core API.
 */
static struct GNUNET_CORE_Handle *handle;

/**
 * Handle to the transport API.
 */
static struct GNUNET_TRANSPORT_Handle *transport;

/**
 * Identity of this peer.
 */
static struct GNUNET_PeerIdentity my_identity;

/**
 * Linked list of all of our friends and all of our current
 * neighbours.
 */
static struct PeerList *friends;

/**
 * Timestamp from the last time we tried to gather HELLOs.
 */
static struct GNUNET_TIME_Absolute last_hello_gather_time;

/**
 * Flag to disallow non-friend connections (pure F2F mode).
 */
static int friends_only;

/**
 * Minimum number of friends to have in the
 * connection set before we allow non-friends.
 */
static unsigned int minimum_friend_count;

/**
 * Number of peers (friends and others) that we are currently connected to.
 */
static unsigned int connection_count;

/**
 * Target number of connections.
 */
static unsigned int target_connection_count;

/**
 * Number of friends that we are currently connected to.
 */
static unsigned int friend_count;

/**
 * Should the topology daemon try to establish connections?
 */
static int autoconnect;

/**
 * Are we currently having a request pending with
 * PEERINFO asking for HELLOs for advertising?
 */
static int hello_gathering_active;



/**
 * Force a disconnect from the specified peer.
 */
static void
force_disconnect (const struct GNUNET_PeerIdentity *peer)
{
  GNUNET_CORE_peer_configure (handle,
			      peer,
			      GNUNET_TIME_UNIT_FOREVER_REL,
			      0,
			      0,
			      0,
			      NULL,
			      NULL);
}


/**
 * Function called by core when our attempt to connect
 * succeeded.  Does nothing.
 */
static size_t
ready_callback (void *cls,
		size_t size, void *buf)
{
  return 0;
}


/**
 * Try to connect to the specified peer.
 *
 * @param pos NULL if not in friend list yet
 */
static void
attempt_connect (const struct GNUNET_PeerIdentity *peer,
		 struct PeerList *pos)
{
  if (pos == NULL)
    {
      pos = friends;
      while (pos != NULL)
	{
	  if (0 == memcmp (&pos->id, peer, sizeof (struct GNUNET_PeerIdentity)))
	    break;
	}
    }
  if (pos == NULL)
    {
      pos = GNUNET_malloc (sizeof(struct PeerList));
      pos->id = *peer;
      pos->next = friends;
      friends = pos;
    }
  if (GNUNET_YES == pos->is_friend)
    pos->blacklisted_until = GNUNET_TIME_relative_to_absolute (BLACKLIST_AFTER_ATTEMPT_FRIEND);
  else
    pos->blacklisted_until = GNUNET_TIME_relative_to_absolute (BLACKLIST_AFTER_ATTEMPT);
  GNUNET_CORE_notify_transmit_ready (handle,
				     0 /* priority */,
				     GNUNET_TIME_UNIT_MINUTES,
				     peer,
				     sizeof(struct GNUNET_MessageHeader),
				     &ready_callback,
				     NULL);
}


/**
 * Is this peer one of our friends?
 */
static int
is_friend (const struct GNUNET_PeerIdentity * peer)
{
  struct PeerList *pos;

  pos = friends;
  while (pos != NULL)
    {
      if ( (GNUNET_YES == pos->is_friend) &&
	   (0 == memcmp (&pos->id, peer, sizeof (struct GNUNET_PeerIdentity))) )
	return GNUNET_YES;
      pos = pos->next;
    }
  return GNUNET_NO;
}


/**
 * Check if an additional connection from the given peer is allowed.
 */
static int
is_connection_allowed (const struct GNUNET_PeerIdentity * peer)
{
  if (0 == memcmp (&my_identity, peer, sizeof (struct GNUNET_PeerIdentity)))
    return GNUNET_SYSERR;       /* disallow connections to self */
  if (is_friend (peer))
    return GNUNET_OK;
  if (GNUNET_YES == friends_only)
    return GNUNET_SYSERR;
  if (friend_count >= minimum_friend_count)
    return GNUNET_OK;
  return GNUNET_SYSERR;
}


/**
 * Method called whenever a peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void connect_notify (void *cls,
			    const struct
			    GNUNET_PeerIdentity * peer)
{
  struct PeerList *pos;

  connection_count++;
  pos = friends;
  while (pos != NULL)
    {
      if ( (GNUNET_YES == pos->is_friend) &&
	   (0 == memcmp (&pos->id, peer, sizeof (struct GNUNET_PeerIdentity))) )
	{
	  GNUNET_assert (GNUNET_NO == pos->is_connected);
	  pos->is_connected = GNUNET_YES;
	  pos->blacklisted_until.value = 0; /* remove blacklisting */
	  friend_count++;
	  return;
	}
      pos = pos->next;
    }
  pos = GNUNET_malloc (sizeof(struct PeerList));
  pos->id = *peer;
  pos->is_connected = GNUNET_YES;
  pos->next = friends;
  friends = pos;
  if (GNUNET_OK != is_connection_allowed (peer))
    force_disconnect (peer);
}


/**
 * Disconnect from all non-friends (we're below quota).
 */
static void
drop_non_friends ()
{
  struct PeerList *pos;

  pos = friends;
  while (pos != NULL)
    {
      if (GNUNET_NO == pos->is_friend)
	{
	  GNUNET_assert (GNUNET_YES == pos->is_connected);
	  force_disconnect (&pos->id);
	}
      pos = pos->next;
    }
}


/**
 * Method called whenever a peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void disconnect_notify (void *cls,
			       const struct
			       GNUNET_PeerIdentity * peer)
{
  struct PeerList *pos;
  struct PeerList *prev;

  connection_count--;
  pos = friends;
  prev = NULL;
  while (pos != NULL)
    {
      if (0 == memcmp (&pos->id, peer, sizeof (struct GNUNET_PeerIdentity)))
	{
	  GNUNET_assert (GNUNET_YES == pos->is_connected);
	  pos->is_connected = GNUNET_NO;
	  if (GNUNET_YES == pos->is_friend)
	    {
	      friend_count--;
	      if (friend_count < minimum_friend_count)
		{
		  /* disconnect from all non-friends */
		  drop_non_friends ();
		  attempt_connect (peer, pos);
		}
	    }
	  else
	    {
	      /* free entry */
	      if (prev == NULL)
		friends = pos->next;
	      else
		prev->next = pos->next;
	      GNUNET_free (pos);
	    }
	  return;
	}
      prev = pos;
      pos = pos->next;
    }
  GNUNET_break (0);
}


/**
 * Find more peers that we should connect to and ask the
 * core to establish connections.
 */
static void
find_more_peers (void *cls,
		 const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Determine when we should try again to find more peers and
 * schedule the task.
 */
static void
schedule_peer_search ()
{
  struct GNUNET_TIME_Relative delay;

  /* Typically, we try again every 15 minutes; the minimum period is
     15s; if we are above the connection target, we reduce re-trying
     by the square of how much we are above; so for example, with 200%
     of the connection target we would only look for more peers once
     every hour (after all, we're quite busy processing twice as many
     connections as we intended to have); similarly, if we are at only
     25% of our connectivity goal, we will try 16x as hard to connect
     (so roughly once a minute, plus the 15s minimum delay */
  delay = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
					 15 + 15 * 60 * connection_count * connection_count / target_connection_count / target_connection_count);
  GNUNET_SCHEDULER_add_delayed (sched,
				GNUNET_NO,
				GNUNET_SCHEDULER_PRIORITY_DEFAULT,
				GNUNET_SCHEDULER_NO_TASK,
				delay,
				&find_more_peers,
				NULL);
}




/**
 * Iterator called on each address.
 *
 * @param cls flag that we will set if we see any addresses.
 */
static int
address_iterator (void *cls,
		  const char *tname,
		  struct GNUNET_TIME_Absolute expiration,
		  const void *addr, size_t addrlen)
{
  int *flag = cls;
  *flag = GNUNET_YES;
  return GNUNET_SYSERR;
}


/**
 * We've gotten a HELLO from another peer.
 * Consider it for advertising.
 */
static void
consider_for_advertising (const struct GNUNET_HELLO_Message *hello)
{
  int have_address;
  struct GNUNET_PeerIdentity pid;
  struct HelloList *pos;
  uint16_t size;

  have_address = GNUNET_NO;
  GNUNET_HELLO_iterate_addresses (hello,
				  GNUNET_NO,
				  &address_iterator,
				  &have_address);
  if (GNUNET_NO == have_address)
    return; /* no point in advertising this one... */
  GNUNET_HELLO_get_id (hello, &pid);
  pos = hellos;
  while (pos != NULL)
    {
      if (0 == memcmp (&pos->id,
		       &pid,
		       sizeof(struct GNUNET_PeerIdentity)))
	return; /* duplicate, at least "mostly" */
      pos = pos->next;
    }
  size = GNUNET_HELLO_size (hello);
  pos = GNUNET_malloc (sizeof(struct HelloList) + size);
  pos->msg = (struct GNUNET_HELLO_Message*) &pos[1];
  memcpy (&pos->msg, hello, size);
  pos->id = pid;
  pos->expiration = GNUNET_TIME_relative_to_absolute (HELLO_ADVERTISEMENT_MIN_FREQUENCY);
  /* 2^{-5} chance of not sending a HELLO to a peer is
     acceptably small (if the filter is 50% full);
     64 bytes of memory are small compared to the rest
     of the data structure and would only really become
     "useless" once a HELLO has been passed on to ~100
     other peers, which is likely more than enough in
     any case; hence 64, 5 as bloomfilter parameters. */
  pos->filter = GNUNET_CONTAINER_bloomfilter_load (NULL, 64, 5);
  /* never send a peer its own HELLO */
  GNUNET_CONTAINER_bloomfilter_add (pos->filter, &pos->id.hashPubKey);
  pos->next = hellos;
  hellos = pos;
}


/**
 * Peerinfo calls this function to let us know about a
 * possible peer that we might want to connect to.
 */
static void
process_peer (void *cls,
	      const struct GNUNET_PeerIdentity *peer,
	      const struct GNUNET_HELLO_Message *hello,
	      uint32_t trust)
{
  struct PeerList *pos;

  if (peer == NULL)
    {
      /* last call, schedule 'find_more_peers' again... */
      schedule_peer_search ();
      return;
    }
  if (hello == NULL)
    {
      /* no HELLO known; can not connect, ignore! */
      return;
    }
  if (0 == memcmp (&my_identity,
                   peer, sizeof (struct GNUNET_PeerIdentity)))
    return;  /* that's me! */

  consider_for_advertising (hello);
  pos = friends;
  while (pos != NULL)
    {
      if (0 == memcmp (&pos->id, peer, sizeof (struct GNUNET_PeerIdentity)))
	{
	  if (GNUNET_YES == pos->is_connected)
	    return;
	  if (GNUNET_TIME_absolute_get_remaining (pos->blacklisted_until).value > 0)
	    return; /* peer still blacklisted */
	  if (GNUNET_YES == pos->is_friend)
	    {
	      attempt_connect (peer, pos);
	      return;
	    }
	}
      pos = pos->next;
    }
  if (GNUNET_YES == friends_only)
    return;
  if (friend_count < minimum_friend_count)
    return;
  attempt_connect (peer, NULL);
}


/**
 * Try to add more friends to our connection set.
 */
static void
try_add_friends ()
{
  struct PeerList *pos;

  pos = friends;
  while (pos != NULL)
    {
      if ( (GNUNET_TIME_absolute_get_remaining (pos->blacklisted_until).value == 0) &&
	   (GNUNET_YES == pos->is_friend) &&
	   (GNUNET_YES != pos->is_connected) )
	attempt_connect (&pos->id, pos);
      pos = pos->next;
    }
}


/**
 * Discard peer entries for blacklisted peers
 * where the blacklisting has expired.
 */
static void
discard_old_blacklist_entries ()
{
  struct PeerList *pos;
  struct PeerList *next;
  struct PeerList *prev;

  next = friends;
  prev = NULL;
  while (NULL != (pos = next))
    {
      next = pos->next;
      if ( (GNUNET_NO == pos->is_friend) &&
	   (GNUNET_NO == pos->is_connected) &&
	   (0 == GNUNET_TIME_absolute_get_remaining (pos->blacklisted_until).value) )
	{
	  /* delete 'pos' from list */
	  if (prev == NULL)
	    friends = next;
	  else
	    prev->next = next;
	  GNUNET_free (pos);
	}
      else
	{
	  prev = pos;
	}
    }
}


/**
 * Find more peers that we should connect to and ask the
 * core to establish connections.
 */
static void
find_more_peers (void *cls,
		 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  discard_old_blacklist_entries ();
  if (target_connection_count <= connection_count)
    {
      schedule_peer_search ();
      return;
    }
  if ( (GNUNET_YES == friends_only) ||
       (friend_count < minimum_friend_count) )
    {
      try_add_friends ();
      schedule_peer_search ();
      return;
    }
  GNUNET_PEERINFO_for_all (cfg,
			   sched,
			   NULL,
			   0, GNUNET_TIME_UNIT_FOREVER_REL,
			   &process_peer, NULL);
}


/**
 * Function called after GNUNET_CORE_connect has succeeded
 * (or failed for good).
 *
 * @param cls closure
 * @param server handle to the server, NULL if we failed
 * @param my_id ID of this peer, NULL if we failed
 * @param publicKey public key of this peer, NULL if we failed
 */
static void
core_init (void *cls,
	   struct GNUNET_CORE_Handle * server,
	   const struct GNUNET_PeerIdentity *
	   my_id,
	   const struct
	   GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *
	   publicKey)
{
  if (server == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Failed to connect to core service, can not manage topology!\n"));
      return;
    }
  handle = server;
  my_identity = *my_id;
  if (autoconnect)
    GNUNET_SCHEDULER_add_delayed (sched,
				  GNUNET_NO,
				  GNUNET_SCHEDULER_PRIORITY_DEFAULT,
				  GNUNET_SCHEDULER_NO_TASK,
				  GNUNET_TIME_UNIT_SECONDS /* give core time to tell us about existing connections */,
				  &find_more_peers,
				  NULL);
}


/**
 * gnunet-daemon-topology command line options.
 */
static struct GNUNET_GETOPT_CommandLineOption options[] = {
  GNUNET_GETOPT_OPTION_END
};


/**
 * Read the friends file.
 */
static void
read_friends_file (struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char *fn;
  char *data;
  size_t pos;
  GNUNET_HashCode hc;
  struct stat frstat;
  struct GNUNET_CRYPTO_HashAsciiEncoded enc;
  unsigned int entries_found;
  struct PeerList *fl;

  fn = NULL;
  GNUNET_CONFIGURATION_get_value_filename (cfg,
					   "TOPOLOGY",
					   "FRIENDS",
					   &fn);
  if (GNUNET_OK != GNUNET_DISK_file_test (fn))
    GNUNET_DISK_fn_write (fn, NULL, 0, GNUNET_DISK_PERM_USER_READ
        | GNUNET_DISK_PERM_USER_WRITE);
  if (0 != STAT (fn, &frstat))
    {
      if ((friends_only) || (minimum_friend_count > 0))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		      _("Could not read friends list `%s'\n"), fn);
	  GNUNET_free (fn);
          return;
        }
    }
  if (frstat.st_size == 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Friends file `%s' is empty.\n"),
		  fn);
      GNUNET_free (fn);
      return;
    }
  data = GNUNET_malloc_large (frstat.st_size);
  if (frstat.st_size !=
      GNUNET_DISK_fn_read (fn, data, frstat.st_size))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Failed to read friends list from `%s'\n"), fn);
      GNUNET_free (fn);
      GNUNET_free (data);
      return;
    }
  entries_found = 0;
  pos = 0;
  while ((pos < frstat.st_size) && isspace (data[pos]))
    pos++;
  while ((frstat.st_size >= sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded)) &&
	 (pos <= frstat.st_size - sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded)))
    {
      memcpy (&enc, &data[pos], sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded));
      if (!isspace (enc.encoding[sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded) - 1]))
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		      _("Syntax error in topology specification at offset %llu, skipping bytes.\n"),
		      (unsigned long long) pos);
	  pos++;
	  while ((pos < frstat.st_size) && (!isspace (data[pos])))
	    pos++;
	  continue;
	}
      enc.encoding[sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded) - 1] = '\0';
      if (GNUNET_OK != GNUNET_CRYPTO_hash_from_string ((char *) &enc, &hc))
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		      _("Syntax error in topology specification at offset %llu, skipping bytes `%s'.\n"),
		      (unsigned long long) pos,
		      &enc);
	}
      else
	{
	  entries_found++;
	  fl = GNUNET_malloc (sizeof(struct PeerList));
	  fl->is_friend = GNUNET_YES;
	  fl->id.hashPubKey = hc;
	  fl->next = friends;
	  friends = fl;
	}
      pos = pos + sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded);
      while ((pos < frstat.st_size) && isspace (data[pos]))
	pos++;
    }
  GNUNET_free (data);
  GNUNET_free (fn);
  if ( (minimum_friend_count > entries_found) &&
       (friends_only == GNUNET_NO) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Fewer friends specified than required by minimum friend count. Will only connect to friends.\n"));
    }
  if ( (minimum_friend_count > target_connection_count) &&
       (friends_only == GNUNET_NO) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("More friendly connections required than target total number of connections.\n"));
    }
}


/**
 * This function is called whenever an encrypted HELLO message is
 * received.
 *
 * @param cls closure
 * @param peer the other peer involved (sender or receiver, NULL
 *        for loopback messages where we are both sender and receiver)
 * @param message the actual HELLO message
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_encrypted_hello (void *cls,
			const struct GNUNET_PeerIdentity * other,
			const struct GNUNET_MessageHeader *
			message)
{
  if (transport != NULL)
    GNUNET_TRANSPORT_offer_hello (transport,
				  message);
  return GNUNET_OK;
}


/**
 * Peerinfo calls this function to let us know about a
 * possible peer that we might want to connect to.
 */
static void
gather_hello_callback (void *cls,
		       const struct GNUNET_PeerIdentity *peer,
		       const struct GNUNET_HELLO_Message *hello,
		       uint32_t trust)
{
  if (peer == NULL)
    {
      hello_gathering_active = GNUNET_NO;
      return;
    }
  if (hello != NULL)
    consider_for_advertising (hello);
}


/**
 * Function to fill send buffer with HELLO.
 *
 * @param receiver the receiver of the message
 * @param position is the reference to the
 *        first unused position in the buffer where GNUnet is building
 *        the message
 * @param padding is the number of bytes left in that buffer.
 * @return the number of bytes written to
 *   that buffer (must be a positive number).
 */
static unsigned int
hello_advertising (void *cls,
		   const struct GNUNET_PeerIdentity *
		   receiver,
		   void *position, unsigned int padding)
{
  struct PeerList *pl;
  struct HelloList *pos;
  struct HelloList *prev;
  struct HelloList *next;
  uint16_t size;

  pl = friends;
  while (pl != NULL)
    {
      if (0 == memcmp (&pl->id, receiver, sizeof (struct GNUNET_PeerIdentity)))
	break;
      pl = pl->next;
    }
  if (pl == NULL)
    {
      GNUNET_break (0);
      return 0;
    }
  /* find applicable HELLOs */
  prev = NULL;
  next = hellos;
  while (NULL != (pos = next))
    {
      next = pos->next;
      if (GNUNET_NO ==
	  GNUNET_CONTAINER_bloomfilter_test (pos->filter,
					     &receiver->hashPubKey))
	break;
      if (0 == GNUNET_TIME_absolute_get_remaining (pos->expiration).value)
	{
	  /* time to discard... */
	  if (prev == NULL)
	    prev->next = next;
	  else
	    hellos = next;
	  GNUNET_CONTAINER_bloomfilter_free (pos->filter);
	  GNUNET_free (pos);
	}
      else
	{
	  prev = pos;
	}
    }
  if (pos != NULL)
    {
      size = GNUNET_HELLO_size (pos->msg);
      if (size < padding)
	{
	  memcpy (position, pos->msg, size);
	  GNUNET_CONTAINER_bloomfilter_add (pos->filter,
					    &receiver->hashPubKey);
	}
      else
	{
	  size = 0;
	}
      return size;
    }
  if ( (GNUNET_NO == hello_gathering_active) &&
       (GNUNET_TIME_absolute_get_duration (last_hello_gather_time).value >
	MIN_HELLO_GATHER_DELAY.value) )
    {
      hello_gathering_active = GNUNET_YES;
      last_hello_gather_time = GNUNET_TIME_absolute_get();
      GNUNET_PEERINFO_for_all (cfg,
			       sched,
			       NULL,
			       0, GNUNET_TIME_UNIT_FOREVER_REL,
			       &gather_hello_callback, NULL);
    }
  return 0;
}


/**
 * Last task run during shutdown.  Disconnects us from
 * the transport and core.
 */
static void
cleaning_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerList *pl;

  GNUNET_TRANSPORT_disconnect (transport);
  transport = NULL;
  GNUNET_CORE_disconnect (handle);
  handle = NULL;
  while (NULL != (pl = friends))
    {
      friends = pl->next;
      GNUNET_free (pl);
    }
}


/**
 * Main function that will be run.
 *
 * @param cls closure
 * @param s the scheduler to use
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param c configuration
 */
static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle * s,
     char *const *args,
     const char *cfgfile,
     struct GNUNET_CONFIGURATION_Handle * c)
{
  struct GNUNET_CORE_MessageHandler handlers[] =
    {
      { &handle_encrypted_hello, GNUNET_MESSAGE_TYPE_HELLO, 0},
      { NULL, 0, 0 }
    };
  unsigned long long opt;

  sched = s;
  cfg = c;
  autoconnect = GNUNET_CONFIGURATION_get_value_yesno (cfg,
						      "TOPOLOGY",
						      "AUTOCONNECT");
  friends_only = GNUNET_CONFIGURATION_get_value_yesno (cfg,
						       "TOPOLOGY",
						       "FRIENDS-ONLY");
  opt = 0;
  GNUNET_CONFIGURATION_get_value_number (cfg,
					 "TOPOLOGY",
					 "MINIMUM-FRIENDS",
					 &opt);
  minimum_friend_count = (unsigned int) opt;
  opt = 16;
  GNUNET_CONFIGURATION_get_value_number (cfg,
					 "TOPOLOGY",
					 "TARGET-CONNECTION-COUNT",
					 &opt);
  target_connection_count = (unsigned int) opt;

  if ( (friends_only == GNUNET_YES) ||
       (minimum_friend_count > 0) )
    read_friends_file (cfg);

  transport = GNUNET_TRANSPORT_connect (sched,
					cfg,
					NULL,
					NULL,
					NULL,
					NULL);
  GNUNET_CORE_connect (sched,
		       cfg,
		       GNUNET_TIME_UNIT_FOREVER_REL,
		       NULL,
		       &core_init,
		       &connect_notify,
		       &disconnect_notify,
		       &hello_advertising,
		       NULL, GNUNET_NO,
		       NULL, GNUNET_NO,
		       handlers);

  GNUNET_SCHEDULER_add_delayed (sched,
                                GNUNET_YES,
                                GNUNET_SCHEDULER_PRIORITY_IDLE,
                                GNUNET_SCHEDULER_NO_TASK,
                                GNUNET_TIME_UNIT_FOREVER_REL,
                                &cleaning_task, NULL);
}


/**
 * The main function for the topology daemon.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  int ret;

  ret = (GNUNET_OK ==
         GNUNET_PROGRAM_run (argc,
                             argv,
                             "topology",
			     _("GNUnet topology control (maintaining P2P mesh and F2F constraints)"),
			     options,
			     &run, NULL)) ? 0 : 1;
  return ret;
}

/* end of gnunet-daemon-topology.c */
