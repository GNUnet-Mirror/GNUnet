/*
     This file is part of GNUnet.
     (C) 2007, 2008, 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @brief code for maintaining the mesh topology
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
 * For how long do we blacklist a peer after a failed connection
 * attempt?
 */
#define BLACKLIST_AFTER_ATTEMPT GNUNET_TIME_UNIT_HOURS

/**
 * For how long do we blacklist a friend after a failed connection
 * attempt?
 */
#define BLACKLIST_AFTER_ATTEMPT_FRIEND GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 15)

/**
 * How often do we at most advertise any HELLO to a peer?
 */
#define HELLO_ADVERTISEMENT_MIN_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 4)

/**
 * How often do we at most advertise the same HELLO to the same peer?
 */
#define HELLO_ADVERTISEMENT_MIN_REPEAT_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 4)


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
   * Our handle for the request to transmit HELLOs to this peer; NULL
   * if no such request is pending.
   */
  struct GNUNET_CORE_TransmitHandle *hello_req;  

  /**
   * Our handle for the request to connect to this peer; NULL if no
   * such request is pending.
   */
  struct GNUNET_CORE_PeerRequestHandle *connect_req;  

  /**
   * Pointer to the HELLO message of this peer; can be NULL.
   */
  struct GNUNET_HELLO_Message *hello;

  /**
   * Bloom filter used to mark which peers already got the HELLO
   * from this peer.
   */
  struct GNUNET_CONTAINER_BloomFilter *filter;

  /**
   * Our request handle for *whitelisting* this peer (NULL if
   * no whitelisting request is pending).
   */
  struct GNUNET_TRANSPORT_BlacklistRequest *wh;

  /**
   * Is this peer listed here because he is a friend?
   */
  int is_friend;

  /**
   * Are we connected to this peer right now?
   */
  int is_connected;

  /**
   * Are we currently blocking this peer (via blacklist)?
   */
  int is_blocked;

  /**
   * Until what time should we not try to connect again
   * to this peer?
   */
  struct GNUNET_TIME_Absolute blacklisted_until;

  /**
   * Next time we are allowed to transmit a HELLO to this peer?
   */
  struct GNUNET_TIME_Absolute next_hello_allowed;

  /**
   * When should we reset the bloom filter of this entry?
   */
  struct GNUNET_TIME_Absolute filter_expiration;

  /**
   * ID of task we use to wait for the time to send the next HELLO
   * to this peer.
   */
  GNUNET_SCHEDULER_TaskIdentifier hello_delay_task;

  /**
   * ID of the peer.
   */
  struct GNUNET_PeerIdentity id;

};


/**
 * Entry in linked list of active 'disconnect' requests that we have issued.
 */
struct DisconnectList
{
  /**
   * This is a doubly-linked list.
   */
  struct DisconnectList *next;

  /**
   * This is a doubly-linked list.
   */
  struct DisconnectList *prev;
  
  /**
   * Our request handle.
   */
  struct GNUNET_TRANSPORT_BlacklistRequest *rh;
  
  /**
   * Peer we tried to disconnect.
   */
  struct GNUNET_PeerIdentity peer;

};


/**
 * Our peerinfo notification context.  We use notification
 * to instantly learn about new peers as they are discovered.
 */
static struct GNUNET_PEERINFO_NotifyContext *peerinfo_notify;

/**
 * Our scheduler.
 */
static struct GNUNET_SCHEDULER_Handle *sched;

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

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
 * Linked list of all of our friends, all of our current neighbours
 * and all peers for which we have HELLOs.  So pretty much everyone.
 */
static struct PeerList *peers;

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
 * Head of doubly-linked list of active 'disconnect' requests that we have issued.
 */
static struct DisconnectList *disconnect_head;

/**
 * Head of doubly-linked list of active 'disconnect' requests that we have issued.
 */
static struct DisconnectList *disconnect_tail;


/**
 * Function called once our request to 'disconnect' a peer
 * has completed.
 *
 * @param cls our 'struct DisconnectList'
 * @param tc unused
 */
static void
disconnect_done (void *cls,
		 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct DisconnectList *dl = cls;

  GNUNET_CONTAINER_DLL_remove (disconnect_head,
			       disconnect_tail,
			       dl);
  GNUNET_free (dl);
}


/**
 * Force a disconnect from the specified peer. 
 */
static void
force_disconnect (struct PeerList *pl)
{
  const struct GNUNET_PeerIdentity *peer = &pl->id;
  struct DisconnectList *dl;

  if (NULL != pl->wh)
    {
      GNUNET_TRANSPORT_blacklist_cancel (pl->wh);
      pl->wh = NULL;
    }
  pl->is_blocked = GNUNET_YES;
  dl = GNUNET_malloc (sizeof (struct DisconnectList));
  dl->peer = *peer;
  GNUNET_CONTAINER_DLL_insert (disconnect_head,
			       disconnect_tail,
			       dl);
  dl->rh = GNUNET_TRANSPORT_blacklist (sched, cfg,						
				       peer,
				       GNUNET_TIME_UNIT_FOREVER_REL,
				       GNUNET_TIME_UNIT_FOREVER_REL,
				       &disconnect_done,
				       dl);
}



/**
 * Function called once our request to 'whitelist' a peer
 * has completed.
 *
 * @param cls our 'struct PeerList'
 * @param tc unused
 */
static void
whitelist_done (void *cls,
		const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerList *pl = cls;

  pl->wh = NULL;
}


/**
 * Whitelist all peers that we blacklisted; we've passed
 * the minimum number of friends.
 */
static void
whitelist_peers ()
{
  struct PeerList *pl;
  struct DisconnectList *dl;

  /* first, cancel all blacklisting requests */
  while (NULL != (dl = disconnect_head))
    {
      GNUNET_CONTAINER_DLL_remove (disconnect_head,
				   disconnect_tail,
				   dl);
      GNUNET_TRANSPORT_blacklist_cancel (dl->rh);
      GNUNET_free (dl);
    }
  /* then, specifically whitelist all peers that we
     know to have blacklisted */
  pl = peers;
  while (pl != NULL)
    {
      if (pl->is_blocked)
	{
	  pl->wh = GNUNET_TRANSPORT_blacklist (sched, cfg,						
					       &pl->id,
					       GNUNET_TIME_UNIT_ZERO,
					       GNUNET_TIME_UNIT_FOREVER_REL,
					       &whitelist_done,
					       pl);
	  pl->is_blocked = GNUNET_NO;
	}
      pl = pl->next;
    }
}


/**
 * Function called by core when our attempt to connect succeeded.
 */
static void
connect_completed_callback (void *cls,
			    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerList *pos = cls;

  pos->connect_req = NULL;
}


/**
 * Try to connect to the specified peer.
 *
 * @param pos peer to connect to
 */
static void
attempt_connect (struct PeerList *pos)
{
  if (GNUNET_YES == pos->is_friend)
    pos->blacklisted_until = GNUNET_TIME_relative_to_absolute (BLACKLIST_AFTER_ATTEMPT_FRIEND);
  else
    pos->blacklisted_until = GNUNET_TIME_relative_to_absolute (BLACKLIST_AFTER_ATTEMPT);
#if DEBUG_TOPOLOGY
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Asking core to connect to `%s'\n",
	      GNUNET_i2s (&pos->id));
#endif
  pos->connect_req = GNUNET_CORE_peer_request_connect (sched, cfg,
						       GNUNET_TIME_UNIT_MINUTES,
						       &pos->id,
						       &connect_completed_callback,
						       pos);
}


/**
 * Find a peer in our linked list.  
 * FIXME: should probably use a hash map instead.
 */
struct PeerList *
find_peer (const struct GNUNET_PeerIdentity * peer)
{
  struct PeerList *pos;

  pos = peers;
  while (pos != NULL)
    {
      if (0 == memcmp (&pos->id, peer, sizeof (struct GNUNET_PeerIdentity)))
	return pos;
      pos = pos->next;
    }
  return NULL;
}


/**
 * Check if an additional connection from the given peer is allowed.
 */
static int
is_connection_allowed (struct PeerList *peer)
{
  if (0 == memcmp (&my_identity, &peer->id, sizeof (struct GNUNET_PeerIdentity)))
    return GNUNET_SYSERR;       /* disallow connections to self */
  if (peer->is_friend)
    return GNUNET_OK;
  if (GNUNET_YES == friends_only)
    {
#if DEBUG_TOPOLOGY
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Determined that `%s' is not allowed to connect (not a friend)\n",
		  GNUNET_i2s (&peer->id));
#endif       
      return GNUNET_SYSERR;
    }
  if (friend_count >= minimum_friend_count)
    return GNUNET_OK;
#if DEBUG_TOPOLOGY
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Determined that `%s' is not allowed to connect (not enough connected friends)\n",
	      GNUNET_i2s (&peer->id));
#endif       
  return GNUNET_SYSERR;
}


/**
 * Create a new entry in the peer list.
 *
 * @param peer identity of the new entry
 * @param hello hello message, can be NULL
 * @param is_friend is the new entry for a friend?
 * @return the new entry
 */
static struct PeerList *
make_peer (const struct
	   GNUNET_PeerIdentity * peer,
	   const struct GNUNET_HELLO_Message *hello,
	   int is_friend)
{
  struct PeerList *ret;
  
  ret = GNUNET_malloc (sizeof (struct PeerList));
  ret->id = *peer;
  ret->is_friend = is_friend;
  if (hello != NULL)
    {
      ret->hello = GNUNET_malloc (GNUNET_HELLO_size (hello));
      memcpy (ret->hello, hello,
	      GNUNET_HELLO_size (hello));
    }
  ret->next = peers;
  peers = ret;
  return ret;
}


/**
 * Free all resources associated with the given peer.
 *
 * @param peer peer to free
 */
static void
free_peer (struct PeerList *peer)
{
  struct PeerList *pos;
  struct PeerList *prev;
  
  prev = NULL;
  pos = peers;
  while (peer != pos)
    {
      prev = pos;
      pos = pos->next;
    }
  GNUNET_assert (pos != NULL);
   if (prev == NULL)
     peers = pos->next;
   else
     prev->next = pos->next;
   if (pos->hello_req != NULL)
     GNUNET_CORE_notify_transmit_ready_cancel (pos->hello_req);
   if (pos->wh != NULL)
     GNUNET_TRANSPORT_blacklist_cancel (pos->wh);
   if (pos->connect_req != NULL)
     GNUNET_CORE_peer_request_connect_cancel (pos->connect_req);	      
   if (pos->hello_delay_task != GNUNET_SCHEDULER_NO_TASK)
     GNUNET_SCHEDULER_cancel (sched,
			      pos->hello_delay_task);
   GNUNET_free_non_null (pos->hello);   
   if (pos->filter != NULL)
     GNUNET_CONTAINER_bloomfilter_free (peer->filter);
   GNUNET_free (pos);
}


/**
 * Setup bloom filter for the given peer entry.
 *
 * @param peer entry to initialize
 */
static void
setup_filter (struct PeerList *peer)
{
  /* 2^{-5} chance of not sending a HELLO to a peer is
     acceptably small (if the filter is 50% full);
     64 bytes of memory are small compared to the rest
     of the data structure and would only really become
     "useless" once a HELLO has been passed on to ~100
     other peers, which is likely more than enough in
     any case; hence 64, 5 as bloomfilter parameters. */
  peer->filter = GNUNET_CONTAINER_bloomfilter_load (NULL, 64, 5);
  peer->filter_expiration = GNUNET_TIME_relative_to_absolute (HELLO_ADVERTISEMENT_MIN_REPEAT_FREQUENCY);
  /* never send a peer its own HELLO */
  GNUNET_CONTAINER_bloomfilter_add (peer->filter, &peer->id.hashPubKey);
}


/**
 * Function to fill send buffer with HELLO.
 *
 * @param cls 'struct PeerList' of the target peer
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
hello_advertising_ready (void *cls,
			 size_t size,
			 void *buf);


/**
 * Calculate when we would like to send the next HELLO to this
 * peer and ask for it.
 *
 * @param cls for which peer to schedule the HELLO
 * @param tc task context
 */
static void
schedule_next_hello (void *cls,
		     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerList *pl = cls;
  struct PeerList *pos;
  struct PeerList *next;
  uint16_t next_want;
  struct GNUNET_TIME_Relative next_adv;
  struct GNUNET_TIME_Relative rst_time;
  
  pl->hello_delay_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return; /* we're out of here */
  next_want = 0;
  next_adv = GNUNET_TIME_UNIT_FOREVER_REL;
  /* find applicable HELLOs */
  next = peers;
  while (NULL != (pos = next))
    {
      next = pos->next;
      if (pos->hello == NULL)
	continue;
      rst_time = GNUNET_TIME_absolute_get_remaining (pos->filter_expiration);
      if (0 == rst_time.value)
	{
	  /* time to discard... */
	  GNUNET_CONTAINER_bloomfilter_free (pos->filter);
	  setup_filter (pos);
	}
      else
	{
	  if (rst_time.value < next_adv.value)
	    next_want = GNUNET_HELLO_size (pos->hello);
	  next_adv = GNUNET_TIME_relative_min (rst_time,
					       next_adv);	  
	}
      if (GNUNET_NO ==
	  GNUNET_CONTAINER_bloomfilter_test (pos->filter,
					     &pl->id.hashPubKey))
	break;
    }
  if (pos != NULL)  
    next_adv = GNUNET_TIME_absolute_get_remaining (pl->next_hello_allowed);
  if (next_adv.value == 0)
    {
      /* now! */
      pl->hello_req = GNUNET_CORE_notify_transmit_ready (handle, 0,
							 next_adv,
							 &pl->id,
							 next_want,
							 &hello_advertising_ready,
							 pl);
      return;
    }
  pl->hello_delay_task 
    = GNUNET_SCHEDULER_add_delayed (sched,
				    next_adv,
				    &schedule_next_hello,
				    pl);
}


/**
 * Cancel existing requests for sending HELLOs to this peer
 * and recalculate when we should send HELLOs to it based
 * on our current state (something changed!).
 */
static void
reschedule_hellos (struct PeerList *peer)
{
  if (peer->hello_req != NULL)
    {
      GNUNET_CORE_notify_transmit_ready_cancel (peer->hello_req);
      peer->hello_req = NULL;
    }
   if (peer->hello_delay_task != GNUNET_SCHEDULER_NO_TASK)
     {
       GNUNET_SCHEDULER_cancel (sched,
				peer->hello_delay_task);
       peer->hello_delay_task = GNUNET_SCHEDULER_NO_TASK;
     }
   peer->hello_delay_task 
     = GNUNET_SCHEDULER_add_now (sched,
				 &schedule_next_hello,
				 peer);
}


/**
 * Method called whenever a peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param latency reported latency of the connection with 'other'
 * @param distance reported distance (DV) to 'other' 
 */
static void 
connect_notify (void *cls,
		const struct
		GNUNET_PeerIdentity * peer,
		struct GNUNET_TIME_Relative latency,
		uint32_t distance)
{
  struct PeerList *pos;

#if DEBUG_TOPOLOGY
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Core told us that we are connecting to `%s'\n",
	      GNUNET_i2s (peer));
#endif
  connection_count++;
  pos = find_peer (peer);
  if (pos == NULL)    
    {
      pos = make_peer (peer, NULL, GNUNET_NO);
      if (GNUNET_OK != is_connection_allowed (pos))
	{
	  GNUNET_assert (pos->is_friend == GNUNET_NO);
	  pos->is_connected = GNUNET_YES;
#if DEBUG_TOPOLOGY
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Connection to `%s' is forbidden, forcing disconnect!\n",
		      GNUNET_i2s (peer));
#endif       
	  force_disconnect (pos);
	  return;
	}
    }
  else
    {
      GNUNET_assert (GNUNET_NO == pos->is_connected);
      pos->blacklisted_until.value = 0; /* remove blacklisting */
    }
  pos->is_connected = GNUNET_YES;
  if (pos->is_friend)
    {
      if ( (friend_count == minimum_friend_count - 1) &&
	   (GNUNET_YES != friends_only) )	
	whitelist_peers ();       
      friend_count++;
    }
  reschedule_hellos (pos);
}


/**
 * Disconnect from all non-friends (we're below quota).
 */
static void
drop_non_friends ()
{
  struct PeerList *pos;

  pos = peers;
  while (pos != NULL)
    {
      if ( (GNUNET_NO == pos->is_friend) &&
	   (GNUNET_YES == pos->is_connected) )
	{
#if DEBUG_TOPOLOGY
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Connection to `%s' is not from a friend, forcing disconnect!\n",
		      GNUNET_i2s (&pos->id));
#endif       
	  force_disconnect (pos);
	}
      pos = pos->next;
    }
}


/**
 * Try to add more peers to our connection set.
 */
static void
try_add_peers ()
{
  struct PeerList *pos;

  pos = peers;
  while (pos != NULL)
    {
      if ( (GNUNET_TIME_absolute_get_remaining (pos->blacklisted_until).value == 0) &&
	   ( (GNUNET_YES == pos->is_friend) ||
	     (friend_count >= minimum_friend_count) ) &&
	   (GNUNET_YES != pos->is_connected) )
	attempt_connect (pos);
      pos = pos->next;
    }
}


/**
 * Method called whenever a peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void 
disconnect_notify (void *cls,
		   const struct
		   GNUNET_PeerIdentity * peer)
{
  struct PeerList *pos;
 
#if DEBUG_TOPOLOGY
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Core told us that we disconnected from `%s'\n",
	      GNUNET_i2s (peer));
#endif       
  pos = find_peer (peer);
  if (pos == NULL)
    {
      GNUNET_break (0);
      return;
    }
  if (pos->is_connected != GNUNET_YES)
    {
      GNUNET_break (0);
      return;
    }
  connection_count--;
  if (pos->is_friend)
    friend_count--; 
  if ( (connection_count < target_connection_count) ||
       (friend_count < minimum_friend_count) )
    try_add_peers ();   
  if (friend_count < minimum_friend_count)
    {
      /* disconnect from all non-friends */
#if DEBUG_TOPOLOGY
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Not enough friendly connections, dropping all non-friend connections\n");
#endif       
      drop_non_friends ();
    }
}


/**
 * Iterator called on each address.
 *
 * @param cls flag that we will set if we see any addresses
 * @param tname name of the transport
 * @param expiration when will the given address expire
 * @param addr the address of the peer
 * @param addrlen number of bytes in addr
 * @return GNUNET_SYSERR always, to terminate iteration
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
 * We've gotten a HELLO from another peer.  Consider it for
 * advertising.
 */
static void
consider_for_advertising (const struct GNUNET_HELLO_Message *hello)
{
  int have_address;
  struct GNUNET_PeerIdentity pid;
  struct PeerList *peer;
  struct PeerList *pos;
  uint16_t size;

  GNUNET_break (GNUNET_OK == GNUNET_HELLO_get_id (hello, &pid));
  if (0 == memcmp (&pid,
		   &my_identity,
		   sizeof (struct GNUNET_PeerIdentity)))
    return; /* that's me! */
  have_address = GNUNET_NO;
  GNUNET_HELLO_iterate_addresses (hello,
				  GNUNET_NO,
				  &address_iterator,
				  &have_address);
  if (GNUNET_NO == have_address)
    return; /* no point in advertising this one... */
  peer = find_peer (&pid);
  if (peer == NULL)
    peer = make_peer (&pid, hello, GNUNET_NO);
  // FIXME: check if 'hello' is any different from peer->hello?
#if DEBUG_TOPOLOGY
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Found `%s' from peer `%s' for advertising\n",
	      "HELLO",
	      GNUNET_i2s (&pid));
#endif 
  size = GNUNET_HELLO_size (hello);
  GNUNET_free_non_null (peer->hello);
  peer->hello = GNUNET_malloc (size);
  memcpy (peer->hello, hello, size);
  if (peer->filter != NULL)
    GNUNET_CONTAINER_bloomfilter_free (peer->filter);
  setup_filter (peer);
  /* since we have a new HELLO to pick from, re-schedule all
     HELLO requests that are not bound by the HELLO send rate! */
  pos = peers;
  while (NULL != pos)
    {
      if (pos != peer)	
	{
	  if ( (pos->is_connected) &&
	       (GNUNET_TIME_absolute_get_remaining (pos->next_hello_allowed).value <= HELLO_ADVERTISEMENT_MIN_FREQUENCY.value) )
	    reschedule_hellos (pos);	
	}
      pos = pos->next;
    }
}


/**
 * Peerinfo calls this function to let us know about a possible peer
 * that we might want to connect to.
 */
static void
process_peer (void *cls,
	      const struct GNUNET_PeerIdentity *peer,
	      const struct GNUNET_HELLO_Message *hello,
	      uint32_t trust)
{
  struct PeerList *pos;

  GNUNET_assert (peer != NULL);
  if (0 == memcmp (&my_identity,
                   peer, sizeof (struct GNUNET_PeerIdentity)))
    return;  /* that's me! */
  if (hello == NULL)
    {
      /* free existing HELLO, if any */
      if (NULL != (pos = find_peer (peer)))
	{
	  GNUNET_free_non_null (pos->hello);
	  pos->hello = NULL;
	  if (pos->filter != NULL)
	    {
	      GNUNET_CONTAINER_bloomfilter_free (pos->filter);
	      pos->filter = NULL;
	    }
	  if ( (! pos->is_connected) &&
	       (! pos->is_friend) &&
	       (0 == GNUNET_TIME_absolute_get_remaining (pos->blacklisted_until).value) )
	    free_peer (pos);
	}
      return;
    }
  consider_for_advertising (hello);
  pos = find_peer (peer);  
  if (pos == NULL)
    pos = make_peer (peer, hello, GNUNET_NO);
  GNUNET_assert (NULL != pos);
#if DEBUG_TOPOLOGY
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Considering connecting to peer `%s'\n",
	      GNUNET_i2s (peer));
#endif 
  if (GNUNET_YES == pos->is_connected)
    {
#if DEBUG_TOPOLOGY
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Already connected to peer `%s'\n",
		  GNUNET_i2s (peer));
#endif 
      return;
    }
  if (GNUNET_TIME_absolute_get_remaining (pos->blacklisted_until).value > 0)
    {
#if DEBUG_TOPOLOGY
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Already tried peer `%s' recently\n",
		  GNUNET_i2s (peer));
#endif 
      return; /* peer still blacklisted */
    }
  if ( (GNUNET_YES == pos->is_friend) ||
       (GNUNET_YES != friends_only) ||    
       (friend_count >= minimum_friend_count) )
    attempt_connect (pos);
}


/**
 * Discard peer entries for blacklisted peers
 * where the blacklisting has expired.
 */
static void
discard_old_blacklist_entries (void *cls,
			       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerList *pos;
  struct PeerList *next;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  next = peers;
  while (NULL != (pos = next))
    {
      next = pos->next;
      if ( (GNUNET_NO == pos->is_friend) &&
	   (GNUNET_NO == pos->is_connected) &&
	   (GNUNET_NO == pos->is_blocked) &&
	   (0 == GNUNET_TIME_absolute_get_remaining (pos->blacklisted_until).value) )
	free_peer (pos);
    }
  GNUNET_SCHEDULER_add_delayed (sched,
				BLACKLIST_AFTER_ATTEMPT,
				&discard_old_blacklist_entries,
				NULL);
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
      GNUNET_SCHEDULER_shutdown (sched);
      return;
    }
  handle = server;
  my_identity = *my_id;
#if DEBUG_TOPOLOGY
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "I am peer `%s'\n",
	      GNUNET_i2s (my_id));
#endif 	
  GNUNET_SCHEDULER_add_delayed (sched,
				BLACKLIST_AFTER_ATTEMPT,
				&discard_old_blacklist_entries,
				NULL);
}


/**
 * Read the friends file.
 */
static void
read_friends_file (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  char *fn;
  char *data;
  size_t pos;
  struct GNUNET_PeerIdentity pid;
  struct stat frstat;
  struct GNUNET_CRYPTO_HashAsciiEncoded enc;
  unsigned int entries_found;
  struct PeerList *fl;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg,
					       "TOPOLOGY",
					       "FRIENDS",
					       &fn))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Option `%s' in section `%s' not specified!\n"),
		  "FRIENDS",
		  "TOPOLOGY");
      return;
    }
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
      if (GNUNET_OK != GNUNET_CRYPTO_hash_from_string ((char *) &enc, &pid.hashPubKey))
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		      _("Syntax error in topology specification at offset %llu, skipping bytes `%s'.\n"),
		      (unsigned long long) pos,
		      &enc);
	}
      else
	{
	  if (0 != memcmp (&pid,
			   &my_identity,
			   sizeof (struct GNUNET_PeerIdentity)))
	    {
	      entries_found++;
	      fl = make_peer (&pid,
			      NULL,
			      GNUNET_YES);
	      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
			  _("Found friend `%s' in configuration\n"),
			  GNUNET_i2s (&fl->id));
	    }
	  else
	    {
	      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
			  _("Found myself `%s' in friend list (useless, ignored)\n"),
			  GNUNET_i2s (&pid));
	    }
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
 * @param other the other peer involved (sender or receiver, NULL
 *        for loopback messages where we are both sender and receiver)
 * @param message the actual HELLO message
 * @param latency reported latency of the connection with 'other'
 * @param distance reported distance (DV) to 'other' 
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_encrypted_hello (void *cls,
			const struct GNUNET_PeerIdentity * other,
			const struct GNUNET_MessageHeader *
			message,
			struct GNUNET_TIME_Relative latency,
			uint32_t distance)
{
#if DEBUG_TOPOLOGY
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received encrypted `%s' from peer `%s'",
	      "HELLO",
	      GNUNET_i2s (other));
#endif 	
  if (transport != NULL)
    GNUNET_TRANSPORT_offer_hello (transport,
				  message);
  return GNUNET_OK;
}


/**
 * Function to fill send buffer with HELLO.
 *
 * @param cls 'struct PeerList' of the target peer
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
hello_advertising_ready (void *cls,
			 size_t size,
			 void *buf)
{
  struct PeerList *pl = cls;
  struct PeerList *pos; 
  struct PeerList *next;
  uint16_t want;
  size_t hs;

  pl->hello_req = NULL;
#if DEBUG_TOPOLOGY
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Data solicited for `%s', considering sending `%s'",
	      GNUNET_i2s (&pl->id),
	      "HELLO");
#endif 	
  /* find applicable HELLOs */
  next = peers;
  while (NULL != (pos = next))
    {
      next = pos->next;
      if (pos->hello == NULL)
	continue;
      if (0 == GNUNET_TIME_absolute_get_remaining (pos->filter_expiration).value)
	{
	  /* time to discard... */
	  GNUNET_CONTAINER_bloomfilter_free (pos->filter);
	  setup_filter (pos);
	}
      if (GNUNET_NO ==
	  GNUNET_CONTAINER_bloomfilter_test (pos->filter,
					     &pl->id.hashPubKey))
	break;
    }
  want = 0;
  if (pos != NULL)
    {
      hs = GNUNET_HELLO_size (pos->hello);
      if (hs < size)
	{
	  want = hs;
	  memcpy (buf, pos->hello, want);
	  GNUNET_CONTAINER_bloomfilter_add (pos->filter,
					    &pl->id.hashPubKey);
#if DEBUG_TOPOLOGY
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		      "Sending %u bytes of `%s's",
		      (unsigned int) want,
		      "HELLO");
#endif 	
	}
    }
  pl->next_hello_allowed = GNUNET_TIME_relative_to_absolute (HELLO_ADVERTISEMENT_MIN_FREQUENCY);
  pl->hello_delay_task 
    = GNUNET_SCHEDULER_add_now (sched,
				&schedule_next_hello,
				pl);
  return want;
}


/**
 * Last task run during shutdown.  Disconnects us from
 * the transport and core.
 */
static void
cleaning_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct DisconnectList *dl;

  if (NULL != peerinfo_notify)
    {
      GNUNET_PEERINFO_notify_cancel (peerinfo_notify);
      peerinfo_notify = NULL;
    }
  GNUNET_TRANSPORT_disconnect (transport);
  transport = NULL;
  while (NULL != peers)
    free_peer (peers);     
  if (handle != NULL)
    {
      GNUNET_CORE_disconnect (handle);
      handle = NULL;
    }
  while (NULL != (dl = disconnect_head))
    {
      GNUNET_CONTAINER_DLL_remove (disconnect_head,
				   disconnect_tail,
				   dl);
      GNUNET_TRANSPORT_blacklist_cancel (dl->rh);
      GNUNET_free (dl);
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
     const struct GNUNET_CONFIGURATION_Handle * c)
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
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg,
					     "TOPOLOGY",
					     "MINIMUM-FRIENDS",
					     &opt))
    opt = 0;
  minimum_friend_count = (unsigned int) opt;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg,
					     "TOPOLOGY",
					     "TARGET-CONNECTION-COUNT",
					     &opt))
    opt = 16;
  target_connection_count = (unsigned int) opt;

  if ( (friends_only == GNUNET_YES) ||
       (minimum_friend_count > 0) )
    read_friends_file (cfg);
#if DEBUG_TOPOLOGY
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Topology would like %u connections with at least %u friends (%s)\n",
	      target_connection_count,
	      minimum_friend_count,
	      autoconnect ? "autoconnect enabled" : "autoconnect disabled");
#endif       
  transport = GNUNET_TRANSPORT_connect (sched,
					cfg,
					NULL,
					NULL,
					NULL,
					NULL);
  handle = GNUNET_CORE_connect (sched,
				cfg,
				GNUNET_TIME_UNIT_FOREVER_REL,
				NULL,
				&core_init,
				NULL,
				&connect_notify,
				&disconnect_notify,
				NULL, GNUNET_NO,
				NULL, GNUNET_NO,
				handlers);
  GNUNET_SCHEDULER_add_delayed (sched,
                                GNUNET_TIME_UNIT_FOREVER_REL,
                                &cleaning_task, NULL);
  if (NULL == transport)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Failed to connect to `%s' service.\n"),
		  "transport");
      GNUNET_SCHEDULER_shutdown (sched);
      return;
    }
  if (NULL == handle)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Failed to connect to `%s' service.\n"),
		  "core");
      GNUNET_SCHEDULER_shutdown (sched);
      return;
    }
  peerinfo_notify = GNUNET_PEERINFO_notify (cfg, sched,
					    &process_peer,
					    NULL);
}


/**
 * gnunet-daemon-topology command line options.
 */
static struct GNUNET_GETOPT_CommandLineOption options[] = {
  GNUNET_GETOPT_OPTION_END
};


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
