/*
     This file is part of GNUnet.
     Copyright (C) 2007-2016 GNUnet e.V.

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
*/

/**
 * @file topology/gnunet-daemon-topology.c
 * @brief code for maintaining the overlay topology
 * @author Christian Grothoff
 *
 * This daemon combines three functions:
 * - suggesting to ATS which peers we might want to connect to
 * - enforcing the F2F restrictions (by blacklisting)
 * - gossping HELLOs
 *
 * All three require similar information (who are our friends
 * impacts connectivity suggestions; connectivity suggestions
 * should consider blacklisting; connectivity suggestions
 * should consider available/known HELLOs; gossip requires
 * connectivity data; connectivity suggestions require
 * connectivity data), which is why they are combined in this
 * program.
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_friends_lib.h"
#include "gnunet_constants.h"
#include "gnunet_core_service.h"
#include "gnunet_protocols.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_ats_service.h"


/**
 * At what frequency do we sent HELLOs to a peer?
 */
#define HELLO_ADVERTISEMENT_MIN_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 5)

/**
 * After what time period do we expire the HELLO Bloom filter?
 */
#define HELLO_ADVERTISEMENT_MIN_REPEAT_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 4)


/**
 * Record for neighbours, friends and blacklisted peers.
 */
struct Peer
{
  /**
   * Which peer is this entry about?
   */
  struct GNUNET_PeerIdentity pid;

  /**
   * Our handle for transmitting to this peer; NULL
   * if peer is not connected.
   */
  struct GNUNET_MQ_Handle *mq;

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
  struct GNUNET_SCHEDULER_Task *hello_delay_task;

  /**
   * Handle for our connectivity suggestion for this peer.
   */
  struct GNUNET_ATS_ConnectivitySuggestHandle *sh;

  /**
   * How much would we like to connect to this peer?
   */
  uint32_t strength;

  /**
   * Is this peer listed here because it is a friend?
   */
  int is_friend;

};


/**
 * Our peerinfo notification context.  We use notification
 * to instantly learn about new peers as they are discovered.
 */
static struct GNUNET_PEERINFO_NotifyContext *peerinfo_notify;

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to the CORE service.
 */
static struct GNUNET_CORE_Handle *handle;

/**
 * Handle to the PEERINFO service.
 */
static struct GNUNET_PEERINFO_Handle *pi;

/**
 * Handle to the ATS service.
 */
static struct GNUNET_ATS_ConnectivityHandle *ats;

/**
 * Identity of this peer.
 */
static struct GNUNET_PeerIdentity my_identity;

/**
 * All of our friends, all of our current neighbours and all peers for
 * which we have HELLOs.  So pretty much everyone.  Maps peer identities
 * to `struct Peer *` values.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *peers;

/**
 * Handle for reporting statistics.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Blacklist (NULL if we have none).
 */
static struct GNUNET_TRANSPORT_Blacklist *blacklist;

/**
 * Task scheduled to asynchronously reconsider adding/removing
 * peer connectivity suggestions.
 */
static struct GNUNET_SCHEDULER_Task *add_task;

/**
 * Active HELLO offering to transport service.
 */
static struct GNUNET_TRANSPORT_OfferHelloHandle *oh;

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
 * Function that decides if a connection is acceptable or not.
 * If we have a blacklist, only friends are allowed, so the check
 * is rather simple.
 *
 * @param cls closure
 * @param pid peer to approve or disapprove
 * @return #GNUNET_OK if the connection is allowed
 */
static int
blacklist_check (void *cls,
                 const struct GNUNET_PeerIdentity *pid)
{
  struct Peer *pos;

  pos = GNUNET_CONTAINER_multipeermap_get (peers,
                                           pid);
  if ( (NULL != pos) &&
       (GNUNET_YES == pos->is_friend))
    return GNUNET_OK;
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# peers blacklisted"),
                            1,
                            GNUNET_NO);
  return GNUNET_SYSERR;
}


/**
 * Whitelist all peers that we blacklisted; we've passed
 * the minimum number of friends.
 */
static void
whitelist_peers ()
{
  if (NULL != blacklist)
  {
    GNUNET_TRANSPORT_blacklist_cancel (blacklist);
    blacklist = NULL;
  }
}


/**
 * Free all resources associated with the given peer.
 *
 * @param cls closure (not used)
 * @param pid identity of the peer
 * @param value peer to free
 * @return #GNUNET_YES (always: continue to iterate)
 */
static int
free_peer (void *cls,
           const struct GNUNET_PeerIdentity * pid,
           void *value)
{
  struct Peer *pos = value;

  GNUNET_break (NULL == pos->mq);
  GNUNET_break (GNUNET_OK ==
                GNUNET_CONTAINER_multipeermap_remove (peers,
                                                      pid,
                                                      pos));
  if (NULL != pos->hello_delay_task)
  {
    GNUNET_SCHEDULER_cancel (pos->hello_delay_task);
    pos->hello_delay_task = NULL;
  }
  if (NULL != pos->sh)
  {
    GNUNET_ATS_connectivity_suggest_cancel (pos->sh);
    pos->sh = NULL;
  }
  if (NULL != pos->hello)
  {
    GNUNET_free_non_null (pos->hello);
    pos->hello = NULL;
  }
  if (NULL != pos->filter)
  {
    GNUNET_CONTAINER_bloomfilter_free (pos->filter);
    pos->filter = NULL;
  }
  GNUNET_free (pos);
  return GNUNET_YES;
}


/**
 * Recalculate how much we want to be connected to the specified peer
 * and let ATS know about the result.
 *
 * @param pos peer to consider connecting to
 */
static void
attempt_connect (struct Peer *pos)
{
  uint32_t strength;

  if (0 ==
      memcmp (&my_identity,
              &pos->pid,
              sizeof (struct GNUNET_PeerIdentity)))
    return; /* This is myself, nothing to do. */
  if (connection_count < target_connection_count)
    strength = 1;
  else
    strength = 0;
  if ( (friend_count < minimum_friend_count) ||
       (GNUNET_YES == friends_only) )
  {
    if (pos->is_friend)
      strength += 10; /* urgently needed */
    else
      strength = 0; /* disallowed */
  }
  if (pos->is_friend)
    strength *= 2; /* friends always count more */
  if (NULL != pos->mq)
    strength *= 2; /* existing connections preferred */
  if (strength == pos->strength)
    return; /* nothing to do */
  if (NULL != pos->sh)
  {
    GNUNET_ATS_connectivity_suggest_cancel (pos->sh);
    pos->sh = NULL;
  }
  pos->strength = strength;
  if (0 != strength)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Asking to connect to `%s' with strength %u\n",
                GNUNET_i2s (&pos->pid),
                (unsigned int) strength);
    GNUNET_STATISTICS_update (stats,
                              gettext_noop ("# connect requests issued to ATS"),
                              1,
                              GNUNET_NO);
    pos->sh = GNUNET_ATS_connectivity_suggest (ats,
                                               &pos->pid,
                                               strength);
  }
}


/**
 * Create a new entry in the peer list.
 *
 * @param peer identity of the new entry
 * @param hello hello message, can be NULL
 * @param is_friend is the new entry for a friend?
 * @return the new entry
 */
static struct Peer *
make_peer (const struct GNUNET_PeerIdentity *peer,
           const struct GNUNET_HELLO_Message *hello,
           int is_friend)
{
  struct Peer *ret;

  ret = GNUNET_new (struct Peer);
  ret->pid = *peer;
  ret->is_friend = is_friend;
  if (NULL != hello)
  {
    ret->hello = GNUNET_malloc (GNUNET_HELLO_size (hello));
    GNUNET_memcpy (ret->hello,
		   hello,
		   GNUNET_HELLO_size (hello));
  }
  GNUNET_break (GNUNET_OK ==
                GNUNET_CONTAINER_multipeermap_put (peers,
                                                   peer,
                                                   ret,
                                                   GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  return ret;
}


/**
 * Setup bloom filter for the given peer entry.
 *
 * @param peer entry to initialize
 */
static void
setup_filter (struct Peer *peer)
{
  struct GNUNET_HashCode hc;

  /* 2^{-5} chance of not sending a HELLO to a peer is
   * acceptably small (if the filter is 50% full);
   * 64 bytes of memory are small compared to the rest
   * of the data structure and would only really become
   * "useless" once a HELLO has been passed on to ~100
   * other peers, which is likely more than enough in
   * any case; hence 64, 5 as bloomfilter parameters. */
  peer->filter = GNUNET_CONTAINER_bloomfilter_init (NULL, 64, 5);
  peer->filter_expiration =
      GNUNET_TIME_relative_to_absolute
      (HELLO_ADVERTISEMENT_MIN_REPEAT_FREQUENCY);
  /* never send a peer its own HELLO */
  GNUNET_CRYPTO_hash (&peer->pid,
                      sizeof (struct GNUNET_PeerIdentity),
                      &hc);
  GNUNET_CONTAINER_bloomfilter_add (peer->filter, &hc);
}


/**
 * Closure for #find_advertisable_hello().
 */
struct FindAdvHelloContext
{

  /**
   * Peer we want to advertise to.
   */
  struct Peer *peer;

  /**
   * Where to store the result (peer selected for advertising).
   */
  struct Peer *result;

  /**
   * Maximum HELLO size we can use right now.
   */
  size_t max_size;

  struct GNUNET_TIME_Relative next_adv;
};


/**
 * Find a peer that would be reasonable for advertising.
 *
 * @param cls closure
 * @param pid identity of a peer
 * @param value 'struct Peer*' for the peer we are considering
 * @return #GNUNET_YES (continue iteration)
 */
static int
find_advertisable_hello (void *cls,
                         const struct GNUNET_PeerIdentity *pid,
                         void *value)
{
  struct FindAdvHelloContext *fah = cls;
  struct Peer *pos = value;
  struct GNUNET_TIME_Relative rst_time;
  struct GNUNET_HashCode hc;
  size_t hs;

  if (pos == fah->peer)
    return GNUNET_YES;
  if (pos->hello == NULL)
    return GNUNET_YES;
  rst_time = GNUNET_TIME_absolute_get_remaining (pos->filter_expiration);
  if (0 == rst_time.rel_value_us)
  {
    /* time to discard... */
    GNUNET_CONTAINER_bloomfilter_free (pos->filter);
    setup_filter (pos);
  }
  fah->next_adv = GNUNET_TIME_relative_min (rst_time, fah->next_adv);
  hs = GNUNET_HELLO_size (pos->hello);
  if (hs > fah->max_size)
    return GNUNET_YES;
  GNUNET_CRYPTO_hash (&fah->peer->pid,
		      sizeof (struct GNUNET_PeerIdentity), &hc);
  if (GNUNET_NO ==
      GNUNET_CONTAINER_bloomfilter_test (pos->filter,
                                         &hc))
    fah->result = pos;
  return GNUNET_YES;
}


/**
 * Calculate when we would like to send the next HELLO to this
 * peer and ask for it.
 *
 * @param cls for which peer to schedule the HELLO
 */
static void
schedule_next_hello (void *cls)
{
  struct Peer *pl = cls;
  struct FindAdvHelloContext fah;
  struct GNUNET_MQ_Envelope *env;
  size_t want;
  struct GNUNET_TIME_Relative delay;
  struct GNUNET_HashCode hc;

  pl->hello_delay_task = NULL;
  GNUNET_assert (NULL != pl->mq);
  /* find applicable HELLOs */
  fah.peer = pl;
  fah.result = NULL;
  fah.max_size = GNUNET_MAX_MESSAGE_SIZE - 1;
  fah.next_adv = GNUNET_TIME_UNIT_FOREVER_REL;
  GNUNET_CONTAINER_multipeermap_iterate (peers,
                                         &find_advertisable_hello,
                                         &fah);
  pl->hello_delay_task =
      GNUNET_SCHEDULER_add_delayed (fah.next_adv,
                                    &schedule_next_hello,
                                    pl);
  if (NULL == fah.result)
    return;
  delay = GNUNET_TIME_absolute_get_remaining (pl->next_hello_allowed);
  if (0 != delay.rel_value_us)
    return;

  want = GNUNET_HELLO_size (fah.result->hello);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Sending HELLO with %u bytes",
	      (unsigned int) want);
  env = GNUNET_MQ_msg_copy (&fah.result->hello->header);
  GNUNET_MQ_send (pl->mq,
		  env);

  /* avoid sending this one again soon */
  GNUNET_CRYPTO_hash (&pl->pid,
		      sizeof (struct GNUNET_PeerIdentity),
		      &hc);
  GNUNET_CONTAINER_bloomfilter_add (fah.result->filter,
				    &hc);

  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# HELLO messages gossipped"),
			    1,
			    GNUNET_NO);
  /* prepare to send the next one */
  pl->next_hello_allowed
    = GNUNET_TIME_relative_to_absolute (HELLO_ADVERTISEMENT_MIN_FREQUENCY);
  if (NULL != pl->hello_delay_task)
    GNUNET_SCHEDULER_cancel (pl->hello_delay_task);
  pl->hello_delay_task
    = GNUNET_SCHEDULER_add_now (&schedule_next_hello,
				pl);
}


/**
 * Cancel existing requests for sending HELLOs to this peer
 * and recalculate when we should send HELLOs to it based
 * on our current state (something changed!).
 *
 * @param cls closure `struct Peer` to skip, or NULL
 * @param pid identity of a peer
 * @param value `struct Peer *` for the peer
 * @return #GNUNET_YES (always)
 */
static int
reschedule_hellos (void *cls,
                   const struct GNUNET_PeerIdentity *pid,
                   void *value)
{
  struct Peer *peer = value;
  struct Peer *skip = cls;

  if (skip == peer)
    return GNUNET_YES;
  if (NULL == peer->mq)
    return GNUNET_YES;
  if (NULL != peer->hello_delay_task)
  {
    GNUNET_SCHEDULER_cancel (peer->hello_delay_task);
    peer->hello_delay_task = NULL;
  }
  peer->hello_delay_task =
      GNUNET_SCHEDULER_add_now (&schedule_next_hello, peer);
  return GNUNET_YES;
}


/**
 * Method called whenever a peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param mq message queue for communicating with @a peer
 * @return our `struct Peer` for @a peer
 */
static void *
connect_notify (void *cls,
                const struct GNUNET_PeerIdentity *peer,
		struct GNUNET_MQ_Handle *mq)
{
  struct Peer *pos;
  uint64_t flags;
  const void *extra;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core told us that we are connecting to `%s'\n",
              GNUNET_i2s (peer));
  if (0 == memcmp (&my_identity,
                   peer,
                   sizeof (struct GNUNET_PeerIdentity)))
    return NULL;
  extra = GNUNET_CORE_get_mq_options (GNUNET_YES,
				      GNUNET_CORE_PRIO_BEST_EFFORT,
				      &flags);
  GNUNET_MQ_set_options (mq,
			 flags,
			 extra);
  connection_count++;
  GNUNET_STATISTICS_set (stats,
                         gettext_noop ("# peers connected"),
                         connection_count,
                         GNUNET_NO);
  pos = GNUNET_CONTAINER_multipeermap_get (peers,
                                           peer);
  if (NULL == pos)
  {
    pos = make_peer (peer,
                     NULL,
                     GNUNET_NO);
  }
  else
  {
    GNUNET_assert (NULL == pos->mq);
  }
  pos->mq = mq;
  if (pos->is_friend)
  {
    friend_count++;
    if ( (friend_count == minimum_friend_count) &&
         (GNUNET_YES != friends_only) )
      whitelist_peers ();
    GNUNET_STATISTICS_set (stats,
                           gettext_noop ("# friends connected"),
                           friend_count,
                           GNUNET_NO);
  }
  reschedule_hellos (NULL,
                     peer,
                     pos);
  return pos;
}


/**
 * Try to add more peers to our connection set.
 *
 * @param cls closure, not used
 * @param pid identity of a peer
 * @param value `struct Peer *` for the peer
 * @return #GNUNET_YES (continue to iterate)
 */
static int
try_add_peers (void *cls,
               const struct GNUNET_PeerIdentity *pid,
               void *value)
{
  struct Peer *pos = value;

  attempt_connect (pos);
  return GNUNET_YES;
}


/**
 * Add peers and schedule connection attempt
 *
 * @param cls unused, NULL
 */
static void
add_peer_task (void *cls)
{
  add_task = NULL;

  GNUNET_CONTAINER_multipeermap_iterate (peers,
                                         &try_add_peers,
                                         NULL);
}


/**
 * Method called whenever a peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param internal_cls the `struct Peer` for this peer
 */
static void
disconnect_notify (void *cls,
                   const struct GNUNET_PeerIdentity *peer,
		   void *internal_cls)
{
  struct Peer *pos = internal_cls;

  if (NULL == pos)
    return; /* myself, we're shutting down */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core told us that we disconnected from `%s'\n",
              GNUNET_i2s (peer));
  if (NULL == pos->mq)
  {
    GNUNET_break (0);
    return;
  }
  pos->mq = NULL;
  connection_count--;
  if (NULL != pos->hello_delay_task)
  {
    GNUNET_SCHEDULER_cancel (pos->hello_delay_task);
    pos->hello_delay_task = NULL;
  }
  GNUNET_STATISTICS_set (stats,
                         gettext_noop ("# peers connected"),
                         connection_count,
                         GNUNET_NO);
  if (pos->is_friend)
  {
    friend_count--;
    GNUNET_STATISTICS_set (stats,
                           gettext_noop ("# friends connected"),
                           friend_count,
                           GNUNET_NO);
  }
  if ( ( (connection_count < target_connection_count) ||
         (friend_count < minimum_friend_count)) &&
       (NULL == add_task) )
    add_task = GNUNET_SCHEDULER_add_now (&add_peer_task,
                                         NULL);
  if ( (friend_count < minimum_friend_count) &&
       (NULL == blacklist))
    blacklist = GNUNET_TRANSPORT_blacklist (cfg,
                                            &blacklist_check,
                                            NULL);
}


/**
 * Iterator called on each address.
 *
 * @param cls flag that we will set if we see any addresses
 * @param address the address of the peer
 * @param expiration when will the given address expire
 * @return #GNUNET_SYSERR always, to terminate iteration
 */
static int
address_iterator (void *cls,
                  const struct GNUNET_HELLO_Address *address,
                  struct GNUNET_TIME_Absolute expiration)
{
  int *flag = cls;

  *flag = GNUNET_YES;
  return GNUNET_SYSERR;
}


/**
 * We've gotten a HELLO from another peer.  Consider it for
 * advertising.
 *
 * @param hello the HELLO we got
 */
static void
consider_for_advertising (const struct GNUNET_HELLO_Message *hello)
{
  int have_address;
  struct GNUNET_PeerIdentity pid;
  struct GNUNET_TIME_Absolute dt;
  struct GNUNET_HELLO_Message *nh;
  struct Peer *peer;
  uint16_t size;

  if (GNUNET_OK != GNUNET_HELLO_get_id (hello, &pid))
  {
    GNUNET_break (0);
    return;
  }
  if (0 == memcmp (&pid,
                   &my_identity,
                   sizeof (struct GNUNET_PeerIdentity)))
    return;                     /* that's me! */
  have_address = GNUNET_NO;
  GNUNET_HELLO_iterate_addresses (hello,
                                  GNUNET_NO,
                                  &address_iterator,
                                  &have_address);
  if (GNUNET_NO == have_address)
    return;                     /* no point in advertising this one... */
  peer = GNUNET_CONTAINER_multipeermap_get (peers, &pid);
  if (NULL == peer)
  {
    peer = make_peer (&pid,
                      hello,
                      GNUNET_NO);
  }
  else if (NULL != peer->hello)
  {
    dt = GNUNET_HELLO_equals (peer->hello,
                              hello,
                              GNUNET_TIME_absolute_get ());
    if (dt.abs_value_us == GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us)
      return;                   /* nothing new here */
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Found HELLO from peer `%s' for advertising\n",
              GNUNET_i2s (&pid));
  if (NULL != peer->hello)
  {
    nh = GNUNET_HELLO_merge (peer->hello,
                             hello);
    GNUNET_free (peer->hello);
    peer->hello = nh;
  }
  else
  {
    size = GNUNET_HELLO_size (hello);
    peer->hello = GNUNET_malloc (size);
    GNUNET_memcpy (peer->hello,
            hello,
            size);
  }
  if (NULL != peer->filter)
  {
    GNUNET_CONTAINER_bloomfilter_free (peer->filter);
    peer->filter = NULL;
  }
  setup_filter (peer);
  /* since we have a new HELLO to pick from, re-schedule all
   * HELLO requests that are not bound by the HELLO send rate! */
  GNUNET_CONTAINER_multipeermap_iterate (peers,
                                         &reschedule_hellos,
                                         peer);
}


/**
 * PEERINFO calls this function to let us know about a possible peer
 * that we might want to connect to.
 *
 * @param cls closure (not used)
 * @param peer potential peer to connect to
 * @param hello HELLO for this peer (or NULL)
 * @param err_msg NULL if successful, otherwise contains error message
 */
static void
process_peer (void *cls,
              const struct GNUNET_PeerIdentity *peer,
              const struct GNUNET_HELLO_Message *hello,
              const char *err_msg)
{
  struct Peer *pos;

  if (NULL != err_msg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                _("Error in communication with PEERINFO service: %s\n"),
                err_msg);
    GNUNET_PEERINFO_notify_cancel (peerinfo_notify);
    peerinfo_notify = GNUNET_PEERINFO_notify (cfg,
                                              GNUNET_NO,
                                              &process_peer,
                                              NULL);
    return;
  }
  GNUNET_assert (NULL != peer);
  if (0 == memcmp (&my_identity,
                   peer,
                   sizeof (struct GNUNET_PeerIdentity)))
    return;                     /* that's me! */
  if (NULL == hello)
  {
    /* free existing HELLO, if any */
    pos = GNUNET_CONTAINER_multipeermap_get (peers,
                                             peer);
    if (NULL != pos)
    {
      GNUNET_free_non_null (pos->hello);
      pos->hello = NULL;
      if (NULL != pos->filter)
      {
        GNUNET_CONTAINER_bloomfilter_free (pos->filter);
        pos->filter = NULL;
      }
      if ( (NULL == pos->mq) &&
           (GNUNET_NO == pos->is_friend) )
        free_peer (NULL,
                   &pos->pid,
                   pos);
    }
    return;
  }
  consider_for_advertising (hello);
  pos = GNUNET_CONTAINER_multipeermap_get (peers,
                                           peer);
  if (NULL == pos)
    pos = make_peer (peer,
                     hello,
                     GNUNET_NO);
  attempt_connect (pos);
}


/**
 * Function called after #GNUNET_CORE_connect has succeeded
 * (or failed for good).
 *
 * @param cls closure
 * @param my_id ID of this peer, NULL if we failed
 */
static void
core_init (void *cls,
           const struct GNUNET_PeerIdentity *my_id)
{
  if (NULL == my_id)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to connect to core service, can not manage topology!\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  my_identity = *my_id;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "I am peer `%s'\n",
	      GNUNET_i2s (my_id));
  peerinfo_notify = GNUNET_PEERINFO_notify (cfg,
                                            GNUNET_NO,
					    &process_peer,
                                            NULL);
}


/**
 * Process friend found in FRIENDS file.
 *
 * @param cls pointer to an `unsigned int` to be incremented per friend found
 * @param pid identity of the friend
 */
static void
handle_friend (void *cls,
               const struct GNUNET_PeerIdentity *pid)
{
  unsigned int *entries_found = cls;
  struct Peer *fl;

  if (0 == memcmp (pid,
                   &my_identity,
                   sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Found myself `%s' in friend list (useless, ignored)\n"),
                GNUNET_i2s (pid));
    return;
  }
  (*entries_found)++;
  fl = make_peer (pid, NULL, GNUNET_YES);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Found friend `%s' in configuration\n"),
              GNUNET_i2s (&fl->pid));
}


/**
 * Read the friends file.
 */
static void
read_friends_file (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  unsigned int entries_found;

  entries_found = 0;
  if (GNUNET_OK !=
      GNUNET_FRIENDS_parse (cfg,
                            &handle_friend,
                            &entries_found))
  {
    if ( (GNUNET_YES == friends_only) ||
         (minimum_friend_count > 0))
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Encountered errors parsing friends list!\n"));
  }
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# friends in configuration"),
                            entries_found,
                            GNUNET_NO);
  if ( (minimum_friend_count > entries_found) &&
       (GNUNET_NO == friends_only) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Fewer friends specified than required by minimum friend count. Will only connect to friends.\n"));
  }
  if ( (minimum_friend_count > target_connection_count) &&
       (GNUNET_NO == friends_only))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("More friendly connections required than target total number of connections.\n"));
  }
}


/**
 * This function is called whenever an encrypted HELLO message is
 * received.
 *
 * @param cls closure with the peer identity of the sender
 * @param message the actual HELLO message
 * @return #GNUNET_OK if @a message is well-formed
 *         #GNUNET_SYSERR if @a message is invalid
 */
static int
check_hello (void *cls,
	     const struct GNUNET_HELLO_Message *message)
{
  struct GNUNET_PeerIdentity pid;

  if (GNUNET_OK !=
      GNUNET_HELLO_get_id (message,
			   &pid))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * This function is called whenever an encrypted HELLO message is
 * received.
 *
 * @param cls closure with the peer identity of the sender
 * @param message the actual HELLO message
 */
static void
handle_hello (void *cls,
	      const struct GNUNET_HELLO_Message *message)
{
  const struct GNUNET_PeerIdentity *other = cls;
  struct Peer *peer;
  struct GNUNET_PeerIdentity pid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received encrypted HELLO from peer `%s'",
              GNUNET_i2s (other));
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_HELLO_get_id (message,
				      &pid));
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# HELLO messages received"),
                            1,
                            GNUNET_NO);
  peer = GNUNET_CONTAINER_multipeermap_get (peers,
					    &pid);
  if (NULL == peer)
  {
    if ( (GNUNET_YES == friends_only) ||
         (friend_count < minimum_friend_count) )
      return;
  }
  else
  {
    if ( (GNUNET_YES != peer->is_friend) &&
         (GNUNET_YES == friends_only) )
      return;
    if ((GNUNET_YES != peer->is_friend) &&
        (friend_count < minimum_friend_count))
      return;
  }
  (void) GNUNET_PEERINFO_add_peer (pi,
                                   message,
                                   NULL,
                                   NULL);
}


/**
 * Last task run during shutdown.  Disconnects us from
 * the transport and core.
 *
 * @param cls unused, NULL
 */
static void
cleaning_task (void *cls)
{
  if (NULL != peerinfo_notify)
  {
    GNUNET_PEERINFO_notify_cancel (peerinfo_notify);
    peerinfo_notify = NULL;
  }
  if (NULL != handle)
  {
    GNUNET_CORE_disconnect (handle);
    handle = NULL;
  }
  whitelist_peers ();
  if (NULL != add_task)
  {
    GNUNET_SCHEDULER_cancel (add_task);
    add_task = NULL;
  }
  if (NULL != oh)
  {
    GNUNET_TRANSPORT_offer_hello_cancel (oh);
    oh = NULL;
  }
  GNUNET_CONTAINER_multipeermap_iterate (peers,
                                         &free_peer,
                                         NULL);
  GNUNET_CONTAINER_multipeermap_destroy (peers);
  peers = NULL;
  if (NULL != ats)
  {
    GNUNET_ATS_connectivity_done (ats);
    ats = NULL;
  }
  if (NULL != pi)
  {
    GNUNET_PEERINFO_disconnect (pi);
    pi = NULL;
  }
  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats, GNUNET_NO);
    stats = NULL;
  }
}


/**
 * Main function that will be run.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param c configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (hello,
                           GNUNET_MESSAGE_TYPE_HELLO,
                           struct GNUNET_HELLO_Message,
                           NULL),
    GNUNET_MQ_handler_end ()
  };
  unsigned long long opt;

  cfg = c;
  stats = GNUNET_STATISTICS_create ("topology", cfg);
  friends_only =
      GNUNET_CONFIGURATION_get_value_yesno (cfg,
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
  peers = GNUNET_CONTAINER_multipeermap_create (target_connection_count * 2,
                                                GNUNET_NO);
  read_friends_file (cfg);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Topology would like %u connections with at least %u friends\n",
              target_connection_count,
              minimum_friend_count);
  if ( (GNUNET_YES == friends_only) ||
       (minimum_friend_count > 0))
    blacklist = GNUNET_TRANSPORT_blacklist (cfg,
                                            &blacklist_check,
                                            NULL);
  ats = GNUNET_ATS_connectivity_init (cfg);
  pi = GNUNET_PEERINFO_connect (cfg);
  handle = GNUNET_CORE_connect (cfg,
				NULL,
				&core_init,
				&connect_notify,
				&disconnect_notify,
				handlers);
  GNUNET_SCHEDULER_add_shutdown (&cleaning_task,
				 NULL);
  if (NULL == handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to connect to `%s' service.\n"),
                "core");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
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
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  ret =
      (GNUNET_OK ==
       GNUNET_PROGRAM_run (argc, argv,
                           "gnunet-daemon-topology",
                           _("GNUnet topology control"),
                           options, &run, NULL)) ? 0 : 1;
  GNUNET_free ((void*) argv);
  return ret;
}


#if defined(LINUX) && defined(__GLIBC__)
#include <malloc.h>

/**
 * MINIMIZE heap size (way below 128k) since this process doesn't need much.
 */
void __attribute__ ((constructor))
GNUNET_ARM_memory_init ()
{
  mallopt (M_TRIM_THRESHOLD, 4 * 1024);
  mallopt (M_TOP_PAD, 1 * 1024);
  malloc_trim (0);
}
#endif

/* end of gnunet-daemon-topology.c */
