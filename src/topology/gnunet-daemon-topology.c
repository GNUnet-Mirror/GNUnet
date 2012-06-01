/*
     This file is part of GNUnet.
     (C) 2007, 2008, 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file topology/gnunet-daemon-topology.c
 * @brief code for maintaining the mesh topology
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_core_service.h"
#include "gnunet_protocols.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_util_lib.h"


/**
 * Minimum required delay between calls to GNUNET_TRANSPORT_try_connect.
 */
#define MAX_CONNECT_FREQUENCY_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 250)

/**
 * For how long do we blacklist a peer after a failed connection
 * attempt?  This is the baseline factor which is then multiplied by
 * two to the power of the number of failed attempts.
 */
#define GREYLIST_AFTER_ATTEMPT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 1)

/**
 * For how long do we blacklist a friend after a failed connection
 * attempt?  This is the baseline factor which is then multiplied by
 * two to the power of the number of failed attempts.
 */
#define GREYLIST_AFTER_ATTEMPT_FRIEND GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 2)

/**
 * For how long do we blacklist anyone under any cirumstances at least after a failed connection
 * attempt?  This is the absolute minimum, regardless of what the calculation based on
 * exponential backoff returns.
 */
#define GREYLIST_AFTER_ATTEMPT_MIN GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * For how long do we blacklist anyone under any cirumstances at most after a failed connection
 * attempt?  This is the absolute maximum, regardless of what the calculation based on 
 * exponential back-off returns.
 */
#define GREYLIST_AFTER_ATTEMPT_MAX GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 1)

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
   * Our handle for the request to transmit HELLOs to this peer; NULL
   * if no such request is pending.
   */
  struct GNUNET_CORE_TransmitHandle *hello_req;

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
   * Until what time should we not try to connect again
   * to this peer?
   */
  struct GNUNET_TIME_Absolute greylisted_until;

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
   * Task for issuing GNUNET_TRANSPORT_try_connect for this peer.
   */
  GNUNET_SCHEDULER_TaskIdentifier attempt_connect_task;

  /**
   * ID of task we use to clear peers from the greylist.
   */
  GNUNET_SCHEDULER_TaskIdentifier greylist_clean_task;

  /**
   * How often have we tried so far?
   */
  unsigned int connect_attempts;

  /**
   * Is this peer listed here because he is a friend?
   */
  int is_friend;

  /**
   * Are we connected to this peer right now?
   */
  int is_connected;

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
 * All of our friends, all of our current neighbours and all peers for
 * which we have HELLOs.  So pretty much everyone.  Maps peer identities
 * to 'struct Peer *' values.
 */
static struct GNUNET_CONTAINER_MultiHashMap *peers;

/**
 * Handle for reporting statistics.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Blacklist (NULL if we have none).
 */
static struct GNUNET_TRANSPORT_Blacklist *blacklist;

/**
 * When can we next ask transport to create a connection?
 */
static struct GNUNET_TIME_Absolute next_connect_attempt;

/**
 * Task scheduled to try to add peers.
 */
static GNUNET_SCHEDULER_TaskIdentifier add_task;

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
 * Function that decides if a connection is acceptable or not.
 * If we have a blacklist, only friends are allowed, so the check
 * is rather simple.
 *
 * @param cls closure
 * @param pid peer to approve or disapproave
 * @return GNUNET_OK if the connection is allowed
 */
static int
blacklist_check (void *cls, const struct GNUNET_PeerIdentity *pid)
{
  struct Peer *pos;

  pos = GNUNET_CONTAINER_multihashmap_get (peers, &pid->hashPubKey);
  if ((pos != NULL) && (pos->is_friend == GNUNET_YES))
    return GNUNET_OK;
  GNUNET_STATISTICS_update (stats, gettext_noop ("# peers blacklisted"), 1,
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
  if (blacklist != NULL)
  {
    GNUNET_TRANSPORT_blacklist_cancel (blacklist);
    blacklist = NULL;
  }
}


/**
 * Check if an additional connection from the given peer is allowed.
 *
 * @param peer connection to check
 * @return GNUNET_OK if the connection is allowed
 */
static int
is_connection_allowed (struct Peer *peer)
{
  if (0 ==
      memcmp (&my_identity, &peer->pid, sizeof (struct GNUNET_PeerIdentity)))
    return GNUNET_SYSERR;       /* disallow connections to self */
  if (peer->is_friend)
    return GNUNET_OK;
  if (GNUNET_YES == friends_only)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Determined that `%s' is not allowed to connect (not a friend)\n",
                GNUNET_i2s (&peer->pid));
    return GNUNET_SYSERR;
  }
  if (friend_count >= minimum_friend_count)
    return GNUNET_OK;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Determined that `%s' is not allowed to connect (not enough connected friends)\n",
              GNUNET_i2s (&peer->pid));
  return GNUNET_SYSERR;
}


/**
 * Free all resources associated with the given peer.
 *
 * @param cls closure (not used)
 * @param pid identity of the peer
 * @param value peer to free
 * @return GNUNET_YES (always: continue to iterate)
 */
static int
free_peer (void *cls, const GNUNET_HashCode * pid, void *value)
{
  struct Peer *pos = value;

  GNUNET_break (GNUNET_NO == pos->is_connected);
  GNUNET_break (GNUNET_OK ==
                GNUNET_CONTAINER_multihashmap_remove (peers, pid, pos));
  if (pos->hello_req != NULL)
    GNUNET_CORE_notify_transmit_ready_cancel (pos->hello_req);
  if (pos->hello_delay_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (pos->hello_delay_task);
  if (pos->attempt_connect_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (pos->attempt_connect_task);
  if (pos->greylist_clean_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (pos->greylist_clean_task);
  GNUNET_free_non_null (pos->hello);
  if (pos->filter != NULL)
    GNUNET_CONTAINER_bloomfilter_free (pos->filter);
  GNUNET_free (pos);
  return GNUNET_YES;
}


/**
 * Discard peer entries for greylisted peers
 * where the greylisting has expired.
 *
 * @param cls 'struct Peer' to greylist
 * @param tc scheduler context
 */
static void
remove_from_greylist (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Try to connect to the specified peer.
 *
 * @param pos peer to connect to
 */
static void
attempt_connect (struct Peer *pos)
{
  struct GNUNET_TIME_Relative rem;

  if ((connection_count >= target_connection_count) &&
      (friend_count >= minimum_friend_count))
    return;
  if (GNUNET_YES == pos->is_connected)
    return;
  if (GNUNET_OK != is_connection_allowed (pos))
    return;
  if (GNUNET_TIME_absolute_get_remaining (pos->greylisted_until).rel_value > 0)
    return;
  if (GNUNET_YES == pos->is_friend)
    rem = GREYLIST_AFTER_ATTEMPT_FRIEND;
  else
    rem = GREYLIST_AFTER_ATTEMPT;
  rem = GNUNET_TIME_relative_multiply (rem, connection_count);
  rem = GNUNET_TIME_relative_divide (rem, target_connection_count);
  if (pos->connect_attempts > 30)
    pos->connect_attempts = 30;
  rem = GNUNET_TIME_relative_multiply (rem, 1 << (++pos->connect_attempts));
  rem = GNUNET_TIME_relative_max (rem, GREYLIST_AFTER_ATTEMPT_MIN);
  rem = GNUNET_TIME_relative_min (rem, GREYLIST_AFTER_ATTEMPT_MAX);
  pos->greylisted_until = GNUNET_TIME_relative_to_absolute (rem);
  if (pos->greylist_clean_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (pos->greylist_clean_task);
  pos->greylist_clean_task =
      GNUNET_SCHEDULER_add_delayed (rem, &remove_from_greylist, pos);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Asking  to connect to `%s'\n",
              GNUNET_i2s (&pos->pid));
  GNUNET_STATISTICS_update (stats,
                            gettext_noop
                            ("# connect requests issued to transport"), 1,
                            GNUNET_NO);
  GNUNET_TRANSPORT_try_connect (transport, &pos->pid);
}


/**
 * Try to connect to the specified peer.
 *
 * @param cls peer to connect to
 * @param tc scheduler context
 */
static void
do_attempt_connect (void *cls,
		    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Peer *pos = cls;
  struct GNUNET_TIME_Relative delay;

  pos->attempt_connect_task = GNUNET_SCHEDULER_NO_TASK;
  if (GNUNET_YES == pos->is_connected)
    return;
  delay = GNUNET_TIME_absolute_get_remaining (next_connect_attempt);
  if (delay.rel_value > 0)
  {
    pos->attempt_connect_task = GNUNET_SCHEDULER_add_delayed (delay,
							      &do_attempt_connect,
							      pos);
    return;
  }
  next_connect_attempt = GNUNET_TIME_relative_to_absolute (MAX_CONNECT_FREQUENCY_DELAY);
  attempt_connect (pos);
}


/**
 * Schedule a task to try to connect to the specified peer.
 *
 * @param pos peer to connect to
 */
static void
schedule_attempt_connect (struct Peer *pos)
{
  if (GNUNET_SCHEDULER_NO_TASK != pos->attempt_connect_task)
    return;
  pos->attempt_connect_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_absolute_get_remaining (next_connect_attempt),
							    &do_attempt_connect,
							    pos);
}


/**
 * Discard peer entries for greylisted peers
 * where the greylisting has expired.
 *
 * @param cls 'struct Peer' to greylist
 * @param tc scheduler context
 */
static void
remove_from_greylist (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Peer *pos = cls;
  struct GNUNET_TIME_Relative rem;

  pos->greylist_clean_task = GNUNET_SCHEDULER_NO_TASK;
  rem = GNUNET_TIME_absolute_get_remaining (pos->greylisted_until);
  if (rem.rel_value == 0)
  {
    schedule_attempt_connect (pos);
  }
  else
  {
    pos->greylist_clean_task =
        GNUNET_SCHEDULER_add_delayed (rem, &remove_from_greylist, pos);
  }
  if ((GNUNET_NO == pos->is_friend) && (GNUNET_NO == pos->is_connected) &&
      (NULL == pos->hello))
  {
    free_peer (NULL, &pos->pid.hashPubKey, pos);
    return;
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
           const struct GNUNET_HELLO_Message *hello, int is_friend)
{
  struct Peer *ret;

  ret = GNUNET_malloc (sizeof (struct Peer));
  ret->pid = *peer;
  ret->is_friend = is_friend;
  if (hello != NULL)
  {
    ret->hello = GNUNET_malloc (GNUNET_HELLO_size (hello));
    memcpy (ret->hello, hello, GNUNET_HELLO_size (hello));
  }
  GNUNET_break (GNUNET_OK ==
                GNUNET_CONTAINER_multihashmap_put (peers, &peer->hashPubKey,
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
  GNUNET_CONTAINER_bloomfilter_add (peer->filter, &peer->pid.hashPubKey);
}


/**
 * Function to fill send buffer with HELLO.
 *
 * @param cls 'struct Peer' of the target peer
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
hello_advertising_ready (void *cls, size_t size, void *buf);


/**
 * Closure for 'find_advertisable_hello'.
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
 * @return GNUNET_YES (continue iteration)
 */
static int
find_advertisable_hello (void *cls, const GNUNET_HashCode * pid, void *value)
{
  struct FindAdvHelloContext *fah = cls;
  struct Peer *pos = value;
  struct GNUNET_TIME_Relative rst_time;
  size_t hs;

  if (pos == fah->peer)
    return GNUNET_YES;
  if (pos->hello == NULL)
    return GNUNET_YES;
  rst_time = GNUNET_TIME_absolute_get_remaining (pos->filter_expiration);
  if (0 == rst_time.rel_value)
  {
    /* time to discard... */
    GNUNET_CONTAINER_bloomfilter_free (pos->filter);
    setup_filter (pos);
  }
  fah->next_adv = GNUNET_TIME_relative_min (rst_time, fah->next_adv);
  hs = GNUNET_HELLO_size (pos->hello);
  if (hs > fah->max_size)
    return GNUNET_YES;
  if (GNUNET_NO ==
      GNUNET_CONTAINER_bloomfilter_test (pos->filter,
                                         &fah->peer->pid.hashPubKey))
    fah->result = pos;
  return GNUNET_YES;
}


/**
 * Calculate when we would like to send the next HELLO to this
 * peer and ask for it.
 *
 * @param cls for which peer to schedule the HELLO
 * @param tc task context
 */
static void
schedule_next_hello (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Peer *pl = cls;
  struct FindAdvHelloContext fah;
  size_t next_want;
  struct GNUNET_TIME_Relative delay;

  pl->hello_delay_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_assert (GNUNET_YES == pl->is_connected);
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;                     /* we're out of here */
  if (pl->hello_req != NULL)
    return;                     /* did not finish sending the previous one */
  /* find applicable HELLOs */
  fah.peer = pl;
  fah.result = NULL;
  fah.max_size = GNUNET_SERVER_MAX_MESSAGE_SIZE - 1;
  fah.next_adv = GNUNET_TIME_UNIT_FOREVER_REL;
  GNUNET_CONTAINER_multihashmap_iterate (peers, &find_advertisable_hello, &fah);
  pl->hello_delay_task =
      GNUNET_SCHEDULER_add_delayed (fah.next_adv, &schedule_next_hello, pl);
  if (fah.result == NULL)
    return;
  next_want = GNUNET_HELLO_size (fah.result->hello);
  delay = GNUNET_TIME_absolute_get_remaining (pl->next_hello_allowed);
  if (delay.rel_value == 0)
  {
    /* now! */
    pl->hello_req =
        GNUNET_CORE_notify_transmit_ready (handle, GNUNET_YES, 0,
                                           GNUNET_CONSTANTS_SERVICE_TIMEOUT,
                                           &pl->pid, next_want,
                                           &hello_advertising_ready, pl);
  }
}


/**
 * Cancel existing requests for sending HELLOs to this peer
 * and recalculate when we should send HELLOs to it based
 * on our current state (something changed!).
 *
 * @param cls closure, 'struct Peer' to skip, or NULL
 * @param pid identity of a peer
 * @param value 'struct Peer*' for the peer
 * @return GNUNET_YES (always)
 */
static int
reschedule_hellos (void *cls, const GNUNET_HashCode * pid, void *value)
{
  struct Peer *peer = value;
  struct Peer *skip = cls;

  if (skip == peer)
    return GNUNET_YES;
  if (!peer->is_connected)
    return GNUNET_YES;
  if (peer->hello_req != NULL)
  {
    GNUNET_CORE_notify_transmit_ready_cancel (peer->hello_req);
    peer->hello_req = NULL;
  }
  if (peer->hello_delay_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (peer->hello_delay_task);
    peer->hello_delay_task = GNUNET_SCHEDULER_NO_TASK;
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
 * @param atsi performance data
 * @param atsi_count number of records in 'atsi'
 */
static void
connect_notify (void *cls, const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_ATS_Information *atsi,
                unsigned int atsi_count)
{
  struct Peer *pos;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core told us that we are connecting to `%s'\n",
              GNUNET_i2s (peer));
  if (0 == memcmp (&my_identity, peer, sizeof (struct GNUNET_PeerIdentity)))
    return;

  connection_count++;
  GNUNET_STATISTICS_set (stats, gettext_noop ("# peers connected"),
                         connection_count, GNUNET_NO);
  pos = GNUNET_CONTAINER_multihashmap_get (peers, &peer->hashPubKey);
  if (NULL == pos)
  {
    pos = make_peer (peer, NULL, GNUNET_NO);
    GNUNET_break (GNUNET_OK == is_connection_allowed (pos));
  }
  else
  {
    GNUNET_assert (GNUNET_NO == pos->is_connected);
    pos->greylisted_until.abs_value = 0;        /* remove greylisting */
  }
  pos->is_connected = GNUNET_YES;
  pos->connect_attempts = 0;    /* re-set back-off factor */
  if (pos->is_friend)
  {
    if ((friend_count == minimum_friend_count - 1) &&
        (GNUNET_YES != friends_only))
      whitelist_peers ();
    friend_count++;
    GNUNET_STATISTICS_set (stats, gettext_noop ("# friends connected"),
                           friend_count, GNUNET_NO);
  }
  reschedule_hellos (NULL, &peer->hashPubKey, pos);
}


/**
 * Try to add more peers to our connection set.
 *
 * @param cls closure, not used
 * @param pid identity of a peer
 * @param value 'struct Peer*' for the peer
 * @return GNUNET_YES (continue to iterate)
 */
static int
try_add_peers (void *cls, const GNUNET_HashCode * pid, void *value)
{
  struct Peer *pos = value;

  schedule_attempt_connect (pos);
  return GNUNET_YES;
}


/**
 * Last task run during shutdown.  Disconnects us from
 * the transport and core.
 *
 * @param cls unused, NULL
 * @param tc scheduler context
 */
static void
add_peer_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  add_task = GNUNET_SCHEDULER_NO_TASK;

  GNUNET_CONTAINER_multihashmap_iterate (peers, &try_add_peers, NULL);
}


/**
 * Method called whenever a peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
disconnect_notify (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct Peer *pos;

  if (0 == memcmp (&my_identity, peer, sizeof (struct GNUNET_PeerIdentity)))
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core told us that we disconnected from `%s'\n",
              GNUNET_i2s (peer));
  pos = GNUNET_CONTAINER_multihashmap_get (peers, &peer->hashPubKey);
  if (NULL == pos)
  {
    GNUNET_break (0);
    return;
  }
  if (pos->is_connected != GNUNET_YES)
  {
    GNUNET_break (0);
    return;
  }
  pos->is_connected = GNUNET_NO;
  connection_count--;
  if (NULL != pos->hello_req)
  {
    GNUNET_CORE_notify_transmit_ready_cancel (pos->hello_req);
    pos->hello_req = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != pos->hello_delay_task)
  {
    GNUNET_SCHEDULER_cancel (pos->hello_delay_task);
    pos->hello_delay_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_STATISTICS_set (stats, gettext_noop ("# peers connected"),
                         connection_count, GNUNET_NO);
  if (pos->is_friend)
  {
    friend_count--;
    GNUNET_STATISTICS_set (stats, gettext_noop ("# friends connected"),
                           friend_count, GNUNET_NO);
  }
  if (((connection_count < target_connection_count) ||
       (friend_count < minimum_friend_count)) &&
      (GNUNET_SCHEDULER_NO_TASK == add_task))
    add_task = GNUNET_SCHEDULER_add_now (&add_peer_task, NULL);
  if ((friend_count < minimum_friend_count) && (blacklist == NULL))
    blacklist = GNUNET_TRANSPORT_blacklist (cfg, &blacklist_check, NULL);
}


/**
 * Iterator called on each address.
 *
 * @param cls flag that we will set if we see any addresses
 * @param address the address of the peer
 * @param expiration when will the given address expire
 * @return GNUNET_SYSERR always, to terminate iteration
 */
static int
address_iterator (void *cls, const struct GNUNET_HELLO_Address *address,
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
  if (0 == memcmp (&pid, &my_identity, sizeof (struct GNUNET_PeerIdentity)))
    return;                     /* that's me! */
  have_address = GNUNET_NO;
  GNUNET_HELLO_iterate_addresses (hello, GNUNET_NO, &address_iterator,
                                  &have_address);
  if (GNUNET_NO == have_address)
    return;                     /* no point in advertising this one... */
  peer = GNUNET_CONTAINER_multihashmap_get (peers, &pid.hashPubKey);
  if (NULL == peer)
  {
    peer = make_peer (&pid, hello, GNUNET_NO);
  }
  else if (peer->hello != NULL)
  {
    dt = GNUNET_HELLO_equals (peer->hello, hello, GNUNET_TIME_absolute_get ());
    if (dt.abs_value == GNUNET_TIME_UNIT_FOREVER_ABS.abs_value)
      return;                   /* nothing new here */
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Found `%s' from peer `%s' for advertising\n", "HELLO",
              GNUNET_i2s (&pid));
  if (peer->hello != NULL)
  {
    nh = GNUNET_HELLO_merge (peer->hello, hello);
    GNUNET_free (peer->hello);
    peer->hello = nh;
  }
  else
  {
    size = GNUNET_HELLO_size (hello);
    peer->hello = GNUNET_malloc (size);
    memcpy (peer->hello, hello, size);
  }
  if (peer->filter != NULL)
    GNUNET_CONTAINER_bloomfilter_free (peer->filter);
  setup_filter (peer);
  /* since we have a new HELLO to pick from, re-schedule all
   * HELLO requests that are not bound by the HELLO send rate! */
  GNUNET_CONTAINER_multihashmap_iterate (peers, &reschedule_hellos, peer);
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
process_peer (void *cls, const struct GNUNET_PeerIdentity *peer,
              const struct GNUNET_HELLO_Message *hello, const char *err_msg)
{
  struct Peer *pos;

  if (err_msg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                _("Error in communication with PEERINFO service: %s\n"),
                err_msg);
    GNUNET_PEERINFO_notify_cancel (peerinfo_notify);
    peerinfo_notify = GNUNET_PEERINFO_notify (cfg, &process_peer, NULL);
    return;
  }
  GNUNET_assert (peer != NULL);
  if (0 == memcmp (&my_identity, peer, sizeof (struct GNUNET_PeerIdentity)))
    return;                     /* that's me! */
  if (hello == NULL)
  {
    /* free existing HELLO, if any */
    pos = GNUNET_CONTAINER_multihashmap_get (peers, &peer->hashPubKey);
    if (NULL != pos)
    {
      GNUNET_free_non_null (pos->hello);
      pos->hello = NULL;
      if (pos->filter != NULL)
      {
        GNUNET_CONTAINER_bloomfilter_free (pos->filter);
        pos->filter = NULL;
      }
      if ((GNUNET_NO == pos->is_connected) && (GNUNET_NO == pos->is_friend) &&
          (0 ==
           GNUNET_TIME_absolute_get_remaining (pos->
                                               greylisted_until).rel_value))
        free_peer (NULL, &pos->pid.hashPubKey, pos);
    }
    return;
  }
  consider_for_advertising (hello);
  pos = GNUNET_CONTAINER_multihashmap_get (peers, &peer->hashPubKey);
  if (pos == NULL)
    pos = make_peer (peer, hello, GNUNET_NO);
  GNUNET_assert (NULL != pos);
  if (GNUNET_YES == pos->is_connected)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Already connected to peer `%s'\n",
                GNUNET_i2s (peer));
    return;
  }
  if (GNUNET_TIME_absolute_get_remaining (pos->greylisted_until).rel_value > 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Already tried peer `%s' recently\n",
                GNUNET_i2s (peer));
    return;                     /* peer still greylisted */
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Considering connecting to peer `%s'\n",
              GNUNET_i2s (peer));
  schedule_attempt_connect (pos);
}


/**
 * Function called after GNUNET_CORE_connect has succeeded
 * (or failed for good).
 *
 * @param cls closure
 * @param server handle to the server, NULL if we failed
 * @param my_id ID of this peer, NULL if we failed
 */
static void
core_init (void *cls, struct GNUNET_CORE_Handle *server,
           const struct GNUNET_PeerIdentity *my_id)
{
  if (server == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _
                ("Failed to connect to core service, can not manage topology!\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  handle = server;
  my_identity = *my_id;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "I am peer `%s'\n", GNUNET_i2s (my_id));
  peerinfo_notify = GNUNET_PEERINFO_notify (cfg, &process_peer, NULL);
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
  uint64_t fsize;
  struct GNUNET_CRYPTO_HashAsciiEncoded enc;
  unsigned int entries_found;
  struct Peer *fl;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (cfg, "TOPOLOGY", "FRIENDS", &fn))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Option `%s' in section `%s' not specified!\n"), "FRIENDS",
                "TOPOLOGY");
    return;
  }
  if (GNUNET_OK != GNUNET_DISK_file_test (fn))
    GNUNET_DISK_fn_write (fn, NULL, 0,
                          GNUNET_DISK_PERM_USER_READ |
                          GNUNET_DISK_PERM_USER_WRITE);
  if (GNUNET_OK != GNUNET_DISK_file_size (fn,
      &fsize, GNUNET_NO, GNUNET_YES))
  {
    if ((friends_only) || (minimum_friend_count > 0))
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Could not read friends list `%s'\n"), fn);
    GNUNET_free (fn);
    return;
  }
  if (fsize == 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, _("Friends file `%s' is empty.\n"),
                fn);
    GNUNET_free (fn);
    return;
  }
  data = GNUNET_malloc_large (fsize);
  if (data == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to read friends list from `%s': out of memory\n"),
                fn);
    GNUNET_free (fn);
    return;
  }
  if (fsize != GNUNET_DISK_fn_read (fn, data, fsize))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to read friends list from `%s'\n"), fn);
    GNUNET_free (fn);
    GNUNET_free (data);
    return;
  }
  entries_found = 0;
  pos = 0;
  while ((pos < fsize) && isspace ((unsigned char) data[pos]))
    pos++;
  while ((fsize >= sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded)) &&
         (pos <=
          fsize - sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded)))
  {
    memcpy (&enc, &data[pos], sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded));
    if (!isspace
        ((unsigned char)
         enc.encoding[sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded) - 1]))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _
                  ("Syntax error in topology specification at offset %llu, skipping bytes.\n"),
                  (unsigned long long) pos);
      pos++;
      while ((pos < fsize) && (!isspace ((unsigned char) data[pos])))
        pos++;
      continue;
    }
    enc.encoding[sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded) - 1] = '\0';
    if (GNUNET_OK !=
        GNUNET_CRYPTO_hash_from_string ((char *) &enc, &pid.hashPubKey))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _
                  ("Syntax error in topology specification at offset %llu, skipping bytes `%s'.\n"),
                  (unsigned long long) pos, &enc);
    }
    else
    {
      if (0 != memcmp (&pid, &my_identity, sizeof (struct GNUNET_PeerIdentity)))
      {
        entries_found++;
        fl = make_peer (&pid, NULL, GNUNET_YES);
        GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                    _("Found friend `%s' in configuration\n"),
                    GNUNET_i2s (&fl->pid));
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    _("Found myself `%s' in friend list (useless, ignored)\n"),
                    GNUNET_i2s (&pid));
      }
    }
    pos = pos + sizeof (struct GNUNET_CRYPTO_HashAsciiEncoded);
    while ((pos < fsize) && isspace ((unsigned char) data[pos]))
      pos++;
  }
  GNUNET_free (data);
  GNUNET_free (fn);
  GNUNET_STATISTICS_update (stats, gettext_noop ("# friends in configuration"),
                            entries_found, GNUNET_NO);
  if ((minimum_friend_count > entries_found) && (friends_only == GNUNET_NO))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _
                ("Fewer friends specified than required by minimum friend count. Will only connect to friends.\n"));
  }
  if ((minimum_friend_count > target_connection_count) &&
      (friends_only == GNUNET_NO))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _
                ("More friendly connections required than target total number of connections.\n"));
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
 * @param atsi performance data
 * @param atsi_count number of records in 'atsi'
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_encrypted_hello (void *cls, const struct GNUNET_PeerIdentity *other,
                        const struct GNUNET_MessageHeader *message,
                        const struct GNUNET_ATS_Information *atsi,
                        unsigned int atsi_count)
{
  struct Peer *peer;
  struct GNUNET_PeerIdentity pid;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received encrypted `%s' from peer `%s'",
              "HELLO", GNUNET_i2s (other));
  if (GNUNET_OK !=
      GNUNET_HELLO_get_id ((const struct GNUNET_HELLO_Message *) message, &pid))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  GNUNET_STATISTICS_update (stats, gettext_noop ("# HELLO messages received"),
                            1, GNUNET_NO);
  peer = GNUNET_CONTAINER_multihashmap_get (peers, &pid.hashPubKey);
  if (NULL == peer)
  {
    if ((GNUNET_YES == friends_only) || (friend_count < minimum_friend_count))
      return GNUNET_OK;
  }
  else
  {
    if ((GNUNET_YES != peer->is_friend) && (GNUNET_YES == friends_only))
      return GNUNET_OK;
    if ((GNUNET_YES != peer->is_friend) &&
        (friend_count < minimum_friend_count))
      return GNUNET_OK;
  }
  if (transport != NULL)
    GNUNET_TRANSPORT_offer_hello (transport, message, NULL, NULL);
  return GNUNET_OK;
}


/**
 * Function to fill send buffer with HELLO.
 *
 * @param cls 'struct Peer' of the target peer
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
hello_advertising_ready (void *cls, size_t size, void *buf)
{
  struct Peer *pl = cls;
  struct FindAdvHelloContext fah;
  size_t want;

  pl->hello_req = NULL;
  GNUNET_assert (GNUNET_YES == pl->is_connected);
  /* find applicable HELLOs */
  fah.peer = pl;
  fah.result = NULL;
  fah.max_size = size;
  fah.next_adv = GNUNET_TIME_UNIT_FOREVER_REL;
  GNUNET_CONTAINER_multihashmap_iterate (peers, &find_advertisable_hello, &fah);
  want = 0;
  if (fah.result != NULL)
  {
    want = GNUNET_HELLO_size (fah.result->hello);
    GNUNET_assert (want <= size);
    memcpy (buf, fah.result->hello, want);
    GNUNET_CONTAINER_bloomfilter_add (fah.result->filter, &pl->pid.hashPubKey);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending `%s' with %u bytes", "HELLO",
                (unsigned int) want);
    GNUNET_STATISTICS_update (stats,
                              gettext_noop ("# HELLO messages gossipped"), 1,
                              GNUNET_NO);
  }

  if (pl->hello_delay_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (pl->hello_delay_task);
  pl->next_hello_allowed =
      GNUNET_TIME_relative_to_absolute (HELLO_ADVERTISEMENT_MIN_FREQUENCY);
  pl->hello_delay_task = GNUNET_SCHEDULER_add_now (&schedule_next_hello, pl);
  return want;
}


/**
 * Last task run during shutdown.  Disconnects us from
 * the transport and core.
 *
 * @param cls unused, NULL
 * @param tc scheduler context
 */
static void
cleaning_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != peerinfo_notify)
  {
    GNUNET_PEERINFO_notify_cancel (peerinfo_notify);
    peerinfo_notify = NULL;
  }
  GNUNET_TRANSPORT_disconnect (transport);
  transport = NULL;
  if (handle != NULL)
  {
    GNUNET_CORE_disconnect (handle);
    handle = NULL;
  }
  whitelist_peers ();
  if (GNUNET_SCHEDULER_NO_TASK != add_task)
  {
    GNUNET_SCHEDULER_cancel (add_task);
    add_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_CONTAINER_multihashmap_iterate (peers, &free_peer, NULL);
  GNUNET_CONTAINER_multihashmap_destroy (peers);
  peers = NULL;
  if (stats != NULL)
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
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  static struct GNUNET_CORE_MessageHandler handlers[] = {
    {&handle_encrypted_hello, GNUNET_MESSAGE_TYPE_HELLO, 0},
    {NULL, 0, 0}
  };
  unsigned long long opt;

  cfg = c;
  stats = GNUNET_STATISTICS_create ("topology", cfg);
  autoconnect =
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "TOPOLOGY", "AUTOCONNECT");
  friends_only =
      GNUNET_CONFIGURATION_get_value_yesno (cfg, "TOPOLOGY", "FRIENDS-ONLY");
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "TOPOLOGY", "MINIMUM-FRIENDS",
                                             &opt))
    opt = 0;
  minimum_friend_count = (unsigned int) opt;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg, "TOPOLOGY",
                                             "TARGET-CONNECTION-COUNT", &opt))
    opt = 16;
  target_connection_count = (unsigned int) opt;
  peers = GNUNET_CONTAINER_multihashmap_create (target_connection_count * 2);

  if ((friends_only == GNUNET_YES) || (minimum_friend_count > 0))
    read_friends_file (cfg);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Topology would like %u connections with at least %u friends (%s)\n",
              target_connection_count, minimum_friend_count,
              autoconnect ? "autoconnect enabled" : "autoconnect disabled");
  if ((friend_count < minimum_friend_count) && (blacklist == NULL))
    blacklist = GNUNET_TRANSPORT_blacklist (cfg, &blacklist_check, NULL);
  transport = GNUNET_TRANSPORT_connect (cfg, NULL, NULL, NULL, NULL, NULL);
  handle =
      GNUNET_CORE_connect (cfg, 1, NULL, &core_init, &connect_notify,
                           &disconnect_notify, NULL, GNUNET_NO, NULL, GNUNET_NO,
                           handlers);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &cleaning_task,
                                NULL);
  if (NULL == transport)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to connect to `%s' service.\n"), "transport");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  if (NULL == handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to connect to `%s' service.\n"), "core");
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

  ret =
      (GNUNET_OK ==
       GNUNET_PROGRAM_run (argc, argv, "gnunet-daemon-topology",
                           _
                           ("GNUnet topology control (maintaining P2P mesh and F2F constraints)"),
                           options, &run, NULL)) ? 0 : 1;
  return ret;
}

/* end of gnunet-daemon-topology.c */
