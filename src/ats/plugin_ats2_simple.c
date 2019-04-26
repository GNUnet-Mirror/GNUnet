/*
 This file is part of GNUnet.
 Copyright (C) 2011-2015, 2018 GNUnet e.V.

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

     SPDX-License-Identifier: AGPL3.0-or-later
 */
/**
 * @file ats/plugin_ats2_simple.c
 * @brief ATS simple solver
 * @author Matthias Wachs
 * @author Christian Grothoff
 *
 * TODO:
 * - needs testing
 */
#include "platform.h"
#include "gnunet_ats_plugin_new.h"
#include "gnunet_hello_lib.h"
#include "gnunet_peerstore_service.h"

#define LOG(kind,...) GNUNET_log_from (kind, "ats-simple",__VA_ARGS__)


/**
 * Base frequency at which we suggest addresses to transport.
 * Multiplied by the square of the number of active connections
 * (and randomized) to calculate the actual frequency at which
 * we will suggest addresses to the transport.  Furthermore, each
 * address is also bounded by an exponential back-off.
 */
#define SUGGEST_FREQ GNUNET_TIME_UNIT_SECONDS

/**
 * What is the minimum bandwidth we always try to allocate for
 * any session that is up? (May still be scaled down lower if
 * the number of sessions is so high that the total bandwidth
 * is insufficient to allow for this value to be granted.)
 */
#define MIN_BANDWIDTH_PER_SESSION 1024


/**
 * A handle for the proportional solver
 */
struct SimpleHandle;


/**
 * Information about preferences and sessions we track
 * per peer.
 */
struct Peer;


/**
 * Entry in list of addresses we could try per peer.
 */
struct Hello
{

  /**
   * Kept in a DLL.
   */
  struct Hello *next;

  /**
   * Kept in a DLL.
   */
  struct Hello *prev;

  /**
   * Peer this hello belongs to.
   */
  struct Peer *peer;

  /**
   * The address we could try.
   */
  const char *address;

  /**
   * Is a session with this address already up?
   * If not, set to NULL.
   */
  struct GNUNET_ATS_SessionHandle *sh;

  /**
   * When does the HELLO expire?
   */
  struct GNUNET_TIME_Absolute expiration;

  /**
   * When did we try it last?
   */
  struct GNUNET_TIME_Absolute last_attempt;

  /**
   * Current exponential backoff value.
   */
  struct GNUNET_TIME_Relative backoff;

  /**
   * Type of the network for this HELLO.
   */
  enum GNUNET_NetworkType nt;

};


/**
 * Internal representation of a session by the plugin.
 * (If desired, plugin may just use NULL.)
 */
struct GNUNET_ATS_SessionHandle
{

  /**
   * Kept in DLL per peer.
   */
  struct GNUNET_ATS_SessionHandle *next;

  /**
   * Kept in DLL per peer.
   */
  struct GNUNET_ATS_SessionHandle *prev;

  /**
   * The session in the main ATS service.
   */
  struct GNUNET_ATS_Session *session;

  /**
   * Current performance data for this @e session
   */
  const struct GNUNET_ATS_SessionData *data;

  /**
   * Hello matching this session, or NULL for none.
   */
  struct Hello *hello;

  /**
   * Peer this session is for.
   */
  struct Peer *peer;

  /**
   * Address used by this session (largely for debugging).
   */
  const char *address;

  /**
   * When did we last update transport about the allocation?
   * Used to dampen the frequency of updates.
   */
  struct GNUNET_TIME_Absolute last_allocation;

  /**
   * Last BW-in allocation given to the transport service.
   */
  struct GNUNET_BANDWIDTH_Value32NBO bw_in;

  /**
   * Last BW-out allocation given to the transport service.
   */
  struct GNUNET_BANDWIDTH_Value32NBO bw_out;

  /**
   * New BW-in allocation given to the transport service.
   */
  uint64_t target_in;

  /**
   * New BW-out allocation given to the transport service.
   */
  uint64_t target_out;

};


/**
 * Information about preferences and sessions we track
 * per peer.
 */
struct Peer
{

  /**
   * Kept in DLL per peer.
   */
  struct GNUNET_ATS_SessionHandle *sh_head;

  /**
   * Kept in DLL per peer.
   */
  struct GNUNET_ATS_SessionHandle *sh_tail;

  /**
   * Kept in a DLL.
   */
  struct Hello *h_head;

  /**
   * Kept in a DLL.
   */
  struct Hello *h_tail;

  /**
   * The handle for the proportional solver
   */
  struct SimpleHandle *h;

  /**
   * Watch context where we are currently looking for HELLOs for
   * this peer.
   */
  struct GNUNET_PEERSTORE_WatchContext *wc;

  /**
   * Task used to try again to suggest an address for this peer.
   */
  struct GNUNET_SCHEDULER_Task *task;

  /**
   * Which peer is this for?
   */
  struct GNUNET_PeerIdentity pid;

  /**
   * When did we last suggest an address to connect to for this peer?
   */
  struct GNUNET_TIME_Absolute last_suggestion;

  /**
   * Array where we sum up the bandwidth requests received indexed
   * by preference kind (see `enum GNUNET_MQ_PreferenceKind`)
   */
  uint64_t bw_by_pk[GNUNET_MQ_PREFERENCE_COUNT];

};


/**
 * Representation of a network (to be expanded...)
 */
struct Network
{

  /**
   * Total inbound quota
   */
  unsigned long long total_quota_in;

  /**
   * Total outbound quota
   */
  unsigned long long total_quota_out;

  /**
   * ATS network type
   */
  enum GNUNET_NetworkType type;

};


/**
 * A handle for the proportional solver
 */
struct SimpleHandle
{

  /**
   * Our execution environment.
   */
  struct GNUNET_ATS_PluginEnvironment *env;

  /**
   * Information we track for each peer.
   */
  struct GNUNET_CONTAINER_MultiPeerMap *peers;

  /**
   * Handle to the peerstore service.
   */
  struct GNUNET_PEERSTORE_Handle *ps;

  /**
   * Array where we sum up the bandwidth requests received indexed
   * by preference kind (see `enum GNUNET_MQ_PreferenceKind`) (sums
   * over all peers).
   */
  uint64_t bw_by_pk[GNUNET_MQ_PREFERENCE_COUNT];

  /**
   * Information we track per network type (quotas).
   */
  struct Network networks[GNUNET_NT_COUNT];

};


/**
 * Lookup peer in the peers map.
 *
 * @param h handle to look up in
 * @param pid peer identity to look up by
 * @return NULL for not found
 */
struct Peer *
lookup_peer (struct SimpleHandle *h,
             const struct GNUNET_PeerIdentity *pid)
{
  return GNUNET_CONTAINER_multipeermap_get (h->peers,
                                            pid);
}


/**
 * Check if there is _any_ interesting information left we
 * store about the peer in @a p.
 *
 * @param p peer to test if we can drop the data structure
 * @return #GNUNET_YES if no information is left in @a p
 */
static int
peer_test_dead (struct Peer *p)
{
  for (enum GNUNET_MQ_PreferenceKind pk = 0;
       pk < GNUNET_MQ_PREFERENCE_COUNT;
       pk++)
    if (0 != p->bw_by_pk[pk])
      return GNUNET_NO;
  if (NULL != p->sh_head)
    return GNUNET_NO;
  return GNUNET_YES;
}


/**
 * Contact the transport service and suggest to it to
 * try connecting to the address of @a hello.  Updates
 * backoff and timestamp values in the @a hello.
 *
 * @param hello[in,out] address suggestion to make
 */
static void
suggest_hello (struct Hello *hello)
{
  struct Peer *p = hello->peer;
  struct SimpleHandle *h = p->h;

  p->last_suggestion
    = hello->last_attempt
    = GNUNET_TIME_absolute_get ();
  hello->backoff = GNUNET_TIME_randomized_backoff (hello->backoff,
                                                   GNUNET_TIME_absolute_get_remaining (hello->expiration));
  h->env->suggest_cb (h->env->cls,
                      &p->pid,
                      hello->address);
}


/**
 * Consider suggesting a HELLO (without a session) to transport.
 * We look at how many active sessions we have for the peer, and
 * if there are many, reduce the frequency of trying new addresses.
 * Also, for each address we consider when we last tried it, and
 * its exponential backoff if the attempt failed.  Note that it
 * is possible that this function is called when no suggestion
 * is to be made.
 *
 * In this case, we only calculate the time until we make the next
 * suggestion.
 *
 * @param cls a `struct Peer`
 */
static void
suggest_start_cb (void *cls)
{
  struct Peer *p = cls;
  struct GNUNET_TIME_Relative delay = GNUNET_TIME_UNIT_ZERO;
  struct Hello *hello = NULL;
  struct GNUNET_TIME_Absolute hpt = GNUNET_TIME_UNIT_FOREVER_ABS;
  struct GNUNET_TIME_Relative xdelay;
  struct GNUNET_TIME_Absolute xnext;
  unsigned int num_sessions = 0;
  uint32_t sq;

  /* count number of active sessions */
  for (struct GNUNET_ATS_SessionHandle *sh = p->sh_head;
       NULL != sh;
       sh = sh->next)
    num_sessions++;
  /* calculate square of number of sessions */
  num_sessions++; /* start with 1, even if we have zero sessions */
  if (num_sessions < UINT16_MAX)
    sq = num_sessions * (uint32_t) num_sessions;
  else
    sq = UINT32_MAX;
  xdelay = GNUNET_TIME_randomized_backoff (GNUNET_TIME_relative_multiply (SUGGEST_FREQ,
                                                                          sq),
                                           GNUNET_TIME_UNIT_FOREVER_REL);
  xnext = GNUNET_TIME_relative_to_absolute (xdelay);

  p->task = NULL;
  while (0 == delay.rel_value_us)
  {
    struct Hello *next;
    struct GNUNET_TIME_Absolute xmax;

    if (NULL != hello)
    {
      /* We went through the loop already once and found
         a HELLO that is due *now*, so make a suggestion! */
      GNUNET_break (NULL == hello->sh);
      suggest_hello (hello);
      hello = NULL;
      hpt = GNUNET_TIME_UNIT_FOREVER_ABS;
    }
    for (struct Hello *pos = p->h_head; NULL != pos; pos = next)
    {
      struct GNUNET_TIME_Absolute pt;

      next = pos->next;
      if (NULL != pos->sh)
        continue;
      if (0 == GNUNET_TIME_absolute_get_remaining (pos->expiration).rel_value_us)
      {
        /* expired, remove! */
        GNUNET_CONTAINER_DLL_remove (p->h_head,
                                     p->h_tail,
                                     pos);
        GNUNET_free (pos);
        continue;
      }
      pt = GNUNET_TIME_absolute_add (pos->last_attempt,
                                     pos->backoff);
      if ( (NULL == hello) ||
           (pt.abs_value_us < hpt.abs_value_us) )
      {
        hello = pos;
        hpt = pt;
      }
    }
    if (NULL == hello)
      return; /* no HELLOs that could still be tried */

    /* hpt is now the *earliest* possible time for any HELLO
       but we might not want to go for as early as possible for
       this peer. So the actual time is the max of the earliest
       HELLO and the 'xnext' */
    xmax = GNUNET_TIME_absolute_max (hpt,
                                     xnext);
    delay = GNUNET_TIME_absolute_get_remaining (xmax);
  }
  p->task = GNUNET_SCHEDULER_add_delayed (delay,
                                          &suggest_start_cb,
                                          p);
}


/**
 * Function called by PEERSTORE for each matching record.
 *
 * @param cls closure with a `struct Peer`
 * @param record peerstore record information
 * @param emsg error message, or NULL if no errors
 */
static void
watch_cb (void *cls,
          const struct GNUNET_PEERSTORE_Record *record,
          const char *emsg)
{
  struct Peer *p = cls;
  char *addr;
  size_t alen;
  enum GNUNET_NetworkType nt;
  struct GNUNET_TIME_Absolute expiration;
  struct Hello *hello;

  if (0 != GNUNET_memcmp (&p->pid,
                   &record->peer))
  {
    GNUNET_break (0);
    return;
  }
  if (0 != strcmp (record->key,
                   GNUNET_PEERSTORE_TRANSPORT_URLADDRESS_KEY))
  {
    GNUNET_break (0);
    return;
  }
  addr = GNUNET_HELLO_extract_address (record->value,
                                       record->value_size,
                                       &p->pid,
                                       &nt,
                                       &expiration);
  if (NULL == addr)
    return; /* invalid hello, bad signature, other problem */
  if (0 == GNUNET_TIME_absolute_get_remaining (expiration).rel_value_us)
  {
    /* expired, ignore */
    GNUNET_free (addr);
    return;
  }
  /* check if addr is already known */
  for (struct Hello *he = p->h_head;
       NULL != he;
       he = he->next)
  {
    if (0 != strcmp (he->address,
                     addr))
      continue;
    if (he->expiration.abs_value_us < expiration.abs_value_us)
    {
      he->expiration = expiration;
      he->nt = nt;
    }
    GNUNET_free (addr);
    return;
  }
  /* create new HELLO */
  alen = strlen (addr) + 1;
  hello = GNUNET_malloc (sizeof (struct Hello) + alen);
  hello->address = (const char *) &hello[1];
  hello->expiration = expiration;
  hello->nt = nt;
  hello->peer = p;
  memcpy (&hello[1],
          addr,
          alen);
  GNUNET_free (addr);
  GNUNET_CONTAINER_DLL_insert (p->h_head,
                               p->h_tail,
                               hello);
  /* check if sh for this HELLO already exists */
  for (struct GNUNET_ATS_SessionHandle *sh = p->sh_head;
       NULL != sh;
       sh = sh->next)
  {
    if ( (NULL == sh->address) ||
         (0 != strcmp (sh->address,
                       addr)) )
      continue;
    GNUNET_assert (NULL == sh->hello);
    sh->hello = hello;
    hello->sh = sh;
    break;
  }
  if (NULL == p->task)
    p->task = GNUNET_SCHEDULER_add_now (&suggest_start_cb,
                                        p);
}


/**
 * Find or add peer if necessary.
 *
 * @param h our plugin handle
 * @param pid the peer identity to add/look for
 * @return a peer handle
 */
static struct Peer *
peer_add (struct SimpleHandle *h,
          const struct GNUNET_PeerIdentity *pid)
{
  struct Peer *p = lookup_peer (h,
                                pid);

  if (NULL != p)
    return p;
  p = GNUNET_new (struct Peer);
  p->h = h;
  p->pid = *pid;
  p->wc = GNUNET_PEERSTORE_watch (h->ps,
                                  "transport",
                                  &p->pid,
                                  GNUNET_PEERSTORE_TRANSPORT_URLADDRESS_KEY,
                                  &watch_cb,
                                  p);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_put (h->peers,
                                                    &p->pid,
                                                    p,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));

  return p;
}


/**
 * Free the entry (and associated tasks) of peer @a p.
 * Note that @a p must be dead already (see #peer_test_dead()).
 *
 * @param p the peer to free
 */
static void
peer_free (struct Peer *p)
{
  struct SimpleHandle *h = p->h;
  struct Hello *hello;

  GNUNET_assert (NULL == p->sh_head);
  while (NULL != (hello = p->h_head))
  {
    GNUNET_CONTAINER_DLL_remove (p->h_head,
                                 p->h_tail,
                                 hello);
    GNUNET_assert (NULL == hello->sh);
    GNUNET_free (hello);
  }
  if (NULL != p->task)
  {
    GNUNET_SCHEDULER_cancel (p->task);
    p->task = NULL;
  }
  if (NULL != p->wc)
  {
    GNUNET_PEERSTORE_watch_cancel (p->wc);
    p->wc = NULL;
  }
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (h->peers,
                                                       &p->pid,
                                                       p));
  GNUNET_free (p);
}


/**
 * Check if the new allocation for @a sh is significantly different
 * from the last one, and if so, tell transport.
 *
 * @param sh session handle to consider updating transport for
 */
static void
consider_notify_transport (struct GNUNET_ATS_SessionHandle *sh)
{
  struct Peer *peer = sh->peer;
  struct SimpleHandle *h = peer->h;
  enum GNUNET_NetworkType nt = sh->data->prop.nt;
  struct GNUNET_TIME_Relative delay;
  uint64_t sig_in;
  uint64_t sig_out;
  int64_t delta_in;
  int64_t delta_out;

  delay = GNUNET_TIME_absolute_get_duration (sh->last_allocation);
  /* A significant change is more than 10% of the quota,
     which is given in bytes/second */
  sig_in
    = h->networks[nt].total_quota_in * (delay.rel_value_us / 1000LL) / 1000LL / 10;
  sig_out
    = h->networks[nt].total_quota_out * (delay.rel_value_us / 1000LL) / 1000LL / 10;
  delta_in = ( (int64_t) ntohl (sh->bw_in.value__)) - ((int64_t) sh->target_in);
  delta_out = ( (int64_t) ntohl (sh->bw_in.value__)) - ((int64_t) sh->target_in);
  /* we want the absolute values */
  if (delta_in < 0)
    delta_in = - delta_in;
  if (INT64_MIN == delta_in)
    delta_in = INT64_MAX;  /* Handle corner case: INT_MIN == - INT_MIN */
  if (delta_out < 0)
    delta_out = - delta_out;
  if (INT64_MIN == delta_out)
    delta_out = INT64_MAX; /* Handle corner case: INT_MIN == - INT_MIN */
  if ( (sig_in > delta_in) &&
       (sig_out > delta_out) )
    return; /* insignificant change */
  /* change is significant, tell transport! */
  if (sh->target_in > UINT32_MAX)
    sh->target_in = UINT32_MAX;
  sh->bw_in.value__ = htonl ((uint32_t) sh->target_in);
  if (sh->target_out > UINT32_MAX)
    sh->target_out = UINT32_MAX;
  sh->bw_out.value__ = htonl ((uint32_t) sh->target_out);
  sh->last_allocation = GNUNET_TIME_absolute_get ();
  h->env->allocate_cb (h->env->cls,
                       sh->session,
                       &peer->pid,
                       sh->bw_in,
                       sh->bw_out);
}


/**
 * Closure for #update_counters and #update_allocation.
 */
struct Counters
{
  /**
   * Plugin's state.
   */
  struct SimpleHandle *h;

  /**
   * Bandwidth that applications would prefer to allocate in this
   * network type.  We initially add all requested allocations to the
   * respective network type where the given preference is best
   * satisfied. Later we may rebalance.
   */
  uint64_t bw_out_by_nt[GNUNET_NT_COUNT];

  /**
   * Current bandwidth utilization for this network type.  We simply
   * add the current goodput up (with some fairness considerations).
   */
  uint64_t bw_in_by_nt[GNUNET_NT_COUNT];

  /**
   * By how much do we have to scale (up or down) our expectations
   * for outbound bandwidth?
   */
  double scale_out[GNUNET_NT_COUNT];

  /**
   * By how much do we have to scale (up or down) our expectations
   * for inbound bandwidth?
   */
  double scale_in[GNUNET_NT_COUNT];

};


/**
 * Function used to iterate over all peers and collect
 * counter data.
 *
 * @param cls a `struct Counters *`
 * @param pid identity of the peer we process, unused
 * @param value a `struct Peer *`
 * @return #GNUNET_YES (continue to iterate)
 */
static int
update_counters (void *cls,
                 const struct GNUNET_PeerIdentity *pid,
                 void *value)
{
  struct Counters *c = cls;
  struct Peer *peer = value;
  struct GNUNET_ATS_SessionHandle *best[GNUNET_MQ_PREFERENCE_COUNT];

  (void) pid;
  if (NULL == peer->sh_head)
    return GNUNET_YES; /* no available session, cannot allocate bandwidth */
  memset (best,
          0,
          sizeof (best));
  for (struct GNUNET_ATS_SessionHandle *sh = peer->sh_head;
       NULL != sh;
       sh = sh->next)
  {
    enum GNUNET_NetworkType nt = sh->data->prop.nt;

    sh->target_out = MIN_BANDWIDTH_PER_SESSION;
    c->bw_out_by_nt[nt] += MIN_BANDWIDTH_PER_SESSION;
    c->bw_in_by_nt[nt] += GNUNET_MAX (MIN_BANDWIDTH_PER_SESSION,
                                      sh->data->prop.goodput_in);
    for (enum GNUNET_MQ_PreferenceKind pk = 0;
         pk < GNUNET_MQ_PREFERENCE_COUNT;
         pk++)
    {
      /* General rule: always prefer smaller distance if possible,
         otherwise decide by pk: */
      switch (pk) {
      case GNUNET_MQ_PREFERENCE_NONE:
        break;
      case GNUNET_MQ_PREFERENCE_BANDWIDTH:
        /* For bandwidth, we compare the sum of transmitted bytes and
           confirmed transmitted bytes, so confirmed data counts twice */
        if ( (NULL == best[pk]) ||
             (sh->data->prop.distance < best[pk]->data->prop.distance) ||
             (sh->data->prop.utilization_out + sh->data->prop.goodput_out >
              best[pk]->data->prop.utilization_out + best[pk]->data->prop.goodput_out) )
          best[pk] = sh;
        /* If both are equal (i.e. usually this happens if there is a zero), use
           latency as a yardstick */
        if ( (sh->data->prop.utilization_out + sh->data->prop.goodput_out ==
              best[pk]->data->prop.utilization_out + best[pk]->data->prop.goodput_out) &&
             (sh->data->prop.distance == best[pk]->data->prop.distance) &&
             (sh->data->prop.delay.rel_value_us <
              best[pk]->data->prop.delay.rel_value_us) )
          best[pk] = sh;
        break;
      case GNUNET_MQ_PREFERENCE_LATENCY:
        if ( (NULL == best[pk]) ||
             (sh->data->prop.distance < best[pk]->data->prop.distance) ||
             ( (sh->data->prop.distance == best[pk]->data->prop.distance) &&
               (sh->data->prop.delay.rel_value_us <
                best[pk]->data->prop.delay.rel_value_us) ) )
          best[pk] = sh;
        break;
      case GNUNET_MQ_PREFERENCE_RELIABILITY:
        /* For reliability, we consider the ratio of goodput to utilization
           (but use multiplicative formultations to avoid division by zero) */
        if ( (NULL == best[pk]) ||
             (1ULL * sh->data->prop.goodput_out * best[pk]->data->prop.utilization_out >
              1ULL * sh->data->prop.utilization_out * best[pk]->data->prop.goodput_out) )
          best[pk] = sh;
        /* If both are equal (i.e. usually this happens if there is a zero), use
           latency as a yardstick */
        if ( (1ULL * sh->data->prop.goodput_out * best[pk]->data->prop.utilization_out ==
              1ULL * sh->data->prop.utilization_out * best[pk]->data->prop.goodput_out) &&
             (sh->data->prop.distance == best[pk]->data->prop.distance) &&
             (sh->data->prop.delay.rel_value_us <
              best[pk]->data->prop.delay.rel_value_us) )
          best[pk] = sh;
        break;
      }
    }
  }
  /* for first round, assign target bandwidth simply to sum of
     requested bandwidth */
  for (enum GNUNET_MQ_PreferenceKind pk = 1 /* skip GNUNET_MQ_PREFERENCE_NONE */;
       pk < GNUNET_MQ_PREFERENCE_COUNT;
       pk++)
  {
    const struct GNUNET_ATS_SessionData *data = best[pk]->data;
    enum GNUNET_NetworkType nt;

    GNUNET_assert (NULL != data);
    nt = data->prop.nt;
    best[pk]->target_out = GNUNET_MIN (peer->bw_by_pk[pk],
                                       MIN_BANDWIDTH_PER_SESSION);
    c->bw_out_by_nt[nt] += (uint64_t) (best[pk]->target_out - MIN_BANDWIDTH_PER_SESSION);
  }
  return GNUNET_YES;
}


/**
 * Function used to iterate over all peers and collect
 * counter data.
 *
 * @param cls a `struct Counters *`
 * @param pid identity of the peer we process, unused
 * @param value a `struct Peer *`
 * @return #GNUNET_YES (continue to iterate)
 */
static int
update_allocation (void *cls,
                   const struct GNUNET_PeerIdentity *pid,
                   void *value)
{
  struct Counters *c = cls;
  struct Peer *peer = value;

  (void) pid;
  for (struct GNUNET_ATS_SessionHandle *sh = peer->sh_head;
       NULL != sh;
       sh = sh->next)
  {
    enum GNUNET_NetworkType nt = sh->data->prop.nt;

    sh->target_out = (uint64_t) (c->scale_out[nt] * sh->target_out);
    sh->target_in = (uint64_t) (c->scale_in[nt] * sh->target_in);
    consider_notify_transport (sh);
  }
  return GNUNET_YES;
}


/**
 * The world changed, recalculate our allocations.
 */
static void
update (struct SimpleHandle *h)
{
  struct Counters cnt = {
    .h = h
  };

  GNUNET_CONTAINER_multipeermap_iterate (h->peers,
                                         &update_counters,
                                         &cnt);
  /* calculate how badly the missmatch between requested
     allocations and available bandwidth is per network type */
  for (enum GNUNET_NetworkType nt = 0;
       nt < GNUNET_NT_COUNT;
       nt++)
  {
    cnt.scale_out[nt] = 1.0 * cnt.bw_out_by_nt[nt] / h->networks[nt].total_quota_out;
    cnt.scale_in[nt] = 1.0 * cnt.bw_in_by_nt[nt] / h->networks[nt].total_quota_in;
  }
  /* recalculate allocations, considering scaling factor, and
     update transport if the change is significant */
  GNUNET_CONTAINER_multipeermap_iterate (h->peers,
                                         &update_allocation,
                                         &cnt);
}


/**
 * The plugin should begin to respect a new preference.
 *
 * @param cls the closure
 * @param pref the preference to add
 * @return plugin's internal representation, or NULL
 */
static struct GNUNET_ATS_PreferenceHandle *
simple_preference_add (void *cls,
		       const struct GNUNET_ATS_Preference *pref)
{
  struct SimpleHandle *h = cls;
  struct Peer *p = peer_add (h,
                             &pref->peer);

  GNUNET_assert (pref->pk < GNUNET_MQ_PREFERENCE_COUNT);
  p->bw_by_pk[pref->pk] += ntohl (pref->bw.value__);
  h->bw_by_pk[pref->pk] += ntohl (pref->bw.value__);
  update (h);
  return NULL;
}


/**
 * The plugin should end respecting a preference.
 *
 * @param cls the closure
 * @param ph whatever @e preference_add returned
 * @param pref the preference to delete
 * @return plugin's internal representation, or NULL
 */
static void
simple_preference_del (void *cls,
		       struct GNUNET_ATS_PreferenceHandle *ph,
		       const struct GNUNET_ATS_Preference *pref)
{
  struct SimpleHandle *h = cls;
  struct Peer *p = lookup_peer (h,
                                &pref->peer);

  GNUNET_assert (NULL != p);
  GNUNET_assert (pref->pk < GNUNET_MQ_PREFERENCE_COUNT);
  p->bw_by_pk[pref->pk] -= ntohl (pref->bw.value__);
  h->bw_by_pk[pref->pk] -= ntohl (pref->bw.value__);
  if ( (0 == p->bw_by_pk[pref->pk]) &&
       (GNUNET_YES == peer_test_dead (p)) )
    peer_free (p);
  update (h);
}


/**
 * Transport established a new session with performance
 * characteristics given in @a data.
 *
 * @param cls closure
 * @param data performance characteristics of @a sh
 * @param address address information (for debugging)
 * @return handle by which the plugin will identify this session
 */
static struct GNUNET_ATS_SessionHandle *
simple_session_add (void *cls,
		    const struct GNUNET_ATS_SessionData *data,
		    const char *address)
{
  struct SimpleHandle *h = cls;
  struct Peer *p = peer_add (h,
                             &data->peer);
  struct Hello *hello;
  size_t alen;
  struct GNUNET_ATS_SessionHandle *sh;

  /* setup session handle */
  GNUNET_assert (NULL != data);
  if (NULL == address)
    alen = 0;
  else
    alen = strlen (address) + 1;
  sh = GNUNET_malloc (sizeof (struct GNUNET_ATS_SessionHandle) + alen);
  sh->peer = p;
  sh->session = data->session;
  sh->data = data;
  if (NULL == address)
  {
    sh->address = NULL;
  }
  else
  {
    memcpy (&sh[1],
            address,
            alen);
    sh->address = (const char *) &sh[1];
  }
  GNUNET_CONTAINER_DLL_insert (p->sh_head,
                               p->sh_tail,
                               sh);
  /* match HELLO */
  hello = p->h_head;
  while ( (NULL != hello) &&
          (0 != strcmp (address,
                        hello->address)) )
    hello = hello->next;
  if (NULL != hello)
  {
    hello->sh = sh;
    hello->backoff = GNUNET_TIME_UNIT_ZERO;
    sh->hello = hello;
  }
  update (h);
  return sh;
}


/**
 * @a data changed for a given @a sh, solver should consider
 * the updated performance characteristics.
 *
 * @param cls closure
 * @param sh session this is about
 * @param data performance characteristics of @a sh
 */
static void
simple_session_update (void *cls,
		       struct GNUNET_ATS_SessionHandle *sh,
		       const struct GNUNET_ATS_SessionData *data)
{
  struct SimpleHandle *h = cls;

  GNUNET_assert (NULL != data);
  sh->data = data; /* this statement should not really do anything... */
  update (h);
}


/**
 * A session went away. Solver should update accordingly.
 *
 * @param cls closure
 * @param sh session this is about
 * @param data (last) performance characteristics of @a sh
 */
static void
simple_session_del (void *cls,
		    struct GNUNET_ATS_SessionHandle *sh,
		    const struct GNUNET_ATS_SessionData *data)
{
  struct SimpleHandle *h = cls;
  struct Peer *p = sh->peer;
  struct Hello *hello = sh->hello;

  /* clean up sh */
  GNUNET_CONTAINER_DLL_remove (p->sh_head,
                               p->sh_tail,
                               sh);
  if (NULL != hello)
  {
    GNUNET_assert (sh == hello->sh);
    hello->sh = NULL;
    /* session went down, if necessary restart suggesting
       addresses */
    if (NULL == p->task)
      p->task = GNUNET_SCHEDULER_add_now (&suggest_start_cb,
                                          p);
  }
  GNUNET_free (sh);
  /* del peer if otherwise dead */
  if ( (NULL == p->sh_head) &&
       (GNUNET_YES == peer_test_dead (p)) )
    peer_free (p);
  update (h);
}


#include "plugin_ats2_common.c"


/**
 * Function invoked when the plugin is loaded.
 *
 * @param[in,out] cls the `struct GNUNET_ATS_PluginEnvironment *` to use;
 *            modified to return the API functions (ugh).
 * @return the `struct SimpleHandle` to pass as a closure
 */
void *
libgnunet_plugin_ats2_simple_init (void *cls)
{
  static struct GNUNET_ATS_SolverFunctions sf;
  struct GNUNET_ATS_PluginEnvironment *env = cls;
  struct SimpleHandle *s;

  s = GNUNET_new (struct SimpleHandle);
  s->env = env;
  s->peers = GNUNET_CONTAINER_multipeermap_create (128,
						   GNUNET_YES);
  s->ps = GNUNET_PEERSTORE_connect (env->cfg);
  sf.cls = s;
  sf.preference_add = &simple_preference_add;
  sf.preference_del = &simple_preference_del;
  sf.session_add = &simple_session_add;
  sf.session_update = &simple_session_update;
  sf.session_del = &simple_session_del;
  for (enum GNUNET_NetworkType nt = 0;
       nt < GNUNET_NT_COUNT;
       nt++)
  {
    const char *name = GNUNET_NT_to_string (nt);

    if (NULL == name)
    {
      GNUNET_break (0);
      break;
    }
    get_quota (env->cfg,
	       name,
	       "IN",
	       &s->networks[nt].total_quota_in);
    get_quota (env->cfg,
	       name,
	       "OUT",
	       &s->networks[nt].total_quota_out);
    s->networks[nt].type = nt;
  }
  return &sf;
}


/**
 * Function used to unload the plugin.
 *
 * @param cls return value from #libgnunet_plugin_ats_proportional_init()
 */
void *
libgnunet_plugin_ats2_simple_done (void *cls)
{
  struct GNUNET_ATS_SolverFunctions *sf = cls;
  struct SimpleHandle *s = sf->cls;

  GNUNET_break (0 ==
                GNUNET_CONTAINER_multipeermap_size (s->peers));
  GNUNET_CONTAINER_multipeermap_destroy (s->peers);
  GNUNET_PEERSTORE_disconnect (s->ps,
			       GNUNET_NO);
  GNUNET_free (s);
  return NULL;
}


/* end of plugin_ats2_simple.c */
