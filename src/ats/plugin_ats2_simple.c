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
 */
/**
 * @file ats/plugin_ats2_simple.c
 * @brief ATS simple solver
 * @author Matthias Wachs
 * @author Christian Grothoff
 *
 * TODO:
 * - subscribe to PEERSTORE when short on HELLOs (given application preferences!)
 * - keep track of HELLOs and when we tried them last => re-suggest
 * - sum up preferences per peer, keep totals! => PeerMap pid -> [preferences + sessions + addrs!]
 * - sum up preferences overall, keep global sum => starting point for "proportional"
 * - store DLL of available sessions per peer
 */
#include "platform.h"
#include "gnunet_ats_plugin_new.h"
#include "gnunet_peerstore_service.h"

#define LOG(kind,...) GNUNET_log_from (kind, "ats-simple",__VA_ARGS__)


/**
 * A handle for the proportional solver
 */
struct SimpleHandle;


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
   * The address we could try.
   */
  const char *address;

  /**
   * When did we try it last?
   */
  struct GNUNET_TIME_Absolute last_attempt;

  /**
   * Current exponential backoff value.
   */
  struct GNUNET_TIME_Relative backoff;

  /**
   * Is a session with this address already up?
   * If not, set to NULL.
   */
  struct GNUNET_ATS_SessionHandle *sh;

};


/**
 * Information about preferences and sessions we track
 * per peer.
 */
struct Peer;


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
   * Last BW-in allocation given to the transport service.
   */
  struct GNUNET_BANDWIDTH_Value32NBO bw_in;

  /**
   * Last BW-out allocation given to the transport service.
   */
  struct GNUNET_BANDWIDTH_Value32NBO bw_out;

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
   * Which peer is this for?
   */
  struct GNUNET_PeerIdentity pid;

  /**
   * Array where we sum up the bandwidth requests received indexed
   * by preference kind (see `enum GNUNET_MQ_PreferenceKind`)
   */
  uint64_t bw_by_pk[GNUNET_MQ_PREFERENCE_COUNT];

  /**
   * Watch context where we are currently looking for HELLOs for
   * this peer.
   */
  struct GNUNET_PEERSTORE_WatchContext *wc;

  /**
   * Task used to try again to suggest an address for this peer.
   */
  struct GNUNET_SCHEDULER_Task *task;

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
   * Information we track per network type (quotas).
   */
  struct Network networks[GNUNET_NT_COUNT];

  /**
   * Handle to the peerstore service.
   */
  struct GNUNET_PEERSTORE_Handle *ps;

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

  // FIXME: process hello!
  // check for expiration
  // (add to p's doubly-linked list)

  if (NULL == p->task)
  {
    // start suggestion task!
  }
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
                                  "HELLO" /* key */,
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
 * The world changed, recalculate our allocations.
 */
static void
update (struct SimpleHandle *h)
{
  // recalculate allocations
  // notify transport if it makes sense (delta significant)
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
    sh->hello = hello;
  }
  update (h);
  return NULL;
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

  // FIXME: tear down session
  // del peer if otherwise dead


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

  // FIXME: iterate over peers and clean up!
  GNUNET_CONTAINER_multipeermap_destroy (s->peers);
  GNUNET_PEERSTORE_disconnect (s->ps,
			       GNUNET_NO);
  GNUNET_free (s);
  return NULL;
}


/* end of plugin_ats2_simple.c */
