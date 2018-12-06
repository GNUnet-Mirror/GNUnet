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
   * Which peer is this for?
   */
  struct GNUNET_PeerIdentity pid;

  /**
   * Array where we sum up the bandwidth requests received indexed
   * by preference kind (see `struct GNUNET_MQ_PreferenceKind`)
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
  struct GNUNET_SCHEDULER_TaskHandle *task;  
 
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
  // Setup peer if necessary (-> including HELLO triggers!)
  // add pref to bw_by_pk
  // trigger update
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
  // find peer
  // subtract pref from bw_by_pk
  // remove peer if otherwise dead
  // trigger update
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

  // find or add peer if necessary
  // setup session
  // match HELLO
  // trigger update
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
  // trigger update
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
  // tear down session
  // del peer if otherwise dead
  // trigger update
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
