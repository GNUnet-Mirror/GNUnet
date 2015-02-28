/*
     This file is part of GNUnet.
     Copyright (C) 2011-2015 Christian Grothoff (and other contributing authors)

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
 * @file ats/gnunet-service-ats_preferences.c
 * @brief manage preferences expressed by clients
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-ats.h"
#include "gnunet-service-ats_addresses.h"
#include "gnunet-service-ats_performance.h"
#include "gnunet-service-ats_plugins.h"
#include "gnunet-service-ats_preferences.h"
#include "gnunet-service-ats_reservations.h"
#include "ats.h"

#define LOG(kind,...) GNUNET_log_from (kind, "ats-preferences",__VA_ARGS__)

/**
 * How frequently do we age preference values?
 */
#define PREF_AGING_INTERVAL GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

/**
 * By which factor do we age preferences expressed during
 * each #PREF_AGING_INTERVAL?
 */
#define PREF_AGING_FACTOR 0.95

/**
 * What is the lowest threshold up to which prefernce values
 * are aged, and below which we consider them zero and thus
 * no longer subject to aging?
 */
#define PREF_EPSILON 0.01


/**
 * Relative preferences for a peer.
 */
struct PeerRelative
{
  /**
   * Array of relative preference values, to be indexed by
   * an `enum GNUNET_ATS_PreferenceKind`.
   */
  double f_rel[GNUNET_ATS_PREFERENCE_END];

  /**
   * Number of clients that are expressing a preference for
   * this peer. When this counter reaches zero, this entry
   * is freed.
   */
  unsigned int num_clients;
};


/**
 * Default values, returned as our preferences if we do not
 * have any preferences expressed for a peer.
 */
static struct PeerRelative defvalues;


/**
 * Preference information per peer and client.
 */
struct PreferencePeer
{
  /**
   * Next in DLL of preference entries for the same client.
   */
  struct PreferencePeer *next;

  /**
   * Previous in DLL of preference entries for the same client.
   */
  struct PreferencePeer *prev;

  /**
   * Absolute preference values for all preference types
   * as expressed by this client for this peer.
   */
  double f_abs[GNUNET_ATS_PREFERENCE_END];

  /**
   * Relative preference values for all preference types,
   * normalized in [0..1] based on how the respective
   * client scored other peers.
   */
  double f_rel[GNUNET_ATS_PREFERENCE_END];

};


/**
 * Preference client, as in a client that expressed preferences
 * for peers.  This is the information we keep track of for each
 * such client.
 */
struct PreferenceClient
{

  /**
   * Next in client list
   */
  struct PreferenceClient *next;

  /**
   * Previous in client peer list
   */
  struct PreferenceClient *prev;

  /**
   * Client handle
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Mapping peer identities to `struct PreferencePeer` entry
   * for the respective peer.
   */
  struct GNUNET_CONTAINER_MultiPeerMap *peer2pref;

  /**
   * Array of sums of absolute preferences for all
   * peers as expressed by this client.
   */
  double f_abs_sum[GNUNET_ATS_PREFERENCE_END];

};


/**
 * Hashmap to store peer information for preference normalization.
 * Maps the identity of a peer to a `struct PeerRelative` containing
 * the current relative preference values for that peer.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *preference_peers;

/**
 * Clients in DLL: head
 */
static struct PreferenceClient *pc_head;

/**
 * Clients in DLL: tail
 */
static struct PreferenceClient *pc_tail;

/**
 * Handle for task we run periodically to age preferences over time.
 */
static struct GNUNET_SCHEDULER_Task *aging_task;


/**
 * Closure for #sum_relative_preferences().
 */
struct SumContext
{
  /**
   * Where to accumulate the result.
   */
  double f_rel_total;

  /**
   * Which kind of preference value are we adding up?
   */
  enum GNUNET_ATS_PreferenceKind kind;
};


/**
 * Add the relative preference for the kind given to the
 * closure.
 *
 * @param cls the `struct SumContext` with the kind and place
 *                to store the result
 * @param peer ignored
 * @param value the `struct PreferencePeer` for getting the rel pref.
 * @return #GNUNET_OK
 */
static int
sum_relative_preferences (void *cls,
                          const struct GNUNET_PeerIdentity *peer,
                          void *value)
{
  struct SumContext *sum_ctx = cls;
  struct PreferencePeer *p_cur = value;

  sum_ctx->f_rel_total += p_cur->f_rel[sum_ctx->kind];
  return GNUNET_OK;
}


/**
 * Update the total releative preference for a peer by summing
 * up the relative preferences all clients have for this peer.
 *
 * @param id peer id of the peer for which we should do the update
 * @param kind the kind of preference value to update
 * @param rp the relative peer struct where we store the global result
 * @return the new relative preference
 */
static void
update_relative_values_for_peer (const struct GNUNET_PeerIdentity *id,
				 enum GNUNET_ATS_PreferenceKind kind)
{
  struct PreferenceClient *c_cur;
  struct SumContext sum_ctx;
  struct PeerRelative *rp;

  sum_ctx.f_rel_total = 0.0;
  sum_ctx.kind = kind;
  for (c_cur = pc_head; NULL != c_cur; c_cur = c_cur->next)
    GNUNET_CONTAINER_multipeermap_get_multiple (c_cur->peer2pref,
                                                id,
                                                &sum_relative_preferences,
                                                &sum_ctx);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Total relative preference for peer `%s' for `%s' is %.3f\n",
       GNUNET_i2s (id),
       GNUNET_ATS_print_preference_type (kind),
       sum_ctx.f_rel_total);
  rp = GNUNET_CONTAINER_multipeermap_get (preference_peers,
                                          id);
  GNUNET_assert (NULL != rp);
  if (rp->f_rel[kind] != sum_ctx.f_rel_total)
  {
    rp->f_rel[kind] = sum_ctx.f_rel_total;
    GAS_plugin_notify_preference_changed (id,
                                          kind,
                                          rp->f_rel[kind]);
  }
}


/**
 * Free a peer's `struct PeerRelative`.
 *
 * @param cls unused
 * @param key the key
 * @param value the `struct PeerRelative` to free.
 * @return #GNUNET_OK to continue
 */
static int
free_peer (void *cls,
           const struct GNUNET_PeerIdentity *key,
           void *value)
{
  struct PeerRelative *rp = value;

  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (preference_peers,
                                                       key,
                                                       value));
  GNUNET_free (rp);
  return GNUNET_OK;
}


/**
 * Free `struct PreferencePeer` entry in map.
 *
 * @param cls the `struct PreferenceClient` with the map
 * @param key the peer the entry is for
 * @param value the `struct PreferencePeer` entry to free
 * @return #GNUNET_OK (continue to iterate)
 */
static int
free_preference (void *cls,
                 const struct GNUNET_PeerIdentity *key,
                 void *value)
{
  struct PreferenceClient *pc = cls;
  struct PreferencePeer *p = value;
  struct PeerRelative *pr;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multipeermap_remove (pc->peer2pref,
                                                       key,
                                                       p));
  GNUNET_free (p);
  pr = GNUNET_CONTAINER_multipeermap_get (preference_peers,
                                          key);
  GNUNET_assert (NULL != pr);
  GNUNET_assert (pr->num_clients > 0);
  pr->num_clients--;
  if (0 == pr->num_clients)
  {
    free_peer (NULL,
               key,
               pr);
  }
  return GNUNET_OK;
}


/**
 * Closure for #age_values().
 */
struct AgeContext
{
  /**
   * Counter of values remaining to update, incremented for each value
   * changed (to a new non-zero value).
   */
  unsigned int values_to_update;

  /**
   * Client we are currently aging values for.
   */
  struct PreferenceClient *cur_client;

};


/**
 * Age preference values of the given peer.
 *
 * @param cls a `
 * @param peer peer being aged
 * @param value the `struct PreferencePeer` for the peer
 * @return #GNUNET_OK (continue to iterate)
 */
static int
age_values (void *cls,
            const struct GNUNET_PeerIdentity *peer,
            void *value)
{
  struct AgeContext *ac = cls;
  struct PreferencePeer *p = value;
  unsigned int i;
  int dead;

  dead = GNUNET_YES;
  for (i = 0; i < GNUNET_ATS_PREFERENCE_END; i++)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Aging preference for peer `%s'\n",
                GNUNET_i2s (peer));
    if (p->f_abs[i] > DEFAULT_ABS_PREFERENCE)
      p->f_abs[i] *= PREF_AGING_FACTOR;
    if (p->f_abs[i] <= DEFAULT_ABS_PREFERENCE + PREF_EPSILON)
    {
      p->f_abs[i] = DEFAULT_ABS_PREFERENCE;
      p->f_rel[i] = DEFAULT_REL_PREFERENCE;
      update_relative_values_for_peer (peer,
                                       i);
    }
    else
    {
      ac->values_to_update++;
      dead = GNUNET_NO;
    }
  }
  if (GNUNET_YES == dead)
  {
    /* all preferences are zero, remove this entry */
    free_preference (ac->cur_client,
                     peer,
                     p);
  }
  return GNUNET_OK;
}


/**
 * Reduce absolute preferences since they got old.
 *
 * @param cls unused
 * @param tc context
 */
static void
preference_aging (void *cls,
                  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct AgeContext ac;

  aging_task = NULL;
  GAS_plugin_solver_lock ();
  ac.values_to_update = 0;
  for (ac.cur_client = pc_head; NULL != ac.cur_client; ac.cur_client = ac.cur_client->next)
    GNUNET_CONTAINER_multipeermap_iterate (ac.cur_client->peer2pref,
                                           &age_values,
                                           &ac);
  GAS_plugin_solver_unlock ();
  if (ac.values_to_update > 0)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Rescheduling aging task due to %u elements remaining to age\n",
                ac.values_to_update);
    if (NULL == aging_task)
      aging_task = GNUNET_SCHEDULER_add_delayed (PREF_AGING_INTERVAL,
                                                 &preference_aging,
                                                 NULL);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No values to age left, not rescheduling aging task\n");
  }
}


/**
 * Closure for #update_rel_sum() and #update_abs_sum().
 */
struct UpdateContext
{
  /**
   * Preference client with the sum of all absolute scores.
   */
  struct PreferenceClient *pc;

  /**
   * Which kind are we updating?
   */
  enum GNUNET_ATS_PreferenceKind kind;

};


/**
 * Compute updated absolute score for the client based on the
 * current absolute scores for each peer.
 *
 * @param cls a `struct UpdateContext`
 * @param peer peer being updated
 * @param value the `struct PreferencePeer` for the peer
 * @return #GNUNET_OK (continue to iterate)
 */
static int
update_abs_sum (void *cls,
                const struct GNUNET_PeerIdentity *peer,
                void *value)
{
  struct UpdateContext *uc = cls;
  struct PreferencePeer *p_cur = value;

  uc->pc->f_abs_sum[uc->kind] += p_cur->f_abs[uc->kind];
  return GNUNET_OK;
}


/**
 * Compute updated relative score for each peer based on the
 * current absolute score given by this client.
 *
 * @param cls a `struct UpdateContext`
 * @param peer peer being updated
 * @param value the `struct PreferencePeer` for the peer (updated)
 * @return #GNUNET_OK (continue to iterate)
 */
static int
update_rel_sum (void *cls,
                const struct GNUNET_PeerIdentity *peer,
                void *value)
{
  struct UpdateContext *uc = cls;
  struct PreferencePeer *p_cur = value;

  p_cur->f_rel[uc->kind] = p_cur->f_abs[uc->kind] / uc->pc->f_abs_sum[uc->kind];
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Client has relative preference for %s for peer `%s' of %.3f\n",
       GNUNET_ATS_print_preference_type (uc->kind),
       GNUNET_i2s (peer),
       p_cur->f_rel[uc->kind]);
  return GNUNET_OK;
}


/**
 * Recalculate preference for a specific ATS property
 *
 * @param c the preference client
 * @param kind the preference kind
 * @return the result
 */
static void
recalculate_relative_preferences (struct PreferenceClient *c,
                                  enum GNUNET_ATS_PreferenceKind kind)
{
  struct UpdateContext uc;

  /* For this client: sum of absolute preference values for this preference */
  uc.kind = kind;
  uc.pc = c;
  c->f_abs_sum[kind] = 0.0;

  /* For all peers: calculate sum of absolute preferences */
  GNUNET_CONTAINER_multipeermap_iterate (c->peer2pref,
                                         &update_abs_sum,
                                         &uc);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Client has sum of total preferences for %s of %.3f\n",
       GNUNET_ATS_print_preference_type (kind),
       c->f_abs_sum[kind]);

  /* For all peers: calculate relative preference */
  GNUNET_CONTAINER_multipeermap_iterate (c->peer2pref,
                                         &update_rel_sum,
                                         &uc);
}


/**
 * The relative preferences of one of the clients have
 * changed, update the global preferences for the given
 * peer and notify the plugin.
 *
 * @param value the kind of preference to calculate the
 *        new global relative preference values for
 * @param key the peer to update relative preference values for
 * @param value a `struct PeerRelative`, unused
 */
static int
update_iterator (void *cls,
                 const struct GNUNET_PeerIdentity *key,
                 void *value)
{
  enum GNUNET_ATS_PreferenceKind *kind = cls;

  update_relative_values_for_peer (key,
                                   *kind);
  return GNUNET_OK;
}


/**
 * Update the absolute preference and calculate the
 * new relative preference value.
 *
 * @param client the client with this preference
 * @param peer the peer to change the preference for
 * @param kind the kind to change the preference
 * @param score_abs the normalized score
 */
static void
update_preference (struct GNUNET_SERVER_Client *client,
                   const struct GNUNET_PeerIdentity *peer,
                   enum GNUNET_ATS_PreferenceKind kind,
                   float score_abs)
{
  struct PreferenceClient *c_cur;
  struct PreferencePeer *p_cur;
  struct PeerRelative *r_cur;
  unsigned int i;

  if (kind >= GNUNET_ATS_PREFERENCE_END)
  {
    GNUNET_break(0);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Client changes preference for peer `%s' for `%s' to %.2f\n",
       GNUNET_i2s (peer),
       GNUNET_ATS_print_preference_type (kind),
       score_abs);

  /* Find preference client */
  for (c_cur = pc_head; NULL != c_cur; c_cur = c_cur->next)
    if (client == c_cur->client)
      break;
  /* Not found: create new preference client */
  if (NULL == c_cur)
  {
    c_cur = GNUNET_new (struct PreferenceClient);
    c_cur->peer2pref = GNUNET_CONTAINER_multipeermap_create (16,
                                                             GNUNET_NO);
    for (i = 0; i < GNUNET_ATS_PREFERENCE_END; i++)
      c_cur->f_abs_sum[i] = DEFAULT_ABS_PREFERENCE;
    GNUNET_CONTAINER_DLL_insert (pc_head,
                                 pc_tail,
                                 c_cur);
  }

  /* check global peer entry exists */
  if (NULL ==
      (r_cur = GNUNET_CONTAINER_multipeermap_get (preference_peers,
                                                  peer)))
  {
    /* Create struct for peer */
    r_cur = GNUNET_new (struct PeerRelative);
    for (i = 0; i < GNUNET_ATS_PREFERENCE_END; i++)
      r_cur->f_rel[i] = DEFAULT_REL_PREFERENCE;
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multipeermap_put (preference_peers,
                                                      peer,
                                                      r_cur,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }

  /* Find entry for peer */
  p_cur = GNUNET_CONTAINER_multipeermap_get (c_cur->peer2pref,
                                             peer);
  if (NULL == p_cur)
  {
    /* Not found: create new peer entry */
    p_cur = GNUNET_new (struct PreferencePeer);
    for (i = 0; i < GNUNET_ATS_PREFERENCE_END; i++)
    {
      /* Default value per peer absolute preference for a preference*/
      p_cur->f_abs[i] = DEFAULT_ABS_PREFERENCE;
      /* Default value per peer relative preference for a quality */
      p_cur->f_rel[i] = DEFAULT_REL_PREFERENCE;
    }
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multipeermap_put (c_cur->peer2pref,
                                                      peer,
                                                      p_cur,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
    r_cur->num_clients++;
  }

  p_cur->f_abs[kind] += score_abs;
  recalculate_relative_preferences (c_cur, kind);
  GNUNET_CONTAINER_multipeermap_iterate (preference_peers,
					 &update_iterator,
					 &kind);

  if (NULL == aging_task)
    aging_task = GNUNET_SCHEDULER_add_delayed (PREF_AGING_INTERVAL,
                                               &preference_aging,
                                               NULL);
}


/**
 * Handle 'preference change' messages from clients.
 *
 * @param cls unused, NULL
 * @param client client that sent the request
 * @param message the request message
 */
void
GAS_handle_preference_change (void *cls,
                              struct GNUNET_SERVER_Client *client,
                              const struct GNUNET_MessageHeader *message)
{
  const struct ChangePreferenceMessage *msg;
  const struct PreferenceInformation *pi;
  uint16_t msize;
  uint32_t nump;
  uint32_t i;

  msize = ntohs (message->size);
  if (msize < sizeof (struct ChangePreferenceMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client,
                                GNUNET_SYSERR);
    return;
  }
  msg = (const struct ChangePreferenceMessage *) message;
  nump = ntohl (msg->num_preferences);
  if ( (msize !=
        sizeof (struct ChangePreferenceMessage) +
        nump * sizeof (struct PreferenceInformation)) ||
       (UINT16_MAX / sizeof (struct PreferenceInformation) < nump) )
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client,
                                GNUNET_SYSERR);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received PREFERENCE_CHANGE message for peer `%s'\n",
              GNUNET_i2s (&msg->peer));
  GNUNET_STATISTICS_update (GSA_stats,
                            "# preference change requests processed",
                            1,
                            GNUNET_NO);
  pi = (const struct PreferenceInformation *) &msg[1];
  GAS_plugin_solver_lock ();
  for (i = 0; i < nump; i++)
    update_preference (client,
                       &msg->peer,
                       (enum GNUNET_ATS_PreferenceKind) ntohl (pi[i].preference_kind),
                       pi[i].preference_value);
  GAS_plugin_solver_unlock ();
  GNUNET_SERVER_receive_done (client,
                              GNUNET_OK);
}


/**
 * Initialize preferences subsystem.
 */
void
GAS_preference_init ()
{
  unsigned int i;

  preference_peers = GNUNET_CONTAINER_multipeermap_create (16,
                                                           GNUNET_NO);
  for (i = 0; i < GNUNET_ATS_PREFERENCE_END; i++)
    defvalues.f_rel[i] = DEFAULT_REL_PREFERENCE;
}


/**
 * Shutdown preferences subsystem.
 */
void
GAS_preference_done ()
{
  struct PreferenceClient *pc;
  struct PreferenceClient *next_pc;

  if (NULL != aging_task)
  {
    GNUNET_SCHEDULER_cancel (aging_task);
    aging_task = NULL;
  }
  next_pc = pc_head;
  while (NULL != (pc = next_pc))
  {
    next_pc = pc->next;
    GNUNET_CONTAINER_DLL_remove (pc_head,
                                 pc_tail,
                                 pc);
    GNUNET_CONTAINER_multipeermap_iterate (pc->peer2pref,
                                           &free_preference,
                                           pc);
    GNUNET_CONTAINER_multipeermap_destroy (pc->peer2pref);
    GNUNET_free (pc);
  }
  GNUNET_CONTAINER_multipeermap_iterate (preference_peers,
					 &free_peer,
                                         NULL);
  GNUNET_CONTAINER_multipeermap_destroy (preference_peers);

}


/**
 * Get the normalized preference values for a specific peer or
 * the default values if
 *
 * @param cls ignored
 * @param id the peer
 * @return pointer to the values, can be indexed with GNUNET_ATS_PreferenceKind,
 * default preferences if peer does not exist
 */
const double *
GAS_preference_get_by_peer (void *cls,
                            const struct GNUNET_PeerIdentity *id)
{
  struct PeerRelative *rp;

  if (NULL ==
      (rp = GNUNET_CONTAINER_multipeermap_get (preference_peers,
                                               id)))
  {
    return defvalues.f_rel;
  }
  return rp->f_rel;
}


/**
 * A performance client disconnected
 *
 * @param client the client
 */
void
GAS_preference_client_disconnect (struct GNUNET_SERVER_Client *client)
{
  struct PreferenceClient *c_cur;

  for (c_cur = pc_head; NULL != c_cur; c_cur = c_cur->next)
    if (client == c_cur->client)
      break;
  if (NULL == c_cur)
    return;
  GNUNET_CONTAINER_DLL_remove (pc_head,
                               pc_tail,
                               c_cur);
  GNUNET_CONTAINER_multipeermap_iterate (c_cur->peer2pref,
                                         &free_preference,
                                         c_cur);
  GNUNET_CONTAINER_multipeermap_destroy (c_cur->peer2pref);
  GNUNET_free (c_cur);
}


/* end of gnunet-service-ats_preferences.c */
