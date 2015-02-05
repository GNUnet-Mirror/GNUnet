/*
     This file is part of GNUnet.
     (C) 2011-2015 Christian Grothoff (and other contributing authors)

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
 * @brief ats service, interaction with 'performance' API
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

#define LOG(kind,...) GNUNET_log_from (kind, "ats-preferencesx",__VA_ARGS__)

#define PREF_AGING_INTERVAL GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)
#define PREF_AGING_FACTOR 0.95
#define PREF_EPSILON 0.01


/**
 * Relative preferences for a peer
 */
struct PeerRelative
{
  /**
   * Relative preference values
   */
  double f_rel[GNUNET_ATS_PreferenceCount];

  /**
   * Peer id
   */
  struct GNUNET_PeerIdentity id;
};


/**
 * FIXME
 */
struct GAS_Addresses_Preference_Clients
{
  /**
   * Next in DLL
   */
  struct GAS_Addresses_Preference_Clients *next;

  /**
   * Previous in DLL
   */
  struct GAS_Addresses_Preference_Clients *prev;

  /**
   * Peer ID
   */
  void *client;
};


/**
 * Preference requests DLL head
 */
static struct GAS_Addresses_Preference_Clients *preference_clients_head;

/**
 * Preference requests DLL head
 */
static struct GAS_Addresses_Preference_Clients *preference_clients_tail;

/**
 * Preferences clients
 */
static int pref_clients;

/**
 * Default values
 */
static struct PeerRelative defvalues;



/**
 * Preference client
 */
struct PreferenceClient
{
  /**
   * Next in DLL
   */
  struct PreferenceClient *prev;

  /**
   * Next in DLL
   */
  struct PreferenceClient *next;

  /**
   * Client handle
   */
  void *client;

  /**
   * Array of sum of absolute preferences for this client
   */
  double f_abs_sum[GNUNET_ATS_PreferenceCount];

  /**
   * Array of sum of relative preferences for this client
   */
  double f_rel_sum[GNUNET_ATS_PreferenceCount];

  /**
   * Head of peer list
   */
  struct PreferencePeer *p_head;

  /**
   * Tail of peer list
   */
  struct PreferencePeer *p_tail;
};


/**
 * Preference peer
 */
struct PreferencePeer
{
  /**
   * Next in DLL
   */
  struct PreferencePeer *next;

  /**
   * Previous in DLL
   */
  struct PreferencePeer *prev;

  /**
   * Client
   */
  struct PreferenceClient *client;

  /**
   * Peer id
   */
  struct GNUNET_PeerIdentity id;

  /**
   * Absolute preference values for all preference types
   */
  double f_abs[GNUNET_ATS_PreferenceCount];

  /**
   * Relative preference values for all preference types
   */
  double f_rel[GNUNET_ATS_PreferenceCount];

  /**
   * Absolute point of time of next aging process
   */
  struct GNUNET_TIME_Absolute next_aging[GNUNET_ATS_PreferenceCount];
};


/**
 * Hashmap to store peer information for preference normalization
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



static struct GNUNET_SCHEDULER_Task * aging_task;




static struct GAS_Addresses_Preference_Clients *
find_preference_client (struct GNUNET_SERVER_Client *client)
{
  struct GAS_Addresses_Preference_Clients *cur;

  for (cur = preference_clients_head; NULL != cur; cur = cur->next)
    if (cur->client == client)
      return cur;
  return NULL;
}


/**
 * Update a peer
 *
 * @param id peer id
 * @param kind the kind
 * @param rp the relative peer struct
 * @return the new relative preference
 */
static void
update_relative_values_for_peer (const struct GNUNET_PeerIdentity *id,
				 enum GNUNET_ATS_PreferenceKind kind,
				 struct PeerRelative *rp)
{
  struct PreferenceClient *c_cur;
  struct PreferencePeer *p_cur;
  double f_rel_total;
  double f_rel_sum;
  double backup;
  unsigned int peer_count;

  f_rel_sum = 0.0;
  f_rel_total = 0.0;
  peer_count = 0;

  /* For all clients */
  for (c_cur = pc_head; NULL != c_cur; c_cur = c_cur->next)
  {
    /* For peer entries with this id */
    for (p_cur = c_cur->p_head; NULL != p_cur; p_cur = p_cur->next)
    {
      f_rel_sum += p_cur->f_rel[kind];
      if (0 == memcmp (id, &p_cur->id, sizeof(struct GNUNET_PeerIdentity)))
      {
        peer_count ++;
        f_rel_total += p_cur->f_rel[kind];
      }

    }
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "%u clients have a total relative preference for peer `%s' `%s' of %.3f and for %s in total %.3f\n",
      peer_count, GNUNET_i2s (id),
      GNUNET_ATS_print_preference_type (kind),
      f_rel_total,
      GNUNET_ATS_print_preference_type (kind),
      f_rel_sum);

  /* Find entry for the peer containing relative values in the hashmap */
  if (NULL != rp)
  {
    backup = rp->f_rel[kind];
    if (f_rel_sum > 0)
      rp->f_rel[kind] = f_rel_total / f_rel_sum;
    else
    {
      /* No client had any preferences for this type and any peer */
      rp->f_rel[kind] = DEFAULT_REL_PREFERENCE;
    }
    if (backup != rp->f_rel[kind])
      GAS_normalized_preference_changed (&rp->id, kind, rp->f_rel[kind]);
  }
}


static int
update_iterator (void *cls,
                 const struct GNUNET_PeerIdentity *key,
                 void *value)
{
  enum GNUNET_ATS_PreferenceKind *kind = cls;
  struct PeerRelative *pr = value;

  update_relative_values_for_peer (key,
                                   *kind,
                                   pr);
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
  struct PreferencePeer *p_cur;

  /* For this client: sum of absolute preference values for this preference */
  c->f_abs_sum[kind] = 0.0;
  /* For this client: sum of relative preference values for this preference
   *
   * Note: this value should also be 1.0, but:
   * if no preferences exist due to aging, this value can be 0.0
   * and the client can be removed */
  c->f_rel_sum[kind] = 0.0;

  for (p_cur = c->p_head; NULL != p_cur; p_cur = p_cur->next)
    c->f_abs_sum[kind] += p_cur->f_abs[kind];
  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Client %p has sum of total preferences for %s of %.3f\n",
      c->client, GNUNET_ATS_print_preference_type (kind), c->f_abs_sum[kind]);

  /* For all peers: calculate relative preference */
  for (p_cur = c->p_head; NULL != p_cur; p_cur = p_cur->next)
  {
    /* Calculate relative preference for specific kind */

    /* Every application has a preference for each peer between
     * [0 .. 1] in relative values
     * and [0 .. inf] in absolute values */
    p_cur->f_rel[kind] =  p_cur->f_abs[kind] / c->f_abs_sum[kind];
    c->f_rel_sum[kind] += p_cur->f_rel[kind];

    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Client %p has relative preference for %s for peer `%s' of %.3f\n",
        c->client,
        GNUNET_ATS_print_preference_type (kind),
        GNUNET_i2s (&p_cur->id),
        p_cur->f_rel[kind]);
  }

}



static void
run_preference_update (struct PreferenceClient *c_cur,
                       struct PreferencePeer *p_cur,
                       enum GNUNET_ATS_PreferenceKind kind,
                       float score_abs)
{
  double old_value;

  /* Update relative value */
  old_value = p_cur->f_rel[kind];
  recalculate_relative_preferences (c_cur, kind);
  if (p_cur->f_rel[kind] == old_value)
    return;

  /* Relative preference value changed, recalculate for all peers */
  GNUNET_CONTAINER_multipeermap_iterate (preference_peers,
					 &update_iterator,
					 &kind);
}




/**
 * Reduce absolute preferences since they got old
 *
 * @param cls the PreferencePeer
 * @param tc context
 */
static void
preference_aging (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PreferencePeer *p;
  struct PreferenceClient *cur_client;
  int i;
  int values_to_update;
  double backup;

  aging_task = NULL;
  values_to_update = 0;
  cur_client = NULL;

  for (cur_client = pc_head; NULL != cur_client; cur_client = cur_client->next)
  {
    for (p = cur_client->p_head; NULL != p; p = p->next)
    {
      /* Aging absolute values: */
      for (i = 0; i < GNUNET_ATS_PreferenceCount; i++)
      {
        if (0
            == GNUNET_TIME_absolute_get_remaining (p->next_aging[i]).rel_value_us)
        {
          GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
              "Aging preference for peer `%s'\n", GNUNET_i2s (&p->id));
          backup = p->f_abs[i];
          if (p->f_abs[i] > DEFAULT_ABS_PREFERENCE)
            p->f_abs[i] *= PREF_AGING_FACTOR;

          if (p->f_abs[i] <= DEFAULT_ABS_PREFERENCE + PREF_EPSILON)
            p->f_abs[i] = DEFAULT_ABS_PREFERENCE;

          if ( (p->f_abs[i] != DEFAULT_ABS_PREFERENCE) &&
               (backup != p->f_abs[i]) )
          {
            GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                "Aged preference for peer `%s' from %.3f to %.3f\n",
                GNUNET_i2s (&p->id), backup, p->f_abs[i]);

            run_preference_update(cur_client, p, i, p->f_abs[i]);

            p->next_aging[i] = GNUNET_TIME_absolute_add (
                GNUNET_TIME_absolute_get (), PREF_AGING_INTERVAL);
            values_to_update++;
          }
        }
      }
    }
  }

  if (values_to_update > 0)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
        "Rescheduling aging task due to %u elements to age\n",
        values_to_update);
    aging_task = GNUNET_SCHEDULER_add_delayed (PREF_AGING_INTERVAL,
        &preference_aging, NULL );
  }
  else
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
        "No values to age left, not rescheduling aging task\n");

}


/**
 * Update the absolute preference value for a peer
 * @param c the client
 * @param p the peer
 * @param kind the preference kind
 * @param score_abs the absolute value
 * @return the new relative preference value
 */
static void
update_abs_preference (struct PreferenceClient *c,
                       struct PreferencePeer *p,
                       enum GNUNET_ATS_PreferenceKind kind,
                       float score_abs)
{
  double score = score_abs;

  /* Update preference value according to type */
  switch (kind)
  {
  case GNUNET_ATS_PREFERENCE_BANDWIDTH:
  case GNUNET_ATS_PREFERENCE_LATENCY:
    p->f_abs[kind] = score;
    /* p->f_abs[kind] = (p->f_abs[kind] + score) / 2;  */
    p->next_aging[kind] = GNUNET_TIME_absolute_add (GNUNET_TIME_absolute_get (),
        PREF_AGING_INTERVAL);
    break;
  case GNUNET_ATS_PREFERENCE_END:
    break;
  default:
    break;
  }
}





/**
 * A performance client disconnected
 *
 * @param client the client
 */
void
GAS_preference_client_disconnect (struct GNUNET_SERVER_Client *client)
{
  struct GAS_Addresses_Preference_Clients *pc;

  if (NULL != (pc = find_preference_client (client)))
  {
    GNUNET_CONTAINER_DLL_remove (preference_clients_head,
                                 preference_clients_tail,
                                 pc);
    GNUNET_free (pc);
    GNUNET_assert (pref_clients > 0);
    pref_clients --;
    GNUNET_STATISTICS_set (GSA_stats,
                           "# active performance clients",
                           pref_clients,
                           GNUNET_NO);
  }
}


/**
 * Change the preference for a peer
 *
 * @param client the client sending this request
 * @param peer the peer id
 * @param kind the preference kind to change
 * @param score_abs the new preference score
 */
static void
preference_change (struct GNUNET_SERVER_Client *client,
                    const struct GNUNET_PeerIdentity *peer,
                    enum GNUNET_ATS_PreferenceKind kind,
                    float score_abs)
{
  struct GAS_Addresses_Preference_Clients *pc;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
      "Received `%s' for peer `%s' for client %p\n", "CHANGE PREFERENCE",
      GNUNET_i2s (peer), client);

  if (GNUNET_NO ==
      GNUNET_CONTAINER_multipeermap_contains (GSA_addresses,
					      peer))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
        "Received `%s' for unknown peer `%s' from client %p\n",
        "CHANGE PREFERENCE", GNUNET_i2s (peer), client);
    return;
  }

  if (NULL == find_preference_client (client))
  {
    pc = GNUNET_new (struct GAS_Addresses_Preference_Clients);
    pc->client = client;
    GNUNET_CONTAINER_DLL_insert (preference_clients_head,
                                 preference_clients_tail,
                                 pc);
    pref_clients ++;
    GNUNET_STATISTICS_set (GSA_stats,
                           "# active performance clients",
                           pref_clients,
                           GNUNET_NO);
  }
  GAS_plugin_update_preferences (client, peer, kind, score_abs);
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' message\n",
              "PREFERENCE_CHANGE");
  msize = ntohs (message->size);
  if (msize < sizeof (struct ChangePreferenceMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  msg = (const struct ChangePreferenceMessage *) message;
  nump = ntohl (msg->num_preferences);
  if (msize !=
      sizeof (struct ChangePreferenceMessage) +
      nump * sizeof (struct PreferenceInformation))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_STATISTICS_update (GSA_stats,
                            "# preference change requests processed",
                            1, GNUNET_NO);
  pi = (const struct PreferenceInformation *) &msg[1];
  for (i = 0; i < nump; i++)
    preference_change (client,
                       &msg->peer,
                       (enum GNUNET_ATS_PreferenceKind)
                       ntohl (pi[i].preference_kind),
                       pi[i].preference_value);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Initialize preferences subsystem.
 */
void
GAS_preference_init ()
{
  int i;

  preference_peers = GNUNET_CONTAINER_multipeermap_create (10, GNUNET_NO);
  for (i = 0; i < GNUNET_ATS_PreferenceCount; i++)
    defvalues.f_rel[i] = DEFAULT_REL_PREFERENCE;
}


/**
 * Free a peer
 *
 * @param cls unused
 * @param key the key
 * @param value RelativePeer
 * @return #GNUNET_OK to continue
 */
static int
free_peer (void *cls,
           const struct GNUNET_PeerIdentity *key,
           void *value)
{
  struct PeerRelative *rp = value;

  if (GNUNET_YES ==
      GNUNET_CONTAINER_multipeermap_remove (preference_peers,
                                            key,
                                            value))
    GNUNET_free (rp);
  else
    GNUNET_break (0);
  return GNUNET_OK;
}


static void
free_client (struct PreferenceClient *pc)
{
  struct PreferencePeer *next_p;
  struct PreferencePeer *p;

  next_p = pc->p_head;
  while (NULL != (p = next_p))
  {
    next_p = p->next;
    GNUNET_CONTAINER_DLL_remove(pc->p_head, pc->p_tail, p);
    GNUNET_free(p);
  }
  GNUNET_free(pc);
}


/**
 * Shutdown preferences subsystem.
 */
void
GAS_preference_done ()
{
  struct GAS_Addresses_Preference_Clients *pcur;
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
    GNUNET_CONTAINER_DLL_remove(pc_head, pc_tail, pc);
    free_client (pc);
  }
  GNUNET_CONTAINER_multipeermap_iterate (preference_peers,
					 &free_peer,
                                         NULL);
  GNUNET_CONTAINER_multipeermap_destroy (preference_peers);

  while (NULL != (pcur = preference_clients_head))
  {
    GNUNET_CONTAINER_DLL_remove (preference_clients_head,
                                 preference_clients_tail,
                                 pcur);
    GNUNET_assert (pref_clients > 0);
    pref_clients --;
    GNUNET_STATISTICS_set (GSA_stats,
                           "# active performance clients",
                           pref_clients,
                           GNUNET_NO);
    GNUNET_free (pcur);
  }
}


/**
 * Normalize an updated preference value
 *
 * @param client the client with this preference
 * @param peer the peer to change the preference for
 * @param kind the kind to change the preference
 * @param score_abs the normalized score
 */
void
GAS_normalization_normalize_preference (struct GNUNET_SERVER_Client *client,
                                        const struct GNUNET_PeerIdentity *peer,
                                        enum GNUNET_ATS_PreferenceKind kind,
                                        float score_abs)
{
  struct PreferenceClient *c_cur;
  struct PreferencePeer *p_cur;
  struct PeerRelative *r_cur;
  double old_value;
  int i;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Client changes preference for peer `%s' for `%s' to %.2f\n",
       GNUNET_i2s (peer),
       GNUNET_ATS_print_preference_type (kind),
       score_abs);

  if (kind >= GNUNET_ATS_PreferenceCount)
  {
    GNUNET_break(0);
    return;
  }

  /* Find preference client */
  for (c_cur = pc_head; NULL != c_cur; c_cur = c_cur->next)
  {
    if (client == c_cur->client)
      break;
  }
  /* Not found: create new preference client */
  if (NULL == c_cur)
  {
    c_cur = GNUNET_new (struct PreferenceClient);
    c_cur->client = client;
    for (i = 0; i < GNUNET_ATS_PreferenceCount; i++)
    {
      c_cur->f_abs_sum[i] = DEFAULT_ABS_PREFERENCE;
      c_cur->f_rel_sum[i] = DEFAULT_REL_PREFERENCE;
    }

    GNUNET_CONTAINER_DLL_insert(pc_head, pc_tail, c_cur);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Adding new client %p \n", c_cur);
  }

  /* Find entry for peer */
  for (p_cur = c_cur->p_head; NULL != p_cur; p_cur = p_cur->next)
    if (0 == memcmp (&p_cur->id, peer, sizeof(p_cur->id)))
      break;

  /* Not found: create new peer entry */
  if (NULL == p_cur)
  {
    p_cur = GNUNET_new (struct PreferencePeer);
    p_cur->client = c_cur;
    p_cur->id = (*peer);
    for (i = 0; i < GNUNET_ATS_PreferenceCount; i++)
    {
      /* Default value per peer absolute preference for a preference: 0 */
      p_cur->f_abs[i] = DEFAULT_ABS_PREFERENCE;
      /* Default value per peer relative preference for a quality: 1.0 */
      p_cur->f_rel[i] = DEFAULT_REL_PREFERENCE;
      p_cur->next_aging[i] = GNUNET_TIME_UNIT_FOREVER_ABS;
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Adding new peer %p for client %p \n",
        p_cur, c_cur);
    GNUNET_CONTAINER_DLL_insert(c_cur->p_head, c_cur->p_tail, p_cur);
  }

  /* Create struct for peer */
  if (NULL == GNUNET_CONTAINER_multipeermap_get (preference_peers, peer))
  {
    r_cur = GNUNET_new (struct PeerRelative);
    r_cur->id = (*peer);
    for (i = 0; i < GNUNET_ATS_PreferenceCount; i++)
      r_cur->f_rel[i] = DEFAULT_REL_PREFERENCE;
    GNUNET_assert(
        GNUNET_OK == GNUNET_CONTAINER_multipeermap_put (preference_peers,
            &r_cur->id, r_cur, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }

  /* Update absolute value */
  old_value = p_cur->f_abs[kind];
  update_abs_preference (c_cur, p_cur, kind, score_abs);
  if (p_cur->f_abs[kind] == old_value)
    return;

  run_preference_update (c_cur, p_cur, kind, score_abs);

  /* Start aging task */
  if (NULL == aging_task)
    aging_task = GNUNET_SCHEDULER_add_delayed (PREF_AGING_INTERVAL,
                                               &preference_aging,
                                               NULL);

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
GAS_normalization_get_preferences_by_peer (void *cls,
					   const struct GNUNET_PeerIdentity *id)
{
  GNUNET_assert(NULL != preference_peers);
  GNUNET_assert(NULL != id);

  struct PeerRelative *rp;
  if (NULL == (rp = GNUNET_CONTAINER_multipeermap_get (preference_peers, id)))
  {
    return defvalues.f_rel;
  }
  return rp->f_rel;
}


/**
 * Get the normalized preference values for a specific client and peer
 *
 * @param client client
 * @param peer the peer
 * @param pref the preference type
 * @return the value
 */
double
GAS_normalization_get_preferences_by_client (const struct GNUNET_SERVER_Client *client,
                                             const struct GNUNET_PeerIdentity *peer,
                                             enum GNUNET_ATS_PreferenceKind pref)
{
  struct PreferenceClient *c_cur;
  struct PreferencePeer *p_cur;

  /* Find preference client */
  for (c_cur = pc_head; NULL != c_cur; c_cur = c_cur->next)
  {
    if (client == c_cur->client)
      break;
  }
  if (NULL == c_cur)
    return -1.0;

  for (p_cur = c_cur->p_head; NULL != p_cur; p_cur = p_cur->next)
  {
    if (0 == memcmp (peer, &p_cur->id, sizeof (struct GNUNET_PeerIdentity)))
      break;
  }
  if (NULL == p_cur)
    return DEFAULT_REL_PREFERENCE; /* Not found, return default */

  return p_cur->f_rel[pref];
}



/**
 * A performance client disconnected
 *
 * @param client the client
 */
void
GAS_normalization_preference_client_disconnect (struct GNUNET_SERVER_Client *client)
{
  struct PreferenceClient *c_cur;
  /* Find preference client */

  for (c_cur = pc_head; NULL != c_cur; c_cur = c_cur->next)
  {
    if (client == c_cur->client)
      break;
  }
  if (NULL == c_cur)
    return;

  GNUNET_CONTAINER_DLL_remove(pc_head, pc_tail, c_cur);
  free_client (c_cur);
}
