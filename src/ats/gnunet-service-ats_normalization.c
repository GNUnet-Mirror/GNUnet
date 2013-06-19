/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file ats/gnunet-service-ats_normalization.c
 * @brief ats service address: management of ATS properties and preferences normalization
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_ats_service.h"
#include "gnunet-service-ats_normalization.h"



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
   * Total preference for this peer
   */
  double f_abs_sum[GNUNET_ATS_PreferenceCount];

  /**
   * List of peer preferences for this client
   */

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
   * Absolute preference values
   */
  double f_abs[GNUNET_ATS_PreferenceCount];

  /**
   * Relative preference values
   */
  double f_rel[GNUNET_ATS_PreferenceCount];

  /**
   * Aging Task
   */
  GNUNET_SCHEDULER_TaskIdentifier aging_task;
};

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

GAS_Normalization_preference_changed_cb pref_changed_cb;
void *pref_changed_cb_cls;
struct GNUNET_CONTAINER_MultiHashMap *peers;
struct PreferenceClient *pc_head;
struct PreferenceClient *pc_tail;
struct PeerRelative defvalues;


static double
update_peers (struct GNUNET_PeerIdentity *id,
							enum GNUNET_ATS_PreferenceKind kind)
{
	struct PreferenceClient *c_cur;
	struct PreferencePeer *p_cur;
	struct PeerRelative *rp;
	double f_rel_total;
	double backup;
	unsigned int count;

	f_rel_total = 0.0;
	count = 0;

	/* For all clients */
	for (c_cur = pc_head; NULL != c_cur; c_cur = c_cur->next)
	{
		/* Find peer with id */
		for (p_cur = c_cur->p_head; NULL != p_cur; p_cur = p_cur->next)
		{
			if (0 == memcmp (id, &p_cur->id, sizeof (struct GNUNET_PeerIdentity)))
				break;
		}
		if (NULL != p_cur)
		{
			/* Found peer with id */
			f_rel_total +=  p_cur->f_rel[kind];
			count ++;
		}
	}

	/* Find a client */
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%u clients have a total relative preference for peer `%s''s `%s' of %.3f\n",
			count,
			GNUNET_i2s (id),
			GNUNET_ATS_print_preference_type (kind),
			f_rel_total);
	if (NULL != (rp = GNUNET_CONTAINER_multihashmap_get (peers, &id->hashPubKey)))
	{
		backup = rp->f_rel[kind];
		if (0 < count)
		{
			rp->f_rel[kind] = f_rel_total / count;
		}
		else
		{
			rp->f_rel[kind] = DEFAULT_REL_PREFERENCE;
		}
	}
	else
	{
		return DEFAULT_REL_PREFERENCE;
	}

	if ((backup != rp->f_rel[kind]) && (NULL != pref_changed_cb))
	{
		pref_changed_cb (pref_changed_cb_cls, &rp->id, kind, rp->f_rel[kind]);
	}

	return rp->f_rel[kind];
}

/**
 * Recalculate preference for a specific ATS property
 *
 * @param c the preference client
 * @param p the peer
 * @param kind the preference kind
 */
static double
recalculate_rel_preferences (struct PreferenceClient *c,
							 struct PreferencePeer *p,
							 enum GNUNET_ATS_PreferenceKind kind)
{
	struct PreferencePeer *p_cur;
	struct PeerRelative *rp;
	double backup;
	double res;
	double ret;

	/* For this client: sum preferences to total preference */
	c->f_abs_sum[kind] = 0;
	for (p_cur = c->p_head; NULL != p_cur; p_cur = p_cur->next)
		c->f_abs_sum[kind] += p_cur->f_abs[kind];
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Client %p has total preference for %s of %.3f\n",
			c->client,
			GNUNET_ATS_print_preference_type (kind),
			c->f_abs_sum[kind]);

	ret = DEFAULT_REL_PREFERENCE;
	/* For all peers: calculate relative preference */
	for (p_cur = c->p_head; NULL != p_cur; p_cur = p_cur->next)
	{
		/* Calculate relative preference for specific kind */
		backup = p_cur->f_rel[kind];
		if (DEFAULT_ABS_PREFERENCE == c->f_abs_sum[kind])
				/* No peer has a preference for this property, so set default preference */
				p_cur->f_rel[kind] = DEFAULT_REL_PREFERENCE;
		else
				p_cur->f_rel[kind] = (c->f_abs_sum[kind] + p_cur->f_abs[kind]) / c->f_abs_sum[kind];

		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Client %p: peer `%s' has relative preference for %s of %.3f\n",
				c->client,
				GNUNET_i2s (&p_cur->id),
				GNUNET_ATS_print_preference_type (kind),
				p_cur->f_rel[kind]);

		res = 0.0;
		if (p_cur->f_rel[kind] != backup)
		{
			/* Value changed, recalculate */
			res = update_peers (&p_cur->id,kind);
			if (0 == memcmp (&p->id, &p_cur->id, sizeof (struct GNUNET_PeerIdentity)))
				ret = res;
		}
		else
	  {
			/* Value did not chang, return old value*/
			GNUNET_assert (NULL != (rp = GNUNET_CONTAINER_multihashmap_get (peers, &p->id.hashPubKey)));
			ret = rp->f_rel[kind];
	  }
	}
	return ret;
}

static double
update_preference (struct PreferenceClient *c,
									 struct PreferencePeer *p,
									 enum GNUNET_ATS_PreferenceKind kind,
    							 float score_abs)
{
	double score = score_abs;

  /* Update preference value according to type */
  switch (kind) {
    case GNUNET_ATS_PREFERENCE_BANDWIDTH:
    case GNUNET_ATS_PREFERENCE_LATENCY:
      p->f_abs[kind] = (p->f_abs[kind] + score) / 2;
      break;
    case GNUNET_ATS_PREFERENCE_END:
      break;
    default:
      break;
  }
  return recalculate_rel_preferences (c, p, kind);
}

static void
preference_aging (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
	int i;
	//double *t = NULL;
	double backup;
	struct PreferencePeer *p = cls;
	GNUNET_assert (NULL != p);

	p->aging_task = GNUNET_SCHEDULER_NO_TASK;

	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Aging preferences for peer `%s'\n",
  		GNUNET_i2s (&p->id));

  /* Issue for aging :
   *
   * Not for every peer preference values are set by default, so reducing the
   * absolute preference value does not help for aging because it does not have
   * influence on the relative values.
   *
   * So we have to reduce the relative value to have an immediate impact on
   * quota calculation. In addition we cannot call recalculate_preferences here
   * but instead reduce the absolute value to have an aging impact on future
   * calls to change_preference where recalculate_preferences is called
   *
   */
  /* Aging absolute values: */
  for (i = 0; i < GNUNET_ATS_PreferenceCount; i++)
  {
			backup = p->f_abs[i];
  		if (p->f_abs[i] > DEFAULT_ABS_PREFERENCE)
  			p->f_abs[i] *= PREF_AGING_FACTOR;
  		if (backup != p->f_abs[i])
  		{
  			GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Aged preference for peer `%s' from %.3f to %.3f\n",
  	  		GNUNET_i2s (&p->id), backup, p->f_abs[i]);
  			recalculate_rel_preferences (p->client, p, i);
  		}
  }
  p->aging_task = GNUNET_SCHEDULER_add_delayed (PREF_AGING_INTERVAL,
  		&preference_aging, p);
}

/**
 * Normalize an updated preference value
 *
 * @param src the client with this preference
 * @param peer the peer to change the preference for
 * @param kind the kind to change the preference
 * @param score_abs the normalized score
 */
float
GAS_normalization_change_preference (void *src,
                                   	 const struct GNUNET_PeerIdentity *peer,
                                   	 enum GNUNET_ATS_PreferenceKind kind,
                                   	 float score_abs)
{
  float score_rel;
  struct PreferenceClient *c_cur;
  struct PreferencePeer *p_cur;
  struct PeerRelative *r_cur;
  int i;


  GNUNET_assert (NULL != src);
  GNUNET_assert (NULL != peer);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Client %p changes preference for peer `%s' for `%s' to %.2f\n",
                                src,
                                GNUNET_i2s (peer),
                                GNUNET_ATS_print_preference_type (kind),
                                score_abs);

  if (kind >= GNUNET_ATS_PreferenceCount)
  {
      GNUNET_break (0);
      return 0.0;
  }

  /* Find preference client */
  for (c_cur = pc_head; NULL != c_cur; c_cur = c_cur->next)
  {
      if (src == c_cur->client)
        break;
  }
  /* Not found: create new preference client */
  if (NULL == c_cur)
  {
    c_cur = GNUNET_malloc (sizeof (struct PreferenceClient));
    c_cur->client = src;
    GNUNET_CONTAINER_DLL_insert (pc_head, pc_tail, c_cur);
  }

  /* Find entry for peer */
  for (p_cur = c_cur->p_head; NULL != p_cur; p_cur = p_cur->next)
    if (0 == memcmp (&p_cur->id, peer, sizeof (p_cur->id)))
        break;

  /* Not found: create new peer entry */
  if (NULL == p_cur)
  {
      p_cur = GNUNET_malloc (sizeof (struct PreferencePeer));
      p_cur->client = c_cur;
      p_cur->id = (*peer);
      for (i = 0; i < GNUNET_ATS_PreferenceCount; i++)
      {
        /* Default value per peer absolut preference for a quality:
         * No value set, so absolute preference 0 */
        p_cur->f_abs[i] = DEFAULT_ABS_PREFERENCE;
        /* Default value per peer relative preference for a quality: 1.0 */
        p_cur->f_rel[i] = DEFAULT_REL_PREFERENCE;
      }
      p_cur->aging_task = GNUNET_SCHEDULER_add_delayed (PREF_AGING_INTERVAL, &preference_aging, p_cur);
      GNUNET_CONTAINER_DLL_insert (c_cur->p_head, c_cur->p_tail, p_cur);
  }

  if (NULL == (r_cur = GNUNET_CONTAINER_multihashmap_get (peers, &peer->hashPubKey)))
  {
  	r_cur = GNUNET_malloc (sizeof (struct PeerRelative));
  	r_cur->id = (*peer);
  	for (i = 0; i < GNUNET_ATS_PreferenceCount; i++)
  		r_cur->f_rel[i] = DEFAULT_REL_PREFERENCE;
  	GNUNET_CONTAINER_multihashmap_put (peers, &r_cur->id.hashPubKey, r_cur, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  }

  score_rel = update_preference (c_cur, p_cur, kind, score_abs);
  return score_rel;
}

/**
 * Get the normalized preference values for a specific peer
 *
 * @param id the peer
 * @return pointer to the values, can be indexed with GNUNET_ATS_PreferenceKind, default preferences if peer does not exist
 */
const double *
GAS_normalization_get_preferences (struct GNUNET_PeerIdentity *id)
{
	GNUNET_assert (NULL != peers);
	GNUNET_assert (NULL != id);

	struct PeerRelative *rp;
	if (NULL == (rp = GNUNET_CONTAINER_multihashmap_get (peers, &id->hashPubKey)))
	{
		return defvalues.f_rel;
	}
	return rp->f_rel;
}


void
GAS_normalization_start (GAS_Normalization_preference_changed_cb pref_ch_cb, void *pref_ch_cb_cls)
{
	int i;
	peers = GNUNET_CONTAINER_multihashmap_create(10, GNUNET_NO);
	pref_changed_cb = pref_ch_cb;
	pref_changed_cb_cls = pref_ch_cb_cls;
	for (i = 0; i < GNUNET_ATS_PreferenceCount; i++)
		defvalues.f_rel[i] = DEFAULT_REL_PREFERENCE;
	return;
}

static int
free_peer (void *cls,
    			 const struct GNUNET_HashCode * key,
    			 void *value)
{
	struct PeerRelative *rp = value;
	GNUNET_CONTAINER_multihashmap_remove (peers, key, value);
	GNUNET_free (rp);
	return GNUNET_OK;
}

void
GAS_normalization_stop ()
{
  struct PreferenceClient *pc;
  struct PreferenceClient *next_pc;
  struct PreferencePeer *p;
  struct PreferencePeer *next_p;

  next_pc = pc_head;
  while (NULL != (pc = next_pc))
  {
      next_pc = pc->next;
      GNUNET_CONTAINER_DLL_remove (pc_head, pc_tail, pc);
      next_p = pc->p_head;
      while (NULL != (p = next_p))
      {
          next_p = p->next;
          if (GNUNET_SCHEDULER_NO_TASK != p->aging_task)
          {
          	GNUNET_SCHEDULER_cancel(p->aging_task);
          	p->aging_task = GNUNET_SCHEDULER_NO_TASK;
          }
          GNUNET_CONTAINER_DLL_remove (pc->p_head, pc->p_tail, p);
          GNUNET_free (p);
      }
      GNUNET_free (pc);
  }
  GNUNET_CONTAINER_multihashmap_iterate (peers, &free_peer, NULL);
  GNUNET_CONTAINER_multihashmap_destroy (peers);
	return;
}

/* end of gnunet-service-ats_normalization.c */
