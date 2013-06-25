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
#include "gnunet-service-ats_addresses.h"
#include "gnunet-service-ats_normalization.h"

#define LOG(kind,...) GNUNET_log_from (kind, "ats-normalization",__VA_ARGS__)


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


/**
 * Callback to call on changing preference values
 */
static GAS_Normalization_preference_changed_cb pref_changed_cb;


/**
 * Closure for callback to call on changing preference values
 */
static void *pref_changed_cb_cls;


/**
 * Callback to call on changing property values
 */
GAS_Normalization_property_changed_cb prop_ch_cb;

/**
 * Closure for callback to call on changing property values
 */
void *prop_ch_cb_cls;


/**
 * Hashmap to store peer information for preference normalization
 */
static struct GNUNET_CONTAINER_MultiHashMap *preference_peers;



/**
 * Hashmap to store peer information for property normalization
 */
static struct GNUNET_CONTAINER_MultiHashMap *property_peers;



/**
 * Clients in DLL: head
 */
static struct PreferenceClient *pc_head;


/**
 * Clients in DLL: tail
 */
static struct PreferenceClient *pc_tail;


/**
 * Default values
 */
static struct PeerRelative defvalues;

/**
 * Application Preference Normalization
 */


/**
 * Update a peer
 * @param id peer id
 * @param kind the kind
 * @return the new relative preference
 */
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
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			"%u clients have a total relative preference for peer `%s''s `%s' of %.3f\n",
			count,
			GNUNET_i2s (id),
			GNUNET_ATS_print_preference_type (kind),
			f_rel_total);
	if (NULL != (rp = GNUNET_CONTAINER_multihashmap_get (preference_peers, &id->hashPubKey)))
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
 * @return the result
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
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
			"Client %p has total preference for %s of %.3f\n",
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
				/* No peer has a preference for this property,
				 * so set default preference */
				p_cur->f_rel[kind] = DEFAULT_REL_PREFERENCE;
		else
				p_cur->f_rel[kind] = (c->f_abs_sum[kind] + p_cur->f_abs[kind]) /
				c->f_abs_sum[kind];

		GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
				"Client %p: peer `%s' has relative preference for %s of %.3f\n",
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
			GNUNET_assert (NULL != (rp = GNUNET_CONTAINER_multihashmap_get (preference_peers,
					&p->id.hashPubKey)));
			ret = rp->f_rel[kind];
	  }
	}
	return ret;
}


/**
 * Update the absolute preference value for a peer
 * @param c the client
 * @param p the peer
 * @param kind the preference kind
 * @param score_abs the absolute value
 * @return the new relative preference value
 */
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


/**
 * Reduce absolute preferences since they got old
 *
 * @param cls the PreferencePeer
 * @param tc context
 */
static void
preference_aging (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
	int i;
	double backup;
	struct PreferencePeer *p = cls;
	GNUNET_assert (NULL != p);

	p->aging_task = GNUNET_SCHEDULER_NO_TASK;

	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Aging preferences for peer `%s'\n",
  		GNUNET_i2s (&p->id));

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
void
GAS_normalization_normalize_preference (void *src,
                                   	 const struct GNUNET_PeerIdentity *peer,
                                   	 enum GNUNET_ATS_PreferenceKind kind,
                                   	 float score_abs)
{
  struct PreferenceClient *c_cur;
  struct PreferencePeer *p_cur;
  struct PeerRelative *r_cur;
  int i;


  GNUNET_assert (NULL != src);
  GNUNET_assert (NULL != peer);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
  		"Client %p changes preference for peer `%s' for `%s' to %.2f\n",
			src,
			GNUNET_i2s (peer),
			GNUNET_ATS_print_preference_type (kind),
			score_abs);

  if (kind >= GNUNET_ATS_PreferenceCount)
  {
      GNUNET_break (0);
      return;
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
      p_cur->aging_task = GNUNET_SCHEDULER_add_delayed (PREF_AGING_INTERVAL,
      		&preference_aging, p_cur);
      GNUNET_CONTAINER_DLL_insert (c_cur->p_head, c_cur->p_tail, p_cur);
  }

  if (NULL == GNUNET_CONTAINER_multihashmap_get (preference_peers,
  		&peer->hashPubKey))
  {
  	r_cur = GNUNET_malloc (sizeof (struct PeerRelative));
  	r_cur->id = (*peer);
  	for (i = 0; i < GNUNET_ATS_PreferenceCount; i++)
  		r_cur->f_rel[i] = DEFAULT_REL_PREFERENCE;
  	GNUNET_CONTAINER_multihashmap_put (preference_peers, &r_cur->id.hashPubKey,
  			r_cur, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  }
  update_preference (c_cur, p_cur, kind, score_abs);
}


/**
 * Get the normalized preference values for a specific peer or
 * the default values if
 *
 * @param id the peer
 * @return pointer to the values, can be indexed with GNUNET_ATS_PreferenceKind,
 * default preferences if peer does not exist
 */
const double *
GAS_normalization_get_preferences (const struct GNUNET_PeerIdentity *id)
{
	GNUNET_assert (NULL != preference_peers);
	GNUNET_assert (NULL != id);

	struct PeerRelative *rp;
	if (NULL == (rp = GNUNET_CONTAINER_multihashmap_get (preference_peers, &id->hashPubKey)))
	{
		return defvalues.f_rel;
	}
	return rp->f_rel;
}

/**
 * Quality Normalization
 */

struct Property
{
	uint32_t prop_type;
	uint32_t atsi_type;
	uint32_t min;
	uint32_t max;
};

struct Property properties[GNUNET_ATS_QualityPropertiesCount];

/**
 * Normalize a specific ATS type with the values in queue
 * @param address the address
 * @param atsi the ats information
 * @return the new average or GNUNET_ATS_VALUE_UNDEFINED
 */

uint32_t
property_average (struct ATS_Address *address,
									const struct GNUNET_ATS_Information *atsi)
{
	struct GAS_NormalizationInfo *ni;
	uint32_t current_type;
	uint32_t current_val;
	uint32_t res;
	uint64_t sum;
	uint32_t count;
	unsigned int c1;
	unsigned int index;
	unsigned int props[] = GNUNET_ATS_QualityProperties;

	/* Average the values of this property */
	current_type = ntohl (atsi->type);
	current_val = ntohl (atsi->value);

	for (c1 = 0; c1 < GNUNET_ATS_QualityPropertiesCount; c1++)
	{
		if (current_type == props[c1])
			break;
	}
	if (c1 == GNUNET_ATS_QualityPropertiesCount)
	{
		GNUNET_break (0);
		return GNUNET_ATS_VALUE_UNDEFINED;
	}
	index = c1;

	ni = &address->atsin[index];
	ni->atsi_abs[ni->avg_queue_index] = current_val;
	ni->avg_queue_index ++;
	if (GAS_normalization_queue_length == ni->avg_queue_index)
		ni->avg_queue_index = 0;

	count = 0;
	sum = 0;
	for (c1 = 0; c1 < GAS_normalization_queue_length; c1++)
	{
		if (GNUNET_ATS_VALUE_UNDEFINED != ni->atsi_abs[c1])
		{
			count++;
			if (GNUNET_ATS_VALUE_UNDEFINED > (sum + ni->atsi_abs[c1]))
				sum += ni->atsi_abs[c1];
			else
			{
				sum = GNUNET_ATS_VALUE_UNDEFINED - 1;
				GNUNET_break (0);
			}
		}
	}
	GNUNET_assert (0 != count);
	res = sum / count;
	LOG (GNUNET_ERROR_TYPE_DEBUG, "New average of `%s' created by adding %u from %u elements: %u\n",
			GNUNET_ATS_print_property_type(current_type),
			current_val, count, res , sum);
	ni->avg = res;
	return res;
}


struct FindMinMaxCtx
{
	struct Property *p;
	uint32_t min;
	uint32_t max;
};

static int
find_min_max_it (void *cls, const struct GNUNET_HashCode *h, void *k)
{
	struct ATS_Address *a = (struct ATS_Address *) k;
	struct FindMinMaxCtx *find_res = cls;

	if (a->atsin[find_res->p->prop_type].avg > find_res->max)
		find_res->max = a->atsin[find_res->p->prop_type].avg;

	if (a->atsin[find_res->p->prop_type].avg < find_res->min)
		find_res->min = a->atsin[find_res->p->prop_type].avg;

	return GNUNET_OK;
}


static int
normalize_address (void *cls, const struct GNUNET_HashCode *h, void *k)
{
	struct Property *p = cls;
	struct ATS_Address *address = (struct ATS_Address *) k;

	double delta;
	uint32_t avg_value = address->atsin[p->prop_type].avg;

	delta = p->max - p->min;
	address->atsin[p->prop_type].norm = (delta + (avg_value - p->min)) / (delta);

	LOG (GNUNET_ERROR_TYPE_DEBUG, "Normalize `%s' address %p's '%s' with value %u to range [%u..%u] = %.3f\n",
			GNUNET_i2s (&address->peer),
			address,
			GNUNET_ATS_print_property_type (p->atsi_type),
			address->atsin[p->prop_type].avg,
			p->min, p->max,
			address->atsin[p->prop_type].norm );

	if (NULL != prop_ch_cb)
		prop_ch_cb (prop_ch_cb_cls, address, p->atsi_type,
				address->atsin[p->prop_type].norm);


	return GNUNET_OK;
}


/**
 * Normalize avg_value to a range of values between [1.0, 2.0]
 * based on min max values currently known.
 *
 * @param property p the property
 * @param address the address
 * @param avg_value the value to normalize
 */

static void
property_normalize (struct GNUNET_CONTAINER_MultiHashMap *addresses,
										struct Property *p,
									  struct ATS_Address *address,
									  uint32_t avg_value)
{
	struct FindMinMaxCtx find_ctx;
	int addr_count;
	int limits_changed;

	find_ctx.p = p;
	find_ctx.max = 0;
	find_ctx.min = UINT32_MAX;
	addr_count = GNUNET_CONTAINER_multihashmap_iterate(addresses, &find_min_max_it, &find_ctx);
	if (0 == addr_count)
	{
		GNUNET_break (0);
		return;
	}


	limits_changed = GNUNET_NO;
	if (find_ctx.max != p->max)
	{
		LOG (GNUNET_ERROR_TYPE_DEBUG, "Normalizing %s: new maximum %u -> recalculate all values\n",
				GNUNET_ATS_print_property_type (p->atsi_type),
				find_ctx.max);
		p->max = find_ctx.max;
		limits_changed = GNUNET_YES;
	}

	if ((find_ctx.min != p->min) && (find_ctx.min < p->max))
	{
		LOG (GNUNET_ERROR_TYPE_DEBUG, "Normalizing %s: new minimum %u -> recalculate all values\n",
				GNUNET_ATS_print_property_type (p->atsi_type),
				find_ctx.min, find_ctx.max);
		p->min = find_ctx.min;
		limits_changed = GNUNET_YES;
	}
	else if (find_ctx.min == p->max)
	{
		/* Only one value, so minimum has to be 0 */
		p->min = 0;
	}

	/* Normalize the values of this property */
	if (GNUNET_NO == limits_changed)
	{
		/* normalize just this  address */
		normalize_address (p, &address->peer.hashPubKey, address);
		return;
	}
	else
	{
		/* limits changed, normalize all addresses */
		GNUNET_CONTAINER_multihashmap_iterate(addresses, &normalize_address, p);
		return;
	}
}


/**
 * Update and normalize a atsi performance information
 *
 * @param addresses hashmap containing all addresses
 * @param address the address to update
 * @param atsi the array of performance information
 * @param atsi_count the number of atsi information in the array
 */
void
GAS_normalization_normalize_property (struct GNUNET_CONTAINER_MultiHashMap *addresses,
																			struct ATS_Address *address,
																			const struct GNUNET_ATS_Information *atsi,
																			uint32_t atsi_count)
{
	struct Property *cur_prop;
	int c1;
	int c2;
	uint32_t current_type;
	uint32_t current_val;
	unsigned int existing_properties[] = GNUNET_ATS_QualityProperties;

	GNUNET_assert (NULL != address);
	GNUNET_assert (NULL != atsi);

	LOG (GNUNET_ERROR_TYPE_DEBUG, "Updating %u elements for peer `%s'\n",
			atsi_count, GNUNET_i2s (&address->peer));

	for (c1 = 0; c1 < atsi_count; c1++)
	{
		current_type = ntohl (atsi[c1].type);
		current_val = ntohl (atsi[c1].value);
		for (c2 = 0; c2 < GNUNET_ATS_QualityPropertiesCount; c2++)
		{
			/* Check if type is valid */
			if (current_type == existing_properties[c2])
				break;
		}
		if (GNUNET_ATS_QualityPropertiesCount == c2)
		{
			/* Invalid property, continue with next element */
			continue;
		}
		/* Averaging */
		current_val = property_average (address, &atsi[c1]);
		if (GNUNET_ATS_VALUE_UNDEFINED == current_val)
		{
			GNUNET_break (0);
			continue;
		}

		/* Normalizing */
		/* Check min, max */
		cur_prop = &properties[c2];
		property_normalize (addresses, cur_prop, address, current_val);
	}
}




/**
 * Start the normalization component
 *
 * @param pref_ch_cb callback to call on relative preference changing
 * @param pref_ch_cb_cls cls for the callback
 */
void
GAS_normalization_start (GAS_Normalization_preference_changed_cb pref_ch_cb,
		void *pref_ch_cb_cls,
		GAS_Normalization_property_changed_cb property_ch_cb,
		void *property_ch_cb_cls)
{
	int c1;
	int i;
	preference_peers = GNUNET_CONTAINER_multihashmap_create(10, GNUNET_NO);
	property_peers = GNUNET_CONTAINER_multihashmap_create(10, GNUNET_NO);
	unsigned int existing_properties[] = GNUNET_ATS_QualityProperties;

	for (c1 = 0; c1 < GNUNET_ATS_QualityPropertiesCount; c1++)
	{
		properties[c1].prop_type = c1;
		properties[c1].atsi_type = existing_properties[c1];
		properties[c1].min = 0;
		properties[c1].max = 0;
	}

	pref_changed_cb = pref_ch_cb;
	pref_changed_cb_cls = pref_ch_cb_cls;
	prop_ch_cb = property_ch_cb;
	prop_ch_cb_cls = pref_ch_cb_cls;

	for (i = 0; i < GNUNET_ATS_PreferenceCount; i++)
		defvalues.f_rel[i] = DEFAULT_REL_PREFERENCE;
	return;
}


/**
 * Free a peer
 *
 * @param cls unused
 * @param key the key
 * @param value RelativePeer
 * @return GNUNET_OK to continue
 */
static int
free_peer (void *cls,
    			 const struct GNUNET_HashCode * key,
    			 void *value)
{
	struct PeerRelative *rp = value;
	if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_remove (preference_peers, key, value))
		GNUNET_free (rp);
	else
		GNUNET_break (0);
	return GNUNET_OK;
}


/**
 * Stop the normalization component and free all items
 */
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
  GNUNET_CONTAINER_multihashmap_iterate (preference_peers, &free_peer, NULL);
  GNUNET_CONTAINER_multihashmap_destroy (preference_peers);
  GNUNET_CONTAINER_multihashmap_destroy (property_peers);
	return;
}

/* end of gnunet-service-ats_normalization.c */
