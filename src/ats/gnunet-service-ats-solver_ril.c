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
 * @file ats/gnunet-service-ats-solver_ril.c
 * @brief ATS reinforcement learning solver
 * @author Fabian Oehlmann
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet-service-ats_addresses.h"
#include "gnunet_statistics_service.h"

#define RIL_DEFAULT_STEP_TIME GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 3000)
#define RIL_DEFAULT_DISCOUNT_FACTOR 0.5
#define RIL_DEFAULT_GRADIENT_STEP_SIZE 0.4
#define RIL_DEFAULT_TRACE_DECAY 0.6

/**
 * ATS reinforcement learning solver
 *
 * General description
 */

/**
 * Global learning parameters
 */
struct RIL_Learning_Parameters
{
	/**
	 * Learning discount factor in the TD-update
	 */
	float gamma;

	/**
	 * Gradient-descent step-size
	 */
	float alpha;

	/**
	 * Trace-decay factor for eligibility traces
	 */
	float lambda;
};

struct RIL_Peer_Agent
{
	/**
	 * Next agent in solver's linked list
	 */
	struct RIL_Peer_Agent *next;

	/**
	 * Previous agent in solver's linked list
	 */
	struct RIL_Peer_Agent *prev;

	/**
	 * Peer ID
	 */
	struct GNUNET_PeerIdentity peer;

	/**
	 * Experience matrix W
	 */
	double ** W;

	/**
	 * Last perceived state feature vector
	 */
	double * s_t;

	/**
	 * Last chosen action
	 */
	double * a_t;

	/**
	 * Last eligibility trace vector
	 */
	double * e_t;
};

struct RIL_Network
{
	  /**
	   * ATS network type
	   */
	  unsigned int type;

	  /**
	   * Network description
	   */
	  char *desc;

	  /**
	   * Total available inbound bandwidth
	   */
	  unsigned long long bw_in_available;

	  /**
	   * Total assigned outbound bandwidth
	   */
	  unsigned long long bw_in_assigned;

	  /**
	   * Total available outbound bandwidth
	   */
	  unsigned long long bw_out_available;

	  /**
	   * Total assigned outbound bandwidth
	   */
	  unsigned long long bw_out_assigned;
};

struct RIL_Callbacks
{
	  /**
	   * Bandwidth changed callback
	   */
	  GAS_bandwidth_changed_cb bw_changed;

	  /**
	   * Bandwidth changed callback cls
	   */
	  void *bw_changed_cls;

	  /**
	   * ATS function to get preferences
	   */
	  GAS_get_preferences get_preferences;

	  /**
	   * Closure for ATS function to get preferences
	   */
	  void *get_preferences_cls;

	  /**
	   * ATS function to get properties
	   */
	  GAS_get_properties get_properties;

	  /**
	   * Closure for ATS function to get properties
	   */
	  void *get_properties_cls;
};

/**
 * A handle for the reinforcement learning solver
 */
struct GAS_RIL_Handle
{
	/**
	* Statistics handle
	*/
	struct GNUNET_STATISTICS_Handle *stats;

	/**
	* Hashmap containing all valid addresses
	*/
	const struct GNUNET_CONTAINER_MultiHashMap *addresses;

	/**
	* Callbacks for the solver
	*/
	struct RIL_Callbacks callbacks;

	/**
	* Bulk lock
	*/
	int bulk_lock;

	/**
	* Number of changes while solver was locked
	*/
	int bulk_requests;

	/**
	* Number of performed time-steps
	*/
	unsigned long long step_count;

	/**
	* Interval time between steps in milliseconds //TODO put in agent
	*/
	struct GNUNET_TIME_Relative step_time;

	/**
	* Task identifier of the next time-step to be executed //TODO put in agent
	*/
	GNUNET_SCHEDULER_TaskIdentifier next_step;

	/**
	* Learning parameters
	*/
	struct RIL_Learning_Parameters parameters;

	/**
	* Array of networks with global assignment state
	*/
	struct RIL_Network * network_entries;

	/**
	* Networks count
	*/
	unsigned int networks_count;

	/**
	* List of active peer-agents
	*/
	struct RIL_Peer_Agent * agents_active_head;
	struct RIL_Peer_Agent * agents_active_tail;

	/**
	* List of paused peer-agents
	*/
	struct RIL_Peer_Agent * agents_paused_head;
	struct RIL_Peer_Agent * agents_paused_tail;
};


enum Actions
{
	bw_dbl,
	bw_hlv
};
//TODO add the rest of the actions

/**
 *  Private functions
 *  ---------------------------
 */

void
agent_periodic_step (void *solver,
				const struct GNUNET_SCHEDULER_TaskContext *tc)
{
	/*
	 * iterate over active agents and do a time step
	 */
	struct GAS_RIL_Handle *s = solver;

	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "RIL step number %d\n", s->step_count);

	s->step_count += 1;
	s->next_step = GNUNET_SCHEDULER_add_delayed (
			s->step_time,
			&agent_periodic_step,
			solver);
}

/**
 * Whether a peer already has an agent in a list
 * @param head of list
 * @param peer in question
 */
int
list_contains_agent (struct RIL_Peer_Agent * head,
					struct GNUNET_PeerIdentity * peer)
{
	struct RIL_Peer_Agent * cur;

	for (cur = head; NULL != cur; cur = cur->next)
	{
		if (!memcmp (&(cur->peer.hashPubKey), &peer->hashPubKey, sizeof(struct GNUNET_HashCode)))
		{
			return GNUNET_YES;
		}
	}
	return GNUNET_NO;
}

/**
 * Iterator, which allocates one agent per peer
 *
 * @param cls solver
 * @param key peer identity
 * @param value address
 * @return whether iterator should continue
 */
int
init_agents_it (void *cls,
				const struct GNUNET_HashCode *key,
				void *value)
{
	struct GAS_RIL_Handle *solver = cls;
	struct ATS_Address *address = value;
	struct RIL_Peer_Agent *agent;

	if (!list_contains_agent (solver->agents_paused_head, &address->peer))
	{
		agent = GNUNET_malloc (sizeof (struct RIL_Peer_Agent));
		agent->peer = address->peer;
		GNUNET_CONTAINER_DLL_insert (solver->agents_paused_head, solver->agents_paused_tail, agent);
	}

	//TODO add address to agent
	return GNUNET_YES;
}



/**
 *  Solver API functions
 *  ---------------------------
 */

/**
 * Changes the preferences for a peer in the problem
 *
 * @param solver the solver handle
 * @param peer the peer to change the preference for
 * @param kind the kind to change the preference
 * @param pref_rel the normalized preference value for this kind over all clients
 */
void
GAS_ril_address_change_preference (void *solver,
								 	 	 	const struct GNUNET_PeerIdentity *peer,
								 	 	 	enum GNUNET_ATS_PreferenceKind kind,
								 	 	 	double pref_rel)
{
	//TODO implement

	/*
	 * Probably nothing to do here. The preference is looked up during reward calculation and does
	 * not trigger anything
	 */
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ril_address_change_preference() has been called\n");
}


/**
 * Init the reinforcement learning problem solver
 *
 * Quotas:
 * network[i] contains the network type as type GNUNET_ATS_NetworkType[i]
 * out_quota[i] contains outbound quota for network type i
 * in_quota[i] contains inbound quota for network type i
 *
 * Example
 * network = {GNUNET_ATS_NET_UNSPECIFIED, GNUNET_ATS_NET_LOOPBACK, GNUNET_ATS_NET_LAN, GNUNET_ATS_NET_WAN, GNUNET_ATS_NET_WLAN}
 * network[2]   == GNUNET_ATS_NET_LAN
 * out_quota[2] == 65353
 * in_quota[2]  == 65353
 *
 * @param cfg configuration handle
 * @param stats the GNUNET_STATISTICS handle
 * @param network array of GNUNET_ATS_NetworkType with length dest_length
 * @param addresses hashmap containing all addresses
 * @param out_quota array of outbound quotas
 * @param in_quota array of outbound quota
 * @param dest_length array length for quota arrays
 * @param bw_changed_cb callback for changed bandwidth amounts
 * @param bw_changed_cb_cls cls for callback
 * @param get_preference callback to get relative preferences for a peer
 * @param get_preference_cls cls for callback to get relative preferences
 * @param get_properties_cls for callback to get relative properties
 * @param get_properties_cls cls for callback to get relative properties
 * @return handle for the solver on success, NULL on fail
 */
void *
GAS_ril_init (const struct GNUNET_CONFIGURATION_Handle *cfg,
				const struct GNUNET_STATISTICS_Handle *stats,
				const struct GNUNET_CONTAINER_MultiHashMap *addresses,
				int *network,
				unsigned long long *out_quota,
				unsigned long long *in_quota,
				int dest_length,
				GAS_bandwidth_changed_cb bw_changed_cb,
				void *bw_changed_cb_cls,
				GAS_get_preferences get_preference,
				void *get_preference_cls,
				GAS_get_properties get_properties,
				void *get_properties_cls)
{
	//TODO implement
	int c;
	unsigned long long tmp;
	struct RIL_Network * cur;
	struct GAS_RIL_Handle *solver = GNUNET_malloc (sizeof (struct GAS_RIL_Handle));
	char * net_str[GNUNET_ATS_NetworkTypeCount] = GNUNET_ATS_NetworkTypeString;

	GNUNET_assert (NULL != cfg);
	GNUNET_assert (NULL != stats);
	GNUNET_assert (NULL != network);
	GNUNET_assert (NULL != bw_changed_cb);
	GNUNET_assert (NULL != get_preference);
	GNUNET_assert (NULL != get_properties);

	if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_time(cfg, "ats", "RIL_STEP_TIME", &solver->step_time))
	{
		solver->step_time = RIL_DEFAULT_STEP_TIME;
	}
	if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size(cfg, "ats", "RIL_DISCOUNT_FACTOR", &tmp))
	{
		solver->parameters.gamma = (double) tmp / 100;;
	}
	else
	{
		solver->parameters.gamma = RIL_DEFAULT_DISCOUNT_FACTOR;
	}
	if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size(cfg, "ats", "RIL_GRADIENT_STEP_SIZE", &tmp))
	{
		solver->parameters.alpha = (double) tmp / 100;;
	}
	else
	{
		solver->parameters.alpha = RIL_DEFAULT_GRADIENT_STEP_SIZE;
	}
	if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size(cfg, "ats", "RIL_TRACE_DECAY", &tmp))
	{
		solver->parameters.lambda = (double) tmp / 100;;
	}
	else
	{
		solver->parameters.lambda = RIL_DEFAULT_TRACE_DECAY;
	}

	solver->stats = (struct GNUNET_STATISTICS_Handle *) stats;
	solver->callbacks.bw_changed = bw_changed_cb;
	solver->callbacks.bw_changed_cls = bw_changed_cb_cls;
	solver->callbacks.get_preferences = get_preference;
	solver->callbacks.get_preferences_cls = get_preference_cls;
	solver->callbacks.get_properties = get_properties;
	solver->callbacks.get_properties_cls = get_properties_cls;
	solver->networks_count = dest_length;
	solver->network_entries = GNUNET_malloc (dest_length * sizeof (struct RIL_Network));
	solver->bulk_lock = GNUNET_NO;
	solver->addresses = addresses;
	solver->step_count = 0;

	for (c = 0; c < dest_length; c++)
	{
		cur = &solver->network_entries[c];
		cur->type = network[c];
		cur->bw_in_available = in_quota[c];
		cur->bw_in_assigned = 0;
		cur->bw_out_available = out_quota[c];
		cur->bw_out_assigned = 0;
		cur->desc = net_str[c];
	}

	c = GNUNET_CONTAINER_multihashmap_iterate (addresses, &init_agents_it, solver);

	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ril_init() has been called\n");
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "RIL number of addresses: %d\n", c);

	solver->next_step = GNUNET_SCHEDULER_add_delayed (
				GNUNET_TIME_relative_multiply (GNUNET_TIME_relative_get_millisecond_ (), 1000),
				&agent_periodic_step,
				solver);

	return solver;
}

/**
 * Shutdown the reinforcement learning problem solver
 *
 * @param solver the respective handle to shutdown
 */
void
GAS_ril_done (void * solver)
{
	//TODO implement
	struct GAS_RIL_Handle *s = solver;

	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ril_done() has been called\n");

	GNUNET_SCHEDULER_cancel (s->next_step);
	GNUNET_free (s->network_entries);
	GNUNET_free (s);
}


/**
 * Add a single address within a network to the solver
 *
 * @param solver the solver Handle
 * @param address the address to add
 * @param network network type of this address
 */
void
GAS_ril_address_add (void *solver,
							struct ATS_Address *address,
							uint32_t network)
{
	//TODO implement
	/*
	 * if (new peer)
	 *     initialize new agent
	 * Add address
	 * increase state vector
	 * knowledge matrix
	 * and action vector
	 */
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ril_address_add() has been called\n");
}

/**
 * Remove an address from the solver
 *
 * @param solver the solver handle
 * @param address the address to remove
 * @param session_only delete only session not whole address
 */
void
GAS_ril_address_delete (void *solver,
    struct ATS_Address *address, int session_only)
{
	//TODO implement
	/*
	 * remove address
	 * if (last address of peer)
	 *     remove agent
	 * else
	 *     decrease state vector
	 *     decrease knowledge matrix
	 *     decrease action vector
	 */
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ril_address_delete() has been called\n");
}

/**
 * Transport properties for this address have changed
 *
 * @param solver solver handle
 * @param address the address
 * @param type the ATSI type in HBO
 * @param abs_value the absolute value of the property
 * @param rel_value the normalized value
 */
void
GAS_ril_address_property_changed (void *solver,
    															struct ATS_Address *address,
    															uint32_t type,
    															uint32_t abs_value,
    															double rel_value)
{
	//TODO implement
	/*
	 * Like change_preference() not really interesting, since lookup happens anyway during reward
	 * calculation
	 */
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ril_address_property_changed() has been called\n");
}


/**
 * Transport session for this address has changed
 *
 * NOTE: values in addresses are already updated
 *
 * @param solver solver handle
 * @param address the address
 * @param cur_session the current session
 * @param new_session the new session
 */
void
GAS_ril_address_session_changed (void *solver,
    															struct ATS_Address *address,
    															uint32_t cur_session,
    															uint32_t new_session)
{
	//TODO implement
	/*
	 * Potentially add session activity as a feature in state vector
	 */
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ril_address_session_changed() has been called\n");
}


/**
 * Usage for this address has changed
 *
 * NOTE: values in addresses are already updated
 *
 * @param solver solver handle
 * @param address the address
 * @param in_use usage state
 */
void
GAS_ril_address_inuse_changed (void *solver,
    															struct ATS_Address *address,
    															int in_use)
{
	//TODO implement
	/**
	 * See matthias' email
	 */
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ril_address_inuse_changed() has been called\n");
}

/**
 * Network scope for this address has changed
 *
 * NOTE: values in addresses are already updated
 *
 * @param solver solver handle
 * @param address the address
 * @param current_network the current network
 * @param new_network the new network
 */
void
GAS_ril_address_change_network (void *solver,
																	   struct ATS_Address *address,
																	   uint32_t current_network,
																	   uint32_t new_network)
{
	//TODO implement
	/*
	 * update network
	 */
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ril_address_change_network() has been called\n");
}

/**
 * Get application feedback for a peer
 *
 * @param solver the solver handle
 * @param application the application
 * @param peer the peer to change the preference for
 * @param scope the time interval for this feedback: [now - scope .. now]
 * @param kind the kind to change the preference
 * @param score the score
 */
void
GAS_ril_address_preference_feedback (void *solver,
											void *application,
								 	 	 	const struct GNUNET_PeerIdentity *peer,
								 	 	 	const struct GNUNET_TIME_Relative scope,
								 	 	 	enum GNUNET_ATS_PreferenceKind kind,
								 	 	 	double score)
{
	//TODO implement
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ril_address_preference_feedback() has been called\n");
}

/**
 * Start a bulk operation
 *
 * @param solver the solver
 */
void
GAS_ril_bulk_start (void *solver)
{
	//TODO implement
	/*
	 * bulk counter up, but not really relevant, because there is no complete calculation of the
	 * bandwidth assignment triggered anyway. Therefore, changes to addresses can come and go as
	 * they want. Consideration: Step-pause during bulk-start-stop period...
	 */
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ril_bulk_start() has been called\n");
}


/**
 * Bulk operation done
 */
void
GAS_ril_bulk_stop (void *solver)
{
	//TODO implement
	/*
	 * bulk counter down, see bulk_start()
	 */
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ril_bulk_stop() has been called\n");
}

/**
 * Get the preferred address for a specific peer
 *
 * @param solver the solver handle
 * @param peer the identity of the peer
 */
const struct ATS_Address *
GAS_ril_get_preferred_address (void *solver,
                               const struct GNUNET_PeerIdentity *peer)
{
	//TODO implement
	/*
	 * connect-only for requested peers, move agent to active list
	 */
	struct GAS_RIL_Handle *s = solver;

	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ril_get_preferred_address() has been called\n");

	if (0 == GNUNET_CONTAINER_multihashmap_contains(s->addresses, &peer->hashPubKey))
	{
		return GNUNET_CONTAINER_multihashmap_get(s->addresses, &peer->hashPubKey);
	}

	GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "No address for peer in addresses\n");
	return NULL;
}

/**
 * Stop notifying about address and bandwidth changes for this peer
 *
 * @param solver the solver handle
 * @param peer the peer
 */
void
GAS_ril_stop_get_preferred_address (void *solver,
                                     const struct GNUNET_PeerIdentity *peer)
{
	//TODO implement
	/*
	 * connect-only for requested peers, move agent to paused list
	 */
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ril_stop_get_preferred_address() has been called\n");
}

/* end of gnunet-service-ats-solver_reinf.c */
