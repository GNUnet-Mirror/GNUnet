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
#include "float.h"
#include "gnunet_util_lib.h"
#include "gnunet-service-ats_addresses.h"
#include "gnunet_statistics_service.h"

#define RIL_DEFAULT_STEP_TIME GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 3000)
#define RIL_DEFAULT_DISCOUNT_FACTOR 0.5
#define RIL_DEFAULT_GRADIENT_STEP_SIZE 0.4
#define RIL_DEFAULT_TRACE_DECAY 0.6
#define RIL_EXPLORE_RATIO 0.1

/**
 * ATS reinforcement learning solver
 *
 * General description
 */

enum RIL_Action_Type
{
	RIL_ACTION_BW_IN_DBL = 0,
	RIL_ACTION_BW_OUT_DBL = 1,
	RIL_ACTION_BW_IN_HLV = 2,
	RIL_ACTION_BW_OUT_HLV = 3,
	RIL_ACTION_TYPE_NUM = 4
};
//TODO! add the rest of the actions

enum RIL_Algorithm
{
	RIL_ALGO_SARSA,
	RIL_ALGO_Q
};

enum RIL_E_Modification
{
	RIL_E_SET,
	RIL_E_ZERO,
	RIL_E_ACCUMULATE,
	RIL_E_REPLACE
};

/**
 * Global learning parameters
 */
struct RIL_Learning_Parameters
{
	/**
	 * The TD-algorithm to use
	 */
	enum RIL_Algorithm algorithm;

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
	 * Environment handle
	 */
	struct GAS_RIL_Handle *envi;

	/**
	 * Peer ID
	 */
	struct GNUNET_PeerIdentity peer;

	/**
	 * Whether the agent is active or not
	 */
	int active;

	/**
	* Number of performed time-steps
	*/
	unsigned long long step_count;

	/**
	 * Experience matrix W
	 */
	double ** W;

	/**
	 * Number of rows of W / Number of state-vector features
	 */
	int m;

	/**
	 * Number of columns of W / Number of actions
	 */
	int n;

	/**
	 * Last perceived state feature vector
	 */
	double * s_old;

	/**
	 * Last chosen action
	 */
	int a_old;

	/**
	 * Eligibility trace vector
	 */
	double * e;

	/**
	 * Address in use
	 */
	struct ATS_Address * address;

	/**
	 * Inbound bandwidth assigned by the agent
	 */
	unsigned long long bw_in;

	/**
	 * Outbound bandwidth assigned by the agent
	 */
	unsigned long long bw_out;
};

struct RIL_Network
{
	  /**
	   * ATS network type
	   */
	  enum GNUNET_ATS_Network_Type type;

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
	struct RIL_Callbacks *callbacks;

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
	* Interval time between steps in milliseconds //TODO? put in agent
	*/
	struct GNUNET_TIME_Relative step_time;

	/**
	* Task identifier of the next time-step to be executed //TODO? put in agent
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
	struct RIL_Peer_Agent * agents_head;
	struct RIL_Peer_Agent * agents_tail;
};

/**
 *  Private functions
 *  ---------------------------
 */

/**
 * Estimate the current action-value for state s and action a
 * @param agent agent performing the estimation
 * @param state s
 * @param action a
 * @return estimation value
 */
static double
agent_estimate_q (struct RIL_Peer_Agent *agent,
		double *state,
		int action)
{
	int i;
	double result = 0;

	for (i = 0; i < agent->m; i++)
	{
		result += state[i] * (agent->W)[agent->m][action];
	}

	return result;
}

/**
 * Decide whether to do exploration (i.e. taking a new action) or exploitation (i.e. taking the
 * currently estimated best action) in the current step
 * @param agent agent performing the step
 * @return yes, if exploring
 */
static int
agent_decide_exploration (struct RIL_Peer_Agent *agent)
{
	double r = (double) GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, UINT32_MAX) / (double) UINT32_MAX;

	if (r < RIL_EXPLORE_RATIO)
	{
		return GNUNET_YES;
	}
	return GNUNET_NO;
}

/**
 * Gets the action, with the maximal estimated Q-value (i.e. the one currently estimated to bring the
 * most reward in the future)
 * @param agent agent performing the calculation
 * @param state the state from which to take the action
 * @return the action promising most future reward
 */
static int
agent_get_action_best (struct RIL_Peer_Agent *agent,
		double *state)
{
	int i;
	int max_i = -1;
	double cur_q;
	double max_q = DBL_MIN;

	for (i = 0; i < agent->n; i++)
	{
		cur_q = agent_estimate_q (agent, state, i);
		if (cur_q > max_q)
		{
			max_q = cur_q;
			max_i = i;
		}
	}

	GNUNET_assert(-1 != max_i);

	return max_i;
}

/**
 * Gets any action, to explore the action space from that state
 * @param agent agent performing the calculation
 * @param state the state from which to take the action
 * @return any action
 */
static int
agent_get_action_explore (struct RIL_Peer_Agent *agent,
		double *state)
{
	return GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, agent->n);
}

/**
 * Updates the weights (i.e. coefficients) of the weight vector in matrix W for action a
 * @param agent the agent performing the update
 * @param reward the reward received for the last action
 * @param s_next the new state, the last step got the agent into
 * @param a_prime the new
 */
static void
agent_update_weights (struct RIL_Peer_Agent *agent,
		double reward,
		double *s_next,
		int a_prime)
{
	int i;
	double delta;
	double *theta = (agent->W)[agent->a_old];

	delta = reward + agent_estimate_q (agent, s_next, a_prime) -
			agent_estimate_q (agent, agent->s_old, agent->a_old);
	for (i = 0; i < agent->m; i++)
	{
		theta[i] += agent->envi->parameters.alpha * delta * (agent->e)[i];
	}
}

/**
 * Changes the eligibility trace vector e in various manners:
 * RIL_E_ACCUMULATE - adds 1 to each component as in accumulating eligibility traces
 * RIL_E_REPLACE - resets each component to 1 as in replacing traces
 * RIL_E_SET - multiplies e with gamma and lambda as in the update rule
 * RIL_E_ZERO - sets e to 0 as in Watkin's Q-learning algorithm when exploring and when initializing
 * @param agent
 * @param mod
 */
static void
agent_modify_eligibility (struct RIL_Peer_Agent *agent,
		enum RIL_E_Modification mod)
{
	int i;
	double *e = agent->e;
	double gamma = agent->envi->parameters.gamma;
	double lambda = agent->envi->parameters.lambda;

	for (i = 0; i < agent->m; i++)
	{
		switch (mod)
		{
			case RIL_E_ACCUMULATE:
				e[i] += 1;
				break;
			case RIL_E_REPLACE:
				e[i] = 1;
				break;
			case RIL_E_SET:
				e[i] = gamma * lambda;
				break;
			case RIL_E_ZERO:
				e[i] = 0;
				break;
		}
	}
}

/**
 * Allocates a state vector and fills it with the features present
 * @param solver the solver handle
 * @return pointer to the state vector
 */
static double *
envi_get_state (struct GAS_RIL_Handle *solver)
{
	int i;
	struct RIL_Network *net;
	double *state = GNUNET_malloc (sizeof (double) * solver->networks_count * 4);

	for (i = 0; i < solver->networks_count; i += 4)
	{
		net = (&solver->network_entries)[i];
		state[i]   = (double) net->bw_in_assigned;
		state[i+1] = (double) net->bw_in_available;
		state[i+2] = (double) net->bw_out_assigned;
		state[i+3] = (double) net->bw_out_available;
	}

	return state;
}

/**
 * Gets the reward of the last performed step
 * @param solver solver handle
 * @return the reward
 */
static double
envi_get_reward (struct GAS_RIL_Handle *solver, struct RIL_Peer_Agent *agent)
{
	//TODO! implement reward calculation

	return (double) GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, UINT32_MAX) / (double) UINT32_MAX;
}

static void
envi_action_bw_double (struct GAS_RIL_Handle *solver,
		struct RIL_Peer_Agent *agent,
		int direction_in)
{
	if (direction_in)
	{
		agent->bw_in *= 2;
		agent->address->assigned_bw_in.value__ = htonl (agent->bw_in);
		solver->callbacks->bw_changed (solver->callbacks->bw_changed_cls, agent->address);
	}
	else
	{
		agent->bw_out *= 2;
		agent->address->assigned_bw_out.value__ = htonl (agent->bw_out);
		solver->callbacks->bw_changed (solver->callbacks->bw_changed_cls, agent->address);
	}
}

static void
envi_action_bw_halven (struct GAS_RIL_Handle *solver,
		struct RIL_Peer_Agent *agent,
		int direction_in)
{
	if ((direction_in && 1 == agent->bw_in) ||
			(!direction_in && 1 == agent->bw_out))
	{
		return;
	}
	if (direction_in)
	{
		agent->bw_in /= 2;
		agent->address->assigned_bw_in.value__ = htonl (agent->bw_in);
		solver->callbacks->bw_changed (solver->callbacks->bw_changed_cls, agent->address);
	}
	else
	{
		agent->bw_out /= 2;
		agent->address->assigned_bw_out.value__ = htonl (agent->bw_out);
		solver->callbacks->bw_changed (solver->callbacks->bw_changed_cls, agent->address);
	}
}

/**
 * Puts the action into effect
 * @param solver solver handle
 * @param action action to perform by the solver
 */
static void
envi_do_action (struct GAS_RIL_Handle *solver,
		struct RIL_Peer_Agent *agent,
		int action)
{
	switch (action)
	{
		case RIL_ACTION_BW_IN_DBL:
			envi_action_bw_double (solver, agent, GNUNET_YES);
			break;
		case RIL_ACTION_BW_IN_HLV:
			envi_action_bw_halven (solver, agent, GNUNET_YES);
			break;
		case RIL_ACTION_BW_OUT_DBL:
			envi_action_bw_double (solver, agent, GNUNET_NO);
			break;
		case RIL_ACTION_BW_OUT_HLV:
			envi_action_bw_halven (solver, agent, GNUNET_NO);
			break;
	}
}

/**
 * Performs one step of the Markov Decision Process. Other than in the literature the step starts
 * after having done the last action a_old. It observes the new state s_next and the reward
 * received. Then the coefficient update is done according to the SARSA or Q-learning method. The
 * next action is put into effect.
 * @param agent the agent performing the step
 */
static void
agent_step (struct RIL_Peer_Agent *agent)
{
	int a_next = -1;
	double *s_next;
	double reward;

	s_next = envi_get_state(agent->envi);
	reward = envi_get_reward(agent->envi, agent);

	switch (agent->envi->parameters.algorithm)
	{
		case RIL_ALGO_SARSA:
			agent_modify_eligibility (agent, RIL_E_SET);
			if (agent_decide_exploration (agent))
			{
				a_next = agent_get_action_explore (agent, s_next);
			}
			else
			{
				a_next = agent_get_action_best (agent, s_next);
			}
			//updates weights with selected action (on-policy)
			agent_update_weights (agent, reward, s_next, a_next);
			break;

		case RIL_ALGO_Q:
			//updates weights with best action, disregarding actually selected action (off-policy)
			a_next = agent_get_action_best (agent, s_next);
			agent_update_weights (agent, reward, s_next, a_next);
			if (agent_decide_exploration (agent))
			{
				a_next = agent_get_action_explore (agent, s_next);
				agent_modify_eligibility(agent, RIL_E_ZERO);
			}
			else
			{
				a_next = agent_get_action_best (agent, s_next);
				agent_modify_eligibility(agent, RIL_E_SET);
			}
			break;
	}

	GNUNET_assert (-1 != a_next);

	agent_modify_eligibility (agent, RIL_E_ACCUMULATE);

	envi_do_action(agent->envi, agent, a_next);

	GNUNET_free(agent->s_old);
	agent->s_old = s_next;
	agent->a_old = a_next;

	agent->step_count += 1;
}

/**
 * Cycles through all agents and lets the active ones do a step. Schedules the next step.
 * @param solver the solver handle
 * @param tc task context for the scheduler
 */
static void
ril_periodic_step (void *cls,
				const struct GNUNET_SCHEDULER_TaskContext *tc)
{
	struct GAS_RIL_Handle *solver = cls;
	struct RIL_Peer_Agent *cur;

	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "RIL step number %d\n", solver->step_count);

	for (cur = solver->agents_head; NULL != cur; cur = cur->next)
	{
		if (cur->active)
		{
			agent_step (cur);
		}
	}

	solver->step_count += 1;
	solver->next_step = GNUNET_SCHEDULER_add_delayed (
			solver->step_time,
			&ril_periodic_step,
			solver);
}

/**
 * Initialize an agent without addresses and its knowledge base
 * @param s ril solver
 * @param peer the one in question
 * @return handle to the new agent
 */
static struct RIL_Peer_Agent *
agent_init (void *s,
		const struct GNUNET_PeerIdentity *peer)
{
	int i;
	struct GAS_RIL_Handle * solver = s;
	struct RIL_Peer_Agent * agent = GNUNET_malloc (sizeof (struct RIL_Peer_Agent));

	agent->envi = solver;
	agent->peer = *peer;
	agent->step_count = 0;
	agent->active = GNUNET_NO;
	agent->s_old = NULL;
	agent->n = RIL_ACTION_TYPE_NUM;
	agent->m = solver->networks_count * 4;
	agent->W = (double **) GNUNET_malloc (sizeof (double) * agent->n);
	for (i = 0; i < agent->n; i++)
	{
		(agent->W)[i] = (double *) GNUNET_malloc (sizeof (double) * agent->m);
	}
	agent->a_old = -1;
	agent->e = (double *) GNUNET_malloc (sizeof (double) * agent->m);
	agent_modify_eligibility (agent, RIL_E_ZERO);

	GNUNET_CONTAINER_DLL_insert_tail (solver->agents_head, solver->agents_tail, agent);

	return agent;
}

/**
 * Deallocate agent
 * @param s solver handle
 * @param agent the agent to retire
 */
static void
agent_die (struct GAS_RIL_Handle *solver,
		struct RIL_Peer_Agent *agent)
{
	int i;

	for (i = 0; i < agent->n; i++)
	{
		GNUNET_free((agent->W)[i]);
	}
	GNUNET_free(agent->W);
	GNUNET_free(agent->e);
	GNUNET_free(agent->s_old);
}

/**
 * Returns the agent for a peer
 * @param s solver handle
 * @param peer identity of the peer
 * @return agent
 */
static struct RIL_Peer_Agent *
ril_get_agent (struct GAS_RIL_Handle *solver,
		const struct GNUNET_PeerIdentity *peer)
{
	struct RIL_Peer_Agent *cur;

	for (cur = solver->agents_head; NULL != cur; cur = cur->next)
	{
		if (0 == GNUNET_CRYPTO_hash_cmp (&peer->hashPubKey, &cur->peer.hashPubKey))
		{
			return cur;
		}
	}

	return agent_init (solver, peer);
}

/**
 * Iterator, which allocates one agent per peer
 *
 * @param cls solver
 * @param key peer identity
 * @param value address
 * @return whether iterator should continue
 */
static int
ril_init_agents_it (void *cls,
				const struct GNUNET_HashCode *key,
				void *value)
{
	struct GAS_RIL_Handle *solver = cls;
	struct ATS_Address *address = value;
	struct RIL_Peer_Agent *agent;
	uint32_t min_bw = ntohl (GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT.value__);

	agent = ril_get_agent (solver, &address->peer);

	GNUNET_assert (NULL != agent);

	if (NULL == agent->address)
	{
		agent->address = address;
		agent->address->active = GNUNET_YES;
		agent->bw_in = min_bw;
		agent->address->assigned_bw_in.value__ = htonl (min_bw);
		agent->bw_out = min_bw;
		agent->address->assigned_bw_out.value__ = htonl (min_bw);
	}

	return GNUNET_YES;
}

/**
 * Lookup network struct by type
 *
 * @param s the solver handle
 * @param type the network type
 * @return the network struct
 */
static struct RIL_Network *
ril_get_network (struct GAS_RIL_Handle *s, uint32_t type)
{
  int i;
  for (i = 0 ; i < s->networks_count; i++)
  {
      if (s->network_entries[i].type == type)
        return &s->network_entries[i];

  }
  return NULL;
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
GAS_ril_address_change_preference (void *s,
		const struct GNUNET_PeerIdentity *peer,
		enum GNUNET_ATS_PreferenceKind kind,
		double pref_rel)
{
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	              "Preference `%s' for peer `%s' changed to %.2f \n",
	              GNUNET_ATS_print_preference_type (kind),
	              GNUNET_i2s (peer),
	              pref_rel);
	  /*
	   * Nothing to do here. Preferences are considered during reward calculation.
	   */
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
	int c;
	unsigned long long tmp;
	struct RIL_Network * cur;
	struct GAS_RIL_Handle *solver = GNUNET_malloc (sizeof (struct GAS_RIL_Handle));

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
	solver->callbacks = GNUNET_malloc (sizeof (struct RIL_Callbacks));
	solver->callbacks->bw_changed = bw_changed_cb;
	solver->callbacks->bw_changed_cls = bw_changed_cb_cls;
	solver->callbacks->get_preferences = get_preference;
	solver->callbacks->get_preferences_cls = get_preference_cls;
	solver->callbacks->get_properties = get_properties;
	solver->callbacks->get_properties_cls = get_properties_cls;
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
	}

	c = GNUNET_CONTAINER_multihashmap_iterate (addresses, &ril_init_agents_it, solver);

	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ril_init() has been called\n");
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "RIL number of addresses: %d\n", c);

	solver->next_step = GNUNET_SCHEDULER_add_delayed (
				GNUNET_TIME_relative_multiply (GNUNET_TIME_relative_get_millisecond_ (), 1000),
				&ril_periodic_step,
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
	struct GAS_RIL_Handle *s = solver;
	struct RIL_Peer_Agent *cur_agent;
	struct RIL_Peer_Agent *next_agent;

	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ril_done() has been called\n");

	cur_agent = s->agents_head;
	while (NULL != cur_agent)
	{
		next_agent = cur_agent->next;
		GNUNET_CONTAINER_DLL_remove (s->agents_head, s->agents_tail, cur_agent);
		agent_die (s, cur_agent);
		cur_agent = next_agent;
	}

	GNUNET_SCHEDULER_cancel (s->next_step);
	GNUNET_free (s->callbacks);
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
	struct GAS_RIL_Handle *s = solver;
	//TODO! implement solver address add
	/*
	 * if (new peer)
	 *     initialize new agent
	 * Add address
	 * increase state vector
	 * knowledge matrix
	 * and action vector
	 */

	/*
	 * reiterate all addresses, create new agent if necessary and give the agent the address
	 */
	GNUNET_CONTAINER_multihashmap_iterate (s->addresses, &ril_init_agents_it, solver);

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
		struct ATS_Address *address,
		int session_only)
{
	//TODO! implement solver address delete
	/*
	 * remove address
	 * if (last address of peer)
	 *     remove agent
	 * else
	 *     decrease state vector
	 *     decrease knowledge matrix
	 *     decrease action vector
	 */
	struct GAS_RIL_Handle *s = solver;
	struct RIL_Peer_Agent *agent;

	agent = ril_get_agent(s, &address->peer);

	if (0 == memcmp (agent->address->addr, address->addr, address->addr_len)) //if used address deleted
	{
		agent->address = NULL; //delete address
		GNUNET_CONTAINER_multihashmap_iterate (s->addresses, &ril_init_agents_it, solver); //put another address
		if (NULL == agent->address) //no other address available
		{
			agent->active = GNUNET_NO;
		}
	}

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
	  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	              "Property `%s' for peer `%s' address %p changed to %.2f \n",
	              GNUNET_ATS_print_property_type (type),
	              GNUNET_i2s (&address->peer),
	              address, rel_value);
	  /*
	   * Nothing to do here, properties are considered in every reward calculation
	   */
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
	//TODO? consider session changed in solver behaviour
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
	//TODO! consider address_inuse_changed according to matthias' email
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
	struct GAS_RIL_Handle *s = solver;
	struct RIL_Peer_Agent *agent;
	struct RIL_Network *net;

	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Network type changed, moving %s address from `%s' to `%s'\n",
				(GNUNET_YES == address->active) ? "active" : "inactive",
				 GNUNET_ATS_print_network_type (current_network),
				 GNUNET_ATS_print_network_type (new_network));

	agent = ril_get_agent(s, &address->peer);

	if (address->active)
	{
		//remove from old network
		net = ril_get_network (s, current_network);
		net->bw_in_assigned -= agent->bw_in;
		net->bw_out_assigned -= agent->bw_out;

		//add to new network
		net = ril_get_network (s, new_network);
		net->bw_in_assigned += agent->bw_in;
		net->bw_out_assigned += agent->bw_out;
	}
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
	//TODO! collect reward until next reward calculation
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
	//TODO? consideration: keep bulk counter and stop agents during bulk
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
	//TODO? consideration: keep bulk counter and stop agents during bulk
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
	/*
	 * activate agent, return currently chosen address
	 */
	struct GAS_RIL_Handle *s = solver;
	struct RIL_Peer_Agent *agent;

	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ril_get_preferred_address() has been called\n");

	agent = ril_get_agent(s, peer);
	agent->active = GNUNET_YES;

	GNUNET_assert (NULL != agent->address);

	return agent->address;
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
	struct GAS_RIL_Handle *s = solver;
	struct RIL_Peer_Agent *agent;

	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ril_stop_get_preferred_address() has been called\n");

	agent = ril_get_agent(s, peer);
	agent->active = GNUNET_NO;
}

/* end of gnunet-service-ats-solver_ril.c */
