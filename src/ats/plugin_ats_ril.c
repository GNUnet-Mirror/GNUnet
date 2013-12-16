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
 * @file ats/plugin_ats_ril.c
 * @brief ATS reinforcement learning solver
 * @author Fabian Oehlmann
 * @author Matthias Wachs
 */
#include "plugin_ats_ril.h"

#define LOG(kind,...) GNUNET_log_from (kind, "ats-ril",__VA_ARGS__)

#define MIN_BW ntohl (GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT.value__)

#define RIL_ACTION_INVALID -1
#define RIL_FEATURES_ADDRESS_COUNT (0)// + GNUNET_ATS_QualityPropertiesCount)
#define RIL_FEATURES_NETWORK_COUNT 2
#define RIL_INTERVAL_EXPONENT 10

#define RIL_DEFAULT_STEP_TIME_MIN GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 500)
#define RIL_DEFAULT_STEP_TIME_MAX GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 3000)
#define RIL_DEFAULT_ALGORITHM RIL_ALGO_SARSA
#define RIL_DEFAULT_DISCOUNT_BETA 1
#define RIL_DEFAULT_DISCOUNT_GAMMA 0.5
#define RIL_DEFAULT_GRADIENT_STEP_SIZE 0.1
#define RIL_DEFAULT_TRACE_DECAY 0.5
#define RIL_DEFAULT_EXPLORE_RATIO 0.1
#define RIL_DEFAULT_GLOBAL_REWARD_SHARE 0.5

#define RIL_INC_DEC_STEP_SIZE 1

/**
 * ATS reinforcement learning solver
 *
 * General description
 */

/**
 * The actions, how an agent can manipulate the current assignment. I.e. how the bandwidth can be
 * changed for the currently chosen address. Not depicted in the enum are the actions of switching
 * to a particular address. The action of switching to address with index i is depicted by the
 * number (RIL_ACTION_TYPE_NUM + i).
 */
enum RIL_Action_Type
{
  RIL_ACTION_NOTHING = -1,
  RIL_ACTION_BW_IN_DBL = -2, //TODO! put actions back
  RIL_ACTION_BW_IN_HLV = -3,
  RIL_ACTION_BW_IN_INC = 0,
  RIL_ACTION_BW_IN_DEC = 1,
  RIL_ACTION_BW_OUT_DBL = -4,
  RIL_ACTION_BW_OUT_HLV = -5,
  RIL_ACTION_BW_OUT_INC = -6,
  RIL_ACTION_BW_OUT_DEC = -7,
  RIL_ACTION_TYPE_NUM = 1
};

enum RIL_Algorithm
{
  RIL_ALGO_SARSA = 0,
  RIL_ALGO_Q = 1
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
   * Gradient-descent step-size
   */
  double alpha;

  /**
   * Learning discount variable in the TD-update for semi-MDPs
   */
  double beta;

  /**
   * Learning discount factor in the TD-update for MDPs
   */
  double gamma;

  /**
   * Trace-decay factor for eligibility traces
   */
  double lambda;

  /**
   * Ratio, with what probability an agent should explore in the e-greed policy
   */
  double explore_ratio;

  /**
   * How big the share of the global part of the reward signal is
   */
  double reward_global_share;

  /**
   * Minimal interval time between steps in milliseconds
   */
  struct GNUNET_TIME_Relative step_time_min;

  /**
   * Maximum interval time between steps in milliseconds
   */
  struct GNUNET_TIME_Relative step_time_max;
};

/**
 * Wrapper for addresses to store them in agent's linked list
 */
struct RIL_Address_Wrapped
{
  /**
   * Next in DLL
   */
  struct RIL_Address_Wrapped *next;

  /**
   * Previous in DLL
   */
  struct RIL_Address_Wrapped *prev;

  /**
   * The address
   */
  struct ATS_Address *address_naked;
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
  int is_active;

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
  unsigned int m;

  /**
   * Number of columns of W / Number of actions
   */
  unsigned int n;

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
  struct ATS_Address * address_inuse;

  /**
   * Head of addresses DLL
   */
  struct RIL_Address_Wrapped * addresses_head;

  /**
   * Tail of addresses DLL
   */
  struct RIL_Address_Wrapped * addresses_tail;

  /**
   * Inbound bandwidth assigned by the agent
   */
  unsigned long long bw_in;

  /**
   * Outbound bandwidth assigned by the agent
   */
  unsigned long long bw_out;

  /**
   * Flag whether a suggestion has to be issued
   */
  int suggestion_issue;

  /**
   * The address which has to be issued
   */
  struct ATS_Address * suggestion_address;
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
   * Bandwidth inbound assigned in network after last step
   */
  unsigned long long bw_in_assigned;

  /**
   * Total available outbound bandwidth
   */
  unsigned long long bw_out_available;

  /**
   * * Bandwidth outbound assigned in network after last step
   */
  unsigned long long bw_out_assigned;
};

/**
 * A handle for the reinforcement learning solver
 */
struct GAS_RIL_Handle
{
  /**
   * The solver-plugin environment of the solver-plugin API
   */
  struct GNUNET_ATS_PluginEnvironment *plugin_envi;

  /**
   * Statistics handle
   */
  struct GNUNET_STATISTICS_Handle *stats;

  /**
   * Number of performed steps
   */
  unsigned long long step_count;

  /**
   * Timestamp for the last time-step
   */
  struct GNUNET_TIME_Absolute step_time_last;

  /**
   * Task identifier of the next time-step to be executed
   */
  GNUNET_SCHEDULER_TaskIdentifier step_next_task_id;

  /**
   * Variable discount factor, dependent on time between steps
   */
  double global_discount_variable;

  /**
   * Integrated variable discount factor, dependent on time between steps
   */
  double global_discount_integrated;

  /**
   * State vector for networks for the current step
   */
  double *global_state_networks;

  /**
   * Lock for bulk operations
   */
  int bulk_lock;

  /**
   * Number of changes during a lock
   */
  int bulk_changes;

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

  /**
   * Shutdown
   */
  int done;

  /**
   * Simulate steps, i.e. schedule steps immediately
   */
  unsigned long long simulate;
};

/*
 *  Private functions
 *  ---------------------------
 */

static int
ril_count_agents(struct GAS_RIL_Handle * solver);


/**
 * Estimate the current action-value for state s and action a
 *
 * @param agent agent performing the estimation
 * @param state s
 * @param action a
 * @return estimation value
 */
static double
agent_estimate_q (struct RIL_Peer_Agent *agent, double *state, int action)
{
  int i;
  double result = 0;

  for (i = 0; i < agent->m; i++)
  {
    result += state[i] * agent->W[action][i];
  }

  GNUNET_assert(!isnan(result));

  if (isinf(result))
  {
    return isinf(result) * UINT32_MAX; //TODO! fix
  }
  return result;
}


/**
 * Decide whether to do exploration (i.e. taking a new action) or exploitation (i.e. taking the
 * currently estimated best action) in the current step
 *
 * @param agent agent performing the step
 * @return yes, if exploring
 */
static int
agent_decide_exploration (struct RIL_Peer_Agent *agent)
{
  //TODO? Future Work: Improve exploration/exploitation trade-off by different mechanisms than e-greedy
  double r = (double) GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
      UINT32_MAX) / (double) UINT32_MAX;

  if (r < agent->envi->parameters.explore_ratio)
  {
    return GNUNET_YES;
  }
  return GNUNET_NO;
}


/**
 * Get the index of the address in the agent's list.
 *
 * @param agent agent handle
 * @param address address handle
 * @return the index, starting with zero
 */
static int
agent_address_get_index (struct RIL_Peer_Agent *agent, struct ATS_Address *address)
{
  int i;
  struct RIL_Address_Wrapped *cur;

  i = -1;
  for (cur = agent->addresses_head; NULL != cur; cur = cur->next)
  {
    i++;
    if (cur->address_naked == address)
      return i;
  }
  return i;
}


/**
 * Gets the wrapped address from the agent's list
 *
 * @param agent agent handle
 * @param address address handle
 * @return wrapped address
 */
static struct RIL_Address_Wrapped *
agent_address_get (struct RIL_Peer_Agent *agent, struct ATS_Address *address)
{
  struct RIL_Address_Wrapped *cur;

  for (cur = agent->addresses_head; NULL != cur; cur = cur->next)
    if (cur->address_naked == address)
      return cur;
  return NULL;
}


/**
 * Gets the action, with the maximal estimated Q-value (i.e. the one currently estimated to bring the
 * most reward in the future)
 *
 * @param agent agent performing the calculation
 * @param state the state from which to take the action
 * @return the action promising most future reward
 */
static int
agent_get_action_best (struct RIL_Peer_Agent *agent, double *state)
{
  int i;
  int max_i = RIL_ACTION_INVALID;
  double cur_q;
  double max_q = -DBL_MAX;

  for (i = 0; i < agent->n; i++)
  {
    cur_q = agent_estimate_q (agent, state, i);
    if (cur_q > max_q)
    {
      max_q = cur_q;
      max_i = i;
    }
  }

  GNUNET_assert(RIL_ACTION_INVALID != max_i);

  return max_i;
}


/**
 * Gets any action, to explore the action space from that state
 *
 * @param agent agent performing the calculation
 * @param state the state from which to take the action
 * @return any action
 */
static int
agent_get_action_explore (struct RIL_Peer_Agent *agent, double *state)
{
  // TODO?: Future Work: Choose the action for exploration, which has been explored the least in this state
  return GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, agent->n);
}


/**
 * Updates the weights (i.e. coefficients) of the weight vector in matrix W for action a
 *
 * @param agent the agent performing the update
 * @param reward the reward received for the last action
 * @param s_next the new state, the last step got the agent into
 * @param a_prime the new
 */
static void
agent_update_weights (struct RIL_Peer_Agent *agent, double reward, double *s_next, int a_prime)
{
  int i;
  double delta;
  double *theta = agent->W[agent->a_old];

  delta = agent->envi->global_discount_integrated * reward; //reward
  delta += agent->envi->global_discount_variable * agent_estimate_q (agent, s_next, a_prime); //discounted future value
  delta -= agent_estimate_q (agent, agent->s_old, agent->a_old); //one step

  LOG(GNUNET_ERROR_TYPE_INFO, "update()   Step# %llu  Q(s,a): %f  a: %f  r: %f  y: %f  Q(s+1,a+1) = %f  delta: %f\n",
      agent->step_count,
      agent_estimate_q (agent, agent->s_old, agent->a_old),
      agent->envi->parameters.alpha,
      reward,
      agent->envi->global_discount_variable,
      agent_estimate_q (agent, s_next, a_prime),
      delta);

  for (i = 0; i < agent->m; i++)
  {
//    LOG(GNUNET_ERROR_TYPE_INFO, "alpha = %f   delta = %f   e[%d] = %f\n",
//        agent->envi->parameters.alpha,
//        delta,
//        i,
//        agent->e[i]);
    theta[i] += agent->envi->parameters.alpha * delta * agent->s_old[i];// * agent->e[i];
  }
}


/**
 * Changes the eligibility trace vector e in various manners:
 * #RIL_E_ACCUMULATE - adds @a f to each component as in accumulating eligibility traces
 * #RIL_E_REPLACE - resets each component to @a f  as in replacing traces
 * #RIL_E_SET - multiplies e with discount factor and lambda as in the update rule
 * #RIL_E_ZERO - sets e to 0 as in Watkin's Q-learning algorithm when exploring and when initializing
 *
 * @param agent the agent handle
 * @param mod the kind of modification
 * @param f how much to change
 */
static void
agent_modify_eligibility (struct RIL_Peer_Agent *agent,
                          enum RIL_E_Modification mod,
                          double *f)
{
  int i;
  double *e = agent->e;

  for (i = 0; i < agent->m; i++)
  {
    switch (mod)
    {
    case RIL_E_ACCUMULATE:
      e[i] += f[i];
      break;
    case RIL_E_REPLACE:
      e[i] = f[i];
      break;
    case RIL_E_SET:
      e[i] *= agent->envi->global_discount_variable * agent->envi->parameters.lambda;
      break;
    case RIL_E_ZERO:
      e[i] = 0;
      break;
    }
  }
}


static void
ril_inform (struct GAS_RIL_Handle *solver,
    enum GAS_Solver_Operation op,
    enum GAS_Solver_Status stat)
{
  if (NULL != solver->plugin_envi->info_cb)
    solver->plugin_envi->info_cb (solver->plugin_envi->info_cb_cls, op, stat, GAS_INFO_NONE);
}


/**
 * Changes the active assignment suggestion of the handler and invokes the bw_changed callback to
 * notify ATS of its new decision
 *
 * @param solver solver handle
 * @param agent agent handle
 * @param new_address the address which is to be used
 * @param new_bw_in the new amount of inbound bandwidth set for this address
 * @param new_bw_out the new amount of outbound bandwidth set for this address
 * @param silent disables invocation of the bw_changed callback, if GNUNET_YES
 */
static void
envi_set_active_suggestion (struct GAS_RIL_Handle *solver,
    struct RIL_Peer_Agent *agent,
    struct ATS_Address *new_address,
    unsigned long long new_bw_in,
    unsigned long long new_bw_out,
    int silent)
{
  int notify = GNUNET_NO;

  LOG(GNUNET_ERROR_TYPE_DEBUG, "    set_active_suggestion() for peer '%s'\n", GNUNET_i2s (&agent->peer));

  //address change
  if (agent->address_inuse != new_address)
  {
    if (NULL != agent->address_inuse)
    {
      agent->address_inuse->active = GNUNET_NO;
      agent->address_inuse->assigned_bw_in.value__ = htonl (0);
      agent->address_inuse->assigned_bw_out.value__ = htonl (0);
    }
    if (NULL != new_address)
    {
      LOG(GNUNET_ERROR_TYPE_DEBUG, "    set address active: %s\n", agent->is_active ? "yes" : "no");
      new_address->active = agent->is_active;
      new_address->assigned_bw_in.value__ = htonl (agent->bw_in);
      new_address->assigned_bw_out.value__ = htonl (agent->bw_out);
    }
    notify |= GNUNET_YES;
  }

  if (new_address)
  {
    //activity change
    if (new_address->active != agent->is_active)
    {
      new_address->active = agent->is_active;
      notify |= GNUNET_YES;
    }

    //bw change
    if (agent->bw_in != new_bw_in)
    {
      agent->bw_in = new_bw_in;
      new_address->assigned_bw_in.value__ = htonl (new_bw_in);
      notify |= GNUNET_YES;
    }
    if (agent->bw_out != new_bw_out)
    {
      agent->bw_out = new_bw_out;
      new_address->assigned_bw_out.value__ = htonl (new_bw_out);
      notify |= GNUNET_YES;
    }
  }

  if (notify && agent->is_active && (GNUNET_NO == silent))
  {
    if (new_address)
    {
      LOG(GNUNET_ERROR_TYPE_DEBUG, "    envi_set_active_suggestion() notify\n");
      agent->suggestion_issue = GNUNET_YES;
      agent->suggestion_address = new_address;
    }
    else if (agent->address_inuse)
    {
      //disconnect case, no new address
      GNUNET_assert(0 == ntohl (agent->address_inuse->assigned_bw_in.value__));
      GNUNET_assert(0 == ntohl (agent->address_inuse->assigned_bw_out.value__));
      agent->bw_in = 0;
      agent->bw_out = 0;

      agent->suggestion_issue = GNUNET_YES;
      agent->suggestion_address = agent->address_inuse;
    }
  }
  agent->address_inuse = new_address;
}


static unsigned long long
ril_network_get_assigned (struct GAS_RIL_Handle *solver, enum GNUNET_ATS_Network_Type type, int direction_in)
{
  struct RIL_Peer_Agent *cur;
  struct RIL_Network *net;
  unsigned long long sum = 0;

  for (cur = solver->agents_head; NULL != cur; cur = cur->next)
  {
    if (cur->is_active && cur->address_inuse)
    {
      net = cur->address_inuse->solver_information;
      if (net->type == type)
      {
        if (direction_in)
          sum += cur->bw_in;
        else
          sum += cur->bw_out;
      }
    }
  }

  return sum;
}

//static void
//envi_state_networks (struct GAS_RIL_Handle *solver)
//{
//  int i;
//  struct RIL_Network net;
//  int overutilized_in;
//  int overutilized_out;
//
//  for (i = 0; i < solver->networks_count; i++)
//  {
//    net = solver->network_entries[i];
//
//    overutilized_in = net.bw_in_assigned > net.bw_in_available;
//    overutilized_out = net.bw_out_assigned > net.bw_out_available;
//
//    solver->global_state_networks[i * RIL_FEATURES_NETWORK_COUNT + 0] = ((double) net.bw_in_assigned / (double) net.bw_in_available)*10;
//    solver->global_state_networks[i * RIL_FEATURES_NETWORK_COUNT + 1] = (double) overutilized_in;
//    solver->global_state_networks[i * RIL_FEATURES_NETWORK_COUNT + 2] = ((double) net.bw_out_assigned / (double) net.bw_out_available)*10;
//    solver->global_state_networks[i * RIL_FEATURES_NETWORK_COUNT + 3] = (double) overutilized_out;
//  }
//}

/**
 * Allocates a state vector and fills it with the features present
 * @param solver the solver handle
 * @param agent the agent handle
 * @return pointer to the state vector
 */
static double *
envi_get_state (struct GAS_RIL_Handle *solver, struct RIL_Peer_Agent *agent)
{
  int i;
//  int k;
  double *state = GNUNET_malloc (sizeof (double) * agent->m);
  struct RIL_Address_Wrapped *cur_address;
//  const double *preferences;
//  const double *properties;
  struct RIL_Network *net;

  //copy global networks state
  for (i = 0; i < solver->networks_count * RIL_FEATURES_NETWORK_COUNT; i++)
  {
//    state[i] = solver->global_state_networks[i];
  }
  net = agent->address_inuse->solver_information;

  state[0] = (double) net->bw_in_assigned / 1024; //(double) net->bw_in_available;
  if (net->bw_in_assigned > net->bw_in_available)
  {
    state[1] = 1;// net->bw_in_available;
  }
  else
  {
    state[1] = 0;
  }
  LOG(GNUNET_ERROR_TYPE_INFO, "get_state()  state[0] = %f\n", state[0]);
  LOG(GNUNET_ERROR_TYPE_INFO, "get_state()  state[1] = %f\n", state[1]);

  LOG(GNUNET_ERROR_TYPE_INFO, "get_state()  W / %08.3f %08.3f \\ \n", agent->W[0][0], agent->W[1][0]);
  LOG(GNUNET_ERROR_TYPE_INFO, "get_state()  W \\ %08.3f %08.3f / \n", agent->W[0][1], agent->W[1][1]);


  //get peer features
//  preferences = solver->plugin_envi->get_preferences (solver->plugin_envi->get_preference_cls,
//        &agent->peer);
//  for (k = 0; k < GNUNET_ATS_PreferenceCount; k++)
//  {
//    state[i++] = preferences[k];
//  }

  //get address specific features
  for (cur_address = agent->addresses_head; NULL != cur_address; cur_address = cur_address->next)
  {
//    //when changing the number of address specific state features, change RIL_FEATURES_ADDRESS_COUNT macro
//    state[i++] = cur_address->address_naked->active;
//    state[i++] = cur_address->address_naked->active ? agent->bw_in : 0;
//    state[i++] = cur_address->address_naked->active ? agent->bw_out : 0;
//    properties = solver->plugin_envi->get_property (solver->plugin_envi->get_property_cls,
//        cur_address->address_naked);
//    for (k = 0; k < GNUNET_ATS_QualityPropertiesCount; k++)
//    {
//      state[i++] = properties[k];
//    }
  }

  return state;
}

///*
// * For all networks a peer has an address in, this gets the maximum bandwidth which could
// * theoretically be available in one of the networks. This is used for bandwidth normalization.
// *
// * @param agent the agent handle
// * @param direction_in whether the inbound bandwidth should be considered. Returns the maximum outbound bandwidth if GNUNET_NO
// */
//static unsigned long long
//ril_get_max_bw (struct RIL_Peer_Agent *agent, int direction_in)
//{
//  /*
//   * get the maximum bandwidth possible for a peer, e.g. among all addresses which addresses'
//   * network could provide the maximum bandwidth if all that bandwidth was used on that one peer.
//   */
//  unsigned long long max = 0;
//  struct RIL_Address_Wrapped *cur;
//  struct RIL_Network *net;
//
//  for (cur = agent->addresses_head; NULL != cur; cur = cur->next)
//  {
//    net = cur->address_naked->solver_information;
//    if (direction_in)
//    {
//      if (net->bw_in_available > max)
//      {
//        max = net->bw_in_available;
//      }
//    }
//    else
//    {
//      if (net->bw_out_available > max)
//      {
//        max = net->bw_out_available;
//      }
//    }
//  }
//  return max;
//}

///*
// * Get the index of the quality-property in question
// *
// * @param type the quality property type
// * @return the index
// */
//static int
//ril_find_property_index (uint32_t type)
//{
//  int existing_types[] = GNUNET_ATS_QualityProperties;
//  int c;
//  for (c = 0; c < GNUNET_ATS_QualityPropertiesCount; c++)
//    if (existing_types[c] == type)
//      return c;
//  return GNUNET_SYSERR;
//}

//static int
//ril_get_atsi (struct ATS_Address *address, uint32_t type)
//{
//  int c1;
//  GNUNET_assert(NULL != address);
//
//  if ((NULL == address->atsi) || (0 == address->atsi_count))
//    return 0;
//
//  for (c1 = 0; c1 < address->atsi_count; c1++)
//  {
//    if (ntohl (address->atsi[c1].type) == type)
//      return ntohl (address->atsi[c1].value);
//  }
//  return 0;
//}

//static double
//envi_reward_global (struct GAS_RIL_Handle *solver)
//{
//  int i;
//  struct RIL_Network net;
//  unsigned int sum_in_available = 0;
//  unsigned int sum_out_available = 0;
//  unsigned int sum_in_assigned = 0;
//  unsigned int sum_out_assigned = 0;
//  double ratio_in;
//  double ratio_out;
//
//  for (i = 0; i < solver->networks_count; i++)
//  {
//    net = solver->network_entries[i];
//    sum_in_available += net.bw_in_available;
//    sum_in_assigned += net.bw_in_assigned;
//    sum_out_available += net.bw_out_available;
//    sum_out_assigned += net.bw_out_assigned;
//  }
//
//  ratio_in = ((double) sum_in_assigned) / ((double) sum_in_available);
//  ratio_out = ((double) sum_out_assigned) / ((double) sum_out_available);
//
//  // global reward in [1,2]
//  return ratio_in +1;
//  return ((ratio_in + ratio_out) / 2) + 1;
//}

//static double
//envi_reward_local (struct GAS_RIL_Handle *solver, struct RIL_Peer_Agent *agent)
//{
//  const double *preferences;
//  const double *properties;
//  int prop_index;
//  double pref_match = 0;
//  double bw_norm;
//  double dl_norm;
//
//  preferences = solver->plugin_envi->get_preferences (solver->plugin_envi->get_preference_cls,
//      &agent->peer);
//  properties = solver->plugin_envi->get_property (solver->plugin_envi->get_property_cls,
//      agent->address_inuse);
//
//  // delay in [0,1]
//  prop_index = ril_find_property_index (GNUNET_ATS_QUALITY_NET_DELAY);
//  dl_norm = 2 - properties[prop_index]; //invert property as we want to maximize for lower latencies
//
//  // utilization in [0,1]
//  bw_norm = (((double) ril_get_atsi (agent->address_inuse, GNUNET_ATS_UTILIZATION_IN)
//      / (double) ril_get_max_bw (agent, GNUNET_YES))
//      + ((double) ril_get_atsi (agent->address_inuse, GNUNET_ATS_UTILIZATION_OUT)
//          / (double) ril_get_max_bw (agent, GNUNET_NO))) / 2;
//
//  // preference matching in [0,4]
//  pref_match += (preferences[GNUNET_ATS_PREFERENCE_LATENCY] * dl_norm);
//  pref_match += (preferences[GNUNET_ATS_PREFERENCE_BANDWIDTH] * bw_norm);
//
//  // local reward in [1,2]
//  return (pref_match / 4) +1;
//}

/**
 * Gets the reward for the last performed step, which is calculated in equal
 * parts from the local (the peer specific) and the global (for all peers
 * identical) reward.
 *
 * @param solver the solver handle
 * @param agent the agent handle
 * @return the reward
 */
static double
envi_get_reward (struct GAS_RIL_Handle *solver, struct RIL_Peer_Agent *agent)
{
  struct RIL_Network *net;
//  double reward = 0;
  long long overutilized_in = 0;
//  long long overutilized_out;
  long long assigned_in = 0;
//  long long assigned_out = 0;
//  long long unused;

  //punish overutilization
  net = agent->address_inuse->solver_information;

  if (net->bw_in_assigned > net->bw_in_available)
  {
    overutilized_in = (net->bw_in_assigned - net->bw_in_available);
    assigned_in = net->bw_in_available;
  }
  else
  {
    assigned_in = net->bw_in_assigned;
  }
//  if (net->bw_out_assigned > net->bw_out_available)
//  {
//    overutilized_out = (net->bw_out_assigned - net->bw_out_available);
//    assigned_out = net->bw_out_available;
//  }
//  else
//  {
//    assigned_out = net->bw_out_assigned;
//  }

//  unused = net->bw_in_available - net->bw_in_assigned;
//  unused = unused < 0 ? unused : -unused;

  return (double) (assigned_in - overutilized_in) / 1024;

//  reward += envi_reward_global (solver) * (solver->parameters.reward_global_share);
//  reward += envi_reward_local (solver, agent) * (1 - solver->parameters.reward_global_share);
//
//  return (reward - 1.) * 100;
}

/**
 * Doubles the bandwidth for the active address
 *
 * @param solver solver handle
 * @param agent agent handle
 * @param direction_in if GNUNET_YES, change inbound bandwidth, otherwise the outbound bandwidth
 */
static void
envi_action_bw_double (struct GAS_RIL_Handle *solver,
    struct RIL_Peer_Agent *agent,
    int direction_in)
{
  unsigned long long new_bw;

  if (direction_in)
  {
    new_bw = agent->bw_in * 2;
    if (new_bw < agent->bw_in || new_bw > GNUNET_ATS_MaxBandwidth)
      new_bw = GNUNET_ATS_MaxBandwidth;
    envi_set_active_suggestion (solver, agent, agent->address_inuse, new_bw,
        agent->bw_out, GNUNET_NO);
  }
  else
  {
    new_bw = agent->bw_out * 2;
    if (new_bw < agent->bw_out || new_bw > GNUNET_ATS_MaxBandwidth)
      new_bw = GNUNET_ATS_MaxBandwidth;
    envi_set_active_suggestion (solver, agent, agent->address_inuse, agent->bw_in,
        new_bw, GNUNET_NO);
  }
}

/**
 * Cuts the bandwidth for the active address in half. The least amount of bandwidth suggested, is
 * the minimum bandwidth for a peer, in order to not invoke a disconnect.
 *
 * @param solver solver handle
 * @param agent agent handle
 * @param direction_in if GNUNET_YES, change inbound bandwidth, otherwise change the outbound
 * bandwidth
 */
static void
envi_action_bw_halven (struct GAS_RIL_Handle *solver,
    struct RIL_Peer_Agent *agent,
    int direction_in)
{
  unsigned long long new_bw;

  if (direction_in)
  {
    new_bw = agent->bw_in / 2;
    if (new_bw < MIN_BW || new_bw > agent->bw_in)
      new_bw = MIN_BW;
    envi_set_active_suggestion (solver, agent, agent->address_inuse, new_bw, agent->bw_out,
        GNUNET_NO);
  }
  else
  {
    new_bw = agent->bw_out / 2;
    if (new_bw < MIN_BW || new_bw > agent->bw_out)
      new_bw = MIN_BW;
    envi_set_active_suggestion (solver, agent, agent->address_inuse, agent->bw_in, new_bw,
        GNUNET_NO);
  }
}

/**
 * Increases the bandwidth by 5 times the minimum bandwidth for the active address.
 *
 * @param solver solver handle
 * @param agent agent handle
 * @param direction_in if GNUNET_YES, change inbound bandwidth, otherwise change the outbound
 * bandwidth
 */
static void
envi_action_bw_inc (struct GAS_RIL_Handle *solver, struct RIL_Peer_Agent *agent, int direction_in)
{
  unsigned long long new_bw;

  if (direction_in)
  {
    new_bw = agent->bw_in + (RIL_INC_DEC_STEP_SIZE * MIN_BW);
    if (new_bw < agent->bw_in || new_bw > GNUNET_ATS_MaxBandwidth)
      new_bw = GNUNET_ATS_MaxBandwidth;
    envi_set_active_suggestion (solver, agent, agent->address_inuse, new_bw,
        agent->bw_out, GNUNET_NO);
  }
  else
  {
    new_bw = agent->bw_out + (RIL_INC_DEC_STEP_SIZE * MIN_BW);
    if (new_bw < agent->bw_out || new_bw > GNUNET_ATS_MaxBandwidth)
      new_bw = GNUNET_ATS_MaxBandwidth;
    envi_set_active_suggestion (solver, agent, agent->address_inuse, agent->bw_in,
        new_bw, GNUNET_NO);
  }
}

/**
 * Decreases the bandwidth by 5 times the minimum bandwidth for the active address. The least amount
 * of bandwidth suggested, is the minimum bandwidth for a peer, in order to not invoke a disconnect.
 *
 * @param solver solver handle
 * @param agent agent handle
 * @param direction_in if GNUNET_YES, change inbound bandwidth, otherwise change the outbound
 * bandwidth
 */
static void
envi_action_bw_dec (struct GAS_RIL_Handle *solver, struct RIL_Peer_Agent *agent, int direction_in)
{
  unsigned long long new_bw;

  if (direction_in)
  {
    new_bw = agent->bw_in - (RIL_INC_DEC_STEP_SIZE * MIN_BW);
    if (new_bw < MIN_BW || new_bw > agent->bw_in)
      new_bw = MIN_BW;
    envi_set_active_suggestion (solver, agent, agent->address_inuse, new_bw, agent->bw_out,
        GNUNET_NO);
  }
  else
  {
    new_bw = agent->bw_out - (RIL_INC_DEC_STEP_SIZE * MIN_BW);
    if (new_bw < MIN_BW || new_bw > agent->bw_out)
      new_bw = MIN_BW;
    envi_set_active_suggestion (solver, agent, agent->address_inuse, agent->bw_in, new_bw,
        GNUNET_NO);
  }
}

/**
 * Switches to the address given by its index
 *
 * @param solver solver handle
 * @param agent agent handle
 * @param address_index index of the address as it is saved in the agent's list, starting with zero
 */
static void
envi_action_address_switch (struct GAS_RIL_Handle *solver,
    struct RIL_Peer_Agent *agent,
    unsigned int address_index)
{
  struct RIL_Address_Wrapped *cur;
  int i = 0;

  for (cur = agent->addresses_head; NULL != cur; cur = cur->next)
  {
    if (i == address_index)
    {
      envi_set_active_suggestion (solver, agent, cur->address_naked, agent->bw_in, agent->bw_out,
          GNUNET_NO);
      return;
    }

    i++;
  }

  //no address with address_index exists, in this case this action should not be callable
  GNUNET_assert(GNUNET_NO);
}

/**
 * Puts the action into effect by calling the according function
 *
 * @param solver the solver handle
 * @param agent the action handle
 * @param action the action to perform by the solver
 */
static void
envi_do_action (struct GAS_RIL_Handle *solver, struct RIL_Peer_Agent *agent, int action)
{
  int address_index;

  switch (action)
  {
  case RIL_ACTION_NOTHING:
    break;
  case RIL_ACTION_BW_IN_DBL:
    envi_action_bw_double (solver, agent, GNUNET_YES);
    break;
  case RIL_ACTION_BW_IN_HLV:
    envi_action_bw_halven (solver, agent, GNUNET_YES);
    break;
  case RIL_ACTION_BW_IN_INC:
    envi_action_bw_inc (solver, agent, GNUNET_YES);
    break;
  case RIL_ACTION_BW_IN_DEC:
    envi_action_bw_dec (solver, agent, GNUNET_YES);
    break;
  case RIL_ACTION_BW_OUT_DBL:
    envi_action_bw_double (solver, agent, GNUNET_NO);
    break;
  case RIL_ACTION_BW_OUT_HLV:
    envi_action_bw_halven (solver, agent, GNUNET_NO);
    break;
  case RIL_ACTION_BW_OUT_INC:
    envi_action_bw_inc (solver, agent, GNUNET_NO);
    break;
  case RIL_ACTION_BW_OUT_DEC:
    envi_action_bw_dec (solver, agent, GNUNET_NO);
    break;
  default:
    if ((action >= RIL_ACTION_TYPE_NUM) && (action < agent->n)) //switch address action
    {
      address_index = action - RIL_ACTION_TYPE_NUM;

      GNUNET_assert(address_index >= 0);
      GNUNET_assert(
          address_index <= agent_address_get_index (agent, agent->addresses_tail->address_naked));

      envi_action_address_switch (solver, agent, address_index);
      break;
    }
    // error - action does not exist
    GNUNET_assert(GNUNET_NO);
  }
}

/**
 * Performs one step of the Markov Decision Process. Other than in the literature the step starts
 * after having done the last action a_old. It observes the new state s_next and the reward
 * received. Then the coefficient update is done according to the SARSA or Q-learning method. The
 * next action is put into effect.
 *
 * @param agent the agent performing the step
 */
static void
agent_step (struct RIL_Peer_Agent *agent)
{
  int a_next = RIL_ACTION_INVALID;
  int explore;
  double *s_next;
  double reward;

  LOG(GNUNET_ERROR_TYPE_DEBUG, "    agent_step() Peer '%s', algorithm %s\n",
      GNUNET_i2s (&agent->peer),
      agent->envi->parameters.algorithm ? "Q" : "SARSA");

  s_next = envi_get_state (agent->envi, agent);
  reward = envi_get_reward (agent->envi, agent);
  explore = agent_decide_exploration (agent);

  switch (agent->envi->parameters.algorithm)
  {
  case RIL_ALGO_SARSA:
    if (explore)
    {
      a_next = agent_get_action_explore (agent, s_next);
    }
    else
    {
      a_next = agent_get_action_best (agent, s_next);
    }
    if (RIL_ACTION_INVALID != agent->a_old)
    {
      //updates weights with selected action (on-policy), if not first step
      agent_update_weights (agent, reward, s_next, a_next);
      agent_modify_eligibility (agent, RIL_E_SET, s_next);
    }
    break;

  case RIL_ALGO_Q:
    a_next = agent_get_action_best (agent, s_next);
    if (RIL_ACTION_INVALID != agent->a_old)
    {
      //updates weights with best action, disregarding actually selected action (off-policy), if not first step
      agent_update_weights (agent, reward, s_next, a_next);
    }
    if (explore)
    {
      a_next = agent_get_action_explore (agent, s_next);
      agent_modify_eligibility (agent, RIL_E_ZERO, NULL);
    }
    else
    {
      a_next = agent_get_action_best (agent, s_next);
      agent_modify_eligibility (agent, RIL_E_SET, s_next);
    }
    break;
  }

  GNUNET_assert(RIL_ACTION_INVALID != a_next);

  agent_modify_eligibility (agent, RIL_E_ACCUMULATE, s_next);

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "step()  Step# %llu  R: %f  IN %llu  OUT %llu  A: %d\n",
        agent->step_count,
        reward,
        agent->bw_in/1024,
        agent->bw_out/1024,
        a_next);

  envi_do_action (agent->envi, agent, a_next);

  GNUNET_free(agent->s_old);
  agent->s_old = s_next;
  agent->a_old = a_next;

  agent->step_count += 1;
}

static void
ril_step (struct GAS_RIL_Handle *solver);

/**
 * Task for the scheduler, which performs one step and lets the solver know that
 * no further step is scheduled.
 *
 * @param cls the solver handle
 * @param tc the task context for the scheduler
 */
static void
ril_step_scheduler_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GAS_RIL_Handle *solver = cls;

  solver->step_next_task_id = GNUNET_SCHEDULER_NO_TASK;
  ril_step (solver);
}

static double
ril_get_used_resource_ratio (struct GAS_RIL_Handle *solver)
{
  int i;
  struct RIL_Network net;
  unsigned long long sum_assigned = 0;
  unsigned long long sum_available = 0;
  double ratio;

  for (i = 0; i < solver->networks_count; i++)
  {
    net = solver->network_entries[i];
    if (net.bw_in_assigned > 0) //only consider scopes where an address is actually active
    {
      sum_assigned += net.bw_in_assigned;
      sum_assigned += net.bw_out_assigned;
      sum_available += net.bw_in_available;
      sum_available += net.bw_out_available;
    }
  }
  if (sum_available > 0)
  {
    ratio = ((double) sum_assigned) / ((double) sum_available);
  }
  else
  {
    ratio = 0;
  }

  return ratio > 1 ? 1 : ratio; //overutilization possible, cap at 1
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

  for (i = 0; i < s->networks_count; i++)
  {
    if (s->network_entries[i].type == type)
    {
      return &s->network_entries[i];
    }
  }
  return NULL ;
}

static int
ril_network_is_not_full (struct GAS_RIL_Handle *solver, enum GNUNET_ATS_Network_Type network)
{
  struct RIL_Network *net;
  struct RIL_Peer_Agent *agent;
  unsigned long long address_count = 0;

  for (agent = solver->agents_head; NULL != agent; agent = agent->next)
  {
    if (agent->address_inuse && agent->is_active)
    {
      net = agent->address_inuse->solver_information;
      if (net->type == network)
      {
        address_count++;
      }
    }
  }

  net = ril_get_network (solver, network);
  return (net->bw_in_available > MIN_BW * address_count) && (net->bw_out_available > MIN_BW * address_count);
}

static void
ril_try_unblock_agent (struct GAS_RIL_Handle *solver, struct RIL_Peer_Agent *agent, int silent)
{
  struct RIL_Address_Wrapped *addr_wrap;
  struct RIL_Network *net;

  for (addr_wrap = agent->addresses_head; NULL != addr_wrap; addr_wrap = addr_wrap->next)
  {
    net = addr_wrap->address_naked->solver_information;
    if (ril_network_is_not_full(solver, net->type))
    {
      if (NULL == agent->address_inuse)
        envi_set_active_suggestion (solver, agent, addr_wrap->address_naked, MIN_BW, MIN_BW, silent);
      return;
    }
  }
  agent->address_inuse = NULL;
}

static void
ril_calculate_discount (struct GAS_RIL_Handle *solver)
{
  struct GNUNET_TIME_Absolute time_now;
  struct GNUNET_TIME_Relative time_delta;
  double tau;

  // MDP case - remove when debugged
  if (solver->simulate)
  {
    solver->global_discount_variable = solver->parameters.gamma;
    solver->global_discount_integrated = 1;
    return;
  }

  // semi-MDP case

  //calculate tau, i.e. how many real valued time units have passed, one time unit is one minimum time step
  time_now = GNUNET_TIME_absolute_get ();
  time_delta = GNUNET_TIME_absolute_get_difference (solver->step_time_last, time_now);
  solver->step_time_last = time_now;
  tau = (double) time_delta.rel_value_us
      / (double) solver->parameters.step_time_min.rel_value_us;

  //calculate reward discounts (once per step for all agents)
  solver->global_discount_variable = pow (M_E, ((-1.) * ((double) solver->parameters.beta) * tau));
  solver->global_discount_integrated = (1. - solver->global_discount_variable)
      / (double) solver->parameters.beta;
}

static void
ril_calculate_assigned_bwnet (struct GAS_RIL_Handle *solver)
{
  int c;
  struct RIL_Network *net;

  for (c = 0; c < solver->networks_count; c++)
  {
    net = &solver->network_entries[c];
    net->bw_in_assigned = ril_network_get_assigned(solver, net->type, GNUNET_YES);
    net->bw_out_assigned = ril_network_get_assigned(solver, net->type, GNUNET_NO);
  }
}

/**
 * Schedules the next global step in an adaptive way. The more resources are
 * left, the earlier the next step is scheduled. This serves the reactivity of
 * the solver to changed inputs.
 *
 * @param solver the solver handle
 */
static void
ril_step_schedule_next (struct GAS_RIL_Handle *solver)
{
  double used_ratio;
  double factor;
  double y;
  double offset;
  struct GNUNET_TIME_Relative time_next;

  used_ratio = ril_get_used_resource_ratio (solver);

  GNUNET_assert(
      solver->parameters.step_time_min.rel_value_us
          <= solver->parameters.step_time_max.rel_value_us);

  factor = (double) GNUNET_TIME_relative_subtract (solver->parameters.step_time_max,
      solver->parameters.step_time_min).rel_value_us;
  offset = (double) solver->parameters.step_time_min.rel_value_us;
  y = factor * pow (used_ratio, RIL_INTERVAL_EXPONENT) + offset;

  GNUNET_assert(y <= (double ) solver->parameters.step_time_max.rel_value_us);
  GNUNET_assert(y >= (double ) solver->parameters.step_time_min.rel_value_us);

  time_next = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MICROSECONDS, (unsigned long long) y);

  if (solver->simulate)
  {
    time_next = GNUNET_TIME_UNIT_ZERO;
  }

  if ((GNUNET_SCHEDULER_NO_TASK == solver->step_next_task_id) && (GNUNET_NO == solver->done))
  {
    solver->step_next_task_id = GNUNET_SCHEDULER_add_delayed (time_next, &ril_step_scheduler_task,
          solver);
  }
}

/**
 * Triggers one step per agent
 * @param solver
 */
static void
ril_step (struct GAS_RIL_Handle *solver)
{
  struct RIL_Peer_Agent *cur;

  if (GNUNET_YES == solver->bulk_lock)
  {
    solver->bulk_changes++;
    return;
  }

  ril_inform (solver, GAS_OP_SOLVE_START, GAS_STAT_SUCCESS);

  LOG(GNUNET_ERROR_TYPE_DEBUG, "    RIL step number %d\n", solver->step_count);

  if (0 == solver->step_count)
  {
    solver->step_time_last = GNUNET_TIME_absolute_get ();
  }

  ril_calculate_discount (solver);
  ril_calculate_assigned_bwnet (solver);

  //calculate network state vector
//  envi_state_networks(solver);

  //trigger one step per active, unblocked agent
  for (cur = solver->agents_head; NULL != cur; cur = cur->next)
  {
    if (cur->is_active)
    {
      if (NULL == cur->address_inuse)
      {
        ril_try_unblock_agent(solver, cur, GNUNET_NO);
      }
      if (cur->address_inuse)
      {
        agent_step (cur);
      }
    }
  }

  ril_calculate_assigned_bwnet (solver);

  solver->step_count += 1;
  ril_step_schedule_next (solver);

  ril_inform (solver, GAS_OP_SOLVE_STOP, GAS_STAT_SUCCESS);

  ril_inform (solver, GAS_OP_SOLVE_UPDATE_NOTIFICATION_START, GAS_STAT_SUCCESS);
  for (cur = solver->agents_head; NULL != cur; cur = cur->next)
  {
    if (cur->suggestion_issue) {
      solver->plugin_envi->bandwidth_changed_cb(solver->plugin_envi->bw_changed_cb_cls, cur->suggestion_address);
      cur->suggestion_issue = GNUNET_NO;
    }
  }
  ril_inform (solver, GAS_OP_SOLVE_UPDATE_NOTIFICATION_STOP, GAS_STAT_SUCCESS);
}

static int
ril_count_agents (struct GAS_RIL_Handle *solver)
{
  int c = 0;
  struct RIL_Peer_Agent *cur_agent;

  for (cur_agent = solver->agents_head; NULL != cur_agent; cur_agent = cur_agent->next)
  {
    c++;
  }
  return c;
}

static void
agent_w_start (struct RIL_Peer_Agent *agent)
{
  int count;
  struct RIL_Peer_Agent *other;
  int i;
  int k;

  count = ril_count_agents(agent->envi);

  for (i = 0; i < agent->n; i++)
  {
    for (k = 0; k < agent->m; k++)
    {
      if (0 == count) {
        agent->W[i][k] = 1;//.1 - ((double) GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, UINT32_MAX/5)/(double)UINT32_MAX);
      }
      else {
        for (other = agent->envi->agents_head; NULL != other; other = other->next)
        {
          agent->W[i][k] += (other->W[i][k] / (double) count);
        }
      }

      GNUNET_assert(!isinf(agent->W[i][k]));
    }
  }
}

/**
 * Initialize an agent without addresses and its knowledge base
 *
 * @param s ril solver
 * @param peer the one in question
 * @return handle to the new agent
 */
static struct RIL_Peer_Agent *
agent_init (void *s, const struct GNUNET_PeerIdentity *peer)
{
  int i;
  struct GAS_RIL_Handle * solver = s;
  struct RIL_Peer_Agent * agent = GNUNET_malloc (sizeof (struct RIL_Peer_Agent));

  agent->envi = solver;
  agent->peer = *peer;
  agent->step_count = 0;
  agent->is_active = GNUNET_NO;
  agent->bw_in = MIN_BW;
  agent->bw_out = MIN_BW;
  agent->suggestion_issue = GNUNET_NO;
  agent->n = RIL_ACTION_TYPE_NUM;
  agent->m = (RIL_FEATURES_NETWORK_COUNT);// + GNUNET_ATS_PreferenceCount;
  agent->W = (double **) GNUNET_malloc (sizeof (double *) * agent->n);
  for (i = 0; i < agent->n; i++)
  {
    agent->W[i] = (double *) GNUNET_malloc (sizeof (double) * agent->m);
  }
  agent_w_start(agent);
  agent->a_old = RIL_ACTION_INVALID;
  agent->s_old = GNUNET_malloc (sizeof (double) * agent->m);
  agent->e = (double *) GNUNET_malloc (sizeof (double) * agent->m);
  agent_modify_eligibility (agent, RIL_E_ZERO, NULL);

  return agent;
}

/**
 * Deallocate agent
 *
 * @param solver the solver handle
 * @param agent the agent to retire
 */
static void
agent_die (struct GAS_RIL_Handle *solver, struct RIL_Peer_Agent *agent)
{
  int i;

  for (i = 0; i < agent->n; i++)
  {
    GNUNET_free(agent->W[i]);
  }
  GNUNET_free(agent->W);
  GNUNET_free(agent->e);
  GNUNET_free(agent->s_old);
  GNUNET_free(agent);
}

/**
 * Returns the agent for a peer
 *
 * @param solver the solver handle
 * @param peer the identity of the peer
 * @param create whether or not to create an agent, if none is allocated yet
 * @return the agent
 */
static struct RIL_Peer_Agent *
ril_get_agent (struct GAS_RIL_Handle *solver, const struct GNUNET_PeerIdentity *peer, int create)
{
  struct RIL_Peer_Agent *cur;

  for (cur = solver->agents_head; NULL != cur; cur = cur->next)
  {
    if (0 == memcmp (peer, &cur->peer, sizeof(struct GNUNET_PeerIdentity)))
    {
      return cur;
    }
  }

  if (create)
  {
    cur = agent_init (solver, peer);
    GNUNET_CONTAINER_DLL_insert_tail(solver->agents_head, solver->agents_tail, cur);
    return cur;
  }
  return NULL ;
}

/**
 * Determine whether at least the minimum bandwidth is set for the network. Otherwise the network is
 * considered inactive and not used. Addresses in an inactive network are ignored.
 *
 * @param solver solver handle
 * @param network the network type
 * @return whether or not the network is considered active
 */
static int
ril_network_is_active (struct GAS_RIL_Handle *solver, enum GNUNET_ATS_Network_Type network)
{
  struct RIL_Network *net;

  net = ril_get_network (solver, network);
  return net->bw_out_available >= MIN_BW;
}

/**
 * Cuts a slice out of a vector of elements. This is used to decrease the size of the matrix storing
 * the reward function approximation. It copies the memory, which is not cut, to the new vector,
 * frees the memory of the old vector, and redirects the pointer to the new one.
 *
 * @param old pointer to the pointer to the first element of the vector
 * @param element_size byte size of the vector elements
 * @param hole_start the first element to cut out
 * @param hole_length the number of elements to cut out
 * @param old_length the length of the old vector
 */
static void
ril_cut_from_vector (void **old,
    size_t element_size,
    unsigned int hole_start,
    unsigned int hole_length,
    unsigned int old_length)
{
  char *tmpptr;
  char *oldptr = (char *) *old;
  size_t size;
  unsigned int bytes_before;
  unsigned int bytes_hole;
  unsigned int bytes_after;

  GNUNET_assert(old_length > hole_length);
  GNUNET_assert(old_length >= (hole_start + hole_length));

  size = element_size * (old_length - hole_length);

  bytes_before = element_size * hole_start;
  bytes_hole = element_size * hole_length;
  bytes_after = element_size * (old_length - hole_start - hole_length);

  if (0 == size)
  {
    tmpptr = NULL;
  }
  else
  {
    tmpptr = GNUNET_malloc (size);
    memcpy (tmpptr, oldptr, bytes_before);
    memcpy (tmpptr + bytes_before, oldptr + (bytes_before + bytes_hole), bytes_after);
  }
  if (NULL != *old)
  {
    GNUNET_free(*old);
  }
  *old = (void *) tmpptr;
}

/*
 *  Solver API functions
 *  ---------------------------
 */

/**
 * Change relative preference for quality in solver
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
  LOG(GNUNET_ERROR_TYPE_DEBUG,
      "API_address_change_preference() Preference '%s' for peer '%s' changed to %.2f \n",
      GNUNET_ATS_print_preference_type (kind), GNUNET_i2s (peer), pref_rel);

  ril_step (solver);
}

/**
 * Entry point for the plugin
 *
 * @param cls pointer to the 'struct GNUNET_ATS_PluginEnvironment'
 */
void *
libgnunet_plugin_ats_ril_init (void *cls)
{
  struct GNUNET_ATS_PluginEnvironment *env = cls;
  struct GAS_RIL_Handle *solver = GNUNET_new (struct GAS_RIL_Handle);
  struct RIL_Network * cur;
  int c;
  char *string;

  LOG(GNUNET_ERROR_TYPE_DEBUG, "API_init() Initializing RIL solver\n");

  GNUNET_assert(NULL != env);
  GNUNET_assert(NULL != env->cfg);
  GNUNET_assert(NULL != env->stats);
  GNUNET_assert(NULL != env->bandwidth_changed_cb);
  GNUNET_assert(NULL != env->get_preferences);
  GNUNET_assert(NULL != env->get_property);

  if (GNUNET_OK
      != GNUNET_CONFIGURATION_get_value_time (env->cfg, "ats", "RIL_STEP_TIME_MIN",
          &solver->parameters.step_time_min))
  {
    solver->parameters.step_time_min = RIL_DEFAULT_STEP_TIME_MIN;
  }
  if (GNUNET_OK
      != GNUNET_CONFIGURATION_get_value_time (env->cfg, "ats", "RIL_STEP_TIME_MAX",
          &solver->parameters.step_time_max))
  {
    solver->parameters.step_time_max = RIL_DEFAULT_STEP_TIME_MAX;
  }
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string (env->cfg, "ats", "RIL_ALGORITHM", &string))
  {
    solver->parameters.algorithm = !strcmp (string, "SARSA") ? RIL_ALGO_SARSA : RIL_ALGO_Q;
    GNUNET_free (string);
  }
  else
  {
    solver->parameters.algorithm = RIL_DEFAULT_ALGORITHM;
  }
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string (env->cfg, "ats", "RIL_DISCOUNT_BETA", &string))
  {
    solver->parameters.beta = strtod (string, NULL);
    GNUNET_free (string);
  }
  else
  {
    solver->parameters.beta = RIL_DEFAULT_DISCOUNT_BETA;
  }
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string (env->cfg, "ats", "RIL_DISCOUNT_GAMMA", &string))
  {
    solver->parameters.gamma = strtod (string, NULL);
    GNUNET_free (string);
  }
  else
  {
    solver->parameters.gamma = RIL_DEFAULT_DISCOUNT_GAMMA;
  }
  if (GNUNET_OK
      == GNUNET_CONFIGURATION_get_value_string (env->cfg, "ats", "RIL_GRADIENT_STEP_SIZE", &string))
  {
    solver->parameters.alpha = strtod (string, NULL);
    GNUNET_free (string);
  }
  else
  {
    solver->parameters.alpha = RIL_DEFAULT_GRADIENT_STEP_SIZE;
  }
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string (env->cfg, "ats", "RIL_TRACE_DECAY", &string))
  {
    solver->parameters.lambda = strtod (string, NULL);
    GNUNET_free (string);
  }
  else
  {
    solver->parameters.lambda = RIL_DEFAULT_TRACE_DECAY;
  }
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string (env->cfg, "ats", "RIL_EXPLORE_RATIO", &string))
  {
    solver->parameters.explore_ratio = strtod (string, NULL);
    GNUNET_free (string);
  }
  else
  {
    solver->parameters.explore_ratio = RIL_DEFAULT_EXPLORE_RATIO;
  }
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string (env->cfg, "ats", "RIL_GLOBAL_REWARD_SHARE", &string))
  {
    solver->parameters.reward_global_share = strtod (string, NULL);
    GNUNET_free (string);
  }
  else
  {
    solver->parameters.reward_global_share = RIL_DEFAULT_GLOBAL_REWARD_SHARE;
  }
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (env->cfg, "ats", "RIL_SIMULATE", &solver->simulate))
  {
    solver->simulate = GNUNET_NO;
  }

  env->sf.s_add = &GAS_ril_address_add;
  env->sf.s_address_update_property = &GAS_ril_address_property_changed;
  env->sf.s_address_update_session = &GAS_ril_address_session_changed;
  env->sf.s_address_update_inuse = &GAS_ril_address_inuse_changed;
  env->sf.s_address_update_network = &GAS_ril_address_change_network;
  env->sf.s_get = &GAS_ril_get_preferred_address;
  env->sf.s_get_stop = &GAS_ril_stop_get_preferred_address;
  env->sf.s_pref = &GAS_ril_address_change_preference;
  env->sf.s_feedback = &GAS_ril_address_preference_feedback;
  env->sf.s_del = &GAS_ril_address_delete;
  env->sf.s_bulk_start = &GAS_ril_bulk_start;
  env->sf.s_bulk_stop = &GAS_ril_bulk_stop;

  solver->plugin_envi = env;
  solver->networks_count = env->network_count;
  solver->network_entries = GNUNET_malloc (env->network_count * sizeof (struct RIL_Network));
  solver->step_count = 0;
  solver->global_state_networks = GNUNET_malloc (solver->networks_count * RIL_FEATURES_NETWORK_COUNT * sizeof (double));
  solver->done = GNUNET_NO;

  for (c = 0; c < env->network_count; c++)
  {
    cur = &solver->network_entries[c];
    cur->type = env->networks[c];
    cur->bw_in_available = env->in_quota[c];
    cur->bw_out_available = env->out_quota[c];
    LOG(GNUNET_ERROR_TYPE_INFO, "init()  Quotas for %s network:  IN %llu - OUT %llu\n", GNUNET_ATS_print_network_type(cur->type), cur->bw_in_available/1024, cur->bw_out_available/1024);
  }

  LOG(GNUNET_ERROR_TYPE_INFO, "init()  Parameters:\n");
  LOG(GNUNET_ERROR_TYPE_INFO, "init()  Algorithm = %s, alpha = %f, beta = %f, lambda = %f\n",
      solver->parameters.algorithm ? "Q" : "SARSA",
      solver->parameters.alpha,
      solver->parameters.beta,
      solver->parameters.lambda);
  LOG(GNUNET_ERROR_TYPE_INFO, "init()  explore = %f, global_share = %f\n",
      solver->parameters.explore_ratio,
      solver->parameters.reward_global_share);

  return solver;
}

/**
 * Exit point for the plugin
 *
 * @param cls the solver handle
 */
void *
libgnunet_plugin_ats_ril_done (void *cls)
{
  struct GAS_RIL_Handle *s = cls;
  struct RIL_Peer_Agent *cur_agent;
  struct RIL_Peer_Agent *next_agent;

  LOG(GNUNET_ERROR_TYPE_DEBUG, "API_done() Shutting down RIL solver\n");

  s->done = GNUNET_YES;

  cur_agent = s->agents_head;
  while (NULL != cur_agent)
  {
    next_agent = cur_agent->next;
    GNUNET_CONTAINER_DLL_remove(s->agents_head, s->agents_tail, cur_agent);
    agent_die (s, cur_agent);
    cur_agent = next_agent;
  }

  if (GNUNET_SCHEDULER_NO_TASK != s->step_next_task_id)
  {
    GNUNET_SCHEDULER_cancel (s->step_next_task_id);
  }
  GNUNET_free(s->network_entries);
  GNUNET_free(s->global_state_networks);
  GNUNET_free(s);

  return NULL;
}

/**
 * Add a new address for a peer to the solver
 *
 * The address is already contained in the addresses hashmap!
 *
 * @param solver the solver Handle
 * @param address the address to add
 * @param network network type of this address
 */
void
GAS_ril_address_add (void *solver, struct ATS_Address *address, uint32_t network)
{
  struct GAS_RIL_Handle *s = solver;
  struct RIL_Peer_Agent *agent;
  struct RIL_Address_Wrapped *address_wrapped;
  struct RIL_Network *net;
  unsigned int m_new;
  unsigned int m_old;
  unsigned int n_new;
  unsigned int n_old;
  int i;
  unsigned int zero;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "API_address_add()\n");

  net = ril_get_network (s, network);
  address->solver_information = net;

  if (!ril_network_is_active (s, network))
  {
    LOG(GNUNET_ERROR_TYPE_DEBUG,
        "API_address_add() Did not add %s address %s for peer '%s', network does not have enough bandwidth\n",
        address->plugin, address->addr, GNUNET_i2s (&address->peer));
    return;
  }

  agent = ril_get_agent (s, &address->peer, GNUNET_YES);

  //add address
  address_wrapped = GNUNET_malloc (sizeof (struct RIL_Address_Wrapped));
  address_wrapped->address_naked = address;
  GNUNET_CONTAINER_DLL_insert_tail(agent->addresses_head, agent->addresses_tail, address_wrapped);

  //increase size of W
  m_new = agent->m + RIL_FEATURES_ADDRESS_COUNT;
  m_old = agent->m;
  n_new = agent->n + 1;
  n_old = agent->n;

  GNUNET_array_grow(agent->W, agent->n, n_new);
  for (i = 0; i < n_new; i++)
  {
    if (i < n_old)
    {
      agent->m = m_old;
      GNUNET_array_grow(agent->W[i], agent->m, m_new);
    }
    else
    {
      zero = 0;
      GNUNET_array_grow(agent->W[i], zero, m_new);
    }
  }

  //increase size of old state vector
  agent->m = m_old;
  GNUNET_array_grow(agent->s_old, agent->m, m_new);

  agent->m = m_old;
  GNUNET_array_grow(agent->e, agent->m, m_new);

  ril_try_unblock_agent(s, agent, GNUNET_NO);

  ril_step (s);

  LOG(GNUNET_ERROR_TYPE_DEBUG, "API_address_add() Added %s %s address %s for peer '%s'\n",
      address->active ? "active" : "inactive", address->plugin, address->addr,
      GNUNET_i2s (&address->peer));
}

/**
 * Delete an address in the solver
 *
 * The address is not contained in the address hashmap anymore!
 *
 * @param solver the solver handle
 * @param address the address to remove
 * @param session_only delete only session not whole address
 */
void
GAS_ril_address_delete (void *solver, struct ATS_Address *address, int session_only)
{
  struct GAS_RIL_Handle *s = solver;
  struct RIL_Peer_Agent *agent;
  struct RIL_Address_Wrapped *address_wrapped;
  int address_was_used = address->active;
  int address_index;
  unsigned int m_new;
  unsigned int n_new;
  int i;
  struct RIL_Network *net;

  LOG(GNUNET_ERROR_TYPE_DEBUG, "API_address_delete() Delete %s%s %s address %s for peer '%s'\n",
      session_only ? "session for " : "", address->active ? "active" : "inactive", address->plugin,
      address->addr, GNUNET_i2s (&address->peer));

  agent = ril_get_agent (s, &address->peer, GNUNET_NO);
  if (NULL == agent)
  {
    net = address->solver_information;
    GNUNET_assert(!ril_network_is_active (s, net->type));
    LOG(GNUNET_ERROR_TYPE_DEBUG,
        "No agent allocated for peer yet, since address was in inactive network\n");
    return;
  }

  address_index = agent_address_get_index (agent, address);
  address_wrapped = agent_address_get (agent, address);

  if (NULL == address_wrapped)
  {
    net = address->solver_information;
    GNUNET_assert(!ril_network_is_active (s, net->type));
    LOG(GNUNET_ERROR_TYPE_DEBUG,
        "Address not considered by agent, address was in inactive network\n");
    return;
  }

  GNUNET_CONTAINER_DLL_remove(agent->addresses_head, agent->addresses_tail, address_wrapped);
  GNUNET_free(address_wrapped);

  //decrease W
  m_new = agent->m - RIL_FEATURES_ADDRESS_COUNT;
  n_new = agent->n - 1;

  LOG(GNUNET_ERROR_TYPE_DEBUG, "first\n");

  for (i = 0; i < agent->n; i++)
  {
    ril_cut_from_vector ((void **) &agent->W[i], sizeof(double),
        //((s->networks_count * RIL_FEATURES_NETWORK_COUNT)
        ((RIL_FEATURES_NETWORK_COUNT) //TODO! replace, when adding more networks
            + (address_index * RIL_FEATURES_ADDRESS_COUNT)), RIL_FEATURES_ADDRESS_COUNT, agent->m);
  }
  GNUNET_free(agent->W[RIL_ACTION_TYPE_NUM + address_index]);
  LOG(GNUNET_ERROR_TYPE_DEBUG, "second\n");
  ril_cut_from_vector ((void **) &agent->W, sizeof(double *), RIL_ACTION_TYPE_NUM + address_index,
      1, agent->n);
  //correct last action
  if (agent->a_old > (RIL_ACTION_TYPE_NUM + address_index))
  {
    agent->a_old -= 1;
  }
  else if (agent->a_old == (RIL_ACTION_TYPE_NUM + address_index))
  {
    agent->a_old = RIL_ACTION_INVALID;
  }
  //decrease old state vector and eligibility vector
  LOG(GNUNET_ERROR_TYPE_DEBUG, "third\n");
  ril_cut_from_vector ((void **) &agent->s_old, sizeof(double),
      //((s->networks_count * RIL_FEATURES_NETWORK_COUNT)
      ((RIL_FEATURES_NETWORK_COUNT) //TODO! replace when adding more networks
          + (address_index * RIL_FEATURES_ADDRESS_COUNT)), RIL_FEATURES_ADDRESS_COUNT, agent->m);
  ril_cut_from_vector ((void **) &agent->e, sizeof(double),
      //((s->networks_count * RIL_FEATURES_NETWORK_COUNT)
      ((RIL_FEATURES_NETWORK_COUNT) //TODO! replace when adding more networks
          + (address_index * RIL_FEATURES_ADDRESS_COUNT)), RIL_FEATURES_ADDRESS_COUNT, agent->m);
  agent->m = m_new;
  agent->n = n_new;

  if (address_was_used)
  {
    if (NULL != agent->addresses_head) //if peer has an address left, use it
    {
      envi_set_active_suggestion (s, agent, agent->addresses_head->address_naked, MIN_BW, MIN_BW,
          GNUNET_NO);
    }
    else
    {
      envi_set_active_suggestion (s, agent, NULL, 0, 0, GNUNET_NO);
    }
  }

  ril_step (solver);
}

/**
 * Update the properties of an address in the solver
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
  LOG(GNUNET_ERROR_TYPE_DEBUG,
      "API_address_property_changed() Property '%s' for peer '%s' address %s changed "
          "to %.2f \n", GNUNET_ATS_print_property_type (type), GNUNET_i2s (&address->peer),
      address->addr, rel_value);

  ril_step (solver);
}

/**
 * Update the session of an address in the solver
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
  /*
   * TODO? Future Work: Potentially add session activity as a feature in state vector
   */
  LOG(GNUNET_ERROR_TYPE_DEBUG, "API_address_session_changed()\n");
}

/**
 * Notify the solver that an address is (not) actively used by transport
 * to communicate with a remote peer
 *
 * NOTE: values in addresses are already updated
 *
 * @param solver solver handle
 * @param address the address
 * @param in_use usage state
 */
void
GAS_ril_address_inuse_changed (void *solver, struct ATS_Address *address, int in_use)
{
  /*
   * TODO? Future Work: Potentially add usage variable to state vector
   */
  LOG(GNUNET_ERROR_TYPE_DEBUG,
      "API_address_inuse_changed() Usage for %s address of peer '%s' changed to %s\n",
      address->plugin, GNUNET_i2s (&address->peer), (GNUNET_YES == in_use) ? "USED" : "UNUSED");
}

/**
 * Notify solver that the network an address is located in has changed
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

  LOG(GNUNET_ERROR_TYPE_DEBUG, "API_address_change_network() Network type changed, moving "
      "%s address of peer %s from '%s' to '%s'\n",
      (GNUNET_YES == address->active) ? "active" : "inactive", GNUNET_i2s (&address->peer),
      GNUNET_ATS_print_network_type (current_network), GNUNET_ATS_print_network_type (new_network));

  if (address->active && !ril_network_is_active (solver, new_network))
  {
    GAS_ril_address_delete (solver, address, GNUNET_NO);
    return;
  }

  agent = ril_get_agent (s, &address->peer, GNUNET_NO);
  if (NULL == agent)
  {
    GNUNET_assert(!ril_network_is_active (solver, current_network));

    GAS_ril_address_add (s, address, new_network);
    return;
  }

  address->solver_information = ril_get_network(solver, new_network);
}

/**
 * Give feedback about the current assignment
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
  LOG(GNUNET_ERROR_TYPE_DEBUG,
      "API_address_preference_feedback() Peer '%s' got a feedback of %+.3f from application %s for "
          "preference %s for %d seconds\n", GNUNET_i2s (peer), "UNKNOWN",
      GNUNET_ATS_print_preference_type (kind), scope.rel_value_us / 1000000);
}

/**
 * Start a bulk operation
 *
 * @param solver the solver
 */
void
GAS_ril_bulk_start (void *solver)
{
  struct GAS_RIL_Handle *s = solver;

  LOG(GNUNET_ERROR_TYPE_DEBUG, "API_bulk_start() lock: %d\n", s->bulk_lock+1);

  s->bulk_lock++;
}

/**
 * Bulk operation done
 *
 * @param solver the solver handle
 */
void
GAS_ril_bulk_stop (void *solver)
{
  struct GAS_RIL_Handle *s = solver;

  LOG(GNUNET_ERROR_TYPE_DEBUG, "API_bulk_stop() lock: %d\n", s->bulk_lock-1);

  if (s->bulk_lock < 1)
  {
    GNUNET_break(0);
    return;
  }
  s->bulk_lock--;

  if (0 < s->bulk_changes)
  {
    ril_step (solver);
    s->bulk_changes = 0;
  }
}

/**
 * Tell solver to notify ATS if the address to use changes for a specific
 * peer using the bandwidth changed callback
 *
 * The solver must only notify about changes for peers with pending address
 * requests!
 *
 * @param solver the solver handle
 * @param peer the identity of the peer
 */
const struct ATS_Address *
GAS_ril_get_preferred_address (void *solver, const struct GNUNET_PeerIdentity *peer)
{
  /*
   * activate agent, return currently chosen address
   */
  struct GAS_RIL_Handle *s = solver;
  struct RIL_Peer_Agent *agent;

  LOG(GNUNET_ERROR_TYPE_DEBUG, "API_get_preferred_address()\n");

  agent = ril_get_agent (s, peer, GNUNET_YES);

  agent->is_active = GNUNET_YES;
  envi_set_active_suggestion (solver, agent, agent->address_inuse, agent->bw_in, agent->bw_out, GNUNET_YES);

  ril_try_unblock_agent(solver, agent, GNUNET_YES);

  if (agent->address_inuse)
  {
    LOG(GNUNET_ERROR_TYPE_DEBUG,
        "API_get_preferred_address() Activated agent for peer '%s' with %s address %s\n",
        GNUNET_i2s (peer), agent->address_inuse->plugin, agent->address_inuse->addr);
  }
  else
  {
    LOG(GNUNET_ERROR_TYPE_DEBUG,
        "API_get_preferred_address() Activated agent for peer '%s', but no address available\n",
        GNUNET_i2s (peer));
  }

  return agent->address_inuse;
}

/**
 * Tell solver stop notifying ATS about changes for this peers
 *
 * The solver must only notify about changes for peers with pending address
 * requests!
 *
 * @param solver the solver handle
 * @param peer the peer
 */
void
GAS_ril_stop_get_preferred_address (void *solver, const struct GNUNET_PeerIdentity *peer)
{
  struct GAS_RIL_Handle *s = solver;
  struct RIL_Peer_Agent *agent;

  LOG(GNUNET_ERROR_TYPE_DEBUG, "API_stop_get_preferred_address()");

  agent = ril_get_agent (s, peer, GNUNET_NO);

  if (NULL == agent)
  {
    GNUNET_break(0);
    return;
  }
  if (GNUNET_NO == agent->is_active)
  {
    GNUNET_break(0);
    return;
  }

  agent->is_active = GNUNET_NO;

  envi_set_active_suggestion (s, agent, agent->address_inuse, agent->bw_in, agent->bw_out,
      GNUNET_YES);

  ril_step (s);

  LOG(GNUNET_ERROR_TYPE_DEBUG,
      "API_stop_get_preferred_address() Paused agent for peer '%s' with %s address\n",
      GNUNET_i2s (peer), agent->address_inuse->plugin);
}

/* end of plugin_ats_ril.c */
