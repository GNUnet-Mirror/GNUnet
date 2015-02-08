/*
 This file is part of GNUnet.
 Copyright (C) 2011-2014 Christian Grothoff (and other contributing authors)

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
#include "platform.h"
#include <float.h>
#include <math.h>
#include "gnunet_ats_plugin.h"
#include "gnunet-service-ats_addresses.h"



#define LOG(kind,...) GNUNET_log_from (kind, "ats-ril",__VA_ARGS__)

#define RIL_MIN_BW                      (5 * ntohl (GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT.value__))
#define RIL_MAX_BW                      GNUNET_ATS_MaxBandwidth

#define RIL_ACTION_INVALID              -1
#define RIL_INTERVAL_EXPONENT           10
#define RIL_UTILITY_DELAY_MAX           1000

#define RIL_DEFAULT_STEP_TIME_MIN       GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 200)
#define RIL_DEFAULT_STEP_TIME_MAX       GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 2000)
#define RIL_DEFAULT_ALGORITHM           RIL_ALGO_SARSA
#define RIL_DEFAULT_SELECT              RIL_SELECT_SOFTMAX
#define RIL_DEFAULT_WELFARE             RIL_WELFARE_NASH
#define RIL_DEFAULT_DISCOUNT_BETA       0.6
#define RIL_DEFAULT_DISCOUNT_GAMMA      0.5
#define RIL_DEFAULT_GRADIENT_STEP_SIZE  0.01
#define RIL_DEFAULT_TRACE_DECAY         0.5
#define RIL_DEFAULT_EXPLORE_RATIO       1
#define RIL_DEFAULT_EXPLORE_DECAY       0.95
#define RIL_DEFAULT_RBF_DIVISOR         50
#define RIL_DEFAULT_TEMPERATURE         0.1
#define RIL_DEFAULT_TEMPERATURE_DECAY   1

#define RIL_INC_DEC_STEP_SIZE           1
#define RIL_NOP_DECAY                   0.5

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
  RIL_ACTION_NOTHING = 0,
  RIL_ACTION_BW_IN_DBL = -2, //TODO? Potentially add more actions
  RIL_ACTION_BW_IN_HLV = -3,
  RIL_ACTION_BW_IN_INC = 1,
  RIL_ACTION_BW_IN_DEC = 2,
  RIL_ACTION_BW_OUT_DBL = -4,
  RIL_ACTION_BW_OUT_HLV = -5,
  RIL_ACTION_BW_OUT_INC = 3,
  RIL_ACTION_BW_OUT_DEC = 4,
  RIL_ACTION_TYPE_NUM = 5
};

enum RIL_Algorithm
{
  RIL_ALGO_SARSA = 0,
  RIL_ALGO_Q = 1
};

enum RIL_Select
{
  RIL_SELECT_SOFTMAX = 0,
  RIL_SELECT_EGREEDY = 1
};

enum RIL_Welfare
{
  RIL_WELFARE_NASH,
  RIL_WELFARE_EGALITARIAN
};

enum RIL_E_Modification
{
  RIL_E_DECAY,
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
   * Whether to accumulate or replace eligibility traces
   */
  enum RIL_E_Modification eligibility_trace_mode;

  /**
   * Initial softmax action-selection temperature
   */
  double temperature_init;

  /**
   * Softmax action-selection temperature
   */
  double temperature;

  /**
   * Decay factor of the temperature value
   */
  double temperature_decay;

  /**
   * Which measure of social welfare should be used
   */
  enum RIL_Welfare social_welfare;

  /**
   * State space divisor
   */
  unsigned long long rbf_divisor;

  /**
   * Action selection strategy;
   */
  enum RIL_Select select;

  /**
   * Initial exploration ratio value
   */
  double epsilon_init;

  /**
   * Ratio, with what probability an agent should explore in the e-greed policy
   */
  double epsilon;

  /**
   * Decay factor of the explore ratio
   */
  double epsilon_decay;

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
  double *s_old;

  /**
   * Last chosen action
   */
  int a_old;

  /**
   * Eligibility traces
   */
  double ** E;

  /**
   * Whether to reset the eligibility traces to 0 after a Q-exploration step
   */
  int eligibility_reset;

  /**
   * Address in use
   */
  struct ATS_Address *address_inuse;

  /**
   * Head of addresses DLL
   */
  struct RIL_Address_Wrapped *addresses_head;

  /**
   * Tail of addresses DLL
   */
  struct RIL_Address_Wrapped *addresses_tail;

  /**
   * Inbound bandwidth assigned by the agent
   */
  uint32_t bw_in;

  /**
   * Outbound bandwidth assigned by the agent
   */
  uint32_t bw_out;

  /**
   * Flag whether a suggestion has to be issued
   */
  int suggestion_issue;

  /**
   * The address which has to be issued
   */
  struct ATS_Address *suggestion_address;

  /**
   * The agent's last objective value
   */
  double objective_old;

  /**
   * NOP bonus
   */
  double nop_bonus;
};

struct RIL_Scope
{
  /**
   * ATS network type
   */
  enum GNUNET_ATS_Network_Type type;

  /**
   * Total available inbound bandwidth
   */
  uint32_t bw_in_available;

  /**
   * Bandwidth inbound assigned in network after last step
   */
  uint32_t bw_in_assigned;

  /**
   * Bandwidth inbound actually utilized in the network
   */
  uint32_t bw_in_utilized;

  /**
   * Total available outbound bandwidth
   */
  uint32_t bw_out_available;

  /**
   * Bandwidth outbound assigned in network after last step
   */
  unsigned long long bw_out_assigned;

  /**
   * Bandwidth outbound actually utilized in the network
   */
  unsigned long long bw_out_utilized;

  /**
   * Number of active agents in scope
   */
  unsigned int active_agent_count;

  /**
   * The social welfare achieved in the scope
   */
  double social_welfare;
};

/**
 * A handle for the reinforcement learning solver
 */
struct GAS_RIL_Handle
{
  /**
   * The solver-plugin environment of the solver-plugin API
   */
  struct GNUNET_ATS_PluginEnvironment *env;

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
  struct GNUNET_SCHEDULER_Task * step_next_task_id;

  /**
   * Variable discount factor, dependent on time between steps
   */
  double global_discount_variable;

  /**
   * Integrated variable discount factor, dependent on time between steps
   */
  double global_discount_integrated;

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
  struct RIL_Scope * network_entries;

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
 *  "Private" functions
 *  ---------------------------
 */

/**
 * Estimate the current action-value for state s and action a
 *
 * @param agent agent performing the estimation
 * @param state s
 * @param action a
 * @return estimation value
 */
static double
agent_q (struct RIL_Peer_Agent *agent,
         const double *state,
         int action)
{
  unsigned int i;
  double result = 0.0;

  for (i = 0; i < agent->m; i++)
    result += state[i] * agent->W[action][i];

  /* prevent crashes if learning diverges */
  if (isnan(result))
      return isnan(result) * UINT32_MAX;
  if (isinf(result))
    return isinf(result) * UINT32_MAX;
  return result;
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
agent_address_get_wrapped (struct RIL_Peer_Agent *agent, struct ATS_Address *address)
{
  struct RIL_Address_Wrapped *cur;

  for (cur = agent->addresses_head; NULL != cur; cur = cur->next)
    if (cur->address_naked == address)
      return cur;
  return NULL;
}


static int
agent_action_is_possible (struct RIL_Peer_Agent *agent, int action)
{
  int address_index;

  switch (action)
  {
  case RIL_ACTION_NOTHING:
    return GNUNET_YES;
    break;
  case RIL_ACTION_BW_IN_INC:
  case RIL_ACTION_BW_IN_DBL:
    if (agent->bw_in >= RIL_MAX_BW)
      return GNUNET_NO;
    else
      return GNUNET_YES;
    break;
  case RIL_ACTION_BW_IN_DEC:
  case RIL_ACTION_BW_IN_HLV:
    if (agent->bw_in <= 0)
      return GNUNET_NO;
    else
      return GNUNET_YES;
    break;
  case RIL_ACTION_BW_OUT_INC:
  case RIL_ACTION_BW_OUT_DBL:
    if (agent->bw_out >= RIL_MAX_BW)
      return GNUNET_NO;
    else
      return GNUNET_YES;
    break;
  case RIL_ACTION_BW_OUT_DEC:
  case RIL_ACTION_BW_OUT_HLV:
    if (agent->bw_out <= 0)
      return GNUNET_NO;
    else
      return GNUNET_YES;
    break;
  default:
    if ((action >= RIL_ACTION_TYPE_NUM) && (action < agent->n)) //switch address action
    {
      address_index = action - RIL_ACTION_TYPE_NUM;

      GNUNET_assert(address_index >= 0);
      GNUNET_assert(
          address_index <= agent_address_get_index (agent, agent->addresses_tail->address_naked));

      if ((agent_address_get_index(agent, agent->address_inuse) == address_index) ||
          agent->address_inuse->active)
        return GNUNET_NO;
      else
        return GNUNET_YES;
      break;
    }
    // error - action does not exist
    GNUNET_assert(GNUNET_NO);
  }
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
agent_get_action_max (struct RIL_Peer_Agent *agent, double *state)
{
  int i;
  int max_i = RIL_ACTION_INVALID;
  double cur_q;
  double max_q = -DBL_MAX;

  for (i = 0; i < agent->n; i++)
  {
    if (agent_action_is_possible(agent, i))
    {
      cur_q = agent_q (agent, state, i);
      if (cur_q > max_q)
      {
        max_q = cur_q;
        max_i = i;
      }
    }
  }

  GNUNET_assert(RIL_ACTION_INVALID != max_i);

  return max_i;
}

/**
 * Chooses a random action from the set of possible ones
 *
 * @param agent the agent performing the action
 * @return the action index
 */
static int
agent_get_action_random (struct RIL_Peer_Agent *agent)
{
  int i;
  int is_possible[agent->n];
  int sum = 0;
  int r;

  for (i = 0; i<agent->n; i++)
  {
    if (agent_action_is_possible(agent, i))
    {
      is_possible[i] = GNUNET_YES;
      sum++;
    }
    else
    {
      is_possible[i] = GNUNET_NO;
    }
  }

  r = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, sum);

  sum = -1;
  for (i = 0; i<agent->n; i++)
  {
    if (is_possible[i])
    {
      sum++;
      if (sum == r)
        return i;
    }
  }

  GNUNET_assert(GNUNET_NO);
  return RIL_ACTION_INVALID;
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
agent_update (struct RIL_Peer_Agent *agent, double reward, double *s_next, int a_prime)
{
  int i;
  int k;
  double delta;
  double **theta = agent->W;

  delta = agent->envi->global_discount_integrated * reward; //reward
  delta += agent->envi->global_discount_variable * agent_q (agent, s_next, a_prime); //discounted future value
  delta -= agent_q (agent, agent->s_old, agent->a_old); //one step

//  LOG(GNUNET_ERROR_TYPE_INFO, "update()   Step# %llu  Q(s,a): %f  a: %f  r: %f  y: %f  Q(s+1,a+1) = %f  delta: %f\n",
//      agent->step_count,
//      agent_q (agent, agent->s_old, agent->a_old),
//      agent->envi->parameters.alpha,
//      reward,
//      agent->envi->global_discount_variable,
//      agent_q (agent, s_next, a_prime),
//      delta);

  for (k = 0; k < agent->n; k++)
  {
    for (i = 0; i < agent->m; i++)
    {
  //    LOG(GNUNET_ERROR_TYPE_INFO, "alpha = %f   delta = %f   e[%d] = %f\n",
  //        agent->envi->parameters.alpha,
  //        delta,
  //        i,
  //        agent->e[i]);
      theta[k][i] += agent->envi->parameters.alpha * delta * agent->E[k][i];
    }
  }
}


/**
 * Changes the eligibility trace vector e in various manners:
 * #RIL_E_ACCUMULATE - adds @a feature to each component as in accumulating eligibility traces
 * #RIL_E_REPLACE - resets each component to @a feature  as in replacing traces
 * #RIL_E_DECAY - multiplies e with discount factor and lambda as in the update rule
 * #RIL_E_ZERO - sets e to 0 as in Watkin's Q-learning algorithm when exploring and when initializing
 *
 * @param agent the agent handle
 * @param mod the kind of modification
 * @param feature the feature vector
 * @param action the action to take
 */
static void
agent_modify_eligibility (struct RIL_Peer_Agent *agent,
                          enum RIL_E_Modification mod,
                          double *feature,
                          int action)
{
  int i;
  int k;

  for (i = 0; i < agent->m; i++)
  {
    switch (mod)
    {
    case RIL_E_ACCUMULATE:
      agent->E[action][i] += feature[i];
      break;
    case RIL_E_REPLACE:
      agent->E[action][i] = agent->E[action][i] > feature[i] ? agent->E[action][i] : feature[i];
      break;
    case RIL_E_DECAY:
      for (k = 0; k < agent->n; k++)
      {
        agent->E[k][i] *= agent->envi->global_discount_variable * agent->envi->parameters.lambda;
      }
      break;
    case RIL_E_ZERO:
      for (k = 0; k < agent->n; k++)
      {
        agent->E[k][i] = 0;
      }
      break;
    }
  }
}

/**
 * Informs the environment about the status of the solver
 *
 * @param solver
 * @param op
 * @param stat
 */
static void
ril_inform (struct GAS_RIL_Handle *solver,
            enum GAS_Solver_Operation op,
            enum GAS_Solver_Status stat)
{
  solver->env->info_cb (solver->env->cls,
                        op,
                        stat,
                        GAS_INFO_NONE);
}

/**
 * Calculates the maximum bandwidth an agent can assign in a network scope
 *
 * @param net
 */
static unsigned long long
ril_get_max_bw (struct RIL_Scope *net)
{
  return GNUNET_MIN(2 * GNUNET_MAX(net->bw_in_available, net->bw_out_available), GNUNET_ATS_MaxBandwidth);
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
 * @param silent disables invocation of the bw_changed callback, if #GNUNET_YES
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

  LOG(GNUNET_ERROR_TYPE_DEBUG,
      "    set_active_suggestion() for peer '%s'\n",
      GNUNET_i2s (&agent->peer));

  //address change
  if (agent->address_inuse != new_address)
  {
    if (NULL != agent->address_inuse)
    {
      agent->address_inuse->active = GNUNET_NO;
      agent->address_inuse->assigned_bw_in = 0;
      agent->address_inuse->assigned_bw_out = 0;
    }
    if (NULL != new_address)
    {
      LOG(GNUNET_ERROR_TYPE_DEBUG, "    set address active: %s\n", agent->is_active ? "yes" : "no");
      new_address->active = agent->is_active;
      new_address->assigned_bw_in = agent->bw_in;
      new_address->assigned_bw_out = agent->bw_out;
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
      new_address->assigned_bw_in = new_bw_in;
      notify |= GNUNET_YES;
    }
    if (agent->bw_out != new_bw_out)
    {
      agent->bw_out = new_bw_out;
      new_address->assigned_bw_out = new_bw_out;
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
      /* disconnect case, no new address */
      GNUNET_assert(0 ==  agent->address_inuse->assigned_bw_in);
      GNUNET_assert(0 == agent->address_inuse->assigned_bw_out);
      agent->bw_in = 0;
      agent->bw_out = 0;

      agent->suggestion_issue = GNUNET_YES;
      agent->suggestion_address = agent->address_inuse;
    }
  }
  agent->address_inuse = new_address;
}


/**
 * Allocates a state vector and fills it with the features present
 * @param solver the solver handle
 * @param agent the agent handle
 * @return pointer to the state vector
 */
static double *
envi_get_state (struct GAS_RIL_Handle *solver, struct RIL_Peer_Agent *agent)
{
  double *state;
  double y[2];
  double x[2];
  double d[2];
  double sigma;
  double f;
  int m;
  int i;
  int k;
  unsigned long long max_bw;

  state = GNUNET_malloc (sizeof(double) * agent->m);

  max_bw = ril_get_max_bw((struct RIL_Scope *) agent->address_inuse->solver_information);

  y[0] = (double) agent->bw_out;
  y[1] = (double) agent->bw_in;

  m = agent_address_get_index (agent, agent->address_inuse) * (solver->parameters.rbf_divisor+1) * (solver->parameters.rbf_divisor+1);
  for (i = 0; i <= solver->parameters.rbf_divisor; i++)
  {
    for (k = 0; k <= solver->parameters.rbf_divisor; k++)
    {
      x[0] = (double) i * (double) max_bw / (double) solver->parameters.rbf_divisor;
      x[1] = (double) k * (double) max_bw / (double) solver->parameters.rbf_divisor;
      d[0] = x[0]-y[0];
      d[1] = x[1]-y[1];
      sigma = (((double) max_bw / ((double) solver->parameters.rbf_divisor + 1)) * 0.5);
      f = exp(-((d[0]*d[0] + d[1]*d[1]) / (2 * sigma * sigma)));
      state[m++] = f;
    }
  }

  return state;
}

/**
 * Retrieves an ATS information value of an address
 *
 * @param address the address in question
 * @param type the ATS information type
 * @return the value
 */
static unsigned int
ril_get_atsi (struct ATS_Address *address, uint32_t type)
{
  int c1;
  GNUNET_assert(NULL != address);

  if ((NULL == address->atsi) || (0 == address->atsi_count))
    return GNUNET_ATS_QUALITY_NET_DELAY == type ? UINT32_MAX : 1;

  for (c1 = 0; c1 < address->atsi_count; c1++)
  {
    if (ntohl (address->atsi[c1].type) == type)
      return ntohl (address->atsi[c1].value);
  }
  return GNUNET_ATS_QUALITY_NET_DELAY == type ? UINT32_MAX : 1;
}

/**
 * Returns the utility value of the connection an agent manages
 *
 * @param agent the agent in question
 * @return the utility value
 */
static double
agent_get_utility (struct RIL_Peer_Agent *agent)
{
  const double *preferences;
  double delay_atsi;
  double delay_norm;
  double pref_match;

  preferences = agent->envi->env->get_preferences (agent->envi->env->cls,
                                                   &agent->peer);

  delay_atsi = (double) ril_get_atsi (agent->address_inuse, GNUNET_ATS_QUALITY_NET_DELAY);
  delay_norm = RIL_UTILITY_DELAY_MAX*exp(-delay_atsi*0.00001);

  pref_match = preferences[GNUNET_ATS_PREFERENCE_LATENCY] * delay_norm;
  pref_match += preferences[GNUNET_ATS_PREFERENCE_BANDWIDTH] *
      sqrt((double) (agent->bw_in/RIL_MIN_BW) * (double) (agent->bw_out/RIL_MIN_BW));
//      sqrt((double) (ril_get_atsi (agent->address_inuse, GNUNET_ATS_UTILIZATION_IN)/RIL_MIN_BW) * (double) (ril_get_atsi (agent->address_inuse, GNUNET_ATS_UTILIZATION_OUT)/RIL_MIN_BW));

//  return (double) (agent->bw_in/RIL_MIN_BW);
//  return sqrt((double) (agent->bw_in/RIL_MIN_BW) * (double) (agent->bw_out/RIL_MIN_BW));
  return pref_match;
}

/**
 * Calculates the social welfare within a network scope according to what social
 * welfare measure is set in the configuration.
 *
 * @param solver the solver handle
 * @param scope the network scope in question
 * @return the social welfare value
 */
static double
ril_network_get_social_welfare (struct GAS_RIL_Handle *solver, struct RIL_Scope *scope)
{
  struct RIL_Peer_Agent *cur;
  double result;

  switch (solver->parameters.social_welfare)
  {
  case RIL_WELFARE_EGALITARIAN:
    result = DBL_MAX;
    for (cur = solver->agents_head; NULL != cur; cur = cur->next)
    {
      if (cur->is_active && cur->address_inuse && (cur->address_inuse->solver_information == scope))
      {
        result = GNUNET_MIN(result, agent_get_utility(cur));
      }
    }
    return result;

  case RIL_WELFARE_NASH:
    result = 0;
    for (cur = solver->agents_head; NULL != cur; cur = cur->next)
    {
      if (cur->is_active && cur->address_inuse && (cur->address_inuse->solver_information == scope))
      {
        result *= pow(agent_get_utility(cur), 1.0 / (double) scope->active_agent_count);
      }
    }
    return result;
  }
  GNUNET_assert(GNUNET_NO);
  return 1;
}

static double
envi_get_penalty (struct GAS_RIL_Handle *solver, struct RIL_Peer_Agent *agent)
{
  struct RIL_Scope *net;
  unsigned long long over_max;
  unsigned long long over_in = 0;
  unsigned long long over_out = 0;

  net = agent->address_inuse->solver_information;

  if (net->bw_in_utilized > net->bw_in_available)
  {
    over_in = net->bw_in_utilized - net->bw_in_available;
    if (RIL_ACTION_BW_IN_INC == agent->a_old)
    {
      /* increase quadratically */
      over_in *= over_in;
    }
  }
  if (net->bw_out_utilized > net->bw_out_available)
  {
    over_out = net->bw_out_utilized - net->bw_out_available;
    if (RIL_ACTION_BW_OUT_INC == agent->a_old)
    {
      /* increase quadratically */
      over_out *= over_out;
    }
  }
  over_max = (over_in + over_out) / (RIL_MIN_BW * RIL_MIN_BW);

  return -1.0 * (double) over_max;
}

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
  struct RIL_Scope *net;
  double objective;
  double delta;
  double steady;
  double penalty;
  double reward;

  net = agent->address_inuse->solver_information;

  penalty = envi_get_penalty(solver, agent);
  objective = (agent_get_utility (agent) + net->social_welfare) / 2;
  delta = objective - agent->objective_old;
  agent->objective_old = objective;

  if (delta != 0 && penalty == 0)
  {
    agent->nop_bonus = delta * RIL_NOP_DECAY;
  }
  else
  {
    agent->nop_bonus *= RIL_NOP_DECAY;
  }

  steady = (RIL_ACTION_NOTHING == agent->a_old) ? agent->nop_bonus : 0;

  reward = delta + steady;
  return reward + penalty;
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
  unsigned long long max_bw;

  max_bw = ril_get_max_bw((struct RIL_Scope *) agent->address_inuse->solver_information);

  if (direction_in)
  {
    new_bw = agent->bw_in * 2;
    if (new_bw < agent->bw_in || new_bw > max_bw)
      new_bw = max_bw;
    envi_set_active_suggestion (solver, agent, agent->address_inuse, new_bw,
        agent->bw_out, GNUNET_NO);
  }
  else
  {
    new_bw = agent->bw_out * 2;
    if (new_bw < agent->bw_out || new_bw > max_bw)
      new_bw = max_bw;
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
    if (new_bw <= 0 || new_bw > agent->bw_in)
      new_bw = 0;
    envi_set_active_suggestion (solver, agent, agent->address_inuse, new_bw, agent->bw_out,
        GNUNET_NO);
  }
  else
  {
    new_bw = agent->bw_out / 2;
    if (new_bw <= 0 || new_bw > agent->bw_out)
      new_bw = 0;
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
  unsigned long long max_bw;

  max_bw = ril_get_max_bw((struct RIL_Scope *) agent->address_inuse->solver_information);

  if (direction_in)
  {
    new_bw = agent->bw_in + (RIL_INC_DEC_STEP_SIZE * RIL_MIN_BW);
    if (new_bw < agent->bw_in || new_bw > max_bw)
      new_bw = max_bw;
    envi_set_active_suggestion (solver, agent, agent->address_inuse, new_bw,
        agent->bw_out, GNUNET_NO);
  }
  else
  {
    new_bw = agent->bw_out + (RIL_INC_DEC_STEP_SIZE * RIL_MIN_BW);
    if (new_bw < agent->bw_out || new_bw > max_bw)
      new_bw = max_bw;
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
    new_bw = agent->bw_in - (RIL_INC_DEC_STEP_SIZE * RIL_MIN_BW);
    if (new_bw <= 0 || new_bw > agent->bw_in)
      new_bw = 0;
    envi_set_active_suggestion (solver, agent, agent->address_inuse, new_bw, agent->bw_out,
        GNUNET_NO);
  }
  else
  {
    new_bw = agent->bw_out - (RIL_INC_DEC_STEP_SIZE * RIL_MIN_BW);
    if (new_bw <= 0 || new_bw > agent->bw_out)
      new_bw = 0;
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

  //cur = agent_address_get_wrapped(agent, agent->address_inuse);

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
 * Selects the next action using the e-greedy strategy. I.e. with a probability
 * of (1-e) the action with the maximum expected return will be chosen
 * (=> exploitation) and with probability (e) a random action will be chosen.
 * In case the Q-learning rule is set, the function also resets the eligibility
 * traces in the exploration case (after Watkin's Q-learning).
 *
 * @param agent the agent selecting an action
 * @param state the current state-feature vector
 * @return the action index
 */
static int
agent_select_egreedy (struct RIL_Peer_Agent *agent, double *state)
{
  int action;
  double r = (double) GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
        UINT32_MAX) / (double) UINT32_MAX;

  if (r < agent->envi->parameters.epsilon) //explore
  {
    action = agent_get_action_random(agent);
    if (RIL_ALGO_Q == agent->envi->parameters.algorithm)
    {
      agent->eligibility_reset = GNUNET_YES;
    }
    agent->envi->parameters.epsilon *= agent->envi->parameters.epsilon_decay;
    return action;
  }
  else //exploit
  {
    action = agent_get_action_max(agent, state);
    return action;
  }
}

/**
 * Selects the next action with a probability corresponding to its value. The
 * probability is calculated using a Boltzmann distribution with a temperature
 * value. The higher the temperature, the more are the action selection
 * probabilities the same. With a temperature of 0, the selection is greedy,
 * i.e. always the action with the highest value is chosen.
 * @param agent
 * @param state
 * @return
 */
static int
agent_select_softmax (struct RIL_Peer_Agent *agent, double *state)
{
  int i;
  int a_max;
  double eqt[agent->n];
  double p[agent->n];
  double sum = 0;
  double r;

  a_max = agent_get_action_max(agent, state);

  for (i=0; i<agent->n; i++)
  {
    if (agent_action_is_possible(agent, i))
    {
      eqt[i] = exp(agent_q(agent,state,i) / agent->envi->parameters.temperature);
      if (isinf (eqt[i]))
        eqt[i] = isinf(eqt[i]) * UINT32_MAX;
      sum += eqt[i];
    }
  }
  for (i=0; i<agent->n; i++)
  {
    if (agent_action_is_possible(agent, i))
    {
      p[i] = eqt[i]/sum;
    }
    else
    {
      p[i] = 0;
    }
  }
  r = (double) GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
      UINT32_MAX) / (double) UINT32_MAX;
  sum = 0;
  for (i=0; i<agent->n; i++)
  {
    if (sum + p[i] > r)
    {
      if (i != a_max)
      {
        if (RIL_ALGO_Q == agent->envi->parameters.algorithm)
          agent->eligibility_reset = GNUNET_YES;
        agent->envi->parameters.temperature *= agent->envi->parameters.temperature_decay;
      }
      return i;
    }
    sum += p[i];
  }
  GNUNET_assert(GNUNET_NO);
  return RIL_ACTION_INVALID;
}

/**
 * Select the next action of an agent either according to the e-greedy strategy
 * or the softmax strategy.
 *
 * @param agent the agent in question
 * @param state the current state-feature vector
 * @return the action index
 */
static int
agent_select_action (struct RIL_Peer_Agent *agent, double *state)
{
  if (agent->envi->parameters.select == RIL_SELECT_EGREEDY)
  {
    return agent_select_egreedy(agent, state);
  }
  else
  {
    return agent_select_softmax(agent, state);
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
  int a_max;
  double *s_next;
  double reward;

  LOG(GNUNET_ERROR_TYPE_DEBUG, "    agent_step() Peer '%s', algorithm %s\n",
      GNUNET_i2s (&agent->peer),
      agent->envi->parameters.algorithm ? "Q" : "SARSA");

  s_next = envi_get_state (agent->envi, agent);
  reward = envi_get_reward (agent->envi, agent);

  if (agent->eligibility_reset)
  {
    agent_modify_eligibility(agent, RIL_E_ZERO, NULL, -1);
    agent->eligibility_reset = GNUNET_NO;
  }
  else
  {
    agent_modify_eligibility (agent, RIL_E_DECAY, NULL, -1);
  }
  if (RIL_ACTION_INVALID != agent->a_old)
  {
    agent_modify_eligibility (agent, agent->envi->parameters.eligibility_trace_mode, agent->s_old, agent->a_old);
  }

  switch (agent->envi->parameters.algorithm)
  {
  case RIL_ALGO_SARSA:
    a_next = agent_select_action (agent, s_next);
    if (RIL_ACTION_INVALID != agent->a_old)
    {
      //updates weights with selected action (on-policy), if not first step
      agent_update (agent, reward, s_next, a_next);
    }
    break;

  case RIL_ALGO_Q:
    a_max = agent_get_action_max (agent, s_next);
    if (RIL_ACTION_INVALID != agent->a_old)
    {
      //updates weights with best action, disregarding actually selected action (off-policy), if not first step
      agent_update (agent, reward, s_next, a_max);
    }
    a_next = agent_select_action (agent, s_next);
    break;
  }

  GNUNET_assert(RIL_ACTION_INVALID != a_next);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "step()  Step# %llu  R: %f  IN %llu  OUT %llu  A: %d\n",
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

/**
 * Prototype of the ril_step() procedure
 *
 * @param solver the solver handle
 */
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

  solver->step_next_task_id = NULL;
  ril_step (solver);
}

/**
 * Determines how much of the available bandwidth is assigned. If more is
 * assigned than available it returns 1. The function is used to determine the
 * step size of the adaptive stepping.
 *
 * @param solver the solver handle
 * @return the ratio
 */
static double
ril_get_used_resource_ratio (struct GAS_RIL_Handle *solver)
{
  int i;
  struct RIL_Scope net;
  unsigned long long sum_assigned = 0;
  unsigned long long sum_available = 0;
  double ratio;

  for (i = 0; i < solver->networks_count; i++)
  {
    net = solver->network_entries[i];
    if (net.bw_in_assigned > 0) //only consider scopes where an address is actually active
    {
      sum_assigned += net.bw_in_utilized;
      sum_assigned += net.bw_out_utilized;
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

  return ratio > 1 ? 1 : ratio; //overutilization is possible, cap at 1
}

/**
 * Lookup network struct by type
 *
 * @param s the solver handle
 * @param type the network type
 * @return the network struct
 */
static struct RIL_Scope *
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

/**
 * Determines whether more connections are allocated in a network scope, than
 * they would theoretically fit. This is used as a heuristic to determine,
 * whether a new connection can be allocated or not.
 *
 * @param solver the solver handle
 * @param network the network scope in question
 * @return GNUNET_YES if there are theoretically enough resources left
 */
static int
ril_network_is_not_full (struct GAS_RIL_Handle *solver, enum GNUNET_ATS_Network_Type network)
{
  struct RIL_Scope *net;
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
  return (net->bw_in_available > RIL_MIN_BW * address_count) && (net->bw_out_available > RIL_MIN_BW * address_count);
}

/**
 * Unblocks an agent for which a connection request is there, that could not
 * be satisfied. Iterates over the addresses of the agent, if one of its
 * addresses can now be allocated in its scope the agent is unblocked,
 * otherwise it remains unchanged.
 *
 * @param solver the solver handle
 * @param agent the agent in question
 * @param silent
 */
static void
ril_try_unblock_agent (struct GAS_RIL_Handle *solver, struct RIL_Peer_Agent *agent, int silent)
{
  struct RIL_Address_Wrapped *addr_wrap;
  struct RIL_Scope *net;
  unsigned long long start_in;
  unsigned long long start_out;

  for (addr_wrap = agent->addresses_head; NULL != addr_wrap; addr_wrap = addr_wrap->next)
  {
    net = addr_wrap->address_naked->solver_information;
    if (ril_network_is_not_full(solver, net->type))
    {
      if (NULL == agent->address_inuse)
      {
        start_in = net->bw_in_available < net->bw_in_utilized ? (net->bw_in_available - net->bw_in_utilized) / 2 : RIL_MIN_BW;
        start_out = net->bw_out_available < net->bw_out_utilized ? (net->bw_out_available - net->bw_out_utilized) / 2 : RIL_MIN_BW;
        envi_set_active_suggestion (solver, agent, addr_wrap->address_naked, start_in, start_out, silent);
      }
      return;
    }
  }
  agent->address_inuse = NULL;
}

/**
 * Determines how much the reward needs to be discounted depending on the amount
 * of time, which has passed since the last time-step.
 *
 * @param solver the solver handle
 */
static void
ril_calculate_discount (struct GAS_RIL_Handle *solver)
{
  struct GNUNET_TIME_Absolute time_now;
  struct GNUNET_TIME_Relative time_delta;
  double tau;

  // MDP case only for debugging purposes
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
  solver->global_discount_variable = pow (M_E, ((-1.0) * ((double) solver->parameters.beta) * tau));
  solver->global_discount_integrated = (1.0 - solver->global_discount_variable)
      / (double) solver->parameters.beta;
}

/**
 * Count the number of active agents/connections in a network scope
 *
 * @param solver the solver handle
 * @param scope the network scope in question
 * @return the number of allocated connections
 */
static int
ril_network_count_active_agents (struct GAS_RIL_Handle *solver, struct RIL_Scope *scope)
{
  int c = 0;
  struct RIL_Peer_Agent *cur_agent;

  for (cur_agent = solver->agents_head; NULL != cur_agent; cur_agent = cur_agent->next)
  {
    if (cur_agent->is_active && cur_agent->address_inuse && (cur_agent->address_inuse->solver_information == scope))
    {
      c++;
    }
  }
  return c;
}

/**
 * Calculates how much bandwidth is assigned in sum in a network scope, either
 * in the inbound or in the outbound direction.
 *
 * @param solver the solver handle
 * @param type the type of the network scope in question
 * @param direction_in GNUNET_YES if the inbound direction should be summed up,
 *   otherwise the outbound direction will be summed up
 * @return the sum of the assigned bandwidths
 */
static unsigned long long
ril_network_get_assigned (struct GAS_RIL_Handle *solver, enum GNUNET_ATS_Network_Type type, int direction_in)
{
  struct RIL_Peer_Agent *cur;
  struct RIL_Scope *net;
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

/**
 * Calculates how much bandwidth is actually utilized in sum in a network scope,
 * either in the inbound or in the outbound direction.
 *
 * @param solver the solver handle
 * @param type the type of the network scope in question
 * @param direction_in GNUNET_YES if the inbound direction should be summed up,
 *   otherwise the outbound direction will be summed up
 * @return the sum of the utilized bandwidths (in bytes/second)
 */
static unsigned long long
ril_network_get_utilized (struct GAS_RIL_Handle *solver, enum GNUNET_ATS_Network_Type type, int direction_in)
{
  struct RIL_Peer_Agent *cur;
  struct RIL_Scope *net;
  unsigned long long sum = 0;

  for (cur = solver->agents_head; NULL != cur; cur = cur->next)
  {
    if (cur->is_active && cur->address_inuse)
    {
      net = cur->address_inuse->solver_information;
      if (net->type == type)
      {
        if (direction_in)
          sum += ril_get_atsi (cur->address_inuse, GNUNET_ATS_UTILIZATION_IN);
        else
          sum += ril_get_atsi (cur->address_inuse, GNUNET_ATS_UTILIZATION_OUT);
      }
    }
  }

  return sum;
}

/**
 * Retrieves the state of the network scope, so that its attributes are up-to-
 * date.
 *
 * @param solver the solver handle
 */
static void
ril_networks_update_state (struct GAS_RIL_Handle *solver)
{
  int c;
  struct RIL_Scope *net;

  for (c = 0; c < solver->networks_count; c++)
  {
    net = &solver->network_entries[c];
    net->bw_in_assigned = ril_network_get_assigned(solver, net->type, GNUNET_YES);
    net->bw_in_utilized = ril_network_get_utilized(solver, net->type, GNUNET_YES);
    net->bw_out_assigned = ril_network_get_assigned(solver, net->type, GNUNET_NO);
    net->bw_out_utilized = ril_network_get_utilized(solver, net->type, GNUNET_NO);
    net->active_agent_count = ril_network_count_active_agents(solver, net);
    net->social_welfare = ril_network_get_social_welfare(solver, net);
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

  GNUNET_assert(y <= (double) solver->parameters.step_time_max.rel_value_us);
  GNUNET_assert(y >= (double) solver->parameters.step_time_min.rel_value_us);

  time_next = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MICROSECONDS, (unsigned long long) y);

//  LOG (GNUNET_ERROR_TYPE_INFO, "ratio: %f, factor: %f, offset: %f, y: %f\n",
//      used_ratio,
//      factor,
//      offset,
//      y);

  if (solver->simulate)
  {
    time_next = GNUNET_TIME_UNIT_ZERO;
  }

  if ((NULL == solver->step_next_task_id) && (GNUNET_NO == solver->done))
  {
    solver->step_next_task_id = GNUNET_SCHEDULER_add_delayed (time_next, &ril_step_scheduler_task,
          solver);
  }
}

/**
 * Triggers one step per agent
 *
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
  ril_networks_update_state (solver);

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

  ril_networks_update_state (solver);

  solver->step_count++;
  ril_step_schedule_next (solver);

  ril_inform (solver, GAS_OP_SOLVE_STOP, GAS_STAT_SUCCESS);

  ril_inform (solver, GAS_OP_SOLVE_UPDATE_NOTIFICATION_START, GAS_STAT_SUCCESS);
  for (cur = solver->agents_head; NULL != cur; cur = cur->next)
  {
    if (cur->suggestion_issue) {
      solver->env->bandwidth_changed_cb (solver->env->cls,
                                         cur->suggestion_address);
      cur->suggestion_issue = GNUNET_NO;
    }
  }
  ril_inform (solver, GAS_OP_SOLVE_UPDATE_NOTIFICATION_STOP, GAS_STAT_SUCCESS);
}

/**
 * Initializes the matrix W of parameter vectors theta with small random numbers.
 *
 * @param agent The respective agent
 */
static void
agent_w_init (struct RIL_Peer_Agent *agent)
{
  int i;
  int k;

  for (i = 0; i < agent->n; i++)
  {
    for (k = 0; k < agent->m; k++)
    {
      agent->W[i][k] = agent->envi->parameters.alpha * (1.0 - 2.0 * ((double) GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, UINT32_MAX)/(double) UINT32_MAX));
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
  struct RIL_Peer_Agent * agent = GNUNET_new (struct RIL_Peer_Agent);

  agent->envi = solver;
  agent->peer = *peer;
  agent->step_count = 0;
  agent->is_active = GNUNET_NO;
  agent->bw_in = RIL_MIN_BW;
  agent->bw_out = RIL_MIN_BW;
  agent->suggestion_issue = GNUNET_NO;
  agent->n = RIL_ACTION_TYPE_NUM;
  agent->m = 0;
  agent->W = (double **) GNUNET_malloc (sizeof (double *) * agent->n);
  agent->E = (double **) GNUNET_malloc (sizeof (double *) * agent->n);
  for (i = 0; i < agent->n; i++)
  {
    agent->W[i] = (double *) GNUNET_malloc (sizeof (double) * agent->m);
    agent->E[i] = (double *) GNUNET_malloc (sizeof (double) * agent->m);
  }
  agent_w_init(agent);
  agent->eligibility_reset = GNUNET_NO;
  agent->a_old = RIL_ACTION_INVALID;
  agent->s_old = GNUNET_malloc (sizeof (double) * agent->m);
  agent->address_inuse = NULL;
  agent->objective_old = 0;
  agent->nop_bonus = 0;

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
    GNUNET_free_non_null(agent->W[i]);
    GNUNET_free_non_null(agent->E[i]);
  }
  GNUNET_free_non_null(agent->W);
  GNUNET_free_non_null(agent->E);
  GNUNET_free_non_null(agent->s_old);
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
  struct RIL_Scope *net;

  net = ril_get_network (solver, network);
  return net->bw_out_available >= RIL_MIN_BW;
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

  GNUNET_assert(old_length >= hole_length);
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
static void
GAS_ril_address_change_preference (void *solver,
				   const struct GNUNET_PeerIdentity *peer,
				   enum GNUNET_ATS_PreferenceKind kind,
				   double pref_rel)
{
  LOG(GNUNET_ERROR_TYPE_DEBUG,
      "API_address_change_preference() Preference '%s' for peer '%s' changed to %.2f \n",
      GNUNET_ATS_print_preference_type (kind), GNUNET_i2s (peer), pref_rel);

  struct GAS_RIL_Handle *s = solver;

  s->parameters.temperature = s->parameters.temperature_init;
  s->parameters.epsilon = s->parameters.epsilon_init;
  ril_step (s);
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
static void
GAS_ril_address_add (void *solver,
		     struct ATS_Address *address,
		     uint32_t network)
{
  struct GAS_RIL_Handle *s = solver;
  struct RIL_Peer_Agent *agent;
  struct RIL_Address_Wrapped *address_wrapped;
  struct RIL_Scope *net;
  unsigned int m_new;
  unsigned int m_old;
  unsigned int n_new;
  unsigned int n_old;
  int i;
  unsigned int zero;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "API_address_add()\n");

  net = ril_get_network (s, network);
  address->solver_information = net;

  if (!ril_network_is_active (s, network))
  {
    LOG(GNUNET_ERROR_TYPE_DEBUG,
        "API_address_add() Did not add %s address %s for peer '%s', network does not have enough bandwidth\n",
        address->plugin, address->addr, GNUNET_i2s (&address->peer));
    return;
  }

  s->parameters.temperature = s->parameters.temperature_init;
  s->parameters.epsilon = s->parameters.epsilon_init;

  agent = ril_get_agent (s, &address->peer, GNUNET_YES);

  //add address
  address_wrapped = GNUNET_new (struct RIL_Address_Wrapped);
  address_wrapped->address_naked = address;
  GNUNET_CONTAINER_DLL_insert_tail(agent->addresses_head, agent->addresses_tail, address_wrapped);

  //increase size of W
  m_new = agent->m + ((s->parameters.rbf_divisor+1) * (s->parameters.rbf_divisor+1));
  m_old = agent->m;
  n_new = agent->n + 1;
  n_old = agent->n;

  GNUNET_array_grow(agent->W, agent->n, n_new);
  agent->n = n_old;
  GNUNET_array_grow(agent->E, agent->n, n_new);
  for (i = 0; i < n_new; i++)
  {
    if (i < n_old)
    {
      agent->m = m_old;
      GNUNET_array_grow(agent->W[i], agent->m, m_new);
      agent->m = m_old;
      GNUNET_array_grow(agent->E[i], agent->m, m_new);
    }
    else
    {
      zero = 0;
      GNUNET_array_grow(agent->W[i], zero, m_new);
      zero = 0;
      GNUNET_array_grow(agent->E[i], zero, m_new);
    }
  }

  //increase size of old state vector
  agent->m = m_old;
  GNUNET_array_grow(agent->s_old, agent->m, m_new);

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
 */
static void
GAS_ril_address_delete (void *solver,
			struct ATS_Address *address)
{
  struct GAS_RIL_Handle *s = solver;
  struct RIL_Peer_Agent *agent;
  struct RIL_Address_Wrapped *address_wrapped;
  int address_index;
  unsigned int m_new;
  unsigned int n_new;
  int i;
  struct RIL_Scope *net;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "API_address_delete() Delete %s %s address %s for peer '%s'\n",
       address->active ? "active" : "inactive",
       address->plugin,
       address->addr,
       GNUNET_i2s (&address->peer));

  agent = ril_get_agent (s, &address->peer, GNUNET_NO);
  if (NULL == agent)
  {
    net = address->solver_information;
    GNUNET_assert(! ril_network_is_active (s, net->type));
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "No agent allocated for peer yet, since address was in inactive network\n");
    return;
  }

  s->parameters.temperature = s->parameters.temperature_init;
  s->parameters.epsilon = s->parameters.epsilon_init;

  address_index = agent_address_get_index (agent, address);
  address_wrapped = agent_address_get_wrapped (agent, address);

  if (NULL == address_wrapped)
  {
    net = address->solver_information;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Address not considered by agent, address was in inactive network\n");
    return;
  }
  GNUNET_CONTAINER_DLL_remove (agent->addresses_head,
                               agent->addresses_tail,
                               address_wrapped);
  GNUNET_free (address_wrapped);

  //decrease W
  m_new = agent->m - ((s->parameters.rbf_divisor+1) * (s->parameters.rbf_divisor+1));
  n_new = agent->n - 1;

  for (i = 0; i < agent->n; i++)
  {
    ril_cut_from_vector ((void **) &agent->W[i], sizeof(double),
        address_index * ((s->parameters.rbf_divisor+1) * (s->parameters.rbf_divisor+1)),
        ((s->parameters.rbf_divisor+1) * (s->parameters.rbf_divisor+1)), agent->m);
    ril_cut_from_vector ((void **) &agent->E[i], sizeof(double),
        address_index * ((s->parameters.rbf_divisor+1) * (s->parameters.rbf_divisor+1)),
        ((s->parameters.rbf_divisor+1) * (s->parameters.rbf_divisor+1)), agent->m);
  }
  GNUNET_free_non_null(agent->W[RIL_ACTION_TYPE_NUM + address_index]);
  GNUNET_free_non_null(agent->E[RIL_ACTION_TYPE_NUM + address_index]);
  ril_cut_from_vector ((void **) &agent->W, sizeof(double *), RIL_ACTION_TYPE_NUM + address_index,
      1, agent->n);
  ril_cut_from_vector ((void **) &agent->E, sizeof(double *), RIL_ACTION_TYPE_NUM + address_index,
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
  //decrease old state vector
  ril_cut_from_vector ((void **) &agent->s_old, sizeof(double),
                       address_index * ((s->parameters.rbf_divisor+1) * (s->parameters.rbf_divisor+1)),
                       ((s->parameters.rbf_divisor+1) * (s->parameters.rbf_divisor+1)), agent->m);
  agent->m = m_new;
  agent->n = n_new;

  if (agent->address_inuse == address)
  {
    if (NULL != agent->addresses_head) //if peer has an address left, use it
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Active address died, suggesting alternative!\n");
      envi_set_active_suggestion (s,
                                  agent,
                                  agent->addresses_head->address_naked,
                                  agent->bw_in,
                                  agent->bw_out,
                                  GNUNET_YES);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Active address died, suggesting disconnect!\n");
      envi_set_active_suggestion (s, agent, NULL, 0, 0, GNUNET_NO);
    }
  }
  ril_step (solver);
  if (agent->suggestion_address == address)
  {
    agent->suggestion_issue = GNUNET_NO;
    agent->suggestion_address = NULL;
  }
  GNUNET_assert (agent->address_inuse != address);
}


/**
 * Update the properties of an address in the solver
 *
 * @param solver solver handle
 * @param address the address
 * @param type the ATSI type
 * @param abs_value the absolute value of the property
 * @param rel_value the normalized value
 */
static void
GAS_ril_address_property_changed (void *solver,
				  struct ATS_Address *address,
				  enum GNUNET_ATS_Property type,
				  uint32_t abs_value,
				  double rel_value)
{
  struct GAS_RIL_Handle *s = solver;

  LOG(GNUNET_ERROR_TYPE_DEBUG,
      "API_address_property_changed() Property '%s' for peer '%s' address %s changed "
          "to %.2f \n",
      GNUNET_ATS_print_property_type (type),
      GNUNET_i2s (&address->peer),
      address->addr, rel_value);


  s->parameters.temperature = s->parameters.temperature_init;
  s->parameters.epsilon = s->parameters.epsilon_init;
  ril_step (s);
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
static void
GAS_ril_address_preference_feedback (void *solver,
                                     struct GNUNET_SERVER_Client *application,
                                     const struct GNUNET_PeerIdentity *peer,
                                     const struct GNUNET_TIME_Relative scope,
                                     enum GNUNET_ATS_PreferenceKind kind,
                                     double score)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "API_address_preference_feedback() Peer '%s' got a feedback of %+.3f from application %s for "
       "preference %s for %d seconds\n",
       GNUNET_i2s (peer),
       "UNKNOWN",
       GNUNET_ATS_print_preference_type (kind),
       scope.rel_value_us / 1000000);
}


/**
 * Start a bulk operation
 *
 * @param solver the solver
 */
static void
GAS_ril_bulk_start (void *solver)
{
  struct GAS_RIL_Handle *s = solver;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "API_bulk_start() lock: %d\n", s->bulk_lock+1);

  s->bulk_lock++;
}


/**
 * Bulk operation done
 *
 * @param solver the solver handle
 */
static void
GAS_ril_bulk_stop (void *solver)
{
  struct GAS_RIL_Handle *s = solver;

  LOG(GNUNET_ERROR_TYPE_DEBUG,
      "API_bulk_stop() lock: %d\n",
      s->bulk_lock - 1);

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
static const struct ATS_Address *
GAS_ril_get_preferred_address (void *solver,
			       const struct GNUNET_PeerIdentity *peer)
{
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
    s->parameters.temperature = s->parameters.temperature_init;
    s->parameters.epsilon = s->parameters.epsilon_init;
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
static void
GAS_ril_stop_get_preferred_address (void *solver,
				    const struct GNUNET_PeerIdentity *peer)
{
  struct GAS_RIL_Handle *s = solver;
  struct RIL_Peer_Agent *agent;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "API_stop_get_preferred_address()");

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

  s->parameters.temperature = s->parameters.temperature_init;
  s->parameters.epsilon = s->parameters.epsilon_init;

  agent->is_active = GNUNET_NO;

  envi_set_active_suggestion (s, agent, agent->address_inuse, agent->bw_in, agent->bw_out,
      GNUNET_YES);

  ril_step (s);

  LOG(GNUNET_ERROR_TYPE_DEBUG,
      "API_stop_get_preferred_address() Paused agent for peer '%s'\n",
      GNUNET_i2s (peer));
}


/**
 * Entry point for the plugin
 *
 * @param cls pointer to the 'struct GNUNET_ATS_PluginEnvironment'
 */
void *
libgnunet_plugin_ats_ril_init (void *cls)
{
  static struct GNUNET_ATS_SolverFunctions sf;
  struct GNUNET_ATS_PluginEnvironment *env = cls;
  struct GAS_RIL_Handle *solver = GNUNET_new (struct GAS_RIL_Handle);
  struct RIL_Scope * cur;
  int c;
  char *string;
  float f_tmp;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "API_init() Initializing RIL solver\n");

  GNUNET_assert (NULL != env);
  GNUNET_assert (NULL != env->cfg);
  GNUNET_assert (NULL != env->stats);
  GNUNET_assert (NULL != env->bandwidth_changed_cb);
  GNUNET_assert (NULL != env->get_preferences);

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number(env->cfg, "ats", "RIL_RBF_DIVISOR", &solver->parameters.rbf_divisor))
  {
    solver->parameters.rbf_divisor = RIL_DEFAULT_RBF_DIVISOR;
  }

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
    GNUNET_STRINGS_utf8_toupper (string, string);
    if (0 == strcmp (string, "SARSA"))
    {
        solver->parameters.algorithm = RIL_ALGO_SARSA;
    }
    if (0 == strcmp (string, "Q-LEARNING"))
    {
        solver->parameters.algorithm = RIL_ALGO_Q;
    }

    GNUNET_free (string);
  }
  else
  {
    solver->parameters.algorithm = RIL_DEFAULT_ALGORITHM;
  }

  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string (env->cfg, "ats", "RIL_SELECT", &string))
  {
    solver->parameters.select = !strcmp (string, "EGREEDY") ? RIL_SELECT_EGREEDY : RIL_SELECT_SOFTMAX;
    GNUNET_free (string);
  }
  else
  {
    solver->parameters.select = RIL_DEFAULT_SELECT;
  }


  solver->parameters.beta = RIL_DEFAULT_DISCOUNT_BETA;
  if (GNUNET_SYSERR != GNUNET_CONFIGURATION_get_value_float (env->cfg, "ats",
      "RIL_DISCOUNT_BETA", &f_tmp))
  {
    if (f_tmp < 0.0)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, _("Invalid %s configuration %f \n"),
          "RIL_DISCOUNT_BETA", f_tmp);
    }
    else
    {
      solver->parameters.beta = f_tmp;
      LOG (GNUNET_ERROR_TYPE_INFO, "Using %s of %.3f\n",
          "RIL_DISCOUNT_BETA", f_tmp);
    }
  }

  solver->parameters.gamma = RIL_DEFAULT_DISCOUNT_GAMMA;
  if (GNUNET_SYSERR != GNUNET_CONFIGURATION_get_value_float (env->cfg, "ats",
      "RIL_DISCOUNT_GAMMA", &f_tmp))
  {
    if ((f_tmp < 0.0) || (f_tmp > 1.0))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, _("Invalid %s configuration %f \n"),
          "RIL_DISCOUNT_GAMMA", f_tmp);
    }
    else
    {
      solver->parameters.gamma = f_tmp;
      LOG (GNUNET_ERROR_TYPE_INFO, "Using %s of %.3f\n",
          "RIL_DISCOUNT_GAMMA", f_tmp);
    }
  }

  solver->parameters.alpha = RIL_DEFAULT_GRADIENT_STEP_SIZE;
  if (GNUNET_SYSERR != GNUNET_CONFIGURATION_get_value_float (env->cfg, "ats",
      "RIL_GRADIENT_STEP_SIZE", &f_tmp))
  {
    if ((f_tmp < 0.0) || (f_tmp > 1.0))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, _("Invalid %s configuration %f \n"),
          "RIL_GRADIENT_STEP_SIZE", f_tmp);
    }
    else
    {
      solver->parameters.alpha = f_tmp;
      LOG (GNUNET_ERROR_TYPE_INFO, "Using %s of %.3f\n",
          "RIL_GRADIENT_STEP_SIZE", f_tmp);
    }
  }

  solver->parameters.lambda = RIL_DEFAULT_TRACE_DECAY;
  if (GNUNET_SYSERR != GNUNET_CONFIGURATION_get_value_float (env->cfg, "ats",
      "RIL_TRACE_DECAY", &f_tmp))
  {
    if ((f_tmp < 0.0) || (f_tmp > 1.0))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, _("Invalid %s configuration %f \n"),
          "RIL_TRACE_DECAY", f_tmp);
    }
    else
    {
      solver->parameters.lambda = f_tmp;
      LOG (GNUNET_ERROR_TYPE_INFO, "Using %s of %.3f\n",
          "RIL_TRACE_DECAY", f_tmp);
    }
  }

  solver->parameters.epsilon_init = RIL_DEFAULT_EXPLORE_RATIO;
  if (GNUNET_SYSERR != GNUNET_CONFIGURATION_get_value_float (env->cfg, "ats",
      "RIL_EXPLORE_RATIO", &f_tmp))
  {
    if ((f_tmp < 0.0) || (f_tmp > 1.0))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, _("Invalid %s configuration %f \n"),
          "RIL_EXPLORE_RATIO", f_tmp);
    }
    else
    {
      solver->parameters.epsilon_init = f_tmp;
      LOG (GNUNET_ERROR_TYPE_INFO, "Using %s of %.3f\n",
          "RIL_EXPLORE_RATIO", f_tmp);
    }
  }

  solver->parameters.epsilon_decay = RIL_DEFAULT_EXPLORE_DECAY;
  if (GNUNET_SYSERR != GNUNET_CONFIGURATION_get_value_float (env->cfg, "ats",
      "RIL_EXPLORE_DECAY", &f_tmp))
  {
    if ((f_tmp < 0.0) || (f_tmp > 1.0))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, _("Invalid %s configuration %f \n"),
          "RIL_EXPLORE_DECAY", f_tmp);
    }
    else
    {
      solver->parameters.epsilon_decay = f_tmp;
      LOG (GNUNET_ERROR_TYPE_INFO, "Using %s of %.3f\n",
          "RIL_EXPLORE_DECAY", f_tmp);
    }
  }

  solver->parameters.temperature_init = RIL_DEFAULT_TEMPERATURE;
  if (GNUNET_SYSERR != GNUNET_CONFIGURATION_get_value_float (env->cfg, "ats",
      "RIL_TEMPERATURE", &f_tmp))
  {
    if (f_tmp <= 0.0)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, _("Invalid %s configuration %f \n"),
          "RIL_TEMPERATURE", f_tmp);
    }
    else
    {
      solver->parameters.temperature_init = f_tmp;
      LOG (GNUNET_ERROR_TYPE_INFO, "Using %s of %.3f\n",
          "RIL_TEMPERATURE", f_tmp);
    }
  }

  solver->parameters.temperature_decay = RIL_DEFAULT_TEMPERATURE_DECAY;
  if (GNUNET_SYSERR != GNUNET_CONFIGURATION_get_value_float (env->cfg, "ats",
      "RIL_TEMPERATURE_DECAY", &f_tmp))
  {
    if ((f_tmp <= 0.0) || solver->parameters.temperature_decay > 1)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, _("Invalid %s configuration %f \n"),
          "RIL_TEMPERATURE_DECAY", f_tmp);
    }
    else
    {
      solver->parameters.temperature_decay = f_tmp;
      LOG (GNUNET_ERROR_TYPE_INFO, "Using %s of %.3f\n",
          "RIL_TEMPERATURE_DECAY", f_tmp);
    }
  }

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (env->cfg, "ats", "RIL_SIMULATE", &solver->simulate))
  {
    solver->simulate = GNUNET_NO;
  }

  if (GNUNET_YES == GNUNET_CONFIGURATION_get_value_yesno(env->cfg, "ats", "RIL_REPLACE_TRACES"))
  {
    solver->parameters.eligibility_trace_mode = RIL_E_REPLACE;
  }
  else
  {
    solver->parameters.eligibility_trace_mode = RIL_E_ACCUMULATE;
  }

  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string (env->cfg, "ats", "RIL_SOCIAL_WELFARE", &string))
  {
    solver->parameters.social_welfare = !strcmp (string, "NASH") ? RIL_WELFARE_NASH : RIL_WELFARE_EGALITARIAN;
    GNUNET_free (string);
  }
  else
  {
    solver->parameters.social_welfare = RIL_DEFAULT_WELFARE;
  }

  solver->env = env;
  sf.cls = solver;
  sf.s_add = &GAS_ril_address_add;
  sf.s_address_update_property = &GAS_ril_address_property_changed;
  sf.s_get = &GAS_ril_get_preferred_address;
  sf.s_get_stop = &GAS_ril_stop_get_preferred_address;
  sf.s_pref = &GAS_ril_address_change_preference;
  sf.s_feedback = &GAS_ril_address_preference_feedback;
  sf.s_del = &GAS_ril_address_delete;
  sf.s_bulk_start = &GAS_ril_bulk_start;
  sf.s_bulk_stop = &GAS_ril_bulk_stop;

  solver->networks_count = env->network_count;
  solver->network_entries = GNUNET_malloc (env->network_count * sizeof (struct RIL_Scope));
  solver->step_count = 0;
  solver->done = GNUNET_NO;

  for (c = 0; c < env->network_count; c++)
  {
    cur = &solver->network_entries[c];
    cur->type = c;
    cur->bw_in_available = env->in_quota[c];
    cur->bw_out_available = env->out_quota[c];
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "init()  Quotas for %s network:  IN %llu - OUT %llu\n",
         GNUNET_ATS_print_network_type(cur->type),
         cur->bw_in_available/1024,
         cur->bw_out_available/1024);
  }

  LOG(GNUNET_ERROR_TYPE_DEBUG, "init()  Parameters:\n");
  LOG(GNUNET_ERROR_TYPE_DEBUG, "init()  Algorithm = %s, alpha = %f, beta = %f, lambda = %f\n",
      solver->parameters.algorithm ? "Q" : "SARSA",
      solver->parameters.alpha,
      solver->parameters.beta,
      solver->parameters.lambda);
  LOG(GNUNET_ERROR_TYPE_DEBUG, "init()  exploration_ratio = %f, temperature = %f, ActionSelection = %s\n",
      solver->parameters.epsilon,
      solver->parameters.temperature,
      solver->parameters.select ? "EGREEDY" : "SOFTMAX");
  LOG(GNUNET_ERROR_TYPE_DEBUG, "init()  RBF_DIVISOR = %llu\n",
      solver->parameters.rbf_divisor);

  return &sf;
}


/**
 * Exit point for the plugin
 *
 * @param cls the solver handle
 */
void *
libgnunet_plugin_ats_ril_done (void *cls)
{
  struct GNUNET_ATS_SolverFunctions *sf = cls;
  struct GAS_RIL_Handle *s = sf->cls;
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

  if (NULL != s->step_next_task_id)
  {
    GNUNET_SCHEDULER_cancel (s->step_next_task_id);
  }
  GNUNET_free(s->network_entries);
  GNUNET_free(s);

  return NULL;
}


/* end of plugin_ats_ril.c */
