/*
     This file is part of GNUnet.
     (C) 2011-2014 Christian Grothoff (and other contributing authors)

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
 * @file ats/plugin_ats_mlp.c
 * @brief ats mlp problem solver
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_ats_service.h"
#include "gnunet_ats_plugin.h"
#include "gnunet-service-ats_addresses.h"
#include "gnunet_statistics_service.h"
#include <float.h>
#include <glpk.h>


#define BIG_M_VALUE (UINT32_MAX) /10
#define BIG_M_STRING "unlimited"

#define MLP_AVERAGING_QUEUE_LENGTH 3

#define MLP_MAX_EXEC_DURATION   GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 10)
#define MLP_MAX_ITERATIONS      4096

#define MLP_DEFAULT_D 1.0
#define MLP_DEFAULT_R 1.0
#define MLP_DEFAULT_U 1.0
#define MLP_DEFAULT_QUALITY 1.0
#define MLP_DEFAULT_MIN_CONNECTIONS 4
#define MLP_DEFAULT_PEER_PREFERENCE 1.0

#define MLP_NaN -1
#define MLP_UNDEFINED 0
#define GLP_YES 1.0
#define GLP_NO  0.0

enum MLP_Output_Format
{
  MLP_MPS,
  MLP_CPLEX,
  MLP_GLPK
};


struct MLP_Solution
{
  int lp_res;
  int lp_presolv;
  int mip_res;
  int mip_presolv;

  double lp_objective_value;
  double mlp_objective_value;
  double mlp_gap;
  double lp_mlp_gap;

  int p_elements;
  int p_cols;
  int p_rows;

  int n_peers;
  int n_addresses;

};

struct ATS_Peer
{
  struct GNUNET_PeerIdentity id;

  /* Was this peer already added to the current problem? */
  int processed;

  /* constraint 2: 1 address per peer*/
  unsigned int r_c2;

  /* constraint 9: relativity */
  unsigned int r_c9;

  /* Legacy preference value */
  double f;
};

struct MLP_Problem
{
  /**
   * GLPK (MLP) problem object
   */
  glp_prob *prob;

  /* Number of addresses in problem */
  unsigned int num_addresses;
  /* Number of peers in problem */
  unsigned int num_peers;
  /* Number of elements in problem matrix */
  unsigned int num_elements;

  /* Row index constraint 2: */
  unsigned int r_c2;
  /* Row index constraint 4: minimum connections */
  unsigned int r_c4;
  /* Row index constraint 6: maximize diversity */
  unsigned int r_c6;
  /* Row index constraint 8: utilization*/
  unsigned int r_c8;
  /* Row index constraint 9: relativity*/
  unsigned int r_c9;
  /* Row indices quality metrics  */
  int r_q[GNUNET_ATS_QualityPropertiesCount];
  /* Row indices ATS network quotas */
  int r_quota[GNUNET_ATS_NetworkTypeCount];

  /* Column index Diversity (D) column */
  int c_d;
  /* Column index Utilization (U) column */
  int c_u;
  /* Column index Proportionality (R) column */
  int c_r;
  /* Column index quality metrics  */
  int c_q[GNUNET_ATS_QualityPropertiesCount];

  /* Problem matrix */
  /* Current index */
  unsigned int ci;
  /* Row index array */
  int *ia;
  /* Column index array */
  int *ja;
  /* Column index value */
  double *ar;

};

struct MLP_Variables
{
  /* Big M value for bandwidth capping */
  double BIG_M;

  /* MIP Gap */
  double mip_gap;

  /* LP MIP Gap */
  double lp_mip_gap;

  /* ATS Quality metrics
   *
   * Array with GNUNET_ATS_QualityPropertiesCount elements
   * contains mapping to GNUNET_ATS_Property*/
  int q[GNUNET_ATS_QualityPropertiesCount];

  /* Number of quality metrics */
  int m_q;

  /* Number of quality metrics */
  int m_rc;

  /* Quality metric coefficients*/
  double co_Q[GNUNET_ATS_QualityPropertiesCount];

  /* Ressource costs coefficients*/
  double co_RC[GNUNET_ATS_QualityPropertiesCount];

  /* Diversity coefficient */
  double co_D;

  /* Utility coefficient */
  double co_U;

  /* Relativity coefficient */
  double co_R;

  /* Minimum bandwidth assigned to an address */
  unsigned int b_min;

  /* Minimum number of addresses with bandwidth assigned */
  unsigned int n_min;

  /* Quotas */
  /* Array mapping array index to ATS network */
  int quota_index[GNUNET_ATS_NetworkTypeCount];
  /* Outbound quotas */
  unsigned long long quota_out[GNUNET_ATS_NetworkTypeCount];
  /* Inbound quotas */

  unsigned long long quota_in[GNUNET_ATS_NetworkTypeCount];

  /* ATS ressource costs
   * array with GNUNET_ATS_QualityPropertiesCount elements
   * contains mapping to GNUNET_ATS_Property
   * */
  int rc[GNUNET_ATS_QualityPropertiesCount];

};

/**
 * MLP Handle
 */
struct GAS_MLP_Handle
{
  struct GNUNET_ATS_PluginEnvironment *env;

  /**
   * Statistics handle
   */
  struct GNUNET_STATISTICS_Handle *stats;

  /**
   * Address hashmap for lookups
   */
  const struct GNUNET_CONTAINER_MultiPeerMap *addresses;

  /**
   * Addresses' bandwidth changed callback
   */
  GAS_bandwidth_changed_cb bw_changed_cb;

  /**
   * Addresses' bandwidth changed callback closure
   */
  void *bw_changed_cb_cls;

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

  /**
   * Exclude peer from next result propagation
   */
  const struct GNUNET_PeerIdentity *exclude_peer;

  /**
   * Encapsulation for the MLP problem
   */
  struct MLP_Problem p;

  /**
   * Encapsulation for the MLP problem variables
   */
  struct MLP_Variables pv;

  /**
   * Encapsulation for the MLP solution
   */
  struct MLP_Solution ps;

  /**
   * Bulk lock
   */

  int stat_bulk_lock;

  /**
   * Number of changes while solver was locked
   */
  int stat_bulk_requests;

  /**
   * GLPK LP control parameter
   */
  glp_smcp control_param_lp;

  /**
   * GLPK LP control parameter
   */
  glp_iocp control_param_mlp;

  /**
   * Peers with pending address requests
   */
  struct GNUNET_CONTAINER_MultiPeerMap *requested_peers;

  /**
   * Was the problem updated since last solution
   */
  int stat_mlp_prob_updated;

  /**
   * Has the problem size changed since last solution
   */
  int stat_mlp_prob_changed;

  /**
   * Solve the problem automatically when updates occur?
   * Default: GNUNET_YES
   * Can be disabled for test and measurements
   */
  int opt_mlp_auto_solve;

  /**
   * Write all MILP problems to a MPS file
   */
  int opt_dump_problem_all;

  /**
   * Write all MILP problem solutions to a file
   */
  int opt_dump_solution_all;

  /**
   * Write MILP problems to a MPS file when solver fails
   */
  int opt_dump_problem_on_fail;

  /**
   * Write MILP problem solutions to a file when solver fails
   */
  int opt_dump_solution_on_fail;

  /**
   * solve feasibility only
   */
  int opt_dbg_feasibility_only;

  /**
   * solve autoscale the problem
   */
  int opt_dbg_autoscale_problem;

  /**
   * use the intopt presolver instead of simplex
   */
  int opt_dbg_intopt_presolver;

  /**
   * Print GLPK output
   */
  int opt_dbg_glpk_verbose;

  /**
   * solve autoscale the problem
   */
  int opt_dbg_optimize_relativity;

  /**
   * solve autoscale the problem
   */
  int opt_dbg_optimize_diversity;

  /**
   * solve autoscale the problem
   */
  int opt_dbg_optimize_quality;

  /**
   * solve autoscale the problem
   */
  int opt_dbg_optimize_utility;


  /**
   * Output format
   */
  enum MLP_Output_Format opt_log_format;
};

/**
 * Address specific MLP information
 */
struct MLP_information
{

  /* Bandwidth assigned outbound */
  uint32_t b_out;

  /* Bandwidth assigned inbound */
  uint32_t b_in;

  /* Address selected */
  int n;

  /* bandwidth column index */
  signed int c_b;

  /* address usage column */
  signed int c_n;

  /* row indexes */

  /* constraint 1: bandwidth capping */
  unsigned int r_c1;

  /* constraint 3: minimum bandwidth */
  unsigned int r_c3;
};



/**
 *
 * NOTE: Do not modify this documentation. This documentation is based on
 * gnunet.org:/vcs/fsnsg/ats-paper.git/tech-doku/ats-tech-guide.tex
 * use build_txt.sh to generate plaintext output
 *
 *    The MLP solver (mlp) tries to finds an optimal bandwidth assignmentby
 *    optimizing an mixed integer programming problem. The MLP solver uses a
 *    number of constraints to find the best adddress for a peer and an optimal
 *    bandwidth assignment. mlp uses the GNU Linear Programming Kit to solve the
 *    MLP problem.
 *
 *    We defined a constraint system to find an optimal bandwidth assignment.
 *    This constraint system uses as an input data addresses, bandwidth quotas,
 *    preferences and quality values. This constraint system is stored in an
 *    matrix based equotation system.
 *
 *   5 Using GLPK
 *
 *    A (M)LP problem consists of a target function to optimizes, constraints
 *    and rows and columns. FIXME GLP uses three arrays to index the matrix: two
 *    integer arrays storing the row and column indices in the matrix and an
 *    float array to store the coeeficient.
 *
 *    To solve the problem we first find an initial solution for the LP problem
 *    using the LP solver and then find an MLP solution based on this solution
 *    using the MLP solver.
 *
 *    Solving (M)LP problems has the property that finding an initial solution
 *    for the LP problem is computationally expensive and finding the MLP
 *    solution is cheaper. This is especially interesting an existing LP
 *    solution can be reused if only coefficients in the matrix have changed
 *    (addresses updated). Only when the problem size changes (addresses added
 *    or deleted) a new LP solution has to be found.
 *
 *    Intended usage
 *    The mlp solver solves the bandwidth assignment problem only on demand when
 *    an address suggestion is requested. When an address is requested mlp the
 *    solves the mlp problem and if the active address or the bandwidth assigned
 *    changes it calls the callback to addresses. The mlp solver gets notified
 *    about new addresses (adding sessions), removed addresses (address
 *    deletions) and address updates. To benefit from the mlp properties
 *    mentioned in section 5 the solver rembers if since the last solution
 *    addresses were added or deleted (problem size changed, problem has to be
 *    rebuild and solved from sratch) or if addresses were updated and the
 *    existing solution can be reused.
 *
 *     5.1 Input data
 *
 *    The quotas for each network segment are passed by addresses. MLP can be
 *    adapted using configuration settings and uses the following parameters:
 *      * MLP_MAX_DURATION:
 *        Maximum duration for a MLP solution procees (default: 3 sec.)
 *      * MLP_MAX_ITERATIONS:
 *        Maximum number of iterations for a MLP solution process (default:
 *        1024)
 *      * MLP_MIN_CONNECTIONS:
 *        Minimum number of desired connections (default: 4)
 *      * MLP_MIN_BANDWIDTH:
 *        Minimum amount of bandwidth assigned to an address (default: 1024)
 *      * MLP_COEFFICIENT_D:
 *        Diversity coefficient (default: 1.0)
 *      * MLP_COEFFICIENT_R:
 *        Relativity coefficient (default: 1.0)
 *      * MLP_COEFFICIENT_U:
 *        Utilization coefficient (default: 1.0)
 *      * MLP_COEFFICIENT_D:
 *        Diversity coefficient (default: 1.0)
 *      * MLP_COEFFICIENT_QUALITY_DELAY:
 *        Quality delay coefficient (default: 1.0)
 *      * MLP_COEFFICIENT_QUALITY_DISTANCE:
 *        Quality distance coefficient (default: 1.0)
 *      * MLP_COEFFICIENT_QUALITY_DISTANCE:
 *        Quality distance coefficient (default: 1.0)
 *      * MLP_COEFFICIENT_QUALITY_DISTANCE:
 *        Quality distance coefficient (default: 1.0)
 *      * MLP_COEFFICIENT_QUALITY_DISTANCE:
 *        Quality distance coefficient (default: 1.0)
 *
 *     5.2 Data structures used
 *
 *    mlp has for each known peer a struct ATS_Peer containing information about
 *    a specific peer. The address field solver_information contains information
 *    about the mlp properties of this address.
 *
 *     5.3 Initializing
 *
 *    During initialization mlp initializes the GLPK libray used to solve the
 *    MLP problem: it initializes the glpk environment and creates an initial LP
 *    problem. Next it loads the configuration values from the configuration or
 *    uses the default values configured in -addresses_mlp.h. The quotas used
 *    are given by addresses but may have to be adjusted. mlp uses a upper limit
 *    for the bandwidth assigned called BIG M and a minimum amount of bandwidth
 *    an address gets assigned as well as a minium desired number of
 *    connections. If the configured quota is bigger than BIG M, it is reduced
 *    to BIG M. If the configured quota is smaller than MLP_MIN_CONNECTIONS
 *    *MLP_MIN_BANDWIDTH it is increased to this value.
 *
 *     5.4 Shutdown

 */

#define LOG(kind,...) GNUNET_log_from (kind, "ats-mlp",__VA_ARGS__)

/**
 * Print debug output for mlp problem creation
 */
#define DEBUG_MLP_PROBLEM_CREATION GNUNET_NO


/**
 * Intercept GLPK terminal output
 * @param info the mlp handle
 * @param s the string to print
 * @return 0: glpk prints output on terminal, 0 != surpress output
 */
static int
mlp_term_hook (void *info, const char *s)
{
  struct GAS_MLP_Handle *mlp = info;

  if (mlp->opt_dbg_glpk_verbose)
    LOG (GNUNET_ERROR_TYPE_ERROR, "%s", s);
  return 1;
}


/**
 * Reset peers for next problem creation
 *
 * @param cls not used
 * @param key the key
 * @param value ATS_Peer
 * @return GNUNET_OK
 */
static int
reset_peers (void *cls,
	     const struct GNUNET_PeerIdentity *key,
	     void *value)
 {
   struct ATS_Peer *peer = value;
   peer->processed = GNUNET_NO;
   return GNUNET_OK;
 }

/**
 * Delete the MLP problem and free the constrain matrix
 *
 * @param mlp the MLP handle
 */
static void
mlp_delete_problem (struct GAS_MLP_Handle *mlp)
{
  int c;
  if (mlp == NULL)
    return;
  if (mlp->p.prob != NULL)
  {
    glp_delete_prob(mlp->p.prob);
    mlp->p.prob = NULL;
  }

  /* delete row index */
  if (mlp->p.ia != NULL)
  {
    GNUNET_free (mlp->p.ia);
    mlp->p.ia = NULL;
  }

  /* delete column index */
  if (mlp->p.ja != NULL)
  {
    GNUNET_free (mlp->p.ja);
    mlp->p.ja = NULL;
  }

  /* delete coefficients */
  if (mlp->p.ar != NULL)
  {
    GNUNET_free (mlp->p.ar);
    mlp->p.ar = NULL;
  }
  mlp->p.ci = 0;
  mlp->p.prob = NULL;

  mlp->p.c_d = MLP_UNDEFINED;
  mlp->p.c_r = MLP_UNDEFINED;
  mlp->p.r_c2 = MLP_UNDEFINED;
  mlp->p.r_c4 = MLP_UNDEFINED;
  mlp->p.r_c6 = MLP_UNDEFINED;
  mlp->p.r_c9 = MLP_UNDEFINED;
  for (c = 0; c < mlp->pv.m_q ; c ++)
    mlp->p.r_q[c] = MLP_UNDEFINED;
  for (c = 0; c < GNUNET_ATS_NetworkTypeCount; c ++)
    mlp->p.r_quota[c] = MLP_UNDEFINED;
  mlp->p.ci = MLP_UNDEFINED;


  GNUNET_CONTAINER_multipeermap_iterate (mlp->requested_peers,
					 &reset_peers, NULL);
}


/**
 * Translate ATS properties to text
 * Just intended for debugging
 *
 * @param ats_index the ATS index
 * @return string with result
 */
static const char *
mlp_ats_to_string (int ats_index)
{
  switch (ats_index) {
    case GNUNET_ATS_ARRAY_TERMINATOR:
      return "GNUNET_ATS_ARRAY_TERMINATOR";
    case GNUNET_ATS_UTILIZATION_OUT:
      return "GNUNET_ATS_UTILIZATION_OUT";
    case GNUNET_ATS_UTILIZATION_IN:
      return "GNUNET_ATS_UTILIZATION_IN";
    case GNUNET_ATS_UTILIZATION_PAYLOAD_OUT:
      return "GNUNET_ATS_UTILIZATION_PAYLOAD_OUT";
    case GNUNET_ATS_UTILIZATION_PAYLOAD_IN:
      return "GNUNET_ATS_UTILIZATION_PAYLOAD_IN";
    case GNUNET_ATS_COST_LAN:
      return "GNUNET_ATS_COST_LAN";
    case GNUNET_ATS_COST_WAN:
      return "GNUNET_ATS_COST_LAN";
    case GNUNET_ATS_COST_WLAN:
      return "GNUNET_ATS_COST_WLAN";
    case GNUNET_ATS_NETWORK_TYPE:
      return "GNUNET_ATS_NETWORK_TYPE";
    case GNUNET_ATS_QUALITY_NET_DELAY:
      return "GNUNET_ATS_QUALITY_NET_DELAY";
    case GNUNET_ATS_QUALITY_NET_DISTANCE:
      return "GNUNET_ATS_QUALITY_NET_DISTANCE";
    default:
      GNUNET_break (0);
      return "unknown";
  }
}

/**
 * Translate glpk status error codes to text
 * @param retcode return code
 * @return string with result
 */
static const char *
mlp_status_to_string (int retcode)
{
  switch (retcode) {
    case GLP_UNDEF:
      return "solution is undefined";
    case GLP_FEAS:
      return "solution is feasible";
    case GLP_INFEAS:
      return "solution is infeasible";
    case GLP_NOFEAS:
      return "no feasible solution exists";
    case GLP_OPT:
      return "solution is optimal";
    case GLP_UNBND:
      return "solution is unbounded";
    default:
      GNUNET_break (0);
      return "unknown error";
  }
}


/**
 * Translate glpk solver error codes to text
 * @param retcode return code
 * @return string with result
 */
static const char *
mlp_solve_to_string (int retcode)
{
  switch (retcode) {
    case 0:
      return "ok";
    case GLP_EBADB:
      return "invalid basis";
    case GLP_ESING:
      return "singular matrix";
    case GLP_ECOND:
      return "ill-conditioned matrix";
    case GLP_EBOUND:
      return "invalid bounds";
    case GLP_EFAIL:
      return "solver failed";
    case GLP_EOBJLL:
      return "objective lower limit reached";
    case GLP_EOBJUL:
      return "objective upper limit reached";
    case GLP_EITLIM:
      return "iteration limit exceeded";
    case GLP_ETMLIM:
      return "time limit exceeded";
    case GLP_ENOPFS:
      return "no primal feasible solution";
    case GLP_ENODFS:
      return "no dual feasible solution";
    case GLP_EROOT:
      return "root LP optimum not provided";
    case GLP_ESTOP:
      return "search terminated by application";
    case GLP_EMIPGAP:
      return "relative mip gap tolerance reached";
    case GLP_ENOFEAS:
      return "no dual feasible solution";
    case GLP_ENOCVG:
      return "no convergence";
    case GLP_EINSTAB:
      return "numerical instability";
    case GLP_EDATA:
      return "invalid data";
    case GLP_ERANGE:
      return "result out of range";
    default:
      GNUNET_break (0);
      return "unknown error";
  }
}

/**
 * Extract an ATS performance info from an address
 *
 * @param address the address
 * @param type the type to extract in HBO
 * @return the value in HBO or GNUNET_ATS_VALUE_UNDEFINED in HBO if value does not exist
 */
static uint32_t
get_performance_info (struct ATS_Address *address, uint32_t type)
{
  int c1;
  GNUNET_assert (NULL != address);

  if ((NULL == address->atsi) || (0 == address->atsi_count))
    return GNUNET_ATS_VALUE_UNDEFINED;

  for (c1 = 0; c1 < address->atsi_count; c1++)
  {
    if (ntohl (address->atsi[c1].type) == type)
      return ntohl (address->atsi[c1].value);
  }
  return GNUNET_ATS_VALUE_UNDEFINED;
}


struct CountContext
{
  const struct GNUNET_CONTAINER_MultiPeerMap *map;
  int result;
};

static int
mlp_create_problem_count_addresses_it (void *cls,
				       const struct GNUNET_PeerIdentity *key,
				       void *value)
{
  struct CountContext *cctx = cls;

  /* Check if we have to add this peer due to a pending request */
  if (GNUNET_YES == GNUNET_CONTAINER_multipeermap_contains (cctx->map, key))
    cctx->result++;
  return GNUNET_OK;
}


static int
mlp_create_problem_count_addresses (const struct GNUNET_CONTAINER_MultiPeerMap *requested_peers,
				    const struct GNUNET_CONTAINER_MultiPeerMap *addresses)
{
  struct CountContext cctx;

  cctx.map = requested_peers;
  cctx.result = 0;
  GNUNET_CONTAINER_multipeermap_iterate (addresses,
           &mlp_create_problem_count_addresses_it, &cctx);
  return cctx.result;
}


static int
mlp_create_problem_count_peers_it (void *cls,
                                   const struct GNUNET_PeerIdentity *key,
                                   void *value)
{
  struct CountContext *cctx = cls;

  /* Check if we have to addresses for the requested peer */
  if (GNUNET_YES == GNUNET_CONTAINER_multipeermap_contains (cctx->map, key))
    cctx->result++;
  return GNUNET_OK;
}


static int
mlp_create_problem_count_peers (const struct GNUNET_CONTAINER_MultiPeerMap *requested_peers,
    const struct GNUNET_CONTAINER_MultiPeerMap *addresses)
{
  struct CountContext cctx;

  cctx.map = addresses;
  cctx.result = 0;
  GNUNET_CONTAINER_multipeermap_iterate (requested_peers,
           &mlp_create_problem_count_peers_it, &cctx);
  return cctx.result;
}


/**
 * Updates an existing value in the matrix
 *
 * Extract the row, updates the value and updates the row in the problem
 *
 * @param p the mlp problem
 * @param row the row to create the value in
 * @param col the column to create the value in
 * @param val the value to set
 * @param line calling line for debbuging
 * @return GNUNET_YES value changed, GNUNET_NO value did not change, GNUNET_SYSERR
 * on error
 */
static int
mlp_create_problem_update_value (struct MLP_Problem *p,
                              int row, int col, double val,
                              int line)
{
  int c_cols;
  int c_elems;
  int c1;
  int res;
  int found;
  double *val_array;
  int *ind_array;

  GNUNET_assert (NULL != p);
  GNUNET_assert (NULL != p->prob);

  /* Get number of columns and prepare data structure */
  c_cols = glp_get_num_cols(p->prob);
  if (0 >= c_cols)
    return GNUNET_SYSERR;

  val_array = GNUNET_malloc ((c_cols +1)* sizeof (double));
  GNUNET_assert (NULL != val_array);
  ind_array = GNUNET_malloc ((c_cols+1) * sizeof (int));
  GNUNET_assert (NULL != ind_array);
  /* Extract the row */

  /* Update the value */
  c_elems = glp_get_mat_row (p->prob, row, ind_array, val_array);
  found = GNUNET_NO;
  for (c1 = 1; c1 < (c_elems+1); c1++)
  {
    if (ind_array[c1] == col)
    {
      found = GNUNET_YES;
      break;
    }
  }
  if (GNUNET_NO == found)
  {
    ind_array[c_elems+1] = col;
    val_array[c_elems+1] = val;
    LOG (GNUNET_ERROR_TYPE_DEBUG, "[P] Setting value in [%s : %s] to `%.2f'\n",
        glp_get_row_name (p->prob, row), glp_get_col_name (p->prob, col),
        val);
    glp_set_mat_row (p->prob, row, c_elems+1, ind_array, val_array);
    GNUNET_free (ind_array);
    GNUNET_free (val_array);
    return GNUNET_YES;
  }
  else
  {
    /* Update value */
    LOG (GNUNET_ERROR_TYPE_DEBUG, "[P] Updating value in [%s : %s] from `%.2f' to `%.2f'\n",
        glp_get_row_name (p->prob, row), glp_get_col_name (p->prob, col),
        val_array[c1], val);
    if (val != val_array[c1])
      res = GNUNET_YES;
    else
      res = GNUNET_NO;
    val_array[c1] = val;
    /* Update the row in the matrix */
    glp_set_mat_row (p->prob, row, c_elems, ind_array, val_array);
  }

  GNUNET_free (ind_array);
  GNUNET_free (val_array);
  return res;
}

/**
 * Creates a new value in the matrix
 *
 * Sets the row and column index in the problem array and increments the
 * position field
 *
 * @param p the mlp problem
 * @param row the row to create the value in
 * @param col the column to create the value in
 * @param val the value to set
 * @param line calling line for debbuging
 */
static void
mlp_create_problem_set_value (struct MLP_Problem *p,
                              int row, int col, double val,
                              int line)
{
  if ((p->ci) >= p->num_elements)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "[P]: line %u: Request for index %u bigger than array size of %u\n",
        line, p->ci + 1, p->num_elements);
    GNUNET_break (0);
    return;
  }
  if ((0 == row) || (0 == col))
  {
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_ERROR, "[P]: Invalid call from line %u: row = %u, col = %u\n",
        line, row, col);
  }
  p->ia[p->ci] = row ;
  p->ja[p->ci] = col;
  p->ar[p->ci] = val;
#if  DEBUG_MLP_PROBLEM_CREATION
  LOG (GNUNET_ERROR_TYPE_DEBUG, "[P]: line %u: Set value [%u,%u] in index %u ==  %.2f\n",
      line, p->ia[p->ci], p->ja[p->ci], p->ci, p->ar[p->ci]);
#endif
  p->ci++;
}

static int
mlp_create_problem_create_column (struct MLP_Problem *p, char *name,
    unsigned int type, unsigned int bound, double lb, double ub,
    double coef)
{
  int col = glp_add_cols (p->prob, 1);
  glp_set_col_name (p->prob, col, name);
  glp_set_col_bnds (p->prob, col, bound, lb, ub);
  glp_set_col_kind (p->prob, col, type);
  glp_set_obj_coef (p->prob, col, coef);
#if  DEBUG_MLP_PROBLEM_CREATION
  LOG (GNUNET_ERROR_TYPE_DEBUG, "[P]: Added column [%u] `%s': %.2f\n",
      col, name, coef);
#endif
  return col;
}

static int
mlp_create_problem_create_constraint (struct MLP_Problem *p, char *name,
    unsigned int bound, double lb, double ub)
{
  char * op;
  int row = glp_add_rows (p->prob, 1);
  /* set row name */
  glp_set_row_name (p->prob, row, name);
  /* set row bounds: <= 0 */
  glp_set_row_bnds (p->prob, row, bound, lb, ub);
  switch (bound)
  {
    case GLP_UP:
            GNUNET_asprintf(&op, "-inf <= x <= %.2f", ub);
            break;
    case GLP_DB:
            GNUNET_asprintf(&op, "%.2f <= x <= %.2f", lb, ub);
            break;
    case GLP_FX:
            GNUNET_asprintf(&op, "%.2f == x == %.2f", lb, ub);
            break;
    case GLP_LO:
            GNUNET_asprintf(&op, "%.2f <= x <= inf", lb);
            break;
    default:
            GNUNET_asprintf(&op, "ERROR");
            break;
  }
#if  DEBUG_MLP_PROBLEM_CREATION
    LOG (GNUNET_ERROR_TYPE_DEBUG, "[P]: Added row [%u] `%s': %s\n",
        row, name, op);
#endif
  GNUNET_free (op);
  return row;
}

/**
 * Create the
 * - address columns b and n
 * - address dependent constraint rows c1, c3
 * - peer dependent rows c2 and c9
 * - Set address dependent entries in problem matrix as well
 */
static int
mlp_create_problem_add_address_information (void *cls,
					    const struct GNUNET_PeerIdentity *key,
					    void *value)
{
  struct GAS_MLP_Handle *mlp = cls;
  struct MLP_Problem *p = &mlp->p;
  struct ATS_Address *address = value;
  struct ATS_Peer *peer;
  struct MLP_information *mlpi;
  char *name;
  const double *props;
  double cur_bigm;

  uint32_t addr_net;
  uint32_t addr_net_index;
  unsigned long long max_quota;
  int c;

  /* Check if we have to add this peer due to a pending request */
  if (GNUNET_NO == GNUNET_CONTAINER_multipeermap_contains(mlp->requested_peers, key))
    return GNUNET_OK;

  mlpi = address->solver_information;
  if (NULL == mlpi)
  {
      fprintf (stderr, "%s %p\n",GNUNET_i2s (&address->peer), address);
      GNUNET_break (0);
      return GNUNET_OK;
  }

  addr_net = get_performance_info (address, GNUNET_ATS_NETWORK_TYPE);
  for (addr_net_index = 0; addr_net_index < GNUNET_ATS_NetworkTypeCount; addr_net_index++)
  {
    if (mlp->pv.quota_index[addr_net_index] == addr_net)
      break;
  }

  if (addr_net_index >= GNUNET_ATS_NetworkTypeCount)
  {
    GNUNET_break (0);
    return GNUNET_OK;
  }

  max_quota = 0;
  for (c = 0; c < GNUNET_ATS_NetworkTypeCount; c++)
  {
    if (mlp->pv.quota_out[c] > max_quota)
      max_quota = mlp->pv.quota_out[c];
    if (mlp->pv.quota_in[c] > max_quota)
      max_quota = mlp->pv.quota_in[c];
  }
  if (max_quota > mlp->pv.BIG_M)
    cur_bigm = (double) mlp->pv.BIG_M;
  else
    cur_bigm = max_quota;


  /* Get peer */
  peer = GNUNET_CONTAINER_multipeermap_get (mlp->requested_peers, key);
  GNUNET_assert (NULL != peer);
  if (peer->processed == GNUNET_NO)
  {
      /* Add peer dependent constraints */
      /* Add c2) One address active per peer */
      GNUNET_asprintf(&name, "c2_%s", GNUNET_i2s(&address->peer));
      peer->r_c2 = mlp_create_problem_create_constraint (p, name, GLP_FX, 1.0, 1.0);
      GNUNET_free (name);
      if (GNUNET_NO == mlp->opt_dbg_feasibility_only)
      {
        if (GNUNET_YES == mlp->opt_dbg_optimize_relativity)
        {
          /* Add c9) Relativity */
          GNUNET_asprintf(&name, "c9_%s", GNUNET_i2s(&address->peer));
          peer->r_c9 = mlp_create_problem_create_constraint (p, name, GLP_LO, 0.0, 0.0);
          GNUNET_free (name);
          /* c9) set coefficient */
          mlp_create_problem_set_value (p, peer->r_c9, p->c_r, -peer->f , __LINE__);
        }
      }
      peer->processed = GNUNET_YES;
  }

  /* Reset addresses' solver information */
  mlpi->c_b = 0;
  mlpi->c_n = 0;
  mlpi->n = 0;
  mlpi->r_c1 = 0;
  mlpi->r_c3 = 0;

  /* Add bandwidth column */
  GNUNET_asprintf (&name, "b_%s_%s_%p", GNUNET_i2s (&address->peer), address->plugin, address);
  if (GNUNET_NO == mlp->opt_dbg_feasibility_only)
  {
    mlpi->c_b = mlp_create_problem_create_column (p, name, GLP_CV, GLP_LO, 0.0, 0.0, 0.0);
  }
  else
  {
    /* Maximize for bandwidth assignment in feasibility testing */
    mlpi->c_b = mlp_create_problem_create_column (p, name, GLP_CV, GLP_LO, 0.0, 0.0, 1.0);
  }
  GNUNET_free (name);

  /* Add address active column */
  GNUNET_asprintf (&name, "n_%s_%s_%p", GNUNET_i2s (&address->peer), address->plugin, address);
  mlpi->c_n = mlp_create_problem_create_column (p, name, GLP_IV, GLP_DB, 0.0, 1.0, 0.0);
  GNUNET_free (name);

  /* Add address dependent constraints */
  /* Add c1) bandwidth capping: b_t  + (-M) * n_t <= 0 */
  GNUNET_asprintf(&name, "c1_%s_%s_%p", GNUNET_i2s(&address->peer), address->plugin, address);
  mlpi->r_c1 = mlp_create_problem_create_constraint (p, name, GLP_UP, 0.0, 0.0);
  GNUNET_free (name);
  /*  c1) set b = 1 coefficient */
  mlp_create_problem_set_value (p, mlpi->r_c1, mlpi->c_b, 1, __LINE__);
  /*  c1) set n = - min (M, quota) coefficient */
  cur_bigm = (double) mlp->pv.quota_out[addr_net_index];
  if (cur_bigm > mlp->pv.BIG_M)
    cur_bigm = (double) mlp->pv.BIG_M;
  mlp_create_problem_set_value (p, mlpi->r_c1, mlpi->c_n, -cur_bigm, __LINE__);

  /* Add constraint c 3) minimum bandwidth
   * b_t + (-n_t * b_min) >= 0
   * */
  GNUNET_asprintf(&name, "c3_%s_%s_%p", GNUNET_i2s(&address->peer), address->plugin, address);
  mlpi->r_c3 = mlp_create_problem_create_constraint (p, name, GLP_LO, 0.0, 0.0);
  GNUNET_free (name);

  /*  c3) set b = 1 coefficient */
  mlp_create_problem_set_value (p, mlpi->r_c3, mlpi->c_b, 1, __LINE__);
  /*  c3) set n = -b_min coefficient */
  mlp_create_problem_set_value (p, mlpi->r_c3, mlpi->c_n, - ((double )mlp->pv.b_min), __LINE__);


  /* Set coefficient entries in invariant rows */

  /* Feasbility */

  /* c 4) minimum connections */
  mlp_create_problem_set_value (p, p->r_c4, mlpi->c_n, 1, __LINE__);
  /* c 2) 1 address peer peer */
  mlp_create_problem_set_value (p, peer->r_c2, mlpi->c_n, 1, __LINE__);
  /* c 10) obey network specific quotas
   * (1)*b_1 + ... + (1)*b_m <= quota_n
   */
  mlp_create_problem_set_value (p, p->r_quota[addr_net_index], mlpi->c_b, 1, __LINE__);

  /* Optimality */
  if (GNUNET_NO == mlp->opt_dbg_feasibility_only)
  {
    /* c 6) maximize diversity */
    mlp_create_problem_set_value (p, p->r_c6, mlpi->c_n, 1, __LINE__);
    /* c 9) relativity */
    if (GNUNET_YES == mlp->opt_dbg_optimize_relativity)
      mlp_create_problem_set_value (p, peer->r_c9, mlpi->c_b, 1, __LINE__);
    /* c 8) utility */
    if (GNUNET_YES == mlp->opt_dbg_optimize_utility)
      mlp_create_problem_set_value (p, p->r_c8, mlpi->c_b, 1, __LINE__);
    /* c 7) Optimize quality */
    /* For all quality metrics, set quality of this address */
    if (GNUNET_YES == mlp->opt_dbg_optimize_quality)
    {
      props = mlp->get_properties (mlp->get_properties_cls, address);
      for (c = 0; c < mlp->pv.m_q; c++)
      {
        if ((props[c] < 1.0) && (props[c] > 2.0))
        {
          fprintf (stderr, "PROP == %.3f \t ", props[c]);
          GNUNET_break (0);
        }
        mlp_create_problem_set_value (p, p->r_q[c], mlpi->c_b, props[c], __LINE__);
      }
    }
  }

  return GNUNET_OK;
}


/**
 * Create the invariant columns c4, c6, c10, c8, c7
 */
static void
mlp_create_problem_add_invariant_rows (struct GAS_MLP_Handle *mlp, struct MLP_Problem *p)
{
  int c;

  /* Feasibility */

  /* Row for c4) minimum connection */
  /* Number of minimum connections is min(|Peers|, n_min) */
  p->r_c4 = mlp_create_problem_create_constraint (p, "c4", GLP_LO, (mlp->pv.n_min > p->num_peers) ? p->num_peers : mlp->pv.n_min, 0.0);

  /* Rows for c 10) Enforce network quotas */
  for (c = 0; c < GNUNET_ATS_NetworkTypeCount; c++)
  {
    char * text;
    GNUNET_asprintf(&text, "c10_quota_ats_%s",
        GNUNET_ATS_print_network_type(mlp->pv.quota_index[c]));
    p->r_quota[c] = mlp_create_problem_create_constraint (p, text, GLP_DB, 0.0, mlp->pv.quota_out[c]);
    GNUNET_free (text);
  }

  /* Optimality */
  if (GNUNET_NO == mlp->opt_dbg_feasibility_only)
  {
    char *name;
    /* Add row for c6) Maximize for diversity */
    if (GNUNET_YES == mlp->opt_dbg_optimize_diversity)
    {
      p->r_c6 = mlp_create_problem_create_constraint (p, "c6", GLP_FX, 0.0, 0.0);
      /* Set c6 ) Setting -D */
      mlp_create_problem_set_value (p, p->r_c6, p->c_d, -1, __LINE__);
    }

    /* Adding rows for c 8) Maximize utility */
    if (GNUNET_YES == mlp->opt_dbg_optimize_utility)
    {
      p->r_c8 = mlp_create_problem_create_constraint (p, "c8", GLP_FX, 0.0, 0.0);
      /* -u */
      mlp_create_problem_set_value (p, p->r_c8, p->c_u, -1, __LINE__);
    }

    /* For all quality metrics:
     * c 7) Maximize quality, austerity */
    if (GNUNET_YES == mlp->opt_dbg_optimize_quality)
    {
      for (c = 0; c < mlp->pv.m_q; c++)
      {
        GNUNET_asprintf(&name, "c7_q%i_%s", c, mlp_ats_to_string(mlp->pv.q[c]));
        p->r_q[c] = mlp_create_problem_create_constraint (p, name, GLP_FX, 0.0, 0.0);
        GNUNET_free (name);
        mlp_create_problem_set_value (p, p->r_q[c], p->c_q[c], -1, __LINE__);
      }
    }
  }
}


/**
 * Create the invariant columns d, u, r, q0 ... qm
 */
static void
mlp_create_problem_add_invariant_columns (struct GAS_MLP_Handle *mlp, struct MLP_Problem *p)
{
  if (GNUNET_NO == mlp->opt_dbg_feasibility_only)
  {
    char *name;
    int c;

    /* Diversity d column  */
    if (GNUNET_YES == mlp->opt_dbg_optimize_diversity)
      p->c_d = mlp_create_problem_create_column (p, "d", GLP_CV, GLP_LO, 0.0, 0.0, mlp->pv.co_D);

    /* Utilization u column  */
    if (GNUNET_YES == mlp->opt_dbg_optimize_utility)
      p->c_u = mlp_create_problem_create_column (p, "u", GLP_CV, GLP_LO, 0.0, 0.0, mlp->pv.co_U);

    /* Relativity r column  */
    if (GNUNET_YES == mlp->opt_dbg_optimize_relativity)
      p->c_r = mlp_create_problem_create_column (p, "r", GLP_CV, GLP_LO, 0.0, 0.0, mlp->pv.co_R);

    /* Quality metric columns */
    if (GNUNET_YES == mlp->opt_dbg_optimize_quality)
    {
      for (c = 0; c < mlp->pv.m_q; c++)
      {
        GNUNET_asprintf (&name, "q_%u", mlp->pv.q[c]);
        p->c_q[c] = mlp_create_problem_create_column (p, name, GLP_CV, GLP_LO, 0.0, 0.0, mlp->pv.co_Q[c]);
        GNUNET_free (name);
      }
    }
  }
}


/**
 * Create the MLP problem
 *
 * @param mlp the MLP handle
 * @return #GNUNET_OK or #GNUNET_SYSERR
 */
static int
mlp_create_problem (struct GAS_MLP_Handle *mlp)
{
  struct MLP_Problem *p = &mlp->p;
  int res = GNUNET_OK;

  GNUNET_assert (p->prob == NULL);
  GNUNET_assert (p->ia == NULL);
  GNUNET_assert (p->ja == NULL);
  GNUNET_assert (p->ar == NULL);
  /* Reset MLP problem struct */

  /* create the glpk problem */
  p->prob = glp_create_prob ();
  GNUNET_assert (NULL != p->prob);
  p->num_peers = mlp_create_problem_count_peers (mlp->requested_peers, mlp->addresses);
  p->num_addresses = mlp_create_problem_count_addresses (mlp->requested_peers, mlp->addresses);

  /* Create problem matrix: 10 * #addresses + #q * #addresses + #q, + #peer + 2 + 1 */
  p->num_elements = (10 * p->num_addresses + mlp->pv.m_q * p->num_addresses +
      mlp->pv.m_q + p->num_peers + 2 + 1);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Rebuilding problem for %u peer(s) and %u addresse(s) and %u quality metrics == %u elements\n",
       p->num_peers,
       p->num_addresses,
       mlp->pv.m_q,
       p->num_elements);

  /* Set a problem name */
  glp_set_prob_name (p->prob, "GNUnet ATS bandwidth distribution");
  /* Set optimization direction to maximize */
  glp_set_obj_dir (p->prob, GLP_MAX);

  /* Create problem matrix */
  /* last +1 caused by glpk index starting with one: [1..elements]*/
  p->ci = 1;
  /* row index */
  p->ia = GNUNET_malloc (p->num_elements * sizeof (int));
  /* column index */
  p->ja = GNUNET_malloc (p->num_elements * sizeof (int));
  /* coefficient */
  p->ar = GNUNET_malloc (p->num_elements * sizeof (double));

  if ((NULL == p->ia) || (NULL == p->ja) || (NULL == p->ar))
  {
      LOG (GNUNET_ERROR_TYPE_ERROR, _("Problem size too large, cannot allocate memory!\n"));
      return GNUNET_SYSERR;
  }

  /* Adding invariant columns */
  mlp_create_problem_add_invariant_columns (mlp, p);

  /* Adding address independent constraint rows */
  mlp_create_problem_add_invariant_rows (mlp, p);

  /* Adding address dependent columns constraint rows */
  GNUNET_CONTAINER_multipeermap_iterate (mlp->addresses,
					 &mlp_create_problem_add_address_information,
					 mlp);

  /* Load the matrix */
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Loading matrix\n");
  glp_load_matrix(p->prob, (p->ci)-1, p->ia, p->ja, p->ar);
  if (GNUNET_YES == mlp->opt_dbg_autoscale_problem)
  {
    glp_scale_prob (p->prob, GLP_SF_AUTO);
  }

  return res;
}


/**
 * Solves the LP problem
 *
 * @param mlp the MLP Handle
 * @return #GNUNET_OK if could be solved, #GNUNET_SYSERR on failure
 */
static int
mlp_solve_lp_problem (struct GAS_MLP_Handle *mlp)
{
  int res = 0;
  int res_status = 0;
  res = glp_simplex(mlp->p.prob, &mlp->control_param_lp);
  if (0 == res)
    LOG(GNUNET_ERROR_TYPE_DEBUG, "Solving LP problem: %s\n",
        mlp_solve_to_string (res));
  else
    LOG(GNUNET_ERROR_TYPE_DEBUG, "Solving LP problem failed: %s\n",
        mlp_solve_to_string (res));

  /* Analyze problem status  */
  res_status = glp_get_status (mlp->p.prob);
  switch (res_status) {
    case GLP_OPT: /* solution is optimal */
      LOG (GNUNET_ERROR_TYPE_INFO,
          "Solving LP problem: %s, %s\n",
          mlp_solve_to_string(res),
          mlp_status_to_string(res_status));
      return GNUNET_OK;
    default:
      LOG (GNUNET_ERROR_TYPE_ERROR,
          "Solving LP problem failed: %s %s\n",
          mlp_solve_to_string(res),
          mlp_status_to_string(res_status));
      return GNUNET_SYSERR;
  }
}


/**
 * Propagates the results when MLP problem was solved
 *
 * @param cls the MLP handle
 * @param key the peer identity
 * @param value the address
 * @return #GNUNET_OK to continue
 */
static int
mlp_propagate_results (void *cls,
		       const struct GNUNET_PeerIdentity *key,
		       void *value)
{
  struct GAS_MLP_Handle *mlp = cls;
  struct ATS_Address *address;
  struct MLP_information *mlpi;
  double mlp_bw_in = MLP_NaN;
  double mlp_bw_out = MLP_NaN;
  double mlp_use = MLP_NaN;

  /* Check if we have to add this peer due to a pending request */
  if (GNUNET_NO == GNUNET_CONTAINER_multipeermap_contains (mlp->requested_peers,
							   key))
  {
    return GNUNET_OK;
  }
  address = value;
  GNUNET_assert (address->solver_information != NULL);
  mlpi = address->solver_information;

  mlp_bw_in = glp_mip_col_val(mlp->p.prob, mlpi->c_b);/* FIXME */
  if (mlp_bw_in > (double) UINT32_MAX)
  {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Overflow in assigned bandwidth, reducing ...\n" );
      mlp_bw_in = (double) UINT32_MAX;
  }
  mlp_bw_out = glp_mip_col_val(mlp->p.prob, mlpi->c_b);
  if (mlp_bw_out > (double) UINT32_MAX)
  {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Overflow in assigned bandwidth, reducing ...\n" );
      mlp_bw_out = (double) UINT32_MAX;
  }
  mlp_use = glp_mip_col_val(mlp->p.prob, mlpi->c_n);

  /*
   * Debug: solution
   * LOG (GNUNET_ERROR_TYPE_INFO, "MLP result address: `%s' `%s' length %u session %u, mlp use %.3f\n",
   *    GNUNET_i2s(&address->peer), address->plugin,
   *    address->addr_len, address->session_id);
   */

  if (GLP_YES == mlp_use)
  {
    /* This address was selected by the solver to be used */
    mlpi->n = GNUNET_YES;
    if (GNUNET_NO == address->active)
    {
            /* Address was not used before, enabling address */
      LOG (GNUNET_ERROR_TYPE_DEBUG, "%s %.2f : enabling address\n",
          (1 == mlp_use) ? "[x]": "[ ]", mlp_bw_out);
      address->active = GNUNET_YES;
      address->assigned_bw_in = mlp_bw_in;
      mlpi->b_in = mlp_bw_in;
      address->assigned_bw_out = mlp_bw_out;
      mlpi->b_out = mlp_bw_out;
      if ((NULL == mlp->exclude_peer) || (0 != memcmp (&address->peer, mlp->exclude_peer, sizeof (address->peer))))
        mlp->bw_changed_cb (mlp->bw_changed_cb_cls, address);
      return GNUNET_OK;
    }
    else if (GNUNET_YES == address->active)
    {
      /* Address was used before, check for bandwidth change */
      if ((mlp_bw_out != address->assigned_bw_out) ||
              (mlp_bw_in != address->assigned_bw_in))
      {
          LOG (GNUNET_ERROR_TYPE_DEBUG, "%s %.2f : bandwidth changed\n",
              (1 == mlp_use) ? "[x]": "[ ]", mlp_bw_out);
          address->assigned_bw_in = mlp_bw_in;
          mlpi->b_in = mlp_bw_in;
          address->assigned_bw_out = mlp_bw_out;
          mlpi->b_out = mlp_bw_out;
          if ((NULL == mlp->exclude_peer) || (0 != memcmp (&address->peer, mlp->exclude_peer, sizeof (address->peer))))
            mlp->bw_changed_cb (mlp->bw_changed_cb_cls, address);
          return GNUNET_OK;
      }
    }
    else
      GNUNET_break (0);
  }
  else if (GLP_NO == mlp_use)
  {
    /* This address was selected by the solver to be not used */
    mlpi->n = GNUNET_NO;
    if (GNUNET_NO == address->active)
    {
      /* Address was not used before, nothing to do */
      LOG (GNUNET_ERROR_TYPE_DEBUG, "%s %.2f : no change\n",
          (1 == mlp_use) ? "[x]": "[ ]", mlp_bw_out);
      return GNUNET_OK;
    }
    else if (GNUNET_YES == address->active)
    {
    /* Address was used before, disabling address */
    LOG (GNUNET_ERROR_TYPE_DEBUG, "%s %.2f : disabling address\n",
        (1 == mlp_use) ? "[x]": "[ ]", mlp_bw_out);
      address->active = GNUNET_NO;
      /* Set bandwidth to 0 */
      address->assigned_bw_in = 0;
      mlpi->b_in = 0;
      address->assigned_bw_out = 0;
      mlpi->b_out = 0;
      return GNUNET_OK;
    }
    else
      GNUNET_break (0);
  }
  else
    GNUNET_break (0);

  return GNUNET_OK;
}


static void
notify (struct GAS_MLP_Handle *mlp,
	enum GAS_Solver_Operation op,
	enum GAS_Solver_Status stat,
	enum GAS_Solver_Additional_Information add)
{
  if (NULL != mlp->env->info_cb)
    mlp->env->info_cb (mlp->env->info_cb_cls, op, stat, add);
}


static void
mlp_branch_and_cut_cb (glp_tree *tree, void *info)
{
  struct GAS_MLP_Handle *mlp = info;
  double mlp_obj = 0;

  switch (glp_ios_reason (tree))
  {
    case GLP_ISELECT:
        /* Do nothing here */
      break;
    case GLP_IPREPRO:
        /* Do nothing here */
      break;
    case GLP_IROWGEN:
        /* Do nothing here */
      break;
    case GLP_IHEUR:
        /* Do nothing here */
      break;
    case GLP_ICUTGEN:
        /* Do nothing here */
      break;
    case GLP_IBRANCH:
        /* Do nothing here */
      break;
    case GLP_IBINGO:
        /* A better solution was found  */
      mlp->ps.mlp_gap = glp_ios_mip_gap (tree);
      mlp_obj = glp_mip_obj_val (mlp->p.prob);
      mlp->ps.lp_mlp_gap = (abs(mlp_obj - mlp->ps.lp_objective_value)) / (abs(mlp_obj) + DBL_EPSILON);

      LOG (GNUNET_ERROR_TYPE_INFO,
          "Found better integer solution, current gaps: %.3f <= %.3f, %.3f <= %.3f\n",
          mlp->ps.mlp_gap, mlp->pv.mip_gap,
          mlp->ps.lp_mlp_gap, mlp->pv.lp_mip_gap);

      if (mlp->ps.mlp_gap <= mlp->pv.mip_gap)
      {
        LOG (GNUNET_ERROR_TYPE_INFO,
          "Current LP/MLP gap of %.3f smaller than tolerated gap of %.3f, terminating search\n",
          mlp->ps.lp_mlp_gap, mlp->pv.lp_mip_gap);
        glp_ios_terminate (tree);
      }

      if (mlp->ps.lp_mlp_gap <= mlp->pv.lp_mip_gap)
      {
        LOG (GNUNET_ERROR_TYPE_INFO,
          "Current LP/MLP gap of %.3f smaller than tolerated gap of %.3f, terminating search\n",
          mlp->ps.lp_mlp_gap, mlp->pv.lp_mip_gap);
        glp_ios_terminate (tree);
      }

      break;
    default:
      break;
  }
  //GNUNET_break (0);
}


/**
 * Solves the MLP problem
 *
 * @param solver the MLP Handle
 * @return #GNUNET_OK if could be solved, #GNUNET_SYSERR on failure
 */
static int
GAS_mlp_solve_problem (void *solver)
{
  struct GAS_MLP_Handle *mlp = solver;
  char *filename;
  int res_lp = 0;
  int mip_res = 0;
  int mip_status = 0;

  struct GNUNET_TIME_Absolute start_total;
  struct GNUNET_TIME_Absolute start_cur_op;
  struct GNUNET_TIME_Relative dur_total;
  struct GNUNET_TIME_Relative dur_setup;
  struct GNUNET_TIME_Relative dur_lp;
  struct GNUNET_TIME_Relative dur_mlp;

  GNUNET_assert(NULL != solver);

  if (GNUNET_YES == mlp->stat_bulk_lock)
    {
      mlp->stat_bulk_requests++;
      return GNUNET_NO;
    }
  notify(mlp, GAS_OP_SOLVE_START, GAS_STAT_SUCCESS,
      (GNUNET_YES == mlp->stat_mlp_prob_changed) ? GAS_INFO_FULL : GAS_INFO_UPDATED);
  start_total = GNUNET_TIME_absolute_get();

  if (0 == GNUNET_CONTAINER_multipeermap_size(mlp->requested_peers))
    {
      notify(mlp, GAS_OP_SOLVE_STOP, GAS_STAT_SUCCESS, GAS_INFO_NONE);
      return GNUNET_OK; /* No pending requests */
    }
  if (0 == GNUNET_CONTAINER_multipeermap_size(mlp->addresses))
    {
      notify(mlp, GAS_OP_SOLVE_STOP, GAS_STAT_SUCCESS, GAS_INFO_NONE);
      return GNUNET_OK; /* No addresses available */
    }

  if ((GNUNET_NO == mlp->stat_mlp_prob_changed)
      && (GNUNET_NO == mlp->stat_mlp_prob_updated))
    {
      LOG(GNUNET_ERROR_TYPE_DEBUG, "No changes to problem\n");
      notify(mlp, GAS_OP_SOLVE_STOP, GAS_STAT_SUCCESS, GAS_INFO_NONE);
      return GNUNET_OK;
    }
  if (GNUNET_YES == mlp->stat_mlp_prob_changed)
  {
    LOG(GNUNET_ERROR_TYPE_DEBUG, "Problem size changed, rebuilding\n");
    notify(mlp, GAS_OP_SOLVE_SETUP_START, GAS_STAT_SUCCESS, GAS_INFO_FULL);
    mlp_delete_problem(mlp);
    if (GNUNET_SYSERR == mlp_create_problem(mlp))
      {
        notify(mlp, GAS_OP_SOLVE_SETUP_STOP, GAS_STAT_FAIL, GAS_INFO_FULL);
        return GNUNET_SYSERR;
      }
    notify(mlp, GAS_OP_SOLVE_SETUP_STOP, GAS_STAT_SUCCESS, GAS_INFO_FULL);
    if (GNUNET_NO == mlp->opt_dbg_intopt_presolver)
    {
    mlp->control_param_lp.presolve = GLP_YES; /* LP presolver, we need lp solution */
    mlp->control_param_mlp.presolve = GNUNET_NO; /* No presolver, we have LP solution */
    }
    else
    {
      mlp->control_param_lp.presolve = GNUNET_NO; /* LP presolver, we need lp solution */
      mlp->control_param_mlp.presolve = GLP_YES; /* No presolver, we have LP solution */
      dur_lp = GNUNET_TIME_UNIT_ZERO;
    }
  }
  else
  {
    LOG(GNUNET_ERROR_TYPE_DEBUG, "Problem was updated, resolving\n");
  }

  /* Reset solution info */
  mlp->ps.lp_objective_value = 0.0;
  mlp->ps.mlp_gap = 1.0;
  mlp->ps.mlp_objective_value = 0.0;
  mlp->ps.lp_mlp_gap = 0.0;

  dur_setup = GNUNET_TIME_absolute_get_duration (start_total);

  /* Run LP solver */
  if (GNUNET_NO == mlp->opt_dbg_intopt_presolver)
  {
    notify(mlp, GAS_OP_SOLVE_MLP_LP_START, GAS_STAT_SUCCESS,
        (GNUNET_YES == mlp->stat_mlp_prob_changed) ? GAS_INFO_FULL : GAS_INFO_UPDATED);
    LOG(GNUNET_ERROR_TYPE_DEBUG,
        "Running LP solver %s\n",
        (GLP_YES == mlp->control_param_lp.presolve)? "with presolver": "without presolver");
    start_cur_op = GNUNET_TIME_absolute_get();

    /* Solve LP */
    /* Only for debugging:
     * Always use LP presolver:
     * mlp->control_param_lp.presolve = GLP_YES; */
    res_lp = mlp_solve_lp_problem(mlp);
    if (GNUNET_OK == res_lp)
    {
        mlp->ps.lp_objective_value = glp_get_obj_val (mlp->p.prob);
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "LP solution was: %.3f\n",
             mlp->ps.lp_objective_value);
    }

    dur_lp = GNUNET_TIME_absolute_get_duration (start_cur_op);
    notify(mlp, GAS_OP_SOLVE_MLP_LP_STOP,
        (GNUNET_OK == res_lp) ? GAS_STAT_SUCCESS : GAS_STAT_FAIL,
        (GNUNET_YES == mlp->stat_mlp_prob_changed) ? GAS_INFO_FULL : GAS_INFO_UPDATED);
  }

  if (GNUNET_YES == mlp->opt_dbg_intopt_presolver)
    res_lp = GNUNET_OK;

  /* Run MLP solver */
  if ((GNUNET_OK == res_lp) || (GNUNET_YES == mlp->opt_dbg_intopt_presolver))
  {
    LOG(GNUNET_ERROR_TYPE_DEBUG, "Running MLP solver \n");
    notify(mlp, GAS_OP_SOLVE_MLP_MLP_START, GAS_STAT_SUCCESS,
        (GNUNET_YES == mlp->stat_mlp_prob_changed) ? GAS_INFO_FULL : GAS_INFO_UPDATED);
    start_cur_op = GNUNET_TIME_absolute_get();

    /* Solve MIP */

    /* Only for debugging, always use LP presolver */
    if (GNUNET_YES == mlp->opt_dbg_intopt_presolver)
      mlp->control_param_mlp.presolve = GNUNET_YES;

    mip_res = glp_intopt (mlp->p.prob, &mlp->control_param_mlp);
    switch (mip_res)
    {
        case 0:
          /* Successful */
          LOG (GNUNET_ERROR_TYPE_INFO,
               "Solving MLP problem: %s\n",
               mlp_solve_to_string (mip_res));
          break;
        case GLP_ETMLIM: /* Time limit reached */
        case GLP_EMIPGAP: /* MIP gap tolerance limit reached */
        case GLP_ESTOP: /* Solver was instructed to stop*/
          /* Semi-successful */
          LOG (GNUNET_ERROR_TYPE_INFO,
               "Solving MLP problem solution was interupted: %s\n",
               mlp_solve_to_string (mip_res));
          break;
        case GLP_EBOUND:
        case GLP_EROOT:
        case GLP_ENOPFS:
        case GLP_ENODFS:
        case GLP_EFAIL:
        default:
         /* Fail */
          LOG (GNUNET_ERROR_TYPE_INFO,
              "Solving MLP problem failed: %s\n",
              mlp_solve_to_string (mip_res));
        break;
    }

    /* Analyze problem status  */
    mip_status = glp_mip_status(mlp->p.prob);
    switch (mip_status)
    {
      case GLP_OPT: /* solution is optimal */
        LOG (GNUNET_ERROR_TYPE_WARNING,
            "Solution of MLP problem is optimal: %s, %s\n",
            mlp_solve_to_string (mip_res),
            mlp_status_to_string (mip_status));
        mip_res = GNUNET_OK;
        break;
      case GLP_FEAS: /* solution is feasible but not proven optimal */

        if ( (mlp->ps.mlp_gap <= mlp->pv.mip_gap) ||
             (mlp->ps.lp_mlp_gap <= mlp->pv.lp_mip_gap) )
        {
          LOG (GNUNET_ERROR_TYPE_INFO,
                 "Solution of MLP problem is feasible and solution within gap constraints: %s, %s\n",
                 mlp_solve_to_string (mip_res),
                 mlp_status_to_string (mip_status));
          mip_res = GNUNET_OK;
        }
        else
        {
          LOG (GNUNET_ERROR_TYPE_WARNING,
               "Solution of MLP problem is feasible but solution not within gap constraints: %s, %s\n",
               mlp_solve_to_string (mip_res),
               mlp_status_to_string (mip_status));
          mip_res = GNUNET_SYSERR;
        }
        break;
      case GLP_UNDEF: /* Solution undefined */
      case GLP_NOFEAS: /* No feasible solution */
      default:
        LOG (GNUNET_ERROR_TYPE_ERROR,
            "Solving MLP problem failed: %s %s\n",
            mlp_solve_to_string (mip_res),
            mlp_status_to_string (mip_status));
        mip_res = GNUNET_SYSERR;
        break;
    }

    dur_mlp = GNUNET_TIME_absolute_get_duration (start_cur_op);
    dur_total = GNUNET_TIME_absolute_get_duration (start_total);

    notify(mlp, GAS_OP_SOLVE_MLP_MLP_STOP,
        (GNUNET_OK == mip_res) ? GAS_STAT_SUCCESS : GAS_STAT_FAIL,
        (GNUNET_YES == mlp->stat_mlp_prob_changed) ? GAS_INFO_FULL : GAS_INFO_UPDATED);
  }
  else
  {
    /* Do not execute mip solver since lp solution is invalid */
    dur_mlp = GNUNET_TIME_UNIT_ZERO;
    dur_total = GNUNET_TIME_absolute_get_duration (start_total);

    notify(mlp, GAS_OP_SOLVE_MLP_MLP_STOP, GAS_STAT_FAIL,
        (GNUNET_YES == mlp->stat_mlp_prob_changed) ? GAS_INFO_FULL : GAS_INFO_UPDATED);
    mip_res = GNUNET_SYSERR;
  }

  /* Notify about end */
  notify(mlp, GAS_OP_SOLVE_STOP,
      ((GNUNET_OK == mip_res) && (GNUNET_OK == mip_res)) ? GAS_STAT_SUCCESS : GAS_STAT_FAIL,
      (GNUNET_YES == mlp->stat_mlp_prob_changed) ? GAS_INFO_FULL : GAS_INFO_UPDATED);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
      "Execution time for %s solve: (total/setup/lp/mlp) : %llu %llu %llu %llu\n",
      (GNUNET_YES == mlp->stat_mlp_prob_changed) ? "full" : "updated",
      (unsigned long long) dur_total.rel_value_us,
      (unsigned long long) dur_setup.rel_value_us,
      (unsigned long long) dur_lp.rel_value_us,
      (unsigned long long) dur_mlp.rel_value_us);

  /* Save stats */
  mlp->ps.lp_res = res_lp;
  mlp->ps.mip_res = mip_res;
  mlp->ps.lp_presolv = mlp->control_param_lp.presolve;
  mlp->ps.mip_presolv = mlp->control_param_mlp.presolve;
  mlp->ps.p_cols = glp_get_num_cols(mlp->p.prob);
  mlp->ps.p_rows = glp_get_num_rows(mlp->p.prob);
  mlp->ps.p_elements = mlp->p.num_elements;

  /* Propagate result*/
  notify (mlp, GAS_OP_SOLVE_UPDATE_NOTIFICATION_START,
      (GNUNET_OK == res_lp) && (GNUNET_OK == mip_res) ? GAS_STAT_SUCCESS : GAS_STAT_FAIL,
      GAS_INFO_NONE);
  if ((GNUNET_OK == res_lp) && (GNUNET_OK == mip_res))
    {
      GNUNET_CONTAINER_multipeermap_iterate(mlp->addresses,
          &mlp_propagate_results, mlp);
    }
  notify (mlp, GAS_OP_SOLVE_UPDATE_NOTIFICATION_STOP,
      (GNUNET_OK == res_lp) && (GNUNET_OK == mip_res) ? GAS_STAT_SUCCESS : GAS_STAT_FAIL,
      GAS_INFO_NONE);

  struct GNUNET_TIME_Absolute time = GNUNET_TIME_absolute_get();
  if ( (GNUNET_YES == mlp->opt_dump_problem_all) ||
      (mlp->opt_dump_problem_on_fail && ((GNUNET_OK != res_lp) || (GNUNET_OK != mip_res))) )
    {
      /* Write problem to disk */
      switch (mlp->opt_log_format) {
        case MLP_CPLEX:
          GNUNET_asprintf(&filename, "problem_p_%u_a%u_%llu.cplex", mlp->p.num_peers,
              mlp->p.num_addresses, time.abs_value_us);
          glp_write_lp (mlp->p.prob, NULL, filename);
          break;
        case MLP_GLPK:
          GNUNET_asprintf(&filename, "problem_p_%u_a%u_%llu.glpk", mlp->p.num_peers,
              mlp->p.num_addresses, time.abs_value_us);
          glp_write_prob (mlp->p.prob, 0, filename);
          break;
        case MLP_MPS:
          GNUNET_asprintf(&filename, "problem_p_%u_a%u_%llu.mps", mlp->p.num_peers,
              mlp->p.num_addresses, time.abs_value_us);
          glp_write_mps (mlp->p.prob, GLP_MPS_FILE, NULL, filename);
          break;
        default:
          break;
      }
      LOG(GNUNET_ERROR_TYPE_ERROR, "Dumped problem to file: `%s' \n", filename);
      GNUNET_free(filename);
    }
  if ( (mlp->opt_dump_solution_all) ||
      (mlp->opt_dump_solution_on_fail && ((GNUNET_OK != res_lp) || (GNUNET_OK != mip_res))) )
  {
    /* Write solution to disk */
    GNUNET_asprintf(&filename, "problem_p_%u_a%u_%llu.sol", mlp->p.num_peers,
        mlp->p.num_addresses, time.abs_value_us);
    glp_print_mip(mlp->p.prob, filename);
    LOG(GNUNET_ERROR_TYPE_ERROR, "Dumped solution to file: `%s' \n", filename);
    GNUNET_free(filename);
  }

  /* Reset change and update marker */
  mlp->control_param_lp.presolve = GLP_NO;
  mlp->stat_mlp_prob_updated = GNUNET_NO;
  mlp->stat_mlp_prob_changed = GNUNET_NO;

  if ((GNUNET_OK == res_lp) && (GNUNET_OK == mip_res))
    return GNUNET_OK;
  else
    return GNUNET_SYSERR;
}

/**
 * Add a single address to the solve
 *
 * @param solver the solver Handle
 * @param address the address to add
 * @param network network type of this address
 */
static void
GAS_mlp_address_add (void *solver,
                    struct ATS_Address *address,
                    uint32_t network)
{
  struct GAS_MLP_Handle *mlp = solver;

  GNUNET_assert (NULL != solver);
  GNUNET_assert (NULL != address);

  if (GNUNET_ATS_NetworkTypeCount <= network)
  {
   GNUNET_break (0);
   return;
  }

  if (NULL == address->solver_information)
  {
      address->solver_information = GNUNET_new (struct MLP_information);
  }
  else
      LOG (GNUNET_ERROR_TYPE_ERROR,
	   _("Adding address for peer `%s' multiple times\n"),
	   GNUNET_i2s(&address->peer));

  /* Is this peer included in the problem? */
  if (NULL ==
      GNUNET_CONTAINER_multipeermap_get (mlp->requested_peers,
                                         &address->peer))
  {
    /* FIXME: should this be an error? */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Adding address for peer `%s' without address request\n",
         GNUNET_i2s(&address->peer));
    return;
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Adding address for peer `%s' with address request \n",
       GNUNET_i2s(&address->peer));
  /* Problem size changed: new address for peer with pending request */
  mlp->stat_mlp_prob_changed = GNUNET_YES;
  if (GNUNET_YES == mlp->opt_mlp_auto_solve)
    GAS_mlp_solve_problem (solver);
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
static void
GAS_mlp_address_property_changed (void *solver,
                                  struct ATS_Address *address,
                                  uint32_t type,
                                  uint32_t abs_value,
                                  double rel_value)
{
  struct MLP_information *mlpi = address->solver_information;
  struct GAS_MLP_Handle *mlp = solver;
  int c1;
  int type_index;

  GNUNET_assert (NULL != solver);
  GNUNET_assert (NULL != address);

  if (NULL == mlpi)
  {
      LOG (GNUNET_ERROR_TYPE_INFO,
          _("Updating address property `%s' for peer `%s' %p not added before\n"),
          GNUNET_ATS_print_property_type (type),
          GNUNET_i2s(&address->peer),
          address);
      GNUNET_break (0);
      return;
  }

  if (NULL ==
      GNUNET_CONTAINER_multipeermap_get (mlp->requested_peers,
                                         &address->peer))
  {
    /* Peer is not requested, so no need to update problem */
    return;
  }
  LOG (GNUNET_ERROR_TYPE_INFO, "Updating property `%s' address for peer `%s' to abs %llu rel %.3f\n",
      GNUNET_ATS_print_property_type (type),
      GNUNET_i2s(&address->peer),
      abs_value,
      rel_value);

  if (GNUNET_YES == mlp->opt_dbg_feasibility_only)
    return;

  /* Find row index */
  type_index = -1;
  for (c1 = 0; c1 < mlp->pv.m_q; c1++)
  {
    if (type == mlp->pv.q[c1])
    {
      type_index = c1;
      break;
    }
  }
  if (-1 == type_index)
  {
    GNUNET_break (0);
    return; /* quality index not found */
  }

  /* Update c7) [r_q[index]][c_b] = f_q * q_averaged[type_index] */
  if (GNUNET_YES == mlp_create_problem_update_value (&mlp->p,
      mlp->p.r_q[type_index], mlpi->c_b, rel_value, __LINE__))
  {
    mlp->stat_mlp_prob_updated = GNUNET_YES;
    if (GNUNET_YES == mlp->opt_mlp_auto_solve)
      GAS_mlp_solve_problem (solver);
  }

}


/**
 * Find the active address in the set of addresses of a peer
 * @param cls destination
 * @param key peer id
 * @param value address
 * @return #GNUNET_OK
 */
static int
mlp_get_preferred_address_it (void *cls,
			      const struct GNUNET_PeerIdentity *key,
			      void *value)
{
  static int counter = 0;
  struct ATS_Address **aa = cls;
  struct ATS_Address *addr = value;
  struct MLP_information *mlpi = addr->solver_information;

  if (mlpi == NULL)
    return GNUNET_YES;

  /*
   * Debug output
   * GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
   *           "MLP [%u] Peer `%s' %s length %u session %u active %s mlp active %s\n",
   *           counter, GNUNET_i2s (&addr->peer), addr->plugin, addr->addr_len, addr->session_id,
   *           (GNUNET_YES == addr->active) ? "active" : "inactive",
   *           (GNUNET_YES == mlpi->n) ? "active" : "inactive");
   */

  if (GNUNET_YES == mlpi->n)
  {

    (*aa) = addr;
    (*aa)->assigned_bw_in = mlpi->b_in;
    (*aa)->assigned_bw_out = mlpi->b_out;
    return GNUNET_NO;
  }
  counter++;
  return GNUNET_YES;
}


static double
get_peer_pref_value (struct GAS_MLP_Handle *mlp,
                     const struct GNUNET_PeerIdentity *peer)
{
  double res;
  const double *preferences = NULL;
  int c;
  preferences = mlp->get_preferences (mlp->get_preferences_cls, peer);

  res = 0.0;
  for (c = 0; c < GNUNET_ATS_PreferenceCount; c++)
  {
    if (c != GNUNET_ATS_PREFERENCE_END)
    {
      /* fprintf (stderr, "VALUE[%u] %s %.3f \n",
       *        c, GNUNET_i2s (&cur->addr->peer), t[c]); */
      res += preferences[c];
    }
  }

  res /= (GNUNET_ATS_PreferenceCount -1);
  res += 1.0;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Peer preference for peer  `%s' == %.2f\n",
       GNUNET_i2s(peer), res);

  return res;
}


/**
 * Get the preferred address for a specific peer
 *
 * @param solver the MLP Handle
 * @param peer the peer
 * @return suggested address
 */
static const struct ATS_Address *
GAS_mlp_get_preferred_address (void *solver,
                               const struct GNUNET_PeerIdentity *peer)
{
  struct GAS_MLP_Handle *mlp = solver;
  struct ATS_Peer *p;
  struct ATS_Address *res;

  GNUNET_assert (NULL != solver);
  GNUNET_assert (NULL != peer);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Getting preferred address for `%s'\n",
      GNUNET_i2s (peer));

  /* Is this peer included in the problem? */
  if (NULL ==
      GNUNET_CONTAINER_multipeermap_get (mlp->requested_peers,
                                         peer))
    {
      LOG (GNUNET_ERROR_TYPE_INFO, "Adding peer `%s' to list of requested_peers with requests\n",
          GNUNET_i2s (peer));

      p = GNUNET_new (struct ATS_Peer);
      p->id = (*peer);
      p->f = get_peer_pref_value (mlp, peer);
      GNUNET_CONTAINER_multipeermap_put (mlp->requested_peers,
					 peer, p,
					 GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);

      /* Added new peer, we have to rebuild problem before solving */
      mlp->stat_mlp_prob_changed = GNUNET_YES;

      if ((GNUNET_YES == mlp->opt_mlp_auto_solve)&&
          (GNUNET_YES == GNUNET_CONTAINER_multipeermap_contains(mlp->addresses,
								peer)))
      {
        mlp->exclude_peer = peer;
        GAS_mlp_solve_problem (mlp);
        mlp->exclude_peer = NULL;
      }
  }
  /* Get prefered address */
  res = NULL;
  GNUNET_CONTAINER_multipeermap_get_multiple (mlp->addresses, peer,
                                              &mlp_get_preferred_address_it, &res);
  return res;
}


/**
 * Deletes a single address in the MLP problem
 *
 * The MLP problem has to be recreated and the problem has to be resolved
 *
 * @param solver the MLP Handle
 * @param address the address to delete
 * @param session_only delete only session not whole address
 */
static void
GAS_mlp_address_delete (void *solver,
			struct ATS_Address *address,
			int session_only)
{
  struct GAS_MLP_Handle *mlp = solver;
  struct MLP_information *mlpi;
  int was_active;

  GNUNET_assert (NULL != solver);
  GNUNET_assert (NULL != address);

  mlpi = address->solver_information;
  if ((GNUNET_NO == session_only) && (NULL != mlpi))
  {
    /* Remove full address */
    GNUNET_free (mlpi);
    address->solver_information = NULL;
  }
  was_active = address->active;
  address->active = GNUNET_NO;
  address->assigned_bw_in = 0;
  address->assigned_bw_out = 0;

  /* Is this peer included in the problem? */
  if (NULL ==
      GNUNET_CONTAINER_multipeermap_get (mlp->requested_peers,
                                         &address->peer))
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         "Deleting %s for peer `%s' without address request \n",
         (session_only == GNUNET_YES) ? "session" : "address",
         GNUNET_i2s(&address->peer));
    return;
  }
  LOG (GNUNET_ERROR_TYPE_INFO, "Deleting %s for peer `%s' with address request \n",
      (session_only == GNUNET_YES) ? "session" : "address",
      GNUNET_i2s(&address->peer));

  /* Problem size changed: new address for peer with pending request */
  mlp->stat_mlp_prob_changed = GNUNET_YES;
  if (GNUNET_YES == mlp->opt_mlp_auto_solve)
  {
    GAS_mlp_solve_problem (solver);
  }
  if (GNUNET_YES == was_active)
  {
    if (NULL == GAS_mlp_get_preferred_address (solver, &address->peer))
    {
      /* No alternative address, disconnecting peer */
      mlp->bw_changed_cb (mlp->bw_changed_cb_cls, address);
    }
  }

  return;
}


/**
 * Start a bulk operation
 *
 * @param solver the solver
 */
static void
GAS_mlp_bulk_start (void *solver)
{
  struct GAS_MLP_Handle *s = solver;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Locking solver for bulk operation ...\n");
  GNUNET_assert (NULL != solver);
  s->stat_bulk_lock ++;
}


static void
GAS_mlp_bulk_stop (void *solver)
{
  struct GAS_MLP_Handle *s = solver;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Unlocking solver from bulk operation ...\n");
  GNUNET_assert (NULL != solver);

  if (s->stat_bulk_lock < 1)
  {
    GNUNET_break (0);
    return;
  }
  s->stat_bulk_lock --;

  if (0 < s->stat_bulk_requests)
  {
    GAS_mlp_solve_problem (solver);
    s->stat_bulk_requests= 0;
  }
}



/**
 * Stop notifying about address and bandwidth changes for this peer
 *
 * @param solver the MLP handle
 * @param peer the peer
 */
static void
GAS_mlp_stop_get_preferred_address (void *solver,
                                     const struct GNUNET_PeerIdentity *peer)
{
  struct GAS_MLP_Handle *mlp = solver;
  struct ATS_Peer *p = NULL;

  GNUNET_assert (NULL != solver);
  GNUNET_assert (NULL != peer);
  if (NULL != (p = GNUNET_CONTAINER_multipeermap_get (mlp->requested_peers, peer)))
  {
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multipeermap_remove (mlp->requested_peers, peer, p));
    GNUNET_free (p);

    mlp->stat_mlp_prob_changed = GNUNET_YES;
    if (GNUNET_YES == mlp->opt_mlp_auto_solve)
    {
      GAS_mlp_solve_problem (solver);
    }
  }
}


/**
 * Changes the preferences for a peer in the MLP problem
 *
 * @param solver the MLP Handle
 * @param peer the peer
 * @param kind the kind to change the preference
 * @param pref_rel the relative score
 */
static void
GAS_mlp_address_change_preference (void *solver,
                   const struct GNUNET_PeerIdentity *peer,
                   enum GNUNET_ATS_PreferenceKind kind,
                   double pref_rel)
{
  struct GAS_MLP_Handle *mlp = solver;
  struct ATS_Peer *p;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Changing preference for address for peer `%s' to %.2f\n",
      GNUNET_i2s(peer), pref_rel);

  GNUNET_STATISTICS_update (mlp->stats,"# LP address preference changes", 1, GNUNET_NO);
  /* Update the constraints with changed preferences */



  /* Update relativity constraint c9 */
  if (NULL == (p = GNUNET_CONTAINER_multipeermap_get (mlp->requested_peers, peer)))
  {
    LOG (GNUNET_ERROR_TYPE_INFO, "Updating preference for unknown peer `%s'\n", GNUNET_i2s(peer));
    return;
  }

  if (GNUNET_NO == mlp->opt_dbg_feasibility_only)
  {
    p->f = get_peer_pref_value (mlp, peer);
    mlp_create_problem_update_value (&mlp->p, p->r_c9, mlp->p.c_r, -p->f, __LINE__);

    /* Problem size changed: new address for peer with pending request */
    mlp->stat_mlp_prob_updated = GNUNET_YES;
    if (GNUNET_YES == mlp->opt_mlp_auto_solve)
      GAS_mlp_solve_problem (solver);
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
static void
GAS_mlp_address_preference_feedback (void *solver,
                                    void *application,
                                    const struct GNUNET_PeerIdentity *peer,
                                    const struct GNUNET_TIME_Relative scope,
                                    enum GNUNET_ATS_PreferenceKind kind,
                                    double score)
{
  struct GAS_PROPORTIONAL_Handle *s = solver;
  GNUNET_assert (NULL != solver);
  GNUNET_assert (NULL != peer);

  GNUNET_assert (NULL != s);
}


static int
mlp_free_peers (void *cls,
		const struct GNUNET_PeerIdentity *key, void *value)
{
  struct GNUNET_CONTAINER_MultiPeerMap *map = cls;
  struct ATS_Peer *p = value;

  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (map, key, value));
  GNUNET_free (p);

  return GNUNET_OK;
}


/**
 * Shutdown the MLP problem solving component
 *
 * @param cls the solver handle
 * @return NULL
 */
void *
libgnunet_plugin_ats_mlp_done (void *cls)
{
  struct GAS_MLP_Handle *mlp = cls;
  GNUNET_assert (mlp != NULL);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Shutting down mlp solver\n");
  mlp_delete_problem (mlp);

  GNUNET_CONTAINER_multipeermap_iterate (mlp->requested_peers,
					 &mlp_free_peers,
					 mlp->requested_peers);
  GNUNET_CONTAINER_multipeermap_destroy (mlp->requested_peers);
  mlp->requested_peers = NULL;

  /* Clean up GLPK environment */
  glp_free_env();
  GNUNET_free (mlp);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Shutdown down of mlp solver complete\n");
  return NULL;
}


void *
libgnunet_plugin_ats_mlp_init (void *cls)
{
  struct GNUNET_ATS_PluginEnvironment *env = cls;
  struct GAS_MLP_Handle * mlp = GNUNET_new (struct GAS_MLP_Handle);

  float f_tmp;
  unsigned long long tmp;
  unsigned int b_min;
  unsigned int n_min;
  int c;
  int c2;
  int found;
  char *outputformat;

  struct GNUNET_TIME_Relative max_duration;
  long long unsigned int max_iterations;

  GNUNET_assert (NULL != env->cfg);
  GNUNET_assert (NULL != env->addresses);
  GNUNET_assert (NULL != env->bandwidth_changed_cb);
  GNUNET_assert (NULL != env->get_preferences);
  GNUNET_assert (NULL != env->get_property);

  /* Init GLPK environment */
  int res = glp_init_env();
  switch (res) {
    case 0:
      LOG (GNUNET_ERROR_TYPE_DEBUG, "GLPK: `%s'\n",
          "initialization successful");
      break;
    case 1:
      LOG (GNUNET_ERROR_TYPE_DEBUG, "GLPK: `%s'\n",
          "environment is already initialized");
      break;
    case 2:
      LOG (GNUNET_ERROR_TYPE_ERROR, "Could not init GLPK: `%s'\n",
          "initialization failed (insufficient memory)");
      GNUNET_free(mlp);
      return NULL;
      break;
    case 3:
      LOG (GNUNET_ERROR_TYPE_ERROR, "Could not init GLPK: `%s'\n",
          "initialization failed (unsupported programming model)");
      GNUNET_free(mlp);
      return NULL;
      break;
    default:
      break;
  }

  mlp->opt_dump_problem_all = GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
     "ats", "MLP_DUMP_PROBLEM_ALL");
  if (GNUNET_SYSERR == mlp->opt_dump_problem_all)
   mlp->opt_dump_problem_all = GNUNET_NO;

  mlp->opt_dump_solution_all = GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
     "ats", "MLP_DUMP_SOLUTION_ALL");
  if (GNUNET_SYSERR == mlp->opt_dump_solution_all)
   mlp->opt_dump_solution_all = GNUNET_NO;

  mlp->opt_dump_problem_on_fail = GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
     "ats", "MLP_DUMP_PROBLEM_ON_FAIL");
  if (GNUNET_SYSERR == mlp->opt_dump_problem_on_fail)
   mlp->opt_dump_problem_on_fail = GNUNET_NO;

  mlp->opt_dump_solution_on_fail = GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
     "ats", "MLP_DUMP_SOLUTION_ON_FAIL");
  if (GNUNET_SYSERR == mlp->opt_dump_solution_on_fail)
   mlp->opt_dump_solution_on_fail = GNUNET_NO;

  mlp->opt_dbg_glpk_verbose = GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
     "ats", "MLP_DBG_GLPK_VERBOSE");
  if (GNUNET_SYSERR == mlp->opt_dbg_glpk_verbose)
   mlp->opt_dbg_glpk_verbose = GNUNET_NO;

  mlp->opt_dbg_feasibility_only = GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
     "ats", "MLP_DBG_FEASIBILITY_ONLY");
  if (GNUNET_SYSERR == mlp->opt_dbg_feasibility_only)
   mlp->opt_dbg_feasibility_only = GNUNET_NO;
  if (GNUNET_YES == mlp->opt_dbg_feasibility_only)
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "MLP solver is configured to check feasibility only!\n");

  mlp->opt_dbg_autoscale_problem = GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
     "ats", "MLP_DBG_AUTOSCALE_PROBLEM");
  if (GNUNET_SYSERR == mlp->opt_dbg_autoscale_problem)
   mlp->opt_dbg_autoscale_problem = GNUNET_NO;
  if (GNUNET_YES == mlp->opt_dbg_autoscale_problem)
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "MLP solver is configured automatically scale the problem!\n");

  mlp->opt_dbg_intopt_presolver = GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
     "ats", "MLP_DBG_INTOPT_PRESOLVE");
  if (GNUNET_SYSERR == mlp->opt_dbg_intopt_presolver)
   mlp->opt_dbg_intopt_presolver = GNUNET_NO;
  if (GNUNET_YES == mlp->opt_dbg_intopt_presolver)
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "MLP solver is configured use the mlp presolver\n");

  mlp->opt_dbg_optimize_diversity = GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
     "ats", "MLP_DBG_OPTIMIZE_DIVERSITY");
  if (GNUNET_SYSERR == mlp->opt_dbg_optimize_diversity)
   mlp->opt_dbg_optimize_diversity = GNUNET_YES;
  if (GNUNET_NO == mlp->opt_dbg_optimize_diversity)
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "MLP solver is not optimizing for diversity\n");

  mlp->opt_dbg_optimize_relativity= GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
     "ats", "MLP_DBG_OPTIMIZE_RELATIVITY");
  if (GNUNET_SYSERR == mlp->opt_dbg_optimize_relativity)
   mlp->opt_dbg_optimize_relativity = GNUNET_YES;
  if (GNUNET_NO == mlp->opt_dbg_optimize_relativity)
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "MLP solver is not optimizing for relativity\n");

  mlp->opt_dbg_optimize_quality = GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
     "ats", "MLP_DBG_OPTIMIZE_QUALITY");
  if (GNUNET_SYSERR == mlp->opt_dbg_optimize_quality)
   mlp->opt_dbg_optimize_quality = GNUNET_YES;
  if (GNUNET_NO == mlp->opt_dbg_optimize_quality)
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "MLP solver is not optimizing for quality\n");

  mlp->opt_dbg_optimize_utility = GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
     "ats", "MLP_DBG_OPTIMIZE_UTILITY");
  if (GNUNET_SYSERR == mlp->opt_dbg_optimize_utility)
   mlp->opt_dbg_optimize_utility = GNUNET_YES;
  if (GNUNET_NO == mlp->opt_dbg_optimize_utility)
    LOG (GNUNET_ERROR_TYPE_WARNING,
        "MLP solver is not optimizing for utility\n");

  if ( (GNUNET_NO == mlp->opt_dbg_optimize_utility) &&
       (GNUNET_NO == mlp->opt_dbg_optimize_quality) &&
       (GNUNET_NO == mlp->opt_dbg_optimize_relativity) &&
       (GNUNET_NO == mlp->opt_dbg_optimize_utility) &&
       (GNUNET_NO == mlp->opt_dbg_feasibility_only))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
        _("MLP solver is not optimizing for anything, changing to feasibility check\n"));
    mlp->opt_dbg_feasibility_only = GNUNET_YES;
  }

  if (GNUNET_SYSERR == GNUNET_CONFIGURATION_get_value_string (env->cfg,
     "ats", "MLP_LOG_FORMAT", &outputformat))
   mlp->opt_log_format = MLP_CPLEX;
  else
  {
    GNUNET_STRINGS_utf8_toupper(outputformat, outputformat);
    if (0 == strcmp (outputformat, "MPS"))
    {
      mlp->opt_log_format = MLP_MPS;
    }
    else if (0 == strcmp (outputformat, "CPLEX"))
    {
      mlp->opt_log_format = MLP_CPLEX;
    }
    else if (0 == strcmp (outputformat, "GLPK"))
    {
      mlp->opt_log_format = MLP_GLPK;
    }
    else
    {
      LOG (GNUNET_ERROR_TYPE_WARNING,
          "Invalid log format `%s' in configuration, using CPLEX!\n",
          outputformat);
      mlp->opt_log_format = MLP_CPLEX;
    }
    GNUNET_free (outputformat);
  }

  mlp->pv.BIG_M = (double) BIG_M_VALUE;

  mlp->pv.mip_gap = (double) 0.0;
  if (GNUNET_SYSERR != GNUNET_CONFIGURATION_get_value_float (env->cfg, "ats",
      "MLP_MAX_MIP_GAP", &f_tmp))
  {
    if ((f_tmp < 0.0) || (f_tmp > 1.0))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, _("Invalid %s configuration %f \n"),
          "MIP gap", f_tmp);
    }
    else
    {
      mlp->pv.mip_gap = f_tmp;
      LOG (GNUNET_ERROR_TYPE_INFO, "Using %s of %.3f\n",
          "MIP gap", f_tmp);
    }
  }

  mlp->pv.lp_mip_gap = (double) 0.0;
  if (GNUNET_SYSERR != GNUNET_CONFIGURATION_get_value_float (env->cfg, "ats",
      "MLP_MAX_LP_MIP_GAP", &f_tmp))
  {
    if ((f_tmp < 0.0) || (f_tmp > 1.0))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, _("Invalid %s configuration %f \n"),
          "LP/MIP", f_tmp);
    }
    else
    {
      mlp->pv.lp_mip_gap = f_tmp;
      LOG (GNUNET_ERROR_TYPE_INFO, "Using %s gap of %.3f\n",
          "LP/MIP", f_tmp);
    }
  }

  /* Get timeout for iterations */
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_time(env->cfg, "ats",
      "MLP_MAX_DURATION", &max_duration))
  {
    max_duration = MLP_MAX_EXEC_DURATION;
  }

  /* Get maximum number of iterations */
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_size(env->cfg, "ats",
      "MLP_MAX_ITERATIONS", &max_iterations))
  {
    max_iterations = MLP_MAX_ITERATIONS;
  }

  /* Get diversity coefficient from configuration */
  mlp->pv.co_D = MLP_DEFAULT_D;
  if (GNUNET_SYSERR != GNUNET_CONFIGURATION_get_value_float (env->cfg, "ats",
      "MLP_COEFFICIENT_D", &f_tmp))
  {
    if ((f_tmp < 0.0))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, _("Invalid %s configuration %f \n"),
          "MLP_COEFFICIENT_D", f_tmp);
    }
    else
    {
      mlp->pv.co_D = f_tmp;
      LOG (GNUNET_ERROR_TYPE_INFO, "Using %s gap of %.3f\n",
          "MLP_COEFFICIENT_D", f_tmp);
    }
  }

  /* Get relativity coefficient from configuration */
  mlp->pv.co_R = MLP_DEFAULT_R;
  if (GNUNET_SYSERR != GNUNET_CONFIGURATION_get_value_float (env->cfg, "ats",
      "MLP_COEFFICIENT_R", &f_tmp))
  {
    if ((f_tmp < 0.0))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, _("Invalid %s configuration %f \n"),
          "MLP_COEFFICIENT_R", f_tmp);
    }
    else
    {
      mlp->pv.co_R = f_tmp;
      LOG (GNUNET_ERROR_TYPE_INFO, "Using %s gap of %.3f\n",
          "MLP_COEFFICIENT_R", f_tmp);
    }
  }


  /* Get utilization coefficient from configuration */
  mlp->pv.co_U = MLP_DEFAULT_U;
  if (GNUNET_SYSERR != GNUNET_CONFIGURATION_get_value_float (env->cfg, "ats",
      "MLP_COEFFICIENT_U", &f_tmp))
  {
    if ((f_tmp < 0.0))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, _("Invalid %s configuration %f \n"),
          "MLP_COEFFICIENT_U", f_tmp);
    }
    else
    {
      mlp->pv.co_U = f_tmp;
      LOG (GNUNET_ERROR_TYPE_INFO, "Using %s gap of %.3f\n",
          "MLP_COEFFICIENT_U", f_tmp);
    }
  }

  /* Get quality metric coefficients from configuration */
  int i_delay = MLP_NaN;
  int i_distance = MLP_NaN;
  int q[GNUNET_ATS_QualityPropertiesCount] = GNUNET_ATS_QualityProperties;
  for (c = 0; c < GNUNET_ATS_QualityPropertiesCount; c++)
  {
    /* initialize quality coefficients with default value 1.0 */
      mlp->pv.co_Q[c] = MLP_DEFAULT_QUALITY;

    mlp->pv.q[c] = q[c];
    if (q[c] == GNUNET_ATS_QUALITY_NET_DELAY)
      i_delay = c;
    if (q[c] == GNUNET_ATS_QUALITY_NET_DISTANCE)
      i_distance = c;
  }

  if ( (i_delay != MLP_NaN) &&
       (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (env->cfg, "ats",
          "MLP_COEFFICIENT_QUALITY_DELAY", &tmp)) )
    mlp->pv.co_Q[i_delay] = (double) tmp / 100;
  else
    mlp->pv.co_Q[i_delay] = MLP_DEFAULT_QUALITY;

  if ( (i_distance != MLP_NaN) &&
        (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (env->cfg, "ats",
          "MLP_COEFFICIENT_QUALITY_DISTANCE", &tmp)) )
    mlp->pv.co_Q[i_distance] = (double) tmp / 100;
  else
    mlp->pv.co_Q[i_distance] = MLP_DEFAULT_QUALITY;

  /* Get minimum bandwidth per used address from configuration */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (env->cfg, "ats",
                                                      "MLP_MIN_BANDWIDTH",
                                                      &tmp))
    b_min = tmp;
  else
  {
    b_min = ntohl (GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT.value__);
  }

  /* Get minimum number of connections from configuration */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (env->cfg, "ats",
                                                      "MLP_MIN_CONNECTIONS",
                                                      &tmp))
    n_min = tmp;
  else
    n_min = MLP_DEFAULT_MIN_CONNECTIONS;

  /* Init network quotas */
  int quotas[GNUNET_ATS_NetworkTypeCount] = GNUNET_ATS_NetworkType;
  for (c = 0; c < GNUNET_ATS_NetworkTypeCount; c++)
  {
      found = GNUNET_NO;
      for (c2 = 0; c2 < env->network_count; c2++)
      {
          if (quotas[c] == env->networks[c2])
          {
              mlp->pv.quota_index[c] = env->networks[c2];
              mlp->pv.quota_out[c] = env->out_quota[c2];
              mlp->pv.quota_in[c] = env->in_quota[c2];

              found = GNUNET_YES;
              LOG (GNUNET_ERROR_TYPE_INFO,
                  "Quota for network `%s' (in/out) %llu/%llu\n",
                  GNUNET_ATS_print_network_type(mlp->pv.quota_index[c]),
                  mlp->pv.quota_out[c],
                  mlp->pv.quota_in[c]);
              break;

          }
      }

      /* Check if defined quota could make problem unsolvable */
      if ((n_min * b_min) > mlp->pv.quota_out[c])
      {
        LOG (GNUNET_ERROR_TYPE_INFO,
            _("Adjusting inconsistent outbound quota configuration for network `%s', is %llu must be at least %llu\n"),
            GNUNET_ATS_print_network_type(mlp->pv.quota_index[c]),
            mlp->pv.quota_out[c],
            (n_min * b_min));
        mlp->pv.quota_out[c] = (n_min * b_min);
      }
      if ((n_min * b_min) > mlp->pv.quota_in[c])
      {
        LOG (GNUNET_ERROR_TYPE_INFO,
            _("Adjusting inconsistent inbound quota configuration for network `%s', is %llu must be at least %llu\n"),
            GNUNET_ATS_print_network_type(mlp->pv.quota_index[c]),
            mlp->pv.quota_in[c],
            (n_min * b_min));
        mlp->pv.quota_in[c] = (n_min * b_min);
      }

      /* Check if bandwidth is too big to make problem solvable */
      if (mlp->pv.BIG_M < mlp->pv.quota_out[c])
      {
        LOG (GNUNET_ERROR_TYPE_INFO,
            _("Adjusting outbound quota configuration for network `%s'from %llu to %.0f\n"),
            GNUNET_ATS_print_network_type(mlp->pv.quota_index[c]),
            mlp->pv.quota_out[c],
            mlp->pv.BIG_M);
        mlp->pv.quota_out[c] = mlp->pv.BIG_M ;
      }
      if (mlp->pv.BIG_M < mlp->pv.quota_in[c])
      {
        LOG (GNUNET_ERROR_TYPE_INFO, _("Adjusting inbound quota configuration for network `%s' from %llu to %.0f\n"),
            GNUNET_ATS_print_network_type(mlp->pv.quota_index[c]),
            mlp->pv.quota_in[c],
            mlp->pv.BIG_M);
        mlp->pv.quota_in[c] = mlp->pv.BIG_M ;
      }

      if (GNUNET_NO == found)
      {
        mlp->pv.quota_in[c] = ntohl (GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT.value__);
        mlp->pv.quota_out[c] = ntohl (GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT.value__);
        LOG (GNUNET_ERROR_TYPE_INFO, _("Using default quota configuration for network `%s' (in/out) %llu/%llu\n"),
            GNUNET_ATS_print_network_type(mlp->pv.quota_index[c]),
            mlp->pv.quota_in[c],
            mlp->pv.quota_out[c]);
      }
  }
  mlp->env = env;
  env->sf.s_add = &GAS_mlp_address_add;
  env->sf.s_address_update_property = &GAS_mlp_address_property_changed;
  env->sf.s_get = &GAS_mlp_get_preferred_address;
  env->sf.s_get_stop = &GAS_mlp_stop_get_preferred_address;
  env->sf.s_pref = &GAS_mlp_address_change_preference;
  env->sf.s_feedback = &GAS_mlp_address_preference_feedback;
  env->sf.s_del = &GAS_mlp_address_delete;
  env->sf.s_bulk_start = &GAS_mlp_bulk_start;
  env->sf.s_bulk_stop = &GAS_mlp_bulk_stop;


  /* Assign options to handle */
  mlp->stats = (struct GNUNET_STATISTICS_Handle *) env->stats;
  mlp->addresses = env->addresses;
  mlp->bw_changed_cb = env->bandwidth_changed_cb;
  mlp->bw_changed_cb_cls = env->bw_changed_cb_cls;
  mlp->get_preferences =  env->get_preferences;
  mlp->get_preferences_cls = env->get_preference_cls;
  mlp->get_properties = env->get_property;
  mlp->get_properties_cls = env->get_property_cls;
  /* Setting MLP Input variables */

  mlp->pv.b_min = b_min;
  mlp->pv.n_min = n_min;
  mlp->pv.m_q = GNUNET_ATS_QualityPropertiesCount;
  mlp->stat_mlp_prob_changed = GNUNET_NO;
  mlp->stat_mlp_prob_updated = GNUNET_NO;
  mlp->opt_mlp_auto_solve = GNUNET_YES;
  mlp->requested_peers = GNUNET_CONTAINER_multipeermap_create (10, GNUNET_NO);
  mlp->stat_bulk_requests = 0;
  mlp->stat_bulk_lock = 0;

  /* Setup GLPK */
  /* Redirect GLPK output to GNUnet logging */
  glp_term_hook (&mlp_term_hook, (void *) mlp);

  /* Init LP solving parameters */
  glp_init_smcp(&mlp->control_param_lp);
  mlp->control_param_lp.msg_lev = GLP_MSG_OFF;
  if (GNUNET_YES == mlp->opt_dbg_glpk_verbose)
    mlp->control_param_lp.msg_lev = GLP_MSG_ALL;

  mlp->control_param_lp.it_lim = max_iterations;
  mlp->control_param_lp.tm_lim = max_duration.rel_value_us / 1000LL;

  /* Init MLP solving parameters */
  glp_init_iocp(&mlp->control_param_mlp);
  /* Setting callback function */
  mlp->control_param_mlp.cb_func = &mlp_branch_and_cut_cb;
  mlp->control_param_mlp.cb_info = mlp;
  mlp->control_param_mlp.msg_lev = GLP_MSG_OFF;
  mlp->control_param_mlp.mip_gap = mlp->pv.mip_gap;
  if (GNUNET_YES == mlp->opt_dbg_glpk_verbose)
    mlp->control_param_mlp.msg_lev = GLP_MSG_ALL;
  mlp->control_param_mlp.tm_lim = max_duration.rel_value_us / 1000LL;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "solver ready\n");

  return mlp;
}

/* end of plugin_ats_mlp.c */
