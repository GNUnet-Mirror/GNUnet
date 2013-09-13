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
 * @file ats/gnunet-service-ats-solver_mlp.c
 * @brief ats mlp problem solver
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet-service-ats-solver_mlp.h"
#include "gnunet_statistics_service.h"
#include "glpk.h"

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
 *      * MLP_MAX_DURATION:
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
 * Enable GLPK verbose output
 */
#define VERBOSE_GLPK GNUNET_NO

/**
 * Maximize bandwidth assigned
 *
 * This option can be used to test if problem can be solved at all without
 * optimizing for utility, diversity or relativity
 *
 */
#define MAXIMIZE_FOR_BANDWIDTH_ASSIGNED GNUNET_NO

/**
 * Intercept GLPK terminal output
 * @param info the mlp handle
 * @param s the string to print
 * @return 0: glpk prints output on terminal, 0 != surpress output
 */
static int
mlp_term_hook (void *info, const char *s)
{
  /* Not needed atm struct MLP_information *mlp = info; */
  LOG (GNUNET_ERROR_TYPE_DEBUG, "%s", s);
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
reset_peers (void *cls, const struct GNUNET_HashCode * key, void *value)
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


  GNUNET_CONTAINER_multihashmap_iterate (mlp->requested_peers, &reset_peers, NULL);
}


/**
 * Translate ATS properties to text
 * Just intended for debugging
 *
 * @param ats_index the ATS index
 * @return string with result
 */
const char *
mlp_ats_to_string (int ats_index)
{
  switch (ats_index) {
    case GNUNET_ATS_ARRAY_TERMINATOR:
      return "GNUNET_ATS_ARRAY_TERMINATOR";
    case GNUNET_ATS_UTILIZATION_UP:
      return "GNUNET_ATS_UTILIZATION_UP";
    case GNUNET_ATS_UTILIZATION_DOWN:
      return "GNUNET_ATS_UTILIZATION_DOWN";
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
const char *
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
const char *
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
static int
get_performance_info (struct ATS_Address *address, uint32_t type)
{
	int c1;
	GNUNET_assert (NULL != address);

	if ((NULL == address->atsi) || (0 == address->atsi_count))
			return GNUNET_ATS_VALUE_UNDEFINED;

	for (c1 = 0; c1 < address->atsi_count; c1++)
	{
			if (ntohl(address->atsi[c1].type) == type)
				return ntohl(address->atsi[c1].value);
	}
	return GNUNET_ATS_VALUE_UNDEFINED;
}


struct CountContext
{
	struct GNUNET_CONTAINER_MultiHashMap * peers;
	int result;
};

static int
mlp_create_problem_count_addresses_it (void *cls, const struct GNUNET_HashCode *key, void *value)
{
	struct CountContext *cctx = cls;
  /* Check if we have to add this peer due to a pending request */
  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains(cctx->peers, key))
  	cctx->result++;
  return GNUNET_OK;
}

static int mlp_create_problem_count_addresses (
		struct GNUNET_CONTAINER_MultiHashMap * peers,
		const struct GNUNET_CONTAINER_MultiHashMap * addresses)
{
	struct CountContext cctx;
	cctx.peers = peers;
	cctx.result = 0;
  GNUNET_CONTAINER_multihashmap_iterate (addresses, &mlp_create_problem_count_addresses_it, &cctx);
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
		GNUNET_break (0);
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
  switch (bound) {
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
mlp_create_problem_add_address_information (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct GAS_MLP_Handle *mlp = cls;
  struct MLP_Problem *p = &mlp->p;
  struct ATS_Address *address = value;
  struct ATS_Peer *peer;
  struct MLP_information *mlpi;
  char *name;
  const double *props;
  uint32_t addr_net;
  int c;

  /* Check if we have to add this peer due to a pending request */
  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains(mlp->requested_peers, key))
  	return GNUNET_OK;

  mlpi = address->solver_information;
  if (NULL == mlpi)
  {
  		fprintf (stderr, "%s %p\n",GNUNET_i2s (&address->peer), address);
  		GNUNET_break (0);
  		return GNUNET_OK;
  }

  /* Get peer */
  peer = GNUNET_CONTAINER_multihashmap_get (mlp->requested_peers, key);
  if (peer->processed == GNUNET_NO)
  {
  		/* Add peer dependent constraints */
  		/* Add constraint c2 */
  	  GNUNET_asprintf(&name, "c2_%s", GNUNET_i2s(&address->peer));
  	  peer->r_c2 = mlp_create_problem_create_constraint (p, name, GLP_FX, 1.0, 1.0);
  		GNUNET_free (name);
  		/* Add constraint c9 */
  	  GNUNET_asprintf(&name, "c9_%s", GNUNET_i2s(&address->peer));
  	  peer->r_c9 = mlp_create_problem_create_constraint (p, name, GLP_LO, 0.0, 0.0);
  		GNUNET_free (name);
  	  /* c 9) set coefficient */
  		mlp_create_problem_set_value (p, peer->r_c9, p->c_r, -peer->f, __LINE__);
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
#if TEST_MAX_BW_ASSIGNMENT
  mlpi->c_b = mlp_create_problem_create_column (p, name, GLP_CV, GLP_LO, 0.0, 0.0, 1.0);
#else
  mlpi->c_b = mlp_create_problem_create_column (p, name, GLP_CV, GLP_LO, 0.0, 0.0, 0.0);
#endif

  GNUNET_free (name);

  /* Add usage column */
  GNUNET_asprintf (&name, "n_%s_%s_%p", GNUNET_i2s (&address->peer), address->plugin, address);
  mlpi->c_n = mlp_create_problem_create_column (p, name, GLP_IV, GLP_DB, 0.0, 1.0, 0.0);
  GNUNET_free (name);

	/* Add address dependent constraints */
	/* Add constraint c1) bandwidth capping
   * b_t  + (-M) * n_t <= 0
   * */
  GNUNET_asprintf(&name, "c1_%s_%s_%p", GNUNET_i2s(&address->peer), address->plugin, address);
  mlpi->r_c1 = mlp_create_problem_create_constraint (p, name, GLP_UP, 0.0, 0.0);
	GNUNET_free (name);

	/*  c1) set b = 1 coefficient */
	mlp_create_problem_set_value (p, mlpi->r_c1, mlpi->c_b, 1, __LINE__);
	/*  c1) set n = -M coefficient */
	mlp_create_problem_set_value (p, mlpi->r_c1, mlpi->c_n, -mlp->pv.BIG_M, __LINE__);

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
  /* c 4) minimum connections */
	mlp_create_problem_set_value (p, p->r_c4, mlpi->c_n, 1, __LINE__);
  /* c 6) maximize diversity */
	mlp_create_problem_set_value (p, p->r_c6, mlpi->c_n, 1, __LINE__);
  /* c 2) 1 address peer peer */
	mlp_create_problem_set_value (p, peer->r_c2, mlpi->c_n, 1, __LINE__);
  /* c 9) relativity */
	mlp_create_problem_set_value (p, peer->r_c9, mlpi->c_b, 1, __LINE__);
  /* c 8) utility */
	mlp_create_problem_set_value (p, p->r_c8, mlpi->c_b, 1, __LINE__);

  /* c 10) obey network specific quotas
   * (1)*b_1 + ... + (1)*b_m <= quota_n
   */
  for (c = 0; c < GNUNET_ATS_NetworkTypeCount; c++)
  {
  	addr_net = get_performance_info (address, GNUNET_ATS_NETWORK_TYPE);
  	if (GNUNET_ATS_VALUE_UNDEFINED == addr_net)
  		addr_net = GNUNET_ATS_NET_UNSPECIFIED;

    if (mlp->pv.quota_index[c] == addr_net)
    {
  		mlp_create_problem_set_value (p, p->r_quota[c], mlpi->c_b, 1, __LINE__);
      break;
    }
  }

  /* c 7) Optimize quality */
  /* For all quality metrics, set quality of this address */
  props = mlp->get_properties (mlp->get_properties_cls, address);
  for (c = 0; c < mlp->pv.m_q; c++)
    mlp_create_problem_set_value (p, p->r_q[c], mlpi->c_b, props[c], __LINE__);

  return GNUNET_OK;
}

/**
 * Create the invariant columns c4, c6, c10, c8, c7
 */
static void
mlp_create_problem_add_invariant_rows (struct GAS_MLP_Handle *mlp, struct MLP_Problem *p)
{
  char *name;
  int c;

  /* Row for c4) minimum connection */
  /* Number of minimum connections is min(|Peers|, n_min) */
  p->r_c4 = mlp_create_problem_create_constraint (p, "c4", GLP_LO, (mlp->pv.n_min > p->num_peers) ? p->num_peers : mlp->pv.n_min, 0.0);

  /* Add row for c6) */
	p->r_c6 = mlp_create_problem_create_constraint (p, "c6", GLP_FX, 0.0, 0.0);
  /* c6 )Setting -D */
	mlp_create_problem_set_value (p, p->r_c6, p->c_d, -1, __LINE__);

  /* Add rows for c 10) */
  for (c = 0; c < GNUNET_ATS_NetworkTypeCount; c++)
  {
      char * text;
      GNUNET_asprintf(&text, "c10_quota_ats_%s", GNUNET_ATS_print_network_type(mlp->pv.quota_index[c]));
  		p->r_quota[c] = mlp_create_problem_create_constraint (p, text, GLP_DB, 0.0, mlp->pv.quota_out[c]);
  		GNUNET_free (text);
  }

  /* Adding rows for c 8) */
  p->r_c8 = mlp_create_problem_create_constraint (p, "c8", GLP_FX, 0.0, 0.0);
  /* -u */
	mlp_create_problem_set_value (p, p->r_c8, p->c_u, -1, __LINE__);

	/* c 7) For all quality metrics */
	for (c = 0; c < mlp->pv.m_q; c++)
	{
		GNUNET_asprintf(&name, "c7_q%i_%s", c, mlp_ats_to_string(mlp->pv.q[c]));
		p->r_q[c] = mlp_create_problem_create_constraint (p, name, GLP_FX, 0.0, 0.0);
		GNUNET_free (name);
		mlp_create_problem_set_value (p, p->r_q[c], p->c_q[c], -1, __LINE__);
	}
}


/**
 * Create the invariant columns d, u, r, q0 ... qm
 */
static void
mlp_create_problem_add_invariant_columns (struct GAS_MLP_Handle *mlp, struct MLP_Problem *p)
{
  char *name;
  int c;

#if TEST_MAX_BW_ASSIGNMENT
  mlp->pv.co_D = 0.0;
  mlp->pv.co_U = 0.0;

#endif
  //mlp->pv.co_R = 0.0;

  /* Diversity d column  */
  p->c_d = mlp_create_problem_create_column (p, "d", GLP_CV, GLP_LO, 0.0, 0.0, mlp->pv.co_D);

  /* Utilization u column  */
  p->c_u = mlp_create_problem_create_column (p, "u", GLP_CV, GLP_LO, 0.0, 0.0, mlp->pv.co_U);

  /* Relativity r column  */
  p->c_r = mlp_create_problem_create_column (p, "r", GLP_CV, GLP_LO, 0.0, 0.0, mlp->pv.co_R);

  /* Quality metric columns */
  for (c = 0; c < mlp->pv.m_q; c++)
  {
    GNUNET_asprintf (&name, "q_%u", mlp->pv.q[c]);
#if TEST_MAX_BW_ASSIGNMENT
  	p->c_q[c] = mlp_create_problem_create_column (p, name, GLP_CV, GLP_LO, 0.0, 0.0, 0.0);
#else
  	p->c_q[c] = mlp_create_problem_create_column (p, name, GLP_CV, GLP_LO, 0.0, 0.0, mlp->pv.co_Q[c]);
#endif
  	GNUNET_free (name);
  }
}


/**
 * Create the MLP problem
 *
 * @param mlp the MLP handle
 * @return GNUNET_OK or GNUNET_SYSERR
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
  p->num_peers = GNUNET_CONTAINER_multihashmap_size (mlp->requested_peers);
  p->num_addresses = mlp_create_problem_count_addresses (mlp->requested_peers, mlp->addresses);

  /* Create problem matrix: 10 * #addresses + #q * #addresses + #q, + #peer + 2 + 1 */
  p->num_elements = (10 * p->num_addresses + mlp->pv.m_q * p->num_addresses +  mlp->pv.m_q + p->num_peers + 2 + 1);
	LOG (GNUNET_ERROR_TYPE_DEBUG, "Rebuilding problem for %u peer(s) and %u addresse(s) and %u quality metrics == %u elements\n",
			p->num_peers, p->num_addresses, mlp->pv.m_q, p->num_elements);

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
  GNUNET_CONTAINER_multihashmap_iterate (mlp->addresses, &mlp_create_problem_add_address_information, mlp);

  /* Load the matrix */
	LOG (GNUNET_ERROR_TYPE_DEBUG, "Loading matrix\n");
  glp_load_matrix(p->prob, (p->ci)-1, p->ia, p->ja, p->ar);

  return res;
}

/**
 * Solves the LP problem
 *
 * @param mlp the MLP Handle
 * @return GNUNET_OK if could be solved, GNUNET_SYSERR on failure
 */
static int
mlp_solve_lp_problem (struct GAS_MLP_Handle *mlp)
{
	int res = 0;

	res = glp_simplex(mlp->p.prob, &mlp->control_param_lp);
	if (0 == res)
		LOG (GNUNET_ERROR_TYPE_DEBUG, "Solving LP problem: 0x%02X %s\n", res, mlp_solve_to_string(res));
	else
		LOG (GNUNET_ERROR_TYPE_WARNING, "Solving LP problem failed: 0x%02X %s\n", res, mlp_solve_to_string(res));

  /* Analyze problem status  */
  res = glp_get_status (mlp->p.prob);
  switch (res) {
    /* solution is optimal */
    case GLP_OPT:
    /* solution is feasible */
    case GLP_FEAS:
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Solving LP problem: 0x%02X %s\n",
      		res, mlp_status_to_string(res));
      return GNUNET_OK;
    /* Problem was ill-defined, no way to handle that */
    default:
      LOG (GNUNET_ERROR_TYPE_WARNING, "Solving LP problem failed, no solution: 0x%02X %s\n",
      		res, mlp_status_to_string(res));
      return GNUNET_SYSERR;
  }
}


/**
 * Solves the MLP problem
 *
 * @param mlp the MLP Handle
 * @return GNUNET_OK if could be solved, GNUNET_SYSERR on failure
 */
int
mlp_solve_mlp_problem (struct GAS_MLP_Handle *mlp)
{
	int res = 0;
	res = glp_intopt(mlp->p.prob, &mlp->control_param_mlp);
	if (0 == res)
		LOG (GNUNET_ERROR_TYPE_DEBUG, "Solving MLP problem: 0x%02X %s\n", res, mlp_solve_to_string(res));
	else
		LOG (GNUNET_ERROR_TYPE_WARNING, "Solving MLP problem failed: 0x%02X %s\n", res, mlp_solve_to_string(res));
  /* Analyze problem status  */
  res = glp_mip_status(mlp->p.prob);
  switch (res) {
    /* solution is optimal */
    case GLP_OPT:
    /* solution is feasible */
    case GLP_FEAS:
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Solving MLP problem: 0x%02X %s\n", res, mlp_status_to_string(res));
      return GNUNET_OK;
    /* Problem was ill-defined, no way to handle that */
    default:
      LOG (GNUNET_ERROR_TYPE_WARNING,"Solving MLP problem failed, 0x%02X %s\n\n", res, mlp_status_to_string(res));
      return GNUNET_SYSERR;
  }
}


/**
 * Propagates the results when MLP problem was solved
 *
 * @param cls the MLP handle
 * @param key the peer identity
 * @param value the address
 * @return GNUNET_OK to continue
 */
int
mlp_propagate_results (void *cls, const struct GNUNET_HashCode *key, void *value)
{
	struct GAS_MLP_Handle *mlp = cls;
	struct ATS_Address *address;
	struct MLP_information *mlpi;
	double mlp_bw_in = MLP_NaN;
	double mlp_bw_out = MLP_NaN;
	double mlp_use = MLP_NaN;

  /* Check if we have to add this peer due to a pending request */
  if (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains(mlp->requested_peers, key))
  	return GNUNET_OK;
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

  if ((GLP_YES == mlp_use) && (GNUNET_NO == address->active))
  {
  	/* Address switch: Activate address*/
  	LOG (GNUNET_ERROR_TYPE_INFO, "%s %.2f : enabling address\n", (1 == mlp_use) ? "[x]": "[ ]", mlp_bw_out);
		address->active = GNUNET_YES;
		address->assigned_bw_in.value__ = htonl (mlp_bw_in);
		mlpi->b_in.value__ = htonl(mlp_bw_in);
		address->assigned_bw_out.value__ = htonl (mlp_bw_out);
		mlpi->b_out.value__ = htonl(mlp_bw_out);
		mlpi->n = GNUNET_YES;
		mlp->bw_changed_cb (mlp->bw_changed_cb_cls, address);
  }
  else if ((GLP_NO == mlp_use) && (GNUNET_YES == address->active))
  {
		/* Address switch: Disable address*/
  	LOG (GNUNET_ERROR_TYPE_INFO, "%s %.2f : disabling address\n", (1 == mlp_use) ? "[x]": "[ ]", mlp_bw_out);
		address->active = GNUNET_NO;
		/* Set bandwidth to 0 */
		address->assigned_bw_in.value__ = htonl (0);
		mlpi->b_in.value__ = htonl(mlp_bw_in);
		address->assigned_bw_out.value__ = htonl (0);
		mlpi->b_out.value__ = htonl(mlp_bw_out);
		mlpi->n = GNUNET_NO;
		mlp->bw_changed_cb (mlp->bw_changed_cb_cls, address);
  }
  else if ((mlp_bw_out != ntohl(address->assigned_bw_out.value__)) ||
  				 (mlp_bw_in != ntohl(address->assigned_bw_in.value__)))
  {
  	/* Bandwidth changed */
		LOG (GNUNET_ERROR_TYPE_INFO, "%s %.2f : bandwidth changed\n", (1 == mlp_use) ? "[x]": "[ ]", mlp_bw_out);
		address->assigned_bw_in.value__ = htonl (mlp_bw_in);
		mlpi->b_in.value__ = htonl(mlp_bw_in);
		address->assigned_bw_out.value__ = htonl (mlp_bw_out);
		mlpi->b_out.value__ = htonl(mlp_bw_out);
		mlpi->n = (GLP_YES == mlp_use) ? GNUNET_YES : GNUNET_NO;
		mlp->bw_changed_cb (mlp->bw_changed_cb_cls, address);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "%s %.2f : no change\n", (1 == mlp_use) ? "[x]": "[ ]", mlp_bw_out);
  }

  return GNUNET_OK;
}



/**
 * Solves the MLP problem
 *
 * @param solver the MLP Handle
 * @return GNUNET_OK if could be solved, GNUNET_SYSERR on failure
 */
int
GAS_mlp_solve_problem (void *solver)
{
	struct GAS_MLP_Handle *mlp = solver;
	char *filename;
	int res_lp = 0;
	int res_mip = 0;
	struct GNUNET_TIME_Absolute start_build;
	struct GNUNET_TIME_Relative duration_build;
	struct GNUNET_TIME_Absolute start_lp;
	struct GNUNET_TIME_Relative duration_lp;
	struct GNUNET_TIME_Absolute start_mlp;
	struct GNUNET_TIME_Relative duration_mlp;
	GNUNET_assert (NULL != solver);

	if (GNUNET_YES == mlp->bulk_lock)
	{
		mlp->bulk_request ++;
		return GNUNET_NO;
	}

	if (0 == GNUNET_CONTAINER_multihashmap_size(mlp->requested_peers))
		return GNUNET_OK; /* No pending requests */
	if (0 == GNUNET_CONTAINER_multihashmap_size(mlp->addresses))
		return GNUNET_OK; /* No addresses available */

	if ((GNUNET_NO == mlp->mlp_prob_changed) && (GNUNET_NO == mlp->mlp_prob_updated))
	{
		LOG (GNUNET_ERROR_TYPE_DEBUG, "No changes to problem\n");
		return GNUNET_OK;
	}
	if (GNUNET_YES == mlp->mlp_prob_changed)
	{
			LOG (GNUNET_ERROR_TYPE_DEBUG, "Problem size changed, rebuilding\n");
			mlp_delete_problem (mlp);
			start_build = GNUNET_TIME_absolute_get();
			if (GNUNET_SYSERR == mlp_create_problem (mlp))
				return GNUNET_SYSERR;
			duration_build = GNUNET_TIME_absolute_get_duration (start_build);
			mlp->control_param_lp.presolve = GLP_YES;
			mlp->control_param_mlp.presolve = GNUNET_NO; /* No presolver, we have LP solution */
	}
	else
	{
			LOG (GNUNET_ERROR_TYPE_DEBUG, "Problem was updated, resolving\n");
			duration_build.rel_value_us = 0;
	}

	/* Run LP solver */
	LOG (GNUNET_ERROR_TYPE_DEBUG, "Running LP solver %s\n", (GLP_YES == mlp->control_param_lp.presolve)? "with presolver": "without presolver");
	start_lp = GNUNET_TIME_absolute_get();
	res_lp = mlp_solve_lp_problem (mlp);
	duration_lp = GNUNET_TIME_absolute_get_duration (start_lp);


  /* Run LP solver */
	LOG (GNUNET_ERROR_TYPE_DEBUG, "Running MLP solver \n");
	start_mlp = GNUNET_TIME_absolute_get();
	res_mip = mlp_solve_mlp_problem (mlp);

	duration_mlp = GNUNET_TIME_absolute_get_duration (start_mlp);

	/* Save stats */
	mlp->ps.lp_res = res_lp;
	mlp->ps.mip_res = res_mip;
	mlp->ps.build_dur = duration_build;
	mlp->ps.lp_dur = duration_lp;
	mlp->ps.mip_dur = duration_mlp;
	mlp->ps.lp_presolv = mlp->control_param_lp.presolve;
	mlp->ps.mip_presolv = mlp->control_param_mlp.presolve;
	mlp->ps.p_cols = glp_get_num_cols (mlp->p.prob);
	mlp->ps.p_rows = glp_get_num_rows (mlp->p.prob);
	mlp->ps.p_elements = mlp->p.num_elements;

	LOG (GNUNET_ERROR_TYPE_DEBUG, 
	     "Execution time: Build %s\n",
	     GNUNET_STRINGS_relative_time_to_string (duration_build, GNUNET_NO));
	LOG (GNUNET_ERROR_TYPE_DEBUG, 
	     "Execution time: LP %s\n",
	     GNUNET_STRINGS_relative_time_to_string (duration_lp, GNUNET_NO));
	LOG (GNUNET_ERROR_TYPE_DEBUG, 
	     "Execution time: MLP %s\n",
	     GNUNET_STRINGS_relative_time_to_string (duration_mlp, GNUNET_NO));

	/* Propagate result*/
	if ((GNUNET_OK == res_lp) && (GNUNET_OK == res_mip))
		GNUNET_CONTAINER_multihashmap_iterate (mlp->addresses, &mlp_propagate_results, mlp);

	struct GNUNET_TIME_Absolute time = GNUNET_TIME_absolute_get();
	if (GNUNET_YES == mlp->write_mip_mps)
	{
		/* Write problem to disk */
		GNUNET_asprintf (&filename, "problem_p_%u_a%u_%llu.mps", mlp->p.num_peers, mlp->p.num_addresses, time.abs_value_us);
		LOG (GNUNET_ERROR_TYPE_ERROR, "DUMP: %s \n", filename);
		glp_write_lp(mlp->p.prob, NULL, filename);
		GNUNET_free (filename);
	}
	if (GNUNET_YES == mlp->write_mip_sol)
	{
		/* Write solution to disk */
		GNUNET_asprintf (&filename, "problem_p_%u_a%u_%llu.sol", mlp->p.num_peers, mlp->p.num_addresses, time.abs_value_us);
		glp_print_mip (mlp->p.prob, filename );
		LOG (GNUNET_ERROR_TYPE_ERROR, "DUMP: %s \n", filename);
		GNUNET_free (filename);
	}

	/* Reset change and update marker */
	mlp->control_param_lp.presolve = GLP_NO;
	mlp->mlp_prob_updated = GNUNET_NO;
	mlp->mlp_prob_changed = GNUNET_NO;

	if ((GNUNET_OK == res_lp) && (GNUNET_OK == res_mip))
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
void
GAS_mlp_address_add (void *solver,
										struct ATS_Address *address,
										uint32_t network)
{
  struct GAS_MLP_Handle *mlp = solver;
  struct ATS_Peer *p;

  GNUNET_assert (NULL != solver);
  GNUNET_assert (NULL != address);

  if (NULL == address->solver_information)
  {
  		address->solver_information = GNUNET_malloc (sizeof (struct MLP_information));
  }
  else
      LOG (GNUNET_ERROR_TYPE_ERROR, _("Adding address for peer `%s' multiple times\n"), GNUNET_i2s(&address->peer));

  /* Is this peer included in the problem? */
  if (NULL == (p = GNUNET_CONTAINER_multihashmap_get (mlp->requested_peers, &address->peer.hashPubKey)))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Adding address for peer `%s' without address request \n", GNUNET_i2s(&address->peer));
  	return;
  }

	LOG (GNUNET_ERROR_TYPE_DEBUG, "Adding address for peer `%s' with address request \n", GNUNET_i2s(&address->peer));
	/* Problem size changed: new address for peer with pending request */
	mlp->mlp_prob_changed = GNUNET_YES;
	if (GNUNET_YES == mlp->mlp_auto_solve)
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
void
GAS_mlp_address_property_changed (void *solver,
    															struct ATS_Address *address,
    															uint32_t type,
    															uint32_t abs_value,
    															double rel_value)
{
	struct MLP_information *mlpi = address->solver_information;
	struct GAS_MLP_Handle *mlp = solver;
	struct ATS_Peer *p;
	int c1;
	int type_index;

	GNUNET_assert (NULL != solver);
	GNUNET_assert (NULL != address);

  if (NULL == mlpi)
  {
      LOG (GNUNET_ERROR_TYPE_ERROR,
      		_("Updating address property `%s' for peer `%s' %p not added before\n"),
      		GNUNET_ATS_print_property_type (type),
      		GNUNET_i2s(&address->peer),
      		address);
      GNUNET_break (0);
      return;
  }

  if (NULL == (p = GNUNET_CONTAINER_multihashmap_get (mlp->requested_peers,
  		&address->peer.hashPubKey)))
  {
  	/* Peer is not requested, so no need to update problem */
  	return;
  }
	LOG (GNUNET_ERROR_TYPE_DEBUG, "Updating property `%s' address for peer `%s'\n",
			GNUNET_ATS_print_property_type (type),
			GNUNET_i2s(&address->peer));

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
		mlp->mlp_prob_updated = GNUNET_YES;
		if (GNUNET_YES == mlp->mlp_auto_solve)
			GAS_mlp_solve_problem (solver);
	}
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
GAS_mlp_address_session_changed (void *solver,
    															struct ATS_Address *address,
    															uint32_t cur_session,
    															uint32_t new_session)
{
	/* Nothing to do here */
	return;
}


/**
 * Transport session for this address has changed
 *
 * NOTE: values in addresses are already updated
 *
 * @param solver solver handle
 * @param address the address
 * @param in_use usage state
 */
void
GAS_mlp_address_inuse_changed (void *solver,
															 struct ATS_Address *address,
															 int in_use)
{
	/* Nothing to do here */
	return;
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
GAS_mlp_address_change_network (void *solver,
															 struct ATS_Address *address,
															 uint32_t current_network,
															 uint32_t new_network)
{
	struct MLP_information *mlpi = address->solver_information;
	struct GAS_MLP_Handle *mlp = solver;
	struct ATS_Peer *p;
	int nets_avail[] = GNUNET_ATS_NetworkType;
	int c1;

	GNUNET_assert (NULL != solver);
	GNUNET_assert (NULL != address);

	if (NULL == mlpi)
	{
		GNUNET_break (0);
		return;
	}

	if (mlpi->c_b == MLP_UNDEFINED)
		return; /* This address is not yet in the matrix*/

	if (NULL == (p = GNUNET_CONTAINER_multihashmap_get (mlp->requested_peers,
			&address->peer.hashPubKey)))
	{
		/* Peer is not requested, so no need to update problem */
		GNUNET_break (0);
		return;
	}

	if (current_network == new_network)
	{
		GNUNET_break (0);
		return;
	}

	for (c1 = 0; c1 < GNUNET_ATS_NetworkTypeCount ; c1 ++)
	{
		if (nets_avail[c1] == new_network)
			break;
	}

	if (GNUNET_ATS_NetworkTypeCount == c1)
	{
		/* Invalid network */
		GNUNET_break (0);
		return;
	}

	LOG (GNUNET_ERROR_TYPE_DEBUG, "Updating network for peer `%s' from `%s' to `%s'\n",
			GNUNET_i2s (&address->peer),
			GNUNET_ATS_print_network_type(current_network),
			GNUNET_ATS_print_network_type(new_network));

  for (c1 = 0; c1 < GNUNET_ATS_NetworkTypeCount; c1++)
  {
    if (mlp->pv.quota_index[c1] == current_network)
    {
  		/* Remove from old network */
  		mlp_create_problem_update_value (&mlp->p,
  				mlp->p.r_quota[c1],
  				mlpi->c_b, 0.0, __LINE__);
      break;
    }
  }

  for (c1 = 0; c1 < GNUNET_ATS_NetworkTypeCount; c1++)
  {
    if (mlp->pv.quota_index[c1] == new_network)
    {
  		/* Remove from old network */
    	if (GNUNET_SYSERR == mlp_create_problem_update_value (&mlp->p,
  				mlp->p.r_quota[c1],
  				mlpi->c_b, 1.0, __LINE__))
    	{
    		/* This quota did not exist in the problem, recreate */
    		GNUNET_break (0);
    	}
      break;
    }
  }

	mlp->mlp_prob_changed = GNUNET_YES;
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
void
GAS_mlp_address_delete (void *solver,
    struct ATS_Address *address,
    int session_only)
{
	struct ATS_Peer *p;
	struct GAS_MLP_Handle *mlp = solver;
	struct MLP_information *mlpi;

	GNUNET_assert (NULL != solver);
	GNUNET_assert (NULL != address);

	mlpi = address->solver_information;
	if ((GNUNET_NO == session_only) && (NULL != mlpi))
	{
		/* Remove full address */
		GNUNET_free (mlpi);
		address->solver_information = NULL;
	}
	address->active = GNUNET_NO;

  /* Is this peer included in the problem? */
  if (NULL == (p = GNUNET_CONTAINER_multihashmap_get (mlp->requested_peers, &address->peer.hashPubKey)))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Deleting %s for peer `%s' without address request \n",
    		(session_only == GNUNET_YES) ? "session" : "address",
    		GNUNET_i2s(&address->peer));
  	return;
  }
  LOG (GNUNET_ERROR_TYPE_INFO, "Deleting %s for peer `%s' with address request \n",
  		(session_only == GNUNET_YES) ? "session" : "address",
  		GNUNET_i2s(&address->peer));

	/* Problem size changed: new address for peer with pending request */
	mlp->mlp_prob_changed = GNUNET_YES;
	if (GNUNET_YES == mlp->mlp_auto_solve)
	{
		GAS_mlp_solve_problem (solver);
	}
  return;
}


/**
 * Find the active address in the set of addresses of a peer
 * @param cls destination
 * @param key peer id
 * @param value address
 * @return GNUNET_OK
 */
static int
mlp_get_preferred_address_it (void *cls, const struct GNUNET_HashCode * key, void *value)
{
	static int counter = 0;
  struct ATS_Address **aa = (struct ATS_Address **) cls;
  struct ATS_Address *addr = value;
  struct MLP_information *mlpi = addr->solver_information;
  if (mlpi == NULL)
    return GNUNET_YES;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "MLP [%u] Peer `%s' %s length %u session %u active %s mlp active %s\n",
              counter, GNUNET_i2s (&addr->peer), addr->plugin, addr->addr_len, addr->session_id,
              (GNUNET_YES == addr->active) ? "active" : "inactive",
              (GNUNET_YES == mlpi->n) ? "active" : "inactive");
  if (GNUNET_YES == mlpi->n)
  {

    (*aa) = addr;
    (*aa)->assigned_bw_in = mlpi->b_in;
    (*aa)->assigned_bw_out = mlpi->b_out;
    return GNUNET_NO;
  }
  counter ++;
  return GNUNET_YES;
}


static double get_peer_pref_value (struct GAS_MLP_Handle *mlp, const struct GNUNET_PeerIdentity *peer)
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
			//fprintf (stderr, "VALUE[%u] %s %.3f \n", c, GNUNET_i2s (&cur->addr->peer), t[c]);
			res += preferences[c];
		}
	}
	res /= (GNUNET_ATS_PreferenceCount -1);
	return res;
}


/**
 * Get the preferred address for a specific peer
 *
 * @param solver the MLP Handle
 * @param peer the peer
 * @return suggested address
 */
const struct ATS_Address *
GAS_mlp_get_preferred_address (void *solver,
                               const struct GNUNET_PeerIdentity *peer)
{
  struct GAS_MLP_Handle *mlp = solver;
  struct ATS_Peer *p;
  struct ATS_Address *res;

  GNUNET_assert (NULL != solver);
  GNUNET_assert (NULL != peer);

  LOG (GNUNET_ERROR_TYPE_INFO, "Getting preferred address for `%s'\n",
  		GNUNET_i2s (peer));

  /* Is this peer included in the problem? */
  if (NULL == (p = GNUNET_CONTAINER_multihashmap_get (mlp->requested_peers, &peer->hashPubKey)))
  {
  	  LOG (GNUNET_ERROR_TYPE_INFO, "Adding peer `%s' to list of requested_peers with requests\n",
  	  		GNUNET_i2s (peer));

  	  p = GNUNET_malloc (sizeof (struct ATS_Peer));
  	  p->id = (*peer);
  	  p->f = get_peer_pref_value (mlp, peer);
  	  GNUNET_CONTAINER_multihashmap_put (mlp->requested_peers, &peer->hashPubKey, p, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);

  	  /* Added new peer, we have to rebuild problem before solving */
  	  mlp->mlp_prob_changed = GNUNET_YES;

  	  if ((GNUNET_YES == mlp->mlp_auto_solve) &&
  	  		(GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains(mlp->addresses, &peer->hashPubKey)))
  	  	GAS_mlp_solve_problem (mlp);
  }
  /* Get prefered address */
	res = NULL;
  GNUNET_CONTAINER_multihashmap_get_multiple (mlp->addresses, &peer->hashPubKey,
  																						mlp_get_preferred_address_it, &res);
  return res;
}


/**
 * Start a bulk operation
 *
 * @param solver the solver
 */
void
GAS_mlp_bulk_start (void *solver)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Locking solver for bulk operation ...\n");
  struct GAS_MLP_Handle *s = (struct GAS_MLP_Handle *) solver;

  GNUNET_assert (NULL != solver);

  s->bulk_lock ++;
}

void
GAS_mlp_bulk_stop (void *solver)
{
	LOG (GNUNET_ERROR_TYPE_DEBUG, "Unlocking solver from bulk operation ...\n");

  struct GAS_MLP_Handle *s = (struct GAS_MLP_Handle *) solver;
  GNUNET_assert (NULL != solver);

  if (s->bulk_lock < 1)
  {
  	GNUNET_break (0);
  	return;
  }
  s->bulk_lock --;

  if (0 < s->bulk_request)
  {
  	GAS_mlp_solve_problem (solver);
  	s->bulk_request= 0;
  }
}



/**
 * Stop notifying about address and bandwidth changes for this peer
 *
 * @param solver the MLP handle
 * @param peer the peer
 */
void
GAS_mlp_stop_get_preferred_address (void *solver,
                                     const struct GNUNET_PeerIdentity *peer)
{
  struct GAS_MLP_Handle *mlp = solver;
  struct ATS_Peer *p = NULL;

  GNUNET_assert (NULL != solver);
  GNUNET_assert (NULL != peer);
  if (NULL != (p = GNUNET_CONTAINER_multihashmap_get (mlp->requested_peers, &peer->hashPubKey)))
  {
  	GNUNET_CONTAINER_multihashmap_remove (mlp->requested_peers, &peer->hashPubKey, p);
  	GNUNET_free (p);

  	mlp->mlp_prob_changed = GNUNET_YES;
  	if (GNUNET_YES == mlp->mlp_auto_solve)
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
void
GAS_mlp_address_change_preference (void *solver,
								   const struct GNUNET_PeerIdentity *peer,
								   enum GNUNET_ATS_PreferenceKind kind,
								   double pref_rel)
{
  struct GAS_MLP_Handle *mlp = solver;
  struct ATS_Peer *p = NULL;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Changing preference for address for peer `%s' to %.2f\n",
  		GNUNET_i2s(peer), pref_rel);

  GNUNET_STATISTICS_update (mlp->stats,"# LP address preference changes", 1, GNUNET_NO);
  /* Update the constraints with changed preferences */

  /* Update quality constraint c7 */

  /* Update relativity constraint c9 */
  if (NULL == (p = GNUNET_CONTAINER_multihashmap_get (mlp->requested_peers, &peer->hashPubKey)))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, "Updating preference for unknown peer `%s'\n", GNUNET_i2s(peer));
  	return;
  }
  p->f = get_peer_pref_value (mlp, peer);
  LOG (GNUNET_ERROR_TYPE_ERROR, "PEER PREF: %s %.2f\n",
  		GNUNET_i2s(peer), p->f);
  mlp_create_problem_update_value (&mlp->p, p->r_c9, mlp->p.c_r, -p->f, __LINE__);

	/* Problem size changed: new address for peer with pending request */
	mlp->mlp_prob_updated = GNUNET_YES;
	if (GNUNET_YES == mlp->mlp_auto_solve)
		GAS_mlp_solve_problem (solver);
  return;
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
mlp_free_peers (void *cls, const struct GNUNET_HashCode *key, void *value)
{
	struct GNUNET_CONTAINER_MultiHashMap *map = cls;
	struct ATS_Peer *p = value;

	GNUNET_CONTAINER_multihashmap_remove (map, key, value);
	GNUNET_free (p);

	return GNUNET_OK;
}


/**
 * Shutdown the MLP problem solving component
 *
 * @param solver the solver handle
 */
void
GAS_mlp_done (void *solver)
{
  struct GAS_MLP_Handle *mlp = solver;
  GNUNET_assert (mlp != NULL);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Shutting down mlp solver\n");
  mlp_delete_problem (mlp);

  GNUNET_CONTAINER_multihashmap_iterate (mlp->requested_peers, &mlp_free_peers, mlp->requested_peers);
  GNUNET_CONTAINER_multihashmap_destroy (mlp->requested_peers);
  mlp->requested_peers = NULL;

  /* Clean up GLPK environment */
  glp_free_env();
  GNUNET_free (mlp);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Shutdown down of mlp solver complete\n");
}


/**
 * Init the MLP problem solving component
 *
 * @param cfg the GNUNET_CONFIGURATION_Handle handle
 * @param stats the GNUNET_STATISTICS handle
 * @param addresses the address hashmap
 * @param network array of GNUNET_ATS_NetworkType with length dest_length
 * @param out_dest array of outbound quotas
 * @param in_dest array of outbound quota
 * @param dest_length array length for quota arrays
 * @param bw_changed_cb callback for changed bandwidth amounts
 * @param bw_changed_cb_cls cls for callback
 * @param get_preference callback to get relative preferences for a peer
 * @param get_preference_cls cls for callback to get relative preferences
 * @param get_properties callback to get relative properties
 * @param get_properties_cls cls for callback to get relative properties
 * @return struct GAS_MLP_Handle on success, NULL on fail
 */
void *
GAS_mlp_init (const struct GNUNET_CONFIGURATION_Handle *cfg,
              const struct GNUNET_STATISTICS_Handle *stats,
              const struct GNUNET_CONTAINER_MultiHashMap *addresses,
              int *network,
              unsigned long long *out_dest,
              unsigned long long *in_dest,
              int dest_length,
              GAS_bandwidth_changed_cb bw_changed_cb,
              void *bw_changed_cb_cls,
              GAS_get_preferences get_preference,
              void *get_preference_cls,
              GAS_get_properties get_properties,
              void *get_properties_cls)
{
  struct GAS_MLP_Handle * mlp = GNUNET_malloc (sizeof (struct GAS_MLP_Handle));

  double D;
  double R;
  double U;
  unsigned long long tmp;
  unsigned int b_min;
  unsigned int n_min;
  int c;
  int c2;
  int found;

  struct GNUNET_TIME_Relative max_duration;
  long long unsigned int max_iterations;

  GNUNET_assert (NULL != cfg);
  GNUNET_assert (NULL != stats);
  GNUNET_assert (NULL != addresses);
  GNUNET_assert (NULL != bw_changed_cb);
  GNUNET_assert (NULL != get_preference);
  GNUNET_assert (NULL != get_properties);

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

   mlp->write_mip_mps = GNUNET_CONFIGURATION_get_value_yesno (cfg, "ats",
  		 	 "DUMP_MLP");
   if (GNUNET_SYSERR == mlp->write_mip_mps)
  	 mlp->write_mip_mps = GNUNET_NO;
   mlp->write_mip_sol = GNUNET_CONFIGURATION_get_value_yesno (cfg, "ats",
  		 	 "DUMP_MLP");
   if (GNUNET_SYSERR == mlp->write_mip_sol)
  	 mlp->write_mip_sol = GNUNET_NO;

  mlp->pv.BIG_M = (double) BIG_M_VALUE;

  /* Get timeout for iterations */
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_time(cfg, "ats", "MLP_MAX_DURATION", &max_duration))
  {
    max_duration = MLP_MAX_EXEC_DURATION;
  }

  /* Get maximum number of iterations */
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_size(cfg, "ats", "MLP_MAX_ITERATIONS", &max_iterations))
  {
    max_iterations = MLP_MAX_ITERATIONS;
  }

  /* Get diversity coefficient from configuration */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (cfg, "ats",
                                                      "MLP_COEFFICIENT_D",
                                                      &tmp))
    D = (double) tmp / 100;
  else
    D = DEFAULT_D;

  /* Get proportionality coefficient from configuration */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (cfg, "ats",
                                                      "MLP_COEFFICIENT_R",
                                                      &tmp))
    R = (double) tmp / 100;
  else
    R = DEFAULT_R;

  /* Get utilization coefficient from configuration */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (cfg, "ats",
                                                      "MLP_COEFFICIENT_U",
                                                      &tmp))
    U = (double) tmp / 100;
  else
    U = DEFAULT_U;

  /* Get quality metric coefficients from configuration */
  int i_delay = MLP_NaN;
  int i_distance = MLP_NaN;
  int q[GNUNET_ATS_QualityPropertiesCount] = GNUNET_ATS_QualityProperties;
  for (c = 0; c < GNUNET_ATS_QualityPropertiesCount; c++)
  {
    /* initialize quality coefficients with default value 1.0 */
  		mlp->pv.co_Q[c] = DEFAULT_QUALITY;

    mlp->pv.q[c] = q[c];
    if (q[c] == GNUNET_ATS_QUALITY_NET_DELAY)
      i_delay = c;
    if (q[c] == GNUNET_ATS_QUALITY_NET_DISTANCE)
      i_distance = c;
  }

  if ((i_delay != MLP_NaN) && (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (cfg, "ats",
                                                      "MLP_COEFFICIENT_QUALITY_DELAY",
                                                      &tmp)))

  	mlp->pv.co_Q[i_delay] = (double) tmp / 100;
  else
  	mlp->pv.co_Q[i_delay] = DEFAULT_QUALITY;

  if ((i_distance != MLP_NaN) && (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (cfg, "ats",
                                                      "MLP_COEFFICIENT_QUALITY_DISTANCE",
                                                      &tmp)))
  	mlp->pv.co_Q[i_distance] = (double) tmp / 100;
  else
  	mlp->pv.co_Q[i_distance] = DEFAULT_QUALITY;

  /* Get minimum bandwidth per used address from configuration */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (cfg, "ats",
                                                      "MLP_MIN_BANDWIDTH",
                                                      &tmp))
    b_min = tmp;
  else
  {
    b_min = ntohl (GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT.value__);
  }

  /* Get minimum number of connections from configuration */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (cfg, "ats",
                                                      "MLP_MIN_CONNECTIONS",
                                                      &tmp))
    n_min = tmp;
  else
    n_min = DEFAULT_MIN_CONNECTIONS;

  /* Init network quotas */
  int quotas[GNUNET_ATS_NetworkTypeCount] = GNUNET_ATS_NetworkType;
  for (c = 0; c < GNUNET_ATS_NetworkTypeCount; c++)
  {
  		found = GNUNET_NO;
  	  for (c2 = 0; c2 < dest_length; c2++)
  	  {
  	  		if (quotas[c] == network[c2])
  	  	  {
  	  				mlp->pv.quota_index[c] = network[c2];
  	  				mlp->pv.quota_out[c] = out_dest[c2];
  	  	      mlp->pv.quota_in[c] = in_dest[c2];
  	  	      found = GNUNET_YES;
  	  	      LOG (GNUNET_ERROR_TYPE_DEBUG, "Quota for network `%s' (in/out) %llu/%llu\n",
  	  	      						GNUNET_ATS_print_network_type(mlp->pv.quota_index[c]),
  	  	      						mlp->pv.quota_out[c],
  	  	      						mlp->pv.quota_in[c]);
  	  	      break;
  	  	  }
  	  }

      /* Check if defined quota could make problem unsolvable */
      if ((n_min * b_min) > mlp->pv.quota_out[c])
      {
        LOG (GNUNET_ERROR_TYPE_INFO, _("Adjusting inconsistent outbound quota configuration for network `%s', is %llu must be at least %llu\n"),
        		GNUNET_ATS_print_network_type(mlp->pv.quota_index[c]),
        		mlp->pv.quota_out[c],
        		(n_min * b_min));
        mlp->pv.quota_out[c] = (n_min * b_min);
      }
      if ((n_min * b_min) > mlp->pv.quota_in[c])
      {
        LOG (GNUNET_ERROR_TYPE_INFO, _("Adjusting inconsistent inbound quota configuration for network `%s', is %llu must be at least %llu\n"),
        		GNUNET_ATS_print_network_type(mlp->pv.quota_index[c]),
        		mlp->pv.quota_in[c],
        		(n_min * b_min));
        mlp->pv.quota_in[c] = (n_min * b_min);
      }

      /* Check if bandwidth is too big to make problem solvable */
      if (mlp->pv.BIG_M < mlp->pv.quota_out[c])
      {
        LOG (GNUNET_ERROR_TYPE_INFO, _("Adjusting outbound quota configuration for network `%s'from %llu to %.0f\n"),
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
  	  	mlp->pv.quota_in[c] = ntohl(GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT.value__);
  	  	mlp->pv.quota_out[c] = ntohl(GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT.value__);
				LOG (GNUNET_ERROR_TYPE_INFO, _("Using default quota configuration for network `%s' (in/out) %llu/%llu\n"),
						GNUNET_ATS_print_network_type(mlp->pv.quota_index[c]),
						mlp->pv.quota_in[c],
						mlp->pv.quota_out[c]);
			}
  }

  /* Assign options to handle */
  mlp->stats = (struct GNUNET_STATISTICS_Handle *) stats;
  mlp->addresses = addresses;
  mlp->bw_changed_cb = bw_changed_cb;
  mlp->bw_changed_cb_cls = bw_changed_cb_cls;
  mlp->get_preferences = get_preference;
  mlp->get_preferences_cls = get_preference_cls;
  mlp->get_properties = get_properties;
  mlp->get_properties_cls = get_properties_cls;
  /* Setting MLP Input variables */
  mlp->pv.co_D = D;
  mlp->pv.co_R = R;
  mlp->pv.co_U = U;
  mlp->pv.b_min = b_min;
  mlp->pv.n_min = n_min;
  mlp->pv.m_q = GNUNET_ATS_QualityPropertiesCount;
  mlp->mlp_prob_changed = GNUNET_NO;
  mlp->mlp_prob_updated = GNUNET_NO;
  mlp->mlp_auto_solve = GNUNET_YES;
  mlp->requested_peers = GNUNET_CONTAINER_multihashmap_create (10, GNUNET_NO);
  mlp->bulk_request = 0;
  mlp->bulk_lock = 0;

  /* Setup GLPK */
  /* Redirect GLPK output to GNUnet logging */
  glp_term_hook (&mlp_term_hook, (void *) mlp);

  /* Init LP solving parameters */
  glp_init_smcp(&mlp->control_param_lp);
  mlp->control_param_lp.msg_lev = GLP_MSG_OFF;
#if VERBOSE_GLPK
  mlp->control_param_lp.msg_lev = GLP_MSG_ALL;
#endif
  mlp->control_param_lp.it_lim = max_iterations;
  mlp->control_param_lp.tm_lim = max_duration.rel_value_us / 1000LL;

  /* Init MLP solving parameters */
  glp_init_iocp(&mlp->control_param_mlp);
  mlp->control_param_mlp.msg_lev = GLP_MSG_OFF;
#if VERBOSE_GLPK
  mlp->control_param_mlp.msg_lev = GLP_MSG_ALL;
#endif
  mlp->control_param_mlp.tm_lim = max_duration.rel_value_us / 1000LL;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "solver ready\n");

  return mlp;
}

/* end of gnunet-service-ats_addresses_mlp.c */
