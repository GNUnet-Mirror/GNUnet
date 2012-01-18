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
 * @file ats/gnunet-service-ats_addresses_mlp.c
 * @brief ats mlp problem solver
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet-service-ats_addresses.h"
#include "gnunet-service-ats_addresses_mlp.h"
#include "gnunet_statistics_service.h"
#if HAVE_LIBGLPK
#include "glpk.h"
#endif
#include "float.h"

#define DEBUG_ATS GNUNET_YES

/* A very big value */
#define M DBL_MAX

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
      break;
    case GLP_EBADB:
      return "invalid basis";
      break;
    case GLP_ESING:
      return "singular matrix";
      break;
    case GLP_ECOND:
      return "ill-conditioned matrix";
      break;
    case GLP_EBOUND:
      return "invalid bounds";
      break;
    case GLP_EFAIL:
      return "solver failed";
      break;
    case GLP_EOBJLL:
      return "objective lower limit reached";
      break;
    case GLP_EOBJUL:
      return "objective upper limit reached";
      break;
    case GLP_EITLIM:
      return "iteration limit exceeded";
      break;
    case GLP_ETMLIM:
      return "time limit exceeded";
      break;
    case GLP_ENOPFS:
      return "no primal feasible solution";
      break;
    case GLP_EROOT:
      return "root LP optimum not provided";
      break;
    case GLP_ESTOP:
      return "search terminated by application";
      break;
    case GLP_EMIPGAP:
      return "relative mip gap tolerance reached";
      break;
    case GLP_ENOFEAS:
      return "no dual feasible solution";
      break;
    case GLP_ENOCVG:
      return "no convergence";
      break;
    case GLP_EINSTAB:
      return "numerical instability";
      break;
    case GLP_EDATA:
      return "invalid data";
      break;
    case GLP_ERANGE:
      return "result out of range";
      break;
    default:
      GNUNET_break (0);
      return "unknown error";
      break;
  }
  GNUNET_break (0);
  return "unknown error";
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
      break;
    case GLP_FEAS:
      return "solution is feasible";
      break;
    case GLP_INFEAS:
      return "solution is infeasible";
      break;
    case GLP_NOFEAS:
      return "no feasible solution exists";
      break;
    case GLP_OPT:
      return "solution is optimal";
      break;
    case GLP_UNBND:
      return "solution is unbounded";
      break;
    default:
      GNUNET_break (0);
      return "unknown error";
      break;
  }
  GNUNET_break (0);
  return "unknown error";
}

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
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "%s", s);
  return 1;
}

/**
 * Delete the MLP problem and free the constrain matrix
 *
 * @param mlp the MLP handle
 */
static void
mlp_delete_problem (struct GAS_MLP_Handle *mlp)
{
  if (mlp != NULL)
  {
    glp_delete_prob(mlp->prob);

    /* delete row index */
    if (mlp->ia != NULL)
      GNUNET_free (mlp->ia);

    /* delete column index */
    if (mlp->ja != NULL)
      GNUNET_free (mlp->ja);

    /* delete coefficients */
    if (mlp->ar != NULL)
      GNUNET_free (mlp->ar);
  }
}

/**
 * Add constraints that are iterating over "forall addresses"
 * and collects all existing peers for "forall peers" constraints
 *
 * @param cls GAS_MLP_Handle
 * @param key Hashcode
 * @param value ATS_Address
 *
 * @return GNUNET_OK to continue
 */
static int
create_constraint_it (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct GAS_MLP_Handle *mlp = cls;
  struct ATS_Address *address = value;
  struct MLP_information *mlpi;
  unsigned int row_index;

  GNUNET_assert (address->mlp_information != NULL);
  mlpi = (struct MLP_information *) address->mlp_information;

  /* c 1) bandwidth capping
   * b_t  + (-M) * n_t <= 0
   */
  row_index = glp_add_rows (mlp->prob, 1);
  mlpi->r_c1 = row_index;
  /* set row bounds: <= 0 */
  glp_set_row_bnds (mlp->prob, row_index, GLP_UP, 0.0, 0.0);

  mlp->ia[mlp->ci] = row_index;
  mlp->ja[mlp->ci] = mlpi->c_b;
  mlp->ar[mlp->ci] = 1;
  mlp->ci++;

  mlp->ia[mlp->ci] = row_index;
  mlp->ja[mlp->ci] = mlpi->c_b;
  mlp->ar[mlp->ci] = -M;
  mlp->ci++;

  /* c 3) minimum bandwidth
   *    b_t + (-n_t * b_min) >= 0
   */

  row_index = glp_add_rows (mlp->prob, 1);
  mlpi->r_c3 = row_index;
  /* set row bounds: >= 0 */
  glp_set_row_bnds (mlp->prob, row_index, GLP_LO, 0.0, 0.0);

  mlp->ia[mlp->ci] = row_index;
  mlp->ja[mlp->ci] = mlpi->c_b;
  mlp->ar[mlp->ci] = 1;
  mlp->ci++;

  mlp->ia[mlp->ci] = row_index;
  mlp->ja[mlp->ci] = mlpi->c_b;
  mlp->ar[mlp->ci] = -mlp->b_min;
  mlp->ci++;

  /* c 4) minimum connections
   *      (1)*n_1 + ... + (1)*n_m >= n_min
   */
  mlp->ia[mlp->ci] = mlp->r_c4;
  mlp->ja[mlp->ci] = mlpi->c_n;
  mlp->ar[mlp->ci] = 1;
  mlp->ci++;

  return GNUNET_OK;
}


/**
 * Adds the problem constraints for all addresses
 * Required for problem recreation after address deletion
 *
 * @param addresses all addresses
 */

static void
mlp_add_constraints_all_addresses (struct GAS_MLP_Handle *mlp, struct GNUNET_CONTAINER_MultiHashMap * addresses)
{
  //double M = VERY_BIG_DOUBLE_VALUE;
  unsigned int n_addresses;

  /* Problem matrix*/
  n_addresses = GNUNET_CONTAINER_multihashmap_size(addresses);

  /* Required indices in the constrain matrix
   *
   * feasibility constraints:
   *
   * c 1) bandwidth capping
   * #rows: |n_addresses|
   * #indices: 2 * |n_addresses|
   *
   * c 2) one active address per peer
   * #rows: |peers|
   * #indices: |n_addresses|
   *
   * c 3) minium bandwidth assigned
   * #rows: |n_addresses|
   * #indices: 2 * |n_addresses|
   *
   * c 4) minimum number of active connections
   * #rows: 1
   * #indices: |n_addresses|
   *
   * c 5) maximum ressource consumption
   * #rows: |ressources|
   * #indices: |n_addresses|
   *
   * Sum for feasibility constraints:
   * #rows: 3 * |n_addresses| +  |ressources| + |peers| + 1
   * #indices: 7 * |n_addresses|
   *
   * optimality constraints:
   * tbc
   * */

  int pi = (7 * n_addresses);
  mlp->cm_size = pi;
  mlp->ci = 0;

  /* row index */
  int *ia = GNUNET_malloc (pi * sizeof (int));
  mlp->ia = ia;

  /* column index */
  int *ja = GNUNET_malloc (pi * sizeof (int));
  mlp->ja = ja;

  /* coefficient */
  double *ar= GNUNET_malloc (pi * sizeof (double));
  mlp->ar = ar;

  /* Adding constraint rows */
  /* Feasibility constraints */

  /* c 1) bandwidth capping */
  /* c 3) minimum bandwidth */
  /* c 4) minimum number of connections */
  mlp->r_c4 = glp_add_rows (mlp->prob, 1);
  glp_set_row_bnds (mlp->prob, mlp->r_c4, GLP_LO, mlp->n_min, 0.0);

  GNUNET_CONTAINER_multihashmap_iterate (addresses, create_constraint_it, mlp);


}

/**
 * Create the MLP problem
 *
 * @param mlp the MLP handle
 * @return GNUNET_OK or GNUNET_SYSERR
 */
static int
mlp_create_problem (struct GAS_MLP_Handle *mlp, struct GNUNET_CONTAINER_MultiHashMap * addresses)
{
  int res = GNUNET_OK;
  int col;
  int c;
  char *name;


  /* Set a problem name */
  glp_set_prob_name (mlp->prob, "gnunet ats bandwidth distribution");

  /* Set optimization direction to maximize */
  glp_set_obj_dir (mlp->prob, GLP_MAX);

  /* Adding invariant columns */

  /* Diversity d column  */

  col = glp_add_cols (mlp->prob, 1);
  mlp->c_d = col;
  /* Column name */
  glp_set_col_name (mlp->prob, col, "d");
  /* Column objective function coefficient */
  glp_set_obj_coef (mlp->prob, col, mlp->co_D);
  /* Column lower bound = 0.0 */
  glp_set_col_bnds (mlp->prob, col, GLP_LO, 0.0, 0.0);

  /* Utilization u column  */

  col = glp_add_cols (mlp->prob, 1);
  mlp->c_u = col;
  /* Column name */
  glp_set_col_name (mlp->prob, col, "u");
  /* Column objective function coefficient */
  glp_set_obj_coef (mlp->prob, col, mlp->co_U);
  /* Column lower bound = 0.0 */
  glp_set_col_bnds (mlp->prob, col, GLP_LO, 0.0, 0.0);

  /* Relativity r column  */
  col = glp_add_cols (mlp->prob, 1);
  mlp->c_r = col;
  /* Column name */
  glp_set_col_name (mlp->prob, col, "r");
  /* Column objective function coefficient */
  glp_set_obj_coef (mlp->prob, col, mlp->co_R);
  /* Column lower bound = 0.0 */
  glp_set_col_bnds (mlp->prob, col, GLP_LO, 0.0, 0.0);

  /* Quality metric columns */
  col = glp_add_cols(mlp->prob, mlp->m);
  for (c = 0; c < mlp->m; c++)
  {
    mlp->c_q[c] = col + c;
    GNUNET_asprintf (&name, "q_%u", mlp->q[c]);
    glp_set_col_name (mlp->prob, col + c, name);
    /* Column lower bound = 0.0 */
    glp_set_col_bnds (mlp->prob, col + c, GLP_LO, 0.0, 0.0);
    GNUNET_free (name);
    /* Coefficient == Qm */
    glp_set_obj_coef (mlp->prob, col + c, mlp->co_Q[c]);
  }

  /* Add columns for existing addresses */

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
  int res;
  struct GNUNET_TIME_Relative duration;
  struct GNUNET_TIME_Absolute end;
  struct GNUNET_TIME_Absolute start = GNUNET_TIME_absolute_get();

  /* LP presolver?
   * Presolver is required if the problem was modified and an existing
   * valid basis is now invalid */
  if (mlp->presolver_required == GNUNET_YES)
    mlp->control_param_lp.presolve = GLP_ON;
  else
    mlp->control_param_lp.presolve = GLP_OFF;

  /* Solve LP problem to have initial valid solution */
lp_solv:
  res = glp_simplex(mlp->prob, &mlp->control_param_lp);
  if (res == 0)
  {
    /* The LP problem instance has been successfully solved. */
  }
  else if (res == GLP_EITLIM)
  {
    /* simplex iteration limit has been exceeded. */
    // TODO Increase iteration limit?
  }
  else if (res == GLP_ETMLIM)
  {
    /* Time limit has been exceeded.  */
    // TODO Increase time limit?
  }
  else
  {
    /* Problem was ill-defined, retry with presolver */
    if (mlp->presolver_required == GNUNET_NO)
    {
      mlp->presolver_required = GNUNET_YES;
      goto lp_solv;
    }
    else
    {
      /* Problem was ill-defined, no way to handle that */
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
          "ats-mlp",
          "Solving LP problem failed:  %s\n", mlp_solve_to_string(res));
      return GNUNET_SYSERR;
    }
  }

  end = GNUNET_TIME_absolute_get ();
  duration = GNUNET_TIME_absolute_get_difference (start, end);
  mlp->lp_solved++;
  mlp->lp_total_duration =+ duration.rel_value;

  GNUNET_STATISTICS_update (mlp->stats,"# LP problem solved", 1, GNUNET_NO);
  GNUNET_STATISTICS_set (mlp->stats,"# LP execution time", duration.rel_value, GNUNET_NO);
  GNUNET_STATISTICS_set (mlp->stats,"# LP execution time average",
                         mlp->lp_total_duration / mlp->lp_solved,  GNUNET_NO);


  /* Analyze problem status  */
  res = glp_get_status (mlp->prob);
  switch (res) {
    /* solution is optimal */
    case GLP_OPT:
    /* solution is feasible */
    case GLP_FEAS:
      break;

    /* Problem was ill-defined, no way to handle that */
    default:
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
          "ats-mlp",
          "Solving LP problem failed, no solution: %s\n", mlp_status_to_string(res));
      return GNUNET_SYSERR;
      break;
  }

  /* solved sucessfully, no presolver required next time */
  mlp->presolver_required = GNUNET_NO;

  return GNUNET_OK;
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
  int res;
  struct GNUNET_TIME_Relative duration;
  struct GNUNET_TIME_Absolute end;
  struct GNUNET_TIME_Absolute start = GNUNET_TIME_absolute_get();

  /* solve MLP problem */
  res = glp_intopt(mlp->prob, &mlp->control_param_mlp);

  if (res == 0)
  {
    /* The MLP problem instance has been successfully solved. */
  }
  else if (res == GLP_EITLIM)
  {
    /* simplex iteration limit has been exceeded. */
    // TODO Increase iteration limit?
  }
  else if (res == GLP_ETMLIM)
  {
    /* Time limit has been exceeded.  */
    // TODO Increase time limit?
  }
  else
  {
    /* Problem was ill-defined, no way to handle that */
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
        "ats-mlp",
        "Solving MLP problem failed:  %s\n", mlp_solve_to_string(res));
    return GNUNET_SYSERR;
  }

  end = GNUNET_TIME_absolute_get ();
  duration = GNUNET_TIME_absolute_get_difference (start, end);
  mlp->mlp_solved++;
  mlp->mlp_total_duration =+ duration.rel_value;

  GNUNET_STATISTICS_update (mlp->stats,"# MLP problem solved", 1, GNUNET_NO);
  GNUNET_STATISTICS_set (mlp->stats,"# MLP execution time", duration.rel_value, GNUNET_NO);
  GNUNET_STATISTICS_set (mlp->stats,"# MLP execution time average",
                         mlp->mlp_total_duration / mlp->mlp_solved,  GNUNET_NO);

  /* Analyze problem status  */
  res = glp_mip_status(mlp->prob);
  switch (res) {
    /* solution is optimal */
    case GLP_OPT:
    /* solution is feasible */
    case GLP_FEAS:
      break;

    /* Problem was ill-defined, no way to handle that */
    default:
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
          "ats-mlp",
          "Solving MLP problem failed, %s\n\n", mlp_status_to_string(res));
      return GNUNET_SYSERR;
      break;
  }

  return GNUNET_OK;
}

int mlp_solve_problem (struct GAS_MLP_Handle *mlp);

static void
mlp_scheduler (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GAS_MLP_Handle *mlp = cls;

  mlp->mlp_task = GNUNET_SCHEDULER_NO_TASK;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

#if DEBUG_ATS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Scheduled problem solving\n");
#endif
  if (mlp->addr_in_problem != 0)
    mlp_solve_problem(mlp);
}


/**
 * Solves the MLP problem
 *
 * @param mlp the MLP Handle
 * @return GNUNET_OK if could be solved, GNUNET_SYSERR on failure
 */
int
mlp_solve_problem (struct GAS_MLP_Handle *mlp)
{
  int res;
  mlp->last_execution = GNUNET_TIME_absolute_get ();
  res = mlp_solve_lp_problem (mlp);
  if (res == GNUNET_OK)
    res = mlp_solve_mlp_problem (mlp);
  if (mlp->mlp_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel(mlp->mlp_task);
    mlp->mlp_task = GNUNET_SCHEDULER_NO_TASK;
  }
  mlp->mlp_task = GNUNET_SCHEDULER_add_delayed (mlp->exec_interval, &mlp_scheduler, mlp);
  return res;
}

/**
 * Init the MLP problem solving component
 *
 * @param stats the GNUNET_STATISTICS handle
 * @param max_duration maximum numbers of iterations for the LP/MLP Solver
 * @param max_iterations maximum time limit for the LP/MLP Solver
 * @return struct GAS_MLP_Handle * on success, NULL on fail
 */
struct GAS_MLP_Handle *
GAS_mlp_init (const struct GNUNET_CONFIGURATION_Handle *cfg,
              const struct GNUNET_STATISTICS_Handle *stats,
              struct GNUNET_TIME_Relative max_duration,
              unsigned int max_iterations)
{
  struct GAS_MLP_Handle * mlp = GNUNET_malloc (sizeof (struct GAS_MLP_Handle));

  double D;
  double R;
  double U;
  long long unsigned int tmp;
  unsigned int b_min;
  unsigned int n_min;
  struct GNUNET_TIME_Relative i_exec;

  /* Init GLPK environment */
  GNUNET_assert (glp_init_env() == 0);

  /* Create initial MLP problem */
  mlp->prob = glp_create_prob();
  GNUNET_assert (mlp->prob != NULL);

  /* Get diversity coefficient from configuration */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (cfg, "ats",
                                                      "COEFFICIENT_D",
                                                      &tmp))
    D = (double) tmp / 100;
  else
    D = 1.0;

  /* Get proportionality coefficient from configuration */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (cfg, "ats",
                                                      "COEFFICIENT_R",
                                                      &tmp))
    R = (double) tmp / 100;
  else
    R = 1.0;

  /* Get utilization coefficient from configuration */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (cfg, "ats",
                                                      "COEFFICIENT_U",
                                                      &tmp))
    U = (double) tmp / 100;
  else
    U = 1.0;

  /* Get quality metric coefficients from configuration */
  int i_delay = -1;
  int i_distance = -1;
  int q[GNUNET_ATS_QualityPropertiesCount] = GNUNET_ATS_QualityProperties;
  int c;
  for (c = 0; c < GNUNET_ATS_QualityPropertiesCount; c++)
  {
    /* initialize quality coefficients with default value 1.0 */
    mlp->co_Q[c] = 1.0;

    mlp->q[c] = q[c];
    if (q[c] == GNUNET_ATS_QUALITY_NET_DELAY)
      i_delay = c;
    if (q[c] == GNUNET_ATS_QUALITY_NET_DISTANCE)
      i_distance = c;
  }

  if ((i_delay != -1) && (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (cfg, "ats",
                                                      "COEFFICIENT_QUALITY_DELAY",
                                                      &tmp)))

    mlp->co_Q[i_delay] = (double) tmp / 100;
  else
    mlp->co_Q[i_delay] = 1.0;

  if ((i_distance != -1) && (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (cfg, "ats",
                                                      "COEFFICIENT_QUALITY_DISTANCE",
                                                      &tmp)))
    mlp->co_Q[i_distance] = (double) tmp / 100;
  else
    mlp->co_Q[i_distance] = 1.0;

  /* Get minimum bandwidth per used address from configuration */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (cfg, "ats",
                                                      "MIN_BANDWIDTH",
                                                      &tmp))
    b_min = tmp;
  else
    b_min = 64000;

  /* Get minimum number of connections from configuration */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_size (cfg, "ats",
                                                      "MIN_CONNECTIONS",
                                                      &tmp))
    n_min = tmp;
  else
    n_min = 4;

  /* Get minimum number of connections from configuration */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_time (cfg, "ats",
                                                        "ATS_EXEC_INTERVAL",
                                                        &i_exec))
    mlp->exec_interval = i_exec;
  else
    mlp->exec_interval = GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 30);

  mlp->stats = (struct GNUNET_STATISTICS_Handle *) stats;
  mlp->max_iterations = max_iterations;
  mlp->max_exec_duration = max_duration;

  /* Redirect GLPK output to GNUnet logging */
  glp_error_hook((void *) mlp, &mlp_term_hook);

  /* Init LP solving parameters */
  glp_init_smcp(&mlp->control_param_lp);
#if DEBUG_MLP
  mlp->control_param_lp.msg_lev = GLP_MSG_ALL;
#else
  mlp->control_param_lp.msg_lev = GLP_MSG_OFF;
#endif
  mlp->control_param_lp.it_lim = max_iterations;
  mlp->control_param_lp.tm_lim = max_duration.rel_value;

  /* Init MLP solving parameters */
  glp_init_iocp(&mlp->control_param_mlp);
#if DEBUG_MLP
  mlp->control_param_mlp.msg_lev = GLP_MSG_ALL;
#else
  mlp->control_param_mlp.msg_lev = GLP_MSG_OFF;
#endif
  mlp->control_param_mlp.tm_lim = max_duration.rel_value;

  mlp->last_execution = GNUNET_TIME_absolute_get_forever();

  mlp->co_D = D;
  mlp->co_R = R;
  mlp->co_U = U;
  mlp->b_min = b_min;
  mlp->n_min = n_min;
  mlp->m = GNUNET_ATS_QualityPropertiesCount;

  return mlp;
}

/**
 * Updates a single address in the MLP problem
 *
 * If the address did not exist before in the problem:
 * The MLP problem has to be recreated and the problem has to be resolved
 *
 * Otherwise the addresses' values can be updated and the existing base can
 * be reused
 *
 * @param mlp the MLP Handle
 * @param addresses the address hashmap
 * @param address the address to update
 */
void
GAS_mlp_address_update (struct GAS_MLP_Handle *mlp, struct GNUNET_CONTAINER_MultiHashMap * addresses, struct ATS_Address *address)
{
  int new;
  int col;
  struct MLP_information *mlpi;
  char * name;

  GNUNET_STATISTICS_update (mlp->stats,"# LP address updates", 1, GNUNET_NO);

  /* We add a new address */
  if (address->mlp_information == NULL)
    new = GNUNET_YES;
  else
    new = GNUNET_NO;

  if (mlp->prob == NULL)
  {
    mlp_create_problem(mlp, addresses);
    mlp_add_constraints_all_addresses (mlp, addresses);
  }

  /* Do the update */
  if (new == GNUNET_YES)
  {
    mlpi = GNUNET_malloc (sizeof (struct MLP_information));
    address->mlp_information = mlpi;
    mlp->addr_in_problem ++;

    /* Add bandwidth column */
    col = glp_add_cols (mlp->prob, 2);
    mlpi->c_b = col;
    mlpi->c_n = col + 1;

    GNUNET_asprintf (&name, "b_%s_%s", GNUNET_i2s (&address->peer), address->plugin);
    glp_set_col_name (mlp->prob, mlpi->c_b , name);
    GNUNET_free (name);
    /* Lower bound == 0 */
    glp_set_col_bnds (mlp->prob, mlpi->c_b , GLP_LO, 0.0, 0.0);
    /* Continuous value*/
    glp_set_col_kind (mlp->prob, mlpi->c_b , GLP_CV);
    /* Objective function coefficient == 0 */
    glp_set_obj_coef (mlp->prob, mlpi->c_b , 0);

    /* Add usage column */
    GNUNET_asprintf (&name, "n_%s_%s", GNUNET_i2s (&address->peer), address->plugin);
    glp_set_col_name (mlp->prob, mlpi->c_n, name);
    GNUNET_free (name);
    /* Limit value : 0 <= value <= 1 */
    glp_set_col_bnds (mlp->prob, mlpi->c_n, GLP_DB, 0.0, 1.0);
    /* Integer value*/
    glp_set_col_kind (mlp->prob, mlpi->c_n, GLP_IV);
    /* Objective function coefficient == 0 */
    glp_set_obj_coef (mlp->prob, mlpi->c_n, 0);

    /* Add */
  }

  /* Recalculate */
  if (new == GNUNET_YES)
    mlp->presolver_required = GNUNET_YES;
  mlp_solve_problem (mlp);
}

/**
 * Deletes a single address in the MLP problem
 *
 * The MLP problem has to be recreated and the problem has to be resolved
 *
 * @param mlp the MLP Handle
 * @param addresses the address hashmap
 * @param address the address to delete
 */
void
GAS_mlp_address_delete (struct GAS_MLP_Handle *mlp, struct GNUNET_CONTAINER_MultiHashMap * addresses, struct ATS_Address *address)
{
  GNUNET_STATISTICS_update (mlp->stats,"# LP address deletions", 1, GNUNET_NO);

  /* Free resources */
  if (address->mlp_information != NULL)
  {
    GNUNET_free (address->mlp_information);
    address->mlp_information = NULL;

    mlp->addr_in_problem --;
  }

  /* Update problem */

  /* Recalculate */
  mlp->presolver_required = GNUNET_YES;
  mlp_solve_problem (mlp);
}

/**
 * Deletes a single address in the MLP problem
 *
 * @param mlp the MLP Handle
 * @param addresses the address hashmap
 * @param address the address to change the preference
 */
void
GAS_mlp_address_change_preference (struct GAS_MLP_Handle *mlp, struct GNUNET_CONTAINER_MultiHashMap * addresses, struct ATS_Address *address)
{
  GNUNET_STATISTICS_update (mlp->stats,"# LP address preference changes", 1, GNUNET_NO);
}

/**
 * Shutdown the MLP problem solving component
 * @param mlp the MLP handle
 */
void
GAS_mlp_done (struct GAS_MLP_Handle *mlp)
{
  if (mlp->mlp_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel(mlp->mlp_task);
    mlp->mlp_task = GNUNET_SCHEDULER_NO_TASK;
  }

  mlp_delete_problem (mlp);

  /* Clean up GLPK environment */
  glp_free_env();

  GNUNET_free (mlp);
}


/* end of gnunet-service-ats_addresses_mlp.c */
