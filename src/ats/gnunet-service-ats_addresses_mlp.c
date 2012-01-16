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


/**
 * Create the MLP problem
 *
 * @param mlp the MLP handle
 * @return GNUNET_OK or GNUNET_SYSERR
 */

static int
mlp_create_problem (struct GAS_MLP_Handle *mlp)
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
  /* Column coffiecient */
  glp_set_obj_coef (mlp->prob, col, mlp->co_D);
  /* Column lower bound = 0.0 */
  glp_set_col_bnds (mlp->prob, col, GLP_LO, 0.0, 0.0);

  /* Utilization u column  */

  col = glp_add_cols (mlp->prob, 1);
  mlp->c_u = col;
  /* Column name */
  glp_set_col_name (mlp->prob, col, "u");
  /* Column coffiecient */
  glp_set_obj_coef (mlp->prob, col, mlp->co_U);
  /* Column lower bound = 0.0 */
  glp_set_col_bnds (mlp->prob, col, GLP_LO, 0.0, 0.0);

  /* Relitivity r column  */

  col = glp_add_cols (mlp->prob, 1);
  mlp->c_r = col;
  /* Column name */
  glp_set_col_name (mlp->prob, col, "r");
  /* Column coffiecient */
  glp_set_obj_coef (mlp->prob, col, mlp->co_R);
  /* Column lower bound = 0.0 */
  glp_set_col_bnds (mlp->prob, col, GLP_LO, 0.0, 0.0);

  /* Quality metric columns */
  col = glp_add_cols(mlp->prob, mlp->m);
  mlp->c_q_start = col;
  mlp->c_q_end = col + mlp->m;
  for (c = 0; c < mlp->m; c++)
  {
    GNUNET_asprintf (&name, "q_%u", mlp->q[c]);
    glp_set_col_name (mlp->prob, col + c, name);
    glp_set_col_bnds (mlp->prob, col + c, GLP_LO, 0.0, 0.0);
    GNUNET_free (name);
    glp_set_obj_coef (mlp->prob, col + c, mlp->co_Q[c]);
  }

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
          "Solving LP problem failed: glp_simplex error 0x%X", res);
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
          "Solving LP problem failed, no solution: glp_get_status 0x%X", res);
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
        "Solving MLP problem failed: glp_intopt error 0x%X", res);
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
          "Solving MLP problem failed, no solution: glp_mip_status 0x%X", res);
      return GNUNET_SYSERR;
      break;
  }

  return GNUNET_OK;
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

  mlp->stats = (struct GNUNET_STATISTICS_Handle *) stats;
  mlp->max_iterations = max_iterations;
  mlp->max_exec_duration = max_duration;

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

  mlp_create_problem (mlp);
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

  GNUNET_STATISTICS_update (mlp->stats,"# LP address updates", 1, GNUNET_NO);

  /* We add a new address */
  if (address->mlp_information == NULL)
  {
    new = GNUNET_YES;
    address->mlp_information = GNUNET_malloc (sizeof (struct MLP_information));

    /* Add bandwidth columns */


    /* Add */
  }
  else
    new = GNUNET_NO;

  /* Do the update */

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
  if (mlp != NULL)
    glp_delete_prob(mlp->prob);

  /* Clean up GLPK environment */
  glp_free_env();

  GNUNET_free (mlp);
}


/* end of gnunet-service-ats_addresses_mlp.c */
