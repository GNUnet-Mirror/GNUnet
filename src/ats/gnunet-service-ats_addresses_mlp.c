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
#if HAVE_LIBGLPK
#include "glpk.h"
#endif

/*
 * The MLP handle
 */
static struct GAS_MLP_Handle *GAS_mlp;


/**
 * Solves the MLP problem
 * @return GNUNET_OK if could be solved, GNUNET_SYSERR on failure
 */
int
mlp_solve_lp_problem (struct GAS_MLP_Handle *mlp)
{
  int res;

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
 * Init the MLP problem solving component
 *
 * @param max_duration maximum numbers of iterations for the LP/MLP Solver
 * @param max_iterations maximum time limit for the LP/MLP Solver
 * @return GNUNET_OK on success, GNUNET_SYSERR on fail
 */
int
GAS_mlp_init (struct GNUNET_TIME_Relative max_duration, unsigned int max_iterations)
{
  GAS_mlp = GNUNET_malloc (sizeof (struct GAS_MLP_Handle));

  /* Init GLPK environment */
  GNUNET_assert (glp_init_env() == 0);

  /* Create initial MLP problem */
  GAS_mlp->prob = glp_create_prob();
  GNUNET_assert (GAS_mlp->prob != NULL);

  GAS_mlp->max_iterations = max_iterations;
  GAS_mlp->max_exec_duration = max_duration;

  /* Init LP solving parameters */
  glp_init_smcp(&GAS_mlp->control_param_lp);
#if DEBUG_MLP
  GAS_mlp->control_param_lp.msg_lev = GLP_MSG_ALL;
#else
  GAS_mlp->control_param_lp.msg_lev = GLP_MSG_OFF;
#endif
  GAS_mlp->control_param_lp.it_lim = max_iterations;
  GAS_mlp->control_param_lp.tm_lim = max_duration.rel_value;

  /* Init MLP solving parameters */
  glp_init_iocp(&GAS_mlp->control_param_mlp);
#if DEBUG_MLP
  GAS_mlp->control_param_mlp.msg_lev = GLP_MSG_ALL;
#else
  GAS_mlp->control_param_mlp.msg_lev = GLP_MSG_OFF;
#endif
  GAS_mlp->control_param_mlp.tm_lim = max_duration.rel_value;

  return GNUNET_OK;
}

/**
 * Updates a single address in the MLP problem
 *
 * If the address did not exist before in the problem:
 * The MLP problem has to be recreated and the problem has to be resolved
 *
 * Otherwise the addresses' values can be updated and the existing base can
 * be reused
 */
void
GAS_mlp_address_update (struct GNUNET_CONTAINER_MultiHashMap * addresses, struct ATS_Address *address)
{

}

/**
 * Deletes a single address in the MLP problem
 *
 * The MLP problem has to be recreated and the problem has to be resolved
 */
void
GAS_mlp_address_delete (struct GNUNET_CONTAINER_MultiHashMap * addresses, struct ATS_Address *address)
{

}

/**
 * Deletes a single address in the MLP problem
 */
void
GAS_mlp_address_change_preference (struct GNUNET_CONTAINER_MultiHashMap * addresses, struct ATS_Address *address)
{

}

/**
 * Shutdown the MLP problem solving component
 */
void
GAS_mlp_done ()
{
  if (GAS_mlp != NULL)
    glp_delete_prob(GAS_mlp->prob);

  /* Clean up GLPK environment */
  glp_free_env();

  GNUNET_free (GAS_mlp);
}


/* end of gnunet-service-ats_addresses_mlp.c */
