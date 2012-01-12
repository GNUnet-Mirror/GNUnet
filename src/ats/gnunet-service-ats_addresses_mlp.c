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
  GAS_mlp->control_param_lp.it_lim = max_iterations;
  GAS_mlp->control_param_lp.tm_lim = max_duration.rel_value;
  /* Init MLP solving parameters */
  glp_init_iocp(&GAS_mlp->control_param_mlp);
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
