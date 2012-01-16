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
 * @file ats/gnunet-service-ats_addresses_mlp.h
 * @brief ats mlp problem solver
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_statistics_service.h"
#include "gnunet-service-ats_addresses.h"
#if HAVE_LIBGLPK
#include "glpk.h"
#endif

#ifndef GNUNET_SERVICE_ATS_ADDRESSES_MLP_H
#define GNUNET_SERVICE_ATS_ADDRESSES_MLP_H

#define VERBOSE GNUNET_EXTRA_LOGGING
#define DEBUG_MLP GNUNET_EXTRA_LOGGING

#define MLP_MAX_EXEC_DURATION   GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 3)
#define MLP_MAX_ITERATIONS      INT_MAX

/**
 * MLP Handle
 */
struct GAS_MLP_Handle
{
  /**
   * Statistics handle
   */
  struct GNUNET_STATISTICS_Handle *stats;

  /**
   * GLPK (MLP) problem object
   */
#if HAVE_LIBGLPK
  glp_prob *prob;
#else
  void *prob;
#endif

  /**
   * GLPK LP control parameter
   */
  glp_smcp control_param_lp;

  /**
   * GLPK LP control parameter
   */
  glp_iocp control_param_mlp;

  /**
   * Maximum execution time per problem solving
   */
  struct GNUNET_TIME_Relative max_exec_duration;

  /**
   * Maximum number of LP iterations per problem solving
   */
  unsigned int max_iterations;

  /* state information */

  /**
   * Do we need to use the LP presolver?
   *
   * If the problem addresses were added or removed and the last basis was we
   * need to use the presolver.
   * presolver_required == GNUNET_YES
   *
   * If values were modified, we can reuse a valid basis
   * presolver_required == GNUNET_NO
   */
  int presolver_required;

  /* statistics */

  /**
   * Time of last execution
   */
  struct GNUNET_TIME_Absolute last_execution;


  /**
   * How often was the LP problem solved
   */
  unsigned int lp_solved;

  /**
   * total duration of all lp solver executions
   */
  uint64_t lp_total_duration;

  /**
   * How often was the MLP problem solved
   */
  unsigned int mlp_solved;

  /**
   * total duration of all mlp solver executions
   */
  uint64_t mlp_total_duration;

  /* Information about the problem */


  /* column index Diversity (D) column */
  int c_d;
  double co_D;

  /* column index Utilization (U) column */
  int c_u;
  double co_U;

  /* column index Proportionality (R) column */
  int c_r;
  double co_R;

  /* ATS Quality metrics
   * array with GNUNET_ATS_QualityPropertiesCount elements
   * contains mapping to GNUNET_ATS_Property*/
  int q[GNUNET_ATS_QualityPropertiesCount];

  /* column index first quality metric (q_1) column */
  int c_q_start;

  /* column index last quality metric (q_n) column */
  int c_q_end;

  /* quality metric coefficients*/
  double co_Q[GNUNET_ATS_QualityPropertiesCount];

  /* number of quality metrics */
  int m;

  /* minimum bandwidth assigned to an address */
  unsigned int b_min;

  /* minimum number of addresses with bandwidth assigned */
  unsigned int n_min;
};


/**
 * Address specific MLP information
 */
struct MLP_information
{
  /* bandwidth column index */
  signed int c_b;

  /* address usage column */
  signed int c_n;
};


/**
 * Init the MLP problem solving component
 *
 * @param cfg configuration handle
 * @param stats the GNUNET_STATISTICS handle
 * @param max_duration maximum numbers of iterations for the LP/MLP Solver
 * @param max_iterations maximum time limit for the LP/MLP Solver
 * @return struct GAS_MLP_Handle * on success, NULL on fail
 */
struct GAS_MLP_Handle *
GAS_mlp_init (const struct GNUNET_CONFIGURATION_Handle *cfg,
              const struct GNUNET_STATISTICS_Handle *stats,
              struct GNUNET_TIME_Relative max_duration,
              unsigned int max_iterations);


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
GAS_mlp_address_update (struct GAS_MLP_Handle *mlp, struct GNUNET_CONTAINER_MultiHashMap * addresses, struct ATS_Address *address);


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
GAS_mlp_address_delete (struct GAS_MLP_Handle *mlp, struct GNUNET_CONTAINER_MultiHashMap * addresses, struct ATS_Address *address);


/**
 * Deletes a single address in the MLP problem
 *
 * @param mlp the MLP Handle
 * @param addresses the address hashmap
 * @param address the address to change the preference
 */
void
GAS_mlp_address_change_preference (struct GAS_MLP_Handle *mlp, struct GNUNET_CONTAINER_MultiHashMap * addresses, struct ATS_Address *address);


/**
 * Shutdown the MLP problem solving component
 */
void
GAS_mlp_done ();

#endif
/* end of gnunet-service-ats_addresses_mlp.h */
