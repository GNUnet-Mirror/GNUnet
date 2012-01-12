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
};


/**
 * Init the MLP problem solving component
 *
 * @param stats the GNUNET_STATISTICS handle
 * @param max_duration maximum numbers of iterations for the LP/MLP Solver
 * @param max_iterations maximum time limit for the LP/MLP Solver
 * @return GNUNET_OK on success, GNUNET_SYSERR on fail
 */
int
GAS_mlp_init (const struct GNUNET_STATISTICS_Handle *stats,
              struct GNUNET_TIME_Relative max_duration,
              unsigned int max_iterations);

/**
 * Update address in the MLP problem
 */
void
GAS_mlp_update (struct ATS_Address *address);

/**
 * Shutdown the MLP problem solving component
 */
void
GAS_mlp_done ();

#endif
/* end of gnunet-service-ats_addresses_mlp.h */
