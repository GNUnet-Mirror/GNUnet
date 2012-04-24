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

#define DEBUG_MLP GNUNET_EXTRA_LOGGING

#define BIG_M_VALUE (UINT32_MAX) /10
#define BIG_M_STRING "unlimited"

#define MLP_AVERAGING_QUEUE_LENGTH 3

#define MLP_MAX_EXEC_DURATION   GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 3)
#define MLP_MAX_ITERATIONS      INT_MAX

struct ATS_Peer
{
  struct ATS_Peer *next;
  struct ATS_Peer *prev;

  struct GNUNET_PeerIdentity id;

  /* Array of quality preferences */
  double f_q[GNUNET_ATS_QualityPropertiesCount];
  /* Legacy preference value */
  double f;

  /* constraint 2: 1 address per peer*/
  unsigned int r_c2;

  /* constraint 9: relativity */
  unsigned int r_c9;

  struct ATS_Address *head;
  struct ATS_Address *tail;
};

struct ATS_PreferedAddress
{
  uint32_t bandwidth_out;
  uint32_t bandwidth_in;
  struct ATS_Address *address;
};

struct GAS_MLP_SolutionContext
{
  int lp_result;
  int mlp_result;
  struct GNUNET_TIME_Relative lp_duration;
  struct GNUNET_TIME_Relative mlp_duration;
};

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

  double BIG_M;

  /**
   * GLPK LP control parameter
   */
  glp_smcp control_param_lp;

  /**
   * GLPK LP control parameter
   */
  glp_iocp control_param_mlp;

  /**
   * Solves the task in an regular interval
   */
  GNUNET_SCHEDULER_TaskIdentifier mlp_task;

  /**
   * Interval between scheduled problem solving
   */
  struct GNUNET_TIME_Relative exec_interval;

  /**
   * Maximum execution time per problem solving
   */
  struct GNUNET_TIME_Relative max_exec_duration;

  /**
   * Maximum number of LP iterations per problem solving
   */
  unsigned int max_iterations;

  /**
   * Solve the problem automatically when updates occur?
   * Default: GNUNET_YES
   * Can be disabled for test and measurements
   */
  int auto_solve;

  int semaphore;

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

  unsigned int addr_in_problem;

  /* Information about the problem */

  struct ATS_Peer *peer_head;
  struct ATS_Peer *peer_tail;

  /* Number of peers */
  unsigned int c_p;

  /* current problem matrix */
  /* row index array */
  int *ia;
  /* column index array */
  int *ja;
  /* column index array */
  double *ar;
  /* current size of the constraint matrix |indices| */
  unsigned int cm_size;
  unsigned int ci;

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
   *
   * array with GNUNET_ATS_QualityPropertiesCount elements
   * contains mapping to GNUNET_ATS_Property*/
  int q[GNUNET_ATS_QualityPropertiesCount];

  /* column index quality metrics  */
  int c_q[GNUNET_ATS_QualityPropertiesCount];

  /* column index quality metrics  */
  int r_q[GNUNET_ATS_QualityPropertiesCount];

  /* quality metric coefficients*/
  double co_Q[GNUNET_ATS_QualityPropertiesCount];

  /* number of quality metrics */
  int m_q;

  /* ATS network quotas */
  int c_quota[GNUNET_ATS_NetworkTypeCount];
  int r_quota[GNUNET_ATS_NetworkTypeCount];
  int quota_index [GNUNET_ATS_NetworkTypeCount];
  unsigned long long quota_out[GNUNET_ATS_NetworkTypeCount];
  unsigned long long quota_in[GNUNET_ATS_NetworkTypeCount];

  /* ATS ressource costs
   *
   * array with GNUNET_ATS_QualityPropertiesCount elements
   * contains mapping to GNUNET_ATS_Property*/
  int rc[GNUNET_ATS_QualityPropertiesCount];

  /* column index ressource costs  */
  int c_rc[GNUNET_ATS_QualityPropertiesCount];

  /* ressource costs coefficients*/
  double co_RC[GNUNET_ATS_QualityPropertiesCount];

  /* number of quality metrics */
  int m_rc;

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
  double b;

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

  /* Quality information row indices */
  unsigned int r_q[GNUNET_ATS_QualityPropertiesCount];

  /* Quality information */
  double q[GNUNET_ATS_QualityPropertiesCount][MLP_AVERAGING_QUEUE_LENGTH];

  /* Quality information averaged */
  double q_averaged[GNUNET_ATS_QualityPropertiesCount];

  /* Averaging index */
  int q_avg_i[GNUNET_ATS_QualityPropertiesCount];
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
 * Solves the MLP problem on demand
 *
 * @param mlp the MLP Handle
 * @param ctx solution context
 * @return GNUNET_OK if could be solved, GNUNET_SYSERR on failure
 */
int
GAS_mlp_solve_problem (struct GAS_MLP_Handle *mlp, struct GAS_MLP_SolutionContext *ctx);


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
 *        the address has to be already added from the hashmap
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
 *        the address has to be already removed from the hashmap
 * @param address the address to delete
 */
void
GAS_mlp_address_delete (struct GAS_MLP_Handle *mlp, struct GNUNET_CONTAINER_MultiHashMap * addresses, struct ATS_Address *address);


/**
 * Changes the preferences for a peer in the MLP problem
 *
 * @param mlp the MLP Handle
 * @param peer the peer
 * @param kind the kind to change the preference
 * @param score the score
 */
void
GAS_mlp_address_change_preference (struct GAS_MLP_Handle *mlp,
                                   const struct GNUNET_PeerIdentity *peer,
                                   enum GNUNET_ATS_PreferenceKind kind,
                                   float score);


/**
 * Get the preferred address for a specific peer
 *
 * @param mlp the MLP Handle
 * @param addresses address hashmap
 * @param peer the peer
 * @return suggested address
 */
struct ATS_PreferedAddress *
GAS_mlp_get_preferred_address (struct GAS_MLP_Handle *mlp,
                               struct GNUNET_CONTAINER_MultiHashMap * addresses,
                               const struct GNUNET_PeerIdentity *peer);

/**
 * Shutdown the MLP problem solving component
 */
void
GAS_mlp_done ();

#endif
/* end of gnunet-service-ats_addresses_mlp.h */
