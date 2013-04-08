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
 * @brief ats MLP problem solver
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

#define BIG_M_VALUE (UINT32_MAX) /10
#define BIG_M_STRING "unlimited"

#define MLP_AVERAGING_QUEUE_LENGTH 3

#define MLP_MAX_EXEC_DURATION   GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 10)
#define MLP_MAX_ITERATIONS      4096

#define DEFAULT_D 1.0
#define DEFAULT_R 1.0
#define DEFAULT_U 1.0
#define DEFAULT_QUALITY 1.0
#define DEFAULT_MIN_CONNECTIONS 4
#define DEFAULT_PEER_PREFERENCE 1.0

#define MLP_NaN -1
#define MLP_UNDEFINED 0
#define GLP_YES 1.0
#define GLP_NO  0.0


struct MLP_Solution
{
	struct GNUNET_TIME_Relative build_dur;
	struct GNUNET_TIME_Relative lp_dur;
	struct GNUNET_TIME_Relative mip_dur;

	int lp_res;
	int lp_presolv;
	int mip_res;
	int mip_presolv;

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

#if 0
  /* Array of quality preferences */
  double f_q[GNUNET_ATS_QualityPropertiesCount];

#endif
};



struct MLP_Problem
{
  /**
   * GLPK (MLP) problem object
   */
#if HAVE_LIBGLPK
  glp_prob *prob;
#else
  void *prob;
#endif
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
  int quota_index [GNUNET_ATS_NetworkTypeCount];
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
  /**
   * Statistics handle
   */
  struct GNUNET_STATISTICS_Handle *stats;

  /**
   * Addresses' bandwidth changed callback
   */
  GAS_bandwidth_changed_cb bw_changed_cb;

  /**
   * Addresses' bandwidth changed callback closure
   */
  void *bw_changed_cb_cls;

  struct MLP_Problem p;

  struct MLP_Variables pv;

  struct MLP_Solution ps;

  /**
   * GLPK LP control parameter
   */
#if HAVE_LIBGLPK
  glp_smcp control_param_lp;
#else
  void *control_param_lp;
#endif

  /**
   * GLPK LP control parameter
   */
#if HAVE_LIBGLPK
  glp_iocp control_param_mlp;
#else
  void *control_param_mlp;
#endif

  /**
   * Peers with pending address requests
   */
  struct GNUNET_CONTAINER_MultiHashMap *peers;

  /**
   * Was the problem updated since last solution
   */
  int mlp_prob_updated;

  /**
   * Has the problem size changed since last solution
   */
  int mlp_prob_changed;

  /**
   * Solve the problem automatically when updates occur?
   * Default: GNUNET_YES
   * Can be disabled for test and measurements
   */
  int mlp_auto_solve;

  /**
   * Write MILP problem to a MPS file
   */
  int write_mip_mps;

  /**
   * Write MILP problem to a MPS file
   */
  int write_mip_sol;

};


/**
 * Address specific MLP information
 */
struct MLP_information
{

	/* Bandwidth assigned */
  struct GNUNET_BANDWIDTH_Value32NBO b_out;
  struct GNUNET_BANDWIDTH_Value32NBO b_in;

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
 * Solves the MLP problem
 *
 * @param solver the MLP Handle
 * @param addresses the address hashmap
 * @return GNUNET_OK if could be solved, GNUNET_SYSERR on failure
 */
int
GAS_mlp_solve_problem (void *solver, struct GNUNET_CONTAINER_MultiHashMap * addresses);


/**
 * Init the MLP problem solving component
 *
 * @param cfg configuration handle
 * @param stats the GNUNET_STATISTICS handle
 * @param network array of GNUNET_ATS_NetworkType with length dest_length
 * @param out_dest array of outbound quotas
 * @param in_dest array of outbound quota
 * @param dest_length array length for quota arrays
 * @param bw_changed_cb callback for changed bandwidth amounts
 * @param bw_changed_cb_cls cls for callback
 * @return struct GAS_MLP_Handle on success, NULL on fail
 */
void *
GAS_mlp_init (const struct GNUNET_CONFIGURATION_Handle *cfg,
              const struct GNUNET_STATISTICS_Handle *stats,
              int *network,
              unsigned long long *out_dest,
              unsigned long long *in_dest,
              int dest_length,
              GAS_bandwidth_changed_cb bw_changed_cb,
              void *bw_changed_cb_cls);


/**
 * Add a single address within a network to the solver
 *
 * @param solver the solver Handle
 * @param addresses the address hashmap containing all addresses
 * @param address the address to add
 * @param network network type of this address
 */
void
GAS_mlp_address_add (void *solver,
										struct GNUNET_CONTAINER_MultiHashMap *addresses,
										struct ATS_Address *address,
										uint32_t network);

/**
 * Updates a single address in the MLP problem
 *
 * If the address did not exist before in the problem:
 * The MLP problem has to be recreated and the problem has to be resolved
 *
 * ATS performance information in address are already updated, delta + previous
 * values are included in atsi_prev (value GNUNET_ATS_VALUE_UNDEFINED if not existing before)
 *
 * Otherwise the addresses' values can be updated and the existing base can
 * be reused
 *
 * @param solver the solver Handle
 * @param addresses the address hashmap containing all addresses
 * @param address the update address
 * @param session the new session (if changed otherwise current)
 * @param in_use the new address in use state (if changed otherwise current)
 * @param atsi_prev ATS information updated + previous values, GNUNET_ATS_VALUE_UNDEFINED if not existing before
 * @param atsi_count_prev number of atsi values updated
 */
void
GAS_mlp_address_update (void *solver,
                        struct GNUNET_CONTAINER_MultiHashMap *addresses,
                        struct ATS_Address *address,
                        uint32_t session,
                        int in_use,
                        const struct GNUNET_ATS_Information *atsi_prev,
                        uint32_t atsi_count_prev);


/**
 * Deletes a single address in the MLP problem
 *
 * The MLP problem has to be recreated and the problem has to be resolved
 *
 * @param solver the MLP Handle
 * @param addresses the address hashmap
 *        the address has to be already removed from the hashmap
 * @param address the address to delete
 * @param session_only delete only session not whole address
 */
void
GAS_mlp_address_delete (void *solver,
                        struct GNUNET_CONTAINER_MultiHashMap *addresses,
                        struct ATS_Address *address,
                        int session_only);


/**
 * Changes the preferences for a peer in the MLP problem
 *
 * @param solver the MLP Handle
 * @param client client
 * @param peer the peer
 * @param kind the kind to change the preference
 * @param score the score
 */
void
GAS_mlp_address_change_preference (void *solver,
                                   void *client,
                                   const struct GNUNET_PeerIdentity *peer,
                                   enum GNUNET_ATS_PreferenceKind kind,
                                   float score);


/**
 * Get the preferred address for a specific peer
 *
 * @param solver the MLP Handle
 * @param addresses address hashmap
 * @param peer the peer
 * @return suggested address
 */
const struct ATS_Address *
GAS_mlp_get_preferred_address (void *solver,
                               struct GNUNET_CONTAINER_MultiHashMap * addresses,
                               const struct GNUNET_PeerIdentity *peer);


/**
 * Stop notifying about address and bandwidth changes for this peer
 *
 * @param solver the MLP handle
 * @param addresses address hashmap
 * @param peer the peer
 */

void
GAS_mlp_stop_get_preferred_address (void *solver,
                                     struct GNUNET_CONTAINER_MultiHashMap *addresses,
                                     const struct GNUNET_PeerIdentity *peer);


/**
 * Shutdown the MLP problem solving component
 *
 * @param solver the solver handle
 */
void
GAS_mlp_done (void *solver);

#endif
/* end of gnunet-service-ats_addresses_mlp.h */
